package tui

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"github.com/DryBearr/dryserver/internal/build"
	"github.com/DryBearr/dryserver/internal/config"
	"github.com/DryBearr/dryserver/internal/owner"
	"github.com/DryBearr/dryserver/internal/packages"
)

// Paths are the project files the app works with.
type Paths struct {
	Config  string // config.env
	OutDir  string // out/
	Secrets string // secrets/
}

type screen int

const (
	menuScreen screen = iota
	configScreen
	buildScreen
	flashScreen
)

type menuItem struct {
	key, label string
}

var menu = []menuItem{
	{"1", "Edit config"},
	{"2", "Build installer ISO"},
	{"3", "Flash USB"},
	{"q", "Quit"},
}

type backMsg struct{ notice string }

func back() tea.Msg { return backMsg{} }

// App is the main menu tying config, build and flash together.
type App struct {
	paths  Paths
	screen screen
	cursor int
	notice string
	width  int
	height int

	cfg    config.Config
	cfgErr error
	iso    fs.FileInfo
	root   bool

	form      *huh.Form
	formCfg   *config.Config
	formTools *[]string // multi-select binds a slice; joined into formCfg.Tools on save
	build     Build
	flash     Flash
}

func NewApp(p Paths) App {
	a := App{paths: p, root: os.Geteuid() == 0}
	a.refresh()
	return a
}

func (a *App) refresh() {
	a.cfg, a.cfgErr = config.Load(a.paths.Config)
	if a.cfgErr == nil {
		a.cfgErr = a.cfg.Validate()
	}
	a.iso, _ = os.Stat(build.ISOPath(a.paths.OutDir))
}

func (a App) Init() tea.Cmd { return nil }

func (a App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if ws, ok := msg.(tea.WindowSizeMsg); ok {
		a.width, a.height = ws.Width, ws.Height
	}
	if b, ok := msg.(backMsg); ok {
		a.screen = menuScreen
		a.notice = b.notice
		a.refresh()
		return a, nil
	}

	switch a.screen {
	case configScreen:
		return a.updateForm(msg)
	case buildScreen:
		var cmd tea.Cmd
		a.build, cmd = a.build.Update(msg)
		return a, cmd
	case flashScreen:
		next, cmd := a.flash.Update(msg)
		a.flash = next.(Flash)
		return a, cmd
	}

	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "ctrl+c", "q", "esc":
			return a, tea.Quit
		case "up", "k":
			a.cursor = max(a.cursor-1, 0)
		case "down", "j":
			a.cursor = min(a.cursor+1, len(menu)-1)
		case "enter":
			return a.choose(menu[a.cursor].key)
		default:
			return a.choose(k.String())
		}
	}
	return a, nil
}

func (a App) choose(k string) (tea.Model, tea.Cmd) {
	a.notice = ""
	switch k {
	case "1":
		return a.openForm()
	case "2":
		if a.cfgErr != nil {
			a.notice = "Fix the config first (1)."
			return a, nil
		}
		a.screen = buildScreen
		a.build = NewBuild(build.Options{Config: a.cfg, OutDir: a.paths.OutDir, SecretsDir: a.paths.Secrets}, back)
		a.build, _ = a.build.Update(tea.WindowSizeMsg{Width: a.width, Height: a.height})
		var cmd tea.Cmd
		a.build, cmd = a.build.Start()
		return a, cmd
	case "3":
		switch {
		case a.iso == nil:
			a.notice = "Build the ISO first (2)."
			return a, nil
		case !a.root:
			a.notice = "Flashing writes to raw disks and needs root. Quit and run: sudo " + os.Args[0]
			return a, nil
		}
		a.screen = flashScreen
		a.flash = NewFlash(build.ISOPath(a.paths.OutDir), a.iso.Size()).Embedded(back)
		next, _ := a.flash.Update(tea.WindowSizeMsg{Width: a.width, Height: a.height})
		a.flash = next.(Flash)
		return a, a.flash.Init()
	case "q":
		return a, tea.Quit
	}
	return a, nil
}

func (a App) openForm() (tea.Model, tea.Cmd) {
	c := a.cfg
	if c.AdminSSHPubkey == "" {
		c.AdminSSHPubkey = config.DefaultPubkey()
	}
	tools := c.ToolList()
	a.formCfg, a.formTools = &c, &tools
	a.form = newConfigForm(a.formCfg, a.formTools)
	a.screen = configScreen
	cmd := a.form.Init()
	if a.width > 0 {
		next, _ := a.form.Update(tea.WindowSizeMsg{Width: a.width, Height: a.height})
		a.form = next.(*huh.Form)
	}
	return a, cmd
}

func (a App) updateForm(msg tea.Msg) (tea.Model, tea.Cmd) {
	next, cmd := a.form.Update(msg)
	a.form = next.(*huh.Form)
	switch a.form.State {
	case huh.StateCompleted:
		a.formCfg.Tools = strings.Join(packages.SortTools(*a.formTools), " ")
		a.formCfg.ExtraPackages = strings.Join(a.formCfg.ExtraList(), " ")
		notice := "Config saved to " + a.paths.Config + "."
		if err := a.formCfg.Save(a.paths.Config); err != nil {
			notice = "Saving config failed: " + err.Error()
		}
		owner.Fix(a.paths.Config)
		return a, func() tea.Msg { return backMsg{notice} }
	case huh.StateAborted:
		return a, func() tea.Msg { return backMsg{"Config not changed."} }
	}
	return a, cmd
}

func newConfigForm(c *config.Config, tools *[]string) *huh.Form {
	var toolOpts []huh.Option[string]
	for _, b := range packages.Optional {
		toolOpts = append(toolOpts, huh.NewOption(b.Title, b.ID).Selected(slices.Contains(*tools, b.ID)))
	}
	km := huh.NewDefaultKeyMap()
	km.Quit = key.NewBinding(key.WithKeys("esc", "ctrl+c"), key.WithHelp("esc", "cancel"))
	return huh.NewForm(
		huh.NewGroup(
			huh.NewNote().Title("WiFi").
				Description("Used by the installer and the servers for internet.\nLeave SSID empty to use Ethernet only."),
			huh.NewInput().Title("WiFi SSID").Value(&c.WifiSSID),
			huh.NewInput().Title("WiFi password").EchoMode(huh.EchoModePassword).
				Value(&c.WifiPass).Validate(config.ValidWifiPass),
		),
		huh.NewGroup(
			huh.NewNote().Title("Mesh").
				Description("The first laptop you install becomes the coordinator.\nReserve its IP in your router's DHCP settings."),
			huh.NewInput().Title("Coordinator LAN IP").Placeholder("192.168.1.50").
				Description("Its address on the WiFi/router network.").
				Value(&c.CoordLanIP).Validate(config.ValidIPv4),
			huh.NewInput().Title("Mesh subnet").Description("WireGuard addresses. Node N gets .N").
				Value(&c.WGSubnet).Validate(func(s string) error { return config.ValidMeshSubnet(s, c.CoordLanIP) }),
			huh.NewInput().Title("WireGuard UDP port").Value(&c.WGPort).Validate(config.ValidPort),
			huh.NewInput().Title("Extra ports open inside the mesh").Placeholder("8080/tcp 53/udp").
				Description("SSH is always open. These never open to WiFi/router.").
				Value(&c.MeshPorts).Validate(config.ValidMeshPorts),
		),
		huh.NewGroup(
			huh.NewSelect[string]().Title("WireGuard network").
				Description("Which cable or radio carries traffic between servers.").
				Options(
					huh.NewOption("Switch when plugged in, else WiFi/router (auto)", config.TransportAuto),
					huh.NewOption("WiFi/router network only", config.TransportLAN),
				).Value(&c.WGTransport),
		),
		huh.NewGroup(
			huh.NewNote().Title("Switch").
				Description("Each Ethernet port gets a fixed IP here, so servers find each\nother on the switch. Works whether or not the switch is\nconnected to your router; if it is, the cable also gets\ninternet from the router."),
			huh.NewInput().Title("Switch subnet").Description("Mesh node .N gets .N here too.").
				Value(&c.SwitchSubnet).
				Validate(func(s string) error { return config.ValidSwitchSubnet(s, c.WGSubnet, c.CoordLanIP) }),
		).WithHideFunc(func() bool { return c.WGTransport != config.TransportAuto }),
		huh.NewGroup(
			huh.NewMultiSelect[string]().Title("Tools").
				Description("Always installed: ssh, git, cron, tmux, htop, curl, rsync,\nripgrep, fzf and other basics. Pick extras (space toggles).").
				Options(toolOpts...).Value(tools),
			huh.NewInput().Title("Extra packages").Placeholder("python nodejs").
				Description("Any other Arch packages, space-separated.").
				Value(&c.ExtraPackages).Validate(config.ValidExtraPackages),
		),
		huh.NewGroup(
			huh.NewNote().Title("Admin access").
				Description("SSH key login only, password login is off."),
			huh.NewInput().Title("Username").Value(&c.Username).Validate(config.ValidUsername),
			huh.NewInput().Title("SSH public key").Placeholder("ssh-ed25519 AAAA... you@pc").
				Value(&c.AdminSSHPubkey).Validate(config.ValidPubkey),
			huh.NewInput().Title("Timezone").Placeholder("Europe/Berlin").
				Value(&c.Timezone).Validate(config.ValidTimezone),
		),
	).WithKeyMap(km).WithTheme(huh.ThemeCharm())
}

func (a App) View() string {
	switch a.screen {
	case configScreen:
		return titleStyle.Render("dryserver · config") + "\n\n" + a.form.View()
	case buildScreen:
		return a.build.View()
	case flashScreen:
		return a.flash.View()
	}

	var b strings.Builder
	b.WriteString(titleStyle.Render("dryserver · laptop server installer") + "\n\n")
	b.WriteString(a.status())
	b.WriteString("\n")
	for i, it := range menu {
		line := fmt.Sprintf("%s  %s", it.key, it.label)
		if i == a.cursor {
			b.WriteString(selStyle.Render("> "+line) + "\n")
		} else {
			b.WriteString("  " + line + "\n")
		}
	}
	if a.notice != "" {
		b.WriteString("\n" + a.notice + "\n")
	}
	b.WriteString("\n" + dimStyle.Render("↑/↓ move · enter or 1-3 select · q quit") + "\n")
	return b.String()
}

func (a App) status() string {
	var b strings.Builder
	row := func(name, value string) { fmt.Fprintf(&b, "  %-8s %s\n", name, value) }

	switch {
	case errors.Is(a.cfgErr, fs.ErrNotExist):
		row("Config", errStyle.Render("not created yet"))
	case a.cfgErr != nil:
		row("Config", errStyle.Render("invalid"))
		for _, line := range strings.Split(a.cfgErr.Error(), "\n") {
			row("", errStyle.Render("· "+line))
		}
	default:
		wifi := "Ethernet only"
		if a.cfg.WifiSSID != "" {
			wifi = "WiFi " + a.cfg.WifiSSID
		}
		over := "over WiFi/router"
		if a.cfg.WGTransport == config.TransportAuto {
			over = "over switch " + a.cfg.SwitchSubnet + " when plugged in"
		}
		row("Config", okStyle.Render("ok")+dimStyle.Render(fmt.Sprintf("  coordinator %s · %s", a.cfg.CoordLanIP, wifi)))
		row("", dimStyle.Render(fmt.Sprintf("  mesh %s %s", a.cfg.WGSubnet, over)))
		tools := strings.Join(append(a.cfg.ToolList(), a.cfg.ExtraList()...), " ")
		if tools == "" {
			tools = "basics only"
		}
		row("", dimStyle.Render("  tools: "+tools))
	}

	if a.iso == nil {
		row("ISO", dimStyle.Render("not built"))
	} else {
		row("ISO", okStyle.Render("ready")+dimStyle.Render(fmt.Sprintf("  %s · built %s",
			build.ISOPath(a.paths.OutDir), a.iso.ModTime().Format("2006-01-02 15:04"))))
		if a.cfgErr == nil {
			if st, err := os.Stat(a.paths.Config); err == nil && st.ModTime().After(a.iso.ModTime()) {
				row("", errStyle.Render("config changed after build, rebuild (2)"))
			}
		}
	}

	if a.root {
		row("Root", okStyle.Render("yes"))
	} else {
		row("Root", dimStyle.Render("no (flashing needs sudo)"))
	}
	return b.String()
}
