package tui

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"

	"github.com/DryBearr/dryserver/internal/config"
	"github.com/DryBearr/dryserver/internal/disks"
	"github.com/DryBearr/dryserver/internal/install"
	"github.com/DryBearr/dryserver/internal/sysconf"
)

type setupState int

const (
	suProbe setupState = iota
	suWelcome
	suWifi
	suBusy  // waiting on a background call (WiFi scan/connect)
	suCheck // prechecks with a live log
	suForm
	suConfirm
	suInstall
	suJoin
	suDone
	suFailed
)

type probeMsg struct {
	m   install.Machine
	err error
}

type wifiListMsg struct {
	ssids []string
	err   error
}

type checkMsg struct{ err error }

type stepMsg install.Step

type installDoneMsg struct{ err error }

type joinCodeMsg string

type joinDoneMsg struct {
	host int
	err  error
}

var codeBox = lipgloss.NewStyle().Border(lipgloss.DoubleBorder()).BorderForeground(lipgloss.Color("12")).
	Padding(1, 4).Bold(true)

type stepView struct {
	name  string
	done  bool
	start time.Time
	took  time.Duration
}

// Setup is the laptop setup screen shown when booting the installer USB.
type Setup struct {
	be    install.Backend
	cfg   config.Config
	state setupState
	m     install.Machine
	ch    *install.Choices

	form        *huh.Form
	diskConfirm *string
	userConfirm *string
	wifiSSID    *string
	wifiPass    *string
	ssids       []string

	confirm textinput.Model
	spin    spinner.Model
	busy    string // what suBusy is waiting for

	steps  []stepView
	lines  []string
	events chan tea.Msg
	cancel context.CancelFunc
	armed  bool // first ctrl+c during install pressed

	code     string
	hostNum  int
	joinErr  error
	checkErr error
	canRetry bool // the install failed; r runs it again

	err    error
	notice string
	width  int
	height int
}

func NewSetup(be install.Backend, cfg config.Config) Setup {
	in := textinput.New()
	in.CharLimit = 8
	in.Width = 10
	return Setup{
		be:      be,
		cfg:     cfg,
		ch:      &install.Choices{},
		spin:    spinner.New(spinner.WithSpinner(spinner.Dot)),
		confirm: in,
		height:  24,
	}
}

func (s Setup) Init() tea.Cmd {
	return tea.Batch(s.probe(), s.spin.Tick)
}

func (s Setup) probe() tea.Cmd {
	be := s.be
	return func() tea.Msg {
		m, err := be.Probe(context.Background())
		return probeMsg{m, err}
	}
}

func (s Setup) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		s.width, s.height = msg.Width, msg.Height
		if s.form != nil {
			next, cmd := s.form.Update(msg)
			s.form = next.(*huh.Form)
			return s, cmd
		}
		return s, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		s.spin, cmd = s.spin.Update(msg)
		return s, cmd

	case probeMsg:
		s.m, s.err = msg.m, msg.err
		if msg.err != nil {
			s.state = suFailed
			return s, nil
		}
		s.state = suWelcome
		return s, nil

	case wifiListMsg:
		if msg.err != nil {
			s.notice = "WiFi scan failed: " + msg.err.Error()
		}
		s.ssids = msg.ssids
		return s.openWifiForm()

	case probeWifiMsg:
		s.state = suWelcome
		if msg.err != nil {
			s.notice = "Could not connect: " + msg.err.Error()
			return s, nil
		}
		s.m = msg.m
		s.notice = ""
		return s, nil

	case checkMsg:
		if msg.err != nil {
			s.checkErr = msg.err
			return s, nil
		}
		s.steps, s.lines = nil, nil
		s.state = suConfirm
		s.confirm.SetValue("")
		return s, s.confirm.Focus()

	case stepMsg:
		s.addStep(install.Step(msg))
		return s, wait(s.events)

	case installDoneMsg:
		if msg.err != nil {
			s.state, s.err = suFailed, msg.err
			s.canRetry = true
			return s, nil
		}
		if s.ch.Role == sysconf.Coordinator {
			s.state = suDone
			return s, nil
		}
		return s.startJoin()

	case joinCodeMsg:
		s.code = string(msg)
		return s, wait(s.events)

	case joinDoneMsg:
		s.hostNum, s.joinErr = msg.host, msg.err
		s.state = suDone
		if errors.Is(msg.err, install.ErrRejected) {
			s.state, s.err = suFailed, msg.err
		}
		return s, nil

	case tea.KeyMsg:
		return s.handleKey(msg)
	}

	if s.form != nil && (s.state == suForm || s.state == suWifi) {
		return s.updateForm(msg)
	}
	if s.state == suConfirm {
		var cmd tea.Cmd
		s.confirm, cmd = s.confirm.Update(msg)
		return s, cmd
	}
	return s, nil
}

type probeWifiMsg probeMsg

func (s Setup) handleKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch s.state {
	case suProbe, suBusy:
		if k.String() == "ctrl+c" {
			return s, tea.Quit
		}
		return s, nil

	case suCheck:
		switch {
		case s.checkErr == nil && k.String() == "ctrl+c":
			s.cancel()
		case s.checkErr != nil && k.String() == "r":
			return s.startCheck()
		case s.checkErr != nil && (k.String() == "enter" || k.String() == "esc"):
			s.notice = "Check failed: " + s.checkErr.Error()
			return s.openForm()
		case s.checkErr != nil && k.String() == "ctrl+c":
			return s, tea.Quit
		}
		return s, nil

	case suWelcome:
		switch k.String() {
		case "ctrl+c", "q":
			return s, tea.Quit
		case "w":
			return s.scanWifi()
		case "enter":
			switch {
			case !s.m.Online:
				return s.scanWifi()
			case len(s.m.Disks) == 0:
				s.notice = "No internal disk found to install on."
				return s, nil
			}
			return s.openForm()
		}
		return s, nil

	case suForm, suWifi:
		return s.updateForm(k)

	case suConfirm:
		switch k.String() {
		case "ctrl+c":
			return s, tea.Quit
		case "esc":
			s.notice = ""
			return s.openForm()
		case "enter":
			if strings.TrimSpace(s.confirm.Value()) != "YES" {
				s.notice = `Type YES in capital letters, or press esc to change answers.`
				return s, nil
			}
			s.notice = ""
			return s.startInstall()
		}
		var cmd tea.Cmd
		s.confirm, cmd = s.confirm.Update(k)
		return s, cmd

	case suInstall:
		if k.String() == "ctrl+c" {
			if s.armed {
				s.cancel()
				return s, nil
			}
			s.armed = true
			s.notice = "Press ctrl+c again to abort. The disk is left half-installed."
		}
		return s, nil

	case suJoin:
		if k.String() == "s" || k.String() == "ctrl+c" {
			s.cancel()
		}
		return s, nil

	case suDone:
		switch k.String() {
		case "enter":
			if err := s.be.Reboot(); err != nil {
				s.notice = "Reboot failed: " + err.Error()
				return s, nil
			}
			return s, tea.Quit
		case "q", "ctrl+c":
			return s, tea.Quit
		}
		return s, nil

	case suFailed:
		switch k.String() {
		case "r":
			if s.canRetry {
				// Same answers; leftovers of the failed attempt are
				// released by the partition step.
				s.canRetry, s.err, s.notice = false, nil, ""
				return s.startInstall()
			}
		case "q", "ctrl+c", "enter":
			return s, tea.Quit
		}
	}
	return s, nil
}

func (s Setup) scanWifi() (tea.Model, tea.Cmd) {
	s.state, s.busy = suBusy, "Scanning WiFi networks…"
	be := s.be
	return s, tea.Batch(s.spin.Tick, func() tea.Msg {
		ssids, err := be.ScanWiFi(context.Background())
		return wifiListMsg{ssids, err}
	})
}

func formKeys() *huh.KeyMap {
	km := huh.NewDefaultKeyMap()
	km.Quit = key.NewBinding(key.WithKeys("esc", "ctrl+c"), key.WithHelp("esc", "back"))
	return km
}

func (s Setup) openWifiForm() (tea.Model, tea.Cmd) {
	ssid, pass := "", ""
	s.wifiSSID, s.wifiPass = &ssid, &pass
	var ssidField huh.Field
	if len(s.ssids) > 0 {
		ssidField = huh.NewSelect[string]().Title("WiFi network").Options(huh.NewOptions(s.ssids...)...).Value(s.wifiSSID)
	} else {
		ssidField = huh.NewInput().Title("WiFi network name").Value(s.wifiSSID)
	}
	s.form = huh.NewForm(huh.NewGroup(
		huh.NewNote().Title("Connect to WiFi").Description("Used for this install only; the servers use the WiFi from your config."),
		ssidField,
		huh.NewInput().Title("Password").EchoMode(huh.EchoModePassword).Value(s.wifiPass),
	)).WithKeyMap(formKeys()).WithTheme(huh.ThemeCharm())
	s.state = suWifi
	return s, s.initForm()
}

func (s *Setup) initForm() tea.Cmd {
	cmd := s.form.Init()
	if s.width > 0 {
		next, _ := s.form.Update(tea.WindowSizeMsg{Width: s.width, Height: s.height})
		s.form = next.(*huh.Form)
	}
	return cmd
}

func (s Setup) openForm() (tea.Model, tea.Cmd) {
	if s.ch.Role == "" {
		// First laptop (nobody answers at the coordinator address) is the
		// coordinator; later ones are servers.
		s.ch.Role = sysconf.Node
		if !s.m.CoordFound {
			s.ch.Role = sysconf.Coordinator
		}
	}
	if s.ch.Encryption == "" || !slices.Contains(s.m.EncryptionOptions(), s.ch.Encryption) {
		s.ch.Encryption = s.m.EncryptionOptions()[0]
	}
	if s.ch.SystemDisk == "" && len(s.m.Disks) > 0 {
		s.ch.SystemDisk = s.m.Disks[0].Path
	}
	dc, uc := "", ""
	s.diskConfirm, s.userConfirm = &dc, &uc
	s.ch.DiskPassphrase, s.ch.UserPassword = "", ""
	s.form = newSetupForm(s.m, s.cfg, s.ch, s.diskConfirm, s.userConfirm)
	s.state = suForm
	return s, s.initForm()
}

func (s Setup) updateForm(msg tea.Msg) (tea.Model, tea.Cmd) {
	next, cmd := s.form.Update(msg)
	s.form = next.(*huh.Form)
	switch s.form.State {
	case huh.StateAborted:
		s.form = nil
		s.state = suWelcome
		return s, nil
	case huh.StateCompleted:
		s.form = nil
		if s.state == suWifi {
			s.state, s.busy = suBusy, "Connecting to "+*s.wifiSSID+"…"
			be, ssid, pass := s.be, *s.wifiSSID, *s.wifiPass
			return s, tea.Batch(s.spin.Tick, func() tea.Msg {
				m, err := be.ConnectWiFi(context.Background(), ssid, pass)
				return probeWifiMsg{m, err}
			})
		}
		if s.ch.Hostname == "" {
			s.ch.Hostname = install.DefaultHostname(s.ch.Role)
		}
		if s.ch.Encryption == install.EncNone {
			s.ch.DiskPassphrase = ""
		}
		s.ch.DataDisks = slices.DeleteFunc(s.ch.DataDisks, func(p string) bool { return p == s.ch.SystemDisk })
		s.notice = ""
		return s.startCheck()
	}
	return s, cmd
}

// startCheck runs the prechecks in the background, streaming steps and log
// lines to the screen.
func (s Setup) startCheck() (tea.Model, tea.Cmd) {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.events = make(chan tea.Msg, 64)
	s.state = suCheck
	s.checkErr = nil
	s.steps, s.lines = nil, nil
	events, be, cfg, ch := s.events, s.be, s.cfg, *s.ch
	go func() {
		defer cancel()
		err := be.Precheck(ctx, cfg, ch, func(st install.Step) { events <- stepMsg(st) })
		events <- checkMsg{err}
	}()
	return s, tea.Batch(wait(s.events), s.spin.Tick)
}

// roleNote explains the role question with what the network says.
func roleNote(m install.Machine, cfg config.Config) string {
	if m.CoordFound {
		return "A coordinator answers at " + cfg.CoordLanIP + ", so this laptop is most likely a server."
	}
	return "No coordinator answers at " + cfg.CoordLanIP + ". If this is your first laptop, choose\ncoordinator. If you already installed one, check it is on and its IP is\nreserved in the router, then choose server."
}

// roleWarning flags a role that does not match the network.
func roleWarning(m install.Machine, cfg config.Config, role sysconf.Role) string {
	switch {
	case role == sysconf.Node && !m.CoordFound:
		return "No coordinator answers at " + cfg.CoordLanIP + ". If this is your first laptop,\npress esc and choose coordinator."
	case role == sysconf.Coordinator && m.CoordFound:
		return "A coordinator already answers at " + cfg.CoordLanIP + ". A second one would start a\nseparate mesh. Press esc and choose server unless you replace it."
	}
	return ""
}

func encTitle(e install.Encryption, recommended bool) string {
	t := map[install.Encryption]string{
		install.EncTPM:        "Encrypted, unlocks itself with the TPM chip",
		install.EncPassphrase: "Encrypted, type passphrase at every boot",
		install.EncNone:       "Not encrypted",
	}[e]
	if recommended {
		t += " (recommended)"
	}
	return t
}

func diskTitle(d disks.Disk) string {
	var has []string
	for _, p := range d.Parts {
		if p.Label != "" {
			has = append(has, p.Label)
		} else if p.FSType != "" {
			has = append(has, p.FSType)
		}
	}
	t := fmt.Sprintf("%s  %s  %s", d.Name, disks.HumanSize(d.Size), strings.TrimSpace(d.Vendor+" "+d.Model))
	if len(has) > 0 {
		t += "  (has: " + strings.Join(has, ", ") + ")"
	}
	return t
}

func newSetupForm(m install.Machine, cfg config.Config, ch *install.Choices, diskConfirm, userConfirm *string) *huh.Form {
	var diskOpts []huh.Option[string]
	for _, d := range m.Disks {
		diskOpts = append(diskOpts, huh.NewOption(diskTitle(d), d.Path))
	}
	var encOpts []huh.Option[install.Encryption]
	for i, e := range m.EncryptionOptions() {
		encOpts = append(encOpts, huh.NewOption(encTitle(e, i == 0), e))
	}
	encNote := "TPM 2.0 chip found: the server can reboot on its own and the\ndisk stays unreadable if taken out. Choose \"every boot\" for a\nlaptop that may leave the house."
	if !m.TPM2 || !m.UEFI {
		encNote = "No TPM 2.0 chip (or legacy BIOS): an encrypted disk needs the\npassphrase typed at every boot."
	}

	return huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[sysconf.Role]().Title("What is this machine?").
				Description(roleNote(m, cfg)).
				Options(
					huh.NewOption("Coordinator: the first machine, approves the others", sysconf.Coordinator),
					huh.NewOption("Server: joins the mesh after your approval", sysconf.Node),
				).Value(&ch.Role),
		),
		huh.NewGroup(
			huh.NewInput().Title("Hostname").
				DescriptionFunc(func() string {
					if ch.Role == sysconf.Coordinator {
						return "Leave empty for: coord"
					}
					return "Leave empty for a random name like node-3a2f"
				}, &ch.Role).
				Value(&ch.Hostname).Validate(install.ValidHostname),
		),
		huh.NewGroup(
			huh.NewSelect[string]().Title("Install on which disk?").
				Description("Everything on this disk will be erased.").
				Options(diskOpts...).Value(&ch.SystemDisk),
		),
		huh.NewGroup(
			huh.NewMultiSelect[string]().Title("Also use these disks for data? (optional)").
				Description("Erased, encrypted like the system disk and mounted at /data.").
				OptionsFunc(func() []huh.Option[string] {
					var out []huh.Option[string]
					for _, d := range m.Disks {
						if d.Path != ch.SystemDisk {
							out = append(out, huh.NewOption(diskTitle(d), d.Path))
						}
					}
					return out
				}, &ch.SystemDisk).
				Value(&ch.DataDisks),
		).WithHideFunc(func() bool { return len(m.Disks) < 2 }),
		huh.NewGroup(
			huh.NewNote().Title("Disk encryption").Description(encNote),
			huh.NewSelect[install.Encryption]().Options(encOpts...).Value(&ch.Encryption),
		),
		huh.NewGroup(
			huh.NewInput().Title("Disk passphrase").
				Description(fmt.Sprintf("At least %d characters. Keep it safe: it is the only way in if the TPM\nor boot files change.", install.MinDiskPassphrase)).
				EchoMode(huh.EchoModePassword).Value(&ch.DiskPassphrase).Validate(install.ValidDiskPassphrase),
			huh.NewInput().Title("Disk passphrase again").EchoMode(huh.EchoModePassword).Value(diskConfirm).
				Validate(func(s string) error {
					if s != ch.DiskPassphrase {
						return errors.New("does not match")
					}
					return nil
				}),
		).WithHideFunc(func() bool { return ch.Encryption == install.EncNone }),
		huh.NewGroup(
			huh.NewInput().Title("Password for "+cfg.Username).
				Description(fmt.Sprintf("For console login and sudo (at least %d characters).\nSSH login uses your key, never this password.", install.MinUserPassword)).
				EchoMode(huh.EchoModePassword).Value(&ch.UserPassword).Validate(install.ValidUserPassword),
			huh.NewInput().Title("Password again").EchoMode(huh.EchoModePassword).Value(userConfirm).
				Validate(func(s string) error {
					if s != ch.UserPassword {
						return errors.New("does not match")
					}
					return nil
				}),
		),
	).WithKeyMap(formKeys()).WithTheme(huh.ThemeCharm())
}

func (s Setup) startInstall() (tea.Model, tea.Cmd) {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.events = make(chan tea.Msg, 64)
	s.state = suInstall
	s.steps, s.lines = nil, nil
	s.confirm.Blur()
	events, be, cfg, ch := s.events, s.be, s.cfg, *s.ch
	go func() {
		defer cancel()
		err := be.Install(ctx, cfg, ch, func(st install.Step) { events <- stepMsg(st) })
		events <- installDoneMsg{err}
	}()
	return s, tea.Batch(wait(s.events), s.spin.Tick)
}

func (s Setup) startJoin() (tea.Model, tea.Cmd) {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.state = suJoin
	s.notice = ""
	events, be, cfg, ch := s.events, s.be, s.cfg, *s.ch
	go func() {
		defer cancel()
		host, err := be.Join(ctx, cfg, ch, func(code string) { events <- joinCodeMsg(code) })
		events <- joinDoneMsg{host, err}
	}()
	return s, tea.Batch(wait(s.events), s.spin.Tick)
}

func (s *Setup) addStep(st install.Step) {
	if st.Log != "" {
		s.lines = append(s.lines, st.Log)
		if len(s.lines) > keepLines {
			s.lines = s.lines[len(s.lines)-keepLines:]
		}
		return
	}
	for i := range s.steps {
		if s.steps[i].name == st.Name {
			s.steps[i].done = st.Done
			if st.Done {
				s.steps[i].took = time.Since(s.steps[i].start)
			}
			return
		}
	}
	s.steps = append(s.steps, stepView{name: st.Name, done: st.Done, start: time.Now()})
}

func (s Setup) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("dryserver · server setup") + "\n\n")

	switch s.state {
	case suProbe:
		b.WriteString(s.spin.View() + " Looking at this machine…\n")
	case suBusy:
		b.WriteString(s.spin.View() + " " + s.busy + "\n")
	case suCheck:
		b.WriteString("Checking before anything is erased:\n\n")
		s.viewInstall(&b)
		if s.checkErr != nil {
			b.WriteString("\n" + errStyle.Render(s.checkErr.Error()) + "\n")
			b.WriteString(dimStyle.Render("r retry · enter back to the answers · full log: /tmp/dryserver-install.log") + "\n")
		} else {
			b.WriteString("\n" + dimStyle.Render("Nothing has been changed yet. ctrl+c stops the check.") + "\n")
		}
	case suWelcome:
		s.viewWelcome(&b)
	case suForm, suWifi:
		b.WriteString(s.form.View())
	case suConfirm:
		s.viewConfirm(&b)
	case suInstall:
		s.viewInstall(&b)
	case suJoin:
		s.viewJoin(&b)
	case suDone:
		s.viewDone(&b)
	case suFailed:
		b.WriteString(errStyle.Render("Setup failed: "+s.err.Error()) + "\n\n")
		if len(s.lines) > 0 {
			for _, l := range s.lines[max(len(s.lines)-10, 0):] {
				b.WriteString(dimStyle.Render(truncate(l, 200)) + "\n")
			}
			b.WriteString("\n")
		}
		if s.canRetry {
			b.WriteString(dimStyle.Render("r: retry the install with the same answers · enter/q: leave to a shell (log: /tmp/dryserver-install.log)") + "\n")
		} else {
			b.WriteString(dimStyle.Render("enter/q: leave to a shell (log: /tmp/dryserver-install.log) · run 'dryserver install' to start over") + "\n")
		}
	}

	if s.notice != "" {
		b.WriteString("\n" + errStyle.Render(s.notice) + "\n")
	}
	return b.String()
}

func yesNo(v bool, yes, no string) string {
	if v {
		return okStyle.Render(yes)
	}
	return dimStyle.Render(no)
}

func (s Setup) viewWelcome(b *strings.Builder) {
	m := s.m
	row := func(name, value string) { fmt.Fprintf(b, "  %-9s %s\n", name, value) }
	row("CPU", m.CPU)
	row("Memory", disks.HumanSize(m.RAM))
	row("Firmware", yesNo(m.UEFI, "UEFI", "legacy BIOS"))
	switch {
	case m.TPM2:
		row("TPM 2.0", okStyle.Render("yes"))
	case m.TPMChip:
		row("TPM 2.0", dimStyle.Render("chip found, but the firmware does not measure boot (no auto-unlock)"))
	default:
		row("TPM 2.0", dimStyle.Render("no"))
	}
	if m.Online {
		row("Network", okStyle.Render(m.Net))
	} else {
		row("Network", errStyle.Render("not connected"))
	}
	if m.CoordFound {
		row("Mesh", okStyle.Render("coordinator "+s.cfg.CoordLanIP+" answers: install this laptop as a server"))
	} else if m.Online {
		row("Mesh", dimStyle.Render("no coordinator at "+s.cfg.CoordLanIP+" yet: the first laptop becomes the coordinator"))
	}
	b.WriteString("\n  Disks:\n")
	if len(m.Disks) == 0 {
		b.WriteString(errStyle.Render("    none found") + "\n")
		b.WriteString(dimStyle.Render("    If the laptop has a disk: in its BIOS setup, set the storage/SATA mode\n    from RAID or Intel RST to AHCI (and turn off VMD if listed).") + "\n")
	}
	for _, d := range m.Disks {
		b.WriteString("    " + diskTitle(d) + "\n")
	}
	b.WriteString("\n")
	if m.Online {
		b.WriteString(dimStyle.Render("enter start setup · w other WiFi · q quit to shell") + "\n")
	} else {
		b.WriteString(dimStyle.Render("enter connect to WiFi (or plug in a cable and restart) · q quit to shell") + "\n")
	}
}

func (s Setup) diskByPath(path string) disks.Disk {
	for _, d := range s.m.Disks {
		if d.Path == path {
			return d
		}
	}
	return disks.Disk{Path: path, Name: path}
}

func (s Setup) viewConfirm(b *strings.Builder) {
	ch := s.ch
	var w strings.Builder
	w.WriteString(errStyle.Bold(true).Render("THESE DISKS WILL BE ERASED") + "\n\n")
	w.WriteString(diskTitle(s.diskByPath(ch.SystemDisk)) + "\n")
	for _, d := range ch.DataDisks {
		w.WriteString(diskTitle(s.diskByPath(d)) + "  → /data\n")
	}
	b.WriteString(warnBox.Render(strings.TrimRight(w.String(), "\n")) + "\n\n")

	row := func(name, value string) { fmt.Fprintf(b, "  %-11s %s\n", name, value) }
	role := "SERVER (joins the mesh after your approval)"
	if ch.Role == sysconf.Coordinator {
		role = "COORDINATOR (first machine)"
	}
	row("Role", selStyle.Render(role))
	row("Hostname", ch.Hostname)
	row("Encryption", encTitle(ch.Encryption, false))
	row("User", s.cfg.Username+" (password set)")
	tools := strings.Join(append(s.cfg.ToolList(), s.cfg.ExtraList()...), " ")
	row("Tools", "basics "+tools)
	if w := roleWarning(s.m, s.cfg, ch.Role); w != "" {
		b.WriteString("\n" + errStyle.Render(w) + "\n")
	}
	b.WriteString("\n")
	fmt.Fprintf(b, "Type %s to erase and install: %s\n", selStyle.Render("YES"), s.confirm.View())
	b.WriteString("\n" + dimStyle.Render("enter confirm · esc change answers") + "\n")
}

func (s Setup) viewInstall(b *strings.Builder) {
	for i, st := range s.steps {
		switch {
		case st.done:
			b.WriteString(okStyle.Render("  ✓ ") + st.name + dimStyle.Render("  "+st.took.Round(time.Second).String()) + "\n")
		case i == len(s.steps)-1:
			b.WriteString("  " + s.spin.View() + " " + st.name + dimStyle.Render("  "+time.Since(st.start).Round(time.Second).String()) + "\n")
		default:
			b.WriteString("    " + st.name + "\n")
		}
	}
	b.WriteString("\n")
	n := max(s.height-len(s.steps)-9, 3)
	for _, l := range s.lines[max(len(s.lines)-n, 0):] {
		b.WriteString(dimStyle.Render(truncate(l, 200)) + "\n")
	}
}

func (s Setup) viewJoin(b *strings.Builder) {
	if s.code == "" {
		b.WriteString(s.spin.View() + " Sending join request to the coordinator at " + s.cfg.CoordLanIP + "…\n")
		return
	}
	b.WriteString("Installed. Now approve this machine on the coordinator:\n\n")
	b.WriteString("  " + selStyle.Render("sudo dryserver approve") + "\n\n")
	b.WriteString("Approve only if it shows the same code:\n\n")
	b.WriteString(codeBox.Render(s.code) + "\n\n")
	b.WriteString(s.spin.View() + " Waiting for approval…\n\n")
	b.WriteString(dimStyle.Render("s skip: the server asks again after reboot and shows the code on its screen") + "\n")
}

func (s Setup) viewDone(b *strings.Builder) {
	switch {
	case s.ch.Role == sysconf.Coordinator:
		b.WriteString(okStyle.Render("Coordinator installed.") + "\n\n")
		b.WriteString("New machines ask to join here. Approve them with:\n  sudo dryserver approve\n")
	case s.joinErr != nil:
		b.WriteString(okStyle.Render("Installed.") + " Joining was skipped or failed: " + s.joinErr.Error() + "\n")
		b.WriteString("After reboot the server asks again and shows the code on its screen.\n")
	default:
		fmt.Fprintf(b, "%s Mesh address: %s\n", okStyle.Render("Installed and approved."), meshIP(s.cfg, s.hostNum))
	}
	if s.ch.Encryption == install.EncTPM {
		b.WriteString("\nAt the first boot, type the disk passphrase once. After that the TPM\nunlocks the disk by itself.\n")
	}
	b.WriteString("\nRemove the USB stick, then press " + selStyle.Render("enter") + " to reboot.\n")
	b.WriteString(dimStyle.Render("q: stay in the live system") + "\n")
}

func meshIP(cfg config.Config, n int) string {
	addr, err := sysconf.HostAddr(cfg.WGSubnet, n)
	if err != nil {
		return fmt.Sprintf("host %d", n)
	}
	return strings.Split(addr, "/")[0]
}
