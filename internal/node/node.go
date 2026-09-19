// Package node runs on a server (or on the installer for a server being
// installed): it asks the coordinator to join, waits for approval, brings
// up the mesh and keeps it in sync.
package node

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DryBearr/dryserver/internal/config"
	"github.com/DryBearr/dryserver/internal/mesh"
	"github.com/DryBearr/dryserver/internal/registry"
	"github.com/DryBearr/dryserver/internal/runner"
	"github.com/DryBearr/dryserver/internal/sysconf"
)

// Files inside the server's root.
const (
	RegistryKey = "/etc/dryserver/registry_ed25519"
	KnownHosts  = "/etc/dryserver/known_hosts" // pinned coordinator host key
	JoinState   = "/etc/dryserver/join.json"
	WGKey       = "/etc/wireguard/wg0.key"
	WGPub       = "/etc/wireguard/wg0.pub"
	WGConf      = "/etc/wireguard/wg0.conf"
	HostKeyPub  = "/etc/ssh/ssh_host_ed25519_key.pub"
)

// State is kept in JoinState between steps and reboots.
type State struct {
	RequestID string `json:"request_id,omitempty"`
	Code      string `json:"code,omitempty"`
	Host      int    `json:"host,omitempty"` // mesh host number once approved
}

type Node struct {
	Cfg      config.Config
	Hostname string
	Root     string // "/" on the server, "/mnt" from the installer
	Run      runner.Runner
	TmpDir   string // RAM-backed dir for temporary key material; "" = /run
}

func (n Node) path(p string) string { return filepath.Join(n.Root, p) }

func (n Node) read(p string) (string, error) {
	b, err := os.ReadFile(n.path(p))
	return strings.TrimSpace(string(b)), err
}

func (n Node) write(p string, mode fs.FileMode, content string) error {
	dst := n.path(p)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), mode); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// SwitchMAC returns the recorded switch port, "" if none.
func (n Node) SwitchMAC() string {
	mac, _ := n.read(SwitchMACFile)
	return mac
}

func (n Node) LoadState() State {
	var s State
	if b, err := os.ReadFile(n.path(JoinState)); err == nil {
		json.Unmarshal(b, &s)
	}
	return s
}

func (n Node) SaveState(s State) error {
	b, _ := json.MarshalIndent(s, "", "  ")
	return n.write(JoinState, 0o600, string(b)+"\n")
}

// ssh runs one registry command on the coordinator as the registry user.
// The coordinator's host key is pinned in KnownHosts on first contact; the
// pairing code shows the admin which key the node saw.
func (n Node) ssh(ctx context.Context, addr, command, stdin string) (string, error) {
	return n.Run.Run(ctx, runner.Cmd{
		Name: "ssh",
		Args: []string{
			"-i", n.path(RegistryKey),
			"-o", "BatchMode=yes",
			"-o", "ConnectTimeout=10",
			"-o", "IdentitiesOnly=yes",
			"-o", "HostKeyAlgorithms=ssh-ed25519",
			"-o", "StrictHostKeyChecking=accept-new",
			"-o", "HashKnownHosts=no",
			"-o", "UserKnownHostsFile=" + n.path(KnownHosts),
			"-o", "GlobalKnownHostsFile=/dev/null",
			"-o", "LogLevel=ERROR",
			sysconf.RegistryUser + "@" + addr,
			command,
		},
		Stdin:      stdin,
		StdoutOnly: true,
	})
}

// coordinatorKey returns the host key pinned for the coordinator.
func (n Node) coordinatorKey() (string, error) {
	f, err := os.Open(n.path(KnownHosts))
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) >= 3 && fl[1] == "ssh-ed25519" {
			for _, h := range strings.Split(fl[0], ",") {
				if h == n.Cfg.CoordLanIP {
					return fl[1] + " " + fl[2], nil
				}
			}
		}
	}
	return "", errors.New("coordinator host key not recorded")
}

// Request sends a join request and returns the pairing code to show.
func (n Node) Request(ctx context.Context, lanIP string, sw bool) (string, error) {
	wg, err := n.read(WGPub)
	if err != nil {
		return "", err
	}
	hostKey, err := n.read(HostKeyPub)
	if err != nil {
		return "", err
	}
	req := registry.Request{Name: n.Hostname, WGKey: wg, SSHHostKey: hostKey, LanIP: lanIP, Switch: sw}
	body, _ := json.Marshal(req)
	out, err := n.ssh(ctx, n.Cfg.CoordLanIP, "request", string(body))
	if err != nil {
		return "", fmt.Errorf("cannot reach the coordinator at %s (is it installed and switched on?): %w", n.Cfg.CoordLanIP, err)
	}
	var reply struct {
		ID string `json:"id"`
	}
	if json.Unmarshal([]byte(out), &reply) != nil || reply.ID == "" {
		return "", fmt.Errorf("coordinator said: %s", strings.TrimSpace(out))
	}
	coordKey, err := n.coordinatorKey()
	if err != nil {
		return "", err
	}
	code := registry.PairingCode(wg, hostKey, coordKey)
	return code, n.SaveState(State{RequestID: reply.ID, Code: code})
}

// Wait polls until the request is decided. Approved returns the reply with
// the host number and the coordinator's details.
func (n Node) Wait(ctx context.Context, every time.Duration) (registry.StatusReply, error) {
	st := n.LoadState()
	if st.RequestID == "" {
		return registry.StatusReply{}, errors.New("no join request sent")
	}
	for {
		out, err := n.ssh(ctx, n.Cfg.CoordLanIP, "status "+st.RequestID, "")
		if err == nil {
			var r registry.StatusReply
			if json.Unmarshal([]byte(out), &r) == nil {
				switch r.Status {
				case registry.Approved:
					if r.Coordinator == nil || r.Host < 2 {
						return r, errors.New("coordinator sent an incomplete approval")
					}
					return r, nil
				case registry.Rejected:
					return r, errRejected
				}
			}
		} else if strings.Contains(out, "no such request") {
			return registry.StatusReply{}, errExpired
		}
		select {
		case <-ctx.Done():
			return registry.StatusReply{}, ctx.Err()
		case <-time.After(every):
		}
	}
}

var (
	errRejected = errors.New("the coordinator rejected this machine")
	errExpired  = errors.New("the join request expired; a new one is needed")
)

// ErrRejected and ErrExpired let callers react.
func IsRejected(err error) bool { return errors.Is(err, errRejected) }
func IsExpired(err error) bool  { return errors.Is(err, errExpired) }

// Activate writes the mesh config for an approved node: its switch address,
// WireGuard with the coordinator as first peer (the rest arrive with the
// first sync), names and host keys.
func (n Node) Activate(r registry.StatusReply, self mesh.Self, plan sysconf.Params) error {
	st := n.LoadState()
	st.Host = r.Host
	if err := n.SaveState(st); err != nil {
		return err
	}
	plan.HostNum = r.Host
	files, err := sysconf.Render(plan)
	if err != nil {
		return err
	}
	for _, f := range files {
		// Only the switch port file depends on the host number.
		if f.Path == "/etc/systemd/network/10-switch.network" {
			if err := n.write(f.Path, f.Mode, f.Content); err != nil {
				return err
			}
		}
	}
	// Pin the coordinator's key under its mesh address too, for sync.
	key, err := n.coordinatorKey()
	if err != nil {
		return err
	}
	pin := fmt.Sprintf("%s,%s %s\n", n.Cfg.CoordLanIP, mesh.IP(n.Cfg.WGSubnet, 1), key)
	if err := n.write(KnownHosts, 0o600, pin); err != nil {
		return err
	}
	self.Host = r.Host
	return n.Apply(self, []registry.Member{*r.Coordinator, {Host: r.Host, Name: n.Hostname}})
}

// Apply writes WireGuard, hosts and SSH files for the given members.
func (n Node) Apply(self mesh.Self, members []registry.Member) error {
	if err := n.write(WGConf, 0o600, mesh.WGConfig(n.Cfg, self, members)); err != nil {
		return err
	}
	cur, _ := os.ReadFile(n.path("/etc/hosts"))
	if err := n.write("/etc/hosts", 0o644, mesh.Hosts(string(cur), n.Cfg, members)); err != nil {
		return err
	}
	if err := n.write("/etc/ssh/ssh_known_hosts", 0o644, mesh.KnownHosts(n.Cfg, members)); err != nil {
		return err
	}
	return n.write("/etc/ssh/ssh_config.d/20-dryserver.conf", 0o644, mesh.SSHConfig(n.Cfg, members))
}

// Heartbeat is what a node reports on each sync.
type Heartbeat struct {
	LanIP  string `json:"lan_ip"`
	Switch bool   `json:"switch"`
}

// FetchMembers asks the coordinator for the member list over the mesh,
// reporting this node's current LAN IP and cable link.
func (n Node) FetchMembers(ctx context.Context, hb Heartbeat) ([]registry.Member, error) {
	body, _ := json.Marshal(hb)
	out, err := n.ssh(ctx, mesh.IP(n.Cfg.WGSubnet, 1), "peers", string(body))
	if err != nil {
		return nil, err
	}
	var reply struct {
		Members []registry.Member `json:"members"`
	}
	if err := json.Unmarshal([]byte(out), &reply); err != nil || len(reply.Members) == 0 {
		return nil, fmt.Errorf("bad member list from coordinator")
	}
	return reply.Members, nil
}
