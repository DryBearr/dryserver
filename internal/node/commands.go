package node

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/DryBearr/dryserver/internal/config"
	"github.com/DryBearr/dryserver/internal/mesh"
	"github.com/DryBearr/dryserver/internal/registry"
	"github.com/DryBearr/dryserver/internal/runner"
	"github.com/DryBearr/dryserver/internal/sysconf"
)

// IssueFile shows join status on the console login screen.
const IssueFile = "/etc/issue.d/50-dryserver.issue"

func (n Node) run(ctx context.Context, name string, args ...string) error {
	_, err := n.Run.Run(ctx, runner.Cmd{Name: name, Args: args})
	return err
}

// JoinLoop runs at boot on a server that is not approved yet: it sends (or
// resumes) a join request, shows the pairing code on the console and waits.
// On approval it brings up the mesh and disables itself.
func JoinLoop(ctx context.Context, n Node, params sysconf.Params, log io.Writer) error {
	if n.LoadState().Host > 0 {
		return n.run(ctx, "systemctl", "disable", "dryserver-join.service")
	}
	show := func(msg string) {
		fmt.Fprintln(log, msg)
		n.write(IssueFile, 0o644, "\n"+msg+"\n\n")
		n.run(ctx, "agetty", "--reload")
	}
	for {
		st := n.LoadState()
		if st.RequestID == "" {
			lan, err := LocalIP(ctx, n.Run, n.Cfg.CoordLanIP)
			if err == nil {
				st.Code, err = n.Request(ctx, lan, PortLink(n.SwitchMAC()))
			}
			if err != nil {
				show("dryserver: cannot reach the coordinator at " + n.Cfg.CoordLanIP + " yet, retrying: " + err.Error())
				if sleep(ctx, 30*time.Second) != nil {
					return ctx.Err()
				}
				continue
			}
		}
		show(fmt.Sprintf("dryserver: waiting for approval. On the coordinator run: sudo dryserver approve\n"+
			"Approve only if it shows this code:  %s", st.Code))
		r, err := n.Wait(ctx, 5*time.Second)
		switch {
		case err == nil:
			if err := n.activateLive(ctx, r, params); err != nil {
				return err
			}
			show(fmt.Sprintf("dryserver: joined the mesh as %s", mesh.IP(n.Cfg.WGSubnet, r.Host)))
			os.Remove(n.path(IssueFile))
			n.run(ctx, "agetty", "--reload")
			return n.run(ctx, "systemctl", "disable", "dryserver-join.service")
		case IsRejected(err):
			show("dryserver: the coordinator rejected this machine.")
			n.run(ctx, "systemctl", "disable", "dryserver-join.service")
			return err
		case IsExpired(err):
			n.SaveState(State{})
		case ctx.Err() != nil:
			return ctx.Err()
		default:
			if sleep(ctx, 10*time.Second) != nil {
				return ctx.Err()
			}
		}
	}
}

// activateLive activates on the running system and starts the mesh.
func (n Node) activateLive(ctx context.Context, r registry.StatusReply, params sysconf.Params) error {
	params.SwitchMAC = n.SwitchMAC()
	if err := n.Activate(r, mesh.Self{Switch: PortLink(params.SwitchMAC)}, params); err != nil {
		return err
	}
	n.run(ctx, "networkctl", "reload") // switch address
	if err := n.run(ctx, "systemctl", "enable", "--now", "wg-quick@wg0.service", "dryserver-sync.timer"); err != nil {
		return err
	}
	// First full sync; if the tunnel is not up yet the timer retries.
	n.run(ctx, "systemctl", "start", "--no-block", "dryserver-sync.service")
	return nil
}

// Sync refreshes the mesh from the member list. Nodes ask the coordinator
// over the mesh; the coordinator reads its own registry.
func Sync(ctx context.Context, n Node, coordinator bool, store registry.Store) error {
	sw := PortLink(n.SwitchMAC())
	var members []registry.Member
	self := mesh.Self{Switch: sw}
	if coordinator {
		self.Host = 1
		err := store.Update(func(s *registry.State) error {
			if err := s.Heartbeat(1, n.Cfg.CoordLanIP, sw, time.Now()); err != nil {
				return err
			}
			members = s.Members
			return nil
		})
		if err != nil {
			return err
		}
	} else {
		self.Host = n.LoadState().Host
		if self.Host == 0 {
			return fmt.Errorf("not joined yet")
		}
		lan, _ := LocalIP(ctx, n.Run, n.Cfg.CoordLanIP)
		var err error
		if members, err = n.FetchMembers(ctx, Heartbeat{LanIP: lan, Switch: sw}); err != nil {
			return err
		}
	}
	if err := n.Apply(self, n.checkSwitch(ctx, self, members)); err != nil {
		return err
	}
	return n.reloadWG(ctx)
}

// checkSwitch pings each peer's switch address when both sides report a
// cable link, and uses the WiFi/router path for peers that do not answer
// (e.g. a cable into the router instead of the switch).
func (n Node) checkSwitch(ctx context.Context, self mesh.Self, members []registry.Member) []registry.Member {
	if !self.Switch || n.Cfg.WGTransport != config.TransportAuto {
		return members
	}
	out := append([]registry.Member(nil), members...)
	for i, m := range out {
		if m.Host == self.Host || !m.Switch {
			continue
		}
		if n.run(ctx, "ping", "-c", "1", "-W", "1", mesh.IP(n.Cfg.SwitchSubnet, m.Host)) != nil {
			out[i].Switch = false
		}
	}
	return out
}

// reloadWG applies wg0.conf to the running interface without dropping
// connections, or starts it.
func (n Node) reloadWG(ctx context.Context) error {
	if n.run(ctx, "systemctl", "is-active", "--quiet", "wg-quick@wg0.service") != nil {
		return n.run(ctx, "systemctl", "start", "wg-quick@wg0.service")
	}
	stripped, err := n.Run.Run(ctx, runner.Cmd{Name: "wg-quick", Args: []string{"strip", "wg0"}, Quiet: true, StdoutOnly: true})
	if err != nil {
		return err
	}
	key, err := n.read(WGKey)
	if err != nil {
		return err
	}
	dir := n.TmpDir
	if dir == "" {
		dir = "/run"
	}
	f, err := os.CreateTemp(dir, "dryserver-wg0-*.conf") // 0600, RAM-backed
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(WithPrivateKey(stripped, key)); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return n.run(ctx, "wg", "syncconf", "wg0", f.Name())
}

// WithPrivateKey adds the private key to a stripped config: syncconf
// applies the file as the whole interface config and would otherwise clear
// the key. wg0.conf itself never holds the key.
func WithPrivateKey(conf, key string) string {
	return strings.Replace(conf, "[Interface]\n", "[Interface]\nPrivateKey = "+strings.TrimSpace(key)+"\n", 1)
}

func sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}
