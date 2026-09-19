package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// DefaultPath is the registry file on the coordinator. Its directory is
// owned by the registry user, which runs Serve.
const DefaultPath = "/var/lib/dryserver/registry.json"

const maxInput = 16 << 10

// Mesh describes the mesh subnet so Serve can tell members by address.
type Mesh interface {
	// HostOf returns the member host number for a mesh IP, or 0.
	HostOf(ip net.IP) int
}

// StatusReply answers "status". When approved it carries what the node
// needs to bring up WireGuard towards the coordinator.
type StatusReply struct {
	Status      Status  `json:"status"`
	Host        int     `json:"host,omitempty"`
	Coordinator *Member `json:"coordinator,omitempty"`
}

var idRe = regexp.MustCompile(`^[0-9a-f]{16}$`)

// Serve handles one call from the SSH forced command. cmdline is
// SSH_ORIGINAL_COMMAND, client is SSH_CLIENT ("ip port port").
//
//	request      stdin: Request JSON      -> {"id": ...}        (any source)
//	status ID                             -> StatusReply        (any source)
//	peers        stdin: {"lan_ip","switch"} -> {"members": [...]} (mesh members only)
func Serve(st Store, mesh Mesh, coordHostKey, cmdline, client string, in io.Reader, out io.Writer, now time.Time) error {
	f := strings.Fields(cmdline)
	if len(f) == 0 {
		return errors.New("no command")
	}
	enc := json.NewEncoder(out)
	switch {
	case f[0] == "request" && len(f) == 1:
		var r Request
		if err := json.NewDecoder(io.LimitReader(in, maxInput)).Decode(&r); err != nil {
			return errors.New("bad request JSON")
		}
		var id string
		err := st.Update(func(s *State) (err error) {
			id, err = s.AddRequest(r, coordHostKey, now)
			return err
		})
		if err != nil {
			return err
		}
		return enc.Encode(map[string]string{"id": id})

	case f[0] == "status" && len(f) == 2 && idRe.MatchString(f[1]):
		var reply StatusReply
		err := st.Update(func(s *State) error {
			r, err := s.RequestStatus(f[1], now)
			if err != nil {
				return err
			}
			reply.Status, reply.Host = r.Status, r.Host
			if r.Status == Approved {
				for _, m := range s.Members {
					if m.Host == 1 {
						c := m
						reply.Coordinator = &c
					}
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		return enc.Encode(reply)

	case f[0] == "peers" && len(f) == 1:
		ip := net.ParseIP(strings.Fields(client + " ")[0])
		host := 0
		if ip != nil {
			host = mesh.HostOf(ip)
		}
		if host == 0 {
			return errors.New("peers is only answered over the mesh")
		}
		var hb struct {
			LanIP  string `json:"lan_ip"`
			Switch bool   `json:"switch"`
		}
		if err := json.NewDecoder(io.LimitReader(in, maxInput)).Decode(&hb); err != nil {
			return errors.New("bad heartbeat JSON")
		}
		var members []Member
		err := st.Update(func(s *State) error {
			if err := s.Heartbeat(host, hb.LanIP, hb.Switch, now); err != nil {
				return err
			}
			members = s.Members
			return nil
		})
		if err != nil {
			return err
		}
		return enc.Encode(map[string][]Member{"members": members})
	}
	return fmt.Errorf("unknown command %q", f[0])
}

// fixOwner hands a file written by root back to the owner of its
// directory, so the registry user can keep writing it.
func fixOwner(path string) {
	if os.Geteuid() != 0 {
		return
	}
	st, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		os.Chown(path, int(sys.Uid), int(sys.Gid))
	}
}
