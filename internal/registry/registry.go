// Package registry keeps the list of mesh members on the coordinator:
// pending join requests, approved nodes and the scan report. Nothing joins
// without an admin approving a request whose pairing code matches the code
// shown on the new machine.
package registry

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
)

const (
	MaxPending = 20
	RequestTTL = time.Hour
)

// Member is an approved mesh node. The coordinator is member 1.
type Member struct {
	Host       int       `json:"host"` // mesh host number: 10.66.0.<host>
	Name       string    `json:"name"`
	WGKey      string    `json:"wg_key"`
	SSHHostKey string    `json:"ssh_host_key"`
	LanIP      string    `json:"lan_ip"`
	Switch     bool      `json:"switch"` // has a cable link to the switch
	Approved   time.Time `json:"approved"`
	LastSeen   time.Time `json:"last_seen"`
}

type Status string

const (
	Pending  Status = "pending"
	Approved Status = "approved"
	Rejected Status = "rejected"
)

// Request is a machine asking to join.
type Request struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	WGKey      string    `json:"wg_key"`
	SSHHostKey string    `json:"ssh_host_key"`
	LanIP      string    `json:"lan_ip"`
	Switch     bool      `json:"switch"`
	Code       string    `json:"code"` // as computed by the coordinator
	Created    time.Time `json:"created"`
	Status     Status    `json:"status"`
	Host       int       `json:"host,omitempty"`
}

// Device is a scan-report entry: something on the network that is not a
// member.
type Device struct {
	IP     string    `json:"ip"`
	MAC    string    `json:"mac"`
	Vendor string    `json:"vendor"`
	SSH    bool      `json:"ssh"`
	Seen   time.Time `json:"seen"`
}

type State struct {
	Members  []Member  `json:"members"`
	Requests []Request `json:"requests"`
	Unknown  []Device  `json:"unknown"`
	Scanned  time.Time `json:"scanned"`
}

// PairingCode is the 6-digit code both sides show. It covers the new
// node's keys and the coordinator's SSH host key as the node saw it, so a
// fake coordinator or a swapped request gives a different code.
func PairingCode(wgKey, nodeHostKey, coordHostKey string) string {
	h := sha256.Sum256([]byte(strings.Join([]string{
		"dryserver-pairing-v1", strings.TrimSpace(wgKey), keyBody(nodeHostKey), keyBody(coordHostKey),
	}, "\n")))
	n := binary.BigEndian.Uint32(h[:4]) % 1_000_000
	return fmt.Sprintf("%03d %03d", n/1000, n%1000)
}

// keyBody drops the comment of an OpenSSH public key line.
func keyBody(k string) string {
	f := strings.Fields(k)
	if len(f) >= 2 {
		return f[0] + " " + f[1]
	}
	return strings.TrimSpace(k)
}

var (
	nameRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	sshKeyRe = regexp.MustCompile(`^(ssh-ed25519|ecdsa-sha2-nistp256|ssh-rsa) [A-Za-z0-9+/]+={0,3}( [^\s]*)?$`)
)

// ValidateRequest checks untrusted join-request fields strictly.
func ValidateRequest(r Request) error {
	if !nameRe.MatchString(r.Name) {
		return errors.New("bad hostname")
	}
	if b, err := base64.StdEncoding.DecodeString(r.WGKey); err != nil || len(b) != 32 {
		return errors.New("bad WireGuard key")
	}
	if !sshKeyRe.MatchString(strings.TrimSpace(r.SSHHostKey)) {
		return errors.New("bad SSH host key")
	}
	if ip := net.ParseIP(r.LanIP); ip == nil || ip.To4() == nil {
		return errors.New("bad LAN IP")
	}
	return nil
}

// AddRequest validates and stores a join request, returning its ID.
func (s *State) AddRequest(r Request, coordHostKey string, now time.Time) (string, error) {
	if err := ValidateRequest(r); err != nil {
		return "", err
	}
	s.prune(now)
	for _, m := range s.Members {
		if m.Name == r.Name {
			return "", fmt.Errorf("%s is already a member; remove it first to re-join", r.Name)
		}
		if m.WGKey == r.WGKey {
			return "", errors.New("this WireGuard key already belongs to a member")
		}
	}
	pending := 0
	for _, q := range s.Requests {
		if q.Status != Pending {
			continue
		}
		// A retry from the same machine (same key) gets its existing request.
		if q.WGKey == r.WGKey && q.Name == r.Name && q.SSHHostKey == r.SSHHostKey {
			return q.ID, nil
		}
		if q.Name == r.Name {
			return "", fmt.Errorf("another machine is already asking to join as %s", r.Name)
		}
		pending++
	}
	if pending >= MaxPending {
		return "", errors.New("too many pending requests; approve or reject some first")
	}
	id := make([]byte, 8)
	rand.Read(id)
	r.ID = hex.EncodeToString(id)
	r.Code = PairingCode(r.WGKey, r.SSHHostKey, coordHostKey)
	r.Created = now
	r.Status = Pending
	r.Host = 0
	s.Requests = append(s.Requests, r)
	return r.ID, nil
}

// prune drops requests older than RequestTTL.
func (s *State) prune(now time.Time) {
	s.Requests = slices.DeleteFunc(s.Requests, func(r Request) bool { return now.Sub(r.Created) > RequestTTL })
}

func (s *State) request(id string) (*Request, error) {
	for i := range s.Requests {
		if s.Requests[i].ID == id {
			return &s.Requests[i], nil
		}
	}
	return nil, errors.New("no such request (expired?)")
}

// RequestStatus returns what a waiting node may learn about its request.
// A pending request whose key already belongs to a member (the machine was
// approved through a duplicate request) reports that membership.
func (s *State) RequestStatus(id string, now time.Time) (Request, error) {
	s.prune(now)
	r, err := s.request(id)
	if err != nil {
		return Request{}, err
	}
	if r.Status == Pending {
		for _, m := range s.Members {
			if m.WGKey == r.WGKey {
				r.Status, r.Host = Approved, m.Host
			}
		}
	}
	return *r, nil
}

// Approve turns a pending request into a member with the next free host
// number (1 is the coordinator). maxHost is the last usable host number.
func (s *State) Approve(id string, maxHost int, now time.Time) (Member, error) {
	r, err := s.request(id)
	if err != nil {
		return Member{}, err
	}
	if r.Status != Pending {
		return Member{}, fmt.Errorf("request is %s", r.Status)
	}
	host := 0
	for n := 2; n <= maxHost; n++ {
		if !slices.ContainsFunc(s.Members, func(m Member) bool { return m.Host == n }) {
			host = n
			break
		}
	}
	if host == 0 {
		return Member{}, errors.New("mesh subnet is full")
	}
	m := Member{Host: host, Name: r.Name, WGKey: r.WGKey, SSHHostKey: r.SSHHostKey,
		LanIP: r.LanIP, Switch: r.Switch, Approved: now, LastSeen: now}
	s.Members = append(s.Members, m)
	r.Status, r.Host = Approved, host
	// Settle other pending requests: the same machine's duplicates are
	// approved with it; another machine asking under the same name is not.
	for i := range s.Requests {
		q := &s.Requests[i]
		switch {
		case q.Status != Pending:
		case q.WGKey == m.WGKey:
			q.Status, q.Host = Approved, host
		case q.Name == m.Name:
			q.Status = Rejected
		}
	}
	return m, nil
}

func (s *State) Reject(id string) error {
	r, err := s.request(id)
	if err != nil {
		return err
	}
	if r.Status != Pending {
		return fmt.Errorf("request is %s", r.Status)
	}
	r.Status = Rejected
	return nil
}

// Remove revokes a member. Its peers drop it at their next sync.
func (s *State) Remove(name string) error {
	i := slices.IndexFunc(s.Members, func(m Member) bool { return m.Name == name })
	switch {
	case i < 0:
		return fmt.Errorf("%s is not a member", name)
	case s.Members[i].Host == 1:
		return errors.New("the coordinator cannot be removed")
	}
	s.Members = slices.Delete(s.Members, i, i+1)
	return nil
}

// Heartbeat records a member's current LAN IP and switch link. host
// identifies the member by its mesh address, which WireGuard ties to its key.
func (s *State) Heartbeat(host int, lanIP string, sw bool, now time.Time) error {
	i := slices.IndexFunc(s.Members, func(m Member) bool { return m.Host == host })
	if i < 0 {
		return errors.New("not a member")
	}
	if ip := net.ParseIP(lanIP); ip != nil && ip.To4() != nil {
		s.Members[i].LanIP = lanIP
	}
	s.Members[i].Switch = sw
	s.Members[i].LastSeen = now
	return nil
}

func (s *State) Pending() []Request {
	var out []Request
	for _, r := range s.Requests {
		if r.Status == Pending {
			out = append(out, r)
		}
	}
	return out
}

// Store is the registry file, guarded by an exclusive lock.
type Store struct {
	Path string
}

// Update loads the state, calls fn and saves the result atomically while
// holding the lock.
func (st Store) Update(fn func(*State) error) error {
	if err := os.MkdirAll(filepath.Dir(st.Path), 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(st.Path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	fixOwner(lock.Name())
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	s, err := st.load()
	if err != nil {
		return err
	}
	if err := fn(&s); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := st.Path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	fixOwner(tmp)
	return os.Rename(tmp, st.Path)
}

// Read returns a snapshot of the state.
func (st Store) Read() (State, error) {
	var s State
	err := st.Update(func(cur *State) error { s = *cur; return nil })
	return s, err
}

func (st Store) load() (State, error) {
	var s State
	b, err := os.ReadFile(st.Path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(b, &s)
}
