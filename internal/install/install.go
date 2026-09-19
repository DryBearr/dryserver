// Package install holds what the laptop setup screen needs: the machine
// description, the user's choices and the Backend that does the work. The
// real backend wipes and installs; the demo backend only pretends, so the
// screens can be tried and tested anywhere.
package install

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"

	"github.com/DryBearr/dryserver/internal/config"
	"github.com/DryBearr/dryserver/internal/disks"
	"github.com/DryBearr/dryserver/internal/sysconf"
)

// Machine describes the laptop the installer runs on.
type Machine struct {
	CPU  string
	RAM  uint64 // bytes
	UEFI bool
	// TPM2 means a TPM 2.0 chip whose firmware measures the boot, which
	// TPM unlock needs. TPMChip alone means the chip exists but the
	// firmware does not measure (TPM unlock would never work).
	TPM2    bool
	TPMChip bool
	Disks   []disks.Disk // install targets: internal disks, live USB excluded
	Online  bool
	Net     string // e.g. "WiFi Home (192.168.1.23)"
}

type Encryption string

const (
	EncTPM        Encryption = "tpm"        // LUKS2, unlocked by the TPM; passphrase as fallback
	EncPassphrase Encryption = "passphrase" // LUKS2, passphrase at every boot
	EncNone       Encryption = "none"
)

// EncryptionOptions lists the modes this machine supports, best first.
// TPM unlock needs UEFI (signed UKI) and a TPM 2.0 chip.
func (m Machine) EncryptionOptions() []Encryption {
	if m.UEFI && m.TPM2 {
		return []Encryption{EncTPM, EncPassphrase, EncNone}
	}
	return []Encryption{EncPassphrase, EncNone}
}

// Choices are the answers from the setup screen.
type Choices struct {
	Role           sysconf.Role
	Hostname       string
	SystemDisk     string   // device path
	DataDisks      []string // device paths, encrypted and mounted under /data
	Encryption     Encryption
	DiskPassphrase string
	UserPassword   string
}

// Step reports install progress. A step is sent when it starts (Done
// false) and when it ends; Log carries output lines in between.
type Step struct {
	Name string
	Done bool
	Log  string
}

type Backend interface {
	Probe(ctx context.Context) (Machine, error)
	ScanWiFi(ctx context.Context) ([]string, error)
	ConnectWiFi(ctx context.Context, ssid, pass string) (Machine, error)
	// Precheck runs before anything is written: packages exist, the
	// coordinator answers (node role).
	Precheck(ctx context.Context, cfg config.Config, ch Choices) error
	Install(ctx context.Context, cfg config.Config, ch Choices, progress func(Step)) error
	// Join sends the join request, reports the pairing code and blocks
	// until the coordinator approves (returns the mesh host number) or
	// rejects. Cancelling ctx skips joining; the server retries at boot.
	Join(ctx context.Context, cfg config.Config, ch Choices, code func(string)) (int, error)
	Reboot() error
}

var ErrRejected = errors.New("the coordinator rejected this machine")

var hostnameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func ValidHostname(s string) error {
	if s != "" && !hostnameRe.MatchString(s) {
		return errors.New("lowercase letters, digits and -, not starting or ending with -")
	}
	return nil
}

const (
	MinDiskPassphrase = 12
	MinUserPassword   = 10
)

func ValidDiskPassphrase(s string) error {
	if len(s) < MinDiskPassphrase {
		return fmt.Errorf("at least %d characters; a few random words work well", MinDiskPassphrase)
	}
	return nil
}

func ValidUserPassword(s string) error {
	if len(s) < MinUserPassword {
		return fmt.Errorf("at least %d characters", MinUserPassword)
	}
	return nil
}

// DefaultHostname is "coord" for the coordinator and node-<4 hex> otherwise.
func DefaultHostname(role sysconf.Role) string {
	if role == sysconf.Coordinator {
		return "coord"
	}
	b := make([]byte, 2)
	rand.Read(b)
	return "node-" + hex.EncodeToString(b)
}
