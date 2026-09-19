// Package flash writes an ISO image to a USB disk and verifies it.
package flash

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/DryBearr/dryserver/internal/disks"
)

type Phase int

const (
	Writing Phase = iota
	Verifying
)

func (p Phase) String() string {
	if p == Verifying {
		return "Verifying"
	}
	return "Writing"
}

// ProgressFunc receives the number of bytes done out of total in the current phase.
type ProgressFunc func(phase Phase, done, total int64)

const (
	chunkSize = 4 << 20  // 4 MiB per write
	syncEvery = 64 << 20 // flush to the device regularly so progress reflects real writes
)

// Write re-checks that target is still a safe USB disk, unmounts it, writes
// the ISO and reads it back to verify. Needs root.
func Write(ctx context.Context, isoPath string, target disks.Disk, progress ProgressFunc) error {
	// The device list may be stale: the stick could have been swapped for
	// another disk that got the same name. Compare against a fresh listing.
	fresh, err := disks.Find(target.Path)
	if err != nil {
		return err
	}
	if fresh.Size != target.Size || fresh.Model != target.Model {
		return fmt.Errorf("%s changed since it was selected, select it again", target.Path)
	}
	if len(disks.USB([]disks.Disk{fresh})) == 0 {
		return fmt.Errorf("%s is no longer a safe USB target", target.Path)
	}

	for _, m := range fresh.Mounts() {
		if out, err := exec.Command("umount", m).CombinedOutput(); err != nil {
			return fmt.Errorf("umount %s: %v: %s", m, err, bytes.TrimSpace(out))
		}
	}

	if err := writeImage(ctx, isoPath, fresh.Path, fresh.Size, progress); err != nil {
		return err
	}
	rereadPartitions(fresh.Path)
	return nil
}

func writeImage(ctx context.Context, isoPath, devPath string, devSize uint64, progress ProgressFunc) error {
	iso, err := os.Open(isoPath)
	if err != nil {
		return err
	}
	defer iso.Close()
	st, err := iso.Stat()
	if err != nil {
		return err
	}
	total := st.Size()
	if uint64(total) > devSize {
		return fmt.Errorf("image is %s but %s is only %s",
			disks.HumanSize(uint64(total)), devPath, disks.HumanSize(devSize))
	}

	// O_EXCL on a block device fails with EBUSY if anything still has it
	// mounted or claimed, which is the last guard against writing a disk in use.
	dev, err := os.OpenFile(devPath, os.O_WRONLY|syscall.O_EXCL, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", devPath, err)
	}
	defer dev.Close()

	want := sha256.New()
	if err := copyChunks(ctx, dev, io.TeeReader(iso, want), total, Writing, progress, dev.Sync); err != nil {
		return err
	}
	if err := dev.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", devPath, err)
	}
	if err := dev.Close(); err != nil {
		return err
	}

	return verify(ctx, devPath, total, want.Sum(nil), progress)
}

func verify(ctx context.Context, devPath string, total int64, want []byte, progress ProgressFunc) error {
	dev, err := os.Open(devPath)
	if err != nil {
		return err
	}
	defer dev.Close()
	// Drop the kernel buffer cache for the device so the read-back hits the
	// stick itself and not the pages we just wrote. Not a block device in tests.
	_ = unix.IoctlSetInt(int(dev.Fd()), unix.BLKFLSBUF, 0)

	got := sha256.New()
	if err := copyChunks(ctx, got, io.LimitReader(dev, total), total, Verifying, progress, nil); err != nil {
		return err
	}
	if !bytes.Equal(got.Sum(nil), want) {
		return errors.New("verification failed: data on the USB does not match the image (bad stick?)")
	}
	return nil
}

func copyChunks(ctx context.Context, dst io.Writer, src io.Reader, total int64, phase Phase, progress ProgressFunc, flush func() error) error {
	buf := make([]byte, chunkSize)
	var done, sinceFlush int64
	progress(phase, 0, total)
	for done < total {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := io.ReadFull(src, buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return fmt.Errorf("%s: %w", phase, werr)
			}
			done += int64(n)
			sinceFlush += int64(n)
			if flush != nil && sinceFlush >= syncEvery {
				if err := flush(); err != nil {
					return fmt.Errorf("%s: %w", phase, err)
				}
				sinceFlush = 0
			}
			progress(phase, done, total)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%s: %w", phase, err)
		}
	}
	if done != total {
		return fmt.Errorf("%s: short read, %d of %d bytes", phase, done, total)
	}
	return nil
}

// rereadPartitions asks the kernel to pick up the new partition table so the
// stick shows the ISO layout without replugging. Failure is harmless.
func rereadPartitions(devPath string) {
	f, err := os.Open(devPath)
	if err != nil {
		return
	}
	defer f.Close()
	_ = unix.IoctlSetInt(int(f.Fd()), unix.BLKRRPART, 0)
}
