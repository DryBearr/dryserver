package flash

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

// writeImage works on regular files too, which stand in for a USB device here.
func TestWriteImage(t *testing.T) {
	dir := t.TempDir()
	img := make([]byte, 9<<20+123) // not a multiple of the chunk size
	rand.Read(img)
	iso := filepath.Join(dir, "test.iso")
	dev := filepath.Join(dir, "dev")
	if err := os.WriteFile(iso, img, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dev, make([]byte, 16<<20), 0o644); err != nil {
		t.Fatal(err)
	}

	last := map[Phase]int64{}
	err := writeImage(context.Background(), iso, dev, 16<<20, func(p Phase, done, total int64) {
		if total != int64(len(img)) {
			t.Errorf("total = %d", total)
		}
		last[p] = done
	})
	if err != nil {
		t.Fatal(err)
	}
	if last[Writing] != int64(len(img)) || last[Verifying] != int64(len(img)) {
		t.Errorf("final progress = %v", last)
	}
	got, _ := os.ReadFile(dev)
	if !bytes.Equal(got[:len(img)], img) {
		t.Error("device content differs from image")
	}
}

func TestWriteImageTooBig(t *testing.T) {
	dir := t.TempDir()
	iso := filepath.Join(dir, "test.iso")
	os.WriteFile(iso, make([]byte, 2048), 0o644)
	err := writeImage(context.Background(), iso, filepath.Join(dir, "dev"), 1024, func(Phase, int64, int64) {})
	if err == nil {
		t.Fatal("expected size error")
	}
}

func TestWriteImageCancel(t *testing.T) {
	dir := t.TempDir()
	iso := filepath.Join(dir, "test.iso")
	dev := filepath.Join(dir, "dev")
	os.WriteFile(iso, make([]byte, 8<<20), 0o644)
	os.WriteFile(dev, nil, 0o644)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := writeImage(ctx, iso, dev, 16<<20, func(Phase, int64, int64) {}); err != context.Canceled {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}
