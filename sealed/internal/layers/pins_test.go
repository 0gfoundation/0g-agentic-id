package layers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuntimeLeasePreventsPruningUntilLastProcessExits(t *testing.T) {
	old := PackagesDir
	PackagesDir = t.TempDir()
	t.Cleanup(func() { PackagesDir = old })
	h := strings.Repeat("ab", 32)
	if err := os.Mkdir(filepath.Join(PackagesDir, h), 0755); err != nil {
		t.Fatal(err)
	}
	one, err := PinHarness(h)
	if err != nil {
		t.Fatal(err)
	}
	two, err := PinHarness(h)
	if err != nil {
		t.Fatal(err)
	}
	PrunePackages()
	if !HarnessInstalled(h) {
		t.Fatal("running package pruned")
	}
	one()
	one()
	PrunePackages()
	if !HarnessInstalled(h) {
		t.Fatal("second process still uses package")
	}
	two()
	PrunePackages()
	if HarnessInstalled(h) {
		t.Fatal("unused package was not pruned")
	}
	if _, err := PinHarness(h); err == nil {
		t.Fatal("missing package leased")
	}
}
