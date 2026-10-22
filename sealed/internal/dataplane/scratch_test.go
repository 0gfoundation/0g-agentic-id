package dataplane

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"seal-verify/internal/privsep"
)

// fakeCLI installs a stand-in 0g-storage-client in a root-only directory put
// first on PATH (RootCommand resolves only there) and returns the file it
// records each run's --file argument and staged content in.
func fakeCLI(t *testing.T) (record string) {
	t.Helper()
	if os.Geteuid() != 0 {
		skipOrFail(t, "needs root: RootCommand resolves binaries only in root-owned directories")
	}
	base, err := os.MkdirTemp("/var/lib", "dataplane-test-")
	if err != nil {
		skipOrFail(t, "no root-only base directory: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	record = filepath.Join(base, "record")
	script := `#!/bin/sh
cmd=$1; shift
file=""
while [ $# -gt 0 ]; do
  case "$1" in --file) file=$2; shift ;; esac
  shift
done
echo "$file" > ` + record + `
case $cmd in
download) printf 'blob-bytes' > "$file" ;;
upload) cat "$file" >> ` + record + `; echo "file uploaded, root = 0x0000000000000000000000000000000000000000000000000000000000000007" ;;
esac
`
	bin := filepath.Join(base, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "0g-storage-client"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	if _, err := privsep.LookPath("0g-storage-client"); err != nil {
		skipOrFail(t, "fake CLI not trusted here: %v", err)
	}
	return record
}

func recorded(t *testing.T, record string) (file, rest string) {
	t.Helper()
	b, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	file, rest, _ = strings.Cut(string(b), "\n")
	return file, rest
}

// Download hands the CLI a path inside a fresh root-only scratch directory,
// returns what the CLI wrote there, and removes the directory.
func TestDownloadStagesInRootOnlyScratch(t *testing.T) {
	record := fakeCLI(t)
	body, err := Download(context.Background(), "0xabc", "http://indexer.invalid")
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "blob-bytes" {
		t.Fatalf("Download = %q, want the CLI's output", body)
	}
	file, _ := recorded(t, record)
	scratch := filepath.Join(privsep.StateDir, "tmp") + "/"
	if !strings.HasPrefix(file, scratch+"download-") {
		t.Fatalf("CLI wrote to %q, want a directory under %s", file, scratch)
	}
	if _, err := os.Lstat(filepath.Dir(file)); !os.IsNotExist(err) {
		t.Fatalf("scratch directory %s left behind: %v", filepath.Dir(file), err)
	}
}

// skipOrFail skips, or with SEALED_PRIVSEP_TESTS=1 (the documented way to
// run the security tests, as root in a Linux container) fails.
func skipOrFail(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("SEALED_PRIVSEP_TESTS") == "1" {
		t.Fatalf("SEALED_PRIVSEP_TESTS=1, but: "+format, args...)
	}
	t.Skipf(format, args...)
}
