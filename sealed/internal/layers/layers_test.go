package layers

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"seal-verify/internal/framework"
)

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestParseHash(t *testing.T) {
	h := strings.Repeat("ab", 32)
	for _, in := range []string{h, "0x" + h, "0x" + strings.ToUpper(h), " 0x" + h + "\n"} {
		if got, ok := ParseHash(in); !ok || got != h {
			t.Fatalf("ParseHash(%q) = %q, %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "0x", strings.Repeat("ab", 31), "0x" + strings.Repeat("zz", 32), strings.Repeat("ab", 33)} {
		if _, ok := ParseHash(in); ok {
			t.Fatalf("ParseHash(%q) accepted", in)
		}
	}
}

func readAll(r io.ReadCloser) ([]byte, error) {
	defer r.Close()
	return io.ReadAll(r)
}

func TestVerifyingReader(t *testing.T) {
	data := []byte("sealed program")
	if got, err := readAll(VerifyingReader(io.NopCloser(bytes.NewReader(data)), sum(data))); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("matching bytes: %q, %v", got, err)
	}
	if _, err := readAll(VerifyingReader(io.NopCloser(bytes.NewReader(data)), sum([]byte("other")))); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("other bytes: %v, want ErrHashMismatch", err)
	}
	old := maxArtifactBytes
	maxArtifactBytes = 4
	defer func() { maxArtifactBytes = old }()
	if _, err := readAll(VerifyingReader(io.NopCloser(bytes.NewReader(data)), sum(data))); err == nil {
		t.Fatal("bytes beyond the limit accepted")
	}
}

func TestFetchArtifact(t *testing.T) {
	data := []byte("harness package")
	h := sum(data)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/artifacts/0x" + h:
			_, _ = w.Write(data)
		case "/artifacts/0x" + strings.Repeat("11", 32):
			_, _ = w.Write([]byte("not what was asked for"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("ATTESTOR_ALLOW_UNPINNED_DEV", "true")

	body, err := FetchArtifact(context.Background(), srv.URL, h)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := readAll(body); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("fetched %q, %v", got, err)
	}
	body, err = FetchArtifact(context.Background(), srv.URL, strings.Repeat("11", 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readAll(body); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("wrong bytes: %v, want ErrHashMismatch", err)
	}
	if _, err := FetchArtifact(context.Background(), srv.URL, strings.Repeat("22", 32)); err == nil {
		t.Fatal("404 accepted")
	}
}

// tarEntry is one entry of a test package.
type tarEntry struct {
	name, body, link string
	typ              byte
	mode             int64
}

func makePackage(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: e.mode, Linkname: e.link, Size: int64(len(e.body))}
		if e.typ != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// usePackagesDir points PackagesDir and framework.StateDir at temp dirs.
func usePackagesDir(t *testing.T) {
	t.Helper()
	oldP, oldS := PackagesDir, framework.StateDir
	PackagesDir = filepath.Join(t.TempDir(), "0g-harness")
	framework.StateDir = t.TempDir()
	t.Cleanup(func() { PackagesDir, framework.StateDir = oldP, oldS })
}

func install(pkg []byte, hash string) error {
	return InstallHarness(VerifyingReader(io.NopCloser(bytes.NewReader(pkg)), hash), hash)
}

func TestInstallHarness(t *testing.T) {
	usePackagesDir(t)
	pkg := makePackage(t, []tarEntry{
		{name: "./", typ: tar.TypeDir, mode: 0o755},
		{name: "./package.json", typ: tar.TypeReg, mode: 0o644, body: `{"version":"1"}`},
		{name: "./bin/", typ: tar.TypeDir, mode: 0o700},
		{name: "./bin/0g-harness.mjs", typ: tar.TypeReg, mode: 0o700, body: "#!/usr/bin/env node\n"},
		{name: "./node_modules/.bin/", typ: tar.TypeDir, mode: 0o755},
		{name: "./node_modules/.bin/cli", typ: tar.TypeSymlink, link: "../../bin/0g-harness.mjs"},
	})
	h := sum(pkg)
	if HarnessInstalled(h) {
		t.Fatal("installed before InstallHarness")
	}
	if err := install(pkg, h); err != nil {
		t.Fatal(err)
	}
	if !HarnessInstalled(h) {
		t.Fatal("not installed")
	}
	dir := HarnessDir(h)
	for p, want := range map[string]fs.FileMode{
		"":                      fs.ModeDir | 0o755,
		"bin":                   fs.ModeDir | 0o755,
		"package.json":          0o644,
		"bin/0g-harness.mjs":    0o755,
		"node_modules/.bin":     fs.ModeDir | 0o755,
		"node_modules/.bin/cli": fs.ModeSymlink,
	} {
		fi, err := os.Lstat(filepath.Join(dir, p))
		if err != nil {
			t.Fatal(err)
		}
		got := fi.Mode()
		if want == fs.ModeSymlink {
			got &= fs.ModeType
		}
		if got != want {
			t.Fatalf("%s: mode %v, want %v", p, got, want)
		}
	}
	if link, _ := os.Readlink(filepath.Join(dir, "node_modules/.bin/cli")); link != "../../bin/0g-harness.mjs" {
		t.Fatalf("link holds %q", link)
	}
	// Installing again leaves it as it is.
	if err := install(pkg, h); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(PackagesDir); len(entries) != 1 {
		t.Fatalf("%d entries in PackagesDir, want just the package", len(entries))
	}
}

func TestInstallHarnessRefuses(t *testing.T) {
	for _, test := range []struct {
		name    string
		entries []tarEntry
	}{
		{"a name that leaves the package", []tarEntry{{name: "../escape", typ: tar.TypeReg, body: "x"}}},
		{"an absolute name", []tarEntry{{name: "/etc/escape", typ: tar.TypeReg, body: "x"}}},
		{"a link that leaves the package", []tarEntry{{name: "l", typ: tar.TypeSymlink, link: "../../etc/passwd"}}},
		{"an absolute link", []tarEntry{{name: "l", typ: tar.TypeSymlink, link: "/etc/passwd"}}},
		{"a hard link", []tarEntry{{name: "f", typ: tar.TypeReg, body: "x"}, {name: "g", typ: tar.TypeLink, link: "f"}}},
		{"a device", []tarEntry{{name: "d", typ: tar.TypeChar}}},
		{"a file through a link", []tarEntry{{name: "l", typ: tar.TypeSymlink, link: "."}, {name: "l/f", typ: tar.TypeReg, body: "x"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			usePackagesDir(t)
			pkg := makePackage(t, test.entries)
			h := sum(pkg)
			if err := install(pkg, h); err == nil {
				t.Fatal("installed")
			}
			if HarnessInstalled(h) {
				t.Fatal("left an installed package")
			}
			if entries, _ := os.ReadDir(PackagesDir); len(entries) != 0 {
				t.Fatalf("left %d entries in PackagesDir", len(entries))
			}
		})
	}
}

func TestInstallHarnessRefusesAMismatch(t *testing.T) {
	usePackagesDir(t)
	pkg := makePackage(t, []tarEntry{{name: "f", typ: tar.TypeReg, body: "x"}})
	other := strings.Repeat("ab", 32)
	if err := install(pkg, other); err == nil {
		t.Fatal("installed a package that does not hash to its name")
	}
	if HarnessInstalled(other) {
		t.Fatal("left it installed")
	}
}

func TestBaseHarnessAndSelection(t *testing.T) {
	usePackagesDir(t)
	if _, err := BaseHarness(); err == nil {
		t.Fatal("base named without a base file")
	}
	h := strings.Repeat("ab", 32)
	if err := os.MkdirAll(PackagesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(PackagesDir, "base"), []byte(h+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := BaseHarness(); err != nil || got != h {
		t.Fatalf("BaseHarness = %q, %v", got, err)
	}

	if s := LoadHarnessSelection(); s != (HarnessSelection{}) {
		t.Fatalf("selection without a record: %+v", s)
	}
	want := HarnessSelection{Current: h, Previous: strings.Repeat("cd", 32)}
	if err := SaveHarnessSelection(want); err != nil {
		t.Fatal(err)
	}
	if got := LoadHarnessSelection(); got != want {
		t.Fatalf("selection %+v, want %+v", got, want)
	}

	if HarnessFailed(h) {
		t.Fatal("failed before MarkHarnessFailed")
	}
	MarkHarnessFailed(h)
	if !HarnessFailed(h) {
		t.Fatal("not failed after MarkHarnessFailed")
	}
}

func TestLoaderHandOver(t *testing.T) {
	old, oldSignal := LoaderDir, signalLoader
	LoaderDir = filepath.Join(t.TempDir(), "loader")
	signals := 0
	signalLoader = func() error { signals++; return nil }
	t.Cleanup(func() { LoaderDir, signalLoader = old, oldSignal })

	program := []byte("sealed v2")
	h := sum(program)
	if err := StageSealed(VerifyingReader(io.NopCloser(bytes.NewReader(program)), strings.Repeat("ab", 32)), strings.Repeat("ab", 32)); err == nil {
		t.Fatal("staged a program that does not hash to its name")
	}
	if _, err := os.Lstat(StagedSealedPath(strings.Repeat("ab", 32))); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("left a mismatched program staged: %v", err)
	}
	if err := StageSealed(VerifyingReader(io.NopCloser(bytes.NewReader(program)), h), h); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(StagedSealedPath(h))
	if err != nil || fi.Mode() != 0o500 {
		t.Fatalf("staged program: %v, %v", fi.Mode(), err)
	}
	if err := RequestSwitch(h); err != nil || signals != 1 {
		t.Fatalf("RequestSwitch: %v, signals %d", err, signals)
	}
	if b, _ := os.ReadFile(filepath.Join(LoaderDir, "request")); string(b) != h {
		t.Fatalf("request holds %q", b)
	}
	if err := Confirm(h); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(LoaderDir, "confirmed")); string(b) != h {
		t.Fatalf("confirmed holds %q", b)
	}
	if err := MarkLayered(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(LoaderDir, "layered")); err != nil {
		t.Fatal(err)
	}
	if SealedFailed(h) {
		t.Fatal("failed without the loader saying so")
	}
	if err := os.WriteFile(filepath.Join(LoaderDir, "failed"), []byte(strings.Repeat("cd", 32)+"\n"+h+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !SealedFailed(h) {
		t.Fatal("not failed after the loader said so")
	}
}
