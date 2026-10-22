package dataplane

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Where the images that build the download CLI install it (their
// COPY --from=storage-builder line): a root-only PATH directory, where
// privsep.RootCommand resolves it.
const installedStorageClient = "/usr/local/bin/0g-storage-client"

// Well-known test key; never used outside tests.
const testSealPrivHex = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"

const testRoot = "0x1111111111111111111111111111111111111111111111111111111111111111"

func assertNoKey(t *testing.T, what, s string) {
	t.Helper()
	if strings.Contains(strings.ToLower(s), testSealPrivHex) {
		t.Fatalf("%s carries the signing key: %q", what, s)
	}
}

// dockerStage returns the lines of the build stage named name in a
// Dockerfile: from its FROM line up to the next FROM line.
func dockerStage(df, name string) string {
	var out []string
	in := false
	for _, line := range strings.Split(df, "\n") {
		if strings.HasPrefix(line, "FROM ") {
			in = strings.HasSuffix(line, " AS "+name)
		}
		if in {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n") + "\n"
}

// TestDockerfiles_BuildOnlyTheDownloadCLI checks every image that has a
// storage-builder stage: it builds only the download CLI, at the
// 0g-storage-client version pinned in sealed's go.mod (the SDK sealed
// uploads with), rather than from a floating clone, refuses to build when
// go.mod replaces that module, and installs it at the
// path sealed runs. No image builds or installs an upload helper any more.
// It also pins which images those are, as the docs name them
// (TRUST_MODEL.md, QUIRKS.md, ARCHITECTURE.md): the base images
// images/openclaw and images/sealed carry no storage CLI.
func TestDockerfiles_BuildOnlyTheDownloadCLI(t *testing.T) {
	files, err := filepath.Glob("../../images/*/Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, "../../Dockerfile")
	var checked []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		df := string(b)
		if strings.Contains(df, "zg-upload") {
			t.Errorf("%s still mentions the removed zg-upload helper", f)
		}
		if !strings.Contains(df, " AS storage-builder\n") {
			continue
		}
		checked = append(checked, f)
		stage := dockerStage(df, "storage-builder")
		for _, want := range []string{
			"COPY go.mod go.sum ./\n",
			"go list -m -f '{{.Version}}' github.com/0gfoundation/0g-storage-client",
			`test -z "$(go list -m -f '{{if .Replace}}replaced{{end}}' github.com/0gfoundation/0g-storage-client)"`,
			`go install -ldflags="-s -w" "github.com/0gfoundation/0g-storage-client@$V"`,
		} {
			if !strings.Contains(stage, want) {
				t.Errorf("%s: storage-builder stage missing %q", f, want)
			}
		}
		if strings.Contains(stage, "git clone") {
			t.Errorf("%s: builds 0g-storage-client from a git clone; build it at the go.mod version", f)
		}
		want := "COPY --from=storage-builder /out/0g-storage-client " + installedStorageClient + "\n"
		if !strings.Contains(df, want) {
			t.Errorf("%s: missing %q", f, want)
		}
		if n := strings.Count(df, "COPY --from=storage-builder "); n != 1 {
			t.Errorf("%s: %d COPY --from=storage-builder lines, want exactly the CLI's", f, n)
		}
	}
	slices.Sort(checked)
	want := []string{"../../Dockerfile", "../../images/dsh/Dockerfile", "../../images/hermes/Dockerfile", "../../images/prime/Dockerfile", "../../images/sealed/Dockerfile"}
	if !slices.Equal(checked, want) {
		t.Fatalf("Dockerfiles with a storage-builder stage = %q, want %q (update the image lists in TRUST_MODEL.md/.zh.md, QUIRKS.md, ARCHITECTURE.md/.zh.md and downloadTo's comment)", checked, want)
	}
}

// TestGoMod_DoesNotReplaceStorageClient: the images install the download
// CLI from upstream at the version go.mod requires, so a replace of
// 0g-storage-client would have sealed upload with one client and download
// with another. go list -m reports the required version even for a
// replaced module, so the version alone does not show it; the images'
// storage-builder stages refuse to build with one, and this fails first.
func TestGoMod_DoesNotReplaceStorageClient(t *testing.T) {
	b, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(string(b), "\n") {
		line, _, _ = strings.Cut(line, "//")
		if left, _, ok := strings.Cut(line, "=>"); ok && strings.Contains(left, "github.com/0gfoundation/0g-storage-client") {
			t.Errorf("go.mod:%d replaces 0g-storage-client; the images' CLI would no longer match the SDK sealed links", i+1)
		}
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
