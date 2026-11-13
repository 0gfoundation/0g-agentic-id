package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
)

// What is linked into sealed, its own packages aside, as the images build
// it (linux/amd64, no cgo), for each of the two builds: the default one the
// openclaw, hermes and prime-agent images ship, and the harnessonly one the
// 0g-harness image ships (adapters_harnessonly.go).
type linkedBuild struct {
	tags string
	// packagesFile lists the non-standard packages.
	packagesFile string
	// stdImportsFile lists the standard-library packages those import
	// directly. Standard packages that only other standard ones import are
	// left out: they change with the Go toolchain, not with a dependency.
	stdImportsFile string
}

var linkedBuilds = []linkedBuild{
	{"", "testdata/linked-packages.txt", "testdata/linked-std-imports.txt"},
	{"harnessonly", "testdata/linked-packages-harnessonly.txt", "testdata/linked-std-imports-harnessonly.txt"},
}

// The go list templates behind the two files.
const (
	nonStandardTemplate = `{{if not .Standard}}{{.ImportPath}}{{end}}`
	importsTemplate     = `{{if and (not .Standard) (ne .Module.Path "seal-verify")}}{{range .Imports}}{{println .}}{{end}}{{end}}`
)

// TestLinkedPackages_Reviewed fails when a dependency change adds or drops
// a package linked into sealed -- the root PID 1 process that holds
// agent_seal_priv -- so that what a bump brings in, init functions
// included, gets reviewed: go.mod and go.sum show version changes, this
// shows the packages. That covers standard-library packages a dependency
// starts or stops importing (net/http/pprof and expvar, for instance,
// register HTTP handlers at init). After reviewing, regenerate the lists,
// for the default build and again with -tags harnessonly into the
// -harnessonly files:
//
//	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' . | grep -v '^seal-verify' | LC_ALL=C sort > testdata/linked-packages.txt
//	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go list -deps -f '{{if and (not .Standard) (ne .Module.Path "seal-verify")}}{{range .Imports}}{{println .}}{{end}}{{end}}' . | grep -v '^[^/]*\.' | LC_ALL=C sort -u > testdata/linked-std-imports.txt
func TestLinkedPackages_Reviewed(t *testing.T) {
	for _, b := range linkedBuilds {
		var nonStandard []string
		for _, p := range goListDeps(t, nonStandardTemplate, b.tags) {
			if p != "seal-verify" && !strings.HasPrefix(p, "seal-verify/") {
				nonStandard = append(nonStandard, p)
			}
		}
		compareList(t, b.packagesFile, nonStandard)

		// A standard-library import path has no dot in its first element.
		var stdImports []string
		for _, p := range goListDeps(t, importsTemplate, b.tags) {
			if first, _, _ := strings.Cut(p, "/"); !strings.Contains(first, ".") && !slices.Contains(stdImports, p) {
				stdImports = append(stdImports, p)
			}
		}
		compareList(t, b.stdImportsFile, stdImports)
	}
}

// The 0g-harness image's sealed links no other framework's adapter.
func TestHarnessOnlyBuild_LinksNoOtherAdapter(t *testing.T) {
	var adapters []string
	for _, p := range goListDeps(t, `{{.ImportPath}}`, "harnessonly") {
		if strings.HasPrefix(p, "seal-verify/internal/framework/") && p != "seal-verify/internal/framework/conformance" {
			adapters = append(adapters, p)
		}
	}
	if len(adapters) != 1 || adapters[0] != "seal-verify/internal/framework/harness" {
		t.Fatalf("the harnessonly build links %q, want only the 0g-harness adapter", adapters)
	}
}

// goListDeps runs go list -deps with template over sealed as the images
// build it (with the build tags given, if any) and returns the words it
// prints.
func goListDeps(t *testing.T, template, tags string) []string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		goBin = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	args := []string{"list", "-deps", "-f", template}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	cmd := exec.Command(goBin, append(args, ".")...)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	return strings.Fields(string(out))
}

// compareList fails when got and the list in file differ.
func compareList(t *testing.T, file string, got []string) {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Fields(string(b))
	sort.Strings(got)
	sort.Strings(want)
	var added, dropped []string
	for _, p := range got {
		if _, found := slices.BinarySearch(want, p); !found {
			added = append(added, p)
		}
	}
	for _, p := range want {
		if _, found := slices.BinarySearch(got, p); !found {
			dropped = append(dropped, p)
		}
	}
	if len(added)+len(dropped) > 0 {
		t.Errorf("the packages linked into sealed changed; review them, then regenerate %s (see this test's comment)\nadded:   %q\ndropped: %q",
			file, added, dropped)
	}
}
