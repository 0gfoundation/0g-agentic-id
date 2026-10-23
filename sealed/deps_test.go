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
// it (linux/amd64, no cgo):
const (
	// linkedPackagesFile lists the non-standard packages.
	linkedPackagesFile = "testdata/linked-packages.txt"
	// linkedStdImportsFile lists the standard-library packages those
	// import directly. Standard packages that only other standard ones
	// import are left out: they change with the Go toolchain, not with a
	// dependency.
	linkedStdImportsFile = "testdata/linked-std-imports.txt"
)

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
// register HTTP handlers at init). After reviewing, regenerate the lists:
//
//	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' . | grep -v '^seal-verify' | LC_ALL=C sort > testdata/linked-packages.txt
//	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go list -deps -f '{{if and (not .Standard) (ne .Module.Path "seal-verify")}}{{range .Imports}}{{println .}}{{end}}{{end}}' . | grep -v '^[^/]*\.' | LC_ALL=C sort -u > testdata/linked-std-imports.txt
func TestLinkedPackages_Reviewed(t *testing.T) {
	var nonStandard []string
	for _, p := range goListDeps(t, nonStandardTemplate) {
		if p != "seal-verify" && !strings.HasPrefix(p, "seal-verify/") {
			nonStandard = append(nonStandard, p)
		}
	}
	compareList(t, linkedPackagesFile, nonStandard)

	// A standard-library import path has no dot in its first element.
	var stdImports []string
	for _, p := range goListDeps(t, importsTemplate) {
		if first, _, _ := strings.Cut(p, "/"); !strings.Contains(first, ".") && !slices.Contains(stdImports, p) {
			stdImports = append(stdImports, p)
		}
	}
	compareList(t, linkedStdImportsFile, stdImports)
}

// goListDeps runs go list -deps with template over sealed as the images
// build it and returns the words it prints.
func goListDeps(t *testing.T, template string) []string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		goBin = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	cmd := exec.Command(goBin, "list", "-deps", "-f", template, ".")
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
