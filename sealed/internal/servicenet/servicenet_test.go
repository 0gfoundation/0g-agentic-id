package servicenet

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstallWritesReadOnlyAdapters(t *testing.T) {
	root := filepath.Join(t.TempDir(), "net")
	if err := Install(root); err != nil {
		t.Fatal(err)
	}
	for _, f := range []struct{ path, embedded string }{
		{NodeBootstrap(root), "node/bootstrap.mjs"},
		{filepath.Join(PythonPath(root), "sitecustomize.py"), "python/sitecustomize.py"},
	} {
		want, err := files.ReadFile(f.embedded)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(f.path)
		if err != nil || string(got) != string(want) {
			t.Fatalf("%s: installed copy differs from the embedded one (%v)", f.path, err)
		}
		fi, err := os.Stat(f.path)
		if err != nil || fi.Mode().Perm() != 0644 {
			t.Fatalf("%s: mode %v, want 0644 (%v)", f.path, fi.Mode().Perm(), err)
		}
	}
	for _, d := range []string{root, filepath.Dir(NodeBootstrap(root)), PythonPath(root)} {
		fi, err := os.Stat(d)
		if err != nil || fi.Mode().Perm() != 0755 {
			t.Fatalf("%s: want a 0755 directory (%v)", d, err)
		}
	}
}
