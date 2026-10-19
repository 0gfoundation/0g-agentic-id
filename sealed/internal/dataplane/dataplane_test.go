package dataplane

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Where the images that build the storage binaries install them (their
// COPY --from=storage-builder lines); sealed runs them from exactly here.
const (
	installedUploadHelper  = "/usr/local/bin/zg-upload"
	installedStorageClient = "/usr/local/bin/0g-storage-client"
)

// Well-known test key; never used outside tests.
const testSealPrivHex = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"

const (
	testRoot  = "0x1111111111111111111111111111111111111111111111111111111111111111"
	decoyRoot = "0x2222222222222222222222222222222222222222222222222222222222222222"
)

func assertNoKey(t *testing.T, what, s string) {
	t.Helper()
	if strings.Contains(strings.ToLower(s), testSealPrivHex) {
		t.Fatalf("%s carries the signing key: %q", what, s)
	}
}

// TestStorageBinaries_AbsolutePaths: sealed runs both storage binaries from
// the absolute paths the images install them at, never through PATH.
func TestStorageBinaries_AbsolutePaths(t *testing.T) {
	if uploadHelperPath != installedUploadHelper {
		t.Errorf("uploadHelperPath = %q, want %q", uploadHelperPath, installedUploadHelper)
	}
	if storageClientPath != installedStorageClient {
		t.Errorf("storageClientPath = %q, want %q", storageClientPath, installedStorageClient)
	}
}

// TestDockerfiles_InstallStorageBinaries checks every image that has a
// storage-builder stage: it installs both binaries at the paths sealed runs,
// and builds the CLI at the 0g-storage-client version pinned in the helper's
// go.mod rather than from a floating clone. It also pins which images those
// are, as the docs name them (TRUST_MODEL.md, QUIRKS.md): the base images
// images/openclaw and images/sealed carry no storage binaries.
func TestDockerfiles_InstallStorageBinaries(t *testing.T) {
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
		if !strings.Contains(df, " AS storage-builder") {
			continue
		}
		checked = append(checked, f)
		for _, want := range []string{
			"COPY --from=storage-builder /out/zg-upload " + installedUploadHelper + "\n",
			"COPY --from=storage-builder /out/0g-storage-client " + installedStorageClient + "\n",
			"COPY tools/zg-upload/go.mod tools/zg-upload/go.sum ./\n",
			"go list -m -f '{{.Version}}' github.com/0gfoundation/0g-storage-client",
			`go install -ldflags="-s -w" "github.com/0gfoundation/0g-storage-client@$V"`,
		} {
			if !strings.Contains(df, want) {
				t.Errorf("%s: missing %q", f, want)
			}
		}
		if strings.Contains(df, "github.com/0gfoundation/0g-storage-client.git") {
			t.Errorf("%s: builds 0g-storage-client from a git clone; build it at the helper's go.mod version", f)
		}
	}
	slices.Sort(checked)
	want := []string{"../../Dockerfile", "../../images/dsh/Dockerfile", "../../images/hermes/Dockerfile", "../../images/prime/Dockerfile"}
	if !slices.Equal(checked, want) {
		t.Fatalf("Dockerfiles with a storage-builder stage = %q, want %q (update the image lists in TRUST_MODEL.md/.zh.md, QUIRKS.md, ARCHITECTURE.md/.zh.md and uploadHelperPath's comment)", checked, want)
	}
}

// clearHelperEnv unsets every variable helperEnv forwards, for the rest of
// the test, so a developer's own proxy or CA settings do not leak into an
// exact-environment assertion.
func clearHelperEnv(t *testing.T) {
	t.Helper()
	for _, k := range helperEnvKeys {
		t.Setenv(k, "") // restores the original value after the test
		if err := os.Unsetenv(k); err != nil {
			t.Fatal(err)
		}
	}
}

// stdinFile returns cmd.Stdin as the *os.File it must be: os/exec hands an
// *os.File to the child directly, while any other io.Reader is copied in
// through a pipe.
func stdinFile(t *testing.T, stdin io.Reader) *os.File {
	t.Helper()
	f, ok := stdin.(*os.File)
	if !ok {
		t.Fatalf("Stdin is a %T; os/exec would feed it through a pipe. The key must travel on the socketpair end (keyChannel)", stdin)
	}
	return f
}

// assertSocket fails unless f is a socket; a pipe in particular can be
// opened again through /proc/<pid>/fd.
func assertSocket(t *testing.T, what string, f *os.File) {
	t.Helper()
	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("stat %s: %v", what, err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("%s has mode %v, want a socket (never a pipe)", what, fi.Mode())
	}
}

func assertCloseOnExec(t *testing.T, what string, f *os.File) {
	t.Helper()
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatalf("F_GETFD %s: %v", what, err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("%s is not close-on-exec in sealed: another child sealed starts would inherit it", what)
	}
}

// TestUploadCommand_KeyOnlyOnStdin pins the invocation: the key goes to
// the helper's stdin, which is a close-on-exec socket rather than a pipe,
// and neither the argument list nor the (explicit) environment carries it.
func TestUploadCommand_KeyOnlyOnStdin(t *testing.T) {
	clearHelperEnv(t)
	t.Setenv("OPENAI_API_KEY", "sk-test-not-forwarded")
	t.Setenv("HTTPS_PROXY", "http://proxy.test:3128")
	for _, key := range []string{testSealPrivHex, "0x" + testSealPrivHex} {
		cmd, keys, err := uploadCommand(context.Background(), "/tmp/blob.bin", "http://indexer:5678", "http://rpc:8545", key)
		if err != nil {
			t.Fatalf("uploadCommand: %v", err)
		}
		defer keys.Close()

		if cmd.Path != installedUploadHelper || !filepath.IsAbs(cmd.Path) {
			t.Fatalf("Path = %q, want the absolute %q", cmd.Path, installedUploadHelper)
		}
		if cmd.Err != nil {
			t.Fatalf("Err = %v; an absolute path needs no lookup", cmd.Err)
		}
		wantArgs := []string{
			installedUploadHelper,
			"--file", "/tmp/blob.bin",
			"--indexer", "http://indexer:5678",
			"--url", "http://rpc:8545",
			"--expected-replica", "1",
			"--skip-tx=true",
			"--fast-mode=true",
			"--full-trusted=true",
			"--method", "random",
		}
		if strings.Join(cmd.Args, "\x00") != strings.Join(wantArgs, "\x00") {
			t.Fatalf("Args = %q\nwant  %q", cmd.Args, wantArgs)
		}
		for _, a := range cmd.Args {
			assertNoKey(t, "argument", a)
			if a == "--key" || strings.HasPrefix(a, "--key=") || a == "-key" || strings.HasPrefix(a, "-key=") {
				t.Fatalf("Args carry a key flag: %q", cmd.Args)
			}
		}
		if cmd.Env == nil {
			t.Fatal("Env is nil: the helper would inherit sealed's whole environment")
		}
		wantEnv := []string{"PATH=" + helperPATH, "HTTPS_PROXY=http://proxy.test:3128"}
		if strings.Join(cmd.Env, "\x00") != strings.Join(wantEnv, "\x00") {
			t.Fatalf("Env = %q\nwant %q", cmd.Env, wantEnv)
		}
		for _, e := range cmd.Env {
			assertNoKey(t, "environment entry", e)
		}

		stdin := stdinFile(t, cmd.Stdin)
		assertSocket(t, "the helper's stdin", stdin)
		assertSocket(t, "sealed's end of the key channel", keys.local)
		assertCloseOnExec(t, "the helper's stdin", stdin)
		assertCloseOnExec(t, "sealed's end of the key channel", keys.local)

		// What the helper reads: the bare hex key, a newline, then EOF.
		if err := keys.send(context.Background()); err != nil {
			t.Fatalf("send: %v", err)
		}
		got, err := io.ReadAll(stdin)
		if err != nil {
			t.Fatalf("read the helper's stdin: %v", err)
		}
		if string(got) != testSealPrivHex+"\n" {
			t.Fatalf("helper stdin = %q, want the bare hex key and a newline", got)
		}
	}
}

// TestKeyChannel_NotReopenableThroughProc: the helper's end cannot be
// opened again through /proc/<pid>/fd, which is what rules out a pipe.
func TestKeyChannel_NotReopenableThroughProc(t *testing.T) {
	if _, err := os.Stat("/proc/self/fd"); err != nil {
		t.Skip("no /proc/self/fd on this system")
	}
	keys, err := newKeyChannel(testSealPrivHex)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Close()
	for what, f := range map[string]*os.File{"helper's end": keys.remote, "sealed's end": keys.local} {
		p := fmt.Sprintf("/proc/self/fd/%d", f.Fd())
		if g, err := os.Open(p); err == nil {
			g.Close()
			t.Fatalf("%s: opened %s again; the key channel must not be reopenable", what, p)
		} else if !errors.Is(err, syscall.ENXIO) {
			t.Fatalf("%s: open %s: %v, want ENXIO (a socket)", what, p, err)
		}
	}
}

// TestKeyChannel_SendRespectsContext: a done context stops the write
// before anything reaches the helper.
func TestKeyChannel_SendRespectsContext(t *testing.T) {
	keys, err := newKeyChannel(testSealPrivHex)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := keys.send(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("send on a cancelled context = %v, want context.Canceled", err)
	}
	// Nothing was written, and send closed sealed's end anyway: the
	// helper's end reads an immediate EOF instead of blocking until the
	// upload deadline.
	done := make(chan struct{})
	var got []byte
	go func() {
		defer close(done)
		got, err = io.ReadAll(keys.remote)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the helper's end still blocks after a failed send; send must close sealed's end")
	}
	if err != nil || len(got) != 0 {
		t.Fatalf("helper's end read %q, %v after a cancelled send; want nothing", got, err)
	}
}

// helperFlags reads the flags the zg-upload helper defines -- the
// fs.<Kind>Var calls in its parseFlags -- from its source, since the
// helper is a separate Go module: flag name -> whether it is boolean.
func helperFlags(t *testing.T) map[string]bool {
	t.Helper()
	const src = "../../tools/zg-upload/main.go"
	f, err := parser.ParseFile(token.NewFileSet(), src, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", src, err)
	}
	flags := map[string]bool{}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "parseFlags" || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) < 2 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !strings.HasSuffix(sel.Sel.Name, "Var") {
				return true
			}
			lit, ok := call.Args[1].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			name, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatalf("flag name %s: %v", lit.Value, err)
			}
			flags[name] = sel.Sel.Name == "BoolVar"
			return true
		})
	}
	if len(flags) == 0 {
		t.Fatalf("found no fs.<Kind>Var flag definitions in parseFlags in %s; update helperFlags", src)
	}
	return flags
}

// TestUploadCommand_ArgsMatchHelperFlags checks uploadCommand's arguments
// against the flags the helper actually defines, the way Go's flag package
// (which the helper uses) consumes them: every flag defined, every
// non-boolean flag given a value, no word left over (the helper rejects
// positional arguments, which is how a separate value after a boolean flag
// ends up). The helper's own TestParseFlags_SealedInvocation runs its real
// parser on this function's arguments in the other direction.
func TestUploadCommand_ArgsMatchHelperFlags(t *testing.T) {
	flags := helperFlags(t)
	if _, ok := flags["key"]; ok {
		t.Fatal("the helper defines a --key flag; the key must reach it only on stdin")
	}
	cmd, keys, err := uploadCommand(context.Background(), "/tmp/blob.bin", "http://indexer:5678", "http://rpc:8545", testSealPrivHex)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Close()
	args := cmd.Args[1:]
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || a == "-" || a == "--" {
			t.Fatalf("argument %d (%q) is positional to the helper's parser; it rejects positional arguments (boolean flags take the --flag=value form)", i, a)
		}
		name, _, hasValue := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-"), "=")
		isBool, ok := flags[name]
		if !ok {
			t.Fatalf("uploadCommand passes --%s, which zg-upload does not define (its flags: %v)", name, flags)
		}
		seen[name] = true
		if !isBool && !hasValue {
			if i++; i >= len(args) {
				t.Fatalf("--%s has no value", name)
			}
		}
	}
	for _, req := range []string{"file", "indexer", "url"} {
		if !seen[req] {
			t.Errorf("uploadCommand does not pass the helper's required --%s", req)
		}
	}
}

// installFake writes an executable shell script into a fresh directory and
// points *target (uploadHelperPath or storageClientPath) at it for the rest
// of the test. It also puts a decoy of the same name first on PATH that
// records any run, and fails the test if the decoy ran: sealed must run the
// binary by its absolute path, never through a PATH lookup. Returns the
// script's directory.
func installFake(t *testing.T, target *string, script func(dir string) string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake binary is a POSIX shell script")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, filepath.Base(*target))
	if err := os.WriteFile(path, []byte(script(dir)), 0o755); err != nil {
		t.Fatal(err)
	}
	prev := *target
	*target = path
	t.Cleanup(func() { *target = prev })

	decoyDir := t.TempDir()
	marker := filepath.Join(decoyDir, "ran")
	decoy := "#!/bin/sh\n: > '" + marker + "'\nexit 1\n"
	if err := os.WriteFile(filepath.Join(decoyDir, filepath.Base(prev)), []byte(decoy), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", decoyDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Cleanup(func() {
		if _, err := os.Stat(marker); err == nil {
			t.Errorf("the PATH decoy %s ran; sealed must run %s", filepath.Base(prev), path)
		}
	})
	return dir
}

func installFakeHelper(t *testing.T, script func(dir string) string) string {
	t.Helper()
	return installFake(t, &uploadHelperPath, script)
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// TestUpload_KeyReachesHelperOnlyOverStdin runs Upload against a fake
// helper that records what the child process actually received: its argv
// (including the kernel's /proc view when available), its environment,
// what kind of file its stdin is, its stdin, and the blob behind --file.
func TestUpload_KeyReachesHelperOnlyOverStdin(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-test-not-forwarded")
	dir := installFakeHelper(t, func(dir string) string {
		return `#!/bin/sh
out='` + dir + `'
printf '%s\n' "$@" > "$out/args"
env > "$out/env"
if [ -r /proc/$$/cmdline ]; then tr '\000' '\n' < /proc/$$/cmdline > "$out/cmdline"; fi
if [ -S /dev/stdin ]; then echo socket; elif [ -p /dev/stdin ]; then echo pipe; else echo other; fi > "$out/stdin-type"
cat > "$out/stdin"
while [ $# -gt 0 ]; do
  if [ "$1" = "--file" ]; then cp "$2" "$out/blob"; fi
  shift
done
echo 'level=info msg="Data merkle root calculated" root=` + decoyRoot + `' >&2
echo 'root = ` + testRoot + `'
`
	})

	blob := []byte("ciphertext bytes")
	root, err := Upload(context.Background(), blob, "http://indexer:5678", "http://rpc:8545", "0x"+testSealPrivHex)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if got := "0x" + hex.EncodeToString(root[:]); got != testRoot {
		t.Fatalf("root = %s, want %s (parsed from stdout, not the stderr log line)", got, testRoot)
	}

	args := readFile(t, filepath.Join(dir, "args"))
	assertNoKey(t, "helper argv", args)
	if !strings.Contains(args, "--indexer\nhttp://indexer:5678\n") || !strings.Contains(args, "--url\nhttp://rpc:8545\n") {
		t.Fatalf("helper argv missing endpoints:\n%s", args)
	}
	if _, err := os.Stat(filepath.Join(dir, "cmdline")); err == nil {
		assertNoKey(t, "/proc/<pid>/cmdline", readFile(t, filepath.Join(dir, "cmdline")))
	}
	env := readFile(t, filepath.Join(dir, "env"))
	assertNoKey(t, "helper environment", env)
	if strings.Contains(env, "sk-test-not-forwarded") {
		t.Fatalf("helper inherited sealed's environment:\n%s", env)
	}
	if got := readFile(t, filepath.Join(dir, "stdin-type")); got != "socket\n" {
		t.Fatalf("helper stdin is a %q, want a socket (never a pipe)", strings.TrimSpace(got))
	}
	if got := readFile(t, filepath.Join(dir, "stdin")); got != testSealPrivHex+"\n" {
		t.Fatalf("helper stdin = %q, want the hex key line", got)
	}
	if got := readFile(t, filepath.Join(dir, "blob")); got != string(blob) {
		t.Fatalf("helper --file content = %q, want %q", got, blob)
	}
}

// TestUpload_HelperFailureKeepsLastLineAndOmitsKey checks the failure
// surface: the helper's final stderr line stays the last line of the error
// (what summarizeError shows the owner), and the key is not in the error.
func TestUpload_HelperFailureKeepsLastLineAndOmitsKey(t *testing.T) {
	installFakeHelper(t, func(string) string {
		return `#!/bin/sh
cat > /dev/null
echo 'level=info msg="Selecting nodes ..."' >&2
echo 'zg-upload: upload: insufficient funds for gas * price + value' >&2
exit 1
`
	})
	_, err := Upload(context.Background(), []byte("ct"), "http://indexer", "http://rpc", testSealPrivHex)
	if err == nil {
		t.Fatal("Upload succeeded against a failing helper")
	}
	msg := err.Error()
	assertNoKey(t, "error", msg)
	lines := strings.Split(msg, "\n")
	if last := lines[len(lines)-1]; last != "zg-upload: upload: insufficient funds for gas * price + value" {
		t.Fatalf("last error line = %q", last)
	}
}

// TestUpload_HelperExitsBeforeReadingKey: when the helper fails before it
// reads stdin (a usage error, say), Upload reports the helper's own error,
// not the failed key write.
func TestUpload_HelperExitsBeforeReadingKey(t *testing.T) {
	installFakeHelper(t, func(string) string {
		return `#!/bin/sh
echo 'zg-upload: missing required flags: --url' >&2
exit 2
`
	})
	_, err := Upload(context.Background(), []byte("ct"), "http://indexer", "http://rpc", testSealPrivHex)
	if err == nil {
		t.Fatal("Upload succeeded against a failing helper")
	}
	msg := err.Error()
	assertNoKey(t, "error", msg)
	if !strings.Contains(msg, "exit status 2") || !strings.HasSuffix(msg, "zg-upload: missing required flags: --url") {
		t.Fatalf("err = %q, want the helper's exit status and its last stderr line", msg)
	}
}

// TestUpload_RootOnlyFromStdout: a root-shaped string in the helper's logs
// must not be taken as the result.
func TestUpload_RootOnlyFromStdout(t *testing.T) {
	installFakeHelper(t, func(string) string {
		return `#!/bin/sh
cat > /dev/null
echo 'file uploaded, root = ` + decoyRoot + `' >&2
exit 0
`
	})
	_, err := Upload(context.Background(), []byte("ct"), "http://indexer", "http://rpc", testSealPrivHex)
	if err == nil || !strings.Contains(err.Error(), "could not parse root") {
		t.Fatalf("err = %v, want a parse failure", err)
	}
	assertNoKey(t, "error", err.Error())
}

func TestUpload_MissingHelper(t *testing.T) {
	prev := uploadHelperPath
	uploadHelperPath = filepath.Join(t.TempDir(), "zg-upload")
	t.Cleanup(func() { uploadHelperPath = prev })
	_, err := Upload(context.Background(), []byte("ct"), "http://indexer", "http://rpc", testSealPrivHex)
	if err == nil || !strings.Contains(err.Error(), uploadHelperPath) {
		t.Fatalf("err = %v, want it to name the missing helper", err)
	}
	assertNoKey(t, "error", err.Error())
}

// TestDownload_RunsCLIByAbsolutePath: the download CLI is run from
// storageClientPath, not looked up through PATH.
func TestDownload_RunsCLIByAbsolutePath(t *testing.T) {
	dir := installFake(t, &storageClientPath, func(dir string) string {
		return `#!/bin/sh
printf '%s\n' "$@" > '` + dir + `/args'
while [ $# -gt 0 ]; do
  if [ "$1" = "--file" ]; then printf 'plain' > "$2"; fi
  shift
done
`
	})
	out := filepath.Join(t.TempDir(), "out.bin")
	// Bounded: a failed first attempt would otherwise sit in Download's
	// retry backoff.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Download(ctx, testRoot, "http://indexer", out); err != nil {
		t.Fatalf("Download: %v", err)
	}
	want := "download\n--root\n" + testRoot + "\n--file\n" + out + "\n--indexer\nhttp://indexer\n"
	if got := readFile(t, filepath.Join(dir, "args")); got != want {
		t.Fatalf("CLI args = %q, want %q", got, want)
	}
	if got := readFile(t, out); got != "plain" {
		t.Fatalf("downloaded file = %q", got)
	}
}
