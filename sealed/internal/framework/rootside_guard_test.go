package framework

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// sealed runs as root, and the agent process can change any tree handed to
// it at any moment. These tests parse every non-test source file of the
// module and pin the root-side discipline structurally:
//
//   - file access and subprocesses go through internal/privsep (its fs
//     helpers, RootCommand, AgentCommand). Outside it, no path-taking
//     function of os, io/ioutil, path/filepath (walks, globs, link
//     resolution), syscall or golang.org/x/sys/unix (for these two, every
//     function with a string parameter but a listed few, and the raw
//     syscall entry points: pathSyscalls, derived from their sources), no
//     unix-socket listen (net) and no file server (net/http) is referenced
//     — called or used as a value — and no function of os/exec, or of
//     another package that starts a process (golang.org/x/sys/execabs,
//     net/http/cgi) or loads code from a path (plugin), is either. The
//     exceptions are the call sites in allowedDirectCalls, each counted and
//     each acting on a root-only path;
//   - nothing outside privsep builds or alters what a command runs as: no
//     exec.Cmd, syscall.SysProcAttr, syscall.Credential or os.ProcAttr value
//     is constructed (a composite literal, new(), or a variable, field or
//     parameter of that type), no .SysProcAttr or .Credential is referenced
//     at all (an AgentCommand's privilege drop lives in
//     cmd.SysProcAttr.Credential, and a read could alias it), no .Path,
//     .Args or .ExtraFiles field is assigned, the address of no .Path,
//     .Args, .ExtraFiles, .Dir or .Env is taken (a write through it would
//     go unseen), no .Args, .ExtraFiles or .Env is used as a value except
//     as append's first argument in an assignment back to it (a copy of
//     the slice shares the command's backing array: copy() into it, or an
//     element written through it, changes the command), a command is never
//     handed to code the guard does not judge — a function outside the
//     module (a reflection-based decoder such as json.Unmarshal sets its
//     fields), an interface, a function value — but only kept in places
//     typed as a command and passed to the module's own functions as one,
//     and neither unsafe nor reflect (beyond reflect.DeepEqual) is used,
//     through which a field could be written without any of these. These
//     rules see types: every package is type-checked against the real
//     os/exec (rootside_types_test.go), so a field is a command's wherever
//     the command came from and whatever the file imports, and only a
//     receiver the check could not type is judged by the field's name;
//   - none of the packages this guard checks is dot-imported, which would
//     turn its functions into bare identifiers the guard does not see;
//   - root executes only the toolchain binaries named below, each from the
//     one function that needs it, and privsep.RootCommand is only ever
//     called directly with a literal binary name (never used as a value);
//     a root command's working directory is set only through
//     privsep.RootDir (a .Dir assignment is allowed only in the functions
//     that start agent processes, agentCommands), and its environment gains
//     only string literals or a rootEnvHelpers result, appended in a
//     rootCommands function (any other .Env assignment outside
//     agentCommands is refused);
//   - the framework, its CLIs and its probes run through AgentCommand, each
//     adapter links its tree into the agent's home, and every adapter's
//     Stop sweeps;
//   - boot hardening and the provisioning gate stay wired in main.
//
// A new path-based call, a new root-run binary or a moved spawn has to be
// added here, with its reason, before the suite passes again.

const privsepImport = "seal-verify/internal/privsep"

// unguardedPackages are not scanned for direct calls, with the reason.
var unguardedPackages = map[string]string{
	"internal/privsep":               "implements the helpers every other package must use",
	"internal/framework/conformance": "test support, imported only by _test.go files (checked below)",
}

// allowedDirectCalls are the direct path-based uses outside internal/privsep,
// keyed "<file> <func> <pkg>.<name>" with how many such uses that function
// may hold, each acting only on a root-only path. A second use in the same
// function needs its own count, and its own reason.
var allowedDirectCalls = map[string]struct {
	count  int
	reason string
}{
	"internal/attestorhttp/client.go resolver.endpoint assigns .Path": {1, "sets net/url.URL.Path while constructing the pinned Scan HTTPS endpoint; this is neither a filesystem path nor exec.Cmd.Path and does not launch a process"},
	"internal/framework/state.go OpenLog os.OpenFile":                 {1, "framework.StateDir/log is root-only and the file is opened O_NOFOLLOW (TestOpenLogRefusesALink)"},
	"internal/logger/logger.go Flush os.MkdirAll":                     {1, "the root-only state directory; logger cannot import privsep (privsep logs through it)"},
	"internal/logger/logger.go Flush os.OpenFile":                     {1, "LogPath in the root-only state directory, opened O_NOFOLLOW"},
	"internal/proxy/sign.go Server.ListenInternal net.Listen":         {1, "the sign socket is created in /run, which only root can write; privsep.Remove clears the name first and privsep.Chmod/OwnPath act on what was bound without following a link"},
}

// rootCommands is everything root executes: the functions that may call
// privsep.RootCommand, and the binaries (string literals) each may name.
var rootCommands = map[string][]string{
	"internal/dataplane.downloadTo":              {"0g-storage-client"},
	"internal/framework/openclaw.installCommand": {"npm"},
	"internal/framework/hermes.installHermes":    {"git", "uv"},
	"internal/framework/prime.npmGlobalRoot":     {"npm"},
}

// rootEnvHelpers are the functions whose result a rootCommands function may
// spread into its command's environment (cmd.Env = append(cmd.Env,
// helper(...)...)), with the reason their values name nothing another uid
// can write. Any other addition to a root command's environment must be a
// string literal that names no path (holds no "/").
var rootEnvHelpers = map[string]string{
	"installEnv": "fixed npm settings plus OPENCLAW_HOME under the root-only framework.StateDir (TestInstallEnvKeepsTheInstallOutOfTheAgentTree)",
}

// agentCommands are the functions that start the framework or run one of
// its CLIs or probes against agent-writable state; each must do so through
// privsep.AgentCommand (and, by rootCommands, never through RootCommand).
var agentCommands = []string{
	"internal/framework/openclaw.spawnGateway",
	"internal/framework/openclaw.validateOpenclawConfig",
	"internal/framework/openclaw.runCompactCLI",
	"internal/framework/hermes.spawnGateway",
	"internal/framework/prime.spawnBridge",
	"internal/framework/prime.probeKernelVenv",
	"internal/framework/harness.spawnBridge",
}

// adapterPackages must each sweep in Stop (privsep.Sweep).
var adapterPackages = []string{
	"internal/framework/openclaw",
	"internal/framework/hermes",
	"internal/framework/prime",
	"internal/framework/harness",
}

// agentHomeLinks are the functions that hand an adapter's tree over and
// must also link it into the agent's home (privsep.LinkAgentHome): the
// framework runs with the agent's own HOME, and the paths the agent is told
// about (~/.openclaw/...) resolve through that link. The framework itself
// is given its tree's absolute path in its environment (for openclaw
// OPENCLAW_STATE_DIR and OPENCLAW_HOME, from which it derives the default
// workspace), so its config, state and workspace do not depend on the link
// (a few openclaw plugins' default locations do: QUIRKS.md).
var agentHomeLinks = []string{
	"internal/framework/openclaw.Adapter.prepareTree",
	"internal/framework/hermes.spawnGateway",
	"internal/framework/prime.spawnBridge",
	"internal/framework/harness.spawnBridge",
}

// pathSyscalls are the syscall / golang.org/x/sys/unix functions that take
// a path (or start a process) and so must not be used outside privsep. The
// set is derived, not curated (loadPathSyscalls): every exported function
// of either package, as built for linux, with a string or []string
// parameter — a path, an argv, a mount source or target — except
// nonPathStringFuncs, plus rawSyscalls. A function a new x/sys version adds
// is therefore covered without anyone listing it.
var pathSyscalls map[string]bool

// nonPathStringFuncs take strings that are not paths: environment,
// conversions, socket and interface names, key descriptions, signal names.
var nonPathStringFuncs = map[string]bool{
	"Getenv": true, "Setenv": true, "Unsetenv": true,
	"BytePtrFromString": true, "ByteSliceFromString": true, "StringBytePtr": true,
	"StringByteSlice": true, "StringSlicePtr": true, "SlicePtrFromStrings": true,
	"ParseDirent": true, "SignalNum": true, "MemfdCreate": true,
	"SetsockoptString": true, "BindToDevice": true, "SetLsfPromisc": true, "NewIfreq": true,
	"IoctlGetEthtoolDrvinfo": true, "IoctlGetEthtoolTsInfo": true, "IoctlGetHwTstamp": true, "IoctlSetHwTstamp": true,
	"AddKey": true, "RequestKey": true, "KeyctlJoinSessionKeyring": true, "KeyctlRestrictKeyring": true, "KeyctlSearch": true,
}

// rawSyscalls take no string but can perform any system call by number,
// including every path-based one.
var rawSyscalls = []string{"Syscall", "Syscall6", "RawSyscall", "RawSyscall6", "SyscallNoError", "RawSyscallNoError"}

var (
	pathSyscallsOnce sync.Once
	pathSyscallsErr  error
)

// loadPathSyscalls derives pathSyscalls from the two packages' sources.
func loadPathSyscalls() error {
	pathSyscallsOnce.Do(func() {
		names := map[string]bool{}
		for _, n := range rawSyscalls {
			names[n] = true
		}
		for _, pkg := range []string{"syscall", "golang.org/x/sys/unix"} {
			ctxt := build.Default
			ctxt.GOOS = "linux"
			bp, err := ctxt.Import(pkg, ".", 0)
			if err != nil {
				pathSyscallsErr = fmt.Errorf("locating %s: %w", pkg, err)
				return
			}
			fset := token.NewFileSet()
			for _, f := range bp.GoFiles {
				af, err := parser.ParseFile(fset, filepath.Join(bp.Dir, f), nil, parser.SkipObjectResolution)
				if err != nil {
					pathSyscallsErr = err
					return
				}
				for _, d := range af.Decls {
					fd, ok := d.(*ast.FuncDecl)
					if !ok || fd.Recv != nil || !fd.Name.IsExported() || nonPathStringFuncs[fd.Name.Name] {
						continue
					}
					for _, p := range fd.Type.Params.List {
						if takesString(p.Type) {
							names[fd.Name.Name] = true
						}
					}
				}
			}
		}
		pathSyscalls = names
	})
	return pathSyscallsErr
}

// takesString reports whether a parameter type is string, []string or
// ...string.
func takesString(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name == "string"
	case *ast.ArrayType:
		return takesString(x.Elt)
	case *ast.Ellipsis:
		return takesString(x.Elt)
	}
	return false
}

// The derived set covers the path-taking functions a hand-picked list once
// missed, and is not empty by accident.
func TestPathSyscallsAreDerived(t *testing.T) {
	if err := loadPathSyscalls(); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{
		"Open", "Openat", "Openat2", "Exec", "ForkExec", "StartProcess", "Rename", "Renameat2",
		"Chown", "Fchownat", "Mkdirat", "Symlinkat", "Readlinkat", "Fstatat", "Statx", "Mount",
		"Utime", "Futimesat", "Listxattr", "Llistxattr", "InotifyAddWatch", "Unmount", "PivotRoot",
		"Acct", "UtimesNanoAt", "NameToHandleAt", "OpenTree", "FanotifyMark", "FsconfigSetPath",
		"Syscall", "RawSyscall6",
	} {
		if !pathSyscalls[n] {
			t.Errorf("%s is not in the derived set", n)
		}
	}
	for n := range nonPathStringFuncs {
		if pathSyscalls[n] {
			t.Errorf("%s is listed as taking no path but is in the set", n)
		}
	}
	if len(pathSyscalls) < 80 {
		t.Errorf("derived only %d functions; the sources were not read as expected", len(pathSyscalls))
	}
}

// forbiddenRef reports whether a reference to pkg.name (pkg is the import
// path) bypasses internal/privsep. call is the call the reference is the
// function of, or nil when it is used as a value.
func forbiddenRef(pkg, name string, call *ast.CallExpr) bool {
	switch pkg {
	case "io/ioutil":
		return true
	case "os/exec":
		return name == "Command" || name == "CommandContext" || name == "LookPath"
	case "golang.org/x/sys/execabs", "net/http/cgi", "unsafe":
		// execabs is os/exec under another name; a cgi.Handler runs its
		// Path with the Args, Env and Dir it is given; unsafe can write any
		// field of a command.
		return true
	case "plugin":
		return name == "Open"
	case "reflect":
		// Through a reflect.Value a command's fields can be set without an
		// assignment the guard sees.
		return name != "DeepEqual"
	case "syscall", "golang.org/x/sys/unix":
		return pathSyscalls[name]
	case "path/filepath":
		return name == "Glob" || strings.HasPrefix(name, "Walk") || name == "EvalSymlinks"
	case "net":
		switch name {
		case "ListenUnix", "ListenUnixgram":
			return true
		case "Listen", "ListenPacket":
			// A unix socket is created at a path; a TCP or UDP listener is not
			// a file. A network that is not a string literal is treated as
			// unix.
			if call == nil || len(call.Args) == 0 {
				return true
			}
			bl, ok := call.Args[0].(*ast.BasicLit)
			if !ok || bl.Kind != token.STRING {
				return true
			}
			network, _ := strconv.Unquote(bl.Value)
			return strings.HasPrefix(network, "unix")
		}
	case "net/http":
		switch name {
		case "ServeFile", "ServeFileFS", "Dir", "FileServer", "FileServerFS":
			return true
		}
	case "os":
		switch name {
		case "ReadFile", "WriteFile", "Rename", "ReadDir", "Stat", "Lstat", "Readlink",
			"Link", "Symlink", "Truncate", "Lchown", "DirFS", "CopyFS", "StartProcess":
			return true
		}
		for _, p := range []string{"Open", "Create", "Remove", "Mkdir", "Ch"} {
			if strings.HasPrefix(name, p) {
				return true
			}
		}
	}
	return false
}

// processTypes are the types whose values decide what a command runs as;
// only privsep constructs them.
var processTypes = map[string]bool{
	"os/exec.Cmd":                       true,
	"syscall.SysProcAttr":               true,
	"syscall.Credential":                true,
	"os.ProcAttr":                       true,
	"golang.org/x/sys/unix.SysProcAttr": true,
}

// processFields are the exec.Cmd fields only privsep assigns.
var processFields = map[string]bool{"Path": true, "Args": true, "ExtraFiles": true}

// commandFields are the exec.Cmd fields whose address nothing outside
// privsep takes: a write through the pointer would bypass every assignment
// rule here.
var commandFields = map[string]bool{"Path": true, "Args": true, "ExtraFiles": true, "Dir": true, "Env": true}

// sliceFields are the exec.Cmd slice fields nothing outside privsep uses as
// a value, except as append's first argument in an assignment back to the
// field itself: a copy of the slice shares the command's backing array.
var sliceFields = map[string]bool{"Args": true, "ExtraFiles": true, "Env": true}

// credentialFields hold a command's privilege drop; nothing outside privsep
// references them, for reading or writing.
var credentialFields = map[string]bool{"SysProcAttr": true, "Credential": true}

// guardedImports are the packages whose identifiers this guard inspects;
// a dot-import would hide them.
var guardedImports = map[string]bool{
	"os": true, "os/exec": true, "io/ioutil": true, "path/filepath": true,
	"syscall": true, "golang.org/x/sys/unix": true, "net": true, "net/http": true,
	"golang.org/x/sys/execabs": true, "net/http/cgi": true, "plugin": true,
	"unsafe": true, "reflect": true,
	privsepImport: true,
}

// privsepCall is one call to a privsep function.
type privsepCall struct {
	name  string // privsep function called
	first string // its first argument, as source text
	arg   string // its second argument when a string literal
	lit   bool   // whether arg is set
	pos   token.Position
}

// directUse is one forbidden reference outside privsep.
type directUse struct {
	key string // "<file> <func> <what>"
	pos token.Position
}

type moduleScan struct {
	fset       *token.FileSet
	files      int
	direct     []directUse              // every forbidden reference or construct
	calls      map[string][]privsepCall // "<pkgdir>.<func>" ("..main" for main) → privsep calls inside it
	conformers []string                 // non-test files importing the conformance package
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the working directory")
		}
		dir = parent
	}
}

// funcName names a top-level declaration: "Func", "Type.Method", or the
// variable a function literal is assigned to.
func funcName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	typ := fd.Recv.List[0].Type
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	if id, ok := typ.(*ast.Ident); ok {
		return id.Name + "." + fd.Name.Name
	}
	return fd.Name.Name
}

var (
	moduleScanOnce sync.Once
	moduleScanned  *moduleScan
	moduleScanErr  error
)

// scanModule scans every non-test source file of the module (once per test
// binary; the scan only reads).
func scanModule(t *testing.T) *moduleScan {
	t.Helper()
	root := moduleRoot(t)
	moduleScanOnce.Do(func() { moduleScanned, moduleScanErr = scanTree(root, "") })
	if moduleScanErr != nil {
		t.Fatal(moduleScanErr)
	}
	if moduleScanned.files < 60 {
		t.Fatalf("scanned only %d files; the module root or the walk is wrong", moduleScanned.files)
	}
	return moduleScanned
}

// scanTree scans the non-test Go files of the module at root: all of them
// (testdata and images aside), or, when only is set, those under that
// directory (relative to root) — a planted package, for the guard's own
// test. Every scanned package is type-checked first (moduleTypes), so the
// rules on a command's fields and on where a command goes see types.
func scanTree(root, only string) (*moduleScan, error) {
	if err := loadPathSyscalls(); err != nil {
		return nil, fmt.Errorf("deriving the path-taking syscall functions: %w", err)
	}
	s := &moduleScan{fset: token.NewFileSet(), calls: map[string][]privsepCall{}}
	type srcFile struct {
		rel, pkgDir string
		f           *ast.File
	}
	var srcs []srcFile
	byPkg := map[string][]*ast.File{}
	start := root
	if only != "" {
		start = filepath.Join(root, filepath.FromSlash(only))
	}
	err := filepath.WalkDir(start, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != start && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata" || d.Name() == "images") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		pkgDir := filepath.ToSlash(filepath.Dir(rel)) // "." for package main
		f, err := parser.ParseFile(s.fset, path, nil, 0)
		if err != nil {
			return err
		}
		s.files++
		srcs = append(srcs, srcFile{rel, pkgDir, f})
		byPkg[pkgDir] = append(byPkg[pkgDir], f)
		return nil
	})
	if err != nil {
		return nil, err
	}
	// A package the scan does not cover (privsep, for a planted package) is
	// parsed for its types only.
	parseDir := func(dir string) ([]*ast.File, error) {
		ents, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		var files []*ast.File
		for _, e := range ents {
			if n := e.Name(); strings.HasSuffix(n, ".go") && !strings.HasSuffix(n, "_test.go") {
				f, err := parser.ParseFile(s.fset, filepath.Join(dir, n), nil, 0)
				if err != nil {
					return nil, err
				}
				files = append(files, f)
			}
		}
		return files, nil
	}
	mt := newModuleTypes(s.fset, root, byPkg, parseDir)
	// Where the type check leaves a receiver untyped, a field is judged by
	// its name, in a package any of whose files can hold a command (imports
	// os/exec or privsep) for .Env, which other types have too (secretenv's
	// payload).
	buildsCommands := map[string]bool{}
	for _, sf := range srcs {
		for _, imp := range sf.f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == "os/exec" || p == privsepImport {
				buildsCommands[sf.pkgDir] = true
			}
		}
	}
	for _, sf := range srcs {
		tp := mt.check(sf.pkgDir)
		if tp == nil {
			return nil, fmt.Errorf("type-checking %s failed", sf.pkgDir)
		}
		s.inspectFile(sf.rel, sf.pkgDir, sf.f, tp.info, buildsCommands[sf.pkgDir])
	}
	return s, nil
}

// inspectFile applies the guard's rules to one parsed file of package
// pkgDir, with the package's type information.
func (s *moduleScan) inspectFile(rel, pkgDir string, f *ast.File, info *types.Info, pkgBuildsCommands bool) {
	_, unguarded := unguardedPackages[pkgDir]
	imports := map[string]string{} // local name → import path
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		if p == "seal-verify/internal/framework/conformance" {
			s.conformers = append(s.conformers, rel)
		}
		local := filepath.Base(p)
		if imp.Name != nil {
			local = imp.Name.Name
		}
		if local == "." && guardedImports[p] && !unguarded {
			s.direct = append(s.direct, directUse{key: rel + "  dot-imports " + p, pos: s.fset.Position(imp.Pos())})
		}
		imports[local] = p
	}
	// cmdField reports whether sel selects a field of a command: by the
	// field's type (commandField), whatever the receiver is and wherever it
	// came from; where the type check left the receiver untyped, by the
	// field's name — for .Env, which other types have too (secretenv's
	// payload), only in a package that can hold a command.
	cmdField := func(sel *ast.SelectorExpr) bool {
		if isCmd, known := commandField(info, sel); known {
			return isCmd
		}
		return sel.Sel.Name != "Env" || pkgBuildsCommands
	}
	// startsCommand reports whether e is a command value (not a type, not
	// the field name of a selector) where a walk up its ancestors starts.
	startsCommand := func(e ast.Expr, stack []ast.Node) bool {
		switch e.(type) {
		case *ast.Ident, *ast.SelectorExpr, *ast.CallExpr, *ast.IndexExpr, *ast.TypeAssertExpr:
		default:
			return false
		}
		if len(stack) >= 2 {
			if p, ok := stack[len(stack)-2].(*ast.SelectorExpr); ok && p.Sel == e {
				return false
			}
		}
		var t types.Type
		if tv, ok := info.Types[e]; ok {
			if !tv.IsValue() {
				return false
			}
			t = tv.Type
		} else if id, ok := e.(*ast.Ident); ok {
			v, _ := info.Uses[id].(*types.Var)
			if v == nil {
				v, _ = info.Defs[id].(*types.Var)
			}
			if v == nil {
				return false
			}
			t = v.Type()
		}
		return isCommandType(t)
	}
	// pkgRef resolves e to (import path, name) when it is <pkg>.<name>.
	pkgRef := func(e ast.Expr) (string, string, bool) {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok {
			return "", "", false
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || id.Obj != nil { // a local variable, not a package
			return "", "", false
		}
		p, ok := imports[id.Name]
		return p, sel.Sel.Name, ok
	}
	// processType reports whether the type expression e is (not a
	// pointer to) one of processTypes.
	processType := func(e ast.Expr) (string, bool) {
		if p, name, ok := pkgRef(e); ok && processTypes[p+"."+name] {
			return filepath.Base(p) + "." + name, true
		}
		return "", false
	}
	inspect := func(owner string, n ast.Node) {
		flag := func(what string, at ast.Node) {
			if !unguarded {
				s.direct = append(s.direct, directUse{key: rel + " " + owner + " " + what, pos: s.fset.Position(at.Pos())})
			}
		}
		// The selector expressions that are the function of a call.
		callOf := map[*ast.SelectorExpr]*ast.CallExpr{}
		// The field selectors an assignment writes (its targets, which
		// the assignment rules below judge), and the x.F that is
		// append's first argument in `x.F = append(x.F, ...)`: the only
		// places a command's slice field may appear outside privsep.
		assigned := map[*ast.SelectorExpr]bool{}
		ast.Inspect(n, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				if sel, ok := n.Fun.(*ast.SelectorExpr); ok {
					callOf[sel] = n
				}
			case *ast.AssignStmt:
				for _, lhs := range n.Lhs {
					if sel := assignedField(lhs); sel != nil {
						assigned[sel] = true
					}
				}
				if len(n.Lhs) != 1 || len(n.Rhs) != 1 {
					return true
				}
				call, ok := n.Rhs[0].(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				if fn, ok := call.Fun.(*ast.Ident); !ok || fn.Name != "append" {
					return true
				}
				if sel, ok := call.Args[0].(*ast.SelectorExpr); ok && types.ExprString(sel) == types.ExprString(n.Lhs[0]) {
					assigned[sel] = true
				}
			}
			return true
		})
		var stack []ast.Node        // n's ancestors, and n
		var sigs []*types.Signature // the enclosing functions' signatures
		var sigAt []int             // the stack depth each was pushed at
		ast.Inspect(n, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				if k := len(sigAt) - 1; k >= 0 && sigAt[k] == len(stack) {
					sigs, sigAt = sigs[:k], sigAt[:k]
				}
				return true
			}
			stack = append(stack, n)
			var sig types.Type
			switch fn := n.(type) {
			case *ast.FuncDecl:
				if o := info.Defs[fn.Name]; o != nil {
					sig = o.Type()
				}
			case *ast.FuncLit:
				sig = info.Types[fn].Type
			}
			if sig, ok := sig.(*types.Signature); ok {
				sigs, sigAt = append(sigs, sig), append(sigAt, len(stack)-1)
			}
			// A command goes only where the guard keeps judging what is
			// done to it (commandEscape).
			if e, ok := n.(ast.Expr); ok && startsCommand(e, stack) {
				if what, bad := commandEscape(info, stack, sigs); bad {
					flag("hands a command to "+what+" (where the guard cannot see what is done to it)", n)
				}
			}
			switch n := n.(type) {
			case *ast.SelectorExpr:
				if credentialFields[n.Sel.Name] {
					flag("references ."+n.Sel.Name, n)
				}
				p, name, ok := pkgRef(n)
				if !ok {
					if f := n.Sel.Name; sliceFields[f] && !assigned[n] && cmdField(n) {
						flag("uses ."+f+" as a value (a copy shares the command's own slice)", n)
					}
					return true
				}
				call := callOf[n]
				if forbiddenRef(p, name, call) {
					flag(filepath.Base(p)+"."+name, n)
				}
				if p != privsepImport {
					return true
				}
				if call == nil {
					if name == "RootCommand" {
						flag("privsep.RootCommand used as a value", n)
					}
					return true
				}
				c := privsepCall{name: name, pos: s.fset.Position(call.Pos())}
				if len(call.Args) >= 1 {
					c.first = types.ExprString(call.Args[0])
				}
				if len(call.Args) >= 2 {
					if bl, ok := call.Args[1].(*ast.BasicLit); ok && bl.Kind == token.STRING {
						c.arg, _ = strconv.Unquote(bl.Value)
						c.lit = true
					}
				}
				key := pkgDir + "." + owner
				s.calls[key] = append(s.calls[key], c)
			case *ast.CompositeLit:
				if what, ok := processType(n.Type); ok {
					flag("constructs "+what, n)
				}
			case *ast.CallExpr:
				if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "new" && len(n.Args) == 1 {
					if what, ok := processType(n.Args[0]); ok {
						flag("constructs "+what, n)
					}
				}
			case *ast.UnaryExpr:
				if n.Op != token.AND {
					return true
				}
				if sel := assignedField(n.X); sel != nil && commandFields[sel.Sel.Name] && cmdField(sel) {
					if _, _, isPkg := pkgRef(sel); !isPkg {
						flag("takes the address of ."+sel.Sel.Name, n)
					}
				}
			case *ast.ValueSpec:
				// var x syscall.Credential: a zero value, constructed.
				if what, ok := processType(n.Type); ok {
					flag("declares a "+what+" value", n)
				}
			case *ast.Field:
				if what, ok := processType(n.Type); ok {
					flag("declares a "+what+" value", n)
				}
			case *ast.AssignStmt:
				for _, lhs := range n.Lhs {
					sel := assignedField(lhs)
					if sel == nil {
						continue
					}
					switch name := sel.Sel.Name; {
					case processFields[name] && cmdField(sel):
						flag("assigns ."+name, n)
					case name == "Dir" && cmdField(sel) && !contains(agentCommands, pkgDir+"."+owner):
						flag("assigns .Dir (a root command's working directory is set through privsep.RootDir)", n)
					case name == "Env" && cmdField(sel) && !contains(agentCommands, pkgDir+"."+owner):
						if _, root := rootCommands[pkgDir+"."+owner]; !root || !fixedEnvAppend(n, lhs) {
							flag("assigns .Env (a root command's environment may only gain string literals or a rootEnvHelpers result: cmd.Env = append(cmd.Env, ...))", n)
						}
					}
				}
			}
			return true
		})
	}
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			inspect(funcName(d), d)
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					inspect("", spec)
					continue
				}
				if vs.Type != nil {
					inspect("", &ast.ValueSpec{Names: vs.Names, Type: vs.Type})
				}
				for i, v := range vs.Values {
					name := ""
					if i < len(vs.Names) {
						name = vs.Names[i].Name
					}
					inspect(name, v)
				}
			}
		}
	}
}

// fixedEnvAppend reports whether the assignment n to lhs (a .Env field) is
// `x.Env = append(x.Env, <values>)` with the same x on both sides, where
// every value is a string literal, or the values are one rootEnvHelpers
// call spread with "...".
func fixedEnvAppend(n *ast.AssignStmt, lhs ast.Expr) bool {
	target, ok := lhs.(*ast.SelectorExpr)
	if !ok || len(n.Lhs) != 1 || len(n.Rhs) != 1 || n.Tok != token.ASSIGN {
		return false
	}
	call, ok := n.Rhs[0].(*ast.CallExpr)
	if !ok || len(call.Args) < 2 {
		return false
	}
	if fn, ok := call.Fun.(*ast.Ident); !ok || fn.Name != "append" {
		return false
	}
	if types.ExprString(call.Args[0]) != types.ExprString(target) {
		return false
	}
	values := call.Args[1:]
	if call.Ellipsis.IsValid() {
		inner, ok := values[0].(*ast.CallExpr)
		if !ok || len(values) != 1 {
			return false
		}
		fn, ok := inner.Fun.(*ast.Ident)
		if !ok {
			return false
		}
		_, pinned := rootEnvHelpers[fn.Name]
		return pinned
	}
	for _, v := range values {
		bl, ok := v.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			return false
		}
		// A literal names no path: one that did (LD_PRELOAD=/..., a config
		// file) could name something another uid can write, and belongs in
		// a rootEnvHelpers function with its reason.
		if lit, err := strconv.Unquote(bl.Value); err != nil || strings.ContainsRune(lit, '/') {
			return false
		}
	}
	return true
}

// assignedField returns the field selector an assignment target writes
// (x.F, x.F[i], x.F[i:j], *x.F, (x.F), *(&x.F)), or nil.
func assignedField(e ast.Expr) *ast.SelectorExpr {
	for {
		switch x := e.(type) {
		case *ast.SelectorExpr:
			return x
		case *ast.IndexExpr:
			e = x.X
		case *ast.SliceExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		case *ast.ParenExpr:
			e = x.X
		case *ast.UnaryExpr:
			if x.Op != token.AND {
				return nil
			}
			e = x.X
		default:
			return nil
		}
	}
}

func TestRootSideFileAccessGoesThroughPrivsep(t *testing.T) {
	s := scanModule(t)
	seen := map[string][]token.Position{}
	for _, d := range s.direct {
		seen[d.key] = append(seen[d.key], d.pos)
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		allowed, ok := allowedDirectCalls[key]
		switch {
		case !ok:
			for _, pos := range seen[key] {
				t.Errorf("%s: %s bypasses internal/privsep (root-side handling of agent-writable paths, or of what a command runs as); use its helpers, or add the use to allowedDirectCalls with the reason its path is root-only", pos, key)
			}
		case len(seen[key]) != allowed.count:
			t.Errorf("%s: %d uses, allowedDirectCalls allows %d (%v); each one needs its own entry and reason", key, len(seen[key]), allowed.count, seen[key])
		}
	}
	for key := range allowedDirectCalls {
		if _, ok := seen[key]; !ok {
			t.Errorf("allowedDirectCalls entry %q matches no use; remove it", key)
		}
	}
	for _, f := range s.conformers {
		t.Errorf("%s: non-test code imports the conformance package, which is not scanned", f)
	}
}

// The guard's rules, run over planted code (testdata/guardprobe), flag each
// shape through which a command could be changed unseen — including from a
// file that imports neither os/exec nor privsep, and through code outside
// the module that a command is handed to — and leave a command passed as a
// command to the module's own code alone. Each planted function holds one
// shape; deleting a rule fails this test even though the module's own code
// has nothing for it to flag.
func TestRootSideGuardFlagsEveryForbiddenShape(t *testing.T) {
	const planted = "internal/framework/testdata/guardprobe"
	s, err := scanTree(moduleRoot(t), planted)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, d := range s.direct {
		keys = append(keys, d.key)
	}
	flagged := func(fn, what string) bool {
		for _, k := range keys {
			if strings.Contains(k, " "+fn+" ") && strings.Contains(k, what) {
				return true
			}
		}
		return false
	}
	for _, c := range []struct{ fn, what string }{
		{"addressOfDir", "takes the address of .Dir"},
		{"writeThroughAddressOfEnv", "takes the address of .Env"},
		{"copyIntoArgs", "uses .Args as a value"},
		{"decodeIntoCommand", "hands a command to json.Unmarshal"},
		{"decodeIntoAddress", "hands a command to json.NewDecoder(nil).Decode"},
		{"commandAsInterface", "hands a command to a variable of type any"},
		{"commandInInterfaceField", "hands a command to a field or element not typed as a command"},
		{"commandToFormatter", "hands a command to fmt.Sprintf"},
		{"commandToFunctionValue", "hands a command to f"},
		{"commandThroughReflect", "reflect.ValueOf"},
		{"assignsPath", "assigns .Path"},
		{"assignsDir", "assigns .Dir"},
		{"referencesCredential", "references .SysProcAttr"},
		{"startsDirectly", "exec.Command"},
		{"envAliasWrite", "uses .Env as a value"},
		{"envPathLiteral", "assigns .Env"},
		{"envAddress", "takes the address of .Env"},
	} {
		if !flagged(c.fn, c.what) {
			t.Errorf("planted %s (%s) is not flagged; the guard's findings there: %q", c.fn, c.what, keys)
		}
	}
	if flagged("passesAsACommand", "hands a command") || flagged("useCommand", "hands a command") {
		t.Errorf("a command passed to the module's own code as a command was flagged: %q", keys)
	}
}

func TestRootRunsOnlyPinnedToolchainCommands(t *testing.T) {
	s := scanModule(t)
	keys := make([]string, 0, len(s.calls))
	for k := range s.calls {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	seen := map[string]bool{}
	for _, fn := range keys {
		for _, c := range s.calls[fn] {
			if c.name != "RootCommand" {
				continue
			}
			allowed, ok := rootCommands[fn]
			switch {
			case !ok:
				t.Errorf("%s: %s runs a command as root (privsep.RootCommand); only the functions in rootCommands may", c.pos, fn)
			case !c.lit:
				t.Errorf("%s: %s passes RootCommand a non-literal command name; name the binary literally", c.pos, fn)
			case !contains(allowed, c.arg):
				t.Errorf("%s: %s runs %q as root; rootCommands allows it only %v", c.pos, fn, c.arg, allowed)
			default:
				seen[fn+" "+c.arg] = true
			}
		}
	}
	for fn, names := range rootCommands {
		for _, n := range names {
			if !seen[fn+" "+n] {
				t.Errorf("rootCommands lists %s running %q, but no such call exists; update the list", fn, n)
			}
		}
	}
}

func TestFrameworkRunsAsTheAgent(t *testing.T) {
	s := scanModule(t)
	has := func(fn, privsepFunc string) bool {
		for _, c := range s.calls[fn] {
			if c.name == privsepFunc {
				return true
			}
		}
		return false
	}
	for _, fn := range agentCommands {
		if !has(fn, "AgentCommand") {
			t.Errorf("%s does not start its process through privsep.AgentCommand", fn)
		}
	}
	for _, fn := range agentHomeLinks {
		if !has(fn, "OwnTree") || !has(fn, "LinkAgentHome") {
			t.Errorf("%s must hand its tree over (privsep.OwnTree) and link it into the agent's home (privsep.LinkAgentHome)", fn)
		}
	}
	for _, pkg := range adapterPackages {
		if !has(pkg+".Adapter.Stop", "Sweep") {
			t.Errorf("%s: Adapter.Stop does not sweep with privsep.Sweep", pkg)
		}
	}
	// Every tree an adapter hands over is declared when it registers (New),
	// so Harden's ReclaimHome, which runs after registration, leaves it in
	// root's home although the agent owns it.
	for _, pkg := range adapterPackages {
		declaredTrees := map[string]bool{}
		for _, c := range s.calls[pkg+".New"] {
			if c.name == "DeclareTree" {
				declaredTrees[c.first] = true
			}
		}
		for fn, calls := range s.calls {
			if !strings.HasPrefix(fn, pkg+".") {
				continue
			}
			for _, c := range calls {
				if c.name == "OwnTree" && !declaredTrees[c.first] {
					t.Errorf("%s: %s hands %s to the agent, but %s.New does not declare it (privsep.DeclareTree)", c.pos, fn, c.first, pkg)
				}
			}
		}
	}
}

// main must run privsep.Harden (non-dumpable; root-only home) before the
// provisioning gate, and the gate must be privsep.Required. Required itself
// refuses until SecureHome has succeeded, so dropping Harden fails closed at
// runtime too; this catches it before a build.
func TestMainWiresBootHardening(t *testing.T) {
	s := scanModule(t)
	var harden token.Position
	for _, c := range s.calls["..main"] {
		if c.name == "Harden" && harden.Line == 0 {
			harden = c.pos
		}
	}
	// privsep.Required is passed to the gate, not called: find it as an
	// argument.
	gate := findSelectorArg(t, s, "provisionGate", "Required")
	switch {
	case harden.Line == 0:
		t.Fatal("main() does not call privsep.Harden")
	case gate.Line == 0:
		t.Fatal("main() does not pass privsep.Required to provisionGate")
	case harden.Line > gate.Line:
		t.Fatalf("privsep.Harden (line %d) must run before the provisioning gate (line %d)", harden.Line, gate.Line)
	}
	// Nothing logs before Harden: the first log line is what makes Go read
	// the time zone TZ names, which Harden's ScrubTimeEnv checks first.
	if first := findPackageCall(t, s, "logger", ""); first.Line != 0 && first.Line < harden.Line {
		t.Errorf("main() logs (line %d) before privsep.Harden (line %d), which settles the time zone that first log line reads", first.Line, harden.Line)
	}
	// The adapters register, and so declare their trees, before Harden
	// reclaims root's home.
	for _, pkg := range adapterPackages {
		name := filepath.Base(pkg)
		reg := findPackageCall(t, s, name, "New")
		switch {
		case reg.Line == 0:
			t.Errorf("main() does not register %s (%s.New)", pkg, name)
		case reg.Line > harden.Line:
			t.Errorf("%s.New (line %d) must run before privsep.Harden (line %d): it declares the trees Harden leaves in root's home", name, reg.Line, harden.Line)
		}
	}
}

// findPackageCall finds, in main(), the first call to pkg.fn (to any
// function of pkg when fn is "").
func findPackageCall(t *testing.T, s *moduleScan, pkg, fn string) token.Position {
	t.Helper()
	path := filepath.Join(moduleRoot(t), "main.go")
	f, err := parser.ParseFile(s.fset, path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var pos token.Position
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "main" || fd.Recv != nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || pos.Line != 0 {
				return true
			}
			if se, ok := call.Fun.(*ast.SelectorExpr); ok && (fn == "" || se.Sel.Name == fn) {
				if x, ok := se.X.(*ast.Ident); ok && x.Name == pkg {
					pos = s.fset.Position(call.Pos())
				}
			}
			return true
		})
	}
	return pos
}

// findSelectorArg finds, in main(), a call to fn that passes privsep.<sel>
// as an argument.
func findSelectorArg(t *testing.T, s *moduleScan, fn, sel string) token.Position {
	t.Helper()
	path := filepath.Join(moduleRoot(t), "main.go")
	f, err := parser.ParseFile(s.fset, path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var pos token.Position
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "main" || fd.Recv != nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok || id.Name != fn {
				return true
			}
			for _, a := range call.Args {
				if se, ok := a.(*ast.SelectorExpr); ok && se.Sel.Name == sel {
					if x, ok := se.X.(*ast.Ident); ok && x.Name == "privsep" {
						pos = s.fset.Position(call.Pos())
					}
				}
			}
			return true
		})
	}
	return pos
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
