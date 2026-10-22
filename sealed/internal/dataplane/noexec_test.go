package dataplane

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"seal-verify/internal/logger"
)

// The signing key must never leave sealed, so Upload starts no child
// process. These tests pin that in the source (nothing Upload can reach in
// this package names a process-starting API, internal/privsep's command
// builders included) and in the dependencies (the packages that name one are
// the reviewed few, none on the upload path). The root-side guard pins it
// too: rootCommands gives Upload no binary to run
// (internal/framework/rootside_guard_test.go).

// jsonRPCErrorServer answers every JSON-RPC request (single or batch) with
// a method-not-found error and counts the calls.
func jsonRPCErrorServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		type req struct {
			ID json.RawMessage `json:"id"`
		}
		reply := func(id json.RawMessage) map[string]any {
			calls.Add(1)
			return map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32601, "message": "method not found"}}
		}
		w.Header().Set("Content-Type", "application/json")
		var batch []req
		if json.Unmarshal(body, &batch) == nil {
			out := make([]map[string]any, len(batch))
			for i, q := range batch {
				out[i] = reply(q.ID)
			}
			_ = json.NewEncoder(w).Encode(out)
			return
		}
		var one req
		_ = json.Unmarshal(body, &one)
		_ = json.NewEncoder(w).Encode(reply(one.ID))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// TestUpload_StartsNoProcess runs Upload through success and failure with
// stand-in SDK clients, and through the real SDK against local endpoints
// that refuse every call.
func TestUpload_StartsNoProcess(t *testing.T) {
	priv, _ := testKey(t)

	t.Run("stand-in success", func(t *testing.T) {
		useSDK(t, (&recordingSDK{idx: &fakeIndexer{roots: []common.Hash{{1}}}}).sdk())
		if _, err := Upload(context.Background(), []byte("ct"), sealedIndexer, sealedRPC, priv); err != nil {
			t.Fatalf("Upload: %v", err)
		}
	})
	t.Run("stand-in failure", func(t *testing.T) {
		useSDK(t, (&recordingSDK{idx: &fakeIndexer{err: context.Canceled}}).sdk())
		if _, err := Upload(context.Background(), []byte("ct"), sealedIndexer, sealedRPC, priv); err == nil {
			t.Fatal("Upload succeeded against a failing SDK")
		}
	})
	t.Run("real SDK, refusing endpoints", func(t *testing.T) {
		srv, rpcCalls := jsonRPCErrorServer(t)
		n := len(logger.Lines())
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err := Upload(ctx, []byte("ciphertext"), srv.URL, srv.URL, priv)
		if err == nil {
			t.Fatal("Upload succeeded against endpoints that refuse every call")
		}
		if rpcCalls.Load() == 0 {
			t.Fatalf("the real SDK made no call (err = %v); the test did not exercise it", err)
		}
		msg := err.Error()
		if !strings.HasPrefix(msg, "0g-storage upload: ") || strings.Contains(msg, "\n") || !strings.Contains(msg, "method not found") {
			t.Fatalf("err = %q, want one line carrying the SDK's cause", msg)
		}
		assertNoKey(t, "error", msg)
		logged := strings.Join(logSince(n), "\n")
		assertNoKey(t, "sealed log", logged)
		if !strings.Contains(logged, "0g-storage: ") || !strings.Contains(logged, "Selecting nodes") {
			t.Fatalf("the SDK's log for the failed call is not in sealed's log:\n%s", logged)
		}
	})
}

// processAPIs are the identifiers, by import path, that start a process.
var processAPIs = map[string]func(sel string) bool{
	"os/exec":                  func(string) bool { return true },
	"golang.org/x/sys/execabs": func(string) bool { return true }, // os/exec with a PATH check
	"os":                       func(sel string) bool { return sel == "StartProcess" },
	"syscall": func(sel string) bool {
		return sel == "ForkExec" || sel == "Exec" || sel == "StartProcess"
	},
	"golang.org/x/sys/unix": func(sel string) bool {
		return sel == "Exec" || sel == "ForkExec" || strings.HasPrefix(sel, "Clone") || sel == "Vfork"
	},
	// sealed's own command builders (RootCommand and AgentCommand, which
	// the root-side hardening adds to internal/privsep): a call through
	// them starts a process too, so the upload-path check must see it.
	"seal-verify/internal/privsep": func(sel string) bool { return sel == "RootCommand" || sel == "AgentCommand" },
}

// pkgIndex is this package's non-test source: its top-level declarations
// and, per declaration, the file's import names.
type pkgIndex struct {
	fset        *token.FileSet
	decls       map[string]ast.Node            // "Name" or "Type.Method"
	methods     map[string][]string            // method name -> "Type.Method" keys
	typeMethods map[string][]string            // type name -> "Type.Method" keys
	imports     map[ast.Node]map[string]string // decl -> import name -> path
}

func indexPackage(t *testing.T) *pkgIndex {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	pkg, ok := pkgs["dataplane"]
	if !ok {
		t.Fatalf("no package dataplane in %v", pkgs)
	}
	ix := &pkgIndex{
		fset:        fset,
		decls:       map[string]ast.Node{},
		methods:     map[string][]string{},
		typeMethods: map[string][]string{},
		imports:     map[ast.Node]map[string]string{},
	}
	for _, f := range pkg.Files {
		names := importNames(f)
		add := func(key string, n ast.Node) {
			ix.decls[key] = n
			ix.imports[n] = names
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil {
					add(d.Name.Name, d)
					continue
				}
				typ := d.Recv.List[0].Type
				if star, ok := typ.(*ast.StarExpr); ok {
					typ = star.X
				}
				typeName := typ.(*ast.Ident).Name
				key := typeName + "." + d.Name.Name
				add(key, d)
				ix.methods[d.Name.Name] = append(ix.methods[d.Name.Name], key)
				ix.typeMethods[typeName] = append(ix.typeMethods[typeName], key)
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.ValueSpec:
						for _, n := range s.Names {
							add(n.Name, s)
						}
					case *ast.TypeSpec:
						add(s.Name.Name, s)
					}
				}
			}
		}
	}
	return ix
}

// reach returns the declarations reachable from root by name: every
// top-level identifier a reached declaration mentions, every method whose
// name it selects (conservatively, of any type), and every method of a
// reached type (it may be called through an interface, as logRing.Write is
// by logrus).
func (ix *pkgIndex) reach(root string) map[string]bool {
	seen := map[string]bool{}
	queue := []string{root}
	for len(queue) > 0 {
		key := queue[0]
		queue = queue[1:]
		if seen[key] {
			continue
		}
		n, ok := ix.decls[key]
		if !ok {
			continue
		}
		seen[key] = true
		if _, ok := n.(*ast.TypeSpec); ok {
			queue = append(queue, ix.typeMethods[key]...)
		}
		ast.Inspect(n, func(x ast.Node) bool {
			switch x := x.(type) {
			case *ast.Ident:
				if _, ok := ix.decls[x.Name]; ok {
					queue = append(queue, x.Name)
				}
			case *ast.SelectorExpr:
				queue = append(queue, ix.methods[x.Sel.Name]...)
			}
			return true
		})
	}
	return seen
}

// processSelector reports whether x names a process-starting API, given
// the import names in scope (name -> path).
func processSelector(x *ast.SelectorExpr, names map[string]string) bool {
	id, ok := x.X.(*ast.Ident)
	if !ok {
		return false
	}
	match, ok := processAPIs[names[id.Name]]
	return ok && match(x.Sel.Name)
}

// importNames maps the import names a file uses to their paths.
func importNames(f *ast.File) map[string]string {
	names := map[string]string{}
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		name := filepath.Base(path)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		names[name] = path
	}
	return names
}

// processCalls lists, for the declarations in keys, every mention of a
// process-starting API or of commandContext.
func (ix *pkgIndex) processCalls(keys map[string]bool) []string {
	var found []string
	for key := range keys {
		n := ix.decls[key]
		names := ix.imports[n]
		ast.Inspect(n, func(x ast.Node) bool {
			switch x := x.(type) {
			case *ast.SelectorExpr:
				if processSelector(x, names) {
					id := x.X.(*ast.Ident)
					found = append(found, key+": "+id.Name+"."+x.Sel.Name+" at "+ix.fset.Position(x.Pos()).String())
				}
			case *ast.Ident:
				if x.Name == "commandContext" {
					found = append(found, key+": commandContext at "+ix.fset.Position(x.Pos()).String())
				}
			}
			return true
		})
	}
	sort.Strings(found)
	return found
}

// TestUploadPath_NamesNoProcessAPI: nothing Upload can reach in this
// package mentions a process-starting API, while Download's path does
// (which shows the check sees one when it is there).
func TestUploadPath_NamesNoProcessAPI(t *testing.T) {
	ix := indexPackage(t)

	up := ix.reach("Upload")
	for _, want := range []string{"Upload", "uploadContext", "runBounded", "storageSDK", "sdk.upload", "boundSigner.SignTransaction", "refuseSendsAfter", "configureSDKLogging", "callLogger", "ringWriter.Write"} {
		if !up[want] {
			t.Fatalf("Upload does not reach %s; the reachability walk is broken (reached %v)", want, keys(up))
		}
	}
	if found := ix.processCalls(up); len(found) > 0 {
		t.Fatalf("the upload path can start a process:\n%s", strings.Join(found, "\n"))
	}

	down := ix.reach("Download")
	if found := ix.processCalls(down); len(found) == 0 {
		t.Fatal("found no process API on Download's path; the check no longer recognises one")
	}
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// processAPIUsers are the non-standard packages in this package's
// dependencies (as built into the image: linux/amd64, no cgo) whose source
// names a process-starting API (processAPIs), each reviewed: none is
// called on the upload path.
//
//	github.com/getsentry/sentry-go               runs git (execabs) to name a release, only when a
//	                                             sentry client is initialised; linked via
//	                                             cockroachdb/errors, pebble and go-ethereum's ethdb
//	github.com/shirou/gopsutil/internal/common   CPU/host queries for go-ethereum's metrics collection
//	golang.org/x/sys/execabs                     the os/exec wrapper sentry-go uses
//	golang.org/x/sys/unix                        its Exec wrapper around syscall.Exec; sealed linked
//	                                             the package before (internal/privsep, for Prctl)
//	seal-verify/internal/privsep                 sealed's own command builders (RootCommand for the
//	                                             download CLI, AgentCommand for the frameworks); the
//	                                             upload path calls neither (TestUploadPath_NamesNoProcessAPI,
//	                                             and the root-side guard gives Upload no binary)
var processAPIUsers = []string{
	"github.com/getsentry/sentry-go",
	"github.com/shirou/gopsutil/internal/common",
	"golang.org/x/sys/execabs",
	"golang.org/x/sys/unix",
	"seal-verify/internal/privsep",
}

// TestDependencies_ProcessAPIUsersReviewed fails when a dependency change
// (an SDK or go-ethereum bump, say) adds a package whose source names a
// process-starting API, so it is reviewed against the upload path before
// processAPIUsers is updated. It parses the Go files each dependency is
// built from, with the processAPIs table the upload-path check uses.
func TestDependencies_ProcessAPIUsersReviewed(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		goBin = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	cmd := exec.Command(goBin, "list", "-deps", "-f",
		`{{if not .Standard}}{{.ImportPath}}{{"\t"}}{{.Dir}}{{range .GoFiles}}{{"\t"}}{{.}}{{end}}{{end}}`, ".")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	fset := token.NewFileSet()
	var got, hits []string
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 3 || f[0] == "seal-verify/internal/dataplane" {
			continue
		}
		pkg, dir, uses := f[0], f[1], false
		for _, name := range f[2:] {
			file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parse %s: %v", filepath.Join(dir, name), err)
			}
			names := importNames(file)
			ast.Inspect(file, func(x ast.Node) bool {
				if sel, ok := x.(*ast.SelectorExpr); ok && processSelector(sel, names) {
					if !uses {
						hits = append(hits, pkg+": "+sel.X.(*ast.Ident).Name+"."+sel.Sel.Name+" at "+fset.Position(sel.Pos()).String())
					}
					uses = true
				}
				return true
			})
		}
		if uses {
			got = append(got, pkg)
		}
	}
	sort.Strings(got)
	if !slices.Equal(got, processAPIUsers) {
		t.Fatalf("non-standard dependencies naming a process-starting API = %q, want the reviewed %q; first use in each:\n%s",
			got, processAPIUsers, strings.Join(hits, "\n"))
	}
}
