package framework

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/token"
	"go/types"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// The root-side guard judges what a command's fields are by their type, not
// by their name or by what the file imports: every package of the module is
// type-checked against the real os/exec, so a .Env, .Dir, .Path, .Args or
// .ExtraFiles selector is a command's exactly when it selects a field of
// exec.Cmd — through any variable, struct field, alias, helper result or
// embedding, in any file — and a command value can be followed wherever it
// goes.
//
// The check is tolerant: only os/exec (and what it imports) is loaded from
// the standard library, the module's own packages from their sources, and
// every other import is an empty stand-in, so expressions built from those
// packages have no type and type errors are ignored. That loses nothing the
// guard needs: a command can only come from os/exec, through privsep or a
// helper of the module's own.

// modulePath is the module's import path (go.mod).
const modulePath = "seal-verify"

// typedPackage is one type-checked package of the module.
type typedPackage struct {
	info *types.Info
	pkg  *types.Package
}

// moduleTypes type-checks the module's packages on demand.
type moduleTypes struct {
	fset   *token.FileSet
	root   string                 // module root on disk
	files  map[string][]*ast.File // pkgDir → parsed non-test files, when the scan has them
	parse  func(dir string) ([]*ast.File, error)
	std    types.Importer
	pkgs   map[string]*typedPackage // import path → checked package
	fakes  map[string]*types.Package
	inProg map[string]bool
}

func newModuleTypes(fset *token.FileSet, root string, files map[string][]*ast.File, parse func(dir string) ([]*ast.File, error)) *moduleTypes {
	return &moduleTypes{
		fset: fset, root: root, files: files, parse: parse,
		std:    importer.ForCompiler(fset, "source", nil),
		pkgs:   map[string]*typedPackage{},
		fakes:  map[string]*types.Package{},
		inProg: map[string]bool{},
	}
}

// Import implements types.Importer.
func (m *moduleTypes) Import(p string) (*types.Package, error) {
	switch {
	case p == "os/exec":
		return m.std.Import(p)
	case strings.HasPrefix(p, modulePath+"/"):
		if tp := m.check(strings.TrimPrefix(p, modulePath+"/")); tp != nil {
			return tp.pkg, nil
		}
	}
	if f, ok := m.fakes[p]; ok {
		return f, nil
	}
	f := types.NewPackage(p, guessPackageName(p))
	f.MarkComplete()
	m.fakes[p] = f
	return f, nil
}

// check type-checks the module package in pkgDir ("." for main) once.
func (m *moduleTypes) check(pkgDir string) *typedPackage {
	ip := modulePath
	if pkgDir != "." {
		ip = modulePath + "/" + pkgDir
	}
	if tp, ok := m.pkgs[ip]; ok {
		return tp
	}
	if m.inProg[ip] {
		return nil
	}
	m.inProg[ip] = true
	defer delete(m.inProg, ip)
	files, ok := m.files[pkgDir]
	if !ok {
		var err error
		if files, err = m.parse(filepath.Join(m.root, filepath.FromSlash(pkgDir))); err != nil {
			return nil
		}
	}
	files = linuxFiles(m.fset, files)
	info := &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
	}
	conf := types.Config{Importer: m, Error: func(error) {}, FakeImportC: true}
	pkg, _ := conf.Check(ip, m.fset, files, info)
	tp := &typedPackage{info: info, pkg: pkg}
	m.pkgs[ip] = tp
	return tp
}

// linuxFiles keeps the files a linux build compiles (sealed runs on linux;
// a file and its !linux counterpart declare the same names).
func linuxFiles(fset *token.FileSet, files []*ast.File) []*ast.File {
	ctxt := build.Default
	ctxt.GOOS = "linux"
	var out []*ast.File
	for _, f := range files {
		name := fset.Position(f.Pos()).Filename
		if ok, err := ctxt.MatchFile(filepath.Dir(name), filepath.Base(name)); err == nil && ok {
			out = append(out, f)
		}
	}
	return out
}

var majorVersion = regexp.MustCompile(`^v[0-9]+$`)

// guessPackageName names a stand-in package after its import path
// ("gopkg.in/yaml.v3" → yaml, ".../go-ethereum/v2" → go_ethereum). A wrong
// guess only leaves more expressions untyped.
func guessPackageName(p string) string {
	base := path.Base(p)
	if majorVersion.MatchString(base) {
		base = path.Base(path.Dir(p))
	}
	base, _, _ = strings.Cut(base, ".")
	return strings.NewReplacer("-", "_").Replace(base)
}

// isCommandType reports whether t is exec.Cmd, or a pointer (to a pointer…)
// to one.
func isCommandType(t types.Type) bool {
	for t != nil {
		switch x := t.(type) {
		case *types.Pointer:
			t = x.Elem()
		case *types.Named:
			o := x.Obj()
			return o.Pkg() != nil && o.Pkg().Path() == "os/exec" && o.Name() == "Cmd"
		case *types.Alias:
			t = types.Unalias(x)
		default:
			return false
		}
	}
	return false
}

// commandField reports whether sel selects a field of exec.Cmd (directly,
// through a pointer, or promoted from an embedded command), and whether
// that could be established at all (known is false when the receiver has
// no type).
func commandField(info *types.Info, sel *ast.SelectorExpr) (isCmd, known bool) {
	if s := info.Selections[sel]; s != nil {
		if s.Kind() != types.FieldVal {
			return false, true
		}
		o := s.Obj()
		return o.Pkg() != nil && o.Pkg().Path() == "os/exec", true
	}
	if tv, ok := info.Types[sel.X]; ok && tv.Type != nil && tv.Type != types.Typ[types.Invalid] {
		return false, true // typed, but not a field: a method value, or a qualified name
	}
	return false, false
}

// commandEscape judges where the command-typed expression at the top of
// stack (stack[len-1]; its ancestors below it) goes. A command may be
// selected from (its fields, its methods), compared, written to, or held
// in a place typed as a command — a variable, field, slice or map element,
// parameter or result — of code in the module, whose uses the guard judges
// in turn. Anything else hands it to code the guard does not see (a
// function outside the module, such as a reflection-based decoder that
// sets its fields, an interface, a function value) and is reported, with
// what it was handed to.
func commandEscape(info *types.Info, stack []ast.Node, sigs []*types.Signature) (string, bool) {
	accepts := func(t types.Type) bool { return isCommandType(t) }
	typeOf := func(e ast.Expr) types.Type {
		if tv, ok := info.Types[e]; ok {
			return tv.Type
		}
		if id, ok := e.(*ast.Ident); ok {
			if o := info.Defs[id]; o != nil {
				return o.Type()
			}
			if o := info.Uses[id]; o != nil {
				return o.Type()
			}
		}
		return nil
	}
	child := stack[len(stack)-1].(ast.Expr)
	for i := len(stack) - 2; i >= 0; i-- {
		switch p := stack[i].(type) {
		case *ast.ParenExpr, *ast.StarExpr:
			child = p.(ast.Expr)
			continue
		case *ast.UnaryExpr:
			if p.Op == token.AND {
				child = p
				continue
			}
			return "an operator", true
		case *ast.SelectorExpr:
			if p.X == child {
				return "", false
			}
			return "", false // the field name itself
		case *ast.BinaryExpr:
			if p.Op == token.EQL || p.Op == token.NEQ {
				return "", false
			}
			return "an operator", true
		case *ast.Field, *ast.ValueSpec:
			if vs, ok := p.(*ast.ValueSpec); ok {
				for _, v := range vs.Values {
					if v == child && vs.Type != nil && !accepts(typeOf(vs.Type)) {
						return "a variable of type " + types.ExprString(vs.Type), true
					}
				}
			}
			return "", false
		case *ast.AssignStmt:
			for _, l := range p.Lhs {
				if l == child {
					return "", false
				}
			}
			for j, r := range p.Rhs {
				if r != child {
					continue
				}
				if len(p.Lhs) != len(p.Rhs) {
					return "a multi-value assignment", true
				}
				if p.Tok == token.DEFINE {
					if id, ok := p.Lhs[j].(*ast.Ident); ok && info.Defs[id] != nil {
						if accepts(info.Defs[id].Type()) {
							return "", false
						}
					}
				}
				if t := typeOf(p.Lhs[j]); accepts(t) {
					return "", false
				}
				return types.ExprString(p.Lhs[j]) + " (not typed as a command)", true
			}
			return "an assignment", true
		case *ast.ReturnStmt:
			if len(sigs) == 0 {
				return "a return", true
			}
			res := sigs[len(sigs)-1].Results()
			for j, r := range p.Results {
				if r == child && len(p.Results) == res.Len() && accepts(res.At(j).Type()) {
					return "", false
				}
			}
			return "a result not typed as a command", true
		case *ast.CallExpr:
			if p.Fun == child {
				return "a call", true
			}
			return commandArgument(info, p, child, typeOf)
		case *ast.KeyValueExpr:
			if i == 0 {
				return "a composite literal", true
			}
			lit, ok := stack[i-1].(*ast.CompositeLit)
			if !ok {
				return "a composite literal", true
			}
			lt := typeOf(lit)
			if lt == nil {
				return "a composite literal of unknown type", true
			}
			switch u := lt.Underlying().(type) {
			case *types.Struct:
				if p.Key == child {
					return "", false // the field name
				}
				name, _ := p.Key.(*ast.Ident)
				for k := 0; name != nil && k < u.NumFields(); k++ {
					if u.Field(k).Name() == name.Name && accepts(u.Field(k).Type()) {
						return "", false
					}
				}
			case *types.Map:
				if (p.Key == child && accepts(u.Key())) || (p.Value == child && accepts(u.Elem())) {
					return "", false
				}
			case *types.Slice:
				if p.Value == child && accepts(u.Elem()) {
					return "", false
				}
			}
			return "a field or element not typed as a command", true
		case *ast.CompositeLit:
			lt := typeOf(p)
			if lt != nil {
				switch u := lt.Underlying().(type) {
				case *types.Slice:
					if accepts(u.Elem()) {
						return "", false
					}
				case *types.Array:
					if accepts(u.Elem()) {
						return "", false
					}
				}
			}
			return "an element not typed as a command", true
		case *ast.IndexExpr:
			if p.Index == child {
				return "", false // a lookup keyed by the command
			}
			return "an index expression", true
		case *ast.SendStmt:
			if ct, ok := typeOf(p.Chan).Underlying().(*types.Chan); ok && accepts(ct.Elem()) {
				return "", false
			}
			return "a channel not typed for commands", true
		case *ast.RangeStmt:
			if p.Key == child || p.Value == child {
				return "", false
			}
			return "a range", true
		default:
			return "a " + typeName(p) + " the guard does not follow", true
		}
	}
	return "", false
}

// commandArgument judges a command passed as an argument to call.
func commandArgument(info *types.Info, call *ast.CallExpr, arg ast.Expr, typeOf func(ast.Expr) types.Type) (string, bool) {
	idx := -1
	for j, a := range call.Args {
		if a == arg {
			idx = j
		}
	}
	callee := types.ExprString(call.Fun)
	fun := ast.Unparen(call.Fun)
	// The callee: a function or method of the module, whose parameter is
	// typed as a command, is judged in turn; so is a function literal.
	var sig *types.Signature
	moduleCode := false
	switch f := fun.(type) {
	case *ast.FuncLit:
		moduleCode = true
	case *ast.Ident:
		switch o := info.Uses[f].(type) {
		case *types.Builtin:
			if o.Name() == "append" && idx > 0 {
				if st, ok := typeOf(call.Args[0]).Underlying().(*types.Slice); ok && isCommandType(st.Elem()) {
					return "", false
				}
			}
			return "the builtin " + o.Name(), true
		case *types.Func:
			moduleCode = o.Pkg() != nil && (o.Pkg().Path() == modulePath || strings.HasPrefix(o.Pkg().Path(), modulePath+"/"))
		case *types.TypeName:
			if isCommandType(o.Type()) {
				return "", false // a conversion to a command type
			}
			return "a conversion to " + callee, true
		}
	case *ast.SelectorExpr:
		if s := info.Selections[f]; s != nil {
			if o, ok := s.Obj().(*types.Func); ok && o.Pkg() != nil {
				moduleCode = o.Pkg().Path() == modulePath || strings.HasPrefix(o.Pkg().Path(), modulePath+"/")
			}
		} else if o, ok := info.Uses[f.Sel].(*types.Func); ok && o.Pkg() != nil {
			moduleCode = o.Pkg().Path() == modulePath || strings.HasPrefix(o.Pkg().Path(), modulePath+"/")
		}
	}
	if t := typeOf(call.Fun); t != nil {
		sig, _ = t.Underlying().(*types.Signature)
	}
	if !moduleCode || sig == nil || idx < 0 {
		return callee + ", outside the module or of unknown type", true
	}
	params := sig.Params()
	var pt types.Type
	switch {
	case idx < params.Len()-1 || (!sig.Variadic() && idx < params.Len()):
		pt = params.At(idx).Type()
	case sig.Variadic() && params.Len() > 0:
		if call.Ellipsis.IsValid() {
			pt = params.At(params.Len() - 1).Type()
		} else if st, ok := params.At(params.Len() - 1).Type().(*types.Slice); ok {
			pt = st.Elem()
		}
	}
	if isCommandType(pt) {
		return "", false
	}
	if st, ok := pt.(*types.Slice); ok && call.Ellipsis.IsValid() && isCommandType(st.Elem()) {
		return "", false
	}
	return callee + " as a parameter not typed as a command", true
}

func typeName(n ast.Node) string { return strings.TrimPrefix(fmt.Sprintf("%T", n), "*ast.") }
