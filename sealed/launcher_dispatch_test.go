package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"testing"
)

// The sealed program is the hosted-service launcher too (privsep.RootSelf
// runs it with servicesandbox.LauncherMode first). That run must leave main
// before anything else in it runs: no adapter registration, no Harden, no
// log line, no state.
func TestLauncherModeIsDispatchedFirst(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "main" || fn.Recv != nil {
			continue
		}
		first, ok := fn.Body.List[0].(*ast.IfStmt)
		if !ok || first.Init != nil {
			t.Fatal("main's first statement is not the launcher dispatch")
		}
		if got, want := types.ExprString(first.Cond), "len(os.Args) > 1 && os.Args[1] == servicesandbox.LauncherMode"; got != want {
			t.Fatalf("dispatch condition %q, want %q", got, want)
		}
		if len(first.Body.List) != 1 || first.Else != nil {
			t.Fatal("the launcher dispatch does more than exit")
		}
		call, ok := first.Body.List[0].(*ast.ExprStmt)
		if !ok || types.ExprString(call.X) != "os.Exit(servicesandbox.Launch(os.Args[2:]))" {
			t.Fatal("the launcher dispatch must be os.Exit(servicesandbox.Launch(os.Args[2:]))")
		}
		return
	}
	t.Fatal("no func main in main.go")
}
