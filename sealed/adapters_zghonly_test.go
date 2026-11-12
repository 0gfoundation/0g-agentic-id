//go:build zghonly

package main

import (
	"seal-verify/internal/framework"
	"testing"
)

func TestRegisterAdapters_ZGH(t *testing.T) {
	registerAdapters()
	for _, name := range []string{"0g-harness", "dsh"} {
		a, err := framework.Get(name)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, r := range a.(framework.RouteProvider).FrameworkRoutes() {
			found = found || r.Kind == "zgh-tasks-v1"
		}
		if !found {
			t.Fatal("zgh capabilities missing")
		}
	}
	for _, name := range []string{"openclaw", "hermes", "prime-agent"} {
		if _, err := framework.Get(name); err == nil {
			t.Errorf("unexpected adapter %s", name)
		}
	}
}
