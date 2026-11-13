package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"seal-verify/internal/layers"
)

func TestServiceRuntimeUsesListedActivePackageWithoutImageBase(t *testing.T) {
	env := newLayeredEnv(t)
	pkg := testPackage(t, "loader-only-active")
	hash := env.serve(pkg)
	if err := layers.InstallHarness(layers.VerifyingReader(nopCloser{bytes.NewReader(pkg)}, hash), hash); err != nil {
		t.Fatal(err)
	}
	h := &fakeHarness{running: hash}
	l := &layeredRuntime{lists: fakeLists{harness: map[string]bool{hash: true}}}
	lease, err := l.acquireServiceRuntime(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	if lease.Hash != hash || lease.Dir != layers.HarnessDir(hash) {
		t.Fatal("wrong worker package")
	}
	layers.PrunePackages()
	if !layers.HarnessInstalled(hash) {
		t.Fatal("leased worker package pruned")
	}
	l.lists = fakeLists{harness: map[string]bool{hash: false}}
	if _, err := l.acquireServiceRuntime(context.Background(), h); err == nil {
		t.Fatal("delisted package admitted a new worker")
	}
	l.lists = fakeLists{unreadable: true}
	if _, err := l.acquireServiceRuntime(context.Background(), h); err == nil {
		t.Fatal("unreadable listing admitted a new worker")
	}
	lease.Release()
	layers.PrunePackages()
	if layers.HarnessInstalled(hash) {
		t.Fatal("unused worker package retained")
	}
	if _, err := os.Stat(filepath.Join(layers.PackagesDir, "base")); !os.IsNotExist(err) {
		t.Fatal("fixture unexpectedly has image base")
	}
}

func TestServiceRuntimeAdmissionHonorsContextDuringLayeredSwitch(t *testing.T) {
	l := &layeredRuntime{}
	l.busy.Lock()
	defer l.busy.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := l.acquireServiceRuntime(ctx, &fakeHarness{}); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("admission error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("service admission ignored its deadline while a layered switch held busy")
	}
}

func TestServiceRuntimeAdmissionRejectsAlreadyCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (&layeredRuntime{}).acquireServiceRuntime(ctx, &fakeHarness{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("admission error=%v", err)
	}
}
