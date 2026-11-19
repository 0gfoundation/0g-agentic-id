//go:build !linux

package main

// harden is a no-op off Linux. The loader only runs in Linux images; this
// file lets the package build and its tests run elsewhere.
func harden() {}
