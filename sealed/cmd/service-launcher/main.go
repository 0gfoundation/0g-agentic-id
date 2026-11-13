//go:build linux

// Trusted root-side helper for hosted service processes (servicesandbox):
//
//	run   confine to a service identity, Landlock and seccomp, then exec the program
//	probe check that this kernel and container enforce that confinement
//	reap  kill every process of one service identity
//
// sealed starts it as root; run sets the rlimits only after leaving root.
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"seal-verify/internal/servicesandbox"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "service-launcher:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if os.Geteuid() != 0 || len(args) == 0 {
		return fmt.Errorf("requires sealed root and a mode")
	}
	switch args[0] {
	case "run":
		p, err := servicesandbox.ParseRun(args[1:])
		if err != nil {
			return err
		}
		return servicesandbox.Run(p)
	case "probe":
		if err := servicesandbox.Probe(); err != nil {
			return err
		}
		fmt.Println("ok")
		return nil
	case "reap":
		if len(args) != 2 || !strings.HasPrefix(args[1], "--uid=") {
			return fmt.Errorf("reap requires --uid")
		}
		uid, err := strconv.ParseUint(strings.TrimPrefix(args[1], "--uid="), 10, 32)
		if err != nil {
			return fmt.Errorf("invalid uid")
		}
		return servicesandbox.Reap(uint32(uid), 2*time.Second)
	}
	return fmt.Errorf("unknown mode %q", args[0])
}
