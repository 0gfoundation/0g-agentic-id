//go:build linux

package servicesandbox

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func launch(args []string) error {
	if os.Geteuid() != 0 || len(args) == 0 {
		return fmt.Errorf("requires sealed root and a mode")
	}
	switch args[0] {
	case "run":
		p, err := ParseRun(args[1:])
		if err != nil {
			return err
		}
		return Run(p)
	case "probe":
		if err := Probe(); err != nil {
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
		return Reap(uint32(uid), 2*time.Second)
	}
	return fmt.Errorf("unknown mode %q", args[0])
}
