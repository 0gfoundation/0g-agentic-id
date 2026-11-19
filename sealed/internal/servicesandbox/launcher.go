package servicesandbox

import (
	"fmt"
	"os"
)

// LauncherMode, as the first argument, makes the sealed program the trusted
// root-side launcher of hosted service processes instead of sealed:
//
//	<sealed> sealed-service-launcher run ...       confine to a service identity, Landlock and seccomp, then exec the program
//	<sealed> sealed-service-launcher probe         check that this kernel and container enforce that confinement
//	<sealed> sealed-service-launcher reap --uid=N  kill every process of one service identity
//
// sealed starts its own executable this way, as root (servicehost, through
// privsep.RootSelf), so a sealed version always runs with the launcher built
// with it. main dispatches it before anything else runs. run sets the
// rlimits only after leaving root.
const LauncherMode = "sealed-service-launcher"

// Launch runs the launcher with the arguments that follow LauncherMode and
// returns the process's exit code.
func Launch(args []string) int {
	if err := launch(args); err != nil {
		fmt.Fprintln(os.Stderr, "service-launcher:", err)
		return 1
	}
	return 0
}
