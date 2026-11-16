//go:build !linux

package servicesandbox

import "fmt"

func launch([]string) error {
	return fmt.Errorf("hosted service confinement needs Linux")
}
