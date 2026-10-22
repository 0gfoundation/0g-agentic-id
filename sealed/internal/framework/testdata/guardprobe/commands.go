// Package guardprobe is not built: it is planted code the root-side guard's
// own test scans (TestRootSideGuardFlagsEveryForbiddenShape), one forbidden
// shape per function, named after it.
package guardprobe

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"reflect"

	"seal-verify/internal/privsep"
)

type holder struct {
	cmd *exec.Cmd
	any any
}

func newCommand() (*exec.Cmd, error) {
	return privsep.RootCommand(context.Background(), "npm")
}

// useCommand takes a command as a command: its body is judged in turn.
func useCommand(c *exec.Cmd) error { return c.Wait() }

func addressOfDir(cmd *exec.Cmd) {
	d := &cmd.Dir
	*d = "/root/.openclaw"
}

func writeThroughAddressOfEnv(cmd *exec.Cmd) {
	*(&cmd.Env) = append(cmd.Env, "X=/root/.openclaw/x")
}

func copyIntoArgs(cmd *exec.Cmd) {
	copy(cmd.Args[1:], []string{"--prefix=/root/.openclaw"})
}

func decodeIntoCommand(cmd *exec.Cmd, b []byte) {
	_ = json.Unmarshal(b, cmd)
}

func decodeIntoAddress(b []byte) {
	cmd, _ := newCommand()
	_ = json.NewDecoder(nil).Decode(&cmd)
}

func commandAsInterface(cmd *exec.Cmd) {
	var x any = cmd
	_ = x
}

func commandInInterfaceField(cmd *exec.Cmd) holder {
	return holder{cmd: cmd, any: cmd}
}

func commandToFormatter(cmd *exec.Cmd) string {
	return fmt.Sprintf("%v", cmd)
}

func commandToFunctionValue(cmd *exec.Cmd) {
	f := useCommand
	_ = f(cmd)
}

func commandThroughReflect(cmd *exec.Cmd) {
	reflect.ValueOf(cmd).Elem().FieldByName("Path").SetString("/root/.openclaw/bin/node")
}

func assignsPath(cmd *exec.Cmd) {
	cmd.Path = "/root/.openclaw/bin/node"
}

func assignsDir(cmd *exec.Cmd) {
	cmd.Dir = "/root/.openclaw"
}

func referencesCredential(cmd *exec.Cmd) {
	_ = cmd.SysProcAttr
}

func startsDirectly() {
	_ = exec.Command("node")
}

func passesAsACommand(cmd *exec.Cmd) {
	_ = useCommand(cmd)
}
