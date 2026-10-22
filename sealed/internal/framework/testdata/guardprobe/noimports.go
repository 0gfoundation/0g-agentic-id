package guardprobe

// This file imports neither os/exec nor privsep: the commands it reaches
// come from the other file, by type inference.

func envAliasWrite() {
	cmd, _ := newCommand()
	e := cmd.Env
	e[0] = "PATH=/root/.openclaw/bin"
}

func envPathLiteral() error {
	cmd, err := newCommand()
	if err != nil {
		return err
	}
	cmd.Env = append(cmd.Env, "npm_config_userconfig=/root/.openclaw/.npmrc")
	return cmd.Run()
}

func envAddress(h holder) {
	p := &h.cmd.Env
	*p = append(*p, "NODE_OPTIONS=--require=/root/.openclaw/hook.js")
}
