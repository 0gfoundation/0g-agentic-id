package proxy

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"path/filepath"

	"seal-verify/internal/logger"
	"seal-verify/internal/privsep"
)

// ServeAgentSocket serves h on a unix socket at sockPath that only the agent
// user may open, the way ListenInternal serves the sign socket: the
// directory, the stale entry and the mode are handled without following
// links, and the file is handed to the agent user (0600, so nobody else).
// The credential sockets use it; the socket file is the credential.
func ServeAgentSocket(sockPath, name string, h http.Handler) error {
	if err := privsep.MkdirAll(filepath.Dir(sockPath), 0o755); err != nil {
		return fmt.Errorf("%s socket: mkdir %s: %w", name, filepath.Dir(sockPath), err)
	}
	if err := privsep.Remove(sockPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s socket: remove stale %s: %w", name, sockPath, err)
	}
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("%s socket: listen %s: %w", name, sockPath, err)
	}
	if err := privsep.Chmod(sockPath, 0o600); err != nil {
		l.Close()
		_ = privsep.Remove(sockPath)
		return fmt.Errorf("%s socket: chmod %s: %w", name, sockPath, err)
	}
	privsep.OwnPath(sockPath)
	go func() {
		logger.Logf("OK   %s socket listening at unix://%s", name, sockPath)
		_ = http.Serve(l, h)
	}()
	return nil
}
