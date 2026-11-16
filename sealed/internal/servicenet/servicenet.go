// Package servicenet holds the network adapters sealed loads into hosted
// service processes. A service process may open only Unix sockets
// (servicesandbox); the adapters send the runtime's ordinary TCP clients to
// sealed's per-identity egress and model proxies, so service code needs no
// sealed-specific networking:
//
//   - node/bootstrap.mjs, loaded with `node --import`, redirects node:net
//     and node:tls connects (fetch, node:http/https, http2 and the clients
//     built on them);
//   - python/sitecustomize.py, first on PYTHONPATH, redirects
//     socket.create_connection, urllib3, asyncio and aiohappyeyeballs.
//
// They are conveniences, not boundaries: the kernel confinement holds
// whatever a program does. They are built into the sealed binary, so they
// ship, upgrade and are measured with the sealed layer; the image provides
// only the interpreters.
package servicenet

import (
	"embed"
	"io/fs"
	"path/filepath"

	"seal-verify/internal/privsep"
)

//go:embed node/bootstrap.mjs python/sitecustomize.py
var files embed.FS

// NodeBootstrap is the Node adapter below an Install root.
func NodeBootstrap(root string) string { return filepath.Join(root, "node", "bootstrap.mjs") }

// PythonPath is the directory below an Install root that holds the Python
// adapter.
func PythonPath(root string) string { return filepath.Join(root, "python") }

// Install writes the adapters below root, created as needed, with the
// caller's ownership (sealed's: root), directories 0755 and files 0644, so
// service identities can read them and only root can change them.
func Install(root string) error {
	return fs.WalkDir(files, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		dst := filepath.Join(root, filepath.FromSlash(p))
		if d.IsDir() {
			if err := privsep.MkdirAll(dst, 0755); err != nil {
				return err
			}
			return privsep.Chmod(dst, 0755)
		}
		b, err := files.ReadFile(p)
		if err != nil {
			return err
		}
		return privsep.WriteFile(dst, b, 0644)
	})
}
