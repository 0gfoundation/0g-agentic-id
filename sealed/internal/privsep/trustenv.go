//go:build linux

package privsep

import (
	"fmt"
	"os"
)

// sealed's own TLS trust.
//
// sealed (root) makes its own outbound connections — chain RPC, the
// attestor, the storage indexer, the inference router — with Go's default
// TLS configuration, whose trusted roots crypto/x509 loads once, on first
// use, from the image's trust store, or instead from whatever SSL_CERT_FILE
// names and the files in the directories SSL_CERT_DIR lists. sealed's
// environment is the container's, which the deploy request sets, so those
// two variables would let the deploy request choose the CAs root trusts: a
// file inside an agent tree, a FIFO that blocks the first handshake, or a
// root-owned file whose contents the caller still sets (/proc/self/environ
// is root-owned and 0400, and holds the values of the caller's other
// variables, so a PEM in one of them would be trusted). No sealed image
// sets either variable, so ScrubTrustEnv removes both, whatever they name:
// the same rule RootCommand applies (CA locations come from the image)
// applies to sealed itself. The provider also strips both from every sealed
// create, and the attestor relays no owner variable but API_KEY and
// SEAL_SECRET_ENV; this check does not depend on either. Proxy endpoints
// are honoured by sealed's own clients as they are by RootCommand's; a
// proxy sees which hosts are contacted but cannot read or alter a TLS
// connection, whose certificate the image's trust store still verifies.

// trustEnv lists the variables crypto/x509 reads on Linux to locate CAs.
var trustEnv = []string{"SSL_CERT_FILE", "SSL_CERT_DIR"}

// ScrubTrustEnv removes sealed's own CA locations (SSL_CERT_FILE and
// SSL_CERT_DIR) from its environment, so TLS trusts the image's store
// only, and returns one line per variable removed for the boot log. It must
// run before sealed's first TLS connection (crypto/x509 reads the variables
// once, then caches the pool); Harden runs it first.
func ScrubTrustEnv() []string {
	var lines []string
	for _, name := range trustEnv {
		v, ok := os.LookupEnv(name)
		if !ok {
			continue
		}
		os.Unsetenv(name)
		lines = append(lines, fmt.Sprintf("%s=%q removed from sealed's environment (CA locations come from the image); TLS trusts the image's store", name, v))
	}
	return lines
}
