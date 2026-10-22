//go:build linux

package privsep

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// sealed's own TLS trust.
//
// sealed (root) makes its own outbound connections — chain RPC, the
// attestor, the storage indexer, the inference router — with Go's default
// TLS configuration, whose trusted roots crypto/x509 loads once, on first
// use, from the image's trust store, plus whatever SSL_CERT_FILE names
// (read with a plain, link-following read) and every file in the
// directories SSL_CERT_DIR lists. sealed's environment is the container's,
// which the deploy request sets, so those two variables could name a file
// inside an agent tree: an agent-written CA would then be trusted by root's
// own connections, and a FIFO there would block the first handshake. The
// same rule RootCommand applies (CA locations come from the image) applies
// to sealed itself: ScrubTrustEnv keeps a CA location only when it names
// root-only files, and removes it otherwise. Proxy endpoints are honoured
// by sealed's own clients as they are by RootCommand's; a proxy sees which
// hosts are contacted but cannot read or alter a TLS connection, whose
// certificate the image's trust store still verifies.

// ScrubTrustEnv makes sealed's own CA locations (SSL_CERT_FILE and
// SSL_CERT_DIR, the variables crypto/x509 reads on Linux) safe to use, and
// returns one line per change for the boot log. It must run before sealed's
// first TLS connection (crypto/x509 reads the variables once, then caches
// the pool); Harden runs it first.
//
// SSL_CERT_FILE is kept only when it resolves to a regular file that, with
// every directory above it, is owned by root and writable by nobody else,
// and is then replaced by that resolved path, so the later read cannot be
// sent elsewhere through a link. SSL_CERT_DIR keeps only the directories
// that resolve to such a directory and whose every entry is a directory or
// resolves to such a regular file (a FIFO or device there would block or
// misbehave on read), again as resolved paths. Anything else is removed from
// the environment, and the image's trust store applies.
func ScrubTrustEnv() []string {
	var lines []string
	if v, ok := os.LookupEnv("SSL_CERT_FILE"); ok {
		real, err := rootOnlyCAFile(v)
		lines = append(lines, applyTrustEnv("SSL_CERT_FILE", v, real, err)...)
	}
	if v, ok := os.LookupEnv("SSL_CERT_DIR"); ok {
		var keep, why []string
		for _, d := range filepath.SplitList(v) {
			if d == "" {
				continue
			}
			real, err := rootOnlyCADir(d)
			if err != nil {
				why = append(why, fmt.Sprintf("%s: %v", d, err))
				continue
			}
			keep = append(keep, real)
		}
		joined := strings.Join(keep, string(os.PathListSeparator))
		var err error
		if len(why) > 0 {
			err = fmt.Errorf("%s", strings.Join(why, "; "))
		}
		if len(keep) == 0 && err == nil {
			err = fmt.Errorf("names no directory")
		}
		lines = append(lines, applyTrustEnv("SSL_CERT_DIR", v, joined, err)...)
	}
	return lines
}

// applyTrustEnv sets name to real (when it is not empty) or removes it, and
// describes what changed.
func applyTrustEnv(name, was, real string, err error) []string {
	if real == "" {
		os.Unsetenv(name)
		return []string{fmt.Sprintf("%s=%q removed from sealed's environment (CA locations must name root-only files: %v); TLS trusts the image's store", name, was, err)}
	}
	var lines []string
	if err != nil {
		lines = append(lines, fmt.Sprintf("%s: entries dropped (CA locations must name root-only files): %v", name, err))
	}
	if real != was {
		os.Setenv(name, real)
		lines = append(lines, fmt.Sprintf("%s=%q used as %q", name, was, real))
	}
	return lines
}

// rootOnlyCAFile resolves p and checks that it is a root-only regular file.
func rootOnlyCAFile(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("empty")
	}
	real, err := resolveCALocation(p)
	if err != nil {
		return "", err
	}
	if err := rootOnly(real, unix.S_IFREG); err != nil {
		return "", err
	}
	return real, nil
}

// resolveCALocation resolves a CA location to an absolute path without
// links. crypto/x509 opens a relative location against the working
// directory, so a relative one is first made absolute against sealed's
// (which is what it named when crypto/x509 would have read it), and the
// variable is then set to the absolute result.
func resolveCALocation(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

// rootOnlyCADir resolves d, checks that it is a root-only directory, and
// that every entry in it (which crypto/x509 reads, following links) is a
// directory (whose read fails harmlessly) or resolves to a root-only
// regular file or directory.
func rootOnlyCADir(d string) (string, error) {
	real, err := resolveCALocation(d)
	if err != nil {
		return "", err
	}
	if err := rootOnly(real, unix.S_IFDIR); err != nil {
		return "", err
	}
	ents, err := os.ReadDir(real)
	if err != nil {
		return "", err
	}
	for _, e := range ents {
		p := filepath.Join(real, e.Name())
		var st unix.Stat_t
		if err := unix.Lstat(p, &st); err != nil {
			return "", err
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			continue
		case unix.S_IFREG:
			if err := rootOnly(p, unix.S_IFREG); err != nil {
				return "", err
			}
		case unix.S_IFLNK:
			// The target must already exist and be root-only too: a target
			// under a directory another uid can write could be created or
			// replaced (by a FIFO, say) before crypto/x509 reads it.
			t, err := filepath.EvalSymlinks(p)
			if err != nil {
				return "", err
			}
			var tst unix.Stat_t
			if err := unix.Lstat(t, &tst); err != nil {
				return "", err
			}
			typ := uint32(unix.S_IFREG)
			if tst.Mode&unix.S_IFMT == unix.S_IFDIR {
				typ = unix.S_IFDIR
			}
			if err := rootOnly(t, typ); err != nil {
				return "", fmt.Errorf("%s -> %v", p, err)
			}
		default:
			return "", fmt.Errorf("%s is not a regular file", p)
		}
	}
	return real, nil
}
