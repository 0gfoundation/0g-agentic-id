package main

// Fetching a sealed version: the program the trust registry lists under its
// sha256, downloaded from the official artifacts release. Where it comes from
// does not matter for trust: the hash comes from the chain, and a download
// counts only if it hashes to that name. It is written to a temporary file in
// the loader's state directory, hashed as it is written, and renamed into
// place (sealed/<hash>) only when it hashes to its name; it is hashed once
// more right before it runs (verifyFile). What a stop or a crash cut off
// mid-download (a name that is no hash) is removed by the next sealed at its
// boot (internal/layers CleanCutOffStaging).

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	// artifactsURL is where the official artifacts are published: the assets
	// of the `artifacts` release of the public GitHub repository
	// 0gfoundation/0g-agentic-id, each named by its sha256. sealed fetches
	// from the same place (internal/layers ArtifactsURL; keep the two in
	// step, TestArtifactsURLMatchesSealed pins it).
	artifactsURL = "https://github.com/0gfoundation/0g-agentic-id/releases/download/artifacts"
	// maxSealedBytes bounds one sealed program.
	maxSealedBytes = 64 << 20
	// fetchTimeout bounds one download, body included.
	fetchTimeout = 5 * time.Minute
	// maxRedirects bounds the redirects one download follows (the release
	// redirects once, to GitHub's storage host).
	maxRedirects = 5
)

// errMismatch: a download did not hash to its name.
var errMismatch = errors.New("the download does not hash to its name")

// newArtifactClient is the HTTP client downloads use: the system's roots,
// at most maxRedirects redirects.
func newArtifactClient() *http.Client {
	return &http.Client{
		Timeout: fetchTimeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return fmt.Errorf("more than %d redirects", maxRedirects)
			}
			return nil
		},
	}
}

// fetchSealed downloads version hash from base into the state directory as
// d.staged(hash), replacing what is there. A download that does not hash to
// its name is remembered in d and never made again in this container.
func fetchSealed(client *http.Client, base string, d stateDir, hash string) error {
	if d.mismatched(hash) {
		return fmt.Errorf("%w earlier in this container; not downloading it again", errMismatch)
	}
	dir := filepath.Dir(d.staged(hash))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	tmp := filepath.Join(dir, ".fetch-"+hash+"-"+hex.EncodeToString(suffix[:]))
	defer os.Remove(tmp)
	err := download(client, base+"/"+hash, tmp, hash)
	if errors.Is(err, errMismatch) {
		if merr := d.markMismatched(hash); merr != nil {
			return fmt.Errorf("%w (and recording it: %v)", err, merr)
		}
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, d.staged(hash))
}

// download writes what url serves to path, a new file executable by root
// only, failing unless it is at most maxSealedBytes and hashes to want.
func download(client *http.Client, url, path, want string) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o500)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxSealedBytes+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	switch {
	case err != nil:
		return err
	case n > maxSealedBytes:
		return fmt.Errorf("larger than %d bytes", maxSealedBytes)
	case hex.EncodeToString(h.Sum(nil)) != want:
		return errMismatch
	}
	return nil
}
