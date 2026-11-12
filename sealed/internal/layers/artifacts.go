package layers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"time"

	"seal-verify/internal/attestorhttp"
)

// MaxArtifactBytes bounds one artifact download (a sealed program or a
// harness package).
const MaxArtifactBytes = 1 << 30

// maxArtifactBytes is the bound VerifyingReader applies; tests lower it.
var maxArtifactBytes int64 = MaxArtifactBytes

// artifactTimeout bounds one artifact download, body included.
const artifactTimeout = 15 * time.Minute

// ArtifactsURL is where the official artifacts are published: the assets of
// the `artifacts` release of the public GitHub repository
// 0gfoundation/0g-agentic-id, each named by its sha256 (64 lowercase hex).
// Where an artifact comes from does not matter for trust: its name comes
// from the trust registry's lists, and a download counts only if it hashes
// to that name. A var so tests serve their own.
var ArtifactsURL = "https://github.com/0gfoundation/0g-agentic-id/releases/download/artifacts"

// artifactClient downloads artifacts with the system's roots, following the
// release's redirect to GitHub's storage host.
var artifactClient = &http.Client{Timeout: artifactTimeout}

// ErrHashMismatch is returned when what was read does not hash to the
// artifact's name.
var ErrHashMismatch = errors.New("the artifact does not hash to its name")

// FetchArtifact opens the artifact named by hash (64 lowercase hex),
// ArtifactsURL/<hash>. The returned reader yields at most MaxArtifactBytes
// and, at its end, fails with ErrHashMismatch unless what it yielded hashes
// to hash: a caller that reads it to io.EOF has the verified bytes, and must
// discard them on any error.
func FetchArtifact(ctx context.Context, hash string) (io.ReadCloser, error) {
	if !isArtifactName(hash) {
		return nil, fmt.Errorf("artifact name %q is not a sha256 (64 lowercase hex)", hash)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ArtifactsURL+"/"+hash, nil)
	if err != nil {
		return nil, err
	}
	resp, err := artifactClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download artifact %s: %w", hash, err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		resp.Body.Close()
		return nil, fmt.Errorf("download artifact %s: HTTP %d: %s", hash, resp.StatusCode, attestorhttp.Excerpt(body))
	}
	return VerifyingReader(resp.Body, hash), nil
}

// isArtifactName reports whether name is a sha256 as 64 lowercase hex.
func isArtifactName(name string) bool {
	if len(name) != 64 {
		return false
	}
	for _, c := range name {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// VerifyingReader reads r up to MaxArtifactBytes and fails at the end
// unless the bytes hash to want (64 hex): with ErrHashMismatch, or with an
// error naming the limit when r holds more.
func VerifyingReader(r io.ReadCloser, want string) io.ReadCloser {
	return &verifying{r: r, h: sha256.New(), want: want}
}

type verifying struct {
	r    io.ReadCloser
	h    hash.Hash
	n    int64
	want string
}

func (v *verifying) Read(p []byte) (int, error) {
	n, err := v.r.Read(p)
	v.h.Write(p[:n])
	v.n += int64(n)
	if v.n > maxArtifactBytes {
		return n, fmt.Errorf("artifact larger than %d bytes", maxArtifactBytes)
	}
	if err == io.EOF && hex.EncodeToString(v.h.Sum(nil)) != v.want {
		return n, ErrHashMismatch
	}
	return n, err
}

func (v *verifying) Close() error { return v.r.Close() }
