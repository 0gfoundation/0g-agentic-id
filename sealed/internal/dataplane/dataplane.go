// Package dataplane provides the encryption + 0g-storage primitives used by
// the bootstrap pipeline. Read path:
//
//  1. Download(root, indexer) -> ciphertext bytes
//  2. UnsealDataKey(sealedKey, agentSealPriv) -> data_key
//  3. Decrypt(ciphertext, data_key) -> plaintext
//
// The uploader reuses SealDataKey, Encrypt and Upload for the symmetric
// outbound flow. Download runs the `0g-storage-client` CLI; Upload runs the
// zg-upload helper (sealed/tools/zg-upload), which takes the signing key on
// stdin (a socketpair, keyChannel).
package dataplane

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	eciesgo "github.com/ecies/go/v2"

	"seal-verify/internal/logger"
)

const downloadAttempts = 10

// Decrypt opens an AES-GCM-256 ciphertext laid out as
// nonce(12) || ciphertext+tag(16 trailing bytes).
//
// The auth tag is verified internally; on failure (wrong key, tampered
// ciphertext) returns an error with no plaintext leaked.
func Decrypt(ciphertext, dataKey []byte) ([]byte, error) {
	if len(ciphertext) < 12+16 {
		return nil, fmt.Errorf("ciphertext too short (%d bytes; need >= 28)", len(ciphertext))
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, fmt.Errorf("aes new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm init: %w", err)
	}
	plaintext, err := gcm.Open(nil, ciphertext[:12], ciphertext[12:], nil)
	if err != nil {
		return nil, fmt.Errorf("gcm open: %w", err)
	}
	return plaintext, nil
}

// Encrypt wraps plaintext with AES-GCM-256 using a freshly generated random
// nonce. Output layout: nonce(12) || ciphertext+tag(16 trailing bytes).
//
// Callers MUST use a fresh data_key per invocation; nonce reuse with the
// same key is catastrophic for AES-GCM.
func Encrypt(plaintext, dataKey []byte) ([]byte, error) {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, fmt.Errorf("aes new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm init: %w", err)
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ct...), nil
}

// UnsealDataKey decrypts a sealed data_key with the agent's seal priv key.
// Mirrors what bootstrap does for every iData entry.
func UnsealDataKey(sealedKey, agentSealPriv []byte) ([]byte, error) {
	priv := eciesgo.NewPrivateKeyFromBytes(agentSealPriv)
	plaintext, err := eciesgo.Decrypt(priv, sealedKey)
	if err != nil {
		return nil, fmt.Errorf("ecies decrypt: %w", err)
	}
	return plaintext, nil
}

// SealDataKey wraps a data_key for delivery to the agent. agentSealPubkey
// must be the secp256k1 compressed public key bytes corresponding to the
// agent_seal address bound on chain.
func SealDataKey(dataKey, agentSealPubkey []byte) ([]byte, error) {
	pub, err := eciesgo.NewPublicKeyFromBytes(agentSealPubkey)
	if err != nil {
		return nil, fmt.Errorf("parse pubkey: %w", err)
	}
	ct, err := eciesgo.Encrypt(pub, dataKey)
	if err != nil {
		return nil, fmt.Errorf("ecies encrypt: %w", err)
	}
	return ct, nil
}

// NewDataKey returns 32 random bytes suitable for use as an AES-GCM-256 key.
func NewDataKey() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// uploadHelperPath is the storage-upload helper built from
// sealed/tools/zg-upload. The images that build the storage binaries
// (sealed/Dockerfile, images/{hermes,prime,dsh}) install it here,
// root-owned, next to 0g-storage-client; the base images images/openclaw
// and images/sealed carry neither binary, so an image built from one of
// them alone fails every upload and download. The helper wraps the
// 0g-storage-client Go SDK with the CLI's upload semantics, but reads the
// signing key from stdin: the CLI accepts the key only as a --key argument,
// and process arguments are readable by every local user via
// /proc/<pid>/cmdline.
//
// Both storage binaries are run by absolute path, never looked up through
// PATH: sealed runs as root, some images put a directory under $HOME first
// on PATH, and the framework adapters hand $HOME to the agent user, so a
// PATH lookup can resolve to a file that user controls. Vars so tests can point
// them at stand-ins.
var uploadHelperPath = "/usr/local/bin/zg-upload"

// storageClientPath is the 0g-storage-client CLI, used for downloads only
// (no key involved). See uploadHelperPath for why it is an absolute path.
var storageClientPath = "/usr/local/bin/0g-storage-client"

// helperPATH is the PATH the upload helper runs with: root-owned system
// directories only. The helper starts no other program; PATH is set so it
// does not carry sealed's own PATH, which can list a directory under $HOME.
const helperPATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// helperEnvKeys are the variables of sealed's own environment passed on to
// the upload helper when set: proxy settings and CA bundle locations, which
// Go's HTTP client and TLS stack read. Nothing else is inherited -- in
// particular not the provider API key the framework adapters export into
// sealed's environment -- so the helper's environment holds no secret by
// construction.
var helperEnvKeys = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
	"http_proxy", "https_proxy", "no_proxy",
	"SSL_CERT_FILE", "SSL_CERT_DIR",
}

// helperEnv builds the upload helper's explicit environment.
func helperEnv() []string {
	env := []string{"PATH=" + helperPATH}
	for _, k := range helperEnvKeys {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// rootLineRegexp matches the helper's success line on stdout:
// "root = 0x<64 hex>" (formatRoot in sealed/tools/zg-upload).
var rootLineRegexp = regexp.MustCompile(`root\s*=\s*(0x[0-9a-fA-F]{64})`)

// perUploadTimeout bounds a single upload-helper invocation.
// 90s is generous for testnet conditions (typical successful uploads
// land in ~10s) while still tight enough to surface a genuinely hung
// upload. The cap lives here — not on the surrounding Apply — so the cost
// of one slow blob doesn't eat the budget of the other entries in the
// same manifest.
const perUploadTimeout = 90 * time.Second

// uploadCommand builds the helper invocation for one blob, and the channel
// that carries the signing key to it: cmd.Stdin is one end of a socketpair
// (keyChannel), and Upload writes the key to the other end once the helper
// has started. The key never appears in the argument list or in the
// environment (an explicit one, helperEnv).
//
// The endpoint URLs do travel in the argument list. CHAIN_RPC_URL and
// INDEXER_URL are public anyway (internal/config) and must not embed
// credentials.
//
// Flags match the `0g-storage-client upload` defaults except where pinned:
//
//	--expected-replica 1   small payload, single replica is fine
//	--skip-tx=true         skip flow tx submission if already submitted
//	--fast-mode=true       small-file fast path (CLI default true)
//	--full-trusted=true    use trusted nodes (CLI default true)
//	--method random        avoid shard.Select empty-method bug
//
// Boolean flags use the --flag=value form; the helper rejects a separate
// value word. The helper lives in another Go module, so the two sides are
// checked against each other's source: TestUploadCommand_ArgsMatchHelperFlags
// (here) checks these arguments against the flags the helper's parseFlags
// defines, and the helper's TestParseFlags_SealedInvocation runs its real
// parser on the literal arguments of the exec.CommandContext call below.
// Keep that call's arguments string literals or the parameters file,
// indexerURL and rpcURL.
//
// What this function and Upload guarantee -- the helper by its absolute
// path, an explicit environment, the key only on the socketpair stdin, the
// root read from stdout only -- is pinned by dataplane_test.go.
// A change that routes this exec through another launcher keeps those
// properties and ports those tests rather than dropping them.
func uploadCommand(ctx context.Context, file, indexerURL, rpcURL, signerPrivHex string) (*exec.Cmd, *keyChannel, error) {
	keys, err := newKeyChannel(signerPrivHex)
	if err != nil {
		return nil, nil, err
	}
	cmd := exec.CommandContext(ctx, uploadHelperPath,
		"--file", file,
		"--indexer", indexerURL,
		"--url", rpcURL,
		"--expected-replica", "1",
		"--skip-tx=true",
		"--fast-mode=true",
		"--full-trusted=true",
		"--method", "random",
	)
	cmd.Env = helperEnv()
	cmd.Stdin = keys.remote
	return cmd, keys, nil
}

// Upload pushes ciphertext to 0g-storage and returns the storage root
// hash. The root is what gets recorded as IntelligentData.dataHash on
// chain. signerPrivHex is the hex-encoded (with or without 0x prefix)
// agent_seal_priv -- it signs the storage submission tx and pays gas.
//
// Runs the zg-upload helper in a subprocess (rather than the Go SDK
// in-process) so that any SDK panic, logrus.Fatal, or OOM stays
// contained -- the sealed binary keeps serving /healthz + /log even when
// the upload itself fails -- and so the SDK's go-ethereum version stays
// out of sealed's module. The key is passed over stdin (uploadCommand,
// keyChannel).
func Upload(
	ctx context.Context,
	ciphertext []byte,
	indexerURL string,
	rpcURL string,
	signerPrivHex string,
) ([32]byte, error) {
	// Per-blob deadline. Inherits the caller's ctx so an Apply-level
	// cancel still propagates, but caps this single subprocess at
	// perUploadTimeout so a stuck helper is bounded even when the parent
	// context is effectively unbounded (uploader.Apply runs without a
	// top-level timeout since sealed/main.go's drift loop).
	uploadCtx, cancel := context.WithTimeout(ctx, perUploadTimeout)
	defer cancel()

	tmp, err := os.CreateTemp("", "0g-upload-*.bin")
	if err != nil {
		return [32]byte{}, fmt.Errorf("create tempfile: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(ciphertext); err != nil {
		tmp.Close()
		return [32]byte{}, fmt.Errorf("write tempfile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return [32]byte{}, fmt.Errorf("close tempfile: %w", err)
	}

	cmd, keys, err := uploadCommand(uploadCtx, tmpPath, indexerURL, rpcURL, signerPrivHex)
	if err != nil {
		return [32]byte{}, err
	}
	defer keys.Close()
	// stdout carries only the result line; SDK logs and the final error
	// line go to stderr.
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return [32]byte{}, fmt.Errorf("upload cmd: %v", err)
	}
	keys.started()
	sendErr := keys.send(uploadCtx)
	// Wait even when the key could not be written: a helper that exited
	// early (bad flags, say) explains itself on stderr, which says more
	// than the write error.
	if err := cmd.Wait(); err != nil {
		return [32]byte{}, fmt.Errorf("upload cmd: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	if sendErr != nil {
		return [32]byte{}, fmt.Errorf("upload cmd: write key: %v", sendErr)
	}

	m := rootLineRegexp.FindSubmatch(stdout.Bytes())
	if len(m) < 2 {
		return [32]byte{}, fmt.Errorf("could not parse root from upload helper output: %s",
			strings.TrimSpace(stdout.String()+"\n"+stderr.String()))
	}
	rootHex := strings.TrimPrefix(string(m[1]), "0x")
	rootBytes, err := hex.DecodeString(rootHex)
	if err != nil || len(rootBytes) != 32 {
		return [32]byte{}, fmt.Errorf("invalid root hex %q: %v", rootHex, err)
	}
	var root [32]byte
	copy(root[:], rootBytes)
	logger.Logf("0g-storage upload OK: root=0x%s size=%dB", rootHex, len(ciphertext))
	return root, nil
}

// Download fetches a file from 0g-storage by content root hash, writing to
// outPath. Implements exponential backoff (1s, 2s, 4s, ..., capped 60s) for
// up to 10 attempts.
//
// The 0g-storage-client binary refuses to overwrite existing files, so any
// leftover at outPath from a previous failed attempt is removed first.
func Download(ctx context.Context, root, indexer, outPath string) error {
	var lastErr error
	for i := 0; i < downloadAttempts; i++ {
		if i > 0 {
			delay := 1 << uint(i)
			if delay > 60 {
				delay = 60
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(delay) * time.Second):
			}
		}
		_ = os.Remove(outPath)
		cmd := exec.CommandContext(ctx, storageClientPath, "download",
			"--root", root, "--file", outPath, "--indexer", indexer)
		out, err := cmd.CombinedOutput()
		if err == nil {
			return nil
		}
		lastErr = fmt.Errorf("attempt %d: %v: %s", i+1, err, strings.TrimSpace(string(out)))
		logger.Logf("download attempt %d failed: %v", i+1, err)
	}
	return lastErr
}
