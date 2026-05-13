// Package dataplane provides the encryption + 0g-storage primitives used by
// the bootstrap pipeline. Read path:
//
//   1. Download(root, indexer) -> ciphertext bytes
//   2. UnsealDataKey(sealedKey, agentSealPriv) -> data_key
//   3. Decrypt(ciphertext, data_key) -> plaintext
//
// Phase 4 (uploader) will reuse SealDataKey and Encrypt for the symmetric
// outbound flow.
package dataplane

import (
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

// rootLineRegexp matches the CLI's success line: "file uploaded, root = 0x..."
// Logged by /root/go/pkg/mod/github.com/0gfoundation/0g-storage-client/cmd/upload.go.
var rootLineRegexp = regexp.MustCompile(`root\s*=\s*(0x[0-9a-fA-F]{64})`)

// Upload pushes ciphertext to 0g-storage and returns the storage root
// hash. The root is what gets recorded as IntelligentData.dataHash on
// chain. signerPrivHex is the hex-encoded (with or without 0x prefix)
// agent_seal_priv -- it signs the storage submission tx and pays gas.
//
// Runs the `0g-storage-client upload` CLI in a subprocess (rather than the
// Go SDK in-process) so that any SDK panic, logrus.Fatal, or OOM stays
// contained -- the sealed binary keeps serving /healthz + /log even when
// the upload itself fails. Matches the Download path, which has always
// shelled out to the same binary.
func Upload(
	ctx context.Context,
	ciphertext []byte,
	indexerURL string,
	rpcURL string,
	signerPrivHex string,
) ([32]byte, error) {
	signerPrivHex = strings.TrimPrefix(signerPrivHex, "0x")

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

	// Flags match cmd/upload.go defaults except where pinned:
	//   --expected-replica 1   small payload, single replica is fine
	//   --skip-tx              skip flow tx submission if already submitted
	//   --fast-mode            small-file fast path (CLI default true)
	//   --full-trusted         use trusted nodes (CLI default true)
	//   --method random        avoid shard.Select empty-method bug
	cmd := exec.CommandContext(ctx, "0g-storage-client", "upload",
		"--file", tmpPath,
		"--indexer", indexerURL,
		"--url", rpcURL,
		"--key", signerPrivHex,
		"--expected-replica", "1",
		"--skip-tx", "true",
		"--fast-mode", "true",
		"--full-trusted", "true",
		"--method", "random",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return [32]byte{}, fmt.Errorf("upload cmd: %v: %s", err, strings.TrimSpace(string(out)))
	}

	m := rootLineRegexp.FindSubmatch(out)
	if len(m) < 2 {
		return [32]byte{}, fmt.Errorf("could not parse root from CLI output: %s", strings.TrimSpace(string(out)))
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
		cmd := exec.CommandContext(ctx, "0g-storage-client", "download",
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
