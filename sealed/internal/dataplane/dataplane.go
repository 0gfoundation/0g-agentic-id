// Package dataplane provides the encryption + 0g-storage primitives used by
// the bootstrap pipeline. Read path:
//
//  1. Download(root, indexer) -> ciphertext bytes
//  2. UnsealDataKey(sealedKey, agentSealPriv) -> data_key
//  3. Decrypt(ciphertext, data_key) -> plaintext
//
// The uploader reuses SealDataKey, Encrypt and Upload for the symmetric
// outbound flow. Download runs the `0g-storage-client` CLI (no key
// involved); Upload runs in-process through the same client's Go SDK
// (upload.go), so the signing key never leaves sealed.
package dataplane

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	eciesgo "github.com/ecies/go/v2"

	"seal-verify/internal/logger"
	"seal-verify/internal/privsep"
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

// Download fetches a blob from 0g-storage by content root hash and returns
// its bytes. The CLI writes to a path (and a "<path>.download" partial next
// to it), so the blob is staged in a fresh root-only scratch directory
// (privsep.TempDir) — no other uid can create, replace or read a name in it
// while the CLI runs — read back without following links, and the directory
// removed. Every root-side download (bootstrap and the uploader) goes
// through here.
func Download(ctx context.Context, root, indexer string) ([]byte, error) {
	dir, err := privsep.TempDir("download-")
	if err != nil {
		return nil, fmt.Errorf("download scratch dir: %w", err)
	}
	defer removeScratch(dir)
	outPath := filepath.Join(dir, "blob.bin")
	if err := downloadTo(ctx, root, indexer, outPath); err != nil {
		return nil, err
	}
	f, err := privsep.Open(outPath)
	if err != nil {
		return nil, fmt.Errorf("read downloaded blob: %w", err)
	}
	defer f.Close()
	body, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read downloaded blob: %w", err)
	}
	return body, nil
}

// removeScratch removes a scratch directory made by privsep.TempDir.
func removeScratch(dir string) {
	if err := privsep.RemoveAll(dir); err != nil {
		logger.Logf("dataplane: removing scratch %s: %v", dir, err)
	}
}

// downloadTo runs the CLI download into outPath with exponential backoff
// (1s, 2s, 4s, ..., capped 60s) for up to 10 attempts.
//
// The 0g-storage-client CLI is what sealed runs for downloads only (no key
// involved; uploads run in-process, upload.go). The images that build it
// (sealed/Dockerfile, images/{hermes,prime,harness,sealed}) install it at
// /usr/local/bin, root-owned, at the SDK version pinned in sealed/go.mod;
// the base image images/openclaw does not carry it, so an image built from
// it alone fails every download. It runs through
// privsep.RootCommand, which resolves it only in root-only PATH directories
// and gives it a fixed environment.
//
// The 0g-storage-client binary refuses to overwrite existing files, so any
// leftover at outPath from a previous failed attempt is removed first.
func downloadTo(ctx context.Context, root, indexer, outPath string) error {
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
		_ = privsep.Remove(outPath)
		cmd, err := privsep.RootCommand(ctx, "0g-storage-client", "download",
			"--root", root, "--file", outPath, "--indexer", indexer)
		if err != nil {
			return fmt.Errorf("download cmd: %w", err)
		}
		out, err := cmd.CombinedOutput()
		if err == nil {
			return nil
		}
		lastErr = fmt.Errorf("attempt %d: %v: %s", i+1, err, strings.TrimSpace(string(out)))
		logger.Logf("download attempt %d failed: %v", i+1, err)
	}
	return lastErr
}
