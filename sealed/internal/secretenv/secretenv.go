// Package secretenv opens the owner's secret env (today: the inference API
// key) that the SDK sealed to this agent's agentSeal public key (issue #166).
//
// Before this channel the key rode the owner-signed sandbox "create"
// envelope as `env.API_KEY` in clear: the owner's wallet prompt displayed it,
// and every hop (an integrator's proxy, the attestor's job store, the sandbox
// provider) held it in plain text. Now the envelope carries only
//
//	SEAL_SECRET_ENV = base64( ECIES(agentSeal_pub, plaintext) )
//
// so the owner still signs the exact bytes the container receives, but those
// bytes are ciphertext. Only holders of agentSeal_priv can open it: this
// container (after Phase 1 /provision) and the attestor's KMS derivation.
//
// ECIES is the scheme sealed already uses for sealedKeys (eciesjs-compatible:
// secp256k1, HKDF-SHA256, AES-256-GCM with a 16-byte nonce).
//
// Plaintext (JSON, v1):
//
//	{"v":1,"owner":"0x…","env":{"API_KEY":"…"}}
//
// `owner` is the envelope signer. Open requires it to equal the agent's live
// on-chain owner, so a ciphertext signed by a previous owner cannot be
// replayed into a container the next owner controls.
package secretenv

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	eciesgo "github.com/ecies/go/v2"
	"github.com/ethereum/go-ethereum/common"
)

// EnvVar is the container env var that carries the sealed secret env.
const EnvVar = "SEAL_SECRET_ENV"

// Version is the only plaintext version this binary understands.
const Version = 1

// supported lists the names a secret env may set. Unknown names are ignored
// (reported, never applied), so an SDK that learns a new name does not break
// an older image: the names it does know still apply.
var supported = map[string]bool{
	"API_KEY": true,
}

// Reason classes for an Open failure. They name a cause, never a value, so
// they are safe in a status report that leaves the container.
const (
	ReasonMalformed          = "malformed"
	ReasonUnsupportedVersion = "unsupported_version"
	ReasonNotSealedToAgent   = "not_sealed_to_this_agent"
	ReasonOwnerUnknown       = "owner_unknown"
	ReasonOwnerMismatch      = "owner_mismatch"
	ReasonInternal           = "internal"
)

// Error is an Open failure with its reason class.
type Error struct {
	Reason string
	err    error
}

func (e *Error) Error() string { return e.err.Error() }
func (e *Error) Unwrap() error { return e.err }

func fail(reason string, err error) error { return &Error{Reason: reason, err: err} }

// Reason returns the reason class of an Open error (ReasonMalformed for an
// error Open did not classify).
func Reason(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ReasonMalformed
}

// Opened is the validated content of a sealed secret env.
type Opened struct {
	// Env holds only supported names with non-empty values.
	Env map[string]string
	// Ignored lists unsupported names (sorted), for a log line. Never values.
	Ignored []string
}

type payload struct {
	V     int               `json:"v"`
	Owner string            `json:"owner"`
	Env   map[string]string `json:"env"`
}

// Open decodes, decrypts and validates a sealed secret env.
//
// chainOwner is the agent's live on-chain owner (hex). An empty chainOwner
// fails closed: without it the owner binding cannot be checked.
//
// Errors never include plaintext values.
func Open(encoded string, agentSealPriv []byte, chainOwner string) (*Opened, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, fail(ReasonMalformed, errors.New("empty"))
	}
	ct, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fail(ReasonMalformed, fmt.Errorf("base64: %w", err))
	}
	if len(agentSealPriv) != 32 {
		return nil, fail(ReasonInternal, fmt.Errorf("agentSeal key must be 32 bytes, got %d", len(agentSealPriv)))
	}
	pt, err := eciesgo.Decrypt(eciesgo.NewPrivateKeyFromBytes(agentSealPriv), ct)
	if err != nil {
		// Not sealed to this agent's key (wrong agent, or corrupted).
		return nil, fail(ReasonNotSealedToAgent, fmt.Errorf("ecies decrypt: %w", err))
	}

	var p payload
	dec := json.NewDecoder(bytes.NewReader(pt))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fail(ReasonMalformed, errors.New("plaintext is not a v1 secret env document"))
	}
	if p.V != Version {
		return nil, fail(ReasonUnsupportedVersion, fmt.Errorf("unsupported version %d (want %d)", p.V, Version))
	}
	if !common.IsHexAddress(p.Owner) {
		return nil, fail(ReasonMalformed, errors.New("owner is not an address"))
	}
	if !common.IsHexAddress(chainOwner) {
		return nil, fail(ReasonOwnerUnknown, errors.New("on-chain owner unknown; refusing to apply an owner-bound secret"))
	}
	if common.HexToAddress(p.Owner) != common.HexToAddress(chainOwner) {
		return nil, fail(ReasonOwnerMismatch, fmt.Errorf("sealed for owner %s, but the agent's owner is %s",
			common.HexToAddress(p.Owner).Hex(), common.HexToAddress(chainOwner).Hex()))
	}

	out := &Opened{Env: map[string]string{}}
	for name, value := range p.Env {
		if !supported[name] {
			out.Ignored = append(out.Ignored, name)
			continue
		}
		if value == "" || strings.ContainsRune(value, 0) {
			return nil, fail(ReasonMalformed, fmt.Errorf("%s: empty or invalid value", name))
		}
		out.Env[name] = value
	}
	sort.Strings(out.Ignored)
	if len(out.Env) == 0 {
		return nil, fail(ReasonMalformed, errors.New("no supported names"))
	}
	return out, nil
}

// NotAppliedPrefix starts the status detail ResolveAPIKey returns when an
// owner supplied a sealed key that did not apply.
const NotAppliedPrefix = "secret_env_not_applied: "

// ResolveAPIKey returns the inference key the adapters should use, given the
// plain API_KEY env value and the raw SEAL_SECRET_ENV value, plus an issue
// for the attestor (empty when there is nothing to report):
//
//   - no secret env: plainKey, unchanged;
//   - a secret env that opens (owner-bound) and carries API_KEY: that value,
//     which wins over plainKey;
//   - a secret env that fails to open: plainKey, with a FAIL line. If that
//     leaves no key at all, the agent boots but cannot call its model, so
//     issue is "secret_env_not_applied: <reason>" (a reason class, never a
//     value) for the caller to report as an owner-recoverable warning.
//
// logf lines name variables and lengths only, never values.
func ResolveAPIKey(plainKey, encoded string, agentSealPriv []byte, chainOwner string, logf func(string, ...any)) (key, issue string) {
	if encoded == "" {
		return plainKey, ""
	}
	opened, err := Open(encoded, agentSealPriv, chainOwner)
	if err != nil {
		logf("FAIL %s not applied: %v", EnvVar, err)
		if plainKey == "" {
			issue = NotAppliedPrefix + Reason(err)
		}
		return plainKey, issue
	}
	for _, name := range opened.Ignored {
		logf("warn: %s: ignoring unsupported name %q", EnvVar, name)
	}
	key = opened.Env["API_KEY"]
	if key == "" {
		return plainKey, ""
	}
	if plainKey != "" {
		logf("warn: both API_KEY and %s are set; using the sealed value", EnvVar)
	}
	logf("OK   API_KEY (from %s, owner-bound): <set, %d chars>", EnvVar, len(key))
	return key, ""
}

// LiveOwner returns known when it is set. Otherwise (the boot-time ownerOf
// read failed, e.g. on a transient RPC error) it re-reads the owner up to
// attempts times, waiting backoff*n before try n, and returns "" if every
// read fails. Open fails closed on an unknown owner, so without the re-read
// one RPC error at boot would leave the agent without its sealed key.
func LiveOwner(known string, read func() (string, error), attempts int, backoff time.Duration, logf func(string, ...any)) string {
	if known != "" || read == nil {
		return known
	}
	for i := 1; i <= attempts; i++ {
		time.Sleep(backoff * time.Duration(i))
		owner, err := read()
		if err == nil && owner != "" {
			return owner
		}
		if err == nil {
			err = errors.New("empty owner")
		}
		logf("warn: %s: owner re-read %d/%d failed: %v", EnvVar, i, attempts, err)
	}
	return ""
}
