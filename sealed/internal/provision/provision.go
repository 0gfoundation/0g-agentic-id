// Package provision implements Phase 1 of bootstrap: prove to the attestor
// that this boot holds the container key the provider certified, and
// receive back an ECIES-encrypted agent_seal_priv that only this container
// can unlock.
//
// One PID-1 boot is one claim, under one random boot_id:
//
//	GET  /provision?seal_id=0x<seal>  → {"generation", "certificate_required"}
//	POST /provision                   → the claim, signed with the container key
//
// The provider's certificate (SANDBOX_SEAL_ATTESTATION) rides the POST only
// when the attestor has no container key recorded for this deployment yet
// (certificate_required); later boots prove possession of the recorded key.
// Each POST is signed afresh with a later boot_started_at.
package provision

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	eciesgo "github.com/ecies/go/v2"
	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/attestorhttp"
	"seal-verify/internal/logger"
)

const (
	// retryWindow is how long after PID-1 start provisioning keeps trying.
	retryWindow = 10 * time.Minute
	// firstBackoff doubles after every retry, up to maxBackoff.
	firstBackoff = time.Second
	maxBackoff   = 30 * time.Second
	// maxResponseBytes caps a /provision response body.
	maxResponseBytes = 1 << 20
)

// clock is the time source of the retry loop; tests replace it.
var clock = struct {
	now   func() time.Time
	sleep func(time.Duration)
}{time.Now, time.Sleep}

// Boot is what one PID-1 boot hands Phase 1.
type Boot struct {
	AttestorURL string
	// SealKey is SANDBOX_SEAL_KEY, the container private key.
	SealKey []byte
	// Certificate is SANDBOX_SEAL_ATTESTATION as parsed and verified in
	// Phase 0; CertificateJSON is the same object as the provider wrote it,
	// forwarded verbatim when the attestor asks for it.
	Certificate     Attestation
	CertificateJSON json.RawMessage
	// Ticket is SEAL_BOOT_TICKET.
	Ticket string
	// Started is PID-1 start; provisioning gives up retryWindow after it.
	Started time.Time
}

// Result is what /provision hands the container.
type Result struct {
	// AgentSealPriv is the agent's signing key. Nil on any failure.
	AgentSealPriv []byte
	// Settings is the owner's configuration document, or nil when this
	// agent has none stored yet. attestor keeps it as an opaque blob and
	// encrypts it to the same container pubkey as the key above, so it
	// rides the channel that already exists rather than needing a new one.
	//
	// It comes down on EVERY boot, including a resume — which is the whole
	// reason it is here and not in the sandbox env: env is supplied only on
	// container create, so a resumed container would come up with no
	// configuration at all.
	Settings []byte
	// StatusToken is this boot's status receipt: 64 lowercase hex, signed
	// into every /status report (report.Binding).
	StatusToken string
}

// authorization is the GET /provision answer.
type authorization struct {
	Generation          int64 `json:"generation"`
	CertificateRequired bool  `json:"certificate_required"`
}

// provisionRequest is the POST /provision body.
type provisionRequest struct {
	SealID             string          `json:"seal_id"`
	Certificate        json.RawMessage `json:"certificate,omitempty"`
	BootTicket         string          `json:"boot_ticket"`
	BootGeneration     int64           `json:"boot_generation"`
	BootID             string          `json:"boot_id"`
	BootStartedAt      int64           `json:"boot_started_at"`
	ContainerSignature string          `json:"container_signature"`
}

type provisionResponse struct {
	EncryptedAgentSealPriv string `json:"encrypted_agent_seal_priv"`
	EncryptedSettings      string `json:"encrypted_settings"`
	EncryptedStatusBinding string `json:"encrypted_status_binding"`
}

// action is what the retry loop does after an attestor answer.
type action int

const (
	proceed     action = iota
	retry              // 5xx, 429, transport and statement-fetch failures
	rediscover         // 409: read the authorization again, then retry
	reauthorize        // 403 on POST: read it once; continue only on a new generation
	stop               // 400, 401 and every other answer
)

func classify(status int) action {
	switch {
	case status == http.StatusOK:
		return proceed
	case status == http.StatusConflict:
		return rediscover
	case status == http.StatusForbidden:
		return reauthorize
	case status == http.StatusTooManyRequests, status >= 500:
		return retry
	default:
		return stop
	}
}

// claim is one boot's provisioning state.
type claim struct {
	boot       Boot
	key        *ecdsa.PrivateKey
	client     *http.Client
	ctx        context.Context
	bootID     [32]byte
	ticketHash [32]byte
	// startedAt is the boot_started_at of the last signed POST.
	startedAt int64
}

// FromAttestor runs Phase 1 and returns the decrypted payload. Transient
// failures are retried with backoff until retryWindow after PID-1 start; an
// answer that needs a reset (400, 401, 403 without a newer generation) or a
// response that does not decrypt ends it. On failure AgentSealPriv is nil and
// the reason is in /log. A settings blob that fails to decrypt is logged and
// dropped rather than being fatal: an agent that boots on its last-good
// configuration beats one that refuses to boot.
func FromAttestor(boot Boot) Result {
	if _, err := boot.Certificate.RecoverSigner(); err != nil {
		logger.Logf("FAIL provision: invalid container certificate: %v", err)
		return Result{}
	}
	if len(boot.CertificateJSON) == 0 {
		logger.Logf("FAIL provision: container certificate JSON missing")
		return Result{}
	}
	if !lowerHex(boot.Ticket, 32) {
		logger.Logf("FAIL provision: SEAL_BOOT_TICKET missing or not 64 hex; recreate the sandbox")
		return Result{}
	}
	key, err := crypto.ToECDSA(boot.SealKey)
	if err != nil {
		logger.Logf("FAIL provision: SANDBOX_SEAL_KEY is not a secp256k1 private key")
		return Result{}
	}
	client, err := attestorhttp.Client(boot.AttestorURL)
	if err != nil {
		logger.Logf("FAIL provision: attestor client: %v", err)
		return Result{}
	}
	remaining := boot.Started.Add(retryWindow).Sub(clock.now())
	if remaining <= 0 {
		logger.Logf("FAIL provision: more than %s since boot", retryWindow)
		return Result{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), remaining)
	defer cancel()
	c := &claim{boot: boot, key: key, client: client, ctx: ctx, ticketHash: sha256.Sum256([]byte(boot.Ticket))}
	if _, err := rand.Read(c.bootID[:]); err != nil {
		logger.Logf("FAIL provision: boot id: %v", err)
		return Result{}
	}
	return c.run()
}

func (c *claim) run() Result {
	var auth *authorization
	// refused is the generation a POST was refused (403) under, 0 for none.
	var refused int64
	backoff := firstBackoff
	for attempt := 1; ; attempt++ {
		if auth == nil {
			found, outcome := c.discover()
			switch {
			case outcome == stop:
				return Result{}
			case outcome == proceed && refused != 0 && found.Generation == refused:
				logger.Logf("FAIL provision: refused and no newer boot authorized; reset required")
				return Result{}
			case outcome == proceed:
				auth, refused = &found, 0
			}
		}
		if auth != nil {
			result, outcome := c.provision(*auth)
			switch outcome {
			case proceed:
				return result
			case stop:
				return Result{}
			case reauthorize:
				// The next successful discovery decides: a newer generation
				// is claimed at once, the same one ends provisioning.
				refused, auth = auth.Generation, nil
				continue
			case rediscover:
				auth = nil
			}
		}
		if !c.wait(attempt, backoff) {
			return Result{}
		}
		backoff = min(2*backoff, maxBackoff)
	}
}

// wait sleeps backoff before the next attempt, or reports false when that
// would pass the retry window.
func (c *claim) wait(attempt int, backoff time.Duration) bool {
	deadline := c.boot.Started.Add(retryWindow)
	if !clock.now().Add(backoff).Before(deadline) {
		logger.Logf("FAIL provision: giving up after %d attempts: the next would start more than %s after boot", attempt, retryWindow)
		return false
	}
	logger.Logf("provision: retrying in %s", backoff)
	clock.sleep(backoff)
	return true
}

// discover reads this seal's boot authorization.
func (c *claim) discover() (authorization, action) {
	req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, c.boot.AttestorURL+"/provision?seal_id=0x"+c.boot.Certificate.SealID, nil)
	if err != nil {
		logger.Logf("FAIL provision: discovery request: %v", err)
		return authorization{}, stop
	}
	status, body, err := c.do(req)
	if err != nil {
		logger.Logf("provision: boot authorization: %v", err)
		return authorization{}, retry
	}
	switch outcome := classify(status); outcome {
	case proceed:
	case retry, rediscover:
		logger.Logf("provision: boot authorization: HTTP %d: %s", status, attestorhttp.Excerpt(body))
		return authorization{}, retry
	default:
		logger.Logf("FAIL provision: boot authorization: HTTP %d: %s", status, attestorhttp.Excerpt(body))
		return authorization{}, stop
	}
	var found authorization
	if err := json.Unmarshal(body, &found); err != nil || found.Generation <= 0 {
		logger.Logf("FAIL provision: boot authorization: malformed answer")
		return authorization{}, stop
	}
	return found, proceed
}

// provision signs and POSTs one claim under auth.
func (c *claim) provision(auth authorization) (Result, action) {
	c.startedAt = max(clock.now().UnixNano(), c.startedAt+1)
	request, err := c.request(auth)
	if err != nil {
		logger.Logf("FAIL provision: sign boot claim: %v", err)
		return Result{}, stop
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		logger.Logf("FAIL provision: encode request: %v", err)
		return Result{}, stop
	}
	req, err := http.NewRequestWithContext(c.ctx, http.MethodPost, c.boot.AttestorURL+"/provision", bytes.NewReader(encoded))
	if err != nil {
		logger.Logf("FAIL provision: request: %v", err)
		return Result{}, stop
	}
	req.Header.Set("Content-Type", "application/json")
	status, body, err := c.do(req)
	if err != nil {
		logger.Logf("provision: POST: %v", err)
		return Result{}, retry
	}
	outcome := classify(status)
	switch outcome {
	case proceed:
		return c.open(body)
	case stop:
		logger.Logf("FAIL provision: HTTP %d: %s", status, attestorhttp.Excerpt(body))
	default:
		logger.Logf("provision: HTTP %d: %s", status, attestorhttp.Excerpt(body))
	}
	return Result{}, outcome
}

// request builds the POST body for auth, signed at c.startedAt.
func (c *claim) request(auth authorization) (provisionRequest, error) {
	signature, err := crypto.Sign(crypto.Keccak256([]byte(bootMessage(c.boot.Certificate.SealID, auth.Generation, c.ticketHash, c.bootID[:], c.startedAt))), c.key)
	if err != nil {
		return provisionRequest{}, err
	}
	signature[64] += 27
	request := provisionRequest{
		SealID:             "0x" + c.boot.Certificate.SealID,
		BootTicket:         c.boot.Ticket,
		BootGeneration:     auth.Generation,
		BootID:             "0x" + hex.EncodeToString(c.bootID[:]),
		BootStartedAt:      c.startedAt,
		ContainerSignature: "0x" + hex.EncodeToString(signature),
	}
	if auth.CertificateRequired {
		request.Certificate = c.boot.CertificateJSON
	}
	return request, nil
}

// do sends req and reads the whole answer.
func (c *claim) do(req *http.Request) (int, []byte, error) {
	response, err := c.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return 0, nil, fmt.Errorf("read response: %w", err)
	}
	if len(body) > maxResponseBytes {
		return 0, nil, fmt.Errorf("response larger than %d bytes", maxResponseBytes)
	}
	return response.StatusCode, body, nil
}

// open decrypts a 200 answer. Any failure here ends provisioning: a
// response this container cannot open will not change on a retry.
func (c *claim) open(body []byte) (Result, action) {
	var out provisionResponse
	if err := json.Unmarshal(body, &out); err != nil {
		logger.Logf("FAIL provision: decode response: %v", err)
		return Result{}, stop
	}
	priv := eciesgo.NewPrivateKeyFromBytes(c.boot.SealKey)
	agentKey, err := decrypt(priv, out.EncryptedAgentSealPriv)
	if err != nil || len(agentKey) == 0 {
		logger.Logf("FAIL provision: encrypted_agent_seal_priv missing or does not decrypt")
		return Result{}, stop
	}
	var binding struct {
		Token string `json:"token"`
	}
	opened, err := decrypt(priv, out.EncryptedStatusBinding)
	if err == nil {
		err = json.Unmarshal(opened, &binding)
	}
	if err != nil || !lowerHex(binding.Token, 32) {
		logger.Logf("FAIL provision: encrypted_status_binding missing or invalid")
		return Result{}, stop
	}

	var settingsBlob []byte
	if out.EncryptedSettings != "" {
		if pt, err := decrypt(priv, out.EncryptedSettings); err != nil {
			logger.Logf("warn: provision: settings do not decrypt (booting without owner settings)")
		} else {
			settingsBlob = pt
			logger.Logf("OK   provisioned owner settings (%d bytes)", len(pt))
		}
	}
	// Confirm size + derived address only — never log the priv bytes.
	if pk, err := crypto.ToECDSA(agentKey); err == nil {
		logger.Logf("OK   provisioned agent_seal_priv (%d bytes), addr=%s",
			len(agentKey), crypto.PubkeyToAddress(pk.PublicKey).Hex())
	} else {
		logger.Logf("OK   provisioned agent_seal_priv (%d bytes)", len(agentKey))
	}
	return Result{AgentSealPriv: agentKey, Settings: settingsBlob, StatusToken: binding.Token}, proceed
}

// decrypt opens a "0x"-prefixed hex ECIES ciphertext.
func decrypt(priv *eciesgo.PrivateKey, ciphertext string) ([]byte, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(ciphertext, "0x"))
	if err != nil || len(raw) == 0 {
		return nil, fmt.Errorf("not hex ciphertext")
	}
	return eciesgo.Decrypt(priv, raw)
}

// lowerHex reports whether value is exactly size bytes as lowercase hex.
func lowerHex(value string, size int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == size && hex.EncodeToString(decoded) == value
}

func bootMessage(seal string, generation int64, ticketHash [32]byte, bootID []byte, startedAt int64) string {
	return fmt.Sprintf("ProvisionBoot.v1:0x%s:%d:%x:%x:%d", seal, generation, ticketHash, bootID, startedAt)
}
