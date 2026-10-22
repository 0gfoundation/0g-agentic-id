// Package attestorhttp authenticates the attestor through a public Scan trust
// descriptor injected at creation. Workloads never receive the tapp socket.
package attestorhttp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const DescriptorEnv = "ATTESTOR_TLS_DESCRIPTOR"

type Descriptor struct {
	Version         int      `json:"version"`
	ChainID         uint64   `json:"chain_id"`
	RegistryAddress string   `json:"registry_address"`
	AppID           string   `json:"app_id"`
	RegisteredAt    uint64   `json:"registered_at"`
	AppSigner       string   `json:"app_signer"`
	URL             string   `json:"url"`
	ScanURL         string   `json:"scan_url"`
	ScanPublicKey   string   `json:"scan_public_key"`
	TLSPins         []string `json:"tls_spki_sha256"`
	CheckedAt       int64    `json:"checked_at"`
	ExpiresAt       int64    `json:"expires_at"`
}

type resolver struct {
	mu         sync.Mutex
	descriptor Descriptor
	base       *url.URL
	scan       *url.URL
	scanHTTP   *http.Client
	transport  *http.Transport
	expiresAt  int64
}

var clients = struct {
	sync.Mutex
	values map[string]*http.Client
}{values: make(map[string]*http.Client)}

// Client returns the one authenticated transport used by provision/status and
// settings calls. Unpinned access requires an explicit development-only switch.
func Client(locator string) (*http.Client, error) {
	raw := os.Getenv(DescriptorEnv)
	dev := os.Getenv("ATTESTOR_ALLOW_UNPINNED_DEV") == "true"
	key := locator + "\x00" + raw + fmt.Sprint(dev)
	clients.Lock()
	defer clients.Unlock()
	if client := clients.values[key]; client != nil {
		return client, nil
	}
	var client *http.Client
	var err error
	if raw == "" && dev {
		client = &http.Client{Timeout: 120 * time.Second, CheckRedirect: noRedirect}
	} else {
		client, err = New(locator, raw)
	}
	if err == nil {
		clients.values[key] = client
	}
	return client, err
}

func New(locator, raw string) (*http.Client, error) {
	var d Descriptor
	if raw == "" || json.Unmarshal([]byte(raw), &d) != nil {
		return nil, fmt.Errorf("missing or invalid %s", DescriptorEnv)
	}
	base, err := httpsURL(locator)
	if err != nil {
		return nil, err
	}
	scan, err := httpsURL(d.ScanURL)
	if err != nil {
		return nil, err
	}
	if d.Version != 1 || d.ChainID == 0 || d.AppID == "" || d.AppID == "." || d.AppID == ".." || len(d.AppID) > 1024 ||
		!nonzeroAddress(d.RegistryAddress) || !nonzeroAddress(d.AppSigner) || d.RegisteredAt == 0 ||
		strings.TrimRight(d.URL, "/") != strings.TrimRight(locator, "/") ||
		d.CheckedAt <= 0 || d.ExpiresAt <= d.CheckedAt || d.ExpiresAt > d.CheckedAt+300 ||
		!validPin(d.ScanPublicKey) || len(d.TLSPins) == 0 {
		return nil, fmt.Errorf("invalid attestor identity descriptor scope")
	}
	for _, pin := range d.TLSPins {
		if !validPin(pin) {
			return nil, fmt.Errorf("invalid attestor TLS pin")
		}
	}
	r := &resolver{descriptor: d, base: base, scan: scan,
		scanHTTP: &http.Client{Transport: pinnedTransport([]string{d.ScanPublicKey}, 0), Timeout: 90 * time.Second, CheckRedirect: noRedirect}}
	// Always refresh independently at first use. Container creation can take
	// longer than the descriptor's initial lease; the Scan anchor is still valid.
	return &http.Client{Transport: r, Timeout: 120 * time.Second, CheckRedirect: noRedirect}, nil
}

func (r *resolver) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != r.base.Scheme || req.URL.Host != r.base.Host ||
		!strings.HasPrefix(req.URL.Path, strings.TrimRight(r.base.Path, "/")+"/") {
		return nil, fmt.Errorf("attestor request left the configured business URL")
	}
	r.mu.Lock()
	if time.Now().Unix()+5 >= r.expiresAt {
		pins, expiry, err := r.resolve(req.Context())
		if err != nil {
			r.mu.Unlock()
			return nil, err
		}
		if r.transport != nil {
			r.transport.CloseIdleConnections()
		}
		r.transport, r.expiresAt = pinnedTransport(pins, expiry), expiry
	}
	transport, expiry := r.transport, r.expiresAt
	r.mu.Unlock()
	if time.Now().Unix() >= expiry {
		return nil, fmt.Errorf("attestor identity expired")
	}
	return transport.RoundTrip(req)
}

func pinnedTransport(pins []string, expiresAt int64) *http.Transport {
	return &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second, IdleConnTimeout: 30 * time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12,
			// The authenticated Scan SPKI replaces CA/name validation.
			InsecureSkipVerify: true, //nolint:gosec
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 || (expiresAt != 0 && time.Now().Unix() >= expiresAt) {
					return fmt.Errorf("missing peer certificate or expired identity")
				}
				hash := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
				for _, pin := range pins {
					if hex.EncodeToString(hash[:]) == strings.TrimPrefix(pin, "0x") {
						return nil
					}
				}
				return fmt.Errorf("attestor/Scan TLS SPKI pin mismatch")
			}}}
}

func noRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

func httpsURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("identity URLs must be HTTPS without credentials, query or fragment")
	}
	return u, nil
}

func validPin(pin string) bool {
	raw := strings.TrimPrefix(pin, "0x")
	decoded, err := hex.DecodeString(raw)
	return err == nil && len(decoded) == 32 && raw == hex.EncodeToString(decoded)
}

func nonzeroAddress(address string) bool {
	return common.IsHexAddress(address) && common.HexToAddress(address) != (common.Address{})
}

func sameAddress(a, b string) bool {
	return nonzeroAddress(a) && nonzeroAddress(b) && common.HexToAddress(a) == common.HexToAddress(b)
}

func (r *resolver) endpoint(tail ...string) string {
	u := *r.scan
	parts := []string{strings.TrimRight(u.EscapedPath(), "/")}
	if !strings.HasSuffix(parts[0], "/api") {
		parts = append(parts, "api")
	}
	for _, part := range tail {
		parts = append(parts, url.PathEscape(part))
	}
	// Preserve encoded app ids as one path segment (including embedded '/').
	u.RawPath = strings.Join(parts, "/")
	u.Path, _ = url.PathUnescape(u.RawPath)
	return u.String()
}

func (r *resolver) request(ctx context.Context, method, target string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := r.scanHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("pinned Scan lookup failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Scan returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024+1))
	if err != nil || len(data) > 2*1024*1024 {
		return fmt.Errorf("invalid Scan response size")
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("invalid Scan response JSON")
	}
	return nil
}

type health struct {
	ChainID     uint64 `json:"chain_id"`
	Contract    string `json:"contract"`
	RefreshedAt int64  `json:"refreshed_at"`
	Block       uint64 `json:"scanned_to_block"`
}

func (r *resolver) health(ctx context.Context) (health, error) {
	var h health
	err := r.request(ctx, http.MethodGet, r.endpoint("health"), nil, &h)
	if err == nil && (h.ChainID != r.descriptor.ChainID || !sameAddress(h.Contract, r.descriptor.RegistryAddress) || !fresh(h.RefreshedAt)) {
		err = fmt.Errorf("Scan scope mismatch or stale refresh")
	}
	return h, err
}

type commitment struct {
	Commitment string `json:"commitment"`
	Material   string `json:"material"`
	Scheme     string `json:"scheme"`
}
type identity struct {
	Algorithm  string      `json:"algorithm"`
	Derivation string      `json:"derivation"`
	KeyRef     *commitment `json:"key_ref"`
	Source     string      `json:"key_source"`
	PublicKey  string      `json:"public_key"`
	Encoding   string      `json:"public_key_encoding"`
	Role       string      `json:"role"`
}
type verdict struct {
	AppID              string `json:"app_id"`
	Signer             string `json:"signer"`
	Verified           bool   `json:"verified"`
	IdentitiesVerified bool   `json:"identities_verified"`
	CheckedAt          int64  `json:"checked_at"`
	ExpiresAt          int64  `json:"expires_at"`
	Reason             string `json:"reason"`
	ImageEnv           string `json:"image_env"`
	Scope              struct {
		ChainID  uint64 `json:"chain_id"`
		Registry string `json:"registry_address"`
		AppID    string `json:"app_id"`
		Epoch    uint64 `json:"registered_at"`
	} `json:"scope"`
	Status struct {
		AppID         string          `json:"app_id"`
		Signer        string          `json:"signer"`
		CheckedAt     int64           `json:"checked_at"`
		Epoch         uint64          `json:"registered_at"`
		VerifierFault bool            `json:"verifier_fault"`
		Error         json.RawMessage `json:"error"`
		Attested      struct {
			Signer      string       `json:"attested_signer"`
			SignerOK    bool         `json:"signer_ok"`
			Fresh       bool         `json:"fresh"`
			Replay      bool         `json:"runtime_replay_ok"`
			Debug       *bool        `json:"td_debug"`
			TCB         string       `json:"tcb_status"`
			TLS         string       `json:"tls_public_key"`
			AppSigner   string       `json:"app_signer"`
			Identities  []identity   `json:"identities"`
			Commitments []commitment `json:"key_commitments"`
		} `json:"attested"`
	} `json:"status"`
}

func (r *resolver) resolve(ctx context.Context) ([]string, int64, error) {
	before, err := r.health(ctx)
	if err != nil {
		return nil, 0, err
	}
	var app struct {
		AppID   string   `json:"app_id"`
		Signers []string `json:"current_signers"`
	}
	if err := r.request(ctx, http.MethodGet, r.endpoint("apps", r.descriptor.AppID), nil, &app); err != nil {
		return nil, 0, err
	}
	if app.AppID != r.descriptor.AppID || len(app.Signers) == 0 || len(app.Signers) > 64 {
		return nil, 0, fmt.Errorf("invalid current app nodes")
	}
	pins, seen, materials := []string{}, make(map[string]bool), make(map[string]commitment)
	kmsRoles := make(map[string]identity)
	expiry := int64(0)
	for _, signer := range app.Signers {
		if !nonzeroAddress(signer) {
			return nil, 0, fmt.Errorf("invalid current node signer")
		}
		var v verdict
		if err := r.request(ctx, http.MethodPost, r.endpoint("verify"), map[string]string{"app_id": app.AppID, "signer": signer}, &v); err != nil {
			return nil, 0, err
		}
		if v.AppID != app.AppID || !sameAddress(v.Signer, signer) || v.Scope.ChainID != r.descriptor.ChainID ||
			!sameAddress(v.Scope.Registry, r.descriptor.RegistryAddress) || v.Scope.AppID != app.AppID || v.Scope.Epoch != r.descriptor.RegisteredAt ||
			v.Status.AppID != app.AppID || !sameAddress(v.Status.Signer, signer) || v.Status.VerifierFault || !fresh(v.Status.CheckedAt) {
			return nil, 0, fmt.Errorf("Scan verdict scope, instance or node mismatch")
		}
		if !v.Verified {
			if v.Reason == "" {
				return nil, 0, fmt.Errorf("invalid negative Scan verdict")
			}
			continue
		}
		a := v.Status.Attested
		if !v.IdentitiesVerified || v.Reason != "" || string(v.Status.Error) != "null" || v.ImageEnv != "prod" ||
			v.Status.Epoch != r.descriptor.RegisteredAt || v.CheckedAt != v.Status.CheckedAt || v.ExpiresAt <= time.Now().Unix() || v.ExpiresAt > v.CheckedAt+300 ||
			!a.SignerOK || !sameAddress(a.Signer, signer) || !a.Fresh || !a.Replay || a.Debug == nil || *a.Debug || a.TCB == "" || strings.EqualFold(a.TCB, "Revoked") ||
			!sameAddress(a.AppSigner, r.descriptor.AppSigner) || !validPin(a.TLS) {
			return nil, 0, fmt.Errorf("Scan did not verify the expected production app identity")
		}
		if err := validateKeys(a.Identities, a.Commitments, signer, a.AppSigner, a.TLS); err != nil {
			return nil, 0, err
		}
		if err := consistentKMSIdentities(kmsRoles, a.Identities); err != nil {
			return nil, 0, err
		}
		for _, c := range a.Commitments {
			if old, ok := materials[c.Material]; ok && old != c {
				return nil, 0, fmt.Errorf("nodes disagree about KMS commitment")
			}
			materials[c.Material] = c
		}
		pin := strings.TrimPrefix(a.TLS, "0x")
		if !seen[pin] {
			pins, seen[pin] = append(pins, pin), true
		}
		if expiry == 0 || v.ExpiresAt < expiry {
			expiry = v.ExpiresAt
		}
	}
	after, err := r.health(ctx)
	if err != nil {
		return nil, 0, err
	}
	if after.Block < before.Block || len(pins) == 0 || expiry <= time.Now().Unix() {
		return nil, 0, fmt.Errorf("Scan identity expired or scope regressed")
	}
	return pins, expiry, nil
}

func consistentKMSIdentities(seen map[string]identity, ids []identity) error {
	for _, id := range ids {
		if id.Source != "kms" {
			continue
		}
		if old, ok := seen[id.Role]; ok && !reflect.DeepEqual(old, id) {
			return fmt.Errorf("nodes disagree about KMS identity")
		}
		seen[id.Role] = id
	}
	return nil
}

func fresh(at int64) bool { now := time.Now().Unix(); return at > 0 && at <= now+30 && at > now-300 }

func validateKeys(ids []identity, refs []commitment, node, app, tlsHash string) error {
	modulus, _ := hex.DecodeString("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001")
	keys := make(map[commitment]bool)
	materials := make(map[string]bool)
	for _, c := range refs {
		raw, err := hex.DecodeString(strings.TrimPrefix(c.Commitment, "0x"))
		m, merr := hex.DecodeString(c.Material)
		if err != nil || !strings.HasPrefix(c.Commitment, "0x") || len(raw) != 32 || hex.EncodeToString(raw) != c.Commitment[2:] || bytes.Compare(raw, modulus) >= 0 ||
			c.Scheme != "poseidon-bn254-4-v1" || merr != nil || len(m) > 256 || hex.EncodeToString(m) != c.Material || materials[c.Material] {
			return fmt.Errorf("invalid or conflicting KMS commitment")
		}
		keys[c], materials[c.Material] = true, true
	}
	roles := make(map[string]bool)
	for _, id := range ids {
		pub, err := hex.DecodeString(strings.TrimPrefix(id.PublicKey, "0x"))
		if err != nil || !strings.HasPrefix(id.PublicKey, "0x") || len(pub) != 33 || hex.EncodeToString(pub) != id.PublicKey[2:] || id.Encoding != "sec1-compressed" || roles[id.Role] {
			return fmt.Errorf("invalid typed public key")
		}
		roles[id.Role] = true
		if id.Source == "kms" {
			material := "70726f7669646572"
			if id.Role == "tls" {
				material = "746c73"
			}
			if id.KeyRef == nil || !keys[*id.KeyRef] || id.KeyRef.Material != material || id.Derivation != "raw-scalar-v1" {
				return fmt.Errorf("invalid KMS identity reference")
			}
		} else if id.Source != "local" || id.KeyRef != nil {
			return fmt.Errorf("invalid identity provenance")
		}
		switch id.Role {
		case "node_signer", "app_signer":
			p, err := crypto.DecompressPubkey(pub)
			if err != nil || id.Algorithm != "ecdsa-secp256k1" {
				return fmt.Errorf("invalid secp256k1 identity")
			}
			expected := app
			if id.Role == "node_signer" {
				expected = node
				if id.Source != "local" || id.Derivation != "tapp-app-signer-v1" {
					return fmt.Errorf("invalid node identity provenance")
				}
			} else if id.Source != "kms" {
				return fmt.Errorf("app signer is not KMS backed")
			}
			if !sameAddress(crypto.PubkeyToAddress(*p).Hex(), expected) {
				return fmt.Errorf("public key/address mismatch")
			}
		case "tls":
			x, y := elliptic.UnmarshalCompressed(elliptic.P256(), pub)
			if x == nil || id.Algorithm != "ecdsa-p256" || (id.Source == "local" && id.Derivation != "tapp-tls-v1-sha256") {
				return fmt.Errorf("invalid P-256 TLS identity")
			}
			spki, err := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y})
			if err != nil {
				return fmt.Errorf("invalid TLS SPKI")
			}
			hash := sha256.Sum256(spki)
			if hex.EncodeToString(hash[:]) != strings.TrimPrefix(tlsHash, "0x") {
				return fmt.Errorf("public key/TLS SPKI mismatch")
			}
		default:
			return fmt.Errorf("unsupported identity role")
		}
	}
	if !roles["node_signer"] || !roles["app_signer"] || !roles["tls"] {
		return fmt.Errorf("incomplete typed app identity")
	}
	return nil
}
