package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/attestorhttp"
	"seal-verify/internal/config"
	"seal-verify/internal/credentials"
	"seal-verify/internal/credproxy"
	"seal-verify/internal/framework"
	"seal-verify/internal/logger"
	"seal-verify/internal/privsep"
	"seal-verify/internal/provision"
	"seal-verify/internal/proxy"
	"seal-verify/internal/report"
)

// Where the credential proxy's pieces live in the container. The CA files
// hold certificates only; the sockets belong to the agent user.
const (
	credSockPath       = "/run/seal-cred.sock"
	credRevealSockPath = "/run/seal-cred-reveal.sock"
	credCAPath         = "/etc/seal/credential-ca.pem"
	credCABundlePath   = "/etc/seal/credential-ca-bundle.pem"
	systemRootsPath    = "/etc/ssl/certs/ca-certificates.crt"
	maxSystemRoots     = 4 << 20
	ownerWatchInterval = time.Minute
	auditFlushInterval = 10 * time.Second
)

func credStateDir() string { return framework.StatePath("credentials") }

// credentialsBoot is what /provision hands over: the signed set and the
// owner epoch the attestor vouches for.
type credentialsBoot struct {
	Document   credentials.Document `json:"document"`
	OwnerEpoch uint64               `json:"owner_epoch"`
}

// startCredentials brings up the credential store, the proxy, its CA files
// and the two harness sockets, loads the provisioned set, and returns the
// runtime fields that point the framework at them, and the registry whose
// values sealed keeps out of what leaves it. Any failure leaves the agent
// running without credentials rather than not running.
func startCredentials(cfg *config.Bootstrap, res *chainBootstrapResult, agentSealPriv []byte, prov provision.Result, sealedProxy *proxy.Server) (framework.RuntimeContext, *credproxy.Registry) {
	var none framework.RuntimeContext
	if res.client == nil || res.agentID == nil || res.client.ChainID() == nil {
		logger.Logf("credentials: off (no chain client)")
		return none, nil
	}
	key, err := crypto.ToECDSA(agentSealPriv)
	if err != nil {
		logger.Logf("FAIL credentials: agentSeal key: %v", err)
		return none, nil
	}
	client, agentID := res.client, res.agentID
	liveOwner := func(ctx context.Context) (common.Address, error) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return client.OwnerOf(ctx, agentID)
	}
	sealID := "0x" + strings.ToLower(strings.TrimPrefix(cfg.Attestation.SealID, "0x"))

	reg := credproxy.NewRegistry()
	ca, err := credproxy.NewCA()
	if err != nil {
		logger.Logf("FAIL credentials: CA: %v", err)
		return none, nil
	}
	if err := writeCredentialCA(ca); err != nil {
		logger.Logf("FAIL credentials: %v", err)
		return none, nil
	}
	audit := &auditSink{}
	store := credentials.NewStore(credentials.Env{
		Domain:        credentials.Domain{ChainID: client.ChainID().Uint64(), Contract: client.ContractAddr()},
		SealID:        sealID,
		AgentSeal:     crypto.PubkeyToAddress(key.PublicKey),
		AgentSealPriv: agentSealPriv,
		BootID:        prov.BootID,
		LiveOwner:     liveOwner,
		Persist:       statePersist{},
		Audit:         audit.add,
		Logf:          logger.Logf,
		Writeback:     attestorWriteback(cfg.AttestorURL, sealID),
	}, reg)
	audit.store = store
	store.SeedAudit(loadAudit())
	go audit.flushLoop()

	token := randomHex(32)
	srv := credproxy.New(credproxy.Config{Registry: reg, CA: ca, Token: token, Logf: logger.Logf, OnUse: store.Record})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		logger.Logf("FAIL credentials: proxy listen: %v", err)
		return none, nil
	}
	go func() { _ = srv.Serve(ln) }()
	port := ln.Addr().(*net.TCPAddr).Port

	if err := proxy.ServeAgentSocket(credSockPath, "credential", store.HarnessHandler()); err != nil {
		logger.Logf("FAIL credentials: %v", err)
		return none, nil
	}
	if err := proxy.ServeAgentSocket(credRevealSockPath, "credential reveal", store.RevealHandler()); err != nil {
		logger.Logf("FAIL credentials: %v", err)
		return none, nil
	}
	sealedProxy.SetCredentials(store)
	sealedProxy.SetScrubber(reg)

	if len(prov.Credentials) > 0 {
		var boot credentialsBoot
		if err := json.Unmarshal(prov.Credentials, &boot); err != nil {
			logger.Logf("warn: credentials: provisioned set is not valid JSON")
		} else if opened, err := store.Load(context.Background(), boot.Document, boot.OwnerEpoch); err != nil {
			logger.Logf("warn: credentials: provisioned set refused: %v", err)
		} else {
			logger.Logf("OK   credentials: set v%d loaded, %d entries, %d skipped", opened.Set.Version, len(opened.Values), len(opened.Skipped))
		}
	}
	if initial, err := liveOwner(context.Background()); err == nil {
		go watchOwner(store, liveOwner, initial)
	}
	report.SetCredentialsPending(store.PendingCount)
	go reportPendingChanges(cfg, agentSealPriv, store)
	logger.Logf("OK   credential proxy listening on 127.0.0.1:%d", port)
	explicit := fmt.Sprintf("http://127.0.0.1:%d/%s", port, token)
	return framework.RuntimeContext{
		CredHold:       credHold(store, explicit),
		CredProxy:      explicit,
		CredHTTPSProxy: fmt.Sprintf("http://agent:%s@127.0.0.1:%d", token, port),
		CredCAFile:     credCAPath,
		CredCABundle:   credCABundlePath,
		CredSock:       credSockPath,
		CredRevealSock: credRevealSockPath,
	}, reg
}

// credHold is RuntimeContext.CredHold: it keeps a value sealed supplies to
// the framework (its inference key) as the entry "sealed:<name>", filled in
// only in the given headers on baseURL's host, and returns baseURL reached
// through the proxy's explicit form, with the placeholder that stands for
// the value.
func credHold(store *credentials.Store, explicit string) func(name, baseURL string, headers map[string]string, value []byte) (string, string, error) {
	return func(name, baseURL string, headers map[string]string, value []byte) (string, string, error) {
		u, err := url.Parse(baseURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" {
			return "", "", fmt.Errorf("credentials: %q is not an https base URL", baseURL)
		}
		e := &credproxy.Entry{Name: "sealed:" + name, Hosts: []string{u.Host}, Use: credproxy.UseInject, Value: value}
		for header, template := range headers {
			e.Positions = append(e.Positions, credproxy.Position{Kind: credproxy.PosHeader, Name: header, Template: template})
		}
		if err := store.HoldSystem(e); err != nil {
			return "", "", err
		}
		return explicit + "/https/" + u.Host + strings.TrimSuffix(u.EscapedPath(), "/"), credproxy.Placeholder(e.Name), nil
	}
}

// writeCredentialCA writes the proxy root alone and after the image's system
// roots. Both are certificates; the key never leaves memory.
func writeCredentialCA(ca *credproxy.CA) error {
	system, err := privsep.ReadFile(systemRootsPath, maxSystemRoots)
	if err != nil {
		return fmt.Errorf("read system roots: %w", err)
	}
	if err := privsep.MkdirAll(filepath.Dir(credCAPath), 0o755); err != nil {
		return fmt.Errorf("CA directory: %w", err)
	}
	if err := privsep.WriteFile(credCAPath, ca.CertPEM(), 0o644); err != nil {
		return fmt.Errorf("write CA: %w", err)
	}
	if err := privsep.WriteFile(credCABundlePath, ca.Bundle(system), 0o644); err != nil {
		return fmt.Errorf("write CA bundle: %w", err)
	}
	return nil
}

// watchOwner clears every credential when the agent's owner changes: the
// previous owner's keys must not serve the new one. A failed lookup changes
// nothing; the next succeeds or fails the same way.
func watchOwner(store *credentials.Store, liveOwner func(context.Context) (common.Address, error), owner common.Address) {
	for range time.Tick(ownerWatchInterval) {
		now, err := liveOwner(context.Background())
		if err != nil || now == owner {
			continue
		}
		logger.Logf("credentials: owner changed from %s to %s; every credential cleared", owner.Hex(), now.Hex())
		store.Clear()
		owner = now
	}
}

// reportPendingChanges sends a status report as soon as a request starts
// waiting for the owner (or is decided), instead of at the next heartbeat,
// so the owner's cross-agent view is current within seconds.
func reportPendingChanges(cfg *config.Bootstrap, agentSealPriv []byte, store *credentials.Store) {
	var after uint64
	for {
		events := store.Events(context.Background(), after, time.Minute)
		changed := false
		for _, e := range events {
			after = e.Seq
			if e.Type == "pending_opened" || e.Type == "pending_decided" || e.Type == "cleared" {
				changed = true
			}
		}
		if changed {
			level, msg := currentStatus.Get()
			report.Status(cfg.AttestorURL, agentSealPriv, cfg.Attestation.SealID, level, msg, cfg.StatusBinding)
		}
	}
}

// statePersist keeps the highest loaded set version in sealed's root-only
// state directory, which survives stop/start.
type statePersist struct{}

func (statePersist) path() string { return filepath.Join(credStateDir(), "highest-version") }

func (p statePersist) LoadHighest() (uint64, error) {
	b, err := privsep.ReadFile(p.path(), 64)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
}

func (p statePersist) SaveHighest(v uint64) error {
	if err := privsep.MkdirAll(credStateDir(), 0o700); err != nil {
		return err
	}
	return privsep.WriteFile(p.path(), []byte(strconv.FormatUint(v, 10)), 0o600)
}

// auditSink persists the store's audit records in the state directory,
// batched so a busy proxy does not rewrite the file per request.
type auditSink struct {
	mu    sync.Mutex
	dirty bool
	store *credentials.Store
}

func auditPath() string { return filepath.Join(credStateDir(), "audit.json") }

func (a *auditSink) add(credentials.AuditRecord) {
	a.mu.Lock()
	a.dirty = true
	a.mu.Unlock()
}

func (a *auditSink) flushLoop() {
	for range time.Tick(auditFlushInterval) {
		a.mu.Lock()
		dirty := a.dirty
		a.dirty = false
		a.mu.Unlock()
		if !dirty || a.store == nil {
			continue
		}
		b, err := json.Marshal(a.store.AuditSince(0))
		if err == nil {
			if err = privsep.MkdirAll(credStateDir(), 0o700); err == nil {
				err = privsep.WriteFile(auditPath(), b, 0o600)
			}
		}
		if err != nil {
			logger.Logf("warn: credentials: audit flush: %v", err)
		}
	}
}

func loadAudit() []credentials.AuditRecord {
	b, err := privsep.ReadFile(auditPath(), 4<<20)
	if err != nil {
		return nil
	}
	var recs []credentials.AuditRecord
	if json.Unmarshal(b, &recs) != nil {
		return nil
	}
	return recs
}

// attestorWriteback posts a value sealed obtained (a rotated refresh token,
// a login) to the attestor, which keeps it for the next boot.
func attestorWriteback(attestorURL, sealID string) func(context.Context, string, credentials.Writeback) error {
	if attestorURL == "" {
		return nil
	}
	return func(ctx context.Context, name string, wb credentials.Writeback) error {
		client, err := attestorhttp.Client(attestorURL)
		if err != nil {
			return err
		}
		body, _ := json.Marshal(map[string]any{"seal_id": sealID, "name": name, "writeback": wb})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, attestorURL+"/credentials/writeback", bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("attestor writeback: HTTP %d: %s", resp.StatusCode, attestorhttp.Excerpt(out))
		}
		return nil
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
