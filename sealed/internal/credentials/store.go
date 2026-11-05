package credentials

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"seal-verify/internal/credproxy"
)

// pendingTTL is how long an undecided request stays open; no decision in
// that time counts as a refusal.
const pendingTTL = 72 * time.Hour

// Refusal codes for a pending request follow OpenID CIBA / RFC 8628.
const (
	CodePending = "authorization_pending"
	CodeDenied  = "access_denied"
)

// Persist keeps the highest credential set version this agent has loaded,
// so a stop/start cannot roll the set back. main wires it to the state
// directory through privsep.
type Persist interface {
	LoadHighest() (uint64, error)
	SaveHighest(uint64) error
}

// AuditRecord is one use of a credential, kept for the owner. It never
// holds a value.
type AuditRecord struct {
	Time   time.Time `json:"ts"`
	Op     string    `json:"op"`
	Names  []string  `json:"names"`
	Host   string    `json:"host,omitempty"`
	Method string    `json:"method,omitempty"`
	Result string    `json:"result"`
}

// Env is what the store needs from the running sealed.
type Env struct {
	Domain        Domain
	SealID        string
	AgentSeal     common.Address
	AgentSealPriv []byte
	BootID        string
	// LiveOwner returns the current on-chain owner; an error fails closed.
	LiveOwner func(ctx context.Context) (common.Address, error)
	Persist   Persist
	Audit     func(AuditRecord)
	Logf      func(string, ...any)
	// Writeback stores a value sealed obtained (rotation or login) at the
	// attestor. Nil when there is no attestor to write to.
	Writeback func(ctx context.Context, name string, w Writeback) error
	// HTTPClient makes token requests; nil builds one on credproxy.SafeDial.
	HTTPClient *http.Client
}

// Pending is a request waiting for the owner.
type Pending struct {
	AuthReqID     string            `json:"auth_req_id"`
	Op            string            `json:"op"` // reveal | add | login
	Name          string            `json:"name"`
	Params        map[string]string `json:"params,omitempty"`
	Facts         map[string]any    `json:"facts"`
	Reason        string            `json:"reason,omitempty"` // from the harness
	RequestDigest string            `json:"request_digest"`
	BootID        string            `json:"boot_id"`
	CreatedAt     int64             `json:"created_at"`
	ExpiresAt     int64             `json:"expires_at"`
	Status        string            `json:"status"` // pending | approved | denied
}

// EntryInfo is what the harness may know about an entry: never its value.
type EntryInfo struct {
	Name        string               `json:"name"`
	Description string               `json:"description,omitempty"`
	Source      string               `json:"source"` // owner | derived
	From        string               `json:"from,omitempty"`
	Use         string               `json:"use"`
	Hosts       []string             `json:"hosts"`
	Positions   []credproxy.Position `json:"positions"`
	// Signer says how a signing entry is used (no secret in it).
	Signer      *credproxy.Signer `json:"signer,omitempty"`
	ExpiresAt   int64             `json:"expires_at,omitempty"`
	AllowReveal bool              `json:"allow_reveal"`
	Placeholder string            `json:"placeholder"`
}

type derived struct {
	from      string
	hosts     []string
	expiresAt int64
}

// Store is the credential state of one running agent.
type Store struct {
	env Env
	reg *credproxy.Registry

	auditMu sync.Mutex

	mu            sync.Mutex
	version       uint64
	defs          map[string]*Definition
	defHashes     map[string]string // the signed hash of each definition
	values        map[string][]byte
	derived       map[string]derived
	system        map[string]*credproxy.Entry // values sealed supplies to the framework
	pending       map[string]*Pending         // by auth_req_id
	approvals     map[string]Approval         // by request digest
	tokenMu       map[string]*sync.Mutex
	logins        map[string]*loginAttempt // by OAuth state
	refreshTimers map[string]*time.Timer   // login entries, by name
	events        *eventLog
	auditLog      []AuditRecord
	now           func() time.Time
}

const auditKeep = 1000

// addAudit keeps rec for the owner's audit route and hands it to Env.Audit,
// which persists it.
func (s *Store) addAudit(rec AuditRecord) {
	s.auditMu.Lock()
	s.auditLog = append(s.auditLog, rec)
	if len(s.auditLog) > auditKeep {
		s.auditLog = s.auditLog[len(s.auditLog)-auditKeep:]
	}
	s.auditMu.Unlock()
	s.env.Audit(rec)
}

// SeedAudit restores records persisted by an earlier boot.
func (s *Store) SeedAudit(recs []AuditRecord) {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	s.auditLog = append(append([]AuditRecord{}, recs...), s.auditLog...)
	if len(s.auditLog) > auditKeep {
		s.auditLog = s.auditLog[len(s.auditLog)-auditKeep:]
	}
}

// AuditSince returns the records newer than after (Unix seconds).
func (s *Store) AuditSince(after int64) []AuditRecord {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	var out []AuditRecord
	for _, r := range s.auditLog {
		if r.Time.Unix() > after {
			out = append(out, r)
		}
	}
	return out
}

// NewStore returns an empty store serving reg.
func NewStore(env Env, reg *credproxy.Registry) *Store {
	if env.Logf == nil {
		env.Logf = func(string, ...any) {}
	}
	if env.Audit == nil {
		env.Audit = func(AuditRecord) {}
	}
	return &Store{
		env: env, reg: reg,
		defs: map[string]*Definition{}, defHashes: map[string]string{}, values: map[string][]byte{}, derived: map[string]derived{},
		pending: map[string]*Pending{}, approvals: map[string]Approval{}, tokenMu: map[string]*sync.Mutex{},
		logins: map[string]*loginAttempt{}, refreshTimers: map[string]*time.Timer{}, system: map[string]*credproxy.Entry{},
		events: newEventLog(), now: time.Now,
	}
}

// Version is the loaded set's version (0 = none).
func (s *Store) Version() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.version
}

// Load verifies doc against the live owner and swaps it in. ownerEpoch,
// when non-zero, is the epoch the attestor vouches for.
func (s *Store) Load(ctx context.Context, doc Document, ownerEpoch uint64) (*Opened, error) {
	owner, err := s.env.LiveOwner(ctx)
	if err != nil {
		return nil, err
	}
	highest := uint64(0)
	if s.env.Persist != nil {
		if highest, err = s.env.Persist.LoadHighest(); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	if s.version > highest {
		highest = s.version
	}
	s.mu.Unlock()
	o, err := Open(doc, Check{Domain: s.env.Domain, SealID: s.env.SealID, Owner: owner, AgentSeal: s.env.AgentSeal,
		AgentSealPriv: s.env.AgentSealPriv, MinVersion: highest, OwnerEpoch: ownerEpoch})
	if err != nil {
		return nil, err
	}
	if s.env.Persist != nil && o.Set.Version > highest {
		if err := s.env.Persist.SaveHighest(o.Set.Version); err != nil {
			return nil, err
		}
	}
	// Refreshes are scheduled once the lock below is released (this defer
	// runs after the Unlock deferred under it).
	var refresh []func()
	defer func() {
		for _, f := range refresh {
			f()
		}
	}()
	s.mu.Lock()
	defer s.mu.Unlock()
	before, beforeHashes, beforeValues := s.defs, s.defHashes, s.values
	hashes := map[string]string{}
	for _, e := range o.Set.Entries {
		hashes[e.Name] = strings.ToLower(e.DefHash)
	}
	// A value sealed obtained (a rotation, a login) outlives a new set that
	// leaves its definition as it was: the owner changed something else.
	for name, d := range o.Defs {
		if d.Writeback && beforeHashes[name] != "" && beforeHashes[name] == hashes[name] && beforeValues[name] != nil {
			o.Values[name] = beforeValues[name]
		}
	}
	s.version, s.defs, s.defHashes, s.values = o.Set.Version, o.Defs, hashes, o.Values
	// Login entries refresh their access token themselves.
	for name, t := range s.refreshTimers {
		t.Stop()
		delete(s.refreshTimers, name)
	}
	for name, d := range s.defs {
		if st, ok := parseMCPState(s.values[name]); ok && d.MCP != nil {
			name := name
			refresh = append(refresh, func() { s.scheduleRefresh(name, st) })
		}
	}
	for name, d := range s.derived {
		if _, ok := s.defs[d.from]; !ok {
			delete(s.derived, name)
		}
	}
	s.syncRegistryLocked()
	for name := range s.defs {
		if _, was := before[name]; !was {
			s.events.add(Event{Type: "entry_added", Name: name})
		}
	}
	for name := range before {
		if _, still := s.defs[name]; !still {
			s.events.add(Event{Type: "entry_removed", Name: name})
		}
	}
	// An add or login request is answered by the owner adding the entry.
	for id, p := range s.pending {
		if (p.Op == "add" || p.Op == "login") && p.Status == "pending" {
			if _, ok := s.defs[p.Name]; ok {
				p.Status = "approved"
				s.events.add(Event{Type: "pending_decided", Name: p.Name, AuthReqID: id, Status: p.Status})
			}
		}
	}
	for name, why := range o.Skipped {
		s.env.Logf("credentials: entry %q skipped: %s", name, why)
	}
	return o, nil
}

// Clear drops every entry, request and approval: the owner changed.
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.defs, s.defHashes, s.values, s.derived = map[string]*Definition{}, map[string]string{}, map[string][]byte{}, map[string]derived{}
	s.pending, s.approvals = map[string]*Pending{}, map[string]Approval{}
	s.logins = map[string]*loginAttempt{}
	// What sealed supplied for the framework came with the previous owner's
	// deployment: it goes too, until the new owner resets the agent.
	s.system = map[string]*credproxy.Entry{}
	for name, t := range s.refreshTimers {
		t.Stop()
		delete(s.refreshTimers, name)
	}
	_ = s.reg.Replace(nil)
	s.events.add(Event{Type: "cleared"})
}

// syncRegistryLocked rebuilds the proxy's entries from defs, values and
// derived entries. Entries with no value yet (a login not done) are left out.
func (s *Store) syncRegistryLocked() {
	var entries []*credproxy.Entry
	for name, d := range s.defs {
		if v, ok := s.values[name]; ok && v != nil {
			entries = append(entries, d.Entry(v))
		}
	}
	for name := range s.derived {
		if e := s.reg.Get(name); e != nil {
			entries = append(entries, e)
		} else {
			delete(s.derived, name)
		}
	}
	for _, e := range s.system {
		entries = append(entries, e)
	}
	if err := s.reg.Replace(entries); err != nil {
		s.env.Logf("credentials: registry: %v", err)
	}
}

// HoldSystem keeps a value sealed itself supplies to the framework (its
// inference key) as an entry named "sealed:<name>": the framework gets the
// placeholder, the proxy fills the value in, and nothing reveals it. A new
// value for the same name replaces the old one.
func (s *Store) HoldSystem(e *credproxy.Entry) error {
	if !strings.HasPrefix(e.Name, "sealed:") {
		return fmt.Errorf("a value sealed supplies is named sealed:<name>, not %q", e.Name)
	}
	if err := e.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.system[e.Name] = e
	s.syncRegistryLocked()
	return nil
}

// List describes every entry the harness may use.
func (s *Store) List() []EntryInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []EntryInfo
	for name, d := range s.defs {
		if _, ok := s.values[name]; !ok {
			continue
		}
		out = append(out, EntryInfo{Name: name, Description: d.Description, Source: "owner", Use: string(useOf(d)),
			Hosts: d.Hosts, Positions: d.Positions, Signer: d.Signer, ExpiresAt: d.ExpiresAt, AllowReveal: d.AllowReveal,
			Placeholder: credproxy.Placeholder(name)})
	}
	for name, d := range s.derived {
		src := s.defs[d.from]
		var positions []credproxy.Position
		if e := s.reg.Get(name); e != nil {
			positions = e.Positions
		}
		out = append(out, EntryInfo{Name: name, Source: "derived", From: d.from, Use: string(credproxy.UseInject),
			Hosts: d.hosts, Positions: positions, ExpiresAt: d.expiresAt, AllowReveal: src != nil && src.AllowReveal,
			Placeholder: credproxy.Placeholder(name)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func useOf(d *Definition) credproxy.Use {
	if d.Use == "" {
		return credproxy.UseInject
	}
	return d.Use
}

// DeleteDerived removes an entry the harness obtained; owner entries are the
// owner's to change.
func (s *Store) DeleteDerived(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.derived[name]; !ok {
		if _, owner := s.defs[name]; owner {
			return &credproxy.Error{Status: http.StatusForbidden, Code: "not_allowed", Message: "only derived entries can be deleted here"}
		}
		return &credproxy.Error{Status: http.StatusNotFound, Code: "unknown_entry", Message: "no credential named " + name}
	}
	delete(s.derived, name)
	s.reg.Delete(name)
	return nil
}

// RequestDigest binds an approval to one request: the operation, the entry
// and the parameters (sorted, k=v joined by '&').
func RequestDigest(op, name string, params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+params[k])
	}
	return crypto.Keccak256Hash([]byte(op + "\n" + name + "\n" + strings.Join(parts, "&"))).Hex()
}

func newID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "0x" + hex.EncodeToString(b)
}

// BootIDHash is the bytes32 form of the boot id signed into approvals.
func BootIDHash(bootID string) string { return crypto.Keccak256Hash([]byte(bootID)).Hex() }

// Reveal hands an entry's value to the harness if the owner allowed it in
// advance or approved this exact request; otherwise it opens (or reports) a
// pending request and returns authorization_pending.
func (s *Store) Reveal(name, reason string) ([]byte, *credproxy.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, def, from := s.valueLocked(name)
	if value == nil {
		return nil, &credproxy.Error{Status: http.StatusNotFound, Code: "unknown_entry", Message: "no credential named " + name}
	}
	if def.AllowReveal {
		s.addAudit(AuditRecord{Time: s.now(), Op: "reveal", Names: []string{name}, Result: "allowed in advance"})
		return value, nil
	}
	digest := RequestDigest("reveal", name, nil)
	if a, ok := s.approvals[digest]; ok {
		delete(s.approvals, digest)
		if uint64(s.now().Unix()) <= a.ExpiresAt {
			s.addAudit(AuditRecord{Time: s.now(), Op: "reveal", Names: []string{name}, Result: "approved once"})
			return value, nil
		}
	}
	p := s.pendingForLocked("reveal", name, nil, reason, map[string]any{"source": sourceOf(from), "from": from, "hosts": def.Hosts, "expires_at": def.ExpiresAt})
	if p.Status == "denied" {
		delete(s.pending, p.AuthReqID)
		return nil, &credproxy.Error{Status: http.StatusForbidden, Code: CodeDenied, Message: "the owner refused this request"}
	}
	return nil, &credproxy.Error{Status: http.StatusForbidden, Code: CodePending, Message: p.AuthReqID}
}

func sourceOf(from string) string {
	if from == "" {
		return "owner"
	}
	return "derived"
}

// valueLocked returns name's value, the definition that governs it (its own,
// or its source's for a derived entry), and the source name for derived ones.
func (s *Store) valueLocked(name string) ([]byte, *Definition, string) {
	if d, ok := s.defs[name]; ok {
		return usableValue(d, s.values[name]), d, ""
	}
	if d, ok := s.derived[name]; ok {
		if e := s.reg.Get(name); e != nil && s.defs[d.from] != nil {
			return e.Value, s.defs[d.from], d.from
		}
	}
	return nil, nil, ""
}

// Request records an add or login request for the owner.
func (s *Store) Request(op, name string, params map[string]string, reason string) (*Pending, *credproxy.Error) {
	if op != "add" && op != "login" {
		return nil, &credproxy.Error{Status: http.StatusBadRequest, Code: "bad_request", Message: "op must be add or login"}
	}
	if !credproxy.ValidName(name) || strings.Contains(name, ":") {
		return nil, &credproxy.Error{Status: http.StatusBadRequest, Code: "bad_request", Message: "invalid entry name"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	facts := map[string]any{}
	for k, v := range params {
		facts[k] = v
	}
	p := s.pendingForLocked(op, name, params, reason, facts)
	cp := *p
	return &cp, nil
}

// pendingForLocked returns the open request for (op, name, params), opening
// one if there is none. Expired requests are dropped first.
func (s *Store) pendingForLocked(op, name string, params map[string]string, reason string, facts map[string]any) *Pending {
	now := s.now().Unix()
	digest := RequestDigest(op, name, params)
	for id, p := range s.pending {
		if p.ExpiresAt < now {
			delete(s.pending, id)
			continue
		}
		if p.RequestDigest == digest {
			return p
		}
	}
	p := &Pending{AuthReqID: newID(), Op: op, Name: name, Params: params, Facts: facts, Reason: reason,
		RequestDigest: digest, BootID: BootIDHash(s.env.BootID), CreatedAt: now, ExpiresAt: now + int64(pendingTTL/time.Second), Status: "pending"}
	s.pending[p.AuthReqID] = p
	s.events.add(Event{Type: "pending_opened", Name: name, AuthReqID: p.AuthReqID})
	return p
}

// PendingList returns the open requests, newest first.
func (s *Store) PendingList() []Pending {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().Unix()
	var out []Pending
	for id, p := range s.pending {
		if p.ExpiresAt < now {
			delete(s.pending, id)
			continue
		}
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

// PendingCount is the number of requests waiting for the owner.
func (s *Store) PendingCount() int {
	n := 0
	for _, p := range s.PendingList() {
		if p.Status == "pending" {
			n++
		}
	}
	return n
}

// ErrUnknownRequest is returned for a decision on a request that is not open.
var ErrUnknownRequest = errors.New("no such pending request")

// Decide records the owner's decision on a pending request. "once" carries
// an EIP-712 Approval signed by the live owner, bound to this boot, this
// request and its digest.
func (s *Store) Decide(ctx context.Context, authReqID, decision string, a *Approval, sig string) error {
	s.mu.Lock()
	p, ok := s.pending[authReqID]
	s.mu.Unlock()
	if !ok {
		return ErrUnknownRequest
	}
	switch decision {
	case "deny":
		s.mu.Lock()
		p.Status = "denied"
		s.events.add(Event{Type: "pending_decided", Name: p.Name, AuthReqID: authReqID, Status: p.Status})
		s.mu.Unlock()
		return nil
	case "once":
	default:
		return errors.New("decision must be once or deny")
	}
	if a == nil {
		return errors.New("an approval is required")
	}
	if !strings.EqualFold(a.SealID, s.env.SealID) || !strings.EqualFold(a.BootID, p.BootID) ||
		!strings.EqualFold(a.AuthReqID, authReqID) || !strings.EqualFold(a.RequestDigest, p.RequestDigest) {
		return errors.New("the approval is for another request, boot or agent")
	}
	if a.ExpiresAt < uint64(s.now().Unix()) || int64(a.ExpiresAt) > p.ExpiresAt {
		return errors.New("the approval has expired or outlives its request")
	}
	digest, err := a.Digest(s.env.Domain)
	if err != nil {
		return err
	}
	signer, err := Recover(digest, sig)
	if err != nil {
		return err
	}
	owner, err := s.env.LiveOwner(ctx)
	if err != nil {
		return err
	}
	if signer != owner {
		return ErrWrongSigner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.approvals[p.RequestDigest] = *a
	p.Status = "approved"
	s.events.add(Event{Type: "pending_decided", Name: p.Name, AuthReqID: authReqID, Status: p.Status})
	return nil
}

// Events returns events after seq, waiting up to wait for one to arrive.
func (s *Store) Events(ctx context.Context, after uint64, wait time.Duration) []Event {
	return s.events.wait(ctx, after, wait)
}

// Record logs a proxy use (credproxy.Config.OnUse).
func (s *Store) Record(r credproxy.Record) {
	result := "sent"
	if r.Code != "" {
		result = r.Code
	}
	s.addAudit(AuditRecord{Time: r.Time, Op: "inject", Names: r.Names, Host: r.Host, Method: r.Method, Result: result})
}
