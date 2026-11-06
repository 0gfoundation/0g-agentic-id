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
	"unicode"
	"unicode/utf8"

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

// Persist keeps the newest credential set this agent has loaded, so a
// stop/start cannot roll the set back. main wires it to the state directory
// through privsep.
type Persist interface {
	LoadHighest() (Mark, error)
	SaveHighest(Mark) error
}

// ownerFresh is how long a confirmed owner stands before a value leaves
// sealed or is traded (a reveal, a token request, a wallet signature, a
// login): older, the owner is looked up again first.
const ownerFresh = 10 * time.Second

// Bounds on what the harness can make sealed keep for the owner.
const (
	maxOpenRequests = 32
	maxReason       = 512
	maxParams       = 4
	maxParam        = 512
	maxURLParam     = 2048
	maxAuditResult  = 256
	maxAuditHost    = 255
	maxAuditNames   = 16
	maxAuditName    = 80
	maxCountKeys    = 1024 // all kinds together, a backstop
	maxResultKeys   = 32   // the named kinds of one operation with one result
)

// ErrEntryChanged is a disconnect that found its entry cleared or redefined
// while it ran: nothing was forgotten.
var ErrEntryChanged = errors.New("the entry changed while the disconnect ran; nothing was forgotten, disconnect again")

// ErrOwnerLookup is a Load that could not look the owner up: worth trying
// again, unlike a set that does not check out.
var ErrOwnerLookup = errors.New("the agent's owner could not be looked up")

// ErrOwnerChanged refuses what sealed would supply the framework after the
// owner changed: it came with the previous owner's deployment.
var ErrOwnerChanged = errors.New("the agent's owner changed; the new owner resets the agent")

// AuditRecord is one use of a credential, kept for the owner. It never
// holds a value.
type AuditRecord struct {
	Time   time.Time `json:"ts"`
	Op     string    `json:"op"`
	Names  []string  `json:"names"`
	Host   string    `json:"host,omitempty"`
	Method string    `json:"method,omitempty"`
	Result string    `json:"result"`
	// Count, with First, makes one record stand for many uses: a value
	// sealed supplies itself (a "sealed:" entry, the framework's inference
	// key) is used on every model call, so its successful uses are counted,
	// not listed. Time is then the latest use.
	Count int        `json:"count,omitempty"`
	First *time.Time `json:"first,omitempty"`
	// repeat: the harness can cause this record as often as it likes (a
	// token request, a failed signature, a reveal allowed in advance), so
	// it is counted by kind rather than listed, and never pushes the rest out.
	repeat bool
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
	Signer    *credproxy.Signer `json:"signer,omitempty"`
	ExpiresAt int64             `json:"expires_at,omitempty"`
	// LoggedInAt is when the owner last completed a login entry's login.
	LoggedInAt int64 `json:"logged_in_at,omitempty"`
	// Status "awaiting_login": the owner has not finished this login entry's
	// login, so it cannot be used yet.
	Status      string `json:"status,omitempty"`
	AllowReveal bool   `json:"allow_reveal"`
	Placeholder string `json:"placeholder"`
}

type derived struct {
	from      string
	srcHash   string            // the source definition it was obtained under
	params    map[string]string // the harness's parameters to its token request
	hosts     []string
	expiresAt int64
}

// Store is the credential state of one running agent.
type Store struct {
	env Env
	reg *credproxy.Registry

	auditMu     sync.Mutex
	auditCounts map[string]*AuditRecord // counted records, by countKey
	auditOpKeys map[string]int          // counted kinds per operation and result class
	// Listed records, in three rings so that what the harness can cause
	// (proxy uses, signatures) never pushes out the rest: the owner's
	// decisions, logins, loads and what sealed did itself.
	auditInject []AuditRecord
	auditSign   []AuditRecord
	auditLog    []AuditRecord
	// auditSeed holds what an earlier boot persisted until the owner is
	// known: it is restored only for the owner who wrote it.
	auditSeed  *AuditFile
	auditReady bool // the seed is decided; persisting may begin

	loadMu sync.Mutex // one Load at a time

	mu sync.Mutex
	// owner is the owner the state belongs to (zero until first seen), and
	// ownerAt when the lookup that last confirmed it began. Lookups are
	// numbered as they begin (lookupSeq); appliedSeq is the latest recorded.
	owner      common.Address
	ownerAt    time.Time
	lookupSeq  uint64
	appliedSeq uint64
	// gen advances when everything is cleared: work begun before (a token
	// request, a login, a decision) is dropped.
	gen uint64
	// retired: the owner changed, and what sealed supplied the framework is
	// not taken again until the new owner resets the agent.
	retired       bool
	version       uint64
	mark          Mark
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
	now           func() time.Time
	// retryUnit paces writeback retries: a second (tests shorten it).
	retryUnit time.Duration
}

// auditKeep bounds each of the two lists: proxy uses, and everything else.
const auditKeep = 1000

// AuditFile is the audit log as persisted: whose it is, and the records.
type AuditFile struct {
	Owner   common.Address `json:"owner"`
	Records []AuditRecord  `json:"records"`
}

// addAudit keeps rec for the owner's audit route and hands it to Env.Audit,
// which persists it. What the harness can repeat at will is counted by kind,
// and proxy uses are kept apart from the rest, so neither pushes reveals,
// signatures or decisions out of the log.
func (s *Store) addAudit(rec AuditRecord) {
	s.auditMu.Lock()
	s.keepLocked(rec, 1)
	s.auditMu.Unlock()
	s.env.Audit(rec)
}

// boundAudit keeps a record small whatever the harness sent: a refused
// request can name any host and any number of placeholders.
func boundAudit(r AuditRecord) AuditRecord {
	r.Result, r.Host = clip(r.Result, maxAuditResult), clip(r.Host, maxAuditHost)
	if len(r.Names) == 0 {
		return r
	}
	names := make([]string, 0, min(len(r.Names), maxAuditNames+1))
	for i, n := range r.Names {
		if i == maxAuditNames {
			names = append(names, fmt.Sprintf("+%d more", len(r.Names)-maxAuditNames))
			break
		}
		names = append(names, clip(n, maxAuditName))
	}
	r.Names = names
	return r
}

func (s *Store) keepLocked(rec AuditRecord, n int) {
	rec = boundAudit(rec)
	switch {
	case rec.Count > 0:
		s.countLocked(rec, rec.Count)
	case counted(rec) || rec.repeat:
		s.countLocked(rec, n)
	case rec.Op == "inject":
		s.auditInject = s.keepRingLocked(s.auditInject, rec)
	case strings.HasPrefix(rec.Op, "sign"):
		s.auditSign = s.keepRingLocked(s.auditSign, rec)
	default:
		s.auditLog = s.keepRingLocked(s.auditLog, rec)
	}
}

// keepRingLocked appends rec to a ring of auditKeep records; what falls out
// of it is folded into a count of its kind, so a record leaves the log as a
// number, never without a trace.
func (s *Store) keepRingLocked(list []AuditRecord, rec AuditRecord) []AuditRecord {
	list = append(list, rec)
	for len(list) > auditKeep {
		old := list[0]
		list = list[1:]
		result := old.Result
		if i := strings.IndexByte(result, ':'); i > 0 {
			result = result[:i] // "signed: chain …" counts as "signed"
		}
		at := old.Time
		s.countLocked(AuditRecord{Op: old.Op, Names: old.Names, Host: old.Host, Result: result, Time: old.Time, First: &at}, 1)
	}
	if cap(list) > 2*auditKeep {
		list = append([]AuditRecord(nil), list...)
	}
	return list
}

// counted: a successful use of entries that are all sealed's own.
func counted(r AuditRecord) bool {
	if r.Result != "sent" || len(r.Names) == 0 {
		return false
	}
	for _, n := range r.Names {
		if !strings.HasPrefix(n, "sealed:") {
			return false
		}
	}
	return true
}

// resultClass is a result's kind: the text before a colon ("refused: …"
// counts as "refused"), so the results a budget is kept for are a bounded
// set.
func resultClass(r string) string {
	if i := strings.IndexByte(r, ':'); i > 0 {
		return r[:i]
	}
	return r
}

func countKey(r AuditRecord) string {
	return strings.Join([]string{r.Op, strings.Join(r.Names, ","), r.Method, r.Host, r.Result}, "\x00")
}

// countLocked adds n uses ending at r.Time (from r.First when set). Each
// operation and result (the result's class: the text before a colon) has its
// own budget of maxResultKeys named kinds; past it, further kinds are
// counted by operation and result class alone, a bounded set. So what the
// harness floods one result with blurs only that result's later kinds:
// refused uses of unknown names leave a host an entry does not allow, the
// owner's own uses and every other operation named. maxCountKeys is a
// backstop past which every operation's new kinds are counted by result
// class alone.
func (s *Store) countLocked(r AuditRecord, n int) {
	first := r.Time
	if r.First != nil {
		first = *r.First
	}
	if _, ok := s.auditCounts[countKey(r)]; !ok {
		switch {
		case len(s.auditCounts) >= maxCountKeys:
			// Still by result class (a bounded set), so no result is lost.
			r = AuditRecord{Op: r.Op, Names: []string{"*"}, Result: resultClass(r.Result), Time: r.Time, First: r.First}
		case s.auditOpKeys[r.Op+"\x00"+resultClass(r.Result)] >= maxResultKeys:
			r = AuditRecord{Op: r.Op, Names: []string{"*"}, Result: resultClass(r.Result), Time: r.Time, First: r.First}
		}
	}
	c := s.auditCounts[countKey(r)]
	if c == nil {
		c = &AuditRecord{Op: r.Op, Names: r.Names, Method: r.Method, Host: r.Host, Result: r.Result, Time: r.Time, First: &first}
		s.auditCounts[countKey(r)] = c
		s.auditOpKeys[r.Op+"\x00"+resultClass(r.Result)]++
	} else {
		if first.Before(*c.First) {
			c.First = &first
		}
		if r.Time.After(c.Time) {
			c.Time = r.Time
		}
	}
	c.Count += n
}

// Note records an event for the owner's audit log only: what sealed's public
// log must not name (an entry skipped, a set refused) goes here.
func (s *Store) Note(op, name, result string) { s.audit(op, name, "", result) }

// SeedAudit restores the records an earlier boot persisted, once the owner
// is known and only if it is the owner who wrote them: a previous owner's
// log is not the new owner's to read. nil (nothing persisted) decides at once.
func (s *Store) SeedAudit(f *AuditFile) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if f == nil {
		s.auditReady = true
		return
	}
	s.auditSeed = f
	s.decideSeedLocked()
}

// decideSeedLocked restores or drops the persisted records once the owner
// is known. Called with mu and auditMu held.
func (s *Store) decideSeedLocked() {
	if s.auditSeed == nil || s.owner == (common.Address{}) {
		return
	}
	seed := s.auditSeed
	s.auditSeed, s.auditReady = nil, true
	if seed.Owner != s.owner {
		return
	}
	kept := append(append(append([]AuditRecord(nil), s.auditInject...), s.auditSign...), s.auditLog...)
	s.auditInject, s.auditSign, s.auditLog = nil, nil, nil
	for _, r := range seed.Records {
		s.keepLocked(r, 1)
	}
	for _, r := range kept {
		s.keepLocked(r, 1)
	}
}

// AuditSnapshot is what to persist: every record, with the owner they
// belong to, read together. ok is false until the persisted records are
// decided (the owner not yet known), so a boot never overwrites them early.
func (s *Store) AuditSnapshot() (f AuditFile, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if !s.auditReady || s.auditSeed != nil || s.owner == (common.Address{}) {
		return AuditFile{}, false
	}
	return AuditFile{Owner: s.owner, Records: s.auditSinceLocked(0)}, true
}

// AuditSince returns the records newer than after (Unix seconds), oldest
// first; a counted record is there when its latest use is.
func (s *Store) AuditSince(after int64) []AuditRecord {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	return s.auditSinceLocked(after)
}

func (s *Store) auditSinceLocked(after int64) []AuditRecord {
	var out []AuditRecord
	for _, list := range [][]AuditRecord{s.auditLog, s.auditSign, s.auditInject} {
		for _, r := range list {
			if r.Time.Unix() > after {
				out = append(out, r)
			}
		}
	}
	for _, c := range s.auditCounts {
		if c.Time.Unix() > after {
			out = append(out, *c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
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
	if env.LiveOwner == nil {
		env.LiveOwner = func(context.Context) (common.Address, error) { return common.Address{}, errors.New("no chain client") }
	}
	return &Store{
		env: env, reg: reg,
		defs: map[string]*Definition{}, defHashes: map[string]string{}, values: map[string][]byte{}, derived: map[string]derived{},
		pending: map[string]*Pending{}, approvals: map[string]Approval{}, tokenMu: map[string]*sync.Mutex{},
		logins: map[string]*loginAttempt{}, refreshTimers: map[string]*time.Timer{}, system: map[string]*credproxy.Entry{},
		events: newEventLog(), now: time.Now, auditCounts: map[string]*AuditRecord{}, auditOpKeys: map[string]int{},
		retryUnit: time.Second,
	}
}

// Version is the loaded set's version (0 = none).
func (s *Store) Version() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.version
}

// ObserveOwner records the live on-chain owner as of now. The first one
// seen is the owner the state belongs to; a different one later clears
// everything (the previous owner's keys must not serve the new one) and is
// reported.
func (s *Store) ObserveOwner(live common.Address) (changed bool) {
	l := s.BeginOwnerLookup()
	_, changed = s.observeOwner(live, l.seq, l.at)
	return changed
}

// RefreshOwner looks the owner up on chain and records it (the watcher).
func (s *Store) RefreshOwner(ctx context.Context) error {
	_, _, err := s.lookupOwner(ctx)
	return err
}

// OwnerLookup marks when a lookup of the owner made elsewhere (an owner
// route's signature check) began: its answer is recorded in the order the
// lookups began, like the store's own.
type OwnerLookup struct {
	seq uint64
	at  time.Time
}

// BeginOwnerLookup is taken before such a lookup.
func (s *Store) BeginOwnerLookup() OwnerLookup {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lookupSeq++
	return OwnerLookup{seq: s.lookupSeq, at: s.now()}
}

// ObserveOwnerLookup records the owner that lookup l found, and reports
// whether that is the owner as recorded: false when a lookup begun later
// was recorded already and found someone else, so the answer confirms
// nothing and the request it came with must not be served.
func (s *Store) ObserveOwnerLookup(l OwnerLookup, owner common.Address) bool {
	recorded, _ := s.observeOwner(owner, l.seq, l.at)
	if recorded {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.owner == owner
}

// lookupOwner asks the chain for the owner and records the answer, unless
// a lookup begun later was recorded first: answers can arrive out of order,
// and an older one must not undo a newer one. recorded says whether this
// answer was the one recorded.
func (s *Store) lookupOwner(ctx context.Context) (live common.Address, recorded bool, err error) {
	l := s.BeginOwnerLookup()
	live, err = s.env.LiveOwner(ctx)
	if err != nil {
		return common.Address{}, false, err
	}
	recorded, _ = s.observeOwner(live, l.seq, l.at)
	return live, recorded, nil
}

// observeOwner records live as the owner at the time lookup seq began,
// unless a lookup begun later was recorded already.
func (s *Store) observeOwner(live common.Address, seq uint64, at time.Time) (recorded, changed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if seq < s.appliedSeq {
		return false, false
	}
	recorded = true
	s.appliedSeq = seq
	if s.owner != (common.Address{}) && live != s.owner {
		s.env.Logf("credentials: owner changed from %s to %s; every credential cleared", s.owner.Hex(), live.Hex())
		s.clearLocked()
		changed = true
	}
	s.owner, s.ownerAt = live, at
	s.auditMu.Lock()
	s.decideSeedLocked()
	s.auditMu.Unlock()
	return recorded, changed
}

// ensureOwner confirms, at most ownerFresh ago, that the owner the state
// belongs to is still the live owner. A lookup that fails refuses: nothing
// leaves sealed on an owner it could not confirm.
func (s *Store) ensureOwner(ctx context.Context) *credproxy.Error {
	s.mu.Lock()
	fresh := !s.ownerAt.IsZero() && s.now().Sub(s.ownerAt) < ownerFresh && s.now().Sub(s.ownerAt) >= 0
	s.mu.Unlock()
	if fresh {
		return nil
	}
	live, recorded, err := s.lookupOwner(ctx)
	s.mu.Lock()
	current := s.owner
	s.mu.Unlock()
	// An answer not recorded (a later lookup was) that disagrees with what
	// was recorded confirms nothing.
	if err != nil || !recorded && live != current {
		return &credproxy.Error{Status: http.StatusServiceUnavailable, Code: "owner_unknown",
			Message: "the agent's owner could not be confirmed on chain; try again"}
	}
	return nil
}

// Load verifies doc against the live owner and swaps it in. ownerEpoch,
// when non-zero, is the epoch the attestor vouches for.
func (s *Store) Load(ctx context.Context, doc Document, ownerEpoch uint64) (*Opened, error) {
	s.loadMu.Lock()
	defer s.loadMu.Unlock()
	// A new owner's set never meets the previous owner's state.
	owner, _, err := s.lookupOwner(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOwnerLookup, err)
	}
	var highest Mark
	if s.env.Persist != nil {
		if highest, err = s.env.Persist.LoadHighest(); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	if highest.Less(s.mark) {
		highest = s.mark
	}
	gen := s.gen
	s.mu.Unlock()
	o, err := Open(doc, Check{Domain: s.env.Domain, SealID: s.env.SealID, Owner: owner, AgentSeal: s.env.AgentSeal,
		AgentSealPriv: s.env.AgentSealPriv, Min: highest, OwnerEpoch: ownerEpoch})
	if err != nil {
		return nil, err
	}
	if s.env.Persist != nil && highest.Less(MarkOf(o.Set)) {
		if err := s.env.Persist.SaveHighest(MarkOf(o.Set)); err != nil {
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
	if s.gen != gen || s.owner != owner {
		return nil, errors.New("the agent's owner changed while the set loaded")
	}
	before, beforeValues := s.defs, s.values
	hashes := map[string]string{}
	for _, e := range o.Set.Entries {
		hashes[e.Name] = strings.ToLower(e.DefHash)
	}
	// A value sealed obtained (a rotation, a login) outlives a new set that
	// binds the entry to the same value or login: the owner edited
	// something else.
	for name, d := range o.Defs {
		if b := before[name]; d.Writeback && b != nil && b.Writeback && b.Binding() == d.Binding() && beforeValues[name] != nil {
			o.Values[name] = beforeValues[name]
		}
	}
	s.version, s.mark, s.defs, s.defHashes, s.values = o.Set.Version, MarkOf(o.Set), o.Defs, hashes, o.Values
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
	// A derived token was obtained under its source's definition (template,
	// hosts): it goes with it.
	for name, d := range s.derived {
		if s.defHashes[d.from] == "" || s.defHashes[d.from] != d.srcHash {
			delete(s.derived, name)
		}
	}
	s.syncRegistryLocked()
	// An entry is there for the harness once it has a value: a login entry
	// only after its login.
	for name := range s.defs {
		if s.values[name] != nil && beforeValues[name] == nil {
			s.events.add(Event{Type: "entry_added", Name: name})
		}
	}
	for name := range before {
		if beforeValues[name] != nil && s.values[name] == nil {
			s.events.add(Event{Type: "entry_removed", Name: name})
		}
	}
	// An add request is answered by the owner adding the entry (a login
	// request, by the login: FinishLogin).
	for id, p := range s.pending {
		if p.Op == "add" && p.Status == "pending" {
			if s.values[p.Name] != nil {
				p.Status = "approved"
				s.events.add(Event{Type: "pending_decided", Name: p.Name, AuthReqID: id, Status: p.Status})
			}
		}
	}
	// The public log counts them (the caller); which ones and why is the
	// owner's to read.
	for name, why := range o.Skipped {
		s.audit("load", name, "", "skipped: "+why)
	}
	return o, nil
}

// Clear drops every entry, request and approval: the owner changed.
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearLocked()
}

func (s *Store) clearLocked() {
	s.gen++
	s.retired = true
	s.version, s.mark = 0, Mark{}
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
	// The audit log is the previous owner's too.
	s.auditMu.Lock()
	s.auditLog, s.auditSign, s.auditInject = nil, nil, nil
	s.auditCounts, s.auditOpKeys = map[string]*AuditRecord{}, map[string]int{}
	s.auditMu.Unlock()
	s.addAudit(AuditRecord{Time: s.now(), Op: "clear", Result: "the owner changed: every credential and earlier record cleared"})
}

// syncRegistryLocked rebuilds the proxy's entries from defs, values and
// derived entries. Entries with no value yet (a login not done) are left
// out, and so is one the proxy cannot serve, so it never holds the rest back.
func (s *Store) syncRegistryLocked() {
	var entries []*credproxy.Entry
	for name, d := range s.defs {
		if v, ok := s.values[name]; ok && v != nil {
			e := d.Entry(v)
			if err := e.Validate(); err != nil {
				s.env.Logf("credentials: an entry the proxy cannot serve was left out (the owner's audit log names it)")
				s.auditRepeat("load", name, "", "left out: "+err.Error())
				continue
			}
			entries = append(entries, e)
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
		s.env.Logf("credentials: the proxy refused the entries (the owner's audit log says why)")
		s.auditRepeat("load", "", "", "refused by the proxy: "+err.Error())
	}
}

// HoldSystem keeps a value sealed itself supplies to the framework (its
// inference key) as an entry named "sealed:<name>": the framework gets the
// placeholder, the proxy fills the value in, and nothing reveals it. A new
// value for the same name replaces the old one. After the owner changed it
// refuses with ErrOwnerChanged: the framework must not get the value either.
func (s *Store) HoldSystem(e *credproxy.Entry) error {
	if !strings.HasPrefix(e.Name, "sealed:") {
		return fmt.Errorf("a value sealed supplies is named sealed:<name>, not %q", e.Name)
	}
	if err := e.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.retired {
		return ErrOwnerChanged
	}
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
		v, ok := s.values[name]
		if !ok {
			continue
		}
		info := EntryInfo{Name: name, Description: d.Description, Source: "owner", Use: string(useOf(d)),
			Hosts: d.Hosts, Positions: d.Positions, Signer: d.Signer, ExpiresAt: d.ExpiresAt, AllowReveal: d.AllowReveal,
			Placeholder: credproxy.Placeholder(name)}
		if v == nil {
			info.Status = "awaiting_login" // only a login entry is loaded without a value
		} else if st, ok := parseMCPState(v); ok && d.MCP != nil {
			info.LoggedInAt = st.LoggedInAt
		}
		out = append(out, info)
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
	return requestDigest(op, name, params, "")
}

// requestDigest also binds what the request is about beyond its parameters
// (for a reveal, the value), without showing it to anyone.
func requestDigest(op, name string, params map[string]string, bind string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+params[k])
	}
	msg := op + "\n" + name + "\n" + strings.Join(parts, "&")
	if bind != "" {
		msg += "\n" + bind
	}
	return crypto.Keccak256Hash([]byte(msg)).Hex()
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
// pending request and returns authorization_pending. A signing key is never
// revealed: it only signs.
func (s *Store) Reveal(ctx context.Context, name, reason string) ([]byte, *credproxy.Error) {
	if err := s.ensureOwner(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	value, def, from := s.valueLocked(name)
	if value == nil {
		return nil, &credproxy.Error{Status: http.StatusNotFound, Code: "unknown_entry", Message: "no credential named " + name}
	}
	if from == "" && useOf(def) == credproxy.UseSign {
		return nil, &credproxy.Error{Status: http.StatusForbidden, Code: "not_allowed", Message: "credential " + name + " is a signing key: it signs and is never revealed"}
	}
	if s.expired(name) {
		return nil, &credproxy.Error{Status: http.StatusGone, Code: "expired", Message: "credential " + name + " has expired"}
	}
	if def.AllowReveal {
		s.addAudit(AuditRecord{Time: s.now(), Op: "reveal", Names: []string{name}, Result: "allowed in advance", repeat: true})
		return value, nil
	}
	// The approval is for this value: a token obtained or rotated since is
	// asked for again.
	bind := crypto.Keccak256Hash([]byte("credential reveal\n"), value).Hex()
	digest := requestDigest("reveal", name, nil, bind)
	if a, ok := s.approvals[digest]; ok {
		delete(s.approvals, digest)
		if uint64(s.now().Unix()) <= a.ExpiresAt {
			s.addAudit(AuditRecord{Time: s.now(), Op: "reveal", Names: []string{name}, Result: "approved once"})
			return value, nil
		}
	}
	// What the owner is shown is about the value asked for: for a derived
	// token, where it goes and what it was obtained with.
	facts := map[string]any{"source": sourceOf(from), "from": from, "hosts": def.Hosts, "expires_at": def.ExpiresAt}
	if d, ok := s.derived[name]; ok {
		facts["hosts"], facts["expires_at"] = d.hosts, d.expiresAt
		if len(d.params) > 0 {
			facts["params"] = d.params
		}
	}
	p, perr := s.pendingForLocked("reveal", name, nil, bind, reason, facts)
	if perr != nil {
		return nil, perr
	}
	if p.Status == "denied" {
		delete(s.pending, p.AuthReqID)
		s.addAudit(AuditRecord{Time: s.now(), Op: "reveal", Names: []string{name}, Result: "refused by the owner"})
		return nil, &credproxy.Error{Status: http.StatusForbidden, Code: CodeDenied, Message: "the owner refused this request"}
	}
	return nil, &credproxy.Error{Status: http.StatusForbidden, Code: CodePending, Message: p.AuthReqID}
}

// expired: the entry's expiry (the owner's, or a derived token's) has passed.
// Filling and signing refuse it in the proxy; revealing it or using it in a
// token request must too.
func (s *Store) expired(name string) bool {
	e := s.reg.Get(name)
	return e != nil && !e.ExpiresAt.IsZero() && s.now().After(e.ExpiresAt)
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
	if len(params) > maxParams {
		return nil, &credproxy.Error{Status: http.StatusBadRequest, Code: "bad_request", Message: "too many parameters"}
	}
	for k, v := range params {
		limit := maxParam
		if k == "url" {
			limit = maxURLParam
		}
		if len(k) > 64 || utf8.RuneCountInString(v) > limit {
			return nil, &credproxy.Error{Status: http.StatusBadRequest, Code: "bad_request", Message: "parameter " + k + " is too long"}
		}
		// What the owner is shown stays text: no control characters.
		if hasControl(k) || hasControl(v) {
			return nil, &credproxy.Error{Status: http.StatusBadRequest, Code: "bad_request", Message: "parameter " + k + " holds control characters"}
		}
	}
	if u, ok := params["url"]; ok && !cleanHTTPS(u) {
		return nil, &credproxy.Error{Status: http.StatusBadRequest, Code: "bad_request", Message: "url must be a plain https URL"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// The agent's parameters stay its own (Pending.Params): facts are what
	// sealed knows, and the agent writes none of them.
	p, perr := s.pendingForLocked(op, name, params, "", reason, map[string]any{})
	if perr != nil {
		return nil, perr
	}
	if p.Status == "denied" {
		delete(s.pending, p.AuthReqID)
		s.addAudit(AuditRecord{Time: s.now(), Op: op, Names: []string{name}, Result: "refused by the owner"})
		return nil, &credproxy.Error{Status: http.StatusForbidden, Code: CodeDenied, Message: "the owner refused this request"}
	}
	cp := *p
	return &cp, nil
}

// pendingForLocked returns the open request for (op, name, params), opening
// one if there is none. Expired requests are dropped first. A refusal is
// returned once for the caller to report; an approved request is done (its
// approval used, or its entry added or logged in), so asking again opens a
// new one the owner sees. At most maxOpenRequests wait at once.
func (s *Store) pendingForLocked(op, name string, params map[string]string, bind, reason string, facts map[string]any) (*Pending, *credproxy.Error) {
	now := s.now().Unix()
	digest := requestDigest(op, name, params, bind)
	for d, a := range s.approvals {
		if a.ExpiresAt < uint64(now) {
			delete(s.approvals, d)
		}
	}
	open := 0
	var found *Pending
	for id, p := range s.pending {
		if p.ExpiresAt < now {
			delete(s.pending, id)
			continue
		}
		if p.RequestDigest == digest {
			if p.Status != "approved" {
				found = p
				continue
			}
			delete(s.pending, id)
			continue
		}
		if p.Status == "pending" {
			open++
		}
	}
	if found != nil {
		return found, nil
	}
	// sealed's own requests (a login to renew, bound "sealed") are not the
	// harness's to crowd out.
	if open >= maxOpenRequests && bind != "sealed" {
		return nil, &credproxy.Error{Status: http.StatusTooManyRequests, Code: "too_many_requests",
			Message: "too many requests are waiting for the owner; wait for a decision"}
	}
	if utf8.RuneCountInString(reason) > maxReason {
		reason = string([]rune(reason)[:maxReason])
	}
	reason = strings.Map(func(r rune) rune {
		if isControl(r) {
			return ' '
		}
		return r
	}, reason)
	p := &Pending{AuthReqID: newID(), Op: op, Name: name, Params: params, Facts: facts, Reason: reason,
		RequestDigest: digest, BootID: BootIDHash(s.env.BootID), CreatedAt: now, ExpiresAt: now + int64(pendingTTL/time.Second), Status: "pending"}
	s.pending[p.AuthReqID] = p
	s.events.add(Event{Type: "pending_opened", Name: name, AuthReqID: p.AuthReqID})
	return p, nil
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
	open := ok && p.Status == "pending" && p.ExpiresAt >= s.now().Unix()
	gen := s.gen
	s.mu.Unlock()
	if !open {
		// Decided already (a used approval must not be accepted again) or
		// gone.
		return ErrUnknownRequest
	}
	// still: the request is as it was when the decision began. Checked
	// again under the lock that records the decision.
	still := func() bool { return s.gen == gen && s.pending[authReqID] == p && p.Status == "pending" }
	switch decision {
	case "deny":
		s.mu.Lock()
		defer s.mu.Unlock()
		if !still() {
			return ErrUnknownRequest
		}
		p.Status = "denied"
		s.events.add(Event{Type: "pending_decided", Name: p.Name, AuthReqID: authReqID, Status: p.Status})
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
	if a.ExpiresAt < uint64(s.now().Unix()) || a.ExpiresAt > uint64(p.ExpiresAt) {
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
	// A new owner never decides on what the previous owner's state holds.
	owner, _, err := s.lookupOwner(ctx)
	if err != nil {
		return err
	}
	if signer != owner {
		return ErrWrongSigner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// The signer must be the owner as recorded, not only the answer of a
	// lookup another one overtook.
	if !still() || s.owner != signer {
		return ErrUnknownRequest
	}
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
	s.addAudit(AuditRecord{Time: r.Time, Op: "inject", Names: r.Names, Host: r.Host, Method: auditMethod(r.Method), Result: result})
}

// hasControl reports whether v holds a control character (C0, DEL or C1)
// or a format character (bidi overrides and the like), which could make
// what the owner reads differ from what it is.
func hasControl(v string) bool {
	for _, r := range v {
		if isControl(r) {
			return true
		}
	}
	return false
}

func isControl(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) ||
		(r != ' ' && unicode.Is(unicode.Zs, r)) // spaces other than the plain one lay text out unseen
}

// auditMethod keeps a standard HTTP method as it is; anything else the
// harness sent is recorded as OTHER, so it cannot make kinds of its own.
func auditMethod(m string) string {
	switch m {
	case "", "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE":
		return m
	}
	return "OTHER"
}
