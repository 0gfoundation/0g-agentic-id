package proxy

// The sign socket's record (sealed/LAYERS.md §4.3), kept for an adapter that
// declares framework.SigningRules (0g-harness): every signature agentSeal
// makes through the socket, and every request a rule refused, whichever way
// the agent called it — a tool, an MCP client, a shell. The record is
// sealed's, out of the agent's reach, so the owner can see afterwards what
// the agent signed; a session log in the framework is the agent's to edit.
// The owner reads it over GET /_seal/signatures.
//
// It keeps the last signLogMax records, in memory and in a root-only state
// file written every signLogFlushInterval, so a restart keeps what was
// recorded before the last flush.

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"

	"seal-verify/internal/evmsign"
	"seal-verify/internal/framework"
	"seal-verify/internal/logger"
)

const (
	signLogMax           = 1000
	signLogStateFile     = "signatures.json"
	signLogFlushInterval = 5 * time.Second
	// signTextMax is how much of a text message a record keeps.
	signTextMax = 200
)

// SignRecord is one signature the sign socket made, or one request a rule
// refused. Which fields are set depends on Kind.
type SignRecord struct {
	Seq    uint64    `json:"seq"`
	Time   time.Time `json:"ts"`
	Kind   string    `json:"kind"`             // personal_sign | typed_data | transaction
	Result string    `json:"result"`           // signed | refused
	Reason string    `json:"reason,omitempty"` // the rule that refused it

	// personal_sign
	MsgHash string `json:"msg_hash,omitempty"`
	Length  *int   `json:"length,omitempty"` // message bytes
	Text    string `json:"text,omitempty"`   // the message's start, when it is text

	// typed_data
	Digest      string            `json:"digest,omitempty"`
	PrimaryType string            `json:"primary_type,omitempty"`
	Domain      map[string]string `json:"domain,omitempty"`

	// transaction
	TxHash   string  `json:"tx_hash,omitempty"`
	ChainID  string  `json:"chain_id,omitempty"`
	To       string  `json:"to,omitempty"`
	Create   bool    `json:"create,omitempty"` // no `to`: a contract creation
	Value    string  `json:"value,omitempty"`  // wei, decimal
	Nonce    *uint64 `json:"nonce,omitempty"`
	Selector string  `json:"selector,omitempty"` // the calldata's first four bytes
	DataLen  *int    `json:"data_len,omitempty"`
}

type signLogFile struct {
	Next    uint64       `json:"next"`
	Records []SignRecord `json:"records"`
}

type signLog struct {
	mu      sync.Mutex
	records []SignRecord
	next    uint64
	dirty   bool
	persist bool
	now     func() time.Time
}

// EnableSignLog restores the record an earlier run of sealed persisted and
// keeps persisting it. Without it the record is kept in memory only. A file
// that is there but cannot be read is left as it is, and this run keeps its
// records in memory.
func (s *Server) EnableSignLog() {
	l := &s.signLog
	b, err := framework.ReadState(signLogStateFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		logger.Logf("warn: signatures: read the record: %v; this run's signatures are kept in memory only", err)
		return
	default:
		var f signLogFile
		if err := json.Unmarshal(b, &f); err != nil {
			logger.Logf("warn: signatures: the record does not parse (%v); it is kept as it is, and this run's signatures are kept in memory only", err)
			return
		}
		l.mu.Lock()
		// Records this run made before the restore (main enables the record
		// before the socket signs anything, so normally none) are numbered
		// after the persisted ones.
		made := l.records
		l.records = append([]SignRecord{}, f.Records...)
		l.next = f.Next
		for _, r := range l.records {
			if r.Seq >= l.next {
				l.next = r.Seq + 1
			}
		}
		for _, r := range made {
			r.Seq = l.next
			l.next++
			l.records = append(l.records, r)
		}
		if len(l.records) > signLogMax {
			l.records = l.records[len(l.records)-signLogMax:]
		}
		l.mu.Unlock()
	}
	l.mu.Lock()
	l.persist = true
	l.mu.Unlock()
	go l.flushLoop()
}

func (l *signLog) add(r SignRecord) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.now == nil {
		l.now = time.Now
	}
	r.Seq = l.next
	l.next++
	r.Time = l.now().UTC()
	l.records = append(l.records, r)
	if len(l.records) > signLogMax {
		l.records = l.records[len(l.records)-signLogMax:]
	}
	l.dirty = true
}

// since returns the records numbered after `after`, oldest first; after < 0
// returns them all.
func (l *signLog) since(after int64) []SignRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []SignRecord{}
	for _, r := range l.records {
		if after < 0 || r.Seq > uint64(after) {
			out = append(out, r)
		}
	}
	return out
}

func (l *signLog) flushLoop() {
	for range time.Tick(signLogFlushInterval) {
		l.flush()
	}
}

func (l *signLog) flush() {
	l.mu.Lock()
	if !l.dirty || !l.persist {
		l.mu.Unlock()
		return
	}
	b, err := json.Marshal(signLogFile{Next: l.next, Records: l.records})
	l.dirty = false
	l.mu.Unlock()
	if err == nil {
		err = framework.WriteState(signLogStateFile, b)
	}
	if err != nil {
		logger.Logf("warn: signatures: write the record: %v", err)
		l.mu.Lock()
		l.dirty = true
		l.mu.Unlock()
	}
}

// handleSignatures serves GET /_seal/signatures?after=<seq>: the records
// numbered after seq, oldest first (all of them without `after`). Owner
// signature, tag 0GSealSignatures.
func (s *Server) handleSignatures(w http.ResponseWriter, r *http.Request) {
	if !s.appliesSigningRules() {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, _, sealID, owner, _ := s.agent.Snapshot()
	if owner == "" {
		http.Error(w, "agent not ready", http.StatusServiceUnavailable)
		return
	}
	if _, ok := s.verifyOwnerSig(w, r, "0GSealSignatures", sealID, owner, ""); !ok {
		return
	}
	after := int64(-1)
	if v := r.URL.Query().Get("after"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			http.Error(w, "after: a record number", http.StatusBadRequest)
			return
		}
		after = n
	}
	writeJSON(w, http.StatusOK, s.signLog.since(after))
}

// ── what a record holds ─────────────────────────────────────────────────────

func personalRecord(req evmsign.PersonalSignRequest, out map[string]any) SignRecord {
	msg := []byte(req.Message)
	if req.MessageHex != "" {
		msg, _ = hex.DecodeString(strings.TrimPrefix(req.MessageHex, "0x"))
	}
	n := len(msg)
	rec := SignRecord{Kind: "personal_sign", Result: "signed", Length: &n}
	rec.MsgHash, _ = out["msg_hash"].(string)
	if utf8.Valid(msg) {
		text := string(msg)
		if utf8.RuneCountInString(text) > signTextMax {
			text = string([]rune(text)[:signTextMax]) + "…"
		}
		rec.Text = text
	}
	return rec
}

func typedRecord(td apitypes.TypedData, out map[string]any) SignRecord {
	rec := SignRecord{Kind: "typed_data", Result: "signed", PrimaryType: td.PrimaryType}
	rec.Digest, _ = out["digest"].(string)
	d := map[string]string{}
	if td.Domain.Name != "" {
		d["name"] = td.Domain.Name
	}
	if td.Domain.Version != "" {
		d["version"] = td.Domain.Version
	}
	if td.Domain.ChainId != nil {
		d["chain_id"] = (*big.Int)(td.Domain.ChainId).String()
	}
	if td.Domain.VerifyingContract != "" {
		d["verifying_contract"] = td.Domain.VerifyingContract
	}
	if len(d) > 0 {
		rec.Domain = d
	}
	return rec
}

// txRecord describes a signed transaction from the transaction itself, so the
// record holds what was signed rather than how the request spelled it.
func txRecord(out map[string]any) SignRecord {
	rec := SignRecord{Kind: "transaction", Result: "signed"}
	rec.TxHash, _ = out["tx_hash"].(string)
	raw, _ := out["raw_tx"].(string)
	b, err := hex.DecodeString(strings.TrimPrefix(raw, "0x"))
	if err != nil {
		return rec
	}
	var tx types.Transaction
	if err := tx.UnmarshalBinary(b); err == nil {
		fillTx(&rec, &tx)
		rec.ChainID = tx.ChainId().String()
	}
	return rec
}

// refusedTxRecord describes a transaction a rule refused to sign. It is not
// signed, and an unsigned legacy transaction carries no chain id, so the
// chain id is the request's.
func refusedTxRecord(tx *types.Transaction, chainID, reason string) SignRecord {
	rec := SignRecord{Kind: "transaction", Result: "refused", Reason: reason}
	fillTx(&rec, tx)
	if id, ok := new(big.Int).SetString(strings.TrimSpace(chainID), 0); ok {
		rec.ChainID = id.String()
	}
	return rec
}

func fillTx(rec *SignRecord, tx *types.Transaction) {
	if to := tx.To(); to != nil {
		rec.To = to.Hex()
	} else {
		rec.Create = true
	}
	rec.Value = tx.Value().String()
	nonce := tx.Nonce()
	rec.Nonce = &nonce
	data := tx.Data()
	n := len(data)
	rec.DataLen = &n
	if n >= 4 {
		rec.Selector = "0x" + hex.EncodeToString(data[:4])
	}
}
