package prime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// The Continual Harness state file — this adapter's identity anchor and the
// only place Prime Agent's self-modification becomes durable.
//
// On-disk shape (prime-agent-runtime/src/rlm/harness.py, HarnessState.save):
//
//	{
//	  "schema": 1,
//	  "entries": {
//	    "prompt":   { "<id>": { "id":…, "title":…, "path":…, "version":…, "scope":… } },
//	    "memory":   { … },
//	    "skill":    { … },   // reference.type == "python" + call contract
//	    "subagent": { … }
//	  },
//	  "refinements": [ { …event… } ]
//	}
//
// Two transformations make it chain-safe:
//
//  1. `refinements` is DROPPED. It is an append-only log of self-modification
//     events — runtime audit data, not identity — and it grows monotonically,
//     so tracking it would drift on every single refine. (Putting the
//     evolution history on chain is a deliberate feature we have not chosen;
//     it would cost one chain.Update per refine.)
//
//  2. Only `scope == "global"` entries survive. The global file should hold
//     nothing else — harness.py stamps the state's own scope onto entries it
//     loads — but filtering is cheap and keeps a hand-edited or
//     future-schema file from leaking session-local, mid-task entries onto
//     chain. Entries with no scope field are treated as global, matching
//     harness.py's own defaulting.
//
// Determinism: the framework writes with `json.dump(indent=2)` and does NOT
// sort keys, so the on-disk bytes are not canonical. Every read is re-marshaled
// through Go's encoding/json, which sorts map keys at every level; numbers are
// decoded as json.Number so an int never round-trips into 1e+06. Same
// "canonical JSON on chain, framework's own format on disk" split the hermes
// adapter uses for config.yaml.

// harnessKinds are the four entry kinds harness.py declares (_KINDS). Used
// only to emit a stable, fully-populated skeleton on restore; unknown kinds
// found on disk are preserved as-is (forward compat).
var harnessKinds = []string{"memory", "prompt", "skill", "subagent"}

// canonicalHarness is the chain wire form. Field order here IS the marshal
// order (struct fields, unlike maps, marshal in declaration order), so the
// two keys are emitted deterministically.
type canonicalHarness struct {
	Entries map[string]map[string]map[string]any `json:"entries"`
	Schema  json.Number                          `json:"schema"`
}

// rawHarness mirrors the on-disk file, keeping `refinements` as an opaque
// blob so restoreHarnessState can preserve the local log it must not track.
type rawHarness struct {
	Schema      json.Number                          `json:"schema"`
	Entries     map[string]map[string]map[string]any `json:"entries"`
	Refinements json.RawMessage                      `json:"refinements,omitempty"`
}

// decodeHarness parses harness-state bytes with numbers preserved verbatim.
func decodeHarness(raw []byte) (*rawHarness, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var st rawHarness
	if err := dec.Decode(&st); err != nil {
		return nil, fmt.Errorf("parse harness state: %w", err)
	}
	return &st, nil
}

// canonicalizeHarness reduces on-disk harness state to the canonical chain
// plaintext. Returns nil when nothing survives the filter — an agent that has
// not promoted anything to global scope yet has no durable harness identity,
// so it gets no chain entry (and matches Defaults, per FRAMEWORK_ADAPTER.md
// §3.1's absent-on-chain invariant).
func canonicalizeHarness(raw []byte) ([]byte, error) {
	st, err := decodeHarness(raw)
	if err != nil {
		return nil, err
	}

	out := canonicalHarness{
		Entries: map[string]map[string]map[string]any{},
		Schema:  st.Schema,
	}
	if out.Schema == "" {
		out.Schema = "1"
	}

	total := 0
	for kind, records := range st.Entries {
		kept := map[string]map[string]any{}
		for id, entry := range records {
			if !isGlobalEntry(entry) {
				continue
			}
			kept[id] = entry
		}
		if len(kept) == 0 {
			continue
		}
		out.Entries[kind] = kept
		total += len(kept)
	}
	if total == 0 {
		return nil, nil
	}
	b, err := json.Marshal(&out)
	if err != nil {
		return nil, fmt.Errorf("marshal harness state: %w", err)
	}
	return b, nil
}

// isGlobalEntry reports whether one harness entry belongs to the cross-session
// (durable) half. A missing or non-string scope is treated as global, matching
// harness.py, which stamps the owning state's scope onto such entries at load.
func isGlobalEntry(entry map[string]any) bool {
	scope, ok := entry["scope"]
	if !ok || scope == nil {
		return true
	}
	s, ok := scope.(string)
	if !ok {
		return true
	}
	return s == "global"
}

// evoHarnessState reads the global harness state and returns its canonical
// plaintext. A missing file — the framework has not written one yet — is "no
// content", same as an all-local state.
func (a *Adapter) evoHarnessState() ([]byte, error) {
	content, err := os.ReadFile(harnessStatePath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("prime evoHarnessState: read %s: %w", harnessStatePath(), err)
	}
	if len(bytes.TrimSpace(content)) == 0 {
		return nil, nil
	}
	out, err := canonicalizeHarness(content)
	if err != nil {
		return nil, fmt.Errorf("prime evoHarnessState: %w", err)
	}
	return out, nil
}

// restoreHarnessState lands the chain plaintext on disk, preserving the local
// `refinements` log (untracked runtime data that must survive a Restore).
//
// nil plaintext means "chain has no entry": the tracked half is cleared to an
// empty skeleton rather than the file being removed, so the framework always
// finds a well-formed state file and the absent-on-chain invariant still holds
// (evoHarnessState normalizes an entry-less state back to nil).
func (a *Adapter) restoreHarnessState(plaintext []byte) error {
	if err := os.MkdirAll(harnessStateDir(), 0o755); err != nil {
		return fmt.Errorf("prime.Restore[harness_state.json]: mkdir %s: %w", harnessStateDir(), err)
	}

	next := rawHarness{
		Schema:  "1",
		Entries: map[string]map[string]map[string]any{},
	}
	for _, kind := range harnessKinds {
		next.Entries[kind] = map[string]map[string]any{}
	}

	if len(bytes.TrimSpace(plaintext)) > 0 {
		incoming, err := decodeHarness(plaintext)
		if err != nil {
			return fmt.Errorf("prime.Restore[harness_state.json]: %w", err)
		}
		if incoming.Schema != "" {
			next.Schema = incoming.Schema
		}
		for kind, records := range incoming.Entries {
			merged := next.Entries[kind]
			if merged == nil {
				merged = map[string]map[string]any{}
			}
			for id, entry := range records {
				merged[id] = entry
			}
			next.Entries[kind] = merged
		}
	}

	// Carry the existing refinements log across untouched: it is deliberately
	// not on chain, but wiping it on every boot would destroy the local audit
	// trail of how this agent got here.
	if existing, err := os.ReadFile(harnessStatePath()); err == nil {
		if prev, perr := decodeHarness(existing); perr == nil && len(prev.Refinements) > 0 {
			next.Refinements = prev.Refinements
		}
	}

	b, err := json.Marshal(&next)
	if err != nil {
		return fmt.Errorf("prime.Restore[harness_state.json]: marshal: %w", err)
	}
	if err := os.WriteFile(harnessStatePath(), b, 0o644); err != nil {
		return fmt.Errorf("prime.Restore[harness_state.json]: write: %w", err)
	}
	return nil
}
