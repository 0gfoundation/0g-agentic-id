// Package settings is the owner's configuration channel.
//
// One document, authored by the owner, stored opaquely by attestor, applied
// by every framework adapter. attestor does not parse it — it stores bytes,
// serves bytes, and gates writes on an owner signature. All meaning lives
// here, so widening the vocabulary never touches attestor or its schema.
//
// The split that makes this work:
//
//   - Doc is what the OWNER chose. It is the only thing persisted.
//   - Resolved is Doc plus what the PLATFORM computes at Start (endpoint,
//     output budget, whether the model takes a reasoning bound). None of it
//     is persisted — a stored copy goes stale and then fights the computed
//     value, which is exactly how an 8192 max-tokens guess once got frozen
//     into an agent's config and starved every reply.
//
// Adapters receive Resolved and place it where their framework reads it.
package settings

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"seal-verify/internal/inference"
)

// Doc is the owner's settings document: the blob attestor persists.
//
// Framework is deliberately opaque. It carries that framework's own knobs,
// which differ by framework and which the platform neither parses nor
// validates nor promises to keep working across a framework upgrade. The
// platform's guarantee covers the named fields only.
type Doc struct {
	// Provider selects who serves the model. inference.ZGComputeProvider
	// means the platform supplies the endpoint; anything else is a framework
	// built-in and the framework supplies its own.
	Provider string `json:"provider,omitempty"`
	// Model is the model id, as the provider spells it.
	Model string `json:"model,omitempty"`
	// Thinking is the owner's reasoning-depth preference, one of Levels.
	Thinking string `json:"thinking,omitempty"`
	// Others is everything beyond the platform's three named settings: the
	// running framework's OWN knobs, passed through opaquely. Named "others"
	// and not "framework" because a live drill showed the obvious reading of
	// that word — choosing WHICH framework runs — is exactly what this field
	// cannot do (the framework binding is minted identity).
	Others json.RawMessage `json:"others,omitempty"`
}

// Levels is the reasoning-depth vocabulary the owner may choose from.
// inference.NormalizeEffort maps these onto what a given wire actually
// accepts, so a level that is legal here can never reach a wire that kills
// it.
var Levels = []string{"low", "high", "max"}

// Resolved is a Doc plus everything the platform computes for it. This is
// what an adapter receives; it never sees the raw blob.
type Resolved struct {
	Doc

	// Facts applies to every provider.
	Facts inference.ModelFacts
	// Endpoint is non-nil only when the platform routes this model. A
	// framework built-in leaves it nil and supplies its own wiring.
	Endpoint *inference.Endpoint
	// APIKey is the inference credential for this boot. It arrives by env,
	// is never part of Doc, and is never persisted anywhere.
	APIKey string
}

// Parse decodes a stored blob. An empty blob is a valid empty document —
// an agent that has never been configured, not an error.
func Parse(blob []byte) (Doc, error) {
	var d Doc
	if len(strings.TrimSpace(string(blob))) == 0 {
		return d, nil
	}
	if err := json.Unmarshal(blob, &d); err != nil {
		return Doc{}, fmt.Errorf("settings: parse: %w", err)
	}
	return d, nil
}

// Marshal encodes a document for storage. Deterministic: encoding/json
// sorts nothing but struct fields marshal in declaration order, and the
// opaque Framework member is passed through byte-for-byte.
func (d Doc) Marshal() ([]byte, error) { return json.Marshal(d) }

// Validate checks what the platform promises to check: the model resolves
// in the router catalog, and the level is one we offer.
//
// It is the container-side gate. The CLI runs the same check before signing
// so the owner learns immediately, but that check is advisory — a caller can
// skip the CLI, so this one decides.
//
// A model the catalog does not list is NOT rejected: the catalog covers the
// 0g router only, and a framework built-in ("anthropic/claude-…") is
// legitimately absent from it. Only a blank model is fatal, because two
// adapters hard-fail Start without a pin.
func (d Doc) Validate() error {
	if strings.TrimSpace(d.Model) == "" {
		return fmt.Errorf("settings: model is required")
	}
	if t := strings.TrimSpace(d.Thinking); t != "" {
		ok := false
		for _, l := range Levels {
			if strings.EqualFold(t, l) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("settings: thinking %q is not one of %v", d.Thinking, Levels)
		}
	}
	if len(d.Others) > 0 && !json.Valid(d.Others) {
		return fmt.Errorf("settings: others section is not valid JSON")
	}
	return nil
}

// Resolve computes everything the platform derives for this document. Call
// once per Start and once per accepted settings push; never persist the
// result.
func Resolve(ctx context.Context, d Doc, apiKey string) Resolved {
	facts, ep := inference.Resolve(ctx, d.Provider, d.Model)
	return Resolved{
		Doc:      d,
		Facts:    facts,
		Endpoint: ep,
		APIKey:   apiKey,
	}
}

// ResolveForCredential checks ownership of the key before catalog access or
// framework writes. A rejected push cannot redirect the existing credential.
func ResolveForCredential(ctx context.Context, d Doc, credential inference.Credential) (Resolved, error) {
	return ResolveForRegistry(ctx, d, credential, inference.DefaultRegistry)
}

func ResolveForRegistry(ctx context.Context, d Doc, credential inference.Credential, registry *inference.Registry) (Resolved, error) {
	if credential.Invalid {
		return Resolved{}, fmt.Errorf("INVALID_INFERENCE_CREDENTIAL: reset with a valid owner/provider-bound key")
	}
	if d.Provider == "" {
		return Resolve(ctx, d, ""), nil
	}
	boundProvider := credential.Provider
	if boundProvider == "" {
		boundProvider = inference.ZGComputeProvider
	}
	if d.Provider != boundProvider {
		return Resolved{}, fmt.Errorf("CREDENTIAL_PROVIDER_MISMATCH: key belongs to %s; reset with a key for %s", boundProvider, d.Provider)
	}
	if d.Provider != inference.ZGComputeProvider && !credential.Bound {
		return Resolved{}, fmt.Errorf("PROVIDER_BOUND_CREDENTIAL_REQUIRED: reset with a v2 key for %s", d.Provider)
	}
	if credential.RouteHash != "" {
		hash, err := registry.RouteHash(d.Provider)
		if err != nil {
			return Resolved{}, err
		}
		if hash != credential.RouteHash {
			return Resolved{}, fmt.Errorf("CREDENTIAL_ROUTE_MISMATCH: reset to authorize the new route for %s", d.Provider)
		}
	} else if registry != inference.DefaultRegistry {
		return Resolved{}, fmt.Errorf("PROVIDER_BOUND_CREDENTIAL_REQUIRED: dynamic registry requires a v3 key")
	}
	facts, endpoint, err := registry.Resolve(ctx, d.Provider, d.Model)
	if err != nil {
		return Resolved{}, err
	}
	return Resolved{Doc: d, Facts: facts, Endpoint: endpoint, APIKey: credential.APIKey}, nil
}

// Effort reports the reasoning bound to apply, and whether the platform
// knows enough to decide at all.
//
// The three outcomes are distinct and an adapter must not collapse them:
//
//	("high", true)   apply this level
//	("",     true)   CLEAR any level — the catalog says this model rejects
//	                 reasoning_effort, and sending it is a hard 400
//	("",     false)  LEAVE whatever is there alone — the catalog was
//	                 unreachable or does not list this model, so we know
//	                 nothing
//
// The third case is why this returns two values. Collapsing "unknown" into
// "clear" means a catalog outage silently strips the bound from an
// always-thinking model, and that model then reasons without end and never
// writes a reply — 23k characters over ten minutes, zero visible output,
// killed upstream. That is the exact failure this mechanism exists to
// prevent, so an outage must not be able to cause it.
//
// An owner who stated a preference gets it applied even when the catalog is
// silent: the level is written into the FRAMEWORK's own thinking knob, and
// every framework gates whether that reaches the wire on its own model
// metadata. Honouring a deliberate choice beats dropping it over an outage.
func (r Resolved) Effort() (level string, decided bool) {
	owner := inference.NormalizeEffort(r.Thinking)

	if !r.Facts.CatalogSourced {
		if owner != "" {
			return owner, true
		}
		return "", false
	}
	if !r.Facts.SupportsReasoningEffort {
		return "", true
	}
	if owner != "" {
		return owner, true
	}
	// A thinking-capable model with no owner preference still needs a bound:
	// absent the parameter, an always-thinking model reasons forever.
	return "low", true
}

// PersistableMaxTokens is the output budget an adapter may write into a
// config file, or 0 for "write nothing". Gated on CatalogSourced: a
// heuristic guess written during a catalog outage looks hand-set forever
// after and permanently starves a reasoning model's shared budget.
func (r Resolved) PersistableMaxTokens() int {
	if !r.Facts.CatalogSourced {
		return 0
	}
	return r.Facts.MaxTokens
}

// RequestOutputCeiling bounds the per-request output budget the platform asks
// frameworks to send. It is the value pi-ai sent by default before the catalog
// budget was wired through, and it covers a reasoning model's shared
// thinking+reply budget with room to spare (largest single completion measured
// on glm-5.3 at effort=max during the 2026-10 investigation: ~13.6K tokens).
const RequestOutputCeiling = 32768

// RequestMaxTokens is the output budget an adapter should configure as the
// framework's per-request max_tokens, or 0 for "configure nothing" (same
// catalog gate as PersistableMaxTokens).
//
// The catalog's max_completion_tokens is a CAPABILITY — the most one reply
// may ever be — not a value to request on every call, which is how
// frameworks send the configured budget. Where a server checks prompt +
// max_tokens against the context window, the capability can take most of
// it: the router lists deepseek-v3 at 147456 of a 163840 window, which
// leaves 16,384 tokens for the conversation; capped, 131,072 (catalog,
// 2026-10-19).
//
// Not the fix for the HTTP 400 code 400001 that long glm-5.3 conversations
// hit in 2026-10. Those requests had prompt + max_tokens at ~196,608 or
// more AND a "developer"-role system prompt; replayed with it as "system",
// the same request went through 65 times out of 65 (2026-10-16), and zg
// compute confirmed (2026-10-19) that Tencent's and 0G's self-hosted
// backends do not support the role. dsh now sends "system" (bridge.mjs).
func (r Resolved) RequestMaxTokens() int {
	mt := r.PersistableMaxTokens()
	if mt > RequestOutputCeiling {
		return RequestOutputCeiling
	}
	return mt
}
