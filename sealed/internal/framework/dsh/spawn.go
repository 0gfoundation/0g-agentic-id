package dsh

import (
	"context"
	"fmt"
	"time"

	"seal-verify/internal/framework"
)

// NOT IMPLEMENTED YET — see the package doc in dsh.go.
//
// This file is the process half of the adapter: composing a DSH plugin tree
// (llm-pi-ai routed at 0G, no session-persistence plugin, sandbox/approval
// configured so doctrine — not a permission dialog — is what constrains the
// agent, per the FRAMEWORK_ADAPTER.md §11 step 10 audit this port already
// did on DSH's shipped web app), materializing the sealed-owned HTTP bridge
// that embeds that tree via `@deepseek-ai/dsh-app-boot`'s `boot()`, injecting
// the platform doc into ctx.systemPrompt after boot settles (the
// authoritative channel — FRAMEWORK_ADAPTER.md §13 point 2's twice-learned
// rule), and exposing exactly one OpenAI-shaped chat endpoint.
//
// Every other bundled adapter's process half was finished against a live
// sandbox: the prime-agent port's own report documents a real mistake
// (installing the npm-only half of a two-channel distribution) that only a
// live container build caught, plus two items explicitly left as "verify on
// first live boot". This port has not had that loop yet, so rather than ship
// an unexecuted ~300-line bridge as if it worked, these methods fail loud.
// The state half above (Roles/Defaults/Restore/EvolutionFor/FrameworkFacts)
// needs no such loop — it is a pure function of disk state, fully covered by
// the conformance suite, and safe to merge on its own
// (FRAMEWORK_ADAPTER.md §13 point 5).
func (a *Adapter) Start(ctx context.Context, rt framework.RuntimeContext) (framework.StartResult, error) {
	return framework.StartResult{}, fmt.Errorf("dsh.Start: not implemented — state half only, see the package doc in dsh.go")
}

func (a *Adapter) Stop(ctx context.Context, gracefulTimeout time.Duration) error {
	return fmt.Errorf("dsh.Stop: not implemented")
}

func (a *Adapter) Liveness(ctx context.Context) error {
	return fmt.Errorf("dsh.Liveness: not implemented")
}

func (a *Adapter) Readiness(ctx context.Context) error {
	return fmt.Errorf("dsh.Readiness: not implemented")
}

func (a *Adapter) AuthResponse(ctx context.Context) (any, error) {
	return nil, fmt.Errorf("dsh.AuthResponse: not implemented")
}

// MonitorExit satisfies manager.Adapter. A no-op stub: with Start always
// failing, the manager never reaches a state where it needs an exit signal
// from this adapter.
func (a *Adapter) MonitorExit(onExit func(err error)) {}
