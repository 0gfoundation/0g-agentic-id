# Data-bound reputation aggregation (design)

Status: **design / north-star**. The simple first cut (`getDataBoundScore`, snapshot
overlap) ships in the SDK today; the full model below is the target for the
event-indexer phase. On-chain `getSummary` is **not** changed by any of this — it
stays the ERC-8004 baseline.

## Problem

On-chain `getSummary` is **id-bound**: it lumps all of an agent's feedback together
regardless of what data the agent was running when each score was earned. But an
agent can `Update` its iData over its life, so old scores were earned under a
different state. Two failures follow:

- **Stale glory** — an agent rated highly under data `abc`, then swapped to `xyz`,
  still reads highly.
- **Cold start after a change** — version `xyz` has no ratings yet: is its score
  `0` (reset), `90` (inherit blindly), or something in between?

We want reputation that reflects the agent **as it is now**, degrades **gracefully**
across routine data changes (not a cliff), and describes the "changed, not yet
re-rated" state honestly.

## Principles

1. **Chain as database, aggregate off-chain.** Feedback + serve-data + iData-update
   history are all on chain (state + events). Rich aggregation is computed off-chain
   (SDK / indexer); it's zero-gas, unlimited scale, and freely iterable. On-chain
   aggregation is only warranted when another contract must consume the score
   trustlessly — not our case today.
2. **Don't touch `getSummary`.** It's the ERC-8004 read baseline; ecosystem tools
   depend on it. This model is additive.
3. **General model, simple defaults.** The model is fully parameterized, but its
   default parameters (all weights equal) collapse it to a plain average. Complexity
   is opt-in.

## The model

Reputation is a **belief**, not a scalar: a state `{ mean, strength }` where `mean`
is the estimated score and `strength` is confidence (an effective review count /
pseudo-count). This is what lets the cold-start case be expressed honestly.

Two orthogonal layers, driven by two independent weight vectors — matching the two
sides of the protocol (reviewer-side vs owner-side; note **`tag` ≠ `role`**, see
Attribution below):

### Layer 1 — score (tag-weighted)

Per data-version, combine the review values, optionally weighting reviewer-chosen
tag dimensions:

```
obs = Σ_t  w_tag[t] · avg_t  /  Σ_t w_tag[t]      # avg_t = mean of values tagged t
n   = number of non-revoked reviews on that version
```

`w_tag` is the evaluator's "what do I care about" (quality vs latency vs …).
Uniform `w_tag` (or no tag split) → `obs` = plain mean of all values.

### Layer 2 — τ, the transition carry (role-weighted)

On a data-version transition `v_{k-1} → v_k`, τ ∈ [0,1] is how much confidence
survives the change:

```
τ_k = Σ_r  w_role[r] · same_r  /  Σ_r w_role[r]   # same_r = 1 if role r's dataHash is unchanged, else 0
```

`w_role` is the owner/protocol "which data matters most" (a persona change should
erode more than a knowledge tweak). Uniform `w_role` → τ = fraction of roles
unchanged. No role split → τ = fraction of dataHashes unchanged (plain overlap).
`τ ≡ 1` → ignore data changes entirely → plain running average (= `getSummary`).

### Recursion — Bayesian filter over the version chain

Order the agent's data versions by time `v_1 … v_N` (`v_N` = current). Start from a
weak **global prior** `G = { mean: g0, strength: κ0 }` (e.g. `g0` = network average,
`κ0` small). Then, per version:

```
prior_k.mean     = τ_k · post_{k-1}.mean     + (1 − τ_k) · g0     # ← τ pulls the mean toward NEUTRAL, not stale
prior_k.strength = τ_k · post_{k-1}.strength + (1 − τ_k) · κ0
post_k.mean      = (prior_k.strength · prior_k.mean + n_k · obs_k) / (prior_k.strength + n_k)
post_k.strength  =  prior_k.strength + n_k
```

Output at the current version: `{ score: post_N.mean, confidence: post_N.strength }`
(plus `provisional = confidence < threshold`).

The key correctness point: **τ blends toward the global prior, it does not merely
decay strength.** As τ→0 (a full swap), the prior collapses to the neutral global
prior — so "changed, no new reviews" reads as *neutral, low-confidence*, never
*stale-high-score, zero-confidence*. As τ→1 (tiny change), the prior is the previous
posterior unchanged.

### Worked example (the "90 → xyz" case)

`abc` rated 90 over 10 reviews → `{mean:90, strength:10}`. Transition `abc→xyz`,
`τ=0.2`, global `g0=50, κ0=1`:

```
prior(xyz).mean     = 0.2·90 + 0.8·50 = 58
prior(xyz).strength = 0.2·10 + 0.8·1  = 2.8
```

- **No reviews yet** → score ≈ **58, confidence ≈ 2.8, provisional** — i.e. "pulled
  from a strong past but discounted toward neutral; unproven."
- **After 5 reviews averaging 70**:
  `mean = (2.8·58 + 5·70) / (2.8 + 5) = (162.4 + 350) / 7.8 ≈ 65.7`, confidence 7.8 —
  converging toward observed as evidence accumulates.

### Simple-default collapse

Set `w_tag` uniform, `w_role` uniform (or no role split), `κ0` ≈ 0, and either keep
τ = overlap or fix τ ≡ 1: the whole thing degrades to a plain average of the values
(τ ≡ 1 → exactly `getSummary`; τ = overlap → the snapshot-overlap first cut).
Simple is the default; per-tag / per-role weighting is opt-in.

## Data sources

- **Version chain**: reconstruct from the AgenticID contract's iData `Update` events
  (each update = a new version + block time); the current version is
  `intelligentDatasOf(agentId)`.
- **Review → version**: attach each feedback to the version live at its `giveFeedback`
  block time (from `NewFeedback` / `FeedbackWithProof` events).
- **Per-role dataHashes**: `intelligentDatasOf` gives `(role=dataDescription, dataHash)`
  for the current version; historical role↔hash mapping comes from the update events.
- **Serve-data per review**: `getServeData(agentId, client, idx)` or the
  `FeedbackWithProof(…, dataHashes, frameworkHash)` event.

## Attribution limits (important)

- **`tag` ≠ `role`.** `tag1/tag2` are reviewer-chosen labels on a *feedback*
  (reputation side); `role`/`dataDescription` is an owner-chosen label on an *iData*
  entry (identity side). There is no built-in mapping between them.
- **The proof records *all* data at serve time, not "which data this task used."**
  So we cannot attribute a review to a specific data dimension from on-chain data.
- Consequence: **τ is necessarily global-per-transition** — it decays every review's
  confidence equally, regardless of what each review was about. Per-review /
  per-dimension attribution would require an added convention (tags named after
  roles, or the sealed proof recording the data actually used).

## Open questions before implementing

1. **Canonical vs personalized.** Are the parameters (`w_tag`, `w_role`, `τ_min`,
   `g0`, `κ0`) fixed by the protocol (one canonical, harder-to-game score) or supplied
   by the consumer (a personalized lens, so every reader gets a different number)?
   Owner-set `w_role` is gameable and must be treated carefully.
2. **Value scale.** ERC-8004 does not enforce a rating scale; averaging assumes a
   shared one. May need per-tag scale normalization.
3. **Time decay.** Optionally age `strength` over wall-clock time (orthogonal to the
   data-change decay).

## Phasing

- **v1 (shipped)**: `getDataBoundScore` — snapshot overlap vs current iData, single
  weighted average + `freshness`. Cheap read loop, no version chain. Good enough at
  low review volume.
- **v2 (indexer)**: the Bayesian version-chain model above, once there's an event
  indexer and enough review volume to justify it. Reduces to v1/`getSummary` under
  simple defaults, so v2 is a strict generalization.
