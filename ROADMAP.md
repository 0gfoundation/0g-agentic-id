# AgenticID Roadmap — H2 2026 (~6 months)

## Strategic direction

Three pillars, in order of construction:

1. **Consolidate the infrastructure** — keys, at-rest storage, protocol completion (transfer/clone/reputation), reputation, observability.
2. **Reduce centralization** — convert single points (the KMS root, the attestor) into distributed, no-single-controller systems; make agent behavior auditable.
3. **Enable open participation** — third parties operate nodes; developers and the community build on and extend the platform.

> Sound before distributed; distributed before opened.

| Pillar | Items |
|--------|-------|
| Consolidate | S1/S2/S3 KMS · S12 FDE · S6 protocol completion (transfer/clone/reputation) · S7 reputation · S5 monitoring |
| Decentralize | S1/S2/S3 KMS · S4 multi-node attestor · S10 on-chain instructions (auditable framework, integrated via S9) |
| Open up | S8 SDK · S9 framework integration path · S4 third-party nodes · S11 multi-agent demo |

## Sequencing rule

**Irreversibility first.** A few changes are cheap now but very costly later — they touch the derivation formula, contracts, or public interfaces. They are tagged **🔒 lock-now** and must be forward-compatible (the lesson from Lit's contract-layer churn). Everything else is **additive** and follows once those are fixed.

Lock-now set: **S1** linear KDF · **S2** DKG decision · **S8** SDK interface · **S9** framework integration contract.

---

## Problems

**P1 — The KMS root has a "full-reconstruction" single point.** Current state = **3-node VSS + non-linear KDF**: the master is split into 3 shares, but a full master still appears in two places — at *use*: HKDF is non-linear, so deriving a child key recombines the shares into a full master (at the KMS combine point + in attestor memory via `crypto.rs:70`); at *generation*: VSS means a dealer generated and split the full master at genesis, so it existed in full at that instant.

**P2 — The attestor service is strictly single-node; one party can deny service.** The api/worker/indexer processes coordinate only through a single Postgres; there is no inter-node consensus/federation, and third parties cannot run a node.

**P3 — Almost no observability.** Only a `/health` that returns `"ok"`; no `/metrics`, no structured health checks, no per-node monitoring — a node federation cannot be operated.

**P4 — Off-chain protocol flows are not yet wired (seal-bound transfer/clone + reputation submission).** A seal-bound agent transfers via ERC-721 `transferFrom` (on-chain owner change), but the running agent caches the owner at boot and still recognizes the old owner after a transfer — the gap is the off-chain owner-handoff. For clone, `iCloneFrom` reverts for seal-bound (an operating entity can't be duplicated on-chain), so it needs an attestor-side copy flow (design). The end-to-end reputation-submission flow (serveProof / feedback) is also not wired through attestor/SDK.

**P5 — No rule for inheriting reputation when the dataHash changes.** Reputation is already anchored to agentId (that part is done); but under one agentId, credit attaches to discrete dataHashes. When the dataHash changes (metadata/data update), there is no rule for how reputation accrued under the old dataHash carries to the new one — the brute-force baseline is a simple average.

**P6 — No SDK.** External integrators have to consume the raw contract ABI + the attestor's bare routes — high integration cost, and any interface change breaks every integrator.

**P7 — No complete way to integrate orchestration frameworks.** The integration layer has a basis (`framework.go` has an interface + registry), but only openclaw is wired; the integration contract is incomplete and undocumented — third parties/community cannot plug in an arbitrary orchestration framework by following it.

**P8 — Agent instructions go through a private chat; behavior is not auditable.** openclaw is fully private chat; before moving toward autonomy, a transparent channel is missing.

**P9 — No end-to-end external proof point.** There is no multi-agent collaboration demo, so P6/P7 lack a forcing function from real demand.

**P10 — TEE components' at-rest storage is unencrypted.** No LUKS/dm-crypt/FDE anywhere; on-disk state in the AgenticID flow is in the clear (sensitive data is encrypted by hand).

---

## Solutions (numbered in order of appearance)

> 🔒 = lock-now (touches the derivation formula / contracts / interfaces; catastrophic to change late; must be forward-compatible)

### S1 — Linear KDF · 🔒 · M1 · solves P1 (use-time reconstruction)
Replace the HKDF in `attestor/crates/shared/src/crypto.rs::derive_agent_seal` with `agentSeal_priv = master + H("agentSeal"‖sealId) mod n` (secp256k1). Shares derive locally and aggregate, so the master need not reconstruct at derivation time. This is the foundation of the whole block — S2/S3 are meaningless without it.
- [ ] Spec the derivation; deterministic + threshold-compatible; keep `AgentSealKeyPair` shape
- [ ] Replace the HKDF
- [ ] Known-answer + cross-process determinism tests

### S2 — DKG-at-genesis decision · 🔒 (decision) · M1 · solves P1 (generation-time reconstruction)
Current state is VSS (a dealer saw the full master at genesis). Decide whether to migrate to DKG — "the master never existed in full anywhere" vs staying on VSS. Migrating to DKG is a one-time breaking re-key, so decide early; only meaningful in combination with S1.
- [ ] Decision memo + recommendation (+ genesis-ceremony outline if DKG)

### S3 — Move existing shares to no-reconstruction derivation + resharing · additive (depends on S1) · M5 · solves P1 (implementation)
Today there are already 3 nodes, each holding one share of the master (share storage is done). What's missing: HKDF is non-linear, so derivation has to recombine the shares into a full master (the combine point = P1's remaining single point). S3 lands S1's linear derivation across those 3 nodes as a **distributed derivation** — each node computes a child-key share locally from its own share, the combiner only sees the aggregate, and the master never reconstructs on any node nor leaves to the attestor in full form.
- [ ] Implement a distributed derivation protocol on the existing 3 nodes (each emits a share, combiner aggregates; master never reconstructs)
- [ ] Proactive resharing to refresh shares
- [ ] Genesis per S2 (if DKG, regenerate the shares so the master never existed in full)
- [ ] (optional, later) back the shares with hardware (HSM, etc.)

### S4 — Attestor node operation · additive · M6 · solves P2
On-chain authorization is already a set (`AgenticID.sol:110` `trustedAttestors` + governance add/remove), so no contract change is needed.
- [ ] Attestor node binary for third parties
- [ ] Incentive design + tapp-based deployment guide

### S5 — Monitoring · additive · M4 · solves P3
- [ ] `/metrics` + health checks for attestor / agent-TEE / indexer
- [ ] Instrument + expose; dashboards + alerts; per-node monitoring for the federation

### S6 — Protocol completion: seal-bound transfer/clone + reputation (submission + simple-average baseline) · additive · M2 · solves P4 + P5 (baseline)
- [ ] seal-bound transfer/clone: design & development
- [ ] reputation submission: end-to-end flow for agent-produced serveProof + client feedback (through attestor/SDK)
- [ ] reputation simple-average aggregation (query-time, off-chain, no contract change) — the P5 baseline
- [ ] End-to-end tests

### S7 — Reputation inheritance across dataHash changes (advanced) · research · M5 · solves P5
The simple-average baseline is done in S6; this is the advanced step — under one agentId, how to better carry reputation across a dataHash change. **Use only framework-agnostic signals** (a change happened + numeric scores); do not parse the per-framework metadata semantics.
- [ ] framework-agnostic advanced: time decay (recent weighted higher); change-boundary discount (apply a decay factor to prior reputation each time the dataHash changes — needs only "it changed", not "what changed")
- [ ] Query API
- *Capability-level, dimension-aware inheritance needs a cross-framework capability schema (metadata differs per framework) → out of this general algorithm; revisit once the S9 framework interface matures.*

### S8 — SDK · interface v1 🔒 + core · M3 · solves P6
- [ ] API design (register(deploy) / query / transfer / clone / reputation) + versioning policy · 🔒
- [ ] Implement core (contract reads + attestor API client); docs, examples, publish

### S9 — Complete orchestration-framework integration path · contract v1 🔒 (M3) + landing (M6) · solves P7
The goal is a complete integration path that lets *any* orchestration framework plug in by following it — not merely adding one more framework.
- [ ] Tidy up and finalize the current framework integration-layer interface (roles / restore / evolution / start, etc.), with openclaw as the reference impl · 🔒
- [ ] Integration docs (interface spec + integration steps + reference impl)
- [ ] Validate by taking one new framework (opencode/hermes) all the way through the path

### S10 — On-chain instructions (auditable framework) · research · M6 · solves P8
- [ ] Design memo: commitment + optional reveal, or verifiable instruction log (content in TEE, on-chain anchor)
- [ ] Such an instruction-auditing orchestration framework plugs in via the S9 integration path; feeds S7 (verifiable behavior → trustworthy reputation)

### S11 — Multi-agent demonstration · additive · v1 M5, final M6 · solves P9
- [ ] Choose scenario (multiple agents collaborating with verifiable identity, transfer, reputation)
- [ ] Build agents via SDK + a framework; demonstrate the full lifecycle
- [ ] Write-up + recorded demo

### S12 — FDE · additive · M4 · solves P10
Depends on the KMS direction (FDE keys come from the KMS).
- [ ] Design FDE key provisioning from KMS (per-component disk key sealed to TEE)
- [ ] Integrate LUKS/dm-crypt into agent-TEE + attestor storage; reboot/reseal tests

---

## Timeline

One focus per month; the trailing parenthesis is the solution.

**M1 · Lock the hardest-to-change foundations**
- Switch key derivation from HKDF to a linear formula + tests (S1)
- Decide whether KMS genesis stays VSS or migrates to DKG (S2)

**M2 · Complete the core**
- Fill the seal-bound transfer/clone + reputation-submission off-chain flows, add the reputation simple-average baseline, and get them working end-to-end (S6)

**M3 · Lock the public interfaces; start the SDK**
- Define the SDK: API shape (register(deploy) / query / transfer / clone / reputation) → skeleton → core + docs (S8)
- Define the integration contract that lets any orchestration framework plug in (S9)

**M4 · Hardening · observability**
- Add monitoring: /metrics, health checks, per-node (S5)
- Full-disk encryption / FDE (S12)

**M5 · Finish decentralizing · reputation · validate demand**
- Convert the existing 3 nodes to no-reconstruction distributed derivation + resharing (S3)
- Reputation inheritance, advanced: time decay / version-aware (the simple-average baseline shipped in M2) (S7)
- Ship the first multi-agent demo (S11)

**M6 · Open up + research + attestor decentralization**
- Write a third-party-runnable attestor node binary + deploy guide (S4)
- Land the framework integration path; validate it by wiring one new framework (opencode/hermes) (S9)
- Final demo (S11)
- Design research for on-chain instructions / auditable framework (S10)

---

## Notes & decisions

- **P1's two reconstruction points; S1/S2 each fix one.** S1 (linear KDF) fixes the *use-time* reconstruction, S2 (DKG) the *generation-time* one. Three relations: (1) **DKG only works with S1** — DKG alone but still on a non-linear KDF means every derivation reassembles the full master anyway, so the use-time reconstruction stays and DKG buys nothing; (2) **do S1 first** — small and low-risk, and it makes "single→threshold" an additive change (moving to threshold later won't re-key every agent); (3) **decide S2 early** — "master never appeared in full anywhere" can only be achieved by DKG at genesis; today is VSS (a dealer saw it once), and migrating to DKG later is a one-time breaking re-key, so the earlier this is decided the cheaper.
- **KMS and attestor are two independent layers**, coupled only at the interface (N attestors sharpen "where does the master live" → argues for threshold KMS, not a merger).
- **Lit is deferred** as the KMS root: its protocol layer churns too fast (mainnet generations sunset within months; keys/PKPs do not migrate). Reconsider once a Lit generation stabilizes.
- **S11 (demo)** checks whether the SDK / framework integration (S8/S9) is good enough; it follows them (M5). **S5 (monitoring)** comes first (M4), paving the way for the later node federation.
- **Attestor decentralization (S4) comes last (M6)**: it is the most uncertain (incentives / third-party operation), and KMS decentralization (S3) has already removed the core "where does the master live" single point — so the service layer can be distributed last, and may slip into the next period if time runs short.

## Scope (6-month constraints)

- **Committed:** lock-now (S1 · S2 · S8 interface · S9 framework integration contract) · S8 SDK core · S6 protocol completion (seal-bound transfer/clone + reputation submission, incl. simple-average baseline) · S3 distributed derivation (3-node VSS already in place + depends on S1; contained change) · S11 demo · S12 FDE · S5 monitoring · S4 attestor node prototype (M6, last; may slip into the next period).
- **Designed now, implementation may extend into the next period:** S7 advanced inheritance (time decay / version-aware) · S4 node federation (incentives + third-party operation — the most uncertain part of attestor decentralization) · S3 proactive-resharing ops hardening (+ the S2 re-key, if selected) · S9 framework integration landing · S10 on-chain instructions.
