# AgenticID Roadmap — H2 2026

## Objective

Turn AgenticID from a single-operator internal system into a **multi-party, auditable, extensible platform** — without compromising the security baseline.

Three phases, built sequentially:

1. **Consolidate** (M1–M4) — fix the core security gaps, complete the protocol, lock public interfaces, add observability.
2. **Decentralize** (M5) — remove the remaining single point of trust in key derivation.
3. **Open up** (M6) — enable third-party node operation, framework integration, and auditable agent behavior.

> **Sequencing principle:** decisions that are expensive to reverse (key formula, SDK interface, contract design) are locked first. Everything else is additive.

---

## Current Gaps (why we need this roadmap)

| Area | Risk | Impact |
|------|------|--------|
| **Key security** | Root key reassembles in full at each use; also existed in full at genesis | One compromise → all agent identities exposed |
| **Service availability** | Attestor is single-node | One outage → all provisioning halts |
| **Protocol completeness** | Transfer, clone, reputation flows are half-wired (on-chain yes, off-chain no) | Agent lifecycle management is incomplete — cannot trade, fork, or score agents |
| **Observability** | No metrics, no alerts, no dashboards | Can't operate a federation; problems found by humans, not systems |
| **Disk security** | No full-disk encryption; sensitive data must be manually encrypted per use | Adds dev overhead, easy to miss, not composable with automated tooling |
| **Developer access** | No SDK; only openclaw integrated; no framework docs | High barrier to entry; every interface change breaks integrators |
| **Reputation continuity** | No rule for carrying reputation across data updates | Agents lose credibility on every metadata change |
| **Transparency** | Agent instructions are private | Can't audit what an agent was told to do |
| **Proof point** | No end-to-end multi-agent demo | Can't validate SDK + integration path with real demand |

---

## Milestones

| Milestone | Theme | Deliverables | Status |
|-----------|-------|-------------|--------|
| **M1** | Lock foundations | Linear KDF (S1) · DKG decision memo (S2) | Planned |
| **M2** | Complete the core | Seal-bound transfer/clone + reputation submission + simple-average baseline (S6) | Planned |
| **M3** | Lock public interfaces | SDK interface v1 + core (S8) · Framework integration contract v1 (S9) | Planned |
| **M4** | Harden | Monitoring (S5) · Full-disk encryption (S12) | Planned |
| **M5** | Decentralize + validate | Distributed derivation on 3 nodes (S3) · Reputation advanced (S7) · First multi-agent demo (S11) | Planned |
| **M6** | Open up + research | Third-party attestor node (S4) · Framework integration landing (S9) · Auditable instructions design (S10) · Final demo (S11) | Planned |

---

## Strategic Choices

**Security foundations before features.** The key derivation formula underpins everything — every agent identity, every transfer, every reputation event. We fix it first (M1) because getting it wrong makes every downstream investment unreliable. The fix itself is small and low-risk; the cost of *not* fixing it is that all later security work is built on sand.

**Defer what's uncertain.** Third-party attestor nodes (S4) involve questions we can't answer yet — incentive design, operator economics, governance. We park it last (M6) and let it slip if needed. The core trust risk (key derivation) is already resolved by M5, so the service layer being single-node in the interim is an availability concern, not a trust concern.

**Lock public interfaces before opening up.** SDK (S8) and framework integration (S9) are commitments to external developers. Once published, changing them breaks every integrator. We lock their shape in M3, before anyone depends on them, so that later changes are additive (new methods, new frameworks) rather than breaking. Reference lesson: Lit's protocol churn made keys non-migratable — we avoid that.

**KMS and attestor are separate concerns.** Decentralizing the key infrastructure (S3, M5) does not require decentralizing the attestor service (S4, M6). They are on independent tracks — one is about "where does the master key live", the other about "who operates the provisioning service."

---

## Scope

**Committed (6 months):** S1 · S2 · S6 · S8 · S9 (contract v1) · S5 · S12 · S3 · S11 · S4 prototype

**Designed now, may extend beyond H2:** S7 advanced reputation · S4 node federation (incentives + operation) · S3 resharing ops hardening · S9 integration landing · S10 auditable instructions
