# Sealed Bootstrap Framework Redesign

This document describes the on-chain data model, encryption layout, lifecycle
flows, and adapter contract for sealed agents running on the 0G AgenticID
substrate. It supersedes any prior version of this file.

The design is intentionally framework-agnostic. openclaw is the first concrete
adapter; the same protocol must be reusable for future frameworks (eliza,
custom builds, etc.) without protocol-level changes.


## 1. Goals

1. Preserve the existing one-shot bootstrap behavior (attestation self-check,
   provision from attestor, fetch encrypted iData from chain, decrypt, hand to
   agent runtime).
2. Add a long-running control plane:
   - HTTP proxy with serve-proof signing (already in place, retained).
   - Agent process supervisor with restart and threshold semantics.
   - Self-evaluation of evolution data and autonomous upload back to chain.
   - Hot-reload semantics where supported by the framework.
3. Treat the agent's defining data as a tradeable asset: only data that
   defines agent behavior AND can be transferred between owners belongs on
   chain. Everything else stays off-chain.


## 2. Module Layout

```
test/sealed/
  cmd/bootstrap/main.go        # entry point, wires everything together
  internal/
    attest/        # phase 0 self-check (SEAL_KEY <-> attestation)
    provision/    # phase 1 attestor handshake (ECIES decrypt agent_seal_priv)
    chain/        # AgenticID contract reads (intelligentDatasOf, ITransferred event scan)
    dataplane/    # 0g-storage upload/download + AES-GCM-256 + ECIES helpers
    framework/    # adapter interface + registration
    framework/openclaw/       # openclaw adapter implementation
    manager/      # agent process supervisor (start/stop/restart/health)
    proxy/        # HTTP server, reverse proxy, serve-proof signing
    state/        # state machine + agentState (single source of truth)
    evaluator/    # per-dimension evolution-trigger strategies
    uploader/     # encrypt + 0g-storage upload + chain write + sealedKey emit
    report/       # status reporter to attestor
    config/       # env-driven config + secret lifecycle
```


## 3. Data Model

### 3.1 Dimensions

Every agent's on-chain data is decomposed into a fixed set of dimensions. The
first is protocol-level; the rest are framework-defined by the adapter.

| Position | Label | Owner | Contents (openclaw) |
| --- | --- | --- | --- |
| 0 | `framework` | protocol | which framework + runtime version + protocol schema version |
| 1 | `persona` | owner | model + agent-wide system prompt + memory engine choice + provider auth profile |
| 2 | `knowledge` | agent | MEMORY.md + DREAMS.md (consolidated long-term memory) |
| 3 | `skills` | owner | installed plugins manifest (name + version + per-plugin config) |
| 4 | `ops` | owner | channels (configs + system prompts + access policy, NO credentials) + MCP servers + hooks + cron + browser |

Other frameworks may define a different set of dimensions; the protocol does
not enforce names other than the reserved label `framework`.

### 3.2 What is NOT on chain (and why)

| State | Why excluded |
| --- | --- |
| Channel auth credentials (`agents/<id>/auth-profiles.json`) | Security risk; not a tradable asset; obtained per-deployment via dashboard OAuth. |
| Daily memory logs (`workspace/memory/YYYY-MM-DD.md`) | Pre-consolidation flow; ephemeral; only consolidated MEMORY.md and DREAMS.md are assets. |
| Conversation / session history | Privacy-sensitive; ephemeral; only what the agent consolidates into MEMORY.md is preserved. |
| Plugin source code | Available from npm registry; the manifest names the plugin, runtime re-installs. |
| `gateway.auth.token` | Regenerated per container boot. |
| `gateway.controlUi.*`, logging, OTel, cache | Runtime configuration with no behavioral semantics. |

These items are either supplied per-deployment by the owner via dashboard, or
ephemerally regenerated, or fetched from public sources (npm). Excluding them
from chain is deliberate.


## 4. iData Schema

Every iData entry has the same shape. There is no inline mode and no special
case for defaults. Defaults are real (small) encrypted blobs in storage with
real sealedKeys, so iTransferFrom re-keying applies uniformly.

```
IntelligentData {
  dataHash:        bytes32         // 0g-storage root hash; never zero
  dataDescription: string          // role label: "framework" or adapter-defined dim name
}

// In ITransferred event:
SealedKeyEntry {
  dataHash:    bytes32             // matches IntelligentData.dataHash
  sealedKey:   bytes               // ECIES.encrypt(agent_seal_pubkey, data_key); never empty
}
```

### 4.1 Label conventions

- Lowercase ASCII, no spaces.
- `framework` is the protocol-reserved label and must appear exactly once.
- All other labels are adapter-defined (returned by `Framework.Dimensions()`).
- Adapters MUST NOT use `framework` as a dimension name.

### 4.2 What's in each plaintext

The bytes that get encrypted vary per label.

```
"framework" plaintext:
  JSON: {"name": "<framework name>", "version": "<runtime version>", "schema_version": 1}
  Small (~50 bytes). schema_version is the protocol schema version, not the
  framework runtime version.

"persona" plaintext (openclaw):
  tar.gz containing:
    + openclaw-config-persona.json   (cherry-picked subset of openclaw.json)
    + PERSONA.md                     (agent-wide system prompt; our convention)

"knowledge" plaintext (openclaw):
  tar.gz containing:
    + workspace/MEMORY.md
    + workspace/DREAMS.md

"skills" plaintext (openclaw):
  JSON manifest: {"plugins": [{"name", "version", "config"}, ...]}

"ops" plaintext (openclaw):
  tar.gz containing:
    + channels.json   (channel configs without credentials)
    + mcp.json        (MCP server endpoints + options)
    + hooks.json      (webhook configs)
    + cron.json       (scheduled tasks)
    + browser.json    (CDP profile choice)
```

Adapters define the exact format for each dimension. Reader (sandbox bootstrap)
hands the decrypted bytes to `adapter.Restore(label, bytes)` and trusts the
adapter to interpret them.


## 5. Encryption Layout

For each dimension entry:

```
plaintext_bytes  = (per-dimension content as defined above)
data_key         = random 32 bytes
nonce            = random 12 bytes
ciphertext       = nonce || AES-GCM-256-encrypt(plaintext_bytes, data_key, nonce) || auth_tag(16)
storage_root     = 0g-storage.upload(ciphertext)
sealed_key       = ECIES.encrypt(agent_seal_pubkey, data_key)
```

The on-chain entry is `IntelligentData{dataHash: storage_root, dataDescription: label}`.
The corresponding sealedKey lives in the latest `ITransferred` event for the
tokenId (paired by index with the IntelligentData array).

Defaults follow the same procedure: the adapter produces a small "default"
plaintext (e.g. an empty MEMORY.md inside a tar.gz), it gets encrypted and
uploaded normally. There is no sentinel mechanism.


## 6. Lifecycle Flows

### 6.1 Mint

Owner submits a form to the attestor (model, system_prompt, plugin choices,
etc.). Attestor:

```
adapter = framework.Get("openclaw")

# Compose plaintext for each dimension. Empty fields fall through to
# adapter.Defaults() values per dimension.
fw_plain      = json.marshal({"name": "openclaw", "version": "2026.5.6", "schema_version": 1})
persona_plain = adapter.BuildInitial("persona",   merge(adapter.Defaults().persona,   form.persona))
know_plain    = adapter.BuildInitial("knowledge", adapter.Defaults().knowledge)   # owner cannot pre-fill
skills_plain  = adapter.BuildInitial("skills",    merge(adapter.Defaults().skills,  form.skills))
ops_plain     = adapter.BuildInitial("ops",       merge(adapter.Defaults().ops,     form.ops))

entries = []; sealedKeys = []
for (label, plaintext) in [("framework", fw_plain), ("persona", persona_plain),
                            ("knowledge", know_plain), ("skills", skills_plain),
                            ("ops", ops_plain)]:
    data_key      = random(32)
    ciphertext    = AES-GCM(plaintext, data_key)
    storage_root  = 0g-storage.upload(ciphertext)
    sealed_key    = ECIES.encrypt(agent_seal_pubkey, data_key)
    entries.append(IntelligentData{dataHash: storage_root, dataDescription: label})
    sealedKeys.append(sealed_key)

AgenticID.registerWithSeal(
    to:                owner,
    agentURI:          "...",
    metadata:          [],
    intelligentDatas:  entries,
    sealedKeys:        sealedKeys,
    agentSeal_:        <TEE-derived agent seal address>,
    sealId:            <bytes32>
)
# Contract emits ITransferred(0, owner, agentId, [...5 SealedKeyEntry...])
```

5 storage uploads, 1 chain transaction.

### 6.2 Evolution (e.g. agent updates knowledge)

Triggered by evaluator strategy on the agent side:

```
new_plain     = adapter.EvolutionFor("knowledge")
data_key      = random(32)
ciphertext    = AES-GCM(new_plain, data_key)
new_root      = 0g-storage.upload(ciphertext)
new_sealed_key= ECIES.encrypt(agent_seal_pubkey, data_key)

# Read current iData (need unchanged dataHashes) and current sealedKeys
cur_entries     = AgenticID.intelligentDatasOf(agentId)
cur_sealed_keys = scan_latest_ITransferred(agentId)

# Find the entry to replace by label
new_entries     = list(cur_entries)
new_sealed_keys = list(cur_sealed_keys)
for i, e in enumerate(cur_entries):
    if e.dataDescription == "knowledge":
        new_entries[i]     = IntelligentData{dataHash: new_root, dataDescription: "knowledge"}
        new_sealed_keys[i] = new_sealed_key
        break

# Submit update with the dimension-aware writer (see Phase 1 contract changes)
sealUpdate(agentId, new_entries, new_sealed_keys)
# Contract emits ITransferred(seal, owner, agentId, [...5 SealedKeyEntry...])
```

1 storage upload (only the changed dimension), 1 chain transaction. Other
dimensions' storage_root and sealed_key stay the same and are simply re-passed
to the contract for full-array semantics.

### 6.3 Restart (read flow during sandbox boot)

```
entries     = AgenticID.intelligentDatasOf(agentId)
sealed_keys = scan_latest_ITransferred(agentId)

by_label = {}
for i, e in enumerate(entries):
    if e.dataDescription in by_label:
        FAIL("duplicate label: " + e.dataDescription)
    by_label[e.dataDescription] = (e, sealed_keys[i])

# Step 1: decrypt framework binding and pick adapter
fw_e, fw_sk = by_label["framework"]
fw_plain    = decrypt(fw_e.dataHash, fw_sk, agent_seal_priv)
fw_info     = json.parse(fw_plain)
if fw_info["schema_version"] not in SUPPORTED_SCHEMAS:
    FAIL("unsupported schema_version: " + fw_info["schema_version"])
adapter     = framework.Get(fw_info["name"])
adapter.CheckCompatible(fw_info["version"])

# Step 2: restore each adapter dimension
for dim in adapter.Dimensions():
    if dim not in by_label:
        log_warning("missing dimension " + dim + ", using defaults")
        adapter.Restore(dim, adapter.Defaults().for_dim(dim))
        continue
    e, sk      = by_label[dim]
    plaintext  = decrypt(e.dataHash, sk, agent_seal_priv)
    adapter.Restore(dim, plaintext)

# Step 3: any chain labels not known to adapter (e.g. removed in newer adapter)
for label in by_label:
    if label != "framework" and label not in adapter.Dimensions():
        log_warning("unknown label, ignoring: " + label)

# Step 4: start agent. Adapter must compose all Restore() calls into a working state.
adapter.Start()
```

Note: the order of `adapter.Restore(dim, ...)` calls is implementation-dependent
(map iteration). Adapters MUST treat Restore as order-independent and idempotent
(see Section 7.2).

### 6.4 Transfer (iTransferFrom)

ERC-7857 standard re-keying. New owner provides their agent_seal_pubkey;
old owner (or their delegate) re-wraps each entry's data_key:

```
for each i in 0..N:
    # Decrypt the data_key with the old seal
    old_dk = ECIES.decrypt(old_seal_priv, old_sealed_keys[i])
    # Re-wrap to new owner's agent_seal_pubkey
    new_sk = ECIES.encrypt(new_agent_seal_pubkey, old_dk)
    # Submit OwnershipProof entry (per ERC-7857)

# Submit iTransferFrom with all new sealed_keys.
# Contract validates proofs, replaces sealed keys, emits new ITransferred(old, new, agentId, entries)
```

Because every entry has the same shape (storage-mode + real sealedKey), the
re-keying loop is uniform with no special cases.


## 7. Framework Adapter Contract

### 7.1 Interface

```go
package framework

type Framework interface {
    // Identity
    Name() string                                       // e.g. "openclaw"
    Version(ctx context.Context) (string, error)        // detected runtime version
    CheckCompatible(version string) error               // accept/reject fw_info.version

    // Dimensions returns the labels this adapter understands, NOT including
    // the protocol-level "framework". Order is informational only.
    Dimensions() []string

    // Defaults returns the adapter's notion of empty/default content per
    // dimension. Used at mint time when the owner leaves a field blank, and
    // at restart time when an expected dimension is missing on chain.
    Defaults() InitialConfig

    // BuildInitial composes the plaintext bytes for a dimension at mint time
    // from a high-level config (which is owner input merged with defaults).
    BuildInitial(ctx context.Context, dim string, cfg InitialConfig) ([]byte, error)

    // EvolutionFor exports the current runtime state for a dimension as
    // plaintext bytes (will be encrypted by uploader).
    EvolutionFor(ctx context.Context, dim string) ([]byte, error)

    // Restore applies plaintext bytes for a dimension to the framework
    // runtime state. Multiple Restore calls (one per dim) MUST commute and
    // be idempotent. See Section 7.2.
    Restore(ctx context.Context, dim string, plaintext []byte) error

    // Process lifecycle
    Start(ctx context.Context, rt RuntimeContext) (StartResult, error)
    Stop(ctx context.Context, gracefulTimeout time.Duration) error

    // Health
    Liveness(ctx context.Context) error                // process alive + listening
    Readiness(ctx context.Context) error               // ready to handle requests
}

// Optional: if the adapter implements this, the manager will prefer Reload
// over Stop+Start during evolution updates.
type Reloadable interface {
    Reload(ctx context.Context, changedDim string) error
}

type RuntimeContext struct {
    DataDir string
    APIKey  string
    Logger  *zap.Logger
}

type StartResult struct {
    Upstream string  // e.g. "http://127.0.0.1:3284"
    Secret   string  // framework-specific access credential (e.g. openclaw token)
    PID      int
}

type InitialConfig struct {
    // Adapter-specific structured form input. openclaw uses:
    Persona    PersonaSpec
    Skills     []SkillSpec
    Ops        OpsSpec
    // Knowledge has no high-level form input; always starts at adapter.Defaults().
}
```

### 7.2 Compose / Decompose contract (the order-independence requirement)

openclaw stores `openclaw.json` as a single file but multiple dimensions
contribute fields to it (persona contributes `agents.defaults.model`; ops
contributes `channels`, `mcp`, etc.).

Adapter implementation MUST:

1. Maintain an in-memory composed state, NOT write per-Restore changes
   directly to disk.
2. Each `Restore(dim, plaintext)` call updates only the slice owned by that
   dimension in the in-memory composed state.
3. `Start()` is the only function that writes the composed state to disk
   (e.g. `~/.openclaw/openclaw.json`) and spawns the runtime process.
4. `EvolutionFor(dim)` reads only the slice owned by that dimension from the
   live runtime state (or from a persisted snapshot), independent of other
   dimensions.

This guarantees:
- Restore call order does not affect the final composed state.
- Two consecutive Restore calls for the same dim with different inputs result
  in only the second taking effect (idempotent in semantics).
- A dimension can be evolved (re-encrypted, re-uploaded, re-applied) without
  touching other dimensions.


## 8. Reader Policies

### 8.1 Duplicate label

If two iData entries share the same `dataDescription` label, the reader MUST
reject the bootstrap:

```
log_error("duplicate label", label)
report_error("agent metadata corrupted: duplicate label " + label)
state.Set(Failed)
exit
```

Rationale: agent identity is undefined when the same dimension claims two
different storage roots. Better to fail loud than silently pick one.

### 8.2 Missing label

If an adapter dimension has no corresponding entry on chain, reader uses
`adapter.Defaults()` for that dimension:

```
log_warning("missing dimension, using defaults", dim)
adapter.Restore(dim, adapter.Defaults().for_dim(dim))
```

Rationale: lets older agents survive when an adapter version adds a new
dimension. Owner can later mint a new entry to fill it in.

### 8.3 Unknown label

If chain has an entry whose label is not in `adapter.Dimensions()` and not
the protocol-reserved `framework`, reader logs a warning and ignores it:

```
log_warning("unknown label, ignoring", label)
```

Rationale: lets newer chains survive when an adapter version drops a
dimension. The historical entry stays on chain (immutable) but is dormant.

### 8.4 Schema version mismatch

If `fw_info.schema_version` from the framework binding plaintext is not in
the reader's supported set, reader fails fast:

```
FAIL("unsupported schema_version: " + n)
```

Rationale: schema-level changes are by definition incompatible. Forcing the
operator to deploy a sandbox image that supports the schema is correct.


## 9. Schema Versioning

`schema_version` lives in the framework binding plaintext, NOT in
dataDescription on chain. This keeps per-entry overhead at zero while still
allowing protocol evolution.

Compatibility rules:

- The current schema version is `1`.
- Old sandbox images can refuse to boot agents minted with future schema
  versions (`fw_info.schema_version > 1`).
- New sandbox images must continue to handle schema 1 alongside any newer
  schemas (forward-compatible reader).
- Schema bumps are reserved for changes that break the field semantics of
  framework / persona / knowledge / skills / ops plaintexts in ways an old
  reader cannot tolerate. Adding optional fields does not require a bump.


## 10. Manager / Supervisor

The manager owns the agent process lifecycle:

- `manager.Start()` calls `adapter.Start()` and begins polling
  `adapter.Liveness()` every 5 seconds.
- On Liveness failure, manager attempts restart with backoff:
  `1s, 2s, 4s, 8s, 16s, 30s, 60s, 60s, ...`.
- Manager has a configurable `maxRetries` (default `5`). If exceeded, state
  transitions to `Failed`, reporter sends `error` to attestor.
- Hard errors (binary missing, config corrupt) skip backoff and go directly
  to `Failed`.
- Restart triggered by evolution prefers `Reloadable.Reload(dim)` if the
  adapter implements it; otherwise falls back to `Stop` + `Start`.


## 11. State Machine

```
Bootstrapping  -- attest + provision + chain read + decrypt + adapter.Restore + adapter.Start
                  /hello returns 503 during this phase
        v
Running        -- normal service. Evaluator polls; manager polls Liveness.
        |
        +-- agent died -----> Restarting (manager backoff loop)
        |                     /hello returns 503; on success -> Running; on max retries -> Failed
        |
        +-- evolution -----> Evolving (concurrent with Running, does NOT block proxy)
        |                    1) adapter.EvolutionFor(dim)
        |                    2) encrypt + upload to 0g-storage
        |                    3) chain write + wait for confirmation
        |                    4) state.AppendDataHash(dim, new_root)
        |                    5) optional: adapter.Reload(dim) or Stop+Start
        |                    -> Running
        |
        +-- unrecoverable -> Failed
                              /hello returns 503; reporter posts "error";
                              external attestor decides whether to force-stop the sandbox.
```

Proxy serve-proof signing always uses the dataHashes currently stored in
`state.dataHashes`. Because those values are only updated AFTER chain tx
confirmation (step 4 above), proxy never produces a signed response that
references a dataHash not on chain.


## 12. Storage / Upload Cost (informational)

Per-mint with full default form (no owner customization):

| Action | Count | Approximate cost |
| --- | --- | --- |
| 0g-storage uploads | 5 (one per dim) | ~5 small ciphertexts (~500 bytes each) |
| Chain transaction | 1 (`registerWithSeal`) | 5 IntelligentData entries + 5 SealedKeyEntry in event |

Per-evolution touching one dimension:

| Action | Count | Approximate cost |
| --- | --- | --- |
| 0g-storage uploads | 1 | size of the changed dimension's tar.gz |
| Chain transaction | 1 (`sealUpdate`) | full 5-entry array re-passed (most unchanged) |


## 13. Open / Pending Items

These are deliberately deferred and tracked separately:

1. Contract-level write function (`sealUpdate`) and dimension-aware authorization.
   Required for evolution flow but read flow does not depend on it.
2. Concrete strategies for `evaluator` (TimerStrategy default; DiffStrategy
   and LLMStrategy are future work).
3. Channel credential injection mechanism via dashboard. Specified at the
   contract layer (out of scope for this document) but design decision is
   "ephemeral, never on chain".
4. Selective `iCloneFrom` semantics (clone only specific dimensions).
   Theoretically possible because dimensions are independent; not in scope
   for v1.


## 14. Implementation Phases

| Phase | Scope | Depends on |
| --- | --- | --- |
| 1 | Contract: `sealUpdate(tokenId, IntelligentData[], bytes[] sealedKeys)` with dimension-aware auth + `ITransferred` emission | none |
| 2 | Refactor `bootstrap.go` read path to dimension-aware (label-based dispatch) | none (uses existing read APIs) |
| 3 | Module decomposition: split monolithic `bootstrap.go` into `internal/` packages; add `manager` | Phase 2 |
| 4 | Outbound: `evaluator` + `uploader`; first wire them up against the new contract function | Phase 1 + Phase 3 |
| 5 | Update attestor mint flow: per-dimension `BuildInitial`, encrypt + upload, `registerWithSeal` with N entries | Phase 1 (so contract supports the call shape) |
| 6 | Documentation refresh; per-package READMEs | last |

Phase 2 can run before Phase 1 because the read path uses the existing
`intelligentDatasOf` and `ITransferred` event surface, which is unchanged.
This lets us deploy a forward-compatible reader before changing the write
side, reducing the risk of a coordinated migration.


## 15. Agent Service Extensibility

This chapter answers the practical question: when an owner asks the agent
to "expose a service externally", what is the path of least resistance for
the agent to take, and how does the system guarantee that path automatically
produces serve-proof signed responses?

### 15.1 Protocol contract

`http://8080-<sandbox-id>.<proxy-domain>/` is the only externally-reachable
URL prefix on which `X-Agent-Proof` is guaranteed. Verifier SDKs MUST:

1. Only accept responses carrying `X-Agent-Proof` as authentic.
2. Verify that header against the agent's on-chain `agentSeal` address.
3. Cross-check `proof.data_hashes` against `intelligentDatasOf(agentId)`.

A response without a valid `X-Agent-Proof` is by definition NOT a sealed-
agent response. Verifiers ignore it.

### 15.2 Trust model

The architecture is designed for **honest agents**, possibly buggy or naive,
but not malicious. Three observations:

- `agent_seal_priv` lives only in the bootstrap process. openclaw and any
  spawned subprocesses cannot read it. Only `proxy.writeServeProof` signs.
- An honest agent that wants its responses to be verifiable picks the path
  that gets auto-signed (Section 15.4). It has no incentive to bypass.
- A malicious agent that bypasses on-chain extension paths produces unsigned
  responses. Verifier protocol (15.1) treats these as non-existent. The
  attacker gains nothing.

The system does NOT employ seccomp / proc monitoring / fork-exec env scrub
to prevent bypass. The threat model accepts that a malicious agent can run
unsigned services on the basis that those services have no authority.

### 15.3 External URL format

The 0g-sandbox proxy uses subdomain-based port routing:

```
  http://<port>-<sandbox-id>.<proxy-domain>:<proxy-port>/<path>
         |     |             |              |
         |     |             |              proxy port (e.g. 4000)
         |     |             |
         |     |             proxy host (e.g. 47.236.111.154.nip.io)
         |     |
         |     sandbox UUID
         |
         port the request is forwarded to inside the container
```

Concretely: `http://8080-bd178e46-...nip.io:4000/api/ppt/generate` reaches
the sealed container's port 8080, which is the bootstrap proxy.Server.

Other port prefixes attempt to reach different ports inside the container.
Reachability depends on whether the sandbox-internal service binds to
`0.0.0.0` or `127.0.0.1`. openclaw with `--bind loopback` binds 127.0.0.1
only, which the daytona proxy CANNOT reach across the network namespace
boundary, so `:3284-<id>...` URLs naturally fail.

### 15.4 Default exposure path: openclaw plugin with `registerHttpRoute`

openclaw plugins call `api.registerHttpRoute({path, auth, match, handler})`
from their `register(api)` function. The handler runs inside the gateway
process and serves the registered path on `127.0.0.1:3284`.

Example (Node.js plugin generating PPT files):

```typescript
import PptxGenJS from "pptxgenjs";

export function register(api) {
  api.registerHttpRoute({
    path: "/api/ppt/generate",
    auth: "plugin",       // serve-proof on :8080 is the trust boundary
    match: "exact",
    handler: async (req, res) => {
      const body = await readJsonBody(req);
      const pptx = new PptxGenJS();
      // populate slides from body.topic, body.outline, etc.
      const buf = await pptx.write({ outputType: "nodebuffer" });
      res.statusCode = 200;
      res.setHeader("Content-Type",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation");
      res.end(buf);
      return true;
    },
  });
}
```

Once installed (npm package + `openclaw config plugin enable`), the route
lives at `127.0.0.1:3284/api/ppt/generate`. The bootstrap proxy.Server has
a catch-all reverse proxy on `/*`, so external traffic at
`http://8080-<id>.<host>/api/ppt/generate` reaches the plugin handler and
the response is automatically signed by `proxy.writeServeProof`.

This is the path the agent should choose by default whenever an owner asks
for an exposed service. No serve-proof code touches the plugin.

### 15.5 How the agent learns its public URL

The agent does not intrinsically know its sandbox's UUID, the proxy host,
or therefore its public URL. The URL is assembled by the bootstrap from
two pieces:

| Piece | Source | Provider |
| --- | --- | --- |
| `<sandbox-uuid>` | env `DAYTONA_SANDBOX_ID` | Daytona auto-injects when starting the container |
| `<proxy-domain>` | env `SANDBOX_PROXY_DOMAIN` | 0g-sandbox proxy injects via `InjectSeal`, copied from billing service's `PROXY_DOMAIN` env |

Bootstrap composes:
```
SANDBOX_PUBLIC_URL = "http://8080-" + DAYTONA_SANDBOX_ID + "." + SANDBOX_PROXY_DOMAIN
                   = "http://8080-bd178e46-...:4000"
```

`InjectSeal` runs before Daytona has assigned a UUID, so it cannot inject
the full URL itself — but `SANDBOX_PROXY_DOMAIN` is static and known at
that point, and `DAYTONA_SANDBOX_ID` is Daytona's standard auto-injected
metadata that lands in the container after creation. No two-phase update
required.

Bootstrap then exposes the composed URL in three places:

1. **`/hello` response**: bootstrap adds `public_url` to the signed JSON
   body. Verifiers can cross-check that the URL they're hitting matches
   the URL the agent claims.

2. **`~/.openclaw/0g-public-url.txt`**: bootstrap writes the URL to a known
   file path. Any plugin can `fs.readFile` to construct full URLs in its
   responses.

3. **`AGENT_PUBLIC_URL` env**: bootstrap adds this to openclaw's spawn-time
   env whitelist. Plugins read `process.env.AGENT_PUBLIC_URL` directly.

The agent uses any of these to tell the owner the canonical service URL.

If `SANDBOX_PROXY_DOMAIN` is unset (e.g. local dev outside the proxy
infrastructure), bootstrap leaves `public_url` empty in `/hello` and skips
the file/env exposure. The system stays functional but agents cannot
self-advertise a URL — owners would have to provide it manually.

### 15.6 Owner verification flow

When an owner receives a URL claim from the agent, the owner can verify
end-to-end with four checks:

1. `curl <claimed-url>/hello` returns 200 with `X-Agent-Proof` header.
2. `ethers.verifyMessage(envelope, sig)` recovers the agent address bound
   on chain at `AgenticID.agentSeals[agentId]`.
3. The decoded envelope's `public_url` field equals `<claimed-url>`.
4. The decoded envelope's `data_hashes` field equals
   `AgenticID.intelligentDatasOf(agentId)` mapped to hex.

All four passing means the URL is genuine, the agent is the on-chain one,
and the runtime is provisioned with the on-chain data.

### 15.7 Future work: multi-upstream routing for non-openclaw services

For agents that need to expose services NOT served by openclaw (e.g. a
Python ML inference microservice running on its own port), the bootstrap
proxy will need route-prefix-to-upstream-port mapping:

```go
type RouteRule struct {
    PathPrefix   string  // e.g. "/api/inference/"
    UpstreamPort int     // 9999 (always 127.0.0.1:port)
}
```

Routes are declared on chain (e.g. as a new `routes` dimension) so they
are owner-signed and auditable. Dynamic registration at runtime is
intentionally NOT supported — it would let a compromised openclaw silently
re-route external traffic to attacker-controlled handlers.

Deferred until a real use case for non-openclaw services emerges. For v1
the `registerHttpRoute` path covers the common case.


## 16. Glossary

- **agent_seal_priv / agent_seal_pubkey**: secp256k1 keypair derived per-agent
  by the trusted attestor; stable across all sandboxes that bootstrap the
  same agent. The pubkey is bound on-chain via `setAgentSeal` and used for
  ECIES to wrap data_keys.
- **data_key**: random 32-byte AES-GCM-256 key generated per iData entry. Wrapped
  with agent_seal_pubkey via ECIES, stored as sealedKey.
- **dimension**: a named slice of an agent's defining data (e.g. persona,
  knowledge). Each dimension corresponds to one iData entry on chain.
- **framework binding**: the protocol-reserved iData entry (label `framework`)
  that names which adapter is responsible for the other dimensions.
- **label**: the value of `IntelligentData.dataDescription`, used as the role
  identifier of an iData entry.
- **schema_version**: protocol version field carried in the framework binding
  plaintext. Used to gate forward compatibility.
- **sentinel**: NOT used in this design. Defaults are real encrypted blobs,
  not on-chain markers.
