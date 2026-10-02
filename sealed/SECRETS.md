# Owner secrets — usable by the agent, never visible to it

See `SECRETS.zh.md` for the Chinese version. Keep the two in sync.

## 1. The problem

An agent doing real work needs credentials the owner holds: a paid API key, a
webhook secret, a chat-platform bot token. Today it has nowhere safe to put
them. `memories/`, `skills/` and the persona files are tracked iData roles, so
a credential written there is encrypted to 0g storage **and conveyed to the
next owner on transfer**. And wherever it lands — a file, an env var — the
agent process can read it, so a prompt-injected agent can exfiltrate it. All
four frameworks confirm this: none keeps a credential out of the model's reach.

The goal is the treatment the agentSeal private key already gets: **the agent
can USE a secret without ever SEEING its value.**

Scope: this covers **business secrets the owner hands in** (Stripe, Telegram
token, …). It does NOT cover the **agentSeal identity key** — that is
environment-generated, injected via `/provision`, used for local signing (never
leaves the container), and must stay hidden even from the owner; see
`TRUST_MODEL.md`.

## 2. The invariants (the contract)

1. **The real value lives only in sealed's memory.** Delivered encrypted, held
   in sealed (root) after decrypt; never written to disk, never put in the
   agent's env, never handed to the framework process.
2. **The agent only ever sees a placeholder** — `{{secret:NAME}}`. A
   placeholder yields nothing: it is not the value and cannot derive it.
3. **Every secret carries its own narrow host allowlist** (the domains it may
   be sent to). A secret with no allowlist is unusable — this is the control
   that makes "even a tricked agent cannot leak it" hold.
4. **Substitution happens only at egress, only when the destination is in that
   secret's allowlist.** Sent anywhere else → not substituted (the far end
   receives the useless placeholder).
5. **Responses are redacted too** — a real value echoed in a response body or
   header is swapped back to its placeholder before the agent sees it.
6. **Owner-bound, revoked with the owner.** Encrypted to agentSeal; on open,
   sealed checks the sealing owner equals the live on-chain owner and discards
   on mismatch (the `secretenv` rule, reused). On transfer the attestor clears
   the stored secrets (unlike settings, which carry over).
7. **Never on chain.** Secrets are operator credentials, not the agent's
   identity or memory; they never enter any iData role.

## 3. Architecture (reuses existing channels)

```
owner (CLI) --encrypt to agentSeal--> attestor stores {ciphertext, hosts[]}
                                         |
                            every boot /provision delivers it (the settings path)
                                         v
                            sealed decrypts -> in-memory { NAME: {value, hosts[]} }
                                         |
agent request (secret slot = {{secret:NAME}}) -> sealed loopback egress proxy
                                         -> host in NAME.hosts? -> substitute -> dial upstream
                                         <- redact response <-
```

- **Store**: reuse the `secretenv` wire format (`agent-seal-ecies-v1` — already
  a name→value map). The attestor keeps the ciphertext plus each secret's
  allowlist (hosts are not secret); writes are owner-signed with
  compare-and-swap, like settings.
- **Deliver**: the `/provision` response carries the encrypted secrets beside
  `encrypted_settings`, every boot including resume.
- **Use**: sealed runs a loopback-only (127.0.0.1) egress proxy; the adapter
  passes its address to the framework. The agent sends outbound calls to it.

## 4. Two uses (both value-blind)

- **Agent tool calls** (v1): the agent sends the request to the loopback proxy
  with a `{{secret:NAME}}` placeholder in a header/field. curl and any HTTP
  library work with a changed base.
- **Framework's own calls** (the inference key, later a bot token; v2): point
  the framework's upstream at the loopback proxy with the key field set to a
  placeholder. The framework sends as usual; sealed substitutes at egress, so
  the inference key stops entering the framework process (hermes no longer
  writes it into `config.yaml`).

## 5. Substitution (explicit proxy; no impersonation, no cert)

- **Explicit proxy**: the agent/framework sends to
  `http://127.0.0.1:<port>/https/api.stripe.com/...` with `{{secret:STRIPE}}`
  in a header; the destination is in the URL, so the proxy reads it directly —
  **no TLS interception, no CA cert** — substitutes the real value, dials the
  real host itself, and relays the response.
  - Why this is enough: the agent has no real value, so a call that skips the
    proxy simply cannot use the secret (it sends the placeholder) — broken, not
    leaked. "Use a secret ⇒ go through the proxy" holds without network-level
    forcing.
  - Why not impersonation (MITM): with CONNECT/MITM the request Host and the
    dialed host can diverge, which **breaks per-secret host pinning** (§2.3/4,
    the whole control). Fly Tokenizer rejects CONNECT for exactly this reason.
    Explicit proxy keeps the destination unambiguous.
- **Transparent interception (not done here)**: only if a workload must stay
  code-unchanged (plain `https://` that gets intercepted). Costs a CA cert and
  must guard the Host/dial split. Forcing all egress through the proxy is a
  network-layer job sealed cannot do — left to the sandbox layer (§8).

## 6. Lifecycle

- **reset (container recreate)**: secrets live in the attestor; redelivered on
  the rebuild, no re-entry.
- **settings push / framework restart**: secrets live in sealed memory,
  redelivered on process restart; substitution is in sealed, so changing a
  secret needs no framework restart.
- **transfer**: the attestor's `on_transfer` does not touch secrets today — a
  new step clears the secret store on transfer (unlike settings), on top of the
  §2.6 owner check.

## 7. CLI / SDK

- `secret set NAME --hosts a.com,b.com` (value entered masked; a recognizable
  key prefix suggests hosts to confirm with Enter; unrecognized → typed in; no
  hosts → refused).
- `secret ls` / `secret rm NAME`.
- SDK methods mirror settings/secretEnv: encrypt to agentSeal, owner-signed
  push.

## 8. Deliberately not done / left to the sandbox layer

- **Forcing all egress through the proxy**, and a **general outbound allowlist**
  (which hosts the agent may reach at all, credential-independent): need
  network-level enforcement, which sealed cannot do (the agent can connect
  directly). Left to the sandbox layer (runner side); see 0g-sandbox#137.
- The sandbox-layer end state: tapp already provides **RA-TLS** (secure
  delivery) and **FDE** (encrypted at rest), so transport and at-rest are not
  prerequisites; with the same explicit-proxy form the CA mount is not needed
  either, leaving **one** prerequisite — dropping privileged mode on the inner
  agent container (the runner stays privileged; DinD needs it).
- **Signature-style auth** (AWS SigV4, webhook HMAC): not a plain substitution;
  unsupported in v1 — later, sign in the proxy (Fly Tokenizer's approach).
- **Non-HTTP credentials** (DB passwords, …): egress substitution cannot cover
  them.

## 9. Prior art

- Deno Sandbox: `secrets:{KEY:{hosts,value}}`, placeholder inside, substitute at
  egress per host — the same shape as §2/§3.
- Fly.io Tokenizer (open-source Go): encrypt-to-proxy, `allowed_hosts`, client
  never sees plaintext; explicit proxy, not MITM.
- Daytona has no such feature (infra `secret`s only); the four frameworks have
  none — so the platform (sealed / sandbox) must provide it.
