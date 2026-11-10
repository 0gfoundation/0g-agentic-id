# Owner credentials

[中文](CREDENTIALS.zh.md)

An owner gives an agent third-party credentials (API keys, tokens, refresh tokens, signing keys, logins to MCP servers) without giving them to the framework the model drives. The values live in sealed. The agent writes a placeholder where a key belongs, `[[credential:<name>]]`, and sealed fills it in on the way out, only for the hosts and request positions the owner allowed, and removes the value from what comes back. A value leaves sealed only when the owner allows it (*reveal*).

What each party sees:

| Party | Sees |
|---|---|
| owner (client) | everything it sets; the agent's requests and the audit log |
| attestor | the signed set and definitions; values only as ciphertext sealed to the agent |
| sealed | values, in memory |
| framework / agent | names, hosts, positions, placeholders; a value only when revealed |

## Entries and the signed set

An entry's **definition** is JSON, serialized once by the client and hashed as is (`def_hash = keccak256(bytes)`):

| Field | Meaning |
|---|---|
| `v`, `name` | `1`; the name used in the placeholder (`[a-z0-9][a-z0-9._-]{0,62}`; the prefixes `derived:` and `sealed:` are sealed's own) |
| `hosts` | where it may be sent; exact match after normalization (lower case, no trailing dot, `:443` dropped) |
| `positions` | where its placeholder may stand: `header` (`name`, `template` with one `{v}`), `basic` (fixed `username`, value is the password), `query` (`param`), `path` (a whole segment), `body` (a top-level JSON or form `field`) |
| `use` | `inject` (default), `token_only` (only feeds a token request), `sign` (a key sealed signs with) |
| `value_hash` | keccak256 of the value's ciphertext; empty only for a login entry |
| `token_request` | a token endpoint template (below) |
| `signer` | with `use: sign`: `sigv4`, `hmac`, `jwt` or `wallet` (below) |
| `mcp` | a login entry: `url`, and `client_id`, `client_secret_entry`, `scopes` when needed (below) |
| `allow_reveal` | the agent may read the value without asking each time |
| `writeback` | sealed may store a value it obtained (rotation, login) for the next boot |
| `expires_at`, `description` | Unix seconds: after it the entry is neither filled, signed with, revealed nor used in a token request; free text shown to the agent |

One entry is one value used in several places: its positions hold on each of its hosts. A GitHub token, for one, serves both the API (`api.github.com`, `Authorization: Bearer`) and git (`github.com`, Basic) when the entry lists both hosts and both positions. A preset (`preset=<name>` in the CLI; `cred presets` lists them with where to create each key) is a shortcut the client expands into hosts, positions and a description; sealed never sees it.

The **value** (at most 16 KiB, as is any value sealed obtains) is ECIES-encrypted to the agent's agentSeal key in the client. Its plaintext binds it: `{"v":1,"type":"credential","owner","seal_id","chain_id","name","value"}`; sealed refuses one bound to another owner, agent, chain or name.

The owner signs the whole set once, EIP-712:

```
domain   {name: "AgentDNA Credentials", version: "1", chainId, verifyingContract: AgenticID}
CredentialSet(bytes32 sealId,uint64 ownerEpoch,uint64 version,Entry[] entries)
Entry(string name,bytes32 defHash)
```

The same digest is pinned in sealed (`TestDigestVectors`), the attestor and the SDK.

- **Version**: each write is `version + 1`, a compare-and-swap at the attestor. sealed remembers the newest set it loaded by (ownership epoch, version) with the set's digest, in its state directory, kept across stop/start, and refuses an older one or another set at the same (ownership epoch, version); a new owner's first set is newer than every set of the owner before.
- **Ownership epoch**: the block of the agent's last transfer. A set signed for an earlier epoch is refused everywhere, so a previous owner's set can never be reinstated. On a transfer the attestor drops the set, and sealed clears every entry, request, approval and audit record, and the framework's inference key it holds. sealed looks the owner up every 10 seconds, and again before a reveal, a token request, a wallet signature or a login when it last confirmed the owner more than 10 seconds before (a failed lookup refuses them); once it finds a new owner, it clears the previous owner's state and the container closes (next bullet). A token request, a refresh or a login still running when the state is cleared, or when the owner gives its entry a new value, keeps nothing.
- **The container serves the owner it was started for**: once the chain names another owner (sealed asks every 10 seconds, and again on each owner-signed request; no answer, or the zero address, is not an owner), the container closes for good. Requests in flight end, streams and upgraded connections included; every route but `/hello`, `/healthz` and the public `/log` and `/log.html` answers 423 `owner_changed`; the agent's signing socket refuses; and no state is written back, an upload under way included. The framework process keeps running, without credentials or its inference key. Neither the previous owner nor the new one drives that container, and it stays closed even if the agent comes back; the owner resets the agent to run it.
- **Per-entry checks**: an entry whose definition does not match its signed hash, whose value does not match `value_hash`, or that the proxy cannot serve is skipped with its reason; the rest of the set loads.
- **The owner's client**: every change signs the whole set again, so the SDK takes the stored set only when this wallet signed it, for this agent and at the version stored, and each definition and stored value is the signed one, and when it is no older than the newest set this client has seen, nor another set at that version (by ownership epoch, then version, with the set's digest; the CLI keeps these in `credential-marks.json` in its config directory, so the check holds across runs on the same machine); otherwise it signs nothing (`CredentialsUnverifiedError`). The ownership epoch comes from the attestor: a made-up later one makes the honest set read as older, and the error then says which record to remove (the CLI names its file).

## Using credentials from the agent

Every adapter appends `RuntimeContext.CredentialEnv()` to the framework's environment:

| Variable | Value |
|---|---|
| `HTTPS_PROXY`, `https_proxy` | `http://agent:<token>@127.0.0.1:<port>` (the token is per boot, in the password position) |
| `NO_PROXY`, `no_proxy` | `localhost,127.0.0.1,::1` |
| `SEAL_CRED_PROXY` | `http://127.0.0.1:<port>/<token>`; explicit form `$SEAL_CRED_PROXY/https/<host>/<path>` for clients that ignore `HTTPS_PROXY` |
| `NODE_EXTRA_CA_CERTS` | `/etc/seal/credential-ca.pem` (the proxy's root alone) |
| `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO`, `AWS_CA_BUNDLE`, `CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE` | `/etc/seal/credential-ca-bundle.pem` (system roots + the proxy's root) |
| `SEAL_CRED_SOCKET` | `/run/seal-cred.sock` |
| `SEAL_CRED_REVEAL_SOCKET` | `/run/seal-cred-reveal.sock` |
| `GIT_CONFIG_SYSTEM` | `/etc/seal/credential-gitconfig`: the image's `/etc/gitconfig`, then git's credential helper, answered by `GET /credentials/git` |

The CA is generated at each boot; its key stays in sealed's memory. The system trust store is not changed.

**The proxy.** A `CONNECT` to a host some entry names is terminated with a leaf certificate from that CA (HTTP/1.1 and HTTP/2); any other host is tunnelled untouched. For a terminated or explicit request it:

- requires the per-boot token; requires the CONNECT target, the TLS SNI (none for an IP address) and the `Host` to agree; refuses an explicit-form host with control, space or format characters; serves at most 512 connections at once (the next waits) and at most 128 requests at once across them, 32 of those kept for requests that fill `sealed:` entries alone, which the framework's tools may send too (a request over that is answered 503 `busy` with `Retry-After: 1`; a CONNECT tunnel counts only as a connection); allows 16 concurrent HTTP/2 streams on a terminated connection and a request head of 64 KiB; closes a connection idle for 2 minutes, and a CONNECT tunnel or WebSocket relay after 10 minutes with no bytes moving either way;
- refuses to dial private, loopback, link-local, multicast, unspecified, NAT64 and metadata addresses; never follows a redirect;
- fills each placeholder only for an allowed host and position, and refuses the whole request otherwise; never fills `Host`, `Content-Length`, `Transfer-Encoding`, `Cookie` or `Proxy-*`;
- reads a body only on a host where some entry may fill a body field or signs requests. There it buffers up to 64 KiB to fill, which must arrive within 30 seconds (else 408 `bad_request`); a larger body is relayed as it streams and scanned to its end, and at a placeholder the upload stops (what came before has gone upstream) and the request is answered 413 `body_too_large`. Anywhere else a body is relayed as it is, placeholder text and all, since nothing could be filled in it;
- fills a body that names a placeholder (as written, or once its percent or JSON escapes are decoded) only when it has exactly one `Content-Type`, JSON or form, and the placeholder is written as is and stands alone as the value of a top-level field; anything else is refused. A form body must be url-encoded throughout once filled (the placeholder itself may be written raw: `token=[[credential:x]]`). A JSON body goes out with its own `&` and `;` written as `\u0026` and `\u003b`: the same JSON, in which a server reading it as a form finds no field separator. A path segment that is a placeholder once percent-decoded is filled;
- sets the headers it adds before it signs, so a signature covers the request as sent; re-signs an AWS-signed request only when its `X-Amz-Date` is within 15 minutes of now and `host` is among the signed headers; refuses (`sign_failed`) to sign a request whose query holds `X-Amz-Signature`, `X-Amz-Credential` or `X-Amz-Algorithm`; drops `X-Seal-Credential-Filled` and `X-Seal-Credential-Error` coming from upstream;
- asks upstream for an unencoded body and refuses a response with any `Content-Encoding`; redacts every value it holds, and every value it filled into this request and the signatures and session token it set on it, from response headers (a header whose name holds a value, in any letter case, is dropped) and the streamed body: raw, percent-encoded (either case), JSON-escaped as common encoders write it (HTML escapes, `+` `'` `=` and backtick escaped, `\u` hex in either case, non-ASCII escaped, `/` as `\/`), quoted-string escaped, and base64 at each alignment; values under 6 bytes are not redacted, nor a value split across WebSocket fragments, line-wrapped base64 or hex. It masks, best effort, tokens of well-known formats it does not hold (GitHub, GitLab, Slack, Stripe, `sk-` keys, Hugging Face, Google API keys, npm, Notion) as `[[redacted]]`. WebSocket frames are read one by one (at most 1 MiB of payload) and masked in place, length kept, control frames too (a ping or pong payload whole, a close frame's reason after its code); a frame with an RSV bit set ends the relay, and the `101` response is redacted like any other. What sealed itself sends on (registered services, committed data, below) is scrubbed of the values it holds only.

A response to a request in which the proxy filled a value carries `X-Seal-Credential-Filled: <entry names>`: a service that echoes the request shows the placeholder again, since the value is hidden on the way back, and this header is how the agent tells a filled request from one that was not. A host no entry names is tunnelled, so nothing is filled there and there is no error either; its responses never carry the header.

A refusal is an HTTP error with `X-Seal-Credential-Error: <code>` and a JSON body `{code, message}` that never carries a value. Codes: `unknown_entry`, `expired` (410), `busy` (503), `token_only`, `position_not_allowed`, `host_not_allowed`, `forbidden_header`, `body_too_large`, `private_address`, `bad_request` (also 408 for a body that does not arrive in time), `bad_target`, `target_mismatch`, `proxy_auth`, `not_allowed`, `sign_failed`, `upstream_error`, `internal`.

**The credential socket** (`$SEAL_CRED_SOCKET`, agent user, JSON):

| Route | |
|---|---|
| `GET /credentials` | entries: `name`, `description`, `source` (`owner` or `derived`), `use`, `hosts`, `positions`, `signer`, `expires_at`, `logged_in_at` (a login entry), `allow_reveal`, `placeholder`, and `status: awaiting_login` for a login entry whose login the owner has not finished (it cannot be used yet) |
| `GET /credentials/git?host=` | git helper answer: `username=…` and `password=[[credential:…]]` for an entry that allows Basic there; 404 otherwise |
| `POST /credentials/token` | `{name, params}`: run the entry's token request; returns the derived entries |
| `POST /credentials/sign` | `{name, personal_sign \| typed_data \| transaction}`: sign with a wallet entry |
| `POST /credentials/request` | `{op: "add" \| "login", name, preset?, url?, reason}`: ask the owner; 202 `{auth_req_id, expires_at}` |
| `DELETE /credentials/{name}` | drop a derived entry (owner entries are the owner's) |
| `GET /events?after=&wait=` | long-poll: `entry_added`, `entry_removed`, `pending_opened`, `pending_decided`, `cleared`, `writeback_failed` |

Requests waiting for the owner are bounded: at most 32 at once (429 `too_many_requests` after that), a reason of up to 512 characters on one line (longer ones are cut; control, format and line-separator characters and spaces other than the plain one become spaces), up to 4 parameters of up to 512 characters each (2048 for `url`, which must be a plain https URL with no userinfo), with no control, format or line-separator characters or spaces other than the plain one. They are shown to the owner as the agent's; a request's facts are only what sealed knows. sealed's own requests (a login to renew) do not count against the 32.

**Reveal** (`$SEAL_CRED_REVEAL_SOCKET`): `POST /credentials/reveal {name, reason}`. With `allow_reveal` it answers `{value}`. Otherwise 403 `authorization_pending` with an `auth_req_id`; the owner decides; the agent sends the same request again. 403 `access_denied` is a refusal. An approval is for the value the agent asked about: a token obtained or rotated after it is asked for again. For a derived token the owner is shown its own hosts and expiry and the parameters it was obtained with. A signing key (`use: sign`) is never revealed (403 `not_allowed`). A login entry reveals its access token, never its stored login state. The socket is separate from the one above so that a harness running its tools as another user could keep it from them; both belong to the agent user, which the tools of the shipped frameworks run as too.

## The framework's inference key

The key a framework calls its model with (the owner's `SEAL_SECRET_ENV`, sealed to agentSeal and opened by sealed after provisioning, or the legacy `API_KEY`) is held by sealed for **0g-harness on a platform-routed model** (0g-compute): it becomes the entry `sealed:inference`, filled in only as `Authorization: Bearer {v}` or `x-api-key: {v}` on the router's host. 0g-harness gets `SEAL_MODEL_API_KEY=[[credential:sealed:inference]]` and `SEAL_MODEL_BASE_URL` set to the router through the proxy's explicit form, so neither it nor any tool it runs can read the key. Nothing reveals that entry. An owner change drops it with the rest, and a framework restart after that does not take it again: 0g-harness then starts without the key, until the new owner resets the agent. Adapters do this through `RuntimeContext.CredHold`.

Everywhere else the framework still receives the key itself, and its tools can read it: 0g-harness on a framework built-in provider (`openai`, `anthropic`), openclaw and hermes (`OPENAI_API_KEY` / `ANTHROPIC_API_KEY`; hermes also writes it into its config file), and prime (`SEAL_MODEL_API_KEY`).

## Token requests and rotation

A `token_request` is a template sealed follows; the agent never sees the request or the response.

| Field | |
|---|---|
| `url`, `encoding` | the token endpoint; `form` (default) or `json` |
| `fields` | field → template: `{v}` is this entry's value, `{cred:<name>}` another entry's (a `jwt` entry stands for a freshly minted token; another signing key is refused) |
| `basic_auth` | `{username_entry, password_entry}` |
| `params` | parameters the agent may add (e.g. `scope`): a field the template does not set; one it sets is refused (403 `not_allowed`). Up to 512 characters, with no control, format or line-separator characters or spaces other than the plain one |
| `take` | response fields kept as derived entries: `field`, `name`, `hosts`, `positions`, `expires_in_field` (seconds, a number or a string of digits); named `derived:<entry>.<field>` unless named. A derived entry never outlives its source's `expires_at` |
| `rotate_field` | e.g. `refresh_token`: a new value in the response replaces the entry's value |

Token requests for one entry run one at a time. A failure answers `token_request_failed` with the OAuth error code only; a request whose entry changed while it ran (see *Ownership epoch*) answers 409 `changed`. A template's fields are filled in one pass: a value that reads like `{cred:<name>}` is sent as it is. A login entry takes no template.

**From the CLI.** `preset=oauth2-refresh` (the value is a refresh token; it rotates and is written back) and `preset=oauth2-client` (the value is a client secret) build the standard OAuth 2.0 template from `token_url=`, `client_id=` and `api_host=`, with optional `scope=` (when given it is fixed; without it the agent may pass one) and, for a refresh token whose client has a secret, `client_secret=<entry>`. The agent runs `POST /credentials/token` on the entry and uses `[[credential:derived:<entry>]]` as a Bearer token on `api_host`. Any other template goes in `token=<json>`.

**Writebacks.** A value sealed obtains (a rotated refresh token, a login) is sealed to agentSeal and posted to the attestor, signed by agentSeal over

```
CredentialWriteback.v2:<seal_id>:<name>:<binding>:<boot_id>:<keccak256(ciphertext)>
```

(keccak256, no EIP-191 prefix; the sign socket cannot produce it). The binding names what the value stands for: `value:<value_hash>` for an entry with a value of the owner's, `mcp:<keccak256 of the server URL, client_id, client_secret_entry and scopes>` for a login entry. A writeback stays valid while the entry keeps that binding: the owner can edit its description, hosts, positions, expiry or `allow_reveal` and keep a rotation or a login; a new value or a different login ends it. It is sealed to the owner it was obtained under and opens for no other. The attestor stores it only from the current boot, for an entry with `writeback: true` in the set, and keeps it across new sets while that holds; at boot sealed takes a writeback whose binding matches the definition over the owner's value. A failed writeback is retried in the background; if the container restarts first, that value is lost.

## Signing keys

`use: sign` entries are never written into a request.

| `signer.method` | Parameters | How it is used |
|---|---|---|
| `sigv4` | `access_key_id`, `region`, `service`, `session_token_entry?` | The proxy signs a request carrying `X-Seal-Sign: <name>`, or signs again a request an AWS tool signed with this `access_key_id` and the placeholder as its secret (the entry's hosts only). Pinned against aws-sdk-go's signer. |
| `hmac` | `message` (over `{method}` `{path}` `{query}` `{body}` `{timestamp}` `{header:<name>}`), `header` or `param`, `algorithm` (`sha256`, `sha512`, `sha1`), `encoding` (`hex`, `base64`), `prefix`, `timestamp_header` | The proxy signs a request carrying `X-Seal-Sign: <name>`. |
| `jwt` | `alg` (`RS256`, `ES256`, `HS256`), `kid`, `claims`, `ttl` (≤ 86400) | The placeholder stands for a token minted from the key, in requests and in token requests (e.g. a service account's `jwt-bearer` assertion). A token minted into a request is redacted like a value, and scrubbed until it expires (the last 256). |
| `wallet` | — | `POST /credentials/sign` with the sign socket's three shapes (personal message, EIP-712, transaction); returns the signature. The audit log records what was signed: a transaction's chain, recipient, value and selector; typed data's primary type, domain name, chain and contract; a message's length. A wallet holding the owner's own key is skipped: the agent could sign as its owner. |

## MCP login

A login entry has `mcp.url` and no value of the owner's.

1. The owner starts the login: `POST /_seal/credentials/login {name}` (owner-signed).
2. sealed reads the server's protected resource metadata (RFC 9728, from the 401's `WWW-Authenticate` or the well-known path), then the authorization server's metadata (RFC 8414 or OpenID). It registers itself as a public client (RFC 7591) unless the entry gives a `client_id`, and answers with an authorization link carrying PKCE (S256), the `resource` indicator and a one-time `state`.
3. The owner opens the link and consents. The browser returns to this agent's `<public URL>/_seal/oauth/callback`; the `state` (valid 10 minutes, used once) binds the code to that login. sealed exchanges the code with the verifier only it holds.
4. The entry then serves the access token where the owner allowed it (Bearer on the server's host). Until then `GET /credentials` lists it with `status: awaiting_login`; from then on with `logged_in_at`, the agent's events show `entry_added`, and a `login` request for it is answered. sealed refreshes it a minute before it expires (halfway through a lifetime under two minutes, never sooner than 10 seconds), keeps the rotated refresh token, and writes the login back. A refused refresh token (a refusal answered with status 200 included), or refreshes that keep failing, become a `login` request for the owner.
5. To disconnect, the owner calls `POST /_seal/credentials/disconnect {name}`: when the authorization server's metadata names a `revocation_endpoint`, sealed asks it to revoke the refresh token, then the access token (RFC 7009); either way it forgets them and the entry waits for a login again. If a new set redefines or removes the entry, or the owner changes, while this runs, sealed forgets nothing and answers 409 `changed` with whether the server revoked the tokens it held when the disconnect began. The client then removes the entry. The CLI calls these `cred <agent> connect` and `disconnect`.

The agent configures the MCP server with the header `Authorization: Bearer [[credential:<name>]]`.

A login entry is checked when the set loads as it will be served after the login, and skipped if the proxy could not serve it.

- **Discovery.** Metadata is read over https only. The protected resource metadata's `resource` must name this server (same origin; its path the server's or a whole-segment prefix of it, RFC 9728 §3.3), and authorization server metadata that names another `issuer` is not used (RFC 8414 §3.3). Revocation is used only when its endpoint is on the token endpoint's host.
- **Client secret.** A `client_secret_entry` is read again at each use (the code exchange, each refresh, revocation) and never kept with the login: it must be loaded, unexpired and not a signing key, and when that entry lists hosts the token endpoint's host must be one of them. Once it is not, refreshes stop and the owner gets a `login` request.
- **Callback.** The `state` is checked first. When the authorization server's redirect names its issuer (`iss`, RFC 9207) it must be the server the owner was sent to, and when the server's metadata says it always names it, it must; otherwise the code is not exchanged.
- **Order.** A login completes after a refresh of the same entry already running, so the newer login stands. A disconnect asks only the revocation endpoint kept from the login, finishes asking even if the owner's client gives up, and writes the disconnect back, so a restart does not bring the login back.
- **Scopes.** With no `scopes` in the entry, sealed asks for the ones the server's metadata lists; the owner sees them on the consent screen.

## The owner's side

Owner routes on the agent (`/_seal/*`, through `:8080`) take `X-Auth-Message` / `X-Auth-Signature` (EIP-191 by the live on-chain owner), grammar `<tag>:0x<sealId>:<unix seconds>[:<sha256(body)>]:<audience>`. A signed `POST` is taken once: the same message sent again within its freshness window answers 409. Each request records its signer as the owner, so a new owner's first request, a read included, clears the previous owner's state before anything of it is served; a request whose owner lookup was overtaken by a later one naming someone else answers 503.

| Route | Tag | |
|---|---|---|
| `GET` / `POST /_seal/credentials` | `0GSealCredentials` | list loaded entries / load a signed set (409 `stale_version` for an older one) |
| `GET /_seal/credentials/pending` | `0GSealCredPending` | requests waiting: sealed's `facts` apart from the agent's `reason` |
| `POST /_seal/credentials/decide` | `0GSealCredDecide` | `{auth_req_id, decision: "once" \| "deny", approval?, signature?}` |
| `GET /_seal/credentials/audit?after=` | `0GSealCredAudit` | what the agent did (fills, token requests, signatures, reveals, logins, writebacks), and which entries a set skipped and why: never values. Oldest first, in three lists of the last 1000 each: proxy uses; wallet signatures; and the rest (the owner's decisions, logins, disconnects, loads, what sealed did itself), so what the agent can cause never pushes the owner's records out. A record that falls out of its list is counted by kind (operation, entries, host, result), never dropped without a trace. What the agent can repeat at will (token requests, refreshes, writebacks, failed signatures, reveals allowed in advance) and the successful uses of what sealed supplies itself (`sealed:` entries, e.g. the framework's inference key) are one record per kind with `count`, `first` and the latest `ts`; each operation and result (the part before a colon) has its own budget of 32 kinds, then further kinds of it are counted by result alone, so flooding one result blurs only that result's later kinds; past 1024 kinds in all, every operation's new kinds are counted by result alone. Hosts and names are cut to a bounded length, control and format characters shown as `?`, and a method other than the standard HTTP ones is recorded as `OTHER`. Kept across stop/start with the owner it belongs to and restored only for that owner; a persisted log a boot cannot read is left as it is and not written over |
| `POST /_seal/credentials/login` | `0GSealCredLogin` | start an MCP login; `{authorize_url}` |
| `POST /_seal/credentials/disconnect` | `0GSealCredDisconnect` | end an MCP login: revoke at the server when it offers that, forget the tokens; `{revoked, note}`, or 409 `{code: "changed", message, revoked, note}` when the entry changed meanwhile |
| `GET /_seal/oauth/callback` | none | the browser's return from a login |

**Approvals.** "Once" is an EIP-712 `Approval(bytes32 sealId,bytes32 bootId,bytes32 authReqId,bytes32 requestDigest,uint64 expiresAt)` signed by the live owner (same domain), bound to this boot, this request and its digest, used once (the SDK gives it 1 hour, never past the request's own expiry). sealed takes a decision only for a request still waiting, so an approval sent again after its use is refused. Requests wait 72 hours and do not survive a restart; the agent asks again. A request to add a credential or log in is answered by doing it. Unanswered means no.

**Attestor routes** (owner messages EIP-191; see `attestor/README.md`):

| Route | Message | |
|---|---|---|
| `GET` / `POST /credentials` | `AgenticID.Credentials.v1:0x<seal>:<ts>:<base version>[:<sha256(body)>]` | read / compare-and-swap write; a write carries over the writebacks of entries it keeps with `writeback: true` |
| `POST /credentials/writeback` | agentSeal signature (above) | from the current boot only |
| `GET /credentials/pending` | `AgenticID.CredentialsPending.v1:<owner>:<ts>` | pending counts of every agent the signer owns |
| `GET` / `POST /credentials/notify` | `AgenticID.CredentialsNotify.v1:<owner>:<ts>[:<sha256(body)>]` | the owner's notification address |

`/provision` hands each boot `{document, owner_epoch}` with its writebacks, ECIES-encrypted to the container. Status reports (`StatusReport.v3`) carry the pending count; when it rises the attestor emails the owner's address (at most once per `ATTESTOR_NOTIFY_COOLDOWN_SECONDS` per agent), naming the agent and the count, never what the agent wrote. An hourly sweep reminds the owner a week before an entry's `expires_at`.

The SDK is `ag.credentials` (`sdk/typescript/src/Credentials.ts`); the CLI is `0g-agentdna cred` (`docs/cli-reference.md`).

## What is outside

- **Responses and committed data.** HTTP responses relayed through `:8080` (registered services, framework routes, event streams, the synthesized `/v1/responses` and its stored result, `/hello`'s service list) are scrubbed of every value sealed holds (a header whose name holds one, in any letter case, is dropped), before a serve-proof is computed; a reply to an upgrade request that is not `101` is scrubbed like any other (trailers too), and an accepted WebSocket upgrade is relayed as it is. The framework's note on a compaction (`/_seal/compact`) is scrubbed before the owner or the public log sees it. A value a model streams in pieces is scrubbed in the stored result, not in the pieces as they stream. What sealed commits on chain is scrubbed the same way (leaf roles, manifest files, files inside directory archives); drift is judged on the scrubbed content. A value removed from sealed (a set without it, an owner change) is still scrubbed, never filled, until sealed restarts (the last 1024 values of owner and sealed entries, and apart from them the last 1024 of derived entries; at most 32 per name).
- **Tools that ignore the proxy.** A tool that ignores `HTTPS_PROXY` or pins its certificates reaches its host directly with the placeholder and fails; it can use the explicit form, or a revealed value.
- **Tokens from ordinary API calls.** A token an ordinary API call returns (not a token request) reaches the agent as returned, unless it has one of the well-known formats the proxy masks: then the agent gets `[[redacted]]` and cannot use it, and the way to obtain it is a token request.
- **Use is not limited.** Within a key's own permissions the agent may do anything with it, including deriving new keys or signing arbitrary content with a signing entry.
- **Rollback after a reset.** sealed refuses a lower set version across stop/start, but after a reset or a new sandbox it trusts the attestor to serve the latest set. Revoke a removed key at its provider too.
- **The ownership epoch comes from the attestor.** The owner's client signs a set for the epoch the attestor reports, and sealed takes a pushed set without checking its epoch. A made-up later epoch, once signed and loaded, makes the honest sets read as older: on the agent until a reset, on the owner's machine until its record is removed.
- **Other channels.** Non-HTTP protocols and browser sessions need a revealed value; response redaction is best effort.
- **What the agent was given goes with it.** A value the previous owner revealed to the agent, and whatever the agent wrote into its memory or files, can be in the agent state committed on chain, which a transfer hands to the new owner with the agent.
- **The framework's own traffic.** `HTTPS_PROXY` is in the framework's environment too. A host no entry names is tunnelled untouched, but the proxy refuses private-network addresses, so a framework whose HTTP client follows `HTTPS_PROXY` cannot reach a model (or anything else) on a private address.
