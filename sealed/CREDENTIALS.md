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
| `expires_at`, `description` | Unix seconds; free text shown to the agent |

One entry is one value used in several places: its positions hold on each of its hosts. A GitHub token, for one, serves both the API (`api.github.com`, `Authorization: Bearer`) and git (`github.com`, Basic) when the entry lists both hosts and both positions. A preset (`preset=<name>` in the CLI; `cred presets` lists them with where to create each key) is a shortcut the client expands into hosts, positions and a description; sealed never sees it.

The **value** is ECIES-encrypted to the agent's agentSeal key in the client. Its plaintext binds it: `{"v":1,"type":"credential","owner","seal_id","chain_id","name","value"}`; sealed refuses one bound to another owner, agent, chain or name.

The owner signs the whole set once, EIP-712:

```
domain   {name: "AgentDNA Credentials", version: "1", chainId, verifyingContract: AgenticID}
CredentialSet(bytes32 sealId,uint64 ownerEpoch,uint64 version,Entry[] entries)
Entry(string name,bytes32 defHash)
```

The same digest is pinned in sealed (`TestDigestVectors`), the attestor and the SDK.

- **Version**: each write is `version + 1`, a compare-and-swap at the attestor. sealed remembers the highest version it loaded (in its state directory, kept across stop/start) and refuses a lower one.
- **Ownership epoch**: the block of the agent's last transfer. A set signed for an earlier epoch is refused everywhere, so a previous owner's set can never be reinstated. On a transfer the attestor drops the set and sealed clears every entry, request and approval (it re-reads the on-chain owner every minute).
- **Per-entry checks**: an entry whose definition does not match its signed hash, whose value does not match `value_hash`, or that the proxy cannot serve is skipped with its reason; the rest of the set loads.

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

- requires the per-boot token; requires the CONNECT target, the TLS SNI and the `Host` to agree;
- refuses to dial private, loopback, link-local, multicast, unspecified and metadata addresses; never follows a redirect;
- fills each placeholder only for an allowed host and position, and refuses the whole request otherwise; never fills `Host`, `Content-Length`, `Transfer-Encoding`, `Cookie` or `Proxy-*`;
- reads a body only on a host where some entry may fill a body field or signs requests, and there only up to 64 KiB (a placeholder in a larger body is refused); anywhere else a body is relayed as it is, placeholder text and all, since nothing could be filled in it;
- asks upstream for an unencoded body, and redacts every value it holds from response headers and the streamed body (raw, percent-encoded, JSON-escaped, base64 at each alignment; values under 6 bytes are not redacted), and masks, best effort, tokens of well-known formats it does not hold (GitHub, GitLab, Slack, Stripe, `sk-` keys, Hugging Face, Google API keys, npm, Notion) as `[[redacted]]`; WebSocket frames are masked in place, length kept. What sealed itself sends on (registered services, committed data, below) is scrubbed of the values it holds only.

A response to a request in which the proxy filled a value carries `X-Seal-Credential-Filled: <entry names>`: a service that echoes the request shows the placeholder again, since the value is hidden on the way back, and this header is how the agent tells a filled request from one that was not. A host no entry names is tunnelled, so nothing is filled there and there is no error either; its responses never carry the header.

A refusal is an HTTP error with `X-Seal-Credential-Error: <code>` and a JSON body `{code, message}` that never carries a value. Codes: `unknown_entry`, `expired` (410), `token_only`, `position_not_allowed`, `host_not_allowed`, `forbidden_header`, `body_too_large`, `private_address`, `bad_request`, `bad_target`, `target_mismatch`, `proxy_auth`, `not_allowed`, `sign_failed`, `upstream_error`, `internal`.

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

**Reveal** (`$SEAL_CRED_REVEAL_SOCKET`, a socket of its own, so its access can be set apart from the routes above): `POST /credentials/reveal {name, reason}`. With `allow_reveal` it answers `{value}`. Otherwise 403 `authorization_pending` with an `auth_req_id`; the owner decides; the agent sends the same request again. 403 `access_denied` is a refusal. A login entry reveals its access token, never its stored login state.

## The framework's inference key

The key a framework calls its model with (the owner's `SEAL_SECRET_ENV`, sealed to agentSeal and opened by sealed after provisioning, or the legacy `API_KEY`) is held by sealed for **0g-harness on a platform-routed model** (0g-compute): it becomes the entry `sealed:inference`, filled in only as `Authorization: Bearer {v}` or `x-api-key: {v}` on the router's host. 0g-harness gets `SEAL_MODEL_API_KEY=[[credential:sealed:inference]]` and `SEAL_MODEL_BASE_URL` set to the router through the proxy's explicit form, so neither it nor any tool it runs can read the key. Nothing reveals that entry, and an owner change drops it with the rest. Adapters do this through `RuntimeContext.CredHold`.

Everywhere else the framework still receives the key itself, and its tools can read it: 0g-harness on a framework built-in provider (`openai`, `anthropic`), openclaw and hermes (`OPENAI_API_KEY` / `ANTHROPIC_API_KEY`; hermes also writes it into its config file), and prime (`SEAL_MODEL_API_KEY`).

## Token requests and rotation

A `token_request` is a template sealed follows; the agent never sees the request or the response.

| Field | |
|---|---|
| `url`, `encoding` | the token endpoint; `form` (default) or `json` |
| `fields` | field → template: `{v}` is this entry's value, `{cred:<name>}` another entry's (a `jwt` entry stands for a freshly minted token; another signing key is refused) |
| `basic_auth` | `{username_entry, password_entry}` |
| `params` | parameters the agent may add (e.g. `scope`) |
| `take` | response fields kept as derived entries: `field`, `name`, `hosts`, `positions`, `expires_in_field`; named `derived:<entry>.<field>` unless named |
| `rotate_field` | e.g. `refresh_token`: a new value in the response replaces the entry's value |

Token requests for one entry run one at a time. A failure answers `token_request_failed` with the OAuth error code only.

**From the CLI.** `preset=oauth2-refresh` (the value is a refresh token; it rotates and is written back) and `preset=oauth2-client` (the value is a client secret) build the standard OAuth 2.0 template from `token_url=`, `client_id=` and `api_host=`, with optional `scope=` (which the agent may also pass) and, for a refresh token whose client has a secret, `client_secret=<entry>`. The agent runs `POST /credentials/token` on the entry and uses `[[credential:derived:<entry>]]` as a Bearer token on `api_host`. Any other template goes in `token=<json>`.

**Writebacks.** A value sealed obtains (a rotated refresh token, a login) is sealed to agentSeal and posted to the attestor, signed by agentSeal over

```
CredentialWriteback.v1:<seal_id>:<name>:<def_hash>:<boot_id>:<keccak256(ciphertext)>
```

(keccak256, no EIP-191 prefix; the sign socket cannot produce it). It is bound to the entry's definition: valid while the owner's definition of that entry is unchanged, through the owner's edits to other entries, and over when the owner changes this one. The attestor stores it only from the current boot, for a definition with `writeback: true` that is still in the set. At boot sealed prefers a valid writeback to the owner's value. A failed writeback is retried in the background; if the container restarts first, that value is lost.

## Signing keys

`use: sign` entries are never written into a request.

| `signer.method` | Parameters | How it is used |
|---|---|---|
| `sigv4` | `access_key_id`, `region`, `service`, `session_token_entry?` | The proxy signs a request carrying `X-Seal-Sign: <name>`, or signs again a request an AWS tool signed with this `access_key_id` and the placeholder as its secret (the entry's hosts only). Pinned against aws-sdk-go's signer. |
| `hmac` | `message` (over `{method}` `{path}` `{query}` `{body}` `{timestamp}` `{header:<name>}`), `header` or `param`, `algorithm` (`sha256`, `sha512`, `sha1`), `encoding` (`hex`, `base64`), `prefix`, `timestamp_header` | The proxy signs a request carrying `X-Seal-Sign: <name>`. |
| `jwt` | `alg` (`RS256`, `ES256`, `HS256`), `kid`, `claims`, `ttl` (≤ 86400) | The placeholder stands for a token minted from the key, in requests and in token requests (e.g. a service account's `jwt-bearer` assertion). Minted tokens are redacted like values. |
| `wallet` | — | `POST /credentials/sign` with the sign socket's three shapes (personal message, EIP-712, transaction); returns the signature. |

## MCP login

A login entry has `mcp.url` and no value of the owner's.

1. The owner starts the login: `POST /_seal/credentials/login {name}` (owner-signed).
2. sealed reads the server's protected resource metadata (RFC 9728, from the 401's `WWW-Authenticate` or the well-known path), then the authorization server's metadata (RFC 8414 or OpenID). It registers itself as a public client (RFC 7591) unless the entry gives a `client_id`, and answers with an authorization link carrying PKCE (S256), the `resource` indicator and a one-time `state`.
3. The owner opens the link and consents. The browser returns to this agent's `<public URL>/_seal/oauth/callback`; the `state` (valid 10 minutes, used once) binds the code to that login. sealed exchanges the code with the verifier only it holds.
4. The entry then serves the access token where the owner allowed it (Bearer on the server's host). Until then `GET /credentials` lists it with `status: awaiting_login`; from then on with `logged_in_at`, the agent's events show `entry_added`, and a `login` request for it is answered. sealed refreshes it a minute before it expires, keeps the rotated refresh token, and writes the login back. A refused refresh token becomes a `login` request for the owner.

The agent configures the MCP server with the header `Authorization: Bearer [[credential:<name>]]`.

## The owner's side

Owner routes on the agent (`/_seal/*`, through `:8080`) take `X-Auth-Message` / `X-Auth-Signature` (EIP-191 by the live on-chain owner), grammar `<tag>:0x<sealId>:<unix seconds>[:<sha256(body)>]:<audience>`:

| Route | Tag | |
|---|---|---|
| `GET` / `POST /_seal/credentials` | `0GSealCredentials` | list loaded entries / load a signed set (409 `stale_version` for an older one) |
| `GET /_seal/credentials/pending` | `0GSealCredPending` | requests waiting: sealed's `facts` apart from the agent's `reason` |
| `POST /_seal/credentials/decide` | `0GSealCredDecide` | `{auth_req_id, decision: "once" \| "deny", approval?, signature?}` |
| `GET /_seal/credentials/audit?after=` | `0GSealCredAudit` | what the agent did (fills, token requests, signatures, reveals, logins, writebacks), and which entries a set skipped and why: never values. The last 1000 records, oldest first; the successful uses of what sealed supplies itself (`sealed:` entries, e.g. the framework's inference key) are one record each with `count`, `first` and the latest `ts` |
| `POST /_seal/credentials/login` | `0GSealCredLogin` | start an MCP login; `{authorize_url}` |
| `GET /_seal/oauth/callback` | none | the browser's return from a login |

**Approvals.** "Once" is an EIP-712 `Approval(bytes32 sealId,bytes32 bootId,bytes32 authReqId,bytes32 requestDigest,uint64 expiresAt)` signed by the live owner (same domain), bound to this boot, this request and its digest, used once (the SDK gives it 1 hour, never past the request's own expiry). Requests wait 72 hours and do not survive a restart; the agent asks again. A request to add a credential or log in is answered by doing it. Unanswered means no.

**Attestor routes** (owner messages EIP-191; see `attestor/README.md`):

| Route | Message | |
|---|---|---|
| `GET` / `POST /credentials` | `AgenticID.Credentials.v1:0x<seal>:<ts>:<base version>[:<sha256(body)>]` | read / compare-and-swap write; a write carries over writebacks whose definitions it keeps |
| `POST /credentials/writeback` | agentSeal signature (above) | from the current boot only |
| `GET /credentials/pending` | `AgenticID.CredentialsPending.v1:<owner>:<ts>` | pending counts of every agent the signer owns |
| `GET` / `POST /credentials/notify` | `AgenticID.CredentialsNotify.v1:<owner>:<ts>[:<sha256(body)>]` | the owner's notification address |

`/provision` hands each boot `{document, owner_epoch}` with its writebacks, ECIES-encrypted to the container. Status reports (`StatusReport.v3`) carry the pending count; when it rises the attestor emails the owner's address (at most once per `ATTESTOR_NOTIFY_COOLDOWN_SECONDS` per agent), naming the agent and the count, never what the agent wrote. An hourly sweep reminds the owner a week before an entry's `expires_at`.

The SDK is `ag.credentials` (`sdk/typescript/src/Credentials.ts`); the CLI is `0g-agentdna cred` (`docs/cli-reference.md`).

## What is outside

- **Responses and committed data.** HTTP responses relayed through `:8080` (registered services, framework routes, event streams, the synthesized `/v1/responses`) are scrubbed of every value sealed holds, before a serve-proof is computed; WebSocket upgrades there are relayed as they are. What sealed commits on chain is scrubbed the same way (leaf roles, manifest files, files inside directory archives); drift is judged on the scrubbed content. A value removed from sealed is no longer known and is no longer scrubbed.
- **Tools that ignore the proxy.** A tool that ignores `HTTPS_PROXY` or pins its certificates reaches its host directly with the placeholder and fails; it can use the explicit form, or a revealed value.
- **Tokens from ordinary API calls.** A token an ordinary API call returns (not a token request) reaches the agent as returned, unless it has one of the well-known formats the proxy masks: then the agent gets `[[redacted]]` and cannot use it, and the way to obtain it is a token request.
- **Use is not limited.** Within a key's own permissions the agent may do anything with it, including deriving new keys or signing arbitrary content with a signing entry.
- **Rollback after a reset.** sealed refuses a lower set version across stop/start, but after a reset or a new sandbox it trusts the attestor to serve the latest set. Revoke a removed key at its provider too.
- **Other channels.** Non-HTTP protocols and browser sessions need a revealed value; response redaction is best effort.
- **The framework's own traffic.** `HTTPS_PROXY` is in the framework's environment too. A host no entry names is tunnelled untouched, but the proxy refuses private-network addresses, so a framework whose HTTP client follows `HTTPS_PROXY` cannot reach a model (or anything else) on a private address.
