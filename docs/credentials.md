# Credentials: how they work

[中文](credentials.zh.md)

This page explains, in plain terms, how AgentDNA lets an agent use the owner's third-party keys. Fields, routes and formats are defined in [`sealed/CREDENTIALS.md`](../sealed/CREDENTIALS.md); commands in [`docs/cli-reference.md`](cli-reference.md).

## The problem

An agent needs the owner's keys to do its work: a GitHub token, API keys, logins to MCP servers, AWS or wallet signing keys. But a model drives the agent: instructions hidden in a web page or a file can lead it astray, and it can make mistakes. The keys cannot simply be handed to it.

The goals:

1. the agent uses a key without seeing it;
2. tokens obtained with a key, or by logging in, stay where the key is kept;
3. a key leaves that place only with the owner's consent.

## Who does what

```
 owner's CLI ──signed credential set──▶ attestor ──handed over at each boot──▶ sealed (the keeper, in the agent's container)
                                                                    ▲            │ fills in / signs / trades for tokens
 agent (the model-driven framework) ── writes [[credential:github]] ┘            ▼
                                                                          external services (GitHub, …)
```

| Party | Does | Sees |
|---|---|---|
| owner (CLI or SDK) | sets entries; approves or refuses the agent's requests | everything it sets; the agent's requests and the audit log |
| attestor (the platform server) | keeps the owner-signed credential set and hands it to the container at each boot | the set and the definitions; values only as ciphertext |
| sealed (the trusted process in the container) | keeps the values and uses them by the owner's rules | the values, in memory |
| agent (the model and the tools it runs) | writes placeholders into requests; asks the owner | names, allowed hosts and positions; a value only when it is handed over |

## What an entry holds

| Item | Meaning |
|---|---|
| name | used in the placeholder, e.g. `[[credential:github]]` |
| value | the key itself, only in sealed |
| allowed hosts | the only hosts it is sent to; several are allowed |
| allowed positions | by default a request header (e.g. `Authorization: Bearer {v}`) and Basic auth; a query parameter, a path segment or a body field only when the owner turns it on |
| use | fill in (the default); only for trading for tokens; or a signing key |
| optional | a token-request template, a signer, an MCP server URL, an expiry, whether it may be handed over without asking |

One entry can serve several places: one GitHub token serves both the API (`api.github.com`, Bearer) and git (`github.com`, Basic).

The CLI has 12 presets: GitHub, GitLab, Hugging Face, Slack, Stripe, Gemini, OpenAI, Anthropic, OpenRouter, DeepSeek, npm, Notion. A preset fills in hosts and positions, and says where to create the key and how to keep it narrow.

## How the agent uses a key

Four ways. In the first three the value never leaves sealed.

| Way | How | Owner's consent |
|---|---|---|
| Fill in | The agent writes the placeholder into a request. The request goes through sealed's outbound proxy; sealed checks the host and position, fills in the value and sends it on. The value is turned back into the placeholder in responses. git over HTTPS works with no setup | not needed |
| Token request | The agent asks "trade entry X once"; sealed runs the template the owner signed. The token it gets becomes a new entry (`derived:…`) and the agent gets its placeholder; a rotated refresh token is written back | not needed |
| Signing | AWS SigV4, HMAC and JWT are signed by sealed as requests go out; for a wallet, the agent submits what to sign and sealed returns only the signature. A signing key is never handed over | not needed |
| Hand over | The value itself goes to the agent, for tools that do not speak HTTP or ignore the proxy | needed: allowed in advance, or approved this once |

## Requests and approval

The agent can ask for three things: a value handed over, a new credential (naming a preset), or a connection to an MCP server.

- **The agent is not blocked.** sealed records the request and answers at once that it waits for the owner; the agent can carry on with other work.
- **What the owner sees.**
  - `cred <agent> pending` lists the requests, and in a session they come up at the prompt.
  - What sealed recorded is shown apart from the agent's reason, which is marked as the agent's.
- **The choices.**
  - Approve once: a wallet signature good for this one request.
  - Always allow: the credential set is signed again.
  - Refuse.
  - Later.
- **Unanswered means no.** A request lapses after 72 hours, and does not survive a restart of the agent's container; the agent asks again.
- **Email.**
  - The owner registers one address for the wallet with `cred notify <email>`; it covers every agent the wallet owns.
  - When requests wait, the attestor emails the agent's number, the count and the command to run. A week before an entry expires, it sends a reminder.
  - The platform writes the email in a fixed form. The agent cannot touch it and never learns the address.

## Storage and versions

- **The credential set.** All the owner's entries form one list, signed with the wallet (EIP-712). Every change makes a new list with the version plus one. Values are encrypted to the agent's key on the owner's machine before they are sent; the attestor stores only ciphertext.
- **The master and the copy.** The attestor keeps the master per agent and hands it over at each boot; the running agent works from a copy. Containers get reset or replaced, so the master lives at the attestor.
- **Order of a change.** The change is stored at the attestor first, then pushed to the running agent at once. If storing fails, the CLI stops with an error and both sides keep the old version, so the agent is never ahead of the attestor.
- **Old lists stay out.**
  - The agent remembers the newest set it has used: version and a fingerprint of its content. It refuses an older set, or another set at the same version.
  - The owner's CLI keeps the same record on the owner's machine (`credential-marks.json`). Even a faulty platform server cannot get the owner to edit and sign on top of an old set.

## Logins and writebacks

- **Connecting an MCP server:** `cred <agent> connect <name> <mcp-url>`.
  - sealed finds the server's authorization server, registers with it and makes a login link; the owner consents in the browser.
  - The callback lands on the agent's own URL, so the tokens stay in sealed.
  - The agent then reaches the server with `Authorization: Bearer [[credential:<name>]]`.
- **Writebacks.**
  - A value sealed obtains itself (a login's tokens, a rotated refresh token) is encrypted and stored back at the attestor, signed with the agent's key so the attestor cannot alter it.
  - Each writeback carries a fingerprint of what it stands for: the hash of the owner's value, or the login's server, client and scopes.
  - At the next boot, sealed computes the fingerprint again from the current set and keeps the writeback when they match. Editing a description or another entry keeps a login; a new value or another server ends it.
- **Disconnecting:** `cred <agent> disconnect <name>`. When the server offers it, sealed first asks it to revoke the tokens (RFC 7009); then the entry is removed.

## The model key

The key the agent calls its model with is kept in the credential set too, one entry per provider (`model.0g-compute`, `model.anthropic`, …).

- **One key per provider, wherever you give it.** The key `login` keeps on your machine is the one every other step offers first: creating or resetting an agent, `cred <agent> set model`, and a `settings` switch to another provider each ask "use the X key saved on this machine?". Answer no and give a new key, and it replaces the one on your machine. A script that pipes a key in is asked nothing; the key it gives replaces the one on your machine.
- **Who uses it.** sealed hands the key to the framework for its model calls. The entry is not in the agent's list of credentials and cannot be revealed. Whether the agent's tools can read the key depends on the framework, as for the key given at create/reset: 0g-harness on 0g-compute never gets it (sealed fills it in on the way out); openclaw, hermes, prime and 0g-harness on `openai`/`anthropic` receive the key itself, so their tools can read it.
- **Which one.** The agent's settings choose the provider (`settings <agent> provider=…`), and sealed takes that provider's key; a key for another provider is only kept. With no provider in the settings, the one provider holding a key is used.
- **Where it may go.** To the provider's address in the platform's provider list as it was when the key was set; a later change to the list does not move the key.
- **Changing it.** `cred <agent> set model` takes effect at once: 0g-harness on 0g-compute switches without restarting; the other frameworks restart in a few seconds.
- **Switching provider.** `settings <agent> provider=X model=…` asks for X's key when the set has none, stores it, then switches.
- **Creating and resetting.** The key goes into the credential set like any other. While older images are still in use, it also travels with the create or reset request, which those images read; an image that reads the set uses the set's key. When the set already holds a key for the provider, a reset asks nothing and sends the key on your machine along for older images; with none on your machine it asks for it (Enter skips; a key given there also replaces the one in the set).
- **A key an app supplies.** An app can pay for the agent's model with its own key without showing it to you: its server seals the key to the agent, and you store it in the credential set, signing only the sealed value. It then works like a key of your own.
- **Without one.** A 0g-harness agent on 0g-compute can be created or reset with no model key: it runs, and its model calls fail until you set one. Other frameworks and other providers need a key to be created or reset.
- **Removing the key in use.** You are asked first. The agent goes back to the key given at create/reset when that one is for the same provider; otherwise it cannot call its model until there is a key. It never keeps using a key you removed.

## Transfer

- **The attestor.** When the agent is transferred, the attestor deletes the agent's credential data and tears down the old container. On dev the old container was gone within 3 seconds of the transfer landing on chain.
- **sealed, as the backstop.**
  - It looks the on-chain owner up every 10 seconds, and again before a reveal, a token request, a signature or a login when the last check is over 10 seconds old.
  - When the owner changes, it clears every credential, request and approval, and the old container closes as a whole: every route but `/hello`, `/healthz` and the public `/log` pages answers 423. Neither the previous owner nor the new one can use it.
  - The new owner resets the agent to run it in a new container.
- **Clones.** A clone is a new seal and carries no credentials.

## Trust boundaries

- **Trusted.** sealed: its image is measured and it runs in a TEE. The credential set's content rests on the owner's signature; what sealed obtains rests on the agent's signature.
- **The attestor cannot change content, but is trusted to serve the latest version.**
  - After a reset or a new sandbox, sealed can only take the version the attestor gives, and the ownership epoch is the attestor's to report.
  - Revoke a removed key at its provider too.
- **Not covered.**
  - Within a key's own permissions, the agent may use it as it likes. Set the permissions when you create the key at the provider.
  - Tools that ignore the proxy or pin certificates, non-HTTP protocols and browser sessions need a value handed over.
  - A new token returned by an ordinary API call reaches the agent as returned, except for well-known token formats, which are masked; use a token-request template to obtain one.
  - A value handed to the agent can end up in its memory or files and go with the agent to a new owner.
  - Masking responses is best effort.

## Common commands

```
0g-agentdna cred <agent>                            list entries (never values)
0g-agentdna cred <agent> set <name> preset=github   add or change one; the value is read without echo
0g-agentdna cred <agent> rm <name>                  remove one (revoke it at the provider too)
0g-agentdna cred <agent> set model [provider=<id>]  set the agent's model key (default: its settings' provider)
0g-agentdna cred <agent> rm model [provider=<id>]   remove a model key
0g-agentdna cred <agent> connect <name> <mcp-url>   connect an MCP server
0g-agentdna cred <agent> disconnect <name>          disconnect, asking the server to revoke
0g-agentdna cred <agent> reveal <name> on|off       let the agent read the value without asking
0g-agentdna cred <agent> pending                    requests waiting for you
0g-agentdna cred <agent> approve|deny [<id>]        approve once / refuse
0g-agentdna cred <agent> log                        what the agent did with its credentials
0g-agentdna cred pending                            waiting counts across every agent you own
0g-agentdna cred notify [<email>|off]               where you are emailed
0g-agentdna cred presets                            presets, and where to create each key
```

In an agent's session (`0g-agentdna <agent>`) use `/cred …`; the agent's requests come up at the prompt, and Ctrl-C or Esc cancels any question.
