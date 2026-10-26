# Upgrading to 0G AgentDNA

The npm package and CLI command are now both `0g-agentdna`. The SDK exposes
`AgentDNA` and `AgentDNAConfig`; the existing `AgenticID` and `AgenticIDConfig`
exports remain compatible. Contract names and signed-message domains retain
their protocol identifiers.

## Existing CLI users

After the matching canonical and compatibility releases are published, quit
the interactive CLI and run these commands in your system terminal:

```bash
0g-agenticid update
0g-agentdna --version
0g-agentdna
```

The old updater reads the old npm package's `latest` tag. Its compatibility
release installs the matching canonical SDK and provides both command names.
Subsequent updates use `0g-agentdna update`. When launched through the bridge,
the updater updates that bridge package so npm retains ownership of its
global command links.

Fresh installations use `npm install -g 0g-agentdna`. A development checkout
uses the repository build workflow instead of the npm self-updater.

## Local configuration

On first access, the CLI moves `~/.config/0g-agenticid/` to
`~/.config/0g-agentdna/` if the destination does not already exist.
`XDG_CONFIG_HOME` replaces `~/.config` when set. The move preserves all files
and permissions, including credentials, proof tickets, secret-env downgrade
pins, and update-hint state. No new login is required.

If both directories exist, the AgentDNA directory wins and the legacy
directory is left intact. A failed move stops with a migration error instead
of creating an empty replacement. Existing `AGENTIC_*` environment variables
remain supported.


The old credential field `apiKey` is atomically converted to
`inferenceKeys["0g-compute"]`, preserving wallet and other provider keys.
Legacy `AGENTIC_API_KEY` / `API_KEY` overrides remain compute-only. Register
additional keys with `login <provider>` inside the manager; use `settings`
then `reset` to switch an existing agent. See [providers](./PROVIDERS.md).

## SDK applications

```typescript
import { AgentDNA, type AgentDNAConfig } from '0g-agentdna';
import { sealAccount } from '0g-agentdna/seal';
```

Existing imports from `@0gfoundation/0g-agenticid-sdk` and its `/seal` subpath
continue through the compatibility package. They can be changed when updating
the application's dependencies.

## Release order

1. Align the canonical package version, lockfile, `SDK_VERSION`, and the
   compatibility manifest's version and exact dependency.
2. Run SDK typecheck and tests, and inspect both npm package contents.
3. Publish `0g-agentdna` from `sdk/typescript`.
4. Publish `@0gfoundation/0g-agenticid-sdk` from `sdk/typescript/compat/legacy`
   at the same version after its canonical dependency is available. Repeat
   this step for each release while supporting the old update path.
5. Set the attestor's `ATTESTOR_CLI_LATEST` and `ATTESTOR_CLI_NOTES` after both
   packages are available. Mention the rename in the notes for old clients.

Publishing only the new package does not upgrade clients that query the old
package. Repository changes alone do not publish either package.

中文：[MIGRATION.zh.md](MIGRATION.zh.md)。
