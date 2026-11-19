# Releasing

How a version goes from `dev` to testnet and mainnet. Each step names the
document that holds its details; this page is the order. Testnet goes first,
mainnet after it.

中文：[RELEASING.zh.md](RELEASING.zh.md)。

## 1. Ready on dev

- Everything the version ships is merged into `dev` and was tested live on
  dev's default images: agents reset onto the attestor's default snapshot,
  not onto per-agent test snapshots.

## 2. The release pull request (into `dev`)

- **Version number.** Set it in every place that carries it:
  - `sdk/typescript/package.json` and `package-lock.json`;
  - `SDK_VERSION` in `sdk/typescript/src/constants.ts`;
  - `sdk/typescript/compat/legacy/package.json` (its version and its exact
    `@0gfoundation/0g-agentdna` dependency);
  - the workspace version in `attestor/Cargo.toml` and `attestor/Cargo.lock`.
- **Release notes.** Write the version's section of
  [`CHANGELOG.md`](CHANGELOG.md) and drop `(unreleased)` from its heading. Its
  first line is the one-line summary owners see in the CLI.
- **Dates and images per environment.** In `releases/testnet.json` and
  `releases/mainnet.json`, give the version:
  - `published_at`: at or after the moment its images become that
    environment's default;
  - `migrate`: the images it replaces, one per framework, each with `until`,
    the end of its transition period. That is at least 14 days on testnet and
    30 on mainnet.

  See the attestor README, [Announcing a release](attestor/README.md#announcing-a-release).
- **Contracts, when the version changes them.** Bump each changed
  implementation's `VERSION` per
  [`contracts/UPGRADING.md`](contracts/UPGRADING.md) §1.
- **Promotion.**
  1. Once merged, `dev` goes to `main` in one squashed pull request titled
     `release: AgentDNA <version> — …`.
  2. Tag `main` with `v<version>`.
  3. Merge `main` back into `dev`.

## 3. Build from the tag

- **Images.** Build the four framework images (`sealed/images/*`) and the
  attestor image from a clean checkout of `v<version>`, and push them to the
  registry. The 0g-harness image takes the harness commit `HARNESS_REF`
  names (`sealed/images/harness/Dockerfile`).
- **Packages.** Publish the sealed programs and the harness package as assets
  of the `artifacts` release, each named by its sha256 (see
  [`sealed/LAYERS.md`](sealed/LAYERS.md), "Download"). Take the harness
  package from the image build's `harness-package` stage, as the Dockerfile's
  header says.
- **Records.** Note every digest and hash in the deployment records.

## 4. Each environment (testnet, then mainnet)

1. **Contracts**, when the version changes them: schedule and execute the
   beacon upgrades through the environment's Timelock
   (`contracts/UPGRADING.md` §2). Mainnet's delay is one day, so schedule
   ahead. Record the new addresses in `contracts/DEPLOYMENT.md` §6.
2. **Trust.** List the new image, sealed and harness hashes on the
   TrustRegistry through the Timelock (`contracts/script/TrustRegistryCalls.s.sol`;
   [`contracts/README.md`](contracts/README.md)), before the images become the
   default. A hash that is already listed makes `list` revert, so batch only
   the new ones.
3. **Snapshots.** Import the images as the environment's sandbox snapshots.
4. **Attestor.**
   - Deploy the new attestor image.
   - Point `ATTESTOR_FRAMEWORKS` / `ATTESTOR_SANDBOX_SNAPSHOT` at the new
     snapshots.
   - Generate the release file and put it on the host:

     ```
     node attestor/scripts/release-entry.mjs --changelog CHANGELOG.md \
       --params releases/<testnet|mainnet>.json --min-days <14|30> \
       --out <deployment dir>/releases/releases.json
     ```

     The compose file mounts `./releases`; set `ATTESTOR_RELEASES_FILE`.
   - Set `ATTESTOR_CLI_LATEST` and an `ATTESTOR_CLI_NOTES` line that names the
     end of the transition period and the reset: a CLI from before release
     notices shows only that line.
   - Restart the attestor and acknowledge the trust roots again.
5. **CLI.** Publish `@0gfoundation/0g-agentdna` and its compatibility package
   in the [release order](sdk/typescript/MIGRATION.md#release-order). Use the
   `next` dist-tag while another network still runs the previous version,
   and move `latest` once every network runs this one.
6. **Smoke test.** For each framework, reset one agent onto the default (no
   snapshot named). Then run `attestor/scripts/verify-agent.sh`, check
   `/hello` (it names the listed hashes), and chat once.

## 5. Transition period

- Agents on the replaced images keep running.
- Owners are told in three places:
  - **the CLI**: a notice when they open it (weekly, then daily in the last
    7 days), and `0g-agentdna releases`;
  - **the owner listing**: `migrate` on each agent to move;
  - **email**: where `ATTESTOR_NOTIFY_*` is set, one when the release is out
    and one in the last 7 days.

## 6. After `until`

- The guardian delists the replaced image hashes, which takes effect at once
  (`contracts/README.md`). An agent still on one keeps running until its
  container next boots; that boot is refused until the agent is reset.
- **Urgent releases.** An entry marked `urgent` (a security fix) may be
  delisted before `until`. Send owners a separate notice when it is.
- Remove the old snapshots once no agent runs on them.
