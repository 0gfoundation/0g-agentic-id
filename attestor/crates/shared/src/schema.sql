-- Attestor v0 bootstrap schema.
-- Executed on api/worker/indexer startup; safe to re-run.

CREATE TABLE IF NOT EXISTS deployments (
    seal_id                  BYTEA PRIMARY KEY,
    agent_seal_addr          BYTEA NOT NULL,
    owner                    BYTEA NOT NULL,
    agent_id                 TEXT,           -- U256 decimal string, NULL until mint confirmed

    agent_uri                TEXT  NOT NULL DEFAULT '',
    agent_card               JSONB NOT NULL DEFAULT '{}'::jsonb,
    i_data                   JSONB NOT NULL DEFAULT '[]'::jsonb,

    phase                    TEXT  NOT NULL DEFAULT 'pending',
    storage_stage            JSONB NOT NULL DEFAULT '{"state":"not_started"}'::jsonb,
    mint_stage               JSONB NOT NULL DEFAULT '{"state":"not_started"}'::jsonb,
    container_stage          JSONB NOT NULL DEFAULT '{"state":"not_started"}'::jsonb,

    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_deployments_owner    ON deployments (owner);
CREATE INDEX IF NOT EXISTS idx_deployments_agent_id ON deployments (agent_id);
CREATE INDEX IF NOT EXISTS idx_deployments_phase    ON deployments (phase);

-- Columns added after initial schema. Use IF NOT EXISTS so the file
-- remains idempotent across schema versions.
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS sandbox_id TEXT;
-- Framework name from the deploy-time iData binding (role="framework"),
-- validated against /config's supported list. NULL on rows minted before
-- this column existed. Read by clients so nobody has to REMEMBER which
-- harness an agent runs (reset defaults, chat model selector, sealed image).
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS framework TEXT;
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS provisioned_at TIMESTAMPTZ;

-- Container record. The first accepted /provision of a container records
-- what its v3 certificate established: the container key, its image hash and
-- the provider instance that signed it (chain, TappRegistry, app id,
-- registration epoch, recovered provider signer). Later boots of the same
-- container send no certificate and are checked against these columns. The
-- seven columns are written in one transaction and cleared together with
-- every new boot ticket, container reset and ownership revocation.
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS container_pubkey          BYTEA;
ALTER TABLE deployments DROP COLUMN IF EXISTS container_pubkey_mac;
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS container_image_hash      BYTEA;
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS provider_chain_id         BIGINT;
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS provider_registry_address BYTEA;
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS provider_app_id           TEXT;
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS provider_registered_at    BIGINT;
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS provider_signer           BYTEA;
-- A key recorded before the certificate columns existed has no certificate
-- behind it; its container must be recreated.
UPDATE deployments SET container_pubkey = NULL
 WHERE container_pubkey IS NOT NULL AND container_image_hash IS NULL;

-- Provision timeout deadline. Written when `sandbox.create` succeeds
-- (handle_deploy / handle_sandbox_recreate). The worker sweep loop
-- flips `container_stage` to Failed once `now > provision_deadline`
-- AND the stage is still Submitted — caters to the case where the
-- container never got far enough to call /provision at all.
-- NULL means "no deadline tracked" (legacy rows or no sandbox yet).
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS provision_deadline TIMESTAMPTZ;

-- Last /provision validation error visible to operators / dashboard.
-- Written on every /provision rejection (bad pubkey shape, signer
-- mismatch, image_hash not whitelisted, stale attestation, etc.) so
-- "still booting" vs "broken" is distinguishable in the UI without
-- having to grep logs. NULL until first failure.
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS last_provision_error    TEXT;
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS last_provision_error_at TIMESTAMPTZ;

-- Partial index for the deadline sweep: only Submitted rows with a
-- deadline are candidates, vastly fewer than the table size in the
-- common case. The cast to text on the JSONB stage probe is what
-- the sweep query uses.
CREATE INDEX IF NOT EXISTS idx_deployments_provision_deadline
    ON deployments (provision_deadline)
    WHERE provision_deadline IS NOT NULL
      AND container_stage->>'state' = 'submitted';

-- Container heartbeat freshness. sealed POSTs /status every 5 min; the
-- /status handler bumps `last_heartbeat`. A worker sweep flips
-- container_stage to Failed when the gap exceeds the staleness
-- threshold (15 min), surfacing sandbox-side terminations (e.g.
-- balance exhaustion) that attestor would otherwise miss.
-- Failed (not Stopped) because the container disappeared on its own
-- and can only be Recreated, never Resumed.
-- NULL on rows that haven't yet received a heartbeat (pre-running).
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS last_heartbeat TIMESTAMPTZ;

-- Partial index for the sweep: only running rows with a heartbeat
-- recorded are candidates. Mirrors the provision-deadline pattern.
CREATE INDEX IF NOT EXISTS idx_deployments_last_heartbeat
    ON deployments (last_heartbeat)
    WHERE last_heartbeat IS NOT NULL
      AND phase = 'running';

-- Agent-declared services moved off the heartbeat onto /hello (signed
-- envelope, fresh per call). Drop the column on the next startup —
-- attestor no longer reads or writes it, and a stale UPDATE from a
-- mid-version rollback would just write into nothing anyway.
ALTER TABLE deployments DROP COLUMN IF EXISTS services;

-- idempotency does NOT FK to deployments — /deploy reserves idempotency
-- before inserting the deployment row, so a FK would fail. The idempotency
-- record is a hint; loss-of-sync with deployments is recoverable.
CREATE TABLE IF NOT EXISTS idempotency (
    key        TEXT PRIMARY KEY,
    seal_id    BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Drop the FK if an earlier schema version created it.
ALTER TABLE idempotency DROP CONSTRAINT IF EXISTS idempotency_seal_id_fkey;

CREATE TABLE IF NOT EXISTS jobs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    payload      JSONB,
    status       TEXT  NOT NULL DEFAULT 'pending',   -- pending | running | done | failed
    picked_by    TEXT,
    error        TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    picked_at    TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_jobs_status_created ON jobs (status, created_at);

-- `payload` is plain JSON; the database lives on the tapp FDE volume. Only a
-- pending row holds one: claiming the job, or failing it before it runs,
-- clears it. `kind` and `seal_id` keep a running job identifiable for the
-- reaper; `expires_at` is the owner envelope expiry of a job that only relays
-- that envelope (NULL: the job does not expire); `heartbeat_at` is the
-- worker's liveness stamp while the job runs. `reap_cause` marks a job the
-- reaper failed ('abandoned' | 'expired'); `reap_settled_at` records that its
-- follow-up ran. The reaper retries rows with a cause and no settlement, and
-- the retention sweep keeps them. Payloads written as encrypted envelopes by
-- earlier releases fail as undecodable when claimed (drain the queue before
-- upgrading; see the attestor README).
ALTER TABLE jobs ALTER COLUMN payload DROP NOT NULL;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS kind            TEXT;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS seal_id         BYTEA;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS expires_at      TIMESTAMPTZ;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS heartbeat_at    TIMESTAMPTZ;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS reap_cause      TEXT;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS reap_settled_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS indexer_checkpoints (
    name       TEXT PRIMARY KEY,
    last_block BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Clone retry recipe (issue #147): the static params needed to re-drive a
-- failed clone under the same sealId. NULL on deploy rows.
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS clone_params JSONB;

-- ── Owner settings document (issue: owner configuration channel) ────────
--
-- ONE document per agent, authored by the owner, stored here as an OPAQUE
-- blob. attestor never parses it, never validates its contents and never
-- logs them: all meaning lives in the sealed container
-- (`sealed/internal/settings`). That is the point — widening the settings
-- vocabulary (a new provider, a new framework knob) must never require an
-- attestor change, so nothing here may grow knowledge of what a field means.
--
-- Deliberately NOT on chain: configuration is re-suppliable (an owner
-- re-picks a model in ten seconds), memory is not. Only the latter earns
-- chain storage.
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS settings JSONB;

-- Last document a container actually BOOTED on: promoted from `settings`
-- when the container reports its post-boot success (`POST /status`
-- status=running while the container track was not already Confirmed).
-- Last-known-good lives server-side, not on the container's disk, because
-- the dangerous case is an owner pushing a document that prevents boot AND
-- the container being recreated — which wipes any local copy. Two framework
-- adapters hard-fail startup without a usable model pin, so that combination
-- would take the agent offline with nothing to fall back to. Also opaque:
-- attestor copies bytes, it does not read them.
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS settings_last_good JSONB;

-- Monotonic counter of accepted settings writes. It is also the CAS token:
-- an owner write carries the version it believes is current (`base_version`
-- in the signed message) and lands only if it still matches, so a captured
-- request cannot be replayed to reinstate a superseded document and two
-- clients editing the same agent cannot silently overwrite each other.
-- Counts writes; says nothing about the contents, which attestor does not
-- inspect. 0 = never configured.
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS settings_version BIGINT NOT NULL DEFAULT 0;

-- The version `settings_last_good` holds, i.e. the newest document a
-- container has actually BOOTED on. Promotion is keyed on this and nothing
-- else: a `running` report promotes only while
-- `settings_confirmed_version < settings_version`, which makes it idempotent
-- by construction — the 5-minute heartbeat repeats the same report and must
-- not be able to bless a document no boot exercised. (The earlier rule
-- inferred "this is the post-boot report" from the container track not being
-- Confirmed; several paths demote a still-running container out of Confirmed
-- without any boot, so that inference promoted documents nothing had run.)
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS settings_confirmed_version BIGINT NOT NULL DEFAULT 0;

-- How many boots have been served the current unconfirmed document. Bumped
-- by `/provision` while `settings_version > settings_confirmed_version`,
-- reset to 0 whenever a document is written or promoted. Past the first
-- attempt `/provision` serves `settings_last_good` instead: the first boot
-- after a push gets the new document, a container that keeps coming back
-- without ever confirming gets the last one that worked. Keyed on repeated
-- attempts rather than on an error report, because an error report arrives
-- on every failing heartbeat — rolling back there made it impossible to land
-- a configuration change while an agent is unhealthy, which is exactly when
-- an owner most needs to.
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS settings_attempts INT NOT NULL DEFAULT 0;
-- The boot (sealed's per-PID-1 boot_id) that made the last counted attempt.
-- A retry of /provision by that same boot is not counted again, so it is
-- served the same document; only a container that comes back as a new boot
-- moves the count past the first attempt.
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS settings_attempt_boot BYTEA;


-- Global provider revisions, scoped to the deployment environment. Exact signed
-- bytes and history survive API restarts and are shared by all replicas.
-- Lock parent deployments before its status child, matching lifecycle transactions.
-- Only the latest attested boot may report status. Its opaque status token is
-- encrypted to the container; only the token's SHA-256 is stored here.
CREATE TABLE IF NOT EXISTS container_status_bindings (
    seal_id BYTEA PRIMARY KEY REFERENCES deployments(seal_id) ON DELETE CASCADE,
    binding_hash BYTEA NOT NULL CHECK (octet_length(binding_hash) = 32)
);

-- Lifecycle authorization remains after stop; a resume reuses its ticket.
ALTER TABLE container_status_bindings ALTER COLUMN binding_hash DROP NOT NULL;
ALTER TABLE container_status_bindings ADD COLUMN IF NOT EXISTS generation BIGINT NOT NULL DEFAULT 0;
ALTER TABLE container_status_bindings ADD COLUMN IF NOT EXISTS ticket_hash BYTEA;
ALTER TABLE container_status_bindings ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE container_status_bindings ADD COLUMN IF NOT EXISTS boot_started_at BIGINT NOT NULL DEFAULT 0;
ALTER TABLE container_status_bindings ADD COLUMN IF NOT EXISTS boot_id BYTEA;
ALTER TABLE container_status_bindings ADD COLUMN IF NOT EXISTS authorized_owner BYTEA;
ALTER TABLE container_status_bindings ADD COLUMN IF NOT EXISTS authorized_sandbox_id TEXT;
-- Unix seconds when the current ticket was issued. A first provision accepts
-- a certificate issued no earlier than 300 seconds before it. NULL on tickets
-- issued before this column existed: such a container must be recreated.
ALTER TABLE container_status_bindings ADD COLUMN IF NOT EXISTS ticket_issued_at BIGINT;
-- The settings document the current boot was served. A running/warning
-- report confirms the version only when its applied digest equals this one.
ALTER TABLE container_status_bindings ADD COLUMN IF NOT EXISTS served_settings_version BIGINT;
ALTER TABLE container_status_bindings ADD COLUMN IF NOT EXISTS served_settings_digest BYTEA;

CREATE TABLE IF NOT EXISTS inference_provider_registry (
    chain_id BIGINT NOT NULL,
    contract BYTEA NOT NULL CHECK (octet_length(contract) = 20),
    version BIGINT NOT NULL CHECK (version > 0),
    document TEXT NOT NULL,
    signature TEXT NOT NULL,
    publisher BYTEA NOT NULL CHECK (octet_length(publisher) = 20),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (chain_id, contract, version)
);

-- Support development databases that already have the earlier registry table.
-- Old rows without a publisher are never served.
ALTER TABLE inference_provider_registry ADD COLUMN IF NOT EXISTS publisher BYTEA;
-- No acceptance MAC: the table lives on the tapp FDE volume, and every read
-- re-checks the row's environment and version.
ALTER TABLE inference_provider_registry DROP COLUMN IF EXISTS acceptance_mac;
