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

-- Container-pubkey binding for /provision freshness bypass on restart.
-- The pubkey is what the container sent on first /provision; the MAC is
-- HMAC(binding_key, seal_id || pubkey) where binding_key is HKDF-derived
-- from the attestor master secret. DB tampering with `container_pubkey`
-- alone is detectable via MAC mismatch — attacker without the master
-- secret can't forge a valid (pk, mac) pair.
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS container_pubkey     BYTEA;
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS container_pubkey_mac BYTEA;

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
    payload      JSONB NOT NULL,
    status       TEXT  NOT NULL DEFAULT 'pending',   -- pending | running | done | failed
    picked_by    TEXT,
    error        TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    picked_at    TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_jobs_status_created ON jobs (status, created_at);

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
