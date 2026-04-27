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
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS provisioned_at TIMESTAMPTZ;

-- Container-pubkey binding for /provision freshness bypass on restart.
-- The pubkey is what the container sent on first /provision; the MAC is
-- HMAC(binding_key, seal_id || pubkey) where binding_key is HKDF-derived
-- from the attestor master secret. DB tampering with `container_pubkey`
-- alone is detectable via MAC mismatch — attacker without the master
-- secret can't forge a valid (pk, mac) pair.
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS container_pubkey     BYTEA;
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS container_pubkey_mac BYTEA;

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
