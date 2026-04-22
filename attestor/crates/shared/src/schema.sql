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
