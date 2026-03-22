CREATE TABLE IF NOT EXISTS ballots (
    ballot_id        TEXT PRIMARY KEY,
    encrypted_ballot JSONB NOT NULL,
    zk_proofs        JSONB NOT NULL,
    submitted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    position         BIGINT NOT NULL UNIQUE,
    merkle_root_sha  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS signed_roots (
    id              BIGSERIAL PRIMARY KEY,
    signed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    root_sha256     TEXT NOT NULL,
    ballot_count    BIGINT NOT NULL,
    signature       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ballots_position ON ballots(position);
