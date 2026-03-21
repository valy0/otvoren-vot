CREATE TABLE IF NOT EXISTS voters (
    egn_hash     TEXT NOT NULL,
    election_id  UUID NOT NULL,
    ballot_id    TEXT NOT NULL,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    channel      TEXT NOT NULL CHECK (channel IN ('online', 'in_person')),
    PRIMARY KEY (egn_hash, election_id)
);
CREATE INDEX IF NOT EXISTS idx_voters_ballot_id ON voters(ballot_id);
