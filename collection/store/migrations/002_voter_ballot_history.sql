CREATE TABLE IF NOT EXISTS voter_ballot_history (
    egn_hash     TEXT        NOT NULL,
    election_id  UUID        NOT NULL,
    ballot_id    TEXT        NOT NULL,
    submitted_at TIMESTAMPTZ NOT NULL,
    channel      TEXT        NOT NULL CHECK (channel IN ('online', 'in_person')),
    seq          INT         NOT NULL,
    row_hash     TEXT        NOT NULL,
    PRIMARY KEY (egn_hash, election_id, seq)
) PARTITION BY LIST (election_id);

CREATE OR REPLACE FUNCTION prevent_history_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'voter_ballot_history is append-only: % operations are forbidden', TG_OP;
END;
$$ LANGUAGE plpgsql;

DO $$ BEGIN
    CREATE TRIGGER trg_no_update
        BEFORE UPDATE ON voter_ballot_history
        FOR EACH ROW EXECUTE FUNCTION prevent_history_mutation();
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TRIGGER trg_no_delete
        BEFORE DELETE ON voter_ballot_history
        FOR EACH ROW EXECUTE FUNCTION prevent_history_mutation();
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TRIGGER trg_no_truncate
        BEFORE TRUNCATE ON voter_ballot_history
        FOR EACH STATEMENT EXECUTE FUNCTION prevent_history_mutation();
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
