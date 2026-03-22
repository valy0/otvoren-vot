-- 003_append_only.sql
-- Enforce append-only semantics on ballots and signed_roots tables.
-- These tables are part of the public audit trail and must never be modified or deleted.

CREATE OR REPLACE FUNCTION prevent_ballot_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'ballots table is append-only: % operations are forbidden', TG_OP;
END;
$$ LANGUAGE plpgsql;

DO $$ BEGIN
    CREATE TRIGGER trg_no_update_ballots
        BEFORE UPDATE ON ballots
        FOR EACH ROW EXECUTE FUNCTION prevent_ballot_mutation();
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TRIGGER trg_no_delete_ballots
        BEFORE DELETE ON ballots
        FOR EACH ROW EXECUTE FUNCTION prevent_ballot_mutation();
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TRIGGER trg_no_truncate_ballots
        BEFORE TRUNCATE ON ballots
        FOR EACH STATEMENT EXECUTE FUNCTION prevent_ballot_mutation();
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Same protections for signed_roots table
CREATE OR REPLACE FUNCTION prevent_signed_root_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'signed_roots table is append-only: % operations are forbidden', TG_OP;
END;
$$ LANGUAGE plpgsql;

DO $$ BEGIN
    CREATE TRIGGER trg_no_update_signed_roots
        BEFORE UPDATE ON signed_roots
        FOR EACH ROW EXECUTE FUNCTION prevent_signed_root_mutation();
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TRIGGER trg_no_delete_signed_roots
        BEFORE DELETE ON signed_roots
        FOR EACH ROW EXECUTE FUNCTION prevent_signed_root_mutation();
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TRIGGER trg_no_truncate_signed_roots
        BEFORE TRUNCATE ON signed_roots
        FOR EACH STATEMENT EXECUTE FUNCTION prevent_signed_root_mutation();
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
