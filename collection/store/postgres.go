package store

import (
	"context"
	"embed"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valy0/otvoren-vot/collection/votermap"
)

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

//go:embed migrations/*.sql
var migrations embed.FS

// PostgresStore implements votermap.Store backed by PostgreSQL.
type PostgresStore struct {
	pool           *pgxpool.Pool
	electionID     string
	historyHMACKey []byte
}

// New creates a new PostgresStore connected to the given database URL.
// electionID must be a valid UUID.
func New(ctx context.Context, databaseURL, electionID string, historyHMACKey []byte) (*PostgresStore, error) {
	if !uuidRe.MatchString(electionID) {
		return nil, fmt.Errorf("invalid ELECTION_ID %q: must be a valid UUID (e.g. 550e8400-e29b-41d4-a716-446655440000)", electionID)
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return &PostgresStore{pool: pool, electionID: electionID, historyHMACKey: historyHMACKey}, nil
}

// RunMigrations executes all SQL migration files in sorted order,
// then creates the election-specific partition for voter_ballot_history.
func (s *PostgresStore) RunMigrations(ctx context.Context) error {
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		sql, err := migrations.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}
		if _, err := s.pool.Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("execute migration %s: %w", entry.Name(), err)
		}
	}
	// Create partition for current election
	sanitizedID := strings.ReplaceAll(s.electionID, "-", "_")
	partitionSQL := fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS voter_ballot_history_p_%s PARTITION OF voter_ballot_history FOR VALUES IN ('%s')`,
		sanitizedID, s.electionID,
	)
	if _, err := s.pool.Exec(ctx, partitionSQL); err != nil {
		return fmt.Errorf("create history partition: %w", err)
	}
	return nil
}

// Close closes the database connection pool.
func (s *PostgresStore) Close() {
	s.pool.Close()
}

// Pool returns the underlying pgxpool for administrative operations (tests only).
func (s *PostgresStore) Pool() *pgxpool.Pool {
	return s.pool
}

// Record inserts or updates a voter's active ballot, returning the previous ballot ID.
// If the voter is new, prevBallotID is empty.
//
// Uses a 3-round-trip explicit transaction:
//
//	RT1: Advisory lock — serialize per-voter to prevent concurrent override races.
//	RT2: Fetch latest history row for hash chaining.
//	RT3: CTE — upsert voters + insert history atomically.
func (s *PostgresStore) Record(ctx context.Context, egnHash, ballotID string, channel votermap.Channel, submittedAt time.Time) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// RT1: Advisory lock — serialize per-voter
	_, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1 || ':' || $2))`, egnHash, s.electionID)
	if err != nil {
		return "", fmt.Errorf("advisory lock: %w", err)
	}

	// RT2: Fetch latest history row
	var prevHash string
	var currentSeq int
	err = tx.QueryRow(ctx,
		`SELECT row_hash, seq FROM voter_ballot_history WHERE egn_hash = $1 AND election_id = $2 ORDER BY seq DESC LIMIT 1`,
		egnHash, s.electionID).Scan(&prevHash, &currentSeq)
	nextSeq := 1
	if err == pgx.ErrNoRows {
		prevHash = ""
	} else if err != nil {
		return "", fmt.Errorf("fetch prev history: %w", err)
	} else {
		nextSeq = currentSeq + 1
	}

	// Compute row hash in Go (key never touches DB)
	rowHash := votermap.ComputeRowHash(s.historyHMACKey, prevHash, egnHash, ballotID, nextSeq)

	// RT3: CTE — upsert voters + insert history
	const upsertSQL = `
		WITH prev AS (
			SELECT ballot_id FROM voters WHERE egn_hash = $1 AND election_id = $2
		),
		upsert AS (
			INSERT INTO voters (egn_hash, election_id, ballot_id, submitted_at, channel)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (egn_hash, election_id) DO UPDATE
				SET ballot_id = EXCLUDED.ballot_id,
				    submitted_at = EXCLUDED.submitted_at,
				    channel = EXCLUDED.channel
			RETURNING ballot_id
		),
		hist AS (
			INSERT INTO voter_ballot_history
				(egn_hash, election_id, ballot_id, submitted_at, channel, seq, row_hash)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		)
		SELECT ballot_id FROM prev`

	var prev pgtype.Text
	err = tx.QueryRow(ctx, upsertSQL,
		egnHash, s.electionID, ballotID, submittedAt, string(channel), nextSeq, rowHash,
	).Scan(&prev)
	if err != nil && err != pgx.ErrNoRows {
		return "", fmt.Errorf("record voter: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("commit tx: %w", err)
	}

	if prev.Valid {
		return prev.String, nil
	}
	return "", nil
}

// GetActiveBallotID returns the current active ballot ID for a voter.
// Returns ("", false, nil) if the voter has not voted.
func (s *PostgresStore) GetActiveBallotID(ctx context.Context, egnHash string) (string, bool, error) {
	var ballotID string
	err := s.pool.QueryRow(ctx,
		`SELECT ballot_id FROM voters WHERE egn_hash = $1 AND election_id = $2`,
		egnHash, s.electionID).Scan(&ballotID)
	if err == pgx.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("get active ballot: %w", err)
	}
	return ballotID, true, nil
}

// ActiveSet returns all active ballot IDs for the current election.
func (s *PostgresStore) ActiveSet(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT ballot_id FROM voters WHERE election_id = $1`, s.electionID)
	if err != nil {
		return nil, fmt.Errorf("query active set: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan ballot id: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// Size returns the number of unique voters for the current election.
func (s *PostgresStore) Size(ctx context.Context) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM voters WHERE election_id = $1`, s.electionID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count voters: %w", err)
	}
	return count, nil
}

// HasVoted returns true if the voter has already voted in the current election.
func (s *PostgresStore) HasVoted(ctx context.Context, egnHash string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM voters WHERE egn_hash = $1 AND election_id = $2)`,
		egnHash, s.electionID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check voted: %w", err)
	}
	return exists, nil
}
