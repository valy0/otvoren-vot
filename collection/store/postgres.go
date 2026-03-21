package store

import (
	"context"
	"embed"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

// PostgresStore implements votermap.Store backed by PostgreSQL.
type PostgresStore struct {
	pool       *pgxpool.Pool
	electionID string
}

// New creates a new PostgresStore connected to the given database URL.
func New(ctx context.Context, databaseURL, electionID string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return &PostgresStore{pool: pool, electionID: electionID}, nil
}

// RunMigrations executes all SQL migration files.
func (s *PostgresStore) RunMigrations(ctx context.Context) error {
	sql, err := migrations.ReadFile("migrations/001_voters.sql")
	if err != nil {
		return fmt.Errorf("read migration: %w", err)
	}
	_, err = s.pool.Exec(ctx, string(sql))
	if err != nil {
		return fmt.Errorf("execute migration: %w", err)
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
func (s *PostgresStore) Record(ctx context.Context, egnHash, ballotID, channel string, timestamp int64) (string, error) {
	query := `
		WITH prev AS (
			SELECT ballot_id FROM voters WHERE egn_hash = $1 AND election_id = $2
		)
		INSERT INTO voters (egn_hash, election_id, ballot_id, submitted_at, channel)
		VALUES ($1, $2, $3, to_timestamp($4), $5)
		ON CONFLICT (egn_hash) DO UPDATE
			SET ballot_id = EXCLUDED.ballot_id,
			    submitted_at = EXCLUDED.submitted_at,
			    channel = EXCLUDED.channel
		RETURNING (SELECT ballot_id FROM prev)`

	var prev pgtype.Text
	err := s.pool.QueryRow(ctx, query, egnHash, s.electionID, ballotID, timestamp, channel).Scan(&prev)
	if err != nil {
		return "", fmt.Errorf("record voter: %w", err)
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
