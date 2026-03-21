package store

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

// BallotRecord represents a row in the ballots table.
type BallotRecord struct {
	BallotID        string          `json:"ballot_id"`
	EncryptedBallot json.RawMessage `json:"encrypted_ballot"`
	ZKProofs        json.RawMessage `json:"zk_proofs"`
	SubmittedAt     time.Time       `json:"submitted_at"`
	Position        int64           `json:"position"`
	MerkleRootSHA   string          `json:"merkle_root_sha"`
}

// SignedRootRecord represents a row in the signed_roots table.
type SignedRootRecord struct {
	ID          int64     `json:"id"`
	SignedAt    time.Time `json:"signed_at"`
	RootSHA256  string    `json:"root_sha256"`
	BallotCount int64     `json:"ballot_count"`
	Signature   string    `json:"signature"`
}

// Store provides database operations for the bulletin board.
type Store struct {
	pool *pgxpool.Pool
}

// New creates a new Store connected to the given database URL.
func New(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close closes the database connection pool.
func (s *Store) Close() {
	s.pool.Close()
}

// RunMigrations executes all SQL migration files.
func (s *Store) RunMigrations(ctx context.Context) error {
	sql, err := migrations.ReadFile("migrations/001_initial.sql")
	if err != nil {
		return fmt.Errorf("read migration: %w", err)
	}
	_, err = s.pool.Exec(ctx, string(sql))
	if err != nil {
		return fmt.Errorf("execute migration: %w", err)
	}
	return nil
}

// Pool returns the underlying pgxpool for administrative operations (tests only).
func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

// InsertBallot inserts a new ballot record. Returns the assigned position.
func (s *Store) InsertBallot(ctx context.Context, rec *BallotRecord) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO ballots (ballot_id, encrypted_ballot, zk_proofs, position, merkle_root_sha)
		 VALUES ($1, $2, $3, $4, $5)`,
		rec.BallotID, rec.EncryptedBallot, rec.ZKProofs, rec.Position, rec.MerkleRootSHA)
	return err
}

// GetBallot retrieves a ballot by ID.
func (s *Store) GetBallot(ctx context.Context, ballotID string) (*BallotRecord, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT ballot_id, encrypted_ballot, zk_proofs, submitted_at, position, merkle_root_sha
		 FROM ballots WHERE ballot_id = $1`, ballotID)

	var rec BallotRecord
	err := row.Scan(&rec.BallotID, &rec.EncryptedBallot, &rec.ZKProofs,
		&rec.SubmittedAt, &rec.Position, &rec.MerkleRootSHA)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

// ListBallots returns ballots paginated by position.
// afterPosition = 0 means start from the beginning.
// Returns up to limit records.
func (s *Store) ListBallots(ctx context.Context, afterPosition int64, limit int) ([]*BallotRecord, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT ballot_id, encrypted_ballot, zk_proofs, submitted_at, position, merkle_root_sha
		 FROM ballots WHERE position > $1 ORDER BY position ASC LIMIT $2`,
		afterPosition, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*BallotRecord
	for rows.Next() {
		var rec BallotRecord
		if err := rows.Scan(&rec.BallotID, &rec.EncryptedBallot, &rec.ZKProofs,
			&rec.SubmittedAt, &rec.Position, &rec.MerkleRootSHA); err != nil {
			return nil, err
		}
		records = append(records, &rec)
	}
	return records, rows.Err()
}

// GetBallotCount returns the total number of ballots.
func (s *Store) GetBallotCount(ctx context.Context) (int64, error) {
	var count int64
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM ballots`).Scan(&count)
	return count, err
}

// GetMaxPosition returns the highest position, or 0 if empty.
func (s *Store) GetMaxPosition(ctx context.Context) (int64, error) {
	var pos *int64
	err := s.pool.QueryRow(ctx, `SELECT MAX(position) FROM ballots`).Scan(&pos)
	if err != nil {
		return 0, err
	}
	if pos == nil {
		return 0, nil
	}
	return *pos, nil
}

// GetAllLeafHashes returns all ballot leaf data in position order.
// Used for Merkle tree computation.
func (s *Store) GetAllLeafData(ctx context.Context) ([][]byte, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT ballot_id, encrypted_ballot, zk_proofs FROM ballots ORDER BY position ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var leaves [][]byte
	for rows.Next() {
		var ballotID string
		var encBallot, proofs json.RawMessage
		if err := rows.Scan(&ballotID, &encBallot, &proofs); err != nil {
			return nil, err
		}
		// Leaf = ballot_id || encrypted_ballot || zk_proofs
		leaf := append([]byte(ballotID), encBallot...)
		leaf = append(leaf, proofs...)
		leaves = append(leaves, leaf)
	}
	return leaves, rows.Err()
}

// InsertSignedRoot inserts a new signed root record.
func (s *Store) InsertSignedRoot(ctx context.Context, rec *SignedRootRecord) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO signed_roots (root_sha256, ballot_count, signature)
		 VALUES ($1, $2, $3)`,
		rec.RootSHA256, rec.BallotCount, rec.Signature)
	return err
}

// GetLatestSignedRoot returns the most recent signed root.
func (s *Store) GetLatestSignedRoot(ctx context.Context) (*SignedRootRecord, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, signed_at, root_sha256, ballot_count, signature
		 FROM signed_roots ORDER BY id DESC LIMIT 1`)

	var rec SignedRootRecord
	err := row.Scan(&rec.ID, &rec.SignedAt, &rec.RootSHA256, &rec.BallotCount, &rec.Signature)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &rec, nil
}
