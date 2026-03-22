package api

import (
	"encoding/base64"
	"net/http"
	"strconv"

	"github.com/valy0/otvoren-vot/bulletin-board/board"
	"github.com/valy0/otvoren-vot/bulletin-board/store"
	"github.com/valy0/otvoren-vot/crypto/merkle"
)

func handleListBallots(b *board.Board) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse cursor (base64-encoded position)
		var afterPos int64
		if cursor := r.URL.Query().Get("cursor"); cursor != "" {
			data, err := base64.URLEncoding.DecodeString(cursor)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid_cursor", "Invalid cursor format")
				return
			}
			afterPos, _ = strconv.ParseInt(string(data), 10, 64)
		}

		limit := 100
		if l := r.URL.Query().Get("limit"); l != "" {
			if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 1000 {
				limit = parsed
			}
		}

		records, err := b.Store().ListBallots(r.Context(), afterPos, limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "Failed to list ballots")
			return
		}

		var nextCursor string
		if len(records) == limit {
			nextCursor = base64.URLEncoding.EncodeToString(
				[]byte(strconv.FormatInt(records[len(records)-1].Position, 10)))
		}

		writeJSON(w, http.StatusOK, Response{
			Data: records,
			Meta: &Meta{
				Cursor: nextCursor,
				Total:  int64(b.Size()),
			},
		})
	}
}

func handleGetBallot(b *board.Board) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ballotID := r.PathValue("ballot_id")
		if ballotID == "" {
			writeError(w, http.StatusBadRequest, "missing_id", "Ballot ID is required")
			return
		}

		rec, proof, err := b.GetBallot(r.Context(), ballotID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "Failed to get ballot")
			return
		}
		if rec == nil {
			writeError(w, http.StatusNotFound, "ballot_not_found", "No ballot with the given ID exists")
			return
		}

		type ballotResponse struct {
			*store.BallotRecord
			MerkleProof []merkle.ProofNode `json:"merkle_proof"`
		}

		writeJSON(w, http.StatusOK, Response{
			Data: ballotResponse{BallotRecord: rec, MerkleProof: proof},
		})
	}
}

func handleGetRoot(b *board.Board) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, Response{
			Data: map[string]interface{}{
				"root_sha256":  b.Root(),
				"ballot_count": b.Size(),
				"sealed":       b.IsSealed(),
			},
		})
	}
}

func handleGetElection(electionID string) http.HandlerFunc {
	// Dev public key: Ristretto255 base point (placeholder for demo).
	// Production replaces this with the real election public key from config.
	const devPublicKey = "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"

	type party struct {
		Name       string   `json:"name"`
		Candidates []string `json:"candidates"`
	}

	devParties := []party{
		{Name: "Партия А", Candidates: []string{"Кандидат А1", "Кандидат А2"}},
		{Name: "Партия Б", Candidates: []string{"Кандидат Б1", "Кандидат Б2"}},
		{Name: "Партия В", Candidates: []string{"Кандидат В1"}},
	}

	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, Response{
			Data: map[string]any{
				"election_id": electionID,
				"public_key":  devPublicKey,
				"parties":     devParties,
				"name":        "Отворен вот — тестови избори",
				"status":      "active",
			},
		})
	}
}
