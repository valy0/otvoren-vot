package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/valy0/otvoren-vot/bulletin-board/board"
)

type submitBallotRequest struct {
	BallotID        string          `json:"ballot_id"`
	EncryptedBallot json.RawMessage `json:"encrypted_ballot"`
	ZKProofs        json.RawMessage `json:"zk_proofs"`
}

func handleSubmitBallot(b *board.Board) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req submitBallotRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_body", "Invalid JSON body")
			return
		}

		if req.BallotID == "" {
			writeError(w, http.StatusBadRequest, "missing_ballot_id", "ballot_id is required")
			return
		}

		result, err := b.AppendBallot(r.Context(), req.BallotID, req.EncryptedBallot, req.ZKProofs)
		if err != nil {
			if errors.Is(err, board.ErrBoardSealed) {
				writeError(w, http.StatusConflict, "board_sealed", "Board is sealed, no more ballots accepted")
				return
			}
			if errors.Is(err, board.ErrDuplicateBallot) {
				writeError(w, http.StatusConflict, "duplicate_ballot", "Ballot ID already exists")
				return
			}
			writeError(w, http.StatusInternalServerError, "internal", "Failed to append ballot")
			return
		}

		writeJSON(w, http.StatusCreated, Response{
			Data: result,
		})
	}
}
