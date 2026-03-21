package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/valy0/otvoren-vot/collection/votermap"
)

type CollectionHandler struct {
	voterMap         *votermap.VoterMap
	bulletinBoardURL string
	internalAPIKey   string
}

func NewCollectionHandler(vm *votermap.VoterMap, bbURL, apiKey string) *CollectionHandler {
	return &CollectionHandler{
		voterMap:         vm,
		bulletinBoardURL: bbURL,
		internalAPIKey:   apiKey,
	}
}

type submitRequest struct {
	BallotID        string          `json:"ballot_id"`
	EncryptedBallot json.RawMessage `json:"encrypted_ballot"`
	ZKProofs        json.RawMessage `json:"zk_proofs"`
}

type submitResponse struct {
	BallotID   string `json:"ballot_id"`
	Position   int64  `json:"position"`
	MerkleRoot string `json:"merkle_root"`
	IsOverride bool   `json:"is_override"`
}

func (h *CollectionHandler) HandleSubmit(w http.ResponseWriter, r *http.Request) {
	// Extract EGN from session (in production: validate JWT from auth service)
	egn := r.Header.Get("X-Voter-EGN")
	if egn == "" {
		writeError(w, http.StatusUnauthorized, "missing_identity", "Voter identity required")
		return
	}

	var req submitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "Invalid JSON")
		return
	}
	if req.BallotID == "" {
		writeError(w, http.StatusBadRequest, "missing_ballot_id", "ballot_id is required")
		return
	}

	// Record in voter map (handles override)
	prevBallotID := h.voterMap.Record(egn, req.BallotID, "online", time.Now().Unix())

	// Forward to bulletin board (identity stripped — no EGN sent)
	bbReq := map[string]interface{}{
		"ballot_id":        req.BallotID,
		"encrypted_ballot": req.EncryptedBallot,
		"zk_proofs":        req.ZKProofs,
	}
	bbBody, _ := json.Marshal(bbReq)

	bbResp, err := h.forwardToBulletinBoard(bbBody)
	if err != nil {
		writeError(w, http.StatusBadGateway, "board_error", fmt.Sprintf("Bulletin board error: %v", err))
		return
	}

	resp := submitResponse{
		BallotID:   req.BallotID,
		Position:   bbResp.Position,
		MerkleRoot: bbResp.MerkleRoot,
		IsOverride: prevBallotID != "",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

type bbResponse struct {
	Data struct {
		Position   int64  `json:"position"`
		MerkleRoot string `json:"merkle_root"`
	} `json:"data"`
}

func (h *CollectionHandler) forwardToBulletinBoard(body []byte) (*struct {
	Position   int64
	MerkleRoot string
}, error) {
	req, err := http.NewRequest("POST", h.bulletinBoardURL+"/internal/v1/ballots", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Key", h.internalAPIKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connect to bulletin board: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("bulletin board returned %d: %s", resp.StatusCode, string(respBody))
	}

	var bbResp bbResponse
	if err := json.NewDecoder(resp.Body).Decode(&bbResp); err != nil {
		return nil, fmt.Errorf("parse bulletin board response: %w", err)
	}

	return &struct {
		Position   int64
		MerkleRoot string
	}{
		Position:   bbResp.Data.Position,
		MerkleRoot: bbResp.Data.MerkleRoot,
	}, nil
}

// HandleActiveSet returns the current active set for deduplication (used after polls close).
func (h *CollectionHandler) HandleActiveSet(w http.ResponseWriter, r *http.Request) {
	set := h.voterMap.ActiveSet()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"active_set": set,
		"size":       len(set),
	})
}

type errorResp struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := errorResp{}
	resp.Error.Code = code
	resp.Error.Message = message
	json.NewEncoder(w).Encode(resp)
}
