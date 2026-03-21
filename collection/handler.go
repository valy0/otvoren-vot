package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/valy0/otvoren-vot/collection/votermap"
)

type CollectionHandler struct {
	voterStore       votermap.Store
	egnHMACKey       []byte
	bulletinBoardURL string
	internalAPIKey   string
	activeSetAPIKey  string
}

func NewCollectionHandler(store votermap.Store, egnHMACKey []byte, bbURL, apiKey, activeSetKey string) *CollectionHandler {
	return &CollectionHandler{
		voterStore:       store,
		egnHMACKey:       egnHMACKey,
		bulletinBoardURL: bbURL,
		internalAPIKey:   apiKey,
		activeSetAPIKey:  activeSetKey,
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
	// TODO: In production, validate JWT from Auth Service and extract EGN from claims.
	// Currently accepts X-Voter-EGN header for development only.
	egn := r.Header.Get("X-Voter-EGN")
	if egn == "" {
		writeError(w, http.StatusUnauthorized, "missing_identity", "Voter identity required. Set X-Voter-EGN header (dev) or provide a valid JWT (production).")
		return
	}
	if len(egn) != 10 {
		writeError(w, http.StatusBadRequest, "invalid_egn", "EGN must be exactly 10 digits")
		return
	}
	for _, c := range egn {
		if c < '0' || c > '9' {
			writeError(w, http.StatusBadRequest, "invalid_egn", "EGN must contain only digits")
			return
		}
	}

	egnHash := votermap.HashEGN(egn, h.egnHMACKey)

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
	prevBallotID, err := h.voterStore.Record(r.Context(), egnHash, req.BallotID, "online", time.Now().Unix())
	if err != nil {
		log.Printf("ERROR: failed to record vote: %v", err)
		writeError(w, http.StatusInternalServerError, "store_error", "Failed to record vote")
		return
	}

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
	set, err := h.voterStore.ActiveSet(r.Context())
	if err != nil {
		log.Printf("ERROR: failed to retrieve active set: %v", err)
		writeError(w, http.StatusInternalServerError, "store_error", "Failed to retrieve active set")
		return
	}
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

func requireKey(key string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Internal-Key")), []byte(key)) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized", "Invalid API key")
			return
		}
		next(w, r)
	}
}
