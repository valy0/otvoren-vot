package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/valy0/otvoren-vot/collection/votermap"
	"github.com/valy0/otvoren-vot/pkg/jwtauth"
)

type CollectionHandler struct {
	voterStore        votermap.Store
	egnHMACKey        []byte
	bulletinBoardURL  string
	internalAPIKey    string
	activeSetAPIKey   string
	overrideReportDir string
	// JWT auth fields
	devAuth        bool
	jwtPublicKey   ed25519.PublicKey // nil in dev mode
	authServiceURL string
	sessionAPIKey  string
	electionID     string
	httpClient     *http.Client // timeout-configured, used for both auth + BB
}

func NewCollectionHandler(
	store votermap.Store,
	egnHMACKey []byte,
	bbURL, apiKey, activeSetKey, overrideReportDir string,
	devAuth bool,
	jwtPublicKey ed25519.PublicKey,
	authServiceURL, sessionAPIKey, electionID string,
	httpClient *http.Client,
) *CollectionHandler {
	return &CollectionHandler{
		voterStore:        store,
		egnHMACKey:        egnHMACKey,
		bulletinBoardURL:  bbURL,
		internalAPIKey:    apiKey,
		activeSetAPIKey:   activeSetKey,
		overrideReportDir: overrideReportDir,
		devAuth:           devAuth,
		jwtPublicKey:      jwtPublicKey,
		authServiceURL:    authServiceURL,
		sessionAPIKey:     sessionAPIKey,
		electionID:        electionID,
		httpClient:        httpClient,
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

// extractToken retrieves the session token from the Authorization header (Bearer)
// or the session cookie. If the Authorization header is present but not Bearer,
// it rejects immediately without falling through to the cookie.
func extractToken(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			return strings.TrimPrefix(auth, "Bearer "), nil
		}
		return "", fmt.Errorf("Authorization header must use Bearer scheme")
	}
	if c, err := r.Cookie("session"); err == nil {
		return c.Value, nil
	}
	return "", fmt.Errorf("no session token provided")
}

// isValidEGN checks whether the given string is a syntactically valid 10-digit EGN.
func isValidEGN(egn string) bool {
	if len(egn) != 10 {
		return false
	}
	for _, c := range egn {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// resolveSession calls the auth service to exchange a session ID for the voter's EGN.
// It retries once on transient errors.
func (h *CollectionHandler) resolveSession(ctx context.Context, sessionID string) (string, error) {
	if len(sessionID) != 36 {
		return "", fmt.Errorf("invalid session ID format")
	}

	url := h.authServiceURL + "/internal/v1/session/" + sessionID

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(500 * time.Millisecond)
		}

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return "", fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("X-Internal-Key", h.sessionAPIKey)

		resp, err := h.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			return "", fmt.Errorf("session not found or expired")
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
			return "", fmt.Errorf("auth service returned %d: %s", resp.StatusCode, body)
		}

		var result struct {
			EGN string `json:"egn"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&result); err != nil {
			return "", fmt.Errorf("decode session response: %w", err)
		}
		return result.EGN, nil
	}
	return "", fmt.Errorf("auth service unavailable: %w", lastErr)
}

func (h *CollectionHandler) HandleSubmit(w http.ResponseWriter, r *http.Request) {
	var egn string
	if h.devAuth {
		egn = r.Header.Get("X-Voter-EGN")
		if !isValidEGN(egn) {
			writeError(w, http.StatusBadRequest, "invalid_egn", "EGN must be exactly 10 digits")
			return
		}
	} else {
		tokenStr, err := extractToken(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "missing_token", err.Error())
			return
		}
		claims, err := jwtauth.Verify(tokenStr, h.jwtPublicKey)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid_token", "Invalid or expired session")
			return
		}
		if claims.ElectionID != h.electionID {
			writeError(w, http.StatusForbidden, "wrong_election", "Token issued for different election")
			return
		}
		egn, err = h.resolveSession(r.Context(), claims.Subject)
		if err != nil {
			log.Printf("ERROR: session resolution failed: %v", err)
			writeError(w, http.StatusUnauthorized, "session_error", "Session not found or expired")
			return
		}
		if !isValidEGN(egn) {
			log.Printf("ERROR: auth service returned invalid EGN format")
			writeError(w, http.StatusBadGateway, "invalid_session", "Auth service returned invalid identity")
			return
		}
	}

	if egn == "" {
		writeError(w, http.StatusUnauthorized, "missing_identity", "Voter identity required")
		return
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
	prevBallotID, err := h.voterStore.Record(r.Context(), egnHash, req.BallotID, votermap.ChannelOnline, time.Now())
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

	resp, err := h.httpClient.Do(req)
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

// HandleOverrideReport serves the pre-generated override report header.
// The report is generated offline by the CLI tool, not by this endpoint.
func (h *CollectionHandler) HandleOverrideReport(w http.ResponseWriter, r *http.Request) {
	if h.overrideReportDir == "" {
		writeError(w, http.StatusNotFound, "not_configured", "Override report directory not configured")
		return
	}
	headerPath := filepath.Join(h.overrideReportDir, "header.json")
	data, err := os.ReadFile(headerPath)
	if err != nil {
		if os.IsNotExist(err) {
			writeError(w, http.StatusNotFound, "not_generated", "Override report has not been generated yet")
			return
		}
		log.Printf("ERROR: failed to read override report: %v", err)
		writeError(w, http.StatusInternalServerError, "read_error", "Failed to read override report")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
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
