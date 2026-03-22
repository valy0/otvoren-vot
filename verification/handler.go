package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"

	"filippo.io/edwards25519"
	"github.com/valy0/otvoren-vot/crypto/threshold"
	"github.com/valy0/otvoren-vot/verification/codes"
	"github.com/valy0/otvoren-vot/verification/session"
)

// VerificationHandler handles all verification HTTP endpoints.
type VerificationHandler struct {
	sessions  *session.Store
	parties   []string
	threshold int
	devSecret *edwards25519.Scalar // only set in dev mode
}

// HandleCreateSession handles POST /api/v1/session.
// In dev mode, codes are generated immediately using devSecret.
// In prod mode, the session awaits trustee share submission.
func (h *VerificationHandler) HandleCreateSession(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64 KB

	sess, err := h.sessions.Create(h.threshold)
	if err != nil {
		http.Error(w, "failed to create session", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if h.devSecret != nil {
		// Dev mode: generate codes immediately
		mapping := codes.GenerateCodeMapping(sess.ID, h.parties, h.devSecret)
		h.sessions.SetCodes(sess.ID, mapping.Codes, h.devSecret)
		json.NewEncoder(w).Encode(map[string]any{
			"session_id":   sess.ID,
			"code_mapping": mapping.Codes,
		})
		return
	}

	// Prod mode: awaiting trustee shares
	json.NewEncoder(w).Encode(map[string]any{
		"session_id":      sess.ID,
		"awaiting_shares": true,
	})
}

// HandleSubmitShare handles POST /internal/v1/shares.
// Accepts a trustee's key share and triggers code generation when the threshold is met.
func (h *VerificationHandler) HandleSubmitShare(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64 KB

	var req struct {
		SessionID    string `json:"session_id"`
		TrusteeIndex int    `json:"trustee_index"`
		Share        string `json:"share"` // hex-encoded 32-byte scalar
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	if req.SessionID == "" || req.TrusteeIndex < 1 || req.Share == "" {
		http.Error(w, "missing required fields", http.StatusBadRequest)
		return
	}

	shareBytes, err := hex.DecodeString(req.Share)
	if err != nil || len(shareBytes) != 32 {
		http.Error(w, "invalid share: must be 64 hex chars (32 bytes)", http.StatusBadRequest)
		return
	}

	share, err := edwards25519.NewScalar().SetCanonicalBytes(shareBytes)
	if err != nil {
		http.Error(w, "invalid scalar: not canonical", http.StatusBadRequest)
		return
	}

	count, met, err := h.sessions.AddShare(req.SessionID, req.TrusteeIndex, share)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if met {
		// Retrieve session to get all shares for reconstruction
		sess, ok := h.sessions.Get(req.SessionID)
		if !ok {
			http.Error(w, "session disappeared", http.StatusInternalServerError)
			return
		}

		// Only generate codes if we haven't already (threshold may have been met before)
		if sess.Codes == nil {
			shares := make([]*edwards25519.Scalar, 0, len(sess.Shares))
			indices := make([]int, 0, len(sess.Shares))
			for idx, s := range sess.Shares {
				shares = append(shares, s)
				indices = append(indices, idx)
			}

			masterSecret := threshold.LagrangeInterpolate(shares, indices)
			mapping := codes.GenerateCodeMapping(req.SessionID, h.parties, masterSecret)
			h.sessions.SetCodes(req.SessionID, mapping.Codes, masterSecret)

			// Zero individual shares now that we have the master secret
			zero := edwards25519.NewScalar()
			for _, s := range shares {
				s.Set(zero)
			}
		}

		json.NewEncoder(w).Encode(map[string]any{
			"shares_received": count,
			"threshold_met":   true,
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]any{
		"shares_received": count,
		"threshold_met":   false,
	})
}

// HandleVerify handles POST /api/v1/verify.
// Returns the return code for an encrypted ballot.
func (h *VerificationHandler) HandleVerify(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64 KB

	var req struct {
		SessionID       string          `json:"session_id"`
		EncryptedBallot json.RawMessage `json:"encrypted_ballot"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	sess, ok := h.sessions.Get(req.SessionID)
	if !ok {
		http.Error(w, "invalid session", http.StatusNotFound)
		return
	}
	if sess.Verified {
		http.Error(w, "session already verified", http.StatusConflict)
		return
	}
	if sess.Codes == nil || sess.MasterSecret == nil {
		http.Error(w, "threshold not yet met, codes unavailable", http.StatusPreconditionFailed)
		return
	}

	returnCode := codes.DeriveReturnCode(sess.MasterSecret, req.SessionID, req.EncryptedBallot)
	h.sessions.MarkVerified(req.SessionID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"return_code": returnCode,
	})
}

// HandleHealth handles GET /health.
func (h *VerificationHandler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":   "ok",
		"sessions": h.sessions.Count(),
	})
}

