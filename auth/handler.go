package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/valy0/otvoren-vot/auth/provider"
	"github.com/valy0/otvoren-vot/auth/session"
	"github.com/valy0/otvoren-vot/pkg/jwtauth"
)

// RateChecker abstracts rate-limit checking so that tests can substitute
// a mock without requiring Redis.
type RateChecker interface {
	Allow(ctx context.Context, egn string) (bool, error)
}

// AuthHandler handles voter authentication requests.
type AuthHandler struct {
	provider    provider.Provider
	sessions    session.Store
	rateLimiter RateChecker
	jwtPrivKey  ed25519.PrivateKey
	electionID  string
}

// NewAuthHandler constructs an AuthHandler with all required dependencies.
func NewAuthHandler(p provider.Provider, sessions session.Store, rl RateChecker, jwtPrivKey ed25519.PrivateKey, electionID string) *AuthHandler {
	return &AuthHandler{
		provider:    p,
		sessions:    sessions,
		rateLimiter: rl,
		jwtPrivKey:  jwtPrivKey,
		electionID:  electionID,
	}
}

type authRequest struct {
	Token string `json:"token"`
}

type authResponse struct {
	SessionToken string `json:"session_token"`
	Provider     string `json:"provider"`
}

// ServeHTTP handles POST /authenticate.
func (h *AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req authRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "Invalid JSON")
		return
	}

	identity, err := h.provider.Authenticate(req.Token)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "auth_error", "Authentication failed")
		return
	}
	if identity == nil {
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "Invalid or expired token")
		return
	}
	if !identity.IsEligible {
		writeError(w, http.StatusForbidden, "not_eligible", "Voter is not eligible for this election")
		return
	}

	// Rate limit per EGN.
	ctx := r.Context()
	allowed, err := h.rateLimiter.Allow(ctx, identity.EGN)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "rate_limit_error", "Rate limit check failed")
		return
	}
	if !allowed {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many authentication attempts")
		return
	}

	// Create session (atomically revokes any prior session for this EGN).
	sessionID, err := h.sessions.Create(ctx, identity.EGN)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session_error", "Failed to create session")
		return
	}

	// Build and sign JWT.
	now := time.Now()
	claims := &jwtauth.SessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    jwtauth.Issuer,
			Audience:  jwt.ClaimStrings{jwtauth.Audience},
			Subject:   sessionID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(session.SessionTTL)),
		},
		ElectionID: h.electionID,
	}
	signed, err := jwtauth.Sign(claims, h.jwtPrivKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "jwt_error", "Failed to sign session token")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    signed,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   int(session.SessionTTL.Seconds()),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(authResponse{
		SessionToken: signed,
		Provider:     h.provider.Name(),
	})
}

// HandleResolveSession handles GET /internal/v1/session/{id}.
// It resolves a session ID to the voter EGN. Called by the Collection
// service over the internal network, protected by RequireKey middleware.
func (h *AuthHandler) HandleResolveSession(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "missing_id", "Session ID required")
		return
	}

	egn, err := h.sessions.Resolve(r.Context(), sessionID)
	if err != nil {
		if errors.Is(err, session.ErrSessionNotFound) {
			writeError(w, http.StatusNotFound, "session_not_found", "Session not found or expired")
			return
		}
		writeError(w, http.StatusInternalServerError, "resolve_error", "Failed to resolve session")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"egn": egn})
}

type errorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := errorResponse{}
	resp.Error.Code = code
	resp.Error.Message = message
	json.NewEncoder(w).Encode(resp)
}
