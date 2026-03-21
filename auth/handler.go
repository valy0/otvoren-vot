package main

import (
	"encoding/json"
	"net/http"

	"github.com/valy0/otvoren-vot/auth/provider"
)

type AuthHandler struct {
	provider provider.Provider
}

func NewAuthHandler(p provider.Provider) *AuthHandler {
	return &AuthHandler{provider: p}
}

type authRequest struct {
	Token string `json:"token"`
}

type authResponse struct {
	SessionToken string             `json:"session_token"`
	Identity     *provider.Identity `json:"identity"`
	Provider     string             `json:"provider"`
}

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

	// Generate a session token (in production, this would be a signed JWT)
	sessionToken := "session-" + identity.EGN

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(authResponse{
		SessionToken: sessionToken,
		Identity:     identity,
		Provider:     h.provider.Name(),
	})
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
