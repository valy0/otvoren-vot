package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/valy0/otvoren-vot/auth/provider"
	"github.com/valy0/otvoren-vot/auth/session"
	"github.com/valy0/otvoren-vot/pkg/jwtauth"
	"github.com/valy0/otvoren-vot/pkg/middleware"
)

// Test key pair generated once for all tests.
var testPub, testPriv, _ = ed25519.GenerateKey(nil)

const testElectionID = "test-election-001"
const testAPIKey = "test-api-key-secret"

// --- Mock session store ---

type mockSessionStore struct {
	sessions map[string]string // uuid -> egn
	egnMap   map[string]string // egn -> uuid
}

func newMockSessionStore() *mockSessionStore {
	return &mockSessionStore{
		sessions: make(map[string]string),
		egnMap:   make(map[string]string),
	}
}

func (m *mockSessionStore) Create(_ context.Context, egn string) (string, error) {
	// Revoke old session if exists.
	if oldID, ok := m.egnMap[egn]; ok {
		delete(m.sessions, oldID)
	}
	id := uuid.New().String()
	m.sessions[id] = egn
	m.egnMap[egn] = id
	return id, nil
}

func (m *mockSessionStore) Resolve(_ context.Context, sessionID string) (string, error) {
	egn, ok := m.sessions[sessionID]
	if !ok {
		return "", session.ErrSessionNotFound
	}
	return egn, nil
}

// --- Mock rate limiter ---

type allowAllRateLimiter struct{}

func (a *allowAllRateLimiter) Allow(_ context.Context, _ string) (bool, error) {
	return true, nil
}

type denyAllRateLimiter struct{}

func (d *denyAllRateLimiter) Allow(_ context.Context, _ string) (bool, error) {
	return false, nil
}

// --- Helpers ---

func newTestHandler() (*AuthHandler, *mockSessionStore) {
	store := newMockSessionStore()
	h := NewAuthHandler(
		provider.NewMockProvider(),
		store,
		&allowAllRateLimiter{},
		testPriv,
		testElectionID,
	)
	return h, store
}

// --- Tests ---

func TestAuthenticateSuccess(t *testing.T) {
	h, _ := newTestHandler()
	body := `{"token":"mock-8501011234"}`
	req := httptest.NewRequest("POST", "/authenticate", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp authResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.SessionToken == "" {
		t.Fatal("session_token should not be empty")
	}
	if resp.Provider != "mock" {
		t.Fatalf("expected provider 'mock', got %q", resp.Provider)
	}

	// Verify the JWT is valid and has the expected claims.
	claims, err := jwtauth.Verify(resp.SessionToken, testPub)
	if err != nil {
		t.Fatalf("JWT verification failed: %v", err)
	}
	if claims.ElectionID != testElectionID {
		t.Fatalf("expected election ID %q, got %q", testElectionID, claims.ElectionID)
	}
	if claims.Subject == "" {
		t.Fatal("JWT subject (session ID) should not be empty")
	}
	if claims.Issuer != jwtauth.Issuer {
		t.Fatalf("expected issuer %q, got %q", jwtauth.Issuer, claims.Issuer)
	}

	// Verify the session cookie is set.
	cookies := w.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected 'session' cookie to be set")
	}
	if !sessionCookie.HttpOnly {
		t.Fatal("session cookie should be HttpOnly")
	}
	// Secure flag is omitted in dev (HTTP); set in production (TLS).
	// Not asserted here since tests run over HTTP.
	if sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie SameSite should be Lax, got %v", sessionCookie.SameSite)
	}
}

func TestAuthenticateNoIdentityLeak(t *testing.T) {
	h, _ := newTestHandler()
	body := `{"token":"mock-8501011234"}`
	req := httptest.NewRequest("POST", "/authenticate", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Verify the raw response does NOT contain any Identity or EGN fields.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := raw["identity"]; ok {
		t.Fatal("response must not contain 'identity' field")
	}
	if _, ok := raw["egn"]; ok {
		t.Fatal("response must not contain 'egn' field")
	}
}

func TestAuthenticateInvalid(t *testing.T) {
	h, _ := newTestHandler()
	body := `{"token":"bad-token"}`
	req := httptest.NewRequest("POST", "/authenticate", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAuthenticateWrongMethod(t *testing.T) {
	h, _ := newTestHandler()
	req := httptest.NewRequest("GET", "/authenticate", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestAuthenticateRateLimited(t *testing.T) {
	store := newMockSessionStore()
	h := NewAuthHandler(
		provider.NewMockProvider(),
		store,
		&denyAllRateLimiter{},
		testPriv,
		testElectionID,
	)

	body := `{"token":"mock-8501011234"}`
	req := httptest.NewRequest("POST", "/authenticate", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAuthenticateSessionRevocation(t *testing.T) {
	h, store := newTestHandler()

	// Authenticate twice with the same EGN.
	body := `{"token":"mock-8501011234"}`

	req1 := httptest.NewRequest("POST", "/authenticate", bytes.NewBufferString(body))
	w1 := httptest.NewRecorder()
	h.ServeHTTP(w1, req1)

	var resp1 authResponse
	json.NewDecoder(w1.Body).Decode(&resp1)
	claims1, _ := jwtauth.Verify(resp1.SessionToken, testPub)

	req2 := httptest.NewRequest("POST", "/authenticate", bytes.NewBufferString(body))
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)

	var resp2 authResponse
	json.NewDecoder(w2.Body).Decode(&resp2)
	claims2, _ := jwtauth.Verify(resp2.SessionToken, testPub)

	// The first session should be revoked (not resolvable).
	_, err := store.Resolve(context.Background(), claims1.Subject)
	if err != session.ErrSessionNotFound {
		t.Fatal("first session should have been revoked")
	}

	// The second session should be valid.
	egn, err := store.Resolve(context.Background(), claims2.Subject)
	if err != nil {
		t.Fatalf("second session should be valid: %v", err)
	}
	if egn != "8501011234" {
		t.Fatalf("expected EGN 8501011234, got %s", egn)
	}
}

func TestResolveSession(t *testing.T) {
	h, store := newTestHandler()

	// Pre-create a session.
	sessionID, err := store.Create(context.Background(), "9901019999")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Build the resolve request using a mux to parse {id} path value.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /internal/v1/session/{id}", middleware.RequireKey(testAPIKey, h.HandleResolveSession))

	req := httptest.NewRequest("GET", "/internal/v1/session/"+sessionID, nil)
	req.Header.Set("X-Internal-Key", testAPIKey)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["egn"] != "9901019999" {
		t.Fatalf("expected EGN 9901019999, got %q", resp["egn"])
	}
}

func TestResolveSessionNotFound(t *testing.T) {
	h, _ := newTestHandler()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /internal/v1/session/{id}", middleware.RequireKey(testAPIKey, h.HandleResolveSession))

	req := httptest.NewRequest("GET", "/internal/v1/session/"+uuid.New().String(), nil)
	req.Header.Set("X-Internal-Key", testAPIKey)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestResolveSessionMissingKey(t *testing.T) {
	h, _ := newTestHandler()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /internal/v1/session/{id}", middleware.RequireKey(testAPIKey, h.HandleResolveSession))

	req := httptest.NewRequest("GET", "/internal/v1/session/"+uuid.New().String(), nil)
	// No X-Internal-Key header.
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}
