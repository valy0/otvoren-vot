package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/valy0/otvoren-vot/collection/votermap"
	"github.com/valy0/otvoren-vot/pkg/jwtauth"
	"github.com/valy0/otvoren-vot/pkg/middleware"
)

var (
	testHMACKey    = []byte("test-hmac-key")
	testHistoryKey = []byte("test-history-key")
	testElectionID = "550e8400-e29b-41d4-a716-446655440000"
)

// newTestHandler creates a handler in dev mode for backward-compatible tests.
func newTestHandler(t *testing.T, vm votermap.Store, bbURL string) *CollectionHandler {
	t.Helper()
	return NewCollectionHandler(
		vm, testHMACKey, bbURL, "test-key", "active-key", "",
		true, nil, "", "", "", &http.Client{Timeout: 3 * time.Second},
	)
}

// newJWTTestHandler creates a handler in production JWT mode.
func newJWTTestHandler(t *testing.T, vm votermap.Store, bbURL string, pubKey ed25519.PublicKey, authURL string) *CollectionHandler {
	t.Helper()
	return NewCollectionHandler(
		vm, testHMACKey, bbURL, "test-key", "active-key", "",
		false, pubKey, authURL, "test-session-key", testElectionID,
		&http.Client{Timeout: 3 * time.Second},
	)
}

// signTestJWT creates a signed JWT for testing purposes.
func signTestJWT(t *testing.T, priv ed25519.PrivateKey, sub, eid string, expiry time.Time) string {
	t.Helper()
	claims := &jwtauth.SessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    jwtauth.Issuer,
			Audience:  jwt.ClaimStrings{jwtauth.Audience},
			Subject:   sub,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(expiry),
		},
		ElectionID: eid,
	}
	tokenStr, err := jwtauth.Sign(claims, priv)
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return tokenStr
}

// mockBulletinBoard returns a test server that always responds with a successful ballot post.
func mockBulletinBoard(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"position": 1, "merkle_root": "abc"},
		})
	}))
}

// mockAuthService returns a test server that resolves session IDs to EGNs.
// If the session ID path segment is "not-found-session-id-placeholder0000",
// it returns 404.
func mockAuthService(t *testing.T, egn string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Internal-Key") != "test-session-key" {
			w.WriteHeader(401)
			return
		}
		// Extract the last path segment as session ID.
		// Path is /internal/v1/session/<id>
		segments := splitPath(r.URL.Path)
		sessionID := segments[len(segments)-1]
		if sessionID == "not-found-session-id-placeholder0000" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"egn": egn})
	}))
}

func splitPath(p string) []string {
	var parts []string
	for _, s := range bytes.Split([]byte(p), []byte("/")) {
		if len(s) > 0 {
			parts = append(parts, string(s))
		}
	}
	return parts
}

// --- Existing tests (dev mode) ---

func TestSubmitBallot(t *testing.T) {
	bb := mockBulletinBoard(t)
	defer bb.Close()

	vm := votermap.NewMemoryStore(testHistoryKey)
	h := newTestHandler(t, vm, bb.URL)

	body := `{"ballot_id":"b1","encrypted_ballot":{},"zk_proofs":{}}`
	req := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(body))
	req.Header.Set("X-Voter-EGN", "8501011234")
	w := httptest.NewRecorder()
	h.HandleSubmit(w, req)

	if w.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp submitResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.IsOverride {
		t.Fatal("first vote should not be an override")
	}

	// Verify voter map was updated
	voted, _ := vm.HasVoted(context.Background(), votermap.HashEGN("8501011234", testHMACKey))
	if !voted {
		t.Fatal("voter should be recorded")
	}
}

func TestSubmitOverride(t *testing.T) {
	bb := mockBulletinBoard(t)
	defer bb.Close()

	vm := votermap.NewMemoryStore(testHistoryKey)
	h := newTestHandler(t, vm, bb.URL)

	// First vote
	req1 := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(`{"ballot_id":"b1","encrypted_ballot":{},"zk_proofs":{}}`))
	req1.Header.Set("X-Voter-EGN", "8501011234")
	w1 := httptest.NewRecorder()
	h.HandleSubmit(w1, req1)

	// Override
	req2 := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(`{"ballot_id":"b2","encrypted_ballot":{},"zk_proofs":{}}`))
	req2.Header.Set("X-Voter-EGN", "8501011234")
	w2 := httptest.NewRecorder()
	h.HandleSubmit(w2, req2)

	var resp submitResponse
	json.NewDecoder(w2.Body).Decode(&resp)
	if !resp.IsOverride {
		t.Fatal("second vote should be an override")
	}

	id, _, _ := vm.GetActiveBallotID(context.Background(), votermap.HashEGN("8501011234", testHMACKey))
	if id != "b2" {
		t.Fatalf("active ballot should be b2, got %s", id)
	}
}

func TestSubmitMissingIdentity(t *testing.T) {
	vm := votermap.NewMemoryStore(testHistoryKey)
	h := newTestHandler(t, vm, "http://unused")

	req := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(`{"ballot_id":"b1","encrypted_ballot":{},"zk_proofs":{}}`))
	// No X-Voter-EGN header — in dev mode this should return 400 (invalid EGN)
	w := httptest.NewRecorder()
	h.HandleSubmit(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestSubmitInvalidEGN(t *testing.T) {
	vm := votermap.NewMemoryStore(testHistoryKey)
	h := newTestHandler(t, vm, "http://unused")

	cases := []struct {
		egn  string
		desc string
	}{
		{"123456789", "too short (9 digits)"},
		{"12345678901", "too long (11 digits)"},
		{"850101123A", "contains non-digit"},
	}

	for _, tc := range cases {
		req := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(`{"ballot_id":"b1","encrypted_ballot":{},"zk_proofs":{}}`))
		req.Header.Set("X-Voter-EGN", tc.egn)
		w := httptest.NewRecorder()
		h.HandleSubmit(w, req)

		if w.Code != 400 {
			t.Fatalf("case %q: expected 400, got %d", tc.desc, w.Code)
		}
	}
}

func TestRequireKey(t *testing.T) {
	vm := votermap.NewMemoryStore(testHistoryKey)
	vm.Record(context.Background(), votermap.HashEGN("1111111111", testHMACKey), "b1", votermap.ChannelOnline, time.Unix(1000, 0))

	h := newTestHandler(t, vm, "http://unused")
	protected := middleware.RequireKey("secret-active-key", h.HandleActiveSet)

	// Missing key
	req := httptest.NewRequest("GET", "/active-set", nil)
	w := httptest.NewRecorder()
	protected(w, req)
	if w.Code != 401 {
		t.Fatalf("expected 401 with no key, got %d", w.Code)
	}

	// Wrong key
	req2 := httptest.NewRequest("GET", "/active-set", nil)
	req2.Header.Set("X-Internal-Key", "wrong-key")
	w2 := httptest.NewRecorder()
	protected(w2, req2)
	if w2.Code != 401 {
		t.Fatalf("expected 401 with wrong key, got %d", w2.Code)
	}

	// Correct key
	req3 := httptest.NewRequest("GET", "/active-set", nil)
	req3.Header.Set("X-Internal-Key", "secret-active-key")
	w3 := httptest.NewRecorder()
	protected(w3, req3)
	if w3.Code != 200 {
		t.Fatalf("expected 200 with correct key, got %d: %s", w3.Code, w3.Body.String())
	}
}

func TestActiveSet(t *testing.T) {
	vm := votermap.NewMemoryStore(testHistoryKey)
	vm.Record(context.Background(), votermap.HashEGN("1111111111", testHMACKey), "b1", votermap.ChannelOnline, time.Unix(1000, 0))
	vm.Record(context.Background(), votermap.HashEGN("2222222222", testHMACKey), "b2", votermap.ChannelOnline, time.Unix(1000, 0))

	h := newTestHandler(t, vm, "http://unused")
	req := httptest.NewRequest("GET", "/active-set", nil)
	w := httptest.NewRecorder()
	h.HandleActiveSet(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if int(resp["size"].(float64)) != 2 {
		t.Fatalf("expected size 2, got %v", resp["size"])
	}
}

// --- JWT-path tests ---

func TestSubmitWithJWT(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Session ID must be 36 chars (UUID format)
	sessionID := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	voterEGN := "8501011234"

	authSrv := mockAuthService(t, voterEGN)
	defer authSrv.Close()

	bb := mockBulletinBoard(t)
	defer bb.Close()

	vm := votermap.NewMemoryStore(testHistoryKey)
	h := newJWTTestHandler(t, vm, bb.URL, pub, authSrv.URL)

	tokenStr := signTestJWT(t, priv, sessionID, testElectionID, time.Now().Add(30*time.Minute))

	body := `{"ballot_id":"b1","encrypted_ballot":{},"zk_proofs":{}}`
	req := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	w := httptest.NewRecorder()
	h.HandleSubmit(w, req)

	if w.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp submitResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.BallotID != "b1" {
		t.Fatalf("expected ballot_id b1, got %s", resp.BallotID)
	}

	// Verify voter was recorded
	voted, _ := vm.HasVoted(context.Background(), votermap.HashEGN(voterEGN, testHMACKey))
	if !voted {
		t.Fatal("voter should be recorded after JWT submit")
	}
}

func TestSubmitExpiredJWT(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	vm := votermap.NewMemoryStore(testHistoryKey)
	h := newJWTTestHandler(t, vm, "http://unused", pub, "http://unused")

	tokenStr := signTestJWT(t, priv, "a1b2c3d4-e5f6-7890-abcd-ef1234567890", testElectionID, time.Now().Add(-30*time.Minute))

	body := `{"ballot_id":"b1","encrypted_ballot":{},"zk_proofs":{}}`
	req := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	w := httptest.NewRecorder()
	h.HandleSubmit(w, req)

	if w.Code != 401 {
		t.Fatalf("expected 401 for expired JWT, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSubmitSessionNotFound(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	authSrv := mockAuthService(t, "8501011234")
	defer authSrv.Close()

	vm := votermap.NewMemoryStore(testHistoryKey)
	h := newJWTTestHandler(t, vm, "http://unused", pub, authSrv.URL)

	// Use the magic session ID that the mock returns 404 for
	tokenStr := signTestJWT(t, priv, "not-found-session-id-placeholder0000", testElectionID, time.Now().Add(30*time.Minute))

	body := `{"ballot_id":"b1","encrypted_ballot":{},"zk_proofs":{}}`
	req := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	w := httptest.NewRecorder()
	h.HandleSubmit(w, req)

	if w.Code != 401 {
		t.Fatalf("expected 401 for session not found, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSubmitWrongElection(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	vm := votermap.NewMemoryStore(testHistoryKey)
	h := newJWTTestHandler(t, vm, "http://unused", pub, "http://unused")

	// Sign JWT with a different election ID
	tokenStr := signTestJWT(t, priv, "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "different-election-id", time.Now().Add(30*time.Minute))

	body := `{"ballot_id":"b1","encrypted_ballot":{},"zk_proofs":{}}`
	req := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	w := httptest.NewRecorder()
	h.HandleSubmit(w, req)

	if w.Code != 403 {
		t.Fatalf("expected 403 for wrong election, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSubmitMalformedBearer(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	vm := votermap.NewMemoryStore(testHistoryKey)
	h := newJWTTestHandler(t, vm, "http://unused", pub, "http://unused")

	body := `{"ballot_id":"b1","encrypted_ballot":{},"zk_proofs":{}}`
	req := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	w := httptest.NewRecorder()
	h.HandleSubmit(w, req)

	if w.Code != 401 {
		t.Fatalf("expected 401 for non-Bearer auth, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDevModeDisabledRejectsHeader(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	vm := votermap.NewMemoryStore(testHistoryKey)
	h := newJWTTestHandler(t, vm, "http://unused", pub, "http://unused")

	body := `{"ballot_id":"b1","encrypted_ballot":{},"zk_proofs":{}}`
	req := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(body))
	req.Header.Set("X-Voter-EGN", "8501011234") // dev header, but dev mode is off
	w := httptest.NewRecorder()
	h.HandleSubmit(w, req)

	if w.Code != 401 {
		t.Fatalf("expected 401 when dev mode disabled and only X-Voter-EGN provided, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSubmitWithCookie(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	sessionID := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	voterEGN := "8501011234"

	authSrv := mockAuthService(t, voterEGN)
	defer authSrv.Close()

	bb := mockBulletinBoard(t)
	defer bb.Close()

	vm := votermap.NewMemoryStore(testHistoryKey)
	h := newJWTTestHandler(t, vm, bb.URL, pub, authSrv.URL)

	tokenStr := signTestJWT(t, priv, sessionID, testElectionID, time.Now().Add(30*time.Minute))

	body := `{"ballot_id":"b1","encrypted_ballot":{},"zk_proofs":{}}`
	req := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(body))
	req.AddCookie(&http.Cookie{Name: "session", Value: tokenStr})
	w := httptest.NewRecorder()
	h.HandleSubmit(w, req)

	if w.Code != 201 {
		t.Fatalf("expected 201 with cookie auth, got %d: %s", w.Code, w.Body.String())
	}
}

// --- JWT auth edge cases ---

func TestSubmitMalformedJWTToken(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	vm := votermap.NewMemoryStore(testHistoryKey)
	h := newJWTTestHandler(t, vm, "http://unused", pub, "http://unused")

	body := `{"ballot_id":"b1","encrypted_ballot":{},"zk_proofs":{}}`
	req := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer not-a-valid-jwt-at-all")
	w := httptest.NewRecorder()
	h.HandleSubmit(w, req)

	if w.Code != 401 {
		t.Fatalf("expected 401 for malformed JWT, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSubmitMissingAuthHeaderAndCookie(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	vm := votermap.NewMemoryStore(testHistoryKey)
	h := newJWTTestHandler(t, vm, "http://unused", pub, "http://unused")

	body := `{"ballot_id":"b1","encrypted_ballot":{},"zk_proofs":{}}`
	req := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(body))
	// No Authorization header, no session cookie
	w := httptest.NewRecorder()
	h.HandleSubmit(w, req)

	if w.Code != 401 {
		t.Fatalf("expected 401 with no auth header and no cookie, got %d: %s", w.Code, w.Body.String())
	}

	var resp errorResp
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error.Code != "missing_token" {
		t.Fatalf("expected error code missing_token, got %s", resp.Error.Code)
	}
}

func TestSubmitJWTSignedWithWrongKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Generate a different key pair for signing
	_, wrongPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	vm := votermap.NewMemoryStore(testHistoryKey)
	h := newJWTTestHandler(t, vm, "http://unused", pub, "http://unused")

	sessionID := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	tokenStr := signTestJWT(t, wrongPriv, sessionID, testElectionID, time.Now().Add(30*time.Minute))

	body := `{"ballot_id":"b1","encrypted_ballot":{},"zk_proofs":{}}`
	req := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	w := httptest.NewRecorder()
	h.HandleSubmit(w, req)

	if w.Code != 401 {
		t.Fatalf("expected 401 for JWT signed with wrong key, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Ballot submission validation ---

func TestSubmitMissingBallotID(t *testing.T) {
	bb := mockBulletinBoard(t)
	defer bb.Close()

	vm := votermap.NewMemoryStore(testHistoryKey)
	h := newTestHandler(t, vm, bb.URL)

	body := `{"encrypted_ballot":{},"zk_proofs":{}}`
	req := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(body))
	req.Header.Set("X-Voter-EGN", "8501011234")
	w := httptest.NewRecorder()
	h.HandleSubmit(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400 for missing ballot_id, got %d: %s", w.Code, w.Body.String())
	}

	var resp errorResp
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error.Code != "missing_ballot_id" {
		t.Fatalf("expected error code missing_ballot_id, got %s", resp.Error.Code)
	}
}

func TestSubmitEmptyBody(t *testing.T) {
	vm := votermap.NewMemoryStore(testHistoryKey)
	h := newTestHandler(t, vm, "http://unused")

	req := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(""))
	req.Header.Set("X-Voter-EGN", "8501011234")
	w := httptest.NewRecorder()
	h.HandleSubmit(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400 for empty body, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSubmitInvalidJSON(t *testing.T) {
	vm := votermap.NewMemoryStore(testHistoryKey)
	h := newTestHandler(t, vm, "http://unused")

	req := httptest.NewRequest("POST", "/submit", bytes.NewBufferString("{not valid json"))
	req.Header.Set("X-Voter-EGN", "8501011234")
	w := httptest.NewRecorder()
	h.HandleSubmit(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400 for invalid JSON, got %d: %s", w.Code, w.Body.String())
	}

	var resp errorResp
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error.Code != "invalid_body" {
		t.Fatalf("expected error code invalid_body, got %s", resp.Error.Code)
	}
}

func TestSubmitMissingEncryptedBallot(t *testing.T) {
	// Note: the handler does NOT validate encrypted_ballot presence;
	// it only requires ballot_id. encrypted_ballot is forwarded as-is
	// (null if missing). This test documents that behavior.
	bb := mockBulletinBoard(t)
	defer bb.Close()

	vm := votermap.NewMemoryStore(testHistoryKey)
	h := newTestHandler(t, vm, bb.URL)

	body := `{"ballot_id":"b1","zk_proofs":{}}`
	req := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(body))
	req.Header.Set("X-Voter-EGN", "8501011234")
	w := httptest.NewRecorder()
	h.HandleSubmit(w, req)

	// Handler currently accepts this — encrypted_ballot will be null/empty in the
	// forwarded payload. Documenting actual behavior: the BB is responsible for
	// rejecting incomplete ballots.
	if w.Code != 201 {
		t.Fatalf("expected 201 (encrypted_ballot not validated by collection), got %d: %s", w.Code, w.Body.String())
	}
}

// --- Vote override via JWT path ---

func TestSubmitOverrideWithJWT(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	sessionID := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	voterEGN := "8501011234"

	authSrv := mockAuthService(t, voterEGN)
	defer authSrv.Close()

	bb := mockBulletinBoard(t)
	defer bb.Close()

	vm := votermap.NewMemoryStore(testHistoryKey)
	h := newJWTTestHandler(t, vm, bb.URL, pub, authSrv.URL)

	// First submission
	token1 := signTestJWT(t, priv, sessionID, testElectionID, time.Now().Add(30*time.Minute))
	body1 := `{"ballot_id":"b1","encrypted_ballot":{"c":"first"},"zk_proofs":{}}`
	req1 := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(body1))
	req1.Header.Set("Authorization", "Bearer "+token1)
	w1 := httptest.NewRecorder()
	h.HandleSubmit(w1, req1)

	if w1.Code != 201 {
		t.Fatalf("first submit: expected 201, got %d: %s", w1.Code, w1.Body.String())
	}
	var resp1 submitResponse
	json.NewDecoder(w1.Body).Decode(&resp1)
	if resp1.IsOverride {
		t.Fatal("first vote should not be an override")
	}

	// Second submission (override) — same voter, different ballot
	token2 := signTestJWT(t, priv, sessionID, testElectionID, time.Now().Add(30*time.Minute))
	body2 := `{"ballot_id":"b2","encrypted_ballot":{"c":"second"},"zk_proofs":{}}`
	req2 := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(body2))
	req2.Header.Set("Authorization", "Bearer "+token2)
	w2 := httptest.NewRecorder()
	h.HandleSubmit(w2, req2)

	if w2.Code != 201 {
		t.Fatalf("override submit: expected 201, got %d: %s", w2.Code, w2.Body.String())
	}
	var resp2 submitResponse
	json.NewDecoder(w2.Body).Decode(&resp2)
	if !resp2.IsOverride {
		t.Fatal("second vote should be marked as override")
	}
	if resp2.BallotID != "b2" {
		t.Fatalf("expected ballot_id b2, got %s", resp2.BallotID)
	}
}

// --- BB forwarding failures ---

func TestSubmitBBUnreachable(t *testing.T) {
	vm := votermap.NewMemoryStore(testHistoryKey)
	// Point to a definitely-unreachable address
	h := newTestHandler(t, vm, "http://127.0.0.1:1")

	body := `{"ballot_id":"b1","encrypted_ballot":{},"zk_proofs":{}}`
	req := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(body))
	req.Header.Set("X-Voter-EGN", "8501011234")
	w := httptest.NewRecorder()
	h.HandleSubmit(w, req)

	if w.Code != 502 {
		t.Fatalf("expected 502 when BB unreachable, got %d: %s", w.Code, w.Body.String())
	}

	var resp errorResp
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error.Code != "board_error" {
		t.Fatalf("expected error code board_error, got %s", resp.Error.Code)
	}
}

func TestSubmitBBReturnsError(t *testing.T) {
	// Mock BB that returns 500
	bbErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte(`{"error":"internal"}`))
	}))
	defer bbErr.Close()

	vm := votermap.NewMemoryStore(testHistoryKey)
	h := newTestHandler(t, vm, bbErr.URL)

	body := `{"ballot_id":"b1","encrypted_ballot":{},"zk_proofs":{}}`
	req := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(body))
	req.Header.Set("X-Voter-EGN", "8501011234")
	w := httptest.NewRecorder()
	h.HandleSubmit(w, req)

	if w.Code != 502 {
		t.Fatalf("expected 502 when BB returns error, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Identity stripping verification ---

func TestIdentityStrippedWhenForwardingToBB(t *testing.T) {
	voterEGN := "8501011234"

	// Custom mock BB that captures the forwarded request body
	var capturedBody []byte
	bbCapture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		capturedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read BB request body: %v", err)
		}
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"position": 1, "merkle_root": "abc"},
		})
	}))
	defer bbCapture.Close()

	vm := votermap.NewMemoryStore(testHistoryKey)
	h := newTestHandler(t, vm, bbCapture.URL)

	body := `{"ballot_id":"b1","encrypted_ballot":{"ct":"cipher"},"zk_proofs":{"proof":"data"}}`
	req := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(body))
	req.Header.Set("X-Voter-EGN", voterEGN)
	w := httptest.NewRecorder()
	h.HandleSubmit(w, req)

	if w.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// Verify the forwarded body does NOT contain the voter EGN
	if strings.Contains(string(capturedBody), voterEGN) {
		t.Fatalf("BB request body must not contain voter EGN, but found it: %s", string(capturedBody))
	}

	// Verify the forwarded body contains only expected fields
	var forwarded map[string]interface{}
	if err := json.Unmarshal(capturedBody, &forwarded); err != nil {
		t.Fatalf("failed to parse forwarded body: %v", err)
	}

	expectedKeys := map[string]bool{"ballot_id": true, "encrypted_ballot": true, "zk_proofs": true}
	for key := range forwarded {
		if !expectedKeys[key] {
			t.Fatalf("unexpected field %q in BB request body", key)
		}
	}
	for key := range expectedKeys {
		if _, ok := forwarded[key]; !ok {
			t.Fatalf("expected field %q missing from BB request body", key)
		}
	}

	// Verify there is no EGN-like field by checking for common field names
	for _, sensitive := range []string{"egn", "voter_egn", "voter_id", "identity"} {
		if _, ok := forwarded[sensitive]; ok {
			t.Fatalf("BB request body must not contain sensitive field %q", sensitive)
		}
	}
}

func TestIdentityStrippedWithJWTAuth(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	sessionID := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	voterEGN := "9901019999"

	authSrv := mockAuthService(t, voterEGN)
	defer authSrv.Close()

	var capturedBody []byte
	bbCapture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"position": 1, "merkle_root": "xyz"},
		})
	}))
	defer bbCapture.Close()

	vm := votermap.NewMemoryStore(testHistoryKey)
	h := newJWTTestHandler(t, vm, bbCapture.URL, pub, authSrv.URL)

	tokenStr := signTestJWT(t, priv, sessionID, testElectionID, time.Now().Add(30*time.Minute))

	body := `{"ballot_id":"b1","encrypted_ballot":{"ct":"data"},"zk_proofs":{"p":"val"}}`
	req := httptest.NewRequest("POST", "/submit", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	w := httptest.NewRecorder()
	h.HandleSubmit(w, req)

	if w.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// Verify EGN is stripped from forwarded payload
	if strings.Contains(string(capturedBody), voterEGN) {
		t.Fatalf("BB request body must not contain voter EGN via JWT auth path, but found it: %s", string(capturedBody))
	}

	// Also verify the session ID is not forwarded
	if strings.Contains(string(capturedBody), sessionID) {
		t.Fatalf("BB request body must not contain session ID, but found it: %s", string(capturedBody))
	}

	// Verify only expected fields are present
	var forwarded map[string]interface{}
	json.Unmarshal(capturedBody, &forwarded)
	allowedKeys := map[string]bool{"ballot_id": true, "encrypted_ballot": true, "zk_proofs": true}
	for key := range forwarded {
		if !allowedKeys[key] {
			t.Fatalf("unexpected field %q in BB request body (JWT auth path)", key)
		}
	}
}
