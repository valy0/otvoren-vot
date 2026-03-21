package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
