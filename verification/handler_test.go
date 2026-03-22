package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/valy0/otvoren-vot/crypto/threshold"
	"github.com/valy0/otvoren-vot/verification/session"
)

var testParties = []string{"ГЕРБ", "ПП-ДБ", "ДПС", "БСП"}

func newDevHandler() *VerificationHandler {
	dealer := threshold.NewDealer(3, 5)
	return &VerificationHandler{
		sessions:  session.NewStore(),
		parties:   testParties,
		threshold: 3,
		devSecret: dealer.Secret(),
	}
}

func newProdHandler() (*VerificationHandler, *threshold.Dealer) {
	dealer := threshold.NewDealer(3, 5)
	return &VerificationHandler{
		sessions:  session.NewStore(),
		parties:   testParties,
		threshold: 3,
	}, dealer
}

func TestCreateSessionDevMode(t *testing.T) {
	h := newDevHandler()
	req := httptest.NewRequest("POST", "/api/v1/session", nil)
	w := httptest.NewRecorder()
	h.HandleCreateSession(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)

	sessionID, ok := resp["session_id"].(string)
	if !ok || sessionID == "" {
		t.Fatal("expected session_id in response")
	}

	codeMapping, ok := resp["code_mapping"].(map[string]any)
	if !ok {
		t.Fatal("expected code_mapping in dev mode response")
	}

	for _, party := range testParties {
		code, ok := codeMapping[party].(string)
		if !ok {
			t.Fatalf("missing code for %s", party)
		}
		if len(code) != 8 {
			t.Fatalf("code should be 8 digits, got %q", code)
		}
	}
}

func TestCreateSessionProdMode(t *testing.T) {
	h, _ := newProdHandler()
	req := httptest.NewRequest("POST", "/api/v1/session", nil)
	w := httptest.NewRecorder()
	h.HandleCreateSession(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["awaiting_shares"] != true {
		t.Fatal("prod mode should return awaiting_shares: true")
	}
	if _, has := resp["code_mapping"]; has {
		t.Fatal("prod mode should not return code_mapping")
	}
}

func TestSubmitShares(t *testing.T) {
	h, dealer := newProdHandler()

	// Create a session
	createReq := httptest.NewRequest("POST", "/api/v1/session", nil)
	createW := httptest.NewRecorder()
	h.HandleCreateSession(createW, createReq)

	var createResp map[string]any
	json.NewDecoder(createW.Body).Decode(&createResp)
	sessionID := createResp["session_id"].(string)

	// Submit 3 shares (threshold)
	for i := 0; i < 3; i++ {
		shareHex := hex.EncodeToString(dealer.Shares[i].Bytes())
		body, _ := json.Marshal(map[string]any{
			"session_id":    sessionID,
			"trustee_index": i + 1,
			"share":         shareHex,
		})
		req := httptest.NewRequest("POST", "/internal/v1/shares", bytes.NewReader(body))
		w := httptest.NewRecorder()
		h.HandleSubmitShare(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("share %d: expected 200, got %d: %s", i+1, w.Code, w.Body.String())
		}

		var resp map[string]any
		json.NewDecoder(w.Body).Decode(&resp)

		count := int(resp["shares_received"].(float64))
		if count != i+1 {
			t.Fatalf("expected %d shares, got %d", i+1, count)
		}
		met := resp["threshold_met"].(bool)
		if i < 2 && met {
			t.Fatalf("threshold should not be met with %d shares", i+1)
		}
		if i == 2 && !met {
			t.Fatal("threshold should be met with 3 shares")
		}
	}

	// Verify the session now has codes
	sess, ok := h.sessions.Get(sessionID)
	if !ok {
		t.Fatal("session should exist")
	}
	if sess.Codes == nil {
		t.Fatal("codes should be set after threshold met")
	}
	for _, party := range testParties {
		if len(sess.Codes[party]) != 8 {
			t.Fatalf("code for %s should be 8 digits, got %q", party, sess.Codes[party])
		}
	}
}

func TestSubmitSharesIdempotent(t *testing.T) {
	h, dealer := newProdHandler()

	createReq := httptest.NewRequest("POST", "/api/v1/session", nil)
	createW := httptest.NewRecorder()
	h.HandleCreateSession(createW, createReq)

	var createResp map[string]any
	json.NewDecoder(createW.Body).Decode(&createResp)
	sessionID := createResp["session_id"].(string)

	shareHex := hex.EncodeToString(dealer.Shares[0].Bytes())
	body, _ := json.Marshal(map[string]any{
		"session_id":    sessionID,
		"trustee_index": 1,
		"share":         shareHex,
	})

	// Submit same share twice
	for attempt := 0; attempt < 2; attempt++ {
		req := httptest.NewRequest("POST", "/internal/v1/shares", bytes.NewReader(body))
		w := httptest.NewRecorder()
		h.HandleSubmitShare(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("attempt %d: expected 200, got %d", attempt, w.Code)
		}

		var resp map[string]any
		json.NewDecoder(w.Body).Decode(&resp)
		count := int(resp["shares_received"].(float64))
		if count != 1 {
			t.Fatalf("attempt %d: expected 1 share, got %d", attempt, count)
		}
	}
}

func TestVerifyWithCodes(t *testing.T) {
	h := newDevHandler()

	// Create session (dev mode: codes immediately available)
	createReq := httptest.NewRequest("POST", "/api/v1/session", nil)
	createW := httptest.NewRecorder()
	h.HandleCreateSession(createW, createReq)

	var createResp map[string]any
	json.NewDecoder(createW.Body).Decode(&createResp)
	sessionID := createResp["session_id"].(string)

	// Verify
	verifyBody, _ := json.Marshal(map[string]any{
		"session_id":       sessionID,
		"encrypted_ballot": []byte("test-ballot-data"),
	})
	verifyReq := httptest.NewRequest("POST", "/api/v1/verify", bytes.NewReader(verifyBody))
	verifyW := httptest.NewRecorder()
	h.HandleVerify(verifyW, verifyReq)

	if verifyW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", verifyW.Code, verifyW.Body.String())
	}

	var verifyResp map[string]string
	json.NewDecoder(verifyW.Body).Decode(&verifyResp)

	returnCode := verifyResp["return_code"]
	if len(returnCode) != 8 {
		t.Fatalf("return code should be 8 digits, got %q", returnCode)
	}

	// Second verify should fail (already verified)
	verifyReq2 := httptest.NewRequest("POST", "/api/v1/verify", bytes.NewReader(verifyBody))
	verifyW2 := httptest.NewRecorder()
	h.HandleVerify(verifyW2, verifyReq2)

	if verifyW2.Code != http.StatusConflict {
		t.Fatalf("second verify should return 409, got %d", verifyW2.Code)
	}
}

func TestVerifyBeforeThreshold(t *testing.T) {
	h, _ := newProdHandler()

	// Create session (prod mode: no codes yet)
	createReq := httptest.NewRequest("POST", "/api/v1/session", nil)
	createW := httptest.NewRecorder()
	h.HandleCreateSession(createW, createReq)

	var createResp map[string]any
	json.NewDecoder(createW.Body).Decode(&createResp)
	sessionID := createResp["session_id"].(string)

	// Try to verify before any shares submitted
	verifyBody, _ := json.Marshal(map[string]any{
		"session_id":       sessionID,
		"encrypted_ballot": []byte("test-ballot-data"),
	})
	verifyReq := httptest.NewRequest("POST", "/api/v1/verify", bytes.NewReader(verifyBody))
	verifyW := httptest.NewRecorder()
	h.HandleVerify(verifyW, verifyReq)

	if verifyW.Code != http.StatusPreconditionFailed {
		t.Fatalf("expected 412, got %d: %s", verifyW.Code, verifyW.Body.String())
	}
}

func TestHealthEndpoint(t *testing.T) {
	h := newDevHandler()
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	h.HandleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", resp["status"])
	}
}

func TestSubmitShareInvalidHex(t *testing.T) {
	h, _ := newProdHandler()

	createReq := httptest.NewRequest("POST", "/api/v1/session", nil)
	createW := httptest.NewRecorder()
	h.HandleCreateSession(createW, createReq)

	var createResp map[string]any
	json.NewDecoder(createW.Body).Decode(&createResp)
	sessionID := createResp["session_id"].(string)

	body, _ := json.Marshal(map[string]any{
		"session_id":    sessionID,
		"trustee_index": 1,
		"share":         "not-valid-hex",
	})
	req := httptest.NewRequest("POST", "/internal/v1/shares", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleSubmitShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid hex, got %d", w.Code)
	}
}

func TestSubmitShareMissingFields(t *testing.T) {
	h, _ := newProdHandler()

	body, _ := json.Marshal(map[string]any{})
	req := httptest.NewRequest("POST", "/internal/v1/shares", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleSubmitShare(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing fields, got %d", w.Code)
	}
}
