package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/valy0/otvoren-vot/auth/provider"
)

func TestAuthenticateSuccess(t *testing.T) {
	h := NewAuthHandler(provider.NewMockProvider())
	body := `{"token":"mock-8501011234"}`
	req := httptest.NewRequest("POST", "/authenticate", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp authResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Identity.EGN != "8501011234" {
		t.Fatalf("expected EGN 8501011234, got %s", resp.Identity.EGN)
	}
	if resp.SessionToken == "" {
		t.Fatal("session token should not be empty")
	}
}

func TestAuthenticateInvalid(t *testing.T) {
	h := NewAuthHandler(provider.NewMockProvider())
	body := `{"token":"bad-token"}`
	req := httptest.NewRequest("POST", "/authenticate", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAuthenticateWrongMethod(t *testing.T) {
	h := NewAuthHandler(provider.NewMockProvider())
	req := httptest.NewRequest("GET", "/authenticate", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != 405 {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}
