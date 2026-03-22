package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireKeyMissing(t *testing.T) {
	handler := RequireKey("secret", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != 401 {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestRequireKeyWrong(t *testing.T) {
	handler := RequireKey("secret", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Internal-Key", "wrong")
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != 401 {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestRequireKeyCorrect(t *testing.T) {
	handler := RequireKey("secret", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Internal-Key", "secret")
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestRequireKeyErrorFormat(t *testing.T) {
	handler := RequireKey("secret", func(w http.ResponseWriter, r *http.Request) {})
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	var resp map[string]map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"]["code"] != "unauthorized" {
		t.Fatalf("expected error code 'unauthorized', got %q", resp["error"]["code"])
	}
}
