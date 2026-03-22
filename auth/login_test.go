package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/valy0/otvoren-vot/auth/provider"
	"github.com/valy0/otvoren-vot/auth/session"
)

var testPrivKey, _, _ = func() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	return priv, pub, err
}()

type mockRateChecker struct{ denyAll bool }

func (m *mockRateChecker) Allow(_ context.Context, _ string) (bool, error) {
	return !m.denyAll, nil
}

type mockLoginSessionStore struct{ lastEGN string }

func (m *mockLoginSessionStore) Create(_ context.Context, egn string) (string, error) {
	m.lastEGN = egn
	return "test-session-id", nil
}

func (m *mockLoginSessionStore) Resolve(_ context.Context, id string) (string, error) {
	if id == "test-session-id" {
		return m.lastEGN, nil
	}
	return "", session.ErrSessionNotFound
}

func newTestLoginHandler() *LoginHandler {
	return NewLoginHandler(
		provider.NewMockProvider(),
		&mockLoginSessionStore{},
		&mockRateChecker{},
		testPrivKey,
		"test-election",
		[]string{"http://localhost:*"},
	)
}

func getCookie(rr *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rr.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestGetLoginRendersForm(t *testing.T) {
	h := newTestLoginHandler()
	req := httptest.NewRequest("GET", "/login?redirect_uri=http://localhost:3000/callback", nil)
	w := httptest.NewRecorder()

	h.HandleGetLogin(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := w.Body.String()
	if !strings.Contains(body, "ТЕСТОВА СРЕДА") {
		t.Fatal("page should contain test environment banner")
	}
	if !strings.Contains(body, "csrf_token") {
		t.Fatal("page should contain csrf_token hidden field")
	}

	// Should set csrf_token cookie.
	cookie := getCookie(w, "csrf_token")
	if cookie == nil {
		t.Fatal("expected csrf_token cookie to be set")
	}
	if !cookie.HttpOnly {
		t.Fatal("csrf_token cookie should be HttpOnly")
	}
}

func TestGetLoginRejectsInvalidRedirect(t *testing.T) {
	h := newTestLoginHandler()
	req := httptest.NewRequest("GET", "/login?redirect_uri=http://evil.com/steal", nil)
	w := httptest.NewRecorder()

	h.HandleGetLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetLoginRejectsMissingRedirect(t *testing.T) {
	h := newTestLoginHandler()
	req := httptest.NewRequest("GET", "/login", nil)
	w := httptest.NewRecorder()

	h.HandleGetLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPostLoginSuccess(t *testing.T) {
	h := newTestLoginHandler()

	// Step 1: GET to obtain a CSRF token.
	getReq := httptest.NewRequest("GET", "/login?redirect_uri=http://localhost:3000/callback", nil)
	getW := httptest.NewRecorder()
	h.HandleGetLogin(getW, getReq)

	csrfCookie := getCookie(getW, "csrf_token")
	if csrfCookie == nil {
		t.Fatal("expected csrf_token cookie from GET")
	}

	// Step 2: POST with valid EGN and CSRF token.
	form := url.Values{}
	form.Set("egn", "8501011234")
	form.Set("csrf_token", csrfCookie.Value)
	form.Set("redirect_uri", "http://localhost:3000/callback")

	postReq := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfCookie.Value})

	postW := httptest.NewRecorder()
	h.HandlePostLogin(postW, postReq)

	if postW.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", postW.Code, postW.Body.String())
	}

	location := postW.Header().Get("Location")
	if !strings.HasPrefix(location, "http://localhost:3000/callback?token=") {
		t.Fatalf("expected redirect to callback with token, got %q", location)
	}
}

func TestPostLoginIneligible(t *testing.T) {
	h := newTestLoginHandler()

	// GET to obtain CSRF.
	getReq := httptest.NewRequest("GET", "/login?redirect_uri=http://localhost:3000/callback", nil)
	getW := httptest.NewRecorder()
	h.HandleGetLogin(getW, getReq)
	csrfCookie := getCookie(getW, "csrf_token")

	form := url.Values{}
	form.Set("egn", "0012345678")
	form.Set("csrf_token", csrfCookie.Value)
	form.Set("redirect_uri", "http://localhost:3000/callback")

	postReq := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfCookie.Value})

	postW := httptest.NewRecorder()
	h.HandlePostLogin(postW, postReq)

	if postW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", postW.Code, postW.Body.String())
	}

	body := postW.Body.String()
	if !strings.Contains(body, "Нямате право на глас") {
		t.Fatalf("expected ineligibility message, got: %s", body)
	}
}

func TestPostLoginInvalidCSRF(t *testing.T) {
	h := newTestLoginHandler()

	// GET to obtain CSRF.
	getReq := httptest.NewRequest("GET", "/login?redirect_uri=http://localhost:3000/callback", nil)
	getW := httptest.NewRecorder()
	h.HandleGetLogin(getW, getReq)
	csrfCookie := getCookie(getW, "csrf_token")

	form := url.Values{}
	form.Set("egn", "8501011234")
	form.Set("csrf_token", "wrong-csrf-value")
	form.Set("redirect_uri", "http://localhost:3000/callback")

	postReq := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfCookie.Value})

	postW := httptest.NewRecorder()
	h.HandlePostLogin(postW, postReq)

	if postW.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", postW.Code, postW.Body.String())
	}
}

func TestSessionStatusAuthenticated(t *testing.T) {
	h := newTestLoginHandler()

	// Full login to get session cookie
	getReq := httptest.NewRequest("GET", "/login?redirect_uri=http://localhost:3000", nil)
	getRR := httptest.NewRecorder()
	h.HandleGetLogin(getRR, getReq)
	csrfCookie := getCookie(getRR, "csrf_token")

	form := url.Values{
		"egn":          {"8501011234"},
		"redirect_uri": {"http://localhost:3000"},
		"csrf_token":   {csrfCookie.Value},
	}
	postReq := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.AddCookie(csrfCookie)
	postRR := httptest.NewRecorder()
	h.HandlePostLogin(postRR, postReq)

	sessionCookie := getCookie(postRR, "session")
	if sessionCookie == nil {
		t.Fatal("login should set session cookie")
	}

	// Check session status
	statusReq := httptest.NewRequest("GET", "/session/status", nil)
	statusReq.AddCookie(sessionCookie)
	statusRR := httptest.NewRecorder()
	h.HandleSessionStatus(statusRR, statusReq)

	if statusRR.Code != 200 {
		t.Fatalf("expected 200, got %d", statusRR.Code)
	}
	var result map[string]any
	json.NewDecoder(statusRR.Body).Decode(&result)
	if result["authenticated"] != true {
		t.Fatal("should be authenticated")
	}
}

func TestSessionStatusNotAuthenticated(t *testing.T) {
	h := newTestLoginHandler()
	req := httptest.NewRequest("GET", "/session/status", nil)
	rr := httptest.NewRecorder()
	h.HandleSessionStatus(rr, req)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var result map[string]any
	json.NewDecoder(rr.Body).Decode(&result)
	if result["authenticated"] != false {
		t.Fatal("should not be authenticated")
	}
}

func TestPostLoginInvalidEGN(t *testing.T) {
	h := newTestLoginHandler()

	// GET to obtain CSRF.
	getReq := httptest.NewRequest("GET", "/login?redirect_uri=http://localhost:3000/callback", nil)
	getW := httptest.NewRecorder()
	h.HandleGetLogin(getW, getReq)
	csrfCookie := getCookie(getW, "csrf_token")

	form := url.Values{}
	form.Set("egn", "abc")
	form.Set("csrf_token", csrfCookie.Value)
	form.Set("redirect_uri", "http://localhost:3000/callback")

	postReq := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfCookie.Value})

	postW := httptest.NewRecorder()
	h.HandlePostLogin(postW, postReq)

	if postW.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", postW.Code, postW.Body.String())
	}

	body := postW.Body.String()
	if !strings.Contains(body, "Невалидно ЕГН") {
		t.Fatalf("expected invalid EGN message, got: %s", body)
	}
}
