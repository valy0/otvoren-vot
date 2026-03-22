# Auth Mock Login Page — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a browser-based mock eAuth login flow so the full voting pipeline works end-to-end from the web app.

**Architecture:** Auth service serves an HTML login form at GET /login, authenticates via POST /login, sets a session cookie, and redirects back to the web app with a JWT in the URL. The web app stores the JWT in memory and sends it as a Bearer token on ballot submission.

**Tech Stack:** Go (auth service), TypeScript/React (web app), HTML/CSS (login page)

**Spec:** `docs/superpowers/specs/2026-03-22-auth-mock-login-design.md`

---

## File Structure

| File | Responsibility |
|------|---------------|
| `auth/redirect.go` (NEW) | Redirect URI parsing, validation against allowlist |
| `auth/redirect_test.go` (NEW) | Tests for redirect URI validation |
| `auth/login.go` (NEW) | GET /login + POST /login handlers, inline HTML template |
| `auth/login_test.go` (NEW) | Tests for login form rendering, CSRF, form submission |
| `auth/config.go` (MODIFY) | Add `AllowedRedirectURIs []string` field |
| `auth/handler.go` (MODIFY) | Add GET /session/status handler, change SameSite to Lax |
| `auth/main.go` (MODIFY) | Register new routes, pass config to login handler |
| `auth/provider/mock.go` (MODIFY) | EGNs starting with `00` → ineligible |
| `auth/provider/mock_test.go` (MODIFY) | Add ineligibility test |
| `web/src/App.tsx` (MODIFY) | Auth redirect, token extraction, session check |
| `web/src/ballot/submit.ts` (MODIFY) | Accept optional Bearer token for Authorization header |
| `deploy/docker-compose.yml` (MODIFY) | Add ALLOWED_REDIRECT_URIS env var |

---

## Task 1: Mock Provider Ineligibility

**Files:**
- Modify: `auth/provider/mock.go:34-38`
- Modify: `auth/provider/mock_test.go`

- [ ] **Step 1: Write failing test for ineligible EGN**

In `auth/provider/mock_test.go`, add:

```go
func TestMockIneligibleEGN(t *testing.T) {
	m := NewMockProvider()
	id, err := m.Authenticate("mock-0012345678")
	if err != nil {
		t.Fatal(err)
	}
	if id == nil {
		t.Fatal("should return identity for valid EGN starting with 00")
	}
	if id.IsEligible {
		t.Fatal("EGN starting with 00 should be ineligible")
	}
}

func TestMockEligibleEGN(t *testing.T) {
	m := NewMockProvider()
	id, err := m.Authenticate("mock-8501011234")
	if err != nil {
		t.Fatal(err)
	}
	if !id.IsEligible {
		t.Fatal("regular EGN should be eligible")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd auth && go test ./provider/... -run TestMockIneligibleEGN -v`
Expected: FAIL — `id.IsEligible` is true

- [ ] **Step 3: Implement ineligibility check**

In `auth/provider/mock.go`, change line 37 from:
```go
IsEligible: true,
```
to:
```go
IsEligible: !strings.HasPrefix(egn, "00"),
```

- [ ] **Step 4: Run tests**

Run: `cd auth && go test ./provider/... -v`
Expected: All 7 tests pass

- [ ] **Step 5: Commit**

```
git add auth/provider/mock.go auth/provider/mock_test.go
git commit -m "feat(auth): mock provider returns ineligible for EGNs starting with 00"
```

---

## Task 2: Redirect URI Validation

**Files:**
- Create: `auth/redirect.go`
- Create: `auth/redirect_test.go`

- [ ] **Step 1: Write failing tests**

Create `auth/redirect_test.go`:

```go
package main

import "testing"

func TestValidateRedirectURI(t *testing.T) {
	patterns := []string{"http://localhost:*"}

	tests := []struct {
		name    string
		uri     string
		wantOK  bool
	}{
		{"localhost any port", "http://localhost:3000", true},
		{"localhost 8080", "http://localhost:8080", true},
		{"localhost no port", "http://localhost", true},
		{"wrong scheme", "https://localhost:3000", false},
		{"wrong host", "http://example.com:3000", false},
		{"userinfo attack", "http://user@evil.com", false},
		{"empty", "", false},
		{"no scheme", "localhost:3000", false},
		{"production exact", "https://izbori.bg", false}, // not in patterns
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateRedirectURI(tt.uri, patterns)
			if got != tt.wantOK {
				t.Errorf("validateRedirectURI(%q) = %v, want %v", tt.uri, got, tt.wantOK)
			}
		})
	}
}

func TestValidateRedirectURIProduction(t *testing.T) {
	patterns := []string{"https://izbori.bg", "https://vote.izbori.bg"}

	tests := []struct {
		uri    string
		wantOK bool
	}{
		{"https://izbori.bg", true},
		{"https://vote.izbori.bg", true},
		{"https://evil.izbori.bg", false},
		{"http://izbori.bg", false}, // wrong scheme
	}

	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			got := validateRedirectURI(tt.uri, patterns)
			if got != tt.wantOK {
				t.Errorf("got %v, want %v", got, tt.wantOK)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd auth && go test -run TestValidateRedirectURI -v`
Expected: FAIL — `validateRedirectURI` undefined

- [ ] **Step 3: Implement redirect URI validation**

Create `auth/redirect.go`:

```go
package main

import (
	"net/url"
	"strings"
)

// validateRedirectURI checks if uri matches any of the allowed patterns.
// Matching compares scheme, host, and port. A "*" in the port position
// of a pattern matches any port. URLs with userinfo are always rejected.
func validateRedirectURI(uri string, patterns []string) bool {
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	if parsed.User != nil {
		return false
	}

	uriScheme := parsed.Scheme
	uriHost := parsed.Hostname()
	uriPort := parsed.Port()

	for _, pattern := range patterns {
		pURL, err := url.Parse(pattern)
		if err != nil {
			continue
		}
		pScheme := pURL.Scheme
		pHost := pURL.Hostname()
		pPort := pURL.Port()

		if uriScheme != pScheme {
			continue
		}
		if !strings.EqualFold(uriHost, pHost) {
			continue
		}
		if pPort == "*" || pPort == uriPort {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run tests**

Run: `cd auth && go test -run TestValidateRedirectURI -v`
Expected: All tests pass

- [ ] **Step 5: Commit**

```
git add auth/redirect.go auth/redirect_test.go
git commit -m "feat(auth): add redirect URI validation with allowlist matching"
```

---

## Task 3: Config — AllowedRedirectURIs

**Files:**
- Modify: `auth/config.go`

- [ ] **Step 1: Add field and parsing**

In `auth/config.go`, add to Config struct:

```go
AllowedRedirectURIs []string
```

In `LoadConfig`, add:

```go
AllowedRedirectURIs: parseCSV(envOr("ALLOWED_REDIRECT_URIS", "http://localhost:*")),
```

Add helper:

```go
func parseCSV(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
```

Add `"strings"` to the import.

- [ ] **Step 2: Verify build**

Run: `cd auth && go build ./...`
Expected: exit 0

- [ ] **Step 3: Commit**

```
git add auth/config.go
git commit -m "feat(auth): add ALLOWED_REDIRECT_URIS config field"
```

---

## Task 4: Login Page Handlers (GET /login, POST /login)

**Files:**
- Create: `auth/login.go`
- Create: `auth/login_test.go`
- Modify: `auth/main.go`

This is the largest task. It contains the HTML template, CSRF logic, and form handling.

- [ ] **Step 1: Write tests for GET /login**

Create `auth/login_test.go`:

```go
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

// Test Ed25519 key pair (package-level for reuse).
var testPrivKey, testPubKey, _ = func() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	return priv, pub, err
}()

// mockRateChecker always allows (set denyAll=true to simulate rate limiting).
type mockRateChecker struct{ denyAll bool }

func (m *mockRateChecker) Allow(_ context.Context, _ string) (bool, error) {
	return !m.denyAll, nil
}

// mockSessionStore stubs the session interface.
type mockSessionStore struct{ lastEGN string }

func (m *mockSessionStore) Create(_ context.Context, egn string) (string, error) {
	m.lastEGN = egn
	return "test-session-id", nil
}
func (m *mockSessionStore) Resolve(_ context.Context, id string) (string, error) {
	if id == "test-session-id" {
		return m.lastEGN, nil
	}
	return "", session.ErrSessionNotFound
}

func newTestLoginHandler() *LoginHandler {
	return NewLoginHandler(
		provider.NewMockProvider(),
		&mockSessionStore{},
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
	req := httptest.NewRequest("GET", "/login?redirect_uri=http://localhost:3000", nil)
	rr := httptest.NewRecorder()
	h.HandleGetLogin(rr, req)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "ТЕСТОВА СРЕДА") {
		t.Fatal("should contain test environment banner")
	}
	if !strings.Contains(body, "csrf_token") {
		t.Fatal("should contain CSRF token field")
	}
}

func TestGetLoginRejectsInvalidRedirect(t *testing.T) {
	h := newTestLoginHandler()
	req := httptest.NewRequest("GET", "/login?redirect_uri=http://evil.com", nil)
	rr := httptest.NewRecorder()
	h.HandleGetLogin(rr, req)
	if rr.Code != 400 {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestGetLoginRejectsMissingRedirect(t *testing.T) {
	h := newTestLoginHandler()
	req := httptest.NewRequest("GET", "/login", nil)
	rr := httptest.NewRecorder()
	h.HandleGetLogin(rr, req)
	if rr.Code != 400 {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}
```

Note: The test file will need a helper to generate an Ed25519 test key. Use `crypto/ed25519.GenerateKey(nil)` from the test.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd auth && go test -run TestGetLogin -v`
Expected: FAIL — `LoginHandler` undefined

- [ ] **Step 3: Implement LoginHandler with GET /login**

Create `auth/login.go` with:

```go
// LoginHandler serves the mock eAuth login page.
type LoginHandler struct {
	provider    provider.Provider
	sessions    session.Store
	rateLimiter RateChecker
	jwtPrivKey  ed25519.PrivateKey
	jwtPubKey   ed25519.PublicKey
	electionID  string
	allowedURIs []string
}

func NewLoginHandler(p provider.Provider, s session.Store, rl RateChecker, privKey ed25519.PrivateKey, electionID string, allowedURIs []string) *LoginHandler {
	return &LoginHandler{
		provider:    p,
		sessions:    s,
		rateLimiter: rl,
		jwtPrivKey:  privKey,
		jwtPubKey:   privKey.Public().(ed25519.PublicKey),
		electionID:  electionID,
		allowedURIs: allowedURIs,
	}
}
```

Then implement:
- `HandleGetLogin` — validates redirect_uri, generates CSRF token, renders HTML
- `loginPageHTML` — Go template string with inline CSS/JS, red "ТЕСТОВА СРЕДА" banner, EGN input, hidden fields for csrf_token and redirect_uri
- CSRF token: generate 32 random bytes (hex), set as `csrf_token` cookie (HttpOnly, 10 min expiry), embed in hidden form field

The HTML template should include:
- Red banner: "ТЕСТОВА СРЕДА — Това не е истинска система за гласуване"
- Form: EGN label, input (maxlength=10, pattern=[0-9]{10}), submit button "Вход с eAuth"
- Error display area (populated via Go template variable)
- Inline JS: prevent submission if EGN is not exactly 10 digits

- [ ] **Step 4: Run tests**

Run: `cd auth && go test -run TestGetLogin -v`
Expected: All 3 tests pass

- [ ] **Step 5: Write tests for POST /login**

Add to `auth/login_test.go`:

```go
func TestPostLoginSuccess(t *testing.T) {
	h := newTestLoginHandler()
	// First GET to obtain CSRF token
	getReq := httptest.NewRequest("GET", "/login?redirect_uri=http://localhost:3000", nil)
	getRR := httptest.NewRecorder()
	h.HandleGetLogin(getRR, getReq)
	csrfCookie := getCookie(getRR, "csrf_token")

	// POST with valid EGN
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

	if postRR.Code != 302 {
		t.Fatalf("expected 302 redirect, got %d", postRR.Code)
	}
	loc := postRR.Header().Get("Location")
	if !strings.HasPrefix(loc, "http://localhost:3000?token=") {
		t.Fatalf("unexpected redirect: %s", loc)
	}
}

func TestPostLoginIneligible(t *testing.T) {
	h := newTestLoginHandler()
	getReq := httptest.NewRequest("GET", "/login?redirect_uri=http://localhost:3000", nil)
	getRR := httptest.NewRecorder()
	h.HandleGetLogin(getRR, getReq)
	csrfCookie := getCookie(getRR, "csrf_token")

	form := url.Values{
		"egn":          {"0012345678"}, // starts with 00 → ineligible
		"redirect_uri": {"http://localhost:3000"},
		"csrf_token":   {csrfCookie.Value},
	}
	postReq := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.AddCookie(csrfCookie)
	postRR := httptest.NewRecorder()
	h.HandlePostLogin(postRR, postReq)

	if postRR.Code != 200 {
		t.Fatalf("expected 200 (re-render), got %d", postRR.Code)
	}
	body := postRR.Body.String()
	if !strings.Contains(body, "Нямате право на глас") {
		t.Fatal("should show ineligibility error")
	}
}

func TestPostLoginInvalidCSRF(t *testing.T) {
	h := newTestLoginHandler()
	form := url.Values{
		"egn":          {"8501011234"},
		"redirect_uri": {"http://localhost:3000"},
		"csrf_token":   {"wrong-token"},
	}
	postReq := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.AddCookie(&http.Cookie{Name: "csrf_token", Value: "correct-token"})
	postRR := httptest.NewRecorder()
	h.HandlePostLogin(postRR, postReq)

	if postRR.Code != 403 {
		t.Fatalf("expected 403, got %d", postRR.Code)
	}
}

func TestPostLoginInvalidEGN(t *testing.T) {
	h := newTestLoginHandler()
	getReq := httptest.NewRequest("GET", "/login?redirect_uri=http://localhost:3000", nil)
	getRR := httptest.NewRecorder()
	h.HandleGetLogin(getRR, getReq)
	csrfCookie := getCookie(getRR, "csrf_token")

	form := url.Values{
		"egn":          {"abc"},
		"redirect_uri": {"http://localhost:3000"},
		"csrf_token":   {csrfCookie.Value},
	}
	postReq := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.AddCookie(csrfCookie)
	postRR := httptest.NewRecorder()
	h.HandlePostLogin(postRR, postReq)

	if postRR.Code != 400 {
		t.Fatalf("expected 400, got %d", postRR.Code)
	}
	body := postRR.Body.String()
	if !strings.Contains(body, "Невалидно ЕГН") {
		t.Fatal("should show invalid EGN error")
	}
}
```

- [ ] **Step 6: Implement POST /login**

Add `HandlePostLogin` to `auth/login.go`:
1. Validate CSRF token (form field vs cookie)
2. Validate redirect_uri against allowlist
3. Validate EGN format (10 digits server-side)
4. Check rate limit
5. Call provider.Authenticate with `"mock-{egn}"`
6. Handle nil identity (generic error), ineligible (specific error), success
7. On success: create session, sign JWT, set session cookie (SameSite=Lax), redirect to `redirect_uri?token={jwt}`
8. On error: re-render form with error message, preserve redirect_uri and CSRF as hidden fields

- [ ] **Step 7: Run all login tests**

Run: `cd auth && go test -run "TestGetLogin|TestPostLogin" -v`
Expected: All tests pass

- [ ] **Step 8: Commit**

```
git add auth/login.go auth/login_test.go
git commit -m "feat(auth): add mock eAuth login page with CSRF protection"
```

---

## Task 5: Session Status Endpoint + Cookie SameSite

**Files:**
- Modify: `auth/handler.go:119-127` (cookie SameSite)
- Modify: `auth/main.go` (register routes)

- [ ] **Step 1: Write test for session status**

Add to `auth/login_test.go`:

```go
func TestSessionStatusAuthenticated(t *testing.T) {
	h := newTestLoginHandler()

	// First, do a full login to get a session cookie
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

	// Now check session status
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
```

- [ ] **Step 2: Implement HandleSessionStatus**

Add to `auth/login.go`:

```go
func (lh *LoginHandler) HandleSessionStatus(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers for allowed origins
	origin := r.Header.Get("Origin")
	if validateRedirectURI(origin, lh.allowedURIs) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Vary", "Origin")
	}

	cookie, err := r.Cookie("session")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"authenticated": false})
		return
	}

	// Parse JWT to get session ID and expiry
	claims, err := jwtauth.Verify(cookie.Value, lh.jwtPubKey)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"authenticated": false})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"authenticated": true,
		"expires_at":    claims.ExpiresAt.Time.Format(time.RFC3339),
	})
}
```

Note: The LoginHandler will need access to the Ed25519 **public** key for JWT verification. Derive it from the private key: `privKey.Public().(ed25519.PublicKey)`.

- [ ] **Step 3: Change SameSite from Strict to Lax**

In `auth/handler.go:124`, change:
```go
SameSite: http.SameSiteStrictMode,
```
to:
```go
SameSite: http.SameSiteLaxMode,
```

Do the same in the login.go cookie-setting code.

- [ ] **Step 4: Register routes in main.go**

In `auth/main.go`, after creating `authHandler`, add:

```go
loginHandler := NewLoginHandler(p, sessions, rateLimiter, jwtPrivKey, cfg.ElectionID, cfg.AllowedRedirectURIs)

mux.HandleFunc("GET /login", loginHandler.HandleGetLogin)
mux.HandleFunc("POST /login", loginHandler.HandlePostLogin)
mux.HandleFunc("GET /session/status", loginHandler.HandleSessionStatus)
```

Also add CORS preflight handling for /session/status:
```go
mux.HandleFunc("OPTIONS /session/status", loginHandler.HandleSessionStatusOptions)
```

`HandleSessionStatusOptions` in `auth/login.go`:
```go
func (lh *LoginHandler) HandleSessionStatusOptions(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if validateRedirectURI(origin, lh.allowedURIs) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Max-Age", "86400")
		w.Header().Set("Vary", "Origin")
	}
	w.WriteHeader(http.StatusNoContent)
}
```

- [ ] **Step 5: Run all auth tests**

Run: `cd auth && go test ./... -v`
Expected: All tests pass

- [ ] **Step 6: Commit**

```
git add auth/handler.go auth/main.go auth/login.go auth/login_test.go
git commit -m "feat(auth): add session status endpoint, change cookie SameSite to Lax"
```

---

## Task 6: Web App — Auth Redirect + Token Handling

**Files:**
- Modify: `web/src/App.tsx`
- Modify: `web/src/ballot/submit.ts`

- [ ] **Step 1: Add AUTH_URL config**

In `web/src/App.tsx`, after the existing BB_URL/COLLECTION_URL constants:

```typescript
const AUTH_URL = (import.meta.env.VITE_AUTH_URL as string | undefined) ?? 'http://localhost:8082'
```

- [ ] **Step 2: Add token state and session detection on mount**

Add a `token` ref and modify the `useEffect` to check for auth token in URL:

```typescript
const [authToken, setAuthToken] = useState<string | null>(null)

useEffect(() => {
  // Check for token in URL (returned from auth service redirect)
  const params = new URLSearchParams(window.location.search)
  const urlToken = params.get('token')
  if (urlToken) {
    setAuthToken(urlToken)
    // Remove token from URL for security
    window.history.replaceState({}, '', window.location.pathname)
  }

  // Check session status with auth service
  const checkSession = async () => {
    try {
      const res = await fetch(`${AUTH_URL}/session/status`, { credentials: 'include' })
      const data = await res.json()
      if (data.authenticated && urlToken) {
        // Session valid + we have token → skip auth
        const config = await fetchElectionConfig(BB_URL)
        electionConfigRef.current = config
        setState({ phase: 'ballot', config })
        return
      }
    } catch {
      // Session check failed — fall through to normal loading
    }
    // Normal loading flow
    fetchElectionConfig(BB_URL)
      .then(config => {
        electionConfigRef.current = config
        setState({ phase: 'auth' })
      })
      .catch(/* existing error handler */)
  }
  checkSession()
}, [])
```

- [ ] **Step 3: Change handleAuth to redirect**

Replace the existing `handleAuth`:

```typescript
function handleAuth() {
  window.location.href = `${AUTH_URL}/login?redirect_uri=${encodeURIComponent(window.location.origin)}`
}
```

- [ ] **Step 4: Modify submitBallot to accept Bearer token**

In `web/src/ballot/submit.ts`, change the function signature to accept an optional token:

```typescript
export async function submitBallot(
  collectionUrl: string,
  ballotId: string,
  encryptedBallot: object,
  zkProofs: object,
  bearerToken?: string,
): Promise<BallotReceipt> {
```

In the fetch call, add Authorization header when token is provided:

```typescript
const headers: Record<string, string> = { 'Content-Type': 'application/json' }
if (bearerToken) {
  headers['Authorization'] = `Bearer ${bearerToken}`
}

res = await fetch(url, {
  method: 'POST',
  credentials: 'include',
  headers,
  body: JSON.stringify({ ... }),
})
```

- [ ] **Step 5: Pass token to submitBallot in App.tsx**

In `handleSubmit`, pass the auth token:

```typescript
const receipt = await submitBallot(
  COLLECTION_URL,
  encrypted.ballotId,
  encrypted.encryptedBallot,
  encrypted.zkProofs,
  authToken ?? undefined,
)
```

- [ ] **Step 6: Handle session expiry → redirect to login**

In the `handleSubmit` catch block, when `SessionExpiredError` is detected, redirect to login:

```typescript
if (isSessionExpired) {
  window.location.href = `${AUTH_URL}/login?redirect_uri=${encodeURIComponent(window.location.origin)}`
  return
}
```

- [ ] **Step 7: Type-check**

Run: `cd web && npx tsc --noEmit`
Expected: exit 0

- [ ] **Step 8: Commit**

```
git add web/src/App.tsx web/src/ballot/submit.ts
git commit -m "feat(web): integrate auth redirect flow with JWT token handling"
```

---

## Task 7: Docker Compose + Integration Verification

**Files:**
- Modify: `deploy/docker-compose.yml`

- [ ] **Step 1: Add ALLOWED_REDIRECT_URIS to auth service**

In `deploy/docker-compose.yml`, add to the auth service environment:

```yaml
ALLOWED_REDIRECT_URIS: ${ALLOWED_REDIRECT_URIS:-http://localhost:*}
```

- [ ] **Step 2: Build all Go services**

Run:
```bash
for svc in auth bulletin-board collection tally verification; do
  echo "=== $svc ==="
  (cd "$svc" && GOTOOLCHAIN=local go build ./...) && echo "OK" || echo "FAIL"
done
```
Expected: All OK

- [ ] **Step 3: Run all Go tests**

Run:
```bash
for svc in auth bulletin-board collection tally verification crypto; do
  echo "=== $svc ==="
  (cd "$svc" && GOTOOLCHAIN=local go test ./... -count=1)
done
```
Expected: All pass

- [ ] **Step 4: Type-check web app**

Run: `cd web && npx tsc --noEmit`
Expected: exit 0

- [ ] **Step 5: Docker compose validation**

Run:
```bash
cd deploy && POSTGRES_PASSWORD_BB=x POSTGRES_PASSWORD_COLLECTION=x INTERNAL_API_KEY=x SESSION_API_KEY=x BULLETIN_BOARD_API_KEY=x ACTIVE_SET_API_KEY=x CEREMONY_API_KEY=x VERIFICATION_API_KEY=x EGN_HMAC_KEY=x HISTORY_HMAC_KEY=x docker compose config > /dev/null
```
Expected: exit 0

- [ ] **Step 6: Full stack integration test**

```bash
cd deploy
bash generate-dev-keys.sh
docker compose --env-file .env down -v
docker compose --env-file .env up --build -d
# Wait for services
sleep 10
docker compose --env-file .env ps -a
# All 9 services should be running
# Test login page renders
curl -s http://localhost:8082/login?redirect_uri=http://localhost:3000 | grep "ТЕСТОВА СРЕДА"
# Test login rejects bad redirect
curl -s -o /dev/null -w "%{http_code}" http://localhost:8082/login?redirect_uri=http://evil.com
# Expected: 400
docker compose --env-file .env down
```

- [ ] **Step 7: Commit**

```
git add deploy/docker-compose.yml
git commit -m "chore: add ALLOWED_REDIRECT_URIS to docker-compose auth service"
```

---

## Execution Dependencies

```
Task 1 (mock provider)     ─┐
Task 2 (redirect validation)─┼─→ Task 4 (login handlers) ─→ Task 5 (session status) ─→ Task 7 (integration)
Task 3 (config)            ─┘                                                            ↑
                                                             Task 6 (web app) ────────────┘
```

Tasks 1, 2, 3 are independent and can run in parallel.
Task 4 depends on 1, 2, 3.
Task 5 depends on 4.
Task 6 is independent of Go tasks but depends on the API contract from Task 4/5.
Task 7 depends on all other tasks.
