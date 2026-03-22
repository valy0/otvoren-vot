package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/valy0/otvoren-vot/auth/provider"
	"github.com/valy0/otvoren-vot/auth/session"
	"github.com/valy0/otvoren-vot/pkg/jwtauth"
)

var egnRegex = regexp.MustCompile(`^\d{10}$`)

// LoginHandler serves the mock eAuth login HTML page and processes form submissions.
type LoginHandler struct {
	provider    provider.Provider
	sessions    session.Store
	rateLimiter RateChecker
	jwtPrivKey  ed25519.PrivateKey
	jwtPubKey   ed25519.PublicKey
	electionID  string
	allowedURIs []string
}

// NewLoginHandler constructs a LoginHandler with all required dependencies.
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

type loginPageData struct {
	CSRFToken   string
	RedirectURI string
	Error       string
}

var loginTemplate = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="bg">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>eAuth — ТЕСТОВА СРЕДА</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    background: #F0EDE8;
    color: #1a1a1a;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
  }
  .tricolor {
    width: 100%;
    height: 3px;
    background: linear-gradient(to right, #fff 0%, #fff 33.33%, #00966E 33.33%, #00966E 66.66%, #C0392B 66.66%, #C0392B 100%);
    flex-shrink: 0;
  }
  .card {
    background: #fff;
    border-radius: 16px;
    box-shadow: 0 4px 24px rgba(11,29,58,0.08), 0 1px 3px rgba(11,29,58,0.04);
    padding: 40px;
    margin-top: 80px;
    width: 100%;
    max-width: 440px;
  }
  .card-header {
    text-align: center;
    margin-bottom: 28px;
  }
  .card-header h1 {
    font-size: 1.75rem;
    font-weight: 700;
    color: #0B1D3A;
    margin-bottom: 6px;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
  }
  .lock-icon {
    display: inline-flex;
    width: 24px;
    height: 24px;
    flex-shrink: 0;
  }
  .card-header .subtitle {
    font-size: 0.9rem;
    color: #6B7280;
    margin-bottom: 12px;
  }
  .test-badge {
    display: inline-block;
    background: #FEF3C7;
    color: #92400E;
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.5px;
    padding: 4px 12px;
    border-radius: 999px;
    border: 1px solid #FDE68A;
  }
  .error {
    background: #FEF2F2;
    color: #991B1B;
    border-left: 3px solid #C0392B;
    border-radius: 8px;
    padding: 12px 16px;
    margin-bottom: 20px;
    font-size: 0.875rem;
    line-height: 1.4;
  }
  label {
    display: block;
    font-size: 0.875rem;
    font-weight: 600;
    color: #0B1D3A;
    margin-bottom: 8px;
  }
  input[type="text"] {
    width: 100%;
    height: 52px;
    padding: 0 16px;
    border: 1.5px solid #D1D5DB;
    border-radius: 12px;
    font-size: 1rem;
    color: #1a1a1a;
    background: #FAFAFA;
    transition: border-color 0.15s, box-shadow 0.15s;
    margin-bottom: 6px;
  }
  input[type="text"]:focus {
    border-color: #00966E;
    outline: none;
    box-shadow: 0 0 0 3px rgba(0,150,110,0.15);
    background: #fff;
  }
  input[type="text"]::placeholder { color: #9CA3AF; }
  .client-error {
    color: #C0392B;
    font-size: 0.8rem;
    margin-bottom: 12px;
    min-height: 1.2em;
    display: none;
  }
  .input-group { margin-bottom: 20px; }
  button[type="submit"] {
    width: 100%;
    height: 52px;
    background: #0B1D3A;
    color: #fff;
    border: none;
    border-radius: 12px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.15s;
    letter-spacing: 0.2px;
  }
  button[type="submit"]:hover { background: #091529; }
  button[type="submit"]:active { background: #060F1D; }
  .footer-text {
    text-align: center;
    font-size: 0.75rem;
    color: #9CA3AF;
    margin-top: 24px;
    padding-top: 20px;
    border-top: 1px solid #F3F4F6;
  }
  @media (max-width: 480px) {
    .card { margin: 40px 16px; padding: 28px 20px; }
  }
</style>
</head>
<body>
<div class="tricolor"></div>
<div class="card">
  <div class="card-header">
    <h1>
      <svg class="lock-icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M17 11V8A5 5 0 0 0 7 8v3" stroke="#0B1D3A" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><rect x="5" y="11" width="14" height="10" rx="2" stroke="#0B1D3A" stroke-width="1.8"/><circle cx="12" cy="16.5" r="1.5" fill="#0B1D3A"/></svg>
      Вход с eAuth
    </h1>
    <p class="subtitle">Електронна автентикация</p>
    <span class="test-badge">ТЕСТОВ РЕЖИМ</span>
  </div>
  {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
  <form method="POST" action="/login" id="loginForm" novalidate>
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
    <div class="input-group">
      <label for="egn">ЕГН (Единен граждански номер)</label>
      <input type="text" id="egn" name="egn" maxlength="10" autocomplete="off" inputmode="numeric" pattern="\d{10}" placeholder="Въведете вашето ЕГН">
      <div class="client-error" id="egnError">ЕГН трябва да съдържа точно 10 цифри.</div>
    </div>
    <button type="submit">Вход с eAuth</button>
  </form>
  <p class="footer-text">Система за електронно гласуване</p>
</div>
<script>
(function() {
  var form = document.getElementById('loginForm');
  var egnInput = document.getElementById('egn');
  var egnError = document.getElementById('egnError');
  form.addEventListener('submit', function(e) {
    var val = egnInput.value.trim();
    if (!/^\d{10}$/.test(val)) {
      e.preventDefault();
      egnError.style.display = 'block';
      egnInput.focus();
    } else {
      egnError.style.display = 'none';
    }
  });
  egnInput.addEventListener('input', function() {
    egnError.style.display = 'none';
  });
})();
</script>
</body>
</html>`))

func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate CSRF token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func (h *LoginHandler) renderLogin(w http.ResponseWriter, status int, data loginPageData) {
	// Always set a fresh CSRF cookie when rendering.
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    data.CSRFToken,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   600, // 10 minutes
	})

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	loginTemplate.Execute(w, data)
}

// HandleGetLogin serves GET /login. It validates the redirect_uri query
// parameter and renders the login form with a CSRF token.
func (h *LoginHandler) HandleGetLogin(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" || !validateRedirectURI(redirectURI, h.allowedURIs) {
		writeError(w, http.StatusBadRequest, "invalid_redirect", "Invalid or missing redirect_uri")
		return
	}

	csrfToken, err := generateCSRFToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "csrf_error", "Failed to generate CSRF token")
		return
	}

	h.renderLogin(w, http.StatusOK, loginPageData{
		CSRFToken:   csrfToken,
		RedirectURI: redirectURI,
	})
}

// HandlePostLogin processes POST /login form submissions.
func (h *LoginHandler) HandlePostLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_form", "Invalid form data")
		return
	}

	formCSRF := r.FormValue("csrf_token")
	redirectURI := r.FormValue("redirect_uri")
	egn := r.FormValue("egn")

	// Helper to re-render with an error message and fresh CSRF.
	rerender := func(status int, errMsg string) {
		csrfToken, err := generateCSRFToken()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "csrf_error", "Failed to generate CSRF token")
			return
		}
		h.renderLogin(w, status, loginPageData{
			CSRFToken:   csrfToken,
			RedirectURI: redirectURI,
			Error:       errMsg,
		})
	}

	// 1. CSRF validation.
	csrfCookie, err := r.Cookie("csrf_token")
	if err != nil || csrfCookie.Value == "" || csrfCookie.Value != formCSRF {
		rerender(http.StatusForbidden, "Невалидна заявка. Моля, опитайте отново.")
		return
	}

	// 2. Redirect URI validation.
	if redirectURI == "" || !validateRedirectURI(redirectURI, h.allowedURIs) {
		writeError(w, http.StatusBadRequest, "invalid_redirect", "Invalid or missing redirect_uri")
		return
	}

	// 3. EGN format validation (exactly 10 digits).
	if !egnRegex.MatchString(egn) {
		rerender(http.StatusBadRequest, "Невалидно ЕГН")
		return
	}

	// 4. Rate limit check.
	ctx := r.Context()
	allowed, err := h.rateLimiter.Allow(ctx, egn)
	if err != nil {
		rerender(http.StatusInternalServerError, "Грешка при проверка. Опитайте отново.")
		return
	}
	if !allowed {
		rerender(http.StatusTooManyRequests, "Твърде много опити. Опитайте отново след 10 минути.")
		return
	}

	// 5. Authenticate via mock provider.
	identity, err := h.provider.Authenticate("mock-" + egn)
	if err != nil {
		rerender(http.StatusInternalServerError, "Грешка при автентикация.")
		return
	}
	if identity == nil {
		rerender(http.StatusBadRequest, "Невалидно ЕГН")
		return
	}
	if !identity.IsEligible {
		rerender(http.StatusOK, "Нямате право на глас в тези избори.")
		return
	}

	// Success: create session and sign JWT.
	sessionID, err := h.sessions.Create(ctx, identity.EGN)
	if err != nil {
		rerender(http.StatusInternalServerError, "Грешка при създаване на сесия.")
		return
	}

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
		rerender(http.StatusInternalServerError, "Грешка при подписване на токен.")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    signed,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   int(session.SessionTTL.Seconds()),
	})

	// Build redirect URL with token.
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_redirect", "Invalid redirect_uri")
		return
	}
	q := redirectURL.Query()
	q.Set("token", signed)
	redirectURL.RawQuery = q.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// HandleSessionStatus returns the authentication status as JSON.
// It checks the session cookie for a valid JWT and responds with
// {"authenticated": true, "expires_at": "..."} or {"authenticated": false}.
func (lh *LoginHandler) HandleSessionStatus(w http.ResponseWriter, r *http.Request) {
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

// HandleSessionStatusOptions handles CORS preflight requests for /session/status.
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
