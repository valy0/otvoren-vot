# Auth Mock Login Page — Design Spec

**Date:** 2026-03-22
**Status:** Draft (pending review)

## Purpose

Provide a demo-ready mock authentication flow that works end-to-end in the browser. The auth service serves a simulated eAuth login page, the web app redirects to it, and after authentication the voter is redirected back with a session cookie to proceed to ballot selection. This enables CIK presentations and public demos without the real eAuth 2.0 integration.

The login page displays a red "ТЕСТОВА СРЕДА" banner to clearly indicate demo mode.

## Architecture

The login page is served by the auth service (not embedded in the web app). This mimics the real eAuth redirect flow, so the web app's auth integration carries over to production with minimal changes.

### Cross-Origin Cookie Strategy

Auth service runs at `localhost:8082`, web app at `localhost:3000` (or any Vite port). The session cookie is set on the auth service's origin and is HttpOnly (not readable by JS). To handle cross-origin session detection:

- The web app calls `GET /session/status` on the **auth service** (not the collection service) using `fetch(..., { credentials: 'include' })` so the browser sends the cookie.
- The auth service sets CORS headers allowing the web app's origin for this endpoint.
- For ballot submission, the collection service is on a different origin, so the JWT is also returned in the redirect URL as a query parameter `?token=...`, which the web app stores in memory and sends as `Authorization: Bearer` header.

### Flow

```
1. Web App: user clicks "Гласувай онлайн"
2. Web App: redirects to {AUTH_URL}/login?redirect_uri={origin}
3. Auth Service: validates redirect_uri against allowlist
4. Auth Service: serves Bulgarian-language HTML login form with CSRF token
5. User: enters 10-digit EGN, clicks "Вход с eAuth"
6. Auth Service: POST /login validates CSRF token, then EGN via mock provider
7. Auth Service: creates session, signs JWT, sets session cookie
8. Auth Service: redirects to redirect_uri?token={JWT}
9. Web App: reads token from URL param, stores in memory, removes from URL
10. Web App: calls GET /session/status on auth service to confirm session
11. Web App: skips auth phase, shows ballot phase
```

## Auth Service Changes

### New: GET /login

Serves a single HTML document with inline `<style>` and `<script>` tags (no external resources):
- Red "ТЕСТОВА СРЕДА" banner at top
- Bulgarian language UI
- Input field for EGN (10 digits), "Вход с eAuth" button
- Inline JavaScript performs client-side validation (10 digits, numeric only) before submission
- Accepts `redirect_uri` query parameter (validated against allowlist before rendering)
- If `redirect_uri` is missing or invalid: returns HTTP 400 JSON `{"error": "invalid redirect_uri"}`
- Generates a CSRF token (random, stored in session-scoped cookie), embedded as hidden form field
- `redirect_uri` preserved as hidden form field

### New: POST /login

Form handler — validates in this order:
1. **CSRF token** — compare form field against CSRF cookie. If mismatch: HTTP 403, re-render form with generic error.
2. **redirect_uri** — validate against allowlist. If invalid: HTTP 400 JSON error (user never saw the form legitimately).
3. **EGN format** — server-side validation: exactly 10 digits. If invalid: HTTP 400, re-render form with error. No rate limit consumed.
4. **Rate limit** — check existing per-EGN rate limiter (5 attempts / 10 min). If exceeded: HTTP 429, re-render form with error "Твърде много опити. Опитайте отново след 10 минути."
5. **Authentication** — construct token `"mock-{egn}"`, call mock provider.
   - If `Identity == nil` (invalid token): HTTP 400, re-render with generic error.
   - If `IsEligible == false`: HTTP 200, re-render with error "Нямате право на глас в тези избори."
   - If success: create session, sign JWT, set `session` cookie, redirect (302) to `{redirect_uri}?token={JWT}`

Error re-renders preserve `redirect_uri` and CSRF token as hidden fields so the user can retry.

**Note on error messages:** Invalid EGN format and authentication failure use the same generic message ("Невалидно ЕГН") to prevent EGN enumeration. Ineligibility is shown distinctly because it's a legitimate voter status, not a security-sensitive distinction in the mock.

### New: GET /session/status

- HTTP 200 `{"authenticated": true, "expires_at": "..."}` if session cookie is valid and session exists in Redis
- HTTP 200 `{"authenticated": false}` if no session cookie or session expired
- CORS: allows the web app's origin (reads from `ALLOWED_REDIRECT_URIS`) with `credentials: true`
- Web app calls this with `fetch(..., { credentials: 'include' })` to send the cookie cross-origin

### New: ALLOWED_REDIRECT_URIS config

- Environment variable: `ALLOWED_REDIRECT_URIS`
- Parsed as `[]string` (comma-separated) in `LoadConfig`
- Default: `http://localhost:*`

**Matching algorithm:**
1. Parse redirect_uri as a URL (must be valid, must have scheme and host)
2. For each allowlist pattern, parse scheme and host:port
3. Match scheme exactly (http vs https)
4. Match host exactly
5. `*` in port position matches any port (e.g., `http://localhost:*` matches `http://localhost:3000`)
6. No path matching — only scheme + host + port are validated
7. Reject URLs with userinfo (e.g., `http://user@evil.com`)

Production example: `ALLOWED_REDIRECT_URIS=https://izbori.bg,https://vote.izbori.bg`

### Existing POST /authenticate — unchanged

The JSON API stays as-is for programmatic/test use.

## Mock Provider Change

**File:** `auth/provider/mock.go`

Current behavior: all valid 10-digit EGNs return `IsEligible: true`.

New behavior:
- EGNs starting with `00` → `IsEligible: false`
- All other valid 10-digit EGNs → `IsEligible: true`

Add test cases in `auth/provider/mock_test.go` for ineligibility.

## Web App Changes

**File:** `web/src/App.tsx`

### Config

Add `AUTH_URL` via Vite env var:
```typescript
const AUTH_URL = (import.meta.env.VITE_AUTH_URL as string | undefined) ?? 'http://localhost:8082'
```

### Auth phase

Replace the current button (which just transitions state) with a redirect:
- "Гласувай онлайн" button triggers: `window.location.href = \`${AUTH_URL}/login?redirect_uri=${encodeURIComponent(window.location.origin)}\``

### Session detection on load

On app mount:
1. Check URL for `?token=...` query parameter
2. If present: store JWT in React state (memory only), remove from URL via `history.replaceState`
3. Call `GET ${AUTH_URL}/session/status` with `{ credentials: 'include' }` to confirm session is valid
4. If `authenticated: true`: skip auth phase, proceed to ballot selection
5. If `authenticated: false`: show auth phase

The JWT stored in memory is sent as `Authorization: Bearer {token}` header on ballot submission to the collection service.

### Session expiry

Session TTL is 30 minutes (set by auth service). The web app should not add expiry warnings for the mock — if the session expires during ballot filling, the 401 from collection service triggers a redirect back to login.

## Collection Service — No Changes

The collection service already validates JWT from `Authorization: Bearer` header (preferred path) or `session` cookie. The web app sends the JWT as a Bearer token, so no cross-origin cookie issues.

## Docker Compose Changes

Add to auth service environment:
```yaml
ALLOWED_REDIRECT_URIS: ${ALLOWED_REDIRECT_URIS:-http://localhost:*}
```

## File Summary

| File | Change |
|------|--------|
| `auth/login.go` (NEW) | Login page HTML template, GET /login, POST /login handlers |
| `auth/handler.go` | Add GET /session/status handler, register login routes |
| `auth/config.go` | Add `AllowedRedirectURIs []string` field, parse from env |
| `auth/redirect.go` (NEW) | Redirect URI validation logic (parse + match against allowlist) |
| `auth/provider/mock.go` | EGNs starting with `00` → ineligible |
| `auth/provider/mock_test.go` | Add ineligibility test cases |
| `web/src/App.tsx` | Auth phase redirects to auth service; session detection on return |
| `deploy/docker-compose.yml` | Add ALLOWED_REDIRECT_URIS to auth env |

## Security Considerations

- **Redirect URI validation:** Parsed as URL, matched on (scheme, host, port) only. Rejects userinfo. Prevents open redirect attacks.
- **CSRF protection:** Login form includes CSRF token in hidden field, validated on POST. Prevents cross-site form submission.
- **Session cookie properties:** HttpOnly, Secure (in prod), SameSite=Lax — SameSite changed from Strict to Lax to allow the cookie to be sent on the redirect back from the login page.
- **JWT in URL:** The token appears briefly in the URL query string during redirect. The web app immediately removes it via `history.replaceState`. This is acceptable for the mock; production eAuth will use a different token exchange mechanism.
- **Error message privacy:** Invalid EGN and authentication failure return the same generic message. Ineligibility is shown distinctly (it's a voter status, not a security-sensitive signal in the mock context).
- **Rate limiting:** Existing per-EGN rate limiting (5 attempts / 10 min) applies to valid EGN submissions. Invalid format returns error without consuming rate limit.
- **Mock provider is dev-only:** Gated by `EAUTH_MOCK=true`. Production uses real eAuth 2.0.

## Testing

- Auth service unit tests: login page renders, CSRF validation, redirect URI validation (valid/invalid/bypass attempts), form submission creates session and redirects, ineligible EGN shows error, rate limiting
- Mock provider tests: eligible EGN, ineligible EGN (00-prefix), invalid format
- Web app: token extraction from URL, session status check, redirect to auth service
- Integration: full browser flow from web app → login → ballot → submit
