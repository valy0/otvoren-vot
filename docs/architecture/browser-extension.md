# Browser Extension Architecture

## 1. Purpose and Security Model

The browser extension provides a trusted second channel for vote verification, independent of the voting page's JavaScript environment. Its primary purpose is to defeat client-side malware that might replace or modify a voter's ballot selection before encryption — a class of attack that cannot be prevented by server-side measures alone.

The core threat the extension mitigates: a malicious browser extension, injected JavaScript, or compromised browser could intercept the voter's selection on the voting page and silently substitute a different choice before the client-side encryption runs. The voting page's own JavaScript is therefore untrusted with respect to confirming what was actually encrypted. A second, independent channel — one that receives confirmation from the server-side Verification Service rather than from the page — can detect or prevent this substitution.

**Sandboxed popup.** The extension popup runs in its own isolated browser process. Content scripts from other extensions cannot access the extension's popup DOM, memory, or message channels. The extension's background service worker is inaccessible to page JavaScript except through the explicit `chrome.runtime.sendMessage` API, which requires knowing the extension's ID. This isolation is enforced by the browser's extension security model (Manifest V3) and is not contingent on the trustworthiness of the voting page.

**No access to page JavaScript.** The extension's background service worker contacts the Verification Service directly, using its own network connection, separate from any network requests made by the voting page. This means that even if the voting page's JavaScript is fully compromised, the return code the extension displays is derived independently from the encrypted ballot as received by the Verification Service — not from anything the page reports.

**Trusted second channel.** The verification flow allows a voter to confirm that what the server received and recorded is consistent with their intended choice, using a display path that does not pass through the potentially compromised page. The return code is short enough to compare visually in seconds.

---

## 2. Verification Code Flow

The verification code protocol allows a voter to confirm their ballot was correctly recorded, without revealing vote content to any service and without requiring a separate physical device.

The protocol uses a 3-of-5 subset of the 9 election trustees as verification trustees. These trustees hold shares of a return code generation key, separate from the election decryption key.

**Session binding via blinded tokens (RFC 9474 RSA Blind Signatures).** The extension must authenticate to the Verification Service to receive the session's code mapping and return code. However, the Verification Service must not learn the voter's identity (ЕГН) — it operates in Layer 2 and is architecturally prohibited from receiving identity information. This is resolved via the blinded session token protocol:

1. After successful eAuth authentication, Layer 1's Collection Server generates a one-time `session_token` for this voting session.
2. The voter's browser generates a `blinding_factor` locally. The browser blinds the token: `blinded_token = Blind(session_token, blinding_factor)`. This operation is defined by RFC 9474 (RSA Blind Signatures, as used in Privacy Pass). The blinded token is mathematically unlinkable to the original token.
3. The Collection Server signs the blinded token and returns the blinded signature to the browser.
4. The browser unblinds the signature: `signed_token = Unblind(blinded_signature, blinding_factor)`. The result is a valid signature over the original `session_token`, but the Collection Server cannot link this specific `signed_token` to any particular voter or session — the blinding is information-theoretically irreversible.
5. The browser passes `signed_token` to the extension via `chrome.runtime.sendMessage`.
6. The extension presents `signed_token` to the Verification Service.
7. The Verification Service validates the signature using the Collection Server's public signing key. It accepts the token as proof that "a valid eAuth session exists" but has no ability to identify which voter it belongs to.
8. The Verification Service uses `signed_token` as the session identifier for all subsequent code mapping and return code operations in this session.

**Code mapping generation.** When the Verification Service accepts a session token, the 3-of-5 verification trustees collaboratively generate a per-session code mapping: a short, human-readable code (typically 4–6 characters) assigned to each party. This mapping is pushed to the extension's background service worker and held in memory for the duration of the session.

**Return code derivation.** After the voter submits their ballot and it is received by the Collection Server, the Collection Server forwards the encrypted ballot to the Verification Service. Each verification trustee independently derives a partial return code from the encrypted ballot using their key share. The protocol is deterministic: the same encrypted content always produces the same return code. Partial codes from 3-of-5 trustees are combined to produce the final return code, which is sent to the extension's background service worker.

**Display and comparison.** The extension popup displays the return code alongside the full session code mapping. The voter visually compares the displayed return code against the code assigned to their intended party. A match confirms that the Verification Service derived a code consistent with the voter's encrypted choice. A mismatch indicates that the encrypted ballot received by the system does not correspond to the voter's stated selection — a signal that client-side tampering may have occurred.

The return code is deterministic: if the voter re-votes (using the override mechanism), the new encrypted ballot will produce a different return code that reflects the new selection, and the previous code becomes irrelevant.

---

## 3. JavaScript Integrity Check

The voting page's JavaScript — which performs client-side ballot encryption — is served from `izbori.bg` and is reproducibly built. The expected SHA-256 hash of each released JavaScript bundle is published in the election configuration on the bulletin board before the election opens, and is independently distributed through multiple channels (CIK website, political party websites).

When the extension's content script detects the `izbori.bg` voting page, it computes a SHA-256 hash of the served JavaScript bundle and compares it against the reference hash from the extension's configuration (which is pinned at extension publish time). If the hashes do not match, the extension displays a warning in its popup and, depending on configuration, may prevent the voter from proceeding.

This check provides a second layer of defense beyond TLS: even if an attacker could serve modified JavaScript over a valid TLS connection (e.g., via a supply chain compromise of the origin server), the hash mismatch would be detected by any voter using the extension. The hash comparison runs entirely within the extension's isolated context and cannot be suppressed by the page.

The reference hash in the extension is updated with each new release of the voting web application. The extension's own release process requires the hash to match the reproducible build output published alongside the source code.

---

## 4. Certificate Pinning

The extension pins the expected TLS certificate (or its public key hash, following the pattern of HTTP Public Key Pinning) for `izbori.bg`. The pinned value is embedded in the extension at publish time and corresponds to the certificate issued to `izbori.bg` under the election PKI.

On every request to `izbori.bg`, the extension's background service worker intercepts the connection and verifies that the served certificate matches the pinned value. If the certificate does not match — indicating either a mismatch due to a DNS hijack, a MITM attack, or an unexpected certificate rotation — the extension takes the following actions:

1. Blocks the voting page from loading.
2. Displays a full-screen warning in the popup explaining that the connection cannot be verified.
3. Provides contact information for reporting the incident.

Certificate pinning is an additional security benefit of making the extension mandatory for online voting. A browser without the extension would accept any certificate that passes normal TLS chain validation. The extension's pinning provides resistance against attacks that present a fraudulent but technically valid certificate — for example, a certificate issued by a compromised CA trusted by the operating system.

Certificate rotation (e.g., at the annual renewal boundary) requires a coordinated extension update. The extension update process and certificate rotation schedule are documented in the election administration procedures.

---

## 5. Configuration Gate

The extension operates in one of three modes, configured by election administrators before the election opens. The mode is published in the signed election configuration on the bulletin board and is enforced by the Collection Server, not only by the extension itself.

| Mode | Behavior |
|------|----------|
| `required` (default) | If the extension is not detected when the voter arrives at the voting page after eAuth, the page displays a prompt to install the extension. The voter cannot proceed to ballot selection until the extension is installed and active. This is the default and recommended mode. |
| `recommended` | If the extension is not detected, a prominent warning is displayed explaining the reduced security level. The voter can acknowledge the warning and proceed to vote without the extension. Return code verification is unavailable for this session. |
| `disabled` | No extension check is performed. The extension gate is bypassed entirely. This mode is intended for testing environments and fallback scenarios authorized by CIK. It must not be used in production elections. |

The Collection Server enforces the `required` mode by rejecting ballot submissions from sessions where no valid extension-signed session token was presented. This means a voter cannot circumvent the gate by suppressing the extension's detection signal on the page — the server-side check is independent.

---

## 6. Manifest V3 Architecture

The extension is built using the Chrome and Firefox Manifest V3 API, targeting both major browsers with a shared codebase.

**Background service worker.** The background service worker is the extension's primary component. It runs in an isolated context, separate from all web page contexts. Responsibilities:

- Maintains the mTLS or authenticated HTTPS connection to the Verification Service.
- Receives the session's code mapping from the Verification Service after session token exchange.
- Receives the return code from the Verification Service after ballot submission.
- Holds all session state in memory. No session data is written to extension storage or `localStorage`.
- Listens for messages from the content script (via `chrome.runtime.onMessage`) and updates the popup state.

Under Manifest V3, background service workers are event-driven and may be suspended by the browser between events. The extension handles this by re-establishing its Verification Service connection on each activation event and by storing the minimum necessary state to resume a session without requiring the voter to re-authenticate.

**Content script.** The content script is injected into pages matching the `izbori.bg` domain pattern after the eAuth redirect completes. Responsibilities:

- Detects that the voter is on the `izbori.bg` voting page and that the eAuth flow has completed.
- Receives the `signed_token` from the page via `window.postMessage` (the page sends the token to the extension using the extension's ID as the target).
- Relays the `signed_token` to the background service worker via `chrome.runtime.sendMessage`.
- Observes the page for the ballot submission event and notifies the background worker.
- Performs the JavaScript integrity hash check against the served bundle.

The content script does not have access to the extension's popup or background service worker's internal state. It acts only as a message relay between the (untrusted) page and the (trusted) background.

**Popup.** The popup is a small HTML/TypeScript UI that renders when the voter clicks the extension icon. Responsibilities:

- Displays the current session's code mapping (party → expected code) so the voter can look up their party's code.
- Displays the return code received from the Verification Service after ballot submission.
- Shows a verification result: a green checkmark and textual confirmation if the return code matches the voter's party's code from the mapping; a red warning indicator and textual description if there is a mismatch.
- Displays certificate pinning status and JavaScript integrity check results.
- Provides a link to the extension's help documentation and incident reporting contact.

The popup communicates with the background service worker via `chrome.runtime.sendMessage` and `chrome.runtime.onMessage`. It holds no state of its own — all state is owned by the background worker and provided to the popup on request.

---

## 7. Web Security Integration

The extension is one layer in a defense-in-depth web security stack. The following measures operate alongside it.

**DNSSEC.** The `izbori.bg` domain is signed with DNSSEC. DNS resolvers that support DNSSEC validation will reject spoofed DNS responses for `izbori.bg`. This reduces the attack surface for DNS hijacking that could redirect voters to a fraudulent site. The extension's certificate pinning provides an additional layer of protection for resolvers that do not perform DNSSEC validation.

**HSTS (HTTP Strict Transport Security).** The `izbori.bg` server sets a Strict-Transport-Security response header with a long `max-age` value (minimum one year) and `includeSubDomains`. After the voter's first visit, the browser enforces HTTPS for all subsequent connections to `izbori.bg`, preventing downgrade attacks that would strip TLS. The domain is also included in the browser's HSTS preload list so that HTTPS is enforced even on the first visit.

**Content Security Policy.** The `izbori.bg` voting page sets a strict Content-Security-Policy header. The policy: prohibits inline scripts (`script-src` without `unsafe-inline`); allows only the origin itself and the specific CDN paths for the libsodium WASM bundle as script sources; prohibits inline styles; restricts form actions to the Collection Server origin; prohibits framing (`frame-ancestors 'none'`). This policy prevents injected scripts from executing if an attacker achieves partial page control, and prevents the voting page from being embedded in a malicious frame.

Together, DNSSEC, certificate pinning, HSTS, and CSP create overlapping layers of protection. A successful attack requires defeating multiple independent controls simultaneously.

---

## 8. Accessibility

The extension popup is designed to be fully usable by voters with disabilities.

**Screen reader support.** All interactive elements in the popup have ARIA labels and roles. The return code and verification result are announced by screen readers without requiring the voter to navigate to them — they use ARIA live regions (`aria-live="polite"`) so that the code and status update are read aloud automatically when they appear. The code mapping table uses `role="table"` with proper `aria-label` on each cell so that assistive technology can navigate the list of party codes without ambiguity.

**Not color-only indicators.** The verification result (match or mismatch) is never communicated by color alone. In addition to the green or red color indicator, the result is expressed as a text label ("Vote recorded correctly" or "Verification mismatch — please contact commission staff"), an icon with an `aria-label`, and, where space permits, a brief explanation. This ensures the result is accessible to voters with color vision deficiency and to screen reader users.

**Keyboard navigation.** All controls in the popup are reachable by keyboard Tab navigation. Focus order follows the logical reading order of the content. The popup does not trap focus.
