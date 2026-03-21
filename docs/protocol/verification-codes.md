# Verification Code Protocol (Browser Extension)

**Status:** Draft
**References:** Design Spec sections 2.8, 4.1, 4.3

---

## 1. Threat Model

The primary threat this protocol addresses: **client-side malware on the voting device modifies the vote before encryption.**

A compromised browser, malicious browser extension, or OS-level keylogger could intercept the voter's party/candidate selection and substitute a different choice before the ballot is encrypted with the election public key. Since encryption happens in the browser, the voter has no way to distinguish a correctly encrypted ballot from a tampered one by inspecting the ciphertext.

The verification code protocol provides a **trusted second channel** via a browser extension. The extension is sandboxed from the page's JavaScript context and communicates with an independent server-side verification service. If malware alters the vote, the return code will not match the expected code, and the extension alerts the voter.

### 1.1 Attacker capabilities (in scope)

- Full control of the page's JavaScript execution (XSS, compromised CDN, malicious script injection)
- Ability to modify DOM elements, intercept form submissions, and alter encryption inputs
- Ability to read the page's memory (JavaScript heap)
- Ability to communicate with external servers from the page context

### 1.2 Attacker limitations (assumptions)

- The attacker does **not** control the browser extension's background service worker (Manifest V3 sandboxing)
- The attacker does **not** control the Verification Service (Layer 2 infrastructure)
- The attacker does **not** hold a threshold number of verification trustee key shares (fewer than 3 of 5)
- The attacker **cannot** intercept `chrome.runtime.sendMessage` calls between the page and extension (browser-enforced isolation)

### 1.3 What the protocol does NOT defend against

- A fully compromised operating system that can inspect extension memory (defense: the extension is a detection mechanism, not prevention; the voter can re-vote from a different device or in person)
- Shoulder surfing (the voter's screen is visible to an attacker)
- A coercer who is physically present and can observe the verification codes

---

## 2. Return Code Generation Key

The verification code system uses a **separate threshold key**, independent of the main election encryption key.

### 2.1 Key generation

During the pre-election DKG ceremony (Design Spec Section 2.1), a **second** Feldman VSS instance is executed to generate the verification key:

- **Trustees:** 3-of-5 threshold, drawn from the same pool of 9 main trustees
- **Key type:** The verification key is a shared secret `vk` over the Ristretto255 group, split into shares `vk_1, ..., vk_5` via Shamir's Secret Sharing with Feldman commitments
- **Polynomial:** A fresh random polynomial `f(x)` of degree `t - 1 = 2` is used, independent of the main election key polynomial
- **Public verification key:** `VK = vk * G` (Ristretto255 base point multiplication) is published on the bulletin board

Each trustee's HSM stores their verification key share `vk_j` alongside their election key share. The two shares are cryptographically independent.

### 2.2 Separation from election key

The verification key is used only for return code generation. It is never used for ballot encryption or decryption. This separation ensures:

- Compromise of the verification key shares does not affect ballot secrecy
- The verification trustees (3-of-5 subset) cannot decrypt ballots (which requires 5-of-9 main election key shares)

---

## 3. Session Binding via Blinded Tokens

The extension must authenticate to the Verification Service (Layer 2) without revealing the voter's identity. This is achieved using **RSA Blind Signatures** per RFC 9474 (as used in Privacy Pass).

### 3.1 Protocol participants

- **Voter's browser** (page JavaScript): initiates the blinding
- **Collection Server** (Layer 1): signs the blinded token
- **Browser extension** (background service worker): receives and presents the unblinded token
- **Verification Service** (Layer 2): validates the token signature

### 3.2 Setup

The Collection Server holds an RSA key pair `(SK_blind, PK_blind)` dedicated to session token signing. The public key `PK_blind` is known to the Verification Service. This key is separate from all other signing keys in the system.

### 3.3 Protocol steps

**Step 1 -- Token generation (Layer 1):**

After the voter completes eAuth authentication, the Collection Server generates a fresh, cryptographically random session token:

```
session_token = random(256 bits)
```

This token is associated with the voter's session in Layer 1's internal state.

**Step 2 -- Blinding (browser page):**

The browser's page JavaScript blinds the token before it is signed. The blinding uses the RSA-PSS blind signature scheme from RFC 9474:

```
blinding_factor = RandomBlindingFactor(PK_blind)
blinded_token = RSABlind(session_token, blinding_factor, PK_blind)
```

The blinded token is computationally unlinkable to `session_token` without knowledge of `blinding_factor`.

**Step 3 -- Blind signing (Collection Server):**

The browser sends `blinded_token` to the Collection Server. The Collection Server signs it without learning the underlying token value:

```
blinded_signature = RSABlindSign(blinded_token, SK_blind)
```

The Collection Server returns `blinded_signature` to the browser.

**Step 4 -- Unblinding (browser page):**

The browser removes the blinding factor to obtain a valid signature on the original token:

```
signed_token = RSAUnblind(blinded_signature, blinding_factor, PK_blind)
```

Now `signed_token` is a valid RSA-PSS signature on `session_token`, but the Collection Server never saw `session_token` in the clear during the signing process. (Note: the Collection Server generated `session_token` in Step 1, so it knows the token value. The blind signature's purpose is that the signature itself is unlinkable -- the Verification Service cannot correlate the signed token with any particular signing request it might observe at the Collection Server.)

**Step 5 -- Handoff to extension (browser -> extension):**

The page JavaScript passes both `session_token` and `signed_token` to the extension's background service worker via the browser's extension messaging API:

```javascript
chrome.runtime.sendMessage(EXTENSION_ID, {
    type: "SESSION_BIND",
    session_token: session_token,
    signed_token: signed_token
});
```

This message channel is enforced by the browser -- only the specified extension can receive it. Page JavaScript in other tabs or other extensions cannot intercept this message.

**Step 6 -- Presentation to Verification Service (extension -> Layer 2):**

The extension's background service worker connects directly to the Verification Service over TLS and presents the token:

```
Extension -> Verification Service: {session_token, signed_token}
```

**Step 7 -- Validation (Verification Service):**

The Verification Service validates:

```
RSAVerify(session_token, signed_token, PK_blind) == true
```

If valid, the Verification Service accepts the session. It knows this is a legitimate voting session (signed by Layer 1) but cannot determine which voter it belongs to. The blind signature scheme ensures that even if the Verification Service colludes with an observer of the Collection Server's signing operations, the two cannot link a specific signing request to a specific session presentation.

### 3.4 Token properties

| Property | Mechanism |
|---|---|
| **Authenticity** | RSA signature by Collection Server's dedicated signing key |
| **Unlinkability** | RSA blind signature (RFC 9474) -- signing request cannot be correlated with token presentation |
| **Single-use** | Verification Service records used tokens; reuse is rejected |
| **Expiry** | Token embeds `election_id` and `timestamp`; Verification Service rejects expired tokens |

---

## 4. Code Mapping Generation

At session start, the Verification Service coordinates with the verification trustees to generate a **code mapping**: a table that assigns a unique, unpredictable code to each party on the ballot.

### 4.1 Per-session determinism

The code mapping must be:
- **Deterministic** per session (same session always produces the same mapping)
- **Unpredictable** without the verification key shares (malware cannot pre-compute the codes)
- **Unique** per session (two different sessions produce different mappings)

### 4.2 Partial code generation

Each verification trustee `T_j` (`j = 1, ..., 5`) independently computes a partial code for each party `P_i` (`i = 1, ..., n_parties`):

```
partial_code_{j,i} = PRF(vk_j, signed_token || party_id_i)
```

Where:
- `PRF` is a pseudorandom function (HMAC-SHA256 keyed by the trustee's verification key share)
- `vk_j` is trustee `T_j`'s verification key share
- `signed_token` is the session's blinded-signed token (ensures per-session uniqueness)
- `party_id_i` is the canonical identifier for party `P_i`

### 4.3 Code combination

The Verification Service collects partial codes from at least 3-of-5 trustees and combines them:

```
combined_i = XOR(partial_code_{j1,i}, partial_code_{j2,i}, partial_code_{j3,i})
code_i = Truncate(combined_i, 6 digits)
```

The truncation maps the combined output to a human-readable 6-digit decimal code. Collision resistance across `n_parties` (up to 50) codes within a single session is ensured by the PRF's output distribution -- the probability of any two parties receiving the same 6-digit code in a session is `~50^2 / (2 * 10^6) = 0.00125`, which is negligible. In the unlikely event of a collision, the Verification Service re-derives with a counter suffix until all codes are unique:

```
partial_code_{j,i} = PRF(vk_j, signed_token || party_id_i || counter)
```

### 4.4 Code mapping delivery

The Verification Service sends the complete mapping to the extension:

```json
{
    "session_id": "...",
    "mapping": [
        {"party": "Партия A", "code": "482917"},
        {"party": "Партия B", "code": "103856"},
        ...
    ],
    "signature": "..."
}
```

The mapping is signed by the Verification Service's key to prevent tampering in transit. The extension stores the mapping in its background service worker's memory (not in `localStorage` or any page-accessible storage).

---

## 5. Return Code Derivation

After the voter submits their encrypted ballot, the Verification Service derives a **return code** from the encrypted ballot content. This code is deterministic -- the same encrypted content always produces the same return code.

### 5.1 Derivation process

Each verification trustee independently computes a partial return code from the encrypted ballot ciphertext:

```
partial_return_{j} = PRF(vk_j, signed_token || encrypted_ballot_hash)
```

Where:
- `encrypted_ballot_hash = SHA-256(serialized_encrypted_ballot)` is a hash of the full encrypted ballot (all ElGamal ciphertext pairs)
- The same PRF and key share are used as in code mapping generation, but with different input domain (the encrypted ballot content, not a party ID)

### 5.2 Combination

The Verification Service collects partial return codes from at least 3-of-5 trustees:

```
combined_return = XOR(partial_return_{j1}, partial_return_{j2}, partial_return_{j3})
return_code = Truncate(combined_return, 6 digits)
```

### 5.3 Why this works

When the voter selects party `P_i` and the browser honestly encrypts the ballot:

1. The encrypted ballot contains `Enc(1)` at position `i` and `Enc(0)` at all other positions
2. `encrypted_ballot_hash` is deterministic for this ciphertext
3. The PRF output is deterministic for `(signed_token, encrypted_ballot_hash)`
4. The return code matches the code for party `P_i` **only if the mapping was generated from the same ciphertext structure that would result from voting for party `P_i`**

**Critical detail:** The code mapping (Section 4) must be generated not from party IDs alone, but from the **expected encrypted ballot hash** for each party. This ensures the return code derivation (which operates on the actual encrypted ballot) produces a code that matches the mapping entry.

Revised mapping generation:

```
For each party P_i:
    expected_ballot_i = Encrypt(ballot_vector_for_party_i, election_public_key, randomness_i)
    expected_hash_i = SHA-256(serialize(expected_ballot_i))
    partial_code_{j,i} = PRF(vk_j, signed_token || expected_hash_i)
```

**Problem:** ElGamal encryption uses random nonces, so the expected ciphertext is different from the actual ciphertext even for the same plaintext. The browser generates fresh randomness for each encryption.

### 5.4 Resolving the randomness problem

Two approaches:

**Approach A -- Deterministic encryption randomness (chosen design):**

The encryption randomness for the verification flow is derived deterministically from the session token and a shared seed:

```
encryption_nonce_i = HKDF(signed_token || "ballot_nonce" || element_index_i)
```

The browser uses this deterministic nonce (instead of `crypto.getRandomValues()`) for the ElGamal encryption of each ballot element. The verification trustees derive the same nonces when generating the expected ballots for the code mapping.

This means the ciphertext is deterministic per (session, vote choice), enabling the return code to match the mapping.

**Security consideration:** Deterministic encryption nonces are safe here because:
- Each session token is unique (one-time use)
- The nonces are derived from a PRF with the session token as input
- Different sessions always produce different nonces
- Within a session, different ballot elements use different nonces (via `element_index_i`)
- The voter can re-vote (new session, new token, new nonces)

**Approach B -- Hash of plaintext structure (alternative):**

Instead of hashing the ciphertext, hash a canonical representation of the plaintext structure:

```
partial_code_{j,i} = PRF(vk_j, signed_token || "party" || party_id_i)
partial_return_{j} = PRF(vk_j, signed_token || "party" || voted_party_id)
```

Where `voted_party_id` is extracted from the encrypted ballot. But this requires the verification trustees to learn which party was voted for -- defeating the purpose of encryption.

**Approach A is the chosen design.** Deterministic nonces allow the return code to be derived from the ciphertext without learning the plaintext.

---

## 6. Verification Flow

### 6.1 Extension popup display

After the voter submits their ballot and the return code is derived, the extension displays a popup:

```
+---------------------------------------+
|  Код за потвърждение                  |
|                                       |
|  Получен код:  482917                 |
|  Очакван код за "Партия A":  482917   |
|                                       |
|  [GREEN] Вотът ви е записан вярно.    |
+---------------------------------------+
```

Or, if malware altered the vote:

```
+---------------------------------------+
|  Код за потвърждение                  |
|                                       |
|  Получен код:  739201                 |
|  Очакван код за "Партия A":  482917   |
|                                       |
|  [RED] ВНИМАНИЕ: Кодовете не          |
|  съвпадат! Вотът може да е променен.  |
|  Гласувайте отново или в секция.      |
+---------------------------------------+
```

### 6.2 Voter actions on mismatch

If the codes do not match, the voter is instructed to:

1. **Re-vote online** from a different device (different browser, different computer)
2. **Vote in person** at a polling station (in-person vote overrides online vote)
3. **Report the incident** to the election commission

### 6.3 Timing

| Event | Timing |
|---|---|
| Code mapping generated | Immediately after session binding (before ballot display) |
| Code mapping delivered to extension | Before voter makes their selection |
| Return code derived | After ballot submission (encrypted ballot on bulletin board) |
| Return code delivered to extension | 1-3 seconds after submission |
| Extension popup displayed | Immediately after return code received |

The voter sees the expected codes in the extension **before** they vote, and the return code **after** they vote. This ordering is critical -- if the expected codes were delivered after voting, malware could potentially intercept and forge them.

---

## 7. Security Analysis

### 7.1 Why malware cannot fake the return code

**Property 1: Code mapping arrives via the extension background script, not page JavaScript.**

The extension's background service worker communicates directly with the Verification Service over its own TLS connection. Page JavaScript cannot read, modify, or intercept these messages. Even if malware completely controls the page DOM and JavaScript execution, it cannot access the extension's internal state.

The only page-to-extension communication is the initial `chrome.runtime.sendMessage` call that passes the signed token (Step 5 of Section 3). Malware could block this message (preventing verification entirely, which the voter would notice) but cannot forge it (the extension validates the token signature).

**Property 2: Return code is derived server-side by threshold trustees.**

The return code is computed by 3-of-5 verification trustees, each using their own key share. Malware on the voter's device does not have access to any verification key shares. To forge a return code, malware would need to compromise at least 3 trustees -- a fundamentally different (and much harder) attack than compromising a browser.

**Property 3: The extension popup is sandboxed from other extensions and page content.**

Manifest V3 enforces strict isolation between extension contexts. The popup's DOM is not accessible from page JavaScript or from other extensions. Malware cannot modify the displayed codes in the popup.

**Property 4: The code mapping is per-session and unpredictable.**

Each voting session produces a unique code mapping derived from the signed token and the verification key shares. Without the key shares, malware cannot predict what codes will be generated for a future session. Pre-computed lookup tables are useless.

### 7.2 Attack scenarios and defenses

| Attack | Defense |
|---|---|
| Malware alters vote before encryption | Return code mismatches; voter alerted |
| Malware blocks extension communication | Voter sees no return code; prompted to re-vote or vote in person |
| Malware replaces extension popup content | Not possible (Manifest V3 isolation) |
| Malware installs a fake extension | Voter must install the official extension (verified by Chrome Web Store / Firefox Add-ons signature). If a malicious extension impersonates the official one, it would need the same extension ID, which is cryptographically controlled. |
| Attacker compromises Verification Service | Verification Service does not hold key shares; it only relays partial codes from trustees. A compromised Verification Service could block code delivery (denial of service) but cannot forge codes. |
| Attacker compromises 1-2 verification trustees | Below threshold (3-of-5). Cannot derive valid codes. |
| Attacker compromises 3+ verification trustees | Can forge return codes. This is a critical compromise requiring trustee collusion. Mitigated by selecting trustees from adversarial institutions. |
| Man-in-the-middle between extension and Verification Service | TLS with certificate pinning in the extension. Extension pins the Verification Service's TLS certificate, preventing MITM even with a compromised CA. |

### 7.3 Limitations

**The verification code protocol is a detection mechanism, not a prevention mechanism.** It tells the voter that something went wrong; it does not prevent the altered ballot from being recorded. The voter must then take corrective action (re-vote from a clean device or vote in person).

**The protocol assumes the extension itself is trustworthy.** If the voter installs a malicious extension that impersonates the official one (e.g., via sideloading), all bets are off. The design mitigates this by:
- Requiring installation from official browser extension stores (signed packages)
- The extension is open-source and reproducibly built (anyone can verify the store package matches the source)
- The extension verifies the hash of the voting page's JavaScript bundle (detecting tampered page code)

**OS-level compromise (rootkit, compromised browser binary) can potentially read extension memory.** This is outside the browser's sandbox guarantees. The mitigation is the same as for all client-side security: the voter can always override by voting in person.

---

## Appendix A: Cryptographic Primitives Summary

| Primitive | Instantiation | Purpose |
|---|---|---|
| Blind signature | RSA-PSS Blind Signature (RFC 9474) | Session token unlinkability |
| PRF | HMAC-SHA256 | Partial code generation |
| Threshold secret sharing | Feldman VSS (degree 2 polynomial over Ristretto255 scalar field) | Verification key distribution |
| Deterministic nonce derivation | HKDF-SHA256 | Reproducible ElGamal encryption nonces |
| Hash | SHA-256 | Encrypted ballot hashing |

## Appendix B: Message Sequence Diagram

```
Voter          Browser (Page JS)      Extension (BG)      Collection Server     Verification Service     Trustees (3-of-5)
  |                  |                      |                      |                      |                      |
  |-- eAuth -------->|                      |                      |                      |                      |
  |                  |-- auth token ------->|                      |                      |                      |
  |                  |                      |<-- session_token -----|                      |                      |
  |                  |                      |                      |                      |                      |
  |                  |-- Blind(token) ----->|                      |                      |                      |
  |                  |<- blinded_sig -------|                      |                      |                      |
  |                  |-- Unblind ---------->|                      |                      |                      |
  |                  |                      |                      |                      |                      |
  |                  |-- sendMessage ------>|                      |                      |                      |
  |                  |   {token, sig}       |                      |                      |                      |
  |                  |                      |-- present token ---->|                      |                      |
  |                  |                      |                      |-- validate sig ----->|                      |
  |                  |                      |                      |                      |                      |
  |                  |                      |                      |-- request codes ---->|                      |
  |                  |                      |                      |                      |-- partial_code_j --->|
  |                  |                      |                      |                      |<-- partial_codes ----|
  |                  |                      |                      |                      |                      |
  |                  |                      |<-- code_mapping -----|                      |                      |
  |                  |                      |                      |                      |                      |
  |-- select party ->|                      |                      |                      |                      |
  |                  |-- encrypt ballot     |                      |                      |                      |
  |                  |   (deterministic     |                      |                      |                      |
  |                  |    nonces from       |                      |                      |                      |
  |                  |    session token)    |                      |                      |                      |
  |                  |                      |                      |                      |                      |
  |                  |-- submit ballot ---->|                      |                      |                      |
  |                  |                      |<--- strip identity ->|                      |                      |
  |                  |                      |                      |-- ballot to BB ----->|                      |
  |                  |                      |                      |                      |                      |
  |                  |                      |                      |-- derive return ---->|                      |
  |                  |                      |                      |                      |-- partial_return --->|
  |                  |                      |                      |                      |<-- partial_returns --|
  |                  |                      |                      |                      |                      |
  |                  |                      |<-- return_code ------|                      |                      |
  |                  |                      |                      |                      |                      |
  |                  |                      |-- popup: compare     |                      |                      |
  |                  |                      |   return_code vs     |                      |                      |
  |                  |                      |   expected code      |                      |                      |
  |                  |                      |                      |                      |                      |
  |<-- MATCH/MISMATCH|                      |                      |                      |                      |
```

## Appendix C: Extension Manifest V3 Permissions

The browser extension requires the following minimum permissions:

```json
{
    "manifest_version": 3,
    "permissions": [
        "activeTab"
    ],
    "host_permissions": [
        "https://izbori.bg/*",
        "https://verify.izbori.bg/*"
    ],
    "background": {
        "service_worker": "background.js"
    },
    "externally_connectable": {
        "matches": ["https://izbori.bg/*"]
    },
    "content_security_policy": {
        "extension_pages": "script-src 'self'; object-src 'self'"
    }
}
```

Key constraints:
- `externally_connectable` restricts which pages can send messages to the extension (only `izbori.bg`)
- No `<all_urls>` or broad host permissions
- No `webRequest` or `webRequestBlocking` (the extension does not intercept page traffic)
- The background service worker has no DOM access (Manifest V3 requirement)
- Content Security Policy prevents injection of external scripts into extension pages
