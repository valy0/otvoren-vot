# Отворен вот (otvoren-vot) — System Design Specification

**Date:** 2026-03-20
**Status:** Approved
**License:** EUPL-1.2
**Target:** Production-grade e-voting system for Bulgarian national elections, presentable to CIK

---

## 1. Overview

Otvoren-vot is an end-to-end verifiable, hybrid online + in-person voting system designed for Bulgarian national elections. The system provides:

- Encrypted ballots on a public bulletin board
- Homomorphic tallying without decrypting individual votes
- Bidirectional vote override for coercion resistance (online↔in-person)
- Browser extension-based verification codes for client-side malware defense
- A nationally televised decryption ceremony with 5-of-9 threshold trustees
- Full independent verifiability by political parties, NGOs, and media

The project includes both the software implementation and non-code deliverables (threat model, legal compliance analysis, cost projection, audit plan, certification path) required for a CIK presentation.

### Key Parameters

| Parameter | Value |
|-----------|-------|
| Components | 11 services (auth, collection, bulletin-board, tally, verification, web, dashboard, extension, machine, admin, CLI tools) |
| Max parties | 50 |
| Max candidates per party | 50 |
| Trustees | 9 (adversarial institutions) |
| Threshold | 5-of-9 |
| Data centers | 2 (Sofia + Varna, documented architecture, Docker Compose for dev) |
| Languages (code) | Go (primary), TypeScript (frontends), Python (admin) |
| Languages (UI) | Bulgarian Cyrillic only |
| Languages (docs) | English (technical), Bulgarian (CIK deliverables) |
| License | EUPL-1.2 |

---

## 2. Cryptographic Protocol

### 2.1 Election Key Generation

Pre-election, the 9 trustees run a Distributed Key Generation (DKG) protocol using Feldman's Verifiable Secret Sharing:

- Each trustee's HSM — a USB-sized hardware security module (e.g., YubiHSM 2, Nitrokey HSM 2), FIPS 140-3 Level 3 — generates a private key share internally
- The shares are never combined — the full private key never exists anywhere
- The protocol produces a single **election public key** for ballot encryption
- Threshold: any 5-of-9 trustees can collectively decrypt; fewer than 5 learn nothing
- Executed once per election, weeks before election day

### 2.1.1 Key Lifecycle

- **Distribution:** Election public key published on bulletin board, embedded in web app, and distributed via multiple independent channels (CIK website, political party websites, print media). Parties verify the key matches across all channels.
- **Compromise response:** If a trustee's HSM is compromised or lost between DKG and election day, the remaining trustees run a re-sharing protocol to exclude the compromised share and issue new shares without changing the election public key (proactive secret sharing). If fewer than 5 shares remain uncompromised, a full new DKG is required.
- **Validity period:** The election public key is valid only for the specific election. It is never reused.
- **Destruction:** After the election results are certified and all legal challenge periods expire, trustees destroy their key shares by wiping their HSMs on camera. The destruction is logged and signed.

### 2.2 Ballot Encoding

**Party vote:** Binary vector with one element per party. All zeros except position `i` = 1 for the chosen party. Example: 30 parties → vector of 30 values.

**Candidate preference:** Separate binary vector per party with one element per candidate. Only the selected party's vector may contain a 1. All other parties' candidate vectors are all-zeros (encrypted).

### 2.3 Ballot Encryption

**Cryptographic group:** Exponential ElGamal over the **Ristretto255** group (prime-order group derived from Curve25519, avoids cofactor issues). Ristretto255 provides a clean prime-order abstraction over the Ed25519 curve.

**Implementation:** ElGamal is NOT a built-in libsodium primitive. We implement exponential ElGamal as custom code atop libsodium's low-level scalar/point arithmetic (`crypto_scalarmult_ristretto255`, `crypto_core_ristretto255_*` family). On the server side (Go), we use `filippo.io/edwards25519` or equivalent for the same group operations.

- Each vector element encrypted independently with **exponential ElGamal** over Ristretto255 using the election public key
- Exponential ElGamal is additively homomorphic: `Enc(a) * Enc(b) = Enc(a + b)`
- Client-side encryption using custom ElGamal built on `libsodium.js` scalar/point primitives (WASM, bundled with web app, hash-verifiable)
- The election public key is embedded in the ballot page and published on the bulletin board

**Performance budget:** Ballot encryption and proof generation must complete within 5 seconds on a mid-range 2024 laptop. For 50 parties with up to 50 candidates each (worst case: 50 + 2500 = 2550 encrypted elements + proofs), this requires benchmarking. If client-side proof generation exceeds 5 seconds, we use batched Sigma proofs to reduce computation.

### 2.4 Zero-Knowledge Proofs

**Mixed proof framework:** Sigma protocols (Chaum-Pedersen) for simple proofs, gnark SNARKs for complex circuits.

| Proof | What it proves | Framework | When published |
|-------|---------------|-----------|----------------|
| Ballot validity | Each element is 0 or 1, vector sums to exactly 1 | Sigma | At ballot submission |
| Candidate validity | Candidate vector sums to 0 or 1, consistent with party selection | Sigma | At ballot submission |
| Deduplication | Filtered set matches active ballot ID set exactly | gnark SNARK (Groth16 with recursion) | During ceremony |
| Partial decryption | Each trustee's decryption share is honestly computed | Chaum-Pedersen | During ceremony |
| Tally correctness | Plaintext results match the encrypted sums | Sigma | End of ceremony |

### 2.5 Homomorphic Tallying

- Multiply all active encrypted ballots element-wise across all voters
- Result: encrypted values each containing the SUM of votes for that option
- Same process for candidate vectors within each party
- No individual ballot is ever decrypted

### 2.6 Threshold Decryption

- Each of 5+ trustees uses their HSM to compute partial decryptions of the summed ciphertexts
- HSM performs computation internally — key share never leaves the device
- Each partial decryption accompanied by a Chaum-Pedersen proof of correctness
- Partial decryptions combined to reveal plaintext sums
- Final step: solve discrete log via baby-step giant-step. For N voters (≤ ~4M), BSGS requires O(√N) time and space per tally slot (~2000 steps). With up to 2550 tally slots (50 parties + 50×50 candidates), this completes in under 1 second on modern hardware.

### 2.7 ZK Deduplication Circuit (gnark)

**Public inputs:**
- Bulletin board Merkle root
- Active set commitment hash
- Filtered set Merkle root
- Active set size

**Private witness:**
- The active set of ballot IDs
- Merkle inclusion proofs for each active ballot ID in the bulletin board
- The encrypted ballots corresponding to each active ID

**Circuit verifies:**
- Each ballot ID in the witness has a valid Merkle inclusion proof against the bulletin board root
- The hash of the sorted witness IDs equals the active set commitment
- The filtered set Merkle root is correctly computed from the included ballots
- Count matches

**Dual-hash Merkle tree:** The bulletin board maintains two parallel Merkle trees:
1. **Public tree** using SHA-256 — for public verification, API responses, and inclusion proofs. Standard, auditable by anyone.
2. **SNARK tree** using Poseidon hash over the BN254 scalar field — used exclusively inside the gnark dedup circuit. Poseidon is SNARK-friendly (~250 constraints per hash vs. ~25,000 for SHA-256), making the circuit feasible.

Both trees are computed on every append. The public tree is the canonical one for external verification. The SNARK tree exists solely to make the dedup proof computationally tractable.

**What is inside vs. outside the SNARK:**
- **Inside the SNARK:** Set membership verification (each active ballot ID has a valid Poseidon Merkle inclusion proof), active set commitment check, filtered set root computation, count check. All operations use BN254-native field arithmetic and Poseidon hashes.
- **Outside the SNARK:** The homomorphic product (multiplying ElGamal ciphertexts over Ristretto255), threshold decryption, and tally correctness — all verified via separate Sigma/Chaum-Pedersen proofs over the ElGamal group. These two cryptographic worlds do not interact inside a circuit.

**Performance:** Recursive proof composition — split into batches of ~10,000 ballots, prove each batch independently, compose into a single aggregate proof. Parallel proving across CPU cores. Estimated 30-60 minutes on a 64-core server (using SNARK-friendly Poseidon hashes, not SHA-256).

### 2.8 Verification Code Protocol (Browser Extension)

- 3-of-5 verification trustees (subset of the 9) hold shares of a return code generation key
- At session start: verification trustees generate a per-session code mapping (party → code) and push it to the browser extension
- At ballot submission: each verification trustee independently derives a partial return code from the encrypted ballot using their key share
- Partial codes combined to produce the final return code
- Return code sent to the extension's background script, displayed in the extension popup
- Voter compares: return code matches their intended party's code from the mapping → vote is correct
- Deterministic: same encrypted content always produces the same return code

**Session binding protocol (extension ↔ Verification Service):**

The extension must authenticate to the Verification Service without leaking voter identity to Layer 2. This is resolved via a **blinded session token** issued by Layer 1:

1. After eAuth, Layer 1's Collection Server generates a one-time `session_token` for this voting session
2. Collection Server blinds the token using RSA Blind Signatures (RFC 9474, as used in Privacy Pass): `blinded_token = Blind(session_token, voter_blinding_factor)`. The blinding ensures the token is unlinkable to the voter's ЕГН.
3. Collection Server signs the blinded token and returns it to the browser
4. Browser unblinds: `signed_token = Unblind(blinded_signed_token, voter_blinding_factor)`
5. Browser passes `signed_token` to the extension (via `chrome.runtime.sendMessage` from the page to the extension)
6. Extension presents `signed_token` to the Verification Service (Layer 2)
7. Verification Service validates the signature (it knows Layer 1's signing public key) but cannot link the token to any voter — the blinding is irreversible
8. Verification Service uses the `signed_token` as the session identifier for code mapping generation and return code delivery

This preserves the two-layer separation: Layer 2 knows "this is a valid session" but not "this is voter X."

---

## 3. Two-Layer Architecture

### 3.1 Layer 1 — Identity Service

**Components:**
- **Auth Service** (Go) — eAuth 2.0 integration via abstracted interface. Ships with a mock eAuth provider for development/testing. Production integration documented.
- **Collection Server** (Go) — receives encrypted ballots from authenticated voters. Records `ЕГН → ballot_id` mapping. Strips voter identity before forwarding to Layer 2.

**Knows:** Who voted (ЕГН), when, which ballot ID.
**Never sees:** Ballot content (encrypted or plaintext), party/candidate choice.

### 3.2 Layer 2 — Ballot Service

**Components:**
- **Bulletin Board** (Go + PostgreSQL) — append-only Merkle tree. Each entry: `[random_ballot_id, encrypted_ballot, zk_proofs, timestamp, merkle_root]`. Publicly readable.
- **Tally Service** (Go) — homomorphic tallying, threshold decryption coordination, ZK dedup proof generation.
- **Verification Service** (Go) — threshold return code generation for the browser extension.

**Knows:** All encrypted ballots with random IDs, ZK proofs, Merkle tree.
**Never sees:** Voter identity (ЕГН), which ballot belongs to which voter.

### 3.3 The Handoff (Layer 1 → Layer 2)

1. Voter authenticates with Layer 1, receives session token
2. Browser encrypts ballot, generates random `ballot_id`
3. Browser sends `{ballot_id, encrypted_ballot, proofs}` to Collection Server
4. Collection Server verifies: authenticated, election is open
5. Collection Server records `ЕГН → ballot_id` in its private database
6. Collection Server forwards `{ballot_id, encrypted_ballot, proofs}` to Bulletin Board — **no ЕГН, no session token, no IP address**
7. Bulletin Board validates proofs, appends to Merkle tree, returns new Merkle root
8. Collection Server returns Merkle root + inclusion proof to voter's browser

### 3.4 Deduplication Bridge (polls close)

Layer 1 computes the "active ballot ID set" — for each ЕГН, the ballot_id of their last ballot. This set (ballot IDs only, no ЕГНs) is handed to Layer 2's Tally Service. The Tally Service filters the bulletin board and generates the ZK dedup proof.

### 3.5 Network Isolation

- Layer 1 and Layer 2 on separate Docker networks (development). **In production, Layer 1 and Layer 2 run on physically separate infrastructure with hardware firewalls enforcing the one-way communication policy.** Docker Compose network isolation is for development only.
- One-way internal API: Collection Server → Bulletin Board (submit ballot)
- One-time handoff: Layer 1 → Tally Service (active ID set at polls close)
- No return path — Layer 2 cannot query Layer 1
- Bulletin Board public API is read-only

### 3.6 Merkle Root Tamper-Evidence Protocol

The bulletin board's "append-only" property is enforced at the application layer, not structurally by PostgreSQL. To provide external tamper-evidence:

- **Periodic signed roots:** Every 60 seconds during the election, the Bulletin Board signs the current Merkle root with its service key and publishes it to the `/api/v1/board/root` endpoint.
- **External anchoring:** Signed roots are simultaneously pushed to multiple independent monitors operated by political parties, NGOs, and media organizations. Each monitor stores the sequence of roots.
- **Consistency verification:** Any monitor can verify that each new root is a consistent extension of the previous root (standard Merkle consistency proof). If the bulletin board retroactively modifies or deletes an entry, the root changes and the monitors detect the inconsistency.
- **Post-election:** The complete sequence of signed roots is published as part of the election archive. Auditors can verify the full chain of consistency.

---

## 4. Online Voting Flow

### 4.1 Voter Experience

1. Open `izbori.bg`, click "Гласувай онлайн"
2. Redirect to eAuth 2.0 for authentication
3. eAuth redirects back with auth token
4. Collection Server validates token, checks eligibility, election status, device policy
5. **Extension gate** (configurable, default: required) — if extension not detected, voter prompted to install. Cannot proceed without it when set to required.
6. Verification trustees generate session code mapping, push to extension
7. Ballot displayed: parties with logos and names in Cyrillic
8. Select party, optionally select preferred candidate
9. Review screen: "Вие избрахте: [party] / [candidate]"
10. Confirm
11. Browser encrypts ballot client-side (custom ElGamal over Ristretto255, built on libsodium.js WASM primitives), generates ZK proofs, generates random ballot_id (256 bits via `crypto.getRandomValues()`, encoded as base64url; Collection Server rejects collisions, though collision probability is negligible at 2^-128)
12. Submit to Collection Server → stripped → Bulletin Board
13. Receive Merkle inclusion proof + ballot ID
14. Extension popup shows return code — voter verifies against session mapping
15. Voter can save/print ballot ID for post-election verification

### 4.2 Re-voting (Override)

- Voter repeats entire flow: re-authenticates, new session, new ballot_id, new random ID
- Collection Server updates `ЕГН → ballot_id` to the new ballot
- Old ballot remains on bulletin board but excluded from active set at tally
- Old and new ballots indistinguishable on the bulletin board

### 4.3 Browser Extension Behavior

1. Detects `izbori.bg` domain after eAuth redirect
2. Background script contacts Verification Service directly (separate from page JS)
3. Receives code mapping: `{party_name → expected_code}`
4. After submission, background script receives return code from Verification Service
5. Popup displays: return code + which party it maps to
6. Match → green checkmark. Mismatch → red warning.
7. Extension also verifies integrity of served JavaScript (hash check against published hash)

### 4.4 Extension Configuration

| Setting | Behavior |
|---------|----------|
| `required` (default) | No extension = cannot vote online. Prompted to install. |
| `recommended` | Warning displayed, voter can proceed without extension |
| `disabled` | No extension check (for testing/fallback) |

### 4.5 Error Handling

- Network failure during submission → queued in `sessionStorage` (cleared on tab close, NOT `localStorage`). Retry occurs only within the same browser session. If the tab is closed, the voter must re-authenticate and re-vote (safe due to override mechanism). No auth tokens are persisted. No encrypted ballots survive the session.
- eAuth timeout → re-authenticate, no data lost
- Proof validation failure → Collection Server returns error, browser re-encrypts with fresh randomness
- Election closed → hard rejection, directed to nearest polling station

### 4.6 Web Security

- **DNSSEC:** `izbori.bg` domain uses DNSSEC to prevent DNS hijacking/spoofing. Voters are directed to the authentic server.
- **Certificate pinning:** The browser extension pins the expected TLS certificate for `izbori.bg`. If the certificate doesn't match (indicating a MITM or DNS hijack), the extension blocks the page and warns the voter. This is an additional benefit of making the extension mandatory.
- **HSTS:** Strict Transport Security header with long max-age, preventing downgrade to HTTP.
- **Content Security Policy:** Strict CSP preventing inline scripts and unauthorized resource loading, mitigating XSS attacks on the voting page.

---

## 5. In-Person Voting & Machine Software

### 5.1 Machine Platform

- Embedded Linux (hardened, read-only root filesystem)
- Go application — full-screen kiosk mode, no window manager, no shell access
- **TPM-based software attestation:** at every boot, the TPM verifies the software image hash against a signed reference hash. If the hash doesn't match, the machine refuses to start and displays an error for the commission. This is the trust anchor — it guarantees the running software is unmodified.
- Offline-first: all crypto and ballot storage works without network
- Local storage: SQLite for encrypted ballot queue
- No printer, no paper, no moving mechanical parts. The machine is a touchscreen + TPM + network interface.

### 5.2 Voter Flow

1. Present ID to election commission
2. Commission verifies eligibility, directs to machine
3. Party selection screen: large touch targets, party logos and names in Cyrillic
4. Select party
5. Optional: candidate preference screen
6. Review screen: "Вие избрахте: [party] / [candidate]"
7. Voter presses green button (confirm) or red button (redo → back to step 3)
8. On confirm: machine encrypts ballot, generates ZK proofs, assigns random ballot_id
9. Encrypted ballot queued to local SQLite
10. Confirmation screen shows ballot ID (voter can photograph or note it for post-election inclusion verification on `verify.izbori.bg`)
11. Machine resets for next voter

**No paper ballot, no printer.** The machine's integrity is guaranteed by TPM attestation at boot — the software is verified to be unmodified. This is fundamentally different from a voter's browser (which runs arbitrary extensions and software). Compromising the machine requires physical tampering that would break tamper-evident seals, be caught on camera, and break the TPM hash chain. The machine is a trusted device; the voter's browser is not.

### 5.3 Identity Binding (In-Person)

- Commission verifies voter identity using their ID card (лична карта) — existing Bulgarian practice
- Commission marks voter in electoral roll via tablet
- Machine does NOT authenticate the voter — doesn't know who is using it

**Machine-tablet pairing protocol:**
1. Before the voter approaches, the commission member scans the voter's лична карта MRZ (Machine Readable Zone) using a USB MRZ reader attached to the commission tablet. The MRZ contains the ЕГН, name, document number, and check digits. This eliminates manual entry errors and speeds up the queue. Fallback: manual ЕГН entry on the tablet if the MRZ reader fails or the document is damaged.
2. Tablet validates MRZ check digits, extracts ЕГН, generates a 6-digit session code and displays it to the commission member
3. Commission member enters the session code on the voting machine's keypad (separate from the voter-facing touchscreen — this is a commission-only input on the side/back of the machine)
4. Machine displays "Ready" on the voter-facing screen. The session code is stored locally, associated with the next ballot_id generated.
5. Voter uses the machine normally. On confirmation, the machine generates ballot_id and pairs it with the session code.
6. Machine transmits `{session_code, ballot_id}` to the commission tablet (via local network or Bluetooth LE)
7. Commission tablet records `ЕГН → ballot_id` and sends this mapping to Layer 1

This ensures: (a) the machine never knows the ЕГН (only the session code), (b) the pairing is explicit per-voter, (c) no race conditions between adjacent machines.

### 5.4 Offline Sync

- Encrypted ballots stored locally in SQLite
- Sync when network available (polling station WiFi or end-of-day USB)
- Machine signs each batch with its station key for Collection Server authenticity verification
- If network never available: USB drive physically transported
- Collection Server processes machine ballots identically to online ballots

**USB sync security protocol:**
- **Station key provisioning:** Each machine receives a unique station key pair during pre-election setup. The private key is stored in the machine's TPM or secure enclave. The public key is registered with the Collection Server, associated with the station ID and constituency.
- **Batch format:** Each USB batch contains: `{station_id, sequence_number, ballots[], batch_signature}`. The sequence number is monotonically increasing per machine, preventing replay attacks.
- **USB media:** Pre-provisioned, write-once USB drives distributed by CIK. The machine writes the batch file and a cryptographic seal. Arbitrary USB drives are rejected by the machine.
- **Collection Server validation:** Verifies station key signature, validates station ID is registered, checks sequence number is strictly greater than the last received for that station, rejects duplicate batches.
- **Chain of custody:** Two commission members must jointly authorize the USB export (two physical buttons pressed simultaneously). The export is logged with timestamp and sequence number.

### 5.5 PKI & Certificate Authority

**CA Hierarchy:**
- **Offline Root CA** → **Online Intermediate CA** → **End-entity certificates** (machines, services)

**Root CA Key Ceremony:**
- Performed on an air-gapped, hardened workstation in a physically secure room (access-controlled, no windows, RF-shielded)
- Root private key generated inside a FIPS 140-3 Level 3 HSM under **M-of-N split knowledge**: 3-of-5 key custodians, each holding a key component. No single custodian can activate the root key alone.
- **Key custodian requirements:** Custodians must be independent individuals from different institutions (e.g., drawn from the trustee pool). Each custodian undergoes a background check (criminal record, financial standing) before appointment. No two custodians may be from the same organization, related by family, or have a reporting relationship. Custodian identities are documented in the CP/CPS.
- Formal ceremony script followed step-by-step. Independent witnesses present (minimum 2, from different trustee institutions).
- Full video recording of the ceremony. Signed audit log produced by each participant.
- Root CA signs a single intermediate CA certificate, then the HSM is powered down.
- HSM stored in a tamper-evident bag, placed in a dual-lock safe (two different custodians hold the keys). Access log maintained — every safe opening recorded with date, time, custodian identities, and purpose.

**Online Intermediate CA:**
- Runs on dedicated infrastructure within the Collection Server environment
- Private key in an HSM (can be a separate device or a partition on the Collection Server's HSM)
- Validity period: election period + 30 days
- Signs machine certificates and service certificates
- If compromised: root CA custodians convene, open the safe, revoke the intermediate, and issue a new one

**Machine Certificate Issuance:**
1. Pre-election setup event at a central CIK facility (weeks before election day)
2. Each machine generates a key pair in its TPM — private key never leaves the chip
3. Machine produces a CSR (Certificate Signing Request)
4. CIK operator verifies the machine's serial number and station assignment
5. Second CIK operator approves (two-person rule)
6. Intermediate CA signs the CSR. Certificate contains: machine serial number, assigned station ID, constituency, validity period (election day ± 3 days)
7. Certificate installed on the machine
8. Machine also receives the full CA chain (root + intermediate) to verify the Collection Server

**Service Certificates:**
- Collection Server, Bulletin Board, Verification Service, and internal services also receive certificates from the intermediate CA
- Enables mTLS everywhere — all service-to-service communication is mutually authenticated

**Certificate Revocation:**
- CRL (Certificate Revocation List) published by the intermediate CA, refreshed hourly
- If a machine is stolen or compromised, its certificate is revoked
- Collection Server checks CRL on every connection (cached, small list)

**Key Destruction:**
- After election results are certified and legal challenge periods expire, the intermediate CA key is destroyed (HSM wiped, witnessed, logged)
- Root CA key is destroyed in a formal ceremony mirroring the generation ceremony: custodians convene, open the safe, wipe the HSM on camera, signed destruction audit log produced
- All machine TPMs are reset during post-election decommissioning

**Certificate Policy (CP) and Certification Practice Statement (CPS):**
- Formal documents defining the CA's operational procedures, roles, responsibilities, and security controls
- Included in the CIK deliverables (docs/cik/pki/)
- Modeled on PCI PIN Security Requirements Annex A (Certificate Authority requirements)

### 5.6 Machine Network Connectivity

- Machines connect to the Collection Server over the public internet using **mTLS** (mutual TLS)
- Machine authenticates with its client certificate (Section 5.5); Collection Server authenticates with its service certificate
- No VPN required — mTLS provides equivalent authentication + encryption without the operational complexity of managing 12,000 VPN tunnels
- If the network drops: machine queues ballots locally, retries automatically when connectivity returns
- If the network never comes up: USB sync fallback (Section 5.4)
- DNS: machines are pre-configured with the Collection Server's IP addresses (no DNS dependency on election day)

### 5.7 Hardware Requirements Specification (Document)

Published spec covering:
- CPU/RAM/storage minimums
- TPM 2.0 requirements (attestation, key storage)
- Touchscreen: 15-17", resolution, brightness, viewing angle (privacy filter to prevent side-viewing)
- Physical confirm/cancel buttons: GPIO or USB HID interface
- Commission-side keypad for session code entry
- MRZ reader (USB, for commission tablet)
- Tamper-evident enclosure with sealed ports
- Battery backup: 30 min minimum
- Environmental: temperature, humidity for Bulgarian conditions
- Network interface: Ethernet and/or WiFi

### 5.8 Machine Audit Logs

Every machine maintains a tamper-evident local audit log. The log records events, never vote content.

**Logged events:**
- Boot, self-test results, software hash verification
- Session start (session code entered by commission)
- Vote cast (timestamp + ballot_id only — never party/candidate selection)
- Voter confirmed/cancelled
- Encryption and proof generation completed
- Network sync: connection established, ballots transmitted, acknowledgement received
- USB export: initiated, batch sequence number, two-person authorization
- Errors: hardware failures, network timeouts, proof validation failures, TPM attestation results
- Shutdown, sleep, power events (battery switchover, power restore)

**Tamper-evidence:**
- Each log entry is hash-chained: `entry_hash = SHA-256(previous_hash + entry_data + timestamp)`
- The chain is anchored to the machine's TPM — the first entry's hash is signed by the TPM at boot
- If any log entry is modified or deleted, the chain breaks and post-election audit detects it

**Export:**
- Logs are exported alongside ballot batches (both network sync and USB)
- Logs are also independently exportable for audit without ballot data
- Post-election: all machine logs are collected centrally. On collection, the central server validates the full hash chain against the TPM anchor signature. Any broken chain is flagged immediately — that machine's ballots are quarantined pending investigation. Validated logs are archived with the election data.

### 5.9 Polling Station Cameras

Bulgarian polling stations are already required by law to have video surveillance. The spec defines integration requirements for the voting machine environment:

**Privacy constraints:**
- Cameras must NOT have line of sight to the machine's voter-facing screen
- Camera placement is documented in the hardware requirements spec with a recommended room layout diagram

**What cameras should capture:**
- The overall polling station environment: entrance, commission table, machine area (from behind/side)
- The machine's physical integrity: no unauthorized access to ports, no tampering with seals
- Commission procedures: MRZ scanning, session code entry

**Recording:**
- Continuous recording during polling hours
- Footage stored locally at the polling station on a dedicated recording device (not on the voting machine)
- Footage archived for the legal challenge period (minimum 6 months)
- Access to footage requires judicial order or CIK administrative decision

**Note:** Camera hardware and recording infrastructure are outside the scope of our software. The spec defines placement constraints and integration requirements only.

---

## 6. Bidirectional Vote Override

### 6.1 Override Rules

| Scenario | Result |
|----------|--------|
| Online → Online | Last online ballot_id replaces previous |
| Online → In-person | In-person ballot_id replaces online (commission tablet notifies Layer 1) |
| In-person → Online | Online ballot_id replaces in-person (voter re-authenticates via eAuth) |
| In-person → In-person | Not possible (commission marks voter as having voted) |

**In all cases:** the last ballot_id associated with the ЕГН becomes the active one.

**Canonical ordering:** "Last" is defined by **receipt time at Layer 1's Collection Server** (wall-clock, NTP-synchronized). This is unambiguous for online votes (received in real-time). For offline machine votes that arrive via USB sync after the election, the machine includes its local timestamp in the batch, but the canonical order is: **in-person always wins over online if the machine's local timestamp is before the sync time.** Specifically: if Layer 1 receives an in-person ballot via USB at 21:00 with a machine timestamp of 14:00, and the voter also voted online at 18:00, the in-person vote (14:00) is earlier but takes precedence because it represents the voter's physical presence — the online vote at 18:00 was the override. The last ballot in temporal order is the active one, using machine local timestamps for in-person votes and Collection Server receipt times for online votes.

### 6.2 Coercion Resistance

- Vote buyer cannot confirm delivery: re-voting is invisible on the bulletin board
- All ballots (original and replacement) look identical: random IDs, encrypted blobs
- Timestamps on bulletin board are for random ballot IDs, not voters
- Individual votes are never decrypted
- Vote buying becomes economically irrational at scale

**Ballot ID coercion analysis:** The voter can note their ballot ID from the confirmation screen. A coercer could demand this ID. However: (a) the ballot ID proves inclusion only, never content — the coercer cannot learn what was voted; (b) a "vote for us or don't vote" coercion strategy is defeated by the fact that the voter can override online later; (c) the voter can simply not note the ballot ID — there is no physical receipt to demand. The ballot ID is a voluntary transparency tool, not a proof of vote content.

### 6.3 Deduplication Protocol (After Polls Close)

1. Layer 1 computes active set: one ballot_id per voter (the latest)
2. Layer 1 publishes commitment: `hash(sorted(active_set))`, signed by Collection Server
3. Active set (ballot IDs only, no ЕГНs) sent to Layer 2's Tally Service
4. Tally Service filters bulletin board: keeps only ballots in active set
5. gnark SNARK proof generated (see Section 2.7)
6. Proof, commitment, and filtered set Merkle root published on bulletin board

**Proof hides:** which IDs were filtered, how many times anyone voted, voter-ballot links.
**Proof reveals:** total active ballots (= unique voters), that filtering was honest.

### 6.4 Active Set Trust Assumption

**This is the most critical trust assumption in the system.** The ZK dedup proof verifies that the filtered set matches the committed active set, but it does NOT prove that Layer 1 honestly computed the active set from its voter-ballot mappings. A compromised Layer 1 could publish a fraudulent active set (e.g., excluding ballots).

**Mitigations:**
1. **Voter count cross-check:** The active set size (total unique voters) must equal the number of voters marked in the electoral rolls. Political party observers independently count voters at polling stations. Any discrepancy between the active set size and the observed voter count is immediately flagged.
2. **Post-election audit:** Layer 1's `ЕГН → ballot_id` database is sealed and made available to court-appointed auditors under judicial order. The auditors can verify the active set was correctly derived. This happens after results certification, under strict access controls.
3. **Parallel observation:** Political party representatives can run parallel tracking at Layer 1 — observing (but not accessing) the total ballot count and deduplication decisions in real-time, similar to how party observers currently watch ballot boxes.
4. **Dual-operator requirement:** The active set computation requires sign-off from two CIK administrators (two-person rule), logged in the audit trail.

---

## 7. Decryption Ceremony

### 7.1 Timeline

```
20:00  Polls close. Bulletin board sealed to read-only.
20:01  Layer 1 publishes active set commitment.
20:02  Live broadcast begins. 9 trustees seated, each with HSM.
20:05  ZK deduplication proof generation begins (progress visible on screen).
~21:05 Dedup proof published (worst case 60 min). Audience can verify.
21:06  Homomorphic tallying: multiply active encrypted ballots element-wise.
~21:15 Tallying complete. Encrypted sums ready.
21:16  Trustee decryption phase begins.
```

### 7.2 Trustee Decryption

1. Host calls first trustee. Trustee inserts HSM into ceremony workstation.
2. HSM authenticates trustee (PIN/biometric).
3. Tally Service sends encrypted sums to HSM.
4. HSM computes partial decryptions internally — key share never leaves device.
5. HSM outputs partial decryption values + Chaum-Pedersen proofs.
6. Tally Service verifies proofs on screen. Green checkmark.
7. HSM removed. Next trustee.
8. After 5th trustee: combine partial decryptions, solve discrete logs.
9. **Results appear on screen.**
10. Remaining trustees (6-9) contribute for additional verification.
11. Final tally correctness proof generated and published.

### 7.3 Published After Ceremony

- Active set commitment + Layer 1 signature
- ZK deduplication proof
- Homomorphic tally ciphertexts (encrypted sums)
- Each trustee's partial decryption + Chaum-Pedersen proof
- Final plaintext results
- Tally correctness proof

### 7.4 Failure Scenarios

| Scenario | Response |
|----------|----------|
| HSM failure | Skip trustee, need 5-of-9 |
| Trustee refuses | Skip, same tolerance |
| < 5 trustees | Ceremony rescheduled (political crisis, not technical) |
| Network failure | Ceremony is local; publish to bulletin board when connectivity returns |
| Power failure | Battery backup on ceremony workstation |

### 7.5 Ceremony Workstation

- Air-gapped from internet during ceremony (local bulletin board connection only)
- Runs Tally Service
- Large display for TV broadcast
- Software hash verified on camera before ceremony

---

## 8. Verification & Public Auditability

### 8.1 Three Levels

**Level 1 — Immediate (during voting):**
- Online: Merkle inclusion proof + ballot ID + extension return code verification
- In-person: screen confirmation + ballot ID displayed (voter can note it voluntarily). Machine integrity guaranteed by TPM attestation.

**Level 2 — Individual (post-election):**
- Voter visits `verify.izbori.bg`
- Enters ballot ID (typed or QR scan)
- Returns: ballot exists at position N, Merkle inclusion proof
- **Inclusion only, never content** — confirms ballot was counted, cannot reveal what it contains

**Level 3 — Delegated (parties, NGOs, universities, media):**
- Download full bulletin board
- Verify all ballot validity proofs
- Recompute Merkle tree from scratch
- Verify deduplication SNARK proof
- Verify each trustee's partial decryption proofs
- Verify tally correctness proof
- Independently recompute results from raw data

### 8.2 Open Data API

```
GET /api/v1/board                    — full bulletin board (paginated)
GET /api/v1/board/{ballot_id}        — single ballot + Merkle proof
GET /api/v1/board/root               — current Merkle root
GET /api/v1/proofs/dedup             — deduplication SNARK proof
GET /api/v1/proofs/tally             — tally correctness proof
GET /api/v1/ceremony/trustees        — partial decryptions + proofs
GET /api/v1/results                  — final plaintext results
GET /api/v1/election                 — election metadata (parties, candidates, public key)
```

All JSON. All signed by bulletin board service key. Downloadable as single archive.

**API details:**
- Pagination: cursor-based (opaque cursor token, not offset). Default page size: 100, max: 1000.
- Rate limiting: public read endpoints rate-limited per IP (100 req/min default, configurable). Delegated verifiers can request higher limits via API key.
- Response envelope: `{"data": ..., "meta": {"cursor": "...", "total": N}, "signature": "..."}`.
- Error format: `{"error": {"code": "...", "message": "..."}}` with standard HTTP status codes.
- Versioning: URL-based (`/api/v1/`). Breaking changes require a new version. Old versions supported for one election cycle after deprecation.
- Authentication: read endpoints are public (no auth). Write endpoints (used only by internal services) require mTLS.

### 8.3 CLI Verification Tools

```
otvoren-vot verify board      — download and verify full Merkle tree
otvoren-vot verify ballots    — verify all ballot validity proofs
otvoren-vot verify dedup      — verify deduplication SNARK
otvoren-vot verify tally      — verify tally correctness proof
otvoren-vot verify all        — run everything, output pass/fail report
```

### 8.4 Public Dashboard

- Before ceremony: ballot count, Merkle tree visualization, system health
- During ceremony: trustee progress, proof generation, live results
- After ceremony: final results, charts, downloadable data, verification tool links

---

## 9. Election Administration

### 9.1 Admin Service (Python FastAPI)

**Pre-election:**
- Create election: name, date, open/close times
- Configure parties: name, logo, candidate lists
- Configure policies: extension requirement, device reuse policy
- Trigger DKG ceremony, register trustees, verify key shares
- Publish signed election config to bulletin board

**During election:**
- Monitor: ballots cast, system health, error rates
- Emergency: extend hours, pause online voting, system alerts
- No access to ballot content or voter-ballot mappings

**Post-election:**
- Initiate ceremony sequence: seal board → dedup → trustee phase
- Publish results
- Export signed archive for long-term storage

### 9.2 Access Control

- Roles: CIK admin (full), CIK observer (read-only), trustee (ceremony only)
- All actions logged to immutable audit trail (append-only PostgreSQL table)
- **Two-person rule** for critical operations: election creation, key generation, emergency controls, active set computation. Mechanism: critical operations enter a "pending approval" state. A second, distinct admin account must approve within a configurable time window (default: 30 minutes). Both the request and approval are recorded in the immutable audit trail with timestamps and admin identities. If the approval window expires, the operation is cancelled and logged.

---

## 10. Availability & Load Management

**Expected load:** ~500,000 online voters over 12 hours = ~12 votes/second average, with peak bursts of ~100 votes/second (morning and evening spikes).

**Rate limiting:**
- Collection Server: rate-limited per authenticated voter (max 10 submissions per hour per ЕГН — generous for override use case, prevents abuse)
- Bulletin Board public API: per-IP rate limiting (see Section 8.2)
- Dashboard: served via CDN (Cloudflare or equivalent) to absorb traffic spikes

**DDoS protection:**
- Voter-facing services (`izbori.bg`, dashboard) behind CDN/DDoS mitigation
- Collection Server and Bulletin Board are on non-public networks, accessed only via the web app's backend (not directly from browsers)
- The Bulletin Board's public read API is a separate, read-only replica that can be scaled independently
- Connection pooling and request queuing at the Collection Server (reject gracefully rather than crash under load)

**Graceful degradation:**
- If online voting is overwhelmed: queue submissions, show estimated wait time
- If online voting is fully down: in-person voting continues unaffected at all polling stations
- Machine failure at a station: polling stations are required to have 2+ machines. If one fails, voters use the remaining machine(s). If all machines at a station fail, voters are directed to the nearest functioning station.
- There are no paper ballots in this system. The cryptographic tally is the count. Manual counting is eliminated entirely.

---

## 11. Accessibility

**Web interface (WCAG 2.1 AA compliance):**
- Full keyboard navigation — every interaction reachable without a mouse
- Screen reader support — all interactive elements have ARIA labels, ballot choices are semantically structured
- High-contrast mode — toggle in the UI, meets WCAG AAA contrast ratios
- Large text mode — minimum 18px base, scalable to 200%
- Focus indicators — visible focus ring on all interactive elements
- No time-limited interactions — the ballot page does not expire while the voter is selecting

**Voting machine:**
- Extra-large text mode with high contrast (activated via accessibility button on machine)
- Audio guidance via headphone jack with physical NEXT/SELECT hardware buttons for blind voters
- Touchscreen targets minimum 44×44px (WCAG touch target size)
- Ballot ID displayed in large, high-contrast text on confirmation screen

**Browser extension:**
- Extension popup is screen-reader accessible
- Return code displayed as both text and a color indicator (not color-only — avoids color-blindness issues)

---

## 12. Non-Code Deliverables

### 12.1 Threat Model (Bulgarian)

Structured analysis: in-scope threats (client malware, server compromise, insider threats, network attacks, vote buying, ballot stuffing, tally manipulation), out-of-scope threats, per-threat analysis (likelihood, impact, mitigation, residual risk).

### 12.2 Legal Compliance Analysis (Bulgarian)

Article-by-article mapping against Изборен кодекс: satisfied articles, articles requiring interpretation, articles requiring amendment. Comparison with Estonian and Swiss legal frameworks. GDPR / ЗЗЛД compliance analysis.

### 12.3 Cost Projection (Bulgarian)

Hardware (HSMs, ceremony workstation, servers, voting machines), software (open source + maintenance + audits), operations (staffing, coordination). 5-year TCO. Comparison with current election costs.

### 12.4 Independent Audit Plan (Bulgarian)

Pre-election code audit (2 firms, 3-6 months), penetration testing, formal verification targets, post-election verification, audit cadence.

### 12.5 Certification Path (Bulgarian)

Common Criteria (Protection Profile, target EAL), FIPS 140-3 Level 3 (HSMs), EU eIDAS compliance, BSI Technical Guidelines reference, timeline (12-18 months).

### 12.6 PKI Certificate Policy & Certification Practice Statement (Bulgarian)

CP/CPS documents for the election PKI, modeled on PCI PIN Security Requirements Annex A. Covers: CA hierarchy, key ceremony procedures, certificate lifecycle, revocation procedures, physical security controls, audit requirements, roles and responsibilities.

---

## 13. Project Structure

Vertical monorepo, organized by architectural layer:

```
otvoren-vot/
├── crypto/              # Go — ElGamal, Merkle, Sigma proofs, gnark circuits
├── bulletin-board/      # Go — append-only log service + PostgreSQL
├── tally/               # Go — homomorphic tallying + threshold decryption
├── collection/          # Go — ballot collection, identity stripping
├── auth/                # Go — eAuth abstraction + mock provider
├── verification/        # Go — threshold return code generation
├── web/                 # TypeScript/React — voter web app
├── dashboard/           # TypeScript/React — public results dashboard
├── extension/           # TypeScript — browser verification extension
├── machine/             # Go — voting machine embedded software
├── admin/               # Python FastAPI — election management
├── deploy/              # Docker Compose + configs
├── docs/
│   ├── architecture/    # English — technical docs
│   ├── protocol/        # English — cryptographic protocol specs
│   └── cik/             # Bulgarian — legal, threat model, cost, audit, certification
└── specs/               # Design specs and decisions
```

### Reproducible Builds

All compiled artifacts (Go binaries, WASM bundles, browser extension package) use **deterministic/reproducible builds**: the same source code, build environment, and build instructions always produce bit-for-bit identical output.

- **Why:** Without reproducible builds, there is no way to verify that the deployed binaries correspond to the audited source code. An auditor reviews the source but the deployed binary could contain different code.
- **How:** Dockerized build environment with pinned base images, pinned compiler versions, pinned dependencies (Go modules, npm lockfile). Build output is hashed and the hash is published alongside the release.
- **Verification:** Any party can clone the repo, run the build in the provided Docker container, and compare the output hash against the published hash. If they match, the binary is faithful to the source.
- **Machine images:** The voting machine's embedded Linux image is also reproducibly built. The image hash is the reference hash stored in the TPM for boot attestation (Section 5.1). Auditors can independently rebuild the image and confirm the TPM is attesting to the audited software.
- **Browser extension:** The extension package submitted to Chrome Web Store / Firefox Add-ons is reproducibly built. The published source hash in the repo matches the store-distributed package.

### Build Order

Bottom-up: crypto primitives → bulletin board → tally → collection + auth → verification → web + dashboard + extension → machine → admin → deploy → docs

---

## 14. Technology Stack

| Component | Technology | Justification |
|-----------|-----------|---------------|
| Critical-path servers | Go + libsodium (CGo) | Performance, type safety, single binary deployment |
| ZK proofs | gnark (Go) | Native Go, Groth16 recursion support |
| Bulletin board storage | PostgreSQL | Battle-tested, familiar to Bulgarian gov IT, standard replication |
| HSM interface | Go PKCS#11 | Standard HSM protocol |
| Client-side encryption | Custom ElGamal on libsodium.js scalar/point primitives (WASM) | Ristretto255 group, homomorphic property required |
| Voter web app | TypeScript/React | Component model, ecosystem, developer availability |
| Public dashboard | TypeScript/React | Shared codebase with web app |
| Browser extension | TypeScript | Chrome + Firefox Manifest V3 |
| Election admin | Python FastAPI | CRUD + workflow, auto-generated API docs |
| Machine software | Go on embedded Linux | Same crypto library as servers, single binary |
| Build system | Reproducible/deterministic builds | Verifiable binary-to-source correspondence |
| Containerization | Docker Compose | Dev/demo deployment |
| Localization | Hardcoded Bulgarian strings (no i18n framework) | Single language, avoids framework overhead. If multi-language is ever needed, extract to resource files. |

---

## 15. Decisions Log

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Target audience | CIK (production-grade) | Build the real thing, not a demo |
| Voting machine | Software + hardware spec doc | Build software, publish hardware requirements |
| Authentication | eAuth abstraction + mock provider | Can't integrate live eAuth without government approval |
| UI language | Bulgarian Cyrillic only | National election for Bulgarian citizens |
| Bulletin board storage | PostgreSQL + app-layer Merkle tree | Operational familiarity, defense in depth |
| ZK framework | Sigma protocols + gnark (mixed) | Right tool per proof complexity |
| Client malware defense | Browser extension (verification codes) | Sandboxed display, no second device needed |
| Mobile verification app | Dropped | Extension covers realistic threats, override covers the rest |
| SMS verification | Dropped | Extension is more secure, no telecom dependency |
| Split-device voting | Dropped | Extension provides equivalent security without UX burden |
| Extension policy default | Required for online voting | Configurable by CIK |
| Device reuse tracking | Removed | eAuth MFA is sufficient; cookie-based tracking adds complexity for minimal value |
| Decryption ceremony | Truly live computation | Maximum public confidence |
| Deployment | Docker Compose (dev/demo) | Production infra is CIK's responsibility |
| Project structure | Vertical monorepo | Solo developer, single audit target |
| License | EUPL-1.2 | EU public sector copyleft, CIK-friendly |
| Project name | otvoren-vot | "Open Vote" — communicates transparency |
