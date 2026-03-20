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
| Components | ~15 services |
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

- Each trustee's HSM (FIPS 140-3 Level 3) generates a private key share internally
- The shares are never combined — the full private key never exists anywhere
- The protocol produces a single **election public key** for ballot encryption
- Threshold: any 5-of-9 trustees can collectively decrypt; fewer than 5 learn nothing
- Executed once per election, weeks before election day

### 2.2 Ballot Encoding

**Party vote:** Binary vector with one element per party. All zeros except position `i` = 1 for the chosen party. Example: 30 parties → vector of 30 values.

**Candidate preference:** Separate binary vector per party with one element per candidate. Only the selected party's vector may contain a 1. All other parties' candidate vectors are all-zeros (encrypted).

### 2.3 Ballot Encryption

- Each vector element encrypted independently with **exponential ElGamal** on Curve25519 using the election public key
- Exponential ElGamal is additively homomorphic: `Enc(a) * Enc(b) = Enc(a + b)`
- Client-side encryption using `libsodium.js` (WASM, bundled with web app, hash-verifiable)
- The election public key is embedded in the ballot page and published on the bulletin board

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
- Final step: solve discrete log via baby-step giant-step (trivial for vote-count-sized numbers ≤ ~4M)

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

**Performance:** Recursive proof composition — split into batches of ~10,000 ballots, prove each batch independently, compose into a single aggregate proof. Parallel proving across CPU cores. Estimated 30-60 minutes on a 64-core server.

### 2.8 Verification Code Protocol (Browser Extension)

- 3-of-5 verification trustees (subset of the 9) hold shares of a return code generation key
- At session start: verification trustees generate a per-session code mapping (party → code) and push it to the browser extension
- At ballot submission: each verification trustee independently derives a partial return code from the encrypted ballot using their key share
- Partial codes combined to produce the final return code
- Return code sent to the extension's background script, displayed in the extension popup
- Voter compares: return code matches their intended party's code from the mapping → vote is correct
- Deterministic: same encrypted content always produces the same return code

---

## 3. Two-Layer Architecture

### 3.1 Layer 1 — Identity Service

**Components:**
- **Auth Service** (Go) — eAuth 2.0 integration via abstracted interface. Ships with a mock eAuth provider for development/testing. Production integration documented.
- **Collection Server** (Go) — receives encrypted ballots from authenticated voters. Records `ЕГН → ballot_id` mapping. Strips voter identity before forwarding to Layer 2.

**Knows:** Who voted (ЕГН), when, which ballot ID, device attestation hash.
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
4. Collection Server verifies: authenticated, within vote limits, device policy passes
5. Collection Server records `ЕГН → ballot_id` in its private database
6. Collection Server forwards `{ballot_id, encrypted_ballot, proofs}` to Bulletin Board — **no ЕГН, no session token, no IP address**
7. Bulletin Board validates proofs, appends to Merkle tree, returns new Merkle root
8. Collection Server returns Merkle root + inclusion proof to voter's browser

### 3.4 Deduplication Bridge (polls close)

Layer 1 computes the "active ballot ID set" — for each ЕГН, the ballot_id of their last ballot. This set (ballot IDs only, no ЕГНs) is handed to Layer 2's Tally Service. The Tally Service filters the bulletin board and generates the ZK dedup proof.

### 3.5 Network Isolation

- Layer 1 and Layer 2 on separate Docker networks
- One-way internal API: Collection Server → Bulletin Board (submit ballot)
- One-time handoff: Layer 1 → Tally Service (active ID set at polls close)
- No return path — Layer 2 cannot query Layer 1
- Bulletin Board public API is read-only

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
11. Browser encrypts ballot client-side (libsodium.js WASM), generates ZK proofs, generates random ballot_id
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

### 4.5 Device Reuse Policy

- At submission, browser generates a device attestation hash
- Layer 1 checks: has this device hash submitted for a different ЕГН in this election?
- Same person re-voting from same device: allowed (override mechanism)
- Configurable: `strict` (reject) / `warn` (proceed with warning) / `disabled`
- Edge cases: shared family computer (scoped to browser profile), public terminals (exemptible)

### 4.6 Error Handling

- Network failure during submission → queued in browser storage, retried automatically
- eAuth timeout → re-authenticate, no data lost
- Proof validation failure → Collection Server returns error, browser re-encrypts with fresh randomness
- Election closed → hard rejection, directed to nearest polling station

---

## 5. In-Person Voting & Machine Software

### 5.1 Machine Platform

- Embedded Linux (hardened, read-only root filesystem)
- Go application — full-screen kiosk mode, no window manager, no shell access
- Offline-first: all crypto and ballot storage works without network
- Local storage: SQLite for encrypted ballot queue

### 5.2 Voter Flow

1. Present ID to election commission
2. Commission verifies eligibility, directs to machine
3. Party selection screen: large touch targets, party logos and names in Cyrillic
4. Select party
5. Optional: candidate preference screen
6. Review screen
7. Paper ballot prints behind one-way tinted glass — voter reads through glass
8. Paper displayed 5 seconds, physical shutter covers it
9. Green button (confirm) or red button (redo → back to step 3)
10. On confirm: machine encrypts ballot, generates ZK proofs, assigns random ballot_id
11. Encrypted ballot queued to local SQLite
12. Paper drops into sealed ballot box
13. Take-home receipt printed: ballot ID + QR code for verification portal
14. Machine resets for next voter

### 5.3 Identity Binding (In-Person)

- Commission checks voter ID manually (existing Bulgarian practice)
- Commission marks voter in electoral roll (paper or tablet)
- Machine does NOT authenticate the voter — doesn't know who is using it
- Layer 1 receives voter identity from commission tablet, paired with machine's ballot_id

### 5.4 Offline Sync

- Encrypted ballots stored locally in SQLite
- Sync when network available (polling station WiFi or end-of-day USB)
- Machine signs each batch with its station key for Collection Server authenticity verification
- If network never available: USB drive physically transported
- Collection Server processes machine ballots identically to online ballots

### 5.5 Hardware Requirements Specification (Document)

Published spec covering:
- CPU/RAM/storage minimums
- Touchscreen: 15-17", resolution, brightness
- Thermal printer: paper width, DPI, speed
- Privacy glass: polarization angle, viewing angle, tint level
- Physical buttons: GPIO or USB HID interface
- Shutter mechanism
- Tamper-evident enclosure
- Battery backup: 30 min minimum
- Environmental: temperature, humidity for Bulgarian conditions

### 5.6 Anti-Photography Measures (In Hardware Spec)

- Polarized privacy filter: 60° viewing angle, opaque from sides
- One-way tinted glass over printer area
- Screen brightness calibrated to wash out in photos
- Physical shutter covers paper after 5 seconds
- No audio output of vote content

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

### 6.2 Coercion Resistance

- Vote buyer cannot confirm delivery: re-voting is invisible on the bulletin board
- All ballots (original and replacement) look identical: random IDs, encrypted blobs
- Timestamps on bulletin board are for random ballot IDs, not voters
- Individual votes are never decrypted
- Vote buying becomes economically irrational at scale

### 6.3 Deduplication Protocol (After Polls Close)

1. Layer 1 computes active set: one ballot_id per voter (the latest)
2. Layer 1 publishes commitment: `hash(sorted(active_set))`, signed by Collection Server
3. Active set (ballot IDs only, no ЕГНs) sent to Layer 2's Tally Service
4. Tally Service filters bulletin board: keeps only ballots in active set
5. gnark SNARK proof generated (see Section 2.7)
6. Proof, commitment, and filtered set Merkle root published on bulletin board

**Proof hides:** which IDs were filtered, how many times anyone voted, voter-ballot links.
**Proof reveals:** total active ballots (= unique voters), that filtering was honest.

---

## 7. Decryption Ceremony

### 7.1 Timeline

```
20:00  Polls close. Bulletin board sealed to read-only.
20:01  Layer 1 publishes active set commitment.
20:02  Live broadcast begins. 9 trustees seated, each with HSM.
20:05  ZK deduplication proof generation begins (progress visible on screen).
~20:45 Dedup proof published. Audience can verify.
20:46  Homomorphic tallying: multiply active encrypted ballots element-wise.
~20:55 Tallying complete. Encrypted sums ready.
20:56  Trustee decryption phase begins.
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
- In-person: screen confirmation + paper ballot behind glass + take-home receipt

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
- Two-person rule for critical operations: election creation, key generation, emergency controls

---

## 10. Non-Code Deliverables

### 10.1 Threat Model (Bulgarian)

Structured analysis: in-scope threats (client malware, server compromise, insider threats, network attacks, vote buying, ballot stuffing, tally manipulation), out-of-scope threats, per-threat analysis (likelihood, impact, mitigation, residual risk).

### 10.2 Legal Compliance Analysis (Bulgarian)

Article-by-article mapping against Изборен кодекс: satisfied articles, articles requiring interpretation, articles requiring amendment. Comparison with Estonian and Swiss legal frameworks. GDPR / ЗЗЛД compliance analysis.

### 10.3 Cost Projection (Bulgarian)

Hardware (HSMs, ceremony workstation, servers, voting machines), software (open source + maintenance + audits), operations (staffing, coordination). 5-year TCO. Comparison with current election costs.

### 10.4 Independent Audit Plan (Bulgarian)

Pre-election code audit (2 firms, 3-6 months), penetration testing, formal verification targets, post-election verification, audit cadence.

### 10.5 Certification Path (Bulgarian)

Common Criteria (Protection Profile, target EAL), FIPS 140-3 Level 3 (HSMs), EU eIDAS compliance, BSI Technical Guidelines reference, timeline (12-18 months).

---

## 11. Project Structure

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

### Build Order

Bottom-up: crypto primitives → bulletin board → tally → collection + auth → verification → web + dashboard + extension → machine → admin → deploy → docs

---

## 12. Technology Stack

| Component | Technology | Justification |
|-----------|-----------|---------------|
| Critical-path servers | Go + libsodium (CGo) | Performance, type safety, single binary deployment |
| ZK proofs | gnark (Go) | Native Go, Groth16 recursion support |
| Bulletin board storage | PostgreSQL | Battle-tested, familiar to Bulgarian gov IT, standard replication |
| HSM interface | Go PKCS#11 | Standard HSM protocol |
| Client-side encryption | libsodium.js (WASM) | Audited crypto in browser, no JS crypto pitfalls |
| Voter web app | TypeScript/React | Component model, ecosystem, developer availability |
| Public dashboard | TypeScript/React | Shared codebase with web app |
| Browser extension | TypeScript | Chrome + Firefox Manifest V3 |
| Election admin | Python FastAPI | CRUD + workflow, auto-generated API docs |
| Machine software | Go on embedded Linux | Same crypto library as servers, single binary |
| Containerization | Docker Compose | Dev/demo deployment |

---

## 13. Decisions Log

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
| Device reuse | Configurable (strict/warn/disabled) | CIK sets policy per election |
| Decryption ceremony | Truly live computation | Maximum public confidence |
| Deployment | Docker Compose (dev/demo) | Production infra is CIK's responsibility |
| Project structure | Vertical monorepo | Solo developer, single audit target |
| License | EUPL-1.2 | EU public sector copyleft, CIK-friendly |
| Project name | otvoren-vot | "Open Vote" — communicates transparency |
