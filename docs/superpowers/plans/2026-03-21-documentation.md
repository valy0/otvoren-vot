# Otvoren-Vot Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create all project documentation — GitHub project files, technical architecture docs, cryptographic protocol specs, and CIK deliverables in Bulgarian — so the repo is presentation-ready before any code is written.

**Architecture:** Documents are organized in three tiers: root-level project files (README, LICENSE, CONTRIBUTING), English technical docs under `docs/architecture/` and `docs/protocol/`, and Bulgarian CIK deliverables under `docs/cik/`. All documents derive from the approved design spec at `docs/superpowers/specs/2026-03-20-otvoren-vot-design.md`.

**Tech Stack:** Markdown, EUPL-1.2 license text

**Reference:** Design spec at `docs/superpowers/specs/2026-03-20-otvoren-vot-design.md`

---

## File Map

### Root-level project files
- Create: `README.md` — project overview, architecture diagram (Mermaid), quick start, verification, links
- Create: `LICENSE` — EUPL-1.2 full text
- Create: `CONTRIBUTING.md` — how to contribute, code of conduct, PR process
- Create: `CLAUDE.md` — Claude Code project instructions
- Create: `SECURITY.md` — responsible disclosure policy
- Update: `.gitignore` — comprehensive Go/TS/Python ignores

### Technical architecture docs (English)
- Create: `docs/architecture/overview.md` — two-layer architecture, component map, data flow, coercion resistance, error handling
- Create: `docs/architecture/layer1-identity.md` — Auth Service, Collection Server, identity binding
- Create: `docs/architecture/layer2-ballots.md` — Bulletin Board, Tally Service, Verification Service, Dashboard, Open Data API
- Create: `docs/architecture/voting-machine.md` — machine platform, TPM attestation, offline sync, hardware spec, accessibility
- Create: `docs/architecture/browser-extension.md` — extension architecture, verification code flow, security model, accessibility
- Create: `docs/architecture/admin.md` — Election admin service, pre/during/post workflows, access control, audit trail
- Create: `docs/architecture/pki.md` — CA hierarchy, key ceremony, certificate lifecycle (PCI PIN RCA model)
- Create: `docs/architecture/infrastructure.md` — dual DC design, Docker Compose dev setup, network isolation, availability

### Cryptographic protocol specs (English)
- Create: `docs/protocol/overview.md` — protocol summary, proof framework, cryptographic groups
- Create: `docs/protocol/elgamal.md` — exponential ElGamal over Ristretto255, ballot encoding, homomorphic properties
- Create: `docs/protocol/ballot-proofs.md` — Sigma protocols for ballot validity, candidate validity
- Create: `docs/protocol/threshold.md` — DKG (Feldman VSS), threshold decryption, Chaum-Pedersen proofs, key lifecycle
- Create: `docs/protocol/deduplication.md` — gnark SNARK circuit, dual-hash Merkle tree, recursive proof composition
- Create: `docs/protocol/verification-codes.md` — return code protocol, blinded session tokens (RFC 9474), extension binding
- Create: `docs/protocol/ceremony.md` — decryption ceremony protocol, timeline, failure scenarios

### CIK deliverables (Bulgarian)
- Create: `docs/cik/threat-model.md` — structured threat analysis
- Create: `docs/cik/legal-compliance.md` — Изборен кодекс article mapping
- Create: `docs/cik/cost-projection.md` — hardware, software, operations, 5-year TCO
- Create: `docs/cik/audit-plan.md` — code audit, pen testing, formal verification, post-election
- Create: `docs/cik/certification-path.md` — Common Criteria, FIPS, eIDAS, BSI, timeline
- Create: `docs/cik/pki-cp-cps.md` — Certificate Policy & Certification Practice Statement

---

## Task 1: License and .gitignore

**Files:**
- Create: `LICENSE`
- Update: `.gitignore`

- [ ] **Step 1: Create EUPL-1.2 license file**

Download the official EUPL-1.2 text and save as `LICENSE`.

- [ ] **Step 2: Update .gitignore**

Comprehensive ignores for Go, TypeScript/Node, Python, IDE files, OS files, build artifacts.

```
# Go
*.exe
*.dll
*.so
*.dylib
*.test
*.out
bin/
vendor/

# Node/TypeScript
node_modules/
dist/
build/
*.tgz
.next/

# Python
__pycache__/
*.py[cod]
*.egg-info/
.venv/
*.egg

# IDE
.idea/
.vscode/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Project
.superpowers/
.env
*.local
```

- [ ] **Step 3: Commit**

```bash
git add LICENSE .gitignore
git commit -m "Add EUPL-1.2 license and comprehensive .gitignore"
```

---

## Task 2: README.md

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write README.md**

Structure:
1. Project title and one-line description in both Bulgarian and English
2. Badges (license, build status placeholder)
3. Overview paragraph — what this is, who it's for
4. Architecture diagram (Mermaid — two-layer architecture from spec Section 3)
5. Key features list (from spec Section 1)
6. Project structure (directory tree from spec Section 13)
7. Quick start (Docker Compose — placeholder for now)
8. Verification tools (CLI commands from spec Section 8.3)
9. Documentation links (architecture, protocol, CIK)
10. Security policy link
11. Contributing link
12. License

Language: English, with the project title "Отворен вот" in Bulgarian.

Reference spec sections: 1 (Overview), 3 (Architecture), 8 (Verification), 13 (Project Structure), 14 (Tech Stack), 15 (Decisions Log).

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "Add project README with architecture overview"
```

---

## Task 3: CONTRIBUTING.md and SECURITY.md

**Files:**
- Create: `CONTRIBUTING.md`
- Create: `SECURITY.md`

- [ ] **Step 1: Write CONTRIBUTING.md**

Structure:
1. Welcome and project context (national election system — contributions are scrutinized)
2. Development setup (Go, Node, Python prerequisites, Docker Compose)
3. Code style (Go: gofmt, TypeScript: ESLint/Prettier, Python: black/ruff)
4. Branch strategy (main is protected, feature branches, squash merges)
5. PR process (description template, review requirements)
6. Testing expectations (TDD, coverage requirements)
7. Reproducible builds (how to verify your build matches the reference hash)
8. Security considerations (no secrets in code, crypto changes require formal review)
9. Code of Conduct (Contributor Covenant reference)

- [ ] **Step 2: Write SECURITY.md**

Structure:
1. Responsible disclosure policy
2. Scope (what counts as a security issue)
3. Contact method (security@otvoren-vot.bg placeholder + GitHub Security Advisories)
4. Response timeline commitments
5. What to expect after reporting
6. Out of scope (social engineering against individuals, DoS testing without permission)

- [ ] **Step 3: Commit**

```bash
git add CONTRIBUTING.md SECURITY.md
git commit -m "Add contributing guidelines and security disclosure policy"
```

---

## Task 4: CLAUDE.md

**Files:**
- Create: `CLAUDE.md`

- [ ] **Step 1: Write CLAUDE.md**

Project instructions for Claude Code sessions:
1. Project overview (one paragraph)
2. Architecture summary (two-layer, Layer 1 identity, Layer 2 ballots)
3. Tech stack and language conventions
4. Directory structure and what lives where
5. Build commands (placeholder — `go build`, `npm run build`, etc.)
6. Test commands (placeholder — `go test`, `npm test`, `pytest`)
7. Code conventions (Go: standard library style, TypeScript: strict mode, Python: type hints)
8. Crypto rules: never implement custom crypto primitives — use libsodium/gnark. All crypto changes require review.
9. Commit conventions: conventional commits, squash merges
10. Key files to read for context (design spec, protocol docs)

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "Add Claude Code project instructions"
```

---

## Task 5: Architecture Overview

**Files:**
- Create: `docs/architecture/overview.md`

- [ ] **Step 1: Write overview.md**

Comprehensive architecture document covering:
1. System overview and design principles (privacy by separation, end-to-end verifiability, coercion resistance)
2. Two-layer architecture diagram (Mermaid) and explanation
3. Component inventory — all 11 services with one-paragraph descriptions
4. Data flow diagrams: online voting flow, in-person voting flow, decryption ceremony flow
5. Network topology: Layer 1 ↔ Layer 2 boundary, public API surface, internal-only services
6. Trust model: what each component trusts, what it doesn't
7. Coercion resistance: why vote buying is economically irrational, bidirectional override, ballot ID coercion analysis
8. Error handling: network failures, eAuth timeouts, proof validation failures, election-closed scenarios
9. Verification levels: immediate, individual, delegated — three paths to trust
10. Configuration: election-level settings (extension policy, etc.)
11. Accessibility: WCAG 2.1 AA for web, machine accessibility features (large text, audio via headphones, physical buttons). Note: no paper receipt (Section 5.1 supersedes Section 11's mention of paper receipts).

Reference spec sections: 1, 3, 4, 4.5, 5, 6.2, 7, 8.1, 10, 11.

- [ ] **Step 2: Commit**

```bash
git add docs/architecture/overview.md
git commit -m "docs: add architecture overview"
```

---

## Task 6: Layer 1 & Layer 2 Architecture Docs

**Files:**
- Create: `docs/architecture/layer1-identity.md`
- Create: `docs/architecture/layer2-ballots.md`

- [ ] **Step 1: Write layer1-identity.md**

Covers:
1. Auth Service: eAuth 2.0 abstraction, mock provider interface, authentication flow
2. Collection Server: ballot reception, EGN→ballot_id mapping, identity stripping protocol
3. Deduplication bridge: active set computation, canonical ordering, handoff to Layer 2
4. Active set trust assumption and mitigations (Section 6.4)
5. Data model: what Layer 1 stores, retention policy, post-election audit access

Reference spec sections: 3.1, 3.3, 3.4, 4.1, 6.1, 6.3, 6.4.

- [ ] **Step 2: Write layer2-ballots.md**

Covers:
1. Bulletin Board: PostgreSQL schema, dual-hash Merkle tree (SHA-256 + Poseidon), append-only enforcement, external root anchoring
2. Tally Service: homomorphic tallying, threshold decryption coordination, ZK dedup proof generation
3. Verification Service: return code generation, blinded session token validation
4. Open Data API: endpoints, pagination, rate limiting, response format
5. Public Dashboard: three phases (before ceremony — ballot count, Merkle tree viz, health; during ceremony — trustee progress, proof generation, live results; after ceremony — final results, charts, verification links)
6. Data model: what Layer 2 stores, public vs internal data

Reference spec sections: 3.2, 3.5, 3.6, 2.5, 2.6, 2.7, 2.8, 8.2, 8.4.

- [ ] **Step 3: Commit**

```bash
git add docs/architecture/layer1-identity.md docs/architecture/layer2-ballots.md
git commit -m "docs: add Layer 1 and Layer 2 architecture details"
```

---

## Task 7: Voting Machine & Browser Extension Docs

**Files:**
- Create: `docs/architecture/voting-machine.md`
- Create: `docs/architecture/browser-extension.md`

- [ ] **Step 1: Write voting-machine.md**

Covers:
1. Machine platform: embedded Linux, Go kiosk, TPM attestation at boot
2. Voter flow (11 steps from spec Section 5.2)
3. Machine-tablet pairing protocol (session code, MRZ reader)
4. Offline sync: SQLite queue, mTLS sync, USB fallback with security protocol
5. Audit logs: hash-chained events, TPM anchor, export and validation
6. Hardware requirements specification (full spec from Section 5.7)
7. Polling station camera requirements
8. Trust model: why TPM replaces paper

Reference spec sections: 5.1–5.9.

- [ ] **Step 2: Write browser-extension.md**

Covers:
1. Extension purpose and security model (sandboxed popup, isolated from page JS)
2. Verification code flow: session binding via blinded tokens, code mapping, return code verification
3. JavaScript integrity check: hash verification of served voting page JS
4. Certificate pinning for izbori.bg
5. Configuration gate: required/recommended/disabled
6. Manifest V3 architecture: background script, content script, popup
7. Root/jailbreak detection (N/A — desktop extension, not mobile)

Reference spec sections: 2.8, 4.3, 4.4, 4.6.

- [ ] **Step 3: Commit**

```bash
git add docs/architecture/voting-machine.md docs/architecture/browser-extension.md
git commit -m "docs: add voting machine and browser extension architecture"
```

---

## Task 8: PKI & Infrastructure Docs

**Files:**
- Create: `docs/architecture/pki.md`
- Create: `docs/architecture/infrastructure.md`

- [ ] **Step 1: Write pki.md**

Covers:
1. CA hierarchy: offline root → online intermediate → end-entity
2. Root CA key ceremony (PCI PIN RCA model): air-gapped workstation, M-of-N split knowledge, custodian requirements, witness protocol, video recording
3. Machine certificate issuance: CSR from TPM, two-person approval, certificate contents
4. Service certificates: mTLS for all internal communication
5. Certificate revocation: CRL, hourly refresh
6. Key destruction: post-election ceremony
7. CP/CPS summary (full CP/CPS is a separate CIK deliverable)

Reference spec section: 5.5.

- [ ] **Step 2: Write infrastructure.md**

Covers:
1. Dual data center design: Sofia + Varna, active-active, 450km separation
2. Docker Compose development setup: all services in a single compose file
3. Production network isolation: Layer 1 and Layer 2 on separate physical infrastructure
4. Merkle root tamper-evidence: external monitors, signed roots every 60 seconds
5. Availability: load management, DDoS protection, graceful degradation
6. Reproducible builds: Docker build environment, hash verification
7. Web security: DNSSEC, HSTS, CSP

Reference spec sections: 3.5, 3.6, 4.6, 10, 13 (Reproducible Builds).

- [ ] **Step 3: Commit**

```bash
git add docs/architecture/pki.md docs/architecture/infrastructure.md
git commit -m "docs: add PKI and infrastructure architecture"
```

---

## Task 9: Election Administration Architecture Doc

**Files:**
- Create: `docs/architecture/admin.md`

- [ ] **Step 1: Write admin.md**

Covers:
1. Admin Service overview: Python FastAPI, internal tool for CIK staff, not voters
2. Pre-election workflows: create election, configure parties/candidates, set policies, trigger DKG, register trustees
3. During-election workflows: monitoring dashboard, emergency controls (extend hours, pause online voting)
4. Post-election workflows: initiate ceremony sequence, publish results, export signed archive
5. Access control: three roles (CIK admin, CIK observer, trustee), what each can do
6. Two-person rule: mechanism (pending approval state, 30-minute window, audit-logged), which operations require it
7. Immutable audit trail: append-only PostgreSQL table, what's logged, retention
8. Why Python FastAPI: CRUD + workflow logic, auto-generated OpenAPI docs, not on critical voting path, no crypto

Reference spec sections: 9.1, 9.2.

- [ ] **Step 2: Commit**

```bash
git add docs/architecture/admin.md
git commit -m "docs: add election administration architecture"
```

---

## Task 10: Cryptographic Protocol — Overview & ElGamal

**Files:**
- Create: `docs/protocol/overview.md`
- Create: `docs/protocol/elgamal.md`

- [ ] **Step 1: Write protocol overview.md**

Covers:
1. Protocol summary: what the system proves, to whom
2. Cryptographic groups: Ristretto255 for ElGamal, BN254 for gnark SNARKs
3. Proof framework: Sigma protocols for simple proofs, gnark SNARKs for complex circuits
4. Dual-hash Merkle tree: SHA-256 public + Poseidon SNARK-friendly
5. Four proofs table (ballot validity, deduplication, partial decryption, tally correctness)
6. Security assumptions: discrete log hardness on Ristretto255, knowledge-of-exponent on BN254

Reference spec sections: 2 (all), 2.4 (table).

- [ ] **Step 2: Write elgamal.md**

Detailed protocol specification:
1. Exponential ElGamal definition: key generation, encryption, decryption, homomorphic property
2. Mathematical notation and group operations over Ristretto255
3. Ballot encoding: party vector (binary, one-hot), candidate vector (binary, conditional)
4. Encryption of a ballot: per-element encryption, randomness generation
5. Homomorphic tallying: element-wise multiplication of ciphertexts
6. Decryption of the tally sum: threshold partial decryption, BSGS for discrete log recovery
7. Performance analysis: encryption time per ballot, tally time for 4M ballots, BSGS for 2550 slots

Reference spec sections: 2.2, 2.3, 2.5, 2.6.

- [ ] **Step 3: Commit**

```bash
git add docs/protocol/overview.md docs/protocol/elgamal.md
git commit -m "docs: add protocol overview and ElGamal specification"
```

---

## Task 11: Cryptographic Protocol — Proofs & Threshold

**Files:**
- Create: `docs/protocol/ballot-proofs.md`
- Create: `docs/protocol/threshold.md`

- [ ] **Step 1: Write ballot-proofs.md**

Detailed protocol specification:
1. Sigma protocol structure: commitment, challenge (Fiat-Shamir), response
2. Proof that an encrypted value is 0 or 1 (OR-proof / disjunctive Chaum-Pedersen)
3. Proof that a vector of encrypted values sums to exactly 1
4. Candidate validity proof: sum to 0 or 1, consistency with party selection
5. Proof sizes and verification costs
6. Batching optimization if needed for client-side performance

Reference spec sections: 2.3, 2.4.

- [ ] **Step 2: Write threshold.md**

Detailed protocol specification:
1. Feldman's Verifiable Secret Sharing: setup, share distribution, verification
2. Distributed Key Generation: how 9 trustees jointly generate a key without any party knowing the full secret
3. Key lifecycle: generation, distribution, compromise response (proactive re-sharing), destruction
4. Threshold decryption: partial decryption computation, Chaum-Pedersen proof of correct partial decryption
5. Share combination: Lagrange interpolation for combining partial decryptions
6. HSM interface: what operations the HSM must support (PKCS#11 subset)

Reference spec sections: 2.1, 2.1.1, 2.6.

- [ ] **Step 3: Commit**

```bash
git add docs/protocol/ballot-proofs.md docs/protocol/threshold.md
git commit -m "docs: add ballot proof and threshold protocol specifications"
```

---

## Task 12: Cryptographic Protocol — Deduplication & Verification Codes

**Files:**
- Create: `docs/protocol/deduplication.md`
- Create: `docs/protocol/verification-codes.md`

- [ ] **Step 1: Write deduplication.md**

Detailed protocol specification:
1. The deduplication problem: why it needs a ZK proof, what it hides vs reveals
2. Dual-hash Merkle tree: SHA-256 public tree, Poseidon SNARK tree, both computed on every append
3. gnark circuit specification: public inputs, private witness, constraint description
4. Recursive proof composition: batch structure (~10K ballots per batch), Groth16 recursion
5. Trusted setup: Groth16 requires a ceremony — how this is handled (powers of tau + circuit-specific)
6. Performance analysis: constraint count estimates, proving time, verification time
7. Active set commitment: hash(sorted(active_set)), signed by Layer 1

Reference spec sections: 2.7, 6.3, 6.4.

- [ ] **Step 2: Write verification-codes.md**

Detailed protocol specification:
1. Threat model: client-side malware on the voting device
2. Return code generation key: threshold among 3-of-5 verification trustees
3. Session binding: blinded session tokens (RFC 9474 RSA Blind Signatures)
4. Code mapping generation: per-session, per-party codes derived by verification trustees
5. Return code derivation: from encrypted ballot content, threshold computation
6. Extension communication protocol: background script ↔ Verification Service
7. Security analysis: why malware cannot fake the return code

Reference spec sections: 2.8.

- [ ] **Step 3: Commit**

```bash
git add docs/protocol/deduplication.md docs/protocol/verification-codes.md
git commit -m "docs: add deduplication and verification code protocol specs"
```

---

## Task 13: Cryptographic Protocol — Ceremony

**Files:**
- Create: `docs/protocol/ceremony.md`

- [ ] **Step 1: Write ceremony.md**

Detailed protocol specification:
1. Pre-ceremony: bulletin board sealed, active set commitment published
2. Timeline with worst-case estimates (20:00–~21:30)
3. ZK deduplication proof generation (live, progress visible)
4. Homomorphic tallying (element-wise ciphertext multiplication)
5. Trustee decryption phase: step-by-step per trustee, HSM interaction, proof publication
6. BSGS discrete log recovery: per-slot, performance characteristics
7. Results publication: what gets written to the bulletin board
8. Failure scenarios and recovery procedures
9. Ceremony workstation: air-gapped, software hash verification on camera

Reference spec sections: 7.1–7.5.

- [ ] **Step 2: Commit**

```bash
git add docs/protocol/ceremony.md
git commit -m "docs: add decryption ceremony protocol specification"
```

---

## Task 14: CIK Threat Model (Bulgarian)

**Files:**
- Create: `docs/cik/threat-model.md`

- [ ] **Step 1: Write threat-model.md**

Written entirely in Bulgarian. Structure:

1. **Въведение** — document purpose, scope, methodology
2. **Модел на заплахите** — threat actors (external attacker, insider, nation-state, organized crime, individual voter fraud)
3. **Заплахи в обхват** — for each threat:
   - Купуване/продаване на гласове (vote buying)
   - Принуда на избиратели (voter coercion)
   - Набиване на бюлетини (ballot stuffing)
   - Манипулация на гласове (vote manipulation)
   - Фалшифициране на резултатите (tally fraud)
   - Кражба на самоличност (identity fraud)
   - Вътрешна измама (insider fraud)
   - Манипулация на машини (machine tampering)
   - Атаки срещу сървъри (server-side attacks)
   - Двойно гласуване (double voting)

   For each: описание, вероятност (ниска/средна/висока), въздействие, защита в системата, остатъчен риск

4. **Заплахи извън обхват** — physical attacks on DCs, compromise of 5+ trustees, eAuth system compromise
5. **Допускания за доверие** — trust assumptions, especially Layer 1 active set (Section 6.4)
6. **Заключение** — overall risk assessment

Reference: fraud resistance analysis from review, spec sections 6.4, 10.

- [ ] **Step 2: Commit**

```bash
git add docs/cik/threat-model.md
git commit -m "docs: add threat model (Bulgarian)"
```

---

## Task 15: CIK Legal Compliance Analysis (Bulgarian)

**Files:**
- Create: `docs/cik/legal-compliance.md`

- [ ] **Step 1: Research Bulgarian Electoral Code structure**

Web search for the current Изборен кодекс structure, key articles related to:
- Voting methods (Глава 12-13)
- Ballot secrecy requirements
- Electronic voting provisions (if any)
- Vote counting procedures
- Election observation rights
- Data protection requirements

- [ ] **Step 2: Write legal-compliance.md**

Written entirely in Bulgarian. Structure:

1. **Въведение** — document purpose, methodology
2. **Текущо правно състояние** — current state of e-voting in Bulgarian law, past referendums and legislative attempts
3. **Анализ по членове** — article-by-article mapping:
   - Членове, които системата удовлетворява
   - Членове, изискващи тълкуване (напр. "бюлетина" включва ли криптирана цифрова бюлетина?)
   - Членове, изискващи законодателна промяна
4. **GDPR / ЗЗЛД съответствие** — personal data handling analysis (ЕГН processing, data retention, right to erasure vs election integrity)
5. **Сравнение с Естония и Швейцария** — how Estonia and Switzerland amended their laws for e-voting
6. **Препоръки за законодателни промени** — specific amendment proposals
7. **Заключение**

- [ ] **Step 3: Commit**

```bash
git add docs/cik/legal-compliance.md
git commit -m "docs: add legal compliance analysis (Bulgarian)"
```

---

## Task 16: CIK Cost Projection (Bulgarian)

**Files:**
- Create: `docs/cik/cost-projection.md`

- [ ] **Step 1: Research hardware costs**

Web search for current prices of:
- YubiHSM 2 / Nitrokey HSM 2 (×9 for trustees + spares)
- Server hardware for dual DC
- Touchscreen kiosk hardware (~12,000 units)
- TPM modules
- MRZ readers
- Ceremony workstation
- Network infrastructure

- [ ] **Step 2: Write cost-projection.md**

Written entirely in Bulgarian. Structure:

1. **Въведение** — document purpose, assumptions
2. **Еднократни разходи (Капиталови)**
   - Хардуер: HSM устройства, сървъри, машини за гласуване, MRZ четци
   - Софтуер: разработка (open source — вече направено), първоначален одит
   - Инфраструктура: два дата центъра (наем/оборудване)
3. **Текущи разходи (Годишни)**
   - Поддръжка на софтуера
   - Одити за сигурност (преди всяко избирано)
   - Оперативен персонал
   - Сертификация
4. **Разходи за изборен ден**
   - Координация на попечители
   - Техническа поддръжка
   - Мрежова инфраструктура
5. **5-годишна обща стойност на притежание (TCO)**
   - Таблица: година 1 (начално), години 2-5 (текущо)
6. **Сравнение с текущите разходи за избори**
   - Настоящ бюджет на ЦИК за машини, хартия, логистика
   - Спестявания от премахване на ръчно броене
7. **Заключение**

- [ ] **Step 3: Commit**

```bash
git add docs/cik/cost-projection.md
git commit -m "docs: add cost projection (Bulgarian)"
```

---

## Task 17: CIK Audit Plan (Bulgarian)

**Files:**
- Create: `docs/cik/audit-plan.md`

- [ ] **Step 1: Write audit-plan.md**

Written entirely in Bulgarian. Structure:

1. **Въведение** — document purpose
2. **Предизборен одит на кода**
   - Обхват: пълна кодова база + криптографски протокол
   - Изпълнители: 2 независими фирми
   - Времеви график: 3-6 месеца преди избори
   - Критерии за приемане
3. **Тестване за проникване**
   - Обхват, правила за участие
   - Времеви график
   - Докладване на уязвимости
4. **Формална верификация**
   - Целеви компоненти: крипто примитиви, ZK вериги
   - Инструменти и методология
5. **Следизборен одит**
   - Верификация с CLI инструменти от множество независими страни
   - Извадково сравнение на машинни логове с дневника на бюлетини
   - Проверка на брой гласоподаватели срещу избирателни списъци
6. **Периодичност на одитите**
   - Пълен одит: преди първото внедряване
   - Делта одит: за последващи избори
7. **Възпроизводими компилации**
   - Как одиторите верифицират, че внедреният софтуер съответства на одитирания код

- [ ] **Step 2: Commit**

```bash
git add docs/cik/audit-plan.md
git commit -m "docs: add audit plan (Bulgarian)"
```

---

## Task 18: CIK Certification Path (Bulgarian)

**Files:**
- Create: `docs/cik/certification-path.md`

- [ ] **Step 1: Write certification-path.md**

Written entirely in Bulgarian. Structure:

1. **Въведение** — document purpose
2. **Common Criteria**
   - Приложим профил за защита (Protection Profile)
   - Целево ниво EAL
   - Оценяващи органи в ЕС
   - Очакван срок и стойност
3. **FIPS 140-3 ниво 3**
   - Приложимост: HSM устройства
   - Сертифицирани HSM, които отговарят на нашите изисквания
   - Не е необходима отделна сертификация — използваме вече сертифициран хардуер
4. **EU eIDAS съответствие**
   - Електронна идентификация и удостоверителни услуги
   - Връзка с eAuth 2.0
5. **BSI Технически указания**
   - Германски федерален офис за информационна сигурност
   - Най-близкият EU референтен стандарт за електронно гласуване
6. **Препоръчителна последователност**
   - Времева линия: 12-18 месеца
   - Стъпка 1: Одит на кода → Стъпка 2: Тестване за проникване → Стъпка 3: Common Criteria оценка → Стъпка 4: eIDAS съответствие
7. **Заключение**

- [ ] **Step 2: Commit**

```bash
git add docs/cik/certification-path.md
git commit -m "docs: add certification path (Bulgarian)"
```

---

## Task 19: CIK PKI CP/CPS (Bulgarian)

**Files:**
- Create: `docs/cik/pki-cp-cps.md`

- [ ] **Step 1: Write pki-cp-cps.md**

Written entirely in Bulgarian. Structure based on RFC 3647 / PCI PIN Annex A:

1. **Въведение** — документ, обхват, дефиниции
2. **Йерархия на CA** — коренов CA → междинен CA → крайни сертификати
3. **Управление на коренов CA**
   - Физическа сигурност: стая, достъп, RF екраниране
   - Церемония за генериране на ключ: скрипт, свидетели, видеозапис
   - M-of-N разделено знание: 3-от-5 пазители, изисквания за независимост и проверка на миналото
   - Съхранение: HSM в запечатан плик, двойна ключалка сейф, дневник за достъп
4. **Управление на междинен CA**
   - Инфраструктура, HSM, срок на валидност
   - Компрометиране: процедура за оттегляне и преиздаване
5. **Издаване на сертификати за машини**
   - CSR от TPM, проверка, двуличен контрол
   - Съдържание на сертификата
6. **Сервизни сертификати**
   - mTLS между всички услуги
7. **Оттегляне на сертификати**
   - CRL, обновяване на всеки час
8. **Унищожаване на ключове**
   - Следизборна церемония за унищожаване
   - Нулиране на TPM на машини
9. **Роли и отговорности**
   - CA администратори, пазители, свидетели, одитори
10. **Журнал за одит**
    - Какво се записва, срок на съхранение

- [ ] **Step 2: Commit**

```bash
git add docs/cik/pki-cp-cps.md
git commit -m "docs: add PKI Certificate Policy and Practice Statement (Bulgarian)"
```

---

## Task 20: Final Review and Cross-linking

- [ ] **Step 1: Add docs/README.md index**

Create a `docs/README.md` that indexes all documentation with brief descriptions and links. Organized by category (Architecture, Protocol, CIK).

- [ ] **Step 2: Cross-link from main README.md**

Ensure the main README.md links to all documentation sections.

- [ ] **Step 3: Verify all files exist and render**

Check that all markdown files are present, all internal links work, all Mermaid diagrams render.

- [ ] **Step 4: Commit**

```bash
git add docs/README.md README.md
git commit -m "docs: add documentation index and cross-links"
```

---

## Execution Notes

- **Tasks 1-4** (project files) should be done first — they set up the repo identity.
- **Tasks 5-9** (architecture) and **Tasks 10-13** (protocol) can be done in parallel — they are independent.
- **Tasks 14-19** (CIK deliverables) can be done in parallel — they are independent but all in Bulgarian.
- **Task 20** (final review) must be last.
- **Tasks 15 and 16** (legal compliance and cost projection) require web research for current data.
- All Bulgarian documents should use formal, professional Bulgarian suitable for parliamentary presentation.
