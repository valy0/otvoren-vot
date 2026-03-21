# otvoren-vot — Claude Code Project Instructions

## Project Overview

Otvoren-vot is an end-to-end verifiable, hybrid online + in-person voting system designed for Bulgarian national elections. The system provides encrypted ballots on a public bulletin board, homomorphic tallying without decrypting individual votes, bidirectional vote override for coercion resistance, and full independent verifiability by political parties, NGOs, and media. It is licensed under EUPL-1.2 and targets production-grade deployment presentable to CIK (Central Election Commission of Bulgaria).

## Architecture

The system uses a strict two-layer architecture that enforces separation between identity and ballot data at the network level:

- **Layer 1 — Identity:** Auth Service + Collection Server. Knows WHO voted; never sees ballot content. Handles voter authentication and submission receipts.
- **Layer 2 — Ballots:** Bulletin Board + Tally Service + Verification Service. Sees encrypted ballots; never sees voter identity. Handles storage, homomorphic tallying, and public verification.

Separation between layers is enforced by network isolation. No service in Layer 2 can query Layer 1, and vice versa. Cross-layer communication uses only cryptographic commitments (e.g., anonymized ballot IDs).

## Tech Stack

| Domain | Technology |
|--------|-----------|
| Critical-path servers + crypto | Go |
| Voter web app + admin dashboard | TypeScript / React |
| Browser extension | TypeScript (Manifest V3) |
| Election admin API | Python / FastAPI |
| Bulletin board storage | PostgreSQL |
| ZK proofs | gnark (Groth16, BN254) |
| Encryption primitives | libsodium (via CGo on server, WASM in browser) |

## Directory Structure

```
crypto/          Go crypto library (ElGamal, Merkle, Sigma proofs, gnark circuits)
bulletin-board/  Go service + PostgreSQL
tally/           Go service
collection/      Go service
auth/            Go service
verification/    Go service
web/             TypeScript/React (voter-facing web app)
dashboard/       TypeScript/React (election admin dashboard)
extension/       TypeScript (Manifest V3 browser extension)
machine/         Go embedded (polling station machines)
admin/           Python FastAPI (election administration API)
deploy/          Docker Compose configuration
docs/            Documentation (architecture, protocol specs, CIK deliverables)
```

## Build Commands

```bash
# Go services (run from each service directory or repo root)
go build ./...
go test ./...

# Web app and dashboard
npm install && npm run build
npm test

# Browser extension
npm install && npm run build

# Admin (Python)
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest

# Full stack
docker compose up
```

## Code Conventions

**Go**
- Standard library style throughout; format with `gofmt`, lint with `go vet`
- Use `filippo.io/edwards25519` for Ristretto255 group operations
- Use `github.com/consensys/gnark` for ZK proof circuits

**TypeScript**
- Strict mode enabled everywhere
- ESLint enforced; `any` types are forbidden

**Python**
- Type hints on all functions and methods
- Format with `black`, lint with `ruff`

**Git**
- Conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`
- Squash merges to main
- No attribution lines ("Generated with Claude Code" etc.) in commits or PRs

## Crypto Rules (CRITICAL)

- **NEVER implement custom cryptographic primitives.** Use libsodium for symmetric/asymmetric primitives and gnark for ZK circuits. Custom code belongs only in the composition layer on top of these libraries.
- **All changes to `crypto/` require review by 2 people.** Do not merge crypto changes with a single approval.
- **ElGamal is custom code, not a libsodium built-in.** We implement exponential ElGamal on top of libsodium's low-level Ristretto255 scalar/point arithmetic (`crypto_scalarmult_ristretto255`, `crypto_core_ristretto255_*`). On the server side (Go) we use `filippo.io/edwards25519` for the same group.
- **Two cryptographic groups are used and must not be mixed:**
  - **Ristretto255** — used for ElGamal ballot encryption and Sigma proofs
  - **BN254** — used for gnark SNARKs (Groth16 circuits)
  - These groups do NOT interact inside circuits.
- **Merkle tree uses dual hashes:** SHA-256 for the public, human-verifiable branch, and Poseidon/BN254 for the SNARK-friendly branch. Both exist in parallel; do not collapse them into one.

## Key Files

- Design spec: `.superpowers/specs/2026-03-20-otvoren-vot-design.md` (not in git)
- Implementation plans: `.superpowers/plans/` (not in git)
- Architecture docs: `docs/architecture/`
- Protocol specs: `docs/protocol/`
- CIK deliverables: `docs/cik/` (Bulgarian)
