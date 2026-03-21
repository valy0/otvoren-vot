# Documentation Index

## Architecture (English)

Technical architecture documentation for developers and auditors.

| Document | Description |
|----------|-------------|
| [Overview](architecture/overview.md) | Two-layer architecture, component inventory, data flows, trust model, coercion resistance, accessibility |
| [Layer 1 — Identity](architecture/layer1-identity.md) | Auth Service, Collection Server, deduplication bridge, active set trust assumption |
| [Layer 2 — Ballots](architecture/layer2-ballots.md) | Bulletin Board, Tally Service, Verification Service, Open Data API, Dashboard |
| [Voting Machine](architecture/voting-machine.md) | TPM attestation, machine-tablet pairing, offline sync, USB security, audit logs, hardware spec |
| [Browser Extension](architecture/browser-extension.md) | Verification codes, blinded tokens, JS integrity check, certificate pinning, Manifest V3 |
| [Election Administration](architecture/admin.md) | Admin service, access control, two-person rule, audit trail |
| [PKI & Certificate Authority](architecture/pki.md) | PCI PIN RCA model, key ceremony, certificate lifecycle, mTLS |
| [Infrastructure](architecture/infrastructure.md) | Dual data centers, Docker Compose, reproducible builds, DDoS protection, web security |

## Cryptographic Protocol (English)

Detailed mathematical specifications for the cryptographic constructions.

| Document | Description |
|----------|-------------|
| [Protocol Overview](protocol/overview.md) | Proof framework, cryptographic groups (Ristretto255 + BN254), dual-hash Merkle tree, security assumptions |
| [Exponential ElGamal](protocol/elgamal.md) | ElGamal over Ristretto255, ballot encoding, homomorphic tallying, threshold decryption, BSGS recovery |
| [Ballot Validity Proofs](protocol/ballot-proofs.md) | Sigma protocols, disjunctive Chaum-Pedersen, sum-to-one proof, batching optimization |
| [Threshold Key Management](protocol/threshold.md) | Feldman VSS, DKG protocol, key lifecycle, HSM PKCS#11 interface |
| [ZK Deduplication](protocol/deduplication.md) | gnark SNARK circuit, Poseidon Merkle tree, recursive proof composition, trusted setup |
| [Verification Codes](protocol/verification-codes.md) | RFC 9474 blinded tokens, threshold return code generation, browser extension binding |
| [Decryption Ceremony](protocol/ceremony.md) | Televised ceremony protocol, timeline, trustee HSM flow, failure scenarios |

## CIK Deliverables (Bulgarian / на български)

Formal documents for presentation to the Central Election Commission.

| Документ | Описание |
|----------|----------|
| [Модел на заплахите](cik/threat-model.md) | Структуриран анализ на заплахите, 10 категории, остатъчен риск |
| [Правно съответствие](cik/legal-compliance.md) | Анализ по членове на Изборния кодекс, GDPR/ЗЗЛД, сравнение с Естония и Швейцария |
| [Финансова прогноза](cik/cost-projection.md) | 5-годишна обща стойност на притежание, сравнение с текущите разходи |
| [План за одит](cik/audit-plan.md) | Одит на кода, тестване за проникване, формална верификация |
| [Път за сертификация](cik/certification-path.md) | Common Criteria, FIPS 140-3, eIDAS, BSI, 18-месечна времева линия |
| [PKI CP/CPS](cik/pki-cp-cps.md) | Политика за сертификати и практика на удостоверителния орган |

## Design Specification

| Document | Description |
|----------|-------------|
| [System Design Spec](superpowers/specs/2026-03-20-otvoren-vot-design.md) | Complete approved design specification — the source of truth |
