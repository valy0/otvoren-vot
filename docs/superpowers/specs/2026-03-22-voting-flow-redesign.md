# Voting Flow Redesign: Routing, "Don't Support Anyone", Candidate Preference

**Date:** 2026-03-22
**Status:** Draft

## Summary

Restructure the voter web app from a single-page state machine into two routes (`/` and `/vote`), add "Не подкрепям никого" (don't support anyone) as a ballot option, and add an optional candidate preference step after party selection.

## Motivation

1. The current single-component state machine mixes login concerns with voting flow, making "start over" awkward.
2. Bulgarian elections require a "don't support anyone" option on every ballot.
3. Voters can optionally express a candidate preference within their chosen party (preferential voting).

## Routes

### `/` — Login Page

- Renders the ceremonial login page (coat of arms, tricolor, "Гласувай онлайн" button).
- **On mount:** clears `sessionStorage.authToken`. Every visit is a clean slate.
- Clicking "Гласувай онлайн" redirects to `AUTH_URL/login?redirect_uri=ORIGIN/vote`.
- No header, no progress steps — standalone ceremonial page.

### `/vote` — Voting Flow

- **On mount:** checks for session token (from URL `?token=` param or `sessionStorage`).
  - If token found in URL: store in `sessionStorage`, strip from URL.
  - If no token anywhere: redirect to `/`.
- Fetches election config from bulletin board.
- Renders the voting flow with header, progress steps, and phase-based content.
- Three steps: Партия → Кандидат → Потвърждение.

### Routing Implementation

No router library needed. Simple `window.location.pathname` check in `App.tsx`:

```tsx
const path = window.location.pathname
if (path === '/vote') return <VoteFlow />
return <LoginPage />
```

"Start over" from any point = `window.location.href = '/'` (navigates to login, clears session).

## Voting Flow Steps

### Step 1: Партия (Party Selection)

Current behavior plus one addition:

- Display all parties from election config as selectable options (numbered, with candidates listed).
- **Last option: "Не подкрепям никого"** — visually distinct (no number, different styling). Treated as a virtual party at index `numParties` in the one-hot vector.
- Selecting "Не подкрепям никого" → skip Step 2, go directly to confirmation.
- Selecting a party → proceed to Step 2.

### Step 2: Кандидат (Candidate Preference) — Optional

Only shown when a party was selected (not "Не подкрепям никого").

- Header: "Предпочитание за кандидат" with the selected party name shown.
- List the party's candidates as selectable options (numbered).
- **First option (default): "Без предпочитание"** — no candidate preference. Always available.
- Selecting a candidate or "Без предпочитание" → proceed to confirmation.
- "Назад" button returns to Step 1 (party selection), preserving the party choice.

### Step 3: Потвърждение (Confirmation)

- Shows selected party name (or "Не подкрепям никого").
- Shows selected candidate name (or "Без предпочитание") — only if a party was selected.
- Crypto status indicator (encrypting → ready).
- "Подай гласа си" and "Промени избора" buttons.
- "Промени избора" returns to Step 1.

### Done State

- Same as current: receipt with ballot ID, merkle root (if available).
- "Започни отначало" navigates to `/`.

## Progress Steps

Three steps displayed in the progress bar:

1. **Партия** — party selection
2. **Кандидат** — candidate preference (skipped for "Не подкрепям никого" but still shows as completed)
3. **Потвърждение** — confirmation and submission

When "Не подкрепям никого" is selected, step 2 is auto-completed (shown with checkmark).

## Crypto Changes

### Party Vector

Current: one-hot vector of length `numParties`.
New: one-hot vector of length `numParties + 1`. The last element represents "Не подкрепям никого".

- Binary proof for each element (0 or 1).
- Sum-one proof over the entire vector (exactly one selection).

### Candidate Vector

For the selected party at index `partyIndex`, encrypt a vector of length `candidates.length`:

- If a candidate was selected at index `candIndex`: one-hot vector (1 at `candIndex`, 0 elsewhere).
- If "Без предпочитание": all-zeros vector.

Proofs:
- Binary proof for each element.
- Sum proof: sum ≤ 1 (either 0 or 1 total). This requires a different proof than sum-one. Two approaches:
  - **(A)** Add a "no preference" slot at the end (vector length `candidates.length + 1`), always exactly one selection → reuse sum-one proof.
  - **(B)** Prove sum = 0 OR sum = 1 using a disjunctive Sigma proof.

**Recommendation:** Approach (A) — add a virtual "no preference" slot. Simpler, reuses existing proof infrastructure, no new proof types needed. The server just ignores the extra slot during tally.

### Worker Interface Update

```ts
type WorkerRequest = {
  type: 'encrypt-ballot'
  electionPubKey: string
  partyIndex: number        // 0..numParties (last = "don't support anyone")
  numParties: number
  candidateIndex: number    // -1 = no preference, 0..numCandidates-1 = preference
  numCandidates: number     // number of candidates in selected party (0 if blank vote)
}
```

### Encrypted Ballot Shape

```json
{
  "party_vector": ["hex_ct", ...],
  "candidate_vectors": [["hex_ct", ...]]
}
```

`candidate_vectors` contains one vector for the selected party. For "Не подкрепям никого", it's an empty array `[]`.

## Data Flow

```
Login (/)
  │
  ├─ click "Гласувай онлайн"
  │   → redirect to AUTH_URL/login?redirect_uri=ORIGIN/vote
  │   → auth redirects to /vote?token=JWT
  │
  ▼
Vote Flow (/vote)
  │
  ├─ mount: extract token, fetch election config
  │
  ├─ Step 1: select party or "Не подкрепям никого"
  │   ├─ party selected → Step 2
  │   └─ blank vote → Step 3
  │
  ├─ Step 2: select candidate or "Без предпочитание"
  │   └─ → Step 3
  │
  ├─ Step 3: confirm → encrypt in worker → submit to collection
  │   └─ → Done
  │
  └─ Done: show receipt, "Започни отначало" → /
```

## Component Structure

Split `App.tsx` into:

| File | Purpose |
|------|---------|
| `App.tsx` | Route switch (`/` vs `/vote`) |
| `LoginPage.tsx` | Ceremonial login page |
| `VoteFlow.tsx` | Voting flow state machine (steps 1-3 + done) |

Keep the state machine in `VoteFlow.tsx` but with cleaner phases:
- `loading` → `party` → `candidate` → `confirm` → `submitting` → `done`
- `error` (reachable from any phase)

## Files Changed

| File | Change |
|------|--------|
| `web/src/App.tsx` | Route switch, extract LoginPage |
| `web/src/LoginPage.tsx` | New — login page component |
| `web/src/VoteFlow.tsx` | New — voting flow with party/candidate/confirm phases |
| `web/src/crypto/worker.ts` | Add candidate vector encryption + proofs |
| `web/src/ballot/config.ts` | No change (already has candidates per party) |
| `web/src/ballot/submit.ts` | No change (already sends encrypted_ballot as-is) |
| `web/src/index.css` | Add candidate selection styles, "blank vote" option styles |

## Out of Scope

- Server-side candidate tally changes (bulletin board, tally service).
- Sum ≤ 1 proof variant (using approach A with virtual slot instead).
- Vite config for SPA fallback (dev server handles `/vote` fine; production deploy needs nginx/CDN config).
