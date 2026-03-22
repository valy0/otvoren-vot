# Voting Flow Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the voter web app into two routes (`/` login, `/vote` voting flow), add "Не подкрепям никого" blank vote option, and add optional candidate preference step.

**Architecture:** Route-based split using `window.location.pathname`. Login page (`/`) clears session on mount. Voting flow (`/vote`) is a state machine with phases: `loading → party → candidate → confirm → submitting → done`. Crypto extended with candidate vector encryption using virtual "no preference" slot for sum-one proof reuse.

**Tech Stack:** React 19 + TypeScript strict, libsodium-wrappers-sumo (WASM), Vite, vitest

**Spec:** `docs/superpowers/specs/2026-03-22-voting-flow-redesign.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `web/src/App.tsx` | Rewrite | Route switch only (`/` → LoginPage, `/vote` → VoteFlow) |
| `web/src/LoginPage.tsx` | Create | Ceremonial login page, clears session on mount |
| `web/src/VoteFlow.tsx` | Create | Full voting state machine: party → candidate → confirm → done |
| `web/src/crypto/worker.ts` | Modify | Accept `candidateIndex`/`numCandidates`, encrypt candidate vector |
| `web/src/crypto/__tests__/proofs.test.ts` | Modify | Add candidate vector encryption + proof tests |
| `web/src/index.css` | Modify | Add candidate selection styles, blank vote option styling |

Files NOT changed: `ballot/config.ts`, `ballot/submit.ts`, `crypto/elgamal.ts`, `crypto/proofs.ts`, `crypto/fiatShamir.ts`, `main.tsx`.

---

### Task 1: Extract LoginPage Component

**Files:**
- Create: `web/src/LoginPage.tsx`
- Modify: `web/src/App.tsx`

- [ ] **Step 1: Create LoginPage.tsx**

Extract the login page JSX from `App.tsx` (the `state.phase === 'auth'` block, lines 367-408) into its own component. Add session clearing on mount.

```tsx
// web/src/LoginPage.tsx
import { useEffect } from 'react'

const AUTH_URL = (import.meta.env.VITE_AUTH_URL as string | undefined) ?? 'http://localhost:8082'

export default function LoginPage() {
  // Clear any existing session on mount — every visit to / is a clean slate
  useEffect(() => {
    sessionStorage.removeItem('authToken')
  }, [])

  function handleAuth() {
    window.location.href = `${AUTH_URL}/login?redirect_uri=${encodeURIComponent(window.location.origin + '/vote')}`
  }

  return (
    <div className="login-page">
      <div className="login-flag" aria-hidden="true">
        <div className="login-flag__band login-flag__band--white" />
        <div className="login-flag__band login-flag__band--green" />
        <div className="login-flag__band login-flag__band--red" />
      </div>

      <main className="login-main">
        <div className="login-hero">
          <img
            src="/coat-of-arms.png"
            alt="Герб на Република България"
            className="login-coat"
          />
          <h2 className="login-country">Република България</h2>
        </div>

        <div className="login-card">
          <h1 className="login-title">Електронно гласуване</h1>
          <p className="login-subtitle">
            Система за сигурно и проверимо електронно гласуване
          </p>

          <button onClick={handleAuth} className="login-btn">
            Гласувай онлайн
          </button>

          <div className="login-footer">
            <div className="login-footer__divider" />
            <p className="login-footer__note">
              Ще бъдете пренасочени към eAuth за удостоверяване на самоличността
            </p>
            <p className="login-footer__brand">Отворен Вот</p>
          </div>
        </div>
      </main>
    </div>
  )
}
```

Note the redirect URI change: `window.location.origin + '/vote'` instead of just `window.location.origin`.

- [ ] **Step 2: Rewrite App.tsx as route switch**

Replace the entire `App.tsx` with a simple route switch:

```tsx
// web/src/App.tsx
import LoginPage from './LoginPage'
import VoteFlow from './VoteFlow'

export default function App() {
  const path = window.location.pathname
  if (path === '/vote') return <VoteFlow />
  return <LoginPage />
}
```

- [ ] **Step 3: Create stub VoteFlow.tsx**

Create a minimal VoteFlow that shows the current ballot flow (copy all non-login logic from the old App.tsx). This is a pure extraction — no new features yet.

The component should:
- Extract token from URL params on mount (same as current App.tsx lines 102-150)
- Redirect to `/` if no token found
- Contain all the current state machine phases except `auth`
- Update `handleAuth` redirect to go to `/` instead of auth service directly
- Update "Започни отначало" to `window.location.href = '/'`
- Update `SessionExpiredError` handling to redirect to `/`

- [ ] **Step 4: Verify login → vote flow works**

Run: `npx vite --port 5173`
Test: Navigate to `http://localhost:5173/`, click "Гласувай онлайн", verify redirect to auth service with `redirect_uri=http://localhost:5173/vote`.

- [ ] **Step 5: Commit**

```bash
git add web/src/App.tsx web/src/LoginPage.tsx web/src/VoteFlow.tsx
git commit -m "refactor(web): split app into LoginPage and VoteFlow route components"
```

---

### Task 2: Add "Не подкрепям никого" Option

**Files:**
- Modify: `web/src/VoteFlow.tsx`
- Modify: `web/src/index.css`

- [ ] **Step 1: Add blank vote option to party selection**

In `VoteFlow.tsx`, after the party list in the `party` phase, add a "Не подкрепям никого" option. It uses `partyIndex = config.parties.length` (one past the last real party — the virtual slot).

After the `config.parties.map(...)` loop inside the `<fieldset>`, add:

```tsx
{/* Separator */}
<div className="ballot-separator" aria-hidden="true" />

{/* Blank vote option */}
<label
  className={`ballot-option ballot-option--blank ${selectedPartyIndex === config.parties.length ? 'ballot-option--selected' : ''}`}
>
  <input
    type="radio"
    name="party"
    value="blank"
    checked={selectedPartyIndex === config.parties.length}
    onChange={() => handlePartySelect(config.parties.length, 'Не подкрепям никого')}
  />
  <span className="ballot-option__indicator">
    <span className="ballot-option__radio" />
  </span>
  <span className="ballot-option__content">
    <span className="ballot-option__name">Не подкрепям никого</span>
  </span>
</label>
```

- [ ] **Step 2: Add CSS for blank vote option and separator**

Add to `web/src/index.css`:

```css
/* Ballot separator */
.ballot-separator {
  height: 1px;
  background: var(--border-light);
  margin: 0.5rem 0;
}

/* Blank vote option — distinct styling */
.ballot-option--blank .ballot-option__name {
  font-style: italic;
  color: var(--text-dim);
}

.ballot-option--blank.ballot-option--selected .ballot-option__name {
  color: var(--navy);
  font-style: italic;
}
```

- [ ] **Step 3: Verify blank vote displays and is selectable**

Run dev server, navigate to `/vote?token=test`, verify "Не подкрепям никого" appears below a separator, can be selected, shows green state.

- [ ] **Step 4: Commit**

```bash
git add web/src/VoteFlow.tsx web/src/index.css
git commit -m "feat(web): add 'Не подкрепям никого' blank vote option to party selection"
```

---

### Task 3: Add Candidate Preference Step (UI)

**Files:**
- Modify: `web/src/VoteFlow.tsx`
- Modify: `web/src/index.css`

- [ ] **Step 1: Update state machine types**

In `VoteFlow.tsx`, update the types:

```tsx
interface BallotChoice {
  partyIndex: number
  partyName: string
  candidateIndex: number  // -1 = no preference
  candidateName: string   // '' = no preference
}

type VoteState =
  | { phase: 'loading' }
  | { phase: 'party'; config: ElectionConfig }
  | { phase: 'candidate'; config: ElectionConfig; partyIndex: number; partyName: string }
  | { phase: 'confirm'; config: ElectionConfig; choice: BallotChoice; encrypted: EncryptedResult | null }
  | { phase: 'submitting'; encrypted: EncryptedResult }
  | { phase: 'done'; receipt: BallotReceipt }
  | { phase: 'error'; message: string; recoverable: boolean }
```

- [ ] **Step 2: Update progress steps**

```tsx
const STEPS = [
  { key: 'party', label: 'Партия' },
  { key: 'candidate', label: 'Кандидат' },
  { key: 'confirm', label: 'Потвърждение' },
] as const

function getStepIndex(phase: VoteState['phase']): number {
  switch (phase) {
    case 'loading':
    case 'party':
      return 0
    case 'candidate':
      return 1
    case 'confirm':
    case 'submitting':
      return 2
    case 'done':
      return 99
    case 'error':
      return -1
  }
}
```

- [ ] **Step 3: Update party selection to route to candidate step**

When a party is selected and confirmed:
- If `partyIndex === config.parties.length` (blank vote): skip candidate, go to confirm with `candidateIndex: -1`
- Otherwise: go to `candidate` phase

Replace the confirm button handler in the party phase:

```tsx
onClick={() => {
  const choice = pendingChoiceRef.current
  if (choice) {
    setSelectedPartyIndex(null)
    pendingChoiceRef.current = null
    const isBlankVote = choice.partyIndex === config.parties.length
    if (isBlankVote) {
      // Skip candidate step
      setState({
        phase: 'confirm',
        config,
        choice: { ...choice, candidateIndex: -1, candidateName: '' },
        encrypted: null,
      })
    } else {
      setState({
        phase: 'candidate',
        config,
        partyIndex: choice.partyIndex,
        partyName: choice.partyName,
      })
    }
  }
}}
```

- [ ] **Step 4: Add candidate selection phase render**

Add a new render block for `state.phase === 'candidate'`:

```tsx
if (state.phase === 'candidate') {
  const { config, partyIndex, partyName } = state
  const party = config.parties[partyIndex]
  const isNoPref = selectedCandidateIndex === -1

  return (
    <div className="vote-shell">
      {renderHeader()}
      {renderSteps()}
      <div className="vote-content">
        <main className="vote-container">
          <div className="vote-card">
            <div className="vote-card__header">
              <div className="vote-card__step-badge">Стъпка 2</div>
              <h1>Предпочитание за кандидат</h1>
              <p>Изберете кандидат от листата на <strong>{partyName}</strong> или продължете без предпочитание</p>
            </div>
            <fieldset className="ballot-grid">
              <legend className="sr-only">Избор на кандидат</legend>

              {/* No preference option — always first */}
              <label className={`ballot-option ballot-option--blank ${isNoPref ? 'ballot-option--selected' : ''}`}>
                <input
                  type="radio"
                  name="candidate"
                  value="-1"
                  checked={isNoPref}
                  onChange={() => setSelectedCandidateIndex(-1)}
                />
                <span className="ballot-option__indicator">
                  <span className="ballot-option__radio" />
                </span>
                <span className="ballot-option__content">
                  <span className="ballot-option__name">Без предпочитание</span>
                </span>
              </label>

              <div className="ballot-separator" aria-hidden="true" />

              {party.candidates.map((name, i) => (
                <label
                  key={i}
                  className={`ballot-option ${selectedCandidateIndex === i ? 'ballot-option--selected' : ''}`}
                >
                  <input
                    type="radio"
                    name="candidate"
                    value={String(i)}
                    checked={selectedCandidateIndex === i}
                    onChange={() => setSelectedCandidateIndex(i)}
                  />
                  <span className="ballot-option__indicator">
                    <span className="ballot-option__radio" />
                  </span>
                  <span className="ballot-option__content">
                    <span className="ballot-option__number">{i + 1}</span>
                    <span className="ballot-option__name">{name}</span>
                  </span>
                </label>
              ))}
            </fieldset>

            {selectedCandidateIndex !== null && (
              <button
                onClick={() => {
                  const candIdx = selectedCandidateIndex
                  const candName = candIdx === -1 ? '' : party.candidates[candIdx]
                  setSelectedCandidateIndex(null)
                  setState({
                    phase: 'confirm',
                    config,
                    choice: {
                      partyIndex,
                      partyName,
                      candidateIndex: candIdx,
                      candidateName: candName,
                    },
                    encrypted: null,
                  })
                }}
                className="vote-btn vote-btn--primary"
              >
                Продължи
              </button>
            )}
            <button
              onClick={() => {
                setSelectedCandidateIndex(null)
                setState({ phase: 'party', config })
              }}
              className="vote-btn vote-btn--secondary"
            >
              Назад
            </button>
          </div>
        </main>
      </div>
    </div>
  )
}
```

- [ ] **Step 5: Add `selectedCandidateIndex` state**

At the top of VoteFlow, add:

```tsx
const [selectedCandidateIndex, setSelectedCandidateIndex] = useState<number | null>(null)
```

- [ ] **Step 6: Update confirmation phase to show candidate choice**

In the confirm phase render, update the choice summary:

```tsx
<div className="confirm-choice__body">
  <div className="confirm-choice__label">Вашият избор</div>
  <div className="confirm-choice__party">{choice.partyName}</div>
  {choice.candidateName && (
    <div className="confirm-choice__candidate">
      Предпочитание: {choice.candidateName}
    </div>
  )}
  {choice.partyIndex < config.parties.length && !choice.candidateName && (
    <div className="confirm-choice__candidate confirm-choice__candidate--none">
      Без предпочитание за кандидат
    </div>
  )}
</div>
```

- [ ] **Step 7: Add CSS for candidate choice in confirmation**

```css
.confirm-choice__candidate {
  font-size: 0.9375rem;
  color: var(--navy);
  margin-top: 0.25rem;
}

.confirm-choice__candidate--none {
  color: var(--text-dim);
  font-style: italic;
}
```

- [ ] **Step 8: Update "Промени избора" to go back to party step**

In the confirm phase, update the back button to go to `party` phase and clear candidate selection:

```tsx
onClick={() => {
  setState({ phase: 'party', config })
  setSelectedPartyIndex(null)
  setSelectedCandidateIndex(null)
}}
```

- [ ] **Step 9: Verify the full 3-step UI flow**

Test manually:
1. Select a party → candidate step appears
2. Select "Без предпочитание" → confirm shows party without candidate
3. Select a candidate → confirm shows party + candidate
4. "Назад" from candidate → returns to party
5. Select "Не подкрепям никого" → skips to confirm directly
6. "Промени избора" from confirm → returns to party

- [ ] **Step 10: Commit**

```bash
git add web/src/VoteFlow.tsx web/src/index.css
git commit -m "feat(web): add candidate preference step with 'Без предпочитание' option"
```

---

### Task 4: Update Crypto Worker for Candidate Vector

**Files:**
- Modify: `web/src/crypto/worker.ts`
- Modify: `web/src/crypto/__tests__/proofs.test.ts`

- [ ] **Step 1: Write tests for candidate vector encryption**

Add to `web/src/crypto/__tests__/proofs.test.ts`:

```ts
describe('candidate vector encryption', () => {
  it('encrypts candidate preference as one-hot vector with virtual no-preference slot', async () => {
    // Simulates what the worker does for candidate encryption
    const { pk } = makeKeyPair()
    const numCandidates = 3
    const candidateIndex = 1 // second candidate
    const vectorLength = numCandidates + 1 // +1 for "no preference" virtual slot

    const encResults = Array.from({ length: vectorLength }, (_, i) => {
      // candidateIndex maps to vector position, last slot = "no preference"
      const selected = i === candidateIndex
      return encrypt(selected ? 1 : 0, pk)
    })

    // Binary proofs
    for (let i = 0; i < vectorLength; i++) {
      const bit = (i === candidateIndex ? 1 : 0) as 0 | 1
      const proof = proveBinary(bit, encResults[i].randomness, pk, encResults[i].ciphertext)
      expect(verifyBinary(pk, encResults[i].ciphertext, proof)).toBe(true)
    }

    // Sum-one proof (exactly one selected)
    const cts = encResults.map(r => r.ciphertext)
    const sodium = getSodium()
    let rSum = encResults[0].randomness
    for (let i = 1; i < encResults.length; i++) {
      rSum = sodium.crypto_core_ristretto255_scalar_add(rSum, encResults[i].randomness)
    }
    const sumProof = proveSumOne(cts, rSum, pk)
    expect(verifySumOne(pk, cts, sumProof)).toBe(true)
  })

  it('encrypts no-preference as last slot selected in candidate vector', async () => {
    const { pk } = makeKeyPair()
    const numCandidates = 3
    const candidateIndex = -1 // no preference → last slot
    const vectorLength = numCandidates + 1
    const activeIndex = vectorLength - 1 // "no preference" virtual slot

    const encResults = Array.from({ length: vectorLength }, (_, i) => {
      return encrypt(i === activeIndex ? 1 : 0, pk)
    })

    const cts = encResults.map(r => r.ciphertext)
    const sodium = getSodium()
    let rSum = encResults[0].randomness
    for (let i = 1; i < encResults.length; i++) {
      rSum = sodium.crypto_core_ristretto255_scalar_add(rSum, encResults[i].randomness)
    }
    const sumProof = proveSumOne(cts, rSum, pk)
    expect(verifySumOne(pk, cts, sumProof)).toBe(true)
  })
})
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cd web && npx vitest run src/crypto/__tests__/proofs.test.ts`
Expected: All tests PASS (these test the existing crypto primitives with candidate-shaped data).

- [ ] **Step 3: Update WorkerRequest type**

In `web/src/crypto/worker.ts`, update the request type:

```ts
export type WorkerRequest = {
  type: 'encrypt-ballot'
  electionPubKey: string
  partyIndex: number      // 0..numParties (last = blank vote)
  numParties: number
  candidateIndex: number  // -1 = no preference, 0..numCandidates-1 = preference
  numCandidates: number   // 0 if blank vote
}
```

- [ ] **Step 4: Add candidate vector encryption to worker**

In the worker's `onmessage` handler, after Step 6 (sum proof for party vector), add candidate vector encryption:

```ts
// Step 7: Build candidate vector (if not blank vote)
let candidateVector: string[] = []
let candidateBinaryProofs: SerializedBinaryProof[] = []
let candidateSumProof: SerializedSumOneProof | null = null

if (req.numCandidates > 0) {
  // Vector length = numCandidates + 1 (last slot = "no preference")
  const candVectorLen = req.numCandidates + 1
  // -1 means no preference → select last slot
  const activeSlot = req.candidateIndex === -1 ? candVectorLen - 1 : req.candidateIndex

  const candEncResults = Array.from({ length: candVectorLen }, (_, i) =>
    encrypt(i === activeSlot ? 1 : 0, pubKey)
  )

  // Binary proofs for each candidate element
  const candBinaryRaw = candEncResults.map((res, i) =>
    proveBinary(i === activeSlot ? 1 : 0, res.randomness, pubKey, res.ciphertext)
  )

  // Sum-one proof for candidate vector
  const candRandomness = candEncResults.map(r => r.randomness)
  let candRSum = candRandomness[0]
  for (let i = 1; i < candRandomness.length; i++) {
    candRSum = sodium.crypto_core_ristretto255_scalar_add(candRSum, candRandomness[i])
  }
  const candCts = candEncResults.map(r => r.ciphertext)
  const candSumProofRaw = proveSumOne(candCts, candRSum, pubKey)

  // Zero randomness
  for (const r of candRandomness) { sodium.memzero(r) }
  sodium.memzero(candRSum)

  // Serialize
  candidateVector = candCts.map(ct => serializeCiphertext(ct))
  candidateBinaryProofs = candBinaryRaw.map(serializeBinaryProof)
  candidateSumProof = serializeSumOneProof(candSumProofRaw)
}
```

- [ ] **Step 5: Update the response to include candidate data**

Update the response construction:

```ts
const response: WorkerResponse = {
  type: 'encrypt-result',
  ballotId,
  encryptedBallot: {
    party_vector: partyVector,
    candidate_vectors: candidateVector.length > 0 ? [candidateVector] : [],
  },
  zkProofs: {
    binary_party: serializedBinaryProofs,
    sum_one: serializedSumProof,
    binary_candidate: candidateBinaryProofs.length > 0 ? candidateBinaryProofs : undefined,
    sum_one_candidate: candidateSumProof ?? undefined,
  },
}
```

Update `WorkerResponse` type to match:

```ts
export type WorkerResponse =
  | {
      type: 'encrypt-result'
      ballotId: string
      encryptedBallot: { party_vector: string[]; candidate_vectors: string[][] }
      zkProofs: {
        binary_party: SerializedBinaryProof[]
        sum_one: SerializedSumOneProof
        binary_candidate?: SerializedBinaryProof[]
        sum_one_candidate?: SerializedSumOneProof
      }
    }
  | {
      type: 'encrypt-error'
      message: string
    }
```

- [ ] **Step 6: Update party vector to include blank vote slot**

In the worker, the party vector now has `numParties + 1` elements. Update the validation and vector construction:

```ts
// partyIndex range is now 0..numParties (inclusive; last = blank vote)
if (partyIndex < 0 || partyIndex > numParties) {
  throw new Error(`partyIndex ${partyIndex} out of range [0, ${numParties}]`)
}

const partyVectorLen = numParties + 1  // +1 for blank vote slot
const encResults = Array.from({ length: partyVectorLen }, (_, i) =>
  encrypt(i === partyIndex ? 1 : 0, pubKey)
)
```

Update binary proofs and sum proof loops to use `partyVectorLen` instead of `numParties`.

- [ ] **Step 7: Run all crypto tests**

Run: `cd web && npx vitest run`
Expected: All tests PASS.

- [ ] **Step 8: Commit**

```bash
git add web/src/crypto/worker.ts web/src/crypto/__tests__/proofs.test.ts
git commit -m "feat(web): extend crypto worker with candidate vector encryption and blank vote slot"
```

---

### Task 5: Wire Crypto to VoteFlow

**Files:**
- Modify: `web/src/VoteFlow.tsx`

- [ ] **Step 1: Update WorkerRequest construction in confirm phase**

In VoteFlow's `useEffect` for the confirm phase, update the worker request:

```tsx
const request: WorkerRequest = {
  type: 'encrypt-ballot',
  electionPubKey: config.publicKey,
  partyIndex: state.choice.partyIndex,
  numParties: config.parties.length,
  candidateIndex: state.choice.candidateIndex,
  numCandidates: state.choice.partyIndex < config.parties.length
    ? config.parties[state.choice.partyIndex].candidates.length
    : 0,
}
```

- [ ] **Step 2: Test full end-to-end flow**

Run dev server and Docker backend. Test:
1. Login → select party → select candidate → confirm → submit → receipt
2. Login → select "Не подкрепям никого" → confirm → submit → receipt
3. Login → select party → "Без предпочитание" → confirm → submit → receipt

- [ ] **Step 3: Commit**

```bash
git add web/src/VoteFlow.tsx
git commit -m "feat(web): wire candidate and blank vote to crypto worker in VoteFlow"
```

---

### Task 6: Final Cleanup

**Files:**
- Modify: `web/src/VoteFlow.tsx`

- [ ] **Step 1: Update step badges**

In VoteFlow, update the step badge text:
- Party phase: `Стъпка 1` (was `Стъпка 2`)
- Candidate phase: `Стъпка 2`
- Confirm phase: `Стъпка 3`

- [ ] **Step 2: Remove dead code from old App.tsx**

Verify no old state types, handlers, or CSS classes remain unused. Remove any leftover `app-shell`, `app-header`, `card`, `btn-primary`, `party-option`, etc. CSS classes that are no longer referenced.

- [ ] **Step 3: Run full test suite**

Run: `cd web && npx vitest run`
Expected: All tests PASS.

- [ ] **Step 4: Commit**

```bash
git add -A web/src/
git commit -m "chore(web): clean up step labels and remove dead code from routing refactor"
```
