import { useState, useEffect, useRef } from 'react'
import { fetchElectionConfig } from './ballot/config'
import { submitBallot, SessionExpiredError } from './ballot/submit'
import type { ElectionConfig } from './ballot/config'
import type { BallotReceipt } from './ballot/submit'
import type { WorkerRequest, WorkerResponse } from './crypto/worker'

// ---------------------------------------------------------------------------
// Configuration from environment (falls back to local dev defaults)
// ---------------------------------------------------------------------------

const BB_URL = (import.meta.env.VITE_BB_URL as string | undefined) ?? 'http://localhost:8080'
const COLLECTION_URL = (import.meta.env.VITE_COLLECTION_URL as string | undefined) ?? 'http://localhost:8083'

// ---------------------------------------------------------------------------
// State machine — discriminated union
// ---------------------------------------------------------------------------

interface BallotChoice {
  partyIndex: number
  partyName: string
}

interface EncryptedResult {
  ballotId: string
  encryptedBallot: object
  zkProofs: object
}

type AppState =
  | { phase: 'loading' }
  | { phase: 'auth' }
  | { phase: 'ballot'; config: ElectionConfig }
  | { phase: 'confirm'; config: ElectionConfig; choice: BallotChoice; encrypted: EncryptedResult | null }
  | { phase: 'submitting'; encrypted: EncryptedResult }
  | { phase: 'done'; receipt: BallotReceipt }
  | { phase: 'error'; message: string; recoverable: boolean }

// ---------------------------------------------------------------------------
// App component
// ---------------------------------------------------------------------------

export default function App() {
  const [state, setState] = useState<AppState>({ phase: 'loading' })

  // Tracks which party is highlighted in the ballot phase
  const [selectedPartyIndex, setSelectedPartyIndex] = useState<number | null>(null)

  // Carries the election config across the auth → ballot transition
  const electionConfigRef = useRef<ElectionConfig | null>(null)

  // Carries the party choice while in the ballot phase (before confirm)
  const pendingChoiceRef = useRef<BallotChoice | null>(null)

  // Single worker instance, created once on mount
  const workerRef = useRef<Worker | null>(null)

  // Create worker on mount, terminate on unmount
  useEffect(() => {
    workerRef.current = new Worker(
      new URL('./crypto/worker.ts', import.meta.url),
      { type: 'module' },
    )
    return () => {
      workerRef.current?.terminate()
      workerRef.current = null
    }
  }, [])

  // Fetch election config on mount
  useEffect(() => {
    let cancelled = false
    fetchElectionConfig(BB_URL)
      .then(config => {
        if (cancelled) return
        electionConfigRef.current = config
        setState({ phase: 'auth' })
      })
      .catch((err: unknown) => {
        if (cancelled) return
        setState({
          phase: 'error',
          message: err instanceof Error ? err.message : 'Грешка при зареждане на изборната конфигурация.',
          recoverable: true,
        })
      })
    return () => { cancelled = true }
  // Run once on mount only
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // When entering confirm phase, immediately start encryption in the worker.
  // Re-runs when partyIndex changes (user navigated back and chose again).
  useEffect(() => {
    if (state.phase !== 'confirm') return
    // Already have an encryption result for this confirm state — skip
    if (state.encrypted !== null) return

    const worker = workerRef.current
    const config = electionConfigRef.current
    if (!worker || !config) return

    const request: WorkerRequest = {
      type: 'encrypt-ballot',
      electionPubKey: config.publicKey,
      partyIndex: state.choice.partyIndex,
      numParties: config.parties.length,
    }

    const onMessage = (event: MessageEvent<WorkerResponse>) => {
      const response = event.data
      if (response.type === 'encrypt-result') {
        setState(prev => {
          if (prev.phase !== 'confirm') return prev
          return {
            ...prev,
            encrypted: {
              ballotId: response.ballotId,
              encryptedBallot: response.encryptedBallot,
              zkProofs: response.zkProofs,
            },
          }
        })
      } else {
        setState({
          phase: 'error',
          message: `Грешка при криптиране: ${response.message}`,
          recoverable: true,
        })
      }
      worker.removeEventListener('message', onMessage)
    }

    worker.addEventListener('message', onMessage)
    worker.postMessage(request)

    return () => {
      worker.removeEventListener('message', onMessage)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.phase, state.phase === 'confirm' ? state.choice.partyIndex : undefined])

  // ---------------------------------------------------------------------------
  // Event handlers
  // ---------------------------------------------------------------------------

  function handleAuth() {
    const config = electionConfigRef.current
    if (!config) {
      setState({ phase: 'error', message: 'Изборната конфигурация не е заредена.', recoverable: true })
      return
    }
    setState({ phase: 'ballot', config })
  }

  function handlePartySelect(partyIndex: number, partyName: string) {
    pendingChoiceRef.current = { partyIndex, partyName }
    setSelectedPartyIndex(partyIndex)
  }

  function handleConfirm(config: ElectionConfig, choice: BallotChoice) {
    setState({ phase: 'confirm', config, choice, encrypted: null })
  }

  async function handleSubmit(encrypted: EncryptedResult) {
    setState({ phase: 'submitting', encrypted })
    try {
      const receipt = await submitBallot(
        COLLECTION_URL,
        encrypted.ballotId,
        encrypted.encryptedBallot,
        encrypted.zkProofs,
      )
      setState({ phase: 'done', receipt })
    } catch (err) {
      const isSessionExpired = err instanceof SessionExpiredError
      setState({
        phase: 'error',
        message: err instanceof Error ? err.message : 'Грешка при подаване на бюлетината.',
        recoverable: !isSessionExpired,
      })
    }
  }

  function handleRetry() {
    setState({ phase: 'loading' })
    fetchElectionConfig(BB_URL)
      .then(config => {
        electionConfigRef.current = config
        setState({ phase: 'auth' })
      })
      .catch((err: unknown) => {
        setState({
          phase: 'error',
          message: err instanceof Error ? err.message : 'Грешка при зареждане на изборната конфигурация.',
          recoverable: true,
        })
      })
  }

  // ---------------------------------------------------------------------------
  // Render phases
  // ---------------------------------------------------------------------------

  if (state.phase === 'loading') {
    return (
      <div className="container">
        <h1>Отворен вот</h1>
        <p>Зарежда се изборната конфигурация…</p>
        <div className="spinner" aria-label="Зареждане" role="status" />
      </div>
    )
  }

  if (state.phase === 'error') {
    return (
      <div className="container">
        <h1>Грешка</h1>
        <p className="error-message" role="alert">{state.message}</p>
        {state.recoverable && (
          <button onClick={handleRetry} className="btn-primary">
            Опитай отново
          </button>
        )}
      </div>
    )
  }

  if (state.phase === 'auth') {
    return (
      <div className="container">
        <h1>Отворен вот</h1>
        <p>Система за електронно гласуване</p>
        <button onClick={handleAuth} className="btn-primary">
          Гласувай онлайн
        </button>
        <p className="note">Ще бъдете пренасочени към eAuth за удостоверяване</p>
      </div>
    )
  }

  if (state.phase === 'ballot') {
    const { config } = state
    return (
      <div className="container">
        <h1>Изберете партия</h1>
        <fieldset className="party-grid">
          <legend className="sr-only">Избор на партия</legend>
          {config.parties.map((party, i) => (
            <label
              key={i}
              className={`party-option ${selectedPartyIndex === i ? 'selected' : ''}`}
            >
              <input
                type="radio"
                name="party"
                value={String(i)}
                checked={selectedPartyIndex === i}
                onChange={() => handlePartySelect(i, party.name)}
              />
              {party.name}
            </label>
          ))}
        </fieldset>
        {selectedPartyIndex !== null && (
          <button
            onClick={() => {
              const choice = pendingChoiceRef.current
              if (choice) {
                setSelectedPartyIndex(null)
                pendingChoiceRef.current = null
                handleConfirm(config, choice)
              }
            }}
            className="btn-primary"
          >
            Потвърди избора
          </button>
        )}
      </div>
    )
  }

  if (state.phase === 'confirm') {
    const { config, choice, encrypted } = state
    const isEncrypting = encrypted === null

    return (
      <div className="container">
        <h1>Потвърждение</h1>
        <p className="choice-display">
          Вие избрахте: <strong>{choice.partyName}</strong>
        </p>
        {isEncrypting ? (
          <p className="encrypt-status" aria-live="polite">
            Генерира се криптирана бюлетина…
          </p>
        ) : (
          <p className="encrypt-status encrypt-status--ready" aria-live="polite">
            Бюлетината е криптирана.
          </p>
        )}
        <div className="actions">
          <button
            onClick={() => {
              if (!isEncrypting && encrypted) {
                void handleSubmit(encrypted)
              }
            }}
            disabled={isEncrypting}
            aria-busy={isEncrypting}
            className="btn-primary"
          >
            {isEncrypting ? 'Изчакайте…' : 'Подай глас'}
          </button>
          <button
            onClick={() => {
              setState({ phase: 'ballot', config })
              setSelectedPartyIndex(null)
            }}
            className="btn-secondary"
          >
            Промени избора
          </button>
        </div>
      </div>
    )
  }

  if (state.phase === 'submitting') {
    return (
      <div className="container">
        <h1>Подаване на бюлетина…</h1>
        <div className="spinner" aria-label="Подаване" role="status" />
      </div>
    )
  }

  // phase === 'done'
  const { receipt } = state
  return (
    <div className="container">
      <h1>Гласът ви е записан</h1>
      {receipt.isOverride && (
        <p className="override-notice" role="status">
          Бюлетината е записана като замяна на предишен глас.
        </p>
      )}
      <p>Идентификатор на бюлетина:</p>
      <code className="ballot-id">{receipt.ballotId}</code>
      <p>Позиция в регистъра: <strong>{receipt.position}</strong></p>
      <p>Корен на Меркъл дървото:</p>
      <code className="ballot-id">{receipt.merkleRoot}</code>
      <p className="note">
        Запазете този идентификатор, за да проверите включването на бюлетината
        на verify.izbori.bg
      </p>
    </div>
  )
}
