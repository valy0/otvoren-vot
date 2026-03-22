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
  candidateIndex: number   // -1 = no preference
  candidateName: string    // '' = no preference
}

interface EncryptedResult {
  ballotId: string
  encryptedBallot: object
  zkProofs: object
}

type AppState =
  | { phase: 'loading' }
  | { phase: 'party'; config: ElectionConfig }
  | { phase: 'candidate'; config: ElectionConfig; partyIndex: number; partyName: string }
  | { phase: 'confirm'; config: ElectionConfig; choice: BallotChoice; encrypted: EncryptedResult | null }
  | { phase: 'submitting'; encrypted: EncryptedResult }
  | { phase: 'done'; receipt: BallotReceipt }
  | { phase: 'error'; message: string; recoverable: boolean }

// ---------------------------------------------------------------------------
// Step indicator helpers
// ---------------------------------------------------------------------------

const STEPS = [
  { key: 'party', label: 'Партия' },
  { key: 'candidate', label: 'Кандидат' },
  { key: 'confirm', label: 'Потвърждение' },
] as const

function getStepIndex(phase: AppState['phase']): number {
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

// ---------------------------------------------------------------------------
// VoteFlow component — all voting logic after authentication
// ---------------------------------------------------------------------------

export default function VoteFlow() {
  const [state, setState] = useState<AppState>({ phase: 'loading' })

  // Tracks which party is highlighted in the party phase
  const [selectedPartyIndex, setSelectedPartyIndex] = useState<number | null>(null)

  // Tracks which candidate is highlighted in the candidate phase
  const [selectedCandidateIndex, setSelectedCandidateIndex] = useState<number | null>(null)

  // JWT token received from auth redirect
  const [authToken, setAuthToken] = useState<string | null>(null)

  // Carries the election config across transitions
  const electionConfigRef = useRef<ElectionConfig | null>(null)

  // Carries the party choice while in the party phase (before confirm)
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

  // On mount: extract token from URL ?token= param or sessionStorage.
  // If no token is found, redirect back to the login page.
  useEffect(() => {
    let cancelled = false

    // Extract auth token from URL (redirect from auth service) or sessionStorage
    // (survives React StrictMode double-mount which cleans the URL on first run).
    const params = new URLSearchParams(window.location.search)
    let token = params.get('token')
    if (token) {
      sessionStorage.setItem('authToken', token)
      setAuthToken(token)
      params.delete('token')
      const newSearch = params.toString()
      const newUrl = window.location.pathname + (newSearch ? `?${newSearch}` : '') + window.location.hash
      history.replaceState(null, '', newUrl)
    } else {
      token = sessionStorage.getItem('authToken')
      if (token) {
        setAuthToken(token)
      }
    }

    // No token found anywhere — redirect to login page
    if (!token) {
      window.location.href = '/'
      return
    }

    const loadConfig = async () => {
      try {
        const config = await fetchElectionConfig(BB_URL)
        if (cancelled) return
        electionConfigRef.current = config
        setState({ phase: 'party', config })
      } catch (err: unknown) {
        if (cancelled) return
        setState({
          phase: 'error',
          message: err instanceof Error ? err.message : 'Грешка при зареждане на изборната конфигурация.',
          recoverable: true,
        })
      }
    }

    void loadConfig()
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

    const requestId = crypto.randomUUID()

    const request: WorkerRequest = {
      type: 'encrypt-ballot',
      electionPubKey: config.publicKey,
      partyIndex: state.choice.partyIndex,
      numParties: config.parties.length,
      candidateIndex: state.choice.candidateIndex,
      numCandidates: state.choice.partyIndex < config.parties.length
        ? config.parties[state.choice.partyIndex].candidates.length
        : 0,
      requestId,
    }

    const onMessage = (event: MessageEvent<WorkerResponse>) => {
      const response = event.data
      // Ignore stale responses from previous encryption jobs
      if ('requestId' in response && response.requestId !== requestId) return
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
  }, [state.phase, state.phase === 'confirm' ? state.choice.partyIndex : undefined, state.phase === 'confirm' ? state.choice.candidateIndex : undefined])

  // ---------------------------------------------------------------------------
  // Event handlers
  // ---------------------------------------------------------------------------

  function handlePartySelect(partyIndex: number, partyName: string) {
    pendingChoiceRef.current = { partyIndex, partyName, candidateIndex: -1, candidateName: '' }
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
        authToken ?? undefined,
      )
      setState({ phase: 'done', receipt })
    } catch (err) {
      if (err instanceof SessionExpiredError) {
        // Session expired — redirect to login page for re-authentication
        window.location.href = '/'
        return
      }
      setState({
        phase: 'error',
        message: err instanceof Error ? err.message : 'Грешка при подаване на бюлетината.',
        recoverable: false,
      })
    }
  }

  function handleRetry() {
    setState({ phase: 'loading' })
    fetchElectionConfig(BB_URL)
      .then(config => {
        electionConfigRef.current = config
        setState({ phase: 'party', config })
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
  // Render helpers
  // ---------------------------------------------------------------------------

  const currentStep = getStepIndex(state.phase)

  function renderHeader() {
    return (
      <header className="vote-header" role="banner">
        <div className="vote-header__inner">
          <img
            src="/coat-of-arms.png"
            alt="Герб на Република България"
            className="vote-header__coat"
          />
          <div className="vote-header__text">
            <span className="vote-header__brand">Отворен Вот</span>
            <span className="vote-header__country">Република България</span>
          </div>
        </div>
        <div className="vote-header__tricolor" aria-hidden="true">
          <span className="vote-header__band vote-header__band--white" />
          <span className="vote-header__band vote-header__band--green" />
          <span className="vote-header__band vote-header__band--red" />
        </div>
      </header>
    )
  }

  function renderSteps() {
    return (
      <nav className="vote-steps" aria-label="Стъпки на гласуване">
        <div className="vote-steps__track">
          {STEPS.map((step, i) => {
            let stepClass = 'vote-step'
            if (i === currentStep) stepClass += ' vote-step--active'
            else if (i < currentStep) stepClass += ' vote-step--done'

            return (
              <span key={step.key} style={{ display: 'contents' }}>
                {i > 0 && <span className="vote-step__line" aria-hidden="true" />}
                <span className={stepClass} aria-current={i === currentStep ? 'step' : undefined}>
                  <span className="vote-step__number">
                    {i < currentStep ? '\u2713' : i + 1}
                  </span>
                  <span className="vote-step__label">{step.label}</span>
                </span>
              </span>
            )
          })}
        </div>
      </nav>
    )
  }

  // ---------------------------------------------------------------------------
  // Render phases
  // ---------------------------------------------------------------------------

  if (state.phase === 'loading') {
    return (
      <div className="vote-shell">
        {renderHeader()}
        {renderSteps()}
        <div className="vote-content">
          <main className="vote-container">
            <div className="vote-card">
              <div className="vote-card__header">
                <h1>Отворен вот</h1>
                <p>Зарежда се изборната конфигурация...</p>
              </div>
              <div className="vote-spinner" aria-label="Зареждане" role="status">
                <div className="vote-spinner__ring" />
              </div>
              <p className="vote-spinner__text">Моля, изчакайте</p>
            </div>
          </main>
        </div>
      </div>
    )
  }

  if (state.phase === 'error') {
    return (
      <div className="vote-shell">
        {renderHeader()}
        <div className="vote-content">
          <main className="vote-container">
            <div className="vote-card vote-card--error">
              <div className="vote-error-icon" aria-hidden="true" />
              <div className="vote-card__header">
                <h1>Грешка</h1>
                <p role="alert">{state.message}</p>
              </div>
              {state.recoverable && (
                <button onClick={handleRetry} className="vote-btn vote-btn--primary">
                  Опитай отново
                </button>
              )}
            </div>
          </main>
        </div>
      </div>
    )
  }

  if (state.phase === 'party') {
    const { config } = state
    const blankIndex = config.parties.length
    return (
      <div className="vote-shell">
        {renderHeader()}
        {renderSteps()}
        <div className="vote-content">
          <main className="vote-container">
            <div className="vote-card">
              <div className="vote-card__header">
                <div className="vote-card__step-badge">Стъпка 1</div>
                <h1>Изберете партия</h1>
                <p>Маркирайте вашия избор от списъка по-долу</p>
              </div>
              <fieldset className="ballot-grid">
                <legend className="sr-only">Избор на партия</legend>
                {config.parties.map((party, i) => (
                  <label
                    key={i}
                    className={`ballot-option ${selectedPartyIndex === i ? 'ballot-option--selected' : ''}`}
                  >
                    <input
                      type="radio"
                      name="party"
                      value={String(i)}
                      checked={selectedPartyIndex === i}
                      onChange={() => handlePartySelect(i, party.name)}
                    />
                    <span className="ballot-option__indicator">
                      <span className="ballot-option__radio" />
                    </span>
                    <span className="ballot-option__content">
                      <span className="ballot-option__number">{i + 1}</span>
                      <span className="ballot-option__name">{party.name}</span>
                      {party.candidates.length > 0 && (
                        <span className="ballot-option__candidates">
                          {party.candidates.join(', ')}
                        </span>
                      )}
                    </span>
                  </label>
                ))}
                <div className="ballot-separator" aria-hidden="true" />
                <label
                  className={`ballot-option ballot-option--blank ${selectedPartyIndex === blankIndex ? 'ballot-option--selected' : ''}`}
                >
                  <input
                    type="radio"
                    name="party"
                    value={String(blankIndex)}
                    checked={selectedPartyIndex === blankIndex}
                    onChange={() => handlePartySelect(blankIndex, 'Не подкрепям никого')}
                  />
                  <span className="ballot-option__indicator">
                    <span className="ballot-option__radio" />
                  </span>
                  <span className="ballot-option__content">
                    <span className="ballot-option__name">Не подкрепям никого</span>
                  </span>
                </label>
              </fieldset>
              {selectedPartyIndex !== null && (
                <button
                  onClick={() => {
                    const choice = pendingChoiceRef.current
                    if (choice) {
                      const isBlank = choice.partyIndex === config.parties.length
                      if (isBlank) {
                        // Blank vote — skip candidate step, go directly to confirm
                        setSelectedPartyIndex(null)
                        pendingChoiceRef.current = null
                        handleConfirm(config, {
                          ...choice,
                          candidateIndex: -1,
                          candidateName: '',
                        })
                      } else {
                        // Real party — go to candidate selection
                        setSelectedPartyIndex(null)
                        setSelectedCandidateIndex(null)
                        pendingChoiceRef.current = null
                        setState({
                          phase: 'candidate',
                          config,
                          partyIndex: choice.partyIndex,
                          partyName: choice.partyName,
                        })
                      }
                    }
                  }}
                  className="vote-btn vote-btn--primary"
                >
                  Продължи
                </button>
              )}
            </div>
          </main>
        </div>
      </div>
    )
  }

  if (state.phase === 'candidate') {
    const { config, partyIndex, partyName } = state
    const candidates = config.parties[partyIndex].candidates
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
                <p>
                  Изберете кандидат от листата на <strong>{partyName}</strong> или продължете без предпочитание
                </p>
              </div>
              <fieldset className="ballot-grid">
                <legend className="sr-only">Избор на кандидат</legend>
                <label
                  className={`ballot-option ballot-option--blank ${selectedCandidateIndex === -1 ? 'ballot-option--selected' : ''}`}
                >
                  <input
                    type="radio"
                    name="candidate"
                    value="-1"
                    checked={selectedCandidateIndex === -1}
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
                {candidates.map((candidate, i) => (
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
                      <span className="ballot-option__name">{candidate}</span>
                    </span>
                  </label>
                ))}
              </fieldset>
              {selectedCandidateIndex !== null && (
                <button
                  onClick={() => {
                    const candidateIdx = selectedCandidateIndex
                    const candidateName = candidateIdx === -1 ? '' : candidates[candidateIdx]
                    setSelectedCandidateIndex(null)
                    handleConfirm(config, {
                      partyIndex,
                      partyName,
                      candidateIndex: candidateIdx,
                      candidateName,
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

  if (state.phase === 'confirm') {
    const { config, choice, encrypted } = state
    const isEncrypting = encrypted === null
    const isBlankVote = choice.partyIndex === config.parties.length
    const selectedParty = isBlankVote ? undefined : config.parties[choice.partyIndex]

    return (
      <div className="vote-shell">
        {renderHeader()}
        {renderSteps()}
        <div className="vote-content">
          <main className="vote-container">
            <div className="vote-card">
              <div className="vote-card__header">
                <div className="vote-card__step-badge">Стъпка 3</div>
                <h1>Потвърждение</h1>
                <p>Прегледайте и потвърдете вашия избор</p>
              </div>

              <div className="confirm-choice">
                <div className="confirm-choice__flag" aria-hidden="true">
                  <span />
                  <span />
                  <span />
                </div>
                <div className="confirm-choice__body">
                  <div className="confirm-choice__label">Вашият избор</div>
                  <div className="confirm-choice__party">{choice.partyName}</div>
                  {!isBlankVote && selectedParty && selectedParty.candidates.length > 0 && (
                    <div className="confirm-choice__candidates">
                      {selectedParty.candidates.join(', ')}
                    </div>
                  )}
                  {!isBlankVote && choice.candidateIndex >= 0 && (
                    <div className="confirm-choice__candidate">
                      Предпочитание: {choice.candidateName}
                    </div>
                  )}
                  {!isBlankVote && choice.candidateIndex === -1 && (
                    <div className="confirm-choice__candidate confirm-choice__candidate--none">
                      Без предпочитание за кандидат
                    </div>
                  )}
                </div>
              </div>

              <div className={`confirm-crypto ${!isEncrypting ? 'confirm-crypto--ready' : ''}`} aria-live="polite">
                <span className="confirm-crypto__icon">{isEncrypting ? '\u26A0' : '\u2705'}</span>
                <span className="confirm-crypto__text">
                  {isEncrypting
                    ? 'Генерира се криптирана бюлетина...'
                    : 'Бюлетината е криптирана и готова за подаване.'}
                </span>
              </div>

              <div className="confirm-actions">
                <button
                  onClick={() => {
                    if (!isEncrypting && encrypted) {
                      void handleSubmit(encrypted)
                    }
                  }}
                  disabled={isEncrypting}
                  aria-busy={isEncrypting}
                  className="vote-btn vote-btn--primary"
                >
                  {isEncrypting ? 'Изчакайте...' : 'Подай гласа си'}
                </button>
                <button
                  onClick={() => {
                    setState({ phase: 'party', config })
                    setSelectedPartyIndex(null)
                    setSelectedCandidateIndex(null)
                  }}
                  className="vote-btn vote-btn--secondary"
                >
                  Промени избора
                </button>
              </div>
            </div>
          </main>
        </div>
      </div>
    )
  }

  if (state.phase === 'submitting') {
    return (
      <div className="vote-shell">
        {renderHeader()}
        {renderSteps()}
        <div className="vote-content">
          <main className="vote-container">
            <div className="vote-card">
              <div className="vote-card__header">
                <h1>Подаване на бюлетина</h1>
                <p>Бюлетината се изпраща към сървъра</p>
              </div>
              <div className="vote-spinner" aria-label="Подаване" role="status">
                <div className="vote-spinner__ring" />
              </div>
              <p className="vote-spinner__text">Моля, не затваряйте прозореца</p>
            </div>
          </main>
        </div>
      </div>
    )
  }

  // phase === 'done'
  const { receipt } = state
  return (
    <div className="vote-shell">
      {renderHeader()}
      {renderSteps()}
      <div className="vote-content">
        <main className="vote-container">
          <div className="vote-card vote-card--success">
            <div className="done-hero">
              <div className="done-hero__icon" aria-hidden="true" />
              <h1>Гласът ви е записан</h1>
              <p className="done-hero__sub">Вашата бюлетина е подадена успешно</p>
            </div>

            {receipt.isOverride && (
              <p className="done-override" role="status">
                Бюлетината е записана като замяна на предишен глас.
              </p>
            )}

            <div className="done-receipt">
              <div className="done-receipt__header">
                <span className="done-receipt__title">Разписка</span>
                <div className="done-receipt__tricolor" aria-hidden="true" />
              </div>

              <div className="done-receipt__row">
                <span className="done-receipt__label">Идентификатор на бюлетина</span>
                <code className="done-receipt__code">{receipt.ballotId}</code>
              </div>
              {receipt.merkleRoot && (
                <div className="done-receipt__row">
                  <span className="done-receipt__label">Корен на Меркъл дървото</span>
                  <code className="done-receipt__code">{receipt.merkleRoot}</code>
                </div>
              )}
            </div>

            <p className="done-note">
              Запазете тази разписка, за да проверите включването на бюлетината
              на <strong>verify.izbori.bg</strong>
            </p>

            <div className="done-actions">
              <button
                onClick={() => {
                  const text = [
                    'Разписка — Отворен Вот',
                    '',
                    `Идентификатор: ${receipt.ballotId}`,
                    receipt.merkleRoot ? `Меркъл корен: ${receipt.merkleRoot}` : '',
                    '',
                    'Проверка: verify.izbori.bg',
                  ].filter(Boolean).join('\n')
                  navigator.clipboard.writeText(text).catch(() => {
                    alert('Копирането не е успешно. Моля, копирайте ръчно.')
                  })
                }}
                className="vote-btn vote-btn--secondary"
              >
                Копирай разписка
              </button>
              <button
                onClick={() => {
                  const text = [
                    'Разписка — Отворен Вот',
                    '========================',
                    '',
                    `Идентификатор: ${receipt.ballotId}`,
                    receipt.merkleRoot ? `Меркъл корен: ${receipt.merkleRoot}` : '',
                    '',
                    'Проверка: verify.izbori.bg',
                  ].filter(Boolean).join('\n')
                  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' })
                  const url = URL.createObjectURL(blob)
                  const a = document.createElement('a')
                  a.href = url
                  a.download = `razpiska-${receipt.ballotId.slice(0, 12)}.txt`
                  a.click()
                  setTimeout(() => URL.revokeObjectURL(url), 10_000)
                }}
                className="vote-btn vote-btn--secondary"
              >
                Изтегли разписка
              </button>
            </div>

            <button
              onClick={() => {
                window.location.href = '/'
              }}
              className="vote-btn vote-btn--secondary"
              style={{ marginTop: '0.5rem' }}
            >
              Започни отначало
            </button>
          </div>
        </main>
      </div>
    </div>
  )
}
