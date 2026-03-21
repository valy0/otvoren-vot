import { useState } from 'react'

type AppState = 'auth' | 'ballot' | 'confirm' | 'done'

interface BallotChoice {
  partyIndex: number
  partyName: string
}

const PARTIES = [
  'ГЕРБ-СДС', 'ПП-ДБ', 'ДПС', 'БСП', 'Възраждане',
  'Има такъв народ', 'Български възход', 'ППДБ'
]

export default function App() {
  const [state, setState] = useState<AppState>('auth')
  const [choice, setChoice] = useState<BallotChoice | null>(null)
  const [ballotId, setBallotId] = useState('')

  if (state === 'auth') {
    return (
      <div className="container">
        <h1>Отворен вот</h1>
        <p>Система за електронно гласуване</p>
        <button onClick={() => setState('ballot')} className="btn-primary">
          Гласувай онлайн
        </button>
        <p className="note">Ще бъдете пренасочени към eAuth за удостоверяване</p>
      </div>
    )
  }

  if (state === 'ballot') {
    return (
      <div className="container">
        <h1>Изберете партия</h1>
        <div className="party-grid" role="radiogroup" aria-label="Избор на партия">
          {PARTIES.map((party, i) => (
            <button
              key={i}
              role="radio"
              aria-checked={choice?.partyIndex === i}
              className={`party-btn ${choice?.partyIndex === i ? 'selected' : ''}`}
              onClick={() => setChoice({ partyIndex: i, partyName: party })}
            >
              {party}
            </button>
          ))}
        </div>
        {choice && (
          <button onClick={() => setState('confirm')} className="btn-primary">
            Потвърди избора
          </button>
        )}
      </div>
    )
  }

  if (state === 'confirm') {
    return (
      <div className="container">
        <h1>Потвърждение</h1>
        <p className="choice-display">Вие избрахте: <strong>{choice?.partyName}</strong></p>
        <div className="actions">
          <button onClick={() => {
            setBallotId(crypto.randomUUID())
            setState('done')
          }} className="btn-primary">
            Подай глас
          </button>
          <button onClick={() => setState('ballot')} className="btn-secondary">
            Промени избора
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="container">
      <h1>Гласът ви е записан</h1>
      <p>Идентификатор на бюлетина:</p>
      <code className="ballot-id">{ballotId}</code>
      <p className="note">
        Запазете този идентификатор, за да проверите включването на бюлетината
        на verify.izbori.bg
      </p>
    </div>
  )
}
