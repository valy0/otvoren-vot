import { useState, useEffect } from 'react'

interface BoardStatus {
  root_sha256: string
  ballot_count: number
  sealed: boolean
}

export default function App() {
  const [status, setStatus] = useState<BoardStatus | null>(null)
  const [error, setError] = useState('')

  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080'

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const res = await fetch(`${API_URL}/api/v1/board/root`)
        const json = await res.json()
        setStatus(json.data)
        setError('')
      } catch {
        setError('Не може да се свърже с бюлетинната дъска')
      }
    }
    fetchStatus()
    const interval = setInterval(fetchStatus, 10000)
    return () => clearInterval(interval)
  }, [API_URL])

  return (
    <div className="container">
      <h1>Отворен вот — Табло</h1>
      <p>Публично табло за наблюдение на изборния процес</p>

      {error && <div className="error">{error}</div>}

      <div className="stats">
        <div className="stat-card">
          <div className="stat-value">{status?.ballot_count ?? '—'}</div>
          <div className="stat-label">Подадени бюлетини</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{status?.sealed ? 'Запечатана' : 'Активна'}</div>
          <div className="stat-label">Бюлетинна дъска</div>
        </div>
      </div>

      {status?.root_sha256 && (
        <div className="merkle-root">
          <h2>Merkle корен (SHA-256)</h2>
          <code>{status.root_sha256}</code>
        </div>
      )}

      <div className="verify-section">
        <h2>Проверка на бюлетина</h2>
        <label htmlFor="ballot-id-input">
          Въведете идентификатор на бюлетината, за да проверите включването:
        </label>
        <input
          id="ballot-id-input"
          type="text"
          placeholder="Идентификатор на бюлетина..."
          className="verify-input"
        />
        <button className="btn-primary">Провери</button>
      </div>
    </div>
  )
}
