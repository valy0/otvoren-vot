import { useEffect } from 'react'

// ---------------------------------------------------------------------------
// Configuration from environment (falls back to local dev defaults)
// ---------------------------------------------------------------------------

const AUTH_URL = (import.meta.env.VITE_AUTH_URL as string | undefined) ?? 'http://localhost:8082'

// ---------------------------------------------------------------------------
// LoginPage — ceremonial Bulgarian state portal login screen
// ---------------------------------------------------------------------------

export default function LoginPage() {
  // Every visit to `/` is a clean slate — clear any stale auth token.
  useEffect(() => {
    sessionStorage.removeItem('authToken')
  }, [])

  function handleAuth() {
    window.location.href = `${AUTH_URL}/login?redirect_uri=${encodeURIComponent(window.location.origin + '/vote')}`
  }

  return (
    <div className="login-page">
      {/* Tricolor flag bands as background */}
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
