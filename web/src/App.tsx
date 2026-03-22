import LoginPage from './LoginPage'
import VoteFlow from './VoteFlow'

export default function App() {
  const path = window.location.pathname
  if (path === '/vote') return <VoteFlow />
  return <LoginPage />
}
