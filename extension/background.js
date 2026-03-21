// Background service worker for Отворен вот verification extension
// Communicates with the Verification Service (Layer 2) independently from page JS

// In production, this MUST be https://verify.izbori.bg
// Using localhost for development only
const VERIFICATION_URL = 'http://localhost:8084'
// TODO: Load from extension storage or manifest for production deployment

let currentSession = null

// Listen for messages from content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'START_SESSION') {
    startSession().then(sendResponse)
    return true // async response
  }

  if (message.type === 'VERIFY_BALLOT') {
    verifyBallot(message.encryptedBallot).then(sendResponse)
    return true
  }

  if (message.type === 'GET_STATUS') {
    sendResponse({
      hasSession: currentSession !== null,
      verified: currentSession?.verified || false,
      returnCode: currentSession?.returnCode || null,
      matchedParty: currentSession?.matchedParty || null
    })
  }
})

async function startSession() {
  try {
    const res = await fetch(`${VERIFICATION_URL}/api/v1/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    })
    if (!res.ok) {
      return { success: false, error: `Server returned ${res.status}` }
    }
    const data = await res.json()
    currentSession = {
      id: data.session_id,
      codeMapping: data.code_mapping,
      verified: false,
      returnCode: null,
      matchedParty: null
    }
    return { success: true, codeMapping: data.code_mapping }
  } catch (err) {
    return { success: false, error: err.message }
  }
}

async function verifyBallot(encryptedBallot) {
  if (!currentSession) {
    return { success: false, error: 'No active session' }
  }
  try {
    const res = await fetch(`${VERIFICATION_URL}/api/v1/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        session_id: currentSession.id,
        encrypted_ballot: encryptedBallot
      })
    })
    if (!res.ok) {
      return { success: false, error: `Server returned ${res.status}` }
    }
    const data = await res.json()
    currentSession.returnCode = data.return_code
    currentSession.verified = true

    // Check which party the return code matches
    for (const [party, code] of Object.entries(currentSession.codeMapping)) {
      if (code === data.return_code) {
        currentSession.matchedParty = party
        break
      }
    }

    return {
      success: true,
      returnCode: data.return_code,
      matchedParty: currentSession.matchedParty
    }
  } catch (err) {
    return { success: false, error: err.message }
  }
}
