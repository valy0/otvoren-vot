// Content script for Отворен вот
// Detects the voting page and bridges communication between page and extension

console.log('[Отворен вот] Extension active on', window.location.hostname)

// Notify background that we're on a voting page
chrome.runtime.sendMessage({ type: 'START_SESSION' }, (response) => {
  if (response?.success) {
    console.log('[Отворен вот] Verification session started')
  } else {
    console.warn('[Отворен вот] Failed to start session:', response?.error)
  }
})

// Listen for messages from the voting page (via window.postMessage)
window.addEventListener('message', (event) => {
  if (event.source !== window) return
  if (event.data?.type === 'OTVOREN_VOT_BALLOT_SUBMITTED') {
    chrome.runtime.sendMessage(
      { type: 'VERIFY_BALLOT', encryptedBallot: event.data.encryptedBallot },
      (response) => {
        // Post result back to page
        window.postMessage({
          type: 'OTVOREN_VOT_VERIFICATION_RESULT',
          ...response
        }, window.location.origin)
      }
    )
  }
})
