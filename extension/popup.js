document.addEventListener('DOMContentLoaded', () => {
  chrome.runtime.sendMessage({ type: 'GET_STATUS' }, (status) => {
    const statusEl = document.getElementById('status')
    const resultEl = document.getElementById('result')

    if (!status?.hasSession) {
      statusEl.textContent = 'Няма активна сесия. Отворете izbori.bg, за да гласувате.'
      return
    }

    if (!status.verified) {
      statusEl.textContent = 'Сесията е активна. Очакване на подаване на глас...'
      const pending = document.createElement('div')
      pending.className = 'result pending'
      pending.textContent = 'Гласувайте, за да получите код за проверка'
      resultEl.appendChild(pending)
      return
    }

    statusEl.textContent = 'Гласът е проверен'

    const resultDiv = document.createElement('div')
    resultDiv.className = status.matchedParty ? 'result match' : 'result mismatch'

    const label = document.createElement('div')
    label.className = 'label'
    label.textContent = status.matchedParty ? 'Код за проверка' : 'Внимание'

    const code = document.createElement('div')
    code.className = 'code'
    code.textContent = status.returnCode

    const party = document.createElement('div')
    party.className = 'party'
    party.textContent = status.matchedParty
      ? status.matchedParty
      : 'Кодът не съответства на нито една партия!'

    resultDiv.appendChild(label)
    resultDiv.appendChild(code)
    resultDiv.appendChild(party)
    resultEl.appendChild(resultDiv)
  })
})
