(function () {
  const apiBaseEl = document.getElementById('apiBase');
  const saveBtn = document.getElementById('save');
  const statusEl = document.getElementById('status');

  chrome.storage.local.get({ apiBase: 'http://127.0.0.1:5000' }, function (o) {
    apiBaseEl.value = o.apiBase;
  });

  saveBtn.addEventListener('click', function () {
    const base = apiBaseEl.value.trim().replace(/\/$/, '');
    chrome.storage.local.set({ apiBase: base || 'http://127.0.0.1:5000' }, function () {
      statusEl.textContent = 'Saved.';
      statusEl.className = 'status ok';
    });
  });
})();
