(function () {
  var keyInput = document.getElementById('heliusKey');
  var saveBtn = document.getElementById('saveHelius');
  var statusEl = document.getElementById('status');

  chrome.storage.local.get(['heliusApiKey'], function (o) {
    if (keyInput && o.heliusApiKey) keyInput.value = o.heliusApiKey;
  });

  if (saveBtn) {
    saveBtn.addEventListener('click', function () {
      var v = keyInput ? keyInput.value.trim() : '';
      chrome.storage.local.set({ heliusApiKey: v }, function () {
        if (statusEl) {
          statusEl.textContent = v ? 'Saved.' : 'Cleared.';
          setTimeout(function () {
            statusEl.textContent = '';
          }, 2500);
        }
      });
    });
  }
})();
