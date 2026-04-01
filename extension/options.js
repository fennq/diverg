/**
 * Diverg Extension — Options: API base URL + Helius key for Solana tab.
 */
(function () {
  const apiUrlEl = document.getElementById('api-url');
  const heliusKeyEl = document.getElementById('helius-key');
  const saveApiBtn = document.getElementById('save-api');
  const saveHeliusBtn = document.getElementById('save-helius');
  const jwtEl = document.getElementById('diverg-jwt');
  const saveJwtBtn = document.getElementById('save-jwt');
  const statusEl = document.getElementById('status');
  const STORAGE_API = 'diverg_api_base_url';
  const STORAGE_HELIUS = 'heliusApiKey';
  const STORAGE_JWT = 'diverg_auth_token';

  function showStatus(msg, isError) {
    statusEl.textContent = msg;
    statusEl.style.color = isError ? 'var(--critical)' : 'var(--low)';
  }

  if (saveApiBtn) {
    saveApiBtn.addEventListener('click', async () => {
      const url = (apiUrlEl.value || '').trim().replace(/\/+$/, '');
      await chrome.storage.local.set({ [STORAGE_API]: url || null });
      showStatus(url ? `API URL saved: ${url}` : 'API URL cleared.', false);
    });
  }

  if (saveHeliusBtn) {
    saveHeliusBtn.addEventListener('click', async () => {
      const key = (heliusKeyEl.value || '').trim();
      await chrome.storage.local.set({ [STORAGE_HELIUS]: key || '' });
      showStatus(key ? 'Helius key saved.' : 'Helius key cleared.', false);
    });
  }

  if (saveJwtBtn && jwtEl) {
    saveJwtBtn.addEventListener('click', async () => {
      const t = (jwtEl.value || '').trim();
      await chrome.storage.local.set({ [STORAGE_JWT]: t || '' });
      showStatus(t ? 'JWT saved (stored locally in this browser).' : 'JWT cleared.', false);
    });
  }

  chrome.storage.local.get([STORAGE_API, STORAGE_HELIUS, STORAGE_JWT], (raw) => {
    if (raw[STORAGE_API]) apiUrlEl.value = raw[STORAGE_API];
    if (raw[STORAGE_HELIUS]) heliusKeyEl.value = raw[STORAGE_HELIUS];
    if (raw[STORAGE_JWT] && jwtEl) jwtEl.value = raw[STORAGE_JWT];
  });
})();
