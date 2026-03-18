/**
 * Diverg Extension — Tech (lives in both Sectester and diverg-extension).
 * Auto-detect API: try 127.0.0.1:5000 then localhost:5000. Backend runs from this repo (Sectester).
 */
(function (global) {
  const DEFAULT_BASE = 'http://127.0.0.1:5000';
  const CANDIDATES = [DEFAULT_BASE, 'http://localhost:5000'];

  function probe(base) {
    return fetch(base.replace(/\/$/, '') + '/api/health', { method: 'GET' })
      .then(function (r) { return r.ok ? base.replace(/\/$/, '') : null; })
      .catch(function () { return null; });
  }

  function detectApiBase() {
    return probe(CANDIDATES[0]).then(function (ok) {
      if (ok) return ok;
      return probe(CANDIDATES[1]).then(function (ok2) {
        return ok2 || DEFAULT_BASE.replace(/\/$/, '');
      });
    });
  }

  global.DivergAPI = { detectApiBase: detectApiBase, DEFAULT_BASE: DEFAULT_BASE.replace(/\/$/, '') };
})(typeof window !== 'undefined' ? window : self);
