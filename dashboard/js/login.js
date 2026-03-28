/* Diverg — Login / Register */
(function () {
  'use strict';

  const API = window.location.origin;
  let isRegister = false;

  if (localStorage.getItem('diverg_token')) {
    window.location.href = '/dashboard/';
    return;
  }

  try {
    var refParam = new URL(window.location.href).searchParams.get('ref');
    if (refParam && refParam.trim()) sessionStorage.setItem('diverg_ref', refParam.trim().toUpperCase().slice(0, 16));
  } catch (e) { /* ignore */ }

  function showError(msg) {
    document.getElementById('authErrorText').textContent = msg;
    document.getElementById('authError').classList.add('show');
  }
  function hideError() {
    document.getElementById('authError').classList.remove('show');
  }

  function toggleMode(e) {
    if (e) e.preventDefault();
    isRegister = !isRegister;
    document.getElementById('authTitle').textContent = isRegister ? 'Create your account' : 'Welcome back';
    document.getElementById('authSubtitle').textContent = isRegister
      ? 'Start securing with Diverg'
      : 'Sign in to your Diverg account';
    document.getElementById('authBtn').querySelector('.btn-text').textContent = isRegister ? 'Create account' : 'Sign in';
    document.getElementById('toggleText').textContent = isRegister ? 'Already have an account?' : 'No account?';
    document.getElementById('toggleLink').textContent = isRegister ? 'Sign in' : 'Create one';
    document.getElementById('nameField').classList.toggle('show', isRegister);
    document.getElementById('authPassword').autocomplete = isRegister ? 'new-password' : 'current-password';
    document.getElementById('authPassword').placeholder = isRegister ? 'Create a password' : 'Min 8 characters';
    hideError();
  }

  function togglePw() {
    var inp = document.getElementById('authPassword');
    var showing = inp.type === 'text';
    inp.type = showing ? 'password' : 'text';
    document.getElementById('pwIcon').innerHTML = showing
      ? '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>'
      : '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>';
  }

  async function handleAuth(e) {
    e.preventDefault();
    hideError();
    var btn = document.getElementById('authBtn');
    btn.disabled = true;
    btn.classList.add('loading');

    var email = document.getElementById('authEmail').value.trim();
    var password = document.getElementById('authPassword').value;
    var name = document.getElementById('authName').value.trim();

    if (password.length > 128) {
      showError('Password is too long');
      btn.disabled = false;
      btn.classList.remove('loading');
      return;
    }

    var endpoint = isRegister ? '/api/auth/register' : '/api/auth/login';
    var body = isRegister ? { email: email, password: password, name: name } : { email: email, password: password };
    if (isRegister) {
      var storedRef = sessionStorage.getItem('diverg_ref');
      if (storedRef) body.referral_code = storedRef;
    }

    try {
      var r = await fetch(API + endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      var data = await r.json();

      if (!r.ok) {
        showError(r.status === 429 ? 'Too many attempts — please wait a few minutes' : (data.error || 'Something went wrong'));
        btn.disabled = false;
        btn.classList.remove('loading');
        return;
      }

      localStorage.setItem('diverg_token', data.token);
      localStorage.setItem('diverg_user', JSON.stringify(data.user));
      sessionStorage.removeItem('diverg_ref');
      window.location.href = '/dashboard/';
    } catch (err) {
      showError('Connection failed — is the server running?');
      btn.disabled = false;
      btn.classList.remove('loading');
    }
  }

  document.getElementById('toggleLink').addEventListener('click', toggleMode);
  document.getElementById('pwToggle').addEventListener('click', togglePw);
  document.getElementById('authForm').addEventListener('submit', handleAuth);
})();
