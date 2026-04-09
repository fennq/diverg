/* Diverg — Privy seamless login (hybrid fallback compatible) */
import Privy, { LocalStorage, createSiwsMessage } from "https://cdn.jsdelivr.net/npm/@privy-io/js-sdk-core@0.60.5/+esm";

const API = window.location.origin;

function setPrivyBtnLoading(loading) {
  const btn = document.getElementById("privyBtn");
  if (!btn) return;
  if (loading) {
    btn.disabled = true;
    btn.classList.add("loading");
  } else {
    btn.disabled = false;
    btn.classList.remove("loading");
  }
}

function setPrivyBtnLabel(text) {
  const el = document.querySelector("#privyBtn .btn-text");
  if (el) el.textContent = text;
}

function showAuthError(msg) {
  const t = document.getElementById("authErrorText");
  const b = document.getElementById("authError");
  if (!t || !b) return;
  t.textContent = msg;
  b.classList.add("show");
}

function clearAuthError() {
  const b = document.getElementById("authError");
  if (b) b.classList.remove("show");
}

function currentAuthMode() {
  return window.__divergAuthMode === "register" ? "register" : "login";
}

function oauthLoginMode() {
  return currentAuthMode() === "register" ? "login-or-sign-up" : "no-signup";
}

function referralCodeFromUI() {
  if (currentAuthMode() !== "register") return "";
  const refEl = document.getElementById("authReferralCode");
  const fromInput = refEl ? String(refEl.value || "").trim().toUpperCase() : "";
  let fromSession = "";
  try {
    fromSession = String(sessionStorage.getItem("diverg_ref") || "").trim().toUpperCase();
  } catch (_) {
    fromSession = "";
  }
  return (fromInput || fromSession).slice(0, 64);
}

function base58Encode(bytes) {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  if (!bytes || !bytes.length) return "";
  const src = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  let digits = [0];
  for (let i = 0; i < src.length; i += 1) {
    let carry = src[i];
    for (let j = 0; j < digits.length; j += 1) {
      const x = digits[j] * 256 + carry;
      digits[j] = x % 58;
      carry = Math.floor(x / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let out = "";
  for (let i = 0; i < src.length && src[i] === 0; i += 1) out += alphabet[0];
  for (let i = digits.length - 1; i >= 0; i -= 1) out += alphabet[digits[i]];
  return out;
}

async function getPrivyConfig() {
  const r = await fetch(API + "/api/auth/privy/config");
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.enabled || !j.app_id) {
    throw new Error("Privy is not enabled on this server");
  }
  return j;
}

async function exchangePrivyToken(accessToken) {
  const referral = referralCodeFromUI();
  const body = { access_token: accessToken, mode: currentAuthMode() };
  if (referral) body.referral_code = referral;
  const r = await fetch(API + "/api/auth/privy", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) {
    throw new Error(j.error || "Privy sign-in failed");
  }
  localStorage.setItem("diverg_token", j.token);
  localStorage.setItem("dv_session", j.token);
  localStorage.setItem("diverg_user", JSON.stringify(j.user || {}));
  window.location.href = "/dashboard/";
}

async function handlePrivyCallback(privy) {
  const q = new URLSearchParams(window.location.search);
  const oauthCode = q.get("privy_oauth_code");
  const oauthState = q.get("privy_oauth_state");
  if (!oauthCode || !oauthState) return false;
  setPrivyBtnLoading(true);
  clearAuthError();
  try {
    await privy.auth.oauth.loginWithCode(oauthCode, oauthState, "google", undefined, oauthLoginMode());
    const accessToken = await privy.getAccessToken();
    if (!accessToken) throw new Error("Privy did not return an access token");
    await exchangePrivyToken(accessToken);
    return true;
  } catch (e) {
    showAuthError(String((e && e.message) || e || "Privy callback failed"));
    return false;
  } finally {
    setPrivyBtnLoading(false);
    // Clean callback params from URL for retries.
    if (window.history && window.history.replaceState) {
      const u = new URL(window.location.href);
      u.searchParams.delete("privy_oauth_code");
      u.searchParams.delete("privy_oauth_state");
      window.history.replaceState({}, "", u.toString());
    }
  }
}

async function loginWithPhantomViaPrivySiws(privy) {
  const provider = window.solana;
  if (!provider || !provider.isPhantom) {
    throw new Error("Phantom wallet is required for Privy wallet sign-in.");
  }
  const conn = await provider.connect();
  const pk = (conn && conn.publicKey) || provider.publicKey || null;
  const address = pk && typeof pk.toBase58 === "function" ? pk.toBase58() : String(pk || "");
  if (!address) throw new Error("Could not read Phantom wallet address");

  const nonceOut = await privy.auth.siws.fetchNonce({ address });
  const nonce = String((nonceOut && nonceOut.nonce) || "");
  if (!nonce) throw new Error("Privy did not provide a SIWS nonce");

  const message = createSiwsMessage({
    address,
    nonce,
    domain: window.location.host,
    uri: window.location.origin + "/login",
  });
  const encoded = new TextEncoder().encode(message);
  const signed = await provider.signMessage(encoded, "utf8");
  const sigRaw = signed && signed.signature ? signed.signature : signed;
  const sigBytes = sigRaw instanceof Uint8Array ? sigRaw : Array.isArray(sigRaw) ? Uint8Array.from(sigRaw) : new Uint8Array();
  if (!sigBytes.length) throw new Error("Wallet signature failed");
  const signature = base58Encode(sigBytes);

  await privy.auth.siws.login({
    mode: oauthLoginMode(),
    message,
    signature,
    walletClientType: "phantom",
    connectorType: "injected",
  });

  const accessToken = await privy.getAccessToken();
  if (!accessToken) throw new Error("Privy did not return an access token");
  await exchangePrivyToken(accessToken);
}

async function main() {
  try {
    const qs = new URLSearchParams(window.location.search);
    const mode = (qs.get("mode") || sessionStorage.getItem("diverg_auth_mode") || "").toLowerCase();
    if (mode === "register" && window.__divergAuthMode !== "register") {
      const toggleLink = document.getElementById("toggleLink");
      if (toggleLink) toggleLink.click();
    }
  } catch (_) {
    // ignore
  }
  try {
    const cfg = await getPrivyConfig();
    const privy = new Privy({
      appId: cfg.app_id,
      clientId: cfg.client_id || undefined,
      storage: new LocalStorage(),
    });
    await privy.initialize();

    window.startPrivyAuthFlow = async function startPrivyAuthFlow() {
      setPrivyBtnLoading(true);
      clearAuthError();
      try {
        // Wallet-first auth path avoids OAuth provider allowlist issues.
        await loginWithPhantomViaPrivySiws(privy);
      } catch (e) {
        showAuthError(String((e && e.message) || e || "Privy wallet sign-in failed"));
        setPrivyBtnLoading(false);
      }
    };
    setPrivyBtnLabel(currentAuthMode() === "register" ? "Create account with Privy (Wallet)" : "Sign in with Privy (Wallet)");

    const handled = await handlePrivyCallback(privy);
    if (!handled) setPrivyBtnLoading(false);
  } catch (e) {
    setPrivyBtnLoading(false);
    // Keep fallback auth functioning if Privy cannot initialize.
    window.startPrivyAuthFlow = undefined;
  }
}

main();
