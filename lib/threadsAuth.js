"use strict";

/* ══════════════════════════════════════════════════════════════════════════
   CONNECT THREADS (LR-2, migration 204e threads_connections). NAMED (Nov 23
   2026, LR-2). A member connects their OWN Threads account through Meta's
   Threads sign-in; Lead Radar searches with the member's own token and, after
   the member approves the exact text, replies from that account.

   THE FLOW (lib/threadsRoutes.js).
     1. GET /api/social/threads/connect (members): signState makes a signed,
        single-use state that names the member and expires in STATE_TTL_MS;
        the member is sent to authorizeUrl.
     2. Threads sends the browser back to the BACKEND callback
        (redirectUri(apiBase) = apiBase + CALLBACK_PATH) with ?code and ?state.
        readState checks the signature and the expiry; the routes module
        spends the state's nonce once (useNonce).
     3. exchangeCode gives a SHORT-LIVED token, never stored: longLived swaps
        it at once for the long-lived one (about 60 days), which is sealed
        with lib/apiKeyCrypto.js before Threads is asked who the account is.

   WHY A SIGNED STATE AND NOT oauth_states: the callback is a public GET (no
   BizForce session rides along with Meta's redirect), so the state itself
   must say which member it belongs to, and oauth_states' purpose CHECK
   (migrations 173-182) does not list a Threads purpose. The state is
   base64url(payload) + "." + base64url(HMAC-SHA256(payload)), the key
   derived from THREADS_APP_SECRET; payload = { u: user id, n: 16 random bytes,
   e: expiry ms }. Nonces are spent in this process's memory, so a state is
   single-use per process and expires in 10 minutes regardless.

   REFRESH. refresh() swaps a long-lived token for a new one; Threads does
   that only once the token is at least 24 hours old and before it expires,
   so refreshDue asks both (the same rule as lib/instagramAuth.js).

   META'S THREADS RULES THIS FOLLOWS (from Meta's Threads API documentation as
   remembered for this build; no call was made to Meta in this build):
     - authorize: https://threads.net/oauth/authorize with client_id,
       redirect_uri, scope (comma-separated), response_type=code, state;
     - code exchange: form POST to https://graph.threads.net/oauth/access_token
       (client_id, client_secret, code, grant_type=authorization_code,
       redirect_uri), answering { access_token, user_id };
     - long-lived: GET https://graph.threads.net/access_token with
       grant_type=th_exchange_token, client_secret, access_token, answering
       { access_token, token_type: "bearer", expires_in };
     - refresh: GET https://graph.threads.net/refresh_access_token with
       grant_type=th_refresh_token, access_token, the same answer shape.

   ALL I/O is through deps.request (lib/guardedFetch.js guardedJsonRequest).
   Nothing here logs. The long-lived exchange and the refresh carry a secret
   in the URL, so their failures are replaced whole: a ThreadsError carries
   only a kind and a short code.
   ══════════════════════════════════════════════════════════════════════════ */

const crypto = require("crypto");

const AUTHORIZE_URL = "https://threads.net/oauth/authorize";
const TOKEN_URL = "https://graph.threads.net/oauth/access_token";
const LONG_LIVED_URL = "https://graph.threads.net/access_token";
const REFRESH_URL = "https://graph.threads.net/refresh_access_token";
const CALLBACK_PATH = "/api/social/threads/callback";
const SCOPES = Object.freeze(["threads_basic", "threads_keyword_search", "threads_content_publish", "threads_manage_replies"]);
const SCOPE = SCOPES.join(",");
const STATE_TTL_MS = 10 * 60 * 1000;
const TOKEN_TIMEOUT_MS = 15 * 1000;
/* A long-lived token is stored as expiring this much before Threads says it does. */
const EXPIRY_SLACK_MS = 60 * 1000;
/* Refresh when the token expires within 10 days, and only once it is 24 hours old. */
const REFRESH_WINDOW_MS = 10 * 24 * 60 * 60 * 1000;
const REFRESH_MIN_AGE_MS = 24 * 60 * 60 * 1000;
const CODE_MAX = 4096;
const STATE_MAX = 400;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const NONCE_RE = /^[A-Za-z0-9_-]{22}$/;

const MESSAGES = Object.freeze({
  notSetUp: "Threads is not set up yet",
  noSecret: "Threads connection can't run right now (the server's encryption key is missing). Nothing was saved.",
  disconnected: "Disconnected. To remove BizForce from your Threads account too, open Threads' settings, then Account, then Website permissions."
});

const deps = {
  request: function (url, options) { return require("./guardedFetch").guardedJsonRequest(url, options); },
  randomBytes: function (n) { return crypto.randomBytes(n); },
  now: function () { return Date.now(); }
};

/* kind: invalid_grant, no_scopes or unreachable. */
function ThreadsError(kind, code) {
  this.name = "ThreadsError";
  this.kind = kind;
  this.code = code;
  this.message = "threads " + kind + " (" + code + ")";
}
ThreadsError.prototype = Object.create(Error.prototype);

function base64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/* { appId, appSecret } when THREADS_APP_ID and THREADS_APP_SECRET are both set, else null. */
function configured(env) {
  env = env || process.env;
  var id = typeof env.THREADS_APP_ID === "string" ? env.THREADS_APP_ID.trim() : "";
  var secret = typeof env.THREADS_APP_SECRET === "string" ? env.THREADS_APP_SECRET.trim() : "";
  if (!id || !secret) return null;
  return { appId: id, appSecret: secret };
}

/* The callback Meta must have on file (Valid OAuth Redirect URIs), on the backend's public origin. */
function redirectUri(apiBase) { return String(apiBase).replace(/\/+$/, "") + CALLBACK_PATH; }

function authorizeUrl(appId, redirect, state) {
  var q = new URLSearchParams();
  q.append("client_id", appId);
  q.append("redirect_uri", redirect);
  q.append("scope", SCOPE);
  q.append("response_type", "code");
  q.append("state", state);
  return AUTHORIZE_URL + "?" + q.toString();
}

function stateKey(config) {
  return crypto.createHmac("sha256", String(config.appSecret)).update("bizforce threads state v1", "utf8").digest();
}
function stateMac(config, body) {
  return base64url(crypto.createHmac("sha256", stateKey(config)).update(body, "utf8").digest());
}

/* A signed state for this member. */
function signState(config, userId, nowMs) {
  var payload = { u: String(userId), n: base64url(deps.randomBytes(16)), e: nowMs + STATE_TTL_MS };
  var body = base64url(Buffer.from(JSON.stringify(payload), "utf8"));
  return body + "." + stateMac(config, body);
}

/* { ok: true, userId, nonce, expiresMs } for a state this server signed and
   that has not expired, else { ok: false }. Never says why. */
function readState(config, state, nowMs) {
  if (!config || typeof state !== "string" || state.length > STATE_MAX) return { ok: false };
  var dot = state.indexOf(".");
  if (dot < 1 || dot !== state.lastIndexOf(".")) return { ok: false };
  var body = state.slice(0, dot);
  var mac = state.slice(dot + 1);
  var want = stateMac(config, body);
  if (mac.length !== want.length || !crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(want))) return { ok: false };
  var p;
  try { p = JSON.parse(Buffer.from(body, "base64").toString("utf8")); } catch (e) { return { ok: false }; }
  if (!p || typeof p !== "object" || !UUID_RE.test(String(p.u)) || !NONCE_RE.test(String(p.n)) || !Number.isFinite(p.e)) return { ok: false };
  if (p.e <= nowMs) return { ok: false };
  return { ok: true, userId: p.u, nonce: p.n, expiresMs: p.e };
}

/* Spent nonces, each kept until its state would have expired anyway. */
const spentNonces = new Map();
/* true the first time a nonce is spent, false after. */
function useNonce(nonce, expiresMs, nowMs) {
  spentNonces.forEach(function (until, n) { if (until <= nowMs) spentNonces.delete(n); });
  if (spentNonces.has(nonce)) return false;
  spentNonces.set(nonce, expiresMs);
  return true;
}

/* The callback's query: { ok: true, code, state } or { ok: false, denied }. */
function callbackShape(query) {
  query = query || {};
  var code = typeof query.code === "string" ? query.code : "";
  var state = typeof query.state === "string" ? query.state : "";
  var denied = typeof query.error === "string" && query.error.length > 0;
  if (denied || !code || code.length > CODE_MAX || /[\u0000- \u007f]/.test(code)) return { ok: false, denied: denied };
  if (!state || state.length > STATE_MAX) return { ok: false, denied: false };
  return { ok: true, code: code, state: state };
}

/* The granted permissions as stored (granted_scopes): lowercase words and commas, at most 500; null when none named. */
function scopesOf(permissions) {
  var list = Array.isArray(permissions) ? permissions : (typeof permissions === "string" ? permissions.split(/[,\s]+/) : []);
  var words = list.filter(function (w) { return typeof w === "string" && /^[a-z_]{1,100}$/.test(w); });
  var joined = words.join(",");
  return joined && joined.length <= 500 ? joined : null;
}

function seconds(v) {
  var n = typeof v === "number" ? v : (typeof v === "string" && /^\d{1,10}$/.test(v) ? Number(v) : NaN);
  return Number.isInteger(n) && n >= 1 ? n : null;
}

/* A Graph error that means the token or the code is no good: 190 (invalid token), 102 (session), or a flat OAuthException. */
function refusedGrant(json) {
  var j = json && typeof json === "object" ? json : {};
  var e = j.error && typeof j.error === "object" ? j.error : null;
  if (e && (e.code === 190 || e.code === 102)) return true;
  if (j.error_type === "OAuthException" || j.code === 190) return true;
  return false;
}

/* The code exchange: a form POST. Returns { shortToken, threadsUserId, scopes }. The
   short token is used once, at once, by longLived, and never stored. */
async function exchangeCode(config, code, redirect) {
  var answer;
  try {
    answer = await deps.request(TOKEN_URL, { method: "POST", timeoutMs: TOKEN_TIMEOUT_MS, form: {
      client_id: config.appId,
      client_secret: config.appSecret,
      code: code,
      grant_type: "authorization_code",
      redirect_uri: redirect
    } });
  } catch (err) {
    throw new ThreadsError("unreachable", "token_request");
  }
  var status = answer && answer.status;
  var j = answer && answer.json && typeof answer.json === "object" ? answer.json : {};
  if (typeof status !== "number" || status < 200 || status >= 300) {
    if (refusedGrant(j) || status === 400) throw new ThreadsError("invalid_grant", "invalid_grant");
    throw new ThreadsError("unreachable", "token_status_" + (typeof status === "number" ? status : "none"));
  }
  if (typeof j.access_token !== "string" || !j.access_token) throw new ThreadsError("unreachable", "token_shape");
  var uid = typeof j.user_id === "number" || typeof j.user_id === "string" ? String(j.user_id) : "";
  // Meta documents { access_token, user_id }; a permissions list, if one ever comes, is kept as granted_scopes.
  return { shortToken: j.access_token, threadsUserId: /^[0-9]{1,30}$/.test(uid) ? uid : null, scopes: scopesOf(j.permissions) };
}

/* One GET whose URL carries a secret. Every failure is replaced whole. */
async function secretGet(url, codeOnFail) {
  var answer;
  try {
    answer = await deps.request(url, { method: "GET", timeoutMs: TOKEN_TIMEOUT_MS });
  } catch (err) {
    // Not err.message, err.detail or the URL: the URL holds a secret.
    throw new ThreadsError("unreachable", codeOnFail);
  }
  var status = answer && answer.status;
  var j = answer && answer.json && typeof answer.json === "object" ? answer.json : {};
  if (typeof status !== "number" || status < 200 || status >= 300) {
    if (refusedGrant(j) || status === 401) throw new ThreadsError("invalid_grant", "invalid_grant");
    throw new ThreadsError("unreachable", codeOnFail + "_" + (typeof status === "number" ? status : "none"));
  }
  if (typeof j.access_token !== "string" || !j.access_token) throw new ThreadsError("unreachable", "token_shape");
  var expiresIn = seconds(j.expires_in);
  if (expiresIn === null) throw new ThreadsError("unreachable", "token_expiry");
  return { accessToken: j.access_token, expiresIn: expiresIn };
}

/* The short-lived token for a long-lived one: { accessToken, expiresIn }. */
function longLived(config, shortToken) {
  var q = new URLSearchParams();
  q.append("grant_type", "th_exchange_token");
  q.append("client_secret", config.appSecret);
  q.append("access_token", shortToken);
  return secretGet(LONG_LIVED_URL + "?" + q.toString(), "long_lived");
}

/* A long-lived token for a new one: { accessToken, expiresIn }. */
function refresh(token) {
  var q = new URLSearchParams();
  q.append("grant_type", "th_refresh_token");
  q.append("access_token", token);
  return secretGet(REFRESH_URL + "?" + q.toString(), "token_refresh");
}

/* When the token expires: now + expires_in, less the slack. */
function expiresAt(nowMs, expiresIn) { return new Date(nowMs + expiresIn * 1000 - EXPIRY_SLACK_MS).toISOString(); }

/* Should this connection's token be refreshed now? Within the 10-day window, not expired, stored 24 hours ago or more. */
function refreshDue(row, nowMs) {
  if (!row) return false;
  var ends = Date.parse(row.access_expires_at || "");
  var stored = Date.parse(row.updated_at || "");
  if (!isFinite(ends) || !isFinite(stored)) return false;
  if (ends <= nowMs) return false;
  if (ends - nowMs > REFRESH_WINDOW_MS) return false;
  return nowMs - stored >= REFRESH_MIN_AGE_MS;
}

module.exports = {
  AUTHORIZE_URL: AUTHORIZE_URL,
  TOKEN_URL: TOKEN_URL,
  LONG_LIVED_URL: LONG_LIVED_URL,
  REFRESH_URL: REFRESH_URL,
  CALLBACK_PATH: CALLBACK_PATH,
  SCOPES: SCOPES,
  SCOPE: SCOPE,
  STATE_TTL_MS: STATE_TTL_MS,
  TOKEN_TIMEOUT_MS: TOKEN_TIMEOUT_MS,
  EXPIRY_SLACK_MS: EXPIRY_SLACK_MS,
  REFRESH_WINDOW_MS: REFRESH_WINDOW_MS,
  REFRESH_MIN_AGE_MS: REFRESH_MIN_AGE_MS,
  CODE_MAX: CODE_MAX,
  MESSAGES: MESSAGES,
  deps: deps,
  ThreadsError: ThreadsError,
  configured: configured,
  redirectUri: redirectUri,
  authorizeUrl: authorizeUrl,
  signState: signState,
  readState: readState,
  useNonce: useNonce,
  callbackShape: callbackShape,
  scopesOf: scopesOf,
  exchangeCode: exchangeCode,
  longLived: longLived,
  refresh: refresh,
  expiresAt: expiresAt,
  refreshDue: refreshDue
};
