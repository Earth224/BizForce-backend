"use strict";

/* ══════════════════════════════════════════════════════════════════════════
   CONNECT INSTAGRAM, with the Instagram API with Instagram Login (migration
   179). OAuth 2.0 authorization code with a single-use state and NO PKCE:
   Instagram Login uses the state alone, so oauth_states keeps no verifier for
   purpose instagram_login (179's verifier rule allows that).

   THE FLOW.
     1. POST /api/instagram/start (a signed-in member): newState. Only its
        sha256 (stateHash) is stored, in oauth_states, purpose
        instagram_login, for STATE_TTL_MS. The member is sent to authorizeUrl.
     2. Instagram sends the browser back to FRONTEND_URL +
        "/agents/social.html" with ?code and ?state. scripts/oauth-return.js
        hands them to scripts/instagram.js, which POSTs both to
        POST /api/instagram/finish, a requireAuth route; the state row is
        consumed by one conditional update.
     3. exchangeCode gives a SHORT-LIVED token, which is never stored:
        longLived exchanges it at once for the long-lived one (about 60 days),
        server.js seals that with lib/apiKeyCrypto.js, and only then is
        Instagram asked who the account is (/me, lib/instagramApi.js).

   REFRESH. refresh() swaps a long-lived token for a new one. Instagram only
   does that once the token is at least 24 hours old and before it expires,
   so refreshDue asks both: it expires within REFRESH_WINDOW_MS (10 days) AND
   it was stored at least REFRESH_MIN_AGE_MS (24 hours) ago (updated_at moves
   only when the token or the status changes).

   INSTAGRAM'S RULES THIS FOLLOWS (from Meta's developer documentation, as the
   build brief states them; not re-checked against Instagram in this build,
   which made no call to Meta or Instagram):
     - the authorize page takes client_id, redirect_uri, response_type=code,
       a comma-separated scope and state;
     - the code exchange is a form POST and answers flat or inside data[0];
     - the long-lived exchange and the refresh are GETs whose query carries
       the app secret or the token.

   ALL I/O is through deps.request (lib/guardedFetch.js guardedJsonRequest,
   https on 443 only, every address checked, no redirect followed). Nothing
   here logs. The long-lived exchange and the refresh put a secret in the
   URL, so their failures are caught whole and replaced: no error message,
   detail or URL from them ever leaves this file. An InstagramError carries
   only a kind and a short code.
   ══════════════════════════════════════════════════════════════════════════ */

const crypto = require("crypto");

const AUTHORIZE_URL = "https://www.instagram.com/oauth/authorize";
const TOKEN_URL = "https://api.instagram.com/oauth/access_token";
const LONG_LIVED_URL = "https://graph.instagram.com/access_token";
const REFRESH_URL = "https://graph.instagram.com/refresh_access_token";
const BASIC_SCOPE = "instagram_business_basic";
const PUBLISH_SCOPE = "instagram_business_content_publish";
const SCOPE = BASIC_SCOPE + "," + PUBLISH_SCOPE;
const PURPOSE = "instagram_login";
const STATE_TTL_MS = 10 * 60 * 1000;
const TOKEN_TIMEOUT_MS = 15 * 1000;
/* A long-lived token is stored as expiring this much before Instagram says it does. */
const EXPIRY_SLACK_MS = 60 * 1000;
/* Refresh when the token expires within 10 days, and only once it is 24 hours old. */
const REFRESH_WINDOW_MS = 10 * 24 * 60 * 60 * 1000;
const REFRESH_MIN_AGE_MS = 24 * 60 * 60 * 1000;
const STATE_RE = /^[A-Za-z0-9_-]{43}$/;
const CODE_MAX = 4096;
const STATES_RETENTION_MS = 24 * 60 * 60 * 1000;

const MESSAGES = Object.freeze({
  notConfigured: "Instagram connection isn't set up yet.",
  noScopes: "Instagram didn't grant both permissions. Connect again and allow BizForce to see your account and publish posts.",
  stateInvalid: "That sign-in link has expired or was already used. Start again.",
  unreachable: "BizForce could not finish the Instagram sign-in just now. Try again later. Nothing was saved.",
  badRequest: "That sign-in answer was not complete. Start again.",
  noSecret: "Instagram connection can't run right now (the server's encryption key is missing). Nothing was saved.",
  personal: "Instagram posting works with Business and Creator accounts. You can switch to one for free in the Instagram app's settings. Nothing was saved.",
  disconnected: "Disconnected. To remove BizForce from your Instagram account too, open Instagram's settings, then Apps and websites."
});

const deps = {
  request: function (url, options) { return require("./guardedFetch").guardedJsonRequest(url, options); },
  randomBytes: function (n) { return crypto.randomBytes(n); },
  now: function () { return Date.now(); }
};

/* kind: invalid_grant, no_scopes or unreachable. */
function InstagramError(kind, code) {
  this.name = "InstagramError";
  this.kind = kind;
  this.code = code;
  this.message = "instagram " + kind + " (" + code + ")";
}
InstagramError.prototype = Object.create(Error.prototype);

function base64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/* { appId, appSecret } when both env vars are set, else null. */
function configured(env) {
  env = env || process.env;
  var id = typeof env.INSTAGRAM_APP_ID === "string" ? env.INSTAGRAM_APP_ID.trim() : "";
  var secret = typeof env.INSTAGRAM_APP_SECRET === "string" ? env.INSTAGRAM_APP_SECRET.trim() : "";
  if (!id || !secret) return null;
  return { appId: id, appSecret: secret };
}

/* 32 random bytes, base64url: 43 characters. */
function newState() { return base64url(deps.randomBytes(32)); }
/* What is stored for a state: its sha256, hex. The state itself never is. */
function stateHash(state) { return crypto.createHash("sha256").update(String(state), "utf8").digest("hex"); }

function authorizeUrl(appId, redirectUri, state) {
  var q = new URLSearchParams();
  q.append("client_id", appId);
  q.append("redirect_uri", redirectUri);
  q.append("response_type", "code");
  q.append("scope", SCOPE);
  q.append("state", state);
  return AUTHORIZE_URL + "?" + q.toString();
}

/* The finish body's shapes: { ok: true, code, state } or { ok: false }. */
function finishShape(body) {
  body = body || {};
  var code = typeof body.code === "string" ? body.code : "";
  var state = typeof body.state === "string" ? body.state : "";
  if (!code || code.length > CODE_MAX || /[\u0000- \u007f]/.test(code)) return { ok: false };
  if (!STATE_RE.test(state)) return { ok: false };
  return { ok: true, code: code, state: state };
}

/* The granted permissions as stored (granted_scopes): lowercase words and
   commas only, at most 500 characters; null when Instagram named none. */
function scopesOf(permissions) {
  var list = Array.isArray(permissions) ? permissions : (typeof permissions === "string" ? permissions.split(/[,\s]+/) : []);
  var words = list.filter(function (w) { return typeof w === "string" && /^[a-z_]{1,100}$/.test(w); });
  var joined = words.join(",");
  return joined && joined.length <= 500 ? joined : null;
}
/* Both permissions granted? When Instagram's answer names none, that is not a refusal. */
function grantsInstagram(permissions) {
  if (permissions === undefined || permissions === null) return true;
  var have = (scopesOf(permissions) || "").split(",");
  return have.indexOf(BASIC_SCOPE) !== -1 && have.indexOf(PUBLISH_SCOPE) !== -1;
}

function seconds(v) {
  var n = typeof v === "number" ? v : (typeof v === "string" && /^\d{1,10}$/.test(v) ? Number(v) : NaN);
  return Number.isInteger(n) && n >= 1 ? n : null;
}

/* An error Instagram named that means the token or the code is no good
   (invalid_grant): the code exchange's flat error_type OAuthException, or a
   Graph error code 190 (invalid token) or 102 (session). A Graph error's type
   alone says nothing: a rate limit is typed OAuthException too. Anything else
   is unreachable. */
function refusedGrant(json) {
  var j = json && typeof json === "object" ? json : {};
  var e = j.error && typeof j.error === "object" ? j.error : null;
  if (e && (e.code === 190 || e.code === 102)) return true;
  if (j.error_type === "OAuthException" || j.code === 190) return true;
  return false;
}

/* The code exchange: a form POST. Returns { shortToken, scopes }. The short
   token is used once, at once, by longLived, and never stored. */
async function exchangeCode(config, code, redirectUri) {
  var answer;
  try {
    answer = await deps.request(TOKEN_URL, { method: "POST", timeoutMs: TOKEN_TIMEOUT_MS, form: {
      client_id: config.appId,
      client_secret: config.appSecret,
      grant_type: "authorization_code",
      redirect_uri: redirectUri,
      code: code
    } });
  } catch (err) {
    throw new InstagramError("unreachable", "token_request");
  }
  var status = answer && answer.status;
  var j = answer && answer.json && typeof answer.json === "object" ? answer.json : {};
  if (typeof status !== "number" || status < 200 || status >= 300) {
    if (refusedGrant(j) || status === 400) throw new InstagramError("invalid_grant", "invalid_grant");
    throw new InstagramError("unreachable", "token_status_" + (typeof status === "number" ? status : "none"));
  }
  // Flat, or wrapped in data[0].
  var g = Array.isArray(j.data) && j.data[0] && typeof j.data[0] === "object" ? j.data[0] : j;
  if (typeof g.access_token !== "string" || !g.access_token) throw new InstagramError("unreachable", "token_shape");
  if (!grantsInstagram(g.permissions)) throw new InstagramError("no_scopes", "scope_missing");
  return { shortToken: g.access_token, scopes: scopesOf(g.permissions) };
}

/* One GET whose URL carries a secret. Every failure is replaced whole. */
async function secretGet(url, codeOnFail) {
  var answer;
  try {
    answer = await deps.request(url, { method: "GET", timeoutMs: TOKEN_TIMEOUT_MS });
  } catch (err) {
    // Not err.message, err.detail or the URL: the URL holds a secret.
    throw new InstagramError("unreachable", codeOnFail);
  }
  var status = answer && answer.status;
  var j = answer && answer.json && typeof answer.json === "object" ? answer.json : {};
  if (typeof status !== "number" || status < 200 || status >= 300) {
    // Graph answers 400 for a rate limit too: only a named token error, or 401, is a refusal.
    if (refusedGrant(j) || status === 401) throw new InstagramError("invalid_grant", "invalid_grant");
    throw new InstagramError("unreachable", codeOnFail + "_" + (typeof status === "number" ? status : "none"));
  }
  if (typeof j.access_token !== "string" || !j.access_token) throw new InstagramError("unreachable", "token_shape");
  var expiresIn = seconds(j.expires_in);
  if (expiresIn === null) throw new InstagramError("unreachable", "token_expiry");
  return { accessToken: j.access_token, expiresIn: expiresIn };
}

/* The short-lived token for a long-lived one: { accessToken, expiresIn }. */
function longLived(config, shortToken) {
  var q = new URLSearchParams();
  q.append("grant_type", "ig_exchange_token");
  q.append("client_secret", config.appSecret);
  q.append("access_token", shortToken);
  return secretGet(LONG_LIVED_URL + "?" + q.toString(), "long_lived");
}

/* A long-lived token for a new one: { accessToken, expiresIn }. */
function refresh(token) {
  var q = new URLSearchParams();
  q.append("grant_type", "ig_refresh_token");
  q.append("access_token", token);
  return secretGet(REFRESH_URL + "?" + q.toString(), "token_refresh");
}

/* When the token expires: now + expires_in, less the slack. */
function expiresAt(nowMs, expiresIn) { return new Date(nowMs + expiresIn * 1000 - EXPIRY_SLACK_MS).toISOString(); }

/* Should this connection's token be refreshed now? It expires within the
   10-day window, has not expired, and was stored at least 24 hours ago. */
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
  BASIC_SCOPE: BASIC_SCOPE,
  PUBLISH_SCOPE: PUBLISH_SCOPE,
  SCOPE: SCOPE,
  PURPOSE: PURPOSE,
  STATE_TTL_MS: STATE_TTL_MS,
  TOKEN_TIMEOUT_MS: TOKEN_TIMEOUT_MS,
  EXPIRY_SLACK_MS: EXPIRY_SLACK_MS,
  REFRESH_WINDOW_MS: REFRESH_WINDOW_MS,
  REFRESH_MIN_AGE_MS: REFRESH_MIN_AGE_MS,
  STATE_RE: STATE_RE,
  CODE_MAX: CODE_MAX,
  STATES_RETENTION_MS: STATES_RETENTION_MS,
  MESSAGES: MESSAGES,
  deps: deps,
  InstagramError: InstagramError,
  configured: configured,
  newState: newState,
  stateHash: stateHash,
  authorizeUrl: authorizeUrl,
  finishShape: finishShape,
  scopesOf: scopesOf,
  grantsInstagram: grantsInstagram,
  exchangeCode: exchangeCode,
  longLived: longLived,
  refresh: refresh,
  expiresAt: expiresAt,
  refreshDue: refreshDue
};
