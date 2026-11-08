"use strict";

/* ══════════════════════════════════════════════════════════════════════════
   CONNECT ETSY, Etsy Open API v3 with OAuth 2.0 and PKCE (migration 181).
   A member connects their own Etsy shop to the Store agent. BizForce's Etsy
   app is identified by its keystring (ETSY_KEYSTRING) and its shared secret
   (ETSY_SHARED_SECRET); both stay on the server.

   THE FLOW (server.js, the store section).
     1. POST /api/store/etsy/start (a signed-in member): newState and
        newVerifier. Only the state's sha256 (stateHash) is stored, in
        oauth_states, purpose store_etsy, with the verifier SEALED and
        flow_context { permission }, for STATE_TTL_MS. The member is sent to
        authorizeUrl, Etsy's own page, asking for READ_SCOPES, plus
        WRITE_SCOPES only when the member allowed changes.
     2. Etsy sends the browser back to FRONTEND_URL + "/store-agent.html"
        with ?code and ?state. The page POSTs both to /api/store/etsy/finish,
        a requireAuth route, so the code is bound to the signed-in member; the
        state row is consumed by one conditional update, and a failure never
        says which.
     3. exchangeCode sends the code with the verifier, as JSON; both tokens
        are sealed before lib/etsyApi.js asks Etsy anything with them; the
        member's shop is read; the row is stored.

   ETSY'S RULES THIS FOLLOWS (from Etsy's developer documentation and
   announcements as the build brief states them; not checked against Etsy in
   this build, which made no call to Etsy):
     - every request carries x-api-key: "<keystring>:<shared secret>" (since
       Feb 9 2026), the token endpoint included (apiKeyHeader);
     - the token endpoint takes JSON bodies (its form-encoded path has a
       known bug);
     - the access token is prefixed "<user_id>." and lasts expires_in seconds
       (3600); a refresh returns a NEW access token AND a NEW refresh token,
       saved together; a refresh token lasts about 90 days (Etsy's answer
       gives no refresh expiry, so REFRESH_LIFETIME_MS is used);
     - scopes are space-separated on the authorize page;
     - there is no token revocation endpoint: the member removes the app in
       their Etsy account settings, under Apps.

   ALL I/O is the caller's guarded JSON request (lib/guardedFetch.js
   guardedJsonRequest: https on 443 only, every address checked, no redirect
   followed). Nothing here logs, and no token, code, verifier or secret is
   ever put into an error, a result a member sees, or a log line. An
   EtsyAuthError carries only a kind and a short code.
   ══════════════════════════════════════════════════════════════════════════ */

const crypto = require("crypto");

const AUTHORIZE_URL = "https://www.etsy.com/oauth/connect";
const TOKEN_URL = "https://api.etsy.com/v3/public/oauth/token";
const PURPOSE = "store_etsy";
const STATE_TTL_MS = 10 * 60 * 1000;
const STATE_RE = /^[A-Za-z0-9_-]{43}$/;
const CODE_MAX = 2048;
const TOKEN_TIMEOUT_MS = 15 * 1000;
/* An access token is stored as expiring this much before Etsy says it does. */
const EXPIRY_SLACK_MS = 60 * 1000;
/* A token this close to its stored expiry is refreshed before use. */
const REFRESH_MARGIN_MS = 5 * 60 * 1000;
/* Etsy's refresh tokens last about 90 days; its answer does not say. */
const REFRESH_LIFETIME_MS = 90 * 24 * 60 * 60 * 1000;
const READ_SCOPES = Object.freeze(["shops_r", "listings_r", "transactions_r"]);
const WRITE_SCOPES = Object.freeze(["listings_w"]);

const MESSAGES = Object.freeze({
  notConfigured: "Etsy connection isn't set up yet.",
  stateInvalid: "That Etsy connection link has expired or was already used. Start again.",
  scopesMissing: "Etsy didn't grant the access needed. Connect again and approve all permissions.",
  takenByOther: "This Etsy shop is already connected to another BizForce account.",
  noShop: "This Etsy account has no shop, so there is nothing to connect. Nothing was saved.",
  unreachable: "BizForce could not finish connecting your Etsy shop just now. Try again later. Nothing was saved.",
  noSecret: "Stores can't be connected on this server just now: its encryption key is not set. Nothing was sent to your store and nothing was saved.",
  useConnect: "Use Connect Etsy on the Store Agent page.",
  disconnected: "Disconnected. To remove BizForce from Etsy too, open your Etsy account settings, then Apps."
});

const deps = {
  request: function (url, options) { return require("./guardedFetch").guardedJsonRequest(url, options); },
  randomBytes: function (n) { return crypto.randomBytes(n); }
};

/* kind: rejected (Etsy refused the code or the refresh token: connect again),
   no_access (the answer lacks what BizForce needs) or unreachable. */
function EtsyAuthError(kind, code) {
  this.name = "EtsyAuthError";
  this.kind = kind;
  this.code = code;
  this.message = "etsy auth " + kind + " (" + code + ")";
}
EtsyAuthError.prototype = Object.create(Error.prototype);

/* { keystring, sharedSecret } when both env vars are set, else null. */
function configured(env) {
  env = env || process.env;
  var key = typeof env.ETSY_KEYSTRING === "string" ? env.ETSY_KEYSTRING.trim() : "";
  var secret = typeof env.ETSY_SHARED_SECRET === "string" ? env.ETSY_SHARED_SECRET.trim() : "";
  if (!key || !secret) return null;
  return { keystring: key, sharedSecret: secret };
}

/* The x-api-key value every Etsy request carries: "<keystring>:<shared secret>". */
function apiKeyHeader(config) {
  return String(config.keystring) + ":" + String(config.sharedSecret);
}

function base64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
/* 32 random bytes, base64url: 43 characters. */
function newState() { return base64url(deps.randomBytes(32)); }
function newVerifier() { return base64url(deps.randomBytes(32)); }
/* What is stored for a state: its sha256, hex. The state itself never is. */
function stateHash(state) { return crypto.createHash("sha256").update(String(state), "utf8").digest("hex"); }
/* RFC 7636 S256: base64url(sha256(ascii(verifier))). */
function challengeFor(verifier) { return base64url(crypto.createHash("sha256").update(String(verifier), "ascii").digest()); }

/* The scopes asked for: read, plus listings_w only when the member allowed changes. */
function scopesFor(permission) {
  return permission === "read_write" ? READ_SCOPES.concat(WRITE_SCOPES) : READ_SCOPES.slice();
}

/* Etsy's own authorization page. The scopes are space-separated (%20). */
function authorizeUrl(config, permission, redirectUri, state, challenge) {
  return AUTHORIZE_URL +
    "?response_type=code" +
    "&client_id=" + encodeURIComponent(config.keystring) +
    "&redirect_uri=" + encodeURIComponent(redirectUri) +
    "&scope=" + encodeURIComponent(scopesFor(permission).join(" ")) +
    "&state=" + encodeURIComponent(state) +
    "&code_challenge=" + encodeURIComponent(challenge) +
    "&code_challenge_method=S256";
}

/* The finish body: { ok: true, code, state } or { ok: false }. */
function finishShape(body) {
  body = body || {};
  var code = typeof body.code === "string" ? body.code : "";
  var state = typeof body.state === "string" ? body.state : "";
  if (!code || code.length > CODE_MAX || /[\u0000- \u007f]/.test(code)) return { ok: false };
  if (!STATE_RE.test(state)) return { ok: false };
  return { ok: true, code: code, state: state };
}

/* "shops_r listings_r" or "shops_r,listings_r" as a list of scope names. */
function parseScopes(scope) {
  if (typeof scope !== "string") return null;
  return scope.split(/[\s,]+/).filter(function (s) { return /^[a-z_]{1,40}$/.test(s); });
}

function positiveInt(v) {
  var n = typeof v === "number" ? v : (typeof v === "string" && /^\d{1,9}$/.test(v) ? Number(v) : NaN);
  return Number.isInteger(n) && n >= 1 ? n : null;
}

/* The numeric user id Etsy puts before the first "." of an access token, or null. */
function userIdOf(accessToken) {
  var m = /^([0-9]{1,30})\./.exec(String(accessToken == null ? "" : accessToken));
  return m ? m[1] : null;
}

/* A token answer, checked. Never returns or logs the answer itself.
   scopes: the list Etsy answered, or null when its answer names none. */
function grantFrom(json) {
  var j = json && typeof json === "object" ? json : {};
  if (typeof j.access_token !== "string" || !j.access_token) throw new EtsyAuthError("unreachable", "token_shape");
  if (typeof j.refresh_token !== "string" || !j.refresh_token) throw new EtsyAuthError("no_access", "no_refresh_token");
  var expiresIn = positiveInt(j.expires_in);
  if (expiresIn === null) throw new EtsyAuthError("no_access", "no_expiry");
  var userId = userIdOf(j.access_token);
  if (userId === null) throw new EtsyAuthError("no_access", "no_user_id");
  return {
    accessToken: j.access_token,
    refreshToken: j.refresh_token,
    expiresIn: expiresIn,
    userId: userId,
    scopes: parseScopes(j.scope)
  };
}

/* One JSON POST to Etsy's token endpoint, with the x-api-key header. A 4xx
   means Etsy refused the code or the refresh token (rejected); anything else
   that fails is unreachable. */
async function tokenRequest(config, body, request) {
  var answer;
  try {
    answer = await (typeof request === "function" ? request : deps.request)(TOKEN_URL,
      { method: "POST", headers: { "x-api-key": apiKeyHeader(config) }, body: body, timeoutMs: TOKEN_TIMEOUT_MS });
  } catch (err) {
    throw new EtsyAuthError("unreachable", "token_request");
  }
  var status = answer && answer.status;
  if (typeof status !== "number" || status < 200 || status >= 300) {
    if (typeof status === "number" && status >= 400 && status < 500 && status !== 408 && status !== 429) throw new EtsyAuthError("rejected", "token_status_" + status);
    throw new EtsyAuthError("unreachable", "token_status_" + (typeof status === "number" ? status : "none"));
  }
  return grantFrom(answer.json);
}

/* The code, exchanged with the PKCE verifier. */
function exchangeCode(config, code, verifier, redirectUri, request) {
  return tokenRequest(config, {
    grant_type: "authorization_code",
    client_id: config.keystring,
    redirect_uri: redirectUri,
    code: code,
    code_verifier: verifier
  }, request);
}

/* A refresh: a new access token AND a new refresh token; the old one is spent. */
function refreshTokens(config, refreshToken, request) {
  return tokenRequest(config, { grant_type: "refresh_token", client_id: config.keystring, refresh_token: refreshToken }, request);
}

/* When each token stops being used: the access token EXPIRY_SLACK_MS early,
   the refresh token after REFRESH_LIFETIME_MS. */
function expiriesFor(grant, nowMs) {
  return {
    access_expires_at: new Date(nowMs + grant.expiresIn * 1000 - EXPIRY_SLACK_MS).toISOString(),
    refresh_expires_at: new Date(nowMs + REFRESH_LIFETIME_MS).toISOString()
  };
}

/* Every asked scope granted? A null list (Etsy's answer named none) counts as
   the asked set: Etsy issues the token for what its page showed. */
function grantCovers(granted, requested) {
  if (granted === null) return true;
  return requested.every(function (s) { return granted.indexOf(s) !== -1; });
}

module.exports = {
  AUTHORIZE_URL: AUTHORIZE_URL,
  TOKEN_URL: TOKEN_URL,
  PURPOSE: PURPOSE,
  STATE_TTL_MS: STATE_TTL_MS,
  STATE_RE: STATE_RE,
  TOKEN_TIMEOUT_MS: TOKEN_TIMEOUT_MS,
  EXPIRY_SLACK_MS: EXPIRY_SLACK_MS,
  REFRESH_MARGIN_MS: REFRESH_MARGIN_MS,
  REFRESH_LIFETIME_MS: REFRESH_LIFETIME_MS,
  READ_SCOPES: READ_SCOPES,
  WRITE_SCOPES: WRITE_SCOPES,
  MESSAGES: MESSAGES,
  deps: deps,
  EtsyAuthError: EtsyAuthError,
  configured: configured,
  apiKeyHeader: apiKeyHeader,
  newState: newState,
  newVerifier: newVerifier,
  stateHash: stateHash,
  challengeFor: challengeFor,
  scopesFor: scopesFor,
  authorizeUrl: authorizeUrl,
  finishShape: finishShape,
  parseScopes: parseScopes,
  userIdOf: userIdOf,
  grantFrom: grantFrom,
  exchangeCode: exchangeCode,
  refreshTokens: refreshTokens,
  expiriesFor: expiriesFor,
  grantCovers: grantCovers
};
