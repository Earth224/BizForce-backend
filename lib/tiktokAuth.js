"use strict";

/* ══════════════════════════════════════════════════════════════════════════
   CONNECT TIKTOK, with TikTok Login Kit for Web (migration 178).
   OAuth 2.0 authorization code with a single-use state and NO PKCE: Login
   Kit for Web uses the state alone, so oauth_states keeps no verifier for
   purpose tiktok_login (178's verifier rule allows that). What comes back is
   an access token (about 24 hours), a refresh token (about 365 days) and the
   member's open_id; server.js seals both tokens with lib/apiKeyCrypto.js
   before TikTok is asked anything (the user read), and lib/tiktokApi.js
   refreshes the access token with a compare-and-set on token_version.

   THE FLOW.
     1. POST /api/tiktok/start (a signed-in member): newState. Only its sha256
        (stateHash) is stored, in oauth_states, purpose tiktok_login, with no
        verifier and no flow_context, for STATE_TTL_MS. The member is sent to
        authorizeUrl.
     2. TikTok sends the browser back to FRONTEND_URL + "/agents/social.html"
        with ?code and ?state. scripts/tiktok.js POSTs both to
        POST /api/tiktok/finish, a requireAuth route, so the code is bound to
        the signed-in member; the state row is consumed by one conditional
        update (this member, this purpose, not consumed, not expired).
     3. exchangeCode; grantsTiktok checks BOTH scopes were granted; the tokens
        are sealed; the user is read; the row is stored.

   TIKTOK'S RULES THIS FOLLOWS (from TikTok's developer documentation, as the
   build brief states them; not re-checked against TikTok in this build, which
   made no call to TikTok):
     - the authorize page takes client_key (not client_id) and a
       comma-separated scope;
     - the token endpoint takes a form; a refresh MAY return a new refresh
       token: it is stored, and the old one kept when none comes back;
     - every answer carries refresh_expires_in; a refused refresh
       (invalid_grant) means the access is gone;
     - revoke is a form POST of client_key, client_secret and token.

   ALL I/O is through deps.request (lib/guardedFetch.js guardedJsonRequest,
   https on 443 only, every address checked, no redirect followed). Nothing
   here logs, and no token or code is ever put into an error, a result a
   member sees, or a log line. A TiktokError carries only a kind and a short
   code.
   ══════════════════════════════════════════════════════════════════════════ */

const crypto = require("crypto");

const AUTHORIZE_URL = "https://www.tiktok.com/v2/auth/authorize/";
const TOKEN_URL = "https://open.tiktokapis.com/v2/oauth/token/";
const REVOKE_URL = "https://open.tiktokapis.com/v2/oauth/revoke/";
const USER_SCOPE = "user.info.basic";
const PUBLISH_SCOPE = "video.publish";
const SCOPE = USER_SCOPE + "," + PUBLISH_SCOPE;
const PURPOSE = "tiktok_login";
const STATE_TTL_MS = 10 * 60 * 1000;
const TOKEN_TIMEOUT_MS = 15 * 1000;
const REVOKE_TIMEOUT_MS = 5 * 1000;
/* An access token is stored as expiring this much before TikTok says it does. */
const EXPIRY_SLACK_MS = 60 * 1000;
const STATE_RE = /^[A-Za-z0-9_-]{43}$/;
const CODE_MAX = 4096;
const OPEN_ID_RE = /^[A-Za-z0-9_.-]{1,100}$/;
/* oauth_states rows older than this are deleted by start, for the member. */
const STATES_RETENTION_MS = 24 * 60 * 60 * 1000;

const MESSAGES = Object.freeze({
  notConfigured: "TikTok connection isn't set up yet.",
  noScopes: "TikTok didn't grant both permissions. Connect again and allow BizForce to see your account and post videos.",
  stateInvalid: "That sign-in link has expired or was already used. Start again.",
  unreachable: "BizForce could not finish the TikTok sign-in just now. Try again later. Nothing was saved.",
  badRequest: "That sign-in answer was not complete. Start again.",
  noSecret: "TikTok connection can't run right now (the server's encryption key is missing). Nothing was saved.",
  disconnected: "Disconnected. BizForce asked TikTok to cancel its access to your account."
});

const deps = {
  request: function (url, options) { return require("./guardedFetch").guardedJsonRequest(url, options); },
  randomBytes: function (n) { return crypto.randomBytes(n); },
  now: function () { return Date.now(); }
};

/* kind: invalid_grant, no_scopes or unreachable. */
function TiktokError(kind, code) {
  this.name = "TiktokError";
  this.kind = kind;
  this.code = code;
  this.message = "tiktok " + kind + " (" + code + ")";
}
TiktokError.prototype = Object.create(Error.prototype);

function base64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/* { clientKey, clientSecret } when both env vars are set, else null. */
function configured(env) {
  env = env || process.env;
  var key = typeof env.TIKTOK_CLIENT_KEY === "string" ? env.TIKTOK_CLIENT_KEY.trim() : "";
  var secret = typeof env.TIKTOK_CLIENT_SECRET === "string" ? env.TIKTOK_CLIENT_SECRET.trim() : "";
  if (!key || !secret) return null;
  return { clientKey: key, clientSecret: secret };
}

/* 32 random bytes, base64url: 43 characters. */
function newState() { return base64url(deps.randomBytes(32)); }
/* What is stored for a state: its sha256, hex. The state itself never is. */
function stateHash(state) { return crypto.createHash("sha256").update(String(state), "utf8").digest("hex"); }

function authorizeUrl(clientKey, redirectUri, state) {
  var q = new URLSearchParams();
  q.append("client_key", clientKey);
  q.append("scope", SCOPE);
  q.append("response_type", "code");
  q.append("redirect_uri", redirectUri);
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

/* Does the granted scope hold BOTH permissions? TikTok answers with a comma-separated list. */
function grantsTiktok(scope) {
  if (typeof scope !== "string") return false;
  var have = scope.split(/[,\s]+/).filter(Boolean);
  return have.indexOf(USER_SCOPE) !== -1 && have.indexOf(PUBLISH_SCOPE) !== -1;
}

function seconds(v) {
  var n = typeof v === "number" ? v : (typeof v === "string" && /^\d{1,9}$/.test(v) ? Number(v) : NaN);
  return Number.isInteger(n) && n >= 1 ? n : null;
}

/* A token answer, checked. Never returns or logs the answer itself.
   exchange: the code exchange must carry a refresh token, the open_id and both scopes; a refresh need not. */
function grantFrom(json, exchange) {
  var j = json && typeof json === "object" ? json : {};
  if (typeof j.access_token !== "string" || !j.access_token) throw new TiktokError("unreachable", "token_shape");
  var refresh = typeof j.refresh_token === "string" && j.refresh_token ? j.refresh_token : null;
  if (exchange && !refresh) throw new TiktokError("unreachable", "no_refresh_token");
  var openId = typeof j.open_id === "string" && OPEN_ID_RE.test(j.open_id) ? j.open_id : null;
  if (exchange && !openId) throw new TiktokError("unreachable", "no_open_id");
  if (exchange && !grantsTiktok(j.scope)) throw new TiktokError("no_scopes", "scope_missing");
  var expiresIn = seconds(j.expires_in);
  if (expiresIn === null) throw new TiktokError("unreachable", "token_expiry");
  return {
    accessToken: j.access_token,
    refreshToken: refresh,
    openId: openId,
    expiresIn: expiresIn,
    refreshExpiresIn: seconds(j.refresh_expires_in),
    scope: typeof j.scope === "string" ? j.scope : null
  };
}

/* One form POST to the token endpoint. A body naming an error (TikTok may send
   one with any status) is a failure: invalid_grant is its own kind; anything
   else, and any failure to reach it, is unreachable. */
async function tokenRequest(form, exchange) {
  var answer;
  try {
    answer = await deps.request(TOKEN_URL, { method: "POST", form: form, timeoutMs: TOKEN_TIMEOUT_MS });
  } catch (err) {
    throw new TiktokError("unreachable", "token_request");
  }
  var status = answer && answer.status;
  var j = answer && answer.json && typeof answer.json === "object" ? answer.json : {};
  var named = typeof j.error === "string" && j.error ? j.error : null;
  if (named === "invalid_grant") throw new TiktokError("invalid_grant", "invalid_grant");
  if (named || typeof status !== "number" || status < 200 || status >= 300) {
    throw new TiktokError("unreachable", "token_status_" + (typeof status === "number" ? status : "none"));
  }
  return grantFrom(j, exchange);
}

function exchangeCode(config, code, redirectUri) {
  return tokenRequest({
    client_key: config.clientKey,
    client_secret: config.clientSecret,
    code: code,
    grant_type: "authorization_code",
    redirect_uri: redirectUri
  }, true);
}

/* refreshToken null in the result: TikTok sent none, so the caller keeps the one it holds. */
function refreshTokens(config, refreshToken) {
  return tokenRequest({
    client_key: config.clientKey,
    client_secret: config.clientSecret,
    grant_type: "refresh_token",
    refresh_token: refreshToken
  }, false);
}

/* Best effort: true when TikTok answered 2xx with no error, false for anything else. Never throws. */
async function revoke(config, token) {
  try {
    var answer = await deps.request(REVOKE_URL, { method: "POST", timeoutMs: REVOKE_TIMEOUT_MS, emptyOk: true,
      form: { client_key: config.clientKey, client_secret: config.clientSecret, token: String(token || "") } });
    var named = answer && answer.json && typeof answer.json === "object" && typeof answer.json.error === "string" && answer.json.error;
    return !!(answer && typeof answer.status === "number" && answer.status >= 200 && answer.status < 300 && !named);
  } catch (err) {
    return false;
  }
}

module.exports = {
  AUTHORIZE_URL: AUTHORIZE_URL,
  TOKEN_URL: TOKEN_URL,
  REVOKE_URL: REVOKE_URL,
  USER_SCOPE: USER_SCOPE,
  PUBLISH_SCOPE: PUBLISH_SCOPE,
  SCOPE: SCOPE,
  PURPOSE: PURPOSE,
  STATE_TTL_MS: STATE_TTL_MS,
  TOKEN_TIMEOUT_MS: TOKEN_TIMEOUT_MS,
  REVOKE_TIMEOUT_MS: REVOKE_TIMEOUT_MS,
  EXPIRY_SLACK_MS: EXPIRY_SLACK_MS,
  STATE_RE: STATE_RE,
  CODE_MAX: CODE_MAX,
  OPEN_ID_RE: OPEN_ID_RE,
  STATES_RETENTION_MS: STATES_RETENTION_MS,
  MESSAGES: MESSAGES,
  deps: deps,
  TiktokError: TiktokError,
  configured: configured,
  newState: newState,
  stateHash: stateHash,
  authorizeUrl: authorizeUrl,
  finishShape: finishShape,
  grantsTiktok: grantsTiktok,
  exchangeCode: exchangeCode,
  refreshTokens: refreshTokens,
  revoke: revoke
};
