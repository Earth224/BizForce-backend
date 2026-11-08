"use strict";

/* ══════════════════════════════════════════════════════════════════════════
   CONNECT FACEBOOK, a Page the member manages, with Facebook Login (migration
   180). OAuth 2.0 authorization code with a single-use state and NO PKCE:
   oauth_states keeps no verifier for purpose facebook_login (180's verifier
   rule allows that).

   THE FLOW.
     1. POST /api/facebook/start (a signed-in member): newState. Only its
        sha256 (stateHash) is stored, in oauth_states, purpose
        facebook_login, for STATE_TTL_MS. The member is sent to authorizeUrl.
     2. Facebook sends the browser back to FRONTEND_URL +
        "/agents/social.html" with ?code and ?state. scripts/oauth-return.js
        hands them to scripts/facebook.js, which POSTs both to
        POST /api/facebook/finish, a requireAuth route; the state row is
        consumed by one conditional update.
     3. exchangeCode gives a SHORT-LIVED user token, which is never stored:
        longLived exchanges it at once for the long-lived one (about 60 days).
        server.js seals that with lib/apiKeyCrypto.js BEFORE Facebook is asked
        anything else; then the granted permissions (all three of SCOPES, or
        nothing is saved) and the member's Pages (lib/facebookApi.js).
     4. One Page the member can post to (its tasks include CREATE_CONTENT):
        its Page token is sealed and stored, and the user token is let go.
        Several: the row waits, status choosing, holding only the sealed user
        token, until POST /api/facebook/choose-page names one of them; a
        choosing row older than CHOOSING_TTL_MS is deleted by the daily chain.
   A Page token obtained with a long-lived user token does not expire, so
   there is no refresh.

   FACEBOOK'S RULES THIS FOLLOWS (from Meta's developer documentation, as the
   build brief states them; not re-checked against Facebook in this build,
   which made no call to Meta or Facebook):
     - the dialog takes client_id, redirect_uri, state, response_type=code
       and a comma-separated scope;
     - the code exchange and the long-lived exchange are GETs on
       /oauth/access_token whose query carries the app secret.

   ALL I/O is through deps.request (lib/guardedFetch.js guardedJsonRequest,
   https on 443 only, every address checked, no redirect followed). Nothing
   here logs. Both exchanges put a secret in the URL, so their failures are
   caught whole and replaced: no error message, detail or URL from them ever
   leaves this file. A FacebookError carries only a kind and a short code.
   ══════════════════════════════════════════════════════════════════════════ */

const crypto = require("crypto");

const GRAPH_VERSION = "v26.0";
const AUTHORIZE_URL = "https://www.facebook.com/" + GRAPH_VERSION + "/dialog/oauth";
const TOKEN_URL = "https://graph.facebook.com/" + GRAPH_VERSION + "/oauth/access_token";
const SCOPES = Object.freeze(["pages_show_list", "pages_manage_posts", "pages_read_engagement"]);
const SCOPE = SCOPES.join(",");
const PURPOSE = "facebook_login";
const STATE_TTL_MS = 10 * 60 * 1000;
const TOKEN_TIMEOUT_MS = 15 * 1000;
/* A long-lived user token is stored as expiring this much before Facebook says it does. */
const EXPIRY_SLACK_MS = 60 * 1000;
/* A row waiting for the member to choose a Page is deleted after this long. */
const CHOOSING_TTL_MS = 60 * 60 * 1000;
const STATE_RE = /^[A-Za-z0-9_-]{43}$/;
const CODE_MAX = 4096;
const STATES_RETENTION_MS = 24 * 60 * 60 * 1000;

const MESSAGES = Object.freeze({
  notConfigured: "Facebook connection isn't set up yet.",
  noScopes: "Facebook didn't grant the access needed. Connect again and approve all permissions.",
  noPage: "No Facebook Page you manage can be posted to. Create a Page or ask for posting access, then connect again.",
  stateInvalid: "That sign-in link has expired or was already used. Start again.",
  unreachable: "BizForce could not finish the Facebook sign-in just now. Try again later. Nothing was saved.",
  badRequest: "That sign-in answer was not complete. Start again.",
  noSecret: "Facebook connection can't run right now (the server's encryption key is missing). Nothing was saved.",
  choiceExpired: "Choosing a Page took too long. Connect Facebook again.",
  notChoosing: "There is no Page to choose right now. Connect Facebook first.",
  notListed: "That Page isn't one you can post to. Choose a Page from the list.",
  disconnected: "Disconnected. To remove BizForce from Facebook too, open Facebook's settings, then Business integrations."
});

const deps = {
  request: function (url, options) { return require("./guardedFetch").guardedJsonRequest(url, options); },
  randomBytes: function (n) { return crypto.randomBytes(n); },
  now: function () { return Date.now(); }
};

/* kind: invalid_grant or unreachable. */
function FacebookError(kind, code) {
  this.name = "FacebookError";
  this.kind = kind;
  this.code = code;
  this.message = "facebook " + kind + " (" + code + ")";
}
FacebookError.prototype = Object.create(Error.prototype);

function base64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/* { appId, appSecret } when both env vars are set, else null. */
function configured(env) {
  env = env || process.env;
  var id = typeof env.FACEBOOK_APP_ID === "string" ? env.FACEBOOK_APP_ID.trim() : "";
  var secret = typeof env.FACEBOOK_APP_SECRET === "string" ? env.FACEBOOK_APP_SECRET.trim() : "";
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
  q.append("state", state);
  q.append("response_type", "code");
  q.append("scope", SCOPE);
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
   commas only, at most 500 characters; null when there are none. */
function scopesOf(list) {
  var words = (Array.isArray(list) ? list : []).filter(function (w) { return typeof w === "string" && /^[a-z_]{1,100}$/.test(w); });
  var joined = words.join(",");
  return joined && joined.length <= 500 ? joined : null;
}
/* All three permissions granted? An empty or missing list is a refusal. */
function grantsAll(list) {
  var have = Array.isArray(list) ? list : [];
  return SCOPES.every(function (s) { return have.indexOf(s) !== -1; });
}

function seconds(v) {
  var n = typeof v === "number" ? v : (typeof v === "string" && /^\d{1,10}$/.test(v) ? Number(v) : NaN);
  return Number.isInteger(n) && n >= 1 ? n : null;
}

/* A Graph error that means the token or the code is no good: code 190
   (invalid token) or 102 (session). A Graph error's type alone says nothing:
   a rate limit is typed OAuthException too. */
function refusedGrant(json) {
  var e = json && typeof json === "object" && json.error && typeof json.error === "object" ? json.error : null;
  return !!e && (e.code === 190 || e.code === 102);
}

/* One GET whose URL carries a secret. Every failure is replaced whole.
   badRequestRefuses: a 400 counts as a refused code (the code exchange,
   where Facebook answers 400 for a used or wrong code). */
async function secretGet(url, codeOnFail, badRequestRefuses) {
  var answer;
  try {
    answer = await deps.request(url, { method: "GET", timeoutMs: TOKEN_TIMEOUT_MS });
  } catch (err) {
    // Not err.message, err.detail or the URL: the URL holds a secret.
    throw new FacebookError("unreachable", codeOnFail);
  }
  var status = answer && answer.status;
  var j = answer && answer.json && typeof answer.json === "object" ? answer.json : {};
  if (typeof status !== "number" || status < 200 || status >= 300) {
    if (refusedGrant(j) || status === 401 || (badRequestRefuses && status === 400)) throw new FacebookError("invalid_grant", "invalid_grant");
    throw new FacebookError("unreachable", codeOnFail + "_" + (typeof status === "number" ? status : "none"));
  }
  if (typeof j.access_token !== "string" || !j.access_token) throw new FacebookError("unreachable", "token_shape");
  return { accessToken: j.access_token, expiresIn: seconds(j.expires_in) };
}

/* The code for a short-lived user token: { accessToken, expiresIn }. Used
   once, at once, by longLived, and never stored. */
function exchangeCode(config, code, redirectUri) {
  var q = new URLSearchParams();
  q.append("client_id", config.appId);
  q.append("redirect_uri", redirectUri);
  q.append("client_secret", config.appSecret);
  q.append("code", code);
  return secretGet(TOKEN_URL + "?" + q.toString(), "token_request", true);
}

/* The short-lived user token for a long-lived one: { accessToken, expiresIn }. */
function longLived(config, shortToken) {
  var q = new URLSearchParams();
  q.append("grant_type", "fb_exchange_token");
  q.append("client_id", config.appId);
  q.append("client_secret", config.appSecret);
  q.append("fb_exchange_token", shortToken);
  return secretGet(TOKEN_URL + "?" + q.toString(), "long_lived", false);
}

/* When the user token expires: now + expires_in, less the slack; null when Facebook named no expiry. */
function expiresAt(nowMs, expiresIn) {
  return expiresIn ? new Date(nowMs + expiresIn * 1000 - EXPIRY_SLACK_MS).toISOString() : null;
}

/* Has a choosing row waited too long? */
function choosingExpired(row, nowMs) {
  var made = Date.parse((row && row.created_at) || "");
  return !isFinite(made) || nowMs - made >= CHOOSING_TTL_MS;
}

module.exports = {
  GRAPH_VERSION: GRAPH_VERSION,
  AUTHORIZE_URL: AUTHORIZE_URL,
  TOKEN_URL: TOKEN_URL,
  SCOPES: SCOPES,
  SCOPE: SCOPE,
  PURPOSE: PURPOSE,
  STATE_TTL_MS: STATE_TTL_MS,
  TOKEN_TIMEOUT_MS: TOKEN_TIMEOUT_MS,
  EXPIRY_SLACK_MS: EXPIRY_SLACK_MS,
  CHOOSING_TTL_MS: CHOOSING_TTL_MS,
  STATE_RE: STATE_RE,
  CODE_MAX: CODE_MAX,
  STATES_RETENTION_MS: STATES_RETENTION_MS,
  MESSAGES: MESSAGES,
  deps: deps,
  FacebookError: FacebookError,
  configured: configured,
  newState: newState,
  stateHash: stateHash,
  authorizeUrl: authorizeUrl,
  finishShape: finishShape,
  scopesOf: scopesOf,
  grantsAll: grantsAll,
  refusedGrant: refusedGrant,
  exchangeCode: exchangeCode,
  longLived: longLived,
  expiresAt: expiresAt,
  choosingExpired: choosingExpired
};
