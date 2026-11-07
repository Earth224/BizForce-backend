"use strict";

/* ══════════════════════════════════════════════════════════════════════════
   SIGN IN WITH GOOGLE, for YouTube uploads (migration 177).
   OAuth 2.0 authorization code with PKCE (S256), on the pattern of
   lib/microsoftAuth.js. What comes back is an access token and a refresh token
   for the member's own YouTube channel; server.js seals both with
   lib/apiKeyCrypto.js before YouTube is asked anything (the channel read), and
   lib/youtubeApi.js refreshes the access token with a compare-and-set on
   token_version.

   THE FLOW.
     1. POST /api/youtube/start (a signed-in member): newState and newVerifier.
        Only the state's sha256 (stateHash) is stored, in oauth_states, purpose
        youtube_google, with the verifier sealed and no flow_context, for
        STATE_TTL_MS. The member is sent to authorizeUrl.
     2. Google sends the browser back to FRONTEND_URL + "/agents/social.html"
        with ?code and ?state. The page POSTs both to POST /api/youtube/finish,
        a requireAuth route, so the code is bound to the signed-in member; the
        state row is consumed by one conditional update (this member, this
        purpose, not consumed, not expired), and a failure never says which.
     3. exchangeCode sends the code with the verifier; grantsYoutube checks
        BOTH scopes were granted; the tokens are sealed; the channel is read;
        the row is stored.

   GOOGLE'S RULES THIS FOLLOWS (from Google's OAuth documentation, as the
   build brief states them; not re-checked against Google in this build, which
   made no call to Google):
     - access_type=offline and prompt=consent, so the exchange returns a
       refresh token;
     - a refresh usually returns NO new refresh token: the stored one is kept
       (refreshTokens returns refreshToken null, and the caller keeps its own);
     - invalid_grant means the access is gone (revoked, expired, or, while the
       Google app is in "testing", older than 7 days);
     - revoke is a form POST of token=<refresh token>.

   ALL I/O is through deps.request (lib/guardedFetch.js guardedJsonRequest,
   https on 443 only, every address checked, no redirect followed). Nothing
   here logs, and no token, code or verifier is ever put into an error, a
   result a member sees, or a log line. A GoogleError carries only a kind and
   a short code.
   ══════════════════════════════════════════════════════════════════════════ */

const crypto = require("crypto");

const AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL = "https://oauth2.googleapis.com/token";
const REVOKE_URL = "https://oauth2.googleapis.com/revoke";
const UPLOAD_SCOPE = "https://www.googleapis.com/auth/youtube.upload";
const READONLY_SCOPE = "https://www.googleapis.com/auth/youtube.readonly";
const SCOPE = UPLOAD_SCOPE + " " + READONLY_SCOPE;
const PURPOSE = "youtube_google";
const STATE_TTL_MS = 10 * 60 * 1000;
const TOKEN_TIMEOUT_MS = 15 * 1000;
const REVOKE_TIMEOUT_MS = 5 * 1000;
/* An access token is stored as expiring this much before Google says it does. */
const EXPIRY_SLACK_MS = 60 * 1000;
const STATE_RE = /^[A-Za-z0-9_-]{43}$/;
const CODE_MAX = 4096;
/* oauth_states rows older than this are deleted by start, for the member. */
const STATES_RETENTION_MS = 24 * 60 * 60 * 1000;

const MESSAGES = Object.freeze({
  notConfigured: "YouTube connection isn't set up yet.",
  noScopes: "Google didn't grant both YouTube permissions. Connect again and allow BizForce to upload videos and see your channel.",
  stateInvalid: "That sign-in link has expired or was already used. Start again.",
  noChannel: "This Google account has no YouTube channel. Create one on YouTube, then connect again.",
  unreachable: "BizForce could not finish the Google sign-in just now. Try again later. Nothing was saved.",
  badRequest: "That sign-in answer was not complete. Start again.",
  noSecret: "YouTube connection can't run right now (the server's encryption key is missing). Nothing was saved.",
  disconnected: "Disconnected. BizForce asked Google to cancel its access to your channel."
});

const deps = {
  request: function (url, options) { return require("./guardedFetch").guardedJsonRequest(url, options); },
  randomBytes: function (n) { return crypto.randomBytes(n); },
  now: function () { return Date.now(); }
};

/* kind: invalid_grant, no_scopes or unreachable. */
function GoogleError(kind, code) {
  this.name = "GoogleError";
  this.kind = kind;
  this.code = code;
  this.message = "google " + kind + " (" + code + ")";
}
GoogleError.prototype = Object.create(Error.prototype);

function base64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/* { clientId, clientSecret } when both env vars are set, else null. */
function configured(env) {
  env = env || process.env;
  var id = typeof env.GOOGLE_OAUTH_CLIENT_ID === "string" ? env.GOOGLE_OAUTH_CLIENT_ID.trim() : "";
  var secret = typeof env.GOOGLE_OAUTH_CLIENT_SECRET === "string" ? env.GOOGLE_OAUTH_CLIENT_SECRET.trim() : "";
  if (!id || !secret) return null;
  return { clientId: id, clientSecret: secret };
}

/* 32 random bytes, base64url: 43 characters. */
function newState() { return base64url(deps.randomBytes(32)); }
function newVerifier() { return base64url(deps.randomBytes(32)); }
/* What is stored for a state: its sha256, hex. The state itself never is. */
function stateHash(state) { return crypto.createHash("sha256").update(String(state), "utf8").digest("hex"); }
/* RFC 7636 S256: base64url(sha256(ascii(verifier))). */
function challengeFor(verifier) { return base64url(crypto.createHash("sha256").update(String(verifier), "ascii").digest()); }

function authorizeUrl(clientId, redirectUri, state, challenge) {
  var q = new URLSearchParams();
  q.append("client_id", clientId);
  q.append("redirect_uri", redirectUri);
  q.append("response_type", "code");
  q.append("scope", SCOPE);
  q.append("access_type", "offline");
  q.append("prompt", "consent");
  q.append("state", state);
  q.append("code_challenge", challenge);
  q.append("code_challenge_method", "S256");
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

/* Does the granted scope hold BOTH YouTube permissions? Google answers with a
   space-separated list of the full scope URLs. */
function grantsYoutube(scope) {
  if (typeof scope !== "string") return false;
  var have = scope.split(/\s+/).filter(Boolean);
  return have.indexOf(UPLOAD_SCOPE) !== -1 && have.indexOf(READONLY_SCOPE) !== -1;
}

/* A token answer, checked. Never returns or logs the answer itself.
   needRefresh: the exchange must carry a refresh token; a refresh need not. */
function grantFrom(json, needRefresh, needScopes) {
  var j = json && typeof json === "object" ? json : {};
  if (typeof j.access_token !== "string" || !j.access_token) throw new GoogleError("unreachable", "token_shape");
  var refresh = typeof j.refresh_token === "string" && j.refresh_token ? j.refresh_token : null;
  if (needRefresh && !refresh) throw new GoogleError("unreachable", "no_refresh_token");
  if (needScopes && !grantsYoutube(j.scope)) throw new GoogleError("no_scopes", "scope_missing");
  var expiresIn = typeof j.expires_in === "number" ? j.expires_in : (typeof j.expires_in === "string" && /^\d{1,7}$/.test(j.expires_in) ? Number(j.expires_in) : NaN);
  if (!Number.isInteger(expiresIn) || expiresIn < 1) throw new GoogleError("unreachable", "token_expiry");
  return {
    accessToken: j.access_token,
    refreshToken: refresh,
    expiresIn: expiresIn,
    scope: typeof j.scope === "string" ? j.scope : null
  };
}

/* One form POST to the token endpoint. invalid_grant is its own kind; any
   other non-2xx, and any failure to reach it, is unreachable. */
async function tokenRequest(form, needRefresh, needScopes) {
  var answer;
  try {
    answer = await deps.request(TOKEN_URL, { method: "POST", form: form, timeoutMs: TOKEN_TIMEOUT_MS });
  } catch (err) {
    throw new GoogleError("unreachable", "token_request");
  }
  var status = answer && answer.status;
  if (typeof status !== "number" || status < 200 || status >= 300) {
    if (answer && answer.json && answer.json.error === "invalid_grant") throw new GoogleError("invalid_grant", "invalid_grant");
    throw new GoogleError("unreachable", "token_status_" + (typeof status === "number" ? status : "none"));
  }
  return grantFrom(answer.json, needRefresh, needScopes);
}

function exchangeCode(config, code, verifier, redirectUri) {
  return tokenRequest({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    grant_type: "authorization_code",
    code: code,
    redirect_uri: redirectUri,
    code_verifier: verifier
  }, true, true);
}

/* refreshToken null in the result: Google sent none, so the caller keeps the one it holds. */
function refreshTokens(config, refreshToken) {
  return tokenRequest({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    grant_type: "refresh_token",
    refresh_token: refreshToken
  }, false, false);
}

/* Best effort: true when Google answered 2xx, false for anything else. Never throws. */
async function revoke(refreshToken) {
  try {
    var answer = await deps.request(REVOKE_URL, { method: "POST", form: { token: String(refreshToken || "") }, timeoutMs: REVOKE_TIMEOUT_MS, emptyOk: true });
    return !!(answer && typeof answer.status === "number" && answer.status >= 200 && answer.status < 300);
  } catch (err) {
    return false;
  }
}

module.exports = {
  AUTHORIZE_URL: AUTHORIZE_URL,
  TOKEN_URL: TOKEN_URL,
  REVOKE_URL: REVOKE_URL,
  UPLOAD_SCOPE: UPLOAD_SCOPE,
  READONLY_SCOPE: READONLY_SCOPE,
  SCOPE: SCOPE,
  PURPOSE: PURPOSE,
  STATE_TTL_MS: STATE_TTL_MS,
  TOKEN_TIMEOUT_MS: TOKEN_TIMEOUT_MS,
  REVOKE_TIMEOUT_MS: REVOKE_TIMEOUT_MS,
  EXPIRY_SLACK_MS: EXPIRY_SLACK_MS,
  STATE_RE: STATE_RE,
  CODE_MAX: CODE_MAX,
  STATES_RETENTION_MS: STATES_RETENTION_MS,
  MESSAGES: MESSAGES,
  deps: deps,
  GoogleError: GoogleError,
  configured: configured,
  newState: newState,
  newVerifier: newVerifier,
  stateHash: stateHash,
  challengeFor: challengeFor,
  authorizeUrl: authorizeUrl,
  finishShape: finishShape,
  grantsYoutube: grantsYoutube,
  exchangeCode: exchangeCode,
  refreshTokens: refreshTokens,
  revoke: revoke
};
