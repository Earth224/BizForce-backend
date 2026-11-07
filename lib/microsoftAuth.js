"use strict";

/* ══════════════════════════════════════════════════════════════════════════
   SIGN IN WITH MICROSOFT, for Your Inbox (migration 173).
   OAuth 2.0 authorization code with PKCE (S256), for an Outlook.com, Hotmail
   or Microsoft 365 mailbox, which no longer take app passwords. What comes
   back is an access token for IMAP and SMTP and a refresh token; server.js
   seals both with lib/apiKeyCrypto.js before any mail server is asked
   anything, and lib/memberEmail.js uses the access token exactly where it
   used the app password, pinned exactly as before.

   THE FLOW.
     1. POST /api/mailbox/microsoft/start (a signed-in member): newState and
        newVerifier. Only the state's sha256 (stateHash) is stored, in
        oauth_states, with the verifier sealed, for STATE_TTL_MS. The member is
        sent to authorizeUrl.
     2. Microsoft sends the browser back to FRONTEND_URL + "/mailbox.html"
        with ?code and ?state. The page POSTs both to
        POST /api/mailbox/microsoft/finish, a requireAuth route, so the code is
        bound to the signed-in member; the state row is consumed by one
        conditional update (this member, this purpose, not consumed, not
        expired), and a failure never says which of those it was.
     3. exchangeCode sends the code with the verifier; readIdToken reads who
        signed in; the tokens are sealed; verifyConnection runs; the row is
        stored.

   ALL I/O is through deps.request (lib/guardedFetch.js guardedJsonRequest,
   its form mode, https on 443 only, every address checked, no redirect
   followed) and through the database calls server.js makes. Nothing here
   logs, and no token, code, verifier or ID token is ever put into an error,
   a result a member sees, or a log line. A MicrosoftError carries only a kind
   and a short code.
   ══════════════════════════════════════════════════════════════════════════ */

const crypto = require("crypto");

const AUTHORIZE_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
const TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
const IMAP_SCOPE = "https://outlook.office.com/IMAP.AccessAsUser.All";
const SMTP_SCOPE = "https://outlook.office.com/SMTP.Send";
const SCOPE = "offline_access openid email profile " + IMAP_SCOPE + " " + SMTP_SCOPE;
/* The tenant every personal Microsoft account (Outlook.com, Hotmail, Live) signs in under. */
const PERSONAL_TID = "9188040d-6c67-4c5b-b112-36a304b66dad";
const HOSTS = Object.freeze({
  personal: Object.freeze({ imap_host: "outlook.office365.com", imap_port: 993, smtp_host: "smtp-mail.outlook.com", smtp_port: 587 }),
  work: Object.freeze({ imap_host: "outlook.office365.com", imap_port: 993, smtp_host: "smtp.office365.com", smtp_port: 587 })
});
const PURPOSE = "mailbox_microsoft";
const STATE_TTL_MS = 10 * 60 * 1000;
const TOKEN_TIMEOUT_MS = 15 * 1000;
/* An access token is stored as expiring this much before Microsoft says it does. */
const EXPIRY_SLACK_MS = 60 * 1000;
const STATE_RE = /^[A-Za-z0-9_-]{43}$/;
const CODE_MAX = 4096;
const STATE_HASH_RE = /^[0-9a-f]{64}$/;
/* oauth_states rows older than this are deleted: by start, for the member
   signing in, and by oauthStatesPurgeTick, daily, for everyone. */
const STATES_RETENTION_MS = 24 * 60 * 60 * 1000;
const STATES_PURGE_JOB_NAME = "oauth_states_purge";

const MESSAGES = Object.freeze({
  notConfigured: "Outlook sign-in isn't set up yet.",
  noMailAccess: "Microsoft didn't grant mail access. Sign in again and approve both permissions.",
  stateInvalid: "That sign-in link has expired or was already used. Start again.",
  orgBlocked: "Your organisation's settings don't let outside apps read or send mail for this mailbox. Ask your administrator to allow IMAP and SMTP sign-in for it.",
  personalRefused: "Microsoft signed you in, but your mailbox did not accept BizForce's access. Sign in with Microsoft again. Nothing was saved.",
  unreachable: "BizForce could not finish the Microsoft sign-in just now. Try again later. Nothing was saved.",
  badRequest: "That sign-in answer was not complete. Start again.",
  noSecret: "Outlook sign-in can't run right now (the server's encryption key is missing). Nothing was saved.",
  disconnected: "Disconnected. To remove BizForce from your Microsoft account too, open your Microsoft account's app permissions and remove BizForce."
});

const deps = {
  request: function (url, options) { return require("./guardedFetch").guardedJsonRequest(url, options); },
  randomBytes: function (n) { return crypto.randomBytes(n); },
  now: function () { return Date.now(); }
};

/* kind: invalid_grant, no_mail_access, id_token or unreachable. */
function MicrosoftError(kind, code) {
  this.name = "MicrosoftError";
  this.kind = kind;
  this.code = code;
  this.message = "microsoft " + kind + " (" + code + ")";
}
MicrosoftError.prototype = Object.create(Error.prototype);

function base64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/* { clientId, clientSecret } when both env vars are set, else null. */
function configured(env) {
  env = env || process.env;
  var id = typeof env.MS_CLIENT_ID === "string" ? env.MS_CLIENT_ID.trim() : "";
  var secret = typeof env.MS_CLIENT_SECRET === "string" ? env.MS_CLIENT_SECRET.trim() : "";
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
  q.append("response_type", "code");
  q.append("redirect_uri", redirectUri);
  q.append("response_mode", "query");
  q.append("scope", SCOPE);
  q.append("state", state);
  q.append("code_challenge", challenge);
  q.append("code_challenge_method", "S256");
  q.append("prompt", "select_account");
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

/* Does the granted scope hold both mail permissions? Microsoft answers with the
   full resource names; a bare name is accepted too, case-insensitively. */
function grantsMail(scope) {
  if (typeof scope !== "string") return false;
  var have = scope.toLowerCase().split(/\s+/).filter(Boolean);
  function has(full) {
    var f = full.toLowerCase();
    var bare = f.slice(f.lastIndexOf("/") + 1);
    return have.indexOf(f) !== -1 || have.indexOf(bare) !== -1;
  }
  return has(IMAP_SCOPE) && has(SMTP_SCOPE);
}

/* A token answer, checked. Never returns or logs the answer itself. */
function grantFrom(json) {
  var j = json && typeof json === "object" ? json : {};
  if (typeof j.access_token !== "string" || !j.access_token) throw new MicrosoftError("unreachable", "token_shape");
  if (typeof j.refresh_token !== "string" || !j.refresh_token) throw new MicrosoftError("no_mail_access", "no_refresh_token");
  if (!grantsMail(j.scope)) throw new MicrosoftError("no_mail_access", "scope_missing");
  var expiresIn = typeof j.expires_in === "number" ? j.expires_in : (typeof j.expires_in === "string" && /^\d{1,7}$/.test(j.expires_in) ? Number(j.expires_in) : NaN);
  if (!Number.isInteger(expiresIn) || expiresIn < 1) throw new MicrosoftError("unreachable", "token_expiry");
  return {
    accessToken: j.access_token,
    refreshToken: j.refresh_token,
    expiresIn: expiresIn,
    idToken: typeof j.id_token === "string" ? j.id_token : null
  };
}

/* One form POST to the token endpoint. invalid_grant is its own kind (the
   member must sign in again); any other non-2xx, and any failure to reach it,
   is unreachable. */
async function tokenRequest(form) {
  var answer;
  try {
    answer = await deps.request(TOKEN_URL, { method: "POST", form: form, timeoutMs: TOKEN_TIMEOUT_MS });
  } catch (err) {
    throw new MicrosoftError("unreachable", "token_request");
  }
  var status = answer && answer.status;
  if (typeof status !== "number" || status < 200 || status >= 300) {
    if (answer && answer.json && answer.json.error === "invalid_grant") throw new MicrosoftError("invalid_grant", "invalid_grant");
    throw new MicrosoftError("unreachable", "token_status_" + (typeof status === "number" ? status : "none"));
  }
  return grantFrom(answer.json);
}

function exchangeCode(config, code, verifier, redirectUri) {
  return tokenRequest({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    grant_type: "authorization_code",
    code: code,
    redirect_uri: redirectUri,
    code_verifier: verifier,
    scope: SCOPE
  });
}

function refreshTokens(config, refreshToken, redirectUri) {
  return tokenRequest({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    redirect_uri: redirectUri,
    scope: SCOPE
  });
}

/* Who signed in, from the ID token's payload. The payload is decoded only; the
   signature is NOT checked here. That is safe for this one use: the token came
   straight from the token endpoint, in the answer to our own code exchange,
   over https to a fixed host with verified TLS (guardedJsonRequest), so no one
   else could have put it there. Never use this on an ID token from anywhere
   else. Requires aud === clientId, exp in the future and a tid.
   { email, accountType } or a MicrosoftError("id_token"). */
function readIdToken(idToken, clientId, nowMs) {
  if (typeof idToken !== "string") throw new MicrosoftError("id_token", "missing");
  var parts = idToken.split(".");
  if (parts.length !== 3 || !parts[1]) throw new MicrosoftError("id_token", "shape");
  var claims;
  try {
    claims = JSON.parse(Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
  } catch (err) {
    throw new MicrosoftError("id_token", "payload");
  }
  if (!claims || typeof claims !== "object") throw new MicrosoftError("id_token", "payload");
  if (claims.aud !== clientId) throw new MicrosoftError("id_token", "aud");
  if (typeof claims.exp !== "number" || !(claims.exp * 1000 > nowMs)) throw new MicrosoftError("id_token", "exp");
  if (typeof claims.tid !== "string" || !claims.tid) throw new MicrosoftError("id_token", "tid");
  var raw = typeof claims.preferred_username === "string" && claims.preferred_username ? claims.preferred_username
    : (typeof claims.email === "string" ? claims.email : "");
  var checked = require("./memberEmail").checkEmailAddress(raw.trim().toLowerCase());
  if (!checked.ok) throw new MicrosoftError("id_token", "email");
  return { email: checked.value, accountType: accountTypeFor(claims.tid) };
}

function accountTypeFor(tid) {
  return tid === PERSONAL_TID ? "personal" : "work";
}

function hostsFor(accountType) {
  return accountType === "personal" ? HOSTS.personal : HOSTS.work;
}

/* ── retention: one-time sign-in states, deleted within a day ──────────────
   Run from the 04:45 UTC cron in server.js, after the card leads purge, but
   claimed through its own job_runs row (oauth_states_purge), so neither job's
   record says anything about the other's table. Deletes every row whose
   created_at is more than STATES_RETENTION_MS ago; each is long expired.
   Never rejects. */
async function claimStatesPurgeDay(supabase, nowMs) {
  var today = new Date(nowMs).toISOString().slice(0, 10);
  var started = new Date(nowMs).toISOString();
  var inserted = await supabase
    .from("job_runs")
    .insert({ job_name: STATES_PURGE_JOB_NAME, last_run_on: today, started_at: started, finished_at: null, last_error: null })
    .select("job_name");
  if (!inserted.error) return true;
  // 23505 = unique_violation: the row exists. Anything else is a failure, never a claim.
  if (inserted.error.code !== "23505") {
    console.error("[OauthStatesPurge] Claim insert failed: " + (inserted.error.code || "error"));
    return false;
  }
  var updated = await supabase
    .from("job_runs")
    .update({ last_run_on: today, started_at: started, finished_at: null, last_error: null })
    .eq("job_name", STATES_PURGE_JOB_NAME)
    .or("last_run_on.is.null,last_run_on.neq." + today)
    .select("job_name");
  if (updated.error) {
    console.error("[OauthStatesPurge] Claim update failed: " + (updated.error.code || "error"));
    return false;
  }
  return (updated.data || []).length > 0;
}

async function oauthStatesPurgeTick(supabase, nowMs) {
  var startedMs = typeof nowMs === "number" ? nowMs : deps.now();
  var finish = async function (errorMessage) {
    var patch = { finished_at: new Date(deps.now()).toISOString() };
    if (errorMessage) patch.last_error = String(errorMessage).slice(0, 2000);
    var result = await supabase.from("job_runs").update(patch).eq("job_name", STATES_PURGE_JOB_NAME);
    if (result.error) console.error("[OauthStatesPurge] Failed to record run completion: " + (result.error.code || "error"));
  };
  try {
    if (!(await claimStatesPurgeDay(supabase, startedMs))) return { claimed: false };
    var cutoff = new Date(startedMs - STATES_RETENTION_MS).toISOString();
    var removed = await supabase.from("oauth_states").delete().lt("created_at", cutoff).select("id");
    var error = removed.error ? "oauth_states delete failed: " + (removed.error.code || "error") : null;
    var deleted = removed.error ? 0 : (removed.data || []).length;
    await finish(error);
    console.log("[OauthStatesPurge] Pass finished: " + deleted + " sign-in state(s) older than " + cutoff + " deleted" + (error ? "; stopped: " + error : "") + ".");
    return { claimed: true, cutoff: cutoff, deleted: deleted, error: error };
  } catch (err) {
    console.error("[OauthStatesPurge] Pass error: " + ((err && err.code) || "error"));
    try { await finish((err && err.code) || "error"); } catch (finishErr) { /* reported above */ }
    return { claimed: true, error: (err && err.code) || "error" };
  }
}

module.exports = {
  AUTHORIZE_URL: AUTHORIZE_URL,
  TOKEN_URL: TOKEN_URL,
  IMAP_SCOPE: IMAP_SCOPE,
  SMTP_SCOPE: SMTP_SCOPE,
  SCOPE: SCOPE,
  PERSONAL_TID: PERSONAL_TID,
  HOSTS: HOSTS,
  PURPOSE: PURPOSE,
  STATE_TTL_MS: STATE_TTL_MS,
  TOKEN_TIMEOUT_MS: TOKEN_TIMEOUT_MS,
  EXPIRY_SLACK_MS: EXPIRY_SLACK_MS,
  STATE_RE: STATE_RE,
  STATE_HASH_RE: STATE_HASH_RE,
  CODE_MAX: CODE_MAX,
  STATES_RETENTION_MS: STATES_RETENTION_MS,
  STATES_PURGE_JOB_NAME: STATES_PURGE_JOB_NAME,
  MESSAGES: MESSAGES,
  deps: deps,
  MicrosoftError: MicrosoftError,
  configured: configured,
  newState: newState,
  newVerifier: newVerifier,
  stateHash: stateHash,
  challengeFor: challengeFor,
  authorizeUrl: authorizeUrl,
  finishShape: finishShape,
  grantsMail: grantsMail,
  exchangeCode: exchangeCode,
  refreshTokens: refreshTokens,
  readIdToken: readIdToken,
  accountTypeFor: accountTypeFor,
  hostsFor: hostsFor,
  oauthStatesPurgeTick: oauthStatesPurgeTick
};
