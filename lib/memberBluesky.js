/* ══════════════════════════════════════════════════════════════════════════
   lib/memberBluesky.js — a member's OWN Bluesky account, connected with an
   app password (migration 152, member_social_connections).

   The platform's own account (BLUESKY_IDENTIFIER, one session shared by Lead
   Radar and the outreach sender through lib/bskyGate.js) is not touched here.
   A member's account gets its own session, made for one action and dropped:

   ONE LOGIN, ONE CALL, NO RETRY. withSession logs in once with the member's
   handle and decrypted app password, runs one call, and returns. A login
   Bluesky refuses, or a call it answers with an expired or refused session,
   is "session_failed": server.js then marks the connection needs_reconnect
   and tells the member once. Nothing here loops, sleeps or tries again,
   because retrying a refused password is how an account gets locked.

   THE PASSWORD NEVER LEAVES THIS FILE IN THE CLEAR. It is decrypted inside
   withSession, handed to the login, and dropped. No message built here
   contains it, and errors are reduced to a short code (last_error_code), never
   Bluesky's own words.

   `api.createAgent` is the one place an agent is made, so a check can replace
   it with a stub and nothing reaches the network.
   ══════════════════════════════════════════════════════════════════════════ */

const gate = require("./bskyGate");

const PLATFORM = "bluesky";
const SERVICE = "https://bsky.social";

// A handle is a domain name: labels of letters, digits and hyphens, a dot
// between each, at most 253 characters. Checked after a leading "@" and
// surrounding space are dropped and it is lowercased.
const HANDLE_RE = /^(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

// Bluesky makes app passwords as four groups of four lowercase letters or digits.
const APP_PASSWORD_RE = /^[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/;

const APP_PASSWORD_HELP = "Use an app password from Bluesky Settings → Privacy and security → App passwords";

const MESSAGES = {
  handle: "Enter your Bluesky handle, like yourname.bsky.social. Nothing was saved.",
  passwordMissing: APP_PASSWORD_HELP + ". Nothing was saved.",
  format: "An app password is four groups of four lowercase letters or numbers, like abcd-efgh-ijkl-mnop. " +
    APP_PASSWORD_HELP + ". Nothing was saved.",
  mainPassword: "That looks like a main account password, and BizForce never takes one. " + APP_PASSWORD_HELP +
    ". Nothing was saved.",
  rejected: "Bluesky didn't accept that handle and app password",
  unreachable: "Bluesky couldn't be reached just now, so nothing was saved. Try again in a few minutes.",
  rateLimited: "Bluesky is limiting sign-ins right now, so nothing was saved. Try again later.",
  noSecret: "Bluesky can't be connected on this server just now: its encryption key is not set. Nothing was sent to Bluesky and nothing was saved."
};

// The profile fields this block may change, and their limits in graphemes.
const DISPLAY_NAME_MAX = 64;
const DESCRIPTION_MAX = 256;

/* The handle, normalized, or null when it is not one. */
function normalizeHandle(raw) {
  if (typeof raw !== "string") return null;
  var h = raw.trim().replace(/^@/, "").toLowerCase();
  return HANDLE_RE.test(h) ? h : null;
}

/* { ok: true, value } or { ok: false, code, error }. Anything that is not an
   app password is refused. A value shaped like dash-separated short groups is
   a mistyped app password ("format"); anything else is treated as what it most
   likely is, a main account password ("looks_like_main_password"). */
function checkAppPassword(raw) {
  var value = typeof raw === "string" ? raw.trim() : "";
  if (!value) return { ok: false, code: "app_password_required", error: MESSAGES.passwordMissing };
  if (APP_PASSWORD_RE.test(value)) return { ok: true, value: value };
  var groups = value.split("-");
  var shaped = groups.length >= 3 && groups.every(function (g) { return /^[A-Za-z0-9]{1,6}$/.test(g); });
  return shaped
    ? { ok: false, code: "app_password_format", error: MESSAGES.format }
    : { ok: false, code: "looks_like_main_password", error: MESSAGES.mainPassword };
}

/* What a thrown Bluesky error means here: "rate_limited", "rejected" (the
   handle and password, or the session, were refused) or "unreachable"
   (anything else: no answer, a 5xx, a network error). Status codes and
   Bluesky's error names are read, never message text. */
var REFUSED_ERRORS = ["AuthenticationRequired", "AuthFactorTokenRequired", "InvalidRequest", "AccountTakedown",
  "AccountDeactivated", "ExpiredToken", "InvalidToken"];
function classify(err) {
  if (gate.isRateLimit(err)) return "rate_limited";
  var status = err && Number(err.status);
  if (status === 400 || status === 401 || status === 403) return "rejected";
  if (err && REFUSED_ERRORS.indexOf(String(err.error || "")) !== -1) return "rejected";
  return "unreachable";
}

const api = {
  createAgent: function () {
    var BskyAgent = require("@atproto/api").BskyAgent;
    return new BskyAgent({ service: SERVICE });
  }
};

/* Connect: one login with what the member typed. { ok: true, did, handle } or
   { ok: false, kind } with kind rejected, rate_limited or unreachable. */
async function verify(handle, password) {
  var agent = api.createAgent();
  try {
    await agent.login({ identifier: handle, password: password });
  } catch (err) {
    return { ok: false, kind: classify(err) };
  }
  var session = agent.session || {};
  if (typeof session.did !== "string" || session.did.indexOf("did:") !== 0) {
    return { ok: false, kind: "unreachable" };
  }
  return { ok: true, did: session.did, handle: normalizeHandle(session.handle) || handle };
}

/* fn(agent) under the member's own session: one login, one call, no retry.
   `row` is their member_social_connections row; `decrypt` is
   lib/apiKeyCrypto.js's. Resolves { ok: true, value } or { ok: false, reason,
   code } with reason:
     session_failed  the stored password no longer signs in, or the session
                     was refused (server.js marks needs_reconnect)
     rate_limited    Bluesky said to slow down
     unreachable     no answer at the login
     call_failed     the login worked and the call itself failed
   Never throws. */
async function withSession(row, decrypt, fn) {
  var password;
  try {
    password = decrypt({ ciphertext: row.app_password_ciphertext, iv: row.app_password_iv, authTag: row.app_password_auth_tag });
  } catch (err) {
    return { ok: false, reason: "session_failed", code: "password_unreadable" };
  }
  var agent = api.createAgent();
  try {
    await agent.login({ identifier: row.handle, password: password });
  } catch (err) {
    var kind = classify(err);
    if (kind === "rejected") return { ok: false, reason: "session_failed", code: "login_rejected" };
    return { ok: false, reason: kind, code: kind === "rate_limited" ? "login_rate_limited" : "login_unreachable" };
  } finally {
    password = null;
  }
  var session = agent.session || {};
  if (row.did && session.did !== row.did) {
    // The handle now belongs to a different account than the one connected.
    return { ok: false, reason: "session_failed", code: "account_changed" };
  }
  try {
    return { ok: true, value: await fn(agent) };
  } catch (err) {
    if (gate.isRateLimit(err)) return { ok: false, reason: "rate_limited", code: "call_rate_limited" };
    // 401, AuthRequired or ExpiredToken: the session itself was refused. Any
    // other error (a record Bluesky rejected, a 5xx) is the call failing.
    if (gate.isAuthExpired(err)) return { ok: false, reason: "session_failed", code: "session_refused" };
    return { ok: false, reason: "call_failed", code: "call_failed" };
  }
}

/* The only fields GET /api/social/bluesky/status returns. */
function statusOf(row) {
  if (!row) return { connected: false, handle: null, status: "disconnected", since: null };
  return { connected: row.status === "connected", handle: "@" + row.handle, status: row.status, since: row.created_at || null };
}

/* The profile update a proposal names: only displayName and description, set
   onto the record Bluesky already holds, so the avatar, the banner and every
   other field are carried over untouched. */
function profileUpdater(fields) {
  return function (existing) {
    var next = Object.assign({}, existing || {});
    if (typeof fields.display_name === "string") next.displayName = fields.display_name;
    if (typeof fields.description === "string") next.description = fields.description;
    return next;
  };
}

module.exports = {
  PLATFORM, SERVICE, HANDLE_RE, APP_PASSWORD_RE, APP_PASSWORD_HELP, MESSAGES, DISPLAY_NAME_MAX, DESCRIPTION_MAX,
  api, normalizeHandle, checkAppPassword, classify, verify, withSession, statusOf, profileUpdater
};
