/* ══════════════════════════════════════════════════════════════════════════
   lib/bskyGate.js — the one way this process logs in to Bluesky and calls it.

   There is one Bluesky account (BLUESKY_IDENTIFIER) and one in-memory session.
   The Lead Radar (leadRadar.js, 32 searches every five minutes) and the
   outreach sender (server.js sendBlueskyReply) both go through this gate, so
   neither can hammer the login the other depends on. What it enforces:

   ONE SESSION, REUSED. A login happens only when there is no session, and
   again at most once in a call when Bluesky answers 401 / AuthRequired /
   ExpiredToken. A caller may also pass a per-tick budget ({ logins: 1 }): the
   radar does, so a tick makes at most one login attempt whatever happens — a
   failed login ends the tick's Bluesky work instead of being retried for each
   keyword.

   BACK-OFF ON 429. A 429 (status 429 or error "RateLimitExceeded") on the
   login or on any call sets a "do not call Bluesky until" time:
     - retry-after (a duration in seconds), when the response carries it;
     - else ratelimit-reset (an EPOCH SECOND, converted to a remaining wait);
     - else 15 minutes, doubling on each consecutive 429 up to 2 hours.
   The first success resets the doubling. While the back-off is in force, call()
   and login() refuse WITHOUT calling Bluesky and say how long is left. Never a
   retry, sleep or backoff loop here: retrying into a rate limit is how a limit
   becomes a suspension, and this is the account the radar captures with.

   `now` is injectable so the check can run on a fake clock.
   ══════════════════════════════════════════════════════════════════════════ */

var FALLBACK_BACKOFF_MS = 15 * 60 * 1000;
var MAX_BACKOFF_MS = 2 * 60 * 60 * 1000;

/* Is this thrown thing Bluesky telling us to stop? Status codes are the
   evidence; message text is never matched, because a false positive would
   stop work that had no reason to stop. Shapes beyond the SDK's own
   (statusCode, response.status) are read because the value may have been
   through a catch. */
function isRateLimit(err) {
  if (!err) return false;
  var status = err.status;
  if (status == null) status = err.statusCode;
  if (status == null && err.response) status = err.response.status;
  if (Number(status) === 429) return true;
  return String(err.error || "") === "RateLimitExceeded";
}

function isAuthExpired(err) {
  if (!err) return false;
  return Number(err.status) === 401 || err.error === "AuthRequired" || err.error === "ExpiredToken";
}

/* The wait the response asks for, in ms, or null when it names none.
   retry-after is a duration; ratelimit-reset is an epoch SECOND (reading it as
   a duration would mean a wait of about fifty-six years). Presence is tested
   before parsing: Number(null) is 0, which would read a missing header as
   "retry now". */
function requestedWaitMs(err, nowMs) {
  var headers = (err && (err.headers || (err.response && err.response.headers))) || null;
  if (!headers || typeof headers !== "object") return null;
  function header(name) {
    if (typeof headers.get === "function") {
      try { return headers.get(name); } catch (getErr) { /* not a Headers */ }
    }
    return headers[name] != null ? headers[name] : headers[name.toUpperCase()];
  }
  function headerNumber(name) {
    var raw = header(name);
    if (raw == null || String(raw).trim() === "") return null;
    var parsed = Number(raw);
    return Number.isFinite(parsed) ? parsed : null;
  }
  var retryAfter = headerNumber("retry-after");
  if (retryAfter != null && retryAfter >= 0) return Math.round(retryAfter * 1000);
  var reset = headerNumber("ratelimit-reset");
  if (reset != null && reset > 0) return Math.max(0, Math.round(reset * 1000 - nowMs));
  return null;
}

function createBskyGate(options) {
  var agent = options.agent;
  var credentials = options.credentials || function () { return { identifier: null, password: null }; };
  var now = options.now || function () { return Date.now(); };
  var log = options.log || console;

  var loggedIn = false;
  var backoffUntil = 0;
  var consecutive429 = 0;
  var loginAttempts = 0;

  function backoffRemainingMs() {
    return Math.max(0, backoffUntil - now());
  }
  function rateLimited(extra) {
    var remaining = backoffRemainingMs();
    return Object.assign({
      ok: false,
      reason: "rate_limited",
      retry_after_seconds: Math.ceil(remaining / 1000),
      resumes_at: new Date(backoffUntil).toISOString()
    }, extra || {});
  }
  function noteRateLimit(err, where) {
    consecutive429++;
    var asked = requestedWaitMs(err, now());
    var wait = asked != null
      ? asked
      : Math.min(FALLBACK_BACKOFF_MS * Math.pow(2, consecutive429 - 1), MAX_BACKOFF_MS);
    backoffUntil = now() + wait;
    log.error("[BskyGate] RATE LIMITED by Bluesky at " + where + " — no Bluesky call until " +
      new Date(backoffUntil).toISOString() + " (" + Math.round(wait / 1000) + "s" +
      (asked != null ? ", as the response asked" : ", fallback, 429 number " + consecutive429 + " in a row") + ").");
  }
  function noteSuccess() {
    consecutive429 = 0;
  }

  /* One login attempt, unless the back-off or the caller's budget says no. */
  async function login(budget) {
    if (backoffRemainingMs() > 0) return rateLimited();
    var cred = credentials() || {};
    if (!cred.identifier || !cred.password) {
      return { ok: false, reason: "no_credentials" };
    }
    if (budget) {
      if (!(budget.logins > 0)) return { ok: false, reason: "login_budget_spent" };
      budget.logins--;
    }
    loginAttempts++;
    try {
      await agent.login({ identifier: cred.identifier, password: cred.password });
      loggedIn = true;
      noteSuccess();
      return { ok: true };
    } catch (err) {
      loggedIn = false;
      if (isRateLimit(err)) {
        noteRateLimit(err, "login");
        return rateLimited({ error: (err && err.message) || String(err) });
      }
      log.error("[BskyGate] Bluesky login failed:", (err && err.message) || err);
      return { ok: false, reason: "login_failed", error: (err && err.message) || String(err) };
    }
  }

  // The session, reused; a login only when there is none.
  async function ensureSession(budget) {
    if (backoffRemainingMs() > 0) return rateLimited();
    if (loggedIn) return { ok: true };
    return login(budget);
  }

  /* fn(agent) through the gate. Resolves { ok: true, value } or the reason it
     did not run; a non-auth, non-429 error from fn is thrown to the caller. */
  async function call(fn, budget) {
    var session = await ensureSession(budget);
    if (!session.ok) return session;
    try {
      var value = await fn(agent);
      noteSuccess();
      return { ok: true, value: value };
    } catch (err) {
      if (isRateLimit(err)) {
        noteRateLimit(err, "a call");
        return rateLimited({ error: (err && err.message) || String(err) });
      }
      if (!isAuthExpired(err)) throw err;
      // The session expired: one fresh login, then the call once more.
      log.warn("[BskyGate] Bluesky session expired; logging in again once.");
      loggedIn = false;
      var again = await login(budget);
      if (!again.ok) return again;
      try {
        var retried = await fn(agent);
        noteSuccess();
        return { ok: true, value: retried };
      } catch (retryErr) {
        if (isRateLimit(retryErr)) {
          noteRateLimit(retryErr, "a call");
          return rateLimited({ error: (retryErr && retryErr.message) || String(retryErr) });
        }
        if (isAuthExpired(retryErr)) {
          loggedIn = false;
          return { ok: false, reason: "auth_failed", error: (retryErr && retryErr.message) || String(retryErr) };
        }
        throw retryErr;
      }
    }
  }

  return {
    agent: agent,
    call: call,
    ensureSession: ensureSession,
    backoffRemainingMs: backoffRemainingMs,
    backoffUntil: function () { return backoffUntil; },
    stats: function () { return { loginAttempts: loginAttempts, loggedIn: loggedIn, consecutive429: consecutive429, backoffUntil: backoffUntil }; }
  };
}

module.exports = { createBskyGate, isRateLimit, isAuthExpired, requestedWaitMs, FALLBACK_BACKOFF_MS, MAX_BACKOFF_MS };
