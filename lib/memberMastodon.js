/* ══════════════════════════════════════════════════════════════════════════
   lib/memberMastodon.js — a member's OWN Mastodon account, connected with a
   personal access token (migration 165, member_mastodon_connections).

   The platform's MASTODON_ACCESS_TOKEN (outreach replies, server.js
   sendMastodonReply) is never read here, and nothing here falls back to it.

   EVERY REQUEST GOES THROUGH lib/guardedFetch.js's JSON MODE. The server a
   member types is someone else's address: guardedJsonRequest allows https on
   443 only, checks every address the name resolves to (and connects to the one
   it checked), follows no redirect, and reads at most 1 MB. `api.transport` is
   the one place a request is made, so a check can replace it.

   ONE CALL, NO RETRY. withToken decrypts the token, runs one call with it, and
   drops it. A 401 or 403 is "session_failed": server.js then marks the
   connection needs_reconnect and tells the member once. Nothing here tries
   again. The one wait is uploadMedia's: a server still processing an image is
   asked again at most MEDIA_POLLS times, MEDIA_POLL_MS apart, inside the same
   call, and then given up on.

   THE TOKEN NEVER LEAVES THIS FILE IN THE CLEAR. It is decrypted inside
   withToken (or typed into verify), put into one Authorization header, and
   dropped. No message built here contains it, and errors are reduced to a
   short code, never the server's own words.
   ══════════════════════════════════════════════════════════════════════════ */

const net = require("net");

const PLATFORM = "mastodon";

/* Migration 165's patterns, as strings (scripts/checkMastodonConnect.js holds
   them equal to the SQL). */
const HOST_PATTERN = "^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$";
const ACCOUNT_ID_PATTERN = "^[A-Za-z0-9_-]{1,64}$";
const ACCT_PATTERN = "^[A-Za-z0-9_.-]{1,64}$";
const HOST_RE = new RegExp(HOST_PATTERN);
const ACCOUNT_ID_RE = new RegExp(ACCOUNT_ID_PATTERN);
const ACCT_RE = new RegExp(ACCT_PATTERN);
const HOST_MIN = 4;
const HOST_MAX = 253;

// 165's ranges, and the defaults used outside them.
const MAX_CHARACTERS_DEFAULT = 500;
const RESERVED_PER_URL_DEFAULT = 23;
const MAX_CHARACTERS_RANGE = [1, 100000];
const RESERVED_PER_URL_RANGE = [0, 1000];
// 168's ranges and defaults: the server's image size limit and alt text (description) limit.
const IMAGE_SIZE_LIMIT_DEFAULT = 16777216;
const MEDIA_DESCRIPTION_LIMIT_DEFAULT = 1500;
const IMAGE_SIZE_LIMIT_RANGE = [1, 104857600];
const MEDIA_DESCRIPTION_LIMIT_RANGE = [1, 100000];

// A personal access token as Mastodon makes them: letters, digits, _ and -.
const TOKEN_RE = /^[A-Za-z0-9_-]{20,200}$/;

const TOKEN_HELP = "In Mastodon, open Preferences, then Development, then New application. Tick only write:statuses and read:accounts, " +
  "press Submit, then open the application and copy \"Your access token\"";

const MESSAGES = {
  instance: "Enter your Mastodon server's address, like mastodon.social. Nothing was saved.",
  instanceAscii: "Enter your server's address in its xn-- form (the ASCII spelling of a name with accents or other scripts), like xn--mnchen-3ya.social. Nothing was saved.",
  tokenMissing: TOKEN_HELP + ". Nothing was saved.",
  tokenFormat: "That doesn't look like a Mastodon access token: it is letters, numbers, _ and -, with no spaces. " + TOKEN_HELP + ". Nothing was saved.",
  rejected: "That Mastodon server didn't accept the access token",
  unreachable: "That Mastodon server couldn't be reached as a Mastodon API over https, so nothing was saved. Check the address and try again.",
  rateLimited: "That Mastodon server is limiting requests right now, so nothing was saved. Try again later.",
  noSecret: "Mastodon can't be connected on this server just now: its encryption key is not set. Nothing was sent to Mastodon and nothing was saved."
};

/* ── the server a member typed ──────────────────────────────────────────────
   "host" or "https://host", with one optional trailing slash and an optional
   :443, and nothing else: no http, no path, query or fragment, no user or
   password, no other port, no IP literal, no localhost, no single-label name,
   and ASCII only (a name with accents is typed in its xn-- form). Lowercased.
   The host returned matches 165's instance_host check. null otherwise. */
function normalizeInstance(input) {
  if (typeof input !== "string") return null;
  var s = input.trim();
  if (!s || s.length > 300) return null;
  if (/[^\x21-\x7e]/.test(s)) return null;
  if (/^https:\/\//i.test(s)) s = s.slice(8);
  else if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) return null;
  if (s.charAt(s.length - 1) === "/") s = s.slice(0, -1);
  if (/[\/?#@\\\[\]%]/.test(s)) return null;
  var colon = s.indexOf(":");
  if (colon !== -1) {
    if (s.slice(colon + 1) !== "443") return null;
    s = s.slice(0, colon);
  }
  s = s.toLowerCase();
  if (net.isIP(s)) return null;
  if (s === "localhost" || /\.localhost$/.test(s)) return null;
  if (s.length < HOST_MIN || s.length > HOST_MAX || !HOST_RE.test(s)) return null;
  return s;
}

/* Which message a refused server address gets. */
function instanceMessage(input) {
  return typeof input === "string" && /[^\x00-\x7f]/.test(input) ? MESSAGES.instanceAscii : MESSAGES.instance;
}

/* { ok: true, value } or { ok: false, code, error }. */
function checkToken(raw) {
  var value = typeof raw === "string" ? raw.trim() : "";
  if (!value) return { ok: false, code: "token_required", error: MESSAGES.tokenMissing };
  if (TOKEN_RE.test(value)) return { ok: true, value: value };
  return { ok: false, code: "token_format", error: MESSAGES.tokenFormat };
}

/* ── what an answer means ───────────────────────────────────────────────────
   classify(outcome, nowMs): outcome is { status, headers } for an answer, or
   { thrown: true } when the request itself was refused or failed (a guard
   refusal, no answer). Status codes and two headers are read; message text
   never is.
     401 or 403   rejected
     429          rate_limited, with waitMs: Retry-After seconds, else the
                  X-RateLimit-Reset ISO time, else 15 minutes; at most 2 hours
     anything else, and every refusal: unreachable */
const FALLBACK_BACKOFF_MS = 15 * 60 * 1000;
const MAX_BACKOFF_MS = 2 * 60 * 60 * 1000;
function waitFrom(headers, nowMs) {
  headers = headers || {};
  var raw = headers["retry-after"];
  if (raw !== undefined && String(raw).trim() !== "" && /^\d+$/.test(String(raw).trim())) {
    return Math.min(Number(String(raw).trim()) * 1000, MAX_BACKOFF_MS);
  }
  var reset = headers["x-ratelimit-reset"];
  if (reset !== undefined && /^\d{4}-\d{2}-\d{2}T/.test(String(reset))) {
    var at = Date.parse(String(reset));
    if (isFinite(at)) return Math.min(Math.max(0, at - nowMs), MAX_BACKOFF_MS);
  }
  return FALLBACK_BACKOFF_MS;
}
function classify(outcome, nowMs) {
  var status = outcome && !outcome.thrown ? Number(outcome.status) : NaN;
  if (status === 401 || status === 403) return { kind: "rejected" };
  if (status === 429) return { kind: "rate_limited", waitMs: waitFrom(outcome.headers, nowMs) };
  return { kind: "unreachable" };
}

/* ── A MEMBER'S OWN RATE-LIMIT BACK-OFF ─────────────────────────────────────
   In memory, per member, and its own Map: lib/memberBluesky.js keeps a
   separate one, so a Bluesky limit never holds a Mastodon post or the other
   way round. While it is in force withToken makes no request. The member's
   next successful call clears it. */
var mastodonBackoffs = new Map();
function backoffKey(userId) {
  return typeof userId === "string" && userId ? userId : null;
}
function backoffUntil(userId, nowMs) {
  var key = backoffKey(userId);
  if (!key) return 0;
  var until = mastodonBackoffs.get(key) || 0;
  if (until <= nowMs) {
    if (until) mastodonBackoffs.delete(key);
    return 0;
  }
  return until;
}
function noteRateLimit(userId, waitMs, nowMs) {
  var key = backoffKey(userId);
  var until = nowMs + Math.min(typeof waitMs === "number" && waitMs >= 0 ? waitMs : FALLBACK_BACKOFF_MS, MAX_BACKOFF_MS);
  if (key) mastodonBackoffs.set(key, until);
  return until;
}
function clearBackoff(userId) {
  var key = backoffKey(userId);
  if (key) mastodonBackoffs.delete(key);
}

const api = {
  // Every request: lib/guardedFetch.js's JSON mode, unless a check replaces it.
  transport: function (url, options) { return require("./guardedFetch").guardedJsonRequest(url, options); },
  // The clock the back-off reads, so a check can move it.
  now: function () { return Date.now(); },
  // The wait between media polls (uploadMedia), so a check can skip it.
  sleep: function (ms) { return new Promise(function (resolve) { setTimeout(resolve, ms); }); }
};

/* A request that answered other than 2xx: its status and the three headers. */
function MastodonAnswer(status, headers) {
  this.name = "MastodonAnswer";
  this.status = status;
  this.headers = headers || {};
  this.message = "the Mastodon server answered " + status;
}
MastodonAnswer.prototype = Object.create(Error.prototype);

/* A request that never got an answer (a guard refusal, no connection). */
function MastodonUnreached() {
  this.name = "MastodonUnreached";
  this.thrown = true;
  this.message = "the Mastodon server was not reached";
}
MastodonUnreached.prototype = Object.create(Error.prototype);

/* The one way a request is made: https on the given host, through
   api.transport, with the token (when there is one) in one header. Resolves
   the parsed JSON of a 2xx; throws MastodonAnswer or MastodonUnreached. The
   transport's own error is dropped unread, so nothing it carries leaves. */
async function send(host, tokenOf, method, path, body, extraHeaders) {
  return (await sendAnswer(host, tokenOf, method, path, body, extraHeaders, null)).json;
}
/* The same, resolving { status, json } of a 2xx, for the media upload and its
   polls, which tell 200 from 202 and 206. `more` adds transport options (an
   upload's maxUploadBytes and timeoutMs); other requests send none. */
async function sendAnswer(host, tokenOf, method, path, body, extraHeaders, more) {
  var headers = Object.assign({}, extraHeaders || {});
  var token = tokenOf ? tokenOf() : null;
  if (tokenOf && !token) throw new MastodonUnreached();
  if (token) headers.Authorization = "Bearer " + token;
  token = null;
  var answer;
  try {
    answer = await api.transport("https://" + host + path, Object.assign({ method: method, headers: headers, body: body }, more || {}));
  } catch (err) {
    throw new MastodonUnreached();
  } finally {
    headers = null;
  }
  if (!answer || typeof answer.status !== "number") throw new MastodonUnreached();
  if (answer.status < 200 || answer.status >= 300) throw new MastodonAnswer(answer.status, answer.headers);
  return { status: answer.status, json: answer.json };
}

/* A client bound to one host and one token reader. */
function makeClient(host, tokenOf) {
  return {
    host: host,
    get: function (path) { return send(host, tokenOf, "GET", path, undefined, null); },
    post: function (path, body, extraHeaders) { return send(host, tokenOf, "POST", path, body, extraHeaders); },
    getAnswer: function (path) { return sendAnswer(host, tokenOf, "GET", path, undefined, null, null); },
    upload: function (path, bytes, contentType) {
      return sendAnswer(host, tokenOf, "POST", path, bytes, { "Content-Type": contentType },
        { maxUploadBytes: MEDIA_UPLOAD_MAX_BYTES, timeoutMs: MEDIA_UPLOAD_TIMEOUT_MS });
    }
  };
}

function outcomeOf(err) {
  return err instanceof MastodonAnswer ? { status: err.status, headers: err.headers } : { thrown: true };
}

function inRange(n, range) {
  return typeof n === "number" && Number.isInteger(n) && n >= range[0] && n <= range[1];
}

/* Connect: two requests with what the member typed, no retry.
   1. GET /api/v1/accounts/verify_credentials with the token: the account's id
      and username, each held to 165's pattern.
   2. GET /api/v2/instance, without the token: the server's post length rules
      (configuration.statuses.max_characters and characters_reserved_per_url),
      or 500 and 23 when either is missing or outside 165's ranges.
   { ok: true, account_id, acct, max_characters, characters_reserved_per_url }
   or { ok: false, kind, waitMs? } with kind rejected, rate_limited or
   unreachable. */
async function verify(host, token) {
  if (normalizeInstance(host) !== host) return { ok: false, kind: "unreachable" };
  var typed = token;
  var who;
  try {
    who = await makeClient(host, function () { return typed; }).get("/api/v1/accounts/verify_credentials");
  } catch (err) {
    return Object.assign({ ok: false }, classify(outcomeOf(err), api.now()));
  } finally {
    typed = null;
  }
  var accountId = who && typeof who.id === "string" ? who.id : (who && typeof who.id === "number" ? String(who.id) : null);
  var acct = who && typeof who.username === "string" ? who.username : null;
  if (!accountId || !ACCOUNT_ID_RE.test(accountId) || !acct || !ACCT_RE.test(acct)) {
    return { ok: false, kind: "unreachable" };
  }
  var maxChars = MAX_CHARACTERS_DEFAULT;
  var reserved = RESERVED_PER_URL_DEFAULT;
  var imageLimit = IMAGE_SIZE_LIMIT_DEFAULT;
  var describeLimit = MEDIA_DESCRIPTION_LIMIT_DEFAULT;
  try {
    var info = await makeClient(host, null).get("/api/v2/instance");
    var st = info && info.configuration && info.configuration.statuses;
    if (st && inRange(st.max_characters, MAX_CHARACTERS_RANGE)) maxChars = st.max_characters;
    if (st && inRange(st.characters_reserved_per_url, RESERVED_PER_URL_RANGE)) reserved = st.characters_reserved_per_url;
    // The same answer's media rules (migration 168), or 16777216 and 1500.
    var ma = info && info.configuration && info.configuration.media_attachments;
    if (ma && inRange(ma.image_size_limit, IMAGE_SIZE_LIMIT_RANGE)) imageLimit = ma.image_size_limit;
    if (ma && inRange(ma.description_limit, MEDIA_DESCRIPTION_LIMIT_RANGE)) describeLimit = ma.description_limit;
  } catch (err) {
    // The rules are optional: without them, 500 and 23, 16777216 and 1500.
  }
  return { ok: true, account_id: accountId, acct: acct, max_characters: maxChars, characters_reserved_per_url: reserved,
    image_size_limit: imageLimit, media_description_limit: describeLimit };
}

/* fn(client) with the member's own token: one call, no retry. `row` is their
   member_mastodon_connections row; `decrypt` is lib/apiKeyCrypto.js's.
   Resolves { ok: true, value } or { ok: false, reason, code } with reason:
     session_failed  the server refused the token (401 or 403), or it could
                     not be decrypted (server.js marks needs_reconnect)
     rate_limited    the server said to slow down (carries resumes_at)
     call_failed     anything else: no answer, a refusal by the guard, a 4xx
                     or 5xx
   While the member's back-off is in force nothing is decrypted and no request
   is made: { reason: "rate_limited", code: "backoff", resumes_at }.
   Never throws. */
// The codes a failure inside fn keeps; anything else is call_failed.
const KNOWN_CALL_CODES = ["no_status_url", "no_media_id", "media_not_ready", "bad_media_ids"];
async function withToken(row, decrypt, fn) {
  var userId = row && row.user_id;
  var held = backoffUntil(userId, api.now());
  if (held) {
    return { ok: false, reason: "rate_limited", code: "backoff", resumes_at: new Date(held).toISOString() };
  }
  var host = row && normalizeInstance(row.instance_host);
  if (!host || host !== row.instance_host) return { ok: false, reason: "call_failed", code: "host_invalid" };
  var token;
  try {
    token = decrypt({ ciphertext: row.token_ciphertext, iv: row.token_iv, authTag: row.token_auth_tag });
  } catch (err) {
    return { ok: false, reason: "session_failed", code: "token_unreadable" };
  }
  try {
    var value = await fn(makeClient(host, function () { return token; }));
    clearBackoff(userId);
    return { ok: true, value: value };
  } catch (err) {
    var verdict = classify(outcomeOf(err), api.now());
    if (verdict.kind === "rejected") return { ok: false, reason: "session_failed", code: "token_refused" };
    if (verdict.kind === "rate_limited") {
      var until = noteRateLimit(userId, verdict.waitMs, api.now());
      return { ok: false, reason: "rate_limited", code: "call_rate_limited", resumes_at: new Date(until).toISOString() };
    }
    var code = err instanceof MastodonAnswer ? "http_" + err.status : (err && KNOWN_CALL_CODES.indexOf(err.code) !== -1 ? err.code : "call_failed");
    return { ok: false, reason: "call_failed", code: code };
  } finally {
    token = null;
  }
}

/* ── how long a post is ─────────────────────────────────────────────────────
   Conservative, so it is never below what Mastodon counts: Unicode code
   points (Mastodon counts graphemes, and a grapheme is at least one code
   point), with each http(s) link counted as the larger of its own length and
   the server's characters_reserved_per_url (Mastodon counts a link as exactly
   that many). A link here is the run after http:// or https:// of the
   characters a link's path can hold, with trailing punctuation left out of it
   (and so counted as itself), as Mastodon leaves it out. A mention counts in
   full, where Mastodon counts only its username. */
const LINK_RE = /https?:\/\/[A-Za-z0-9\-._~\/?#=&%+]+/gi;
const LINK_END_RE = /[.?&%~]+$/;
function countForMastodon(text, reservedPerUrl) {
  var s = String(text === undefined || text === null ? "" : text);
  var reserved = Number.isInteger(reservedPerUrl) && reservedPerUrl >= 0 ? reservedPerUrl : RESERVED_PER_URL_DEFAULT;
  var total = 0;
  var last = 0;
  var m;
  LINK_RE.lastIndex = 0;
  while ((m = LINK_RE.exec(s))) {
    var link = m[0].replace(LINK_END_RE, "");
    total += Array.from(s.slice(last, m.index)).length;
    if (/^https?:\/\/$/i.test(link)) {
      total += Array.from(m[0]).length;
    } else {
      total += Math.max(link.length, reserved) + (m[0].length - link.length);
    }
    last = m.index + m[0].length;
  }
  total += Array.from(s.slice(last)).length;
  return total;
}

/* The limit a post is held to: the member's stored max_characters, else 500. */
function limitOf(row) {
  return row && inRange(row.max_characters, MAX_CHARACTERS_RANGE) ? row.max_characters : MAX_CHARACTERS_DEFAULT;
}
function reservedOf(row) {
  return row && inRange(row.characters_reserved_per_url, RESERVED_PER_URL_RANGE) ? row.characters_reserved_per_url : RESERVED_PER_URL_DEFAULT;
}

/* An https address on the stored host, at most 1024 characters, or null. */
const STATUS_URL_MAX = 1024;
function statusAddress(value, host) {
  if (typeof value !== "string" || value.length > STATUS_URL_MAX) return null;
  var u;
  try { u = new URL(value); } catch (e) { return null; }
  if (u.protocol !== "https:" || u.hostname.toLowerCase() !== host || u.username || u.password || (u.port && u.port !== "443")) return null;
  return value;
}

/* One public post. The Idempotency-Key makes the server answer a repeated
   request with the post it already made, instead of posting twice. Resolves
   { id, url }; url is the status's url, else its uri, each held to https on
   the stored host. Throws (and so withToken reports call_failed) otherwise. */
const IDEMPOTENCY_KEY_RE = /^[A-Za-z0-9_-]{1,64}$/;
async function postStatus(client, text, idempotencyKey, mediaIds) {
  if (typeof text !== "string" || !text.trim()) throw Object.assign(new Error("no text"), { code: "no_text" });
  if (typeof idempotencyKey !== "string" || !IDEMPOTENCY_KEY_RE.test(idempotencyKey)) {
    throw Object.assign(new Error("no idempotency key"), { code: "no_idempotency_key" });
  }
  var attach = mediaIds === undefined || mediaIds === null ? [] : mediaIds;
  if (!Array.isArray(attach) || attach.length > MEDIA_PER_POST || attach.some(function (m) { return typeof m !== "string" || !ACCOUNT_ID_RE.test(m); })) {
    throw Object.assign(new Error("bad media ids"), { code: "bad_media_ids" });
  }
  // With no images the body is exactly { status, visibility }, as it always was.
  var statusBody = { status: text, visibility: "public" };
  if (attach.length) statusBody.media_ids = attach.slice();
  var made = await client.post("/api/v1/statuses", statusBody, { "Idempotency-Key": idempotencyKey });
  var id = made && (typeof made.id === "string" || typeof made.id === "number") ? String(made.id) : null;
  var url = made ? (statusAddress(made.url, client.host) || statusAddress(made.uri, client.host)) : null;
  if (!id || !ACCOUNT_ID_RE.test(id) || !url) throw Object.assign(new Error("no status url"), { code: "no_status_url" });
  return { id: id, url: url };
}

/* ── images (migration 168) ─────────────────────────────────────────────────
   One image: POST /api/v2/media as multipart (a "file" part and a
   "description" part, under a crypto-random boundary), through the same
   guarded JSON mode with a Buffer body. A 200 with a url is ready. Otherwise
   (a 202, or no url yet) GET /api/v1/media/:id is asked at most
   MEDIA_POLLS times, MEDIA_POLL_MS apart, while it answers 206 or has no url.
   Still not ready is MediaNotReady (code media_not_ready): the post is never
   made with unprocessed media. Resolves the media id. At most 4 images a post,
   so at most 4 uploads and 20 polls, all inside the caller's one withToken. */
const MEDIA_PER_POST = 4;
const MEDIA_POLLS = 5;
const MEDIA_POLL_MS = 2000;
const MEDIA_UPLOAD_MAX_BYTES = 12 * 1024 * 1024;
const MEDIA_UPLOAD_TIMEOUT_MS = 30000;
const MEDIA_MIMES = { "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/gif": "gif" };
const CRLF = String.fromCharCode(13, 10);
function mediaFailure(code) { return Object.assign(new Error(code), { code: code }); }
function multipartImage(bytes, mime, description, boundary) {
  var dash = "--" + boundary;
  var head = dash + CRLF +
    'Content-Disposition: form-data; name="file"; filename="image.' + MEDIA_MIMES[mime] + '"' + CRLF +
    "Content-Type: " + mime + CRLF + CRLF;
  var tail = CRLF + dash + CRLF +
    'Content-Disposition: form-data; name="description"' + CRLF + CRLF +
    description + CRLF + dash + "--" + CRLF;
  return Buffer.concat([Buffer.from(head, "utf8"), bytes, Buffer.from(tail, "utf8")]);
}
function mediaReady(json) { return !!(json && typeof json.url === "string" && json.url); }
async function uploadMedia(client, media) {
  media = media || {};
  if (!Buffer.isBuffer(media.bytes) || !media.bytes.length) throw mediaFailure("no_media_bytes");
  if (!MEDIA_MIMES[media.mime]) throw mediaFailure("media_type");
  if (typeof media.description !== "string" || !media.description.trim()) throw mediaFailure("no_description");
  var boundary;
  do { boundary = "BizForceBoundary" + require("crypto").randomBytes(16).toString("hex"); } while (media.description.indexOf(boundary) !== -1);
  var answer = await client.upload("/api/v2/media", multipartImage(media.bytes, media.mime, media.description, boundary),
    "multipart/form-data; boundary=" + boundary);
  var made = answer && answer.json;
  var id = made && (typeof made.id === "string" || typeof made.id === "number") ? String(made.id) : null;
  if (!id || !ACCOUNT_ID_RE.test(id)) throw mediaFailure("no_media_id");
  if (answer.status === 200 && mediaReady(made)) return id;
  for (var p = 0; p < MEDIA_POLLS; p++) {
    await api.sleep(MEDIA_POLL_MS);
    var polled = await client.getAnswer("/api/v1/media/" + id);
    if (polled.status !== 206 && mediaReady(polled.json)) return id;
  }
  throw mediaFailure("media_not_ready");
}

/* The image size and alt text limits a filing is held to: the connection's
   stored ones, else 168's defaults. */
function imageSizeLimitOf(row) {
  return row && inRange(row.image_size_limit, IMAGE_SIZE_LIMIT_RANGE) ? row.image_size_limit : IMAGE_SIZE_LIMIT_DEFAULT;
}
function descriptionLimitOf(row) {
  return row && inRange(row.media_description_limit, MEDIA_DESCRIPTION_LIMIT_RANGE) ? row.media_description_limit : MEDIA_DESCRIPTION_LIMIT_DEFAULT;
}

/* The only fields GET /api/social/mastodon/status returns. */
function statusOf(row) {
  if (!row) return { connected: false, account: null, status: "disconnected", since: null, max_characters: null };
  return {
    connected: row.status === "connected",
    account: "@" + row.acct + "@" + row.instance_host,
    status: row.status,
    since: row.created_at || null,
    max_characters: limitOf(row)
  };
}

module.exports = {
  PLATFORM, HOST_PATTERN, ACCOUNT_ID_PATTERN, ACCT_PATTERN, HOST_RE, ACCOUNT_ID_RE, ACCT_RE, TOKEN_RE, TOKEN_HELP, MESSAGES,
  MAX_CHARACTERS_DEFAULT, RESERVED_PER_URL_DEFAULT, FALLBACK_BACKOFF_MS, MAX_BACKOFF_MS,
  api, normalizeInstance, instanceMessage, checkToken, classify, verify, withToken, countForMastodon, limitOf, reservedOf,
  postStatus, statusOf, backoffUntil, noteRateLimit, clearBackoff,
  IMAGE_SIZE_LIMIT_DEFAULT, MEDIA_DESCRIPTION_LIMIT_DEFAULT, IMAGE_SIZE_LIMIT_RANGE, MEDIA_DESCRIPTION_LIMIT_RANGE,
  MEDIA_PER_POST, MEDIA_POLLS, MEDIA_POLL_MS, MEDIA_UPLOAD_MAX_BYTES, uploadMedia, imageSizeLimitOf, descriptionLimitOf
};
