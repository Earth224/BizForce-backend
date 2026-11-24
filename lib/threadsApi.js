"use strict";

/* ══════════════════════════════════════════════════════════════════════════
   THREADS API (LR-2). NAMED (Nov 23 2026, LR-2). Everything Lead Radar asks of
   Threads, always with the MEMBER'S OWN token (threads_connections, migration
   204e; lib/threadsAuth.js connects it):

     readMe(token)                    { threads_user_id, username }
     keywordSearch(token, q, sinceIso, ownUsername)
                                      { posts, ownOnly, ownCount, permission }
     keywordSearchState(previous, result)
                                      the next threads_connections.keyword_search_state
     replyTo(token, threadsUserId, replyToId, text)
                                      { id, permalink }
     takeSearch / searchesLeft / exhaustSearches
                                      the per-member search budget
     readConnection, stateOf, statusView, accessToken, markNeedsReconnect,
     recordKeywordState               the connection row

   KEYWORD SEARCH. GET graph.threads.net/v1.0/keyword_search with q,
   search_type=RECENT, fields and since (unix seconds), never earlier than 7
   days ago. Until Meta approves threads_keyword_search for BizForce, a search
   only sees posts owned by the member (Meta's documented behaviour), so:
     - ownOnly is true when there was at least one result and every result is
       the member's own (username equal, case ignored), or when Meta answers a
       permission error (Graph code 10, or 200-299) for the search;
     - the member's own posts are never returned as posts: they are not leads
       (ownCount says how many were dropped);
     - keywordSearchState turns that into 'own_posts_only' | 'approved' |
       'unknown'. Once 'approved', only a permission error moves it back: a
       niche keyword whose only recent posts are the member's own does not.
   The screens show "Waiting for Meta's approval" for 'own_posts_only'.

   THE SEARCH BUDGET. Meta allows 2,200 keyword_search queries per 24 hours per
   user token. takeSearch(userId, nowMs) spends one from a sliding 24-hour
   window kept IN THIS PROCESS'S MEMORY ({ ok, remaining, resetsAt }); it
   answers ok false, spending nothing, once 2,200 were taken in the last 24
   hours. The caller takes one BEFORE each keywordSearch and skips the search
   when ok is false. exhaustSearches(userId, nowMs) marks the window full when
   Meta itself answers a rate limit (ThreadsApiError kind rate_limited). A
   restart forgets the window; Meta's own limit still holds, and its rate-limit
   answer refills this one through exhaustSearches.

   REPLIES. replyTo is TWO documented steps plus a status wait: create a TEXT
   container with reply_to_id (POST /{threads-user-id}/threads), wait until
   the container's status is FINISHED (GET /{container-id}?fields=status,
   every POLL_INTERVAL_MS, at most POLL_MAX_MS), publish it once
   (POST /{threads-user-id}/threads_publish with creation_id), then read its
   permalink (GET /{id}?fields=permalink; null if that read fails, the reply
   is out either way). It sends exactly the text it is given: no rewriting, no
   trimming. It refuses an empty text or one over TEXT_MAX characters, and it
   NEVER runs unless the caller passes text the member approved. It never
   retries the publish: a publish that may or may not have happened throws
   kind unknown_outcome, so the caller must not send again blindly.

   The token goes in the Authorization: Bearer header, never in a URL. All I/O
   is through deps.request (lib/guardedFetch.js guardedJsonRequest). Nothing
   here logs a token.
   ══════════════════════════════════════════════════════════════════════════ */

const TA = require("./threadsAuth");

const API_BASE = "https://graph.threads.net/v1.0";
const SEARCH_URL = API_BASE + "/keyword_search";
const ME_URL = API_BASE + "/me?fields=id,username";
const SEARCH_FIELDS = "id,text,media_type,permalink,timestamp,username";
const SEARCH_DAYS = 7;
const SEARCH_WINDOW_MS = SEARCH_DAYS * 24 * 60 * 60 * 1000;
/* Meta: since must be on or after this (unix seconds, Threads' launch week). */
const SEARCH_EARLIEST_S = 1688540400;
const SEARCHES_PER_DAY = 2200;
const BUDGET_WINDOW_MS = 24 * 60 * 60 * 1000;
const Q_MAX = 100;
const TEXT_MAX = 500;
const POST_TEXT_MAX = 1000;
const POLL_INTERVAL_MS = 1000;
const POLL_MAX_MS = 30 * 1000;
const API_TIMEOUT_MS = 15 * 1000;
const ID_RE = /^[0-9]{1,30}$/;
const USERNAME_RE = /^[A-Za-z0-9._]{1,100}$/;
const PERMALINK_RE = /^https:\/\/www\.threads\.(net|com)\/[A-Za-z0-9_\/.@?=&-]{1,280}$/;
const KEYWORD_STATES = Object.freeze(["unknown", "own_posts_only", "approved"]);
const ROW_COLUMNS = "id, user_id, threads_user_id, username, access_ciphertext, access_iv, access_auth_tag, access_expires_at, granted_scopes, keyword_search_state, status, last_ok_at, last_error_at, last_error_code, created_at, updated_at";

const deps = {
  request: function (url, options) { return require("./guardedFetch").guardedJsonRequest(url, options); },
  now: function () { return Date.now(); },
  sleep: function (ms) { return new Promise(function (resolve) { setTimeout(resolve, ms); }); }
};

/* kind: auth (token refused), permission, rate_limited, bad_input, refused, unreachable, unknown_outcome. */
function ThreadsApiError(kind, code) {
  this.name = "ThreadsApiError";
  this.kind = kind;
  this.code = code;
  this.message = "threads api " + kind + " (" + code + ")";
}
ThreadsApiError.prototype = Object.create(Error.prototype);

function bearer(token) { return { Authorization: "Bearer " + token }; }
function graphError(answer) {
  var j = answer && answer.json && typeof answer.json === "object" ? answer.json : {};
  return j.error && typeof j.error === "object" ? j.error : {};
}
function ok(answer) { return !!(answer && typeof answer.status === "number" && answer.status >= 200 && answer.status < 300 && answer.json && typeof answer.json === "object"); }
function tokenRefused(answer) {
  if (!answer) return false;
  var e = graphError(answer);
  return answer.status === 401 || e.code === 190 || e.code === 102;
}
function permissionRefused(answer) {
  if (!answer || ok(answer)) return false;
  var c = graphError(answer).code;
  return c === 10 || (typeof c === "number" && c >= 200 && c <= 299);
}
function rateLimited(answer) {
  if (!answer || ok(answer)) return false;
  var c = graphError(answer).code;
  return answer.status === 429 || c === 4 || c === 17 || c === 32 || c === 613;
}
/* The answer's failure as a ThreadsApiError. */
function failure(answer, what) {
  if (tokenRefused(answer)) return new ThreadsApiError("auth", "unauthorized");
  if (permissionRefused(answer)) return new ThreadsApiError("permission", what + "_permission");
  if (rateLimited(answer)) return new ThreadsApiError("rate_limited", what + "_rate_limited");
  var s = answer && typeof answer.status === "number" ? answer.status : "none";
  return new ThreadsApiError(typeof s === "number" && s >= 400 && s < 500 ? "refused" : "unreachable", what + "_" + s);
}

async function api(url, options) {
  try {
    return await deps.request(url, Object.assign({ timeoutMs: API_TIMEOUT_MS }, options));
  } catch (err) {
    throw new ThreadsApiError("unreachable", (err && typeof err.code === "string" && /^[a-z_]{1,40}$/.test(err.code)) ? err.code : "request");
  }
}

function idOf(v) {
  var s = typeof v === "number" ? String(v) : (typeof v === "string" ? v : "");
  return ID_RE.test(s) ? s : null;
}

/* /me with a token in hand: { threads_user_id, username }, or null for an unreadable answer. */
async function readMe(token) {
  var answer = await api(ME_URL, { method: "GET", headers: bearer(token) });
  if (!ok(answer)) throw failure(answer, "me");
  var id = idOf(answer.json.id);
  var username = typeof answer.json.username === "string" && USERNAME_RE.test(answer.json.username) ? answer.json.username : null;
  return id && username ? { threads_user_id: id, username: username } : null;
}

/* since as unix seconds: the given time, never earlier than SEARCH_DAYS ago nor than Meta's earliest. */
function sinceSeconds(sinceIso, nowMs) {
  var floor = nowMs - SEARCH_WINDOW_MS;
  var asked = Date.parse(sinceIso || "");
  var ms = isFinite(asked) && asked > floor ? asked : floor;
  return Math.max(SEARCH_EARLIEST_S, Math.floor(ms / 1000));
}

function postOf(item) {
  if (!item || typeof item !== "object") return null;
  var id = idOf(item.id);
  var username = typeof item.username === "string" && USERNAME_RE.test(item.username) ? item.username : null;
  var at = Date.parse(typeof item.timestamp === "string" ? item.timestamp : "");
  if (!id || !username || !isFinite(at)) return null;
  return {
    id: id,
    text: typeof item.text === "string" ? item.text.slice(0, POST_TEXT_MAX) : "",
    username: username,
    timestamp: new Date(at).toISOString(),
    permalink: typeof item.permalink === "string" && PERMALINK_RE.test(item.permalink) ? item.permalink : null
  };
}

/* One keyword search with the member's own token. { posts, ownOnly, ownCount,
   permission }: posts are other people's, newest first, from the last 7 days.
   Throws ThreadsApiError: auth (the token is refused: the caller marks
   needs_reconnect), rate_limited (the caller calls exhaustSearches),
   bad_input, refused or unreachable. A permission error is NOT thrown: it is
   the pre-approval state, { posts: [], ownOnly: true, permission: true }. */
async function keywordSearch(token, q, sinceIso, ownUsername) {
  var query = typeof q === "string" ? q.trim() : "";
  if (!query || query.length > Q_MAX) throw new ThreadsApiError("bad_input", "query");
  var nowMs = deps.now();
  var since = sinceSeconds(sinceIso, nowMs);
  var params = new URLSearchParams();
  params.append("q", query);
  params.append("search_type", "RECENT");
  params.append("fields", SEARCH_FIELDS);
  params.append("since", String(since));
  var answer = await api(SEARCH_URL + "?" + params.toString(), { method: "GET", headers: bearer(token) });
  if (!ok(answer)) {
    if (permissionRefused(answer) && !tokenRefused(answer)) return { posts: [], ownOnly: true, ownCount: 0, permission: true };
    throw failure(answer, "search");
  }
  var data = Array.isArray(answer.json.data) ? answer.json.data : [];
  var own = typeof ownUsername === "string" && ownUsername ? ownUsername.toLowerCase() : null;
  var all = data.map(postOf).filter(function (p) { return p && Date.parse(p.timestamp) >= since * 1000; });
  var others = all.filter(function (p) { return !own || p.username.toLowerCase() !== own; });
  var ownCount = all.length - others.length;
  others.sort(function (a, b) { return Date.parse(b.timestamp) - Date.parse(a.timestamp); });
  return { posts: others, ownOnly: all.length > 0 && others.length === 0 && !!own, ownCount: ownCount, permission: false };
}

/* The next keyword_search_state from the previous one and a search result. */
function keywordSearchState(previous, result) {
  var prev = KEYWORD_STATES.indexOf(previous) !== -1 ? previous : "unknown";
  if (!result) return prev;
  if (result.permission === true) return "own_posts_only";
  if (Array.isArray(result.posts) && result.posts.length > 0) return "approved";
  if (result.ownOnly === true && prev !== "approved") return "own_posts_only";
  return prev;
}

/* ── the reply ─────────────────────────────────────────────────────────── */
async function waitFinished(token, containerId) {
  var started = deps.now();
  for (;;) {
    var answer = await api(API_BASE + "/" + containerId + "?fields=status,error_message", { method: "GET", headers: bearer(token) });
    if (!ok(answer)) throw failure(answer, "container_status");
    var status = answer.json.status;
    if (status === "FINISHED") return;
    if (status === "ERROR" || status === "EXPIRED" || status === "PUBLISHED") throw new ThreadsApiError("refused", "container_" + String(status).toLowerCase());
    if (deps.now() - started >= POLL_MAX_MS) throw new ThreadsApiError("unreachable", "container_timeout");
    await deps.sleep(POLL_INTERVAL_MS);
  }
}

/* A reply from the member's own account, of exactly this text, to post
   replyToId: { id, permalink }. Call it only with text the member approved. */
async function replyTo(token, threadsUserId, replyToId, text) {
  var uid = idOf(threadsUserId);
  var target = idOf(replyToId);
  if (!uid || !target) throw new ThreadsApiError("bad_input", "ids");
  if (typeof text !== "string" || text.trim().length === 0 || Array.from(text).length > TEXT_MAX) throw new ThreadsApiError("bad_input", "text");
  var created = await api(API_BASE + "/" + uid + "/threads", { method: "POST", headers: bearer(token), form: {
    media_type: "TEXT",
    text: text,
    reply_to_id: target
  } });
  if (!ok(created)) throw failure(created, "container");
  var containerId = idOf(created.json.id);
  if (!containerId) throw new ThreadsApiError("unreachable", "container_shape");
  await waitFinished(token, containerId);
  var published;
  try {
    published = await deps.request(API_BASE + "/" + uid + "/threads_publish", { method: "POST", timeoutMs: API_TIMEOUT_MS, headers: bearer(token), form: { creation_id: containerId } });
  } catch (err) {
    // It may have gone out: never sent again from here.
    throw new ThreadsApiError("unknown_outcome", "publish_request");
  }
  if (!ok(published)) throw failure(published, "publish");
  var id = idOf(published.json.id);
  if (!id) throw new ThreadsApiError("unknown_outcome", "publish_shape");
  var permalink = null;
  try {
    var read = await api(API_BASE + "/" + id + "?fields=permalink", { method: "GET", headers: bearer(token) });
    if (ok(read) && typeof read.json.permalink === "string" && PERMALINK_RE.test(read.json.permalink)) permalink = read.json.permalink;
  } catch (err) {
    permalink = null;
  }
  return { id: id, permalink: permalink };
}

/* ── the search budget (in this process's memory) ──────────────────────── */
const searchLog = new Map();
function recent(userId, nowMs) {
  var list = (searchLog.get(userId) || []).filter(function (t) { return t > nowMs - BUDGET_WINDOW_MS && t <= nowMs; });
  searchLog.set(userId, list);
  return list;
}
/* { ok, remaining, resetsAt }: ok true spends one search; ok false spends nothing. */
function takeSearch(userId, nowMs) {
  var list = recent(String(userId), nowMs);
  if (list.length >= SEARCHES_PER_DAY) return { ok: false, remaining: 0, resetsAt: new Date(list[0] + BUDGET_WINDOW_MS).toISOString() };
  list.push(nowMs);
  return { ok: true, remaining: SEARCHES_PER_DAY - list.length, resetsAt: new Date(list[0] + BUDGET_WINDOW_MS).toISOString() };
}
function searchesLeft(userId, nowMs) { return SEARCHES_PER_DAY - recent(String(userId), nowMs).length; }
/* Meta said the limit is reached: the window is full from now. */
function exhaustSearches(userId, nowMs) {
  var list = recent(String(userId), nowMs);
  while (list.length < SEARCHES_PER_DAY) list.push(nowMs);
}

/* ── the connection row ────────────────────────────────────────────────── */
async function readConnection(supabase, userId) {
  var r = await supabase.from("threads_connections").select(ROW_COLUMNS).eq("user_id", userId).maybeSingle();
  if (r.error) throw r.error;
  return r.data && r.data.user_id === userId ? r.data : null;
}

/* 'not_set_up' | 'not_connected' | 'needs_reconnect' | 'waiting_approval' | 'ready'. */
function stateOf(row, available, nowMs) {
  if (!available) return "not_set_up";
  if (!row) return "not_connected";
  var ends = Date.parse(row.access_expires_at || "");
  if (row.status !== "connected" || !isFinite(ends) || ends <= nowMs) return "needs_reconnect";
  if (row.keyword_search_state === "own_posts_only") return "waiting_approval";
  return "ready";
}

/* GET /api/social/threads/status: { state, username, keyword_search }. Never a token. */
function statusView(row, available, nowMs) {
  return {
    state: stateOf(row, available, nowMs),
    username: row ? row.username : null,
    keyword_search: row && KEYWORD_STATES.indexOf(row.keyword_search_state) !== -1 ? row.keyword_search_state : "unknown"
  };
}

/* needs_reconnect, only from connected. Never throws. ctx = { supabase, now }. */
async function markNeedsReconnect(ctx, row, code) {
  try {
    var stamp = new Date(ctx.now()).toISOString();
    var marked = await ctx.supabase.from("threads_connections")
      .update({ status: "needs_reconnect", last_error_at: stamp, last_error_code: String(code || "refused").slice(0, 60), updated_at: stamp })
      .eq("id", row.id).eq("user_id", row.user_id).eq("status", "connected").select("id");
    return !marked.error && (marked.data || []).length > 0;
  } catch (err) {
    return false;
  }
}

/* Store a new keyword_search_state when it changed. Never throws. */
async function recordKeywordState(ctx, row, next) {
  if (!row || KEYWORD_STATES.indexOf(next) === -1 || row.keyword_search_state === next) return false;
  try {
    var stamp = new Date(ctx.now()).toISOString();
    var r = await ctx.supabase.from("threads_connections").update({ keyword_search_state: next, last_ok_at: stamp })
      .eq("id", row.id).eq("user_id", row.user_id).select("id");
    return !r.error && (r.data || []).length > 0;
  } catch (err) {
    return false;
  }
}

/* { token, row } for a connected row: needs_reconnect when expired or when a
   refresh is refused; refreshed when due (lib/threadsAuth.js refreshDue); a
   refresh that cannot reach Threads while the token is valid uses the token
   as it is. ctx = { supabase, crypt, now }. */
async function accessToken(ctx, row) {
  if (!row || row.status !== "connected") throw new ThreadsApiError("auth", "not_connected");
  var nowMs = ctx.now();
  var ends = Date.parse(row.access_expires_at || "");
  if (!isFinite(ends) || ends <= nowMs) {
    await markNeedsReconnect(ctx, row, "expired");
    throw new ThreadsApiError("auth", "expired");
  }
  var current;
  try {
    current = ctx.crypt.decrypt({ ciphertext: row.access_ciphertext, iv: row.access_iv, authTag: row.access_auth_tag });
  } catch (err) {
    throw new ThreadsApiError("auth", "secret_unreadable");
  }
  if (!TA.refreshDue(row, nowMs)) return { token: current, row: row };
  var grant;
  try {
    grant = await TA.refresh(current);
  } catch (err) {
    if (err && err.kind === "invalid_grant") {
      await markNeedsReconnect(ctx, row, "refresh_refused");
      throw new ThreadsApiError("auth", "refresh_refused");
    }
    return { token: current, row: row };
  }
  var s = ctx.crypt.encrypt(grant.accessToken);
  var stamp = new Date(nowMs).toISOString();
  var update = { access_ciphertext: s.ciphertext, access_iv: s.iv, access_auth_tag: s.authTag,
    access_expires_at: TA.expiresAt(nowMs, grant.expiresIn), last_ok_at: stamp, updated_at: stamp };
  // Only if the row is still the one read: a refresh elsewhere wins.
  var swapped = await ctx.supabase.from("threads_connections").update(update)
    .eq("id", row.id).eq("user_id", row.user_id).eq("updated_at", row.updated_at).select("id");
  if (swapped.error || (swapped.data || []).length !== 1) {
    var winner = await readConnection(ctx.supabase, row.user_id);
    if (!winner || winner.status !== "connected") throw new ThreadsApiError("auth", "refresh_lost");
    return { token: ctx.crypt.decrypt({ ciphertext: winner.access_ciphertext, iv: winner.access_iv, authTag: winner.access_auth_tag }), row: winner };
  }
  return { token: grant.accessToken, row: Object.assign({}, row, update) };
}

module.exports = {
  API_BASE: API_BASE,
  SEARCH_URL: SEARCH_URL,
  ME_URL: ME_URL,
  SEARCH_FIELDS: SEARCH_FIELDS,
  SEARCH_DAYS: SEARCH_DAYS,
  SEARCHES_PER_DAY: SEARCHES_PER_DAY,
  BUDGET_WINDOW_MS: BUDGET_WINDOW_MS,
  TEXT_MAX: TEXT_MAX,
  POLL_INTERVAL_MS: POLL_INTERVAL_MS,
  POLL_MAX_MS: POLL_MAX_MS,
  KEYWORD_STATES: KEYWORD_STATES,
  ROW_COLUMNS: ROW_COLUMNS,
  deps: deps,
  ThreadsApiError: ThreadsApiError,
  readMe: readMe,
  sinceSeconds: sinceSeconds,
  keywordSearch: keywordSearch,
  keywordSearchState: keywordSearchState,
  replyTo: replyTo,
  takeSearch: takeSearch,
  searchesLeft: searchesLeft,
  exhaustSearches: exhaustSearches,
  readConnection: readConnection,
  stateOf: stateOf,
  statusView: statusView,
  markNeedsReconnect: markNeedsReconnect,
  recordKeywordState: recordKeywordState,
  accessToken: accessToken
};
