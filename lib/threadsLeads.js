"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   THREADS FOR LEAD RADAR (LR-2, Nov 23 2026). The three things Lead Radar asks of a
   member's Threads connection, over lib/threadsApi.js and lib/threadsAuth.js:

     state(sb, userId)               { state, username }: not_set_up (no THREADS_APP_ID and
                                     THREADS_APP_SECRET), not_connected, needs_reconnect,
                                     waiting_approval (Meta has not approved
                                     threads_keyword_search: the search sees only the
                                     member's own posts) or ready.
     search(sb, userId, q, sinceIso) the member's OWN token, their own budget (2,200 a day):
                                     { ok, posts, ownOnly, username } | { ok: false, code }.
                                     The keyword_search_state the answer implies is stored,
                                     so the screens can say "Waiting for Meta's approval".
     reply(sb, userId, replyToId, text)  exactly this text, from the member's own account,
                                     only when the connection is ready (approved):
                                     { ok, id, permalink } | { ok: false, code, status }.
                                     Called only by POST /api/leads/:id/send, after the
                                     member approved the text and the guarded step passed.
   ═══════════════════════════════════════════════════════════════════════════ */

const TA = require("./threadsAuth");
const TAPI = require("./threadsApi");
const crypt = require("./apiKeyCrypto");

function ctx(sb) { return { supabase: sb, crypt: crypt, now: function () { return Date.now(); } }; }

async function state(sb, userId) {
  var available = !!TA.configured(process.env);
  var row = available ? await TAPI.readConnection(sb, userId) : null;
  return { state: TAPI.stateOf(row, available, Date.now()), username: row ? row.username : null };
}

async function search(sb, userId, q, sinceIso) {
  if (!TA.configured(process.env)) return { ok: false, code: "not_set_up" };
  var row = await TAPI.readConnection(sb, userId);
  if (!row || row.status !== "connected") return { ok: false, code: row ? "needs_reconnect" : "not_connected" };
  var nowMs = Date.now();
  if (!TAPI.takeSearch(userId, nowMs).ok) return { ok: false, code: "out_of_searches" };
  var c = ctx(sb), got;
  try {
    var t = await TAPI.accessToken(c, row);
    row = t.row;
    got = await TAPI.keywordSearch(t.token, q, sinceIso, row.username);
  } catch (err) {
    if (err && err.kind === "rate_limited") TAPI.exhaustSearches(userId, nowMs);
    if (err && err.kind === "auth") await TAPI.markNeedsReconnect(c, row, err.code || "refused");
    return { ok: false, code: (err && err.kind) || "failed" };
  }
  var next = TAPI.keywordSearchState(row.keyword_search_state, got);
  await TAPI.recordKeywordState(c, row, next);
  return { ok: true, posts: got.posts || [], ownOnly: next === "own_posts_only", username: row.username };
}

async function reply(sb, userId, replyToId, text) {
  var s = await state(sb, userId);
  if (s.state !== "ready") return { ok: false, code: s.state === "waiting_approval" ? "waiting_approval" : "not_connected", status: 409 };
  var row = await TAPI.readConnection(sb, userId);
  var c = ctx(sb);
  try {
    var t = await TAPI.accessToken(c, row);
    var made = await TAPI.replyTo(t.token, t.row.threads_user_id, replyToId, text);
    return { ok: true, id: made.id, permalink: made.permalink, uri: made.permalink || made.id };
  } catch (err) {
    if (err && err.kind === "auth") await TAPI.markNeedsReconnect(c, row, err.code || "refused");
    // An unknown outcome may have posted: reported as such, never retried from here or by the send route.
    if (err && err.kind === "unknown_outcome") return { ok: false, code: "unknown_outcome", status: 502 };
    return { ok: false, code: err && err.kind === "rate_limited" ? "rate_limited" : "post_error", status: err && err.kind === "rate_limited" ? 429 : 502 };
  }
}

module.exports = { state, search, reply };
