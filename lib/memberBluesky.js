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

/* A Bluesky post's address and content id, exactly as migration 164's
   social_post_drafts_reply_refs_check states them (checkBlueskyMentions holds
   these two strings equal to the SQL). A uri is also at most 1024 characters. */
const POST_URI_PATTERN = "^at://did:[a-z]+:[A-Za-z0-9._:%-]+/app\\.bsky\\.feed\\.post/[A-Za-z0-9._~:-]+$";
const CID_PATTERN = "^b[a-z2-7]{20,200}$";
const POST_URI_RE = new RegExp(POST_URI_PATTERN);
const CID_RE = new RegExp(CID_PATTERN);
const POST_URI_MAX = 1024;
function isPostUri(uri) {
  return typeof uri === "string" && uri.length <= POST_URI_MAX && POST_URI_RE.test(uri);
}
function isCid(cid) {
  return typeof cid === "string" && CID_RE.test(cid);
}

/* The notification reasons the Mentions inbox shows. Every other reason (a
   like, a follow, a repost and the rest) is dropped. */
const MENTION_REASONS = ["mention", "reply", "quote"];

/* ── A MEMBER'S OWN RATE-LIMIT BACK-OFF ─────────────────────────────────────
   In memory, per member (the backend runs one replica). When Bluesky answers a
   member's login or call with 429, the wait it asks for (retry-after, else
   ratelimit-reset, read by bskyGate's requestedWaitMs) or else
   FALLBACK_BACKOFF_MS is recorded, and withSession makes no login for that
   member until it has passed. The member's next successful session clears it.
   The platform account's gate (lib/bskyGate.js, made once in leadRadar.js)
   keeps its own back-off and is never touched from here. */
var memberBackoffs = new Map();
function backoffKey(userId) {
  return typeof userId === "string" && userId ? userId : null;
}
/* The epoch ms the member's back-off ends, or 0 when none is in force. */
function backoffUntil(userId, nowMs) {
  var key = backoffKey(userId);
  if (!key) return 0;
  var until = memberBackoffs.get(key) || 0;
  if (until <= nowMs) {
    if (until) memberBackoffs.delete(key);
    return 0;
  }
  return until;
}
/* Records the wait a 429 asked for; returns the epoch ms it ends. */
function noteRateLimit(userId, err, nowMs) {
  var key = backoffKey(userId);
  var asked = gate.requestedWaitMs(err, nowMs);
  var until = nowMs + (asked != null ? asked : gate.FALLBACK_BACKOFF_MS);
  if (key) memberBackoffs.set(key, until);
  return until;
}
function clearBackoff(userId) {
  var key = backoffKey(userId);
  if (key) memberBackoffs.delete(key);
}

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
  },
  // The clock the back-off reads, so a check can move it.
  now: function () { return Date.now(); }
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
   A rate limit carries resumes_at. While the member's back-off is in force
   nothing is decrypted and no login is made: { reason: "rate_limited", code:
   "backoff", resumes_at }.
   Never throws. */
async function withSession(row, decrypt, fn) {
  var userId = row && row.user_id;
  var held = backoffUntil(userId, api.now());
  if (held) {
    return { ok: false, reason: "rate_limited", code: "backoff", resumes_at: new Date(held).toISOString() };
  }
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
    if (kind === "rate_limited") {
      var loginUntil = noteRateLimit(userId, err, api.now());
      return { ok: false, reason: kind, code: "login_rate_limited", resumes_at: new Date(loginUntil).toISOString() };
    }
    return { ok: false, reason: kind, code: "login_unreachable" };
  } finally {
    password = null;
  }
  var session = agent.session || {};
  if (row.did && session.did !== row.did) {
    // The handle now belongs to a different account than the one connected.
    return { ok: false, reason: "session_failed", code: "account_changed" };
  }
  try {
    var value = await fn(agent);
    clearBackoff(userId);
    return { ok: true, value: value };
  } catch (err) {
    if (gate.isRateLimit(err)) {
      var callUntil = noteRateLimit(userId, err, api.now());
      return { ok: false, reason: "rate_limited", code: "call_rate_limited", resumes_at: new Date(callUntil).toISOString() };
    }
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

/* ── THE MENTIONS INBOX: pure readers of what Bluesky returns ───────────────
   Shapes are the SDK's (@atproto/api 0.20.25): a PostView
   (app.bsky.feed.defs#postView) whose `record` is an app.bsky.feed.post Main
   with an optional ReplyRef (root and parent, each a
   com.atproto.repo.strongRef Main), facets (app.bsky.richtext.facet Main,
   whose features include app.bsky.richtext.facet#mention { did }) and an
   embed (app.bsky.embed.record Main { record: strongRef }, or
   app.bsky.embed.recordWithMedia Main { record: { record: strongRef } }); and
   a listNotifications Notification (app.bsky.notification.listNotifications
   #notification) with uri, cid, author (app.bsky.actor.defs#profileView),
   reason, record and indexedAt. */

function quotedUri(embed) {
  if (!embed || typeof embed !== "object" || !embed.record || typeof embed.record !== "object") return null;
  if (typeof embed.record.uri === "string") return embed.record.uri;
  if (embed.record.record && typeof embed.record.record.uri === "string") return embed.record.record.uri;
  return null;
}

/* True only when the post is someone else's AND it replies to one of
   `accountDid`'s posts, mentions that DID in a facet, or quotes one of its
   posts. Anything else (the account's own post, a post that only says the
   handle in plain text) is false. */
function mentionTargets(postView, accountDid) {
  if (!postView || typeof postView !== "object") return false;
  if (typeof accountDid !== "string" || accountDid.indexOf("did:") !== 0) return false;
  var author = postView.author && postView.author.did;
  if (typeof author !== "string" || !author || author === accountDid) return false;
  var record = postView.record && typeof postView.record === "object" ? postView.record : {};
  var prefix = "at://" + accountDid + "/";
  var parent = record.reply && record.reply.parent && record.reply.parent.uri;
  if (typeof parent === "string" && parent.indexOf(prefix) === 0) return true;
  var facets = Array.isArray(record.facets) ? record.facets : [];
  var mentioned = facets.some(function (facet) {
    var features = facet && Array.isArray(facet.features) ? facet.features : [];
    return features.some(function (f) {
      return Boolean(f) && f.$type === "app.bsky.richtext.facet#mention" && f.did === accountDid;
    });
  });
  if (mentioned) return true;
  var quoted = quotedUri(record.embed);
  return typeof quoted === "string" && quoted.indexOf(prefix) === 0;
}

/* Why a post that targets the account does: "reply" when it answers one of
   the account's posts, else "quote" when it quotes one, else "mention".
   null when mentionTargets is false. */
function mentionReason(postView, accountDid) {
  if (!mentionTargets(postView, accountDid)) return null;
  var record = postView.record && typeof postView.record === "object" ? postView.record : {};
  var prefix = "at://" + accountDid + "/";
  var parent = record.reply && record.reply.parent && record.reply.parent.uri;
  if (typeof parent === "string" && parent.indexOf(prefix) === 0) return "reply";
  var quoted = quotedUri(record.embed);
  if (typeof quoted === "string" && quoted.indexOf(prefix) === 0) return "quote";
  return "mention";
}

/* The reply references for answering `postView`, from what Bluesky returned:
   parent is the post itself, root is the thread's root when the post is itself
   a reply, else the post. null unless every uri and cid is well formed. */
function replyRefsFor(postView) {
  if (!postView || typeof postView !== "object") return null;
  var parent = { uri: postView.uri, cid: postView.cid };
  var record = postView.record && typeof postView.record === "object" ? postView.record : {};
  var root = record.reply && record.reply.root && typeof record.reply.root === "object"
    ? { uri: record.reply.root.uri, cid: record.reply.root.cid }
    : { uri: parent.uri, cid: parent.cid };
  if (!isPostUri(parent.uri) || !isCid(parent.cid) || !isPostUri(root.uri) || !isCid(root.cid)) return null;
  return { parent: parent, root: root };
}

/* One inbox item, and nothing else: no avatar, no labels, no other field.
   null for any reason but mention, reply or quote, or a malformed address. */
function mentionItem(notification) {
  var n = notification && typeof notification === "object" ? notification : null;
  if (!n || MENTION_REASONS.indexOf(n.reason) === -1) return null;
  if (!isPostUri(n.uri) || !isCid(n.cid)) return null;
  var author = n.author && typeof n.author === "object" ? n.author : {};
  var authorDid = typeof author.did === "string" && /^did:[a-z]+:[A-Za-z0-9._:%-]+$/.test(author.did) ? author.did : null;
  var rkey = n.uri.slice(n.uri.lastIndexOf("/") + 1);
  var record = n.record && typeof n.record === "object" ? n.record : {};
  return {
    uri: n.uri,
    cid: n.cid,
    reason: n.reason,
    author: {
      handle: typeof author.handle === "string" ? author.handle : "",
      displayName: typeof author.displayName === "string" ? author.displayName : ""
    },
    text: typeof record.text === "string" ? record.text : "",
    indexed_at: typeof n.indexedAt === "string" ? n.indexedAt : null,
    link: authorDid ? "https://bsky.app/profile/" + authorDid + "/post/" + rkey : null
  };
}

module.exports = {
  PLATFORM, SERVICE, HANDLE_RE, APP_PASSWORD_RE, APP_PASSWORD_HELP, MESSAGES, DISPLAY_NAME_MAX, DESCRIPTION_MAX,
  api, normalizeHandle, checkAppPassword, classify, verify, withSession, statusOf, profileUpdater,
  POST_URI_PATTERN, CID_PATTERN, POST_URI_RE, CID_RE, POST_URI_MAX, MENTION_REASONS, isPostUri, isCid,
  backoffUntil, noteRateLimit, clearBackoff, mentionTargets, mentionReason, replyRefsFor, mentionItem
};
