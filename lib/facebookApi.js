"use strict";

/* ══════════════════════════════════════════════════════════════════════════
   FACEBOOK, ON ONE PAGE THE MEMBER MANAGES (migration 180).

   THE CONNECTION, member_facebook_pages, one per member:
     choosing         the sealed long-lived USER token only, while the member
                      picks one of several Pages (listChoices, choosePage);
     connected        the Page's id, name and sealed PAGE token; no user token;
     needs_reconnect  the same, after Facebook refused the Page token.
   A Page token obtained with a long-lived user token does not expire. A
   refused token (401, or a token or permission error code: tokenRefused, the
   same rule as lib/instagramApi.js) marks the connection needs_reconnect and
   raises ONE in-app notice. A choosing row older than lib/facebookAuth.js
   CHOOSING_TTL_MS is deleted by choosingPurgeTick, in the 04:45 chain with
   its own job_runs row.

   FILING (proposePost), never running: text; 1 photo (kind photo) or 2 to 10
   (kind photos) from the Media Library, JPEG, PNG or GIF by their own bytes
   (WebP is refused); or one MP4 or MOV from "Your videos" (kind video). The
   message is at most MESSAGE_MAX characters, through the claims screen. At
   most POSTS_PER_DAY posts in 24 hours (facebook_posts not failed).

   THE POST, executePublish (the publish_facebook_post executor), on approval
   only:
     1. the payload, the claims, the message again; the connection (the same
        Page, connected);
     2. a facebook_posts row for this proposal: found, the run CONTINUES from
        it; not found, the files and the cap are checked again and the row is
        inserted, status creating, BEFORE any call to Facebook;
     3. every photo's bytes are read and checked (sha256, size, type) RIGHT
        BEFORE its address is handed over; a video's file is streamed and
        hashed, then a signed link valid SIGNED_URL_SECONDS (2 hours) is made
        and used only in that one request body. Several photos are uploaded
        unpublished first; with nothing attempted yet (status creating), a
        replay uploads them again (unused uploads are never shown);
     4. the row is set publishing (a compare-and-set from creating) BEFORE the
        final call: the feed post, the one published photo, or the video;
     5. Facebook's id is recorded, status published (a video is published
        once Facebook accepts it; Facebook processes it after that).
   A replay that finds publishing with no post_id never posts again: the
   newest of the Page's last 10 posts with the same message, at or after the
   row's created_at, is recorded; none, the row is failed with
   MESSAGES.publishedUnknown.
   REMOVAL (executeDelete, delete_facebook_post), on approval only: one
   DELETE, then removed_at. A removed post cannot be removed again.

   Nothing here logs. No token, signed link or code is ever put into an
   error, a stored row, a result a member sees, or a log line.
   ══════════════════════════════════════════════════════════════════════════ */

const FA = require("./facebookAuth");
const MV = require("./memberVideos");
const MM = require("./memberMedia");

const API_BASE = "https://graph.facebook.com/" + FA.GRAPH_VERSION;
const VIDEO_BASE = "https://graph-video.facebook.com/" + FA.GRAPH_VERSION;
const PAGE_HOST = "https://www.facebook.com";
const ACTION = "publish_facebook_post";
const DELETE_ACTION = "delete_facebook_post";
const POSTS_PER_DAY = 10;
const ITEMS_MAX = 10;
const MESSAGE_MAX = 63206;
const DRAFT_MAX = 500;
const PHOTO_MIMES = Object.freeze(["image/jpeg", "image/png", "image/gif"]);
const VIDEO_MIMES = Object.freeze(["video/mp4", "video/quicktime"]);
/* What the bytes must sniff as (lib/memberMedia.js sniffMedia) for each photo type. */
const SNIFF_FOR = Object.freeze({ "image/jpeg": "jpg", "image/png": "png", "image/gif": "gif" });
/* The video's signed link: two hours, used only inside one request body. */
const SIGNED_URL_SECONDS = 7200;
/* A row still "creating" this long after it was made never reached Facebook's final step. */
const STALE_CREATING_MS = 60 * 60 * 1000;
const API_TIMEOUT_MS = 30 * 1000;
const PAGE_LIST_MAX = 100;
const ID_RE = /^[0-9]{1,30}$/;
const POST_ID_RE = /^[0-9]{1,30}(_[0-9]{1,30})?$/;
const SHA_RE = /^[0-9a-f]{64}$/;
const PERMALINK_RE = /^https:\/\/www\.facebook\.com\/[A-Za-z0-9_\/.?=&%-]{1,270}$/;
const CREATE_CONTENT = "CREATE_CONTENT";
const STATUS_COLUMNS = "id, user_id, page_id, page_name, status, created_at, last_ok_at, last_error_code";
const SECRET_COLUMNS = "id, user_id, page_id, page_name, page_ciphertext, page_iv, page_auth_tag, user_ciphertext, user_iv, user_auth_tag, user_expires_at, granted_scopes, status, created_at, updated_at";
const POST_COLUMNS = "id, user_id, proposal_id, kind, status, post_id, permalink, video_id, error, removed_at, created_at, updated_at, published_at";
const MEDIA_COLUMNS = "id, user_id, path, kind, mime, bytes, sha256, label";
const CHOOSING_JOB_NAME = "facebook_choosing_purge";

const MESSAGES = Object.freeze({
  notConnected: "Connect Facebook first.",
  needsReconnect: "Facebook stopped accepting BizForce's access to your Page, so nothing is being posted. Connect again.",
  choosing: "Choose the Page to post to first.",
  webp: "Facebook doesn't accept WebP photos. Choose a JPEG, PNG or GIF.",
  photoType: "Facebook accepts JPEG, PNG and GIF photos. Choose one of those.",
  videoType: "Facebook videos must be MP4 or MOV.",
  kind: "Choose Text, Photos or Video.",
  items: "A Facebook post has 1 to 10 photos from your Media Library, each chosen once.",
  notInLibrary: "That photo isn't in your Media Library.",
  message: "A Facebook post's text is at most 63206 characters.",
  textEmpty: "Write the post's text first.",
  dailyCap: "You can post to Facebook 10 times in 24 hours. Nothing was sent. Try again later.",
  fingerprint: "A file in this post no longer matches the one you filed, so nothing was sent.",
  unread: "A file in this post could not be read just now, so nothing was sent.",
  pageChanged: "The Facebook Page connected now isn't the one this was filed for. Nothing was sent; file it again.",
  pending: "This video already has a Facebook post waiting for your approval.",
  fileGone: "That video's file is no longer here. Nothing was sent.",
  unreachable: "Facebook couldn't be reached just now. Nothing changed. Try again later.",
  publishedUnknown: "Facebook may have published this post. Check your Page before filing it again.",
  publishing: "Facebook hasn't confirmed this post yet. Check its status on the Social page in a minute.",
  notFound: "That Facebook post isn't here.",
  stale: "BizForce didn't finish sending this post to Facebook, so nothing was published. File it again.",
  failedRow: "This Facebook post already failed. File it again to try once more.",
  busy: "This post is being sent right now. Check its status in a minute.",
  notPublished: "Only a published Facebook post can be removed.",
  alreadyRemoved: "This post was already removed from Facebook.",
  removalPending: "A removal of this post is already waiting for your approval.",
  removed: "Removed from Facebook.",
  shape: "The filed post is not complete. Nothing was sent."
});

class FacebookApiError extends Error {
  constructor(kind, code, said) { super("facebook " + kind + " (" + code + ")"); this.name = "FacebookApiError"; this.kind = kind; this.code = code; this.said = said || null; }
}

function nowIso(deps) { return new Date(deps.now()).toISOString(); }
function bearer(token) { return { Authorization: "Bearer " + token }; }
function codePoints(s) { return Array.from(String(s)).length; }
function clean(text, max) { return String(text || "").replace(/[\u0000-\u001f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, max); }
/* What Facebook said, safe to show: plain text, no markup, at most 300 characters. */
function said(json) {
  var e = json && json.error && typeof json.error === "object" ? json.error : null;
  var m = e && typeof e.message === "string" ? clean(e.message, 300) : "";
  return m || null;
}
function ok(answer) { return !!(answer && typeof answer.status === "number" && answer.status >= 200 && answer.status < 300 && answer.json && typeof answer.json === "object"); }
/* A token Facebook refuses: 401, or the token and permission error codes
   (190 invalid token, 102 session, 10 and 200 to 299 permission), the rule
   lib/instagramApi.js tokenRefused uses. Not the error type: nearly every
   Graph error is typed OAuthException, including a refused photo or a rate
   limit, and those must not cut the member off. */
function tokenRefused(answer) {
  if (!answer) return false;
  if (answer.status === 401) return true;
  var e = answer.json && answer.json.error && typeof answer.json.error === "object" ? answer.json.error : null;
  var c = e ? e.code : null;
  return c === 190 || c === 102 || c === 10 || (typeof c === "number" && c >= 200 && c <= 299);
}
function idOf(v) {
  var s = typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? String(v) : (typeof v === "string" ? v : "");
  return ID_RE.test(s) ? s : null;
}
function postIdOf(v) { return typeof v === "string" && POST_ID_RE.test(v) ? v : idOf(v); }
/* A permalink as stored: absolute https://www.facebook.com/..., a relative one prefixed; else null. */
function permalinkFrom(v) {
  if (typeof v !== "string" || !v) return null;
  var p = v.charAt(0) === "/" ? PAGE_HOST + v : v;
  return p.length <= 300 && PERMALINK_RE.test(p) ? p : null;
}

/* ── the message ────────────────────────────────────────────────────────── */
/* { ok: true, message } or { ok: false, error }. needText: a text post must say something. */
function checkMessage(value, needText) {
  var message = value === undefined || value === null ? "" : value;
  if (typeof message !== "string") return { ok: false, error: MESSAGES.message };
  message = message.trim();
  if (codePoints(message) > MESSAGE_MAX) return { ok: false, error: MESSAGES.message };
  if (needText && !message) return { ok: false, error: MESSAGES.textEmpty };
  return { ok: true, message: message };
}

/* ── the files ──────────────────────────────────────────────────────────── */
/* One photo's bytes, checked against what was filed: the row the poster's
   image with the frozen sha256, size and type; the bytes exactly that long,
   hashing to it, and sniffing as that type. Throws FacebookApiError
   ("fingerprint" | "unread" | "type"). */
async function readPhoto(deps, ownerId, row, frozen) {
  if (!row || PHOTO_MIMES.indexOf(row.mime) === -1 || row.mime !== frozen.mime) throw new FacebookApiError("type", "photo_type");
  var buf;
  try {
    buf = await MM.readMediaForPost(row, { id: frozen.id, sha256: frozen.sha256, mime: frozen.mime, bytes: frozen.bytes },
      { storage: deps.storage, userId: ownerId, maxBytes: MM.MAX_FILE_BYTES });
  } catch (err) {
    throw new FacebookApiError(err && err.reason === "unread" ? "unread" : "fingerprint", (err && err.reason) || "changed");
  }
  if (MM.sniffMedia(buf) !== SNIFF_FOR[row.mime]) throw new FacebookApiError("type", "photo_bytes");
  return buf;
}

/* The video's file still holds the filed file: streamed and hashed, never held whole. */
async function verifyVideo(deps, video, frozen) {
  if (!video || video.sha256 !== frozen.sha256 || Number(video.bytes) !== Number(frozen.bytes) || video.mime !== frozen.mime) return false;
  var stream = await MV.openStream(deps.storage, video.path);
  if (!stream) return false;
  var m = await MV.measureStream(stream, MV.MAX_BYTES);
  return !m.tooBig && m.bytes === Number(frozen.bytes) && m.sha256 === frozen.sha256;
}

/* ── the connection ─────────────────────────────────────────────────────── */
async function readConnection(supabase, userId) {
  var r = await supabase.from("member_facebook_pages").select(SECRET_COLUMNS).eq("user_id", userId).maybeSingle();
  if (r.error) throw r.error;
  return r.data && r.data.user_id === userId ? r.data : null;
}

function statusOf(row, available) {
  var r = row || null;
  var paged = !!r && (r.status === "connected" || r.status === "needs_reconnect");
  return {
    facebook_available: available === true,
    connected: !!r && r.status === "connected",
    choosing: !!r && r.status === "choosing",
    status: r ? r.status : "not_connected",
    page_name: paged ? r.page_name : null,
    since: r ? r.created_at : null,
    reconnect_message: r && r.status === "needs_reconnect" ? MESSAGES.needsReconnect : null
  };
}

/* needs_reconnect and ONE notice, only when it was connected. Never throws. */
async function markNeedsReconnect(deps, row, code) {
  try {
    var stamp = nowIso(deps);
    var marked = await deps.supabase.from("member_facebook_pages")
      .update({ status: "needs_reconnect", last_error_at: stamp, last_error_code: String(code || "refused").slice(0, 60), updated_at: stamp })
      .eq("id", row.id).eq("user_id", row.user_id).eq("status", "connected").select("id");
    if (marked.error || !(marked.data || []).length) return false;
    var notice = await deps.supabase.from("notifications").insert({
      user_id: row.user_id,
      type: "facebook_reconnect",
      title: "Reconnect your Facebook Page",
      message: "Facebook stopped accepting BizForce's access to " + row.page_name + ", so nothing is being posted and nothing will be tried again. Connect Facebook again on the Social Agent page.",
      read: false
    });
    if (notice.error) console.warn("[facebook] the reconnect notice could not be saved: " + (notice.error.code || "error"));
    return true;
  } catch (err) {
    return false;
  }
}

function unseal(deps, row, which) {
  try {
    return deps.crypt.decrypt({ ciphertext: row[which + "_ciphertext"], iv: row[which + "_iv"], authTag: row[which + "_auth_tag"] });
  } catch (err) {
    throw new FacebookApiError("auth", "secret_unreadable");
  }
}

async function api(deps, url, options) {
  try {
    return await deps.jsonRequest(url, Object.assign({ timeoutMs: API_TIMEOUT_MS }, options));
  } catch (err) {
    throw new FacebookApiError("unreachable", (err && typeof err.code === "string" && /^[a-z_]{1,40}$/.test(err.code)) ? err.code : "request");
  }
}

/* A call with the Page token. A refused token marks needs_reconnect. */
async function withToken(deps, row, send) {
  if (!row || row.status !== "connected") throw new FacebookApiError("auth", "not_connected");
  var token = unseal(deps, row, "page");
  var answer;
  try {
    answer = await send(token);
  } finally {
    token = null;
  }
  if (tokenRefused(answer)) {
    await markNeedsReconnect(deps, row, "unauthorized");
    throw new FacebookApiError("auth", "unauthorized");
  }
  return answer;
}

/* ── the user token's calls: permissions and Pages ──────────────────────── */
/* The permissions Facebook says are granted: [name]. */
async function readPermissions(deps, userToken) {
  var answer = await api(deps, API_BASE + "/me/permissions", { method: "GET", headers: bearer(userToken) });
  if (tokenRefused(answer)) throw new FacebookApiError("auth", "unauthorized");
  if (!ok(answer)) throw new FacebookApiError("unreachable", "permissions_" + (answer ? answer.status : "none"));
  var list = Array.isArray(answer.json.data) ? answer.json.data : [];
  return list.filter(function (p) { return p && p.status === "granted" && typeof p.permission === "string"; })
    .map(function (p) { return p.permission; });
}

/* The member's Pages: [{ page_id, name, token, postable }]. postable: the
   member's tasks on it include CREATE_CONTENT. Tokens stay in this result and
   are never returned to a member (pageChoices). */
async function readPages(deps, userToken) {
  var answer = await api(deps, API_BASE + "/me/accounts?fields=id,name,access_token,tasks&limit=" + PAGE_LIST_MAX, { method: "GET", headers: bearer(userToken) });
  if (tokenRefused(answer)) throw new FacebookApiError("auth", "unauthorized");
  if (!ok(answer)) throw new FacebookApiError("unreachable", "accounts_" + (answer ? answer.status : "none"));
  var list = Array.isArray(answer.json.data) ? answer.json.data : [];
  var out = [];
  list.forEach(function (p) {
    if (!p || typeof p !== "object") return;
    var id = idOf(p.id);
    var name = typeof p.name === "string" ? clean(p.name, 200) : "";
    if (!id || !name || typeof p.access_token !== "string" || !p.access_token) return;
    var tasks = Array.isArray(p.tasks) ? p.tasks : [];
    out.push({ page_id: id, name: name, token: p.access_token, postable: tasks.indexOf(CREATE_CONTENT) !== -1 });
  });
  return out;
}
function postablePages(pages) { return (pages || []).filter(function (p) { return p.postable === true; }); }
/* What a member is shown of their Pages: the id and the name, never a token. */
function pageChoices(pages) { return postablePages(pages).map(function (p) { return { page_id: p.page_id, name: p.name }; }); }

/* The row for one chosen Page: its token sealed, the user token cleared. */
function connectedRow(deps, page, stamp) {
  var s = deps.crypt.encrypt(page.token);
  return {
    page_id: page.page_id, page_name: page.name,
    page_ciphertext: s.ciphertext, page_iv: s.iv, page_auth_tag: s.authTag,
    user_ciphertext: null, user_iv: null, user_auth_tag: null, user_expires_at: null,
    status: "connected", last_ok_at: stamp, last_error_at: null, last_error_code: null, updated_at: stamp
  };
}

/* After finish has sealed the long-lived user token: the permissions, then
   the Pages. { status, body }. sealedUser: the user token as sealed; userToken
   is used for the two reads only. */
async function connectAfterSeal(deps, userId, userToken, sealedUser, userExpiresAt) {
  var granted;
  try {
    granted = await readPermissions(deps, userToken);
  } catch (err) {
    return { status: 502, body: { error: FA.MESSAGES.unreachable, code: "unreachable", saved: false } };
  }
  if (!FA.grantsAll(granted)) return { status: 422, body: { error: FA.MESSAGES.noScopes, code: "no_scopes", saved: false } };
  var pages;
  try {
    pages = await readPages(deps, userToken);
  } catch (err) {
    return { status: 502, body: { error: FA.MESSAGES.unreachable, code: "unreachable", saved: false } };
  }
  var postable = postablePages(pages);
  if (!postable.length) return { status: 422, body: { error: FA.MESSAGES.noPage, code: "no_page", saved: false } };
  var stamp = nowIso(deps);
  var base = { user_id: userId, granted_scopes: FA.scopesOf(granted), created_at: stamp };
  var record;
  if (postable.length === 1) {
    // One Page: connected at once, its token sealed, the user token let go.
    record = Object.assign(base, connectedRow(deps, postable[0], stamp));
  } else {
    record = Object.assign(base, {
      page_id: null, page_name: null, page_ciphertext: null, page_iv: null, page_auth_tag: null,
      user_ciphertext: sealedUser.ciphertext, user_iv: sealedUser.iv, user_auth_tag: sealedUser.authTag, user_expires_at: userExpiresAt,
      status: "choosing", last_ok_at: stamp, last_error_at: null, last_error_code: null, updated_at: stamp
    });
  }
  pages = null;
  var saved = await deps.supabase.from("member_facebook_pages").upsert(record, { onConflict: "user_id" }).select(STATUS_COLUMNS).single();
  if (saved.error) throw saved.error;
  var body = statusOf(saved.data, true);
  if (record.status === "choosing") body.pages = pageChoices(postable);
  return { status: 200, body: body };
}

/* The choosing row and its live list, read with the sealed user token.
   { row, pages } or { error: { status, body } }. An expired or refused choice
   is deleted: the member connects again. */
async function choosingPages(deps, userId) {
  var row = await readConnection(deps.supabase, userId);
  if (!row || row.status !== "choosing") return { error: { status: 409, body: { error: FA.MESSAGES.notChoosing, code: "not_choosing" } } };
  var drop = async function () {
    var d = await deps.supabase.from("member_facebook_pages").delete().eq("id", row.id).eq("user_id", userId).eq("status", "choosing");
    if (d.error) throw d.error;
  };
  if (FA.choosingExpired(row, deps.now())) {
    await drop();
    return { error: { status: 410, body: { error: FA.MESSAGES.choiceExpired, code: "choice_expired" } } };
  }
  var token = unseal(deps, row, "user");
  try {
    return { row: row, pages: await readPages(deps, token) };
  } catch (err) {
    if (err && err.kind === "auth") {
      await drop();
      return { error: { status: 410, body: { error: FA.MESSAGES.choiceExpired, code: "choice_expired" } } };
    }
    return { error: { status: 502, body: { error: MESSAGES.unreachable, code: "unreachable" } } };
  } finally {
    token = null;
  }
}

/* GET /api/facebook/pages: the Pages to choose from, never a token. */
async function listChoices(deps, userId) {
  var got = await choosingPages(deps, userId);
  if (got.error) return got.error;
  return { status: 200, body: { pages: pageChoices(got.pages) } };
}

/* POST /api/facebook/choose-page { page_id }: only a Page the live list names
   as postable. Its token sealed, the user token cleared, connected. */
async function choosePage(deps, userId, input) {
  var pageId = input && typeof input.page_id === "string" && ID_RE.test(input.page_id) ? input.page_id : null;
  if (!pageId) return { status: 400, body: { error: FA.MESSAGES.notListed, code: "invalid", field: "page_id" } };
  var got = await choosingPages(deps, userId);
  if (got.error) return got.error;
  var page = postablePages(got.pages).filter(function (p) { return p.page_id === pageId; })[0];
  got.pages = null;
  if (!page) return { status: 404, body: { error: FA.MESSAGES.notListed, code: "not_listed", field: "page_id" } };
  var stamp = nowIso(deps);
  var u = await deps.supabase.from("member_facebook_pages").update(connectedRow(deps, page, stamp))
    .eq("id", got.row.id).eq("user_id", userId).eq("status", "choosing").select(STATUS_COLUMNS);
  page = null;
  if (u.error) throw u.error;
  if ((u.data || []).length !== 1) return { status: 409, body: { error: FA.MESSAGES.notChoosing, code: "not_choosing" } };
  return { status: 200, body: statusOf(u.data[0], true) };
}

/* ── the Graph calls with the Page token ────────────────────────────────── */
/* POST on the Page; the answer as it came (FacebookApiError("auth") when the token was refused). */
function pagePost(deps, conn, url, body) {
  return withToken(deps, conn, function (token) { return api(deps, url, { method: "POST", headers: bearer(token), body: body }); });
}

/* One unpublished photo upload: its id. Throws FacebookApiError ("refused" with Facebook's words). */
async function uploadUnpublished(deps, conn, url) {
  var answer = await pagePost(deps, conn, API_BASE + "/" + conn.page_id + "/photos", { url: url, published: false });
  if (!ok(answer)) throw new FacebookApiError("refused", "photo_" + answer.status, said(answer.json));
  var id = idOf(answer.json.id);
  if (!id) throw new FacebookApiError("refused", "photo_shape");
  return id;
}

/* The final call's answer: { id } when Facebook answered with one; { refused,
   said } when it refused; { unclear } when the answer never came or can't be
   read (the post may or may not be up: the status check looks it up). */
function finalOutcome(answer, idField) {
  if (ok(answer)) {
    var id = postIdOf(answer.json[idField]) || (idField !== "id" ? postIdOf(answer.json.id) : null);
    return id ? { id: id } : { unclear: true };
  }
  if (answer && answer.status >= 400 && answer.status < 500) return { refused: true, said: said(answer.json) };
  return { unclear: true };
}

/* The post's address, or null. Best effort: never throws. For a video, also
   Facebook's processing state (video_status), when it says one. */
async function permalinkOf(deps, conn, postId, isVideo) {
  try {
    var answer = await withToken(deps, conn, function (token) {
      return api(deps, API_BASE + "/" + postId + "?fields=permalink_url" + (isVideo ? ",status" : ""), { method: "GET", headers: bearer(token) });
    });
    if (!ok(answer)) return { permalink: null, video_status: null };
    var vs = isVideo && answer.json.status && typeof answer.json.status.video_status === "string" ? clean(answer.json.status.video_status, 40) : null;
    return { permalink: permalinkFrom(answer.json.permalink_url), video_status: vs };
  } catch (err) {
    return { permalink: null, video_status: null, auth: !!(err && err.kind === "auth") };
  }
}

/* The newest of the Page's last 10 posts with this message, at or after
   `since`: its id, or null. Throws when the list can't be read. */
async function findPublished(deps, conn, message, since) {
  var answer = await withToken(deps, conn, function (token) {
    return api(deps, API_BASE + "/" + conn.page_id + "/posts?fields=id,message,created_time&limit=10", { method: "GET", headers: bearer(token) });
  });
  if (!ok(answer)) throw new FacebookApiError("unreachable", "posts_list_" + answer.status);
  var list = Array.isArray(answer.json.data) ? answer.json.data : [];
  var sinceMs = Date.parse(since || "");
  var want = String(message || "").trim();
  var best = null, bestMs = -Infinity;
  list.forEach(function (m) {
    if (!m || typeof m !== "object") return;
    var id = postIdOf(m.id);
    var at = Date.parse(String(m.created_time || "").replace(/([+-]\d\d)(\d\d)$/, "$1:$2"));
    var text = typeof m.message === "string" ? m.message.trim() : "";
    // Facebook's clock may run a little behind ours: a minute's grace.
    if (!id || !isFinite(at) || !isFinite(sinceMs) || at < sinceMs - 60 * 1000 || text !== want) return;
    if (at > bestMs) { best = id; bestMs = at; }
  });
  return best;
}

/* ── the post row ───────────────────────────────────────────────────────── */
async function readPostByProposal(supabase, proposalId) {
  var r = await supabase.from("facebook_posts").select(POST_COLUMNS).eq("proposal_id", proposalId).maybeSingle();
  if (r.error) throw r.error;
  return r.data || null;
}

async function postsToday(deps, userId) {
  var since = new Date(deps.now() - 24 * 60 * 60 * 1000).toISOString();
  var counted = await deps.supabase.from("facebook_posts").select("id", { count: "exact", head: true })
    .eq("user_id", userId).neq("status", "failed").gte("created_at", since);
  if (counted.error) throw new FacebookApiError("unreachable", "count");
  return counted.count || 0;
}

async function markFailed(deps, row, text) {
  var stamp = nowIso(deps);
  var u = await deps.supabase.from("facebook_posts").update({ status: "failed", error: String(text || MESSAGES.unreachable).slice(0, 300), updated_at: stamp })
    .eq("id", row.id).in("status", ["creating", "publishing"]).select("id");
  return !u.error && (u.data || []).length === 1;
}

/* creating -> publishing, BEFORE the final call: the row then says the post may be up. */
async function markPublishing(deps, row) {
  var stamp = nowIso(deps);
  var u = await deps.supabase.from("facebook_posts").update({ status: "publishing", updated_at: stamp })
    .eq("id", row.id).eq("status", "creating").is("post_id", null).select(POST_COLUMNS);
  if (u.error || (u.data || []).length !== 1) return null;
  return u.data[0];
}

async function recordPublished(deps, conn, row, postId) {
  var link = await permalinkOf(deps, conn, postId, row.kind === "video");
  var stamp = nowIso(deps);
  var u = await deps.supabase.from("facebook_posts").update({ status: "published", post_id: postId, permalink: link.permalink, published_at: stamp, error: null, updated_at: stamp })
    .eq("id", row.id).in("status", ["creating", "publishing"]).select("id");
  if (u.error || (u.data || []).length !== 1) {
    throw new Error("publish_facebook_post: the post WAS published to Facebook, but it could not be recorded. Don't file it again.");
  }
  return { published: true, status: "published", permalink: link.permalink, published_at: stamp,
    processing: row.kind === "video" ? (link.video_status || "processing") : null };
}

/* publishing with no post_id recorded: look it up, or fail the row with the plain words. */
async function recoverPublishing(deps, conn, row, message) {
  var found;
  try {
    found = await findPublished(deps, conn, message, row.created_at);
  } catch (err) {
    if (err && err.kind === "auth") return { status: "publishing", error: MESSAGES.needsReconnect, needs_reconnect: true };
    return { publishing: true, status: "publishing", note: MESSAGES.publishing };
  }
  if (found) return recordPublished(deps, conn, row, found);
  await markFailed(deps, row, MESSAGES.publishedUnknown);
  return { published_unknown: true, status: "failed", error: MESSAGES.publishedUnknown };
}

/* ── the payload ────────────────────────────────────────────────────────── */
function itemShape(it) {
  return !!it && typeof it === "object" && MV.UUID_RE.test(String(it.id || "")) && SHA_RE.test(String(it.sha256 || "")) &&
    Number.isInteger(it.bytes) && it.bytes > 0 && PHOTO_MIMES.indexOf(it.mime) !== -1;
}
function payloadShape(p) {
  if (!p || typeof p !== "object" || typeof p.message !== "string" || typeof p.page_id !== "string" || !ID_RE.test(p.page_id)) return false;
  if (codePoints(p.message) > MESSAGE_MAX) return false;
  if (p.kind === "text") return !p.items && !p.video && p.message.trim().length > 0;
  if (p.kind === "photo" || p.kind === "photos") {
    if (!Array.isArray(p.items) || p.video) return false;
    var n = p.items.length;
    if (p.kind === "photo" ? n !== 1 : (n < 2 || n > ITEMS_MAX)) return false;
    var seen = {};
    return p.items.every(function (it) { if (!itemShape(it) || seen[it.id]) return false; seen[it.id] = true; return true; });
  }
  if (p.kind === "video") {
    var v = p.video;
    return !p.items && !!v && typeof v === "object" && MV.UUID_RE.test(String(v.id || "")) && SHA_RE.test(String(v.sha256 || "")) &&
      Number.isInteger(v.bytes) && v.bytes > 0 && VIDEO_MIMES.indexOf(v.mime) !== -1;
  }
  return false;
}
function deletePayloadShape(p) {
  return !!p && typeof p === "object" && MV.UUID_RE.test(String(p.facebook_post_id || "")) && typeof p.post_id === "string" && POST_ID_RE.test(p.post_id) &&
    typeof p.page_id === "string" && ID_RE.test(p.page_id);
}

async function readMediaRows(supabase, userId, ids) {
  var r = await supabase.from("member_media").select(MEDIA_COLUMNS).eq("user_id", userId).in("id", ids);
  if (r.error) throw r.error;
  var byId = {};
  (r.data || []).forEach(function (row) { if (row.user_id === userId) byId[row.id] = row; });
  return byId;
}

/* ── the executors ──────────────────────────────────────────────────────── */

/* The publish_facebook_post executor. One argument, the claimed proposal. */
async function executePublish(deps, proposal) {
  var fail = function (why) { return new Error("publish_facebook_post: " + why); };
  var p = proposal && proposal.payload && typeof proposal.payload === "object" ? proposal.payload : {};
  var ownerId = proposal && proposal.user_id;
  if (!payloadShape(p) || !proposal.id) throw fail(MESSAGES.shape);
  var msg = checkMessage(p.message, p.kind === "text");
  if (!msg.ok) throw fail(msg.error + " Nothing was sent.");
  var refused = msg.message ? deps.claims(msg.message) : null;
  if (refused) throw fail(refused.error + " Nothing was sent.");
  var conn = await readConnection(deps.supabase, ownerId);
  if (!conn) throw fail(MESSAGES.notConnected + " Nothing was sent.");
  if (conn.status !== "connected") throw fail(conn.status === "choosing" ? MESSAGES.choosing + " Nothing was sent." : MESSAGES.needsReconnect);
  if (conn.page_id !== p.page_id) throw fail(MESSAGES.pageChanged);

  // The row first: a replay continues from it and never posts a second time.
  var row = await readPostByProposal(deps.supabase, proposal.id);
  if (row && row.user_id !== ownerId) throw fail(MESSAGES.shape);
  if (row && row.status === "published") return { already_published: true, status: "published", permalink: row.permalink, published_at: row.published_at };
  if (row && row.status === "failed") throw fail(row.error || MESSAGES.failedRow);
  if (row && row.status === "publishing") {
    // The final call may have reached Facebook: never sent again, only looked up.
    var rec = await recoverPublishing(deps, conn, row, msg.message);
    if (rec.published_unknown || rec.needs_reconnect) throw fail(rec.error);
    return Object.assign({ post_id: row.id }, rec);
  }

  // Nothing at Facebook is ours yet (no row, or creating): the files are checked again.
  var mediaRows = null, video = null;
  if (p.kind === "video") {
    video = await MV.readVideo(deps.supabase, ownerId, p.video.id);
    if (!video || video.status !== "ready" || !video.path) throw fail(MESSAGES.fileGone);
    if (VIDEO_MIMES.indexOf(video.mime) === -1) throw fail(MESSAGES.videoType + " Nothing was sent.");
    if (video.sha256 !== p.video.sha256 || Number(video.bytes) !== p.video.bytes || video.mime !== p.video.mime) throw fail(MESSAGES.fingerprint);
  } else if (p.kind !== "text") {
    mediaRows = await readMediaRows(deps.supabase, ownerId, p.items.map(function (it) { return it.id; }));
    for (var c = 0; c < p.items.length; c++) {
      var mr = mediaRows[p.items[c].id];
      if (!mr) throw fail(MESSAGES.fingerprint);
      if (mr.kind !== "image" || PHOTO_MIMES.indexOf(mr.mime) === -1) throw fail((mr.mime === "image/webp" ? MESSAGES.webp : MESSAGES.photoType) + " Nothing was sent.");
      if (mr.sha256 !== p.items[c].sha256 || mr.bytes !== p.items[c].bytes || mr.mime !== p.items[c].mime) throw fail(MESSAGES.fingerprint);
    }
  }

  if (!row) {
    var today;
    try { today = await postsToday(deps, ownerId); } catch (err) { throw fail(MESSAGES.unreachable); }
    if (today >= POSTS_PER_DAY) throw fail(MESSAGES.dailyCap);
    var stamp = nowIso(deps);
    var ins = await deps.supabase.from("facebook_posts").insert({
      user_id: ownerId, proposal_id: proposal.id, kind: p.kind, status: "creating",
      video_id: p.kind === "video" ? p.video.id : null, created_at: stamp, updated_at: stamp
    }).select(POST_COLUMNS).single();
    if (ins.error && ins.error.code === "23505") {
      row = await readPostByProposal(deps.supabase, proposal.id);
      if (!row) throw fail(MESSAGES.unreachable);
      if (row.status !== "creating") throw fail(MESSAGES.busy);
    } else if (ins.error || !ins.data) {
      throw fail("the post couldn't be recorded before sending, so nothing was sent.");
    } else {
      row = ins.data;
    }
  }

  var outcome, publishingRow = null;
  try {
    if (p.kind === "text") {
      publishingRow = await markPublishing(deps, row);
      if (!publishingRow) throw new FacebookApiError("busy", "not_creating");
      outcome = finalOutcome(await pagePost(deps, conn, API_BASE + "/" + conn.page_id + "/feed", { message: msg.message }), "id");
    } else if (p.kind === "photo") {
      // Checked right before its address is handed over.
      await readPhoto(deps, ownerId, mediaRows[p.items[0].id], p.items[0]);
      publishingRow = await markPublishing(deps, row);
      if (!publishingRow) throw new FacebookApiError("busy", "not_creating");
      outcome = finalOutcome(await pagePost(deps, conn, API_BASE + "/" + conn.page_id + "/photos",
        { url: MM.publicUrlFor(mediaRows[p.items[0].id].path, deps.base), message: msg.message, published: true }), "post_id");
    } else if (p.kind === "photos") {
      var media = [];
      for (var k = 0; k < p.items.length; k++) {
        var it = p.items[k];
        // Each checked right before ITS address is handed over; uploaded unpublished.
        await readPhoto(deps, ownerId, mediaRows[it.id], it);
        media.push({ media_fbid: await uploadUnpublished(deps, conn, MM.publicUrlFor(mediaRows[it.id].path, deps.base)) });
      }
      publishingRow = await markPublishing(deps, row);
      if (!publishingRow) throw new FacebookApiError("busy", "not_creating");
      outcome = finalOutcome(await pagePost(deps, conn, API_BASE + "/" + conn.page_id + "/feed", { message: msg.message, attached_media: media }), "id");
    } else {
      // Streamed and hashed first; only then the short signed link, used in this one body.
      if (!(await verifyVideo(deps, video, p.video))) throw new FacebookApiError("fingerprint", "video_sha");
      var signed = await deps.storage.from(MV.BUCKET).createSignedUrl(video.path, SIGNED_URL_SECONDS);
      var link = signed && !signed.error && signed.data && typeof signed.data.signedUrl === "string" ? signed.data.signedUrl : "";
      if (link.indexOf("https://") !== 0) throw new FacebookApiError("unread", "signed_url");
      try {
        publishingRow = await markPublishing(deps, row);
        if (!publishingRow) throw new FacebookApiError("busy", "not_creating");
        outcome = finalOutcome(await pagePost(deps, conn, VIDEO_BASE + "/" + conn.page_id + "/videos", { file_url: link, description: msg.message }), "id");
      } finally {
        link = null; signed = null;
      }
    }
  } catch (err) {
    if (err && err.kind === "auth") {
      // A refused token: the final call did not post, so the row is failed, never left publishing.
      if (publishingRow) await markFailed(deps, publishingRow, MESSAGES.needsReconnect);
      throw fail(MESSAGES.needsReconnect);
    }
    if (err && err.kind === "busy") throw fail(MESSAGES.busy);
    if (err && err.kind === "type") { await markFailed(deps, row, MESSAGES.photoType); throw fail(MESSAGES.photoType + " Nothing was sent."); }
    if (err && err.kind === "fingerprint") { await markFailed(deps, row, MESSAGES.fingerprint); throw fail(MESSAGES.fingerprint); }
    if (err && err.kind === "unread") throw fail(MESSAGES.unread);
    if (err && err.kind === "refused") {
      var words = err.said ? "Facebook refused the post: " + err.said : "Facebook didn't accept the post.";
      await markFailed(deps, row, words + " Nothing was published.");
      throw fail(words + " Nothing was published.");
    }
    // No answer to the final call: the row stays publishing, and "Check status" looks it up.
    if (publishingRow) return { publishing: true, status: "publishing", post_id: row.id, note: MESSAGES.publishing };
    throw fail(MESSAGES.unreachable);
  }
  if (outcome.id) return Object.assign({ post_id: row.id }, await recordPublished(deps, conn, publishingRow, outcome.id));
  if (outcome.refused) {
    var refusedWhy = (outcome.said ? "Facebook refused the post: " + outcome.said : "Facebook refused the post.").slice(0, 300);
    await markFailed(deps, publishingRow, refusedWhy);
    throw fail(refusedWhy);
  }
  return { publishing: true, status: "publishing", post_id: row.id, note: MESSAGES.publishing };
}

/* The delete_facebook_post executor: ONE DELETE, then removed_at. Never twice. */
async function executeDelete(deps, proposal) {
  var fail = function (why) { return new Error("delete_facebook_post: " + why); };
  var p = proposal && proposal.payload && typeof proposal.payload === "object" ? proposal.payload : {};
  var ownerId = proposal && proposal.user_id;
  if (!deletePayloadShape(p)) throw fail(MESSAGES.shape);
  var r = await deps.supabase.from("facebook_posts").select(POST_COLUMNS).eq("id", p.facebook_post_id).eq("user_id", ownerId).maybeSingle();
  if (r.error) throw r.error;
  var row = r.data && r.data.user_id === ownerId ? r.data : null;
  if (!row) throw fail(MESSAGES.notFound);
  if (row.removed_at) throw fail(MESSAGES.alreadyRemoved);
  if (row.status !== "published" || row.post_id !== p.post_id) throw fail(MESSAGES.notPublished);
  var conn = await readConnection(deps.supabase, ownerId);
  if (!conn) throw fail(MESSAGES.notConnected + " Nothing was removed.");
  if (conn.status !== "connected") throw fail(MESSAGES.needsReconnect);
  if (conn.page_id !== p.page_id) throw fail(MESSAGES.pageChanged.replace("Nothing was sent; file it again.", "Nothing was removed."));
  var answer;
  try {
    answer = await withToken(deps, conn, function (token) { return api(deps, API_BASE + "/" + row.post_id, { method: "DELETE", headers: bearer(token) }); });
  } catch (err) {
    throw fail(err && err.kind === "auth" ? MESSAGES.needsReconnect : MESSAGES.unreachable);
  }
  if (!ok(answer) || answer.json.success === false) {
    var words = said(answer && answer.json);
    throw fail((words ? "Facebook didn't remove it: " + words : "Facebook didn't remove it.") + " Nothing changed.");
  }
  var stamp = nowIso(deps);
  var u = await deps.supabase.from("facebook_posts").update({ removed_at: stamp, updated_at: stamp })
    .eq("id", row.id).eq("user_id", ownerId).eq("status", "published").is("removed_at", null).select("id");
  if (u.error || (u.data || []).length !== 1) throw new Error("delete_facebook_post: the post WAS removed from Facebook, but that could not be recorded.");
  return { removed: true, removed_at: stamp, note: MESSAGES.removed };
}

/* What a member is shown about one post: never a proposal payload. */
function postView(row) {
  var published = row.status === "published";
  return { id: row.id, kind: row.kind, status: row.status, permalink: published ? row.permalink || null : null,
    error: row.status === "failed" ? row.error || null : null, created_at: row.created_at, published_at: row.published_at || null,
    removed_at: published ? row.removed_at || null : null };
}

/* GET /api/facebook/posts/:id/status. { status, body }. Never posts. */
async function postStatus(deps, userId, id) {
  if (typeof id !== "string" || !MV.UUID_RE.test(id)) return { status: 404, body: { error: MESSAGES.notFound, code: "not_found" } };
  var r = await deps.supabase.from("facebook_posts").select(POST_COLUMNS).eq("id", id).eq("user_id", userId).maybeSingle();
  if (r.error) throw r.error;
  var row = r.data && r.data.user_id === userId ? r.data : null;
  if (!row) return { status: 404, body: { error: MESSAGES.notFound, code: "not_found" } };
  if (row.status === "failed" || (row.status === "published" && row.removed_at)) return { status: 200, body: postView(row) };
  if (row.status === "creating") {
    if (deps.now() - Date.parse(row.created_at) >= STALE_CREATING_MS && await markFailed(deps, row, MESSAGES.stale)) {
      return { status: 200, body: postView(Object.assign({}, row, { status: "failed", error: MESSAGES.stale })) };
    }
    return { status: 200, body: Object.assign(postView(row), { note: MESSAGES.busy }) };
  }
  var conn = await readConnection(deps.supabase, userId);
  if (!conn) return { status: 409, body: { error: MESSAGES.notConnected, code: "not_connected" } };
  if (conn.status !== "connected") return { status: 409, body: { error: MESSAGES.needsReconnect, code: "needs_reconnect" } };
  if (row.status === "published") {
    // The address and, for a video, Facebook's processing, read again.
    var link = await permalinkOf(deps, conn, row.post_id, row.kind === "video");
    if (link.auth) return { status: 409, body: { error: MESSAGES.needsReconnect, code: "needs_reconnect" } };
    if (link.permalink && link.permalink !== row.permalink) {
      var u = await deps.supabase.from("facebook_posts").update({ permalink: link.permalink, updated_at: nowIso(deps) })
        .eq("id", row.id).eq("user_id", userId).eq("status", "published").select("id");
      if (!u.error && (u.data || []).length === 1) row = Object.assign({}, row, { permalink: link.permalink });
    }
    return { status: 200, body: Object.assign(postView(row), row.kind === "video" ? { processing: link.video_status } : {}) };
  }
  // publishing with no post_id: look it up with the approved message, from the proposal. Never posted again.
  var prop = await deps.supabase.from("agent_proposals").select("id, user_id, payload").eq("id", row.proposal_id).eq("user_id", userId).maybeSingle();
  if (prop.error) throw prop.error;
  var message = prop.data && prop.data.payload && typeof prop.data.payload.message === "string" ? prop.data.payload.message.trim() : "";
  var out = await recoverPublishing(deps, conn, row, message);
  if (out.needs_reconnect) return { status: 409, body: { error: MESSAGES.needsReconnect, code: "needs_reconnect" } };
  var fresh = await deps.supabase.from("facebook_posts").select(POST_COLUMNS).eq("id", row.id).eq("user_id", userId).maybeSingle();
  var view = postView(fresh.data || row);
  return { status: 200, body: Object.assign(view, out.note ? { note: out.note } : {}, out.error ? { error: out.error } : {}) };
}

/* GET /api/facebook/posts: the member's own, newest first. */
async function listPosts(deps, userId) {
  var r = await deps.supabase.from("facebook_posts").select(POST_COLUMNS).eq("user_id", userId).order("created_at", { ascending: false }).limit(50);
  if (r.error) throw r.error;
  return (r.data || []).filter(function (row) { return row.user_id === userId; }).map(postView);
}

/* ── filing ─────────────────────────────────────────────────────────────── */

async function connectedOr(deps, userId) {
  var conn = await readConnection(deps.supabase, userId);
  if (!conn) return { error: { status: 409, body: { error: MESSAGES.notConnected, code: "not_connected" } } };
  if (conn.status === "choosing") return { error: { status: 409, body: { error: MESSAGES.choosing, code: "choosing" } } };
  if (conn.status !== "connected") return { error: { status: 409, body: { error: MESSAGES.needsReconnect, code: "needs_reconnect" } } };
  return { conn: conn };
}

/* The media_ids a filing sent: { ids } or { error }. */
function parseItems(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > ITEMS_MAX) return { error: MESSAGES.items };
  var seen = {};
  for (var i = 0; i < value.length; i++) {
    if (typeof value[i] !== "string" || !MV.UUID_RE.test(value[i]) || seen[value[i]]) return { error: MESSAGES.items };
    seen[value[i]] = true;
  }
  return { ids: value.slice() };
}

/* POST /api/facebook/propose-post { kind: "text" | "photos" | "video", message, media_ids, video_id }. { status, body }. Files; never runs it. */
async function proposePost(deps, userId, input) {
  var b = input || {};
  var c = await connectedOr(deps, userId);
  if (c.error) return c.error;
  if (b.kind !== "text" && b.kind !== "photos" && b.kind !== "video") return { status: 400, body: { error: MESSAGES.kind + " Nothing was filed.", code: "invalid", field: "kind" } };
  var msg = checkMessage(b.message, b.kind === "text");
  if (!msg.ok) return { status: 400, body: { error: msg.error + " Nothing was filed.", code: "invalid", field: "message" } };
  var refused = msg.message ? deps.claims(msg.message) : null;
  if (refused) return { status: 422, body: { error: refused.error + " Nothing was filed.", code: "claims", field: "message", violations: refused.violations } };
  if (await postsToday(deps, userId) >= POSTS_PER_DAY) return { status: 409, body: { error: MESSAGES.dailyCap, code: "daily_cap" } };

  var payload, label;
  if (b.kind === "text") {
    payload = { kind: "text", message: msg.message, page_id: c.conn.page_id };
    label = "text";
  } else if (b.kind === "photos") {
    var parsed = parseItems(b.media_ids);
    if (parsed.error) return { status: 400, body: { error: parsed.error + " Nothing was filed.", code: "invalid", field: "media_ids" } };
    var rows = await readMediaRows(deps.supabase, userId, parsed.ids);
    var items = [];
    for (var i = 0; i < parsed.ids.length; i++) {
      var row = rows[parsed.ids[i]];
      if (!row) return { status: 404, body: { error: MESSAGES.notInLibrary, code: "not_found", field: "media_ids" } };
      var name = (row.label || "").trim() || "untitled photo";
      if (row.kind !== "image" || PHOTO_MIMES.indexOf(row.mime) === -1) {
        return { status: 400, body: { error: (row.mime === "image/webp" ? MESSAGES.webp : MESSAGES.photoType) + " (" + name + ")", code: row.mime === "image/webp" ? "webp" : "photo_type", field: "media_ids" } };
      }
      // The bytes themselves, now: the type by its own bytes, matching the row.
      try {
        await readPhoto(deps, userId, row, { id: row.id, sha256: row.sha256, bytes: row.bytes, mime: row.mime });
      } catch (err) {
        if (err && err.kind === "type") return { status: 400, body: { error: MESSAGES.photoType + " (" + name + ")", code: "photo_type", field: "media_ids" } };
        return { status: 409, body: { error: MESSAGES.unread + " (" + name + ")", code: "unread", field: "media_ids" } };
      }
      items.push({ id: row.id, sha256: row.sha256, bytes: row.bytes, mime: row.mime });
    }
    payload = { kind: items.length === 1 ? "photo" : "photos", items: items, message: msg.message, page_id: c.conn.page_id };
    label = items.length === 1 ? "1 photo" : items.length + " photos";
  } else {
    var video = await MV.readVideo(deps.supabase, userId, b.video_id);
    if (!video) return { status: 404, body: { error: MV.MESSAGES.notFound, code: "not_found" } };
    if (video.status !== "ready" || !video.path) return { status: 409, body: { error: MESSAGES.fileGone, code: "not_ready" } };
    if (VIDEO_MIMES.indexOf(video.mime) === -1) return { status: 400, body: { error: MESSAGES.videoType + " Nothing was filed.", code: "video_type", field: "video_id" } };
    if ((await MV.proposalsNaming(deps.supabase, userId, video.id, [ACTION])).length) return { status: 409, body: { error: MESSAGES.pending, code: "pending" } };
    payload = { kind: "video", video: { id: video.id, sha256: video.sha256, bytes: Number(video.bytes), mime: video.mime }, message: msg.message, page_id: c.conn.page_id };
    label = "a video";
  }
  if (!payloadShape(payload)) return { status: 400, body: { error: MESSAGES.shape, code: "invalid" } };
  var title = ("Post to the Facebook Page " + c.conn.page_name + " (" + label + "): " + (msg.message || "no text")).slice(0, 200);
  var ins = await deps.supabase.from("agent_proposals").insert({
    user_id: userId, agent_type: "social", action_type: ACTION,
    title: title, target: "facebook", payload: payload, cost_amount: 0, cost_currency: "USD", reversible: true,
    status: "pending", created_at: nowIso(deps)
  }).select("*").single();
  if (ins.error) throw ins.error;
  return { status: 201, body: { proposal: ins.data, page_name: c.conn.page_name,
    note: "Filed for approval. Nothing has been sent to Facebook. Approving it on the proposals page publishes this post to " + c.conn.page_name + "." } };
}

/* POST /api/facebook/posts/:id/propose-delete. { status, body }. Files the removal; never runs it. */
async function proposeDelete(deps, userId, id) {
  if (typeof id !== "string" || !MV.UUID_RE.test(id)) return { status: 404, body: { error: MESSAGES.notFound, code: "not_found" } };
  var c = await connectedOr(deps, userId);
  if (c.error) return c.error;
  var r = await deps.supabase.from("facebook_posts").select(POST_COLUMNS).eq("id", id).eq("user_id", userId).maybeSingle();
  if (r.error) throw r.error;
  var row = r.data && r.data.user_id === userId ? r.data : null;
  if (!row) return { status: 404, body: { error: MESSAGES.notFound, code: "not_found" } };
  if (row.removed_at) return { status: 409, body: { error: MESSAGES.alreadyRemoved, code: "already_removed" } };
  if (row.status !== "published" || !row.post_id) return { status: 409, body: { error: MESSAGES.notPublished, code: "not_published" } };
  var pend = await deps.supabase.from("agent_proposals").select("id, payload").eq("user_id", userId).eq("action_type", DELETE_ACTION).in("status", ["pending", "executing"]);
  if (pend.error) throw pend.error;
  if ((pend.data || []).some(function (pr) { return pr.payload && pr.payload.facebook_post_id === row.id; })) {
    return { status: 409, body: { error: MESSAGES.removalPending, code: "pending" } };
  }
  var payload = { facebook_post_id: row.id, post_id: row.post_id, page_id: c.conn.page_id };
  if (!deletePayloadShape(payload)) return { status: 400, body: { error: MESSAGES.shape, code: "invalid" } };
  var ins = await deps.supabase.from("agent_proposals").insert({
    user_id: userId, agent_type: "social", action_type: DELETE_ACTION,
    title: ("Remove a post from the Facebook Page " + c.conn.page_name).slice(0, 200), target: "facebook", payload: payload,
    cost_amount: 0, cost_currency: "USD", reversible: false, status: "pending", created_at: nowIso(deps)
  }).select("*").single();
  if (ins.error) throw ins.error;
  return { status: 201, body: { proposal: ins.data, note: "Filed for approval. Nothing was removed yet. Approving it on the proposals page removes this post from " + c.conn.page_name + "." } };
}

/* ── the daily cleanup of unfinished Page choices (04:45 chain) ─────────── */
async function claimChoosingDay(supabase, nowMs) {
  var today = new Date(nowMs).toISOString().slice(0, 10);
  var started = new Date(nowMs).toISOString();
  var inserted = await supabase.from("job_runs")
    .insert({ job_name: CHOOSING_JOB_NAME, last_run_on: today, started_at: started, finished_at: null, last_error: null }).select("job_name");
  if (!inserted.error) return true;
  if (inserted.error.code !== "23505") {
    console.error("[FacebookChoosingPurge] Claim insert failed: " + (inserted.error.code || "error"));
    return false;
  }
  var updated = await supabase.from("job_runs").update({ last_run_on: today, started_at: started, finished_at: null, last_error: null })
    .eq("job_name", CHOOSING_JOB_NAME).or("last_run_on.is.null,last_run_on.neq." + today).select("job_name");
  if (updated.error) {
    console.error("[FacebookChoosingPurge] Claim update failed: " + (updated.error.code || "error"));
    return false;
  }
  return (updated.data || []).length > 0;
}

/* Once a day: every choosing row older than CHOOSING_TTL_MS is deleted, with
   the user token it holds. Never rejects. */
async function choosingPurgeTick(deps, nowMs) {
  var supabase = deps.supabase;
  var startedMs = typeof nowMs === "number" ? nowMs : deps.now();
  async function finish(errorMessage) {
    var patch = { finished_at: new Date(deps.now()).toISOString() };
    if (errorMessage) patch.last_error = String(errorMessage).slice(0, 2000);
    var r = await supabase.from("job_runs").update(patch).eq("job_name", CHOOSING_JOB_NAME);
    if (r.error) console.error("[FacebookChoosingPurge] Failed to record run completion: " + (r.error.code || "error"));
  }
  try {
    if (!(await claimChoosingDay(supabase, startedMs))) return { claimed: false };
    var cutoff = new Date(startedMs - FA.CHOOSING_TTL_MS).toISOString();
    var d = await supabase.from("member_facebook_pages").delete().eq("status", "choosing").lt("created_at", cutoff).select("id");
    if (d.error) throw new Error("member_facebook_pages could not be cleaned");
    var deleted = (d.data || []).length;
    await finish(null);
    console.log("[FacebookChoosingPurge] Pass finished: " + deleted + " unfinished Facebook Page choice(s) deleted.");
    return { claimed: true, deleted: deleted, error: null };
  } catch (err) {
    var message = (err && err.message) || "error";
    console.error("[FacebookChoosingPurge] Pass error: " + message);
    try { await finish(message); } catch (finishErr) { /* reported above */ }
    return { claimed: true, error: message };
  }
}

module.exports = {
  API_BASE: API_BASE,
  VIDEO_BASE: VIDEO_BASE,
  ACTION: ACTION,
  DELETE_ACTION: DELETE_ACTION,
  POSTS_PER_DAY: POSTS_PER_DAY,
  ITEMS_MAX: ITEMS_MAX,
  MESSAGE_MAX: MESSAGE_MAX,
  DRAFT_MAX: DRAFT_MAX,
  PHOTO_MIMES: PHOTO_MIMES,
  VIDEO_MIMES: VIDEO_MIMES,
  SIGNED_URL_SECONDS: SIGNED_URL_SECONDS,
  STALE_CREATING_MS: STALE_CREATING_MS,
  CHOOSING_JOB_NAME: CHOOSING_JOB_NAME,
  CREATE_CONTENT: CREATE_CONTENT,
  STATUS_COLUMNS: STATUS_COLUMNS,
  POST_COLUMNS: POST_COLUMNS,
  PERMALINK_RE: PERMALINK_RE,
  MESSAGES: MESSAGES,
  FacebookApiError: FacebookApiError,
  tokenRefused: tokenRefused,
  permalinkFrom: permalinkFrom,
  checkMessage: checkMessage,
  readConnection: readConnection,
  statusOf: statusOf,
  markNeedsReconnect: markNeedsReconnect,
  readPermissions: readPermissions,
  readPages: readPages,
  pageChoices: pageChoices,
  connectAfterSeal: connectAfterSeal,
  listChoices: listChoices,
  choosePage: choosePage,
  payloadShape: payloadShape,
  deletePayloadShape: deletePayloadShape,
  executePublish: executePublish,
  executeDelete: executeDelete,
  postStatus: postStatus,
  postView: postView,
  listPosts: listPosts,
  proposePost: proposePost,
  proposeDelete: proposeDelete,
  choosingPurgeTick: choosingPurgeTick
};
