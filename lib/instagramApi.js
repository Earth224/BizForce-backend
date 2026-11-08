"use strict";

/* ══════════════════════════════════════════════════════════════════════════
   INSTAGRAM, ON THE MEMBER'S OWN PROFESSIONAL ACCOUNT (migration 179).

   THE CONNECTION, member_instagram_connections, one per member, holding the
   long-lived token sealed (lib/apiKeyCrypto.js). accessToken uses it as it
   is until it expires within lib/instagramAuth.js REFRESH_WINDOW_MS (10
   days) and is at least 24 hours old (refreshDue); then it refreshes and
   writes the new token in ONE update guarded by a compare-and-set on
   token_version. The loser of a race writes nothing more, reads the row
   again and uses the winner's token. One refresh per member at a time in
   this process. A token past its expiry, or refused (401, or a token or
   permission error code, tokenRefused), marks the connection needs_reconnect
   and raises ONE in-app notice.
   refreshTick, in the 04:45 chain with its own job_runs row, refreshes every
   connection that is due, so a member who posts rarely is not cut off.

   FILING (proposePost), never running: 1 JPEG photo (kind image), 2 to 10
   JPEG photos (kind carousel), or one MP4 or MOV from "Your videos" (kind
   reel). A photo must be JPEG by its own bytes, read back now (MPO and JPS
   are refused too); its library alt text goes with it, frozen. The caption
   is at most SOCIAL_PLATFORMS.instagram.max characters, with at most
   hashtag_max hashtags and MENTION_MAX @mentions, through the claims screen.
   At most POSTS_PER_DAY posts in 24 hours (instagram_posts not failed).

   THE POST, executePublish (the publish_instagram_post executor), on
   approval only:
     1. the payload, the claims, the caption limits again; the connection
        (the same ig_user_id, connected);
     2. an instagram_posts row for this proposal: found, the run CONTINUES
        from it; not found, the files and the cap are checked again and the
        row is inserted, status creating, BEFORE any container;
     3. with no parent container stored: every photo's bytes are read and
        checked (sha256, size, JPEG) RIGHT BEFORE its container; a Reel's file
        is streamed and hashed, then a signed link valid SIGNED_URL_SECONDS (2
        hours) is made and used only in that one request body. The parent's
        id is stored, status processing, the moment it exists;
     4. the containers are polled every POLL_INTERVAL_MS for at most
        POLL_MAX_MS, children first, then the parent; not finished in time,
        the result is { processing: true } and the row stays processing;
     5. publishOnce: the row is CLAIMED with a compare-and-set on updated_at,
        the parent's status is read again (PUBLISHED: never published again),
        Instagram's publishing limit is read (refused at or over its total),
        then ONE media_publish, then the permalink.
   GET /api/instagram/posts/:id/status (postStatus) finishes a slow one the
   same way. PUBLISHED with no media id recorded: the newest of the account's
   last 10 media with the same caption, at or after the row's created_at, is
   recorded; none, the row is failed with MESSAGES.publishedUnknown.
   Instagram has no API to delete a post: the member deletes it in Instagram.

   Nothing here logs. No token, signed link or code is ever put into an
   error, a stored row, a result a member sees, or a log line.
   ══════════════════════════════════════════════════════════════════════════ */

const IA = require("./instagramAuth");
const MV = require("./memberVideos");
const MM = require("./memberMedia");

const API_BASE = "https://graph.instagram.com/v26.0";
const ME_URL = API_BASE + "/me?fields=user_id,username,account_type";
const ACTION = "publish_instagram_post";
const ACCOUNT_TYPES = Object.freeze(["BUSINESS", "MEDIA_CREATOR"]);
const POSTS_PER_DAY = 10;
const ITEMS_MAX = 10;
const MENTION_MAX = 20;
const POLL_INTERVAL_MS = 5 * 1000;
const POLL_MAX_MS = 60 * 1000;
/* The Reel's signed link: two hours, used only inside one request body. */
const SIGNED_URL_SECONDS = 7200;
/* A claimed row is left alone by anyone else for this long. */
const CLAIM_LEASE_MS = 2 * 60 * 1000;
/* A row still "creating" this long after it was made never reached Instagram's publish step. */
const STALE_CREATING_MS = 60 * 60 * 1000;
const API_TIMEOUT_MS = 15 * 1000;
const ID_RE = /^[0-9]{1,30}$/;
const USERNAME_RE = /^[A-Za-z0-9._]{1,100}$/;
const SHA_RE = /^[0-9a-f]{64}$/;
const ALT_MAX = 1000;
const REEL_MIMES = Object.freeze(["video/mp4", "video/quicktime"]);
const PERMALINK_RE = /^https:\/\/www\.instagram\.com\/[A-Za-z0-9_\/.?=&-]{1,280}$/;
const STATUS_COLUMNS = "id, user_id, ig_user_id, username, account_type, status, created_at, last_ok_at, last_error_code";
const SECRET_COLUMNS = "id, user_id, ig_user_id, username, account_type, access_ciphertext, access_iv, access_auth_tag, access_expires_at, token_version, granted_scopes, status, created_at, updated_at";
const POST_COLUMNS = "id, user_id, proposal_id, kind, container_id, status, media_id, permalink, video_id, error, created_at, updated_at, published_at";
const MEDIA_COLUMNS = "id, user_id, path, kind, mime, bytes, sha256, label, alt_text";
const REFRESH_JOB_NAME = "instagram_token_refresh";
const REFRESH_PAGE = 1000;

const MESSAGES = Object.freeze({
  notConnected: "Connect your Instagram account first.",
  needsReconnect: "Instagram stopped accepting BizForce's access to your account, so nothing is being posted. Connect again.",
  jpegOnly: "Instagram accepts JPEG photos only. Choose a JPEG photo.",
  reelType: "Instagram Reels need an MP4 or MOV video.",
  kind: "Choose Photos or Reel.",
  items: "An Instagram post has 1 to 10 photos from your Media Library, each chosen once.",
  notInLibrary: "That photo isn't in your Media Library.",
  caption: "A caption is at most 2200 characters, with at most 30 hashtags and 20 @mentions.",
  dailyCap: "You can post to Instagram 10 times in 24 hours. Nothing was sent. Try again later.",
  limitReached: "Instagram's own publishing limit for your account is reached for now, so nothing was published. File the post again later.",
  fingerprint: "A file in this post no longer matches the one you filed, so nothing was sent.",
  unread: "A file in this post could not be read just now, so nothing was sent.",
  accountChanged: "The Instagram account connected now isn't the one this was filed for. Nothing was sent; file it again.",
  pending: "This video already has an Instagram post waiting for your approval.",
  fileGone: "That video's file is no longer here. Nothing was sent.",
  unreachable: "Instagram couldn't be reached just now. Nothing changed. Try again later.",
  noDelete: "To remove an Instagram post, delete it in the Instagram app.",
  publishedUnknown: "Instagram shows this post as published. Open Instagram to see it.",
  processing: "Instagram is still preparing this post. Check its status on the Social page in a minute.",
  busy: "This post is being checked right now. Try again in a minute or two.",
  notFound: "That Instagram post isn't here.",
  stale: "BizForce didn't finish sending this post to Instagram, so nothing was published. File it again.",
  failedRow: "This Instagram post already failed. File it again to try once more.",
  shape: "The filed post is not complete. Nothing was sent."
});

class InstagramApiError extends Error {
  constructor(kind, code, said) { super("instagram " + kind + " (" + code + ")"); this.name = "InstagramApiError"; this.kind = kind; this.code = code; this.said = said || null; }
}

var refreshesInFlight = new Map();

function nowIso(deps) { return new Date(deps.now()).toISOString(); }
function bearer(token) { return { Authorization: "Bearer " + token }; }
function sealed(crypt, plain) { var s = crypt.encrypt(plain); return { ciphertext: s.ciphertext, iv: s.iv, authTag: s.authTag }; }
function codePoints(s) { return Array.from(String(s)).length; }
function clean(text, max) { return String(text || "").replace(/[\u0000-\u001f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, max); }
/* What Instagram said, safe to show: plain text, no markup, at most 300 characters. */
function said(json) {
  var e = json && json.error && typeof json.error === "object" ? json.error : null;
  var m = e && typeof e.message === "string" ? clean(e.message, 300) : "";
  return m || null;
}
function ok(answer) { return !!(answer && typeof answer.status === "number" && answer.status >= 200 && answer.status < 300 && answer.json && typeof answer.json === "object"); }
/* A token Instagram refuses: 401, or the token and permission error codes
   (190 invalid token, 102 session, 10 and 200 to 299 permission). Not the error
   type: nearly every Graph error is typed OAuthException, including a refused
   photo or a rate limit, and those must not cut the member off. */
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

/* ── the caption ────────────────────────────────────────────────────────── */
function hashtagCount(caption) { return (String(caption).match(/#[\p{L}\p{N}_]+/gu) || []).length; }
function mentionCount(caption) { return (String(caption).match(/(?<![A-Za-z0-9._])@[A-Za-z0-9._]+/g) || []).length; }
/* { ok: true, caption } or { ok: false, error }. limits is SOCIAL_PLATFORMS.instagram (max, hashtag_max). */
function checkCaption(value, limits) {
  var caption = value === undefined || value === null ? "" : value;
  if (typeof caption !== "string") return { ok: false, error: MESSAGES.caption };
  caption = caption.trim();
  var max = limits && limits.max;
  var tags = limits && limits.hashtag_max;
  if (!(typeof max === "number" && codePoints(caption) <= max)) return { ok: false, error: MESSAGES.caption };
  if (!(typeof tags === "number" && hashtagCount(caption) <= tags)) return { ok: false, error: MESSAGES.caption };
  if (mentionCount(caption) > MENTION_MAX) return { ok: false, error: MESSAGES.caption };
  return { ok: true, caption: caption };
}

/* ── JPEG, by the bytes ─────────────────────────────────────────────────── */
/* A plain JPEG: FF D8 FF, and no MPO (APP2 "MPF\0") or JPS (APP3 "_JPSJPS_")
   segment before the image data. Pure byte reads; never throws. */
function isInstagramJpeg(buf) {
  if (!buf || buf.length < 4 || buf[0] !== 0xff || buf[1] !== 0xd8 || buf[2] !== 0xff) return false;
  var i = 2;
  for (var n = 0; n < 200 && i + 4 <= buf.length; n++) {
    if (buf[i] !== 0xff) return true;
    var marker = buf[i + 1];
    if (marker === 0xff) { i += 1; continue; }
    if (marker === 0xda || marker === 0xd9) return true;
    var len = buf.readUInt16BE(i + 2);
    if (len < 2) return false;
    var body = buf.toString("latin1", i + 4, Math.min(buf.length, i + 4 + 8));
    if (marker === 0xe2 && body.indexOf("MPF\u0000") === 0) return false;
    if (marker === 0xe3 && body.indexOf("_JPSJPS_") === 0) return false;
    i += 2 + len;
  }
  return true;
}

/* One photo's bytes, checked against what was filed: the row the poster's
   JPEG image with the frozen sha256 and size; the bytes exactly that long,
   hashing to it, and a plain JPEG. Throws InstagramApiError("fingerprint" |
   "unread" | "jpeg"). */
async function readPhoto(deps, ownerId, row, frozen) {
  if (!row || row.mime !== "image/jpeg") throw new InstagramApiError("jpeg", "not_jpeg");
  var buf;
  try {
    buf = await MM.readMediaForPost(row, { id: frozen.id, sha256: frozen.sha256, mime: "image/jpeg", bytes: frozen.bytes },
      { storage: deps.storage, userId: ownerId, maxBytes: MM.MAX_FILE_BYTES });
  } catch (err) {
    throw new InstagramApiError(err && err.reason === "unread" ? "unread" : "fingerprint", (err && err.reason) || "changed");
  }
  if (!isInstagramJpeg(buf)) throw new InstagramApiError("jpeg", "not_jpeg");
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
  var r = await supabase.from("member_instagram_connections").select(SECRET_COLUMNS).eq("user_id", userId).maybeSingle();
  if (r.error) throw r.error;
  return r.data && r.data.user_id === userId ? r.data : null;
}

function statusOf(row, available) {
  var r = row || null;
  return {
    instagram_available: available === true,
    connected: !!r && r.status === "connected",
    status: r ? r.status : "not_connected",
    username: r ? r.username : null,
    account_type: r ? r.account_type : null,
    since: r ? r.created_at : null,
    reconnect_message: r && r.status === "needs_reconnect" ? MESSAGES.needsReconnect : null
  };
}

/* needs_reconnect and ONE notice, only when it was connected. Never throws. */
async function markNeedsReconnect(deps, row, code) {
  try {
    var stamp = nowIso(deps);
    var marked = await deps.supabase.from("member_instagram_connections")
      .update({ status: "needs_reconnect", last_error_at: stamp, last_error_code: String(code || "refused").slice(0, 60), updated_at: stamp })
      .eq("id", row.id).eq("user_id", row.user_id).eq("status", "connected").select("id");
    if (marked.error || !(marked.data || []).length) return false;
    var notice = await deps.supabase.from("notifications").insert({
      user_id: row.user_id,
      type: "instagram_reconnect",
      title: "Reconnect your Instagram account",
      message: "Instagram stopped accepting BizForce's access to @" + row.username + ", so nothing is being posted and nothing will be tried again. Connect Instagram again on the Social Agent page.",
      read: false
    });
    if (notice.error) console.warn("[instagram] the reconnect notice could not be saved: " + (notice.error.code || "error"));
    return true;
  } catch (err) {
    return false;
  }
}

function readAccess(deps, row) {
  try {
    return deps.crypt.decrypt({ ciphertext: row.access_ciphertext, iv: row.access_iv, authTag: row.access_auth_tag });
  } catch (err) {
    throw new InstagramApiError("auth", "secret_unreadable");
  }
}

async function refreshRow(deps, row) {
  // The version this row was read at, taken before Instagram is asked: the compare-and-set below is against it.
  var version = Number.isInteger(row.token_version) ? row.token_version : 0;
  var current = readAccess(deps, row);
  var grant;
  try {
    grant = await IA.refresh(current);
  } catch (err) {
    if (err && err.kind === "invalid_grant") {
      await markNeedsReconnect(deps, row, "refresh_refused");
      throw new InstagramApiError("auth", "refresh_refused");
    }
    throw new InstagramApiError("unreachable", "token_refresh");
  } finally {
    current = null;
  }
  var access = sealed(deps.crypt, grant.accessToken);
  var stamp = nowIso(deps);
  var update = {
    access_ciphertext: access.ciphertext, access_iv: access.iv, access_auth_tag: access.authTag,
    access_expires_at: IA.expiresAt(deps.now(), grant.expiresIn),
    token_version: version + 1,
    last_ok_at: stamp,
    updated_at: stamp
  };
  var swapped = await deps.supabase.from("member_instagram_connections").update(update)
    .eq("id", row.id).eq("user_id", row.user_id).eq("token_version", version).select("id");
  if (swapped.error) throw new InstagramApiError("unreachable", "token_store");
  if ((swapped.data || []).length === 1) {
    return { token: grant.accessToken, row: Object.assign({}, row, update), refreshedNow: true };
  }
  // Lost the race: nothing more is written. The winner's token is the one to use.
  grant = null;
  var winner = await readConnection(deps.supabase, row.user_id);
  if (!winner || winner.status !== "connected") throw new InstagramApiError("auth", "refresh_lost");
  return { token: readAccess(deps, winner), row: winner, refreshedNow: true };
}

/* One refresh per member at a time in this process. */
function refreshOnce(deps, row) {
  var key = row.user_id;
  var running = refreshesInFlight.get(key);
  if (running) return running;
  var started = refreshRow(deps, row);
  refreshesInFlight.set(key, started);
  var clear = function () { if (refreshesInFlight.get(key) === started) refreshesInFlight.delete(key); };
  started.then(clear, clear);
  return started;
}

/* { token, row, refreshedNow }. Expired: needs_reconnect. Due (lib/instagramAuth.js
   refreshDue): refreshed; a refresh that cannot reach Instagram while the
   token is still valid uses the token as it is. */
async function accessToken(deps, row) {
  if (!row || row.status !== "connected") throw new InstagramApiError("auth", "not_connected");
  var expires = Date.parse(row.access_expires_at || "");
  if (!isFinite(expires) || expires <= deps.now()) {
    await markNeedsReconnect(deps, row, "expired");
    throw new InstagramApiError("auth", "expired");
  }
  if (IA.refreshDue(row, deps.now())) {
    try {
      return await refreshOnce(deps, row);
    } catch (err) {
      if (err && err.kind === "auth") throw err;
    }
  }
  return { token: readAccess(deps, row), row: row, refreshedNow: false };
}

async function api(deps, url, options) {
  try {
    return await deps.jsonRequest(url, Object.assign({ timeoutMs: API_TIMEOUT_MS }, options));
  } catch (err) {
    throw new InstagramApiError("unreachable", (err && typeof err.code === "string" && /^[a-z_]{1,40}$/.test(err.code)) ? err.code : "request");
  }
}

/* A call with the access token. A refused token marks needs_reconnect. */
async function withToken(deps, row, send) {
  var got = await accessToken(deps, row);
  var answer = await send(got.token);
  if (tokenRefused(answer)) {
    await markNeedsReconnect(deps, got.row, "unauthorized");
    throw new InstagramApiError("auth", "unauthorized");
  }
  return { answer: answer, row: got.row };
}

/* /me with a token in hand (finish uses it before any row exists):
   { ig_user_id, username, account_type }, or null for an unreadable answer. */
async function readMe(deps, token) {
  var answer = await api(deps, ME_URL, { method: "GET", headers: bearer(token) });
  if (tokenRefused(answer)) throw new InstagramApiError("auth", "unauthorized");
  if (!ok(answer)) throw new InstagramApiError("unreachable", "me_status_" + (answer ? answer.status : "none"));
  var j = answer.json;
  var id = idOf(j.user_id);
  var username = typeof j.username === "string" && USERNAME_RE.test(j.username) ? j.username : null;
  var type = typeof j.account_type === "string" ? j.account_type : null;
  if (!id || !username || !type) return null;
  return { ig_user_id: id, username: username, account_type: type };
}
function professional(me) { return !!me && ACCOUNT_TYPES.indexOf(me.account_type) !== -1; }

/* ── the Graph calls ────────────────────────────────────────────────────── */
function mediaUrl(igUserId) { return API_BASE + "/" + igUserId + "/media"; }

/* One container: its id. Throws InstagramApiError ("refused" with Instagram's words). */
async function createContainer(deps, conn, form) {
  var out = await withToken(deps, conn, function (token) {
    return api(deps, mediaUrl(conn.ig_user_id), { method: "POST", headers: bearer(token), form: form });
  });
  if (!ok(out.answer)) throw new InstagramApiError("refused", "container_" + out.answer.status, said(out.answer.json));
  var id = idOf(out.answer.json.id);
  if (!id) throw new InstagramApiError("refused", "container_shape");
  return id;
}

/* A container's status: { code, text }. code is IN_PROGRESS, FINISHED,
   PUBLISHED, EXPIRED, ERROR, or null for a word not documented. */
async function containerStatus(deps, conn, containerId) {
  var out = await withToken(deps, conn, function (token) {
    return api(deps, API_BASE + "/" + containerId + "?fields=status_code,status", { method: "GET", headers: bearer(token) });
  });
  if (!ok(out.answer)) throw new InstagramApiError("unreachable", "status_" + out.answer.status);
  var c = out.answer.json.status_code;
  var known = ["IN_PROGRESS", "FINISHED", "PUBLISHED", "EXPIRED", "ERROR"];
  return { code: known.indexOf(c) !== -1 ? c : null, text: typeof out.answer.json.status === "string" ? clean(out.answer.json.status, 300) : null };
}

/* { usage, total }; throws when Instagram's answer can't be read. */
async function publishingLimit(deps, conn) {
  var out = await withToken(deps, conn, function (token) {
    return api(deps, API_BASE + "/" + conn.ig_user_id + "/content_publishing_limit?fields=quota_usage,config", { method: "GET", headers: bearer(token) });
  });
  if (!ok(out.answer)) throw new InstagramApiError("unreachable", "limit_" + out.answer.status);
  var j = out.answer.json;
  var d = Array.isArray(j.data) && j.data[0] && typeof j.data[0] === "object" ? j.data[0] : j;
  var usage = d.quota_usage;
  var total = d.config && d.config.quota_total;
  if (!Number.isInteger(usage) || !Number.isInteger(total) || usage < 0 || total < 0) throw new InstagramApiError("unreachable", "limit_shape");
  return { usage: usage, total: total };
}

/* ONE media_publish. { id } when Instagram answered with one; { refused, said }
   when it refused; throws InstagramApiError("unreachable") when the answer
   never came (the post may or may not be up: the status says). */
async function mediaPublish(deps, conn, creationId) {
  var out = await withToken(deps, conn, function (token) {
    return api(deps, API_BASE + "/" + conn.ig_user_id + "/media_publish", { method: "POST", headers: bearer(token), form: { creation_id: creationId } });
  });
  if (ok(out.answer)) {
    var id = idOf(out.answer.json.id);
    return id ? { id: id } : { unclear: true };
  }
  if (out.answer.status >= 400 && out.answer.status < 500) return { refused: true, said: said(out.answer.json) };
  return { unclear: true };
}

/* The post's address, or null. Best effort: never throws. */
async function permalinkOf(deps, conn, mediaId) {
  try {
    var out = await withToken(deps, conn, function (token) {
      return api(deps, API_BASE + "/" + mediaId + "?fields=permalink", { method: "GET", headers: bearer(token) });
    });
    var p = ok(out.answer) ? out.answer.json.permalink : null;
    return typeof p === "string" && p.length <= 300 && PERMALINK_RE.test(p) ? p : null;
  } catch (err) {
    return null;
  }
}

/* The newest of the account's last 10 media with this caption, at or after
   `since`: its id, or null. Throws when the list can't be read. */
async function findPublished(deps, conn, caption, since) {
  var out = await withToken(deps, conn, function (token) {
    return api(deps, mediaUrl(conn.ig_user_id) + "?fields=id,timestamp,caption&limit=10", { method: "GET", headers: bearer(token) });
  });
  if (!ok(out.answer)) throw new InstagramApiError("unreachable", "media_list_" + out.answer.status);
  var list = Array.isArray(out.answer.json.data) ? out.answer.json.data : [];
  var sinceMs = Date.parse(since || "");
  var want = String(caption || "").trim();
  var best = null, bestMs = -Infinity;
  list.forEach(function (m) {
    if (!m || typeof m !== "object") return;
    var id = idOf(m.id);
    var at = Date.parse(String(m.timestamp || "").replace(/([+-]\d\d)(\d\d)$/, "$1:$2"));
    var text = typeof m.caption === "string" ? m.caption.trim() : "";
    if (!id || !isFinite(at) || !isFinite(sinceMs) || at < sinceMs || text !== want) return;
    if (at > bestMs) { best = id; bestMs = at; }
  });
  return best;
}

/* ── the post row ───────────────────────────────────────────────────────── */
async function readPostByProposal(supabase, proposalId) {
  var r = await supabase.from("instagram_posts").select(POST_COLUMNS).eq("proposal_id", proposalId).maybeSingle();
  if (r.error) throw r.error;
  return r.data || null;
}

async function postsToday(deps, userId) {
  var since = new Date(deps.now() - 24 * 60 * 60 * 1000).toISOString();
  var counted = await deps.supabase.from("instagram_posts").select("id", { count: "exact", head: true })
    .eq("user_id", userId).neq("status", "failed").gte("created_at", since);
  if (counted.error) throw new InstagramApiError("unreachable", "count");
  return counted.count || 0;
}

async function markFailed(deps, row, text) {
  var stamp = nowIso(deps);
  var u = await deps.supabase.from("instagram_posts").update({ status: "failed", error: String(text || MESSAGES.unreachable).slice(0, 300), updated_at: stamp })
    .eq("id", row.id).in("status", ["creating", "processing"]).select("id");
  return !u.error && (u.data || []).length === 1;
}

async function recordPublished(deps, conn, row, mediaId) {
  var permalink = await permalinkOf(deps, conn, mediaId);
  var stamp = nowIso(deps);
  var u = await deps.supabase.from("instagram_posts").update({ status: "published", media_id: mediaId, permalink: permalink, published_at: stamp, error: null, updated_at: stamp })
    .eq("id", row.id).in("status", ["creating", "processing"]).select("id");
  if (u.error || (u.data || []).length !== 1) {
    throw new Error("publish_instagram_post: the post WAS published to Instagram, but it could not be recorded. Don't file it again.");
  }
  return { published: true, status: "published", media_id: mediaId, permalink: permalink, published_at: stamp, note: MESSAGES.noDelete };
}

/* The row claimed with a compare-and-set on updated_at: the claimed row, or
   null when someone else holds it. lease: also refuse a row touched less
   than CLAIM_LEASE_MS ago (the executor claims the row it just wrote without one). */
async function claim(deps, row, lease) {
  var before = Date.parse(row.updated_at || "");
  if (lease && isFinite(before) && deps.now() - before < CLAIM_LEASE_MS) return null;
  var stampMs = deps.now();
  if (isFinite(before) && stampMs <= before) stampMs = before + 1;
  var stamp = new Date(stampMs).toISOString();
  var u = await deps.supabase.from("instagram_posts").update({ updated_at: stamp })
    .eq("id", row.id).eq("updated_at", row.updated_at).eq("status", "processing").select("id");
  if (u.error || (u.data || []).length !== 1) return null;
  return Object.assign({}, row, { updated_at: stamp });
}

/* PUBLISHED, with no media id recorded: look it up, or fail the row with the plain words. */
async function recoverPublished(deps, conn, row, caption) {
  var found;
  try {
    found = await findPublished(deps, conn, caption, row.created_at);
  } catch (err) {
    return { processing: true, status: "processing", note: MESSAGES.processing };
  }
  if (found) return recordPublished(deps, conn, row, found);
  await markFailed(deps, row, MESSAGES.publishedUnknown);
  return { published_unknown: true, status: "failed", error: MESSAGES.publishedUnknown };
}

/* Publish exactly once: claim, read the parent's status again, the limit,
   then ONE media_publish. Returns a result; throws only for an unrecorded publish. */
async function publishOnce(deps, conn, row, caption, lease) {
  var claimed = await claim(deps, row, lease);
  if (!claimed) return { busy: true, status: "processing", note: MESSAGES.busy };
  var st;
  try {
    st = await containerStatus(deps, conn, claimed.container_id);
  } catch (err) {
    if (err && err.kind === "auth") return { status: "processing", error: MESSAGES.needsReconnect, needs_reconnect: true };
    return { processing: true, status: "processing", note: MESSAGES.processing };
  }
  if (st.code === "PUBLISHED") return recoverPublished(deps, conn, claimed, caption);
  if (st.code === "EXPIRED" || st.code === "ERROR") {
    var why = st.text ? "Instagram couldn't publish it: " + st.text : "Instagram couldn't publish it (" + st.code.toLowerCase() + ").";
    await markFailed(deps, claimed, why);
    return { failed: true, status: "failed", error: why.slice(0, 300) };
  }
  if (st.code !== "FINISHED") return { processing: true, status: "processing", note: MESSAGES.processing };
  var limit;
  try {
    limit = await publishingLimit(deps, conn);
  } catch (err) {
    return { processing: true, status: "processing", note: MESSAGES.processing };
  }
  if (limit.usage >= limit.total) {
    await markFailed(deps, claimed, MESSAGES.limitReached);
    return { failed: true, status: "failed", error: MESSAGES.limitReached };
  }
  var sent;
  try {
    sent = await mediaPublish(deps, conn, claimed.container_id);
  } catch (err) {
    // No answer: whether it went up is for the next status check to see.
    return { processing: true, status: "processing", note: MESSAGES.processing };
  }
  if (sent.id) return recordPublished(deps, conn, claimed, sent.id);
  if (sent.refused) {
    var refusedWhy = sent.said ? "Instagram refused the post: " + sent.said : "Instagram refused the post.";
    await markFailed(deps, claimed, refusedWhy);
    return { failed: true, status: "failed", error: refusedWhy.slice(0, 300) };
  }
  return { processing: true, status: "processing", note: MESSAGES.processing };
}

/* Poll each container in order (children first, then the parent) every
   POLL_INTERVAL_MS, for at most POLL_MAX_MS from startedMs.
   { state: "finished" | "published" | "failed" | "timeout", text }. */
async function waitForContainers(deps, conn, ids, startedMs) {
  for (var i = 0; i < ids.length; i++) {
    for (;;) {
      var st;
      try {
        st = await containerStatus(deps, conn, ids[i]);
      } catch (err) {
        if (err && err.kind === "auth") throw err;
        return { state: "timeout" };
      }
      if (st.code === "FINISHED") break;
      if (st.code === "PUBLISHED" && i === ids.length - 1) return { state: "published" };
      if (st.code === "EXPIRED" || st.code === "ERROR" || st.code === "PUBLISHED") return { state: "failed", code: st.code, text: st.text };
      if (deps.now() + POLL_INTERVAL_MS - startedMs > POLL_MAX_MS) return { state: "timeout" };
      await deps.sleep(POLL_INTERVAL_MS);
    }
  }
  return { state: "finished" };
}

/* ── the payload ────────────────────────────────────────────────────────── */
function itemShape(it) {
  return !!it && typeof it === "object" && MV.UUID_RE.test(String(it.id || "")) && SHA_RE.test(String(it.sha256 || "")) &&
    Number.isInteger(it.bytes) && it.bytes > 0 && typeof it.alt === "string" && it.alt.length <= ALT_MAX;
}
function payloadShape(p) {
  if (!p || typeof p !== "object" || typeof p.caption !== "string" || typeof p.ig_user_id !== "string" || !ID_RE.test(p.ig_user_id)) return false;
  if (p.kind === "image" || p.kind === "carousel") {
    if (!Array.isArray(p.items) || p.video) return false;
    var n = p.items.length;
    if (p.kind === "image" ? n !== 1 : (n < 2 || n > ITEMS_MAX)) return false;
    var seen = {};
    return p.items.every(function (it) { if (!itemShape(it) || seen[it.id]) return false; seen[it.id] = true; return true; });
  }
  if (p.kind === "reel") {
    var v = p.video;
    return !p.items && !!v && typeof v === "object" && MV.UUID_RE.test(String(v.id || "")) && SHA_RE.test(String(v.sha256 || "")) &&
      Number.isInteger(v.bytes) && v.bytes > 0 && REEL_MIMES.indexOf(v.mime) !== -1;
  }
  return false;
}

async function readMediaRows(supabase, userId, ids) {
  var r = await supabase.from("member_media").select(MEDIA_COLUMNS).eq("user_id", userId).in("id", ids);
  if (r.error) throw r.error;
  var byId = {};
  (r.data || []).forEach(function (row) { if (row.user_id === userId) byId[row.id] = row; });
  return byId;
}

/* ── the executor ───────────────────────────────────────────────────────── */

/* The publish_instagram_post executor. One argument, the claimed proposal. */
async function executePublish(deps, proposal) {
  var fail = function (why) { return new Error("publish_instagram_post: " + why); };
  var p = proposal && proposal.payload && typeof proposal.payload === "object" ? proposal.payload : {};
  var ownerId = proposal && proposal.user_id;
  if (!payloadShape(p) || !proposal.id) throw fail(MESSAGES.shape);
  var refused = p.caption ? deps.claims(p.caption) : null;
  if (refused) throw fail(refused.error + " Nothing was sent.");
  var cap = checkCaption(p.caption, deps.limits);
  if (!cap.ok) throw fail(cap.error + " Nothing was sent.");
  var conn = await readConnection(deps.supabase, ownerId);
  if (!conn) throw fail(MESSAGES.notConnected + " Nothing was sent.");
  if (conn.status !== "connected") throw fail(MESSAGES.needsReconnect);
  if (conn.ig_user_id !== p.ig_user_id) throw fail(MESSAGES.accountChanged);
  try {
    conn = (await accessToken(deps, conn)).row;
  } catch (err) {
    throw fail(err && err.kind === "auth" ? MESSAGES.needsReconnect : MESSAGES.unreachable);
  }

  // The row first: a replay continues from it and never starts a second parent container.
  var row = await readPostByProposal(deps.supabase, proposal.id);
  if (row && row.user_id !== ownerId) throw fail(MESSAGES.shape);
  if (row && row.status === "published") return { already_published: true, status: "published", permalink: row.permalink, published_at: row.published_at, note: MESSAGES.noDelete };
  if (row && row.status === "failed") throw fail(row.error || MESSAGES.failedRow);

  var mediaRows = null, video = null;
  if (!row || !row.container_id) {
    // Nothing at Instagram is ours yet: the files are checked again.
    if (p.kind === "reel") {
      video = await MV.readVideo(deps.supabase, ownerId, p.video.id);
      if (!video || video.status !== "ready" || !video.path) throw fail(MESSAGES.fileGone);
      if (REEL_MIMES.indexOf(video.mime) === -1) throw fail(MESSAGES.reelType + " Nothing was sent.");
      if (video.sha256 !== p.video.sha256 || Number(video.bytes) !== p.video.bytes || video.mime !== p.video.mime) throw fail(MESSAGES.fingerprint);
    } else {
      mediaRows = await readMediaRows(deps.supabase, ownerId, p.items.map(function (it) { return it.id; }));
      for (var c = 0; c < p.items.length; c++) {
        var mr = mediaRows[p.items[c].id];
        if (!mr) throw fail(MESSAGES.fingerprint);
        if (mr.kind !== "image" || mr.mime !== "image/jpeg") throw fail(MESSAGES.jpegOnly + " Nothing was sent.");
        if (mr.sha256 !== p.items[c].sha256 || mr.bytes !== p.items[c].bytes) throw fail(MESSAGES.fingerprint);
      }
    }
  }

  if (!row) {
    var today;
    try { today = await postsToday(deps, ownerId); } catch (err) { throw fail(MESSAGES.unreachable); }
    if (today >= POSTS_PER_DAY) throw fail(MESSAGES.dailyCap);
    var stamp = nowIso(deps);
    var ins = await deps.supabase.from("instagram_posts").insert({
      user_id: ownerId, proposal_id: proposal.id, kind: p.kind, status: "creating",
      video_id: p.kind === "reel" ? p.video.id : null, created_at: stamp, updated_at: stamp
    }).select(POST_COLUMNS).single();
    if (ins.error && ins.error.code === "23505") {
      row = await readPostByProposal(deps.supabase, proposal.id);
      if (!row) throw fail(MESSAGES.unreachable);
      if (row.status === "published") return { already_published: true, status: "published", permalink: row.permalink, published_at: row.published_at, note: MESSAGES.noDelete };
      if (row.status === "failed") throw fail(row.error || MESSAGES.failedRow);
    } else if (ins.error || !ins.data) {
      throw fail("the post couldn't be recorded before sending, so nothing was sent.");
    } else {
      row = ins.data;
    }
  }

  var startedMs = deps.now();
  var pollIds = [];
  if (!row.container_id) {
    var parent;
    try {
      if (p.kind === "reel") {
        // Streamed and hashed first; only then the short signed link, used in this one body.
        if (!(await verifyVideo(deps, video, p.video))) throw new InstagramApiError("fingerprint", "video_sha");
        var signed = await deps.storage.from(MV.BUCKET).createSignedUrl(video.path, SIGNED_URL_SECONDS);
        var link = signed && !signed.error && signed.data && typeof signed.data.signedUrl === "string" ? signed.data.signedUrl : "";
        if (link.indexOf("https://") !== 0) throw new InstagramApiError("unread", "signed_url");
        try {
          parent = await createContainer(deps, conn, { media_type: "REELS", video_url: link, caption: cap.caption, share_to_feed: "true" });
        } finally {
          link = null; signed = null;
        }
      } else if (p.kind === "image") {
        await readPhoto(deps, ownerId, mediaRows[p.items[0].id], p.items[0]);
        parent = await createContainer(deps, conn, { image_url: MM.publicUrlFor(mediaRows[p.items[0].id].path, deps.base), caption: cap.caption, alt_text: p.items[0].alt });
      } else {
        for (var k = 0; k < p.items.length; k++) {
          var it = p.items[k];
          // Checked right before ITS container.
          await readPhoto(deps, ownerId, mediaRows[it.id], it);
          pollIds.push(await createContainer(deps, conn, { image_url: MM.publicUrlFor(mediaRows[it.id].path, deps.base), is_carousel_item: "true", alt_text: it.alt }));
        }
        parent = await createContainer(deps, conn, { media_type: "CAROUSEL", children: pollIds.join(","), caption: cap.caption });
      }
    } catch (err) {
      if (err && err.kind === "auth") throw fail(MESSAGES.needsReconnect);
      if (err && err.kind === "jpeg") { await markFailed(deps, row, MESSAGES.jpegOnly); throw fail(MESSAGES.jpegOnly + " Nothing was sent."); }
      if (err && err.kind === "fingerprint") { await markFailed(deps, row, MESSAGES.fingerprint); throw fail(MESSAGES.fingerprint); }
      if (err && err.kind === "unread") throw fail(MESSAGES.unread);
      if (err && err.kind === "refused") {
        var words = err.said ? "Instagram refused the post: " + err.said : "Instagram didn't accept the post.";
        await markFailed(deps, row, words + " Nothing was published.");
        throw fail(words + " Nothing was published.");
      }
      throw fail(MESSAGES.unreachable);
    }
    // Stored the moment it exists: a replay polls this one and never makes another.
    var storedAt = nowIso(deps);
    var stored = await deps.supabase.from("instagram_posts").update({ container_id: parent, status: "processing", updated_at: storedAt })
      .eq("id", row.id).is("container_id", null).eq("status", "creating").select(POST_COLUMNS);
    if (stored.error || (stored.data || []).length !== 1) throw fail("the post couldn't be recorded at Instagram's first step, so nothing was published. Check its status on the Social page.");
    row = stored.data[0];
  }
  pollIds.push(row.container_id);

  var waited;
  try {
    waited = await waitForContainers(deps, conn, pollIds, startedMs);
  } catch (err) {
    throw fail(MESSAGES.needsReconnect);
  }
  if (waited.state === "timeout") return { processing: true, status: "processing", post_id: row.id, note: MESSAGES.processing };
  if (waited.state === "failed") {
    var why = waited.text ? "Instagram couldn't publish it: " + waited.text : "Instagram couldn't publish it (" + String(waited.code || "error").toLowerCase() + ").";
    await markFailed(deps, row, why);
    throw fail(why.slice(0, 300));
  }
  var out = await publishOnce(deps, conn, row, cap.caption, false);
  if (out.failed || out.published_unknown) throw fail(out.error);
  return Object.assign({ post_id: row.id }, out);
}

/* GET /api/instagram/posts/:id/status. { status, body }. */
async function postStatus(deps, userId, id) {
  if (typeof id !== "string" || !MV.UUID_RE.test(id)) return { status: 404, body: { error: MESSAGES.notFound, code: "not_found" } };
  var r = await deps.supabase.from("instagram_posts").select(POST_COLUMNS).eq("id", id).eq("user_id", userId).maybeSingle();
  if (r.error) throw r.error;
  var row = r.data && r.data.user_id === userId ? r.data : null;
  if (!row) return { status: 404, body: { error: MESSAGES.notFound, code: "not_found" } };
  if (row.status === "published" || row.status === "failed") return { status: 200, body: Object.assign(postView(row), { note: MESSAGES.noDelete }) };
  if (!row.container_id) {
    if (deps.now() - Date.parse(row.created_at) >= STALE_CREATING_MS && await markFailed(deps, row, MESSAGES.stale)) {
      return { status: 200, body: Object.assign(postView(Object.assign({}, row, { status: "failed", error: MESSAGES.stale })), { note: MESSAGES.noDelete }) };
    }
    return { status: 200, body: Object.assign(postView(row), { note: MESSAGES.processing }) };
  }
  var conn = await readConnection(deps.supabase, userId);
  if (!conn) return { status: 409, body: { error: MESSAGES.notConnected, code: "not_connected" } };
  if (conn.status !== "connected") return { status: 409, body: { error: MESSAGES.needsReconnect, code: "needs_reconnect" } };
  var st;
  try {
    conn = (await accessToken(deps, conn)).row;
    st = await containerStatus(deps, conn, row.container_id);
  } catch (err) {
    if (err && err.kind === "auth") return { status: 409, body: { error: MESSAGES.needsReconnect, code: "needs_reconnect" } };
    return { status: 502, body: { error: MESSAGES.unreachable, code: "unreachable" } };
  }
  if (st.code === "EXPIRED" || st.code === "ERROR") {
    var why = (st.text ? "Instagram couldn't publish it: " + st.text : "Instagram couldn't publish it (" + st.code.toLowerCase() + ").").slice(0, 300);
    await markFailed(deps, row, why);
    return { status: 200, body: Object.assign(postView(Object.assign({}, row, { status: "failed", error: why })), { note: MESSAGES.noDelete }) };
  }
  if (st.code !== "FINISHED" && st.code !== "PUBLISHED") return { status: 200, body: Object.assign(postView(row), { instagram_says: st.code, note: MESSAGES.processing }) };
  // FINISHED or PUBLISHED: the caption is the approved one, from the proposal.
  var prop = await deps.supabase.from("agent_proposals").select("id, user_id, payload").eq("id", row.proposal_id).eq("user_id", userId).maybeSingle();
  if (prop.error) throw prop.error;
  var caption = prop.data && prop.data.payload && typeof prop.data.payload.caption === "string" ? prop.data.payload.caption.trim() : "";
  var out = await publishOnce(deps, conn, row, caption, true);
  if (out.busy) return { status: 409, body: { error: MESSAGES.busy, code: "busy" } };
  var fresh = await deps.supabase.from("instagram_posts").select(POST_COLUMNS).eq("id", row.id).eq("user_id", userId).maybeSingle();
  var view = postView(fresh.data || row);
  return { status: 200, body: Object.assign(view, { note: out.note || MESSAGES.noDelete }, out.error ? { error: out.error } : {}) };
}

/* What a member is shown about one post: never a container id or proposal payload. */
function postView(row) {
  return { id: row.id, kind: row.kind, status: row.status, permalink: row.status === "published" ? row.permalink || null : null,
    error: row.status === "failed" ? row.error || null : null, created_at: row.created_at, published_at: row.published_at || null };
}

/* GET /api/instagram/posts: the member's own, newest first. */
async function listPosts(deps, userId) {
  var r = await deps.supabase.from("instagram_posts").select(POST_COLUMNS).eq("user_id", userId).order("created_at", { ascending: false }).limit(50);
  if (r.error) throw r.error;
  return (r.data || []).filter(function (row) { return row.user_id === userId; }).map(postView);
}

/* ── filing ─────────────────────────────────────────────────────────────── */

async function connectedOr(deps, userId) {
  var conn = await readConnection(deps.supabase, userId);
  if (!conn) return { error: { status: 409, body: { error: MESSAGES.notConnected, code: "not_connected" } } };
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

/* POST /api/instagram/propose-post { kind: "photos" | "reel", media_ids, video_id, caption }. { status, body }. Files; never runs it. */
async function proposePost(deps, userId, input) {
  var b = input || {};
  var c = await connectedOr(deps, userId);
  if (c.error) return c.error;
  if (b.kind !== "photos" && b.kind !== "reel") return { status: 400, body: { error: MESSAGES.kind + " Nothing was filed.", code: "invalid", field: "kind" } };
  var cap = checkCaption(b.caption, deps.limits);
  if (!cap.ok) return { status: 400, body: { error: cap.error + " Nothing was filed.", code: "invalid", field: "caption" } };
  var refused = cap.caption ? deps.claims(cap.caption) : null;
  if (refused) return { status: 422, body: { error: refused.error + " Nothing was filed.", code: "claims", field: "caption", violations: refused.violations } };
  if (await postsToday(deps, userId) >= POSTS_PER_DAY) return { status: 409, body: { error: MESSAGES.dailyCap, code: "daily_cap" } };

  var payload, title, label;
  if (b.kind === "photos") {
    var parsed = parseItems(b.media_ids);
    if (parsed.error) return { status: 400, body: { error: parsed.error + " Nothing was filed.", code: "invalid", field: "media_ids" } };
    var rows = await readMediaRows(deps.supabase, userId, parsed.ids);
    var items = [];
    for (var i = 0; i < parsed.ids.length; i++) {
      var row = rows[parsed.ids[i]];
      if (!row) return { status: 404, body: { error: MESSAGES.notInLibrary, code: "not_found", field: "media_ids" } };
      var name = (row.label || "").trim() || "untitled photo";
      if (row.kind !== "image" || row.mime !== "image/jpeg") return { status: 400, body: { error: MESSAGES.jpegOnly + " (" + name + ")", code: "not_jpeg", field: "media_ids" } };
      // The bytes themselves, now: JPEG by its own bytes, matching the row.
      try {
        await readPhoto(deps, userId, row, { id: row.id, sha256: row.sha256, bytes: row.bytes });
      } catch (err) {
        if (err && err.kind === "jpeg") return { status: 400, body: { error: MESSAGES.jpegOnly + " (" + name + ")", code: "not_jpeg", field: "media_ids" } };
        return { status: 409, body: { error: MESSAGES.unread + " (" + name + ")", code: "unread", field: "media_ids" } };
      }
      var alt = typeof row.alt_text === "string" ? row.alt_text.trim().slice(0, ALT_MAX) : "";
      items.push({ id: row.id, sha256: row.sha256, bytes: row.bytes, alt: alt });
    }
    payload = { kind: items.length === 1 ? "image" : "carousel", items: items, caption: cap.caption, ig_user_id: c.conn.ig_user_id };
    label = items.length === 1 ? "1 photo" : items.length + " photos";
  } else {
    var video = await MV.readVideo(deps.supabase, userId, b.video_id);
    if (!video) return { status: 404, body: { error: MV.MESSAGES.notFound, code: "not_found" } };
    if (video.status !== "ready" || !video.path) return { status: 409, body: { error: MESSAGES.fileGone, code: "not_ready" } };
    if (REEL_MIMES.indexOf(video.mime) === -1) return { status: 400, body: { error: MESSAGES.reelType + " Nothing was filed.", code: "reel_type", field: "video_id" } };
    if ((await MV.proposalsNaming(deps.supabase, userId, video.id, [ACTION])).length) return { status: 409, body: { error: MESSAGES.pending, code: "pending" } };
    payload = { kind: "reel", video: { id: video.id, sha256: video.sha256, bytes: Number(video.bytes), mime: video.mime }, caption: cap.caption, ig_user_id: c.conn.ig_user_id };
    label = "a Reel";
  }
  if (!payloadShape(payload)) return { status: 400, body: { error: MESSAGES.shape, code: "invalid" } };
  title = ("Post to Instagram as @" + c.conn.username + " (" + label + "): " + (cap.caption || "no caption")).slice(0, 200);
  var ins = await deps.supabase.from("agent_proposals").insert({
    user_id: userId, agent_type: "social", action_type: ACTION,
    title: title, target: "instagram", payload: payload, cost_amount: 0, cost_currency: "USD", reversible: false,
    status: "pending", created_at: nowIso(deps)
  }).select("*").single();
  if (ins.error) throw ins.error;
  return { status: 201, body: { proposal: ins.data, username: c.conn.username,
    note: "Filed for approval. Nothing has been sent to Instagram. Approving it on the proposals page publishes this post to @" + c.conn.username + "'s Instagram account. " + MESSAGES.noDelete } };
}

/* ── the daily refresh (04:45 chain) ────────────────────────────────────── */
async function claimRefreshDay(supabase, nowMs) {
  var today = new Date(nowMs).toISOString().slice(0, 10);
  var started = new Date(nowMs).toISOString();
  var inserted = await supabase.from("job_runs")
    .insert({ job_name: REFRESH_JOB_NAME, last_run_on: today, started_at: started, finished_at: null, last_error: null }).select("job_name");
  if (!inserted.error) return true;
  if (inserted.error.code !== "23505") {
    console.error("[InstagramRefresh] Claim insert failed: " + (inserted.error.code || "error"));
    return false;
  }
  var updated = await supabase.from("job_runs").update({ last_run_on: today, started_at: started, finished_at: null, last_error: null })
    .eq("job_name", REFRESH_JOB_NAME).or("last_run_on.is.null,last_run_on.neq." + today).select("job_name");
  if (updated.error) {
    console.error("[InstagramRefresh] Claim update failed: " + (updated.error.code || "error"));
    return false;
  }
  return (updated.data || []).length > 0;
}

/* Once a day: every connected token expiring within the window is refreshed
   (when refreshDue), and an expired one is marked needs_reconnect. Never rejects. */
async function refreshTick(deps, nowMs) {
  var supabase = deps.supabase;
  var startedMs = typeof nowMs === "number" ? nowMs : deps.now();
  var result = { claimed: true, refreshed: 0, expired: 0, failed: 0, error: null };
  async function finish(errorMessage) {
    var patch = { finished_at: new Date(deps.now()).toISOString() };
    if (errorMessage) patch.last_error = String(errorMessage).slice(0, 2000);
    var r = await supabase.from("job_runs").update(patch).eq("job_name", REFRESH_JOB_NAME);
    if (r.error) console.error("[InstagramRefresh] Failed to record run completion: " + (r.error.code || "error"));
  }
  try {
    if (!(await claimRefreshDay(supabase, startedMs))) return { claimed: false };
    if (!deps.config()) { await finish(null); return Object.assign(result, { skipped: "not_configured" }); }
    var horizon = new Date(startedMs + IA.REFRESH_WINDOW_MS).toISOString();
    var due = await supabase.from("member_instagram_connections").select(SECRET_COLUMNS).eq("status", "connected")
      .lte("access_expires_at", horizon).limit(REFRESH_PAGE);
    if (due.error) throw new Error("member_instagram_connections could not be read");
    var rows = due.data || [];
    for (var i = 0; i < rows.length; i++) {
      var row = rows[i];
      var ends = Date.parse(row.access_expires_at || "");
      if (!isFinite(ends) || ends <= deps.now()) {
        if (await markNeedsReconnect(deps, row, "expired")) result.expired++;
        continue;
      }
      if (!IA.refreshDue(row, deps.now())) continue;
      try {
        await refreshOnce(deps, row);
        result.refreshed++;
      } catch (err) {
        result.failed++;
      }
    }
    await finish(null);
    console.log("[InstagramRefresh] Pass finished: " + result.refreshed + " Instagram token(s) refreshed, " + result.expired +
      " expired connection(s) marked to reconnect, " + result.failed + " refresh(es) that didn't go through.");
    return result;
  } catch (err) {
    var message = (err && err.message) || "error";
    console.error("[InstagramRefresh] Pass error: " + message);
    try { await finish(message); } catch (finishErr) { /* reported above */ }
    return { claimed: true, error: message };
  }
}

module.exports = {
  API_BASE: API_BASE,
  ME_URL: ME_URL,
  ACTION: ACTION,
  ACCOUNT_TYPES: ACCOUNT_TYPES,
  POSTS_PER_DAY: POSTS_PER_DAY,
  ITEMS_MAX: ITEMS_MAX,
  MENTION_MAX: MENTION_MAX,
  POLL_INTERVAL_MS: POLL_INTERVAL_MS,
  POLL_MAX_MS: POLL_MAX_MS,
  SIGNED_URL_SECONDS: SIGNED_URL_SECONDS,
  CLAIM_LEASE_MS: CLAIM_LEASE_MS,
  STALE_CREATING_MS: STALE_CREATING_MS,
  REEL_MIMES: REEL_MIMES,
  REFRESH_JOB_NAME: REFRESH_JOB_NAME,
  STATUS_COLUMNS: STATUS_COLUMNS,
  POST_COLUMNS: POST_COLUMNS,
  MESSAGES: MESSAGES,
  InstagramApiError: InstagramApiError,
  hashtagCount: hashtagCount,
  mentionCount: mentionCount,
  checkCaption: checkCaption,
  isInstagramJpeg: isInstagramJpeg,
  readConnection: readConnection,
  statusOf: statusOf,
  markNeedsReconnect: markNeedsReconnect,
  accessToken: accessToken,
  readMe: readMe,
  professional: professional,
  payloadShape: payloadShape,
  executePublish: executePublish,
  postStatus: postStatus,
  postView: postView,
  listPosts: listPosts,
  proposePost: proposePost,
  refreshTick: refreshTick
};
