"use strict";

/* ══════════════════════════════════════════════════════════════════════════
   TIKTOK, ON THE MEMBER'S OWN ACCOUNT (migration 178).

   THE CONNECTION, member_tiktok_connections, one per member. accessToken
   uses the stored access token while it is more than REFRESH_MARGIN_MS (5
   minutes) from its stored expiry; otherwise it refreshes (lib/tiktokAuth.js)
   and writes the new access token, and a new refresh token only when TikTok
   sent one, in ONE update guarded by a compare-and-set on token_version. The
   loser of a race writes nothing more, reads the row again and uses the
   winner's token. One refresh per member at a time in this process. A
   refused refresh (invalid_grant), or a refresh token past its
   refresh_expires_at, marks the connection needs_reconnect and raises ONE
   in-app notice.

   POSTING (Direct Post), TikTok's UX rules, enforced here at filing AND again
   at execution against a fresh creator_info:
     - the privacy is one of creator_info's privacy_level_options, chosen by
       the member: there is NO default;
     - Allow comments, Allow duet and Allow stitch are off unless the member
       turns them on, and one creator_info disables can never be turned on;
     - "Disclose video content" needs "Your brand", "Branded content" or both;
       branded content can't be private (SELF_ONLY);
     - the caption is at most SOCIAL_SEARCH_LIMITS.tiktok.caption_max (2200)
       characters, through the claims screen.

   THE POST, executePublish (the publish_tiktok_post executor), on approval
   only. One video is sent as ONE FILE_UPLOAD chunk (ours are at most 50 MB,
   under TikTok's 64 MB single-chunk limit):
     - with NO publish stored: the connection (the same open_id), the file,
       the 5-in-24-hours cap (tiktok_posted_at), a fresh creator_info against
       the payload, the fingerprint by streaming; then init, and the
       publish_id and the SEALED upload_url (with tiktok_upload_expires_at)
       are stored, tiktok_status initiated, BEFORE the PUT;
     - with a publish stored: the status is fetched FIRST. Posted is
       recorded. Failed is let go. While the bytes never all arrived and the
       upload_url is still valid, the whole file is PUT once more; expired,
       the stored upload is cleared and the status failed, so the next filing
       starts over. NEVER two inits while a valid upload is stored.
     - the PUT goes through lib/guardedFetch.js guardedStreamUpload, profile
       tiktok, streamed from Storage through lib/youtubeApi.js
       fingerprintGuard, with Content-Range "bytes 0-(N-1)/N": 201 is all
       received; anything else is unfinished;
     - then ONE status fetch.
   TikTok has no API to delete a post: the member deletes it in TikTok.

   Nothing here logs. No token, code or upload URL is ever put into an error,
   a result a member sees, or a log line.
   ══════════════════════════════════════════════════════════════════════════ */

const { pipeline } = require("stream");
const TA = require("./tiktokAuth");
const MV = require("./memberVideos");
const YA = require("./youtubeApi");

const API_BASE = "https://open.tiktokapis.com/v2";
const USER_URL = API_BASE + "/user/info/?fields=open_id,display_name";
const CREATOR_URL = API_BASE + "/post/publish/creator_info/query/";
const INIT_URL = API_BASE + "/post/publish/video/init/";
const STATUS_URL = API_BASE + "/post/publish/status/fetch/";
const UPLOAD_PREFIX = "https://open-upload.tiktokapis.com/upload/";
/* TikTok's upload_url is valid for an hour; it is treated as expired a little sooner. */
const UPLOAD_TTL_MS = 60 * 60 * 1000;
const UPLOAD_SLACK_MS = 5 * 60 * 1000;
// NAMED (Nov 13 2026, S3): a repost of a video waits until its last TikTok post is this old (the daily cap's window).
const REPOST_GAP_MS = 24 * 60 * 60 * 1000;
const REFRESH_MARGIN_MS = 5 * 60 * 1000;
const API_TIMEOUT_MS = 15 * 1000;
const ACTION = "publish_tiktok_post";
const PRIVACY_RE = /^[A-Z_]{1,40}$/;
const PUBLISH_ID_RE = /^[A-Za-z0-9_.~-]{1,64}$/;
const SHA_RE = /^[0-9a-f]{64}$/;
const SELF_ONLY = "SELF_ONLY";
const STATUS_COLUMNS = "id, user_id, open_id, display_name, status, created_at, last_ok_at, last_error_code";
const SECRET_COLUMNS = "id, user_id, open_id, display_name, refresh_ciphertext, refresh_iv, refresh_auth_tag, access_ciphertext, access_iv, access_auth_tag, access_expires_at, refresh_expires_at, token_version, granted_scopes, status, created_at";
const PRIVACY_WORDS = Object.freeze({
  PUBLIC_TO_EVERYONE: "Everyone",
  MUTUAL_FOLLOW_FRIENDS: "Friends",
  FOLLOWER_OF_CREATOR: "Followers",
  SELF_ONLY: "Only you"
});

const MESSAGES = Object.freeze({
  notConnected: "Connect your TikTok account first.",
  needsReconnect: "TikTok stopped accepting BizForce's access to your account, so nothing is being posted. Connect again.",
  unfinished: "The TikTok upload didn't finish. File the post again and BizForce will send the same upload again while TikTok still accepts it.",
  expired: "That TikTok upload expired before it finished, so BizForce let it go. File the post again to start it over.",
  dailyCap: "You can post 5 videos to TikTok in 24 hours. Nothing was sent. Try again later.",
  fingerprint: "The video file no longer matches the one you filed, so nothing was sent.",
  accountChanged: "The TikTok account connected now isn't the one this was filed for. Nothing was sent; file it again.",
  pending: "This video already has a TikTok post waiting for your approval.",
  alreadyPosted: "That video is already on TikTok.",
  inFlight: "That video is already being posted to TikTok. Check its status.",
  // NAMED (Nov 13 2026, S3): the time is added after it.
  repostTooSoon: "This video was posted to TikTok less than 24 hours ago. You can post it again after",
  notOnTiktok: "That video hasn't been sent to TikTok.",
  fileGone: "That video's file is no longer here. Nothing was sent.",
  unreachable: "TikTok couldn't be reached just now. Nothing changed. Try again later.",
  noDelete: "To remove a TikTok post, delete it in the TikTok app.",
  reviewed: "Until TikTok reviews BizForce, TikTok keeps posts from BizForce visible only to you.",
  privacyMissing: "Choose who can see this post.",
  privacyNotOffered: "That privacy setting isn't one TikTok offers your account. Choose again.",
  interactionOff: "Turned off in your TikTok settings",
  brandedPrivate: "Branded content can't be private.",
  disclosureOption: "Choose Your brand, Branded content, or both.",
  disclosureOff: "Turn on \"Disclose video content\" to choose Your brand or Branded content.",
  caption: "A caption is at most 2200 characters, without < or >.",
  flags: "Allow comments, Allow duet and Allow stitch are each on or off.",
  reused: "This video's earlier TikTok upload didn't finish, so approving this sends that same upload again, with the caption and settings you filed then."
});

class TiktokApiError extends Error {
  constructor(kind, code, said) { super("tiktok " + kind + " (" + code + ")"); this.name = "TiktokApiError"; this.kind = kind; this.code = code; this.said = said || null; }
}

var refreshesInFlight = new Map();

function nowIso(deps) { return new Date(deps.now()).toISOString(); }
function bearer(token) { return { Authorization: "Bearer " + token }; }
function sealed(crypt, plain) { var s = crypt.encrypt(plain); return { ciphertext: s.ciphertext, iv: s.iv, authTag: s.authTag }; }
function codePoints(s) { return Array.from(String(s)).length; }
/* What TikTok said, safe to show: plain text, no markup, at most 300 characters. */
function said(json) {
  var e = json && json.error && typeof json.error === "object" ? json.error : null;
  var m = e && typeof e.message === "string" ? e.message.replace(/[<>]/g, "").replace(/\s+/g, " ").trim().slice(0, 300) : "";
  return m || null;
}
/* Every TikTok JSON answer carries error.code "ok" on success. */
function tiktokOk(answer) {
  return !!(answer && answer.status >= 200 && answer.status < 300 && answer.json && answer.json.error && answer.json.error.code === "ok");
}
function errorCode(answer) {
  var c = answer && answer.json && answer.json.error && answer.json.error.code;
  return typeof c === "string" && /^[a-z0-9_]{1,60}$/.test(c) ? c : "status_" + (answer ? answer.status : "none");
}

/* ── the connection ─────────────────────────────────────────────────────── */
async function readConnection(supabase, userId) {
  var r = await supabase.from("member_tiktok_connections").select(SECRET_COLUMNS).eq("user_id", userId).maybeSingle();
  if (r.error) throw r.error;
  return r.data && r.data.user_id === userId ? r.data : null;
}

function statusOf(row, available) {
  var r = row || null;
  return {
    tiktok_available: available === true,
    connected: !!r && r.status === "connected",
    status: r ? r.status : "not_connected",
    display_name: r ? r.display_name : null,
    since: r ? r.created_at : null,
    reconnect_message: r && r.status === "needs_reconnect" ? MESSAGES.needsReconnect : null
  };
}

/* needs_reconnect and ONE notice, only when it was connected. Never throws. */
async function markNeedsReconnect(deps, row, code) {
  try {
    var stamp = nowIso(deps);
    var marked = await deps.supabase.from("member_tiktok_connections")
      .update({ status: "needs_reconnect", last_error_at: stamp, last_error_code: String(code || "invalid_grant").slice(0, 60), updated_at: stamp })
      .eq("id", row.id).eq("user_id", row.user_id).eq("status", "connected").select("id");
    if (marked.error || !(marked.data || []).length) return false;
    var notice = await deps.supabase.from("notifications").insert({
      user_id: row.user_id,
      type: "tiktok_reconnect",
      title: "Reconnect your TikTok account",
      message: "TikTok stopped accepting BizForce's access to " + row.display_name + ", so nothing is being posted and nothing will be tried again. Connect TikTok again on the Social Agent page.",
      read: false
    });
    if (notice.error) console.warn("[tiktok] the reconnect notice could not be saved: " + (notice.error.code || "error"));
    return true;
  } catch (err) {
    return false;
  }
}

function readAccess(deps, row) {
  try {
    return deps.crypt.decrypt({ ciphertext: row.access_ciphertext, iv: row.access_iv, authTag: row.access_auth_tag });
  } catch (err) {
    throw new TiktokApiError("auth", "secret_unreadable");
  }
}

async function refreshRow(deps, row) {
  var config = deps.config();
  if (!config) throw new TiktokApiError("unreachable", "not_configured");
  // The version this row was read at, taken before TikTok is asked: the compare-and-set below is against it.
  var version = Number.isInteger(row.token_version) ? row.token_version : 0;
  var refreshEnds = Date.parse(row.refresh_expires_at || "");
  if (isFinite(refreshEnds) && refreshEnds <= deps.now()) {
    await markNeedsReconnect(deps, row, "refresh_expired");
    throw new TiktokApiError("auth", "refresh_expired");
  }
  var refreshToken;
  try {
    refreshToken = deps.crypt.decrypt({ ciphertext: row.refresh_ciphertext, iv: row.refresh_iv, authTag: row.refresh_auth_tag });
  } catch (err) {
    throw new TiktokApiError("auth", "secret_unreadable");
  }
  var grant;
  try {
    grant = await TA.refreshTokens(config, refreshToken);
  } catch (err) {
    if (err && err.kind === "invalid_grant") {
      await markNeedsReconnect(deps, row, "invalid_grant");
      throw new TiktokApiError("auth", "invalid_grant");
    }
    throw new TiktokApiError("unreachable", "token_refresh");
  } finally {
    refreshToken = null;
  }
  var access = sealed(deps.crypt, grant.accessToken);
  var update = {
    access_ciphertext: access.ciphertext, access_iv: access.iv, access_auth_tag: access.authTag,
    access_expires_at: new Date(deps.now() + grant.expiresIn * 1000 - TA.EXPIRY_SLACK_MS).toISOString(),
    token_version: version + 1,
    updated_at: nowIso(deps)
  };
  if (grant.refreshExpiresIn) update.refresh_expires_at = new Date(deps.now() + grant.refreshExpiresIn * 1000).toISOString();
  // A rotated refresh token is stored; with none, the stored one stays.
  if (grant.refreshToken) {
    var refresh = sealed(deps.crypt, grant.refreshToken);
    update.refresh_ciphertext = refresh.ciphertext; update.refresh_iv = refresh.iv; update.refresh_auth_tag = refresh.authTag;
  }
  var swapped = await deps.supabase.from("member_tiktok_connections").update(update)
    .eq("id", row.id).eq("user_id", row.user_id).eq("token_version", version).select("id");
  if (swapped.error) throw new TiktokApiError("unreachable", "token_store");
  if ((swapped.data || []).length === 1) {
    return { token: grant.accessToken, row: Object.assign({}, row, update), refreshedNow: true };
  }
  // Lost the race: nothing more is written. The winner's token is the one to use.
  grant = null;
  var current = await readConnection(deps.supabase, row.user_id);
  if (!current || current.status !== "connected") throw new TiktokApiError("auth", "refresh_lost");
  return { token: readAccess(deps, current), row: current, refreshedNow: true };
}

async function accessToken(deps, row, force) {
  if (!row || row.status !== "connected") throw new TiktokApiError("auth", "not_connected");
  var expires = Date.parse(row.access_expires_at);
  if (!force && isFinite(expires) && expires - deps.now() > REFRESH_MARGIN_MS) {
    return { token: readAccess(deps, row), row: row, refreshedNow: false };
  }
  var key = row.user_id;
  var running = refreshesInFlight.get(key);
  if (running) return running;
  var started = refreshRow(deps, row);
  refreshesInFlight.set(key, started);
  try {
    return await started;
  } finally {
    if (refreshesInFlight.get(key) === started) refreshesInFlight.delete(key);
  }
}

async function api(deps, url, options) {
  try {
    return await deps.jsonRequest(url, Object.assign({ timeoutMs: API_TIMEOUT_MS }, options));
  } catch (err) {
    throw new TiktokApiError("unreachable", (err && err.code) || "request");
  }
}

/* A JSON call with the access token; a 401 on a token not refreshed in this
   call gets ONE forced refresh and ONE more try. */
async function withToken(deps, row, send) {
  var got = await accessToken(deps, row, false);
  var answer = await send(got.token);
  if (answer && answer.status === 401 && !got.refreshedNow) {
    got = await accessToken(deps, got.row, true);
    answer = await send(got.token);
  }
  if (answer && answer.status === 401) {
    await markNeedsReconnect(deps, got.row, "unauthorized");
    throw new TiktokApiError("auth", "unauthorized");
  }
  return { answer: answer, token: got.token, row: got.row };
}

/* The account the token belongs to: { open_id, display_name }, or null. */
async function readUser(deps, token) {
  var answer = await api(deps, USER_URL, { method: "GET", headers: bearer(token) });
  if (answer.status === 401) throw new TiktokApiError("auth", "unauthorized");
  if (!tiktokOk(answer)) throw new TiktokApiError("unreachable", errorCode(answer));
  var u = answer.json.data && answer.json.data.user;
  if (!u || typeof u.open_id !== "string" || !TA.OPEN_ID_RE.test(u.open_id)) return null;
  var name = typeof u.display_name === "string" ? u.display_name.replace(/[\u0000-\u001f]/g, "").trim().slice(0, 200) : "";
  return { open_id: u.open_id, display_name: name || "your TikTok account" };
}

/* creator_info, live, normalised. Throws TiktokApiError. */
async function creatorInfo(deps, conn) {
  var out = await withToken(deps, conn, function (token) {
    return api(deps, CREATOR_URL, { method: "POST", headers: bearer(token), body: {} });
  });
  var a = out.answer;
  if (!tiktokOk(a)) throw new TiktokApiError("refused", errorCode(a), said(a.json));
  var d = a.json.data && typeof a.json.data === "object" ? a.json.data : {};
  var options = Array.isArray(d.privacy_level_options) ? d.privacy_level_options.filter(function (o) { return typeof o === "string" && PRIVACY_RE.test(o); }) : [];
  var nickname = typeof d.creator_nickname === "string" ? d.creator_nickname.replace(/[\u0000-\u001f]/g, "").trim().slice(0, 200) : "";
  var username = typeof d.creator_username === "string" && /^[A-Za-z0-9_.]{1,64}$/.test(d.creator_username) ? d.creator_username : null;
  var maxSec = typeof d.max_video_post_duration_sec === "number" && Number.isInteger(d.max_video_post_duration_sec) && d.max_video_post_duration_sec > 0 ? d.max_video_post_duration_sec : null;
  return {
    creator_nickname: nickname || "your TikTok account",
    creator_username: username,
    privacy_level_options: options,
    comment_disabled: d.comment_disabled === true,
    duet_disabled: d.duet_disabled === true,
    stitch_disabled: d.stitch_disabled === true,
    max_video_post_duration_sec: maxSec
  };
}

/* ── the posting rules ──────────────────────────────────────────────────── */

/* { ok: true, value } or { ok: false, error, field }. TikTok's UX rules against
   one creator_info; limits is SOCIAL_SEARCH_LIMITS.tiktok (caption_max). */
function validatePost(input, creator, limits) {
  var b = input || {};
  var c = creator || {};
  var max = limits && limits.caption_max;
  var caption = b.caption === undefined || b.caption === null ? "" : b.caption;
  if (typeof caption !== "string") return { ok: false, error: MESSAGES.caption, field: "caption" };
  caption = caption.trim();
  if (!(typeof max === "number" && codePoints(caption) <= max) || /[<>]/.test(caption)) return { ok: false, error: MESSAGES.caption, field: "caption" };
  // No default: the member chooses, from what TikTok offers this account.
  if (typeof b.privacy_level !== "string" || !b.privacy_level) return { ok: false, error: MESSAGES.privacyMissing, field: "privacy_level" };
  if ((c.privacy_level_options || []).indexOf(b.privacy_level) === -1) return { ok: false, error: MESSAGES.privacyNotOffered, field: "privacy_level" };
  var flags = {};
  var names = [["allow_comment", "comment_disabled", "Allow comments"], ["allow_duet", "duet_disabled", "Allow duet"], ["allow_stitch", "stitch_disabled", "Allow stitch"]];
  for (var i = 0; i < names.length; i++) {
    var v = b[names[i][0]] === undefined ? false : b[names[i][0]];
    if (typeof v !== "boolean") return { ok: false, error: MESSAGES.flags, field: names[i][0] };
    if (v && c[names[i][1]] === true) return { ok: false, error: names[i][2] + ": " + MESSAGES.interactionOff + ".", field: names[i][0] };
    flags[names[i][0]] = v;
  }
  var organic = b.brand_organic === undefined ? false : b.brand_organic;
  var content = b.brand_content === undefined ? false : b.brand_content;
  var disclose = b.disclose === undefined ? (organic === true || content === true) : b.disclose;
  if (typeof organic !== "boolean" || typeof content !== "boolean" || typeof disclose !== "boolean") return { ok: false, error: MESSAGES.disclosureOption, field: "disclose" };
  if (disclose && !organic && !content) return { ok: false, error: MESSAGES.disclosureOption, field: "disclose" };
  if (!disclose && (organic || content)) return { ok: false, error: MESSAGES.disclosureOff, field: "disclose" };
  if (content && b.privacy_level === SELF_ONLY) return { ok: false, error: MESSAGES.brandedPrivate, field: "privacy_level" };
  return { ok: true, value: {
    caption: caption, privacy_level: b.privacy_level,
    allow_comment: flags.allow_comment, allow_duet: flags.allow_duet, allow_stitch: flags.allow_stitch,
    brand_organic: organic, brand_content: content
  } };
}

/* The label TikTok puts on the video, and the consent line, word for word. */
function labelLine(v) {
  if (v.brand_content) return "Your video will be labeled 'Paid partnership'.";
  if (v.brand_organic) return "Your video will be labeled 'Promotional content'.";
  return null;
}
function consentLine(v) {
  return v.brand_content ? "By posting, you agree to TikTok's Branded Content Policy and Music Usage Confirmation." :
    "By posting, you agree to TikTok's Music Usage Confirmation.";
}

/* The filed payload, checked for shape (its rules are checked against creator_info separately). */
function payloadShape(p) {
  if (!p || typeof p !== "object") return false;
  return MV.UUID_RE.test(String(p.video_id || "")) && SHA_RE.test(String(p.sha256 || "")) && Number.isInteger(p.bytes) && p.bytes > 0 &&
    typeof p.mime === "string" && typeof p.caption === "string" && typeof p.privacy_level === "string" && PRIVACY_RE.test(p.privacy_level) &&
    ["allow_comment", "allow_duet", "allow_stitch", "brand_organic", "brand_content"].every(function (k) { return typeof p[k] === "boolean"; }) &&
    typeof p.open_id === "string" && TA.OPEN_ID_RE.test(p.open_id);
}
function postFields(p) {
  return { caption: p.caption, privacy_level: p.privacy_level, allow_comment: p.allow_comment, allow_duet: p.allow_duet, allow_stitch: p.allow_stitch,
    brand_organic: p.brand_organic, brand_content: p.brand_content, disclose: p.brand_organic === true || p.brand_content === true };
}

/* ── the post ───────────────────────────────────────────────────────────── */

/* TikTok's status words, as stored: posted, failed, processing; null for a word it has not documented. */
function mapStatus(s) {
  if (s === "PUBLISH_COMPLETE") return "posted";
  if (s === "FAILED") return "failed";
  if (s === "PROCESSING_UPLOAD" || s === "PROCESSING_DOWNLOAD" || s === "SEND_TO_USER_INBOX") return "processing";
  return null;
}
function postIdOf(d) {
  var v = d && d.publicaly_available_post_id;
  var first = Array.isArray(v) ? v[0] : v;
  var s = typeof first === "number" && Number.isSafeInteger(first) ? String(first) : (typeof first === "string" ? first : "");
  return MV.TIKTOK_POST_ID_RE.test(s) ? s : null;
}
function failReason(d) {
  var r = d && typeof d.fail_reason === "string" ? d.fail_reason : "";
  return /^[a-z0-9_]{1,60}$/.test(r) ? r : null;
}

async function fetchStatus(deps, conn, publishId) {
  var out = await withToken(deps, conn, function (token) {
    return api(deps, STATUS_URL, { method: "POST", headers: bearer(token), body: { publish_id: publishId } });
  });
  if (!tiktokOk(out.answer)) throw new TiktokApiError("unreachable", errorCode(out.answer));
  var d = out.answer.json.data && typeof out.answer.json.data === "object" ? out.answer.json.data : {};
  return { status: typeof d.status === "string" ? d.status : null, mapped: mapStatus(d.status), post_id: postIdOf(d), fail_reason: failReason(d) };
}

var UPLOAD_CLEARED = { tiktok_upload_ciphertext: null, tiktok_upload_iv: null, tiktok_upload_auth_tag: null, tiktok_upload_expires_at: null };

async function recordPosted(deps, video, st) {
  var at = nowIso(deps);
  var u = await deps.supabase.from("member_videos").update(Object.assign({ tiktok_status: "posted", tiktok_posted_at: at, tiktok_post_id: st.post_id || null }, UPLOAD_CLEARED))
    .eq("id", video.id).eq("user_id", video.user_id).select("id");
  if (u.error || (u.data || []).length !== 1) {
    throw new Error("publish_tiktok_post: the video WAS posted to TikTok, but it could not be recorded. Don't file it again.");
  }
  return { posted: true, status: "posted", post_url: MV.tiktokUrl(st.post_id), posted_at: at };
}
async function markFailed(deps, video) {
  await deps.supabase.from("member_videos").update(Object.assign({ tiktok_status: "failed", tiktok_publish_id: null }, UPLOAD_CLEARED))
    .eq("id", video.id).eq("user_id", video.user_id);
}
async function markUploaded(deps, video) {
  await deps.supabase.from("member_videos").update(Object.assign({ tiktok_status: "processing" }, UPLOAD_CLEARED))
    .eq("id", video.id).eq("user_id", video.user_id);
}
function failedText(st) {
  return "TikTok couldn't post it" + (st && st.fail_reason ? " (" + st.fail_reason + ")" : "") + ". File it again to try once more.";
}

/* The whole file, ONE chunk, through the fingerprint guard. The answer, or null when the connection failed. */
async function sendWhole(deps, uploadUrl, video) {
  var total = Number(video.bytes);
  var source = await MV.openStream(deps.storage, video.path);
  if (!source) throw new TiktokApiError("unreachable", "storage_unreadable");
  var guard = YA.fingerprintGuard(video.sha256, total, 0);
  pipeline(source, guard, function () { /* an error reaches the upload through guard */ });
  try {
    return await deps.streamUpload(uploadUrl, {
      profile: "tiktok",
      method: "PUT",
      headers: { "Content-Type": video.mime },
      body: guard,
      contentLength: total,
      contentRange: "bytes 0-" + (total - 1) + "/" + total
    });
  } catch (err) {
    if (err && err.code === "body_failed") throw new TiktokApiError("fingerprint", "body_failed");
    return null;
  }
}
function putComplete(answer) { return !!answer && answer.status === 201; }

/* The stored file still holds the filed file: streamed and hashed, never held whole. */
async function verifyFile(deps, video) {
  var stream = await MV.openStream(deps.storage, video.path);
  if (!stream) return false;
  var m = await MV.measureStream(stream, MV.MAX_BYTES);
  return !m.tooBig && m.bytes === Number(video.bytes) && m.sha256 === video.sha256;
}

/* After the bytes are all there: ONE status fetch. */
async function afterUpload(deps, conn, video, fail) {
  var st;
  try {
    st = await fetchStatus(deps, conn, video.tiktok_publish_id);
  } catch (err) {
    return { processing: true, status: "processing", note: "TikTok has the video and is processing it. Check its status on the Social page." };
  }
  if (st.mapped === "posted") return recordPosted(deps, video, st);
  if (st.mapped === "failed") { await markFailed(deps, video); throw fail(failedText(st)); }
  return { processing: true, status: "processing", note: "TikTok has the video and is processing it. Check its status on the Social page." };
}

async function postsToday(deps, userId) {
  var since = new Date(deps.now() - 24 * 60 * 60 * 1000).toISOString();
  var counted = await deps.supabase.from("member_videos").select("id", { count: "exact", head: true }).eq("user_id", userId).gte("tiktok_posted_at", since);
  if (counted.error) throw new TiktokApiError("unreachable", "count");
  return counted.count || 0;
}

/* The publish_tiktok_post executor. One argument, the claimed proposal. */
async function executePublish(deps, proposal) {
  var fail = function (why) { return new Error("publish_tiktok_post: " + why); };
  var p = proposal && proposal.payload && typeof proposal.payload === "object" ? proposal.payload : {};
  var ownerId = proposal && proposal.user_id;
  if (!payloadShape(p)) throw fail("the filed post is not complete. Nothing was sent.");
  var refused = p.caption ? deps.claims(p.caption) : null;
  if (refused) throw fail(refused.error + " Nothing was sent.");
  var video = await MV.readVideo(deps.supabase, ownerId, p.video_id);
  if (!video) throw fail(MV.MESSAGES.notFound + " Nothing was sent.");
  /* NAMED (Nov 13 2026, S3): a filed repost (repost: true) goes on only while the row still holds the posted publish
     it was filed against (repost_of). The new publish replaces that one when it is stored, so approving it again
     is "already posted" (or continues the new upload), as before. */
  var reposting = p.repost === true && video.tiktok_status === "posted" && (video.tiktok_publish_id || null) === (p.repost_of || null);
  if (video.tiktok_status === "posted" && !reposting) {
    return { already_posted: true, post_url: MV.tiktokUrl(video.tiktok_post_id), posted_at: video.tiktok_posted_at };
  }
  var conn = await readConnection(deps.supabase, ownerId);
  if (!conn) throw fail(MESSAGES.notConnected + " Nothing was sent.");
  if (conn.status !== "connected") throw fail(MESSAGES.needsReconnect);
  if (conn.open_id !== p.open_id) throw fail(MESSAGES.accountChanged);
  try {
    await accessToken(deps, conn, false);
  } catch (err) {
    throw fail(err && err.kind === "auth" ? MESSAGES.needsReconnect : MESSAGES.unreachable);
  }

  if (video.tiktok_publish_id && !reposting) {
    // A stored publish: ask TikTok first. Never a second init while a valid upload is stored.
    var st;
    try {
      st = await fetchStatus(deps, conn, video.tiktok_publish_id);
    } catch (err) {
      throw fail(err && err.kind === "auth" ? MESSAGES.needsReconnect : MESSAGES.unfinished);
    }
    if (st.mapped === "posted") return recordPosted(deps, video, st);
    if (st.mapped === "failed") { await markFailed(deps, video); throw fail(failedText(st)); }
    if (!video.tiktok_upload_ciphertext) {
      // Every byte arrived earlier; TikTok is still working on it.
      if (video.tiktok_status !== "processing") await markUploaded(deps, video);
      return { processing: true, status: "processing", note: "TikTok has the video and is processing it. Check its status on the Social page." };
    }
    var ends = Date.parse(video.tiktok_upload_expires_at || "");
    if (!isFinite(ends) || ends <= deps.now()) { await markFailed(deps, video); throw fail(MESSAGES.expired); }
    if (video.status !== "ready" || !video.path) { await markFailed(deps, video); throw fail(MESSAGES.fileGone); }
    if (video.sha256 !== p.sha256 || Number(video.bytes) !== Number(p.bytes) || video.mime !== p.mime) throw fail(MESSAGES.fingerprint);
    if (!(await verifyFile(deps, video))) throw fail(MESSAGES.fingerprint);
    var again;
    try {
      again = deps.crypt.decrypt({ ciphertext: video.tiktok_upload_ciphertext, iv: video.tiktok_upload_iv, authTag: video.tiktok_upload_auth_tag });
    } catch (err) {
      throw fail(MESSAGES.unfinished);
    }
    var resent;
    try {
      resent = await sendWhole(deps, again, video);
    } catch (err) {
      throw fail(err && err.kind === "fingerprint" ? MESSAGES.fingerprint : MESSAGES.unfinished);
    }
    again = null;
    if (!putComplete(resent)) throw fail(MESSAGES.unfinished);
    await markUploaded(deps, video);
    return afterUpload(deps, conn, video, fail);
  }

  // A new post.
  if (video.status !== "ready" || !video.path) throw fail(MESSAGES.fileGone);
  if (video.sha256 !== p.sha256 || Number(video.bytes) !== Number(p.bytes) || video.mime !== p.mime) throw fail(MESSAGES.fingerprint);
  var today;
  try { today = await postsToday(deps, ownerId); } catch (err) { throw fail(MESSAGES.unreachable); }
  if (today >= MV.TIKTOK_POSTS_PER_DAY) throw fail(MESSAGES.dailyCap);
  var creator;
  try {
    creator = await creatorInfo(deps, conn);
  } catch (err) {
    if (err && err.kind === "auth") throw fail(MESSAGES.needsReconnect);
    throw fail(err && err.said ? "TikTok said: " + err.said + " Nothing was sent." : MESSAGES.unreachable);
  }
  // The rules again, against what TikTok says now.
  var checked = validatePost(postFields(p), creator, deps.limits);
  if (!checked.ok) throw fail(checked.error + " Nothing was sent.");
  if (!(await verifyFile(deps, video))) throw fail(MESSAGES.fingerprint);
  var v = checked.value;
  var out;
  try {
    out = await withToken(deps, conn, function (token) {
      return api(deps, INIT_URL, { method: "POST", headers: bearer(token), body: {
        post_info: {
          title: v.caption, privacy_level: v.privacy_level,
          disable_comment: !v.allow_comment, disable_duet: !v.allow_duet, disable_stitch: !v.allow_stitch,
          brand_content_toggle: v.brand_content, brand_organic_toggle: v.brand_organic
        },
        source_info: { source: "FILE_UPLOAD", video_size: Number(video.bytes), chunk_size: Number(video.bytes), total_chunk_count: 1 }
      } });
    });
  } catch (err) {
    throw fail(err && err.kind === "auth" ? MESSAGES.needsReconnect : "TikTok couldn't be reached to start the post. Nothing was sent.");
  }
  var a = out.answer;
  if (!tiktokOk(a)) {
    var words = said(a.json);
    throw fail(words ? "TikTok refused the post: " + words + " Nothing was sent." : "TikTok didn't start the post (" + errorCode(a) + "). Nothing was sent.");
  }
  var d = a.json.data && typeof a.json.data === "object" ? a.json.data : {};
  var publishId = typeof d.publish_id === "string" ? d.publish_id : "";
  var uploadUrl = typeof d.upload_url === "string" ? d.upload_url : "";
  if (!PUBLISH_ID_RE.test(publishId) || uploadUrl.indexOf(UPLOAD_PREFIX) !== 0) {
    throw fail("TikTok didn't start the post. Nothing was sent.");
  }
  // Sealed and stored BEFORE the PUT: a crash from here on leaves an upload to continue, never a second init.
  var s = sealed(deps.crypt, uploadUrl);
  var storing = deps.supabase.from("member_videos").update({
    tiktok_publish_id: publishId, tiktok_status: "initiated", tiktok_posted_at: null, tiktok_post_id: null,
    tiktok_upload_ciphertext: s.ciphertext, tiktok_upload_iv: s.iv, tiktok_upload_auth_tag: s.authTag,
    tiktok_upload_expires_at: new Date(deps.now() + UPLOAD_TTL_MS - UPLOAD_SLACK_MS).toISOString()
  }).eq("id", video.id).eq("user_id", ownerId).eq("status", "ready");
  // NAMED (Nov 13 2026, S3): a repost replaces only the posted publish it was filed against; a new post only an empty slot.
  if (reposting && p.repost_of) storing = storing.eq("tiktok_publish_id", p.repost_of).eq("tiktok_status", "posted");
  else storing = storing.is("tiktok_publish_id", null);
  var stored = await storing.select("id");
  if (stored.error || (stored.data || []).length !== 1) throw fail("the upload couldn't be recorded before sending, so nothing was sent.");
  video = Object.assign({}, video, { tiktok_publish_id: publishId });
  var put;
  try {
    put = await sendWhole(deps, uploadUrl, video);
  } catch (err) {
    throw fail(err && err.kind === "fingerprint" ? MESSAGES.fingerprint : MESSAGES.unfinished);
  }
  uploadUrl = null;
  if (!putComplete(put)) throw fail(MESSAGES.unfinished);
  await markUploaded(deps, video);
  return afterUpload(deps, conn, video, fail);
}

/* GET /api/tiktok/videos/:id/status: a live status fetch, recording what changed. { status, body }. */
async function videoStatus(deps, userId, id) {
  var video = await MV.readVideo(deps.supabase, userId, id);
  if (!video) return { status: 404, body: { error: MV.MESSAGES.notFound, code: "not_found" } };
  if (!video.tiktok_publish_id) {
    if (video.tiktok_status === "failed") return { status: 200, body: { tiktok_status: "failed", message: "TikTok didn't post it. File it again to try once more." } };
    return { status: 409, body: { error: MESSAGES.notOnTiktok, code: "not_on_tiktok" } };
  }
  var conn = await readConnection(deps.supabase, userId);
  if (!conn) return { status: 409, body: { error: MESSAGES.notConnected, code: "not_connected" } };
  if (conn.status !== "connected") return { status: 409, body: { error: MESSAGES.needsReconnect, code: "needs_reconnect" } };
  var st;
  try {
    st = await fetchStatus(deps, conn, video.tiktok_publish_id);
  } catch (err) {
    if (err && err.kind === "auth") return { status: 409, body: { error: MESSAGES.needsReconnect, code: "needs_reconnect" } };
    return { status: 502, body: { error: MESSAGES.unreachable, code: "unreachable" } };
  }
  var now = video.tiktok_status;
  var postUrl = MV.tiktokUrl(video.tiktok_post_id);
  if (st.mapped === "posted" && (video.tiktok_status !== "posted" || (!video.tiktok_post_id && st.post_id))) {
    var rec = await recordPosted(deps, video, st);
    now = "posted"; postUrl = rec.post_url;
  } else if (st.mapped === "failed") {
    await markFailed(deps, video);
    now = "failed";
  } else if (st.mapped === "processing" && video.tiktok_status === "initiated" && !video.tiktok_upload_ciphertext) {
    await markUploaded(deps, video);
    now = "processing";
  }
  return { status: 200, body: { tiktok_status: now, tiktok_says: st.status, fail_reason: st.mapped === "failed" ? st.fail_reason : null, post_url: postUrl,
    note: MESSAGES.noDelete } };
}

/* ── filing ─────────────────────────────────────────────────────────────── */

async function connectedOr(deps, userId) {
  var conn = await readConnection(deps.supabase, userId);
  if (!conn) return { error: { status: 409, body: { error: MESSAGES.notConnected, code: "not_connected" } } };
  if (conn.status !== "connected") return { error: { status: 409, body: { error: MESSAGES.needsReconnect, code: "needs_reconnect" } } };
  return { conn: conn };
}

/* GET /api/tiktok/creator-info, live. { status, body }. */
async function creatorView(deps, userId) {
  var c = await connectedOr(deps, userId);
  if (c.error) return c.error;
  try {
    var info = await creatorInfo(deps, c.conn);
    return { status: 200, body: Object.assign({}, info, { privacy_words: PRIVACY_WORDS }) };
  } catch (err) {
    if (err && err.kind === "auth") return { status: 409, body: { error: MESSAGES.needsReconnect, code: "needs_reconnect" } };
    return { status: 502, body: { error: err && err.said ? "TikTok said: " + err.said : MESSAGES.unreachable, code: "unreachable" } };
  }
}

/* The most recent TikTok proposal filed for this video, of any status. */
async function lastProposal(supabase, userId, videoId) {
  var r = await supabase.from("agent_proposals").select("id, payload, created_at").eq("user_id", userId).eq("action_type", ACTION)
    .order("created_at", { ascending: false }).limit(200);
  if (r.error) throw r.error;
  var mine = (r.data || []).filter(function (x) { return x.payload && x.payload.video_id === videoId; });
  mine.sort(function (a, b) { return String(b.created_at).localeCompare(String(a.created_at)); });
  return mine[0] || null;
}

/* POST /api/tiktok/propose-post. { status, body }. Files; never runs it. */
async function proposePost(deps, userId, input) {
  var b = input || {};
  var c = await connectedOr(deps, userId);
  if (c.error) return c.error;
  var video = await MV.readVideo(deps.supabase, userId, b.video_id);
  if (!video) return { status: 404, body: { error: MV.MESSAGES.notFound, code: "not_found" } };
  if (video.status !== "ready" || !video.path) return { status: 409, body: { error: MESSAGES.fileGone, code: "not_ready" } };
  /* NAMED (Nov 13 2026, S3, "Post again"): a video already on TikTok is filed again ONLY when the request says
     repost: true (exactly true), sent after the member confirms "Post again"; without it, 409 already_posted as before.
     Every other rule stands: in flight, one pending post per video, the daily cap, creator_info, the UX rules, the
     claims screen. A repost waits until its last post is 24 hours old, so the one posted time the row keeps never
     hides a post from the daily cap. The payload names the publish it was filed against (repost_of). */
  var repost = b.repost === true && video.tiktok_status === "posted";
  if (video.tiktok_status === "posted" && !repost) return { status: 409, body: { error: MESSAGES.alreadyPosted, code: "already_posted" } };
  if (video.tiktok_status === "processing") return { status: 409, body: { error: MESSAGES.inFlight, code: "in_flight" } };
  if ((await MV.proposalsNaming(deps.supabase, userId, video.id, [ACTION])).length) {
    return { status: 409, body: { error: MESSAGES.pending, code: "pending" } };
  }
  if (repost) {
    var lastAt = Date.parse(video.tiktok_posted_at || "");
    if (isFinite(lastAt) && deps.now() - lastAt < REPOST_GAP_MS) {
      return { status: 409, body: { error: MESSAGES.repostTooSoon + " " + new Date(lastAt + REPOST_GAP_MS).toISOString().slice(0, 16).replace("T", " ") + " UTC.", code: "repost_too_soon" } };
    }
  }
  if (await postsToday(deps, userId) >= MV.TIKTOK_POSTS_PER_DAY) return { status: 409, body: { error: MESSAGES.dailyCap, code: "daily_cap" } };
  var value = null, reused = false, creator;
  try {
    creator = await creatorInfo(deps, c.conn);
  } catch (err) {
    if (err && err.kind === "auth") return { status: 409, body: { error: MESSAGES.needsReconnect, code: "needs_reconnect" } };
    return { status: 502, body: { error: err && err.said ? "TikTok said: " + err.said + " Nothing was filed." : MESSAGES.unreachable, code: "unreachable" } };
  }
  if (video.tiktok_publish_id && video.tiktok_upload_ciphertext) {
    // An upload that never finished is sent again as it was started: its settings are already at TikTok.
    var prior = await lastProposal(deps.supabase, userId, video.id);
    if (prior && payloadShape(prior.payload)) { value = postFields(prior.payload); delete value.disclose; reused = true; }
  }
  if (!value) {
    var checked = validatePost(b, creator, deps.limits);
    if (!checked.ok) return { status: 400, body: { error: checked.error + " Nothing was filed.", code: "invalid", field: checked.field } };
    value = checked.value;
  }
  var refused = value.caption ? deps.claims(value.caption) : null;
  if (refused) return { status: 422, body: { error: refused.error + " Nothing was filed.", code: "claims", field: "caption", violations: refused.violations } };
  var payload = {
    video_id: video.id, sha256: video.sha256, bytes: Number(video.bytes), mime: video.mime,
    caption: value.caption, privacy_level: value.privacy_level,
    allow_comment: value.allow_comment, allow_duet: value.allow_duet, allow_stitch: value.allow_stitch,
    brand_organic: value.brand_organic, brand_content: value.brand_content, open_id: c.conn.open_id
  };
  if (repost) { payload.repost = true; payload.repost_of = video.tiktok_publish_id || null; }
  var word = PRIVACY_WORDS[value.privacy_level] || value.privacy_level;
  var ins = await deps.supabase.from("agent_proposals").insert({
    user_id: userId, agent_type: "social", action_type: ACTION,
    title: ((repost ? "Post to TikTok again as " : "Post to TikTok as ") + creator.creator_nickname + " (" + word + "): " + (value.caption || video.label || "video")).slice(0, 200),
    target: "tiktok", payload: payload, cost_amount: 0, cost_currency: "USD", reversible: false,
    status: "pending", created_at: nowIso(deps)
  }).select("*").single();
  if (ins.error) throw ins.error;
  var note = "Filed for approval. Nothing has been sent to TikTok. Approving it on the proposals page posts this video to " +
    creator.creator_nickname + "'s TikTok account, visible to: " + word + ".";
  if (reused) note += " " + MESSAGES.reused;
  return { status: 201, body: { proposal: ins.data, creator_nickname: creator.creator_nickname, reused_earlier_details: reused, note: note,
    label_line: labelLine(value), consent_line: consentLine(value) } };
}

module.exports = {
  API_BASE: API_BASE,
  USER_URL: USER_URL,
  CREATOR_URL: CREATOR_URL,
  INIT_URL: INIT_URL,
  STATUS_URL: STATUS_URL,
  UPLOAD_PREFIX: UPLOAD_PREFIX,
  UPLOAD_TTL_MS: UPLOAD_TTL_MS,
  UPLOAD_SLACK_MS: UPLOAD_SLACK_MS,
  REFRESH_MARGIN_MS: REFRESH_MARGIN_MS,
  ACTION: ACTION,
  PRIVACY_WORDS: PRIVACY_WORDS,
  STATUS_COLUMNS: STATUS_COLUMNS,
  MESSAGES: MESSAGES,
  TiktokApiError: TiktokApiError,
  readConnection: readConnection,
  statusOf: statusOf,
  markNeedsReconnect: markNeedsReconnect,
  accessToken: accessToken,
  readUser: readUser,
  creatorInfo: creatorInfo,
  creatorView: creatorView,
  validatePost: validatePost,
  labelLine: labelLine,
  consentLine: consentLine,
  mapStatus: mapStatus,
  executePublish: executePublish,
  videoStatus: videoStatus,
  proposePost: proposePost
};
