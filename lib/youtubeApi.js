"use strict";

/* ══════════════════════════════════════════════════════════════════════════
   YOUTUBE, ON THE MEMBER'S OWN CHANNEL (migration 177).

   THE CONNECTION, member_youtube_connections, one per member. accessToken
   uses the stored access token while it is more than REFRESH_MARGIN_MS (5
   minutes) from its stored expiry; otherwise it refreshes (lib/googleAuth.js)
   and writes the new access token, and a new refresh token only when Google
   sent one, in ONE update guarded by a compare-and-set on token_version. The
   loser of a race writes nothing more, reads the row again and uses the
   winner's token. One refresh per member at a time in this process
   (refreshesInFlight); that is only an optimisation, the compare-and-set is
   what keeps it right. invalid_grant marks the connection needs_reconnect and
   raises ONE in-app notice (the update is conditional on status connected).

   THE UPLOAD, executePublish (the publish_youtube_video executor), on approval
   only. It checks the filed metadata again, the video row and the connection,
   the claims screen, and then:
     - with NO session stored: the 5-in-24-hours cap; the fingerprint, by
       streaming the object from Storage and hashing it (verifyFile); the
       quota (videos.insert, 100 units, lib/youtubeQuota.js, failing closed);
       then the resumable session is started (POST, JSON mode) and its URI is
       SEALED into member_videos.session_* BEFORE the first byte is PUT;
     - with a session stored: a status query FIRST (PUT "bytes *\/N", empty).
       Complete records the video, with no new upload. 308 resumes from the
       Range offset. A session YouTube no longer knows (404 or 410) is cleared,
       and the member files again. NEVER a second insert while a session is
       stored.
     - the bytes go through lib/guardedFetch.js guardedStreamUpload, streamed
       from Storage through fingerprintGuard, which hashes every byte and holds
       the last chunk back until the whole file has matched the filed sha256:
       a file that changed never completes an upload.
     - within one run, ONE resume after an interruption, never two;
     - a failure leaves the session stored and fails the proposal with
       MESSAGES.unfinished, so filing again continues the same upload;
     - complete: youtube_video_id and uploaded_at are recorded and the
       session cleared. NAMED (Nov 7 2026, TikTok posting, migration 178): the
       file is kept and its status stays ready, for TikTok; retention deletes
       it once both platforms have it, or after 14 days. Removing from YouTube
       sets youtube_video_id to null and leaves the file alone.

   Nothing here logs. No token, session URI or code is ever put into an error,
   a result a member sees, or a log line.
   ══════════════════════════════════════════════════════════════════════════ */

const crypto = require("crypto");
const { Transform, pipeline } = require("stream");
const GA = require("./googleAuth");
const MV = require("./memberVideos");
const YQ = require("./youtubeQuota");

const API_BASE = "https://www.googleapis.com/youtube/v3";
const UPLOAD_URL = "https://www.googleapis.com/upload/youtube/v3/videos?uploadType=resumable&part=snippet,status";
const SESSION_PREFIX = "https://www.googleapis.com/upload/";
const REFRESH_MARGIN_MS = 5 * 60 * 1000;
const API_TIMEOUT_MS = 15 * 1000;
const ACTION_UPLOAD = "publish_youtube_video";
const ACTION_DELETE = "delete_youtube_video";
const CHANNEL_ID_RE = /^UC[A-Za-z0-9_-]{22}$/;
const STATUS_COLUMNS = "id, user_id, channel_id, channel_title, status, created_at, last_ok_at, last_error_code";
const SECRET_COLUMNS = "id, user_id, channel_id, channel_title, refresh_ciphertext, refresh_iv, refresh_auth_tag, access_ciphertext, access_iv, access_auth_tag, access_expires_at, token_version, granted_scopes, status, created_at";

const MESSAGES = Object.freeze({
  notConnected: "Connect your YouTube channel first.",
  needsReconnect: "YouTube stopped accepting BizForce's access to your channel, so nothing is being uploaded. Connect again.",
  unfinished: "YouTube upload didn't finish. File the upload again and BizForce will continue the same upload.",
  expired: "That upload expired at YouTube before it finished, so BizForce let it go. File the upload again to start it over.",
  quota: "BizForce has used today's YouTube allowance. Nothing was sent. Try again tomorrow.",
  dailyCap: "You can upload 5 videos to YouTube in 24 hours. Nothing was sent. Try again later.",
  fingerprint: "The video file no longer matches the one you filed, so nothing was sent.",
  channelChanged: "The YouTube channel connected now isn't the one this was filed for. Nothing was sent; file it again.",
  pendingUpload: "This video already has an upload waiting for your approval.",
  pendingDelete: "Removing this video is already waiting for your approval.",
  reused: "This video's earlier upload didn't finish, so this proposal continues it with the title, description, tags and privacy you filed then.",
  notUploaded: "That video isn't on YouTube.",
  gone: "YouTube no longer has this video.",
  unreachable: "YouTube couldn't be reached just now. Nothing changed. Try again later."
});

class YoutubeError extends Error {
  constructor(kind, code) { super("youtube " + kind + " (" + code + ")"); this.name = "YoutubeError"; this.kind = kind; this.code = code; }
}

var refreshesInFlight = new Map();

function nowIso(deps) { return new Date(deps.now()).toISOString(); }
function bearer(token) { return { Authorization: "Bearer " + token }; }
function sealed(crypt, plain) { var s = crypt.encrypt(plain); return { ciphertext: s.ciphertext, iv: s.iv, authTag: s.authTag }; }

/* ── the quota, reserved before every call, failing closed ─────────────── */
async function reserve(deps, method, userId) {
  var caps = YQ.youtubeCaps(deps.env || process.env);
  if (caps.error) throw new YoutubeError("quota", "cap_unusable");
  var units = YQ.YOUTUBE_API_UNITS[method];
  var today;
  try {
    today = await YQ.youtubeUnitsToday(deps.supabase, deps.now());
  } catch (err) {
    throw new YoutubeError("quota", "ledger_unreadable");
  }
  if (today.total + units > caps.daily) throw new YoutubeError("quota", "daily_cap");
  try {
    await YQ.reserveYoutubeUnits(deps.supabase, { method: method, caller: YQ.YOUTUBE_MEMBER_CALLER, user_id: userId }, deps.now());
  } catch (err) {
    throw new YoutubeError("quota", "ledger_unwritable");
  }
  return units;
}

/* ── the connection ─────────────────────────────────────────────────────── */
async function readConnection(supabase, userId) {
  var r = await supabase.from("member_youtube_connections").select(SECRET_COLUMNS).eq("user_id", userId).maybeSingle();
  if (r.error) throw r.error;
  return r.data && r.data.user_id === userId ? r.data : null;
}

function statusOf(row, available) {
  var r = row || null;
  return {
    youtube_available: available === true,
    connected: !!r && r.status === "connected",
    status: r ? r.status : "not_connected",
    channel_title: r ? r.channel_title : null,
    channel_id: r ? r.channel_id : null,
    since: r ? r.created_at : null,
    reconnect_message: r && r.status === "needs_reconnect" ? MESSAGES.needsReconnect : null
  };
}

/* needs_reconnect and ONE notice, only when it was connected. Never throws. */
async function markNeedsReconnect(deps, row, code) {
  try {
    var stamp = nowIso(deps);
    var marked = await deps.supabase.from("member_youtube_connections")
      .update({ status: "needs_reconnect", last_error_at: stamp, last_error_code: String(code || "invalid_grant").slice(0, 60), updated_at: stamp })
      .eq("id", row.id).eq("user_id", row.user_id).eq("status", "connected").select("id");
    if (marked.error || !(marked.data || []).length) return false;
    var notice = await deps.supabase.from("notifications").insert({
      user_id: row.user_id,
      type: "youtube_reconnect",
      title: "Reconnect your YouTube channel",
      // NAMED (Nov 14 2026, L1): the notice no longer names the channel, so no data from Google is kept in it.
      message: "Google stopped accepting BizForce's access to your YouTube channel, so nothing is being uploaded and nothing will be tried again. Connect YouTube again on the Social Agent page.",
      read: false
    });
    if (notice.error) console.warn("[youtube] the reconnect notice could not be saved: " + (notice.error.code || "error"));
    return true;
  } catch (err) {
    return false;
  }
}

function readAccess(deps, row) {
  try {
    return deps.crypt.decrypt({ ciphertext: row.access_ciphertext, iv: row.access_iv, authTag: row.access_auth_tag });
  } catch (err) {
    throw new YoutubeError("auth", "secret_unreadable");
  }
}

async function refreshRow(deps, row) {
  var config = deps.config();
  if (!config) throw new YoutubeError("unreachable", "not_configured");
  // The version this row was read at, taken before Google is asked: the compare-and-set below is against it.
  var version = Number.isInteger(row.token_version) ? row.token_version : 0;
  var refreshToken;
  try {
    refreshToken = deps.crypt.decrypt({ ciphertext: row.refresh_ciphertext, iv: row.refresh_iv, authTag: row.refresh_auth_tag });
  } catch (err) {
    throw new YoutubeError("auth", "secret_unreadable");
  }
  var grant;
  try {
    grant = await GA.refreshTokens(config, refreshToken);
  } catch (err) {
    if (err && err.kind === "invalid_grant") {
      await markNeedsReconnect(deps, row, "invalid_grant");
      throw new YoutubeError("auth", "invalid_grant");
    }
    throw new YoutubeError("unreachable", "token_refresh");
  } finally {
    refreshToken = null;
  }
  var access = sealed(deps.crypt, grant.accessToken);
  var update = {
    access_ciphertext: access.ciphertext, access_iv: access.iv, access_auth_tag: access.authTag,
    access_expires_at: new Date(deps.now() + grant.expiresIn * 1000 - GA.EXPIRY_SLACK_MS).toISOString(),
    token_version: version + 1,
    updated_at: nowIso(deps)
  };
  // Google usually sends no new refresh token: then the stored one stays.
  if (grant.refreshToken) {
    var refresh = sealed(deps.crypt, grant.refreshToken);
    update.refresh_ciphertext = refresh.ciphertext; update.refresh_iv = refresh.iv; update.refresh_auth_tag = refresh.authTag;
  }
  var swapped = await deps.supabase.from("member_youtube_connections").update(update)
    .eq("id", row.id).eq("user_id", row.user_id).eq("token_version", version).select("id");
  if (swapped.error) throw new YoutubeError("unreachable", "token_store");
  if ((swapped.data || []).length === 1) {
    return { token: grant.accessToken, row: Object.assign({}, row, update), refreshedNow: true };
  }
  // Lost the race: nothing more is written. The winner's token is the one to use.
  grant = null;
  var current = await readConnection(deps.supabase, row.user_id);
  if (!current || current.status !== "connected") throw new YoutubeError("auth", "refresh_lost");
  return { token: readAccess(deps, current), row: current, refreshedNow: true };
}

async function accessToken(deps, row, force) {
  if (!row || row.status !== "connected") throw new YoutubeError("auth", "not_connected");
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

/* A JSON-mode call with the access token; a 401 on a token that was not
   refreshed in this call gets ONE forced refresh and ONE more try. */
async function withToken(deps, row, send) {
  var got = await accessToken(deps, row, false);
  var answer = await send(got.token);
  if (answer && answer.status === 401 && !got.refreshedNow) {
    got = await accessToken(deps, got.row, true);
    answer = await send(got.token);
  }
  if (answer && answer.status === 401) {
    await markNeedsReconnect(deps, got.row, "unauthorized");
    throw new YoutubeError("auth", "unauthorized");
  }
  return { answer: answer, token: got.token, row: got.row };
}

async function api(deps, url, options) {
  try {
    return await deps.jsonRequest(url, Object.assign({ timeoutMs: API_TIMEOUT_MS }, options));
  } catch (err) {
    throw new YoutubeError("unreachable", (err && err.code) || "request");
  }
}

/* The channel the token belongs to: { id, title } or null. */
async function readChannel(deps, token) {
  var answer = await api(deps, API_BASE + "/channels?part=snippet&mine=true", { method: "GET", headers: bearer(token) });
  if (answer.status === 401) throw new YoutubeError("auth", "unauthorized");
  if (answer.status < 200 || answer.status >= 300) throw new YoutubeError("unreachable", "channel_status_" + answer.status);
  var items = answer.json && Array.isArray(answer.json.items) ? answer.json.items : [];
  var c = items[0];
  if (!c) return null;
  var title = c.snippet && typeof c.snippet.title === "string" ? c.snippet.title.trim().slice(0, 200) : "";
  if (!CHANNEL_ID_RE.test(String(c.id || "")) || !title) throw new YoutubeError("unreachable", "channel_shape");
  return { id: c.id, title: title };
}

/* ── the upload ─────────────────────────────────────────────────────────── */

/* Hashes every byte that passes and holds the last chunk back until the
   whole file has matched `sha256`; bytes before `skip` are hashed but not
   passed on (a resume). A mismatch errors instead of releasing the last
   chunk, so the upload can never complete. */
function fingerprintGuard(sha256, total, skip) {
  var hash = crypto.createHash("sha256");
  var seen = 0;
  var held = null;
  return new Transform({
    transform: function (chunk, enc, cb) {
      hash.update(chunk);
      var start = seen;
      seen += chunk.length;
      if (seen > total) return cb(new Error("fingerprint"));
      var part = start >= skip ? chunk : (seen > skip ? chunk.subarray(skip - start) : null);
      if (part && part.length) {
        if (held) this.push(held);
        held = Buffer.from(part);
      }
      cb();
    },
    flush: function (cb) {
      if (seen !== total || hash.digest("hex") !== sha256) return cb(new Error("fingerprint"));
      if (held) this.push(held);
      cb();
    }
  });
}

/* The stored object still holds the filed file: streamed and hashed, never held whole. */
async function verifyFile(deps, video) {
  var stream = await MV.openStream(deps.storage, video.path);
  if (!stream) return false;
  var m = await MV.measureStream(stream, MV.MAX_BYTES);
  return !m.tooBig && m.bytes === Number(video.bytes) && m.sha256 === video.sha256;
}

function nextOffset(range) {
  var m = /^bytes=0-(\d+)$/.exec(String(range || "").trim());
  return m ? Number(m[1]) + 1 : 0;
}

async function startSession(deps, token, meta, video) {
  var body = {
    snippet: { title: meta.title, description: meta.description, tags: meta.tags, categoryId: MV.CATEGORY_ID },
    status: { privacyStatus: meta.privacy, selfDeclaredMadeForKids: meta.made_for_kids }
  };
  return api(deps, UPLOAD_URL, {
    method: "POST", body: body, emptyOk: true, exposeHeaders: ["location"],
    headers: Object.assign(bearer(token), { "X-Upload-Content-Type": video.mime, "X-Upload-Content-Length": String(Number(video.bytes)) })
  });
}

function queryUpload(deps, session, token, total) {
  return deps.streamUpload(session, { profile: "youtube", method: "PUT", headers: bearer(token), body: null, contentLength: 0, contentRange: "bytes */" + total });
}

async function sendFrom(deps, session, token, video, offset) {
  var total = Number(video.bytes);
  var source = await MV.openStream(deps.storage, video.path);
  if (!source) throw new YoutubeError("unreachable", "storage_unreadable");
  var guard = fingerprintGuard(video.sha256, total, offset);
  pipeline(source, guard, function () { /* an error reaches the upload through guard */ });
  return deps.streamUpload(session, {
    profile: "youtube",
    method: "PUT",
    headers: Object.assign(bearer(token), { "Content-Type": video.mime }),
    body: guard,
    contentLength: total - offset,
    contentRange: offset > 0 ? "bytes " + offset + "-" + (total - 1) + "/" + total : null
  });
}

function complete(answer) {
  return answer && (answer.status === 200 || answer.status === 201) && answer.json && typeof answer.json === "object";
}

async function clearSession(deps, video) {
  await deps.supabase.from("member_videos").update({ session_ciphertext: null, session_iv: null, session_auth_tag: null })
    .eq("id", video.id).eq("user_id", video.user_id);
}

/* Records a finished upload. Returns the result.
   NAMED (Nov 7 2026, TikTok posting, migration 178): the file is NOT deleted
   here any more and the status stays the file's (ready): the same video may
   still go to TikTok. lib/memberVideos.js retentionTick deletes the file once
   YouTube and TikTok both have it, or 14 days after it was added. */
async function record(deps, video, answer, meta, channelTitle) {
  var id = answer.json.id;
  if (!MV.YOUTUBE_ID_RE.test(String(id || ""))) {
    throw new Error("publish_youtube_video: YouTube finished the upload but answered with no video id. Check YouTube Studio before filing it again.");
  }
  var at = nowIso(deps);
  var done = await deps.supabase.from("member_videos").update({
    youtube_video_id: id, uploaded_at: at, session_ciphertext: null, session_iv: null, session_auth_tag: null
  }).eq("id", video.id).eq("user_id", video.user_id).select("id");
  if (done.error || (done.data || []).length !== 1) {
    throw new Error("publish_youtube_video: the video WAS uploaded, at " + MV.youtubeUrl(id) + ", but it could not be recorded. Don't file it again.");
  }
  return { youtube_video_id: id, url: MV.youtubeUrl(id), privacy: meta.privacy, channel: channelTitle, uploaded_at: at };
}

/* Sends from offset, with at most ONE resume after an interruption in this run.
   resumed: whether the run's one resume is already spent (a stored session). */
async function sendWithResume(deps, session, token, video, offset, resumed) {
  var total = Number(video.bytes);
  for (;;) {
    var answer = null;
    try {
      answer = await sendFrom(deps, session, token, video, offset);
    } catch (err) {
      if (err && err.code === "body_failed") throw new Error("publish_youtube_video: " + MESSAGES.fingerprint);
      answer = null;
    }
    if (complete(answer)) return answer;
    var interrupted = answer === null || answer.status === 308 || answer.status >= 500;
    if (!interrupted || resumed) return null;
    resumed = true;
    var q;
    try { q = await queryUpload(deps, session, token, total); } catch (err) { return null; }
    if (complete(q)) return q;
    if (q.status !== 308) return null;
    offset = nextOffset(q.headers && q.headers.range);
  }
}

function payloadMeta(p) {
  return { title: p.title, description: p.description, tags: p.tags, privacy: p.privacy, made_for_kids: p.made_for_kids };
}

/* The publish_youtube_video executor. One argument, the claimed proposal. */
async function executePublish(deps, proposal) {
  var fail = function (why) { return new Error("publish_youtube_video: " + why); };
  var p = proposal && proposal.payload && typeof proposal.payload === "object" ? proposal.payload : {};
  var ownerId = proposal && proposal.user_id;
  var checked = MV.validateMetadata(payloadMeta(p), deps.limits);
  if (!checked.ok) throw fail(checked.error + " Nothing was sent.");
  var meta = checked.value;
  if (p.category_id !== MV.CATEGORY_ID) throw fail("the category is not the one BizForce files. Nothing was sent.");
  ["title", "description"].forEach(function (f) {
    var refused = meta[f] ? deps.claims(meta[f]) : null;
    if (refused) throw fail(refused.error + " Nothing was sent.");
  });
  var video = await MV.readVideo(deps.supabase, ownerId, p.video_id);
  if (!video) throw fail(MV.MESSAGES.notFound + " Nothing was sent.");
  // NAMED (Nov 7 2026, TikTok posting): the YouTube id says YouTube has it, whatever the file's status.
  /* NAMED (Nov 13 2026, S3): a filed repost (repost: true) goes on only while the stored id is still the one it was
     filed against (repost_of). Once the new upload is recorded the id changes, so approving it again is "already
     uploaded", as before. */
  var reposting = p.repost === true && !!video.youtube_video_id && typeof p.repost_of === "string" && video.youtube_video_id === p.repost_of;
  if (video.youtube_video_id && !reposting) {
    return { already_uploaded: true, youtube_video_id: video.youtube_video_id, url: MV.youtubeUrl(video.youtube_video_id), uploaded_at: video.uploaded_at };
  }
  if (video.status !== "ready" || !video.path) throw fail("that video is no longer waiting to be uploaded. Nothing was sent.");
  if (video.sha256 !== p.sha256 || Number(video.bytes) !== Number(p.bytes) || video.mime !== p.mime) throw fail(MESSAGES.fingerprint);
  var conn = await readConnection(deps.supabase, ownerId);
  if (!conn) throw fail(MESSAGES.notConnected + " Nothing was sent.");
  if (conn.status !== "connected") throw fail(MESSAGES.needsReconnect);
  if (conn.channel_id !== p.channel_id) throw fail(MESSAGES.channelChanged);

  var got;
  try {
    got = await accessToken(deps, conn, false);
  } catch (err) {
    throw fail(err && err.kind === "auth" ? MESSAGES.needsReconnect : MESSAGES.unreachable);
  }
  var token = got.token;
  var finished = null;

  if (video.session_ciphertext) {
    // A stored session: ask YouTube first. Never a second insert while one is stored.
    var session;
    try {
      session = deps.crypt.decrypt({ ciphertext: video.session_ciphertext, iv: video.session_iv, authTag: video.session_auth_tag });
    } catch (err) {
      throw fail(MESSAGES.unfinished);
    }
    try {
      await reserve(deps, "uploads.status", ownerId);
    } catch (err) {
      throw fail(MESSAGES.quota);
    }
    var q;
    try {
      q = await queryUpload(deps, session, token, Number(video.bytes));
    } catch (err) {
      throw fail(MESSAGES.unfinished);
    }
    if (complete(q)) {
      finished = q;
    } else if (q.status === 308) {
      if (!(await verifyFile(deps, video))) throw fail(MESSAGES.fingerprint);
      finished = await sendWithResume(deps, session, token, video, nextOffset(q.headers && q.headers.range), true);
    } else if (q.status === 404 || q.status === 410) {
      await clearSession(deps, video);
      throw fail(MESSAGES.expired);
    }
    session = null;
    if (!finished) throw fail(MESSAGES.unfinished);
    return record(deps, video, finished, meta, conn.channel_title);
  }

  // A new upload.
  var since = new Date(deps.now() - 24 * 60 * 60 * 1000).toISOString();
  var counted = await deps.supabase.from("member_videos").select("id", { count: "exact", head: true }).eq("user_id", ownerId).gte("uploaded_at", since);
  if (counted.error) throw fail(MESSAGES.unreachable);
  if ((counted.count || 0) >= MV.UPLOADS_PER_DAY) throw fail(MESSAGES.dailyCap);
  if (!(await verifyFile(deps, video))) throw fail(MESSAGES.fingerprint);
  try {
    await reserve(deps, "videos.insert", ownerId);
  } catch (err) {
    throw fail(MESSAGES.quota);
  }
  var started;
  try {
    started = await startSession(deps, token, meta, video);
    if (started.status === 401 && !got.refreshedNow) {
      got = await accessToken(deps, got.row, true);
      token = got.token;
      started = await startSession(deps, token, meta, video);
    }
  } catch (err) {
    throw fail(err && err.kind === "auth" ? MESSAGES.needsReconnect : "YouTube couldn't be reached to start the upload. Nothing was sent.");
  }
  if (started.status === 401) { await markNeedsReconnect(deps, got.row, "unauthorized"); throw fail(MESSAGES.needsReconnect); }
  var location = started.headers && started.headers.location;
  if (started.status < 200 || started.status >= 300 || typeof location !== "string" || location.indexOf(SESSION_PREFIX) !== 0) {
    throw fail("YouTube didn't start the upload (" + started.status + "). Nothing was sent.");
  }
  // Sealed BEFORE the first byte: a crash from here on leaves a session to continue, never a second insert.
  var s = sealed(deps.crypt, location);
  var stored = await deps.supabase.from("member_videos").update({ session_ciphertext: s.ciphertext, session_iv: s.iv, session_auth_tag: s.authTag })
    .eq("id", video.id).eq("user_id", ownerId).eq("status", "ready").is("session_ciphertext", null).select("id");
  if (stored.error || (stored.data || []).length !== 1) throw fail("the upload couldn't be recorded before sending, so nothing was sent.");
  finished = await sendWithResume(deps, location, token, video, 0, false);
  location = null;
  if (!finished) throw fail(MESSAGES.unfinished);
  return record(deps, video, finished, meta, conn.channel_title);
}

/* The delete_youtube_video executor. */
async function executeDelete(deps, proposal) {
  var fail = function (why) { return new Error("delete_youtube_video: " + why); };
  var p = proposal && proposal.payload && typeof proposal.payload === "object" ? proposal.payload : {};
  var ownerId = proposal && proposal.user_id;
  var video = await MV.readVideo(deps.supabase, ownerId, p.video_id);
  if (!video) throw fail(MV.MESSAGES.notFound + " Nothing was removed.");
  // NAMED (Nov 7 2026, TikTok posting): removed from YouTube means youtube_video_id is null; the file's status is not YouTube's.
  if (!video.youtube_video_id) return { already_removed: true, youtube_video_id: p.youtube_video_id };
  if (video.youtube_video_id !== p.youtube_video_id || !MV.YOUTUBE_ID_RE.test(String(p.youtube_video_id || ""))) {
    throw fail(MESSAGES.notUploaded + " Nothing was removed.");
  }
  var conn = await readConnection(deps.supabase, ownerId);
  if (!conn) throw fail(MESSAGES.notConnected + " Nothing was removed.");
  if (conn.status !== "connected") throw fail(MESSAGES.needsReconnect);
  if (conn.channel_id !== p.channel_id) throw fail(MESSAGES.channelChanged);
  try {
    await reserve(deps, "videos.delete", ownerId);
  } catch (err) {
    throw fail(MESSAGES.quota);
  }
  var out;
  try {
    out = await withToken(deps, conn, function (token) {
      return api(deps, API_BASE + "/videos?id=" + encodeURIComponent(p.youtube_video_id), { method: "DELETE", headers: bearer(token), emptyOk: true });
    });
  } catch (err) {
    throw fail(err && err.kind === "auth" ? MESSAGES.needsReconnect : MESSAGES.unreachable);
  }
  var status = out.answer.status;
  if (status !== 204 && status !== 200 && status !== 404) throw fail("YouTube refused to remove it (" + status + "). Nothing changed.");
  var at = nowIso(deps);
  // NAMED (Nov 7 2026, TikTok posting): only YouTube's id is cleared; the file and the TikTok side are untouched (the proposal keeps the history).
  var u = await deps.supabase.from("member_videos").update({ youtube_video_id: null })
    .eq("id", video.id).eq("user_id", ownerId).eq("youtube_video_id", p.youtube_video_id).select("id");
  if (u.error) throw fail("it was removed from YouTube, but the record could not be updated.");
  return { removed: true, youtube_video_id: p.youtube_video_id, already_gone: status === 404, removed_at: at };
}

/* GET /api/youtube/videos/:id/status. { status, body }. */
async function videoStatus(deps, userId, id) {
  var video = await MV.readVideo(deps.supabase, userId, id);
  if (!video) return { status: 404, body: { error: MV.MESSAGES.notFound, code: "not_found" } };
  if (!video.youtube_video_id) return { status: 409, body: { error: MESSAGES.notUploaded, code: "not_uploaded" } };
  var conn = await readConnection(deps.supabase, userId);
  if (!conn) return { status: 409, body: { error: MESSAGES.notConnected, code: "not_connected" } };
  if (conn.status !== "connected") return { status: 409, body: { error: MESSAGES.needsReconnect, code: "needs_reconnect" } };
  try {
    await reserve(deps, "videos.list", userId);
  } catch (err) {
    return { status: 503, body: { error: MESSAGES.quota, code: "quota" } };
  }
  var out;
  try {
    out = await withToken(deps, conn, function (token) {
      return api(deps, API_BASE + "/videos?part=status,processingDetails&id=" + encodeURIComponent(video.youtube_video_id), { method: "GET", headers: bearer(token) });
    });
  } catch (err) {
    if (err && err.kind === "auth") return { status: 409, body: { error: MESSAGES.needsReconnect, code: "needs_reconnect" } };
    return { status: 502, body: { error: MESSAGES.unreachable, code: "unreachable" } };
  }
  var a = out.answer;
  if (a.status < 200 || a.status >= 300) return { status: 502, body: { error: MESSAGES.unreachable, code: "unreachable" } };
  var item = a.json && Array.isArray(a.json.items) ? a.json.items[0] : null;
  if (!item) return { status: 200, body: { found: false, message: MESSAGES.gone, url: MV.youtubeUrl(video.youtube_video_id) } };
  var st = item.status || {}, pd = item.processingDetails || {};
  function word(v) { return typeof v === "string" && /^[A-Za-z]{1,40}$/.test(v) ? v : null; }
  return { status: 200, body: {
    found: true, url: MV.youtubeUrl(video.youtube_video_id),
    upload_status: word(st.uploadStatus), privacy_status: word(st.privacyStatus), processing_status: word(pd.processingStatus)
  } };
}

/* ── filing ─────────────────────────────────────────────────────────────── */

async function connectedOr(deps, userId) {
  var conn = await readConnection(deps.supabase, userId);
  if (!conn) return { error: { status: 409, body: { error: MESSAGES.notConnected, code: "not_connected" } } };
  if (conn.status !== "connected") return { error: { status: 409, body: { error: MESSAGES.needsReconnect, code: "needs_reconnect" } } };
  return { conn: conn };
}

/* The most recent upload proposal filed for this video, of any status. */
async function lastUploadProposal(supabase, userId, videoId) {
  var r = await supabase.from("agent_proposals").select("id, payload, created_at").eq("user_id", userId).eq("action_type", ACTION_UPLOAD)
    .order("created_at", { ascending: false }).limit(200);
  if (r.error) throw r.error;
  var mine = (r.data || []).filter(function (x) { return x.payload && x.payload.video_id === videoId; });
  mine.sort(function (a, b) { return String(b.created_at).localeCompare(String(a.created_at)); });
  return mine[0] || null;
}

/* POST /api/youtube/propose-upload. { status, body }. Files; never runs it. */
async function proposeUpload(deps, userId, input) {
  var b = input || {};
  var c = await connectedOr(deps, userId);
  if (c.error) return c.error;
  var video = await MV.readVideo(deps.supabase, userId, b.video_id);
  if (!video) return { status: 404, body: { error: MV.MESSAGES.notFound, code: "not_found" } };
  if (video.status !== "ready" || !video.path) return { status: 409, body: { error: "That video is not waiting to be uploaded.", code: "not_ready" } };
  // NAMED (Nov 7 2026, TikTok posting): the file stays after a YouTube upload, so "ready" no longer means "not on YouTube".
  /* NAMED (Nov 13 2026, S3, "Post again"): a video already on YouTube is filed again ONLY when the request says
     repost: true (exactly true), which the Social page sends after the member confirms "Post again". Without it the
     answer is 409 already_uploaded, as before. Every other rule stands: one pending upload per video, the file,
     the metadata rules and the claims screen. The payload names the YouTube id it was filed against (repost_of). */
  var repost = b.repost === true && !!video.youtube_video_id;
  if (video.youtube_video_id && !repost) return { status: 409, body: { error: "That video is already on YouTube.", code: "already_uploaded" } };
  if ((await MV.proposalsNaming(deps.supabase, userId, video.id, [ACTION_UPLOAD])).length) {
    return { status: 409, body: { error: MESSAGES.pendingUpload, code: "pending" } };
  }
  var meta, reused = false;
  if (video.session_ciphertext) {
    var prior = await lastUploadProposal(deps.supabase, userId, video.id);
    if (prior) {
      var again = MV.validateMetadata(payloadMeta(prior.payload), deps.limits);
      if (again.ok) { meta = again.value; reused = true; }
    }
  }
  if (!meta) {
    var checked = MV.validateMetadata(b, deps.limits);
    if (!checked.ok) return { status: 400, body: { error: checked.error + " Nothing was filed.", code: "invalid", field: checked.field } };
    meta = checked.value;
  }
  var fields = ["title", "description"];
  for (var i = 0; i < fields.length; i++) {
    var refused = meta[fields[i]] ? deps.claims(meta[fields[i]]) : null;
    if (refused) return { status: 422, body: { error: refused.error + " Nothing was filed.", code: "claims", field: fields[i], violations: refused.violations } };
  }
  var payload = {
    video_id: video.id, sha256: video.sha256, bytes: Number(video.bytes), mime: video.mime,
    title: meta.title, description: meta.description, tags: meta.tags, privacy: meta.privacy, made_for_kids: meta.made_for_kids,
    category_id: MV.CATEGORY_ID, channel_id: c.conn.channel_id
  };
  if (repost) { payload.repost = true; payload.repost_of = video.youtube_video_id; }
  var ins = await deps.supabase.from("agent_proposals").insert({
    user_id: userId, agent_type: "social", action_type: ACTION_UPLOAD,
    title: ((repost ? "Upload to YouTube again (" : "Upload to YouTube (") + meta.privacy + "): " + meta.title).slice(0, 200),
    target: "youtube", payload: payload, cost_amount: 0, cost_currency: "USD", reversible: false,
    status: "pending", created_at: nowIso(deps)
  }).select("*").single();
  if (ins.error) throw ins.error;
  var note = "Filed for approval. Nothing has been sent to YouTube. Approving it on the proposals page uploads this video" + (repost ? " again" : "") + " to " +
    c.conn.channel_title + " as " + meta.privacy + ".";
  if (reused) note += " " + MESSAGES.reused;
  return { status: 201, body: { proposal: ins.data, reused_earlier_details: reused, note: note } };
}

/* POST /api/youtube/videos/:id/propose-delete. { status, body }. */
async function proposeDelete(deps, userId, id) {
  var c = await connectedOr(deps, userId);
  if (c.error) return c.error;
  var video = await MV.readVideo(deps.supabase, userId, id);
  if (!video) return { status: 404, body: { error: MV.MESSAGES.notFound, code: "not_found" } };
  if (!video.youtube_video_id) return { status: 409, body: { error: MESSAGES.notUploaded, code: "not_uploaded" } };
  if ((await MV.proposalsNaming(deps.supabase, userId, video.id, [ACTION_DELETE])).length) {
    return { status: 409, body: { error: MESSAGES.pendingDelete, code: "pending" } };
  }
  var ins = await deps.supabase.from("agent_proposals").insert({
    user_id: userId, agent_type: "social", action_type: ACTION_DELETE,
    title: ("Remove from YouTube: " + (video.label || video.youtube_video_id)).slice(0, 200),
    target: "youtube", payload: { video_id: video.id, youtube_video_id: video.youtube_video_id, channel_id: c.conn.channel_id },
    cost_amount: 0, cost_currency: "USD", reversible: false, status: "pending", created_at: nowIso(deps)
  }).select("*").single();
  if (ins.error) throw ins.error;
  return { status: 201, body: { proposal: ins.data, note: "Filed for approval. Nothing has changed on YouTube. Approving it removes the video from " + c.conn.channel_title + "." } };
}

/* ── Google's user data rules, in code (L1, Nov 14 2026) ──────────────────
   What BizForce keeps from Google for a member's YouTube connection
   ("authorized data"): the connection row (the channel's name and id and the
   sealed tokens), the YouTube id and upload time on member_videos, an
   unfinished upload's sealed session, and the YouTube proposals (their
   payload names the channel id, their result the video's address). The
   Privacy Policy, section 9 part A, states these rules:
     - DISCONNECT (POST /api/youtube/disconnect): the token is revoked at
       Google, then purgeYoutubeData deletes all of it at once.
     - A GRANT GOOGLE REFUSES (invalid_grant): youtubeDataTick, daily in the
       04:45 UTC chain, claimed through job_runs youtube_data_check, asks
       Google for a fresh token for every connection; a refusal marks the
       connection (ONE notice, markNeedsReconnect's) and purges its data.
     - 30 DAYS: the channel's name is read again from YouTube by the same
       pass once it is CHANNEL_REFRESH_DAYS old; a connection that has not
       been refreshed for AUTHORIZED_DATA_DAYS is purged; a video's YouTube
       fields and a YouTube proposal older than AUTHORIZED_DATA_DAYS are
       cleared or deleted, and so are those of a member with no connection.
   KEPT, because it holds no channel data: youtube_api_calls, the daily quota
   ledger (method, units, time and the member's id). An upload proposal that
   is executing when the member disconnects is left to finish failing, and
   the next daily pass deletes it. */
const AUTHORIZED_DATA_DAYS = 30;
const CHANNEL_REFRESH_DAYS = 7;
/* What the Privacy Policy promises after a disconnect. The delete itself is at once; only an upload proposal that
   was executing at that moment waits, and the next daily pass deletes it. */
const DISCONNECT_PROMISE_DAYS = 7;
const DATA_CHECK_JOB_NAME = "youtube_data_check";
const DATA_CHECK_MAX = 500;
const DAY_MS = 24 * 60 * 60 * 1000;

/* Deletes the member's YouTube authorized data. opts.notices also deletes the
   member's YouTube reconnect notices (on their own disconnect). Throws on a
   database error, so the caller can say the disconnect is not finished. */
async function purgeYoutubeData(deps, userId, opts) {
  var o = opts || {};
  var sb = deps.supabase;
  var out = { connection: 0, videos: 0, proposals: 0, notices: 0, states: 0 };
  var conn = await sb.from("member_youtube_connections").delete().eq("user_id", userId).select("id");
  if (conn.error) throw conn.error;
  out.connection = (conn.data || []).length;
  var states = await sb.from("oauth_states").delete().eq("user_id", userId).eq("purpose", GA.PURPOSE).select("id");
  if (states.error) throw states.error;
  out.states = (states.data || []).length;
  var vids = await sb.from("member_videos").update({ youtube_video_id: null, uploaded_at: null, session_ciphertext: null, session_iv: null, session_auth_tag: null })
    .eq("user_id", userId).select("id");
  if (vids.error) throw vids.error;
  out.videos = (vids.data || []).length;
  var props = await sb.from("agent_proposals").select("id, status").eq("user_id", userId).in("action_type", [ACTION_UPLOAD, ACTION_DELETE]);
  if (props.error) throw props.error;
  var doomed = (props.data || []).filter(function (p) { return p.status !== "executing"; }).map(function (p) { return p.id; });
  if (doomed.length) {
    var gone = await sb.from("agent_proposals").delete().eq("user_id", userId).in("id", doomed).select("id");
    if (gone.error) throw gone.error;
    out.proposals = (gone.data || []).length;
  }
  if (o.notices) {
    var notes = await sb.from("notifications").delete().eq("user_id", userId).eq("type", "youtube_reconnect").select("id");
    if (notes.error) throw notes.error;
    out.notices = (notes.data || []).length;
  }
  return out;
}

function olderThan(iso, nowMs, days) {
  var t = Date.parse(iso || "");
  return !isFinite(t) || nowMs - t > days * DAY_MS;
}

/* One connection in the daily pass: "purged", "refreshed", "kept" or "skipped". */
async function checkOneConnection(deps, row, nowMs, result) {
  var lastOk = row.last_ok_at || row.created_at;
  var stale = olderThan(lastOk, nowMs, AUTHORIZED_DATA_DAYS);
  var config = deps.config();
  var refused = false;
  var token = null;
  if (config) {
    if (row.status === "connected") {
      try {
        token = (await accessToken(deps, row, true)).token;
      } catch (err) {
        refused = !!(err && err.code === "invalid_grant");
      }
    } else {
      var plain = null;
      try {
        plain = deps.crypt.decrypt({ ciphertext: row.refresh_ciphertext, iv: row.refresh_iv, authTag: row.refresh_auth_tag });
        await GA.refreshTokens(config, plain);
      } catch (err) {
        refused = !!(err && err.kind === "invalid_grant");
      } finally {
        plain = null;
      }
    }
  }
  if (refused) {
    // markNeedsReconnect sends the ONE notice, and only when the connection was still connected.
    await markNeedsReconnect(deps, row, "invalid_grant");
    await purgeYoutubeData(deps, row.user_id, {});
    result.refused++;
    return "purged";
  }
  if (token && olderThan(lastOk, nowMs, CHANNEL_REFRESH_DAYS)) {
    try {
      await reserve(deps, "channels.list", row.user_id);
      var channel = await readChannel(deps, token);
      if (channel && channel.id === row.channel_id) {
        var at = new Date(nowMs).toISOString();
        var u = await deps.supabase.from("member_youtube_connections").update({ channel_title: channel.title, last_ok_at: at, updated_at: at })
          .eq("id", row.id).eq("user_id", row.user_id).select("id");
        if (!u.error && (u.data || []).length) { result.refreshed++; return "refreshed"; }
      }
    } catch (err) { /* not refreshed today; the 30-day rule below decides */ }
  } else if (token) {
    return "kept";
  }
  if (stale) {
    await purgeYoutubeData(deps, row.user_id, {});
    result.stale++;
    return "purged";
  }
  return "kept";
}

/* The daily pass. Never rejects. */
async function youtubeDataTick(deps, nowMs) {
  var claim = require("./dailyClaim");
  var startedMs = typeof nowMs === "number" ? nowMs : deps.now();
  var result = { claimed: true, checked: 0, refused: 0, stale: 0, refreshed: 0, videos: 0, proposals: 0, error: null };
  try {
    if (!(await claim.claimToday(deps.supabase, DATA_CHECK_JOB_NAME, startedMs))) return { claimed: false };
    var conns = await deps.supabase.from("member_youtube_connections").select(SECRET_COLUMNS + ", last_ok_at").limit(DATA_CHECK_MAX);
    if (conns.error) throw new Error("member_youtube_connections could not be read");
    var connected = {};
    for (var i = 0; i < (conns.data || []).length; i++) {
      var row = conns.data[i];
      result.checked++;
      var what = await checkOneConnection(deps, row, startedMs, result);
      if (what !== "purged") connected[row.user_id] = true;
    }
    var cutoff = new Date(startedMs - AUTHORIZED_DATA_DAYS * DAY_MS).toISOString();
    // A video's YouTube fields: cleared 30 days after the upload, or at once when its member has no connection.
    var vids = await deps.supabase.from("member_videos").select("id, user_id, uploaded_at").not("youtube_video_id", "is", null).limit(DATA_CHECK_MAX);
    if (vids.error) throw new Error("member_videos could not be read");
    var clearIds = (vids.data || []).filter(function (v) { return !connected[v.user_id] || olderThan(v.uploaded_at, startedMs, AUTHORIZED_DATA_DAYS); })
      .map(function (v) { return v.id; });
    if (clearIds.length) {
      var cleared = await deps.supabase.from("member_videos").update({ youtube_video_id: null, uploaded_at: null }).in("id", clearIds).select("id");
      if (cleared.error) throw new Error("member_videos could not be cleared");
      result.videos += (cleared.data || []).length;
    }
    // An unfinished upload's sealed session: cleared 30 days after the video was added, or at once when its member has no connection.
    var sess = await deps.supabase.from("member_videos").select("id, user_id, created_at").not("session_ciphertext", "is", null).limit(DATA_CHECK_MAX);
    if (sess.error) throw new Error("member_videos could not be read");
    var sessIds = (sess.data || []).filter(function (v) { return !connected[v.user_id] || olderThan(v.created_at, startedMs, AUTHORIZED_DATA_DAYS); })
      .map(function (v) { return v.id; });
    if (sessIds.length) {
      var unsealed = await deps.supabase.from("member_videos").update({ session_ciphertext: null, session_iv: null, session_auth_tag: null }).in("id", sessIds).select("id");
      if (unsealed.error) throw new Error("member_videos sessions could not be cleared");
      result.videos += (unsealed.data || []).length;
    }
    // A YouTube proposal: deleted 30 days after it was filed, or at once when its member has no connection; never while executing.
    var props = await deps.supabase.from("agent_proposals").select("id, user_id, status, created_at").in("action_type", [ACTION_UPLOAD, ACTION_DELETE]).limit(DATA_CHECK_MAX);
    if (props.error) throw new Error("agent_proposals could not be read");
    var dropIds = (props.data || []).filter(function (p) {
      return p.status !== "executing" && (!connected[p.user_id] || String(p.created_at || "") < cutoff);
    }).map(function (p) { return p.id; });
    if (dropIds.length) {
      var dropped = await deps.supabase.from("agent_proposals").delete().in("id", dropIds).select("id");
      if (dropped.error) throw new Error("agent_proposals could not be deleted");
      result.proposals += (dropped.data || []).length;
    }
    await claim.recordFinish(deps.supabase, DATA_CHECK_JOB_NAME, deps.now(), null);
    console.log("[YoutubeDataCheck] Pass finished: " + result.checked + " connection(s) checked, " + result.refused + " refused by Google and deleted, " +
      result.stale + " deleted after " + AUTHORIZED_DATA_DAYS + " days without a refresh, " + result.refreshed + " channel name(s) refreshed, " +
      result.videos + " video record(s) and " + result.proposals + " proposal(s) cleared.");
    return result;
  } catch (err) {
    var message = (err && err.message) || "error";
    console.error("[YoutubeDataCheck] Pass error: " + message);
    await claim.recordFinish(deps.supabase, DATA_CHECK_JOB_NAME, deps.now(), message);
    return { claimed: true, error: message };
  }
}

module.exports = {
  AUTHORIZED_DATA_DAYS: AUTHORIZED_DATA_DAYS,
  CHANNEL_REFRESH_DAYS: CHANNEL_REFRESH_DAYS,
  DISCONNECT_PROMISE_DAYS: DISCONNECT_PROMISE_DAYS,
  DATA_CHECK_JOB_NAME: DATA_CHECK_JOB_NAME,
  purgeYoutubeData: purgeYoutubeData,
  youtubeDataTick: youtubeDataTick,
  API_BASE: API_BASE,
  UPLOAD_URL: UPLOAD_URL,
  SESSION_PREFIX: SESSION_PREFIX,
  REFRESH_MARGIN_MS: REFRESH_MARGIN_MS,
  ACTION_UPLOAD: ACTION_UPLOAD,
  ACTION_DELETE: ACTION_DELETE,
  CHANNEL_ID_RE: CHANNEL_ID_RE,
  STATUS_COLUMNS: STATUS_COLUMNS,
  SECRET_COLUMNS: SECRET_COLUMNS,
  MESSAGES: MESSAGES,
  YoutubeError: YoutubeError,
  reserve: reserve,
  readConnection: readConnection,
  statusOf: statusOf,
  markNeedsReconnect: markNeedsReconnect,
  accessToken: accessToken,
  readChannel: readChannel,
  fingerprintGuard: fingerprintGuard,
  nextOffset: nextOffset,
  executePublish: executePublish,
  executeDelete: executeDelete,
  videoStatus: videoStatus,
  proposeUpload: proposeUpload,
  proposeDelete: proposeDelete
};
