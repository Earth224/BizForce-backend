"use strict";

/* ══════════════════════════════════════════════════════════════════════════
   VIDEOS FOR YOUTUBE (migration 177): the private bucket bf-video and the
   member_videos rows that record each file.

   HOW A VIDEO GETS IN. Never through the server's memory:
     1. POST /api/videos/upload-url { mime, bytes, label }: the type and size
        are checked, at most READY_MAX videos may wait, and a Storage signed
        upload URL is made for a fresh path video/<user id>/<32 hex>.<ext>.
        The browser PUTs the file straight to it.
     2. POST /api/videos/finalize { path, label, bytes }: the object is READ AS
        A STREAM (storage-js download(path).asStream(), whose body is a web
        ReadableStream that Readable.fromWeb turns into a Node stream). Its
        first bytes are sniffed (SNIFF below), its bytes counted and its sha256
        hashed as they pass; nothing is ever held whole. It must be at most
        MAX_BYTES, exactly the size the browser declared, and the type its
        path's extension names. Any mismatch deletes the object and answers
        422. Only then is the row written, status ready.
   WHAT HAPPENS NEXT is lib/youtubeApi.js: an approved upload proposal streams
   the object again, checks the fingerprint, and sends it to YouTube (and
   lib/tiktokApi.js the same for TikTok). The object is deleted by
   retentionTick, as the NAMED paragraph below says, and an object with no
   row after ORPHAN_MS.
   NAMED (Nov 7 2026, TikTok posting, migration 178): one video can go to
   YouTube AND TikTok (lib/tiktokApi.js), so status now describes the FILE:
     ready     the file is here;
     uploaded  the file was deleted after at least one platform got it;
     removed   the file was deleted without any platform getting it.
   What each platform has is youtube_video_id and uploaded_at (YouTube) and
   the tiktok_* columns. Neither executor deletes the file any more:
   retentionTick deletes it once YouTube has it AND TikTok has posted it and
   no pending proposal names it, or READY_DAYS after it was added. The ready
   cap counts files and is shared; each platform keeps its own 5 in 24 hours
   (uploaded_at for YouTube, tiktok_posted_at for TikTok).

   THE SNIFF TABLE (the build brief's decision 3):
     MP4   "ftyp" at byte 4, brand isom, iso2, iso4, iso5, iso6, mp41, mp42,
           avc1, dash or "M4V "                                  video/mp4
     MOV   "ftyp" at byte 4, brand "qt  "                         video/quicktime
     WebM  EBML 1A 45 DF A3, DocType "webm" in the first 64 bytes video/webm
   HEIC and HEIF brands (heic, heix, hevc, hevx, heim, heis, mif1, msf1, avif)
   are refused, and so is every brand not listed.

   NOTHING HERE TALKS TO THE NETWORK by itself: the Supabase client and its
   storage are passed in (deps), so scripts/checkYoutubeUploads.js runs all of
   it against stubs. Nothing here logs a path's signed URL or token.
   ══════════════════════════════════════════════════════════════════════════ */

const crypto = require("crypto");
const { Readable } = require("stream");

const BUCKET = "bf-video";
const MAX_BYTES = 50 * 1024 * 1024;
const READY_MAX = 2;
const UPLOADS_PER_DAY = 5;
// NAMED (Nov 7 2026, TikTok posting): TikTok's own cap, counted by tiktok_posted_at.
const TIKTOK_POSTS_PER_DAY = 5;
// The proposals that need the file: while one is pending or running, retention keeps it and Delete refuses.
const FILE_ACTIONS = Object.freeze(["publish_youtube_video", "delete_youtube_video", "publish_tiktok_post"]);
const TIKTOK_POST_ID_RE = /^[0-9]{1,64}$/;
const READY_DAYS = 14;
const ORPHAN_MS = 24 * 60 * 60 * 1000;
const LABEL_MAX = 120;
const SNIFF_BYTES = 64;
const LIST_MAX = 50;
const PAGE_SIZE = 1000;
const MAX_PAGES = 100;
const REMOVE_BATCH = 100;
const RETENTION_JOB_NAME = "member_videos_retention";

const TYPES = Object.freeze({ mp4: "video/mp4", webm: "video/webm", mov: "video/quicktime" });
const EXTENSIONS = Object.freeze({ "video/mp4": "mp4", "video/webm": "webm", "video/quicktime": "mov" });
const MP4_BRANDS = ["isom", "iso2", "iso4", "iso5", "iso6", "mp41", "mp42", "avc1", "dash", "M4V "];
const MOV_BRAND = "qt  ";
const REFUSED_BRANDS = ["heic", "heix", "hevc", "hevx", "heim", "heis", "mif1", "msf1", "avif"];

/* The same pattern as migration 177's member_videos_path_check. */
const PATH_RE = /^video\/[0-9a-f-]{36}\/[0-9a-f]{32}\.(mp4|webm|mov)$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const PRIVACY = ["private", "unlisted", "public"];
const CATEGORY_ID = "22";
const YOUTUBE_ID_RE = /^[A-Za-z0-9_-]{11}$/;

const MESSAGES = Object.freeze({
  limits: "Videos up to 50 MB (MP4, WebM or MOV).",
  kept: "BizForce deletes the file once every platform you sent it to has it, or 14 days after you added it.",
  privateUntilVerified: "Until Google approves BizForce, YouTube keeps uploads from BizForce private.",
  unsupported: "That file type isn't supported. Use MP4, WebM or MOV.",
  mismatch: "That file isn't the type it says it is, so it was deleted.",
  tooBig: "A video is at most 50 MB, so it was deleted.",
  sizeMismatch: "That file isn't the size the browser said it was, so it was deleted.",
  badSize: "Say the video's size in bytes, from 1 to 52428800.",
  badLabel: "A label is text of at most 120 characters.",
  badPath: "That isn't a video upload BizForce made for you.",
  notUploaded: "The file hasn't reached storage yet. Upload it, then try again.",
  already: "That video is already in your list.",
  readyCap: "You have 2 videos waiting. Upload or delete one first.",
  notFound: "That video isn't in your list.",
  notReady: "Only a video waiting to be uploaded can be deleted here.",
  inProposal: "A proposal waiting for your approval names this video. Reject it first.",
  unreadable: "The video couldn't be read from storage just now. Try again.",
  stored: "The video couldn't be stored. Try again.",
  removeFailed: "The video file couldn't be deleted just now, so nothing changed. Try again.",
  title: "A title is 1 to 100 characters, without < or >.",
  description: "A description is at most 5000 bytes, without < or >.",
  tags: "Tags are a list of words, without < > or commas, 500 characters in all.",
  privacy: "Privacy is private, unlisted or public.",
  kids: "Answer \"Made for kids?\" with Yes or No."
});

class VideoRefused extends Error {
  constructor(status, code, message) { super(message); this.name = "VideoRefused"; this.status = status; this.code = code; }
}

function ascii(buf, a, b) { return buf.length >= b ? Buffer.from(buf).toString("latin1", a, b) : ""; }

/* What a file's first bytes say it is: mp4, mov, webm or null. */
function sniffVideo(buf) {
  if (!buf || buf.length < 12) return null;
  if (ascii(buf, 4, 8) === "ftyp") {
    var brand = ascii(buf, 8, 12);
    if (REFUSED_BRANDS.indexOf(brand) !== -1) return null;
    if (brand === MOV_BRAND) return "mov";
    return MP4_BRANDS.indexOf(brand) !== -1 ? "mp4" : null;
  }
  if (buf[0] === 0x1a && buf[1] === 0x45 && buf[2] === 0xdf && buf[3] === 0xa3) return webmDocType(buf) === "webm" ? "webm" : null;
  return null;
}

/* The EBML header's DocType (element 0x4282) within the first 64 bytes. */
function webmDocType(buf) {
  var end = Math.min(buf.length, SNIFF_BYTES);
  for (var i = 4; i + 3 <= end; i++) {
    if (buf[i] !== 0x42 || buf[i + 1] !== 0x82) continue;
    var len = buf[i + 2];
    if (!(len & 0x80)) return null;
    len = len & 0x7f;
    if (i + 3 + len > end) return null;
    return ascii(buf, i + 3, i + 3 + len);
  }
  return null;
}

function extOf(path) { var m = PATH_RE.exec(String(path || "")); return m ? m[1] : null; }
function pathOwned(path, userId) {
  return typeof path === "string" && PATH_RE.test(path) && UUID_RE.test(String(userId)) && path.indexOf("video/" + userId + "/") === 0;
}
function newPath(userId, ext, randomBytes) {
  return "video/" + userId + "/" + (randomBytes || crypto.randomBytes)(16).toString("hex") + "." + ext;
}
function youtubeUrl(id) { return YOUTUBE_ID_RE.test(String(id || "")) ? "https://www.youtube.com/watch?v=" + id : null; }
/* TikTok's embed player address for a post id: it needs no username. */
function tiktokUrl(id) { return TIKTOK_POST_ID_RE.test(String(id || "")) ? "https://www.tiktok.com/player/v1/" + id : null; }
/* Has any platform got this video? YouTube has its id; TikTok has posted it. */
function platformGot(row) { return !!(row && (row.youtube_video_id || row.tiktok_status === "posted")); }
/* What deleting the file writes: the status by whether any platform got it, and
   everything that needed the file cleared. A TikTok upload still waiting for its
   bytes can never finish without the file, so it is failed and let go. */
function fileGonePatch(row) {
  var patch = { status: platformGot(row) ? "uploaded" : "removed", path: null, session_ciphertext: null, session_iv: null, session_auth_tag: null,
    tiktok_upload_ciphertext: null, tiktok_upload_iv: null, tiktok_upload_auth_tag: null, tiktok_upload_expires_at: null };
  if (row && row.tiktok_status === "initiated") { patch.tiktok_status = "failed"; patch.tiktok_publish_id = null; }
  return patch;
}

/* The object as a Node stream, read straight from Storage: never a Blob or an
   ArrayBuffer. A web ReadableStream (what storage-js hands back) is wrapped
   with Readable.fromWeb; a Node stream passes through. */
async function openStream(storage, path) {
  var got = await storage.from(BUCKET).download(path).asStream();
  if (!got || got.error || !got.data) return null;
  var body = got.data;
  if (typeof body.getReader === "function") return Readable.fromWeb(body);
  if (typeof body.on === "function" && typeof body.pipe === "function") return body;
  return null;
}

/* Counts and hashes a stream as it passes, keeping only its first 64 bytes.
   { bytes, sha256, head } or { tooBig: true } (the stream is then destroyed). */
async function measureStream(readable, maxBytes) {
  var hash = crypto.createHash("sha256");
  var bytes = 0;
  var head = [];
  var headLen = 0;
  for await (const chunk of readable) {
    bytes += chunk.length;
    if (bytes > maxBytes) {
      if (typeof readable.destroy === "function") readable.destroy();
      return { tooBig: true, bytes: bytes };
    }
    hash.update(chunk);
    if (headLen < SNIFF_BYTES) {
      var part = chunk.subarray(0, SNIFF_BYTES - headLen);
      head.push(Buffer.from(part));
      headLen += part.length;
    }
  }
  return { bytes: bytes, sha256: hash.digest("hex"), head: Buffer.concat(head) };
}

async function readyCount(supabase, userId) {
  var r = await supabase.from("member_videos").select("id", { count: "exact", head: true }).eq("user_id", userId).eq("status", "ready");
  if (r.error) throw r.error;
  return r.count || 0;
}

function labelOf(v) {
  if (v === undefined || v === null) return { ok: true, value: "" };
  if (typeof v !== "string") return { ok: false };
  var s = v.trim();
  return Array.from(s).length <= LABEL_MAX ? { ok: true, value: s } : { ok: false };
}

function sizeOf(v) {
  return typeof v === "number" && Number.isInteger(v) && v >= 1 && v <= MAX_BYTES ? v : null;
}

/* POST /api/videos/upload-url. { status, body }. */
async function uploadUrl(deps, userId, input) {
  var b = input || {};
  var ext = typeof b.mime === "string" ? EXTENSIONS[b.mime] : undefined;
  if (!ext) return { status: 400, body: { error: MESSAGES.unsupported, code: "unsupported", field: "mime" } };
  if (typeof b.bytes === "number" && Number.isInteger(b.bytes) && b.bytes > MAX_BYTES) {
    return { status: 413, body: { error: "A video is at most 50 MB.", code: "too_big", field: "bytes" } };
  }
  if (sizeOf(b.bytes) === null) return { status: 400, body: { error: MESSAGES.badSize, code: "bad_size", field: "bytes" } };
  if (!labelOf(b.label).ok) return { status: 400, body: { error: MESSAGES.badLabel, code: "bad_label", field: "label" } };
  if (await readyCount(deps.supabase, userId) >= READY_MAX) return { status: 409, body: { error: MESSAGES.readyCap, code: "ready_cap" } };
  var path = newPath(userId, ext, deps.randomBytes);
  var signed = await deps.storage.from(BUCKET).createSignedUploadUrl(path);
  if (!signed || signed.error || !signed.data || typeof signed.data.signedUrl !== "string") {
    return { status: 503, body: { error: "The upload couldn't be prepared just now. Try again.", code: "storage" } };
  }
  return { status: 200, body: { upload_url: signed.data.signedUrl, path: path, mime: TYPES[ext], max_bytes: MAX_BYTES } };
}

async function removeObject(storage, path) {
  try {
    var r = await storage.from(BUCKET).remove([path]);
    return !(r && r.error);
  } catch (err) {
    return false;
  }
}

/* POST /api/videos/finalize. { status, body }. */
async function finalize(deps, userId, input) {
  var b = input || {};
  var path = b.path;
  if (!pathOwned(path, userId)) return { status: 400, body: { error: MESSAGES.badPath, code: "bad_path", field: "path" } };
  var label = labelOf(b.label);
  if (!label.ok) return { status: 400, body: { error: MESSAGES.badLabel, code: "bad_label", field: "label" } };
  var declared = sizeOf(b.bytes);
  if (declared === null) return { status: 400, body: { error: MESSAGES.badSize, code: "bad_size", field: "bytes" } };
  var existing = await deps.supabase.from("member_videos").select("id").eq("path", path).maybeSingle();
  if (existing.error) throw existing.error;
  if (existing.data) return { status: 409, body: { error: MESSAGES.already, code: "already" } };
  if (await readyCount(deps.supabase, userId) >= READY_MAX) return { status: 409, body: { error: MESSAGES.readyCap, code: "ready_cap" } };

  var stream = await openStream(deps.storage, path);
  if (!stream) return { status: 404, body: { error: MESSAGES.notUploaded, code: "not_uploaded" } };
  var m;
  try {
    m = await measureStream(stream, MAX_BYTES);
  } catch (err) {
    return { status: 503, body: { error: MESSAGES.unreadable, code: "unreadable" } };
  }
  var refusal = null;
  if (m.tooBig) refusal = { status: 422, code: "too_big", error: MESSAGES.tooBig };
  else {
    var sniffed = sniffVideo(m.head);
    if (!sniffed) refusal = { status: 422, code: "unsupported", error: MESSAGES.unsupported + " It was deleted." };
    else if (sniffed !== extOf(path)) refusal = { status: 422, code: "mismatch", error: MESSAGES.mismatch };
    else if (m.bytes !== declared) refusal = { status: 422, code: "size_mismatch", error: MESSAGES.sizeMismatch };
  }
  if (refusal) {
    await removeObject(deps.storage, path);
    return { status: refusal.status, body: { error: refusal.error, code: refusal.code, deleted: true } };
  }
  var ins = await deps.supabase.from("member_videos").insert({
    user_id: userId, path: path, mime: TYPES[extOf(path)], bytes: m.bytes, sha256: m.sha256, label: label.value,
    status: "ready", created_at: new Date(deps.now()).toISOString()
  }).select("*").single();
  if (ins.error) {
    if (ins.error.code === "23505") return { status: 409, body: { error: MESSAGES.already, code: "already" } };
    throw ins.error;
  }
  return { status: 201, body: { video: publicView(ins.data) } };
}

/* What a member sees of a row: never the path, the fingerprint or the session. */
function publicView(row) {
  var r = row || {};
  return {
    id: r.id, label: r.label || "", bytes: Number(r.bytes) || 0, mime: r.mime, status: r.status,
    youtube_video_id: r.youtube_video_id || null, youtube_url: youtubeUrl(r.youtube_video_id),
    uploaded_at: r.uploaded_at || null, created_at: r.created_at || null,
    upload_unfinished: r.status === "ready" && !!r.session_ciphertext,
    // NAMED (Nov 7 2026, TikTok posting): TikTok's side. Never the publish id's upload address.
    tiktok_status: r.tiktok_status || null, tiktok_posted_at: r.tiktok_posted_at || null, tiktok_post_url: tiktokUrl(r.tiktok_post_id),
    tiktok_upload_unfinished: r.status === "ready" && r.tiktok_status === "initiated"
  };
}

const ROW_COLUMNS = "id, user_id, path, mime, bytes, sha256, label, status, youtube_video_id, session_ciphertext, session_iv, session_auth_tag, uploaded_at, created_at, " +
  "tiktok_publish_id, tiktok_status, tiktok_posted_at, tiktok_post_id, tiktok_upload_ciphertext, tiktok_upload_iv, tiktok_upload_auth_tag, tiktok_upload_expires_at";

async function listVideos(deps, userId) {
  var r = await deps.supabase.from("member_videos").select(ROW_COLUMNS).eq("user_id", userId).in("status", ["ready", "uploaded"])
    .order("created_at", { ascending: false }).limit(LIST_MAX);
  if (r.error) throw r.error;
  return (r.data || []).filter(function (row) { return row.user_id === userId; }).map(publicView);
}

async function readVideo(supabase, userId, id) {
  if (typeof id !== "string" || !UUID_RE.test(id)) return null;
  var r = await supabase.from("member_videos").select(ROW_COLUMNS).eq("id", id).eq("user_id", userId).maybeSingle();
  if (r.error) throw r.error;
  return r.data && r.data.user_id === userId ? r.data : null;
}

/* The member's pending (or running) proposals that name this video. */
async function proposalsNaming(supabase, userId, videoId, actionTypes) {
  var r = await supabase.from("agent_proposals").select("id, action_type, status, payload, created_at").eq("user_id", userId)
    .in("action_type", actionTypes).in("status", ["pending", "executing"]);
  if (r.error) throw r.error;
  return (r.data || []).filter(function (p) { return p.payload && p.payload.video_id === videoId; });
}

/* DELETE /api/videos/:id. { status, body }. */
async function deleteVideo(deps, userId, id) {
  var row = await readVideo(deps.supabase, userId, id);
  if (!row) return { status: 404, body: { error: MESSAGES.notFound, code: "not_found" } };
  if (row.status !== "ready") return { status: 409, body: { error: MESSAGES.notReady, code: "not_ready" } };
  // NAMED (Nov 7 2026, TikTok posting): a pending YouTube OR TikTok proposal blocks it.
  var naming = await proposalsNaming(deps.supabase, userId, row.id, FILE_ACTIONS.slice());
  if (naming.length) return { status: 409, body: { error: MESSAGES.inProposal, code: "in_proposal" } };
  if (row.path && !(await removeObject(deps.storage, row.path))) return { status: 503, body: { error: MESSAGES.removeFailed, code: "remove_failed" } };
  var u = await deps.supabase.from("member_videos").update(fileGonePatch(row))
    .eq("id", row.id).eq("user_id", userId).eq("status", "ready").select("id");
  if (u.error) throw u.error;
  return { status: 200, body: { deleted: true, id: row.id } };
}

/* ── the upload's metadata, measured against server.js's SOCIAL_SEARCH_LIMITS.youtube ── */
function codePoints(s) { return Array.from(String(s)).length; }
function tagsTotal(tags) { return tags.reduce(function (n, t) { return n + codePoints(t); }, 0) + Math.max(0, tags.length - 1); }

/* { ok: true, value } or { ok: false, error, field }. limits is
   SOCIAL_SEARCH_LIMITS.youtube (title_max, description_max_bytes, tags_max_total). */
function validateMetadata(input, limits) {
  var b = input || {};
  var L = limits || {};
  if (typeof b.title !== "string") return { ok: false, error: MESSAGES.title, field: "title" };
  var title = b.title.trim();
  if (!title || codePoints(title) > L.title_max || /[<>]/.test(title)) return { ok: false, error: MESSAGES.title, field: "title" };
  var description = b.description === undefined || b.description === null ? "" : b.description;
  if (typeof description !== "string") return { ok: false, error: MESSAGES.description, field: "description" };
  description = description.trim();
  if (Buffer.byteLength(description, "utf8") > L.description_max_bytes || /[<>]/.test(description)) return { ok: false, error: MESSAGES.description, field: "description" };
  var tags = b.tags === undefined || b.tags === null ? [] : b.tags;
  if (!Array.isArray(tags) || tags.length > 500) return { ok: false, error: MESSAGES.tags, field: "tags" };
  var clean = [];
  for (var i = 0; i < tags.length; i++) {
    if (typeof tags[i] !== "string") return { ok: false, error: MESSAGES.tags, field: "tags" };
    var t = tags[i].trim();
    if (!t || /[<>,]/.test(t)) return { ok: false, error: MESSAGES.tags, field: "tags" };
    clean.push(t);
  }
  if (tagsTotal(clean) > L.tags_max_total) return { ok: false, error: MESSAGES.tags, field: "tags" };
  var privacy = b.privacy === undefined || b.privacy === null || b.privacy === "" ? "private" : b.privacy;
  if (PRIVACY.indexOf(privacy) === -1) return { ok: false, error: MESSAGES.privacy, field: "privacy" };
  if (typeof b.made_for_kids !== "boolean") return { ok: false, error: MESSAGES.kids, field: "made_for_kids" };
  return { ok: true, value: { title: title, description: description, tags: clean, privacy: privacy, made_for_kids: b.made_for_kids, category_id: CATEGORY_ID } };
}

/* For a draft: how each field measures, in code. */
function measureMetadata(m, limits) {
  var L = limits || {};
  var title = String((m && m.title) || ""), description = String((m && m.description) || "");
  var tags = Array.isArray(m && m.tags) ? m.tags.map(String) : [];
  return {
    title: { length: codePoints(title), limit: L.title_max, within_limit: codePoints(title) <= L.title_max && codePoints(title) >= 1 && !/[<>]/.test(title) },
    description: { bytes: Buffer.byteLength(description, "utf8"), limit_bytes: L.description_max_bytes, within_limit: Buffer.byteLength(description, "utf8") <= L.description_max_bytes && !/[<>]/.test(description) },
    tags: { total: tagsTotal(tags), limit: L.tags_max_total, within_limit: tagsTotal(tags) <= L.tags_max_total && tags.every(function (t) { return t && !/[<>,]/.test(t); }) }
  };
}

/* ── retention, in the 04:45 UTC chain, claimed through its own job_runs row ──
   1. a ready video READY_DAYS after it was added: the object, then the row is
      status uploaded (a platform got it) or removed, with path null;
   1b. a ready video YouTube has and TikTok has posted, named by no pending or
      running proposal: the object, then status uploaded, path null;
   2. an uploaded video whose object is still there: the object, then path null;
   3. an object in bf-video with no row, ORPHAN_MS old: the object.
   Never rejects. */
async function claimDay(supabase, nowMs) {
  var today = new Date(nowMs).toISOString().slice(0, 10);
  var started = new Date(nowMs).toISOString();
  var inserted = await supabase.from("job_runs")
    .insert({ job_name: RETENTION_JOB_NAME, last_run_on: today, started_at: started, finished_at: null, last_error: null }).select("job_name");
  if (!inserted.error) return true;
  if (inserted.error.code !== "23505") {
    console.error("[VideoRetention] Claim insert failed: " + (inserted.error.code || "error"));
    return false;
  }
  var updated = await supabase.from("job_runs").update({ last_run_on: today, started_at: started, finished_at: null, last_error: null })
    .eq("job_name", RETENTION_JOB_NAME).or("last_run_on.is.null,last_run_on.neq." + today).select("job_name");
  if (updated.error) {
    console.error("[VideoRetention] Claim update failed: " + (updated.error.code || "error"));
    return false;
  }
  return (updated.data || []).length > 0;
}

async function listAll(storage, prefix) {
  var out = [];
  for (var page = 0; page < MAX_PAGES; page++) {
    var r = await storage.from(BUCKET).list(prefix, { limit: PAGE_SIZE, offset: page * PAGE_SIZE });
    if (r.error) throw new Error(BUCKET + " could not be listed");
    var items = r.data || [];
    out = out.concat(items);
    if (items.length < PAGE_SIZE) return out;
  }
  throw new Error(BUCKET + " holds more than " + (MAX_PAGES * PAGE_SIZE) + " entries under one folder");
}

async function removeMany(storage, paths) {
  var gone = [];
  for (var i = 0; i < paths.length; i += REMOVE_BATCH) {
    var batch = paths.slice(i, i + REMOVE_BATCH);
    var r = await storage.from(BUCKET).remove(batch);
    if (!r || !r.error) gone = gone.concat(batch);
  }
  return gone;
}

async function retentionTick(deps, nowMs) {
  var supabase = deps.supabase, storage = deps.storage;
  var startedMs = typeof nowMs === "number" ? nowMs : deps.now();
  var result = { claimed: true, expired: 0, both: 0, leftovers: 0, orphans: 0, error: null };
  async function finish(errorMessage) {
    var patch = { finished_at: new Date(deps.now()).toISOString() };
    if (errorMessage) patch.last_error = String(errorMessage).slice(0, 2000);
    var r = await supabase.from("job_runs").update(patch).eq("job_name", RETENTION_JOB_NAME);
    if (r.error) console.error("[VideoRetention] Failed to record run completion: " + (r.error.code || "error"));
  }
  try {
    if (!(await claimDay(supabase, startedMs))) return { claimed: false };
    // 1. ready videos READY_DAYS after they were added: whatever any platform has, the file goes
    var cutoff = new Date(startedMs - READY_DAYS * 24 * 60 * 60 * 1000).toISOString();
    var stale = await supabase.from("member_videos").select("id, user_id, path, youtube_video_id, tiktok_status").eq("status", "ready").lt("created_at", cutoff).limit(PAGE_SIZE);
    if (stale.error) throw new Error("member_videos could not be read");
    var staleRows = (stale.data || []).filter(function (r) { return r.path; });
    var staleGone = await removeMany(storage, staleRows.map(function (r) { return r.path; }));
    for (var i = 0; i < staleRows.length; i++) {
      if (staleGone.indexOf(staleRows[i].path) === -1) continue;
      var u = await supabase.from("member_videos").update(fileGonePatch(staleRows[i]))
        .eq("id", staleRows[i].id).eq("status", "ready").select("id");
      if (!u.error) result.expired += (u.data || []).length;
    }
    /* 1b. NAMED (Nov 7 2026, TikTok posting): a ready video YouTube has AND TikTok
       has posted, that no pending or running proposal names: its file goes now. */
    var held = await supabase.from("agent_proposals").select("payload").in("action_type", FILE_ACTIONS.slice()).in("status", ["pending", "executing"]);
    if (held.error) throw new Error("agent_proposals could not be read");
    var named = {};
    (held.data || []).forEach(function (p) { if (p.payload && typeof p.payload.video_id === "string") named[p.payload.video_id] = true; });
    var both = await supabase.from("member_videos").select("id, user_id, path, youtube_video_id, tiktok_status").eq("status", "ready")
      .not("youtube_video_id", "is", null).eq("tiktok_status", "posted").limit(PAGE_SIZE);
    if (both.error) throw new Error("member_videos could not be read");
    var bothRows = (both.data || []).filter(function (r) { return r.path && !named[r.id]; });
    var bothGone = await removeMany(storage, bothRows.map(function (r) { return r.path; }));
    for (var b = 0; b < bothRows.length; b++) {
      if (bothGone.indexOf(bothRows[b].path) === -1) continue;
      var w = await supabase.from("member_videos").update(fileGonePatch(bothRows[b]))
        .eq("id", bothRows[b].id).eq("status", "ready").select("id");
      if (!w.error) result.both += (w.data || []).length;
    }
    // 2. an uploaded video's leftover object
    var left = await supabase.from("member_videos").select("id, path").eq("status", "uploaded").not("path", "is", null).limit(PAGE_SIZE);
    if (left.error) throw new Error("member_videos could not be read");
    var leftRows = (left.data || []).filter(function (r) { return r.path; });
    var leftGone = await removeMany(storage, leftRows.map(function (r) { return r.path; }));
    for (var j = 0; j < leftRows.length; j++) {
      if (leftGone.indexOf(leftRows[j].path) === -1) continue;
      var v = await supabase.from("member_videos").update({ path: null }).eq("id", leftRows[j].id).eq("status", "uploaded").select("id");
      if (!v.error) result.leftovers += (v.data || []).length;
    }
    // 3. objects with no row, ORPHAN_MS old
    var orphanCutoff = startedMs - ORPHAN_MS;
    var folders = (await listAll(storage, "video")).filter(function (it) { return it && it.name && UUID_RE.test(it.name) && (it.id === null || it.id === undefined); });
    for (var k = 0; k < folders.length; k++) {
      var owner = folders[k].name;
      var files = (await listAll(storage, "video/" + owner)).filter(function (it) { return it && it.name && it.id; });
      if (!files.length) continue;
      var known = await supabase.from("member_videos").select("path").eq("user_id", owner);
      if (known.error) throw new Error("member_videos could not be read");
      var paths = (known.data || []).map(function (r) { return r.path; }).filter(Boolean);
      var orphans = files.filter(function (f) {
        var key = "video/" + owner + "/" + f.name;
        var made = Date.parse(f.created_at || "");
        return paths.indexOf(key) === -1 && isFinite(made) && made < orphanCutoff;
      }).map(function (f) { return "video/" + owner + "/" + f.name; });
      result.orphans += (await removeMany(storage, orphans)).length;
    }
    await finish(null);
    console.log("[VideoRetention] Pass finished: " + result.expired + " video file(s) older than " + READY_DAYS + " days, " +
      result.both + " file(s) both YouTube and TikTok have, " +
      result.leftovers + " leftover file(s) of uploaded videos, and " + result.orphans + " file(s) with no record deleted.");
    return result;
  } catch (err) {
    var message = (err && err.message) || "error";
    console.error("[VideoRetention] Pass error: " + message);
    try { await finish(message); } catch (finishErr) { /* reported above */ }
    return { claimed: true, error: message };
  }
}

module.exports = {
  BUCKET: BUCKET,
  MAX_BYTES: MAX_BYTES,
  READY_MAX: READY_MAX,
  UPLOADS_PER_DAY: UPLOADS_PER_DAY,
  TIKTOK_POSTS_PER_DAY: TIKTOK_POSTS_PER_DAY,
  FILE_ACTIONS: FILE_ACTIONS,
  TIKTOK_POST_ID_RE: TIKTOK_POST_ID_RE,
  tiktokUrl: tiktokUrl,
  platformGot: platformGot,
  fileGonePatch: fileGonePatch,
  READY_DAYS: READY_DAYS,
  ORPHAN_MS: ORPHAN_MS,
  LABEL_MAX: LABEL_MAX,
  TYPES: TYPES,
  EXTENSIONS: EXTENSIONS,
  MP4_BRANDS: MP4_BRANDS,
  MOV_BRAND: MOV_BRAND,
  REFUSED_BRANDS: REFUSED_BRANDS,
  PATH_RE: PATH_RE,
  UUID_RE: UUID_RE,
  PRIVACY: PRIVACY,
  CATEGORY_ID: CATEGORY_ID,
  YOUTUBE_ID_RE: YOUTUBE_ID_RE,
  RETENTION_JOB_NAME: RETENTION_JOB_NAME,
  ROW_COLUMNS: ROW_COLUMNS,
  MESSAGES: MESSAGES,
  VideoRefused: VideoRefused,
  sniffVideo: sniffVideo,
  extOf: extOf,
  pathOwned: pathOwned,
  newPath: newPath,
  youtubeUrl: youtubeUrl,
  openStream: openStream,
  measureStream: measureStream,
  removeObject: removeObject,
  uploadUrl: uploadUrl,
  finalize: finalize,
  publicView: publicView,
  listVideos: listVideos,
  readVideo: readVideo,
  proposalsNaming: proposalsNaming,
  deleteVideo: deleteVideo,
  validateMetadata: validateMetadata,
  measureMetadata: measureMetadata,
  retentionTick: retentionTick
};
