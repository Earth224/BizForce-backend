"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   THE DIRECT-UPLOAD CHECK (P2-2, Nov 20 2026; the P2-0 defect "uploads are
   unchecked"). POST /api/bfp/upload-url hands the browser a signed URL to the
   public bucket, so the bytes never pass through the server. Two checks,
   with the limits and sniffing the libraries already use:

   1. When the URL is issued (checkDeclared): the declared size (required) and
      type must fit the folder. What each folder holds is what its pages upload
      today (KINDS): card-media a picture, a video or audio (the card's
      background, still, pitch video and audio); marketplace-media a picture or
      a video (listings and campaigns); videos a video; music audio; every other
      folder a picture. Pictures: JPEG, PNG, WebP or GIF. Video: MP4, WebM or
      QuickTime (a phone's .mov, which the card's pitch video has always taken).
      Audio: the music library's types (MP3, M4A/AAC, Ogg, Opus, FLAC, WAV).
      At most the bucket's 10 MB (the media library's MAX_FILE_BYTES), and the
      music folder the music library's FILE_MAX_BYTES (25 MB).
   2. After the upload (POST /api/bfp/upload-check, checkStored): the stored
      file is read back and SNIFFED (lib/memberMedia.js sniffMedia, lib/music.js
      sniffAudio) and measured; a file that is not what it said, or is too big,
      is deleted and refused. The pages call it before they save the link.
   ══════════════════════════════════════════════════════════════════════════ */
const media = require("./memberMedia");
const music = require("./music");

const IMAGE_EXTS = ["jpg", "png", "webp", "gif"];
const VIDEO_EXTS = ["mp4", "webm", "mov"];
const FOLDERS = ["marketplace-media", "card-media", "banners", "avatars", "videos", "music", "music-art", "products", "portfolio"];
const KINDS = { "card-media": ["image", "video", "audio"], "marketplace-media": ["image", "video"], videos: ["video"], music: ["audio"] };
const MIMES = {
  image: IMAGE_EXTS.map(function (e) { return media.TYPES[e].mime; }),
  video: ["video/mp4", "video/webm", "video/quicktime"],
  audio: music.MIMES.concat(["audio/mp3", "audio/x-wav", "audio/wave", "audio/x-m4a", "audio/x-flac"])
};
const NAMES = { image: "JPEG, PNG, WebP or GIF", video: "MP4, WebM or MOV", audio: "MP3, M4A, AAC, Ogg, Opus, FLAC or WAV" };

function kindsOf(folder) { return KINDS[folder] || ["image"]; }
function kindOf(folder) { return kindsOf(folder)[0]; }
function limitOf(folder) { return folder === "music" ? music.FILE_MAX_BYTES : media.MAX_FILE_BYTES; }
function mb(n) { return Math.round(n / (1024 * 1024)) + " MB"; }

function allowedMimes(folder) {
  return kindsOf(folder).reduce(function (all, k) { return all.concat(MIMES[k]); }, []);
}
/* The stored bytes' kind: "image", "video" or "audio", or null. QuickTime (an "ftyp" box of brand "qt  ") is a video here;
   the media library refuses it, this check does not. */
function sniffKind(buf) {
  var t = media.sniffMedia(buf);
  if (IMAGE_EXTS.indexOf(t) !== -1) return "image";
  if (t === "mp4" || t === "webm") return "video";
  if (buf.length >= 12 && buf.toString("latin1", 4, 8) === "ftyp" && buf.toString("latin1", 8, 12) === "qt  ") return "video";
  if (music.sniffAudio(buf)) return "audio";
  return null;
}

const MESSAGES = {
  size: "Send the file's size in bytes.",
  tooBig: function (folder) { return "A file here is at most " + mb(limitOf(folder)) + "."; },
  type: function (folder) {
    return "That file type isn't supported here. Use " + kindsOf(folder).map(function (k) { return NAMES[k]; }).join(", or ") + ".";
  },
  mismatch: "That file isn't the type it says it is, so it was deleted.",
  notYours: "That upload isn't yours to check.",
  missing: "That upload wasn't found. Try uploading again."
};

/* At issue: { contentType, limit } or { status, error, reason }. */
function checkDeclared(folder, contentType, size) {
  var n = Number(size);
  if (!Number.isFinite(n) || n <= 0 || Math.floor(n) !== n) return { status: 400, error: MESSAGES.size, reason: "size" };
  if (n > limitOf(folder)) return { status: 413, error: MESSAGES.tooBig(folder), reason: "too_big" };
  var ct = String(contentType || "").toLowerCase().trim();
  if (allowedMimes(folder).indexOf(ct) === -1) return { status: 415, error: MESSAGES.type(folder), reason: "type" };
  return { contentType: ct, limit: limitOf(folder) };
}

/* The path an upload of this member's may have: <folder>/<their id>/<name>. */
function ownPath(path, userId) {
  var p = String(path || "");
  var parts = p.split("/");
  return parts.length === 3 && FOLDERS.indexOf(parts[0]) !== -1 && parts[1] === userId && /^[0-9]+_[a-zA-Z0-9._-]{1,120}$/.test(parts[2]) ? parts[0] : null;
}

/* After the upload: the stored bytes. { ok } or { status, error, reason }. */
function checkStored(folder, buf) {
  if (!buf || !buf.length) return { status: 400, error: MESSAGES.missing, reason: "missing" };
  if (buf.length > limitOf(folder)) return { status: 413, error: MESSAGES.tooBig(folder), reason: "too_big" };
  var kind = sniffKind(buf);
  if (!kind || kindsOf(folder).indexOf(kind) === -1) return { status: 415, error: MESSAGES.mismatch, reason: "mismatch" };
  return { ok: true, type: kind };
}

module.exports = { FOLDERS, IMAGE_EXTS, VIDEO_EXTS, KINDS, MIMES, MESSAGES, kindOf, kindsOf, limitOf, allowedMimes, sniffKind, checkDeclared, ownPath, checkStored };
