/* ══════════════════════════════════════════════════════════════════════════
   lib/music.js — a member's own music library: the files they upload, the
   playlists they build from them, and the rules both are held to
   (migration 155). The player is the frontend's scripts/bf-music.js.

   THE FILES. Private, in the bf-music bucket, at `<member id>/<time>-<random>.<ext>`:
   the member's own folder, which lib/accountFiles.js lists and removes with
   the account. Never a public URL: the player is handed a signed URL that
   expires after SIGNED_URL_SECONDS and asks for a fresh one when it does.

   WHAT IS ACCEPTED is decided by the file's first bytes, never by its name or
   the type the browser declared (sniffAudio): MP3, M4A/AAC, Ogg, Opus, FLAC
   or WAV. At most FILE_MAX_BYTES each, and at most MEMBER_TOTAL_BYTES across
   the member's whole library.

   STORAGE PLAN. The repo states no Supabase plan or storage quota anywhere
   (no config, no code), and nothing here asks Supabase. Supabase's published
   plans: Free holds 1 GB of files with a 50 MB per-file upload limit; Pro
   holds 100 GB, then bills per GB. So 25 MB per file sits under every plan's
   per-file limit, and 250 MB per member means four full libraries fill the
   Free plan: on Free, lower MEMBER_TOTAL_BYTES or move to Pro before members
   upload in earnest.

   WHAT IS STORED about a track: its title (the file's own tag when it has
   one, else the file name), the artist (its tag, optional), the duration (read
   from a WAV or FLAC header, else what the member's browser measured), the
   type and size, and when it was added. Title and artist can be edited.

   NOTHING HERE TALKS TO THE DATABASE OR THE NETWORK: pure functions, so
   scripts/checkMusicPlayer.js runs all of it directly.
   ══════════════════════════════════════════════════════════════════════════ */

var BUCKET = "bf-music";
var FILE_MAX_BYTES = 25 * 1024 * 1024;
var MEMBER_TOTAL_BYTES = 250 * 1024 * 1024;
var SIGNED_URL_SECONDS = 600;
var TITLE_MAX = 200;
var ARTIST_MAX = 200;
var PLAYLIST_NAME_MAX = 80;
var PLAYLIST_MAX_TRACKS = 500;
var MAX_PLAYLISTS = 50;
var DURATION_MAX = 24 * 60 * 60;
var UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/* Each kind of file, the extension it is stored under and the type it is
   served as. */
var TYPES = {
  mp3:  { mime: "audio/mpeg", label: "MP3" },
  m4a:  { mime: "audio/mp4", label: "M4A" },
  aac:  { mime: "audio/aac", label: "AAC" },
  ogg:  { mime: "audio/ogg", label: "Ogg" },
  opus: { mime: "audio/ogg", label: "Opus" },
  flac: { mime: "audio/flac", label: "FLAC" },
  wav:  { mime: "audio/wav", label: "WAV" }
};
var EXTS = Object.keys(TYPES);
var MIMES = EXTS.map(function (e) { return TYPES[e].mime; }).filter(function (m, i, all) { return all.indexOf(m) === i; });

function ascii(buf, a, b) { return buf.length >= b ? buf.toString("latin1", a, b) : ""; }

/* What a file's first bytes say it is: one of EXTS, or null. */
function sniffAudio(buf) {
  if (!buf || buf.length < 12) return null;
  if (ascii(buf, 0, 4) === "fLaC") return "flac";
  if (ascii(buf, 0, 4) === "RIFF" && ascii(buf, 8, 12) === "WAVE") return "wav";
  if (ascii(buf, 0, 4) === "OggS") {
    var head = ascii(buf, 0, Math.min(buf.length, 512));
    return head.indexOf("OpusHead") !== -1 ? "opus" : "ogg";
  }
  if (ascii(buf, 4, 8) === "ftyp") {
    var brand = ascii(buf, 8, 12);
    return /^(M4A |M4B |M4P |mp42|mp41|isom|iso2|dash|MSNV|3gp|NDAS|f4a )/.test(brand) || brand.indexOf("3gp") === 0 ? "m4a" : null;
  }
  var at = 0;
  if (ascii(buf, 0, 3) === "ID3") {
    // A real ID3v2 header: version 2 … 4, and a size of four 7-bit bytes.
    if (buf[3] < 2 || buf[3] > 4 || buf[4] === 0xff || (buf[6] | buf[7] | buf[8] | buf[9]) & 0x80) return null;
    var tagSize = ((buf[6] & 0x7f) << 21) | ((buf[7] & 0x7f) << 14) | ((buf[8] & 0x7f) << 7) | (buf[9] & 0x7f);
    at = 10 + tagSize + ((buf[5] & 0x10) ? 10 : 0);
    // An ID3 tag is followed by MPEG frames, or (rarely) by ADTS AAC: the
    // whole file is here, so a tag with no audio after it is not music.
  }
  return frameAt(buf, at);
}
/* An MPEG audio frame header (MP3) or an ADTS header (AAC) at `at`. */
function frameAt(buf, at) {
  if (at + 4 > buf.length || buf[at] !== 0xff) return null;
  var b1 = buf[at + 1], b2 = buf[at + 2];
  if ((b1 & 0xf6) === 0xf0) return "aac";            // ADTS: sync, layer 00
  if ((b1 & 0xe0) !== 0xe0) return null;
  var version = (b1 >> 3) & 3, layer = (b1 >> 1) & 3;
  var bitrate = (b2 >> 4) & 0xf, rate = (b2 >> 2) & 3;
  if (version === 1 || layer === 0 || bitrate === 0xf || rate === 3) return null;
  return "mp3";
}

/* ── tags: title and artist, when the file carries them ─────────────────── */
function cleanText(s, max) {
  if (typeof s !== "string") return "";
  return s.replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim().slice(0, max);
}
function decodeId3Text(buf) {
  if (!buf.length) return "";
  var enc = buf[0], body = buf.slice(1);
  if (enc === 1 || enc === 2) {
    var le = enc === 1 ? !(body[0] === 0xfe && body[1] === 0xff) : false;
    if (enc === 1 && ((body[0] === 0xff && body[1] === 0xfe) || (body[0] === 0xfe && body[1] === 0xff))) body = body.slice(2);
    var out = "";
    for (var i = 0; i + 1 < body.length; i += 2) {
      var code = le ? body[i] | (body[i + 1] << 8) : (body[i] << 8) | body[i + 1];
      if (code === 0) break;
      out += String.fromCharCode(code);
    }
    return out;
  }
  var text = enc === 3 ? body.toString("utf8") : body.toString("latin1");
  return text.split("\u0000")[0];
}
function id3Tags(buf) {
  if (ascii(buf, 0, 3) !== "ID3" || buf.length < 10) return {};
  var major = buf[3];
  var size = ((buf[6] & 0x7f) << 21) | ((buf[7] & 0x7f) << 14) | ((buf[8] & 0x7f) << 7) | (buf[9] & 0x7f);
  var end = Math.min(buf.length, 10 + size), at = 10, out = {};
  if (buf[5] & 0x40) at += major === 4 ? (((buf[10] & 0x7f) << 21) | ((buf[11] & 0x7f) << 14) | ((buf[12] & 0x7f) << 7) | (buf[13] & 0x7f)) : (buf.readUInt32BE(10) + 4);
  var idLen = major === 2 ? 3 : 4, headLen = major === 2 ? 6 : 10;
  while (at + headLen <= end) {
    var id = ascii(buf, at, at + idLen);
    if (!/^[A-Z0-9]+$/.test(id)) break;
    var len = major === 2 ? (buf[at + 3] << 16) | (buf[at + 4] << 8) | buf[at + 5]
      : major === 4 ? ((buf[at + 4] & 0x7f) << 21) | ((buf[at + 5] & 0x7f) << 14) | ((buf[at + 6] & 0x7f) << 7) | (buf[at + 7] & 0x7f)
      : buf.readUInt32BE(at + 4);
    var body = buf.slice(at + headLen, Math.min(end, at + headLen + len));
    if (id === "TIT2" || id === "TT2") out.title = decodeId3Text(body);
    if (id === "TPE1" || id === "TP1") out.artist = decodeId3Text(body);
    if (len <= 0) break;
    at += headLen + len;
  }
  return out;
}
/* Vorbis comments (FLAC, Ogg Vorbis, Opus): TITLE= and ARTIST=. */
function vorbisComments(buf, at) {
  var out = {};
  if (at + 8 > buf.length) return out;
  var vendor = buf.readUInt32LE(at); at += 4 + vendor;
  if (at + 4 > buf.length) return out;
  var count = buf.readUInt32LE(at); at += 4;
  for (var i = 0; i < count && i < 200 && at + 4 <= buf.length; i++) {
    var len = buf.readUInt32LE(at); at += 4;
    if (at + len > buf.length) break;
    var kv = buf.toString("utf8", at, at + len); at += len;
    var eq = kv.indexOf("=");
    if (eq === -1) continue;
    var key = kv.slice(0, eq).toUpperCase();
    if (key === "TITLE" && !out.title) out.title = kv.slice(eq + 1);
    if (key === "ARTIST" && !out.artist) out.artist = kv.slice(eq + 1);
  }
  return out;
}
function flacInfo(buf) {
  var out = {}, at = 4;
  for (var n = 0; n < 64 && at + 4 <= buf.length; n++) {
    var last = buf[at] & 0x80, type = buf[at] & 0x7f;
    var len = (buf[at + 1] << 16) | (buf[at + 2] << 8) | buf[at + 3];
    var body = at + 4;
    if (type === 0 && body + 18 <= buf.length) {
      var rate = (buf[body + 10] << 12) | (buf[body + 11] << 4) | (buf[body + 12] >> 4);
      var samples = (buf[body + 13] & 0x0f) * 4294967296 + buf.readUInt32BE(body + 14);
      if (rate > 0 && samples > 0) out.duration = samples / rate;
    }
    if (type === 4) Object.assign(out, vorbisComments(buf, body));
    if (last) break;
    at = body + len;
  }
  return out;
}
function oggTags(buf) {
  var head = buf.slice(0, Math.min(buf.length, 65536));
  var at = head.indexOf("OpusTags", 0, "latin1");
  if (at !== -1) return vorbisComments(head, at + 8);
  at = head.indexOf("\u0003vorbis", 0, "latin1");
  return at !== -1 ? vorbisComments(head, at + 7) : {};
}
/* M4A: the ilst atoms named byte 0xA9 + "nam" and 0xA9 + "ART", each holding a "data" atom. */
function mp4Tags(buf) {
  var out = {};
  [["title", String.fromCharCode(0xa9) + "nam"], ["artist", String.fromCharCode(0xa9) + "ART"]].forEach(function (pair) {
    var at = buf.indexOf(Buffer.from(pair[1], "latin1"));
    if (at === -1 || at + 20 > buf.length) return;
    if (ascii(buf, at + 8, at + 12) !== "data") return;
    var dataLen = buf.readUInt32BE(at + 4);
    var start = at + 20, end = Math.min(buf.length, at + 4 + dataLen);
    if (end > start) out[pair[0]] = buf.toString("utf8", start, end);
  });
  return out;
}
/* WAV: the data chunk over the byte rate, and LIST/INFO INAM and IART. */
function wavInfo(buf) {
  var out = {}, at = 12, byteRate = 0;
  while (at + 8 <= buf.length) {
    var id = ascii(buf, at, at + 4), len = buf.readUInt32LE(at + 4), body = at + 8;
    if (id === "fmt " && body + 12 <= buf.length) byteRate = buf.readUInt32LE(body + 8);
    if (id === "data" && byteRate > 0) out.duration = len / byteRate;
    if (id === "LIST" && ascii(buf, body, body + 4) === "INFO") {
      var p = body + 4, stop = Math.min(buf.length, body + len);
      while (p + 8 <= stop) {
        var sub = ascii(buf, p, p + 4), sl = buf.readUInt32LE(p + 4);
        var text = buf.toString("utf8", p + 8, Math.min(stop, p + 8 + sl)).split("\u0000")[0];
        if (sub === "INAM") out.title = text;
        if (sub === "IART") out.artist = text;
        p += 8 + sl + (sl & 1);
      }
    }
    if (id === "data") break;
    at = body + len + (len & 1);
  }
  return out;
}
/* { title, artist, duration } from the file itself; each may be missing. */
function readTags(buf, ext) {
  var raw = {};
  try {
    if (ext === "mp3" || ext === "aac") raw = id3Tags(buf);
    else if (ext === "flac") raw = flacInfo(buf);
    else if (ext === "ogg" || ext === "opus") raw = oggTags(buf);
    else if (ext === "m4a") raw = mp4Tags(buf);
    else if (ext === "wav") raw = wavInfo(buf);
  } catch (e) { raw = {}; }
  var out = {};
  var title = cleanText(raw.title, TITLE_MAX), artist = cleanText(raw.artist, ARTIST_MAX);
  if (title) out.title = title;
  if (artist) out.artist = artist;
  var d = cleanDuration(raw.duration);
  if (d !== null) out.duration = d;
  return out;
}
/* The file name without its folder or extension, as a title. */
function titleFromName(name) {
  var base = String(name || "").split(/[\\/]/).pop().replace(/\.[a-z0-9]{1,5}$/i, "").replace(/[_]+/g, " ");
  return cleanText(base, TITLE_MAX) || "Untitled track";
}
function cleanDuration(value) {
  var n = typeof value === "string" && value.trim() !== "" ? Number(value) : value;
  if (typeof n !== "number" || !isFinite(n) || n <= 0 || n > DURATION_MAX) return null;
  return Math.round(n * 1000) / 1000;
}

/* An upload, before anything is stored: { ext, mime, size } or { status, error }.
   `usedBytes` is what the member's library already holds. */
function checkUpload(file, usedBytes) {
  if (!file || !file.buffer || !file.buffer.length) return { status: 400, error: "Choose a music file." };
  var size = file.buffer.length;
  if (size > FILE_MAX_BYTES) return { status: 413, error: "A music file is at most " + mb(FILE_MAX_BYTES) + "." };
  var ext = sniffAudio(file.buffer);
  if (!ext) return { status: 415, error: "That file is not MP3, M4A, AAC, Ogg, Opus, FLAC or WAV audio." };
  if ((Number(usedBytes) || 0) + size > MEMBER_TOTAL_BYTES) {
    return { status: 413, error: "Your music library holds at most " + mb(MEMBER_TOTAL_BYTES) + ", and this file would take it past that. Delete a track to make room." };
  }
  return { ext: ext, mime: TYPES[ext].mime, size: size };
}
function mb(bytes) { return Math.round(bytes / (1024 * 1024)) + " MB"; }

/* The row an accepted upload becomes. `body` carries the browser's own
   measure of the duration, used when the file's header has none. */
function trackRow(userId, file, checked, body, nowMs) {
  var tags = readTags(file.buffer, checked.ext);
  var duration = tags.duration !== undefined ? tags.duration : cleanDuration(body && body.duration);
  return {
    user_id: userId,
    title: tags.title || titleFromName(file.originalname),
    artist: tags.artist || null,
    duration_secs: duration,
    storage_path: trackPathFor(userId, nowMs, checked.ext),
    mime: checked.mime,
    size_bytes: checked.size
  };
}
/* <member id>/<ms>-<8 random hex>.<ext>: the random part keeps two uploads
   in the same millisecond (two tabs, a multi-file drop) from sharing a path. */
function trackPathFor(userId, nowMs, ext) {
  return String(userId).toLowerCase() + "/" + String(nowMs) + "-" + require("crypto").randomBytes(4).toString("hex") + "." + ext;
}
/* A path in the member's own folder of bf-music, and nothing else. */
function ownTrackPath(value, userId) {
  if (typeof value !== "string" || !userId) return false;
  var m = /^([0-9a-f-]{36})\/\d{10,16}-[0-9a-f]{8}\.(mp3|m4a|aac|ogg|opus|flac|wav)$/.exec(value);
  return !!m && m[1] === String(userId).toLowerCase();
}

/* PUT /api/music/tracks/:id: { updates } or { error }. */
function trackUpdates(body) {
  body = body || {};
  var out = {};
  if (body.title !== undefined) {
    var t = cleanText(body.title, TITLE_MAX);
    if (!t) return { error: "A track needs a title." };
    out.title = t;
  }
  if (body.artist !== undefined) out.artist = cleanText(body.artist, ARTIST_MAX) || null;
  if (body.duration_secs !== undefined) {
    var d = cleanDuration(body.duration_secs);
    if (d === null) return { error: "duration_secs must be a number of seconds." };
    out.duration_secs = d;
  }
  if (!Object.keys(out).length) return { error: "Send a new title, artist or duration." };
  return { updates: out };
}

/* A playlist's name and its tracks, in order, each one the member's own. */
function playlistName(value) {
  var name = cleanText(value, PLAYLIST_NAME_MAX);
  return name ? { name: name } : { error: "A playlist needs a name." };
}
function playlistTracks(value, ownedIds) {
  if (!Array.isArray(value)) return { error: "track_ids must be a list." };
  if (value.length > PLAYLIST_MAX_TRACKS) return { error: "A playlist holds at most " + PLAYLIST_MAX_TRACKS + " tracks." };
  var seen = {}, out = [];
  for (var i = 0; i < value.length; i++) {
    var id = value[i];
    if (typeof id !== "string" || !UUID.test(id)) return { error: "track_ids must hold track ids." };
    if (ownedIds.indexOf(id) === -1) return { error: "A playlist can hold only your own tracks." };
    if (seen[id]) continue;
    seen[id] = true;
    out.push(id);
  }
  return { track_ids: out };
}

/* What the API answers about a track: never its storage path. */
function publicTrack(row) {
  return { id: row.id, title: row.title, artist: row.artist || null, duration_secs: row.duration_secs === null || row.duration_secs === undefined ? null : Number(row.duration_secs),
    mime: row.mime, size_bytes: Number(row.size_bytes) || 0, created_at: row.created_at };
}
function usedBytes(rows) {
  return (rows || []).reduce(function (n, r) { return n + (Number(r.size_bytes) || 0); }, 0);
}

module.exports = {
  BUCKET: BUCKET,
  FILE_MAX_BYTES: FILE_MAX_BYTES,
  MEMBER_TOTAL_BYTES: MEMBER_TOTAL_BYTES,
  SIGNED_URL_SECONDS: SIGNED_URL_SECONDS,
  TITLE_MAX: TITLE_MAX,
  ARTIST_MAX: ARTIST_MAX,
  PLAYLIST_NAME_MAX: PLAYLIST_NAME_MAX,
  PLAYLIST_MAX_TRACKS: PLAYLIST_MAX_TRACKS,
  MAX_PLAYLISTS: MAX_PLAYLISTS,
  TYPES: TYPES,
  EXTS: EXTS,
  MIMES: MIMES,
  UUID: UUID,
  sniffAudio: sniffAudio,
  readTags: readTags,
  titleFromName: titleFromName,
  cleanDuration: cleanDuration,
  checkUpload: checkUpload,
  trackRow: trackRow,
  trackPathFor: trackPathFor,
  ownTrackPath: ownTrackPath,
  trackUpdates: trackUpdates,
  playlistName: playlistName,
  playlistTracks: playlistTracks,
  publicTrack: publicTrack,
  usedBytes: usedBytes,
  mb: mb
};
