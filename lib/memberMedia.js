"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   lib/memberMedia.js — a member's own Media Library: images and short videos
   they upload once and reuse (build list item 4, migration 167). The page is
   the frontend's media.html; the picker every page shares is
   scripts/media-picker.js.

   THE FILES. In the public bf-public bucket at
   media/<user id>/<32 random hex>.<ext>. The hex is 16 bytes of
   crypto.randomBytes; the file's own name never appears in the path. Anyone
   with a file's link can open it, and the page says so.

   WHAT IS ACCEPTED is decided by the file's first bytes (sniffMedia), never
   by its name or the type the browser declared, and a declared type that
   disagrees with the bytes is refused: JPEG, PNG, GIF, WebP, MP4 (ISO brands
   only: HEIC/HEIF and QuickTime are refused) and WebM. At most MAX_FILE_BYTES
   a file (the bucket's own ceiling) and MEMBER_MEDIA_BYTES across the library.

   LOCATION AND CAMERA DETAILS are removed from JPEG, PNG and WebP photos
   before they are hashed and stored (stripMetadata), by walking the file's
   own structure and copying the image data byte for byte. A photo that does
   not parse cleanly is REFUSED, never stored as it came. GIF, MP4 and WebM
   are stored as they are, with metadata_stripped false.

   NEVER DELETED WHILE IN USE. Where a file is used is found by scanning the
   member's own rows in the tables lib/accountFiles.js FILE_TABLES lists as
   holding bf-public URLs (findUses). Item-level cleanups elsewhere (card media,
   theme photos) never remove an object under media/ (isLibraryKey).

   NOTHING HERE TALKS TO THE NETWORK: the database client is passed in, so
   scripts/checkMediaLibrary.js runs all of it against stubs.
   ══════════════════════════════════════════════════════════════════════════ */

const crypto = require("crypto");
const accountFiles = require("./accountFiles");

const BUCKET = "bf-public";
const FOLDER = "media";
const MAX_FILE_BYTES = 10 * 1024 * 1024;
const MEMBER_MEDIA_BYTES = 250 * 1024 * 1024;
const PAGE_SIZE = 60;
const LABEL_MAX = 120;
const ALT_MAX = 1000;
const READ_PAGE = 1000;
const READ_PAGES = 200;

/* The same pattern as migration 167's member_media_path_check. */
const PATH_PATTERN = "^media/[0-9a-f-]{36}/[0-9a-f]{32}\\.(jpg|png|webp|gif|mp4|webm)$";
const PATH_RE = new RegExp(PATH_PATTERN);
const PUBLIC_MARKER = "/storage/v1/object/public/" + BUCKET + "/";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/* Each accepted kind of file: the extension it is stored under, the type it
   is served as, image or video, and whether its metadata is removed. */
const TYPES = {
  jpg:  { mime: "image/jpeg", kind: "image", strip: true },
  png:  { mime: "image/png",  kind: "image", strip: true },
  webp: { mime: "image/webp", kind: "image", strip: true },
  gif:  { mime: "image/gif",  kind: "image", strip: false },
  mp4:  { mime: "video/mp4",  kind: "video", strip: false },
  webm: { mime: "video/webm", kind: "video", strip: false }
};
const MIMES = Object.keys(TYPES).map(function (e) { return TYPES[e].mime; });
const MP4_BRANDS = ["isom", "iso2", "iso4", "iso5", "iso6", "mp41", "mp42", "avc1", "dash", "M4V "];
const REFUSED_BRANDS = ["heic", "heix", "mif1", "msf1", "qt  "];

const MESSAGES = {
  empty: "Choose a file to upload.",
  field: "Send one file, as the field \"file\".",
  unsupported: "That file type isn't supported. Use JPEG, PNG, WebP, GIF, MP4 or WebM.",
  mismatch: "That file isn't the type it says it is.",
  tooBig: "A file is at most 10 MB.",
  full: "Your Media Library holds at most 250 MB, and this file would take it past that. Delete a file to make room.",
  unreadable: "That photo couldn't be read cleanly, so it wasn't saved.",
  notFound: "That file isn't in your library.",
  inUse: "This file is used in: ",
  usesUnknown: "Where this file is used couldn't be checked just now, so it wasn't deleted. Try again.",
  labelLong: "A label is at most 120 characters.",
  altLong: "Alt text is at most 1000 characters.",
  textType: "The label and alt text must be text.",
  nothing: "Send a label or alt text to save.",
  badKind: "kind is image or video.",
  badBefore: "before is a date and time.",
  stored: "The file couldn't be stored. Try again."
};

class MediaRefused extends Error {
  constructor(status, reason, message) { super(message); this.name = "MediaRefused"; this.status = status; this.reason = reason; }
}
function refuse(status, reason, message) { throw new MediaRefused(status, reason, message); }

function ascii(buf, a, b) { return buf.length >= b ? buf.toString("latin1", a, b) : ""; }

/* What a file's first bytes say it is: one of the TYPES keys, or null. */
function sniffMedia(buf) {
  if (!buf || buf.length < 12) return null;
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return "jpg";
  if (buf[0] === 0x89 && ascii(buf, 1, 4) === "PNG" && buf[4] === 0x0d && buf[5] === 0x0a && buf[6] === 0x1a && buf[7] === 0x0a) return "png";
  if (ascii(buf, 0, 6) === "GIF87a" || ascii(buf, 0, 6) === "GIF89a") return "gif";
  if (ascii(buf, 0, 4) === "RIFF" && ascii(buf, 8, 12) === "WEBP") return "webp";
  if (ascii(buf, 4, 8) === "ftyp") {
    var brand = ascii(buf, 8, 12);
    if (REFUSED_BRANDS.indexOf(brand) !== -1) return null;
    return MP4_BRANDS.indexOf(brand) !== -1 ? "mp4" : null;
  }
  if (buf[0] === 0x1a && buf[1] === 0x45 && buf[2] === 0xdf && buf[3] === 0xa3) return webmDocType(buf) === "webm" ? "webm" : null;
  return null;
}

/* The EBML header's DocType (element 0x4282) within the first 64 bytes. */
function webmDocType(buf) {
  var end = Math.min(buf.length, 64);
  for (var i = 4; i + 3 <= end; i++) {
    if (buf[i] !== 0x42 || buf[i + 1] !== 0x82) continue;
    var len = buf[i + 2];
    if (!(len & 0x80)) return null;          // a one-byte size is all a DocType needs
    len = len & 0x7f;
    if (i + 3 + len > end) return null;
    return ascii(buf, i + 3, i + 3 + len);
  }
  return null;
}

/* ── metadata removal ─────────────────────────────────────────────────────
   JPEG: the segments from SOI to SOS. APP1 (EXIF, XMP), APP13 (IPTC) and COM
   are dropped; APP0, APP2 (ICC colour) and every image segment are kept.
   Everything from SOS to the end is copied unchanged, and an EOI must follow. */
const JPEG_DROP = [0xe1, 0xed, 0xfe];
function stripJpeg(buf) {
  if (!buf || buf.length < 4 || buf[0] !== 0xff || buf[1] !== 0xd8) refuse(422, "unreadable", MESSAGES.unreadable);
  var out = [buf.subarray(0, 2)];
  var i = 2;
  for (;;) {
    if (i + 2 > buf.length || buf[i] !== 0xff) refuse(422, "unreadable", MESSAGES.unreadable);
    var marker = buf[i + 1];
    if (marker === 0xff) { i++; continue; }                 // a fill byte
    if (marker === 0xd8 || marker === 0xd9 || marker === 0x00) refuse(422, "unreadable", MESSAGES.unreadable);
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) { out.push(buf.subarray(i, i + 2)); i += 2; continue; }
    if (i + 4 > buf.length) refuse(422, "unreadable", MESSAGES.unreadable);
    var len = buf.readUInt16BE(i + 2);
    if (len < 2 || i + 2 + len > buf.length) refuse(422, "unreadable", MESSAGES.unreadable);
    if (marker === 0xda) {
      var rest = buf.subarray(i);
      var eoi = false;
      for (var k = len + 2; k + 1 < rest.length; k++) { if (rest[k] === 0xff && rest[k + 1] === 0xd9) { eoi = true; break; } }
      if (!eoi) refuse(422, "unreadable", MESSAGES.unreadable);
      out.push(rest);
      return Buffer.concat(out);
    }
    if (JPEG_DROP.indexOf(marker) === -1) out.push(buf.subarray(i, i + 2 + len));
    i += 2 + len;
  }
}

/* PNG: the chunks to IEND, each CRC checked. eXIf, tEXt, zTXt, iTXt and tIME
   are dropped; every other chunk is kept byte for byte; nothing after IEND. */
const PNG_DROP = ["eXIf", "tEXt", "zTXt", "iTXt", "tIME"];
var CRC_TABLE = null;
function crc32(buf) {
  if (!CRC_TABLE) {
    CRC_TABLE = new Int32Array(256);
    for (var n = 0; n < 256; n++) { var c = n; for (var k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; CRC_TABLE[n] = c; }
  }
  var crc = -1;
  for (var i = 0; i < buf.length; i++) crc = CRC_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ -1) >>> 0;
}
function stripPng(buf) {
  if (sniffMedia(buf) !== "png") refuse(422, "unreadable", MESSAGES.unreadable);
  var out = [buf.subarray(0, 8)];
  var i = 8, first = true;
  for (;;) {
    if (i + 12 > buf.length) refuse(422, "unreadable", MESSAGES.unreadable);
    var len = buf.readUInt32BE(i);
    var type = ascii(buf, i + 4, i + 8);
    var end = i + 12 + len;
    if (!/^[A-Za-z]{4}$/.test(type) || end > buf.length) refuse(422, "unreadable", MESSAGES.unreadable);
    if (crc32(buf.subarray(i + 4, i + 8 + len)) !== buf.readUInt32BE(i + 8 + len)) refuse(422, "unreadable", MESSAGES.unreadable);
    if (first && type !== "IHDR") refuse(422, "unreadable", MESSAGES.unreadable);
    first = false;
    if (PNG_DROP.indexOf(type) === -1) out.push(buf.subarray(i, end));
    i = end;
    if (type === "IEND") return Buffer.concat(out);
  }
}

/* WebP: the RIFF chunks. EXIF and XMP are dropped; when VP8X is present its
   EXIF (0x08) and XMP (0x04) flags are cleared; the RIFF size is rewritten.
   The first chunk must be VP8, VP8L or VP8X. */
const WEBP_DROP = ["EXIF", "XMP "];
function stripWebp(buf) {
  if (sniffMedia(buf) !== "webp") refuse(422, "unreadable", MESSAGES.unreadable);
  var limit = 8 + buf.readUInt32LE(4);
  if (limit > buf.length || limit < 20) refuse(422, "unreadable", MESSAGES.unreadable);
  var chunks = [];
  var i = 12, first = true;
  while (i < limit) {
    if (i + 8 > limit) refuse(422, "unreadable", MESSAGES.unreadable);
    var fourcc = ascii(buf, i, i + 4);
    var size = buf.readUInt32LE(i + 4);
    var end = i + 8 + size + (size & 1);
    if (!/^[A-Z0-9 ]{4}$/i.test(fourcc) || i + 8 + size > limit) refuse(422, "unreadable", MESSAGES.unreadable);
    if (end > limit) end = limit;                                         // an odd last chunk whose pad byte is missing
    if (first && ["VP8 ", "VP8L", "VP8X"].indexOf(fourcc) === -1) refuse(422, "unreadable", MESSAGES.unreadable);
    first = false;
    if (WEBP_DROP.indexOf(fourcc) === -1) {
      var chunk = Buffer.from(buf.subarray(i, end));
      if (fourcc === "VP8X") {
        if (size < 10) refuse(422, "unreadable", MESSAGES.unreadable);
        chunk[8] = chunk[8] & ~0x08 & ~0x04;
      }
      chunks.push(chunk);
    }
    i = end;
  }
  if (!chunks.some(function (c) { var f = ascii(c, 0, 4); return f === "VP8 " || f === "VP8L" || f === "ANIM"; })) refuse(422, "unreadable", MESSAGES.unreadable);
  var body = Buffer.concat(chunks);
  var head = Buffer.alloc(12);
  head.write("RIFF", 0, "latin1");
  head.writeUInt32LE(4 + body.length, 4);
  head.write("WEBP", 8, "latin1");
  return Buffer.concat([head, body]);
}

/* { bytes, stripped } for a sniffed file, or throws MediaRefused. */
function stripMetadata(buf, mime) {
  if (mime === "image/jpeg") return { bytes: stripJpeg(buf), stripped: true };
  if (mime === "image/png") return { bytes: stripPng(buf), stripped: true };
  if (mime === "image/webp") return { bytes: stripWebp(buf), stripped: true };
  if (mime === "image/gif" || mime === "video/mp4" || mime === "video/webm") return { bytes: buf, stripped: false };
  refuse(415, "unsupported", MESSAGES.unsupported);
}

/* An upload, before anything is stored: sniff, compare with the declared
   type, strip, hash. { ext, mime, kind, bytes, size, stripped, sha256 } or
   throws MediaRefused. */
function checkFile(file) {
  if (!file || !file.buffer || !file.buffer.length) refuse(400, "empty", MESSAGES.empty);
  if (file.buffer.length > MAX_FILE_BYTES) refuse(413, "too_big", MESSAGES.tooBig);
  var ext = sniffMedia(file.buffer);
  if (!ext) refuse(415, "unsupported", MESSAGES.unsupported);
  var t = TYPES[ext];
  if (file.mimetype !== t.mime) refuse(415, "mismatch", MESSAGES.mismatch);
  var s = stripMetadata(file.buffer, t.mime);
  return { ext: ext, mime: t.mime, kind: t.kind, bytes: s.bytes, size: s.bytes.length, stripped: s.stripped,
    sha256: crypto.createHash("sha256").update(s.bytes).digest("hex") };
}

/* media/<user id>/<32 random hex>.<ext>: never the file's own name. */
function mediaPath(userId, ext, randomBytes) {
  var hex = Buffer.from((randomBytes || crypto.randomBytes)(16)).toString("hex");
  return FOLDER + "/" + String(userId).toLowerCase() + "/" + hex + "." + ext;
}
function isLibraryPath(path, userId) {
  return typeof path === "string" && PATH_RE.test(path) && path.split("/")[1] === String(userId || "").toLowerCase();
}
/* Any object in the library folder, whoever's: what item cleanups must never remove. */
function isLibraryKey(key) { return typeof key === "string" && key.indexOf(FOLDER + "/") === 0; }

function baseOf(base) { return String(base || process.env.SUPABASE_URL || "").replace(/\/+$/, ""); }
function publicUrlFor(path, base) {
  var b = baseOf(base);
  return b ? b + PUBLIC_MARKER + encodeURI(path) : null;
}

/* True only for this project's bf-public public URL of an object whose path
   has userId as its second segment, in any folder. */
function isOwnPublicMediaUrl(url, userId, base) {
  if (typeof url !== "string" || !url || !userId) return false;
  var b = baseOf(base);
  if (!b) return false;
  var parsed, host;
  try { parsed = new URL(url); host = new URL(b).host; } catch (err) { return false; }
  if (parsed.protocol !== "https:" || parsed.host !== host || parsed.search || parsed.hash || parsed.username || parsed.password) return false;
  if (parsed.pathname.indexOf(PUBLIC_MARKER) !== 0) return false;
  var key;
  try { key = decodeURI(parsed.pathname.slice(PUBLIC_MARKER.length)); } catch (err) { return false; }
  var parts = key.split("/");
  if (parts.length < 3 || parts.some(function (p) { return !p || p === "." || p === ".."; })) return false;
  return parts[1] === String(userId).toLowerCase();
}

/* What a member is shown about one item: never user_id, sha256 or the path. */
function publicItem(row, base) {
  return { id: row.id, url: publicUrlFor(row.path, base), kind: row.kind, mime: row.mime, bytes: row.bytes,
    label: row.label || "", alt_text: row.alt_text || "", metadata_stripped: row.metadata_stripped === true, created_at: row.created_at };
}

/* The label and alt text a request sets: { updates } or { error }.
   `optional` (an upload) allows neither to be sent. */
function textUpdates(body, optional) {
  body = body || {};
  var updates = {};
  if (body.label !== undefined && body.label !== null) {
    if (typeof body.label !== "string") return { error: MESSAGES.textType };
    var label = body.label.trim();
    if (label.length > LABEL_MAX) return { error: MESSAGES.labelLong };
    updates.label = label;
  }
  if (body.alt_text !== undefined && body.alt_text !== null) {
    if (typeof body.alt_text !== "string") return { error: MESSAGES.textType };
    var alt = body.alt_text.trim();
    if (alt.length > ALT_MAX) return { error: MESSAGES.altLong };
    updates.alt_text = alt;
  }
  if (!optional && !Object.keys(updates).length) return { error: MESSAGES.nothing };
  return { updates: updates };
}

async function readAll(supabase, cols, userId) {
  var rows = [];
  for (var p = 0; p < READ_PAGES; p++) {
    var r = await supabase.from("member_media").select(cols).eq("user_id", userId)
      .order("created_at", { ascending: true }).order("id", { ascending: true }).range(p * READ_PAGE, p * READ_PAGE + READ_PAGE - 1);
    if (r.error) throw r.error;
    rows = rows.concat(r.data || []);
    if ((r.data || []).length < READ_PAGE) return rows;
  }
  throw new Error("member_media: more rows than can be read");
}
async function usage(supabase, userId) {
  var rows = await readAll(supabase, "id, bytes", userId);
  return { used_bytes: rows.reduce(function (s, r) { return s + (Number(r.bytes) || 0); }, 0), cap_bytes: MEMBER_MEDIA_BYTES, count: rows.length };
}
/* After an insert: whether the item `id` is past the cap, counting the
   library oldest first (created_at, then id). Two uploads that race both
   count the same order, so only the later one is over. */
async function overCap(supabase, userId, id) {
  var rows = await readAll(supabase, "id, bytes, created_at", userId);
  var total = 0;
  for (var i = 0; i < rows.length; i++) {
    total += Number(rows[i].bytes) || 0;
    if (rows[i].id === id) return total > MEMBER_MEDIA_BYTES;
  }
  return false;
}

/* Where a file is used: [{ place, title }], from the member's own rows only. */
const PLACES = {
  users: "Your account", profiles: "Your profile", bf_profiles: "Your profile page", profile_products: "A product on your profile",
  profile_portfolio: "Your portfolio", profile_music: "Music on your profile", profile_videos: "A video on your profile",
  bf_music_tracks: "Music on your profile", bf_videos: "A video on your profile", digital_cards: "A digital card",
  content_library: "Your content library", crowdfunding_campaigns: "A crowdfunding campaign", bizbooks: "A BizBook",
  cover_wraps: "A cover wrap", marketplace_listings: "A marketplace listing", member_tracks: "Your music library",
  social_post_drafts: "A social post waiting for approval",
  instagram_posts: "An Instagram post waiting for approval or still publishing",
  facebook_posts: "A Facebook post waiting for approval or still publishing"
};
const SOCIAL_PLATFORM_NAMES = { bluesky: "Bluesky", mastodon: "Mastodon" };
function titleOf(row) {
  var t = row && (row.title || row.name || row.card_name || row.full_name || row.business_name);
  return typeof t === "string" && t.trim() ? t.trim().slice(0, 120) : null;
}
/* Throws when a table cannot be read: a file is never called unused on a
   partial read. */
async function findUses(supabase, userId, path, base) {
  var host = null;
  try { host = new URL(baseOf(base)).host; } catch (err) { host = null; }
  var uses = [];
  for (var t of accountFiles.FILE_TABLES) {
    for (var p = 0; p < READ_PAGES; p++) {
      var r = await supabase.from(t.table).select("*").eq(t.owner, userId).range(p * READ_PAGE, p * READ_PAGE + READ_PAGE - 1);
      if (r.error) throw r.error;
      (r.data || []).forEach(function (row) {
        var hit = accountFiles.filesInRow(row, null, userId, host).some(function (f) { return f.bucket === BUCKET && f.path === path; });
        if (hit) uses.push({ place: PLACES[t.table] || t.table, title: titleOf(row) });
      });
      if ((r.data || []).length < READ_PAGE) break;
    }
  }
  /* A social post waiting for approval holds the item by id (migration 168's
     media_ids), not by link. Only pending_approval counts: a published post's
     images already live on that service, and a failed one never went out.
     social_post_drafts is not a FILE_TABLES table, so account deletion is
     unchanged. */
  var own = await supabase.from("member_media").select("id").eq("user_id", userId).eq("path", path).maybeSingle();
  if (own.error) throw own.error;
  if (own.data && own.data.id) {
    for (var q = 0; q < READ_PAGES; q++) {
      var d = await supabase.from("social_post_drafts").select("id, platform, status, media_ids").eq("user_id", userId)
        .eq("status", "pending_approval").range(q * READ_PAGE, q * READ_PAGE + READ_PAGE - 1);
      if (d.error) throw d.error;
      (d.data || []).forEach(function (draft) {
        if (draft.status === "pending_approval" && Array.isArray(draft.media_ids) && draft.media_ids.indexOf(own.data.id) !== -1) {
          uses.push({ place: PLACES.social_post_drafts, title: SOCIAL_PLATFORM_NAMES[draft.platform] || null });
        }
      });
      if ((d.data || []).length < READ_PAGE) break;
    }
    /* NAMED (Nov 7 2026, Instagram posting, migration 179): an Instagram post
       holds its photos by id in its proposal payload (items[].id). A pending
       or running publish_instagram_post proposal counts, and so does one whose
       instagram_posts row is still creating or processing (Instagram may still
       be fetching the photo from its public address). */
    var igProposals = {};
    var pend = await supabase.from("agent_proposals").select("id, status, payload").eq("user_id", userId)
      .eq("action_type", "publish_instagram_post").in("status", ["pending", "executing"]);
    if (pend.error) throw pend.error;
    (pend.data || []).forEach(function (pr) { igProposals[pr.id] = pr; });
    var live = await supabase.from("instagram_posts").select("proposal_id, status").eq("user_id", userId).in("status", ["creating", "processing"]);
    if (live.error) throw live.error;
    var liveIds = (live.data || []).map(function (r) { return r.proposal_id; }).filter(function (pid) { return pid && !igProposals[pid]; });
    if (liveIds.length) {
      var more = await supabase.from("agent_proposals").select("id, status, payload").eq("user_id", userId).in("id", liveIds);
      if (more.error) throw more.error;
      (more.data || []).forEach(function (pr) { igProposals[pr.id] = pr; });
    }
    var igHit = Object.keys(igProposals).some(function (pid) {
      var items = igProposals[pid].payload && igProposals[pid].payload.items;
      return Array.isArray(items) && items.some(function (it) { return it && it.id === own.data.id; });
    });
    if (igHit) uses.push({ place: PLACES.instagram_posts, title: "Instagram" });
    /* NAMED (Nov 7 2026, Facebook Pages posting, migration 180): a Facebook post
       holds its photos by id in its proposal payload (items[].id) the same way.
       A pending or running publish_facebook_post proposal counts, and so does
       one whose facebook_posts row is still creating or publishing (Facebook
       may still be fetching the photo from its public address). */
    var fbProposals = {};
    var fbPend = await supabase.from("agent_proposals").select("id, status, payload").eq("user_id", userId)
      .eq("action_type", "publish_facebook_post").in("status", ["pending", "executing"]);
    if (fbPend.error) throw fbPend.error;
    (fbPend.data || []).forEach(function (pr) { fbProposals[pr.id] = pr; });
    var fbLive = await supabase.from("facebook_posts").select("proposal_id, status").eq("user_id", userId).in("status", ["creating", "publishing"]);
    if (fbLive.error) throw fbLive.error;
    var fbLiveIds = (fbLive.data || []).map(function (r) { return r.proposal_id; }).filter(function (pid) { return pid && !fbProposals[pid]; });
    if (fbLiveIds.length) {
      var fbMore = await supabase.from("agent_proposals").select("id, status, payload").eq("user_id", userId).in("id", fbLiveIds);
      if (fbMore.error) throw fbMore.error;
      (fbMore.data || []).forEach(function (pr) { fbProposals[pr.id] = pr; });
    }
    var fbHit = Object.keys(fbProposals).some(function (pid) {
      var items = fbProposals[pid].payload && fbProposals[pid].payload.items;
      return Array.isArray(items) && items.some(function (it) { return it && it.id === own.data.id; });
    });
    if (fbHit) uses.push({ place: PLACES.facebook_posts, title: "Facebook" });
  }
  return uses;
}
function usesText(uses) {
  return MESSAGES.inUse + uses.map(function (u) { return u.title ? u.place + " (" + u.title + ")" : u.place; }).join(", ") + ".";
}

/* ── images in Bluesky and Mastodon posts (migration 168) ──────────────────
   A post carries at most 4 library images, chosen when it is filed. The draft
   keeps their ids in order (social_post_drafts.media_ids); the proposal keeps
   a frozen copy, [{ id, sha256, mime, bytes, alt }], with the alt text as it
   was at filing. At posting the two must agree, each row must still be the
   poster's with the same sha256 and type, and the bytes read back must be
   exactly row.bytes long and hash to the frozen sha256 (readMediaForPost).
   Any difference fails the post, and nothing is sent. */
const POST_MEDIA_MAX = 4;
const POST_IMAGE_MIMES = ["image/jpeg", "image/png", "image/webp", "image/gif"];
const BLUESKY_IMAGE_MAX_BYTES = 2000000;
const BLUESKY_ALT_MAX = 1000;
const SHA256_RE = /^[0-9a-f]{64}$/;
const POST_MESSAGES = {
  shape: "media_ids is a list of 1 to 4 different image ids from your Media Library.",
  notInLibrary: "That image isn't in your Media Library.",
  onlyImages: "Only images can be attached to posts for now.",
  altMissing: "Add alt text to this image in your Media Library first: ",
  blueskyTooBig: "This image is over Bluesky's 2 MB limit. Choose a smaller one.",
  mastodonTooBig: "This image is over your Mastodon server's size limit. Choose a smaller one.",
  blueskyAltLong: "Alt text for a Bluesky image is at most 1000 characters. Shorten it in your Media Library: ",
  mastodonAltLong: "Alt text is longer than your Mastodon server allows. Shorten it in your Media Library: ",
  changed: "An image attached to this post changed or left your Media Library after the post was filed, so nothing was posted. File the post again.",
  unread: "An image attached to this post could not be read just now, so nothing was posted."
};
/* reason: mismatch (payload and draft disagree), row (the row changed or left), limit (over the size limit), unread (the bytes
   could not be read), length (not row.bytes long) or sha (the bytes hash to something else). */
class MediaChanged extends Error {
  constructor(message, reason) { super(message || POST_MESSAGES.changed); this.name = "MediaChanged"; this.reason = reason || "row"; }
}
function itemName(row) {
  var label = row && typeof row.label === "string" ? row.label.trim() : "";
  return label || "untitled image";
}

/* The media_ids a filing sent: { ids } (empty when none was sent) or { error }. */
function parseMediaIds(value) {
  if (value === undefined) return { ids: [] };
  if (!Array.isArray(value) || value.length < 1 || value.length > POST_MEDIA_MAX) return { error: POST_MESSAGES.shape };
  var seen = {};
  for (var i = 0; i < value.length; i++) {
    if (typeof value[i] !== "string" || !UUID_RE.test(value[i]) || seen[value[i]]) return { error: POST_MESSAGES.shape };
    seen[value[i]] = true;
  }
  return { ids: value.slice() };
}

/* The frozen copy a filing stores, from the member's own rows, in the order
   asked: { media } or { status, error }. `rules` is { altMax, sizeMax,
   tooBig }: Bluesky's 1000 characters and 2,000,000 bytes, or the Mastodon
   connection's own limits. */
function freezeForPost(rowsById, ids, userId, rules) {
  var media = [];
  for (var i = 0; i < ids.length; i++) {
    var row = rowsById[ids[i]];
    if (!row || row.user_id !== userId) return { status: 404, error: POST_MESSAGES.notInLibrary };
    if (row.kind !== "image" || POST_IMAGE_MIMES.indexOf(row.mime) === -1) return { status: 400, error: POST_MESSAGES.onlyImages };
    var alt = typeof row.alt_text === "string" ? row.alt_text.trim() : "";
    if (!alt) return { status: 400, error: POST_MESSAGES.altMissing + itemName(row) };
    if (alt.length > rules.altMax) return { status: 400, error: rules.altLong + itemName(row) };
    if (!Number.isInteger(row.bytes) || row.bytes > rules.sizeMax) return { status: 400, error: rules.tooBig };
    media.push({ id: row.id, sha256: row.sha256, mime: row.mime, bytes: row.bytes, alt: alt });
  }
  return { media: media };
}

/* The two-way check: the proposal's frozen ids equal the draft's media_ids,
   in order. null when they agree, else the reason. */
function postMediaMismatch(frozen, draftIds) {
  var a = frozen === undefined || frozen === null ? [] : frozen;
  var b = draftIds === undefined || draftIds === null ? [] : draftIds;
  if (!Array.isArray(a) || !Array.isArray(b) || a.length > POST_MEDIA_MAX) return POST_MESSAGES.changed;
  if (a.length !== b.length) return POST_MESSAGES.changed;
  for (var i = 0; i < a.length; i++) {
    var f = a[i];
    if (!f || typeof f !== "object" || f.id !== b[i] || !SHA256_RE.test(String(f.sha256)) || POST_IMAGE_MIMES.indexOf(f.mime) === -1 ||
        !Number.isInteger(f.bytes) || typeof f.alt !== "string" || !f.alt.trim()) {
      return POST_MESSAGES.changed;
    }
  }
  return null;
}

/* One image's bytes for posting, from bf-public with the service role.
   deps: { storage, userId, maxBytes }. The row must still be the poster's
   image with the frozen sha256, type and size, and within maxBytes, before
   anything is downloaded; the bytes must then be exactly row.bytes long and
   hash to the frozen sha256. Throws MediaChanged otherwise. */
async function readMediaForPost(row, frozen, deps) {
  if (!row || !frozen || row.user_id !== deps.userId || row.id !== frozen.id || row.kind !== "image") throw new MediaChanged(null, "row");
  if (row.sha256 !== frozen.sha256 || row.mime !== frozen.mime || row.bytes !== frozen.bytes) throw new MediaChanged(null, "row");
  if (!Number.isInteger(row.bytes) || row.bytes < 1 || row.bytes > deps.maxBytes) throw new MediaChanged(null, "limit");
  var got;
  try { got = await deps.storage.from(BUCKET).download(row.path); } catch (err) { throw new MediaChanged(POST_MESSAGES.unread, "unread"); }
  if (!got || got.error || !got.data) throw new MediaChanged(POST_MESSAGES.unread, "unread");
  var buffer = Buffer.from(await got.data.arrayBuffer());
  if (buffer.length !== row.bytes) throw new MediaChanged(null, "length");
  if (crypto.createHash("sha256").update(buffer).digest("hex") !== frozen.sha256) throw new MediaChanged(null, "sha");
  return buffer;
}

/* An image's width and height from its own bytes, or null. Pure byte reads,
   never throws: JPEG's SOF0-3, 5-7, 9-11 and 13-15 frame headers; PNG's
   IHDR; WebP's VP8X canvas, VP8L's 14-bit fields or VP8's frame size; GIF's
   logical screen. */
const JPEG_SOF = [0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf];
function sized(width, height) {
  return Number.isInteger(width) && Number.isInteger(height) && width >= 1 && height >= 1 ? { width: width, height: height } : null;
}
function imageDimensions(bytes, mime) {
  try {
    var buf = bytes;
    if (!Buffer.isBuffer(buf) || buf.length < 10) return null;
    if (mime === "image/gif") {
      if (ascii(buf, 0, 6) !== "GIF87a" && ascii(buf, 0, 6) !== "GIF89a") return null;
      return sized(buf.readUInt16LE(6), buf.readUInt16LE(8));
    }
    if (mime === "image/png") {
      if (sniffMedia(buf) !== "png" || buf.length < 24 || ascii(buf, 12, 16) !== "IHDR" || buf.readUInt32BE(8) < 13) return null;
      return sized(buf.readUInt32BE(16), buf.readUInt32BE(20));
    }
    if (mime === "image/webp") {
      if (sniffMedia(buf) !== "webp" || buf.length < 30) return null;
      var fourcc = ascii(buf, 12, 16);
      if (fourcc === "VP8X") return sized(buf.readUIntLE(24, 3) + 1, buf.readUIntLE(27, 3) + 1);
      if (fourcc === "VP8L") {
        if (buf[20] !== 0x2f) return null;
        var bits = buf.readUInt32LE(21);
        return sized((bits & 0x3fff) + 1, ((bits >>> 14) & 0x3fff) + 1);
      }
      if (fourcc === "VP8 ") {
        if (buf[23] !== 0x9d || buf[24] !== 0x01 || buf[25] !== 0x2a) return null;
        return sized(buf.readUInt16LE(26) & 0x3fff, buf.readUInt16LE(28) & 0x3fff);
      }
      return null;
    }
    if (mime === "image/jpeg") {
      if (buf[0] !== 0xff || buf[1] !== 0xd8) return null;
      var i = 2;
      while (i + 4 <= buf.length) {
        if (buf[i] !== 0xff) return null;
        var marker = buf[i + 1];
        if (marker === 0xff) { i++; continue; }
        if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) { i += 2; continue; }
        if (marker === 0xd8 || marker === 0xd9 || marker === 0xda || marker === 0x00) return null;
        var len = buf.readUInt16BE(i + 2);
        if (len < 2 || i + 2 + len > buf.length) return null;
        if (JPEG_SOF.indexOf(marker) !== -1) {
          if (len < 7) return null;
          return sized(buf.readUInt16BE(i + 7), buf.readUInt16BE(i + 5));
        }
        i += 2 + len;
      }
      return null;
    }
    return null;
  } catch (err) {
    return null;
  }
}

module.exports = {
  BUCKET, FOLDER, MAX_FILE_BYTES, MEMBER_MEDIA_BYTES, PAGE_SIZE, LABEL_MAX, ALT_MAX, PATH_PATTERN, PATH_RE, UUID_RE, TYPES, MIMES,
  MP4_BRANDS, REFUSED_BRANDS, MESSAGES, PLACES, MediaRefused,
  sniffMedia, stripJpeg, stripPng, stripWebp, stripMetadata, checkFile, crc32,
  mediaPath, isLibraryPath, isLibraryKey, publicUrlFor, isOwnPublicMediaUrl, publicItem, textUpdates,
  usage, overCap, findUses, usesText,
  POST_MEDIA_MAX, POST_IMAGE_MIMES, BLUESKY_IMAGE_MAX_BYTES, BLUESKY_ALT_MAX, POST_MESSAGES, MediaChanged,
  parseMediaIds, freezeForPost, postMediaMismatch, readMediaForPost, imageDimensions
};
