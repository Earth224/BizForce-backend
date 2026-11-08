"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkMediaLibrary — a member's own Media Library (build list item 4,
   migration 167, Nov 4 2026): images and short videos uploaded through the
   server, typed by their first bytes, location and camera details removed
   from photos, reusable from a picker, never deleted while in use.

   Synthetic files are built here, in memory: a JPEG carrying an EXIF APP1
   with a GPS IFD, an XMP APP1, IPTC and a comment; a PNG with eXIf, tEXt,
   iTXt, zTXt and tIME; a WebP with VP8X, ICCP, EXIF and XMP chunks; a GIF; MP4
   headers with allowed and refused brands; WebM and Matroska headers; and
   malformed and truncated variants. server.js's routes are lifted and run in
   a vm against a stub database that enforces migration 167's CHECKs and
   unique keys, and a stub Storage. lib/memberMedia.js, lib/accountFiles.js,
   lib/legalPages.js and the rest run for real, compiled from their (possibly
   mutated) text. The pages run in jsdom. Every socket and DNS lookup is a
   tripwire: nothing leaves the machine.

   WHAT THIS PROVES
     S. Sniffing by bytes, every accepted and refused type, and a declared
        type that disagrees refused.
     X. Metadata removal: no Exif header, GPS IFD, XMP packet, IPTC, comment
        or PNG text survives, while the image bytes from SOS (JPEG), the IDAT
        data (PNG) and the VP8 data (WebP) are byte-identical; the WebP RIFF
        size and VP8X flags; malformed and truncated files refused.
     M. Migration 167: the header, the SQL as run, the path pattern equal to
        lib/memberMedia.js's, the highest migration.
     U. Upload: the order (sniff, strip, hash, dedupe, quota, store, row,
        quota again), crypto paths with no file name, dedupe, the quota before
        and after the insert with two uploads racing, cleanup when the insert
        fails, auth, subscription, the limiter.
     L. List, usage, label and alt text: the shape (no user_id, sha256 or
        path), pages of 60, kind, the 120 and 1000 limits, ownership (404).
     D. Delete: refused with 409 while used (the uses list from the member's
        own rows only), the file before the row, the pending_storage_deletions
        fallback.
     R. Elsewhere: sanitizeMedia keeps only the caller's own bf-public URLs;
        upload-url's folder allowlist; card and theme cleanups never remove
        media/; account deletion lists media/<id>/.
     F. media.html, media-library.js and media-picker.js in jsdom, and the
        picker beside the upload controls on four pages.
     G. Privacy and Terms word for word; the guide; yourData, backup and
        schemaCheck; Z, zero network.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check. A mutation
   whose search text does not match exactly once is an ERROR.

   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm"), Module = require("module"), net = require("net"), dns = require("dns"), zlib = require("zlib"), crypto = require("crypto");
const s = require("./_shared");

const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkMediaLibrary: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkMediaLibrary: no network"); };

const BASE = "https://proj.supabase.co";
process.env.SUPABASE_URL = BASE;   // the libs read it; this check never connects
const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";

const SV = "server.js", MM = "lib/memberMedia.js", AF = "lib/accountFiles.js", LP_FILE = "lib/legalPages.js", MIG = "supabase/migrations/167_member_media.sql";
const MLJS = "fe:scripts/media-library.js", MPJS = "fe:scripts/media-picker.js", MPAGE = "fe:media.html";

const MUTATIONS = {
  // the declared type decides, not the bytes
  "sniff-trusts-declared": [[MM, "  var ext = sniffMedia(file.buffer);\n", "  var ext = Object.keys(TYPES).filter(function (k) { return TYPES[k].mime === file.mimetype; })[0] || sniffMedia(file.buffer);\n"]],
  // an iPhone HEIC photo is taken as MP4
  "heic-accepted": [
    [MM, "    if (REFUSED_BRANDS.indexOf(brand) !== -1) return null;\n", ""],
    [MM, "const MP4_BRANDS = [\"isom\",", "const MP4_BRANDS = [\"heic\", \"mif1\", \"isom\","]],
  // a JPEG keeps its EXIF and XMP
  "jpeg-exif-kept": [[MM, "const JPEG_DROP = [0xe1, 0xed, 0xfe];", "const JPEG_DROP = [0xed, 0xfe];"]],
  // the EXIF block (with its GPS IFD) survives; only XMP goes
  "gps-survives": [[MM, "    if (JPEG_DROP.indexOf(marker) === -1) out.push(buf.subarray(i, i + 2 + len));",
    "    if (JPEG_DROP.indexOf(marker) === -1 || ascii(buf, i + 4, i + 8) === \"Exif\") out.push(buf.subarray(i, i + 2 + len));"]],
  // a PNG keeps its text chunks
  "png-text-kept": [[MM, "const PNG_DROP = [\"eXIf\", \"tEXt\", \"zTXt\", \"iTXt\", \"tIME\"];", "const PNG_DROP = [\"eXIf\", \"tIME\"];"]],
  // a WebP's VP8X still says it carries EXIF and XMP
  "webp-flags-kept": [[MM, "        chunk[8] = chunk[8] & ~0x08 & ~0x04;\n", ""]],
  // the RIFF size is left as it was before the chunks were dropped
  "webp-size-stale": [[MM, "  head.writeUInt32LE(4 + body.length, 4);", "  head.writeUInt32LE(buf.readUInt32LE(4), 4);"]],
  // a photo that does not parse is stored as it came
  "malformed-stored-unstripped": [[MM, "  var s = stripMetadata(file.buffer, t.mime);\n", "  var s; try { s = stripMetadata(file.buffer, t.mime); } catch (e) { s = { bytes: file.buffer, stripped: false }; }\n"]],
  // the image data after SOS is changed
  "image-data-altered": [[MM, "      out.push(rest);\n", "      out.push(Buffer.from(rest).fill(0, len + 2, len + 3));\n"]],
  // the file's own name goes into the path
  "path-has-filename": [[SV, "      const path = memberMedia.mediaPath(userId, checked.ext);\n",
    "      const path = memberMedia.mediaPath(userId, checked.ext).replace(/[0-9a-f]{32}/, String(req.file.originalname || \"\").replace(/[^a-z]/gi, \"\").slice(0, 32));\n"]],
  // the path's random part comes from Math.random
  "math-random-path": [[MM, "  var hex = Buffer.from((randomBytes || crypto.randomBytes)(16)).toString(\"hex\");",
    "  var hex = Buffer.from((randomBytes || function (n) { var a = []; for (var k = 0; k < n; k++) a.push(Math.floor(Math.random() * 256)); return a; })(16)).toString(\"hex\");"]],
  // the same file is stored again
  "dedupe-ignored": [[SV, "      if (same.data) return res.status(200).json({ item: memberMedia.publicItem(same.data), duplicate: true });\n", ""]],
  // the quota is not checked before the upload
  "quota-unchecked": [[SV, "      if (before.used_bytes + checked.size > memberMedia.MEMBER_MEDIA_BYTES) return res.status(413).json({ error: memberMedia.MESSAGES.full, reason: \"full\" });\n", ""]],
  // the quota is not checked again after the insert
  "quota-recheck-missing": [[SV, "      if (await memberMedia.overCap(supabase, userId, ins.data.id)) {", "      if (false) {"]],
  // a failed insert leaves the file in storage
  "orphan-on-insert-fail": [[SV, "      if (ins.error) {\n        await supabase.storage.from(memberMedia.BUCKET).remove([path]);\n", "      if (ins.error) {\n"]],
  // another member's items are listed
  "foreign-item-visible": [[SV, "    let q = supabase.from(\"member_media\").select(MEDIA_COLUMNS).eq(\"user_id\", req.user.id);", "    let q = supabase.from(\"member_media\").select(MEDIA_COLUMNS);"]],
  // another member's item can be acted on
  "foreign-item-deleted": [[SV, "select(MEDIA_COLUMNS).eq(\"id\", id).eq(\"user_id\", userId).maybeSingle();", "select(MEDIA_COLUMNS).eq(\"id\", id).maybeSingle();"]],
  // an item in use is deleted anyway
  "in-use-deleted": [[SV, "    if (uses.length) return res.status(409).json({ error: memberMedia.usesText(uses), uses: uses, reason: \"in_use\" });\n", ""]],
  // the row goes before the file
  "delete-row-before-storage": [[SV,
    "    const removed = await accountFiles.removeFiles({ supabase: supabase, storage: supabase.storage, files: [{ bucket: memberMedia.BUCKET, path: item.path }] });\n" +
    "    if (removed.not_queued) console.error(\"[media] a library file could be neither removed nor queued for user \" + req.user.id);\n" +
    "    const { error } = await supabase.from(\"member_media\").delete().eq(\"id\", item.id).eq(\"user_id\", req.user.id);\n",
    "    const { error } = await supabase.from(\"member_media\").delete().eq(\"id\", item.id).eq(\"user_id\", req.user.id);\n" +
    "    const removed = await accountFiles.removeFiles({ supabase: supabase, storage: supabase.storage, files: [{ bucket: memberMedia.BUCKET, path: item.path }] });\n"]],
  // sanitizeMedia keeps any https URL again
  "sanitize-foreign-url": [[SV, "      if (!url || !memberMedia.isOwnPublicMediaUrl(url, userId)) {", "      if (!url || url.indexOf(\"https://\") !== 0) {"]],
  // upload-url takes any folder again
  "upload-url-free-folder": [[SV,
    "  if (typeof req.body.folder !== \"string\" || UPLOAD_URL_FOLDERS.indexOf(req.body.folder) === -1) {\n" +
    "    return res.status(400).json({ error: \"folder must be one of: \" + UPLOAD_URL_FOLDERS.join(\", \") + \".\", reason: \"folder\" });\n  }\n" +
    "  const folder      = req.body.folder;",
    "  const folder      = safeText(req.body.folder, 40)   || \"misc\";"]],
  // a card's displaced background removes a Media Library file
  "card-removal-touches-library": [[SV, "    if (memberMedia.isLibraryKey(key)) continue;\n", ""]],
  // account deletion leaves media/<id>/ behind
  "account-delete-skips-media": [[AF,
    "  var library = await listUnder(storage, PUBLIC, media, 0);\n  library.forEach(function (k) { if (keyUnder(k, media)) add(PUBLIC, k, \"in \" + PUBLIC + \" under the member's Media Library folder\"); });\n", ""]],
  // uploading without a subscription
  "unsubscribed-can-upload": [[SV, "app.post(\"/api/media\", requireAuth, requireActiveSubscription, mediaUploadLimiter,", "app.post(\"/api/media\", requireAuth, mediaUploadLimiter,"]],
  // the list carries each file's hash
  "sha-in-list": [
    [SV, "const MEDIA_COLUMNS = \"id, path, kind, mime, bytes, label, alt_text, metadata_stripped, created_at\";", "const MEDIA_COLUMNS = \"id, path, kind, mime, bytes, label, alt_text, metadata_stripped, created_at, sha256\";"],
    [MM, "metadata_stripped: row.metadata_stripped === true, created_at: row.created_at };", "metadata_stripped: row.metadata_stripped === true, created_at: row.created_at, sha256: row.sha256 };"]],
  // a server message is parsed as HTML on the library page
  "innerHTML-on-page": [[MLJS, "    function note(text, isError) { msg.textContent = text || \"\";", "    function note(text, isError) { msg.innerHTML = text || \"\";"]],
  // the Privacy Policy loses the media sentence
  "privacy-sentence-removed": [[LP_FILE, "      MEDIA_PRIVACY_SENTENCE,\n", ""]],
  // alt text of any length is accepted
  "alt-text-unbounded": [[MM, "    if (alt.length > ALT_MAX) return { error: MESSAGES.altLong };\n", ""]],
  // ── earned by the code ──
  // a declared type that disagrees with the bytes is let through
  "declared-mismatch-accepted": [[MM, "  if (file.mimetype !== t.mime) refuse(415, \"mismatch\", MESSAGES.mismatch);\n", ""]],
  // a PNG with a broken CRC is taken
  "png-crc-unchecked": [[MM, "    if (crc32(buf.subarray(i + 4, i + 8 + len)) !== buf.readUInt32BE(i + 8 + len)) refuse(422, \"unreadable\", MESSAGES.unreadable);\n", ""]],
  // any EBML file (Matroska) is taken as WebM
  "webm-doctype-unchecked": [[MM, "return webmDocType(buf) === \"webm\" ? \"webm\" : null;", "return \"webm\";"]],
  // a failed file removal is not queued
  "queue-fallback-missing": [[SV,
    "    const removed = await accountFiles.removeFiles({ supabase: supabase, storage: supabase.storage, files: [{ bucket: memberMedia.BUCKET, path: item.path }] });\n",
    "    await supabase.storage.from(memberMedia.BUCKET).remove([item.path]); const removed = { queued: 0, not_queued: 0 };\n"]],
  // the picker hands back the mime type, not image or video
  "picker-wrong-shape": [[MPJS, "type: item.kind === \"video\" ? \"video\" : \"image\"", "type: item.mime"]],
  // the page sends a file over 10 MB
  "oversize-sent": [[MLJS, "    if (file.size > MAX_BYTES) { say(TOO_BIG, true); return; }\n", ""]],
  // the page's notice about photos is reworded
  "notice-reworded": [[MPAGE, "Location and camera details are removed from JPEG, PNG and WebP photos before they are saved.", "Photos are cleaned before they are saved."]],
  // a label of any length is accepted
  "label-unbounded": [[MM, "    if (label.length > LABEL_MAX) return { error: MESSAGES.labelLong };\n", ""]],
  // the upload is not rate-limited
  "upload-unlimited": [[SV, "app.post(\"/api/media\", requireAuth, requireActiveSubscription, mediaUploadLimiter, function", "app.post(\"/api/media\", requireAuth, requireActiveSubscription, function"]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

/* ── the files ──────────────────────────────────────────────────────────── */
const lf = t => t.replace(/\r\n/g, "\n");
const ALL = {};
[SV, MM, AF, "lib/supportLinks.js", "lib/scrollbars.js", LP_FILE, "lib/legal.js", "lib/themes.js", "lib/yourData.js", "lib/backup.js", "lib/schemaCheck.js", MIG].forEach(f => { ALL[f] = lf(fs.readFileSync(path.join(REPO, f), "utf8")); });
["media.html", "scripts/media-library.js", "scripts/media-picker.js", "campaigns.html", "marketplace.html", "garage-sale.html", "digital-cards.html", "dashboard.html",
  "terms.html", "privacy.html", "scripts/termaximus-guide.js"].forEach(f => {
  const p = path.join(FRONTEND, f);
  ALL["fe:" + f] = fs.existsSync(p) ? lf(fs.readFileSync(p, "utf8")) : null;
});
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) ALL[file] = s.replaceOnce(ALL[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}
const SRC = ALL[SV];
const fe = f => ALL["fe:" + f];

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}
const J = JSON.stringify;

/* ── the libs, compiled from the (possibly mutated) text ─────────────────── */
const realRequire = Module.createRequire(path.join(REPO, "server.js"));
const LIB_CACHE = {};
function loadLib(rel) {
  if (LIB_CACHE[rel]) return LIB_CACHE[rel].exports;
  const file = path.join(REPO, rel);
  const m = new Module(file, module);
  m.filename = file;
  m.paths = Module._nodeModulePaths(path.dirname(file));
  LIB_CACHE[rel] = m;
  m.require = function (req) {
    if (req.indexOf("./") === 0 || req.indexOf("../") === 0) {
      const target = path.relative(REPO, path.join(path.dirname(file), req)).replace(/\\/g, "/").replace(/(\.js)?$/, ".js");
      if (ALL[target] !== undefined) return loadLib(target);
      return realRequire(path.join(REPO, target));
    }
    return realRequire(req);
  };
  m._compile(ALL[rel], file);
  return m.exports;
}
const MED = loadLib(MM), AFL = loadLib(AF), LP = loadLib(LP_FILE), LEGAL = loadLib("lib/legal.js");

/* ── synthetic files ─────────────────────────────────────────────────────── */
const B = (...parts) => Buffer.concat(parts.map(p => Buffer.isBuffer(p) ? p : typeof p === "string" ? Buffer.from(p, "latin1") : Buffer.from(p)));
const u16 = n => Buffer.from([(n >> 8) & 255, n & 255]);
const u32be = n => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b; };
const u32le = n => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };
const seg = (marker, body) => B([0xff, marker], u16(body.length + 2), body);
/* A TIFF block, big-endian: IFD0 holds Make "CamCo" and the GPSInfo pointer (tag 0x8825); the GPS IFD holds
   GPSLatitudeRef "N" and GPSLatitude 37/1 46/1 30/1. */
function exifBlock() {
  const ifd0At = 8, ifd0Count = 2, ifd0Size = 2 + ifd0Count * 12 + 4;
  const makeAt = ifd0At + ifd0Size, gpsAt = makeAt + 6;
  const gpsCount = 2, gpsSize = 2 + gpsCount * 12 + 4, latAt = gpsAt + gpsSize;
  const entry = (tag, type, count, value) => B(u16(tag), u16(type), u32be(count), value);
  const tiff = B("MM", [0, 42], u32be(ifd0At),
    u16(ifd0Count), entry(0x010f, 2, 6, u32be(makeAt)), entry(0x8825, 4, 1, u32be(gpsAt)), u32be(0),
    "CamCo\0",
    u16(gpsCount), entry(0x0001, 2, 2, B("N\0\0\0")), entry(0x0002, 5, 3, u32be(latAt)), u32be(0),
    u32be(37), u32be(1), u32be(46), u32be(1), u32be(30), u32be(1));
  return B("Exif\0\0", tiff);
}
const XMP_NS = "http://ns.adobe.com/xap/1.0/\0";
const XMP_PACKET = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF><rdf:Description exif:GPSLatitude=\"37,46.5N\"/></rdf:RDF></x:xmpmeta>";
const SCAN = Buffer.from([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0xff, 0x00, 0x33, 0x44]);   // entropy-coded data, an escaped FF 00 inside
function jpeg(opts) {
  opts = opts || {};
  const sos = B(seg(0xda, Buffer.from([0x01, 0x01, 0x00, 0x00, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00])), opts.scan || SCAN, opts.noEoi ? Buffer.alloc(0) : Buffer.from([0xff, 0xd9]));
  return B([0xff, 0xd8],
    seg(0xe0, B("JFIF\0", [1, 1, 0, 0, 1, 0, 1, 0, 0])),
    opts.noExif ? Buffer.alloc(0) : seg(0xe1, exifBlock()),
    opts.noXmp ? Buffer.alloc(0) : seg(0xe1, B(XMP_NS, XMP_PACKET)),
    seg(0xe2, B("ICC_PROFILE\0", [1, 1], "iccdata")),
    seg(0xed, B("Photoshop 3.0\0", "8BIM", [4, 4], "iptc-city:Lisbon")),
    seg(0xfe, B("shot on a CamCo at home")),
    seg(0xdb, B([0], Buffer.alloc(64, 7))),
    seg(0xc0, B([8, 0, 16, 0, 16, 1, 1, 0x11, 0])),
    seg(0xc4, B([0], Buffer.alloc(16, 0), [1])),
    sos);
}
function pngChunk(type, data) {
  const body = B(type, data);
  return B(u32be(data.length), body, u32be(zlib.crc32(body)));
}
const IDAT = Buffer.from([0x78, 0x9c, 0x63, 0x60, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0xaa, 0xbb]);
const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
function png(opts) {
  opts = opts || {};
  const parts = [PNG_SIG];
  if (!opts.idatFirst) parts.push(pngChunk("IHDR", B(u32be(1), u32be(1), [8, 2, 0, 0, 0])));
  parts.push(pngChunk("tEXt", B("Comment\0", "taken at 37.775N")), pngChunk("eXIf", exifBlock().subarray(6)),
    pngChunk("iTXt", B("XML:com.adobe.xmp\0\0\0\0\0", XMP_PACKET)), pngChunk("tIME", Buffer.from([7, 234, 11, 4, 12, 0, 0])));
  parts.push(pngChunk("IDAT", IDAT), pngChunk("zTXt", B("Author\0\0", [0x78, 0x9c, 3, 0])));
  if (!opts.noIend) parts.push(pngChunk("IEND", Buffer.alloc(0)));
  let out = B(...parts);
  if (opts.badCrc) { out = Buffer.from(out); out[8 + 8 + 13] ^= 0xff; }   // IHDR's CRC
  return out;
}
const VP8 = Buffer.from([0x30, 0x01, 0x00, 0x9d, 0x01, 0x2a, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x34, 0x25, 0xa4]);  // 15 bytes, odd: padded
function webpChunk(fourcc, data) { return B(fourcc, u32le(data.length), data, data.length & 1 ? [0] : []); }
function webp(opts) {
  opts = opts || {};
  const vp8x = B([0x20 | 0x08 | 0x04, 0, 0, 0], [0, 0, 0], [0, 0, 0]);   // ICC, EXIF, XMP; a 1 x 1 canvas
  const body = B("WEBP", webpChunk("VP8X", vp8x), webpChunk("ICCP", B("iccdata")), webpChunk("VP8 ", VP8),
    webpChunk("EXIF", exifBlock().subarray(6)), webpChunk("XMP ", B(XMP_PACKET)));
  const size = opts.badSize ? body.length + 100 : body.length;
  return B("RIFF", u32le(size), body);
}
const GIF = B("GIF89a", [1, 0, 1, 0, 0x80, 0, 0], [0, 0, 0, 255, 255, 255], ",", [0, 0, 0, 0, 1, 0, 1, 0, 0], [2, 2, 0x44, 1, 0], ";");
const mp4 = brand => B(u32be(24), "ftyp", brand, u32be(0), brand, "isom", u32be(8), "mdat");
function ebml(docType) {
  const doc = Buffer.from(docType, "latin1");
  const head = B([0x42, 0x86, 0x81, 1], [0x42, 0xf7, 0x81, 1], [0x42, 0xf2, 0x81, 4], [0x42, 0xf3, 0x81, 8], [0x42, 0x82, 0x80 | doc.length], doc, [0x42, 0x87, 0x81, 2], [0x42, 0x85, 0x81, 2]);
  return B([0x1a, 0x45, 0xdf, 0xa3, 0x80 | head.length], head, [0x18, 0x53, 0x80, 0x67], Buffer.alloc(8, 0));
}
const WEBM = ebml("webm");
const has = (buf, needle) => buf.indexOf(Buffer.isBuffer(needle) ? needle : Buffer.from(needle, "latin1")) !== -1;
function jpegSegments(buf) {
  const out = []; let i = 2;
  while (i < buf.length && buf[i] === 0xff) {
    const m = buf[i + 1];
    if (m === 0xda) { out.push(m); break; }
    out.push(m); i += 2 + buf.readUInt16BE(i + 2);
  }
  return out;
}
function pngTypes(buf) { const t = []; let i = 8; while (i + 8 <= buf.length) { const n = buf.readUInt32BE(i); t.push(buf.toString("latin1", i + 4, i + 8)); i += 12 + n; } return t; }
function webpChunks(buf) { const c = []; let i = 12; while (i + 8 <= buf.length) { const n = buf.readUInt32LE(i + 4); c.push({ fourcc: buf.toString("latin1", i, i + 4), data: buf.subarray(i + 8, i + 8 + n) }); i += 8 + n + (n & 1); } return c; }
function refusedWith(fn) { try { fn(); return null; } catch (e) { return e instanceof MED.MediaRefused ? e.reason + ":" + e.status : "threw " + e.message; } }

/* ── the database and Storage ────────────────────────────────────────────── */
const SQL_PATH = /member_media_path_check CHECK \(path ~ '([^']+)'\)/.exec(ALL[MIG]);
const PATH_SQL_RE = new RegExp(SQL_PATH ? SQL_PATH[1] : "^$");
const MIMES167 = ["image/jpeg", "image/png", "image/webp", "image/gif", "video/mp4", "video/webm"];
function rule167(rows) {
  for (const r of rows) {
    if (!PATH_SQL_RE.test(r.path)) return { code: "23514", message: "violates check constraint member_media_path_check" };
    if (r.path.indexOf("media/" + r.user_id + "/") !== 0) return { code: "23514", message: "violates check constraint member_media_path_owner_check" };
    if (["image", "video"].indexOf(r.kind) === -1 || MIMES167.indexOf(r.mime) === -1) return { code: "23514", message: "violates check constraint member_media_kind_check" };
    if (!(Number.isInteger(r.bytes) && r.bytes > 0 && r.bytes <= 10485760)) return { code: "23514", message: "violates check constraint member_media_bytes_check" };
    if (!/^[0-9a-f]{64}$/.test(r.sha256)) return { code: "23514", message: "violates check constraint member_media_sha256_check" };
    if (typeof r.alt_text !== "string" || r.alt_text.length > 1000) return { code: "23514", message: "violates check constraint member_media_alt_text_check" };
    if (typeof r.label !== "string" || r.label.length > 120) return { code: "23514", message: "violates check constraint member_media_label_check" };
  }
  const paths = rows.map(r => r.path), shas = rows.map(r => r.user_id + "|" + r.sha256);
  if (new Set(paths).size !== paths.length) return { code: "23505", message: "duplicate key value violates unique constraint member_media_path_key" };
  if (new Set(shas).size !== shas.length) return { code: "23505", message: "duplicate key value violates unique constraint member_media_user_sha_key" };
  return null;
}
let clock = Date.parse("2026-11-04T12:00:00.000Z");
function makeDb(seed) {
  const t = JSON.parse(JSON.stringify(seed));
  const db = { t, log: [], failInsert: null, failRead: null };
  db.from = function (table) {
    const st = { op: "select", cols: null, ret: null, filters: [], orders: [], limit: null, range: null, row: null, upsert: null };
    function run() {
      if (db.failRead && db.failRead === table && st.op === "select") return Promise.resolve({ data: null, error: { code: "XX000", message: "read failed" } });
      if (!t[table]) return Promise.resolve({ data: null, error: { code: "PGRST205", message: "no table " + table } });
      const before = JSON.stringify(t[table]);
      if (st.op === "insert" || st.op === "upsert") {
        if (st.op === "insert" && db.failInsert === table) return Promise.resolve({ data: null, error: { code: "XX000", message: "insert failed" } });
        const rows = (Array.isArray(st.row) ? st.row : [st.row]).map(r => Object.assign(
          table === "member_media" ? { alt_text: "", label: "", metadata_stripped: false } : {},
          { id: crypto.randomUUID(), created_at: new Date(clock += 1000).toISOString() }, JSON.parse(JSON.stringify(r))));
        if (st.op === "upsert") {
          const fresh = rows.filter(r => !t[table].some(x => x.bucket === r.bucket && x.path === r.path));
          t[table].push(...fresh);
          db.log.push(table + ":upsert");
          return Promise.resolve({ data: null, error: null });
        }
        t[table].push(...rows);
        const bad = table === "member_media" ? rule167(t[table]) : null;
        if (bad) { t[table] = JSON.parse(before); return Promise.resolve({ data: null, error: bad }); }
        db.log.push(table + ":insert");
        return Promise.resolve({ data: st.ret ? project(rows, st.ret) : null, error: null });
      }
      let rows = t[table].filter(r => st.filters.every(f => f(r)));
      if (st.op === "update") {
        rows.forEach(r => Object.assign(r, JSON.parse(JSON.stringify(st.row))));
        const bad = table === "member_media" ? rule167(t[table]) : null;
        if (bad) { t[table] = JSON.parse(before); return Promise.resolve({ data: null, error: bad }); }
        db.log.push(table + ":update");
        return Promise.resolve({ data: project(rows, st.ret || "*"), error: null });
      }
      if (st.op === "delete") {
        t[table] = t[table].filter(r => rows.indexOf(r) === -1);
        db.log.push(table + ":delete:" + rows.length);
        return Promise.resolve({ data: null, error: null });
      }
      rows = rows.slice().sort((x, y) => { for (const [c, asc] of st.orders) { if (x[c] < y[c]) return asc ? -1 : 1; if (x[c] > y[c]) return asc ? 1 : -1; } return 0; });
      if (st.range) rows = rows.slice(st.range[0], st.range[1] + 1);
      if (st.limit != null) rows = rows.slice(0, st.limit);
      db.log.push(table + ":select");
      return Promise.resolve({ data: project(rows, st.cols), error: null });
    }
    const q = {
      select(c) { if (st.op === "select") st.cols = c || "*"; else st.ret = c || "*"; return q; },
      insert(r) { st.op = "insert"; st.row = r; return q; },
      upsert(r) { st.op = "upsert"; st.row = r; return q; },
      update(p) { st.op = "update"; st.row = p; return q; },
      delete() { st.op = "delete"; return q; },
      eq(c, v) { st.filters.push(r => r[c] === v); return q; },
      lt(c, v) { st.filters.push(r => r[c] < v); return q; },
      in(c, vs) { st.filters.push(r => vs.indexOf(r[c]) !== -1); return q; },
      order(c, o) { st.orders.push([c, !o || o.ascending !== false]); return q; },
      limit(n) { st.limit = n; return q; },
      range(a, b) { st.range = [a, b]; return q; },
      maybeSingle() { return run().then(r => r.error ? r : r.data.length > 1 ? { data: null, error: { code: "PGRST116" } } : { data: r.data[0] || null, error: null }); },
      single() { return run().then(r => r.error ? r : r.data.length !== 1 ? { data: null, error: { code: "PGRST116", message: r.data.length + " rows" } } : { data: r.data[0], error: null }); },
      then(ok, bad) { return run().then(ok, bad); }
    };
    return q;
  };
  return db;
}
function project(rows, cols) {
  if (!cols || cols === "*") return rows.map(r => JSON.parse(JSON.stringify(r)));
  const names = cols.split(",").map(c => c.trim());
  return rows.map(r => { const o = {}; names.forEach(n => { o[n] = r[n] === undefined ? null : JSON.parse(JSON.stringify(r[n])); }); return o; });
}
function makeStorage(log) {
  const st = { objects: {}, uploads: [], removes: [], failRemove: false, signed: [] };
  st.from = function (bucket) {
    return {
      upload: async (p, bytes, o) => {
        st.uploads.push({ bucket, path: p, size: bytes.length, contentType: o && o.contentType, upsert: o && o.upsert });
        if (st.objects[bucket + "/" + p] && !(o && o.upsert)) return { data: null, error: { message: "The resource already exists" } };
        st.objects[bucket + "/" + p] = Buffer.from(bytes);
        if (log) log.push("storage:upload");
        return { data: { path: p }, error: null };
      },
      remove: async paths => {
        if (log) log.push("storage:remove");
        st.removes.push({ bucket, paths: paths.slice() });
        if (st.failRemove) return { data: null, error: { message: "storage unavailable" } };
        paths.forEach(p => { delete st.objects[bucket + "/" + p]; });
        return { data: paths, error: null };
      },
      list: async (prefix, o) => {
        const keys = Object.keys(st.objects).filter(k => k.indexOf(bucket + "/") === 0).map(k => k.slice(bucket.length + 1));
        const pre = prefix ? prefix + "/" : "";
        const names = new Map();
        keys.filter(k => k.indexOf(pre) === 0).forEach(k => {
          const rest = k.slice(pre.length), slash = rest.indexOf("/");
          if (slash === -1) names.set(rest, { name: rest, id: "obj-" + rest, metadata: { size: 1 } });
          else names.set(rest.slice(0, slash), { name: rest.slice(0, slash), id: null, metadata: null });
        });
        const all = [...names.values()];
        return { data: all.slice((o && o.offset) || 0, ((o && o.offset) || 0) + ((o && o.limit) || 1000)), error: null };
      },
      createSignedUploadUrl: async p => { st.signed.push(p); return { data: { signedUrl: BASE + "/storage/v1/object/upload/sign/" + bucket + "/" + p + "?token=t", token: "t" }, error: null }; },
      getPublicUrl: p => ({ data: { publicUrl: BASE + "/storage/v1/object/public/" + bucket + "/" + encodeURI(p) } })
    };
  };
  return st;
}

/* ── the fixture ─────────────────────────────────────────────────────────── */
const OWEN = "0e0e0e0e-0000-4000-8000-000000000001", DANA = "da0da0da-0000-4000-8000-000000000002", LOU = "10101010-0000-4000-8000-000000000003";
const INACTIVE = new Set([LOU]);
const urlOf = p => BASE + "/storage/v1/object/public/bf-public/" + p;
function seed() {
  const t = { member_media: [], pending_storage_deletions: [], gate_decisions: [], users: [], profiles: [] };
  AFL.FILE_TABLES.forEach(x => { if (!t[x.table]) t[x.table] = []; });
  // NAMED (Nov 5 2026, images in social posts, migration 168): BEFORE no social_post_drafts table here. AFTER an empty one,
  // because findUses now also reads the member's pending social posts (scripts/checkSocialImages.js covers that case).
  t.social_post_drafts = [];
  // NAMED (Nov 7 2026, Instagram posting, migration 179): BEFORE no agent_proposals or instagram_posts here. AFTER empty ones,
  // because findUses now also reads Instagram proposals and posts (scripts/checkInstagramPosting.js covers those cases).
  t.agent_proposals = [];
  t.instagram_posts = [];
  t.users.push({ id: OWEN, avatar_url: null, business_name: "Owen Pottery" }, { id: DANA, avatar_url: null }, { id: LOU, avatar_url: null });
  return t;
}

/* ── server.js, lifted ───────────────────────────────────────────────────── */
function routeText(sig) {
  const start = SRC.indexOf(sig);
  if (start < 0 || SRC.indexOf(sig, start + 1) !== -1) return null;
  const fnAt = SRC.indexOf("function (req", start);
  const end = s.braceMatch(SRC, SRC.indexOf("{", fnAt));
  return SRC.slice(start, end) + ");";
}
function fnText(name) {
  const m = new RegExp("^(?:async )?function " + name + "\\(", "m").exec(SRC);
  if (!m) return null;
  return SRC.slice(m.index, s.braceMatch(SRC, SRC.indexOf(") {", m.index) + 2));
}
const R = {
  upload: routeText('app.post("/api/media",'),
  list: routeText('app.get("/api/media",'),
  usage: routeText('app.get("/api/media/usage",'),
  patch: routeText('app.patch("/api/media/:id",'),
  uses: routeText('app.get("/api/media/:id/uses",'),
  del: routeText('app.delete("/api/media/:id",'),
  uploadUrl: routeText('app.post("/api/bfp/upload-url",')
};
const STUB = new Set(["supabase", "console", "process", "require", "module", "app", "requireAuth", "getUserPlan", "rateLimit", "multer",
  "readThemeState", "profileDesignPhotoOf", "Date", "Math", "JSON", "Object", "Number", "String", "Array", "Promise", "Error", "Set", "Map", "URL", "Buffer"]);
function closure(root) {
  const have = new Map();
  const queue = [...new Set(root.match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || STUB.has(name)) continue;
    const def = s.definitionOf(SRC, name);
    if (!def) continue;
    try { new vm.Script(def); } catch (e) { continue; }
    have.set(name, def);
    new Set(def.match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !STUB.has(id)) queue.push(id); });
  }
  return [...have.values()].sort((x, y) => SRC.indexOf(x) - SRC.indexOf(y)).join("\n\n") + "\n\n" + root;
}
let CUR = makeDb(seed()), STO = makeStorage(CUR.log);
const ROUTES = {};
const CTX = {
  supabase: { from: t => CUR.from(t), get storage() { return STO; }, rpc: async () => ({ data: null, error: { code: "PGRST202" } }) },
  console: { log() {}, warn() {}, error() {} },
  process: { env: { SUPABASE_URL: BASE } },
  require: function (p) {
    if (p.indexOf("./") === 0) { const rel = p.slice(2).replace(/(\.js)?$/, ".js"); if (ALL[rel] !== undefined) return loadLib(rel); return realRequire(path.join(REPO, rel)); }
    return realRequire(p);
  },
  requireAuth: function requireAuth(req, res, next) { if (!req.user) return res.status(401).json({ error: "Authentication required" }); next(); },
  getUserPlan: async function (id) { return INACTIVE.has(id) ? { active: false, plan: null, subscription: null, inactive_reason: "no_subscription", access_reason: null } : { active: true, plan: "all_access", subscription: { status: "active" }, access_reason: "subscription" }; },
  rateLimit: function (opts) { const f = function limiter(req, res, next) { next(); }; f.opts = opts; return f; },
  multer: Object.assign(function (o) {
    return { single: field => function (req, res, cb) {
      const f = req.__file;
      if (f && f.fieldname !== field) { const e = new Error("Unexpected field"); e.code = "LIMIT_UNEXPECTED_FILE"; return cb(e); }
      if (f && o.limits && f.buffer.length > o.limits.fileSize) { const e = new Error("File too large"); e.code = "LIMIT_FILE_SIZE"; return cb(e); }
      req.file = f; cb();
    } };
  }, { memoryStorage: () => ({}) }),
  readThemeState: async () => ({ themes: [], prefs: {} }),
  profileDesignPhotoOf: async () => null,
  URL: URL, Buffer: Buffer,
  app: {}
};
["get", "post", "put", "patch", "delete", "use"].forEach(v => { CTX.app[v] = function (p) { ROUTES[v + " " + p] = Array.prototype.slice.call(arguments, 1); }; });
let LIFT_ERROR = null;
try {
  vm.createContext(CTX);
  const root = Object.values(R).concat([fnText("requireActiveSubscription"), fnText("sanitizeMedia"), fnText("removeDisplacedCardMedia"), fnText("removeUnusedThemePhotos")]).join("\n\n");
  vm.runInContext(closure(root), CTX);
} catch (e) { LIFT_ERROR = e; }

function mkRes() {
  return {
    statusCode: 200, body: undefined, ended: false, headers: {},
    status(c) { this.statusCode = c; return this; },
    json(b) { this.body = JSON.parse(JSON.stringify(b)); this.ended = true; return this; },
    send(t) { this.text = String(t); this.ended = true; return this; },
    set(k, v) { this.headers[k.toLowerCase()] = v; return this; }
  };
}
const tick = () => new Promise(r => setImmediate(r));
async function hit(key, user, opts) {
  opts = opts || {};
  const fns = ROUTES[key];
  if (!fns) return { status: 0, error: "no route " + key };
  const req = { method: key.split(" ")[0].toUpperCase(), user: user ? { id: user, role: "user" } : undefined, body: opts.body || {}, params: opts.params || {}, query: opts.query || {}, headers: {}, __file: opts.file };
  const res = mkRes();
  let err = null;
  for (let i = 0; i < fns.length; i++) {
    let advanced = false;
    await fns[i](req, res, e => { if (e) err = e; else advanced = true; });
    if (err || !advanced || res.ended) break;
  }
  for (let k = 0; k < 400 && !res.ended && !err; k++) await tick();
  if (err && !res.ended) { res.statusCode = 500; res.body = { error: String(err.message || err) }; }
  return { status: res.statusCode, body: res.body, err: err && (err.message || String(err)) };
}
const fileOf = (buf, mime, name) => ({ fieldname: "file", originalname: name || "photo.bin", mimetype: mime, buffer: buf, size: buf.length });
const upload = (user, buf, mime, name, body) => hit("post /api/media", user, { file: fileOf(buf, mime, name), body: body || {} });
const names = key => (ROUTES[key] || []).map(f => f.name);
function fresh() { CUR = makeDb(seed()); STO = makeStorage(CUR.log); }
const rows = () => CUR.t.member_media;
// rows already held, each within 167's 10 MB bytes CHECK, adding up to total
function holdBytes(user, total) {
  for (let left = total, k = 0; left > 0; k++) {
    const n = Math.min(left, 10485760);
    CUR.t.member_media.push({ id: crypto.randomUUID(), user_id: user, path: "media/" + user + "/" + crypto.randomBytes(16).toString("hex") + ".jpg", kind: "image", mime: "image/jpeg",
      bytes: n, sha256: crypto.randomBytes(32).toString("hex"), alt_text: "", label: "held " + k, metadata_stripped: true, created_at: "2026-11-01T00:00:00.000Z" });
    left -= n;
  }
}

/* ── jsdom ───────────────────────────────────────────────────────────────── */
let JSDOM = null;
try { JSDOM = realRequire("jsdom").JSDOM; } catch (e) { JSDOM = null; }
async function settle() { for (let i = 0; i < 20; i++) await tick(); }
const stripScripts = html => html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/g, "");

(async function main() {
  /* ════ S. sniffing ════ */
  console.log("\n══ S. what a file is, by its bytes ══");
  check("S0. the routes and helpers were lifted from server.js and run", !LIFT_ERROR && Object.values(R).every(Boolean), LIFT_ERROR ? LIFT_ERROR.stack : Object.keys(R).filter(k => !R[k]).join(","));
  const sn = b => MED.sniffMedia(b);
  check("S1. JPEG, PNG, GIF87a, GIF89a, WebP and WebM are told by their first bytes",
    sn(jpeg()) === "jpg" && sn(png()) === "png" && sn(GIF) === "gif" && sn(B("GIF87a", Buffer.alloc(10))) === "gif" && sn(webp()) === "webp" && sn(WEBM) === "webm",
    [sn(jpeg()), sn(png()), sn(GIF), sn(webp()), sn(WEBM)].join(","));
  const okBrands = ["isom", "iso2", "iso4", "iso5", "iso6", "mp41", "mp42", "avc1", "dash", "M4V "];
  check("S2. MP4 is \"ftyp\" at offset 4 with an ISO brand: all ten taken", okBrands.every(b => sn(mp4(b)) === "mp4"), okBrands.filter(b => sn(mp4(b)) !== "mp4").join(","));
  const badBrands = ["heic", "heix", "mif1", "msf1", "qt  ", "3gp4", "M4A ", "avif"];
  check("S3. HEIC/HEIF (heic, heix, mif1, msf1), QuickTime (\"qt  \") and every other brand are refused", badBrands.every(b => sn(mp4(b)) === null), badBrands.filter(b => sn(mp4(b)) !== null).join(","));
  check("S4. EBML with DocType matroska is refused; so are text, a PDF, an SVG, a BMP, an empty and a short file",
    sn(ebml("matroska")) === null && sn(Buffer.from("hello there, not an image at all")) === null && sn(B("%PDF-1.7\n", Buffer.alloc(20))) === null &&
    sn(Buffer.from("<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>")) === null && sn(B("BM", Buffer.alloc(30))) === null && sn(Buffer.alloc(0)) === null && sn(Buffer.from([0xff, 0xd8, 0xff])) === null);
  check("S5. checkFile: a type the bytes do not say is refused with the brief's sentence",
    refusedWith(() => MED.checkFile(fileOf(Buffer.from("plain text pretending to be a video"), "video/mp4"))) === "unsupported:415" &&
    MED.MESSAGES.unsupported === "That file type isn't supported. Use JPEG, PNG, WebP, GIF, MP4 or WebM.");
  check("S6. checkFile: a declared type that disagrees with the bytes is refused (a PNG sent as JPEG, a JPEG sent as PNG, a GIF sent as WebP)",
    refusedWith(() => MED.checkFile(fileOf(png(), "image/jpeg"))) === "mismatch:415" && refusedWith(() => MED.checkFile(fileOf(jpeg(), "image/png"))) === "mismatch:415" &&
    refusedWith(() => MED.checkFile(fileOf(GIF, "image/webp"))) === "mismatch:415");
  check("S7. checkFile: over 10 MB is 413 and an empty file is 400", refusedWith(() => MED.checkFile(fileOf(B(jpeg(), Buffer.alloc(10 * 1024 * 1024)), "image/jpeg"))) === "too_big:413" &&
    refusedWith(() => MED.checkFile(fileOf(Buffer.alloc(0), "image/jpeg"))) === "empty:400" && MED.MAX_FILE_BYTES === 10485760 && MED.MEMBER_MEDIA_BYTES === 250 * 1048576);

  /* ════ X. metadata removal ════ */
  console.log("\n══ X. location and camera details removed, image data untouched ══");
  const J0 = jpeg(), J1 = MED.stripMetadata(J0, "image/jpeg");
  const sosAt = b => { let i = 2; while (b[i + 1] !== 0xda) i += 2 + b.readUInt16BE(i + 2); return i; };
  check("X1. the JPEG test file carries Exif, a GPS IFD (tag 0x8825), XMP, IPTC and a comment before stripping",
    has(J0, "Exif\0\0") && has(J0, Buffer.from([0x88, 0x25])) && has(J0, "<x:xmpmeta") && has(J0, "Photoshop 3.0") && has(J0, "shot on a CamCo"));
  check("X2. after: no Exif header, no GPS IFD tag, no latitude, no XMP packet, no IPTC, no comment, no camera make; stripped true",
    J1.stripped === true && !has(J1.bytes, "Exif") && !has(J1.bytes, Buffer.from([0x88, 0x25])) && !has(J1.bytes, Buffer.from([0, 0, 0, 37, 0, 0, 0, 1])) && !has(J1.bytes, "xmpmeta") &&
    !has(J1.bytes, "ns.adobe.com") && !has(J1.bytes, "Photoshop") && !has(J1.bytes, "Lisbon") && !has(J1.bytes, "CamCo"));
  check("X3. APP0, APP2 (ICC colour) and every image segment are kept, in order: E0 E2 DB C0 C4 DA",
    J(jpegSegments(J1.bytes)) === J([0xe0, 0xe2, 0xdb, 0xc0, 0xc4, 0xda]), jpegSegments(J1.bytes).map(m => m.toString(16)).join(" "));
  check("X4. everything from SOS to the end is byte-identical", Buffer.compare(J1.bytes.subarray(sosAt(J1.bytes)), J0.subarray(sosAt(J0))) === 0 &&
    Buffer.compare(J1.bytes.subarray(0, 2), Buffer.from([0xff, 0xd8])) === 0);
  const P0 = png(), P1 = MED.stripMetadata(P0, "image/png");
  const idatOf = b => { let i = 8; while (i < b.length) { const n = b.readUInt32BE(i); if (b.toString("latin1", i + 4, i + 8) === "IDAT") return b.subarray(i, i + 12 + n); i += 12 + n; } return null; };
  check("X5. PNG: eXIf, tEXt, zTXt, iTXt and tIME are gone; IHDR, IDAT, IEND remain, each CRC valid",
    J(pngTypes(P1.bytes)) === J(["IHDR", "IDAT", "IEND"]) && P1.stripped === true && !has(P1.bytes, "37.775N") && !has(P1.bytes, "xmpmeta") &&
    pngTypes(P1.bytes).length === 3, J(pngTypes(P1.bytes)));
  check("X6. PNG: the signature and the IDAT chunk, length, data and CRC, are byte-identical", Buffer.compare(P1.bytes.subarray(0, 8), PNG_SIG) === 0 &&
    !!idatOf(P1.bytes) && Buffer.compare(idatOf(P1.bytes), idatOf(P0)) === 0);
  const W0 = webp(), W1 = MED.stripMetadata(W0, "image/webp");
  const wc = webpChunks(W1.bytes);
  check("X7. WebP: the EXIF and XMP chunks are gone; VP8X, ICCP and VP8 remain", J(wc.map(c => c.fourcc)) === J(["VP8X", "ICCP", "VP8 "]) && !has(W1.bytes, "CamCo") && !has(W1.bytes, "xmpmeta"), J(wc.map(c => c.fourcc)));
  check("X8. WebP: VP8X keeps its ICC flag (0x20) and loses EXIF (0x08) and XMP (0x04)", wc[0] && wc[0].data[0] === 0x20, wc[0] && wc[0].data[0].toString(16));
  check("X9. WebP: the RIFF size is the file's length less 8, and the VP8 data, with its pad byte, is byte-identical",
    W1.bytes.readUInt32LE(4) === W1.bytes.length - 8 && wc[2] && Buffer.compare(wc[2].data, VP8) === 0 && (W1.bytes.length % 2) === 0, W1.bytes.readUInt32LE(4) + " vs " + (W1.bytes.length - 8));
  check("X10. GIF, MP4 and WebM are stored exactly as they came, stripped false",
    ["image/gif", "video/mp4", "video/webm"].every((m, i) => { const src = [GIF, mp4("isom"), WEBM][i]; const r = MED.stripMetadata(src, m); return r.stripped === false && Buffer.compare(r.bytes, src) === 0; }));
  const truncJ = J0.subarray(0, 30);
  const malformed = [
    ["a JPEG cut inside its EXIF segment", truncJ, "image/jpeg"], ["a JPEG with no end marker", jpeg({ noEoi: true }), "image/jpeg"],
    ["a JPEG whose second segment is not a marker", B([0xff, 0xd8, 0xff, 0xe0, 0, 4, 1, 2], "garbage, not a segment"), "image/jpeg"],
    ["a PNG with a broken CRC", png({ badCrc: true }), "image/png"], ["a PNG with no IEND", png({ noIend: true }), "image/png"],
    ["a PNG whose first chunk is not IHDR", png({ idatFirst: true }), "image/png"], ["a WebP whose RIFF size runs past the file", webp({ badSize: true }), "image/webp"],
    ["a WebP cut in its first chunk", webp().subarray(0, 24), "image/webp"]];
  const notRefused = malformed.filter(([, b, m]) => refusedWith(() => MED.checkFile(fileOf(b, m))) !== "unreadable:422");
  check("X11. a photo that does not parse cleanly is refused (422), never stored unstripped: " + malformed.map(x => x[0]).join("; "), notRefused.length === 0,
    notRefused.map(x => x[0] + " -> " + refusedWith(() => MED.checkFile(fileOf(x[1], x[2])))).join(" | "));
  fresh();
  const badUp = await upload(OWEN, jpeg({ noEoi: true }), "image/jpeg", "broken.jpg");
  check("X12. ... and through the route: 422 with the message, nothing uploaded, no row", badUp.status === 422 && badUp.body.error === MED.MESSAGES.unreadable && STO.uploads.length === 0 && rows().length === 0, J(badUp));

  /* ════ M. migration 167 and the path ════ */
  console.log("\n══ M. migration 167, and the path ══");
  const SQL_AS_RUN = "CREATE TABLE public.member_media (\n  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),\n  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,\n" +
    "  path text NOT NULL UNIQUE,\n  kind text NOT NULL CHECK (kind IN ('image', 'video')),\n" +
    "  mime text NOT NULL CHECK (mime IN ('image/jpeg', 'image/png', 'image/webp', 'image/gif', 'video/mp4', 'video/webm')),\n" +
    "  bytes integer NOT NULL CHECK (bytes > 0 AND bytes <= 10485760),\n  sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),\n" +
    "  alt_text text NOT NULL DEFAULT '' CHECK (char_length(alt_text) <= 1000),\n  label text NOT NULL DEFAULT '' CHECK (char_length(label) <= 120),\n" +
    "  metadata_stripped boolean NOT NULL DEFAULT false,\n  created_at timestamptz NOT NULL DEFAULT now(),\n" +
    "  CONSTRAINT member_media_path_check CHECK (path ~ '^media/[0-9a-f-]{36}/[0-9a-f]{32}\\.(jpg|png|webp|gif|mp4|webm)$'),\n" +
    "  CONSTRAINT member_media_path_owner_check CHECK (path LIKE 'media/' || user_id::text || '/%'),\n  CONSTRAINT member_media_user_sha_key UNIQUE (user_id, sha256)\n);\n\n" +
    "CREATE INDEX member_media_user_created_idx ON public.member_media (user_id, created_at DESC);\n\nALTER TABLE public.member_media ENABLE ROW LEVEL SECURITY;\n";
  check("M1. 167_member_media.sql says the owner applied it by hand on Nov 4, 2026, and ends with the SQL as run, the backslash in the path pattern included",
    ALL[MIG].indexOf("Applied by the owner by hand in the Supabase SQL editor on Nov 4, 2026. This file is the text as run.") !== -1 && ALL[MIG].endsWith(SQL_AS_RUN) && ALL[MIG].indexOf("{32}\\.(jpg") !== -1);
  const migFiles = fs.readdirSync(path.join(REPO, "supabase/migrations")).filter(f => /^\d+_/.test(f));
  // NAMED (Nov 5 2026, images in social posts, migration 168): BEFORE "the highest" with every migration at most 167. AFTER 167 is
  // still the only one numbered 167, and every migration but 168_social_post_images.sql is at most 167; "the highest" is checkSocialImages M2's.
  // NAMED (Nov 5 2026, mailbox connection, migration 169): BEFORE every migration but 168 at most 167. AFTER
  // 169_member_email_connections.sql too; "the highest" is checkMailboxConnect M2's.
  // NAMED (Nov 5 2026, mailbox replies, migration 170): BEFORE every migration but 168 and 169 at most 167. AFTER
  // 170_member_email_replies.sql too; "the highest" is checkMailboxReply M2's.
  // NAMED (Nov 6 2026, card upgrades C1, migration 171): BEFORE every migration but 168, 169 and 170 at most 167. AFTER
  // 171_card_counts.sql too; "the highest" is checkCardUpgrades R1's.
  // NAMED (Nov 6 2026, card upgrades C2, migration 172): BEFORE 171_card_counts.sql was the last allowed above 167. AFTER
  // 172_card_leads.sql too; "the highest" is checkCardLeads R1's.
  // NAMED (Nov 6 2026, Outlook sign-in, migration 173): BEFORE 172_card_leads.sql was the last allowed above 167. AFTER
  // 173_mailbox_microsoft.sql too; "the highest" is checkMailboxOutlook R1's.
  // NAMED (Nov 6 2026, Google Wallet, migration 174): BEFORE 173_mailbox_microsoft.sql was the last allowed above 167. AFTER
  // 174_card_wallet_count.sql too; "the highest" is checkGoogleWallet R1's.
  // NAMED (Nov 6 2026, store changes, migration 175): 175_store_changes.sql is allowed too; "the highest" is checkStoreChanges R1's.
  check("M2. 167_member_media.sql is the only migration numbered 167, and every other migration but 168_social_post_images.sql, 169_member_email_connections.sql, 170_member_email_replies.sql, 171_card_counts.sql, 172_card_leads.sql, 173_mailbox_microsoft.sql and 174_card_wallet_count.sql is at most 167",
    migFiles.filter(f => /^167_/.test(f)).length === 1 && migFiles.indexOf("167_member_media.sql") !== -1 && migFiles.every(f => f === "168_social_post_images.sql" || f === "169_member_email_connections.sql" || f === "170_member_email_replies.sql" || f === "171_card_counts.sql" || f === "172_card_leads.sql" || f === "173_mailbox_microsoft.sql" || f === "174_card_wallet_count.sql" || f === "175_store_changes.sql" || /* NAMED (Nov 7 2026, Shopify on OAuth, migration 176): 176 is allowed too; "the highest" is checkShopifyConnect R1's. */ f === "176_shopify_oauth.sql" || /* NAMED (Nov 7 2026, YouTube uploads, migration 177): 177 is allowed too; "the highest" is checkYoutubeUploads R1's. */ f === "177_youtube_uploads.sql" || /* NAMED (Nov 7 2026, TikTok posting, migration 178): 178 is allowed too; "the highest" is checkTiktokPosting R1's. */ f === "178_tiktok_posting.sql" || /* NAMED (Nov 7 2026, Instagram posting, migration 179): 179 is allowed too; "the highest" is checkInstagramPosting R1's. */ f === "179_instagram_posting.sql" || Number(f.split("_")[0]) <= 167) && migFiles.some(f => /^166_/.test(f)));
  check("M3. PATH_PATTERN equals the 167 CHECK character for character", !!SQL_PATH && MED.PATH_PATTERN === SQL_PATH[1] && MED.PATH_RE.source === PATH_SQL_RE.source, SQL_PATH && SQL_PATH[1]);
  const many = Array.from({ length: 300 }, (_, i) => MED.mediaPath(OWEN, ["jpg", "png", "webp", "gif", "mp4", "webm"][i % 6]));
  check("M4. 300 paths each match the 167 pattern and the owner rule, under media/<id>/, and no two are the same",
    many.every(p => PATH_SQL_RE.test(p) && p.indexOf("media/" + OWEN + "/") === 0) && new Set(many).size === 300, many[0]);
  let asked = [];
  const fixed = MED.mediaPath(OWEN, "png", n => { asked.push(n); return Buffer.alloc(n, 0xab); });
  check("M5. the random part is 16 bytes of crypto.randomBytes, as 32 hex; no Math.random in lib/memberMedia.js or the routes",
    J(asked) === "[16]" && fixed === "media/" + OWEN + "/" + "ab".repeat(16) + ".png" && /\(randomBytes \|\| crypto\.randomBytes\)\(16\)/.test(ALL[MM]) &&
    ALL[MM].replace(/\/\*[\s\S]*?\*\//g, "").indexOf("Math.random") === -1 && [R.upload, R.del].join("").indexOf("Math.random") === -1);

  /* ════ U. upload ════ */
  console.log("\n══ U. upload ══");
  fresh();
  const up1 = await upload(OWEN, J0, "image/jpeg", "my-secret-vacation-home.jpg", { label: "  Kiln photo  ", alt_text: "A blue kiln" });
  const r1 = rows()[0];
  const obj1 = r1 && STO.objects["bf-public/" + r1.path];
  check("U1. a JPEG is stored: 201 { item }, one row, one object, stored as image/jpeg with upsert false", up1.status === 201 && rows().length === 1 && !!obj1 &&
    STO.uploads.length === 1 && STO.uploads[0].contentType === "image/jpeg" && STO.uploads[0].upsert === false && STO.uploads[0].bucket === "bf-public", J(up1));
  check("U2. what is stored is the stripped file: no Exif, no XMP, the image bytes intact; metadata_stripped true",
    !!obj1 && !has(obj1, "Exif") && !has(obj1, "xmpmeta") && Buffer.compare(obj1, J1.bytes) === 0 && r1.metadata_stripped === true && r1.bytes === J1.bytes.length);
  check("U3. sha256 is of the stored bytes", !!r1 && r1.sha256 === crypto.createHash("sha256").update(J1.bytes).digest("hex"));
  check("U4. the path is media/<id>/<32 hex>.jpg and never carries the file's own name", !!r1 && PATH_SQL_RE.test(r1.path) && !/secret|vacation|home/i.test(r1.path), r1 && r1.path);
  check("U5. the label and alt text are trimmed and kept", !!r1 && r1.label === "Kiln photo" && r1.alt_text === "A blue kiln");
  const LIST_KEYS = J(["alt_text", "bytes", "created_at", "id", "kind", "label", "metadata_stripped", "mime", "url"]);
  check("U6. the item answered: id, url, kind, mime, bytes, label, alt_text, metadata_stripped, created_at; never user_id, sha256 or path",
    !!up1.body && !!up1.body.item && J(Object.keys(up1.body.item).sort()) === LIST_KEYS && up1.body.item.url === urlOf(r1.path), J(up1.body));
  const again = await upload(OWEN, J0, "image/jpeg", "again.jpg");
  const otherExif = await upload(OWEN, jpeg({ noXmp: true }), "image/jpeg", "same-photo-other-metadata.jpg");
  check("U7. dedupe: the same file again is 200 { item, duplicate: true }, the same item, and nothing new stored",
    again.status === 200 && again.body.duplicate === true && again.body.item.id === r1.id && STO.uploads.length === 1 && rows().length === 1, J(again));
  check("U8. ... and the same photo with different metadata strips to the same bytes, so it is the same item too",
    otherExif.status === 200 && otherExif.body.duplicate === true && otherExif.body.item.id === r1.id && STO.uploads.length === 1);
  const kinds = [[png(), "image/png", "image"], [webp(), "image/webp", "image"], [GIF, "image/gif", "image"], [mp4("mp42"), "video/mp4", "video"], [WEBM, "video/webm", "video"]];
  const got = [];
  for (const [b, m] of kinds) got.push(await upload(OWEN, b, m, "f"));
  check("U9. PNG, WebP, GIF, MP4 and WebM are each stored under their own kind and type; GIF and video unstripped",
    got.every((r, i) => r.status === 201 && r.body.item.mime === kinds[i][1] && r.body.item.kind === kinds[i][2]) &&
    got.map(r => r.body.item.metadata_stripped).join() === "true,true,false,false,false", got.map(r => r.status + ":" + (r.body.item && r.body.item.mime)).join(","));
  const heic = await upload(OWEN, mp4("heic"), "video/mp4", "IMG_0001.HEIC");
  const lie = await upload(OWEN, png(), "image/jpeg", "x.jpg");
  check("U10. a HEIC is refused with the sentence; a declared type that lies is refused; nothing stored for either",
    heic.status === 415 && heic.body.error === MED.MESSAGES.unsupported && lie.status === 415 && lie.body.reason === "mismatch" && STO.uploads.length === 6, heic.status + " " + lie.status);
  const big = await upload(OWEN, B(jpeg(), Buffer.alloc(10 * 1024 * 1024)), "image/jpeg", "big.jpg");
  check("U11. over 10 MB: 413 from the upload limit, \"A file is at most 10 MB.\"", big.status === 413 && big.body.error === "A file is at most 10 MB.", J(big));
  const noFile = await hit("post /api/media", OWEN, {});
  check("U12. no file: 400 \"Choose a file to upload.\"", noFile.status === 400 && noFile.body.error === MED.MESSAGES.empty, J(noFile));

  // the quota
  fresh();
  const CAP = MED.MEMBER_MEDIA_BYTES;
  holdBytes(OWEN, CAP - 50);
  const full = await upload(OWEN, png(), "image/png", "p.png");
  check("U13. the quota before the upload: a file that would pass 250 MB is 413, and nothing is uploaded", full.status === 413 && full.body.error === MED.MESSAGES.full && STO.uploads.length === 0, J(full));
  fresh();
  const size = MED.checkFile(fileOf(png(), "image/png")).size;
  holdBytes(OWEN, CAP - size - Math.floor(size / 2));
  const race = await Promise.all([upload(OWEN, png(), "image/png", "a.png"), upload(OWEN, webp(), "image/webp", "b.webp")]);
  const kept = rows().filter(r => !/^held /.test(r.label));
  check("U14. two uploads racing past the cap: one is kept (201), the other is removed and refused (413); storage holds only the one kept",
    race.map(r => r.status).sort().join() === "201,413" && kept.length === 1 && Object.keys(STO.objects).length === 1 && STO.objects["bf-public/" + kept[0].path] !== undefined,
    race.map(r => r.status).join() + " rows " + kept.length + " objects " + Object.keys(STO.objects).length);
  check("U15. ... the total held never stays over 250 MB", rows().reduce((a, r) => a + r.bytes, 0) <= CAP);
  fresh();
  CUR.failInsert = "member_media";
  const failIns = await upload(OWEN, png(), "image/png", "p.png");
  check("U16. when the insert fails, the file just uploaded is removed: no object, no row", failIns.status === 500 && STO.uploads.length === 1 && Object.keys(STO.objects).length === 0 && rows().length === 0,
    failIns.status + " objects " + Object.keys(STO.objects).length);
  CUR.failInsert = null;
  fresh();
  const anon = await upload(null, png(), "image/png");
  const lapsed = await upload(LOU, png(), "image/png");
  check("U17. signed out is 401; without a subscription 402; nothing stored for either", anon.status === 401 && lapsed.status === 402 && STO.uploads.length === 0 && rows().length === 0, anon.status + " " + lapsed.status);
  const upMw = ROUTES["post /api/media"] || [];
  check("U18. POST /api/media is requireAuth, requireActiveSubscription, then a limiter keyed media-upload:<id>, 60 an hour",
    J(names("post /api/media").slice(0, 2)) === J(["requireAuth", "requireActiveSubscription"]) && !!upMw[2] && !!upMw[2].opts && upMw[2].opts.max === 60 &&
    upMw[2].opts.windowMs === 3600000 && upMw[2].opts.keyGenerator({ user: { id: "x" } }) === "media-upload:x", J(names("post /api/media")));
  check("U19. multer: memory storage, 10 MB, one file, field \"file\"", /const mediaUpload = multer\(\{\n  storage: multer\.memoryStorage\(\),\n  limits: \{ fileSize: memberMedia\.MAX_FILE_BYTES, files: 1 \}\n\}\);/.test(SRC) &&
    R.upload && R.upload.indexOf("mediaUpload.single(\"file\")") !== -1);
  const order = ["memberMedia.checkFile(", "eq(\"sha256\", checked.sha256)", "memberMedia.usage(supabase, userId)", ".upload(path, checked.bytes, { contentType: checked.mime, upsert: false })",
    "from(\"member_media\").insert(", "memberMedia.overCap("].map(x => (R.upload || "").indexOf(x));
  check("U20. the steps are in order: sniff, strip and hash; dedupe; the quota; the upload; the row; the quota again",
    order.every(i => i !== -1) && order.every((x, i) => i === 0 || x > order[i - 1]), J(order));
  check("U21. checkFile sniffs, compares, strips, then hashes the stripped bytes", (() => { const t = ALL[MM]; const a = t.indexOf("function checkFile"); const x = ["sniffMedia(file.buffer)", "file.mimetype !== t.mime", "stripMetadata(file.buffer", "update(s.bytes)"].map(n => t.indexOf(n, a)); return x.every(i => i > a) && x.every((v, i) => i === 0 || v > x[i - 1]); })());

  /* ════ L. list, usage, edit ════ */
  console.log("\n══ L. list, usage, label and alt text ══");
  fresh();
  const mk = (user, n, kind) => ({ id: crypto.randomUUID(), user_id: user, path: "media/" + user + "/" + crypto.randomBytes(16).toString("hex") + (kind === "video" ? ".mp4" : ".png"),
    kind: kind || "image", mime: kind === "video" ? "video/mp4" : "image/png", bytes: 1000 + n, sha256: crypto.randomBytes(32).toString("hex"), alt_text: "", label: "item " + n,
    metadata_stripped: kind !== "video", created_at: new Date(Date.parse("2026-10-01T00:00:00Z") + n * 60000).toISOString() });
  for (let i = 0; i < 61; i++) CUR.t.member_media.push(mk(OWEN, i, i % 10 === 0 ? "video" : "image"));
  CUR.t.member_media.push(mk(DANA, 99));
  const p1 = await hit("get /api/media", OWEN, {});
  const p2 = await hit("get /api/media", OWEN, { query: { before: p1.body && p1.body.next_before } });
  check("L1. newest first, 60 a page, next_before then the last one", p1.status === 200 && p1.body.items.length === 60 && p1.body.items[0].label === "item 60" && !!p1.body.next_before &&
    p2.body.items.length === 1 && p2.body.items[0].label === "item 0" && p2.body.next_before === null, p1.body && p1.body.items && p1.body.items.length);
  check("L2. each item is exactly id, url, kind, mime, bytes, label, alt_text, metadata_stripped, created_at: no user_id, sha256 or path",
    p1.body.items.every(i => J(Object.keys(i).sort()) === LIST_KEYS) && J(p1.body).indexOf("sha256") === -1 && J(p1.body).indexOf(OWEN.slice(9)) === -1 ||
    p1.body.items.every(i => J(Object.keys(i).sort()) === LIST_KEYS && i.url.indexOf("/media/" + OWEN + "/") !== -1) && J(p1.body).indexOf("sha256") === -1 && J(p1.body).indexOf("\"user_id\"") === -1,
    J(p1.body.items[0]));
  check("L3. only the member's own: Dana's item is in no page of Owen's, and Dana sees only hers",
    p1.body.items.concat(p2.body.items).every(i => i.label !== "item 99") && (await hit("get /api/media", DANA, {})).body.items.map(i => i.label).join() === "item 99");
  const vids = await hit("get /api/media", OWEN, { query: { kind: "video" } });
  const badQ = await Promise.all([hit("get /api/media", OWEN, { query: { kind: "audio" } }), hit("get /api/media", OWEN, { query: { before: "not a date" } })]);
  check("L4. ?kind=video lists the 7 videos; an unknown kind or a bad before is 400", vids.body.items.length === 7 && vids.body.items.every(i => i.kind === "video") && badQ.every(r => r.status === 400));
  const us = await hit("get /api/media/usage", OWEN, {});
  check("L5. usage: { used_bytes, cap_bytes, count } of the member's own", us.status === 200 && J(Object.keys(us.body).sort()) === J(["cap_bytes", "count", "used_bytes"]) && us.body.count === 61 &&
    us.body.cap_bytes === CAP && us.body.used_bytes === rows().filter(r => r.user_id === OWEN).reduce((a, r) => a + r.bytes, 0), J(us.body));
  const mine = rows().find(r => r.user_id === OWEN), hers = rows().find(r => r.user_id === DANA);
  const ed = await hit("patch /api/media/:id", OWEN, { params: { id: mine.id }, body: { label: "  Studio  ", alt_text: "  A potter at a wheel  " } });
  check("L6. PATCH trims and saves the label and alt text", ed.status === 200 && mine.label === "Studio" && mine.alt_text === "A potter at a wheel" && ed.body.item.label === "Studio", J(ed));
  const lim = await Promise.all([hit("patch /api/media/:id", OWEN, { params: { id: mine.id }, body: { label: "x".repeat(121) } }),
    hit("patch /api/media/:id", OWEN, { params: { id: mine.id }, body: { alt_text: "y".repeat(1001) } }),
    hit("patch /api/media/:id", OWEN, { params: { id: mine.id }, body: { label: 7 } }), hit("patch /api/media/:id", OWEN, { params: { id: mine.id }, body: {} })]);
  const at = await hit("patch /api/media/:id", OWEN, { params: { id: mine.id }, body: { label: "z".repeat(120), alt_text: "w".repeat(1000) } });
  check("L7. a label over 120 or alt text over 1000 characters, a non-string and an empty body are 400; exactly 120 and 1000 are saved",
    lim.map(r => r.status).join() === "400,400,400,400" && lim[0].body.error === MED.MESSAGES.labelLong && lim[1].body.error === MED.MESSAGES.altLong && at.status === 200 && mine.label.length === 120,
    lim.map(r => r.status + ":" + (r.body && r.body.error)).join(" | "));
  const foreign = await Promise.all([hit("patch /api/media/:id", OWEN, { params: { id: hers.id }, body: { label: "mine now" } }),
    hit("get /api/media/:id/uses", OWEN, { params: { id: hers.id } }), hit("delete /api/media/:id", OWEN, { params: { id: hers.id } }),
    hit("patch /api/media/:id", OWEN, { params: { id: "not-a-uuid" }, body: { label: "x" } })]);
  check("L8. another member's item is 404 on PATCH, uses and DELETE, and is unchanged; a malformed id is 404",
    foreign.every(r => r.status === 404) && hers.label === "item 99" && rows().indexOf(hers) !== -1 && STO.removes.length === 0, foreign.map(r => r.status).join());
  const anonAll = await Promise.all(["get /api/media", "get /api/media/usage", "patch /api/media/:id", "get /api/media/:id/uses", "delete /api/media/:id"].map(k => hit(k, null, { params: { id: mine.id } })));
  check("L9. every route is 401 signed out", anonAll.every(r => r.status === 401), anonAll.map(r => r.status).join());
  const lapsedOk = await Promise.all([hit("get /api/media", LOU, {}), hit("get /api/media/usage", LOU, {})]);
  check("L10. without a subscription, listing and usage still answer (only uploading needs one)", lapsedOk.every(r => r.status === 200) &&
    ["get /api/media", "get /api/media/usage", "patch /api/media/:id", "get /api/media/:id/uses", "delete /api/media/:id"].every(k => names(k).indexOf("requireActiveSubscription") === -1 && names(k)[0] === "requireAuth"));

  /* ════ D. delete ════ */
  console.log("\n══ D. delete: never while in use; the file first, then the row ══");
  fresh();
  await upload(OWEN, J0, "image/jpeg", "k.jpg", { label: "Kiln" });
  const item = rows()[0], itemUrl = urlOf(item.path);
  CUR.t.crowdfunding_campaigns.push({ id: "c-1", owner_id: OWEN, title: "Kiln fund", media: [{ url: itemUrl, type: "image", name: "Kiln" }] });
  CUR.t.digital_cards.push({ id: "d-1", user_id: OWEN, full_name: "Owen Oak", bg_image_url: itemUrl });
  CUR.t.crowdfunding_campaigns.push({ id: "c-2", owner_id: DANA, title: "Dana's secret plan", media: [{ url: itemUrl, type: "image", name: "x" }] });
  const usesR = await hit("get /api/media/:id/uses", OWEN, { params: { id: item.id } });
  check("D1. where used: the member's own campaign and card, by title; never another member's row",
    usesR.status === 200 && J(usesR.body.uses) === J([{ place: "A digital card", title: "Owen Oak" }, { place: "A crowdfunding campaign", title: "Kiln fund" }].sort((a, b) => 0)) ||
    usesR.status === 200 && usesR.body.uses.length === 2 && usesR.body.uses.some(u => u.place === "A crowdfunding campaign" && u.title === "Kiln fund") &&
    usesR.body.uses.some(u => u.place === "A digital card" && u.title === "Owen Oak") && J(usesR.body).indexOf("Dana") === -1, J(usesR.body));
  const inUse = await hit("delete /api/media/:id", OWEN, { params: { id: item.id } });
  check("D2. in use: 409 { uses } with \"This file is used in: ...\", and the file and row stay", inUse.status === 409 && Array.isArray(inUse.body.uses) && inUse.body.uses.length === 2 &&
    /^This file is used in: /.test(inUse.body.error) && /Kiln fund/.test(inUse.body.error) && rows().length === 1 && !!STO.objects["bf-public/" + item.path] && STO.removes.length === 0, J(inUse.body));
  CUR.t.crowdfunding_campaigns = CUR.t.crowdfunding_campaigns.filter(c => c.owner_id !== OWEN);
  CUR.t.digital_cards = [];
  CUR.log.length = 0;
  const gone = await hit("delete /api/media/:id", OWEN, { params: { id: item.id } });
  const iRemove = CUR.log.indexOf("storage:remove"), iRow = CUR.log.findIndex(x => /^member_media:delete/.test(x));
  check("D3. unused (another member's row naming it does not count): the file is removed first, then the row", gone.status === 200 && gone.body.deleted === true &&
    rows().length === 0 && !STO.objects["bf-public/" + item.path] && iRemove !== -1 && iRow !== -1 && iRemove < iRow, J(gone) + " " + CUR.log.join(","));
  fresh();
  await upload(OWEN, png(), "image/png", "p.png");
  const it2 = rows()[0];
  STO.failRemove = true;
  const queued = await hit("delete /api/media/:id", OWEN, { params: { id: it2.id } });
  check("D4. when Storage refuses, the file is queued in pending_storage_deletions and the row is still deleted",
    queued.status === 200 && queued.body.queued === true && rows().length === 0 && CUR.t.pending_storage_deletions.some(p => p.bucket === "bf-public" && p.path === it2.path), J(queued) + " " + J(CUR.t.pending_storage_deletions));
  STO.failRemove = false;
  fresh();
  await upload(OWEN, png(), "image/png", "p.png");
  CUR.failRead = "crowdfunding_campaigns";
  const unknownUse = await hit("delete /api/media/:id", OWEN, { params: { id: rows()[0].id } });
  CUR.failRead = null;
  check("D5. when a table cannot be read, nothing is deleted: 503", unknownUse.status === 503 && rows().length === 1 && STO.removes.length === 0, J(unknownUse));
  check("D6. where used is read from every table lib/accountFiles.js FILE_TABLES lists, by its owner column",
    R.uses && /memberMedia\.findUses\(supabase, req\.user\.id, item\.path\)/.test(R.uses) && /for \(var t of accountFiles\.FILE_TABLES\)/.test(ALL[MM]) && /\.eq\(t\.owner, userId\)/.test(ALL[MM]));

  /* ════ R. elsewhere ════ */
  console.log("\n══ R. sanitizeMedia, upload-url, card and theme cleanups, account deletion ══");
  const own = urlOf("media/" + OWEN + "/" + "c".repeat(32) + ".jpg"), ownUpload = urlOf("marketplace-media/" + OWEN + "/1730000000_kiln.jpg");
  const raw = [{ url: own, type: "image", name: "a" }, { url: ownUpload, type: "image/jpeg", name: "b" },
    { url: urlOf("media/" + DANA + "/" + "d".repeat(32) + ".jpg"), type: "image", name: "hers" },
    { url: "https://evil.example.com/storage/v1/object/public/bf-public/media/" + OWEN + "/" + "c".repeat(32) + ".jpg", type: "image", name: "foreign" },
    { url: own.replace("https://", "http://"), type: "image", name: "http" }, { url: own + "?download=1", type: "image", name: "query" },
    { url: BASE + "/storage/v1/object/public/bf-books/" + OWEN + "/x.png", type: "image", name: "other bucket" },
    { url: urlOf("media/../" + OWEN + "/x/y.jpg"), type: "image", name: "dots" }, { url: "javascript:alert(1)", type: "image", name: "js" }];
  const kept2 = CTX.sanitizeMedia(raw, OWEN);
  check("R1. sanitizeMedia keeps only the caller's own bf-public files (the library and their own uploads), never another member's, a foreign host, http, a query, another bucket or a script URL",
    J(kept2.map(m => m.name)) === J(["a", "b"]), J(kept2.map(m => m.name)));
  check("R2. all five callers pass the caller's id (the listing and campaign creates and edits, and the agent's listing)",
    (SRC.match(/sanitizeMedia\(req\.body\.media, req\.user\.id\)/g) || []).length === 4 && (SRC.match(/sanitizeMedia\(payload\.media, proposal\.user_id\)/g) || []).length === 1 &&
    (SRC.match(/sanitizeMedia\(/g) || []).length === 6);
  fresh();
  const uu = async folder => hit("post /api/bfp/upload-url", OWEN, { body: { folder: folder, filename: "x.png", contentType: "image/png" } });
  const okFolders = ["marketplace-media", "card-media", "banners", "avatars", "videos", "music", "music-art", "products", "portfolio"];
  const okR = []; for (const f of okFolders) okR.push(await uu(f));
  const badR = []; for (const f of ["media", "misc", "avatars/" + DANA, "theme-photos", "", undefined, "../avatars", "Avatars"]) badR.push(await uu(f));
  check("R3. upload-url: the nine page folders answer a signed URL under <folder>/<own id>/", okR.every((r, i) => r.status === 200 && r.body.path.indexOf(okFolders[i] + "/" + OWEN + "/") === 0), okR.map(r => r.status).join());
  check("R4. upload-url: media, misc, a path with \"/\", theme-photos, empty, missing and a wrong case are 400, and no URL is signed",
    badR.every(r => r.status === 400) && STO.signed.length === okFolders.length, badR.map(r => r.status).join());
  fresh();
  const libUrl = urlOf("media/" + OWEN + "/" + "e".repeat(32) + ".jpg"), cardUrl = urlOf("card-media/" + OWEN + "/1730000000_bg.png");
  await CTX.removeDisplacedCardMedia({ bg_image_url: libUrl, still_image_url: cardUrl, video_url: null, audio_url: null }, null, OWEN, "check");
  const removedKeys = STO.removes.reduce((a, r) => a.concat(r.paths), []);
  check("R5. a card's displaced media: its own card-media file is removed, a Media Library file never is",
    removedKeys.indexOf("card-media/" + OWEN + "/1730000000_bg.png") !== -1 && removedKeys.every(k => k.indexOf("media/") !== 0), J(removedKeys));
  fresh();
  await CTX.removeUnusedThemePhotos(OWEN, ["media/" + OWEN + "/" + "f".repeat(32) + ".jpg", "theme-photos/" + OWEN + "/1730000000000.jpg"]);
  const themeKeys = STO.removes.reduce((a, r) => a.concat(r.paths), []);
  check("R6. an unused theme photo is removed, a Media Library file never is", themeKeys.indexOf("theme-photos/" + OWEN + "/1730000000000.jpg") !== -1 && themeKeys.every(k => k.indexOf("media/") !== 0) &&
    /!memberMedia\.isLibraryKey\(p\)/.test(fnText("removeUnusedThemePhotos") || ""), J(themeKeys));
  fresh();
  ["media/" + OWEN + "/" + "1".repeat(32) + ".jpg", "media/" + OWEN + "/" + "2".repeat(32) + ".mp4", "media/" + DANA + "/" + "3".repeat(32) + ".jpg", "avatars/" + OWEN + "/1_a.png"]
    .forEach(k => { STO.objects["bf-public/" + k] = Buffer.from("x"); });
  const owned = await AFL.filesOwnedBy({ supabase: { from: t => CUR.from(t) }, storage: STO, userId: OWEN, publicUrlBase: BASE });
  const ownedKeys = owned.filter(f => f.bucket === "bf-public").map(f => f.path).sort();
  check("R7. account deletion lists media/<id>/ (both files), and never another member's media/",
    J(ownedKeys) === J(["avatars/" + OWEN + "/1_a.png", "media/" + OWEN + "/" + "1".repeat(32) + ".jpg", "media/" + OWEN + "/" + "2".repeat(32) + ".mp4"]), J(ownedKeys));
  check("R8. ... by name (MEDIA_FOLDER), so a root listing that misses it still finds it; and member_media rows go with the account (yourData, ON DELETE CASCADE)",
    AFL.MEDIA_FOLDER === "media" && /REFERENCES public\.users\(id\) ON DELETE CASCADE/.test(ALL[MIG]));

  /* ════ F. the pages ════ */
  console.log("\n══ F. media.html, the library script and the picker ══");
  const page = fe("media.html") || "", mlJs = fe("scripts/media-library.js") || "", mpJs = fe("scripts/media-picker.js") || "";
  const NOTE_A = "Location and camera details are removed from JPEG, PNG and WebP photos before they are saved. Videos and GIFs are saved as they are.";
  const NOTE_B = "Anyone who has a file's link can open it.";
  check("F1. media.html is \"Media Library\", with the two notices word for word, the Upload button and the file input's six types",
    /<title>BizForce AI — Media Library<\/title>/.test(page) && /<h1 class="hero-title">Media Library<\/h1>/.test(page) && page.indexOf(">" + NOTE_A + "<") !== -1 && page.indexOf(">" + NOTE_B + "<") !== -1 &&
    page.indexOf('<input type="file" id="mlFile" accept="image/jpeg,image/png,image/webp,image/gif,video/mp4,video/webm"') !== -1 && /id="mlUploadBtn">Upload<\/button>/.test(page));
  check("F2. no innerHTML, insertAdjacentHTML or document.write in the page or either script",
    [page, mlJs, mpJs].every(t => !/innerHTML|insertAdjacentHTML|document\.write/.test(t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/<!--[\s\S]*?-->/g, "").replace(/^\s*\/\/.*$/gm, ""))));
  check("F3. the page loads its script, the guide and the legal footer, and bf-theme.js first in <head>", page.indexOf('<script src="/scripts/media-library.js"></script>') !== -1 &&
    page.indexOf("<head>\n<script src=\"/scripts/bf-theme.js\"></script>") !== -1 && page.indexOf("/scripts/termaximus-guide.js") !== -1 && page.indexOf("/scripts/bf-legal-footer.js") !== -1);
  if (JSDOM) {
    const HOSTILE = "<img src=x onerror=alert(1)>";
    const ITEMS = [{ id: "11111111-1111-4111-8111-111111111111", url: urlOf("media/" + OWEN + "/" + "a".repeat(32) + ".jpg"), kind: "image", mime: "image/jpeg", bytes: 2 * 1048576, label: HOSTILE, alt_text: "A blue kiln", metadata_stripped: true, created_at: "2026-11-04T00:00:00Z" },
      { id: "22222222-2222-4222-8222-222222222222", url: urlOf("media/" + OWEN + "/" + "b".repeat(32) + ".mp4"), kind: "video", mime: "video/mp4", bytes: 5 * 1048576, label: "Tour", alt_text: "", metadata_stripped: false, created_at: "2026-11-03T00:00:00Z" }];
    async function libraryPage(answers) {
      const dom = new JSDOM(stripScripts(page), { url: "https://bizforceai.net/media.html", runScripts: "outside-only" });
      const w = dom.window, log = { fetches: [], confirms: [] };
      w.localStorage.setItem("bf_token", "tok");
      w.confirm = q => { log.confirms.push(q); return true; };
      w.fetch = function (u, init) {
        const m = (init && init.method) || "GET";
        log.fetches.push({ url: String(u), method: m, body: init && init.body });
        const a = answers.find(x => String(u).indexOf(x.match) !== -1 && (!x.method || x.method === m)) || { status: 404, body: {} };
        const p = Promise.resolve({ ok: (a.status || 200) < 400, status: a.status || 200, json: () => Promise.resolve(JSON.parse(J(a.body))) });
        p.catch(() => {});
        return p;
      };
      w.eval(mlJs);
      await settle();
      return { w, doc: w.document, log };
    }
    const answers = [{ match: "/api/media/usage", body: { used_bytes: Math.round(5.5 * 1048576), cap_bytes: CAP, count: 2 } },
      { match: "/uses", body: { uses: [{ place: "A crowdfunding campaign", title: "Kiln fund" }] } },
      { match: "/api/media/1111", method: "DELETE", status: 409, body: { error: "This file is used in: A crowdfunding campaign (" + HOSTILE + ").", uses: [] } },
      { match: "/api/media/2222", method: "DELETE", body: { deleted: true } },
      { match: "/api/media/1111", method: "PATCH", body: { item: Object.assign({}, ITEMS[0], { alt_text: "Saved alt" }) } },
      { match: "/api/media", method: "GET", body: { items: ITEMS, next_before: null } }];
    const L1 = await libraryPage(answers);
    const cards = Array.from(L1.doc.querySelectorAll(".ml-card"));
    check("F4. the usage line reads \"N MB of 250 MB used\"", L1.doc.getElementById("mlUsage").textContent === "5.5 MB of 250 MB used", L1.doc.getElementById("mlUsage").textContent);
    const img = cards[0] && cards[0].querySelector("img"), vid = cards[1] && cards[1].querySelector("video");
    check("F5. an image is an img with its alt text; a video is a video with controls, muted, preload metadata",
      !!img && img.getAttribute("alt") === "A blue kiln" && !!vid && vid.hasAttribute("controls") && vid.muted === true && vid.getAttribute("preload") === "metadata");
    check("F6. each card: Label and Alt text fields, Save, Copy link, Where used, Delete; a hostile label is a value, never markup",
      cards.length === 2 && cards.every(c => J(Array.from(c.querySelectorAll("button")).map(b => b.textContent)) === J(["Save", "Copy link", "Where used", "Delete"])) &&
      cards[0].querySelector("input").value === HOSTILE && L1.doc.querySelectorAll("img[onerror]").length === 0 && L1.doc.querySelectorAll(".ml-card img").length === 1);
    const btn = (c, t) => Array.from(c.querySelectorAll("button")).find(b => b.textContent === t);
    btn(cards[0], "Delete").click(); await settle();
    check("F7. Delete on a file in use shows the 409's \"This file is used in: ...\" as text, and the card stays",
      cards[0].querySelector(".ml-msg").textContent === "This file is used in: A crowdfunding campaign (" + HOSTILE + ")." && cards[0].querySelectorAll("img").length === 1 &&
      L1.doc.querySelectorAll("img[onerror]").length === 0 && !!cards[0].parentNode && L1.log.confirms.length === 1, cards[0].querySelector(".ml-msg").textContent);
    btn(cards[0], "Where used").click(); await settle();
    check("F8. Where used lists the places", cards[0].querySelector(".ml-msg").textContent === "This file is used in: A crowdfunding campaign (Kiln fund).");
    cards[0].querySelector("textarea").value = "Saved alt"; btn(cards[0], "Save").click(); await settle();
    const patch = L1.log.fetches.find(f => f.method === "PATCH");
    check("F9. Save PATCHes the label and alt text and the image takes the new alt", !!patch && J(JSON.parse(patch.body)) === J({ label: HOSTILE, alt_text: "Saved alt" }) && img.getAttribute("alt") === "Saved alt");
    btn(cards[1], "Delete").click(); await settle();
    check("F10. Delete on an unused file removes its card", L1.doc.querySelectorAll(".ml-card").length === 1);
    const L2 = await libraryPage(answers);
    const fileInput = L2.doc.getElementById("mlFile");
    const bigFile = new L2.w.File([new Uint8Array(10)], "big.jpg", { type: "image/jpeg" });
    Object.defineProperty(bigFile, "size", { value: 10 * 1048576 + 1 });
    Object.defineProperty(fileInput, "files", { configurable: true, value: [bigFile] });
    fileInput.dispatchEvent(new L2.w.Event("change")); await settle();
    check("F11. a file over 10 MB is refused in the browser with the server's message, and nothing is sent",
      L2.doc.getElementById("mlStatus").textContent === MED.MESSAGES.tooBig && L2.log.fetches.every(f => f.method !== "POST"), L2.doc.getElementById("mlStatus").textContent);
    // the picker
    async function pickerPage(items) {
      const dom = new JSDOM("<!DOCTYPE html><html><head></head><body></body></html>", { url: "https://bizforceai.net/campaigns.html", runScripts: "outside-only" });
      const w = dom.window, log = { fetches: [] };
      w.localStorage.setItem("bf_token", "tok");
      w.fetch = function (u, init) {
        log.fetches.push({ url: String(u), method: (init && init.method) || "GET" });
        const p = Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(JSON.parse(J({ items: items, next_before: null }))) });
        p.catch(() => {});
        return p;
      };
      w.eval(mpJs);
      return { w, doc: w.document, log };
    }
    const K1 = await pickerPage(ITEMS);
    const pick1 = K1.w.BFMediaPicker.open({});
    await settle();
    const tiles = Array.from(K1.doc.querySelectorAll(".bf-mp-item"));
    check("F12. the picker is \"Choose from my library\" with \"Upload new\", one tile per item, labels as text",
      K1.doc.getElementById("bfMpTitle").textContent === "Choose from my library" && K1.doc.getElementById("bfMpUpload").textContent === "Upload new" && tiles.length === 2 &&
      tiles[0].querySelector(".bf-mp-label").textContent === HOSTILE && K1.doc.querySelectorAll("img[onerror]").length === 0);
    tiles[1].click();
    const chosen = await pick1;
    check("F13. choosing returns { url, type, name } as the pages store it: type \"video\", name from the label; the modal closes",
      J(chosen) === J({ url: ITEMS[1].url, type: "video", name: "Tour" }) && !K1.doc.getElementById("bfMediaPicker"), J(chosen));
    const pick2 = K1.w.BFMediaPicker.open({ kind: "image" }); await settle();
    K1.doc.querySelector(".bf-mp-item").click();
    const chosen2 = await pick2;
    check("F14. an image returns type \"image\"; kind=image asks the server for images", chosen2 && chosen2.type === "image" && chosen2.url === ITEMS[0].url &&
      K1.log.fetches.some(f => /\/api\/media\?kind=image$/.test(f.url)), J(chosen2));
    const pick3 = K1.w.BFMediaPicker.open({}); await settle();
    K1.doc.getElementById("bfMpClose").click();
    check("F15. Close returns null", (await pick3) === null);
  } else check("F4. jsdom is installed", false);
  const PAGES = [["campaigns.html", "Add Photos / Video", "campaignMedia.push(m); renderMediaPreview();"], ["marketplace.html", "Add Photos / Video", "listingMedia.push(m); renderMediaPreview();"],
    ["garage-sale.html", "Add Photos / Video", "listingMedia.push(m); renderMediaPreview();"], ["digital-cards.html", "Choose Image", "setBgImage(m.url);"]];
  const pageBad = PAGES.filter(([f, old, use]) => { const h = fe(f) || ""; return !(h.indexOf(">Choose from my library</button>") !== -1 && h.indexOf(">" + old + "</button>") !== -1 &&
    h.indexOf('<script src="/scripts/media-picker.js"></script>') !== -1 && h.indexOf(use) !== -1 && h.indexOf("BFMediaPicker.open(") !== -1); });
  check("F16. campaigns, marketplace, garage sale and cards each offer \"Choose from my library\" beside their upload button, which stays, and use what it returns as an upload",
    pageBad.length === 0, pageBad.map(p => p[0]).join(","));
  check("F17. the dashboard links the page", (fe("dashboard.html") || "").indexOf('<a href="media.html" class="bf-btn" onclick="event.stopPropagation()">Open Media Library</a>') !== -1);

  /* ════ G. legal, guide, registries ════ */
  console.log("\n══ G. Privacy and Terms, the guide, the registries ══");
  const PRIVACY = "Files you add to your Media Library are stored so you can reuse them, and anyone who has a file's link can open it. BizForce removes location and camera details from JPEG, PNG and WebP photos before saving them, but not from videos or GIFs. A file that is still in use cannot be deleted until you remove it from where it is used, and your files are deleted with your account.";
  const TERMS = "Upload only photos and videos you have the right to use and share.";
  check("G1. lib/legalPages.js: MEDIA_PRIVACY_SENTENCE and MEDIA_TERMS_SENTENCE are the brief's sentences", LP.MEDIA_PRIVACY_SENTENCE === PRIVACY && LP.MEDIA_TERMS_SENTENCE === TERMS);
  const built = LP.buildLegalPages(), esc = LEGAL.escapeHtml;
  const after = (h, a, b) => h.indexOf(a) !== -1 && h.indexOf(b) > h.indexOf(a);
  check("G2. the Privacy Policy carries it right after the campaign sentence, built and on disk",
    [built["privacy.html"], fe("privacy.html") || ""].every(h => after(h, esc(LP.CAMPAIGN_PRIVACY_SENTENCE), esc(PRIVACY)) && h.indexOf(esc(PRIVACY)) - h.indexOf(esc(LP.CAMPAIGN_PRIVACY_SENTENCE)) < esc(LP.CAMPAIGN_PRIVACY_SENTENCE).length + 40));
  check("G3. the Terms carry it right after the campaign sentence, built and on disk",
    [built["terms.html"], fe("terms.html") || ""].every(h => after(h, esc(LP.CAMPAIGN_TERMS_SENTENCE), esc(TERMS)) && h.indexOf(esc(TERMS)) - h.indexOf(esc(LP.CAMPAIGN_TERMS_SENTENCE)) < esc(LP.CAMPAIGN_TERMS_SENTENCE).length + 40));
  // NAMED (Nov 5 2026, images in social posts): BEFORE "2026-11-04", the version this change set. AFTER "2026-11-05", the version
  // the social images privacy sentence set; this change's own sentences are still checked in G1-G3.
  // NAMED (Nov 6 2026, card upgrades C1): BEFORE "2026-11-05" (images in social posts). AFTER "2026-11-06", the version the
  // card visits privacy sentence set.
  // NAMED (Nov 7 2026, Shopify on OAuth, migration 176): BEFORE "2026-11-06" (card visits). AFTER "2026-11-07", the version the Shopify privacy sentence set.
  check("G4. TERMS_VERSION is the latest change's, Nov 7 2026 (Shopify on OAuth; this change set Nov 4)", LEGAL.TERMS_VERSION === "2026-11-07" && LEGAL.TERMS_UPDATED === "Last updated November 7, 2026");
  const guide = fe("scripts/termaximus-guide.js") || "";
  const block = (/"media\.html": \[\n([\s\S]*?)\n    \]/.exec(guide) || ["", ""])[1];
  const tips = (block.match(/"(?:[^"\\]|\\.)*"/g) || []).map(t => JSON.parse(t));
  const quoted = tips.reduce((a, t) => a.concat((t.match(/"([^"]+)"/g) || []).map(q => q.slice(1, -1))), []);
  check("G5. media.html has 4 tips, each at most 160 characters, and every label they quote is on the page",
    tips.length === 4 && tips.every(t => t.length <= 160) && quoted.length >= 3 && quoted.every(l => page.indexOf(">" + l + "<") !== -1 || mlJs.indexOf("\"" + l + "\"") !== -1), J(quoted));
  check("G6. the tips say what the page does: 10 MB, 250 MB, the removal, reuse, and the in-use refusal", /10 MB/.test(tips[0]) && /250 MB/.test(tips[0]) && /removed/.test(tips[1]) && /reused/.test(tips[2]) && /refused while it is used/.test(tips[3]));
  const YD = loadLib("lib/yourData.js"), BK = loadLib("lib/backup.js"), SC = loadLib("lib/schemaCheck.js");
  const yd = YD.DATA.find(e => e.table === "member_media");
  check("G7. yourData: \"Your Media Library\" in content, label, alt text, kind, type, size and date plus the public link, never sha256; deleted with the account",
    !!yd && yd.group === "content" && /^Your Media Library/.test(yd.what) && yd.onDelete === "delete" && J(yd.owner) === J(["user_id"]) && yd.select.indexOf("sha256") === -1 &&
    ["label", "alt_text", "kind", "mime", "bytes", "created_at", "path"].every(c => yd.select.indexOf(c) !== -1) && yd.publicUrlFrom === "path" && YD.DELETE_ORDER.indexOf("member_media") !== -1, J(yd));
  check("G8. the export writes the public url in place of the storage path", /if \(e\.publicUrlFrom\) \{ row\.url = require\("\.\/memberMedia"\)\.publicUrlFor\(row\[e\.publicUrlFrom\]\); delete row\[e\.publicUrlFrom\]; \}/.test(ALL["lib/yourData.js"]));
  check("G9. backup includes member_media, next to content_library; schemaCheck names it 167_member_media.sql",
    BK.BACKUP_TABLES.indexOf("member_media") === BK.BACKUP_TABLES.indexOf("content_library") + 1 && SC.SCHEMA_TABLES.some(e => e[0] === "member_media" && e[1] === "167_member_media.sql"));

  console.log("\n══ Z. no network ══");
  check("Z. zero sockets and DNS lookups", NETWORK.length === 0, J(NETWORK));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures) + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : "")); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED" + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(0);
})().catch(function (err) {
  console.log("    FAIL  the check threw: " + ((err && err.stack) || err));
  process.exit(1);
});
