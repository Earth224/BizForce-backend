/* ══════════════════════════════════════════════════════════════════════════
   checkSocialImages — images from a member's Media Library in their Bluesky
   and Mastodon posts (migration 168, Nov 5 2026). Images only, at most 4 a
   post, alt text required and frozen at filing, size limits per service,
   verified byte for byte at posting, and never automatic.

   Everything runs against stubs: a fake database that enforces 168's CHECKs,
   a fake Storage that holds real synthetic image bytes (built as
   checkMediaLibrary builds them), a fake Bluesky agent with login, post and
   uploadBlob, a fake Mastodon server behind lib/guardedFetch.js's real JSON
   mode (200, 202 then 206 then 200, and never ready), and a network tripwire.

     I. imageDimensions: JPEG, PNG, WebP (VP8X, VP8L, VP8) and GIF; null on
        anything malformed, never a throw.
     F. Filing (both propose-post routes): the shapes media_ids may take, every
        refusal and its message, the frozen payload, and the draft's media_ids;
        with no images the filing is exactly as before.
     A. A post with images is never automatic.
     E. The executors: the payload must equal the draft, each row must still
        be the poster's with the same sha256 and type, and the bytes must be
        row.bytes long and hash to the frozen sha256; any difference fails the
        post with publish_failed and nothing is sent.
     B. Bluesky: one login, the uploads then the post in one fn, the embed's
        shape and aspect ratio; the platform gate path; no-image records as
        before.
     M. Mastodon: verify reads the media limits in its two requests; the
        multipart shape, the poll bounds, the not-ready failure, media_ids in
        the status; no-image bodies as before.
     G. guardedJsonRequest's Buffer body branch.
     U. "Where used": a pending post blocks deletion, a published one does not.
     P. The page: the controls, the lines word for word, the body with and
        without media, and escaping. proposals.html's Images row.
     L. The privacy sentence in source and in the built pages; the migration.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check. A mutation
   whose search text does not match exactly once is an ERROR.

   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm"), Module = require("module"), net = require("net"), dns = require("dns"),
  zlib = require("zlib"), crypto = require("crypto"), { EventEmitter } = require("events"), { PassThrough } = require("stream"), { execFileSync } = require("child_process");
const s = require("./_shared");

const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkSocialImages: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkSocialImages: no network"); };
global.fetch = async function (u) { NETWORK.push("fetch " + u); throw new Error("checkSocialImages: no network"); };

const BASE = "https://proj.supabase.co";
process.env.SUPABASE_URL = BASE;
const TEST_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
process.env.ENCRYPTION_SECRET = TEST_KEY;
const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
// The frontend as it was before this change: proposals.html's no-image cards must draw exactly what they drew there.
const PRE_IMAGES_FRONTEND = "9813d86";

const SV = "server.js", MED_FILE = "lib/memberMedia.js", MM_FILE = "lib/memberMastodon.js", GF_FILE = "lib/guardedFetch.js",
  LP_FILE = "lib/legalPages.js", MIG = "supabase/migrations/168_social_post_images.sql";
const SPJS = "fe:scripts/social-publish.js", PROP = "fe:proposals.html";

const MUTATIONS = {
  // an image with no alt text is filed
  "alt-optional": [[MED_FILE, "    if (!alt) return { status: 400, error: POST_MESSAGES.altMissing + itemName(row) };\n", ""]],
  // Bluesky's 2 MB limit is the library's 10 MB
  "bluesky-oversize-accepted": [[MED_FILE, "const BLUESKY_IMAGE_MAX_BYTES = 2000000;", "const BLUESKY_IMAGE_MAX_BYTES = 10 * 1024 * 1024;"]],
  // the Mastodon server's size limit is not applied at filing
  "mastodon-oversize-accepted": [[SV, "sizeMax: require(\"./lib/memberMastodon\").imageSizeLimitOf(row), tooBig:", "sizeMax: Infinity, tooBig:"]],
  // a post with images follows the member's auto_post
  "automatic-with-images": [[SV, "        bskyPayload.posts_as.automatic = false;\n", ""], [SV, "        mastoPayload.posts_as.automatic = false;\n", ""]],
  // another member's image is attached
  "foreign-media-accepted": [[SV, "      .eq(\"id\", parsed.ids[i])\n      .eq(\"user_id\", userId)\n", "      .eq(\"id\", parsed.ids[i])\n"],
    [MED_FILE, "    if (!row || row.user_id !== userId) return { status: 404, error: POST_MESSAGES.notInLibrary };", "    if (!row) return { status: 404, error: POST_MESSAGES.notInLibrary };"]],
  // a video is attached
  "video-attached": [[MED_FILE, "    if (row.kind !== \"image\" || POST_IMAGE_MIMES.indexOf(row.mime) === -1) return { status: 400, error: POST_MESSAGES.onlyImages };\n", ""]],
  // five images are taken
  "more-than-four": [[MED_FILE, "value.length > POST_MEDIA_MAX) return { error: POST_MESSAGES.shape };", "value.length > 99) return { error: POST_MESSAGES.shape };"]],
  // the same image twice is taken
  "duplicate-ids-accepted": [[MED_FILE, " || seen[value[i]]) return { error: POST_MESSAGES.shape };", ") return { error: POST_MESSAGES.shape };"]],
  // the bytes are never hashed at posting
  "sha-unchecked-at-post": [[MED_FILE, "  if (crypto.createHash(\"sha256\").update(buffer).digest(\"hex\") !== frozen.sha256) throw new MediaChanged(null, \"sha\");\n", ""]],
  // the bytes' length is never compared at posting
  "length-unchecked-at-post": [[MED_FILE, "  if (buffer.length !== row.bytes) throw new MediaChanged(null, \"length\");\n", ""]],
  // the payload's images need not be the draft's
  "payload-draft-mismatch-allowed": [[SV, "  if (mismatch) throw new MED.MediaChanged(mismatch, \"mismatch\");\n", ""]],
  // the alt text is read from the library at posting, not frozen at filing
  "alt-read-at-post": [[SV, "      .select(\"id, user_id, kind, mime, bytes, sha256, path\")", "      .select(\"id, user_id, kind, mime, bytes, sha256, path, alt_text\")"],
    [SV, "    images.push({ bytes: bytes, mime: frozen.mime, alt: frozen.alt.trim(), size:", "    images.push({ bytes: bytes, mime: frozen.mime, alt: (current.data && current.data.alt_text) || frozen.alt.trim(), size:"]],
  // the images are uploaded in a session of their own, a second login
  "second-login-for-upload": [[SV, "    // The member's own session: one login, one post, no retry (lib/memberBluesky.js).\n",
    "    // The member's own session: one login, one post, no retry (lib/memberBluesky.js).\n    if (images.length) await require(\"./lib/memberBluesky\").withSession(account.row, require(\"./lib/apiKeyCrypto\").decrypt, function (agent) { return agent.uploadBlob(images[0].bytes, { encoding: images[0].mime }); });\n"]],
  // a blob is uploaded when the post is filed
  "blob-uploaded-at-filing": [[SV, "        bskyMedia = bskyAttached.media;\n",
    "        bskyMedia = bskyAttached.media;\n        if (account.kind === \"member\") await require(\"./lib/memberBluesky\").withSession(account.row, require(\"./lib/apiKeyCrypto\").decrypt, function (agent) { return agent.uploadBlob(Buffer.from(\"x\"), { encoding: \"image/jpeg\" }); });\n"]],
  // a Mastodon image is polled for ten times as long
  "mastodon-poll-unbounded": [[MM_FILE, "const MEDIA_POLLS = 5;", "const MEDIA_POLLS = 50;"]],
  // a Mastodon image still processing is posted anyway
  "mastodon-posts-unprocessed": [[MM_FILE, "  throw mediaFailure(\"media_not_ready\");\n}", "  return id;\n}"]],
  // the polls do not wait
  "mastodon-poll-no-wait": [[MM_FILE, "    await api.sleep(MEDIA_POLL_MS);\n", ""]],
  // a status with no images still carries media_ids
  "media-ids-sent-when-none": [[MM_FILE, "  if (attach.length) statusBody.media_ids = attach.slice();", "  statusBody.media_ids = attach.slice();"]],
  // a Bluesky post with no images gets an embed too
  "record-changed-without-images": [[SV, "      function (agent) { return images.length ? blueskyPostWithImages(agent, record, images) : agent.post(record); });",
    "      function (agent) { return blueskyPostWithImages(agent, record, images); });"]],
  // width and height swapped
  "aspect-ratio-swapped": [[SV, "entry.aspectRatio = { width: images[i].size.width, height: images[i].size.height };", "entry.aspectRatio = { width: images[i].size.height, height: images[i].size.width };"]],
  // JPEG width and height read from the wrong offsets
  "jpeg-dimensions-swapped": [[MED_FILE, "          return sized(buf.readUInt16BE(i + 7), buf.readUInt16BE(i + 5));", "          return sized(buf.readUInt16BE(i + 5), buf.readUInt16BE(i + 7));"]],
  // a Buffer body is JSON-encoded
  "buffer-json-encoded": [[GF_FILE, "        payload = opts.body;\n      } else {", "        payload = Buffer.from(JSON.stringify(opts.body), \"utf8\");\n      } else {"]],
  // a Buffer body goes out under any Content-Type
  "multipart-type-unchecked": [[GF_FILE, "        if (declared.indexOf(JSON_MULTIPART_PREFIX) !== 0 || declared.length === JSON_MULTIPART_PREFIX.length) {", "        if (false) {"]],
  // a Buffer body of any size goes out
  "upload-unbounded": [[GF_FILE, "        if (opts.body.length > uploadCap) {", "        if (false) {"]],
  // a maxUploadBytes over the ceiling is clamped, not refused
  "upload-ceiling-clamped": [[GF_FILE, "        const uploadCap = opts.maxUploadBytes === undefined ? JSON_MAX_UPLOAD_BYTES : opts.maxUploadBytes;",
    "        const uploadCap = Math.min(opts.maxUploadBytes === undefined ? JSON_MAX_UPLOAD_BYTES : opts.maxUploadBytes, JSON_MAX_UPLOAD_BYTES_CEILING);"]],
  // verify ignores the server's image size limit
  "verify-media-limit-ignored": [[MM_FILE, "    if (ma && inRange(ma.image_size_limit, IMAGE_SIZE_LIMIT_RANGE)) imageLimit = ma.image_size_limit;\n", ""]],
  // connect does not store the media limits
  "connect-limits-not-stored": [[SV, "          image_size_limit:            verified.image_size_limit,\n          media_description_limit:     verified.media_description_limit,\n", ""]],
  // a pending post does not count as a use
  "in-use-ignores-pending-post": [[MED_FILE, "          uses.push({ place: PLACES.social_post_drafts, title: SOCIAL_PLATFORM_NAMES[draft.platform] || null });\n", ""]],
  // a published post blocks deletion
  "published-post-blocks-delete": [[MED_FILE, "        .eq(\"status\", \"pending_approval\").range(q * READ_PAGE", "        .range(q * READ_PAGE"],
    [MED_FILE, "        if (draft.status === \"pending_approval\" && Array.isArray(draft.media_ids)", "        if (Array.isArray(draft.media_ids)"]],
  // the Privacy Policy loses the sentence
  "privacy-sentence-removed": [[LP_FILE, "      SOCIAL_MEDIA_PRIVACY_SENTENCE,\n", ""]],
  // the proposal card's alt text is markup
  "proposal-alt-unescaped": [[PROP, "'<span class=\"pf-value pf-image-alt\">' + escapeHtml(alt) + '</span>'", "'<span class=\"pf-value pf-image-alt\">' + alt + '</span>'"]],
  // the page sends media_ids with no images
  "page-media-ids-always": [[SPJS, "    return ids.length ? { task_id: taskId, media_ids: ids } : { task_id: taskId };", "    return { task_id: taskId, media_ids: ids };"]],
  // the page draws a picked image's alt text as markup
  "page-alt-as-markup": [[SPJS, "      alt.textContent = m.alt_text || NO_ALT_LINE;", "      alt.innerHTML = m.alt_text || NO_ALT_LINE;"]],
  // the page takes a fifth image
  "page-five-images": [[SPJS, "      if (now.length >= IMAGES_MAX || now.some(", "      if (now.some("]],
  // the picker opens with four images already attached
  "page-picker-opened-when-full": [[SPJS, "    if (attachedImages(box).length >= IMAGES_MAX) return Promise.resolve(false);\n", ""]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

/* ── the files ──────────────────────────────────────────────────────────── */
const lf = t => t.replace(/\r\n/g, "\n");
const ALL = {};
[SV, MED_FILE, MM_FILE, GF_FILE, LP_FILE, "lib/legal.js", "lib/accountFiles.js", "lib/yourData.js", "lib/scrollbars.js", "lib/supportLinks.js", "lib/themes.js", MIG].forEach(f => {
  const p = path.join(REPO, f);
  ALL[f] = fs.existsSync(p) ? lf(fs.readFileSync(p, "utf8")) : null;
});
["scripts/social-publish.js", "scripts/media-picker.js", "agents/social.html", "proposals.html", "privacy.html"].forEach(f => {
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

let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}
const J = JSON.stringify;
const clone = v => v === undefined ? undefined : JSON.parse(JSON.stringify(v));
const CRLF = String.fromCharCode(13, 10);

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
      if (ALL[target] !== undefined && ALL[target] !== null) return loadLib(target);
      return realRequire(path.join(REPO, target));
    }
    return realRequire(req);
  };
  m._compile(ALL[rel], file);
  return m.exports;
}
const MED = loadLib(MED_FILE), MM = loadLib(MM_FILE), GF = loadLib(GF_FILE), LP = loadLib(LP_FILE), LEGAL = loadLib("lib/legal.js"), AFL = loadLib("lib/accountFiles.js");
const CRYPTO_REAL = require(path.join(REPO, "lib/apiKeyCrypto.js"));
const MB = require(path.join(REPO, "lib/memberBluesky.js"));
const DECRYPTS = [];
const CRYPTO = { encrypt: CRYPTO_REAL.encrypt, decrypt: function (sealed) { DECRYPTS.push(1); return CRYPTO_REAL.decrypt(sealed); } };

/* ── synthetic images, built as checkMediaLibrary builds them ────────────── */
const B = (...parts) => Buffer.concat(parts.map(p => Buffer.isBuffer(p) ? p : typeof p === "string" ? Buffer.from(p, "latin1") : Buffer.from(p)));
const u16 = n => Buffer.from([(n >> 8) & 255, n & 255]);
const u16le = n => Buffer.from([n & 255, (n >> 8) & 255]);
const u24le = n => Buffer.from([n & 255, (n >> 8) & 255, (n >> 16) & 255]);
const u32be = n => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b; };
const u32le = n => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };
const seg = (marker, body) => B([0xff, marker], u16(body.length + 2), body);
const SCAN = Buffer.from([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0xff, 0x00, 0x33, 0x44]);
function jpeg(w, h, sof, opts) {
  opts = opts || {};
  const sos = B(seg(0xda, Buffer.from([0x01, 0x01, 0x00, 0x00, 0x3f, 0x00])), SCAN, [0xff, 0xd9]);
  const frame = seg(sof === undefined ? 0xc0 : sof, B([8], u16(h), u16(w), [1, 1, 0x11, 0]));
  return B([0xff, 0xd8], seg(0xe0, B("JFIF\0", [1, 1, 0, 0, 1, 0, 1, 0, 0])), [0xff, 0xff], seg(0xdb, B([0], Buffer.alloc(64, 7))),
    opts.sosFirst ? sos : frame, seg(0xc4, B([0], Buffer.alloc(16, 0), [1])), opts.sosFirst ? frame : sos);
}
function pngChunk(type, data) { const body = B(type, data); return B(u32be(data.length), body, u32be(zlib.crc32(body))); }
const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const IDAT = Buffer.from([0x78, 0x9c, 0x63, 0x60, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0xaa, 0xbb]);
const png = (w, h) => B(PNG_SIG, pngChunk("IHDR", B(u32be(w), u32be(h), [8, 2, 0, 0, 0])), pngChunk("IDAT", IDAT), pngChunk("IEND", Buffer.alloc(0)));
function webpChunk(fourcc, data) { return B(fourcc, u32le(data.length), data, data.length & 1 ? [0] : []); }
const riff = body => B("RIFF", u32le(body.length), body);
const webpX = (w, h) => riff(B("WEBP", webpChunk("VP8X", B([0x20, 0, 0, 0], u24le(w - 1), u24le(h - 1))), webpChunk("VP8 ", B([0x30, 0x01, 0x00, 0x9d, 0x01, 0x2a], u16le(w), u16le(h), [0x34, 0x25, 0xa4]))));
const webpLossy = (w, h) => riff(B("WEBP", webpChunk("VP8 ", B([0x30, 0x01, 0x00, 0x9d, 0x01, 0x2a], u16le(w | 0x4000), u16le(h | 0x8000), [0x34, 0x25, 0xa4]))));
const webpLossless = (w, h) => riff(B("WEBP", webpChunk("VP8L", B([0x2f], u32le(((w - 1) & 0x3fff) | (((h - 1) & 0x3fff) << 14)), [0x10, 0x07, 0x00, 0x00, 0x00]))));
const gif = (w, h) => B("GIF89a", u16le(w), u16le(h), [0x80, 0, 0], [0, 0, 0, 255, 255, 255], ",", [0, 0, 0, 0], u16le(w), u16le(h), [0], [2, 2, 0x44, 1, 0], ";");
const sha = b => crypto.createHash("sha256").update(b).digest("hex");

/* ── the fake database, with migration 168's CHECKs ──────────────────────── */
const DRAFT_STATUSES = ["pending", "not_published", "scheduled", "pending_approval", "published", "publish_failed"];
function violates(table, row) {
  if (table === "social_post_drafts") {
    if (!Array.isArray(row.media_ids) || row.media_ids.length > 4) return "social_post_drafts_media_ids_check";
    if (DRAFT_STATUSES.indexOf(row.status) === -1) return "social_post_drafts_status_check";
  }
  if (table === "member_mastodon_connections") {
    if (!(Number.isInteger(row.image_size_limit) && row.image_size_limit >= 1 && row.image_size_limit <= 104857600)) return "member_mastodon_connections_image_size_check";
    if (!(Number.isInteger(row.media_description_limit) && row.media_description_limit >= 1 && row.media_description_limit <= 100000)) return "member_mastodon_connections_media_desc_check";
  }
  return null;
}
const DEFAULTS = {
  social_post_drafts: () => ({ media_ids: [] }),
  member_mastodon_connections: () => ({ status: "connected", auto_post: false, max_characters: 500, characters_reserved_per_url: 23,
    image_size_limit: 16777216, media_description_limit: 1500, created_at: "2026-11-05T09:00:00.000Z" }),
  notifications: () => ({ read: false })
};
function fakeDb(seed) {
  const db = { tables: {}, log: [], seq: 0 };
  Object.keys(seed || {}).forEach(t => { db.tables[t] = seed[t].map(clone); });
  const rows = t => db.tables[t] || (db.tables[t] = []);
  function project(row, cols) {
    if (!cols || cols.trim() === "*") return clone(row);
    const out = {};
    cols.split(",").map(c => c.trim()).filter(Boolean).forEach(c => { out[c] = row[c] === undefined ? null : clone(row[c]); });
    return out;
  }
  const keep = (q, r) => q.filters.every(f => f[0] === "eq" ? r[f[1]] === f[2] : f[0] === "neq" ? r[f[1]] !== f[2] : f[0] === "in" ? f[2].indexOf(r[f[1]]) !== -1 : f[0] === "is" ? r[f[1]] === f[2] : true);
  function finish(q, list) {
    const cols = q.op === "select" ? q.cols : q.retCols;
    let out = list;
    if (q.from !== null) out = out.slice(q.from, q.to + 1);
    const data = (q.op === "select" || q.returning) ? out.map(r => project(r, cols)) : null;
    if (q.single === "single") return data && data.length === 1 ? { data: data[0], error: null } : { data: null, error: { code: "PGRST116", message: (data ? data.length : 0) + " rows" } };
    if (q.single === "maybe") return data && data.length > 1 ? { data: null, error: { message: "more than one row" } } : { data: data ? data[0] || null : null, error: null };
    return { data: data, error: null };
  }
  function insertOne(table, payload) {
    const row = Object.assign({ id: "00000000-0000-4000-8000-" + String(++db.seq).padStart(12, "0") }, DEFAULTS[table] ? DEFAULTS[table]() : {}, clone(payload));
    const bad = violates(table, row);
    if (bad) return { error: { code: "23514", message: "violates check constraint \"" + bad + "\"" } };
    rows(table).push(row);
    return { row };
  }
  function answer(q) {
    db.log.push({ table: q.table, op: q.op, cols: q.cols, filters: clone(q.filters), payload: clone(q.payload) });
    if (q.op === "insert") {
      const list = Array.isArray(q.payload) ? q.payload : [q.payload];
      const made = [];
      for (const p of list) { const r = insertOne(q.table, p); if (r.error) return Promise.resolve({ data: null, error: r.error }); made.push(r.row); }
      return Promise.resolve(finish(q, made));
    }
    if (q.op === "upsert") {
      const keys = String((q.opts && q.opts.onConflict) || "id").split(",");
      const found = rows(q.table).find(r => keys.every(k => r[k] === q.payload[k]));
      if (found) {
        const merged = Object.assign({}, found, clone(q.payload));
        const bad = violates(q.table, merged);
        if (bad) return Promise.resolve({ data: null, error: { code: "23514", message: bad } });
        Object.assign(found, clone(q.payload));
        return Promise.resolve(finish(q, [found]));
      }
      const r = insertOne(q.table, q.payload);
      if (r.error) return Promise.resolve({ data: null, error: r.error });
      return Promise.resolve(finish(q, [r.row]));
    }
    const hits = rows(q.table).filter(r => keep(q, r));
    if (q.op === "update") {
      for (const r of hits) { const bad = violates(q.table, Object.assign({}, r, q.payload)); if (bad) return Promise.resolve({ data: null, error: { code: "23514", message: bad } }); }
      hits.forEach(r => Object.assign(r, clone(q.payload)));
      return Promise.resolve(finish(q, hits));
    }
    if (q.op === "delete") {
      db.tables[q.table] = rows(q.table).filter(r => hits.indexOf(r) === -1);
      return Promise.resolve(finish(q, hits));
    }
    return Promise.resolve(finish(q, hits));
  }
  function from(table) {
    const q = { table, op: "select", cols: "*", retCols: "*", payload: null, opts: null, filters: [], single: false, returning: false, from: null, to: null };
    const b = {
      select(cols) { if (q.op === "select") q.cols = cols || "*"; else { q.returning = true; q.retCols = cols || "*"; } return b; },
      insert(p) { q.op = "insert"; q.payload = p; return b; },
      update(p) { q.op = "update"; q.payload = p; return b; },
      upsert(p, o) { q.op = "upsert"; q.payload = p; q.opts = o; return b; },
      delete() { q.op = "delete"; return b; },
      eq(c, v) { q.filters.push(["eq", c, v]); return b; },
      neq(c, v) { q.filters.push(["neq", c, v]); return b; },
      in(c, v) { q.filters.push(["in", c, v]); return b; },
      is(c, v) { q.filters.push(["is", c, v]); return b; },
      or() { return b; }, not() { return b; }, gte() { return b; }, lte() { return b; }, lt() { return b; }, gt() { return b; }, contains() { return b; },
      order() { return b; },
      limit(n) { q.from = 0; q.to = n - 1; return b; },
      range(a, z) { q.from = a; q.to = z; return b; },
      single() { q.single = "single"; return answer(q); },
      maybeSingle() { q.single = "maybe"; return answer(q); },
      then(res, rej) { return answer(q).then(res, rej); }
    };
    return b;
  }
  db.client = { from, async rpc() { return { data: 0, error: null }; } };
  db.rows = rows;
  db.writes = () => db.log.filter(q => q.op !== "select");
  return db;
}
/* Storage: bf-public holds the library's bytes; every download is counted. */
function fakeStorage() {
  const st = { objects: {}, downloads: [] };
  st.from = function (bucket) {
    return {
      async download(p) {
        st.downloads.push(bucket + "/" + p);
        const b = st.objects[bucket + "/" + p];
        if (!b) return { data: null, error: { message: "Object not found" } };
        return { data: { arrayBuffer: async () => Uint8Array.from(b).buffer }, error: null };
      },
      async list() { return { data: [], error: null }; },
      async remove() { return { data: [], error: null }; }
    };
  };
  return st;
}

/* ── the fake Bluesky ────────────────────────────────────────────────────── */
const BSKY = { logins: [], posts: [], blobs: [], reset() { this.logins = []; this.posts = []; this.blobs = []; } };
function bskyAgent(who) {
  const agent = {
    session: null,
    async login(cred) { BSKY.logins.push({ who, identifier: cred.identifier }); agent.session = { did: "did:plc:alice111", handle: cred.identifier }; },
    async uploadBlob(bytes, o) {
      BSKY.blobs.push({ who, size: bytes.length, encoding: o && o.encoding, sha: sha(Buffer.from(bytes)), order: BSKY.blobs.length + BSKY.posts.length });
      return { success: true, headers: {}, data: { blob: { $type: "blob", ref: { $link: "bafkblob" + BSKY.blobs.length }, mimeType: o && o.encoding, size: bytes.length } } };
    },
    async post(record) {
      BSKY.posts.push({ who, record: clone(record), order: BSKY.blobs.length + BSKY.posts.length });
      return { uri: "at://did:plc:alice111/app.bsky.feed.post/3k" + BSKY.posts.length, cid: "bafypost" + BSKY.posts.length };
    }
  };
  return agent;
}
MB.api.createAgent = () => bskyAgent("member");
const GATE = { calls: 0, reset() { this.calls = 0; } };
const bskyGate = { async call(fn) { GATE.calls++; return { ok: true, value: await fn(bskyAgent("platform")) }; } };

/* ── the fake Mastodon, behind lib/guardedFetch.js's real JSON mode ──────── */
const TOK = { alice: "aliceTestToken_0123456789abcdefghijklmnopq" };
const PUBLIC = "93.184.216.34";
const STUB = {
  names: { "mastodon.social": PUBLIC, "small.example": PUBLIC, "odd.example": PUBLIC, "nomedia.example": PUBLIC },
  media: {
    "mastodon.social": { image_size_limit: 10485760, description_limit: 1500 },
    "small.example": { image_size_limit: 4000, description_limit: 40 },
    "odd.example": { image_size_limit: 0, description_limit: 999999 }
  },
  seen: [], uploads: [], polls: [], statuses: [], sleeps: [], mode: "ready", pollsUntilReady: 2, mediaSeq: 0,
  reset() { this.seen = []; this.uploads = []; this.polls = []; this.statuses = []; this.sleeps = []; this.mode = "ready"; this.pollsUntilReady = 2; this.mediaSeq = 0; this.mediaState = {}; }
};
STUB.mediaState = {};
const jsonAnswer = (status, body, headers) => ({ status, headers: Object.assign({ "content-type": "application/json; charset=utf-8" }, headers || {}), body: Buffer.from(J(body)) });
function bearerOf(h) { const v = h.Authorization || h.authorization; return typeof v === "string" && v.indexOf("Bearer ") === 0 ? v.slice(7) : null; }
function serve(q) {
  const tok = bearerOf(q.headers);
  if (q.path === "/api/v1/accounts/verify_credentials" && q.method === "GET") {
    return tok === TOK.alice ? jsonAnswer(200, { id: "109000000000000001", username: "alice", acct: "alice" }) : jsonAnswer(401, { error: "The access token is invalid" });
  }
  if (q.path === "/api/v2/instance" && q.method === "GET") {
    const cfg = { statuses: { max_characters: 500, characters_reserved_per_url: 23 } };
    if (STUB.media[q.host]) cfg.media_attachments = Object.assign({ supported_mime_types: ["image/jpeg", "image/png"] }, STUB.media[q.host]);
    return jsonAnswer(200, { domain: q.host, configuration: cfg });
  }
  if (tok !== TOK.alice) return jsonAnswer(401, { error: "The access token is invalid" });
  if (q.path === "/api/v2/media" && q.method === "POST") {
    const id = String(220000000000000000 + (++STUB.mediaSeq));
    STUB.uploads.push({ id, contentType: q.headers["Content-Type"], raw: q.raw });
    STUB.mediaState[id] = 0;
    if (STUB.mode === "ready") return jsonAnswer(200, { id, type: "image", url: "https://files.mastodon.social/m/" + id + ".jpg" });
    return jsonAnswer(202, { id, type: "image", url: null });
  }
  const m = /^\/api\/v1\/media\/([0-9]+)$/.exec(q.path);
  if (m && q.method === "GET") {
    STUB.polls.push(m[1]);
    STUB.mediaState[m[1]] = (STUB.mediaState[m[1]] || 0) + 1;
    if (STUB.mode === "slow" && STUB.mediaState[m[1]] >= STUB.pollsUntilReady) return jsonAnswer(200, { id: m[1], url: "https://files.mastodon.social/m/" + m[1] + ".jpg" });
    return jsonAnswer(206, { id: m[1], url: null });
  }
  if (q.path === "/api/v1/statuses" && q.method === "POST") {
    const id = String(110000000000000000 + STUB.statuses.length + 1);
    STUB.statuses.push({ body: JSON.parse(q.raw.toString("utf8")), key: q.headers["Idempotency-Key"], contentType: q.headers["Content-Type"] });
    return jsonAnswer(200, { id, url: "https://" + q.host + "/@alice/" + id, uri: "https://" + q.host + "/users/alice/statuses/" + id });
  }
  return jsonAnswer(404, { error: "Not found" });
}
function fakeResolve(hostname, options, cb) {
  const address = STUB.names[hostname];
  if (!address) { const e = new Error("getaddrinfo ENOTFOUND " + hostname); e.code = "ENOTFOUND"; return cb(e); }
  return cb(null, [{ address, family: 4 }]);
}
function fakeRequest(options) {
  const req = new EventEmitter();
  req.destroy = function () {};
  req.end = function (payload) {
    options.lookup(options.hostname, { all: true }, function (err, addresses) {
      if (err) return setImmediate(() => req.emit("error", err));
      const q = { host: options.hostname, method: options.method, path: options.path, headers: Object.assign({}, options.headers), raw: payload ? Buffer.from(payload) : Buffer.alloc(0) };
      STUB.seen.push(q);
      const a = serve(q);
      const res = new PassThrough();
      res.statusCode = a.status;
      res.headers = a.headers;
      setImmediate(() => { req.emit("response", res); res.end(a.body); });
    });
  };
  return req;
}
const JSON_MODE = GF.createGuardedFetch({ resolve: fakeResolve, request: fakeRequest }).json;
MM.api.transport = JSON_MODE;
MM.api.sleep = async function (ms) { STUB.sleeps.push(ms); };

/* ── server.js, lifted ───────────────────────────────────────────────────── */
const SPANS = [];
{
  const re = /^(?:(?:async )?function [A-Za-z_$][A-Za-z0-9_$]*[(]|app[.][a-z]+[(])/gm; let m;
  while ((m = re.exec(SRC))) { const end = s.braceMatch(SRC, SRC.indexOf("{", m.index)); if (end > 0) SPANS.push([m.index, end]); }
}
const FN_AT = new Map(), DECL_AT = new Map();
{
  let m;
  const fre = /^(?:async )?function ([A-Za-z_$][A-Za-z0-9_$]*)\(/gm;
  while ((m = fre.exec(SRC))) if (!FN_AT.has(m[1])) FN_AT.set(m[1], m.index);
  const dre = /^(?:var|const|let) ([A-Za-z_$][A-Za-z0-9_$]*)[ \t]*=[ \t]*/gm;
  while ((m = dre.exec(SRC))) {
    const at = m.index;
    if (!DECL_AT.has(m[1]) && !SPANS.some(([x, y]) => at > x && at < y)) DECL_AT.set(m[1], { index: at, length: m[0].length });
  }
}
function definitionOf(name) {
  if (FN_AT.has(name)) { const at = FN_AT.get(name); return SRC.slice(at, s.braceMatch(SRC, SRC.indexOf(") {", at) + 2)); }
  const d = DECL_AT.get(name);
  if (!d) return null;
  const brk = /;\n/g; brk.lastIndex = d.index + d.length;
  let b;
  while ((b = brk.exec(SRC))) {
    const next = SRC[b.index + b[0].length];
    if (next === undefined || next === "\n" || /[^\s]/.test(next)) return SRC.slice(d.index, b.index + 1);
  }
  return null;
}
const STUBS = new Set(["supabase", "nowIso", "console", "process", "require", "module", "app", "Buffer", "setTimeout", "fetch",
  "requireAuth", "requireActiveSubscription", "aiLimiter", "bskyGate", "RichText", "rateLimit", "refuseUnlessSubscribed", "anthropic", "Anthropic", "memberMedia"]);
const uncommented = code => code.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
function closure(root) {
  const have = new Map();
  const queue = [...new Set(uncommented(root).match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || STUBS.has(name)) continue;
    const def = definitionOf(name);
    if (!def) continue;
    try { new vm.Script(def); } catch (e) { continue; }
    have.set(name, def);
    new Set(uncommented(def).match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !STUBS.has(id)) queue.push(id); });
  }
  return [...have.values()].sort((x, y) => SRC.indexOf(x) - SRC.indexOf(y)).join("\n\n") + "\n\n" + root;
}
function routeText(method, route) {
  const sig = "app." + method + "(\"" + route + "\"";
  const start = SRC.indexOf(sig);
  if (start < 0 || SRC.indexOf(sig, start + 1) !== -1) throw new Error(method + " " + route + " not found once");
  const end = s.braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("function (req, res, next)", start)));
  return SRC.slice(start, end + 2);
}
const R = {
  bsky: ["post", "/api/agents/social/propose-post"], masto: ["post", "/api/social/mastodon/propose-post"], connect: ["post", "/api/social/mastodon/connect"]
};
let LIFTED;
try {
  const root = Object.keys(R).map(k => routeText(R[k][0], R[k][1])).join("\n\n") +
    "\n\nthis.api = { executePublishSocialPost: executePublishSocialPost, executePublishMastodonPost: executePublishMastodonPost };";
  LIFTED = closure(root);
  new vm.Script(LIFTED);
} catch (e) {
  console.log("    FAIL  the routes could not be lifted from server.js: " + e.message);
  process.exit(1);
}

/* ── the fixture ─────────────────────────────────────────────────────────── */
const OWNER = "aaaaaaaa-0000-4000-8000-000000000001", ALICE = "bbbbbbbb-0000-4000-8000-000000000002", BOB = "cccccccc-0000-4000-8000-000000000003";
const tid = n => "11111111-0000-4000-8000-" + String(n).padStart(12, "0");
const mid = n => "22222222-0000-4000-8000-" + String(n).padStart(12, "0");
const POST = "Saturday wheel class at 10am, two seats left.";
const run = (n, user, platform) => ({ id: tid(n), user_id: user, agent_type: "social", task_type: "social/post", status: "completed",
  output: { success: true, platform: platform, platform_label: platform, post: POST + " (" + n + ")" } });
const IMG = {
  kiln: jpeg(640, 480), wide: png(3, 2), leaf: webpX(300, 200), dot: gif(5, 7), fifth: png(9, 9), sixth: png(4, 4)
};
const pathOf = (user, n, ext) => "media/" + user + "/" + String(n).repeat(32).slice(0, 32) + "." + ext;
function item(n, user, bytes, mime, ext, label, alt, extra) {
  return Object.assign({ id: mid(n), user_id: user, path: pathOf(user, n, ext), kind: "image", mime: mime, bytes: bytes.length, sha256: sha(bytes),
    label: label, alt_text: alt, metadata_stripped: true, created_at: "2026-11-04T0" + n + ":00:00.000Z" }, extra || {});
}
function seed(opts) {
  opts = opts || {};
  const sealedBsky = CRYPTO_REAL.encrypt("alice-app-pass-1234");
  const sealedMasto = CRYPTO_REAL.encrypt(TOK.alice);
  const media = [
    item(1, ALICE, IMG.kiln, "image/jpeg", "jpg", "Kiln photo", "  A blue kiln, door open  "),
    item(2, ALICE, IMG.wide, "image/png", "png", "Wide", "Three bowls in a row"),
    item(3, ALICE, IMG.leaf, "image/webp", "webp", "Leaf", "A leaf-shaped dish"),
    item(4, ALICE, IMG.dot, "image/gif", "gif", "Dot", "A spinning dot"),
    item(5, ALICE, IMG.fifth, "image/png", "png", "Fifth", "A fifth picture"),
    item(6, ALICE, IMG.sixth, "image/png", "png", "", "   "),
    item(7, ALICE, IMG.sixth, "image/png", "png", "Unlabelled photo", ""),
    Object.assign(item(8, ALICE, IMG.kiln, "video/mp4", "mp4", "Tour", "A studio tour"), { kind: "video" }),
    Object.assign(item(9, ALICE, IMG.kiln, "image/jpeg", "jpg", "Big", "A big photo"), { bytes: 2000001 }),
    Object.assign(item(10, ALICE, IMG.kiln, "image/jpeg", "jpg", "Two MB", "Exactly at the limit"), { bytes: 2000000 }),
    item(11, BOB, IMG.wide, "image/png", "png", "Bob's", "Bob's bowls"),
    item(12, ALICE, IMG.wide, "image/png", "png", "Long alt", "x".repeat(1001)),
    item(13, ALICE, IMG.wide, "image/png", "png", "Mid alt", "y".repeat(60)),
    item(14, OWNER, IMG.wide, "image/png", "png", "Owner's", "The studio sign")
  ];
  return {
    users: [{ id: OWNER, role: "admin" }, { id: ALICE, role: "user" }, { id: BOB, role: "user" }],
    ai_tasks: [run(1, ALICE, "bluesky"), run(2, ALICE, "bluesky"), run(3, ALICE, "mastodon"), run(4, OWNER, "bluesky"), run(5, ALICE, "mastodon"), run(6, ALICE, "bluesky")],
    member_social_connections: [{ id: "c1", user_id: ALICE, platform: "bluesky", handle: "alice.bsky.social", did: "did:plc:alice111", status: "connected",
      auto_post: opts.autoBsky === true, app_password_ciphertext: sealedBsky.ciphertext, app_password_iv: sealedBsky.iv, app_password_auth_tag: sealedBsky.authTag }],
    member_mastodon_connections: opts.noMasto ? [] : [Object.assign({ id: "m1", user_id: ALICE, instance_host: opts.mastoHost || "mastodon.social", account_id: "109000000000000001",
      acct: "alice", status: "connected", auto_post: opts.autoMasto === true, max_characters: 500, characters_reserved_per_url: 23,
      image_size_limit: 16777216, media_description_limit: 1500, token_ciphertext: sealedMasto.ciphertext, token_iv: sealedMasto.iv, token_auth_tag: sealedMasto.authTag },
      opts.mastoLimits || {})],
    member_media: media, social_post_drafts: [], agent_proposals: [], notifications: [], gate_decisions: [], member_gates: [], member_social_setting_changes: []
  };
}
function build(opts) {
  const db = fakeDb(seed(opts));
  const store = fakeStorage();
  db.tables.member_media.forEach(r => {
    const bytes = { 1: IMG.kiln, 2: IMG.wide, 3: IMG.leaf, 4: IMG.dot, 5: IMG.fifth, 6: IMG.sixth, 7: IMG.sixth, 11: IMG.wide, 12: IMG.wide, 13: IMG.wide, 14: IMG.wide }[Number(r.id.slice(-2))];
    if (bytes && r.bytes === bytes.length) store.objects["bf-public/" + r.path] = Buffer.from(bytes);
  });
  const ctx = {
    supabase: { from: db.client.from, rpc: db.client.rpc, storage: store },
    Date, JSON, Math, Promise, Number, Object, Array, String, Intl, Buffer, RegExp, Error, TypeError, Set, Map, URL,
    nowIso: () => "2026-11-05T12:00:00.000Z",
    process: { env: {} },
    require: p => p === "./lib/memberMastodon" ? MM : p === "./lib/memberMedia" ? MED : p === "./lib/apiKeyCrypto" ? CRYPTO : p === "./lib/guardedFetch" ? GF :
      p === "./lib/memberBluesky" ? MB : realRequire(p.indexOf("./") === 0 ? path.join(REPO, p) : p),
    fetch: global.fetch,
    console: { log() {}, error() {}, warn() {}, info() {} },
    setImmediate, setTimeout, clearTimeout, AsyncLocalStorage: require("async_hooks").AsyncLocalStorage,
    bskyGate,
    requireAuth: function requireAuth() {}, requireActiveSubscription: function requireActiveSubscription() {}, aiLimiter: function aiLimiter() {},
    rateLimit: function () { return function mastodonConnectLimiter() {}; },
    refuseUnlessSubscribed: async function () { return false; }
  };
  const routes = {};
  ctx.app = { post: function (p) { routes["post " + p] = arguments[arguments.length - 1]; }, get() {}, put() {} };
  vm.createContext(ctx);
  vm.runInContext(LIFTED, ctx);
  async function hit(key, user, body) {
    const [method, route] = R[key];
    const res = { code: 200, body: null, status(x) { this.code = x; return this; }, json(x) { this.body = clone(x); return this; } };
    const role = (db.rows("users").find(u => u.id === user) || {}).role || "user";
    await routes[method + " " + route]({ user: { id: user, role: role }, body: body || {}, params: {}, query: {} }, res,
      e => { res.error = e; res.code = 500; res.body = { error: String(e && e.message || e) }; });
    return res;
  }
  async function approve(proposal, which) {
    const fn = which === "mastodon" ? ctx.api.executePublishMastodonPost : ctx.api.executePublishSocialPost;
    try { return { result: await fn(clone(Object.assign({}, proposal, { status: "executing" }))) }; } catch (e) { return { error: e }; }
  }
  return { db, store, ctx, hit, approve };
}
function resetWorld() { BSKY.reset(); GATE.reset(); STUB.reset(); DECRYPTS.length = 0; }
const draftOf = (b, id) => b.db.rows("social_post_drafts").find(d => d.id === id);
const lastProposal = b => b.db.rows("agent_proposals").slice(-1)[0];
const settle = async (n) => { for (let i = 0; i < (n || 20); i++) await new Promise(r => setImmediate(r)); };

(async function main() {
  /* ════ I. imageDimensions ════ */
  console.log("\n══ I. imageDimensions ══");
  const D = (b, m) => MED.imageDimensions(b, m);
  check("I1. JPEG: SOF0 640 x 480; SOF2 (progressive) and SOF9 read the same way; a fill byte before a segment is skipped",
    J(D(jpeg(640, 480), "image/jpeg")) === J({ width: 640, height: 480 }) && J(D(jpeg(17, 33, 0xc2), "image/jpeg")) === J({ width: 17, height: 33 }) &&
    J(D(jpeg(2, 1, 0xc9), "image/jpeg")) === J({ width: 2, height: 1 }), J(D(jpeg(640, 480), "image/jpeg")));
  check("I2. JPEG: DHT (C4), JPG (C8) and DAC (CC) are not frames; a scan before any frame is null",
    D(B([0xff, 0xd8], seg(0xc4, B([0], u16(9), u16(9))), seg(0xc8, B([8], u16(5), u16(6), [1])), seg(0xcc, B([8], u16(5), u16(6), [1]))), "image/jpeg") === null &&
    D(jpeg(4, 4, 0xc0, { sosFirst: true }), "image/jpeg") === null);
  check("I3. PNG: IHDR 3 x 2", J(D(png(3, 2), "image/png")) === J({ width: 3, height: 2 }), J(D(png(3, 2), "image/png")));
  check("I4. WebP: VP8X canvas 300 x 200 (24-bit fields plus 1), VP8L 14-bit fields plus 1, VP8 u16 & 0x3fff (scale bits ignored)",
    J(D(webpX(300, 200), "image/webp")) === J({ width: 300, height: 200 }) && J(D(webpLossless(1000, 16383), "image/webp")) === J({ width: 1000, height: 16383 }) &&
    J(D(webpLossy(320, 240), "image/webp")) === J({ width: 320, height: 240 }), J([D(webpX(300, 200), "image/webp"), D(webpLossless(1000, 16383), "image/webp"), D(webpLossy(320, 240), "image/webp")]));
  check("I5. GIF: logical screen 5 x 7", J(D(gif(5, 7), "image/gif")) === J({ width: 5, height: 7 }));
  const bad = [[Buffer.alloc(0), "image/png"], [Buffer.from("not an image at all"), "image/png"], [png(3, 2).subarray(0, 20), "image/png"], [png(0, 2), "image/png"],
    [jpeg(9, 9).subarray(0, 40), "image/jpeg"], [jpeg(0, 9), "image/jpeg"], [B([0xff, 0xd8, 0xff, 0xc0, 0xff, 0xff, 1, 2, 3, 4, 5, 6]), "image/jpeg"],
    [riff(B("WEBP", webpChunk("VP8L", B([0x00], u32le(0), [0, 0])))), "image/webp"], [riff(B("WEBP", webpChunk("ALPH", Buffer.alloc(30)))), "image/webp"],
    [B("GIF89a", [0, 0, 0, 0], Buffer.alloc(8)), "image/gif"], [png(3, 2), "image/jpeg"], [gif(5, 7), "video/mp4"], ["a string", "image/png"], [null, "image/gif"], [undefined, "image/webp"]];
  let threw = false, nonNull = [];
  bad.forEach(([b, m], i) => { try { if (MED.imageDimensions(b, m) !== null) nonNull.push(i); } catch (e) { threw = true; } });
  check("I6. malformed, truncated, zero-sized, wrong-type and non-Buffer input is null, never a throw", !threw && nonNull.length === 0, J(nonNull));

  /* ════ F. filing ════ */
  console.log("\n══ F. filing: shapes, refusals, the frozen payload ══");
  const shapes = [["a string", "x"], ["null", null], ["empty", []], ["five", [mid(1), mid(2), mid(3), mid(4), mid(5)]], ["duplicate", [mid(1), mid(1)]],
    ["not a uuid", ["kiln"]], ["a number", [1]], ["an object", { a: mid(1) }], ["six", [mid(1), mid(2), mid(3), mid(4), mid(5), mid(7)]]];
  for (const [name, value] of shapes) {
    resetWorld();
    const b = build();
    const r = await b.hit("bsky", ALICE, { task_id: tid(1), media_ids: value });
    const m = await b.hit("masto", ALICE, { task_id: tid(3), media_ids: value });
    check("F1. media_ids " + name + ": 400 \"" + MED.POST_MESSAGES.shape + "\" on both routes, and nothing filed",
      r.code === 400 && r.body.error === MED.POST_MESSAGES.shape && m.code === 400 && m.body.error === MED.POST_MESSAGES.shape &&
      b.db.rows("social_post_drafts").length === 0 && b.db.rows("agent_proposals").length === 0, J([r.code, r.body, m.code, m.body]));
  }
  const refusals = [
    ["another member's image", [mid(11)], 404, "That image isn't in your Media Library."],
    ["an id nobody has", ["99999999-0000-4000-8000-000000000099"], 404, "That image isn't in your Media Library."],
    ["a video", [mid(8)], 400, "Only images can be attached to posts for now."],
    ["no alt text (only spaces), no label", [mid(6)], 400, "Add alt text to this image in your Media Library first: untitled image"],
    ["no alt text, labelled", [mid(1), mid(7)], 400, "Add alt text to this image in your Media Library first: Unlabelled photo"],
    ["over Bluesky's 2 MB", [mid(9)], 400, "This image is over Bluesky's 2 MB limit. Choose a smaller one."],
    ["alt over 1000 characters", [mid(12)], 400, MED.POST_MESSAGES.blueskyAltLong + "Long alt"]
  ];
  for (const [name, ids, code, msg] of refusals) {
    resetWorld();
    const b = build();
    const r = await b.hit("bsky", ALICE, { task_id: tid(1), media_ids: ids });
    check("F2. Bluesky, " + name + ": " + code + " \"" + msg + "\", nothing filed, no login and no upload",
      r.code === code && r.body && r.body.error === msg && b.db.rows("social_post_drafts").length === 0 && BSKY.logins.length === 0 && BSKY.blobs.length === 0, J([r.code, r.body]));
  }
  {
    resetWorld();
    const b = build();
    const ok = await b.hit("bsky", ALICE, { task_id: tid(1), media_ids: [mid(10)] });
    check("F3. Bluesky: exactly 2,000,000 bytes is accepted", ok.code === 201, J([ok.code, ok.body]));
  }
  {
    resetWorld();
    // the GIF fits exactly; the JPEG is larger
    const b = build({ mastoLimits: { image_size_limit: IMG.dot.length, media_description_limit: 40 } });
    const big = await b.hit("masto", ALICE, { task_id: tid(3), media_ids: [mid(1)] });
    const longAlt = await b.hit("masto", ALICE, { task_id: tid(3), media_ids: [mid(13)] });
    const video = await b.hit("masto", ALICE, { task_id: tid(3), media_ids: [mid(8)] });
    const foreign = await b.hit("masto", ALICE, { task_id: tid(3), media_ids: [mid(11)] });
    check("F4. Mastodon: over the connection's image_size_limit, alt over its media_description_limit, a video and another member's image are refused",
      big.code === 400 && big.body.error === "This image is over your Mastodon server's size limit. Choose a smaller one." &&
      longAlt.code === 400 && longAlt.body.error === MED.POST_MESSAGES.mastodonAltLong + "Mid alt" &&
      video.code === 400 && video.body.error === MED.POST_MESSAGES.onlyImages && foreign.code === 404 && foreign.body.error === MED.POST_MESSAGES.notInLibrary &&
      b.db.rows("social_post_drafts").length === 0, J([big.body, longAlt.body, video.body, foreign.body]));
    const fits = await b.hit("masto", ALICE, { task_id: tid(3), media_ids: [mid(4)] });
    check("F5. Mastodon: an image within those limits is filed", fits.code === 201, J([fits.code, fits.body]));
  }
  let filedB, filedBproposal, filedBdraft;
  {
    resetWorld();
    const b = build();
    const r = await b.hit("bsky", ALICE, { task_id: tid(1), media_ids: [mid(1), mid(2), mid(3), mid(4)] });
    const p = lastProposal(b), d = p && draftOf(b, p.payload.draft_id);
    const want = [1, 2, 3, 4].map(n => { const row = b.db.rows("member_media").find(x => x.id === mid(n)); return { id: row.id, sha256: row.sha256, mime: row.mime, bytes: row.bytes, alt: row.alt_text.trim() }; });
    check("F6. four images: 201; the payload's media is [{ id, sha256, mime, bytes, alt }] in order, alt trimmed",
      r.code === 201 && p && J(p.payload.media) === J(want), J([r.code, p && p.payload.media]));
    check("F7. the draft's media_ids are the four ids, in order", d && J(d.media_ids) === J([mid(1), mid(2), mid(3), mid(4)]), J(d && d.media_ids));
    check("F8. the payload keeps its other keys: draft_id, text, source_task_id, posts_as, media",
      p && J(Object.keys(p.payload)) === J(["draft_id", "text", "source_task_id", "posts_as", "media"]), J(p && Object.keys(p.payload)));
    check("F9. nothing went to Bluesky at filing: no login, no upload, no post", BSKY.logins.length === 0 && BSKY.blobs.length === 0 && BSKY.posts.length === 0 && DECRYPTS.length === 0,
      J([BSKY.logins.length, BSKY.blobs.length]));
    check("F10. the note says images always wait", r.body && /Images always wait for your approval\.$/.test(r.body.note), r.body && r.body.note);
    filedB = b; filedBproposal = p; filedBdraft = d;
  }
  {
    resetWorld();
    const b = build();
    const r = await b.hit("bsky", ALICE, { task_id: tid(1) });
    const p = lastProposal(b), d = p && draftOf(b, p.payload.draft_id);
    const ins = b.db.log.find(q => q.op === "insert" && q.table === "social_post_drafts");
    check("F11. no media_ids: exactly as before; the payload is draft_id, text, source_task_id, posts_as; the draft insert names no media_ids; the note ends as it did",
      r.code === 201 && J(Object.keys(p.payload)) === J(["draft_id", "text", "source_task_id", "posts_as"]) && !("media_ids" in ins.payload) &&
      J(d.media_ids) === J([]) && r.body.note === "Filed for approval. Nothing has been posted. Approving it posts exactly this text, as a new top-level post, from your Bluesky account @alice.bsky.social.",
      J([r.code, Object.keys(p.payload), r.body.note]));
    const m = await b.hit("masto", ALICE, { task_id: tid(3) });
    const mp = lastProposal(b);
    check("F12. Mastodon with no media_ids: the payload is draft_id, task_id, text, posts_as, measured, and the note ends as it did",
      m.code === 201 && J(Object.keys(mp.payload)) === J(["draft_id", "task_id", "text", "posts_as", "measured"]) &&
      m.body.note === "Filed for approval. Nothing has been posted. Approving it posts exactly this text, publicly, from your Mastodon account @alice@mastodon.social.", J([m.code, m.body.note]));
  }

  /* ════ A. never automatic ════ */
  console.log("\n══ A. a post with images is never automatic ══");
  {
    resetWorld();
    const b = build({ autoBsky: true, autoMasto: true });
    const r = await b.hit("bsky", ALICE, { task_id: tid(1), media_ids: [mid(1)] });
    const p = lastProposal(b);
    check("A1. Bluesky with auto_post on and an image: filed, pending, posts_as.automatic false, nothing posted, no login",
      r.code === 201 && r.body.automatic !== true && p.status === "pending" && p.payload.posts_as.automatic === false && BSKY.posts.length === 0 && BSKY.logins.length === 0 &&
      /Images always wait for your approval\.$/.test(r.body.note), J([r.code, r.body.automatic, p.status, p.payload.posts_as]));
    const m = await b.hit("masto", ALICE, { task_id: tid(3), media_ids: [mid(2)] });
    const mp = lastProposal(b);
    check("A2. Mastodon with auto_post on and an image: the same", m.code === 201 && m.body.automatic !== true && mp.status === "pending" && mp.payload.posts_as.automatic === false &&
      STUB.statuses.length === 0 && STUB.uploads.length === 0 && /Images always wait for your approval\.$/.test(m.body.note), J([m.code, m.body.automatic, mp.payload.posts_as]));
    const plain = await b.hit("bsky", ALICE, { task_id: tid(2) });
    check("A3. the same member's post with no image still posts automatically (the harness's own control)", plain.code === 201 && plain.body.automatic === true && plain.body.posted === true &&
      BSKY.posts.length === 1, J([plain.code, plain.body.automatic, plain.body.posted]));
  }

  /* ════ B. the Bluesky executor ════ */
  console.log("\n══ B. Bluesky: one login, uploads then the post, the embed ══");
  {
    resetWorld();
    const b = filedB;
    const x = await b.approve(filedBproposal);
    const post = BSKY.posts[0], rec = post && post.record;
    check("B1. approved: one login (one decrypt), four uploads, then one post, all in the member's one session",
      x.result && BSKY.logins.length === 1 && DECRYPTS.length === 1 && BSKY.blobs.length === 4 && BSKY.posts.length === 1 &&
      BSKY.blobs.every((bl, i) => bl.order === i && bl.who === "member") && post.order === 4 && GATE.calls === 0, J([BSKY.logins.length, BSKY.blobs.map(x => x.order), post && post.order, x.error && x.error.message]));
    check("B2. each upload is the image's own bytes with its type, in order",
      J(BSKY.blobs.map(bl => [bl.sha, bl.encoding])) === J([[sha(IMG.kiln), "image/jpeg"], [sha(IMG.wide), "image/png"], [sha(IMG.leaf), "image/webp"], [sha(IMG.dot), "image/gif"]]));
    const imgs = rec && rec.embed && rec.embed.images;
    check("B3. the record: text, createdAt, embed { $type app.bsky.embed.images, images }, and no reply",
      rec && J(Object.keys(rec)) === J(["text", "createdAt", "embed"]) && rec.embed.$type === "app.bsky.embed.images" && Array.isArray(imgs) && imgs.length === 4 && !("reply" in rec), J(rec && Object.keys(rec)));
    check("B4. each image is the blob Bluesky answered, the frozen alt, and the aspect ratio read from its bytes (640x480, 3x2, 300x200, 5x7)",
      imgs && imgs.every((im, i) => J(im.image) === J({ $type: "blob", ref: { $link: "bafkblob" + (i + 1) }, mimeType: filedBproposal.payload.media[i].mime, size: filedBproposal.payload.media[i].bytes })) &&
      J(imgs.map(im => im.alt)) === J(["A blue kiln, door open", "Three bowls in a row", "A leaf-shaped dish", "A spinning dot"]) &&
      J(imgs.map(im => im.aspectRatio)) === J([{ width: 640, height: 480 }, { width: 3, height: 2 }, { width: 300, height: 200 }, { width: 5, height: 7 }]), J(imgs));
    check("B5. the draft is published", draftOf(b, filedBdraft.id).status === "published" && !!draftOf(b, filedBdraft.id).platform_post_uri);
  }
  {
    resetWorld();
    const b = build();
    await b.hit("bsky", ALICE, { task_id: tid(1), media_ids: [mid(2)] });
    const p = lastProposal(b);
    b.db.rows("member_media").find(r => r.id === mid(2)).alt_text = "Changed in the library after filing";
    const x = await b.approve(p);
    const im = BSKY.posts[0] && BSKY.posts[0].record.embed.images[0];
    check("B6. a library alt edit after filing changes nothing: the frozen alt is posted", x.result && im && im.alt === "Three bowls in a row", im && im.alt);
  }
  {
    resetWorld();
    const b = build();
    const r = await b.hit("bsky", OWNER, { task_id: tid(4), media_ids: [mid(14)] });
    const p = lastProposal(b);
    const x = await b.approve(p);
    check("B7. the platform path (the owner, no connection): one bskyGate.call, the upload then the post in its one fn, no member login",
      r.code === 201 && p.payload.posts_as.account === "platform" && p.payload.posts_as.automatic === false && x.result && GATE.calls === 1 && BSKY.logins.length === 0 &&
      BSKY.blobs.length === 1 && BSKY.blobs[0].who === "platform" && BSKY.posts.length === 1 && BSKY.posts[0].who === "platform" && BSKY.posts[0].order === 1 &&
      BSKY.posts[0].record.embed.images[0].alt === "The studio sign", J([r.code, GATE.calls, BSKY.blobs.length, x.error && x.error.message]));
  }
  {
    resetWorld();
    const b = build();
    await b.hit("bsky", ALICE, { task_id: tid(1) });
    const x = await b.approve(lastProposal(b));
    const rec = BSKY.posts[0] && BSKY.posts[0].record;
    check("B8. a Bluesky post with no images: record keys exactly text, createdAt; no upload; one login",
      x.result && rec && J(Object.keys(rec)) === J(["text", "createdAt"]) && BSKY.blobs.length === 0 && BSKY.logins.length === 1, J(rec && Object.keys(rec)));
  }
  check("B9. replies carry no images in this build: executeReplyBlueskyMention never uploads or reads media",
    (() => { const t = definitionOf("executeReplyBlueskyMention") || ""; return t.length > 100 && t.indexOf("uploadBlob") === -1 && t.indexOf("media") === -1; })());

  /* ════ E. the two-way check and the byte check ════ */
  console.log("\n══ E. the executors hold the payload to the draft and the bytes to the frozen copy ══");
  const changes = [
    ["the draft's ids reordered", (b, p, d) => { d.media_ids = [mid(2), mid(1)]; }],
    ["the draft's ids emptied", (b, p, d) => { d.media_ids = []; }],
    ["the payload's ids emptied, the draft's kept", (b, p, d) => { p.payload.media = []; }],
    ["the row deleted", (b) => { b.db.tables.member_media = b.db.rows("member_media").filter(r => r.id !== mid(2)); }],
    ["the row given to another member", (b) => { b.db.rows("member_media").find(r => r.id === mid(2)).user_id = BOB; }],
    ["the row's sha256 changed", (b) => { b.db.rows("member_media").find(r => r.id === mid(2)).sha256 = "0".repeat(64); }],
    ["the row's type changed", (b) => { b.db.rows("member_media").find(r => r.id === mid(2)).mime = "image/gif"; }],
    ["the stored bytes replaced by others of the same length", (b) => { const k = "bf-public/" + pathOf(ALICE, 2, "png"); const x = Buffer.from(b.store.objects[k]); x[x.length - 5] ^= 0xff; b.store.objects[k] = x; }],
    ["the stored bytes longer than row.bytes", (b) => { const k = "bf-public/" + pathOf(ALICE, 2, "png"); b.store.objects[k] = B(b.store.objects[k], [0]); }],
    ["the stored object gone", (b) => { delete b.store.objects["bf-public/" + pathOf(ALICE, 2, "png")]; }],
    ["the frozen alt emptied", (b, p) => { p.payload.media[1].alt = " "; }]
  ];
  for (const [name, change] of changes) {
    for (const svc of ["bluesky", "mastodon"]) {
      resetWorld();
      const b = build();
      await b.hit(svc === "bluesky" ? "bsky" : "masto", ALICE, { task_id: svc === "bluesky" ? tid(1) : tid(3), media_ids: [mid(1), mid(2)] });
      const p = clone(lastProposal(b)), d = draftOf(b, p.payload.draft_id);
      change(b, p, d);
      const x = await b.approve(p, svc);
      const dr = draftOf(b, p.payload.draft_id);
      check("E1. " + svc + ", " + name + ": the post fails, the draft is publish_failed with the reason, and nothing is sent (no login, no upload, no post)",
        !!x.error && dr.status === "publish_failed" && typeof dr.publish_error === "string" && /nothing was posted/i.test(dr.publish_error) &&
        BSKY.logins.length === 0 && BSKY.blobs.length === 0 && BSKY.posts.length === 0 && STUB.seen.length === 0 && DECRYPTS.length === 0,
        J([x.error && x.error.message, dr.status, BSKY.logins.length, STUB.seen.length]));
    }
  }
  {
    const rowOf = b => clone(b.db.rows("member_media").find(r => r.id === mid(2)));
    const frozenOf = row => ({ id: row.id, sha256: row.sha256, mime: row.mime, bytes: row.bytes, alt: "x" });
    const reason = async (row, frozen, store, maxBytes) => { try { await MED.readMediaForPost(row, frozen, { storage: store, userId: ALICE, maxBytes: maxBytes || 2000000 }); return "ok"; } catch (e) { return e.name + ":" + e.reason; } };
    const b = build(), row = rowOf(b), fz = frozenOf(row);
    const good = await MED.readMediaForPost(row, fz, { storage: b.store, userId: ALICE, maxBytes: 2000000 });
    check("E2. readMediaForPost: the stored bytes, byte for byte", Buffer.isBuffer(good) && good.equals(IMG.wide));
    const k = "bf-public/" + row.path;
    const b2 = build(); b2.store.objects[k] = B(b2.store.objects[k], [0]);
    const b3 = build(); { const x = Buffer.from(b3.store.objects[k]); x[x.length - 5] ^= 0xff; b3.store.objects[k] = x; }
    const b4 = build();
    const overLimit = await reason(row, fz, b4.store, row.bytes - 1);
    check("E3. a longer object is MediaChanged:length; the same length with other bytes is MediaChanged:sha",
      (await reason(row, fz, b2.store)) === "MediaChanged:length" && (await reason(row, fz, b3.store)) === "MediaChanged:sha");
    check("E4. a row over the limit is MediaChanged:limit, refused before any download", overLimit === "MediaChanged:limit" && b4.store.downloads.length === 0, J([overLimit, b4.store.downloads]));
    check("E5. a missing object is MediaChanged:unread; another member's row, or a frozen sha256 that differs, is MediaChanged:row",
      (await reason(row, fz, fakeStorage())) === "MediaChanged:unread" && (await reason(Object.assign({}, row, { user_id: BOB }), fz, b.store)) === "MediaChanged:row" &&
      (await reason(row, Object.assign({}, fz, { sha256: "1".repeat(64) }), b.store)) === "MediaChanged:row");
  }

  /* ════ M. Mastodon ════ */
  console.log("\n══ M. Mastodon: the media limits, the multipart upload, the polls ══");
  {
    resetWorld();
    const v1 = await MM.verify("mastodon.social", TOK.alice);
    const n1 = STUB.seen.length;
    const v2 = await MM.verify("small.example", TOK.alice);
    const v3 = await MM.verify("odd.example", TOK.alice);
    const v4 = await MM.verify("nomedia.example", TOK.alice);
    check("M1. verify reads configuration.media_attachments in the same /api/v2/instance answer: still exactly two requests",
      n1 === 2 && STUB.seen[0].path === "/api/v1/accounts/verify_credentials" && STUB.seen[1].path === "/api/v2/instance" && !bearerOf(STUB.seen[1].headers), J(STUB.seen.slice(0, 2).map(q => q.path)));
    check("M2a. image_size_limit and description_limit are taken when in 168's ranges, else 16777216 and 1500",
      v1.image_size_limit === 10485760 && v1.media_description_limit === 1500 && v2.image_size_limit === 4000 && v2.media_description_limit === 40 &&
      v3.image_size_limit === 16777216 && v3.media_description_limit === 1500 && v4.image_size_limit === 16777216 && v4.media_description_limit === 1500, J([v1, v2, v3, v4]));
    resetWorld();
    const b = build({ noMasto: true });
    const c = await b.hit("connect", ALICE, { instance: "small.example", access_token: TOK.alice });
    const row = b.db.rows("member_mastodon_connections").find(r => r.user_id === ALICE);
    check("M3. connect stores them on the connection", c.code === 200 && row && row.image_size_limit === 4000 && row.media_description_limit === 40, J([c.code, row && [row.image_size_limit, row.media_description_limit]]));
    check("M4. the defaults hold for a connection made before 168 (stored values missing or out of range)",
      MM.imageSizeLimitOf({}) === 16777216 && MM.descriptionLimitOf({ media_description_limit: 0 }) === 1500 && MM.imageSizeLimitOf({ image_size_limit: 104857601 }) === 16777216);
  }
  async function mastoPost(mode, ids, opts) {
    resetWorld();
    STUB.mode = mode;
    if (opts && opts.pollsUntilReady) STUB.pollsUntilReady = opts.pollsUntilReady;
    const b = build();
    const f = await b.hit("masto", ALICE, { task_id: tid(3), media_ids: ids });
    const p = lastProposal(b);
    STUB.seen.length = 0;
    const x = await b.approve(p, "mastodon");
    return { b, f, p, x, draft: draftOf(b, p.payload.draft_id) };
  }
  {
    const r = await mastoPost("ready", [mid(1), mid(2)]);
    const st = STUB.statuses[0];
    check("M5. ready at once (200 with a url): two uploads, no poll, then one status with media_ids in order and Idempotency-Key the draft id",
      r.x.result && STUB.uploads.length === 2 && STUB.polls.length === 0 && STUB.sleeps.length === 0 && STUB.statuses.length === 1 &&
      J(st.body) === J({ status: r.p.payload.text, visibility: "public", media_ids: STUB.uploads.map(u => u.id) }) && st.key === r.draft.id && DECRYPTS.length === 1,
      J([r.x.error && r.x.error.message, st && st.body]));
    check("M6. the order of requests: upload, upload, status, all with the member's token", J(STUB.seen.map(q => q.method + " " + q.path)) === J(["POST /api/v2/media", "POST /api/v2/media", "POST /api/v1/statuses"]) &&
      STUB.seen.every(q => bearerOf(q.headers) === TOK.alice));
    const u = STUB.uploads[0];
    const bnd = (/^multipart\/form-data; boundary=(.+)$/.exec(u.contentType || "") || [])[1];
    const want = bnd && B("--" + bnd + CRLF + "Content-Disposition: form-data; name=\"file\"; filename=\"image.jpg\"" + CRLF + "Content-Type: image/jpeg" + CRLF + CRLF,
      IMG.kiln, CRLF + "--" + bnd + CRLF + "Content-Disposition: form-data; name=\"description\"" + CRLF + CRLF + "A blue kiln, door open" + CRLF + "--" + bnd + "--" + CRLF);
    check("M7. the multipart body: a file part with the image's own bytes and type, a description part with the frozen alt, the closing boundary",
      !!bnd && u.raw.equals(want), u.contentType);
    const bnd2 = (/boundary=(.+)$/.exec(STUB.uploads[1].contentType || "") || [])[1];
    check("M8. the boundary is crypto-random hex, different for each upload, and the length the request said",
      /^BizForceBoundary[0-9a-f]{32}$/.test(bnd) && /^BizForceBoundary[0-9a-f]{32}$/.test(bnd2) && bnd !== bnd2 &&
      STUB.seen[0].headers["Content-Length"] === String(STUB.uploads[0].raw.length), J([bnd, bnd2]));
    check("M9. the draft is published", r.draft.status === "published");
  }
  {
    const r = await mastoPost("slow", [mid(1)], { pollsUntilReady: 2 });
    check("M10. 202, then 206, then 200 with a url: two polls, each after a 2 second wait, then the status",
      r.x.result && STUB.uploads.length === 1 && STUB.polls.length === 2 && J(STUB.sleeps) === J([2000, 2000]) && STUB.statuses.length === 1 &&
      J(STUB.seen.map(q => q.method + " " + q.path.replace(/[0-9]{6,}/, ":id"))) === J(["POST /api/v2/media", "GET /api/v1/media/:id", "GET /api/v1/media/:id", "POST /api/v1/statuses"]),
      J([r.x.error && r.x.error.message, STUB.polls.length, STUB.sleeps]));
  }
  {
    const r = await mastoPost("slow", [mid(1), mid(2), mid(3), mid(4)], { pollsUntilReady: 5 });
    check("M11. the most a post can take: four images each ready on the fifth poll is 4 uploads, 20 polls and one status, in one token",
      r.x.result && STUB.uploads.length === 4 && STUB.polls.length === 20 && STUB.statuses.length === 1 && DECRYPTS.length === 1, J([STUB.uploads.length, STUB.polls.length, r.x.error && r.x.error.message]));
  }
  {
    const r = await mastoPost("never", [mid(1), mid(2)]);
    const NOT_READY = "Mastodon was still processing an image. Approve the post again in a minute.";
    check("M12. never ready: five polls, five 2 second waits, then it gives up: no status is posted",
      !!r.x.error && STUB.uploads.length === 1 && STUB.polls.length === 5 && J(STUB.sleeps) === J([2000, 2000, 2000, 2000, 2000]) && STUB.statuses.length === 0,
      J([STUB.uploads.length, STUB.polls.length, STUB.statuses.length]));
    check("M13. ... and the draft is publish_failed with \"" + NOT_READY + "\"", r.draft.status === "publish_failed" && r.draft.publish_error === NOT_READY &&
      r.x.error.message.indexOf(NOT_READY) !== -1, J([r.draft.status, r.draft.publish_error]));
  }
  {
    resetWorld();
    const b = build();
    await b.hit("masto", ALICE, { task_id: tid(3) });
    const p = lastProposal(b);
    const x = await b.approve(p, "mastodon");
    check("M14. a Mastodon post with no images: no media request, and the status body is exactly { status, visibility }",
      x.result && STUB.uploads.length === 0 && STUB.polls.length === 0 && STUB.statuses.length === 1 && J(STUB.statuses[0].body) === J({ status: p.payload.text, visibility: "public" }),
      J(STUB.statuses[0] && STUB.statuses[0].body));
  }

  /* ════ G. guardedJsonRequest's Buffer body ════ */
  console.log("\n══ G. guardedJsonRequest: a Buffer body ══");
  {
    const MP = "multipart/form-data; boundary=abc";
    const refused = async (opts) => { try { await JSON_MODE("https://mastodon.social/api/v2/media", Object.assign({ method: "POST" }, opts)); return "sent"; } catch (e) { return e instanceof TypeError ? "TypeError: " + e.message : "other: " + e.message; } };
    resetWorld();
    const noType = await refused({ body: Buffer.from("x") });
    const jsonType = await refused({ body: Buffer.from("x"), headers: { "Content-Type": "application/json" } });
    const bare = await refused({ body: Buffer.from("x"), headers: { "Content-Type": "multipart/form-data; boundary=" } });
    check("G1. a Buffer body needs the caller's multipart/form-data; boundary=... Content-Type, else a TypeError before any request",
      /^TypeError/.test(noType) && /^TypeError/.test(jsonType) && /^TypeError/.test(bare) && STUB.seen.length === 0, J([noType, jsonType, bare]));
    const overDefault = await refused({ body: Buffer.alloc(GF.JSON_MAX_UPLOAD_BYTES + 1), headers: { "Content-Type": MP, Authorization: "Bearer " + TOK.alice } });
    const atDefault = await refused({ body: Buffer.alloc(GF.JSON_MAX_UPLOAD_BYTES), headers: { "Content-Type": MP, Authorization: "Bearer " + TOK.alice } });
    check("G2. at most maxUploadBytes, 1 MB by default: one byte over is refused, exactly 1 MB is sent",
      GF.JSON_MAX_UPLOAD_BYTES === 1048576 && /^TypeError/.test(overDefault) && atDefault === "sent", J([overDefault, atDefault]));
    const ceiling = await refused({ body: Buffer.from("x"), headers: { "Content-Type": MP }, maxUploadBytes: GF.JSON_MAX_UPLOAD_BYTES_CEILING + 1 });
    const zero = await refused({ body: Buffer.from("x"), headers: { "Content-Type": MP }, maxUploadBytes: 0 });
    const half = await refused({ body: Buffer.from("x"), headers: { "Content-Type": MP }, maxUploadBytes: 1.5 });
    const atCeiling = await refused({ body: Buffer.alloc(GF.JSON_MAX_UPLOAD_BYTES + 1), headers: { "Content-Type": MP, Authorization: "Bearer " + TOK.alice }, maxUploadBytes: GF.JSON_MAX_UPLOAD_BYTES_CEILING });
    check("G3. maxUploadBytes above the 12 MB ceiling, 0 or not whole is refused, never clamped; the ceiling itself is allowed",
      GF.JSON_MAX_UPLOAD_BYTES_CEILING === 12582912 && /maxUploadBytes must be/.test(ceiling) && /maxUploadBytes must be/.test(zero) && /maxUploadBytes must be/.test(half) && atCeiling === "sent",
      J([ceiling, zero, half, atCeiling]));
    resetWorld();
    const bytes = Buffer.from([0, 255, 0xc3, 0x28, 10, 13, 0x80]);
    await JSON_MODE("https://mastodon.social/api/v2/media", { method: "POST", body: bytes, headers: { "Content-Type": MP, Authorization: "Bearer " + TOK.alice } });
    const sent = STUB.seen[0];
    check("G4. the bytes go out as they are (not JSON, not UTF-8), under the caller's Content-Type, with their own Content-Length",
      sent && sent.raw.equals(bytes) && sent.headers["Content-Type"] === MP && sent.headers["Content-Length"] === "7", sent && J([sent.raw, sent.headers["Content-Type"]]));
    resetWorld();
    await JSON_MODE("https://mastodon.social/api/v1/statuses", { method: "POST", body: { status: "hi", visibility: "public" }, headers: { Authorization: "Bearer " + TOK.alice } });
    check("G5. a JSON body is as before: JSON, application/json", STUB.seen[0] && STUB.seen[0].raw.toString("utf8") === J({ status: "hi", visibility: "public" }) && STUB.seen[0].headers["Content-Type"] === "application/json");
    const getBody = await refused({ method: "GET", body: Buffer.from("x"), headers: { "Content-Type": MP } });
    check("G6. a GET still carries no body, Buffer or not", /only a POST carries a body/.test(getBody), getBody);
  }

  /* ════ U. where used ════ */
  console.log("\n══ U. \"Where used\": a pending post blocks deletion, a published one does not ══");
  {
    const b = build();
    const P = pathOf(ALICE, 2, "png");
    const at = (status, user, platform) => ({ id: crypto.randomUUID(), user_id: user || ALICE, platform: platform || "bluesky", content: "x", status: status, media_ids: [mid(1), mid(2)] });
    const uses = async () => MED.findUses(b.db.client, ALICE, P, BASE);
    check("U1. with no post holding it, it is unused", J(await uses()) === J([]));
    b.db.tables.social_post_drafts = [at("published"), at("publish_failed"), at("pending_approval", BOB)];
    check("U2. a published post, a failed one, and another member's pending one do not block deletion", J(await uses()) === J([]), J(await uses()));
    b.db.tables.social_post_drafts.push(at("pending_approval", ALICE, "mastodon"));
    const u = await uses();
    check("U3. a pending post of the member's is a use: \"A social post waiting for approval (Mastodon)\"",
      J(u) === J([{ place: "A social post waiting for approval", title: "Mastodon" }]) && MED.usesText(u) === "This file is used in: A social post waiting for approval (Mastodon).", J(u));
    check("U4. social_post_drafts is not a FILE_TABLES table, so account deletion is unchanged", !AFL.FILE_TABLES.some(t => t.table === "social_post_drafts"));
    const failing = build();
    failing.db.client.from = (orig => t => t === "social_post_drafts" ? { select() { return this; }, eq() { return this; }, range() { return Promise.resolve({ data: null, error: { message: "down" } }); } } : orig(t))(failing.db.client.from);
    let threwUses = false;
    try { await MED.findUses(failing.db.client, ALICE, P, BASE); } catch (e) { threwUses = true; }
    check("U5. a posts table that cannot be read throws, so the file is never called unused on a partial read", threwUses);
  }

  /* ════ P. the pages ════ */
  console.log("\n══ P. the Social page and proposals.html ══");
  let JSDOM = null;
  try { JSDOM = require("jsdom").JSDOM; } catch (e) { JSDOM = null; }
  const social = fe("agents/social.html") || "";
  check("P1. social.html loads media-picker.js right before social-publish.js",
    social.indexOf('<script src="/scripts/media-picker.js"></script>\n<script src="/scripts/social-publish.js"></script>') !== -1);
  if (JSDOM) {
    const HOSTILE = "<img src=x onerror=alert(1)>";
    const PICKS = [
      { id: mid(1), url: BASE + "/storage/v1/object/public/bf-public/" + pathOf(ALICE, 1, "jpg"), kind: "image", mime: "image/jpeg", label: "Kiln photo", alt_text: HOSTILE },
      { id: mid(7), url: BASE + "/storage/v1/object/public/bf-public/" + pathOf(ALICE, 7, "png"), kind: "image", mime: "image/png", label: "Unlabelled photo", alt_text: "" },
      { id: mid(2), url: "javascript:alert(1)", kind: "image", mime: "image/png", label: "Wide", alt_text: "Three bowls" },
      { id: mid(3), url: BASE + "/x3.webp", kind: "image", mime: "image/webp", label: "Leaf", alt_text: "Leaf" },
      { id: mid(4), url: BASE + "/x4.gif", kind: "image", mime: "image/gif", label: "Dot", alt_text: "Dot" }
    ];
    async function page(answers) {
      const dom = new JSDOM("<!DOCTYPE html><html><head></head><body><div id=\"result\"></div></body></html>", { url: "https://bizforceai.net/agents/social.html", runScripts: "outside-only" });
      const w = dom.window, log = { fetches: [], picks: [] };
      w.localStorage.setItem("bf_token", "tok");
      let pickAt = 0;
      w.BFMediaPicker = { open: function (o) { log.picks.push(clone(o)); const it = PICKS[pickAt++]; return Promise.resolve(it ? { url: it.url, type: "image", name: it.label, item: clone(it) } : null); } };
      w.fetch = function (u, init) {
        const m = (init && init.method) || "GET";
        log.fetches.push({ url: String(u), method: m, body: init && init.body ? JSON.parse(init.body) : undefined });
        const a = answers.find(x => String(u).indexOf(x.match) !== -1 && (!x.method || x.method === m)) || { status: 404, body: {} };
        const p = Promise.resolve({ ok: (a.status || 200) < 400, status: a.status || 200, json: () => Promise.resolve(clone(a.body)) });
        p.catch(() => {});
        return p;
      };
      w.eval(fe("scripts/social-publish.js"));
      await settle();
      return { w, doc: w.document, log };
    }
    const ANS = [{ match: "/api/social/bluesky/status", body: { connected: true, status: "connected", handle: "alice.bsky.social" } },
      { match: "/api/social/bluesky/automation", body: { auto_post: false } },
      { match: "/api/social/mastodon/status", body: { connected: true, status: "connected", account: "@alice@mastodon.social", max_characters: 500 } },
      { match: "/api/social/mastodon/automation", body: { auto_post: false } },
      { match: "/api/agents/social/propose-post", method: "POST", body: { note: "Filed for approval. Images always wait for your approval." }, status: 201 },
      { match: "/api/social/mastodon/propose-post", method: "POST", status: 400, body: { error: "Add alt text to this image in your Media Library first: " + HOSTILE } }];
    const P1 = await page(ANS);
    const resEl = P1.doc.getElementById("result");
    P1.w.bfAfterToolResult("social", "post", { success: true, platform: "bluesky", task_id: tid(1) }, resEl);
    await settle(40);
    const form = P1.doc.querySelector(".sp-file[data-sp-task]");
    const kids = form ? Array.from(form.children) : [];
    const idx = sel => kids.findIndex(k => k.matches(sel));
    const addBtn = form && form.querySelector("[data-sp-add-images]");
    check("P2. the Bluesky box: \"Add images (up to 4)\" sits between the explanation line and the File button",
      !!form && !!addBtn && addBtn.textContent === "Add images (up to 4)" && idx(".sp-images") > idx("p.sp-quiet:not(.sp-posts-as)") && idx(".sp-images") < idx("[data-sp-file]") && idx("[data-sp-file]") !== -1,
      form && form.innerHTML.slice(0, 300));
    const lines = form ? Array.from(form.querySelectorAll(".sp-images p")).map(p => p.textContent) : [];
    check("P3. the lines, word for word: \"Images always wait for your approval.\" and \"Bluesky accepts images up to 2 MB.\"",
      J(lines) === J(["Images always wait for your approval.", "Bluesky accepts images up to 2 MB."]), J(lines));
    form.querySelector("[data-sp-file]").click();
    await settle(20);
    const first = P1.log.fetches.find(f => f.method === "POST");
    check("P4. filing with no image sends exactly { task_id }", first && J(first.body) === J({ task_id: tid(1) }), first && J(first.body));
  }
  if (JSDOM) {
    const HOSTILE = "<img src=x onerror=alert(1)>";
    const PICKS = [
      { id: mid(1), url: BASE + "/storage/v1/object/public/bf-public/" + pathOf(ALICE, 1, "jpg"), kind: "image", label: "Kiln photo", alt_text: HOSTILE },
      { id: mid(7), url: BASE + "/storage/v1/object/public/bf-public/" + pathOf(ALICE, 7, "png"), kind: "image", label: "Unlabelled photo", alt_text: "" },
      { id: mid(2), url: "javascript:alert(1)", kind: "image", label: "Wide", alt_text: "Three bowls" },
      { id: mid(1), url: BASE + "/again.jpg", kind: "image", label: "Kiln photo", alt_text: "again" },
      { id: mid(3), url: BASE + "/x3.webp", kind: "image", label: "Leaf", alt_text: "Leaf" },
      { id: mid(4), url: BASE + "/x4.gif", kind: "image", label: "Dot", alt_text: "Dot" }
    ];
    const dom = new JSDOM("<!DOCTYPE html><html><head></head><body><div id=\"r1\"></div><div id=\"r2\"></div></body></html>", { url: "https://bizforceai.net/agents/social.html", runScripts: "outside-only" });
    const w = dom.window, doc = w.document, log = { fetches: [], picks: [] };
    w.localStorage.setItem("bf_token", "tok");
    let pickAt = 0;
    w.BFMediaPicker = { open: function (o) { log.picks.push(clone(o)); const it = PICKS[pickAt++]; return Promise.resolve(it ? { url: it.url, type: "image", name: it.label, item: clone(it) } : null); } };
    const ANS = [{ match: "/api/social/bluesky/status", body: { connected: true, status: "connected", handle: "alice.bsky.social" } },
      { match: "/api/social/bluesky/automation", body: { auto_post: false } },
      { match: "/api/social/mastodon/status", body: { connected: true, status: "connected", account: "@alice@mastodon.social", max_characters: 500 } },
      { match: "/api/social/mastodon/automation", body: { auto_post: false } },
      { match: "/api/agents/social/propose-post", method: "POST", status: 400, body: { error: "This image is over Bluesky's 2 MB limit. Choose a smaller one. " + HOSTILE } },
      { match: "/api/social/mastodon/propose-post", method: "POST", status: 201, body: { note: "Filed for approval." } }];
    w.fetch = function (u, init) {
      const m = (init && init.method) || "GET";
      log.fetches.push({ url: String(u), method: m, body: init && init.body ? JSON.parse(init.body) : undefined });
      const a = ANS.find(x => String(u).indexOf(x.match) !== -1 && (!x.method || x.method === m)) || { status: 404, body: {} };
      const p = Promise.resolve({ ok: (a.status || 200) < 400, status: a.status || 200, json: () => Promise.resolve(clone(a.body)) });
      p.catch(() => {});
      return p;
    };
    w.eval(fe("scripts/social-publish.js"));
    await settle();
    w.bfAfterToolResult("social", "post", { success: true, platform: "bluesky", task_id: tid(1) }, doc.getElementById("r1"));
    w.bfAfterToolResult("social", "post", { success: true, platform: "mastodon", task_id: tid(3) }, doc.getElementById("r2"));
    await settle(40);
    const bForm = doc.querySelector("#r1 .sp-file"), mForm = doc.querySelector("#r2 .sp-masto");
    const add = f => { f.querySelector("[data-sp-add-images]").click(); return settle(20); };
    await add(bForm); await add(bForm); await add(bForm);
    const rows = Array.from(bForm.querySelectorAll(".sp-image"));
    check("P5. the picker opens for images, and asks for the item (its id)", log.picks.length === 3 && log.picks.every(o => o.kind === "image" && o.withItem === true), J(log.picks));
    check("P6. each picked image: a thumbnail, its alt text as text (never markup), and a Remove button",
      rows.length === 3 && rows[0].querySelector(".sp-image-alt").textContent === HOSTILE && doc.querySelectorAll("img[onerror]").length === 0 &&
      rows.every(r => r.querySelector("button").textContent === "Remove") && rows[0].querySelector("img").getAttribute("src") === PICKS[0].url, bForm.innerHTML.slice(0, 400));
    check("P7. an image with no alt text says \"No alt text yet\", as a warning", rows[1].querySelector(".sp-image-alt").textContent === "No alt text yet" &&
      rows[1].querySelector(".sp-image-alt").classList.contains("sp-warn"));
    check("P8. a thumbnail address that is not https is never used", !rows[2].querySelector("img").hasAttribute("src"));
    await add(bForm);
    check("P9. the same image twice is kept once", bForm.querySelectorAll(".sp-image").length === 3);
    // two picks in flight at three images: both open, only the first may land
    bForm.querySelector("[data-sp-add-images]").click();
    bForm.querySelector("[data-sp-add-images]").click();
    await settle(30);
    check("P10. at four images, Add is disabled and a fifth is never taken, even from two picks in flight",
      bForm.querySelectorAll(".sp-image").length === 4 && bForm.querySelector("[data-sp-add-images]").disabled === true, bForm.querySelectorAll(".sp-image").length);
    const picksBefore = log.picks.length;
    bForm.querySelector("[data-sp-add-images]").disabled = false;
    await add(bForm);
    check("P11. ... and when the button is pressed anyway at four, the picker is not even opened",
      bForm.querySelectorAll(".sp-image").length === 4 && log.picks.length === picksBefore, J([log.picks.length, picksBefore]));
    bForm.querySelectorAll(".sp-image")[1].querySelector("[data-sp-remove-image]").click();
    await settle();
    check("P12. Remove takes it off", J(Array.from(bForm.querySelectorAll(".sp-image")).map(r => r.getAttribute("data-sp-image-id"))) === J([mid(1), mid(2), mid(3)]));
    bForm.querySelector("[data-sp-file]").click();
    await settle(20);
    const bPost = log.fetches.find(f => f.method === "POST" && /propose-post/.test(f.url) && /agents\/social/.test(f.url));
    check("P13. filing sends { task_id, media_ids } in the order shown", bPost && J(bPost.body) === J({ task_id: tid(1), media_ids: [mid(1), mid(2), mid(3)] }), bPost && J(bPost.body));
    const msg = bForm.querySelector(".sp-file-msg");
    check("P14. the server's refusal is shown as it comes, as text", msg && msg.textContent === ANS[4].body.error && doc.querySelectorAll("img[onerror]").length === 0, msg && msg.textContent);
    const mLines = mForm ? Array.from(mForm.querySelectorAll(".sp-images p")).map(p => p.textContent) : [];
    check("P15. the Mastodon box has the same control and the approval line, and no Bluesky size line",
      !!mForm && mForm.querySelector("[data-sp-add-images]").textContent === "Add images (up to 4)" && J(mLines) === J(["Images always wait for your approval."]), J(mLines));
    mForm.querySelector("[data-sp-masto-file]").click();
    await settle(20);
    const mPost = log.fetches.find(f => f.method === "POST" && /mastodon\/propose-post/.test(f.url));
    check("P16. a Mastodon box with no image files with exactly { task_id }; each box keeps its own images",
      mPost && J(mPost.body) === J({ task_id: tid(3) }), mPost && J(mPost.body));
  } else check("P2. jsdom is installed", false);
  {
    // proposals.html: the Images row, and nothing new without images (the same output as before this change).
    const PR = fe("proposals.html") || "";
    const fnSrc = (src, name) => { const i = src.indexOf("function " + name + "("); return i < 0 ? "" : src.slice(i, s.braceMatch(src, src.indexOf("{", i)) + 1); };
    let before = "";
    try { before = lf(execFileSync("git", ["show", PRE_IMAGES_FRONTEND + ":proposals.html"], { cwd: FRONTEND, encoding: "utf8", maxBuffer: 64 << 20 })); } catch (e) { before = ""; }
    const lift = (src, names) => { const c = {}; vm.createContext(c); vm.runInContext(names.map(n => fnSrc(src, n)).join("\n"), c); return c; };
    const NOW = lift(PR, ["escapeHtml", "graphemeCountText", "postsAsText", "postImagesFields", "socialPostPayloadFields", "mastodonPostPayloadFields"]);
    const OLD = before ? lift(before, ["escapeHtml", "graphemeCountText", "postsAsText", "socialPostPayloadFields", "mastodonPostPayloadFields"]) : null;
    const plainB = [{ text: "<b>hi</b>", posts_as: { account: "member", handle: "alice.bsky.social", automatic: false } }, { text: "x" }, { text: "y", posts_as: { account: "member", handle: "a", automatic: true } }];
    const plainM = [{ text: "<b>hi</b>", posts_as: { account: "member", acct: "alice", host: "mastodon.social" }, measured: { length: 9, limit: 500, reserved_per_url: 23 } }, { text: "z" }];
    check("P17. with no images, both cards draw exactly what they drew at frontend " + PRE_IMAGES_FRONTEND,
      !!OLD && plainB.every(p => NOW.socialPostPayloadFields(clone(p)) === OLD.socialPostPayloadFields(clone(p))) &&
      plainM.every(p => NOW.mastodonPostPayloadFields(clone(p)) === OLD.mastodonPostPayloadFields(clone(p))) &&
      NOW.socialPostPayloadFields({ text: "x", media: [] }) === OLD.socialPostPayloadFields({ text: "x" }));
    const HOSTILE = "<img src=x onerror=alert(1)>";
    const media = [{ id: mid(1), sha256: "a".repeat(64), mime: "image/jpeg", bytes: 10, alt: HOSTILE }, { id: mid(2), sha256: "b".repeat(64), mime: "image/png", bytes: 10, alt: "Three bowls" }];
    const card = NOW.socialPostPayloadFields({ text: "x", posts_as: { account: "member", handle: "alice.bsky.social" }, media: media });
    const mcard = NOW.mastodonPostPayloadFields({ text: "x", posts_as: { account: "member", acct: "alice", host: "mastodon.social" }, media: media });
    check("P18. with images, both cards add an \"Images\" row after the text: one thumbnail per image, its alt text escaped, no address yet",
      [card, mcard].every(h => h.indexOf('<span class="pf-label">Images</span>') > h.indexOf("</pre>") && (h.match(/<img /g) || []).length === 2 &&
        h.indexOf(HOSTILE) === -1 && h.indexOf("&lt;img src=x onerror=alert(1)&gt;") !== -1 && h.indexOf('data-pf-media-id="' + mid(2) + '"') !== -1 && !/<img [^>]*src=/.test(h.replace(/alt="[^"]*"/g, "alt=\"\""))), card);
    if (JSDOM) {
      const dom = new JSDOM("<!DOCTYPE html><html><body><div id=\"list\"></div></body></html>", { url: "https://bizforceai.net/proposals.html", runScripts: "outside-only" });
      const w = dom.window;
      const asked = [];
      w.fetch = function (u) {
        asked.push(String(u));
        const page2 = String(u).indexOf("before=") !== -1;
        const body = page2 ? { items: [{ id: mid(2), url: "javascript:alert(1)" }], next_before: null }
          : { items: [{ id: mid(1), url: BASE + "/storage/v1/object/public/bf-public/k.jpg" }, { id: mid(9), url: BASE + "/other.jpg" }], next_before: "2026-11-01T00:00:00.000Z" };
        const p = Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) }); p.catch(() => {}); return p;
      };
      w.eval("var API_URL = \"https://api.example\"; var token = \"tok\";\n" + ["escapeHtml", "postImagesFields"].map(n => fnSrc(PR, n)).join("\n") + "\nvar libraryUrls = null;\nvar LIBRARY_PAGES = 5;\n" +
        ["readLibraryUrls", "showPostImages"].map(n => fnSrc(PR, n)).join("\n"));
      w.document.getElementById("list").innerHTML = w.postImagesFields({ media: media });
      w.showPostImages(w.document.getElementById("list"));
      await settle(40);
      const imgs = Array.from(w.document.querySelectorAll("#list img"));
      check("P19. thumbnails come from the member's own library (GET /api/media?kind=image, paged), matched by id; only an https address is used",
        imgs.length === 2 && imgs[0].getAttribute("src") === BASE + "/storage/v1/object/public/bf-public/k.jpg" && !imgs[1].hasAttribute("src") &&
        asked.length === 2 && asked[0] === "https://api.example/api/media?kind=image" && /before=/.test(asked[1]) && w.document.querySelectorAll("img[onerror]").length === 0, J(asked));
    }
    // NAMED (Nov 5 2026, mailbox replies, migration 170): BEFORE showPostImages(container) closed renderProposals. AFTER it is
    // still called once after every render, followed only by fillMailboxReplies(container), which fills the email reply cards (checkMailboxReply J12).
    check("P20. both cards are wired to call the Images row", (PR.match(/postImagesFields\(payload\) \+/g) || []).length === 2 &&
      PR.indexOf("  showPostImages(container);\n  fillMailboxReplies(container);\n}") !== -1 && PR.split("showPostImages(container);").length === 2);
  }

  /* ════ L. legal and the migration ════ */
  console.log("\n══ L. the Privacy Policy and migration 168 ══");
  const SENTENCE = "When you attach images from your Media Library to a Bluesky or Mastodon post, copies of the images and their alt text are sent to that service with the post, and they stay there under its rules even if you later delete them here.";
  check("L1. lib/legalPages.js: SOCIAL_MEDIA_PRIVACY_SENTENCE is the brief's sentence, word for word", LP.SOCIAL_MEDIA_PRIVACY_SENTENCE === SENTENCE);
  const built = LP.buildLegalPages(), esc = LEGAL.escapeHtml;
  const nextTo = h => { const a = h.indexOf(esc(LP.MASTODON_PRIVACY_SENTENCE)), b = h.indexOf(esc(SENTENCE)); return a !== -1 && b > a && b - a - esc(LP.MASTODON_PRIVACY_SENTENCE).length < 20; };
  check("L2. the Privacy Policy carries it directly after the Mastodon sentence, as built and on disk", nextTo(built["privacy.html"]) && nextTo(fe("privacy.html") || ""));
  // NAMED (Nov 6 2026, card upgrades C1): BEFORE "2026-11-05", the date of this change. AFTER "2026-11-06", the version the
  // card visits privacy sentence set; this change's own sentence is still checked in L1-L2.
  // NAMED (Nov 7 2026, Shopify on OAuth, migration 176): BEFORE "2026-11-06" (card visits). AFTER "2026-11-07", the version the Shopify privacy sentence set.
  check("L3. TERMS_VERSION is the latest change's, Nov 7 2026 (Shopify on OAuth; this change set Nov 5)", LEGAL.TERMS_VERSION === "2026-11-07" && LEGAL.TERMS_UPDATED === "Last updated November 7, 2026", LEGAL.TERMS_VERSION);
  const SQL_AS_RUN = "ALTER TABLE public.social_post_drafts\n  ADD COLUMN IF NOT EXISTS media_ids uuid[] NOT NULL DEFAULT '{}'::uuid[];\n\n" +
    "ALTER TABLE public.social_post_drafts\n  ADD CONSTRAINT social_post_drafts_media_ids_check CHECK (cardinality(media_ids) <= 4);\n\n" +
    "CREATE INDEX IF NOT EXISTS social_post_drafts_media_ids_idx\n  ON public.social_post_drafts USING gin (media_ids);\n\n" +
    "ALTER TABLE public.member_mastodon_connections\n  ADD COLUMN IF NOT EXISTS image_size_limit integer NOT NULL DEFAULT 16777216,\n  ADD COLUMN IF NOT EXISTS media_description_limit integer NOT NULL DEFAULT 1500;\n\n" +
    "ALTER TABLE public.member_mastodon_connections\n  ADD CONSTRAINT member_mastodon_connections_image_size_check CHECK (image_size_limit BETWEEN 1 AND 104857600),\n" +
    "  ADD CONSTRAINT member_mastodon_connections_media_desc_check CHECK (media_description_limit BETWEEN 1 AND 100000);\n";
  const mig = ALL[MIG] || "";
  check("M1. 168_social_post_images.sql says the owner applied it by hand on Nov 5, 2026, and ends with the SQL as run",
    mig.indexOf("Applied by the owner by hand in the Supabase SQL editor on Nov 5, 2026. This file is the text as run.") !== -1 && mig.endsWith(SQL_AS_RUN));
  const migFiles = fs.readdirSync(path.join(REPO, "supabase/migrations")).filter(f => /^\d+_/.test(f));
  // NAMED (Nov 5 2026, mailbox connection, migration 169): BEFORE "the highest" with every migration at most 168. AFTER 168 is
  // still the only one numbered 168, and every migration but 169_member_email_connections.sql is at most 168; "the highest" is checkMailboxConnect M2's.
  // NAMED (Nov 5 2026, mailbox replies, migration 170): BEFORE every migration but 169 at most 168. AFTER
  // 170_member_email_replies.sql too; "the highest" is checkMailboxReply M2's.
  // NAMED (Nov 6 2026, card upgrades C1, migration 171): BEFORE every migration but 169 and 170 at most 168. AFTER
  // 171_card_counts.sql too; "the highest" is checkCardUpgrades R1's.
  // NAMED (Nov 6 2026, card upgrades C2, migration 172): BEFORE 171_card_counts.sql was the last allowed above 168. AFTER
  // 172_card_leads.sql too; "the highest" is checkCardLeads R1's.
  // NAMED (Nov 6 2026, Outlook sign-in, migration 173): BEFORE 172_card_leads.sql was the last allowed above 168. AFTER
  // 173_mailbox_microsoft.sql too; "the highest" is checkMailboxOutlook R1's.
  // NAMED (Nov 6 2026, Google Wallet, migration 174): BEFORE 173_mailbox_microsoft.sql was the last allowed above 168. AFTER
  // 174_card_wallet_count.sql too; "the highest" is checkGoogleWallet R1's.
  // NAMED (Nov 6 2026, store changes, migration 175): 175_store_changes.sql is allowed too; "the highest" is checkStoreChanges R1's.
  check("M2. 168_social_post_images.sql is the only migration numbered 168, and every other migration but 169_member_email_connections.sql, 170_member_email_replies.sql, 171_card_counts.sql, 172_card_leads.sql, 173_mailbox_microsoft.sql and 174_card_wallet_count.sql is at most 168",
    migFiles.filter(f => /^168_/.test(f)).length === 1 && migFiles.indexOf("168_social_post_images.sql") !== -1 && migFiles.every(f => f === "169_member_email_connections.sql" || f === "170_member_email_replies.sql" || f === "171_card_counts.sql" || f === "172_card_leads.sql" || f === "173_mailbox_microsoft.sql" || f === "174_card_wallet_count.sql" || f === "175_store_changes.sql" || /* NAMED (Nov 7 2026, Shopify on OAuth, migration 176): 176 is allowed too; "the highest" is checkShopifyConnect R1's. */ f === "176_shopify_oauth.sql" || /* NAMED (Nov 7 2026, YouTube uploads, migration 177): 177 is allowed too; "the highest" is checkYoutubeUploads R1's. */ f === "177_youtube_uploads.sql" || /* NAMED (Nov 7 2026, TikTok posting, migration 178): 178 is allowed too; "the highest" is checkTiktokPosting R1's. */ f === "178_tiktok_posting.sql" || Number(f.split("_")[0]) <= 168) && migFiles.some(f => /^167_/.test(f)));
  check("M3. the code's limits are 168's: Mastodon 16777216 and 1500 by default, ranges 1-104857600 and 1-100000; at most 4 a post",
    MM.IMAGE_SIZE_LIMIT_DEFAULT === 16777216 && MM.MEDIA_DESCRIPTION_LIMIT_DEFAULT === 1500 && J(MM.IMAGE_SIZE_LIMIT_RANGE) === J([1, 104857600]) &&
    J(MM.MEDIA_DESCRIPTION_LIMIT_RANGE) === J([1, 100000]) && MED.POST_MEDIA_MAX === 4 && MM.MEDIA_PER_POST === 4 && /cardinality\(media_ids\) <= 4/.test(mig));

  console.log("\n══ Z. no network ══");
  check("Z. zero sockets, DNS lookups and fetches", NETWORK.length === 0, J(NETWORK));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures) + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : "")); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED" + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(0);
})().catch(function (err) {
  console.log("    FAIL  the check threw: " + ((err && err.stack) || err));
  process.exit(1);
});
