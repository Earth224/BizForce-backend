"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   checkPostMedia.js — a post's photos (P2-3, Nov 20 2026; migration 193;
   lib/postMedia.js, POST /api/posts/photos, scripts/bf-composer.js).

   A post photo is a Media Library file: the browser makes it smaller (a 1080
   px long edge, WebP at 0.8 or JPEG at 0.82, and a 360 px thumbnail), and the
   server takes each through the library's own rules plus a 600 KB limit and
   the shared storage guard.

   WHAT THIS PROVES (an in-memory database, scripts/_p23Db.js, and a fake
   Storage; never the real ones)
     A. STORING ONE: a JPEG, PNG or WebP of at most 600 KB is stored in the
        library (label "Post photo", its metadata stripped, 201); over 600 KB
        is 413 too_big; a GIF or anything else 415; the same bytes again are
        the same library file (200 duplicate), never a second upload; the
        member's 250 MB library cap is 413 full; the storage guard's refusal is
        passed on and nothing is uploaded; the guard is asked for the size.
     B. NAMING THEM IN A POST: each photo is the author's own image of at
        most 600 KB; another member's file 404 not_yours; a video 415; the
        same photo twice 400; an id that is not one 400; up to four, in order
        (idx 0..3), each with its thumbnail.
     C. A PHOTO IN A POST STAYS: usedInPosts finds it as the photo or the
        thumbnail, and DELETE /api/media/:id answers 409 in_post before
        anything is removed.
     D. THE BROWSER: bf-composer.js uses the server's numbers (1080, 360, 0.8,
        0.82, 600 KB, four photos, 2200 characters) and posts the file as
        "file" to /api/posts/photos; the route takes one file of at most
        600 KB, needs an active plan, and is limited to 80 an hour.
     E. MIGRATION 193: post_media keys a post's photos by (post_id, idx), idx
        0 to 3, and a library file in a post cannot be deleted under it
        (ON DELETE RESTRICT); posts' kinds, audiences, statuses and the 2200
        character rule; row level security on, every grant revoked.

   MUTATE=<name> applies one mutation in memory; MUTATE=all runs each.
   ═══════════════════════════════════════════════════════════════════════════ */
const zlib = require("zlib");
const H = require("./_p21Harness");
const { memDb } = require("./_p23Db");

const SERVER = "@server.js", PM = "@lib/postMedia.js", POSTS = "@lib/posts.js", MIG = "@supabase/migrations/193_posts.sql", COMPOSER = "scripts/bf-composer.js";
const MUTATIONS = {
  "no-size-limit": [[PM, "  if (checked.size > PHOTO_MAX_BYTES) return { status: 413, body: { error: MESSAGES.tooBig, reason: \"too_big\" } };\n", ""],
    [PM, "  if (file && file.buffer && file.buffer.length > PHOTO_MAX_BYTES) return { status: 413, body: { error: MESSAGES.tooBig, reason: \"too_big\" } };\n", ""]],
  "gif-allowed": [[PM, 'const PHOTO_EXTS = ["jpg", "png", "webp"];', 'const PHOTO_EXTS = ["jpg", "png", "webp", "gif"];']],
  "no-dedupe": [[PM, "  if (existing.data) return { status: 200, body: { item: MM.publicItem(existing.data, deps.base), duplicate: true } };\n", ""]],
  "guard-ignored": [[PM, "  var full = await deps.guard(checked.size);\n  if (full) return full;\n", ""]],
  "library-cap-ignored": [[PM, "  if (held.used_bytes + checked.size > MM.MEMBER_MEDIA_BYTES) return", "  if (false) return"]],
  "others-photo": [[PM, '  var r = await sb.from("member_media").select("id, user_id, kind, mime, bytes").eq("user_id", userId).in("id", [...new Set(ids)]);',
    '  var r = await sb.from("member_media").select("id, user_id, kind, mime, bytes").in("id", [...new Set(ids)]);'],
    [PM, "  (r.data || []).forEach(function (row) { if (row.user_id === userId) mine[row.id] = row; });", "  (r.data || []).forEach(function (row) { mine[row.id] = row; });"]],
  "video-as-photo": [[PM, '    if (f.kind !== "image" || ["image/jpeg", "image/png", "image/webp"].indexOf(f.mime) === -1) return refused(415, "type", MESSAGES.type);\n', ""]],
  "twice-allowed": [[PM, "    if (photos.some(function (p) { return p.media_id === m.media_id; })) return refused(400, \"twice\", MESSAGES.twice);\n", ""]],
  "thumb-not-in-use": [[PM, '  for (const col of ["media_id", "thumb_media_id"]) {', '  for (const col of ["media_id"]) {']],
  "delete-in-use": [[SERVER, "    if (await require(\"./lib/postMedia\").usedInPosts(supabase, item.id)) {", "    if (false) {"]],
  "composer-bigger": [[COMPOSER, "LONG_EDGE = 1080, THUMB_EDGE = 360,", "LONG_EDGE = 2048, THUMB_EDGE = 360,"]],
  "photos-without-plan": [[SERVER, 'app.post("/api/posts/photos", requireAuth, requireActiveSubscription, postPhotoLimiter,', 'app.post("/api/posts/photos", requireAuth, postPhotoLimiter,']],
  "migration-cascade": [[MIG, "  media_id uuid NOT NULL REFERENCES public.member_media(id) ON DELETE RESTRICT,", "  media_id uuid NOT NULL REFERENCES public.member_media(id) ON DELETE CASCADE,"]]
};
const T = H.setup(__filename, MUTATIONS, [SERVER, PM, POSTS, MIG, COMPOSER]);
const { FILES, check, J, has } = T;
const PMX = T.libRequire("./lib/postMedia");
const MM = require("../lib/memberMedia");

const ME = "11111111-1111-4111-8111-111111111111", THEM = "22222222-2222-4222-8222-222222222222";
const mid = n => "eeeeeeee-0000-4000-8000-" + String(n).padStart(12, "0");

/* image bytes */
const u32be = n => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b; };
const B = (...parts) => Buffer.concat(parts.map(p => Buffer.isBuffer(p) ? p : typeof p === "string" ? Buffer.from(p, "latin1") : Buffer.from(p)));
const chunk = (type, data) => { const body = B(type, data); return B(u32be(data.length), body, u32be(zlib.crc32(body))); };
function png(extra) {
  return B([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], chunk("IHDR", B(u32be(1), u32be(1), [8, 2, 0, 0, 0])), chunk("tEXt", B("Comment\0", "taken at 37.775N")),
    chunk("IDAT", B([0x78, 0x9c, 0x63, 0x60, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01], extra || Buffer.alloc(2, 0xaa))), chunk("IEND", Buffer.alloc(0)));
}
const GIF = B("GIF89a", [1, 0, 1, 0, 0x80, 0, 0], [0, 0, 0, 255, 255, 255], ",", [0, 0, 0, 0, 1, 0, 1, 0, 0], [2, 2, 0x44, 1, 0], ";");
const file = (buf, name, mime) => ({ fieldname: "file", originalname: name || "photo.png", mimetype: mime || "image/png", buffer: buf, size: buf.length });

function storage() {
  const st = { uploads: [], removes: [] };
  st.from = bucket => ({
    upload: async (p, bytes, o) => { st.uploads.push({ bucket, path: p, size: bytes.length, contentType: o && o.contentType }); return { data: { path: p }, error: null }; },
    remove: async paths => { st.removes.push({ bucket, paths }); return { data: paths, error: null }; }
  });
  return st;
}
function world(seed) {
  const db = memDb(Object.assign({ member_media: [], post_media: [], posts: [] }, seed || {}));
  const st = storage();
  const asked = [];
  let refuse = null;
  const deps = { sb: db.client, storage: st, base: "https://x.supabase.co", guard: async n => { asked.push(n); return refuse; } };
  return { db, st, deps, asked, refuseWith: v => { refuse = v; } };
}

(async function main() {
  /* ── A ── */
  console.log("\n══ A. storing one ══");
  let w = world();
  let r = await PMX.storePhoto(w.deps, ME, file(png()));
  const row = w.db.t.member_media[0];
  check("A1. a PNG of a few bytes: 201, stored in the library as \"Post photo\", its text chunk stripped", r.status === 201 && row && row.label === "Post photo" && row.user_id === ME &&
    row.metadata_stripped === true && w.st.uploads.length === 1 && w.st.uploads[0].bucket === MM.BUCKET && r.body.item.url.indexOf("https://x.supabase.co/") === 0, J(r));
  check("A2. the storage guard is asked for exactly the size stored", J(w.asked) === J([row && row.bytes]));
  r = await PMX.storePhoto(w.deps, ME, file(png()));
  check("A3. the same bytes again are the same file: 200 duplicate, no second upload or row", r.status === 200 && r.body.duplicate === true && w.st.uploads.length === 1 && w.db.t.member_media.length === 1);
  const big = png(Buffer.alloc(PMX.PHOTO_MAX_BYTES + 10, 0x55));
  r = await PMX.storePhoto(w.deps, ME, file(big));
  check("A4. over 600 KB: 413 too_big, nothing stored", r.status === 413 && r.body.reason === "too_big" && w.st.uploads.length === 1);
  r = await PMX.storePhoto(w.deps, ME, file(GIF, "a.gif", "image/gif"));
  check("A5. a GIF: 415 type (JPEG, PNG or WebP only)", r.status === 415 && r.body.error === PMX.MESSAGES.type && w.st.uploads.length === 1, J(r));
  r = await PMX.storePhoto(w.deps, ME, file(Buffer.from("not an image at all"), "a.png"));
  check("A6. bytes that are not a picture are refused by the library's own check", r.status >= 400 && r.status < 500 && w.st.uploads.length === 1);
  w = world({ member_media: [{ id: mid(1), user_id: ME, bytes: MM.MEMBER_MEDIA_BYTES - 10, path: "x", created_at: "2026-11-01T00:00:00.000Z", sha256: "f" }] });
  r = await PMX.storePhoto(w.deps, ME, file(png()));
  check("A7. the member's 250 MB library cap: 413 full, nothing uploaded", r.status === 413 && r.body.reason === "full" && w.st.uploads.length === 0);
  w = world();
  w.refuseWith({ status: 507, body: { error: "full", reason: "storage_full" } });
  r = await PMX.storePhoto(w.deps, ME, file(png()));
  check("A8. the shared storage guard's refusal is the answer, and nothing is uploaded or written", r.status === 507 && r.body.reason === "storage_full" && w.st.uploads.length === 0 && w.db.t.member_media.length === 0);

  /* ── B ── */
  console.log("\n══ B. naming them in a post ══");
  const lib = [
    { id: mid(1), user_id: ME, kind: "image", mime: "image/webp", bytes: 300000 }, { id: mid(2), user_id: ME, kind: "image", mime: "image/webp", bytes: 30000 },
    { id: mid(3), user_id: THEM, kind: "image", mime: "image/png", bytes: 1000 }, { id: mid(4), user_id: ME, kind: "video", mime: "video/mp4", bytes: 1000 },
    { id: mid(5), user_id: ME, kind: "image", mime: "image/jpeg", bytes: PMX.PHOTO_MAX_BYTES + 1 }, { id: mid(6), user_id: ME, kind: "image", mime: "image/jpeg", bytes: 1000 }
  ];
  w = world({ member_media: lib });
  const c = m => PMX.checkForPost(w.db.client, ME, m);
  r = await c([{ media_id: mid(1), thumb_media_id: mid(2) }, { media_id: mid(6) }]);
  check("B1. the author's own images: the photos, in order, each with its thumbnail", J(r.photos) === J([{ media_id: mid(1), thumb_media_id: mid(2) }, { media_id: mid(6), thumb_media_id: null }]), J(r));
  check("B2. another member's file: 404 not_yours", (await c([{ media_id: mid(3) }])).reason === "not_yours" && (await c([{ media_id: mid(1), thumb_media_id: mid(3) }])).reason === "not_yours");
  check("B3. a video: 415", (await c([{ media_id: mid(4) }])).status === 415);
  check("B4. over 600 KB: 413", (await c([{ media_id: mid(5) }])).status === 413);
  check("B5. the same photo twice: 400 twice; an id that is not one: 400 bad_id", (await c([{ media_id: mid(1) }, { media_id: mid(1) }])).reason === "twice" && (await c([{ media_id: "x" }])).reason === "bad_id");
  const P = T.libRequire("./lib/posts");
  const pw = memDb({ member_media: lib, post_media: [], posts: [], users: [{ id: ME, created_at: "2026-01-01T00:00:00.000Z" }], bf_profiles: [], profiles: [], moderation_queue: [],
    follows: [], member_blocks: [], member_mutes: [], post_likes: [], post_saves: [] });
  const made = await P.createPost({ sb: pw.client, now: () => "2026-11-20T12:00:00.000Z", claims: () => null, ownerPublic: async () => true, env: { SUPABASE_URL: "https://x.supabase.co" } },
    ME, { kind: "photo", body: "", media: [{ media_id: mid(1), thumb_media_id: mid(2) }, { media_id: mid(6) }] });
  check("B6. a photo post links them as idx 0 and 1, and answers each photo's url and thumbnail url", made.status === 201 && J(pw.t.post_media.map(x => x.idx + ":" + x.media_id)) === J(["0:" + mid(1), "1:" + mid(6)]) &&
    made.body.post.photos.length === 2, J(made.body));
  const refusedPost = await P.createPost({ sb: pw.client, now: () => "2026-11-20T12:00:00.000Z", claims: () => null, ownerPublic: async () => true, env: {} }, ME, { kind: "photo", media: [{ media_id: mid(3) }] });
  check("B7. a post naming another member's photo is refused and not saved", refusedPost.status === 404 && pw.t.posts.length === 1);

  /* ── C ── */
  console.log("\n══ C. a photo in a post stays ══");
  w = world({ post_media: [{ post_id: mid(90), media_id: mid(1), thumb_media_id: mid(2), idx: 0 }] });
  check("C1. usedInPosts finds a file as the photo and as the thumbnail, and not a file in no post",
    await PMX.usedInPosts(w.db.client, mid(1)) === true && await PMX.usedInPosts(w.db.client, mid(2)) === true && await PMX.usedInPosts(w.db.client, mid(6)) === false);
  const del = H.routeStatement(FILES[SERVER], "delete", "/api/media/:id") || "";
  const inUse = del.indexOf('if (await require("./lib/postMedia").usedInPosts(supabase, item.id)) {');
  const firstRemove = Math.min(...[".remove(", ".delete()"].map(x => del.indexOf(x)).filter(i => i !== -1));
  check("C2. DELETE /api/media/:id answers 409 in_post before anything is removed", inUse !== -1 && inUse < firstRemove && has(del, 'reason: "in_post"'), inUse + " / " + firstRemove);

  /* ── D ── */
  console.log("\n══ D. the browser and the route ══");
  const comp = FILES[COMPOSER] || "";
  const P2 = T.libRequire("./lib/posts");
  check("D1. bf-composer.js uses the server's numbers", has(comp, "var BODY_MAX = " + P2.BODY_MAX + ", PHOTOS_MAX = " + P2.PHOTOS_MAX + ", LONG_EDGE = " + PMX.LONG_EDGE + ", THUMB_EDGE = " + PMX.THUMB_EDGE +
    ", WEBP_Q = " + PMX.WEBP_QUALITY + ", JPEG_Q = " + PMX.JPEG_QUALITY + ", PHOTO_MAX_BYTES = 600 * 1024;") && PMX.PHOTO_MAX_BYTES === 600 * 1024 && PMX.LONG_EDGE === 1080 && PMX.THUMB_EDGE === 360);
  check("D2. it sends each as \"file\" to POST /api/posts/photos, and only offers JPEG, PNG and WebP", has(comp, 'fd.append("file", blob,') && has(comp, 'api() + "/api/posts/photos", { method: "POST"') &&
    has(comp, 'accept="image/jpeg,image/png,image/webp"'));
  const S = FILES[SERVER];
  check("D3. the route: signed in, an active plan, 80 an hour, one file of at most 600 KB, through storePhoto with the shared guard",
    has(S, 'app.post("/api/posts/photos", requireAuth, requireActiveSubscription, postPhotoLimiter, function (req, res, next) {') &&
    has(S, "const postPhotoUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: require(\"./lib/postMedia\").PHOTO_MAX_BYTES, files: 1 } });") &&
    /const postPhotoLimiter = rateLimit\(\{\n  windowMs: 60 \* 60 \* 1000,\n  max: 80,/.test(S) && has(S, "guard: function (bytes) { return storageGuard(bytes); } }, req.user.id, req.file);"));

  /* ── E ── */
  console.log("\n══ E. migration 193 ══");
  const M = FILES[MIG] || "";
  check("E1. post_media: (post_id, idx), idx 0 to 3, a library file in a post cannot be deleted under it", has(M, "  PRIMARY KEY (post_id, idx)") && has(M, "  CHECK (idx BETWEEN 0 AND 3);") &&
    has(M, "  media_id uuid NOT NULL REFERENCES public.member_media(id) ON DELETE RESTRICT,") && has(M, "  thumb_media_id uuid REFERENCES public.member_media(id) ON DELETE RESTRICT,"));
  check("E2. posts: the kinds, public or followers, the statuses, fewer than 2201 characters", has(M, "  CHECK (kind IN ('text','photo','video','product','service','listing','campaign','garage','card'));") &&
    has(M, "  CHECK (audience IN ('public','followers'));") && has(M, "  CHECK (status IN ('draft','pending','published','hidden','removed'));") && has(M, "  CHECK (char_length(body) < 2201);"));
  check("E3. row level security on and every grant revoked, in one transaction, paste-safe", ["posts", "post_media"].every(t => has(M, "ALTER TABLE public." + t + " ENABLE ROW LEVEL SECURITY;") &&
    has(M, "REVOKE ALL ON public." + t + " FROM anon, authenticated;")) && /^BEGIN;/m.test(M) && /^COMMIT;/m.test(M) && M.indexOf("<=") === -1 && M.indexOf(">=") === -1);

  T.finish();
})().catch(e => { check("the check ran to the end", false, e && (e.stack || e.message || JSON.stringify(e))); T.finish(); });
