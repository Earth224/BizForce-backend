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
   NAMED (Nov 7 2026, Instagram posting, migration 179): a Reel is a third
   platform. Instagram has it when an instagram_posts row for it is
   published; a row still creating or processing holds the file (Delete
   refuses, retention keeps it), and so does a pending publish_instagram_post
   proposal, which names the video as payload.video.id. The early delete now
   needs YouTube, TikTok AND Instagram; READY_DAYS still ends every file.
   NAMED (Nov 7 2026, Facebook Pages posting, migration 180): a Facebook video
   post is a fourth platform. Facebook has it when a facebook_posts row for it
   is published; a row still creating or publishing holds the file, and so
   does a pending publish_facebook_post proposal (payload.video.id). The early
   delete now needs YouTube, TikTok, Instagram AND Facebook.

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
const { Readable, Transform, pipeline } = require("stream");

const BUCKET = "bf-video";
/* NAMED (Nov 18 2026, BV1, migration 187): BEFORE MAX_BYTES was 50 * 1024 * 1024 and every video was ONE object.
   AFTER a video is at most MAX_BYTES (500 MiB, member_videos_bytes_check). Supabase's Free plan caps each object:
   "For Free projects, the limit can't exceed 50 MB." (supabase.com/docs/guides/storage/uploads/file-limits), and the
   bf-video bucket's file_size_limit stays 52428800. So:
     - a video of at most ONE_FILE_MAX_BYTES is still ONE object at path, uploaded and checked exactly as before
       (part_count 1). Instagram and Facebook fetch one URL, so they take only these;
     - a larger one is PARTS: part_count objects of PART_BYTES each (the last 1..PART_BYTES), in order, part 0 at
       path and part i at partPath(path, i) (".p01" before the extension), each recorded in member_video_parts as it
       arrives (partUrl, partDone) and checked by finalize, which reads every part ONCE, in order: each part's size and
       sha256 against its row, and the whole file's sha256, type and length (mvhd) across the parts.
   PART_BYTES is 45 MiB = 180 x 256 KiB, so a part is also a YouTube chunk ("The chunk size must be a multiple of
   256 KB.") and between TikTok's 5 MB and 64 MB. Before an upload is accepted, the bytes already stored are checked
   against the storage budget (VIDEO_STORAGE_BUDGET_BYTES, default BUDGET_BYTES_DEFAULT, 900 MiB of the Free plan's
   1 GB). */
const MAX_BYTES = 500 * 1024 * 1024;
const ONE_FILE_MAX_BYTES = 50 * 1024 * 1024;
const PART_BYTES = 45 * 1024 * 1024;
const PARTS_MAX = 12;
const BUDGET_BYTES_DEFAULT = 900 * 1024 * 1024;
// An upload's parts with no video after this long are deleted, objects and rows (retentionTick step 4).
const ABANDONED_MS = 24 * 60 * 60 * 1000;
const READY_MAX = 2;
const UPLOADS_PER_DAY = 5;
// NAMED (Nov 7 2026, TikTok posting): TikTok's own cap, counted by tiktok_posted_at.
const TIKTOK_POSTS_PER_DAY = 5;
// The proposals that need the file: while one is pending or running, retention keeps it and Delete refuses.
// NAMED (Nov 7 2026, Instagram posting, migration 179): publish_instagram_post, whose payload names the video as video.id.
// NAMED (Nov 7 2026, Facebook Pages posting, migration 180): publish_facebook_post, payload.video.id too.
const FILE_ACTIONS = Object.freeze(["publish_youtube_video", "delete_youtube_video", "publish_tiktok_post", "publish_instagram_post", "publish_facebook_post"]);
// An instagram_posts row in one of these still needs the file (Instagram may still be fetching it).
const INSTAGRAM_HOLDING = Object.freeze(["creating", "processing"]);
// A facebook_posts row in one of these still needs the file (the final call may be under way).
const FACEBOOK_HOLDING = Object.freeze(["creating", "publishing"]);
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
  // NAMED (Nov 18 2026, BV1): BEFORE "Videos up to 50 MB (MP4, WebM or MOV).", and tooBig, badSize and the 413 said 50 MB.
  limits: "Videos up to 500 MB for YouTube and TikTok (MP4, WebM or MOV). Instagram and Facebook take videos up to 50 MB.",
  kept: "BizForce deletes the file once every platform you sent it to has it, or 14 days after you added it.",
  privateUntilVerified: "Until Google approves BizForce, YouTube keeps uploads from BizForce private.",
  unsupported: "That file type isn't supported. Use MP4, WebM or MOV.",
  mismatch: "That file isn't the type it says it is, so it was deleted.",
  tooBig: "A video is at most 500 MB, so it was deleted.",
  sizeMismatch: "That file isn't the size the browser said it was, so it was deleted.",
  badSize: "Say the video's size in bytes, from 1 to 524288000.",
  // NAMED (Nov 18 2026, BV1): the parts of a video over 50 MB, the storage budget and the preview of the first part.
  storageFull: "Storage is full right now. Post or delete a waiting video first.",
  storageUnknown: "BizForce couldn't check its video storage just now, so nothing was accepted. Try again.",
  badPart: "That isn't a part of this upload.",
  partMissing: "That part hasn't reached storage yet. Upload it again.",
  partSize: "That part isn't the size it should be, so it was deleted. Upload it again.",
  partsMissing: "Not every part of the video has arrived yet. Upload the missing parts, then try again.",
  partMismatch: "A part of the video isn't the one the browser sent, so the video was deleted.",
  previewStart: "Preview shows the start of the video.",
  metaTooBig: "takes videos up to 50 MB from BizForce, and this one is larger.",
  badLabel: "A label is text of at most 120 characters.",
  badPath: "That isn't a video upload BizForce made for you.",
  notUploaded: "The file hasn't reached storage yet. Upload it, then try again.",
  already: "That video is already in your list.",
  readyCap: "You have 2 videos waiting. Upload or delete one first.",
  notFound: "That video isn't in your list.",
  notReady: "Only a video waiting to be uploaded can be deleted here.",
  inProposal: "A proposal waiting for your approval names this video. Reject it first.",
  instagramPublishing: "An Instagram post is still publishing this video. Check its status on the Social page, then try again.",
  facebookPublishing: "A Facebook post is still publishing this video. Check its status on the Social page, then try again.",
  unreadable: "The video couldn't be read from storage just now. Try again.",
  stored: "The video couldn't be stored. Try again.",
  removeFailed: "The video file couldn't be deleted just now, so nothing changed. Try again.",
  title: "A title is 1 to 100 characters, without < or >.",
  description: "A description is at most 5000 bytes, without < or >.",
  tags: "Tags are a list of words, without < > or commas, 500 characters in all.",
  privacy: "Privacy is private, unlisted or public.",
  kids: "Answer \"Made for kids?\" with Yes or No.",
  // NAMED (Nov 17 2026, TK1): the preview (GET /api/videos/:id/preview).
  previewGone: "This video's file was deleted, so there is nothing to preview.",
  previewUnavailable: "The preview couldn't be opened just now. Try again."
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
/* NAMED (Nov 18 2026, BV1): the parts of a video. Part 0 is the video's own path; part i (1..PARTS_MAX-1) is the same
   name with ".p<two digits>" before the extension: the pattern of migration 187's member_video_parts_path_check. */
const PART_PATH_RE = /^video\/[0-9a-f-]{36}\/[0-9a-f]{32}(?:\.p[0-9]{2})?\.(mp4|webm|mov)$/;
function partPath(path, idx) {
  if (!PATH_RE.test(String(path || "")) || !Number.isInteger(idx) || idx < 0 || idx >= PARTS_MAX) return null;
  return idx === 0 ? path : path.replace(/\.(mp4|webm|mov)$/, ".p" + (idx < 10 ? "0" : "") + idx + ".$1");
}
/* Each part's size for a video of `bytes`: PART_BYTES, the last one what is left. [] when it is not a parted video. */
function partSizes(bytes) {
  if (!Number.isInteger(bytes) || bytes <= ONE_FILE_MAX_BYTES || bytes > MAX_BYTES) return [];
  var n = Math.ceil(bytes / PART_BYTES), out = [];
  for (var i = 0; i < n; i++) out.push(i < n - 1 ? PART_BYTES : bytes - (n - 1) * PART_BYTES);
  return out;
}
/* How many objects hold a row's file: part_count when it is 2..PARTS_MAX, else 1 (every row before migration 187). */
function partCount(row) {
  var n = row && row.part_count;
  return Number.isInteger(n) && n > 1 && n <= PARTS_MAX ? n : 1;
}
/* Every object path of a row's file, in order: [path] for one object. [] when the row has no path. */
function filePaths(row) {
  if (!row || !row.path) return [];
  var out = [];
  for (var i = 0; i < partCount(row); i++) { var p = partPath(row.path, i); if (p) out.push(p); }
  return out.length ? out : [row.path];
}
/* The parts of a row's file as { idx, path, start, bytes, sha256 }, read from member_video_parts (upload_path) and
   checked against the row: part_count rows, idx 0.., the sizes partSizes gives, the paths partPath gives. A row of
   one object is that object, its sha256 the file's. Throws "parts" when they do not add up. */
async function fileParts(supabase, row) {
  if (partCount(row) === 1) return [{ idx: 0, path: row.path, start: 0, bytes: Number(row.bytes), sha256: row.sha256 }];
  // By the video's path (its parts' upload_path), so a part not yet tied to the row by video_id still counts.
  var r = await supabase.from("member_video_parts").select("idx, path, bytes, sha256").eq("upload_path", row.path).eq("user_id", row.user_id);
  if (r.error) throw new Error("member_video_parts could not be read");
  return partsInOrder(r.data || [], row.path, Number(row.bytes), partCount(row));
}
function partsInOrder(rows, path, bytes, count) {
  var sizes = partSizes(bytes);
  var list = rows.slice().sort(function (a, b) { return a.idx - b.idx; });
  if (sizes.length !== count || list.length !== count) throw new Error("parts");
  var start = 0;
  return list.map(function (p, i) {
    if (p.idx !== i || Number(p.bytes) !== sizes[i] || p.path !== partPath(path, i) || !/^[0-9a-f]{64}$/.test(String(p.sha256))) throw new Error("parts");
    var out = { idx: i, path: p.path, start: start, bytes: sizes[i], sha256: p.sha256 };
    start += sizes[i];
    return out;
  });
}

/* Hashes a part's every byte and passes on only [from, to) of it, holding the last piece back until the whole part
   has matched its size and sha256: a part that is not the recorded one errors ("part_mismatch") before its last
   bytes go anywhere. The same idea as lib/youtubeApi.js fingerprintGuard, per part. */
function partGuard(sha256, total, from, to) {
  var hash = crypto.createHash("sha256");
  var seen = 0, held = null;
  return new Transform({
    transform: function (chunk, enc, cb) {
      hash.update(chunk);
      var start = seen;
      seen += chunk.length;
      if (seen > total) return cb(partError("part_mismatch"));
      var a = Math.max(from, start), b = Math.min(to, seen);
      if (b > a) {
        if (held) this.push(held);
        held = Buffer.from(chunk.subarray(a - start, b - start));
      }
      cb();
    },
    flush: function (cb) {
      if (seen !== total || hash.digest("hex") !== sha256) return cb(partError("part_mismatch"));
      if (held) this.push(held);
      cb();
    }
  });
}
function partError(code) { var e = new Error(code); e.code = code; return e; }

/* Bytes [from, to) of a file made of `parts` (fileParts), as ONE Node stream: each part that overlaps is read from
   Storage in turn, through partGuard, and nothing is ever held whole; parts outside the range are not read. Errors
   "storage_unreadable" when a part can't be opened, "part_mismatch" when one is not its recorded self. */
function openRange(storage, parts, from, to) {
  async function* bytes() {
    for (var i = 0; i < parts.length; i++) {
      var p = parts[i], end = p.start + p.bytes;
      if (end <= from || p.start >= to) continue;
      var src = await openStream(storage, p.path);
      if (!src) throw partError("storage_unreadable");
      var guard = partGuard(p.sha256, p.bytes, Math.max(0, from - p.start), Math.min(p.bytes, to - p.start));
      pipeline(src, guard, function () { /* an error reaches the reader through guard */ });
      for await (const chunk of guard) yield chunk;
    }
  }
  return Readable.from(bytes(), { objectMode: false });
}
/* NAMED (Nov 18 2026, BV2): ONE read of a parted file per send. A cursor over bytes [from, total) of `parts`, handed
   out chunk by chunk: take(a, b) is a stream of bytes [a, b). When `a` is where the cursor stands (the chunk before
   ended there), it carries on the SAME openRange stream, so a part a chunk boundary cuts through is still read once;
   any other `a` (a resume from YouTube's Range) opens a new range from `a`. Every byte still passes its part's
   partGuard, so a part that is not its recorded self errors ("part_mismatch") before its last bytes go anywhere, and
   the chunk carrying them never completes. The stream is carried on only when the chunk before was read to its very
   end; a chunk cut short (its PUT broke) leaves the stream to that chunk alone, and the next opens a new one. close()
   lets the open stream go. */
function rangeCursor(storage, parts, total) {
  var cur = null;
  function close() {
    var c = cur;
    cur = null;
    if (c && typeof c.it.return === "function") { try { c.it.return().catch(function () {}); } catch (err) { /* already running or ended */ } }
  }
  return {
    take: function (a, b) {
      if (!cur || !cur.whole || cur.pos !== a) {
        close();
        cur = { it: openRange(storage, parts, a, total)[Symbol.asyncIterator](), pos: a, left: null, whole: true };
      }
      var s = cur;
      s.whole = false;
      async function* bytes() {
        while (s.pos < b) {
          if (cur !== s) throw partError("storage_unreadable");
          var c = s.left;
          s.left = null;
          if (!c) {
            var n = await s.it.next();
            if (n.done) throw partError("storage_unreadable");
            c = n.value;
          }
          if (c.length > b - s.pos) { s.left = c.subarray(b - s.pos); c = c.subarray(0, b - s.pos); }
          s.pos += c.length;
          if (s.pos === b) s.whole = true;
          yield c;
        }
      }
      return Readable.from(bytes(), { objectMode: false });
    },
    close: close
  };
}

/* NAMED (Nov 18 2026, BV2): verifyParts (the whole parted file read once more before each send, to check it) is gone:
   partGuard checks every part while it is sent, so a send reads each part once. */

/* NAMED (Nov 18 2026, BV1): the storage budget. The bytes held now: every video row whose file is still stored
   (ready, or uploaded with a leftover path) plus every recorded part not yet a video. Throws when unreadable, and the
   caller refuses (fail closed). */
function budgetBytes(env) {
  var v = Number(env && env.VIDEO_STORAGE_BUDGET_BYTES);
  return Number.isInteger(v) && v > 0 ? v : BUDGET_BYTES_DEFAULT;
}
/* NAMED (Nov 20 2026, P2-3): every row is read, PAGE_SIZE at a time in id order, up to MAX_PAGES pages; a table with
   more than that throws, and the caller refuses (fail closed). BEFORE: one read of at most PAGE_SIZE (1000) rows each,
   so rows past the first 1000 were not counted. */
async function pagedBytes(read, what) {
  var sum = 0;
  for (var page = 0; page < MAX_PAGES; page++) {
    var got = await read(page * PAGE_SIZE, page * PAGE_SIZE + PAGE_SIZE - 1);
    if (got.error) throw new Error(what + " could not be read");
    var batch = got.data || [];
    batch.forEach(function (r) { sum += Number(r.bytes) || 0; });
    if (batch.length < PAGE_SIZE) return sum;
  }
  throw new Error(what + " has more rows than the budget reads");
}
async function storedBytes(supabase) {
  var total = 0;
  total += await pagedBytes(function (from, to) {
    return supabase.from("member_videos").select("id, bytes").in("status", ["ready", "uploaded"]).not("path", "is", null).order("id", { ascending: true }).range(from, to);
  }, "member_videos");
  total += await pagedBytes(function (from, to) {
    return supabase.from("member_video_parts").select("id, bytes").is("video_id", null).order("id", { ascending: true }).range(from, to);
  }, "member_video_parts");
  return total;
}
/* null when `adding` more bytes fit the budget, else the refusal { status, body }. */
async function budgetRefusal(deps, adding) {
  var held;
  try { held = await storedBytes(deps.supabase); } catch (err) {
    return { status: 503, body: { error: MESSAGES.storageUnknown, code: "storage_unknown" } };
  }
  if (held + adding > budgetBytes(deps.env)) return { status: 409, body: { error: MESSAGES.storageFull, code: "storage_full" } };
  return null;
}

function youtubeUrl(id) { return YOUTUBE_ID_RE.test(String(id || "")) ? "https://www.youtube.com/watch?v=" + id : null; }
/* TikTok's embed player address for a post id: it needs no username. */
function tiktokUrl(id) { return TIKTOK_POST_ID_RE.test(String(id || "")) ? "https://www.tiktok.com/player/v1/" + id : null; }
/* Has any platform got this video? YouTube has its id; TikTok has posted it;
   NAMED (Nov 7 2026, Instagram posting): an Instagram Reel of it is published
   (instagram_published, set from instagram_posts by instagramState).
   NAMED (Nov 7 2026, Facebook Pages posting): a Facebook video post of it is
   published (facebook_published, set from facebook_posts by facebookState). */
function platformGot(row) { return !!(row && (row.youtube_video_id || row.tiktok_status === "posted" || row.instagram_published === true || row.facebook_published === true)); }

/* What Instagram has of these videos, from instagram_posts:
   { published: { id: true }, holding: { id: true } }. holding: a row still
   creating or processing, which needs the file. Throws when unreadable. */
async function instagramState(supabase, videoIds) {
  var out = { published: {}, holding: {} };
  if (!videoIds.length) return out;
  var r = await supabase.from("instagram_posts").select("video_id, status").in("video_id", videoIds)
    .in("status", ["published"].concat(INSTAGRAM_HOLDING));
  if (r.error) throw new Error("instagram_posts could not be read");
  (r.data || []).forEach(function (p) {
    if (!p.video_id) return;
    if (p.status === "published") out.published[p.video_id] = true;
    else if (INSTAGRAM_HOLDING.indexOf(p.status) !== -1) out.holding[p.video_id] = true;
  });
  return out;
}
function withInstagram(row, state) { return Object.assign({}, row, { instagram_published: !!state.published[row.id] }); }
/* What Facebook has of these videos, from facebook_posts: the same shape as
   instagramState. holding: a row still creating or publishing. Throws when unreadable. */
async function facebookState(supabase, videoIds) {
  var out = { published: {}, holding: {} };
  if (!videoIds.length) return out;
  var r = await supabase.from("facebook_posts").select("video_id, status").in("video_id", videoIds)
    .in("status", ["published"].concat(FACEBOOK_HOLDING));
  if (r.error) throw new Error("facebook_posts could not be read");
  (r.data || []).forEach(function (p) {
    if (!p.video_id) return;
    if (p.status === "published") out.published[p.video_id] = true;
    else if (FACEBOOK_HOLDING.indexOf(p.status) !== -1) out.holding[p.video_id] = true;
  });
  return out;
}
function withFacebook(row, state) { return Object.assign({}, row, { facebook_published: !!state.published[row.id] }); }
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
async function measureStream(readable, maxBytes, reader) {
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
    // NAMED (Nov 17 2026, TK1): the MP4/MOV length is read from the same pass (durationReader); nothing is read twice.
    if (reader) reader.push(chunk);
    if (headLen < SNIFF_BYTES) {
      var part = chunk.subarray(0, SNIFF_BYTES - headLen);
      head.push(Buffer.from(part));
      headLen += part.length;
    }
  }
  return { bytes: bytes, sha256: hash.digest("hex"), head: Buffer.concat(head), durationMs: reader ? reader.result() : null };
}

/* ── a video's length (NAMED, Nov 17 2026, TK1) ─────────────────────────────
   For TikTok's rule: "API clients must check if the duration of the
   to-be-posted video follows the max_video_post_duration_sec returned in the
   creator_info API." (developers.tiktok.com/docs/en/content-sharing-guidelines)
   Stored in member_videos.duration_ms (migration 186), NULL when unknown.
   MP4 and MOV: the movie header, moov > mvhd, read as the file streams past
   once (durationReader): only the top-level boxes are walked, moov's body
   (at most MOOV_MAX bytes) is kept to find mvhd, and the length is
   duration / timescale in whole milliseconds. Anything malformed is null,
   never a guess. WebM, or an MP4/MOV with no readable mvhd: the browser's
   measured length (duration_ms in the finalize body), only when it passes
   browserDuration's sanity checks. */
const MOOV_MAX = 8 * 1024 * 1024;
const DURATION_MAX_MS = 4 * 60 * 60 * 1000;
// A browser length is believed only if the file's bitrate it implies is between 1 kB/s and 25 MB/s.
const BROWSER_MIN_BYTES_PER_SEC = 1000;
const BROWSER_MAX_BYTES_PER_SEC = 25 * 1000 * 1000;

function msOf(duration, timescale) {
  if (!(timescale > 0) || !(duration > 0)) return null;
  var ms = Math.round(duration * 1000 / timescale);
  return ms >= 1 && ms <= DURATION_MAX_MS ? ms : null;
}

/* The length in an mvhd box found among moov's children, or null. */
function mvhdMs(body) {
  var i = 0;
  while (i + 8 <= body.length) {
    var size = body.readUInt32BE(i), type = body.toString("latin1", i + 4, i + 8);
    if (size < 8 || i + size > body.length) return null;
    if (type === "mvhd") {
      var version = body[i + 8], p = i + 12;
      if (version === 0) {
        if (size < 28) return null;
        var d32 = body.readUInt32BE(p + 12);
        return d32 === 0xFFFFFFFF ? null : msOf(d32, body.readUInt32BE(p + 8));
      }
      if (version === 1) {
        if (size < 40) return null;
        var d64 = body.readBigUInt64BE(p + 20);
        return d64 > BigInt(Number.MAX_SAFE_INTEGER) ? null : msOf(Number(d64), body.readUInt32BE(p + 16));
      }
      return null;
    }
    i += size;
  }
  return null;
}

/* Fed every chunk of an MP4/MOV in order; result() is the length in ms, or null. */
function durationReader() {
  var pending = null, skip = 0, keep = -1, moov = [], done = false, result = null, broken = false;
  return {
    push: function (chunk) {
      if (done || broken) return;
      var buf = pending ? Buffer.concat([pending, chunk]) : chunk;
      pending = null;
      var i = 0;
      while (i < buf.length && !done && !broken) {
        if (keep > 0) {
          var take = Math.min(keep, buf.length - i);
          moov.push(Buffer.from(buf.subarray(i, i + take)));
          keep -= take; i += take;
          if (keep === 0) { result = mvhdMs(Buffer.concat(moov)); moov = []; done = true; }
          continue;
        }
        if (skip > 0) { var s = Math.min(skip, buf.length - i); skip -= s; i += s; continue; }
        if (buf.length - i < 8) { pending = Buffer.from(buf.subarray(i)); return; }
        var size = buf.readUInt32BE(i), type = buf.toString("latin1", i + 4, i + 8), headLen = 8;
        if (size === 1) {
          if (buf.length - i < 16) { pending = Buffer.from(buf.subarray(i)); return; }
          var big = buf.readBigUInt64BE(i + 8);
          if (big > BigInt(Number.MAX_SAFE_INTEGER)) { broken = true; return; }
          size = Number(big); headLen = 16;
        }
        if (size < headLen) { broken = true; return; }
        i += headLen;
        if (type === "moov") {
          if (size - headLen > MOOV_MAX || size === headLen) { broken = true; return; }
          keep = size - headLen;
        } else {
          skip = size - headLen;
        }
      }
    },
    result: function () { return done ? result : null; }
  };
}

/* The browser's measured length, used only when the file gave none: a whole number of ms from 1 to 4 hours whose
   implied bitrate for this many bytes is plausible. Otherwise null. */
function browserDuration(v, bytes) {
  if (!Number.isInteger(v) || v < 1 || v > DURATION_MAX_MS) return null;
  var perSec = Number(bytes) * 1000 / v;
  return perSec >= BROWSER_MIN_BYTES_PER_SEC && perSec <= BROWSER_MAX_BYTES_PER_SEC ? v : null;
}

/* "45 s", "3 min", "2 min 5 s", "1 h 2 min". */
function durationText(ms) {
  var total = Math.max(0, Math.round(Number(ms) / 1000));
  var h = Math.floor(total / 3600), m = Math.floor((total % 3600) / 60), sec = total % 60;
  var parts = [];
  if (h) parts.push(h + " h");
  if (m) parts.push(m + " min");
  if (sec || !parts.length) parts.push(sec + " s");
  return parts.join(" ");
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
    return { status: 413, body: { error: "A video is at most 500 MB.", code: "too_big", field: "bytes" } };
  }
  if (sizeOf(b.bytes) === null) return { status: 400, body: { error: MESSAGES.badSize, code: "bad_size", field: "bytes" } };
  if (!labelOf(b.label).ok) return { status: 400, body: { error: MESSAGES.badLabel, code: "bad_label", field: "label" } };
  if (await readyCount(deps.supabase, userId) >= READY_MAX) return { status: 409, body: { error: MESSAGES.readyCap, code: "ready_cap" } };
  // NAMED (Nov 18 2026, BV1): the storage budget first, for every upload; nothing is signed when it is full.
  var full = await budgetRefusal(deps, b.bytes);
  if (full) return full;
  // NAMED (Nov 20 2026, P2-3): and the shared guard across every bucket (lib/storageGuard.js), for the whole file
  if (typeof deps.storageGuard === "function") {
    var sharedFull = await deps.storageGuard(b.bytes);
    if (sharedFull) return sharedFull;
  }
  var path = newPath(userId, ext, deps.randomBytes);
  // NAMED (Nov 18 2026, BV1): over ONE_FILE_MAX_BYTES, the plan only; each part asks POST /api/videos/part-url for its own URL.
  if (b.bytes > ONE_FILE_MAX_BYTES) {
    return { status: 200, body: { path: path, mime: TYPES[ext], max_bytes: MAX_BYTES, parts: partSizes(b.bytes).length, part_bytes: PART_BYTES } };
  }
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
/* NAMED (Nov 18 2026, BV1): every object of a file at once (at most PARTS_MAX). true when Storage said yes. */
async function removeObjects(storage, paths) {
  if (!paths.length) return true;
  try {
    var r = await storage.from(BUCKET).remove(paths.slice());
    return !(r && r.error);
  } catch (err) {
    return false;
  }
}
/* An upload's parts, objects then rows: what a refused or abandoned upload leaves behind. */
async function dropUpload(deps, userId, path, n) {
  var paths = [];
  for (var i = 0; i < Math.max(1, n || PARTS_MAX); i++) { var p = partPath(path, i); if (p) paths.push(p); }
  await removeObjects(deps.storage, paths);
  await deps.supabase.from("member_video_parts").delete().eq("user_id", userId).eq("upload_path", path).is("video_id", null);
}

/* The size Storage holds for one object, from its folder listing (no bytes are downloaded): a number, or null when
   there is no such object, or undefined when Storage could not be asked. */
async function storedSize(storage, path) {
  var cut = path.lastIndexOf("/");
  var r;
  try { r = await storage.from(BUCKET).list(path.slice(0, cut), { limit: 100, search: path.slice(cut + 1) }); } catch (err) { return undefined; }
  if (!r || r.error) return undefined;
  var hit = (r.data || []).filter(function (it) { return it && it.name === path.slice(cut + 1); })[0];
  if (!hit) return null;
  var size = hit.metadata && Number(hit.metadata.size);
  return Number.isInteger(size) && size >= 0 ? size : undefined;
}

/* The checks partUrl and partDone share: { path, idx, total, size } or a refusal. */
function partInput(userId, b) {
  if (!pathOwned(b.path, userId)) return { refusal: { status: 400, body: { error: MESSAGES.badPath, code: "bad_path", field: "path" } } };
  var sizes = partSizes(sizeOf(b.bytes) || 0);
  if (!sizes.length) return { refusal: { status: 400, body: { error: MESSAGES.badSize, code: "bad_size", field: "bytes" } } };
  if (!Number.isInteger(b.idx) || b.idx < 0 || b.idx >= sizes.length) return { refusal: { status: 400, body: { error: MESSAGES.badPart, code: "bad_part", field: "idx" } } };
  return { path: b.path, idx: b.idx, total: b.bytes, size: sizes[b.idx], partPath: partPath(b.path, b.idx) };
}

/* NAMED (Nov 18 2026, BV1): POST /api/videos/part-url { path, idx, bytes }: a signed upload URL for ONE part of a
   video over ONE_FILE_MAX_BYTES. Asking again for the same part is the retry: the URL may replace what is there
   (upsert), and partDone checks it again. { status, body }. */
async function partUrl(deps, userId, input) {
  var p = partInput(userId, input || {});
  if (p.refusal) return p.refusal;
  var done = await deps.supabase.from("member_videos").select("id").eq("path", p.path).maybeSingle();
  if (done.error) throw done.error;
  if (done.data) return { status: 409, body: { error: MESSAGES.already, code: "already" } };
  /* NAMED (Nov 20 2026, P2-3): the shared guard again before each part; the whole file was counted when its upload was
     planned (uploadUrl), so a part adds nothing more and is refused only when storage is already past the guard. */
  if (typeof deps.storageGuard === "function") {
    var partFull = await deps.storageGuard(0);
    if (partFull) return partFull;
  }
  var signed = await deps.storage.from(BUCKET).createSignedUploadUrl(p.partPath, { upsert: true });
  if (!signed || signed.error || !signed.data || typeof signed.data.signedUrl !== "string") {
    return { status: 503, body: { error: "The upload couldn't be prepared just now. Try again.", code: "storage" } };
  }
  return { status: 200, body: { upload_url: signed.data.signedUrl, idx: p.idx, bytes: p.size } };
}

/* NAMED (Nov 18 2026, BV1): POST /api/videos/part-done { path, idx, bytes, sha256 }: one part has been PUT. Its size
   is read from Storage's listing (nothing downloaded) and must be the size its place in the file gives; then the part
   is recorded in member_video_parts with the sha256 the browser computed, which finalize checks against the bytes.
   A part of the wrong size is deleted. { status, body }. */
async function partDone(deps, userId, input) {
  var b = input || {};
  var p = partInput(userId, b);
  if (p.refusal) return p.refusal;
  if (typeof b.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(b.sha256)) return { status: 400, body: { error: MESSAGES.badPart, code: "bad_sha256", field: "sha256" } };
  var done = await deps.supabase.from("member_videos").select("id").eq("path", p.path).maybeSingle();
  if (done.error) throw done.error;
  if (done.data) return { status: 409, body: { error: MESSAGES.already, code: "already" } };
  var size = await storedSize(deps.storage, p.partPath);
  if (size === undefined) return { status: 503, body: { error: MESSAGES.unreadable, code: "unreadable" } };
  if (size === null) return { status: 404, body: { error: MESSAGES.partMissing, code: "part_missing" } };
  if (size !== p.size) {
    await removeObject(deps.storage, p.partPath);
    return { status: 422, body: { error: MESSAGES.partSize, code: "part_size", deleted: true } };
  }
  var up = await deps.supabase.from("member_video_parts").upsert({
    user_id: userId, upload_path: p.path, idx: p.idx, path: p.partPath, bytes: size, sha256: b.sha256, video_id: null,
    created_at: new Date(deps.now()).toISOString()
  }, { onConflict: "upload_path,idx" }).select("idx");
  if (up.error) throw up.error;
  return { status: 200, body: { recorded: true, idx: p.idx } };
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
  // NAMED (Nov 18 2026, BV1): a video over ONE_FILE_MAX_BYTES is checked from its parts.
  if (declared > ONE_FILE_MAX_BYTES) return finalizeParts(deps, userId, b, path, label.value, declared);

  var stream = await openStream(deps.storage, path);
  if (!stream) return { status: 404, body: { error: MESSAGES.notUploaded, code: "not_uploaded" } };
  var m;
  try {
    // NAMED (Nov 18 2026, BV1): one object is still at most ONE_FILE_MAX_BYTES (the bucket's own limit); larger is parts.
    m = await measureStream(stream, ONE_FILE_MAX_BYTES, extOf(path) === "webm" ? null : durationReader());
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
    // NAMED (Nov 17 2026, TK1): the file's own length first; the browser's only when the file gave none.
    duration_ms: m.durationMs !== null ? m.durationMs : browserDuration(b.duration_ms, m.bytes),
    status: "ready", created_at: new Date(deps.now()).toISOString()
  }).select("*").single();
  if (ins.error) {
    if (ins.error.code === "23505") return { status: 409, body: { error: MESSAGES.already, code: "already" } };
    throw ins.error;
  }
  return { status: 201, body: { video: publicView(ins.data) } };
}

/* NAMED (Nov 18 2026, BV1): finalize for a parted video. Every part must be recorded (partDone), in order, each the
   size its place gives. Then ONE pass over the parts, in order: each part's bytes against its recorded size and
   sha256 (partGuard), and the whole file's bytes, sha256, type (its first bytes) and length (mvhd, read across the
   parts). Any mismatch deletes every part and its rows. Only then the row, part_count parts, and the parts are
   tied to it (video_id). */
async function finalizeParts(deps, userId, b, path, label, declared) {
  var sizes = partSizes(declared);
  var r = await deps.supabase.from("member_video_parts").select("idx, path, bytes, sha256, video_id").eq("user_id", userId).eq("upload_path", path);
  if (r.error) throw r.error;
  var rows = (r.data || []).filter(function (x) { return x.video_id === null || x.video_id === undefined; });
  if (rows.length < sizes.length) return { status: 409, body: { error: MESSAGES.partsMissing, code: "parts_missing", parts: sizes.length, recorded: rows.length } };
  var parts;
  try {
    parts = partsInOrder(rows, path, declared, sizes.length);
  } catch (err) {
    await dropUpload(deps, userId, path, PARTS_MAX);
    return { status: 422, body: { error: MESSAGES.sizeMismatch, code: "size_mismatch", deleted: true } };
  }
  var m;
  try {
    m = await measureStream(openRange(deps.storage, parts, 0, declared), MAX_BYTES, extOf(path) === "webm" ? null : durationReader());
  } catch (err) {
    if (err && err.code === "part_mismatch") {
      await dropUpload(deps, userId, path, PARTS_MAX);
      return { status: 422, body: { error: MESSAGES.partMismatch, code: "part_mismatch", deleted: true } };
    }
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
    await dropUpload(deps, userId, path, PARTS_MAX);
    return { status: refusal.status, body: { error: refusal.error, code: refusal.code, deleted: true } };
  }
  var ins = await deps.supabase.from("member_videos").insert({
    user_id: userId, path: path, mime: TYPES[extOf(path)], bytes: m.bytes, sha256: m.sha256, label: label,
    duration_ms: m.durationMs !== null ? m.durationMs : browserDuration(b.duration_ms, m.bytes),
    part_count: parts.length, status: "ready", created_at: new Date(deps.now()).toISOString()
  }).select("*").single();
  if (ins.error) {
    if (ins.error.code === "23505") return { status: 409, body: { error: MESSAGES.already, code: "already" } };
    throw ins.error;
  }
  // The parts now belong to the video; retentionTick never treats a live video's parts as abandoned either way.
  var tied = await deps.supabase.from("member_video_parts").update({ video_id: ins.data.id }).eq("user_id", userId).eq("upload_path", path).is("video_id", null);
  if (tied.error) console.error("[videos/finalize] Parts not tied to their video: " + (tied.error.code || "error"));
  return { status: 201, body: { video: publicView(ins.data) } };
}

/* NAMED (Nov 13 2026, S2): what Instagram and Facebook have of each listed video,
   read from rows that already exist (no migration, no write, no model call):
     instagram_posts / facebook_posts (migrations 179, 180): video_id, status,
       permalink, error, created_at; facebook_posts also removed_at;
     agent_proposals: publish_instagram_post / publish_facebook_post, pending or
       executing, whose payload names the video as video.id.
   One platform's status, first match wins:
     posted      a published row (Facebook: not removed); url = its permalink when it is the platform's own address;
     publishing  a row still creating, processing or publishing, or an executing proposal;
     pending     a proposal waiting for the member's approval;
     failed      the newest row failed; error = its reason (what the post's own view already shows the member);
     removed     Facebook only: a published post the member removed;
     not_sent    nothing at all.
   A table that cannot be read leaves that platform "unknown" rather than failing the list.
   Every read is bounded by the listed ids and by SOCIAL_ROWS_MAX. */
const SOCIAL_ROWS_MAX = 500;
const SOCIAL_PLATFORMS = Object.freeze({
  instagram: { table: "instagram_posts", action: "publish_instagram_post", holding: INSTAGRAM_HOLDING, columns: "video_id, status, permalink, error, created_at", url: /^https:\/\/www\.instagram\.com\/[^\s"'<>]{1,280}$/ },
  facebook: { table: "facebook_posts", action: "publish_facebook_post", holding: FACEBOOK_HOLDING, columns: "video_id, status, permalink, error, removed_at, created_at", url: /^https:\/\/www\.facebook\.com\/[^\s"'<>]{1,280}$/ }
});
const SOCIAL_STATUSES = Object.freeze(["posted", "publishing", "pending", "failed", "removed", "not_sent", "unknown"]);
const NOT_SENT = Object.freeze({ status: "not_sent", url: null, error: null });

/* One platform's status for one video, from its post rows (any order) and the proposals naming it. Pure. */
function platformStatus(name, rows, proposals) {
  var P = SOCIAL_PLATFORMS[name];
  var list = (rows || []).slice().sort(function (a, b) { return String(b.created_at || "").localeCompare(String(a.created_at || "")); });
  var props = proposals || [];
  var live = list.filter(function (r) { return r.status === "published" && !r.removed_at; })[0];
  if (live) return { status: "posted", url: typeof live.permalink === "string" && P.url.test(live.permalink) ? live.permalink : null, error: null };
  if (list.some(function (r) { return P.holding.indexOf(r.status) !== -1; }) || props.some(function (p) { return p.status === "executing"; })) return { status: "publishing", url: null, error: null };
  if (props.some(function (p) { return p.status === "pending"; })) return { status: "pending", url: null, error: null };
  if (list.length && list[0].status === "failed") return { status: "failed", url: null, error: typeof list[0].error === "string" && list[0].error.trim() ? list[0].error.trim().slice(0, 200) : "not posted" };
  if (list.some(function (r) { return r.status === "published" && r.removed_at; })) return { status: "removed", url: null, error: null };
  return NOT_SENT;
}

/* NAMED (Nov 13 2026, S3, "Post again"): each platform's filed proposal naming the video, from the same one
   read: "publishing" while one is executing, "pending" while one waits for approval, else null (also when
   the proposals could not be read: the server's one-pending guard still refuses a second filing). The
   Social page disables that platform's button with the reason. Read only. */
const PROPOSAL_ACTIONS = Object.freeze({ youtube: "publish_youtube_video", tiktok: "publish_tiktok_post",
  instagram: "publish_instagram_post", facebook: "publish_facebook_post" });
function proposalState(proposals, name, videoId) {
  var mine = (proposals || []).filter(function (p) { return p.action_type === PROPOSAL_ACTIONS[name] && namesVideo(p.payload, videoId); });
  if (mine.some(function (p) { return p.status === "executing"; })) return "publishing";
  if (mine.some(function (p) { return p.status === "pending"; })) return "pending";
  return null;
}

/* { <video id>: { instagram: {status,url,error}, facebook: {...}, proposals: {youtube, tiktok, instagram, facebook} } }
   for these videos. Reads only. */
async function socialStatus(supabase, userId, videoIds) {
  var out = {};
  videoIds.forEach(function (id) { out[id] = { instagram: NOT_SENT, facebook: NOT_SENT, proposals: {} }; });
  if (!videoIds.length) return out;
  var proposals = null;
  try {
    // NAMED (Nov 13 2026, S3): the same one read also names YouTube's and TikTok's filed proposals.
    var pr = await supabase.from("agent_proposals").select("action_type, status, payload, created_at").eq("user_id", userId)
      .in("action_type", Object.keys(PROPOSAL_ACTIONS).map(function (k) { return PROPOSAL_ACTIONS[k]; })).in("status", ["pending", "executing"])
      .order("created_at", { ascending: false }).limit(SOCIAL_ROWS_MAX);
    if (!pr.error) proposals = pr.data || [];
  } catch (e) { proposals = null; }
  for (var name of Object.keys(SOCIAL_PLATFORMS)) {
    var P = SOCIAL_PLATFORMS[name], rows = null;
    try {
      var r = await supabase.from(P.table).select(P.columns).eq("user_id", userId).in("video_id", videoIds)
        .order("created_at", { ascending: false }).limit(SOCIAL_ROWS_MAX);
      if (!r.error) rows = r.data || [];
    } catch (e) { rows = null; }
    videoIds.forEach(function (id) {
      if (rows === null || proposals === null) { out[id][name] = { status: "unknown", url: null, error: null }; return; }
      out[id][name] = platformStatus(name, rows.filter(function (x) { return x.video_id === id; }),
        proposals.filter(function (p) { return p.action_type === P.action && namesVideo(p.payload, id); }));
    });
  }
  videoIds.forEach(function (id) {
    Object.keys(PROPOSAL_ACTIONS).forEach(function (k) { out[id].proposals[k] = proposals === null ? null : proposalState(proposals, k, id); });
  });
  return out;
}

/* What a member sees of a row: never the path, the fingerprint or the session.
   NAMED (Nov 13 2026, S2): social, from socialStatus, adds Instagram's and Facebook's
   status; without it (a video just added) both are not_sent. */
function publicView(row, social) {
  var r = row || {};
  var s = social || {};
  var ig = s.instagram || NOT_SENT, fb = s.facebook || NOT_SENT;
  // NAMED (Nov 13 2026, S3): <platform>_proposal, "pending", "publishing" or null (see proposalState).
  var pp = s.proposals || {};
  var filed = function (k) { return pp[k] === "pending" || pp[k] === "publishing" ? pp[k] : null; };
  return {
    id: r.id, label: r.label || "", bytes: Number(r.bytes) || 0, mime: r.mime, status: r.status,
    // NAMED (Nov 17 2026, TK1): the length in ms, null when unknown.
    duration_ms: Number.isInteger(r.duration_ms) ? r.duration_ms : null,
    // NAMED (Nov 18 2026, BV1): how many stored parts hold it, and whether Instagram and Facebook can take it (one object, at most 50 MB).
    parts: partCount(r), fits_meta: partCount(r) === 1 && (Number(r.bytes) || 0) <= ONE_FILE_MAX_BYTES,
    youtube_video_id: r.youtube_video_id || null, youtube_url: youtubeUrl(r.youtube_video_id),
    uploaded_at: r.uploaded_at || null, created_at: r.created_at || null,
    upload_unfinished: r.status === "ready" && !!r.session_ciphertext,
    // NAMED (Nov 7 2026, TikTok posting): TikTok's side. Never the publish id's upload address.
    tiktok_status: r.tiktok_status || null, tiktok_posted_at: r.tiktok_posted_at || null, tiktok_post_url: tiktokUrl(r.tiktok_post_id),
    tiktok_upload_unfinished: r.status === "ready" && r.tiktok_status === "initiated",
    instagram_status: ig.status, instagram_post_url: ig.url, instagram_error: ig.error,
    facebook_status: fb.status, facebook_post_url: fb.url, facebook_error: fb.error,
    youtube_proposal: filed("youtube"), tiktok_proposal: filed("tiktok"), instagram_proposal: filed("instagram"), facebook_proposal: filed("facebook")
  };
}

// NAMED (Nov 17 2026, TK1): duration_ms (migration 186) is read with the rest.
// NAMED (Nov 18 2026, BV1): part_count (migration 187) too.
const ROW_COLUMNS = "id, user_id, path, mime, bytes, sha256, label, status, duration_ms, part_count, youtube_video_id, session_ciphertext, session_iv, session_auth_tag, uploaded_at, created_at, " +
  "tiktok_publish_id, tiktok_status, tiktok_posted_at, tiktok_post_id, tiktok_upload_ciphertext, tiktok_upload_iv, tiktok_upload_auth_tag, tiktok_upload_expires_at";

async function listVideos(deps, userId) {
  var r = await deps.supabase.from("member_videos").select(ROW_COLUMNS).eq("user_id", userId).in("status", ["ready", "uploaded"])
    .order("created_at", { ascending: false }).limit(LIST_MAX);
  if (r.error) throw r.error;
  var rows = (r.data || []).filter(function (row) { return row.user_id === userId; });
  // NAMED (Nov 13 2026, S2): each video's Instagram and Facebook status, read only.
  var social = await socialStatus(deps.supabase, userId, rows.map(function (row) { return row.id; }));
  return rows.map(function (row) { return publicView(row, social[row.id]); });
}

async function readVideo(supabase, userId, id) {
  if (typeof id !== "string" || !UUID_RE.test(id)) return null;
  var r = await supabase.from("member_videos").select(ROW_COLUMNS).eq("id", id).eq("user_id", userId).maybeSingle();
  if (r.error) throw r.error;
  return r.data && r.data.user_id === userId ? r.data : null;
}

/* NAMED (Nov 17 2026, TK1): GET /api/videos/:id/preview. A signed address to the member's own file for
   PREVIEW_SECONDS, so the TikTok form and the TikTok proposal card can show the video before it is posted
   ("API Clients should display a preview of the to-be-posted content.", developers.tiktok.com/docs/en/
   content-sharing-guidelines). 410 file_gone once the file is deleted. Nothing is logged. */
const PREVIEW_SECONDS = 10 * 60;
async function previewUrl(deps, userId, id) {
  var video = await readVideo(deps.supabase, userId, id);
  if (!video) return { status: 404, body: { error: MESSAGES.notFound, code: "not_found" } };
  if (video.status !== "ready" || !video.path) return { status: 410, body: { error: MESSAGES.previewGone, code: "file_gone" } };
  var signed = await deps.storage.from(BUCKET).createSignedUrl(video.path, PREVIEW_SECONDS);
  if (!signed || signed.error || !signed.data || typeof signed.data.signedUrl !== "string") {
    return { status: 502, body: { error: MESSAGES.previewUnavailable, code: "unavailable" } };
  }
  // NAMED (Nov 18 2026, BV1): a parted video's preview is its first part (path), and says so.
  if (partCount(video) > 1) return { status: 200, body: { url: signed.data.signedUrl, mime: video.mime, expires_in: PREVIEW_SECONDS, partial: true, note: MESSAGES.previewStart } };
  return { status: 200, body: { url: signed.data.signedUrl, mime: video.mime, expires_in: PREVIEW_SECONDS } };
}

/* The member's pending (or running) proposals that name this video. */
async function proposalsNaming(supabase, userId, videoId, actionTypes) {
  var r = await supabase.from("agent_proposals").select("id, action_type, status, payload, created_at").eq("user_id", userId)
    .in("action_type", actionTypes).in("status", ["pending", "executing"]);
  if (r.error) throw r.error;
  return (r.data || []).filter(function (p) { return namesVideo(p.payload, videoId); });
}
/* A proposal payload naming this video: video_id (YouTube, TikTok) or video.id (Instagram). */
function namesVideo(payload, videoId) {
  if (!payload || typeof payload !== "object") return false;
  return payload.video_id === videoId || !!(payload.video && typeof payload.video === "object" && payload.video.id === videoId);
}

/* NAMED (Nov 18 2026, BV1): a deleted file's part rows. Best effort: a row left behind names an object already gone. */
async function dropPartRows(supabase, row) {
  try {
    var r = await supabase.from("member_video_parts").delete().eq("upload_path", row.path).eq("user_id", row.user_id);
    if (r && r.error) console.error("[videos] Part rows not deleted: " + (r.error.code || "error"));
  } catch (err) { console.error("[videos] Part rows not deleted: error"); }
}

/* DELETE /api/videos/:id. { status, body }. */
async function deleteVideo(deps, userId, id) {
  var row = await readVideo(deps.supabase, userId, id);
  if (!row) return { status: 404, body: { error: MESSAGES.notFound, code: "not_found" } };
  if (row.status !== "ready") return { status: 409, body: { error: MESSAGES.notReady, code: "not_ready" } };
  // NAMED (Nov 7 2026, TikTok posting): a pending YouTube OR TikTok proposal blocks it.
  var naming = await proposalsNaming(deps.supabase, userId, row.id, FILE_ACTIONS.slice());
  if (naming.length) return { status: 409, body: { error: MESSAGES.inProposal, code: "in_proposal" } };
  // NAMED (Nov 7 2026, Instagram posting): an Instagram post still creating or processing needs the file too.
  var ig = await instagramState(deps.supabase, [row.id]);
  if (ig.holding[row.id]) return { status: 409, body: { error: MESSAGES.instagramPublishing, code: "instagram_publishing" } };
  // NAMED (Nov 7 2026, Facebook Pages posting): a Facebook post still creating or publishing needs the file too.
  var fb = await facebookState(deps.supabase, [row.id]);
  if (fb.holding[row.id]) return { status: 409, body: { error: MESSAGES.facebookPublishing, code: "facebook_publishing" } };
  // NAMED (Nov 18 2026, BV1): BEFORE removeObject(row.path). AFTER every part of the file (filePaths), then their rows.
  if (row.path && !(await removeObjects(deps.storage, filePaths(row)))) return { status: 503, body: { error: MESSAGES.removeFailed, code: "remove_failed" } };
  var u = await deps.supabase.from("member_videos").update(fileGonePatch(withFacebook(withInstagram(row, ig), fb)))
    .eq("id", row.id).eq("user_id", userId).eq("status", "ready").select("id");
  if (u.error) throw u.error;
  if (partCount(row) > 1) await dropPartRows(deps.supabase, row);
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
   4. NAMED (Nov 18 2026, BV1): recorded parts of an upload that never became a video, ABANDONED_MS old: the objects,
      then the rows. Steps 1, 1b and 2 remove every part of a parted file, and step 3 knows every part.
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

/* NAMED (Nov 18 2026, BV1): every object of these rows (filePaths), and whether all of one row's are in `gone`. */
function allPaths(rows) { return rows.reduce(function (out, r) { return out.concat(filePaths(r)); }, []); }
function allGone(row, gone) { var p = filePaths(row); return p.length > 0 && p.every(function (x) { return gone.indexOf(x) !== -1; }); }

async function retentionTick(deps, nowMs) {
  var supabase = deps.supabase, storage = deps.storage;
  var startedMs = typeof nowMs === "number" ? nowMs : deps.now();
  var result = { claimed: true, expired: 0, both: 0, leftovers: 0, orphans: 0, abandoned: 0, error: null };
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
    /* NAMED (Nov 18 2026, BV1): BEFORE each step removed row.path. AFTER every part of the file (filePaths, by
       part_count); a row counts as gone only when ALL its parts are, and its part rows go with it (gonePaths). */
    var stale = await supabase.from("member_videos").select("id, user_id, path, part_count, youtube_video_id, tiktok_status").eq("status", "ready").lt("created_at", cutoff).limit(PAGE_SIZE);
    if (stale.error) throw new Error("member_videos could not be read");
    var staleRows = (stale.data || []).filter(function (r) { return r.path; });
    var staleIg = await instagramState(supabase, staleRows.map(function (r) { return r.id; }));
    var staleFb = await facebookState(supabase, staleRows.map(function (r) { return r.id; }));
    var staleGone = await removeMany(storage, allPaths(staleRows));
    for (var i = 0; i < staleRows.length; i++) {
      if (!allGone(staleRows[i], staleGone)) continue;
      var u = await supabase.from("member_videos").update(fileGonePatch(withFacebook(withInstagram(staleRows[i], staleIg), staleFb)))
        .eq("id", staleRows[i].id).eq("status", "ready").select("id");
      if (!u.error) result.expired += (u.data || []).length;
      if (!u.error && partCount(staleRows[i]) > 1) await dropPartRows(supabase, staleRows[i]);
    }
    /* 1b. NAMED (Nov 7 2026, TikTok posting): a ready video YouTube has AND TikTok
       has posted, that no pending or running proposal names: its file goes now. */
    var held = await supabase.from("agent_proposals").select("payload").in("action_type", FILE_ACTIONS.slice()).in("status", ["pending", "executing"]);
    if (held.error) throw new Error("agent_proposals could not be read");
    var named = {};
    (held.data || []).forEach(function (p) {
      if (!p.payload) return;
      if (typeof p.payload.video_id === "string") named[p.payload.video_id] = true;
      if (p.payload.video && typeof p.payload.video.id === "string") named[p.payload.video.id] = true;
    });
    /* NAMED (Nov 7 2026, Instagram posting): a Reel counts as a platform. The
       file goes early only once YouTube has it, TikTok has posted it AND an
       Instagram Reel of it is published, with no Instagram post of it still
       creating or processing.
       NAMED (Nov 7 2026, Facebook Pages posting): AND a Facebook video post of
       it is published, with no Facebook post of it still creating or publishing. */
    var both = await supabase.from("member_videos").select("id, user_id, path, part_count, youtube_video_id, tiktok_status").eq("status", "ready")
      .not("youtube_video_id", "is", null).eq("tiktok_status", "posted").limit(PAGE_SIZE);
    if (both.error) throw new Error("member_videos could not be read");
    var bothIg = await instagramState(supabase, (both.data || []).map(function (r) { return r.id; }));
    var bothFb = await facebookState(supabase, (both.data || []).map(function (r) { return r.id; }));
    var bothRows = (both.data || []).filter(function (r) { return r.path && !named[r.id] && bothIg.published[r.id] && !bothIg.holding[r.id]; })
      .filter(function (r) { return bothFb.published[r.id] && !bothFb.holding[r.id]; })
      .map(function (r) { return withFacebook(withInstagram(r, bothIg), bothFb); });
    var bothGone = await removeMany(storage, allPaths(bothRows));
    for (var b = 0; b < bothRows.length; b++) {
      if (!allGone(bothRows[b], bothGone)) continue;
      var w = await supabase.from("member_videos").update(fileGonePatch(bothRows[b]))
        .eq("id", bothRows[b].id).eq("status", "ready").select("id");
      if (!w.error) result.both += (w.data || []).length;
      if (!w.error && partCount(bothRows[b]) > 1) await dropPartRows(supabase, bothRows[b]);
    }
    // 2. an uploaded video's leftover object
    var left = await supabase.from("member_videos").select("id, user_id, path, part_count").eq("status", "uploaded").not("path", "is", null).limit(PAGE_SIZE);
    if (left.error) throw new Error("member_videos could not be read");
    var leftRows = (left.data || []).filter(function (r) { return r.path; });
    var leftGone = await removeMany(storage, allPaths(leftRows));
    for (var j = 0; j < leftRows.length; j++) {
      if (!allGone(leftRows[j], leftGone)) continue;
      var v = await supabase.from("member_videos").update({ path: null }).eq("id", leftRows[j].id).eq("status", "uploaded").select("id");
      if (!v.error) result.leftovers += (v.data || []).length;
      if (!v.error && partCount(leftRows[j]) > 1) await dropPartRows(supabase, leftRows[j]);
    }
    /* 4. NAMED (Nov 18 2026, BV1): an upload's parts that never became a video (no video_id) ABANDONED_MS after they
       were recorded: the objects, then the rows. Never a part of a video that exists (its path is a row's path). */
    var abandonCutoff = new Date(startedMs - ABANDONED_MS).toISOString();
    var loose = await supabase.from("member_video_parts").select("id, user_id, upload_path, path").is("video_id", null).lt("created_at", abandonCutoff).limit(PAGE_SIZE);
    if (loose.error) throw new Error("member_video_parts could not be read");
    var looseRows = loose.data || [];
    if (looseRows.length) {
      var owners = await supabase.from("member_videos").select("path").in("path", looseRows.map(function (r) { return r.upload_path; }));
      if (owners.error) throw new Error("member_videos could not be read");
      var live = (owners.data || []).map(function (r) { return r.path; });
      looseRows = looseRows.filter(function (r) { return live.indexOf(r.upload_path) === -1 && PART_PATH_RE.test(String(r.path || "")); });
      var looseGone = await removeMany(storage, looseRows.map(function (r) { return r.path; }));
      var looseIds = looseRows.filter(function (r) { return looseGone.indexOf(r.path) !== -1; }).map(function (r) { return r.id; });
      if (looseIds.length) {
        var dropped = await supabase.from("member_video_parts").delete().in("id", looseIds).is("video_id", null).select("id");
        if (!dropped.error) result.abandoned += (dropped.data || []).length;
      }
    }
    // 3. objects with no row, ORPHAN_MS old
    var orphanCutoff = startedMs - ORPHAN_MS;
    var folders = (await listAll(storage, "video")).filter(function (it) { return it && it.name && UUID_RE.test(it.name) && (it.id === null || it.id === undefined); });
    for (var k = 0; k < folders.length; k++) {
      var owner = folders[k].name;
      var files = (await listAll(storage, "video/" + owner)).filter(function (it) { return it && it.name && it.id; });
      if (!files.length) continue;
      var known = await supabase.from("member_videos").select("path, part_count").eq("user_id", owner);
      if (known.error) throw new Error("member_videos could not be read");
      // NAMED (Nov 18 2026, BV1): every part of a known video, and every recorded part (an upload under way), is known.
      var recorded = await supabase.from("member_video_parts").select("path").eq("user_id", owner);
      if (recorded.error) throw new Error("member_video_parts could not be read");
      var paths = allPaths(known.data || []).concat((recorded.data || []).map(function (r) { return r.path; })).filter(Boolean);
      var orphans = files.filter(function (f) {
        var key = "video/" + owner + "/" + f.name;
        var made = Date.parse(f.created_at || "");
        return paths.indexOf(key) === -1 && isFinite(made) && made < orphanCutoff;
      }).map(function (f) { return "video/" + owner + "/" + f.name; });
      result.orphans += (await removeMany(storage, orphans)).length;
    }
    await finish(null);
    console.log("[VideoRetention] Pass finished: " + result.expired + " video file(s) older than " + READY_DAYS + " days, " +
      result.both + " file(s) YouTube, TikTok, Instagram and Facebook all have, " +
      result.leftovers + " leftover file(s) of uploaded videos, " + result.abandoned + " part(s) of uploads that never finished, and " +
      result.orphans + " file(s) with no record deleted.");
    return result;
  } catch (err) {
    var message = (err && err.message) || "error";
    console.error("[VideoRetention] Pass error: " + message);
    try { await finish(message); } catch (finishErr) { /* reported above */ }
    return { claimed: true, error: message };
  }
}

module.exports = {
  // NAMED (Nov 17 2026, TK1): a video's length and its preview.
  durationReader: durationReader,
  mvhdMs: mvhdMs,
  browserDuration: browserDuration,
  durationText: durationText,
  previewUrl: previewUrl,
  DURATION_MAX_MS: DURATION_MAX_MS,
  MOOV_MAX: MOOV_MAX,
  PREVIEW_SECONDS: PREVIEW_SECONDS,
  BUCKET: BUCKET,
  MAX_BYTES: MAX_BYTES,
  // NAMED (Nov 18 2026, BV1): videos over 50 MB as parts, the storage budget, abandoned parts.
  ONE_FILE_MAX_BYTES: ONE_FILE_MAX_BYTES,
  PART_BYTES: PART_BYTES,
  PARTS_MAX: PARTS_MAX,
  BUDGET_BYTES_DEFAULT: BUDGET_BYTES_DEFAULT,
  ABANDONED_MS: ABANDONED_MS,
  PART_PATH_RE: PART_PATH_RE,
  partPath: partPath,
  partSizes: partSizes,
  partCount: partCount,
  filePaths: filePaths,
  fileParts: fileParts,
  partGuard: partGuard,
  openRange: openRange,
  rangeCursor: rangeCursor,
  budgetBytes: budgetBytes,
  storedBytes: storedBytes,
  budgetRefusal: budgetRefusal,
  removeObjects: removeObjects,
  partUrl: partUrl,
  partDone: partDone,
  READY_MAX: READY_MAX,
  UPLOADS_PER_DAY: UPLOADS_PER_DAY,
  TIKTOK_POSTS_PER_DAY: TIKTOK_POSTS_PER_DAY,
  FILE_ACTIONS: FILE_ACTIONS,
  INSTAGRAM_HOLDING: INSTAGRAM_HOLDING,
  instagramState: instagramState,
  FACEBOOK_HOLDING: FACEBOOK_HOLDING,
  facebookState: facebookState,
  namesVideo: namesVideo,
  PROPOSAL_ACTIONS: PROPOSAL_ACTIONS,
  proposalState: proposalState,
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
  SOCIAL_PLATFORMS: SOCIAL_PLATFORMS,
  SOCIAL_STATUSES: SOCIAL_STATUSES,
  SOCIAL_ROWS_MAX: SOCIAL_ROWS_MAX,
  platformStatus: platformStatus,
  socialStatus: socialStatus,
  listVideos: listVideos,
  readVideo: readVideo,
  proposalsNaming: proposalsNaming,
  deleteVideo: deleteVideo,
  validateMetadata: validateMetadata,
  measureMetadata: measureMetadata,
  retentionTick: retentionTick
};
