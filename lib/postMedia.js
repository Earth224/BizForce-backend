"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   POST PHOTOS (P2-3, Nov 20 2026; migration 193 post_media).

   IN THE BROWSER (scripts/bf-composer.js), before upload, with a canvas only:
   the long edge at most LONG_EDGE (1080) px, WebP at quality 0.8 (JPEG at 0.82
   where the browser cannot encode WebP), and a THUMB_EDGE (360) px thumbnail of
   each. Both are sent here one at a time.

   ON THE SERVER every photo and thumbnail is a member_media row, through the
   media library's own rules (lib/memberMedia.js): the type from the file's own
   bytes (JPEG, PNG or WebP only), location and camera details stripped, the
   sha256 de-duplication (a photo already in the library is reused, never
   copied), the 250 MB per-member cap, and the shared storage guard
   (lib/storageGuard.js). A post photo over PHOTO_MAX_BYTES (600 KB) is refused.

   A POST links them through post_media (idx 0 to 3, thumb_media_id), each
   checked here to be the author's own image within the limit. member_media's
   foreign key is ON DELETE RESTRICT, so a linked file is never deleted:
   DELETE /api/media/:id answers 409 while usedInPosts finds it.

   THE FEED loads thumb_url only; the full url is loaded when the post is
   opened or a photo tapped.
   ══════════════════════════════════════════════════════════════════════════ */
const MM = require("./memberMedia");

const PHOTO_MAX_BYTES = 600 * 1024;
const LONG_EDGE = 1080;
const THUMB_EDGE = 360;
const WEBP_QUALITY = 0.8;
const JPEG_QUALITY = 0.82;
const PHOTO_EXTS = ["jpg", "png", "webp"];
const ITEM_COLUMNS = "id, path, kind, mime, bytes, label, alt_text, metadata_stripped, created_at";

const MESSAGES = {
  tooBig: "A post photo is at most 600 KB. The page makes photos smaller before sending them; if this one is still too big, try another photo.",
  type: "A post photo must be a JPEG, PNG or WebP picture.",
  notYours: "One of the photos isn't in your library.",
  twice: "The same photo is in the post twice.",
  badId: "One of the photos isn't valid."
};

function refused(status, reason, error) { return { status: status, reason: reason, error: error }; }

/* Stores one photo (or thumbnail) the way POST /api/media does, plus the 600 KB rule. deps = { sb, storage, guard, base }.
   Returns { status, body }. */
async function storePhoto(deps, userId, file) {
  if (file && file.buffer && file.buffer.length > PHOTO_MAX_BYTES) return { status: 413, body: { error: MESSAGES.tooBig, reason: "too_big" } };
  var checked;
  try { checked = MM.checkFile(file); } catch (refusal) {
    if (refusal instanceof MM.MediaRefused) return { status: refusal.status, body: { error: refusal.message, reason: refusal.reason } };
    throw refusal;
  }
  if (PHOTO_EXTS.indexOf(checked.ext) === -1) return { status: 415, body: { error: MESSAGES.type, reason: "type" } };
  if (checked.size > PHOTO_MAX_BYTES) return { status: 413, body: { error: MESSAGES.tooBig, reason: "too_big" } };

  var existing = await deps.sb.from("member_media").select(ITEM_COLUMNS).eq("user_id", userId).eq("sha256", checked.sha256).maybeSingle();
  if (existing.error) throw existing.error;
  if (existing.data) return { status: 200, body: { item: MM.publicItem(existing.data, deps.base), duplicate: true } };

  var held = await MM.usage(deps.sb, userId);
  if (held.used_bytes + checked.size > MM.MEMBER_MEDIA_BYTES) return { status: 413, body: { error: MM.MESSAGES.full, reason: "full" } };
  var full = await deps.guard(checked.size);
  if (full) return full;

  var key = MM.mediaPath(userId, checked.ext);
  var put = await deps.storage.from(MM.BUCKET).upload(key, checked.bytes, { contentType: checked.mime, upsert: false });
  if (put.error) return { status: 502, body: { error: MM.MESSAGES.stored } };
  var row = await deps.sb.from("member_media").insert({ user_id: userId, path: key, kind: checked.kind, mime: checked.mime, bytes: checked.size,
    sha256: checked.sha256, metadata_stripped: checked.stripped, label: "Post photo" }).select(ITEM_COLUMNS).single();
  if (row.error) {
    await deps.storage.from(MM.BUCKET).remove([key]);
    if (row.error.code === "23505") {
      var again = await deps.sb.from("member_media").select(ITEM_COLUMNS).eq("user_id", userId).eq("sha256", checked.sha256).maybeSingle();
      if (!again.error && again.data) return { status: 200, body: { item: MM.publicItem(again.data, deps.base), duplicate: true } };
    }
    throw row.error;
  }
  if (await MM.overCap(deps.sb, userId, row.data.id)) {
    await deps.storage.from(MM.BUCKET).remove([key]);
    await deps.sb.from("member_media").delete().eq("id", row.data.id).eq("user_id", userId);
    return { status: 413, body: { error: MM.MESSAGES.full, reason: "full" } };
  }
  return { status: 201, body: { item: MM.publicItem(row.data, deps.base) } };
}

/* The photos a new post names: [{ media_id, thumb_media_id }], each the author's own image within the limit.
   { photos } or { status, error, reason }. */
async function checkForPost(sb, userId, media) {
  var ids = [], photos = [];
  for (var i = 0; i < media.length; i++) {
    var m = media[i] || {};
    if (!MM.UUID_RE.test(String(m.media_id || ""))) return refused(400, "bad_id", MESSAGES.badId);
    if (m.thumb_media_id !== undefined && m.thumb_media_id !== null && !MM.UUID_RE.test(String(m.thumb_media_id))) return refused(400, "bad_id", MESSAGES.badId);
    if (photos.some(function (p) { return p.media_id === m.media_id; })) return refused(400, "twice", MESSAGES.twice);
    photos.push({ media_id: m.media_id, thumb_media_id: m.thumb_media_id || null });
    ids.push(m.media_id);
    if (m.thumb_media_id) ids.push(m.thumb_media_id);
  }
  var r = await sb.from("member_media").select("id, user_id, kind, mime, bytes").eq("user_id", userId).in("id", [...new Set(ids)]);
  if (r.error) throw r.error;
  var mine = {};
  (r.data || []).forEach(function (row) { if (row.user_id === userId) mine[row.id] = row; });
  for (var j = 0; j < ids.length; j++) {
    var f = mine[ids[j]];
    if (!f) return refused(404, "not_yours", MESSAGES.notYours);
    if (f.kind !== "image" || ["image/jpeg", "image/png", "image/webp"].indexOf(f.mime) === -1) return refused(415, "type", MESSAGES.type);
    if (Number(f.bytes) > PHOTO_MAX_BYTES) return refused(413, "too_big", MESSAGES.tooBig);
  }
  return { photos: photos };
}

/* Whether a library file is linked to a post (as a photo or a thumbnail). */
async function usedInPosts(sb, mediaId) {
  // as the photo or as its thumbnail: two plain reads, so no filter string is built from the id
  for (const col of ["media_id", "thumb_media_id"]) {
    var r = await sb.from("post_media").select("post_id").eq(col, mediaId).limit(1);
    if (r.error) throw r.error;
    if ((r.data || []).length > 0) return true;
  }
  return false;
}

module.exports = { PHOTO_MAX_BYTES, LONG_EDGE, THUMB_EDGE, WEBP_QUALITY, JPEG_QUALITY, PHOTO_EXTS, MESSAGES, storePhoto, checkForPost, usedInPosts };
