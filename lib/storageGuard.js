"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   THE SHARED STORAGE GUARD (P2-3, Nov 20 2026). One number across every bucket
   (bf-public, bf-video, bf-music, bf-books, bf-digital-goods and any other):
   STORAGE_TOTAL_GUARD, 920 MB, under the free plan's 1 GB.

   Before EVERY upload anywhere on the site (the media library, post photos,
   music, videos and their parts, books and their covers, cover wraps, editor
   images, digital goods, theme photos, and the signed uploads of
   POST /api/bfp/upload-url: avatars, banners, card media, listing media...)
   the route asks refusal(supabase, bytes). The total is measured by
   lib/storageUsage.js (every bucket walked, cached CACHE_MS); the bytes this
   server has let through since that measurement are added, so a burst of
   uploads inside the cache window cannot slip past. Over the guard: 507 with
   a plain sentence, and nothing is uploaded. When storage cannot be measured
   (an error, or a walk that stopped early): 503, and nothing is uploaded,
   because a guard that waves uploads through when it cannot see is no guard.

   The video library's own 900 MB budget (lib/memberVideos.js) stays, and a
   video must pass both.
   ══════════════════════════════════════════════════════════════════════════ */
const usage = require("./storageUsage");

const STORAGE_TOTAL_GUARD = 920 * 1024 * 1024;
const MESSAGES = {
  full: "BizForce's storage is nearly full, so this upload can't be taken right now. Nothing was uploaded. Please try again later.",
  unknown: "The storage space couldn't be checked just now, so nothing was uploaded. Try again in a minute."
};
let since = { measuredAt: null, added: 0 };

/* null when `bytes` more fit under the guard; else { status, body }. */
async function refusal(supabase, bytes, opts) {
  opts = opts || {};
  const adding = Math.max(0, Number(bytes) || 0);
  let m;
  try { m = await usage.measure(supabase, { now: opts.now }); } catch (e) {
    console.error("[storage-guard] storage could not be measured (" + ((e && (e.code || e.message)) || "error") + "); the upload was refused.");
    return { status: 503, body: { error: MESSAGES.unknown, reason: "storage_unknown" } };
  }
  if (!m || m.partial === true || typeof m.total_bytes !== "number") {
    console.error("[storage-guard] the storage walk was incomplete; the upload was refused.");
    return { status: 503, body: { error: MESSAGES.unknown, reason: "storage_unknown" } };
  }
  if (since.measuredAt !== m.measured_at) since = { measuredAt: m.measured_at, added: 0 };
  if (m.total_bytes + since.added + adding > STORAGE_TOTAL_GUARD) {
    return { status: 507, body: { error: MESSAGES.full, reason: "storage_full" } };
  }
  since.added += adding;
  return null;
}

/* What the guard counts now: the last measurement plus what was let through since. */
async function status(supabase) {
  const m = await usage.measure(supabase);
  const extra = since.measuredAt === m.measured_at ? since.added : 0;
  return { guard_bytes: STORAGE_TOTAL_GUARD, measured_bytes: m.total_bytes, added_since_bytes: extra, total_bytes: m.total_bytes + extra,
    measured_at: m.measured_at, partial: m.partial === true };
}

function reset() { since = { measuredAt: null, added: 0 }; }

module.exports = { STORAGE_TOTAL_GUARD, MESSAGES, refusal, status, reset };
