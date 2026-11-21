"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   lib/storageAccount.js — storage per account, across every bucket
   (P3-1, Nov 20 2026; migrations 196 to 198).

   THE LIMITS ARE IN CODE (lib/membership.js): a free account may store
   STORAGE_FREE_BYTES (50 MB) and a member STORAGE_MEMBER_BYTES (500 MB), in
   all buckets together. The owner account is exempt (counted, never refused).
   The shared 920 MB guard (lib/storageGuard.js) is asked first and stays.

   EVERY UPLOAD RESERVES BEFORE IT STORES. reserve() calls the database's
   storage_account_reserve(user, bucket, path, bytes, limit) (migration 197):
   it locks the account's totals row, so two uploads at once cannot both slip
   under the limit, and counts the file only when it fits. A failed upload,
   and every delete, calls release() (storage_account_release), so the count
   follows the files. A signed upload reserves the size the browser declared;
   POST /api/bfp/upload-check reserves again with the size that arrived, which
   replaces the declared one.

   FAILS CLOSED. A reserve the database cannot answer refuses the upload
   (503, nothing stored). A release that fails is logged and the delete goes
   on: an over-count can only refuse an upload, never lose a file.
   ══════════════════════════════════════════════════════════════════════════ */

const M = require("./membership");

const EXEMPT_LIMIT = Number.MAX_SAFE_INTEGER;

function mb(bytes) {
  const v = Number(bytes) / M.MB;
  return (v < 10 ? Math.round(v * 10) / 10 : Math.round(v)) + " MB";
}

/* The plain sentence a refusal says, with how much is used. */
function fullSentence(usedBytes, limitBytes, fileBytes, tier) {
  return "Your account can store " + mb(limitBytes) + " of files and " + mb(usedBytes) + " is used, so this " + mb(fileBytes) +
    " file does not fit. Nothing was uploaded. Delete files you no longer need" +
    (tier === "member" ? "." : ", or join BizForce for " + mb(M.STORAGE_MEMBER_BYTES) + ".");
}

const UNCHECKED_SENTENCE = "Your storage use could not be checked just now, so nothing was uploaded. Try again in a minute.";

function limitFor(who) {
  if (who && who.owner === true) return EXEMPT_LIMIT;
  return M.storageLimitFor(who && who.tier);
}

/* who: { tier: "free" | "member", owner: boolean }. null when the file is counted; else { status, body } and nothing may be stored. */
async function reserve(sb, userId, who, bucket, path, bytes) {
  const size = Math.max(0, Math.round(Number(bytes) || 0));
  const limit = limitFor(who);
  let r;
  try {
    r = await sb.rpc("storage_account_reserve", { p_user: userId, p_bucket: bucket, p_path: path, p_bytes: size, p_limit: limit });
  } catch (e) { r = { error: e }; }
  if (!r || r.error) {
    console.error("[storage-account] reserve failed for " + userId + " " + bucket + "/" + path + ": " +
      ((r && r.error && r.error.message) || (r && r.error) || "no answer") + " — upload refused.");
    return { status: 503, body: { error: UNCHECKED_SENTENCE, reason: "account_storage_unchecked" } };
  }
  const answer = r.data || {};
  if (answer.ok === true) return null;
  const used = Number(answer.used_bytes) || 0;
  return {
    status: 413,
    body: {
      error: fullSentence(used, limit, size, who && who.tier),
      reason: "account_storage_full",
      used_bytes: used,
      limit_bytes: limit,
      file_bytes: size
    }
  };
}

/* Best effort: the count follows a deleted or failed file. Returns the bytes freed, or 0. */
async function release(sb, bucket, path) {
  if (!bucket || !path) return 0;
  try {
    const r = await sb.rpc("storage_account_release", { p_bucket: bucket, p_path: path });
    if (r && r.error) throw r.error;
    return Number(r && r.data) || 0;
  } catch (e) {
    console.error("[storage-account] release failed for " + bucket + "/" + path + ": " + ((e && e.message) || e) + " — the file is still counted.");
    return 0;
  }
}

async function releaseMany(sb, bucket, paths) {
  let freed = 0;
  for (const p of (paths || []).filter(Boolean)) freed += await release(sb, bucket, p);
  return freed;
}

/* What the account has stored, for Your data ("your storage use"). */
async function usage(sb, userId) {
  const t = await sb.from("storage_account_totals").select("user_id, bytes, files, updated_at").eq("user_id", userId).maybeSingle();
  if (t.error) throw t.error;
  return { bytes: Number(t.data && t.data.bytes) || 0, files: Number(t.data && t.data.files) || 0 };
}

module.exports = { reserve, release, releaseMany, usage, fullSentence, limitFor, mb, EXEMPT_LIMIT, UNCHECKED_SENTENCE };
