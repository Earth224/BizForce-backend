/* ══════════════════════════════════════════════════════════════════════════
   scripts/storageAccountBackfill.js — count every stored file for its owner
   (P3-1, Nov 20 2026; after migrations 196 to 198).

   WHY. Migration 198 counted a file for the first account id in its PATH.
   Most stored paths do not carry their owner's id (a profile image is
   recorded as a URL on the row, a book under the owner's folder in bf-books,
   and so on), so it counted 1 account. This finds each file's owner the way
   the account delete does (lib/accountFiles.js filesOwnedBy: every table that
   points at a file, plus the member's own folders), then an account id in the
   path as the last resort, and counts the file for that owner through the
   same storage_account_reserve the upload routes call, with no limit (an
   existing file is counted, never refused).

   WHAT IT PRINTS (and writes as JSON to the path in OUT, if set): the totals
   per bucket BEFORE and AFTER, the files counted now, and every file whose
   owner cannot be found (left uncounted; platform files such as the site's
   own images are expected there).

   DRY RUN BY DEFAULT. Nothing is written unless WRITE=1. Safe to re-run: a
   file already counted for its owner is left alone; a file counted for a
   DIFFERENT account is reported, never moved.

   Run from the repo root: node scripts/storageAccountBackfill.js
   ══════════════════════════════════════════════════════════════════════════ */
require("dotenv").config();
const fs = require("fs");
const { createClient } = require("@supabase/supabase-js");
const AF = require("../lib/accountFiles");
const SA = require("../lib/storageAccount");

const WRITE = process.env.WRITE === "1";
const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g;
const PAGE = 100;

async function walk(storage, bucket) {
  const out = [];
  const folders = [""];
  while (folders.length) {
    const prefix = folders.shift();
    for (let offset = 0; ; offset += PAGE) {
      const r = await storage.from(bucket).list(prefix, { limit: PAGE, offset: offset, sortBy: { column: "name", order: "asc" } });
      if (r.error) throw new Error(bucket + "/" + prefix + " could not be listed: " + (r.error.message || r.error));
      const rows = r.data || [];
      rows.forEach(function (o) {
        if (!o || !o.name) return;
        const key = prefix ? prefix + "/" + o.name : o.name;
        if (o.id === null || o.id === undefined) folders.push(key);
        else out.push({ bucket: bucket, path: key, bytes: Number(o.metadata && o.metadata.size) || 0 });
      });
      if (rows.length < PAGE) break;
    }
  }
  return out;
}

async function counted(sb) {
  const rows = [];
  for (let from = 0; ; from += 1000) {
    const r = await sb.from("storage_account_objects").select("bucket, path, user_id, bytes").range(from, from + 999);
    if (r.error) throw r.error;
    rows.push(...(r.data || []));
    if ((r.data || []).length < 1000) break;
  }
  return rows;
}

function perBucket(rows) {
  const out = {};
  AF.BUCKETS.forEach(function (b) { out[b] = { files: 0, bytes: 0 }; });
  rows.forEach(function (r) { const b = out[r.bucket] || (out[r.bucket] = { files: 0, bytes: 0 }); b.files++; b.bytes += Number(r.bytes) || 0; });
  return out;
}

(async function main() {
  const sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY);
  const before = await counted(sb);
  const beforeKey = new Map(before.map(function (r) { return [r.bucket + "\u0000" + r.path, r]; }));

  const stored = [];
  for (const b of AF.BUCKETS) stored.push(...(await walk(sb.storage, b)));

  const users = [];
  for (let from = 0; ; from += 1000) {
    const r = await sb.from("users").select("id, role").range(from, from + 999);
    if (r.error) throw r.error;
    users.push(...(r.data || []));
    if ((r.data || []).length < 1000) break;
  }
  const ids = new Set(users.map(function (u) { return u.id; }));

  // Owner from the tables (the account delete's own list), then an account id in the path.
  const ownerOf = new Map(), claims = [];
  for (const u of users) {
    if (u.role === "deleted") continue;
    const files = await AF.filesOwnedBy({ supabase: sb, storage: sb.storage, userId: u.id, publicUrlBase: process.env.SUPABASE_URL });
    files.forEach(function (f) {
      const k = f.bucket + "\u0000" + f.path;
      if (ownerOf.has(k) && ownerOf.get(k).user !== u.id) claims.push({ bucket: f.bucket, path: f.path, first: ownerOf.get(k).user, also: u.id });
      else if (!ownerOf.has(k)) ownerOf.set(k, { user: u.id, how: f.reason });
    });
  }

  const plan = [], unowned = [], conflicts = [];
  for (const f of stored) {
    const k = f.bucket + "\u0000" + f.path;
    let owner = ownerOf.get(k);
    if (!owner) {
      const hit = (f.path.toLowerCase().match(UUID) || []).find(function (id) { return ids.has(id); });
      if (hit) owner = { user: hit, how: "an account id in the path" };
    }
    if (!owner) { unowned.push(f); continue; }
    const have = beforeKey.get(k);
    if (have && have.user_id !== owner.user) { conflicts.push({ bucket: f.bucket, path: f.path, counted_for: have.user_id, owner: owner.user }); continue; }
    if (have) continue;
    plan.push({ bucket: f.bucket, path: f.path, bytes: f.bytes, user: owner.user, how: owner.how });
  }

  let wrote = 0, failed = 0;
  if (WRITE) {
    for (const p of plan) {
      const r = await sb.rpc("storage_account_reserve", { p_user: p.user, p_bucket: p.bucket, p_path: p.path, p_bytes: p.bytes, p_limit: SA.EXEMPT_LIMIT });
      if (r.error || !(r.data && r.data.ok === true)) { failed++; console.error("  not counted: " + p.bucket + "/" + p.path + " " + ((r.error && r.error.message) || JSON.stringify(r.data))); }
      else wrote++;
    }
  }
  const after = WRITE ? await counted(sb) : before.concat(plan.map(function (p) { return { bucket: p.bucket, path: p.path, user_id: p.user, bytes: p.bytes }; }));

  const result = {
    mode: WRITE ? "write" : "dry run",
    stored: perBucket(stored.map(function (f) { return { bucket: f.bucket, bytes: f.bytes }; })),
    before: perBucket(before), after: perBucket(after),
    accounts_before: new Set(before.map(function (r) { return r.user_id; })).size,
    accounts_after: new Set(after.map(function (r) { return r.user_id; })).size,
    to_count: plan.length, counted_now: wrote, failed: failed,
    by_how: plan.reduce(function (m, p) { const h = p.how.replace(/ \d+$/, ""); m[h] = (m[h] || 0) + 1; return m; }, {}),
    unowned: unowned, conflicts: conflicts, double_claims: claims
  };
  const mb = function (b) { return (b / 1048576).toFixed(2) + " MB"; };
  console.log("Storage back-fill (" + result.mode + ")");
  console.log("bucket".padEnd(18) + "stored".padStart(22) + "before".padStart(22) + "after".padStart(22));
  Object.keys(result.stored).forEach(function (b) {
    const c = function (o) { return ((o && o.files) || 0) + " / " + mb((o && o.bytes) || 0); };
    console.log(b.padEnd(18) + c(result.stored[b]).padStart(22) + c(result.before[b]).padStart(22) + c(result.after[b]).padStart(22));
  });
  console.log("accounts counted: before " + result.accounts_before + ", after " + result.accounts_after);
  console.log("files to count " + plan.length + ", counted now " + wrote + ", failed " + failed);
  console.log("owner found by: " + JSON.stringify(result.by_how));
  console.log("files with no owner found (left uncounted): " + unowned.length);
  unowned.forEach(function (f) { console.log("  " + f.bucket + "/" + f.path + " (" + mb(f.bytes) + ")"); });
  if (conflicts.length) console.log("counted for a different account (left as is): " + JSON.stringify(conflicts));
  if (claims.length) console.log("claimed by two accounts (the first kept): " + claims.length);
  if (process.env.OUT) fs.writeFileSync(process.env.OUT, JSON.stringify(result, null, 1));
  process.exit(failed ? 1 : 0);
})().catch(function (e) { console.error("back-fill failed: " + ((e && e.stack) || e)); process.exit(1); });
