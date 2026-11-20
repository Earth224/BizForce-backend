"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   STORAGE USAGE (P2-2, Nov 20 2026): the moderation page's usage panel. Every
   bucket is walked (Supabase Storage list, 1000 a page, folders followed) and
   its files' sizes added up, against the free plan's FREE_PLAN_BYTES (1 GB).
   The walk stops at MAX_OBJECTS files or MAX_FOLDERS folders and says so
   (partial: true), so it can never run away. The answer is kept CACHE_MS
   (10 minutes), because the walk is slow and the totals move slowly.
   ══════════════════════════════════════════════════════════════════════════ */
const FREE_PLAN_BYTES = 1024 * 1024 * 1024;
const PAGE = 1000;
const MAX_OBJECTS = 50000;
const MAX_FOLDERS = 5000;
const CACHE_MS = 10 * 60 * 1000;
let cache = { at: 0, value: null };

async function bucketTotal(storage, bucket, budget) {
  let bytes = 0, files = 0, partial = false;
  const folders = [""];
  while (folders.length) {
    if (budget.folders-- <= 0) { partial = true; break; }
    const prefix = folders.shift();
    for (let offset = 0; ; offset += PAGE) {
      const r = await storage.from(bucket).list(prefix, { limit: PAGE, offset: offset, sortBy: { column: "name", order: "asc" } });
      if (r.error) throw r.error;
      const rows = r.data || [];
      rows.forEach(function (o) {
        if (!o || !o.name) return;
        if (o.id === null || o.id === undefined) folders.push(prefix ? prefix + "/" + o.name : o.name);
        else { files++; budget.objects--; bytes += Number(o.metadata && o.metadata.size) || 0; }
      });
      if (budget.objects <= 0) { partial = true; break; }
      if (rows.length < PAGE) break;
    }
    if (partial) break;
  }
  return { bucket: bucket, bytes: bytes, files: files, partial: partial };
}

/* { buckets: [{ bucket, bytes, files, partial }], total_bytes, limit_bytes, percent, partial, measured_at } */
async function measure(supabase, opts) {
  opts = opts || {};
  const now = opts.now || Date.now();
  if (!opts.fresh && cache.value && now - cache.at < CACHE_MS) return Object.assign({ cached: true }, cache.value);
  const list = await supabase.storage.listBuckets();
  if (list.error) throw list.error;
  const budget = { objects: MAX_OBJECTS, folders: MAX_FOLDERS };
  const buckets = [];
  for (const b of (list.data || [])) buckets.push(await bucketTotal(supabase.storage, b.name || b.id, budget));
  const total = buckets.reduce(function (n, b) { return n + b.bytes; }, 0);
  const value = { buckets: buckets, total_bytes: total, limit_bytes: FREE_PLAN_BYTES, percent: Math.round(total / FREE_PLAN_BYTES * 1000) / 10,
    partial: buckets.some(function (b) { return b.partial; }), measured_at: new Date(now).toISOString() };
  cache = { at: now, value: value };
  return Object.assign({ cached: false }, value);
}

function resetCache() { cache = { at: 0, value: null }; }

module.exports = { FREE_PLAN_BYTES, PAGE, MAX_OBJECTS, MAX_FOLDERS, CACHE_MS, measure, bucketTotal, resetCache };
