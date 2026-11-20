"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   _p23Db.js — an in-memory, supabase-shaped database for the P2-3 checks
   (Nov 20 2026): checkPosts, checkSocialGraph, checkPostMedia,
   checkPublicPostPage and checkPostRetention.

   memDb(seed) holds tables of plain rows and answers the query builder the
   libs use: select (with { count: "exact", head: true }), eq, neq, in, is,
   not(col, "is", null), lt, lte, gt, gte, ilike, or("a.eq.x,and(b.lt.y,...)"),
   order, limit, range, single, maybeSingle; insert, update, upsert
   ({ onConflict, ignoreDuplicates }) and delete, each with .select() for the
   rows written. Every query is logged ({ table, op, filters, payload }).

   As migrations 193 and 194 do, it keeps:
     the primary keys (follows, post_likes, post_saves, post_share_days,
       post_media): a second row is error 23505;
     the counters (posts_count_bump): an insert or delete on post_likes,
       post_saves, post_share_days or post_comments moves the post's
       like_count, save_count, share_count or comment_count, never below 0;
     a new row's id (a uuid) and created_at when none is given.

   db.failOn(table, op) makes the next such query answer { error }.
   ═══════════════════════════════════════════════════════════════════════════ */
const crypto = require("crypto");

const KEYS = {
  follows: ["follower_id", "following_id"],
  post_likes: ["post_id", "user_id"],
  post_saves: ["post_id", "user_id"],
  post_share_days: ["post_id", "user_id", "day"],
  post_media: ["post_id", "idx"]
};
const COUNTERS = { post_likes: "like_count", post_saves: "save_count", post_share_days: "share_count", post_comments: "comment_count" };
const NO_ID = new Set(["follows", "post_likes", "post_saves", "post_share_days", "post_media", "job_runs"]);

function unquote(v) { v = String(v); return v.length > 1 && v.charAt(0) === '"' && v.charAt(v.length - 1) === '"' ? v.slice(1, -1) : v; }
function cmp(a, b) {
  if (a === null || a === undefined || b === null || b === undefined) return NaN;
  if (typeof a === "number" || typeof b === "number") return Number(a) - Number(b);
  const da = Date.parse(a), dbb = Date.parse(b);
  if (/^\d{4}-\d\d-\d\d/.test(String(a)) && /^\d{4}-\d\d-\d\d/.test(String(b)) && !isNaN(da) && !isNaN(dbb)) return da - dbb;
  return String(a) < String(b) ? -1 : String(a) > String(b) ? 1 : 0;
}
/* split "a,and(b,c),d" at top-level commas */
function splitTop(s) {
  const out = []; let depth = 0, q = false, cur = "";
  for (const ch of s) {
    if (ch === '"') q = !q;
    if (!q && ch === "(") depth++;
    if (!q && ch === ")") depth--;
    if (!q && depth === 0 && ch === ",") { out.push(cur); cur = ""; continue; }
    cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}
function orTerm(t) {
  t = t.trim();
  const m = /^(and|or)\((.*)\)$/.exec(t);
  if (m) { const parts = splitTop(m[2]).map(orTerm); return m[1] === "and" ? (r => parts.every(p => p(r))) : (r => parts.some(p => p(r))); }
  const i = t.indexOf("."), j = t.indexOf(".", i + 1);
  const col = t.slice(0, i), op = t.slice(i + 1, j), val = unquote(t.slice(j + 1));
  return r => test(r[col], op, val);
}
function test(v, op, x) {
  switch (op) {
    case "eq": return v !== null && v !== undefined && String(v) === String(x);
    case "neq": return v !== null && v !== undefined && String(v) !== String(x);
    case "lt": return cmp(v, x) < 0;
    case "lte": return cmp(v, x) <= 0;
    case "gt": return cmp(v, x) > 0;
    case "gte": return cmp(v, x) >= 0;
    default: throw new Error("memDb: no operator " + op);
  }
}
function pick(row, cols) {
  if (!cols || cols === "*") return Object.assign({}, row);
  const out = {};
  cols.split(",").map(c => c.trim()).filter(Boolean).forEach(c => { out[c] = row[c] === undefined ? null : row[c]; });
  return out;
}

function memDb(seed, opts) {
  opts = opts || {};
  const t = {};
  Object.keys(seed || {}).forEach(k => { t[k] = (seed[k] || []).map(r => Object.assign({}, r)); });
  const log = [];
  const fails = [];
  let clock = 0;
  const stamp = () => opts.now ? opts.now() : new Date(Date.UTC(2026, 10, 20, 12, 0, 0) + (clock++)).toISOString();

  function bump(table, row, d) {
    const col = COUNTERS[table];
    if (!col || !t.posts) return;
    const p = t.posts.find(x => x.id === row.post_id);
    if (p) p[col] = Math.max(0, (Number(p[col]) || 0) + d);
  }
  function keyOf(table, row) { return KEYS[table] ? KEYS[table].map(k => String(row[k])).join("|") : null; }

  function from(table) {
    if (!t[table]) t[table] = [];
    const q = { table, op: "select", cols: null, returning: undefined, payload: null, opts: null, filters: [], preds: [], order: [], lim: null, from: 0, head: false, count: null };
    log.push(q);
    const b = {};
    const add = (name, args, pred) => { q.filters.push([name].concat(args)); q.preds.push(pred); return b; };
    b.eq = (c, v) => add("eq", [c, v], r => test(r[c], "eq", v));
    b.neq = (c, v) => add("neq", [c, v], r => test(r[c], "neq", v));
    b.lt = (c, v) => add("lt", [c, v], r => test(r[c], "lt", v));
    b.lte = (c, v) => add("lte", [c, v], r => test(r[c], "lte", v));
    b.gt = (c, v) => add("gt", [c, v], r => test(r[c], "gt", v));
    b.gte = (c, v) => add("gte", [c, v], r => test(r[c], "gte", v));
    b.in = (c, list) => add("in", [c, list], r => (list || []).map(String).indexOf(String(r[c])) !== -1);
    b.is = (c, v) => add("is", [c, v], r => v === null ? (r[c] === null || r[c] === undefined) : r[c] === v);
    b.not = (c, op, v) => add("not", [c, op, v], r => op === "is" && v === null ? !(r[c] === null || r[c] === undefined) : !test(r[c], op, v));
    b.ilike = (c, v) => add("ilike", [c, v], r => r[c] !== null && r[c] !== undefined && new RegExp("^" + String(v).replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/%/g, ".*") + "$", "i").test(String(r[c])));
    b.or = (s) => add("or", [s], (() => { const parts = splitTop(s).map(orTerm); return r => parts.some(p => p(r)); })());
    b.order = (c, o) => { q.order.push([c, !(o && o.ascending === false)]); return b; };
    b.limit = (n) => { q.lim = n; return b; };
    b.range = (a, z) => { q.from = a; q.lim = z - a + 1; return b; };
    b.select = (cols, o) => {
      if (q.op === "select") { q.cols = cols; if (o && o.head) q.head = true; if (o && o.count) q.count = o.count; }
      else q.returning = cols || "*";
      return b;
    };
    ["insert", "update", "upsert", "delete"].forEach(m => { b[m] = (p, o) => { q.op = m; q.payload = p; q.opts = o || null; return b; }; });
    function matching() { return t[table].filter(r => q.preds.every(p => p(r))); }
    function sorted(rows) {
      rows = rows.slice();
      if (q.order.length) rows.sort((a, z) => { for (const [c, asc] of q.order) { const d = cmp(a[c], z[c]); if (d) return asc ? d : -d; if (isNaN(d)) { const an = a[c] == null, zn = z[c] == null; if (an !== zn) return an ? 1 : -1; } } return 0; });
      return rows.slice(q.from, q.lim === null ? undefined : q.from + q.lim);
    }
    function run() {
      const fi = fails.findIndex(f => f.table === table && (f.op === q.op || f.op === "*"));
      if (fi !== -1) { const f = fails.splice(fi, 1)[0]; return { data: null, error: f.error || { code: "XX000", message: "memDb: refused " + table + " " + q.op }, count: null }; }
      if (q.op === "select") {
        const all = matching();
        if (q.head) return { data: null, error: null, count: all.length };
        return { data: sorted(all).map(r => pick(r, q.cols)), error: null, count: q.count ? all.length : null };
      }
      if (q.op === "insert" || q.op === "upsert") {
        const rows = (Array.isArray(q.payload) ? q.payload : [q.payload]).map(r => Object.assign({}, r));
        const written = [];
        for (const r of rows) {
          if (!NO_ID.has(table) && !r.id) r.id = crypto.randomUUID();
          if (!r.created_at && table !== "post_media") r.created_at = stamp();
          if (table === "posts") ["like_count", "comment_count", "save_count", "share_count"].forEach(c => { if (r[c] === undefined) r[c] = 0; });
          const k = keyOf(table, r);
          const clash = k !== null ? t[table].find(x => keyOf(table, x) === k) : (r.id ? t[table].find(x => x.id === r.id) : null);
          if (clash) {
            if (q.op === "upsert" && q.opts && q.opts.ignoreDuplicates) continue;
            if (q.op === "upsert") { Object.assign(clash, r); written.push(clash); continue; }
            return { data: null, error: { code: "23505", message: "duplicate key value violates unique constraint" } };
          }
          t[table].push(r); written.push(r); bump(table, r, 1);
        }
        return { data: q.returning !== undefined ? written.map(r => pick(r, q.returning)) : null, error: null };
      }
      if (q.op === "update") {
        const rows = matching();
        rows.forEach(r => Object.assign(r, q.payload));
        return { data: q.returning !== undefined ? rows.map(r => pick(r, q.returning)) : null, error: null };
      }
      if (q.op === "delete") {
        const rows = matching();
        t[table] = t[table].filter(r => rows.indexOf(r) === -1);
        rows.forEach(r => bump(table, r, -1));
        return { data: q.returning !== undefined ? rows.map(r => pick(r, q.returning)) : null, error: null };
      }
      throw new Error("memDb: no op " + q.op);
    }
    function one(strict) {
      const r = run();
      if (r.error) return Promise.resolve(r);
      const list = r.data || [];
      if (list.length > 1) return Promise.resolve({ data: null, error: { code: "PGRST116", message: "more than one row" } });
      if (!list.length && strict) return Promise.resolve({ data: null, error: { code: "PGRST116", message: "no rows" } });
      return Promise.resolve({ data: list[0] || null, error: null });
    }
    b.single = () => one(true);
    b.maybeSingle = () => one(false);
    b.then = (res, rej) => Promise.resolve().then(run).then(res, rej);
    return b;
  }
  return {
    t, log,
    client: { from },
    failOn(table, op, error) { fails.push({ table, op, error }); },
    writes() { return log.filter(q => q.op !== "select"); },
    clearLog() { log.length = 0; }
  };
}

module.exports = { memDb, splitTop };
