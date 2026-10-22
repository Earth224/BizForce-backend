/* ══════════════════════════════════════════════════════════════════════════
   checkAccountFiles — deleting an account deletes the member's uploaded
   files, except files another member bought, and a file Storage refuses is
   queued, retried daily and alerted on, never dropped.

   Runs lib/accountFiles.js and lib/yourData.js, with POST /api/me/delete and
   GET /api/purchases/:orderId/download lifted out of server.js, against
   in-memory tables and an in-memory Storage. No network, no database, no
   bucket.

     I. Inventory. Every file is found, through every kind of record (a
        bf-public URL in a column, inside JSON, inside text, URL-encoded; a
        bare bf-books or bf-digital-goods path in a column, in JSON text, in a
        design object, in book content) and through the member's folders
        alone (orphans, nested folders, more than one page of a listing).
    II. The delete. Every one of those files is removed; the files of
        listings another member bought are kept and each buyer can still
        download theirs (with and without the order's snapshot); another
        member's files are never touched, including a member whose id
        begins with this member's ("abc" and "abcd"); removal is in batches;
        the answer counts what was deleted, queued and kept.
   III. Failures. A batch Storage refuses (an error, or a throw) is queued;
        the daily retry is claimed once a day in job_runs, counts attempts,
        raises ONE alert at the fifth, keeps trying, and empties the queue
        when Storage recovers. A queue that cannot be written is logged and
        alerted, never silent. A folder that cannot be listed deletes
        nothing. A delete that stops part-way removes no file, and the retry
        finishes the files too.
    IV. The wiring and the words: the route passes Storage, the retry is a
        04:15 UTC cron with no boot-time run, migration 144 makes the queue,
        and the delete note says what happens.

   MUTATE=<name> applies one mutation and must fail; MUTATE=all runs each.
   ══════════════════════════════════════════════════════════════════════════ */
"use strict";

const fs = require("fs");
const path = require("path");
const Module = require("module");
const MUT = require("./_shared");
const { braceMatch } = MUT;
const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");

const MUTATIONS = ["purchased-file-deleted", "sold-listing-deleted", "prefix-without-slash", "failure-dropped",
  "retry-never-alerts", "retry-alerts-every-pass", "files-read-after-rows"];
const MUTATE = process.env.MUTATE || "";
if (MUTATE === "all") MUT.runAllMutations(__filename, MUTATIONS);
if (MUTATE && MUTATIONS.indexOf(MUTATE) === -1) {
  console.error("Unknown MUTATE=" + MUTATE + ". Known: " + MUTATIONS.join(", "));
  process.exit(2);
}

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

const lf = s => s.replace(/\r\n/g, "\n");
const read = rel => lf(fs.readFileSync(path.join(REPO, rel), "utf8"));
let FILES = read("lib/accountFiles.js");
let LIB = read("lib/yourData.js");
const SERVER = read("server.js");
const PAGE = lf(fs.readFileSync(path.join(FRONTEND, "your-data.html"), "utf8"));

if (MUTATE === "purchased-file-deleted") FILES = MUT.replaceOnce(FILES, "return owned.filter(function (f) { return !keepIds[fileId(f)]; });", "return owned;", MUTATE);
if (MUTATE === "sold-listing-deleted") LIB = MUT.replaceOnce(LIB, "var unsold = mine.filter(function (id) { return sold.indexOf(id) === -1; });", "var unsold = mine;", MUTATE);
if (MUTATE === "prefix-without-slash") FILES = MUT.replaceOnce(FILES, "key.indexOf(prefix + \"/\") === 0", "key.indexOf(prefix) === 0", MUTATE);
if (MUTATE === "failure-dropped") FILES = MUT.replaceOnce(FILES, "var q = await queue(supabase, batch.map(function (p) { return { bucket: bucket, path: p }; }), error, nowIso);",
  "var q = { queued: batch.length, error: null };", MUTATE);
if (MUTATE === "retry-never-alerts") FILES = MUT.replaceOnce(FILES, "if (attempts === ALERT_AT) stuck.push(", "if (false) stuck.push(", MUTATE);
if (MUTATE === "retry-alerts-every-pass") FILES = MUT.replaceOnce(FILES, "if (attempts === ALERT_AT) stuck.push(", "if (attempts >= ALERT_AT) stuck.push(", MUTATE);
// The inventory taken after the rows are gone: only the folders are left to find files by.
if (MUTATE === "files-read-after-rows") LIB = MUT.replaceOnce(LIB, "    done.push(\"users emptied\");\n",
  "    done.push(\"users emptied\");\n    files = accountFiles.toRemove(await accountFiles.filesOwnedBy({ supabase: supabase, storage: opts.storage, userId: userId, publicUrlBase: opts.publicUrlBase }), keep);\n", MUTATE);

/* A module from (possibly mutated) source, resolving its requires from its real
   path; `cache` puts it where a sibling's require() finds it. */
function loadFrom(rel, src, cache) {
  const file = path.join(REPO, rel);
  const m = new Module(file, module);
  m.filename = file;
  m.paths = Module._nodeModulePaths(path.dirname(file));
  if (cache) { require.cache[file] = m; }
  m._compile(src, file);
  m.loaded = true;
  return m.exports;
}
function handlerSource(src, sig) {
  const start = src.indexOf(sig);
  if (start === -1) throw new Error("route " + sig + " was not found in server.js");
  const lineEnd = src.indexOf("\n", start);
  let fnAt = src.indexOf("function (req, res", start);
  if (fnAt === -1 || fnAt > lineEnd) throw new Error("route " + sig + " has no handler on its first line");
  if (src.slice(fnAt - 6, fnAt) === "async ") fnAt -= 6;
  const end = braceMatch(src, src.indexOf("{", fnAt));
  return src.slice(fnAt, end);
}
function runRoute(handlerSrc, deps) {
  const names = Object.keys(deps);
  return new Function(...names, "return (" + handlerSrc + ");")(...names.map(n => deps[n]));
}
function fakeRes() {
  return { statusCode: 200, body: undefined, status(c) { this.statusCode = c; return this; }, json(b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
}

// ── in-memory tables: the parts of PostgREST the code uses ───────────────────
const UNIQUE = { job_runs: ["job_name"], pending_storage_deletions: ["bucket", "path"] };
function makeDb(tables) {
  const db = { tables: tables, failOn: null, seq: 0, writes: 0, log: [] };
  const rowsOf = t => db.tables[t] || (db.tables[t] = []);
  function test(row, f) {
    const v = row[f.col] === undefined ? null : row[f.col];
    if (f.op === "eq") return v === f.val;
    if (f.op === "neq") return v !== null && v !== f.val;
    if (f.op === "in") return f.val.indexOf(v) !== -1;
    if (f.op === "is") return v === f.val;
    if (f.op === "or") return f.any.some(g => test(row, g));
    return false;
  }
  function clash(table, row) {
    const keys = UNIQUE[table];
    return keys ? rowsOf(table).find(r => keys.every(k => r[k] === row[k])) : null;
  }
  function query(table) {
    const q = { op: "select", filters: [], from: null, to: null, single: false, rows: null, patch: null, upsert: null, returning: false };
    const api = {
      select() { if (q.op !== "select") q.returning = true; return api; },
      insert(rows) { q.op = "insert"; q.rows = [].concat(rows); return api; },
      upsert(rows, o) { q.op = "upsert"; q.rows = [].concat(rows); q.upsert = o || {}; return api; },
      update(patch) { q.op = "update"; q.patch = patch; return api; },
      delete() { q.op = "delete"; return api; },
      eq(c, v) { q.filters.push({ op: "eq", col: c, val: v }); return api; },
      in(c, v) { q.filters.push({ op: "in", col: c, val: v }); return api; },
      is(c, v) { q.filters.push({ op: "is", col: c, val: v }); return api; },
      or(text) {
        q.filters.push({ op: "or", any: text.split(",").map(function (part) {
          const m = /^(\w+)\.(is|eq|neq)\.(.*)$/.exec(part);
          return { op: m[2], col: m[1], val: m[2] === "is" && m[3] === "null" ? null : m[3] };
        }) });
        return api;
      },
      order() { return api; },
      range(a, b) { q.from = a; q.to = b; return api; },
      limit(n) { q.from = 0; q.to = n - 1; return api; },
      maybeSingle() { q.single = true; return api; },
      then(resolve, reject) { return Promise.resolve().then(run).then(resolve, reject); }
    };
    function run() {
      db.log.push(table + ":" + q.op);
      if (db.failOn) { const e = db.failOn(table, q.op); if (e) return { data: null, error: { message: e } }; }
      const all = rowsOf(table);
      const hit = all.filter(r => q.filters.every(f => test(r, f)));
      if (q.op === "select") {
        let data = hit.map(r => Object.assign({}, r));
        if (q.from !== null) data = data.slice(q.from, q.to + 1);
        if (q.single) return { data: data[0] || null, error: null };
        return { data: data, error: null };
      }
      db.writes++;
      if (q.op === "insert") {
        for (const r of q.rows) if (clash(table, r)) return { data: null, error: { code: "23505", message: "duplicate key value violates unique constraint" } };
        q.rows.forEach(r => all.push(Object.assign({ id: table + "-" + (++db.seq) }, r)));
        return { data: q.returning ? q.rows.map(r => Object.assign({}, r)) : null, error: null };
      }
      if (q.op === "upsert") {
        q.rows.forEach(function (r) {
          const old = clash(table, r);
          if (old) { if (!q.upsert.ignoreDuplicates) Object.assign(old, r); }
          else all.push(Object.assign({ id: table + "-" + (++db.seq) }, r));
        });
        return { data: null, error: null };
      }
      if (q.op === "update") { hit.forEach(r => Object.assign(r, q.patch)); return { data: q.returning ? hit.map(r => Object.assign({}, r)) : null, error: null }; }
      if (q.op === "delete") { db.tables[table] = all.filter(r => hit.indexOf(r) === -1); return { data: null, error: null }; }
      return { data: null, error: { message: "unsupported" } };
    }
    return api;
  }
  db.client = { from: query, async rpc() { return { data: null, error: { message: "no rpc here" } }; } };
  db.rows = rowsOf;
  return db;
}

// ── in-memory Storage ────────────────────────────────────────────────────────
function makeStorage(files) {
  const st = { files: {}, removeCalls: [], failRemove: null, failList: null };
  Object.keys(files).forEach(b => { st.files[b] = new Set(files[b]); });
  const keys = b => st.files[b] || (st.files[b] = new Set());
  st.client = {
    from(bucket) {
      return {
        async list(prefix, o) {
          if (st.failList) { const e = st.failList(bucket, prefix); if (e) return { data: null, error: { message: e } }; }
          const pre = prefix ? prefix + "/" : "", seen = {}, out = [];
          [...keys(bucket)].filter(k => k.indexOf(pre) === 0).forEach(function (k) {
            const rest = k.slice(pre.length), slash = rest.indexOf("/");
            const name = slash === -1 ? rest : rest.slice(0, slash);
            if (seen[name]) return;
            seen[name] = true;
            out.push({ name: name, id: slash === -1 ? "obj:" + k : null });
          });
          out.sort((x, y) => x.name < y.name ? -1 : 1);
          const off = (o && o.offset) || 0, lim = (o && o.limit) || 100;
          return { data: out.slice(off, off + lim), error: null };
        },
        async remove(paths) {
          st.removeCalls.push({ bucket: bucket, n: paths.length });
          if (st.failRemove) {
            const e = st.failRemove(bucket, paths);
            if (e === "throw") throw new Error("socket hang up");
            if (e) return { data: null, error: { message: e } };
          }
          const gone = paths.filter(k => keys(bucket).has(k));
          gone.forEach(k => keys(bucket).delete(k));
          return { data: gone.map(k => ({ name: k })), error: null };
        },
        async createSignedUrl(p) {
          return keys(bucket).has(p) ? { data: { signedUrl: "https://signed.example/" + bucket + "/" + p }, error: null } : { data: null, error: { message: "Object not found" } };
        }
      };
    }
  };
  st.all = () => [].concat(...Object.keys(st.files).map(b => [...st.files[b]].map(k => b + "/" + k))).sort();
  return st;
}

(async function main() {
  const AF = loadFrom("lib/accountFiles.js", FILES, true);
  const YD = loadFrom("lib/yourData.js", LIB, false);
  const BASE = "https://proj-ref.supabase.co";
  process.env.SUPABASE_URL = BASE;
  const url = key => BASE + "/storage/v1/object/public/bf-public/" + encodeURI(key);

  const A = "aaaaaaaa-0000-4000-8000-00000000000a";    // the member deleting
  const L = A + "d";                                   // another member whose id begins with A's
  const B = "bbbbbbbb-0000-4000-8000-00000000000b";    // another member, who bought from A
  const HASH = "HASH-A";

  /* What A owns and must lose, by how it is found. */
  const DEL = {
    "bf-public": ["avatars/" + A + "/user.png", "avatars/" + A + "/profile.png", "banners/" + A + "/banner.png", "avatars/" + A + "/bfp.png",
      "products/" + A + "/p.png", "portfolio/" + A + "/q.png", "music/" + A + "/song.mp3", "music-art/" + A + "/art.png", "videos/" + A + "/clip.mp4",
      "music/" + A + "/track.mp3", "videos/" + A + "/v.mp4", "card-media/" + A + "/bg.png", "card-media/" + A + "/layout.png",
      "products/" + A + "/in text.png", "marketplace-media/" + A + "/camp.png", "marketplace-media/" + A + "/unsold.png",
      "custom/sub/" + A + "/nested.png", "music/" + A + "/orphan.mp3"],
    "bf-books": [A + "/book.pdf", A + "/book.epub", A + "/cover.png", A + "/wrap_1_bg.png", A + "/editorimg_1.png",
      A + "/wrap_2_bg.png", A + "/wrap_2_region.png", A + "/wrap_2_layer.png", A + "/sub/deep.png", A + "/orphan.pdf"],
    "bf-digital-goods": [A + "/unsold.zip", A + "/orphan.zip"]
  };
  for (let i = 0; i < 1200; i++) DEL["bf-books"].push(A + "/bulk/" + String(i).padStart(4, "0") + ".png");
  /* Recorded only, in a row: the folder alone would not find them (or they are in no folder listing). */
  const RECORD_ONLY = ["bf-public/custom/sub/" + A + "/nested.png"];
  /* Found only through the member's folders. */
  const FOLDER_ONLY = ["bf-public/music/" + A + "/orphan.mp3", "bf-books/" + A + "/sub/deep.png", "bf-books/" + A + "/orphan.pdf", "bf-digital-goods/" + A + "/orphan.zip"];
  /* A's, but bought by B. */
  const KEEP = { "bf-public": ["marketplace-media/" + A + "/sold-cover.png"], "bf-digital-goods": [A + "/sold.pdf", A + "/sold2.pdf"] };
  /* Other members'. */
  const OTHERS = { "bf-public": ["avatars/" + B + "/me.png", "avatars/" + L + "/me.png", "marketplace-media/" + B + "/ebook.png"],
    "bf-books": [B + "/book.pdf", L + "/book.pdf"], "bf-digital-goods": [B + "/ebook.pdf", L + "/x.zip"] };
  const flat = m => [].concat(...Object.keys(m).map(b => m[b].map(k => b + "/" + k))).sort();

  function seedTables() {
    const t = {};
    const put = (table, row) => (t[table] = t[table] || []).push(row);
    put("users", { id: A, email: "alice+bftest@bizforceai.invalid", role: "user", password_hash: HASH, avatar_url: url("avatars/" + A + "/user.png") });
    put("users", { id: B, email: "bob+bftest@bizforceai.invalid", role: "user", password_hash: "HASH-B", avatar_url: url("avatars/" + B + "/me.png") });
    put("users", { id: L, email: "lou+bftest@bizforceai.invalid", role: "user", password_hash: "HASH-L", avatar_url: url("avatars/" + L + "/me.png") });
    put("profiles", { id: "profiles-A", user_id: A, username: "alice", logo_url: url("avatars/" + A + "/profile.png"), banner_url: url("banners/" + A + "/banner.png") });
    put("profiles", { id: "profiles-L", user_id: L, username: "lou", logo_url: url("avatars/" + L + "/me.png") });
    put("bf_profiles", { id: "bf_profiles-A", user_id: A, username: "alice", avatar_url: url("avatars/" + A + "/bfp.png") });
    put("profile_products", { id: "pp-A", user_id: A, image_url: url("products/" + A + "/p.png") });
    put("profile_portfolio", { id: "pf-A", user_id: A, image_url: url("portfolio/" + A + "/q.png") });
    // A's portfolio shows lou's and bob's pictures: theirs, never A's to delete
    put("profile_portfolio", { id: "pf-A-borrowed", user_id: A, image_url: url("avatars/" + L + "/me.png"), caption: "see " + url("avatars/" + B + "/me.png") });
    put("profile_music", { id: "pm-A", user_id: A, audio_url: url("music/" + A + "/song.mp3"), cover_url: url("music-art/" + A + "/art.png") });
    put("profile_videos", { id: "pv-A", user_id: A, video_url: url("videos/" + A + "/clip.mp4") });
    put("bf_music_tracks", { id: "mt-A", user_id: A, audio_url: url("music/" + A + "/track.mp3") });
    put("bf_videos", { id: "v-A", user_id: A, video_url: url("videos/" + A + "/v.mp4"), thumbnail_url: url("custom/sub/" + A + "/nested.png") });
    put("digital_cards", { id: "dc-A", user_id: A, bg_image_url: url("card-media/" + A + "/bg.png"), still_image_url: url("avatars/" + B + "/me.png"),
      media_layout: { slots: [{ src: url("card-media/" + A + "/layout.png") }] } });
    put("content_library", { id: "cl-A", user_id: A, body: "<p>Look</p><img src=\"" + url("products/" + A + "/in text.png") + "\"> and <a href='" + url("avatars/" + L + "/me.png") + "'>lou</a>" });
    put("crowdfunding_campaigns", { id: "cc-A", owner_id: A, media: [{ type: "image", url: url("marketplace-media/" + A + "/camp.png") }] });
    put("bizbooks", { id: "bb-A", owner_id: A, storage_path: A + "/book.pdf", storage_path_epub: A + "/book.epub", cover_path: A + "/cover.png",
      cover_design: JSON.stringify({ bgImage: A + "/wrap_1_bg.png", ref: L + "/book.pdf" }), content: [{ type: "image", path: A + "/editorimg_1.png" }, { type: "text", text: B + "/book.pdf" }] });
    put("cover_wraps", { id: "cw-A", owner_id: A, front_design: { bgImage: A + "/wrap_2_bg.png", regions: [{ bgImage: A + "/wrap_2_region.png" }], layers: [{ src: A + "/wrap_2_layer.png" }] } });
    // listings: S bought by B (with the order's snapshot), S2 bought by B before migration 113 (no snapshot), U bought by nobody
    put("marketplace_listings", { id: "S", seller_id: A, status: "active", digital_file_path: A + "/sold.pdf", digital_file_name: "Guide.pdf", media: [{ url: url("marketplace-media/" + A + "/sold-cover.png") }] });
    put("marketplace_listings", { id: "S2", seller_id: A, status: "sold", digital_file_path: A + "/sold2.pdf", digital_file_name: "Old guide.pdf" });
    put("marketplace_listings", { id: "U", seller_id: A, status: "active", digital_file_path: A + "/unsold.zip", preview: L + "/x.zip", media: [{ url: url("marketplace-media/" + A + "/unsold.png") }] });
    put("marketplace_listings", { id: "LB", seller_id: B, status: "active", digital_file_path: B + "/ebook.pdf", media: [{ url: url("marketplace-media/" + B + "/ebook.png") }] });
    put("marketplace_orders", { id: "O1", buyer_id: B, seller_id: A, listing_id: "S", is_digital: true, digital_file_path: A + "/sold.pdf", digital_file_name: "Guide.pdf" });
    put("marketplace_orders", { id: "O2", buyer_id: B, seller_id: A, listing_id: "S2", is_digital: true });
    put("marketplace_orders", { id: "O3", buyer_id: A, seller_id: B, listing_id: "LB", is_digital: true, digital_file_path: B + "/ebook.pdf" });
    put("subscriptions", { id: "sub-A", user_id: A, status: "canceled" });
    return t;
  }
  function seedFiles() {
    const all = {};
    [DEL, KEEP, OTHERS].forEach(m => Object.keys(m).forEach(b => { all[b] = (all[b] || []).concat(m[b]); }));
    return all;
  }
  const alertsLog = [];
  const ALERTS = {
    storageDeletionStuck: async info => { alertsLog.push({ kind: "stuck", info: info }); return { sent: true }; },
    storageDeletionUnqueued: async info => { alertsLog.push({ kind: "unqueued", info: info }); return { sent: true }; }
  };
  const DELETE_SIG = "app.post(\"/api/me/delete\"";
  const DOWNLOAD_SIG = "app.get(\"/api/purchases/:orderId/download\"";
  async function doDelete(db, st, body) {
    const lines = [];
    const h = runRoute(handlerSource(SERVER, DELETE_SIG), { yourData: YD, supabase: Object.assign({}, db.client, { storage: st.client }),
      console: { log: m => lines.push(["log", String(m)]), error: m => lines.push(["error", String(m)]) },
      bcrypt: { compare: async (p, h2) => p === "pw" && h2 === HASH }, getActiveSubscriptions: async () => [], OWNER_ACCOUNT_ID: "none", opsAlerts: ALERTS });
    const res = fakeRes();
    await h({ user: { id: A }, body: body || { username: "alice", password: "pw" } }, res);
    return { status: res.statusCode, body: res.body || {}, lines: lines };
  }
  async function download(db, st, orderId, uid) {
    const h = runRoute(handlerSource(SERVER, DOWNLOAD_SIG), { supabase: Object.assign({}, db.client, { storage: st.client }), console: { log() {}, error() {} } });
    const res = fakeRes(); let err = null;
    await h({ user: { id: uid }, params: { orderId: orderId } }, res, e => { err = e; });
    return { status: err ? 500 : res.statusCode, body: res.body || {} };
  }
  const sameList = (x, y) => JSON.stringify(x.slice().sort()) === JSON.stringify(y.slice().sort());

  // ════ I. the inventory ════
  console.log("\n══ I. every file the member owns is found, and nothing else ══");
  {
    const db = makeDb(seedTables()), st = makeStorage(seedFiles());
    const owned = await AF.filesOwnedBy({ supabase: db.client, storage: st.client, userId: A, publicUrlBase: BASE });
    const ids = owned.map(f => f.bucket + "/" + f.path);
    const want = flat(DEL).concat(flat(KEEP));
    const missing = want.filter(k => ids.indexOf(k) === -1), extra = ids.filter(k => want.indexOf(k) === -1);
    check("I1. every file of A's is found: " + want.length + " across the three buckets", missing.length === 0, "missing: " + missing.slice(0, 5).join(", "));
    check("I2. and nothing that is not A's: not bob's, not lou's (whose id begins with A's), though A's rows point at them", extra.length === 0, "extra: " + extra.join(", "));
    check("I3. each file once", new Set(ids).size === ids.length, ids.length + " listed, " + new Set(ids).size + " distinct");
    check("I4. each with its bucket and why it is A's", owned.every(f => ["bf-public", "bf-books", "bf-digital-goods"].indexOf(f.bucket) !== -1 && /^(recorded in \w+|in bf-[\w-]+ under )/.test(f.reason)));
    const why = k => (owned.find(f => f.bucket + "/" + f.path === k) || {}).reason || "";
    const byRecord = {
      "users": "bf-public/avatars/" + A + "/user.png", "profiles": "bf-public/banners/" + A + "/banner.png", "bf_profiles": "bf-public/avatars/" + A + "/bfp.png",
      "profile_products": "bf-public/products/" + A + "/p.png", "profile_portfolio": "bf-public/portfolio/" + A + "/q.png", "profile_music": "bf-public/music-art/" + A + "/art.png",
      "profile_videos": "bf-public/videos/" + A + "/clip.mp4", "bf_music_tracks": "bf-public/music/" + A + "/track.mp3", "bf_videos": "bf-public/custom/sub/" + A + "/nested.png",
      "digital_cards": "bf-public/card-media/" + A + "/layout.png", "content_library": "bf-public/products/" + A + "/in text.png",
      "crowdfunding_campaigns": "bf-public/marketplace-media/" + A + "/camp.png", "bizbooks": "bf-books/" + A + "/editorimg_1.png",
      "cover_wraps": "bf-books/" + A + "/wrap_2_layer.png", "marketplace_listings": "bf-digital-goods/" + A + "/unsold.zip"
    };
    const wrongWhy = Object.keys(byRecord).filter(t => why(byRecord[t]) !== "recorded in " + t);
    check("I5. found through each kind of record: a URL in a column, in JSON, in HTML text, URL-encoded; a bare path in a column, in JSON text, in a design object, in book content",
      wrongWhy.length === 0 && AF.FILE_TABLES.every(t => byRecord[t.table]), "wrong: " + wrongWhy.map(t => t + "=" + why(byRecord[t])).join("; "));
    check("I6. found through A's folders alone: orphans no row records, a nested folder, and more than one page of a listing (1,200 in one folder)",
      FOLDER_ONLY.every(k => /^in bf-/.test(why(k))) && ids.filter(k => k.indexOf("bf-books/" + A + "/bulk/") === 0).length === 1200, FOLDER_ONLY.map(why).join(" | "));
    check("I7. the one-folder guard: \"abc\" owns \"abc/x\", never \"abcd/x\"", AF.keyUnder(A + "/x", A) && !AF.keyUnder(L + "/x", A) && !AF.keyUnder(A, A) &&
      AF.publicKeyOwned("avatars/" + A + "/x", A) && !AF.publicKeyOwned("avatars/" + L + "/x", A) && !AF.publicKeyOwned(A + "/avatars/x", A));
    check("I8. a URL on another host that mimics the storage path is not ours", AF.publicUrlToKey("https://evil.example/storage/v1/object/public/bf-public/avatars/" + A + "/x.png", "proj-ref.supabase.co") === null &&
      AF.publicUrlToKey(url("avatars/" + A + "/x.png"), "proj-ref.supabase.co") === "avatars/" + A + "/x.png");
    const kept = await AF.keptForBuyers({ supabase: db.client, userId: A, publicUrlBase: BASE });
    check("I9. kept for buyers, per bucket: the files of the two listings bob bought and that listing's picture; nothing of the unsold listing; bob's purchase from A changes nothing",
      sameList(kept.files.map(f => f.bucket + "/" + f.path), flat(KEEP)) && sameList(kept.listings, ["S", "S2"]) && kept.orders === 2, JSON.stringify(kept.files.map(f => f.path)));
    check("I10. reading changed nothing", db.writes === 0 && st.removeCalls.length === 0);
  }

  // ════ II. the delete ════
  console.log("\n══ II. the delete removes A's files, keeps what bob bought, touches no one else's ══");
  {
    const db = makeDb(seedTables()), st = makeStorage(seedFiles());
    const before = await download(db, st, "O2", B);
    const r = await doDelete(db, st);
    check("II1. the delete succeeds", r.status === 200 && r.body.deleted === true, r.status + " " + JSON.stringify(r.body).slice(0, 300));
    const left = st.all();
    const stillThere = flat(DEL).filter(k => left.indexOf(k) !== -1);
    check("II2. every one of A's " + flat(DEL).length + " files is deleted, whichever way it was found", stillThere.length === 0, stillThere.slice(0, 5).join(", "));
    check("II3. ... including those only a row records and those only a folder holds", RECORD_ONLY.concat(FOLDER_ONLY).every(k => left.indexOf(k) === -1));
    check("II4. the files bob bought are kept", flat(KEEP).every(k => left.indexOf(k) !== -1), flat(KEEP).filter(k => left.indexOf(k) === -1).join(", "));
    check("II5. no other member's file is touched: bob's, and lou's whose id begins with A's", flat(OTHERS).every(k => left.indexOf(k) !== -1) && left.length === flat(KEEP).length + flat(OTHERS).length,
      flat(OTHERS).filter(k => left.indexOf(k) === -1).join(", "));
    const d1 = await download(db, st, "O1", B), d2 = await download(db, st, "O2", B);
    check("II6. bob can still download both: through the order's snapshot, and through the kept listing for the order that has none",
      d1.status === 200 && d1.body.url === "https://signed.example/bf-digital-goods/" + A + "/sold.pdf" && d2.status === 200 && d2.body.url === "https://signed.example/bf-digital-goods/" + A + "/sold2.pdf" &&
      before.status === 200, d1.status + " " + d2.status + " " + JSON.stringify(d2.body));
    const T = db.tables;
    const S = T.marketplace_listings.find(l => l.id === "S"), S2 = T.marketplace_listings.find(l => l.id === "S2");
    check("II7. the listings bob bought are kept off sale (S paused, S2 still sold); the unsold one is deleted; bob's own listing is untouched",
      S && S.status === "paused" && S2 && S2.status === "sold" && !T.marketplace_listings.some(l => l.id === "U") && T.marketplace_listings.some(l => l.id === "LB" && l.status === "active"));
    const o1 = T.marketplace_orders.find(o => o.id === "O1");
    check("II8. the orders are kept as they were, and A is a deleted member", T.marketplace_orders.length === 3 && o1.seller_id === A && T.users.find(u => u.id === A).role === "deleted");
    check("II9. the answer counts them: deleted, queued, kept for buyers", JSON.stringify(r.body.files) === JSON.stringify({ deleted: flat(DEL).length, queued: 0, kept_for_buyers: flat(KEEP).length, not_queued: 0 }),
      JSON.stringify(r.body.files));
    check("II10. removal is in batches of " + AF.REMOVE_BATCH + " per bucket, never one bucket's call for another's files",
      st.removeCalls.every(c => c.n <= AF.REMOVE_BATCH) && st.removeCalls.filter(c => c.bucket === "bf-books").length === Math.ceil(DEL["bf-books"].length / AF.REMOVE_BATCH), JSON.stringify(st.removeCalls.slice(0, 3)));
    check("II11. the log line carries the counts", r.lines.some(l => l[0] === "log" && new RegExp("status=200 reason=deleted files deleted=" + flat(DEL).length + " queued=0 kept_for_buyers=3 not_queued=0").test(l[1])));
    check("II12. nothing is queued when Storage removes everything", (T.pending_storage_deletions || []).length === 0);
    check("II13. the files are removed after the rows: no remove() until the account row is emptied",
      db.log.lastIndexOf("users:update") !== -1 && st.removeCalls.length > 0 && r.body.done.indexOf("users emptied") < r.body.done.findIndex(d => /^files: /.test(d)));
  }

  // ════ III. failures ════
  console.log("\n══ III. a file Storage refuses is queued, retried, alerted once, and removed ══");
  {
    const db = makeDb(seedTables()), st = makeStorage(seedFiles());
    let storageDown = true;
    st.failRemove = (b) => storageDown && b === "bf-public" ? "storage timeout" : null;
    const r = await doDelete(db, st);
    const pub = DEL["bf-public"];
    const q = db.rows("pending_storage_deletions");
    check("III1. the delete still completes; the refused files are queued, each with its bucket, path, one attempt and the error",
      r.status === 200 && q.length === pub.length && sameList(q.map(x => x.path), pub) && q.every(x => x.bucket === "bf-public" && x.attempts === 1 && x.last_error === "storage timeout" && x.created_at),
      r.status + " queued " + q.length);
    check("III2. the answer says how many were deleted and how many are queued", r.body.files.deleted === flat(DEL).length - pub.length && r.body.files.queued === pub.length && r.body.files.not_queued === 0,
      JSON.stringify(r.body.files));
    check("III3. the queued files are still in Storage (nothing pretends they are gone)", pub.every(k => st.files["bf-public"].has(k)));
    alertsLog.length = 0;
    const day = n => new Date(Date.UTC(2026, 9, 22 + n, 4, 15));
    const run = n => AF.runRetryJob({ supabase: db.client, storage: st.client, alerts: ALERTS, now: day(n), log: { log() {}, error() {} } });
    const a1 = await run(1);
    const twice = await run(1);
    check("III4. the retry is claimed once a day in job_runs: a second run the same UTC day does nothing", a1.claimed === true && twice.claimed === false &&
      db.rows("pending_storage_deletions").every(x => x.attempts === 2) && db.rows("job_runs").filter(j => j.job_name === AF.RETRY_JOB_NAME).length === 1);
    await run(2); await run(3);
    check("III5. four failed attempts: no alert yet", alertsLog.length === 0 && db.rows("pending_storage_deletions").every(x => x.attempts === 4));
    const a5 = await run(4);
    check("III6. the fifth failed attempt raises ONE alert naming the stuck files", alertsLog.length === 1 && alertsLog[0].kind === "stuck" && alertsLog[0].info.files.length === pub.length &&
      alertsLog[0].info.attempts === 5 && a5.result.alerted === pub.length, JSON.stringify(alertsLog.map(x => x.kind)));
    await run(5);
    check("III7. it keeps trying after the alert, and does not alert again", alertsLog.length === 1 && db.rows("pending_storage_deletions").every(x => x.attempts === 6 && x.last_attempt_at === day(5).toISOString()));
    storageDown = false;
    const fixed = await run(6);
    check("III8. when Storage recovers, the files go and the queue empties", fixed.result.removed === pub.length && db.rows("pending_storage_deletions").length === 0 && pub.every(k => !st.files["bf-public"].has(k)));
    const jr = db.rows("job_runs").find(j => j.job_name === AF.RETRY_JOB_NAME);
    check("III9. the run is recorded in job_runs, finished, with no error", jr && jr.last_run_on === "2026-10-28" && jr.finished_at && jr.last_error === null, JSON.stringify(jr));
    db.failOn = (t, op) => t === "pending_storage_deletions" && op === "select" ? "relation unavailable" : null;
    const broken = await run(7);
    check("III10. a retry that cannot read the queue records the error in job_runs (the ops scan reads it) and does not throw",
      broken.claimed && /relation unavailable/.test(broken.error) && /relation unavailable/.test(db.rows("job_runs").find(j => j.job_name === AF.RETRY_JOB_NAME).last_error || ""));
  }
  {
    // a throw, not an error result
    const db = makeDb(seedTables()), st = makeStorage(seedFiles());
    st.failRemove = (b) => b === "bf-digital-goods" ? "throw" : null;
    const r = await doDelete(db, st);
    check("III11. a remove() that throws is queued like one that errors", r.status === 200 && r.body.files.queued === DEL["bf-digital-goods"].length &&
      sameList(db.rows("pending_storage_deletions").map(x => x.path), DEL["bf-digital-goods"]) && /socket hang up/.test(db.rows("pending_storage_deletions")[0].last_error));
  }
  {
    // the queue itself cannot be written: logged with the paths, and the owner alerted
    const db = makeDb(seedTables()), st = makeStorage(seedFiles());
    st.failRemove = (b) => b === "bf-digital-goods" ? "storage timeout" : null;
    db.failOn = (t, op) => t === "pending_storage_deletions" && op === "upsert" ? "permission denied" : null;
    alertsLog.length = 0;
    const r = await doDelete(db, st);
    check("III12. files neither removed nor queued are counted, logged with their paths, and alerted, never silent",
      r.status === 200 && r.body.files.not_queued === 2 && r.body.files.queued === 0 &&
      r.lines.some(l => l[0] === "error" && /FILES NOT QUEUED/.test(l[1]) && l[1].indexOf(A + "/orphan.zip") !== -1) &&
      alertsLog.length === 1 && alertsLog[0].kind === "unqueued" && alertsLog[0].info.count === 2, JSON.stringify(r.body.files) + " " + alertsLog.length);
  }
  {
    // a folder that cannot be listed: nothing is deleted
    const db = makeDb(seedTables()), st = makeStorage(seedFiles());
    st.failList = (b) => b === "bf-public" ? "list failed" : null;
    const snap = JSON.stringify(db.tables), files = st.all();
    const r = await doDelete(db, st);
    check("III13. if the files cannot be listed, nothing at all is deleted, and it says so (503)", r.status === 503 && r.body.reason === "files_unreadable" &&
      JSON.stringify(db.tables) === snap && JSON.stringify(st.all()) === JSON.stringify(files) && db.writes === 0, r.status + " " + r.body.reason);
  }
  {
    // the rows stop part-way: no file goes; pressing Delete again finishes the files too
    const db = makeDb(seedTables()), st = makeStorage(seedFiles());
    let failing = true;
    db.failOn = (t, op) => failing && t === "digital_cards" && op === "delete" ? "connection reset" : null;
    const files = st.all();
    const r1 = await doDelete(db, st);
    check("III14. a delete that stops part-way removes no file", r1.status === 500 && JSON.stringify(st.all()) === JSON.stringify(files) && st.removeCalls.length === 0, r1.status);
    failing = false;
    const r2 = await doDelete(db, st);
    const left = st.all();
    check("III15. pressing Delete again removes them all: what the deleted rows recorded is still found in A's folders",
      r2.status === 200 && flat(DEL).filter(k => RECORD_ONLY.indexOf(k) === -1).every(k => left.indexOf(k) === -1) && flat(KEEP).every(k => left.indexOf(k) !== -1) && flat(OTHERS).every(k => left.indexOf(k) !== -1),
      r2.status + " " + flat(DEL).filter(k => left.indexOf(k) !== -1).slice(0, 4).join(", "));
  }

  // ════ IV. wiring and words ════
  console.log("\n══ IV. the route, the schedule, the migration and the words ══");
  {
    const route = handlerSource(SERVER, DELETE_SIG);
    check("IV1. the route hands the delete Storage and the project URL", /storage: supabase\.storage,/.test(route) && /publicUrlBase: process\.env\.SUPABASE_URL/.test(route));
    const listenAt = SERVER.indexOf("app.listen(");
    const cronAt = SERVER.indexOf("cron.schedule(\"15 4 * * *\", function () {\n      pendingStorageDeletionTick()");
    const block = cronAt === -1 ? "" : SERVER.slice(cronAt, SERVER.indexOf("});", cronAt) + 60);
    check("IV2. the retry runs daily at 04:15 UTC, inside the listen callback, and can be turned off only by ENABLE_STORAGE_DELETION_RETRY=\"false\"",
      cronAt > listenAt && listenAt !== -1 && /timezone: "UTC"/.test(block) && /if \(process\.env\.ENABLE_STORAGE_DELETION_RETRY !== "false"\) \{\n    cron\.schedule\("15 4/.test(SERVER));
    const calls = (SERVER.match(/pendingStorageDeletionTick\(/g) || []).length;
    check("IV3. no boot-time run: the tick is defined once and called only by the cron", calls === 2 && /function pendingStorageDeletionTick\(\) \{\n  return accountFiles\.runRetryJob\(\{ supabase: supabase, storage: supabase\.storage, alerts: opsAlerts, log: console \}\);/.test(SERVER),
      calls + " mentions");
    const mig = lf(fs.readFileSync(path.join(REPO, "supabase", "migrations", "144_pending_storage_deletions.sql"), "utf8")).replace(/--[^\n]*/g, "");
    check("IV4. migration 144 makes the queue: bucket, path, attempts, last_error, created_at, one row per file, RLS on",
      /create table if not exists public\.pending_storage_deletions \(/.test(mig) && /bucket text not null/.test(mig) && /path text not null/.test(mig) &&
      /attempts integer not null default 1/.test(mig) && /last_error text/.test(mig) && /created_at timestamptz not null default now\(\)/.test(mig) &&
      /unique \(bucket, path\)/.test(mig) && /alter table public\.pending_storage_deletions enable row level security;/.test(mig));
    const latest = fs.readdirSync(path.join(REPO, "supabase", "migrations")).filter(f => /^\d+_.*\.sql$/.test(f)).sort().pop();
    check("IV5. it is the next migration number", latest === "144_pending_storage_deletions.sql", latest);
    const backup = require(path.join(REPO, "lib", "backup.js"));
    check("IV6. the queue is classified: backed up, and not member data", backup.BACKUP_TABLES.indexOf("pending_storage_deletions") !== -1 && !!YD.NOT_MEMBER_DATA.pending_storage_deletions);
    const note = YD.DELETE_NOTES.find(n => /^Your files are deleted/.test(n)) || "";
    check("IV7. the delete note says the files are deleted, except files sold, which stay for their buyers, and the rest go within a few days",
      /^Your files are deleted \(pictures, audio, video, book and document files you uploaded\), except files you sold, which stay available to the members who bought them\. If any could not be removed right away, they are removed automatically within a few days\.$/.test(note) &&
      YD.describe().deleteNotes.indexOf(note) !== -1 && !YD.DELETE_NOTES.some(n => /not deleted by this button/.test(n)), note);
    const listing = YD.DATA.find(e => e.table === "marketplace_listings");
    check("IV8. the listings line says what happens to a listing someone bought", listing.onDelete === "sold" && /except a listing another member bought: it is taken off sale and kept/.test(YD.onDeleteText(listing)));
    check("IV9. the page shows the counts from the answer, as text", /var f = r\.body\.files;/.test(PAGE) && /f\.deleted/.test(PAGE) && /f\.queued/.test(PAGE) && /f\.kept_for_buyers/.test(PAGE) && /f\.not_queued/.test(PAGE) &&
      !/innerHTML/.test(PAGE.slice(PAGE.indexOf("var f = r.body.files;"), PAGE.indexOf("var home"))));
  }

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : "")); process.exit(1); }
  console.log("ALL CHECKS PASSED" + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(0);
})().catch(function (err) {
  // A crash is a failure, never the mutation-anchor exit (3).
  console.log("    FAIL  the check threw: " + ((err && err.stack) || err));
  process.exit(1);
});
