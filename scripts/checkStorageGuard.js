"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   checkStorageGuard.js — the shared storage guard (P2-3, Nov 20 2026;
   lib/storageGuard.js, lib/storageUsage.js, server.js, lib/memberVideos.js).

   One number across every bucket: 920 MB, under the free plan's 1 GB. Every
   upload anywhere on the site asks it first.

   WHAT THIS PROVES (a fake Storage that lists buckets and files; never the
   real one)
     A. THE GUARD: room is null; past 920 MB (what is stored plus what this
        server let through since the last measurement plus this upload) is 507
        storage_full and its plain sentence; a burst inside the 10-minute cache
        cannot slip past; a fresh measurement starts the count again; storage
        that cannot be listed, or a walk that stopped early, is 503
        storage_unknown (a guard that cannot see refuses); status() reports the
        same total the guard uses.
     B. EVERY UPLOAD ASKS IT: each Storage .upload( and createSignedUploadUrl(
        in server.js has storageGuard( before it in the same route or helper,
        and a refusal stops it (fifteen sites); post photos ask it
        (lib/postMedia.js through the route's guard).
     C. VIDEOS: lib/memberVideos.js asks it after its own 900 MB budget for the
        whole file, and again (for nothing more) before each part's signed
        URL; the server hands it in (youtubeDeps). The video budget now reads
        every row, a page of 1000 at a time, and refuses rather than guess
        past its last page.

   MUTATE=<name> applies one mutation in memory; MUTATE=all runs each.
   ═══════════════════════════════════════════════════════════════════════════ */
const H = require("./_p21Harness");
const { memDb } = require("./_p23Db");

const SERVER = "@server.js", SG = "@lib/storageGuard.js", SU = "@lib/storageUsage.js", MV = "@lib/memberVideos.js";
const MUTATIONS = {
  "guard-raised": [[SG, "const STORAGE_TOTAL_GUARD = 920 * 1024 * 1024;", "const STORAGE_TOTAL_GUARD = 2048 * 1024 * 1024;"]],
  "burst-not-counted": [[SG, "  since.added += adding;\n", ""]],
  "unknown-waves-through": [[SG, '"); the upload was refused.");\n    return { status: 503, body: { error: MESSAGES.unknown, reason: "storage_unknown" } };\n  }\n  if (!m', '"); the upload was refused.");\n    return null;\n  }\n  if (!m']],
  "partial-waves-through": [[SG, "  if (!m || m.partial === true || typeof m.total_bytes !== \"number\") {", "  if (!m || typeof m.total_bytes !== \"number\") {"]],
  "music-unguarded": [[SERVER, "      const musicFull = await storageGuard(req.file.buffer.length);\n", "      const musicFull = null;\n"]],
  "signed-unguarded": [[SERVER, "  const signedFull = await storageGuard(Number(req.body.size));\n", "  const signedFull = null;\n"]],
  "media-refusal-ignored": [[SERVER, "      const mediaFull = await storageGuard(checked.size);\n      if (mediaFull)", "      const mediaFull = await storageGuard(checked.size);\n      if (false)"]],
  "video-part-unguarded": [[MV, "    var partFull = await deps.storageGuard(0);\n    if (partFull) return partFull;\n", ""]],
  "video-deps-no-guard": [[SERVER, "    storageGuard: storageGuard\n  };", "    storageGuard: null\n  };"]],
  "video-budget-one-page": [[MV, "    if (batch.length < PAGE_SIZE) return sum;\n  }\n  throw new Error(what + \" has more rows than the budget reads\");", "    return sum;\n  }\n  throw new Error(what + \" has more rows than the budget reads\");"]]
};
const T = H.setup(__filename, MUTATIONS, [SERVER, SG, SU, MV]);
const { FILES, check, J, has } = T;
const G = T.libRequire("./lib/storageGuard");
const U = T.libRequire("./lib/storageUsage");
const MB = 1024 * 1024;

/* a Storage of buckets, each a flat list of file sizes; list() pages 1000 at a time */
function fakeSb(buckets, opts) {
  opts = opts || {};
  return { storage: {
    listBuckets: async () => opts.listError ? { data: null, error: { message: "unavailable" } } : { data: Object.keys(buckets).map(n => ({ name: n, id: n })), error: null },
    from: b => ({ list: async (prefix, o) => {
      if (opts.endless) return { data: Array.from({ length: o.limit }, (_, i) => ({ name: "f" + (o.offset + i), id: "x", metadata: { size: 1 } })), error: null };
      const all = (buckets[b] || []).map((s, i) => ({ name: "f" + i, id: "id" + i, metadata: { size: s } }));
      return { data: prefix ? [] : all.slice(o.offset, o.offset + o.limit), error: null };
    } })
  } };
}
let clock = 1000000;
const fresh = () => { U.resetCache(); G.reset(); clock += U.CACHE_MS + 1; };
const ask = (sb, bytes) => G.refusal(sb, bytes, { now: clock });
const quiet = async fn => { const e = console.error; console.error = () => {}; try { return await fn(); } finally { console.error = e; } };

(async function main() {
  /* ── A ── */
  console.log("\n══ A. the guard ══");
  check("A1. 920 MB, under the free plan's 1 GB", G.STORAGE_TOTAL_GUARD === 920 * MB && G.STORAGE_TOTAL_GUARD < U.FREE_PLAN_BYTES);
  fresh();
  let sb = fakeSb({ "bf-public": [100 * MB], "bf-video": [50 * MB] });
  check("A2. room: null", await ask(sb, 10 * MB) === null);
  fresh();
  sb = fakeSb({ "bf-public": [900 * MB], "bf-video": [10 * MB] });
  let r = await ask(sb, 11 * MB);
  check("A3. past 920 MB across the buckets: 507 storage_full, with its plain sentence", r && r.status === 507 && r.body.reason === "storage_full" && r.body.error === G.MESSAGES.full, J(r));
  check("A4. exactly at 920 MB is still room", await quiet(() => ask(sb, 10 * MB)) === null);
  fresh();
  sb = fakeSb({ "bf-public": [890 * MB] });
  const a = await ask(sb, 15 * MB), b = await ask(sb, 16 * MB);
  check("A5. a burst inside the cache window: 15 MB then 16 MB, the second is refused (890 + 15 + 16 is past 920)", a === null && b && b.status === 507, J([a, b]));
  clock += U.CACHE_MS + 1; G.reset(); U.resetCache();
  sb = fakeSb({ "bf-public": [890 * MB, 15 * MB] });
  check("A6. a fresh measurement counts what was stored, and starts the count again", await ask(sb, 14 * MB) === null && (await ask(sb, 2 * MB)).status === 507);
  fresh();
  r = await quiet(() => ask(fakeSb({}, { listError: true }), 1));
  check("A7. storage that cannot be listed: 503 storage_unknown, refused", r && r.status === 503 && r.body.reason === "storage_unknown", J(r));
  fresh();
  r = await quiet(() => ask(fakeSb({ "bf-public": [] }, { endless: true }), 1));
  check("A8. a walk that stopped early: 503, refused", r && r.status === 503 && r.body.reason === "storage_unknown", J(r));
  U.resetCache(); G.reset();   // status() reads the real clock, so these do too
  sb = fakeSb({ "bf-public": [100 * MB] });
  await G.refusal(sb, 5 * MB);
  await G.refusal(sb, 0);
  await G.refusal(sb, -50);
  const st = await G.status(sb);
  check("A9. status(): what was measured plus what was let through since (a size of 0 or less adds nothing)", st.measured_bytes === 100 * MB && st.added_since_bytes === 5 * MB &&
    st.total_bytes === 105 * MB && st.guard_bytes === 920 * MB, J(st));

  /* ── B ── */
  console.log("\n══ B. every upload asks it ══");
  const S = FILES[SERVER];
  const sites = [];
  const re = /\.upload\(|\.createSignedUploadUrl\(/g;
  let m;
  while ((m = re.exec(S))) sites.push(m.index);
  const starts = [/\napp\.(get|post|put|patch|delete)\(/g, /\n(async )?function [A-Za-z0-9_]+\(/g];
  const unguarded = sites.filter(i => {
    let from = 0;
    starts.forEach(rx => { rx.lastIndex = 0; let k; while ((k = rx.exec(S)) && k.index < i) from = Math.max(from, k.index); });
    const body = S.slice(from, i);
    const g = body.lastIndexOf("storageGuard(");
    return g === -1;
  }).map(i => "line " + (S.slice(0, i).split("\n").length));
  check("B1. every Storage upload and signed upload URL in server.js (" + sites.length + ") has storageGuard( before it in its route or helper", sites.length === 15 && unguarded.length === 0, J(unguarded));
  // a created book answers with the book too: .json(Object.assign({ book: book }, createdBookFull.body))
  const stops = (S.match(/(?:const|var) (\w+Full) = await storageGuard\([^;]+\);\n\s+if \(\1\) return res\.status\(\1\.status\)\.json\([^\n]*\b\1\.body\)+;/g) || []).length;
  const optional = (S.match(/if \(await storageGuard\([^)]+\)\) throw new Error\("the shared storage guard refused the (EPUB|cover)"\);/g) || []).length;
  check("B2. a refusal stops each one: answered as the guard said (11), or an optional EPUB or cover skipped (4)", stops === 11 && optional === 4, stops + " + " + optional);
  check("B3. post photos ask it through the route", has(S, "guard: function (bytes) { return storageGuard(bytes); } }, req.user.id, req.file);") &&
    has(S, 'function storageGuard(bytes) {\n  return require("./lib/storageGuard").refusal(supabase, bytes);\n}'));

  /* ── C ── */
  console.log("\n══ C. videos ══");
  const V = FILES[MV];
  const up = V.slice(V.indexOf("async function uploadUrl("), V.indexOf("\n}\n", V.indexOf("async function uploadUrl(")));
  const pu = V.slice(V.indexOf("async function partUrl("), V.indexOf("\n}\n", V.indexOf("async function partUrl(")));
  check("C1. a video asks it for the whole file, after its own budget and before anything is signed",
    up.indexOf("var full = await budgetRefusal(deps, b.bytes);") < up.indexOf("var sharedFull = await deps.storageGuard(b.bytes);") && up.indexOf("var sharedFull = await deps.storageGuard(b.bytes);") !== -1 &&
    up.indexOf("if (sharedFull) return sharedFull;") < up.indexOf("createSignedUploadUrl("));
  check("C2. each part asks again (for nothing more) before its signed URL", pu.indexOf("var partFull = await deps.storageGuard(0);\n    if (partFull) return partFull;") !== -1 &&
    pu.indexOf("deps.storageGuard(0)") < pu.indexOf("createSignedUploadUrl("));
  check("C3. the server hands it in (youtubeDeps)", /function youtubeDeps\(\) \{[\s\S]{0,2500}?    storageGuard: storageGuard\n  \};/.test(S));
  const MVX = T.libRequire("./lib/memberVideos");
  const rows = Array.from({ length: 2500 }, (_, i) => ({ id: "v" + String(i).padStart(5, "0"), bytes: 1000, status: "ready", path: "p" + i }));
  const db = memDb({ member_videos: rows, member_video_parts: [{ id: "q1", bytes: 7, video_id: null }] });
  check("C4. the video budget reads every row, 1000 a page (2500 videos and a loose part)", await MVX.storedBytes(db.client) === 2500 * 1000 + 7);
  const huge = { from: () => { const q = { select: () => q, in: () => q, not: () => q, is: () => q, order: () => q, range: async (a, z) => ({ data: Array.from({ length: z - a + 1 }, () => ({ bytes: 1 })), error: null }) }; return q; } };
  let threw = false;
  try { await MVX.storedBytes(huge); } catch (e) { threw = true; }
  check("C5. past its last page it refuses to guess (an error, so the upload is refused)", threw);

  T.finish();
})().catch(e => { check("the check ran to the end", false, e && (e.stack || e.message || JSON.stringify(e))); T.finish(); });
