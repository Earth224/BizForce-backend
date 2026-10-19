"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkYoutubeRetention — YouTube data is kept for at most 30 days, deleted
   with what was built on it, and never mixed with other sources.

   lib/youtubeRetention.js is compiled from its source (so MUTATE can edit it
   in memory) and run against in-memory tables: bsky_leads,
   sales_lead_pipeline, outreach_sends, prospects and job_runs. Demand
   Signals' loadDemandRows is lifted from server.js and run against the same
   kind of table. No network, no model, no database.

   WHAT THIS PROVES
     A. The boundary: a YouTube row 1 ms older than 30 days is deleted; one
        exactly 30 days old, or 1 ms younger, is kept.
     B. Bluesky and Mastodon rows of every age are untouched, and so is every
        pipeline row whose lead is not a deleted YouTube lead; a pipeline row
        on a deleted YouTube lead is deleted with it. Proved on a mixed table
        of 600 rows as well as on named rows.
     C. A YouTube lead that outreach_sends or prospects points at is skipped:
        it is kept, its pipeline row is kept, the send and the prospect are
        kept; the skip is logged loudly with its count and lands in
        job_runs.last_error.
     D. Dependents first: in every batch the pipeline delete comes before the
        lead delete. If a dependent read or delete fails, no lead in that
        batch is deleted and the pass stops; if the lead delete fails, the
        pass stops. Each failure is recorded in job_runs.last_error, tried
        once (never looped), and the next day's pass finishes the work.
     E. Batches are at most 500 (100 is used), every in(...) list too, and the
        per-pass ceiling of 5,000 holds: 5,250 old rows take two days.
     F. The job_runs claim: a second tick the same UTC day reads nothing; the
        next day runs.
     G. The gate: only the exact value "false" disables it; unset, blank,
        "False", "0" and "true" leave it on. server.js schedules it at 09:00
        UTC behind that gate, with no boot-time run.
     H. No model call on any path: the module requires nothing, and no fetch
        or require happens while it runs.
     I. Demand Signals reads no YouTube row (the filter is in the query),
        lists no YouTube-only keyword, and says why in not_measured.
     Every batch logs its counts.

   MUTATE=<name> edits lib/youtubeRetention.js or server.js IN MEMORY (nothing
   on disk is touched). MUTATE=all runs each in its own process and passes only
   if every one fails at least one check. A mutation whose search text does
   not match exactly once is an ERROR, never counted as caught.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm"), Module = require("module");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const LIB_PATH = path.join(REPO, "lib", "youtubeRetention.js");
const MUTATE = process.env.MUTATE || "";
const LIB = "lib", SERVER = "server";

let LIB_SRC = fs.readFileSync(LIB_PATH, "utf8").replace(/\r\n/g, "\n");
let SERVER_SRC = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");

// The pipeline delete and the lead delete, as they stand, for the reordering mutation.
function dependentsThenLeads(src) {
  const p0 = src.indexOf("    var pipeline = await supabase\n");
  const p1 = src.indexOf("    summary.pipeline_rows_deleted += pipelineDeleted;\n");
  const l0 = src.indexOf("    // (b) THE LEADS.");
  const l1 = src.indexOf("    summary.leads_deleted += leadsDeleted;\n");
  if (p0 < 0 || p1 < 0 || l0 < 0 || l1 < 0) s.mutationAnchorError("lead-before-dependents: a block was not found");
  const P = src.slice(p0, p1 + "    summary.pipeline_rows_deleted += pipelineDeleted;\n".length);
  const L = src.slice(l0, l1 + "    summary.leads_deleted += leadsDeleted;\n".length);
  return [P + "\n" + L, L + "\n" + P];
}

const MUTATIONS = {
  // the source filter is dropped from the read and from the delete: Bluesky and Mastodon rows go too
  "drop-source-filter": [[LIB, "      .select(\"id, post_uri\")\n      .eq(\"source\", \"youtube\")\n", "      .select(\"id, post_uri\")\n"],
    [LIB, "      .eq(\"source\", \"youtube\")\n      .lt(\"created_at\", cutoff)\n      .select(\"id\");", "      .lt(\"created_at\", cutoff)\n      .select(\"id\");"]],
  // an off-by-one day: 31 days instead of 30
  "off-by-one-day": [[LIB, "var YOUTUBE_RETENTION_DAYS = 30;", "var YOUTUBE_RETENTION_DAYS = 31;"]],
  // an unset variable is treated as off
  "unset-is-off": [[LIB, "  return (env || process.env).ENABLE_YOUTUBE_RETENTION !== \"false\";", "  return (env || process.env).ENABLE_YOUTUBE_RETENTION === \"true\";"]],
  // the lead is deleted before its dependents
  "lead-before-dependents": [[LIB, dependentsThenLeads]],
  // a lead a send or a prospect points at is deleted instead of skipped
  "delete-referenced-lead": [[LIB, "    var deletable = leads.filter(function (lead) { return referenced.indexOf(lead.post_uri) === -1; });",
    "    var deletable = leads;"]],
  // Demand Signals reads YouTube rows again
  "demand-reads-youtube": [[SERVER, "    q = q.neq(\"source\", DEMAND_EXCLUDED_SOURCE);\n", ""]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const e of edits) {
    if (e[0] === LIB) {
      const [from, to] = typeof e[1] === "function" ? e[1](LIB_SRC) : [e[1], e[2]];
      LIB_SRC = s.replaceOnce(LIB_SRC, from, to, MUTATE);
    } else {
      SERVER_SRC = s.replaceOnce(SERVER_SRC, e[1], e[2], MUTATE);
    }
  }
  console.log("\n!! MUTATION: " + MUTATE);
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}

/* ── the module, compiled from its (possibly mutated) source ────────────── */
const REQUIRES = [];
const FETCHES = [];
const realFetch = globalThis.fetch;
globalThis.fetch = function (u) { FETCHES.push(String(u)); return Promise.reject(new Error("checkYoutubeRetention: no network")); };
const mod = new Module(LIB_PATH, module);
mod.filename = LIB_PATH;
mod.paths = Module._nodeModulePaths(path.dirname(LIB_PATH));
mod.require = function (id) { REQUIRES.push(id); throw new Error("checkYoutubeRetention: lib/youtubeRetention.js required " + id); };
mod._compile(LIB_SRC, LIB_PATH);
const R = mod.exports;

/* ── in-memory tables ───────────────────────────────────────────────────── */
function fakeDb(tables, opts) {
  opts = opts || {};
  const log = [];
  const copy = (v) => JSON.parse(JSON.stringify(v));
  const cmp = (col, x, y) => {
    if (col === "created_at" || col === "post_created_at") { const a = Date.parse(x), b = Date.parse(y); return a < b ? -1 : a > b ? 1 : 0; }
    return x < y ? -1 : x > y ? 1 : 0;
  };
  function keep(f, r) {
    const [op, col, a] = f;
    if (op === "eq") return r[col] === a;
    if (op === "neq") return r[col] !== a;
    if (op === "lt") return r[col] != null && cmp(col, r[col], a) < 0;
    if (op === "gt") return r[col] != null && cmp(col, r[col], a) > 0;
    if (op === "gte") return r[col] != null && cmp(col, r[col], a) >= 0;
    if (op === "in") return a.indexOf(r[col]) !== -1;
    if (op === "is") return a === null ? r[col] == null : r[col] === a;
    if (op === "not") return f[2] === "is" && f[3] === null ? r[col] != null : true;
    if (op === "or") {
      // only the claim's own form: last_run_on.is.null,last_run_on.neq.<day>
      const m = /^last_run_on\.is\.null,last_run_on\.neq\.(\d{4}-\d{2}-\d{2})$/.exec(col);
      if (!m) throw new Error("fake or(): unsupported " + col);
      return r.last_run_on == null || r.last_run_on !== m[1];
    }
    throw new Error("fake: unsupported filter " + op);
  }
  function run(q) {
    log.push(q);
    const failure = typeof opts.fail === "function" ? opts.fail(q, log) : null;
    if (failure) return Promise.resolve({ data: null, error: { message: failure }, count: null });
    const rows = tables[q.table] || (tables[q.table] = []);
    const hits = rows.filter(r => q.filters.every(f => keep(f, r)));
    if (q.op === "insert") {
      if (q.table === "job_runs" && rows.some(r => r.job_name === q.payload.job_name)) {
        return Promise.resolve({ data: null, error: { code: "23505", message: "duplicate key value violates unique constraint \"job_runs_pkey\"" } });
      }
      rows.push(copy(q.payload));
      return Promise.resolve({ data: [{ job_name: q.payload.job_name }], error: null });
    }
    if (q.op === "update") {
      hits.forEach(r => Object.assign(r, copy(q.payload)));
      return Promise.resolve({ data: hits.map(r => ({ job_name: r.job_name })), error: null });
    }
    if (q.op === "delete") {
      const gone = new Set(hits);
      tables[q.table] = rows.filter(r => !gone.has(r));
      return Promise.resolve({ data: hits.map(r => ({ id: r.id })), error: null });
    }
    if (q.head) return Promise.resolve({ data: null, count: hits.length, error: null });
    let out = hits.slice();
    if (q.order) out.sort((x, y) => cmp(q.order, x[q.order], y[q.order]));
    if (q.range) out = out.slice(q.range[0], q.range[1] + 1);
    if (q.limit != null) out = out.slice(0, q.limit);
    const cols = String(q.cols || "*").split(",").map(c => c.trim());
    return Promise.resolve({ data: out.map(r => { if (cols[0] === "*") return copy(r); const o = {}; cols.forEach(c => { o[c] = r[c] === undefined ? null : r[c]; }); return o; }), error: null });
  }
  function from(table) {
    const q = { table, op: "select", cols: null, head: false, filters: [], order: null, limit: null, range: null, payload: null };
    const b = {
      select(cols, o) { if (q.op === "select") { q.cols = cols; q.head = !!(o && o.head); } return b; },
      insert(p) { q.op = "insert"; q.payload = p; return b; },
      update(p) { q.op = "update"; q.payload = p; return b; },
      delete() { q.op = "delete"; return b; },
      order(c) { q.order = c; return b; },
      limit(n) { q.limit = n; return b; },
      range(a, z) { q.range = [a, z]; return b; },
      then(res, rej) { return run(q).then(res, rej); }
    };
    ["eq", "neq", "lt", "gt", "gte", "in", "is", "not", "or"].forEach(op => { b[op] = function () { q.filters.push([op].concat([].slice.call(arguments))); return b; }; });
    return b;
  }
  return { log, tables, client: { from } };
}

/* ── fixtures ───────────────────────────────────────────────────────────── */
const DAY = 24 * 3600 * 1000;
const NOW = Date.parse("2026-10-20T09:00:00.000Z");
const CUTOFF = NOW - 30 * DAY;
const iso = (ms) => new Date(ms).toISOString();
let seq = 0;
function lead(source, createdMs, tag) {
  const n = ++seq;
  const uri = source === "youtube" ? "https://www.youtube.com/watch?v=v" + String(n).padStart(10, "0") + "&lc=c" + n
    : source === "mastodon" ? "https://mastodon.example/@p" + n + "/" + n : "at://did:plc:p" + n + "/app.bsky.feed.post/" + n;
  return { id: "lead-" + String(n).padStart(6, "0"), source, created_at: iso(createdMs), post_uri: uri, tag: tag || null };
}
function pipe(l, tag) { return { id: "pipe-" + (++seq), user_id: "owner", lead_post_uri: l.post_uri, status: "drafted", last_draft: "a reply", tag: tag || null }; }

async function quietly(fn) {
  const logs = [], realLog = console.log, realErr = console.error;
  console.log = (...a) => { logs.push(a.join(" ")); };
  console.error = (...a) => { logs.push("ERR " + a.join(" ")); };
  try { return { value: await fn(), logs }; } finally { console.log = realLog; console.error = realErr; }
}
const byTag = (rows, tag) => rows.filter(r => r.tag === tag);
const has = (rows, id) => rows.some(r => r.id === id);

(async function main() {
  /* ── A. the 30-day boundary ─────────────────────────────────────────────── */
  console.log("\n══ A. the 30-day boundary ══");
  seq = 0;
  const outside = lead("youtube", CUTOFF - 1, "outside");
  const exact = lead("youtube", CUTOFF, "exact");
  const inside = lead("youtube", CUTOFF + 1, "inside");
  const ancient = lead("youtube", NOW - 400 * DAY, "ancient");
  const others = [lead("bluesky", NOW - 400 * DAY), lead("bluesky", CUTOFF - 1), lead("bluesky", NOW - DAY),
    lead("mastodon", NOW - 400 * DAY), lead("mastodon", CUTOFF - 1), lead("mastodon", NOW - DAY)];
  const pOnAncient = pipe(ancient, "on-deleted-youtube"), pOnBluesky = pipe(others[0], "on-bluesky"), pOnInside = pipe(inside, "on-kept-youtube");
  const dbA = fakeDb({ bsky_leads: [outside, exact, inside, ancient].concat(others), sales_lead_pipeline: [pOnAncient, pOnBluesky, pOnInside],
    outreach_sends: [], prospects: [], job_runs: [] });
  const tA = await quietly(() => R.youtubeRetentionTick(dbA.client, NOW));
  const leadsA = dbA.tables.bsky_leads;
  check("cutoff is exactly 30 days before the pass", R.youtubeRetentionCutoff(NOW) === iso(CUTOFF), R.youtubeRetentionCutoff(NOW));
  check("A. a YouTube row 1 ms older than 30 days is deleted", !has(leadsA, outside.id));
  check("A. a YouTube row exactly 30 days old is kept", has(leadsA, exact.id));
  check("A. a YouTube row 1 ms younger than 30 days is kept", has(leadsA, inside.id));
  check("A. a YouTube row 400 days old is deleted", !has(leadsA, ancient.id));
  check("A. the pass reports 2 leads deleted, 1 pipeline row deleted, 0 skipped",
    tA.value && tA.value.leads_deleted === 2 && tA.value.pipeline_rows_deleted === 1 && tA.value.leads_skipped === 0, JSON.stringify(tA.value));

  /* ── B. other sources, and pipeline rows not on a deleted YouTube lead ──── */
  console.log("\n══ B. nothing of another source, no other pipeline row ══");
  check("B. every Bluesky and Mastodon row is untouched, 400 days old included", others.every(o => has(leadsA, o.id)),
    JSON.stringify(others.filter(o => !has(leadsA, o.id)).map(o => o.source + " " + o.created_at)));
  check("B. the pipeline row on the deleted YouTube lead is deleted with it", !has(dbA.tables.sales_lead_pipeline, pOnAncient.id));
  check("B. the pipeline row on a Bluesky lead is untouched", has(dbA.tables.sales_lead_pipeline, pOnBluesky.id));
  check("B. the pipeline row on a YouTube lead younger than 30 days is untouched", has(dbA.tables.sales_lead_pipeline, pOnInside.id));
  const leadDeletes = dbA.log.filter(q => q.table === "bsky_leads" && q.op === "delete");
  check("B. the lead delete itself filters source = youtube and created_at < cutoff, not ids alone",
    leadDeletes.length > 0 && leadDeletes.every(q => q.filters.some(f => f[0] === "eq" && f[1] === "source" && f[2] === "youtube") &&
      q.filters.some(f => f[0] === "lt" && f[1] === "created_at" && f[2] === iso(CUTOFF))), JSON.stringify(leadDeletes.map(q => q.filters.map(f => f[0] + " " + f[1]))));

  // A mixed table: 600 leads of every source and age, a pipeline row on each.
  seq = 0;
  const mixed = [], mixedPipes = [];
  for (let i = 0; i < 600; i++) {
    const src = ["bluesky", "mastodon", "youtube"][i % 3];
    const age = [400, 60, 31, 30.5, 30, 29, 1, 0.01][i % 8] * DAY + (i % 5);
    const l = lead(src, NOW - age);
    mixed.push(l);
    mixedPipes.push(pipe(l));
  }
  const dbM = fakeDb({ bsky_leads: mixed.map(r => Object.assign({}, r)), sales_lead_pipeline: mixedPipes.map(r => Object.assign({}, r)),
    outreach_sends: [], prospects: [], job_runs: [] });
  const tM = await quietly(() => R.youtubeRetentionTick(dbM.client, NOW));
  const shouldGo = new Set(mixed.filter(r => r.source === "youtube" && Date.parse(r.created_at) < CUTOFF).map(r => r.id));
  const goneLeads = mixed.filter(r => !has(dbM.tables.bsky_leads, r.id));
  const goneUris = new Set(goneLeads.map(r => r.post_uri));
  const gonePipes = mixedPipes.filter(p => !has(dbM.tables.sales_lead_pipeline, p.id));
  check("B. mixed table: exactly the YouTube rows older than 30 days are deleted (" + shouldGo.size + "), nothing else",
    shouldGo.size > 0 && goneLeads.length === shouldGo.size && goneLeads.every(r => shouldGo.has(r.id)), goneLeads.length + " gone vs " + shouldGo.size);
  check("B. mixed table: not one Bluesky or Mastodon row deleted", goneLeads.every(r => r.source === "youtube"));
  check("B. mixed table: exactly the pipeline rows on deleted leads are deleted, none other",
    gonePipes.length === shouldGo.size && gonePipes.every(p => goneUris.has(p.lead_post_uri)), gonePipes.length);
  check("B. mixed table: no pipeline row left pointing at a missing lead",
    dbM.tables.sales_lead_pipeline.every(p => dbM.tables.bsky_leads.some(l => l.post_uri === p.lead_post_uri)));

  /* ── C. a lead a send or a prospect points at is skipped ────────────────── */
  console.log("\n══ C. referenced leads are skipped, never orphaned ══");
  seq = 0;
  const sent = lead("youtube", NOW - 100 * DAY, "sent"), prospected = lead("youtube", NOW - 100 * DAY, "prospected"), plain = lead("youtube", NOW - 100 * DAY, "plain");
  const send = { id: "send-1", user_id: "owner", lead_post_uri: sent.post_uri }, prospect = { id: "prospect-1", user_id: "owner", lead_post_uri: prospected.post_uri };
  const pSent = pipe(sent, "on-sent"), pProspected = pipe(prospected, "on-prospected"), pPlain = pipe(plain, "on-plain");
  const dbC = fakeDb({ bsky_leads: [sent, prospected, plain], sales_lead_pipeline: [pSent, pProspected, pPlain],
    outreach_sends: [send], prospects: [prospect], job_runs: [] });
  const tC = await quietly(() => R.youtubeRetentionTick(dbC.client, NOW));
  check("C. the lead outreach_sends points at is kept", has(dbC.tables.bsky_leads, sent.id));
  check("C. the lead prospects points at is kept", has(dbC.tables.bsky_leads, prospected.id));
  check("C. nothing referencing them is deleted: the send, the prospect and both pipeline rows remain",
    has(dbC.tables.outreach_sends, send.id) && has(dbC.tables.prospects, prospect.id) &&
    has(dbC.tables.sales_lead_pipeline, pSent.id) && has(dbC.tables.sales_lead_pipeline, pProspected.id));
  check("C. the unreferenced lead and its pipeline row are deleted", !has(dbC.tables.bsky_leads, plain.id) && !has(dbC.tables.sales_lead_pipeline, pPlain.id));
  check("C. no send or prospect is ever deleted: no delete was issued on either table",
    !dbC.log.some(q => (q.table === "outreach_sends" || q.table === "prospects") && q.op !== "select"));
  check("C. the skip is logged loudly with its count", tC.logs.some(l => /^ERR \[YouTubeRetention\] SKIPPED 2 YouTube lead\(s\)/.test(l)), tC.logs.join(" | "));
  const jrC = dbC.tables.job_runs[0] || {};
  check("C. and recorded in job_runs.last_error, with the run closed", /2 YouTube lead\(s\) skipped because outreach_sends or prospects still points at them/.test(jrC.last_error || "") && !!jrC.finished_at,
    JSON.stringify(jrC));

  /* ── D. dependents first; a failure stops the pass ──────────────────────── */
  console.log("\n══ D. dependents first, and a failed batch stops the pass ══");
  const orderOk = [dbA, dbM, dbC].every(db => {
    let pendingPipeline = false, ok = true, sawLead = false;
    db.log.forEach(q => {
      if (q.table === "sales_lead_pipeline" && q.op === "delete") pendingPipeline = true;
      if (q.table === "bsky_leads" && q.op === "delete") { sawLead = true; if (!pendingPipeline) ok = false; pendingPipeline = false; }
    });
    return ok && sawLead;
  });
  check("D. in every batch, the pipeline delete comes before the lead delete", orderOk);
  function oldYoutube(n) {
    seq = 0;
    const leads = [];
    for (let i = 0; i < n; i++) leads.push(lead("youtube", NOW - (40 + (i % 50)) * DAY));
    return leads;
  }
  // The pipeline delete fails.
  const leadsD1 = oldYoutube(250);
  const dbD1 = fakeDb({ bsky_leads: leadsD1.slice(), sales_lead_pipeline: leadsD1.map(l => pipe(l)), outreach_sends: [], prospects: [], job_runs: [] },
    { fail: (q) => q.table === "sales_lead_pipeline" && q.op === "delete" ? "pipeline is unavailable" : null });
  const tD1 = await quietly(() => R.youtubeRetentionTick(dbD1.client, NOW));
  const jrD1 = dbD1.tables.job_runs[0] || {};
  check("D. the pipeline delete fails: every lead survives", dbD1.tables.bsky_leads.length === 250, dbD1.tables.bsky_leads.length);
  check("D. …no lead delete was issued at all", !dbD1.log.some(q => q.table === "bsky_leads" && q.op === "delete"));
  check("D. …the pass stopped at the first batch: one pipeline delete tried, never looped",
    dbD1.log.filter(q => q.table === "sales_lead_pipeline" && q.op === "delete").length === 1 && dbD1.log.filter(q => q.table === "bsky_leads" && q.op === "select").length === 1);
  check("D. …and job_runs.last_error records it, the run closed", /sales_lead_pipeline delete failed: pipeline is unavailable\. No lead in this batch was deleted\./.test(jrD1.last_error || "") && !!jrD1.finished_at,
    JSON.stringify(jrD1));
  // A reference read fails.
  const leadsD2 = oldYoutube(50);
  const dbD2 = fakeDb({ bsky_leads: leadsD2.slice(), sales_lead_pipeline: leadsD2.map(l => pipe(l)), outreach_sends: [], prospects: [], job_runs: [] },
    { fail: (q) => q.table === "prospects" ? "prospects is unavailable" : null });
  await quietly(() => R.youtubeRetentionTick(dbD2.client, NOW));
  check("D. a reference read fails: nothing is deleted, in either table",
    dbD2.tables.bsky_leads.length === 50 && dbD2.tables.sales_lead_pipeline.length === 50 && !dbD2.log.some(q => q.op === "delete"));
  check("D. …recorded in last_error", /prospects could not be read: prospects is unavailable/.test((dbD2.tables.job_runs[0] || {}).last_error || ""));
  // The lead delete fails.
  const leadsD3 = oldYoutube(250);
  const dbD3 = fakeDb({ bsky_leads: leadsD3.slice(), sales_lead_pipeline: [], outreach_sends: [], prospects: [], job_runs: [] },
    { fail: (q) => q.table === "bsky_leads" && q.op === "delete" ? "leads are unavailable" : null });
  await quietly(() => R.youtubeRetentionTick(dbD3.client, NOW));
  check("D. the lead delete fails: the pass stops after one attempt, never looped, and last_error records it",
    dbD3.log.filter(q => q.table === "bsky_leads" && q.op === "delete").length === 1 && dbD3.tables.bsky_leads.length === 250 &&
    /bsky_leads delete failed after 0 pipeline row\(s\) were deleted: leads are unavailable/.test((dbD3.tables.job_runs[0] || {}).last_error || ""),
    (dbD3.tables.job_runs[0] || {}).last_error);
  // The next day, with the fault gone, the work is finished.
  const dbD1next = fakeDb(Object.assign({}, dbD1.tables));
  const tD1next = await quietly(() => R.youtubeRetentionTick(dbD1next.client, NOW + DAY));
  check("D. the next day's pass, the fault gone, deletes all 250 and their pipeline rows, and closes clean",
    dbD1next.tables.bsky_leads.length === 0 && dbD1next.tables.sales_lead_pipeline.length === 0 && (dbD1next.tables.job_runs[0] || {}).last_error === null,
    JSON.stringify([dbD1next.tables.bsky_leads.length, dbD1next.tables.sales_lead_pipeline.length, (dbD1next.tables.job_runs[0] || {}).last_error]));

  /* ── E. batch size and the per-pass ceiling ─────────────────────────────── */
  console.log("\n══ E. batches of at most 500, and the per-pass ceiling ══");
  check("E. the batch is at most 500 (it is " + R.YOUTUBE_RETENTION_BATCH + ") and the ceiling is 5,000",
    R.YOUTUBE_RETENTION_BATCH > 0 && R.YOUTUBE_RETENTION_BATCH <= 500 && R.YOUTUBE_RETENTION_MAX_PER_TICK === 5000);
  const leadsE = oldYoutube(5250);
  const dbE = fakeDb({ bsky_leads: leadsE.slice(), sales_lead_pipeline: [], outreach_sends: [], prospects: [], job_runs: [] });
  const tE = await quietly(() => R.youtubeRetentionTick(dbE.client, NOW));
  const reads = dbE.log.filter(q => q.table === "bsky_leads" && q.op === "select");
  const inLists = dbE.log.reduce((acc, q) => acc.concat(q.filters.filter(f => f[0] === "in").map(f => f[2].length)), []);
  check("E. every read asks for at most 500 rows", reads.length > 0 && reads.every(q => q.limit > 0 && q.limit <= 500), JSON.stringify([...new Set(reads.map(q => q.limit))]));
  check("E. every in(...) list holds at most 500 values", inLists.length > 0 && Math.max.apply(null, inLists) <= 500, Math.max.apply(null, inLists));
  check("E. the first pass deletes exactly 5,000 (the ceiling) and says so", tE.value && tE.value.leads_deleted === 5000 && tE.value.ceiling_reached === true &&
    dbE.tables.bsky_leads.length === 250 && tE.logs.some(l => /Per-pass ceiling of 5000 lead\(s\) reached/.test(l)), JSON.stringify(tE.value));
  check("E. every batch logs its counts", tE.value && tE.logs.filter(l => /^\[YouTubeRetention\] Batch \d+: \d+ lead\(s\) deleted, \d+ pipeline row\(s\) deleted, \d+ lead\(s\) skipped\.$/.test(l)).length === tE.value.batches,
    tE.value && tE.value.batches);
  const dbE2 = fakeDb(Object.assign({}, dbE.tables));
  const tE2 = await quietly(() => R.youtubeRetentionTick(dbE2.client, NOW + DAY));
  check("E. the next day deletes the remaining 250", tE2.value && tE2.value.leads_deleted === 250 && dbE2.tables.bsky_leads.length === 0, JSON.stringify(tE2.value));

  /* ── F. the claim ───────────────────────────────────────────────────────── */
  console.log("\n══ F. the job_runs claim ══");
  seq = 0;
  const dbF = fakeDb({ bsky_leads: [lead("youtube", NOW - 90 * DAY)], sales_lead_pipeline: [], outreach_sends: [], prospects: [], job_runs: [] });
  const f1 = await quietly(() => R.youtubeRetentionTick(dbF.client, NOW));
  dbF.tables.bsky_leads.push(lead("youtube", NOW - 90 * DAY));
  const readsBefore = dbF.log.filter(q => q.table === "bsky_leads").length;
  const f2 = await quietly(() => R.youtubeRetentionTick(dbF.client, NOW + 3 * 3600 * 1000));
  const readsAfter = dbF.log.filter(q => q.table === "bsky_leads").length;
  check("F. the first tick claims the UTC day under daily_youtube_retention", f1.value && dbF.tables.job_runs.length === 1 &&
    dbF.tables.job_runs[0].job_name === "daily_youtube_retention" && dbF.tables.job_runs[0].last_run_on === "2026-10-20", JSON.stringify(dbF.tables.job_runs));
  check("F. a second tick the same UTC day is refused and reads nothing", f2.value === null && readsAfter === readsBefore && dbF.tables.bsky_leads.length === 1 &&
    f2.logs.some(l => /already claimed for 2026-10-20/.test(l)), f2.logs.join(" | "));
  const f3 = await quietly(() => R.youtubeRetentionTick(dbF.client, NOW + DAY));
  check("F. the next UTC day runs", f3.value && f3.value.leads_deleted === 1 && dbF.tables.job_runs[0].last_run_on === "2026-10-21", JSON.stringify(f3.value));

  /* ── G. the gate, and the schedule ──────────────────────────────────────── */
  console.log("\n══ G. only the exact \"false\" disables it ══");
  const gate = (v) => R.youtubeRetentionEnabled(v === undefined ? {} : { ENABLE_YOUTUBE_RETENTION: v });
  check("G. unset: on", gate(undefined) === true);
  check("G. blank: on", gate("") === true);
  check("G. \"False\", \"FALSE\", \"0\", \"no\" and \" false\": on", ["False", "FALSE", "0", "no", " false"].every(v => gate(v) === true));
  check("G. \"true\": on", gate("true") === true);
  check("G. exactly \"false\": off", gate("false") === false);
  const sched = /  if \(youtubeRetentionEnabled\(process\.env\)\) \{\n    cron\.schedule\("0 9 \* \* \*", function \(\) \{\n      youtubeRetentionTick\(supabase\)\.catch\(function \(err\) \{\n[\s\S]{0,200}?\}, \{\n      timezone: "UTC"\n    \}\);/.exec(SERVER_SRC);
  check("G. server.js schedules it at 09:00 UTC, behind youtubeRetentionEnabled(process.env), inside app.listen", !!sched &&
    SERVER_SRC.lastIndexOf("app.listen(PORT, function () {", sched.index) !== -1 && SERVER_SRC.indexOf("\nmodule.exports = {", sched.index) !== -1);
  check("G. no boot-time run: youtubeRetentionTick is called only from that schedule",
    (SERVER_SRC.match(/youtubeRetentionTick\(/g) || []).length === 1 && !/setTimeout\([^)]*youtubeRetention/.test(SERVER_SRC));

  /* ── H. no model call ───────────────────────────────────────────────────── */
  console.log("\n══ H. no model call on any path ══");
  check("H. lib/youtubeRetention.js requires nothing, and nothing was required while it ran", !/\brequire\(/.test(LIB_SRC.replace(/\/\/[^\n]*/g, "")) && REQUIRES.length === 0, JSON.stringify(REQUIRES));
  check("H. no fetch was made on any path", FETCHES.length === 0, JSON.stringify(FETCHES));
  check("H. it names no model client: no anthropic, callAnthropic, openai or messages.create",
    !/anthropic|callAnthropic|openai|messages\.create|toolGenerate/i.test(LIB_SRC.replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g, "")));
  check("H. it touches only its five tables", [dbA, dbM, dbC, dbD1, dbE, dbF].every(db => db.log.every(q => ["bsky_leads", "sales_lead_pipeline", "outreach_sends", "prospects", "job_runs"].indexOf(q.table) !== -1)));

  /* ── I. Demand Signals ──────────────────────────────────────────────────── */
  console.log("\n══ I. Demand Signals reads no YouTube row ══");
  const lifted = ["DEMAND_THEME_KEYWORDS", "DEMAND_NOT_MEASURED", "DEMAND_EXCLUDED_SOURCE", "DEMAND_PAGE", "loadDemandRows"]
    .map(n => { const d = s.definitionOf(SERVER_SRC, n); if (!d) throw new Error(n + " not found in server.js"); return d; }).join("\n\n");
  seq = 0;
  const dsRows = [];
  ["bluesky", "mastodon", "youtube"].forEach(src => {
    dsRows.push(Object.assign(lead(src, NOW - 5 * DAY), { matched_keyword: "how to manifest", post_created_at: iso(Date.now() - 5 * DAY) }));
    dsRows.push(Object.assign(lead(src, NOW - 5 * DAY), { matched_keyword: "how to manifest", post_created_at: null }));
    dsRows.push(Object.assign(lead(src, NOW - 5 * DAY), { matched_keyword: "how to manifest", post_created_at: iso(Date.now() - 300 * DAY) }));
  });
  const dbI = fakeDb({ bsky_leads: dsRows });
  const ctx = { supabase: dbI.client, Date, Object, Array, String, Number, JSON };
  vm.createContext(ctx);
  vm.runInContext(lifted + "\nthis.__api = { loadDemandRows: loadDemandRows, DEMAND_NOT_MEASURED: DEMAND_NOT_MEASURED, DEMAND_THEME_KEYWORDS: DEMAND_THEME_KEYWORDS };", ctx);
  const windowStart = iso(Date.now() - 90 * DAY);
  const gotAll = await ctx.__api.loadDemandRows("all", windowStart);
  const gotTheme = await ctx.__api.loadDemandRows("manifestation", windowStart);
  check("I. theme all: no YouTube row read; 2 rows in the window, 2 undated, 2 before it (Bluesky and Mastodon only)",
    gotAll.rows.length === 2 && gotAll.rows.every(r => r.source !== "youtube") && gotAll.undated === 2 && gotAll.datedBefore === 2,
    JSON.stringify([gotAll.rows.map(r => r.source), gotAll.undated, gotAll.datedBefore]));
  check("I. a theme: the same", gotTheme.rows.length === 2 && gotTheme.rows.every(r => r.source !== "youtube") && gotTheme.undated === 2 && gotTheme.datedBefore === 2,
    JSON.stringify([gotTheme.rows.map(r => r.source), gotTheme.undated, gotTheme.datedBefore]));
  check("I. the filter is in every query (source neq youtube), not applied afterwards",
    dbI.log.length === 6 && dbI.log.every(q => q.filters.some(f => f[0] === "neq" && f[1] === "source" && f[2] === "youtube")), dbI.log.length);
  const nm = ctx.__api.DEMAND_NOT_MEASURED;
  check("I. not_measured says YouTube is excluded, and why", nm.some(x => /^YouTube: excluded\. YouTube's API terms forbid combining YouTube data with data from other sources/.test(x)), JSON.stringify(nm));
  const radarSrc = fs.readFileSync(path.join(REPO, "leadRadar.js"), "utf8") + fs.readFileSync(path.join(REPO, "mastodonRadar.js"), "utf8");
  const ytSrc = fs.readFileSync(path.join(REPO, "youtubeRadar.js"), "utf8");
  const ytKw = /KEYWORDS = \[([\s\S]*?)\];/.exec(ytSrc);
  const ytToday = ytKw ? (ytKw[1].match(/"[^"]+"/g) || []).map(x => x.slice(1, -1)) : [];
  const ytOnlyToday = ytToday.filter(k => radarSrc.indexOf("\"" + k + "\"") === -1);
  // youtubeRadar.js's list at 5746f53, never searched on Bluesky or Mastodon and on no Bluesky or Mastodon row (Oct 2026).
  const ytOnlyEarlier = ["low libido help", "boost energy naturally", "natural male vitality", "tongkat ali reviews"];
  const flat = [].concat.apply([], Object.values(ctx.__api.DEMAND_THEME_KEYWORDS));
  check("I. no theme lists a YouTube-only keyword (" + ytOnlyToday.length + " searched only by youtubeRadar.js today, " + ytOnlyEarlier.length + " from its earlier list)",
    ytOnlyToday.length === 3 && ytOnlyToday.concat(ytOnlyEarlier).every(k => flat.indexOf(k) === -1), JSON.stringify(ytOnlyToday.concat(ytOnlyEarlier).filter(k => flat.indexOf(k) !== -1)));

  globalThis.fetch = realFetch;
  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
