"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkDemandSignals — the radar read as demand evidence, without reading out
   a person.

   POST /api/agents/rd/demand-signals is lifted from server.js and run in a vm
   against a fake Supabase holding bsky_leads rows, with startToolRun recording
   the persisted body and callAnthropicText a stub that records every prompt
   and answers what each case needs. No network, no model, no database.

   WHAT THIS PROVES
     1. The keyword map: every theme's keywords are the stored values it says,
        each keyword sits in one theme, bizforce is exactly leadRadar.js's
        BIZFORCE_KEYWORDS, and "all" reads every row.
     2. The window is the author's date: rows outside it are not in scope,
        undated rows are counted apart and appear in no month and no sample.
     3. "<5": every count from 0 to 4 is shown as "<5", never the number.
     4. Real scores only: a failed scoring (score_failed, or the legacy 0 with
        the failure reason) and an unscored row are never bucketed as scores.
     5. The model sees cleaned text only: no @, no handle, no URL, no domain,
        no email, no phone number, and no post longer than 600 characters; and
        no row field beyond keyword and cleaned text.
     6. Determinism: the same seed draws the same sample; another seed can
        differ; the sample spreads across keywords.
     7. Theme drops: a theme citing no keyword in scope, or claiming more
        support than the sample has, is dropped and counted.
     8. Privacy drops: a theme repeating 6 consecutive words of a sampled post
        is removed and counted; a 5-word overlap is not.
     9. A model failure returns 200 with measured, themes null and
        explanation_error. A non-admin is refused 403 before anything is read.
    10. No row-level field anywhere in the response or the persisted body.
     And zero network.

   MUTATE=<name> edits the lifted source (server.js on disk is never touched).
   MUTATE=all runs each in its own process and passes only if every one fails
   at least one check. A mutation whose search text does not match exactly once
   is an ERROR, never counted as caught.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), vm = require("vm"), path = require("path"), net = require("net"), dns = require("dns");
const s = require("./_shared");

const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkDemandSignals: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkDemandSignals: no network"); };

const REPO = path.join(__dirname, "..");
const MUTATE = process.env.MUTATE || "";

const MUTATIONS = {
  // the sample goes to the model uncleaned
  "uncleaned-text": [["    return { ref: \"S\" + (i + 1), keyword: String(r.matched_keyword), text: demandCleanText(r.post_text) };",
    "    return { ref: \"S\" + (i + 1), keyword: String(r.matched_keyword), text: String(r.post_text) };"]],
  // a theme that repeats a sampled post is kept
  "skip-privacy-check": [["    if (demandRepeatsSample(m[1] + \" \" + m[2], quoteRuns)) { privacy++; return; }\n", ""]],
  // counts below 5 are shown as numbers
  "show-small-counts": [["  return n < DEMAND_SMALL_COUNT ? \"<\" + DEMAND_SMALL_COUNT : n;", "  return n;"]],
  // a failed or missing score is bucketed as a score
  "include-failed-scores": [["    if (leadHasRealScore(r)) {\n      real++;", "    if (r.intent_score != null || r.status === \"score_failed\") {\n      real++;"]],
  // the response carries the sampled post text
  "return-post-text": [["        not_measured: DEMAND_NOT_MEASURED,\n", "        not_measured: DEMAND_NOT_MEASURED,\n        sample_posts: loaded.rows.slice(0, 3).map(function (r) { return { post_text: r.post_text }; }),\n"]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

let SRC = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
const RADAR = fs.readFileSync(path.join(REPO, "leadRadar.js"), "utf8").replace(/\r\n/g, "\n");
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [from, to] of edits) SRC = s.replaceOnce(SRC, from, to, MUTATE);
  console.log("\n!! MUTATION: " + MUTATE);
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}

/* ── lifting ────────────────────────────────────────────────────────────── */
const SPANS = [];
{
  const re = /^(?:(?:async )?function [A-Za-z_$][A-Za-z0-9_$]*[(]|app[.][a-z]+[(])/gm; let m;
  while ((m = re.exec(SRC))) { const end = s.braceMatch(SRC, SRC.indexOf("{", m.index)); if (end > 0) SPANS.push([m.index, end]); }
}
function definitionOf(name) {
  let m = new RegExp("^(?:async )?function " + name + "\\(", "m").exec(SRC);
  if (m) return SRC.slice(m.index, s.braceMatch(SRC, SRC.indexOf(") {", m.index) + 2));
  const re = new RegExp("^(?:var|const|let) " + name + "[ \t]*=[ \t]*", "gm");
  while ((m = re.exec(SRC)) && SPANS.some(([x, y]) => m.index > x && m.index < y)) { /* a local */ }
  if (!m) return null;
  const brk = /;\n/g; brk.lastIndex = m.index + m[0].length;
  let b;
  while ((b = brk.exec(SRC))) {
    const next = SRC[b.index + b[0].length];
    if (next === undefined || next === "\n" || /[^\s]/.test(next)) return SRC.slice(m.index, b.index + 1);
  }
  return null;
}
const STUBS = new Set(["supabase", "nowIso", "console", "process", "require", "module", "app", "Buffer", "setTimeout", "fetch",
  "requireAuth", "requireActiveSubscription", "aiLimiter", "startToolRun", "callAnthropicText", "resolvePreferredLanguage", "Date", "stripe", "Stripe"]);
const uncommented = (code) => code.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
function closure(root) {
  const have = new Map();
  const queue = [...new Set(uncommented(root).match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || STUBS.has(name)) continue;
    const def = definitionOf(name);
    if (!def) continue;
    if (/^(?:var|const|let) [^=]*=[^;]*\brequire\(/.test(def)) continue;
    try { new vm.Script(def); } catch (e) { continue; }
    have.set(name, def);
    new Set(uncommented(def).match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !STUBS.has(id)) queue.push(id); });
  }
  return [...have.values()].sort((x, y) => SRC.indexOf(x) - SRC.indexOf(y)).join("\n\n") + "\n\n" + root;
}
const ROUTE = "/api/agents/rd/demand-signals";
function routeText() {
  const start = SRC.indexOf("app.post(\"" + ROUTE + "\",");
  if (start < 0) throw new Error("POST " + ROUTE + " not found");
  const end = s.braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("async function (req, res, next)", start)));
  if (SRC.slice(end, end + 2) !== ");") throw new Error("POST " + ROUTE + " did not end where expected");
  return SRC.slice(start, end + 2);
}
const LIFTED = closure(routeText() + "\n\nthis.api = { DEMAND_THEME_KEYWORDS: DEMAND_THEME_KEYWORDS, demandSample: demandSample, " +
  "demandCleanText: demandCleanText, demandSeed: demandSeed };");

/* ── the fake database ──────────────────────────────────────────────────── */
function fakeDb(rows) {
  const log = [];
  const copy = v => JSON.parse(JSON.stringify(v));
  function keep(q, r) {
    return q.filters.every(f => {
      const [op, col, a, b] = f;
      if (op === "in") return a.indexOf(r[col]) !== -1;
      if (op === "is") return a === null ? r[col] == null : r[col] === a;
      if (op === "not" && a === "is" && b === null) return r[col] != null;
      if (op === "gte") return r[col] != null && r[col] >= a;
      if (op === "lt") return r[col] != null && r[col] < a;
      return true;
    });
  }
  function answer(q) {
    let hits = rows.filter(r => keep(q, r));
    if (q.head) return Promise.resolve({ data: null, count: hits.length, error: null });
    hits = hits.slice().sort((x, y) => x.id < y.id ? -1 : 1);
    const range = q.filters.find(f => f[0] === "range");
    if (range) hits = hits.slice(range[1], range[2] + 1);
    const cols = String(q.cols || "*").split(",").map(c => c.trim());
    return Promise.resolve({ data: hits.map(r => { if (cols[0] === "*") return copy(r); const o = {}; cols.forEach(c => { o[c] = r[c] === undefined ? null : r[c]; }); return o; }), error: null });
  }
  function from(table) {
    const q = { table, cols: null, head: false, filters: [] };
    log.push(q);
    const b = { select(cols, opts) { q.cols = cols; q.head = !!(opts && opts.head); return b; } };
    ["in", "is", "not", "gte", "lt", "order", "range", "limit", "eq"].forEach(op => { b[op] = function () { q.filters.push([op].concat([].slice.call(arguments))); return b; }; });
    b.then = (res, rej) => answer(q).then(res, rej);
    return b;
  }
  return { log, client: { from } };
}

/* ── fixtures ───────────────────────────────────────────────────────────── */
const DAY = 24 * 3600 * 1000;
const ago = (d) => new Date(Date.now() - d * DAY).toISOString();
const FAILED = "scoring failed after 3 attempts";
let n = 0;
const row = (kw, extra) => Object.assign({ id: "r" + String(++n).padStart(4, "0"), matched_keyword: kw, source: "bluesky", post_created_at: ago(10),
  status: "scored", intent_score: 15, intent_reason: "asks a question", post_text: "plain post " + n, author_handle: "person" + n + ".bsky.social",
  author_did: "did:plc:person" + n, post_uri: "at://did:plc:person" + n + "/app.bsky.feed.post/" + n, post_id: "pid" + n, post_cid: "cid" + n,
  outreach_safe: true, suggested_product: "Tongkat Ali" }, extra || {});
const PRIVATE_FIELDS = ["post_text", "author_handle", "author_did", "post_uri", "post_id", "post_cid", "intent_reason", "outreach_safe", "suggested_product"];
const DIRTY = "Ask @someone.bsky.social or mail jane.doe@example.com or call +1 (555) 123-4567, see https://example.com/x and shop.example.org/deal www.foo.net @user@mastodon.social";
const QUOTE = "i have tried every single method there is and nothing has worked for me at all";
function world() {
  n = 0;
  const rows = [];
  for (let i = 0; i < 12; i++) rows.push(row("how to manifest", { intent_score: 70 + (i % 5), post_text: (i === 0 ? QUOTE : "manifest post " + i) + (i === 1 ? " " + DIRTY : "") }));
  for (let i = 0; i < 7; i++) rows.push(row("law of assumption", { intent_score: 12 }));
  rows.push(row("living in the end", { intent_score: 95, source: "mastodon" }));
  rows.push(row("living in the end", { intent_score: 3 }));
  rows.push(row("how to manifest", { post_text: "x".repeat(900) }));
  // failed and unscored rows, in the window
  for (let i = 0; i < 6; i++) rows.push(row("does manifestation work", { status: "score_failed", intent_score: null, intent_reason: FAILED }));
  for (let i = 0; i < 6; i++) rows.push(row("does manifestation work", { status: "scored", intent_score: 0, intent_reason: FAILED }));
  rows.push(row("does manifestation work", { status: "new", intent_score: null }));
  // outside the window, undated, other themes
  for (let i = 0; i < 3; i++) rows.push(row("how to manifest", { post_created_at: ago(200) }));
  for (let i = 0; i < 8; i++) rows.push(row("how to manifest", { post_created_at: null }));
  for (let i = 0; i < 9; i++) rows.push(row("low libido", { intent_score: 40 }));
  rows.push(row("ad account disabled", { intent_score: 80 }));
  return rows;
}

const GOOD_REPLY = (kw) => "THEME: Doubt after trying | WANT: People want to know why methods fail for them and what to change. | KEYWORDS: " + kw + " | SUPPORT: 5";
function build(opts) {
  opts = opts || {};
  const rows = opts.rows || world();
  const db = fakeDb(rows);
  const prompts = [];
  const persisted = [];
  const ctx = {
    supabase: db.client, JSON, Math, Promise, Number, Object, Array, String, Date,
    nowIso: () => new Date().toISOString(), process: { env: {} },
    console: { log() {}, error() {}, warn() {} },
    requireAuth: function requireAuth() {}, requireActiveSubscription: function requireActiveSubscription() {}, aiLimiter: function aiLimiter() {},
    startToolRun: async () => ({ taskId: opts.taskId || "task-0001", complete: async (body) => { persisted.push(JSON.parse(JSON.stringify(body))); return true; }, fail: async () => {} }),
    resolvePreferredLanguage: async () => null,
    callAnthropicText: async (prompt) => {
      prompts.push(prompt);
      if (opts.modelThrows) throw new Error("model unavailable");
      return { text: typeof opts.reply === "function" ? opts.reply(prompt) : (opts.reply || GOOD_REPLY("how to manifest")) };
    }
  };
  let handler = null, middleware = null;
  ctx.app = { post(p) { if (p === ROUTE) { handler = arguments[arguments.length - 1]; middleware = [].slice.call(arguments, 1, -1).map(f => f.name); } } };
  vm.createContext(ctx);
  vm.runInContext(LIFTED, ctx);
  async function call(body, role) {
    const res = { code: 200, body: null, status(x) { this.code = x; return this; }, json(x) { this.body = JSON.parse(JSON.stringify(x)); return this; } };
    let err = null;
    await handler({ user: { id: "owner", role: role || "admin" }, body: body || {} }, res, e => { err = e; res.code = 500; });
    return { status: res.code, body: res.body, err };
  }
  return { db, prompts, persisted, call, api: ctx.api, middleware, rows };
}
const sampleBlock = (prompt) => prompt.slice(prompt.indexOf("SAMPLE:\n") + 8);
function leaks(obj, rows) {
  const text = JSON.stringify(obj);
  const found = [];
  PRIVATE_FIELDS.forEach(f => { if (text.indexOf("\"" + f + "\"") !== -1) found.push("key " + f); });
  rows.forEach(r => {
    ["author_handle", "author_did", "post_uri", "post_id", "post_cid"].forEach(f => { if (r[f] && text.indexOf(r[f]) !== -1) found.push(f + " " + r[f]); });
    if (r.post_text && r.post_text.length > 20 && text.indexOf(r.post_text) !== -1) found.push("post_text of " + r.id);
  });
  return found;
}

(async function main() {
  /* ── 1. the keyword map ───────────────────────────────────────────────── */
  console.log("\n══ 1. the keyword map ══");
  const b0 = build();
  const MAP = b0.api.DEMAND_THEME_KEYWORDS;
  check("themes are manifestation, quantum_jumping, supplements, libido, energy, bizforce",
    JSON.stringify(Object.keys(MAP)) === JSON.stringify(["manifestation", "quantum_jumping", "supplements", "libido", "energy", "bizforce"]), JSON.stringify(Object.keys(MAP)));
  const flat = [].concat.apply([], Object.values(MAP));
  check("each keyword sits in exactly one theme", flat.length === new Set(flat).size, flat.length + " vs " + new Set(flat).size);
  const biz = /const BIZFORCE_KEYWORDS = \[([\s\S]*?)\];/.exec(RADAR);
  const bizList = biz ? (biz[1].match(/"[^"]+"/g) || []).map(x => x.slice(1, -1)).sort() : [];
  check("bizforce is exactly leadRadar.js's BIZFORCE_KEYWORDS", JSON.stringify(MAP.bizforce.slice().sort()) === JSON.stringify(bizList), JSON.stringify(bizList));
  const radarKw = /const KEYWORDS = \[([\s\S]*?)\];/.exec(RADAR);
  const searched = radarKw ? (radarKw[1].match(/"[^"]+"/g) || []).map(x => x.slice(1, -1)) : [];
  check("every phrase leadRadar.js searches today has a theme", searched.length === 25 && searched.every(k => flat.indexOf(k) !== -1), JSON.stringify(searched.filter(k => flat.indexOf(k) === -1)));
  let r = await b0.call({ theme: "manifestation" });
  const q0 = b0.db.log[0];
  check("a theme reads only its keywords (.in matched_keyword)", q0 && q0.filters.some(f => f[0] === "in" && f[1] === "matched_keyword" && JSON.stringify(f[2]) === JSON.stringify(MAP.manifestation)), q0 && JSON.stringify(q0.filters).slice(0, 200));
  check("manifestation sees only manifestation keywords", r.status === 200 && r.body.measured.by_keyword.every(k => MAP.manifestation.indexOf(k.keyword) !== -1), r.status + " " + JSON.stringify(r.body && r.body.measured && r.body.measured.by_keyword));
  const ball = build();
  const rall = await ball.call({ theme: "all" });
  check("all reads every keyword, with no keyword filter", rall.status === 200 && !ball.db.log[0].filters.some(f => f[0] === "in") &&
    ["how to manifest", "low libido", "ad account disabled"].every(k => rall.body.measured.by_keyword.some(x => x.keyword === k)), JSON.stringify(rall.body && rall.body.measured.by_keyword));
  const bad = await build().call({ theme: "nonsense" });
  check("an unknown theme is a 400 listing the valid ones", bad.status === 400 && Array.isArray(bad.body.valid_themes) && bad.body.valid_themes.length === 7);
  for (const [body, label] of [[{ theme: "all", window_days: 6 }, "window_days 6"], [{ theme: "all", window_days: 366 }, "window_days 366"], [{ theme: "all", sample_size: 9 }, "sample_size 9"], [{ theme: "all", sample_size: 81 }, "sample_size 81"], [{ theme: "all", window_days: "ten" }, "window_days ten"]]) {
    const x = await build().call(body);
    check(label + ": 400", x.status === 400, x.status);
  }

  /* ── 2. the window ────────────────────────────────────────────────────── */
  console.log("\n══ 2. the window is the author's date ══");
  const m = r.body.measured;
  check("defaults: window 90 days, sample 40 requested", m.window_days === 90 && m.sample.requested === 40, JSON.stringify([m.window_days, m.sample.requested]));
  check("rows in the window: 35 (the 3 rows from 200 days ago and the 8 undated are not in it)", m.rows_in_window === 35, m.rows_in_window);
  check("undated rows are counted apart: 8", m.undated_rows === 8, m.undated_rows);
  check("dated before the window: <5 (3)", m.dated_before_window === "<5", m.dated_before_window);
  check("by_month holds no undated month", m.by_month.every(x => /^\d{4}-\d{2}$/.test(x.month)), JSON.stringify(m.by_month));
  const qs = b0.db.log.map(q => q.filters);
  check("the row read requires a date and the window start; the undated count reads is null",
    qs[0].some(f => f[0] === "not" && f[1] === "post_created_at") && qs[0].some(f => f[0] === "gte" && f[1] === "post_created_at") &&
    qs.some(fs2 => fs2.some(f => f[0] === "is" && f[1] === "post_created_at" && f[2] === null)), JSON.stringify(qs).slice(0, 300));
  const r365 = await build().call({ theme: "manifestation", window_days: 365 });
  check("window 365 takes in the 200-day rows: 38", r365.body.measured.rows_in_window === 38, r365.body.measured.rows_in_window);

  /* ── 3. "<5" ──────────────────────────────────────────────────────────── */
  console.log("\n══ 3. counts below 5 ══");
  const tiny = build({ rows: [row("ad account disabled", { intent_score: 80 })] });
  const rt = await tiny.call({ theme: "bizforce" });
  const mt = rt.body.measured;
  check("one row: rows_in_window is <5", mt.rows_in_window === "<5", mt.rows_in_window);
  check("one row: its keyword and source counts are <5", mt.by_keyword[0].rows === "<5" && mt.by_source[0].rows === "<5", JSON.stringify([mt.by_keyword, mt.by_source]));
  const smallNumbers = [];
  (function walk(v, k) {
    if (typeof v === "number" && v > 0 && v < 5 && ["window_days", "requested", "seed", "supporting_posts"].indexOf(k) === -1) smallNumbers.push(k + "=" + v);
    if (v && typeof v === "object") Object.keys(v).forEach(kk => walk(v[kk], kk));
  })(mt, "");
  check("no count from 1 to 4 appears anywhere in measured", smallNumbers.length === 0, smallNumbers.join(", "));
  check("a zero bucket is shown as <5, not 0", mt.intent_scores.buckets["0-9"] === "<5", JSON.stringify(mt.intent_scores.buckets));

  /* ── 4. real scores only ──────────────────────────────────────────────── */
  console.log("\n══ 4. real scores only ══");
  check("real scores: 22 (6 score_failed, 6 legacy 0s with the failure reason and 1 unscored are not)", m.intent_scores.real_scores === 22, m.intent_scores.real_scores);
  check("without a real score: 13", m.intent_scores.without_a_real_score === 13, m.intent_scores.without_a_real_score);
  check("buckets: 70-79 is 12, 10-19 is 8 (7 law-of-assumption rows and the long post) and 0-9 is <5 (the one real 3, none of the failed 0s)",
    m.intent_scores.buckets["70-79"] === 12 && m.intent_scores.buckets["10-19"] === 8 && m.intent_scores.buckets["0-9"] === "<5", JSON.stringify(m.intent_scores.buckets));

  /* ── 5. cleaned before the model ──────────────────────────────────────── */
  console.log("\n══ 5. what the model sees ══");
  const prompt = b0.prompts[0] || "";
  const sb = sampleBlock(prompt);
  check("one model call", b0.prompts.length === 1, b0.prompts.length);
  check("no @ anywhere in the sample", sb.indexOf("@") === -1, sb.slice(0, 200));
  check("no handle, URL, domain or email in the model input",
    !/someone\.bsky\.social|example\.com|example\.org|foo\.net|mastodon\.social|jane\.doe|https?:|www\./i.test(prompt), (prompt.match(/someone\.bsky\.social|example\.com|example\.org|foo\.net|mastodon\.social|jane\.doe|https?:|www\./i) || [])[0]);
  check("no phone number in the model input", !/555|123-4567/.test(prompt));
  check("the dirty post arrives with its placeholders", /\[someone\]/.test(sb) && /\[email\]/.test(sb) && /\[link\]/.test(sb) && /\[number\]/.test(sb), sb.slice(0, 400));
  const lines = sb.split("\n").filter(Boolean);
  check("every sampled post is at most 600 characters", lines.every(l => Array.from(l.replace(/^S\d+ \[[^\]]*\] /, "")).length <= 600) && lines.some(l => /x{600}/.test(l) && !/x{601}/.test(l)), lines.map(l => l.length).join(","));
  check("no row field reaches the model: no handle, DID, post address, ids or reasons",
    !b0.rows.some(rw => [rw.author_handle, rw.author_did, rw.post_uri, rw.post_id, rw.post_cid].some(v => prompt.indexOf(v) !== -1)) && prompt.indexOf("asks a question") === -1 && prompt.indexOf("Tongkat Ali") === -1);
  check("the cleaner on its own: handle, email, phone, URL and domain all replaced",
    b0.api.demandCleanText(DIRTY) === "Ask [someone] or mail [email] or call [number], see [link] and [link] [link] [someone]", b0.api.demandCleanText(DIRTY));

  /* ── 6. determinism ───────────────────────────────────────────────────── */
  console.log("\n══ 6. the sample is reproducible ══");
  const pA = build({ taskId: "task-A" }); await pA.call({ theme: "manifestation", sample_size: 10 });
  const pA2 = build({ taskId: "task-A" }); await pA2.call({ theme: "manifestation", sample_size: 10 });
  const pB = build({ taskId: "task-B" }); await pB.call({ theme: "manifestation", sample_size: 10 });
  check("the same run seed draws the same sample", sampleBlock(pA.prompts[0]) === sampleBlock(pA2.prompts[0]));
  check("another seed draws a different order", sampleBlock(pA.prompts[0]) !== sampleBlock(pB.prompts[0]));
  check("the seed is reported", typeof pA.persisted[0].measured.sample.seed === "number" && pA.persisted[0].measured.sample.seed === b0.api.demandSeed("task-A"));
  const kwInSample = new Set(sampleBlock(pA.prompts[0]).split("\n").filter(Boolean).map(l => /\[([^\]]+)\]/.exec(l)[1]));
  check("a sample of 10 spreads across every keyword in scope with text (4)", kwInSample.size === 4, JSON.stringify([...kwInSample]));

  /* ── 7. theme drops ───────────────────────────────────────────────────── */
  console.log("\n══ 7. theme drops ══");
  const dropReply = [
    GOOD_REPLY("how to manifest"),
    "THEME: Off topic | WANT: Something else. | KEYWORDS: low libido | SUPPORT: 3",
    "THEME: Too many | WANT: Everything. | KEYWORDS: how to manifest | SUPPORT: 999"
  ].join("\n");
  const bd = build({ reply: dropReply });
  const rd = await bd.call({ theme: "manifestation", sample_size: 10 });
  check("a theme citing no keyword in scope, and one claiming support above the sample size, are dropped: 2",
    rd.body.points_dropped === 2 && rd.body.themes.length === 1 && rd.body.themes[0].label === "Doubt after trying", JSON.stringify([rd.body.points_dropped, rd.body.themes]));
  check("a kept theme carries label, what people want, keywords and support",
    JSON.stringify(Object.keys(rd.body.themes[0])) === JSON.stringify(["label", "what_people_want", "keywords", "supporting_posts"]) && rd.body.themes[0].supporting_posts === 5);

  /* ── 8. privacy drops ─────────────────────────────────────────────────── */
  console.log("\n══ 8. privacy drops ══");
  const six = "THEME: Frustration | WANT: Some say every single method there is and they feel stuck. | KEYWORDS: how to manifest | SUPPORT: 4";
  const five = "THEME: Frustration | WANT: Some say every single method there and they feel stuck. | KEYWORDS: how to manifest | SUPPORT: 4";
  const p6 = await build({ reply: GOOD_REPLY("how to manifest") + "\n" + six }).call({ theme: "manifestation", sample_size: 40 });
  check("a theme repeating 6 consecutive words of a sampled post is removed: privacy_drops 1",
    p6.body.privacy_drops === 1 && p6.body.themes.length === 1 && p6.body.themes[0].label === "Doubt after trying", JSON.stringify([p6.body.privacy_drops, p6.body.themes && p6.body.themes.map(t => t.label)]));
  const p5 = await build({ reply: GOOD_REPLY("how to manifest") + "\n" + five }).call({ theme: "manifestation", sample_size: 40 });
  check("a 5-word overlap is kept: privacy_drops 0", p5.body.privacy_drops === 0 && p5.body.themes.length === 2, JSON.stringify([p5.body.privacy_drops, p5.body.themes && p5.body.themes.length]));

  /* ── 9. failure and refusal ───────────────────────────────────────────── */
  console.log("\n══ 9. a model failure, and a non-admin ══");
  const bf = build({ modelThrows: true });
  const rf = await bf.call({ theme: "manifestation" });
  check("a model failure: 200 with measured, themes null and explanation_error",
    rf.status === 200 && rf.body.measured && rf.body.measured.rows_in_window === 35 && rf.body.themes === null && /could not be generated/.test(rf.body.explanation_error), rf.status + " " + JSON.stringify(rf.body && rf.body.explanation_error));
  const bn = build();
  const rn = await bn.call({ theme: "manifestation" }, "user");
  check("a non-admin: 403, before anything is read", rn.status === 403 && /owner account/.test(rn.body.error) && bn.db.log.length === 0 && bn.prompts.length === 0, rn.status);
  check("the route has requireAuth, requireActiveSubscription and aiLimiter", JSON.stringify(b0.middleware) === JSON.stringify(["requireAuth", "requireActiveSubscription", "aiLimiter"]));

  /* ── 10. no row-level field ───────────────────────────────────────────── */
  console.log("\n══ 10. no row leaves ══");
  for (const [label, res, bb] of [["manifestation", r, b0], ["all", rall, ball], ["privacy case", p6, null], ["failure", rf, bf]]) {
    check(label + ": no row-level field or value in the response", leaks(res.body, world()).length === 0, leaks(res.body, world()).join("; "));
    if (bb) check(label + ": none in the persisted body either", leaks(bb.persisted[0], world()).length === 0, leaks(bb.persisted[0], world()).join("; "));
  }
  check("the response keys", JSON.stringify(Object.keys(r.body)) === JSON.stringify(["success", "theme", "measured", "themes", "explanation_error", "points_dropped", "privacy_drops", "not_measured", "provenance", "task_id", "persisted"]), JSON.stringify(Object.keys(r.body)));
  check("not_measured names the four things", r.body.not_measured.length === 4 && /authors/.test(r.body.not_measured[0]) && /represents/.test(r.body.not_measured[1]) && /never searched/.test(r.body.not_measured[2]) && /before collection/.test(r.body.not_measured[3]));

  /* ── wiring ───────────────────────────────────────────────────────────── */
  check("TOOL_INPUT_SPECS has rd/demand-signals: theme required, window_days and sample_size optional",
    /"rd\/demand-signals": \[\n    toolField\("theme", "string", true,[^\n]*\n    toolField\("window_days", "number", false,[^\n]*\n    toolField\("sample_size", "number", false,[^\n]*\n  \]/.test(SRC));
  const nonDispatch = /var CHAIN_NON_DISPATCHABLE_TOOLS = \[([^\]]*)\]/.exec(SRC);
  check("rd/demand-signals is not in CHAIN_NON_DISPATCHABLE_TOOLS (it only reads)", nonDispatch && nonDispatch[1].indexOf("rd/demand-signals") === -1);
  check("zero network", NETWORK.length === 0, JSON.stringify(NETWORK));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.error("\nThe check threw: " + (e && e.stack || e)); process.exit(1); });
