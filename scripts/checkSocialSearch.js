"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkSocialSearch — the SEO agent's Social Search measures a YouTube, TikTok
   or Instagram draft against the phrase it should be found by, in code, at the
   exact limits; refuses anything it was not given in the right shape; calls a
   model only for suggested rewrites, measures each rewrite again, and never
   calls YouTube or any other platform. Termaximus's Latest Social Search
   section carries no draft text and no phrase.

   POST /api/agents/seo/social-search, requireActiveSubscription and
   buildOracleAgentRecords are lifted from server.js with everything they call,
   and run in a vm against an in-memory Supabase, with the model stubbed to a
   queued reply and fetch and the network stubbed to record any call. TEST ROWS
   ARE ISOLATED BY CONSTRUCTION: no database, no network, no model and no
   platform is reached, and nothing is written anywhere.

   WHAT THIS PROVES
     A. Exact boundaries: title 100 / 101; description 5000 / 5001 BYTES, and
        a multi-byte description within 5000 characters but over 5000 bytes;
        tags 500 / 501 for the whole list (characters plus one comma between
        each pair); TikTok 2200 / 2201; Instagram 5 / 6 and 30 / 31 hashtags,
        each reported against both limits; YouTube description hashtags 3 / 4
        and 60 / 61.
     B. Where the phrase is: before and after the cut, straddling it, in the
        title, across a line break, in tags, and #tongkatali for "tongkat ali".
     C. Hashtags: a non-ASCII hashtag is counted; and countHashtags and
        measureSocialPost give byte-identical results to PRE_CHANGE (the
        commit before this one) on social/post's fixtures and an ASCII set.
     D. Validation: a bad platform, a missing one, an empty or 1-character or
        101-character phrase, a string boolean, tags that are not an array, a
        field from another platform, and a YouTube draft with nothing: each a
        400 naming the field, nothing read or recorded.
     E. No model call without suggest_rewrites, and none when nothing needs
        fixing; youtube_api_called false and no fetch on every path.
     F. Rewrites: each re-measured in place of its field and reported fixing
        or not fixing each finding; a rewrite with a benchmark or a views, rank
        or reach claim is dropped whole; an unreadable block is counted; a
        model failure is null with its reason.
     G. Without an active subscription: a 402, and nothing is read.
     H. Termaximus: yes/no and positions only, never the draft text, its
        hashtags or the phrase; "- none" without a run; "could not be read
        just now" on a failed read; the caller's own run only.

   MUTATE=<name> edits server.js IN MEMORY (nothing on disk is touched).
   MUTATE=all runs each in its own process; an unmatched search text is an
   ERROR, never a catch (scripts/_shared.js).
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm"), crypto = require("crypto"), net = require("net"), dns = require("dns");
const { execFileSync } = require("child_process");
const REPO = path.join(__dirname, "..");
const MUTATE = process.env.MUTATE || "";
const MUT = require("./_shared");
const s = MUT;
const { OWNER_ACCOUNT_ID } = require("../lib/ownerAccount");

const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkSocialSearch: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkSocialSearch: no network"); };

/* The commit before Social Search and the Unicode hashtag pattern. Pinned, not HEAD. */
const PRE_CHANGE = "01a1b52";

const SERVER = "server.js";
const MUTATIONS = {
  // the description is measured in characters, not bytes
  "description-in-characters": [[SERVER, "  var size = unit === \"bytes\" ? Buffer.byteLength(s, \"utf8\") : chars;", "  var size = chars;"]],
  // the tags are measured per tag (the longest), not as the whole list
  "tags-per-tag": [[SERVER, "      var total = draft.tags.reduce(function (n, t) { return n + socialSearchChars(t); }, 0) + Math.max(0, draft.tags.length - 1);",
    "      var total = draft.tags.reduce(function (n, t) { return Math.max(n, socialSearchChars(t)); }, 0);"]],
  // Instagram's newer-account 5 is no longer checked
  "instagram-5-removed": [[SERVER, "      m.hashtags.within_newer_account_limit = ch.count <= L.hashtag_max_newer_accounts;",
    "      m.hashtags.within_newer_account_limit = true;"]],
  // a missing platform is taken as YouTube
  "platform-defaulted": [[SERVER, "  var platform = b.platform;\n  if (typeof platform !== \"string\"", "  var platform = b.platform === undefined ? \"youtube\" : b.platform;\n  if (typeof platform !== \"string\""]],
  // the route loses its subscription gate
  "ungate": [[SERVER, "app.post(\"/api/agents/seo/social-search\", requireAuth, requireActiveSubscription, aiLimiter,",
    "app.post(\"/api/agents/seo/social-search\", requireAuth, aiLimiter,"]],
  // a rewrite is reported as given, never measured again
  "rewrites-not-remeasured": [[SERVER, "    var again = measureSocialSearch(platform, phrase, next);", "    var again = original;"]],
  // the ASCII-only hashtag pattern is back
  "ascii-hashtags": [[SERVER, "  var matches = String(text || \"\").match(/#\\p{L}[\\p{L}\\p{M}\\p{N}_]*/gu) || [];",
    "  var matches = String(text || \"\").match(/#[A-Za-z][A-Za-z0-9_]*/g) || [];"]],
  // Termaximus prints the stored draft's matching hashtags
  "termaximus-draft-text": [[SERVER, "    lines.push(\"- hashtags: \" + n(h.count) + \" against a practical \"",
    "    lines.push(\"- hashtags: \" + (h.matching_hashtags || []).join(\" \") + \" \" + n(h.count) + \" against a practical \""]]
};
if (MUTATE === "all") MUT.runAllMutations(__filename, Object.keys(MUTATIONS));

let SRC = fs.readFileSync(path.join(REPO, SERVER), "utf8").replace(/\r\n/g, "\n");
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [, from, to] of edits) SRC = MUT.replaceOnce(SRC, from, to, MUTATE + " in " + SERVER);
  console.log("\n!! MUTATION: " + MUTATE);
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}

/* ── lifting ──────────────────────────────────────────────────────────────── */
const MODEL_ENTRY = ["callAnthropicText", "toolGenerateWithOneRetry", "callAnthropic", "callClaude", "Anthropic", "anthropic"];
const PROMPT_STUBS = ["loadProfileForTool", "resolvePreferredLanguage", "buildLanguageInstruction", "buildAgentSystemPrompt"];
const STUBS = new Set(["supabase", "console", "process", "require", "module", "app", "requireAuth", "aiLimiter", "getUserPlan",
  "Buffer", "URL", "setTimeout", "setImmediate", "fetch", "crypto", "OWNER_ACCOUNT_ID"].concat(MODEL_ENTRY, PROMPT_STUBS));
function lifter(SOURCE) {
  const SPANS = [];
  const re = /^(?:(?:async )?function [A-Za-z_$][A-Za-z0-9_$]*[(]|app[.][a-z]+[(])/gm; let m;
  while ((m = re.exec(SOURCE))) { const end = s.braceMatch(SOURCE, SOURCE.indexOf("{", m.index)); if (end > 0) SPANS.push([m.index, end]); }
  function definitionOf(name) {
    let m2 = new RegExp("^(?:async )?function " + name + "\\(", "m").exec(SOURCE);
    if (m2) return SOURCE.slice(m2.index, s.braceMatch(SOURCE, SOURCE.indexOf(") {", m2.index) + 2));
    const re2 = new RegExp("^(?:var|const|let) " + name + "[ \t]*=[ \t]*", "gm");
    while ((m2 = re2.exec(SOURCE)) && SPANS.some(([x, y]) => m2.index > x && m2.index < y)) { /* a local */ }
    if (!m2) return null;
    const brk = /;\n/g; brk.lastIndex = m2.index + m2[0].length;
    let b;
    while ((b = brk.exec(SOURCE))) {
      const next = SOURCE[b.index + b[0].length];
      if (next === undefined || next === "\n" || /[^\s]/.test(next)) return SOURCE.slice(m2.index, b.index + 1);
    }
    return null;
  }
  return function closure(root) {
    const have = new Map();
    const queue = [...new Set(uncommented(root).match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
    while (queue.length) {
      const name = queue.shift();
      if (have.has(name) || STUBS.has(name)) continue;
      const def = definitionOf(name);
      if (!def) continue;
      try { new vm.Script(def); } catch (e) { continue; }
      have.set(name, def);
      new Set(uncommented(def).match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !STUBS.has(id)) queue.push(id); });
    }
    return { code: [...have.values()].sort((x, y) => SOURCE.indexOf(x) - SOURCE.indexOf(y)).join("\n\n") + "\n\n" + root, names: [...have.keys()] };
  };
}
const uncommented = (code) => code.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
const closure = lifter(SRC);
const PATH = "/api/agents/seo/social-search";
const SIG = 'app.post("' + PATH + '",';
const routeStart = SRC.indexOf(SIG);
if (routeStart < 0) { console.log("    FAIL  POST " + PATH + " not found"); process.exit(1); }
const ROUTE = SRC.slice(routeStart, s.braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("async function (req, res, next)", routeStart))) + 3);
const LIFT = closure(ROUTE + "\n\nthis.__api = { buildOracleAgentRecords: buildOracleAgentRecords, requireActiveSubscription: requireActiveSubscription, " +
  "countHashtags: countHashtags, measureSocialPost: measureSocialPost, SOCIAL_PLATFORMS: SOCIAL_PLATFORMS, SOCIAL_SEARCH_LIMITS: SOCIAL_SEARCH_LIMITS };");

// PRE_CHANGE's countHashtags and measureSocialPost, lifted the same way from git (execFileSync: cmd.exe never sees the ref).
const OLD_SRC = execFileSync("git", ["show", PRE_CHANGE + ":server.js"], { cwd: REPO, maxBuffer: 256 << 20 }).toString("utf8").replace(/\r\n/g, "\n");
const OLD_LIFT = lifter(OLD_SRC)("this.__api = { countHashtags: countHashtags, measureSocialPost: measureSocialPost, SOCIAL_PLATFORMS: SOCIAL_PLATFORMS };");
const NEW_POST_LIFT = closure("this.__api = { countHashtags: countHashtags, measureSocialPost: measureSocialPost, SOCIAL_PLATFORMS: SOCIAL_PLATFORMS };");
function plain(code) {
  const ctx = { console: { log() {}, error() {}, warn() {} }, Intl, Buffer };
  vm.createContext(ctx); vm.runInContext(code, ctx); return ctx.__api;
}

/* ── the fake database ────────────────────────────────────────────────────── */
function fakeDb(seed, fail) {
  const tables = {};
  Object.keys(seed).forEach(t => { tables[t] = seed[t].map(r => JSON.parse(JSON.stringify(r))); });
  const log = [];
  function test(op, v, val, extra) {
    if (op === "eq") return v === val;
    if (op === "neq") return v !== val;
    if (op === "in") return val.indexOf(v) !== -1;
    if (op === "is") return val === null ? v == null : v === val;
    if (op === "not") return extra === null && val === "is" ? v != null : true;
    if (op === "gte") return v != null && String(v) >= String(val);
    if (op === "lte") return v != null && String(v) <= String(val);
    return true;
  }
  function keep(q, row) { return q.filters.every(([op, col, val, extra]) => op === "or" ? true : test(op, row[col], val, extra)); }
  function answer(q) {
    log.push(q);
    const injected = fail && fail(q);
    if (injected === "throw") return Promise.reject(new Error("the connection dropped"));
    if (injected) return Promise.resolve({ data: null, count: null, error: injected });
    const rows = tables[q.table] || (tables[q.table] = []);
    if (q.op === "insert" || q.op === "upsert") {
      const payload = [].concat(q.payload).map(p => Object.assign({ id: crypto.randomUUID(), created_at: new Date().toISOString() }, JSON.parse(JSON.stringify(p))));
      rows.push(...payload);
      return Promise.resolve({ data: q.single ? payload[0] : payload, error: null });
    }
    if (q.op === "update") {
      const hit = rows.filter(r => keep(q, r)); hit.forEach(r => Object.assign(r, JSON.parse(JSON.stringify(q.payload))));
      return Promise.resolve({ data: hit, error: null });
    }
    if (q.op === "delete") return Promise.resolve({ data: null, error: null });
    let hits = rows.filter(r => keep(q, r));
    const order = q.mods.find(m => m[0] === "order");
    if (order) hits = hits.slice().sort((a, b) => (a[order[1]] < b[order[1]] ? -1 : a[order[1]] > b[order[1]] ? 1 : 0) * (order[2] && order[2].ascending === false ? -1 : 1));
    const total = hits.length;
    const range = q.mods.find(m => m[0] === "range"); if (range) hits = hits.slice(range[1], range[2] + 1);
    const limit = q.mods.find(m => m[0] === "limit"); if (limit) hits = hits.slice(0, limit[1]);
    const copies = hits.map(r => JSON.parse(JSON.stringify(r)));
    const count = q.opts && q.opts.count ? total : null;
    if (q.opts && q.opts.head) return Promise.resolve({ data: null, count, error: null });
    if (q.single) {
      if (copies.length > 1) return Promise.resolve({ data: null, error: { message: "multiple rows" } });
      if (!copies.length && q.single === "single") return Promise.resolve({ data: null, error: { code: "PGRST116", message: "no rows" } });
      return Promise.resolve({ data: copies[0] || null, error: null });
    }
    return Promise.resolve({ data: copies, count, error: null });
  }
  function from(table) {
    const q = { table, op: "select", cols: null, opts: null, payload: null, filters: [], mods: [], single: false };
    const b = {
      select(cols, opts) { if (q.op === "select") { q.cols = cols || "*"; q.opts = opts || null; } return b; },
      insert(p) { q.op = "insert"; q.payload = p; return b; },
      upsert(p) { q.op = "upsert"; q.payload = p; return b; },
      update(p) { q.op = "update"; q.payload = p; return b; },
      delete() { q.op = "delete"; return b; },
      not(col, op, val) { q.filters.push(["not", col, op, val]); return b; },
      or(expr) { q.filters.push(["or", expr]); return b; },
      single() { q.single = "single"; return answer(q); },
      maybeSingle() { q.single = "maybe"; return answer(q); },
      then(res, rej) { return answer(q).then(res, rej); }
    };
    ["eq", "neq", "in", "is", "gte", "lte", "gt", "lt", "like", "ilike"].forEach(op => { b[op] = function (col, val) { q.filters.push([op, col, val]); return b; }; });
    ["order", "limit", "range"].forEach(op => { b[op] = function () { q.mods.push([op].concat([].slice.call(arguments))); return b; }; });
    return b;
  }
  return { tables, log, client: { from, rpc: () => Promise.resolve({ data: null, error: { message: "no rpc" } }) } };
}

/* ── the harness ──────────────────────────────────────────────────────────── */
const OWNER = OWNER_ACCOUNT_ID;
const OTHER = "bbbbbbbb-0000-4000-8000-0000000000b2";
function context(seed, opts) {
  const o = opts || {};
  const db = fakeDb(seed || { ai_tasks: [] }, o.fail);
  const modelCalls = [], fetches = [], logs = [], handlers = {};
  const refuse = (name) => function () { modelCalls.push(name); throw new Error("checkSocialSearch: " + name + " must not be called"); };
  const rq = require("module").createRequire(path.join(REPO, "server.js"));
  const ctx = {
    supabase: db.client, require: rq, module: {}, Date, Buffer, URL, setImmediate, crypto, OWNER_ACCOUNT_ID, Intl,
    setTimeout: () => 0,
    fetch: function (url) { fetches.push(String(url)); throw new Error("checkSocialSearch: fetch must not be called"); },
    process: { env: Object.assign({ ENABLE_EMAIL_SEQUENCES: "false" }, o.env || {}) },
    console: { log: (...a) => logs.push(a.join(" ")), error: (...a) => logs.push(a.join(" ")), warn: (...a) => logs.push(a.join(" ")) },
    getUserPlan: async () => (o.plan || { active: true, plan: "pro", subscription: { status: "active" }, config: {}, exempt: false, access_reason: "subscribed" }),
    loadProfileForTool: async () => ({ business_name: "Fixture Biz" }),
    resolvePreferredLanguage: async () => null,
    buildLanguageInstruction: () => "",
    buildAgentSystemPrompt: () => "SYSTEM",
    app: { post(p) { handlers[p] = [].slice.call(arguments, 1); }, get() {}, use() {} }
  };
  MODEL_ENTRY.forEach(n => { ctx[n] = refuse(n); });
  ctx.callAnthropicText = async function (prompt, max, user, model, ledger) {
    modelCalls.push("callAnthropicText");
    ctx.__prompts = (ctx.__prompts || []).concat([prompt]);
    if (o.modelThrows) throw new Error("model-down");
    if (typeof o.modelText !== "string") throw new Error("checkSocialSearch: no model reply was queued");
    return { text: o.modelText, stopReason: "end_turn" };
  };
  ctx.requireAuth = function requireAuth(req, res, next) { next(); };
  ctx.aiLimiter = function aiLimiter(req, res, next) { next(); };
  vm.createContext(ctx);
  vm.runInContext(LIFT.code, ctx);
  return { ctx, db, modelCalls, fetches, logs, handlers };
}
async function post(body, opts) {
  const o = opts || {};
  const h = context(o.seed, o);
  const chain = h.handlers[PATH] || [];
  const req = { user: { id: o.user || OWNER, role: "user" }, body, method: "POST", route: { path: PATH }, headers: {} };
  const res = { statusCode: 200, body: null, status(c) { this.statusCode = c; return this; }, json(b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
  let error = null;
  for (let i = 0; i < chain.length; i++) {
    let advanced = false;
    await chain[i](req, res, (e) => { if (e) error = e; else advanced = true; });
    if (error || !advanced) break;
  }
  return { status: error ? 500 : res.statusCode, body: res.body, error, h, chain };
}
const ALL = [];
async function run(body, opts) { const r = await post(body, opts); ALL.push(r); return r; }
const M = (r) => (r.body && r.body.measured) || {};
const ids = (r) => (M(r).findings || []).map(f => f.id);
const a = (n, ch) => (ch || "a").repeat(n);
const tagStr = (n) => "#t" + "abcdefghijklmnopqrstuvwxyz"[n % 26] + "x" + String.fromCharCode(97 + Math.floor(n / 26));

(async function main() {
  check("the route, requireActiveSubscription and buildOracleAgentRecords were lifted",
    ["requireActiveSubscription", "buildOracleAgentRecords", "measureSocialSearch", "socialSearchInput", "remeasureSocialSearchRewrites",
      "SOCIAL_SEARCH_LIMITS", "countHashtags", "scanBenchmarkClaims", "startToolRun", "toolProvenance", "oracleSocialSearchLines"].every(n => LIFT.names.indexOf(n) !== -1),
    LIFT.names.join(","));

  /* ── A. boundaries ───────────────────────────────────────────────────── */
  console.log("\n══ A. exact boundaries ══");
  const L = context().ctx.__api.SOCIAL_SEARCH_LIMITS;
  check("A. the limits as specified: YouTube title 100, description 5000 bytes, tags 500, hashtags 3 / 60; TikTok 2200, cut 100, practical 5; Instagram 2200, cut 125, 5 and 30",
    L.youtube.title_max === 100 && L.youtube.description_max_bytes === 5000 && L.youtube.tags_max_total === 500 && L.youtube.description_hashtags_shown_by_title === 3 &&
    L.youtube.description_hashtags_ignored_over === 60 && L.youtube.title_visible_approx === 70 && L.youtube.description_visible_approx === 150 &&
    L.tiktok.caption_max === 2200 && L.tiktok.truncates_at === 100 && L.tiktok.hashtag_practical === 5 &&
    L.instagram.caption_max === 2200 && L.instagram.truncates_at === 125 && L.instagram.hashtag_max_newer_accounts === 5 && L.instagram.hashtag_max_legacy === 30,
    JSON.stringify(L));
  let r = await run({ platform: "youtube", target_phrase: "wool hat", title: "wool hat " + a(91) });
  check("A. a 100-character title is within the limit", r.status === 200 && M(r).title.length === 100 && M(r).title.within_limit === true && M(r).title.over_by === 0, JSON.stringify(M(r).title));
  r = await run({ platform: "youtube", target_phrase: "wool hat", title: "wool hat " + a(92) });
  check("A. a 101-character title is over by 1, and title_over_limit is a finding", M(r).title.within_limit === false && M(r).title.over_by === 1 && ids(r).indexOf("title_over_limit") !== -1, JSON.stringify(M(r).title));
  r = await run({ platform: "youtube", target_phrase: "wool hat", title: "wool hat " + a(90) + "\u{1F9F6}" });
  check("A. an emoji counts once: 'wool hat ' + 90 + an emoji is 100 characters, within", M(r).title.length === 100 && M(r).title.within_limit === true, JSON.stringify(M(r).title));
  r = await run({ platform: "youtube", target_phrase: "wool hat", description: "wool hat " + a(4991) });
  check("A. a 5000-byte description is within: 5000 bytes, 5000 characters", M(r).description.bytes === 5000 && M(r).description.length === 5000 && M(r).description.within_limit === true, JSON.stringify(M(r).description).slice(0, 300));
  r = await run({ platform: "youtube", target_phrase: "wool hat", description: "wool hat " + a(4992) });
  check("A. a 5001-byte description is over by 1 byte", M(r).description.bytes === 5001 && M(r).description.within_limit === false && M(r).description.over_by === 1 && ids(r).indexOf("description_over_limit") !== -1);
  r = await run({ platform: "youtube", target_phrase: "wool hat", description: "wool hat " + a(2600, "é") });
  check("A. multi-byte: 2609 characters (within 5000) but 5209 bytes, so over by 209 bytes",
    M(r).description.length === 2609 && M(r).description.bytes === 5209 && M(r).description.within_limit === false && M(r).description.over_by === 209 &&
    M(r).description.limit_bytes === 5000, JSON.stringify(M(r).description).slice(0, 300));
  const tags500 = [a(100, "a"), a(100, "b"), a(100, "c"), a(100, "d"), a(96, "e")];
  r = await run({ platform: "youtube", target_phrase: "wool hat", tags: tags500 });
  check("A. tags at exactly 500 for the list (496 characters + 4 commas) are within, and the counting rule is stated",
    M(r).tags.total_characters === 500 && M(r).tags.within_limit === true && M(r).tags.count === 5 && /plus one comma between each pair/.test(M(r).tags.counted_as), JSON.stringify(M(r).tags));
  r = await run({ platform: "youtube", target_phrase: "wool hat", tags: tags500.slice(0, 4).concat([a(97, "e")]) });
  check("A. tags at 501 are over by 1, and tags_over_limit is a finding (no single tag is over 100)",
    M(r).tags.total_characters === 501 && M(r).tags.within_limit === false && M(r).tags.over_by === 1 && ids(r).indexOf("tags_over_limit") !== -1, JSON.stringify(M(r).tags));
  r = await run({ platform: "tiktok", target_phrase: "wool hat", caption: "wool hat " + a(2191) });
  check("A. a 2200-character TikTok caption is within", M(r).caption.length === 2200 && M(r).caption.within_limit === true && M(r).caption.limit === 2200);
  r = await run({ platform: "tiktok", target_phrase: "wool hat", caption: "wool hat " + a(2192) });
  check("A. a 2201-character TikTok caption is over by 1, and 2101 characters are hidden by the cut at 100",
    M(r).caption.within_limit === false && M(r).caption.over_by === 1 && M(r).caption.hidden_by_truncation === 2101 && ids(r).indexOf("caption_over_limit") !== -1, JSON.stringify(M(r).caption).slice(0, 300));
  const ig = (n) => ({ platform: "instagram", target_phrase: "wool hat", caption: "wool hat " + Array.from({ length: n }, (_, i) => tagStr(i)).join(" ") });
  const ig5 = await run(ig(5)), ig6 = await run(ig(6)), ig30 = await run(ig(30)), ig31 = await run(ig(31));
  check("A. Instagram 5 hashtags: within the newer-account 5 and the legacy 30, no hashtag finding",
    M(ig5).hashtags.count === 5 && M(ig5).hashtags.within_newer_account_limit === true && M(ig5).hashtags.within_legacy_limit === true && !ids(ig5).some(x => /hashtags/.test(x)), JSON.stringify(M(ig5).hashtags));
  check("A. Instagram 6: over the newer-account 5, within the legacy 30, and the finding says so",
    M(ig6).hashtags.count === 6 && M(ig6).hashtags.within_newer_account_limit === false && M(ig6).hashtags.within_legacy_limit === true &&
    ids(ig6).indexOf("hashtags_over_newer_account_limit") !== -1, JSON.stringify(M(ig6).hashtags));
  check("A. Instagram 30: within the legacy limit", M(ig30).hashtags.count === 30 && M(ig30).hashtags.within_legacy_limit === true && M(ig30).hashtags.within_newer_account_limit === false);
  check("A. Instagram 31: over both, and the finding is the legacy one", M(ig31).hashtags.count === 31 && M(ig31).hashtags.within_legacy_limit === false &&
    ids(ig31).indexOf("hashtags_over_legacy_limit") !== -1);
  check("A. Instagram says plainly that the limit varies by account", /varies by account: 30 on older accounts, and reported as 5 on newer ones/.test(M(ig6).hashtags.limit_varies_by_account || "") &&
    (ig6.body.limits.sources || []).some(x => /varies by account/.test(x)));
  const ytTags = (n) => ({ platform: "youtube", target_phrase: "wool hat", description: "wool hat " + Array.from({ length: n }, (_, i) => tagStr(i)).join(" ") });
  const yh3 = await run(ytTags(3)), yh4 = await run(ytTags(4)), yh60 = await run(ytTags(60)), yh61 = await run(ytTags(61));
  check("A. YouTube description hashtags: 3 may all show by the title, 4 may not", M(yh3).description_hashtags.within_shown_by_title === true && M(yh4).description_hashtags.within_shown_by_title === false &&
    ids(yh4).indexOf("hashtags_over_practical") !== -1);
  check("A. YouTube 60 hashtags are not all ignored; 61 are, and the finding says so", M(yh60).description_hashtags.all_ignored === false && M(yh61).description_hashtags.all_ignored === true &&
    ids(yh61).indexOf("description_hashtags_all_ignored") !== -1, JSON.stringify(M(yh61).description_hashtags).slice(0, 200));
  check("A. the YouTube cuts are labelled approximate; TikTok's and Instagram's are not", M(r).caption.cut_is_approximate === false && M(yh3).description.cut_is_approximate === true);

  /* ── B. where the phrase is ──────────────────────────────────────────── */
  console.log("\n══ B. where the phrase is ══");
  r = await run({ platform: "tiktok", target_phrase: "Tongkat Ali", caption: "Is tongkat ali worth it? " + a(200) });
  check("B. before the cut: first index 3, before_cut true, not in the body, no phrase finding",
    M(r).caption.phrase_first_index === 3 && M(r).caption.phrase_first_before_cut === true && M(r).found.before_cut === true && M(r).found.body === false &&
    ids(r).indexOf("phrase_not_before_cut") === -1, JSON.stringify(M(r).found));
  r = await run({ platform: "tiktok", target_phrase: "tongkat ali", caption: a(150) + " tongkat ali" });
  check("B. after the cut: first index 151 against the cut at 100, in the body, and the finding names the cut",
    M(r).caption.phrase_first_index === 151 && M(r).caption.phrase_first_before_cut === false && M(r).found.before_cut === false && M(r).found.body === true &&
    ids(r).indexOf("phrase_not_before_cut") !== -1, JSON.stringify(M(r).caption).slice(0, 300));
  r = await run({ platform: "tiktok", target_phrase: "tongkat ali", caption: a(94) + " tongkat ali" });
  check("B. straddling the cut (starts at 95, ends at 106) is not before it", M(r).caption.phrase_first_index === 95 && M(r).caption.phrase_first_before_cut === false);
  r = await run({ platform: "instagram", target_phrase: "tongkat ali", caption: "Morning routine\n\nTongkat\n  Ali in my coffee" });
  check("B. case-insensitive across a line break and extra spaces: found at 17, before the cut", M(r).caption.phrase_first_index === 17 && M(r).found.before_cut === true);
  r = await run({ platform: "instagram", target_phrase: "tongkat ali", caption: "My routine #TongkatAli #morning" });
  check("B. #TongkatAli matches \"tongkat ali\" with its space stripped; the words themselves are not in the text",
    M(r).found.hashtags === true && JSON.stringify(M(r).hashtags.matching_hashtags) === JSON.stringify(["#TongkatAli"]) && M(r).caption.phrase_occurrences === 0 &&
    ids(r).indexOf("phrase_not_found") === -1, JSON.stringify(M(r).hashtags));
  r = await run({ platform: "youtube", target_phrase: "tongkat ali", title: "Does Tongkat Ali work?", tags: ["supplements", "tongkat ali review"] });
  check("B. YouTube: in the title at 5, before its approximate 70, and in a tag", M(r).found.title === true && M(r).title.phrase_first_index === 5 &&
    M(r).title.phrase_first_before_cut === true && M(r).found.tags === true && M(r).tags.phrase_in_tags === true, JSON.stringify(M(r).found));
  r = await run({ platform: "youtube", target_phrase: "tongkat ali", title: a(75) + " tongkat ali" });
  check("B. YouTube: in the title but past about 70, so the finding says it ends past the usual cut (approximate)", ids(r).indexOf("phrase_after_title_cut") !== -1 && M(r).title.cut_is_approximate === true);
  r = await run({ platform: "youtube", target_phrase: "tongkat ali", title: "Morning routine" });
  check("B. not anywhere: phrase_not_in_title and phrase_not_found; what was not given is null with its reason",
    ids(r).indexOf("phrase_not_in_title") !== -1 && ids(r).indexOf("phrase_not_found") !== -1 && M(r).description === null && /no description was given/.test(M(r).description_reason || "") &&
    M(r).found.tags === null && /no tags were given|no tags was given/.test(M(r).found.tags_reason || ""), JSON.stringify(M(r)).slice(0, 300));
  const regexPhrase = await run({ platform: "tiktok", target_phrase: "c++ (tips)", caption: "Learn c++ (tips) today" });
  check("B. a phrase with regex characters is matched literally", M(regexPhrase).caption.phrase_first_index === 6, JSON.stringify(M(regexPhrase).caption).slice(0, 200));

  /* ── C. hashtags ─────────────────────────────────────────────────────── */
  console.log("\n══ C. hashtags ══");
  r = await run({ platform: "instagram", target_phrase: "wool hat", caption: "wool hat #café #日本 #über #हिन्दी #1 bestseller" });
  check("C. non-ASCII hashtags are counted: #café #日本 #über #हिन्दी are 4, and #1 is not one",
    M(r).hashtags.count === 4 && M(r).hashtags.unique_count === 4, JSON.stringify(M(r).hashtags));
  const NEWP = plain(NEW_POST_LIFT.code), OLDP = plain(OLD_LIFT.code);
  check("C. the new pattern counts #café whole: \"#café\", not \"#caf\"", JSON.stringify(NEWP.countHashtags("#café").unique) === JSON.stringify(["#café"]) &&
    JSON.stringify(OLDP.countHashtags("#café").unique) === JSON.stringify(["#caf"]));
  const SHARED_POST = /POST: ([^\n]*)/.exec(MUT.F["social/post"].model)[1];
  const BLUESKY_SRC = fs.readFileSync(path.join(__dirname, "checkSocialBlueskyPublish.js"), "utf8");
  const bctx = {}; vm.createContext(bctx);
  vm.runInContext(["const FAMILY", "const LINK", "const POST"].map(k => BLUESKY_SRC.match(new RegExp("^" + k + " = [^\\n]*", "m"))[0]).join("\n") + "\nthis.out = [FAMILY, POST];", bctx);
  const FIXTURES = [SHARED_POST, bctx.out[1], bctx.out[0].repeat(300), bctx.out[0].repeat(301), bctx.out[0],
    "#1 bestseller #Wool #wool #knit_hat2 ##double # #x", "Our new colourway is here. #wool #knit #handmade #winter #cosy #gift",
    "No hashtags at all.", "", "#a1 #b_2 #C3 text #a1", "#ad on every post"].concat(Object.keys(MUT.F).map(k => MUT.F[k].model).filter(t => typeof t === "string"));
  const diffs = [];
  FIXTURES.forEach((text, i) => {
    if (JSON.stringify(OLDP.countHashtags(text)) !== JSON.stringify(NEWP.countHashtags(text))) diffs.push("countHashtags #" + i);
    Object.keys(OLDP.SOCIAL_PLATFORMS).forEach(p => {
      if (JSON.stringify(OLDP.measureSocialPost(text, OLDP.SOCIAL_PLATFORMS[p])) !== JSON.stringify(NEWP.measureSocialPost(text, NEWP.SOCIAL_PLATFORMS[p]))) diffs.push("measureSocialPost #" + i + " " + p);
    });
  });
  check("C. social/post unchanged: countHashtags and measureSocialPost byte-identical to " + PRE_CHANGE + " on " + FIXTURES.length + " fixtures × " +
    Object.keys(OLDP.SOCIAL_PLATFORMS).length + " platforms (social/post's, checkSocialBlueskyPublish's, an ASCII set)", diffs.length === 0, diffs.join(", "));
  check("C. SOCIAL_PLATFORMS' numbers are unchanged from " + PRE_CHANGE + "; only Instagram's note differs",
    JSON.stringify(Object.keys(OLDP.SOCIAL_PLATFORMS).map(p => Object.assign({}, OLDP.SOCIAL_PLATFORMS[p], { note: null }))) ===
    JSON.stringify(Object.keys(NEWP.SOCIAL_PLATFORMS).map(p => Object.assign({}, NEWP.SOCIAL_PLATFORMS[p], { note: null }))) &&
    Object.keys(OLDP.SOCIAL_PLATFORMS).filter(p => OLDP.SOCIAL_PLATFORMS[p].note !== NEWP.SOCIAL_PLATFORMS[p].note).join(",") === "instagram");
  check("C. Instagram's note keeps 2,200 and 125 and says 30 on older accounts and reported as 5 on newer ones",
    /2,200 characters is enforced/.test(NEWP.SOCIAL_PLATFORMS.instagram.note) && /125 characters/.test(NEWP.SOCIAL_PLATFORMS.instagram.note) &&
    /varies by account: 30 on older accounts, and reported as 5 on newer ones/.test(NEWP.SOCIAL_PLATFORMS.instagram.note) && !/30 hashtags is the enforced maximum/.test(NEWP.SOCIAL_PLATFORMS.instagram.note),
    NEWP.SOCIAL_PLATFORMS.instagram.note);

  /* ── D. validation ───────────────────────────────────────────────────── */
  console.log("\n══ D. refused, never coerced ══");
  const BAD = [
    ["platform", { platform: "facebook", target_phrase: "wool hat", caption: "x" }],
    ["platform", { target_phrase: "wool hat", caption: "wool hat" }],
    ["platform", { platform: "YouTube", target_phrase: "wool hat", title: "x" }],
    ["target_phrase", { platform: "tiktok", target_phrase: "", caption: "x" }],
    ["target_phrase", { platform: "tiktok", target_phrase: "a", caption: "x" }],
    ["target_phrase", { platform: "tiktok", target_phrase: a(101), caption: "x" }],
    ["target_phrase", { platform: "tiktok", caption: "x" }],
    ["suggest_rewrites", { platform: "tiktok", target_phrase: "wool hat", caption: "x", suggest_rewrites: "true" }],
    ["suggest_rewrites", { platform: "tiktok", target_phrase: "wool hat", caption: "x", suggest_rewrites: 1 }],
    ["tags", { platform: "youtube", target_phrase: "wool hat", tags: "wool, hat" }],
    ["tags", { platform: "youtube", target_phrase: "wool hat", tags: ["wool", ""] }],
    ["tags", { platform: "youtube", target_phrase: "wool hat", tags: ["wool", 5] }],
    ["caption", { platform: "youtube", target_phrase: "wool hat", caption: "wool hat" }],
    ["title", { platform: "tiktok", target_phrase: "wool hat", caption: "x", title: "x" }],
    ["caption", { platform: "instagram", target_phrase: "wool hat" }],
    ["caption", { platform: "instagram", target_phrase: "wool hat", caption: 42 }],
    ["title", { platform: "youtube", target_phrase: "wool hat" }]
  ];
  for (const [field, body] of BAD) {
    const rv = await run(body);
    check("D. " + JSON.stringify(body).slice(0, 90) + " → 400 naming " + field + ", nothing read or recorded",
      rv.status === 400 && rv.body && rv.body.field === field && rv.body.error.indexOf(field) !== -1 && rv.h.db.log.length === 0 && rv.h.modelCalls.length === 0,
      rv.status + " " + JSON.stringify(rv.body));
  }
  r = await run({ platform: "tiktok", target_phrase: "wool hat", caption: "wool hat", suggest_rewrites: false });
  check("D. suggest_rewrites false is accepted, and absent is false", r.status === 200 && r.h.modelCalls.length === 0 && !("suggested_rewrites" in r.body));

  /* ── E. no model, no YouTube ─────────────────────────────────────────── */
  console.log("\n══ E. no model without rewrites; YouTube never called ══");
  const plainRuns = ALL.filter(x => x.status === 200);
  check("E. no model call on any run without suggest_rewrites (" + plainRuns.length + " runs)", plainRuns.every(x => x.h.modelCalls.length === 0));
  check("E. every response says model_call_made false, youtube_api_called false, search_data_read false, and inferred nothing",
    plainRuns.every(x => x.body.provenance.model_call_made === false && x.body.provenance.youtube_api_called === false && x.body.provenance.search_data_read === false &&
      x.body.provenance.inferred_by_model.length === 0 && /Model called: no\./.test(x.body.provenance.caveat)));
  check("E. not_measured names search volume, ranking, competition, reach and any platform's search data",
    ["Search volume", "Ranking", "Competition", "Reach", "Any platform's search data"].every(p => plainRuns[0].body.limitations.not_measured.some(x => x.indexOf(p) === 0)));
  r = await run({ platform: "tiktok", target_phrase: "wool hat", caption: "wool hat, warm and soft", suggest_rewrites: true });
  check("E. suggest_rewrites with nothing to fix: no model call, an empty list and a note saying why", r.status === 200 && r.h.modelCalls.length === 0 &&
    Array.isArray(r.body.suggested_rewrites) && r.body.suggested_rewrites.length === 0 && /Nothing was found to fix/.test(r.body.suggested_rewrites_note || "") &&
    r.body.provenance.model_call_made === false);

  /* ── F. rewrites ─────────────────────────────────────────────────────── */
  console.log("\n══ F. rewrites, measured again ══");
  const MODEL = [
    "FIELD: title\nREWRITE: Tongkat Ali: does it work? An honest look\nNOTE: Moves the phrase to the start and cuts the title under 100.",
    "FIELD: description\nREWRITE: " + a(200) + " tongkat ali comes late here.\nNOTE: Keeps the description short.",
    "FIELD: tags\nREWRITE: tongkat ali, supplements, honest review\nNOTE: Adds the phrase as a tag.",
    "FIELD: title\nREWRITE: Tongkat Ali tips that get more views\nNOTE: A stronger hook.",
    "FIELD: description\nREWRITE: tongkat ali, explained.\nNOTE: The industry average conversion rate is 2.35% for videos like this.",
    "FIELD: caption\nREWRITE: tongkat ali\nNOTE: Not a YouTube field."
  ].join("\n---\n");
  const yt = { platform: "youtube", target_phrase: "tongkat ali", title: "My morning routine with lots of words " + a(80), description: a(300) + " tongkat ali", suggest_rewrites: true };
  const rr = await run(yt, { modelText: MODEL });
  const rw = rr.body && rr.body.suggested_rewrites || [];
  const byField = (f) => rw.filter(x => x.field === f);
  const fixed = (x, id) => ((x.remeasured.findings.find(f => f.id === id)) || {}).fixed;
  check("F. one model call, through callAnthropicText, and provenance says so", rr.status === 200 && rr.h.modelCalls.length === 1 && rr.body.provenance.model_call_made === true &&
    rr.body.provenance.youtube_api_called === false && rr.body.provenance.inferred_by_model.length > 0, rr.status + " " + rr.h.modelCalls.join(","));
  check("F. the original findings: title over 100, phrase not in the title, phrase not before the description cut",
    ["title_over_limit", "phrase_not_in_title", "phrase_not_before_description_cut"].every(id => ids(rr).indexOf(id) !== -1), ids(rr).join(","));
  check("F. three rewrites kept (title, description, tags), each marked suggested_by_model", rw.length === 3 && rw.every(x => x.suggested_by_model === true) &&
    byField("title").length === 1 && byField("description").length === 1 && byField("tags").length === 1, JSON.stringify(rw.map(x => x.field)));
  const tr = byField("title")[0] || { remeasured: { findings: [] } };
  check("F. the title rewrite, measured again, fixes title_over_limit and phrase_not_in_title, and not the description's finding",
    fixed(tr, "title_over_limit") === true && fixed(tr, "phrase_not_in_title") === true && fixed(tr, "phrase_not_before_description_cut") === false, JSON.stringify(tr.remeasured));
  const dr = byField("description")[0] || { remeasured: { findings: [] } };
  check("F. the description rewrite still has the phrase past the cut, so it does not fix that finding", fixed(dr, "phrase_not_before_description_cut") === false, JSON.stringify(dr.remeasured));
  const tg = byField("tags")[0] || { remeasured: { findings: [] }, rewrite: null };
  check("F. the tags rewrite is split into an array and measured as tags", JSON.stringify(tg.rewrite) === JSON.stringify(["tongkat ali", "supplements", "honest review"]));
  check("F. the views claim and the benchmark are dropped whole, with what each claimed",
    M(rr).rewrites_dropped === 2 && M(rr).rewrites_dropped_for.some(d => /views, rank or reach/.test(d.problems.join(" "))) &&
    M(rr).rewrites_dropped_for.some(d => d.problems.some(p => !/views, rank or reach/.test(p))) && rw.every(x => !/more views|2\.35/.test(x.rewrite + x.note)), JSON.stringify(M(rr).rewrites_dropped_for));
  check("F. the block for a field YouTube does not have is counted unreadable", M(rr).rewrite_blocks_unreadable === 1, M(rr).rewrite_blocks_unreadable);
  check("F. the prompt forbids views, ranking and reach claims and gives the findings", /Do not claim or predict views, ranking, reach/.test((rr.h.ctx.__prompts || [])[0] || "") &&
    /title_over_limit/.test((rr.h.ctx.__prompts || [])[0] || ""));
  const rf = await run(yt, { modelThrows: true });
  check("F. a model failure: 200, suggested_rewrites null with its reason, the measurement intact", rf.status === 200 && rf.body.suggested_rewrites === null &&
    /could not be reached/.test(rf.body.suggested_rewrites_reason || "") && ids(rf).indexOf("title_over_limit") !== -1);
  check("E. no fetch and no network on any path, rewrites included", ALL.every(x => x.h.fetches.length === 0) && NETWORK.length === 0, NETWORK.join(","));
  const routeCode = uncommented(closure(ROUTE).code);
  check("E. nothing reachable from the route names a YouTube or platform endpoint, or fetch", !/googleapis|youtube\/v3|graph\.facebook|open\.tiktokapis|\bfetch\(/.test(routeCode));

  /* ── G. the gate ─────────────────────────────────────────────────────── */
  console.log("\n══ G. no free tier ══");
  const rj = await post({ platform: "tiktok", target_phrase: "wool hat", caption: "wool hat" }, { plan: { active: false, plan: null, subscription: null, config: null, exempt: false, access_reason: "no_subscription" } });
  check("G. without an active subscription: 402, and no ai_tasks row", rj.status === 402 && !rj.h.db.log.some(q => q.table === "ai_tasks"), rj.status);
  check("G. the gate in front of the handler is the real requireActiveSubscription", rr.chain.some(f => f === rr.h.ctx.__api.requireActiveSubscription));

  /* ── H. Termaximus ───────────────────────────────────────────────────── */
  console.log("\n══ H. Termaximus ══");
  const TITLE = "Latest Social Search (counts only)";
  async function records(seed, who, fail) {
    const h = context(seed, { fail });
    const failed = [];
    const text = await h.ctx.__api.buildOracleAgentRecords(who || OWNER, (what) => failed.push(what));
    const i = text.indexOf(TITLE);
    const rest = i === -1 ? "" : text.slice(i);
    const nx = rest.slice(TITLE.length).search(/\n[A-Z][^\n]*?:/);
    return { section: nx < 0 ? rest : rest.slice(0, TITLE.length + nx), failed, log: h.db.log };
  }
  const DRAFT_TITLE = "Secret Draft Title About Tongkat Ali";
  const stored = await run({ platform: "youtube", target_phrase: "tongkat ali", title: DRAFT_TITLE, description: "Uniquedescriptionword tongkat ali #TongkatAli #Uniquehashtag",
    tags: ["uniquetagword", "tongkat ali"] });
  const row = stored.h.db.tables.ai_tasks.find(t => t.task_type === "seo/social-search" && t.output);
  check("H. the run was stored on ai_tasks with its output", !!row && row.user_id === OWNER);
  const seed = { ai_tasks: [row, { id: "acacacac-0000-4000-8000-000000000001", user_id: OTHER, task_type: "seo/social-search", status: "completed", created_at: new Date().toISOString(),
    output: { measured: { platform: "tiktok", found: { before_cut: true }, caption: { phrase_first_index: 999, cut_at: 100, within_limit: true }, hashtags: { count: 999, practical: 5 } } } }] };
  const k1 = await records(seed);
  check("H. the section: platform and yes/no for title, before the cut, body, hashtags and tags",
    /- \d{4}-\d{2}-\d{2}: YouTube; phrase in the title: yes; before the cut: yes; in the body: no; in hashtags: yes; in tags: yes/.test(k1.section), k1.section);
  check("H. first positions against the cuts, lengths within limits, and hashtags against the practical number",
    /- title: first position 25 against the cut at 70 \(approximate\); within its limit: yes/.test(k1.section) &&
    /- description: first position 22 against the cut at 150 \(approximate\); within its limit: yes/.test(k1.section) &&
    /- tags: within the 500 for the list: yes/.test(k1.section) && /- hashtags: 2 against a practical 3/.test(k1.section), k1.section);
  const leaks = [DRAFT_TITLE, "Secret", "Uniquedescriptionword", "Uniquehashtag", "#TongkatAli", "uniquetagword", "tongkat ali", "Tongkat Ali"].filter(x => k1.section.toLowerCase().indexOf(x.toLowerCase()) !== -1);
  check("H. no draft text, no hashtag and no phrase in the section", leaks.length === 0, leaks.join(", "));
  check("H. the caller's run only: the other account's 999 is not shown, and the read filters on the caller's user_id",
    k1.section.indexOf("999") === -1 && k1.log.filter(q => q.table === "ai_tasks" && q.filters.some(f => f[1] === "task_type" && f[2] === "seo/social-search"))
      .every(q => q.filters.some(f => f[0] === "eq" && f[1] === "user_id" && f[2] === OWNER)));
  const k0 = await records({ ai_tasks: [] });
  check("H. no run yet: \"- none\"", /^Latest Social Search \(counts only\):\n- none/.test(k0.section), k0.section);
  for (const how of ["error", "throw"]) {
    const kf = await records(seed, OWNER, q => q.table === "ai_tasks" && q.filters.some(f => f[1] === "task_type" && f[2] === "seo/social-search")
      ? (how === "throw" ? "throw" : { message: "permission denied" }) : null);
    check("H. a failed read (" + how + ") says it could not be read, never a count",
      /^Latest Social Search \(counts only\): could not be read just now\./.test(kf.section) && !/first position/.test(kf.section) && kf.failed.some(f => /Latest Social Search/.test(f)), kf.section);
  }
  const kt = await records({ ai_tasks: [{ id: "acacacac-0000-4000-8000-000000000002", user_id: OWNER, task_type: "seo/social-search", status: "completed", created_at: new Date().toISOString(),
    output: { measured: { platform: "tiktok", found: { before_cut: false, body: true, hashtags: null }, caption: { phrase_first_index: 151, cut_at: 100, cut_is_approximate: false, within_limit: false }, hashtags: { count: 7, practical: 5 } } } }] });
  check("H. TikTok: no title line, the position past the cut, a null as \"not measured\"",
    /TikTok; phrase in the title: no title on this platform; before the cut: no; in the body: yes; in hashtags: not measured/.test(kt.section) &&
    /- caption: first position 151 against the cut at 100; within its limit: no/.test(kt.section) && /- hashtags: 7 against a practical 5/.test(kt.section), kt.section);

  console.log("\n" + (failures ? failures + " FAILED, " + passes + " passed" : "ALL " + passes + " CHECKS PASSED"));
  process.exit(failures ? 1 : 0);
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack)); process.exit(1); });
