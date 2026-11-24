"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkDemandSignals — the radar read as demand evidence, without reading out
   a person.

   POST /api/agents/rd/demand-signals is lifted from server.js and run in a vm
   against a fake Supabase holding member_leads rows (NAMED Nov 23 2026, LR-2:
   BEFORE bsky_leads, the owner's shared pool), with startToolRun recording
   the persisted body and callAnthropicText a stub that records every prompt
   and answers what each case needs. No network, no model, no database.

   WHAT THIS PROVES
     1. The themes (NAMED Nov 23 2026, LR-2: BEFORE a fixed keyword map with
        a bizforce theme equal to leadRadar.js's BIZFORCE_KEYWORDS): a theme is
        one word of the member's own Fingerprint, or "all"; a word reads only
        its own rows; "all" reads every row of the member's, and never another
        member's.
     2. The window is the author's date: rows outside it are not in scope,
        undated rows are counted apart and appear in no month and no sample.
     3. "<5": every count from 0 to 4 is shown as "<5", never the number.
     4. Real scores only: a score that could not be read (stored as 0 with no
        reason), a lead still waiting to be scored and an unscored row are
        never bucketed as scores.
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
        explanation_error. NAMED (Nov 23 2026, LR-2): BEFORE a non-owner was
        refused 403; AFTER every member reads their own leads, and the
        member's sales>rd link switched off refuses (G26) before anything is read.
    10. No row-level field anywhere in the response or the persisted body.
    11. No YouTube row is read: every query filters source 'youtube' out in
        the query itself, so a YouTube row is in no count, no month, no
        sample and no prompt, and not_measured says why.
     And zero network.

   NAMED BEFORE → AFTER (YouTube retention build, Oct 2026, assertions changed
   on purpose): "not_measured names the four things" now names five, the
   fifth being that YouTube is excluded because YouTube's API terms forbid
   combining its data with other sources. The fixture gains three YouTube
   rows (in the window, before it, and undated); every count asserted
   elsewhere is unchanged, which is itself the proof they are not read.

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
  // NAMED (Nov 23 2026, LR-2): BEFORE the mutation counted a non-null score or status score_failed, which no member_leads row has
  // (it survived); AFTER every row whose status is scored counts, so a score that could not be read is bucketed again.
  "include-failed-scores": [["    if (leadHasRealScore(r)) {\n      real++;", "    if (r.status === \"scored\") {\n      real++;"]],
  // NAMED (Nov 23 2026, LR-2): a score that could not be read (score null, SCORE_UNREAD_REASON) is read as still waiting (new), as the
  // first LR-2 demandRowOf did (BEFORE anchored on its 0-with-no-reason line)
  "unread-score-real": [["  var scored = !!l.scored_at;\n", "  var scored = !!l.scored_at && typeof l.score === \"number\";\n"]],
  // NAMED (Nov 23 2026, LR-2): another member's leads are read
  "reads-other-members": [["    q = q.eq(\"user_id\", userId).neq(\"source\", DEMAND_EXCLUDED_SOURCE)", "    q = q.neq(\"source\", DEMAND_EXCLUDED_SOURCE)"]],
  // NAMED (Nov 23 2026, LR-2): a word outside the member's Fingerprint is accepted as a theme
  "any-theme": [["      if (demandThemes.indexOf(theme) === -1) {", "      if (!theme) {"]],
  // the response carries the sampled post text
  // the source filter is gone, and YouTube rows are read again
  // NAMED (Nov 23 2026, LR-1): BEFORE the anchor was the source filter alone; LR-1 chained the archived filter onto the same line.
  // NAMED (Nov 23 2026, LR-2): BEFORE the anchor was the bsky_leads filter line (LR-1). AFTER the member_leads line, which starts with the member.
  "reads-youtube": [["    q = q.eq(\"user_id\", userId).neq(\"source\", DEMAND_EXCLUDED_SOURCE).neq(\"status\", \"archived\");", "    q = q.eq(\"user_id\", userId).neq(\"status\", \"archived\");"]],
  // NAMED (Nov 23 2026, LR-1): archived rows (scripts/oneoff/lr1Archive.js) are read again
  "reads-archived": [["    q = q.eq(\"user_id\", userId).neq(\"source\", DEMAND_EXCLUDED_SOURCE).neq(\"status\", \"archived\");", "    q = q.eq(\"user_id\", userId).neq(\"source\", DEMAND_EXCLUDED_SOURCE);"]],
  // NAMED (Nov 23 2026, LR-2): BEFORE "admin-by-role" (the owner test, gone). AFTER the sales>rd link test is skipped
  "ignores-link": [["      if (await memberLinkOff(userId, \"sales\", \"rd\")) {", "      if (false) {"]],
  "return-post-text": [["        not_measured: DEMAND_NOT_MEASURED,\n", "        not_measured: DEMAND_NOT_MEASURED,\n        sample_posts: loaded.rows.slice(0, 3).map(function (r) { return { post_text: r.post_text }; }),\n"]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

let SRC = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
const RADAR = fs.readFileSync(path.join(REPO, "leadRadar.js"), "utf8").replace(/\r\n/g, "\n");   // NAMED (Nov 23 2026, LR-2): read to prove it holds no keyword list
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
  "requireAuth", "requireActiveSubscription", "aiLimiter", "startToolRun", "callAnthropicText", "resolvePreferredLanguage", "Date", "stripe", "Stripe",
  "OWNER_ACCOUNT_ID", "recordGateDecision"]);   // NAMED (Nov 23 2026, LR-2): + recordGateDecision, recorded by the fake. LR-1: the owner's id, stubbed as "owner". LR-2: the route no longer tests it; kept as a stub
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
// NAMED (Nov 23 2026, LR-2): BEFORE the api exposed DEMAND_THEME_KEYWORDS, which LR-2 removed (themes are the member's Fingerprint words).
const LIFTED = closure(routeText() + "\n\nthis.api = { demandSample: demandSample, " +
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
      if (op === "neq") return r[col] !== a;
      if (op === "eq") return r[col] === a;   // NAMED (Nov 23 2026, LR-2): the member and the one-word theme
      return true;
    });
  }
  function answer(q) {
    let hits = q.table === "member_leads" ? rows.filter(r => keep(q, r)) : [];   // NAMED (Nov 23 2026, LR-2): only member_leads holds rows
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
    ["in", "is", "not", "gte", "lt", "order", "range", "limit", "eq", "neq"].forEach(op => { b[op] = function () { q.filters.push([op].concat([].slice.call(arguments))); return b; }; });
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
/* NAMED (Nov 23 2026, LR-2): BEFORE bsky_leads rows (status scored, intent_score, intent_reason, post_text, post_uri, a product).
   AFTER member_leads rows of member "u1" unless named: score, scored_at, match_reason, text, url, external_id. */
const row = (kw, extra) => Object.assign({ id: "r" + String(++n).padStart(4, "0"), user_id: "u1", matched_keyword: kw, source: "bluesky", posted_at: ago(10),
  status: "new", score: 15, scored_at: ago(9), match_reason: "Good match: asks a question", text: "plain post " + n, author_handle: "person" + n + ".bsky.social",
  url: "https://bsky.app/profile/person" + n + ".bsky.social/post/" + n, external_id: "at://did:plc:person" + n + "/app.bsky.feed.post/" + n,
  outreach_safe: true, reply_invited: true }, extra || {});
const PRIVATE_FIELDS = ["text", "author_handle", "url", "external_id", "match_reason", "outreach_safe", "reply_invited"];
const FP = { u1: ["how to manifest", "law of assumption", "living in the end", "does manifestation work", "tongkat ali reviews", "low energy"],
  u2: ["low libido", "ad account disabled"] };
const DIRTY = "Ask @someone.bsky.social or mail jane.doe@example.com or call +1 (555) 123-4567, see https://example.com/x and shop.example.org/deal www.foo.net @user@mastodon.social";
const QUOTE = "i have tried every single method there is and nothing has worked for me at all";
function world() {
  n = 0;
  const rows = [];
  for (let i = 0; i < 12; i++) rows.push(row("how to manifest", { score: 70 + (i % 5), text: (i === 0 ? QUOTE : "manifest post " + i) + (i === 1 ? " " + DIRTY : "") }));
  for (let i = 0; i < 7; i++) rows.push(row("law of assumption", { score: 12 }));
  rows.push(row("living in the end", { score: 95, source: "threads" }));   // NAMED (Nov 23 2026, LR-2): BEFORE source mastodon, no longer a source
  rows.push(row("living in the end", { score: 3 }));
  rows.push(row("how to manifest", { text: "x".repeat(900) }));
  // NAMED (Nov 23 2026, LR-2): BEFORE 6 score_failed and 6 legacy 0s with the failure reason. AFTER 6 scores that could not be read
  // (stored as score null with SCORE_UNREAD_REASON, lib/memberRadar.js; NAMED (Nov 23 2026, LR-2): BEFORE stored as 0 with no reason)
  // and 6 leads still waiting under the daily cap (scored_at null).
  for (let i = 0; i < 6; i++) rows.push(row("does manifestation work", { score: null, match_reason: require("../lib/memberRadar").SCORE_UNREAD_REASON, outreach_safe: false, reply_invited: false }));
  for (let i = 0; i < 6; i++) rows.push(row("does manifestation work", { score: null, scored_at: null, match_reason: null }));
  rows.push(row("does manifestation work", { score: null, scored_at: null, match_reason: null }));
  // outside the window, undated
  for (let i = 0; i < 3; i++) rows.push(row("how to manifest", { posted_at: ago(200) }));
  for (let i = 0; i < 8; i++) rows.push(row("how to manifest", { posted_at: null }));
  // NAMED (Nov 23 2026, LR-2): BEFORE other themes of the same pool. AFTER another member's leads, which u1 never reads.
  for (let i = 0; i < 9; i++) rows.push(row("low libido", { score: 40, user_id: "u2", text: "other member post " + i }));
  rows.push(row("ad account disabled", { score: 80, user_id: "u2", text: "other member ad post" }));
  rows.push(row("how to manifest", { score: 90, user_id: "u2", text: "other member manifest post" }));
  // YouTube rows: in the window, before it, and undated. None may be read.
  // NAMED (Nov 23 2026, LR-1): archived rows in the window. None may be read.
  for (let i = 0; i < 3; i++) rows.push(row("how to manifest", { status: "archived", score: 88, text: "archived row in the window " + i }));
  rows.push(row("how to manifest", { source: "youtube", score: null, text: "youtube comment in the window", url: "https://www.youtube.com/watch?v=aaaaaaaaaaa&lc=1" }));
  rows.push(row("how to manifest", { source: "youtube", score: null, posted_at: ago(200), text: "youtube comment before the window", url: "https://www.youtube.com/watch?v=aaaaaaaaaaa&lc=2" }));
  rows.push(row("how to manifest", { source: "youtube", score: null, posted_at: null, text: "youtube comment undated", url: "https://www.youtube.com/watch?v=aaaaaaaaaaa&lc=3" }));
  // NAMED (Nov 23 2026, LR-2): a Fingerprint word only ever found on YouTube
  rows.push(row("tongkat ali reviews", { source: "youtube", score: null, text: "youtube comment on a youtube-only word", url: "https://www.youtube.com/watch?v=bbbbbbbbbbb&lc=1" }));
  return rows;
}

const GOOD_REPLY = (kw) => "THEME: Doubt after trying | WANT: People want to know why methods fail for them and what to change. | KEYWORDS: " + kw + " | SUPPORT: 5";
function build(opts) {
  opts = opts || {};
  const rows = opts.rows || world();
  const db = fakeDb(rows);
  const prompts = [];
  const persisted = [];
  const gates = [];
  const ctx = {
    supabase: db.client, JSON, Math, Promise, Number, Object, Array, String, Date,
    nowIso: () => new Date().toISOString(), process: { env: {} }, OWNER_ACCOUNT_ID: "owner",
    // NAMED (Nov 23 2026, LR-2): the member's Fingerprint (lib/leadFingerprint.js) and the sales>rd link (lib/agentNetwork.js), faked
    require: (p) => {
      if (p === "./lib/leadFingerprint") return { getOrBuild: async (sb, uid) => ({ keywords: (FP[uid] || []).slice() }), shape: (x) => x };
      if (p === "./lib/agentNetwork") return { linkSwitchedOff: async () => !!opts.linkOff };
      throw new Error("unexpected require " + p);
    },
    recordGateDecision: function () { gates.push([].slice.call(arguments)); },
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
  async function call(body, role, id) {   // NAMED (Nov 23 2026, LR-1): + id. LR-2: BEFORE the owner by default; AFTER member u1
    const res = { code: 200, body: null, status(x) { this.code = x; return this; }, json(x) { this.body = JSON.parse(JSON.stringify(x)); return this; } };
    let err = null;
    await handler({ user: { id: id || "u1", role: role || "user" }, body: body || {} }, res, e => { err = e; res.code = 500; });
    return { status: res.code, body: res.body, err };
  }
  return { db, prompts, persisted, gates, call, api: ctx.api, middleware, rows };
}
const sampleBlock = (prompt) => prompt.slice(prompt.indexOf("SAMPLE:\n") + 8);
function leaks(obj, rows) {
  const text = JSON.stringify(obj);
  const found = [];
  PRIVATE_FIELDS.forEach(f => { if (text.indexOf("\"" + f + "\"") !== -1) found.push("key " + f); });
  rows.forEach(r => {
    ["author_handle", "url", "external_id"].forEach(f => { if (r[f] && text.indexOf(r[f]) !== -1) found.push(f + " " + r[f]); });
    if (r.text && r.text.length > 20 && text.indexOf(r.text) !== -1) found.push("text of " + r.id);
  });
  return found;
}

(async function main() {
  /* ── 1. the themes ────────────────────────────────────────────────────── */
  /* NAMED (Nov 23 2026, LR-2): BEFORE "the keyword map": six fixed themes (manifestation, quantum_jumping, supplements, libido, energy,
     bizforce), bizforce equal to leadRadar.js's BIZFORCE_KEYWORDS, every phrase leadRadar.js searched in a theme, and a theme read with
     .in(matched_keyword). AFTER a theme is "all" or one word of the member's own Fingerprint, read with .eq(matched_keyword); "all" reads
     the member's rows and no other member's; and no fixed list is left anywhere (server.js or leadRadar.js). */
  console.log("\n══ 1. the themes are the member's own words ══");
  const b0 = build();
  check("no fixed theme map is left: server.js has no DEMAND_THEME_KEYWORDS and leadRadar.js no KEYWORDS or BIZFORCE_KEYWORDS list",
    !/DEMAND_THEME_KEYWORDS\s*=/.test(SRC) && !/const (BIZFORCE_)?KEYWORDS = \[/.test(RADAR));
  let r = await b0.call({ theme: "all" });
  const q0 = b0.db.log.find(q => q.table === "member_leads");
  check("every read is the member's own (.eq user_id)", b0.db.log.filter(q => q.table === "member_leads").every(q => q.filters.some(f => f[0] === "eq" && f[1] === "user_id" && f[2] === "u1")),
    JSON.stringify(b0.db.log.map(q => q.filters.filter(f => f[0] === "eq"))));
  check("all: no keyword filter, and every word of the member's with rows is measured", r.status === 200 && !q0.filters.some(f => (f[0] === "eq" || f[0] === "in") && f[1] === "matched_keyword") &&
    ["how to manifest", "law of assumption", "living in the end", "does manifestation work"].every(k => r.body.measured.by_keyword.some(x => x.keyword === k)), JSON.stringify(r.body && r.body.measured && r.body.measured.by_keyword));
  check("all: another member's words and rows are never read", r.body.measured.by_keyword.every(x => ["low libido", "ad account disabled"].indexOf(x.keyword) === -1) &&
    b0.prompts.every(p => !/other member/.test(p)), JSON.stringify(r.body.measured.by_keyword));
  const bw = build();
  const rw = await bw.call({ theme: "law of assumption" });
  const qw = bw.db.log.find(q => q.table === "member_leads");
  check("a word reads only its own rows (.eq matched_keyword)", qw && qw.filters.some(f => f[0] === "eq" && f[1] === "matched_keyword" && f[2] === "law of assumption") &&
    rw.status === 200 && rw.body.measured.by_keyword.length === 1 && rw.body.measured.by_keyword[0].keyword === "law of assumption", JSON.stringify(rw.body && rw.body.measured && rw.body.measured.by_keyword));
  const bad = await build().call({ theme: "nonsense" });
  check("a word outside the Fingerprint is a 400 listing the valid ones: the member's 6 words and all",
    bad.status === 400 && Array.isArray(bad.body.valid_themes) && bad.body.valid_themes.length === 7 && JSON.stringify(bad.body.valid_themes) === JSON.stringify(FP.u1.concat(["all"])), JSON.stringify(bad.body));
  const other = await build().call({ theme: "law of assumption" }, "user", "u2");
  check("another member's word is not a theme for them (their own Fingerprint decides)", other.status === 400 && other.body.valid_themes.indexOf("law of assumption") === -1, JSON.stringify(other.body));
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
    // NAMED (Nov 23 2026, LR-2): BEFORE post_created_at (bsky_leads). AFTER posted_at (member_leads).
    qs[0].some(f => f[0] === "not" && f[1] === "posted_at") && qs[0].some(f => f[0] === "gte" && f[1] === "posted_at") &&
    qs.some(fs2 => fs2.some(f => f[0] === "is" && f[1] === "posted_at" && f[2] === null)), JSON.stringify(qs).slice(0, 300));
  const r365 = await build().call({ theme: "all", window_days: 365 });
  check("window 365 takes in the 200-day rows: 38", r365.body.measured.rows_in_window === 38, r365.body.measured.rows_in_window);

  /* ── 3. "<5" ──────────────────────────────────────────────────────────── */
  console.log("\n══ 3. counts below 5 ══");
  const tiny = build({ rows: [row("low energy", { score: 80 })] });   // NAMED (Nov 23 2026, LR-2): BEFORE theme bizforce
  const rt = await tiny.call({ theme: "low energy" });
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
  check("real scores: 22 (6 scores that could not be read, 6 waiting under the cap and 1 unscored are not)", m.intent_scores.real_scores === 22, m.intent_scores.real_scores);
  check("without a real score: 13", m.intent_scores.without_a_real_score === 13, m.intent_scores.without_a_real_score);
  /* NAMED (Nov 23 2026, LR-2): demandRowOf itself. An unreadable score (null, SCORE_UNREAD_REASON) and a first-LR-2 row (0, no
     reason) are done but failed: status scored, no score, the failure reason; a lead never scored is new; a real 0 stays a 0. */
  {
    const dctx = {};
    vm.createContext(dctx);
    const at = SRC.indexOf("function demandRowOf(l) {"), fr = SRC.search(/^var LEAD_SCORE_FAILED_REASON = .*;$/m);
    vm.runInContext(SRC.slice(fr, SRC.indexOf("\n", fr)) + "\n" + SRC.slice(at, SRC.indexOf("\n}\n", at) + 2) + "\nthis.f = demandRowOf;", dctx);
    const ts = "2026-11-23T10:00:00.000Z";
    const rowsOut = [{ score: null, match_reason: require("../lib/memberRadar").SCORE_UNREAD_REASON, scored_at: ts }, { score: 0, match_reason: null, scored_at: ts },
      { score: null, match_reason: null, scored_at: null }, { score: 0, match_reason: "Good match: not asking", scored_at: ts }]
      .map(x => dctx.f(Object.assign({ id: "x", source: "bluesky", matched_keyword: "k", posted_at: ts, text: "t" }, x))).map(o => [o.status, o.intent_score, o.intent_reason]);
    check("demandRowOf: unreadable and 0-with-no-reason rows are done but failed, an unscored lead is new, a real 0 stays 0",
      JSON.stringify(rowsOut) === JSON.stringify([["scored", null, FAILED], ["scored", null, FAILED], ["new", null, null], ["scored", 0, "Good match: not asking"]]), JSON.stringify(rowsOut));
  }
  check("buckets: 70-79 is 12, 10-19 is 8 (7 law-of-assumption rows and the long post) and 0-9 is <5 (the one real 3, none of the unread 0s)",
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
  check("no row field reaches the model: no handle, post address, ids or reasons",
    !b0.rows.some(rw => [rw.author_handle, rw.url, rw.external_id].some(v => prompt.indexOf(v) !== -1)) && prompt.indexOf("asks a question") === -1);
  check("the cleaner on its own: handle, email, phone, URL and domain all replaced",
    b0.api.demandCleanText(DIRTY) === "Ask [someone] or mail [email] or call [number], see [link] and [link] [link] [someone]", b0.api.demandCleanText(DIRTY));

  /* ── 6. determinism ───────────────────────────────────────────────────── */
  console.log("\n══ 6. the sample is reproducible ══");
  const pA = build({ taskId: "task-A" }); await pA.call({ theme: "all", sample_size: 10 });
  const pA2 = build({ taskId: "task-A" }); await pA2.call({ theme: "all", sample_size: 10 });
  const pB = build({ taskId: "task-B" }); await pB.call({ theme: "all", sample_size: 10 });
  check("the same run seed draws the same sample", sampleBlock(pA.prompts[0]) === sampleBlock(pA2.prompts[0]));
  check("another seed draws a different order", sampleBlock(pA.prompts[0]) !== sampleBlock(pB.prompts[0]));
  check("the seed is reported", typeof pA.persisted[0].measured.sample.seed === "number" && pA.persisted[0].measured.sample.seed === b0.api.demandSeed("task-A"));
  const kwInSample = new Set(sampleBlock(pA.prompts[0]).split("\n").filter(Boolean).map(l => /\[([^\]]+)\]/.exec(l)[1]));
  check("a sample of 10 spreads across every keyword in scope with text (4)", kwInSample.size === 4, JSON.stringify([...kwInSample]));

  /* ── 7. theme drops ───────────────────────────────────────────────────── */
  console.log("\n══ 7. theme drops ══");
  const dropReply = [
    GOOD_REPLY("how to manifest"),
    "THEME: Off topic | WANT: Something else. | KEYWORDS: low energy | SUPPORT: 3",
    "THEME: Too many | WANT: Everything. | KEYWORDS: how to manifest | SUPPORT: 999"
  ].join("\n");
  const bd = build({ reply: dropReply });
  const rd = await bd.call({ theme: "all", sample_size: 10 });
  check("a theme citing no keyword in scope, and one claiming support above the sample size, are dropped: 2",
    rd.body.points_dropped === 2 && rd.body.themes.length === 1 && rd.body.themes[0].label === "Doubt after trying", JSON.stringify([rd.body.points_dropped, rd.body.themes]));
  check("a kept theme carries label, what people want, keywords and support",
    JSON.stringify(Object.keys(rd.body.themes[0])) === JSON.stringify(["label", "what_people_want", "keywords", "supporting_posts"]) && rd.body.themes[0].supporting_posts === 5);

  /* ── 8. privacy drops ─────────────────────────────────────────────────── */
  console.log("\n══ 8. privacy drops ══");
  const six = "THEME: Frustration | WANT: Some say every single method there is and they feel stuck. | KEYWORDS: how to manifest | SUPPORT: 4";
  const five = "THEME: Frustration | WANT: Some say every single method there and they feel stuck. | KEYWORDS: how to manifest | SUPPORT: 4";
  const p6 = await build({ reply: GOOD_REPLY("how to manifest") + "\n" + six }).call({ theme: "all", sample_size: 40 });
  check("a theme repeating 6 consecutive words of a sampled post is removed: privacy_drops 1",
    p6.body.privacy_drops === 1 && p6.body.themes.length === 1 && p6.body.themes[0].label === "Doubt after trying", JSON.stringify([p6.body.privacy_drops, p6.body.themes && p6.body.themes.map(t => t.label)]));
  const p5 = await build({ reply: GOOD_REPLY("how to manifest") + "\n" + five }).call({ theme: "all", sample_size: 40 });
  check("a 5-word overlap is kept: privacy_drops 0", p5.body.privacy_drops === 0 && p5.body.themes.length === 2, JSON.stringify([p5.body.privacy_drops, p5.body.themes && p5.body.themes.length]));

  /* ── 9. failure and refusal ───────────────────────────────────────────── */
  console.log("\n══ 9. a model failure, every member, and the switched-off link ══");
  const bf = build({ modelThrows: true });
  const rf = await bf.call({ theme: "all" });
  check("a model failure: 200 with measured, themes null and explanation_error",
    rf.status === 200 && rf.body.measured && rf.body.measured.rows_in_window === 35 && rf.body.themes === null && /could not be generated/.test(rf.body.explanation_error), rf.status + " " + JSON.stringify(rf.body && rf.body.explanation_error));
  /* NAMED (Nov 23 2026, LR-2): BEFORE a member who was not the owner, and an admin who was not, got 403 before anything was read.
     AFTER every member reads their own leads (members only: requireActiveSubscription), and the member's sales>rd link is the refusal. */
  const bn = build();
  const rn = await bn.call({ theme: "low libido" }, "user", "u2");
  check("any member, not the owner: 200 over their own leads only", rn.status === 200 && rn.body.measured.rows_in_window === 9 &&
    bn.db.log.filter(q => q.table === "member_leads").every(q => q.filters.some(f => f[0] === "eq" && f[1] === "user_id" && f[2] === "u2")), rn.status + " " + JSON.stringify(rn.body && rn.body.measured && rn.body.measured.rows_in_window));
  const ba = build({ linkOff: true });
  const ra = await ba.call({ theme: "all" });
  check("the sales>rd link switched off: 403 link_disabled_by_member (G26), before anything is read",
    ra.status === 403 && ra.body.reason === "link_disabled_by_member" && ba.db.log.filter(q => q.table === "member_leads").length === 0 && ba.prompts.length === 0 && ba.gates.length === 1, ra.status);
  check("the route has requireAuth, requireActiveSubscription and aiLimiter", JSON.stringify(b0.middleware) === JSON.stringify(["requireAuth", "requireActiveSubscription", "aiLimiter"]));

  /* ── 10. no row-level field ───────────────────────────────────────────── */
  console.log("\n══ 10. no row leaves ══");
  for (const [label, res, bb] of [["all", r, b0], ["one word", rw, bw], ["privacy case", p6, null], ["failure", rf, bf]]) {   // NAMED (Nov 23 2026, LR-2): BEFORE manifestation and all
    check(label + ": no row-level field or value in the response", leaks(res.body, world()).length === 0, leaks(res.body, world()).join("; "));
    if (bb) check(label + ": none in the persisted body either", leaks(bb.persisted[0], world()).length === 0, leaks(bb.persisted[0], world()).join("; "));
  }
  check("the response keys", JSON.stringify(Object.keys(r.body)) === JSON.stringify(["success", "theme", "measured", "themes", "explanation_error", "points_dropped", "privacy_drops", "not_measured", "provenance", "task_id", "persisted"]), JSON.stringify(Object.keys(r.body)));
  // NAMED BEFORE → AFTER: was "not_measured names the four things", length 4.
  check("not_measured names the five things, the fifth that YouTube is excluded and why", r.body.not_measured.length === 5 && /authors/.test(r.body.not_measured[0]) && /represents/.test(r.body.not_measured[1]) && /never searched/.test(r.body.not_measured[2]) && /before collection/.test(r.body.not_measured[3]) &&
    /^YouTube: excluded\. YouTube's API terms forbid combining YouTube data with data from other sources/.test(r.body.not_measured[4]), JSON.stringify(r.body.not_measured[4]));

  /* ── 11. no YouTube row ───────────────────────────────────────────────── */
  console.log("\n══ 11. no YouTube row is read ══");
  const allQueries = b0.db.log.concat(bw.db.log).filter(q => q.table !== "member_links");
  // NAMED (Nov 23 2026, LR-2): BEFORE every bsky_leads query. AFTER every member_leads query.
  check("every member_leads query, the page and both counts, filters source neq youtube in the query (" + allQueries.length + " queries)",
    allQueries.length >= 6 && allQueries.every(q => q.table === "member_leads" && q.filters.some(f => f[0] === "neq" && f[1] === "source" && f[2] === "youtube")),
    JSON.stringify(allQueries.map(q => q.filters.filter(f => f[0] === "neq"))));
  check("by_source names no youtube, for a word and for all", !r.body.measured.by_source.some(x => x.source === "youtube") && !rw.body.measured.by_source.some(x => x.source === "youtube"),
    JSON.stringify([r.body.measured.by_source, rw.body.measured.by_source]));
  check("no YouTube comment reaches the model, for a word or for all", [b0, bw].every(bb => bb.prompts.every(p => !/youtube comment/.test(p))));
  // NAMED (Nov 23 2026, LR-1)
  check("no archived row reaches the model, for a word or for all", [b0, bw].every(bb => bb.prompts.every(p => !/archived row in the window/.test(p))));
  check("the YouTube rows are in no count: the window still holds 35 rows, 8 undated, <5 before it",
    m.rows_in_window === 35 && m.undated_rows === 8 && m.dated_before_window === "<5", JSON.stringify([m.rows_in_window, m.undated_rows, m.dated_before_window]));
  // NAMED (Nov 23 2026, LR-2): BEFORE "no theme lists a keyword only ever searched on YouTube" (the fixed map). AFTER a member's word found only
  // on YouTube is a theme like any other, and measures nothing: its YouTube rows are never read.
  const yo = build();
  const ryo = await yo.call({ theme: "tongkat ali reviews" });
  check("a word found only on YouTube measures no row and sends nothing to the model", ryo.status === 200 && ryo.body.measured.rows_in_window === "<5" &&
    ryo.body.measured.by_source.length === 0 && yo.prompts.length === 0, JSON.stringify(ryo.body && ryo.body.measured && [ryo.body.measured.rows_in_window, ryo.body.measured.by_source]));

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
