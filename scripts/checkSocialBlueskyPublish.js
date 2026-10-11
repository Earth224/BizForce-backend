"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkSocialBlueskyPublish — the Social agent drafts a Bluesky post, the
   owner files it, approving it publishes it as a top-level post through the
   Bluesky gate, and the post's uri and cid are recorded on the draft. Only the
   server can mark a draft published.

   POST /api/agents/social/post, POST /api/agents/social/propose-post,
   executePublishSocialPost (publish_social_post in PROPOSAL_EXECUTORS),
   PUT /api/social-drafts/:id and POST /api/proposals are lifted from server.js
   and run in a vm against an in-memory Supabase that keeps its rows between
   calls and enforces migration 136's two CHECKs, so a proposal filed by the
   route is the row the executor is handed. The Bluesky gate is a stub whose
   agent records every post; nothing leaves the machine — fetch inside the vm
   and every socket and DNS lookup in this process are tripwires.

   WHAT THIS PROVES
     1. Graphemes: a family emoji counts 1, a combining accent 1; 300 family
        emojis (2,400 UTF-16 units) are within Bluesky's limit and 301 are
        not, in measureSocialPost, in social/post, in the route and in the
        executor. Other platforms keep String.length and their old shape.
        With no Intl.Segmenter, Bluesky is refused 503 before anything runs.
     2. The route: a non-admin is refused 403 before anything is read;
        another user's task, a missing task and a malformed id get identical
        404s; a wrong task type, an unfinished run, another platform, an empty
        post and 301 graphemes are 400s; no refusal writes anything. Filing
        writes one draft (bluesky, the stored post, pending_approval, its
        proposal_id) and one proposal (social, publish_social_post, payload
        exactly { draft_id, text, source_task_id }). Text in the body is never
        read.
     3. The executor refuses, posting nothing and changing nothing: an owner
        no longer admin or gone, a missing, foreign or non-Bluesky draft, text
        that differs from the draft or from the source run, a source run that
        is missing, unfinished or not Bluesky, over 300 graphemes, empty text,
        a draft not pending_approval, and no segmenter.
     4. The executor publishes: one top-level record { text, createdAt,
        facets } with no reply field, link facets only, offsets into the
        exact text; the draft becomes published with the uri, cid and
        published_at it returns. A replay posts nothing and returns
        already_published with the uri. rate_limited, a refused login, a
        thrown post and an answer with no uri each mark the draft
        publish_failed with the reason (resumes_at for a rate limit), throw,
        and are tried exactly once. A post that went out but could not be
        recorded throws naming its uri.
     5. PUT refuses pending_approval, published and publish_failed as a
        status, and any edit to a filed or published draft; it still edits a
        plain draft, and another user's draft is a 404.
     6. POST /api/proposals refuses publish_social_post.
     7. The wiring: middleware, executor, subscription gate, chain block,
        TOOL_INPUT_SPECS, the platform list, the field description.
     8. Zero network.

   MUTATE=<name> edits the lifted source (server.js on disk is never touched).
   MUTATE=all runs each in its own process and passes only if every one fails
   at least one check. A mutation whose search text does not match exactly once
   is an ERROR, never counted as caught.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const net = require("net");
const dns = require("dns");
const s = require("./_shared");

/* ── the network tripwire, before anything else can open a socket ─────────── */
const NETWORK = [];
const realConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkSocialBlueskyPublish: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkSocialBlueskyPublish: no network"); };
void realConnect;

const REPO = path.join(__dirname, "..");
const MUTATE = process.env.MUTATE || "";

const MUTATIONS = {
  // graphemes counted as UTF-16 code units
  "count-string-length": [["  for (var piece of GRAPHEME_SEGMENTER.segment(String(text))) count++;\n  return count;\n",
    "  return String(text).length;\n"]],
  // the route takes the text from the request body
  "text-from-body": [["      var text = typeof output.post === \"string\" ? output.post : \"\";\n",
    "      var text = typeof req.body.text === \"string\" ? req.body.text : (typeof output.post === \"string\" ? output.post : \"\");\n"]],
  // the executor no longer compares the text with the draft and the source run
  "skip-deep-equal": [["  if (draft.content !== text) {\n", "  if (false) {\n"],
    ["  if (source.output.post !== text) {\n", "  if (false) {\n"]],
  // a published draft is posted again
  "post-again-on-replay": [["  if (draft.status === \"published\" && draft.platform_post_uri) {\n", "  if (false) {\n"],
    ["  if (draft.status !== \"pending_approval\") {\n", "  if (false) {\n"]],
  // an answer with no uri is recorded as published
  "published-without-uri": [["  if (!uri) {\n    var why", "  if (!outcome.ok) {\n    var why"]],
  // PUT may set a status only the server sets
  "put-sets-published": [["    if (updates.status !== undefined && SOCIAL_DRAFT_SERVER_STATUSES.indexOf(updates.status) !== -1) {\n",
    "    if (false) {\n"]],
  // the post becomes a reply
  "reply-field": [["  var record = { text: text, createdAt: nowIso() };\n",
    "  var record = { text: text, createdAt: nowIso(), reply: { root: { uri: \"at://x\", cid: \"c\" }, parent: { uri: \"at://x\", cid: \"c\" } } };\n"]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}

/* ── the source ─────────────────────────────────────────────────────────── */
let SRC = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
const DISK = SRC;
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [from, to] of edits) SRC = s.replaceOnce(SRC, from, to, MUTATE);
  console.log("\n!! MUTATION: " + MUTATE);
}

/* _shared.definitionOf caches by "working tree or not", and a mutated SRC is
   neither; this one reads only SRC. */
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
  "requireAuth", "requireActiveSubscription", "aiLimiter", "bskyGate", "RichText",
  "startToolRun", "toolGenerateWithOneRetry", "toolSectionShapeCorrection", "toolProvenance", "loadProfileForTool",
  "resolvePreferredLanguage", "buildAgentSystemPrompt", "buildLanguageInstruction"]);
function closure(root) {
  const have = new Map();
  const queue = [...new Set(root.match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || STUBS.has(name)) continue;
    const def = definitionOf(name);
    if (!def) continue;
    try { new vm.Script(def); } catch (e) { continue; }
    have.set(name, def);
    new Set(def.match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !STUBS.has(id)) queue.push(id); });
  }
  return [...have.values()].sort((x, y) => SRC.indexOf(x) - SRC.indexOf(y)).join("\n\n") + "\n\n" + root;
}
function routeText(method, route) {
  const sig = "app." + method + "(\"" + route + "\"";
  const start = SRC.indexOf(sig);
  if (start < 0) throw new Error(method.toUpperCase() + " " + route + " not found");
  const end = s.braceMatch(SRC, SRC.indexOf("{", start));
  if (SRC.slice(end, end + 2) !== ");") throw new Error(method.toUpperCase() + " " + route + " did not end where expected");
  return SRC.slice(start, end + 2);
}
const R_POST = "/api/agents/social/post", R_PROPOSE = "/api/agents/social/propose-post",
  R_PUT = "/api/social-drafts/:id", R_PROPOSALS = "/api/proposals";
const ROOT = [routeText("post", R_POST), routeText("post", R_PROPOSE), routeText("put", R_PUT), routeText("post", R_PROPOSALS)].join("\n\n") +
  "\n\nthis.executePublishSocialPost = executePublishSocialPost; this.measureSocialPost = measureSocialPost;" +
  " this.countGraphemes = countGraphemes; this.SOCIAL_PLATFORMS = SOCIAL_PLATFORMS;";
const LIFTED = closure(ROOT);

/* ── the fake database, with migration 136's CHECKs ────────────────────── */
const DRAFT_STATUSES = ["pending", "not_published", "scheduled", "pending_approval", "published", "publish_failed"];
function violates(table, row) {
  if (table !== "social_post_drafts") return null;
  if (DRAFT_STATUSES.indexOf(row.status) === -1) return "social_post_drafts_status_check";
  if (row.status === "published" && (row.platform_post_uri == null || row.published_at == null)) return "social_post_drafts_published_check";
  return null;
}
const TABLES = ["ai_tasks", "users", "social_post_drafts", "agent_proposals"];
function fakeDb(seed, override) {
  const tables = {};
  TABLES.forEach(t => { tables[t] = ((seed || {})[t] || []).map(r => JSON.parse(JSON.stringify(r))); });
  const log = [];
  let seq = 0;
  const keep = (q, row) => q.filters.every(f => f[0] === "eq" ? row[f[1]] === f[2] : f[0] === "in" ? f[2].indexOf(row[f[1]]) !== -1 : true);
  const copy = v => JSON.parse(JSON.stringify(v));
  function finish(q, rows) {
    if (q.single === "single") {
      return rows.length === 1 ? { data: copy(rows[0]), error: null } : { data: null, error: { code: "PGRST116", message: rows.length + " rows" } };
    }
    if (q.single === "maybe") return { data: rows[0] ? copy(rows[0]) : null, error: null };
    return { data: q.returning || q.op === "select" ? copy(rows) : null, error: null };
  }
  function answer(q) {
    const forced = override && override(q, tables);
    if (forced) return Promise.resolve(forced);
    const rows = tables[q.table];
    if (!rows) return Promise.resolve({ data: null, error: { message: "unplanned table " + q.table } });
    if (q.op === "insert") {
      const row = Object.assign({ id: "00000000-0000-4000-8000-" + String(++seq).padStart(12, "0") }, copy(q.payload));
      const bad = violates(q.table, row);
      if (bad) return Promise.resolve({ data: null, error: { code: "23514", message: "violates check constraint \"" + bad + "\"" } });
      rows.push(row);
      return Promise.resolve(finish(q, [row]));
    }
    const hits = rows.filter(r => keep(q, r));
    if (q.op === "update") {
      for (const r of hits) {
        const bad = violates(q.table, Object.assign({}, r, q.payload));
        if (bad) return Promise.resolve({ data: null, error: { code: "23514", message: "violates check constraint \"" + bad + "\"" } });
      }
      hits.forEach(r => Object.assign(r, copy(q.payload)));
      return Promise.resolve(finish(q, hits));
    }
    if (q.op === "delete") {
      tables[q.table] = rows.filter(r => hits.indexOf(r) === -1);
      return Promise.resolve(finish(q, hits));
    }
    return Promise.resolve(finish(q, hits));
  }
  function from(table) {
    const q = { table, op: "select", payload: null, filters: [], single: false, returning: false };
    log.push(q);
    const b = {
      select() { if (q.op === "select") q.cols = arguments[0]; else q.returning = true; return b; },
      insert(p) { q.op = "insert"; q.payload = p; return b; },
      update(p) { q.op = "update"; q.payload = p; return b; },
      delete() { q.op = "delete"; return b; }
    };
    ["eq", "in", "order", "limit"].forEach(op => { b[op] = function () { q.filters.push([op].concat([].slice.call(arguments))); return b; }; });
    b.single = () => { q.single = "single"; return answer(q); };
    b.maybeSingle = () => { q.single = "maybe"; return answer(q); };
    b.then = (res, rej) => answer(q).then(res, rej);
    return b;
  }
  return { log, tables, client: { from } };
}

/* ── fixtures ───────────────────────────────────────────────────────────── */
const OWNER = "aaaaaaaa-0000-4000-8000-000000000001";
const OTHER = "bbbbbbbb-0000-4000-8000-000000000002";
const PLAIN = "cccccccc-0000-4000-8000-000000000003";
const tid = n => "11111111-0000-4000-8000-" + String(n).padStart(12, "0");
const FAMILY = "\u{1F468}‍\u{1F469}‍\u{1F467}";
const ACCENT = "é";
const LINK = "https://example.com/launch";
const POST = "New colourway été " + FAMILY + " is here: " + LINK + " — thanks @someone.bsky.social #wool";
const runOutput = (post, platform) => ({ success: true, platform: platform || "bluesky", platform_label: "Bluesky", post, hook_note: "Leads with it." });
const task = (n, user, output, extra) => Object.assign({ id: tid(n), user_id: user, agent_type: "social", task_type: "social/post", status: "completed", output }, extra || {});
const T = { ok: tid(1), other: tid(2), seo: tid(3), processing: tid(4), insta: tid(5), empty: tid(6), max: tid(7), over: tid(8), missing: tid(99) };
function seed() {
  return {
    users: [{ id: OWNER, role: "admin" }, { id: OTHER, role: "admin" }, { id: PLAIN, role: "user" }],
    ai_tasks: [
      task(1, OWNER, runOutput(POST)), task(2, OTHER, runOutput(POST)), task(3, OWNER, runOutput(POST), { task_type: "seo/audit" }),
      task(4, OWNER, runOutput(POST), { status: "processing" }), task(5, OWNER, runOutput(POST, "instagram")),
      task(6, OWNER, runOutput("   ")), task(7, OWNER, runOutput(FAMILY.repeat(300))), task(8, OWNER, runOutput(FAMILY.repeat(301)))
    ],
    social_post_drafts: [
      { id: "dddd0000-0000-4000-8000-000000000001", user_id: OWNER, platform: "bluesky", content: "plain draft", status: "not_published" },
      { id: "dddd0000-0000-4000-8000-000000000002", user_id: OTHER, platform: "bluesky", content: POST, status: "pending_approval" }
    ],
    agent_proposals: []
  };
}
const PLAIN_DRAFT = "dddd0000-0000-4000-8000-000000000001";
const OTHERS_DRAFT = "dddd0000-0000-4000-8000-000000000002";
const POSTED = { uri: "at://did:plc:owner/app.bsky.feed.post/3kabc", cid: "bafyreicid" };

/* ── the build ──────────────────────────────────────────────────────────── */
const FETCHES = [];
const { RichText } = require(require.resolve("@atproto/api", { paths: [REPO] }));
function build(seedTables, opts) {
  opts = opts || {};
  const db = fakeDb(seedTables, opts.override);
  const logs = [];
  const gate = { calls: 0, posts: [] };
  const agent = {
    post: async function (record) {
      gate.posts.push(JSON.parse(JSON.stringify(record)));
      if (opts.gate === "throws") throw new Error("upstream 500");
      if (opts.gate === "no_uri") return {};
      return Object.assign({}, POSTED);
    }
  };
  gate.call = async function (fn) {
    gate.calls++;
    if (opts.gate === "rate_limited") return { ok: false, reason: "rate_limited", retry_after_seconds: 900, resumes_at: "2026-10-11T12:15:00.000Z", error: "RateLimitExceeded" };
    if (opts.gate === "login_failed") return { ok: false, reason: "login_failed", error: "Invalid identifier or password" };
    return { ok: true, value: await fn(agent) };
  };
  const runs = { started: 0, completed: [] };
  const ctx = {
    supabase: db.client, bskyGate: gate, RichText, Date, JSON, Math, Promise, Number, Object, Array, String, Intl,
    nowIso: () => "2026-10-11T12:00:00.000Z",
    process: { env: {} },
    fetch: async (u) => { FETCHES.push(String(u)); throw new Error("no network"); },
    console: { log: m => logs.push(String(m)), error: m => logs.push(String(m)), warn: m => logs.push(String(m)) },
    requireAuth: function requireAuth() {}, requireActiveSubscription: function requireActiveSubscription() {}, aiLimiter: function aiLimiter() {},
    startToolRun: async () => { runs.started++; return { taskId: "t-run", complete: async (o) => { runs.completed.push(o); return true; }, fail: async () => {} }; },
    toolGenerateWithOneRetry: async (o) => { o.parse(opts.model || ""); return { raw: opts.model || "", completionExtra: undefined, failureDetails: null }; },
    toolSectionShapeCorrection: () => "", toolProvenance: () => ({}), loadProfileForTool: async () => ({}),
    resolvePreferredLanguage: async () => null, buildAgentSystemPrompt: () => "SYSTEM", buildLanguageInstruction: () => ""
  };
  const routes = {};
  const mount = method => function (p) { routes[method + " " + p] = { handler: arguments[arguments.length - 1], middleware: [].slice.call(arguments, 1, -1).map(f => f.name) }; };
  ctx.app = { post: mount("post"), put: mount("put"), get: mount("get") };
  vm.createContext(ctx);
  vm.runInContext(LIFTED, ctx);
  if (opts.noSegmenter) ctx.GRAPHEME_SEGMENTER = null;
  async function hit(key, user, body, params) {
    const res = { code: 200, body: null, error: null, status(x) { this.code = x; return this; }, json(x) { this.body = JSON.parse(JSON.stringify(x)); return this; } };
    await routes[key].handler({ user: { id: user, role: user === PLAIN ? "user" : "admin" }, body: body || {}, params: params || {} }, res, e => { res.error = e; res.code = 500; });
    return res;
  }
  async function execute(proposal) {
    try { return { result: await ctx.executePublishSocialPost(JSON.parse(JSON.stringify(proposal))) }; }
    catch (e) { return { error: e }; }
  }
  return { db, logs, gate, runs, ctx, routes, hit, execute,
    propose: (user, body) => hit("post " + R_PROPOSE, user, body),
    put: (user, id, body) => hit("put " + R_PUT, user, body, { id }) };
}
const writes = db => db.log.filter(q => q.op !== "select");
const draftOf = (db, id) => db.tables.social_post_drafts.find(d => d.id === id);
const snapshot = db => JSON.stringify(db.tables);

// A filed proposal and its draft, made by the real route.
async function filed(seedTables, opts, taskId) {
  const b = build(seedTables || seed(), opts);
  const r = await b.propose(OWNER, { task_id: taskId || T.ok });
  if (r.code !== 201) throw new Error("could not file: " + r.code + " " + JSON.stringify(r.body));
  const proposal = Object.assign({}, b.db.tables.agent_proposals[0], { status: "executing" });
  return { b, proposal, draftId: proposal.payload.draft_id };
}

(async function main() {
  /* ── 1. graphemes ─────────────────────────────────────────────────────── */
  console.log("\n══ 1. Bluesky is measured in graphemes ══");
  let b = build(seed());
  const spec = b.ctx.SOCIAL_PLATFORMS.bluesky;
  check("SOCIAL_PLATFORMS.bluesky: hard 300, unit graphemes", spec && spec.max === 300 && spec.kind === "hard" && spec.unit === "graphemes", JSON.stringify(spec));
  check("a family emoji is 1 grapheme (8 UTF-16 units)", b.ctx.countGraphemes(FAMILY) === 1 && FAMILY.length === 8, b.ctx.countGraphemes(FAMILY));
  check("a letter with a combining accent is 1 grapheme", b.ctx.countGraphemes(ACCENT) === 1, b.ctx.countGraphemes(ACCENT));
  let m = b.ctx.measureSocialPost(FAMILY.repeat(300), spec);
  check("measureSocialPost: 300 family emojis are length 300, within the limit, length_unit graphemes",
    m.length === 300 && m.within_limit === true && m.chars_over_limit === 0 && m.length_unit === "graphemes", JSON.stringify([m.length, m.within_limit, m.length_unit]));
  m = b.ctx.measureSocialPost(FAMILY.repeat(301), spec);
  check("measureSocialPost: 301 are over by 1", m.length === 301 && m.within_limit === false && m.chars_over_limit === 1, JSON.stringify([m.length, m.within_limit]));
  m = b.ctx.measureSocialPost(FAMILY, b.ctx.SOCIAL_PLATFORMS.instagram);
  check("other platforms keep String.length and have no length_unit", m.length === 8 && !("length_unit" in m), JSON.stringify(m));

  b = build(seed(), { model: "POST: " + FAMILY.repeat(300) + "\nHOOK_NOTE: emoji wall" });
  let r = await b.hit("post " + R_POST, OWNER, { idea: "an emoji wall", platform: "bluesky" });
  check("social/post for bluesky: 300 family emojis measured 300 graphemes, within the limit",
    r.code === 200 && r.body.platform === "bluesky" && r.body.measured.length === 300 && r.body.measured.within_limit === true, r.code + " " + JSON.stringify(r.body && r.body.measured && [r.body.measured.length, r.body.measured.within_limit]));
  b = build(seed(), { model: "POST: " + FAMILY.repeat(301) + "\nHOOK_NOTE: emoji wall" });
  r = await b.hit("post " + R_POST, OWNER, { idea: "an emoji wall", platform: "bluesky" });
  check("social/post for bluesky: 301 are over, the note says graphemes",
    r.code === 200 && r.body.measured.within_limit === false && /1 graphemes over Bluesky/.test(r.body.measured.note), r.body && r.body.measured && r.body.measured.note);
  b = build(seed(), { noSegmenter: true, model: "POST: hi\nHOOK_NOTE: x" });
  r = await b.hit("post " + R_POST, OWNER, { idea: "anything", platform: "bluesky" });
  check("no Intl.Segmenter: social/post for bluesky is 503 graphemes_uncountable, before a run starts",
    r.code === 503 && r.body.code === "graphemes_uncountable" && b.runs.started === 0, r.code + " " + JSON.stringify(r.body) + " runs " + b.runs.started);
  r = await b.hit("post " + R_POST, OWNER, { idea: "anything", platform: "instagram" });
  check("no Intl.Segmenter: instagram is unaffected", r.code === 200 && b.runs.started === 1, r.code);
  r = await b.propose(OWNER, { task_id: T.ok });
  check("no Intl.Segmenter: propose-post is 503 and writes nothing", r.code === 503 && writes(b.db).length === 0, r.code);

  /* ── 2. the route ─────────────────────────────────────────────────────── */
  console.log("\n══ 2. POST /api/agents/social/propose-post ══");
  b = build(seed());
  r = await b.propose(PLAIN, { task_id: T.ok });
  check("a non-admin: 403 naming the single Bluesky account", r.code === 403 && /owner account/.test(r.body.error) && /single Bluesky/.test(r.body.error), r.code + " " + JSON.stringify(r.body));
  check("…before reading anything", b.db.log.length === 0, b.db.log.length);
  const rOther = await b.propose(OWNER, { task_id: T.other });
  const rMissing = await b.propose(OWNER, { task_id: T.missing });
  const rMalformed = await b.propose(OWNER, { task_id: "not-a-uuid" });
  check("another user's task: 404", rOther.code === 404, rOther.code);
  check("another user's task, a missing task and a malformed id: identical status and body",
    [rOther, rMissing, rMalformed].every(x => x.code === 404 && JSON.stringify(x.body) === JSON.stringify(rMissing.body)), JSON.stringify([rOther.body, rMissing.body, rMalformed.body]));
  const taskRead = b.db.log.find(q => q.table === "ai_tasks");
  check("the task is read scoped to the caller", taskRead && taskRead.filters.some(f => f[0] === "eq" && f[1] === "user_id" && f[2] === OWNER));
  const refusals = [
    ["no task_id", {}, 400, /task_id is required/],
    ["a task that is not social/post", { task_id: T.seo }, 400, /not a social post run/],
    ["a run that is not completed", { task_id: T.processing }, 400, /not completed/],
    ["a run for instagram", { task_id: T.insta }, 400, /not Bluesky/],
    ["an empty post", { task_id: T.empty }, 400, /empty/],
    ["301 graphemes", { task_id: T.over }, 400, /301 graphemes, over Bluesky's limit of 300/]
  ];
  for (const [label, body, code, re] of refusals) {
    b = build(seed());
    r = await b.propose(OWNER, body);
    check(label + ": " + code + " " + re.source, r.code === code && re.test(r.body && r.body.error), r.code + " " + JSON.stringify(r.body));
    check(label + ": nothing written", writes(b.db).length === 0, JSON.stringify(writes(b.db).map(q => q.table)));
  }
  b = build(seed());
  r = await b.propose(OWNER, { task_id: T.max });
  check("300 graphemes (2,400 UTF-16 units): filed, measured 300", r.code === 201 && r.body.measured.length === 300, r.code + " " + JSON.stringify(r.body && r.body.measured));

  b = build(seed());
  r = await b.propose(OWNER, { task_id: T.ok, text: "INJECTED FROM THE BODY", post: "INJECTED", content: "INJECTED" });
  const proposal = b.db.tables.agent_proposals[0];
  const draft = proposal && draftOf(b.db, proposal.payload.draft_id);
  check("201 with the draft and the proposal", r.code === 201 && r.body.proposal.id === (proposal && proposal.id) && r.body.draft.id === (draft && draft.id), r.code + " " + JSON.stringify(r.body));
  check("one draft and one proposal written, and the draft linked: insert, insert, update",
    JSON.stringify(writes(b.db).map(q => q.op + " " + q.table)) === JSON.stringify(["insert social_post_drafts", "insert agent_proposals", "update social_post_drafts"]),
    JSON.stringify(writes(b.db).map(q => q.op + " " + q.table)));
  check("the draft: the caller's, bluesky, the stored post exactly, pending_approval, proposal_id set",
    draft && draft.user_id === OWNER && draft.platform === "bluesky" && draft.content === POST && draft.status === "pending_approval" && draft.proposal_id === proposal.id,
    JSON.stringify(draft));
  check("the proposal: social, publish_social_post, pending, the caller's",
    proposal && proposal.agent_type === "social" && proposal.action_type === "publish_social_post" && proposal.status === "pending" && proposal.user_id === OWNER, JSON.stringify(proposal));
  check("payload is exactly { draft_id, text, source_task_id }",
    proposal && JSON.stringify(Object.keys(proposal.payload)) === JSON.stringify(["draft_id", "text", "source_task_id"]) &&
    proposal.payload.draft_id === draft.id && proposal.payload.text === POST && proposal.payload.source_task_id === T.ok, proposal && JSON.stringify(proposal.payload));
  check("text in the body is never read", !JSON.stringify(b.db.tables).includes("INJECTED"));
  check("the response says nothing was posted", /Nothing has been posted/.test(r.body.note), r.body.note);

  /* ── 3. the executor refuses ──────────────────────────────────────────── */
  console.log("\n══ 3. the executor trusts nothing it is handed ══");
  const executorRefusals = [
    ["an owner who is no longer admin", (t) => { t.users[0].role = "user"; }, p => p, /limited to the owner account/],
    ["an owner who no longer exists", (t) => { t.users.splice(0, 1); }, p => p, /limited to the owner account/],
    ["a missing draft", null, p => Object.assign(p, { payload: Object.assign({}, p.payload, { draft_id: "eeee0000-0000-4000-8000-000000000009" }) }), /draft is missing or not this owner's/],
    ["another user's draft", null, p => Object.assign(p, { payload: Object.assign({}, p.payload, { draft_id: OTHERS_DRAFT }) }), /draft is missing or not this owner's/],
    ["no draft_id", null, p => Object.assign(p, { payload: Object.assign({}, p.payload, { draft_id: undefined }) }), /names no draft/],
    ["a draft that is not for Bluesky", (t, id) => { t.social_post_drafts.find(d => d.id === id).platform = "x"; }, p => p, /not Bluesky/],
    ["text that differs from the draft", (t, id) => { t.social_post_drafts.find(d => d.id === id).content = POST + " (edited)"; }, p => p, /differs from the draft's content/],
    ["text that differs from the source run", (t) => { t.ai_tasks.find(x => x.id === T.ok).output.post = POST + " (edited)"; }, p => p, /differs from the post the source run drafted/],
    ["a source run that is missing", (t) => { t.ai_tasks = t.ai_tasks.filter(x => x.id !== T.ok); }, p => p, /source run is missing/],
    ["a source run that is not completed", (t) => { t.ai_tasks.find(x => x.id === T.ok).status = "failed"; }, p => p, /source run is missing/],
    ["a source run that is not Bluesky", (t) => { t.ai_tasks.find(x => x.id === T.ok).output.platform = "x"; }, p => p, /source run is missing/],
    ["no source_task_id", null, p => Object.assign(p, { payload: Object.assign({}, p.payload, { source_task_id: null }) }), /names no source run/],
    ["301 graphemes", null, p => Object.assign(p, { payload: Object.assign({}, p.payload, { text: FAMILY.repeat(301) }) }), /301 graphemes, over Bluesky's limit of 300/],
    ["empty text", null, p => Object.assign(p, { payload: Object.assign({}, p.payload, { text: "  " }) }), /stored text is empty/],
    ["a draft that is publish_failed, not pending_approval", (t, id) => { t.social_post_drafts.find(d => d.id === id).status = "publish_failed"; }, p => p, /not pending_approval/]
  ];
  for (const [label, tamperDb, tamperProposal, re] of executorRefusals) {
    const f = await filed();
    if (tamperDb) tamperDb(f.b.db.tables, f.draftId);
    const before = snapshot(f.b.db);
    const x = await f.b.execute(tamperProposal(JSON.parse(JSON.stringify(f.proposal))));
    check("executor, " + label + ": throws " + re.source, x.error && re.test(x.error.message), x.error ? x.error.message : JSON.stringify(x.result));
    check("executor, " + label + ": posts nothing and changes nothing", f.b.gate.calls === 0 && f.b.gate.posts.length === 0 && snapshot(f.b.db) === before,
      "gate calls " + f.b.gate.calls);
  }
  {
    const f = await filed(seed(), { noSegmenter: false });
    f.b.ctx.GRAPHEME_SEGMENTER = null;
    const x = await f.b.execute(f.proposal);
    check("executor, no Intl.Segmenter: throws, posts nothing", x.error && /Intl\.Segmenter/.test(x.error.message) && f.b.gate.calls === 0, x.error ? x.error.message : "no error");
  }

  /* ── 4. the executor publishes ────────────────────────────────────────── */
  console.log("\n══ 4. the executor publishes one top-level post ══");
  let f = await filed();
  let x = await f.b.execute(f.proposal);
  const d1 = draftOf(f.b.db, f.draftId);
  check("returns { uri, cid, published_at, draft_id }",
    x.result && x.result.uri === POSTED.uri && x.result.cid === POSTED.cid && x.result.published_at === "2026-10-11T12:00:00.000Z" && x.result.draft_id === f.draftId,
    x.error ? x.error.message : JSON.stringify(x.result));
  check("the draft is published with that uri, cid and published_at, and no error",
    d1.status === "published" && d1.platform_post_uri === POSTED.uri && d1.platform_post_cid === POSTED.cid && d1.published_at === x.result.published_at && d1.publish_error === null,
    JSON.stringify(d1));
  const markWrite = writes(f.b.db).filter(q => q.table === "social_post_drafts" && q.op === "update").pop();
  check("the published update is conditional on status pending_approval and scoped to the owner",
    markWrite && markWrite.filters.some(f2 => f2[0] === "eq" && f2[1] === "status" && f2[2] === "pending_approval") &&
    markWrite.filters.some(f2 => f2[0] === "eq" && f2[1] === "user_id" && f2[2] === OWNER), markWrite && JSON.stringify(markWrite.filters));
  check("exactly one gate call and one post", f.b.gate.calls === 1 && f.b.gate.posts.length === 1, f.b.gate.calls + "/" + f.b.gate.posts.length);
  const rec = f.b.gate.posts[0] || {};
  check("the record is top-level: keys exactly text, createdAt, facets — no reply field",
    JSON.stringify(Object.keys(rec)) === JSON.stringify(["text", "createdAt", "facets"]) && !("reply" in rec), JSON.stringify(Object.keys(rec)));
  check("the record's text is the filed text exactly", rec.text === POST);
  const features = (rec.facets || []).flatMap(fc => fc.features || []);
  check("facets are links only (the @mention and #tag in the text are not facets)",
    features.length === 1 && features[0].$type === "app.bsky.richtext.facet#link" && features[0].uri === LINK, JSON.stringify(rec.facets));
  const bytes = Buffer.from(POST, "utf8");
  const idx = rec.facets && rec.facets[0] && rec.facets[0].index;
  check("the facet's byte offsets point at the link in the exact text posted (multibyte text before it)",
    idx && bytes.slice(idx.byteStart, idx.byteEnd).toString("utf8") === LINK && idx.byteStart !== POST.indexOf(LINK), JSON.stringify(idx));

  const beforeReplay = snapshot(f.b.db);
  x = await f.b.execute(f.proposal);
  check("a replay returns already_published with the uri", x.result && x.result.already_published === true && x.result.uri === POSTED.uri,
    x.error ? x.error.message : JSON.stringify(x.result));
  check("a replay posts nothing and changes nothing", f.b.gate.calls === 1 && f.b.gate.posts.length === 1 && snapshot(f.b.db) === beforeReplay, f.b.gate.calls);

  f = await filed(seed(), {}, T.max);
  x = await f.b.execute(f.proposal);
  check("300 graphemes publish", x.result && x.result.uri === POSTED.uri && f.b.gate.posts.length === 1, x.error ? x.error.message : "");
  const plain = seed();
  plain.ai_tasks.push(task(20, OWNER, runOutput("No links here.")));
  f = await filed(plain, {}, tid(20));
  x = await f.b.execute(f.proposal);
  check("a post with no link has no facets key at all", x.result && JSON.stringify(Object.keys(f.b.gate.posts[0])) === JSON.stringify(["text", "createdAt"]),
    f.b.gate.posts[0] && JSON.stringify(Object.keys(f.b.gate.posts[0])));

  const failuresCases = [
    ["rate_limited", /rate limit: no Bluesky call until 2026-10-11T12:15:00\.000Z/, 0],
    ["login_failed", /did not take the post \(login_failed: Invalid identifier or password\)/, 0],
    ["throws", /did not take the post \(post_error: upstream 500\)/, 1],
    ["no_uri", /without a post uri/, 1]
  ];
  for (const [mode, re, posts] of failuresCases) {
    f = await filed(seed(), { gate: mode });
    x = await f.b.execute(f.proposal);
    const d = draftOf(f.b.db, f.draftId);
    check(mode + ": throws " + re.source + ", saying nothing is retried", x.error && re.test(x.error.message) && /Nothing is retried automatically/.test(x.error.message),
      x.error ? x.error.message : JSON.stringify(x.result));
    check(mode + ": the draft is publish_failed with that reason, not published", d.status === "publish_failed" && re.test(d.publish_error) && !d.platform_post_uri && !d.published_at,
      JSON.stringify(d));
    check(mode + ": tried exactly once", f.b.gate.calls === 1 && f.b.gate.posts.length === posts, f.b.gate.calls + "/" + f.b.gate.posts.length);
  }

  f = await filed(seed(), {
    override: (q) => q.table === "social_post_drafts" && q.op === "update" && q.payload.status === "published" ? { data: null, error: { message: "db down" } } : null
  });
  x = await f.b.execute(f.proposal);
  check("posted but not recorded: throws naming the uri and saying not to post again",
    x.error && x.error.message.indexOf(POSTED.uri) !== -1 && /WAS published/.test(x.error.message) && /Do not post it again/.test(x.error.message),
    x.error ? x.error.message : JSON.stringify(x.result));

  /* ── 5. PUT ───────────────────────────────────────────────────────────── */
  console.log("\n══ 5. PUT /api/social-drafts/:id: only the server marks a draft ══");
  for (const st of ["pending_approval", "published", "publish_failed"]) {
    b = build(seed());
    const before = snapshot(b.db);
    r = await b.put(OWNER, PLAIN_DRAFT, { status: st });
    check("PUT status " + st + ": 400, nothing changed", r.code === 400 && /set only by the server/.test(r.body && r.body.error) && snapshot(b.db) === before,
      r.code + " " + JSON.stringify(r.body));
  }
  for (const st of ["pending_approval", "published"]) {
    b = build(seed());
    draftOf(b.db, PLAIN_DRAFT).status = st;
    if (st === "published") Object.assign(draftOf(b.db, PLAIN_DRAFT), { platform_post_uri: POSTED.uri, published_at: "2026-10-11T00:00:00Z" });
    const before = snapshot(b.db);
    r = await b.put(OWNER, PLAIN_DRAFT, { content: "edited after filing" });
    check("PUT content on a " + st + " draft: 400, nothing changed", r.code === 400 && /cannot be edited/.test(r.body && r.body.error) && snapshot(b.db) === before,
      r.code + " " + JSON.stringify(r.body));
  }
  b = build(seed());
  r = await b.put(OWNER, PLAIN_DRAFT, { content: "edited", status: "pending" });
  check("PUT on a plain draft still edits it", r.code === 200 && r.body.draft.content === "edited" && draftOf(b.db, PLAIN_DRAFT).status === "pending", r.code + " " + JSON.stringify(r.body));
  b = build(seed());
  r = await b.put(OWNER, OTHERS_DRAFT, { content: "mine now" });
  check("PUT on another user's draft: 404, nothing changed", r.code === 404 && draftOf(b.db, OTHERS_DRAFT).content === POST, r.code);

  /* ── 6. POST /api/proposals ───────────────────────────────────────────── */
  console.log("\n══ 6. POST /api/proposals ══");
  b = build(seed());
  r = await b.hit("post " + R_PROPOSALS, OWNER, { agent_type: "social", action_type: "publish_social_post", title: "Post it", payload: { draft_id: PLAIN_DRAFT, text: "anything" } });
  check("action_type publish_social_post: 400 pointing at propose-post, nothing filed",
    r.code === 400 && /social\/propose-post/.test(r.body && r.body.error) && b.db.tables.agent_proposals.length === 0, r.code + " " + JSON.stringify(r.body));

  /* ── 7. the wiring ────────────────────────────────────────────────────── */
  console.log("\n══ 7. the wiring ══");
  b = build(seed());
  check("propose-post has the social routes' middleware: requireAuth, requireActiveSubscription, aiLimiter",
    JSON.stringify(b.routes["post " + R_PROPOSE].middleware) === JSON.stringify(["requireAuth", "requireActiveSubscription", "aiLimiter"]) &&
    JSON.stringify(b.routes["post " + R_POST].middleware) === JSON.stringify(b.routes["post " + R_PROPOSE].middleware));
  const execStart = DISK.indexOf("const PROPOSAL_EXECUTORS = {");
  const executors = execStart < 0 ? "" : DISK.slice(execStart, s.braceMatch(DISK, DISK.indexOf("{", execStart)) + 1);
  check("PROPOSAL_EXECUTORS registers publish_social_post: executePublishSocialPost", /\n  publish_social_post: executePublishSocialPost,\n/.test(executors));
  const gated = /const SUBSCRIPTION_GATED_PROPOSAL_ACTIONS = \[([^\]]*)\]/.exec(DISK);
  check("publish_social_post is subscription gated at approval", gated && /"publish_social_post"/.test(gated[1]), gated && gated[1]);
  const nonDispatch = /var CHAIN_NON_DISPATCHABLE_TOOLS = \[([^\]]*)\]/.exec(DISK);
  check("social/propose-post is in CHAIN_NON_DISPATCHABLE_TOOLS", nonDispatch && /"social\/propose-post"/.test(nonDispatch[1]), nonDispatch && nonDispatch[1]);
  check("TOOL_INPUT_SPECS has social/propose-post with one required task_id",
    /"social\/propose-post": \[\n    toolField\("task_id", "string", true,[^\n]*\n  \]/.test(DISK));
  check("the social/post platform description names all five platforms",
    DISK.indexOf("Must be a key of SOCIAL_PLATFORMS (x, instagram, linkedin, tiktok, bluesky); anything else is a 400.") !== -1);
  check("the outreach sender's gate call is still the only one written that way (checkBskyGate's anchor)",
    DISK.split("    var posted = await bskyGate.call(function (agent) { return agent.post(postRecord); });").length === 2);
  check("/health reports icu.graphemes_counted", /graphemes_counted: graphemesCounted\(\)/.test(DISK));

  /* ── 8. no network ────────────────────────────────────────────────────── */
  console.log("\n══ 8. no network ══");
  check("zero fetches from the lifted code", FETCHES.length === 0, JSON.stringify(FETCHES));
  check("zero sockets and DNS lookups in this process", NETWORK.length === 0, JSON.stringify(NETWORK));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.error("\nThe check threw: " + (e && e.stack || e)); process.exit(1); });
