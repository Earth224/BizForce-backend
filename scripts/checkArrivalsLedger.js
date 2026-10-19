"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkArrivalsLedger — the Analytics agent's Arrivals Ledger counts arrivals
   per post, and per week, only through the caller's own tracked links, in
   code. It never gives an untracked post 0 arrivals, never fills a failed
   read with 0, never shows a Lead Radar lead's URI, shows the unmatched
   arrivals to the owner account alone, and never calls a model. Termaximus's
   Latest Arrivals Ledger section is counts only and fails loud, and the
   existing arrivals section counts only posts that carry their ref.

   POST /api/agents/analytics/arrivals, requireActiveSubscription and
   buildOracleAgentRecords are lifted from server.js with everything they call,
   and run in a vm against an in-memory Supabase (failures injected per read)
   with every model entry point stubbed to record a call. TEST ROWS ARE
   ISOLATED BY CONSTRUCTION: no database, no network, no model and no email is
   reached, so nobody's live data is read and nothing is written anywhere. The
   owner account's id is used only inside the in-memory tables, as the account
   lib/ownerAccount.js names; the other accounts are made up.

   WHAT THIS PROVES
     A. Scope: every content_library and outreach_sends read for the caller
        filters on the caller's user_id; engine_visits is asked only for the
        caller's own tracked refs, in batches of at most 200. The owner's one
        cross-account read is the unmatched count's, and no one else makes it.
     B. Exact counts on a known fixture: per tracked post and per outreach ref,
        all-time and per ISO week (Monday, UTC), every week of the window
        listed oldest first, a week with none a real 0, an arrival older than
        the window in the total but in no week; and the totals.
     C. A tracked post versus an untracked one: a post whose body does not
        carry its own ref (even one carrying another post's ref) is a count
        under posts_without_tracked_link, never a post with 0 arrivals, and its
        arrivals are not attributed.
     D. No tracked link: posts_tracked [] and arrivals_attributed null with
        the reason, never 0.
     E. arrivals_unmatched is the owner's alone: present and exact for the
        owner, absent for anyone else.
     F. No lead URI, post body or slug of another account anywhere in the
        response, the stored run or the Termaximus section.
     G. A failed read (error or throw) is null with its reason in exactly the
        figures it feeds, never 0.
     H. weeks 0, 53, "12", true, 1.5 and -1 are each a 400 naming the field,
        with nothing read or recorded; absent is 12; 1 and 52 are accepted.
     I. No model call on any path, none reachable, model_call_made: false.
     J. Without an active subscription: a 402, and nothing is read.
     K. Termaximus: the latest run's window, tracked posts, attributed and
        in-window arrivals, up to 3 tracked posts with titles cut to 80
        characters, and the short note; "not measured" for a missing figure;
        "could not be read just now" for a failed read. The existing arrivals
        section counts only posts whose body carries the ref (2, not 3).

   NAMED BEFORE → AFTER (Social Search build, Oct 2026, assertion changed on
   purpose): the outreach note moved from measured.outreach_note to the
   response's own outreach_note, which the page's shared renderer lists in
   TOOL_REF_KEYS. Inside measured it rendered as one narrow measured cell; it
   is a standing statement about outreach_sends, not a measurement. The
   section that pins it now reads r.body.outreach_note and asserts it is gone
   from measured.

   MUTATE=<name> edits server.js IN MEMORY (nothing on disk is touched).
   MUTATE=all runs each in its own process; an unmatched search text is an
   ERROR, never a catch (scripts/_shared.js).
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm"), crypto = require("crypto"), net = require("net"), dns = require("dns");
const REPO = path.join(__dirname, "..");
const MUTATE = process.env.MUTATE || "";
const MUT = require("./_shared");
const s = MUT;
const { OWNER_ACCOUNT_ID } = require("../lib/ownerAccount");

const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkArrivalsLedger: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkArrivalsLedger: no network"); };

const SERVER = "server.js";
const MUTATIONS = {
  // the caller's posts read loses its user filter
  "drop-user-scope": [[SERVER, "      return supabase.from(\"content_library\").select(\"id, title, slug, status, body, created_at\").eq(\"user_id\", userId).not(\"slug\", \"is\", null);",
    "      return supabase.from(\"content_library\").select(\"id, title, slug, status, body, created_at\").not(\"slug\", \"is\", null);"]],
  // every post is listed as tracked, so an untracked one shows 0 arrivals
  "untracked-as-zero": [[SERVER, "    tracked = posts.filter(function (p) { return p.tracked; })", "    tracked = posts.filter(function (p) { return true; })"]],
  // the unmatched count is computed and returned for whoever asks
  "unmatched-for-anyone": [[SERVER, "      var isOwner = userId === OWNER_ACCOUNT_ID;", "      var isOwner = true;"]],
  // the Termaximus arrivals section counts every slugged post again
  "old-denominator": [[SERVER, "\" arrival(s) through the tracked links of \" + refs.length + \" post(s);",
    "\" arrival(s) through the tracked links of \" + posts.length + \" post(s);"]],
  // the route loses its subscription gate
  "ungate": [[SERVER, "app.post(\"/api/agents/analytics/arrivals\", requireAuth, requireActiveSubscription, aiLimiter,",
    "app.post(\"/api/agents/analytics/arrivals\", requireAuth, aiLimiter,"]],
  // a failed read is taken as an empty table, so its figures read 0
  "failed-read-as-zero": [[SERVER, "    return { rows: null, reason: table + \" \" + ORACLE_RECORDS_UNREADABLE };", "    return { rows: [], reason: null };"]],
  // no tracked link reads as 0 attributed arrivals
  "no-link-as-zero": [[SERVER, "    : !tracked.length && !outreach.length ? ARRIVALS_NO_TRACKED_LINK\n", ""]]
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
const STUBS = new Set(["supabase", "console", "process", "require", "module", "app", "requireAuth", "aiLimiter", "getUserPlan",
  "Buffer", "URL", "setTimeout", "setImmediate", "fetch", "crypto", "OWNER_ACCOUNT_ID"].concat(MODEL_ENTRY));
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
const uncommented = (code) => code.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
function closure(root) {
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
  return { code: [...have.values()].sort((x, y) => SRC.indexOf(x) - SRC.indexOf(y)).join("\n\n") + "\n\n" + root, names: [...have.keys()] };
}
const PATH = "/api/agents/analytics/arrivals";
const SIG = 'app.post("' + PATH + '",';
const routeStart = SRC.indexOf(SIG);
if (routeStart < 0) { console.log("    FAIL  POST " + PATH + " not found"); process.exit(1); }
const ROUTE = SRC.slice(routeStart, s.braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("async function (req, res, next)", routeStart))) + 3);
const LIFT = closure(ROUTE + "\n\nthis.__api = { buildOracleAgentRecords: buildOracleAgentRecords, requireActiveSubscription: requireActiveSubscription, " +
  "blogRefToken: blogRefToken, outreachRefToken: outreachRefToken };");

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
  function keep(q, row) {
    return q.filters.every(([op, col, val, extra]) => {
      if (op === "or") {
        return String(col).split(",").some(part => {
          const [c, o, ...rest] = part.split("."); const raw = rest.join(".");
          return o === "is" ? test("is", row[c], raw === "null" ? null : raw) : test(o, row[c], raw);
        });
      }
      return test(op, row[col], val, extra);
    });
  }
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
    ["eq", "neq", "in", "is", "gte", "lte", "gt", "lt"].forEach(op => { b[op] = function (col, val) { q.filters.push([op, col, val]); return b; }; });
    ["order", "limit", "range"].forEach(op => { b[op] = function () { q.mods.push([op].concat([].slice.call(arguments))); return b; }; });
    return b;
  }
  return { tables, log, client: { from, rpc: () => Promise.resolve({ data: null, error: { message: "no rpc" } }) } };
}

/* ── fixtures ─────────────────────────────────────────────────────────────── */
const OWNER = OWNER_ACCOUNT_ID;
const OTHER = "bbbbbbbb-0000-4000-8000-0000000000b2";
const SUB = "cccccccc-0000-4000-8000-0000000000c3";    // a subscriber whose only post carries no tracked link
const BARE = "dddddddd-0000-4000-8000-0000000000d4";   // no posts, no sends
const BIG = "eeeeeeee-0000-4000-8000-0000000000e5";    // 450 tracked posts, for the batching
const DAY = 86400000;
const NOW = Date.now();
// The check's own ISO week arithmetic, written apart from the route's.
function monday(ms) { const d = new Date(ms); const dow = d.getUTCDay() === 0 ? 7 : d.getUTCDay(); return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()) - (dow - 1) * DAY; }
const THIS_WEEK = monday(NOW);
const WEEKS12 = Array.from({ length: 12 }, (_, i) => new Date(THIS_WEEK - (11 - i) * 7 * DAY).toISOString().slice(0, 10));
// An arrival k weeks back: this week's is a minute ago (never before Monday), an older one Monday 01:00 of that week. Postgres's +00:00 form.
const at = (k) => new Date(k === 0 ? Math.max(THIS_WEEK, NOW - 60000) : THIS_WEEK - k * 7 * DAY + 3600000).toISOString().replace("Z", "+00:00");
const day = (n) => new Date(NOW - n * DAY).toISOString();
const sha = (x) => crypto.createHash("sha256").update(x).digest("hex").slice(0, 10);
const bl = (u, slug) => "bl-" + sha("blog:" + u + ":" + slug);
const lr = (uri) => "lr-" + sha("leadradar:" + uri);
const BODY_MARK = "BODYTEXT-should-never-leave";
const body = (ref) => "<p>" + BODY_MARK + "</p><a href=\"/suppressed.html" + (ref ? "?ref=" + ref : "") + "\">See the page</a>";
const URIS = { o1: "at://did:plc:ownerlead1/app.bsky.feed.post/3kaaaaaaaaa1", o2: "at://did:plc:ownerlead2/app.bsky.feed.post/3kaaaaaaaaa2",
  x1: "at://did:plc:otherlead1/app.bsky.feed.post/3kbbbbbbbbb1" };
const P = { a1: "11111111-0000-4000-8000-000000000001", a2: "11111111-0000-4000-8000-000000000002", a3: "11111111-0000-4000-8000-000000000003",
  a4: "11111111-0000-4000-8000-000000000004", x1: "22222222-0000-4000-8000-000000000001", s1: "33333333-0000-4000-8000-000000000001" };
const OTHER_SLUG = "other-account-only-slug";
const UNMATCHED = ["bl-0000000000", "bl-0000000000", "lr-ffffffffff"];

function world() {
  let vid = 0;
  const visit = (ref, k) => ({ id: ++vid, ref, landing_path: "/suppressed.html", created_at: at(k) });
  return {
    content_library: [
      { id: P.a1, user_id: OWNER, title: "Ad account disabled", slug: "ad-account-disabled", status: "published", body: body(bl(OWNER, "ad-account-disabled")), created_at: day(20) },
      { id: P.a2, user_id: OWNER, title: "Processor dropped", slug: "processor-dropped", status: "published", body: body(bl(OWNER, "processor-dropped")), created_at: day(10) },
      // untracked, though its body carries ANOTHER post's ref
      { id: P.a3, user_id: OWNER, title: "Untracked draft", slug: "untracked-draft", status: "draft", body: body(bl(OWNER, "ad-account-disabled")), created_at: day(5) },
      { id: P.a4, user_id: OWNER, title: "No slug", slug: null, status: "draft", body: body(null), created_at: day(1) },
      { id: P.x1, user_id: OTHER, title: "Other account post", slug: OTHER_SLUG, status: "published", body: body(bl(OTHER, OTHER_SLUG)), created_at: day(3) },
      { id: P.s1, user_id: SUB, title: "Subscriber post", slug: "sub-post", status: "published", body: body(null), created_at: day(3) }
    ],
    outreach_sends: [
      { id: "aaaaaaaa-0000-4000-8000-000000000001", user_id: OWNER, lead_post_uri: URIS.o1, source: "bluesky", sent_at: day(30) },
      { id: "aaaaaaaa-0000-4000-8000-000000000002", user_id: OWNER, lead_post_uri: URIS.o2, source: "bluesky", sent_at: day(30) },
      { id: "aaaaaaaa-0000-4000-8000-000000000003", user_id: OTHER, lead_post_uri: URIS.x1, source: "bluesky", sent_at: day(30) }
    ],
    engine_visits: [
      visit(bl(OWNER, "ad-account-disabled"), 0), visit(bl(OWNER, "ad-account-disabled"), 0), visit(bl(OWNER, "ad-account-disabled"), 2),
      visit(bl(OWNER, "processor-dropped"), 1), visit(bl(OWNER, "processor-dropped"), 20),    // the second is older than 12 weeks
      visit(bl(OWNER, "untracked-draft"), 0),                                                  // through an untracked post's ref: never attributed
      visit(lr(URIS.o1), 3),
      visit(bl(OTHER, OTHER_SLUG), 0), visit(bl(OTHER, OTHER_SLUG), 4),
      visit(lr(URIS.x1), 1),
      visit(UNMATCHED[0], 0), visit(UNMATCHED[1], 5), visit(UNMATCHED[2], 6)
    ],
    ai_tasks: []
  };
}
function bigWorld() {
  const w = world();
  for (let i = 0; i < 450; i++) {
    const slug = "big-post-" + i;
    w.content_library.push({ id: "44444444-0000-4000-8000-" + String(i).padStart(12, "0"), user_id: BIG, title: "Big " + i, slug, status: "published",
      body: body(bl(BIG, slug)), created_at: day(400 - i % 300) });
  }
  w.engine_visits.push({ id: 900, ref: bl(BIG, "big-post-437"), landing_path: "/suppressed.html", created_at: at(0) });
  w.engine_visits.push({ id: 901, ref: bl(BIG, "big-post-3"), landing_path: "/suppressed.html", created_at: at(1) });
  return w;
}

/* ── the harness ──────────────────────────────────────────────────────────── */
function context(seed, opts) {
  const o = opts || {};
  const db = fakeDb(seed, o.fail);
  const modelCalls = [];
  const logs = [];
  const handlers = {};
  const record = (name) => function () { modelCalls.push(name); throw new Error("checkArrivalsLedger: " + name + " must not be called"); };
  const rq = require("module").createRequire(path.join(REPO, "server.js"));
  const ctx = {
    supabase: db.client, require: rq, module: {}, Date, Buffer, URL, setImmediate, crypto, OWNER_ACCOUNT_ID,
    setTimeout: () => 0, fetch: record("fetch"),
    process: { env: Object.assign({ ENABLE_EMAIL_SEQUENCES: "false" }, o.env || {}) },
    console: { log: (...a) => logs.push(a.join(" ")), error: (...a) => logs.push(a.join(" ")), warn: (...a) => logs.push(a.join(" ")) },
    getUserPlan: async () => (o.plan || { active: true, plan: "pro", subscription: { status: "active" }, config: {}, exempt: false, access_reason: "subscribed" }),
    app: { post(p) { handlers[p] = [].slice.call(arguments, 1); }, get() {}, use() {} }
  };
  MODEL_ENTRY.forEach(n => { ctx[n] = record(n); });
  ctx.requireAuth = function requireAuth(req, res, next) { next(); };
  ctx.aiLimiter = function aiLimiter(req, res, next) { next(); };
  vm.createContext(ctx);
  vm.runInContext(LIFT.code, ctx);
  return { ctx, db, modelCalls, logs, handlers };
}

// One request down the route's real middleware chain, as registered.
async function post(body, opts) {
  const o = opts || {};
  const h = context(o.seed || world(), o);
  const chain = h.handlers[PATH] || [];
  const req = { user: { id: o.user || OWNER, role: "user" }, body, method: "POST", route: { path: PATH }, headers: {} };
  const res = { statusCode: 200, body: null, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; return this; } };
  let error = null;
  for (let i = 0; i < chain.length; i++) {
    let advanced = false;
    await chain[i](req, res, (e) => { if (e) error = e; else advanced = true; });
    if (error || !advanced) break;
  }
  return { status: error ? 500 : res.statusCode, body: res.body, error, h, chain };
}
const reads = (r, table) => r.h.db.log.filter(q => q.table === table && q.op === "select");
const scoped = (q, who) => q.filters.some(f => f[0] === "eq" && f[1] === "user_id" && f[2] === who) && !q.filters.some(f => f[0] === "or");
const UNMATCHED_COLS = { content_library: "id, user_id, slug", outreach_sends: "id, lead_post_uri", engine_visits: "id, ref" };
const isUnmatchedRead = (q) => UNMATCHED_COLS[q.table] === q.cols && !q.filters.some(f => f[0] === "eq" || f[0] === "in");
const weeksOf = (row) => (row && row.arrivals_by_week || []).map(w => w.week_start);
const countsOf = (row) => (row && row.arrivals_by_week || []).map(w => w.arrivals);
const expectWeeks = (byK) => WEEKS12.map((_, i) => byK[11 - i] || 0);
function withoutRunId(b) { const c = JSON.parse(JSON.stringify(b || {})); delete c.task_id; return c; }
function leaksIn(text, extra) {
  return [].concat(Object.values(URIS), [BODY_MARK, OTHER_SLUG, "Other account post", "did:plc:"], extra || []).filter(x => text.indexOf(x) !== -1);
}
function unreasonedNulls(measured) {
  const out = [];
  (function walk(v, where) {
    if (Array.isArray(v)) return v.forEach((y, i) => walk(y, where + "[" + i + "]"));
    if (!v || typeof v !== "object") return;
    Object.keys(v).forEach(k => {
      if (v[k] === null && !(typeof v[k + "_reason"] === "string" && v[k + "_reason"].trim())) out.push(where + "." + k);
      walk(v[k], where + "." + k);
    });
  })(measured, "measured");
  return out;
}
const NOTE = "An arrival is one request from the landing page. It records no person, so one arrival cannot be told apart from your own test click, a repeat visit, or anyone posting the ref by hand. These are arrivals, not visitors.";
const NO_LINK = "none of your posts carries a tracked link, so arrivals cannot be counted";

(async function main() {
  check("the route, requireActiveSubscription and buildOracleAgentRecords were lifted",
    ["requireActiveSubscription", "buildOracleAgentRecords", "loadArrivals", "measureArrivals", "arrivalsRead", "blogRefToken", "outreachRefToken",
      "startToolRun", "toolProvenance", "oracleArrivalsLedgerLines"].every(n => LIFT.names.indexOf(n) !== -1), LIFT.names.join(","));
  check("the check's tokens are the server's: blogRefToken and outreachRefToken recompute to the same refs",
    (function () { const h = context(world()); return h.ctx.__api.blogRefToken(OWNER, "x-y") === bl(OWNER, "x-y") && h.ctx.__api.outreachRefToken({ post_uri: URIS.o1 }) === lr(URIS.o1); })());

  /* ── A, B, C. the owner, on the fixture ─────────────────────────────── */
  console.log("\n══ A, B, C. scope, exact counts and weeks, tracked against untracked ══");
  const r = await post({});
  const m = (r.body && r.body.measured) || {};
  const t = m.totals || {};
  const byRef = {}; (m.posts_tracked || []).forEach(p => { byRef[p.ref] = p; });
  check("200 with a measured block", r.status === 200 && r.body && r.body.success === true, r.status + " " + (r.error && r.error.message));
  const ownPosts = reads(r, "content_library").filter(q => !isUnmatchedRead(q));
  const ownSends = reads(r, "outreach_sends").filter(q => !isUnmatchedRead(q));
  check("A. the caller's content_library read filters on the caller's user_id, and only that", ownPosts.length > 0 && ownPosts.every(q => scoped(q, OWNER)),
    JSON.stringify(reads(r, "content_library").map(q => [q.cols, q.filters])));
  check("A. the caller's outreach_sends read filters on the caller's user_id, and only that", ownSends.length > 0 && ownSends.every(q => scoped(q, OWNER)),
    JSON.stringify(reads(r, "outreach_sends").map(q => [q.cols, q.filters])));
  const askedRefs = [].concat(...reads(r, "engine_visits").filter(q => !isUnmatchedRead(q)).map(q => (q.filters.find(f => f[0] === "in" && f[1] === "ref") || [0, 0, ["(none)"]])[2]));
  const ownRefs = [bl(OWNER, "ad-account-disabled"), bl(OWNER, "processor-dropped"), lr(URIS.o1), lr(URIS.o2)];
  check("A. engine_visits is asked for the caller's tracked refs only: the 2 tracked posts and the 2 sends, not the untracked post's",
    askedRefs.length === 4 && ownRefs.every(x => askedRefs.indexOf(x) !== -1) && askedRefs.indexOf(bl(OWNER, "untracked-draft")) === -1, JSON.stringify(askedRefs));
  check("A. the owner's cross-account reads are exactly the unmatched count's three, one per table",
    ["content_library", "outreach_sends", "engine_visits"].every(tb => reads(r, tb).filter(isUnmatchedRead).length === 1) &&
    r.h.db.log.filter(q => q.op === "select" && q.table !== "ai_tasks").every(q => isUnmatchedRead(q) || scoped(q, OWNER) || (q.table === "engine_visits" && q.filters.some(f => f[0] === "in"))));
  check("A. nothing was written but the tool run's own ai_tasks row", r.h.db.log.filter(q => q.op !== "select").every(q => q.table === "ai_tasks") &&
    r.h.db.log.some(q => q.table === "ai_tasks" && q.op === "insert"));
  check("B. weeks defaults to 12, and the window starts on the Monday 11 weeks before this one", m.weeks === 12 && m.window_start === WEEKS12[0], m.weeks + " " + m.window_start);
  const a1 = byRef[bl(OWNER, "ad-account-disabled")], a2 = byRef[bl(OWNER, "processor-dropped")];
  check("B. every tracked post lists every week of the window, oldest first, each a Monday", [a1, a2].every(p => p && JSON.stringify(weeksOf(p)) === JSON.stringify(WEEKS12)) &&
    WEEKS12.every(w => new Date(w + "T00:00:00Z").getUTCDay() === 1), JSON.stringify(weeksOf(a1)));
  check("B. \"Ad account disabled\": 3 arrivals, 2 this week, 0 last week (a real 0), 1 two weeks back",
    a1 && a1.arrivals_total === 3 && JSON.stringify(countsOf(a1)) === JSON.stringify(expectWeeks({ 0: 2, 2: 1 })) && countsOf(a1)[10] === 0 && typeof countsOf(a1)[10] === "number",
    JSON.stringify(a1 && countsOf(a1)));
  check("B. \"Processor dropped\": 2 arrivals all-time, but only 1 in a week: the 20-week-old one is in the total and in no week",
    a2 && a2.arrivals_total === 2 && JSON.stringify(countsOf(a2)) === JSON.stringify(expectWeeks({ 1: 1 })), JSON.stringify(a2 && [a2.arrivals_total, countsOf(a2)]));
  check("B. each tracked post carries content_id, title, slug, status and ref", a1 && a1.content_id === P.a1 && a1.title === "Ad account disabled" &&
    a1.slug === "ad-account-disabled" && a1.status === "published" && a1.ref === bl(OWNER, "ad-account-disabled"), JSON.stringify(a1).slice(0, 300));
  check("B. tracked posts are listed busiest first", (m.posts_tracked || []).map(p => p.title).join("|") === "Ad account disabled|Processor dropped");
  const outByRef = {}; (m.outreach || []).forEach(o => { outByRef[o.ref] = o; });
  check("B. outreach: both of the owner's sends, by ref: 1 arrival three weeks back, and a real 0 for the other",
    (m.outreach || []).length === 2 && outByRef[lr(URIS.o1)] && outByRef[lr(URIS.o1)].arrivals_total === 1 &&
    JSON.stringify(countsOf(outByRef[lr(URIS.o1)])) === JSON.stringify(expectWeeks({ 3: 1 })) && outByRef[lr(URIS.o2)] && outByRef[lr(URIS.o2)].arrivals_total === 0 &&
    countsOf(outByRef[lr(URIS.o2)]).every(x => x === 0), JSON.stringify(m.outreach).slice(0, 300));
  check("B. an outreach row is its ref and counts only", (m.outreach || []).every(o => JSON.stringify(Object.keys(o).sort()) === JSON.stringify(["arrivals_by_week", "arrivals_total", "ref"])));
  check("B. totals: posts_read 3, posts_with_tracked_link 2, outreach_refs 2, arrivals_attributed 6 (3 + 2 + 1 + 0), arrivals_in_window 5",
    t.posts_read === 3 && t.posts_with_tracked_link === 2 && t.outreach_refs === 2 && t.arrivals_attributed === 6 && t.arrivals_in_window === 5, JSON.stringify(t));
  check("C. the untracked post (its body carries another post's ref) is not among the tracked, and its arrival is not attributed",
    !(m.posts_tracked || []).some(p => p.slug === "untracked-draft" || p.content_id === P.a3) && t.arrivals_attributed === 6);
  check("C. posts_without_tracked_link is a count only, 1, labelled \"arrivals cannot be counted\"",
    JSON.stringify(m.posts_without_tracked_link) === JSON.stringify({ count: 1, label: "arrivals cannot be counted" }), JSON.stringify(m.posts_without_tracked_link));
  check("C. a post with no slug is not read as a post", t.posts_read === 3);
  check("the fixed note is present, exactly", m.note === NOTE, m.note);
  // NAMED BEFORE → AFTER (Social Search build, Oct 2026): was measured.outreach_note; now the response's own outreach_note, shown in the reference zone.
  check("the outreach note says a 0 for an outreach ref may be a reply that never linked here, beside the limitations rather than among the measured cells",
    /may be a reply that never linked here/.test(r.body.outreach_note || "") && !("outreach_note" in m));
  check("an account with no outreach refs gets no outreach note", !("outreach_note" in ((await post({}, { user: SUB })).body || {})));
  check("E. the owner gets arrivals_unmatched: 3 (two bl-0000000000, one lr-ffffffffff; the untracked post's arrival is matched)",
    t.arrivals_unmatched === 3, t.arrivals_unmatched);

  /* ── A. batching ─────────────────────────────────────────────────────── */
  console.log("\n══ A. more than 200 refs are batched ══");
  const rb = await post({}, { user: BIG, seed: bigWorld() });
  const batches = reads(rb, "engine_visits").map(q => ((q.filters.find(f => f[0] === "in" && f[1] === "ref") || [0, 0, []])[2]).length);
  check("A. 450 tracked refs are asked in batches of at most 200 (200, 200, 50)", JSON.stringify(batches) === JSON.stringify([200, 200, 50]), JSON.stringify(batches));
  check("A. … and every arrival in every batch is counted: 2 attributed, 450 tracked posts", rb.status === 200 && rb.body.measured.totals.arrivals_attributed === 2 &&
    rb.body.measured.totals.posts_with_tracked_link === 450 && rb.body.measured.posts_tracked.filter(p => p.arrivals_total === 1).map(p => p.slug).sort().join(",") === "big-post-3,big-post-437",
    JSON.stringify(rb.body && rb.body.measured.totals));

  /* ── E. another account ──────────────────────────────────────────────── */
  console.log("\n══ E. another account ══");
  const ro = await post({}, { user: OTHER });
  const mo = (ro.body && ro.body.measured) || {};
  check("E. a non-owner sees only its own: 1 tracked post with 2 arrivals, 1 outreach ref with 1, 3 attributed",
    ro.status === 200 && mo.posts_tracked.length === 1 && mo.posts_tracked[0].arrivals_total === 2 && mo.outreach.length === 1 && mo.outreach[0].arrivals_total === 1 &&
    mo.totals.arrivals_attributed === 3 && mo.totals.posts_read === 1, JSON.stringify(mo.totals));
  check("E. a non-owner gets no arrivals_unmatched key, anywhere", !("arrivals_unmatched" in mo.totals) && !("arrivals_unmatched_reason" in mo.totals) &&
    JSON.stringify(ro.body).indexOf("arrivals_unmatched") === -1 && JSON.stringify(ro.body.provenance).indexOf("owner account only") === -1);
  check("E. a non-owner never makes the cross-account read, and every content_library and outreach_sends read is on its own user_id",
    !ro.h.db.log.some(isUnmatchedRead) && reads(ro, "content_library").concat(reads(ro, "outreach_sends")).every(q => scoped(q, OTHER)) &&
    reads(ro, "content_library").length === 1 && reads(ro, "outreach_sends").length === 1);
  check("E. nothing of the owner's reaches a non-owner", JSON.stringify(ro.body).indexOf("Ad account disabled") === -1 &&
    JSON.stringify(ro.body).indexOf(bl(OWNER, "ad-account-disabled")) === -1 && JSON.stringify(ro.body).indexOf(lr(URIS.o1)) === -1);
  check("E. the provenance says other_accounts_read true for the owner (the unmatched count), false for anyone else",
    r.body.provenance.other_accounts_read === true && ro.body.provenance.other_accounts_read === false);

  /* ── D. no tracked link ──────────────────────────────────────────────── */
  console.log("\n══ D. no tracked link: null with the reason, never 0 ══");
  const rs = await post({}, { user: SUB });
  const ms = (rs.body && rs.body.measured) || {};
  check("D. a subscriber whose only post carries no ref: posts_tracked [], posts_without_tracked_link 1, outreach []",
    rs.status === 200 && Array.isArray(ms.posts_tracked) && ms.posts_tracked.length === 0 && ms.posts_without_tracked_link.count === 1 &&
    Array.isArray(ms.outreach) && ms.outreach.length === 0, JSON.stringify(ms).slice(0, 300));
  check("D. … arrivals_attributed and arrivals_in_window are null with the reason, never 0",
    ms.totals.arrivals_attributed === null && ms.totals.arrivals_attributed_reason === NO_LINK &&
    ms.totals.arrivals_in_window === null && ms.totals.arrivals_in_window_reason === NO_LINK, JSON.stringify(ms.totals));
  check("D. … engine_visits is not read at all (there is no ref of theirs to ask for)", reads(rs, "engine_visits").length === 0);
  check("D. … and the fixed note is still there", ms.note === NOTE);
  const rn = await post({}, { user: BARE });
  check("D. an account with no posts and no sends: the same null with the reason, posts_read 0 (a real 0)",
    rn.status === 200 && rn.body.measured.totals.arrivals_attributed === null && rn.body.measured.totals.arrivals_attributed_reason === NO_LINK &&
    rn.body.measured.totals.posts_read === 0 && rn.body.measured.posts_tracked.length === 0, JSON.stringify(rn.body && rn.body.measured.totals));

  /* ── F. never a URI, a body or another account's post ───────────────── */
  console.log("\n══ F. refs and counts only ══");
  const storedRun = r.h.db.tables.ai_tasks.find(x => x.task_type === "analytics/arrivals" && x.output);
  const leaks = leaksIn(JSON.stringify(withoutRunId(r.body))).concat(leaksIn(JSON.stringify(storedRun || {})));
  check("F. no lead URI, did:plc:, post body or other account's post anywhere in the owner's response or the stored run", leaks.length === 0 && !!storedRun, leaks.join(", "));
  check("F. no field named lead_post_uri, post_uri, body or user_id in the measured block", (function () {
    const keys = []; (function walk(v) { if (Array.isArray(v)) return v.forEach(walk); if (v && typeof v === "object") Object.keys(v).forEach(k => { keys.push(k); walk(v[k]); }); })(m);
    return !keys.some(k => /^(lead_post_uri|post_uri|body|user_id|id)$/.test(k));
  })());

  /* ── G. failed reads ─────────────────────────────────────────────────── */
  console.log("\n══ G. a failed read is null with its reason, never 0 ══");
  for (const how of ["error", "throw"]) {
    const failOwn = (tb) => (q) => q.table === tb && q.op === "select" && !isUnmatchedRead(q) ? (how === "throw" ? "throw" : { message: "permission denied" }) : null;
    const fp = await post({}, { fail: failOwn("content_library") });
    const fpm = fp.body && fp.body.measured;
    check("G. content_library failing (" + how + "): posts_tracked, the untracked count and the totals it feeds null with reasons; outreach still counted",
      fp.status === 200 && fpm.posts_tracked === null && /content_library could not be read/.test(fpm.posts_tracked_reason || "") &&
      fpm.posts_without_tracked_link.count === null && /content_library could not be read/.test(fpm.posts_without_tracked_link.count_reason || "") &&
      fpm.totals.posts_read === null && fpm.totals.arrivals_attributed === null && /content_library could not be read/.test(fpm.totals.arrivals_attributed_reason || "") &&
      fpm.outreach.length === 2 && fpm.totals.outreach_refs === 2, JSON.stringify(fpm).slice(0, 400));
    const fs2 = await post({}, { fail: failOwn("outreach_sends") });
    const fsm = fs2.body && fs2.body.measured;
    check("G. outreach_sends failing (" + how + "): outreach and outreach_refs null with reasons, arrivals_attributed null (it would be short), posts still counted",
      fs2.status === 200 && fsm.outreach === null && /outreach_sends could not be read/.test(fsm.outreach_reason || "") && fsm.totals.outreach_refs === null &&
      fsm.totals.arrivals_attributed === null && /outreach_sends could not be read/.test(fsm.totals.arrivals_attributed_reason || "") && fsm.posts_tracked.length === 2,
      JSON.stringify(fsm && fsm.totals));
    const fv = await post({}, { fail: failOwn("engine_visits") });
    const fvm = fv.body && fv.body.measured;
    check("G. engine_visits failing (" + how + "): every post's and ref's arrivals null with the reason, the totals null, the posts still listed",
      fv.status === 200 && fvm.posts_tracked.length === 2 && fvm.posts_tracked.every(p => p.arrivals_total === null && p.arrivals_by_week === null &&
        /engine_visits could not be read/.test(p.arrivals_total_reason || "")) && fvm.outreach.every(o => o.arrivals_total === null) &&
      fvm.totals.arrivals_attributed === null && fvm.totals.arrivals_in_window === null && fvm.totals.posts_with_tracked_link === 2,
      JSON.stringify(fvm && fvm.totals));
    const fu = await post({}, { fail: (q) => isUnmatchedRead(q) && q.table === "outreach_sends" ? (how === "throw" ? "throw" : { message: "x" }) : null });
    check("G. the unmatched count failing (" + how + "): arrivals_unmatched null with its reason, everything else counted",
      fu.status === 200 && fu.body.measured.totals.arrivals_unmatched === null && /could not be read/.test(fu.body.measured.totals.arrivals_unmatched_reason || "") &&
      fu.body.measured.totals.arrivals_attributed === 6, JSON.stringify(fu.body && fu.body.measured.totals));
    check("G. … and not_read names what failed", (fp.body.measured.not_read || []).some(x => /content_library/.test(x)) && (fu.body.measured.not_read || []).length === 1);
  }
  const nulls = [r, rs, await post({}, { fail: q => q.table === "content_library" ? { message: "x" } : null }),
    await post({}, { fail: q => q.table === "engine_visits" ? { message: "x" } : null })].map(x => unreasonedNulls(x.body && x.body.measured));
  check("G. every null in the measured block has a <key>_reason beside it", nulls.every(n => n.length === 0), JSON.stringify(nulls));

  /* ── H. validation ───────────────────────────────────────────────────── */
  console.log("\n══ H. weeks is refused, never coerced ══");
  for (const bad of [0, 53, "12", true, 1.5, -1]) {
    const rv = await post({ weeks: bad });
    check("H. weeks " + JSON.stringify(bad) + " is a 400 naming the field, and nothing is read or recorded",
      rv.status === 400 && rv.body && rv.body.field === "weeks" && /weeks/.test(rv.body.error || "") && rv.h.db.log.length === 0, rv.status + " " + JSON.stringify(rv.body));
  }
  for (const good of [1, 52]) {
    const rg = await post({ weeks: good });
    check("H. weeks " + good + " is accepted, with " + good + " week(s) listed", rg.status === 200 && rg.body.measured.weeks === good &&
      rg.body.measured.posts_tracked[0].arrivals_by_week.length === good, rg.status);
  }
  const r1 = await post({ weeks: 1 });
  check("H. a 1-week window: this week only, so 2 arrivals in the window (the post's 2 this week)", r1.body.measured.totals.arrivals_in_window === 2 &&
    r1.body.measured.totals.arrivals_attributed === 6, JSON.stringify(r1.body.measured.totals));
  const ru = await post({ weeks: 12, user_id: OTHER });
  check("H. a user id in the body is never read: the owner's figures, the owner's scope", ru.status === 200 && ru.body.measured.totals.arrivals_attributed === 6 &&
    reads(ru, "content_library").filter(q => !isUnmatchedRead(q)).every(q => scoped(q, OWNER)));

  /* ── I. no model ─────────────────────────────────────────────────────── */
  console.log("\n══ I. no model call ══");
  const every = [r, rb, ro, rs, rn, r1, ru];
  check("I. no model entry point or network call was made on any path", every.every(x => x.h.modelCalls.length === 0) && NETWORK.length === 0,
    every.map(x => x.h.modelCalls.join("+")).join(" | ") + " " + NETWORK.join(","));
  const lifted = closure(ROUTE);
  const reach = MODEL_ENTRY.filter(n => new RegExp("\\b" + n + "\\b").test(uncommented(lifted.code)));
  check("I. no model entry point is reachable from the route", reach.length === 0, reach.join(","));
  check("I. the provenance says model_call_made: false, inferred nothing, from the caller's own records",
    r.body.provenance && r.body.provenance.model_call_made === false && r.body.provenance.inferred_by_model.length === 0 &&
    r.body.provenance.own_records_read === true && /Model called: no\./.test(r.body.provenance.caveat), JSON.stringify(r.body.provenance).slice(0, 300));
  check("I. not_measured names Bluesky reach and clicks, article views, the channel, unique people and conversions",
    ["Reach, impressions, likes, reposts or clicks on Bluesky", "Article views", "Which channel brought a reader", "Unique people", "Conversions"].every(p =>
      r.body.limitations.not_measured.some(x => x.indexOf(p) === 0)), JSON.stringify(r.body.limitations));

  /* ── J. the gate ─────────────────────────────────────────────────────── */
  console.log("\n══ J. no free tier ══");
  const rj = await post({}, { plan: { active: false, plan: null, subscription: null, config: null, exempt: false, access_reason: "no_subscription" } });
  check("J. without an active subscription: 402", rj.status === 402, rj.status + " " + JSON.stringify(rj.body).slice(0, 200));
  check("J. and none of content_library, outreach_sends, engine_visits or ai_tasks was touched",
    rj.h.db.log.every(q => !/content_library|outreach_sends|engine_visits|ai_tasks/.test(q.table)), rj.h.db.log.map(q => q.table).join(","));
  check("J. the gate in front of the handler is the real requireActiveSubscription", r.chain.some(f => f === r.h.ctx.__api.requireActiveSubscription));

  /* ── K. Termaximus ───────────────────────────────────────────────────── */
  console.log("\n══ K. Termaximus ══");
  async function records(seed, who, fail) {
    const h = context(seed, { fail });
    const failed = [];
    const text = await h.ctx.__api.buildOracleAgentRecords(who || OWNER, (what) => failed.push(what));
    return { text, failed, log: h.db.log };
  }
  function sectionOf(text, title) {
    const i = text.indexOf(title);
    if (i === -1) return "";
    const rest = text.slice(i);
    const next = rest.slice(title.length).search(/\n[A-Z][^\n]*?:/);
    return next < 0 ? rest : rest.slice(0, title.length + next);
  }
  const TITLE = "Latest Arrivals Ledger (counts only)";
  const ARR = "Arrivals from this account's published posts";
  const seeded = world();
  seeded.ai_tasks = [JSON.parse(JSON.stringify(storedRun)),
    { id: "acacacac-0000-4000-8000-000000000001", user_id: OTHER, task_type: "analytics/arrivals", status: "completed", created_at: day(0),
      output: { measured: { weeks: 4, posts_tracked: [{ title: "Other account post", arrivals_total: 999 }], totals: { posts_with_tracked_link: 999, arrivals_attributed: 999 } } } }];
  const k1 = await records(seeded);
  const sec = sectionOf(k1.text, TITLE);
  check("K. the latest run: its date, window 12 weeks, 2 tracked posts, 6 attributed, 5 in the window",
    sec.indexOf("- " + String(storedRun.created_at).slice(0, 10) + ": window 12 week(s); tracked posts: 2; attributed arrivals: 6; in the window: 5") !== -1, sec);
  check("K. then the tracked posts with their arrivals, busiest first, then the short note",
    /\n- "Ad account disabled": arrivals 3\n- "Processor dropped": arrivals 2\n- An arrival is one landing-page request, not a person/.test(sec), sec);
  check("K. the caller's run only: the other account's 999 is not shown, and the read filters on the caller's user_id",
    sec.indexOf("999") === -1 && sec.indexOf("Other account post") === -1 &&
    k1.log.filter(q => q.table === "ai_tasks" && q.filters.some(f => f[1] === "task_type" && f[2] === "analytics/arrivals")).every(q => q.filters.some(f => f[0] === "eq" && f[1] === "user_id" && f[2] === OWNER)));
  check("K. no lead URI, ref, body or other account's post in the section", leaksIn(sec, ["bl-", "lr-"]).length === 0, leaksIn(sec, ["bl-", "lr-"]).join(","));
  const longTitle = "A very long article title that keeps going well past the eighty characters the records allow for any one title";
  const many = world();
  many.ai_tasks = [{ id: "acacacac-0000-4000-8000-000000000002", user_id: OWNER, task_type: "analytics/arrivals", status: "completed", created_at: day(1),
    output: { measured: { weeks: 8, posts_tracked: [longTitle, "Two", "Three", "Four", "Five"].map((title, i) => ({ title, arrivals_total: 5 - i })),
      totals: { posts_with_tracked_link: 5, arrivals_attributed: 15, arrivals_in_window: 9 } } } }];
  const k2 = sectionOf((await records(many)).text, TITLE);
  const titleLine = (k2.match(/\n- "([^"]*)": arrivals 5/) || [])[1] || "";
  check("K. at most 3 tracked posts, and a title is cut to 80 characters", (k2.match(/": arrivals \d/g) || []).length === 3 && titleLine.length > 0 &&
    titleLine.length <= 80 && longTitle.indexOf(titleLine.replace(/…$/, "")) === 0 && !/"Four"/.test(k2), k2);
  const nulled = world();
  nulled.ai_tasks = [{ id: "acacacac-0000-4000-8000-000000000003", user_id: OWNER, task_type: "analytics/arrivals", status: "completed", created_at: day(1),
    output: { measured: { weeks: 12, posts_tracked: [], totals: { posts_with_tracked_link: 0, arrivals_attributed: null, arrivals_in_window: null } } } }];
  const k3 = sectionOf((await records(nulled)).text, TITLE);
  check("K. a missing figure prints \"not measured\", never 0", /tracked posts: 0; attributed arrivals: not measured; in the window: not measured/.test(k3), k3);
  const k0 = sectionOf((await records(world())).text, TITLE);
  check("K. no run yet: \"- none\"", /^Latest Arrivals Ledger \(counts only\):\n- none/.test(k0), k0);
  for (const how of ["error", "throw"]) {
    const kf = await records(seeded, OWNER, q => q.table === "ai_tasks" && q.filters.some(f => f[1] === "task_type" && f[2] === "analytics/arrivals")
      ? (how === "throw" ? "throw" : { message: "permission denied" }) : null);
    const ks = sectionOf(kf.text, TITLE);
    check("K. a failed read (" + how + ") says it could not be read, never a count",
      /^Latest Arrivals Ledger \(counts only\): could not be read just now\./.test(ks) && !/arrivals \d/.test(ks) && kf.failed.some(f => /Latest Arrivals Ledger/.test(f)), ks);
  }
  // The existing section, with its denominator fixed: 3 slugged posts, 2 of them carry their ref.
  const arrOwner = sectionOf(k1.text, ARR);
  check("K. the arrivals section counts only posts whose body carries the ref: \"5 arrival(s) through the tracked links of 2 post(s)\" (was \"of 3\")",
    /- 5 arrival\(s\) through the tracked links of 2 post\(s\)/.test(arrOwner), arrOwner);
  const arrSub = sectionOf((await records(world(), SUB)).text, ARR);
  check("K. a subscriber with posts but no tracked link: says arrivals cannot be counted, never \"0 arrival(s)\"",
    /- none of this account's 1 post\(s\) carries a tracked link, so arrivals cannot be counted/.test(arrSub) && !/0 arrival/.test(arrSub), arrSub);
  const arrBare = sectionOf((await records(world(), BARE)).text, ARR);
  check("K. an account with no slugged post: \"- none\"", /\n- none$/.test(arrBare.trim() ? arrBare.trimEnd() : ""), arrBare);

  console.log("\n" + (failures ? failures + " FAILED, " + passes + " passed" : "ALL " + passes + " CHECKS PASSED"));
  process.exit(failures ? 1 : 0);
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack)); process.exit(1); });
