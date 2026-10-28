"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkGuideAsk — Termaximus's Guide mode answers only with steps that exist,
   takes only whitelisted page state, writes nothing but its ledger row, is
   capped, and leaves the Oracle as it was.

   Backend "Termaximus Guide mode: verified steps from a generated map of the
   app" added POST /api/guide/ask (lib/guideAsk.js, callGuideModel in
   server.js); frontend "Guide and Oracle tabs in the Termaximus mist, with
   Show me" added the Guide tab to scripts/termaximus-presence.js.

     G1  the whitelist: question, context.page, context.visible (open_panels,
         selected_tab, empty, error_banner) and context.trail (at most 5
         { page, ago_s }); any other field, at any level, is a 400 that names
         it, and an id that carries text (a name, an email) is refused;
     G2  verification: a step whose page is not in the map, or whose
         control_id is not one of that page's controls, or which promises a
         feature BizForce lacks, is DROPPED; an answer with nothing left says
         it does not know the path and links the closest real page;
     G3  the route as server.js wires it, against an in-memory database and a
         stubbed model: requireAuth and aiLimiter, no subscription gate; the
         model is claude-haiku-4-5-20251001 with max_tokens 400 and the map in
         a cache_control system block; ONE row is written, to model_calls,
         route "guide", and no row anywhere holds the trail, the visible state
         or the question;
     G4  the limits: 30 a day subscribed, 5 unsubscribed, counted from the
         ledger; a count that cannot be read refuses (503); the platform spend
         ceiling at 100% refuses (429) before the model is asked;
     G5  the client, run in jsdom: Guide is the default tab, tabs work by
         keyboard, the answer region is aria-live, each step is a real link,
         Show me appears only for a control on THIS page and highlights it
         (outline, scrolled into view, removed on click); what it sends passes
         the whitelist and holds no input value; the trail is in
         sessionStorage only;
     G6  the Oracle is unchanged: its functions and markup in the mist are
         byte-identical to frontend aabdd14, and POST /api/oracle to backend
         6f2b68e;
     G7  the Privacy page has the sentence naming what Guide sends.

   No network (the model and the database are stubbed; jsdom's fetch is a
   stub), no live database rows.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check. A mutation
   whose search text does not match exactly once is an ERROR.

   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm");
const { execFileSync } = require("child_process");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const LIB = "lib/guideAsk.js", SERVER = "server.js", MAPF = "lib/appMap.json", LEGAL = "lib/legalPages.js";
const PRESENCE = "scripts/termaximus-presence.js", PRIVACY = "privacy.html";
const FRONT_BASE = "aabdd14", BACK_BASE = "6f2b68e";

const MUTATIONS = {
  // a step naming a control its page does not have is kept (G2)
  "invented-control-kept": [[LIB, "(cid !== null && !controlOf(map, page, cid))", "false"]],
  // a step promising a feature BizForce lacks is kept (G2)
  "false-promise-kept": [[LIB, "if (!page || !text || promisesFalsely(text) || ", "if (!page || !text || "]],
  // a field outside the whitelist is accepted in context.visible (G1)
  "non-whitelisted-field-accepted": [[LIB, '  if (extra.length) return { error: badRequest("context.visible." + extra[0], "only open_panels, selected_tab, empty and error_banner are accepted") };\n', ""]],
  // ... or at the top of the body (G1)
  "extra-body-field-accepted": [[LIB, '  if (extra.length) return { error: badRequest(extra[0], "it is not one of question or context") };\n', ""]],
  // an "id" may carry any text, so a name or an email can travel in one (G1)
  "id-carries-text": [[LIB, "var GUIDE_ID_RE = /^[A-Za-z][\\w-]{0,59}$/;", "var GUIDE_ID_RE = /^[\\s\\S]{1,200}$/;"]],
  // the trail and visible state are written to a table (G3)
  "trail-written-to-db": [[SERVER, "  await recordModelCall({\n    userId:     opts.userId,\n    agentType:  null,\n",
    "  await supabase.from(\"guide_context\").insert({ user_id: opts.userId, context: opts.user });\n  await recordModelCall({\n    userId:     opts.userId,\n    agentType:  null,\n"]],
  // ... or into the ledger row itself (G3)
  "trail-in-ledger-row": [[SERVER, "    fallbackReason: resolvedKey.reason\n  });\n  var text = (response.content || [])", "    fallbackReason: opts.user\n  });\n  var text = (response.content || [])"]],
  // guide answers are never capped (G4)
  "guide-uncapped": [[LIB, "      if (count.count >= limit) {\n", "      if (false) {\n"]],
  // unsubscribed members get the subscribers' limit (G4)
  "unsubscribed-not-tighter": [[LIB, "var GUIDE_DAILY_LIMIT_UNSUBSCRIBED = 5;", "var GUIDE_DAILY_LIMIT_UNSUBSCRIBED = 30;"]],
  // an unreadable count lets the question through (G4)
  "count-fails-open": [[LIB, '      if (!count || count.error || typeof count.count !== "number") {\n', "      if (false) {\n"]],
  // the platform spend ceiling is not consulted (G4)
  "spend-ceiling-skipped": [[SERVER, "  await enforceDailyModelCallLimit(opts.userId, guideAsk.GUIDE_ROUTE);\n", ""]],
  // the map loses its prompt-cache mark (G3)
  "map-not-cached": [[LIB, ",\n      cache_control: { type: \"ephemeral\" } }", " }"]],
  // the route gets the Oracle's subscription gate, so an unsubscribed member is never guided (G3)
  "route-subscribers-only": [[SERVER, 'app.post("/api/guide/ask", requireAuth, aiLimiter,', 'app.post("/api/guide/ask", requireAuth, requireActiveSubscription, aiLimiter,']],
  // Show me is offered for a control that is not on the page (G5)
  "show-me-missing-control": [[PRESENCE, "    if (!el || chat.contains(el)) return null;\n    return el;\n", "    if (el && chat.contains(el)) return null;\n    return el || doc.body;\n"]],
  // Show me is offered for a step on another page (G5)
  "show-me-other-page": [[PRESENCE, "    if (!step || !step.control_id || step.page !== pageKey) return null;\n", "    if (!step || !step.control_id) return null;\n"]],
  // the client sends an input's value (G5)
  "input-value-sent": [[PRESENCE, "    return { open_panels: open, selected_tab: tab, empty: empty, error_banner: banner };\n",
    "    return { open_panels: open, selected_tab: tab, empty: empty, error_banner: banner, typed: (document.querySelector(\"input\") || {}).value };\n"]],
  // the trail is kept in localStorage, beyond the tab (G5)
  "trail-in-localstorage": [[PRESENCE, "    try { sessionStorage.setItem(TMX_TRAIL_KEY, ", "    try { localStorage.setItem(TMX_TRAIL_KEY, "]],
  // the answer region is not announced (G5)
  "answer-not-live": [[PRESENCE, '<div id="tmx-guide-answer" aria-live="polite" tabindex="-1">', '<div id="tmx-guide-answer" tabindex="-1">']],
  // the Oracle is the default tab again (G5)
  "guide-not-default": [[PRESENCE, '  chat.insertBefore(guide, chatMsgs);\n  chat.classList.add("tmx-mode-guide");\n', "  chat.insertBefore(guide, chatMsgs);\n"]],
  // the Oracle's reply text changed (G6)
  "oracle-changed": [[PRESENCE, '"The channel fell silent… speak once more."', '"The channel is quiet."']],
  // the Oracle route loses its limiter (G6)
  "oracle-route-changed": [[SERVER, 'app.post("/api/oracle", requireAuth, requireActiveSubscription, oracleChatLimiter, ', 'app.post("/api/oracle", requireAuth, requireActiveSubscription, ']],
  // the Privacy page drops the sentence (G7)
  "privacy-sentence-missing": [[PRIVACY, "and the last 5 pages you visited; nothing typed into the page is sent, and that list of pages stays only in this browser tab.", "and the pages you visited."]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

let JSDOM;
try { ({ JSDOM } = require("jsdom")); } catch (e) { console.log("    FAIL  jsdom could not be loaded: " + e.message); process.exit(1); }

const lf = t => t.replace(/\r\n/g, "\n");
const FILES = {};
[LIB, SERVER, MAPF, LEGAL].forEach(f => { FILES[f] = lf(fs.readFileSync(path.join(REPO, f), "utf8")); });
[PRESENCE, PRIVACY].forEach(f => {
  const p = path.join(FRONTEND, f);
  if (!fs.existsSync(p)) { console.log("    FAIL  frontend file not found: " + p + " (set BIZFORCE_FRONTEND_DIR)"); process.exit(1); }
  FILES[f] = lf(fs.readFileSync(p, "utf8"));
});
function gitShow(cwd, rev, file) {
  try { return lf(execFileSync("git", ["show", rev + ":" + file], { cwd, maxBuffer: 64 << 20 }).toString("utf8")); }
  catch (e) { console.log("    FAIL  git show " + rev + ":" + file + " failed: " + e.message.split("\n")[0]); process.exit(1); }
}
const BASE_PRESENCE = gitShow(FRONTEND, FRONT_BASE, PRESENCE);
const BASE_SERVER = gitShow(REPO, BACK_BASE, SERVER);

if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE);
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}
const rq = require("module").createRequire(path.join(REPO, "server.js"));
const MAP = JSON.parse(FILES[MAPF]);

/* lib/guideAsk.js, compiled from FILES so a mutation of it is the one that runs. */
const G = (function () {
  const m = { exports: {} };
  vm.runInNewContext(FILES[LIB], { module: m, exports: m.exports, require: rq, Number, JSON, Object, Array, String }, { filename: LIB });
  return m.exports;
})();

/* ── lifting from server.js, by name ──────────────────────────────────────── */
const SRC = FILES[SERVER];
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
const uncommented = code => code.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
function closureOf(root, stubs) {
  const have = new Map();
  const queue = [...new Set(uncommented(root).match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || stubs.has(name)) continue;
    const def = definitionOf(name);
    if (!def) continue;
    try { new vm.Script(def); } catch (e) { continue; }
    have.set(name, def);
    new Set(uncommented(def).match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !stubs.has(id)) queue.push(id); });
  }
  return [...have.values()].sort((x, y) => SRC.indexOf(x) - SRC.indexOf(y)).join("\n\n") + "\n\n" + root;
}
// The whole app.post("/api/guide/ask", ...) statement, as server.js has it.
const ROUTE_SIG = 'app.post("/api/guide/ask",';
const routeAt = SRC.indexOf(ROUTE_SIG);
const ROUTE_SRC = routeAt === -1 ? null : SRC.slice(routeAt, SRC.indexOf("}));\n", routeAt) + 4);
const STUBS = new Set(["supabase", "console", "process", "require", "module", "app", "Buffer", "URL", "setTimeout", "setImmediate", "fetch",
  "requireAuth", "requireActiveSubscription", "aiLimiter", "Date", "Math", "JSON", "Object", "Number", "String", "Array", "Promise", "Error",
  "OWNER_ACCOUNT_ID", "isTestAccount", "Anthropic", "resolveAnthropicKey", "guideAsk", "APP_MAP", "getUserPlan"]);

/* ── an in-memory database that records every write ──────────────────────── */
const clone = x => JSON.parse(JSON.stringify(x));
function fakeDb(seed, opts) {
  const o = opts || {};
  const t = {};
  Object.keys(seed).forEach(k => { t[k] = seed[k].map(clone); });
  const writes = [];
  function from(table) {
    const q = { table, filters: [], cols: "*", opts: {}, lim: null, write: null };
    const api = {
      select(cols, so) { q.cols = cols || "*"; q.opts = so || {}; return api; },
      eq(c, v) { q.filters.push(["eq", c, v]); return api; },
      neq(c, v) { q.filters.push(["neq", c, v]); return api; },
      gte(c, v) { q.filters.push(["gte", c, v]); return api; },
      gt(c, v) { q.filters.push(["gt", c, v]); return api; },
      lte(c, v) { q.filters.push(["lte", c, v]); return api; },
      lt(c, v) { q.filters.push(["lt", c, v]); return api; },
      in(c, v) { q.filters.push(["in", c, v]); return api; },
      is(c, v) { q.filters.push(["eq", c, v]); return api; },
      order() { return api; },
      limit(n) { q.lim = n; return api; },
      range() { return api; },
      insert(rows) { q.write = "insert"; writes.push({ table, op: "insert", rows: clone([].concat(rows)) }); (t[table] = t[table] || []).push(...clone([].concat(rows))); return api; },
      upsert(rows) { q.write = "upsert"; writes.push({ table, op: "upsert", rows: clone([].concat(rows)) }); return api; },
      update(patch) { q.write = "update"; writes.push({ table, op: "update", rows: [clone(patch)] }); return api; },
      delete() { q.write = "delete"; writes.push({ table, op: "delete", rows: [] }); return api; },
      maybeSingle() { return run().then(r => r.error ? r : { data: r.data && r.data.length ? r.data[0] : null, error: null }); },
      single() { return run().then(r => r.error ? r : (r.data && r.data.length === 1 ? { data: r.data[0], error: null } : { data: null, error: { message: "not one row" } })); },
      then(res, rej) { return run().then(res, rej); }
    };
    function keep(row) {
      return q.filters.every(([op, c, v]) => {
        const x = row[c];
        if (op === "eq") return x === v;
        if (op === "neq") return x !== v;
        if (op === "gte") return x != null && String(x) >= String(v);
        if (op === "gt") return x != null && String(x) > String(v);
        if (op === "lte") return x != null && String(x) <= String(v);
        if (op === "lt") return x != null && String(x) < String(v);
        if (op === "in") return v.indexOf(x) !== -1;
        return true;
      });
    }
    function run() {
      if (q.write) return Promise.resolve({ data: null, error: null });
      if (o.fail && o.fail(q)) return Promise.resolve({ data: null, error: { message: "the database is unavailable" }, count: null });
      let rows = (t[table] || []).filter(keep);
      const count = rows.length;
      if (q.lim != null) rows = rows.slice(0, q.lim);
      return Promise.resolve({ data: q.opts.head ? null : rows.map(clone), error: null, count: q.opts.count ? count : null });
    }
    return api;
  }
  return { t, writes, client: { from, rpc: async () => ({ data: null, error: { message: "no rpc here" } }) } };
}

/* ── the route, wired as server.js wires it ──────────────────────────────── */
const OWNER_ID = rq("./lib/ownerAccount").OWNER_ACCOUNT_ID;
const SUBSCRIBER = "a0000000-0000-4000-8000-0000000000a1";
const MEMBER = "a0000000-0000-4000-8000-0000000000a2";
const AUTH = function requireAuthSentinel() {}, LIMITER = function aiLimiterSentinel() {}, SUBGATE = function requireActiveSubscriptionSentinel() {};
function wired(rows, script, dbOpts) {
  const db = fakeDb({ model_calls: rows || [] }, dbOpts);
  const calls = [];
  const routes = {};
  const logs = [];
  function Anthropic(opts) {
    this.messages = { create: async req => { calls.push(clone(req)); return script(req); } };
  }
  const ctx = {
    supabase: db.client, process: { env: {} }, OWNER_ACCOUNT_ID: OWNER_ID, isTestAccount: rq("./lib/testAccounts").isTestAccount,
    console: { log() {}, warn(m) { logs.push(String(m)); }, error(m) { logs.push(String(m)); } },
    Anthropic, resolveAnthropicKey: { withSource: async () => ({ key: "stub-key", source: "platform", reason: "no_stored_key" }) },
    guideAsk: G, APP_MAP: MAP, getUserPlan: async id => ({ active: id === SUBSCRIBER }),
    requireAuth: AUTH, aiLimiter: LIMITER, requireActiveSubscription: SUBGATE,
    app: { post(p) { routes[p] = Array.prototype.slice.call(arguments, 1); } }
  };
  vm.createContext(ctx);
  // The closure is the same text every time and finding it is the slow part, so it is found and compiled once.
  if (!wired.script) wired.script = new vm.Script(closureOf(ROUTE_SRC + "\n\nthis.__api = { PLATFORM_SPEND_STATE, modelCallUtcDay };", STUBS));
  wired.script.runInContext(ctx);
  ctx.__api.PLATFORM_SPEND_STATE.raise = function () { return Promise.resolve(); };
  const chain = routes["/api/guide/ask"] || [];
  const handler = chain[chain.length - 1];
  async function ask(userId, body) {
    const res = { statusCode: 200, body: null, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; return this; } };
    let err = null;
    await handler({ user: { id: userId }, body: clone(body) }, res, e => { err = e; });
    if (err) { res.statusCode = err.status || 500; res.body = { error: err.message, thrown: true }; }
    return res;
  }
  return { db, calls, chain, ask, logs, day: ctx.__api.modelCallUtcDay() };
}
const reply = obj => async () => ({ model: "claude-haiku-4-5-20251001", content: [{ type: "text", text: JSON.stringify(obj) }],
  usage: { input_tokens: 120, output_tokens: 90, cache_creation_input_tokens: 0, cache_read_input_tokens: 16000 } });
function guideRows(userId, day, n) {
  const out = [];
  for (let i = 0; i < n; i++) out.push({ id: 1000 + i, user_id: userId, route: "guide", model: "claude-haiku-4-5-20251001", input_tokens: 10, output_tokens: 10, created_on: day, funded_by: "platform" });
  return out;
}
const CONTEXT = {
  page: "crm.html",
  visible: { open_panels: ["customerModal"], selected_tab: null, empty: ["emptyState"], error_banner: false },
  trail: [{ page: "dashboard.html", ago_s: 95 }, { page: "wallet.html", ago_s: 40 }]
};
const Q_ADD = "How do I add a customer?";

/* Three sample questions and what the stubbed model says to each. */
const SAMPLES = [
  { q: Q_ADD, page: "crm.html", model: { steps: [
      { text: "Press \"+ Add Customer\" at the top of the list.", page: "crm.html", control_id: "#addCustomerBtn" },
      { text: "Fill in the name and what you know, then press \"Save\".", page: "crm.html", control_id: "#customerSaveBtn" }],
    link: "crm.html", note: "The ledger of your patrons opens with one press." } },
  { q: "How do I send BizCash to another member?", page: "dashboard.html", model: { steps: [
      { text: "Open your Wallet.", page: "wallet.html", control_id: null },
      { text: "Press \"Send BFC\" and enter the member and the amount.", page: "wallet.html", control_id: "#send-btn" },
      { text: "Press \"Instant Payout\" to move it to your bank.", page: "wallet.html", control_id: "#instantPayoutBtn" },
      { text: "Press \"Confirm\" to send it.", page: "wallet.html", control_id: "#send-confirm-btn" }],
    link: "wallet.html", note: "BizCash travels member to member through the Wallet." } },
  { q: "How do I schedule my Instagram posts?", page: "dashboard.html", model: { steps: [
      { text: "Open Integrations and press \"Connect Instagram\".", page: "integrations.html", control_id: "#connectInstagramBtn" },
      { text: "Schedule your posts from the Social Scheduler.", page: "social-scheduler.html", control_id: "#scheduleBtn" }],
    link: "social-scheduler.html", note: "Your posts will publish themselves." } }
];

async function main() {
  console.log("\n══ G1. only the whitelist is accepted ══");
  {
    check("G1. the whitelist is exactly: body question, context; context page, visible, trail; visible open_panels, selected_tab, empty, error_banner; trail page, ago_s",
      JSON.stringify([G.GUIDE_BODY_KEYS, G.GUIDE_CONTEXT_KEYS, G.GUIDE_VISIBLE_KEYS, G.GUIDE_TRAIL_KEYS]) ===
      JSON.stringify([["question", "context"], ["page", "visible", "trail"], ["open_panels", "selected_tab", "empty", "error_banner"], ["page", "ago_s"]]));
    const ok = G.validateGuideRequest({ question: Q_ADD, context: CONTEXT });
    check("G1. a whitelisted request is accepted, and what is kept is only the whitelist", !ok.error &&
      JSON.stringify(ok) === JSON.stringify({ question: Q_ADD, context: CONTEXT }), JSON.stringify(ok));
    const refused = [
      ["a top-level field", { question: Q_ADD, context: CONTEXT, user_email: "jane@example.com" }, "user_email"],
      ["a context field", { question: Q_ADD, context: Object.assign({}, CONTEXT, { url: "https://x/crm.html?id=9" }) }, "context.url"],
      ["a visible field (an input's value)", { question: Q_ADD, context: Object.assign({}, CONTEXT, { visible: Object.assign({}, CONTEXT.visible, { input_values: { name: "Jane Doe" } }) }) }, "context.visible.input_values"],
      ["a trail field (a page title)", { question: Q_ADD, context: Object.assign({}, CONTEXT, { trail: [{ page: "crm.html", ago_s: 3, title: "Jane's deals" }] }) }, "context.trail[0].title"],
      ["a name where an id goes", { question: Q_ADD, context: Object.assign({}, CONTEXT, { visible: Object.assign({}, CONTEXT.visible, { open_panels: ["Jane Doe"] }) }) }, "context.visible.open_panels"],
      ["an email where the tab id goes", { question: Q_ADD, context: Object.assign({}, CONTEXT, { visible: Object.assign({}, CONTEXT.visible, { selected_tab: "jane@example.com" }) }) }, "context.visible.selected_tab"],
      ["six trail entries", { question: Q_ADD, context: Object.assign({}, CONTEXT, { trail: [1, 2, 3, 4, 5, 6].map(i => ({ page: "crm.html", ago_s: i })) }) }, "context.trail"],
      ["a page that is not a page key", { question: Q_ADD, context: Object.assign({}, CONTEXT, { page: "../server.js" }) }, "context.page"],
      ["an amount as error_banner", { question: Q_ADD, context: Object.assign({}, CONTEXT, { visible: Object.assign({}, CONTEXT.visible, { error_banner: "$1,250.00" }) }) }, "context.visible.error_banner"]
    ];
    refused.forEach(([what, body, field]) => {
      const r = G.validateGuideRequest(body);
      check("G1. refused with a 400 naming the field: " + what, !!r.error && r.error.status === 400 && r.error.body.field === field && r.error.body.reason === "context_refused",
        JSON.stringify(r.error || r));
    });
    const w = wired([], reply(SAMPLES[0].model));
    const r = await w.ask(MEMBER, refused[2][1]);
    check("G1. through the route: a 400, nothing asked of the model, nothing written", r.statusCode === 400 && w.calls.length === 0 && w.db.writes.length === 0,
      r.statusCode + " " + w.calls.length + " " + JSON.stringify(w.db.writes));
  }

  console.log("\n══ G2. a step is kept only if its page and control are in the map ══");
  const shown = [];
  {
    const a1 = G.verifyGuideAnswer(MAP, SAMPLES[0].model, SAMPLES[0].q);
    check("G2. sample 1 (" + SAMPLES[0].q + "): both steps are real and kept, each with its page's path", a1.known && a1.dropped === 0 && a1.steps.length === 2 &&
      a1.steps[0].href === "/crm.html" && a1.steps[0].control_id === "#addCustomerBtn" && a1.steps[0].label === "+ Add Customer", JSON.stringify(a1));
    const a2 = G.verifyGuideAnswer(MAP, SAMPLES[1].model, SAMPLES[1].q);
    check("G2. sample 2 (" + SAMPLES[1].q + "): the invented \"#instantPayoutBtn\" step is dropped, the three real ones kept in order",
      a2.known && a2.dropped === 1 && a2.steps.map(x => x.control_id).join(",") === ",#send-btn,#send-confirm-btn", JSON.stringify(a2.steps.map(x => x.control_id)));
    const a3 = G.verifyGuideAnswer(MAP, SAMPLES[2].model, SAMPLES[2].q);
    check("G2. sample 3 (" + SAMPLES[2].q + "): an invented control and an invented page are both dropped, and the reply says it does not know that path",
      a3.known === false && a3.dropped === 2 && a3.steps.length === 0 && /^I don't know a path for that in BizForce, and I won't invent one\. The closest real page is /.test(a3.note) &&
      !!a3.link && !!MAP.pages[a3.link.page] && a3.link.href === MAP.pages[a3.link.page].p, JSON.stringify(a3));
    check("G2. ... and the model's false note (\"Your posts will publish themselves\") does not reach the member", JSON.stringify(a3).indexOf("publish themselves") === -1);
    const promise = G.verifyGuideAnswer(MAP, { steps: [{ text: "Connect your Instagram account here.", page: "integrations.html", control_id: null },
      { text: "Open Integrations.", page: "integrations.html", control_id: null }] }, "instagram");
    check("G2. a step on a real page that promises a feature BizForce lacks (connecting Instagram) is dropped too", promise.dropped === 1 && promise.steps.length === 1, JSON.stringify(promise));
    const junk = G.verifyGuideAnswer(MAP, G.parseGuideJson("I think you should press the big button."), "where is billing");
    check("G2. a reply that is not JSON gives the does-not-know answer, linking the closest page (billing.html for \"where is billing\")",
      junk.known === false && junk.link.page === "billing.html", JSON.stringify(junk));
    const many = G.verifyGuideAnswer(MAP, { steps: new Array(9).fill(SAMPLES[0].model.steps[0]) }, Q_ADD);
    check("G2. at most 6 steps survive", many.steps.length === 6 && many.dropped === 3);
    shown.push(a1, a2, a3);
    SAMPLES.forEach((smp, i) => console.log("    info  sample " + (i + 1) + " on " + smp.page + ": " + JSON.stringify(smp.q) + " -> " + JSON.stringify(shown[i])));
  }

  console.log("\n══ G3. the route as server.js wires it ══");
  {
    check("G3. server.js mounts POST /api/guide/ask", !!ROUTE_SRC);
    if (!ROUTE_SRC) return;
    const w = wired([], reply(SAMPLES[0].model));
    check("G3. its middleware is requireAuth then aiLimiter, with no subscription gate", w.chain.length === 3 && w.chain[0] === AUTH && w.chain[1] === LIMITER,
      w.chain.map(f => f && f.name).join(","));
    check("G3. aiLimiter is server.js's 20-a-minute limiter", /const aiLimiter = rateLimit\(\{\n  windowMs: 60 \* 1000,\n  max: 20,/.test(SRC));
    const body = { question: Q_ADD, context: CONTEXT };
    const r = await w.ask(MEMBER, body);
    check("G3. an unsubscribed member is answered (200) with the verified steps", r.statusCode === 200 && r.body.known === true && r.body.steps.length === 2 &&
      r.body.limit.per_day === 5 && r.body.limit.subscribed === false, JSON.stringify(r.body));
    const req = w.calls[0] || {};
    check("G3. the model is claude-haiku-4-5-20251001, max_tokens 400", req.model === "claude-haiku-4-5-20251001" && req.max_tokens === 400, req.model + " " + req.max_tokens);
    const sys = req.system || [];
    check("G3. the system is the persona, then the map in a block marked cache_control ephemeral", sys.length === 2 && sys[0].text === G.GUIDE_PERSONA && !sys[0].cache_control &&
      sys[1].cache_control && sys[1].cache_control.type === "ephemeral" && sys[1].text.indexOf(JSON.stringify({ routes: MAP.routes, pages: MAP.pages })) !== -1,
      JSON.stringify(sys.map(b => [b.text.length, b.cache_control])));
    check("G3. the persona says Termaximus, at most three sentences of framing, only the map, and the JSON shape",
      /You are Termaximus/.test(G.GUIDE_PERSONA) && /at most three sentences/.test(G.GUIDE_PERSONA) && /Use ONLY the APP MAP/.test(G.GUIDE_PERSONA) &&
      G.GUIDE_PERSONA.indexOf('{"steps":[{"text":"…","page":"<page key>","control_id":"<selector>"|null}],"link":"<page key>"|null,"note":"…"}') !== -1);
    const user = JSON.parse(((req.messages || [])[0] || { content: [{ text: "{}" }] }).content[0].text);
    check("G3. the user message carries the question, the subscription flag and the whitelisted context, and nothing else",
      JSON.stringify(user) === JSON.stringify({ question: Q_ADD, member_has_active_subscription: false, on_page: "crm.html", visible: CONTEXT.visible, trail: CONTEXT.trail }), JSON.stringify(user));
    const tables = [...new Set(w.db.writes.map(x => x.table + ":" + x.op))];
    check("G3. exactly one row is written, an insert into model_calls", w.db.writes.length === 1 && tables.join(",") === "model_calls:insert", JSON.stringify(w.db.writes));
    const row = (w.db.writes[0] || { rows: [{}] }).rows[0];
    check("G3. ... route \"guide\", the member's id, the Haiku model, and every token counted (16,000 cached read as input)",
      row.route === "guide" && row.user_id === MEMBER && row.model === "claude-haiku-4-5-20251001" && row.input_tokens === 16120 && row.output_tokens === 90, JSON.stringify(row));
    const written = JSON.stringify(w.db.writes);
    const leaked = ["dashboard.html", "wallet.html", "customerModal", "emptyState", "add a customer", "ago_s", "trail"].filter(x => written.indexOf(x) !== -1);
    check("G3. no row holds the trail, the visible state or the question", leaked.length === 0, leaked.join(","));
    check("G3. no cache-token undercount is logged for the guide's row", !w.logs.some(l => /CACHE TOKENS NOT RECORDED/.test(l)), w.logs.join(" | "));
  }

  console.log("\n══ G4. the limits ══");
  {
    check("G4. 30 guide answers a day subscribed, 5 unsubscribed", G.GUIDE_DAILY_LIMIT_SUBSCRIBED === 30 && G.GUIDE_DAILY_LIMIT_UNSUBSCRIBED === 5 &&
      G.guideDailyLimit(true) === 30 && G.guideDailyLimit(false) === 5);
    const body = { question: Q_ADD, context: CONTEXT };
    const day = wired([], reply(SAMPLES[0].model)).day;
    {
      const w = wired(guideRows(MEMBER, day, 4), reply(SAMPLES[0].model));
      const r = await w.ask(MEMBER, body);
      check("G4. an unsubscribed member's 5th guide answer of the day goes", r.statusCode === 200 && w.calls.length === 1, r.statusCode);
    }
    {
      const w = wired(guideRows(MEMBER, day, 5), reply(SAMPLES[0].model));
      const r = await w.ask(MEMBER, body);
      check("G4. ... the 6th is refused (429 guide_daily_limit, limit 5, pointing to Billing), the model never asked, nothing written",
        r.statusCode === 429 && r.body.reason === "guide_daily_limit" && r.body.limit === 5 && r.body.link.href === "/billing.html" && w.calls.length === 0 && w.db.writes.length === 0,
        r.statusCode + " " + JSON.stringify(r.body));
    }
    {
      const w = wired(guideRows(SUBSCRIBER, day, 5), reply(SAMPLES[0].model));
      const r = await w.ask(SUBSCRIBER, body);
      check("G4. a subscriber with 5 today is answered, so the unsubscribed cap is the tighter one", r.statusCode === 200 && r.body.limit.per_day === 30, r.statusCode);
    }
    {
      const w = wired(guideRows(SUBSCRIBER, day, 30), reply(SAMPLES[0].model));
      const r = await w.ask(SUBSCRIBER, body);
      check("G4. a subscriber's 31st is refused (429, limit 30)", r.statusCode === 429 && r.body.limit === 30 && w.calls.length === 0, r.statusCode + " " + JSON.stringify(r.body));
    }
    {
      const rows = guideRows(MEMBER, "2026-01-01", 9).concat(guideRows(MEMBER, day, 1).map(x => Object.assign(x, { route: "callAnthropicText" })));
      const w = wired(rows, reply(SAMPLES[0].model));
      const r = await w.ask(MEMBER, body);
      check("G4. only today's guide rows count (9 from another day and 1 other route today do not)", r.statusCode === 200, r.statusCode);
    }
    {
      const w = wired([], reply(SAMPLES[0].model), { fail: q => q.table === "model_calls" && q.filters.some(f => f[1] === "route" && f[2] === "guide") });
      const r = await w.ask(MEMBER, body);
      check("G4. a count that cannot be read refuses (503), and the model is not asked", r.statusCode === 503 && r.body.reason === "guide_count_unreadable" && w.calls.length === 0,
        r.statusCode + " " + JSON.stringify(r.body));
    }
    {
      // claude-sonnet-5 is $10 per million output tokens: $25, the default ceiling, is 2,500,000.
      const spend = [{ id: 1, user_id: "someone", route: "callAnthropicText", model: "claude-sonnet-5", input_tokens: 0, output_tokens: 2500000, funded_by: "platform", created_on: day }];
      const w = wired(spend, reply(SAMPLES[0].model));
      const r = await w.ask(SUBSCRIBER, body);
      check("G4. the platform spend ceiling at 100% refuses (429 PLATFORM_DAILY_SPEND_LIMIT) before the model is asked, nothing written",
        r.statusCode === 429 && r.body.reason === "PLATFORM_DAILY_SPEND_LIMIT" && w.calls.length === 0 && w.db.writes.length === 0, r.statusCode + " " + JSON.stringify(r.body));
      const w2 = wired([Object.assign({}, spend[0], { output_tokens: 2400000 })], reply(SAMPLES[0].model));
      const r2 = await w2.ask(SUBSCRIBER, body);
      check("G4. ... and at 96% it still answers", r2.statusCode === 200 && w2.calls.length === 1, r2.statusCode);
    }
  }

  console.log("\n══ G5. the mist's Guide tab, run in jsdom ══");
  await client();

  console.log("\n══ G6. the Oracle is unchanged ══");
  {
    const fnOf = (src, name) => { const at = src.indexOf("\n  function " + name + "("); return at === -1 ? null : src.slice(at, s.braceMatch(src, src.indexOf("{", at))); };
    const names = ["addMsg", "removeHistoryFailure", "showHistoryFailure", "loadChatHistory", "openChat", "closeChat", "_openGlitch", "_closeGlitch", "_renderAttachInfo", "sendMsg"];
    const differ = names.filter(n => { const a = fnOf(FILES[PRESENCE], n), b = fnOf(BASE_PRESENCE, n); return !a || a !== b; });
    check("G6. the Oracle's " + names.length + " functions in the mist are byte-identical to frontend " + FRONT_BASE, differ.length === 0, differ.join(","));
    const markupOf = src => { const a = src.indexOf("  chat.innerHTML =\n"); return a === -1 ? null : src.slice(a, src.indexOf("</div>';\n", a)); };
    check("G6. ... and so is the mist's chat markup (header, messages, attachments, the Oracle's input)", !!markupOf(FILES[PRESENCE]) && markupOf(FILES[PRESENCE]) === markupOf(BASE_PRESENCE));
    const oracleOf = src => { const a = src.indexOf('app.post("/api/oracle", '); return a === -1 ? null : src.slice(a, s.braceMatch(src, src.indexOf("async function (req, res, next) {", a) + 31)); };
    check("G6. POST /api/oracle is byte-identical to backend " + BACK_BASE, !!oracleOf(SRC) && oracleOf(SRC) === oracleOf(BASE_SERVER));
  }

  console.log("\n══ G7. the Privacy page says what Guide sends ══");
  {
    const legal = rq("./lib/legalPages");
    const sentence = (/const GUIDE_PRIVACY_SENTENCE =\n([\s\S]*?);\n/.exec(FILES[LEGAL]) || [])[1];
    const text = sentence ? vm.runInNewContext(sentence) : "";
    const escd = text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
    const deviceAt = FILES[PRIVACY].indexOf('<h2 id="device">');
    const nextAt = FILES[PRIVACY].indexOf("<h2 ", deviceAt + 5);
    const inDevice = deviceAt !== -1 && FILES[PRIVACY].slice(deviceAt, nextAt).indexOf("<li>" + escd + "</li>") !== -1;
    check("G7. privacy.html carries the sentence once, under \"5. On your device\"", !!text && inDevice && FILES[PRIVACY].split(escd).length === 2 && legal.GUIDE_PRIVACY_SENTENCE === text);
    check("G7. ... naming exactly what is sent: the page, the open panels and tab, the empty-list and error-banner flags, the last 5 pages; nothing typed; the trail stays in the tab",
      /only the page you are on/.test(text) && /which panels and tab are open/.test(text) && /whether an empty list or an error banner is showing/.test(text) &&
      /the last 5 pages you visited/.test(text) && /nothing typed into the page is sent/.test(text) && /stays only in this browser tab/.test(text));
    check("G7. the sentence matches the whitelist it describes (4 visible fields, at most 5 trail pages)", G.GUIDE_VISIBLE_KEYS.length === 4 &&
      !G.validateGuideRequest({ question: "x", context: { page: "crm.html", trail: [1, 2, 3, 4, 5].map(i => ({ page: "crm.html", ago_s: i })) } }).error &&
      !!G.validateGuideRequest({ question: "x", context: { page: "crm.html", trail: [1, 2, 3, 4, 5, 6].map(i => ({ page: "crm.html", ago_s: i })) } }).error);
  }
}

/* ── the client ──────────────────────────────────────────────────────────── */
async function client() {
  const P = FILES[PRESENCE];
  const START = "  /* ── Guide mode ─";
  const END = '  guideAnswer.addEventListener("click", function (e) { e.stopPropagation(); });\n';
  const a = P.indexOf(START), b = P.indexOf(END);
  check("G5. termaximus-presence.js has the Guide block", a !== -1 && b > a);
  if (a === -1 || b < a) return;
  const block = P.slice(a, b + END.length);
  const page = '<!doctype html><html><body>' +
    '<button id="addCustomerBtn">+ Add Customer</button>' +
    '<div id="customerModal" class="modal open"><input id="custName" value="Jane Doe"><input id="custEmail" value="jane@example.com">' +
    '<button id="customerSaveBtn">Save</button></div>' +
    '<div id="emptyState">No customers yet</div><div role="alert">Could not load $1,250.00 for Jane</div>' +
    '<div role="tablist"><button role="tab" id="tabAll" aria-selected="true">All</button></div>' +
    '<div id="tmx-chat"><div id="tmx-chat-msgs"></div><input id="tmx-chat-input"><span id="tmx-chat-title-name"></span></div></body></html>';
  const dom = new JSDOM(page, { url: "https://bizforceai.com/crm.html", runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window;
  w.sessionStorage.setItem("bf_tmx_trail", JSON.stringify([{ page: "dashboard.html", t: Date.now() - 95000 }, { page: "wallet.html", t: Date.now() - 40000 }]));
  w.localStorage.setItem("bf_token", "tok");
  const scrolled = [];
  w.Element.prototype.scrollIntoView = function () { scrolled.push(this.id); };
  w.Element.prototype.getBoundingClientRect = function () { return { width: 10, height: 10, left: 0, top: 0, right: 10, bottom: 10 }; };
  const sent = [];
  let answer = { steps: [], link: null, note: null, known: true };
  w.fetch = function (url, opts) {
    sent.push({ url, opts });
    const p = Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(answer) });
    p.catch(() => {});
    return p;
  };
  w.eval("(function () {\n  var chat = document.getElementById('tmx-chat');\n  var chatMsgs = document.getElementById('tmx-chat-msgs');\n" +
    "  var chatInput = document.getElementById('tmx-chat-input');\n  var chatTitleName = document.getElementById('tmx-chat-title-name');\n  var _chatOpen = true;\n" +
    block + "\n  window.__g = { tmxShowMeTarget: tmxShowMeTarget, tmxRenderGuide: tmxRenderGuide, tmxVisibleState: tmxVisibleState, tmxTrailForRequest: tmxTrailForRequest, tmxSelectTab: tmxSelectTab };\n})();");
  const d = w.document, g = w.__g;
  const chat = d.getElementById("tmx-chat");

  // Tabs and accessibility.
  const tg = d.getElementById("tmx-tab-guide"), to = d.getElementById("tmx-tab-oracle");
  check("G5. two tabs, Guide then Oracle, in a role=tablist; Guide is selected by default and the mist is in Guide mode",
    d.getElementById("tmx-chat-tabs").getAttribute("role") === "tablist" && tg.textContent === "Guide" && to.textContent === "Oracle" &&
    tg.getAttribute("aria-selected") === "true" && to.getAttribute("aria-selected") === "false" && chat.classList.contains("tmx-mode-guide"));
  check("G5. the Guide pane is a tabpanel labelled by its tab, and its answer region is aria-live polite",
    d.getElementById("tmx-guide").getAttribute("role") === "tabpanel" && d.getElementById("tmx-guide").getAttribute("aria-labelledby") === "tmx-tab-guide" &&
    d.getElementById("tmx-guide-answer").getAttribute("aria-live") === "polite");
  check("G5. the question box has a label and the send button is a submit with an aria-label",
    !!d.querySelector('label[for="tmx-guide-input"]') && d.getElementById("tmx-guide-send").type === "submit" && !!d.getElementById("tmx-guide-send").getAttribute("aria-label"));
  tg.focus();
  tg.dispatchEvent(new w.KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true }));
  const afterRight = [chat.classList.contains("tmx-mode-guide"), to.getAttribute("aria-selected"), d.activeElement && d.activeElement.id];
  to.dispatchEvent(new w.KeyboardEvent("keydown", { key: "ArrowLeft", bubbles: true }));
  const afterLeft = [chat.classList.contains("tmx-mode-guide"), tg.getAttribute("aria-selected"), d.activeElement && d.activeElement.id];
  check("G5. ArrowRight moves to Oracle (Oracle mode, focus on its tab), ArrowLeft back to Guide",
    JSON.stringify(afterRight) === JSON.stringify([false, "true", "tmx-tab-oracle"]) && JSON.stringify(afterLeft) === JSON.stringify([true, "true", "tmx-tab-guide"]),
    JSON.stringify([afterRight, afterLeft]));
  to.click();
  const oracleFocus = d.activeElement && d.activeElement.id;
  tg.click();
  check("G5. clicking a tab moves focus to its input (Oracle's own input, then the Guide's)", oracleFocus === "tmx-chat-input" && d.activeElement.id === "tmx-guide-input",
    oracleFocus + " " + (d.activeElement && d.activeElement.id));
  check("G5. CSS: Guide mode hides the Oracle's three parts and the Oracle mode hides the Guide; the pane fits the mist's own size",
    P.indexOf('"#tmx-chat.tmx-mode-guide #tmx-chat-msgs, #tmx-chat.tmx-mode-guide #tmx-chat-attach-info, #tmx-chat.tmx-mode-guide #tmx-chat-foot { display: none !important; }",') !== -1 &&
    P.indexOf('"#tmx-chat:not(.tmx-mode-guide) #tmx-guide { display: none; }",') !== -1 &&
    P.indexOf('"#tmx-guide { flex: 1; display: flex; flex-direction: column; min-height: 0; }",') !== -1 &&
    P.indexOf('"  width: min(288px, calc(100vw - 16px));",') !== -1);
  check("G5. opening the mist puts the cursor in the Guide's box when Guide is selected",
    P.indexOf("if (_chatOpen) { closeChat(); } else { openChat(); tmxFocusModeSoon(); }") !== -1 && /if \(_chatOpen && chat\.classList\.contains\("tmx-mode-guide"\)\) guideInput\.focus\(\);/.test(block));

  // What it sends.
  const vis = g.tmxVisibleState();
  const trail = g.tmxTrailForRequest();
  check("G5. the visible state read from a page with a filled-in form: ids and one flag only",
    JSON.stringify(vis) === JSON.stringify({ open_panels: ["customerModal"], selected_tab: "tabAll", empty: ["emptyState"], error_banner: true }), JSON.stringify(vis));
  check("G5. the trail is the pages before this one with whole seconds (this page is the context's page, not a trail entry)",
    trail.length === 2 && trail[0].page === "dashboard.html" && trail[1].page === "wallet.html" && Math.abs(trail[0].ago_s - 95) <= 2, JSON.stringify(trail));
  d.getElementById("tmx-guide-input").value = "How do I add a customer?";
  answer = G.verifyGuideAnswer(MAP, SAMPLES[0].model, SAMPLES[0].q);
  d.getElementById("tmx-guide-foot").dispatchEvent(new w.Event("submit", { bubbles: true, cancelable: true }));
  await new Promise(r => setTimeout(r, 30));
  const req = sent[0] || { opts: { body: "{}" } };
  const sentBody = JSON.parse(req.opts.body);
  check("G5. a question is POSTed to /api/guide/ask with the bearer token", /\/api\/guide\/ask$/.test(req.url || "") && req.opts.method === "POST" &&
    req.opts.headers.Authorization === "Bearer tok", req.url);
  const v = G.validateGuideRequest(sentBody);
  check("G5. what it sends passes the server's whitelist unchanged", !v.error && JSON.stringify(v) === JSON.stringify(sentBody), JSON.stringify(v.error || sentBody));
  const raw = req.opts.body;
  const typed = ["Jane", "jane@example.com", "1,250", "No customers yet", "Could not load"].filter(x => raw.indexOf(x) !== -1);
  check("G5. ... and holds no input value, name, email, amount or banner text", typed.length === 0, typed.join(","));
  check("G5. the trail is kept in sessionStorage only (bf_tmx_trail), never localStorage",
    w.sessionStorage.getItem("bf_tmx_trail") !== null && w.localStorage.getItem("bf_tmx_trail") === null &&
    JSON.parse(w.sessionStorage.getItem("bf_tmx_trail")).slice(-1)[0].page === "crm.html");

  // The answer and Show me.
  const ans = d.getElementById("tmx-guide-answer");
  const items = [...ans.querySelectorAll("ol > li")];
  check("G5. the answer is numbered steps (an <ol>), each with a real <a href> to its page",
    items.length === 2 && items.every(li => { const l = li.querySelector("a"); return l && l.getAttribute("href") === "/crm.html"; }), ans.innerHTML.slice(0, 300));
  const shows = [...ans.querySelectorAll("button.tmx-guide-show")];
  check("G5. each step whose control is on this page gets a Show me button, named for the control", shows.length === 2 &&
    shows[0].getAttribute("aria-label") === "Show me + Add Customer" && shows[1].getAttribute("aria-label") === "Show me Save", shows.map(x => x.getAttribute("aria-label")).join(","));
  shows[0].click();
  const btn = d.getElementById("addCustomerBtn");
  const lit = btn.classList.contains("tmx-show-me") && scrolled.indexOf("addCustomerBtn") !== -1;
  await new Promise(r => setTimeout(r, 5));
  d.body.click();
  check("G5. Show me outlines the control and scrolls it into view; a click anywhere removes it", lit && !btn.classList.contains("tmx-show-me"), lit + " " + btn.className);
  check("G5. the highlight is a 3px outline, removed after 6 seconds", /"\.tmx-show-me \{ outline: 3px solid #f7dd8a !important;/.test(P) && /var TMX_SHOW_MS = 6000;/.test(block) &&
    /_tmxShowTimer = setTimeout\(tmxClearShowMe, TMX_SHOW_MS\);/.test(block));
  const here = "crm.html";
  const t1 = g.tmxShowMeTarget({ page: "crm.html", control_id: "#customerSaveBtn" }, here, d);
  const t2 = g.tmxShowMeTarget({ page: "crm.html", control_id: "#activitySaveBtn" }, here, d);
  const t3 = g.tmxShowMeTarget({ page: "wallet.html", control_id: "#addCustomerBtn" }, here, d);
  const t4 = g.tmxShowMeTarget({ page: "crm.html", control_id: "#tmx-chat-input" }, here, d);
  const t5 = g.tmxShowMeTarget({ page: "crm.html", control_id: null }, here, d);
  const t6 = g.tmxShowMeTarget({ page: "crm.html", control_id: "a[href=" }, here, d);
  check("G5. Show me only for an existing control on the current page: yes for one here; no for a control missing here, a step on another page, the mist's own input, no control, or a broken selector",
    !!t1 && t1.id === "customerSaveBtn" && t2 === null && t3 === null && t4 === null && t5 === null && t6 === null, JSON.stringify([!!t1, t2, t3, t4, t5, t6].map(x => x && x.id !== undefined ? x.id : x)));
  answer = G.verifyGuideAnswer(MAP, { steps: [{ text: "Open your Wallet and press \"Send BFC\".", page: "wallet.html", control_id: "#send-btn" }] }, "send");
  d.getElementById("tmx-guide-input").value = "How do I send BizCash?";
  d.getElementById("tmx-guide-foot").dispatchEvent(new w.Event("submit", { bubbles: true, cancelable: true }));
  await new Promise(r => setTimeout(r, 30));
  check("G5. a step on another page links there and has no Show me", ans.querySelectorAll("button.tmx-guide-show").length === 0 &&
    !!ans.querySelector('ol a[href="/wallet.html"]'), ans.innerHTML.slice(0, 200));
  w.fetch = function () { const p = Promise.resolve({ ok: false, status: 429, json: () => Promise.resolve({ error: "That is all 5 guide answers for today.", link: { page: "billing.html", href: "/billing.html" } }) }); p.catch(() => {}); return p; };
  d.getElementById("tmx-guide-input").value = "again?";
  d.getElementById("tmx-guide-foot").dispatchEvent(new w.Event("submit", { bubbles: true, cancelable: true }));
  await new Promise(r => setTimeout(r, 30));
  check("G5. an error shows plainly, in the live region, with the server's words and its link", !!ans.querySelector(".tmx-guide-error") &&
    ans.querySelector(".tmx-guide-error").textContent === "That is all 5 guide answers for today." && !!ans.querySelector('a[href="/billing.html"]') &&
    d.activeElement.id === "tmx-guide-input", ans.innerHTML.slice(0, 200));
  w.close();
}

main().then(() => {
  console.log("\n" + (failures ? "CHECKS FAILED: " + failures + " of " + (passes + failures) : "ALL " + passes + " CHECKS PASSED") + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(failures ? 1 : 0);
}, e => {
  console.log("    FAIL  the harness crashed: " + (e && e.stack || e));
  process.exit(1);
});
