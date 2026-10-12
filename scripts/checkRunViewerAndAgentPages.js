"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkRunViewerAndAgentPages — every run can be opened, and agent pages read
   only the server.

   Frontend "Every run can be opened, and agent pages read only the server"
   added run.html?id=<uuid>, pointed the Command Center's run links at it, and
   took the leftover browser stores (bf_executive_memory,
   bf_executive_agent_memory and each agent's key in them, and bf_user) out of
   every agent page's business context, Agent Stats and "Last run".

   THE FIXTURES ARE THE REAL ROUTES' ANSWERS. GET /api/ai/tasks/:id,
   GET /api/ai/tasks and GET /api/command-center are lifted from server.js and
   run in a vm against an in-memory database. run.html runs with the real
   scripts/agent-profile.js, so a tool run goes through the real renderers; the
   dashboard's Command Center script and every agent page run the same way,
   each in a vm with a stubbed DOM, every fetch answered by those routes. No
   network, no model call, no database.

   WHAT THIS PROVES
     1. run.html renders a tool run through agent-profile.js's renderToolResult
        (a whole-result renderer too), leaving the user's echoed input out of
        "Written by the model", and a markdown run as escaped text, never as
        rendered HTML. It shows the agent, type, status, created and completed
        times and the prompt, escaped.
     2. A missing id, a malformed id (no request is made) and another
        account's id all read "No run with that id was found"; a failed read
        and a network failure say the run could not be read. Never an empty
        page.
     3. The Command Center's "Ran" state, its failed runs and its newest runs
        each link to run.html with that run's id, and nothing links to Task
        History.
     4. No agent page reads the leftover store: with poisoned values in
        bf_executive_memory, bf_executive_agent_memory and bf_user, every page
        reads none of those keys and shows none of their values; the business
        context is the server's profile, a failed read says so, "Last run" is
        the newest ai_tasks row (linked to run.html) and the line is removed
        when there is none. No page or shared script names a store key in code.
     5. agent-profile.js's field map for stored runs equals every agent page's
        declared tool fields, and every inline script in every changed page
        parses.

   MUTATE=<name> edits the frontend files IN MEMORY. MUTATE=all runs each in
   its own process and passes only if every one fails at least one check. A
   mutation whose search text does not match exactly once is an ERROR, never
   counted as caught.

   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const crypto = require("crypto");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const RUN = "run.html", DASH = "dashboard.html", AP = "scripts/agent-profile.js";
const AGENT_PAGES = ["ads-agent.html", "agents/analytics.html", "agents/sales.html", "agents/seo.html", "agents/social.html", "broker-agent.html",
  "community-agent.html", "email-agent.html", "etsy-agent.html", "executive-agent.html", "influencer-agent.html", "operations-agent.html",
  "publicist-agent.html", "rd-agent.html", "reputation-agent.html", "store-agent.html", "vertical-marketing-agent.html"];

const MUTATIONS = {
  // the markdown result is put on the page as HTML
  "result-unescaped": [[RUN, "      if (task.result) { return '<pre class=\"rv-pre rv-result\">' + esc(task.result) + '</pre>'; }\n",
    "      if (task.result) { return '<pre class=\"rv-pre rv-result\">' + task.result + '</pre>'; }\n"]],
  // "Ran" links back to Task History
  "ran-to-task-history": [[DASH, "                text += ' · ' + runLink(ld.tool_task_id, \"open the run\");\n",
    "                text += ' · <a href=\"email-agent.html\">see it in Task History</a>';\n"]],
  // one agent page reads the leftover store again
  "restore-store-read": [[ "email-agent.html", "    function refreshPage() {\n",
    "    function refreshPage() {\n      var memory = JSON.parse(localStorage.getItem(\"bf_executive_memory\") || \"null\");\n" +
    "      if (memory && memory.emailAgent && memory.emailAgent.stats) document.getElementById(\"lastRunText\").textContent = String(memory.emailAgent.stats.lastRun);\n"]],
  // a failed read leaves the page empty
  "failed-read-empty": [[RUN, "        .catch(function (err) { failed((err && err.message) || \"the request failed\"); });\n",
    "        .catch(function (err) { view.innerHTML = \"\"; });\n"]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}

/* ── the frontend ───────────────────────────────────────────────────────── */
const FILES = {};
[RUN, DASH, AP, "agents/content.html"].concat(AGENT_PAGES).forEach(f => {
  const p = path.join(FRONTEND, f);
  if (!fs.existsSync(p)) { console.error("Frontend file not found: " + p + " (set BIZFORCE_FRONTEND_DIR)."); process.exit(2); }
  FILES[f] = fs.readFileSync(p, "utf8").replace(/\r\n/g, "\n");
});
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (frontend, in memory)");
}
const inlineScripts = (html) => {
  const out = []; const re = /<script(\s[^>]*)?>([\s\S]*?)<\/script>/g; let m;
  while ((m = re.exec(html))) if (!(m[1] && /\bsrc=/.test(m[1]))) out.push(m[2]);
  return out;
};

/* ── the server, lifted (the same lifter as checkCommandCenterPage) ──────── */
const SRC = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
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
const STUBS = new Set(["supabase", "nowIso", "console", "process", "require", "module", "app", "Buffer", "setTimeout",
  "requireAuth", "requireActiveSubscription", "requireAdmin", "aiLimiter", "crypto", "Date", "cron", "dispatchToolCall", "Anthropic"]);
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
  return [...have.values()].sort((x, y) => SRC.indexOf(x) - SRC.indexOf(y)).join("\n\n") + "\n\n" + root;
}
function routeText(method, route) {
  const sig = "app." + method + "(\"" + route + "\",";
  const start = SRC.indexOf(sig);
  if (start < 0 || SRC.indexOf(sig, start + 1) >= 0) throw new Error(method.toUpperCase() + " " + route + " not found exactly once");
  const end = s.braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("function (req, res, next)", start)));
  if (SRC.slice(end, end + 2) !== ");") throw new Error(method.toUpperCase() + " " + route + " did not end where expected");
  return SRC.slice(start, end + 2);
}
const LIFTED = closure([routeText("get", "/api/ai/tasks/:id"), routeText("get", "/api/ai/tasks"), routeText("get", "/api/command-center")].join("\n\n"));

/* ── the fake database ──────────────────────────────────────────────────── */
const TABLES = ["ai_tasks", "executive_dispatches", "agent_proposals", "agent_autonomy", "agent_schedules", "email_sequences",
  "email_sequence_enrollments", "social_post_drafts", "content_library", "model_calls"];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function fakeDb(seed, fail) {
  const tables = {};
  TABLES.forEach(t => { tables[t] = ((seed || {})[t] || []).map(r => JSON.parse(JSON.stringify(r))); });
  const log = [];
  function orClause(clause, row) {
    return clause.split(",").some(part => {
      const [col, op, val] = part.split(".");
      if (op === "neq") return row[col] !== null && row[col] !== undefined && row[col] !== val;
      if (op === "eq") return row[col] === val;
      throw new Error("fake db: unplanned or operator " + op);
    });
  }
  function keep(q, row) {
    return q.filters.every(f => {
      if (f[0] === "eq") return row[f[1]] === f[2];
      if (f[0] === "in") return f[2].indexOf(row[f[1]]) !== -1;
      if (f[0] === "gte") return row[f[1]] !== null && row[f[1]] !== undefined && row[f[1]] >= f[2];
      if (f[0] === "or") return orClause(f[1], row);
      return true;
    });
  }
  function project(q, row) {
    const copy = JSON.parse(JSON.stringify(row));
    if (!q.cols || q.cols.trim() === "*") return copy;
    const out = {};
    q.cols.split(",").map(c => c.trim()).forEach(c => { out[c] = copy[c] === undefined ? null : copy[c]; });
    return out;
  }
  function answer(q) {
    const injected = fail && fail(q);
    if (injected) return Promise.resolve({ data: null, error: injected, count: null });
    // Postgres refuses a uuid column compared with something that is not one.
    const badId = q.filters.find(f => f[0] === "eq" && f[1] === "id" && typeof f[2] === "string" && !UUID.test(f[2]));
    if (badId) return Promise.resolve({ data: null, error: { message: "invalid input syntax for type uuid: \"" + badId[2] + "\"" }, count: null });
    const rows = tables[q.table];
    if (!rows) return Promise.resolve({ data: null, error: { message: "unplanned table " + q.table } });
    let hits = rows.filter(r => keep(q, r));
    const orders = q.filters.filter(f => f[0] === "order");
    if (orders.length) {
      hits = hits.slice().sort((a, b) => {
        for (const o of orders) {
          const dir = o[2] && o[2].ascending === false ? -1 : 1;
          if (a[o[1]] < b[o[1]]) return -1 * dir;
          if (a[o[1]] > b[o[1]]) return 1 * dir;
        }
        return 0;
      });
    }
    const count = q.opts && q.opts.count === "exact" ? hits.length : null;
    const range = q.filters.find(f => f[0] === "range");
    if (range) hits = hits.slice(range[1], range[2] + 1);
    const limit = q.filters.find(f => f[0] === "limit");
    if (limit) hits = hits.slice(0, limit[1]);
    if (q.opts && q.opts.head) return Promise.resolve({ data: null, error: null, count });
    const copies = hits.map(r => project(q, r));
    if (q.single) return Promise.resolve({ data: copies[0] || null, error: null, count });
    return Promise.resolve({ data: copies, error: null, count });
  }
  function from(table) {
    const q = { table, op: "select", cols: null, opts: null, filters: [], single: false };
    log.push(q);
    const b = { select(cols, opts) { q.cols = cols || "*"; q.opts = opts || null; return b; } };
    ["eq", "in", "gte", "or", "order", "range", "limit"].forEach(op => { b[op] = function () { q.filters.push([op].concat([].slice.call(arguments))); return b; }; });
    b.single = b.maybeSingle = () => { q.single = true; return answer(q); };
    b.then = (res, rej) => answer(q).then(res, rej);
    return b;
  }
  return { tables, log, client: { from } };
}

/* ── fixtures ───────────────────────────────────────────────────────────── */
const OWNER = "aaaaaaaa-0000-4000-8000-000000000001";
const OTHER = "aaaaaaaa-0000-4000-8000-000000000003";
const NOW = Date.now();
const ago = (days) => new Date(NOW - days * 86400000).toISOString();
const id = (prefix, k) => prefix + "-1111-4111-8111-" + String(k).padStart(12, "0");
const T = (k) => id("71111111", k), P = (k) => id("72222222", k), D = (k) => id("73333333", k);
const HOSTILE = "<img src=x onerror=alert(1)>";
const TOOL_RUN = {
  id: T(1), user_id: OWNER, agent_type: "email", task_type: "email/subject-lines", status: "completed",
  prompt: "Subject lines for " + HOSTILE, result: "## Subject lines\n- one", error: null,
  created_at: ago(1), completed_at: ago(0.99), updated_at: ago(0.99),
  output: {
    purpose: "ECHOED-INPUT-PURPOSE",
    audience: "ECHOED-INPUT-AUDIENCE",
    subject_lines: ["Spring is here " + HOSTILE, "Last call"],
    measured: { count: 2, longest_chars: 15 },
    provenance: { model: "claude-sonnet-5", read: [] }
  }
};
const SEO_RUN = {
  id: T(2), user_id: OWNER, agent_type: "seo", task_type: "seo/audit", status: "completed", prompt: "Audit https://example.com",
  result: "audit", error: null, created_at: ago(2), completed_at: ago(1.99), updated_at: ago(1.99),
  output: { url: "https://example.com", flags: [], measured: { final_status: 200, title: "Example" }, provenance: { read: ["page"] } }
};
const MARKDOWN_RUN = {
  id: T(3), user_id: OWNER, agent_type: "content", task_type: "general", status: "completed", prompt: "Write about **bold** things",
  result: "# Heading\n\n" + HOSTILE + " and **bold** & <script>steal()</script>", error: null, output: null,
  created_at: ago(3), completed_at: ago(2.99), updated_at: ago(2.99)
};
const FAILED_RUN = {
  id: T(4), user_id: OWNER, agent_type: "content", task_type: "content/outline", status: "failed", prompt: "Outline",
  result: "Task failed: model refused", error: "model refused <b>", output: null, created_at: ago(1.5), completed_at: ago(1.49), updated_at: ago(1.49)
};
const PROCESSING_RUN = {
  id: T(5), user_id: OWNER, agent_type: "content", task_type: "general", status: "processing", prompt: "Still going",
  result: null, error: null, output: null, created_at: ago(0.01), completed_at: null, updated_at: ago(0.01)
};
const OTHERS_RUN = { id: T(6), user_id: OTHER, agent_type: "email", task_type: "general", status: "completed", prompt: "Not yours",
  result: "Another account's result", error: null, output: null, created_at: ago(1), completed_at: ago(1), updated_at: ago(1) };
const EMAIL_NEWEST = { id: T(7), user_id: OWNER, agent_type: "email", task_type: "email/sequence", status: "completed", prompt: "Newest email run",
  result: "x", error: null, output: null, created_at: "2026-10-01T09:30:00.000Z", completed_at: null, updated_at: null };
function world() {
  return {
    ai_tasks: [TOOL_RUN, SEO_RUN, MARKDOWN_RUN, FAILED_RUN, PROCESSING_RUN, OTHERS_RUN, EMAIL_NEWEST,
      { id: P(1), user_id: OWNER, agent_type: "executive", task_type: "executive/plan", status: "completed", prompt: "Plan", created_at: ago(8),
        output: { goal: "Grow", assignments: [{ id: 1, agent: "email", tool: "subject-lines", task: "Lines", priority: "high", is_dispatchable: true }] } }],
    executive_dispatches: [{ id: D(1), user_id: OWNER, plan_task_id: P(1), assignment_id: 1, agent_type: "email", tool: "subject-lines",
      outcome: "ran", refused_reason: null, detail: null, tool_task_id: T(1), chain_id: null, created_at: ago(1) }]
  };
}
const ENV = { ENABLE_EMAIL_SEQUENCES: "true", MAIL_POSTAL_ADDRESS: "1 Fixture Lane", RESEND_WEBHOOK_SECRET: "whsec_fixture", EMAIL_MARKETING_DAILY_CAP: "37" };

function server(seed, opts) {
  const o = opts || {};
  const db = fakeDb(seed, o.fail);
  const ctx = {
    supabase: db.client, JSON, Math, Promise, Date, crypto, Map, Set,
    nowIso: () => new Date().toISOString(),
    process: { env: Object.assign({}, ENV) },
    console: { log() {}, error() {}, warn() {} },
    requireAuth: function requireAuth(req, res, next) { req.user = { id: req.headers.user, role: "user" }; next(); }
  };
  const routes = {};
  const register = (method) => function (p) { routes[method + " " + p] = [].slice.call(arguments, 1); };
  ctx.app = { get: register("get") };
  vm.createContext(ctx);
  vm.runInContext(LIFTED, ctx);
  async function call(key, user, params, query) {
    const chain = routes[key];
    const res = { code: 200, body: null, status(x) { this.code = x; return this; }, json(x) { this.body = JSON.parse(JSON.stringify(x)); return this; } };
    const req = { headers: { user }, params: params || {}, query: query || {}, body: {} };
    let i = 0;
    async function step() {
      const fn = chain[i++];
      if (!fn) return;
      let advanced = false;
      await fn(req, res, (e) => { if (e) { res.code = 500; res.body = { error: "Internal server error" }; return; } advanced = true; });
      if (advanced) await step();
    }
    await step();
    return res;
  }
  // Answers a fetch the way the deployed server would, as `user`.
  async function serve(url) {
    const u = new URL(url);
    let m;
    if ((m = /^\/api\/ai\/tasks\/([^/]+)$/.exec(u.pathname))) return call("get /api/ai/tasks/:id", OWNER_SESSION.user, { id: decodeURIComponent(m[1]) });
    if (u.pathname === "/api/ai/tasks") return call("get /api/ai/tasks", OWNER_SESSION.user, {}, Object.fromEntries(u.searchParams));
    if (u.pathname === "/api/command-center") return call("get /api/command-center", OWNER_SESSION.user);
    return null;
  }
  return { db, call, serve };
}
const OWNER_SESSION = { user: OWNER };

/* ── a stubbed DOM ──────────────────────────────────────────────────────── */
function el(tag) {
  const node = {
    tagName: tag || "div", id: "", innerHTML: "", className: "", style: {}, children: [], parentNode: null, disabled: false, type: "",
    listeners: {}, attrs: {},
    get textContent() { return node._text !== undefined ? node._text : node.innerHTML; },
    set textContent(v) { node._text = String(v); node.innerHTML = String(v).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); node.children = []; },
    appendChild(c) { c.parentNode = node; node.children.push(c); return c; },
    insertBefore(c) { c.parentNode = node; node.children.unshift(c); return c; },
    removeChild(c) { node.children = node.children.filter(x => x !== c); c.parentNode = null; c.detached = true; return c; },
    addEventListener(t, f) { (node.listeners[t] = node.listeners[t] || []).push(f); },
    setAttribute(k, v) { node.attrs[k] = String(v); }, getAttribute(k) { return node.attrs[k] || null; },
    querySelector() { return null }, querySelectorAll() { return []; },
    closest() { return null; }, classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } }
  };
  return node;
}
// Everything a node shows: its HTML and every appended child's.
const shown = (node) => node ? node.innerHTML + node.children.map(shown).join("") : "";
function anything() {
  const store = {};
  const fn = function () { return proxy; };
  const proxy = new Proxy(fn, {
    get(t, k) {
      if (k in store) return store[k];
      if (k === Symbol.toPrimitive) return () => "";
      if (["value", "innerHTML", "textContent", "id", "className"].indexOf(k) !== -1) return "";
      if (k === "length") return 0;
      if (k === "checked" || k === "disabled") return false;
      if (k === "querySelectorAll" || k === "getElementsByClassName" || k === "getElementsByTagName") return () => [];
      if (k === "then" || k === "forEach") return undefined;
      return anything();
    },
    set(t, k, v) { store[k] = v; return true; },
    apply() { return anything(); }
  });
  return proxy;
}
const settle = async () => { for (let i = 0; i < 60; i++) await new Promise(r => setImmediate(r)); };
const unescape = (t) => t.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, "\"").replace(/&amp;/g, "&");
const text = (html) => unescape(String(html).replace(/<[^>]+>/g, " ")).replace(/\s+/g, " ");

/* Runs a page's inline scripts (and the given external scripts first or
   last, in page order) in one context. serve(url, init) answers fetches. */
async function runPage(opts) {
  const els = {};
  const getItemCalls = [];
  const local = Object.assign({ bf_token: "tok" }, opts.storage || {});
  if (opts.token === null) delete local.bf_token;
  const calls = [];
  const domListeners = {};
  const real = new Set(opts.realIds || []);
  const toolbarMeta = el("div"); toolbarMeta.className = "toolbar-meta";
  const document = {
    readyState: "loading",
    getElementById(i) {
      if (!real.has(i)) return opts.strict ? null : anything();
      if (!els[i]) {
        els[i] = el("div"); els[i].id = i;
        if (i === "lastRunText") { toolbarMeta.appendChild(els[i]); els[i].closest = (sel) => sel === ".toolbar-meta" ? toolbarMeta : null; toolbarMeta.parentNode = el("div"); }
      }
      return els[i];
    },
    querySelector(sel) { return opts.strict ? null : anything(); },
    querySelectorAll() { return []; },
    createElement(tag) { return el(tag); },
    addEventListener(t, f) { (domListeners[t] = domListeners[t] || []).push(f); },
    head: el("head"), body: el("body"), documentElement: el("html")
  };
  const window = {
    location: { search: opts.search || "", pathname: "/" + (opts.page || ""), href: "https://x/" + (opts.page || ""), hash: "" },
    AGENT_PROFILE_CONFIG: undefined
  };
  const ctx = {
    document, window, console: { log() {}, error() {}, warn() {}, info() {} },
    localStorage: {
      getItem(k) { getItemCalls.push(k); return Object.prototype.hasOwnProperty.call(local, k) ? local[k] : null; },
      setItem(k, v) { local[k] = String(v); }, removeItem(k) { delete local[k]; }
    },
    fetch(url, init) {
      calls.push({ url, init });
      return Promise.resolve().then(() => opts.serve(url, init)).then(r => {
        if (!r) return { ok: false, status: 404, json: () => Promise.resolve({ error: "Not found" }), text: () => Promise.resolve("{}") };
        const body = JSON.stringify(r.body);
        return { ok: r.code >= 200 && r.code < 300, status: r.code, json: () => Promise.resolve(JSON.parse(body)), text: () => Promise.resolve(body) };
      });
    },
    URLSearchParams, URL, Promise, JSON, Date, Math, Object, Array, String, Number, Boolean, RegExp, Error, Map, Set, isNaN, parseInt, parseFloat,
    encodeURIComponent, decodeURIComponent, setTimeout: () => 0, clearTimeout() {}, setInterval: () => 0, clearInterval() {},
    requestAnimationFrame: () => 0, navigator: { userAgent: "x" }, alert() {}, confirm: () => false,
    MutationObserver: function () { return { observe() {}, disconnect() {} }; },
    matchMedia: () => ({ matches: false, addEventListener() {} }), history: { replaceState() {} }
  };
  ctx.self = ctx.window = Object.assign(window, ctx, { window });
  vm.createContext(window);
  const errors = [];
  opts.scripts.forEach((code, i) => { try { vm.runInContext(code, window); } catch (e) { errors.push("script " + i + ": " + e.message); } });
  (domListeners.DOMContentLoaded || []).forEach(f => { try { f({}); } catch (e) { errors.push("DOMContentLoaded: " + e.message); } });
  await settle();
  return { els, calls, errors, getItemCalls, toolbarMeta, window, shown: (i) => shown(els[i]) };
}

/* run.html's scripts in page order: agent-profile.js, then the viewer. */
function runViewer(search, serve, extra) {
  return runPage(Object.assign({ page: RUN, search, serve, realIds: ["runView", "runRetry"], strict: true,
    scripts: [FILES[AP]].concat(inlineScripts(FILES[RUN])) }, extra || {}));
}

(async function main() {
  const srv = server(world());

  /* ── 1. a tool run and a markdown run ─────────────────────────────────── */
  console.log("\n══ 1. run.html renders what was stored ══");
  const viaRoute = await srv.call("get /api/ai/tasks/:id", OWNER, { id: T(1) });
  check("the fixture is the real route's answer: GET /api/ai/tasks/:id returns { task } for the owner", viaRoute.code === 200 && viaRoute.body.task && viaRoute.body.task.id === T(1));
  let pg = await runViewer("?id=" + T(1), (url) => srv.serve(url));
  const toolHtml = pg.shown("runView");
  // The expected HTML from the same renderer, called directly in its own page context.
  const direct = await runPage({ page: RUN, serve: () => null, scripts: [FILES[AP]], strict: true });
  const expected = direct.window.bfRenderStoredToolRun ? direct.window.bfRenderStoredToolRun(JSON.parse(JSON.stringify(viaRoute.body.task))) : null;
  check("a tool run is rendered through agent-profile.js's renderToolResult (its generated, measured and provenance panels)",
    pg.errors.length === 0 && typeof expected === "string" && expected.length > 0 && toolHtml.indexOf(expected) !== -1 &&
    /class="ap-generated"/.test(toolHtml) && /Written by the model/.test(toolHtml) && /class="ap-measured/.test(toolHtml), pg.errors.join(" | ") || toolHtml.slice(0, 300));
  const generated = (toolHtml.split('class="ap-generated"')[1] || "").split('class="ap-measured')[0];
  check("…with the user's echoed input left out of \"Written by the model\"",
    generated.indexOf("Subject lines") !== -1 && generated.indexOf("ECHOED-INPUT-PURPOSE") === -1 && generated.indexOf("ECHOED-INPUT-AUDIENCE") === -1, generated.slice(0, 300));
  check("…and the model's text escaped", toolHtml.indexOf(HOSTILE) === -1 && toolHtml.indexOf("&lt;img src=x onerror=alert(1)&gt;") !== -1);
  check("the run's agent, type, status, created and completed times and prompt (escaped)",
    ["Agent", "email", "Tool or task type", "email/subject-lines", "Status", "completed", new Date(TOOL_RUN.created_at).toLocaleString(),
      new Date(TOOL_RUN.completed_at).toLocaleString(), "Subject lines for " + HOSTILE].every(t => text(toolHtml).indexOf(t) !== -1) &&
    toolHtml.indexOf('<pre class="rv-pre rv-prompt">Subject lines for &lt;img') !== -1, text(toolHtml).slice(0, 400));
  pg = await runViewer("?id=" + T(2), (url) => srv.serve(url));
  check("a whole-result tool (seo/audit) goes through its own renderer", pg.errors.length === 0 && /ap-seo-audit/.test(pg.shown("runView")), pg.errors.join(" | ") || pg.shown("runView").slice(0, 200));

  pg = await runViewer("?id=" + T(3), (url) => srv.serve(url));
  const md = pg.shown("runView");
  check("a markdown run is shown as escaped text, not rendered",
    md.indexOf('<pre class="rv-pre rv-result"># Heading') !== -1 && md.indexOf("&lt;script&gt;steal()&lt;/script&gt;") !== -1 &&
    md.indexOf("<script>steal") === -1 && md.indexOf(HOSTILE) === -1 && !/<h1/.test(md.split("Result")[1] || "") && md.indexOf("**bold**") !== -1, md.slice(md.indexOf("Result"), md.indexOf("Result") + 300));
  pg = await runViewer("?id=" + T(4), (url) => srv.serve(url));
  check("a failed run shows its error, escaped", pg.shown("runView").indexOf("Task failed: model refused &lt;b&gt;") !== -1 && text(pg.shown("runView")).indexOf("failed") !== -1);
  pg = await runViewer("?id=" + T(5), (url) => srv.serve(url));
  check("a run still processing says so, with no completed time", text(pg.shown("runView")).indexOf("No result yet: the run is still processing.") !== -1 &&
    text(pg.shown("runView")).indexOf("not completed") !== -1);

  /* ── 2. not found, failed read ─────────────────────────────────────────── */
  console.log("\n══ 2. not found, and a failed read ══");
  const NOT_FOUND = "No run with that id was found";
  pg = await runViewer("?id=" + id("7fffffff", 9), (url) => srv.serve(url));
  check("a missing id: \"" + NOT_FOUND + "\" (the route answered 404)", text(pg.shown("runView")).indexOf(NOT_FOUND) !== -1 && pg.calls.length === 1);
  pg = await runViewer("?id=" + T(6), (url) => srv.serve(url));
  check("another account's run: the same, and none of it shown", text(pg.shown("runView")).indexOf(NOT_FOUND) !== -1 && pg.shown("runView").indexOf("Another account") === -1);
  const malformed = await srv.call("get /api/ai/tasks/:id", OWNER, { id: "not-a-uuid" });
  check("the route itself answers a malformed id with a 500 (it does not check the shape)", malformed.code === 500);
  for (const q of ["?id=not-a-uuid", "?id=", "", "?id=" + T(1) + "x", "?id=%3Cscript%3E"]) {
    pg = await runViewer(q, (url) => srv.serve(url));
    check("malformed or missing id " + JSON.stringify(q) + ": \"" + NOT_FOUND + "\", and no request made",
      text(pg.shown("runView")).indexOf(NOT_FOUND) !== -1 && pg.calls.length === 0, pg.calls.length + " " + text(pg.shown("runView")));
  }
  const broken = server(world(), { fail: q => q.table === "ai_tasks" ? { message: "connection reset" } : null });
  pg = await runViewer("?id=" + T(1), (url) => broken.serve(url));
  check("a failed read (the route answers 500) says the run could not be read, with a way to try again",
    text(pg.shown("runView")).indexOf("The run could not be read: HTTP 500") !== -1 && pg.shown("runView").indexOf('id="runRetry"') !== -1 &&
    text(pg.shown("runView")).indexOf(NOT_FOUND) === -1, text(pg.shown("runView")));
  pg = await runViewer("?id=" + T(1), () => { throw new Error("Failed to fetch"); });
  check("a network failure says so", text(pg.shown("runView")).indexOf("The run could not be read: Failed to fetch") !== -1, text(pg.shown("runView")));
  pg = await runViewer("?id=" + T(1), async () => ({ code: 200, body: { nope: true } }));
  check("an answer with no run says so", text(pg.shown("runView")).indexOf("The run could not be read: the answer carried no run") !== -1);
  pg = await runViewer("?id=" + T(1), (url) => srv.serve(url), { token: null });
  check("no session: the page says so (bf-session.js, loaded first in its head, sends the browser to sign in)",
    text(pg.shown("runView")).indexOf("Sign in to see this run.") !== -1 && pg.calls.length === 0 &&
    FILES[RUN].indexOf('<script src="/scripts/bf-session.js"></script>') !== -1 && FILES[RUN].indexOf('<script src="/scripts/bf-session.js"></script>') < FILES[RUN].indexOf("</head>"));

  /* ── 3. the Command Center links ──────────────────────────────────────── */
  console.log("\n══ 3. the Command Center links to run.html ══");
  const cc = (await srv.call("get /api/command-center", OWNER)).body;
  check("the fixture is the real GET /api/command-center's answer", cc && cc.plans && cc.plans.ok === true && cc.activity.ok === true && cc.needs_you.ok === true,
    JSON.stringify(cc && [cc.plans, cc.activity, cc.needs_you].map(x => x && x.error)));
  const ccScript = inlineScripts(FILES[DASH]).filter(c => c.indexOf("(function commandCenter() {") !== -1);
  const ccPage = await runPage({ page: DASH, serve: (url) => srv.serve(url), strict: true, scripts: ccScript,
    realIds: ["commandCenterSection", "ccStatus", "ccRefresh", "ccNeedsYou", "ccPlans", "ccActivity", "ccAutopilot", "ccOutbound", "ccSpend", "ccPlatformPanel", "ccPlatform"] });
  const links = (html) => [...html.matchAll(/href="run\.html\?id=([^"]+)"/g)].map(m => decodeURIComponent(m[1]));
  const ranDispatch = cc.plans.data[0].assignments[0].latest_dispatch;
  check("\"Ran\" links to run.html with the dispatched run's id",
    ranDispatch.outcome === "ran" && JSON.stringify(links(ccPage.shown("ccPlans"))) === JSON.stringify([ranDispatch.tool_task_id]) && ranDispatch.tool_task_id === T(1),
    ccPage.shown("ccPlans").slice(0, 400));
  const failedIds = cc.needs_you.data.failed_runs_7d.rows.map(r => r.id);
  check("each failed run links to run.html with its id",
    failedIds.length === 1 && failedIds[0] === T(4) && JSON.stringify(links(ccPage.shown("ccNeedsYou"))) === JSON.stringify(failedIds), ccPage.shown("ccNeedsYou").slice(0, 400));
  const newestIds = cc.activity.data.newest_runs.map(r => r.id);
  const newestHtml = ccPage.shown("ccActivity").split("Newest runs")[1] || "";
  check("each of the newest runs links to run.html with its id",
    newestIds.length >= 5 && JSON.stringify(links(newestHtml)) === JSON.stringify(newestIds), JSON.stringify(links(newestHtml)) + " vs " + JSON.stringify(newestIds));
  check("nothing in the Command Center links to Task History or an agent page",
    !/Task History/.test(PANEL_TEXT(ccPage)) && !/href="[a-z/-]*agent[a-z-]*\.html"|href="agents\//.test(PANEL_TEXT(ccPage)));

  /* ── 4. agent pages read the server only ──────────────────────────────── */
  console.log("\n══ 4. every agent page reads the server only ══");
  const POISON = {
    bf_user: JSON.stringify({ business_name: "POISON-USER-BIZ", website: "poison-user.example", industry: "POISON-INDUSTRY" }),
    bf_executive_memory: JSON.stringify(poisonMemory("EXEC")),
    bf_executive_agent_memory: JSON.stringify(poisonMemory("AGENTMEM"))
  };
  const PROFILE = { business_name: "Acme Server Co", industry: "Bakeries", website: "acme.example", location: "Leeds", top_competitors: "Rival Ltd" };
  const STORE_KEYS = ["bf_executive_memory", "bf_executive_agent_memory", "bf_user"];
  for (const page of AGENT_PAGES) {
    const agentType = (/agentType:\s*"([a-z_]+)"/.exec(FILES[page]) || [])[1];
    const newest = { id: id("7aaaaaaa", AGENT_PAGES.indexOf(page)), user_id: OWNER, agent_type: agentType, task_type: "general", status: "completed",
      prompt: "p", result: "r", output: null, created_at: "2026-10-0" + (1 + (AGENT_PAGES.indexOf(page) % 9)) + "T08:00:00.000Z" };
    const pageSrv = server({ ai_tasks: [newest] });
    const scripts = pageScripts(page);
    const served = [];
    const serve = async (url) => {
      const u = new URL(url); served.push(u.pathname + u.search);
      if (u.pathname === "/api/business-profile") return { code: 200, body: { ok: true, profile: PROFILE } };
      if (u.pathname === "/api/ai/tasks") return pageSrv.call("get /api/ai/tasks", OWNER, {}, Object.fromEntries(u.searchParams));
      if (u.pathname === "/api/agents/" + agentType) return { code: 404, body: { error: "Agent not found" } };
      return null;
    };
    const ids = ["businessContextGrid", "lastRunText", "liveAgentStats", "refreshBtn", "statsGrid"];
    const p = await runPage({ page, serve, storage: POISON, scripts, realIds: ids });
    // And again through the page's own Refresh button.
    (p.els.refreshBtn && p.els.refreshBtn.listeners.click || []).forEach(f => f({}));
    await settle();
    const everything = Object.keys(p.els).map(k => p.shown(k)).join(" ");
    const readKeys = p.getItemCalls.filter(k => STORE_KEYS.indexOf(k) !== -1);
    const lastRun = p.els.lastRunText;
    const expectLastRun = FILES[page].indexOf('id="lastRunText"') !== -1;
    check(page + ": on load and on Refresh, reads none of the store keys, shows none of their values, and draws the server's profile",
      p.errors.length === 0 && readKeys.length === 0 && !/POISON|999 invented|INVENTED/.test(everything) &&
      ["Acme Server Co", "Bakeries", "acme.example", "Leeds", "Rival Ltd"].every(v => p.shown("businessContextGrid").indexOf(v) !== -1),
      (p.errors.join(" | ") || "") + " read=" + readKeys.join(",") + " grid=" + p.shown("businessContextGrid").slice(0, 160));
    check(page + ": \"Last run\" is the newest ai_tasks row (GET /api/ai/tasks?agent_type=" + agentType + "&limit=1), linked to it" + (expectLastRun ? "" : " — n/a, no Last run on this page"),
      !expectLastRun || (served.indexOf("/api/ai/tasks?agent_type=" + agentType + "&limit=1") !== -1 &&
        lastRun.innerHTML.indexOf('href="/run.html?id=' + newest.id + '"') !== -1 && text(lastRun.innerHTML).indexOf(new Date(newest.created_at).toLocaleString()) !== -1),
      served.join(", ") + " | " + (lastRun && lastRun.innerHTML));
    check(page + ": no stats grid, and no Agent Stats from anything but the server",
      FILES[page].indexOf('id="statsGrid"') === -1 && !p.els.statsGrid);
  }
  // The same page with no run, no profile, and a failed profile read.
  {
    const page = "email-agent.html";
    const emptySrv = server({});
    const p = await runPage({ page, storage: POISON, scripts: pageScripts(page), realIds: ["businessContextGrid", "lastRunText", "liveAgentStats", "refreshBtn"],
      serve: async (url) => { const u = new URL(url);
        if (u.pathname === "/api/business-profile") return { code: 200, body: { ok: true, profile: null } };
        if (u.pathname === "/api/ai/tasks") return emptySrv.call("get /api/ai/tasks", OWNER, {}, Object.fromEntries(u.searchParams));
        return null; } });
    check("no run yet: the \"Last run\" line is removed, not filled with a guess", p.toolbarMeta.detached === true &&
      p.els.lastRunText.innerHTML === "", p.els.lastRunText.innerHTML);
    check("no profile saved: it says so, and shows nothing from the store", p.shown("businessContextGrid").indexOf("No business profile is saved yet.") !== -1 &&
      !/POISON/.test(p.shown("businessContextGrid")));
    const f = await runPage({ page, storage: POISON, scripts: pageScripts(page), realIds: ["businessContextGrid", "lastRunText", "liveAgentStats", "refreshBtn"],
      serve: async (url) => { const u = new URL(url);
        if (u.pathname === "/api/business-profile") return { code: 500, body: { ok: false, error: "Failed to fetch business profile" } };
        if (u.pathname === "/api/ai/tasks") return { code: 500, body: { error: "Internal server error" } };
        return null; } });
    check("a failed profile read says so, and shows nothing in the profile's place",
      text(f.shown("businessContextGrid")).indexOf("Your business profile could not be loaded from the server (HTTP 500), so none of it is shown.") !== -1 &&
      !/POISON|Loading/.test(f.shown("businessContextGrid")), text(f.shown("businessContextGrid")));
    check("a failed \"Last run\" read says so", text(f.els.lastRunText.innerHTML).indexOf("could not be read (HTTP 500)") !== -1, f.els.lastRunText.innerHTML);
  }
  // In code (comments stripped), no agent page and no shared script names a store key.
  const codeOf = (f) => (f.endsWith(".js") ? [FILES[f]] : inlineScripts(FILES[f])).join("\n").replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
  const named = AGENT_PAGES.concat([AP, "agents/content.html"]).filter(f => /bf_executive_memory|bf_executive_agent_memory|"bf_user"|getAgentStore|loadExecutiveMemory|AGENT_KEY|store\.stats|statsSimNote/.test(codeOf(f)));
  check("no agent page, agents/content.html or agent-profile.js names a store key or reader in code", named.length === 0, named.join(", "));

  /* ── 5. the field map, and parsing ────────────────────────────────────── */
  console.log("\n══ 5. the stored-run field map, and every script parses ══");
  const declared = {};
  AGENT_PAGES.concat(["agents/content.html"]).forEach(page => {
    inlineScripts(FILES[page]).filter(c => /AGENT_PROFILE_CONFIG\s*=/.test(c)).forEach(c => {
      const ctx = { window: {} }; vm.runInNewContext(c, ctx);
      const cfg = ctx.window.AGENT_PROFILE_CONFIG;
      (cfg.tools || []).forEach(t => { declared[cfg.agentType + "/" + t.id] = (t.fields || []).map(f => f.name); });
    });
  });
  const mapSrc = /var STORED_TOOL_FIELDS = (\{[\s\S]*?\n  \});/.exec(FILES[AP]);
  const map = mapSrc ? vm.runInNewContext("(" + mapSrc[1] + ")") : null;
  const canon = (o) => JSON.stringify(Object.keys(o || {}).sort().map(k => [k, o[k]]));
  check("agent-profile.js's STORED_TOOL_FIELDS equals every page's declared tool fields (" + Object.keys(declared).length + " tools)",
    map && Object.keys(declared).length >= 31 && canon(map) === canon(declared), map ? Object.keys(declared).filter(k => JSON.stringify(map[k]) !== JSON.stringify(declared[k])).join(", ") : "map not found");
  const bad = [];
  [RUN, DASH].concat(AGENT_PAGES).forEach(f => inlineScripts(FILES[f]).forEach((code, i) => { try { new vm.Script(code); } catch (e) { bad.push(f + "#" + i + ": " + e.message); } }));
  try { new vm.Script(FILES[AP]); } catch (e) { bad.push(AP + ": " + e.message); }
  check("every inline script in run.html, dashboard.html and the " + AGENT_PAGES.length + " agent pages parses, and agent-profile.js", bad.length === 0, bad.join(" | "));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });

function PANEL_TEXT(p) { return ["ccNeedsYou", "ccPlans", "ccActivity", "ccAutopilot", "ccOutbound", "ccSpend"].map(i => p.shown(i)).join(" "); }

// A store as the dashboard's removed simulations left it, under every agent key.
function poisonMemory(tag) {
  const agent = { stats: { runs: "999 invented", confidence: "HIGH-INVENTED", lastRun: "POISON-LAST-RUN-" + tag },
    lastRun: "POISON-LAST-RUN-" + tag,
    businessContext: { businessName: "POISON-BIZ-" + tag, industry: "POISON-IND", competitors: "POISON-COMP", shopGoals: "POISON-GOALS", researchGoals: "POISON-RG" } };
  const out = {};
  ["adsAgent", "analyticsAgent", "salesAgent", "seoAgent", "socialAgent", "brokerAgent", "communityAgent", "emailAgent", "etsyAgent", "executiveAgent",
    "influencerAgent", "operationsAgent", "publicistAgent", "rdAgent", "reputationAgent", "storeAgent", "verticalMarketingAgent", "vertical_marketingAgent"]
    .forEach(k => { out[k] = JSON.parse(JSON.stringify(agent)); });
  return out;
}

// A page's scripts in page order: its inline scripts, then agent-profile.js where the page loads it.
function pageScripts(page) {
  const html = FILES[page];
  const out = []; const re = /<script(\s[^>]*)?>([\s\S]*?)<\/script>/g; let m;
  while ((m = re.exec(html))) {
    if (m[1] && /\bsrc=/.test(m[1])) { if (/agent-profile\.js/.test(m[1])) out.push(FILES[AP]); }
    else out.push(m[2]);
  }
  return out;
}
