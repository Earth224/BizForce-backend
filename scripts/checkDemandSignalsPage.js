"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkDemandSignalsPage — the demand page is honest.

   Frontend "Demand signals on the R&D page" added the rd/demand-signals tool
   to rd-agent.html as an owner-only tool (adminOnly), drawn by
   scripts/agent-profile.js only after /api/auth/me says admin, with its own
   renderer. This runs agent-profile.js in vm with a stubbed DOM and fetch, and
   feeds it FIXTURES MADE BY THIS REPO'S REAL ROUTE: POST
   /api/agents/rd/demand-signals, lifted from server.js and run against a fake
   database whose rows carry post text, handles and post addresses, with the
   model stubbed. No browser, no network, no model; nothing is written.

   WHAT THIS PROVES
     A. The form only for an admin; nothing at all for anyone else; an error
        line, never the form, when /api/auth/me cannot be read. The other R&D
        tools are drawn as before.
     B. Themes first, each with its keyword chips and "supported by N of M
        sampled posts"; a "<5" from the server is "fewer than 5", never a
        number; undated posts are stated as counted but not dated.
     C. themes null: the amber panel with explanation_error verbatim, saying
        the counts below are complete without it. Drops shown in plain words.
     D. not_measured always visible; provenance in the dashed style.
     E. No post text, handle or post address appears — from the real route, or
        from a response that carries them in unexpected places.
     F. A failed request shows the server's message and no result; a 200 with
        no measured counts is "could not be read", never an empty report.

   MUTATE=<name> edits agent-profile.js IN MEMORY. MUTATE=all runs each in its
   own process and passes only if every one fails. A mutation whose search text
   does not match exactly once is an ERROR, never counted as caught.

   BIZFORCE_FRONTEND_DIR overrides the frontend location (default: the
   BizForce-fronyend checkout beside this repo).
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), vm = require("vm"), path = require("path"), net = require("net"), dns = require("dns");
const s = require("./_shared");

const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkDemandSignalsPage: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkDemandSignalsPage: no network"); };

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const PROFILE = "scripts/agent-profile.js", RD = "rd-agent.html";

const MUTATIONS = {
  // the owner-only tool is drawn for everyone
  "form-for-non-admins": [["slot.innerHTML = admin ? toolMarkup(tool) : \"\";", "slot.innerHTML = toolMarkup(tool);"]],
  // a suppressed count is printed as its threshold
  "small-count-as-number": [["    if (m) return \"fewer than \" + m[1];\n", "    if (m) return m[1];\n"]],
  // what the report cannot say is hidden
  "hide-not-measured": [["      demandNotMeasured(data.not_measured),\n", ""]],
  // a response without counts renders as an empty report
  "empty-result-on-failure": [["    var m = data && data.measured;\n    if (!isPlainObject(m)) {\n", "    var m = data && data.measured;\n    if (!isPlainObject(m)) { return \"\"; }\n    if (false) {\n"]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

const FILES = {};
[PROFILE, RD].forEach(f => { FILES[f] = fs.readFileSync(path.join(FRONTEND, f), "utf8").replace(/\r\n/g, "\n"); });
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [from, to] of edits) FILES[PROFILE] = s.replaceOnce(FILES[PROFILE], from, to, MUTATE);
  console.log("\n!! MUTATION: " + MUTATE + " (agent-profile.js, in memory)");
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}
const flush = async () => { for (let i = 0; i < 30; i++) await new Promise(r => setImmediate(r)); };
const escH = (t) => String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/* ── the backend's real route, lifted ───────────────────────────────────── */
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
const routeStart = SRC.indexOf("app.post(\"" + ROUTE + "\",");
const routeEnd = s.braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("async function (req, res, next)", routeStart)));
const LIFTED = closure(SRC.slice(routeStart, routeEnd + 2) + "\n\nthis.api = { publicUser: publicUser };");

function fakeDb(rows) {
  const copy = v => JSON.parse(JSON.stringify(v));
  function keep(q, r) {
    return q.filters.every(f => {
      const [op, col, a, b] = f;
      if (op === "in") return a.indexOf(r[col]) !== -1;
      if (op === "is") return r[col] == null;
      if (op === "not" && a === "is" && b === null) return r[col] != null;
      if (op === "gte") return r[col] != null && r[col] >= a;
      if (op === "lt") return r[col] != null && r[col] < a;
      return true;
    });
  }
  function from() {
    const q = { cols: null, head: false, filters: [] };
    const b = { select(cols, opts) { q.cols = cols; q.head = !!(opts && opts.head); return b; } };
    ["in", "is", "not", "gte", "lt", "order", "range", "limit", "eq"].forEach(op => { b[op] = function () { q.filters.push([op].concat([].slice.call(arguments))); return b; }; });
    b.then = (res, rej) => {
      let hits = rows.filter(r => keep(q, r));
      if (q.head) return Promise.resolve({ data: null, count: hits.length, error: null }).then(res, rej);
      const range = q.filters.find(f => f[0] === "range");
      if (range) hits = hits.slice(range[1], range[2] + 1);
      const cols = String(q.cols).split(",").map(c => c.trim());
      return Promise.resolve({ data: hits.map(r => { const o = {}; cols.forEach(c => { o[c] = r[c] === undefined ? null : r[c]; }); return o; }), error: null }).then(res, rej);
    };
    return b;
  }
  return { from };
}

const DAY = 24 * 3600 * 1000;
const ago = (d) => new Date(Date.now() - d * DAY).toISOString();
let n = 0;
const SECRET_HANDLE = "secret-person.bsky.social";
const SECRET_URI = "at://did:plc:secretperson/app.bsky.feed.post/3kxyz";
const SECRET_TEXT = "my private struggle with this method has lasted eleven long months now";
const row = (kw, extra) => Object.assign({ id: "r" + String(++n).padStart(4, "0"), matched_keyword: kw, source: "bluesky", post_created_at: ago(10),
  status: "scored", intent_score: 72, intent_reason: "asks a question", post_text: SECRET_TEXT + " " + n + " @" + SECRET_HANDLE,
  author_handle: SECRET_HANDLE, author_did: "did:plc:secretperson", post_uri: SECRET_URI + n, post_id: "pid" + n, post_cid: "cid" + n,
  outreach_safe: true, suggested_product: "Tongkat Ali" }, extra || {});
function rows() {
  n = 0;
  const out = [];
  for (let i = 0; i < 12; i++) out.push(row("how to manifest"));
  for (let i = 0; i < 3; i++) out.push(row("law of assumption", { intent_score: 15 }));
  for (let i = 0; i < 2; i++) out.push(row("how to manifest", { post_created_at: ago(300) }));
  for (let i = 0; i < 6; i++) out.push(row("how to manifest", { post_created_at: null }));
  return out;
}
const THEMES_REPLY = [
  "THEME: Doubt after trying | WANT: People want to know why methods fail for them and what to change. | KEYWORDS: how to manifest; law of assumption | SUPPORT: 7",
  "THEME: Off topic | WANT: Something else entirely. | KEYWORDS: low libido | SUPPORT: 3",
  "THEME: Quoted | WANT: Some wrote that my private struggle with this method has lasted. | KEYWORDS: how to manifest | SUPPORT: 2"
].join("\n");

async function realResponse(opts) {
  opts = opts || {};
  const ctx = {
    supabase: fakeDb(rows()), JSON, Math, Promise, Number, Object, Array, String, Date,
    nowIso: () => new Date().toISOString(), process: { env: {} }, console: { log() {}, error() {}, warn() {} },
    requireAuth: function requireAuth() {}, requireActiveSubscription: function requireActiveSubscription() {}, aiLimiter: function aiLimiter() {},
    startToolRun: async () => ({ taskId: "task-page", complete: async () => true, fail: async () => {} }),
    resolvePreferredLanguage: async () => null,
    callAnthropicText: async () => { if (opts.modelThrows) throw new Error("model unavailable"); return { text: opts.reply || THEMES_REPLY }; }
  };
  let handler = null;
  ctx.app = { post(p) { if (p === ROUTE) handler = arguments[arguments.length - 1]; } };
  vm.createContext(ctx);
  vm.runInContext(LIFTED, ctx);
  const res = { code: 200, body: null, status(x) { this.code = x; return this; }, json(x) { this.body = JSON.parse(JSON.stringify(x)); return this; } };
  await handler({ user: { id: "owner", role: opts.role || "admin" }, body: opts.body || { theme: "manifestation" } }, res, () => { res.code = 500; });
  return { status: res.code, body: res.body, publicUser: ctx.api.publicUser };
}

/* ── the page ───────────────────────────────────────────────────────────── */
function fakeEl(id) {
  return { id, innerHTML: "", textContent: "", className: "", value: "", disabled: false, hidden: true, children: [], style: {},
    appendChild(c) { this.children.push(c); return c; }, addEventListener() {}, setAttribute() {}, getAttribute() { return null; },
    querySelector() { return null; }, querySelectorAll() { return []; } };
}
function rdConfig() {
  const m = FILES[RD].match(/<script>\s*(window\.AGENT_PROFILE_CONFIG\s*=[\s\S]*?)<\/script>/);
  const w = {}; vm.runInNewContext(m[1], { window: w });
  return w.AGENT_PROFILE_CONFIG;
}
function loadPage(handlers) {
  const els = new Map(), posted = [];
  const document = { head: { appendChild() {} }, createElement() { return fakeEl(null); }, addEventListener() {},
    getElementById(id) { if (!els.has(id)) els.set(id, fakeEl(id)); return els.get(id); }, querySelector() { return fakeEl(null); }, querySelectorAll() { return []; } };
  const window = { AGENT_PROFILE_CONFIG: rdConfig() };
  const fetchStub = (url, init) => {
    const method = (init && init.method) || "GET";
    const p = url.replace(/^https?:\/\/[^/]+/, "");
    const body = init && init.body ? JSON.parse(init.body) : undefined;
    posted.push({ method, path: p, body });
    const h = handlers(method, p, body);
    if (h === "reject") return Promise.reject(new TypeError("Failed to fetch"));
    return Promise.resolve(h).then(r => ({ ok: r.status >= 200 && r.status < 300, status: r.status,
      json: () => r.body === undefined ? Promise.reject(new SyntaxError("Unexpected end")) : Promise.resolve(JSON.parse(JSON.stringify(r.body))) }));
  };
  const ctx = { window, document, console, localStorage: { getItem() { return "check-token"; }, setItem() {} }, fetch: fetchStub,
    setTimeout() { return 0; }, clearTimeout() {}, setInterval() { return 0; }, clearInterval() {} };
  const tail = '  document.addEventListener("DOMContentLoaded", inject);\n})();';
  const src = FILES[PROFILE];
  if (src.indexOf(tail) < 0) throw new Error("agent-profile.js does not end where expected");
  vm.createContext(ctx);
  vm.runInContext(src.slice(0, src.lastIndexOf(tail)) +
    "  window.__ap = { renderToolResult: renderToolResult, toolsMarkup: toolsMarkup, runTool: runTool, TOOLS: TOOLS, toolDomId: toolDomId, drawAdminTools: drawAdminTools };\n" + tail, ctx);
  return { ap: window.__ap, els, document, posted };
}
const meAs = (role, publicUser) => () => ({ status: 200, body: { user: publicUser({ id: "u", role: role, email: "o@example.com" }) } });

(async function main() {
  const real = await realResponse();
  const pu = real.publicUser;

  /* ── A. who sees the form ─────────────────────────────────────────────── */
  console.log("\n══ A. the form, only for the owner ══");
  const cfg = rdConfig();
  const tool = cfg.tools.find(t => t.id === "demand-signals");
  check("rd-agent.html has the demand-signals tool, owner-only", tool && tool.adminOnly === true);
  const themeField = tool && tool.fields.find(f => f.name === "theme");
  check("theme is a select of the seven themes", themeField && themeField.type === "select" &&
    JSON.stringify(themeField.options.map(o => o.value)) === JSON.stringify(["manifestation", "quantum_jumping", "supplements", "libido", "energy", "bizforce", "all"]));
  const wd = tool && tool.fields.find(f => f.name === "window_days"), ss = tool && tool.fields.find(f => f.name === "sample_size");
  check("window_days 7-365 and sample_size 10-80, both numbers", wd && wd.type === "number" && wd.min === 7 && wd.max === 365 && ss && ss.type === "number" && ss.min === 10 && ss.max === 80);
  async function gate(meHandler) {
    const pg = loadPage((m, p) => p === "/api/auth/me" ? meHandler() : { status: 404, body: { error: "unplanned" } });
    const markup = pg.ap.toolsMarkup();
    await pg.ap.drawAdminTools();
    return { markup, slot: pg.els.get(pg.ap.toolDomId("demand-signals", "gate")).innerHTML };
  }
  const asAdmin = await gate(meAs("admin", pu));
  check("before /api/auth/me answers, the page has an empty slot and no demand-signals button",
    asAdmin.markup.indexOf('data-tool-run="demand-signals"') === -1 && asAdmin.markup.indexOf('id="apTool_demand_signals_gate"') !== -1);
  check("the other R&D tools are drawn as before", asAdmin.markup.indexOf('data-tool-run="brief"') !== -1 && asAdmin.markup.indexOf('data-tool-run="competitor-scan"') !== -1);
  check("admin: the form is drawn, with its run button and three fields",
    asAdmin.slot.indexOf('data-tool-run="demand-signals"') !== -1 && ["theme", "window_days", "sample_size"].every(f => asAdmin.slot.indexOf("apTool_demand_signals_f_" + f) !== -1), asAdmin.slot.slice(0, 200));
  const asUser = await gate(meAs("user", pu));
  check("non-admin: nothing at all is drawn", asUser.slot === "", asUser.slot);
  const asBroken = await gate(() => ({ status: 500, body: { error: "auth lookup failed" } }));
  check("/api/auth/me failing: an error line, never the form",
    asBroken.slot.indexOf("data-tool-run") === -1 && /could not be checked/.test(asBroken.slot) && /auth lookup failed/.test(asBroken.slot), asBroken.slot);
  const asOffline = await gate(() => "reject");
  check("/api/auth/me unreachable: an error line too", asOffline.slot.indexOf("data-tool-run") === -1 && /could not be checked/.test(asOffline.slot), asOffline.slot);

  /* ── B. themes and measured ───────────────────────────────────────────── */
  console.log("\n══ B. the report ══");
  check("fixture: the real route answered 200 with themes, a dropped theme and a privacy drop",
    real.status === 200 && Array.isArray(real.body.themes) && real.body.themes.length === 1 && real.body.points_dropped === 1 && real.body.privacy_drops === 1,
    JSON.stringify(real.body && [real.body.themes, real.body.points_dropped, real.body.privacy_drops]));
  const page = loadPage(() => ({ status: 404, body: {} }));
  const render = (body) => page.ap.renderToolResult(tool, body);
  const h = render(real.body);
  const themesAt = h.indexOf("Doubt after trying"), measuredAt = h.indexOf("Measured by the server");
  check("themes come first, before the measured counts", themesAt !== -1 && measuredAt !== -1 && themesAt < measuredAt);
  check("each theme: what people want, its keyword chips", h.indexOf("People want to know why methods fail") !== -1 &&
    h.indexOf('<span class="ap-ds-chip">how to manifest</span>') !== -1 && h.indexOf('<span class="ap-ds-chip">law of assumption</span>') !== -1);
  const sampled = real.body.measured.sample.posts;
  check("'supported by 7 of " + sampled + " sampled posts'", h.indexOf("supported by 7 of " + sampled + " sampled posts") !== -1, sampled);
  check("dated before the window (2, so <5 from the server) reads 'fewer than 5'", real.body.measured.dated_before_window === "<5" &&
    /Dated before the window<\/div><div class="ap-m-val">fewer than 5</.test(h));
  check("no '<5', '&lt;5' or a bare 5 standing for it anywhere", h.indexOf("&lt;5") === -1 && h.indexOf("<5") === -1 && !/class="ap-m-val">5</.test(h) && !/class="ap-ds-n">5</.test(h));
  check("by keyword: law of assumption reads 'fewer than 5'", /law of assumption<\/td><td class="ap-ds-n">fewer than 5</.test(h));
  check("undated posts: the count, and that they are counted but not dated",
    /Undated posts<\/div><div class="ap-m-val">6</.test(h) && h.indexOf("Undated posts are counted, but never given a date") !== -1);
  check("by source, by month and the score buckets are shown", h.indexOf("By source") !== -1 && h.indexOf("By month the post was written") !== -1 && h.indexOf("Real scores") !== -1 && h.indexOf("70-79") !== -1);

  /* ── C. themes null, and drops ────────────────────────────────────────── */
  console.log("\n══ C. no themes, and drops ══");
  check("drops in plain words: 1 dropped, 1 removed for repeating a post",
    h.indexOf("1 theme was dropped for citing no keyword in scope") !== -1 && h.indexOf("1 theme was removed because it repeated a sampled post word for word") !== -1);
  const failed = await realResponse({ modelThrows: true });
  check("fixture: a model failure is 200 with themes null and explanation_error", failed.status === 200 && failed.body.themes === null && /could not be generated/.test(failed.body.explanation_error));
  const hf = render(failed.body);
  check("themes null: the amber panel with explanation_error verbatim",
    hf.indexOf('<div class="ap-nothing-read ap-ds-nothemes">') !== -1 && hf.indexOf(escH(failed.body.explanation_error)) !== -1, hf.slice(0, 300));
  check("…saying the measured counts below are complete without them, and still showing them",
    hf.indexOf("The measured counts below are complete without them.") !== -1 && hf.indexOf("Measured by the server") !== -1 && /Posts in the window<\/div><div class="ap-m-val">15</.test(hf));
  check("no drop line when there were no drops", hf.indexOf("ap-ds-drop") === -1);

  /* ── D. not measured, provenance ──────────────────────────────────────── */
  console.log("\n══ D. what is not measured ══");
  check("not_measured: all four, always visible, never collapsed",
    real.body.not_measured.every(x => h.indexOf(escH(x)) !== -1) && h.indexOf("Not measured by this report") !== -1 && h.indexOf("<details") === -1);
  check("not_measured shown on the failure report too", failed.body.not_measured.every(x => hf.indexOf(escH(x)) !== -1));
  check("provenance in the dashed style", h.indexOf('class="ap-prov"') !== -1);

  /* ── E. no person ─────────────────────────────────────────────────────── */
  console.log("\n══ E. no post, handle or address ══");
  const leaks = (html) => [SECRET_HANDLE, "secret-person", "secretperson", SECRET_URI, "my private struggle", "asks a question", "Tongkat Ali"].filter(x => html.indexOf(x) !== -1);
  check("the real route's report shows none of the fixture's post text, handles or addresses", leaks(h).length === 0, leaks(h).join(", "));
  const hostile = JSON.parse(JSON.stringify(real.body));
  hostile.post_text = SECRET_TEXT; hostile.author_handle = SECRET_HANDLE; hostile.post_uri = SECRET_URI;
  hostile.measured.post_text = SECRET_TEXT; hostile.measured.sample.author_handle = SECRET_HANDLE;
  hostile.measured.by_keyword.push({ keyword: "how to manifest", rows: 1, post_uri: SECRET_URI, author_handle: SECRET_HANDLE });
  hostile.themes[0].post_text = SECRET_TEXT; hostile.themes[0].author_handle = SECRET_HANDLE;
  const hh = render(hostile);
  check("a response carrying them in unexpected places still shows none of them", leaks(hh).length === 0, leaks(hh).join(", "));

  /* ── F. failures ──────────────────────────────────────────────────────── */
  console.log("\n══ F. a failed request ══");
  async function run(handler) {
    const pg = loadPage(handler);
    const t = pg.ap.TOOLS.find(x => x.id === "demand-signals");
    pg.document.getElementById(pg.ap.toolDomId("demand-signals", "f_theme")).value = "manifestation";
    pg.ap.runTool(t);
    await flush();
    return { msg: pg.els.get(pg.ap.toolDomId("demand-signals", "msg")), result: pg.els.get(pg.ap.toolDomId("demand-signals", "result")).innerHTML, posted: pg.posted };
  }
  const refused = await realResponse({ role: "user" });
  const r403 = await run((m, p) => p === ROUTE ? refused : { status: 404, body: {} });
  check("a 403 shows the server's message and no result", refused.status === 403 && r403.msg.textContent === refused.body.error && r403.result === "", r403.msg.textContent);
  const r500 = await run((m, p) => p === ROUTE ? { status: 500, body: { error: "database unavailable" } } : { status: 404, body: {} });
  check("a 500 shows the server's message and no result — never an empty report", r500.msg.textContent === "database unavailable" && r500.result === "" && /err/.test(r500.msg.className));
  const r200 = await run((m, p) => p === ROUTE ? { status: 200, body: { success: true, themes: [] } } : { status: 404, body: {} });
  check("a 200 without measured counts: 'could not be read', not an empty report or 'no themes'",
    /could not be read/.test(r200.result) && r200.result.indexOf("Measured by the server") === -1 && r200.result.indexOf("No themes") === -1, r200.result.slice(0, 200));
  const rok = await run((m, p) => p === ROUTE ? { status: 200, body: real.body } : { status: 404, body: {} });
  const sent = rok.posted.find(x => x.path === ROUTE);
  check("the form posts the theme to the route, leaving unset numbers to the server's defaults", sent && JSON.stringify(sent.body) === JSON.stringify({ theme: "manifestation" }), sent && JSON.stringify(sent.body));
  check("and a success renders the report", rok.result.indexOf("Doubt after trying") !== -1);

  check("zero network", NETWORK.length === 0, JSON.stringify(NETWORK));
  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.error("\nThe check threw: " + (e && e.stack || e)); process.exit(1); });
