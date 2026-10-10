"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkEmailSequencesPage — the sequences page is honest.

   Frontend ee5a3e3 "Email sequences on the page" added
   scripts/email-sequences.js (the filing form under a sequence result, and the
   sequences panel on email-agent.html), a hook in agent-profile.js that hands
   each tool result to it, and send_email_sequence cards on proposals.html.
   This runs those files in vm with a stubbed DOM and a stubbed fetch, and feeds
   them FIXTURES MADE BY THIS REPO'S REAL ROUTES: GET /api/email/sequences,
   GET /api/email/sequences/:id, POST /api/email/sequences/:id/status,
   POST /api/agents/email/propose-sequence and the send_email_sequence
   executor, lifted from server.js and run against a fake database. No browser,
   no network, no model, no email; nothing is written to either repo.

   WHAT THIS PROVES
     0. The real shapes: /api/auth/me reports role through publicUser; the
        hook in agent-profile.js hands a sequence result to the page.
     A. Filing: the form only for an admin; the one quiet line otherwise; an
        unreadable /api/auth/me is neither. A success shows the measured count
        and the server's note verbatim with a link to the proposals page; an
        error shows the server's message unchanged; a blank name posts nothing.
     B. The sender: each reason on its own line, none when all is set, and no
        environment value ever.
     C. The list: "No sequences yet" only for a real empty array; a 500, a
        network failure, an unparseable body and a 200 without a sequences
        array are each an error panel.
     D. The moves: each button only where the real route allows the move;
        Pause posts at once; Cancel posts nothing until confirmed; a 409 shows
        the server's message.
     E. The detail: steps and each contact's position, status and reason;
        step text escaped.
     F. proposals.html: a send_email_sequence proposal's name, brand, step
        count and each step's day and subject, escaped; after approval the
        four counts with plain labels, skipped_unreadable included.
     And zero Resend calls.

   MUTATE=<name> edits the frontend files IN MEMORY (nothing on disk is
   touched). MUTATE=all runs each in its own process and passes only if every
   one fails. A mutation whose search text does not match exactly once is an
   ERROR, never counted as caught.

   BIZFORCE_FRONTEND_DIR overrides the frontend location (default: the
   BizForce-fronyend checkout beside this repo).
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), vm = require("vm"), path = require("path");
const { spawnSync } = require("child_process");
const s = require("./_shared");
const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const ANCHOR_ERROR_EXIT = 3;

const SEQ_JS = "scripts/email-sequences.js", PROPOSALS = "proposals.html", PROFILE = "scripts/agent-profile.js";
const MUTATIONS = {
  // a failed load says "No sequences yet"
  "empty-on-failed-load": [[SEQ_JS, "list.innerHTML = loadFailMarkup(\"Your sequences\", res.ok ? \"the answer could not be read\" : serverMessage(res));",
    "list.innerHTML = listMarkup([]);"]],
  // the filing form is shown to everyone
  "form-for-non-admins": [[SEQ_JS, "slot.innerHTML = admin ? filingFormMarkup(data.task_id) : notOwnerMarkup();", "slot.innerHTML = filingFormMarkup(data.task_id);"]],
  // Cancel posts on the first tap
  "drop-cancel-confirmation": [[SEQ_JS, "if (to === \"cancelled\") { askCancel(actions, id); return; }\n", ""]],
  // step text rendered as HTML
  "unescaped-step-text": [[SEQ_JS, "'<span class=\"es-subject\">' + esc(s.subject) + '</span>'", "'<span class=\"es-subject\">' + s.subject + '</span>'"],
    [PROPOSALS, "return '<li>' + escapeHtml(dayText) + ': ' + escapeHtml(s && s.subject) + '</li>';", "return '<li>' + escapeHtml(dayText) + ': ' + (s && s.subject) + '</li>';"]],
  // skipped_unreadable is not shown after approval
  "hide-skipped-unreadable": [[PROPOSALS, "  [\"skipped_not_confirmed\", \"Skipped — consent not confirmed\"],\n  [\"skipped_unreadable\", \"Skipped — consent could not be read\"]\n",
    "  [\"skipped_not_confirmed\", \"Skipped — consent not confirmed\"]\n"]]
};

if (MUTATE === "all") {
  const names = Object.keys(MUTATIONS);
  let survived = 0, errors = 0;
  for (const name of names) {
    const r = spawnSync(process.execPath, [__filename], { env: Object.assign({}, process.env, { MUTATE: name }), encoding: "utf8", timeout: 300000 });
    if (r.status === ANCHOR_ERROR_EXIT) {
      errors++;
      console.log("    ERROR     " + name.padEnd(26) + " " + (r.stdout.trim().split("\n").pop() || r.stderr.trim()));
      continue;
    }
    const fails = (r.stdout.match(/^ {4}FAIL {2}.*$/gm) || []);
    const caught = r.status !== 0 && fails.length > 0;
    if (!caught) survived++;
    console.log((caught ? "    caught    " : "    SURVIVED  ") + name.padEnd(26) + " " + fails.length + " failing check(s)" +
      (fails.length ? "  e.g. " + fails[0].trim().slice(6, 110) : (r.stderr ? "  stderr: " + r.stderr.trim().split("\n")[0] : "")));
  }
  const ok = survived === 0 && errors === 0;
  console.log(ok ? "\nALL CHECKS PASSED — every one of " + names.length + " mutations was caught"
    : "\nCHECKS FAILED: " + survived + " mutation(s) survived, " + errors + " mutation(s) could not be applied");
  process.exit(ok ? 0 : 1);
}

/* ── the frontend files, mutated in memory ──────────────────────────────── */
const FILES = {};
[SEQ_JS, PROPOSALS, PROFILE, "email-agent.html"].forEach(f => { FILES[f] = fs.readFileSync(path.join(FRONTEND, f), "utf8").replace(/\r\n/g, "\n"); });
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) {
    const hits = FILES[file].split(from).length - 1;
    if (hits !== 1) { console.log("MUTATION ANCHOR ERROR: expected exactly one match in " + file + ", found " + hits + ": " + JSON.stringify(from.slice(0, 80))); process.exit(ANCHOR_ERROR_EXIT); }
    FILES[file] = FILES[file].replace(from, () => to);
  }
  console.log("\n!! MUTATION: " + MUTATE + " (frontend, in memory)");
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}
const count = (h, needle) => String(h).split(needle).length - 1;
const flush = async () => { for (let i = 0; i < 30; i++) await new Promise(r => setImmediate(r)); };

/* ── the backend's real routes, lifted ──────────────────────────────────── */
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
const STUBS = new Set(["supabase", "nowIso", "console", "process", "require", "module", "Resend", "app", "Buffer", "setTimeout",
  "requireAuth", "requireActiveSubscription", "requireAdmin", "aiLimiter", "crypto", "Date", "cron"]);
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
  if (start < 0) throw new Error(method.toUpperCase() + " " + route + " not found");
  const end = s.braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("function (req, res, next)", start)));
  if (SRC.slice(end, end + 2) !== ");") throw new Error(method.toUpperCase() + " " + route + " did not end where expected");
  return SRC.slice(start, end + 2);
}
const ROUTES = [["get", "/api/email/sequences"], ["get", "/api/email/sequences/:id"], ["post", "/api/email/sequences/:id/status"],
  ["post", "/api/agents/email/propose-sequence"]];
const LIFTED = closure(ROUTES.map(([m, r]) => routeText(m, r)).join("\n\n") +
  "\n\nthis.api = { execute: executeSendEmailSequence, publicUser: publicUser };");

const TABLES = ["email_sequences", "email_sequence_enrollments", "contacts", "consent_events", "ai_tasks", "agent_proposals", "users"];
function fakeDb(seed, fail) {
  const tables = {};
  TABLES.forEach(t => { tables[t] = ((seed || {})[t] || []).map(r => JSON.parse(JSON.stringify(r))); });
  let n = 0;
  function keep(q, row) {
    return q.filters.every(f => {
      if (f[0] === "eq") return row[f[1]] === f[2];
      if (f[0] === "in") return f[2].indexOf(row[f[1]]) !== -1;
      return true;
    });
  }
  function shape(q, row) {
    const copy = JSON.parse(JSON.stringify(row));
    if (q.table === "email_sequence_enrollments" && /contacts\(name, email\)/.test(q.cols || "")) {
      const c = tables.contacts.find(x => x.id === row.contact_id);
      copy.contacts = c ? { name: c.name, email: c.email } : null;
    }
    return copy;
  }
  function answer(q) {
    const injected = fail && fail(q);
    if (injected) return Promise.resolve({ data: null, error: injected });
    const rows = tables[q.table];
    if (!rows) return Promise.resolve({ data: null, error: { message: "unplanned table " + q.table } });
    if (q.op === "insert") {
      const row = Object.assign({ id: "00000000-0000-4000-8000-" + String(++n).padStart(12, "0") }, JSON.parse(JSON.stringify(q.payload)));
      rows.push(row);
      return Promise.resolve({ data: q.single ? shape(q, row) : (q.cols ? [shape(q, row)] : null), error: null });
    }
    if (q.op === "update") {
      const hit = rows.filter(r => keep(q, r));
      hit.forEach(r => Object.assign(r, JSON.parse(JSON.stringify(q.payload))));
      const copies = hit.map(r => shape(q, r));
      return Promise.resolve({ data: q.single ? (copies[0] || null) : (q.cols ? copies : null), error: null });
    }
    let hits = rows.filter(r => keep(q, r));
    const order = q.filters.find(f => f[0] === "order");
    if (order) hits = hits.slice().sort((a, b) => (a[order[1]] < b[order[1]] ? -1 : a[order[1]] > b[order[1]] ? 1 : 0) * (order[2] && order[2].ascending === false ? -1 : 1));
    const range = q.filters.find(f => f[0] === "range");
    if (range) hits = hits.slice(range[1], range[2] + 1);
    const limit = q.filters.find(f => f[0] === "limit");
    if (limit) hits = hits.slice(0, limit[1]);
    const copies = hits.map(r => shape(q, r));
    if (q.single) return Promise.resolve({ data: copies[0] || null, error: null });
    return Promise.resolve({ data: copies, error: null });
  }
  function from(table) {
    const q = { table, op: "select", cols: null, payload: null, filters: [], single: false };
    const b = {
      select(cols) { q.cols = cols || "*"; return b; },
      insert(p) { q.op = "insert"; q.payload = p; return b; },
      update(p) { q.op = "update"; q.payload = p; return b; }
    };
    ["eq", "in", "order", "range", "limit"].forEach(op => { b[op] = function () { q.filters.push([op].concat([].slice.call(arguments))); return b; }; });
    b.single = b.maybeSingle = () => { q.single = true; return answer(q); };
    b.then = (res, rej) => answer(q).then(res, rej);
    return b;
  }
  return { tables, client: { from } };
}

/* ── fixtures, from the real routes ─────────────────────────────────────── */
const OWNER = "aaaaaaaa-0000-4000-8000-000000000001";
const NOBODY = "aaaaaaaa-0000-4000-8000-000000000009";   // an admin with no sequences
const TASK = "11111111-0000-4000-8000-000000000001";
const XSS = "<img src=x onerror=alert(1)>";
const STEPS = [
  { step: 1, delay_days: 0, cumulative_day: 0, purpose: "welcome", subject: "Welcome & hello", body: "b1", subject_measurement: {} },
  { step: 2, delay_days: 3, cumulative_day: 3, purpose: "tips <b>bold</b>", subject: XSS, body: "b2", subject_measurement: {} },
  { step: 3, delay_days: 4, cumulative_day: 7, purpose: "ask", subject: "One question", body: "b3", subject_measurement: {} }
];
const sid = (k) => "5e000000-0000-4000-8000-" + String(k).padStart(12, "0");
function seqRow(k, status, created) {
  return { id: sid(k), owner_id: OWNER, name: "Seq " + k, brand: k === 1 ? "bizforce" : null, status, steps: STEPS, created_at: created, approved_at: created };
}
function world() {
  let en = 0;
  const enr = (seqK, contact, status, extra) => Object.assign({ id: "e0000000-0000-4000-8000-" + String(++en).padStart(12, "0"), sequence_id: sid(seqK),
    contact_id: contact, next_step: 0, next_send_at: null, status, stop_reason: null, last_sent_at: null }, extra || {});
  return {
    users: [{ id: OWNER, role: "admin" }, { id: NOBODY, role: "admin" }],
    email_sequences: [seqRow(1, "active", "2026-10-01T00:00:00.000Z"), seqRow(2, "paused", "2026-10-03T00:00:00.000Z"),
      seqRow(3, "completed", "2026-09-20T00:00:00.000Z"), seqRow(4, "cancelled", "2026-09-25T00:00:00.000Z")],
    email_sequence_enrollments: [
      enr(1, "c1", "active", { next_send_at: "2026-10-12T09:00:00.000Z", next_step: 1, last_sent_at: "2026-10-09T09:00:00.000Z" }),
      enr(1, "c2", "completed", { next_step: 3, last_sent_at: "2026-10-05T09:00:00.000Z" }),
      enr(1, "c3", "stopped", { stop_reason: "suppressed" }),
      enr(1, "c4", "stopped", { stop_reason: "cancelled_by_owner" }),
      enr(2, "c1", "active", { next_send_at: "2026-10-20T00:00:00.000Z" })
    ],
    contacts: [
      { id: "c1", owner_id: OWNER, name: "Pat <script>x</script>", email: "p1@example.com", brand: "bizforce" },
      { id: "c2", owner_id: OWNER, name: "Sam", email: "p2@example.com", brand: "bizforce" },
      { id: "c3", owner_id: OWNER, name: "Lee", email: "p3@example.com", brand: "bizforce" },
      { id: "c4", owner_id: OWNER, name: "Kim", email: "p4@example.com", brand: "other" }
    ],
    consent_events: [
      { contact_id: "c1", channel: "email", action: "confirmed", occurred_at: "2" },
      { contact_id: "c2", channel: "email", action: "confirmed", occurred_at: "2" },
      { contact_id: "c3", channel: "email", action: "granted", occurred_at: "2" }
      // c4: its read fails (see consentDown), so it is unreadable
    ],
    ai_tasks: [{ id: TASK, user_id: OWNER, task_type: "email/sequence", status: "completed", output: { steps: STEPS } }],
    agent_proposals: []
  };
}
const ENV_ALL = { ENABLE_EMAIL_SEQUENCES: "true", MAIL_POSTAL_ADDRESS: "SECRET-POSTAL 9 Hidden Lane", RESEND_WEBHOOK_SECRET: "whsec_LEAKME_123",
  EMAIL_MARKETING_DAILY_CAP: "37", RESEND_API_KEY: "re_SHOULD_NOT_APPEAR" };
let RESEND_CALLS = 0;

function backend(env) {
  const db = fakeDb(world(), q => q.table === "consent_events" && q.filters.some(f => f[2] === "c4") ? { message: "down" } : null);
  class Resend { constructor() { RESEND_CALLS++; this.emails = { send: async () => { RESEND_CALLS++; return { data: { id: "x" }, error: null }; } }; } }
  const ctx = {
    supabase: db.client, Resend, JSON, Math, Promise, Date,
    nowIso: () => new Date().toISOString(),
    process: { env: Object.assign({}, env || ENV_ALL) },
    console: { log() {}, error() {}, warn() {} },
    requireAuth: function requireAuth(req, res, next) { req.user = { id: req.headers.user, role: "admin" }; next(); },
    requireActiveSubscription: function requireActiveSubscription(req, res, next) { next(); }
  };
  const routes = {};
  const register = (method) => function (p) { routes[method + " " + p] = [].slice.call(arguments, 1); };
  ctx.app = { get: register("get"), post: register("post") };
  vm.createContext(ctx);
  vm.runInContext(LIFTED, ctx);
  async function call(key, user, params, body) {
    const chain = routes[key];
    const res = { code: 200, body: null, status(x) { this.code = x; return this; }, json(x) { this.body = JSON.parse(JSON.stringify(x)); return this; } };
    const req = { headers: { user }, params: params || {}, query: {}, body: body || {} };
    let i = 0;
    async function step() {
      const fn = chain[i++];
      if (!fn) return;
      let advanced = false;
      await fn(req, res, (e) => { if (e) { res.code = 500; res.body = { error: String(e.message || e) }; return; } advanced = true; });
      if (advanced) await step();
    }
    await step();
    return { status: res.code, body: res.body };
  }
  return { db, api: ctx.api, call };
}

/* ── the frontend in a fake page ────────────────────────────────────────── */
function fakeEl(id) {
  return { id, innerHTML: "", textContent: "", className: "", value: "", disabled: false, children: [],
    appendChild(c) { this.children.push(c); return c; }, addEventListener() {}, setAttribute() {}, getAttribute() { return null; } };
}
function responder(handlers, posted) {
  return function fetchStub(url, init) {
    const method = (init && init.method) || "GET";
    const p = url.replace(/^https?:\/\/[^/]+/, "");
    posted.push({ method, path: p, body: init && init.body ? JSON.parse(init.body) : undefined });
    const h = handlers(method, p, init && init.body ? JSON.parse(init.body) : undefined);
    if (h === "reject") return Promise.reject(new TypeError("Failed to fetch"));
    return Promise.resolve(h).then(r => ({ ok: r.status >= 200 && r.status < 300, status: r.status,
      json: () => r.body === undefined ? Promise.reject(new SyntaxError("Unexpected end of JSON input")) : Promise.resolve(JSON.parse(JSON.stringify(r.body))) }));
  };
}
function loadPage(handlers, opts) {
  const o = opts || {};
  const els = new Map(), clicks = [], posted = [];
  const page = fakeEl("page");
  const document = {
    readyState: "complete",
    head: fakeEl("head"),
    createElement() { return fakeEl(null); },
    addEventListener(type, fn) { if (type === "click") clicks.push(fn); },
    getElementById(id) { if (!els.has(id)) els.set(id, fakeEl(id)); return els.get(id); },
    querySelector(sel) { return sel === ".page" && o.mount !== false ? page : null; },
    querySelectorAll() { return []; }
  };
  const window = {};
  const ctx = { window, document, console, localStorage: { getItem() { return "check-token"; }, setItem() {} },
    fetch: responder(handlers, posted), setTimeout(fn) { return 0; }, clearTimeout() {} };
  vm.createContext(ctx);
  vm.runInContext(FILES[SEQ_JS], ctx);
  return { es: window.bfEmailSequences, window, document, els, clicks, posted, page };
}

// A handler that answers from the real backend.
function realHandlers(be, user, override) {
  return function (method, p, body) {
    const o = override && override(method, p, body);
    if (o !== undefined) return o;
    let m;
    if (method === "GET" && p === "/api/auth/me") return { status: 200, body: { user: be.api.publicUser({ id: user, role: "admin", email: "o@example.com" }) } };
    if (method === "GET" && p === "/api/email/sequences") return be.call("get /api/email/sequences", user);
    if (method === "GET" && (m = p.match(/^\/api\/email\/sequences\/([^/]+)$/))) return be.call("get /api/email/sequences/:id", user, { id: decodeURIComponent(m[1]) });
    if (method === "POST" && (m = p.match(/^\/api\/email\/sequences\/([^/]+)\/status$/))) return be.call("post /api/email/sequences/:id/status", user, { id: decodeURIComponent(m[1]) }, body);
    if (method === "POST" && p === "/api/agents/email/propose-sequence") return be.call("post /api/agents/email/propose-sequence", user, {}, body);
    return { status: 404, body: { error: "unplanned " + method + " " + p } };
  };
}

// A fake click: the button the delegated handler finds.
function clickOn(page, attrs, scope) {
  const btn = { getAttribute(a) { return Object.prototype.hasOwnProperty.call(attrs, a) ? attrs[a] : null; },
    closest(sel) { return scope && scope[sel] || null; }, disabled: false };
  const target = { closest(sel) {
    const want = sel.replace(/^\[|\]$/g, "");
    return Object.prototype.hasOwnProperty.call(attrs, want) ? btn : null;
  } };
  page.es.onClick({ target });
}

const rowsOf = (html) => {
  const out = {};
  html.split('<div class="es-row" data-es-row="').slice(1).forEach(chunk => { out[chunk.slice(0, chunk.indexOf('"'))] = chunk; });
  return out;
};
const movesIn = (rowHtml) => (rowHtml.match(/data-es-move="([a-z]+)"/g) || []).map(x => x.slice(14, -1));

(async function main() {
  /* ── 0. the real shapes ──────────────────────────────────────────────── */
  console.log("\n══ 0. the real shapes ══");
  check("/api/auth/me reports the user through publicUser", routeText("get", "/api/auth/me").includes("user: Object.assign({}, publicUser(req.user)"));
  const be0 = backend();
  check("publicUser carries role", be0.api.publicUser({ id: OWNER, role: "admin" }).role === "admin" && be0.api.publicUser({ id: OWNER }).role === "user");
  check("email-agent.html loads email-sequences.js after agent-profile.js",
    /<script src="\/scripts\/agent-profile\.js"><\/script>\n<script src="\/scripts\/email-sequences\.js"><\/script>/.test(FILES["email-agent.html"]));
  // agent-profile.js hands a sequence result to the page.
  {
    const html = FILES["email-agent.html"];
    const m = html.match(/<script>\s*(window\.AGENT_PROFILE_CONFIG\s*=[\s\S]*?)<\/script>/);
    const w = {}; vm.runInNewContext(m[1], { window: w });
    const cfg = w.AGENT_PROFILE_CONFIG;
    const els = new Map();
    const document = { head: { appendChild() {} }, createElement() { return fakeEl(null); }, addEventListener() {},
      getElementById(id) { if (!els.has(id)) els.set(id, fakeEl(id)); return els.get(id); }, querySelector() { return fakeEl(null); }, querySelectorAll() { return []; } };
    const handed = [];
    const window = { AGENT_PROFILE_CONFIG: cfg, bfAfterToolResult: (a, t, d, el) => handed.push([a, t, d, el]) };
    const RESULT = { success: true, steps: STEPS, measured: { step_count: 3 }, task_id: TASK, persisted: true };
    const ctx = { window, document, console, localStorage: { getItem() { return "t"; }, setItem() {} },
      fetch: () => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(RESULT) }), setTimeout() { return 0; }, clearTimeout() {}, setInterval() { return 0; }, clearInterval() {} };
    const tail = '  document.addEventListener("DOMContentLoaded", inject);\n})();';
    const src = FILES[PROFILE];
    vm.createContext(ctx);
    vm.runInContext(src.slice(0, src.lastIndexOf(tail)) + "  window.__ap = { runTool: runTool, TOOLS: TOOLS, toolDomId: toolDomId };\n" + tail, ctx);
    const tool = window.__ap.TOOLS.find(t => t.id === "sequence");
    tool.fields.forEach(f => { document.getElementById(window.__ap.toolDomId("sequence", "f_" + f.name)).value = f.type === "number" ? "3" : "x"; });
    window.__ap.runTool(tool);
    await flush();
    check("agent-profile.js hands the sequence result to bfAfterToolResult as (email, sequence, data, result element)",
      handed.length === 1 && handed[0][0] === "email" && handed[0][1] === "sequence" && handed[0][2].task_id === TASK &&
      handed[0][3] === document.getElementById(window.__ap.toolDomId("sequence", "result")), JSON.stringify(handed.map(h => h.slice(0, 2))));
  }

  /* ── A. filing ───────────────────────────────────────────────────────── */
  console.log("\n══ A. filing ══");
  const RESULT = { success: true, steps: STEPS, task_id: TASK, persisted: true };
  async function drawn(meRole, meFail) {
    const be = backend();
    const pg = loadPage(realHandlers(be, OWNER, (m, p) => {
      if (p !== "/api/auth/me") return undefined;
      if (meFail) return meFail;
      return { status: 200, body: { user: be.api.publicUser({ id: OWNER, role: meRole }) } };
    }), { mount: false });
    const slot = fakeEl("slot");
    await pg.es.drawFiling(slot, RESULT);
    return { pg, be, html: slot.innerHTML };
  }
  const admin = await drawn("admin");
  check("admin: the form, posting this run's task_id", admin.html.includes("data-es-file") && admin.html.includes('data-es-task="' + TASK + '"') &&
    admin.html.includes("es-name") && admin.html.includes("es-brand"), admin.html);
  check("admin: no 'owner account' line", !admin.html.includes(admin.pg.es.NOT_OWNER_LINE));
  const user = await drawn("user");
  check("non-admin: no form", !user.html.includes("data-es-file") && !user.html.includes("es-name"), user.html);
  check("non-admin: the one quiet line", count(user.html, user.pg.es.NOT_OWNER_LINE) === 1, user.html);
  const meDown = await drawn(null, { status: 500, body: { error: "boom" } });
  check("/api/auth/me unreadable: neither the form nor the non-admin line, an error instead",
    !meDown.html.includes("data-es-file") && !meDown.html.includes(meDown.pg.es.NOT_OWNER_LINE) && /could not be checked/.test(meDown.html), meDown.html);

  {
    const be = backend();
    const pg = loadPage(realHandlers(be, OWNER), { mount: false });
    const msg = fakeEl("msg"), form = fakeEl("form");
    await pg.es.fileSequence(TASK, "  Welcome series  ", "bizforce", msg, form);
    const filed = pg.posted.find(x => x.path === "/api/agents/email/propose-sequence");
    check("files with { task_id, name trimmed, brand }", filed && JSON.stringify(filed.body) === JSON.stringify({ task_id: TASK, name: "Welcome series", brand: "bizforce" }),
      filed && JSON.stringify(filed.body));
    const real = await be.call("post /api/agents/email/propose-sequence", OWNER, {}, { task_id: TASK, name: "Again", brand: "bizforce" });
    check("fixture: the real route answers 201 with audience_now", real.status === 201 && typeof real.body.audience_now.confirmed_contacts === "number", JSON.stringify(real.body));
    check("success: the measured count (2 confirmed of the brand)", form.innerHTML.includes("Confirmed contacts right now: <strong>2</strong>"), form.innerHTML);
    check("success: the server's note verbatim", form.innerHTML.includes(real.body.audience_now.note.replace(/&/g, "&amp;").replace(/'/g, "&#39;")) ||
      form.innerHTML.includes(real.body.audience_now.note), form.innerHTML);
    check("success: a link to the proposals page", form.innerHTML.includes('href="/proposals.html"'));
    const msg2 = fakeEl("msg2"), form2 = fakeEl("form2");
    await pg.es.fileSequence(TASK, "X", "no-such-brand", msg2, form2);
    const refused = await be.call("post /api/agents/email/propose-sequence", OWNER, {}, { task_id: TASK, name: "X", brand: "no-such-brand" });
    check("error: the server's message, unchanged", refused.status === 400 && msg2.textContent === refused.body.error && /err/.test(msg2.className), msg2.textContent);
    check("error: no success panel", form2.innerHTML === "");
    const before = pg.posted.length, msg3 = fakeEl("msg3");
    await pg.es.fileSequence(TASK, "   ", "", msg3, fakeEl("f3"));
    check("a blank name posts nothing and says why", pg.posted.length === before && /1 to 100/.test(msg3.textContent));
  }

  /* ── B. the sender ───────────────────────────────────────────────────── */
  console.log("\n══ B. the sender ══");
  async function senderFor(env) {
    const be = backend(env);
    const list = await be.call("get /api/email/sequences", OWNER);
    const pg = loadPage(realHandlers(be, OWNER), { mount: false });
    return { body: list.body, html: pg.es.senderMarkup(list.body.sender) };
  }
  const reasonsIn = (h) => (h.match(/data-es-reason>([^<]*)</g) || []).map(x => x.slice(15, -1));
  const all = await senderFor(ENV_ALL);
  check("all set: 'Sending is on' with the daily cap 37", all.html.includes("Sending is on. Daily cap: 37"), all.html);
  check("all set: no reason lines", reasonsIn(all.html).length === 0, all.html);
  const LEAKS = ["SECRET-POSTAL", "Hidden Lane", "whsec_", "LEAKME", "re_SHOULD"];
  const cases = [
    ["sender switched off", Object.assign({}, ENV_ALL, { ENABLE_EMAIL_SEQUENCES: "false" }), /switched off/],
    ["postal address not set", Object.assign({}, ENV_ALL, { MAIL_POSTAL_ADDRESS: " " }), /postal address/],
    ["webhook secret not set", Object.assign({}, ENV_ALL, { RESEND_WEBHOOK_SECRET: "" }), /webhook secret/],
    ["daily cap unreadable", Object.assign({}, ENV_ALL, { EMAIL_MARKETING_DAILY_CAP: "lots" }), /daily cap could not be read/]
  ];
  for (const [label, env, re] of cases) {
    const r = await senderFor(env);
    const reasons = reasonsIn(r.html);
    check(label + ": exactly one reason line, saying so", reasons.length === 1 && re.test(reasons[0]), JSON.stringify(reasons));
    check(label + ": no environment value in the server's sender or on the page", !LEAKS.some(x => JSON.stringify(r.body.sender).includes(x) || r.html.includes(x)));
    if (label !== "webhook secret not set") check(label + ": 'Nothing is being sent', not 'Sending is on'", r.html.includes("Nothing is being sent") && !r.html.includes("Sending is on"));
  }
  // An unset cap is the server's default (50), so "nothing usable" sets it to garbage.
  const none = await senderFor({ EMAIL_MARKETING_DAILY_CAP: "lots" });
  check("nothing usable: four reason lines", reasonsIn(none.html).length === 4, JSON.stringify(reasonsIn(none.html)));
  const dflt = await senderFor({ ENABLE_EMAIL_SEQUENCES: "true", MAIL_POSTAL_ADDRESS: "x", RESEND_WEBHOOK_SECRET: "y" });
  check("cap unset: the server's default, 50, shown as on", dflt.html.includes("Sending is on. Daily cap: 50") && reasonsIn(dflt.html).length === 0, dflt.html);
  check("the sender's fields are booleans and the cap", Object.keys(all.body.sender).sort().join() === "daily_cap,enabled,postal_address_set,webhook_secret_set" &&
    ["enabled", "postal_address_set", "webhook_secret_set"].every(k => typeof all.body.sender[k] === "boolean"));
  check("all set: no environment value on the page", !LEAKS.some(x => all.html.includes(x)));

  /* ── C. the list, empty and failed ───────────────────────────────────── */
  console.log("\n══ C. the list: empty and failed ══");
  const EMPTY = "No sequences yet.";
  async function listed(user, override) {
    const be = backend();
    const pg = loadPage(realHandlers(be, user, override));
    await flush();
    return { pg, be, list: pg.els.get("esList").innerHTML, sender: pg.els.get("esSender").innerHTML };
  }
  const full = await listed(OWNER);
  check("a real list: four sequences, no empty line", Object.keys(rowsOf(full.list)).length === 4 && count(full.list, EMPTY) === 0, full.list.slice(0, 200));
  const empty = await listed(NOBODY);
  check("a real empty array: 'No sequences yet.' exactly once", count(empty.list, EMPTY) === 1, empty.list);
  const failCases = [
    ["a 500", (m, p) => p === "/api/email/sequences" ? { status: 500, body: { error: "Internal server error" } } : undefined],
    ["a network failure", (m, p) => p === "/api/email/sequences" ? "reject" : undefined],
    ["an unparseable 200", (m, p) => p === "/api/email/sequences" ? { status: 200, body: undefined } : undefined],
    ["a 200 without a sequences array", (m, p) => p === "/api/email/sequences" ? { status: 200, body: { sender: {} } } : undefined]
  ];
  const failedLists = [];
  for (const [label, override] of failCases) {
    const r = await listed(OWNER, override);
    failedLists.push(r.list);
    check(label + ": an error panel", /could not be loaded/.test(r.list) && /data-es-retry/.test(r.list), r.list);
    check(label + ": never 'No sequences yet.'", count(r.list, EMPTY) === 0);
  }
  check("'No sequences yet.' appeared only for the real empty array",
    count(full.list, EMPTY) === 0 && failedLists.every(h => count(h, EMPTY) === 0) && count(empty.list, EMPTY) === 1);

  /* ── D. the moves ────────────────────────────────────────────────────── */
  console.log("\n══ D. the moves ══");
  const rows = rowsOf(full.list);
  const statusOf = { [sid(1)]: "active", [sid(2)]: "paused", [sid(3)]: "completed", [sid(4)]: "cancelled" };
  for (const id of Object.keys(statusOf)) {
    const offered = movesIn(rows[id] || "");
    for (const to of ["active", "paused", "cancelled"]) {
      const be = backend();
      const r = await be.call("post /api/email/sequences/:id/status", OWNER, { id }, { status: to });
      const allowed = r.status === 200;
      check(statusOf[id] + " → " + to + ": button " + (allowed ? "shown" : "not shown") + " (the real route answers " + r.status + ")",
        offered.includes(to) === allowed, JSON.stringify(offered));
    }
  }
  check("the list row shows the stopped counts with plain labels", /Stopped: bounced or complained 1 · cancelled by you 1/.test(rows[sid(1)] || ""), rows[sid(1)]);
  check("the list row shows the brand, steps and enrollment counts", /Brand: bizforce · Steps: 3/.test(rows[sid(1)] || "") && /Contacts: active 1 · completed 1 · stopped 2/.test(rows[sid(1)] || ""), rows[sid(1)]);
  const localNext = new Date("2026-10-12T09:00:00.000Z").toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
  check("the next send is in the viewer's local time", (rows[sid(1)] || "").includes("Next send: " + localNext), localNext);

  {
    const be = backend();
    const pg = loadPage(realHandlers(be, OWNER));
    await flush();
    const actions = fakeEl("actions"), amsg = fakeEl("amsg");
    actions.querySelector = (sel) => sel === ".es-action-msg" ? amsg : null;
    const posts = () => pg.posted.filter(x => x.method === "POST");
    clickOn(pg, { "data-es-move": "cancelled", "data-es-id": sid(1) }, { ".es-actions": actions });
    await flush();
    check("Cancel: the first tap posts nothing", posts().length === 0, JSON.stringify(posts()));
    check("Cancel: it asks, saying it stops every remaining send and cannot be undone",
      /stops every remaining send/.test(actions.innerHTML) && /cannot be undone/.test(actions.innerHTML) && actions.innerHTML.includes("data-es-confirm-cancel"), actions.innerHTML);
    check("Cancel: the sequence is still active", be.db.tables.email_sequences.find(x => x.id === sid(1)).status === "active");
    clickOn(pg, { "data-es-confirm-cancel": "", "data-es-id": sid(1) }, { ".es-actions": actions });
    await flush();
    check("Cancel confirmed: posts { status: cancelled } once", posts().length === 1 && posts()[0].path === "/api/email/sequences/" + sid(1) + "/status" &&
      posts()[0].body.status === "cancelled", JSON.stringify(posts()));
    check("Cancel confirmed: the real route cancelled it", be.db.tables.email_sequences.find(x => x.id === sid(1)).status === "cancelled");
    clickOn(pg, { "data-es-move": "paused", "data-es-id": sid(2) }, { ".es-actions": actions });
    await flush();
    check("Pause on a paused sequence's stale button: a 409 shows the server's message", /This sequence is paused, so it cannot be set to paused/.test(amsg.textContent) && /err/.test(amsg.className), amsg.textContent);
    const be2 = backend();
    const pg2 = loadPage(realHandlers(be2, OWNER));
    await flush();
    const a2 = fakeEl("a2"); a2.querySelector = () => fakeEl("m");
    clickOn(pg2, { "data-es-move": "paused", "data-es-id": sid(1) }, { ".es-actions": a2 });
    await flush();
    check("Pause: posts at once, and the real route pauses it", pg2.posted.some(x => x.method === "POST" && x.body && x.body.status === "paused") &&
      be2.db.tables.email_sequences.find(x => x.id === sid(1)).status === "paused");
  }

  /* ── E. the detail ───────────────────────────────────────────────────── */
  console.log("\n══ E. the detail ══");
  {
    const be = backend();
    const pg = loadPage(realHandlers(be, OWNER));
    await flush();
    await pg.es.loadDetail(sid(1));
    const h = pg.els.get("esDetail").innerHTML;
    check("the detail lists the three steps", count(h, "<li>") === 3, h.slice(0, 300));
    check("step text escaped: no raw tag, the escaped form shown", !h.includes(XSS) && h.includes("&lt;img src=x onerror=alert(1)&gt;"));
    check("purpose escaped", !h.includes("<b>bold</b>") && h.includes("&lt;b&gt;bold&lt;/b&gt;"));
    check("contact name escaped", !h.includes("<script>x</script>") && h.includes("Pat &lt;script&gt;x&lt;/script&gt;"));
    check("each contact's position", h.includes("next: step 2 of 3") && h.includes("all 3 sent"), h);
    check("each contact's reason, plainly", h.includes("bounced or complained") && h.includes("cancelled by you"));
    await pg.es.loadDetail(sid(99));
    const nf = pg.els.get("esDetail").innerHTML;
    check("another sequence's id: the server's 404 message, as an error", nf.includes("No sequence with that id was found.") && /could not be loaded/.test(nf), nf);
  }

  /* ── F. proposals.html ───────────────────────────────────────────────── */
  console.log("\n══ F. proposals.html ══");
  {
    const be = backend();
    const filed = await be.call("post /api/agents/email/propose-sequence", OWNER, {}, { task_id: TASK, name: "Welcome <i>series</i>", brand: "bizforce" });
    const pending = filed.body.proposal;
    const result = await be.api.execute(Object.assign({}, pending, { status: "executing" }));
    check("fixture: the real executor's result carries all four counts", ["enrolled", "already_enrolled", "skipped_not_confirmed", "skipped_unreadable"].every(k => typeof result[k] === "number") &&
      result.skipped_unreadable === 0 && result.enrolled === 2, JSON.stringify(result));
    // One with an unreadable consent among the brand's contacts.
    const be2 = backend();
    be2.db.tables.contacts.find(c => c.id === "c4").brand = "bizforce";
    const filed2 = await be2.call("post /api/agents/email/propose-sequence", OWNER, {}, { task_id: TASK, name: "Second", brand: "bizforce" });
    const result2 = await be2.api.execute(Object.assign({}, filed2.body.proposal, { status: "executing" }));
    check("fixture: an unreadable consent is counted as skipped_unreadable 1", result2.skipped_unreadable === 1, JSON.stringify(result2));
    const executed = Object.assign({}, filed2.body.proposal, { id: "p-2", status: "executed", execution_result: result2 });

    const m = FILES[PROPOSALS].match(/<script>\nvar API_URL[\s\S]*?<\/script>/);
    const script = m[0].replace(/^<script>/, "").replace(/<\/script>$/, "");
    const els = new Map();
    const document = { getElementById(id) { if (!els.has(id)) { const e = fakeEl(id); e.querySelectorAll = () => []; els.set(id, e); } return els.get(id); },
      querySelectorAll() { return []; }, querySelector() { return null; } };
    const ctx = { document, console, localStorage: { getItem() { return "t"; } }, setTimeout() { return 0; }, clearTimeout() {},
      fetch: () => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ proposals: [pending, executed] }) }) };
    ctx.window = ctx;
    vm.createContext(ctx);
    vm.runInContext(script, ctx);
    await flush();
    const h = els.get("proposalsList").innerHTML;
    check("the card shows the sequence name, escaped", h.includes("Welcome &lt;i&gt;series&lt;/i&gt;") && !h.includes("<i>series</i>"));
    check("the card shows the brand and the step count", /brand<\/span><span class="pf-value">bizforce/.test(h) && /steps<\/span><span class="pf-value">3</.test(h));
    check("each step's day and subject: Day 0, Day 3, Day 7", h.includes("<li>Day 0: Welcome &amp; hello</li>") &&
      h.includes("<li>Day 3: &lt;img src=x onerror=alert(1)&gt;</li>") && h.includes("<li>Day 7: One question</li>"), h.slice(0, 600));
    check("step text never raw", !h.includes(XSS));
    const labels = [["Enrolled now", result2.enrolled], ["Already enrolled", result2.already_enrolled],
      ["Skipped — consent not confirmed", result2.skipped_not_confirmed], ["Skipped — consent could not be read", result2.skipped_unreadable]];
    labels.forEach(([label, v]) => check("after approval: " + label + " " + v,
      h.includes('<span class="pf-label">' + label + '</span><span class="pf-value">' + v + '</span>'), label));
    check("after approval: the counts are not a raw JSON block", !h.includes("&quot;skipped_unreadable&quot;"));
  }

  check("zero Resend calls", RESEND_CALLS === 0, RESEND_CALLS);

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.error("\nThe check threw: " + (e && e.stack || e)); process.exit(1); });
