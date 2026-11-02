/* ═══════════════════════════════════════════════════════════════════════════
   checkTermaximusRecords.js — Termaximus answers from records (intelligence
   layer B10)

   WHAT THIS PROVES (the model is stubbed: no external call is made)

     A. THE TEMPLATES, word for word from fixtures: why_ran and why_not from a
        stored decision (every gate in order with its REASONS sentence; the
        member gate by name; "the record shows it did not" when the question
        and the record disagree), next_fire with triggers on (the next :30 UTC
        check, the last value against the line, the cooldown left) and OFF
        (said plainly: no check time, no firing claimed), flow for a declared
        link (the runs counted from the member's own rows in the window).
     B. THE BUTTONS (GET /api/guide/records/answer, lifted from server.js):
        each intent gives exactly its template, with ZERO model calls, zero
        limit checks and zero ledger rows; another member's record and an
        undeclared link are "There is no record of that."; a bad intent or a
        subject of the wrong kind is a 400; a failed read is a 503.
     C. FREE TEXT (POST /api/guide/records, lifted, with the real
        callGuideModel and a stubbed Anthropic client): the model is shown
        only ids, kinds, agents and times (no name, prompt, reason, gate or
        other content, nothing older than 7 days, nothing of another member);
        it may only pick; a subject_id not offered, another member's, or of
        the wrong kind is refused; the answer is the template, never the
        model's words; no match is exactly "There is no record of that." with
        the closest real page.
     D. THE LIMITS AND THE LEDGER: one Haiku call per typed question, inside
        Guide mode's 30 a day (subscribed) and 5 (not): over either, a 429 and
        no call; a count that cannot be read, a 503 and no call; the server's
        limits (enforceDailyModelCallLimit, route "guide") run before the
        call and their refusal is sent as it is, with no ledger row; the
        ledger row is route "guide"; G25 is recorded for the route.
     E. SUGGESTIONS BY RULE (GET /api/guide/suggestions, lifted): each rule
        and its boundaries, the numbers shown from the member's own rows,
        another member's rows never counted, a trigger already held not
        offered again, a failed read named and not guessed, every body a
        valid trigger, and NOTHING WRITTEN.
     F. OWNERSHIP: every read in every section names the caller's user_id.
     U. THE PAGES, in jsdom: the Guide tab's "Ask about your records" box and
        "Suggestions"; a button question renders the template's lines, gates
        in order, its links and the Why panel button, as text; the typed box
        sends only the question; "Add it" is the only thing that saves (POST
        /api/triggers with the offered body); "Not now" hides one for 30 days
        on this device and it comes back after; HQ mounts the suggestions;
        "Ask Termaximus" in the Why panel, the trigger list and the network
        map; the kept-at-sign-out key is named.
     W. THE WIRING in server.js and the guide tip.
     S. No emoji in any new or edited file.

   MUTATIONS — MUTATE=<name> applies one in memory; MUTATE=all runs each:
     model-text-used-as-answer          the model's reply is shown        -> C
     unoffered-subject-accepted         an id not offered is answered     -> C
     another-members-record             a decision read without user_id   -> B, F
     model-call-for-button              a button question calls the model -> B
     suggestion-saved-without-approval  suggestions are saved as offered  -> E
     next-fire-while-off                triggers off still names a check  -> A, B
   ═══════════════════════════════════════════════════════════════════════════ */
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const Module = require("module");
const { execFileSync } = require("child_process");
const MUT = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const read = p => fs.readFileSync(path.join(REPO, p), "utf8").replace(/\r\n/g, "\n");
const readFe = p => fs.readFileSync(path.join(FRONTEND, p), "utf8").replace(/\r\n/g, "\n");
const PRE_RECORDS = "57d0089";
const PRE_FRONTEND = "d51ffd1";

const MUTATIONS = {
  "model-text-used-as-answer": ["lib",
    "      out.limit = { per_day: limit, subscribed: subscribed, used: used.count + spent };",
    "      if (reply && reply.text) out = { known: true, title: null, lines: [String(reply.text)], text: String(reply.text), links: [] };\n      out.limit = { per_day: limit, subscribed: subscribed, used: used.count + spent };"],
  "unoffered-subject-accepted": ["lib",
    "  if (!offered) return { ok: false, reason: \"not_offered\" };", "  if (false) return { ok: false, reason: \"not_offered\" };"],
  "another-members-record": ["lib",
    "  var got = await db.from(\"gate_decisions\").select(DECISION_ROW).eq(\"id\", id).eq(\"user_id\", userId).maybeSingle();",
    "  var got = await db.from(\"gate_decisions\").select(DECISION_ROW).eq(\"id\", id).maybeSingle();"],
  "model-call-for-button": ["server",
    "      said = await REC.answerFor(recordsContext(), req.user.id, asked.intent, asked.subject, asked.window);",
    "      await callGuideModel({ userId: req.user.id, system: [], user: \"\", maxTokens: 10 });\n      said = await REC.answerFor(recordsContext(), req.user.id, asked.intent, asked.subject, asked.window);"],
  "suggestion-saved-without-approval": ["lib",
    "  return { suggestions: out, unreadable: unreadable, rules:",
    "  for (var sx = 0; sx < out.length; sx++) await db.from(\"member_triggers\").insert(Object.assign({ user_id: userId }, out[sx].body));\n  return { suggestions: out, unreadable: unreadable, rules:"],
  "next-fire-while-off": ["lib", "  if (!serverOn) {", "  if (false) {"]
};
const NAMES = Object.keys(MUTATIONS);
const MUTATE = process.env.MUTATE || "";
if (MUTATE === "all") MUT.runAllMutations(__filename, NAMES);
if (MUTATE && NAMES.indexOf(MUTATE) === -1) { console.error("Unknown MUTATE=" + MUTATE + ". Known: " + NAMES.join(", ")); process.exit(2); }

let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 700) + "]" : "")); }
}
const UNHANDLED = [];
process.on("unhandledRejection", function (e) { UNHANDLED.push(e); });

const FILES = {
  lib: read("lib/termaximusRecords.js"),
  server: read("server.js"),
  presence: readFe("scripts/termaximus-presence.js"),
  why: readFe("scripts/bf-why.js"),
  triggers: readFe("scripts/bf-triggers.js"),
  network: readFe("scripts/bf-network.js"),
  session: readFe("scripts/bf-session.js"),
  execHtml: readFe("executive-agent.html"),
  guide: readFe("scripts/termaximus-guide.js"),
  tipClaims: read("scripts/checkGuideTipClaims.js"),
  offline: read("scripts/checkOfflineMode.js")
};
if (MUTATE) {
  const m = MUTATIONS[MUTATE];
  FILES[m[0]] = MUT.replaceOnce(FILES[m[0]], m[1], m[2], MUTATE);
  console.log("\n!! MUTATION: " + MUTATE);
}
const J = JSON.stringify;
const realRequire = Module.createRequire(path.join(REPO, "server.js"));
const GATES = realRequire("./lib/gates");
const T = realRequire("./lib/triggers");
const NET = realRequire("./lib/agentNetwork");
const GUIDE = realRequire("./lib/guideAsk");
const RUNNER = realRequire("./lib/triggerRunner");
const APP_MAP = JSON.parse(read("lib/appMap.json"));
function compile(src, filename, req) {
  const m = { exports: {} };
  const fn = vm.compileFunction(src, ["module", "exports", "require"], { filename: filename });
  fn(m, m.exports, req);
  return m.exports;
}
const REC = compile(FILES.lib, "lib/termaximusRecords.js", r => realRequire(r.replace(/^\.\//, "./lib/")));
const NO_RECORD = "There is no record of that.";
const CLOSING = "That is all the record holds; I add nothing to it.";

/* ── fixtures ─────────────────────────────────────────────────────────────── */
const NOW = Date.parse("2026-11-01T14:10:00.000Z");
const ME = "11111111-1111-4111-8111-111111111111";
const OTHER = "22222222-2222-4222-8222-222222222222";
const ID = n => "d1000000-0000-4000-8000-00000000000" + n;
const RUN1 = "a1000000-0000-4000-8000-000000000001";
const DEC_BLOCKED = { id: ID(1), user_id: ME, action: "schedule_run", target: "schedule:5c000000-0000-4000-8000-000000000001", outcome: "blocked",
  results: [{ gate: "G18", result: "pass" }, { gate: "G16", result: "fail", code: "autonomy_off" }, { gate: "G13", result: "not_reached" }],
  facts: { agent: "seo" }, member_gate_name: null, created_at: "2026-10-31T09:00:00.000Z" };
const DEC_RAN = { id: ID(2), user_id: ME, action: "dispatch", target: "ai_task:" + RUN1, outcome: "ran",
  results: [{ gate: "G19", result: "pass" }, { gate: "G12", result: "bypass" }], facts: { agent: "content" }, member_gate_name: null, created_at: "2026-11-01T08:15:00.000Z" };
const DEC_MEMBER = { id: ID(3), user_id: ME, action: "proposal_approve", target: "proposal:b1000000-0000-4000-8000-000000000001", outcome: "blocked",
  results: [{ gate: "G3", result: "pass" }, { gate: "G1", result: "pass" }], facts: { agent: "social" }, member_gate_name: "Weekdays only", created_at: "2026-10-30T22:05:00.000Z" };
const DEC_OLD = { id: ID(4), user_id: ME, action: "schedule_run", target: "schedule:5c000000-0000-4000-8000-000000000002", outcome: "blocked",
  results: [{ gate: "G18", result: "fail", code: "schedule_paused" }], facts: { agent: "seo" }, member_gate_name: null, created_at: "2026-10-10T09:00:00.000Z" };
const DEC_OTHER = { id: ID(5), user_id: OTHER, action: "schedule_run", target: "schedule:5c000000-0000-4000-8000-000000000003", outcome: "blocked",
  results: [{ gate: "G18", result: "fail", code: "schedule_paused" }], facts: { agent: "seo" }, member_gate_name: "Other member gate", created_at: "2026-11-01T09:00:00.000Z" };
const TRIG_ID = "c1000000-0000-4000-8000-000000000001", TRIG_FRESH = "c1000000-0000-4000-8000-000000000002", TRIG_OFF = "c1000000-0000-4000-8000-000000000003", TRIG_OTHER = "c1000000-0000-4000-8000-000000000004";
function trig(id, user, name, extra) {
  return Object.assign({ id: id, user_id: user, name: name, metric: "tasks_failed", metric_agent: null, comparator: "gte", threshold: 3, metric_window: "24h",
    cooldown_hours: 24, action: { kind: "raise_alert" }, enabled: true, last_value: 4, last_checked_at: "2026-11-01T13:30:00.000Z",
    last_attempt_at: "2026-11-01T03:30:00.000Z", last_fired_at: "2026-11-01T03:30:00.000Z", created_at: "2026-10-01T00:00:00.000Z", updated_at: "2026-10-01T00:00:00.000Z" }, extra || {});
}
function task(id, user, agent, status, at, prompt) { return { id: id, user_id: user, agent_type: agent, status: status, task_type: null, prompt: prompt || "ZEBRA-PROMPT write the secret plan", created_at: at }; }
function world(over) {
  const w = {
    gate_decisions: [DEC_BLOCKED, DEC_RAN, DEC_MEMBER, DEC_OLD, DEC_OTHER],
    ai_tasks: [
      task(RUN1, ME, "content", "completed", "2026-11-01T08:10:00.000Z"),
      task("f1000000-0000-4000-8000-000000000001", ME, "seo", "failed", "2026-10-29T10:00:00.000Z"),
      task("f1000000-0000-4000-8000-000000000002", ME, "seo", "failed", "2026-10-30T10:00:00.000Z"),
      task("f1000000-0000-4000-8000-000000000003", ME, "content", "failed", "2026-10-31T10:00:00.000Z"),
      task("f1000000-0000-4000-8000-000000000004", ME, "seo", "failed", "2026-10-01T10:00:00.000Z"),
      task("f2000000-0000-4000-8000-000000000001", OTHER, "sales", "failed", "2026-10-31T10:00:00.000Z"),
      task("f2000000-0000-4000-8000-000000000002", OTHER, "sales", "failed", "2026-10-31T11:00:00.000Z"),
      task("f2000000-0000-4000-8000-000000000003", OTHER, "sales", "failed", "2026-10-31T12:00:00.000Z")
    ],
    member_triggers: [
      trig(TRIG_ID, ME, "Moonlight Stock"),
      trig(TRIG_FRESH, ME, "Fresh Line", { last_attempt_at: null, last_fired_at: null, created_at: "2026-10-02T00:00:00.000Z" }),
      trig(TRIG_OFF, ME, "Quiet One", { enabled: false, created_at: "2026-10-03T00:00:00.000Z" }),
      trig(TRIG_OTHER, OTHER, "Other Trigger Name")
    ],
    executive_dispatches: [
      { id: "e1", user_id: ME, agent_type: "content", tool: "blog-post", outcome: "ran", tool_task_id: RUN1, chain_id: null, created_at: "2026-11-01T12:00:00.000Z" },
      { id: "e2", user_id: ME, agent_type: "content", tool: "blog-post", outcome: "ran", tool_task_id: "a1000000-0000-4000-8000-000000000002", chain_id: null, created_at: "2026-10-31T16:00:00.000Z" },
      { id: "e3", user_id: ME, agent_type: "content", tool: "blog-post", outcome: "ran", tool_task_id: "a1000000-0000-4000-8000-000000000003", chain_id: null, created_at: "2026-10-30T10:00:00.000Z" },
      { id: "e4", user_id: ME, agent_type: "content", tool: "blog-post", outcome: "refused", tool_task_id: null, chain_id: null, created_at: "2026-11-01T13:00:00.000Z" },
      { id: "e5", user_id: OTHER, agent_type: "content", tool: "blog-post", outcome: "ran", tool_task_id: "a2000000-0000-4000-8000-000000000001", chain_id: null, created_at: "2026-11-01T11:00:00.000Z" }
    ],
    agent_proposals: [],
    member_links: [{ user_id: OTHER, from_agent: "executive", to_agent: "content", enabled: false }],
    inventory_items: [],
    model_calls: [],
    content_library: [],
    engine_visits: []
  };
  for (let i = 0; i < 6; i++) w.agent_proposals.push({ id: "p" + i, user_id: ME, agent_type: "seo", action_type: "publish_blog_post", status: "pending", executed_at: null, created_at: "2026-10-30T00:00:00.000Z" });
  for (let i = 0; i < 9; i++) w.agent_proposals.push({ id: "q" + i, user_id: OTHER, agent_type: "seo", action_type: "publish_blog_post", status: "pending", executed_at: null, created_at: "2026-10-30T00:00:00.000Z" });
  w.inventory_items.push({ id: "i1", user_id: ME, quantity_on_hand: 2, reorder_point: 3 }, { id: "i2", user_id: ME, quantity_on_hand: 9, reorder_point: 3 },
    { id: "i3", user_id: OTHER, quantity_on_hand: 0, reorder_point: 3 }, { id: "i4", user_id: OTHER, quantity_on_hand: 0, reorder_point: 3 });
  return Object.assign(w, over || {});
}

/* ── a fake supabase: filters, order, limit, range, counts; reads and writes logged ── */
const ISO_RE = /^\d{4}-\d{2}-\d{2}T/;
function cmp(a, b) {
  if (typeof a === "string" && typeof b === "string" && ISO_RE.test(a) && ISO_RE.test(b)) return Date.parse(a) - Date.parse(b);
  return a < b ? -1 : a > b ? 1 : 0;
}
function fakeDb(tables, opts) {
  const log = { reads: [], writes: [] };
  const fail = new Set((opts && opts.fail) || []);
  function from(table) {
    const st = { filters: [], head: false, count: null, order: null, limit: null, range: null, single: false, op: "select", payload: null };
    function val(row, c) { if (c.indexOf("->>") !== -1) { const p = c.split("->>"); return row[p[0]] && row[p[0]][p[1]]; } return row[c]; }
    function match(row) {
      return st.filters.every(f => {
        const x = val(row, f[1]), v = f[2];
        switch (f[0]) {
          case "eq": return x === v;
          case "neq": return x !== v;
          case "gt": return x !== null && x !== undefined && cmp(x, v) > 0;
          case "gte": return x !== null && x !== undefined && cmp(x, v) >= 0;
          case "lt": return x !== null && x !== undefined && cmp(x, v) < 0;
          case "lte": return x !== null && x !== undefined && cmp(x, v) <= 0;
          case "in": return v.indexOf(x) !== -1;
          case "like": return typeof x === "string" && x.indexOf(String(v).replace(/%$/, "")) === 0;
          case "not": return x !== null && x !== undefined;
          default: return false;
        }
      });
    }
    function run() {
      if (st.op !== "select") { log.writes.push({ table: table, op: st.op, payload: st.payload }); return { data: null, error: null }; }
      log.reads.push({ table: table, filters: st.filters.slice() });
      if (fail.has(table)) return { data: null, error: { message: table + " is down" }, count: null };
      let rows = (tables[table] || []).filter(match);
      if (st.order) rows = rows.slice().sort((a, b) => (st.order[1] ? 1 : -1) * cmp(a[st.order[0]], b[st.order[0]]));
      const count = rows.length;
      if (st.range) rows = rows.slice(st.range[0], st.range[1] + 1);
      if (st.limit !== null) rows = rows.slice(0, st.limit);
      if (st.head) return { data: null, error: null, count: count };
      if (st.single) return { data: rows[0] ? JSON.parse(J(rows[0])) : null, error: null };
      return { data: JSON.parse(J(rows)), error: null, count: st.count ? count : null };
    }
    const api = {
      select(cols, o) { if (st.op === "select" && o) { st.count = o.count || null; st.head = !!o.head; } return api; },
      eq(c, v) { st.filters.push(["eq", c, v]); return api; },
      neq(c, v) { st.filters.push(["neq", c, v]); return api; },
      gt(c, v) { st.filters.push(["gt", c, v]); return api; },
      gte(c, v) { st.filters.push(["gte", c, v]); return api; },
      lt(c, v) { st.filters.push(["lt", c, v]); return api; },
      lte(c, v) { st.filters.push(["lte", c, v]); return api; },
      in(c, v) { st.filters.push(["in", c, v]); return api; },
      like(c, v) { st.filters.push(["like", c, v]); return api; },
      not(c, op, v) { st.filters.push(["not", c, v]); return api; },
      order(c, o) { st.order = [c, !o || o.ascending !== false]; return api; },
      limit(n) { st.limit = n; return api; },
      range(a, b) { st.range = [a, b]; return api; },
      maybeSingle() { st.single = true; return api; },
      single() { st.single = true; return api; },
      insert(p) { st.op = "insert"; st.payload = p; return api; },
      update(p) { st.op = "update"; st.payload = p; return api; },
      upsert(p) { st.op = "upsert"; st.payload = p; return api; },
      delete() { st.op = "delete"; return api; },
      then(res, rej) { return Promise.resolve().then(run).then(res, rej); }
    };
    return api;
  }
  return { from: from, log: log };
}
const MEMBER_TABLES = ["gate_decisions", "ai_tasks", "member_triggers", "executive_dispatches", "agent_proposals", "member_links", "model_calls", "inventory_items", "content_library"];
function readsScoped(db, userId) {
  return db.log.reads.filter(r => MEMBER_TABLES.indexOf(r.table) !== -1 && !r.filters.some(f => f[0] === "eq" && f[1] === "user_id" && f[2] === userId));
}

const GRAPH = NET.buildGraph(["content/blog-post", "seo/generate-post", "rd/demand-signals"], ["seo/generate-post"]);
class FixedDate extends Date {
  constructor(...a) { if (a.length) super(...a); else super(NOW); }
  static now() { return FixedDate._now; }
}
FixedDate._now = NOW;

/* ── lifting from server.js ───────────────────────────────────────────────── */
function braceMatch(src, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < src.length; i++) {
    const c = src[i];
    if (c === "{") depth++;
    else if (c === "}") { depth--; if (depth === 0) return i + 1; }
  }
  return -1;
}
function fnText(src, name) {
  const m = new RegExp("^(?:async )?function " + name + "\\(", "m").exec(src);
  if (!m) return null;
  return src.slice(m.index, braceMatch(src, src.indexOf(") {", m.index) + 2));
}
function lineText(src, startsWith) {
  const i = src.indexOf("\n" + startsWith);
  return i === -1 ? null : src.slice(i + 1, src.indexOf("\n", i + 1));
}
function routeText(src, sig, terminator) {
  const a = src.indexOf(sig);
  if (a === -1) return null;
  if (terminator) { const b = src.indexOf(terminator, a); return b === -1 ? null : src.slice(a, b + terminator.length); }
  const open = src.indexOf("async function (req, res, next) {", a) + "async function (req, res, next) ".length;
  const end = braceMatch(src, open);
  return src.slice(a, end) + ");";
}
const SV = FILES.server;
const LIFT = [
  fnText(SV, "watchGateResponse"), lineText(SV, "var GUIDE_GATE_REFUSALS = "), fnText(SV, "guideGateObservation"),
  fnText(SV, "recordsAskWithGateRecord"), fnText(SV, "recordsContext"), fnText(SV, "callGuideModel"),
  routeText(SV, 'app.get("/api/guide/records/answer", '), routeText(SV, 'app.post("/api/guide/records", ', "})));\n"),
  routeText(SV, 'app.get("/api/guide/suggestions", ')
];
check("lifted from server.js: the gate watcher, G25, the records recorder and context, callGuideModel and the three routes", LIFT.every(Boolean),
  LIFT.map((x, i) => x ? "" : i).join(","));
const LIFTED = new vm.Script(LIFT.join("\n\n"), { filename: "server.js (lifted)" });

function server(opts) {
  opts = opts || {};
  const db = opts.db || fakeDb(world(), opts);
  const S = { db: db, routes: {}, anthropic: [], enforce: [], ledger: [], gate: [], plan: opts.plan === undefined ? { active: true } : opts.plan,
    reply: opts.reply || "{}", refuse: opts.refuse || null, env: opts.env || { ENABLE_TRIGGERS: "true" }, order: [] };
  const app = {};
  ["get", "post", "put", "delete"].forEach(m => { app[m] = function (p) { S.routes[m.toUpperCase() + " " + p] = Array.prototype.slice.call(arguments, 1); }; });
  const pass = (req, res, next) => next();
  const ctx = {
    app: app, requireAuth: pass, recordsLimiter: pass, aiLimiter: pass, supabase: db, process: { env: S.env }, Date: FixedDate, console: { log() {}, error() {}, warn() {} },
    APP_MAP: APP_MAP, agentNetworkGraph: () => GRAPH, getUserPlan: async () => S.plan, modelCallUtcDay: () => "2026-11-01",
    guideAsk: GUIDE, Object: Object, Array: Array, JSON: JSON, String: String, Number: Number, Promise: Promise,
    require: r => r === "./lib/termaximusRecords" ? REC : realRequire(r),
    enforceDailyModelCallLimit: async (userId, route) => { S.enforce.push([userId, route]); S.order.push("limits"); if (S.refuse) throw S.refuse; },
    resolveAnthropicKey: { withSource: async () => ({ key: "test-key", source: "platform", reason: null }) },
    Anthropic: function () { this.messages = { create: async p => { S.anthropic.push(p); S.order.push("call"); return { model: "claude-haiku-4-5-20251001", usage: { input_tokens: 40, output_tokens: 9 }, content: [{ type: "text", text: S.reply }] }; } }; },
    recordModelCall: async r => { S.ledger.push(r); S.order.push("ledger"); },
    recordGateDecision: function () { S.gate.push(Array.prototype.slice.call(arguments)); },
    triggerDeps: () => ({ supabase: db, isOwner: () => false, spendLimit: () => (opts.cap === undefined ? 10 : opts.cap), spendThisMonth: async () => (opts.spendFails ? { error: "down" } : { usd: opts.spend === undefined ? 6 : opts.spend }),
      scoreFrom: () => null, blogRef: () => "x" })
  };
  vm.createContext(ctx);
  LIFTED.runInContext(ctx);
  S.call = async function (method, p, req) {
    const hs = S.routes[method + " " + p];
    const res = { statusCode: 200, body: undefined, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; return this; } };
    let i = 0, err = null;
    const next = async e => { if (e) { err = e; return; } const h = hs[i++]; if (h) await h(req, res, next); };
    await next();
    for (let k = 0; k < 5; k++) await new Promise(r => setImmediate(r));
    res.err = err;
    return res;
  };
  S.button = (q, user) => S.call("GET", "/api/guide/records/answer", { user: { id: user || ME }, query: q });
  S.ask = (body, user) => S.call("POST", "/api/guide/records", { user: { id: user || ME }, body: body });
  S.suggest = user => S.call("GET", "/api/guide/suggestions", { user: { id: user || ME }, query: {} });
  return S;
}

const SUMMARY = "When the number of your agent runs that failed in 24 hours is at least 3, you get an alert. At most once a day.";
const EXPECT = {
  blocked: ["It did not run. Autonomy (consent) stopped it.",
    "A scheduled run for the SEO agent, recorded 2026-10-31 09:00 UTC.",
    "1. Schedule pause: Pass. Passed.",
    "2. Autonomy (consent): Fail. Automatic runs are switched off for this agent.",
    "3. Entitlement (background passes): Not reached. Not reached: an earlier gate decided first, or this gate did not run.",
    CLOSING],
  ran: ["It ran. No gate in the record stopped it.",
    "A chained tool for the Content agent, recorded 2026-11-01 08:15 UTC.",
    "1. Chaining: Pass. Passed.",
    "2. Entitlement (routes): Bypass. Passed over by the owner pass.",
    CLOSING],
  member: ["It did not run. Your own gate \"Weekdays only\" stopped it after the platform's gates let it through.",
    "You asked why it ran; the record shows it did not.",
    "An approval for the Social agent, recorded 2026-10-30 22:05 UTC.",
    "1. Subscription-gated proposal actions: Pass. Passed.",
    "2. Approval (proposals): Pass. Passed.",
    "Your gate \"Weekdays only\": Fail. A gate you set for your own account stopped this.",
    CLOSING],
  fireOn: [SUMMARY,
    "The next check is at 2026-11-01 14:30 UTC.",
    "At the last check (2026-11-01 13:30 UTC) the number was 4.",
    "That crosses your line.",
    "Its cooldown runs until 2026-11-02 03:30 UTC, 13 hours 20 minutes from now; it cannot fire before then.",
    "It crossed your line, but the cooldown holds it until 2026-11-02 03:30 UTC.",
    CLOSING],
  fireFresh: [SUMMARY,
    "The next check is at 2026-11-01 14:30 UTC.",
    "At the last check (2026-11-01 13:30 UTC) the number was 4.",
    "That crosses your line.",
    "No cooldown is running: it has never reached the gates.",
    "If the number still crosses your line at that check, it fires, within your daily cap and the gates.",
    CLOSING],
  fireOff: [SUMMARY,
    "Triggers are switched off on the server right now, so \"Moonlight Stock\" will not fire. Nothing is checked until they are switched on.",
    "At the last check (2026-11-01 13:30 UTC) the number was 4.",
    "That crosses your line.",
    "Its cooldown runs until 2026-11-02 03:30 UTC, 13 hours 20 minutes from now; it cannot fire before then.",
    CLOSING],
  fireDisabled: [SUMMARY,
    "\"Quiet One\" is switched off, so it is not checked and will not fire.",
    "At the last check (2026-11-01 13:30 UTC) the number was 4.",
    "That crosses your line.",
    "Its cooldown runs until 2026-11-02 03:30 UTC, 13 hours 20 minutes from now; it cannot fire before then.",
    CLOSING],
  flow24: ["In the last 24 hours, 2 runs flowed from Executive Agent to Content Agent.",
    "The newest was at 2026-11-01 12:00 UTC.",
    "This link carries: Executive plan assignments dispatched as a chain.",
    CLOSING],
  flow7: ["In the last 7 days, 3 runs flowed from Executive Agent to Content Agent.",
    "The newest was at 2026-11-01 12:00 UTC.",
    "This link carries: Executive plan assignments dispatched as a chain.",
    CLOSING]
};
const FIRE_CLAIMS = /next check is at|it fires|cooldown holds it/;

(async function main() {
  try {
  /* ═══ A. the templates ══════════════════════════════════════════════════ */
  console.log("\n== A. the templates, word for word ==");
  {
    const b = REC.whyTemplate("why_not", DEC_BLOCKED);
    check("A1. why_not, a platform gate stopped it: the exact lines, every gate in order with its REASONS sentence", J(b.lines) === J(EXPECT.blocked) && b.title === "Why it did not run" && b.known === true, J(b.lines));
    check("A1. ... each gate line is the gate's registered name, its result and GATES.reasonFor(result, code)",
      DEC_BLOCKED.results.every((r, i) => b.lines[2 + i] === (i + 1) + ". " + GATES.GATES.find(g => g.id === r.gate).name + ": " + { pass: "Pass", fail: "Fail", not_reached: "Not reached" }[r.result] + ". " + GATES.reasonFor(r.result, r.code || null)));
    check("A1. ... links: the Why panel for that decision and every decision on HQ", J(b.links) === J([{ label: "Open the Why panel", why_decision: ID(1) }, { label: "Every decision", href: "/executive-agent.html#approvals" }]), J(b.links));
    const r = REC.whyTemplate("why_ran", DEC_RAN);
    check("A2. why_ran, it ran: the exact lines (a bypass is said as one), and the run.html link", J(r.lines) === J(EXPECT.ran) && r.title === "Why it ran" &&
      r.links.some(l => l.href === "/run.html?id=" + RUN1), J(r.lines));
    const m = REC.whyTemplate("why_ran", DEC_MEMBER);
    check("A3. a member gate stopped it, asked why it ran: the gate by its own name, and the record's answer, not the question's", J(m.lines) === J(EXPECT.member), J(m.lines));
    check("A3. ... asked why it did not run of a run that ran, the record is said",
      REC.whyTemplate("why_not", DEC_RAN).lines[1] === "You asked why it did not run; the record shows it ran.");
    const on = REC.nextFireTemplate(world().member_triggers[0], { ENABLE_TRIGGERS: "true" }, NOW);
    check("A4. next_fire, triggers on: the next :30 UTC check, the last value against the line, the cooldown left", J(on.lines) === J(EXPECT.fireOn) && on.title === "When \"Moonlight Stock\" fires next", J(on.lines));
    const fresh = REC.nextFireTemplate(world().member_triggers[1], { ENABLE_TRIGGERS: "true" }, NOW);
    check("A4. ... no cooldown running and the line crossed: it fires if the number still crosses at that check", J(fresh.lines) === J(EXPECT.fireFresh), J(fresh.lines));
    const off = REC.nextFireTemplate(world().member_triggers[0], {}, NOW);
    check("A5. next_fire, triggers OFF on the server: said plainly, and no check time or firing is claimed", J(off.lines) === J(EXPECT.fireOff) && !FIRE_CLAIMS.test(off.text), J(off.lines));
    check("A5. ... only exactly \"true\" is on (TRUE, 1 and yes are off)", ["TRUE", "1", "yes", "", " true"].every(v => !FIRE_CLAIMS.test(REC.nextFireTemplate(world().member_triggers[0], { ENABLE_TRIGGERS: v }, NOW).text)));
    const dis = REC.nextFireTemplate(world().member_triggers[2], { ENABLE_TRIGGERS: "true" }, NOW);
    check("A6. a trigger the member switched off: said, and nothing fires", J(dis.lines) === J(EXPECT.fireDisabled) && !FIRE_CLAIMS.test(dis.text), J(dis.lines));
    check("A7. the next check is :30 UTC of this hour, or of the next once :30 has passed",
      REC.nextCheckMs(Date.parse("2026-11-01T14:29:59Z")) === Date.parse("2026-11-01T14:30:00Z") && REC.nextCheckMs(Date.parse("2026-11-01T14:30:00Z")) === Date.parse("2026-11-01T15:30:00Z") &&
      REC.nextCheckMs(Date.parse("2026-11-01T23:45:00Z")) === Date.parse("2026-11-02T00:30:00Z"));
    const edge = GRAPH.edges.find(e => e.id === "executive>content");
    const fl = REC.flowTemplate(edge, [{ at: "2026-11-01T12:00:00.000Z", kind: "dispatch", task_id: RUN1 }, { at: "2026-10-31T16:00:00.000Z", kind: "dispatch", task_id: null }], true, "24h");
    check("A8. flow: the count, the newest run, what the link carries, and links to the map and the runs", J(fl.lines) === J(EXPECT.flow24) &&
      J(fl.links) === J([{ label: "Open the network map", href: "/executive-agent.html#agents" }, { label: "A run at 2026-11-01 12:00 UTC", href: "/run.html?id=" + RUN1 }]), J(fl));
    const unread = REC.flowTemplate(edge, null, false, "24h");
    check("A8. ... runs that could not be read give no count, and a switched-off link is said", unread.lines[0] === "This link's runs could not be read just now, so I will not give a count." &&
      !/\d+ runs? flowed/.test(unread.text) && unread.lines.indexOf("You have switched this link off, so no new work flows along it.") !== -1);
    const none = REC.noRecord(APP_MAP, "why did my seo not run", "no_match");
    check("A9. no record: exactly \"There is no record of that.\" and the closest real page from the app map", J(none.lines) === J([NO_RECORD]) && none.text === NO_RECORD && none.known === false &&
      none.links.length === 1 && none.links[0].href === APP_MAP.pages[GUIDE.closestPage(APP_MAP, "why did my seo not run")].p);
  }

  /* ═══ B. the buttons ═══════════════════════════════════════════════════ */
  console.log("\n== B. button questions: the template, zero model calls ==");
  const SB = server();
  {
    const q = async (intent, subject, extra) => (await SB.button(Object.assign({ intent: intent, subject: subject }, extra || {}))).body;
    const b1 = await q("why_not", "decision:" + ID(1));
    check("B1. why_not by a decision's \"Ask Termaximus\": exactly the template", b1 && J(b1.lines) === J(EXPECT.blocked) && b1.intent === "why_not" && b1.subject === "decision:" + ID(1), J(b1));
    const b2 = await q("why_ran", "decision:" + ID(2));
    check("B2. why_ran: exactly the template", b2 && J(b2.lines) === J(EXPECT.ran), J(b2 && b2.lines));
    const b3 = await q("why_ran", "decision:" + ID(3));
    check("B3. a member gate: exactly the template", b3 && J(b3.lines) === J(EXPECT.member));
    const b4 = await q("next_fire", "trigger:" + TRIG_ID);
    check("B4. next_fire by a trigger's \"Ask Termaximus\", triggers on: exactly the template", b4 && J(b4.lines) === J(EXPECT.fireOn), J(b4 && b4.lines));
    const b5 = await q("flow", "edge:executive>content");
    check("B5. flow by a map link's \"Ask Termaximus\" (24 hours by default): exactly the template, another member's run not counted", b5 && J(b5.lines) === J(EXPECT.flow24), J(b5 && b5.lines));
    const b5w = await q("flow", "edge:executive>content", { window: "7d" });
    check("B5. ... with window 7d", b5w && J(b5w.lines) === J(EXPECT.flow7), J(b5w && b5w.lines));
    check("B6. ZERO model calls, zero limit checks, zero ledger rows for every button question", SB.anthropic.length === 0 && SB.enforce.length === 0 && SB.ledger.length === 0,
      J({ calls: SB.anthropic.length, limits: SB.enforce.length, ledger: SB.ledger.length }));
    const SOFF = server({ env: {} });
    const off = (await SOFF.button({ intent: "next_fire", subject: "trigger:" + TRIG_ID })).body;
    check("B7. next_fire with ENABLE_TRIGGERS unset: said plainly, no check time, no firing", off && J(off.lines) === J(EXPECT.fireOff) && !FIRE_CLAIMS.test(off.text), J(off && off.lines));
    const o1 = await q("why_not", "decision:" + ID(5));
    const o2 = await q("next_fire", "trigger:" + TRIG_OTHER);
    check("B8. another member's decision and trigger: \"There is no record of that.\", nothing of theirs in the answer",
      o1 && o1.text === NO_RECORD && o1.reason === "not_owned" && o2 && o2.text === NO_RECORD && J(o1).indexOf("Other member gate") === -1 && J(o2).indexOf("Other Trigger Name") === -1, J([o1, o2]));
    const o3 = await q("flow", "edge:content>seo");
    check("B9. a link that is not declared: \"There is no record of that.\"", o3 && o3.text === NO_RECORD && o3.reason === "not_declared");
    const bad = await SB.button({ intent: "why_maybe", subject: "decision:" + ID(1) });
    const kind = await SB.button({ intent: "next_fire", subject: "decision:" + ID(1) });
    const extra = await SB.button({ intent: "why_not", subject: "decision:" + ID(1), prompt: "x" });
    const win = await SB.button({ intent: "flow", subject: "edge:executive>content", window: "90d" });
    check("B10. 400s: an unknown intent, a subject of the wrong kind, an unknown field, a window over 30 days",
      bad.statusCode === 400 && bad.body.field === "intent" && kind.statusCode === 400 && kind.body.field === "subject" && extra.statusCode === 400 && win.statusCode === 400 && win.body.field === "window");
    const SF = server({ fail: ["gate_decisions"] });
    const down = await SF.button({ intent: "why_not", subject: "decision:" + ID(1) });
    check("B11. a decision that cannot be read: 503 records_unreadable, never a guess", down.statusCode === 503 && down.body.reason === "records_unreadable");
    check("F1. every button read names the caller's user_id", readsScoped(SB.db, ME).length === 0, J(readsScoped(SB.db, ME)));
  }

  /* ═══ C. free text ═════════════════════════════════════════════════════ */
  console.log("\n== C. free text: the model only picks an offered id ==");
  {
    const pick = (intent, id, extra) => J(Object.assign({ intent: intent, subject_id: id }, extra || {}));
    const S1 = server({ reply: pick("why_not", "decision:" + ID(1), { answer: "Your SEO run was eaten by a dragon." }) });
    const r1 = await S1.ask({ question: "why didn't my SEO run yesterday?" });
    check("C1. a typed question answered from the record: exactly the why_not template", r1.statusCode === 200 && J(r1.body.lines) === J(EXPECT.blocked) && r1.body.known === true, J(r1.body));
    check("C1. ... the model's own words are never the answer", J(r1.body).indexOf("dragon") === -1);
    const sent = S1.anthropic[0] || {};
    const userMsg = sent.messages && sent.messages[0] && sent.messages[0].content[0].text;
    let parsed = null;
    try { parsed = JSON.parse(userMsg); } catch (e) { parsed = null; }
    check("C2. one Haiku call, 120 tokens at most, with the records persona as the whole system prompt",
      S1.anthropic.length === 1 && sent.model === "claude-haiku-4-5-20251001" && sent.max_tokens === 120 && J(sent.system) === J([{ type: "text", text: REC.RECORDS_PERSONA }]));
    check("C3. the model sees only the question, the time and the records, each record exactly { id, kind, agent, at }",
      !!parsed && J(Object.keys(parsed)) === J(["question", "now", "records"]) && parsed.records.every(x => J(Object.keys(x)) === J(["id", "kind", "agent", "at"])), userMsg && userMsg.slice(0, 300));
    const since = NOW - 7 * 86400000;
    const w = world();
    const expectIds = []
      .concat(w.gate_decisions.filter(d => d.user_id === ME && Date.parse(d.created_at) >= since).map(d => "decision:" + d.id))
      .concat(w.ai_tasks.filter(t => t.user_id === ME && Date.parse(t.created_at) >= since).map(t => "run:" + t.id))
      .concat(w.member_triggers.filter(t => t.user_id === ME).map(t => "trigger:" + t.id))
      .concat(GRAPH.edges.map(e => "edge:" + e.id)).sort();
    check("C4. the records offered are the member's own of the last 7 days (decisions, runs), their triggers and the declared links, and nothing else",
      !!parsed && J(parsed.records.map(x => x.id).sort()) === J(expectIds), parsed && J(parsed.records.map(x => x.id)));
    const whole = J(sent.system) + userMsg;
    const SECRETS = ["Moonlight Stock", "Fresh Line", "Quiet One", "ZEBRA-PROMPT", "Weekdays only", "autonomy_off", "schedule_paused", "G16", "Autonomy (consent)",
      "Other Trigger Name", "Other member gate", OTHER, ID(4), ID(5), "blocked", "5c000000"];
    check("C5. NO CONTENT: no trigger name, prompt, gate, reason, outcome, target, older record or other member reaches the model",
      SECRETS.every(s => whole.indexOf(s) === -1), SECRETS.filter(s => whole.indexOf(s) !== -1).join(","));
    check("C5. ... each kind is a closed token and each agent a roster key, a from>to pair or null",
      parsed && parsed.records.every(x => /^(decision_[a-z_]+|run|trigger|edge)$/.test(x.kind) && (x.agent === null || /^[a-z_]+(>[a-z_]+)?$/.test(x.agent))));
    const S2 = server({ reply: pick("why_not", "decision:" + ID(4)) });
    const r2 = await S2.ask({ question: "why was my seo paused in early october?" });
    check("C6. an id that was NOT offered (the member's own, older than 7 days) is refused: \"There is no record of that.\"",
      r2.body.text === NO_RECORD && r2.body.reason === "not_offered" && J(r2.body).indexOf("Schedule pause") === -1, J(r2.body));
    const S3 = server({ reply: pick("why_not", "decision:" + ID(5)) });
    const r3 = await S3.ask({ question: "why did it not run?" });
    check("C7. another member's id is refused (it is never offered)", r3.body.text === NO_RECORD && J(r3.body).indexOf("Other member gate") === -1);
    const S4 = server({ reply: pick("next_fire", "decision:" + ID(1)) });
    const r4 = await S4.ask({ question: "when does it fire?" });
    check("C8. an intent that does not fit the id's kind is refused", r4.body.text === NO_RECORD && r4.body.reason === "intent_does_not_fit");
    const S5 = server({ reply: "Your SEO run was eaten by a dragon." });
    const r5 = await S5.ask({ question: "why didn't my SEO run?" });
    check("C9. a reply that is not a pick: exactly \"There is no record of that.\" and the closest real page, none of the reply",
      J(r5.body.lines) === J([NO_RECORD]) && r5.body.links.length === 1 && r5.body.links[0].href === APP_MAP.pages[GUIDE.closestPage(APP_MAP, "why didn't my SEO run?")].p && J(r5.body).indexOf("dragon") === -1, J(r5.body));
    const S6 = server({ reply: pick(null, null) });
    const r6 = await S6.ask({ question: "what is the weather on mars?" });
    check("C10. no match: exactly \"There is no record of that.\"", r6.body.text === NO_RECORD && r6.body.known === false && S6.anthropic.length === 1);
    const S7 = server({ reply: pick("why_ran", "run:" + RUN1) });
    const r7 = await S7.ask({ question: "why did my content run go?" });
    check("C11. a run picked: the decision recorded for that run, by the same template", J(r7.body.lines) === J(EXPECT.ran), J(r7.body.lines));
    const S8 = server({ reply: pick("flow", "edge:executive>content") });
    const r8 = await S8.ask({ question: "how much work did the executive send to content this week?" });
    check("C12. a link picked: the flow template over 7 days", J(r8.body.lines) === J(EXPECT.flow7), J(r8.body.lines));
    const S9 = server({ reply: pick("next_fire", "trigger:" + TRIG_ID), env: {} });
    const r9 = await S9.ask({ question: "when will my stock trigger fire?" });
    check("C13. a trigger picked with triggers off: said plainly, nothing claimed", J(r9.body.lines) === J(EXPECT.fireOff) && !FIRE_CLAIMS.test(r9.body.text));
    const bad1 = await S6.ask({ question: "why?", context: { page: "crm.html" } });
    const bad2 = await S6.ask({ question: "   " });
    check("C14. only a question is accepted (400 for anything else or an empty one), with no model call", bad1.statusCode === 400 && bad2.statusCode === 400 && S6.anthropic.length === 1);
    check("F2. every read for a typed question names the caller's user_id",
      [S1, S2, S3, S4, S5, S6, S7, S8, S9].every(s => readsScoped(s.db, ME).length === 0), J(readsScoped(S1.db, ME)));
    check("C15. the picker refuses ids not offered and intents that do not fit, on its own",
      !REC.pickSubject({ intent: "why_not", subject_id: "decision:" + ID(9) }, [{ id: "decision:" + ID(1) }]).ok &&
      !REC.pickSubject({ intent: "flow", subject_id: "decision:" + ID(1) }, [{ id: "decision:" + ID(1) }]).ok &&
      !REC.pickSubject({ intent: "why_now", subject_id: "decision:" + ID(1) }, [{ id: "decision:" + ID(1) }]).ok &&
      REC.pickSubject({ intent: "why_not", subject_id: "decision:" + ID(1) }, [{ id: "decision:" + ID(1) }]).ok);
  }

  /* ═══ D. limits, gates, ledger ═════════════════════════════════════════ */
  console.log("\n== D. one call inside Guide mode's 30/5 a day, gated and ledgered ==");
  {
    const pick = J({ intent: "why_not", subject_id: "decision:" + ID(1) });
    const S1 = server({ reply: pick });
    await S1.ask({ question: "why did my seo not run?" });
    check("D1. the server's limits first (enforceDailyModelCallLimit, route \"guide\"), then the call, then the ledger row",
      J(S1.order) === J(["limits", "call", "ledger"]) && J(S1.enforce) === J([[ME, "guide"]]), J(S1.order));
    check("D2. the ledger row: route \"guide\", the member, the model, every token", S1.ledger.length === 1 && S1.ledger[0].route === "guide" && S1.ledger[0].userId === ME &&
      S1.ledger[0].model === "claude-haiku-4-5-20251001" && S1.ledger[0].usage.input_tokens === 40 && S1.ledger[0].usage.output_tokens === 9);
    check("D3. G25 is recorded for the route: pass", S1.gate.length === 1 && S1.gate[0][0] === ME && S1.gate[0][1] === "route_access" && S1.gate[0][2] === "route:post /api/guide/records" &&
      J(S1.gate[0][3]) === J({ G25: { result: "pass" } }), J(S1.gate));
    check("D4. Guide mode's daily allowance: 30 subscribed, 5 not", GUIDE.GUIDE_DAILY_LIMIT_SUBSCRIBED === 30 && GUIDE.GUIDE_DAILY_LIMIT_UNSUBSCRIBED === 5);
    const used = n => { const w = world(); for (let i = 0; i < n; i++) w.model_calls.push({ id: "m" + i, user_id: ME, route: "guide", created_on: "2026-11-01" }); w.model_calls.push({ id: "mx", user_id: ME, route: "oracle", created_on: "2026-11-01" }, { id: "my", user_id: OTHER, route: "guide", created_on: "2026-11-01" }); return w; };
    const S30 = server({ reply: pick, db: fakeDb(used(30)) });
    const r30 = await S30.ask({ question: "why did my seo not run?" });
    check("D5. subscribed, 30 guide answers today (an Oracle call and another member's not counted): 429 guide_daily_limit, no call",
      r30.statusCode === 429 && r30.body.reason === "guide_daily_limit" && r30.body.limit === 30 && S30.anthropic.length === 0 && S30.enforce.length === 0, J(r30.body));
    check("D5. ... G25 recorded as a fail with that code", S30.gate.length === 1 && J(S30.gate[0][3]) === J({ G25: { result: "fail", code: "guide_daily_limit" } }));
    const S29 = server({ reply: pick, db: fakeDb(used(29)) });
    const r29 = await S29.ask({ question: "why did my seo not run?" });
    check("D6. subscribed, 29 used: answered, one call, used 30 of 30", r29.statusCode === 200 && S29.anthropic.length === 1 && J(r29.body.limit) === J({ per_day: 30, subscribed: true, used: 30 }), J(r29.body.limit));
    const S5 = server({ reply: pick, db: fakeDb(used(5)), plan: { active: false } });
    const r5 = await S5.ask({ question: "why did my seo not run?" });
    check("D7. not subscribed, 5 used: 429 with the Billing link, no call", r5.statusCode === 429 && r5.body.limit === 5 && r5.body.link.href === "/billing.html" && S5.anthropic.length === 0);
    const S4 = server({ reply: pick, db: fakeDb(used(4)), plan: { active: false } });
    const r4 = await S4.ask({ question: "why did my seo not run?" });
    check("D8. not subscribed, 4 used: answered, used 5 of 5", r4.statusCode === 200 && J(r4.body.limit) === J({ per_day: 5, subscribed: false, used: 5 }) && S4.anthropic.length === 1);
    const SU = server({ reply: pick, fail: ["model_calls"] });
    const ru = await SU.ask({ question: "why did my seo not run?" });
    check("D9. the count cannot be read: 503 guide_count_unreadable, no call", ru.statusCode === 503 && ru.body.reason === "guide_count_unreadable" && SU.anthropic.length === 0);
    const refusal = Object.assign(new Error("The daily model call limit for this account was reached."), { status: 429, code: "DAILY_MODEL_CALL_LIMIT" });
    const SR = server({ reply: pick, refuse: refusal });
    const rr = await SR.ask({ question: "why did my seo not run?" });
    check("D10. the server's limits refuse: their 429 is sent as it is, no call, no ledger row", rr.statusCode === 429 && rr.body.reason === "DAILY_MODEL_CALL_LIMIT" && SR.anthropic.length === 0 && SR.ledger.length === 0, J(rr.body));
    const SX = server({ reply: pick, fail: ["member_triggers"] });
    const rx = await SX.ask({ question: "why did my seo not run?" });
    check("D11. the records cannot be read: 503 records_unreadable, and nothing is asked", rx.statusCode === 503 && rx.body.reason === "records_unreadable" && SX.anthropic.length === 0);
  }

  /* ═══ E. suggestions ═══════════════════════════════════════════════════ */
  console.log("\n== E. suggestions by rule, never saved ==");
  {
    const S1 = server();
    const r1 = (await S1.suggest()).body;
    const keys = (r1.suggestions || []).map(s => s.key);
    check("E1. all four rules hold for the member: pause after failures, proposals waiting, spend near the cap, stock at reorder",
      J(keys) === J(["pause_after_failures", "proposals_waiting", "spend_near_cap", "stock_reorder"]), J(r1));
    const by = k => (r1.suggestions || []).find(s => s.key === k) || {};
    check("E2. each shows its numbers, from the member's own rows (another member's failed runs, proposals and stock not counted)",
      by("pause_after_failures").why === "3 runs failed in the last 7 days; the SEO agent had the most (2)." &&
      by("proposals_waiting").why === "6 proposals are waiting for your approval now, more than 5." &&
      by("spend_near_cap").why === "This month's AI spend is 60% of your monthly cap, and it is only day 1 of the month (UTC)." &&
      by("stock_reorder").why === "1 item is at or below the reorder point now." &&
      J(by("pause_after_failures").numbers) === J({ failed_runs_7d: 3, most_agent: "seo", most_count: 2 }), J((r1.suggestions || []).map(s => s.why)));
    check("E3. the failures rule offers a trigger that pauses the agent with the most failures",
      J(by("pause_after_failures").body) === J({ name: "Pause after failures", metric: "tasks_failed", comparator: "gte", threshold: 3, window: "24h", cooldown_hours: 24, action: { kind: "pause_schedule", agent: "seo" }, enabled: true }));
    check("E4. the others are the ready-made templates, unchanged", ["proposals_waiting", "spend_near_cap", "stock_reorder"].every(k => J(by(k).body) === J(T.TEMPLATES.find(t => t.key === k).body)));
    check("E5. every offered body is a trigger POST /api/triggers would accept, and its summary is the trigger's own",
      (r1.suggestions || []).every(s => { const v = T.validateTrigger(s.body, null, { owner: false }); return v.ok && s.summary === T.summarize(v.value); }));
    check("E6. NOTHING IS WRITTEN: no insert, update, upsert or delete anywhere", S1.db.log.writes.length === 0, J(S1.db.log.writes));
    check("E7. the rules are named, and Not now lasts 30 days", (r1.rules || []).length === 4 && r1.not_now_days === 30);
    const w2 = world();
    w2.ai_tasks = w2.ai_tasks.filter(t => t.id !== "f1000000-0000-4000-8000-000000000003");
    w2.agent_proposals = w2.agent_proposals.slice(1);
    w2.inventory_items = w2.inventory_items.filter(i => i.user_id !== ME);
    const S2 = server({ db: fakeDb(w2), spend: 5.9 });
    const r2 = (await S2.suggest()).body;
    check("E8. just under every line (2 failed runs, 5 waiting, 59%, no item at reorder): nothing is suggested", (r2.suggestions || []).length === 0, J(r2.suggestions));
    FixedDate._now = Date.parse("2026-11-20T10:00:00.000Z");
    const S3 = server({ spend: 9 });
    const r3 = (await S3.suggest()).body;
    FixedDate._now = NOW;
    check("E9. spend at 90% on the 20th: not suggested (the rule is before the 20th); the others still are",
      (r3.suggestions || []).every(s => s.key !== "spend_near_cap") && (r3.suggestions || []).length >= 1, J((r3.suggestions || []).map(s => s.key)));
    const w4 = world();
    w4.member_triggers.push(trig("c1000000-0000-4000-8000-000000000009", ME, "Proposals waiting"));
    const S4 = server({ db: fakeDb(w4) });
    const r4 = (await S4.suggest()).body;
    check("E10. a trigger the member already holds by that name is not offered again", (r4.suggestions || []).every(s => s.key !== "proposals_waiting") && (r4.suggestions || []).length === 3);
    const S5 = server({ fail: ["agent_proposals"], spendFails: true });
    const r5 = (await S5.suggest()).body;
    check("E11. a number that cannot be read is named, never guessed, and the rest still stand",
      (r5.suggestions || []).every(s => s.key !== "proposals_waiting" && s.key !== "spend_near_cap") && (r5.unreadable || []).length === 2 &&
      (r5.unreadable || []).some(u => u.reason === "Your pending proposals could not be read just now.") && (r5.unreadable || []).some(u => u.reason === "Your spend could not be read just now."), J(r5));
    check("F3. every suggestion read names the caller's user_id", [S1, S2, S3, S4, S5].every(s => readsScoped(s.db, ME).length === 0), J(readsScoped(S1.db, ME)));
    check("E12. no model call for suggestions", [S1, S2, S3, S4, S5].every(s => s.anthropic.length === 0 && s.enforce.length === 0));
  }

  /* ═══ U. the pages ═════════════════════════════════════════════════════ */
  console.log("\n== U. the Guide tab, the buttons and HQ, in jsdom ==");
  await ui();

  /* ═══ W. wiring ════════════════════════════════════════════════════════ */
  console.log("\n== W. the wiring ==");
  {
    check("W1. GET /api/guide/records/answer: login and its own rate limit, no subscription needed, no aiLimiter, no model",
      SV.indexOf('app.get("/api/guide/records/answer", requireAuth, recordsLimiter, async function (req, res, next) {') !== -1);
    check("W2. POST /api/guide/records: login, aiLimiter, G25 recorded, and the guide's own callGuideModel and UTC day",
      /app\.post\("\/api\/guide\/records", requireAuth, aiLimiter, recordsAskWithGateRecord\(require\("\.\/lib\/termaximusRecords"\)\.createRecordsAskHandler\(\{[\s\S]*?callModel: callGuideModel,[\s\S]*?\}\)\)\);/.test(SV));
    check("W3. GET /api/guide/suggestions: login and the rate limit; it writes nothing", SV.indexOf('app.get("/api/guide/suggestions", requireAuth, recordsLimiter, async function (req, res, next) {') !== -1 &&
      !/\.(insert|update|upsert|delete)\(/.test(routeText(SV, 'app.get("/api/guide/suggestions", ') || "x.insert("));
    const before = execFileSync("git", ["show", PRE_RECORDS + ":server.js"], { cwd: REPO, maxBuffer: 64 << 20 }).toString("utf8").replace(/\r\n/g, "\n");
    check("W4. callGuideModel and POST /api/guide/ask are byte-identical to " + PRE_RECORDS, fnText(before, "callGuideModel") === fnText(SV, "callGuideModel") &&
      routeText(before, 'app.post("/api/guide/ask", ', "})));\n") === routeText(SV, 'app.post("/api/guide/ask", ', "})));\n"));
    check("W5. the records lib makes no model call and touches no network itself", !/messages\.create|Anthropic|fetch\(|callAnthropicText/.test(FILES.lib));
    check("W6. the guide tip names \"Ask Termaximus\" and checkGuideTipClaims proves it (row executive 20)",
      FILES.guide.indexOf("\\\"Ask Termaximus\\\" by a decision, trigger or link answers from its record alone.") !== -1 && FILES.tipClaims.indexOf('["executive 20", exTips,') !== -1);
  }

  /* ═══ S. no emoji ══════════════════════════════════════════════════════ */
  console.log("\n== S. no emoji ==");
  {
    const BS = String.fromCharCode(92);
    const ESCAPED = ["&#" + "x1F", BS + "u{1F", BS + "uD83", BS + "uFE0F"];
    function hasEmoji(text) {
      for (const ch of text) {
        const cp = ch.codePointAt(0);
        if ((cp >= 0x1F000 && cp <= 0x1FAFF) || (cp >= 0x2600 && cp <= 0x27BF) || cp === 0xFE0F || cp === 0x200D) return true;
      }
      return ESCAPED.some(e => text.indexOf(e) !== -1);
    }
    const added = (file, now) => {
      const old = new Set(execFileSync("git", ["show", PRE_FRONTEND + ":" + file], { cwd: FRONTEND, maxBuffer: 16 << 20 }).toString("utf8").replace(/\r\n/g, "\n").split("\n"));
      return now.split("\n").filter(l => !old.has(l)).join("\n");
    };
    const scanned = [["lib/termaximusRecords.js", FILES.lib],
      ["termaximus-presence.js (added lines)", added("scripts/termaximus-presence.js", FILES.presence)], ["bf-why.js (added lines)", added("scripts/bf-why.js", FILES.why)],
      ["bf-triggers.js (added lines)", added("scripts/bf-triggers.js", FILES.triggers)], ["bf-network.js (added lines)", added("scripts/bf-network.js", FILES.network)],
      ["executive-agent.html (added lines)", added("executive-agent.html", FILES.execHtml)], ["termaximus-guide.js (added lines)", added("scripts/termaximus-guide.js", FILES.guide)],
      ["bf-session.js (added lines)", added("scripts/bf-session.js", FILES.session)], ["this check", fs.readFileSync(__filename, "utf8")]];
    check("S0. the added lines were found", /TermaximusRecords/.test(scanned[1][1]) && /data-bf-why-ask/.test(scanned[2][1]) && /deckSuggestions/.test(scanned[5][1]) && /Ask Termaximus/.test(scanned[6][1]));
    const withEmoji = scanned.filter(s => hasEmoji(s[1])).map(s => s[0]);
    check("S1. no emoji in any new or edited file (by code point and by escape)", withEmoji.length === 0, withEmoji.join(", "));
    check("S2. nothing reached the network or an unhandled rejection", UNHANDLED.length === 0, UNHANDLED.map(e => e && e.message).join(" | "));
  }
  } catch (e) {
    failures++;
    console.log("    FAIL  the check threw: " + (e && e.stack || e));
  }
  console.log("\n" + (failures === 0 ? "ALL CHECKS PASSED — " + passes + " passed, 0 failed" : failures + " FAILED, " + passes + " passed"));
  process.exit(failures === 0 ? 0 : 1);
})();

/* ── the pages ────────────────────────────────────────────────────────────── */
async function ui() {
  const { JSDOM } = realRequire("jsdom");
  const API = "https://dynamic-prosperity-production-5382.up.railway.app";
  const P = FILES.presence;
  const START = "  /* ── Guide mode ─";
  const END = "    tmxSuggestionsInto(list);\n  })();\n";
  const a = P.indexOf(START), b = P.indexOf(END);
  check("U0. termaximus-presence.js holds the Guide block and, after it, the records block", a !== -1 && b > a && P.indexOf("window.TermaximusRecords = {") > a);
  if (a === -1 || b < a) return;
  const block = P.slice(a, b + END.length);
  const SUGG = [
    { key: "pause_after_failures", kind: "trigger", title: "Pause after failures", why: "3 runs failed in the last 7 days; the SEO agent had the most (2).",
      numbers: {}, body: { name: "Pause after failures", metric: "tasks_failed", comparator: "gte", threshold: 3, window: "24h", cooldown_hours: 24, action: { kind: "pause_schedule", agent: "seo" }, enabled: true }, summary: "When it fails, it pauses." },
    { key: "proposals_waiting", kind: "trigger", title: "Proposals waiting", why: "6 proposals are waiting for your approval now, more than 5.", numbers: {}, body: { name: "Proposals waiting" }, summary: "When proposals wait, you get an alert." }
  ];
  function page(opts) {
    opts = opts || {};
    const html = '<!doctype html><html><head></head><body>' + (opts.hq ? '<div id="deckSuggestions" role="region" aria-label="Suggestions"></div>' : "") +
      '<div id="tmx-chat"><div id="tmx-chat-msgs"></div><input id="tmx-chat-input"><span id="tmx-chat-title-name"></span></div></body></html>';
    const dom = new JSDOM(html, { url: "https://bizforceai.com/executive-agent.html", runScripts: "outside-only", pretendToBeVisual: true });
    const w = dom.window;
    if (opts.token !== false) w.localStorage.setItem("bf_token", "tok");
    if (opts.notNow) w.localStorage.setItem("bf_tmx_not_now", J(opts.notNow));
    w.Element.prototype.scrollIntoView = function () {};
    w.Element.prototype.getBoundingClientRect = function () { return { width: 10, height: 10, left: 0, top: 0, right: 10, bottom: 10 }; };
    const sent = [];
    w.fetch = function (url, init) {
      sent.push({ url: url, method: (init && init.method) || "GET", body: init && init.body });
      let body = {};
      if (url.indexOf("/api/guide/records/answer") !== -1) body = REC.whyTemplate("why_not", DEC_BLOCKED);
      else if (url.indexOf("/api/guide/records") !== -1) body = REC.noRecord(APP_MAP, "x", "no_match");
      else if (url.indexOf("/api/guide/suggestions") !== -1) body = { suggestions: SUGG, unreadable: [{ rule: "x", reason: "Your spend could not be read just now." }], rules: [], not_now_days: 30 };
      else if (url.indexOf("/api/triggers") !== -1) body = { trigger: { id: "t" } };
      const p = Promise.resolve({ ok: true, status: url.indexOf("/api/triggers") !== -1 ? 201 : 200, json: () => Promise.resolve(JSON.parse(J(body))) });
      p.catch(() => {});
      return p;
    };
    w.__opened = 0;
    w.eval("(function () {\n  var chat = document.getElementById('tmx-chat');\n  var chatMsgs = document.getElementById('tmx-chat-msgs');\n" +
      "  var chatInput = document.getElementById('tmx-chat-input');\n  var chatTitleName = document.getElementById('tmx-chat-title-name');\n  var _chatOpen = false;\n" +
      "  function openChat() { _chatOpen = true; window.__opened++; }\n" + block + "\n})();");
    return { w: w, d: w.document, sent: sent };
  }
  const flush = async () => { for (let i = 0; i < 8; i++) await new Promise(r => setTimeout(r, 0)); };

  const P1 = page();
  const d = P1.d;
  check("U1. the Guide tab has the \"Ask about your records\" hint, a labelled box (500 characters) and \"Ask\" and \"Suggestions\"",
    /^Ask about your records: why something ran or did not, when a trigger fires next, how work flows between agents\.$/.test(d.getElementById("tmx-records-hint").textContent) &&
    !!d.querySelector('label[for="tmx-records-input"]') && d.getElementById("tmx-records-input").getAttribute("maxlength") === "500" &&
    d.getElementById("tmx-records-send").textContent === "Ask" && d.getElementById("tmx-suggest-btn").textContent === "Suggestions" &&
    d.getElementById("tmx-guide").contains(d.getElementById("tmx-records-foot")));
  check("U1. ... nothing is fetched until asked (no HQ region on this page)", P1.sent.length === 0);
  const whyCalls = [];
  P1.w.BFWhy = { openById: id => whyCalls.push(id) };
  P1.w.TermaximusRecords.ask("why_not", "decision:" + ID(1));
  await flush();
  check("U2. a button question opens the mist on the Guide tab and GETs the answer by intent and subject, nothing else",
    P1.w.__opened === 1 && d.getElementById("tmx-tab-guide").getAttribute("aria-selected") === "true" && P1.sent.length === 1 && P1.sent[0].method === "GET" &&
    P1.sent[0].url === API + "/api/guide/records/answer?intent=why_not&subject=decision%3A" + ID(1), J(P1.sent));
  const ans = d.getElementById("tmx-guide-answer");
  const lis = [...ans.querySelectorAll("ol li")].map(x => x.textContent);
  const ps = [...ans.querySelectorAll("p")].map(x => x.textContent);
  check("U3. the answer is the template's lines: the title, the gates in order as a list, the other lines as they are",
    ans.querySelector("strong").textContent === "Why it did not run" && J(lis) === J(EXPECT.blocked.slice(2, 5).map(l => l.replace(/^\d+\. /, ""))) &&
    ps.indexOf(EXPECT.blocked[0]) !== -1 && ps.indexOf(EXPECT.blocked[1]) !== -1 && ps.indexOf(CLOSING) !== -1, J({ lis: lis, ps: ps }));
  const whyBtn = [...ans.querySelectorAll("button")].find(x => x.textContent === "Open the Why panel");
  if (whyBtn) whyBtn.click();
  check("U4. its links: \"Open the Why panel\" opens that decision in the Why panel; \"Every decision\" is a link to HQ's Approvals",
    !!whyBtn && J(whyCalls) === J([ID(1)]) && !!ans.querySelector('a[href="/executive-agent.html#approvals"]'));
  check("U4. ... the answer area is a polite live region", ans.getAttribute("aria-live") === "polite");
  P1.w.TermaximusRecords.render({ title: "<img src=x onerror=alert(1)>", lines: ["<b>bold</b>", "1. <i>gate</i>"], links: [{ label: "<u>x</u>", href: "/x.html" }] });
  check("U5. everything is shown as text, never markup", ans.querySelectorAll("img,b,i,u").length === 0 && ans.textContent.indexOf("<b>bold</b>") !== -1);
  d.getElementById("tmx-records-input").value = "  why didn't my   SEO run?  ";
  d.getElementById("tmx-records-foot").dispatchEvent(new P1.w.Event("submit", { cancelable: true }));
  await flush();
  const post = P1.sent.find(s => s.method === "POST");
  check("U6. a typed question POSTs only { question }, trimmed, to /api/guide/records", !!post && post.url === API + "/api/guide/records" && post.body === J({ question: "why didn't my SEO run?" }), J(post));
  check("U6. ... and shows \"There is no record of that.\" and the closest real page when the server says so",
    [...ans.querySelectorAll("p")].some(x => x.textContent === NO_RECORD) && !!ans.querySelector("a[href]"));

  const P2 = page();
  P2.d.getElementById("tmx-suggest-btn").click();
  await flush();
  const items = [...P2.d.querySelectorAll("[data-tmx-suggest]")];
  check("U7. \"Suggestions\" GETs /api/guide/suggestions and lists each with its title, \"Why:\" and its numbers, and its summary",
    P2.sent.length === 1 && P2.sent[0].url === API + "/api/guide/suggestions" && items.length === 2 && items[0].querySelector("strong").textContent === "Pause after failures" &&
    items[0].textContent.indexOf("Why: 3 runs failed in the last 7 days; the SEO agent had the most (2).") !== -1 && items[0].textContent.indexOf("When it fails, it pauses.") !== -1);
  check("U7. ... with the fixed note that nothing is saved unless Add it is pressed, and a read that failed named",
    P2.d.getElementById("tmx-guide-answer").textContent.indexOf("Nothing is saved unless you press Add it.") !== -1 && P2.d.getElementById("tmx-guide-answer").textContent.indexOf("Your spend could not be read just now.") !== -1);
  check("U8. NOTHING SAVED on showing: no POST to /api/triggers", P2.sent.every(s => s.method === "GET"));
  const addBtn = [...items[0].querySelectorAll("button")].find(x => x.textContent === "Add it");
  check("U8. ... each has \"Add it\" and \"Not now\", each named for its suggestion", !!addBtn && addBtn.getAttribute("aria-label") === "Add it: Pause after failures" &&
    [...items[0].querySelectorAll("button")].some(x => x.textContent === "Not now" && x.getAttribute("aria-label") === "Not now: Pause after failures"));
  addBtn.click();
  await flush();
  const saved = P2.sent.filter(s => s.method === "POST");
  check("U9. \"Add it\" POSTs exactly the offered body to /api/triggers, once, and says so", saved.length === 1 && saved[0].url === API + "/api/triggers" && saved[0].body === J(SUGG[0].body) &&
    items[0].textContent.indexOf("Added to your triggers.") !== -1, J(saved));
  const t0 = Date.now();
  [...items[1].querySelectorAll("button")].find(x => x.textContent === "Not now").click();
  const t1 = Date.now();
  let notNow = {};
  try { notNow = JSON.parse(P2.w.localStorage.getItem("bf_tmx_not_now")); } catch (e) { notNow = {}; }
  const DAYS30 = 30 * 24 * 3600 * 1000;
  check("U10. \"Not now\" hides it and keeps it hidden on this device for 30 days (bf_tmx_not_now), saving nothing on the server",
    !P2.d.querySelector('[data-tmx-suggest="proposals_waiting"]') && notNow.proposals_waiting >= t0 + DAYS30 && notNow.proposals_waiting <= t1 + DAYS30 &&
    P2.sent.filter(s => s.method === "POST").length === 1, J(notNow));
  P2.d.getElementById("tmx-suggest-btn").click();
  await flush();
  check("U10. ... the next time, it stays hidden", !P2.d.querySelector('[data-tmx-suggest="proposals_waiting"]') && !!P2.d.querySelector('[data-tmx-suggest="pause_after_failures"]'));
  const P3 = page({ notNow: { proposals_waiting: Date.now() - 1000 } });
  P3.d.getElementById("tmx-suggest-btn").click();
  await flush();
  check("U11. once the 30 days are over, it is offered again", !!P3.d.querySelector('[data-tmx-suggest="proposals_waiting"]'));
  const P4 = page({ hq: true });
  await flush();
  check("U12. HQ shows the suggestions in its own region on load, signed in", P4.sent.length === 1 && P4.sent[0].url === API + "/api/guide/suggestions" &&
    P4.d.querySelector("#deckSuggestions h3").textContent === "Suggestions from Termaximus" && P4.d.querySelectorAll("#deckSuggestionsList [data-tmx-suggest]").length === 2);
  const P5 = page({ hq: true, token: false });
  await flush();
  check("U12. ... and asks nothing when signed out", P5.sent.length === 0);

  // "Ask Termaximus" in the Why panel.
  const W = new JSDOM('<!doctype html><html><body></body></html>', { url: "https://bizforceai.com/executive-agent.html", runScripts: "outside-only" }).window;
  W.fetch = () => { const p = Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({}) }); p.catch(() => {}); return p; };
  W.eval(FILES.why);
  const shown = GATES.explain(DEC_BLOCKED);
  const without = W.BFWhy.decisionHtml(shown);
  const asked = [];
  W.TermaximusRecords = { ask: (i, s) => asked.push([i, s]) };
  const withIt = W.BFWhy.decisionHtml(shown);
  const box = W.document.createElement("div");
  box.innerHTML = withIt;
  W.document.body.appendChild(box);
  const askBtn = box.querySelector("[data-bf-why-ask]");
  if (askBtn) askBtn.click();
  const ranBox = W.document.createElement("div");
  ranBox.innerHTML = W.BFWhy.decisionHtml(GATES.explain(DEC_RAN));
  W.document.body.appendChild(ranBox);
  const askRan = ranBox.querySelector("[data-bf-why-ask]");
  if (askRan) askRan.click();
  check("U13. the Why panel: \"Ask Termaximus\" on each decision asks why_not of a blocked one and why_ran of one that ran, by its id",
    !!askBtn && askBtn.textContent === "Ask Termaximus" && askBtn.getAttribute("aria-label") === "Ask Termaximus about this decision" &&
    J(asked) === J([["why_not", "decision:" + ID(1)], ["why_ran", "decision:" + ID(2)]]), J(asked));
  check("U13. ... and without Termaximus on the page the decision is drawn exactly as before", without.indexOf("Ask Termaximus") === -1 &&
    withIt.replace(/<p><button type="button" class="bf-why-link" data-bf-why-ask="[^"]*" data-bf-why-intent="why_not" aria-label="Ask Termaximus about this decision">Ask Termaximus<\/button><\/p>/, "") === without);
  check("U14. the trigger list: \"Ask Termaximus\" asks next_fire of that trigger by its id",
    FILES.triggers.indexOf('(window.TermaximusRecords ? \'<button type="button" class="hq-btn" data-trg-ask="\' + esc(t.id) + \'"') !== -1 &&
    FILES.triggers.indexOf('if (ask && window.TermaximusRecords) { window.TermaximusRecords.ask("next_fire", "trigger:" + ask.getAttribute("data-trg-ask")); return; }') !== -1);
  check("U15. the network map: \"Ask Termaximus\" on the chosen link asks flow of that edge in the window shown",
    FILES.network.indexOf("toggleHtml(e) + askHtml(e) + body") !== -1 &&
    FILES.network.indexOf('if (ak && window.TermaximusRecords) { window.TermaximusRecords.ask("flow", "edge:" + ak.getAttribute("data-bfn-ask"), S.window); return true; }') !== -1);
  check("U16. HQ has the suggestions region on the Command tab and loads termaximus-presence.js",
    FILES.execHtml.indexOf('<div id="deckSuggestions" role="region" aria-label="Suggestions"></div>') !== -1 &&
    FILES.execHtml.indexOf('id="deckSuggestions"') > FILES.execHtml.indexOf('id="deckPanel-command"') && FILES.execHtml.indexOf('id="deckSuggestions"') < FILES.execHtml.indexOf('id="deckPanel-plans"') &&
    FILES.execHtml.indexOf('<script src="/scripts/termaximus-presence.js"></script>') !== -1);
  check("U17. bf_tmx_not_now is kept at sign-out on purpose (named in bf-session.js and checkOfflineMode's KEPT), never cleared as member data",
    /bf_tmx_not_now \(which of Termaximus's suggestions were set aside/.test(FILES.session) && !/"bf_tmx_not_now"/.test(FILES.session.slice(FILES.session.indexOf("var PER_USER_LOCAL"), FILES.session.indexOf("var OFFLINE_DB"))) &&
    /bf_tmx_not_now: "/.test(FILES.offline));
}
