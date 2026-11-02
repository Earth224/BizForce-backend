/* ═══════════════════════════════════════════════════════════════════════════
   checkTriggers.js — member triggers (intelligence layer B4 and B5), and the
   malformed-language guard in bf-why.js (the follow-up from 737c871)

   WHAT THIS PROVES

     A. THE METRICS, against fixtures. Each of the nine numbers is read for two
        members from an in-memory database holding both members' rows, and is
        exactly the hand-counted value for each. Every read of a member table
        names that member's user_id; the arrivals read asks only for the
        member's own tracked refs; the lead read happens only for the owner.
     B. THE COMPARATORS at their boundaries (threshold - 1, threshold,
        threshold + 1 for lt, lte, gt, gte), and drop_pct (no judgement under
        10 before; 50% fires at 50 and not at 51).
     C. THE CLOSED SCHEMA refuses unknown fields, metrics, comparators, windows,
        actions and action fields, an out-of-range or fractional threshold, a
        cooldown outside 6 to 168, a name with markup, a metric agent where none
        belongs or missing where one does, and lead scores for anyone but the
        owner.
     D. THE TEMPLATES: six, each valid for a member, the first one saying "When
        stock of any item drops to its reorder point, the Store agent drafts a
        reorder. At most once a day."
     E. THE PASS (lib/triggerRunner.js with the server's own recordGateDecision):
        E1 ENABLE_TRIGGERS exactly "true", or nothing is read at all;
        E2 the hourly claim (hourly_triggers_h<hh>) stops a second tick firing
           the same hour, and the next hour claims again;
        E3 every firing goes through the gate evaluator: one gate_decisions row,
           action trigger_fire, target trigger:<id>, G13 then G9, and the firing
           row carries that row's id;
        E4 the cooldown: a trigger still crossing the next hour does not fire,
           and fires again once its cooldown has passed;
        E5 the daily cap (TRIGGERS_DAILY_FIRINGS): firings stop at the cap, a
           skipped trigger is recorded once a day with no decision;
        E6 the spend ceiling refuses: the firing is blocked_by_gate, its
           decision says G9 failed, nothing acts; not entitled stops at G13;
        E7 a drafted task is a saved prompt, never a publish or a send: no
           proposal, post, email or outreach row is written, and the drafted text
           is held by the server's own high-risk approval pattern when run;
        E8 pause_schedule pauses that agent's schedules only, the member's only.
     F. THE PREVIEW writes nothing (route and runner) and lists the dates the
        trigger would have fired in the last 30 days.
     G. THE ROUTES: mounted with requireAuth, writes and the preview with
        requireActiveSubscription, all with the limiter; the closed schema at
        the route; a member's own rows only.
     H. EXPORT, DELETION, BACKUP and MIGRATION 160.
     U. THE UI in jsdom: the six templates (one press to create), the builder
        and its summary (equal to lib/triggers.js on 600 random triggers), the
        preview, the list with switches, last value and last fired, the firings
        with "Why?", the empty-state copy and the server-off note.
     Z. PART 0: bf-why.js treats a malformed /api/member-gates/language answer
        (missing fields, scopes, comparators or limits) as no language: the
        Decisions list still renders, the builder says it could not load, and
        nothing throws.
     S. No emoji in any new file.

   MUTATIONS — MUTATE=<name> applies one in memory; MUTATE=all runs each:
     cooldown-ignored         plan() skips the cooldown                 → E4
     daily-cap-ignored        plan() skips the daily cap                → E5
     preview-writes           the preview writes last_value             → F
     double-fire              the claim ignores the day already claimed → E2
     publish-bypasses-approval  the draft no longer asks for approval   → E7
     firing-not-recorded      the gated firing row is not written       → E3
     other-member-read        the failed-runs read drops its user_id    → A
     malformed-language-guard-removed  bf-why trusts any language       → Z
     decision-id-dropped      the firing row loses its decision id      → E3
     why-link-missing         the UI firing row has no "Why?"           → U
   ═══════════════════════════════════════════════════════════════════════════ */
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const Module = require("module");
const MUT = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const read = p => fs.readFileSync(path.join(REPO, p), "utf8").replace(/\r\n/g, "\n");
const readFe = p => fs.readFileSync(path.join(FRONTEND, p), "utf8").replace(/\r\n/g, "\n");

const MUTATIONS = {
  "cooldown-ignored": ["triggers",
    "  if (!cooledDown(trigger, nowMs)) return \"cooldown\";\n", ""],
  "daily-cap-ignored": ["triggers",
    "  if (firedToday >= cap) return \"daily_cap\";\n", ""],
  "preview-writes": ["runner",
    "  var now = await metricValue(deps, userId, t, nowMs);\n  var out = {",
    "  var now = await metricValue(deps, userId, t, nowMs);\n  await deps.supabase.from(\"member_triggers\").update({ last_value: now.value }).eq(\"user_id\", userId);\n  var out = {"],
  "double-fire": ["runner",
    "    .eq(\"job_name\", name).or(\"last_run_on.is.null,last_run_on.neq.\" + today).select(\"job_name\");",
    "    .eq(\"job_name\", name).select(\"job_name\");"],
  "publish-bypasses-approval": ["triggers",
    "\"Draft \" + m.draft + \" for me to review. Prepare it for my approval; do not publish or send anything.\";",
    "\"Draft \" + m.draft + \" for me to review.\";"],
  "firing-not-recorded": ["runner",
    "      var firingOk = await insertFiring(db, { id: deps.uuid(), user_id: userId, trigger_id: t.id, metric_value: v.value, threshold: t.threshold,\n        fired_at: now.toISOString(), outcome: outcome, action_ref: ref, gate_decision_id: gateDecisionId });",
    "      var firingOk = true;"],
  "other-member-read": ["runner",
    "        .eq(\"user_id\", userId).eq(\"status\", \"failed\").gt(\"created_at\", iso(nowMs - w)), \"failed runs\");",
    "        .eq(\"status\", \"failed\").gt(\"created_at\", iso(nowMs - w)), \"failed runs\");"],
  "malformed-language-guard-removed": ["why",
    "        return whole ? b : null;", "        return b;"],
  "decision-id-dropped": ["runner",
    "outcome: outcome, action_ref: ref, gate_decision_id: gateDecisionId });", "outcome: outcome, action_ref: ref, gate_decision_id: null });"],
  "why-link-missing": ["ui",
    "          (f.gate_decision_id\n            ?", "          (false\n            ?"]
};
const NAMES = Object.keys(MUTATIONS);
const MUTATE = process.env.MUTATE || "";
if (MUTATE === "all") MUT.runAllMutations(__filename, NAMES);
if (MUTATE && NAMES.indexOf(MUTATE) === -1) { console.error("Unknown MUTATE=" + MUTATE + ". Known: " + NAMES.join(", ")); process.exit(2); }

let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}
const UNHANDLED = [];
process.on("unhandledRejection", function (e) { UNHANDLED.push(e); });
process.on("uncaughtException", function (e) { UNHANDLED.push(e); });

const FILES = {
  triggers: read("lib/triggers.js"),
  runner: read("lib/triggerRunner.js"),
  server: read("server.js"),
  migration: read("supabase/migrations/160_member_triggers.sql"),
  yourData: read("lib/yourData.js"),
  backup: read("lib/backup.js"),
  readme: read("README.md"),
  why: readFe("scripts/bf-why.js"),
  ui: readFe("scripts/bf-triggers.js"),
  execHtml: readFe("executive-agent.html"),
  profile: readFe("scripts/agent-profile.js")
};
if (MUTATE) {
  const m = MUTATIONS[MUTATE];
  FILES[m[0]] = MUT.replaceOnce(FILES[m[0]], m[1], m[2], MUTATE);
  console.log("\n!! MUTATION: " + MUTATE);
}

const J = JSON.stringify;
const realRequire = Module.createRequire(path.join(REPO, "server.js"));
function compile(src, file, map) {
  const m = { exports: {} };
  const fn = vm.compileFunction(src, ["module", "exports", "require"], { filename: file });
  fn(m, m.exports, function (r) { return Object.prototype.hasOwnProperty.call(map, r) ? map[r] : realRequire(r.replace(/^\.\//, "./lib/")); });
  return m.exports;
}
const GATES = realRequire("./lib/gates");
const RULES = realRequire("./lib/gateRules");
const LEARN = realRequire("./lib/learningLoop");
const T = compile(FILES.triggers, "lib/triggers.js", { "./gateRules": RULES });
const R = compile(FILES.runner, "lib/triggerRunner.js", { "./triggers": T, "./gates": GATES });

function UUID(n) { const h = String(n).padStart(12, "0"); return "00000000-0000-4000-8000-" + h; }
const A = UUID(1), B = UUID(2), OWNER = UUID(9);

/* ── an in-memory database: filters, counts, pages, unique keys, a log ───── */
function makeDb(seed) {
  const tables = JSON.parse(J(seed || {}));
  const log = [];
  let auto = 5000;
  const fail = {};
  function cmp(a, b) {
    if (typeof a === "number" && typeof b === "number") return a < b ? -1 : a > b ? 1 : 0;
    if (typeof a === "number" && typeof b === "string" && b !== "" && isFinite(Number(b))) return cmp(a, Number(b));
    const x = String(a), y = String(b); return x < y ? -1 : x > y ? 1 : 0;
  }
  function matches(r, f) {
    const [k, c, v] = f;
    const val = r[c];
    if (k === "eq") return val === v || (val != null && v != null && String(val) === String(v));
    if (k === "neq") return !(val === v || String(val) === String(v));
    if (k === "gt") return val != null && cmp(val, v) > 0;
    if (k === "gte") return val != null && cmp(val, v) >= 0;
    if (k === "lt") return val != null && cmp(val, v) < 0;
    if (k === "lte") return val != null && cmp(val, v) <= 0;
    if (k === "in") return v.some(x => String(x) === String(val));
    if (k === "notnull") return val !== null && val !== undefined;
    if (k === "or") return v.some(g => matches(r, g));
    return false;
  }
  function uniqueClash(t, row) {
    const rows = tables[t] || [];
    if (t === "job_runs") return rows.some(r => r.job_name === row.job_name);
    if (t === "saved_prompts") return rows.some(r => r.user_id === row.user_id && String(r.name).trim().toLowerCase() === String(row.name).trim().toLowerCase());
    if (t === "member_triggers") return rows.some(r => r.user_id === row.user_id && String(r.name).trim().toLowerCase() === String(row.name).trim().toLowerCase());
    return false;
  }
  class Q {
    constructor(t) { this.t = t; this.op = "select"; this.f = []; this.opts = {}; this.payload = null; this.ord = null; this.rng = null; this.lim = null; this.mode = null; this.sel = false; }
    select(cols, opts) { if (this.op === "select") this.opts = opts || {}; else this.sel = true; return this; }
    insert(p) { this.op = "insert"; this.payload = p; return this; }
    upsert(p) { this.op = "upsert"; this.payload = p; return this; }
    update(p) { this.op = "update"; this.payload = p; return this; }
    delete() { this.op = "delete"; return this; }
    eq(c, v) { this.f.push(["eq", c, v]); return this; }
    neq(c, v) { this.f.push(["neq", c, v]); return this; }
    gt(c, v) { this.f.push(["gt", c, v]); return this; }
    gte(c, v) { this.f.push(["gte", c, v]); return this; }
    lt(c, v) { this.f.push(["lt", c, v]); return this; }
    lte(c, v) { this.f.push(["lte", c, v]); return this; }
    in(c, v) { this.f.push(["in", c, v.slice()]); return this; }
    not(c, op, v) { if (op === "is" && v === null) this.f.push(["notnull", c]); return this; }
    or(s) {
      const parts = String(s).split(",").map(p => { const [c, k, ...rest] = p.split("."); const v = rest.join("."); return k === "is" ? ["is_null", c] : [k, c, v]; });
      this.f.push(["or", null, parts.map(p => p[0] === "is_null" ? ["eqnull", p[1]] : p)]);
      return this;
    }
    order(c, o) { this.ord = [c, !(o && o.ascending === false)]; return this; }
    range(a, b) { this.rng = [a, b]; return this; }
    limit(n) { this.lim = n; return this; }
    maybeSingle() { this.mode = "maybe"; return this; }
    single() { this.mode = "single"; return this; }
    then(res, rej) { return Promise.resolve().then(() => this.exec()).then(res, rej); }
    exec() {
      log.push({ table: this.t, op: this.op, filters: J(this.f), payload: this.payload });
      if (fail[this.t + ":" + this.op]) return { data: null, error: { message: "down", code: "XX000" } };
      const rows = tables[this.t] || (tables[this.t] = []);
      const f = this.f.map(x => x[0] === "or" ? ["or", null, x[2].map(g => g[0] === "eqnull" ? ["eq", g[1], null] : g)] : x);
      const match = r => f.every(x => x[0] === "or" ? x[2].some(g => (g[0] === "eq" && g[2] === null) ? (r[g[1]] === null || r[g[1]] === undefined) : matches(r, g)) : matches(r, x));
      if (this.op === "select") {
        let hit = rows.filter(match);
        const count = hit.length;
        if (this.ord) { const [c, asc] = this.ord; hit = hit.slice().sort((x, y) => (asc ? 1 : -1) * cmp(x[c], y[c])); }
        if (this.rng) hit = hit.slice(this.rng[0], this.rng[1] + 1);
        if (this.lim != null) hit = hit.slice(0, this.lim);
        const data = this.opts.head ? null : hit.map(r => Object.assign({}, r));
        if (this.mode === "maybe") return { data: data && data.length ? data[0] : null, error: null, count };
        if (this.mode === "single") return data && data.length === 1 ? { data: data[0], error: null } : { data: null, error: { message: "not one row", code: "PGRST116" } };
        return { data, error: null, count };
      }
      if (this.op === "insert" || this.op === "upsert") {
        const list = Array.isArray(this.payload) ? this.payload : [this.payload];
        const made = [];
        for (const p of list) {
          const row = Object.assign({}, p);
          if (!row.id) row.id = UUID(++auto);
          if (this.op === "insert" && uniqueClash(this.t, row)) return { data: null, error: { message: "duplicate key", code: "23505" } };
          rows.push(row); made.push(Object.assign({}, row));
        }
        if (this.mode === "single") return { data: made[0], error: null };
        return { data: this.sel ? made : null, error: null };
      }
      if (this.op === "update") {
        const hit = rows.filter(match);
        hit.forEach(r => Object.assign(r, this.payload));
        const data = hit.map(r => Object.assign({}, r));
        if (this.mode === "maybe") return { data: data[0] || null, error: null };
        return { data: this.sel ? data : null, error: null };
      }
      if (this.op === "delete") {
        const keep = [], gone = [];
        rows.forEach(r => (match(r) ? gone : keep).push(r));
        tables[this.t] = keep;
        return { data: this.sel ? gone : null, error: null };
      }
      return { data: null, error: { message: "unknown op" } };
    }
  }
  return { from: t => new Q(t), tables, log, fail };
}

/* ── the server's own pieces, lifted ─────────────────────────────────────── */
function lift(names, ctx) {
  const src = names.map(n => { const d = MUT.definitionOf(FILES.server, n); if (!d) throw new Error("not found in server.js: " + n); return d; }).join("\n");
  const sandbox = Object.assign({ console: { log() {}, error() {}, warn() {} }, require: realRequire }, ctx);
  vm.createContext(sandbox);
  vm.runInContext(src + "\n;this.__out = {" + names.map(n => n + ": " + n).join(", ") + "};", sandbox);
  return sandbox.__out;
}
function recorderFor(db) {
  return lift(["recordGateDecision", "gateRecordNotWritten"], { supabase: db }).recordGateDecision;
}
const PLAN_OBS = lift(["entitlementGateObservation"], {}).entitlementGateObservation;
const HIGH_RISK = (function () {
  const m = /var highRiskPattern = (\/[^\n]*\/i);/.exec(FILES.server);
  return m ? vm.runInNewContext(m[1]) : null;
})();

/* ── fixtures ──────────────────────────────────────────────────────────── */
const NOW = Date.parse("2026-10-20T10:40:00.000Z");
const H = 3600000, D = 24 * H;
const ago = ms => new Date(NOW - ms).toISOString();
const ref = (u, s) => "bl-" + u.slice(-4) + "-" + s;
const SPEND = { [A]: 48, [B]: 6, [OWNER]: 0 };

function seedTables() {
  const t = {
    inventory_items: [
      { id: UUID(101), user_id: A, quantity_on_hand: 2, reorder_point: 5 },
      { id: UUID(102), user_id: A, quantity_on_hand: 5, reorder_point: 5 },
      { id: UUID(103), user_id: A, quantity_on_hand: 9, reorder_point: 5 },
      { id: UUID(104), user_id: A, quantity_on_hand: 1, reorder_point: null },
      { id: UUID(105), user_id: A, quantity_on_hand: "", reorder_point: 3 },
      { id: UUID(106), user_id: B, quantity_on_hand: 0, reorder_point: 3 },
      { id: UUID(107), user_id: B, quantity_on_hand: 0, reorder_point: 3 },
      { id: UUID(108), user_id: B, quantity_on_hand: 1, reorder_point: 3 }
    ],
    content_library: [
      { id: UUID(201), user_id: A, slug: "a1", body: "<a href=\"/x?ref=" + ref(A, "a1") + "\">x</a>" },
      { id: UUID(202), user_id: A, slug: "a2", body: "no tracked link" },
      { id: UUID(203), user_id: A, slug: null, body: "" },
      { id: UUID(204), user_id: B, slug: "b1", body: "?ref=" + ref(B, "b1") }
    ],
    engine_visits: [],
    ai_tasks: [],
    agent_proposals: [],
    bsky_leads: [],
    user_wallets: [{ id: UUID(401), user_id: A, balance: 150 }, { id: UUID(402), user_id: B, balance: 9000 }],
    agent_schedules: [
      { id: UUID(501), user_id: A, agent_type: "seo", consecutive_failures: 2, paused: false, paused_reason: null },
      { id: UUID(502), user_id: A, agent_type: "content", consecutive_failures: 0, paused: false, paused_reason: null },
      { id: UUID(503), user_id: A, agent_type: "content", consecutive_failures: 1, paused: false, paused_reason: null },
      { id: UUID(504), user_id: A, agent_type: "sales", consecutive_failures: 0, paused: true, paused_reason: "owner" },
      { id: UUID(505), user_id: B, agent_type: "content", consecutive_failures: 3, paused: false, paused_reason: null }
    ],
    agent_feedback: [],
    saved_prompts: [], notifications: [], member_triggers: [], trigger_firings: [], gate_decisions: [], job_runs: []
  };
  let n = 600;
  const v = (r, at) => t.engine_visits.push({ id: UUID(++n), ref: r, created_at: at });
  for (let i = 0; i < 4; i++) v(ref(A, "a1"), ago((i + 1) * D));          // 4 in the last 7 days
  for (let i = 0; i < 12; i++) v(ref(A, "a1"), ago(8 * D + i * H));      // 12 in the 7 days before
  for (let i = 0; i < 5; i++) v(ref(A, "a2"), ago(2 * D));               // an untracked post's
  for (let i = 0; i < 20; i++) v(ref(B, "b1"), ago(3 * D));              // the other member's
  const task = (u, status, at) => t.ai_tasks.push({ id: UUID(++n), user_id: u, status, created_at: at });
  [1, 2, 3].forEach(h => task(A, "failed", ago(h * H)));
  [30, 31].forEach(h => task(A, "failed", ago(h * H)));
  [1, 2, 3, 4].forEach(h => task(A, "completed", ago(h * H)));
  for (let i = 0; i < 7; i++) task(B, "failed", ago((i + 1) * H));
  const prop = (u, status, at) => t.agent_proposals.push({ id: UUID(++n), user_id: u, status, created_at: at });
  prop(A, "pending", ago(72 * H)); prop(A, "pending", ago(72 * H));
  for (let i = 0; i < 4; i++) prop(A, "pending", ago(H));
  for (let i = 0; i < 3; i++) prop(A, "approved", ago(80 * H));
  for (let i = 0; i < 5; i++) prop(B, "pending", ago(100 * H));
  const lead = (score, at) => t.bsky_leads.push({ id: UUID(++n), intent_score: score, created_at: at });
  [1, 2, 3].forEach(h => lead(80, ago(h * H)));
  [1, 2].forEach(h => lead(50, ago(h * H)));
  lead(90, ago(30 * H));
  const rate = (u, agent, rating, at) => t.agent_feedback.push({ id: UUID(++n), user_id: u, agent_type: agent, rating, created_at: at, updated_at: at });
  for (let i = 0; i < 10; i++) rate(A, "content", i < 4 ? "up" : "down", ago((i + 1) * D));
  for (let i = 0; i < 3; i++) rate(A, "seo", "up", ago((i + 1) * D));
  for (let i = 0; i < 10; i++) rate(B, "content", "up", ago((i + 1) * D));
  return t;
}

let uuidN = 9000;
function deps(db, over) {
  return Object.assign({
    supabase: db, env: { ENABLE_TRIGGERS: "true" }, now: () => new Date(NOW),
    isOwner: id => id === OWNER,
    userPlan: async () => ({ plan: { active: true }, error: null }),
    planObservation: PLAN_OBS,
    spendCeiling: async () => ({ allowed: true, counted: true }),
    spendThisMonth: async id => ({ usd: SPEND[id] || 0 }),
    spendLimit: () => 60,
    blogRef: ref,
    scoreFrom: LEARN.scoreFrom,
    record: recorderFor(db),
    uuid: () => "aaaaaaaa-0000-4000-8000-" + String(++uuidN).padStart(12, "0"),
    log: () => {}
  }, over || {});
}
const flush = async (n) => { for (let i = 0; i < (n || 8); i++) await new Promise(r => setImmediate(r)); };
const MEMBER_TABLES = ["inventory_items", "content_library", "ai_tasks", "agent_proposals", "user_wallets", "agent_schedules", "agent_feedback"];

(async function main() {
  /* ═══ A. the metrics against fixtures, scoped to the member ═══════════════ */
  console.log("\n══ A. each metric against fixtures, for two members, each read scoped to its member ══");
  const expected = {
    stock_at_reorder: { [A]: 2, [B]: 3, w: "now" },
    blog_arrivals: { [A]: 4, [B]: 20, w: "7d", prevA: 12 },
    tasks_failed: { [A]: 3, [B]: 7, w: "24h" },
    proposals_pending: { [A]: 6, [B]: 5, w: "now" },
    bfc_balance: { [A]: 150, [B]: 9000, w: "now" },
    schedule_failures: { [A]: 2, [B]: 1, w: "now" },
    spend_vs_cap: { [A]: 80, [B]: 10, w: "now" },
    helpful_share: { [A]: 40, [B]: 100, w: "30d", agent: "content" }
  };
  for (const metric of Object.keys(expected)) {
    for (const who of [A, B]) {
      const db = makeDb(seedTables());
      const e = expected[metric];
      const got = await R.metricValue(deps(db), who, { metric, window: e.w, comparator: "gte", threshold: 1, metric_agent: e.agent || null }, NOW);
      const memberReads = db.log.filter(l => MEMBER_TABLES.indexOf(l.table) !== -1);
      const spendAsked = [];
      if (metric === "spend_vs_cap") {
        const g2 = await R.metricValue(deps(makeDb(seedTables()), { spendThisMonth: async id => { spendAsked.push(id); return { usd: SPEND[id] || 0 }; } }), who, { metric, window: e.w }, NOW);
        if (g2.value !== got.value) spendAsked.push("mismatch");
      }
      const scoped = metric === "spend_vs_cap" ? (memberReads.length === 0 && J(spendAsked) === J([who])) : memberReads.length > 0 && memberReads.every(l => JSON.parse(l.filters).some(f => f[0] === "eq" && f[1] === "user_id" && f[2] === who));
      check("A. " + metric + " for member " + (who === A ? "A" : "B") + ": " + e[who] + ", every read of a member table names that member",
        got.value === e[who] && scoped, J(got) + " " + J(memberReads.map(l => l.table + l.filters)));
      if (metric === "blog_arrivals") {
        const refsAsked = db.log.filter(l => l.table === "engine_visits").map(l => JSON.parse(l.filters).find(f => f[0] === "in")[2]).flat();
        const own = who === A ? [ref(A, "a1")] : [ref(B, "b1")];
        check("A. blog_arrivals for member " + (who === A ? "A" : "B") + ": only that member's tracked refs are asked for" + (who === A ? ", and the 7 days before hold 12" : ""),
          J(refsAsked) === J(own) && (who !== A || got.previous === 12), J(refsAsked) + " prev " + got.previous);
      }
    }
  }
  {
    const db = makeDb(seedTables());
    const pend48 = await R.metricValue(deps(db), A, { metric: "proposals_pending", window: "48h" }, NOW);
    check("A. proposals_pending over 48h: only those waiting longer than 48 hours (2 of A's 6)", pend48.value === 2, J(pend48));
    const seo = await R.metricValue(deps(db), A, { metric: "helpful_share", window: "30d", metric_agent: "seo" }, NOW);
    check("A. helpful_share with 3 ratings: not judged (null), never a guess", seo.value === null, J(seo));
    const before = db.log.length;
    const leadA = await R.metricValue(deps(db), A, { metric: "lead_scores", window: "24h" }, NOW);
    check("A. lead_scores for a member: null, and bsky_leads is never read", leadA.value === null && !db.log.slice(before).some(l => l.table === "bsky_leads"), J(leadA));
    const leadO = await R.metricValue(deps(db), OWNER, { metric: "lead_scores", window: "24h" }, NOW);
    check("A. lead_scores for the owner: 3 scored 70 or more in 24 hours (and 1 in the 24 before)", leadO.value === 3 && leadO.previous === 1, J(leadO));
    const noWallet = await R.metricValue(deps(db), OWNER, { metric: "bfc_balance", window: "now" }, NOW);
    check("A. bfc_balance with no wallet: null, not zero", noWallet.value === null, J(noWallet));
    const noCap = await R.metricValue(deps(db, { spendLimit: () => null }), A, { metric: "spend_vs_cap", window: "now" }, NOW);
    check("A. spend_vs_cap with a cap that cannot be read: null", noCap.value === null, J(noCap));
    db.fail["ai_tasks:select"] = true;
    let threw = false;
    try { await R.metricValue(deps(db), A, { metric: "tasks_failed", window: "24h" }, NOW); } catch (e) { threw = true; }
    check("A. a read that fails throws (the pass counts it unreadable and fires nothing)", threw);
  }

  /* ═══ B. comparators at their boundaries ════════════════════════════════ */
  console.log("\n══ B. comparator boundaries ══");
  const th = 5;
  const table = { lt: [true, false, false], lte: [true, true, false], gt: [false, false, true], gte: [false, true, true] };
  for (const c of Object.keys(table)) {
    const got = [th - 1, th, th + 1].map(v => T.crosses({ comparator: c, threshold: th }, v, null));
    check("B. " + c + " " + th + " at 4, 5, 6: " + J(table[c]), J(got) === J(table[c]), J(got));
  }
  check("B. no number (null) never crosses", [null, undefined, NaN].every(v => T.crosses({ comparator: "gte", threshold: 0 }, v, null) === null));
  check("B. drop_pct with 9 before: not judged", T.crosses({ comparator: "drop_pct", threshold: 10 }, 0, 9) === null);
  check("B. drop_pct with 10 before and 5 now is 50%: fires at 50, not at 51",
    T.dropPct(5, 10) === 50 && T.crosses({ comparator: "drop_pct", threshold: 50 }, 5, 10) === true && T.crosses({ comparator: "drop_pct", threshold: 51 }, 5, 10) === false);
  check("B. a rise is a 0% drop", T.dropPct(20, 10) === 0);

  /* ═══ C. the closed schema ══════════════════════════════════════════════ */
  console.log("\n══ C. the closed schema refuses ══");
  const good = { name: "Runs failing", metric: "tasks_failed", comparator: "gte", threshold: 3, window: "24h", cooldown_hours: 24, action: { kind: "raise_alert" } };
  const v0 = T.validateTrigger(good, null, { owner: false });
  check("C. a good trigger is accepted, enabled by default", v0.ok && v0.value.enabled === true && v0.value.metric_agent === null, J(v0));
  const refusals = [
    ["an unknown field (price)", Object.assign({}, good, { price: 1 }), "price"],
    ["an unknown field (__proto__ as a key)", JSON.parse("{\"__proto__\":1,\"name\":\"x\"}"), null],
    ["an unknown metric (page_views)", Object.assign({}, good, { metric: "page_views" }), "metric"],
    ["an unknown comparator (eq)", Object.assign({}, good, { comparator: "eq" }), "comparator"],
    ["drop_pct on a metric without history", Object.assign({}, good, { metric: "stock_at_reorder", window: "now", comparator: "drop_pct", threshold: 50 }), "comparator"],
    ["a window the metric does not allow (stock over 7d)", Object.assign({}, good, { metric: "stock_at_reorder", window: "7d" }), "window"],
    ["an unknown window (90d)", Object.assign({}, good, { window: "90d" }), "window"],
    ["an unknown action (send_email)", Object.assign({}, good, { action: { kind: "send_email" } }), "action.kind"],
    ["an unknown action field (to)", Object.assign({}, good, { action: { kind: "raise_alert", to: "x@y.z" } }), "action.to"],
    ["an action that is a string", Object.assign({}, good, { action: "raise_alert" }), "action"],
    ["a draft for an unknown agent", Object.assign({}, good, { action: { kind: "draft_task", agent: "hacker" } }), "action.agent"],
    ["an alert naming an agent", Object.assign({}, good, { action: { kind: "raise_alert", agent: "seo" } }), "action.agent"],
    ["a threshold as text", Object.assign({}, good, { threshold: "3" }), "threshold"],
    ["a fractional count threshold", Object.assign({}, good, { threshold: 2.5 }), "threshold"],
    ["a negative threshold", Object.assign({}, good, { threshold: -1 }), "threshold"],
    ["a drop of 101%", Object.assign({}, good, { metric: "blog_arrivals", window: "7d", comparator: "drop_pct", threshold: 101 }), "threshold"],
    ["a cooldown of 5 hours", Object.assign({}, good, { cooldown_hours: 5 }), "cooldown_hours"],
    ["a cooldown of 169 hours", Object.assign({}, good, { cooldown_hours: 169 }), "cooldown_hours"],
    ["a cooldown of 24.5 hours", Object.assign({}, good, { cooldown_hours: 24.5 }), "cooldown_hours"],
    ["a name with markup", Object.assign({}, good, { name: "<b>x</b>" }), "name"],
    ["a metric agent where none belongs", Object.assign({}, good, { metric_agent: "seo" }), "metric_agent"],
    ["helpful_share with no agent", Object.assign({}, good, { metric: "helpful_share", window: "30d", comparator: "lt", threshold: 50 }), "metric_agent"],
    ["lead scores for a member", Object.assign({}, good, { metric: "lead_scores" }), "metric"],
    ["enabled as text", Object.assign({}, good, { enabled: "yes" }), "enabled"],
    ["an array body", [good], "body"]
  ];
  refusals.forEach(([what, body, field]) => {
    const r = T.validateTrigger(body, null, { owner: false });
    check("C. refused: " + what, r.ok === false && (field === null || r.field === field), J(r));
  });
  const ownerLead = T.validateTrigger(Object.assign({}, good, { metric: "lead_scores" }), null, { owner: true });
  check("C. lead scores for the owner: accepted", ownerLead.ok === true, J(ownerLead));
  const partial = T.validateTrigger({ enabled: false }, T.fromRow(Object.assign({ id: UUID(1) }, T.toRow(v0.value))), { owner: false });
  check("C. a partial edit (the switch) keeps the rest and validates the whole trigger", partial.ok && partial.value.enabled === false && partial.value.metric === "tasks_failed");
  check("C. TRIGGERS_DAILY_FIRINGS: unset 10, \"3\" 3, \"0\" 1, \"50\" 20, \"x\" 10",
    T.dailyFiringsCap({}) === 10 && T.dailyFiringsCap({ TRIGGERS_DAILY_FIRINGS: "3" }) === 3 && T.dailyFiringsCap({ TRIGGERS_DAILY_FIRINGS: "0" }) === 1 &&
    T.dailyFiringsCap({ TRIGGERS_DAILY_FIRINGS: "50" }) === 20 && T.dailyFiringsCap({ TRIGGERS_DAILY_FIRINGS: "x" }) === 10);
  check("C. the metric list is the nine of design section 2.1", J(T.METRIC_KEYS) === J(["stock_at_reorder", "blog_arrivals", "tasks_failed", "proposals_pending", "lead_scores", "bfc_balance", "schedule_failures", "spend_vs_cap", "helpful_share"]));
  check("C. the agents are lib/gateRules.js AGENTS", J(T.AGENTS) === J(RULES.AGENTS));
  check("C. nothing in lib/triggers.js is evaluated as code: no eval, Function, new RegExp or process", !/\beval\(|\bFunction\(|new RegExp|\bprocess\./.test(FILES.triggers));

  /* ═══ D. the templates ═══════════════════════════════════════════════════ */
  console.log("\n══ D. the six ready-made templates ══");
  check("D. six templates", T.TEMPLATES.length === 6, T.TEMPLATES.length);
  T.TEMPLATES.forEach(tp => {
    const r = T.validateTrigger(JSON.parse(J(tp.body)), null, { owner: false });
    check("D. \"" + tp.title + "\" validates for a member, against the closed lists", r.ok === true && T.METRIC_KEYS.indexOf(tp.body.metric) !== -1, J(r));
  });
  check("D. the first says: \"When stock of any item drops to its reorder point, the Store agent drafts a reorder. At most once a day.\"",
    T.summarize(T.TEMPLATES[0].body) === "When stock of any item drops to its reorder point, the Store agent drafts a reorder. At most once a day.", T.summarize(T.TEMPLATES[0].body));
  check("D. the six cover the design's six: stock, failing runs, waiting proposals, spend, arrivals, helpful share",
    J(T.TEMPLATES.map(t => t.body.metric)) === J(["stock_at_reorder", "tasks_failed", "proposals_pending", "spend_vs_cap", "blog_arrivals", "helpful_share"]));

  /* ═══ E. the pass ═══════════════════════════════════════════════════════ */
  console.log("\n══ E. the hourly pass: switch, claim, gates, cooldown, cap, ceiling, no publishing ══");
  function trig(u, n, body) {
    const v = T.validateTrigger(body, null, { owner: u === OWNER });
    if (!v.ok) throw new Error("fixture trigger invalid: " + v.error);
    return Object.assign({ id: UUID(n), user_id: u, created_at: ago(10 * D), updated_at: ago(10 * D), last_value: null, last_checked_at: null, last_attempt_at: null, last_fired_at: null }, T.toRow(v.value));
  }
  function scenario() {
    const t = seedTables();
    t.member_triggers = [
      trig(A, 1001, { name: "Reorder", metric: "stock_at_reorder", comparator: "gt", threshold: 0, window: "now", cooldown_hours: 24, action: { kind: "draft_task", agent: "store" } }),
      trig(A, 1002, { name: "Failing", metric: "tasks_failed", comparator: "gte", threshold: 3, window: "24h", cooldown_hours: 24, action: { kind: "raise_alert" } }),
      trig(A, 1003, { name: "Waiting", metric: "proposals_pending", comparator: "gte", threshold: 10, window: "now", cooldown_hours: 24, action: { kind: "raise_alert" } }),
      trig(A, 1004, { name: "Spend", metric: "spend_vs_cap", comparator: "gte", threshold: 80, window: "now", cooldown_hours: 168, action: { kind: "pause_schedule", agent: "content" } }),
      trig(B, 1005, { name: "Helpful", metric: "helpful_share", metric_agent: "content", comparator: "lt", threshold: 50, window: "30d", cooldown_hours: 168, action: { kind: "raise_alert" } }),
      trig(B, 1006, { name: "Failing B", metric: "tasks_failed", comparator: "gte", threshold: 5, window: "24h", cooldown_hours: 24, action: { kind: "raise_alert" } })
    ];
    t.member_triggers.push(Object.assign(trig(A, 1007, { name: "Off", metric: "stock_at_reorder", comparator: "gt", threshold: 0, window: "now", cooldown_hours: 24, action: { kind: "raise_alert" } }), { enabled: false }));
    return makeDb(t);
  }
  {
    // E1. the switch
    for (const val of [undefined, "", "TRUE", "1", "true ", "yes"]) {
      const db = scenario();
      const r = await R.triggerTick(deps(db, { env: val === undefined ? {} : { ENABLE_TRIGGERS: val } }));
      check("E1. ENABLE_TRIGGERS " + J(val === undefined ? "(unset)" : val) + ": the pass does not run and reads nothing", r.ran === false && r.reason === "disabled" && db.log.length === 0, J(r) + " " + db.log.length);
    }
    const db = scenario();
    const first = await R.triggerTick(deps(db));
    check("E1. ENABLE_TRIGGERS exactly \"true\": the pass runs", first.ran === true && !first.error, J(first));
    const fir = db.tables.trigger_firings;
    const byTrig = id => fir.filter(f => f.trigger_id === UUID(id));
    check("E. the first pass: Reorder, Failing, Spend and Failing B fire; Waiting (6 of 10) and Helpful (100%) stay quiet; the switched-off one is never read",
      byTrig(1001).length === 1 && byTrig(1002).length === 1 && byTrig(1004).length === 1 && byTrig(1006).length === 1 && byTrig(1003).length === 0 && byTrig(1005).length === 0 &&
      byTrig(1007).length === 0 && fir.every(f => f.outcome === "fired"), J(fir.map(f => [f.trigger_id.slice(-4), f.outcome])));
    const tr = id => db.tables.member_triggers.find(x => x.id === UUID(id));
    check("E. each enabled trigger keeps its last value and when it was read; the fired ones their last fired time",
      tr(1001).last_value === 2 && tr(1003).last_value === 6 && tr(1005).last_value === 100 && tr(1004).last_value === 80 && tr(1001).last_checked_at === new Date(NOW).toISOString() &&
      tr(1001).last_fired_at === new Date(NOW).toISOString() && tr(1003).last_fired_at === null && tr(1007).last_checked_at === null,
      J(db.tables.member_triggers.map(x => [x.name, x.last_value, x.last_fired_at])));
    // E3. through the gates, recorded with the decision id
    const decisions = db.tables.gate_decisions;
    const allLinked = fir.every(f => {
      const d = decisions.find(x => x.id === f.gate_decision_id);
      return d && d.action === "trigger_fire" && d.target === "trigger:" + f.trigger_id && d.user_id === f.user_id && d.outcome === "ran" &&
        J(d.results) === J([{ gate: "G13", result: "pass" }, { gate: "G9", result: "pass" }]);
    });
    check("E3. every firing went through the gate evaluator: one trigger_fire decision each (G13 then G9), the firing row carrying its id",
      fir.length === 4 && decisions.length === 4 && allLinked, J({ fir: fir.map(f => f.gate_decision_id), dec: decisions.map(d => [d.id, d.action, d.target, d.results]) }));
    check("E3. lib/gates.js lists trigger_fire's gates as G13 then G9", J(GATES.ACTION_GATES.trigger_fire) === J(["G13", "G9"]));
    // E2. the claim
    const second = await R.triggerTick(deps(db));
    check("E2. a second tick the same hour finds hourly_triggers_h10 claimed and fires nothing", second.ran === false && second.reason === "claimed" && db.tables.trigger_firings.length === 4 &&
      db.tables.job_runs.length === 1 && db.tables.job_runs[0].job_name === "hourly_triggers_h10", J(second) + " " + J(db.tables.job_runs));
    // E4. the cooldown
    const third = await R.triggerTick(deps(db, { now: () => new Date(NOW + H) }));
    check("E4. the next hour claims hourly_triggers_h11, and every trigger still crossing is inside its cooldown: nothing fires", third.ran === true && db.tables.trigger_firings.length === 4 &&
      db.tables.job_runs.some(j => j.job_name === "hourly_triggers_h11"), J(third));
    const later = await R.triggerTick(deps(db, { now: () => new Date(NOW + 25 * H) }));
    check("E4. 25 hours on, the 24-hour cooldowns have passed: Reorder (stock still at its reorder point) fires again; Spend (a week) does not; Failing and Failing B are quiet (their failures are now over 24 hours old)",
      later.ran === true && byTrig(1001).length === 2 && byTrig(1006).length === 1 && byTrig(1004).length === 1 && byTrig(1002).length === 1 && db.tables.trigger_firings.length === 5, J(db.tables.trigger_firings.map(f => [f.trigger_id.slice(-4), f.fired_at])));
    // E7. nothing published or sent
    const writes = db.log.filter(l => l.op !== "select").map(l => l.table);
    const forbidden = ["agent_proposals", "social_post_drafts", "email_sends", "outreach_sends", "marketplace_listings", "ai_tasks", "model_calls", "wallet_transactions"];
    check("E7. the passes wrote no proposal, post, email, outreach, listing, task, model call or wallet row", !writes.some(t => forbidden.indexOf(t) !== -1), J([...new Set(writes)]));
    const draft = db.tables.saved_prompts;
    check("E7. Reorder filed one saved prompt (updated, not duplicated, on its second firing) for the Store agent, named \"Trigger draft: Reorder\"",
      draft.length === 1 && draft[0].user_id === A && draft[0].agent_type === "store" && draft[0].name === "Trigger draft: Reorder", J(draft));
    check("E7. the drafted text is held by the server's own high-risk pattern (handleAiTaskRequest's G2), so running it waits for approval",
      !!HIGH_RISK && draft.length === 1 && HIGH_RISK.test(draft[0].prompt), draft[0] && draft[0].prompt);
    const asks = draft[0] ? draft[0].prompt.replace(/ Prepare it for my approval; do not publish or send anything.$/, "") : "";
    check("E7. ...and it is held because it asks for approval, not by chance: without that sentence no part of it matches the pattern",
      !!HIGH_RISK && asks !== (draft[0] && draft[0].prompt) && !HIGH_RISK.test(asks), asks);
    check("E7. running a draft is POST /api/saved-prompts/:id/run, which calls handleAiTaskRequest, whose high-risk pattern sets requires_approval",
      /RUN THROUGH handleAiTaskRequest/.test(FILES.server) && /return await handleAiTaskRequest\(taskReq, taskRes, next\);/.test(FILES.server) &&
      /var requiresApproval = highRiskPattern\.test\(userPrompt\);/.test(FILES.server));
    const reorderFiring = byTrig(1001)[0];
    check("E7. the firing points at the saved prompt", reorderFiring.action_ref === "saved_prompt:" + draft[0].id, reorderFiring.action_ref);
    const notes = db.tables.notifications;
    check("E. Failing and Failing B raised one alert each, under their own members; Spend's pause raised one too (type trigger, the trigger's summary)",
      notes.filter(n => n.user_id === A).length === 2 && notes.filter(n => n.user_id === B).length === 1 && notes.length === 3 && notes.every(n => n.type === "trigger" && /^Trigger: /.test(n.title)), J(notes.map(n => [n.user_id.slice(-1), n.title])));
    // E8. the pause
    const sch = db.tables.agent_schedules;
    check("E8. Spend paused A's two content schedules (paused_reason trigger); A's seo, A's already-paused sales and B's content are untouched",
      sch.filter(s => s.user_id === A && s.agent_type === "content").every(s => s.paused === true && s.paused_reason === "trigger") &&
      sch.find(s => s.id === UUID(501)).paused === false && sch.find(s => s.id === UUID(504)).paused_reason === "owner" && sch.find(s => s.id === UUID(505)).paused === false, J(sch));
  }
  {
    // E5. the daily cap
    const t = seedTables();
    t.member_triggers = [1, 2, 3, 4].map(i => trig(A, 1100 + i, { name: "Cap " + i, metric: "stock_at_reorder", comparator: "gt", threshold: 0, window: "now", cooldown_hours: 6, action: { kind: "raise_alert" } }));
    const db = makeDb(t);
    await R.triggerTick(deps(db, { env: { ENABLE_TRIGGERS: "true", TRIGGERS_DAILY_FIRINGS: "2" } }));
    const f1 = db.tables.trigger_firings;
    check("E5. with a cap of 2 and four triggers crossing: 2 fire, 2 are recorded skipped_daily_cap with no decision",
      f1.filter(f => f.outcome === "fired").length === 2 && f1.filter(f => f.outcome === "skipped_daily_cap").length === 2 &&
      f1.filter(f => f.outcome === "skipped_daily_cap").every(f => f.gate_decision_id === null) && db.tables.gate_decisions.length === 2, J(f1.map(f => f.outcome)));
    await R.triggerTick(deps(db, { env: { ENABLE_TRIGGERS: "true", TRIGGERS_DAILY_FIRINGS: "2" }, now: () => new Date(NOW + H) }));
    await R.triggerTick(deps(db, { env: { ENABLE_TRIGGERS: "true", TRIGGERS_DAILY_FIRINGS: "2" }, now: () => new Date(NOW + 7 * H) }));
    const f2 = db.tables.trigger_firings;
    const skippedIds = f2.filter(f => f.outcome === "skipped_daily_cap").map(f => f.trigger_id);
    check("E5. later the same UTC day (after the 6-hour cooldown too): still 2 fired, and each skipped trigger is recorded once a day only (Cap 3 and 4 at 10:40 not again; Cap 1 and 2 once at 17:40)",
      f2.filter(f => f.outcome === "fired").length === 2 && skippedIds.length === 4 && new Set(skippedIds).size === 4, J(f2.map(f => [f.trigger_id.slice(-4), f.outcome, f.fired_at])));
    await R.triggerTick(deps(db, { env: { ENABLE_TRIGGERS: "true", TRIGGERS_DAILY_FIRINGS: "2" }, now: () => new Date(NOW + 14 * H) }));
    check("E5. the next UTC day the cap starts again: 2 more fire", db.tables.trigger_firings.filter(f => f.outcome === "fired").length === 4, J(db.tables.trigger_firings.map(f => f.outcome)));
    const t2 = seedTables();
    t2.member_triggers = [trig(A, 1201, { name: "Cap x", metric: "stock_at_reorder", comparator: "gt", threshold: 0, window: "now", cooldown_hours: 6, action: { kind: "raise_alert" } })];
    const db2 = makeDb(t2);
    db2.fail["trigger_firings:select"] = true;
    await R.triggerTick(deps(db2));
    check("E5. today's firings that cannot be read: the member's triggers do not fire on a guess", db2.tables.trigger_firings.length === 0 && db2.tables.notifications.length === 0);
  }
  {
    // E6. the spend ceiling, and the plan
    const db = scenario();
    let asked = 0;
    await R.triggerTick(deps(db, { spendCeiling: async () => { asked++; const e = new Error("limit"); e.code = "PLATFORM_DAILY_SPEND_LIMIT"; throw e; } }));
    const fir = db.tables.trigger_firings;
    const allBlocked = fir.length === 4 && fir.every(f => f.outcome === "blocked_by_gate" && f.gate_decision_id);
    const dec = db.tables.gate_decisions;
    check("E6. the platform spend ceiling refuses: every crossing trigger is blocked_by_gate, its decision blocked with G9 failed PLATFORM_DAILY_SPEND_LIMIT",
      allBlocked && asked === 4 && dec.length === 4 && dec.every(d => d.outcome === "blocked" && J(d.results) === J([{ gate: "G13", result: "pass" }, { gate: "G9", result: "fail", code: "PLATFORM_DAILY_SPEND_LIMIT" }])), J(dec.map(d => d.results)));
    check("E6. ...and nothing acted: no alert, no saved prompt, no schedule paused, no last fired time",
      db.tables.notifications.length === 0 && db.tables.saved_prompts.length === 0 && db.tables.agent_schedules.every(s => s.paused_reason !== "trigger") &&
      db.tables.member_triggers.every(x => x.last_fired_at === null));
    const db2 = scenario();
    let asked2 = 0;
    await R.triggerTick(deps(db2, { userPlan: async () => ({ plan: { active: false }, error: null }), spendCeiling: async () => { asked2++; return {}; } }));
    check("E6. not entitled: G13 fails not_entitled, G9 is never asked (not reached), nothing acts",
      asked2 === 0 && db2.tables.gate_decisions.length === 4 && db2.tables.gate_decisions.every(d => J(d.results) === J([{ gate: "G13", result: "fail", code: "not_entitled" }, { gate: "G9", result: "not_reached" }])) &&
      db2.tables.notifications.length === 0, J(db2.tables.gate_decisions.map(d => d.results)));
    const db3 = scenario();
    await R.triggerTick(deps(db3, { userPlan: async () => ({ plan: null, error: new Error("down") }) }));
    check("E6. a plan that cannot be read: G13 fails entitlement_unknown", db3.tables.gate_decisions.every(d => d.results[0].code === "entitlement_unknown") && db3.tables.notifications.length === 0);
    const t4 = seedTables();
    t4.member_triggers = [trig(OWNER, 1301, { name: "Leads", metric: "lead_scores", comparator: "gte", threshold: 3, window: "24h", cooldown_hours: 24, action: { kind: "raise_alert" } })];
    const db4 = makeDb(t4);
    await R.triggerTick(deps(db4, { userPlan: async () => ({ plan: { active: true, access_reason: "owner" }, error: null }), spendCeiling: async () => ({ allowed: true, owner: true }) }));
    check("E6. the owner: G13 and G9 are bypasses (owner_pass), never passes, and the owner's lead trigger fires",
      db4.tables.trigger_firings.length === 1 && db4.tables.trigger_firings[0].outcome === "fired" &&
      J(db4.tables.gate_decisions[0].results) === J([{ gate: "G13", result: "bypass", code: "owner_pass" }, { gate: "G9", result: "bypass", code: "owner_pass" }]), J(db4.tables.gate_decisions));
    const db5 = scenario();
    db5.fail["notifications:insert"] = true;
    await R.triggerTick(deps(db5));
    const f5 = db5.tables.trigger_firings.filter(f => f.trigger_id === UUID(1002));
    check("E. an alert that cannot be written: the firing says action_failed, with its decision id, and counts toward the cap",
      f5.length === 1 && f5[0].outcome === "action_failed" && !!f5[0].gate_decision_id && db5.tables.member_triggers.find(x => x.id === UUID(1002)).last_fired_at === null, J(f5));
    const db6 = scenario();
    db6.fail["gate_decisions:insert"] = true;
    await R.triggerTick(deps(db6));
    check("E3. a decision record that cannot be written: the firing still happens (fail-open for the record) and carries no decision id",
      db6.tables.trigger_firings.length === 4 && db6.tables.trigger_firings.every(f => f.gate_decision_id === null && f.outcome === "fired"));
  }

  /* ═══ F. the preview ═════════════════════════════════════════════════════ */
  console.log("\n══ F. the preview reads only, and dates the last 30 days ══");
  const C = UUID(3);
  function previewDb() {
    const t = seedTables();
    ["2026-10-10T05:10:00.000Z", "2026-10-10T05:20:00.000Z", "2026-10-20T08:05:00.000Z", "2026-10-20T08:15:00.000Z", "2026-10-20T08:25:00.000Z"]
      .forEach((at, i) => t.ai_tasks.push({ id: UUID(7000 + i), user_id: C, status: "failed", created_at: at }));
    t.ai_tasks.push({ id: UUID(7100), user_id: C, status: "failed", created_at: "2026-08-01T00:00:00.000Z" });
    return makeDb(t);
  }
  const pbody = { name: "Preview", metric: "tasks_failed", comparator: "gte", threshold: 2, window: "24h", cooldown_hours: 24, action: { kind: "raise_alert" } };
  {
    const db = previewDb();
    const p = await R.preview(deps(db), C, T.validateTrigger(pbody, null, {}).value, NOW);
    const writes = db.log.filter(l => l.op !== "select");
    check("F. the runner's preview: now 3 in 24 hours, it would fire now; in 30 days it would have fired twice, at 2026-10-10 05:30 and 2026-10-20 08:30 UTC",
      p.value_now === 3 && p.would_fire_now === true && p.replay === true && p.count === 2 &&
      J(p.fired_at) === J(["2026-10-10T05:30:00.000Z", "2026-10-20T08:30:00.000Z"]), J(p));
    check("F. THE PREVIEW WRITES NOTHING: no insert, update, delete or upsert on any table", writes.length === 0, J(writes));
    const s = await R.preview(deps(db), A, T.validateTrigger({ name: "S", metric: "stock_at_reorder", comparator: "gt", threshold: 0, window: "now", cooldown_hours: 24, action: { kind: "raise_alert" } }, null, {}).value, NOW);
    check("F. a number with no history: the value now and \"Now only: there is no history of this number.\"", s.replay === false && s.value_now === 2 && s.count === null && s.note === "Now only: there is no history of this number.", J(s));
    const dropT = { comparator: "drop_pct", threshold: 50, window: "24h", cooldown_hours: 24 };
    const evs = []; for (let i = 0; i < 10; i++) evs.push(NOW - 30 * H - i * 60000);
    const fired = T.replay(dropT, evs, NOW, 30);
    check("F. the replay of a drop: 10 in a day then none fires once the day before holds 10 and the day now holds none", fired.length === 1, J(fired));
  }

  /* ═══ G. the routes ══════════════════════════════════════════════════════ */
  console.log("\n══ G. the routes ══");
  const start = FILES.server.indexOf("/* ── MEMBER TRIGGERS (intelligence layer B4)");
  const end = FILES.server.indexOf("app.post(\"/api/oracle\"", start);
  check("G0. the triggers block is in server.js", start > 0 && end > start);
  const BLOCK = FILES.server.slice(start, end);
  const decl = {};
  (BLOCK.match(/^app\.(get|post|put|delete)\("\/api\/triggers[^"]*", [^\n]*$/gm) || []).forEach(line => {
    const m = /^app\.(get|post|put|delete)\("([^"]+)", (.*)$/.exec(line);
    const parts = m[3].split(", "), names = [];
    for (const x of parts) { if (!/^[A-Za-z]+$/.test(x)) break; names.push(x); }
    decl[m[1] + " " + m[2]] = names;
  });
  const wantMw = {
    "get /api/triggers/language": ["requireAuth"],
    "get /api/triggers": ["requireAuth", "triggersLimiter"],
    "post /api/triggers": ["requireAuth", "requireActiveSubscription", "triggersLimiter"],
    "put /api/triggers/:id": ["requireAuth", "requireActiveSubscription", "triggersLimiter"],
    "delete /api/triggers/:id": ["requireAuth", "requireActiveSubscription", "triggersLimiter"],
    "get /api/triggers/firings": ["requireAuth", "triggersLimiter"],
    "post /api/triggers/preview": ["requireAuth", "requireActiveSubscription", "triggersLimiter"]
  };
  Object.keys(wantMw).forEach(k => check("G0. " + k + " is mounted with " + wantMw[k].join(", "), J(decl[k]) === J(wantMw[k]), J(decl[k])));
  check("G0. seven trigger routes, and no others", Object.keys(decl).length === 7, J(Object.keys(decl)));

  function routes(db, over) {
    const handlers = {};
    const app = {};
    ["get", "post", "put", "delete"].forEach(m => { app[m] = function (p) { handlers[m + " " + p] = Array.prototype.slice.call(arguments, 1); }; });
    const mw = name => { const f = function (req, res, next) { next(); }; f.mw = name; return f; };
    const ctx = Object.assign({
      app, rateLimit: () => mw("limiter"), requireAuth: mw("auth"), requireActiveSubscription: mw("sub"),
      supabase: db, isOwnerAccount: id => id === OWNER, getUserPlan: async () => ({ active: true }),
      entitlementGateObservation: PLAN_OBS, enforcePlatformDailySpendCeiling: async () => ({ allowed: true }),
      modelSpendThisMonth: async id => ({ usd: SPEND[id] || 0 }), modelSpendMonthlyLimit: () => 60, blogRefToken: ref,
      LEARNING: LEARN, recordGateDecision: recorderFor(db), crypto: require("crypto"), console: { log() {}, error() {}, warn() {} },
      nowIso: () => new Date(NOW).toISOString(), UUID_RE: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
      process: { env: { ENABLE_TRIGGERS: "true" } },
      require: function (r) { if (r === "./lib/triggers") return T; if (r === "./lib/triggerRunner") return R; return realRequire(r); }
    }, over || {});
    vm.createContext(ctx);
    vm.runInContext(BLOCK, ctx);
    return async function call(key, user, opts) {
      const chain = handlers[key];
      if (!chain) throw new Error("no route " + key);
      const req = { user: { id: user }, body: (opts && opts.body), params: (opts && opts.params) || {}, query: (opts && opts.query) || {}, method: key.split(" ")[0].toUpperCase() };
      const out = { status: 200, body: undefined, error: null };
      const res = { status(c) { out.status = c; return res; }, json(b) { out.body = JSON.parse(J(b)); return res; } };
      for (let i = 0; i < chain.length; i++) {
        let moved = false, err = null;
        await chain[i](req, res, e => { moved = true; err = e || null; });
        if (err) { out.error = err; break; }
        if (!moved) break;
      }
      return out;
    };
  }
  {
    const db = makeDb(seedTables());
    const call = routes(db);
    const made = await call("post /api/triggers", A, { body: T.TEMPLATES[1].body });
    check("G. a template saved (201) under the caller, with its summary", made.status === 201 && made.body.trigger.name === "Runs failing" &&
      db.tables.member_triggers.length === 1 && db.tables.member_triggers[0].user_id === A && db.tables.member_triggers[0].metric_window === "24h" &&
      made.body.trigger.summary === T.summarize(T.TEMPLATES[1].body), J(made));
    const before = db.tables.member_triggers.length;
    for (const [what, body] of [["an unknown field", Object.assign({}, T.TEMPLATES[1].body, { name: "X1", sql: "drop" })],
      ["an unknown metric", Object.assign({}, T.TEMPLATES[1].body, { name: "X2", metric: "page_views" })],
      ["an unknown action", Object.assign({}, T.TEMPLATES[1].body, { name: "X3", action: { kind: "publish_post" } })],
      ["lead scores for a member", Object.assign({}, T.TEMPLATES[1].body, { name: "X4", metric: "lead_scores" })]]) {
      const r = await call("post /api/triggers", A, { body });
      check("G. refused (400), nothing saved: " + what, r.status === 400 && /Nothing was saved\.$/.test(r.body.error) && db.tables.member_triggers.length === before, J(r));
    }
    const dup = await call("post /api/triggers", A, { body: T.TEMPLATES[1].body });
    check("G. the same name twice: 409", dup.status === 409, J(dup));
    for (let i = 0; i < 9; i++) await call("post /api/triggers", A, { body: Object.assign({}, T.TEMPLATES[1].body, { name: "More " + i }) });
    const eleventh = await call("post /api/triggers", A, { body: Object.assign({}, T.TEMPLATES[1].body, { name: "Eleventh" }) });
    check("G. the 11th trigger is refused (400 too_many_triggers)", eleventh.status === 400 && eleventh.body.reason === "too_many_triggers" && db.tables.member_triggers.filter(x => x.user_id === A).length === 10, J(eleventh));
    const bMade = await call("post /api/triggers", B, { body: T.TEMPLATES[0].body });
    const listA = await call("get /api/triggers", A, {});
    check("G. the list is the caller's own triggers only, each with its summary, and says whether the server runs them",
      listA.status === 200 && listA.body.triggers.length === 10 && listA.body.triggers.every(x => x.summary) && listA.body.enabled_on_server === true &&
      !listA.body.triggers.some(x => x.id === bMade.body.trigger.id), J(listA.body).slice(0, 300));
    const bId = bMade.body.trigger.id;
    const steal = await call("put /api/triggers/:id", A, { params: { id: bId }, body: { enabled: false } });
    const stealDel = await call("delete /api/triggers/:id", A, { params: { id: bId } });
    check("G. another member's trigger cannot be changed or deleted (404), and is unchanged", steal.status === 404 && stealDel.status === 404 &&
      db.tables.member_triggers.find(x => x.id === bId).enabled === true);
    const mine = listA.body.triggers[0].id;
    const off = await call("put /api/triggers/:id", A, { params: { id: mine }, body: { enabled: false } });
    check("G. the switch: a partial edit turns it off and keeps the rest", off.status === 200 && off.body.trigger.enabled === false && off.body.trigger.metric === "tasks_failed", J(off));
    const badEdit = await call("put /api/triggers/:id", A, { params: { id: mine }, body: { cooldown_hours: 1 } });
    check("G. an edit outside the schema is refused (400), nothing changed", badEdit.status === 400 && db.tables.member_triggers.find(x => x.id === mine).cooldown_hours === 24, J(badEdit));
    const gone = await call("delete /api/triggers/:id", A, { params: { id: mine } });
    check("G. the caller's own trigger is deleted", gone.status === 200 && !db.tables.member_triggers.some(x => x.id === mine));
    db.tables.trigger_firings.push({ id: UUID(8001), user_id: A, trigger_id: listA.body.triggers[1].id, metric_value: 3, threshold: 3, fired_at: ago(H), outcome: "fired", action_ref: "notification:x", gate_decision_id: UUID(8101) });
    db.tables.trigger_firings.push({ id: UUID(8002), user_id: B, trigger_id: bId, metric_value: 3, threshold: 0, fired_at: ago(H), outcome: "fired", action_ref: null, gate_decision_id: UUID(8102) });
    const fl = await call("get /api/triggers/firings", A, { query: {} });
    check("G. the firings list: the caller's only, with the trigger's name and the decision id", fl.status === 200 && fl.body.firings.length === 1 &&
      fl.body.firings[0].trigger_name === listA.body.triggers[1].name && fl.body.firings[0].gate_decision_id === UUID(8101), J(fl));
    const badPage = await call("get /api/triggers/firings", A, { query: { page: "0" } });
    check("G. a firings page of 0 is refused (400)", badPage.status === 400);
    const lang = await call("get /api/triggers/language", A, {});
    const langO = await call("get /api/triggers/language", OWNER, {});
    check("G. the language: lead scores listed for the owner only", lang.status === 200 && !lang.body.metrics.lead_scores && !!langO.body.metrics.lead_scores && lang.body.templates.length === 6);
    // F. the preview through the route
    const pdb = previewDb();
    const pcall = routes(pdb);
    const logBefore = pdb.log.length;
    const pr = await pcall("post /api/triggers/preview", C, { body: Object.assign({}, pbody, { name: undefined }) });
    const prWrites = pdb.log.slice(logBefore).filter(l => l.op !== "select");
    check("F. POST /api/triggers/preview: the dates, and it wrote nothing at all (no trigger, firing, decision or job row)",
      pr.status === 200 && pr.body.count === 2 && J(pr.body.fired_at) === J(["2026-10-10T05:30:00.000Z", "2026-10-20T08:30:00.000Z"]) && prWrites.length === 0 &&
      pdb.tables.member_triggers.length === 0 && pdb.tables.gate_decisions.length === 0, J(pr) + " " + J(prWrites));
    const prBad = await pcall("post /api/triggers/preview", C, { body: Object.assign({}, pbody, { metric: "nope" }) });
    check("F. a preview outside the schema is refused (400)", prBad.status === 400, J(prBad));
    pdb.fail["ai_tasks:select"] = true;
    const prDown = await pcall("post /api/triggers/preview", C, { body: pbody });
    check("F. a preview whose number cannot be read: 503, nothing changed", prDown.status === 503 && pdb.log.slice(logBefore).filter(l => l.op !== "select").length === 0, J(prDown));
  }
  {
    // the cron wiring
    const s = FILES.server;
    const cronAt = s.indexOf("cron.schedule(\"30 * * * *\"");
    const guard = s.lastIndexOf("if (require(\"./lib/triggers\").triggersEnabled(process.env)) {", cronAt);
    check("G. server.js schedules the pass at :30 UTC inside the startup block, behind triggersEnabled", cronAt > 0 && guard > 0 && cronAt - guard < 200 &&
      /cron\.schedule\("30 \* \* \* \*", function \(\) \{\n      triggerTickNow\(\)/.test(s) && s.slice(cronAt, cronAt + 400).indexOf("timezone: \"UTC\"") !== -1);
    check("G. no boot-time run: triggerTickNow is called only from the cron callback", (s.match(/triggerTickNow\(\)/g) || []).length === 2);
    check("G. the job name is hourly_triggers_h<hh>", R.jobName(new Date("2026-10-20T03:30:00Z")) === "hourly_triggers_h03" && R.jobName(new Date("2026-10-20T23:30:00Z")) === "hourly_triggers_h23");
    check("G. README: ENABLE_TRIGGERS (off, exactly true), TRIGGERS_DAILY_FIRINGS (10) and the triggerTick job row",
      /\| `ENABLE_TRIGGERS` \| off \| Exactly `true` runs the hourly member-trigger pass/.test(FILES.readme) && /\| `TRIGGERS_DAILY_FIRINGS` \| 10 \|/.test(FILES.readme) &&
      /\| `triggerTick`: member triggers[^\n]*\| cron `30 \* \* \* \*`, UTC, claimed `hourly_triggers_h<hh>` \| off unless `ENABLE_TRIGGERS` is exactly `true` \|/.test(FILES.readme));
    check("G. recordGateDecision takes the caller's decision id (a uuid only)", /if \(typeof more\.id === "string" && \/\^\[0-9a-f\]\{8\}/.test(s));
  }

  /* ═══ H. export, deletion, backup, migration 160 ═════════════════════════ */
  console.log("\n══ H. export, deletion, backup and migration 160 ══");
  const YD = realRequire("./lib/yourData");
  const dataRows = (YD.DATA || []).filter(x => x.table === "member_triggers" || x.table === "trigger_firings");
  check("H1. member_triggers and trigger_firings are in DATA once each: group agents, owner user_id, onDelete delete",
    dataRows.length === 2 && dataRows.every(x => x.group === "agents" && J(x.owner) === J(["user_id"]) && x.onDelete === "delete"), J(dataRows));
  const order = YD.DELETE_ORDER || [];
  check("H2. both are in DELETE_ORDER once, firings before triggers", order.filter(x => x === "trigger_firings").length === 1 && order.filter(x => x === "member_triggers").length === 1 &&
    order.indexOf("trigger_firings") < order.indexOf("member_triggers"), J(order.slice(-4)));
  check("H3. lib/backup.js backs up both", /"member_triggers",/.test(FILES.backup) && /"trigger_firings",/.test(FILES.backup));
  const sql = FILES.migration;
  const code = sql.split("\n").filter(l => !/^\s*--/.test(l)).join("\n");
  check("H4. 160_member_triggers.sql is the only migration numbered 160", fs.readdirSync(path.join(REPO, "supabase/migrations")).filter(f => /^160_/.test(f)).length === 1);
  check("H4. member_triggers has the columns, metric_window (window is reserved), the cooldown range and the action object",
    ["id uuid PRIMARY KEY", "user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE", "name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 60)",
      "metric_window text NOT NULL", "cooldown_hours integer NOT NULL DEFAULT 24 CHECK (cooldown_hours BETWEEN 6 AND 168)",
      "action jsonb NOT NULL CHECK (jsonb_typeof(action) = 'object'", "enabled boolean NOT NULL DEFAULT true", "last_fired_at", "last_value", "created_at", "updated_at"]
      .every(x => code.replace(/\s+/g, " ").indexOf(x.replace(/\s+/g, " ")) !== -1));
  const metricList = /metric\s+text NOT NULL CHECK \(metric IN \(([^)]*)\)\)/.exec(code);
  check("H4. the metric list equals lib/triggers.js", !!metricList && J(metricList[1].replace(/\s+/g, "").split(",").map(x => x.replace(/'/g, ""))) === J(T.METRIC_KEYS), metricList && metricList[1]);
  const cmpList = /comparator\s+text NOT NULL CHECK \(comparator IN \(([^)]*)\)\)/.exec(code);
  check("H4. the comparator list equals lib/triggers.js", !!cmpList && J(cmpList[1].replace(/\s+/g, "").split(",").map(x => x.replace(/'/g, ""))) === J(T.COMPARATOR_KEYS));
  const winList = /metric_window\s+text NOT NULL CHECK \(metric_window IN \(([^)]*)\)\)/.exec(code);
  check("H4. the window list equals lib/triggers.js", !!winList && J(winList[1].replace(/\s+/g, "").split(",").map(x => x.replace(/'/g, ""))) === J(T.WINDOW_KEYS));
  const outList = /outcome\s+text NOT NULL CHECK \(outcome IN \(([^)]*)\)\)/.exec(code);
  check("H4. trigger_firings: trigger_id cascading, metric value, fired_at, outcome (equal to lib/triggers.js), action_ref, gate_decision_id",
    /trigger_id\s+uuid NOT NULL REFERENCES public\.member_triggers\(id\) ON DELETE CASCADE/.test(code) && /metric_value\s+numeric/.test(code) && /fired_at\s+timestamptz NOT NULL DEFAULT now\(\)/.test(code) &&
    /gate_decision_id\s+uuid/.test(code) && !!outList && J(outList[1].replace(/\s+/g, "").split(",").map(x => x.replace(/'/g, ""))) === J(T.FIRING_OUTCOMES));
  check("H4. row level security on both, with no policy and no grant", /ALTER TABLE public\.member_triggers ENABLE ROW LEVEL SECURITY;/.test(code) &&
    /ALTER TABLE public\.trigger_firings ENABLE ROW LEVEL SECURITY;/.test(code) && !/CREATE POLICY|GRANT /i.test(code));
  check("H4. paused_reason gains 'trigger', keeping 'owner' and 'failures'", /CHECK \(paused_reason IS NULL OR paused_reason IN \('owner', 'failures', 'trigger'\)\)/.test(code));
  check("H4. the migration only creates, alters and indexes: no DROP TABLE, DELETE, UPDATE or TRUNCATE", !/DROP TABLE|DELETE FROM|^\s*UPDATE\b|TRUNCATE/im.test(code));

  /* ═══ U. the UI, in jsdom ════════════════════════════════════════════════ */
  console.log("\n══ U. Triggers in HQ: templates, builder, preview, list, firings with Why ══");
  let JSDOM = null; try { JSDOM = require("jsdom").JSDOM; } catch (e) { JSDOM = null; }
  check("U0. jsdom is available", !!JSDOM);
  const LANG = JSON.parse(J(T.language({ owner: false })));
  const LANG_O = JSON.parse(J(T.language({ owner: true })));
  function page(html, answer, scripts) {
    const dom = new JSDOM("<!doctype html><html><head></head><body>" + html + "</body></html>", { runScripts: "outside-only", url: "https://bizforceai.net/executive-agent.html" });
    const calls = [];
    dom.window.fetch = function (url, init) {
      const u = String(url).replace("https://dynamic-prosperity-production-5382.up.railway.app", "");
      calls.push({ method: (init && init.method) || "GET", url: u, body: init && init.body ? JSON.parse(init.body) : undefined });
      const a = answer(u, init || {});
      return Promise.resolve({ status: a.status || 200, ok: (a.status || 200) < 400, json: () => Promise.resolve(JSON.parse(J(a.body))) });
    };
    (scripts || []).forEach(s => dom.window.eval(s));
    return { dom, w: dom.window, d: dom.window.document, calls };
  }
  if (JSDOM) {
    const rowsUi = [
      Object.assign(T.fromRow(trig(A, 1401, T.TEMPLATES[1].body)), { last_value: 3, last_checked_at: ago(H), last_fired_at: ago(2 * H) }),
      Object.assign(T.fromRow(Object.assign(trig(A, 1402, T.TEMPLATES[0].body), { enabled: false })), {})
    ].map(t => Object.assign(t, { summary: T.summarize(t) }));
    const DEC = UUID(9101), DRAFT = UUID(9201);
    const firingsUi = [
      { id: UUID(9301), trigger_id: UUID(1401), trigger_name: "Runs failing", metric_value: 3, threshold: 3, fired_at: ago(2 * H), outcome: "fired", action_ref: "saved_prompt:" + DRAFT, gate_decision_id: DEC },
      { id: UUID(9302), trigger_id: UUID(1402), trigger_name: "Stock at reorder point", metric_value: 2, threshold: 0, fired_at: ago(3 * H), outcome: "skipped_daily_cap", action_ref: null, gate_decision_id: null }
    ];
    const explained = GATES.explain({ id: DEC, action: "trigger_fire", target: "trigger:" + UUID(1401), outcome: "ran", created_at: ago(2 * H), results: [{ gate: "G13", result: "pass" }, { gate: "G9", result: "pass" }] });
    const serve = (u, init) => {
      const m = (init.method || "GET");
      if (u === "/api/triggers/language") return { body: LANG };
      if (u === "/api/triggers" && m === "GET") return { body: { triggers: rowsUi, enabled_on_server: false } };
      if (u.indexOf("/api/triggers/firings") === 0) return { body: { firings: firingsUi, page: 1, pages: 1, total: 2, per_page: 20 } };
      if (u === "/api/triggers" && m === "POST") { const b = JSON.parse(init.body); return { status: 201, body: { trigger: Object.assign(T.fromRow(trig(A, 1499, b)), { summary: T.summarize(b) }) } }; }
      if (u.indexOf("/api/triggers/") === 0 && m === "PUT") return { body: { trigger: rowsUi[0] } };
      if (u === "/api/triggers/preview") return { body: { summary: "x", value_now: 3, previous: null, would_fire_now: true, days: 30, replay: true, fired_at: ["2026-10-10T05:30:00.000Z", "2026-10-20T08:30:00.000Z"], count: 2, capped: false, note: null } };
      if (u === "/api/gate-decisions/" + DEC) return { body: { decision: explained } };
      if (u.indexOf("/api/saved-prompts/") === 0) return { body: { task_id: "t", status: "requires_approval" } };
      return { status: 404, body: { error: "no" } };
    };
    const P = page("<div id=\"deckTriggers\"></div>", serve, [FILES.why, FILES.ui]);
    await flush(20);
    const d = P.d;
    check("U1. the Triggers section mounts on #deckTriggers with its heading", !!d.getElementById("bfTrgTitle") && d.getElementById("bfTrgTitle").textContent === "Triggers");
    const empty = d.getElementById("bfTrgEmpty").textContent;
    check("U1. the empty-state copy says plainly what triggers do and that publishing still needs approval",
      empty === P.w.BFTriggers.EMPTY_COPY && /watches one number from your own account/.test(empty) && /raises an alert, has an agent draft a task for you, or pauses an agent's schedules/.test(empty) &&
      /never publishes or sends anything/.test(empty) && /still waits for your approval/.test(empty), empty);
    check("U1. the server-off note says none will fire until triggers are switched on", /switched off on the server right now, so none will fire/.test(d.getElementById("bfTrgServer").textContent));
    const tps = [...d.querySelectorAll(".bf-trg-template")];
    check("U2. six templates, each with its title, the server's summary and \"Use this template\"",
      tps.length === 6 && tps.every((li, i) => li.querySelector("strong").textContent === T.TEMPLATES[i].title && li.querySelector("p").textContent === T.summarize(T.TEMPLATES[i].body) &&
        li.querySelector("button").textContent === "Use this template"), tps.length);
    tps[0].querySelector("button").click(); await flush(20);
    const posted = P.calls.filter(c => c.method === "POST" && c.url === "/api/triggers");
    check("U2. one press creates it: one POST /api/triggers with exactly the template's body, then it is in the builder to edit",
      posted.length === 1 && J(posted[0].body) === J(T.TEMPLATES[0].body) && d.getElementById("bfTrgName").value === "Stock at reorder point" &&
      d.getElementById("bfTrgSave").textContent === "Save changes", J(posted));
    const items = [...d.querySelectorAll(".bf-trg-item")];
    const sw = items.map(li => li.querySelector("input[role=switch]"));
    check("U3. the list: each trigger with its on/off switch, its summary, its last value and last fired time",
      items.length === 2 && sw[0].checked === true && sw[1].checked === false && sw[0].getAttribute("aria-label") === "On: Runs failing" &&
      items[0].textContent.indexOf(rowsUi[0].summary) !== -1 && /Last value: 3, read /.test(items[0].textContent) && /Last fired: /.test(items[0].textContent) &&
      /Not read yet\./.test(items[1].textContent) && /Never fired\./.test(items[1].textContent), items.map(i => i.textContent).join(" | "));
    sw[0].checked = false; sw[0].dispatchEvent(new P.w.Event("change", { bubbles: true })); await flush(20);
    const put = P.calls.filter(c => c.method === "PUT");
    check("U3. the switch sends PUT /api/triggers/:id with { enabled: false } only", put.length === 1 && put[0].url === "/api/triggers/" + UUID(1401) && J(put[0].body) === J({ enabled: false }), J(put));
    const ids = ["bfTrgMetric", "bfTrgComparator", "bfTrgThreshold", "bfTrgWindow", "bfTrgCooldown", "bfTrgAction"];
    check("U4. the builder is dropdowns: metric, comparator, threshold, window, cooldown, action", ids.every(id => !!d.getElementById(id)) &&
      [...d.getElementById("bfTrgMetric").options].map(o => o.value).join() === Object.keys(LANG.metrics).join());
    const set = (id, v) => { const e = d.getElementById(id); e.value = v; e.dispatchEvent(new P.w.Event("change", { bubbles: true })); };
    d.getElementById("bfTrgNew").click();
    set("bfTrgMetric", "blog_arrivals"); set("bfTrgComparator", "drop_pct"); set("bfTrgWindow", "7d");
    const thEl = d.getElementById("bfTrgThreshold"); thEl.value = "50"; thEl.dispatchEvent(new P.w.Event("input", { bubbles: true }));
    set("bfTrgCooldown", "168"); set("bfTrgAction", "draft_task"); set("bfTrgActionAgent", "seo");
    const want = T.summarize(T.TEMPLATES[4].body);
    check("U4. the live summary follows the dropdowns and is lib/triggers.js's sentence", d.getElementById("bfTrgSummary").textContent === want, d.getElementById("bfTrgSummary").textContent);
    const writesBefore = P.calls.filter(c => c.method !== "GET").length;
    d.getElementById("bfTrgPreview").click(); await flush(20);
    const after = P.calls.filter(c => c.method !== "GET").slice(writesBefore);
    check("U5. \"Preview last 30 days\" sends one POST /api/triggers/preview and nothing else", after.length === 1 && after[0].url === "/api/triggers/preview" &&
      after[0].body.metric === "blog_arrivals" && after[0].body.comparator === "drop_pct", J(after));
    const pout = d.getElementById("bfTrgPreviewOut").textContent;
    check("U5. it says the value now, whether it would fire now, how many times in 30 days with the dates, and that nothing was changed",
      /^Now: 3\. It would fire now\. In the last 30 days it would have fired 2 times: .+\. Nothing was changed\.$/.test(pout), pout);
    // the property: the builder's sentence equals the server's on random triggers
    let mismatches = [];
    const rnd = (() => { let s = 12345; return () => (s = (s * 1103515245 + 12345) % 2147483648) / 2147483648; })();
    const pick = a => a[Math.floor(rnd() * a.length)];
    let made = 0;
    for (let i = 0; i < 4000 && made < 600; i++) {
      const metric = pick(T.METRIC_KEYS); const m = T.METRICS[metric];
      const comparator = pick(T.COMPARATOR_KEYS);
      const body = { name: "R" + i, metric, comparator, window: pick(m.windows), cooldown_hours: pick(T.COOLDOWNS),
        threshold: comparator === "drop_pct" ? 1 + Math.floor(rnd() * 100) : (m.kind === "bfc" ? Math.round(rnd() * 100000) / 100 : Math.floor(rnd() * Math.min(m.max, 200))),
        action: pick([{ kind: "raise_alert" }, { kind: "draft_task", agent: pick(T.AGENTS) }, { kind: "pause_schedule", agent: pick(T.AGENTS) }]) };
      if (m.needsAgent) body.metric_agent = pick(T.AGENTS);
      if (rnd() < 0.1 && metric === "stock_at_reorder") { body.comparator = pick(["gt", "gte"]); body.threshold = body.comparator === "gt" ? 0 : 1; }
      const v = T.validateTrigger(body, null, { owner: true });
      if (!v.ok) continue;
      made++;
      const a = P.w.BFTriggers.summarize(LANG_O, v.value), b = T.summarize(v.value);
      if (a !== b) mismatches.push([a, b]);
    }
    check("U6. PROPERTY: the builder's summary equals lib/triggers.js summarize() on " + made + " random valid triggers", made >= 600 && mismatches.length === 0, J(mismatches.slice(0, 2)));
    const fl = [...d.querySelectorAll(".bf-trg-firing")];
    const why = fl[0] && fl[0].querySelector("[data-bf-why-id]");
    check("U7. the firings history: each with its time, trigger, outcome and value; a firing that reached the gates has \"Why?\" with its decision id",
      fl.length === 2 && !!why && why.getAttribute("data-bf-why-id") === DEC && why.textContent === "Why?" && /Fired/.test(fl[0].textContent) && /Runs failing/.test(fl[0].textContent), fl.map(x => x.innerHTML).join(" | "));
    check("U7. a daily-limit skip says no check was asked, since the limit stopped it first", fl[1] && !fl[1].querySelector("[data-bf-why-id]") &&
      /Skipped: the daily limit of firings was reached/.test(fl[1].textContent) && /No check was asked: the daily limit stopped it first\./.test(fl[1].textContent));
    why.click(); await flush(20);
    const panel = d.querySelector(".bf-why-panel");
    check("U7. \"Why?\" opens bf-why's panel from GET /api/gate-decisions/:id, the gates in order", P.calls.some(c => c.url === "/api/gate-decisions/" + DEC) && panel && !panel.hidden &&
      J([...panel.querySelectorAll(".bf-why-gate")].map(l => l.getAttribute("data-gate"))) === J(["G13", "G9"]));
    const run = fl[0].querySelector("[data-trg-run]");
    check("U8. a drafted task offers \"Run the draft\"", !!run && run.textContent === "Run the draft" && run.getAttribute("data-trg-run") === DRAFT);
    run.click(); await flush(20);
    check("U8. it runs through POST /api/saved-prompts/:id/run, the normal task route, and says approval still holds",
      P.calls.some(c => c.method === "POST" && c.url === "/api/saved-prompts/" + DRAFT + "/run") && /waits for your approval/.test(d.getElementById("bfTrgNote").textContent), d.getElementById("bfTrgNote").textContent);
    const html = FILES.execHtml;
    const settings = html.indexOf("id=\"deckPanel-settings\"");
    const region = html.indexOf("<div id=\"deckTriggers\" role=\"region\" aria-label=\"Triggers\"></div>");
    const nextPanel = html.indexOf("class=\"deck-panel\"", settings + 10);
    check("U9. executive-agent.html: #deckTriggers sits in HQ's Settings tab, and bf-triggers.js loads after bf-why.js",
      settings > 0 && region > settings && (nextPanel === -1 || region < nextPanel) && html.indexOf("<script src=\"/scripts/bf-why.js\"></script>\n<script src=\"/scripts/bf-triggers.js\"></script>") !== -1);
    check("U9. the schedule card names a pause by a trigger", /pausedTrigger:\s+"Paused by one of your triggers\. It will not run until you press Resume\."/.test(FILES.profile) &&
      /row\.paused_reason === "trigger" \? SCHED_WORDS\.pausedTrigger/.test(FILES.profile));
    const bad = page("<div id=\"deckTriggers\"></div>", u => u === "/api/triggers/language" ? { body: { metrics: {} } } : { body: {} }, [FILES.ui]);
    await flush(20);
    check("U10. a malformed trigger language: \"Triggers could not load.\" and nothing throws", /^Triggers could not load\./.test(bad.d.getElementById("bfTrgNote").textContent) && UNHANDLED.length === 0,
      bad.d.getElementById("bfTrgNote").textContent + " " + UNHANDLED.map(String).join(" "));
  }

  /* ═══ Z. Part 0: bf-why.js and a malformed language ══════════════════════ */
  console.log("\n══ Z. bf-why.js treats a malformed /api/member-gates/language as no language ══");
  if (JSDOM) {
    const GL = JSON.parse(J(RULES.language()));
    const variants = [
      ["fields missing", (() => { const x = JSON.parse(J(GL)); delete x.fields; return x; })()],
      ["scopes missing", (() => { const x = JSON.parse(J(GL)); delete x.scopes; return x; })()],
      ["comparators missing", (() => { const x = JSON.parse(J(GL)); delete x.comparators; return x; })()],
      ["limits missing", (() => { const x = JSON.parse(J(GL)); delete x.limits; return x; })()],
      ["fields without an agent field", (() => { const x = JSON.parse(J(GL)); delete x.fields.agent; return x; })()],
      ["an empty object", {}]
    ];
    const rows = [0, 1, 2].map(i => ({ id: UUID(9500 + i), action: "schedule_run", target: "schedule:" + UUID(9500 + i), outcome: "ran", created_at: ago(i * H), agent: "seo",
      gates: [{ gate: "G18", name: "Schedule pause", result: "pass", code: null, reason: "Passed." }], member: null }));
    for (const [what, lang] of variants) {
      const before = UNHANDLED.length;
      const Pz = page("<div id=\"deckDecisions\"></div><div id=\"deckMemberGates\"></div>", u => {
        if (u === "/api/member-gates/language") return { body: lang };
        if (u.indexOf("/api/gate-decisions") === 0) return { body: { decisions: rows, page: 1, pages: 1, total: 3, per_page: 20 } };
        if (u === "/api/member-gates") return { body: { gates: [] } };
        return { body: {} };
      }, [FILES.why]);
      await flush(20);
      const listed = Pz.d.querySelectorAll("#bfWhyList .bf-why-item").length;
      const agentOpts = [...Pz.d.getElementById("bfWhyAgent").options].map(o => o.value);
      const note = Pz.d.getElementById("bfGateNote").textContent;
      check("Z. " + what + ": the Decisions list still renders its rows, the agent filter offers only \"All agents\", the builder says it could not load, nothing throws",
        listed === 3 && J(agentOpts) === J([""]) && note === "The gate builder could not load. Reload the page to try again." && UNHANDLED.length === before,
        J({ listed, agentOpts, note, thrown: UNHANDLED.slice(before).map(e => String(e && e.message || e)) }));
    }
    const Pok = page("<div id=\"deckDecisions\"></div>", u => u === "/api/member-gates/language" ? { body: GL } : { body: { decisions: rows, page: 1, pages: 1, total: 3 } }, [FILES.why]);
    await flush(20);
    check("Z. a whole language still fills the agent filter (the guard refuses only the malformed)", Pok.d.getElementById("bfWhyAgent").options.length === RULES.AGENTS.length + 1);
  }

  /* ═══ S. no emoji ═══════════════════════════════════════════════════════ */
  console.log("\n══ S. no emoji ══");
  const EMOJI = /[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}\u{2B00}-\u{2BFF}\u{FE0F}]/u;
  const files = { "lib/triggers.js": FILES.triggers, "lib/triggerRunner.js": FILES.runner, "migration 160": FILES.migration, "scripts/bf-triggers.js": FILES.ui };
  check("S1. no emoji in lib/triggers.js, lib/triggerRunner.js, migration 160 or scripts/bf-triggers.js", Object.keys(files).every(k => !EMOJI.test(files[k])),
    Object.keys(files).filter(k => EMOJI.test(files[k])).join());

  check("no unhandled rejection or uncaught error anywhere", UNHANDLED.length === 0, UNHANDLED.map(e => (e && e.stack) || String(e)).join(" | ").slice(0, 400));
  console.log("\n" + (failures ? "CHECKS FAILED: " + failures + " of " + (failures + passes) : "ALL CHECKS PASSED (" + passes + ")"));
  process.exit(failures ? 1 : 0);
})().catch(e => { console.log("    FAIL  the check itself threw: " + ((e && e.stack) || e)); process.exit(1); });
