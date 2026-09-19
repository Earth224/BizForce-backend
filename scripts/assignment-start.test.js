"use strict";
/* Extracts POST /api/assignments/:id/start and its helper closure from server.js
   (working copy) and from git HEAD, runs both in vm contexts against a scripted
   fake agent_assignments table and a recording orchestrateAgentWorkflow stub.
   No network, no database. */
const fs = require("fs");
const vm = require("vm");
const assert = require("assert");
const { execSync } = require("child_process");

const REPO = "C:/Users/ALGORITHM/BizForce-backend";
const after = fs.readFileSync(REPO + "/server.js", "utf8");
const before = execSync("git show HEAD:server.js", { cwd: REPO, maxBuffer: 64 * 1024 * 1024 }).toString("utf8");

/* ── extraction (same machinery as tool-run-all.test.js) ────────────────── */
function braceMatch(src, openIdx) { let d = 0; for (let i = openIdx; i < src.length; i++) { const c = src[i]; if (c === "{") d++; else if (c === "}") { d--; if (d === 0) return i + 1; } } return -1; }
const SPANS = new Map();
function spansOf(src) {
  if (SPANS.has(src)) return SPANS.get(src);
  const out = []; const re = new RegExp("^(?:(?:async )?function [A-Za-z_$][A-Za-z0-9_$]*[(]|app[.][a-z]+[(])", "gm"); let m;
  while ((m = re.exec(src))) { const open = src.indexOf("{", m.index); const end = braceMatch(src, open); if (end > 0) out.push([m.index, end]); }
  SPANS.set(src, out); return out;
}
function insideSpan(src, idx) { return spansOf(src).some(([a, b]) => idx > a && idx < b); }
const DEF = new Map();
function definitionOf(src, name) {
  const key = (src === after ? "A:" : "B:") + name; if (DEF.has(key)) return DEF.get(key);
  let v = null, m = new RegExp("^(?:async )?function " + name + "\\(", "m").exec(src);
  if (m) v = src.slice(m.index, braceMatch(src, src.indexOf("{", m.index)));
  else {
    const re = new RegExp("^(?:var|const|let) " + name + "[ \\t]*=[ \\t]*", "gm");
    while ((m = re.exec(src)) && insideSpan(src, m.index)) {}
    if (m) { let from = m.index + m[0].length; for (;;) { const semi = src.indexOf(";\n", from); if (semi === -1) break; const n = src[semi + 2]; if (n === undefined || n === "\n" || /[^\s]/.test(n)) { v = src.slice(m.index, semi + 1); break; } from = semi + 1; } }
  }
  DEF.set(key, v); return v;
}
const STUBS = new Set(["supabase", "nowIso", "console", "process", "require", "module", "orchestrateAgentWorkflow", "requireAuth", "app", "AGENT_SYSTEM_PROMPTS", "buildAgentSystemPrompt", "getLiveStats", "callAnthropicText", "resolvePreferredLanguage", "buildLanguageInstruction", "SALES_AGENT_BRAIN"]);
function closureFor(src, rootCode) {
  const have = new Map(); const queue = [...new Set(rootCode.match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  while (queue.length) { const n = queue.shift(); if (have.has(n) || STUBS.has(n)) continue; const d = definitionOf(src, n); if (!d) continue; try { new vm.Script(d); } catch (e) { continue; } have.set(n, d); new Set(d.match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(i => { if (!have.has(i) && !STUBS.has(i)) queue.push(i); }); }
  return [...have.values()].join("\n\n") + "\n\n" + rootCode;
}
function routeCode(src) {
  const sig = 'app.post("/api/assignments/:id/start"'; const s = src.indexOf(sig); assert(s > 0);
  const e = braceMatch(src, src.indexOf("{", s)); assert.strictEqual(src.slice(e, e + 3), ");\n"); return src.slice(s, e + 2);
}

/* ── fake agent_assignments ─────────────────────────────────────────────── */
/* plan: { row, claimRow, releaseError, lostRaceRow } */
function fakeSupabase(plan) {
  const writes = [];
  function chain(op, payload) {
    const w = { op, payload, filters: [] }; writes.push(w);
    const c = {
      eq(k, v) { w.filters.push(["eq", k, v]); return c; },
      in(k, v) { w.filters.push(["in", k, v]); return c; },
      select(cols) { w.select = cols; return c; },
      async maybeSingle() { return terminal(w); },
      async single() { return terminal(w); },
      then(r) { return Promise.resolve(terminal(w)).then(r); }
    };
    return c;
  }
  function terminal(w) {
    if (w.op === "select") return { data: plan.row === undefined ? null : plan.row, error: null };
    if (w.op === "update") {
      const st = w.payload.status;
      if (st === "in_progress") return { data: plan.claimRow === undefined ? null : plan.claimRow, error: null };   // the claim
      if (st === "pending" || st === "completed") return plan.releaseError ? { data: null, error: plan.releaseError } : { data: Object.assign({}, plan.claimRow, { status: st, updated_at: "T1" }), error: null };
      if (st === "failed") return { data: null, error: null };
    }
    return { data: null, error: null };
  }
  return { writes, client: { from(t) { assert.strictEqual(t, "agent_assignments", "unexpected table " + t); return { select(cols) { const c = chain("select"); c.select(cols); return c; }, update(p) { return chain("update", p); } }; } } };
}

function build(src, plan) {
  const sb = fakeSupabase(plan); const logs = [], orchCalls = [];
  const ctx = {
    supabase: sb.client, nowIso: () => "T1", process: { env: {} },
    console: { log: (m, o) => logs.push([m, o]), error: (m) => logs.push(["error", String(m)]) },
    requireAuth: 0,
    orchestrateAgentWorkflow: async (o) => { orchCalls.push(JSON.parse(JSON.stringify(o))); return { memory_created: false, collaboration_created: false, sales_call_result: null }; }
  };
  let handler = null; ctx.app = { post() { handler = arguments[arguments.length - 1]; } };
  vm.createContext(ctx); vm.runInContext(closureFor(src, routeCode(src)), ctx);
  return { handler, writes: sb.writes, logs, orchCalls };
}
async function call(handler, id, body) {
  const res = { statusCode: 200, body: undefined, status(c) { this.statusCode = c; return this; }, json(b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
  let nextErr = null; await handler({ user: { id: "u1" }, params: { id }, body: body || {} }, res, (e) => { nextErr = e || new Error("next"); });
  return { status: res.statusCode, body: res.body, nextErr };
}
const norm = (v) => JSON.parse(JSON.stringify(v));

const UUID = "3f1b2c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
const ROW = { id: UUID, user_id: "u1", executive_task_id: "x", assignment_number: 1, agent_type: "seo",
  mission: "Rank the wool hat page", priority: "high", timeline: "2 weeks",
  tasks: ["Audit the page", "Pick keywords"], kpis: ["Top 10 for wool hat"], risks: ["Thin content"], status: "pending", created_at: "T0", updated_at: "T0" };
const CLAIMED = Object.assign({}, ROW, { status: "in_progress", updated_at: "T1" });

const FORBIDDEN = [/EXECUTION REPORT/, /Status: Complete/, /Mission Accepted/, /^Status:/m, /\bcompleted\b/i, /\bwas executed\b/i, /\bhas been done\b/i, /\bwere executed\b/i, /\bdelivered\b/i, /\bfinished\b/i, /\baccomplished\b/i, /(?<!No agent )\bhas run\b/];

let failures = 0;
async function t(name, fn) { try { await fn(); console.log("PASS " + name); } catch (e) { failures++; console.log("FAIL " + name + ": " + e.message); } }

(async () => {
  // a) text claims — on both the persisted-row output and the frontend default (no tasks) output
  await t("a) template text makes no claim of work performed (real output, two fixtures)", async () => {
    const h = build(after, { row: ROW, claimRow: CLAIMED });
    const r = await call(h.handler, UUID);
    assert.strictEqual(r.status, 200, r.nextErr && r.nextErr.message);
    const text = r.body.result;
    assert(/^SEO AGENT STARTING PLAN \(TEMPLATE\)\n/.test(text) || /^[A-Z &]+ STARTING PLAN \(TEMPLATE\)\n/.test(text), text.split("\n")[0]);
    assert(/^This is a starting checklist generated from the assignment's own fields\. No agent has run and nothing has been executed\.$/m.test(text));
    FORBIDDEN.forEach(re => assert(!re.test(text), "forbidden " + re + " in:\n" + text));
    assert(/\nMission\nRank the wool hat page\n/.test(text));
    assert(/\nPlan to follow\n1\. Audit the page\n2\. Pick keywords\n/.test(text));
    assert(/\nSuccess criteria to meet\n- Top 10 for wool hat\n/.test(text));
    assert(/\nRecommended handoff\nSuggested next agent: .*Content.*\. Consider handing off there once this work is actually done/.test(text), text.slice(-300));
    // frontend default: no tasks/kpis/risks → canned bullets and defaults must also be clean
    const h2 = build(after, {});
    const r2 = await call(h2.handler, "asg_1_abc", { agent_type: "analytics", mission: "m" });
    FORBIDDEN.forEach(re => assert(!re.test(r2.body.result), "forbidden " + re + " in default:\n" + r2.body.result));
    assert(/No automatic handoff is configured|Suggested next agent/.test(r2.body.result));
    // and an agent with no handoff rule
    const h3 = build(after, {});
    const r3 = await call(h3.handler, "asg_1_abc", { agent_type: "ads", mission: "m" });
    assert(/\nRecommended handoff\nNo automatic handoff is configured for this agent\.$/.test(r3.body.result), r3.body.result.slice(-120));
    console.log("   ── skeleton ──\n" + r2.body.result.split("\n").map(l => "   " + l).join("\n"));
  });

  // b) persisted-row branch transitions
  await t("b) persisted row: claim in_progress, then written pending, never completed; executed false", async () => {
    const h = build(after, { row: ROW, claimRow: CLAIMED });
    const r = await call(h.handler, UUID);
    assert.strictEqual(r.status, 200);
    const w = norm(h.writes);
    const updates = w.filter(x => x.op === "update");
    assert.deepStrictEqual(updates.map(u => u.payload.status), ["in_progress", "pending"]);
    assert.deepStrictEqual(updates[0].filters, [["eq", "id", UUID], ["eq", "user_id", "u1"], ["in", "status", ["pending", "failed"]]]);
    assert.deepStrictEqual(updates[1].filters, [["eq", "id", UUID], ["eq", "user_id", "u1"]]);
    assert(!JSON.stringify(w).includes('"completed"'), "a completed write happened");
    assert.strictEqual(r.body.executed, false);
    assert.strictEqual(r.body.assignment.status, "pending");
    assert.strictEqual(h.orchCalls.length, 1);
    assert.strictEqual(h.orchCalls[0].assignment.status, "pending");
    assert.strictEqual(h.orchCalls[0].resultText, r.body.result);
  });

  // c) frontend branch
  await t("c) frontend asg_* branch: no table write, status not completed, executed false", async () => {
    const h = build(after, {});
    const r = await call(h.handler, "asg_1700000000_abc", { agent_type: "seo", mission: "Rank it", priority: "high", timeline: "1 week", tasks: ["a", "b"] });
    assert.strictEqual(r.status, 200);
    assert.deepStrictEqual(h.writes, []);
    assert.notStrictEqual(r.body.assignment.status, "completed");
    assert.strictEqual(r.body.assignment.status, "pending");
    assert.strictEqual(r.body.executed, false);
    assert.strictEqual(h.orchCalls[0].assignment.status, "pending");
    assert.strictEqual(h.orchCalls[0].isFrontendAssignment, true);
    // client-supplied result is still passed through untouched
    const h2 = build(after, {});
    const r2 = await call(h2.handler, "asg_1_x", { agent_type: "seo", result: "client text" });
    assert.strictEqual(r2.body.result, "client text");
  });

  // d) throw inside the window → failed
  await t("d) a throw inside the window still writes failed", async () => {
    const h = build(after, { row: ROW, claimRow: CLAIMED, releaseError: { message: "release-down" } });
    const r = await call(h.handler, UUID);
    assert(r.nextErr && /release-down/.test(r.nextErr.message), r.nextErr && r.nextErr.message);
    const st = norm(h.writes).filter(x => x.op === "update").map(u => u.payload.status);
    assert.deepStrictEqual(st, ["in_progress", "pending", "failed"]);
    assert.strictEqual(h.orchCalls.length, 0);
  });

  // e) 409 lost race unchanged
  await t("e) lost race → 409 unchanged; completed row → already-completed unchanged", async () => {
    const h = build(after, { row: ROW, claimRow: null });       // claim returns nothing, re-read says pending
    const r = await call(h.handler, UUID);
    const h0 = build(before, { row: ROW, claimRow: null });
    const r0 = await call(h0.handler, UUID);
    assert.strictEqual(r.status, 409);
    assert.deepStrictEqual(r, r0);
    const done = Object.assign({}, ROW, { status: "completed" });
    const hc = build(after, { row: done }), hc0 = build(before, { row: done });
    assert.deepStrictEqual(await call(hc.handler, UUID), await call(hc0.handler, UUID));
    // validation paths unchanged too
    const hv = build(after, {}), hv0 = build(before, {});
    assert.deepStrictEqual(await call(hv.handler, "not-an-id"), await call(hv0.handler, "not-an-id"));
    const hu = build(after, { row: Object.assign({}, ROW, { agent_type: "ads" }) }), hu0 = build(before, { row: Object.assign({}, ROW, { agent_type: "ads" }) });
    assert.deepStrictEqual(await call(hu.handler, UUID), await call(hu0.handler, UUID));
  });

  // f) every other key byte-identical
  await t("f) every response key other than result / executed / assignment.status identical to pre-change", async () => {
    for (const [id, body, plan] of [[UUID, {}, { row: ROW, claimRow: CLAIMED }], ["asg_1_abc", { agent_type: "seo", mission: "Rank it", priority: "high", timeline: "1 week", tasks: ["a"] }, {}]]) {
      const r = await call(build(after, plan).handler, id, body);
      const r0 = await call(build(before, plan).handler, id, body);
      assert.strictEqual(r.status, r0.status);
      const scrub = (b) => { const c = JSON.parse(JSON.stringify(b)); delete c.result; delete c.executed; if (c.assignment) delete c.assignment.status; return c; };
      assert.deepStrictEqual(scrub(r.body), scrub(r0.body));
      assert.deepStrictEqual(Object.keys(r.body), Object.keys(r0.body).concat(["executed"]));
      assert.strictEqual(r0.body.assignment.status, "completed", "pre-change should have said completed");
      assert(/EXECUTION REPORT/.test(r0.body.result) && /Status: Complete/.test(r0.body.result), "pre-change text should have carried the old claims");
    }
  });

  console.log("failures: " + failures);
  process.exitCode = failures ? 1 : 0;
})();
