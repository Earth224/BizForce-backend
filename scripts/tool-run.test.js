"use strict";
/* Extracts the REAL startToolRun, renderToolOutputMarkdown, toolProvenance, the
   parsing helpers, and both pilot routes (as app.post(...) calls) from server.js
   — and the pre-change routes from git HEAD — and runs them in vm contexts with
   a fake Supabase and a stubbed callAnthropicText. No network, no database. */
const fs = require("fs");
const vm = require("vm");
const assert = require("assert");
const { execSync } = require("child_process");

const REPO = "C:/Users/ALGORITHM/BizForce-backend";
const after = fs.readFileSync(REPO + "/server.js", "utf8");
const before = execSync("git show HEAD:server.js", { cwd: REPO, maxBuffer: 64 * 1024 * 1024 }).toString("utf8");

function braceBlock(src, signature, keepTail) {
  const start = src.indexOf(signature);
  assert(start > 0, signature + " not found");
  let depth = 0, i = src.indexOf("{", start), end = -1;
  for (; i < src.length; i++) {
    const c = src[i];
    if (c === "{") depth++;
    else if (c === "}") { depth--; if (depth === 0) { end = i + 1; break; } }
  }
  if (keepTail) { assert.strictEqual(src.slice(end, end + 3), ");\n", "unexpected tail"); end += 2; }
  return src.slice(start, end);
}
function varStmt(src, name) {
  const start = src.indexOf("\nvar " + name + " =") + 1;
  assert(start > 0, name + " not found");
  const end = src.indexOf(";\n", start);
  return src.slice(start, end + 1);
}

const HELPERS = [
  "function safeText(value, maxLength) {", "function countWords(text) {", "function escapeForRegex(",
  "function parseLabeledFields(text, fields) {", "function splitToolBlocks(text) {",
  "function parseToolLines(text) {", "function scanInventedFigures(text) {",
  "function extractArticleHeadings(text) {", "function auditHeadingNesting(headings) {",
  "function toolProvenance(measured, inferred, caveat, extra) {"
];
const VARS = ["RD_INVENTED_FIGURE_PATTERNS", "RD_READS_NOTHING", "RD_PROVENANCE_FLAGS", "ARTICLE_LONG_PARAGRAPH_WORDS"];

function commonCode(src) {
  return HELPERS.map(s => braceBlock(src, s)).concat(VARS.map(v => varStmt(src, v))).join("\n");
}
const afterCode = commonCode(after) + "\n" + varStmt(after, "TOOL_RESULT_MARKDOWN_CAP") + "\n" +
  braceBlock(after, "function renderToolOutputMarkdown(output) {") + "\n" +
  braceBlock(after, "async function startToolRun(req, options) {") + "\n" +
  braceBlock(after, 'app.post("/api/agents/rd/competitor-scan"', true) + "\n" +
  braceBlock(after, 'app.post("/api/agents/content/audit"', true);
const beforeCode = commonCode(before) + "\n" +
  braceBlock(before, 'app.post("/api/agents/rd/competitor-scan"', true) + "\n" +
  braceBlock(before, 'app.post("/api/agents/content/audit"', true);

/* fake supabase for ai_tasks only: records inserts/updates, returns per-plan errors */
function fakeSupabase(plan) {
  const writes = [];
  return {
    writes,
    client: {
      from(table) {
        assert.strictEqual(table, "ai_tasks", "unexpected table " + table);
        return {
          insert(payload) {
            writes.push({ op: "insert", payload });
            return { select() { return { single: async () => plan.insertError ? { data: null, error: plan.insertError } : { data: { id: "task-1" }, error: null } }; } };
          },
          update(payload) {
            const w = { op: "update", payload, where: [] };
            writes.push(w);
            const chain = { eq(c, v) { w.where.push([c, v]); return chain; }, then(res) { return Promise.resolve({ error: plan.updateError || null }).then(res); } };
            return chain;
          }
        };
      }
    }
  };
}

const MODEL_TEXT =
  "COMPETITOR: Acme\nPOSITIONING: Budget tools for makers\nSTRENGTHS: Cheap\nBig catalogue\nWEAKNESSES: Slow support\nCONFIDENCE: medium\nVERIFY_FIRST: Current pricing\n---\n" +
  "COMPETITOR: Globex\nPOSITIONING: Enterprise suite\nSTRENGTHS: Integrations\nWEAKNESSES: FIGURE NEEDED on price\nCONFIDENCE: low\nVERIFY_FIRST: Whether still trading";

function build(code, plan) {
  const sb = fakeSupabase(plan);
  const logs = [], modelCalls = [];
  const ctx = {
    supabase: sb.client,
    nowIso: () => "2026-09-11T12:00:00.000Z",
    console: { log: (m) => logs.push(["log", String(m)]), error: (m) => logs.push(["error", String(m)]), warn: (m) => logs.push(["warn", String(m)]) },
    requireAuth: 0, requireActiveSubscription: 0, aiLimiter: 0,
    loadProfileForTool: async () => ({ business_name: "Biz" }),
    resolvePreferredLanguage: async () => null,
    buildLanguageInstruction: () => "",
    buildAgentSystemPrompt: () => "SYSTEM",
    callAnthropicText: async (prompt, max, u, m, ledger) => {
      modelCalls.push(ledger.route);
      if (plan.modelThrows) throw new Error("model-down");
      return { text: plan.modelText === undefined ? MODEL_TEXT : plan.modelText, stopReason: "end_turn" };
    }
  };
  const routes = {};
  ctx.app = { post(path) { routes[path] = arguments[arguments.length - 1]; } };
  vm.createContext(ctx);
  vm.runInContext(code + "\nthis.renderToolOutputMarkdown = typeof renderToolOutputMarkdown === 'function' ? renderToolOutputMarkdown : null;", ctx);
  return { routes, writes: sb.writes, logs, modelCalls, render: ctx.renderToolOutputMarkdown };
}

async function call(handler, body) {
  const res = { statusCode: 200, body: undefined, status(c) { this.statusCode = c; return this; }, json(b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
  let nextErr = null;
  await handler({ user: { id: "u1" }, body }, res, (e) => { nextErr = e || new Error("next"); });
  return { status: res.statusCode, body: res.body, nextErr };
}
const strip = (b) => { const c = Object.assign({}, b); delete c.task_id; delete c.persisted; return c; };
const norm = (v) => JSON.parse(JSON.stringify(v));

let failures = 0;
async function t(name, fn) { try { await fn(); console.log("PASS " + name); } catch (e) { failures++; console.log("FAIL " + name + ": " + e.message); } }

const SCAN_BODY = { competitors: ["Acme", "Globex"], your_product: "Widgets" };
const AUDIT_BODY = { article: "# Best Widgets\n\nBest widgets are great. Buy best widgets.\n\n## Why\n\nBecause best widgets last.", keyword: "best widgets" };

(async () => {
  // a) competitor-scan success
  await t("a) competitor-scan success: insert + completed update with output; response has task_id/persisted true", async () => {
    const h = build(afterCode, {});
    const r = await call(h.routes["/api/agents/rd/competitor-scan"], SCAN_BODY);
    assert.strictEqual(r.status, 200, JSON.stringify(r.nextErr && r.nextErr.message));
    assert.deepStrictEqual(h.modelCalls, ["POST /api/agents/rd/competitor-scan"]);
    const w = norm(h.writes);
    assert.strictEqual(w.length, 2);
    assert.deepStrictEqual(w[0], { op: "insert", payload: { user_id: "u1", agent_type: "rd", task_type: "rd/competitor-scan", prompt: "R&D · Competitor scan: Acme, Globex", result: null, status: "processing" } });
    assert.strictEqual(w[1].op, "update");
    assert.deepStrictEqual(w[1].where, [["id", "task-1"], ["user_id", "u1"]]);
    assert.strictEqual(w[1].payload.status, "completed");
    assert.strictEqual(w[1].payload.completed_at, "2026-09-11T12:00:00.000Z");
    assert.strictEqual(w[1].payload.updated_at, "2026-09-11T12:00:00.000Z");
    assert.deepStrictEqual(w[1].payload.output, strip(r.body));
    assert(typeof w[1].payload.result === "string" && w[1].payload.result.length > 100);
    assert(!/\[object Object\]/.test(w[1].payload.result));
    assert.strictEqual(r.body.task_id, "task-1");
    assert.strictEqual(r.body.persisted, true);
    assert.deepStrictEqual(Object.keys(w[1].payload).sort(), ["completed_at", "output", "result", "status", "updated_at"]);
  });

  // b) validation failure
  await t("b) competitor-scan validation failure: zero writes, response identical to today", async () => {
    const h = build(afterCode, {}), h0 = build(beforeCode, {});
    const r = await call(h.routes["/api/agents/rd/competitor-scan"], { competitors: [] });
    const r0 = await call(h0.routes["/api/agents/rd/competitor-scan"], { competitors: [] });
    assert.strictEqual(r.status, 400);
    assert.deepStrictEqual(h.writes, []);
    assert.deepStrictEqual(h.modelCalls, []);
    assert.deepStrictEqual(r, r0);
  });

  // c) insert error
  await t("c) insert returns an error: model never called, error response", async () => {
    const h = build(afterCode, { insertError: { message: "insert-down" } });
    const r = await call(h.routes["/api/agents/rd/competitor-scan"], SCAN_BODY);
    assert.deepStrictEqual(h.modelCalls, []);
    assert(r.nextErr && /insert-down/.test(r.nextErr.message) && /Nothing was spent/.test(r.nextErr.message), r.nextErr && r.nextErr.message);
    assert.strictEqual(r.body, undefined);
    assert.strictEqual(norm(h.writes).filter(w => w.op === "update").length, 0);
  });

  // d) model throws
  await t("d) model call throws: row updated to failed with error and completed_at; nothing left processing", async () => {
    const h = build(afterCode, { modelThrows: true });
    const r = await call(h.routes["/api/agents/rd/competitor-scan"], SCAN_BODY);
    assert(r.nextErr && /model-down/.test(r.nextErr.message));
    const w = norm(h.writes);
    assert.strictEqual(w.length, 2);
    assert.strictEqual(w[1].op, "update");
    assert.deepStrictEqual(w[1].payload, { status: "failed", error: "model-down", result: "Task failed: model-down", completed_at: "2026-09-11T12:00:00.000Z", updated_at: "2026-09-11T12:00:00.000Z" });
    assert.deepStrictEqual(w[1].where, [["id", "task-1"], ["user_id", "u1"]]);
  });

  // d2) parse failure (502 path) also marks failed
  await t("d2) model returns unparseable text: 502 and row marked failed", async () => {
    const h = build(afterCode, { modelText: "nonsense with no labels" });
    const r = await call(h.routes["/api/agents/rd/competitor-scan"], SCAN_BODY);
    assert.strictEqual(r.status, 502);
    const w = norm(h.writes);
    assert.strictEqual(w[1].payload.status, "failed");
  });

  // e) completion update errors
  await t("e) completion update errors: response delivered with persisted false; exactly one UNPERSISTED TOOL OUTPUT line", async () => {
    const h = build(afterCode, { updateError: { message: "update-down" } });
    const r = await call(h.routes["/api/agents/rd/competitor-scan"], SCAN_BODY);
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body.task_id, "task-1");
    assert.strictEqual(r.body.persisted, false);
    assert(r.body.comparison.length === 2);
    const unp = h.logs.filter(l => l[1].indexOf("UNPERSISTED TOOL OUTPUT") === 0);
    assert.strictEqual(unp.length, 1, JSON.stringify(h.logs));
    assert(/task-1/.test(unp[0][1]) && /rd\/competitor-scan/.test(unp[0][1]) && /u1/.test(unp[0][1]), unp[0][1]);
  });

  // f) content/audit success
  await t("f) content/audit success: row completed with output, no model call", async () => {
    const h = build(afterCode, {});
    const r = await call(h.routes["/api/agents/content/audit"], AUDIT_BODY);
    assert.strictEqual(r.status, 200);
    assert.deepStrictEqual(h.modelCalls, []);
    const w = norm(h.writes);
    assert.strictEqual(w.length, 2);
    assert.deepStrictEqual(w[0].payload, { user_id: "u1", agent_type: "content", task_type: "content/audit", prompt: "Content · Audit: best widgets", result: null, status: "processing" });
    assert.strictEqual(w[1].payload.status, "completed");
    assert.deepStrictEqual(w[1].payload.output, strip(r.body));
    assert(!/\[object Object\]/.test(w[1].payload.result));
    assert.strictEqual(r.body.persisted, true);
    assert.strictEqual(r.body.task_id, "task-1");
  });

  await t("f2) content/audit validation failure: zero writes, identical to today", async () => {
    const h = build(afterCode, {}), h0 = build(beforeCode, {});
    const r = await call(h.routes["/api/agents/content/audit"], {});
    const r0 = await call(h0.routes["/api/agents/content/audit"], {});
    assert.strictEqual(r.status, 400);
    assert.deepStrictEqual(h.writes, []);
    assert.deepStrictEqual(r, r0);
  });

  // g) identity minus the two keys
  await t("g) a and f: response minus task_id/persisted deep-equals the pre-change response", async () => {
    const h = build(afterCode, {}), h0 = build(beforeCode, {});
    const a = await call(h.routes["/api/agents/rd/competitor-scan"], SCAN_BODY);
    const a0 = await call(h0.routes["/api/agents/rd/competitor-scan"], SCAN_BODY);
    assert.deepStrictEqual(strip(a.body), a0.body);
    assert.deepStrictEqual(Object.keys(a.body), Object.keys(a0.body).concat(["task_id", "persisted"]));
    const f = await call(h.routes["/api/agents/content/audit"], AUDIT_BODY);
    const f0 = await call(h0.routes["/api/agents/content/audit"], AUDIT_BODY);
    assert.deepStrictEqual(strip(f.body), f0.body);
    assert.deepStrictEqual(Object.keys(f.body), Object.keys(f0.body).concat(["task_id", "persisted"]));
  });

  // h) markdown renderer on real shapes + truncation
  await t("h) renderToolOutputMarkdown: headings, lists, no [object Object], 50k input truncated with note", async () => {
    const h = build(afterCode, {});
    const a = await call(h.routes["/api/agents/rd/competitor-scan"], SCAN_BODY);
    const f = await call(h.routes["/api/agents/content/audit"], AUDIT_BODY);
    const mdA = h.render(strip(a.body)), mdF = h.render(strip(f.body));
    for (const md of [mdA, mdF]) {
      assert(!/\[object Object\]/.test(md));
      assert(!/^## Success/m.test(md), "success key must be skipped");
      assert(/^## Measured/m.test(md) && /^## Provenance/m.test(md), md.slice(0, 200));
    }
    assert(/^## Competitors requested\n\n- Acme\n- Globex/m.test(mdA), mdA.slice(0, 300));      // array of strings → bullets
    assert(/^## Comparison\n\n-\n  - Competitor: Acme/m.test(mdA), mdA.slice(0, 600));          // array of objects → nested key: value
    assert(/- Strengths:\n    - Cheap\n    - Big catalogue/.test(mdA), mdA);                       // nested array inside object
    assert(/^## Measured\n\n- Word count: \d+/m.test(mdF), mdF.slice(0, 200));                    // nested object → indented key: value
    assert(/- Headings:\n  -\n    - Level: 1\n    - Text: Best Widgets/.test(mdF), mdF);
    assert(/- Headings by level:\n  - H1: 1/.test(mdF), mdF);
    const big = h.render({ success: true, text: "x".repeat(50000) });
    assert(big.length <= 20000, "length " + big.length);
    assert(/Truncated for display at 20000 characters/.test(big));
    assert(big.endsWith("stored with this task._"));
    // safety: bare scalars and null values
    assert(!/\[object Object\]/.test(h.render({ a: null, b: [{ c: { d: [1, { e: 2 }] } }], f: {} })));
  });

  console.log("failures: " + failures);
  process.exitCode = failures ? 1 : 0;
})();
