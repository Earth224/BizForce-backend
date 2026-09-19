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
  "function safeText(value, maxLength) {", "function countWords(text) {",
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
  const h = build(afterCode, {});
  const r = await call(h.routes["/api/agents/rd/competitor-scan"], SCAN_BODY);
  console.log("status", r.status, "nextErr", r.nextErr && r.nextErr.stack);
  console.log(JSON.stringify(h.logs, null, 1).slice(0, 1500));
})();