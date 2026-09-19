"use strict";
/* Extracts renderToolResult and its transitive helpers/constants out of
   scripts/agent-profile.js (working copy AND git HEAD), runs each set in a vm
   context, and compares rendered HTML for fixture responses. No browser. */
const fs = require("fs");
const vm = require("vm");
const assert = require("assert");
const { execSync } = require("child_process");

const FE = "C:/Users/ALGORITHM/BizForce-fronyend";
const after = fs.readFileSync(FE + "/scripts/agent-profile.js", "utf8");
const before = execSync("git show HEAD:scripts/agent-profile.js", { cwd: FE, maxBuffer: 64 * 1024 * 1024 }).toString("utf8");

function braceBlock(src, start) {
  let depth = 0, i = src.indexOf("{", start), end = -1;
  for (; i < src.length; i++) {
    const c = src[i];
    if (c === "{") depth++;
    else if (c === "}") { depth--; if (depth === 0) { end = i + 1; break; } }
  }
  return src.slice(start, end);
}
function definitionOf(src, name) {
  let m = new RegExp("^  function " + name + "\\(", "m").exec(src);
  if (m) return braceBlock(src, m.index);
  m = new RegExp("^  var " + name + " = ", "m").exec(src);
  if (m) {
    const eq = m.index + m[0].length;
    const first = src[eq];
    if (first === "{" || first === "[") {
      // brace/bracket match then include trailing ;
      let depth = 0, i = eq, end = -1;
      for (; i < src.length; i++) {
        const c = src[i];
        if (c === "{" || c === "[") depth++;
        else if (c === "}" || c === "]") { depth--; if (depth === 0) { end = i + 1; break; } }
      }
      return src.slice(m.index, end) + ";";
    }
    const end = src.indexOf(";\n", eq);
    return src.slice(m.index, end + 1);
  }
  return null;
}
function closure(src, roots, stubs) {
  const have = new Map(); const queue = roots.slice();
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || stubs.has(name)) continue;
    const def = definitionOf(src, name);
    if (!def) continue;
    have.set(name, def);
    const ids = new Set(def.match(/[A-Za-z_$][A-Za-z0-9_$]*/g));
    ids.forEach(id => { if (!have.has(id) && !stubs.has(id)) queue.push(id); });
  }
  return [...have.values()].join("\n\n");
}

const STUBS = new Set(["document", "window", "console", "localStorage", "fetch", "API_URL", "AGENT_TYPE", "AGENT_LABEL", "renderExecutivePlan"]);

function buildRenderer(src) {
  const code = closure(src, ["renderToolResult"], STUBS);
  const ctx = { document: { getElementById: () => null, createElement: () => ({ set textContent(v) { this._t = v; }, get innerHTML() { return String(this._t).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); } }) },
    window: {}, console: { log() {}, error() {}, warn() {} }, renderExecutivePlan: () => "" };
  vm.createContext(ctx);
  new vm.Script(code);   // parse check of the extracted code
  vm.runInContext(code + "\nthis.renderToolResult = renderToolResult; this.TOOL_SKIP_KEYS = TOOL_SKIP_KEYS;", ctx);
  return { render: ctx.renderToolResult, skip: ctx.TOOL_SKIP_KEYS, code };
}

const A = buildRenderer(after), B = buildRenderer(before);
const TOOL = { id: "competitor-scan", fields: [{ name: "competitors" }] };

const BASE = {
  success: true,
  competitors_requested: ["Acme", "Globex"],
  comparison: [{ competitor: "Acme", positioning: "Budget", strengths: ["Cheap"], weaknesses: [], confidence: "medium", verify_first: "Pricing" }],
  contains_unverifiable_figures: false,
  measured: { competitors_requested: 2, competitors_returned: 1, note: "One returned." },
  provenance: { measured_from: ["counts"], inferred_by_model: ["text"], external_data_sources_read: [], caveat: "Nothing read.", market_data_read: false }
};
const NOTICE = '<div class="ap-nothing-read">This result was not saved to Task History.</div>';

let failures = 0;
function t(name, fn) { try { fn(); console.log("PASS " + name); } catch (e) { failures++; console.log("FAIL " + name + ": " + e.message); } }

t("parse: node --check on the whole file, and the extracted closure compiles", () => {
  execSync("node --check scripts/agent-profile.js", { cwd: FE });
  assert(A.code.length > 5000 && B.code.length > 5000);
});

t("skip list now contains task_id and persisted", () => {
  assert.deepStrictEqual(Array.from(A.skip), ["success", "task_id", "persisted"]);
  assert.deepStrictEqual(Array.from(B.skip), ["success"]);
});

t("a) task_id + persisted true: neither rendered, no extra line, everything else identical to before", () => {
  const data = Object.assign({}, BASE, { task_id: "9f1c2a3b-task-uuid", persisted: true });
  const html = A.render(TOOL, data);
  assert(html.indexOf("9f1c2a3b-task-uuid") === -1, "task_id leaked");
  assert(!/Task id|Persisted/.test(html), "bookkeeping key label rendered");
  assert(html.indexOf(NOTICE) === -1, "notice shown on persisted true");
  assert.strictEqual(html, B.render(TOOL, BASE), "differs from pre-change render of the same content");
  // and prove the pre-change code DID leak them, so the assertion above is meaningful
  const old = B.render(TOOL, data);
  assert(old.indexOf("9f1c2a3b-task-uuid") !== -1 && /Persisted/.test(old), "pre-change did not leak as expected");
});

t("b) persisted false: exactly one notice line, task_id still not rendered", () => {
  const data = Object.assign({}, BASE, { task_id: "9f1c2a3b-task-uuid", persisted: false });
  const html = A.render(TOOL, data);
  assert.strictEqual(html.split(NOTICE).length - 1, 1, "notice count");
  assert(html.indexOf("9f1c2a3b-task-uuid") === -1);
  assert(!/Task id|Persisted/.test(html));
  assert(html.endsWith(NOTICE), "notice is the last block");
  assert.strictEqual(html.slice(0, -NOTICE.length), B.render(TOOL, BASE), "rest identical to pre-change");
});

t("b2) persisted 'false' as a string or null: no notice (strict false only)", () => {
  assert(A.render(TOOL, Object.assign({}, BASE, { persisted: "false" })).indexOf(NOTICE) === -1);
  assert(A.render(TOOL, Object.assign({}, BASE, { persisted: null })).indexOf(NOTICE) === -1);
});

t("c) neither key (unconverted tool): output identical to before the change", () => {
  assert.strictEqual(A.render(TOOL, BASE), B.render(TOOL, BASE));
  const audit = { success: true, keyword: "best widgets", measured: { word_count: 12, headings: [{ level: 1, text: "H" }] }, provenance: { measured_from: ["x"], inferred_by_model: [], external_data_sources_read: [], caveat: "c", model_call_made: false } };
  assert.strictEqual(A.render({ id: "audit", fields: [{ name: "keyword" }] }, audit), B.render({ id: "audit", fields: [{ name: "keyword" }] }, audit));
});

t("c2) custom-renderer branch (executive plan) also gets the notice and hides the keys", () => {
  const plan = { success: true, goal: "g", assignments: [], measured: {}, provenance: { measured_from: [], inferred_by_model: [], external_data_sources_read: [], caveat: "c" }, task_id: "t-1", persisted: false };
  const html = A.render({ id: "plan", fields: [] }, plan);
  assert(html.endsWith(NOTICE) && html.indexOf("t-1") === -1);
});

console.log("failures: " + failures);
process.exitCode = failures ? 1 : 0;
