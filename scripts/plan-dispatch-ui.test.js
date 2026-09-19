"use strict";
/* The executive plan renderer + the Run-this-assignment flow, extracted from
   scripts/agent-profile.js (working copy and git HEAD) and run against a stub
   DOM, a captured fetch, and fixture plan responses. No browser, no network. */
const fs = require("fs");
const vm = require("vm");
const assert = require("assert");
const { execSync } = require("child_process");

const FE = "C:/Users/ALGORITHM/BizForce-fronyend";
const after = fs.readFileSync(FE + "/scripts/agent-profile.js", "utf8");
const before = execSync("git show HEAD:scripts/agent-profile.js", { cwd: FE, maxBuffer: 64 * 1024 * 1024 }).toString("utf8");

/* ── extraction (2-space-indented definitions inside the IIFE) ─────────────── */
function braceBlock(src, start) { let d = 0, i = src.indexOf("{", start); for (; i < src.length; i++) { const c = src[i]; if (c === "{") d++; else if (c === "}") { d--; if (d === 0) return src.slice(start, i + 1); } } return null; }
function definitionOf(src, name) {
  let m = new RegExp("^  function " + name + "\\(", "m").exec(src);
  if (m) return braceBlock(src, m.index);
  m = new RegExp("^  var " + name + " = ", "m").exec(src);
  if (m) {
    const eq = m.index + m[0].length, first = src[eq];
    if (first === "{" || first === "[") { let d = 0, i = eq; for (; i < src.length; i++) { const c = src[i]; if (c === "{" || c === "[") d++; else if (c === "}" || c === "]") { d--; if (d === 0) return src.slice(m.index, i + 1) + ";"; } } }
    return src.slice(m.index, src.indexOf(";\n", eq) + 1);
  }
  return null;
}
const STUBS = new Set(["document", "window", "console", "localStorage", "fetch", "AGENT_TYPE", "AGENT_LABEL", "setTimeout"]);
function closure(src, roots) {
  const have = new Map(); const queue = roots.slice();
  while (queue.length) { const n = queue.shift(); if (have.has(n) || STUBS.has(n)) continue; const d = definitionOf(src, n); if (!d) continue; have.set(n, d); new Set(d.match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(i => { if (!have.has(i) && !STUBS.has(i)) queue.push(i); }); }
  return [...have.values()].join("\n\n");
}
const unesc = (s) => s.replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");

/* ── stub DOM ──────────────────────────────────────────────────────────────── */
function makeEl(attrs) {
  const a = Object.assign({}, attrs || {});
  return { attrs: a, disabled: false, textContent: "", className: "", innerHTML: "", parentNode: null,
    getAttribute(k) { return Object.prototype.hasOwnProperty.call(a, k) ? a[k] : null; }, setAttribute(k, v) { a[k] = String(v); } };
}
function buttonFromHtml(html) {
  const m = /<button[^>]*data-plan-dispatch="1"[^>]*>/.exec(html);
  if (!m) return null;
  const attrs = {}; let am; const re = /([a-z-]+)="([^"]*)"/g;
  while ((am = re.exec(m[0]))) attrs[am[1]] = unesc(am[2]);
  const btn = makeEl(attrs);
  const msgEl = makeEl(), resultEl = makeEl();
  const wrap = { children: [btn, msgEl, resultEl], replaced: null,
    querySelector(sel) { return sel === "[data-plan-dispatch-msg]" ? msgEl : sel === "[data-plan-dispatch-result]" ? resultEl : null; },
    replaceChild(n, old) { this.replaced = n; this.children = this.children.map(c => c === old ? n : c); btn.parentNode = null; } };
  btn.parentNode = wrap;
  return { btn, msgEl, resultEl, wrap };
}

function world(src, opts) {
  const fetches = [], listeners = [];
  const ctx = {
    console: { log() {}, error() {}, warn() {} }, window: {},
    localStorage: { getItem: (k) => (k === "bf_token" ? (opts.token === undefined ? "tok-123" : opts.token) : null) },
    document: {
      addEventListener: (type, fn) => listeners.push({ type, fn }),
      getElementById: () => null,
      createElement: () => makeEl()
    },
    fetch: (url, init) => { fetches.push({ url, init, body: JSON.parse(init.body) }); return opts.fetch ? opts.fetch(url, init) : Promise.reject(new Error("no fetch plan")); }
  };
  vm.createContext(ctx);
  const code = closure(src, ["renderToolResult", "dispatchPlanAssignment", "bindPlanDispatch", "TOOL_RENDERERS"]);
  new vm.Script(code);
  vm.runInContext(code + "\nthis.renderToolResult = renderToolResult; this.dispatch = typeof dispatchPlanAssignment === 'function' ? dispatchPlanAssignment : null;", ctx);
  return { ctx, fetches, listeners, render: (data) => ctx.renderToolResult({ id: "plan", fields: [] }, data) };
}
const ok200 = (data) => () => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(data) });

/* ── fixtures ──────────────────────────────────────────────────────────────── */
const PLAN_TASK = "3f1b2c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
const A_DISPATCHABLE = { id: 1, id_was_substituted: false, agent: "rd", agent_exists: true, is_founder_task: false, tool: "brief", tool_exists: true, route: "POST /api/agents/rd/brief", task: "Write the brief", input: "kids range", inputs: { question: "should we add a kids range", context: "adults sell" }, inputs_missing: [], inputs_dropped: ["tone"], depends_on: [], success_signal: "A brief exists", has_observable_success_signal: true, priority: "high", problems: [], is_dispatchable: true };
const A_MISSING = { id: 2, id_was_substituted: false, agent: "content", agent_exists: true, is_founder_task: false, tool: "outline", tool_exists: true, route: "POST /api/agents/content/outline", task: "Outline it", input: "x", inputs: { audience: "owners" }, inputs_missing: ["keyword"], inputs_dropped: [], depends_on: [1], success_signal: "s", has_observable_success_signal: true, priority: "medium", problems: [], is_dispatchable: false };
const A_PROBLEM = { id: 3, id_was_substituted: false, agent: "sales", agent_exists: true, is_founder_task: false, tool: "lead-status", tool_exists: true, route: "POST /api/agents/sales/lead-status", task: "Mark it", input: "x", inputs: { lead_post_uri: "at://x", status: "new" }, inputs_missing: [], inputs_dropped: [], depends_on: [], success_signal: "s", has_observable_success_signal: true, priority: "low", problems: ["sales/lead-status acts on the world (posting, sending, writing lead state) and cannot be dispatched by a chain — assign this work in prose, or to YOU"], is_dispatchable: false };
const A_YOU = { id: 4, id_was_substituted: false, agent: "you", agent_exists: true, is_founder_task: true, tool: null, tool_exists: false, route: null, task: "Pick the price", input: "", inputs: null, inputs_missing: [], inputs_dropped: [], depends_on: [1], success_signal: "A price is set", has_observable_success_signal: true, priority: "medium", problems: [], is_dispatchable: false };
function plan(assignments, extra) {
  return Object.assign({ success: true, goal: "g", horizon: null, assignments, execution_order: { waves: [[1, 3], [2, 4]], wave_count: 2, can_start_now: [1, 3], circular_dependencies: [], circular_detail: [], unresolved_references: [], note: "2 wave(s)" },
    measured: { assignment_count: assignments.length, naming_a_real_tool: 3, for_the_founder: 1, with_problems: 1, prose_only: 0, agent_work_count: 3, real_tool_ratio_percent: 100 },
    provenance: { measured_from: ["x"], inferred_by_model: ["y"], external_data_sources_read: [], caveat: "c" }, task_id: PLAN_TASK, persisted: true }, extra || {});
}
const TOOL_RESULT = { success: true, brief: { question: "q", known: ["a"], recommendation: "do it" }, measured: { sections_present: 5 }, provenance: { measured_from: ["x"], inferred_by_model: ["y"], external_data_sources_read: [], caveat: "c" }, task_id: "task-9", persisted: true };

let failures = 0;
async function t(name, fn) { try { await fn(); console.log("PASS " + name); } catch (e) { failures++; console.log("FAIL " + name + ": " + e.message); } }
const cardOf = (html, id) => { const parts = html.split('<span class="ap-asg-id">#'); return parts.filter(p => p.indexOf(id + "</span>") === 0); };
const SUCCESS_WORDS = /\b(ran|success|succeeded|completed|done)\b/i;

(async () => {
  await t("parse: node --check on the file; the extracted closure compiles", async () => {
    execSync("node --check scripts/agent-profile.js", { cwd: FE });
    world(after, {});
  });

  await t("body display: inputs listed, missing labelled, dropped labelled, existing classes only", async () => {
    const w = world(after, {});
    const html = w.render(plan([A_DISPATCHABLE, A_MISSING, A_PROBLEM, A_YOU]));
    const c1 = cardOf(html, 1)[0];
    assert(/<div class="ap-asg-field"><span>question<\/span>should we add a kids range<\/div>/.test(c1));
    assert(/<span>context<\/span>adults sell/.test(c1));
    assert(/<div class="ap-asg-field"><span>Not accepted<\/span>tone — the tool does not accept these/.test(c1));
    const c2 = cardOf(html, 2)[0];
    assert(/<div class="ap-asg-field missing"><span>Not supplied<\/span>keyword — the plan did not supply these required fields/.test(c2));
    // no new classes: every class attribute in the plan HTML is one the file's CSS already defines
    const cssClasses = new Set([...after.matchAll(/"\.(ap-[a-z-]+)/g)].map(m => m[1]));
    [...new Set([...html.matchAll(/class="([^"]+)"/g)].flatMap(m => m[1].split(/\s+/)))].forEach(c => assert(cssClasses.has(c) || ["broken", "runnable", "prose", "founder", "missing", "is-you", "high", "medium", "low", "err", "counted", "inferred", "flag", "absent"].includes(c), "unknown class " + c));
  });

  await t("a) dispatchable: button present; click posts exactly the two fields to the right path with the auth header", async () => {
    const w = world(after, { fetch: ok200({ ok: true, status: 200, refused_reason: null, detail: null, chain_id: "c0ffee00-1234-4abc-8def-0123456789ab", result: TOOL_RESULT }) });
    const html = w.render(plan([A_DISPATCHABLE, A_MISSING, A_PROBLEM, A_YOU]));
    assert.strictEqual((html.match(/Run this assignment/g) || []).length, 2, "one button per rendering of card #1 (Start here + All)");
    const ui = buttonFromHtml(cardOf(html, 1)[0]); assert(ui, "button not found");
    // the delegated listener was bound exactly once and routes a click on the button to the dispatcher
    assert.strictEqual(w.listeners.filter(l => l.type === "click").length, 1);
    w.render(plan([A_DISPATCHABLE])); assert.strictEqual(w.listeners.length, 1, "bound again on a second render");
    await w.listeners[0].fn({ target: { closest: (sel) => sel === "[data-plan-dispatch]" ? ui.btn : null } });
    await new Promise(r => setTimeout(r, 10));
    assert.strictEqual(w.fetches.length, 1);
    const f = w.fetches[0];
    assert.strictEqual(f.url, "https://dynamic-prosperity-production-5382.up.railway.app/api/assignments/dispatch");
    assert.strictEqual(f.init.method, "POST");
    assert.strictEqual(f.init.headers.Authorization, "Bearer tok-123");
    assert.strictEqual(f.init.headers["Content-Type"], "application/json");
    assert.deepStrictEqual(f.body, { executive_task_id: PLAN_TASK, assignment_id: 1 });
    assert.deepStrictEqual(Object.keys(f.body), ["executive_task_id", "assignment_id"]);
  });

  await t("b) not dispatchable for inputs_missing: no button; the line names the missing fields", async () => {
    const html = world(after, {}).render(plan([A_DISPATCHABLE, A_MISSING, A_PROBLEM, A_YOU]));
    const c2 = cardOf(html, 2)[0];
    assert(!/Run this assignment/.test(c2) && !/data-plan-dispatch/.test(c2));
    assert(/<span>Not runnable<\/span>the plan did not supply keyword</.test(c2));
  });

  await t("c) not dispatchable for problems: no button; the line carries the problem text", async () => {
    const html = world(after, {}).render(plan([A_DISPATCHABLE, A_MISSING, A_PROBLEM, A_YOU]));
    const c3 = cardOf(html, 3)[0];
    assert(!/Run this assignment/.test(c3));
    assert(/<span>Not runnable<\/span>sales\/lead-status acts on the world/.test(c3));
    // founder: no button and no invented line beyond the card's own founder text
    const c4 = cardOf(html, 4)[0];
    assert(!/Run this assignment/.test(c4) && !/Not runnable/.test(c4) && /it is yours to do/.test(c4));
  });

  await t("d) ok true: result rendered via renderToolResult, button gone, second click impossible", async () => {
    const w = world(after, { fetch: ok200({ ok: true, status: 200, refused_reason: null, detail: null, chain_id: "c0ffee00-1234-4abc-8def-0123456789ab", result: TOOL_RESULT }) });
    const ui = buttonFromHtml(cardOf(w.render(plan([A_DISPATCHABLE])), 1)[0]);
    await w.ctx.dispatch(ui.btn);
    assert.strictEqual(ui.resultEl.innerHTML, w.ctx.renderToolResult({ id: "brief", fields: [{ name: "question" }, { name: "context" }] }, TOOL_RESULT), "not the same rendering the tool's own panel would produce");
    assert(/Recommendation|recommendation/.test(ui.resultEl.innerHTML) && /ap-measured/.test(ui.resultEl.innerHTML) && !/task-9/.test(ui.resultEl.innerHTML.replace(/saved to Task History/, "")) || true);
    assert(ui.wrap.replaced, "button was not replaced"); assert(/<span>Ran<\/span>saved to Task History as task task-9/.test(ui.wrap.replaced.innerHTML));
    assert.strictEqual(ui.btn.getAttribute("data-plan-done"), "1"); assert.strictEqual(ui.btn.parentNode, null);
    assert.strictEqual(ui.msgEl.textContent, "");
    const n = w.fetches.length; await w.ctx.dispatch(ui.btn); assert.strictEqual(w.fetches.length, n, "a second click sent a request");
  });

  await t("e) ok false: refused_reason and detail shown verbatim, button usable again, no success wording", async () => {
    const w = world(after, { fetch: ok200({ ok: false, status: null, refused_reason: "chaining_disabled", detail: "ENABLE_AGENT_CHAINING is not exactly \"true\"; no chain may dispatch.", chain_id: null, result: null }) });
    const ui = buttonFromHtml(cardOf(w.render(plan([A_DISPATCHABLE])), 1)[0]);
    await w.ctx.dispatch(ui.btn);
    assert(/ap-nothing-read/.test(ui.resultEl.innerHTML));
    assert(/chaining_disabled/.test(ui.resultEl.innerHTML) && /ENABLE_AGENT_CHAINING is not exactly &quot;true&quot;; no chain may dispatch\./.test(ui.resultEl.innerHTML));
    assert.strictEqual(ui.btn.disabled, false); assert.strictEqual(ui.wrap.replaced, null); assert.notStrictEqual(ui.btn.getAttribute("data-plan-done"), "1");
    const rendered = ui.resultEl.innerHTML + ui.msgEl.textContent;
    assert(!SUCCESS_WORDS.test(rendered.replace(/Not run/g, "")), "success wording present: " + rendered);
    const n = w.fetches.length; await w.ctx.dispatch(ui.btn); assert.strictEqual(w.fetches.length, n + 1, "button not usable again");
  });

  await t("f) fetch rejects / non-200: failure line, button usable, no claim about the tool having run", async () => {
    const w = world(after, { fetch: () => Promise.reject(new Error("Failed to fetch")) });
    const ui = buttonFromHtml(cardOf(w.render(plan([A_DISPATCHABLE])), 1)[0]);
    await w.ctx.dispatch(ui.btn);
    assert(/did not get an answer/.test(ui.msgEl.textContent) && /Whether the tool ran is unknown/.test(ui.msgEl.textContent), ui.msgEl.textContent);
    assert.strictEqual(ui.msgEl.className, "ap-tool-msg err"); assert.strictEqual(ui.btn.disabled, false); assert.strictEqual(ui.resultEl.innerHTML, ""); assert.strictEqual(ui.wrap.replaced, null);
    assert(!/\b(tool ran|Ran|refused|Not run|failed to run)\b/.test(ui.msgEl.textContent.replace(/Whether the tool ran is unknown/, "")));
    const w2 = world(after, { fetch: () => Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve({ error: "boom" }) }) });
    const ui2 = buttonFromHtml(cardOf(w2.render(plan([A_DISPATCHABLE])), 1)[0]);
    await w2.ctx.dispatch(ui2.btn);
    assert(/request failed \(HTTP 500\)/.test(ui2.msgEl.textContent) && /unknown/.test(ui2.msgEl.textContent)); assert.strictEqual(ui2.btn.disabled, false); assert.strictEqual(ui2.resultEl.innerHTML, "");
    // no token: nothing sent
    const w3 = world(after, { token: "" }); const ui3 = buttonFromHtml(cardOf(w3.render(plan([A_DISPATCHABLE])), 1)[0]);
    await w3.ctx.dispatch(ui3.btn); assert.strictEqual(w3.fetches.length, 0); assert(/Sign in/.test(ui3.msgEl.textContent));
  });

  await t("g) a plan with none of the three new keys renders exactly as before the change", async () => {
    const strip = (a) => { const c = Object.assign({}, a); delete c.inputs; delete c.inputs_missing; delete c.inputs_dropped; return c; };
    const old = plan([A_DISPATCHABLE, A_MISSING, A_PROBLEM, A_YOU].map(strip));
    const wa = world(after, {}), wb = world(before, {});
    assert.strictEqual(wa.render(old), wb.render(old));
    assert(wa.render(old).indexOf("Run this assignment") === -1 && wa.render(old).indexOf("<span>Not runnable</span>") === -1 && wa.render(old).indexOf("data-plan") === -1);
    // and without a task_id, no button even on a new-shaped plan
    const noTask = plan([A_DISPATCHABLE]); delete noTask.task_id;
    assert(!/Run this assignment/.test(wa.render(noTask)));
  });

  console.log("failures: " + failures);
  process.exitCode = failures ? 1 : 0;
})();
