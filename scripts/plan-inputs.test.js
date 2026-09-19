"use strict";
/* POST /api/agents/executive/plan with INPUTS: the real route (working copy and
   git HEAD), the real TOOL_INPUT_SPECS / agentToolRoutes / validateToolInputs /
   chainBodyHas, a fake router stack of the real paths, a stubbed model. */
const vm = require("vm");
const assert = require("assert");
const S = require("./_shared.js");
const { after, before, braceMatch, closureFor, routeCode } = S;

const ALL_PATHS = [...new Set([...after.matchAll(/app\.post\("(\/api\/agents\/[a-z_]+\/[a-z0-9-]+)"/g)].map(m => m[1]))].sort();
const aspStart = after.indexOf("const AGENT_SYSTEM_PROMPTS = {");
const AGENT_KEYS = [...after.slice(aspStart, braceMatch(after, after.indexOf("{", aspStart))).matchAll(/^\s{2}([a-z_]+):/gm)].map(m => m[1]);
["COMPLIANCE_PROFILES", "COMPLIANCE_DISCLAIMER", "SALES_LEAD_STATUSES", "getUserPlan"].forEach(s => S.STUBS.add(s));
S.STUBS.delete("agentToolCatalogue"); S.STUBS.delete("agentToolCatalogueWithSpecs");

function build(src, modelText) {
  const writes = [], modelCalls = [];
  const ctx = {
    process: { env: {} }, console: { log() {}, error() {}, warn() {} },
    AGENT_SYSTEM_PROMPTS: Object.fromEntries(AGENT_KEYS.map(k => [k, "x"])),
    nowIso: () => "T", requireAuth: 0, requireActiveSubscription: 0, aiLimiter: 0,
    loadProfileForTool: async () => ({}), resolvePreferredLanguage: async () => null, buildLanguageInstruction: () => "", buildAgentSystemPrompt: () => "SYSTEM",
    callAnthropicText: async (prompt, max, u, m, ledger) => { modelCalls.push({ prompt, ledger }); return { text: modelText, stopReason: "end_turn" }; },
    supabase: { from() { return {
      insert(p) { writes.push({ op: "insert", payload: p }); return { select() { return { single: async () => ({ data: { id: "task-1" }, error: null }) }; } }; },
      update(p) { const w = { op: "update", payload: p }; writes.push(w); const c = { eq() { return c; }, then(r) { return Promise.resolve({ error: null }).then(r); } }; return c; }
    }; } },
    app: { _router: { stack: ALL_PATHS.map(p => ({ route: { path: p, methods: { post: true }, stack: [] } })) }, post() { ctx.__handler = arguments[arguments.length - 1]; }, get() {} }
  };
  vm.createContext(ctx);
  const seeds = src === after ? "\n/* seeds: chainBodyHas validateToolInputs parseToolInputsBlock TOOL_INPUT_SPECS agentToolRoutes CHAIN_NON_DISPATCHABLE_TOOLS */\n" : "";
  vm.runInContext(closureFor(src, routeCode(src, "executive/plan") + seeds) + (src === after ? "\nthis.chainBodyHas = chainBodyHas; this.TOOL_INPUT_SPECS = TOOL_INPUT_SPECS;" : ""), ctx);
  return { ctx, handler: ctx.__handler, writes, modelCalls };
}
async function call(h, body) {
  const res = { statusCode: 200, body: undefined, status(c) { this.statusCode = c; return this; }, json(b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
  let nextErr = null; await h({ user: { id: "u1" }, body }, res, (e) => { nextErr = e || new Error("next"); });
  return { status: res.statusCode, body: res.body, nextErr };
}
const norm = (v) => JSON.parse(JSON.stringify(v));
const BODY = { goal: "double online sales by spring" };

const blk = (o) => Object.keys(o).map(k => k + ": " + o[k]).join("\n");
const COMPLETE =
  blk({ ID: 1, AGENT: "rd", TOOL: "competitor-scan", TASK: "Compare rivals", INPUT: "the three closest rivals" }) +
  "\nINPUTS:\n  competitors = Acme, Globex, Initech\n  your_product = wool hats\n" +
  blk({ DEPENDS_ON: "NONE", SUCCESS_SIGNAL: "A comparison exists", PRIORITY: "high" }) + "\n---\n" +
  blk({ ID: 2, AGENT: "analytics", TOOL: "funnel", TASK: "Read the funnel", INPUT: "visit, cart, buy" }) +
  '\nINPUTS:\n  stages = [{"name":"visit","count":1000},{"name":"cart","count":100},{"name":"buy","count":10}]\n  funnel_name = shop\n' +
  blk({ DEPENDS_ON: "1", SUCCESS_SIGNAL: "The drop is named", PRIORITY: "medium" }) + "\n---\n" +
  blk({ ID: 3, AGENT: "content", TOOL: "outline", TASK: "Outline the guide", INPUT: "how to wash wool" }) +
  "\nINPUTS:\n  keyword = how to wash wool\n  audience = new owners\n" +
  blk({ DEPENDS_ON: "NONE", SUCCESS_SIGNAL: "An outline exists", PRIORITY: "low" }) + "\n---\n" +
  blk({ ID: 4, AGENT: "YOU", TOOL: "NONE", TASK: "Pick the price point", INPUT: "the comparison", DEPENDS_ON: "1", SUCCESS_SIGNAL: "A price is set", PRIORITY: "medium" });

let failures = 0;
async function t(name, fn) { try { await fn(); console.log("PASS " + name); } catch (e) { failures++; console.log("FAIL " + name + ": " + e.message); } }
const byId = (r, id) => r.body.assignments.find(a => a.id === id);

(async () => {
  await t("a) complete inputs for three tools: inputs present, inputs_missing empty, is_dispatchable true, each passes the dispatcher's real checker", async () => {
    const h = build(after, COMPLETE); const r = await call(h.handler, BODY);
    assert.strictEqual(r.status, 200, r.nextErr && r.nextErr.message);
    for (const id of [1, 2, 3]) {
      const a = byId(r, id);
      assert.strictEqual(a.is_dispatchable, true, "#" + id + " " + JSON.stringify(a.problems) + " " + JSON.stringify(a.inputs_missing));
      assert.deepStrictEqual(a.inputs_missing, []); assert.deepStrictEqual(a.inputs_dropped, []);
      assert(a.inputs && typeof a.inputs === "object");
      const spec = h.ctx.TOOL_INPUT_SPECS[a.agent + "/" + a.tool];
      spec.filter(f => f.required).forEach(f => assert.strictEqual(h.ctx.chainBodyHas(a.inputs, f), true, "#" + id + " chainBodyHas(" + f.name + ")"));
    }
    assert.deepStrictEqual(byId(r, 1).inputs, { competitors: ["Acme", "Globex", "Initech"], your_product: "wool hats" });
    assert.deepStrictEqual(byId(r, 2).inputs, { stages: [{ name: "visit", count: 1000 }, { name: "cart", count: 100 }, { name: "buy", count: 10 }], funnel_name: "shop" });
    assert.deepStrictEqual(byId(r, 3).inputs, { keyword: "how to wash wool", audience: "new owners" });
    const you = byId(r, 4);
    assert.strictEqual(you.is_founder_task, true); assert.strictEqual(you.inputs, null); assert.deepStrictEqual(you.inputs_missing, []); assert.strictEqual(you.is_dispatchable, false);
    // the prompt carried the field list and the INPUTS instruction
    const p = h.modelCalls[0].prompt;
    assert(/WHAT EACH TOOL TAKES/.test(p) && /rd\/competitor-scan:\n  competitors \(string_array, required\)/.test(p) && /^INPUTS:$/m.test(p));
    assert(/sales\/convert: not chainable/.test(p) && !/sales\/convert:\n  lead_post_uri/.test(p));
    // every dispatchable spec field appears in the prompt
    Object.keys(h.ctx.TOOL_INPUT_SPECS).forEach(k => { if (!/^(store|seo|sales)\//.test(k)) h.ctx.TOOL_INPUT_SPECS[k].forEach(f => assert(p.indexOf("  " + f.name + " (" + f.type) !== -1, k + "." + f.name + " absent from prompt")); });
  });

  await t("b) a required field absent: inputs_missing names it, is_dispatchable false, nothing invented", async () => {
    const text = COMPLETE.replace("  competitors = Acme, Globex, Initech\n", "");
    const r = await call(build(after, text).handler, BODY); const a = byId(r, 1);
    assert.deepStrictEqual(a.inputs_missing, ["competitors"]); assert.strictEqual(a.is_dispatchable, false);
    assert.deepStrictEqual(a.inputs, { your_product: "wool hats" }); assert(!("competitors" in a.inputs));
    assert.deepStrictEqual(a.problems, []);   // a missing input is not a plan problem; it is reported in its own key
    assert.strictEqual(a.tool_exists, true); assert.strictEqual(a.route, "POST /api/agents/rd/competitor-scan");
  });

  await t("c) an undeclared field: dropped, named in inputs_dropped, absent from inputs", async () => {
    const text = COMPLETE.replace("  keyword = how to wash wool\n", "  keyword = how to wash wool\n  tone = friendly\n  wordcount = 900\n");
    const r = await call(build(after, text).handler, BODY); const a = byId(r, 3);
    assert.deepStrictEqual(a.inputs_dropped, ["tone", "wordcount"]);
    assert.deepStrictEqual(a.inputs, { keyword: "how to wash wool", audience: "new owners" });
    assert.strictEqual(a.is_dispatchable, true);
  });

  await t("d) coercions: comma string → string_array; numeric string → number; unparseable left as given and judged as the dispatcher would", async () => {
    // string_array from a comma list is a) already; number:
    const text = blk({ ID: 1, AGENT: "reputation", TOOL: "review-response", TASK: "Reply", INPUT: "x" }) +
      "\nINPUTS:\n  review = The hat arrived late.\n  rating = 2\n" + blk({ DEPENDS_ON: "NONE", SUCCESS_SIGNAL: "s", PRIORITY: "high" }) + "\n---\n" +
      blk({ ID: 2, AGENT: "reputation", TOOL: "review-response", TASK: "Reply", INPUT: "x" }) +
      "\nINPUTS:\n  review = Late.\n  rating = two stars\n" + blk({ DEPENDS_ON: "NONE", SUCCESS_SIGNAL: "s", PRIORITY: "high" }) + "\n---\n" +
      blk({ ID: 3, AGENT: "analytics", TOOL: "funnel", TASK: "Funnel", INPUT: "x" }) +
      "\nINPUTS:\n  stages = visit then cart then buy\n" + blk({ DEPENDS_ON: "NONE", SUCCESS_SIGNAL: "s", PRIORITY: "high" }) + "\n---\n" +
      blk({ ID: 4, AGENT: "ads", TOOL: "policy-check", TASK: "Check", INPUT: "x" }) +
      "\nINPUTS:\n  copy = Guaranteed cure\n  suggest_rewrites = false\n" + blk({ DEPENDS_ON: "NONE", SUCCESS_SIGNAL: "s", PRIORITY: "high" }) + "\n---\n" +
      blk({ ID: 5, AGENT: "rd", TOOL: "competitor-scan", TASK: "Scan", INPUT: "x" }) +
      "\nINPUTS:\n  competitors = , ,\n" + blk({ DEPENDS_ON: "NONE", SUCCESS_SIGNAL: "s", PRIORITY: "high" });
    const h = build(after, text); const r = await call(h.handler, BODY);
    assert.strictEqual(byId(r, 1).inputs.rating, 2); assert.strictEqual(typeof byId(r, 1).inputs.rating, "number"); assert.strictEqual(byId(r, 1).is_dispatchable, true);
    // unparseable number: left as the string; present per the dispatcher's test (non-blank string), so not "missing"
    assert.strictEqual(byId(r, 2).inputs.rating, "two stars"); assert.deepStrictEqual(byId(r, 2).inputs_missing, []);
    assert.strictEqual(h.ctx.chainBodyHas(byId(r, 2).inputs, { name: "rating" }), true);
    // unparseable object_array: left as given, present as a non-blank string
    assert.strictEqual(byId(r, 3).inputs.stages, "visit then cart then buy"); assert.deepStrictEqual(byId(r, 3).inputs_missing, []);
    // boolean
    assert.strictEqual(byId(r, 4).inputs.suggest_rewrites, false);
    // a comma list of blanks coerces to [] and is judged ABSENT, exactly as chainBodyHas does
    assert.deepStrictEqual(byId(r, 5).inputs.competitors, []); assert.deepStrictEqual(byId(r, 5).inputs_missing, ["competitors"]); assert.strictEqual(byId(r, 5).is_dispatchable, false);
    assert.strictEqual(h.ctx.chainBodyHas(byId(r, 5).inputs, { name: "competitors" }), false);
  });

  await t("e) no INPUTS at all: inputs null, every required field in inputs_missing, is_dispatchable false", async () => {
    const text = blk({ ID: 1, AGENT: "email", TOOL: "sequence", TASK: "Welcome series", INPUT: "welcome new buyers", DEPENDS_ON: "NONE", SUCCESS_SIGNAL: "s", PRIORITY: "high" }) + "\n---\n" +
      blk({ ID: 2, AGENT: "email", TOOL: "sequence", TASK: "Welcome series", INPUT: "x" }) + "\nINPUTS: NONE\n" + blk({ DEPENDS_ON: "NONE", SUCCESS_SIGNAL: "s", PRIORITY: "high" });
    const r = await call(build(after, text).handler, BODY);
    for (const id of [1, 2]) {
      const a = byId(r, id);
      assert.strictEqual(a.inputs, null); assert.deepStrictEqual(a.inputs_missing, ["goal", "audience"]); assert.deepStrictEqual(a.inputs_dropped, []);
      assert.strictEqual(a.is_dispatchable, false); assert.strictEqual(a.tool_exists, true); assert.deepStrictEqual(a.problems, []);
    }
  });

  await t("f) a non-dispatchable tool: is_dispatchable false with the reason in problems", async () => {
    const text = blk({ ID: 1, AGENT: "sales", TOOL: "lead-status", TASK: "Mark lead", INPUT: "x" }) + "\nINPUTS:\n  lead_post_uri = at://x\n  status = contacted\n" +
      blk({ DEPENDS_ON: "NONE", SUCCESS_SIGNAL: "s", PRIORITY: "high" });
    const r = await call(build(after, text).handler, BODY); const a = byId(r, 1);
    assert.strictEqual(a.tool_exists, true); assert.strictEqual(a.is_dispatchable, false);
    assert.strictEqual(a.problems.length, 1); assert(/sales\/lead-status acts on the world/.test(a.problems[0]) && /cannot be dispatched by a chain/.test(a.problems[0]));
    assert.deepStrictEqual(a.inputs_missing, []);
    assert.strictEqual(r.body.measured.with_problems, 1);
  });

  await t("g) every other response key byte-identical to pre-change for the same model output", async () => {
    for (const text of [COMPLETE, COMPLETE.replace("  competitors = Acme, Globex, Initech\n", ""), blk({ ID: 1, AGENT: "email", TOOL: "sequence", TASK: "W", INPUT: "x", DEPENDS_ON: "NONE", SUCCESS_SIGNAL: "s", PRIORITY: "high" })]) {
      const r = await call(build(after, text).handler, BODY);
      const r0 = await call(build(before, text).handler, BODY);
      assert.strictEqual(r.status, 200); assert.strictEqual(r0.status, 200);
      const hasInputsBlock = /^INPUTS:/m.test(text);
      const scrub = (b) => { const c = norm(b); delete c.task_id; delete c.persisted; c.assignments.forEach(a => { delete a.inputs; delete a.inputs_missing; delete a.inputs_dropped; delete a.is_dispatchable; if (hasInputsBlock) delete a.input; }); return c; };
      assert.deepStrictEqual(scrub(r.body), scrub(r0.body));
      if (hasInputsBlock) {
        // the ONE inherent difference: the old parser had no INPUTS label, so its
        // `input` swallowed the INPUTS block. New input === old input minus that block.
        r.body.assignments.forEach((a, i) => {
          const old = r0.body.assignments[i].input;
          assert(old === a.input || old.indexOf(a.input + "\nINPUTS:") === 0, "#" + a.id + " input differs beyond the INPUTS block: " + JSON.stringify(old));
        });
      }
      // the added keys sit beside the old ones, and the old is_dispatchable is exactly the old expression
      r.body.assignments.forEach((a, i) => {
        const a0 = r0.body.assignments[i];
        assert.deepStrictEqual(Object.keys(a).filter(k => !["inputs", "inputs_missing", "inputs_dropped"].includes(k)), Object.keys(a0));
        assert.strictEqual(a0.is_dispatchable, !!a0.tool_exists && a0.problems.length === 0);
        assert.strictEqual(a.is_dispatchable, !!a.tool_exists && a.problems.length === 0 && a.inputs_missing.length === 0);
      });
      // execution order and founder handling untouched
      assert.deepStrictEqual(r.body.execution_order, r0.body.execution_order);
      assert.deepStrictEqual(r.body.measured, r0.body.measured);
    }
  });

  console.log("failures: " + failures);
  process.exitCode = failures ? 1 : 0;
})();
