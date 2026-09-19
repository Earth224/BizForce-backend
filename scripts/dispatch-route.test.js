"use strict";
/* POST /api/assignments/dispatch, run for real against the REAL dispatchToolCall,
   the REAL callAnthropicText (Anthropic client, cap, key and ledger writer
   stubbed; ledger recorded) and REAL tool handlers in an Express-shaped fake
   router. ai_tasks is a fake serving one stored plan row. No network, no DB. */
const vm = require("vm");
const assert = require("assert");
const { AsyncLocalStorage } = require("async_hooks");
const S = require("./_shared.js");
const { after, braceMatch, closureFor, routeCode, F } = S;

const ALL_PATHS = [...new Set([...after.matchAll(/app\.post\("(\/api\/agents\/[a-z_]+\/[a-z0-9-]+)"/g)].map(m => m[1]))].sort();
const aspStart = after.indexOf("const AGENT_SYSTEM_PROMPTS = {");
const AGENT_KEYS = [...after.slice(aspStart, braceMatch(after, after.indexOf("{", aspStart))).matchAll(/^\s{2}([a-z_]+):/gm)].map(m => m[1]);
["enforceDailyModelCallLimit", "resolveAnthropicKey", "recordModelCall", "Anthropic", "AsyncLocalStorage", "getUserPlan", "agentToolCatalogue", "agentToolCatalogueWithSpecs", "crypto"].forEach(s => S.STUBS.add(s));
S.STUBS.delete("callAnthropicText");

function routeBlock(src, sig) { const s = src.indexOf(sig); assert(s > 0, sig); const e = braceMatch(src, src.indexOf("{", s)); assert.strictEqual(src.slice(e, e + 3), ");\n"); return src.slice(s, e + 2); }

const REAL_TOOLS = ["rd/brief", "content/outline"];
const PLAN_ID = "3f1b2c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";

function planRow(overrides) {
  return Object.assign({
    id: PLAN_ID, user_id: "u1", task_type: "executive/plan", status: "completed",
    output: {
      success: true, goal: "g",
      assignments: [
        { id: 1, agent: "rd", tool: "brief", route: "POST /api/agents/rd/brief", is_founder_task: false, tool_exists: true, problems: [], inputs: F["rd/brief"].body, inputs_missing: [], inputs_dropped: [], is_dispatchable: true },
        { id: 2, agent: "content", tool: "outline", route: "POST /api/agents/content/outline", is_founder_task: false, tool_exists: true, problems: [], inputs: { audience: "owners" }, inputs_missing: ["keyword"], inputs_dropped: [], is_dispatchable: false },
        { id: 3, agent: "sales", tool: "lead-status", route: "POST /api/agents/sales/lead-status", is_founder_task: false, tool_exists: true, problems: ["sales/lead-status acts on the world (posting, sending, writing lead state) and cannot be dispatched by a chain — assign this work in prose, or to YOU"], inputs: { lead_post_uri: "at://x", status: "new" }, inputs_missing: [], inputs_dropped: [], is_dispatchable: false },
        { id: 4, agent: "you", tool: null, route: null, is_founder_task: true, tool_exists: false, problems: [], inputs: null, inputs_missing: [], inputs_dropped: [], is_dispatchable: false },
        /* a stored row that CLAIMS dispatchable for a blocked tool — the dispatcher must still refuse it */
        { id: 5, agent: "sales", tool: "lead-status", route: "POST /api/agents/sales/lead-status", is_founder_task: false, tool_exists: true, problems: [], inputs: { lead_post_uri: "at://x", status: "new" }, inputs_missing: [], inputs_dropped: [], is_dispatchable: true }
      ]
    }
  }, overrides || {});
}

function world(env, row) {
  const ledger = [], aiWrites = [], logs = [], handlerCalls = [], reads = [];
  const ctx = {
    process: { env: Object.assign({}, env || {}) },
    console: { log: (m) => logs.push(["log", String(m)]), error: (m) => logs.push(["error", String(m)]), warn: (m) => logs.push(["warn", String(m)]) },
    AsyncLocalStorage, crypto: { randomUUID: () => "c0ffee00-1234-4abc-8def-0123456789ab" },
    AGENT_SYSTEM_PROMPTS: Object.fromEntries(AGENT_KEYS.map(k => [k, "x"])),
    nowIso: () => "T", requireAuth: function rA() {}, requireActiveSubscription: function rS() {}, aiLimiter: function aL() {},
    loadProfileForTool: async () => ({}), resolvePreferredLanguage: async () => null, buildLanguageInstruction: () => "", buildAgentSystemPrompt: () => "SYSTEM",
    enforceDailyModelCallLimit: async () => ({ allowed: true }), resolveAnthropicKey: async () => "sk-test",
    recordModelCall: async (d) => { ledger.push(JSON.parse(JSON.stringify(d))); },
    Anthropic: function Anthropic() { this.messages = { create: async (params) => ({ content: [{ type: "text", text: ctx.MODEL_TEXT }], usage: { input_tokens: 1, output_tokens: 1 }, model: params.model, stop_reason: "end_turn" }) }; },
    MODEL_TEXT: F["rd/brief"].model,
    PLAN: { active: true, exempt: false, inactive_reason: null },
    getUserPlan: async () => ctx.PLAN,
    supabase: { from(t) { assert.strictEqual(t, "ai_tasks"); return {
      select(cols) { const q = { cols, filters: [] }; reads.push(q); const c = { eq(k, v) { q.filters.push([k, v]); return c; }, async maybeSingle() {
        const id = q.filters.find(f => f[0] === "id"), uid = q.filters.find(f => f[0] === "user_id");
        return { data: (row && id && uid && row.id === id[1] && row.user_id === uid[1]) ? row : null, error: null }; } }; return c; },
      insert(p) { aiWrites.push({ op: "insert", payload: p }); return { select() { return { single: async () => ({ data: { id: "task-9" }, error: null }) }; } }; },
      update(p) { const w = { op: "update", payload: p }; aiWrites.push(w); const c = { eq() { return c; }, then(r) { return Promise.resolve({ error: null }).then(r); } }; return c; }
    }; } }
  };
  const stack = []; const routes = {};
  ctx.app = {
    _router: { stack },
    post(path) { const handlers = [].slice.call(arguments, 1); const last = handlers[handlers.length - 1];
      routes[path] = last;
      stack.push({ route: { path, methods: { post: true }, stack: handlers.map(h => ({ handle: function (req) { if (h === last) handlerCalls.push({ path, body: JSON.parse(JSON.stringify(req.body)), user: req.user }); return h.apply(null, arguments); } })) } }); },
    get() {}
  };
  vm.createContext(ctx);
  const names = ["toolField", "TOOL_INPUT_SPECS", "agentToolRoutesCache", "agentToolRoutes", "CHAIN_NON_DISPATCHABLE_TOOLS", "chainLimit", "chainMaxDepth", "chainMaxFanout", "chainMaxCalls", "agentChainingEnabled", "CHAIN_FANOUT_TRACK_CAP", "chainFanoutCounts", "chainFanoutKey", "chainFanoutSoFar", "chainFanoutNote", "chainBodyHas", "resolveToolRouteHandler", "chainRefusal", "dispatchToolCall", "agentChainScope", "callAnthropicText", "dispatchRefusal", "isValidUuid"];
  const roots = REAL_TOOLS.map(k => routeCode(after, k)).join("\n\n") + "\n\n" + routeBlock(after, 'app.post("/api/assignments/dispatch"') + "\n/* seeds: " + names.join(" ") + " */\n";
  const dummies = ALL_PATHS.filter(p => !REAL_TOOLS.includes(p.replace("/api/agents/", ""))).map(p => `app.post(${JSON.stringify(p)}, requireAuth, function (req, res) { res.json({ dummy: true }); });`).join("\n");
  vm.runInContext(closureFor(after, roots) + "\n\n" + dummies, ctx);
  return { ctx, dispatchRoute: routes["/api/assignments/dispatch"], ledger, aiWrites, logs, handlerCalls, reads };
}
async function call(handler, body, userId) {
  const res = { statusCode: 200, body: undefined, status(c) { this.statusCode = c; return this; }, json(b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
  let nextErr = null; await handler({ user: { id: userId || "u1" }, body }, res, (e) => { nextErr = e || new Error("next"); });
  return { status: res.statusCode, body: res.body, nextErr };
}
const ON = { ENABLE_AGENT_CHAINING: "true" };
const RESP_KEYS = ["ok", "status", "refused_reason", "detail", "chain_id", "result"];
const toolCalls = (w) => w.handlerCalls.filter(h => h.path !== "/api/assignments/dispatch");

let failures = 0;
async function t(name, fn) { try { await fn(); console.log("PASS " + name); } catch (e) { failures++; console.log("FAIL " + name + ": " + e.message); } }

(async () => {
  await t("route is mounted with requireAuth, requireActiveSubscription, aiLimiter in the tool routes' order", async () => {
    assert(/app\.post\("\/api\/assignments\/dispatch", requireAuth, requireActiveSubscription, aiLimiter,\n  async function \(req, res, next\)/.test(after));
    assert(!/agent_collaborations|agent_assignments/.test(routeBlock(after, 'app.post("/api/assignments/dispatch"')), "route mentions a table it must not write");
  });

  await t("a) gate off: ok false, chaining_disabled, handler never called", async () => {
    const w = world({}, planRow());
    const r = await call(w.dispatchRoute, { executive_task_id: PLAN_ID, assignment_id: 1 });
    assert.strictEqual(r.status, 200); assert.strictEqual(r.body.ok, false); assert.strictEqual(r.body.refused_reason, "chaining_disabled");
    assert.deepStrictEqual(Object.keys(r.body), RESP_KEYS);
    assert.deepStrictEqual(toolCalls(w), []); assert.deepStrictEqual(w.ledger, []); assert.deepStrictEqual(w.aiWrites, []);
    assert(w.reads.length === 1, "the plan row was read once (scoped)");
  });

  await t("b) gate on, happy path: tool runs once, result carries task_id, chain_id is a uuid, ledger has that chain_id at depth 1", async () => {
    const w = world(ON, planRow());
    const r = await call(w.dispatchRoute, { executive_task_id: PLAN_ID, assignment_id: 1 });
    assert.strictEqual(r.status, 200, r.nextErr && r.nextErr.message);
    assert.strictEqual(r.body.ok, true); assert.strictEqual(r.body.status, 200); assert.strictEqual(r.body.refused_reason, null);
    assert(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(r.body.chain_id), r.body.chain_id);
    assert.deepStrictEqual(toolCalls(w).map(h => h.path), ["/api/agents/rd/brief"]);
    assert.strictEqual(r.body.result.success, true); assert.strictEqual(r.body.result.task_id, "task-9"); assert.strictEqual(r.body.result.persisted, true); assert(r.body.result.brief);
    assert.strictEqual(w.ledger.length, 1); assert.strictEqual(w.ledger[0].chainId, r.body.chain_id); assert.strictEqual(w.ledger[0].chainDepth, 1); assert.strictEqual(w.ledger[0].userId, "u1");
    // the tool persisted itself; this route wrote nothing of its own
    assert.deepStrictEqual(w.aiWrites.map(x => x.op), ["insert", "update"]); assert.strictEqual(w.aiWrites[0].payload.task_type, "rd/brief");
    assert.deepStrictEqual(Object.keys(r.body), RESP_KEYS);
  });

  await t("c) executive_task_id belonging to another user: refused, nothing run", async () => {
    const w = world(ON, planRow({ user_id: "someone-else" }));
    const r = await call(w.dispatchRoute, { executive_task_id: PLAN_ID, assignment_id: 1 });
    assert.strictEqual(r.status, 200); assert.strictEqual(r.body.ok, false); assert.strictEqual(r.body.refused_reason, "plan_not_found");
    assert.deepStrictEqual(toolCalls(w), []); assert.deepStrictEqual(w.ledger, []);
    // the one read was scoped to the caller's user_id in the query
    assert.deepStrictEqual(w.reads[0].filters, [["id", PLAN_ID], ["user_id", "u1"]]);
  });

  await t("d) assignment_id not in the stored output: refused by name", async () => {
    const w = world(ON, planRow());
    const r = await call(w.dispatchRoute, { executive_task_id: PLAN_ID, assignment_id: 42 });
    assert.strictEqual(r.body.refused_reason, "assignment_not_in_plan"); assert(/id 42/.test(r.body.detail) && /it has: 1, 2, 3, 4, 5/.test(r.body.detail));
    assert.deepStrictEqual(toolCalls(w), []);
    // output null → its own reason
    const w2 = world(ON, planRow({ output: null, status: "processing" }));
    assert.strictEqual((await call(w2.dispatchRoute, { executive_task_id: PLAN_ID, assignment_id: 1 })).body.refused_reason, "plan_has_no_output");
  });

  await t("e) is_dispatchable false: refused naming inputs_missing / problems; handler never called", async () => {
    const w = world(ON, planRow());
    const r2 = await call(w.dispatchRoute, { executive_task_id: PLAN_ID, assignment_id: 2 });
    assert.strictEqual(r2.body.refused_reason, "assignment_not_dispatchable"); assert(/inputs_missing: keyword/.test(r2.body.detail), r2.body.detail);
    const r3 = await call(w.dispatchRoute, { executive_task_id: PLAN_ID, assignment_id: 3 });
    assert.strictEqual(r3.body.refused_reason, "assignment_not_dispatchable"); assert(/problems: sales\/lead-status acts on the world/.test(r3.body.detail), r3.body.detail);
    const r4 = await call(w.dispatchRoute, { executive_task_id: PLAN_ID, assignment_id: 4 });
    assert.strictEqual(r4.body.refused_reason, "assignment_not_dispatchable"); assert(/founder work/.test(r4.body.detail));
    assert.deepStrictEqual(toolCalls(w), []); assert.deepStrictEqual(w.ledger, []); assert.deepStrictEqual(w.aiWrites, []);
  });

  await t("f) a stored assignment naming a non-dispatchable tool, even if marked dispatchable: refused by the dispatcher by name", async () => {
    const w = world(ON, planRow());
    const r = await call(w.dispatchRoute, { executive_task_id: PLAN_ID, assignment_id: 5 });
    assert.strictEqual(r.body.ok, false); assert.strictEqual(r.body.refused_reason, "tool_takes_external_action"); assert(/sales\/lead-status/.test(r.body.detail));
    assert(r.body.chain_id, "a chain id was minted before the dispatcher refused"); assert.strictEqual(r.body.result, null);
    assert.deepStrictEqual(toolCalls(w), []);
  });

  await t("g) extra client fields reach neither the dispatcher nor the tool", async () => {
    const w = world(ON, planRow());
    const r = await call(w.dispatchRoute, { executive_task_id: PLAN_ID, assignment_id: 1, question: "INJECTED", context: "INJECTED", body: { question: "INJECTED" }, inputs: { question: "INJECTED" }, chain: { depth: 9 } });
    assert.strictEqual(r.body.ok, true, r.body.refused_reason + " " + r.body.detail);
    const received = toolCalls(w)[0];
    assert.deepStrictEqual(received.body, F["rd/brief"].body);            // exactly the stored inputs
    assert.strictEqual(JSON.stringify(received).indexOf("INJECTED"), -1);
    assert.deepStrictEqual(JSON.parse(JSON.stringify(received.user)), { id: "u1" });
    assert.strictEqual(w.ledger[0].chainDepth, 1);                        // the client's chain.depth: 9 changed nothing
    // static check: the handler reads exactly two body fields
    const src = routeBlock(after, 'app.post("/api/assignments/dispatch"');
    assert.deepStrictEqual([...new Set([...src.matchAll(/req\.body\.([a-z_]+)/g)].map(m => m[1]))].sort(), ["assignment_id", "executive_task_id"]);
    assert(!/req\.body\)|\.\.\.req\.body|Object\.assign\([^)]*req\.body/.test(src), "the body object itself is never spread or forwarded");
  });

  await t("h) task_type not executive/plan: refused", async () => {
    const w = world(ON, planRow({ task_type: "rd/brief" }));
    const r = await call(w.dispatchRoute, { executive_task_id: PLAN_ID, assignment_id: 1 });
    assert.strictEqual(r.body.refused_reason, "not_an_executive_plan"); assert(/"rd\/brief"/.test(r.body.detail));
    const w2 = world(ON, planRow({ task_type: "general" }));
    assert.strictEqual((await call(w2.dispatchRoute, { executive_task_id: PLAN_ID, assignment_id: 1 })).body.refused_reason, "not_an_executive_plan");
    assert.deepStrictEqual(toolCalls(w), []);
  });

  await t("malformed request is a 400, not a refusal", async () => {
    const w = world(ON, planRow());
    assert.strictEqual((await call(w.dispatchRoute, { executive_task_id: "nope", assignment_id: 1 })).status, 400);
    assert.strictEqual((await call(w.dispatchRoute, { executive_task_id: PLAN_ID })).status, 400);
    assert.strictEqual((await call(w.dispatchRoute, { executive_task_id: PLAN_ID, assignment_id: "abc" })).status, 400);
    assert.strictEqual((await call(w.dispatchRoute, { executive_task_id: PLAN_ID, assignment_id: "1" })).body.ok, true, "numeric string id accepted");
    assert.deepStrictEqual(w.reads.length, 1);
  });

  console.log("failures: " + failures);
  process.exitCode = failures ? 1 : 0;
})();
