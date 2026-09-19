"use strict";
/* dispatchToolCall, run for real: the dispatcher, its limits, TOOL_INPUT_SPECS,
   the router walk, agentChainScope and the REAL callAnthropicText are extracted
   from server.js and run in one vm context. Real tool route handlers are
   registered into a fake Express app whose _router.stack has the same shape as
   Express's. The Anthropic client, the daily cap, the key lookup and the ledger
   writer are stubs; the ledger writer records what it is handed. No network, no
   database, no live router. */
const vm = require("vm");
const assert = require("assert");
const { AsyncLocalStorage } = require("async_hooks");
const S = require("./_shared.js");
const { after, braceMatch, closureFor, routeCode, F } = S;

const ALL_PATHS = [...new Set([...after.matchAll(/app\.post\("(\/api\/agents\/[a-z_]+\/[a-z0-9-]+)"/g)].map(m => m[1]))].sort();
const aspStart = after.indexOf("const AGENT_SYSTEM_PROMPTS = {");
const AGENT_KEYS = [...after.slice(aspStart, braceMatch(after, after.indexOf("{", aspStart))).matchAll(/^\s{2}([a-z_]+):/gm)].map(m => m[1]);

// stubs the closure must not try to pull in
["enforceDailyModelCallLimit", "resolveAnthropicKey", "recordModelCall", "Anthropic", "AsyncLocalStorage", "getUserPlan", "agentToolCatalogue", "agentToolCatalogueWithSpecs", "COMPLIANCE_PROFILES", "COMPLIANCE_DISCLAIMER", "SALES_LEAD_STATUSES"].forEach(s => S.STUBS.add(s));
S.STUBS.delete("callAnthropicText");   // we want the REAL one this time
// AGENT_SYSTEM_PROMPTS stays a stub built from the REAL key list (its full graph of consts cannot be reordered safely in a vm)

const REAL_TOOLS = ["rd/brief", "content/outline", "rd/competitor-scan", "content/audit", "email/subject-lines"];

function world(env) {
  const ledger = [], aiWrites = [], logs = [], handlerCalls = [];
  const ctx = {
    process: { env: Object.assign({}, env || {}) },
    console: { log: (m) => logs.push(["log", String(m)]), error: (m) => logs.push(["error", String(m)]), warn: (m) => logs.push(["warn", String(m)]) },
    AsyncLocalStorage: AsyncLocalStorage,
    AGENT_SYSTEM_PROMPTS: Object.fromEntries(AGENT_KEYS.map(k => [k, "x"])),
    nowIso: () => "2026-09-11T12:00:00.000Z",
    requireAuth: function rA() {}, requireActiveSubscription: function rS() {}, aiLimiter: function aL() {},
    // route helpers the tools need
    loadProfileForTool: async () => ({}), resolvePreferredLanguage: async () => null, buildLanguageInstruction: () => "", buildAgentSystemPrompt: () => "SYSTEM",
    // callAnthropicText's dependencies
    enforceDailyModelCallLimit: async () => ({ allowed: true }),
    resolveAnthropicKey: async () => "sk-test",
    recordModelCall: async (d) => { ledger.push(JSON.parse(JSON.stringify(d))); },
    Anthropic: function Anthropic() { this.messages = { create: async (params) => ({ content: [{ type: "text", text: ctx.MODEL_TEXT }], usage: { input_tokens: 1, output_tokens: 1 }, model: params.model, stop_reason: "end_turn" }) }; },
    MODEL_TEXT: "",
    // entitlement, controllable
    PLAN: { active: true, exempt: false, inactive_reason: null },
    getUserPlan: async (uid) => { if (ctx.PLAN instanceof Error) throw ctx.PLAN; return ctx.PLAN; },
    // ai_tasks only
    supabase: { from(t) { assert.strictEqual(t, "ai_tasks"); return {
      insert(p) { aiWrites.push({ op: "insert", payload: p }); return { select() { return { single: async () => ({ data: { id: "task-1" }, error: null }) }; } }; },
      update(p) { const w = { op: "update", payload: p }; aiWrites.push(w); const c = { eq() { return c; }, then(r) { return Promise.resolve({ error: null }).then(r); } }; return c; }
    }; } }
  };
  // fake Express app with an Express-shaped router
  const stack = [];
  ctx.app = {
    _router: { stack },
    post(path) { const handlers = [].slice.call(arguments, 1); stack.push({ route: { path, methods: { post: true }, stack: handlers.map(h => ({ handle: function () { if (h === handlers[handlers.length - 1]) handlerCalls.push(path); return h.apply(null, arguments); } })) } }); },
    get() {}
  };
  vm.createContext(ctx);
  // registry + dispatcher + real callAnthropicText + the real tool routes we exercise
  const names = ["toolField", "TOOL_INPUT_SPECS", "agentToolRoutesCache", "agentToolRoutes", "CHAIN_NON_DISPATCHABLE_TOOLS", "chainLimit", "chainMaxDepth", "chainMaxFanout", "chainMaxCalls", "agentChainingEnabled", "CHAIN_FANOUT_TRACK_CAP", "chainFanoutCounts", "chainFanoutKey", "chainFanoutSoFar", "chainFanoutNote", "chainBodyHas", "resolveToolRouteHandler", "chainRefusal", "dispatchToolCall", "agentChainScope", "callAnthropicText"];
  names.forEach(n => assert(S.definitionOf(after, n), n + " not found"));
  // ONE closure over every root: the real route code plus a comment naming the
  // registry/dispatcher symbols, so each definition is pulled exactly once.
  const roots = REAL_TOOLS.map(k => routeCode(after, k)).join("\n\n") + "\n/* seeds: " + names.join(" ") + " */\n";
  const code = closureFor(after, roots);
  // every other catalogued path gets a dummy handler so the router membership check is real
  const dummies = ALL_PATHS.filter(p => !REAL_TOOLS.includes(p.replace("/api/agents/", ""))).map(p => `app.post(${JSON.stringify(p)}, requireAuth, function (req, res) { res.json({ dummy: true }); });`).join("\n");
  vm.runInContext(code + "\n\n" + dummies + "\nthis.dispatchToolCall = dispatchToolCall; this.chainFanoutCounts = chainFanoutCounts; this.callAnthropicText = callAnthropicText;", ctx);
  return { ctx, dispatch: ctx.dispatchToolCall, ledger, aiWrites, logs, handlerCalls };
}

const CHAIN = (depth, calls) => ({ id: "11111111-2222-4333-8444-555555555555", depth, callsSoFar: calls });
const ON = { ENABLE_AGENT_CHAINING: "true" };
let failures = 0;
async function t(name, fn) { try { await fn(); console.log("PASS " + name); } catch (e) { failures++; console.log("FAIL " + name + ": " + e.message); } }

(async () => {
  await t("a) gate off: refuses with a named reason; zero model calls; zero ai_tasks writes", async () => {
    const w = world({}); w.ctx.MODEL_TEXT = F["rd/brief"].model;
    const r = await w.dispatch({ userId: "u1", agentType: "rd", tool: "brief", body: F["rd/brief"].body, chain: CHAIN(0, 0) });
    assert.strictEqual(r.ok, false); assert.strictEqual(r.refused_reason, "chaining_disabled"); assert(/ENABLE_AGENT_CHAINING/.test(r.detail));
    assert.deepStrictEqual(w.ledger, []); assert.deepStrictEqual(w.aiWrites, []); assert.deepStrictEqual(w.handlerCalls, []);
    const w2 = world({ ENABLE_AGENT_CHAINING: "TRUE" });   // not exactly "true"
    assert.strictEqual((await w2.dispatch({ userId: "u1", agentType: "rd", tool: "brief", body: F["rd/brief"].body, chain: CHAIN(0, 0) })).refused_reason, "chaining_disabled");
  });

  await t("b) depth at CHAIN_MAX_DEPTH: refuses naming depth (default 2; and via env)", async () => {
    const w = world(ON);
    const r = await w.dispatch({ userId: "u1", agentType: "rd", tool: "brief", body: F["rd/brief"].body, chain: CHAIN(2, 0) });
    assert.strictEqual(r.refused_reason, "chain_depth_reached"); assert(/CHAIN_MAX_DEPTH is 2/.test(r.detail) && /depth 3/.test(r.detail));
    assert.deepStrictEqual(w.handlerCalls, []);
    const w2 = world(Object.assign({ CHAIN_MAX_DEPTH: "1" }, ON));
    assert.strictEqual((await w2.dispatch({ userId: "u1", agentType: "rd", tool: "brief", body: F["rd/brief"].body, chain: CHAIN(1, 0) })).refused_reason, "chain_depth_reached");
    // clamp: "99" → 5, "abc" → default 2 with an error log
    const w3 = world(Object.assign({ CHAIN_MAX_DEPTH: "99" }, ON));
    assert(/CHAIN_MAX_DEPTH is 5/.test((await w3.dispatch({ userId: "u1", agentType: "rd", tool: "brief", body: F["rd/brief"].body, chain: CHAIN(5, 0) })).detail));
    const w4 = world(Object.assign({ CHAIN_MAX_DEPTH: "abc" }, ON));
    assert(/CHAIN_MAX_DEPTH is 2/.test((await w4.dispatch({ userId: "u1", agentType: "rd", tool: "brief", body: F["rd/brief"].body, chain: CHAIN(2, 0) })).detail));
    assert(w4.logs.some(l => l[0] === "error" && /CHAIN_MAX_DEPTH is set to "abc"/.test(l[1])));
  });

  await t("c) fan-out beyond CHAIN_MAX_FANOUT: refuses naming fan-out (tracked per chain id + caller depth)", async () => {
    const w = world(Object.assign({ CHAIN_MAX_DEPTH: "3" }, ON)); w.ctx.MODEL_TEXT = F["rd/brief"].model;
    for (let i = 0; i < 3; i++) {
      const r = await w.dispatch({ userId: "u1", agentType: "rd", tool: "brief", body: F["rd/brief"].body, chain: CHAIN(0, i) });
      assert.strictEqual(r.ok, true, "dispatch " + (i + 1) + " should run: " + r.refused_reason + " " + r.detail);
    }
    const r4 = await w.dispatch({ userId: "u1", agentType: "rd", tool: "brief", body: F["rd/brief"].body, chain: CHAIN(0, 3) });
    assert.strictEqual(r4.refused_reason, "chain_fanout_reached"); assert(/CHAIN_MAX_FANOUT is 3/.test(r4.detail) && /dispatched 3/.test(r4.detail));
    assert.strictEqual(w.handlerCalls.length, 3);
    // a different step (depth 1) of the same chain has its own budget
    const r5 = await w.dispatch({ userId: "u1", agentType: "rd", tool: "brief", body: F["rd/brief"].body, chain: CHAIN(1, 3) });
    assert.strictEqual(r5.ok, true, r5.refused_reason);
  });

  await t("d) callsSoFar at CHAIN_MAX_CALLS: refuses naming the total", async () => {
    const w = world(ON);
    const r = await w.dispatch({ userId: "u1", agentType: "rd", tool: "brief", body: F["rd/brief"].body, chain: CHAIN(0, 10) });
    assert.strictEqual(r.refused_reason, "chain_total_calls_reached"); assert(/CHAIN_MAX_CALLS is 10/.test(r.detail) && /10 tool call/.test(r.detail));
    const w2 = world(Object.assign({ CHAIN_MAX_CALLS: "2" }, ON));
    assert.strictEqual((await w2.dispatch({ userId: "u1", agentType: "rd", tool: "brief", body: F["rd/brief"].body, chain: CHAIN(0, 2) })).refused_reason, "chain_total_calls_reached");
    // malformed chain refused by name too
    assert.strictEqual((await w.dispatch({ userId: "u1", agentType: "rd", tool: "brief", body: {}, chain: {} })).refused_reason, "chain_id_missing");
    assert.strictEqual((await w.dispatch({ userId: "u1", agentType: "rd", tool: "brief", body: {}, chain: { id: "x", depth: -1, callsSoFar: 0 } })).refused_reason, "chain_depth_invalid");
  });

  await t("e) unknown agent/tool refuses; a path absent from the router refuses; handler never called", async () => {
    const w = world(ON);
    assert.strictEqual((await w.dispatch({ userId: "u1", agentType: "rd", tool: "nothing-here", body: {}, chain: CHAIN(0, 0) })).refused_reason, "tool_not_in_router");
    assert.strictEqual((await w.dispatch({ userId: "u1", agentType: "notanagent", tool: "brief", body: {}, chain: CHAIN(0, 0) })).refused_reason, "tool_not_in_router");
    // present in TOOL_INPUT_SPECS but pulled from the router after the catalogue was built → handler_not_found, never guessed
    const w2 = world(ON); w2.ctx.MODEL_TEXT = F["rd/brief"].model;
    w2.ctx.app._router.stack.length && (await w2.dispatch({ userId: "u1", agentType: "rd", tool: "brief", body: F["rd/brief"].body, chain: CHAIN(0, 0) })); // warm the catalogue
    const idx = w2.ctx.app._router.stack.findIndex(l => l.route.path === "/api/agents/rd/brief");
    w2.ctx.app._router.stack.splice(idx, 1);
    const r = await w2.dispatch({ userId: "u1", agentType: "rd", tool: "brief", body: F["rd/brief"].body, chain: CHAIN(0, 1) });
    assert.strictEqual(r.refused_reason, "handler_not_found");
    assert.deepStrictEqual(w.handlerCalls, []);
  });

  await t("f) each of the five blocked routes refuses naming external action", async () => {
    const w = world(ON);
    for (const k of ["store/generate-proposals", "seo/generate-post", "seo/optimize", "sales/convert", "sales/lead-status"]) {
      const [agent, tool] = k.split("/");
      const r = await w.dispatch({ userId: "u1", agentType: agent, tool, body: { website: "https://x.test", lead_post_uri: "at://x", status: "new" }, chain: CHAIN(0, 0) });
      assert.strictEqual(r.refused_reason, "tool_takes_external_action", k);
      assert(/a chain may not take external action/.test(r.detail) && r.detail.indexOf(k) === 0, r.detail);
    }
    assert.deepStrictEqual(w.handlerCalls, []);
  });

  await t("g) body missing a required field per TOOL_INPUT_SPECS: refuses before the handler is invoked", async () => {
    const w = world(ON);
    let r = await w.dispatch({ userId: "u1", agentType: "rd", tool: "brief", body: { context: "c" }, chain: CHAIN(0, 0) });
    assert.strictEqual(r.refused_reason, "body_missing_required_fields"); assert(/requires question/.test(r.detail));
    r = await w.dispatch({ userId: "u1", agentType: "email", tool: "subject-lines", body: { purpose: "   " }, chain: CHAIN(0, 0) });
    assert.strictEqual(r.refused_reason, "body_missing_required_fields");
    r = await w.dispatch({ userId: "u1", agentType: "rd", tool: "competitor-scan", body: { competitors: [] }, chain: CHAIN(0, 0) });
    assert.strictEqual(r.refused_reason, "body_missing_required_fields");
    assert.deepStrictEqual(w.handlerCalls, []); assert.deepStrictEqual(w.ledger, []); assert.deepStrictEqual(w.aiWrites, []);
    // an alias satisfies the requirement
    w.ctx.MODEL_TEXT = F["email/subject-lines"].model;
    r = await w.dispatch({ userId: "u1", agentType: "email", tool: "subject-lines", body: { email_purpose: "launch" }, chain: CHAIN(0, 0) });
    assert.strictEqual(r.ok, true, r.refused_reason + " " + r.detail);
  });

  await t("h) getUserPlan inactive refuses; getUserPlan throws refuses (fail closed); handler never called", async () => {
    const w = world(ON);
    w.ctx.PLAN = { active: false, inactive_reason: "no_subscription" };
    let r = await w.dispatch({ userId: "u1", agentType: "rd", tool: "brief", body: F["rd/brief"].body, chain: CHAIN(0, 0) });
    assert.strictEqual(r.refused_reason, "not_entitled"); assert(/no_subscription/.test(r.detail));
    w.ctx.PLAN = new Error("plan-db-down");
    r = await w.dispatch({ userId: "u1", agentType: "rd", tool: "brief", body: F["rd/brief"].body, chain: CHAIN(0, 0) });
    assert.strictEqual(r.refused_reason, "entitlement_unknown"); assert(/plan-db-down/.test(r.detail) && /Failing closed/.test(r.detail));
    w.ctx.PLAN = null;
    assert.strictEqual((await w.dispatch({ userId: "u1", agentType: "rd", tool: "brief", body: F["rd/brief"].body, chain: CHAIN(0, 0) })).refused_reason, "not_entitled");
    w.ctx.PLAN = { active: "true" };   // not exactly true
    assert.strictEqual((await w.dispatch({ userId: "u1", agentType: "rd", tool: "brief", body: F["rd/brief"].body, chain: CHAIN(0, 0) })).refused_reason, "not_entitled");
    assert.deepStrictEqual(w.handlerCalls, []); assert.deepStrictEqual(w.ledger, []); assert.deepStrictEqual(w.aiWrites, []);
  });

  await t("i) happy path on a real tool handler: invoked once, response intact with task_id, ledger carries chain_id and depth 1", async () => {
    const w = world(ON); w.ctx.MODEL_TEXT = F["rd/brief"].model;
    const r = await w.dispatch({ userId: "u1", agentType: "rd", tool: "brief", body: F["rd/brief"].body, chain: CHAIN(0, 0) });
    assert.strictEqual(r.ok, true, r.refused_reason + " " + r.detail); assert.strictEqual(r.status, 200); assert.strictEqual(r.refused_reason, null);
    assert.deepStrictEqual(w.handlerCalls, ["/api/agents/rd/brief"]);
    assert.strictEqual(r.body.success, true); assert.strictEqual(r.body.task_id, "task-1"); assert.strictEqual(r.body.persisted, true);
    assert(r.body.brief && r.body.measured && r.body.provenance);
    // the tool's own persistence still ran
    assert.deepStrictEqual(w.aiWrites.map(x => x.op), ["insert", "update"]);
    assert.strictEqual(w.aiWrites[0].payload.task_type, "rd/brief");
    // the ledger
    assert.strictEqual(w.ledger.length, 1);
    assert.strictEqual(w.ledger[0].chainId, CHAIN(0, 0).id);
    assert.strictEqual(w.ledger[0].chainDepth, 1);
    assert.strictEqual(w.ledger[0].userId, "u1");
    assert.strictEqual(w.ledger[0].route, "POST /api/agents/rd/brief");
    // and a model call OUTSIDE any dispatch carries no chain
    await w.ctx.callAnthropicText("p", 10, null, undefined, { user_id: "u1", agent_type: "rd", route: "plain" });
    assert.strictEqual(w.ledger[1].chainId, undefined); assert.strictEqual(w.ledger[1].chainDepth, undefined);
    // a tool route that makes no model call also dispatches (content/audit)
    const r2 = await w.dispatch({ userId: "u1", agentType: "content", tool: "audit", body: F["content/audit"].body, chain: CHAIN(0, 1) });
    assert.strictEqual(r2.ok, true, r2.refused_reason); assert.strictEqual(r2.body.task_id, "task-1"); assert.strictEqual(w.ledger.length, 2);
  });

  await t("j) a chain of three dispatches at increasing depth: same chain_id, ledger depths 1, 2, 3", async () => {
    const w = world(Object.assign({ CHAIN_MAX_DEPTH: "3" }, ON));
    const id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    const steps = [["rd", "brief", F["rd/brief"]], ["content", "outline", F["content/outline"]], ["rd", "competitor-scan", F["rd/competitor-scan"]]];
    for (let i = 0; i < steps.length; i++) {
      const [agent, tool, fx] = steps[i]; w.ctx.MODEL_TEXT = fx.model;
      const r = await w.dispatch({ userId: "u1", agentType: agent, tool, body: fx.body, chain: { id, depth: i, callsSoFar: i } });
      assert.strictEqual(r.ok, true, "step " + (i + 1) + ": " + r.refused_reason + " " + r.detail);
    }
    assert.deepStrictEqual(w.ledger.map(l => l.chainId), [id, id, id]);
    assert.deepStrictEqual(w.ledger.map(l => l.chainDepth), [1, 2, 3]);
    assert.deepStrictEqual(w.ledger.map(l => l.route), ["POST /api/agents/rd/brief", "POST /api/agents/content/outline", "POST /api/agents/rd/competitor-scan"]);
    // the fourth hop is over the depth limit
    w.ctx.MODEL_TEXT = F["rd/brief"].model;
    assert.strictEqual((await w.dispatch({ userId: "u1", agentType: "rd", tool: "brief", body: F["rd/brief"].body, chain: { id, depth: 3, callsSoFar: 3 } })).refused_reason, "chain_depth_reached");
  });

  await t("k) a handler failure surfaces as handler_error, never as success; parse failure returns the tool's 502 body", async () => {
    const w = world(ON); w.ctx.MODEL_TEXT = "nothing parseable";
    const r = await w.dispatch({ userId: "u1", agentType: "rd", tool: "brief", body: F["rd/brief"].body, chain: CHAIN(0, 0) });
    assert.strictEqual(r.ok, false); assert.strictEqual(r.status, 502); assert(r.body && r.body.error);
    assert.strictEqual(w.aiWrites[1].payload.status, "failed");
  });

  await t("startup: both gate messages name ENABLE_AGENT_CHAINING", async () => {
    assert(/\[startup\] agent chaining ENABLED \(ENABLE_AGENT_CHAINING=\\"true\\"\)/.test(after));
    assert(/\[startup\] agent chaining disabled \(ENABLE_AGENT_CHAINING not exactly \\"true\\"\)/.test(after));
    // and nothing calls the dispatcher
    const calls = [...after.matchAll(/(?<!function )dispatchToolCall\(/g)].length;
    assert.strictEqual(calls, 0, "dispatchToolCall has " + calls + " call site(s); it must ship inert");
  });

  console.log("failures: " + failures);
  process.exitCode = failures ? 1 : 0;
})();
