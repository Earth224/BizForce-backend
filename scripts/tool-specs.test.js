"use strict";
/* TOOL_INPUT_SPECS registry checks. Builds a fake app._router.stack from every
   app.post("/api/agents/...") literal in server.js — the routes the live router
   registers — and runs the real agentToolRoutes / agentToolCatalogue /
   agentToolCatalogueWithSpecs / checkToolInputSpecsAgainstRouter and the real
   route handlers in vm contexts. No network, no database. */
const vm = require("vm");
const assert = require("assert");
const S = require("./_shared.js");
const { after, before, braceMatch, closureFor, build, call, F } = S;

/* ── the routes the source registers ─────────────────────────────────────── */
const ALL_PATHS = [...new Set([...after.matchAll(/app\.post\("(\/api\/agents\/[a-z_]+\/[a-z0-9-]+)"/g)].map(m => m[1]))].sort();
const fakeStack = (paths) => paths.map(p => ({ route: { path: p, methods: { post: true } } }));

/* AGENT_SYSTEM_PROMPTS keys, from the real object */
const aspStart = after.indexOf("const AGENT_SYSTEM_PROMPTS = {");
const aspBody = after.slice(aspStart, braceMatch(after, after.indexOf("{", aspStart)));
const AGENT_KEYS = [...aspBody.matchAll(/^\s{2}([a-z_]+):/gm)].map(m => m[1]);

/* ── registry code, extracted ─────────────────────────────────────────────── */
function defs(src, names) {
  return names.map(n => { const d = S.definitionOf(src, n); assert(d, n + " not found"); return d; }).join("\n\n");
}
const REG_NAMES = ["toolField", "TOOL_INPUT_SPECS", "agentToolRoutesCache", "agentToolRoutes", "agentToolCatalogue", "agentToolCatalogueWithSpecs", "checkToolInputSpecsAgainstRouter"];
function registry(paths) {
  const logs = [];
  const ctx = {
    console: { log: (m) => logs.push(["log", String(m)]), error: (m) => logs.push(["error", String(m)]) },
    AGENT_SYSTEM_PROMPTS: Object.fromEntries(AGENT_KEYS.map(k => [k, "x"])),
    app: { _router: { stack: fakeStack(paths) } }
  };
  vm.createContext(ctx);
  vm.runInContext(defs(after, REG_NAMES) + "\nthis.R = { agentToolRoutes, agentToolCatalogue, agentToolCatalogueWithSpecs, checkToolInputSpecsAgainstRouter, TOOL_INPUT_SPECS };", ctx);
  return { R: ctx.R, logs };
}
// the pre-change catalogue, for f)
function oldCatalogue(paths) {
  const ctx = { AGENT_SYSTEM_PROMPTS: Object.fromEntries(AGENT_KEYS.map(k => [k, "x"])), app: { _router: { stack: fakeStack(paths) } } };
  vm.createContext(ctx);
  vm.runInContext(defs(before, ["agentToolCatalogueCache", "agentToolCatalogue"]) + "\nthis.cat = agentToolCatalogue();", ctx);
  return JSON.parse(JSON.stringify(ctx.cat));
}

/* req.body.* reads per route, from the source */
function bodyReads(path) {
  const sig = 'app.post("' + path + '"'; const s = after.indexOf(sig); const e = braceMatch(after, after.indexOf("{", s));
  return [...new Set([...after.slice(s, e).matchAll(/req\.body\.([a-z_]+)/g)].map(m => m[1]))];
}

let failures = 0;
async function t(name, fn) { try { await fn(); console.log("PASS " + name); } catch (e) { failures++; console.log("FAIL " + name + ": " + e.message); } }
const key = (p) => p.replace("/api/agents/", "");

(async () => {
  const { R, logs } = registry(ALL_PATHS);
  const routes = R.agentToolRoutes();
  const specKeys = Object.keys(R.TOOL_INPUT_SPECS).sort();

  await t("a) every route the router exposes has a spec (" + routes.length + " routes), and every spec has a route", async () => {
    const routeKeys = JSON.parse(JSON.stringify(routes.map(r => r.key))).sort();
    assert.deepStrictEqual(routeKeys, JSON.parse(JSON.stringify(specKeys)));
    assert(routes.every(r => Array.isArray(r.spec)), "a route has spec null");
    const check = R.checkToolInputSpecsAgainstRouter();
    assert.deepStrictEqual(JSON.parse(JSON.stringify(check)), { routes: routes.length, routes_without_spec: [], specs_without_route: [] });
    assert(logs.some(l => l[0] === "log" && /every one with a declared input spec/.test(l[1])));
    console.log("   routes: " + routeKeys.join(", "));
  });

  await t("d) no spec names a field (or alias) the route never reads from req.body; and every read is covered", async () => {
    const problems = [];
    for (const r of routes) {
      const reads = new Set(bodyReads(r.path));
      const named = new Set();
      r.spec.forEach(f => { named.add(f.name); (f.aliases || []).forEach(a => named.add(a)); });
      named.forEach(n => { if (!reads.has(n)) problems.push(r.key + ": spec names '" + n + "' which the route never reads"); });
      reads.forEach(n => { if (!named.has(n)) problems.push(r.key + ": route reads '" + n + "' which the spec omits"); });
    }
    assert.deepStrictEqual(problems, []);
  });

  /* b) + c) per route, driving the real handler */
  const rows = [];
  for (const r of routes) {
    const fx = F[r.key];
    const required = r.spec.filter(f => f.required);
    const row = { route: r.key, required: required.map(f => f.name).join(",") || "(none)", b: "-", c: "-" };
    if (!fx) {
      // not a measured/provenance tool: drive b) only where a required field exists and validation is reachable pre-DB
      if (r.key === "seo/optimize" || r.key === "sales/lead-status") {
        try {
          const full = r.key === "seo/optimize" ? { website: "https://example.com/page" } : { lead_post_uri: "at://did/x", status: "new" };
          for (const f of required) {
            const body = Object.assign({}, full); delete body[f.name];
            const h = build(after, r.key, {}); const res = await call(h.handler, body);
            assert.strictEqual(res.status, 400, f.name + " absent → " + res.status);
          }
          // alias accepted where declared
          for (const f of required.filter(f => f.aliases)) {
            const body = Object.assign({}, full); const v = body[f.name]; delete body[f.name]; body[f.aliases[0]] = v;
            const h = build(after, r.key, {}); const res = await call(h.handler, body);
            assert.notStrictEqual(res.status, 400, "alias " + f.aliases[0] + " rejected");
          }
          row.b = "PASS";
        } catch (e) { row.b = "FAIL " + e.message; failures++; }
      } else row.b = "n/a (no required field)";
      row.c = "not driven (not a tool route: needs DB/network past validation)";
      rows.push(row); continue;
    }
    // b) each required field absent → 400
    try {
      for (const f of required) {
        const body = Object.assign({}, fx.body); delete body[f.name]; (f.aliases || []).forEach(a => delete body[a]);
        const h = build(after, r.key, { modelText: fx.model }); const res = await call(h.handler, body);
        assert.strictEqual(res.status, 400, "'" + f.name + "' absent → " + res.status + " " + JSON.stringify(res.body || (res.nextErr && res.nextErr.message)).slice(0, 120));
        assert.deepStrictEqual(h.writes, [], "'" + f.name + "' absent wrote to ai_tasks");
      }
      for (const f of required.filter(f => f.aliases && fx.body[f.name] !== undefined)) {
        const body = Object.assign({}, fx.body); const v = body[f.name]; delete body[f.name]; body[f.aliases[0]] = v;
        const h = build(after, r.key, { modelText: fx.model }); const res = await call(h.handler, body);
        assert.notStrictEqual(res.status, 400, "alias '" + f.aliases[0] + "' rejected");
      }
      row.b = required.length ? "PASS" : "n/a (no required field)";
    } catch (e) { row.b = "FAIL " + e.message; failures++; }
    // c) exactly the required fields → reaches the model (or, with no model, the success response)
    try {
      const body = {}; required.forEach(f => { assert(fx.body[f.name] !== undefined, "fixture lacks required '" + f.name + "'"); body[f.name] = fx.body[f.name]; });
      const h = build(after, r.key, { modelText: fx.model }); const res = await call(h.handler, body);
      if (fx.model !== null) assert.deepStrictEqual(h.modelCalls, ["POST /api/agents/" + r.key], "model not reached: " + res.status + " " + JSON.stringify(res.body || (res.nextErr && res.nextErr.message)).slice(0, 160));
      else assert.strictEqual(res.status, 200);
      assert.notStrictEqual(res.status, 400);
      row.c = "PASS";
    } catch (e) { row.c = "FAIL " + e.message; failures++; }
    rows.push(row);
  }
  const pad = (s, n) => (String(s) + " ".repeat(n)).slice(0, n);
  console.log("\n" + pad("route", 32) + pad("required fields", 34) + pad("b) 400 when absent", 22) + "c) required-only reaches model");
  rows.forEach(r => console.log(pad(r.route, 32) + pad(r.required, 34) + pad(r.b, 22) + r.c));
  console.log("");

  await t("e) boot guard logs on an injected mismatch in each direction and does not throw", async () => {
    const extra = registry(ALL_PATHS.concat(["/api/agents/rd/nothing-here"]));
    const c1 = JSON.parse(JSON.stringify(extra.R.checkToolInputSpecsAgainstRouter()));
    assert.deepStrictEqual(c1.routes_without_spec, ["rd/nothing-here"]);
    assert.deepStrictEqual(c1.specs_without_route, []);
    assert(extra.logs.some(l => l[0] === "error" && /NO entry in TOOL_INPUT_SPECS: rd\/nothing-here/.test(l[1])));
    const missing = registry(ALL_PATHS.filter(p => p !== "/api/agents/content/audit"));
    const c2 = JSON.parse(JSON.stringify(missing.R.checkToolInputSpecsAgainstRouter()));
    assert.deepStrictEqual(c2.specs_without_route, ["content/audit"]);
    assert.deepStrictEqual(c2.routes_without_spec, []);
    assert(missing.logs.some(l => l[0] === "error" && /NOT mounted: content\/audit/.test(l[1])));
    // unregistered agent is ignored, as before
    const foreign = registry(ALL_PATHS.concat(["/api/agents/notanagent/tool"]));
    assert.deepStrictEqual(JSON.parse(JSON.stringify(foreign.R.checkToolInputSpecsAgainstRouter())).routes_without_spec, []);
  });

  await t("f) agentToolCatalogue() output identical to the pre-change implementation; WithSpecs carries the same tools", async () => {
    const now = JSON.parse(JSON.stringify(R.agentToolCatalogue()));
    const old = oldCatalogue(ALL_PATHS);
    assert.deepStrictEqual(now, old);
    assert.deepStrictEqual(Object.keys(now).sort(), Object.keys(old).sort());
    const withSpecs = JSON.parse(JSON.stringify(R.agentToolCatalogueWithSpecs()));
    Object.keys(now).forEach(agent => {
      assert.deepStrictEqual(withSpecs[agent].map(x => x.tool).sort(), now[agent]);
      withSpecs[agent].forEach(x => { assert(Array.isArray(x.spec)); assert.strictEqual(x.path, "/api/agents/" + agent + "/" + x.tool); });
    });
    // the executive plan's usages still work: indexOf / join over arrays of names
    assert(now.rd.indexOf("competitor-scan") !== -1 && typeof now.rd.join(", ") === "string");
    // the caller list: exactly one call site besides the definitions
    const callSites = [...after.matchAll(/(?<!function )agentToolCatalogue\(\)/g)].length;
    assert.strictEqual(callSites, 1, "expected exactly one agentToolCatalogue() call site, found " + callSites);
  });

  await t("GET /api/agents/tool-specs is registered behind requireAuth and returns the WithSpecs catalogue", async () => {
    const m = /app\.get\("\/api\/agents\/tool-specs", requireAuth, function \(req, res\) \{[\s\S]*?agentToolCatalogueWithSpecs\(\)/.exec(after);
    assert(m, "route not found in the expected shape");
    // the catalogue regex must not admit the new GET route as a tool
    assert(!ALL_PATHS.includes("/api/agents/tool-specs"));
    assert(!routes.some(r => r.tool === "tool-specs"));
  });

  console.log("failures: " + failures);
  process.exitCode = failures ? 1 : 0;
})();
