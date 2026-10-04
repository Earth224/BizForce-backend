/* ══════════════════════════════════════════════════════════════════════════
   checkChainRefusals.js — three refusals the chain dispatcher makes that
   nothing else proved, against the live router.

   WHY THIS EXISTS. ENABLE_AGENT_CHAINING is "true" in production (read from
   Railway, 2026-10-04), so these refusals are live. Seven scripts/*.test.js
   harnesses were meant to prove them; nothing ever ran those, and all seven
   failed at the commit that created them. They also proved things against a
   FAKE router — tool-specs passed while the real GET /api/agents/tool-specs was
   shadowed by /api/agents/:type for its entire life. So this runs server.js
   itself: the dispatcher walks the real app._router.stack, the dispatch route
   is the real handler, and the tool bodies are built from the live
   GET /api/agents/tool-specs response.

   WHAT THIS PROVES

     1. BLOCKED TOOLS. Each of the five CHAIN_NON_DISPATCHABLE_TOOLS —
        store/generate-proposals, seo/generate-post, seo/optimize,
        sales/convert, sales/lead-status — is mounted, and a dispatch to it is
        refused tool_takes_external_action, with a body that satisfies its
        spec, from an entitled account. The handler never runs. The list in
        server.js is exactly those five.
     2. ANOTHER USER'S PLAN. POST /api/assignments/dispatch, given an
        executive/plan row that belongs to someone else, refuses plan_not_found
        and runs nothing. The same assignment in the caller's own plan runs, so
        the refusal is about ownership and nothing else.
     3. DEPTH. A dispatch from caller depth 1 (running at 2) runs; from caller
        depth 2 (running at 3) it is refused chain_depth_reached, naming
        CHAIN_MAX_DEPTH. Neither Railway nor .env sets CHAIN_MAX_DEPTH, so the
        limit is the default, 2; it is unset here too so this run matches.

   THE FIVE ACTION HANDLERS ARE REPLACED BY TRIPWIRES. In the live router, the
   final handler of each blocked route is swapped for one that records the call
   and answers without doing anything. The dispatcher still walks the same
   router and finds the same layers; only what sits at the end is different.
   That is what lets MUTATE=blocked lift the block without posting an article,
   fetching a site, writing proposals or touching a lead. A tripwire that fires
   is the failure.

   THE ACTORS. Dispatches run as the seed account (resolveEntitledAccount),
   because the dispatcher refuses an unentitled account before it reaches most
   of what is tested here. The "other user" in 2 is BIZFORCE_CHECK_USER_ID,
   which owns one plan row for the length of the run. Each account has its own
   residue guard; both are cleaned with a read-back.

   ENABLE_AGENT_CHAINING is set to "true" for this process only, matching
   production. The model is stubbed; no request leaves the machine.

   MUTATE=blocked     the CHAIN_NON_DISPATCHABLE_TOOLS test in dispatchToolCall
                      is disabled at compile time. All five must go red (the
                      tripwires fire); 2 and 3 must stay green.
   MUTATE=cross-user  the dispatch route's .eq("user_id", userId) scope is
                      removed at compile time. 2 must go red; 1 and 3 green.
   MUTATE=depth       the CHAIN_MAX_DEPTH test in dispatchToolCall is disabled
                      at compile time. 3 must go red; 1 and 2 green.
   Nothing is written to server.js on disk.
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const { createResidueGuard, resolveSubjectAccount, resolveEntitledAccount, ENTITLED_CHECK_EMAIL } = require("./checkRunResidue");
const SUBJECT_USER_ID = resolveSubjectAccount();

const MUTATIONS = ["blocked", "cross-user", "depth"];
const MUTATE = process.env.MUTATE || "";
if (MUTATE && MUTATIONS.indexOf(MUTATE) === -1) {
  console.error("Unknown MUTATE=" + MUTATE + ". Known: " + MUTATIONS.join(", "));
  process.exit(2);
}

process.env.ENABLE_AGENT_CHAINING = "true";
delete process.env.CHAIN_MAX_DEPTH;
const EXPECTED_MAX_DEPTH = 2;

const path = require("path");
const crypto = require("crypto");
const Module = require("module");
const REPO = path.join(__dirname, "..");
const SERVER_PATH = path.join(REPO, "server.js");

const BLOCKED = ["store/generate-proposals", "seo/generate-post", "seo/optimize", "sales/convert", "sales/lead-status"];

/* ── the mutations, at compile ──────────────────────────────────────────── */
const MUTATION_EDITS = {
  "blocked": {
    /* The list is also read by the executive-plan code and routineStepProblem; the comment
       line pins this anchor to the dispatcher's own test. */
    from: "  // 4. the target must be a real, dispatchable tool\n  if (CHAIN_NON_DISPATCHABLE_TOOLS.indexOf(key) !== -1) {\n",
    to:   "  // 4. the target must be a real, dispatchable tool\n  if (false && CHAIN_NON_DISPATCHABLE_TOOLS.indexOf(key) !== -1) {\n",
    say:  "the CHAIN_NON_DISPATCHABLE_TOOLS test is disabled — all five blocked tools must reach their tripwires."
  },
  "cross-user": {
    from: "        .eq(\"id\", executiveTaskId)\n        .eq(\"user_id\", userId)\n",
    to:   "        .eq(\"id\", executiveTaskId)\n",
    say:  "the dispatch route no longer scopes the plan read to the caller — another user's plan must now run."
  },
  "depth": {
    from: "  if (nextDepth > maxDepth) {\n",
    to:   "  if (false && nextDepth > maxDepth) {\n",
    say:  "the CHAIN_MAX_DEPTH test is disabled — a dispatch from depth 2 must now run."
  }
};
if (MUTATE) {
  const edit = MUTATION_EDITS[MUTATE];
  const realCompile = Module.prototype._compile;
  Module.prototype._compile = function (content, filename) {
    if (path.resolve(filename) === path.resolve(SERVER_PATH)) {
      content = content.replace(/\r\n/g, "\n");   // the anchors span lines; a CRLF checkout would never match
      const hits = content.split(edit.from).length - 1;
      if (hits !== 1) { console.error("MUTATION REFUSED: expected exactly one anchor, found " + hits + ": " + edit.from.trim()); process.exit(1); }
      content = content.replace(edit.from, edit.to);
      console.log("\n!! MUTATION: " + edit.say);
    }
    return realCompile.call(this, content, filename);
  };
}

/* ── the model, stubbed ─────────────────────────────────────────────────── */
const SDK_PATH = require.resolve("@anthropic-ai/sdk", { paths: [REPO] });
const RealAnthropic = require(SDK_PATH);
let modelCalls = 0;
function FakeAnthropic() {
  const instance = new RealAnthropic({ apiKey: "sk-ant-stub", timeout: 1000 });
  instance.messages = {
    create: async function (args) {
      modelCalls++;
      return {
        id: "msg_check_" + modelCalls,
        model: (args && args.model) || "stubbed",
        /* email/subject-lines parses "subject | angle" per line. */
        content: [{ type: "text", text: "Your order is ready | urgency\nA quick question about your setup | curiosity\nThree ideas for this week | value" }],
        stop_reason: "end_turn",
        usage: { input_tokens: 1, output_tokens: 1 }
      };
    }
  };
  return instance;
}
Object.keys(RealAnthropic).forEach(function (k) { FakeAnthropic[k] = RealAnthropic[k]; });
require.cache[SDK_PATH].exports = FakeAnthropic;

const EXPRESS_PATH = require.resolve("express", { paths: [REPO] });
const realExpress = require(EXPRESS_PATH);
let app = null;
const expressWrapper = function () { const made = realExpress.apply(this, arguments); if (!app) app = made; return made; };
Object.keys(realExpress).forEach(function (k) { expressWrapper[k] = realExpress[k]; });
require.cache[EXPRESS_PATH].exports = expressWrapper;

process.env.PORT = process.env.CHECK_PORT || "0";
const server = require(SERVER_PATH);

const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY);

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

/* The live route's final handler, called with the user supplied directly —
   requireAuth / requireActiveSubscription / aiLimiter are what sits before it. */
function callRoute(routePath, method, req) {
  const layer = app._router.stack.filter(function (l) {
    return l.route && l.route.path === routePath && l.route.methods[method];
  })[0];
  if (!layer) throw new Error("route not mounted: " + routePath);
  const handler = layer.route.stack[layer.route.stack.length - 1].handle;
  return new Promise(function (resolve) {
    let done = false;
    const fin = function (r) { if (!done) { done = true; resolve(r); } };
    const res = {
      statusCode: 200,
      status: function (c) { this.statusCode = c; return this; },
      json: function (p) { fin({ status: this.statusCode, body: p }); return this; }
    };
    Promise.resolve()
      .then(function () { return handler(Object.assign({ params: {}, query: {}, headers: {} }, req), res, function (e) { fin({ status: 500, body: { error: String(e) } }); }); })
      .catch(function (e) { fin({ status: 500, body: { error: String(e) } }); });
  });
}

/* ── the tripwires ──────────────────────────────────────────────────────── */
const tripped = {};
function installTripwires() {
  const found = {};
  BLOCKED.forEach(function (key) {
    const layers = app._router.stack.filter(function (l) {
      return l.route && l.route.path === "/api/agents/" + key && l.route.methods.post;
    });
    found[key] = layers.length;
    if (layers.length !== 1) return;
    const routeStack = layers[0].route.stack;
    routeStack[routeStack.length - 1].handle = function tripwire(req, res) {
      tripped[key] = (tripped[key] || 0) + 1;
      return res.status(200).json({ success: true, tripwire: key, note: "checkChainRefusals tripwire — the real handler did not run" });
    };
  });
  return found;
}

/* A body that satisfies every required field of the live spec. */
function bodyFor(spec) {
  const body = {};
  (spec || []).filter(function (f) { return f.required; }).forEach(function (f) {
    if (f.type === "number") body[f.name] = 1;
    else if (f.type === "boolean") body[f.name] = true;
    else if (f.type === "string_array") body[f.name] = ["check"];
    else if (f.type === "object_array") body[f.name] = [{ name: "check" }];
    else if (f.type === "object") body[f.name] = { check: true };
    else body[f.name] = f.name === "website" ? "https://example.invalid/" : "checkChainRefusals fixture";
  });
  return body;
}

const PLAN_ASSIGNMENT = {
  id: 1, agent: "email", tool: "subject-lines",
  inputs: { purpose: "checkChainRefusals fixture" },
  is_dispatchable: true, problems: [], inputs_missing: []
};

async function insertPlan(userId, guard, label) {
  const r = await supabase.from("ai_tasks").insert({
    user_id: userId,
    agent_type: "executive",
    task_type: "executive/plan",
    prompt: "CHECK " + label + " — scripts/checkChainRefusals.js",
    result: null,
    status: "completed",
    output: { assignments: [PLAN_ASSIGNMENT] }
  }).select("id").single();
  if (r.error) throw new Error("could not insert the " + label + " plan row: " + r.error.message);
  guard.record("ai_tasks", r.data.id);
  return r.data.id;
}

async function recordActorRowsSince(actorGuard, actorId, sinceIso) {
  const t = await supabase.from("ai_tasks").select("id").eq("user_id", actorId).gte("created_at", sinceIso);
  (t.data || []).forEach(function (row) { actorGuard.record("ai_tasks", row.id); });
  const m = await supabase.from("model_calls").select("id").eq("user_id", actorId).gte("created_at", sinceIso);
  (m.data || []).forEach(function (row) { actorGuard.record("model_calls", row.id); });
  return { ai_tasks: (t.data || []).length, model_calls: (m.data || []).length };
}

(async function main() {
  /* ── accounts ── */
  const actor = await resolveEntitledAccount(supabase);
  const seedRead = await supabase.from("users").select("id").eq("email", ENTITLED_CHECK_EMAIL);
  if (seedRead.error) throw seedRead.error;
  const seedId = seedRead.data && seedRead.data.length === 1 ? String(seedRead.data[0].id).toLowerCase() : null;
  if (!seedId || seedId !== actor.id) {
    console.log("\nSTOPPED before writing anything: the actor is not the seed account.");
    process.exit(1);
  }
  if (actor.id === SUBJECT_USER_ID) {
    console.log("\nSTOPPED before writing anything: the subject and the actor are the same account.");
    process.exit(1);
  }

  const actorGuard = createResidueGuard({ supabase: supabase, name: "chainRefusals-actor", subject: actor.id, tables: ["ai_tasks", "model_calls"] });
  const subjectGuard = createResidueGuard({ supabase: supabase, name: "chainRefusals-subject", subject: SUBJECT_USER_ID, tables: ["ai_tasks", "model_calls"] });
  actorGuard.install();
  subjectGuard.install();
  await actorGuard.sweepPrevious(actor.id);
  await subjectGuard.sweepPrevious(SUBJECT_USER_ID);

  console.log("\n══ who this runs as ══");
  console.log("    actor, entitled (dispatches)  : " + actor.id + "  (" + actor.email + ")");
  console.log("    other user (owns one plan)    : " + SUBJECT_USER_ID);
  console.log("    ENABLE_AGENT_CHAINING         : " + JSON.stringify(process.env.ENABLE_AGENT_CHAINING) + " (this process; production is \"true\")");

  const sinceRun = new Date(Date.now() - 2000).toISOString();

  try {
    /* ── 1. the five blocked tools ─────────────────────────────────────── */
    console.log("\n══ 1. the five tools a chain may not run ══");
    const src = require("fs").readFileSync(SERVER_PATH, "utf8").replace(/\r\n/g, "\n");
    const listMatch = /var CHAIN_NON_DISPATCHABLE_TOOLS = \[([^\]]*)\]/.exec(src);
    const listed = listMatch ? (listMatch[1].match(/"[^"]+"/g) || []).map(function (s) { return s.slice(1, -1); }) : [];
    check("CHAIN_NON_DISPATCHABLE_TOOLS in server.js is exactly the five",
      JSON.stringify(listed.slice().sort()) === JSON.stringify(BLOCKED.slice().sort()), JSON.stringify(listed));

    const mounted = installTripwires();
    const specsResp = await callRoute("/api/agents/tool-specs", "get", { user: { id: actor.id } });
    const catalogue = (specsResp.body && specsResp.body.agents) || {};
    check("the live GET /api/agents/tool-specs answers with a catalogue",
      specsResp.status === 200 && Object.keys(catalogue).length > 0, specsResp.status);

    for (const key of BLOCKED) {
      const parts = key.split("/");
      const entry = (catalogue[parts[0]] || []).filter(function (t) { return t.tool === parts[1]; })[0];
      check(key + ": mounted once in the live router, with a spec", mounted[key] === 1 && !!entry && Array.isArray(entry.spec),
        "layers " + mounted[key] + ", spec " + (entry ? JSON.stringify(entry.spec) : "none"));
      const before = modelCalls;
      const d = await server.__dispatchToolCall({
        userId: actor.id, agentType: parts[0], tool: parts[1],
        body: bodyFor(entry && entry.spec),
        chain: { id: crypto.randomUUID(), depth: 0, callsSoFar: 0 }
      });
      console.log("    " + key + " → " + (d.ok ? "RAN" : d.refused_reason) + (d.detail ? "  (" + String(d.detail).slice(0, 110) + ")" : ""));
      check(key + ": refused tool_takes_external_action", d.ok === false && d.refused_reason === "tool_takes_external_action",
        (d.ok ? "ran" : d.refused_reason));
      check(key + ": its handler never ran, and no model call was made", !tripped[key] && modelCalls === before,
        "tripwire " + (tripped[key] || 0) + ", model calls " + (modelCalls - before));
    }

    /* ── 2. another user's plan ────────────────────────────────────────── */
    console.log("\n══ 2. dispatching another user's executive plan ══");
    const othersPlan = await insertPlan(SUBJECT_USER_ID, subjectGuard, "other user's plan");
    const ownPlan = await insertPlan(actor.id, actorGuard, "actor's own plan");
    console.log("    plan owned by the other user : " + othersPlan);
    console.log("    plan owned by the actor      : " + ownPlan);

    let before = modelCalls;
    const own = await callRoute("/api/assignments/dispatch", "post", {
      user: { id: actor.id }, body: { executive_task_id: ownPlan, assignment_id: 1 }
    });
    console.log("    own plan   → HTTP " + own.status + " " + JSON.stringify({ ok: own.body && own.body.ok, refused_reason: own.body && own.body.refused_reason }));
    check("control: the same assignment in the actor's own plan runs", own.status === 200 && own.body && own.body.ok === true,
      own.status + " " + JSON.stringify(own.body).slice(0, 200));
    check("control: and the model was called for it", modelCalls === before + 1, String(modelCalls - before));

    before = modelCalls;
    const tasksBefore = (await recordActorRowsSince(actorGuard, actor.id, sinceRun)).ai_tasks;
    const others = await callRoute("/api/assignments/dispatch", "post", {
      user: { id: actor.id }, body: { executive_task_id: othersPlan, assignment_id: 1 }
    });
    const tasksAfter = (await recordActorRowsSince(actorGuard, actor.id, sinceRun)).ai_tasks;
    console.log("    other's plan → HTTP " + others.status + " " + JSON.stringify({ ok: others.body && others.body.ok, refused_reason: others.body && others.body.refused_reason }));
    check("another user's plan is refused plan_not_found",
      others.status === 200 && others.body && others.body.ok === false && others.body.refused_reason === "plan_not_found",
      others.status + " " + JSON.stringify(others.body).slice(0, 200));
    check("and nothing ran: no model call, no new task row", modelCalls === before && tasksAfter === tasksBefore,
      "model calls " + (modelCalls - before) + ", task rows " + (tasksAfter - tasksBefore));

    /* ── 3. depth ──────────────────────────────────────────────────────── */
    console.log("\n══ 3. CHAIN_MAX_DEPTH (default " + EXPECTED_MAX_DEPTH + "; unset on Railway and here) ══");
    before = modelCalls;
    const atLimit = await server.__dispatchToolCall({
      userId: actor.id, agentType: "email", tool: "subject-lines",
      body: { purpose: "checkChainRefusals depth control" },
      chain: { id: crypto.randomUUID(), depth: EXPECTED_MAX_DEPTH - 1, callsSoFar: 0 }
    });
    console.log("    from depth " + (EXPECTED_MAX_DEPTH - 1) + " → " + (atLimit.ok ? "ran" : atLimit.refused_reason));
    check("control: a dispatch running at depth " + EXPECTED_MAX_DEPTH + " runs", atLimit.ok === true && modelCalls === before + 1,
      (atLimit.ok ? "ran" : atLimit.refused_reason) + ", model calls " + (modelCalls - before));

    before = modelCalls;
    const past = await server.__dispatchToolCall({
      userId: actor.id, agentType: "email", tool: "subject-lines",
      body: { purpose: "checkChainRefusals depth probe" },
      chain: { id: crypto.randomUUID(), depth: EXPECTED_MAX_DEPTH, callsSoFar: 0 }
    });
    console.log("    from depth " + EXPECTED_MAX_DEPTH + " → " + (past.ok ? "RAN" : past.refused_reason) + (past.detail ? "  (" + past.detail + ")" : ""));
    check("a dispatch that would run at depth " + (EXPECTED_MAX_DEPTH + 1) + " is refused chain_depth_reached",
      past.ok === false && past.refused_reason === "chain_depth_reached", past.ok ? "ran" : past.refused_reason);
    check("and the refusal names CHAIN_MAX_DEPTH is " + EXPECTED_MAX_DEPTH,
      !!past.detail && past.detail.indexOf("CHAIN_MAX_DEPTH is " + EXPECTED_MAX_DEPTH) !== -1, past.detail);
    check("and no model call was made", modelCalls === before, String(modelCalls - before));

    await recordActorRowsSince(actorGuard, actor.id, sinceRun);
  } finally {
    console.log("\n══ cleanup ══");
    const a = await actorGuard.cleanup("end of run");
    const s = await subjectGuard.cleanup("end of run");
    if (a.leftovers.length || s.leftovers.length) failures++;
  }

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : "")); process.exit(1); }
  console.log("ALL CHECKS PASSED" + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(0);
})().catch(function (err) {
  console.error("\nThe check threw: " + ((err && err.stack) || err));
  process.exit(1);
});
