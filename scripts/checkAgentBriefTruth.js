/* ══════════════════════════════════════════════════════════════════════════
   checkAgentBriefTruth.js — what every agent is told about the platform, the
   business and how long it may write is true.

   THE DEFECTS.
     - config/brain.js told every agent "Pricing: $29.99/month" while
       PLAN_CONFIG charged 199, and listed 19 agents where the roster has 18
       ("general" is the fallback, not an agent).
     - formatBusinessProfile rendered 11 columns of business_profiles and
       dropped the rest — including offer and banned_topics.
     - processAiTask capped sixteen specialists at 1,200 output tokens, and a
       run cut off at the ceiling looked like a short answer.

   WHAT THIS PROVES, against the working copy, with no model call and no
   database write:
     1. PRICE. The assembled system prompt states PLAN_CONFIG.all_access.price
        and its tier name, read through useBillingPlans — not a typed figure.
     2. ROSTER. "Agents on this platform (N)" has N equal to the real roster
        (the keys of AGENT_SYSTEM_PROMPTS) and lists exactly those agents.
     3. PROFILE. banned_topics renders when set; a profile without the extra
        columns renders none of them and no placeholder for them, while the
        eleven core lines are unchanged.
     4. CEILINGS. TASK_OUTPUT_TOKEN_CEILINGS holds 8,192 for executive and
        content and 4,096 for the other sixteen, and processAiTask hands the
        model exactly that ceiling (1,200 for the general fallback).
     5. STOP REASON. processAiTask, given a reply that stopped at max_tokens,
        writes ai_tasks.error saying so, naming the ceiling; given end_turn,
        writes null.

   MUTATE=price    states a typed $29.99 again                 → 1 goes red
   MUTATE=roster   lists every PLATFORM_KNOWLEDGE agent again  → 2 goes red
   MUTATE=banned   drops the banned_topics line                → 3 goes red
   MUTATE=ceiling  puts operations back to 1,200               → 4 goes red
   MUTATE=stop     stops writing the stop reason               → 5 goes red
   Each mutation is applied to extracted source, never to a file, and refuses
   to run if its anchor is not found.
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const { createResidueGuard, resolveSubjectAccount } = require("./checkRunResidue");
const SUBJECT_USER_ID = resolveSubjectAccount();

const fs = require("fs");
const vm = require("vm");
const path = require("path");
const { definitionOf } = require("./_shared");
const REPO = path.join(__dirname, "..");

const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY
);
/* Nothing here writes; the guard exists so a future edit that adds a write has
   somewhere to record it, and its read-back runs regardless. */
const residue = createResidueGuard({ supabase: supabase, name: "agentBriefTruth", subject: SUBJECT_USER_ID, tables: [] });
residue.install();

const MUTATIONS = ["price", "roster", "banned", "ceiling", "stop"];
const MUTATE = process.env.MUTATE || "";
if (MUTATE && MUTATIONS.indexOf(MUTATE) === -1) { console.error("Unknown MUTATE=" + MUTATE + ". Known: " + MUTATIONS.join(", ")); process.exit(2); }

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}
function mutate(src, from, to, what) {
  if (src.split(from).length !== 2) { console.error("MUTATION REFUSED (" + what + "): anchor not found exactly once."); process.exit(3); }
  return src.replace(from, () => to);
}

const SERVER = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
function def(name) {
  const d = definitionOf(SERVER, name);
  if (!d) { console.error("EXTRACTION FAILED: " + name + " not found in server.js"); process.exit(3); }
  return d;
}

/* ── config/brain.js, loaded from source so a mutation can be applied ───── */
let BRAIN = fs.readFileSync(path.join(REPO, "config", "brain.js"), "utf8").replace(/\r\n/g, "\n");
if (MUTATE === "price") {
  BRAIN = mutate(BRAIN, `"Pricing: $" + (Number.isInteger(plan.price) ? String(plan.price) : plan.price.toFixed(2)) +`,
    `"Pricing: $29.99" +`, "price");
  console.log("\n!! MUTATION: a typed $29.99 is stated again — 1 must fail.");
}
if (MUTATE === "roster") {
  BRAIN = mutate(BRAIN, `  var roster = plan && Array.isArray(plan.allowedAgents)
    ? plan.allowedAgents
    : PLATFORM_KNOWLEDGE.agents.map(function (agent) { return agent.key; }).filter(function (key) { return key !== "general"; });`,
    `  var roster = PLATFORM_KNOWLEDGE.agents.map(function (agent) { return agent.key; });`, "roster");
  console.log("\n!! MUTATION: every PLATFORM_KNOWLEDGE agent is listed again, general included — 2 must fail.");
}
if (MUTATE === "banned") {
  BRAIN = mutate(BRAIN, `  if (banned) {`, `  if (false) {`, "banned");
  console.log("\n!! MUTATION: banned_topics is no longer rendered — 3 must fail.");
}
function loadBrain() {
  const mod = { exports: {} };
  vm.runInNewContext(BRAIN, { module: mod, exports: mod.exports, require: require, console: console, JSON: JSON });
  return mod.exports;
}

/* PLAN_CONFIG and the roster, from server.js source, exactly as declared. */
const planCtx = {};
vm.runInNewContext(def("AGENT_SYSTEM_PROMPTS").replace(/^const /, "var ") + "\n" + def("PLAN_CONFIG").replace(/^const /, "var "), planCtx);
const PLAN = planCtx.PLAN_CONFIG;
const ROSTER = Object.keys(planCtx.AGENT_SYSTEM_PROMPTS);

/* ── processAiTask, lifted, with the model and the database stubbed ─────── */
let ceilingSrc = def("TASK_OUTPUT_TOKEN_CEILINGS");
let taskSrc = def("processAiTask");
if (MUTATE === "ceiling") {
  ceilingSrc = mutate(ceilingSrc, "operations: 4096,", "operations: 1200,", "ceiling");
  console.log("\n!! MUTATION: operations is capped at 1,200 again — 4 must fail.");
}
if (MUTATE === "stop") {
  taskSrc = mutate(taskSrc, "                error: stoppedEarly,\n", "", "stop");
  console.log("\n!! MUTATION: the stop reason is no longer written — 5 must fail.");
}
function runTask(agentType, stopReason) {
  const calls = [], updates = [];
  function fake(table) {
    const st = { op: "select", payload: null, one: null };
    const b = {
      select() { return b; }, eq() { return b; }, order() { return b; }, limit() { return b; }, in() { return b; },
      insert(p) { st.op = "insert"; st.payload = p; return b; },
      update(p) { st.op = "update"; st.payload = p; if (table === "ai_tasks") updates.push(p); return b; },
      maybeSingle() { st.one = "maybe"; return b; }, single() { st.one = "single"; return b; },
      then(res, rej) { return Promise.resolve({ data: st.one ? (st.op === "insert" ? { id: "fake" } : null) : [], error: null }).then(res, rej); }
    };
    return b;
  }
  const ctx = {
    supabase: { from: fake }, console: { log() {}, warn() {}, error() {} },
    resolvePreferredLanguage: async function () { return null; },
    buildLanguageInstruction: function () { return ""; },
    executiveLanguageBlock: function () { return ""; },
    callAnthropicText: async function (prompt, maxTokens) { calls.push(maxTokens); return { text: "partial output", stopReason: stopReason }; },
    finalizeExecutiveTaskOutput: async function (u, output) { return { output: output, complete: true }; },
    reportMemoryConstraintViolation: function () {},
    /* No memory row is wanted here; an empty roster skips the write. */
    MEMORY_AGENT_TYPES: []
  };
  vm.createContext(ctx);
  vm.runInContext([ceilingSrc, def("TASK_OUTPUT_TOKEN_DEFAULT"), def("nowIso"),
    def("truncateOrchestratorPreview"), def("normalizeMemoryMetadata"), taskSrc, "this.run = processAiTask;"].join("\n\n"), ctx);
  return ctx.run("task-1", SUBJECT_USER_ID, agentType, "general", "PROMPT", false, "user prompt").then(function () {
    return { maxTokens: calls[0], update: updates[updates.length - 1], ceilings: vm.runInContext("TASK_OUTPUT_TOKEN_CEILINGS", ctx) };
  });
}

(async function main() {
  await residue.sweepPrevious(SUBJECT_USER_ID);
  const brain = loadBrain();
  brain.useBillingPlans(PLAN);
  const prompt = brain.buildAgentSystemPrompt("AGENT PROMPT", { business_name: "Fixture Co" }, {}, []);
  const lines = prompt.split("\n");

  console.log("\n══ 1. the price ══");
  const priceLine = lines.find(l => l.startsWith("Pricing:")) || "";
  console.log("    " + priceLine.slice(0, 90));
  check("1. the prompt states PLAN_CONFIG.all_access.price ($" + PLAN.all_access.price + ") and its tier name",
    priceLine.indexOf("$" + PLAN.all_access.price + "/month") === 0 + "Pricing: ".length && priceLine.indexOf("\"" + PLAN.all_access.name + "\"") !== -1, priceLine.slice(0, 60));
  check("1. no other dollar figure appears in the platform knowledge", (prompt.slice(0, prompt.indexOf("REASONING")).match(/\$\d[\d.,]*/g) || []).every(m => m === "$" + PLAN.all_access.price),
    JSON.stringify(prompt.slice(0, prompt.indexOf("REASONING")).match(/\$\d[\d.,]*/g)));

  console.log("\n══ 2. the roster ══");
  const heading = lines.find(l => l.startsWith("Agents on this platform")) || "";
  const hIdx = lines.indexOf(heading);
  const listed = [];
  for (let i = hIdx + 1; i < lines.length && lines[i].startsWith("- "); i++) listed.push((/\(([a-z_]+)\):/.exec(lines[i]) || [])[1]);
  console.log("    " + heading + " " + listed.length + " listed");
  check("2. the stated count equals the roster (" + ROSTER.length + ")", heading === "Agents on this platform (" + ROSTER.length + "):", heading);
  check("2. the agents listed are exactly the roster, in its order", JSON.stringify(listed) === JSON.stringify(ROSTER), JSON.stringify(listed));

  console.log("\n══ 3. the profile ══");
  const core = { business_name: "Fixture Co", industry: "Herbal goods", website: "example.invalid", description: "d", products_services: "p",
    target_audience: "t", brand_voice: "v", primary_goal: "g", location: "l", top_keywords: "k", top_competitors: "c" };
  const withBanned = brain.buildAgentSystemPrompt("X", Object.assign({}, core, { banned_topics: "cures, prescription drug comparisons", offer: "Shots" }), {}, []);
  const bannedLine = withBanned.split("\n").find(l => l.startsWith("BANNED TOPICS")) || "";
  console.log("    " + (bannedLine || "(no banned-topics line)"));
  check("3. banned_topics renders when set, with its value", /cures, prescription drug comparisons/.test(bannedLine), bannedLine || "missing");
  const bare = brain.buildAgentSystemPrompt("X", Object.assign({}, core, { offer: null, banned_topics: "", monthly_budget: "   ", niche: "Herbal goods" }), {}, []);
  const bareBlock = bare.slice(bare.indexOf("BUSINESS PROFILE:"), bare.indexOf("LIVE PLATFORM STATS:")).trim().split("\n");
  check("3. a profile without the extras renders none of them and no placeholder for them",
    bareBlock.length === 12 && !/Offer|BANNED|Budget|Niche/.test(bareBlock.join("\n")), JSON.stringify(bareBlock.slice(12)));
  check("3. the eleven core lines are unchanged", bareBlock[1] === "Business Name: Fixture Co" && bareBlock[11] === "Competitors: c", JSON.stringify(bareBlock.slice(0, 12)));

  console.log("\n══ 4. the output ceilings ══");
  const expected = {};
  ROSTER.forEach(a => { expected[a] = (a === "executive" || a === "content") ? 8192 : 4096; });
  const probe = await runTask("operations", "end_turn");
  ROSTER.forEach(a => check("4. " + a + " is capped at " + expected[a], probe.ceilings[a] === expected[a], probe.ceilings[a]));
  check("4. processAiTask hands the model operations' ceiling (" + expected.operations + ")", probe.maxTokens === expected.operations, probe.maxTokens);
  const general = await runTask("general", "end_turn");
  check("4. the general fallback keeps 1,200", general.maxTokens === 1200, general.maxTokens);

  console.log("\n══ 5. the stop reason ══");
  const cut = await runTask("email", "max_tokens");
  console.log("    max_tokens → error " + JSON.stringify(cut.update && cut.update.error));
  check("5. a reply that hit the ceiling is recorded as incomplete, naming max_tokens and the 4096-token limit",
    !!cut.update && /stop_reason "max_tokens"/.test(cut.update.error || "") && /4096-token output limit/.test(cut.update.error || "") && cut.update.status === "completed",
    JSON.stringify(cut.update));
  const whole = await runTask("email", "end_turn");
  check("5. a reply that finished records no error", !!whole.update && whole.update.error === null, JSON.stringify(whole.update && whole.update.error));

  console.log("\n══ cleanup ══");
  const done = await residue.cleanup("end of run");
  if (done.leftovers.length) failures++;
  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
})().catch(function (err) {
  console.error("\nThe check threw: " + ((err && err.stack) || err));
  process.exit(1);
});
