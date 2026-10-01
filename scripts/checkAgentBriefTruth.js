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
     6-10. THE OTHER SYSTEMS. Each corrected sentence about Lead Radar, SMS,
        social publishing, the subscription and agent_memory is asserted
        twice: once against the code it describes (leadRadar.js, server.js)
        and once against what the agents are told. Social publishing is gated,
        so it must be named as unavailable, not left out.
     NOT ASSERTED, because no source file holds it: the deployed values of
     ENABLE_MASTODON_RADAR, ENABLE_YOUTUBE_RADAR, ENABLE_LEAD_SCORING and
     ENABLE_DRIP_SCHEDULER ("off by default" is what the code says, not what
     Railway has set); and the Oracle and card-builder sentences, which were
     true and were not changed.

   MUTATE=price    states a typed $29.99 again                 → 1 goes red
   MUTATE=roster   lists every PLATFORM_KNOWLEDGE agent again  → 2 goes red
   MUTATE=banned   drops the banned_topics line                → 3 goes red
   MUTATE=ceiling  puts operations back to 1,200               → 4 goes red
   MUTATE=stop     stops writing the stop reason               → 5 goes red
   MUTATE=radar    restores "scores against the profile"       → 6 goes red
   MUTATE=sms      restores "broadcasts segmentable by filter" → 7 goes red
   MUTATE=social   leaves social publishing out                → 8 goes red
   Each mutation is applied to extracted source, never to a file, and refuses
   to run if its anchor is not found.
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const { createResidueGuard, resolveSubjectAccount } = require("./checkRunResidue");
const SUBJECT_USER_ID = resolveSubjectAccount();

const fs = require("fs");
const vm = require("vm");
const path = require("path");
const { definitionOf, braceMatch } = require("./_shared");
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

const MUTATIONS = ["price", "roster", "banned", "ceiling", "stop", "radar", "sms", "social"];
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
function routeBody(signature) {
  const at = SERVER.indexOf(signature);
  if (at === -1) { console.error("EXTRACTION FAILED: " + signature + " not found in server.js"); process.exit(3); }
  return SERVER.slice(at, braceMatch(SERVER, SERVER.indexOf("{", SERVER.indexOf("function", at))));
}
const RADAR = fs.readFileSync(path.join(REPO, "leadRadar.js"), "utf8").replace(/\r\n/g, "\n");
function radarDef(name) {
  const d = definitionOf(RADAR, name);
  if (!d) { console.error("EXTRACTION FAILED: " + name + " not found in leadRadar.js"); process.exit(3); }
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
if (MUTATE === "radar") {
  BRAIN = mutate(BRAIN, /"A background job that every 5 minutes collects public Bluesky posts[^"]*"/.exec(BRAIN)[0],
    `"A background job that scans Bluesky every 5 minutes for buying-intent posts, scores them against the user's business profile (industry, competitors), and separates genuine buyers from competitor mentions by matched keyword and suggested product (stored in bsky_leads)."`, "radar");
  console.log("\n!! MUTATION: Lead Radar is described as scoring against the business profile again — 6 must fail.");
}
if (MUTATE === "sms") {
  BRAIN = mutate(BRAIN, /"An SMS subscriber list \(sms_subscribers\)[^"]*"/.exec(BRAIN)[0],
    `"Opted-in SMS subscriber list (sms_subscribers) with consent tracking, and broadcast campaigns (sms_campaigns) segmentable by filter. Subscriber counts, opt-in counts, and campaign counts feed the live Analytics dashboard."`, "sms");
  console.log("\n!! MUTATION: SMS is described as sending, segmentable broadcasts again — 7 must fail.");
}
if (MUTATE === "social") {
  BRAIN = mutate(BRAIN, /    social_publishing: \{[\s\S]*?\n    \},\n/.exec(BRAIN)[0], "", "social");
  console.log("\n!! MUTATION: social publishing is left out instead of said to be unavailable — 8 must fail.");
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

  /* Sections 6-10 pair each corrected sentence with the code it describes:
     one assertion reads the code, the other reads what the agents are told.
     A change to either side turns its own assertion red. */
  const systemLine = name => lines.find(l => l.startsWith("- " + name + ":")) || "";

  console.log("\n══ 6. Lead Radar ══");
  const radar = systemLine("Lead Radar");
  const tick = radarDef("radarTick"), scorer = radarDef("scoreNewLeads"), start = radarDef("startLeadRadar");
  const scorerPromptStart = scorer.indexOf("var prompt =");
  const scorerPrompt = scorer.slice(scorerPromptStart, scorer.indexOf("\";\n", scorerPromptStart) + 2);
  console.log("    " + radar.slice(0, 110) + "…");
  check("6. code: the tick runs every 300,000 ms and Bluesky capture is not behind a switch",
    /setInterval\(radarTick, 300000\)/.test(start) && tick.indexOf("runLeadRadarOnce(") !== -1 && tick.indexOf("runLeadRadarOnce(") < tick.indexOf("process.env.ENABLE_"));
  check("6. code: Mastodon and YouTube capture run only when their switch is exactly \"true\"",
    tick.indexOf('process.env.ENABLE_MASTODON_RADAR === "true"') !== -1 && tick.indexOf('process.env.ENABLE_YOUTUBE_RADAR === "true"') !== -1);
  check("6. code: Reddit is never started (every startRedditRadar call is commented out)",
    SERVER.split("\n").filter(l => l.indexOf("startRedditRadar(") !== -1).every(l => l.trim().startsWith("//")));
  check("6. told: Bluesky every 5 minutes, Mastodon and YouTube off by default, Reddit disabled",
    /every 5 minutes collects public Bluesky posts/.test(radar) && /Mastodon and YouTube collection exist behind switches that are off by default/.test(radar) && /Reddit is disabled/.test(radar), radar.slice(0, 80));
  const PROFILE_FIELDS = ["business_profiles", "industry", "competitor", "target_audience", "products_services", "business_name", "profile"];
  check("6. code: neither scoreNewLeads nor its prompt reads a business-profile field",
    scorerPromptStart !== -1 && PROFILE_FIELDS.every(f => scorer.indexOf(f) === -1), PROFILE_FIELDS.filter(f => scorer.indexOf(f) !== -1).join(","));
  check("6. told: it does not read the business profile, and nothing says it scores against industry or competitors",
    /It does not read the user's business profile\./.test(radar) && !/business profile \(|competitor/i.test(radar), radar.slice(0, 80));
  check("6. code: scoring runs only when ENABLE_LEAD_SCORING is exactly \"true\"",
    /if \(process\.env\.ENABLE_LEAD_SCORING === "true"\) \{[^}]*scoreNewLeads\(/.test(tick));
  check("6. code: the scorer separates seekers from teachers and sellers, scores 0-100, and screens safety and invitation",
    ["teaching, coaching, promoting, or selling", "<integer 0-100>", "SAFE | UNSAFE", "INVITED | NOT_INVITED"].every(s => scorerPrompt.indexOf(s) !== -1));
  check("6. told: scoring is switched, 0-100, seekers vs teachers, coaches and sellers, a fixed product list, safety and invitation",
    /When scoring is switched on/.test(radar) && /rated 0-100/.test(radar) && /teachers, coaches and sellers/.test(radar) && /fixed list/.test(radar) && /safe and invited/.test(radar));
  const radarRefusals = (SERVER.match(/res\.status\(403\)\.json\(LEAD_RADAR_UNAVAILABLE\)/g) || []).length;
  check("6. code: the lead routes refuse other accounts with LEAD_RADAR_UNAVAILABLE (" + radarRefusals + " routes)",
    /const LEAD_RADAR_UNAVAILABLE = \{/.test(SERVER) && radarRefusals >= 4, radarRefusals);
  check("6. told: unavailable to customer accounts", /UNAVAILABLE TO CUSTOMER ACCOUNTS/.test(radar));

  console.log("\n══ 7. SMS ══");
  const sms = systemLine("SMS Marketing / Drip System");
  const enroll = routeBody('app.post("/api/sms/campaigns/:id/enroll"');
  console.log("    " + sms.slice(0, 110) + "…");
  const smsSendsNothing = /^const SMS_DIRECT_SEND_ENABLED = false;$/m.test(SERVER) && def("runDripEngine").indexOf("var DRY_RUN = true;") !== -1;
  check("7. code: direct sending is off and the drip engine is a hard-coded dry run", smsSendsNothing);
  check("7. told: sending is unavailable, and never that messages went out",
    /SENDING IS CURRENTLY UNAVAILABLE/.test(sms) && /Never tell a user their messages have gone out/.test(sms));
  check("7. code: enrolment takes an explicit subscriber_ids list, with no filter or segment",
    enroll.indexOf("req.body.subscriber_ids") !== -1 && !/filter|segment/i.test(enroll));
  check("7. told: drip campaigns enrolled by hand, no filter or segment, nothing called a broadcast",
    /enrolled in by hand/.test(sms) && /there is no filter or segment/.test(sms) && !/segmentable|broadcast/i.test(sms), sms.slice(0, 80));
  const liveStats = def("getLiveStats");
  check("7. code: GET /api/analytics/summary returns getLiveStats, which counts subscribers and campaigns",
    routeBody('app.get("/api/analytics/summary"').indexOf("getLiveStats(") !== -1 && liveStats.indexOf('"sms_subscribers"') !== -1 && liveStats.indexOf('"sms_campaigns"') !== -1);
  check("7. told: the counts feed the live Analytics dashboard", /feed the live Analytics dashboard/.test(sms));

  console.log("\n══ 8. social publishing — gated, so said to be unavailable, not left out ══");
  const social = systemLine("Social Publishing");
  console.log("    " + (social.slice(0, 110) || "(no Social Publishing line)"));
  const socialGated = /^const SOCIAL_ACCOUNTS_SCOPED = false;$/m.test(SERVER) && /status:\s+"not_published"/.test(SERVER);
  check("8. code: SOCIAL_ACCOUNTS_SCOPED is false and a publish is saved as not_published", socialGated);
  check("8. told: the feature is named, said to be unavailable, and drafts said to be saved unpublished",
    /currently unavailable/.test(social) && /marked not published; nothing is posted/.test(social), social.slice(0, 60) || "missing");

  console.log("\n══ 9. what the subscription unlocks ══");
  const pricing = lines.find(l => l.startsWith("Pricing:")) || "";
  const platform = lines.find(l => l.startsWith("BizForce AI — ")) || "";
  const unlocks = pricing.slice(pricing.indexOf("unlocks"), pricing.indexOf("—"));
  check("9. told: the unlock list names nothing that is gated off", !/lead radar|sms drip|publish/i.test(unlocks), unlocks);
  check("9. told: the pricing line says SMS sending, social publishing and Lead Radar are unavailable, as the code has them",
    smsSendsNothing && socialGated && radarRefusals >= 4 && /SMS sending, social publishing and Lead Radar are unavailable on every customer account/.test(pricing), pricing.slice(-120));
  check("9. told: the platform line claims no SMS marketing or lead detection, and names what is unavailable",
    !/SMS marketing|lead detection/.test(platform) && /Sending SMS, publishing to social accounts and Lead Radar are currently unavailable/.test(platform), platform.slice(0, 80));

  console.log("\n══ 10. data_model (documentation: never rendered into a prompt) ══");
  const memDoc = brain.PLATFORM_KNOWLEDGE.data_model.agent_memory;
  check("10. data_model is not rendered into the agents' prompt", prompt.indexOf("Longer-lived per-agent") === -1);
  const memInserts = ["orchestrateAgentWorkflow", "processAiTask", "convertSingleLead"].map(def)
    .concat(['app.post("/api/oracle"', 'app.post("/api/memory"', 'app.post("/api/agents/seo/optimize"', 'app.post("/api/agents/sales/lead-status"'].map(routeBody));
  check("10. code: agent_memory is inserted by the task, assignment, Oracle, memory-page, SEO and sales paths it names",
    memInserts.every(b => /\.from\("agent_memory"\)\s*\.insert\(/.test(b)), memInserts.map(b => /\.from\("agent_memory"\)\s*\.insert\(/.test(b)).join(","));
  check("10. code: a typed task reads its agent's five newest memories",
    /\.from\("agent_memory"\)[\s\S]{0,300}\.eq\("agent_type", agentType\)[\s\S]{0,100}\.limit\(5\)/.test(def("handleAiTaskRequest")));
  check("10. documented: the same writers, and five newest read into the next typed task",
    /when a task completes/.test(memDoc) && /when an assignment starts/.test(memDoc) && /on each Oracle exchange/.test(memDoc) && /by the SEO and sales tools/.test(memDoc) && /from the memory page/.test(memDoc) && /five newest per agent are read into that agent's next typed task/.test(memDoc), memDoc);

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
