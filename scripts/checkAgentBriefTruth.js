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
     11. NO INVENTION. NO_INVENTION_RULE covers statistics, offers, arithmetic,
        estimates and "I don't have that figure", and is the LAST block of the
        assembled prompt — after memory, which carries earlier invented
        figures — appearing once and not also inside BRAIN_DIRECTIVES.
     12. TASKS PER AGENT. getLiveStats, run against a fake table of 7,951 rows
        that returns at most 1,000 to a non-count select, reports sales as
        7,900, every agent exactly, and a breakdown summing to tasksRun.
     13. LEAD RADAR BY ACCOUNT. getLiveStats says "available" to the credential
        owner and "not available" to anyone else, with the constant the lead
        routes refuse on; the knowledge text points at that line and covers
        available, not available and absent.
     14. WHAT A ZERO MEANS. A zero-stats account — every figure getLiveStats
        produces, at 0 — renders a stats block that says the counts cover only
        BizForce on this account, that a zero means nothing recorded here,
        never "none", never a baseline or projection input, and that the
        user's own site, lists, channels and sales are not measured; every
        zero is still shown, each with what it counts; and the trailing
        NO_INVENTION_RULE says the same of the stats it names as a source.
        Section 11 also holds the rule at 1,600 characters or fewer, with every
        clause giving a sentence, a slot or an example, or naming a specific
        error — the only kind measured to land — and no ESTIMATE or "assuming".
     15. PEOPLE AND PRODUCT FACTS. The rule forbids words presented as a
        customer's, even as an example or labelled sample, and what customers
        do or how many there are, and gives the marked slot instead; forbids
        product and company facts the profile does not hold; and makes BANNED
        TOPICS bind words put in a customer's mouth.
     16. REASONING STAYS OUT OF THE REPLY. The model call has no private
        reasoning channel (no thinking parameter), so the directive no longer
        says "internally": it says the thinking is not part of the reply, the
        reply begins with the answer, and no section narrates the reasoning.
     17. INVENTED CUSTOMER WORDS, IN CODE. processAiTask screens the output
        before the first result write and the memory write. Run with an agent
        reply holding the two clean-2 fabrications, neither appears in any
        stored row — result, error or agent_memory — and the result opens with
        the notice and carries the marked slots. A quotation the user supplied,
        in the request or the profile, is kept; a question, a negated
        instruction, the placeholder and an unattributed line are left alone.
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
   MUTATE=invent   puts the rule with the directives, not last → 11 goes red
   MUTATE=tally    restores the fetch-and-tally byAgent        → 12 goes red
   MUTATE=owner    restores "unavailable to customer accounts" → 13 goes red
   MUTATE=zero     restores "this user's real, current usage"  → 14 goes red
   MUTATE=dontknow     drops the "I don't have that figure" clause → 11 goes red
   MUTATE=memory       drops the memory-is-not-fact clause     → 11 goes red
   MUTATE=offers       drops the only-the-profile's-offers clause → 11 goes red
   MUTATE=zerobase     drops the stats-scope and zero clause   → 14 goes red
   MUTATE=testimonial  drops the customer-words clause         → 15 goes red
   MUTATE=product      drops the product-facts clause          → 15 goes red
   MUTATE=reach        drops "BANNED TOPICS bind every word"   → 15 goes red
   MUTATE=reasoning    restores "reason step-by-step and internally" → 16 goes red
   MUTATE=screen       screens the output but stores the original → 17 goes red
   MUTATE=cue          takes out any first-person quote, attributed or not → 17 goes red
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

const MUTATIONS = ["price", "roster", "banned", "ceiling", "stop", "radar", "sms", "social", "invent", "tally", "owner", "zero",
  "dontknow", "memory", "offers", "zerobase", "testimonial", "product", "reach", "reasoning", "screen", "cue",
  "inference", "audit", "reader"];
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

let SERVER = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
if (MUTATE === "tally") {
  SERVER = mutate(SERVER, `    countTasksByAgent(userId)\n  ]);`, `    supabase.from("ai_tasks").select("agent_type").eq("user_id", userId)\n  ]);`, "tally");
  SERVER = mutate(SERVER, `  } else {\n    byAgent = agentRowsResult.byAgent;\n  }`,
    `  } else if (Array.isArray(agentRowsResult.data)) {\n    agentRowsResult.data.forEach(function (row) {\n      var t = row.agent_type || "general";\n      byAgent[t] = (byAgent[t] || 0) + 1;\n    });\n  }`, "tally");
  console.log("\n!! MUTATION: byAgent is a fetch-and-tally again — 12 must fail.");
}
if (MUTATE === "audit") {
  SERVER = mutate(SERVER, "            throw updateResult.error;\n        }\n\n        await recordTestimonialRemovals(taskId, userId, agentType, testimonialScreen.removals);\n",
    "            throw updateResult.error;\n        }\n", "audit");
  console.log("\n!! MUTATION: a completed task no longer records what the screen removed — 18 must fail.");
}
if (MUTATE === "reader") {
  SERVER = mutate(SERVER, "async function recordTestimonialRemovals(", "async function readRemovalsForPrompt(userId) {\n  return supabase.from(\"testimonial_screen_removals\").select(\"passage\").eq(\"user_id\", userId);\n}\nasync function recordTestimonialRemovals(", "reader");
  console.log("\n!! MUTATION: something now reads the removal record — 18 must fail.");
}
if (MUTATE === "screen") {
  SERVER = mutate(SERVER, "        output = testimonialScreen.text;\n", "", "screen");
  console.log("\n!! MUTATION: processAiTask screens the output but stores the original — 17 must fail.");
}
if (MUTATE === "cue") {
  SERVER = mutate(SERVER, "    if (!(CUSTOMER_CUE.test(before) || CUSTOMER_CUE.test(after) || SIGNATURE.test(after))) continue;\n", "", "cue");
  console.log("\n!! MUTATION: any first-person quote is taken out, attributed or not — 17 must fail.");
}
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
if (MUTATE === "invent") {
  BRAIN = mutate(BRAIN, `    BRAIN_DIRECTIVES,\n    String(agentSpecificPrompt || "").trim(),`, `    BRAIN_DIRECTIVES,\n    NO_INVENTION_RULE,\n    String(agentSpecificPrompt || "").trim(),`, "invent");
  BRAIN = mutate(BRAIN, `    formatMemories(memories),\n    NO_INVENTION_RULE\n  ].join`, `    formatMemories(memories)\n  ].join`, "invent");
  console.log("\n!! MUTATION: the no-invention rule sits with the directives, ahead of the agent prompt and memory — 11 must fail.");
}
if (MUTATE === "owner") {
  BRAIN = mutate(BRAIN, /IT WORKS ON ONE ACCOUNT ONLY:[^"]*"/.exec(BRAIN)[0],
    `UNAVAILABLE TO CUSTOMER ACCOUNTS: it runs against the platform's own connected social account, and its leads, scores and replies are shown to no other account."`, "owner");
  console.log("\n!! MUTATION: Lead Radar is \"unavailable to customer accounts\" again, with nothing to tell the owner apart — 13 must fail.");
}
if (MUTATE === "zero") {
  BRAIN = mutate(BRAIN, `  return LIVE_STATS_HEADER + "\\n" + lines.join("\\n");`,
    `  return "LIVE PLATFORM STATS (this user's real, current usage — use it, don't ignore it):\\n" + lines.join("\\n");`, "zero");
  console.log("\n!! MUTATION: the stats block calls itself \"this user's real, current usage\" again — 14 must fail.");
}
/* Each drops one clause of NO_INVENTION_RULE. The last clause ends the string
   with ";" rather than " +", so it is dropped with the "+" of the line before. */
const RULE_CLAUSE_MUTATIONS = {
  dontknow:    ["If a figure is not in the BUSINESS PROFILE", "11"],
  memory:      ["A figure found only in ACCUMULATED MEMORY", "11"],
  offers:      ["Only the offers in the business profile exist", "11"],
  zerobase:    ["LIVE PLATFORM STATS counts only activity inside BizForce", "14"],
  testimonial: ["Do not write words presented as a customer's", "15"],
  product:     ["Do not state a product or company fact", "15"],
  reach:       ["BANNED TOPICS bind every word", "15"]
};
if (MUTATE === "inference") {
  BRAIN = mutate(BRAIN, " The user naming a product says nothing about it: do not say which product sells most or best, what is new or launching, how anything is packaged, shipped or paid for, or a price, size, strength, format, ingredient, process or company age it does not give; say what the owner must supply.",
    " Say what the owner must supply.", "inference");
  console.log("\n!! MUTATION: the named inferences are gone, the category is left — 15 must fail.");
}
if (RULE_CLAUSE_MUTATIONS[MUTATE]) {
  const prefix = RULE_CLAUSE_MUTATIONS[MUTATE][0];
  const line = new RegExp("\\n  \"- " + prefix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "[^\\n]*").exec(BRAIN);
  if (!line) { console.error("MUTATION REFUSED (" + MUTATE + "): clause not found."); process.exit(3); }
  BRAIN = /;$/.test(line[0])
    ? mutate(BRAIN, " +" + line[0], ";", MUTATE).replace(/\\n";$/m, "\";")
    : mutate(BRAIN, line[0], "", MUTATE);
  console.log("\n!! MUTATION: the clause beginning \"" + prefix + "\" is gone — " + RULE_CLAUSE_MUTATIONS[MUTATE][1] + " must fail.");
}
if (MUTATE === "reasoning") {
  BRAIN = mutate(BRAIN, "Before answering, think it through: break the request into its component parts, weigh the realistic options for each, check your own logic for gaps or contradictions, and converge on the strongest concrete answer. That thinking is not part of the reply. Begin with the answer itself, and never write a section that narrates your reasoning, your reading of the request or these instructions.",
    "Before answering, reason step-by-step and internally: break the request into its component parts, weigh the realistic options for each, check your own logic for gaps or contradictions, and converge on the strongest concrete answer.", "reasoning");
  console.log("\n!! MUTATION: the directive says \"reason step-by-step and internally\" again — 16 must fail.");
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
  taskSrc = mutate(taskSrc, "error: [stoppedEarly, testimonialScreen.removed", "error: [testimonialScreen.removed", "stop");
  console.log("\n!! MUTATION: the stop reason is no longer written — 5 must fail.");
}
function runTask(agentType, stopReason, opts) {
  opts = opts || {};
  const calls = [], updates = [], inserts = [];
  function fake(table) {
    const st = { op: "select", payload: null, one: null };
    const b = {
      select() { return b; }, eq() { return b; }, order() { return b; }, limit() { return b; }, in() { return b; },
      insert(p) { st.op = "insert"; st.payload = p; inserts.push({ table: table, payload: p }); return b; },
      update(p) { st.op = "update"; st.payload = p; if (table === "ai_tasks") updates.push(p); return b; },
      maybeSingle() { st.one = "maybe"; return b; }, single() { st.one = "single"; return b; },
      then(res, rej) {
        /* opts.failAudit: the removal record cannot be written (migration 124 not applied). */
        if (opts.failAudit && table === "testimonial_screen_removals") {
          return Promise.resolve({ data: null, error: { message: "relation \"testimonial_screen_removals\" does not exist" } }).then(res, rej);
        }
        return Promise.resolve({ data: st.one ? (st.op === "insert" ? { id: "fake" } : null) : [], error: null }).then(res, rej);
      }
    };
    return b;
  }
  const ctx = {
    supabase: { from: fake }, console: { log() {}, warn() {}, error() {} },
    resolvePreferredLanguage: async function () { return null; },
    buildLanguageInstruction: function () { return ""; },
    executiveLanguageBlock: function () { return ""; },
    callAnthropicText: async function (prompt, maxTokens) { calls.push(maxTokens); return { text: opts.text || "partial output", stopReason: stopReason }; },
    finalizeExecutiveTaskOutput: async function (u, output) { return { output: output, complete: true }; },
    reportMemoryConstraintViolation: function () {},
    /* No memory row is wanted unless asked for; an empty roster skips the write. */
    MEMORY_AGENT_TYPES: opts.memory ? [agentType] : []
  };
  vm.createContext(ctx);
  vm.runInContext([ceilingSrc, def("TASK_OUTPUT_TOKEN_DEFAULT"), def("nowIso"),
    def("truncateOrchestratorPreview"), def("normalizeMemoryMetadata"),
    def("TESTIMONIAL_SLOT"), def("normalizedQuoteText"), def("screenFabricatedTestimonials"), def("recordTestimonialRemovals"),
    taskSrc, "this.run = processAiTask;"].join("\n\n"), ctx);
  return ctx.run("task-1", SUBJECT_USER_ID, agentType, "general", opts.finalPrompt || "PROMPT", false, opts.userPrompt || "user prompt").then(function () {
    return { maxTokens: calls[0], update: updates[updates.length - 1], updates: updates, inserts: inserts,
      ceilings: vm.runInContext("TASK_OUTPUT_TOKEN_CEILINGS", ctx), slot: vm.runInContext("TESTIMONIAL_SLOT", ctx) };
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
  check("9. told: the pricing line says SMS sending and social publishing are unavailable, and Lead Radar works on one account, as the code has them",
    smsSendsNothing && socialGated && radarRefusals >= 4 &&
    /SMS sending and social publishing are unavailable on every account, whatever the plan, and Lead Radar works only on the one account that holds the platform's connected social credentials\./.test(pricing), pricing.slice(-160));
  check("9. told: the platform line claims no SMS marketing or lead detection, and names what is unavailable",
    !/SMS marketing|lead detection/.test(platform) && /Sending SMS and publishing to social accounts are currently unavailable; Lead Radar works on one account only/.test(platform), platform.slice(0, 80));

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

  console.log("\n══ 11. no invented numbers or offers — present, short, and last ══");
  const rule = brain.NO_INVENTION_RULE || "";
  const withMemory = brain.buildAgentSystemPrompt("AGENT PROMPT", { business_name: "Fixture Co" }, { tasksRun: 3 },
    [{ agent_type: "sales", title: "Earlier plan", content: "Estimated impact: 3-5 percent conversion." }]);
  console.log("    " + rule.slice(0, 100) + "…  (" + rule.length + " chars)");
  check("11. a missing figure gets the sentence \"I don't have that figure\", not a supplied one",
    /- If a figure is not in the BUSINESS PROFILE or LIVE PLATFORM STATS, do not supply one: say "I don't have that figure" and where the owner can find it\./.test(rule));
  check("11. a figure found only in memory is not repeated as a fact",
    /- A figure found only in ACCUMULATED MEMORY came from an earlier agent's output: do not repeat it as a fact\./.test(rule));
  check("11. only the profile's offers exist; any other is recommended once as the owner's decision",
    /- Only the offers in the business profile exist\. Do not write a discount, guarantee, bundle, subscription, shipping term or return policy into copy or a plan; if one might help, recommend it once as the owner's decision\./.test(rule));
  check("11. derived numbers show their arithmetic, by example",
    /- Show the arithmetic for a derived number: \$55 \/ 6 = \$9\.17 a shot\./.test(rule));
  check("11. the rule is the last block of the assembled prompt, after memory, and appears once",
    !!rule && withMemory.endsWith(rule) && withMemory.indexOf(rule) > withMemory.indexOf("ACCUMULATED MEMORY") &&
    withMemory.split(rule).length === 2, withMemory.slice(-80));
  check("11. it says it governs the instructions after it, forecasts included",
    /This rule governs every instruction above and after it, including requests for forecasts or projections\./.test(rule));
  check("11. it is not also inside BRAIN_DIRECTIVES (one copy, one position)", brain.BRAIN_DIRECTIVES.indexOf("NO INVENTED NUMBERS") === -1);
  /* Measured over four runs, only clauses that give a sentence to say or name
     a specific error were followed; the rule was cut to those. These two keep
     it that way: it stays short, and the abstract clauses do not come back. */
  check("11. the rule stays short (" + rule.length + " characters, at most 1,600)", rule.length > 0 && rule.length <= 1600, rule.length);
  const clauses = rule.split("\n").filter(l => l.indexOf("- ") === 0);
  check("11. every clause gives a sentence, a slot or an example, or names a specific error (" + clauses.length + " clauses)",
    clauses.length >= 8 && clauses.every(c => /"[^"]+"|\[TESTIMONIAL NEEDED|\$55 \/ 6|\b(?:do not|never|is not|not 0%)\b/i.test(c)) &&
    !/ESTIMATE|assuming/.test(rule), JSON.stringify(clauses.filter(c => !/"[^"]+"|\[TESTIMONIAL NEEDED|\$55 \/ 6|\b(?:do not|never|is not|not 0%)\b/i.test(c))));

  console.log("\n══ 12. tasks per agent — counted, not a capped tally ══");
  /* A fake ai_tasks holding the owner's real shape: 7,951 rows, 7,900 of them
     sales, plus a type no longer on the roster and a null. A select that is not
     a head-count returns at most 1,000 rows, as PostgREST does. */
  const FAKE_ROWS = [];
  const SHAPE = { sales: 7900, content: 21, executive: 13, social: 7, seo: 3, general: 2, email: 2, rd: 2, operations: 1, legacy_type: 3, "": 1 };
  Object.keys(SHAPE).forEach(t => { for (let i = 0; i < SHAPE[t]; i++) FAKE_ROWS.push({ user_id: require("../lib/ownerAccount").OWNER_ACCOUNT_ID, agent_type: t === "" ? null : t }); });
  const fakeCalls = [];
  function statsDb() {
    return {
      from(table) {
        const st = { filters: [], head: false, cols: "" };
        const b = {
          select(cols, opts) { st.cols = cols; st.head = !!(opts && opts.head); return b; },
          eq(col, val) { st.filters.push(r => r[col] === val); return b; },
          is(col, val) { st.filters.push(r => r[col] === val); return b; },
          then(res, rej) {
            fakeCalls.push({ table: table, head: st.head, cols: st.cols });
            const rows = table === "ai_tasks" ? FAKE_ROWS.filter(r => st.filters.every(f => f(r))) : [];
            const out = st.head ? { count: rows.length, error: null } : { data: rows.slice(0, 1000), error: null };
            return Promise.resolve(out).then(res, rej);
          }
        };
        return b;
      }
    };
  }
  const statsCtx = { supabase: statsDb(), console: { error() {}, log() {}, warn() {} }, OWNER_ACCOUNT_ID: require("../lib/ownerAccount").OWNER_ACCOUNT_ID };
  vm.createContext(statsCtx);
  const helper = definitionOf(SERVER, "countTasksByAgent");
  vm.runInContext([def("AGENT_SYSTEM_PROMPTS"), def("OUTREACH_CREDENTIAL_OWNER_ID"), def("getLiveStats"), helper || ""]
    .map(s => s.replace(/^const /, "var ")).join("\n\n") + "\nthis.run = getLiveStats;", statsCtx);
  const ownerStats = await statsCtx.run(statsCtx.OWNER_ACCOUNT_ID);
  const expectedByAgent = { seo: 3, sales: 7900, content: 21, email: 2, operations: 1, executive: 13, social: 7, rd: 2, general: 3, other: 3 };
  console.log("    byAgent " + JSON.stringify(ownerStats.byAgent));
  check("12. code: getLiveStats fetches no agent_type rows to tally",
    !/\.select\("agent_type"\)/.test(def("getLiveStats")) && !fakeCalls.some(c => c.table === "ai_tasks" && !c.head),
    JSON.stringify(fakeCalls.filter(c => !c.head)));
  check("12. sales is counted past the 1,000-row cap (7,900, not a slice)", ownerStats.byAgent.sales === 7900, ownerStats.byAgent.sales);
  check("12. every agent is exact; a null type counts as general; an unlisted type is reported as other",
    JSON.stringify(Object.keys(expectedByAgent).sort().map(k => [k, ownerStats.byAgent[k]])) === JSON.stringify(Object.keys(expectedByAgent).sort().map(k => [k, expectedByAgent[k]])) &&
    Object.keys(ownerStats.byAgent).length === Object.keys(expectedByAgent).length, JSON.stringify(ownerStats.byAgent));
  check("12. the breakdown sums to tasksRun (" + ownerStats.tasksRun + ")",
    Object.values(ownerStats.byAgent).reduce((a, b) => a + b, 0) === ownerStats.tasksRun, Object.values(ownerStats.byAgent).reduce((a, b) => a + b, 0));

  console.log("\n══ 13. Lead Radar — the owner told apart from a customer ══");
  const customerStats = await statsCtx.run(SUBJECT_USER_ID);
  const radarLine = systemLine("Lead Radar");
  console.log("    owner: " + ownerStats.leadRadar + " | other account: " + customerStats.leadRadar);
  check("13. code: getLiveStats decides with the same constant the lead routes refuse on",
    /userId === OUTREACH_CREDENTIAL_OWNER_ID/.test(def("getLiveStats")) && /req\.user\.id !== OUTREACH_CREDENTIAL_OWNER_ID/.test(SERVER));
  check("13. code: the credential owner is told available, any other account not available",
    /^available on this account/.test(ownerStats.leadRadar || "") && customerStats.leadRadar === "not available on this account",
    JSON.stringify([ownerStats.leadRadar, customerStats.leadRadar]));
  const ownerPrompt = brain.buildAgentSystemPrompt("X", {}, { leadRadar: ownerStats.leadRadar }, []);
  check("13. the leadRadar line reaches the prompt", ownerPrompt.indexOf("- leadRadar: available on this account") !== -1);
  check("13. told: one account only, the leadRadar line names which, all three cases covered, no blanket \"customer accounts\"",
    /IT WORKS ON ONE ACCOUNT ONLY/.test(radarLine) && /The leadRadar line in LIVE PLATFORM STATS says which this user is\./.test(radarLine) &&
    /If it says available, this user holds the credentials and Lead Radar is theirs to use\./.test(radarLine) &&
    /If it says not available, it is unavailable to them\./.test(radarLine) &&
    /If there is no leadRadar line, you do not know which account this is: do not tell the user either way\./.test(radarLine) &&
    !/CUSTOMER ACCOUNTS/i.test(radarLine), radarLine.slice(-200));

  console.log("\n══ 14. what a zero in the stats means ══");
  /* customerStats is the real getLiveStats run for an account with no rows at
     all — a new account, every count at zero. */
  const zeroPrompt = brain.buildAgentSystemPrompt("X", {}, customerStats, []);
  /* The block, not the Lead Radar sentence that names it: the last heading
     before the memory block. */
  const memoryAt = zeroPrompt.indexOf("\n\nACCUMULATED MEMORY");
  const statsBlock = zeroPrompt.slice(zeroPrompt.lastIndexOf("\n\nLIVE PLATFORM STATS", memoryAt), memoryAt).trim();
  const statsLines = statsBlock.split("\n");
  console.log("    " + statsLines[0]);
  const countKeys = Object.keys(customerStats).filter(k => k !== "_unreadable" && typeof customerStats[k] === "number");
  check("14. the account really is all zeros (" + countKeys.length + " counts)", countKeys.length >= 9 && countKeys.every(k => customerStats[k] === 0), JSON.stringify(customerStats));
  check("14. told: the counts cover only what is done inside BizForce, on this account",
    /^LIVE PLATFORM STATS \(activity inside BizForce on this account, and nothing else\):$/.test(statsLines[0]) &&
    /These figures count only what has been done inside BizForce on this account\./.test(statsBlock), statsLines[0]);
  check("14. told: a zero means nothing recorded here, not that the business has none",
    /A zero means nothing has been recorded here yet, not that the user's business has none\./.test(statsBlock));
  check("14. told: never imply none from a zero, never a baseline, starting point or projection input",
    /Never state or imply that the user has none of something because a count here is zero, and never use a zero from this block as a baseline, a starting point or an input to a projection\./.test(statsBlock));
  check("14. told: the user's own website, lists, channels and sales exist outside and are not measured here",
    /The user's own website, customers, email and SMS lists, social channels, sales and history exist outside this platform and are not measured here\./.test(statsBlock));
  check("14. the old self-description is gone", statsBlock.indexOf("this user's real, current usage") === -1);
  check("14. every zero is still shown, each with what it counts",
    countKeys.every(k => statsLines.some(l => l.indexOf("- " + k + ": 0 (") === 0)),
    countKeys.filter(k => !statsLines.some(l => l.indexOf("- " + k + ": 0 (") === 0)).join(","));
  check("14. the zeros most easily misread say what they do not count",
    statsLines.some(l => /^- blogItems: 0 \(.*not articles on the user's own website\)$/.test(l)) &&
    statsLines.some(l => /^- subscribers: 0 \(.*not the user's customer, email or SMS list elsewhere\)$/.test(l)) &&
    statsLines.some(l => /^- socialDrafts: 0 \(.*not posts on the user's own social channels\)$/.test(l)) &&
    statsLines.some(l => /^- contentItems: 0 \(.*not content the user has published elsewhere\)$/.test(l)));
  check("14. the trailing rule, which names the stats as a source, says the same of them",
    /- LIVE PLATFORM STATS counts only activity inside BizForce, not the business\. A zero there is never a baseline or a projection input, and an unknown rate is not 0%\./.test(rule) &&
    zeroPrompt.indexOf(statsBlock) < zeroPrompt.indexOf(rule));

  console.log("\n══ 15. no invented people or product facts ══");
  check("15. no words presented as a customer's, not even as an example or sample, nothing about what customers do; the marked slot instead",
    /- Do not write words presented as a customer's, not even as an example or a labelled sample, and do not say what customers do, notice or how many there are\. Where copy needs a testimonial, write \[TESTIMONIAL NEEDED: what to ask a real customer for\]\./.test(rule));
  check("15. no product or company fact the profile does not hold; say what the owner must supply",
    /- Do not state a product or company fact the profile does not hold\./.test(rule) && /say what the owner must supply\./.test(rule));
  /* The inferences clean-3 made, named one by one: the request naming a product
     ("your highest-volume products", four agents), what is new ("Black
     Launch"), packaging and checkout ("discreet packaging"), and a price or
     format the profile does not give. */
  check("15. the inferences are named: the request naming a product is no evidence; best-seller, new or launching, packaging, shipping, checkout, price, size, format",
    /The user naming a product says nothing about it: do not say which product sells most or best, what is new or launching, how anything is packaged, shipped or paid for, or a price, size, strength, format, ingredient, process or company age it does not give;/.test(rule));
  check("15. BANNED TOPICS bind every word: not in a customer's mouth, an example or a draft",
    /- BANNED TOPICS bind every word you write: do not put one in a customer's mouth, an example or a draft\./.test(rule));
  check("15. the heading names people and product facts, and the rule is still the last block",
    /^NO INVENTED NUMBERS, OFFERS, PEOPLE OR PRODUCT FACTS\./.test(rule) && withMemory.endsWith(rule));

  console.log("\n══ 16. the reasoning stays out of the reply ══");
  const reasoningDirective = brain.BRAIN_DIRECTIVES.split("\n\n")[0];
  console.log("    " + reasoningDirective.slice(0, 110) + "…");
  check("16. code: the model call has no private reasoning channel (no thinking parameter), so the wording is what decides",
    !/thinking\s*:/.test(def("callAnthropicText")));
  check("16. told: think it through, but the thinking is not part of the reply, which begins with the answer",
    /Before answering, think it through:/.test(reasoningDirective) && /That thinking is not part of the reply\. Begin with the answer itself/.test(reasoningDirective));
  check("16. told: never a section narrating the reasoning; the word \"internally\" is gone",
    /never write a section that narrates your reasoning, your reading of the request or these instructions\./.test(reasoningDirective) && !/internally/.test(reasoningDirective));

  console.log("\n══ 17. invented customer words are taken out in code, before anything is stored ══");
  const taskBody = def("processAiTask");
  const screenAt = taskBody.indexOf("output = testimonialScreen.text;");
  check("17. code: processAiTask replaces output with the screened text before the first result write and the memory write",
    screenAt !== -1 && taskBody.indexOf("screenFabricatedTestimonials(output") !== -1 &&
    screenAt < taskBody.indexOf("result: output") && screenAt < taskBody.indexOf("from(\"agent_memory\")"),
    JSON.stringify([screenAt, taskBody.indexOf("result: output"), taskBody.indexOf("from(\"agent_memory\")")]));
  /* The two fabrications found in clean-2, written the way an agent writes them. */
  const FABRICATED = "Lead with proof. \"I have reordered War Horse every month for three years,\" one customer told us. " +
    "Men tell us they notice the difference by the third shot. Then show the six-pack at $55.";
  const screened = await runTask("social", "end_turn", { text: FABRICATED, memory: true });
  /* Everything a user or a later prompt can read: the task row and memory. The
     removal record (section 18) is the one place the passage is kept, by design. */
  const everything = JSON.stringify(screened.updates) + JSON.stringify(screened.inserts.filter(i => i.table !== "testimonial_screen_removals"));
  console.log("    stored: " + (screened.update && screened.update.result || "").slice(0, 120) + "…");
  check("17. neither fabrication is stored anywhere: not in the result, not in the error, not in agent_memory",
    !/three years|third shot|men tell us/i.test(everything) && screened.inserts.some(i => i.table === "agent_memory"), everything.slice(0, 200));
  check("17. the result says what happened, at the top, and marks each place",
    !!screened.update && /^NOTE FROM BIZFORCE: 2 passages written as a customer's words/.test(screened.update.result) &&
    screened.update.result.split(screened.slot).length === 3 && /Then show the six-pack at \$55\./.test(screened.update.result) &&
    screened.update.status === "completed", screened.update && screened.update.result.slice(0, 120));
  check("17. the same notice is recorded in ai_tasks.error", !!screened.update && /^NOTE FROM BIZFORCE: 2 passages/.test(screened.update.error || ""), screened.update && screened.update.error);
  const SUPPLIED = "Use my customer Dave's words: \"I have reordered War Horse every month for three years\"";
  const kept = await runTask("social", "end_turn", { text: "Open with Dave's line: \"I have reordered War Horse every month for three years,\" he told us.", userPrompt: SUPPLIED });
  check("17. a quotation the user supplied in their request is kept, with no notice",
    !!kept.update && /three years/.test(kept.update.result) && !/NOTE FROM BIZFORCE/.test(kept.update.result) && kept.update.error === null, kept.update && kept.update.result);
  const PROFILE_PROMPT = "BUSINESS PROFILE:\nBrand Values: \"I make what I would give my own father\" says the founder.\n\nLIVE PLATFORM STATS:\n- tasksRun: 0";
  const fromProfile = await runTask("social", "end_turn", { text: "Close with the founder's line: \"I make what I would give my own father\" says the founder.", finalPrompt: PROFILE_PROMPT });
  check("17. a quotation from the business profile is kept",
    !!fromProfile.update && /my own father/.test(fromProfile.update.result) && !/NOTE FROM BIZFORCE/.test(fromProfile.update.result), fromProfile.update && fromProfile.update.result);
  const plain = await runTask("social", "end_turn", { text: "Ask a buyer: \"What made you reorder?\" Then lead with the six-pack. Never write lines like customers tell us they love it. Put [TESTIMONIAL NEEDED: ask a repeat buyer why they reorder] under the price. Write \"I'm proud of this formula\" on the label." });
  check("17. a question, a negated instruction, the placeholder and an unattributed first-person line are left alone",
    !!plain.update && !/NOTE FROM BIZFORCE/.test(plain.update.result) && plain.update.error === null, plain.update && plain.update.result.slice(0, 160));

  console.log("\n══ 18. what the screen removes is recorded, and nothing in the product reads it ══");
  const records = screened.inserts.filter(i => i.table === "testimonial_screen_removals").map(i => i.payload).flat();
  console.log("    recorded: " + JSON.stringify(records.map(r => [r.pattern, r.passage.slice(0, 50)])));
  check("18. each removal is recorded with its task, account, agent, pattern and the passage itself",
    records.length === 2 && records.every(r => r.task_id === "task-1" && r.user_id === SUBJECT_USER_ID && r.agent_type === "social") &&
    records.some(r => /three years/.test(r.passage) && /one customer told us/.test(r.passage) && r.pattern === "both") &&
    records.some(r => /third shot/.test(r.passage) && r.pattern === "attributed_claim"), JSON.stringify(records));
  check("18. nothing is recorded when nothing is removed", plain.inserts.filter(i => i.table === "testimonial_screen_removals").length === 0);
  const auditDown = await runTask("social", "end_turn", { text: FABRICATED, failAudit: true });
  check("18. if the record cannot be written, the task is still stored, screened, and completed",
    !!auditDown.update && auditDown.update.status === "completed" && /^NOTE FROM BIZFORCE: 2 passages/.test(auditDown.update.result) &&
    !/three years|third shot/.test(auditDown.update.result), auditDown.update && auditDown.update.status);
  const recordCalls = (taskBody.match(/await recordTestimonialRemovals\(taskId, userId, agentType, testimonialScreen\.removals\);/g) || []).length;
  check("18. code: the record is written on both paths that store a screened result, after the task row (" + recordCalls + " calls)",
    recordCalls === 2 && taskBody.indexOf("await recordTestimonialRemovals") > taskBody.indexOf("result: output"));
  /* Nothing reads it: the only reference in product code is the one insert. */
  const PRODUCT_SOURCES = [SERVER, fs.readFileSync(path.join(REPO, "leadRadar.js"), "utf8")]
    .concat(fs.readdirSync(path.join(REPO, "lib")).filter(f => f.endsWith(".js")).map(f => fs.readFileSync(path.join(REPO, "lib", f), "utf8")))
    .concat(fs.readdirSync(path.join(REPO, "config")).filter(f => f.endsWith(".js")).map(f => fs.readFileSync(path.join(REPO, "config", f), "utf8")));
  const fromUses = PRODUCT_SOURCES.map(s => s.match(/\.from\("testimonial_screen_removals"\)\s*\.\w+\(/g) || []).flat();
  check("18. code: the table's only use in server.js, lib, config and leadRadar.js is one insert",
    fromUses.length === 1 && /\.insert\($/.test(fromUses[0]), JSON.stringify(fromUses));
  check("18. code: no prompt builder can reach it — brain.js never names it", BRAIN.indexOf("testimonial_screen_removals") === -1);
  const FRONTEND_DIR = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
  if (fs.existsSync(FRONTEND_DIR)) {
    const pages = [];
    (function walk(dir) { fs.readdirSync(dir, { withFileTypes: true }).forEach(e => {
      if (e.name === "node_modules" || e.name.startsWith(".")) return;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p); else if (/\.(html|js)$/.test(e.name)) pages.push(p);
    }); })(FRONTEND_DIR);
    const naming = pages.filter(p => fs.readFileSync(p, "utf8").indexOf("testimonial_screen_removals") !== -1);
    check("18. no frontend page names it (" + pages.length + " files)", naming.length === 0, naming.join(","));
  } else {
    console.log("    (frontend checkout not found at " + FRONTEND_DIR + "; the page check is skipped)");
  }
  const MIGRATION = fs.readFileSync(path.join(REPO, "supabase", "migrations", "124_testimonial_screen_removals.sql"), "utf8");
  const migrationSql = MIGRATION.split("\n").filter(l => !/^\s*--/.test(l)).join("\n");
  check("18. migration 124: RLS on, no policy, anon and authenticated revoked, gone with the task or the account",
    /alter table public\.testimonial_screen_removals enable row level security;/.test(migrationSql) &&
    !/create policy/i.test(migrationSql) &&
    /revoke all on public\.testimonial_screen_removals from anon, authenticated;/.test(migrationSql) &&
    /task_id\s+uuid\s+not null references public\.ai_tasks\(id\) on delete cascade/.test(migrationSql) &&
    /user_id\s+uuid\s+not null references public\.users\(id\) on delete cascade/.test(migrationSql));

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
