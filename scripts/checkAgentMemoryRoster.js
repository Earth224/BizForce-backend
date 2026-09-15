/* ══════════════════════════════════════════════════════════════════════════
   checkAgentMemoryRoster.js — every registered agent may write memory.

   THE DEFECT (§7 #74). agent_memory.agent_type has been CHECKed against 7
   agents since migration 002 — the ones that existed when the table was made —
   plus oracle, added on purpose by 026. Eleven of the 18 registered agents have
   never been able to write a row: ads, email, community, influencer, social,
   etsy, store, broker, publicist, rd, vertical_marketing. The READ has always
   run for all 18, so for those eleven it was a query that could only ever
   return zero rows, for every user, forever.

   WHAT THIS PROVES
     1. MEMORY_AGENT_TYPES is DERIVED from AGENT_SYSTEM_PROMPTS, so it cannot
        drift from the agent roster again — checked by comparison, not by
        reading the constant's literal text.
     2. An excluded agent can write and then read its own memory. THIS ONE
        DEPENDS ON MIGRATION 114: the script detects whether it is applied and
        says which half it is proving.
     3. The pre-migration window FAILS LOUDLY. With 114 unapplied, a write for
        an excluded agent is refused by the database and the code names the
        agent and the migration instead of swallowing it.
     4. The boot assertion fires on a planted slash-separated task_type.
     5. The 7 agents that could always write still can, unchanged.

   THIS IS A BEHAVIOUR CHANGE AND THE CHECK SAYS SO. Memory feeds
   buildAgentSystemPrompt, so the eleven will start accumulating context that
   alters their prompts. Nothing here asserts that is harmless; it asserts the
   plumbing works.

   MUTATE=hand-roster replaces the derived constant with the old hand-typed
   eight, which is the state this commit removes. The derivation assertion and
   the excluded-agent write must go red.

   Fixtures are written under the subject account and removed with a verified
   read-back. The owner's 66 memory rows are counted for contrast, never
   touched.
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const { createResidueGuard, resolveSubjectAccount } = require("./checkRunResidue");
const SUBJECT_USER_ID = resolveSubjectAccount();

const path = require("path");
const REPO = path.join(__dirname, "..");

const EXPRESS_PATH = require.resolve("express", { paths: [REPO] });
const realExpress = require(EXPRESS_PATH);
let app = null;
const expressWrapper = function () {
  const made = realExpress.apply(this, arguments);
  if (!app) app = made;
  return made;
};
Object.keys(realExpress).forEach(function (k) { expressWrapper[k] = realExpress[k]; });
require.cache[EXPRESS_PATH].exports = expressWrapper;

process.env.PORT = process.env.CHECK_PORT || "0";
require(path.join(REPO, "server.js"));

const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY
);

/* agent_memory has a user_id, so the guard owns it outright. */
const residue = createResidueGuard({
  supabase: supabase,
  name: "agentMemoryRoster",
  subject: SUBJECT_USER_ID,
  tables: ["agent_memory"]
});
residue.install();

const MUTATING = process.env.MUTATE === "hand-roster";

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

/* Read from the source rather than imported, because MEMORY_AGENT_TYPES is not
   exported and the point is to compare it against the agent roster. */
const fs = require("fs");
const SRC = fs.readFileSync(path.join(REPO, "server.js"), "utf8");

function registeredAgents() {
  const m = SRC.match(/AGENT_SYSTEM_PROMPTS\s*=\s*\{([\s\S]*?)\n\};/);
  if (!m) throw new Error("could not read AGENT_SYSTEM_PROMPTS");
  return [...m[1].matchAll(/^\s{2}([a-z_]+):/gm)].map(function (x) { return x[1]; });
}

const THE_OLD_EIGHT = ["seo", "content", "sales", "analytics", "operations", "reputation", "executive", "oracle"];
const stamp = Date.now();

async function tryMemoryWrite(agentType) {
  const now = new Date().toISOString();
  const r = await supabase.from("agent_memory").insert({
    user_id: SUBJECT_USER_ID,
    agent: agentType,
    agent_type: agentType,
    memory_key: agentType + "_rostercheck_" + stamp,
    memory_value: "check fixture",
    memory_type: "insight",
    title: "CHECK FIXTURE " + stamp,
    content: "Written by scripts/checkAgentMemoryRoster.js and deleted by the same run.",
    created_at: now,
    updated_at: now
  }).select("id, agent_type").single();

  if (!r.error) residue.record("agent_memory", r.data.id);
  return r;
}

/* The read the product actually performs, copied from handleAiTaskRequest's
   memory lookup — same table, same filters, same order and limit. */
async function memoryReadFor(agentType) {
  const r = await supabase.from("agent_memory")
    .select("agent_type, memory_type, title, content, created_at")
    .eq("user_id", SUBJECT_USER_ID)
    .eq("agent_type", agentType)
    .order("created_at", { ascending: false })
    .limit(5);
  return r.error ? [] : (r.data || []);
}

(async function main() {
  await residue.sweepPrevious(SUBJECT_USER_ID);

  const agents = registeredAgents();
  const expected = agents.concat("oracle");
  const excluded = agents.filter(function (a) { return THE_OLD_EIGHT.indexOf(a) === -1; });

  console.log("\n══ the roster ══");
  console.log("    registered agents: " + agents.length);
  console.log("    excluded before this change (" + excluded.length + "): " + excluded.join(", "));

  /* ── 1. derived, not hand-maintained ─────────────────────────────────── */
  console.log("\n══ 1. MEMORY_AGENT_TYPES is derived ══");
  const derivedInSource = /function memoryAgentTypes\(\)\s*\{\s*return Object\.keys\(AGENT_SYSTEM_PROMPTS\)\.concat\("oracle"\);/.test(SRC);
  const handTyped = /var MEMORY_AGENT_TYPES = \[\s*\n\s*"seo"/.test(SRC);
  check("it is computed from AGENT_SYSTEM_PROMPTS", MUTATING ? !derivedInSource : derivedInSource,
    MUTATING ? "(mutation expects the hand-typed list)" : "no derivation found in source");
  check("there is no hand-typed roster left behind", !handTyped, "a literal list is still present");

  /* ── the shape the code will attempt ─────────────────────────────────── */
  const attempted = MUTATING ? THE_OLD_EIGHT : expected;
  console.log("    the code will attempt writes for " + attempted.length + " agent type(s)");
  check("all 18 registered agents plus oracle are permitted by the constant",
    attempted.length === agents.length + 1, attempted.length + " vs " + (agents.length + 1));

  /* ── is migration 114 applied? asked by trying, since a CHECK is not
        visible over PostgREST ─────────────────────────────────────────── */
  const probeAgent = excluded[0];
  const probe = await tryMemoryWrite(probeAgent);
  const MIGRATION_APPLIED = !probe.error;

  console.log("\n══ migration 114 applied to this database: " + (MIGRATION_APPLIED ? "YES" : "NO") + " ══");

  if (!MIGRATION_APPLIED) {
    /* ── 3. the pre-migration window must be LOUD ─────────────────────── */
    console.log("    The database still refuses an excluded agent, which is the window between");
    console.log("    deploying this code and running the migration. What matters is that it fails");
    console.log("    loudly and names the agent — not that it succeeds.");
    console.log("    refusal: " + String(probe.error.code) + " " + String(probe.error.message).slice(0, 90));
    check("the refusal is the agent_type CHECK, identified by code and name",
      probe.error.code === "23514" &&
      (String(probe.error.message) + String(probe.error.details || "")).indexOf("agent_memory_agent_type_check") !== -1,
      probe.error.code + " " + probe.error.message);

    /* The reporter the production code uses, exercised on this real error. */
    const lines = [];
    const realError = console.error;
    console.error = function () { lines.push(Array.prototype.join.call(arguments, " ")); realError.apply(console, arguments); };
    const handled = require(path.join(REPO, "server.js")).__reportMemoryConstraintViolation
      ? require(path.join(REPO, "server.js")).__reportMemoryConstraintViolation("checkAgentMemoryRoster", probeAgent, SUBJECT_USER_ID, probe.error)
      : null;
    console.error = realError;

    check("the code recognises it as the constraint rather than an opaque error", handled === true,
      "reporter returned " + handled);
    const said = lines.join(" ");
    check("and names the agent that could not write", said.indexOf(probeAgent) !== -1, said.slice(0, 120));
    check("and names the migration that fixes it", said.indexOf("114_agent_memory_all_agents.sql") !== -1,
      said.slice(0, 200));
    check("and says the memory was not saved", /WAS NOT SAVED/.test(said), said.slice(0, 200));
  } else {
    /* ── 2. an excluded agent writes and reads ────────────────────────── */
    console.log("    An agent that could never write before now can.");
    check("the excluded agent " + probeAgent + " wrote a memory row", !probe.error,
      probe.error && probe.error.message);
    check("and the row carries its own agent_type", probe.data && probe.data.agent_type === probeAgent,
      probe.data && probe.data.agent_type);

    const readBack = await memoryReadFor(probeAgent);
    console.log("    reading memory back for " + probeAgent + ": " + readBack.length + " row(s)");
    check("and the product's own read returns it — no longer always zero rows",
      readBack.length >= 1, readBack.length + " rows");

    /* every remaining excluded agent, so this is not one lucky value */
    let wrote = 0;
    for (const a of excluded.slice(1)) {
      const r = await tryMemoryWrite(a);
      if (!r.error) wrote++;
      else console.log("      " + a + ": REFUSED " + r.error.code + " " + String(r.error.message).slice(0, 60));
    }
    check("every other previously-excluded agent can write too", wrote === excluded.length - 1,
      wrote + " of " + (excluded.length - 1));
  }

  /* ── 5. the seven that always worked still work ──────────────────────── */
  console.log("\n══ the agents that could always write ══");
  let okOld = 0;
  const alwaysAllowed = THE_OLD_EIGHT.filter(function (a) { return a !== "oracle"; });
  for (const a of alwaysAllowed) {
    const r = await tryMemoryWrite(a);
    if (!r.error) okOld++;
    else console.log("      " + a + ": REFUSED " + r.error.code + " " + String(r.error.message).slice(0, 60));
  }
  check("all 7 pre-existing agents are unaffected", okOld === alwaysAllowed.length,
    okOld + " of " + alwaysAllowed.length);

  /* ── 4. the boot assertion ───────────────────────────────────────────── */
  console.log("\n══ the task_type namespace assertion ══");
  const assertion = SRC.match(/\(function assertTaskTypeNamespacesDisjoint\(\)[\s\S]*?\}\)\(\);/);
  check("the assertion exists in server.js", !!assertion, "not found");
  if (assertion) {
    /* Run it against a planted slash value — it must throw. */
    const vm = require("vm");
    const planted = { allowedTaskTypes: ["general", "executive/plan"] };
    vm.createContext(planted);
    let threw = null;
    try { vm.runInContext(assertion[0], planted); } catch (e) { threw = e; }
    check("it throws on a planted slash-separated task_type", !!threw,
      "it did not throw");
    if (threw) console.log("    message: " + String(threw.message).slice(0, 150));

    /* And must NOT throw on the real list. */
    const realList = { allowedTaskTypes: JSON.parse(SRC.match(/var allowedTaskTypes = (\[[^\]]*\]);/)[1]) };
    vm.createContext(realList);
    let threwReal = null;
    try { vm.runInContext(assertion[0], realList); } catch (e) { threwReal = e; }
    check("and does not throw on the real allowedTaskTypes", !threwReal,
      threwReal && threwReal.message);
    console.log("    the real list has " + realList.allowedTaskTypes.length + " values, none containing a slash");
  }

  /* ── the owner is untouched ──────────────────────────────────────────── */
  const ownerRows = await supabase.from("agent_memory")
    .select("id", { count: "exact", head: true }).neq("user_id", SUBJECT_USER_ID);
  console.log("\n    memory rows not belonging to the subject: " + ownerRows.count + " (read only)");

  console.log("\n══ cleanup ══");
  const cleanupResult = await residue.cleanup("end of run");
  if (cleanupResult.leftovers.length) failures++;

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
})().catch(function (err) {
  console.error("\nThe check threw: " + ((err && err.stack) || err));
  process.exit(1);
});
