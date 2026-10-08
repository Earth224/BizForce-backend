/* ═══════════════════════════════════════════════════════════════════════════
   checkSpecialistNotes.js — a typed task reads a bounded excerpt of its own
   past, and a bounded, filtered excerpt of the other agents'.

   THE GAPS. (1) Each typed task was given its agent's five newest tasks with
   the RESULT IN FULL: one executive result was 58,342 characters, five were
   241,114. (2) Each agent read only its own memory, so the homepage's "what
   the SEO agent learns, the content agent already knows" was untrue.

   WHAT THIS PROVES, reading the live database and writing nothing:
     1. A prior task's result is cut at 2,000 characters and its prompt at 500,
        at a line, sentence or word break, and the cut says so — on the five
        longest real results in ai_tasks.
     2. Against EVERY memory row the owner has, for every agent type, the notes
        an agent would see contain no Oracle row and no sales lead note — and
        the owner does have both, so the proof is not vacuous.
     3. On a fixture built to break it: one note per other agent, at most
        three, never the reader's own, titles cut to 80 and content to 500.
     4. The block sits after ACCUMULATED MEMORY and before NO_INVENTION_RULE,
        with its header; with no notes, every prompt is byte-identical to
        BASELINE's, so the 30-odd other callers are unchanged.
     5. Only handleAiTaskRequest reads the notes, and it hands them to the
        prompt; a failed read gives none and the task goes on.

   MUTATIONS — each must turn the named section red:
     MUTATE=nocap      prior results go in whole again                 → 1
     MUTATE=silentcut  a cut is not marked                             → 1
     MUTATE=midword    the cut ignores breaks                          → 1
     MUTATE=oracle     the Oracle is not excluded                      → 3
     MUTATE=leadnotes  sales lead notes are not excluded               → 3
     MUTATE=peragent   several notes from one agent                    → 3
     MUTATE=limit      more than three agents                          → 3
     MUTATE=self       the reader's own memory counted as another's    → 3
     MUTATE=notrunc    note content not cut                            → 3
     MUTATE=unwired    the notes never reach the prompt                → 5
   ═══════════════════════════════════════════════════════════════════════════ */
"use strict";
require("dotenv").config();
const fs = require("fs");
const vm = require("vm");
const path = require("path");
const Module = require("module");
const { execSync } = require("child_process");
const REPO = path.join(__dirname, "..");
const { createResidueGuard, resolveSubjectAccount } = require("./checkRunResidue");
const SUBJECT_USER_ID = resolveSubjectAccount();
const OWNER = require(path.join(REPO, "lib", "ownerAccount")).OWNER_ACCOUNT_ID;
const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY);
/* Reads only; the guard is built so a future edit that adds a write has
   somewhere to record it, and its read-back runs regardless. */
const residue = createResidueGuard({ supabase: supabase, name: "specialistNotes", subject: SUBJECT_USER_ID, tables: [] });
residue.install();

const BASELINE = "1c7c5dd";
/* THE ONE ROSTER LINE THAT HAS CHANGED SINCE BASELINE. The assembled prompt
   carries the agent roster, and the Etsy agent's description was corrected
   after BASELINE: it promised competitor shop analysis, which nothing here can
   do. Section 4 swaps exactly this description in BASELINE's prompt and still
   demands every other byte be identical — and that the old line was there to
   swap, so the exception cannot pass vacuously. */
const ETSY_ROSTER_BEFORE = "Etsy listing optimization, keyword research, pricing strategy, and competitor shop analysis.";
const ETSY_ROSTER_NOW = "Etsy listing copy, tag-length keyword candidates, and pricing arithmetic on figures the seller supplies. Reads no marketplace.";
const MUTATIONS = ["nocap", "silentcut", "midword", "oracle", "leadnotes", "peragent", "limit", "self", "notrunc", "unwired"];
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
if (MUTATE === "nocap") SERVER = mutate(SERVER, "\"Prompt: \" + excerptWithMarker(task.prompt, PRIOR_TASK_PROMPT_CAP) + \" | Result: \" + excerptWithMarker(task.result, PRIOR_TASK_RESULT_CAP)",
  "\"Prompt: \" + task.prompt + \" | Result: \" + task.result", "nocap");
if (MUTATE === "silentcut") SERVER = mutate(SERVER, "  return cut + \" [cut: the first \" + cut.length + \" of \" + text.length + \" characters; the rest is not included]\";", "  return cut;", "silentcut");
if (MUTATE === "midword") SERVER = mutate(SERVER, "  if (lastBreak > maxLength * 0.6) cut = cut.slice(0, lastBreak);", "", "midword");
if (MUTATE === "oracle") SERVER = mutate(SERVER, "var SPECIALIST_NOTE_EXCLUDED_AGENTS = [\"oracle\"];", "var SPECIALIST_NOTE_EXCLUDED_AGENTS = [];", "oracle");
if (MUTATE === "leadnotes") SERVER = mutate(SERVER, "var SPECIALIST_NOTE_EXCLUDED_KEYS = [\"sales_convert_\", \"sales_lead_status_\"];", "var SPECIALIST_NOTE_EXCLUDED_KEYS = [];", "leadnotes");
if (MUTATE === "peragent") SERVER = mutate(SERVER, "    if (!type || type === agentType || seen[type]) continue;", "    if (!type || type === agentType) continue;", "peragent");
if (MUTATE === "limit") SERVER = mutate(SERVER, "var SPECIALIST_NOTE_AGENTS = 3;", "var SPECIALIST_NOTE_AGENTS = 99;", "limit");
if (MUTATE === "self") SERVER = mutate(SERVER, "    if (!type || type === agentType || seen[type]) continue;", "    if (!type || seen[type]) continue;", "self");
if (MUTATE === "notrunc") SERVER = mutate(SERVER, "var SPECIALIST_NOTE_CAP = 500;", "var SPECIALIST_NOTE_CAP = 50000;", "notrunc");
if (MUTATE === "unwired") SERVER = mutate(SERVER, "buildAgentSystemPrompt(agentBrain, businessProfile, liveStats, combinedMemoriesForBrain, specialistNotes);",
  "buildAgentSystemPrompt(agentBrain, businessProfile, liveStats, combinedMemoriesForBrain);", "unwired");
if (MUTATE) console.log("\n!! MUTATION: " + MUTATE);

const SHARED = require.resolve("./_shared");
function defs(src, names) {
  delete require.cache[SHARED];
  const { definitionOf } = require(SHARED);
  return names.map(n => { const d = definitionOf(src, n); if (!d) throw new Error("EXTRACTION FAILED: " + n); return d; }).join("\n\n");
}
const api = (function () {
  const c = { console: { log() {}, warn() {}, error() {} } };
  vm.runInNewContext(defs(SERVER, ["PRIOR_TASK_RESULT_CAP", "PRIOR_TASK_PROMPT_CAP", "SPECIALIST_NOTE_CAP", "SPECIALIST_NOTE_TITLE_CAP", "SPECIALIST_NOTE_AGENTS",
    "SPECIALIST_NOTE_SCAN", "SPECIALIST_NOTE_EXCLUDED_AGENTS", "SPECIALIST_NOTE_EXCLUDED_KEYS", "truncateOrchestratorPreview", "excerptWithMarker", "pickSpecialistNotes"]) +
    "\nthis.api = { excerptWithMarker, pickSpecialistNotes, SCAN: SPECIALIST_NOTE_SCAN };", c);
  return c.api;
})();
function loadBrain(src, name) { const m = new Module(name, null); m.filename = path.join(REPO, "config", name); m.paths = Module._nodeModulePaths(path.join(REPO, "config")); m._compile(src, m.filename); return m.exports; }
const brainNow = require(path.join(REPO, "config", "brain.js"));
const brain0 = loadBrain(execSync("git show " + BASELINE + ":config/brain.js", { cwd: REPO }).toString("utf8"), "brain.baseline.js");

async function pages(table, cols, filter) {
  let rows = [], from = 0;
  for (;;) { let q = supabase.from(table).select(cols).order("created_at", { ascending: false }).range(from, from + 999); if (filter) q = filter(q);
    const r = await q; if (r.error) throw r.error; rows = rows.concat(r.data); if (r.data.length < 1000) break; from += 1000; }
  return rows;
}

(async function main() {
  await residue.sweepPrevious(SUBJECT_USER_ID);

  console.log("\n══ 1. prior tasks, capped and marked ══");
  const mapping = /var memoriesForBrain = \(memoryResult\.data \|\| \[\]\)\.map\(function \(task\) \{[\s\S]*?\}\);/.exec(SERVER);
  check("1. code: handleAiTaskRequest cuts each prior prompt at PRIOR_TASK_PROMPT_CAP and each result at PRIOR_TASK_RESULT_CAP",
    !!mapping && /excerptWithMarker\(task\.prompt, PRIOR_TASK_PROMPT_CAP\)/.test(mapping[0]) && /excerptWithMarker\(task\.result, PRIOR_TASK_RESULT_CAP\)/.test(mapping[0]));
  const tasks = await pages("ai_tasks", "id, agent_type, result, created_at", q => q.not("result", "is", null));
  const longest = tasks.slice().sort((a, b) => b.result.length - a.result.length).slice(0, 5);
  const before = longest.reduce((s, t) => s + t.result.length, 0);
  const cuts = longest.map(t => ({ full: t.result.trim(), ex: api.excerptWithMarker(t.result, 2000) }));
  const after = cuts.reduce((s, c) => s + c.ex.length, 0);
  console.log("    five longest results: " + before + " characters in full → " + after + " as excerpts (" + longest.map(t => t.agent_type + " " + t.result.length).join(", ") + ")");
  const marked = cuts.every(c => /\[cut: the first \d+ of \d+ characters; the rest is not included\]$/.test(c.ex));
  const bounded = cuts.every(c => c.ex.length <= 2000 + 90);
  const atBreak = cuts.every(c => { const body = c.ex.replace(/ \[cut: [^\]]*\]$/, ""); const next = c.full.charAt(body.length); return /\s|\./.test(next) || /[.\n]$/.test(body); });
  check("1. each is at most 2,000 characters plus its marker", bounded, JSON.stringify(cuts.map(c => c.ex.length)));
  check("1. each ends by saying it was cut, and how much of how much is shown", marked);
  check("1. each is cut at a line, sentence or word break, never inside a word", atBreak);
  check("1. a short text is left exactly as it was", api.excerptWithMarker("A short result.", 2000) === "A short result.");

  console.log("\n══ 2. the exclusions, against every memory row the owner has ══");
  const owner = await pages("agent_memory", "agent_type, memory_key, memory_type, title, content, created_at", q => q.eq("user_id", OWNER));
  const isLead = r => /^sales_(convert|lead_status)_/.test(String(r.memory_key || ""));
  console.log("    owner rows: " + owner.length + " — oracle " + owner.filter(r => r.agent_type === "oracle").length + ", sales lead notes " + owner.filter(isLead).length);
  check("2. the owner has Oracle rows and sales lead notes, so this is not vacuous", owner.some(r => r.agent_type === "oracle") && owner.some(isLead));
  const AGENTS = ["executive", "sales", "seo", "content", "email", "social", "operations", "analytics", "ads", "reputation", "community", "influencer",
    "etsy", "store", "broker", "publicist", "rd", "vertical_marketing", "general", "oracle"];
  const leaks = [];
  let shown = 0;
  AGENTS.forEach(t => {
    // As the read returns them: not the reader's own type, newest first, the newest SCAN.
    const windowed = api.pickSpecialistNotes(owner.filter(r => r.agent_type !== t).slice(0, api.SCAN), t);
    // And with no window at all, every row the owner has.
    const unbounded = api.pickSpecialistNotes(owner, t);
    [windowed, unbounded].forEach(notes => notes.forEach(n => {
      shown++;
      const src = owner.find(r => r.agent_type === n.agent_type && String(r.created_at).slice(0, 10) === n.created_on && (r.content || "").trim().indexOf(n.content.replace(/ \[cut: [^\]]*\]$/, "")) === 0);
      if (n.agent_type === "oracle" || (src && isLead(src)) || n.agent_type === t) leaks.push(t + " ← " + n.agent_type);
    }));
  });
  console.log("    notes shown across " + AGENTS.length + " reading agents, windowed and unbounded: " + shown);
  check("2. no reading agent is ever shown an Oracle row, a sales lead note or its own memory", leaks.length === 0, leaks.join(", "));
  const forContent = api.pickSpecialistNotes(owner.filter(r => r.agent_type !== "content").slice(0, api.SCAN), "content");
  console.log("    the owner's content agent would see: " + JSON.stringify(forContent.map(n => n.agent_type + " " + n.created_on + " — " + n.title.slice(0, 50))));

  console.log("\n══ 3. the selection, on rows built to break it ══");
  const iso = d => "2026-10-0" + d + "T12:00:00Z";
  const long = "x".repeat(3000);
  const fixture = [
    { agent_type: "oracle", memory_key: "oracle_message_1", title: "Prompt: my life", content: "personal", created_at: iso(9) },
    { agent_type: "sales", memory_key: "sales_convert_abc", title: "Converted lead: @stranger", content: "a stranger's post", created_at: iso(9) },
    { agent_type: "sales", memory_key: "sales_lead_status_at://x_1", title: "Lead status", content: "Lead marked as contacted", created_at: iso(9) },
    { agent_type: "content", memory_key: "content_ai_task_1", title: "own", content: "the reader's own memory", created_at: iso(9) },
    { agent_type: "sales", memory_key: "sales_ai_task_1", title: "Prompt: " + "t".repeat(200), content: long, created_at: iso(8) },
    { agent_type: "sales", memory_key: "sales_ai_task_2", title: "older sales", content: "older", created_at: iso(7) },
    { agent_type: "seo", memory_key: null, title: "seo note", content: "seo content", created_at: iso(6) },
    { agent_type: "email", memory_key: "email_ai_task_1", title: "email note", content: "email content", created_at: iso(5) },
    { agent_type: "social", memory_key: "social_ai_task_1", title: "social note", content: "social content", created_at: iso(4) }
  ];
  const picked = api.pickSpecialistNotes(fixture, "content");
  console.log("    picked: " + JSON.stringify(picked.map(n => n.agent_type + " " + n.created_on + " (" + n.title.length + "/" + n.content.length + ")")));
  check("3. exactly three notes, one each from the newest other agents: sales, seo, email", JSON.stringify(picked.map(n => n.agent_type)) === JSON.stringify(["sales", "seo", "email"]));
  check("3. no Oracle row, no lead note, not the reader's own", !picked.some(n => n.agent_type === "oracle" || n.agent_type === "content" || /stranger|marked as/.test(n.content)));
  check("3. the sales note is its newest non-lead memory, its title cut to 80 (with ...) and its content to 500 (with the cut marker)",
    picked[0] && picked[0].content.indexOf("x".repeat(400)) === 0 && picked[0].content.length <= 500 + 90 && /\[cut: /.test(picked[0].content) &&
    picked[0].title.length === 83 && /\.\.\.$/.test(picked[0].title), picked[0] && (picked[0].title.length + "/" + picked[0].content.length));
  check("3. a row with no memory_key still counts (it is not a lead note)", picked.some(n => n.agent_type === "seo"));

  console.log("\n══ 4. the block, and every other prompt unchanged ══");
  const profile = { business_name: "Fixture Co", industry: "Retail" };
  const memories = [{ agent_type: "content", title: "Prior task", content: "x" }];
  const withNotes = brainNow.buildAgentSystemPrompt("AGENT", profile, {}, memories, picked);
  const iMem = withNotes.indexOf("ACCUMULATED MEMORY"), iNotes = withNotes.indexOf(brainNow.SPECIALIST_NOTES_HEADER), iRule = withNotes.indexOf("NO_INVENTION") >= 0 ? -1 : withNotes.lastIndexOf("\n\n");
  check("4. with notes: the header, then one line per note, after ACCUMULATED MEMORY and before the closing rule",
    iNotes > iMem && iMem > 0 && withNotes.indexOf("- From the sales agent (2026-10-08) — ") > iNotes && withNotes.indexOf("- From the SEO agent (2026-10-06) — seo note: seo content") > iNotes &&
    withNotes.slice(iNotes).indexOf("\n\n") > 0 && withNotes.endsWith(brain0.buildAgentSystemPrompt("A", {}, {}, []).split("\n\n").slice(-1)[0]));
  function baselinePrompt(a) {
    const p = brain0.buildAgentSystemPrompt("AGENT", a[0], a[1], a[2]);
    return p.split(ETSY_ROSTER_BEFORE).length === 2 ? p.replace(ETSY_ROSTER_BEFORE, ETSY_ROSTER_NOW) : null;
  }
  const same = [[{}, {}, []], [profile, {}, memories], [profile, { tasksRun: 3 }, []]].every(a => baselinePrompt(a) !== null &&
    brainNow.buildAgentSystemPrompt("AGENT", a[0], a[1], a[2]) === baselinePrompt(a) &&
    brainNow.buildAgentSystemPrompt("AGENT", a[0], a[1], a[2], []) === baselinePrompt(a));
  check("4. with no notes (absent or empty), every prompt is byte-identical to " + BASELINE + " but for the corrected Etsy roster line", same);

  console.log("\n══ 5. only the typed-task path reads them ══");
  const handler = defs(SERVER, ["handleAiTaskRequest"]);
  const callers = (SERVER.match(/fetchSpecialistNotes\(/g) || []).length;
  check("5. fetchSpecialistNotes is called once, in handleAiTaskRequest, and its notes reach the prompt",
    callers === 2 && /var specialistNotes = await fetchSpecialistNotes\(userId, agentType\);/.test(handler) &&
    /buildAgentSystemPrompt\(agentBrain, businessProfile, liveStats, combinedMemoriesForBrain, specialistNotes\)/.test(handler), callers + " occurrences");
  const fetchSrc = defs(SERVER, ["fetchSpecialistNotes"]);
  check("5. a failed read gives no notes, never a failed task", /if \(read\.error\) \{[\s\S]*?return \[\];/.test(fetchSrc) && /catch \(notesErr\) \{[\s\S]*?return \[\];/.test(fetchSrc));

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
