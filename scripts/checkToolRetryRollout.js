/* ══════════════════════════════════════════════════════════════════════════
   checkToolRetryRollout.js — the one-retry helper across routes with
   DIFFERENT label sets, proved against the live database.

   social/calendar was the pilot (scripts/checkSocialCalendarRetry.js). This
   checks the rollout: that the shared helper works for routes whose parsers
   look for entirely different things, and — the point of the exercise — that
   each route's correction names ITS OWN labels. A correction telling the model
   to emit DAY and PLATFORM to a parser looking for H2 and COVERS would spend a
   second call teaching it to produce something unreadable.

   THREE ROUTES, THREE SHAPES:

     content/outline     blocks separated by ---, labels H1/SEARCH_INTENT/
                         QUESTIONS_TO_ANSWER then H2/COVERS/WHY_HERE
     rd/brief            one document in labelled sections (RD_BRIEF_SECTIONS)
     email/subject-lines one item per line, "subject | angle", no labels at all

   For each: the first-fails-retry-succeeds path and the both-fail path, read
   back from ai_tasks and model_calls.

   Same method as the other two check scripts: the real server.js is booted in
   this process and the real route handler invoked, so the real parse, the real
   retry decision and the real database writes all run. Only the Anthropic SDK
   is stubbed, from a queue — one reply per call — which is what makes "exactly
   one retry, never two" checkable. Every row caused is deleted and the removal
   verified by reading the tables back.

   Usage:  node scripts/checkToolRetryRollout.js
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const path = require("path");
const REPO = path.join(__dirname, "..");

const SDK_PATH = require.resolve("@anthropic-ai/sdk", { paths: [REPO] });
const RealAnthropic = require(SDK_PATH);

let replyQueue = [];
let callLog = [];

function FakeAnthropic(options) {
  const instance = new RealAnthropic(options);
  instance.messages = {
    create: async function (args) {
      const promptText = (((args || {}).messages || [])[0] || {}).content;
      callLog.push(Array.isArray(promptText)
        ? promptText.map(function (b) { return b.text || ""; }).join("")
        : String(promptText || ""));
      const reply = replyQueue.length ? replyQueue.shift() : "__UNEXPECTED_EXTRA_CALL__";
      return {
        id: "msg_check_" + callLog.length,
        model: (args && args.model) || "stubbed",
        content: [{ type: "text", text: reply }],
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

let failures = 0;
/* EVERY ROW THIS RUN CAUSES, RECORDED AS IT HAPPENS AND REMOVED ON EVERY WAY
   OUT — the end of the run, a throw, an unhandled rejection, a Ctrl-C. Twice
   a crash mid-run left rows behind because cleanup only ran on the happy
   path; scripts/checkRunResidue.js is where that is fixed, once, for all
   three scripts. */
const { createResidueGuard } = require("./checkRunResidue");
const residue = createResidueGuard({
  supabase: supabase,
  name: "toolRetryRollout",
  tables: ["ai_tasks", "model_calls"]
});
residue.install();

const created = residue.ids;
let ledgerMark = 0;

function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

async function noteLedgerRows(userId) {
  const { data, error } = await supabase
    .from("model_calls").select("id, route").eq("user_id", userId).gt("id", ledgerMark)
    .order("id", { ascending: true });
  if (error) { console.error("    (model_calls read failed: " + error.message + ")"); return []; }
  (data || []).forEach(function (row) {
    residue.record("model_calls", row.id);
    if (row.id > ledgerMark) { ledgerMark = row.id; residue.setLedgerMark(ledgerMark); }
  });
  return data || [];
}

function handlerFor(routePath) {
  const layer = app._router.stack.filter(function (l) {
    return l.route && l.route.path === routePath && l.route.methods.post;
  })[0];
  if (!layer) throw new Error("route not mounted: " + routePath);
  return layer.route.stack[layer.route.stack.length - 1].handle;
}

function callRoute(routePath, userId, body) {
  const handler = handlerFor(routePath);
  return new Promise(function (resolve) {
    let settled = false;
    const done = function (r) { if (!settled) { settled = true; resolve(r); } };
    const res = {
      statusCode: 200,
      status: function (code) { this.statusCode = code; return this; },
      json: function (payload) { done({ status: this.statusCode, body: payload }); return this; }
    };
    Promise.resolve()
      .then(function () { return handler({ user: { id: userId }, body: body }, res, function (err) { done({ status: 500, body: { error: (err && err.message) || String(err) } }); }); })
      .catch(function (err) { done({ status: 500, body: { error: (err && err.message) || String(err) } }); });
  });
}

async function latestTaskRow(userId, taskType, since) {
  const { data, error } = await supabase
    .from("ai_tasks").select("id, status, error, output, task_type, created_at")
    .eq("user_id", userId).eq("task_type", taskType).gte("created_at", since)
    .order("created_at", { ascending: false }).limit(1).maybeSingle();
  if (error) throw error;
  return data;
}

/* Prose with none of the labels any of these parsers looks for. */
const JUNK_1 = "Certainly! Here's what I'd suggest. Think about your audience, keep it simple, " +
  "and revisit it in a month. Let me know if you'd like me to go deeper on any part.";
const JUNK_2 = "In summary: focus on clarity, publish consistently, and measure what happens.";

/* One parseable reply per route, in THAT route's own shape. */
const GOOD = {
  "content/outline": [
    "H1: How to price a workshop",
    "SEARCH_INTENT: commercial investigation",
    "QUESTIONS_TO_ANSWER: What do comparable workshops charge?",
    "---",
    "H2: What you are actually selling",
    "COVERS: the outcome, not the hours",
    "WHY_HERE: it reframes the price before the number appears",
    "---",
    "H2: Three ways to set the number",
    "COVERS: cost-plus, comparable, outcome",
    "WHY_HERE: gives the reader a method rather than a figure"
  ].join("\n"),
  /* RD_BRIEF_SECTIONS, read off the route's own constant — not invented here. */
  "rd/brief": [
    "QUESTION: Why do repeat customers stop returning after 90 days?",
    "KNOWN: The onboarding sequence stops after day three.",
    "ASSUMED: The drop-off is attention rather than dissatisfaction.",
    "WOULD_CHANGE: A four-week follow-up sequence, if attention is the cause.",
    "RECOMMENDATION: Run a holdout test on the next 200 customers."
  ].join("\n"),
  "email/subject-lines": [
    "Your seat is still open | urgency without a deadline claim",
    "What the last cohort changed their mind about | curiosity",
    "Three questions before you book | objection-handling"
  ].join("\n")
};

const BODIES = {
  "content/outline": { keyword: "check run — pricing a workshop", audience: "solo founders" },
  "rd/brief": { question: "check run — why do repeat customers stop returning?", context: "they buy once and do not come back" },
  "email/subject-lines": { purpose: "check run — invite past attendees back", audience: "past attendees" }
};

const ROUTES = [
  { key: "content/outline", path: "/api/agents/content/outline", shape: "blocks (H1/H2/COVERS/WHY_HERE)",
    labelInCorrection: ["H1:", "H2:", "COVERS:", "WHY_HERE:"], mustNotContain: ["DAY:", "PLATFORM:"] },
  { key: "rd/brief", path: "/api/agents/rd/brief", shape: "sections (RD_BRIEF_SECTIONS)",
    labelInCorrection: ["QUESTION:", "KNOWN:", "ASSUMED:", "WOULD_CHANGE:", "RECOMMENDATION:"], mustNotContain: ["DAY:", "H2:"] },
  { key: "email/subject-lines", path: "/api/agents/email/subject-lines", shape: "one per line (subject | angle)",
    labelInCorrection: ["the subject line | the angle it takes"], mustNotContain: ["DAY:", "H2:", "QUESTION:"] }
];

(async function () {
  console.log("checkToolRetryRollout — live database\n");

  const { data: someUser } = await supabase.from("users").select("id").limit(1).maybeSingle();
  if (!someUser) { console.error("no users row to attribute check rows to"); process.exit(1); }
  const userId = someUser.id;

  /* Before anything is written: what a previous crashed run left. */
  await residue.sweepPrevious(userId);

  const { data: highest } = await supabase.from("model_calls").select("id").order("id", { ascending: false }).limit(1).maybeSingle();
  ledgerMark = highest ? highest.id : 0;
  residue.setLedgerMark(ledgerMark);
  const ledgerBefore = await supabase.from("model_calls").select("id", { count: "exact", head: true }).eq("user_id", userId);
  const tasksBefore = await supabase.from("ai_tasks").select("id", { count: "exact", head: true }).eq("user_id", userId);
  console.log("user " + userId + "   before — model_calls: " + ledgerBefore.count + ", ai_tasks: " + tasksBefore.count + "\n");

  const since = new Date(Date.now() - 60000).toISOString();

  for (const r of ROUTES) {
    console.log("── " + r.key + "   " + r.shape + " ──");

    /* first fails, retry succeeds */
    replyQueue = [JUNK_1, GOOD[r.key]];
    callLog = [];
    const okRun = await callRoute(r.path, userId, BODIES[r.key]);
    const okLedger = await noteLedgerRows(userId);
    const okRow = await latestTaskRow(userId, r.key, since);
    if (okRow) residue.record("ai_tasks", okRow.id);
    console.log("  retry-succeeds: HTTP " + okRun.status + "   model calls " + callLog.length +
      "   ledger rows " + okLedger.length + "   row " + (okRow && okRow.id));
    console.log("    output.parse_retry: " + JSON.stringify(okRow && okRow.output && okRow.output.parse_retry));
    check(r.key + ": 200", okRun.status === 200, okRun.status + " " + JSON.stringify(okRun.body && okRun.body.error));
    check(r.key + ": exactly two model calls", callLog.length === 2, callLog.length);
    check(r.key + ": two model_calls rows", okLedger.length === 2, okLedger.length);
    check(r.key + ": status completed", okRow && okRow.status === "completed", okRow && okRow.status);
    check(r.key + ": output carries the retry marker", !!(okRow && okRow.output && okRow.output.parse_retry));
    check(r.key + ": it holds the first attempt's raw text",
      okRow && okRow.output.parse_retry.first_attempt.raw_output === JUNK_1);
    check(r.key + ": with its true length",
      okRow && okRow.output.parse_retry.first_attempt.raw_output_length === JUNK_1.length);
    /* THE CORRECTION NAMES THIS ROUTE'S OWN LABELS */
    const correction = callLog[1] || "";
    check(r.key + ": the correction was sent", correction.indexOf("STOP. YOUR PREVIOUS ANSWER") !== -1);
    r.labelInCorrection.forEach(function (label) {
      check(r.key + ": the correction names " + JSON.stringify(label), correction.indexOf(label) !== -1,
        correction.slice(correction.indexOf("THE SHAPE"), correction.indexOf("THE SHAPE") + 200));
    });
    r.mustNotContain.forEach(function (label) {
      check(r.key + ": the correction does NOT mention " + JSON.stringify(label),
        correction.indexOf("\n    " + label) === -1);
    });

    /* both fail */
    replyQueue = [JUNK_1, JUNK_2];
    callLog = [];
    const badRun = await callRoute(r.path, userId, BODIES[r.key]);
    const badLedger = await noteLedgerRows(userId);
    const badRow = await latestTaskRow(userId, r.key, since);
    if (badRow) residue.record("ai_tasks", badRow.id);
    console.log("  both-fail:      HTTP " + badRun.status + "   model calls " + callLog.length +
      "   ledger rows " + badLedger.length + "   row " + (badRow && badRow.id));
    console.log("    output.attempts: " + JSON.stringify(badRow && badRow.output && (badRow.output.attempts || []).map(function (a) {
      return { attempt: a.attempt, length: a.raw_output_length, starts: String(a.raw_output).slice(0, 24) };
    })));
    check(r.key + ": 502", badRun.status === 502, badRun.status);
    check(r.key + ": the 502 body still carries raw_output and provenance",
      !!(badRun.body && typeof badRun.body.raw_output === "string" && badRun.body.provenance));
    check(r.key + ": exactly two model calls, never a third", callLog.length === 2, callLog.length);
    check(r.key + ": no unexpected extra call", callLog.every(function (p) { return p.indexOf("__UNEXPECTED_EXTRA_CALL__") === -1; }));
    check(r.key + ": two model_calls rows", badLedger.length === 2, badLedger.length);
    check(r.key + ": status failed", badRow && badRow.status === "failed", badRow && badRow.status);
    check(r.key + ": output records both attempts", badRow && badRow.output && badRow.output.attempt_count === 2);
    check(r.key + ": attempt 1 is the first reply",
      badRow && badRow.output.attempts[0].attempt === 1 && badRow.output.attempts[0].raw_output === JUNK_1);
    check(r.key + ": attempt 2 is the second reply",
      badRow && badRow.output.attempts[1].attempt === 2 && badRow.output.attempts[1].raw_output === JUNK_2);
    console.log("");
  }

  /* ── cleanup, verified ───────────────────────────────────────────────────── */
  console.log("cleanup");
  console.log("  rows this run caused — ai_tasks: " + created.ai_tasks.length + ", model_calls: " + created.model_calls.length);
  const cleanupResult = await residue.cleanup("end of run");
  const leftovers = cleanupResult.leftovers.map(function (l) { return l.table + ": " + l.ids.join(", "); });
  if (leftovers.length) failures++;
  const ledgerAfter = await supabase.from("model_calls").select("id", { count: "exact", head: true }).eq("user_id", userId);
  const tasksAfter = await supabase.from("ai_tasks").select("id", { count: "exact", head: true }).eq("user_id", userId);
  console.log("  model_calls for that user: " + ledgerBefore.count + " before, " + ledgerAfter.count + " after");
  console.log("  ai_tasks for that user:    " + tasksBefore.count + " before, " + tasksAfter.count + " after");
  check("no row from this run remains", leftovers.length === 0, leftovers.join(" | "));
  check("both counts are back where they started",
    ledgerAfter.count === ledgerBefore.count && tasksAfter.count === tasksBefore.count);
  if (leftovers.length) {
    console.log("\n  RESIDUE LEFT BEHIND — remove by hand:");
    leftovers.forEach(function (l) { console.log("    " + l); });
  } else {
    console.log("\n  verified by reading both tables back: 0 rows from this run remain.");
  }

  console.log("\n" + (failures === 0 ? "ALL CHECKS PASSED" : failures + " CHECK(S) FAILED"));
  process.exit(failures === 0 ? 0 : 1);
})().catch(function (err) {
  console.error("check run threw: " + ((err && err.stack) || err));
  process.exit(1);
});
