/* ══════════════════════════════════════════════════════════════════════════
   checkSocialCalendarRetry.js — the one retry on social/calendar, proved
   against the live database.

   WHY THE ROUTE HAS A RETRY. Measured, not suspected: the same prompt — byte
   for byte, 2,158 input tokens from the agent page and from a routine alike —
   succeeded twice and failed twice. Both failures came back short (613 and 410
   output tokens against a 4,000 limit) and parsed to zero entries. The route
   used to spend the money, discard the answer and return 502.

   THE FOUR PATHS THIS PROVES, each by reading the rows back:

     A  first attempt parses     → 1 model_calls row, 200, no retry marker
     B  first fails, retry works → 2 model_calls rows, 200, output carries the
                                   retry marker AND the first attempt's raw text
     C  both fail                → 2 model_calls rows, 502, output carries BOTH
                                   attempts' raw texts, labelled 1 and 2
     D  model transport error    → at most 1 model_calls row, no retry, and the
                                   row behaves exactly as it did before

   HOW IT RUNS, and what is stubbed: the same approach as
   checkToolFailureOutput.js — the real server.js is booted in this process and
   the real route handler is invoked, so the real startToolRun, the real parse,
   the real retry decision and the real Supabase writes all run. Only the
   Anthropic SDK is replaced, because a real model cannot be asked to return
   unparseable text on demand and the check must not spend money. The stub
   answers from a QUEUE, one reply per call, which is what makes "exactly one
   retry, never two" checkable: a third call would find the queue empty and is
   recorded as a violation.

   IT CLEANS UP, AND VERIFIES THE CLEANUP. Every ai_tasks and model_calls row
   this run causes is recorded by id and deleted at the end; the closing report
   reads both tables back and states what actually remains.

   Usage:  node scripts/checkSocialCalendarRetry.js
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const path = require("path");
const REPO = path.join(__dirname, "..");

/* ── the model stub: a queue of replies, one per call ─────────────────────── */
const SDK_PATH = require.resolve("@anthropic-ai/sdk", { paths: [REPO] });
const RealAnthropic = require(SDK_PATH);

let replyQueue = [];
let callLog = [];          // every prompt the route sent, in order
let throwOnCall = 0;       // 1-based index of a call that should throw; 0 = none

function FakeAnthropic(options) {
  const instance = new RealAnthropic(options);
  instance.messages = {
    create: async function (args) {
      const n = callLog.length + 1;
      const promptText = (((args || {}).messages || [])[0] || {}).content;
      const sent = Array.isArray(promptText)
        ? promptText.map(function (b) { return b.text || ""; }).join("")
        : String(promptText || "");
      callLog.push(sent);

      if (throwOnCall === n) {
        const transportError = new Error("check run — forced model transport failure");
        transportError.status = 500;
        throw transportError;
      }

      /* An empty queue means the route asked for one call more than this check
         allows. Recorded as text the assertions can catch rather than thrown,
         so the run keeps going and the report names it. */
      const reply = replyQueue.length ? replyQueue.shift() : "__UNEXPECTED_EXTRA_CALL__";
      return {
        id: "msg_check_" + n,
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

/* ── capture the express app ──────────────────────────────────────────────── */
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
const created = { ai_tasks: [], model_calls: [] };
let ledgerMark = 0;

function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

async function noteLedgerRows(userId) {
  const { data, error } = await supabase
    .from("model_calls").select("id, route, input_tokens, output_tokens, created_at")
    .eq("user_id", userId).gt("id", ledgerMark).order("id", { ascending: true });
  if (error) { console.error("    (could not read model_calls: " + error.message + ")"); return []; }
  (data || []).forEach(function (row) {
    if (created.model_calls.indexOf(row.id) === -1) created.model_calls.push(row.id);
    if (row.id > ledgerMark) ledgerMark = row.id;
  });
  return data || [];
}

function noteTaskRow(row) {
  if (row && row.id && created.ai_tasks.indexOf(row.id) === -1) created.ai_tasks.push(row.id);
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
    const req = { user: { id: userId }, body: body };
    const res = {
      statusCode: 200,
      status: function (code) { this.statusCode = code; return this; },
      json: function (payload) { done({ status: this.statusCode, body: payload }); return this; }
    };
    Promise.resolve()
      .then(function () { return handler(req, res, function (err) { done({ status: 500, body: { error: (err && err.message) || String(err) } }); }); })
      .catch(function (err) { done({ status: 500, body: { error: (err && err.message) || String(err) } }); });
  });
}

async function latestTaskRow(userId, since) {
  const { data, error } = await supabase
    .from("ai_tasks")
    .select("id, status, error, result, output, created_at")
    .eq("user_id", userId).eq("task_type", "social/calendar").gte("created_at", since)
    .order("created_at", { ascending: false }).limit(1).maybeSingle();
  if (error) throw error;
  return data;
}

/* A reply the parser accepts, and one it cannot read at all. */
const PARSEABLE = [
  "DAY: 1", "PLATFORM: linkedin", "FORMAT: text post",
  "HOOK: What the last cohort changed their mind about",
  "PURPOSE: Open the topic",
  "---",
  "DAY: 4", "PLATFORM: instagram", "FORMAT: carousel",
  "HOOK: Three questions we kept being asked",
  "PURPOSE: Answer the objection before it is raised"
].join("\n");

const UNPARSEABLE_1 = "Of course — here's a posting plan. Post consistently, engage with replies, and " +
  "focus on what your customers care about. Let me know if you'd like me to adjust the cadence.";
const UNPARSEABLE_2 = "| Day | Platform | Format |\n|---|---|---|\n| 1 | LinkedIn | Text |\n" +
  "That table should cover the first week.";

const BODY = { goal: "check run — retry pilot", cadence: "twice a week", weeks: 2 };

function reset(queue, throwAt) {
  replyQueue = queue.slice();
  callLog = [];
  throwOnCall = throwAt || 0;
}

(async function () {
  console.log("checkSocialCalendarRetry — live database\n");

  const { data: someUser, error: userErr } = await supabase.from("users").select("id").limit(1).maybeSingle();
  if (userErr) throw userErr;
  if (!someUser) { console.error("No users row to attribute check rows to."); process.exit(1); }
  const userId = someUser.id;

  const { data: highest } = await supabase
    .from("model_calls").select("id").order("id", { ascending: false }).limit(1).maybeSingle();
  ledgerMark = highest ? highest.id : 0;
  const ledgerBefore = await supabase.from("model_calls").select("id", { count: "exact", head: true }).eq("user_id", userId);
  const tasksBefore = await supabase.from("ai_tasks").select("id", { count: "exact", head: true }).eq("user_id", userId);
  console.log("user " + userId);
  console.log("before this run — model_calls for that user: " + ledgerBefore.count +
    ", ai_tasks: " + tasksBefore.count + " (ledger high-water id " + ledgerMark + ")\n");

  const since = new Date(Date.now() - 60000).toISOString();

  /* ── A. the first attempt parses ─────────────────────────────────────────── */
  console.log("A) first attempt parses — no retry expected");
  reset([PARSEABLE]);
  const a = await callRoute("/api/agents/social/calendar", userId, BODY);
  const aLedger = await noteLedgerRows(userId);
  const aRow = await latestTaskRow(userId, since);
  noteTaskRow(aRow);
  console.log("   HTTP " + a.status + "   model calls: " + callLog.length +
    "   ledger rows: " + aLedger.length + "   row " + (aRow && aRow.id));
  console.log("   row: " + JSON.stringify({ status: aRow && aRow.status, output_keys: aRow && Object.keys(aRow.output || {}) }));
  check("200", a.status === 200, a.status);
  check("exactly ONE model call", callLog.length === 1, callLog.length);
  check("exactly ONE model_calls row", aLedger.length === 1, aLedger.length);
  check("status completed", aRow && aRow.status === "completed", aRow && aRow.status);
  check("no retry marker in output", !!(aRow && aRow.output && aRow.output.parse_retry === undefined),
    aRow && JSON.stringify(aRow.output && aRow.output.parse_retry));
  check("the result is the normal one", !!(aRow && aRow.output && Array.isArray(aRow.output.entries) && aRow.output.entries.length === 2));
  check("the correction was NOT sent", callLog[0].indexOf("STOP. YOUR PREVIOUS ANSWER") === -1);

  /* ── B. first fails, the retry works ─────────────────────────────────────── */
  console.log("\nB) first attempt parses to zero, retry succeeds");
  reset([UNPARSEABLE_1, PARSEABLE]);
  const b = await callRoute("/api/agents/social/calendar", userId, BODY);
  const bLedger = await noteLedgerRows(userId);
  const bRow = await latestTaskRow(userId, since);
  noteTaskRow(bRow);
  console.log("   HTTP " + b.status + "   model calls: " + callLog.length + "   ledger rows: " + bLedger.length);
  console.log("   ledger: " + JSON.stringify(bLedger.map(function (r) { return { id: r.id, route: r.route, in: r.input_tokens, out: r.output_tokens }; })));
  console.log("   row " + (bRow && bRow.id) + ": " + JSON.stringify({
    status: bRow && bRow.status,
    parse_retry: bRow && bRow.output && bRow.output.parse_retry
  }));
  check("200 — the caller gets a normal result", b.status === 200, b.status);
  check("the response body is the normal shape",
    !!(b.body && b.body.success === true && Array.isArray(b.body.entries) && b.body.measured && b.body.provenance));
  check("the response carries NO retry key — unchanged in shape",
    b.body && b.body.parse_retry === undefined, JSON.stringify(b.body && b.body.parse_retry));
  check("exactly TWO model calls", callLog.length === 2, callLog.length);
  check("the second call carried the correction", callLog[1] && callLog[1].indexOf("STOP. YOUR PREVIOUS ANSWER COULD NOT BE READ") !== -1);
  check("the correction names the three-hyphen separator", callLog[1] && callLog[1].indexOf("only three hyphens: ---") !== -1);
  check("the correction names all five labels",
    ["DAY:", "PLATFORM:", "FORMAT:", "HOOK:", "PURPOSE:"].every(function (l) { return callLog[1].indexOf(l) !== -1; }));
  check("the correction forbids JSON and tables",
    callLog[1].indexOf("No JSON") !== -1 && callLog[1].indexOf("No table") !== -1);
  check("the first prompt is still inside the second call", callLog[1].indexOf(callLog[0]) === 0);
  check("TWO model_calls rows — the retry is ledgered", bLedger.length === 2, bLedger.length);
  check("both ledger rows carry the same route",
    bLedger.length === 2 && bLedger[0].route === bLedger[1].route && bLedger[0].route === "POST /api/agents/social/calendar",
    JSON.stringify(bLedger.map(function (r) { return r.route; })));
  check("status completed", bRow && bRow.status === "completed", bRow && bRow.status);
  check("output carries the retry marker", !!(bRow && bRow.output && bRow.output.parse_retry));
  check("it says a retry happened, with the count",
    bRow && bRow.output.parse_retry.retried === true && bRow.output.parse_retry.attempts === 2);
  check("it holds the FIRST attempt's raw text",
    bRow && bRow.output.parse_retry.first_attempt &&
    bRow.output.parse_retry.first_attempt.raw_output === UNPARSEABLE_1,
    bRow && bRow.output.parse_retry.first_attempt && String(bRow.output.parse_retry.first_attempt.raw_output).slice(0, 50));
  check("with its true length",
    bRow && bRow.output.parse_retry.first_attempt.raw_output_length === UNPARSEABLE_1.length,
    bRow && bRow.output.parse_retry.first_attempt.raw_output_length);
  check("the successful entries are stored as normal",
    bRow && Array.isArray(bRow.output.entries) && bRow.output.entries.length === 2);
  check("the markdown result does NOT carry the raw text — history stays readable",
    bRow && String(bRow.result || "").indexOf(UNPARSEABLE_1.slice(0, 40)) === -1);

  /* ── C. both attempts fail ───────────────────────────────────────────────── */
  console.log("\nC) both attempts parse to zero");
  reset([UNPARSEABLE_1, UNPARSEABLE_2]);
  const c = await callRoute("/api/agents/social/calendar", userId, BODY);
  const cLedger = await noteLedgerRows(userId);
  const cRow = await latestTaskRow(userId, since);
  noteTaskRow(cRow);
  console.log("   HTTP " + c.status + "   model calls: " + callLog.length + "   ledger rows: " + cLedger.length);
  console.log("   row " + (cRow && cRow.id) + ": " + JSON.stringify({
    status: cRow && cRow.status,
    attempt_count: cRow && cRow.output && cRow.output.attempt_count,
    attempts: cRow && cRow.output && (cRow.output.attempts || []).map(function (x) {
      return { attempt: x.attempt, length: x.raw_output_length, starts: String(x.raw_output).slice(0, 28) };
    })
  }));
  check("502 — unchanged", c.status === 502, c.status);
  check("the same error sentence", !!(c.body && /could not be read back from the model/.test(c.body.error)), c.body && c.body.error);
  check("the response still carries raw_output and provenance",
    !!(c.body && typeof c.body.raw_output === "string" && c.body.provenance));
  check("exactly TWO model calls — never a third", callLog.length === 2, callLog.length);
  check("no unexpected extra call was made", callLog.every(function (p) { return p.indexOf("__UNEXPECTED_EXTRA_CALL__") === -1; }));
  check("TWO model_calls rows", cLedger.length === 2, cLedger.length);
  check("status failed", cRow && cRow.status === "failed", cRow && cRow.status);
  check("the error sentence is on the row", !!(cRow && /could not be read back/.test(cRow.error || "")));
  check("output records two attempts", cRow && cRow.output && cRow.output.attempt_count === 2);
  check("attempt 1 is the FIRST raw text",
    cRow && cRow.output.attempts[0].attempt === 1 && cRow.output.attempts[0].raw_output === UNPARSEABLE_1,
    cRow && String(cRow.output.attempts[0].raw_output).slice(0, 40));
  check("attempt 2 is the SECOND raw text",
    cRow && cRow.output.attempts[1].attempt === 2 && cRow.output.attempts[1].raw_output === UNPARSEABLE_2,
    cRow && String(cRow.output.attempts[1].raw_output).slice(0, 40));
  check("both true lengths are recorded",
    cRow && cRow.output.attempts[0].raw_output_length === UNPARSEABLE_1.length &&
    cRow.output.attempts[1].raw_output_length === UNPARSEABLE_2.length);
  check("parse_failure is still true", cRow && cRow.output.parse_failure === true);

  /* ── D. a transport error: no retry ──────────────────────────────────────── */
  console.log("\nD) the model call throws — no retry, behaviour unchanged");
  reset([PARSEABLE, PARSEABLE], 1);
  const d = await callRoute("/api/agents/social/calendar", userId, BODY);
  const dLedger = await noteLedgerRows(userId);
  const dRow = await latestTaskRow(userId, since);
  noteTaskRow(dRow);
  console.log("   HTTP " + d.status + "   model calls attempted: " + callLog.length + "   ledger rows: " + dLedger.length);
  console.log("   row " + (dRow && dRow.id) + ": " + JSON.stringify({ status: dRow && dRow.status, output: dRow && dRow.output }));
  check("exactly ONE model call attempted — no retry after a throw", callLog.length === 1, callLog.length);
  check("at most one model_calls row", dLedger.length <= 1, dLedger.length);
  check("the route did not answer 2xx", d.status !== 200, d.status);
  check("status failed", dRow && dRow.status === "failed", dRow && dRow.status);
  check("output stays null — a transport error is not a parse failure",
    dRow && dRow.output === null, JSON.stringify(dRow && dRow.output));
  check("no retry marker anywhere", !(dRow && dRow.output && dRow.output.parse_retry));

  /* ── E. a validation refusal never reaches the model ─────────────────────── */
  console.log("\nE) a rejected input — no model call at all");
  reset([PARSEABLE, PARSEABLE]);
  const e = await callRoute("/api/agents/social/calendar", userId, { cadence: "twice a week" });
  const eLedger = await noteLedgerRows(userId);
  console.log("   HTTP " + e.status + "   model calls: " + callLog.length + "   ledger rows: " + eLedger.length);
  check("400", e.status === 400, e.status);
  check("no model call", callLog.length === 0, callLog.length);
  check("no ledger row", eLedger.length === 0, eLedger.length);

  /* ── cleanup, verified by reading back ───────────────────────────────────── */
  console.log("\ncleanup");
  console.log("  rows this run caused — ai_tasks: " + created.ai_tasks.length +
    ", model_calls: " + created.model_calls.length);
  const leftovers = [];
  for (const table of ["ai_tasks", "model_calls"]) {
    const ids = created[table];
    if (!ids.length) { console.log("  " + table + ": nothing to delete"); continue; }
    const { error: delErr } = await supabase.from(table).delete().in("id", ids);
    if (delErr) console.log("  " + table + ": delete reported " + delErr.message);
    const { count, error: countErr } = await supabase
      .from(table).select("id", { count: "exact", head: true }).in("id", ids);
    if (countErr) {
      console.log("  " + table + ": COULD NOT VERIFY — " + countErr.message);
      leftovers.push(table + ": verification failed"); failures++; continue;
    }
    console.log("  " + table + ": " + ids.length + " written, " + count + " still present after deletion");
    if (count > 0) {
      const { data: stuck } = await supabase.from(table).select("id").in("id", ids);
      leftovers.push(table + ": " + (stuck || []).map(function (r) { return r.id; }).join(", "));
    }
  }
  const ledgerAfter = await supabase.from("model_calls").select("id", { count: "exact", head: true }).eq("user_id", userId);
  const tasksAfter = await supabase.from("ai_tasks").select("id", { count: "exact", head: true }).eq("user_id", userId);
  console.log("  model_calls for that user: " + ledgerBefore.count + " before, " + ledgerAfter.count + " after");
  console.log("  ai_tasks for that user:    " + tasksBefore.count + " before, " + tasksAfter.count + " after");
  check("no ai_tasks row from this run remains", !leftovers.some(function (l) { return l.indexOf("ai_tasks") === 0; }), leftovers.join(" | "));
  check("no model_calls row from this run remains", !leftovers.some(function (l) { return l.indexOf("model_calls") === 0; }), leftovers.join(" | "));
  check("that user's model_calls count is back where it started", ledgerAfter.count === ledgerBefore.count,
    ledgerBefore.count + " -> " + ledgerAfter.count);
  check("that user's ai_tasks count is back where it started", tasksAfter.count === tasksBefore.count,
    tasksBefore.count + " -> " + tasksAfter.count);
  if (leftovers.length) {
    console.log("\n  RESIDUE LEFT BEHIND — remove these by hand:");
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
