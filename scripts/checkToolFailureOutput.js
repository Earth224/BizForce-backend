/* ══════════════════════════════════════════════════════════════════════════
   checkToolFailureOutput.js — does a failed tool run leave its evidence behind?

   WHAT THIS PROVES, AGAINST THE REAL DATABASE:

     1. A tool route that SUCCEEDS writes ai_tasks.status "completed" and
        ai_tasks.output holding the tool's own result body — with no
        parse_failure flag anywhere in it.

     2. A tool route whose model reply CANNOT BE PARSED writes
        ai_tasks.status "failed", the error sentence, and an output object
        carrying { parse_failure: true, raw_output, raw_output_length,
        raw_output_truncated } — the evidence that used to exist only inside
        the 502 response and was gone at the end of the request.

     3. Truncation: a reply longer than 4000 characters is stored cut to 4000
        with the TRUE length beside it, so a truncated row cannot be mistaken
        for a short reply.

     4. A route whose failure branch was NOT changed still writes its rows
        exactly as before — output null on failure.

   HOW IT RUNS. It boots the real server.js in this process (nothing is
   modified on disk) and invokes the route handlers the same way
   dispatchToolCall does: by walking app._router.stack for the route and
   calling its final handler with a req/res shim. That runs the REAL handler,
   the REAL startToolRun, the REAL parse path and the REAL Supabase writes.

   THE ONLY THING STUBBED IS THE ANTHROPIC HTTP CALL. The SDK class is
   replaced in the require cache before server.js loads, so messages.create
   returns text this script chooses. Two reasons, both deliberate: a real model
   call cannot be made to return unparseable text on demand, which is the
   condition under test; and the check would otherwise spend money on every
   run. Everything downstream of that reply — the parse, the failure branch,
   the ai_tasks write — is the shipped code.

   IT CLEANS UP AFTER ITSELF, IN EVERY TABLE IT WRITES, AND PROVES IT.

   TWO TABLES ARE WRITTEN by a tool run, not one:
     ai_tasks     the run's own row, created by startToolRun
     model_calls  the SPEND LEDGER, written by callAnthropicText on every
                  model call that returns — including a stubbed one

   An earlier version of this script tracked only ai_tasks and reported "no
   residue" while leaving fourteen ledger rows behind under a real user's id.
   That is the failure this section exists to prevent: the claim was about what
   cleanup had been ASKED to do, not about what was left in the tables.

   So every row this script causes is recorded by id as it appears, in both
   tables, and the closing report DELETES them and then READS THE TABLES BACK
   to count what actually remains. It reports the verified number, not the
   attempt. Anything it could not remove is named with its table and id.

   IT CREATES NO ACCOUNT. It picks an existing users row to attribute its rows
   to, and never inserts into users, profiles or auth.

   Usage:  node scripts/checkToolFailureOutput.js
   Needs the same .env the server needs (SUPABASE_URL, SUPABASE_SERVICE_KEY).
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const path = require("path");
const REPO = path.join(__dirname, "..");

/* ── the model stub, installed before server.js loads ─────────────────────── */
const SDK_PATH = require.resolve("@anthropic-ai/sdk", { paths: [REPO] });
const RealAnthropic = require(SDK_PATH);

var nextModelText = "";
var modelShouldThrow = false;

function FakeAnthropic(options) {
  const instance = new RealAnthropic(options);
  instance.messages = {
    create: async function (args) {
      /* server.js binds the SDK class once, at require time, so the throwing
         case has to live inside this one implementation — swapping the module
         export later would not reach the binding it already holds. */
      if (modelShouldThrow) {
        var transportError = new Error("check run — forced model transport failure");
        transportError.status = 500;
        throw transportError;
      }
      return {
        id: "msg_check",
        model: (args && args.model) || "stubbed",
        content: [{ type: "text", text: nextModelText }],
        stop_reason: "end_turn",
        usage: { input_tokens: 1, output_tokens: 1 }
      };
    }
  };
  return instance;
}
Object.keys(RealAnthropic).forEach(function (k) { FakeAnthropic[k] = RealAnthropic[k]; });
require.cache[SDK_PATH].exports = FakeAnthropic;

/* ── capture the express app the server creates ───────────────────────────── */
const EXPRESS_PATH = require.resolve("express", { paths: [REPO] });
const realExpress = require(EXPRESS_PATH);
let app = null;
const expressWrapper = function () {
  const created = realExpress.apply(this, arguments);
  if (!app) app = created;
  return created;
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

/* EVERY ROW THIS RUN CAUSES, BY TABLE. Recorded as it appears rather than
   inferred at the end from a time window: a window catches rows somebody else
   wrote in the same seconds, and misses one written a moment late. */
const created = { ai_tasks: [], model_calls: [] };

/* The high-water mark of model_calls.id before the run. Every ledger row this
   script causes is written after it, under the user it borrowed, so the ids to
   clean up are exactly those above the mark for that user — read from the table
   after each call rather than assumed. */
let ledgerMark = 0;

async function noteLedgerRows(userId) {
  const { data, error } = await supabase
    .from("model_calls")
    .select("id")
    .eq("user_id", userId)
    .gt("id", ledgerMark)
    .order("id", { ascending: true });
  if (error) { console.error("    (could not read model_calls to track it: " + error.message + ")"); return; }
  (data || []).forEach(function (row) {
    if (created.model_calls.indexOf(row.id) === -1) created.model_calls.push(row.id);
    if (row.id > ledgerMark) ledgerMark = row.id;
  });
}

function noteTaskRow(row) {
  if (row && row.id && created.ai_tasks.indexOf(row.id) === -1) created.ai_tasks.push(row.id);
}
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

/* ── invoking one route handler, the way dispatchToolCall does ────────────── */
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

async function latestTaskRow(userId, taskType, since) {
  const { data, error } = await supabase
    .from("ai_tasks")
    .select("id, status, error, result, output, task_type, created_at")
    .eq("user_id", userId)
    .eq("task_type", taskType)
    .gte("created_at", since)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();
  if (error) throw error;
  return data;
}

/* Model text that parses: the labelled block format social/calendar asks for. */
const PARSEABLE_CALENDAR = [
  "DAY: 1", "PLATFORM: linkedin", "FORMAT: text post",
  "HOOK: What nobody tells you about pricing a workshop",
  "PURPOSE: Open the topic and gather replies",
  "---",
  "DAY: 3", "PLATFORM: instagram", "FORMAT: carousel",
  "HOOK: Three things the last cohort changed their mind about",
  "PURPOSE: Social proof without naming numbers"
].join("\n");

/* Model text that cannot parse: prose, none of the labels, no separators. */
const UNPARSEABLE = "Sure! Here is a thoughtful posting plan for you. I would suggest posting " +
  "regularly and engaging with your audience. Consistency matters more than volume, and you " +
  "should focus on what your customers actually care about.";

/* Long unparseable text, to exercise the 4000-character ceiling. */
const LONG_UNPARSEABLE = UNPARSEABLE + " " + "x".repeat(5000);

(async function () {
  console.log("checkToolFailureOutput — live database\n");

  /* A real user id is required by ai_tasks.user_id's foreign key. Any existing
     one will do; every row this script writes is deleted again below. */
  const { data: someUser, error: userErr } = await supabase
    .from("users").select("id").limit(1).maybeSingle();
  if (userErr) throw userErr;
  if (!someUser) { console.error("No users row to attribute the check rows to. Nothing was run."); process.exit(1); }
  const userId = someUser.id;
  console.log("using user " + userId + " for the check rows (all deleted at the end)\n");

  const since = new Date(Date.now() - 60000).toISOString();

  /* Read before anything runs, so nothing already in the ledger is ever a
     candidate for deletion by this script. */
  const { data: highest } = await supabase
    .from("model_calls").select("id").order("id", { ascending: false }).limit(1).maybeSingle();
  ledgerMark = highest ? highest.id : 0;
  const ledgerBefore = await supabase
    .from("model_calls").select("id", { count: "exact", head: true }).eq("user_id", userId);
  const tasksBefore = await supabase
    .from("ai_tasks").select("id", { count: "exact", head: true }).eq("user_id", userId);
  console.log("before this run — model_calls for that user: " + ledgerBefore.count +
    ", ai_tasks for that user: " + tasksBefore.count + " (ledger high-water id " + ledgerMark + ")\n");

  /* ── 1. a successful run ────────────────────────────────────────────────── */
  console.log("1) social/calendar SUCCEEDS");
  nextModelText = PARSEABLE_CALENDAR;
  const ok = await callRoute("/api/agents/social/calendar", userId, {
    goal: "check run — fill the spring workshop",
    cadence: "twice a week",
    platforms: ["linkedin", "instagram"],
    weeks: 2
  });
  const okRow = await latestTaskRow(userId, "social/calendar", since);
  noteTaskRow(okRow); await noteLedgerRows(userId);
  console.log("   HTTP " + ok.status + "   row " + (okRow && okRow.id));
  check("the route answered 200", ok.status === 200, ok.status + " " + JSON.stringify(ok.body && ok.body.error));
  check("an ai_tasks row exists", !!okRow);
  check("status is completed", okRow && okRow.status === "completed", okRow && okRow.status);
  check("output holds the tool's own result", !!(okRow && okRow.output && Array.isArray(okRow.output.entries) && okRow.output.entries.length === 2),
    okRow && JSON.stringify(Object.keys(okRow.output || {})));
  check("output carries the measured block", !!(okRow && okRow.output && okRow.output.measured));
  check("NO parse-failure flag on a successful run",
    !!(okRow && okRow.output && okRow.output.parse_failure === undefined), okRow && okRow.output && okRow.output.parse_failure);
  check("no error text", !(okRow && okRow.error), okRow && okRow.error);

  /* ── 2. a forced parse failure ──────────────────────────────────────────── */
  console.log("\n2) social/calendar CANNOT PARSE the reply");
  nextModelText = UNPARSEABLE;
  const bad = await callRoute("/api/agents/social/calendar", userId, {
    goal: "check run — forced parse failure",
    cadence: "twice a week"
  });
  const badRow = await latestTaskRow(userId, "social/calendar", since);
  noteTaskRow(badRow); await noteLedgerRows(userId);
  console.log("   HTTP " + bad.status + "   row " + (badRow && badRow.id));
  check("the route answered 502", bad.status === 502, bad.status);
  check("the 502 body still carries raw_output", bad.body && bad.body.raw_output === UNPARSEABLE);
  check("the 502 body still carries the error sentence",
    !!(bad.body && /could not be read back from the model/.test(bad.body.error)), bad.body && bad.body.error);
  check("an ai_tasks row exists", !!badRow);
  check("status is failed", badRow && badRow.status === "failed", badRow && badRow.status);
  check("the error sentence is on the row",
    !!(badRow && /the model's output could not be read back/.test(badRow.error || "")), badRow && badRow.error);
  check("output is not null", !!(badRow && badRow.output), badRow && String(badRow.output));
  check("output.parse_failure is true", !!(badRow && badRow.output && badRow.output.parse_failure === true));
  check("output.raw_output IS the model's text", badRow && badRow.output && badRow.output.raw_output === UNPARSEABLE,
    badRow && badRow.output && String(badRow.output.raw_output).slice(0, 60));
  check("output.raw_output_length is the true length",
    badRow && badRow.output && badRow.output.raw_output_length === UNPARSEABLE.length,
    badRow && badRow.output && badRow.output.raw_output_length);
  check("output.raw_output_truncated is false for a short reply",
    badRow && badRow.output && badRow.output.raw_output_truncated === false);
  check("the prompt was NOT stored",
    badRow && badRow.output && Object.keys(badRow.output).sort().join(",") ===
      "parse_failure,raw_output,raw_output_length,raw_output_truncated",
    badRow && badRow.output && Object.keys(badRow.output).join(","));

  /* ── 3. truncation ──────────────────────────────────────────────────────── */
  console.log("\n3) a reply longer than 4000 characters");
  nextModelText = LONG_UNPARSEABLE;
  const longRun = await callRoute("/api/agents/social/calendar", userId, {
    goal: "check run — truncation",
    cadence: "twice a week"
  });
  const longRow = await latestTaskRow(userId, "social/calendar", since);
  noteTaskRow(longRow); await noteLedgerRows(userId);
  console.log("   HTTP " + longRun.status + "   stored " +
    (longRow && longRow.output && String(longRow.output.raw_output).length) + " of " +
    (longRow && longRow.output && longRow.output.raw_output_length) + " characters");
  check("still a 502", longRun.status === 502, longRun.status);
  check("stored text is cut to exactly 4000 characters",
    longRow && longRow.output && String(longRow.output.raw_output).length === 4000,
    longRow && longRow.output && String(longRow.output.raw_output).length);
  check("the true length is recorded, not the truncated one",
    longRow && longRow.output && longRow.output.raw_output_length === LONG_UNPARSEABLE.length,
    longRow && longRow.output && longRow.output.raw_output_length);
  check("raw_output_truncated is true", longRow && longRow.output && longRow.output.raw_output_truncated === true);
  check("the stored text is the START of the reply",
    longRow && longRow.output && LONG_UNPARSEABLE.indexOf(String(longRow.output.raw_output)) === 0);

  /* ── 4. a route whose failure branch was not changed ─────────────────────── */
  console.log("\n4) etsy/pricing-strategy — a route with NO parse-failure branch, unchanged");
  nextModelText = "PRICE: 48\nRATIONALE: A check run.";
  const control = await callRoute("/api/agents/etsy/pricing-strategy", userId, {
    listing_title: "check run — control route"
  });
  const controlRow = await latestTaskRow(userId, "etsy/pricing-strategy", since);
  noteTaskRow(controlRow); await noteLedgerRows(userId);
  console.log("   HTTP " + control.status + "   row " + (controlRow && controlRow.id) +
    "   status " + (controlRow && controlRow.status));
  check("it still answers", control.status === 200 || control.status === 502, control.status);
  check("it wrote its row", !!controlRow);
  check("no parse-failure flag was added to it",
    !(controlRow && controlRow.output && controlRow.output.parse_failure),
    controlRow && controlRow.output && JSON.stringify(Object.keys(controlRow.output)));
  if (controlRow && controlRow.status === "completed") {
    check("a completed control row still stores its result in output", !!controlRow.output);
  } else {
    check("a failed control row still leaves output null — unchanged behaviour",
      controlRow && controlRow.output === null, controlRow && JSON.stringify(controlRow.output));
  }

  /* ── 5. the one-argument path: an existing caller, unchanged ─────────────── */
  /* THE REQUIREMENT THIS PROVES: every call that passes only an error must
     behave exactly as before and write no output. Forced through the REAL
     route by making the model call throw, which sends social/calendar down its
     catch — where run.fail(error) is called with one argument, as it always
     has been. */
  console.log("\n5) a failure that is NOT a parse failure — run.fail(error) with no details");
  modelShouldThrow = true;
  const thrown = await callRoute("/api/agents/social/calendar", userId, {
    goal: "check run — model transport failure",
    cadence: "twice a week"
  });
  const thrownRow = await latestTaskRow(userId, "social/calendar", since);
  noteTaskRow(thrownRow); await noteLedgerRows(userId);
  console.log("   HTTP " + thrown.status + "   row " + (thrownRow && thrownRow.id) +
    "   output " + (thrownRow && JSON.stringify(thrownRow.output)));
  check("the route did not answer 2xx", thrown.status !== 200, thrown.status);
  check("the row is still marked failed", thrownRow && thrownRow.status === "failed", thrownRow && thrownRow.status);
  check("output stays NULL when no details are passed — unchanged behaviour",
    thrownRow && thrownRow.output === null, thrownRow && JSON.stringify(thrownRow.output));
  check("the error text is still recorded", !!(thrownRow && thrownRow.error), thrownRow && thrownRow.error);
  modelShouldThrow = false;

  /* ── 6. an empty reply: the flag with a length of 0 ──────────────────────── */
  /* The requirement that a missing or empty raw text stores the flag and a
     length of 0 rather than throwing or storing null. Forced by handing the
     route a reply of "" — it parses to nothing, so the parse-failure branch
     fires with an empty string in hand. */
  console.log("\n6) an EMPTY model reply — the flag, with a length of 0");
  nextModelText = "";
  const empty = await callRoute("/api/agents/social/calendar", userId, {
    goal: "check run — empty reply",
    cadence: "twice a week"
  });
  const emptyRow = await latestTaskRow(userId, "social/calendar", since);
  noteTaskRow(emptyRow); await noteLedgerRows(userId);
  console.log("   HTTP " + empty.status + "   output " + (emptyRow && JSON.stringify(emptyRow.output)));
  check("still a 502", empty.status === 502, empty.status);
  check("output is stored, not null", !!(emptyRow && emptyRow.output));
  check("parse_failure is true", emptyRow && emptyRow.output && emptyRow.output.parse_failure === true);
  check("raw_output is an empty string, not null",
    emptyRow && emptyRow.output && emptyRow.output.raw_output === "", emptyRow && emptyRow.output && String(emptyRow.output.raw_output));
  check("raw_output_length is 0", emptyRow && emptyRow.output && emptyRow.output.raw_output_length === 0);
  check("nothing threw", empty.status !== 500, empty.status);

  /* ── cleanup, and then the only thing worth reporting: what is left ─────── */
  console.log("\ncleanup");
  console.log("  rows this run caused — ai_tasks: " + created.ai_tasks.length +
    ", model_calls: " + created.model_calls.length);

  const leftovers = [];

  for (const table of ["ai_tasks", "model_calls"]) {
    const ids = created[table];
    if (!ids.length) { console.log("  " + table + ": nothing to delete"); continue; }

    const { error: delErr } = await supabase.from(table).delete().in("id", ids);
    if (delErr) console.log("  " + table + ": delete reported " + delErr.message);

    /* THE REPORT IS THE READ-BACK, NOT THE DELETE. A delete that returned no
       error is not evidence the rows are gone; counting them is. */
    const { count, error: countErr } = await supabase
      .from(table).select("id", { count: "exact", head: true }).in("id", ids);
    if (countErr) {
      console.log("  " + table + ": COULD NOT VERIFY — " + countErr.message);
      leftovers.push(table + ": verification failed (" + ids.length + " ids unknown)");
      failures++;
      continue;
    }
    console.log("  " + table + ": " + ids.length + " written, " + count + " still present after deletion");
    if (count > 0) {
      const { data: stuck } = await supabase.from(table).select("id").in("id", ids);
      leftovers.push(table + ": " + (stuck || []).map(r => r.id).join(", "));
    }
  }

  /* A second, independent look: whatever this user has in those two tables now,
     compared with what they had before the run. It catches a row this script
     caused but failed to record — the exact way the previous version went wrong. */
  const ledgerAfter = await supabase
    .from("model_calls").select("id", { count: "exact", head: true }).eq("user_id", userId);
  const tasksAfter = await supabase
    .from("ai_tasks").select("id", { count: "exact", head: true }).eq("user_id", userId);
  console.log("  model_calls for that user: " + ledgerBefore.count + " before, " + ledgerAfter.count + " after");
  console.log("  ai_tasks for that user:    " + tasksBefore.count + " before, " + tasksAfter.count + " after");

  check("no ai_tasks row from this run remains", !leftovers.some(l => l.indexOf("ai_tasks") === 0), leftovers.join(" | "));
  check("no model_calls row from this run remains", !leftovers.some(l => l.indexOf("model_calls") === 0), leftovers.join(" | "));
  check("that user's model_calls count is back to where it started",
    ledgerAfter.count === ledgerBefore.count, ledgerBefore.count + " -> " + ledgerAfter.count);
  check("that user's ai_tasks count is back to where it started",
    tasksAfter.count === tasksBefore.count, tasksBefore.count + " -> " + tasksAfter.count);

  if (leftovers.length) {
    console.log("\n  RESIDUE LEFT BEHIND — remove these by hand:");
    leftovers.forEach(l => console.log("    " + l));
  } else {
    console.log("\n  verified by reading both tables back: 0 rows from this run remain.");
  }

  console.log("\n" + (failures === 0 ? "ALL CHECKS PASSED" : failures + " CHECK(S) FAILED"));
  process.exit(failures === 0 ? 0 : 1);
})().catch(function (err) {
  console.error("check run threw: " + ((err && err.stack) || err));
  process.exit(1);
});
