/* ══════════════════════════════════════════════════════════════════════════
   checkAiTaskFields.js — the /api/ai/tasks lane records what it was asked for.

   THE DEFECT (§7 #73, this lane only). handleAiTaskRequest validated task_type
   against allowedTaskTypes, used it to pick the instruction the run was given,
   and then left it out of the insert — so the column's DEFAULT 'general' filled
   every row. 7,932 of 7,945 say "general" whatever was asked. processAiTask
   never wrote completed_at or error either, so a finished row was
   indistinguishable from a running one except by status, and a failure's reason
   lived only inside the result sentence.

   THE OTHER LANE WAS ALREADY RIGHT and is not touched: startToolRun has written
   task_type, completed_at, error and output since dfcce4d. This check asserts
   the two lanes now agree, rather than inventing a second shape.

   WHAT THIS PROVES
     1. A successful task records its real task_type, completed_at and result.
     2. A failed task records its real task_type, completed_at and error.
     3. A row of the OLD shape — task_type left to the default, completed_at and
        error null — still reads correctly through every path that displays it:
        GET /api/ai/tasks, GET /api/ai/tasks/:id, and the dashboard's own
        `task.task_type || "general"` expression.

   NOTHING IS BACKFILLED and this check would notice if it were: it counts the
   pre-existing rows before and after and asserts the number is unchanged.

   MUTATE=old-insert points the task_type assertions at a row inserted the
   PRE-FIX way — the insert without task_type — instead of at the row the route
   wrote. They must go red. That is what shows the assertions can tell a
   pre-fix row from a post-fix one, which is the only thing they are for.
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const { createResidueGuard, resolveSubjectAccount } = require("./checkRunResidue");
const SUBJECT_USER_ID = resolveSubjectAccount();

const path = require("path");
const REPO = path.join(__dirname, "..");

const SDK_PATH = require.resolve("@anthropic-ai/sdk", { paths: [REPO] });
const RealAnthropic = require(SDK_PATH);

/* The next reply the stub will give. "THROW" makes the model call fail, which
   is how the failure path is reached without breaking anything else. */
let nextReply = "A perfectly ordinary answer.";

function FakeAnthropic(options) {
  const instance = new RealAnthropic({ apiKey: "sk-ant-stub", timeout: 1000 });
  instance.messages = {
    create: async function (args) {
      if (nextReply === "THROW") throw new Error("checkAiTaskFields: simulated model failure");
      return {
        id: "msg_check",
        model: (args && args.model) || "stubbed",
        content: [{ type: "text", text: nextReply }],
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

const residue = createResidueGuard({
  supabase: supabase,
  name: "aiTaskFields",
  subject: SUBJECT_USER_ID,
  tables: ["ai_tasks", "model_calls"]
});
residue.install();

const MUTATING = process.env.MUTATE === "old-insert";

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

/* A real value from allowedTaskTypes, deliberately not "general" — the whole
   point is that what was asked for is what gets recorded. */
const ASKED_TASK_TYPE = "research_report";
const AGENT = "rd";

function callRoute(routePath, method, req) {
  const layer = app._router.stack.filter(function (l) {
    return l.route && l.route.path === routePath && l.route.methods[method];
  })[0];
  if (!layer) throw new Error("route not mounted: " + routePath);
  const stack = layer.route.stack;
  const handler = stack[stack.length - 1].handle;
  return new Promise(function (resolve) {
    let done = false;
    const fin = function (r) { if (!done) { done = true; resolve(r); } };
    const res = {
      statusCode: 200,
      status: function (c) { this.statusCode = c; return this; },
      json: function (p) { fin({ status: this.statusCode, body: p }); return this; }
    };
    Promise.resolve()
      .then(function () { return handler(req, res, function (e) { fin({ status: 500, body: { error: String(e) } }); }); })
      .catch(function (e) { fin({ status: 500, body: { error: String(e) } }); });
  });
}

/* processAiTask is fired without being awaited — the route answers first and the
   row reaches its terminal state afterwards. So the row is polled rather than
   read once. */
async function waitForTerminal(taskId) {
  for (let i = 0; i < 40; i++) {
    const r = await supabase.from("ai_tasks").select("*").eq("id", taskId).maybeSingle();
    if (r.data && r.data.status !== "processing") return r.data;
    await new Promise(function (res) { setTimeout(res, 250); });
  }
  const last = await supabase.from("ai_tasks").select("*").eq("id", taskId).maybeSingle();
  return last.data;
}

async function submit(taskType, prompt) {
  const before = new Date(Date.now() - 2000).toISOString();
  const r = await callRoute("/api/ai/tasks", "post", {
    user: { id: SUBJECT_USER_ID },
    body: { agent_type: AGENT, task_type: taskType, prompt: prompt },
    params: {}, query: {}, headers: {}
  });
  /* Whatever happened, find and record every row this submission caused. */
  const rows = await supabase.from("ai_tasks").select("id")
    .eq("user_id", SUBJECT_USER_ID).gte("created_at", before);
  (rows.data || []).forEach(function (x) { residue.record("ai_tasks", x.id); });
  const calls = await supabase.from("model_calls").select("id")
    .eq("user_id", SUBJECT_USER_ID).gte("created_at", before);
  (calls.data || []).forEach(function (x) { residue.record("model_calls", x.id); });
  return r;
}

(async function main() {
  await residue.sweepPrevious(SUBJECT_USER_ID);

  const preExisting = await supabase.from("ai_tasks").select("id", { count: "exact", head: true });
  console.log("\n══ before ══");
  console.log("    ai_tasks rows in the table: " + preExisting.count);

  if (MUTATING) {
    console.log("\n    !! MUTATION: the task_type assertions will be pointed at a row inserted the");
    console.log("       PRE-FIX way — no task_type on the insert. They must go red.\n");
  }

  /* ── an old-shaped row, written exactly as the route used to ─────────── */
  const oldShaped = await supabase.from("ai_tasks").insert({
    user_id: SUBJECT_USER_ID,
    agent_type: AGENT,
    prompt: "CHECK FIXTURE — pre-fix shape",
    result: null,
    status: "processing"
  }).select("*").single();
  if (oldShaped.error) throw new Error("could not create the old-shaped row: " + oldShaped.error.message);
  residue.record("ai_tasks", oldShaped.data.id);
  console.log("\n══ a row of the OLD shape, inserted the way the route used to ══");
  console.log("    task_type: " + JSON.stringify(oldShaped.data.task_type) +
    "   completed_at: " + JSON.stringify(oldShaped.data.completed_at) +
    "   error: " + JSON.stringify(oldShaped.data.error));
  check("the old shape gets 'general' from the column DEFAULT, not null",
    oldShaped.data.task_type === "general", String(oldShaped.data.task_type));
  check("and its completed_at and error are null",
    oldShaped.data.completed_at === null && oldShaped.data.error === null,
    JSON.stringify([oldShaped.data.completed_at, oldShaped.data.error]));

  /* ── 1. a successful task ───────────────────────────────────────────── */
  console.log("\n══ 1. a task that succeeds ══");
  nextReply = "Here is the research you asked for.";
  const okRes = await submit(ASKED_TASK_TYPE, "Check fixture: a research report, please.");
  const okId = okRes.body && (okRes.body.task_id || (okRes.body.task && okRes.body.task.id) || okRes.body.id);
  check("the route accepted the task", okRes.status === 200 || okRes.status === 202,
    okRes.status + " " + JSON.stringify(okRes.body).slice(0, 120));
  check("and returned a task id", !!okId, JSON.stringify(okRes.body).slice(0, 160));

  const okRow = okId ? await waitForTerminal(okId) : null;
  const okSubject = MUTATING ? oldShaped.data : okRow;
  if (okRow) {
    console.log("    row: " + JSON.stringify({
      task_type: okRow.task_type, status: okRow.status,
      completed_at: okRow.completed_at ? "set" : null,
      error: okRow.error, result: okRow.result ? "set" : null
    }));
    check("it records the task_type that was asked for, not 'general'",
      okSubject.task_type === ASKED_TASK_TYPE, String(okSubject.task_type));
    check("it reached a completed status", okRow.status === "completed" || okRow.status === "requires_approval",
      String(okRow.status));
    check("completed_at is written", !!okSubject.completed_at, String(okSubject.completed_at));
    check("result is written", !!okRow.result, String(okRow.result).slice(0, 60));
    check("error stays null on a success", okRow.error === null, String(okRow.error));
  }

  /* ── 2. a failing task ──────────────────────────────────────────────── */
  console.log("\n══ 2. a task that fails ══");
  nextReply = "THROW";
  const badRes = await submit(ASKED_TASK_TYPE, "Check fixture: this one fails.");
  const badId = badRes.body && (badRes.body.task_id || (badRes.body.task && badRes.body.task.id) || badRes.body.id);
  const badRow = badId ? await waitForTerminal(badId) : null;
  nextReply = "A perfectly ordinary answer.";

  if (badRow) {
    console.log("    row: " + JSON.stringify({
      task_type: badRow.task_type, status: badRow.status,
      completed_at: badRow.completed_at ? "set" : null,
      error: String(badRow.error || "").slice(0, 60),
      result: String(badRow.result || "").slice(0, 60)
    }));
    const badSubject = MUTATING ? oldShaped.data : badRow;
    check("a failed task still records its task_type",
      badSubject.task_type === ASKED_TASK_TYPE, String(badSubject.task_type));
    check("it is marked failed", badRow.status === "failed", String(badRow.status));
    check("completed_at is written on a failure too", !!badSubject.completed_at,
      String(badSubject.completed_at));
    check("error carries the message in its own column", !!badRow.error, String(badRow.error));
    check("and result still carries the sentence a person reads",
      String(badRow.result || "").indexOf("Task failed:") === 0, String(badRow.result).slice(0, 60));
  } else {
    check("the failing task produced a row", false, "no row found");
  }

  /* ── 3. the old shape still reads through every display path ────────── */
  console.log("\n══ 3. the old-shaped row, through every path that displays it ══");

  const list = await callRoute("/api/ai/tasks", "get", {
    user: { id: SUBJECT_USER_ID }, query: {}, params: {}, body: {}, headers: {}
  });
  check("GET /api/ai/tasks returns 200", list.status === 200,
    list.status + " " + JSON.stringify(list.body).slice(0, 100));
  const listed = (list.body && (list.body.tasks || list.body)) || [];
  const oldInList = (Array.isArray(listed) ? listed : []).filter(function (t) { return t.id === oldShaped.data.id; })[0];
  check("the old-shaped row appears in the list", !!oldInList,
    "listed " + (Array.isArray(listed) ? listed.length : "?") + " row(s)");
  if (oldInList) {
    console.log("    as listed: " + JSON.stringify({
      task_type: oldInList.task_type, completed_at: oldInList.completed_at, error: oldInList.error
    }));
    /* The dashboard's own expression, applied to what the API actually returns. */
    const rendered = oldInList.task_type || "general";
    check("the dashboard's `task.task_type || \"general\"` renders it as general",
      rendered === "general", rendered);
    check("its null completed_at and error come back as null, not missing",
      "completed_at" in oldInList && "error" in oldInList, Object.keys(oldInList).join(", "));
  }

  const single = await callRoute("/api/ai/tasks/:id", "get", {
    user: { id: SUBJECT_USER_ID }, params: { id: oldShaped.data.id }, query: {}, body: {}, headers: {}
  });
  check("GET /api/ai/tasks/:id returns 200 for an old-shaped row", single.status === 200,
    single.status + " " + JSON.stringify(single.body).slice(0, 120));

  /* ── nothing was backfilled ─────────────────────────────────────────── */
  console.log("\n══ nothing was backfilled ══");
  const stillGeneral = await supabase.from("ai_tasks")
    .select("id", { count: "exact", head: true })
    .eq("task_type", "general").is("completed_at", null);
  console.log("    rows still 'general' with a null completed_at: " + stillGeneral.count);
  check("the pre-existing rows were not rewritten", stillGeneral.count >= 7932,
    String(stillGeneral.count) + " — expected at least the 7,932 that predate this change");

  console.log("\n══ cleanup ══");
  const cleanupResult = await residue.cleanup("end of run");
  if (cleanupResult.leftovers.length) failures++;

  const after = await supabase.from("ai_tasks").select("id", { count: "exact", head: true });
  console.log("    ai_tasks rows after cleanup: " + after.count + " (was " + preExisting.count + ")");
  check("the table is back to the row count it started with", after.count === preExisting.count,
    preExisting.count + " → " + after.count);

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
})().catch(function (err) {
  console.error("\nThe check threw: " + ((err && err.stack) || err));
  process.exit(1);
});
