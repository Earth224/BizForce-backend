/* ═══════════════════════════════════════════════════════════════════════════
   lib/triggerRunner.js — the hourly trigger pass, the metric reads and the
   preview (intelligence layer B4). lib/triggers.js decides; this reads, asks
   the gates, acts and records.

   THE PASS. triggerTick runs at :30 UTC every hour (server.js schedules it) and
   only when ENABLE_TRIGGERS is exactly "true", read again at the top of every
   tick. It claims the hour through job_runs as hourly_triggers_h<hh> for the
   UTC day (the agent schedules' idiom: job_runs.last_run_on is a DATE, so the
   job name carries the hour), so two processes, or a repeated tick, cannot both
   fire an hour. Then, for each member with an enabled trigger:
     1. today's firings are read once (the daily cap; a read that fails skips
        the member: a cap that cannot be counted is not applied on a guess);
     2. each trigger's number is read (counts and sums over the member's own
        rows only) and kept on the trigger as last_value;
     3. the line, the cooldown and the daily cap are applied (triggers.plan);
     4. a firing goes through lib/gates.js as trigger_fire: G13 (the plan; the
        owner passes over it) then G9 (the platform daily spend ceiling, which
        refuses at 100% and when it cannot be read). The decision is recorded
        with an id made here, and the firing row carries that id;
     5. only a decision that ran acts. Nothing here publishes or sends:
          raise_alert     a notification for the member
          draft_task      a saved prompt the member runs with one press, through
                          the normal task route (handleAiTaskRequest), whose
                          text asks for approval, so G2 holds anything that
                          would publish or send
          pause_schedule  the agent's schedules paused (paused_reason
                          'trigger'), and a notification
   Quiet hours and cooldowns write no firing row. A member at the cap gets one
   skipped_daily_cap row per trigger per day.

   ZERO MODEL CALLS. Nothing in a pass calls a model; a drafted task costs only
   when the member runs it, inside G9 to G11.

   deps (server.js passes the real ones; checks pass fakes):
     supabase, env, now() -> Date, isOwner(id), userPlan(id) -> { error, plan },
     planObservation(plan), spendCeiling(id, route, now) (throws a PLATFORM_*
     error to refuse), spendThisMonth(id, now) -> { usd } | { error },
     spendLimit() -> number | null, blogRef(id, slug), scoreFrom(rows, nowMs),
     record(id, action, target, observed, extra) -> Promise<boolean>,
     uuid() -> string, log(msg).
   ═══════════════════════════════════════════════════════════════════════════ */
"use strict";

var T = require("./triggers");
var gates = require("./gates");

var JOB_PREFIX = "hourly_triggers_h";
var PAGE = 1000;
var REF_CHUNK = 200;
var PREVIEW_MAX_ROWS = 20000;
var TRIGGER_ROW = "id, user_id, name, metric, metric_agent, comparator, threshold, metric_window, cooldown_hours, action, enabled, " +
  "last_value, last_checked_at, last_attempt_at, last_fired_at, created_at, updated_at";

function iso(ms) { return new Date(ms).toISOString(); }
function utcDay(now) { return now.toISOString().slice(0, 10); }
function jobName(now) {
  var h = now.getUTCHours();
  return JOB_PREFIX + (h < 10 ? "0" : "") + h;
}

/* Every row a query matches, in pages, checked against the exact count. */
async function readAll(build, what, max) {
  var rows = [];
  var total = null;
  for (var from = 0; ; from += PAGE) {
    var page = await build().range(from, from + PAGE - 1);
    if (page.error) throw new Error(what + ": " + (page.error.message || JSON.stringify(page.error)));
    if (total === null) total = page.count;
    rows = rows.concat(page.data || []);
    if (!page.data || page.data.length < PAGE) break;
    if (max && rows.length >= max) return { rows: rows, capped: true };
  }
  if (typeof total !== "number" || rows.length !== total) throw new Error(what + ": read " + rows.length + " rows but the exact count is " + JSON.stringify(total));
  return { rows: rows, capped: false };
}

async function headCount(q, what) {
  var r = await q;
  if (r.error) throw new Error(what + ": " + (r.error.message || JSON.stringify(r.error)));
  if (typeof r.count !== "number") throw new Error(what + ": the count did not come back");
  return r.count;
}

/* The refs of the member's own tracked posts (a post whose body carries its
   ?ref= token), as the Command Center reads them. */
async function memberRefs(deps, userId) {
  var posts = (await readAll(function () {
    return deps.supabase.from("content_library").select("id, slug, body", { count: "exact" })
      .eq("user_id", userId).not("slug", "is", null).order("id", { ascending: true });
  }, "your posts")).rows;
  return posts.map(function (p) { return { ref: deps.blogRef(userId, p.slug), body: String(p.body == null ? "" : p.body) }; })
    .filter(function (p) { return p.body.indexOf("?ref=" + p.ref) !== -1; })
    .map(function (p) { return p.ref; });
}

async function arrivalTimes(deps, userId, sinceMs, max) {
  var refs = await memberRefs(deps, userId);
  var times = [];
  var capped = false;
  for (var i = 0; i < refs.length; i += REF_CHUNK) {
    var chunk = refs.slice(i, i + REF_CHUNK);
    var got = await readAll(function () {
      return deps.supabase.from("engine_visits").select("id, created_at", { count: "exact" })
        .in("ref", chunk).gt("created_at", iso(sinceMs)).order("id", { ascending: true });
    }, "arrivals", max);
    if (got.capped) capped = true;
    got.rows.forEach(function (v) { times.push(Date.parse(v.created_at)); });
  }
  return { times: times, capped: capped };
}

async function failedTimes(deps, userId, sinceMs, max) {
  var got = await readAll(function () {
    return deps.supabase.from("ai_tasks").select("id, created_at", { count: "exact" })
      .eq("user_id", userId).eq("status", "failed").gt("created_at", iso(sinceMs)).order("id", { ascending: true });
  }, "failed runs", max);
  return { times: got.rows.map(function (r) { return Date.parse(r.created_at); }), capped: got.capped };
}

async function leadTimes(deps, sinceMs, max) {
  var got = await readAll(function () {
    return deps.supabase.from("bsky_leads").select("id, created_at", { count: "exact" })
      .gte("intent_score", T.LIMITS.LEAD_HIGH_INTENT).gt("created_at", iso(sinceMs)).order("id", { ascending: true });
  }, "high-intent leads", max);
  return { times: got.rows.map(function (r) { return Date.parse(r.created_at); }), capped: got.capped };
}

function countBetween(times, from, to) {
  var n = 0;
  times.forEach(function (t) { if (t > from && t <= to) n++; });
  return n;
}

/* One trigger's number now: { value, previous } where previous is the window
   before (for a drop), or value null when it cannot be judged (an owner-only
   metric for anyone else, no wallet, a cap that cannot be read, too few
   ratings). A read that fails throws. */
async function metricValue(deps, userId, t, nowMs) {
  var w = T.WINDOWS[t.window] ? T.WINDOWS[t.window].ms : 0;
  var db = deps.supabase;
  switch (t.metric) {
    case "stock_at_reorder": {
      var items = (await readAll(function () {
        return db.from("inventory_items").select("id, quantity_on_hand, reorder_point", { count: "exact" })
          .eq("user_id", userId).order("id", { ascending: true });
      }, "inventory items")).rows;
      var at = 0;
      items.forEach(function (it) {
        if (it.reorder_point === null || it.reorder_point === undefined || it.reorder_point === "") return;
        if (it.quantity_on_hand === null || it.quantity_on_hand === undefined || it.quantity_on_hand === "") return;
        var rp = Number(it.reorder_point), q = Number(it.quantity_on_hand);
        if (isFinite(rp) && isFinite(q) && q <= rp) at++;
      });
      return { value: at, previous: null };
    }
    case "blog_arrivals": {
      var a = await arrivalTimes(deps, userId, nowMs - 2 * w);
      return { value: countBetween(a.times, nowMs - w, nowMs), previous: countBetween(a.times, nowMs - 2 * w, nowMs - w) };
    }
    case "tasks_failed": {
      var n = await headCount(db.from("ai_tasks").select("id", { count: "exact", head: true })
        .eq("user_id", userId).eq("status", "failed").gt("created_at", iso(nowMs - w)), "failed runs");
      return { value: n, previous: null };
    }
    case "proposals_pending": {
      var q = db.from("agent_proposals").select("id", { count: "exact", head: true }).eq("user_id", userId).eq("status", "pending");
      if (w > 0) q = q.lte("created_at", iso(nowMs - w));
      return { value: await headCount(q, "pending proposals"), previous: null };
    }
    case "lead_scores": {
      if (!deps.isOwner(userId)) return { value: null, previous: null, reason: "owner_only" };
      var l = await leadTimes(deps, nowMs - 2 * w);
      return { value: countBetween(l.times, nowMs - w, nowMs), previous: countBetween(l.times, nowMs - 2 * w, nowMs - w) };
    }
    case "bfc_balance": {
      var wallet = await db.from("user_wallets").select("balance").eq("user_id", userId).maybeSingle();
      if (wallet.error) throw new Error("wallet: " + (wallet.error.message || JSON.stringify(wallet.error)));
      if (!wallet.data) return { value: null, previous: null, reason: "no_wallet" };
      var b = Number(wallet.data.balance);
      return { value: isFinite(b) ? b : null, previous: null };
    }
    case "schedule_failures": {
      var f = await headCount(db.from("agent_schedules").select("id", { count: "exact", head: true })
        .eq("user_id", userId).gte("consecutive_failures", 1), "schedules");
      return { value: f, previous: null };
    }
    case "spend_vs_cap": {
      var limit = deps.spendLimit();
      if (typeof limit !== "number" || !(limit > 0)) return { value: null, previous: null, reason: "cap_unreadable" };
      var spend = await deps.spendThisMonth(userId, new Date(nowMs));
      if (!spend || spend.error || typeof spend.usd !== "number") throw new Error("spend: " + ((spend && spend.error) || "unreadable"));
      return { value: Math.round(spend.usd / limit * 100), previous: null };
    }
    case "helpful_share": {
      var fb = await db.from("agent_feedback").select("rating, created_at, updated_at")
        .eq("user_id", userId).eq("agent_type", t.metric_agent);
      if (fb.error) throw new Error("ratings: " + (fb.error.message || JSON.stringify(fb.error)));
      var score = deps.scoreFrom(fb.data || [], nowMs);
      return { value: score && score.enough ? score.percent : null, previous: null, reason: score && score.enough ? null : "too_few_ratings" };
    }
    default:
      throw new Error("unknown metric " + JSON.stringify(t.metric));
  }
}

/* ── the preview: reads only ─────────────────────────────────────────────── */
async function preview(deps, userId, t, nowMs) {
  var m = T.METRICS[t.metric];
  var now = await metricValue(deps, userId, t, nowMs);
  var out = {
    summary: T.summarize(t),
    value_now: now.value,
    previous: now.previous,
    would_fire_now: T.crosses(t, now.value, now.previous) === true,
    days: T.LIMITS.PREVIEW_DAYS,
    replay: !!m.replay,
    fired_at: [],
    count: null,
    capped: false,
    note: null
  };
  if (now.value === null) out.note = "There is no number to judge right now.";
  if (!m.replay) {
    out.note = (out.note ? out.note + " " : "") + "Now only: there is no history of this number.";
    return out;
  }
  var w = T.WINDOWS[t.window].ms;
  var since = nowMs - T.LIMITS.PREVIEW_DAYS * 24 * 3600000 - 2 * w;
  var ev;
  if (t.metric === "blog_arrivals") ev = await arrivalTimes(deps, userId, since, PREVIEW_MAX_ROWS);
  else if (t.metric === "tasks_failed") ev = await failedTimes(deps, userId, since, PREVIEW_MAX_ROWS);
  else ev = deps.isOwner(userId) ? await leadTimes(deps, since, PREVIEW_MAX_ROWS) : { times: [], capped: false };
  out.fired_at = T.replay(t, ev.times, nowMs, T.LIMITS.PREVIEW_DAYS);
  out.count = out.fired_at.length;
  out.capped = ev.capped;
  return out;
}

/* ── the claim ────────────────────────────────────────────────────────── */
async function claimTriggerHour(db, now) {
  var name = jobName(now);
  var today = utcDay(now);
  var stamp = new Date().toISOString();
  var ins = await db.from("job_runs").insert({ job_name: name, last_run_on: today, started_at: stamp, finished_at: null, last_error: null }).select("job_name");
  if (!ins.error) return true;
  if (ins.error.code !== "23505") return false;
  var upd = await db.from("job_runs").update({ last_run_on: today, started_at: stamp, finished_at: null, last_error: null })
    .eq("job_name", name).or("last_run_on.is.null,last_run_on.neq." + today).select("job_name");
  if (upd.error) return false;
  return (upd.data || []).length > 0;
}

async function finishTriggerRun(db, now, errorMessage) {
  var patch = { finished_at: new Date().toISOString() };
  if (errorMessage) patch.last_error = String(errorMessage).slice(0, 2000);
  return db.from("job_runs").update(patch).eq("job_name", jobName(now));
}

/* ── acting ───────────────────────────────────────────────────────────── */
async function notify(db, userId, t, value) {
  var words = T.alertText(t, value);
  var made = await db.from("notifications").insert({ user_id: userId, type: "trigger", title: words.title, message: words.message, read: false }).select("id").single();
  if (made.error || !made.data) return null;
  return made.data.id;
}

async function act(deps, userId, t, value, now) {
  var db = deps.supabase;
  var a = t.action || {};
  if (a.kind === "raise_alert") {
    var id = await notify(db, userId, t, value);
    return id ? { ok: true, ref: "notification:" + id } : { ok: false, ref: null };
  }
  if (a.kind === "draft_task") {
    var name = T.draftName(t);
    var prompt = T.draftPrompt(t, value, now.toISOString());
    var made = await db.from("saved_prompts").insert({ user_id: userId, name: name, agent_type: a.agent, prompt: prompt }).select("id").single();
    if (made.error && made.error.code === "23505") {
      made = await db.from("saved_prompts").update({ agent_type: a.agent, prompt: prompt, updated_at: now.toISOString() })
        .eq("user_id", userId).eq("name", name).select("id").maybeSingle();
    }
    if (made.error || !made.data) return { ok: false, ref: null };
    return { ok: true, ref: "saved_prompt:" + made.data.id };
  }
  if (a.kind === "pause_schedule") {
    var paused = await db.from("agent_schedules").update({ paused: true, paused_reason: "trigger" })
      .eq("user_id", userId).eq("agent_type", a.agent).eq("paused", false).select("id");
    if (paused.error) return { ok: false, ref: null };
    var told = await notify(db, userId, t, value);
    return { ok: !!told, ref: "agent:" + a.agent };
  }
  return { ok: false, ref: null };
}

/* What G13 and G9 said for one member's firing. */
async function fireObservations(deps, userId, planned, now) {
  var observed = {};
  var p = planned;
  if (!p || p.error || !p.plan) observed.G13 = { result: "fail", code: "entitlement_unknown" };
  else if (p.plan.active !== true) observed.G13 = { result: "fail", code: "not_entitled" };
  else observed.G13 = deps.planObservation(p.plan);
  if (observed.G13.result === "fail") return observed;
  try {
    var ceiling = await deps.spendCeiling(userId, "trigger_fire", now);
    observed.G9 = ceiling && ceiling.owner ? { result: "bypass", code: "owner_pass" } : { result: "pass" };
  } catch (err) {
    var code = err && typeof err.code === "string" && err.code.indexOf("PLATFORM_") === 0 ? err.code : "gate_error";
    observed.G9 = { result: "fail", code: code };
  }
  return observed;
}

async function insertFiring(db, row) {
  var w = await db.from("trigger_firings").insert(row);
  return !(w && w.error);
}

/* The pass over every enabled trigger. Returns a summary; never throws for one
   member's trouble. */
async function runTriggerPass(deps, now) {
  var db = deps.supabase;
  var nowMs = now.getTime();
  var cap = T.dailyFiringsCap(deps.env);
  var dayStart = utcDay(now) + "T00:00:00.000Z";
  var summary = { members: 0, triggers: 0, fired: 0, action_failed: 0, blocked: 0, capped: 0, unreadable: 0, failures: 0, first_failure: null };
  function fail(what) { summary.failures++; if (!summary.first_failure) summary.first_failure = what; deps.log("[Triggers] " + what); }

  var all = (await readAll(function () {
    return db.from("member_triggers").select(TRIGGER_ROW, { count: "exact" }).eq("enabled", true).order("id", { ascending: true });
  }, "enabled triggers")).rows;
  var byUser = {};
  var order = [];
  all.forEach(function (r) {
    if (!byUser[r.user_id]) { byUser[r.user_id] = []; order.push(r.user_id); }
    byUser[r.user_id].push(r);
  });

  for (var u = 0; u < order.length; u++) {
    var userId = order[u];
    summary.members++;
    var today;
    try {
      today = (await readAll(function () {
        return db.from("trigger_firings").select("id, trigger_id, outcome", { count: "exact" })
          .eq("user_id", userId).gte("fired_at", dayStart).order("id", { ascending: true });
      }, "today's firings")).rows;
    } catch (e) {
      fail("member " + userId + ": today's firings could not be read, so no trigger of theirs ran this hour: " + e.message);
      continue;
    }
    var firedToday = today.filter(function (f) { return f.outcome === "fired" || f.outcome === "action_failed"; }).length;
    var capSkipped = {};
    today.forEach(function (f) { if (f.outcome === "skipped_daily_cap") capSkipped[f.trigger_id] = true; });
    var planned;

    var rows = byUser[userId];
    for (var i = 0; i < rows.length; i++) {
      var t = T.fromRow(rows[i]);
      summary.triggers++;
      var v;
      try {
        v = await metricValue(deps, userId, t, nowMs);
      } catch (e) {
        summary.unreadable++;
        deps.log("[Triggers] trigger " + t.id + ": its number could not be read: " + e.message);
        continue;
      }
      await db.from("member_triggers").update({ last_value: v.value, last_checked_at: now.toISOString() }).eq("id", t.id).eq("user_id", userId);

      var step = T.plan(t, v.value, v.previous, nowMs, firedToday, cap);
      if (step === "quiet" || step === "cooldown") continue;
      if (step === "daily_cap") {
        if (!capSkipped[t.id]) {
          capSkipped[t.id] = true;
          summary.capped++;
          await insertFiring(db, { id: deps.uuid(), user_id: userId, trigger_id: t.id, metric_value: v.value, threshold: t.threshold,
            fired_at: now.toISOString(), outcome: "skipped_daily_cap", action_ref: null, gate_decision_id: null });
        }
        continue;
      }

      if (planned === undefined) {
        try { planned = await deps.userPlan(userId); } catch (e) { planned = { error: e }; }
      }
      var observed = await fireObservations(deps, userId, planned, now);
      var decision = gates.evaluate("trigger_fire", { observed: observed });
      var decisionId = deps.uuid();
      var facts = { action_type: t.action.kind, channel: "agent" };
      if (t.action.agent) facts.agent = t.action.agent;
      var written = await deps.record(userId, "trigger_fire", "trigger:" + t.id, observed, { id: decisionId, facts: facts });
      var gateDecisionId = written ? decisionId : null;

      var outcome, ref = null;
      if (decision.outcome !== "ran") {
        outcome = "blocked_by_gate";
        summary.blocked++;
      } else {
        var done;
        try { done = await act(deps, userId, t, v.value, now); } catch (e) { done = { ok: false, ref: null }; }
        outcome = done.ok ? "fired" : "action_failed";
        ref = done.ref;
        firedToday++;
        if (done.ok) summary.fired++; else summary.action_failed++;
      }
      var firingOk = await insertFiring(db, { id: deps.uuid(), user_id: userId, trigger_id: t.id, metric_value: v.value, threshold: t.threshold,
        fired_at: now.toISOString(), outcome: outcome, action_ref: ref, gate_decision_id: gateDecisionId });
      if (!firingOk) fail("trigger " + t.id + ": the firing row was not written (" + outcome + ")");
      var patch = { last_attempt_at: now.toISOString() };
      if (outcome === "fired") patch.last_fired_at = now.toISOString();
      await db.from("member_triggers").update(patch).eq("id", t.id).eq("user_id", userId);
    }
  }
  return summary;
}

var running = false;

/* The hourly tick. Off unless ENABLE_TRIGGERS is exactly "true". */
async function triggerTick(deps) {
  if (!T.triggersEnabled(deps.env)) return { ran: false, reason: "disabled" };
  if (running) return { ran: false, reason: "running" };
  running = true;
  var now = deps.now();
  try {
    var claimed = await claimTriggerHour(deps.supabase, now);
    if (!claimed) {
      deps.log("[Triggers] Tick skipped: " + jobName(now) + " already claimed for " + utcDay(now));
      return { ran: false, reason: "claimed" };
    }
    try {
      var summary = await runTriggerPass(deps, now);
      await finishTriggerRun(deps.supabase, now, summary.failures ? summary.failures + " failure(s); first: " + summary.first_failure : null);
      return { ran: true, summary: summary };
    } catch (passErr) {
      var msg = (passErr && passErr.message) || String(passErr);
      deps.log("[Triggers] Pass error: " + msg);
      await finishTriggerRun(deps.supabase, now, msg);
      return { ran: true, error: msg };
    }
  } catch (err) {
    deps.log("[Triggers] Tick error: " + ((err && err.message) || err));
    return { ran: false, reason: "error" };
  } finally {
    running = false;
  }
}

module.exports = {
  JOB_PREFIX: JOB_PREFIX,
  TRIGGER_ROW: TRIGGER_ROW,
  jobName: jobName,
  metricValue: metricValue,
  preview: preview,
  claimTriggerHour: claimTriggerHour,
  runTriggerPass: runTriggerPass,
  triggerTick: triggerTick,
  act: act
};
