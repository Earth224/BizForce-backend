"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   lib/agentLive.js — what each of the 18 agents is doing, from the member's
   own rows and nothing else. Pure: server.js does the reads (agentLiveBody)
   and hands them here with the functions it already trusts — the schedule
   runner's agentScheduleIsDue and the ledger's modelCallCostUsd — so the
   "next run" and the spend this says are the runner's and the ledger's own
   rules, not a second copy that could drift.

   NOW. "running" only while an ai_tasks row is 'processing' and less than
   STALL_AFTER_MIN minutes old. Nothing sweeps a run whose process died, so an
   older 'processing' row is "stalled", never "running". 'dry_run' (Sales's
   outreach rehearsals) is never activity, here or in the counts.

   NEXT. Hourly slots replayed forward from the next hour, up to 32 days,
   through agentScheduleIsDue. null, with the reason, when there is no
   schedule, it is switched off or paused, the scheduler is off
   (ENABLE_AGENT_SCHEDULES not exactly "true"), autonomy is off for the agent
   (the runner skips it), or the subscription is inactive or unknown.

   A READ THAT FAILED IS { unavailable: reason }, NEVER ZERO. Each section
   stands alone, the GET /api/command-center pattern: one failed table fails
   its own field on every agent and nothing else.
   ══════════════════════════════════════════════════════════════════════════ */

var brain = require("../config/brain");

var STALL_AFTER_MIN = 10;
var NEXT_HORIZON_HOURS = 32 * 24;
var HOUR_MS = 3600000;
var LIST_CAP = 5;
var PAYLOAD_BUDGET_ONE = 3 * 1024;
var PAYLOAD_BUDGET_ALL = 24 * 1024;

/* The 18 agents with pages, from the one roster (config/brain.js
   PLATFORM_KNOWLEDGE.agents, which AGENT_DESCRIPTIONS is built from). The
   general agent has no page and no panel. */
var AGENT_KEYS = Object.freeze(brain.PLATFORM_KNOWLEDGE.agents
  .map(function (a) { return a.key; })
  .filter(function (k) { return k !== "general" && brain.agentDescription(k) !== ""; }));
var AGENT_NAMES = Object.freeze(brain.PLATFORM_KNOWLEDGE.agents.reduce(function (out, a) {
  out[a.key] = a.name;
  return out;
}, {}));

function cut(text, max) {
  var s = String(text == null ? "" : text).replace(/\s+/g, " ").trim();
  return s.length > max ? s.slice(0, max - 1) + "…" : s;
}

function unavailable(read) {
  return !read || read.unavailable !== undefined || !Array.isArray(read.rows);
}

function unavailableOf(read) {
  return { unavailable: (read && read.unavailable) || "not read" };
}

function rowsFor(read, type) {
  return read.rows.filter(function (r) { return r && r.agent_type === type && r.status !== "dry_run"; });
}

function newestFirst(a, b) {
  return Date.parse(b.created_at) - Date.parse(a.created_at);
}

/* running · stalled · idle, from this agent's 'processing' rows. */
function nowState(rows, nowMs) {
  var open = rows.filter(function (r) { return r.status === "processing"; }).sort(newestFirst);
  if (!open.length) return { state: "idle" };
  var fresh = open.filter(function (r) { return nowMs - Date.parse(r.created_at) < STALL_AFTER_MIN * 60000; });
  var row = fresh.length ? fresh[0] : open[0];
  return { state: fresh.length ? "running" : "stalled", task_id: row.id, task_type: row.task_type || null, since: row.created_at };
}

function lastRun(row) {
  if (!row) return null;
  return {
    task_id: row.id,
    task_type: row.task_type || null,
    status: row.status,
    started_at: row.created_at,
    finished_at: row.completed_at || null,
    error_short: row.error ? cut(row.error, 120) : null
  };
}

function scheduleCard(row) {
  if (!row) return null;
  return {
    cadence: row.cadence,
    hour_utc: row.hour_utc,
    enabled: row.enabled === true,
    paused: row.paused === true,
    paused_reason: row.paused_reason ? cut(row.paused_reason, 120) : null,
    last_run_status: row.last_run_status || null,
    consecutive_failures: typeof row.consecutive_failures === "number" ? row.consecutive_failures : 0
  };
}

/* The first hourly slot after `now` that the runner's own rule calls due. */
function nextSlot(row, now, isDue) {
  var start = Math.floor(now.getTime() / HOUR_MS) * HOUR_MS + HOUR_MS;
  for (var i = 0; i < NEXT_HORIZON_HOURS; i++) {
    var slot = new Date(start + i * HOUR_MS);
    if (isDue(row, slot)) return slot;
  }
  return null;
}

/* { next, reason }: next is { at, cadence, task_type } or null with the reason. */
function nextRun(row, opts) {
  if (!row) return { next: null, reason: "no_schedule" };
  if (row.enabled !== true) return { next: null, reason: "disabled" };
  if (row.paused === true) return { next: null, reason: "paused" };
  if (opts.schedulerOn !== true) return { next: null, reason: "scheduler_off" };
  if (opts.autonomy && opts.autonomy.unavailable !== undefined) return { next: { unavailable: "autonomy: " + opts.autonomy.unavailable }, reason: null };
  if (opts.autonomy !== true) return { next: null, reason: "autonomy_off" };
  if (opts.subscriptionActive === false) return { next: null, reason: "subscription_inactive" };
  if (opts.subscriptionActive !== true) return { next: null, reason: "subscription_unknown" };
  var slot = nextSlot(row, opts.now, opts.isDue);
  if (!slot) return { next: null, reason: "no_slot_in_32_days" };
  return { next: { at: slot.toISOString(), cadence: row.cadence, task_type: row.task_type || null }, reason: null };
}

/* The calendar's "Agent runs" layer (calendar.html, GET /api/agents/live/calendar):
   every slot between opts.from and opts.to (exclusive), and none before now,
   found by nextSlot — the same walk "next" makes through the runner's own
   isDue — after the same gates nextRun applies, so the calendar and the panel
   cannot disagree. { runs: [iso…], reason } with reason null when any run falls. */
var CALENDAR_SPAN_DAYS = 62;
function runsBetween(row, opts) {
  var cursor = new Date(Math.max(opts.from.getTime(), opts.now.getTime()) - 1);
  var gate = nextRun(row, { now: cursor, isDue: opts.isDue, schedulerOn: opts.schedulerOn, autonomy: opts.autonomy, subscriptionActive: opts.subscriptionActive });
  if (gate.next && gate.next.unavailable !== undefined) return { runs: [], unavailable: gate.next.unavailable };
  if (!gate.next && gate.reason !== "no_slot_in_32_days") return { runs: [], reason: gate.reason };
  var runs = [];
  var slot = nextSlot(row, cursor, opts.isDue);
  while (slot && slot.getTime() < opts.to.getTime()) {
    runs.push(slot.toISOString());
    slot = nextSlot(row, slot, opts.isDue);
  }
  return { runs: runs, reason: runs.length ? null : "no_run_in_range" };
}

function buildAgent(type, reads, opts) {
  var nowMs = opts.now.getTime();
  var out = { type: type, name: AGENT_NAMES[type] || type };

  out.now = unavailable(reads.processing) ? unavailableOf(reads.processing) : nowState(rowsFor(reads.processing, type), nowMs);

  if (unavailable(reads.recent) || unavailable(reads.last)) {
    out.runs = unavailableOf(unavailable(reads.recent) ? reads.recent : reads.last);
  } else {
    var recent = rowsFor(reads.recent, type);
    var last = rowsFor(reads.last, type).concat(recent).sort(newestFirst)[0];
    out.runs = {
      last: lastRun(last),
      runs_7d: recent.length,
      completed_7d: recent.filter(function (r) { return r.status === "completed"; }).length,
      failed_7d: recent.filter(function (r) { return r.status === "failed"; }).length
    };
    /* ONE STATS TRUTH. An agent page's Agent Stats and its weekday chart read
       these, never ai_agents.tasks_completed (which counts approved proposals
       only) and never a 50-row page of ai_tasks with dry runs in it. Bucket 0
       is the last 24 hours, bucket 6 the oldest; together they are runs_7d. */
    if (!opts.compact) {
      var byDay = [0, 0, 0, 0, 0, 0, 0];
      recent.forEach(function (r) {
        // A row read at the window's very edge is still in it: the oldest bucket.
        var ago = Math.min(6, Math.max(0, Math.floor((nowMs - Date.parse(r.created_at)) / 86400000)));
        if (!isNaN(ago)) byDay[ago] += 1;
      });
      out.runs.days_ago_7d = byDay;
    }
  }

  var autonomy;
  if (unavailable(reads.autonomy)) autonomy = unavailableOf(reads.autonomy);
  else {
    // A missing row is consent never given: false (migration 064).
    var a = reads.autonomy.rows.filter(function (r) { return r.agent_type === type; })[0];
    autonomy = !!(a && a.enabled === true);
  }
  out.autonomy = autonomy;

  if (unavailable(reads.schedules)) {
    out.schedule = unavailableOf(reads.schedules);
    out.next = unavailableOf(reads.schedules);
    out.next_reason = null;
  } else {
    var row = reads.schedules.rows.filter(function (r) { return r.agent_type === type; })[0] || null;
    out.schedule = scheduleCard(row);
    var n = nextRun(row, { now: opts.now, isDue: opts.isDue, schedulerOn: opts.schedulerOn, autonomy: autonomy, subscriptionActive: opts.subscriptionActive });
    out.next = n.next;
    out.next_reason = n.reason;
  }

  if (unavailable(reads.proposals)) out.proposals = unavailableOf(reads.proposals);
  else {
    var pending = reads.proposals.rows.filter(function (r) { return r.agent_type === type; }).sort(newestFirst);
    out.proposals = {
      pending: pending.length,
      newest: pending.slice(0, LIST_CAP).map(function (p) {
        return opts.compact
          ? { title: cut(p.title, 60), created_at: p.created_at }
          : { id: p.id, title: cut(p.title, 120), created_at: p.created_at };
      })
    };
  }

  if (unavailable(reads.feedback)) out.score = unavailableOf(reads.feedback);
  else {
    var fb = reads.feedback.rows.filter(function (r) { return r.agent_type === type; });
    out.score = {
      up: fb.filter(function (r) { return r.rating === "up"; }).length,
      down: fb.filter(function (r) { return r.rating === "down"; }).length,
      pinned: fb.filter(function (r) { return r.pinned === true; }).length
    };
  }

  if (unavailable(reads.spend)) out.spend_month_usd = unavailableOf(reads.spend);
  else {
    // The commandCenterSpend rule: every platform-funded row, priced; a row the
    // member's own key paid for is not counted.
    var usd = 0;
    reads.spend.rows.forEach(function (r) {
      if (r.agent_type !== type || r.funded_by === "user") return;
      usd += opts.costOf(r).usd;
    });
    out.spend_month_usd = Number(usd.toFixed(4));
  }

  // The slot the signature module fills (Blocks 2a and 2b). Nothing yet.
  out.signature = null;
  return out;
}

/* The whole answer. opts: { types, now, isDue, costOf, schedulerOn,
   subscriptionActive (true | false | null), dailyCalls ({ used, limit } or
   { unavailable }), reads }. One type → { agent }, several → { agents }. */
function buildLive(opts) {
  var types = opts.types;
  var one = types.length === 1;
  var shared = {
    now: opts.now, isDue: opts.isDue, costOf: opts.costOf, schedulerOn: opts.schedulerOn === true,
    subscriptionActive: opts.subscriptionActive === true ? true : (opts.subscriptionActive === false ? false : null),
    compact: !one
  };
  var body = {
    generated_at: opts.now.toISOString(),
    stall_after_min: STALL_AFTER_MIN,
    scheduler_on: shared.schedulerOn,
    subscription_active: shared.subscriptionActive,
    daily_calls: opts.dailyCalls
  };
  if (one) {
    body.agent = buildAgent(types[0], opts.reads, shared);
    return body;
  }
  body.agents = {};
  types.forEach(function (t) { body.agents[t] = buildAgent(t, opts.reads, shared); });
  /* The budget. Titles are the only free text that grows with the account;
     over budget, the five newest are dropped (the count stays), and the
     answer says so rather than shrinking silently. */
  if (JSON.stringify(body).length > PAYLOAD_BUDGET_ALL) {
    types.forEach(function (t) {
      var p = body.agents[t].proposals;
      if (p && Array.isArray(p.newest)) { p.newest = []; p.newest_omitted = "payload budget"; }
    });
  }
  return body;
}

module.exports = {
  AGENT_KEYS: AGENT_KEYS,
  AGENT_NAMES: AGENT_NAMES,
  STALL_AFTER_MIN: STALL_AFTER_MIN,
  NEXT_HORIZON_HOURS: NEXT_HORIZON_HOURS,
  LIST_CAP: LIST_CAP,
  PAYLOAD_BUDGET_ONE: PAYLOAD_BUDGET_ONE,
  PAYLOAD_BUDGET_ALL: PAYLOAD_BUDGET_ALL,
  nowState: nowState,
  nextSlot: nextSlot,
  nextRun: nextRun,
  CALENDAR_SPAN_DAYS: CALENDAR_SPAN_DAYS,
  runsBetween: runsBetween,
  buildAgent: buildAgent,
  buildLive: buildLive
};
