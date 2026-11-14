/* ══════════════════════════════════════════════════════════════════════════
   lib/jobSchedules.js — THE ONE LIST OF WHEN THE SERVER'S BACKGROUND JOBS RUN
   (Nov 10 2026, dashboard tabs).

   Every cron.schedule(...) and tracked setInterval(...) that server.js declares
   is listed here once: what it calls (tick, a text that appears at the top of
   its callback), its timing (cron or every_ms), and the job_runs rows it writes
   (jobs: exact names; prefix: a family of rows named prefix + "00" … "23", one
   per UTC hour). server.js keeps its own literals, which a dozen checks pin;
   scripts/checkCommandCenter.js holds this list and those declarations equal,
   call for call, so neither can change without the other.

   GET /api/command-center (admin only, platform) reads this for each job_runs
   row's expected cadence and whether it ran on time.

   ON TIME. A job_runs row is on time when ALL hold:
     - its name is declared here (otherwise on_time is null: no schedule known);
     - finished_at is set (a claimed run that has not finished, or never ran,
       is not on time);
     - last_error is null. Every claim writes last_error null and every finish
       writes the run's own error or null, so a row's last_error is always its
       newest run's: an error there is newer than any success;
     - now - finished_at <= the row's interval + the grace:
         every N minutes   N minutes      + 15 minutes
         hourly            60 minutes     + 15 minutes
         hourly, per hour  24 hours       + 15 minutes  (a prefix row such as
                           hourly_triggers_h05 is claimed once a day, at its hour)
         daily             24 hours       + 2 hours
   Reads only; nothing here writes.
   ══════════════════════════════════════════════════════════════════════════ */
"use strict";

var GRACE_MS = { minutes: 15 * 60000, hourly: 15 * 60000, daily: 2 * 3600000 };

var SCHEDULES = [
  { tick: "storeProposalTick(", cron: "0 6 * * *", jobs: ["daily_store_proposals"] },
  { tick: "selfReviewTick(", cron: "0 7 * * *", jobs: ["daily_self_reviews"] },
  { tick: "agentScheduleTick(", cron: "0 * * * *", prefix: "hourly_agent_schedules_h" },
  { tick: "emailSequenceTick(", cron: "0 * * * *", prefix: "hourly_email_sequences_h" },
  { tick: "youtubeRetentionTick(", cron: "0 9 * * *", jobs: ["daily_youtube_retention"] },
  { tick: "opsAlerts.scanTick(", cron: "*/30 * * * *", jobs: ["ops_alert_scan"] },
  { tick: "pendingStorageDeletionTick(", cron: "15 4 * * *", jobs: ["pending_storage_deletions"] },
  { tick: "gateDecisionsSweepTick(", cron: "30 4 * * *", jobs: ["gate_decisions_sweep"] },
  { tick: "cardLeadsPurgeTick(", cron: "45 4 * * *",
    jobs: ["card_leads_purge", "oauth_states_purge", "shopify_webhook_events_purge", "member_videos_retention",
      "instagram_token_refresh", "facebook_choosing_purge",
      // Nov 14 2026, L1: YouTube's daily data check, then the yearly renewal reminder and the terms-change email.
      "youtube_data_check", "renewal_yearly_reminder", "terms_change_email"] },
  { tick: "schemaCheckTick(", cron: "0 6 * * *", jobs: ["schema_check"] },
  { tick: "storeSyncTick(", cron: "0 5 * * *", jobs: ["store_sync"] },
  { tick: "triggerTickNow(", cron: "30 * * * *", prefix: "hourly_triggers_h" },
  // BACKUP_CRON may move it; the default is server.js's own.
  { tick: "runNightlyBackup(", cron: "0 8 * * *", cron_env: "BACKUP_CRON", jobs: ["nightly_backup"] },
  // Intervals that write no job_runs row: listed so the list is the whole schedule.
  { tick: "dripTick", every_ms: 300000, jobs: [] },
  { tick: "reminderTick", every_ms: 60000, jobs: [] },
  { tick: "salesAutoConvertTick", every_ms: 300000, jobs: [] }
];

/* The cadence a cron expression states: { kind: "minutes", n } | { kind: "hourly" } | { kind: "daily" } | null. */
function cadenceOfCron(expr) {
  var f = String(expr || "").trim().split(/\s+/);
  if (f.length !== 5) return null;
  var rest = f[2] === "*" && f[3] === "*" && f[4] === "*";
  if (!rest) return null;
  var every = /^\*\/(\d+)$/.exec(f[0]);
  if (every && f[1] === "*") return { kind: "minutes", n: Number(every[1]) };
  if (/^\d+$/.test(f[0]) && f[1] === "*") return { kind: "hourly" };
  if (/^\d+$/.test(f[0]) && /^\d+$/.test(f[1])) return { kind: "daily" };
  return null;
}

function cronOf(entry, env) {
  var e = env || {};
  if (entry.cron_env && typeof e[entry.cron_env] === "string" && e[entry.cron_env].trim() !== "") return e[entry.cron_env].trim();
  return entry.cron;
}

/* The schedule a job_runs row belongs to, and whether it is one hour's row of a family. */
function scheduleOf(jobName) {
  var name = String(jobName || "");
  for (var i = 0; i < SCHEDULES.length; i++) {
    var s = SCHEDULES[i];
    if (s.jobs && s.jobs.indexOf(name) !== -1) return { entry: s, perHour: false };
    if (s.prefix && name.indexOf(s.prefix) === 0 && /^(?:[01]\d|2[0-3])$/.test(name.slice(s.prefix.length))) return { entry: s, perHour: true };
  }
  return null;
}

function cadenceWords(c) {
  if (!c) return null;
  if (c.kind === "minutes") return "every " + c.n + " minutes";
  return c.kind;
}

/* "hourly", "daily", "every N minutes", or null when the row's name is declared nowhere. */
function jobCadence(jobName, env) {
  var at = scheduleOf(jobName);
  if (!at || !at.entry.cron) return null;
  return cadenceWords(cadenceOfCron(cronOf(at.entry, env)));
}

/* The longest a row may go between finishes and still be on time, grace included. */
function allowedGapMs(jobName, env) {
  var at = scheduleOf(jobName);
  if (!at || !at.entry.cron) return null;
  var c = cadenceOfCron(cronOf(at.entry, env));
  if (!c) return null;
  if (c.kind === "minutes") return c.n * 60000 + GRACE_MS.minutes;
  if (c.kind === "hourly") return (at.perHour ? 24 * 3600000 : 3600000) + GRACE_MS.hourly;
  return 24 * 3600000 + GRACE_MS.daily;
}

/* { job_name, cadence, on_time: true | false | null, reason } for one job_runs row. */
function jobOnTime(row, now, env) {
  var name = row && row.job_name;
  var cadence = jobCadence(name, env);
  var gap = allowedGapMs(name, env);
  var out = { job_name: name, cadence: cadence, on_time: null, reason: null };
  if (gap === null) { out.reason = "no schedule is declared for this job"; return out; }
  if (!row.finished_at) { out.on_time = false; out.reason = "the last run has not finished"; return out; }
  if (row.last_error) { out.on_time = false; out.reason = "the last run failed"; return out; }
  var finished = new Date(row.finished_at).getTime();
  var at = now instanceof Date ? now.getTime() : Number(now);
  if (isNaN(finished)) { out.on_time = false; out.reason = "the finish time is not a date"; return out; }
  if (at - finished > gap) { out.on_time = false; out.reason = "late: it has not finished within its " + cadence + " schedule"; return out; }
  out.on_time = true;
  return out;
}

/* { job_name: cadence } for the rows given. */
function jobCadences(rows, env) {
  var out = {};
  (rows || []).forEach(function (r) { if (r && r.job_name) out[r.job_name] = jobCadence(r.job_name, env); });
  return out;
}

module.exports = {
  SCHEDULES: SCHEDULES,
  GRACE_MS: GRACE_MS,
  cadenceOfCron: cadenceOfCron,
  scheduleOf: scheduleOf,
  jobCadence: jobCadence,
  allowedGapMs: allowedGapMs,
  jobOnTime: jobOnTime,
  jobCadences: jobCadences
};
