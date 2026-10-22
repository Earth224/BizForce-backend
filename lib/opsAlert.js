// lib/opsAlert.js — failures reach the owner, by email, instead of only the logs.
//
// WHAT RAISES AN ALERT (launch audit #6). Four triggers, each with its own key:
//
//   job:<job_name>     a job_runs row whose last_error is set, or has changed
//                      since the last alert. Read by scanOps, which server.js
//                      runs from a cron every 30 minutes (UTC) under its own
//                      job_runs claim, never at boot. Cleared when the row's
//                      last_error is empty AND the run has finished, so a pass
//                      that is still running is not reported as fixed.
//   stripe_webhook     the Stripe webhook handler threw while processing an
//                      event. A SIGNATURE failure is NOT an alert: those are
//                      forged or misrouted requests, not breakage, and alerting
//                      on them would let anyone on the internet fill the
//                      owner's inbox. They are counted (signatureFailures).
//   backup_failed      the nightly backup ran and did not send, or sent with a
//                      table missing or partial (lib/backup.js: complete
//                      false). A missing or malformed BACKUP_ENCRYPTION_KEY
//                      is this alert too, worded "Backup not encrypted".
//   backup_stale       ENABLE_NIGHTLY_BACKUP is "true" and no backup has
//                      succeeded in the last 30 hours (job_runs.nightly_backup
//                      finished_at, which server.js writes on success only).
//   health_db          /health's database probe failed 3 times in a row in
//                      this process. Cleared by the next probe that answers.
//
// DEDUPE. A key is emailed at most once per 6 hours for the same error. A
// changed error on an open key sends at once: it is news. When a key clears,
// one "resolved" email goes out and the key is closed. Open keys are kept in
// public.ops_alerts (migration 140) so a deploy neither re-sends everything
// nor forgets to say "resolved". Until that table exists, the state is held in
// this process only, and that is logged once.
//
// THE GATE. ENABLE_OPS_ALERTS is ON BY DEFAULT: only the exact string "false"
// turns it off. Every other gate in this codebase is opt-in because each one
// starts work that spends money or writes data. This one is the opposite: it
// is how anyone learns that something else stopped. An alerting system that is
// off until somebody remembers to turn it on is off on the day it is needed,
// and "true", "1", "yes", a typo and an unset variable all leave it on.
//
// NEVER THROWS INTO ITS CALLER. Every public function catches everything and
// logs it. An alert is raised from inside a webhook, a health check and a
// cron; a failure to email must never become a failure of the thing it was
// reporting on.
//
// ITS OWN RESEND CLIENT, like lib/backup.js and for the same reason: sendEmail
// in server.js attaches List-Unsubscribe headers and requires a consent row,
// and a mailbox that auto-clicked an unsubscribe link would silently switch
// the alerts off. Same API key, same sending address, so still one identity.

const { Resend } = require("resend");

const FROM_EMAIL = "BizForce AI <hello@mail.bizforceai.net>";
const DEDUPE_MS = 6 * 60 * 60 * 1000;
const ERROR_MAX_CHARS = 500;
const HEALTH_FAILS_TO_ALERT = 3;
const HEALTH_TIMEOUT_MS = 2000;
// Probe results are reused for this long, and concurrent requests share one
// probe, so /health can be hammered without hammering the database.
const HEALTH_CACHE_MS = 10000;
const BACKUP_STALE_MS = 30 * 60 * 60 * 1000;
const BACKUP_JOB_NAME = "nightly_backup";
const SCAN_JOB_NAME = "ops_alert_scan";
const TABLE = "ops_alerts";
// Retry reading ops_alerts at most this often while it is unreadable.
const HYDRATE_RETRY_MS = 10 * 60 * 1000;
const PACIFIC = "America/Los_Angeles";
const TAG = "[OpsAlert]";

const RAILWAY_LOGS = "Railway: the BizForce backend service > Deployments > View logs";

function opsAlertsEnabled(env) {
  return (env || {}).ENABLE_OPS_ALERTS !== "false";
}

function opsAlertRecipient(env) {
  var e = env || {};
  return String(e.OPS_ALERT_EMAIL || "").trim() || String(e.BACKUP_EMAIL_TO || "").trim() || null;
}

function errorText(error) {
  var text;
  if (error && typeof error === "object" && error.message) text = String(error.message);
  else text = String(error == null ? "unknown error" : error);
  return text.length > ERROR_MAX_CHARS ? text.slice(0, ERROR_MAX_CHARS) : text;
}

function utcStamp(ms) {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d{3}Z$/, " UTC");
}

function pacificStamp(ms) {
  try {
    return new Intl.DateTimeFormat("en-US", {
      timeZone: PACIFIC, year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23", timeZoneName: "short"
    }).format(new Date(ms));
  } catch (err) {
    return "Pacific time unavailable (" + errorText(err) + ")";
  }
}

function whenLine(ms) {
  return utcStamp(ms) + " (" + pacificStamp(ms) + ")";
}

/* The email, as plain text. Exported so the check reads the real format. */
function alertEmail(kind, alert, nowMs) {
  var lines;
  var subject;
  if (kind === "resolved") {
    subject = "[BizForce RESOLVED] " + alert.what;
    lines = [
      "Resolved: " + alert.what,
      "Alert key: " + alert.key,
      "Opened: " + whenLine(Date.parse(alert.opened_at)),
      "Resolved: " + whenLine(nowMs),
      "",
      "The last error was (first " + ERROR_MAX_CHARS + " characters):",
      alert.error || "(none recorded)"
    ];
  } else {
    subject = "[BizForce ALERT] " + alert.what;
    lines = [
      "What broke: " + alert.what,
      "Alert key: " + alert.key,
      "When: " + whenLine(nowMs),
      "Open since: " + whenLine(Date.parse(alert.opened_at)),
      "",
      "Error (first " + ERROR_MAX_CHARS + " characters):",
      alert.error,
      "",
      "Where to look:",
      "- " + RAILWAY_LOGS + (alert.log_tag ? "; search for " + alert.log_tag : ""),
      "- Supabase: " + (alert.where || "the project dashboard > Logs"),
      "",
      "This key is emailed at most once every 6 hours while the error stays the same, " +
        "and once more when it clears."
    ];
  }
  return { subject: subject, text: lines.join("\n") };
}

async function resendSend(message, env) {
  var apiKey = String((env || {}).RESEND_API_KEY || "").trim();
  if (!apiKey) return { ok: false, error: "RESEND_API_KEY is not set" };
  var result = await new Resend(apiKey).emails.send(message);
  // The SDK reports a rejection on the result rather than throwing (see
  // lib/backup.js), so the result is read, not assumed.
  if (result && result.error) return { ok: false, error: errorText(result.error) };
  if (!result || !result.data || !result.data.id) return { ok: false, error: "the provider returned no message id" };
  return { ok: true, id: result.data.id };
}

function createOpsAlerts(options) {
  var opts = options || {};
  var supabase = opts.supabase;
  var env = opts.env || process.env;
  var now = opts.now || function () { return Date.now(); };
  var send = opts.send || resendSend;
  var log = opts.log || console;
  var bootMs = now();

  var open = new Map();
  var hydrated = false;
  var lastHydrateAttempt = null;
  var loggedOnce = new Set();
  var signatureFailures = 0;
  var healthFails = 0;
  var probeInFlight = null;
  var probeCached = null;
  // The alert work the last probe started, so a check can wait for it.
  var lastAlertWork = Promise.resolve();

  function once(key, message) {
    if (loggedOnce.has(key)) return;
    loggedOnce.add(key);
    log.error(TAG + " " + message);
  }

  /* Loads open keys from ops_alerts. Entries this process already holds win:
     they are newer than anything a previous process wrote. */
  async function hydrate() {
    if (hydrated) return true;
    if (lastHydrateAttempt !== null && now() - lastHydrateAttempt < HYDRATE_RETRY_MS) return false;
    lastHydrateAttempt = now();
    try {
      var result = await supabase
        .from(TABLE)
        .select("alert_key, what, fingerprint, error, where_to_look, log_tag, opened_at, last_sent_at");
      if (result.error) throw result.error;
      (result.data || []).forEach(function (row) {
        if (open.has(row.alert_key)) return;
        open.set(row.alert_key, {
          key: row.alert_key, what: row.what, fingerprint: row.fingerprint, error: row.error,
          where: row.where_to_look, log_tag: row.log_tag, opened_at: row.opened_at, last_sent_at: row.last_sent_at
        });
      });
      hydrated = true;
      return true;
    } catch (err) {
      once("hydrate", "public." + TABLE + " could not be read (" + errorText(err) + "). Alerts still send, " +
        "but which keys are open is held in this process only until migration 140 is applied: a deploy " +
        "may re-send an open alert once and will not send its \"resolved\".");
      return false;
    }
  }

  async function persist(alert) {
    try {
      var result = await supabase.from(TABLE).upsert({
        alert_key: alert.key, what: alert.what, fingerprint: alert.fingerprint, error: alert.error,
        where_to_look: alert.where || null, log_tag: alert.log_tag || null,
        opened_at: alert.opened_at, last_sent_at: alert.last_sent_at
      }, { onConflict: "alert_key" });
      if (result && result.error) throw result.error;
    } catch (err) {
      once("persist", "could not write public." + TABLE + " (" + errorText(err) + "); open alerts are held in memory.");
    }
  }

  async function unpersist(key) {
    try {
      var result = await supabase.from(TABLE).delete().eq("alert_key", key);
      if (result && result.error) throw result.error;
    } catch (err) {
      once("unpersist", "could not delete from public." + TABLE + " (" + errorText(err) + ").");
    }
  }

  async function deliver(kind, alert) {
    var to = opsAlertRecipient(env);
    if (!to) {
      once("no-recipient", "Neither OPS_ALERT_EMAIL nor BACKUP_EMAIL_TO is set, so no alert email is sent. " +
        "First unsent alert: " + alert.key + " — " + alert.what + ". Set OPS_ALERT_EMAIL on Railway.");
      return false;
    }
    var message = alertEmail(kind, alert, now());
    try {
      var outcome = await send({ from: FROM_EMAIL, to: to, subject: message.subject, text: message.text }, env);
      if (!outcome || !outcome.ok) {
        log.error(TAG + " " + kind + " email for " + alert.key + " was NOT sent: " + ((outcome && outcome.error) || "no result"));
        return false;
      }
      log.log(TAG + " " + kind + " email sent for " + alert.key + " to " + to + ".");
      return true;
    } catch (err) {
      log.error(TAG + " " + kind + " email for " + alert.key + " was NOT sent: the send threw — " + errorText(err));
      return false;
    }
  }

  /* Opens or refreshes an alert. info: { what, error, where, log_tag,
     fingerprint }. The fingerprint (the error text unless given) is what
     "the same alert" means for dedupe. Resolves to { sent, reason }. */
  async function raise(key, info) {
    try {
      if (!opsAlertsEnabled(env)) return { sent: false, reason: "disabled" };
      await hydrate();
      var i = info || {};
      var error = errorText(i.error);
      var fingerprint = i.fingerprint != null ? String(i.fingerprint) : error;
      var prev = open.get(key) || null;
      var nowMs = now();
      var alert = {
        key: key, what: String(i.what || key), fingerprint: fingerprint, error: error,
        where: i.where || null, log_tag: i.log_tag || null,
        opened_at: prev ? prev.opened_at : new Date(nowMs).toISOString(),
        last_sent_at: prev ? prev.last_sent_at : null
      };
      if (prev && prev.fingerprint === fingerprint && prev.last_sent_at && nowMs - Date.parse(prev.last_sent_at) < DEDUPE_MS) {
        open.set(key, alert);
        return { sent: false, reason: "deduped" };
      }
      var sent = await deliver("alert", alert);
      if (sent) alert.last_sent_at = new Date(nowMs).toISOString();
      open.set(key, alert);
      await persist(alert);
      return { sent: sent, reason: sent ? "sent" : "not_sent" };
    } catch (err) {
      log.error(TAG + " raising " + key + " failed: " + errorText(err));
      return { sent: false, reason: "error" };
    }
  }

  /* Closes an open key with one "resolved" email. A key that is not open
     does nothing, so callers may resolve on every healthy reading. */
  async function resolve(key) {
    try {
      if (!opsAlertsEnabled(env)) return { sent: false, reason: "disabled" };
      await hydrate();
      var prev = open.get(key);
      if (!prev) return { sent: false, reason: "not_open" };
      open.delete(key);
      var sent = prev.last_sent_at ? await deliver("resolved", prev) : false;
      await unpersist(key);
      return { sent: sent, reason: sent ? "sent" : "not_sent" };
    } catch (err) {
      log.error(TAG + " resolving " + key + " failed: " + errorText(err));
      return { sent: false, reason: "error" };
    }
  }

  /* For Termaximus. Fail-loud: when ops_alerts cannot be read, this throws
     rather than reporting what one process happens to remember as the whole. */
  async function openAlerts() {
    if (!(await hydrate())) throw new Error("public." + TABLE + " could not be read");
    return Array.from(open.values())
      .map(function (a) { return { key: a.key, what: a.what, since: a.opened_at }; })
      .sort(function (a, b) { return a.key < b.key ? -1 : a.key > b.key ? 1 : 0; });
  }

  /* (a) job_runs, and (c) backup staleness. Throws on an unreadable job_runs:
     the caller records that as its own last_error. */
  async function scanOps() {
    var result = await supabase.from("job_runs").select("job_name, last_error, started_at, finished_at");
    if (result.error) throw new Error("job_runs could not be read: " + errorText(result.error));
    var rows = result.data || [];
    var byName = new Map(rows.map(function (r) { return [r.job_name, r]; }));
    var summary = { raised: 0, resolved: 0 };

    for (var r of rows) {
      if (r.job_name === BACKUP_JOB_NAME) continue;  // backup_failed owns it
      if (r.last_error && String(r.last_error).trim()) {
        var out = await raise("job:" + r.job_name, {
          what: "Scheduled job " + r.job_name + " recorded an error",
          error: r.last_error,
          where: "Table editor > job_runs, row " + r.job_name + " (last_error, started_at " + (r.started_at || "unknown") + ")",
          log_tag: r.job_name
        });
        if (out.sent) summary.raised++;
      }
    }
    for (var key of Array.from(open.keys())) {
      if (key.indexOf("job:") !== 0) continue;
      var row = byName.get(key.slice(4));
      var clear = !row || (!(row.last_error && String(row.last_error).trim()) && !!row.finished_at);
      if (clear && (await resolve(key)).sent) summary.resolved++;
    }

    if (env.ENABLE_NIGHTLY_BACKUP === "true") {
      var backup = byName.get(BACKUP_JOB_NAME);
      var lastOk = backup && backup.finished_at ? Date.parse(backup.finished_at) : NaN;
      // No success on record: counted from this process's start, so a fresh
      // deploy is not reported stale before a backup was ever due.
      var since = isFinite(lastOk) ? lastOk : bootMs;
      if (now() - since > BACKUP_STALE_MS) {
        await raise("backup_stale", {
          what: "No nightly backup has succeeded in the last 30 hours",
          error: isFinite(lastOk) ? "Last successful backup: " + new Date(lastOk).toISOString()
            : "No successful backup is recorded (job_runs." + BACKUP_JOB_NAME + " has no finished_at)",
          fingerprint: "stale since " + (isFinite(lastOk) ? new Date(lastOk).toISOString() : "never"),
          where: "Table editor > job_runs, row " + BACKUP_JOB_NAME + "; and the BACKUP_EMAIL_TO inbox",
          log_tag: "[NightlyBackup]"
        });
      } else {
        await resolve("backup_stale");
      }
    } else {
      await resolve("backup_stale");
    }
    return summary;
  }

  /* The 30-minute scan, claimed through job_runs so two processes cannot both
     run one slot. job_runs.last_run_on is a date, so the claim is on
     started_at instead: the conditional update wins only for a row last
     started before this half-hour began. The same two statements as every
     other claim here (insert; on 23505, a conditional update). A scan that
     fails records its error in its own row AND alerts at once, because the
     next claim clears last_error before any scan could read it. */
  async function scanTick() {
    try {
      if (!opsAlertsEnabled(env)) return { claimed: false, reason: "disabled" };
      var nowMs = now();
      var slotIso = new Date(Math.floor(nowMs / 1800000) * 1800000).toISOString();
      var started = new Date(nowMs).toISOString();
      var claim = { last_run_on: started.slice(0, 10), started_at: started, finished_at: null, last_error: null };

      var inserted = await supabase.from("job_runs").insert(Object.assign({ job_name: SCAN_JOB_NAME }, claim)).select("job_name");
      var claimed = !inserted.error;
      if (inserted.error) {
        if (inserted.error.code !== "23505") {
          log.error(TAG + " scan claim insert failed: " + errorText(inserted.error));
          return { claimed: false, reason: "claim_failed" };
        }
        var updated = await supabase.from("job_runs").update(claim)
          .eq("job_name", SCAN_JOB_NAME)
          .or("started_at.is.null,started_at.lt.\"" + slotIso + "\"")
          .select("job_name");
        if (updated.error) {
          log.error(TAG + " scan claim update failed: " + errorText(updated.error));
          return { claimed: false, reason: "claim_failed" };
        }
        claimed = (updated.data || []).length > 0;
      }
      if (!claimed) return { claimed: false, reason: "held" };

      var failure = null;
      var summary = null;
      try {
        summary = await scanOps();
      } catch (err) {
        failure = errorText(err);
      }
      var patch = { finished_at: new Date(now()).toISOString() };
      if (failure) patch.last_error = failure;
      var finished = await supabase.from("job_runs").update(patch).eq("job_name", SCAN_JOB_NAME);
      if (finished && finished.error) log.error(TAG + " could not record the scan's completion: " + errorText(finished.error));
      if (failure) {
        await raise("ops_scan", {
          what: "The 30-minute ops alert scan failed",
          error: failure,
          where: "Table editor > job_runs, row " + SCAN_JOB_NAME,
          log_tag: TAG
        });
      } else {
        await resolve("ops_scan");
      }
      return { claimed: true, failure: failure, summary: summary };
    } catch (err) {
      log.error(TAG + " scan tick failed: " + errorText(err));
      return { claimed: false, reason: "error" };
    }
  }

  /* Records one backup run in job_runs.nightly_backup and alerts on it.
     RECORDED, NOT CLAIMED: the backup still takes no claim (server.js says
     why), this only writes down how it went. finished_at is written on
     SUCCESS ONLY (sent, and not marked incomplete), so it is the last
     successful backup, which is what the 30-hour staleness test reads; a
     failure writes last_error and leaves it.
     Never rejects. */
  async function backupFinished(result, startedMs) {
    try {
      var nowMs = now();
      var row = {
        job_name: BACKUP_JOB_NAME,
        last_run_on: new Date(nowMs).toISOString().slice(0, 10),
        started_at: new Date(startedMs || nowMs).toISOString()
      };
      if (backupSucceeded(result)) {
        row.finished_at = new Date(nowMs).toISOString();
        row.last_error = null;
      } else {
        row.last_error = (result && result.sent ? "sent incomplete: " + [].concat(result.incomplete || [], result.errored || []).join(", ")
          : "sent: false, reason " + ((result && result.reason) || "unknown")) +
          (result && result.error ? " — " + errorText(result.error) : "");
      }
      var written = await supabase.from("job_runs").upsert(row, { onConflict: "job_name" });
      if (written && written.error) log.error(TAG + " could not record the backup run in job_runs: " + errorText(written.error));
    } catch (err) {
      log.error(TAG + " could not record the backup run in job_runs: " + errorText(err));
    }
    return noteBackupResult(result);
  }

  /* A backup counts only when it was sent AND holds every table whole. */
  function backupSucceeded(result) {
    return !!(result && result.sent && result.complete !== false);
  }

  /* (c) One backup run's outcome, from runNightlyBackup's result. */
  async function noteBackupResult(result) {
    if (backupSucceeded(result)) return resolve("backup_failed");
    if (result && result.sent) {
      var gaps = [].concat(result.incomplete || [], result.errored || []);
      return raise("backup_failed", {
        what: "The nightly backup was sent incomplete",
        error: "Tables missing or partial in the backup: " + gaps.join(", "),
        fingerprint: "incomplete: " + gaps.join(","),
        where: "Railway logs, search [NightlyBackup][FAILED]; Table editor > backup_runs, latest row",
        log_tag: "[NightlyBackup][FAILED]"
      });
    }
    var reason = (result && result.reason) || "unknown";
    return raise("backup_failed", {
      what: (result && result.alert) || "The nightly backup failed",
      error: "runNightlyBackup returned sent: false, reason " + reason + (result && result.error ? " — " + errorText(result.error) : ""),
      fingerprint: reason,
      where: "the BACKUP_EMAIL_TO inbox (no backup arrived); Table editor > job_runs, row " + BACKUP_JOB_NAME,
      log_tag: "[NightlyBackup][FAILED]"
    });
  }

  /* (b) Called from the webhook's catch WITHOUT await: the response to Stripe
     never waits on an email. raise never rejects. */
  function stripeWebhookFailed(event, error) {
    return raise("stripe_webhook", {
      what: "The Stripe webhook failed to process an event",
      error: "event " + ((event && event.id) || "unknown") + " (" + ((event && event.type) || "unknown type") + "): " + errorText(error),
      fingerprint: errorText(error),
      where: "Stripe dashboard > Developers > Webhooks (the failed delivery retries); Supabase table subscriptions",
      log_tag: "Stripe webhook handler failed"
    });
  }

  function noteSignatureFailure() {
    signatureFailures++;
  }

  /* A member's scheduled run failed three times in a row and the runner paused
     it. One key per schedule (user and agent), so two schedules pausing are two
     alerts and one schedule is one: a paused schedule is not due, so it cannot
     fail or raise again until its owner resumes it, and Resume resolves the key.
     Never rejects. */
  function scheduleAlertKey(userId, agentType) {
    return "schedule_paused:" + userId + ":" + agentType;
  }

  function scheduleAutoPaused(info) {
    var i = info || {};
    return raise(scheduleAlertKey(i.user_id, i.agent_type), {
      what: "A scheduled " + i.agent_type + " run failed " + i.failures + " times in a row and paused itself",
      error: "user " + i.user_id + ", last failure: " + errorText(i.error),
      fingerprint: "paused",
      where: "Table editor > agent_schedules, user_id " + i.user_id + ", agent_type " + i.agent_type +
        " (last_error, last_attempt_at, consecutive_failures)",
      log_tag: "[AgentSchedules] PAUSED"
    });
  }

  function scheduleResumed(userId, agentType) {
    return resolve(scheduleAlertKey(userId, agentType));
  }

  /* (d) The /health probe: one read of one row of job_runs, with a timeout.
     Shared by concurrent callers and reused for HEALTH_CACHE_MS. */
  async function runProbe() {
    var timer = null;
    try {
      var read = supabase.from("job_runs").select("job_name").limit(1);
      var timeout = new Promise(function (_, reject) {
        timer = setTimeout(function () { reject(new Error("no answer within " + HEALTH_TIMEOUT_MS + " ms")); }, HEALTH_TIMEOUT_MS);
      });
      var result = await Promise.race([read, timeout]);
      if (result && result.error) throw new Error(errorText(result.error));
      return { ok: true, error: null };
    } catch (err) {
      return { ok: false, error: errorText(err) };
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  async function probeDatabase() {
    if (probeCached && now() - probeCached.at < HEALTH_CACHE_MS) return probeCached.result;
    if (probeInFlight) return probeInFlight;
    probeInFlight = (async function () {
      var result = await runProbe();
      probeCached = { at: now(), result: result };
      // Not awaited: /health answers an uptime monitor now, and never waits on
      // an email. raise and resolve never reject.
      if (result.ok) {
        healthFails = 0;
        lastAlertWork = resolve("health_db");
      } else {
        healthFails++;
        log.error(TAG + " /health database probe failed (" + healthFails + " in a row): " + result.error);
        if (healthFails >= HEALTH_FAILS_TO_ALERT) {
          lastAlertWork = raise("health_db", {
            what: "/health: the database did not answer " + healthFails + " times in a row",
            error: result.error,
            fingerprint: "db_down",
            where: "the project dashboard > Project status and Logs > API",
            log_tag: "/health database probe failed"
          });
        }
      }
      return result;
    })();
    try {
      return await probeInFlight;
    } finally {
      probeInFlight = null;
    }
  }

  return {
    raise: raise,
    resolve: resolve,
    openAlerts: openAlerts,
    scanOps: scanOps,
    scanTick: scanTick,
    noteBackupResult: noteBackupResult,
    backupFinished: backupFinished,
    stripeWebhookFailed: stripeWebhookFailed,
    noteSignatureFailure: noteSignatureFailure,
    scheduleAutoPaused: scheduleAutoPaused,
    scheduleResumed: scheduleResumed,
    signatureFailures: function () { return signatureFailures; },
    probeDatabase: probeDatabase,
    settled: function () { return lastAlertWork; }
  };
}

module.exports = {
  createOpsAlerts,
  opsAlertsEnabled,
  opsAlertRecipient,
  alertEmail,
  OPS_ALERT_SCAN_JOB_NAME: SCAN_JOB_NAME,
  OPS_ALERT_BACKUP_JOB_NAME: BACKUP_JOB_NAME,
  HEALTH_TIMEOUT_MS,
  HEALTH_CACHE_MS
};
