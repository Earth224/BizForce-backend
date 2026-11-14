"use strict";

/* ══════════════════════════════════════════════════════════════════════════
   lib/dailyClaim.js — one claim per UTC day for a scheduled pass, through its
   own job_runs row (L1, Nov 14 2026).

   The same rule every 04:45 UTC step follows (lib/memberVideos.js claimDay):
   the first insert of the job's row wins the day; after that, one
   conditional update wins it only when last_run_on is not today. A second
   process, a second call or a restart on the same day claims nothing.
   Nothing here throws: a failed claim is "not claimed".
   ══════════════════════════════════════════════════════════════════════════ */

async function claimToday(supabase, jobName, nowMs) {
  var day = new Date(nowMs).toISOString().slice(0, 10);
  var at = new Date(nowMs).toISOString();
  try {
    var first = await supabase.from("job_runs")
      .insert({ job_name: jobName, last_run_on: day, started_at: at, finished_at: null, last_error: null }).select("job_name");
    if (!first.error) return true;
    if (first.error.code !== "23505") {
      console.error("[" + jobName + "] The day's claim could not be written: " + (first.error.code || "error"));
      return false;
    }
    var again = await supabase.from("job_runs").update({ last_run_on: day, started_at: at, finished_at: null, last_error: null })
      .eq("job_name", jobName).or("last_run_on.is.null,last_run_on.neq." + day).select("job_name");
    if (again.error) {
      console.error("[" + jobName + "] The day's claim could not be taken: " + (again.error.code || "error"));
      return false;
    }
    return (again.data || []).length > 0;
  } catch (err) {
    console.error("[" + jobName + "] The day's claim failed: " + ((err && err.code) || "error"));
    return false;
  }
}

/* Records the end of a claimed run, and its error when it had one. Never throws. */
async function recordFinish(supabase, jobName, nowMs, errorMessage) {
  try {
    var patch = { finished_at: new Date(nowMs).toISOString() };
    if (errorMessage) patch.last_error = String(errorMessage).slice(0, 2000);
    var r = await supabase.from("job_runs").update(patch).eq("job_name", jobName);
    if (r.error) console.error("[" + jobName + "] The run's end could not be recorded: " + (r.error.code || "error"));
  } catch (err) {
    console.error("[" + jobName + "] The run's end could not be recorded.");
  }
}

module.exports = { claimToday: claimToday, recordFinish: recordFinish };
