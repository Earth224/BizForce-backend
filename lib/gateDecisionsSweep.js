// ── Gate decisions sweep: a decision is kept for 90 days ─────────────────────
//
// WHY. gate_decisions (migration 158) holds one row per gated action, which is
// what the "Why?" panel and the Decisions list read. The design (section 1.5)
// keeps them 90 days; this is the daily job that makes that true.
//
// WHAT ONE PASS DOES. It reads gate_decisions ids with created_at strictly
// before (pass start - 90 days), oldest first, a batch at a time, and deletes
// those ids, with the cutoff repeated in the delete itself, so a delete can
// never reach a recent row whatever ids it is handed. A read or delete that
// fails stops the pass; the error lands in job_runs.last_error and the next
// day's pass tries again. It never loops on a failure.
//
// CLAIMED. Its own job_runs row, gate_decisions_sweep, claimed for the UTC day
// with the same two statements the other daily jobs use, so two processes
// cannot both run it. The cron fires at 04:30 UTC (server.js); there is no
// boot-time run.
//
// ON BY DEFAULT: only ENABLE_GATE_DECISIONS_SWEEP exactly "false" turns it off,
// because retention must not depend on someone remembering a variable.
//
// It takes the Supabase client by injection, reads and deletes only
// gate_decisions (and its own job_runs row), and never requires server.js.
"use strict";

var GATE_DECISIONS_SWEEP_JOB_NAME = "gate_decisions_sweep";
var GATE_DECISIONS_RETENTION_DAYS = 90;
var GATE_DECISIONS_SWEEP_BATCH = 500;
// The per-pass ceiling: 100 batches. Anything past it waits for the next day.
var GATE_DECISIONS_SWEEP_MAX_PER_TICK = 50000;

function gateDecisionsSweepEnabled(env) {
  return (env || process.env).ENABLE_GATE_DECISIONS_SWEEP !== "false";
}

function gateDecisionsSweepClaimDay(nowMs) {
  return new Date(nowMs).toISOString().slice(0, 10);
}

// A row is deleted when created_at < cutoff; a row exactly 90 days old waits a day.
function gateDecisionsCutoff(nowMs) {
  return new Date(nowMs - GATE_DECISIONS_RETENTION_DAYS * 24 * 60 * 60 * 1000).toISOString();
}

async function claimGateDecisionsSweepDay(supabase, nowMs) {
  var today = gateDecisionsSweepClaimDay(nowMs);
  var started = new Date(nowMs).toISOString();
  var inserted = await supabase
    .from("job_runs")
    .insert({ job_name: GATE_DECISIONS_SWEEP_JOB_NAME, last_run_on: today, started_at: started, finished_at: null, last_error: null })
    .select("job_name");
  if (!inserted.error) return true;
  // 23505 = unique_violation: the row exists. Anything else is a failure, never a claim.
  if (inserted.error.code !== "23505") {
    console.error("[GateDecisionsSweep] Claim insert failed:", inserted.error.message);
    return false;
  }
  var updated = await supabase
    .from("job_runs")
    .update({ last_run_on: today, started_at: started, finished_at: null, last_error: null })
    .eq("job_name", GATE_DECISIONS_SWEEP_JOB_NAME)
    .or("last_run_on.is.null,last_run_on.neq." + today)
    .select("job_name");
  if (updated.error) {
    console.error("[GateDecisionsSweep] Claim update failed:", updated.error.message);
    return false;
  }
  return (updated.data || []).length > 0;
}

async function finishGateDecisionsSweep(supabase, errorMessage) {
  var patch = { finished_at: new Date().toISOString() };
  if (errorMessage) patch.last_error = String(errorMessage).slice(0, 2000);
  var result = await supabase.from("job_runs").update(patch).eq("job_name", GATE_DECISIONS_SWEEP_JOB_NAME);
  if (result.error) console.error("[GateDecisionsSweep] Failed to record run completion:", result.error.message);
}

/* The pass body, split from the claim so a check drives it directly. */
async function runGateDecisionsSweepPass(supabase, nowMs) {
  var cutoff = gateDecisionsCutoff(nowMs);
  var summary = { cutoff: cutoff, batches: 0, rows_read: 0, rows_deleted: 0, ceiling_reached: false, error: null };
  console.log("[GateDecisionsSweep] Pass starting: deleting gate decisions created before " + cutoff + ".");
  while (summary.rows_read < GATE_DECISIONS_SWEEP_MAX_PER_TICK) {
    var size = Math.min(GATE_DECISIONS_SWEEP_BATCH, GATE_DECISIONS_SWEEP_MAX_PER_TICK - summary.rows_read);
    var page = await supabase
      .from("gate_decisions")
      .select("id")
      .lt("created_at", cutoff)
      .order("created_at", { ascending: true })
      .limit(size);
    if (page.error) {
      summary.error = "batch " + (summary.batches + 1) + ": gate_decisions could not be read: " + page.error.message;
      break;
    }
    var ids = (page.data || []).map(function (row) { return row.id; });
    if (!ids.length) break;
    summary.batches++;
    summary.rows_read += ids.length;
    var removed = await supabase
      .from("gate_decisions")
      .delete()
      .in("id", ids)
      .lt("created_at", cutoff)
      .select("id");
    if (removed.error) {
      summary.error = "batch " + summary.batches + ": gate_decisions delete failed: " + removed.error.message;
      break;
    }
    summary.rows_deleted += (removed.data || []).length;
    if (ids.length < size) break;
  }
  if (!summary.error && summary.rows_read >= GATE_DECISIONS_SWEEP_MAX_PER_TICK) summary.ceiling_reached = true;
  console.log("[GateDecisionsSweep] Pass finished: " + summary.rows_deleted + " decision(s) deleted in " + summary.batches + " batch(es)" +
    (summary.ceiling_reached ? "; the ceiling was reached and the rest wait for tomorrow" : "") +
    (summary.error ? "; stopped: " + summary.error : "") + ".");
  return summary;
}

/* The cron's whole job: claim the day, run the pass, close the claim. Never rejects. */
async function gateDecisionsSweepTick(supabase, nowMs) {
  var startedMs = typeof nowMs === "number" ? nowMs : Date.now();
  try {
    if (!(await claimGateDecisionsSweepDay(supabase, startedMs))) {
      console.log("[GateDecisionsSweep] Already claimed for " + gateDecisionsSweepClaimDay(startedMs) + "; nothing to do.");
      return { claimed: false };
    }
    var summary = await runGateDecisionsSweepPass(supabase, startedMs);
    await finishGateDecisionsSweep(supabase, summary.error);
    return { claimed: true, summary: summary };
  } catch (err) {
    console.error("[GateDecisionsSweep] Pass error:", (err && err.message) || err);
    try { await finishGateDecisionsSweep(supabase, (err && err.message) || String(err)); } catch (finishErr) { /* reported above */ }
    return { claimed: true, error: (err && err.message) || String(err) };
  }
}

module.exports = {
  GATE_DECISIONS_SWEEP_JOB_NAME: GATE_DECISIONS_SWEEP_JOB_NAME,
  GATE_DECISIONS_RETENTION_DAYS: GATE_DECISIONS_RETENTION_DAYS,
  GATE_DECISIONS_SWEEP_BATCH: GATE_DECISIONS_SWEEP_BATCH,
  GATE_DECISIONS_SWEEP_MAX_PER_TICK: GATE_DECISIONS_SWEEP_MAX_PER_TICK,
  gateDecisionsSweepEnabled: gateDecisionsSweepEnabled,
  gateDecisionsCutoff: gateDecisionsCutoff,
  claimGateDecisionsSweepDay: claimGateDecisionsSweepDay,
  runGateDecisionsSweepPass: runGateDecisionsSweepPass,
  gateDecisionsSweepTick: gateDecisionsSweepTick
};
