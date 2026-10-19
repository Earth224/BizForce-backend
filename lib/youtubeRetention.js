// ── YouTube retention: YouTube data is kept for at most 30 days ──────────────
//
// WHY THIS EXISTS. youtubeRadar.js stored public YouTube comments in bsky_leads
// through the YouTube Data API. The YouTube API Services Developer Policies
// allow non-authorised API data to be stored for at most 30 days unless it is
// refreshed, and youtubeRadar no longer runs, so nothing is ever refreshed: a
// YouTube row older than 30 days must go. The owner approved permanent
// deletion, including the YouTube-derived records that depend on a deleted
// lead.
//
// WHAT ONE PASS DOES. It reads bsky_leads rows with source = 'youtube' and
// created_at more than 30 days before the pass began, in id order, a batch at a
// time, and for each batch:
//   (a) DEPENDENTS FIRST.
//       - A lead that outreach_sends or prospects points at is SKIPPED: never
//         deleted, nothing that references it deleted. A send record is never
//         removed, and a lead is never deleted out from under one. Each skip is
//         logged loudly with its count and lands in job_runs.last_error, so the
//         owner can decide what to do with it.
//       - sales_lead_pipeline rows on the remaining leads are deleted. That
//         removes the reply drafted from the YouTube comment (last_draft), which
//         is YouTube-derived text, and leaves no pipeline row pointing at a
//         lead that no longer exists.
//   (b) THEN THE LEADS, still filtered on source = 'youtube' and the cutoff in
//       the delete itself, so a delete can never reach another source's row
//       whatever ids it is handed.
// If a dependent read or delete fails, that batch's leads are NOT deleted and
// the pass stops. If the lead delete fails, the pass stops. Either way the
// error lands in job_runs.last_error and the next day's pass tries again; a
// pass never loops on a failure.
//
// NO MODEL CALL ON ANY PATH. This module requires nothing that can reach a
// model; it is given the Supabase client and uses nothing else.
//
// It takes the Supabase client by injection and never builds its own, and it
// never requires server.js, which requires this.

var YOUTUBE_RETENTION_JOB_NAME = "daily_youtube_retention";

// The 30 days of the YouTube API Services Developer Policies. A row is deleted
// when its created_at is strictly before (pass start − 30 days); a row exactly
// 30 days old is kept until the next pass.
var YOUTUBE_RETENTION_DAYS = 30;

/* At most 500 per batch was the requirement; 100 is the size used. Every batch
   sends its post_uris to PostgREST as a literal in.(…) list in the URL. A
   YouTube post_uri is up to 73 characters, 89 once URL-encoded (measured on
   the stored rows, Oct 2026), so 100 of them is under 9 KB, inside the
   request-line limit EXCLUSION_INLINE_MAX in server.js is set against; 500
   would be about 45 KB and fail with a 414. */
var YOUTUBE_RETENTION_BATCH = 100;

// The per-pass ceiling, in leads read: 50 batches. 2,169 YouTube rows were
// stored in Oct 2026, so the first pass clears them all; anything past the
// ceiling waits for the next day.
var YOUTUBE_RETENTION_MAX_PER_TICK = 5000;

/* ON BY DEFAULT, and only the exact string "false" turns it off.

   Every other job in server.js is off unless its variable is exactly "true",
   because those jobs spend money or send things. This one is the opposite: it
   is how stored YouTube data stays within YouTube's 30-day rule, and compliance
   must not depend on someone remembering to set a variable on a new deployment.
   So an unset, blank or misspelt value leaves it running; "False", "0" and "no"
   leave it running too. Turning it off takes the deliberate, exact value
   "false". */
function youtubeRetentionEnabled(env) {
  return (env || process.env).ENABLE_YOUTUBE_RETENTION !== "false";
}

// The claim day. The cron fires in UTC and the claim is a UTC calendar day, so
// the two cannot drift apart.
function youtubeRetentionClaimDay(nowMs) {
  return new Date(nowMs).toISOString().slice(0, 10);
}

function youtubeRetentionCutoff(nowMs) {
  return new Date(nowMs - YOUTUBE_RETENTION_DAYS * 24 * 60 * 60 * 1000).toISOString();
}

// Claim today for this job, atomically, the same two statements the other
// daily passes in server.js use (claimSelfReviewDay): insert, and on a unique
// violation, a conditional update that only a not-yet-claimed row can win.
async function claimYoutubeRetentionDay(supabase, nowMs) {
  var today = youtubeRetentionClaimDay(nowMs);
  var started = new Date(nowMs).toISOString();

  var insertResult = await supabase
    .from("job_runs")
    .insert({
      job_name:    YOUTUBE_RETENTION_JOB_NAME,
      last_run_on: today,
      started_at:  started,
      finished_at: null,
      last_error:  null
    })
    .select("job_name");

  if (!insertResult.error) {
    return true;
  }

  // 23505 = unique_violation: the row exists. Anything else is a failure, and
  // a failure to read the claim is never treated as holding it.
  if (insertResult.error.code !== "23505") {
    console.error("[YouTubeRetention] Claim insert failed:", insertResult.error.message);
    return false;
  }

  var updateResult = await supabase
    .from("job_runs")
    .update({
      last_run_on: today,
      started_at:  started,
      finished_at: null,
      last_error:  null
    })
    .eq("job_name", YOUTUBE_RETENTION_JOB_NAME)
    .or("last_run_on.is.null,last_run_on.neq." + today)
    .select("job_name");

  if (updateResult.error) {
    console.error("[YouTubeRetention] Claim update failed:", updateResult.error.message);
    return false;
  }

  return (updateResult.data || []).length > 0;
}

async function finishYoutubeRetentionRun(supabase, errorMessage) {
  var patch = { finished_at: new Date().toISOString() };

  if (errorMessage) {
    patch.last_error = String(errorMessage).slice(0, 2000);
  }

  var result = await supabase
    .from("job_runs")
    .update(patch)
    .eq("job_name", YOUTUBE_RETENTION_JOB_NAME);

  if (result.error) {
    console.error("[YouTubeRetention] Failed to record run completion:", result.error.message);
  }
}

// The post_uris among `uris` that `table` points at through lead_post_uri.
async function referencedUris(supabase, table, uris) {
  var result = await supabase
    .from(table)
    .select("lead_post_uri")
    .in("lead_post_uri", uris);

  if (result.error) {
    throw new Error(table + " could not be read: " + result.error.message);
  }
  return (result.data || []).map(function (row) { return row.lead_post_uri; });
}

/* The pass body, split from the claim so the check drives it directly.
   Returns the counts; throws nothing for a failed batch, which is reported in
   `error` with the pass stopped at that batch. */
async function runYoutubeRetentionPass(supabase, nowMs) {
  var cutoff = youtubeRetentionCutoff(nowMs);
  var summary = {
    cutoff: cutoff,
    batches: 0,
    leads_read: 0,
    leads_deleted: 0,
    pipeline_rows_deleted: 0,
    leads_skipped: 0,
    ceiling_reached: false,
    error: null
  };
  var lastId = null;

  console.log("[YouTubeRetention] Pass starting: deleting YouTube leads created before " + cutoff + ".");

  while (summary.leads_read < YOUTUBE_RETENTION_MAX_PER_TICK) {
    var size = Math.min(YOUTUBE_RETENTION_BATCH, YOUTUBE_RETENTION_MAX_PER_TICK - summary.leads_read);
    var query = supabase
      .from("bsky_leads")
      .select("id, post_uri")
      .eq("source", "youtube")
      .lt("created_at", cutoff);
    // Keyset paging by id: a skipped lead stays in the table and must not be
    // read again, which an offset or a re-read of the first page would do.
    if (lastId !== null) query = query.gt("id", lastId);
    var page = await query.order("id", { ascending: true }).limit(size);

    if (page.error) {
      summary.error = "batch " + (summary.batches + 1) + ": bsky_leads could not be read: " + page.error.message;
      break;
    }
    var leads = page.data || [];
    if (!leads.length) break;

    summary.batches++;
    summary.leads_read += leads.length;
    lastId = leads[leads.length - 1].id;
    var uris = leads.map(function (lead) { return lead.post_uri; });

    // (a) DEPENDENTS. References first: a lead anything still points at is skipped.
    var referenced;
    try {
      referenced = (await referencedUris(supabase, "outreach_sends", uris))
        .concat(await referencedUris(supabase, "prospects", uris));
    } catch (refErr) {
      summary.error = "batch " + summary.batches + ": " + refErr.message + ". No lead in this batch was deleted.";
      break;
    }
    var deletable = leads.filter(function (lead) { return referenced.indexOf(lead.post_uri) === -1; });
    var skipped = leads.length - deletable.length;
    if (skipped) {
      summary.leads_skipped += skipped;
      console.error("[YouTubeRetention] SKIPPED " + skipped + " YouTube lead(s) in batch " + summary.batches +
        ": outreach_sends or prospects still points at them. They are kept, and so is everything that references them.");
    }
    if (!deletable.length) {
      console.log("[YouTubeRetention] Batch " + summary.batches + ": 0 lead(s) deleted, 0 pipeline row(s) deleted, " + skipped + " lead(s) skipped.");
      continue;
    }
    var deletableUris = deletable.map(function (lead) { return lead.post_uri; });

    var pipeline = await supabase
      .from("sales_lead_pipeline")
      .delete()
      .in("lead_post_uri", deletableUris)
      .select("id");
    if (pipeline.error) {
      summary.error = "batch " + summary.batches + ": sales_lead_pipeline delete failed: " + pipeline.error.message + ". No lead in this batch was deleted.";
      break;
    }
    var pipelineDeleted = (pipeline.data || []).length;
    summary.pipeline_rows_deleted += pipelineDeleted;

    // (b) THE LEADS. source and the cutoff are repeated in the delete itself.
    var removed = await supabase
      .from("bsky_leads")
      .delete()
      .in("id", deletable.map(function (lead) { return lead.id; }))
      .eq("source", "youtube")
      .lt("created_at", cutoff)
      .select("id");
    if (removed.error) {
      summary.error = "batch " + summary.batches + ": bsky_leads delete failed after " + pipelineDeleted +
        " pipeline row(s) were deleted: " + removed.error.message;
      break;
    }
    var leadsDeleted = (removed.data || []).length;
    summary.leads_deleted += leadsDeleted;

    console.log("[YouTubeRetention] Batch " + summary.batches + ": " + leadsDeleted + " lead(s) deleted, " +
      pipelineDeleted + " pipeline row(s) deleted, " + skipped + " lead(s) skipped.");

    if (leads.length < size) break;
  }

  if (!summary.error && summary.leads_read >= YOUTUBE_RETENTION_MAX_PER_TICK) {
    summary.ceiling_reached = true;
    console.log("[YouTubeRetention] Per-pass ceiling of " + YOUTUBE_RETENTION_MAX_PER_TICK + " lead(s) reached; the rest wait for tomorrow.");
  }
  if (summary.error) {
    console.error("[YouTubeRetention] Pass STOPPED: " + summary.error);
  }
  console.log("[YouTubeRetention] Pass finished: " + summary.batches + " batch(es), " + summary.leads_deleted + " lead(s) deleted, " +
    summary.pipeline_rows_deleted + " pipeline row(s) deleted, " + summary.leads_skipped + " lead(s) skipped.");
  return summary;
}

var youtubeRetentionRunning = false;

async function youtubeRetentionTick(supabase, nowMs) {
  if (youtubeRetentionRunning) {
    console.log("[YouTubeRetention] Tick skipped — previous run still in progress");
    return null;
  }
  youtubeRetentionRunning = true;
  var at = typeof nowMs === "number" ? nowMs : Date.now();

  try {
    var claimed = await claimYoutubeRetentionDay(supabase, at);
    if (!claimed) {
      console.log("[YouTubeRetention] Tick skipped — " + YOUTUBE_RETENTION_JOB_NAME + " already claimed for " +
        youtubeRetentionClaimDay(at) + " (another process or an earlier run today)");
      return null;
    }

    try {
      var summary = await runYoutubeRetentionPass(supabase, at);
      var problems = [];
      if (summary.error) problems.push(summary.error);
      if (summary.leads_skipped) {
        problems.push(summary.leads_skipped + " YouTube lead(s) skipped because outreach_sends or prospects still points at them; they are older than 30 days and were not deleted");
      }
      await finishYoutubeRetentionRun(supabase, problems.length ? problems.join(" | ") : null);
      return summary;
    } catch (passErr) {
      var message = passErr && (passErr.message || String(passErr));
      console.error("[YouTubeRetention] Pass error:", message);
      await finishYoutubeRetentionRun(supabase, message);
      return null;
    }
  } catch (err) {
    console.error("[YouTubeRetention] Tick error:", err && (err.message || err));
    return null;
  } finally {
    youtubeRetentionRunning = false;
  }
}

module.exports = {
  YOUTUBE_RETENTION_JOB_NAME: YOUTUBE_RETENTION_JOB_NAME,
  YOUTUBE_RETENTION_DAYS: YOUTUBE_RETENTION_DAYS,
  YOUTUBE_RETENTION_BATCH: YOUTUBE_RETENTION_BATCH,
  YOUTUBE_RETENTION_MAX_PER_TICK: YOUTUBE_RETENTION_MAX_PER_TICK,
  youtubeRetentionEnabled: youtubeRetentionEnabled,
  youtubeRetentionCutoff: youtubeRetentionCutoff,
  runYoutubeRetentionPass: runYoutubeRetentionPass,
  youtubeRetentionTick: youtubeRetentionTick
};
