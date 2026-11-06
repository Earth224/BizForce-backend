// ── Schema check: a missing table is named the day it goes missing ───────────
//
// WHY. On Oct 29 2026 the nightly backup began failing because
// public.member_support did not exist: migration 150 had never been run. The
// backup said "incomplete" and nothing more, and five nights passed before
// anyone read backup_runs.problems. This module names the table, and the exact
// migration file that creates it, on the first day it is missing.
//
// THE LIST. SCHEMA_TABLES is every table the code relies on, each tagged with
// the first migration file that creates it. It is the migrations folder's
// created tables minus the ones a later migration drops (053 and 123), which
// is exactly the union of lib/backup.js's BACKUP_TABLES, SKIPPED_TABLES and
// EXCLUDED_TABLES, and it holds every table any non-script file reads with a
// literal .from("..."). scripts/checkSchemaCheck.js proves all three, so a new
// migration or a new read that is not added here fails the suite.
//
// THE SIGNAL. PostgREST says a table is missing in two ways: a non-head select
// answers PGRST205 ("Could not find the table"), and a head count answers 204
// with no error and a null count. Both count as missing here. Any other error
// is "unreadable": reported, never alerted as missing.
//
// READ-ONLY. One pass is one head count per table (select("*", { count:
// "exact", head: true })): no rows are fetched and nothing is written to any
// table but this job's own job_runs row. The alert email goes through
// lib/opsAlert.js, which records open alerts in ops_alerts as it always has.
//
// WHEN. Once per process, 60 seconds after boot (server.js, only when it runs
// as the program), and daily at 06:00 UTC through its own job_runs row,
// schema_check, claimed for the UTC day with the same two statements the
// other daily jobs use, so two processes cannot both run the daily pass.
//
// ONE EMAIL PER MISSING TABLE. Each missing table is alert key
// schema_missing:<table>. A key that is already open (ops_alerts, so across
// restarts) or already raised by this process is not raised again; when the
// table is counted again, the key is resolved with one "resolved" email.
//
// ON BY DEFAULT: only ENABLE_SCHEMA_CHECK exactly "false" turns it off.
//
// It takes the Supabase client and the ops alerts by injection and never
// requires server.js or lib/backup.js (lib/backup.js requires this file).
"use strict";

var SCHEMA_CHECK_JOB_NAME = "schema_check";
var MIGRATIONS_DIR = "supabase/migrations";
var ALERT_PREFIX = "schema_missing:";

// [table, the migration file that creates it]. Generated from the migrations
// folder; scripts/checkSchemaCheck.js regenerates it and compares.
var SCHEMA_TABLES = [
  ["admin_flags", "083_missing_referenced_tables.sql"],
  ["agent_assignments", "001_agent_assignments.sql"],
  ["agent_autonomy", "064_agent_autonomy_and_job_runs.sql"],
  ["agent_collaborations", "003_agent_collaborations.sql"],
  ["agent_feedback", "151_learning_loop.sql"],
  ["agent_memory", "002_agent_memory.sql"],
  ["agent_preferences", "151_learning_loop.sql"],
  ["agent_proposals", "054_agent_proposals.sql"],
  ["agent_schedules", "102_agent_schedules.sql"],
  ["ai_agents", "000_foundation_tables.sql"],
  ["ai_reports", "000_foundation_tables.sql"],
  ["ai_tasks", "000_foundation_tables.sql"],
  ["auth_sessions", "100_auth_sessions.sql"],
  ["automation_queue", "000_foundation_tables.sql"],
  ["backup_runs", "141_backup_runs.sql"],
  ["bf_music_tracks", "009_profile_page.sql"],
  ["bf_profiles", "009_profile_page.sql"],
  ["bf_videos", "010_videos.sql"],
  ["bfc_transfers", "145_bfc_transfers.sql"],
  ["birth_records", "066_birth_records.sql"],
  ["bizbooks", "035_bizbooks.sql"],
  ["bizdoc_documents", "032_bizdoc.sql"],
  ["bizdoc_signatures", "032_bizdoc.sql"],
  ["bsky_leads", "068_bsky_leads.sql"],
  ["business_profiles", "014_business_profiles.sql"],
  ["businesses", "000_foundation_tables.sql"],
  ["calendar_events", "043_calendar_events.sql"],
  ["campaign_donations", "031_crowdfunding.sql"],
  ["card_leads", "172_card_leads.sql"],
  ["card_view_counts", "171_card_counts.sql"],
  ["chat_messages", "000_foundation_tables.sql"],
  ["consent_events", "069_contacts_and_consent.sql"],
  ["contacts", "069_contacts_and_consent.sql"],
  ["content_library", "025_content_library.sql"],
  ["cover_wraps", "037_cover_wraps.sql"],
  ["crm_activities", "086_crm_system.sql"],
  ["crm_customers", "086_crm_system.sql"],
  ["crowdfunding_campaigns", "031_crowdfunding.sql"],
  ["digital_cards", "007_digital_cards.sql"],
  ["email_sends", "070_email_sends.sql"],
  ["email_sequence_enrollments", "134_email_sequences.sql"],
  ["email_sequences", "134_email_sequences.sql"],
  ["engine_visits", "128_engine_visits.sql"],
  ["executive_dispatches", "137_executive_dispatches.sql"],
  ["gate_decisions", "158_gate_decisions.sql"],
  ["icp_profiles", "087_prospecting_system.sql"],
  ["inner_iq_results", "050_inner_iq_results.sql"],
  ["inventory_items", "091_inventory_system.sql"],
  ["inventory_movements", "091_inventory_system.sql"],
  ["job_runs", "064_agent_autonomy_and_job_runs.sql"],
  ["lead_captures", "028_lead_captures.sql"],
  ["marketplace_listings", "006_marketplace.sql"],
  ["marketplace_orders", "034_marketplace_orders_usd.sql"],
  ["member_email_connections", "169_member_email_connections.sql"],
  ["member_email_replies", "170_member_email_replies.sql"],
  ["member_gates", "159_member_gates.sql"],
  ["member_links", "161_member_links.sql"],
  ["member_mastodon_connections", "165_member_mastodon_connections.sql"],
  ["member_media", "167_member_media.sql"],
  ["member_playlists", "155_member_music.sql"],
  ["member_social_connections", "152_member_social_connections.sql"],
  ["member_social_setting_changes", "152_member_social_connections.sql"],
  ["member_store_connections", "163_store_connections.sql"],
  ["member_support", "150_member_support.sql"],
  ["member_themes", "154_member_themes.sql"],
  ["member_tracks", "155_member_music.sql"],
  ["member_triggers", "160_member_triggers.sql"],
  ["messages", "000_foundation_tables.sql"],
  ["model_calls", "103_model_calls.sql"],
  ["moderation_logs", "083_missing_referenced_tables.sql"],
  ["notifications", "081_notifications_analytics_events.sql"],
  ["ops_alerts", "140_ops_alerts.sql"],
  ["oracle_messages", "041_oracle_sync_messages_and_fk_repoint.sql"],
  ["oracle_sync", "041_oracle_sync_messages_and_fk_repoint.sql"],
  ["outreach_sends", "074_outreach_sends.sql"],
  ["pending_storage_deletions", "144_pending_storage_deletions.sql"],
  ["plan_cycles", "162_plan_cycles.sql"],
  ["profile_music", "000_foundation_tables.sql"],
  ["profile_portfolio", "000_foundation_tables.sql"],
  ["profile_products", "000_foundation_tables.sql"],
  ["profile_videos", "000_foundation_tables.sql"],
  ["profiles", "000_foundation_tables.sql"],
  ["prospects", "087_prospecting_system.sql"],
  ["push_subscriptions", "048_push_subscriptions.sql"],
  ["radar_status", "135_radar_status.sql"],
  ["reddit_leads", "083_missing_referenced_tables.sql"],
  ["revenue_events", "000_foundation_tables.sql"],
  ["routines", "108_routines.sql"],
  ["sales_lead_pipeline", "027_sales_lead_pipeline.sql"],
  ["saved_prompts", "107_saved_prompts.sql"],
  ["self_reviews", "097_self_reviews.sql"],
  ["seo_refused_drafts", "131_seo_refused_drafts.sql"],
  ["sms_campaign_enrollments", "059_sms_campaign_enrollments.sql"],
  ["sms_campaign_messages", "060_sms_campaign_messages_send_log.sql"],
  ["sms_campaigns", "024_sms_campaigns.sql"],
  ["sms_send_log", "060_sms_campaign_messages_send_log.sql"],
  ["sms_subscribers", "023_sms_subscribers.sql"],
  ["social_post_drafts", "021_social_post_drafts.sql"],
  ["store_order_summaries", "163_store_connections.sql"],
  ["subscriptions", "000_foundation_tables.sql"],
  ["tasks", "000_foundation_tables.sql"],
  ["testimonial_screen_removals", "124_testimonial_screen_removals.sql"],
  ["trigger_firings", "160_member_triggers.sql"],
  ["usage_logs", "000_foundation_tables.sql"],
  ["user_api_keys", "029_user_api_keys.sql"],
  ["user_certifications", "004_certifications.sql"],
  ["user_preferences", "030_user_preferences.sql"],
  ["user_wallets", "005_wallet.sql"],
  ["users", "000_foundation_tables.sql"],
  ["wallet_transactions", "005_wallet.sql"],
  ["webauthn_challenges", "101_webauthn.sql"],
  ["webauthn_credentials", "101_webauthn.sql"],
  ["youtube_api_calls", "138_youtube_api_calls.sql"]
];

var MIGRATION_BY_TABLE = new Map(SCHEMA_TABLES.map(function (e) { return [e[0], e[1]]; }));

function schemaCheckEnabled(env) {
  return (env || process.env).ENABLE_SCHEMA_CHECK !== "false";
}

/* "supabase/migrations/150_member_support.sql", or null for a table not on the list. */
function migrationFor(table) {
  var file = MIGRATION_BY_TABLE.get(table);
  return file ? MIGRATIONS_DIR + "/" + file : null;
}

/* "member_support (run supabase/migrations/150_member_support.sql)". */
function missingTableText(table) {
  var file = migrationFor(table);
  return table + " (run " + (file || "the migration that creates it; the table is not on lib/schemaCheck.js's list") + ")";
}

/* True for either form of PostgREST's missing-table answer. */
function isMissingSignal(res) {
  if (!res) return false;
  if (res.error) return res.error.code === "PGRST205";
  return typeof res.count !== "number";
}

function errorText(error) {
  if (!error) return "unknown error";
  return String(error.message || error.code || error);
}

/* One head count. Resolves to { state: "present" | "missing" | "unreadable", error? }. Never rejects. */
async function probeTable(supabase, table) {
  try {
    var res = await supabase.from(table).select("*", { count: "exact", head: true });
    if (isMissingSignal(res)) return { state: "missing" };
    if (res.error) return { state: "unreadable", error: errorText(res.error) };
    return { state: "present" };
  } catch (err) {
    return { state: "unreadable", error: errorText(err) };
  }
}

var lastStatus = null;

/* The pass: one head count per listed table, nothing else. */
async function runSchemaCheckPass(supabase, nowMs) {
  var at = typeof nowMs === "number" ? nowMs : Date.now();
  var summary = { checked_at: new Date(at).toISOString(), checked: 0, missing: [], unreadable: [] };
  for (var i = 0; i < SCHEMA_TABLES.length; i++) {
    var table = SCHEMA_TABLES[i][0];
    var probe = await probeTable(supabase, table);
    summary.checked++;
    if (probe.state === "missing") summary.missing.push({ table: table, migration: migrationFor(table) });
    else if (probe.state === "unreadable") summary.unreadable.push({ table: table, error: probe.error });
  }
  lastStatus = summary;
  if (summary.missing.length) {
    console.error("[SchemaCheck][MISSING] " + summary.missing.map(function (m) { return missingTableText(m.table); }).join("; "));
  }
  console.log("[SchemaCheck] Pass finished: " + summary.checked + " table(s) checked, " + summary.missing.length + " missing, " +
    summary.unreadable.length + " unreadable" +
    (summary.unreadable.length ? " (" + summary.unreadable.map(function (u) { return u.table + ": " + u.error; }).join("; ") + ")" : "") + ".");
  return summary;
}

// Keys this process has raised; ops_alerts carries them across restarts.
var raisedHere = new Set();

/* One alert per missing table, resolved when it is counted again.
   Returns { raised, resolved }. Never rejects. */
async function noteSchemaResult(opsAlerts, summary) {
  var out = { raised: [], resolved: [] };
  if (!opsAlerts || !summary) return out;
  var openKeys = new Set();
  try {
    (await opsAlerts.openAlerts()).forEach(function (a) { openKeys.add(a.key); });
  } catch (err) {
    console.error("[SchemaCheck] Open alerts could not be read (" + errorText(err) + "); only this process's own raises are remembered.");
  }
  var missingNow = new Set();
  for (var i = 0; i < summary.missing.length; i++) {
    var m = summary.missing[i];
    var key = ALERT_PREFIX + m.table;
    missingNow.add(key);
    if (openKeys.has(key) || raisedHere.has(key)) continue;
    raisedHere.add(key);
    try {
      await opsAlerts.raise(key, {
        what: "A table the code relies on is missing: " + m.table,
        error: "public." + m.table + " does not exist. Run " + (m.migration || "the migration that creates it") + " in the Supabase SQL editor.",
        fingerprint: "missing:" + m.table,
        where: "Railway logs, search [SchemaCheck][MISSING]; /api/admin/health, the schema line",
        log_tag: "[SchemaCheck][MISSING]"
      });
      out.raised.push(m.table);
    } catch (err) {
      console.error("[SchemaCheck] Alert for " + m.table + " failed: " + errorText(err));
    }
  }
  var keys = Array.from(new Set(Array.from(openKeys).concat(Array.from(raisedHere))));
  for (var k = 0; k < keys.length; k++) {
    var openKey = keys[k];
    if (openKey.indexOf(ALERT_PREFIX) !== 0 || missingNow.has(openKey)) continue;
    var table = openKey.slice(ALERT_PREFIX.length);
    // Only a table this pass counted is resolved; an unreadable one stays open.
    if (summary.unreadable.some(function (u) { return u.table === table; })) continue;
    raisedHere.delete(openKey);
    try {
      await opsAlerts.resolve(openKey);
      out.resolved.push(table);
    } catch (err) {
      console.error("[SchemaCheck] Resolving " + table + " failed: " + errorText(err));
    }
  }
  return out;
}

function schemaCheckClaimDay(nowMs) {
  return new Date(nowMs).toISOString().slice(0, 10);
}

async function claimSchemaCheckDay(supabase, nowMs) {
  var today = schemaCheckClaimDay(nowMs);
  var started = new Date(nowMs).toISOString();
  var inserted = await supabase
    .from("job_runs")
    .insert({ job_name: SCHEMA_CHECK_JOB_NAME, last_run_on: today, started_at: started, finished_at: null, last_error: null })
    .select("job_name");
  if (!inserted.error) return true;
  // 23505 = unique_violation: the row exists. Anything else is a failure, never a claim.
  if (inserted.error.code !== "23505") {
    console.error("[SchemaCheck] Claim insert failed:", inserted.error.message);
    return false;
  }
  var updated = await supabase
    .from("job_runs")
    .update({ last_run_on: today, started_at: started, finished_at: null, last_error: null })
    .eq("job_name", SCHEMA_CHECK_JOB_NAME)
    .or("last_run_on.is.null,last_run_on.neq." + today)
    .select("job_name");
  if (updated.error) {
    console.error("[SchemaCheck] Claim update failed:", updated.error.message);
    return false;
  }
  return (updated.data || []).length > 0;
}

async function finishSchemaCheck(supabase, errorMessage) {
  var patch = { finished_at: new Date().toISOString() };
  if (errorMessage) patch.last_error = String(errorMessage).slice(0, 2000);
  var result = await supabase.from("job_runs").update(patch).eq("job_name", SCHEMA_CHECK_JOB_NAME);
  if (result.error) console.error("[SchemaCheck] Failed to record run completion:", result.error.message);
}

/* What job_runs.last_error says for a pass that found missing tables. */
function summaryError(summary) {
  if (!summary || !summary.missing.length) return null;
  return "missing tables: " + summary.missing.map(function (m) { return missingTableText(m.table); }).join("; ");
}

/* The 06:00 UTC cron: claim the day, run the pass, alert, close the claim. Never rejects. */
async function schemaCheckTick(supabase, opsAlerts, nowMs) {
  var startedMs = typeof nowMs === "number" ? nowMs : Date.now();
  try {
    if (!(await claimSchemaCheckDay(supabase, startedMs))) {
      console.log("[SchemaCheck] Already claimed for " + schemaCheckClaimDay(startedMs) + "; nothing to do.");
      return { claimed: false };
    }
    var summary = await runSchemaCheckPass(supabase, startedMs);
    var alerts = await noteSchemaResult(opsAlerts, summary);
    await finishSchemaCheck(supabase, summaryError(summary));
    return { claimed: true, summary: summary, alerts: alerts };
  } catch (err) {
    console.error("[SchemaCheck] Pass error:", errorText(err));
    try { await finishSchemaCheck(supabase, errorText(err)); } catch (finishErr) { /* reported above */ }
    return { claimed: true, error: errorText(err) };
  }
}

var bootRan = false;

/* The once-per-process run 60 s after boot. Unclaimed, because a deploy is
   exactly when a table can go missing; read-only, and deduped by the alert
   keys. A second call in the same process does nothing. Never rejects. */
async function schemaCheckBoot(supabase, opsAlerts, nowMs) {
  if (bootRan) return { ran: false };
  bootRan = true;
  try {
    var summary = await runSchemaCheckPass(supabase, nowMs);
    var alerts = await noteSchemaResult(opsAlerts, summary);
    return { ran: true, summary: summary, alerts: alerts };
  } catch (err) {
    console.error("[SchemaCheck] Boot pass error:", errorText(err));
    return { ran: true, error: errorText(err) };
  }
}

/* The admin health detail's line. */
function schemaStatusLine(status) {
  var s = status === undefined ? lastStatus : status;
  if (!s) return "Schema: not checked yet in this process (the first check runs 60 seconds after boot)";
  if (s.missing.length) {
    return "Schema: MISSING " + s.missing.map(function (m) { return missingTableText(m.table); }).join("; ") + " (checked " + s.checked_at + ")";
  }
  return "Schema: all " + s.checked + " tables present" +
    (s.unreadable.length ? ", " + s.unreadable.length + " unreadable (" + s.unreadable.map(function (u) { return u.table; }).join(", ") + ")" : "") +
    " (checked " + s.checked_at + ")";
}

function lastSchemaStatus() { return lastStatus; }

module.exports = {
  SCHEMA_CHECK_JOB_NAME: SCHEMA_CHECK_JOB_NAME,
  SCHEMA_TABLES: SCHEMA_TABLES,
  MIGRATIONS_DIR: MIGRATIONS_DIR,
  ALERT_PREFIX: ALERT_PREFIX,
  schemaCheckEnabled: schemaCheckEnabled,
  migrationFor: migrationFor,
  missingTableText: missingTableText,
  isMissingSignal: isMissingSignal,
  probeTable: probeTable,
  runSchemaCheckPass: runSchemaCheckPass,
  noteSchemaResult: noteSchemaResult,
  claimSchemaCheckDay: claimSchemaCheckDay,
  schemaCheckTick: schemaCheckTick,
  schemaCheckBoot: schemaCheckBoot,
  schemaStatusLine: schemaStatusLine,
  summaryError: summaryError,
  lastSchemaStatus: lastSchemaStatus
};
