"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   POST RETENTION (P2-3, Nov 20 2026), a step of the 04:45 UTC chain, claimed
   through job_runs post_retention. Never throws.

   1. BODIES of removed posts (by their author or by moderation) are emptied
      BODY_PURGE_DAYS (90) after removed_at; bodies of comments moderation
      removed become "[removed]" 90 days after the decision (moderation_queue
      decided_at). Not while an OPEN report (content_reports status open) or a
      live copyright notice (received, removed or countered) holds the item.
   2. PHOTOS of a removed post are released PHOTO_RELEASE_DAYS (30) after
      removed_at: its post_media rows are deleted, so the files follow the media
      library's own rules again (the member may delete them there). Not while a
      report or notice holds the post.
   3. post_share_days rows older than SHARE_DAYS_KEEP (30) are deleted. Their
      share stays counted on the post: migration 194's trigger takes one off
      for each deleted row, so the step adds them back.
   ══════════════════════════════════════════════════════════════════════════ */
const JOB_NAME = "post_retention";
const BODY_PURGE_DAYS = 90;
const PHOTO_RELEASE_DAYS = 30;
const SHARE_DAYS_KEEP = 30;
const BATCH = 500;
const REMOVED_COMMENT_BODY = "[removed]";
const HOLDING_NOTICES = ["received", "removed", "countered"];
const DAY = 86400000;

function daysAgo(nowIso, days) { return new Date(Date.parse(nowIso) - days * DAY).toISOString(); }

/* Of these ids of one type, those an open report or a live copyright notice holds. */
async function heldAmong(sb, type, ids) {
  var held = new Set();
  if (!ids.length) return held;
  var r = await Promise.all([
    sb.from("content_reports").select("object_id").eq("object_type", type).in("object_id", ids).eq("status", "open"),
    sb.from("copyright_notices").select("object_id").eq("object_type", type).in("object_id", ids).in("status", HOLDING_NOTICES)
  ]);
  if (r[0].error) throw r[0].error;
  if (r[1].error) throw r[1].error;
  (r[0].data || []).concat(r[1].data || []).forEach(function (x) { if (x && ids.indexOf(x.object_id) !== -1) held.add(x.object_id); });
  return held;
}

async function purgePostBodies(sb, nowIso) {
  var r = await sb.from("posts").select("id").eq("status", "removed").lt("removed_at", daysAgo(nowIso, BODY_PURGE_DAYS)).neq("body", "").limit(BATCH);
  if (r.error) throw r.error;
  var ids = (r.data || []).map(function (x) { return x.id; });
  var held = await heldAmong(sb, "post", ids);
  var due = ids.filter(function (id) { return !held.has(id); });
  if (!due.length) return { purged: 0, held: held.size };
  var u = await sb.from("posts").update({ body: "" }).in("id", due).eq("status", "removed").select("id");
  if (u.error) throw u.error;
  return { purged: (u.data || []).length, held: held.size };
}

async function purgeCommentBodies(sb, nowIso) {
  var q = await sb.from("moderation_queue").select("object_id").eq("object_type", "comment").eq("state", "removed")
    .lt("decided_at", daysAgo(nowIso, BODY_PURGE_DAYS)).limit(BATCH);
  if (q.error) throw q.error;
  var ids = (q.data || []).map(function (x) { return x.object_id; });
  if (!ids.length) return { purged: 0, held: 0 };
  var c = await sb.from("post_comments").select("id").in("id", ids).eq("status", "removed").neq("body", REMOVED_COMMENT_BODY);
  if (c.error) throw c.error;
  var found = (c.data || []).map(function (x) { return x.id; });
  var held = await heldAmong(sb, "comment", found);
  var due = found.filter(function (id) { return !held.has(id); });
  if (!due.length) return { purged: 0, held: held.size };
  var u = await sb.from("post_comments").update({ body: REMOVED_COMMENT_BODY }).in("id", due).eq("status", "removed").select("id");
  if (u.error) throw u.error;
  return { purged: (u.data || []).length, held: held.size };
}

async function releasePhotos(sb, nowIso) {
  var r = await sb.from("posts").select("id").eq("status", "removed").lt("removed_at", daysAgo(nowIso, PHOTO_RELEASE_DAYS)).limit(BATCH);
  if (r.error) throw r.error;
  var ids = (r.data || []).map(function (x) { return x.id; });
  if (!ids.length) return { released: 0, held: 0 };
  var held = await heldAmong(sb, "post", ids);
  var due = ids.filter(function (id) { return !held.has(id); });
  if (!due.length) return { released: 0, held: held.size };
  var d = await sb.from("post_media").delete().in("post_id", due).select("post_id");
  if (d.error) throw d.error;
  return { released: (d.data || []).length, held: held.size };
}

/* The old daily share rows go; the trigger took one share off each post per row, so they are added back. */
async function dropOldShareDays(sb, nowIso) {
  var cutoff = daysAgo(nowIso, SHARE_DAYS_KEEP).slice(0, 10);
  var d = await sb.from("post_share_days").delete().lt("day", cutoff).select("post_id");
  if (d.error) throw d.error;
  var per = {};
  (d.data || []).forEach(function (x) { per[x.post_id] = (per[x.post_id] || 0) + 1; });
  var restored = 0;
  for (var id of Object.keys(per)) {
    var p = await sb.from("posts").select("share_count").eq("id", id).maybeSingle();
    if (p.error) throw p.error;
    if (!p.data) continue;
    var u = await sb.from("posts").update({ share_count: (Number(p.data.share_count) || 0) + per[id] }).eq("id", id);
    if (u.error) throw u.error;
    restored += per[id];
  }
  return { deleted: (d.data || []).length, restored: restored };
}

async function tick(deps) {
  var sb = deps.supabase, nowIso = (deps.now ? deps.now() : new Date()).toISOString();
  try {
    var claimed = await deps.claimDailyJob(sb, JOB_NAME, nowIso.slice(0, 10), nowIso);
    if (!claimed) return { claimed: false };
    var out = { claimed: true };
    var err = null;
    var steps = [["posts", purgePostBodies], ["comments", purgeCommentBodies], ["photos", releasePhotos], ["shares", dropOldShareDays]];
    for (var i = 0; i < steps.length; i++) {
      try { out[steps[i][0]] = await steps[i][1](sb, nowIso); } catch (e) { err = err || e; out[steps[i][0]] = null; }
    }
    await sb.from("job_runs").update({ finished_at: new Date().toISOString(), last_error: err ? String(err.code || err.message || "error").slice(0, 200) : null }).eq("job_name", JOB_NAME);
    console.log("[PostRetention] " + JSON.stringify(out) + (err ? " (with an error: " + (err.code || "error") + ")" : ""));
    return out;
  } catch (e) {
    console.error("[PostRetention] run error: " + ((e && e.code) || "error"));
    return null;
  }
}

module.exports = { JOB_NAME, BODY_PURGE_DAYS, PHOTO_RELEASE_DAYS, SHARE_DAYS_KEEP, BATCH, REMOVED_COMMENT_BODY, HOLDING_NOTICES,
  heldAmong, purgePostBodies, purgeCommentBodies, releasePhotos, dropOldShareDays, tick };
