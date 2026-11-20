"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   SAFETY (P2-2, Nov 20 2026; migration 191): reports, blocks, mutes, the
   moderation queue, copyright notices and their retention. server.js holds the
   routes; the rules are here so the checks can run them.

   BLOCKS work both ways and silently: neither member sees the other's profile
   or storefront, can message, send BizCash to, support, buy from or donate to
   the other, and the blocked member is never told. Every refusal says only
   NOT_AVAILABLE. MUTES hide someone from the muter's lists and Home's People only.

   REPORTS: REASONS (13), DETAIL_MAX (1000) characters of detail, 20 an hour (the
   route's limiter), one OPEN report per member per item (the partial unique
   index content_reports_once; a second is a 409). A report raises the item's
   moderation_queue row or creates it; minor_safety and copyright are priority 1.
   AUTO-HIDE: AUTO_HIDE_REPORTERS (3) distinct open reporters, or one minor_safety
   report, hides the item until the owner decides: the queue row's state becomes
   "hidden" with no decided_at (it stays in the Waiting tab), and the author is
   told it is under review, never by whom. Public reads leave out every item whose
   queue state is hidden or removed (hiddenAmong).

   The lookups that guard a page (blockedEitherWay, blockedIds, mutedIds,
   hiddenAmong) compare the ids they get back, so a row about anyone else never
   counts, and on a database error they log one line and let the page work as if
   there were no block or hide: a failed lookup must not take messages down.
   ══════════════════════════════════════════════════════════════════════════ */

const REASONS = ["spam", "harassment", "hate", "sexual", "minor_safety", "violence", "health_claim", "prohibited_item",
  "scam", "copyright", "impersonation", "privacy", "other"];
const OBJECT_TYPES = ["post", "comment", "profile", "listing", "campaign", "message", "review"];
// what exists to report today; posts, comments and reviews arrive with their tables (P2-3, P2-7)
const REPORTABLE_NOW = ["profile", "listing", "campaign", "message"];
const PRIORITY_ONE = ["minor_safety", "copyright"];
const AUTO_HIDE_REPORTERS = 3;
const DETAIL_MAX = 1000;
const NOTE_MAX = 1000;
const REPORTS_PER_HOUR = 20;
const BLOCKS_PER_HOUR = 60;
const REPORT_RETENTION_DAYS = 365;
const COPYRIGHT_RETENTION_DAYS = 3 * 365;
const RESTORE_BUSINESS_DAYS = 10;
const REPEAT_INFRINGER_LIMIT = 3;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NOTIFY_OBJECT_TYPES = ["listing", "campaign", "message"];   // the ones notifications.object_type accepts (migration 190)
const RETENTION_JOB_NAME = "safety_retention";
const RESTORE_JOB_NAME = "copyright_restore";

const MESSAGES = {
  notAvailable: "This isn't available.",
  badType: "You can report a profile, a listing, a campaign or a message.",
  badId: "That isn't something you can report.",
  badReason: "Choose one of the reasons.",
  detailLong: "The detail is at most " + DETAIL_MAX + " characters.",
  notFound: "That isn't available to report.",
  ownItem: "You can't report your own.",
  already: "You have already reported this. It is waiting for review.",
  reported: "Thanks. Your report was sent. We review every report; the person you reported is never told who sent it.",
  self: "You can't block or mute yourself.",
  noMember: "That member isn't available.",
  rateLimited: "You can send " + REPORTS_PER_HOUR + " reports an hour. Try again later.",
  blockLimited: "Too many changes to who you block or mute. Try again in an hour."
};

function isUuid(v) { return typeof v === "string" && UUID_RE.test(v); }

/* A report's body: { object_type, object_id, reason, detail }. */
function validateReport(body) {
  body = body || {};
  if (REPORTABLE_NOW.indexOf(body.object_type) === -1) return { error: MESSAGES.badType, field: "object_type" };
  if (!isUuid(body.object_id)) return { error: MESSAGES.badId, field: "object_id" };
  if (REASONS.indexOf(body.reason) === -1) return { error: MESSAGES.badReason, field: "reason" };
  var detail = body.detail === undefined || body.detail === null ? "" : body.detail;
  if (typeof detail !== "string") return { error: MESSAGES.badReason, field: "detail" };
  detail = detail.trim();
  if (detail.length > DETAIL_MAX) return { error: MESSAGES.detailLong, field: "detail" };
  return { object_type: body.object_type, object_id: body.object_id.toLowerCase(), reason: body.reason, detail: detail || null };
}

function priorityFor(reason) { return PRIORITY_ONE.indexOf(reason) !== -1 ? 1 : 2; }

/* Auto-hide: AUTO_HIDE_REPORTERS distinct open reporters, or any minor_safety report. */
function shouldAutoHide(openReports) {
  var reporters = {};
  var minor = false;
  (openReports || []).forEach(function (r) {
    if (r.reporter_id) reporters[r.reporter_id] = true;
    if (r.reason === "minor_safety") minor = true;
  });
  return minor || Object.keys(reporters).length >= AUTO_HIDE_REPORTERS;
}

function logLookup(what, error) {
  console.error("[safety] " + what + " lookup failed (" + ((error && (error.code || error.message)) || "error") + "); the page was served as if there were none.");
}

/* True when a has blocked b or b has blocked a. */
async function blockedEitherWay(sb, a, b) {
  if (!isUuid(a) || !isUuid(b) || a === b) return false;
  try {
    var r = await sb.from("member_blocks").select("blocker_id, blocked_id")
      .or("and(blocker_id.eq." + a + ",blocked_id.eq." + b + "),and(blocker_id.eq." + b + ",blocked_id.eq." + a + ")").limit(2);
    if (r.error) { logLookup("block", r.error); return false; }
    return (Array.isArray(r.data) ? r.data : []).some(function (row) {
      return row && ((row.blocker_id === a && row.blocked_id === b) || (row.blocker_id === b && row.blocked_id === a));
    });
  } catch (e) { logLookup("block", e); return false; }
}

/* Every member userId has blocked or is blocked by. */
async function blockedIds(sb, userId) {
  var out = new Set();
  if (!isUuid(userId)) return out;
  try {
    var r = await sb.from("member_blocks").select("blocker_id, blocked_id")
      .or("blocker_id.eq." + userId + ",blocked_id.eq." + userId).limit(5000);
    if (r.error) { logLookup("blocks", r.error); return out; }
    (Array.isArray(r.data) ? r.data : []).forEach(function (row) {
      if (!row) return;
      if (row.blocker_id === userId && isUuid(row.blocked_id)) out.add(row.blocked_id);
      else if (row.blocked_id === userId && isUuid(row.blocker_id)) out.add(row.blocker_id);
    });
  } catch (e) { logLookup("blocks", e); }
  return out;
}

/* Every member userId has muted. */
async function mutedIds(sb, userId) {
  var out = new Set();
  if (!isUuid(userId)) return out;
  try {
    var r = await sb.from("member_mutes").select("muter_id, muted_id").eq("muter_id", userId).limit(5000);
    if (r.error) { logLookup("mutes", r.error); return out; }
    (Array.isArray(r.data) ? r.data : []).forEach(function (row) { if (row && row.muter_id === userId && isUuid(row.muted_id)) out.add(row.muted_id); });
  } catch (e) { logLookup("mutes", e); }
  return out;
}

/* Of these ids of one object type, the ones hidden or removed by moderation. */
async function hiddenAmong(sb, objectType, ids) {
  var out = new Set();
  var list = (ids || []).filter(isUuid);
  if (!list.length) return out;
  try {
    var r = await sb.from("moderation_queue").select("object_type, object_id, state")
      .eq("object_type", objectType).in("object_id", list).in("state", ["hidden", "removed"]);
    if (r.error) { logLookup("moderation", r.error); return out; }
    (Array.isArray(r.data) ? r.data : []).forEach(function (row) {
      if (row && row.object_type === objectType && (row.state === "hidden" || row.state === "removed") && list.indexOf(row.object_id) !== -1) out.add(row.object_id);
    });
  } catch (e) { logLookup("moderation", e); }
  return out;
}

/* Who owns a reportable item, and what the moderation page shows of it. null when it does not exist. */
async function describeObject(sb, type, id) {
  if (!isUuid(id)) return null;
  if (type === "profile") {
    var u = await sb.from("users").select("id").eq("id", id).maybeSingle();
    if (u.error) throw u.error;
    if (!u.data) return null;
    var p = await sb.from("bf_profiles").select("username, display_name, tagline, bio").eq("user_id", id).maybeSingle();
    if (p.error) throw p.error;
    var pd = p.data || {};
    return { owner_id: id, title: pd.display_name || (pd.username ? "@" + pd.username : "A member"),
      text: [pd.tagline, pd.bio].filter(Boolean).join("\n"), link: pd.username ? "/@" + pd.username : null, media: [] };
  }
  if (type === "listing") {
    var l = await sb.from("marketplace_listings").select("id, seller_id, title, description, slug, media").eq("id", id).maybeSingle();
    if (l.error) throw l.error;
    if (!l.data) return null;
    return { owner_id: l.data.seller_id, title: l.data.title || "A listing", text: l.data.description || "",
      link: "/listing/" + (l.data.slug || l.data.id), media: Array.isArray(l.data.media) ? l.data.media : [] };
  }
  if (type === "campaign") {
    var c = await sb.from("crowdfunding_campaigns").select("id, owner_id, title, description, share_id, share_on, media").eq("id", id).maybeSingle();
    if (c.error) throw c.error;
    if (!c.data) return null;
    return { owner_id: c.data.owner_id, title: c.data.title || "A campaign", text: c.data.description || "",
      link: c.data.share_on === true && c.data.share_id ? "/campaign/" + c.data.share_id : null, media: Array.isArray(c.data.media) ? c.data.media : [] };
  }
  if (type === "message") {
    var m = await sb.from("messages").select("id, sender_id, receiver_id, content").eq("id", id).maybeSingle();
    if (m.error) throw m.error;
    if (!m.data) return null;
    return { owner_id: m.data.sender_id, receiver_id: m.data.receiver_id, title: "A message", text: m.data.content || "", link: null, media: [] };
  }
  return null;
}

function nounFor(type) { return { profile: "profile", listing: "listing", campaign: "campaign", message: "message" }[type] || "item"; }

/* A notice about an item. Only the object types notifications accepts are named on it. */
function itemNotice(userId, type, objectId, title, message, link) {
  var n = { user_id: userId, type: "moderation", title: title, message: message, read: false, link: link || "/inbox.html?tab=notifications" };
  if (NOTIFY_OBJECT_TYPES.indexOf(type) !== -1) { n.object_type = type; n.object_id = objectId; }
  return n;
}

async function notify(sb, notice) {
  try {
    var r = await sb.from("notifications").insert(notice);
    if (r.error) console.warn("[safety] a notice could not be written (" + (r.error.code || "error") + "); the action stands.");
  } catch (e) { console.warn("[safety] a notice could not be written; the action stands."); }
}

/* Add to or raise an item's queue row. A row the owner kept goes back to waiting when something new arrives; a removed
   row stays removed. Returns the row. */
async function raiseQueue(sb, item, nowIso) {
  var existing = await sb.from("moderation_queue").select("*").eq("object_type", item.object_type).eq("object_id", item.object_id).maybeSingle();
  if (existing.error) throw existing.error;
  var row = existing.data;
  if (!row) {
    var fresh = { object_type: item.object_type, object_id: item.object_id, owner_id: item.owner_id || null, source: item.source,
      priority: item.priority || 2, report_count: item.reports || 0, screen_findings: item.findings || null, state: "waiting", created_at: nowIso };
    var ins = await sb.from("moderation_queue").insert(fresh).select("*").single();
    if (ins.error && ins.error.code !== "23505") throw ins.error;
    if (!ins.error) return ins.data;
    var again = await sb.from("moderation_queue").select("*").eq("object_type", item.object_type).eq("object_id", item.object_id).maybeSingle();
    if (again.error) throw again.error;
    row = again.data;
  }
  var patch = { priority: Math.min(Number(row.priority) || 2, item.priority || 2), report_count: (Number(row.report_count) || 0) + (item.reports || 0) };
  if (item.findings) patch.screen_findings = (Array.isArray(row.screen_findings) ? row.screen_findings : []).concat(item.findings);
  if (row.state === "kept") { patch.state = "waiting"; patch.decided_at = null; patch.decided_by = null; }
  var upd = await sb.from("moderation_queue").update(patch).eq("id", row.id).select("*").single();
  if (upd.error) throw upd.error;
  return upd.data;
}

/* The content screen found something unclear: the item is saved, and waits in the queue (source policy_screen). */
async function queueScreenFindings(sb, item, findings, nowIso) {
  try {
    return await raiseQueue(sb, { object_type: item.object_type, object_id: item.object_id, owner_id: item.owner_id, source: "policy_screen",
      priority: 2, reports: 0, findings: findings }, nowIso);
  } catch (e) {
    console.error("[safety] the screen's findings for " + item.object_type + " " + item.object_id + " could not be queued (" + ((e && e.code) || "error") + ").");
    return null;
  }
}

/* File a report. Returns { status, body }. */
async function fileReport(sb, reporterId, body, nowIso) {
  var v = validateReport(body);
  if (v.error) return { status: 400, body: { error: v.error, field: v.field } };
  var item = await describeObject(sb, v.object_type, v.object_id);
  if (!item) return { status: 404, body: { error: MESSAGES.notFound } };
  if (v.object_type === "message" && item.receiver_id !== reporterId) return { status: 404, body: { error: MESSAGES.notFound } };
  if (item.owner_id === reporterId) return { status: 400, body: { error: MESSAGES.ownItem } };
  var ins = await sb.from("content_reports").insert({ reporter_id: reporterId, object_type: v.object_type, object_id: v.object_id,
    owner_id: item.owner_id || null, reason: v.reason, detail: v.detail, status: "open", created_at: nowIso }).select("id").single();
  if (ins.error) {
    if (ins.error.code === "23505") return { status: 409, body: { error: MESSAGES.already, reason: "already_reported" } };
    throw ins.error;
  }
  var row = await raiseQueue(sb, { object_type: v.object_type, object_id: v.object_id, owner_id: item.owner_id, source: "report",
    priority: priorityFor(v.reason), reports: 1 }, nowIso);
  var open = await sb.from("content_reports").select("reporter_id, reason").eq("object_type", v.object_type).eq("object_id", v.object_id).eq("status", "open");
  if (open.error) throw open.error;
  var hidden = false;
  if (row && row.state === "waiting" && shouldAutoHide(open.data)) {
    var h = await sb.from("moderation_queue").update({ state: "hidden", decided_at: null, decided_by: null }).eq("id", row.id).eq("state", "waiting").select("id");
    if (h.error) throw h.error;
    hidden = (h.data || []).length > 0;
    if (hidden && item.owner_id) {
      await notify(sb, itemNotice(item.owner_id, v.object_type, v.object_id, "Your " + nounFor(v.object_type) + " is under review",
        "It was reported and is hidden while we review it. We will tell you what we decide.", null));
    }
  }
  return { status: 201, body: { reported: true, message: MESSAGES.reported, id: ins.data && ins.data.id, hidden: hidden } };
}

/* ── Copyright notices ──────────────────────────────────────────────────── */
const NOTICE_LIMITS = { name: 200, email: 254, work: 2000, location: 500, signature: 200, address: 500, phone: 40 };
const COPYRIGHT_MESSAGES = {
  missing: function (what) { return "Fill in " + what + "."; },
  email: "Give an email address we can reach you at.",
  where: "Give the BizForce link to the material (a listing, a campaign, a profile or a storefront).",
  goodFaith: "Confirm the good-faith statement.",
  accuracy: "Confirm the accuracy statement, under penalty of perjury.",
  long: function (what, n) { return what + " is at most " + n + " characters."; },
  received: "Your notice was received. We review it and will reply by email.",
  rateLimited: "You can send 5 notices an hour. Try again later.",
  counterReceived: "Your counter-notice was received. Unless the person who complained tells us they have gone to court, the material is restored after 10 business days.",
  counterNotYours: "That counter-notice isn't available.",
  counterState: "A counter-notice can be sent only after the material was removed for this notice."
};

/* Where on BizForce: a link the site serves, resolved to an object. */
function locateObject(where) {
  var s = String(where || "").trim();
  var m = /(?:^|bizforceai\.net)\/listing\/([a-z0-9-]{1,100})/i.exec(s);
  if (m) return { object_type: "listing", key: m[1] };
  m = /(?:^|bizforceai\.net)\/campaign\/([a-z0-9]{8,64})/i.exec(s);
  if (m) return { object_type: "campaign", share_id: m[1] };
  m = /(?:^|bizforceai\.net)\/@([a-z0-9_-]{3,30})/i.exec(s);
  if (m) return { object_type: "profile", handle: m[1].toLowerCase() };
  m = /seller\.html\?u=([a-z0-9_-]{3,30})/i.exec(s);
  if (m) return { object_type: "profile", handle: m[1].toLowerCase() };
  return null;
}

function trimmed(v) { return typeof v === "string" ? v.trim() : ""; }

function validateNotice(body) {
  body = body || {};
  var out = { name: trimmed(body.name), email: trimmed(body.email), work: trimmed(body.work), location: trimmed(body.location),
    address: trimmed(body.address), phone: trimmed(body.phone), signature: trimmed(body.signature) };
  var labels = { name: "your full name", email: "your email address", work: "the work you own", location: "where it is on BizForce", signature: "your signature (type your full name)" };
  var keys = ["name", "email", "work", "location", "signature"];
  for (var i = 0; i < keys.length; i++) if (!out[keys[i]]) return { error: COPYRIGHT_MESSAGES.missing(labels[keys[i]]), field: keys[i] };
  for (var k in NOTICE_LIMITS) if (out[k] && out[k].length > NOTICE_LIMITS[k]) return { error: COPYRIGHT_MESSAGES.long(k, NOTICE_LIMITS[k]), field: k };
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(out.email)) return { error: COPYRIGHT_MESSAGES.email, field: "email" };
  var where = locateObject(out.location);
  if (!where) return { error: COPYRIGHT_MESSAGES.where, field: "location" };
  if (body.good_faith !== true) return { error: COPYRIGHT_MESSAGES.goodFaith, field: "good_faith" };
  if (body.accuracy !== true) return { error: COPYRIGHT_MESSAGES.accuracy, field: "accuracy" };
  out.where = where;
  return out;
}

function validateCounter(body) {
  body = body || {};
  var out = { name: trimmed(body.name), address: trimmed(body.address), phone: trimmed(body.phone), statement: trimmed(body.statement), signature: trimmed(body.signature) };
  if (!out.name) return { error: COPYRIGHT_MESSAGES.missing("your full name"), field: "name" };
  if (!out.address) return { error: COPYRIGHT_MESSAGES.missing("your address"), field: "address" };
  if (!out.statement) return { error: COPYRIGHT_MESSAGES.missing("why the material was removed by mistake"), field: "statement" };
  if (!out.signature) return { error: COPYRIGHT_MESSAGES.missing("your signature (type your full name)"), field: "signature" };
  if (out.statement.length > 2000) return { error: COPYRIGHT_MESSAGES.long("The statement", 2000), field: "statement" };
  if (out.name.length > 200 || out.signature.length > 200 || out.address.length > 500 || out.phone.length > 40) return { error: "One of the fields is too long.", field: "name" };
  if (body.perjury !== true) return { error: "Confirm the statement under penalty of perjury.", field: "perjury" };
  if (body.consent !== true) return { error: "Confirm that you consent to the court's jurisdiction and accept service.", field: "consent" };
  return out;
}

/* Business days (Monday to Friday, UTC) from a to b. */
function businessDaysBetween(aIso, bIso) {
  var a = new Date(aIso), b = new Date(bIso);
  if (!(a < b)) return 0;
  var d = new Date(Date.UTC(a.getUTCFullYear(), a.getUTCMonth(), a.getUTCDate()));
  var end = Date.UTC(b.getUTCFullYear(), b.getUTCMonth(), b.getUTCDate());
  var n = 0;
  while (d.getTime() < end) {
    d.setUTCDate(d.getUTCDate() + 1);
    var w = d.getUTCDay();
    if (w !== 0 && w !== 6) n++;
  }
  return n;
}

/* A countered notice whose material may be restored: RESTORE_BUSINESS_DAYS business days since the counter-notice, and no
   court filing recorded. */
function restoreDue(notice, nowIso) {
  var c = notice && notice.counter_notice;
  if (!notice || notice.status !== "countered" || !c || !c.received_at) return false;
  if (c.court_filed === true) return false;
  return businessDaysBetween(c.received_at, nowIso) >= RESTORE_BUSINESS_DAYS;
}

function daysAgoIso(nowIso, days) { return new Date(Date.parse(nowIso) - days * 86400000).toISOString(); }

/* The yearly retention, a step of the 04:45 UTC chain (job_runs safety_retention): resolved reports and decided queue
   items older than a year, and copyright notices older than three years, are deleted. Never throws. */
async function retentionTick(deps) {
  var sb = deps.supabase, nowIso = (deps.now ? deps.now() : new Date()).toISOString();
  try {
    var claimed = await deps.claimDailyJob(sb, RETENTION_JOB_NAME, nowIso.slice(0, 10), nowIso);
    if (!claimed) return { claimed: false };
    var yearAgo = daysAgoIso(nowIso, REPORT_RETENTION_DAYS), threeYearsAgo = daysAgoIso(nowIso, COPYRIGHT_RETENTION_DAYS);
    var reports = await sb.from("content_reports").delete().neq("status", "open").lt("resolved_at", yearAgo).select("id");
    var queue = await sb.from("moderation_queue").delete().in("state", ["kept", "hidden", "removed"]).not("decided_at", "is", null).lt("decided_at", yearAgo).select("id");
    var notices = await sb.from("copyright_notices").delete().lt("created_at", threeYearsAgo).select("id");
    var err = reports.error || queue.error || notices.error;
    await sb.from("job_runs").update({ finished_at: new Date().toISOString(), last_error: err ? String(err.code || "error") : null }).eq("job_name", RETENTION_JOB_NAME);
    var out = { claimed: true, reports: (reports.data || []).length, queue: (queue.data || []).length, notices: (notices.data || []).length };
    console.log("[SafetyRetention] deleted " + out.reports + " resolved reports, " + out.queue + " decided queue items, " + out.notices + " copyright notices" + (err ? " (with an error: " + (err.code || "error") + ")" : "") + ".");
    return out;
  } catch (e) {
    console.error("[SafetyRetention] run error: " + ((e && e.code) || "error"));
    return null;
  }
}

/* The counter-notice restore, a step of the 04:45 UTC chain (job_runs copyright_restore): each countered notice past
   RESTORE_BUSINESS_DAYS business days with no court filing recorded has its material restored (the queue row kept),
   the notice marked restored, and the member told. Never throws. */
async function restoreTick(deps) {
  var sb = deps.supabase, nowIso = (deps.now ? deps.now() : new Date()).toISOString();
  try {
    var claimed = await deps.claimDailyJob(sb, RESTORE_JOB_NAME, nowIso.slice(0, 10), nowIso);
    if (!claimed) return { claimed: false };
    var due = await sb.from("copyright_notices").select("id, object_type, object_id, status, counter_notice").eq("status", "countered").limit(500);
    if (due.error) throw due.error;
    var restored = 0;
    for (var i = 0; i < (due.data || []).length; i++) {
      var n = due.data[i];
      if (!restoreDue(n, nowIso)) continue;
      var q = await sb.from("moderation_queue").update({ state: "kept", decided_at: nowIso, decided_by: null,
        decision_note: "Restored after a counter-notice (no court filing reported)." })
        .eq("object_type", n.object_type).eq("object_id", n.object_id).eq("state", "removed").select("owner_id");
      if (q.error) throw q.error;
      var s = await sb.from("copyright_notices").update({ status: "restored" }).eq("id", n.id).eq("status", "countered");
      if (s.error) throw s.error;
      var owner = (q.data || [])[0] && q.data[0].owner_id;
      if (owner) await notify(sb, itemNotice(owner, n.object_type, n.object_id, "Your " + nounFor(n.object_type) + " is back",
        "It was restored after your counter-notice, because no court filing was reported to us.", null));
      restored++;
    }
    await sb.from("job_runs").update({ finished_at: new Date().toISOString(), last_error: null }).eq("job_name", RESTORE_JOB_NAME);
    console.log("[CopyrightRestore] restored " + restored + " item(s).");
    return { claimed: true, restored: restored };
  } catch (e) {
    console.error("[CopyrightRestore] run error: " + ((e && e.code) || "error"));
    return null;
  }
}

module.exports = {
  REASONS, OBJECT_TYPES, REPORTABLE_NOW, PRIORITY_ONE, AUTO_HIDE_REPORTERS, DETAIL_MAX, NOTE_MAX, REPORTS_PER_HOUR, BLOCKS_PER_HOUR,
  REPORT_RETENTION_DAYS, COPYRIGHT_RETENTION_DAYS, RESTORE_BUSINESS_DAYS, REPEAT_INFRINGER_LIMIT, RETENTION_JOB_NAME, RESTORE_JOB_NAME,
  MESSAGES, COPYRIGHT_MESSAGES, NOTICE_LIMITS,
  isUuid, validateReport, priorityFor, shouldAutoHide, blockedEitherWay, blockedIds, mutedIds, hiddenAmong, describeObject, nounFor,
  itemNotice, notify, raiseQueue, queueScreenFindings, fileReport, locateObject, validateNotice, validateCounter, businessDaysBetween,
  restoreDue, retentionTick, restoreTick
};
