"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   THE MODERATION QUEUE AND COPYRIGHT NOTICES (P2-2, Nov 20 2026; migration
   191). The owner's page moderation.html reads and acts through the admin
   routes in server.js (requireAuth + requireAdmin on every one); the rules are
   here.

   TABS: waiting (state waiting, or hidden by reports and not yet decided;
   priority, then oldest first), reports (open reports, newest first),
   copyright (notices, newest first), decided (newest decision first).

   AN ITEM shows the content and its link, the author and their history
   (account age, past removals, banned or not), the reports and reasons, the
   screen's findings and any copyright notices. The OWNER sees who reported;
   the author never does.

   DECISIONS: keep, hide, remove (with a note to the author). Each writes
   moderation_logs, resolves the item's open reports (actioned, or dismissed on
   keep), and notifies the author and every reporter (never naming the
   reporters to the author, nor the author's note to the reporters). "Remove and
   ban" is remove followed by the existing POST /api/admin/ban/:userId.

   COPYRIGHT: a removal for a notice tells the author they may send a
   counter-notice (copyright.html?counter=<notice>), and marks the notice
   removed (upheld). REPEAT_INFRINGER_LIMIT (3) upheld notices against one
   member bans them (users.banned_at, logged as a ban). Keep marks the notice
   rejected. A counter-notice marks it countered; lib/safety.js restoreTick
   restores the item after RESTORE_BUSINESS_DAYS business days unless the owner
   recorded that the claimant reported a court filing (courtFiled).
   ══════════════════════════════════════════════════════════════════════════ */
const SF = require("./safety");

const ACTIONS = { keep: "kept", hide: "hidden", remove: "removed" };
const TABS = ["waiting", "reports", "copyright", "decided"];
const LIST_LIMIT = 100;

const MESSAGES = {
  badTab: "tab is waiting, reports, copyright or decided.",
  badAction: "action is keep, hide or remove.",
  noteLong: "The note is at most " + SF.NOTE_MAX + " characters.",
  notFound: "That item isn't in the queue.",
  noticeNotFound: "That notice isn't available."
};

function day(iso) { return iso ? String(iso).slice(0, 10) : null; }

async function namesFor(sb, ids) {
  const list = [...new Set((ids || []).filter(SF.isUuid))];
  const out = {};
  if (!list.length) return out;
  const r = await sb.from("bf_profiles").select("user_id, username, display_name").in("user_id", list);
  if (r.error) throw r.error;
  (r.data || []).forEach(function (p) { out[p.user_id] = p.username ? "@" + p.username : (p.display_name || null); });
  return out;
}

/* The queue row of each (object_type, object_id), so a report or a notice opens its item: { "type:id": queue id }. */
async function queueIdsFor(sb, rows) {
  const out = {};
  const ids = [...new Set((rows || []).map(function (r) { return r.object_id; }).filter(SF.isUuid))];
  if (!ids.length) return out;
  const q = await sb.from("moderation_queue").select("id, object_type, object_id").in("object_id", ids);
  if (q.error) throw q.error;
  (q.data || []).forEach(function (x) { out[x.object_type + ":" + x.object_id] = x.id; });
  return out;
}

async function queueList(sb, tab) {
  if (TABS.indexOf(tab) === -1) return { status: 400, body: { error: MESSAGES.badTab } };
  if (tab === "reports") {
    const r = await sb.from("content_reports").select("id, reporter_id, object_type, object_id, owner_id, reason, detail, status, created_at")
      .eq("status", "open").order("created_at", { ascending: false }).limit(LIST_LIMIT);
    if (r.error) throw r.error;
    const names = await namesFor(sb, (r.data || []).map(function (x) { return x.reporter_id; }).concat((r.data || []).map(function (x) { return x.owner_id; })));
    const qids = await queueIdsFor(sb, r.data);
    return { status: 200, body: { tab: tab, items: (r.data || []).map(function (x) {
      return Object.assign({}, x, { reporter: names[x.reporter_id] || null, author: names[x.owner_id] || null, queue_id: qids[x.object_type + ":" + x.object_id] || null });
    }) } };
  }
  if (tab === "copyright") {
    const r = await sb.from("copyright_notices").select("id, claimant_name, claimant_email, work, object_type, object_id, status, counter_notice, created_at")
      .order("created_at", { ascending: false }).limit(LIST_LIMIT);
    if (r.error) throw r.error;
    const qids = await queueIdsFor(sb, r.data);
    return { status: 200, body: { tab: tab, items: (r.data || []).map(function (x) { return Object.assign({}, x, { queue_id: qids[x.object_type + ":" + x.object_id] || null }); }) } };
  }
  let q = sb.from("moderation_queue").select("*");
  q = tab === "waiting"
    ? q.or("state.eq.waiting,and(state.eq.hidden,decided_at.is.null)").order("priority", { ascending: true }).order("created_at", { ascending: true })
    : q.not("decided_at", "is", null).order("decided_at", { ascending: false });
  const r = await q.limit(LIST_LIMIT);
  if (r.error) throw r.error;
  const names = await namesFor(sb, (r.data || []).map(function (x) { return x.owner_id; }));
  return { status: 200, body: { tab: tab, items: (r.data || []).map(function (x) { return Object.assign({}, x, { author: names[x.owner_id] || null, auto_hidden: x.state === "hidden" && !x.decided_at }); }) } };
}

async function itemDetail(sb, id, nowIso) {
  if (!SF.isUuid(id)) return { status: 404, body: { error: MESSAGES.notFound } };
  const q = await sb.from("moderation_queue").select("*").eq("id", id).maybeSingle();
  if (q.error) throw q.error;
  if (!q.data) return { status: 404, body: { error: MESSAGES.notFound } };
  const row = q.data;
  const content = await SF.describeObject(sb, row.object_type, row.object_id);
  const ownerId = row.owner_id || (content && content.owner_id) || null;
  let author = null;
  if (ownerId) {
    const [u, removals, names] = await Promise.all([
      sb.from("users").select("id, created_at, banned_at").eq("id", ownerId).maybeSingle(),
      sb.from("moderation_queue").select("id", { count: "exact", head: true }).eq("owner_id", ownerId).eq("state", "removed"),
      namesFor(sb, [ownerId])
    ]);
    if (u.error) throw u.error;
    if (removals.error) throw removals.error;
    const created = u.data && u.data.created_at;
    author = { id: ownerId, name: names[ownerId] || null, joined: day(created),
      account_age_days: created ? Math.max(0, Math.floor((Date.parse(nowIso) - Date.parse(created)) / 86400000)) : null,
      past_removals: removals.count || 0, banned: !!(u.data && u.data.banned_at) };
  }
  const [reports, notices] = await Promise.all([
    sb.from("content_reports").select("id, reporter_id, reason, detail, status, created_at").eq("object_type", row.object_type).eq("object_id", row.object_id).order("created_at", { ascending: false }),
    sb.from("copyright_notices").select("id, claimant_name, claimant_email, work, status, counter_notice, created_at").eq("object_type", row.object_type).eq("object_id", row.object_id).order("created_at", { ascending: false })
  ]);
  if (reports.error) throw reports.error;
  if (notices.error) throw notices.error;
  const reporterNames = await namesFor(sb, (reports.data || []).map(function (r) { return r.reporter_id; }));
  return { status: 200, body: { item: Object.assign({}, row, { auto_hidden: row.state === "hidden" && !row.decided_at }),
    content: content ? { title: content.title, text: content.text, link: content.link, media: content.media } : null,
    author: author,
    reports: (reports.data || []).map(function (r) { return Object.assign({}, r, { reporter: reporterNames[r.reporter_id] || null }); }),
    findings: Array.isArray(row.screen_findings) ? row.screen_findings : [],
    notices: notices.data || [] } };
}

async function banForRepeats(sb, adminId, ownerId, nowIso) {
  const owned = await sb.from("moderation_queue").select("object_type, object_id").eq("owner_id", ownerId);
  if (owned.error) throw owned.error;
  let upheld = 0;
  for (const o of (owned.data || [])) {
    const n = await sb.from("copyright_notices").select("id", { count: "exact", head: true }).eq("object_type", o.object_type).eq("object_id", o.object_id).eq("status", "removed");
    if (n.error) throw n.error;
    upheld += n.count || 0;
  }
  if (upheld < SF.REPEAT_INFRINGER_LIMIT) return { banned: false, upheld: upheld };
  const reason = "Repeat infringement: " + upheld + " upheld copyright notices.";
  const b = await sb.from("users").update({ banned_at: nowIso, ban_reason: reason, updated_at: nowIso }).eq("id", ownerId).is("banned_at", null).select("id");
  if (b.error) throw b.error;
  if ((b.data || []).length) {
    const log = await sb.from("moderation_logs").insert({ admin_id: adminId, target_user_id: ownerId, action: "ban", reason: reason, created_at: nowIso });
    if (log.error) console.error("[moderation] AUDIT ROW LOST for the repeat-infringer ban of " + ownerId + "; THE BAN STANDS.");
  }
  return { banned: (b.data || []).length > 0, upheld: upheld };
}

const AUTHOR_TEXT = {
  kept: ["Your {noun} is visible again", "We reviewed it and it stays up."],
  hidden: ["Your {noun} is hidden", "We reviewed it and it is hidden from others for now."],
  removed: ["Your {noun} was removed", "We reviewed it and removed it, because it breaks the Terms."]
};
const REPORTER_TEXT = {
  kept: "We reviewed what you reported and it stays up, because it does not break the Terms.",
  hidden: "We reviewed what you reported and it is now hidden.",
  removed: "We reviewed what you reported and removed it."
};

async function decide(sb, opts) {
  const state = ACTIONS[opts.action];
  if (!state) return { status: 400, body: { error: MESSAGES.badAction } };
  const note = typeof opts.note === "string" ? opts.note.trim() : "";
  if (note.length > SF.NOTE_MAX) return { status: 400, body: { error: MESSAGES.noteLong } };
  if (!SF.isUuid(opts.id)) return { status: 404, body: { error: MESSAGES.notFound } };
  const q = await sb.from("moderation_queue").select("*").eq("id", opts.id).maybeSingle();
  if (q.error) throw q.error;
  if (!q.data) return { status: 404, body: { error: MESSAGES.notFound } };
  const row = q.data, nowIso = opts.nowIso;
  const upd = await sb.from("moderation_queue").update({ state: state, decided_by: opts.adminId, decided_at: nowIso, decision_note: note || null })
    .eq("id", row.id).select("*").single();
  if (upd.error) throw upd.error;
  /* NAMED (Nov 20 2026, P2-3): a decision on a post or a comment sets its own status as well (lib/posts.js applyDecision):
     keep publishes it (a new member's held post goes public), hide hides it, remove removes it (removed_at starts the
     retention clock). */
  let applied = { changed: false };
  if (row.object_type === "post" || row.object_type === "comment") applied = await require("./posts").applyDecision(sb, row, state, nowIso);
  const open = await sb.from("content_reports").select("id, reporter_id").eq("object_type", row.object_type).eq("object_id", row.object_id).eq("status", "open");
  if (open.error) throw open.error;
  if ((open.data || []).length) {
    const res = await sb.from("content_reports").update({ status: state === "kept" ? "dismissed" : "actioned", resolved_at: nowIso })
      .eq("object_type", row.object_type).eq("object_id", row.object_id).eq("status", "open");
    if (res.error) throw res.error;
  }
  const log = await sb.from("moderation_logs").insert({ admin_id: opts.adminId, target_user_id: row.owner_id || null,
    action: "moderation_" + opts.action, reason: (row.object_type + " " + row.object_id + (note ? ": " + note : "")).slice(0, 1000), created_at: nowIso });
  if (log.error) console.error("[moderation] AUDIT ROW LOST for the " + opts.action + " of " + row.object_type + " " + row.object_id + "; the decision stands.");

  // copyright notices on the item
  const notices = await sb.from("copyright_notices").select("id, status").eq("object_type", row.object_type).eq("object_id", row.object_id).in("status", ["received", "restored"]);
  if (notices.error) throw notices.error;
  const live = (notices.data || []).filter(function (n) { return n.status === "received"; });
  let counterLink = null, repeat = null;
  if (live.length && state === "removed") {
    const m = await sb.from("copyright_notices").update({ status: "removed" }).in("id", live.map(function (n) { return n.id; }));
    if (m.error) throw m.error;
    counterLink = "/copyright.html?counter=" + live[0].id;
    if (row.owner_id) repeat = await banForRepeats(sb, opts.adminId, row.owner_id, nowIso);
  } else if (live.length && state === "kept") {
    const m = await sb.from("copyright_notices").update({ status: "rejected" }).in("id", live.map(function (n) { return n.id; }));
    if (m.error) throw m.error;
  }

  // the author: told what was decided and the note; never who reported
  const wasHidden = row.state === "hidden" || row.state === "removed";
  if (row.owner_id && !(state === "kept" && !wasHidden)) {
    const t = AUTHOR_TEXT[state];
    let message = t[1] + (note ? " " + note : "");
    if (counterLink) message += " If you think this is a mistake, you can send a counter-notice.";
    await SF.notify(sb, SF.itemNotice(row.owner_id, row.object_type, row.object_id, t[0].replace("{noun}", SF.nounFor(row.object_type)), message.slice(0, 1000), counterLink));
  }
  // NAMED (Nov 20 2026, P2-3): a held post that was approved: its author is told it is public now
  if (row.owner_id && applied.published) {
    await SF.notify(sb, SF.itemNotice(row.owner_id, row.object_type, row.object_id, "Your post is up", "We reviewed it and it is public now.", applied.link));
  }
  // every reporter: told the outcome, not the author's note
  const reporters = [...new Set((open.data || []).map(function (r) { return r.reporter_id; }).filter(SF.isUuid))];
  for (const id of reporters) {
    await SF.notify(sb, { user_id: id, type: "moderation", title: "Your report was reviewed", message: REPORTER_TEXT[state], read: false, link: "/inbox.html?tab=notifications" });
  }
  return { status: 200, body: { item: upd.data, reports_resolved: (open.data || []).length, reporters_told: reporters.length,
    counter_notice_link: counterLink, repeat_infringer: repeat } };
}

/* The owner records that the claimant reported a court filing: the item is not restored. */
async function courtFiled(sb, noticeId, adminId, nowIso) {
  if (!SF.isUuid(noticeId)) return { status: 404, body: { error: MESSAGES.noticeNotFound } };
  const n = await sb.from("copyright_notices").select("id, status, counter_notice").eq("id", noticeId).maybeSingle();
  if (n.error) throw n.error;
  if (!n.data || n.data.status !== "countered") return { status: 404, body: { error: MESSAGES.noticeNotFound } };
  const c = Object.assign({}, n.data.counter_notice || {}, { court_filed: true, court_filed_at: nowIso });
  const u = await sb.from("copyright_notices").update({ counter_notice: c }).eq("id", noticeId);
  if (u.error) throw u.error;
  const log = await sb.from("moderation_logs").insert({ admin_id: adminId, target_user_id: null, action: "copyright_court_filed", reason: "notice " + noticeId, created_at: nowIso });
  if (log.error) console.error("[moderation] AUDIT ROW LOST for the court filing on notice " + noticeId + ".");
  return { status: 200, body: { court_filed: true } };
}

/* Where a notice points: { object_type, object_id, owner_id } or null. */
async function resolveLocation(sb, where) {
  if (where.object_type === "listing") {
    const q = sb.from("marketplace_listings").select("id, seller_id");
    const r = await (SF.isUuid(where.key) ? q.eq("id", where.key) : q.eq("slug", where.key)).maybeSingle();
    if (r.error) throw r.error;
    return r.data ? { object_type: "listing", object_id: r.data.id, owner_id: r.data.seller_id } : null;
  }
  if (where.object_type === "campaign") {
    const r = await sb.from("crowdfunding_campaigns").select("id, owner_id").eq("share_id", where.share_id).maybeSingle();
    if (r.error) throw r.error;
    return r.data ? { object_type: "campaign", object_id: r.data.id, owner_id: r.data.owner_id } : null;
  }
  if (where.object_type === "profile") {
    const r = await sb.from("bf_profiles").select("user_id").ilike("username", where.handle).maybeSingle();
    if (r.error) throw r.error;
    return r.data ? { object_type: "profile", object_id: r.data.user_id, owner_id: r.data.user_id } : null;
  }
  return null;
}

async function submitNotice(sb, body, nowIso) {
  const v = SF.validateNotice(body);
  if (v.error) return { status: 400, body: { error: v.error, field: v.field } };
  const target = await resolveLocation(sb, v.where);
  if (!target) return { status: 404, body: { error: "We couldn't find that on BizForce. Check the link and try again.", field: "location" } };
  // the table keeps the contact details the notice must carry inside the work field, labelled, when given
  const work = (v.work + (v.address ? "\n\nClaimant address: " + v.address : "") + (v.phone ? "\nClaimant phone: " + v.phone : "") +
    "\n\nWhere: " + v.location + "\nAccuracy statement confirmed under penalty of perjury.").slice(0, 4000);
  const ins = await sb.from("copyright_notices").insert({ claimant_name: v.name, claimant_email: v.email, work: work,
    object_type: target.object_type, object_id: target.object_id, good_faith: true, signature: v.signature, counter_notice: null,
    status: "received", created_at: nowIso }).select("id").single();
  if (ins.error) throw ins.error;
  await SF.raiseQueue(sb, { object_type: target.object_type, object_id: target.object_id, owner_id: target.owner_id, source: "copyright_notice", priority: 1, reports: 0 }, nowIso);
  return { status: 201, body: { received: true, id: ins.data && ins.data.id, message: SF.COPYRIGHT_MESSAGES.received } };
}

async function ownedNotice(sb, userId, noticeId) {
  if (!SF.isUuid(noticeId)) return null;
  const n = await sb.from("copyright_notices").select("id, object_type, object_id, work, status, counter_notice, created_at").eq("id", noticeId).maybeSingle();
  if (n.error) throw n.error;
  if (!n.data) return null;
  const item = await SF.describeObject(sb, n.data.object_type, n.data.object_id);
  let owner = item && item.owner_id;
  if (!owner) {
    const q = await sb.from("moderation_queue").select("owner_id").eq("object_type", n.data.object_type).eq("object_id", n.data.object_id).maybeSingle();
    if (q.error) throw q.error;
    owner = q.data && q.data.owner_id;
  }
  if (owner !== userId) return null;
  return { notice: n.data, item: item };
}

async function counterView(sb, userId, noticeId) {
  const o = await ownedNotice(sb, userId, noticeId);
  if (!o) return { status: 404, body: { error: SF.COPYRIGHT_MESSAGES.counterNotYours } };
  return { status: 200, body: { notice: { id: o.notice.id, status: o.notice.status, received: day(o.notice.created_at), object_type: o.notice.object_type,
    title: o.item ? o.item.title : null, work: String(o.notice.work || "").split("\n\n")[0], countered: o.notice.status === "countered" } } };
}

async function submitCounter(sb, userId, noticeId, body, nowIso) {
  const o = await ownedNotice(sb, userId, noticeId);
  if (!o) return { status: 404, body: { error: SF.COPYRIGHT_MESSAGES.counterNotYours } };
  if (o.notice.status !== "removed") return { status: 409, body: { error: SF.COPYRIGHT_MESSAGES.counterState } };
  const v = SF.validateCounter(body);
  if (v.error) return { status: 400, body: { error: v.error, field: v.field } };
  const counter = { name: v.name, address: v.address, phone: v.phone || null, statement: v.statement, signature: v.signature,
    perjury: true, consent: true, received_at: nowIso, court_filed: false };
  const u = await sb.from("copyright_notices").update({ counter_notice: counter, status: "countered" }).eq("id", noticeId).eq("status", "removed").select("id");
  if (u.error) throw u.error;
  if (!(u.data || []).length) return { status: 409, body: { error: SF.COPYRIGHT_MESSAGES.counterState } };
  const log = await sb.from("moderation_logs").insert({ admin_id: null, target_user_id: userId, action: "copyright_counter_notice", reason: "notice " + noticeId, created_at: nowIso });
  if (log.error) console.error("[moderation] AUDIT ROW LOST for the counter-notice on notice " + noticeId + ".");
  return { status: 200, body: { countered: true, message: SF.COPYRIGHT_MESSAGES.counterReceived } };
}

module.exports = { ACTIONS, TABS, LIST_LIMIT, MESSAGES, AUTHOR_TEXT, REPORTER_TEXT, queueList, itemDetail, decide, banForRepeats, courtFiled,
  resolveLocation, submitNotice, counterView, submitCounter };
