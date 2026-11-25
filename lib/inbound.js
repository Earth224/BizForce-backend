"use strict";
/* ═════════════════════════════════════════════════════════════════════════════
   INBOUND (LR-3, Nov 24 2026): everything coming TO a member, in one list (inbound_items, migration 205), which the
   member moves New, Talking, Won or Lost on Lead Radar's Inbound tab (lib/inboundRoutes.js).

   ONE ENTRY POINT. Every item is written here, by the action that caused it, after that action has succeeded:
     message     POST /api/messages: the FIRST message in a conversation someone else started (one item per
                 conversation, never per message; migration 205c's partial unique index holds it)
     i_can_help  POST /api/messages: a message that links the receiver's own open Need (/p/<id>, as the feed's
                 I can help always does), in place of a message item
     sale        POST /api/marketplace/listings/:id/buy: the order, for its seller (won at once)
     card_lead   POST /api/cards/lead: the lead, for the card's owner
     campaign    POST /api/crowdfunding/campaigns/:id/donate: the donation, for the campaign's owner (won at once)
     tip         POST /api/wallet/support: the BizCash support, for the member it went to (won at once)
     lead_reply  GET /api/social/bluesky/mentions: a reply to a reply the member posted through Lead Radar
                 (member_lead_replies.platform_uri); the linked member_lead becomes replied unless won or lost
   A writer NEVER throws and is never awaited by the route that calls it (fire), so it never delays or fails the
   action: a failure is logged and the item is simply missing. unique (user_id, kind, source_id) makes every writer
   and the backfill (scripts/oneoff/lr3Backfill.js) safe to run again. NEVER FOR THE MEMBER'S OWN ACTIONS: an item
   whose other person is the member is never written.

   WHAT IS KEPT. Who (a short name: "Ana P.", "@handle", or "a buyer", "a supporter", "your digital card"), a summary
   of at most 200 characters, the BizCash amount, the status. A Bluesky reply keeps the replier's handle and never the
   text of their post.

   TELLING THE MEMBER. A sale and a donation now leave an in-app notice (type sale, object_type order; type donation,
   object_type campaign) and a Web Push, the way a like or a comment does. No email, no SMS. A card lead keeps its own
   hourly-capped notice; a message, a tip and an I can help keep theirs.
   ═════════════════════════════════════════════════════════════════════════════ */

const KINDS = ["message", "i_can_help", "sale", "card_lead", "campaign", "tip", "lead_reply"];
const STATUSES = ["new", "talking", "won", "lost"];
const WON_AT_ONCE = ["sale", "campaign", "tip"];
const CONVERSATION_KINDS = ["message", "i_can_help"];
const SUMMARY_MAX = 200;
const LABEL_MAX = 80;
const LIST_PAGE = 30;
const LIST_MAX = 100;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NEED_LINK_RE = /\/p\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?![0-9a-f-])/i;
const KIND_LABELS = { message: "Message", i_can_help: "I can help", sale: "Sale", card_lead: "Card lead", campaign: "Campaign", tip: "Tip", lead_reply: "Reply" };
const STATUS_LABELS = { new: "New", talking: "Talking", won: "Won", lost: "Lost" };
const LABEL = { buyer: "a buyer", supporter: "a supporter", card: "your digital card", member: "a member" };
const GENERIC_LABELS = [LABEL.buyer, LABEL.supporter, LABEL.card, LABEL.member];
const FIELDS = "id, user_id, kind, source_id, counterpart_user_id, counterpart_label, summary, amount_bfc, status, customer_id, created_at, updated_at";
const TABLE = "inbound_items";

function isUuid(v) { return typeof v === "string" && UUID_RE.test(v); }
function nowIso() { return new Date().toISOString(); }
function warn(what, err) { console.warn("[inbound] " + what + " (" + ((err && (err.code || err.message)) || "error") + "); the action stands."); }

/* Text kept short and on one line; "..." when cut. */
function clip(s, n) {
  const t = String(s == null ? "" : s).replace(/\s+/g, " ").trim();
  return t.length > n ? t.slice(0, n - 3).trimEnd() + "..." : t;
}
/* "Ana Perez" -> "Ana P."; a handle or a single word stays as it is. */
function shortName(name) {
  const s = clip(name, LABEL_MAX);
  if (!s) return LABEL.member;
  if (s.charAt(0) === "@") return s;
  const parts = s.split(" ");
  if (parts.length < 2) return s;
  return clip(parts[0] + " " + parts[parts.length - 1].charAt(0).toUpperCase() + ".", LABEL_MAX);
}
function bfc(n) { return Number(n).toLocaleString("en-US") + " BFC"; }
function amountOf(n) { const v = Number(n); return Number.isInteger(v) && v > 0 ? v : null; }

/* The row for one item, or null when it must not be written (an unknown kind, a bad id, the member's own action). */
function itemRow(o) {
  const x = o || {};
  if (KINDS.indexOf(x.kind) === -1 || !isUuid(x.userId) || !isUuid(x.sourceId)) return null;
  const other = isUuid(x.counterpartId) ? x.counterpartId : null;
  if (other && other === x.userId) return null;
  const at = typeof x.at === "string" && !isNaN(Date.parse(x.at)) ? new Date(x.at).toISOString() : nowIso();
  return {
    user_id: x.userId, kind: x.kind, source_id: x.sourceId, counterpart_user_id: other,
    counterpart_label: clip(x.label, LABEL_MAX) || LABEL.member, summary: clip(x.summary, SUMMARY_MAX),
    amount_bfc: amountOf(x.amount), status: WON_AT_ONCE.indexOf(x.kind) !== -1 ? "won" : "new",
    created_at: at, updated_at: at
  };
}

/* Writes one item. { created, id } or { created: false, reason: skipped | exists | error }. Never throws. */
async function record(sb, row) {
  if (!row) return { created: false, reason: "skipped" };
  try {
    const r = await sb.from(TABLE).insert(row).select("id").single();
    if (r.error) {
      if (r.error.code === "23505") return { created: false, reason: "exists" };
      warn("an item could not be written", r.error);
      return { created: false, reason: "error" };
    }
    return { created: true, id: r.data && r.data.id };
  } catch (e) { warn("an item could not be written", e); return { created: false, reason: "error" }; }
}

/* Runs a writer without the caller waiting on it. */
function fire(p) { if (p && typeof p.then === "function") p.then(null, function (e) { warn("a writer failed", e); }); return p; }

async function nameOf(sb, userId) {
  const [bf, legacy] = await Promise.all([
    sb.from("bf_profiles").select("user_id, username, display_name").eq("user_id", userId).maybeSingle(),
    sb.from("profiles").select("user_id, full_name, business_name").eq("user_id", userId).maybeSingle()
  ]);
  const b = (bf && !bf.error && bf.data) || {}, l = (legacy && !legacy.error && legacy.data) || {};
  return b.display_name || l.business_name || l.full_name || (b.username ? "@" + b.username : LABEL.member);
}

/* The receiver's own open Need that a message links (/p/<id>), or null. */
function needLinkIn(content) { const m = NEED_LINK_RE.exec(String(content || "")); return m ? m[1].toLowerCase() : null; }
async function needFor(sb, content, receiverId, categoryName) {
  const id = needLinkIn(content);
  if (!id) return null;
  const r = await sb.from("posts").select("id, author_id, intent, category").eq("id", id).maybeSingle();
  if (r.error || !r.data || r.data.author_id !== receiverId || r.data.intent !== "need") return null;
  let cat = null;
  try { cat = r.data.category && typeof categoryName === "function" ? await categoryName(r.data.category) : null; } catch (e) { cat = null; }
  return { id: r.data.id, category: cat };
}
function needSummary(need) { return "Replied to your Need" + (need && need.category ? " in " + need.category : "") + "."; }

/* ── the plans (read only: the row an action makes, or null) and the writers (record(plan)) ──
   The backfill's dry run calls the plans alone, so it never writes. */

/* opts.categoryName(slug) -> name (optional). Reads the Need a message links, the sender's name, and whether the two
   have messaged before. { row } or { row: null, reason }. */
async function planMessage(sb, msg, opts) {
  const m = msg || {};
  if (!isUuid(m.id) || !isUuid(m.sender_id) || !isUuid(m.receiver_id) || m.sender_id === m.receiver_id) return { row: null, reason: "skipped" };
  const need = await needFor(sb, m.content, m.receiver_id, opts && opts.categoryName);
  const label = shortName(await nameOf(sb, m.sender_id));
  if (need) return { row: itemRow({ userId: m.receiver_id, kind: "i_can_help", sourceId: m.id, counterpartId: m.sender_id, label: label, summary: needSummary(need), at: m.created_at }) };
  // the first message between the two, either way: any earlier one means the conversation already began
  const pair = "and(sender_id.eq." + m.sender_id + ",receiver_id.eq." + m.receiver_id + "),and(sender_id.eq." + m.receiver_id + ",receiver_id.eq." + m.sender_id + ")";
  let q = sb.from("messages").select("id").or(pair).neq("id", m.id);
  if (m.created_at) q = q.lte("created_at", m.created_at);
  const earlier = await q.limit(1);
  if (earlier.error) throw earlier.error;
  if ((earlier.data || []).length) return { row: null, reason: "not_first" };
  return { row: itemRow({ userId: m.receiver_id, kind: "message", sourceId: m.id, counterpartId: m.sender_id, label: label, summary: m.content, at: m.created_at }) };
}
async function fromMessage(sb, msg, opts) {
  try {
    const p = await planMessage(sb, msg, opts);
    return p.row ? await record(sb, p.row) : { created: false, reason: p.reason };
  } catch (e) { warn("a message item could not be written", e); return { created: false, reason: "error" }; }
}

function planOrder(order) {
  const o = order || {};
  if (!isUuid(o.seller_id) || o.buyer_id === o.seller_id) return null;
  const amount = amountOf(o.amount_bfc);
  return itemRow({ userId: o.seller_id, kind: "sale", sourceId: o.id, counterpartId: o.buyer_id, label: LABEL.buyer,
    summary: "Bought: " + clip(o.listing_title || "a listing", 120) + (amount ? " · " + bfc(amount) : ""), amount: amount, at: o.created_at });
}
async function fromOrder(sb, order) {
  try { return await record(sb, planOrder(order)); } catch (e) { warn("a sale item could not be written", e); return { created: false, reason: "error" }; }
}

function cardLeadSummary(lead) {
  const l = lead || {}, left = [];
  if (l.phone) left.push("a phone number");
  if (l.email) left.push("an email");
  const msg = clip(l.message, 150);
  if (!left.length) return msg ? "Wrote: " + msg : "Left their details.";
  return "Left " + left.join(" and ") + (msg ? ": " + msg : ".");
}
function planCardLead(lead) {
  const l = lead || {};
  return itemRow({ userId: l.user_id, kind: "card_lead", sourceId: l.id, counterpartId: null, label: LABEL.card, summary: cardLeadSummary(l), at: l.created_at });
}
async function fromCardLead(sb, lead) {
  try { return await record(sb, planCardLead(lead)); } catch (e) { warn("a card lead item could not be written", e); return { created: false, reason: "error" }; }
}

function planDonation(donation, campaignTitle) {
  const d = donation || {};
  if (!isUuid(d.owner_id) || d.donor_id === d.owner_id) return null;
  const amount = amountOf(d.amount_bfc);
  return itemRow({ userId: d.owner_id, kind: "campaign", sourceId: d.id, counterpartId: d.donor_id, label: LABEL.supporter,
    summary: "Gave " + (amount ? bfc(amount) : "BizCash") + " to " + clip(campaignTitle || "your campaign", 120) + ".", amount: amount, at: d.created_at });
}
async function fromDonation(sb, donation, campaignTitle) {
  try {
    const d = donation || {};
    let title = campaignTitle;
    if (!title && isUuid(d.campaign_id)) {
      const c = await sb.from("crowdfunding_campaigns").select("title").eq("id", d.campaign_id).maybeSingle();
      title = c && !c.error && c.data ? c.data.title : null;
    }
    return await record(sb, planDonation(d, title));
  } catch (e) { warn("a campaign item could not be written", e); return { created: false, reason: "error" }; }
}

/* senderLabel: "@username" when known, else the sender's short name. */
function planTip(transfer, senderLabel) {
  const t = transfer || {};
  if (!isUuid(t.recipient_id) || t.sender_id === t.recipient_id) return null;
  const amount = amountOf(t.amount_bfc);
  const note = clip(t.note, 140);
  return itemRow({ userId: t.recipient_id, kind: "tip", sourceId: t.id, counterpartId: t.sender_id, label: senderLabel || LABEL.member,
    summary: "Sent you " + (amount ? bfc(amount) : "BizCash") + (note ? ": " + note : "."), amount: amount, at: t.created_at });
}
async function fromTip(sb, transfer, senderUsername) {
  try {
    const t = transfer || {};
    if (!isUuid(t.recipient_id) || t.sender_id === t.recipient_id) return { created: false, reason: "skipped" };
    const label = senderUsername ? "@" + senderUsername : shortName(await nameOf(sb, t.sender_id));
    return await record(sb, planTip(t, label));
  } catch (e) { warn("a tip item could not be written", e); return { created: false, reason: "error" }; }
}

/* The replies among a listNotifications page: { parent, handle, at } for each reason "reply" with a parent post. */
function replyParents(notifications) {
  return (Array.isArray(notifications) ? notifications : []).map(function (n) {
    if (!n || n.reason !== "reply" || !n.record || !n.record.reply || !n.record.reply.parent) return null;
    const parent = n.record.reply.parent.uri;
    if (typeof parent !== "string" || parent.indexOf("at://") !== 0 || parent.length > 600) return null;
    const handle = n.author && typeof n.author.handle === "string" && /^[A-Za-z0-9.-]{1,253}$/.test(n.author.handle) ? n.author.handle : null;
    return { parent: parent, handle: handle, at: typeof n.indexedAt === "string" ? n.indexedAt : null };
  }).filter(Boolean);
}
/* Each reply to one of the member's own Lead Radar replies becomes a lead_reply item (one per reply of theirs), and the
   linked member_lead becomes replied unless it is already won, lost or replied. { created, matched } */
async function fromMentions(sb, userId, notifications) {
  const out = { created: 0, matched: 0 };
  try {
    if (!isUuid(userId)) return out;
    const found = replyParents(notifications);
    if (!found.length) return out;
    const uris = Array.from(new Set(found.map(function (f) { return f.parent; })));
    const r = await sb.from("member_lead_replies").select("id, member_lead_id, platform_uri").eq("user_id", userId).eq("platform", "bluesky").in("platform_uri", uris);
    if (r.error) { warn("the member's replies could not be read", r.error); return out; }
    for (const reply of (r.data || [])) {
      const f = found.find(function (x) { return x.parent === reply.platform_uri; });
      if (!f) continue;
      out.matched++;
      const w = await record(sb, itemRow({ userId: userId, kind: "lead_reply", sourceId: reply.id, counterpartId: null,
        label: f.handle ? "@" + f.handle : "someone on Bluesky", summary: "Replied to your reply on Bluesky.", at: f.at }));
      if (w.created) out.created++;
      if (isUuid(reply.member_lead_id)) {
        const u = await sb.from("member_leads").update({ status: "replied" }).eq("id", reply.member_lead_id).eq("user_id", userId).not("status", "in", "(won,lost,replied)");
        if (u.error) warn("the lead could not be marked replied", u.error);
      }
    }
  } catch (e) { warn("lead replies could not be written", e); }
  return out;
}

/* ── telling the member: a sale and a donation (in-app, plus push the way a like or a comment does) ── */
function saleNotice(order) {
  const o = order || {}, amount = amountOf(o.amount_bfc);
  return { user_id: o.seller_id, type: "sale", title: "You made a sale",
    message: "Someone bought " + clip(o.listing_title || "your listing", 120) + (amount ? " for " + bfc(amount) : "") + ".",
    object_type: "order", object_id: isUuid(o.id) ? o.id : null, link: "/receipts.html" };
}
function donationNotice(donation, campaignTitle) {
  const d = donation || {}, amount = amountOf(d.amount_bfc);
  return { user_id: d.owner_id, type: "donation", title: "Someone gave to your campaign",
    message: (amount ? bfc(amount) : "BizCash") + " to " + clip(campaignTitle || "your campaign", 120) + ".",
    object_type: "campaign", object_id: isUuid(d.campaign_id) ? d.campaign_id : null, link: "/campaigns.html" };
}
/* Writes the notice, then pushes it. Never throws. push(userId, { title, body, url }) */
async function notify(sb, push, row) {
  if (!row || !isUuid(row.user_id)) return false;
  try {
    const ins = await sb.from("notifications").insert(Object.assign({ read: false, created_at: nowIso() }, row));
    if (ins.error) { warn("a notice could not be written", ins.error); return false; }
  } catch (e) { warn("a notice could not be written", e); return false; }
  if (typeof push === "function") {
    try { await push(row.user_id, { title: row.title, body: row.message, url: row.link || "/inbox.html?tab=notifications" }); }
    catch (e) { warn("a push could not be sent", e); }
  }
  return true;
}

/* ── what the screens see ── */
function bskyLink(atUri) {
  const m = /^at:\/\/(did:[a-z]+:[A-Za-z0-9._:%-]+)\/app\.bsky\.feed\.post\/([A-Za-z0-9._~-]+)$/.exec(String(atUri || ""));
  return m ? "https://bsky.app/profile/" + m[1] + "/post/" + m[2] : null;
}
/* Where tapping an item goes: the conversation, the order, the card lead, the campaign, the wallet, the reply. */
function openFor(item, replyUri) {
  const i = item || {};
  if (CONVERSATION_KINDS.indexOf(i.kind) !== -1) return { href: isUuid(i.counterpart_user_id) ? "/inbox.html?with=" + i.counterpart_user_id : "/inbox.html", external: false };
  if (i.kind === "sale") return { href: "/receipts.html", external: false };
  if (i.kind === "card_lead") return { href: "/digital-cards.html#cardLeadsTitle", external: false };
  if (i.kind === "campaign") return { href: "/campaigns.html", external: false };
  if (i.kind === "tip") return { href: "/wallet.html", external: false };
  const link = bskyLink(replyUri);
  return link ? { href: link, external: true } : { href: "/agents/lead-radar.html", external: false };
}
function view(item, replyUri) {
  const i = item || {};
  return {
    id: i.id, kind: i.kind, kind_label: KIND_LABELS[i.kind] || "Item", who: i.counterpart_label || LABEL.member, summary: i.summary || "",
    amount_bfc: i.amount_bfc == null ? null : i.amount_bfc, status: i.status, status_label: STATUS_LABELS[i.status] || "",
    created_at: i.created_at, updated_at: i.updated_at, open: openFor(i, replyUri),
    customer_added: !!i.customer_id, can_add_customer: i.status === "won" && !i.customer_id
  };
}

/* The member's items per status. */
async function counts(sb, userId) {
  const r = await Promise.all(STATUSES.map(function (s) {
    return sb.from(TABLE).select("id", { count: "exact", head: true }).eq("user_id", userId).eq("status", s);
  }));
  const out = {};
  STATUSES.forEach(function (s, i) { if (r[i].error) throw r[i].error; out[s] = r[i].count || 0; });
  return out;
}

/* The Leads tab's "won": member_leads won, plus Inbound items won, counting once a lead_reply item won whose linked
   member_lead is also won (the same conversation). */
async function wonCount(sb, userId) {
  const [leads, items] = await Promise.all([
    sb.from("member_leads").select("id", { count: "exact", head: true }).eq("user_id", userId).eq("status", "won"),
    sb.from(TABLE).select("id", { count: "exact", head: true }).eq("user_id", userId).eq("status", "won")
  ]);
  if (leads.error) throw leads.error;
  if (items.error) throw items.error;
  const replies = await sb.from(TABLE).select("source_id").eq("user_id", userId).eq("status", "won").eq("kind", "lead_reply").limit(1000);
  if (replies.error) throw replies.error;
  let both = 0;
  const ids = (replies.data || []).map(function (r) { return r.source_id; });
  if (ids.length) {
    const links = await sb.from("member_lead_replies").select("member_lead_id").eq("user_id", userId).in("id", ids);
    if (links.error) throw links.error;
    const leadIds = Array.from(new Set((links.data || []).map(function (l) { return l.member_lead_id; }).filter(isUuid)));
    if (leadIds.length) {
      const wonToo = await sb.from("member_leads").select("id", { count: "exact", head: true }).eq("user_id", userId).eq("status", "won").in("id", leadIds);
      if (wonToo.error) throw wonToo.error;
      both = wonToo.count || 0;
    }
  }
  return (leads.count || 0) + (items.count || 0) - both;
}

/* "Add to my customers": the crm_customers row a won item makes (the existing table, the member's own). */
function customerFields(item, cardLead) {
  const i = item || {}, c = cardLead || {};
  const label = clip(i.counterpart_label, 150);
  const generic = !label || GENERIC_LABELS.indexOf(label) !== -1;
  const name = i.kind === "card_lead" && c.name ? clip(c.name, 150) : generic ? (label ? label.charAt(0).toUpperCase() + label.slice(1) : "A customer") : label;
  return {
    name: name,
    email: i.kind === "card_lead" && c.email ? clip(c.email, 320) : null,
    phone: i.kind === "card_lead" && c.phone ? clip(c.phone, 40) : null,
    status: "active",
    source: "Lead Radar Inbound: " + (KIND_LABELS[i.kind] || "Item"),
    notes: clip(i.summary, SUMMARY_MAX) || null
  };
}

module.exports = {
  KINDS, STATUSES, WON_AT_ONCE, CONVERSATION_KINDS, SUMMARY_MAX, LABEL_MAX, LIST_PAGE, LIST_MAX, KIND_LABELS, STATUS_LABELS, LABEL, FIELDS, TABLE,
  NEED_LINK_RE, isUuid, clip, shortName, itemRow, record, fire, needLinkIn, needSummary, cardLeadSummary,
  planMessage, planOrder, planCardLead, planDonation, planTip, fromMessage, fromOrder, fromCardLead, fromDonation, fromTip, replyParents, fromMentions, nameOf,
  saleNotice, donationNotice, notify, bskyLink, openFor, view, counts, wonCount, customerFields
};
