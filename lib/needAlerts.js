"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   NEED ALERTS (P3-3, Nov 23 2026; migration 202): Need-to-Offer matching
   inside BizForce, the start of Lead Radar's internal side.

   WHO OFFERS IN A CATEGORY (offerersIn, offeredBy): a member with an active
   Market listing or service filed under it (marketplace_listings.category_slug,
   status active), or a published Offer post in it in the last OFFER_DAYS (90).

   WHEN A NEED IS PUBLISHED (alertNeed, run by lib/posts.js after the post is
   saved; it never delays or fails the post, and a failure is logged): the
   post must be a Need, published (the content screen passed), public (which
   already needed a confirmed email), with a category, and not Found. Then:
     the candidates are the members who offer in its category, never the
     poster, never anyone who blocked or is blocked by the poster (an
     unreadable block list sends nothing), never a free account (deps.tierOf),
     never anyone who turned "Need alerts in my categories" off
     (user_preferences.need_alerts false; NULL reads as on), and never anyone
     who has had PER_MEMBER_DAY (20) Need alerts in the last day;
     with a place, members whose profile city (bf_profiles.place_city) is the
     Need's city (its text up to the first comma), case-insensitive, are
     preferred: if any of them qualifies only they are told, else the
     category's members are;
     at most PER_NEED (10), the most recently active first.
   ONCE ONLY (NAMED (Nov 23 2026, P3-3B)): a Need may become published and public more than once (published at once, approved from
   moderation, or edited from Followers to Public); its alerts are sent the first time only. The record is the
   notifications table itself: if any need_alert row already names the post (object_type post, object_id its id),
   nothing more is sent (reason already_sent). An unreadable record sends nothing (it throws; the caller logs it).
   Each is ONE in-app notification (the notifications table, type need_alert):
   "[Name] needs help in [Category]: [the first 80 characters]", linking to the
   post. Lead Radar's consent rule: no email, no SMS, no push, no message is
   sent by this feature; nothing is sent to anyone outside BizForce.
   ══════════════════════════════════════════════════════════════════════════ */
const SF = require("./safety");

const TYPE = "need_alert";
const PER_NEED = 10;
const PER_MEMBER_DAY = 20;
const OFFER_DAYS = 90;
const PREVIEW_CHARS = 80;
const SCAN = 500;          // listings and offer posts read per category
const TIER_LOOKS = 60;     // members whose tier is read per Need, at most
const DAY = 86400000;

function ago(nowIso, ms) { return new Date(Date.parse(nowIso) - ms).toISOString(); }
function cityOf(place) { return String(place || "").split(",")[0].replace(/\s+/g, " ").trim().toLowerCase(); }
function preview(body) { return Array.from(String(body || "").replace(/\s+/g, " ").trim()).slice(0, PREVIEW_CHARS).join(""); }
function later(a, b) { return !a ? b : !b ? a : (Date.parse(b) > Date.parse(a) ? b : a); }

/* { userId: the latest offer activity } for one category. A read error throws. */
async function offerersIn(sb, slug, nowIso) {
  const since = ago(nowIso, OFFER_DAYS * DAY);
  const r = await Promise.all([
    sb.from("marketplace_listings").select("seller_id, updated_at, created_at").eq("category_slug", slug).eq("status", "active").limit(SCAN),
    sb.from("posts").select("author_id, published_at").eq("intent", "offer").eq("category", slug).eq("status", "published").gt("published_at", since).limit(SCAN)
  ]);
  if (r[0].error) throw r[0].error;
  if (r[1].error) throw r[1].error;
  const out = {};
  (r[0].data || []).forEach(function (l) { if (SF.isUuid(l.seller_id)) out[l.seller_id] = later(out[l.seller_id], l.updated_at || l.created_at || null); });
  (r[1].data || []).forEach(function (p) { if (SF.isUuid(p.author_id)) out[p.author_id] = later(out[p.author_id], p.published_at || null); });
  return out;
}

/* The categories one member offers in (a Set of slugs). A read error throws. */
async function offeredBy(sb, userId, nowIso) {
  const out = new Set();
  if (!SF.isUuid(userId)) return out;
  const since = ago(nowIso, OFFER_DAYS * DAY);
  const r = await Promise.all([
    sb.from("marketplace_listings").select("category_slug").eq("seller_id", userId).eq("status", "active").limit(SCAN),
    sb.from("posts").select("category").eq("author_id", userId).eq("intent", "offer").eq("status", "published").gt("published_at", since).limit(SCAN)
  ]);
  if (r[0].error) throw r[0].error;
  if (r[1].error) throw r[1].error;
  (r[0].data || []).forEach(function (l) { if (l.category_slug) out.add(l.category_slug); });
  (r[1].data || []).forEach(function (p) { if (p.category) out.add(p.category); });
  return out;
}

/* Everyone the poster blocked or is blocked by. Unlike lib/safety.js blockedIds this FAILS CLOSED: an unreadable list throws. */
async function blockSet(sb, posterId) {
  const r = await sb.from("member_blocks").select("blocker_id, blocked_id").or("blocker_id.eq." + posterId + ",blocked_id.eq." + posterId).limit(5000);
  if (r.error) throw r.error;
  const out = new Set();
  (r.data || []).forEach(function (row) {
    if (row && row.blocker_id === posterId) out.add(row.blocked_id);
    if (row && row.blocked_id === posterId) out.add(row.blocker_id);
  });
  return out;
}

/* Members (of these) who turned Need alerts off. A read error throws. */
async function switchedOff(sb, ids) {
  const out = new Set();
  if (!ids.length) return out;
  const r = await sb.from("user_preferences").select("user_id, need_alerts").in("user_id", ids);
  if (r.error) throw r.error;
  (r.data || []).forEach(function (p) { if (p && p.need_alerts === false) out.add(p.user_id); });
  return out;
}

/* Need alerts this member has had in the last day; null when it cannot be read (then none is sent to them). */
async function alertsToday(sb, userId, nowIso) {
  const r = await sb.from("notifications").select("id", { count: "exact", head: true }).eq("user_id", userId).eq("type", TYPE).gt("created_at", ago(nowIso, DAY));
  if (r.error || typeof r.count !== "number") return null;
  return r.count;
}

async function citiesOf(sb, ids) {
  const out = {};
  if (!ids.length) return out;
  const r = await sb.from("bf_profiles").select("user_id, place_city").in("user_id", ids);
  if (r.error) throw r.error;
  (r.data || []).forEach(function (p) { if (p && p.user_id) out[p.user_id] = cityOf(p.place_city); });
  return out;
}

/* NAMED (Nov 23 2026, P3-3B): whether this Need's alerts were already sent (any need_alert row naming the post). A read error throws. */
async function alreadySent(sb, postId) {
  const r = await sb.from("notifications").select("id", { count: "exact", head: true }).eq("type", TYPE).eq("object_type", "post").eq("object_id", postId);
  if (r.error) throw r.error;
  if (typeof r.count !== "number") throw new Error("need_alert count unreadable");
  return r.count > 0;
}

/* deps = { sb, now(), tierOf(userId), names(ids) -> { id: name }, categoryName(slug) }. post: the saved posts row.
   Answers { sent, to: [ids], reason } and never throws for a reason it can name; a read error throws (the caller logs it). */
async function alertNeed(deps, post) {
  if (!post || post.intent !== "need") return { sent: 0, to: [], reason: "not_need" };
  if (post.status !== "published") return { sent: 0, to: [], reason: "not_published" };
  if (post.audience !== "public") return { sent: 0, to: [], reason: "not_public" };
  if (post.need_found_at) return { sent: 0, to: [], reason: "found" };
  if (!post.category) return { sent: 0, to: [], reason: "no_category" };
  if (await alreadySent(deps.sb, post.id)) return { sent: 0, to: [], reason: "already_sent" };   // NAMED (Nov 23 2026, P3-3B)
  const sb = deps.sb, at = deps.now ? deps.now() : new Date().toISOString(), poster = post.author_id;
  const active = await offerersIn(sb, post.category, at);
  const blocked = await blockSet(sb, poster);
  let ids = Object.keys(active).filter(function (id) { return id !== poster && !blocked.has(id); });
  const off = await switchedOff(sb, ids);
  ids = ids.filter(function (id) { return !off.has(id); });
  ids.sort(function (a, b) { return (Date.parse(active[b]) || 0) - (Date.parse(active[a]) || 0) || (a < b ? -1 : a > b ? 1 : 0); });
  const city = cityOf(post.need_place);
  let near = [], rest = ids;
  if (city) {
    const cities = await citiesOf(sb, ids);
    near = ids.filter(function (id) { return cities[id] === city; });
    rest = ids.filter(function (id) { return cities[id] !== city; });
  }
  let looks = 0;
  async function qualified(group) {
    const out = [];
    for (let i = 0; i < group.length && out.length < PER_NEED && looks < TIER_LOOKS; i++) {
      looks++;
      let tier = null;
      try { tier = deps.tierOf ? await deps.tierOf(group[i]) : null; } catch (e) { tier = null; }
      if (tier !== "member") continue;
      const n = await alertsToday(sb, group[i], at);
      if (n === null || n >= PER_MEMBER_DAY) continue;
      out.push(group[i]);
    }
    return out;
  }
  let to = await qualified(near);
  if (!to.length) to = await qualified(rest);
  if (!to.length) return { sent: 0, to: [], reason: "no_match" };
  const names = deps.names ? await deps.names([poster]) : {};
  const who = names[poster] || "A member";
  const cat = (deps.categoryName ? await deps.categoryName(post.category) : null) || post.category;
  const rows = to.map(function (id) {
    return { user_id: id, type: TYPE, title: "A Need in " + cat, message: who + " needs help in " + cat + ": " + preview(post.body), read: false,
      actor_id: poster, object_type: "post", object_id: post.id, link: "/home.html?post=" + post.id, created_at: at };
  });
  const ins = await sb.from("notifications").insert(rows);
  if (ins.error) throw ins.error;
  return { sent: rows.length, to: to, reason: city && to.some(function (id) { return near.indexOf(id) !== -1; }) ? "place" : "category" };
}

module.exports = { TYPE, PER_NEED, PER_MEMBER_DAY, OFFER_DAYS, PREVIEW_CHARS, TIER_LOOKS, cityOf, preview, offerersIn, offeredBy, alreadySent, alertNeed };
