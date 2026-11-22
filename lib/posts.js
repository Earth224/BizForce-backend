"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   POSTS AND THE SOCIAL GRAPH (P2-3, Nov 20 2026; migrations 193 and 194).
   server.js holds thin routes; every rule is here, so the checks run it
   against a fake database. deps = { sb, now() (an ISO string), claims (the
   server's health-claims screen, passed to lib/contentPolicy.js), ownerPublic
   (userId -> true while that member's pages are public: ownerPagePublic),
   push (userId, payload -> Web Push to the member's own subscribed devices;
   a member who never opted in has none), env }.

   POSTS. Kinds now: text and photo (KINDS_NOW); every other kind is refused
   until its block. A body is at most BODY_MAX (2200) characters and goes
   through the content policy screen: a refusal is its one sentence; an
   unclear match saves the post as pending with a moderation queue item
   (source policy_screen). Everything else is published at once.
   NAMED (Nov 20 2026, P3-1, instant use): BEFORE a member whose account was
   younger than the BizCash hold (7 days) posted as pending with a queue item
   (source new_member). AFTER there is no posting hold: a new account posts at
   once, still through the content screen, reports and auto-hide. Old
   new_member queue rows stay readable. A PUBLIC post needs a confirmed email
   (users.email_verified_at, lib/emailVerification.js): 403 email_unverified,
   nothing saved; a followers-only post does not. The audience is
   public or followers. The place is copied from the author's profile only
   while "Show my posts in Local" (local_opt_in) is on. Ten posts a day.
   Edit (the body only, the author only) is screened again; a finding sends
   the post back to pending. Delete (the author) marks it removed; its photos
   stay linked for PHOTO_KEEP_DAYS (30), then lib/postRetention.js releases
   them to the media library's own rules.

   WHO SEES A POST (canSee). Its author, unless removed. Anyone else only when
   it is published, moderation has not hidden it, neither has blocked the
   other, the author's pages are public, and it is public or they follow the
   author. Feeds also leave out members the viewer muted.

   THE FOLLOWING FEED. Posts by people the viewer follows and the viewer's
   own, newest first, FEED_PAGE (10) at a time with a cursor
   (published_at, id). Under FIND_PEOPLE_UNDER (3) follows it carries
   suggestions: members with a public page, Verified first (P3-2, lib/verified.js),
   then those with recent posts.

   TALK. Comments oldest first, one level of replies (a reply to a reply
   joins the top comment), 1000 characters, screened (an unclear match is
   published and queued), 60 an hour. The author deletes their own (a
   tombstone, "[deleted]", keeps the replies in place); the post's author can
   hide a comment on their own post.

   LIKE (200 an hour), SAVE, SHARE (one counted share per member per post per
   day, post_share_days) and FOLLOW (100 a day). The counts on a post are kept
   by migration 194's triggers. A block either way refuses every one of them
   with NOT_AVAILABLE, and a new block removes the follows between the two.

   NOTICES. A like (grouped: one notice per post per LIKE_GROUP_MS, its text
   counting the likes since), a comment, a reply, a follow, and moderation
   decisions (lib/moderation.js), each with actor_id, object_type, object_id
   and link. A Web Push goes with each new notice to the devices the member
   subscribed (a grouped like pushes only once).
   ══════════════════════════════════════════════════════════════════════════ */
const CP = require("./contentPolicy");
const SF = require("./safety");
const IN = require("./inbox");
const MM = require("./memberMedia");

const KINDS_NOW = ["text", "photo"];
const KINDS_ALL = ["text", "photo", "video", "product", "service", "listing", "campaign", "garage", "card"];
const AUDIENCES = ["public", "followers"];
const BODY_MAX = 2200;
const COMMENT_MAX = 1000;
/* NAMED (Nov 21 2026, P3-1B): a post's intent (migration 200: share, offer, need) and a member's search fields (posts.search_visible,
   seo_title under 71 characters, seo_description under 161). An offer post is members only (selling). */
const INTENTS = ["share", "offer", "need"];
const SEO_TITLE_MAX = 70;
const SEO_DESCRIPTION_MAX = 160;
const PHOTOS_MAX = 4;
const FEED_PAGE = 10;
const FEED_SCAN = 30;
const LIST_PAGE = 30;
const COMMENTS_PAGE = 100;
const PEOPLE_PAGE = 50;
const POSTS_PER_DAY = 10;
const COMMENTS_PER_HOUR = 60;
const LIKES_PER_HOUR = 200;
const FOLLOWS_PER_DAY = 100;
const FIND_PEOPLE_UNDER = 3;
const SUGGEST_MAX = 8;
const SUGGEST_RECENT_DAYS = 30;
const LIKE_GROUP_MS = 60 * 60 * 1000;
const PHOTO_KEEP_DAYS = 30;
const DELETED_BODY = "[deleted]";
const HOUR = 3600000, DAY = 86400000;
// NAMED (Nov 21 2026, FX2): + listing_id (migration 193), so a post that carries a linked listing shows its product strip
const POST_COLUMNS = "id, author_id, kind, body, audience, status, place_city, place_region, place_country, like_count, comment_count, save_count, share_count, created_at, published_at, removed_at, listing_id, intent, search_visible, seo_title, seo_description";   // NAMED (Nov 21 2026, P3-1B): + intent and the search fields (migration 200)
const COMMENT_COLUMNS = "id, post_id, author_id, parent_id, body, status, created_at";

const MESSAGES = {
  notAvailable: SF.MESSAGES.notAvailable,
  kind: "Only text and photo posts can be made now. Other kinds of post arrive later.",
  audience: "Choose who sees it: public or followers.",
  bodyType: "The post's text must be text.",
  bodyLong: "A post is at most " + BODY_MAX + " characters.",
  textEmpty: "Write something to post.",
  photosNone: "A photo post needs at least one photo.",
  photosMany: "A post has at most " + PHOTOS_MAX + " photos.",
  textPhotos: "A text post has no photos. Choose a photo post to add them.",
  postsDay: "You can make " + POSTS_PER_DAY + " posts a day. Try again tomorrow.",
  commentEmpty: "Write something to send.",
  commentLong: "A comment is at most " + COMMENT_MAX + " characters.",
  commentsHour: "You can send " + COMMENTS_PER_HOUR + " comments an hour. Try again later.",
  likesHour: "You can like " + LIKES_PER_HOUR + " posts an hour. Try again later.",
  followsDay: "You can follow " + FOLLOWS_PER_DAY + " members a day. Try again tomorrow.",
  pending: "Your post was saved and is waiting for review. It goes public once it is approved.",
  published: "Your post is up.",
  editPending: "Your change was saved and is waiting for review before others see it.",
  self: "You can't follow yourself.",
  noMember: "That member isn't available.",
  cursor: "That page marker isn't valid.",
  notYours: "That isn't yours to change.",
  removed: "Your post was deleted.",
  commentGone: "That comment isn't available.",
  // NAMED (Nov 21 2026, P3-1B)
  intent: "Choose what the post is: share, offer or need.",
  offerMembers: "Offer posts are for members: selling is part of membership. Nothing was posted.",
  listingBad: "That listing isn't one of your active listings. Nothing was posted.",
  seoTitle: "A search title is at most " + SEO_TITLE_MAX + " characters.",
  seoDescription: "A search description is at most " + SEO_DESCRIPTION_MAX + " characters.",
  searchType: "Show in Google is on or off.",
  searchMembers: "Showing a post in Google is for members. Nothing was changed."
};

function now(deps) { return deps.now ? deps.now() : new Date().toISOString(); }
function ago(deps, ms) { return new Date(Date.parse(now(deps)) - ms).toISOString(); }
function chars(s) { return Array.from(String(s)).length; }
function isUuid(v) { return SF.isUuid(v); }
function screenText(deps, fields) { return CP.screenFields(fields, { claims: deps.claims, surface: "public" }); }
function fail(status, error, extra) { return { status: status, body: Object.assign({ error: error }, extra || {}) }; }
function notAvailable() { return fail(404, MESSAGES.notAvailable, { reason: "not_available" }); }

/* ── cursors: "<iso>_<uuid>" ── */
function encodeCursor(at, id) { return at && id ? String(at) + "_" + id : null; }
function decodeCursor(raw) {
  if (raw === undefined || raw === null || raw === "") return { none: true };
  var s = String(raw), i = s.lastIndexOf("_");
  if (i < 1 || s.length > 80) return null;
  var at = s.slice(0, i), id = s.slice(i + 1);
  if (isNaN(Date.parse(at)) || !isUuid(id)) return null;
  return { at: at, id: id };
}
/* A timestamp inside an or() filter, double-quoted: it holds ":" and may hold "+". */
function quoted(at) { return '"' + String(at) + '"'; }
/* Rows newer-first by (col, id), after the cursor. */
function afterCursor(q, col, c) {
  if (!c || c.none) return q;
  return q.or(col + ".lt." + quoted(c.at) + ",and(" + col + ".eq." + quoted(c.at) + ",id.lt." + c.id + ")");
}

/* ── counts for the rate limits ── */
async function countSince(sb, table, col, id, sinceIso) {
  var r = await sb.from(table).select(col, { count: "exact", head: true }).eq(col, id).gt("created_at", sinceIso);
  if (r.error) throw r.error;
  if (typeof r.count !== "number") throw new Error(table + " count unavailable");
  return r.count;
}

/* ── the viewer's relations, read once per request ── */
async function viewerContext(deps, viewerId) {
  var ctx = { viewer: isUuid(viewerId) ? viewerId : null, blocked: new Set(), muted: new Set(), following: new Set(), publicCache: {} };
  if (!ctx.viewer) return ctx;
  var r = await Promise.all([SF.blockedIds(deps.sb, ctx.viewer), SF.mutedIds(deps.sb, ctx.viewer), followingIds(deps.sb, ctx.viewer)]);
  ctx.blocked = r[0]; ctx.muted = r[1]; ctx.following = r[2];
  return ctx;
}
async function followingIds(sb, userId) {
  var out = new Set();
  var r = await sb.from("follows").select("follower_id, following_id").eq("follower_id", userId).limit(5000);
  if (r.error) throw r.error;
  (r.data || []).forEach(function (f) { if (f && f.follower_id === userId && isUuid(f.following_id)) out.add(f.following_id); });
  return out;
}
async function authorPublic(deps, ctx, authorId) {
  if (authorId === ctx.viewer) return true;
  if (!(authorId in ctx.publicCache)) ctx.publicCache[authorId] = deps.ownerPublic ? deps.ownerPublic(authorId) : Promise.resolve(false);
  return (await ctx.publicCache[authorId]) === true;
}

/* Which of these posts the viewer may see. opts.feed also leaves out the muted. */
async function visiblePosts(deps, ctx, rows, opts) {
  opts = opts || {};
  var list = (rows || []).filter(Boolean);
  var hidden = await SF.hiddenAmong(deps.sb, "post", list.map(function (p) { return p.id; }));
  var out = [];
  for (var i = 0; i < list.length; i++) {
    var p = list[i];
    if (ctx.viewer && p.author_id === ctx.viewer) {
      if (p.status === "removed") continue;
      if (opts.publishedOnly && p.status !== "published") continue;
      out.push(p);
      continue;
    }
    if (p.status !== "published" || hidden.has(p.id)) continue;
    if (ctx.blocked.has(p.author_id)) continue;
    if (opts.feed && ctx.muted.has(p.author_id)) continue;
    if (p.audience !== "public" && !(ctx.viewer && ctx.following.has(p.author_id))) continue;
    if (!(await authorPublic(deps, ctx, p.author_id))) continue;
    out.push(p);
  }
  return out;
}
async function canSee(deps, ctx, post) { return post ? (await visiblePosts(deps, ctx, [post])).length === 1 : false; }

async function loadPost(sb, id) {
  if (!isUuid(id)) return null;
  var r = await sb.from("posts").select(POST_COLUMNS).eq("id", id).maybeSingle();
  if (r.error) throw r.error;
  return r.data || null;
}

/* ── people ── */
async function peopleById(sb, ids) {
  var list = [...new Set((ids || []).filter(isUuid))];
  var out = {};
  if (!list.length) return out;
  var r = await Promise.all([
    sb.from("bf_profiles").select("user_id, username, display_name, avatar_url, verified_reason").in("user_id", list),
    sb.from("profiles").select("user_id, full_name, business_name, logo_url").in("user_id", list)
  ]);
  if (r[0].error) throw r[0].error;
  if (r[1].error) throw r[1].error;
  var bf = {}, legacy = {};
  (r[0].data || []).forEach(function (x) { bf[x.user_id] = x; });
  (r[1].data || []).forEach(function (x) { legacy[x.user_id] = x; });
  list.forEach(function (id) {
    var p = IN.personFrom(bf[id], legacy[id]);
    // NAMED (Nov 21 2026, P3-2): verified is the Verified badge's reason (lib/verified.js), or null
    out[id] = { id: id, username: p.username, name: p.name, avatar_url: p.avatar_url,
      link: p.username ? "/@" + p.username : "/profile.html?id=" + id, verified: require("./verified").reasonOf(bf[id]) };
  });
  return out;
}

/* ── photos: post_media rows and their member_media files ── */
async function photosFor(deps, postIds) {
  var out = {};
  var ids = (postIds || []).filter(isUuid);
  if (!ids.length) return out;
  var pm = await deps.sb.from("post_media").select("post_id, media_id, thumb_media_id, idx").in("post_id", ids);
  if (pm.error) throw pm.error;
  var mediaIds = [];
  (pm.data || []).forEach(function (r) { mediaIds.push(r.media_id); if (r.thumb_media_id) mediaIds.push(r.thumb_media_id); });
  var files = {};
  if (mediaIds.length) {
    var mm = await deps.sb.from("member_media").select("id, path, alt_text").in("id", [...new Set(mediaIds)]);
    if (mm.error) throw mm.error;
    (mm.data || []).forEach(function (m) { files[m.id] = m; });
  }
  var base = deps.env && deps.env.SUPABASE_URL;
  (pm.data || []).slice().sort(function (a, b) { return a.idx - b.idx; }).forEach(function (r) {
    var full = files[r.media_id], thumb = files[r.thumb_media_id] || full;
    if (!full) return;
    (out[r.post_id] = out[r.post_id] || []).push({ idx: r.idx, url: MM.publicUrlFor(full.path, base), thumb_url: MM.publicUrlFor(thumb.path, base), alt: full.alt_text || "" });
  });
  return out;
}

/* What a member is shown of posts: the author, the photos, the counts, and the viewer's own like and save. */
/* NAMED (Nov 21 2026, FX2): the linked listings of these posts, for the feed's product strip: only an active listing is shown
   (one that was sold out, paused or removed shows no strip), with its title, its price in BFC, its first photo and its page. */
async function listingsFor(deps, rows) {
  var ids = [...new Set(rows.map(function (p) { return p.listing_id; }).filter(isUuid))];
  if (!ids.length) return {};
  var r = await deps.sb.from("marketplace_listings").select("id, slug, title, price_bfc, media, status").in("id", ids).eq("status", "active");
  if (r.error) throw r.error;
  var out = {};
  (r.data || []).forEach(function (l) {
    var m = Array.isArray(l.media) ? l.media : [];
    var photo = m.length && m[0] && typeof m[0].url === "string" && /^https:\/\//.test(m[0].url) ? m[0].url : null;
    out[l.id] = { id: l.id, title: l.title || "", price_bfc: Number(l.price_bfc) || 0, photo: photo, link: "/listing/" + (l.slug || l.id) };
  });
  return out;
}

async function decorate(deps, ctx, rows) {
  var list = rows || [];
  if (!list.length) return [];
  var ids = list.map(function (p) { return p.id; });
  var got = await Promise.all([
    peopleById(deps.sb, list.map(function (p) { return p.author_id; })),
    photosFor(deps, ids),
    ctx.viewer ? deps.sb.from("post_likes").select("post_id").eq("user_id", ctx.viewer).in("post_id", ids) : Promise.resolve({ data: [] }),
    ctx.viewer ? deps.sb.from("post_saves").select("post_id").eq("user_id", ctx.viewer).in("post_id", ids) : Promise.resolve({ data: [] }),
    listingsFor(deps, list)   // NAMED (Nov 21 2026, FX2)
  ]);
  if (got[2].error) throw got[2].error;
  if (got[3].error) throw got[3].error;
  var liked = new Set((got[2].data || []).map(function (r) { return r.post_id; }));
  var saved = new Set((got[3].data || []).map(function (r) { return r.post_id; }));
  return list.map(function (p) {
    var mine = !!ctx.viewer && p.author_id === ctx.viewer;
    return {
      id: p.id, kind: p.kind, body: p.body || "", audience: p.audience, status: mine ? p.status : "published",
      author: got[0][p.author_id] || { id: p.author_id, username: null, name: "Member", avatar_url: null, link: "/profile.html?id=" + p.author_id },
      photos: got[1][p.id] || [],
      like_count: Number(p.like_count) || 0, comment_count: Number(p.comment_count) || 0, save_count: Number(p.save_count) || 0, share_count: Number(p.share_count) || 0,
      created_at: p.created_at, published_at: p.published_at || null,
      liked: liked.has(p.id), saved: saved.has(p.id), mine: mine, following: !!ctx.viewer && ctx.following.has(p.author_id),
      link: "/p/" + p.id,
      listing: (p.listing_id && got[4][p.listing_id]) || null,   // NAMED (Nov 21 2026, FX2): the product strip's listing, or null
      // NAMED (Nov 21 2026, P3-1B): the intent; the search fields only for the author (Edit post fills them)
      intent: INTENTS.indexOf(p.intent) !== -1 ? p.intent : "share",
      search: mine ? { visible: p.search_visible !== false, title: p.seo_title || null, description: p.seo_description || null } : undefined
    };
  });
}

/* ── notices ── */
async function notice(deps, row, pushIt) {
  try {
    var ins = await deps.sb.from("notifications").insert(Object.assign({ read: false, created_at: now(deps) }, row));
    if (ins.error) { console.warn("[posts] a notice could not be written (" + (ins.error.code || "error") + "); the action stands."); return false; }
  } catch (e) { console.warn("[posts] a notice could not be written; the action stands."); return false; }
  if (pushIt && typeof deps.push === "function") {
    try { await deps.push(row.user_id, { title: row.title, body: row.message, url: row.link || "/inbox.html?tab=notifications" }); }
    catch (e) { console.warn("[posts] a push could not be sent; the notice stands."); }
  }
  return true;
}
async function nameOf(deps, userId) { var p = await peopleById(deps.sb, [userId]); return (p[userId] && p[userId].name) || "A member"; }

/* A like: one notice per post per LIKE_GROUP_MS, counting the likes since it began. */
async function likeNotice(deps, post, likerId) {
  if (post.author_id === likerId) return;
  var who = await nameOf(deps, likerId);
  var since = ago(deps, LIKE_GROUP_MS);
  var open = await deps.sb.from("notifications").select("id, created_at").eq("user_id", post.author_id).eq("type", "like")
    .eq("object_type", "post").eq("object_id", post.id).gt("created_at", since).order("created_at", { ascending: false }).limit(1);
  if (open.error) { console.warn("[posts] the like notice could not be read; none was written."); return; }
  var row = (open.data || [])[0];
  if (!row) {
    await notice(deps, { user_id: post.author_id, type: "like", title: "New like", message: who + " liked your post.", actor_id: likerId,
      object_type: "post", object_id: post.id, link: "/home.html?post=" + post.id }, true);
    return;
  }
  var n = await deps.sb.from("post_likes").select("post_id", { count: "exact", head: true }).eq("post_id", post.id).gt("created_at", row.created_at);
  // the like that opened the notice is not newer than it, so every like counted here (this one included) is one more liker
  // than the notice named: the others are this count minus this like, plus the first one
  var others = Math.max(0, typeof n.count === "number" ? n.count : 1);
  var text = who + (others ? " and " + others + " other" + (others === 1 ? "" : "s") : "") + " liked your post.";
  var u = await deps.sb.from("notifications").update({ message: text, actor_id: likerId, read: false }).eq("id", row.id);
  if (u.error) console.warn("[posts] the like notice could not be updated; the like stands.");
}

/* ── creating, editing and deleting ── */
function validateNew(b) {
  b = b || {};
  var kind = b.kind === undefined ? "text" : b.kind;
  if (KINDS_NOW.indexOf(kind) === -1) return { status: 400, error: MESSAGES.kind, field: "kind" };
  var audience = b.audience === undefined || b.audience === null ? "public" : b.audience;
  if (AUDIENCES.indexOf(audience) === -1) return { status: 400, error: MESSAGES.audience, field: "audience" };
  var body = b.body === undefined || b.body === null ? "" : b.body;
  if (typeof body !== "string") return { status: 400, error: MESSAGES.bodyType, field: "body" };
  body = body.trim();
  if (chars(body) > BODY_MAX) return { status: 400, error: MESSAGES.bodyLong, field: "body" };
  var media = b.media === undefined || b.media === null ? [] : b.media;
  if (!Array.isArray(media)) return { status: 400, error: MESSAGES.photosNone, field: "media" };
  if (kind === "text") {
    if (!body) return { status: 400, error: MESSAGES.textEmpty, field: "body" };
    if (media.length) return { status: 400, error: MESSAGES.textPhotos, field: "media" };
  } else {
    if (!media.length) return { status: 400, error: MESSAGES.photosNone, field: "media" };
    if (media.length > PHOTOS_MAX) return { status: 400, error: MESSAGES.photosMany, field: "media" };
  }
  // NAMED (Nov 21 2026, P3-1B): intent (share by default), listing_id, and the search fields (checked here; who may set them is createPost's)
  var intent = b.intent === undefined || b.intent === null ? "share" : b.intent;
  if (INTENTS.indexOf(intent) === -1) return { status: 400, error: MESSAGES.intent, field: "intent" };
  var listingId = b.listing_id === undefined || b.listing_id === null || b.listing_id === "" ? null : b.listing_id;
  if (listingId !== null && !isUuid(listingId)) return { status: 400, error: MESSAGES.listingBad, field: "listing_id" };
  var search = validateSearch(b);
  if (search.error) return search;
  return { kind: kind, audience: audience, body: body, media: media, intent: intent, listing_id: listingId, search: search.fields };
}

/* NAMED (Nov 21 2026, P3-1B): a member's search fields. Absent keys are left out (fields), so an edit changes only what it names.
   An empty title or description is stored as null (the post page then uses the post's own first words). */
function validateSearch(b) {
  var fields = {};
  if (b.search_visible !== undefined) {
    if (typeof b.search_visible !== "boolean") return { status: 400, error: MESSAGES.searchType, field: "search_visible" };
    fields.search_visible = b.search_visible;
  }
  var pairs = [["seo_title", SEO_TITLE_MAX, MESSAGES.seoTitle], ["seo_description", SEO_DESCRIPTION_MAX, MESSAGES.seoDescription]];
  for (var i = 0; i < pairs.length; i++) {
    var k = pairs[i][0], v = b[k];
    if (v === undefined) continue;
    if (v !== null && typeof v !== "string") return { status: 400, error: pairs[i][2], field: k };
    v = v === null ? "" : v.replace(/\s+/g, " ").trim();
    if (chars(v) > pairs[i][1]) return { status: 400, error: pairs[i][2], field: k };
    fields[k] = v || null;
  }
  return { fields: fields };
}

/* NAMED (Nov 21 2026, P3-1B): the account's tier, "member" or "free" (server.js accessTier over getUserPlan, deps.tierOf).
   Without deps.tierOf (the older checks' test deps) every account reads as a member, as before P3-1B. */
async function tierOf(deps, userId) { return deps.tierOf ? deps.tierOf(userId) : "member"; }
function membersOnly(deps, sentence, reason) {
  return { status: 403, body: { error: sentence, reason: reason, members_panel: deps.membersPanel ? deps.membersPanel() : null } };
}

/* P3-1: a public post needs a confirmed email; read fresh, and a read error throws (the route answers 500, nothing saved). */
async function authorVerified(deps, userId) {
  return require("./emailVerification").verifiedById(deps.sb, userId);
}

async function placeFor(sb, userId) {
  var p = await sb.from("bf_profiles").select("place_city, place_region, place_country, local_opt_in").eq("user_id", userId).maybeSingle();
  if (p.error) throw p.error;
  var r = p.data;
  if (!r || r.local_opt_in !== true) return { place_city: null, place_region: null, place_country: null };
  return { place_city: r.place_city || null, place_region: r.place_region || null, place_country: r.place_country || null };
}

async function createPost(deps, userId, body) {
  var PM = require("./postMedia");
  var v = validateNew(body);
  if (v.error) return fail(v.status, v.error, { field: v.field });
  /* NAMED (Nov 21 2026, P3-1B, the owner's rules): a free account's share post carries at least one photo (text-only is for
     members; a Need may be text); offer posts, a linked listing and the search fields are members only. */
  var FR = require("./membership").FREE_RULES;
  var tier = await tierOf(deps, userId);
  if (tier !== "member") {
    if (v.intent === "offer") return membersOnly(deps, MESSAGES.offerMembers, "members_only");
    if (v.listing_id) return membersOnly(deps, FR.listing_link, "members_only");
    if (v.intent === "share" && v.kind !== "photo") return membersOnly(deps, FR.share_photo, "photo_required");
    if (Object.keys(v.search).length) return membersOnly(deps, MESSAGES.searchMembers, "members_only");
  }
  if (v.listing_id) {
    var ls = await deps.sb.from("marketplace_listings").select("id, seller_id, status").eq("id", v.listing_id).maybeSingle();
    if (ls.error) throw ls.error;
    if (!ls.data || ls.data.seller_id !== userId || ls.data.status !== "active") return fail(400, MESSAGES.listingBad, { field: "listing_id" });
  }
  var screened = screenText(deps, { body: v.body });
  if (!screened.ok) return { status: 400, body: CP.refusalBody(screened) };
  if (v.audience === "public" && !(await authorVerified(deps, userId))) return { status: 403, body: require("./emailVerification").unverifiedBody("post_public") };
  if (await countSince(deps.sb, "posts", "author_id", userId, ago(deps, DAY)) >= POSTS_PER_DAY) return fail(429, MESSAGES.postsDay, { reason: "rate_limited" });
  var photos = [];
  if (v.kind === "photo") {
    var checked = await PM.checkForPost(deps.sb, userId, v.media);
    if (checked.error) return fail(checked.status, checked.error, { field: "media", reason: checked.reason });
    photos = checked.photos;
  }
  var findings = screened.review ? screened.review.findings : null;
  var at = now(deps);
  var place = await placeFor(deps.sb, userId);
  var row = Object.assign({ author_id: userId, kind: v.kind, body: v.body, audience: v.audience,
    status: findings ? "pending" : "published", published_at: findings ? null : at, created_at: at }, place);
  // NAMED (Nov 21 2026, P3-1B): the intent and link; a member's search fields (Show in Google on unless they turn it off); a free
  // account's post is stored with search_visible false, so joining later never puts its old posts in Google on its own.
  row.intent = v.intent;
  if (v.listing_id) row.listing_id = v.listing_id;
  Object.assign(row, tier === "member" ? Object.assign({ search_visible: true }, v.search) : { search_visible: false });
  var ins = await deps.sb.from("posts").insert(row).select(POST_COLUMNS).single();
  if (ins.error) throw ins.error;
  var post = ins.data;
  async function undo() {
    await deps.sb.from("post_media").delete().eq("post_id", post.id);
    await deps.sb.from("posts").delete().eq("id", post.id).eq("author_id", userId);
  }
  if (photos.length) {
    var links = photos.map(function (p, i) { return { post_id: post.id, media_id: p.media_id, thumb_media_id: p.thumb_media_id || null, idx: i }; });
    var pm = await deps.sb.from("post_media").insert(links);
    if (pm.error) { await undo(); throw pm.error; }
  }
  if (findings) {
    var q = null;
    try {
      q = await SF.queueScreenFindings(deps.sb, { object_type: "post", object_id: post.id, owner_id: userId }, findings, at);
    } catch (e) { q = null; }
    if (!q) { await undo(); return fail(503, "Your post couldn't be sent for review just now, so it wasn't saved. Try again in a minute.", { reason: "queue_unavailable" }); }
  }
  var ctx = await viewerContext(deps, userId);
  var shown = await decorate(deps, ctx, [post]);
  return { status: 201, body: { post: shown[0], message: post.status === "pending" ? MESSAGES.pending : MESSAGES.published, held: false, review: !!findings } };
}

async function editPost(deps, userId, postId, body) {
  var post = await loadPost(deps.sb, postId);
  if (!post || post.author_id !== userId || post.status === "removed") return notAvailable();
  // NAMED (Nov 21 2026, P3-1B): Edit post may change a member's search fields; text stays required as before
  var search = validateSearch(body || {});
  if (search.error) return fail(search.status, search.error, { field: search.field });
  if (Object.keys(search.fields).length && (await tierOf(deps, userId)) !== "member") return membersOnly(deps, MESSAGES.searchMembers, "members_only");
  var text = body && body.body;
  if (typeof text !== "string") return fail(400, MESSAGES.bodyType, { field: "body" });
  text = text.trim();
  if (chars(text) > BODY_MAX) return fail(400, MESSAGES.bodyLong, { field: "body" });
  if (post.kind === "text" && !text) return fail(400, MESSAGES.textEmpty, { field: "body" });
  var screened = screenText(deps, { body: text });
  if (!screened.ok) return { status: 400, body: CP.refusalBody(screened) };
  var findings = screened.review ? screened.review.findings : null;
  var patch = Object.assign({ body: text }, search.fields);   // NAMED (Nov 21 2026, P3-1B)
  if (findings && post.status === "published") patch.status = "pending";
  var u = await deps.sb.from("posts").update(patch).eq("id", post.id).eq("author_id", userId).select(POST_COLUMNS).single();
  if (u.error) throw u.error;
  if (findings) {
    var q = await SF.queueScreenFindings(deps.sb, { object_type: "post", object_id: post.id, owner_id: userId }, findings, now(deps));
    if (!q) {
      await deps.sb.from("posts").update({ body: post.body, status: post.status }).eq("id", post.id).eq("author_id", userId);
      return fail(503, "Your change couldn't be sent for review just now, so it wasn't saved. Try again in a minute.", { reason: "queue_unavailable" });
    }
  }
  var ctx = await viewerContext(deps, userId);
  return { status: 200, body: { post: (await decorate(deps, ctx, [u.data]))[0], message: findings ? MESSAGES.editPending : null } };
}

async function deletePost(deps, userId, postId) {
  var post = await loadPost(deps.sb, postId);
  if (!post || post.author_id !== userId || post.status === "removed") return notAvailable();
  var u = await deps.sb.from("posts").update({ status: "removed", removed_at: now(deps), removed_reason: "author" }).eq("id", post.id).eq("author_id", userId).select("id");
  if (u.error) throw u.error;
  return { status: 200, body: { deleted: true, message: MESSAGES.removed } };
}

/* ── reading ── */
async function getPost(deps, viewerId, postId) {
  var ctx = await viewerContext(deps, viewerId);
  var post = await loadPost(deps.sb, postId);
  if (!(await canSee(deps, ctx, post))) return notAvailable();
  return { status: 200, body: { post: (await decorate(deps, ctx, [post]))[0] } };
}

async function postsByAuthor(deps, viewerId, authorId, rawCursor) {
  if (!isUuid(authorId)) return notAvailable();
  var c = decodeCursor(rawCursor);
  if (!c) return fail(400, MESSAGES.cursor);
  var ctx = await viewerContext(deps, viewerId);
  var own = ctx.viewer === authorId;
  if (!own && (ctx.blocked.has(authorId) || !(await authorPublic(deps, ctx, authorId)))) return notAvailable();
  var q = deps.sb.from("posts").select(POST_COLUMNS).eq("author_id", authorId).in("status", own ? ["published", "pending", "hidden"] : ["published"]);
  var r = await afterCursor(q, "created_at", c).order("created_at", { ascending: false }).order("id", { ascending: false }).limit(LIST_PAGE + 1);
  if (r.error) throw r.error;
  var rows = r.data || [];
  var page = rows.slice(0, LIST_PAGE);
  var shown = await visiblePosts(deps, ctx, page);
  var last = page[page.length - 1];
  return { status: 200, body: { posts: await decorate(deps, ctx, shown), next_cursor: rows.length > LIST_PAGE && last ? encodeCursor(last.created_at, last.id) : null } };
}

async function savedPosts(deps, viewerId, rawCursor) {
  var c = decodeCursor(rawCursor);
  if (!c) return fail(400, MESSAGES.cursor);
  var ctx = await viewerContext(deps, viewerId);
  var q = deps.sb.from("post_saves").select("post_id, created_at").eq("user_id", ctx.viewer);
  if (!c.none) q = q.lt("created_at", c.at);
  var r = await q.order("created_at", { ascending: false }).limit(LIST_PAGE + 1);
  if (r.error) throw r.error;
  var saves = (r.data || []);
  var page = saves.slice(0, LIST_PAGE);
  var ids = page.map(function (s) { return s.post_id; });
  var rows = [];
  if (ids.length) {
    var p = await deps.sb.from("posts").select(POST_COLUMNS).in("id", ids);
    if (p.error) throw p.error;
    var byId = {};
    (p.data || []).forEach(function (x) { byId[x.id] = x; });
    rows = ids.map(function (id) { return byId[id]; }).filter(Boolean);
  }
  var shown = await visiblePosts(deps, ctx, rows, { publishedOnly: true });
  var last = page[page.length - 1];
  return { status: 200, body: { posts: await decorate(deps, ctx, shown), next_cursor: saves.length > LIST_PAGE && last ? encodeCursor(last.created_at, last.post_id) : null } };
}

async function anyPosts(sb) {
  var r = await sb.from("posts").select("id", { count: "exact", head: true }).eq("status", "published").eq("audience", "public");
  if (r.error) throw r.error;
  return typeof r.count === "number" ? r.count > 0 : true;
}

/* Members to follow: a public page, not the viewer, not followed, blocked or muted; those with recent posts first. */
function VERIFIED_RANK(p) { return require("./verified").reasonOf(p) ? 1 : 0; }
async function suggestions(deps, ctx) {
  var r = await deps.sb.from("bf_profiles").select("user_id, username, display_name, avatar_url, updated_at, verified_reason").not("username", "is", null)
    .order("updated_at", { ascending: false }).limit(60);
  if (r.error) throw r.error;
  var cand = (r.data || []).filter(function (p) {
    return isUuid(p.user_id) && p.user_id !== ctx.viewer && !ctx.following.has(p.user_id) && !ctx.blocked.has(p.user_id) && !ctx.muted.has(p.user_id);
  });
  var hidden = await SF.hiddenAmong(deps.sb, "profile", cand.map(function (p) { return p.user_id; }));
  var shown = [];
  for (var i = 0; i < cand.length; i++) {
    if (hidden.has(cand[i].user_id)) continue;
    if (await authorPublic(deps, ctx, cand[i].user_id)) shown.push(cand[i]);
  }
  var counts = {};
  if (shown.length) {
    var recent = await deps.sb.from("posts").select("author_id").in("author_id", shown.map(function (p) { return p.user_id; }))
      .eq("status", "published").eq("audience", "public").gt("published_at", ago(deps, SUGGEST_RECENT_DAYS * DAY)).limit(1000);
    if (recent.error) throw recent.error;
    (recent.data || []).forEach(function (x) { counts[x.author_id] = (counts[x.author_id] || 0) + 1; });
  }
  return shown.map(function (p, i) { return { p: p, i: i, n: counts[p.user_id] || 0 }; })
    // NAMED (Nov 21 2026, P3-2): Verified first (lib/verified.js), then the recent posts, then the order read
    .sort(function (a, b) { return VERIFIED_RANK(b.p) - VERIFIED_RANK(a.p) || b.n - a.n || a.i - b.i; }).slice(0, SUGGEST_MAX)
    .map(function (x) { return { user_id: x.p.user_id, username: x.p.username, name: x.p.display_name || "@" + x.p.username, avatar_url: x.p.avatar_url || null,
      link: "/@" + x.p.username, recent_posts: x.n, verified: require("./verified").reasonOf(x.p) }; });
}

async function followingFeed(deps, viewerId, rawCursor) {
  var c = decodeCursor(rawCursor);
  if (!c) return fail(400, MESSAGES.cursor);
  var ctx = await viewerContext(deps, viewerId);
  var authors = [ctx.viewer].concat([...ctx.following]);
  var q = deps.sb.from("posts").select(POST_COLUMNS).in("author_id", authors).eq("status", "published");
  var r = await afterCursor(q, "published_at", c).order("published_at", { ascending: false }).order("id", { ascending: false }).limit(FEED_SCAN);
  if (r.error) throw r.error;
  var rows = r.data || [];
  var shown = (await visiblePosts(deps, ctx, rows, { feed: true })).slice(0, FEED_PAGE);
  var lastShown = shown[shown.length - 1], lastRead = rows[rows.length - 1];
  var next = null;
  if (shown.length === FEED_PAGE && lastShown) next = encodeCursor(lastShown.published_at, lastShown.id);
  else if (rows.length === FEED_SCAN && lastRead) next = encodeCursor(lastRead.published_at, lastRead.id);
  var body = { tab: "following", posts: await decorate(deps, ctx, shown), next_cursor: next, following_count: ctx.following.size };
  if (c.none) {
    body.any_posts = await anyPosts(deps.sb);
    if (ctx.following.size < FIND_PEOPLE_UNDER) body.suggestions = await suggestions(deps, ctx);
  }
  return { status: 200, body: body };
}

/* ── Talk ── */
async function listComments(deps, viewerId, postId, rawAfter) {
  var ctx = await viewerContext(deps, viewerId);
  var post = await loadPost(deps.sb, postId);
  if (!(await canSee(deps, ctx, post))) return notAvailable();
  var q = deps.sb.from("post_comments").select(COMMENT_COLUMNS).eq("post_id", post.id).in("status", ["published", "deleted"]);
  if (rawAfter) {
    var a = decodeCursor(rawAfter);
    if (!a || a.none) return fail(400, MESSAGES.cursor);
    q = q.or("created_at.gt." + quoted(a.at) + ",and(created_at.eq." + quoted(a.at) + ",id.gt." + a.id + ")");
  }
  var r = await q.order("created_at", { ascending: true }).order("id", { ascending: true }).limit(COMMENTS_PAGE + 1);
  if (r.error) throw r.error;
  var rows = r.data || [];
  var page = rows.slice(0, COMMENTS_PAGE);
  var hidden = await SF.hiddenAmong(deps.sb, "comment", page.map(function (x) { return x.id; }));
  var kept = page.filter(function (x) {
    if (hidden.has(x.id)) return false;
    if (x.status === "deleted") return true;
    return !(x.author_id && (ctx.blocked.has(x.author_id) || ctx.muted.has(x.author_id)));
  });
  var people = await peopleById(deps.sb, kept.map(function (x) { return x.author_id; }));
  var postMine = ctx.viewer === post.author_id;
  var rule = await commentRule(deps, ctx.viewer, post);   // NAMED (Nov 21 2026, P3-1B)
  var last = page[page.length - 1];
  return { status: 200, body: { comments: kept.map(function (x) {
    if (x.status === "deleted") return { id: x.id, parent_id: x.parent_id || null, deleted: true, body: DELETED_BODY, author: null, created_at: x.created_at, mine: false, can_hide: false };
    var mine = !!ctx.viewer && x.author_id === ctx.viewer;
    return { id: x.id, parent_id: x.parent_id || null, deleted: false, body: x.body, author: people[x.author_id] || null, created_at: x.created_at,
      mine: mine, can_hide: postMine && !mine };
  }), next_after: rows.length > COMMENTS_PAGE && last ? encodeCursor(last.created_at, last.id) : null, comment_count: Number(post.comment_count) || 0,
    // NAMED (Nov 21 2026, P3-1B): whether this viewer may comment here, and if not the sentence Talk shows (with Join)
    // NAMED (Nov 22 2026, FX3): BEFORE comment_rule was the refusal itself. AFTER the sentence for before an attempt.
    can_comment: !rule, comment_rule: rule ? require("./membership").TALK_MEMBERS_ONLY : null } };
}

/* NAMED (Nov 21 2026, P3-1B): the sentence that refuses this viewer's comment on this post, or null. A free viewer may comment
   on a free author's post (their own too); never on a paid member's. */
async function commentRule(deps, viewerId, post) {
  if (!viewerId || !post) return null;
  if ((await tierOf(deps, viewerId)) === "member") return null;
  if (post.author_id === viewerId) return null;
  if ((await tierOf(deps, post.author_id)) !== "member") return null;
  return require("./membership").FREE_RULES.comment_member_post;
}

async function addComment(deps, viewerId, postId, b) {
  b = b || {};
  var ctx = await viewerContext(deps, viewerId);
  var post = await loadPost(deps.sb, postId);
  if (!(await canSee(deps, ctx, post)) || post.status !== "published") return notAvailable();
  // NAMED (Nov 21 2026, P3-1B, the owner's rule): a free account comments only on posts by other free accounts
  var rule = await commentRule(deps, ctx.viewer, post);
  if (rule) return membersOnly(deps, rule, "members_only");
  var text = typeof b.body === "string" ? b.body.trim() : "";
  if (!text) return fail(400, MESSAGES.commentEmpty, { field: "body" });
  if (chars(text) > COMMENT_MAX) return fail(400, MESSAGES.commentLong, { field: "body" });
  var parent = null;
  if (b.parent_id !== undefined && b.parent_id !== null && b.parent_id !== "") {
    if (!isUuid(b.parent_id)) return fail(404, MESSAGES.commentGone);
    var pr = await deps.sb.from("post_comments").select(COMMENT_COLUMNS).eq("id", b.parent_id).maybeSingle();
    if (pr.error) throw pr.error;
    parent = pr.data;
    if (!parent || parent.post_id !== post.id || parent.status === "removed" || parent.status === "hidden") return fail(404, MESSAGES.commentGone);
    if (parent.parent_id) {   // one level: a reply to a reply joins the top comment
      var top = await deps.sb.from("post_comments").select(COMMENT_COLUMNS).eq("id", parent.parent_id).maybeSingle();
      if (top.error) throw top.error;
      if (!top.data || top.data.post_id !== post.id) return fail(404, MESSAGES.commentGone);
      parent = Object.assign({}, top.data, { reply_to_author: parent.author_id });
    }
    if (parent.author_id && ctx.blocked.has(parent.author_id)) return notAvailable();
    if (parent.reply_to_author && ctx.blocked.has(parent.reply_to_author)) return notAvailable();
  }
  var screened = screenText(deps, { body: text });
  if (!screened.ok) return { status: 400, body: CP.refusalBody(screened) };
  if (await countSince(deps.sb, "post_comments", "author_id", ctx.viewer, ago(deps, HOUR)) >= COMMENTS_PER_HOUR) return fail(429, MESSAGES.commentsHour, { reason: "rate_limited" });
  var ins = await deps.sb.from("post_comments").insert({ post_id: post.id, author_id: ctx.viewer, parent_id: parent ? parent.id : null, body: text, status: "published", created_at: now(deps) })
    .select(COMMENT_COLUMNS).single();
  if (ins.error) throw ins.error;
  var row = ins.data;
  if (screened.review) await SF.queueScreenFindings(deps.sb, { object_type: "comment", object_id: row.id, owner_id: ctx.viewer }, screened.review.findings, now(deps));
  var who = await nameOf(deps, ctx.viewer);
  var link = "/home.html?post=" + post.id + "&talk=1";
  var told = {};
  told[ctx.viewer] = true;
  var replyTo = parent ? (parent.reply_to_author || parent.author_id) : null;
  if (replyTo && !told[replyTo]) {
    told[replyTo] = true;
    await notice(deps, { user_id: replyTo, type: "reply", title: "New reply", message: who + " replied to your comment.", actor_id: ctx.viewer, object_type: "comment", object_id: row.id, link: link }, true);
  }
  if (!told[post.author_id]) {
    await notice(deps, { user_id: post.author_id, type: "comment", title: "New comment", message: who + " commented on your post.", actor_id: ctx.viewer, object_type: "comment", object_id: row.id, link: link }, true);
  }
  var people = await peopleById(deps.sb, [ctx.viewer]);
  return { status: 201, body: { comment: { id: row.id, parent_id: row.parent_id || null, deleted: false, body: row.body, author: people[ctx.viewer] || null, created_at: row.created_at, mine: true, can_hide: false } } };
}

async function deleteComment(deps, viewerId, commentId) {
  if (!isUuid(commentId)) return fail(404, MESSAGES.commentGone);
  var r = await deps.sb.from("post_comments").select(COMMENT_COLUMNS).eq("id", commentId).maybeSingle();
  if (r.error) throw r.error;
  if (!r.data || r.data.author_id !== viewerId || r.data.status === "deleted") return fail(404, MESSAGES.commentGone);
  var u = await deps.sb.from("post_comments").update({ status: "deleted", body: DELETED_BODY }).eq("id", commentId).eq("author_id", viewerId);
  if (u.error) throw u.error;
  return { status: 200, body: { deleted: true } };
}

async function hideComment(deps, viewerId, commentId) {
  if (!isUuid(commentId)) return fail(404, MESSAGES.commentGone);
  var r = await deps.sb.from("post_comments").select(COMMENT_COLUMNS).eq("id", commentId).maybeSingle();
  if (r.error) throw r.error;
  var c = r.data;
  if (!c || c.status !== "published" || c.author_id === viewerId) return fail(404, MESSAGES.commentGone);
  var post = await loadPost(deps.sb, c.post_id);
  if (!post || post.author_id !== viewerId) return fail(404, MESSAGES.commentGone);
  var u = await deps.sb.from("post_comments").update({ status: "hidden" }).eq("id", c.id).eq("post_id", post.id);
  if (u.error) throw u.error;
  return { status: 200, body: { hidden: true } };
}

/* ── Like, Save, Share ── */
async function countsOf(sb, postId) {
  var r = await sb.from("posts").select("like_count, comment_count, save_count, share_count").eq("id", postId).maybeSingle();
  if (r.error) throw r.error;
  var p = r.data || {};
  return { like_count: Number(p.like_count) || 0, comment_count: Number(p.comment_count) || 0, save_count: Number(p.save_count) || 0, share_count: Number(p.share_count) || 0 };
}

async function react(deps, viewerId, postId, table, on) {
  var ctx = await viewerContext(deps, viewerId);
  var post = await loadPost(deps.sb, postId);
  if (!(await canSee(deps, ctx, post)) || post.status !== "published") return notAvailable();
  var added = false;
  if (on) {
    var had = await deps.sb.from(table).select("post_id").eq("post_id", post.id).eq("user_id", ctx.viewer).maybeSingle();
    if (had.error) throw had.error;
    if (!had.data) {
      if (table === "post_likes" && await countSince(deps.sb, "post_likes", "user_id", ctx.viewer, ago(deps, HOUR)) >= LIKES_PER_HOUR) return fail(429, MESSAGES.likesHour, { reason: "rate_limited" });
      var ins = await deps.sb.from(table).insert({ post_id: post.id, user_id: ctx.viewer, created_at: now(deps) });
      if (ins.error && ins.error.code !== "23505") throw ins.error;
      added = !ins.error;
    }
  } else {
    var del = await deps.sb.from(table).delete().eq("post_id", post.id).eq("user_id", ctx.viewer);
    if (del.error) throw del.error;
  }
  if (added && table === "post_likes") await likeNotice(deps, post, ctx.viewer);
  var counts = await countsOf(deps.sb, post.id);
  var out = Object.assign({ post_id: post.id }, counts);
  out[table === "post_likes" ? "liked" : "saved"] = !!on;
  return { status: 200, body: out };
}
function like(deps, viewerId, postId, on) { return react(deps, viewerId, postId, "post_likes", on); }
function save(deps, viewerId, postId, on) { return react(deps, viewerId, postId, "post_saves", on); }

/* One counted share per member per post per (UTC) day. */
async function share(deps, viewerId, postId) {
  var ctx = await viewerContext(deps, viewerId);
  var post = await loadPost(deps.sb, postId);
  if (!(await canSee(deps, ctx, post)) || post.status !== "published") return notAvailable();
  var day = now(deps).slice(0, 10);
  var up = await deps.sb.from("post_share_days").upsert({ post_id: post.id, user_id: ctx.viewer, day: day }, { onConflict: "post_id,user_id,day", ignoreDuplicates: true });
  if (up.error) throw up.error;
  return { status: 200, body: Object.assign({ post_id: post.id, link: "/p/" + post.id }, await countsOf(deps.sb, post.id)) };
}

/* ── Follow ── */
async function targetOf(sb, body) {
  body = body || {};
  if (isUuid(body.user_id)) {
    var u = await sb.from("users").select("id").eq("id", body.user_id).maybeSingle();
    if (u.error) throw u.error;
    return u.data ? u.data.id : null;
  }
  if (typeof body.handle === "string" && /^@?[a-z0-9_-]{3,30}$/i.test(body.handle.trim())) {
    var p = await sb.from("bf_profiles").select("user_id").ilike("username", body.handle.trim().replace(/^@/, "")).maybeSingle();
    if (p.error) throw p.error;
    return p.data ? p.data.user_id : null;
  }
  return null;
}

async function follow(deps, viewerId, body) {
  var target = await targetOf(deps.sb, body);
  if (!target) return fail(404, MESSAGES.noMember);
  if (target === viewerId) return fail(400, MESSAGES.self);
  if (await SF.blockedEitherWay(deps.sb, viewerId, target)) return notAvailable();
  var had = await deps.sb.from("follows").select("following_id").eq("follower_id", viewerId).eq("following_id", target).maybeSingle();
  if (had.error) throw had.error;
  if (!had.data) {
    if (await countSince(deps.sb, "follows", "follower_id", viewerId, ago(deps, DAY)) >= FOLLOWS_PER_DAY) return fail(429, MESSAGES.followsDay, { reason: "rate_limited" });
    var ins = await deps.sb.from("follows").insert({ follower_id: viewerId, following_id: target, created_at: now(deps) });
    if (ins.error && ins.error.code !== "23505") throw ins.error;
    if (!ins.error) {
      var who = await peopleById(deps.sb, [viewerId]);
      var me = who[viewerId] || { name: "A member", link: "/profile.html?id=" + viewerId };
      await notice(deps, { user_id: target, type: "follow", title: "New follower", message: me.name + " started following you.", actor_id: viewerId,
        object_type: "follow", object_id: viewerId, link: me.link }, true);
    }
  }
  return { status: 201, body: { user_id: target, following: true } };
}

async function unfollow(deps, viewerId, targetId) {
  if (!isUuid(targetId)) return fail(404, MESSAGES.noMember);
  var del = await deps.sb.from("follows").delete().eq("follower_id", viewerId).eq("following_id", targetId);
  if (del.error) throw del.error;
  return { status: 200, body: { user_id: targetId, following: false } };
}

/* A new block removes the follows between the two, both ways. */
async function unfollowBoth(sb, a, b) {
  if (!isUuid(a) || !isUuid(b)) return;
  var d = await sb.from("follows").delete().or("and(follower_id.eq." + a + ",following_id.eq." + b + "),and(follower_id.eq." + b + ",following_id.eq." + a + ")");
  if (d.error) console.error("[posts] the follows between two members could not be removed after a block (" + (d.error.code || "error") + ").");
}

async function followGate(deps, ctx, userId) {
  if (!isUuid(userId)) return false;
  if (ctx.viewer === userId) return true;
  if (ctx.blocked.has(userId)) return false;
  if (ctx.viewer && await SF.blockedEitherWay(deps.sb, ctx.viewer, userId)) return false;
  return authorPublic(deps, ctx, userId);
}

async function followCounts(deps, viewerId, userId) {
  var ctx = await viewerContext(deps, viewerId);
  if (!(await followGate(deps, ctx, userId))) return notAvailable();
  var r = await Promise.all([
    deps.sb.from("follows").select("follower_id, following_id").eq("following_id", userId).limit(5000),
    deps.sb.from("follows").select("follower_id, following_id").eq("follower_id", userId).limit(5000)
  ]);
  if (r[0].error) throw r[0].error;
  if (r[1].error) throw r[1].error;
  var followers = (r[0].data || []).filter(function (f) { return f.following_id === userId && !ctx.blocked.has(f.follower_id); });
  var following = (r[1].data || []).filter(function (f) { return f.follower_id === userId && !ctx.blocked.has(f.following_id); });
  return { status: 200, body: { user_id: userId, followers: followers.length, following: following.length,
    i_follow: !!ctx.viewer && followers.some(function (f) { return f.follower_id === ctx.viewer; }),
    follows_me: !!ctx.viewer && following.some(function (f) { return f.following_id === ctx.viewer; }), self: ctx.viewer === userId } };
}

async function followList(deps, viewerId, userId, which, rawCursor) {
  if (which !== "followers" && which !== "following") return notAvailable();
  var c = decodeCursor(rawCursor);
  if (!c) return fail(400, MESSAGES.cursor);
  var ctx = await viewerContext(deps, viewerId);
  if (!(await followGate(deps, ctx, userId))) return notAvailable();
  var mineCol = which === "followers" ? "following_id" : "follower_id", theirCol = which === "followers" ? "follower_id" : "following_id";
  var q = deps.sb.from("follows").select("follower_id, following_id, created_at").eq(mineCol, userId);
  if (!c.none) q = q.lt("created_at", c.at);
  var r = await q.order("created_at", { ascending: false }).limit(PEOPLE_PAGE + 1);
  if (r.error) throw r.error;
  var rows = r.data || [];
  var page = rows.slice(0, PEOPLE_PAGE);
  var kept = page.filter(function (f) { return f[mineCol] === userId && !ctx.blocked.has(f[theirCol]); });
  var people = await peopleById(deps.sb, kept.map(function (f) { return f[theirCol]; }));
  var last = page[page.length - 1];
  return { status: 200, body: { which: which, people: kept.map(function (f) {
    var id = f[theirCol], p = people[id] || { id: id, username: null, name: "Member", avatar_url: null, link: "/profile.html?id=" + id };
    return Object.assign({ user_id: id, i_follow: ctx.following.has(id), self: id === ctx.viewer }, p);
  }), next_cursor: rows.length > PEOPLE_PAGE && last ? encodeCursor(last.created_at, last[theirCol]) : null } };
}

/* ── moderation (lib/moderation.js decide): a decision on a post or a comment sets its status ── */
async function applyDecision(sb, row, state, nowIso) {
  if (row.object_type === "post") {
    var p = await loadPost(sb, row.object_id);
    if (!p || (p.status === "removed" && state !== "removed")) return { changed: false };
    var patch = state === "kept" ? { status: "published", published_at: p.published_at || nowIso }
      : state === "hidden" ? { status: "hidden" } : { status: "removed", removed_at: p.removed_at || nowIso, removed_reason: "moderation" };
    var u = await sb.from("posts").update(patch).eq("id", p.id);
    if (u.error) throw u.error;
    return { changed: true, published: state === "kept" && p.status === "pending", link: "/p/" + p.id };
  }
  if (row.object_type === "comment") {
    var c = await sb.from("post_comments").select("id, post_id, status").eq("id", row.object_id).maybeSingle();
    if (c.error) throw c.error;
    if (!c.data || c.data.status === "deleted") return { changed: false };
    var to = state === "kept" ? "published" : state;
    var cu = await sb.from("post_comments").update({ status: to }).eq("id", c.data.id);
    if (cu.error) throw cu.error;
    return { changed: true, published: false, link: "/home.html?post=" + c.data.post_id + "&talk=1" };
  }
  return { changed: false };
}

/* ── the public page (lib/postPage.js renders it) ── */
/* NAMED (Nov 21 2026, P3-1B): a post page Google may index: published, PUBLIC, not hidden by moderation, its author's page public,
   the author a paid member (deps.tierOf), and search_visible on. Every other post page stays noindex. */
async function indexablePost(deps, post) {
  if (!post || post.status !== "published" || post.audience !== "public" || post.search_visible !== true) return false;
  if (!deps.tierOf) return false;
  return (await deps.tierOf(post.author_id)) === "member";
}

async function publicPost(deps, postId) {
  var post = await loadPost(deps.sb, postId);
  if (!post || post.status !== "published" || post.audience !== "public") return null;
  if ((await SF.hiddenAmong(deps.sb, "post", [post.id])).has(post.id)) return null;
  if (!(deps.ownerPublic && (await deps.ownerPublic(post.author_id)) === true)) return null;
  var ctx = { viewer: null, blocked: new Set(), muted: new Set(), following: new Set(), publicCache: {} };
  var shown = (await decorate(deps, ctx, [post]))[0];
  // NAMED (Nov 21 2026, P3-1B): seo is set only when Google may index the page (indexablePost); else null and the page stays noindex
  shown.seo = (await indexablePost(deps, post)) ? { title: post.seo_title || null, description: post.seo_description || null } : null;
  return shown;
}

module.exports = {
  KINDS_NOW, KINDS_ALL, AUDIENCES, BODY_MAX, COMMENT_MAX, PHOTOS_MAX, FEED_PAGE, FEED_SCAN, LIST_PAGE, COMMENTS_PAGE, PEOPLE_PAGE,
  POSTS_PER_DAY, COMMENTS_PER_HOUR, LIKES_PER_HOUR, FOLLOWS_PER_DAY, FIND_PEOPLE_UNDER, SUGGEST_MAX, LIKE_GROUP_MS, PHOTO_KEEP_DAYS,
  DELETED_BODY, POST_COLUMNS, MESSAGES, INTENTS, SEO_TITLE_MAX, SEO_DESCRIPTION_MAX,   // NAMED (Nov 21 2026, P3-1B)
  chars, encodeCursor, decodeCursor, validateNew, authorVerified, placeFor, viewerContext, visiblePosts, canSee, loadPost, peopleById, photosFor,
  decorate, likeNotice, createPost, editPost, deletePost, getPost, postsByAuthor, savedPosts, anyPosts, suggestions, followingFeed,
  listComments, addComment, deleteComment, hideComment, like, save, share, follow, unfollow, unfollowBoth, followCounts, followList,
  applyDecision, publicPost, validateSearch, tierOf, commentRule, indexablePost   // NAMED (Nov 21 2026, P3-1B)
};
