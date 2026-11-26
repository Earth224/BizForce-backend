"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   THE HOME TABS (H1, Nov 25 2026; the owner's canvas row 7: FeedLocal,
   FeedFollowing, FeedMarket; migration 207). server.js holds thin routes;
   every rule is here, run by scripts/checkHomeTabs.js against a fake database.
   deps = lib/posts.js's deps (sb, now, ownerPublic, tierOf, membersPanel, push,
   env) plus, for lib/geo.js, request, clock and sleep.

   WHERE THE VIEWER IS (viewerPlace). The member's own place (Settings, Local:
   place_city, place_region, place_country and its point), unless they chose
   "Use a different city" on Local (home_prefs.local_place and its point). The
   reach is home_prefs.local_reach: "city" (My city), "25" (Within 25 mi, the
   default) or "anywhere". Kept per member, on the server.

   LOCAL (localFeed). PUBLIC posts by members who show their posts in Local
   (bf_profiles.local_opt_in, read now, not when the post was made) and OPEN
   Needs, newest first, within the reach, through lib/posts.js's own rules
   (visiblePosts: published, not hidden by moderation, no block either way, not
   muted, the author's pages public). A post is placed by its author's profile
   place; a Need by its own place when it has one, else its author's (when they
   show their posts in Local). Within 25 mi compares the two city points; when
   either point is missing (the lookup failed or found nothing) it falls back
   to matching the city's name as text (lib/geo.js sameCity). My city is the
   name match. Anywhere keeps every one; a Need with no place shows only there.
   Each post carries local: { area, distance_label } for its line ("Hair and
   Beauty · North Park · 0.8 mi"). No place at all: place null, and the tab
   offers "Add your city".

   MARKET (marketFeed). ACTIVE listings by MEMBERS only (deps.tierOf; only
   members sell), never the viewer's own, never a seller blocked either way,
   muted, banned or hidden, never a listing moderation hid; one category when
   asked (category_slug). The order: those within the reach first, nearest
   first (then newest), then every other, newest first. With no place, newest
   first. Each card: photo, category and place, title, seller (with follow),
   price in BizCash, Like and Save (listing_likes and listing_saves, the same
   rules as posts: a block either way refuses, 200 likes an hour), Ask, Share.
   THE MARKET DOT (tabsState.market_new): a member listing newer than the
   viewer's last Market visit (home_prefs.market_seen_at; never visited: any).

   FOLLOW SUGGESTIONS (suggestPeople; the Following tab when the viewer follows
   nobody). Up to SUGGEST_MAX (8) members with a handle and a public page, never
   the viewer, never one they follow, never blocked either way, muted, banned
   or hidden. Nearest first (city points; unknown last), then the most
   categories shared with the viewer (their Fingerprint's categories, their
   active listings', their posts'), then Verified first among equals.
   ══════════════════════════════════════════════════════════════════════════ */
const P = require("./posts");
const G = require("./geo");
const SF = require("./safety");
const CAT = require("./categories");
const CP = require("./contentPolicy");

const LOCAL_SCAN = 50;
const LOCAL_ROUNDS = 3;
const MARKET_SCAN = 300;
const MARKET_PAGE = 10;
const SUGGEST_MAX = 8;
const SUGGEST_SCAN = 200;
const CATEGORY_DAYS = 90;
const DOT_SCAN = 50;
const LISTING_LIKES_PER_HOUR = 200;
const PLACE_MAX = 80;
const DAY = 86400000;
const LISTING_COLUMNS = "id, slug, seller_id, title, description, price_bfc, category_slug, listing_kind, media, created_at, status";
const PLACE_COLUMNS = "user_id, place_city, place_region, place_country, place_lat, place_lng, local_opt_in";

const MESSAGES = {
  cursor: "That page marker is not valid. Reload to start again.",
  reach: "Choose My city, Within 25 mi or Anywhere.",
  place: "Type a city, up to 80 characters.",
  notAvailable: "That listing isn't available.",
  likes: "Two hundred likes an hour at most. Try again later.",
  own: "That is your own listing."
};

function nowOf(deps) { return deps.now ? deps.now() : new Date().toISOString(); }
function agoIso(deps, ms) { return new Date(Date.parse(nowOf(deps)) - ms).toISOString(); }
function isUuid(v) { return SF.isUuid(v); }
function fail(status, error, extra) { return { status: status, body: Object.assign({ error: error }, extra || {}) }; }
function geoDeps(deps) { return { sb: deps.sb, now: deps.now, request: deps.request, clock: deps.clock, sleep: deps.sleep }; }

/* ── where the viewer is ── */
async function prefsOf(sb, userId) {
  var r = await sb.from("home_prefs").select("user_id, local_reach, local_place, local_lat, local_lng, market_seen_at").eq("user_id", userId).maybeSingle();
  if (r.error) throw r.error;
  return r.data || null;
}
async function viewerPlace(deps, viewerId) {
  var got = await Promise.all([
    deps.sb.from("bf_profiles").select(PLACE_COLUMNS).eq("user_id", viewerId).maybeSingle(),
    prefsOf(deps.sb, viewerId)
  ]);
  if (got[0].error) throw got[0].error;
  var pr = got[0].data || {}, hp = got[1] || {};
  var out = { reach: G.normalReach(hp.local_reach), centre: null, prefs: hp };
  if (G.clean(hp.local_place)) {
    out.centre = { text: G.clean(hp.local_place), point: G.point(hp.local_lat, hp.local_lng), label: G.clean(hp.local_place), chosen: true };
  } else if (G.clean(pr.place_city)) {
    out.centre = { text: G.clean(pr.place_city), point: G.point(pr.place_lat, pr.place_lng),
      label: [G.clean(pr.place_city), G.clean(pr.place_region)].filter(Boolean).join(", "), chosen: false };
  }
  return out;
}
function placeReply(vp) {
  return vp.centre ? { label: vp.centre.label, chosen: vp.centre.chosen, located: !!vp.centre.point } : null;
}

/* The places of these members: only those who show their posts in Local. */
async function placesOf(sb, ids) {
  var list = [...new Set((ids || []).filter(isUuid))];
  var out = {};
  if (!list.length) return out;
  var r = await sb.from("bf_profiles").select(PLACE_COLUMNS).in("user_id", list);
  if (r.error) throw r.error;
  (r.data || []).forEach(function (x) {
    if (!x || x.local_opt_in !== true || !G.clean(x.place_city)) return;
    out[x.user_id] = { text: G.clean(x.place_city), point: G.point(x.place_lat, x.place_lng), label: G.placeLabel(x.place_city) };
  });
  return out;
}
function postPlace(p, authorPlaces) {
  if (p.intent === "need" && G.clean(p.need_place)) return { text: G.clean(p.need_place), point: G.point(p.need_lat, p.need_lng), label: G.placeLabel(p.need_place) };
  return authorPlaces[p.author_id] || null;
}
function localLine(here, there) {
  var miles = here && here.point && there && there.point ? G.milesBetween(here.point, there.point) : null;
  return { area: there ? there.label : null, distance_label: G.distanceLabel(miles), miles: miles };
}

/* ── Local ── */
async function localFeed(deps, viewerId, rawCursor) {
  var c = P.decodeCursor(rawCursor);
  if (!c) return fail(400, MESSAGES.cursor);
  var ctx = await P.viewerContext(deps, viewerId);
  var vp = await viewerPlace(deps, ctx.viewer);
  if (!vp.centre) return { status: 200, body: { tab: "local", reach: vp.reach, place: null, posts: [], next_cursor: null, attribution: G.ATTRIBUTION } };
  var kept = [], places = {}, lastRead = null, readAll = false;
  for (var round = 0; round < LOCAL_ROUNDS && kept.length < P.FEED_PAGE && !readAll; round++) {
    var q = deps.sb.from("posts").select(P.POST_COLUMNS + ", need_lat, need_lng").eq("status", "published").eq("audience", "public");
    var at = lastRead ? { at: lastRead.published_at, id: lastRead.id } : (c.none ? null : c);
    if (at) q = q.or("published_at.lt." + JSON.stringify(String(at.at)) + ",and(published_at.eq." + JSON.stringify(String(at.at)) + ",id.lt." + at.id + ")");
    var r = await q.order("published_at", { ascending: false }).order("id", { ascending: false }).limit(LOCAL_SCAN);
    if (r.error) throw r.error;
    var rows = r.data || [];
    if (rows.length < LOCAL_SCAN) readAll = true;
    if (rows.length) lastRead = rows[rows.length - 1];
    var authorPlaces = await placesOf(deps.sb, rows.map(function (p) { return p.author_id; }));
    var placed = rows.filter(function (p) {
      var openNeed = p.intent === "need" && !p.need_found_at;
      if (adultText([p.body])) return false;   // adult content never shows on Home
      var there = postPlace(p, authorPlaces);
      if (!there) return openNeed && vp.reach === "anywhere";
      if (p.intent !== "need" && !authorPlaces[p.author_id]) return false;   // a share or offer: its author shows posts in Local
      if (p.intent === "need" && !openNeed) return false;                      // Found Needs leave Local
      if (!G.withinReach(vp.reach, vp.centre, there)) return false;
      places[p.id] = there;
      return true;
    });
    var shown = await P.visiblePosts(deps, ctx, placed, { feed: true });
    shown.forEach(function (p) { if (kept.length < P.FEED_PAGE) kept.push(p); });
  }
  var lastKept = kept[kept.length - 1];
  var next = null;
  if (kept.length === P.FEED_PAGE && lastKept) next = P.encodeCursor(lastKept.published_at, lastKept.id);
  else if (!readAll && lastRead) next = P.encodeCursor(lastRead.published_at, lastRead.id);
  var posts = await P.decorate(deps, ctx, kept);
  posts.forEach(function (p) { var l = localLine(vp.centre, places[p.id]); p.local = { area: l.area, distance_label: l.distance_label }; });
  return { status: 200, body: { tab: "local", reach: vp.reach, place: placeReply(vp), posts: posts, next_cursor: next, attribution: G.ATTRIBUTION } };
}

/* ── who may appear: members in good standing the viewer has not blocked, muted or been blocked by ── */
async function standingOf(deps, ctx, ids) {
  var list = [...new Set((ids || []).filter(isUuid))].filter(function (id) { return id !== ctx.viewer && !ctx.blocked.has(id) && !ctx.muted.has(id); });
  var ok = new Set();
  for (var i = 0; i < list.length; i++) if ((await deps.ownerPublic(list[i])) === true) ok.add(list[i]);
  return ok;
}
async function membersAmong(deps, ids) {
  var out = new Set();
  for (var i = 0; i < ids.length; i++) if ((await P.tierOf(deps, ids[i])) === "member") out.add(ids[i]);
  return out;
}

function firstPhoto(media) {
  var m = Array.isArray(media) ? media : [];
  for (var i = 0; i < m.length; i++) if (m[i] && typeof m[i].url === "string" && /^https:\/\//.test(m[i].url)) return m[i].url;
  return null;
}
async function listingCards(deps, ctx, rows, extra) {
  if (!rows.length) return [];
  var ids = rows.map(function (l) { return l.id; });
  var got = await Promise.all([
    P.peopleById(deps.sb, rows.map(function (l) { return l.seller_id; })),
    ctx.viewer ? deps.sb.from("listing_likes").select("listing_id").eq("user_id", ctx.viewer).in("listing_id", ids) : Promise.resolve({ data: [] }),
    ctx.viewer ? deps.sb.from("listing_saves").select("listing_id").eq("user_id", ctx.viewer).in("listing_id", ids) : Promise.resolve({ data: [] }),
    CAT.list(deps.sb).catch(function () { return []; })
  ]);
  if (got[1].error) throw got[1].error;
  if (got[2].error) throw got[2].error;
  var liked = new Set((got[1].data || []).map(function (x) { return x.listing_id; }));
  var saved = new Set((got[2].data || []).map(function (x) { return x.listing_id; }));
  return rows.map(function (l) {
    var e = (extra && extra[l.id]) || {};
    return {
      id: l.id, title: l.title || "", description: String(l.description || "").slice(0, 280), price_bfc: Number(l.price_bfc) || 0,
      kind: l.listing_kind || null, photo: firstPhoto(l.media), link: "/listing/" + (l.slug || l.id),
      category: l.category_slug ? { slug: l.category_slug, name: CAT.nameOf(got[3], l.category_slug) || l.category_slug } : null,
      seller: got[0][l.seller_id] || { id: l.seller_id, name: "Member", username: null, avatar_url: null, link: "/profile.html?id=" + l.seller_id, verified: null },
      following: ctx.following.has(l.seller_id), liked: liked.has(l.id), saved: saved.has(l.id),
      place: e.area || null, distance_label: e.distance_label || null
    };
  });
}
/* Active listings by members the viewer may see (one category when asked), with their sellers' places. */
async function marketRows(deps, ctx, category, sinceIso, scan) {
  var q = deps.sb.from("marketplace_listings").select(LISTING_COLUMNS).eq("status", "active");
  if (category) q = q.eq("category_slug", category);
  if (sinceIso) q = q.gt("created_at", sinceIso);
  var r = await q.order("created_at", { ascending: false }).limit(scan);
  if (r.error) throw r.error;
  return shownListings(deps, ctx, r.data || []);
}
/* Of these listing rows, those the viewer may see on Home and in Search: active, by a member in good standing (not the viewer,
   no block either way, not muted), not hidden by moderation, no adult content. */
async function shownListings(deps, ctx, data) {
  var rows = (data || []).filter(function (l) { return l && isUuid(l.seller_id) && l.status === "active"; });
  var ok = await standingOf(deps, ctx, rows.map(function (l) { return l.seller_id; }));
  rows = rows.filter(function (l) { return ok.has(l.seller_id); });
  var members = await membersAmong(deps, [...new Set(rows.map(function (l) { return l.seller_id; }))]);
  rows = rows.filter(function (l) { return members.has(l.seller_id); });
  var hidden = await SF.hiddenAmong(deps.sb, "listing", rows.map(function (l) { return l.id; }));
  return rows.filter(function (l) { return !hidden.has(l.id) && !adultText([l.title, l.description]); });
}
/* Adult content never shows (the content screen refuses it when written; this keeps it out even of older rows). */
function adultText(fields) {
  var f = CP.prohibitedFindings(fields.filter(Boolean).join(" \n "));
  return !!(f.refused && f.refused.category === "adult") || f.review.some(function (x) { return x && x.category === "adult"; });
}

async function marketFeed(deps, viewerId, query) {
  query = query || {};
  var cat = typeof query.category === "string" && query.category ? query.category : null;
  if (cat && !(await CAT.find(deps.sb, cat))) cat = "__none__";
  var raw = query.cursor;
  var offset = 0;
  if (raw !== undefined && raw !== null && raw !== "") {
    if (!/^o\d{1,5}$/.test(String(raw))) return fail(400, MESSAGES.cursor);
    offset = Number(String(raw).slice(1));
  }
  var ctx = await P.viewerContext(deps, viewerId);
  var vp = await viewerPlace(deps, ctx.viewer);
  var rows = cat === "__none__" ? [] : await marketRows(deps, ctx, cat, null, MARKET_SCAN);
  var places = await placesOf(deps.sb, rows.map(function (l) { return l.seller_id; }));
  var extra = {};
  var ranked = rows.map(function (l, i) {
    var there = places[l.seller_id] || null;
    var line = localLine(vp.centre, there);
    extra[l.id] = line;
    var near = !!(vp.centre && there && G.withinReach(vp.reach, vp.centre, there));
    return { l: l, i: i, near: near, miles: line.miles };
  });
  if (vp.centre) {
    ranked.sort(function (a, b) {
      if (a.near !== b.near) return a.near ? -1 : 1;
      if (a.near) {
        var am = a.miles === null ? Infinity : a.miles, bm = b.miles === null ? Infinity : b.miles;
        if (am !== bm) return am - bm;
      }
      return a.i - b.i;
    });
  }
  var page = ranked.slice(offset, offset + MARKET_PAGE).map(function (x) { return x.l; });
  var cards = await listingCards(deps, ctx, page, extra);
  var next = offset + MARKET_PAGE < ranked.length ? "o" + (offset + MARKET_PAGE) : null;
  return { status: 200, body: { tab: "market", category: cat === "__none__" ? query.category : cat, reach: vp.reach, place: placeReply(vp), listings: cards, next_cursor: next } };
}

async function marketSeen(deps, viewerId) {
  var w = await deps.sb.from("home_prefs").upsert({ user_id: viewerId, market_seen_at: nowOf(deps), updated_at: nowOf(deps) }, { onConflict: "user_id" });
  if (w.error) throw w.error;
  return { status: 200, body: { ok: true } };
}

/* What the tab row needs: the place chip and the Market dot. */
async function tabsState(deps, viewerId) {
  var ctx = await P.viewerContext(deps, viewerId);
  var vp = await viewerPlace(deps, ctx.viewer);
  var seen = vp.prefs && vp.prefs.market_seen_at ? vp.prefs.market_seen_at : null;
  var fresh = await marketRows(deps, ctx, null, seen, DOT_SCAN);
  return { status: 200, body: { reach: vp.reach, place: placeReply(vp), market_new: fresh.length > 0, attribution: G.ATTRIBUTION } };
}

/* Change, on Local: { reach } and/or { place } (a city's text, or null to go back to the member's own city). "My city" sends
   reach "city" and place null. A new place is looked up (lib/geo.js); a failed lookup still saves the text. */
async function savePrefs(deps, viewerId, body) {
  body = body || {};
  var row = { user_id: viewerId, updated_at: nowOf(deps) };
  if (body.reach !== undefined) {
    if (G.REACHES.indexOf(body.reach) === -1) return fail(400, MESSAGES.reach, { field: "reach" });
    row.local_reach = body.reach;
  }
  var looked = null;
  if (body.place !== undefined) {
    if (body.place === null || body.place === "") { row.local_place = null; row.local_lat = null; row.local_lng = null; }
    else {
      var t = G.clean(body.place);
      if (typeof body.place !== "string" || t.length < 2 || Array.from(t).length > PLACE_MAX) return fail(400, MESSAGES.place, { field: "place" });
      looked = await G.geocode(geoDeps(deps), { text: t });
      row.local_place = t; row.local_lat = looked.point ? looked.point.lat : null; row.local_lng = looked.point ? looked.point.lng : null;
    }
  }
  var w = await deps.sb.from("home_prefs").upsert(row, { onConflict: "user_id" });
  if (w.error) throw w.error;
  var vp = await viewerPlace(deps, viewerId);
  return { status: 200, body: { reach: vp.reach, place: placeReply(vp), lookup: looked ? looked.source : null, attribution: G.ATTRIBUTION } };
}

/* The profile place's point, after Settings, Local saved it (server.js PUT /api/me/place): looked up when the place's text
   changed, or when it has no point yet (a place saved before 207; the cache answers a place already looked up). No place:
   the point is cleared. */
async function locateProfile(deps, userId, before, after) {
  var keyOf = function (x) { return x && G.clean(x.place_city) ? G.placeKey([x.place_city, x.place_region, x.place_country]) : null; };
  var k = keyOf(after);
  var hadPoint = !!(before && G.point(before.place_lat, before.place_lng));
  if (k && k === keyOf(before) && hadPoint) return { source: "unchanged" };
  if (!k && !hadPoint) return { source: "empty" };
  var looked = k ? await G.geocode(geoDeps(deps), { text: G.profileText(after), country: after.place_country }) : { point: null, source: "empty" };
  var w = await deps.sb.from("bf_profiles").update({ place_lat: looked.point ? looked.point.lat : null, place_lng: looked.point ? looked.point.lng : null }).eq("user_id", userId);
  if (w.error) throw w.error;
  return { source: looked.source };
}
/* A Need's point, after it is saved (never delays or fails the post). */
function startNeedPoint(deps, post) {
  if (!post || post.intent !== "need" || !G.clean(post.need_place)) return Promise.resolve(null);
  return G.geocode(geoDeps(deps), { text: post.need_place }).then(function (looked) {
    if (!looked.point) return looked.source;
    return deps.sb.from("posts").update({ need_lat: looked.point.lat, need_lng: looked.point.lng }).eq("id", post.id).then(function () { return looked.source; });
  }).catch(function () { return "failed"; });
}

/* ── Like and Save on listings: the same rules as posts ── */
async function listingReact(deps, viewerId, listingId, table, on) {
  if (!isUuid(listingId)) return fail(404, MESSAGES.notAvailable, { reason: "not_available" });
  var r = await deps.sb.from("marketplace_listings").select("id, seller_id, status").eq("id", listingId).maybeSingle();
  if (r.error) throw r.error;
  var l = r.data;
  var ctx = await P.viewerContext(deps, viewerId);
  if (!l || l.status !== "active" || ctx.blocked.has(l.seller_id)) return fail(404, MESSAGES.notAvailable, { reason: "not_available" });
  if (l.seller_id !== ctx.viewer) {
    if ((await deps.ownerPublic(l.seller_id)) !== true) return fail(404, MESSAGES.notAvailable, { reason: "not_available" });
    if ((await SF.hiddenAmong(deps.sb, "listing", [l.id])).has(l.id)) return fail(404, MESSAGES.notAvailable, { reason: "not_available" });
  }
  if (on) {
    if (table === "listing_likes") {
      var c = await deps.sb.from("listing_likes").select("user_id", { count: "exact", head: true }).eq("user_id", ctx.viewer).gt("created_at", agoIso(deps, 3600000));
      if (c.error) throw c.error;
      if (typeof c.count !== "number") throw new Error("listing_likes count unavailable");
      if (c.count > LISTING_LIKES_PER_HOUR - 1) return fail(429, MESSAGES.likes, { reason: "rate_limited" });
    }
    var ins = await deps.sb.from(table).upsert({ listing_id: l.id, user_id: ctx.viewer, created_at: nowOf(deps) }, { onConflict: "listing_id,user_id", ignoreDuplicates: true });
    if (ins.error) throw ins.error;
  } else {
    var del = await deps.sb.from(table).delete().eq("listing_id", l.id).eq("user_id", ctx.viewer);
    if (del.error) throw del.error;
  }
  return { status: 200, body: table === "listing_likes" ? { liked: !!on } : { saved: !!on } };
}
function likeListing(deps, viewerId, id, on) { return listingReact(deps, viewerId, id, "listing_likes", on); }
function saveListing(deps, viewerId, id, on) { return listingReact(deps, viewerId, id, "listing_saves", on); }

/* ── follow suggestions ── */
async function categoriesOf(deps, ids) {
  var list = [...new Set(ids.filter(isUuid))];
  var out = {};
  list.forEach(function (id) { out[id] = new Set(); });
  if (!list.length) return out;
  var got = await Promise.all([
    deps.sb.from("lead_fingerprints").select("user_id, categories, reach").in("user_id", list),
    deps.sb.from("marketplace_listings").select("seller_id, category_slug").in("seller_id", list).eq("status", "active").limit(2000),
    deps.sb.from("posts").select("author_id, category").in("author_id", list).eq("status", "published").gt("published_at", agoIso(deps, CATEGORY_DAYS * DAY)).limit(2000)
  ]);
  got.forEach(function (g) { if (g.error) throw g.error; });
  var online = new Set();
  (got[0].data || []).forEach(function (f) {
    (Array.isArray(f.categories) ? f.categories : []).forEach(function (s) { if (typeof s === "string" && out[f.user_id]) out[f.user_id].add(s); });
    if (f.reach === "online") online.add(f.user_id);
  });
  (got[1].data || []).forEach(function (l) { if (l.category_slug && out[l.seller_id]) out[l.seller_id].add(l.category_slug); });
  (got[2].data || []).forEach(function (p) { if (p.category && out[p.author_id]) out[p.author_id].add(p.category); });
  out.__online = online;
  return out;
}
async function suggestPeople(deps, viewerId) {
  var ctx = await P.viewerContext(deps, viewerId);
  var r = await deps.sb.from("bf_profiles").select("user_id, username, display_name, avatar_url, verified_reason, updated_at").not("username", "is", null)
    .order("updated_at", { ascending: false }).limit(SUGGEST_SCAN);
  if (r.error) throw r.error;
  var cand = (r.data || []).filter(function (p) { return p && isUuid(p.user_id) && !ctx.following.has(p.user_id); })
    .filter(function (p) { return !adultText([p.display_name, p.username]); });   // never an adult name, as in Search
  var ok = await standingOf(deps, ctx, cand.map(function (p) { return p.user_id; }));
  cand = cand.filter(function (p) { return ok.has(p.user_id); });
  var vp = await viewerPlace(deps, ctx.viewer);
  var places = await placesOf(deps.sb, cand.map(function (p) { return p.user_id; }));
  var cats = await categoriesOf(deps, [ctx.viewer].concat(cand.map(function (p) { return p.user_id; })));
  var mine = cats[ctx.viewer] || new Set();
  var catList = await CAT.list(deps.sb).catch(function () { return []; });
  var verified = require("./verified");
  return { status: 200, body: { people: cand.map(function (p, i) {
    var there = places[p.user_id] || null;
    var line = localLine(vp.centre, there);
    var theirs = [...(cats[p.user_id] || [])];
    var shared = theirs.filter(function (s) { return mine.has(s); });
    var shownCat = shared[0] || theirs[0] || null;
    return { p: p, i: i, miles: line.miles === null ? Infinity : Math.round(line.miles), shared: shared.length, v: verified.reasonOf(p) ? 1 : 0,
      area: there ? there.label : (cats.__online.has(p.user_id) ? "Online" : null), category: shownCat ? CAT.nameOf(catList, shownCat) || shownCat : null, distance_label: line.distance_label };
  }).sort(function (a, b) { return a.miles - b.miles || b.shared - a.shared || b.v - a.v || a.i - b.i; }).slice(0, SUGGEST_MAX).map(function (x) {
    return { user_id: x.p.user_id, username: x.p.username, name: x.p.display_name || "@" + x.p.username, avatar_url: x.p.avatar_url || null,
      link: "/@" + x.p.username, verified: verified.reasonOf(x.p), category: x.category, area: x.area, distance_label: x.distance_label };
  }) } };
}

module.exports = {
  LOCAL_SCAN, LOCAL_ROUNDS, MARKET_SCAN, MARKET_PAGE, SUGGEST_MAX, SUGGEST_SCAN, DOT_SCAN, LISTING_LIKES_PER_HOUR, PLACE_MAX, MESSAGES,
  prefsOf, viewerPlace, placesOf, postPlace, localLine, localFeed, standingOf, membersAmong, marketRows, shownListings, adultText, listingCards, marketFeed, marketSeen,
  tabsState, savePrefs, locateProfile, startNeedPoint, listingReact, likeListing, saveListing, categoriesOf, suggestPeople
};
