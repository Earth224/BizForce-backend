"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   checkHomeTabs.js — H1 (Nov 25 2026): Home's Local, Following (nobody
   followed), Market and Search tabs; city points and distance; Like and Save
   on listings. The owner's canvas row 7 (FeedLocal, FeedFollowing, FeedMarket,
   FeedSearch); migration 207, and 208's point rules (NAMED (Nov 25 2026, H1B), section K).

   Runs lib/geo.js, lib/homeTabs.js, lib/search.js and lib/posts.js over the
   P2-3 in-memory database (scripts/_p23Db.js), categories from migration 200
   (scripts/_categories.js). Never the real database, never the network: the
   geocoder's request is a fake that records what it was sent (Nominatim is
   never called).

     A. the distance maths, the label ("0.8 mi", whole miles), the reach
     B. geocoding: 1 request a second server-wide, a real User-Agent, cached once
        (found and not found), a failure not cached, "busy", "off" without a
        request function, points rounded to 2 decimals
     C. Local's Change (reach and "Use a different city"), the profile place's
        point, a Need's point
     D. Local: public posts and open Needs within reach, newest first, the line;
        the name-match fallback; every privacy rule; no place
     E. Market: members' active listings only, nearest within reach then newest,
        the category, the pages; the Market dot
     F. Like and Save on listings: the same rules as posts, 200 likes an hour
     G. follow suggestions: never the viewer, followed, blocked, muted, banned
        or adult; nearest, then shared categories, then Verified; at most 8
     H. Search: people (handle, name, business, city of opted-in members,
        category), listings, posts, Needs; every privacy rule; free accounts
        as people; adult never; groups, See all and pages; the limits
     I. the routes and limits (server.js)
     J. the frontend: the tabs, Search, Market's members-only actions, no Tip,
        no sideways swipe, the storefront's Verified badge race, the attribution

   MUTATE=<name> applies one mutation in memory; MUTATE=all runs each.
   ═══════════════════════════════════════════════════════════════════════════ */
const H = require("./_p21Harness");
const { memDb } = require("./_p23Db");
const CATEGORY_ROWS = require("./_categories").rows();

const SERVER = "@server.js", POSTS = "@lib/posts.js", GEO = "@lib/geo.js", HOME = "@lib/homeTabs.js", SEARCH = "@lib/search.js";
// NAMED (Nov 25 2026, H1B): the two migrations whose point rules section K evaluates
const M207 = "@supabase/migrations/207_h1_home_tabs.sql", M208 = "@supabase/migrations/208_h1b_point_checks.sql";
const TABS = "scripts/bf-home-tabs.js", HOMEPAGE = "home.html", SELLER = "seller.html", SETTINGS = "settings.html", FEED = "scripts/bf-feed.js";
const MUTATIONS = {
  // A
  "miles-wrong-radius": [[GEO, "const EARTH_MILES = 3958.8;", "const EARTH_MILES = 6371;"]],
  "label-no-decimal": [[GEO, "  if (miles < 0.95) return Math.max(0.1, Math.round(miles * 10) / 10).toFixed(1) + \" mi\";", "  if (miles < 0.95) return Math.round(miles) + \" mi\";"]],
  "label-zero": [[GEO, "Math.max(0.1, Math.round(miles * 10) / 10)", "(Math.round(miles * 10) / 10)"]],
  "reach-30": [[GEO, "milesBetween(here.point, there.point) < REACH_MILES + 0.0001", "milesBetween(here.point, there.point) < 30"]],
  "no-fallback": [[GEO, "  return sameCity(here.text, there.text);\n}", "  return reach === \"city\" && sameCity(here.text, there.text);\n}"]],
  "state-code-matches": [[GEO, ".filter(function (s) { return s.length > 2; });", ".filter(Boolean);"]],
  "no-round": [[GEO, "function round2(v) { var n = Number(v); return isFinite(n) ? Math.round(n * 100) / 100 : null; }", "function round2(v) { var n = Number(v); return isFinite(n) ? n : null; }"]],
  "reach-default-anywhere": [[GEO, "const DEFAULT_REACH = \"25\";", "const DEFAULT_REACH = \"anywhere\";"]],
  // B
  "queue-off": [[GEO, "  nextSlotAt = at + SLOT_MS;\n", ""]],
  "slot-half": [[GEO, "const SLOT_MS = 1000;", "const SLOT_MS = 500;"]],
  "no-busy": [[GEO, "  if (at - t > QUEUE_MAX_MS) return -1;\n", ""]],
  "cache-unread": [[GEO, "  var hit = await cached(deps.sb, key);\n  if (hit)", "  var hit = null;\n  if (hit)"]],
  "not-found-uncached": [[GEO, "  var p = first ? point(parseFloat(first.lat), parseFloat(first.lon)) : null;\n  await remember(", "  var p = first ? point(parseFloat(first.lat), parseFloat(first.lon)) : null;\n  if (p) await remember("]],
  "failure-cached": [[GEO, "  if (!r || r.status !== 200 || !Array.isArray(r.json)) return { point: null, source: \"failed\" };", "  if (!r || r.status !== 200 || !Array.isArray(r.json)) { await remember(deps.sb, key, null, deps.now()); return { point: null, source: \"failed\" }; }"]],
  "agent-anonymous": [[GEO, "const USER_AGENT = \"BizForce/1.0 (https://bizforceai.net; \" + require(\"./legal\").CONTACT_EMAIL + \")\";", "const USER_AGENT = \"node\";"]],
  "ua-not-sent": [[GEO, "headers: { \"User-Agent\": USER_AGENT, \"Accept\"", "headers: { \"Accept\""]],
  "key-case": [[GEO, ".filter(Boolean).map(function (s) { return s.toLowerCase(); });", ".filter(Boolean);"]],
  "off-reaches-network": [[GEO, "  if (typeof deps.request !== \"function\") return { point: null, source: \"off\" };\n", ""]],
  // C
  "reach-any-word": [[HOME, "    if (G.REACHES.indexOf(body.reach) === -1) return fail(400, MESSAGES.reach, { field: \"reach\" });\n", ""]],
  "place-long": [[HOME, "Array.from(t).length > PLACE_MAX", "Array.from(t).length > 200"]],
  "failed-lookup-unsaved": [[HOME, "      looked = await G.geocode(geoDeps(deps), { text: t });\n", "      looked = await G.geocode(geoDeps(deps), { text: t });\n      if (!looked.point) return fail(400, MESSAGES.place, { field: \"place\" });\n"]],
  "profile-relookup-always": [[HOME, "  if (k && k === keyOf(before) && hadPoint) return { source: \"unchanged\" };\n", ""]],
  "profile-clear-keeps-point": [[HOME, "  if (!k && !hadPoint) return { source: \"empty\" };", "  if (!k) return { source: \"empty\" };"]],
  "need-point-unsaved": [[HOME, "    return deps.sb.from(\"posts\").update({ need_lat: looked.point.lat, need_lng: looked.point.lng }).eq(\"id\", post.id)", "    return Promise.resolve({})"]],
  "need-point-not-started": [[POSTS, "  require(\"./homeTabs\").startNeedPoint(deps, post);   // NAMED (Nov 25 2026, H1): a Need's city point (lib/geo.js), never awaited\n", ""]],
  // D
  "local-followers": [[HOME, "select(P.POST_COLUMNS + \", need_lat, need_lng\").eq(\"status\", \"published\").eq(\"audience\", \"public\");", "select(P.POST_COLUMNS + \", need_lat, need_lng\").eq(\"status\", \"published\");"]],
  "optout-shown": [[HOME, "    if (!x || x.local_opt_in !== true || !G.clean(x.place_city)) return;", "    if (!x || !G.clean(x.place_city)) return;"]],
  "found-needs-shown": [[HOME, "      if (p.intent === \"need\" && !openNeed) return false;", "      if (false) return false;"]],
  "placeless-need-everywhere": [[HOME, "      if (!there) return openNeed && vp.reach === \"anywhere\";", "      if (!there) return openNeed;"]],
  "local-adult": [[HOME, "      if (adultText([p.body])) return false;   // adult content never shows on Home\n", ""]],
  "local-no-visibility": [[HOME, "    var shown = await P.visiblePosts(deps, ctx, placed, { feed: true });", "    var shown = placed;"]],
  "local-muted": [[HOME, "P.visiblePosts(deps, ctx, placed, { feed: true })", "P.visiblePosts(deps, ctx, placed, {})"]],
  "chosen-city-ignored": [[HOME, "  if (G.clean(hp.local_place)) {", "  if (false) {"]],
  "no-local-line": [[HOME, "posts.forEach(function (p) { var l = localLine(vp.centre, places[p.id]); p.local = { area: l.area, distance_label: l.distance_label }; });", "posts.forEach(function (p) { p.local = null; });"]],
  // E
  "market-free-sellers": [[HOME, "  rows = rows.filter(function (l) { return members.has(l.seller_id); });\n", ""]],
  "market-inactive": [[HOME, "select(LISTING_COLUMNS).eq(\"status\", \"active\");", "select(LISTING_COLUMNS);"], [HOME, "return l && isUuid(l.seller_id) && l.status === \"active\"; });", "return l && isUuid(l.seller_id); });"]],
  "market-hidden": [[HOME, "  var hidden = await SF.hiddenAmong(deps.sb, \"listing\", rows.map(function (l) { return l.id; }));\n  return rows.filter(function (l) { return !hidden.has(l.id) && ", "  return rows.filter(function (l) { return "]],
  "market-adult": [[HOME, "return !hidden.has(l.id) && !adultText([l.title, l.description]);", "return !hidden.has(l.id);"]],
  "standing-self": [[HOME, "return id !== ctx.viewer && !ctx.blocked.has(id) && !ctx.muted.has(id);", "return !ctx.blocked.has(id) && !ctx.muted.has(id);"]],
  "standing-blocked": [[HOME, "return id !== ctx.viewer && !ctx.blocked.has(id) && !ctx.muted.has(id);", "return id !== ctx.viewer && !ctx.muted.has(id);"]],
  "standing-muted": [[HOME, "return id !== ctx.viewer && !ctx.blocked.has(id) && !ctx.muted.has(id);", "return id !== ctx.viewer && !ctx.blocked.has(id);"]],
  "standing-banned": [[HOME, "if ((await deps.ownerPublic(list[i])) === true) ok.add(list[i]);", "ok.add(list[i]);"]],
  "market-newest-only": [[HOME, "  if (vp.centre) {\n    ranked.sort(", "  if (false) {\n    ranked.sort("]],
  "market-near-unsorted": [[HOME, "        if (am !== bm) return am - bm;\n", ""]],
  "market-reach-ignored": [[HOME, "var near = !!(vp.centre && there && G.withinReach(vp.reach, vp.centre, there));", "var near = !!(vp.centre && there);"]],
  "market-unknown-category-all": [[HOME, "  if (cat && !(await CAT.find(deps.sb, cat))) cat = \"__none__\";", "  if (cat && !(await CAT.find(deps.sb, cat))) cat = null;"]],
  "market-category-ignored": [[HOME, "  if (category) q = q.eq(\"category_slug\", category);\n", ""]],
  "market-cursor-loose": [[HOME, "    if (!/^o\\d{1,5}$/.test(String(raw))) return fail(400, MESSAGES.cursor);", "    if (false) return fail(400, MESSAGES.cursor);"]],
  "market-page-size": [[HOME, "const MARKET_PAGE = 10;", "const MARKET_PAGE = 20;"]],
  "dot-always": [[HOME, "market_new: fresh.length > 0", "market_new: true"]],
  "dot-ignores-seen": [[HOME, "var fresh = await marketRows(deps, ctx, null, seen, DOT_SCAN);", "var fresh = await marketRows(deps, ctx, null, null, DOT_SCAN);"]],
  "seen-not-saved": [[HOME, "{ user_id: viewerId, market_seen_at: nowOf(deps), updated_at: nowOf(deps) }", "{ user_id: viewerId, updated_at: nowOf(deps) }"]],
  // F
  "like-blocked": [[HOME, "if (!l || l.status !== \"active\" || ctx.blocked.has(l.seller_id)) return fail(404", "if (!l || l.status !== \"active\") return fail(404"]],
  "like-inactive": [[HOME, "if (!l || l.status !== \"active\" || ctx.blocked.has(l.seller_id)) return fail(404", "if (!l || ctx.blocked.has(l.seller_id)) return fail(404"]],
  "like-hidden": [[HOME, "    if ((await SF.hiddenAmong(deps.sb, \"listing\", [l.id])).has(l.id)) return fail(404, MESSAGES.notAvailable, { reason: \"not_available\" });\n", ""]],
  "like-banned-seller": [[HOME, "    if ((await deps.ownerPublic(l.seller_id)) !== true) return fail(404, MESSAGES.notAvailable, { reason: \"not_available\" });\n", ""]],
  "likes-unlimited": [[HOME, "      if (c.count > LISTING_LIKES_PER_HOUR - 1) return fail(429", "      if (false) return fail(429"]],
  "likes-off-by-one": [[HOME, "c.count > LISTING_LIKES_PER_HOUR - 1", "c.count > LISTING_LIKES_PER_HOUR"]],
  "unlike-anyones": [[HOME, "    var del = await deps.sb.from(table).delete().eq(\"listing_id\", l.id).eq(\"user_id\", ctx.viewer);", "    var del = await deps.sb.from(table).delete().eq(\"listing_id\", l.id);"]],
  "save-to-likes": [[HOME, "function saveListing(deps, viewerId, id, on) { return listingReact(deps, viewerId, id, \"listing_saves\", on); }", "function saveListing(deps, viewerId, id, on) { return listingReact(deps, viewerId, id, \"listing_likes\", on); }"]],
  "cards-liked-anyones": [[HOME, "deps.sb.from(\"listing_likes\").select(\"listing_id\").eq(\"user_id\", ctx.viewer).in(\"listing_id\", ids)", "deps.sb.from(\"listing_likes\").select(\"listing_id\").in(\"listing_id\", ids)"]],
  // G
  "suggest-followed": [[HOME, "return p && isUuid(p.user_id) && !ctx.following.has(p.user_id); })", "return p && isUuid(p.user_id); })"]],
  "suggest-adult": [[HOME, "    .filter(function (p) { return !adultText([p.display_name, p.username]); });   // never an adult name, as in Search", ";"]],
  "suggest-cap": [[HOME, "const SUGGEST_MAX = 8;", "const SUGGEST_MAX = 9;"]],
  "suggest-no-distance": [[HOME, "return a.miles - b.miles || b.shared - a.shared", "return b.shared - a.shared"]],
  "suggest-no-shared": [[HOME, "a.miles - b.miles || b.shared - a.shared || b.v - a.v", "a.miles - b.miles || b.v - a.v"]],
  "suggest-unverified-first": [[HOME, "b.shared - a.shared || b.v - a.v || a.i - b.i", "b.shared - a.shared || a.v - b.v || a.i - b.i"]],
  // H
  "search-adult-query": [[SEARCH, "  var adult = HT.adultText([t]);", "  var adult = false;"]],
  "search-posts-adult": [[SEARCH, "  return shown.filter(function (p) { return !HT.adultText([p.body]); });", "  return shown;"]],
  "search-people-adult": [[SEARCH, "return ok.has(p.user_id) && !HT.adultText([p.display_name, p.username]); });", "return ok.has(p.user_id); });"]],
  "search-no-visibility": [[SEARCH, "  var shown = await P.visiblePosts(deps, ctx, r.data || [], { feed: true, publishedOnly: true });", "  var shown = r.data || [];"]],
  "search-found-needs": [[SEARCH, "q.eq(\"intent\", \"need\").is(\"need_found_at\", null)", "q.eq(\"intent\", \"need\")"]],
  "search-needs-in-posts": [[SEARCH, ": q.in(\"intent\", [\"share\", \"offer\"]);", ": q;"]],
  "search-city-optout": [[SEARCH, "\",and(place_city.ilike.\" + v + \",local_opt_in.is.true)\"", "\",place_city.ilike.\" + v"]],
  "search-business-ignored": [[SEARCH, "    deps.sb.from(\"profiles\").select(\"user_id\").ilike(\"business_name\", \"%\" + t + \"%\").limit(SCAN),", "    Promise.resolve({ data: [] }),"]],
  "search-category-ignored": [[SEARCH, "  var slugs = adult ? [] : await categorySlugs(deps.sb, t);", "  var slugs = [];"]],
  "search-group-size": [[SEARCH, "const GROUP = { people: 3,", "const GROUP = { people: 4,"]],
  "search-page": [[SEARCH, "const PAGE = 20;", "const PAGE = 25;"]],
  "search-cursor-on-all": [[SEARCH, "if (scope === \"all\" || !/^o\\d{1,4}$/", "if (!/^o\\d{1,4}$/"]],
  "search-one-letter": [[SEARCH, "return n < Q_MIN || n > Q_MAX ? null : t;", "return n < 1 || n > Q_MAX ? null : t;"]],
  "search-handle-at": [[SEARCH, ".trim().replace(/^@+/, \"\").trim();", ".trim();"]],
  "search-any-scope": [[SEARCH, "  if (SCOPES.indexOf(scope) === -1) return fail(400, MESSAGES.scope, { field: \"scope\" });\n", "  if (SCOPES.indexOf(scope) === -1) scope = \"people\";\n"]],
  // I
  "search-unlimited": [[SERVER, "app.get(\"/api/search\", requireAuth, searchLimiter, postRoute(", "app.get(\"/api/search\", requireAuth, postRoute("]],
  "search-signed-out": [[SERVER, "app.get(\"/api/search\", requireAuth, searchLimiter, postRoute(", "app.get(\"/api/search\", searchLimiter, postRoute("]],
  "search-limit-loose": [[SERVER, "  max: 60,\n  keyGenerator: function (req) { return \"search:\"", "  max: 600,\n  keyGenerator: function (req) { return \"search:\""]],
  "prefs-unlimited": [[SERVER, "app.put(\"/api/home/prefs\", requireAuth, homePrefsLimiter, postRoute(", "app.put(\"/api/home/prefs\", requireAuth, postRoute("]],
  "deps-no-request": [[SERVER, ",\n    request: require(\"./lib/guardedFetch\").guardedJsonRequest };", " };"]],
  "place-lookup-awaited": [[SERVER, "    require(\"./lib/homeTabs\").locateProfile(homeDeps(), req.user.id,", "    await require(\"./lib/homeTabs\").locateProfile(homeDeps(), req.user.id,"]],
  // J
  "storage-unguarded": [[TABS, "function keptTab() { try { return localStorage.getItem(TAB_KEY); } catch (e) { return null; } }", "function keptTab() { return localStorage.getItem(TAB_KEY); }"]],
  "search-field-small": [[TABS, "color:#e6eaf5;font:400 16px/1 \" + F + \";outline:none;padding:0}", "color:#e6eaf5;font:400 14px/1 \" + F + \";outline:none;padding:0}"]],
  "swipe-tabs": [[TABS, "  window.addEventListener(\"resize\", function () {", "  document.addEventListener(\"touchend\", function () { setTab(\"market\"); });\n  window.addEventListener(\"resize\", function () {"]],
  "market-tip": [[TABS, "'<button type=\"button\" class=\"bfm-act\" data-mact=\"share\"", "'<button type=\"button\" class=\"bfm-act\" data-mact=\"tip\">Tip</button><button type=\"button\" class=\"bfm-act\" data-mact=\"share\""]],
  "buy-ungated": [[TABS, "data-bf-buy data-mact=\"buy\"", "data-mact=\"buy\""]],
  "ask-ungated": [[TABS, "data-mact=\"ask\" data-members-only", "data-mact=\"ask\""]],
  "back-to-following": [[TABS, "    setTab(S.from, true);", "    setTab(\"following\", true);"]],
  "tab-not-kept": [[TABS, "    keepTab(name);\n", ""]],
  "recent-unlimited": [[TABS, "var RECENT_MAX = 8;", "var RECENT_MAX = 80;"]],
  "dot-always-drawn": [[HOMEPAGE, "<button type=\"button\" class=\"feed-tab\" role=\"tab\" id=\"tabMarket\"", "<button type=\"button\" class=\"feed-tab has-dot\" role=\"tab\" id=\"tabMarket\""]],
  "verified-race": [[SELLER, "  if (data.verified) whenVerified(function () {", "  if (window.bfVerified && data.verified) (function (fn) { fn(); })(function () {"]],
  "osm-missing": [[SETTINGS, " Data from OpenStreetMap contributors.</p>", "</p>"]],
  "feed-path-ignored": [[FEED, "(opts.local === true ? call(\"GET\", \"/api/feed/local\" + page) : ", "(false ? call(\"GET\", \"/api/feed/local\" + page) : "]],
  "local-line-missing": [[FEED, "    if (p.local && typeof p.local === \"object\") {", "    if (false) {"]],
  // K (NAMED (Nov 25 2026, H1B)): each of 208's rules loses its IS NOT NULL guard, a bound, or its name
  "k-geo-half": [[M208, "(found AND lat IS NOT NULL AND lng IS NOT NULL AND lat BETWEEN", "(found AND lat BETWEEN"]],
  "k-profile-half": [[M208, "(place_lat IS NOT NULL AND place_lng IS NOT NULL AND place_lat BETWEEN", "(place_lat BETWEEN"]],
  "k-post-half": [[M208, "(need_lat IS NOT NULL AND need_lng IS NOT NULL AND need_lat BETWEEN", "(need_lat BETWEEN"]],
  "k-prefs-half": [[M208, "(local_lat IS NOT NULL AND local_lng IS NOT NULL AND local_lat BETWEEN", "(local_lat BETWEEN"]],
  "k-post-lng-only": [[M208, "need_lat IS NOT NULL AND need_lng IS NOT NULL AND need_lat", "need_lat IS NOT NULL AND need_lat"]],
  "k-prefs-wide": [[M208, "local_lat BETWEEN -90 AND 90", "local_lat BETWEEN -90 AND 95"]],
  "k-geo-notfound-point": [[M208, "(NOT found AND lat IS NULL AND lng IS NULL));", "(NOT found AND lat IS NULL));"]],
  "k-208-renamed": [[M208, "ADD CONSTRAINT bf_profiles_place_point_check", "ADD CONSTRAINT bf_profiles_place_point_check2"]],
  "k-208-unsafe": [[M208, "-- ===== PART 208b", "BEGIN;\n-- ===== PART 208b"]],
  "k-208-no-drop": [[M208, "ALTER TABLE public.posts DROP CONSTRAINT IF EXISTS posts_need_point_check;\n", ""]]
};
const T = H.setup(__filename, MUTATIONS, [SERVER, POSTS, GEO, HOME, SEARCH, TABS, HOMEPAGE, SELLER, SETTINGS, FEED, M207, M208]);
const { FILES, check, J, has } = T;
const G = T.libRequire("./lib/geo");
const HT = T.libRequire("./lib/homeTabs");
const SR = T.libRequire("./lib/search");
const P = T.libRequire("./lib/posts");

const u = n => "aaaaaaaa-0000-4000-8000-" + String(n).padStart(12, "0");
const pid = n => "dddddddd-0000-4000-8000-" + String(n).padStart(12, "0");
const lid = n => "cccccccc-0000-4000-8000-" + String(n).padStart(12, "0");
const V = u(1), A = u(2), B = u(3), B2 = u(4), C = u(5), D = u(6), E = u(7), FR = u(8), F = u(9), M = u(10), X = u(11), FO = u(12), S = u(13), Q = u(14), Z = u(15);
const NOW = "2026-11-25T12:00:00.000Z", OLD = "2026-01-01T00:00:00.000Z";
const minus = m => new Date(Date.parse(NOW) - m * 60000).toISOString();
const SD = [32.72, -117.16];

function world(o) {
  o = o || {};
  const prof = (id, username, name, city, pt, optIn, extra) => Object.assign({ user_id: id, username, display_name: name, avatar_url: null, place_city: city, place_region: city ? "CA" : null,
    place_country: city ? "US" : null, place_lat: pt ? pt[0] : null, place_lng: pt ? pt[1] : null, local_opt_in: !!optIn, verified_reason: null, updated_at: OLD }, extra || {});
  const profiles = [
    prof(V, "veralane", "Vera Lane", "San Diego", SD, true),
    prof(A, "rosacuts", "Rosa Diaz", "North Park, San Diego", [32.73, -117.16], true),
    prof(B, "benito", "Ben Ito", "La Jolla", [32.84, -117.27], true),
    prof(B2, "esccobb", "Esc Cobb", "Escondido", [33.12, -117.09], true),
    prof(C, "caralopez", "Cara Lopez", "Los Angeles", [34.05, -118.24], true),
    prof(D, "danafox", "Dana Fox", "San Diego", SD, false, { updated_at: "2026-11-02T00:00:00.000Z" }),
    prof(E, "elipark", "Eli Park", "San Diego", null, true, { verified_reason: "member" }),
    prof(FR, "freddie", "Freddie Moss", "San Diego", SD, true),
    prof(F, "fiona", "Fiona Black", "San Diego", SD, true),
    prof(M, "milo", "Milo Hart", "San Diego", SD, true),
    prof(X, "xavier", "Xavier Cole", "San Diego", SD, true),
    prof(FO, "fola", "Fola Ade", "San Diego", SD, true),
    prof(S, "samreed", "Sam Reed", null, null, false),
    prof(Q, "quinn", "Quinn Ray", null, null, false, { updated_at: "2026-11-01T00:00:00.000Z" }),
    prof(Z, "xxxstudio", "XXX Studio", "San Diego", SD, true)
  ];
  if (o.many) for (let i = 1; i < 23; i++) profiles.push(prof(u(100 + i), "painter" + String(i).padStart(2, "0"), "Painter " + i, null, null, false));
  let n = 0;
  const post = (id, author, body, extra) => Object.assign({ id, author_id: author, body, kind: "text", intent: "share", category: "hair_beauty", status: "published", audience: "public",
    published_at: minus(++n), created_at: minus(n), like_count: 0, comment_count: 0, save_count: 0, share_count: 0, need_place: null, need_when: null, need_found_at: null, need_lat: null, need_lng: null, listing_id: null }, extra || {});
  const posts = [
    post(pid(1), A, "Fresh fade in North Park"),
    post(pid(2), B, "Glow facial openings"),
    post(pid(3), B2, "Escondido market day"),
    post(pid(4), C, "LA shoot recap"),
    post(pid(5), D, "Dana's open house", { category: "cleaning_moving" }),
    post(pid(6), E, "Eli's walk-in hours", { category: "art" }),
    post(pid(7), F, "Fresh fade special"),
    post(pid(8), M, "fade day"),
    post(pid(9), X, "fade deal"),
    post(pid(10), A, "Followers note", { audience: "followers" }),
    post(pid(11), A, "Pending note", { status: "pending" }),
    post(pid(12), A, "hidden circle"),
    post(pid(13), A, "nudes for sale"),
    post(pid(14), S, "Need a tattoo artist this week", { intent: "need", category: "tattoo_body_art", need_place: "San Diego" }),
    post(pid(15), S, "Need a mover", { intent: "need", category: "cleaning_moving", need_place: "Austin, TX" }),
    post(pid(16), S, "Need a photographer", { intent: "need", category: "photography" }),
    post(pid(17), S, "Need a tattoo touch up", { intent: "need", category: "tattoo_body_art", need_place: "San Diego", need_found_at: minus(1) }),
    post(pid(18), FR, "Freddie's fresh cuts"),
    post(pid(19), FO, "Members circle update", { audience: "followers" }),
    post(pid(20), FO, "circle draft", { status: "pending" })
  ];
  let k = 0;
  const listing = (id, seller, title, cat, extra) => Object.assign({ id, slug: null, seller_id: seller, title, description: "", price_bfc: 40, category_slug: cat, category: cat, listing_kind: "service",
    media: [], status: "active", created_at: minus(++k) }, extra || {});
  const listings = [
    listing(lid(3), C, "LA portrait session", "art"),
    listing(lid(13), B2, "Escondido mural", "art"),
    listing(lid(14), D, "Moving help", "cleaning_moving"),
    listing(lid(4), E, "Eli's sketch", "art"),
    listing(lid(2), B, "Glow facial", "hair_beauty"),
    listing(lid(1), A, "Fade and beard trim", "hair_beauty", { description: "Skin fade, beard line-up", media: [{ url: "https://cdn.example/fade.jpg" }] })
  ];
  for (let i = 1; i < 9; i++) listings.push(listing(lid(30 + i), C, "Print " + i, "art"));
  listings.push(
    listing(lid(5), FR, "Fade kit", "hair_beauty"),
    listing(lid(6), V, "Vera's frames", "art"),
    listing(lid(7), F, "Fiona's fade", "hair_beauty"),
    listing(lid(8), X, "Xavier's trims", "hair_beauty"),
    listing(lid(9), A, "Paused trim", "hair_beauty", { status: "paused" }),
    listing(lid(10), A, "Hidden trim", "hair_beauty"),
    listing(lid(11), A, "xxx videos", "art"),
    listing(lid(12), M, "Milo's cuts", "hair_beauty"));
  const db = memDb({
    categories: CATEGORY_ROWS,
    users: [], bf_profiles: profiles,
    profiles: [{ user_id: B, business_name: "Jolla Glow Studio", full_name: null, logo_url: null }],
    posts, post_media: [], post_comments: [], post_likes: [], post_saves: [], post_share_days: [], notifications: [], user_preferences: [],
    follows: [{ follower_id: V, following_id: FO }],
    member_blocks: [{ blocker_id: F, blocked_id: V }],
    member_mutes: [{ muter_id: V, muted_id: M }],
    moderation_queue: [{ id: u(900), object_type: "post", object_id: pid(12), state: "hidden" }, { id: u(901), object_type: "listing", object_id: lid(10), state: "hidden" }],
    marketplace_listings: listings,
    lead_fingerprints: [{ user_id: V, categories: ["hair_beauty"], reach: "local" }, { user_id: S, categories: ["hair_beauty"], reach: "online" }],
    home_prefs: [], geo_cache: [], listing_likes: [], listing_saves: []
  });
  const banned = new Set([X]), free = new Set([FR]);
  const W = { db, now: NOW, calls: [], sleeps: [], t: 1e9, answers: {} };
  W.deps = { sb: db.client, now: () => W.now, env: {}, claims: () => null, push: async () => {}, background: j => j,
    ownerPublic: async id => !banned.has(id), tierOf: async id => (free.has(id) ? "free" : "member"), membersPanel: () => ({ title: "Members" }),
    clock: () => W.t, sleep: async ms => { W.sleeps.push(ms); W.t += ms; } };
  W.lookups = () => { W.deps.request = async (url, opts) => { W.calls.push({ url, opts }); const a = W.answers[decodeURIComponent((/[?&]q=([^&]*)/.exec(url) || [])[1] || "")]; if (a instanceof Error) throw a; return a || { status: 200, json: [] }; }; };
  return W;
}
const ids = list => (list || []).map(x => x.id || x.user_id);
const setOf = list => J(ids(list).slice().sort());

(async function main() {
  /* ── A ── */
  console.log("\n══ A. distance, its label, the reach ══");
  const sdla = G.milesBetween({ lat: 32.72, lng: -117.16 }, { lat: 34.05, lng: -118.24 });
  check("A1. distance is the great-circle miles between two city points (San Diego to Los Angeles about 111 mi)", sdla > 108 && sdla < 114 && G.milesBetween(null, { lat: 1, lng: 1 }) === null, sdla);
  check("A2. under 1 mile with one decimal (0.8 mi), never 0.0 (0.1 mi at least); whole miles from 1 up",
    G.distanceLabel(0.84) === "0.8 mi" && G.distanceLabel(0.02) === "0.1 mi" && G.distanceLabel(0.96) === "1 mi" && G.distanceLabel(12.4) === "12 mi" && G.distanceLabel(null) === null,
    J([G.distanceLabel(0.84), G.distanceLabel(0.02), G.distanceLabel(0.96), G.distanceLabel(12.4)]));
  const here = { text: "San Diego", point: { lat: 32.72, lng: -117.16 } };
  check("A3. Within 25 mi by the points: 10 mi in, 27 mi (Escondido) out, 111 mi out",
    G.withinReach("25", here, { text: "La Jolla", point: { lat: 32.84, lng: -117.27 } }) && !G.withinReach("25", here, { text: "Escondido", point: { lat: 33.12, lng: -117.09 } }) &&
    !G.withinReach("25", here, { text: "Los Angeles", point: { lat: 34.05, lng: -118.24 } }) && G.REACH_MILES === 25);
  check("A4. a missing point falls back to the city's name as text; My city is the name; Anywhere is everything",
    G.withinReach("25", here, { text: "San Diego", point: null }) && !G.withinReach("25", here, { text: "Austin", point: null }) &&
    G.withinReach("city", here, { text: "North Park, San Diego", point: null }) && !G.withinReach("city", here, { text: "La Jolla", point: { lat: 32.84, lng: -117.27 } }) &&
    G.withinReach("anywhere", here, { text: "Austin", point: null }));
  check("A5. a state code alone never matches two cities; a neighbourhood shows only when typed",
    !G.sameCity("Austin, TX", "Dallas, TX") && G.sameCity("San Diego, CA", "san diego") && J(G.splitPlace("North Park, San Diego")) === J({ area: "North Park", city: "San Diego" }) &&
    G.placeLabel("San Diego") === "San Diego" && G.placeLabel("North Park, San Diego") === "North Park");
  check("A6. points are rounded to 2 decimals (about 1 km) and checked", J(G.point(32.71533, -117.15726)) === J({ lat: 32.72, lng: -117.16 }) && G.point(91, 0) === null && G.point(null, 1) === null);
  check("A7. the reaches: My city, Within 25 mi (the default), Anywhere", J(G.REACHES) === J(["city", "25", "anywhere"]) && G.normalReach(undefined) === "25" && G.normalReach("50") === "25");

  /* ── B ── */
  console.log("\n══ B. geocoding: once a second, a real User-Agent, cached ══");
  let w = world();
  G.resetQueue();
  let g = await G.geocode(w.deps, { text: "San Diego" });
  check("B1. no request function: nothing is looked up and the cache is not read (no check reaches Nominatim)", g.source === "off" && !w.db.log.some(q => q.table === "geo_cache"), J(g));
  w.lookups();
  w.answers["san diego, ca"] = { status: 200, json: [{ lat: "32.71533", lon: "-117.15726" }] };
  g = await G.geocode(w.deps, { text: "San Diego", region: "CA" });
  const c0 = w.calls[0] || { opts: { headers: {} }, url: "" };
  check("B2. a lookup: the point rounded to 2 decimals, kept in geo_cache by the place's text", g.source === "lookup" && J(g.point) === J({ lat: 32.72, lng: -117.16 }) &&
    w.db.t.geo_cache.length === 1 && w.db.t.geo_cache[0].place_key === "san diego, ca" && w.db.t.geo_cache[0].lat === 32.72 && w.db.t.geo_cache[0].found === true, J([g, w.db.t.geo_cache]));
  check("B3. the request: Nominatim, a User-Agent naming BizForce and its support address (lib/legal.js), a timeout",
    c0.url.indexOf("https://nominatim.openstreetmap.org/search?") === 0 && /BizForce/.test(c0.opts.headers["User-Agent"] || "") && /support@bizforceai\.net/.test(c0.opts.headers["User-Agent"] || "") &&
    c0.opts.timeoutMs > 0, J(c0));
  g = await G.geocode(w.deps, { text: "  san   DIEGO ", region: "ca" });
  check("B4. the same place again (any case or spacing) is answered by the cache, no second request", g.source === "cache" && w.calls.length === 1 && J(g.point) === J({ lat: 32.72, lng: -117.16 }), J([g, w.calls.length]));
  g = await G.geocode(w.deps, { text: "Nowhereville" });
  const g2 = await G.geocode(w.deps, { text: "Nowhereville" });
  check("B5. not found is an answer: cached too, asked once", g.source === "not_found" && g2.source === "cache" && g2.point === null && w.calls.length === 2 && w.db.t.geo_cache.some(r => r.place_key === "nowhereville" && r.found === false), J([g, g2]));
  w.answers["brokenville"] = { status: 503, json: null };
  w.answers["throwville"] = new Error("network");
  const g3 = await G.geocode(w.deps, { text: "Brokenville" }), g4 = await G.geocode(w.deps, { text: "Throwville" });
  check("B6. a failed request (an HTTP error, no answer) is not an answer: failed, never cached", g3.source === "failed" && g4.source === "failed" && !w.db.t.geo_cache.some(r => r.place_key === "brokenville" || r.place_key === "throwville"), J([g3, g4]));
  check("B7. one request a second across the server: each lookup after the first waited 1000 ms", J(w.sleeps) === J([1000, 1000, 1000]) && G.SLOT_MS === 1000, J(w.sleeps));
  G.resetQueue();
  const fixed = { clock: () => 5e9 };
  const waits = []; for (let i = 0; i < 10; i++) waits.push(G.takeSlot(fixed));
  check("B8. the queue is shared and bounded: waits 0, 1000 ... 8000 ms, then busy (nothing is looked up)", J(waits) === J([0, 1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, -1]), J(waits));
  const busy = await G.geocode(Object.assign({}, w.deps, fixed), { text: "Busyville" });
  check("B9. busy: no request, nothing cached", busy.source === "busy" && w.calls.length === 4, J(busy));
  G.resetQueue();
  check("B10. the attribution", G.ATTRIBUTION === "Data from OpenStreetMap contributors" && G.lookupUrl("x", "US").indexOf("&countrycodes=us") !== -1);

  /* ── C ── */
  console.log("\n══ C. Change, the profile point, a Need's point ══");
  w = world(); w.lookups(); G.resetQueue();
  w.answers["los angeles"] = { status: 200, json: [{ lat: "34.0522", lon: "-118.2437" }] };
  let r = await HT.savePrefs(w.deps, V, { reach: "50" });
  const rPlace = await HT.savePrefs(w.deps, V, { place: "x".repeat(81) });
  check("C1. the reach is My city, Within 25 mi or Anywhere; a place 2 to 80 characters", r.status === 400 && r.body.field === "reach" && rPlace.status === 400 && rPlace.body.field === "place" &&
    (await HT.savePrefs(w.deps, V, { place: "x" })).status === 400 && w.db.t.home_prefs.length === 0, J([r, rPlace]));
  r = await HT.savePrefs(w.deps, V, { place: "Los Angeles", reach: "25" });
  const hp = w.db.t.home_prefs[0] || {};
  check("C2. Use a different city: looked up, kept per member with its rounded point", r.status === 200 && hp.local_place === "Los Angeles" && hp.local_lat === 34.05 && hp.local_lng === -118.24 &&
    r.body.place.label === "Los Angeles" && r.body.place.chosen === true && r.body.reach === "25" && r.body.attribution === G.ATTRIBUTION, J([r, hp]));
  w.answers["atlantis"] = { status: 500, json: null };
  r = await HT.savePrefs(w.deps, V, { place: "Atlantis" });
  check("C3. a failed lookup still saves the place (Local then matches it by name)", r.status === 200 && w.db.t.home_prefs[0].local_place === "Atlantis" && w.db.t.home_prefs[0].local_lat === null && r.body.lookup === "failed", J(r));
  r = await HT.savePrefs(w.deps, V, { reach: "city", place: null });
  check("C4. My city: the member's own city again", r.status === 200 && w.db.t.home_prefs[0].local_place === null && r.body.place.label === "San Diego, CA" && r.body.place.chosen === false && r.body.reach === "city", J(r));
  w = world(); w.lookups(); G.resetQueue();
  w.answers["austin, tx, us"] = { status: 200, json: [{ lat: "30.267", lon: "-97.743" }] };
  const before = { place_city: "San Diego", place_region: "CA", place_country: "US", place_lat: 32.72, place_lng: -117.16 };
  r = await HT.locateProfile(w.deps, V, before, { place_city: "San Diego", place_region: "CA", place_country: "US" });
  check("C5. the profile place unchanged with a point: not looked up again", r.source === "unchanged" && w.calls.length === 0, J(r));
  r = await HT.locateProfile(w.deps, V, before, { place_city: "Austin", place_region: "TX", place_country: "US" });
  const vrow = w.db.t.bf_profiles.find(p => p.user_id === V);
  check("C6. a new place: looked up (the country sent), the point saved rounded", r.source === "lookup" && vrow.place_lat === 30.27 && vrow.place_lng === -97.74 && /countrycodes=us/.test(w.calls[0].url), J([r, vrow.place_lat]));
  r = await HT.locateProfile(w.deps, V, { place_city: "Austin", place_lat: 30.27, place_lng: -97.74 }, { place_city: null });
  check("C7. the place cleared: the point cleared too", vrow.place_lat === null && vrow.place_lng === null, J([r, vrow.place_lat]));
  w = world(); w.lookups(); G.resetQueue();
  w.answers["san diego"] = { status: 200, json: [{ lat: "32.7153", lon: "-117.1573" }] };
  const src = await HT.startNeedPoint(w.deps, w.db.t.posts.find(p => p.id === pid(14)));
  const p14 = w.db.t.posts.find(p => p.id === pid(14));
  check("C8. a Need's place gets its own point after it is saved; a share never looks up", src === "lookup" && p14.need_lat === 32.72 && p14.need_lng === -117.16 &&
    (await HT.startNeedPoint(w.deps, w.db.t.posts.find(p => p.id === pid(1)))) === null, J([src, p14.need_lat]));
  const cp = FILES[POSTS].indexOf("require(\"./homeTabs\").startNeedPoint(deps, post);"), cpa = FILES[POSTS].indexOf("startNeedAlerts(deps, post);   // NAMED (Nov 23 2026, P3-3)");
  check("C9. createPost starts the Need's point after the save, never awaited", cp > cpa && cpa > 0 && FILES[POSTS].slice(cp - 8, cp).indexOf("await") === -1);

  /* ── D ── */
  console.log("\n══ D. Local ══");
  w = world();
  r = await HT.localFeed(w.deps, V);
  const lp = r.body.posts || [];
  check("D1. Within 25 mi (the default): public posts and open Needs near the member, newest first", r.status === 200 && r.body.reach === "25" &&
    J(ids(lp)) === J([pid(1), pid(2), pid(6), pid(14), pid(18)]), J(ids(lp)));
  check("D2. never: out of reach, a member not showing posts in Local, blocked either way, muted, suspended, Followers-only, held, hidden by moderation, adult, a Found Need",
    [3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 17, 19, 20].every(i => ids(lp).indexOf(pid(i)) === -1));
  const l1 = lp.find(p => p.id === pid(1)) || {}, l6 = lp.find(p => p.id === pid(6)) || {};
  check("D3. each post's line: the neighbourhood (only when typed) and the distance", l1.local && l1.local.area === "North Park" && l1.local.distance_label === "0.7 mi" &&
    l6.local && l6.local.area === "San Diego" && l6.local.distance_label === null, J([l1.local, l6.local]));
  check("D4. the place chip and the attribution", r.body.place && r.body.place.label === "San Diego, CA" && r.body.place.located === true && r.body.attribution === G.ATTRIBUTION, J(r.body.place));
  w.db.t.home_prefs.push({ user_id: V, local_reach: "city" });
  r = await HT.localFeed(w.deps, V);
  check("D5. My city: the city's name, any distance", J(ids(r.body.posts)) === J([pid(1), pid(6), pid(14), pid(18)]), J(ids(r.body.posts)));
  w.db.t.home_prefs[0].local_reach = "anywhere";
  r = await HT.localFeed(w.deps, V);
  check("D6. Anywhere: every public post and open Need, a Need with no place only here", J(ids(r.body.posts)) === J([pid(1), pid(2), pid(3), pid(4), pid(6), pid(14), pid(15), pid(16), pid(18)]), J(ids(r.body.posts)));
  Object.assign(w.db.t.home_prefs[0], { local_reach: "25", local_place: "Los Angeles", local_lat: 34.05, local_lng: -118.24 });
  r = await HT.localFeed(w.deps, V);
  check("D7. Use a different city: Local around that city", J(ids(r.body.posts)) === J([pid(4)]) && r.body.place.chosen === true, J(ids(r.body.posts)));
  r = await HT.localFeed(w.deps, S);
  check("D8. no place set: none shown, place null (the tab offers Add your city)", r.status === 200 && r.body.place === null && r.body.posts.length === 0, J(r.body));
  check("D9. a bad page marker is refused", (await HT.localFeed(w.deps, V, "zz")).status === 400);

  /* ── E ── */
  console.log("\n══ E. Market ══");
  w = world();
  r = await HT.marketFeed(w.deps, V, {});
  const m1 = r.body.listings || [];
  const NEAR_ORDER = [lid(1), lid(2), lid(4), lid(3), lid(13), lid(14), lid(31), lid(32), lid(33), lid(34)];
  check("E1. within reach first, nearest first (a seller with no point after), then the rest newest first", r.status === 200 && J(ids(m1)) === J(NEAR_ORDER), J(ids(m1)));
  check("E2. active listings by members only: never a free account's, the viewer's own, blocked either way, muted, suspended, paused, hidden by moderation, adult",
    [5, 6, 7, 8, 9, 10, 11, 12].every(i => ids(m1).indexOf(lid(i)) === -1));
  const r2 = await HT.marketFeed(w.deps, V, { cursor: r.body.next_cursor });
  check("E3. ten a page; the next page goes on", r.body.next_cursor === "o10" && J(ids(r2.body.listings)) === J([lid(35), lid(36), lid(37), lid(38)]) && r2.body.next_cursor === null, J([r.body.next_cursor, ids(r2.body.listings)]));
  const c1 = m1[0] || {};
  check("E4. a card: photo, category and place, title, seller, gold price in BizCash; no Tip", c1.photo === "https://cdn.example/fade.jpg" && c1.category && c1.category.name === "Hair & Beauty" &&
    c1.place === "North Park" && c1.distance_label === "0.7 mi" && c1.seller && c1.seller.name === "Rosa Diaz" && c1.price_bfc === 40 && !("tip" in c1), J(c1));
  r = await HT.marketFeed(w.deps, S, {});
  check("E5. with no place: newest first", J(ids(r.body.listings).slice(0, 6)) === J([lid(3), lid(13), lid(14), lid(4), lid(2), lid(1)]), J(ids(r.body.listings)));
  r = await HT.marketFeed(w.deps, V, { category: "hair_beauty" });
  const rNone = await HT.marketFeed(w.deps, V, { category: "no_such_cat" });
  check("E6. a category chip (from the categories table): that category only; an unknown one shows nothing", J(ids(r.body.listings)) === J([lid(1), lid(2)]) && rNone.body.listings.length === 0, J([ids(r.body.listings), ids(rNone.body.listings)]));
  check("E7. a bad page marker is refused", (await HT.marketFeed(w.deps, V, { cursor: "x" })).status === 400 && (await HT.marketFeed(w.deps, V, { cursor: "o1x" })).status === 400);
  let st = await HT.tabsState(w.deps, V);
  check("E8. the Market dot: never visited, any member's listing counts", st.body.market_new === true && st.body.reach === "25", J(st.body));
  await HT.marketSeen(w.deps, V);
  st = await HT.tabsState(w.deps, V);
  check("E9. after a visit: no dot until something new", st.body.market_new === false && w.db.t.home_prefs[0].market_seen_at === NOW, J([st.body, w.db.t.home_prefs]));
  w.db.t.marketplace_listings.push({ id: lid(60), seller_id: FR, title: "New free", category_slug: "art", status: "active", media: [], created_at: "2026-11-25T13:00:00.000Z" });
  st = await HT.tabsState(w.deps, V);
  const freeOnly = st.body.market_new;
  w.db.t.marketplace_listings.push({ id: lid(61), seller_id: A, title: "New member", category_slug: "art", status: "active", media: [], created_at: "2026-11-25T13:00:00.000Z" });
  st = await HT.tabsState(w.deps, V);
  check("E10. the dot comes back for a member's new listing, never a free account's", freeOnly === false && st.body.market_new === true, J([freeOnly, st.body]));

  /* ── F ── */
  console.log("\n══ F. Like and Save on listings ══");
  w = world();
  await HT.likeListing(w.deps, A, lid(2), true);
  r = await HT.likeListing(w.deps, V, lid(2), true);
  const r2b = await HT.likeListing(w.deps, V, lid(2), true);
  check("F1. Like: one row per member (twice is still one)", r.status === 200 && r.body.liked === true && r2b.status === 200 && w.db.t.listing_likes.filter(x => x.user_id === V).length === 1, J(r));
  let cards = (await HT.marketFeed(w.deps, V, {})).body.listings;
  check("F2. the card says the viewer's own Like", (cards.find(x => x.id === lid(2)) || {}).liked === true && (cards.find(x => x.id === lid(1)) || {}).liked === false);
  r = await HT.likeListing(w.deps, V, lid(2), false);
  check("F3. Unlike removes the viewer's row only", r.status === 200 && !w.db.t.listing_likes.some(x => x.user_id === V) && w.db.t.listing_likes.some(x => x.user_id === A), J(w.db.t.listing_likes));
  cards = (await HT.marketFeed(w.deps, V, {})).body.listings;
  check("F4. another member's Like is not the viewer's", (cards.find(x => x.id === lid(2)) || {}).liked === false);
  r = await HT.saveListing(w.deps, V, lid(1), true);
  check("F5. Save: its own table", r.status === 200 && r.body.saved === true && w.db.t.listing_saves.length === 1 && w.db.t.listing_saves[0].listing_id === lid(1) && !w.db.t.listing_likes.some(x => x.listing_id === lid(1)), J(w.db.t.listing_saves));
  const refused = [];
  for (const [who, l] of [[V, lid(7)], [V, lid(9)], [V, lid(10)], [V, lid(8)], [V, "not-a-uuid"], [V, lid(99)]]) refused.push((await HT.likeListing(w.deps, who, l, true)).status);
  check("F6. refused as not available: blocked either way, paused, hidden by moderation, a suspended seller, no such listing", J(refused) === J([404, 404, 404, 404, 404, 404]) &&
    (await HT.saveListing(w.deps, V, lid(7), true)).status === 404, J(refused));
  w = world();
  for (let i = 0; i < 199; i++) w.db.t.listing_likes.push({ listing_id: lid(500 + i), user_id: V, created_at: minus(30) });
  w.db.t.listing_likes.push({ listing_id: lid(800), user_id: V, created_at: minus(120) });
  const ok199 = await HT.likeListing(w.deps, V, lid(1), true);
  const no200 = await HT.likeListing(w.deps, V, lid(2), true);
  check("F7. 200 likes an hour at most (older ones do not count)", ok199.status === 200 && no200.status === 429 && no200.body.reason === "rate_limited" && HT.LISTING_LIKES_PER_HOUR === 200, J([ok199.status, no200]));

  /* ── G ── */
  console.log("\n══ G. follow suggestions ══");
  w = world();
  r = await HT.suggestPeople(w.deps, V);
  const sg = r.body.people || [];
  check("G1. nearest first, then shared categories, then Verified first among equals; at most 8", J(ids(sg)) === J([FR, A, B, B2, C, E, S, D]), J(sg.map(p => p.username)));
  check("G2. never the viewer, anyone they follow, blocked either way, muted, suspended, or an adult name", [V, FO, F, M, X, Z].every(id => ids(sg).indexOf(id) === -1));
  const sa = sg.find(p => p.user_id === A) || {}, ss = sg.find(p => p.user_id === S) || {}, se = sg.find(p => p.user_id === E) || {};
  check("G3. each row: name, Verified, category and area", sa.name === "Rosa Diaz" && sa.category === "Hair & Beauty" && sa.area === "North Park" && sa.link === "/@rosacuts" &&
    se.verified === "member" && ss.area === "Online", J([sa, se, ss]));

  /* ── H ── */
  console.log("\n══ H. Search ══");
  w = world();
  const sr = async (q, scope, viewer, cursor) => (await SR.search(w.deps, viewer || V, { q, scope, cursor })).body;
  const ppl = async q => ids((await sr(q, "people")).items);
  check("H1. people by handle (with or without @), name, business name", J(await ppl("rosa")) === J([A]) && J(await ppl("@rosacuts")) === J([A]) && J(await ppl("glow")) === J([B]));
  check("H2. people by city only when they show their posts in Local", J(await ppl("la jolla")) === J([B]) && J((await ppl("san diego")).sort()) === J([A, E, FR, FO].sort()), J(await ppl("san diego")));
  check("H3. people by category (their Fingerprint or an active listing's); a free account is a person too", J((await ppl("hair")).sort()) === J([A, B, FR, S].sort()) && J(await ppl("freddie")) === J([FR]), J(await ppl("hair")));
  const never = [];
  for (const q of ["xavier", "fiona", "milo", "veralane"]) never.push((await ppl(q)).length);
  check("H4. never a suspended account, one blocked either way, one muted, or the viewer", J(never) === J([0, 0, 0, 0]) && J(await ppl("studio")) === J([B]), J(never));
  check("H5. listings: members' active ones, never a free account's, hidden, adult", J(ids((await sr("fade", "listings")).items)) === J([lid(1)]) &&
    J(ids((await sr("trim", "listings")).items)) === J([lid(1)]) && (await sr("videos", "listings")).items.length === 0);
  check("H6. posts: never blocked, muted, suspended, hidden or adult", J(ids((await sr("fade", "posts")).items)) === J([pid(1)]) && (await sr("sale", "posts")).items.length === 0 &&
    J(ids((await sr("circle", "posts")).items)) === J([pid(19)]), J(ids((await sr("circle", "posts")).items)));
  check("H7. Followers-only posts only to followers; never held", (await sr("circle", "posts", S)).items.length === 0 && (await sr("draft", "posts")).items.length === 0);
  check("H8. Needs: open ones only, and never among Posts", J(ids((await sr("tattoo", "needs")).items)) === J([pid(14)]) && (await sr("tattoo", "posts")).items.length === 0);
  w.db.clearLog();
  const ad = await sr("nudes", "all");
  check("H9. an adult search finds nothing and reads nothing", ["people", "listings", "posts", "needs"].every(k => ad.groups[k].items.length === 0) &&
    !w.db.log.some(q => ["posts", "marketplace_listings", "profiles"].indexOf(q.table) !== -1 || (q.table === "bf_profiles" && q.op === "select" && q.filters.some(f => f[0] === "or"))), J(w.db.log.map(q => q.table)));
  w = world({ many: true });
  let all = await sr("painter", "all");
  check("H10. All: grouped, at most 3 people, See all when there are more", all.groups.people.items.length === 3 && all.groups.people.more === true && all.groups.listings.more === false, J(all.groups.people));
  const pg1 = await sr("painter", "people"), pg2 = await sr("painter", "people", V, pg1.next_cursor);
  check("H11. one group: 20 a page, then the rest", pg1.items.length === 20 && pg1.next_cursor === "o20" && pg2.items.length === 2 && pg2.next_cursor === null, J([pg1.items.length, pg1.next_cursor, pg2.items.length]));
  const bad = [];
  for (const q of [{ q: "a" }, { q: "x".repeat(81) }, { q: "painter", scope: "everything" }, { q: "painter", scope: "all", cursor: "o20" }, { q: "painter", scope: "people", cursor: "zz" }]) bad.push((await SR.search(w.deps, V, q)).status);
  check("H12. 2 to 80 characters, a known scope, a page marker only within one group", J(bad) === J([400, 400, 400, 400, 400]), J(bad));

  /* ── I ── */
  console.log("\n══ I. the routes ══");
  const sv = FILES[SERVER];
  const routes = ["app.get(\"/api/feed/local\", requireAuth,", "app.get(\"/api/home/tabs\", requireAuth,", "app.put(\"/api/home/prefs\", requireAuth, homePrefsLimiter,", "app.get(\"/api/home/market\", requireAuth,",
    "app.post(\"/api/home/market/seen\", requireAuth,", "app.get(\"/api/home/suggestions\", requireAuth,", "app.post(\"/api/listings/:id/like\", requireAuth,", "app.delete(\"/api/listings/:id/like\", requireAuth,",
    "app.post(\"/api/listings/:id/save\", requireAuth,", "app.delete(\"/api/listings/:id/save\", requireAuth,", "app.get(\"/api/search\", requireAuth, searchLimiter,"];
  check("I1. every route signed in; Search and Change rate-limited", routes.every(x => has(sv, x)), routes.filter(x => !has(sv, x)).join(" | "));
  check("I2. the limits: 60 searches a minute, 30 changes an hour, per member", /max: 60,\n  keyGenerator: function \(req\) \{ return "search:"/.test(sv) && /windowMs: 60 \* 1000,\n  max: 60,/.test(sv) &&
    /windowMs: 60 \* 60 \* 1000,\n  max: 30,\n  keyGenerator: function \(req\) \{ return "home-prefs:"/.test(sv));
  check("I3. the server's deps carry the geocoder's request (guardedFetch); the profile point is never awaited", has(sv, "request: require(\"./lib/guardedFetch\").guardedJsonRequest };") &&
    has(sv, "\n    require(\"./lib/homeTabs\").locateProfile(homeDeps(), req.user.id,") && !has(sv, "await require(\"./lib/homeTabs\").locateProfile("));

  /* ── J ── */
  console.log("\n══ J. the frontend ══");
  const tb = FILES[TABS] || "";
  const lsLines = tb.split("\n").filter(l => /localStorage\./.test(l));
  check("J1. every localStorage use is inside try/catch; recent searches at most 8", lsLines.length >= 2 && lsLines.every(l => /try \{/.test(l)) && has(tb, "var RECENT_MAX = 8;"), lsLines.length);
  check("J2. the search field is 16 px (no zoom on a phone)", /\.bfh-s-input\{[^}]*font:400 16px\/1 /.test(tb));
  check("J3. no sideways swipe between tabs", !/addEventListener\("(touch|pointer)/.test(tb));
  check("J4. Market: no Tip; Buy and Ask members only (bf-access.js answers a free account)", !/data-mact="tip"|>Tip</.test(tb) && has(tb, "data-bf-buy data-mact=\"buy\"") && has(tb, "data-mact=\"ask\" data-members-only"));
  check("J5. back returns to the tab the viewer came from; the last tab is kept", has(tb, "    S.from = S.tab;") && has(tb, "    setTab(S.from, true);") && has(tb, "    keepTab(name);\n"));
  check("J6. home.html: Local and Market are tabs; the Market dot is not drawn by the page", has(FILES[HOMEPAGE], "<script src=\"/scripts/bf-home-tabs.js\"></script>") &&
    !/id="tab(Local|Market)"[^>]*data-soon/.test(FILES[HOMEPAGE]) && !/class="[^"]*has-dot[^"]*"[^>]*id="tabMarket"/.test(FILES[HOMEPAGE]));
  const sl = FILES[SELLER] || "";
  check("J7. the storefront's Verified badge waits for whichever loads last (whenVerified), once", has(sl, "function whenVerified(fn) {") && has(sl, "  if (data.verified) whenVerified(function () {") &&
    has(sl, "if (!nameEl.querySelector(\"[data-bf-verified]\"))"));
  check("J8. the attribution where a member picks their place", has(FILES[SETTINGS], " Data from OpenStreetMap contributors.</p>") && has(tb, "Data from OpenStreetMap contributors"));
  check("J9. bf-feed.js: Local's path and its line", has(FILES[FEED], "(opts.local === true ? call(\"GET\", \"/api/feed/local\" + page) : call(\"GET\", \"/api/feed/following\" + page))") && has(FILES[TABS], "window.BFFeed.mount(host, { full: true, local: true,") && has(FILES[FEED], "    if (p.local && typeof p.local === \"object\") {"));

  /* ── K ── NAMED (Nov 25 2026, H1B) */
  console.log("\n══ K. the point rules (migrations 207 and 208), with SQL's NULL logic ══");
  // A CHECK passes unless it comes out FALSE: NULL (unknown) passes. Each rule is parsed from the migration text and
  // evaluated with three-valued logic (true, false, null), so a half point (one value, the other empty) must come out false.
  {
    const rules = sql => {
      const out = [], re = /ADD CONSTRAINT ([a-z_0-9]+)\s+CHECK \(/g; let m;
      while ((m = re.exec(sql))) {
        let i = re.lastIndex, d = 1; const st = i;
        while (i < sql.length && d) { if (sql[i] === "(") d++; else if (sql[i] === ")") d--; i++; }
        out.push([m[1], sql.slice(st, i - 1)]);
      }
      return out;
    };
    const evalCheck = (src, row) => {
      const toks = src.match(/-?\d+(?:\.\d+)?|[A-Za-z_][A-Za-z_0-9]*|[()]/g) || [];
      let p = 0;
      const peek = () => (toks[p] || "").toUpperCase(), take = w => { if (peek() !== w) throw new Error("expected " + w + " at " + p + " in " + src); p++; };
      const and3 = (a, b) => a === false || b === false ? false : a === null || b === null ? null : true;
      const or3 = (a, b) => a === true || b === true ? true : a === null || b === null ? null : false;
      const num = () => { const t = toks[p++]; if (!/^-?\d/.test(t)) throw new Error("number expected: " + t); return Number(t); };
      function expr() { let v = conj(); while (peek() === "OR") { p++; v = or3(v, conj()); } return v; }
      function conj() { let v = neg(); while (peek() === "AND") { p++; v = and3(v, neg()); } return v; }
      function neg() { if (peek() === "NOT") { p++; const v = neg(); return v === null ? null : !v; } return pred(); }
      function pred() {
        let v;
        if (toks[p] === "(") { p++; v = expr(); take(")"); }
        else if (/^-?\d/.test(toks[p])) v = num();
        else { const k = toks[p++]; if (!(k in row)) throw new Error("unknown column " + k); v = row[k]; }
        if (peek() === "IS") { p++; let not = false; if (peek() === "NOT") { p++; not = true; } take("NULL"); return not ? v !== null : v === null; }
        if (peek() === "BETWEEN") { p++; const lo = num(); take("AND"); const hi = num(); return v === null ? null : (v >= lo && v <= hi); }
        return v;
      }
      const v = expr(); if (p !== toks.length) throw new Error("left over at " + p + " in " + src); return v;
    };
    const m207 = FILES[M207] || "", m208 = FILES[M208] || "";
    const live = {};   // the rule each name ends with once 207 then 208 have run
    rules(m207).concat(rules(m208)).forEach(([n, src]) => { live[n] = src; });
    const old = {}; rules(m207).forEach(([n, src]) => { old[n] = src; });
    const PAIRS = { geo_cache_point_check: ["lat", "lng"], bf_profiles_place_point_check: ["place_lat", "place_lng"], posts_need_point_check: ["need_lat", "need_lng"], home_prefs_point_check: ["local_lat", "local_lng"] };
    const row = (n, a, b, found) => { const r = {}; r[PAIRS[n][0]] = a; r[PAIRS[n][1]] = b; if (n === "geo_cache_point_check") r.found = found; return r; };
    const cases = n => {
      const g = n === "geo_cache_point_check";
      return [
        ["no point", row(n, null, null, false), true],
        ["a full point", row(n, 32.72, -117.16, true), true],
        ["a latitude with no longitude", row(n, 10, null, true), false],
        ["a longitude with no latitude", row(n, null, 10, true), false],
        ["latitude 95", row(n, 95, 0, true), false],
        ["longitude 181", row(n, 0, 181, true), false],
        ["longitude -181", row(n, 0, -181, true), false]
      ].concat(g ? [["not found, yet a point", row(n, 10, 10, false), false], ["not found, half a point", row(n, 10, null, false), false], ["not found, a longitude only", row(n, null, 10, false), false],["found, no point", row(n, null, null, true), false]] : []);
    };
    const results = {};
    Object.keys(PAIRS).forEach(n => {
      let r;
      try { r = live[n] ? cases(n).map(([label, rw, want]) => [label, evalCheck(live[n], rw), want]) : null; } catch (e) { r = String(e.message); }
      results[n] = r;
    });
    check("K1. 207's four rules, as written, let a half point through (NULL passes a CHECK): the hole 208 closes",
      Object.keys(PAIRS).every(n => !!old[n] && evalCheck(old[n], row(n, 10, null, true)) === null), J(Object.keys(PAIRS).map(n => [n, old[n] ? evalCheck(old[n], row(n, 10, null, true)) : "missing"])));
    Object.keys(PAIRS).forEach((n, i) => {
      const r = results[n];
      check("K" + (i + 2) + ". " + n + " (its 208 rule): no point and a full point pass; half a point and any point off the map are refused (false, never NULL)",
        Array.isArray(r) && r.every(([, got, want]) => got === want), J(r));
    });
    const parts = m208.split(/-- ===== PART /).slice(1);
    check("K6. 208 is paste-safe: no less-or-equal or greater-or-equal, no DO block, no BEGIN or COMMIT; parts 208a to 208d, in order",
      !/<=|>=|\bDO\s|\$\$|\bBEGIN\b|\bCOMMIT\b/i.test(m208.replace(/^--.*$/gm, "")) && J(parts.map(x => x.slice(0, 4))) === J(["208a", "208b", "208c", "208d"]), J(parts.map(x => x.slice(0, 4))));
    check("K7. every 208 rule is dropped IF EXISTS just before it is added (the same name, so 207's is replaced)",
      Object.keys(PAIRS).every(n => new RegExp("DROP CONSTRAINT IF EXISTS " + n + ";\\n[^\\n]*ADD CONSTRAINT " + n + "\\n").test(m208)) && rules(m208).length === 4, J(rules(m208).map(x => x[0])));
  }

  T.finish();
})().catch(e => { console.error(e); process.exit(1); });
