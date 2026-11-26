"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   SEARCH (H1, Nov 25 2026; the owner's board "Search: people, listings, posts,
   Needs"; migration 207's trigram indexes). GET /api/search?q=&scope=&cursor=
   (signed in, free accounts too; rate-limited in server.js). Every rule is here,
   run by scripts/checkHomeTabs.js against a fake database.

   WHAT IS SEARCHED
     people    the handle, the display name, the business name (profiles), the
               city (only of members who show their posts in Local), and the
               category (a category whose name matches: the member's Fingerprint
               categories or an active listing filed under it)
     listings  the title, the description and the category
     posts     the text and the category (Share and Offer posts)
     needs     the text and the category (open Needs)
   The text match is a case-insensitive substring (ILIKE), which the trigram
   indexes (pg_trgm) serve. The query keeps letters, digits, spaces and
   @ ' & . - only, 2 to 80 characters.

   WHAT NEVER SHOWS (every rule, for every group)
     a stranger sees public posts only; a follower also sees that author's
       Followers-only posts (lib/posts.js visiblePosts);
     nothing private, held (pending), removed, or hidden by moderation;
     nobody suspended (banned), deleted or with a hidden profile, nor their
       listings or posts (ownerPublic);
     nobody blocked either way, nor anyone the viewer muted;
     adult content, ever (the content screen's adult category, refused or under
       review; an adult query finds nothing).
   Free accounts are searchable as people. Listings are members' only (only
   members sell).

   THE ANSWER. scope "all": four groups (people 3, listings 3, posts 6, needs
   3), each with more: true when there are more ("See all" opens that scope).
   Any other scope: one list, PAGE (20) at a time, next_cursor "o<offset>".
   ══════════════════════════════════════════════════════════════════════════ */
const P = require("./posts");
const HT = require("./homeTabs");
const CAT = require("./categories");
const G = require("./geo");

const SCOPES = ["all", "people", "listings", "posts", "needs"];
const Q_MIN = 2;
const Q_MAX = 80;
const GROUP = { people: 3, listings: 3, posts: 6, needs: 3 };
const PAGE = 20;
const SCAN = 200;
const MESSAGES = {
  q: "Type at least 2 letters to search, up to 80.",
  scope: "Choose All, People, Listings, Posts or Needs.",
  cursor: "That page marker is not valid. Search again."
};

function fail(status, error, extra) { return { status: status, body: Object.assign({ error: error }, extra || {}) }; }
/* The text matched: letters, digits, spaces and @ ' & . - only; a leading @ is dropped (a handle is matched without it). */
function matchText(raw) {
  if (typeof raw !== "string") return null;
  var t = raw.normalize("NFKC").replace(/[^\p{L}\p{N}\s@'&.\-]/gu, " ").replace(/\s+/g, " ").trim().replace(/^@+/, "").trim();
  var n = Array.from(t).length;
  return n < Q_MIN || n > Q_MAX ? null : t;
}
function like(t) { return '"%' + t.replace(/"/g, "") + '%"'; }
async function categorySlugs(sb, t) {
  var list = await CAT.list(sb).catch(function () { return []; });
  var lower = t.toLowerCase();
  return list.filter(function (c) { return c.name.toLowerCase().indexOf(lower) !== -1 || c.slug.indexOf(lower.replace(/\s+/g, "_")) !== -1; })
    .map(function (c) { return c.slug; }).slice(0, 20);
}
function inList(col, slugs) { return slugs.length ? "," + col + ".in.(" + slugs.join(",") + ")" : ""; }

/* ── people ── */
async function people(deps, ctx, t, slugs) {
  var v = like(t);
  var got = await Promise.all([
    deps.sb.from("bf_profiles").select("user_id, username, display_name, avatar_url, verified_reason, place_city, local_opt_in, updated_at").not("username", "is", null)
      .or("username.ilike." + v + ",display_name.ilike." + v + ",and(place_city.ilike." + v + ",local_opt_in.is.true)").limit(SCAN),
    deps.sb.from("profiles").select("user_id").ilike("business_name", "%" + t + "%").limit(SCAN),
    slugs.length ? deps.sb.from("lead_fingerprints").select("user_id").overlaps("categories", slugs).limit(SCAN) : Promise.resolve({ data: [] }),
    slugs.length ? deps.sb.from("marketplace_listings").select("seller_id").in("category_slug", slugs).eq("status", "active").limit(SCAN) : Promise.resolve({ data: [] })
  ]);
  got.forEach(function (g) { if (g.error) throw g.error; });
  var rows = got[0].data || [];
  var have = new Set(rows.map(function (p) { return p.user_id; }));
  var extra = [...new Set([].concat((got[1].data || []).map(function (x) { return x.user_id; }), (got[2].data || []).map(function (x) { return x.user_id; }),
    (got[3].data || []).map(function (x) { return x.seller_id; })))].filter(function (id) { return id && !have.has(id); }).slice(0, SCAN);
  if (extra.length) {
    var more = await deps.sb.from("bf_profiles").select("user_id, username, display_name, avatar_url, verified_reason, place_city, local_opt_in, updated_at")
      .in("user_id", extra).not("username", "is", null);
    if (more.error) throw more.error;
    rows = rows.concat(more.data || []);
  }
  var ok = await HT.standingOf(deps, ctx, rows.map(function (p) { return p.user_id; }));
  rows = rows.filter(function (p) { return ok.has(p.user_id) && !HT.adultText([p.display_name, p.username]); });
  var lower = t.toLowerCase(), verified = require("./verified");
  var rank = function (p) {
    if (String(p.username || "").toLowerCase() === lower) return 0;
    if (String(p.display_name || "").toLowerCase().indexOf(lower) === 0) return 1;
    return 2;
  };
  rows = rows.map(function (p, i) { return { p: p, i: i }; })
    .sort(function (a, b) { return rank(a.p) - rank(b.p) || (verified.reasonOf(b.p) ? 1 : 0) - (verified.reasonOf(a.p) ? 1 : 0) || a.i - b.i; })
    .map(function (x) { return x.p; });
  return rows;
}
async function peopleItems(deps, ctx, rows) {
  if (!rows.length) return [];
  var ids = rows.map(function (p) { return p.user_id; });
  var places = await HT.placesOf(deps.sb, ids);
  var cats = await HT.categoriesOf(deps, ids);
  var catList = await CAT.list(deps.sb).catch(function () { return []; });
  var verified = require("./verified");
  return rows.map(function (p) {
    var first = [...(cats[p.user_id] || [])][0] || null;
    return { user_id: p.user_id, username: p.username, name: p.display_name || "@" + p.username, avatar_url: p.avatar_url || null, link: "/@" + p.username,
      verified: verified.reasonOf(p), following: ctx.following.has(p.user_id), mine: p.user_id === ctx.viewer,
      category: first ? CAT.nameOf(catList, first) || first : null,
      area: places[p.user_id] ? places[p.user_id].label : (cats.__online.has(p.user_id) ? "Online" : null) };
  });
}

/* ── listings ── */
async function listings(deps, ctx, t, slugs) {
  var v = like(t);
  var r = await deps.sb.from("marketplace_listings").select("id, slug, seller_id, title, description, price_bfc, category_slug, listing_kind, media, created_at, status")
    .eq("status", "active").or("title.ilike." + v + ",description.ilike." + v + inList("category_slug", slugs))
    .order("created_at", { ascending: false }).limit(SCAN);
  if (r.error) throw r.error;
  return HT.shownListings(deps, ctx, r.data || []);
}
async function listingItems(deps, ctx, rows) {
  var places = await HT.placesOf(deps.sb, rows.map(function (l) { return l.seller_id; }));
  var extra = {};
  rows.forEach(function (l) { var pl = places[l.seller_id]; extra[l.id] = { area: pl ? pl.label : null, distance_label: null }; });
  return HT.listingCards(deps, ctx, rows, extra);
}

/* ── posts and Needs ── */
async function postsOf(deps, ctx, t, slugs, needs) {
  var v = like(t);
  var q = deps.sb.from("posts").select(P.POST_COLUMNS).eq("status", "published");
  q = needs ? q.eq("intent", "need").is("need_found_at", null) : q.in("intent", ["share", "offer"]);
  var r = await q.or("body.ilike." + v + inList("category", slugs)).order("published_at", { ascending: false }).order("id", { ascending: false }).limit(SCAN);
  if (r.error) throw r.error;
  var shown = await P.visiblePosts(deps, ctx, r.data || [], { feed: true, publishedOnly: true });
  return shown.filter(function (p) { return !HT.adultText([p.body]); });
}
async function postItems(deps, ctx, rows) { return P.decorate(deps, ctx, rows); }

const RUN = {
  people: { find: people, items: peopleItems },
  listings: { find: listings, items: listingItems },
  posts: { find: function (deps, ctx, t, s) { return postsOf(deps, ctx, t, s, false); }, items: postItems },
  needs: { find: function (deps, ctx, t, s) { return postsOf(deps, ctx, t, s, true); }, items: postItems }
};

async function search(deps, viewerId, query) {
  query = query || {};
  var scope = query.scope === undefined || query.scope === "" ? "all" : query.scope;
  if (SCOPES.indexOf(scope) === -1) return fail(400, MESSAGES.scope, { field: "scope" });
  var t = matchText(query.q);
  if (!t) return fail(400, MESSAGES.q, { field: "q" });
  var offset = 0;
  if (query.cursor !== undefined && query.cursor !== null && query.cursor !== "") {
    if (scope === "all" || !/^o\d{1,4}$/.test(String(query.cursor))) return fail(400, MESSAGES.cursor, { field: "cursor" });
    offset = Number(String(query.cursor).slice(1));
  }
  var adult = HT.adultText([t]);
  var ctx = await P.viewerContext(deps, viewerId);
  var slugs = adult ? [] : await categorySlugs(deps.sb, t);
  var kinds = scope === "all" ? ["people", "listings", "posts", "needs"] : [scope];
  var found = {};
  for (var i = 0; i < kinds.length; i++) found[kinds[i]] = adult ? [] : await RUN[kinds[i]].find(deps, ctx, t, slugs);
  if (scope === "all") {
    var groups = {};
    for (var k = 0; k < kinds.length; k++) {
      var key = kinds[k], n = GROUP[key];
      groups[key] = { items: await RUN[key].items(deps, ctx, found[key].slice(0, n)), more: found[key].length > n };
    }
    return { status: 200, body: { q: t, scope: "all", groups: groups } };
  }
  var all = found[scope];
  var page = all.slice(offset, offset + PAGE);
  return { status: 200, body: { q: t, scope: scope, items: await RUN[scope].items(deps, ctx, page), next_cursor: offset + PAGE < all.length ? "o" + (offset + PAGE) : null } };
}

module.exports = { SCOPES, Q_MIN, Q_MAX, GROUP, PAGE, SCAN, MESSAGES, matchText, like, categorySlugs, people, listings, postsOf, search, ATTRIBUTION: G.ATTRIBUTION };
