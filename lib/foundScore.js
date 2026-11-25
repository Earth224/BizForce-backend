"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   THE FOUND SCORE (LR-4, Nov 25 2026): "How easy you are to find on Google and
   the apps people search." Lead Radar's Get found tab (the owner's canvas row 6,
   LeadsFound). No model is called: every item is a plain read of what BizForce
   already holds, and the score is the sum of the done items' weights (0 to 100).

     weight  item                         done when
     15      Add your city and a short bio  bf_profiles place_city and bio are filled
     20      Your profile page on Google    the profile is indexable (lib/publicPages.js robotsFor)
     20      Your listings on Google        an active, indexable listing has a photo, a category
                                            and a USD price or a description
     15      Posts shown in Google          every public published post has Show in Google on
                                            (N of M; with no public post it is to do)
     15      Connected accounts             Bluesky or Threads is connected
     15      Fingerprint complete           categories, a place or "Online, anywhere", 5+ words

   Each item is "todo" (a gold "!" and an action), "done" (a green tick) or
   "waiting" (a grey "..."): YouTube, TikTok, Instagram and Facebook, when
   connected, show as one waiting row, "Connected, waiting for each platform's
   approval", which carries no weight. The list shows the to-do items first, then
   the done ones, then the waiting row; within each, the table's order.

   ACTIONS go to the existing screens: Edit profile (profile.html#edit-bio) or
   Settings, Local (settings.html#local); Settings, Privacy (settings.html#privacy);
   Add a listing (marketplace.html?create=product) or Fix (marketplace.html?edit=<id>);
   Fix for posts (Edit post's Show in Google, PATCH /api/posts/:id with
   search_visible true, after a confirm, on the page); Connect (agents/social.html);
   Open Fingerprint (the Fingerprint tab).
   ══════════════════════════════════════════════════════════════════════════ */

var PP = require("./publicPages");
var FP = require("./leadFingerprint");

var WEIGHTS = { basics: 15, profile: 20, listings: 20, posts: 15, connected: 15, fingerprint: 15 };
var ORDER = ["basics", "profile", "listings", "posts", "connected", "fingerprint"];
var MIN_WORDS = 5;
var POSTS_SCAN = 500;
var LISTINGS_SCAN = 200;
var WAITING_PLATFORMS = [["youtube", "YouTube"], ["tiktok", "TikTok"], ["instagram", "Instagram"], ["facebook", "Facebook"]];
var HREF = {
  bio: "/profile.html#edit-bio", local: "/settings.html#local", privacy: "/settings.html#privacy", handle: "/profile.html#edit-bio",
  addListing: "/marketplace.html?create=product", fixListing: "/marketplace.html?edit=", connect: "/agents/social.html", compose: "/compose.html"
};

function filled(v) { return PP.clean(v).length > 0; }
function plural(n, one, many) { return n + " " + (n === 1 ? one : many); }
function listParts(parts) { return parts.length < 2 ? parts.join("") : parts.slice(0, -1).join(", ") + " and " + parts[parts.length - 1]; }

/* What a listing still needs before it is complete for Google: a photo, a category, a USD price or a description. */
function listingMissing(l) {
  var miss = [];
  if (!PP.firstPhoto(l.media)) miss.push("a photo");
  if (!filled(l.category_slug) && !filled(l.category)) miss.push("a category");
  if (PP.usdPrice(l) === null && !filled(l.description)) miss.push("a description");
  return miss;
}

/* facts: { profile, profileIndexable, profileWhy, listings: [{..., indexable}], posts: [{id, body, search_visible}],
   connections: { bluesky, threads, youtube, tiktok, instagram, facebook } (true when connected), fingerprint (shape or null) } */
function compute(facts) {
  var f = facts || {}, p = f.profile || {}, items = {};
  var handle = p.username && PP.HANDLE_RE.test(p.username) ? p.username : null;

  // 15: city and bio
  var hasCity = filled(p.place_city), hasBio = filled(p.bio);
  items.basics = hasCity && hasBio
    ? { status: "done", title: "Add your city and a short bio", detail: "Your city and bio are on your profile" }
    : { status: "todo", title: "Add your city and a short bio", detail: "Google and Need alerts use them to match you",
        action: { label: "Add", href: hasBio ? HREF.local : HREF.bio } };

  // 20: the profile page on Google
  if (f.profileIndexable === true && handle) {
    items.profile = { status: "done", title: "Your profile page on Google", detail: "bizforceai.net/@" + handle + " with your name, city and work", url: "/@" + handle };
  } else if (!handle) {
    items.profile = { status: "todo", title: "Your profile page on Google", detail: "Choose a handle so your page has an address", action: { label: "Add", href: HREF.handle } };
  } else if (f.profileWhy === "switch_off") {
    items.profile = { status: "todo", title: "Your profile page on Google", detail: "Show my profile and listings in Google is off", action: { label: "Turn on", href: HREF.privacy } };
  } else {
    items.profile = { status: "todo", title: "Your profile page on Google", detail: "Your profile is not public just now, so Google is not shown it" };
  }

  // 20: listings on Google
  var listings = Array.isArray(f.listings) ? f.listings : [];
  var complete = listings.filter(function (l) { return l.indexable === true && !listingMissing(l).length; });
  if (complete.length) {
    items.listings = { status: "done", title: "Your listings on Google", detail: plural(complete.length, "listing", "listings") + " with photos and details" };
  } else if (!listings.length) {
    items.listings = { status: "todo", title: "Your listings on Google", detail: "Add a listing people can find", action: { label: "Add a listing", href: HREF.addListing } };
  } else if (f.profileWhy === "switch_off") {
    items.listings = { status: "todo", title: "Your listings on Google", detail: "Show my profile and listings in Google is off", action: { label: "Turn on", href: HREF.privacy } };
  } else {
    var first = listings.find(function (l) { return listingMissing(l).length; }) || listings[0];
    var miss = listingMissing(first);
    items.listings = miss.length
      ? { status: "todo", title: "Your listings on Google", detail: "“" + PP.cut(first.title || "Your listing", 40) + "” needs " + listParts(miss), action: { label: "Fix", href: HREF.fixListing + encodeURIComponent(first.id) } }
      : { status: "todo", title: "Your listings on Google", detail: "Your listings are not shown in Google just now" };
  }

  // 15: posts shown in Google
  var posts = Array.isArray(f.posts) ? f.posts : [];
  var on = posts.filter(function (x) { return x.search_visible === true; }), off = posts.filter(function (x) { return x.search_visible !== true; });
  if (!posts.length) {
    items.posts = { status: "todo", title: "Posts shown in Google", detail: "No public posts yet. Post what you offer", action: { label: "Post", href: HREF.compose } };
  } else if (!off.length) {
    items.posts = { status: "done", title: "Posts shown in Google", detail: on.length + " of " + posts.length + " public posts" };
  } else {
    items.posts = { status: "todo", title: "Posts shown in Google",
      detail: on.length + " of " + posts.length + " public posts. Turn on Show in Google for " + (off.length === 1 ? (posts.length === 1 ? "it" : "the last one") : "the other " + off.length),
      action: { label: "Fix", act: "posts" } };
  }

  // 15: connected accounts
  var c = f.connections || {};
  var named = [c.bluesky ? "Bluesky" : null, c.threads ? "Threads" : null].filter(Boolean);
  items.connected = named.length
    ? { status: "done", title: listParts(named) + " connected", detail: "Your posts and approved replies go out from your account" }
    : { status: "todo", title: "Connect Bluesky or Threads", detail: "Your posts and approved replies go out from your own account", action: { label: "Connect", href: HREF.connect } };

  // 15: the Fingerprint
  var fp = f.fingerprint || null;
  var fpMiss = [];
  if (!fp || !(fp.categories || []).length) fpMiss.push("what you do");
  if (!fp || !(filled(fp.place_city) || fp.reach === "online")) fpMiss.push("where");
  if (!fp || (fp.keywords || []).length < MIN_WORDS) fpMiss.push("at least " + MIN_WORDS + " words");
  items.fingerprint = !fpMiss.length
    ? { status: "done", title: "Fingerprint complete", detail: "Lead Radar knows what you do and where" }
    : { status: "todo", title: "Fingerprint complete", detail: "Add " + listParts(fpMiss), action: { label: "Open Fingerprint", act: "fingerprint" } };

  var list = ORDER.map(function (k) { return Object.assign({ key: k, weight: WEIGHTS[k] }, items[k]); });
  var waiting = WAITING_PLATFORMS.filter(function (w) { return c[w[0]] === true; }).map(function (w) { return w[1]; });
  if (waiting.length) list.push({ key: "waiting", weight: 0, status: "waiting", title: waiting.join(", "), detail: "Connected, waiting for each platform's approval" });
  var rank = { todo: 0, done: 1, waiting: 2 };
  var ordered = list.map(function (x, i) { return [x, i]; }).sort(function (a, b) { return (rank[a[0].status] - rank[b[0].status]) || (a[1] - b[1]); }).map(function (x) { return x[0]; });
  var score = list.reduce(function (s, x) { return s + (x.status === "done" ? x.weight : 0); }, 0);
  return { score: score, items: ordered, fix_posts: off.map(function (x) { return { id: x.id, body: typeof x.body === "string" ? x.body : "" }; }) };
}

/* ── reading the facts ─────────────────────────────────────────────────── */

/* deps: { sb, indexability(userId) -> { indexable, why, member, switchOn }, hiddenAmong(sb, kind, ids), connections(userId) } */
async function gather(deps, userId) {
  var sb = deps.sb;
  var r = await Promise.all([
    sb.from("bf_profiles").select("username, display_name, bio, place_city, place_region").eq("user_id", userId).maybeSingle(),
    sb.from("marketplace_listings").select("id, slug, title, description, category, category_slug, price_usd, media, status").eq("seller_id", userId).eq("status", "active").limit(LISTINGS_SCAN),
    sb.from("posts").select("id, body, search_visible").eq("author_id", userId).eq("status", "published").eq("audience", "public").order("published_at", { ascending: false }).limit(POSTS_SCAN)
  ]);
  for (var i = 0; i < r.length; i++) if (r[i].error) throw r[i].error;
  var idx = await deps.indexability(userId);
  var listings = r[1].data || [];
  var hidden = listings.length ? await deps.hiddenAmong(sb, "listing", listings.map(function (l) { return l.id; })) : new Set();
  listings = listings.filter(function (l) { return !hidden.has(l.id); }).map(function (l) { return Object.assign({}, l, { indexable: idx.indexable === true }); });
  var fpRow = await FP.readRow(sb, userId);
  return {
    profile: r[0].data || {}, profileIndexable: idx.indexable === true, profileWhy: idx.why || null,
    listings: listings, posts: r[2].data || [], connections: await deps.connections(userId), fingerprint: fpRow ? FP.shape(fpRow) : null
  };
}

module.exports = { WEIGHTS, ORDER, MIN_WORDS, WAITING_PLATFORMS, HREF, listingMissing, compute, gather };
