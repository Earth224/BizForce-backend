"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   checkPostIntent.js — P3-3 (Nov 23 2026): Share, Offer or Need on every post,
   ONE category list, Need alerts, Found, and the Market's category.

   Runs lib/posts.js, lib/needAlerts.js, lib/categories.js and lib/postPage.js
   over the P2-3 in-memory database (scripts/_p23Db.js), its categories seeded
   from migration 200 (scripts/_categories.js). Never the real database, never
   the network.

     A. a new post's intent, category and a Need's Where and When (validateNew)
     B. who may post what (createPost): the category on the list, an Offer
        members only with an owned active listing, a free Need in text, the
        content screen on every intent, a confirmed email for public posts
     C. Need alerts (alertNeed, started by createPost): members who offer in
        the category; the city preferred; never the poster, a blocked member,
        a free account or one who switched them off; at most 10 per Need and
        20 per member per day; none for a Found, followers or pending Need;
        in-app only (no push); the post never waits for or fails with them
     D. the feed's parts (can_help, intent, category, need), Found and the
        composer's info
     E. the one list (lib/categories.js) and the server's routes
     F. the /p/ page: the intent line and the JSON-LD
     G. the frontend: the composer sends the intent; I can help through the
        messages route; the settings switch; the Market's filter and form
     J. (NAMED (Nov 23 2026, P3-3B)) a Need sends its alerts when it becomes published and public,
        whichever way: approved from moderation (lib/moderation.js decide hands
        the server's postDeps to applyDecision) or edited from Followers to
        Public; once only (the need_alert rows already naming the post); a
        Found Need approved later sends nothing; Public by edit needs a
        confirmed email

   MUTATE=<name> applies one mutation in memory; MUTATE=all runs each.
   ═══════════════════════════════════════════════════════════════════════════ */
const H = require("./_p21Harness");
const { memDb } = require("./_p23Db");
const CATEGORY_ROWS = require("./_categories").rows();

const MOD = "@lib/moderation.js";   // NAMED (Nov 23 2026, P3-3B)
const SERVER = "@server.js", POSTS = "@lib/posts.js", NA = "@lib/needAlerts.js", CATS = "@lib/categories.js", PAGE = "@lib/postPage.js", ACCESS = "@lib/routeAccess.js";
const COMP = "scripts/bf-composer.js", FEED = "scripts/bf-feed.js", SETTINGS = "settings.html", MARKET = "marketplace.html";
const MUTATIONS = {
  // A
  "intent-optional": [[POSTS, "  if (INTENTS.indexOf(intent) === -1) return { status: 400, error: MESSAGES.intent, field: \"intent\" };", "  if (intent === undefined) intent = \"share\";\n  if (INTENTS.indexOf(intent) === -1) return { status: 400, error: MESSAGES.intent, field: \"intent\" };"]],
  "category-optional": [[POSTS, "  if (category === null) return { status: 400, error: MESSAGES.category, field: \"category\" };\n", ""]],
  "need-links-listing": [[POSTS, "  if (intent === \"need\" && listingId !== null) return", "  if (false) return"]],
  "place-anywhere": [[POSTS, "    if (hasPlace || hasWhen) return { status: 400, error: MESSAGES.needOnly,", "    if (false) return { status: 400, error: MESSAGES.needOnly,"]],
  "place-long": [[POSTS, "    if (chars(place) > NEED_PLACE_MAX) return", "    if (chars(place) > 200) return"]],
  "when-any-word": [[POSTS, "  if (NEED_WHENS.indexOf(when) === -1) return { status: 400, error: MESSAGES.needWhen, field: \"need_when\" };\n", ""]],
  // B
  "category-off-list": [[POSTS, "  if (!(await CAT.find(deps.sb, v.category))) return fail(400, MESSAGES.categoryBad, { field: \"category\" });\n", ""]],
  "free-offers": [[POSTS, "    if (v.intent === \"offer\") return membersOnly(deps, MESSAGES.offerMembers, \"members_only\");\n", ""]],
  "offer-without-listing": [[POSTS, "  if (v.intent === \"offer\" && !v.listing_id) return fail(400, MESSAGES.offerListing, { field: \"listing_id\" });\n", ""]],
  "offer-anyones-listing": [[POSTS, "    if (!ls.data || ls.data.seller_id !== userId || ls.data.status !== \"active\") return", "    if (!ls.data || ls.data.status !== \"active\") return"]],
  "free-need-needs-photo": [[POSTS, "    if (v.intent === \"share\" && v.kind !== \"photo\") return", "    if (v.intent !== \"offer\" && v.kind !== \"photo\") return"]],
  "need-unscreened": [[POSTS, "  var screened = screenText(deps, { body: v.body });\n  if (!screened.ok) return { status: 400, body: CP.refusalBody(screened) };\n  if (v.audience", "  var screened = v.intent === \"need\" ? { ok: true } : screenText(deps, { body: v.body });\n  if (!screened.ok) return { status: 400, body: CP.refusalBody(screened) };\n  if (v.audience"]],
  "intent-not-saved": [[POSTS, "  row.intent = v.intent;", "  row.intent = \"share\";"]],
  // C
  "alerts-awaited": [[POSTS, "  startNeedAlerts(deps, post);   // NAMED (Nov 23 2026, P3-3): after the save, never awaited", "  await require(\"./needAlerts\").alertNeed({ sb: deps.sb, now: function () { return now(deps); }, tierOf: deps.tierOf }, post);"]],
  "alerts-for-followers": [[POSTS, "  if (!post || post.intent !== \"need\" || post.status !== \"published\" || post.audience !== \"public\") return null;", "  if (!post || post.intent !== \"need\" || post.status !== \"published\") return null;"],
    [NA, "  if (post.audience !== \"public\") return { sent: 0, to: [], reason: \"not_public\" };\n", ""]],
  "alerts-when-found": [[NA, "  if (post.need_found_at) return { sent: 0, to: [], reason: \"found\" };\n", ""]],
  "alerts-to-poster": [[NA, "return id !== poster && !blocked.has(id); });", "return !blocked.has(id); });"]],
  "alerts-to-blocked": [[NA, "return id !== poster && !blocked.has(id); });", "return id !== poster; });"]],
  "blocks-fail-open": [[NA, "  if (r.error) throw r.error;\n  const out = new Set();\n  (r.data || []).forEach(function (row) {", "  const out = new Set();\n  (r.data || []).forEach(function (row) {"]],
  "alerts-to-free": [[NA, "      if (tier !== \"member\") continue;\n", ""]],
  "alerts-ignore-switch": [[NA, "  ids = ids.filter(function (id) { return !off.has(id); });\n", ""]],
  "switch-null-off": [[NA, "if (p && p.need_alerts === false) out.add(p.user_id);", "if (p && p.need_alerts !== true) out.add(p.user_id);"]],
  "no-place-preference": [[NA, "  let to = await qualified(near);\n  if (!to.length) to = await qualified(rest);", "  let to = await qualified(near.concat(rest));"]],
  "per-need-cap": [[NA, "const PER_NEED = 10;", "const PER_NEED = 11;"]],
  "per-day-cap": [[NA, "      if (n === null || n >= PER_MEMBER_DAY) continue;", "      if (n === null || n > PER_MEMBER_DAY) continue;"]],
  "offer-window": [[NA, "const OFFER_DAYS = 90;", "const OFFER_DAYS = 3650;"]],
  "listings-any-status": [[NA, "select(\"seller_id, updated_at, created_at\").eq(\"category_slug\", slug).eq(\"status\", \"active\")", "select(\"seller_id, updated_at, created_at\").eq(\"category_slug\", slug)"]],
  "message-words": [[NA, "message: who + \" needs help in \" + cat + \": \" + preview(post.body)", "message: who + \" needs \" + cat + \": \" + preview(post.body)"]],
  "preview-long": [[NA, "const PREVIEW_CHARS = 80;", "const PREVIEW_CHARS = 120;"]],
  "alerts-push": [[POSTS, "  startNeedAlerts(deps, post);   // NAMED (Nov 23 2026, P3-3): after the save, never awaited", "  startNeedAlerts(deps, post); if (post.intent === \"need\" && deps.push) deps.push(userId, { title: \"Need\" });"]],
  "alert-failure-fails-post": [[POSTS, "  }).catch(function (e) {\n    console.warn(\"[need-alerts]", "  }).then(function (x) { return x; }, function (e) { throw e; }).catch(function (e) {\n    throw e;\n    console.warn(\"[need-alerts]"]],
  // D
  // the two guards (the members' offers read only for others' open Needs, and can_help itself) each removed with the other
  "help-for-poster": [[POSTS, "    var canHelp = !!need && !need.found && !mine && !!p.category && offers.has(p.category);", "    var canHelp = !!need && !need.found && !!p.category && offers.has(p.category);"],
    [POSTS, "var open = list.filter(function (p) { return p.intent === \"need\" && !p.need_found_at && p.category && ctx.viewer && p.author_id !== ctx.viewer; });", "var open = list.filter(function (p) { return p.intent === \"need\" && !p.need_found_at && p.category && ctx.viewer; });"]],
  "help-when-found": [[POSTS, "    var canHelp = !!need && !need.found && !mine && !!p.category && offers.has(p.category);", "    var canHelp = !!need && !mine && !!p.category && offers.has(p.category);"],
    [POSTS, "var open = list.filter(function (p) { return p.intent === \"need\" && !p.need_found_at && p.category && ctx.viewer && p.author_id !== ctx.viewer; });", "var open = list.filter(function (p) { return p.intent === \"need\" && p.category && ctx.viewer && p.author_id !== ctx.viewer; });"]],
  "help-any-category": [[POSTS, "    var canHelp = !!need && !need.found && !mine && !!p.category && offers.has(p.category);", "    var canHelp = !!need && !need.found && !mine && !!p.category && offers.size > 0;"]],
  "help-for-free": [[POSTS, "  if (open.length && (await tierOf(deps, ctx.viewer)) === \"member\") offers =", "  if (open.length) offers ="]],
  "found-by-anyone": [[POSTS, "  if (!post || post.author_id !== userId || post.status === \"removed\") return notAvailable();\n  if (post.intent !== \"need\")", "  if (!post || post.status === \"removed\") return notAvailable();\n  if (post.intent !== \"need\")"]],
  "found-on-share": [[POSTS, "  if (post.intent !== \"need\") return fail(400, MESSAGES.foundNeed, { field: \"intent\" });\n", ""]],
  "reopen-keeps-found": [[POSTS, "update({ need_found_at: on ? now(deps) : null })", "update({ need_found_at: now(deps) })"]],
  "composer-others-listings": [[POSTS, "select(\"id, title, listing_kind, category_slug, price_bfc, created_at\").eq(\"seller_id\", userId).eq(\"status\", \"active\")", "select(\"id, title, listing_kind, category_slug, price_bfc, created_at\").eq(\"status\", \"active\")"]],
  // E
  "list-inactive": [[CATS, ".from(\"categories\").select(\"slug, name, parent_group, sort_order\").eq(\"active\", true)", ".from(\"categories\").select(\"slug, name, parent_group, sort_order\")"]],
  "list-unsorted": [[CATS, ".order(\"sort_order\", { ascending: true })", ".order(\"slug\", { ascending: true })"]],
  "categories-private": [[ACCESS, "\"get /api/categories\"", "\"get /api/categories-x\""]],
  "listing-category-optional": [[SERVER, "    if (!category) return res.status(400).json({ error: LISTING_CATEGORY_MESSAGE, field: \"category\" });\n", ""]],
  "listing-slug-not-stored": [[SERVER, "      price_bfc: priceBfc, price_usd: null, category, category_slug: category, tags, media: sanitizeMedia(req.body.media, req.user.id), status: \"active\",", "      price_bfc: priceBfc, price_usd: null, category, tags, media: sanitizeMedia(req.body.media, req.user.id), status: \"active\","]],
  "filter-free-text": [[SERVER, "    if (category && category !== \"all\") query = query.eq(\"category_slug\", category);", "    if (category && category !== \"all\") query = query.eq(\"category\", category);"]],
  "prefs-default-off": [[SERVER, "      need_alerts: row.need_alerts !== false,", "      need_alerts: row.need_alerts === true,"]],
  // F
  "page-no-intent": [[PAGE, "  if (cat) data.articleSection = cat;\n", ""]],
  "page-found-as-need": [[PAGE, "  var parts = [post.need && post.need.found ? \"Found\" : (INTENT_WORDS[post.intent] || INTENT_WORDS.share)];", "  var parts = [INTENT_WORDS[post.intent] || INTENT_WORDS.share];"]],
  // G
  "composer-no-intent": [[COMP, "      var extra = { intent: it, category: category() };", "      var extra = { category: category() };"]],
  "composer-no-category-stop": [[COMP, "      if (!category()) { stop(MSG.category, cats.querySelector(\"input\")); return; }\n", ""]],
  "help-public-reply": [[FEED, "      call(\"POST\", \"/api/messages\", { receiver_id: a.id, content: text })", "      call(\"POST\", \"/api/posts/\" + encodeURIComponent(p.id) + \"/comments\", { body: text })"]],
  "help-unlinked": [[FEED, "      if (text.indexOf(link) === -1) text = (text ? text + \"\\n\\n\" : \"\") + link;   // the post stays linked\n", ""]],
  "settings-switch-unsaved": [[SETTINGS, "        putPreferences({ need_alerts: needAlertsToggle.checked }, needAlertsSaved);", "        needAlertsSaved.textContent = \"\";"]],
  "settings-switch-for-free": [[SETTINGS, "needAlertsRow.hidden = !(d && d.access && d.access.tier === \"member\");", "needAlertsRow.hidden = false;"]],
  "market-filter-free-text": [[MARKET, "    items = items.filter(function(l) { return l.category_slug === activeCat; });", "    items = items.filter(function(l) { return l.category === activeCat; });"]],
  "market-save-without-category": [[MARKET, "  if (!category) {\n    var cn = document.getElementById(\"fCategoryNote\");", "  if (false) {\n    var cn = document.getElementById(\"fCategoryNote\");"]],
  // J (NAMED (Nov 23 2026, P3-3B))
  "approval-sends-nothing": [[POSTS, "    if (state === \"kept\" && p.status !== \"published\") startNeedAlerts(", "    if (false) startNeedAlerts("]],
  "approval-drops-deps": [[MOD, "applyDecision(sb, row, state, nowIso, opts.postDeps || null);", "applyDecision(sb, row, state, nowIso, null);"]],
  "approval-ignores-found": [[POSTS, "Object.assign({}, p, patch));\n    return { changed: true,", "Object.assign({}, p, patch, { need_found_at: null }));\n    return { changed: true,"],
    [NA, "  if (post.need_found_at) return { sent: 0, to: [], reason: \"found\" };\n", ""]],
  "sent-twice": [[NA, "  if (await alreadySent(deps.sb, post.id)) return { sent: 0, to: [], reason: \"already_sent\" };", "  if (false) return { sent: 0, to: [], reason: \"already_sent\" };"]],
  "guard-other-type": [[NA, ".eq(\"type\", TYPE).eq(\"object_type\", \"post\").eq(\"object_id\", postId);", ".eq(\"type\", \"need_alerts\").eq(\"object_type\", \"post\").eq(\"object_id\", postId);"]],
  "guard-fails-open": [[NA, "  if (r.error) throw r.error;\n  if (typeof r.count !== \"number\") throw new Error(\"need_alert count unreadable\");", "  if (r.error) return false;\n  if (typeof r.count !== \"number\") return false;"]],
  "edit-sends-nothing": [[POSTS, "  if (!(post.status === \"published\" && post.audience === \"public\")) startNeedAlerts(deps, u.data);\n", ""]],
  "edit-audience-ignored": [[POSTS, "  if (audience !== post.audience) patch.audience = audience;", "  if (false) patch.audience = audience;"]],
  "edit-audience-any-word": [[POSTS, "  if (AUDIENCES.indexOf(audience) === -1) return fail(400, MESSAGES.audience, { field: \"audience\" });\n  if (audience === \"public\" && post.audience", "  if (audience === \"public\" && post.audience"]],
  "edit-public-unverified": [[POSTS, "  if (audience === \"public\" && post.audience !== \"public\" && !(await authorVerified(deps, userId))) return", "  if (false) return"]],
  "route-drops-deps": [[SERVER, "nowIso: nowIso(), postDeps: postDeps() });", "nowIso: nowIso() });"]]
};
const T = H.setup(__filename, MUTATIONS, [SERVER, POSTS, NA, CATS, PAGE, ACCESS, "@lib/postMedia.js", COMP, FEED, SETTINGS, MARKET, MOD]);
const { FILES, check, J, has } = T;
const P = T.libRequire("./lib/posts");
const NAL = T.libRequire("./lib/needAlerts");
const CAT = T.libRequire("./lib/categories");
const PP = T.libRequire("./lib/postPage");
const MODL = T.libRequire("./lib/moderation");   // NAMED (Nov 23 2026, P3-3B)

const u = n => "bbbbbbbb-0000-4000-8000-" + String(n).padStart(12, "0");
const POSTER = u(1), FREE = u(2), NEAR1 = u(3), FAR1 = u(4), OFFQ = u(5), BLK = u(6), FREEOFF = u(7), FULL = u(8), UNVER = u(9), OLDOFF = u(10), NULLPREF = u(11);
const ARTIST = u(12);
const MANY = Array.from({ length: 14 }, (_, i) => u(100 + i));
const NOW = "2026-11-23T12:00:00.000Z", OLD = "2026-01-01T00:00:00.000Z";
const lid = n => "cccccccc-0000-4000-8000-" + String(n).padStart(12, "0");
const quiet = async fn => { const w = console.warn; const said = []; console.warn = m => said.push(String(m)); try { return { v: await fn(), said }; } finally { console.warn = w; } };

function world(o) {
  o = o || {};
  const everyone = [POSTER, FREE, NEAR1, FAR1, OFFQ, BLK, FREEOFF, FULL, UNVER, OLDOFF, NULLPREF, ARTIST].concat(MANY);
  const city = { [POSTER]: "San Diego", [NEAR1]: "San Diego", [FAR1]: "Austin", [OFFQ]: "San Diego", [BLK]: "San Diego", [FREEOFF]: "San Diego", [FULL]: "San Diego", [NULLPREF]: "Austin" };
  const listings = [];
  const sell = (seller, slug, n, extra) => listings.push(Object.assign({ id: lid(n), seller_id: seller, title: "Item " + n, listing_kind: n % 2 ? "service" : "product", category_slug: slug, category: slug,
    status: "active", price_bfc: 10 + n, created_at: "2026-11-0" + (1 + (n % 9)) + "T00:00:00.000Z", updated_at: "2026-11-1" + (n % 9) + "T00:00:00.000Z" }, extra || {}));
  sell(NEAR1, "tattoo_body_art", 1); sell(FAR1, "tattoo_body_art", 2); sell(OFFQ, "tattoo_body_art", 3); sell(BLK, "tattoo_body_art", 4);
  sell(FREEOFF, "tattoo_body_art", 5); sell(FULL, "tattoo_body_art", 6); sell(NULLPREF, "tattoo_body_art", 7);
  sell(OLDOFF, "tattoo_body_art", 8, { status: "paused" });
  sell(ARTIST, "art", 12);
  sell(POSTER, "tattoo_body_art", 9); sell(POSTER, "art", 10); sell(POSTER, "art", 11, { status: "sold" });
  if (o.many) MANY.forEach((m, i) => { sell(m, "photography", 50 + i); city[m] = "Leeds"; });
  const offerPosts = [
    { id: "dddddddd-0000-4000-8000-000000000001", author_id: OLDOFF, intent: "offer", category: "tattoo_body_art", status: "published", audience: "public", kind: "text", body: "old offer", published_at: "2026-07-01T00:00:00.000Z", created_at: "2026-07-01T00:00:00.000Z" }
  ];
  const notes = [];
  for (let i = 0; i < 20; i++) notes.push({ id: "eeeeeeee-0000-4000-8000-" + String(i).padStart(12, "0"), user_id: FULL, type: "need_alert", read: false, created_at: "2026-11-23T0" + (i % 9) + ":00:00.000Z" });
  if (o.nineteen) notes.splice(19, 1);
  const db = memDb({
    categories: CATEGORY_ROWS.concat([{ slug: "retired_cat", name: "Retired", parent_group: null, sort_order: 999, active: false }]),
    users: everyone.map(id => ({ id, created_at: OLD, email_verified_at: id === UNVER ? null : OLD })),
    bf_profiles: everyone.map(id => ({ user_id: id, username: "u" + id.slice(-3), display_name: id === POSTER ? "Rosa Diaz" : "N" + id.slice(-3), avatar_url: null, place_city: city[id] || null, place_region: city[id] === "San Diego" ? "CA" : null, place_country: "US", local_opt_in: false })),
    marketplace_listings: listings, posts: offerPosts, post_media: [], post_comments: [], post_likes: [], post_saves: [], post_share_days: [], notifications: notes, moderation_queue: [],
    follows: [], member_blocks: [{ blocker_id: BLK, blocked_id: POSTER }], member_mutes: [], member_media: [], profiles: [],
    user_preferences: [{ user_id: OFFQ, need_alerts: false }, { user_id: NULLPREF, need_alerts: null }]
  });
  const jobs = [], pushes = [];
  const free = new Set([FREE, FREEOFF]);
  const deps = { sb: db.client, now: () => NOW, claims: () => null, ownerPublic: async () => true, push: async (a, b) => { pushes.push([a, b]); }, env: {},
    tierOf: async id => (free.has(id) ? "free" : "member"), membersPanel: () => ({ title: "Members" }), background: j => jobs.push(j) };
  return { db, deps, jobs, pushes, settle: async () => { await new Promise(r => setTimeout(r, 30)); await Promise.all(jobs.slice()); await new Promise(r => setTimeout(r, 10)); } };
}
const NEED = { body: "Looking for a tattoo artist for a forearm piece, black and grey, this month, someone patient with first timers please.", intent: "need", category: "tattoo_body_art", need_place: "San Diego, CA", need_when: "week" };
const alerts = w => w.db.t.notifications.filter(n => n.type === "need_alert" && n.user_id !== FULL);

(async function main() {
  /* ── A ── */
  console.log("\n══ A. a new post's intent, category, Where and When ══");
  const v = b => P.validateNew(Object.assign({ body: "x" }, b));
  check("A1. the intent is required: share, offer or need, nothing else", v({ category: "art" }).field === "intent" && v({ intent: "sell", category: "art" }).field === "intent" &&
    J(P.INTENTS) === J(["share", "offer", "need"]) && v({ intent: "share", category: "art" }).intent === "share", J(v({ category: "art" })));
  check("A2. the category is required, a slug's form", v({ intent: "need" }).error === P.MESSAGES.category && v({ intent: "need", category: "Not A Slug" }).error === P.MESSAGES.categoryBad &&
    v({ intent: "need", category: "art" }).category === "art");
  check("A3. a Need links no listing", v({ intent: "need", category: "art", listing_id: lid(1) }).error === P.MESSAGES.needListing);
  check("A4. Where and When are a Need's alone", v({ intent: "share", category: "art", need_place: "Leeds" }).error === P.MESSAGES.needOnly && v({ intent: "share", category: "art", need_when: "today" }).field === "need_when");
  const okPlace = v({ intent: "need", category: "art", need_place: "  San   Diego,  CA " + "x".repeat(0) }), longPlace = v({ intent: "need", category: "art", need_place: "y".repeat(81) });
  check("A5. Where at most 80 characters (spaces folded), empty is none", okPlace.need.need_place === "San Diego, CA" && longPlace.error === P.MESSAGES.needPlace &&
    !v({ intent: "need", category: "art", need_place: "y".repeat(80) }).error && v({ intent: "need", category: "art", need_place: "  " }).need.need_place === null && P.NEED_PLACE_MAX === 80, J(okPlace.need));
  check("A6. When is today, week or any; absent reads as any", v({ intent: "need", category: "art", need_when: "month" }).error === P.MESSAGES.needWhen &&
    v({ intent: "need", category: "art" }).need.need_when === "any" && v({ intent: "need", category: "art", need_when: "today" }).need.need_when === "today" && J(P.NEED_WHENS) === J(["today", "week", "any"]));

  /* ── B ── */
  console.log("\n══ B. who may post what ══");
  let w = world();
  let r = await P.createPost(w.deps, POSTER, { body: "x", intent: "share", category: "nope_cat" });
  check("B1. a category not on the list (or switched off) is refused, nothing saved", r.status === 400 && r.body.error === P.MESSAGES.categoryBad &&
    (await P.createPost(w.deps, POSTER, { body: "x", intent: "share", category: "retired_cat" })).status === 400 && w.db.t.posts.length === 1, J(r.body));
  r = await P.createPost(w.deps, FREE, { body: "x", intent: "offer", category: "art", listing_id: lid(10) });
  const rFree2 = await P.createPost(w.deps, FREE, { body: "x", intent: "offer", category: "art" });
  check("B2. a free account's Offer: 403, the Offer's own sentence and the members panel, with or without a listing; nothing saved", r.status === 403 && r.body.reason === "members_only" && r.body.members_panel &&
    r.body.error === P.MESSAGES.offerMembers && rFree2.status === 403 && rFree2.body.error === P.MESSAGES.offerMembers && w.db.t.posts.length === 1, J([r.body, rFree2.body]));
  r = await P.createPost(w.deps, POSTER, { body: "x", intent: "offer", category: "art" });
  check("B3. a member's Offer names a listing", r.status === 400 && r.body.error === P.MESSAGES.offerListing, J(r.body));
  r = await P.createPost(w.deps, POSTER, { body: "x", intent: "offer", category: "tattoo_body_art", listing_id: lid(1) });
  const rSold = await P.createPost(w.deps, POSTER, { body: "x", intent: "offer", category: "art", listing_id: lid(11) });
  check("B4. ...one of their own active listings (not another's, not a sold one)", r.status === 400 && r.body.error === P.MESSAGES.listingBad && rSold.status === 400, J(r.body));
  r = await P.createPost(w.deps, POSTER, { body: "Prints of my work, signed.", intent: "offer", category: "art", listing_id: lid(10) });
  const offerRow = w.db.t.posts.find(p => p.intent === "offer" && p.author_id === POSTER);
  check("B5. a member's Offer with their listing is posted with its intent, category and listing", r.status === 201 && offerRow && offerRow.category === "art" && offerRow.listing_id === lid(10) && r.body.post.intent === "offer", J(r.body));
  r = await P.createPost(w.deps, FREE, { body: "Need a plumber for a leaking tap.", intent: "need", category: "home_services" in {} ? "x" : CATEGORY_ROWS[0].slug });
  check("B6. a free account's Need may be text only", r.status === 201 && r.body.post.intent === "need", J(r.body));
  r = await P.createPost(w.deps, FREE, { body: "Just words.", intent: "share", category: "art" });
  check("B7. a free account's text Share still needs a photo", r.status === 403 && r.body.reason === "photo_required", J(r.body));
  const n0 = w.db.t.posts.length;
  r = await P.createPost(w.deps, POSTER, { body: "need onlyfans nudes shoot", intent: "need", category: "photography" });
  const rOffer = await P.createPost(w.deps, POSTER, { body: "selling nude photos", intent: "offer", category: "art", listing_id: lid(10) });
  check("B8. the content screen runs on a Need and an Offer too (adult content refused), nothing saved", r.status === 400 && r.body.reason === "content_policy" && rOffer.status === 400 && w.db.t.posts.length === n0, J(r.body));
  r = await P.createPost(w.deps, UNVER, { body: "Help please", intent: "need", category: "photography" });
  check("B9. an unconfirmed email cannot post a public Need", r.status === 403 && w.db.t.posts.length === n0, J(r.body));
  r = await P.createPost(w.deps, POSTER, NEED);
  const needRow = w.db.t.posts.find(p => p.id === (r.body.post && r.body.post.id));
  check("B10. a Need is stored with its intent, category, Where and When", r.status === 201 && needRow && needRow.intent === "need" && needRow.category === "tattoo_body_art" &&
    needRow.need_place === "San Diego, CA" && needRow.need_when === "week" && needRow.need_found_at == null, J(needRow));

  /* ── C ── */
  console.log("\n══ C. Need alerts ══");
  check("C1. the post answered before any alert was written (never delayed by them)", alerts(w).length === 0);
  await w.settle();
  const to = alerts(w).map(n => n.user_id);
  check("C2. the members who offer in the category in the Need's city are told, and only they (the city preferred)", J(to) === J([NEAR1]), J(to));
  const fullRows = w.db.t.notifications.filter(n => n.user_id === FULL).length;
  check("C3. never the poster, a blocked member, a free account, one who switched alerts off, one past 20 today, nor an offer older than 90 days or a paused listing",
    [POSTER, BLK, FREEOFF, OFFQ, OLDOFF].every(x => to.indexOf(x) === -1) && fullRows === 20, fullRows);
  const note = alerts(w)[0] || {};
  check("C4. \"[Name] needs help in [Category]: [first 80 characters]\", linking to the post, in-app (type need_alert)",
    note.message === "Rosa Diaz needs help in Tattoo & Body Art: " + Array.from(NEED.body).slice(0, 80).join("") && note.link === "/home.html?post=" + needRow.id && note.type === "need_alert" && note.object_id === needRow.id, J(note));
  check("C5. no push, no email, no SMS: nothing leaves BizForce", w.pushes.length === 0 && !/deps\.push|sendEmail|sendSms|sendMail|twilio|resend|webpush|fcm/i.test(FILES[NA]), J(w.pushes));
  w = world();
  await P.createPost(w.deps, POSTER, Object.assign({}, NEED, { need_place: "Portland, OR" })); await w.settle();
  const far = alerts(w).map(n => n.user_id).sort();
  check("C6. with nobody in the city, the category's members are told (NULL preference reads as on)", J(far) === J([FAR1, NEAR1, NULLPREF].sort()), J(far));
  w = world({ many: true });
  await P.createPost(w.deps, POSTER, Object.assign({}, NEED, { category: "photography", need_place: null })); await w.settle();
  check("C7. at most 10 per Need", alerts(w).length === 10 && NAL.PER_NEED === 10, alerts(w).length);
  w = world({ nineteen: true });
  await P.createPost(w.deps, POSTER, NEED); await w.settle();
  check("C8. 20 per member per day: the 20th is still sent, a 21st is not", w.db.t.notifications.filter(n => n.user_id === FULL).length === 20 && NAL.PER_MEMBER_DAY === 20);
  w = world();
  await P.createPost(w.deps, POSTER, Object.assign({}, NEED, { audience: "followers" })); await w.settle();
  const fol = alerts(w).length;
  const fRes = await NAL.alertNeed({ sb: w.deps.sb, now: () => NOW, tierOf: w.deps.tierOf }, Object.assign({ id: u(900), author_id: POSTER, status: "published", audience: "public" }, NEED, { need_found_at: NOW }));
  check("C9. none for a followers-only Need or a Found one", fol === 0 && fRes.sent === 0 && fRes.reason === "found", J(fRes));
  // the alert job alone, over a Need already saved: its block list unreadable
  w = world();
  const saved = await P.createPost(w.deps, POSTER, Object.assign({}, NEED, { audience: "followers" }));
  const row10 = Object.assign({}, w.db.t.posts.find(p => p.id === saved.body.post.id), { audience: "public" });
  w.db.failOn("member_blocks", "select");
  const q = await quiet(async () => P.startNeedAlerts(w.deps, row10));
  check("C10. an unreadable block list sends nothing (fails closed); the failure is logged, the job never throws, and the post stands",
    saved.status === 201 && q.v === null && alerts(w).length === 0 && q.said.some(s => /\[need-alerts\]/.test(s)) && w.db.t.posts.some(p => p.id === row10.id), J(q.said));
  check("C11. the preview counts characters: 80 at most", NAL.preview("a".repeat(100)).length === 80 && NAL.PREVIEW_CHARS === 80 && NAL.OFFER_DAYS === 90);

  /* ── D ── */
  console.log("\n══ D. the feed's parts, Found, the composer ══");
  w = world();
  r = await P.createPost(w.deps, POSTER, NEED); await w.settle();
  const nid = r.body.post.id;
  const seen = async (viewer) => { const x = await P.getPost(w.deps, viewer, nid); return x.body && x.body.post; };
  let mp = r.body.post, np = await seen(NEAR1), fp = await seen(FREEOFF), op = await seen(u(500)), ap = await seen(ARTIST);
  check("D1. the post carries intent, its category {slug, name} and need {place, city, when, found}", mp.intent === "need" && J(mp.category) === J({ slug: "tattoo_body_art", name: "Tattoo & Body Art" }) &&
    J(mp.need) === J({ place: "San Diego, CA", city: "San Diego", when: "week", found: false }), J(mp));
  check("D2. can_help for a member who offers in the category; never the poster, a free account or a member who does not", np && np.can_help === true && mp.can_help === false && (await seen(POSTER)).can_help === false && fp && fp.can_help === false && op && op.can_help === false && ap && ap.can_help === false,
    J([np && np.can_help, mp.can_help, fp && fp.can_help, op && op.can_help, ap && ap.can_help]));
  const other = await P.markFound(w.deps, NEAR1, nid, true);
  check("D3. only the poster marks it Found", other.status === 404 && !w.db.t.posts.find(p => p.id === nid).need_found_at);
  const f1 = await P.markFound(w.deps, POSTER, nid, true);
  np = await seen(NEAR1);
  check("D4. Found: need.found true, no I can help", f1.status === 200 && f1.body.post.need.found === true && np.can_help === false && f1.body.post.can_help === false, J(f1.body));
  const f2 = await P.markFound(w.deps, POSTER, nid, false);
  np = await seen(NEAR1);
  check("D5. it can be reopened, and the strip comes back", f2.status === 200 && f2.body.post.need.found === false && np.can_help === true && w.db.t.posts.find(p => p.id === nid).need_found_at === null);
  const sh = await P.createPost(w.deps, POSTER, { body: "My new piece.", intent: "share", category: "art" });
  const f3 = await P.markFound(w.deps, POSTER, sh.body.post.id, true);
  check("D6. only a Need can be Found", f3.status === 400 && f3.body.error === P.MESSAGES.foundNeed, J(f3.body));
  const ci = await P.composerInfo(w.deps, POSTER);
  check("D7. the composer gets the profile's place and the member's own active listings and services, each with its category",
    ci.status === 200 && ci.body.place === "San Diego, CA" && J(ci.body.offers.map(o => o.id).sort()) === J([lid(9), lid(10)]) && ci.body.offers.every(o => o.category && (o.kind === "service" || o.kind === "product")), J(ci.body));

  /* ── E ── */
  console.log("\n══ E. the one list and the server ══");
  w = world();
  const list = await CAT.list(w.deps.sb);
  check("E1. lib/categories.js reads the categories table: the 32 active ones, in sort order, none switched off", list.length === 32 && list.every(c => c.slug !== "retired_cat") &&
    J(list.map(c => c.slug)) === J(CATEGORY_ROWS.slice().sort((a, b) => a.sort_order - b.sort_order).map(c => c.slug)), list.length);
  const codeFiles = [POSTS, NA, CATS, SERVER, COMP, FEED, MARKET];
  check("E2. no copy of the list lives in code (no category names typed in the libs, the composer, the feed or the Market)",
    codeFiles.every(f => !/"Tattoo & Body Art"|"Hair & Beauty"|'Tattoo & Body Art'/.test(FILES[f] || "")) &&
    // the agents' publish_listing allowlist predates P3-3: ten slugs, every one on the list (reported); it is not grown into a copy
    (FILES[SERVER].match(/const MARKETPLACE_CATEGORIES = \[([^\]]*)\]/) || [, ""])[1].split(",").length === 10);
  check("E3. GET /api/categories is public; the composer and Found routes need a session", has(FILES[ACCESS], "\"get /api/categories\"") && has(FILES[ACCESS], "\"get /api/posts/composer\"") &&
    has(FILES[ACCESS], "\"post /api/posts/:id/found\"") && has(FILES[ACCESS], "\"delete /api/posts/:id/found\"") &&
    has(FILES[SERVER], "app.get(\"/api/categories\", async function (req, res, next) {\n  try {\n    const rows = await require(\"./lib/categories\").list(supabase);") &&
    has(FILES[SERVER], "app.post(\"/api/posts/:id/found\", requireAuth, postRoute(") && has(FILES[SERVER], "app.delete(\"/api/posts/:id/found\", requireAuth, postRoute("));
  check("E4. a listing needs a category on the list, stored as category_slug; an edit keeps one",
    has(FILES[SERVER], "    if (!category) return res.status(400).json({ error: LISTING_CATEGORY_MESSAGE, field: \"category\" });\n    if (!(await require(\"./lib/categories\").find(supabase, category))) return res.status(400).json({ error: LISTING_CATEGORY_BAD_MESSAGE, field: \"category\" });") &&
    has(FILES[SERVER], "      price_bfc: priceBfc, price_usd: null, category, category_slug: category, tags, media: sanitizeMedia(req.body.media, req.user.id), status: \"active\",") &&
    has(FILES[SERVER], "      updates.category_slug = editCategory.slug;") && has(FILES[SERVER], "if (!updates.category_slug && !existing.category_slug) return res.status(400).json({ error: LISTING_CATEGORY_MESSAGE"));
  check("E5. the Market's ?category filters by category_slug", has(FILES[SERVER], "    if (category && category !== \"all\") query = query.eq(\"category_slug\", category);"));
  check("E6. the preference: on unless switched off; true, false or null accepted", has(FILES[SERVER], "      need_alerts: row.need_alerts !== false,") &&
    has(FILES[SERVER], "      if (req.body.need_alerts !== null && typeof req.body.need_alerts !== \"boolean\") {"));

  /* ── F ── */
  console.log("\n══ F. the /p/ page ══");
  // seo: a member's indexable post (P3-1B), the only kind with JSON-LD
  const pagePost = Object.assign({}, mp, { need: Object.assign({}, mp.need), seo: { title: "Tattoo artist wanted", description: "A Need in San Diego" } });
  const html = PP.renderPostPage(pagePost);
  check("F1. the page shows \"Need · Category · City · When\"", has(html, '<p class="pp-intent" id="ppIntent" data-intent="need">Need · Tattoo &amp; Body Art · San Diego · This week</p>'), (html.match(/<p class="pp-intent"[^\n]*/) || [""])[0]);
  const ld = JSON.parse((/<script type="application\/ld\+json">([\s\S]*?)<\/script>/.exec(html) || [, "{}"])[1].replace(/\\u003c/g, "<"));
  check("F2. the JSON-LD names the category (articleSection) and the intent (keywords)", ld.articleSection === "Tattoo & Body Art" && ld.keywords === "Need, Tattoo & Body Art", J([ld.articleSection, ld.keywords]));
  const fhtml = PP.renderPostPage(Object.assign({}, pagePost, { need: Object.assign({}, pagePost.need, { found: true, when: "any" }) }));
  check("F3. a Found Need reads Found, and Any is left out", has(fhtml, ">Found · Tattoo &amp; Body Art · San Diego</p>"));

  /* ── G ── */
  console.log("\n══ G. the frontend ══");
  check("G1. the composer sends the intent and category, an Offer's listing, a Need's Where and When; it stops without a category",
    has(FILES[COMP], "      var extra = { intent: it, category: category() };") && has(FILES[COMP], "      if (it === \"offer\") extra.listing_id = listing.value;") &&
    has(FILES[COMP], "        extra.need_when = val(\"bfcWhen\", \"any\");") && has(FILES[COMP], "      if (!category()) { stop(MSG.category, cats.querySelector(\"input\")); return; }"));
  check("G2. I can help opens a private message through the messages route, the post linked, then the conversation",
    has(FILES[FEED], "      call(\"POST\", \"/api/messages\", { receiver_id: a.id, content: text })") && has(FILES[FEED], "      if (text.indexOf(link) === -1) text = (text ? text + \"\\n\\n\" : \"\") + link;   // the post stays linked") &&
    has(FILES[FEED], "window.location.href = \"/inbox.html?with=\" + encodeURIComponent(a.id);"));
  check("G3. Settings: the Need alerts switch, on unless switched off, saved as need_alerts, shown to members",
    has(FILES[SETTINGS], "        putPreferences({ need_alerts: needAlertsToggle.checked }, needAlertsSaved);") && has(FILES[SETTINGS], "needAlertsToggle.checked = prefs.need_alerts !== false;") &&
    has(FILES[SETTINGS], "        .then(function (d) { needAlertsRow.hidden = !(d && d.access && d.access.tier === \"member\"); })"));
  check("G4. the Market: chips from the list filter by category_slug; a listing cannot be saved without one; the owner's uncategorised listing asks for one",
    has(FILES[MARKET], "    items = items.filter(function(l) { return l.category_slug === activeCat; });") && has(FILES[MARKET], "  if (!category) {\n    var cn = document.getElementById(\"fCategoryNote\");") &&
    has(FILES[MARKET], "var addCat = isOwn && !l.category_slug ?") && has(FILES[MARKET], "fetch(API_URL + \"/api/categories\")"));
  /* ── J (NAMED (Nov 23 2026, P3-3B)) ── */
  console.log("\n══ J. a Need approved later, or made Public by an edit ══");
  const held = (w, extra) => {
    const id = "ffffffff-0000-4000-8000-" + String(w.db.t.posts.length + 1).padStart(12, "0");
    w.db.t.posts.push(Object.assign({ id, author_id: POSTER, kind: "text", status: "pending", audience: "public", published_at: null, created_at: NOW, removed_at: null, listing_id: null,
      body: NEED.body, intent: "need", category: NEED.category, need_place: NEED.need_place, need_when: "week", need_found_at: null, search_visible: false }, extra || {}));
    const qid = "99999999-0000-4000-8000-" + String(w.db.t.moderation_queue.length + 1).padStart(12, "0");
    w.db.t.moderation_queue.push({ id: qid, object_type: "post", object_id: id, owner_id: POSTER, state: "waiting", created_at: NOW });
    return { id, qid };
  };
  const decide = (w, qid) => quiet(() => MODL.decide(w.deps.sb, { adminId: u(999), id: qid, action: "keep", note: "", nowIso: NOW, postDeps: w.deps }));
  const forPost = (w, id) => w.db.t.notifications.filter(n => n.type === "need_alert" && n.object_id === id).map(n => n.user_id).sort();
  w = world();
  let hp = held(w);
  let d1 = await decide(w, hp.qid); await w.settle();
  const firstTo = forPost(w, hp.id);
  check("J1. a held Need approved from moderation (decide, keep) is published and sends its alerts, as a Need published at once does",
    d1.v.status === 200 && w.db.t.posts.find(p => p.id === hp.id).status === "published" && J(firstTo) === J([NEAR1]), J([d1.v.status, firstTo, d1.said]));
  w.db.t.posts.find(p => p.id === hp.id).status = "pending";
  w.db.t.moderation_queue.find(q => q.id === hp.qid).state = "waiting";
  await decide(w, hp.qid); await w.settle();
  await P.editPost(w.deps, POSTER, hp.id, { body: NEED.body + " Thanks.", audience: "public" }); await w.settle();
  check("J2. a second approval, and an edit after it, send nothing more (once only: the need_alert rows already naming the post)", J(forPost(w, hp.id)) === J([NEAR1]), J(forPost(w, hp.id)));
  w = world();
  hp = held(w, { need_found_at: NOW });
  await decide(w, hp.qid); await w.settle();
  check("J3. a Need marked Found while held, approved later, sends nothing", w.db.t.posts.find(p => p.id === hp.id).status === "published" && forPost(w, hp.id).length === 0, J(forPost(w, hp.id)));
  w = world();
  const fo = await P.createPost(w.deps, POSTER, Object.assign({}, NEED, { audience: "followers" })); await w.settle();
  const foId = fo.body.post.id, before = forPost(w, foId).length;
  const e1 = await P.editPost(w.deps, POSTER, foId, { body: NEED.body, audience: "public" }); await w.settle();
  const afterPublic = forPost(w, foId);
  await P.editPost(w.deps, POSTER, foId, { body: NEED.body, audience: "followers" });
  await P.editPost(w.deps, POSTER, foId, { body: NEED.body, audience: "public" }); await w.settle();
  check("J4. a Followers Need edited to Public sends its alerts once; back to Followers and Public again sends nothing more",
    fo.status === 201 && before === 0 && e1.status === 200 && w.db.t.posts.find(p => p.id === foId).audience === "public" && J(afterPublic) === J([NEAR1]) && J(forPost(w, foId)) === J([NEAR1]), J([e1.status, afterPublic, forPost(w, foId)]));
  w = world();
  const pub = await P.createPost(w.deps, POSTER, NEED); await w.settle();
  w.db.t.notifications = w.db.t.notifications.filter(n => n.object_id !== pub.body.post.id);   // even with no record, an edit of a Need already public sends nothing
  await P.editPost(w.deps, POSTER, pub.body.post.id, { body: NEED.body + " Still looking." }); await w.settle();
  check("J5. an edit of a Need that was already published and public starts no alerts", forPost(w, pub.body.post.id).length === 0, J(forPost(w, pub.body.post.id)));
  const ux = await P.createPost(w.deps, UNVER, Object.assign({}, NEED, { audience: "followers" }));
  const ue = ux.status === 201 ? await P.editPost(w.deps, UNVER, ux.body.post.id, { body: NEED.body, audience: "public" }) : { status: 0 };
  const bad = await P.editPost(w.deps, POSTER, pub.body.post.id, { body: NEED.body, audience: "everyone" });
  check("J6. Public by edit needs a confirmed email (403, still Followers); the audience is public or followers, nothing else",
    ux.status === 201 && ue.status === 403 && w.db.t.posts.find(p => p.id === ux.body.post.id).audience === "followers" && bad.status === 400 && bad.body.field === "audience", J([ux.status, ue.status, bad.body]));
  w = world();
  hp = held(w);
  w.db.failOn("notifications", "select");
  const fq = await quiet(async () => { const x = await MODL.decide(w.deps.sb, { adminId: u(999), id: hp.qid, action: "keep", note: "", nowIso: NOW, postDeps: w.deps }); await w.settle(); return x; });
  check("J7. an unreadable once-only record sends nothing (fails closed), is logged, and the approval stands",
    fq.v.status === 200 && w.db.t.posts.find(p => p.id === hp.id).status === "published" && forPost(w, hp.id).length === 0 && fq.said.some(s => /\[need-alerts\]/.test(s)), J([fq.v.status, forPost(w, hp.id), fq.said]));
  w = world();
  hp = held(w);
  await quiet(() => MODL.decide(w.deps.sb, { adminId: u(999), id: hp.qid, action: "keep", note: "", nowIso: NOW })); await w.settle();
  check("J8. without the post deps (no tier lookup) nobody is told; the server's decide route hands postDeps()",
    forPost(w, hp.id).length === 0 && has(FILES[SERVER], "action: body.action, note: body.note, nowIso: nowIso(), postDeps: postDeps() });") &&
    has(FILES[MOD], "applyDecision(sb, row, state, nowIso, opts.postDeps || null);"), J(forPost(w, hp.id)));
  T.finish();
})().catch(e => { console.log("    FAIL  the check ran to its end  [" + (e && e.stack || e) + "]"); process.exit(1); });
