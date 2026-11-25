#!/usr/bin/env node
"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   checkGetFound.js — LR-4 (Nov 25 2026): Get found.
     node scripts/checkGetFound.js                 the checks
     MUTATE=<name> node scripts/checkGetFound.js   one mutation, in memory (a check must FAIL)
     MUTATE=all node scripts/checkGetFound.js      every mutation, each in its own process

   Everything here runs on fakes: an in-memory database, a fake app for the routes, a fake fetch and a fake
   timer for IndexNow. No network, no model, no live write, no IndexNow or search-engine ping.

   A. migration 206: 206a (user_preferences.show_in_google) and 206b (indexnow_sent), paste-safe
   B. the robots rule: member, free, not public, suspended, hidden, switch off, a paused or hidden listing
   C. the heads and the JSON-LD: Person or LocalBusiness, Product with no offers (NAMED (Nov 25 2026, LR-4B): BEFORE offers
      with a USD price; AFTER none, even for an old price_usd, since listings are priced in BizCash only), never BizCash
   D. every string escaped: user text cannot leave the JSON-LD script, a tag or an attribute
   E. the pages: /@handle and /listing/:id answer 200, 404 or 503 with the right head; the shells are the frontend's
   F. the sitemaps list only indexable pages, are cached, and the switch takes a page out at once
   G. IndexNow: off by default, batched, once per address per day, written before it is sent, never blocking a save
   H. the Found score: every item, weight, status, action and the order
   I. the switch: GET and PUT /api/me/google, booleans only, NULL and a missing column read as on, the Settings page
   J. members only: the three member routes are M, a free account gets 402; the pages
   K. the lists and the words: yourData, backup, schemaCheck, the Privacy Policy, README, _redirects, robots.txt,
      sitemap.xml
   ═══════════════════════════════════════════════════════════════════════════ */
const path = require("path");
const vm = require("vm");
const cp = require("child_process");
const H = require("./_p21Harness");

const PPF = "@lib/publicPages.js", GFR = "@lib/getFoundRoutes.js", IXF = "@lib/indexNow.js", FSF = "@lib/foundScore.js", SERVER = "@server.js";
const MIG = "@supabase/migrations/206_lr4_get_found.sql", YD = "@lib/yourData.js", BK = "@lib/backup.js", SC = "@lib/schemaCheck.js", RM = "@README.md", LEGAL = "@lib/legalPages.js";
const SETTINGS = "settings.html", RADAR = "agents/lead-radar.html", PRIV = "privacy.html", REDIR = "_redirects", ROBOTS = "robots.txt", SMAP = "sitemap.xml";

const MUTATIONS = {
  // A. the migration
  "mig-no-column": [[MIG, "ADD COLUMN IF NOT EXISTS show_in_google boolean;", "ADD COLUMN IF NOT EXISTS show_in_google boolean DEFAULT false;"]],
  "mig-no-rls": [[MIG, "ALTER TABLE public.indexnow_sent ENABLE ROW LEVEL SECURITY;", ""]],
  "mig-gte": [[MIG, "length(url) < 501", "length(url) <= 500"]],
  // B. the robots rule
  "robots-free": [[PPF, "if (f.member !== true || f.pagePublic", "if (f.pagePublic"]],
  "robots-private": [[PPF, "f.pagePublic !== true || f.suspended", "f.suspended"]],
  "robots-suspended": [[PPF, "f.suspended === true || f.profileHidden", "f.profileHidden"]],
  "robots-hidden": [[PPF, "f.profileHidden === true || f.switchOn", "f.switchOn"]],
  "robots-switch": [[PPF, "|| f.switchOn !== true) return NOINDEX;", ") return NOINDEX;"]],
  "robots-paused": [[PPF, "if (!f.listing || f.listing.active !== true || f.listing.hidden === true) return NOINDEX;", "if (!f.listing || f.listing.hidden === true) return NOINDEX;"]],
  "robots-listing-hidden": [[PPF, "f.listing.active !== true || f.listing.hidden === true) return NOINDEX;", "f.listing.active !== true) return NOINDEX;"]],
  "switch-null-off": [[PPF, "function switchOn(value) { return value !== false; }", "function switchOn(value) { return value === true; }"]],
  "route-shows-suspended": [[GFR, "function shown(idx) { return idx.pagePublic && !idx.suspended && !idx.profileHidden; }", "function shown(idx) { return idx.pagePublic && !idx.profileHidden; }"]],
  "route-paused-listing": [[GFR, "if (!l || l.status !== \"active\") return null;", "if (!l) return null;"]],
  "route-hidden-listing": [[GFR, "  if ((await deps.hiddenAmong(deps.sb, \"listing\", [l.id])).has(l.id)) return null;\n", ""]],
  "route-switch-ignored": [[GFR, "    switchOn: PP.switchOn(await readSwitch(deps.sb, userId))\n", "    switchOn: true\n"]],
  // C. the heads
  "title-words": [[PPF, "\" (@\" + p.username + \") on BizForce\"", "\" (@\" + p.username + \") | BizForce\""]],
  "listing-title-words": [[PPF, "\" by \" + sellerName(s) + \" | BizForce\"", "\" | BizForce\""]],
  "always-person": [[PPF, "var local = !!clean(p.place_city) && listingCount > 0;", "var local = false;"]],
  "local-no-listings": [[PPF, "var local = !!clean(p.place_city) && listingCount > 0;", "var local = !!clean(p.place_city);"]],
  "no-region": [[PPF, "    if (clean(p.place_region)) data.address.addressRegion = clean(p.place_region);\n", ""]],
  "no-same-as": [[PPF, "  if (same.length) data.sameAs = same;\n", ""]],
  // NAMED (Nov 25 2026, LR-4B): BEFORE four offers mutations (always, BizCash, currency, fraction); AFTER there is no offers code,
  // so the mutants put an Offer back, from an old price_usd or from the BizCash price
  "offers-legacy-usd": [[PPF, "  if (image) data.image = image;\n", "  if (image) data.image = image;\n  if (l.price_usd) data.offers = { \"@type\": \"Offer\", price: String(l.price_usd), priceCurrency: \"USD\" };\n"]],
  "offers-bfc": [[PPF, "  if (image) data.image = image;\n", "  if (image) data.image = image;\n  if (l.price_bfc) data.offers = { \"@type\": \"Offer\", price: String(l.price_bfc), priceCurrency: \"BFC\" };\n"]],
  "no-brand": [[PPF, ",\n    brand: { \"@type\": \"Brand\", name: sellerName(s) } };", " };"]],
  "no-category": [[PPF, "  if (clean(categoryName || l.category)) data.category = clean(categoryName || l.category);\n", ""]],
  "canonical-handle-case": [[PPF, "function profileUrl(handle) { return SITE + \"/@\" + handle; }", "function profileUrl(handle) { return SITE + \"/seller.html?u=\" + handle; }"]],
  "og-no-avatar": [[PPF, "function profileImage(p) { return httpsUrl(p.avatar_url) || httpsUrl(p.banner_url) || DEFAULT_IMAGE; }", "function profileImage(p) { return DEFAULT_IMAGE; }"]],
  "noscript-all-listings": [[PPF, "var items = (listings || []).slice(0, NOSCRIPT_LISTINGS).map(", "var items = (listings || []).map("]],
  "desc-no-bio": [[PPF, "  if (bio) return bio;\n", ""]],
  // D. escaping
  "ld-lt": [[PPF, ".replace(/</g, \"\\\\u003c\")", ""]],
  "ld-2028": [[PPF, "\n    .replace(/\\u2028/g, \"\\\\u2028\").replace(/\\u2029/g, \"\\\\u2029\");", ";"]],
  "title-unescaped": [[PPF, "    \"  <title>\" + esc(title) + \"</title>\"\n  ];\n}\n\nfunction renderProfilePage", "    \"  <title>\" + title + \"</title>\"\n  ];\n}\n\nfunction renderProfilePage"]],
  "desc-unescaped": [[PPF, "    '  <meta name=\"description\" content=\"' + esc(desc) + '\"/>',\n    '  <meta name=\"robots\" content=\"' + (view.robots === INDEX ? INDEX : NOINDEX) + '\"/>',\n    '  <link rel=\"canonical\" href=\"' + esc(url) + '\"/>',\n    '  <meta property=\"og:type\" content=\"profile\"/>',",
    "    '  <meta name=\"description\" content=\"' + desc + '\"/>',\n    '  <meta name=\"robots\" content=\"' + (view.robots === INDEX ? INDEX : NOINDEX) + '\"/>',\n    '  <link rel=\"canonical\" href=\"' + esc(url) + '\"/>',\n    '  <meta property=\"og:type\" content=\"profile\"/>',"]],
  "noscript-unescaped": [[PPF, "\"<h1>\" + esc(clean(l.title) || \"A listing\") + \"</h1>\"", "\"<h1>\" + (clean(l.title) || \"A listing\") + \"</h1>\""]],
  "image-any-url": [[PPF, "function httpsUrl(url) { return typeof url === \"string\" && /^https:\\/\\/[^\\s\"'<>\\\\]+$/.test(url) && url.length < 501 ? url : null; }", "function httpsUrl(url) { return typeof url === \"string\" ? url : null; }"]],
  // E. the pages
  "no-503": [[GFR, "      res.set(\"Retry-After\", \"60\");\n      return sendPage(res, 503, PP.renderProfilePage(null));", "      return sendPage(res, 200, PP.renderProfilePage(null));"]],
  "missing-200": [[GFR, "return sendPage(res, view ? 200 : 404, PP.renderProfilePage(view));", "return sendPage(res, 200, PP.renderProfilePage(view));"]],
  "products-hidden-shown": [[GFR, "  if (p.show_products !== false) {", "  if (true) {"]],
  // F. the sitemaps
  "sitemap-all-profiles": [[GFR, "      if ((await indexability(deps, p.user_id)).indexable) out.push(", "      out.push("]],
  "sitemap-hidden-listing": [[GFR, "      if (hid.has(l.id)) continue;\n", ""]],
  "sitemap-free-listing": [[GFR, "      if (sellers[l.seller_id]) out.push(", "      out.push("]],
  "sitemap-not-cached": [[GFR, "if (!cache[name].xml || now() - cache[name].at > SITEMAP_CACHE_MS)", "if (true)"]],
  "switch-keeps-cache": [[GFR, "      if (w.error) throw w.error;\n      resetSitemaps();\n", "      if (w.error) throw w.error;\n"]],
  // G. IndexNow
  "ix-on-by-default": [[IXF, "env.ENABLE_INDEXNOW === \"true\" && keyOf(env) !== null", "env.ENABLE_INDEXNOW !== \"false\" && keyOf(env) !== null"]],
  "ix-no-key-needed": [[IXF, "env.ENABLE_INDEXNOW === \"true\" && keyOf(env) !== null", "env.ENABLE_INDEXNOW === \"true\""]],
  "ix-twice-a-day": [[IXF, "return r.sent_on === today;", "return false;"]],
  "ix-send-before-mark": [[IXF, "    if (mark.error) { log(\"could not record the batch; nothing sent: \" + (mark.error.message || mark.error)); return { sent: 0 }; }\n", ""]],
  "ix-timer-per-queue": [[IXF, "if (added && !timer) {", "if (added) {"]],
  "ix-no-unref": [[IXF, "      if (timer && typeof timer.unref === \"function\") timer.unref();\n", ""]],
  "ix-throws": [[IXF, "running = tick().catch(function (e) { log(\"tick failed: \" + ((e && e.message) || e)); return { sent: 0 }; })", "running = tick()"]],
  "ix-any-url": [[IXF, "if (typeof u === \"string\" && URL_RE.test(u) && pending.size", "if (typeof u === \"string\" && pending.size"]],
  "ix-key-file-off": [[GFR, "    if (!IX.enabled(deps.env)) return res.status(404).type(\"text/plain\").send(\"Not found\");\n", ""]],
  "ix-key-location": [[IXF, "keyLocation: SITE + KEY_PATH,", "keyLocation: SITE + \"/\" + key + \".txt\","]],
  "ix-blocks-save": [[SERVER, "      indexNowAfterSave(req.user.id, postId);\n    });\n  }\n  next();", "      indexNowAfterSave(req.user.id, postId);\n    });\n    res.on(\"finish\", function () { next(); }); return;\n  }\n  next();"]],
  "ix-on-error": [[SERVER, "      if (res.statusCode < 200 || res.statusCode > 299 || !req.user || !req.user.id) return;\n      var postId = t[2]", "      if (!req.user || !req.user.id) return;\n      var postId = t[2]"]],
  "ix-when-off": [[SERVER, "  if (t && require(\"./lib/indexNow\").enabled(process.env)) {\n    var sent = null;", "  if (t) {\n    var sent = null;"]],
  // H. the score
  "w-basics": [[FSF, "var WEIGHTS = { basics: 15, profile: 20,", "var WEIGHTS = { basics: 10, profile: 20,"]],
  "w-profile": [[FSF, "basics: 15, profile: 20, listings: 20,", "basics: 15, profile: 25, listings: 20,"]],
  "w-listings": [[FSF, "profile: 20, listings: 20, posts: 15,", "profile: 20, listings: 15, posts: 15,"]],
  "w-posts": [[FSF, "listings: 20, posts: 15, connected: 15,", "listings: 20, posts: 20, connected: 15,"]],
  "w-connected": [[FSF, "posts: 15, connected: 15, fingerprint: 15 };", "posts: 15, connected: 10, fingerprint: 15 };"]],
  "w-fingerprint": [[FSF, "connected: 15, fingerprint: 15 };", "connected: 15, fingerprint: 20 };"]],
  "basics-city-only": [[FSF, "items.basics = hasCity && hasBio", "items.basics = hasCity"]],
  "profile-done-when-free": [[FSF, "if (f.profileIndexable === true && handle) {", "if (handle) {"]],
  "listing-no-photo-ok": [[FSF, "  if (!PP.firstPhoto(l.media)) miss.push(\"a photo\");\n", ""]],
  "listing-no-category-ok": [[FSF, "  if (!filled(l.category_slug) && !filled(l.category)) miss.push(\"a category\");\n", ""]],
  "listing-price-or-desc": [[FSF, "  if (!filled(l.description)) miss.push(\"a description\");", "  if (!l.price_usd && !filled(l.description)) miss.push(\"a description\");"]],   // NAMED (Nov 25 2026, LR-4B): the mutant lets a USD price stand in again
  "posts-some-is-done": [[FSF, "  } else if (!off.length) {", "  } else if (on.length) {"]],
  "posts-none-done": [[FSF, "  if (!posts.length) {\n    items.posts = { status: \"todo\"", "  if (!posts.length) {\n    items.posts = { status: \"done\""]],
  "connected-youtube-counts": [[FSF, "var named = [c.bluesky ? \"Bluesky\" : null, c.threads ? \"Threads\" : null].filter(Boolean);", "var named = [c.bluesky ? \"Bluesky\" : null, c.threads ? \"Threads\" : null, c.youtube ? \"YouTube\" : null].filter(Boolean);"]],
  "fp-four-words": [[FSF, "var MIN_WORDS = 5;", "var MIN_WORDS = 4;"]],
  "fp-no-place": [[FSF, "  if (!fp || !(filled(fp.place_city) || fp.reach === \"online\")) fpMiss.push(\"where\");\n", ""]],
  "waiting-weighs": [[FSF, "list.push({ key: \"waiting\", weight: 0,", "list.push({ key: \"waiting\", weight: 5,"]],
  "waiting-done": [[FSF, "list.push({ key: \"waiting\", weight: 0, status: \"waiting\",", "list.push({ key: \"waiting\", weight: 0, status: \"done\","]],
  "order-table": [[FSF, "return (rank[a[0].status] - rank[b[0].status]) || (a[1] - b[1]);", "return a[1] - b[1];"]],
  "fix-posts-all": [[FSF, "fix_posts: off.map(", "fix_posts: posts.map("]],
  "hidden-listing-counts": [[FSF, "listings = listings.filter(function (l) { return !hidden.has(l.id); }).map(", "listings = listings.map("]],
  "found-not-member": [[GFR, "  app.get(\"/api/leads/found\", M, async", "  app.get(\"/api/leads/found\", L, async"]],
  // I. the switch
  "switch-any-type": [[GFR, "if (typeof v !== \"boolean\") return res.status(400)", "if (v === undefined) return res.status(400)"]],
  "switch-missing-column-throws": [[GFR, "if (r.error.code === \"42703\" || /show_in_google/.test(String(r.error.message || \"\"))) {", "if (false) {"]],
  "switch-free-can-set": [[GFR, "  const M = [deps.requireAuth, deps.requireActiveSubscription];", "  const M = [deps.requireAuth];"]],
  "settings-no-free-line": [[SETTINGS, "if (res.status === 402) { googleFree.hidden = false; return; }", "if (res.status === 402) { return; }"]],
  "settings-no-revert": [[SETTINGS, "if (!res.ok || res.data.saved !== true) { googleToggle.checked = !want;", "if (!res.ok || res.data.saved !== true) {"]],
  "settings-default-off": [[SETTINGS, "googleToggle.checked = res.data.show_in_google !== false;", "googleToggle.checked = res.data.show_in_google === true;"]],
  // J. the page
  "fix-without-confirm": [[RADAR, "if (act === \"posts\") { GF.asking = true; drawFound();", "if (act === \"posts\") { fixPosts(((GF.data && GF.data.fix_posts) || []).slice());"]],
  "fix-no-search-visible": [[RADAR, "{ body: p.body, search_visible: true }", "{ body: p.body }"]],
  // K. the lists and the words
  "yd-no-switch": [[YD, "updated_at, need_alerts, show_in_google\", onDelete", "updated_at, need_alerts\", onDelete"]],
  "bk-no-table": [[BK, "  indexnow_sent:       \"the day each public address", "  indexnow_x:       \"the day each public address"]],
  "privacy-no-switch": [[PRIV, "Show my profile and listings in Google is on", "your profile is on"]],
  "redirect-below-catchall": [[REDIR, "/@:handle https://", "/@:handle-gone https://"]],
  "robots-no-allow": [[ROBOTS, "Allow: /@\n", ""]],
  "sitemap-index-no-profiles": [[SMAP, "sitemap-profiles.xml", "sitemap-people.xml"]]
};

const T = H.setup(__filename, MUTATIONS, [PPF, GFR, IXF, FSF, SERVER, MIG, YD, BK, SC, RM, LEGAL, SETTINGS, RADAR, PRIV, REDIR, ROBOTS, SMAP]);
const { FILES, check, finish, J } = T;

/* ── a small in-memory database: the query builder the four libs use ── */
function memDb(seed, opts) {
  const o = opts || {};
  const t = {}; Object.keys(seed || {}).forEach(k => { t[k] = seed[k].map(r => Object.assign({}, r)); });
  const log = [];
  const rows = n => (t[n] = t[n] || []);
  function from(name) {
    const q = { table: name, op: "select", cols: "*", payload: null, opts: null, filters: [], order: null, limit: null };
    log.push(q);
    const b = {};
    const add = (fn) => { q.filters.push(fn); return b; };
    b.select = (cols) => { if (q.op === "select") q.cols = cols || "*"; return b; };
    b.eq = (c, v) => add(r => r[c] !== undefined && r[c] !== null && String(r[c]) === String(v));
    b.in = (c, vs) => add(r => (vs || []).map(String).indexOf(String(r[c])) !== -1);
    b.not = (c, op, v) => add(r => op === "is" && v === null ? !(r[c] === null || r[c] === undefined) : true);
    b.order = (c, oo) => { q.order = [c, !(oo && oo.ascending === false)]; return b; };
    b.limit = n => { q.limit = n; return b; };
    b.upsert = (p, oo) => { q.op = "upsert"; q.payload = p; q.opts = oo || {}; return b; };
    function pick(r) {
      if (q.cols === "*") return Object.assign({}, r);
      const out = {}; String(q.cols).split(",").map(c => c.trim()).filter(Boolean).forEach(c => { out[c] = r[c] === undefined ? null : r[c]; }); return out;
    }
    function run() {
      if (o.fail && o.fail(name, q.op)) return { data: null, error: { code: "XX000", message: "down" } };
      if (o.missingColumn && name === "user_preferences" && q.op === "select" && /show_in_google/.test(q.cols)) return { data: null, error: { code: "42703", message: "column user_preferences.show_in_google does not exist" } };
      if (q.op === "upsert") {
        const key = (q.opts.onConflict || "id").split(",").map(s => s.trim());
        (Array.isArray(q.payload) ? q.payload : [q.payload]).forEach(p => {
          const hit = rows(name).find(r => key.every(k => String(r[k]) === String(p[k])));
          if (hit) Object.assign(hit, p); else rows(name).push(Object.assign({}, p));
        });
        return { data: null, error: null };
      }
      let all = rows(name).filter(r => q.filters.every(f => f(r)));
      if (q.order) { const [c, asc] = q.order; all = all.slice().sort((a, z) => (String(a[c]) < String(z[c]) ? -1 : String(a[c]) > String(z[c]) ? 1 : 0) * (asc ? 1 : -1)); }
      if (q.limit !== null) all = all.slice(0, q.limit);
      return { data: all.map(pick), error: null };
    }
    b.maybeSingle = () => Promise.resolve().then(() => { const r = run(); if (r.error) return r; return { data: r.data[0] || null, error: null }; });
    b.then = (res, rej) => Promise.resolve().then(run).then(res, rej);
    return b;
  }
  return { t, log, client: { from }, writes: () => log.filter(q => q.op !== "select") };
}

/* ── a fake app: records each route's handlers; call() runs them in order ── */
function fakeApp() {
  const reg = {};
  const app = {};
  ["get", "put", "post", "patch", "delete"].forEach(m => { app[m] = function (p) { reg[m.toUpperCase() + " " + p] = [].slice.call(arguments, 1).flat(); }; });
  async function call(key, req) {
    const fns = reg[key];
    if (!fns) return { status: 0, missing: true };
    const r = Object.assign({ params: {}, query: {}, body: {}, headers: {} }, req);
    const res = { statusCode: 200, body: undefined, text: undefined, headers: {},
      status(c) { this.statusCode = c; return this; }, json(b) { this.body = JSON.parse(JSON.stringify(b)); return this; },
      send(x) { this.text = String(x); return this; }, set(k, v) { this.headers[k] = v; return this; }, type(v) { this.headers["Content-Type"] = v; return this; } };
    let err = null;
    for (const fn of fns) {
      let went = false;
      await fn(r, res, e => { if (e) err = e; else went = true; });
      if (err || !went) break;
    }
    return { status: err ? 500 : res.statusCode, body: res.body, text: res.text, headers: res.headers, err };
  }
  return { app, reg, call };
}

const uid = n => "00000000-0000-4000-8000-" + String(n).padStart(12, "0");
const ANA = uid(1), FRED = uid(2), SUS = uid(3), OFF = uid(4), HID = uid(5), GONE = uid(6), EVE = uid(7), BARE = uid(8);
const L1 = uid(101), L2 = uid(102), L3 = uid(103), L4 = uid(104), L5 = uid(105), L6 = uid(106), L7 = uid(107);
const PHOTO = "https://cdn.example.com/a/garden.jpg";
const EVIL = "Eve \"</script><script>alert(1)</script> <img src=x onerror=alert(2)> & 'q' \u2028end";
function seed() {
  const prof = (id, u, extra) => Object.assign({ user_id: id, username: u, display_name: null, bio: null, avatar_url: null, banner_url: null, place_city: null, place_region: null, place_country: null, show_products: true, updated_at: "2026-11-20T10:00:00Z" }, extra || {});
  return {
    users: [ANA, FRED, SUS, OFF, HID, EVE, BARE].map(id => ({ id, banned_at: id === SUS ? "2026-11-01T00:00:00Z" : null, role: "user" })).concat([{ id: GONE, banned_at: null, role: "deleted" }]),
    bf_profiles: [
      prof(ANA, "ana", { display_name: "Ana Rivera", bio: "Garden design and care in Austin.", avatar_url: "https://cdn.example.com/a/ana.jpg", place_city: "Austin", place_region: "TX", place_country: "US" }),
      prof(FRED, "fred", { display_name: "Fred", bio: "Free account.", place_city: "Reno" }),
      prof(SUS, "sus", { display_name: "Sus" }), prof(OFF, "offie", { display_name: "Off", bio: "Switch off." }), prof(HID, "hidy", { display_name: "Hid" }),
      prof(GONE, "gone", { display_name: "Gone" }),
      prof(EVE, "eve_x", { display_name: EVIL, bio: EVIL, avatar_url: "javascript:alert(1)", banner_url: "https://cdn.example.com/b\"><script>.jpg" }),
      prof(BARE, "bare", { display_name: "Bare Person", bio: "Writes code online.", place_city: null })
    ],
    business_profiles: [{ user_id: FRED, business_name: "Fred's Fixes" }],
    marketplace_listings: [
      { id: L1, slug: "garden-design", title: "Garden design", description: "A plan for your garden, drawn by hand.", category: null, category_slug: "services", price_usd: null, price_bfc: 500, media: [{ url: PHOTO }], status: "active", seller_id: ANA, created_at: "2026-11-10T00:00:00Z", updated_at: "2026-11-21T00:00:00Z" },
      { id: L2, slug: "old-pots", title: "Old pots", description: "Paused.", category_slug: "services", price_usd: null, media: [{ url: PHOTO }], status: "paused", seller_id: ANA, created_at: "2026-11-09T00:00:00Z", updated_at: "2026-11-21T00:00:00Z" },
      { id: L3, slug: "hidden-thing", title: "Hidden thing", description: "Moderated.", category_slug: "services", price_usd: null, media: [{ url: PHOTO }], status: "active", seller_id: ANA, created_at: "2026-11-08T00:00:00Z", updated_at: "2026-11-21T00:00:00Z" },
      { id: L4, slug: "fred-fix", title: "Fred fixes", description: "Free seller.", category_slug: "services", price_usd: null, media: [], status: "active", seller_id: FRED, created_at: "2026-11-07T00:00:00Z", updated_at: "2026-11-21T00:00:00Z" },
      { id: L5, slug: "off-item", title: "Off item", description: "Switch off.", category_slug: "services", price_usd: null, media: [], status: "active", seller_id: OFF, created_at: "2026-11-06T00:00:00Z", updated_at: "2026-11-21T00:00:00Z" },
      { id: L6, slug: "lawn-plan", title: "Lawn plan", description: "", category_slug: null, category: "Gardening", price_usd: 25, price_bfc: 900, media: [{ url: PHOTO }], status: "active", seller_id: ANA, created_at: "2026-11-05T00:00:00Z", updated_at: "2026-11-21T00:00:00Z" },
      { id: L7, slug: "eve-thing", title: EVIL, description: EVIL, category_slug: "services", price_usd: null, media: [{ url: "https://cdn.example.com/e.jpg" }], status: "active", seller_id: EVE, created_at: "2026-11-05T00:00:00Z", updated_at: "2026-11-21T00:00:00Z" }
    ],
    categories: [{ slug: "services", name: "Services", parent_group: null, sort_order: 1, active: true }],
    user_preferences: [{ user_id: OFF, show_in_google: false }],
    member_social_connections: [{ user_id: ANA, platform: "bluesky", handle: "ana.bsky.social", status: "connected" }],
    threads_connections: [], member_youtube_connections: [{ user_id: ANA, channel_id: "UC" + "a".repeat(22), status: "connected" }],
    member_tiktok_connections: [], member_instagram_connections: [], member_facebook_pages: [],
    posts: [], lead_fingerprints: [], indexnow_sent: []
  };
}
const TIER = { [ANA]: "member", [FRED]: "free", [SUS]: "member", [OFF]: "member", [HID]: "member", [GONE]: "member", [EVE]: "member", [BARE]: "member" };
const HIDDEN = { profile: new Set([HID]), listing: new Set([L3]), post: new Set() };

const PP = T.libRequire("./lib/publicPages"), GF = T.libRequire("./lib/getFoundRoutes"), IX = T.libRequire("./lib/indexNow"), FS = T.libRequire("./lib/foundScore");

function mount(db, extra) {
  const A = fakeApp();
  const deps = Object.assign({
    sb: db.client,
    requireAuth: (req, res, next) => { if (!req.user) return res.status(401).json({ error: "Sign in" }); next(); },
    requireActiveSubscription: (req, res, next) => { if (TIER[req.user.id] !== "member") return res.status(402).json({ error: "members only", code: "members_only" }); next(); },
    tierOf: async id => TIER[id] || "free",
    hiddenAmong: async (sb, kind, ids) => new Set((ids || []).filter(id => HIDDEN[kind] && HIDDEN[kind].has(id))),
    env: {}, now: () => Date.parse("2026-11-25T12:00:00Z")
  }, extra || {});
  const api = GF.mountGetFoundRoutes(A.app, deps);
  return Object.assign(A, { api, deps });
}
const metaOf = (html, attr, name) => { const m = new RegExp("<meta " + attr + "=\"" + name + "\" content=\"([^\"]*)\"/>").exec(html); return m ? m[1] : null; };
const robotsOf = html => metaOf(html, "name", "robots");
function ldOf(html) {
  const a = html.indexOf('<script type="application/ld+json">');
  if (a < 0) return null;
  const b = html.indexOf("</script>", a);
  try { return JSON.parse(html.slice(a + '<script type="application/ld+json">'.length, b)); } catch (e) { return { parseError: e.message }; }
}
const headOf = html => html.slice(html.indexOf("<head>"), html.indexOf("</head>") + 7);

(async function main() {
  /* ── A ── */
  console.log("\n== A. migration 206 ==");
  const mig = FILES[MIG] || "";
  const sql = mig.split("\n").filter(l => !/^\s*--/.test(l)).join("\n");
  check("A1. two parts, 206a then 206b; no BEGIN, COMMIT or DO block; no <= or >=",
    /PART 206a[\s\S]*PART 206b/.test(mig) && !/\bBEGIN\b|\bCOMMIT\b|\bDO\s*(\$\$|\$[a-z_]*\$)/i.test(sql) && !/<=|>=/.test(mig));
  check("A2. 206a: user_preferences.show_in_google boolean, nullable with no default (NULL is never chosen, which reads as on)",
    /ALTER TABLE public\.user_preferences ADD COLUMN IF NOT EXISTS show_in_google boolean;/.test(sql));
  check("A3. 206b: indexnow_sent (url text primary key, sent_on date not null), its named check dropped IF EXISTS first, RLS on, no policies, revoked from anon and authenticated",
    /CREATE TABLE IF NOT EXISTS public\.indexnow_sent \(\s*url\s+text PRIMARY KEY,\s*sent_on\s+date NOT NULL\s*\);/.test(sql) &&
    sql.indexOf("DROP CONSTRAINT IF EXISTS indexnow_sent_url_check") !== -1 && sql.indexOf("DROP CONSTRAINT IF EXISTS indexnow_sent_url_check") < sql.indexOf("ADD CONSTRAINT indexnow_sent_url_check") &&
    /ADD CONSTRAINT indexnow_sent_url_check\s+CHECK \(url LIKE 'https:\/\/bizforceai\.net\/%' AND length\(url\) < 501\)/.test(sql) &&
    /ALTER TABLE public\.indexnow_sent ENABLE ROW LEVEL SECURITY;/.test(sql) && !/CREATE POLICY/i.test(sql) &&
    /REVOKE ALL ON public\.indexnow_sent FROM anon, authenticated;/.test(sql));

  /* ── B ── */
  console.log("\n== B. the robots rule ==");
  const base = { member: true, pagePublic: true, suspended: false, profileHidden: false, switchOn: true };
  const R = f => PP.robotsFor(Object.assign({}, base, f));
  check("B1. a member, public, not suspended or hidden, switch on: \"index, follow\"", R({}) === "index, follow" && PP.INDEX === "index, follow" && PP.NOINDEX === "noindex");
  check("B2. a free account: noindex", R({ member: false }) === "noindex");
  check("B3. a page not public: noindex", R({ pagePublic: false }) === "noindex");
  check("B4. suspended: noindex", R({ suspended: true }) === "noindex");
  check("B5. moderated hidden: noindex", R({ profileHidden: true }) === "noindex");
  check("B6. the switch off: noindex", R({ switchOn: false }) === "noindex");
  check("B7. a listing: active and shown is indexed; paused, hidden or missing is noindex",
    R({ listing: { active: true, hidden: false } }) === "index, follow" && R({ listing: { active: false, hidden: false } }) === "noindex" &&
    R({ listing: { active: true, hidden: true } }) === "noindex" && R({ listing: null }) === "noindex" && R({ member: false, listing: { active: true, hidden: false } }) === "noindex");
  check("B8. the switch's value: NULL (never chosen) and true are on, false is off", PP.switchOn(null) === true && PP.switchOn(undefined) === true && PP.switchOn(true) === true && PP.switchOn(false) === false);
  {
    const m = mount(memDb(seed()));
    const page = async h => m.call("GET /@:handle", { params: { handle: h } });
    const ana = await page("ana"), fred = await page("fred"), off = await page("offie"), sus = await page("sus"), hid = await page("hidy"), gone = await page("gone"), none = await page("nobody");
    check("B9. /@ana (member): 200, index; /@fred (free): 200, noindex; /@offie (switch off): 200, noindex",
      ana.status === 200 && robotsOf(ana.text) === "index, follow" && fred.status === 200 && robotsOf(fred.text) === "noindex" && off.status === 200 && robotsOf(off.text) === "noindex",
      J([ana.status, robotsOf(ana.text), fred.status, robotsOf(fred.text), off.status, robotsOf(off.text)]));
    check("B10. suspended, moderated hidden, deleted or unknown: 404 with a noindex head",
      [sus, hid, gone, none].every(x => x.status === 404 && robotsOf(x.text) === "noindex" && !ldOf(x.text)), J([sus, hid, gone, none].map(x => [x.status, robotsOf(x.text)])));
    const lp = async k => m.call("GET /listing/:id", { params: { id: k } });
    const l1 = await lp("garden-design"), l1id = await lp(L1), l2 = await lp("old-pots"), l3 = await lp("hidden-thing"), l4 = await lp("fred-fix"), l5 = await lp("off-item");
    check("B11. listings: Ana's active one by slug or id is index; paused 404 noindex; hidden 404 noindex; a free seller's and a switched-off seller's are 200 noindex",
      l1.status === 200 && robotsOf(l1.text) === "index, follow" && l1id.status === 200 && robotsOf(l1id.text) === "index, follow" &&
      l2.status === 404 && robotsOf(l2.text) === "noindex" && l3.status === 404 && robotsOf(l3.text) === "noindex" &&
      l4.status === 200 && robotsOf(l4.text) === "noindex" && l5.status === 200 && robotsOf(l5.text) === "noindex",
      J([l1, l1id, l2, l3, l4, l5].map(x => [x.status, robotsOf(x.text)])));
  }

  /* ── C ── */
  console.log("\n== C. the heads and the JSON-LD ==");
  {
    const m = mount(memDb(seed()));
    const ana = (await m.call("GET /@:handle", { params: { handle: "ana" } })).text;
    const ld = ldOf(ana) || {};
    check("C1. the profile: title \"Ana Rivera (@ana) on BizForce\", the bio as description, canonical https://bizforceai.net/@ana, og and twitter with the avatar",
      /<title>Ana Rivera \(@ana\) on BizForce<\/title>/.test(ana) && metaOf(ana, "name", "description") === "Garden design and care in Austin." &&
      ana.indexOf('<link rel="canonical" href="https://bizforceai.net/@ana"/>') !== -1 && metaOf(ana, "property", "og:url") === "https://bizforceai.net/@ana" &&
      metaOf(ana, "property", "og:image") === "https://cdn.example.com/a/ana.jpg" && metaOf(ana, "name", "twitter:image") === "https://cdn.example.com/a/ana.jpg" &&
      metaOf(ana, "name", "twitter:card") === "summary_large_image" && metaOf(ana, "property", "og:type") === "profile", headOf(ana).slice(0, 600));
    check("C2. a member with a place and listings is LocalBusiness: name, url, image, PostalAddress (Austin, TX, US), sameAs the connected Bluesky and YouTube",
      ld["@type"] === "LocalBusiness" && ld.name === "Ana Rivera" && ld.url === "https://bizforceai.net/@ana" && ld.image === "https://cdn.example.com/a/ana.jpg" &&
      J(ld.address) === J({ "@type": "PostalAddress", addressLocality: "Austin", addressRegion: "TX", addressCountry: "US" }) &&
      J(ld.sameAs) === J(["https://bsky.app/profile/ana.bsky.social", "https://www.youtube.com/channel/UC" + "a".repeat(22)]), J(ld));
    const bare = (await m.call("GET /@:handle", { params: { handle: "bare" } })).text, fred = (await m.call("GET /@:handle", { params: { handle: "fred" } })).text;
    check("C3. no place, or a place and no listings: Person; no image line for the default; the description falls back to the business name and city",
      (ldOf(bare) || {})["@type"] === "Person" && !("address" in (ldOf(bare) || {})) && !("image" in (ldOf(bare) || {})) &&
      (ldOf(fred) || {})["@type"] === "LocalBusiness" &&
      PP.profileDescription({ username: "x", place_city: "Reno" }, { business_name: "Fred's Fixes" }) === "Fred's Fixes in Reno, on BizForce." &&
      PP.profileStructuredData({ username: "x", display_name: "X", place_city: "Reno" }, "d", [], 0)["@type"] === "Person", J([ldOf(bare), ldOf(fred)]));
    check("C4. the noscript summary: the name, the bio and up to " + PP.NOSCRIPT_LISTINGS + " listings with links, just after <body>",
      /<body>\n<noscript>\n<div class="bf-noscript">\n<h1>Ana Rivera \(@ana\)<\/h1>\n<p>Garden design and care in Austin\.<\/p>/.test(ana) &&
      ana.indexOf('<li><a href="https://bizforceai.net/listing/garden-design">Garden design</a>: A plan for your garden, drawn by hand.</li>') !== -1 &&
      ana.indexOf("hidden-thing") === -1 && ana.indexOf("old-pots") === -1 &&
      (PP.noscriptProfile({ username: "z", display_name: "Z" }, "d", Array.from({ length: 14 }, (x, i) => ({ id: uid(900 + i), title: "T" + i }))).match(/<li>/g) || []).length === 10);
    const l1 = (await m.call("GET /listing/:id", { params: { id: "garden-design" } })).text, lld = ldOf(l1) || {};
    check("C5. the listing: title \"Garden design by Ana Rivera | BizForce\", its description, canonical, og:image the first photo, og:type product",
      /<title>Garden design by Ana Rivera \| BizForce<\/title>/.test(l1) && metaOf(l1, "name", "description") === "A plan for your garden, drawn by hand." &&
      l1.indexOf('<link rel="canonical" href="https://bizforceai.net/listing/garden-design"/>') !== -1 && metaOf(l1, "property", "og:image") === PHOTO && metaOf(l1, "property", "og:type") === "product");
    check("C6. Product: name, description, image, category (the category's name), the seller as brand; NO offers, and BizCash never appears",
      lld["@type"] === "Product" && lld.name === "Garden design" && lld.image === PHOTO && lld.category === "Services" && J(lld.brand) === J({ "@type": "Brand", name: "Ana Rivera" }) &&
      !("offers" in lld) && !/BFC|BizCash|500/.test(J(lld)), J(lld));
    const usd = PP.listingStructuredData({ id: L6, slug: "lawn-plan", title: "Lawn plan", price_usd: 25, price_bfc: 900, status: "active", media: [] }, { username: "ana", display_name: "Ana Rivera" }, "d", null);
    const paused = PP.listingStructuredData({ id: L6, slug: "lawn-plan", title: "Lawn plan", price_usd: 25, status: "paused", media: [] }, { username: "ana" }, "d", null);
    // NAMED (Nov 25 2026, LR-4B): BEFORE C7 expected an Offer from price_usd 25; AFTER an old price_usd gives no Offer (the live
    // proof found price_usd 7500 on a listing from before BizCash only), and neither does the BizCash price
    check("C7. an old USD price (price_usd 25, from before BizCash only) gives no offers, active or paused; never the BizCash price",
      !("offers" in usd) && !("offers" in paused) && J(usd).indexOf("900") === -1 && J(usd).indexOf("\"25\"") === -1, J(usd));
    check("C8. no offers for any price: BizCash only, zero, fractional, negative, text, null, or 7500",
      [{ price_bfc: 500 }, { price_usd: 0 }, { price_usd: 9.5 }, { price_usd: -3 }, { price_usd: "25" }, { price_usd: null }, { price_usd: 7500, price_bfc: 7500 }].every(x =>
        !("offers" in PP.listingStructuredData(Object.assign({ id: L1, title: "t", status: "active", media: [] }, x), { username: "ana" }, "d", null))));
  }

  /* ── D ── */
  console.log("\n== D. escaping ==");
  {
    const m = mount(memDb(seed()));
    const eve = (await m.call("GET /@:handle", { params: { handle: "eve_x" } })).text, ld = ldOf(eve) || {};
    const head = headOf(eve);
    check("D1. the JSON-LD is one script that parses back to the member's own words: no </script, no raw <, > or &, U+2028 escaped",
      ld.name === PP.clean(EVIL) && ld.description === PP.clean(EVIL) && (head.match(/<script type="application\/ld\+json">[^\n]*<\/script>/g) || []).length === 1 &&
      !/<\/script|<script>alert/.test((head.match(/<script type="application\/ld\+json">([^\n]*)<\/script>/) || [, ""])[1]) &&
      PP.jsonLd({ a: "</script>&<!--\u2028\u2029" }) === "{\"a\":\"\\u003c/script\\u003e\\u0026\\u003c!--\\u2028\\u2029\"}", J(ld).slice(0, 300));
    check("D2. the title, every meta and the noscript are escaped: no tag the member typed reaches the page",
      eve.indexOf("<script>alert(1)") === -1 && eve.indexOf("<img src=x") === -1 && /<title>Eve &quot;&lt;\/script&gt;/.test(eve) &&
      (metaOf(eve, "name", "description") || "").indexOf("&lt;img src=x") !== -1 && eve.indexOf("<h1>Eve &quot;&lt;/script&gt;") !== -1);
    check("D3. an image must be a plain https address: javascript: and a quote-breaking banner fall back to the site's icon",
      metaOf(eve, "property", "og:image") === PP.DEFAULT_IMAGE && !("image" in ld) && PP.httpsUrl("https://a.b/c\">") === null && PP.httpsUrl("http://a.b/c") === null);
    const l7 = (await m.call("GET /listing/:id", { params: { id: "eve-thing" } })).text, l7ld = ldOf(l7) || {};
    check("D4. a listing's title and description: escaped in the title, the metas and the noscript; whole in the JSON-LD",
      l7ld.name === PP.clean(EVIL) && l7.indexOf("<script>alert(1)") === -1 && l7.indexOf("<img src=x") === -1 && /<noscript>\n<div class="bf-noscript">\n<h1>Eve &quot;&lt;\/script&gt;/.test(l7));
    check("D5. a handle or listing key outside its shape is never read: 404, no query by it",
      PP.normalHandle("ana\"><script>") === null && PP.normalHandle("../etc") === null && PP.listingKey("<x>") === null && PP.normalHandle("Ana") === "ana");
  }

  /* ── E ── */
  console.log("\n== E. the pages ==");
  {
    const m = mount(memDb(seed(), { fail: (t) => t === "bf_profiles" }));
    const r = await m.call("GET /@:handle", { params: { handle: "ana" } });
    check("E1. a read that fails: 503, Retry-After, the noindex fallback head", r.status === 503 && r.headers["Retry-After"] === "60" && robotsOf(r.text) === "noindex", J([r.status, r.headers]));
    const m2 = mount(memDb(seed()));
    const ok = await m2.call("GET /@:handle", { params: { handle: "ana" } }), miss = await m2.call("GET /@:handle", { params: { handle: "nobody" } });
    check("E2. every page answers no-cache (and the frontend's security headers), and a missing page is 404", ok.headers["Cache-Control"] === "no-cache" && miss.status === 404 &&
      Object.keys(PP.pageHeaders()).length > 2, J(ok.headers));
    const seed2 = seed(); seed2.bf_profiles.find(p => p.user_id === ANA).show_products = false;
    const m3 = mount(memDb(seed2));
    const np = (await m3.call("GET /@:handle", { params: { handle: "ana" } })).text;
    check("E3. a member who hides their products: no listings in the noscript, and Person", np.indexOf("<h2>Listings</h2>") === -1 && (ldOf(np) || {})["@type"] === "Person");
    let shellOk = false, out = "";
    try { out = cp.execFileSync(process.execPath, [path.join(__dirname, "buildPublicShells.js"), "--check"], { encoding: "utf8", timeout: 60000 }); shellOk = true; } catch (e) { out = String(e.stdout || e.message); }
    check("E4. the shells are the frontend's seller.html and listing.html as they are now (buildPublicShells --check)", shellOk, out.slice(0, 300));
    const sellerFile = require("fs").readFileSync(path.join(H.FRONTEND, "seller.html"), "utf8").replace(/\r\n/g, "\n");
    const bodyOf = h => h.slice(h.indexOf("</head>"));
    const served = ok.text;
    check("E5. the page in the browser is the same page: the body after the noscript is seller.html's own, byte for byte",
      bodyOf(served).replace(/<body>\n<noscript>[\s\S]*?<\/noscript>\n/, "<body>\n") === bodyOf(sellerFile));
  }

  /* ── F ── */
  console.log("\n== F. the sitemaps ==");
  {
    let clock = Date.parse("2026-11-25T12:00:00Z");
    const db = memDb(seed());
    const m = mount(db, { now: () => clock });
    const locs = x => [...String(x.text).matchAll(/<loc>([^<]+)<\/loc>/g)].map(a => a[1]);
    const p1 = await m.call("GET /api/sitemap/profiles.xml"), l1 = await m.call("GET /api/sitemap/listings.xml");
    check("F1. profiles.xml lists only indexable profiles: ana, eve_x and bare (not the free, suspended, hidden, deleted or switched-off ones)",
      J(locs(p1).sort()) === J(["https://bizforceai.net/@ana", "https://bizforceai.net/@bare", "https://bizforceai.net/@eve_x"]) && p1.headers["Content-Type"] === "application/xml; charset=utf-8", J(locs(p1)));
    check("F2. listings.xml lists only indexable listings: active, shown, from an indexable member (never paused, hidden, free or switched off)",
      J(locs(l1).sort()) === J(["https://bizforceai.net/listing/eve-thing", "https://bizforceai.net/listing/garden-design", "https://bizforceai.net/listing/lawn-plan"]), J(locs(l1)));
    db.t.bf_profiles.push({ user_id: uid(50), username: "newbie", updated_at: "2026-11-25T00:00:00Z" }); TIER[uid(50)] = "member"; db.t.users.push({ id: uid(50), banned_at: null, role: "user" });
    const p2 = await m.call("GET /api/sitemap/profiles.xml");
    clock += 11 * 60 * 1000;
    const p3 = await m.call("GET /api/sitemap/profiles.xml");
    check("F3. cached 10 minutes, then built again", locs(p2).indexOf("https://bizforceai.net/@newbie") === -1 && locs(p3).indexOf("https://bizforceai.net/@newbie") !== -1);
    const put = await m.call("PUT /api/me/google", { user: { id: ANA }, body: { show_in_google: false } });
    const p4 = await m.call("GET /api/sitemap/profiles.xml"), l4 = await m.call("GET /api/sitemap/listings.xml");
    const page = await m.call("GET /@:handle", { params: { handle: "ana" } });
    check("F4. the switch off takes the profile and listings out of both sitemaps at once (inside the 10 minutes) and makes the page noindex",
      put.status === 200 && locs(p4).indexOf("https://bizforceai.net/@ana") === -1 && locs(l4).every(u => u.indexOf("garden-design") === -1 && u.indexOf("lawn-plan") === -1) && robotsOf(page.text) === "noindex");
    check("F5. the sitemap: XML-escaped, at most " + PP.SITEMAP_MAX + " addresses, lastmod a day",
      PP.sitemapXml([{ loc: "https://bizforceai.net/@a&b", lastmod: "2026-11-20T10:00:00Z" }]).indexOf("<loc>https://bizforceai.net/@a&amp;b</loc><lastmod>2026-11-20</lastmod>") !== -1 &&
      (PP.sitemapXml(Array.from({ length: PP.SITEMAP_MAX + 3 }, (x, i) => ({ loc: "https://bizforceai.net/@u" + i }))).match(/<url>/g) || []).length === PP.SITEMAP_MAX);
    const bad = mount(memDb(seed(), { fail: t => t === "marketplace_listings" }));
    const b = await bad.call("GET /api/sitemap/listings.xml");
    check("F6. a sitemap that cannot be built: 503 with Retry-After, never a partial list", b.status === 503 && b.headers["Retry-After"] === "600" && !/<loc>/.test(b.text || ""));
  }

  /* ── G ── */
  console.log("\n== G. IndexNow ==");
  {
    const KEY = "0123456789abcdef0123456789abcdef";
    function harness(env, dbo) {
      const db = memDb({ indexnow_sent: [] }, dbo);
      const timers = [], sent = [];
      let day = "2026-11-25T12:00:00Z";
      const q = IX.createQueue({ sb: db.client, env, now: () => Date.parse(day), log: () => {},
        fetch: async (u, o) => { sent.push({ u, o: JSON.parse(o.body) }); return { status: 202 }; },
        setTimeout: (fn, ms) => { const t = { fn, ms, unrefd: false, unref() { this.unrefd = true; } }; timers.push(t); return t; }, clearTimeout: () => {} });
      return { db, q, timers, sent, setDay: d => { day = d; } };
    }
    const off = harness({});
    const offQ = off.q.queue(["https://bizforceai.net/@ana"]);
    await off.q.flush();
    check("G1. off by default: with no ENABLE_INDEXNOW nothing is queued, no timer, nothing sent or stored; \"1\" or a missing key is still off",
      offQ === false && off.timers.length === 0 && off.sent.length === 0 && off.db.writes().length === 0 &&
      IX.enabled({ ENABLE_INDEXNOW: "1", INDEXNOW_KEY: KEY }) === false && IX.enabled({ ENABLE_INDEXNOW: "true" }) === false && IX.enabled({ ENABLE_INDEXNOW: "true", INDEXNOW_KEY: "short" }) === false &&
      IX.enabled({ ENABLE_INDEXNOW: "true", INDEXNOW_KEY: KEY }) === true);
    const on = harness({ ENABLE_INDEXNOW: "true", INDEXNOW_KEY: KEY });
    const r1 = on.q.queue(["https://bizforceai.net/@ana", "https://bizforceai.net/listing/garden-design"]);
    const r2 = on.q.queue("https://bizforceai.net/@ana");
    on.q.queue(["https://evil.example/@x", "http://bizforceai.net/@ana", "javascript:alert(1)"]);
    check("G2. queue() returns at once (a boolean, not a promise), starts ONE timer of " + IX.DELAY_MS + " ms that does not hold the process open, and keeps only bizforceai.net https addresses",
      r1 === true && typeof r2 === "boolean" && on.timers.length === 1 && on.timers[0].ms === 60000 && on.timers[0].unrefd === true &&
      J(on.q.pending().sort()) === J(["https://bizforceai.net/@ana", "https://bizforceai.net/listing/garden-design"]), J([on.timers.length, on.q.pending()]));
    on.timers[0].fn(); await on.q.flush();
    check("G3. the tick sends ONE batched POST to api.indexnow.org with host, key, keyLocation (the root key file) and the addresses",
      on.sent.length === 1 && on.sent[0].u === "https://api.indexnow.org/indexnow" &&
      J(on.sent[0].o) === J({ host: "bizforceai.net", key: KEY, keyLocation: "https://bizforceai.net/indexnow-key.txt", urlList: ["https://bizforceai.net/@ana", "https://bizforceai.net/listing/garden-design"] }), J(on.sent));
    check("G4. each address is written as sent today before the request", on.db.t.indexnow_sent.length === 2 && on.db.t.indexnow_sent.every(r => r.sent_on === "2026-11-25") &&
      on.db.log.findIndex(q => q.op === "upsert") !== -1);
    on.q.queue(["https://bizforceai.net/@ana", "https://bizforceai.net/@bare"]); await on.q.flush();
    check("G5. at most once per address per day: the same day, only the new address is sent", on.sent.length === 2 && J(on.sent[1].o.urlList) === J(["https://bizforceai.net/@bare"]), J(on.sent.map(s => s.o.urlList)));
    on.setDay("2026-11-26T09:00:00Z"); on.q.queue(["https://bizforceai.net/@ana"]); await on.q.flush();
    check("G6. the next day it may be sent again", on.sent.length === 3 && J(on.sent[2].o.urlList) === J(["https://bizforceai.net/@ana"]));
    const markFail = harness({ ENABLE_INDEXNOW: "true", INDEXNOW_KEY: KEY }, { fail: (t, op) => t === "indexnow_sent" && op === "upsert" });
    markFail.q.queue(["https://bizforceai.net/@ana"]); const mf = await markFail.q.flush();
    check("G7. a failed write sends nothing (so no address can go twice in a day)", markFail.sent.length === 0 && mf.sent === 0);
    const boom = harness({ ENABLE_INDEXNOW: "true", INDEXNOW_KEY: KEY });
    boom.q.queue(["https://bizforceai.net/@ana"]);
    let threw = false;
    const bq = IX.createQueue({ sb: boom.db.client, env: { ENABLE_INDEXNOW: "true", INDEXNOW_KEY: KEY }, now: () => Date.parse("2026-11-25T12:00:00Z"), log: () => {}, setTimeout: () => ({ unref() {} }), clearTimeout: () => {},
      fetch: async () => { throw new Error("network down"); } });
    bq.queue(["https://bizforceai.net/@ana"]);
    try { const r = await bq.flush(); threw = !r || r.sent !== 0; } catch (e) { threw = true; }
    check("G8. a failing send never throws (the tick answers sent 0)", threw === false);
    const m = mount(memDb(seed()), { env: {} }), m2 = mount(memDb(seed()), { env: { ENABLE_INDEXNOW: "true", INDEXNOW_KEY: KEY } });
    const k1 = await m.call("GET /api/indexnow/key.txt"), k2 = await m2.call("GET /api/indexnow/key.txt");
    check("G9. the key file: 404 while IndexNow is off; the key as plain text while it is on", k1.status === 404 && k2.status === 200 && k2.text === KEY, J([k1.status, k2.status]));
    // the server's middleware, run in a sandbox: next() first, the queue only after a 2xx answer has finished, nothing while off
    const srv = FILES[SERVER] || "";
    const a = srv.indexOf("var INDEXNOW_TRIGGERS = ["), z = srv.indexOf("\n});\n", a);
    const block = a !== -1 && z !== -1 ? srv.slice(a, z + 4) : "";
    function runMw(enabled, method, p, status) {
      const events = [], calls = [];
      let mw = null;
      const ctx = { app: { use: f => { mw = f; } }, require: n => n === "./lib/indexNow" ? { enabled: () => enabled } : require(n), indexNowAfterSave: (u, id) => calls.push([u, id]), process: { env: {} } };
      try { vm.runInNewContext(block, ctx); } catch (e) { return { error: e.message }; }
      const handlers = {};
      const req = { method, path: p, user: { id: ANA } };
      const res = { statusCode: status, json(b) { return b; }, on(ev, f) { handlers[ev] = f; } };
      let nexted = false;
      if (!mw) return { error: "no middleware" };
      mw(req, res, () => { nexted = true; events.push("next"); });
      const queuedBeforeFinish = calls.length;
      if (method === "POST" && p === "/api/posts") res.json({ post: { id: uid(300) } });
      if (handlers.finish) { events.push("finish"); handlers.finish(); }
      return { nexted, events, calls, queuedBeforeFinish, listened: !!handlers.finish };
    }
    const g1 = runMw(true, "PUT", "/api/profile/me", 200), g2 = runMw(true, "PUT", "/api/profile/me", 400), g3 = runMw(false, "PUT", "/api/profile/me", 200),
      g4 = runMw(true, "POST", "/api/posts", 201), g5 = runMw(true, "PATCH", "/api/posts/" + uid(301), 200), g6 = runMw(true, "GET", "/api/profile/me", 200);
    check("G10. never blocking a save: the middleware calls next() at once, and queues only after a 2xx answer has finished; never after an error, never while off, never for a read",
      g1.nexted && g1.events[0] === "next" && g1.queuedBeforeFinish === 0 && g1.calls.length === 1 && g2.calls.length === 0 && g2.nexted &&
      g3.nexted && !g3.listened && g3.calls.length === 0 && g6.nexted && !g6.listened, J([g1, g2, g3, g6]));
    check("G11. a post's address: the new post's id from the answer, or the edited post's id from the address",
      J(g4.calls) === J([[ANA, uid(300)]]) && J(g5.calls) === J([[ANA, uid(301)]]), J([g4.calls, g5.calls]));
    check("G12. after a save, the member's indexable addresses only (indexableUrls), and the post only when lib/posts.js indexablePost says so; never awaited by the save",
      /function indexNowAfterSave\(userId, postId\) \{\n  if \(!require\("\.\/lib\/indexNow"\)\.enabled\(process\.env\)\) return;\n  \(async function \(\) \{/.test(srv) &&
      srv.indexOf("var urls = await getFoundApi.indexableUrls(userId);") !== -1 && srv.indexOf("await require(\"./lib/posts\").indexablePost(postDeps(), row.data)) urls.push(") !== -1 &&
      /\}\)\(\)\.catch\(function \(e\) \{ console\.warn\("\[indexnow\] after save: "/.test(srv));
    const db = memDb(seed());
    const mu = mount(db);
    check("G13. indexableUrls: Ana's profile and her two shown active listings; nothing for a free, suspended or switched-off member",
      J((await mu.api.indexableUrls(ANA)).sort()) === J(["https://bizforceai.net/@ana", "https://bizforceai.net/listing/garden-design", "https://bizforceai.net/listing/lawn-plan"]) &&
      (await mu.api.indexableUrls(FRED)).length === 0 && (await mu.api.indexableUrls(SUS)).length === 0 && (await mu.api.indexableUrls(OFF)).length === 0);
  }

  /* ── H ── */
  console.log("\n== H. the Found score ==");
  {
    const all = {
      profile: { username: "ana", bio: "Garden design.", place_city: "Austin" }, profileIndexable: true, profileWhy: null,
      listings: [{ id: L1, title: "Garden design", description: "d", category_slug: "services", media: [{ url: PHOTO }], indexable: true }],
      posts: [{ id: uid(201), body: "a", search_visible: true }, { id: uid(202), body: "b", search_visible: true }],
      connections: { bluesky: true }, fingerprint: { categories: ["services"], place_city: "Austin", reach: "city", keywords: ["a", "b", "c", "d", "e"] }
    };
    const full = FS.compute(all);
    const byKey = (res, k) => res.items.find(x => x.key === k) || {};
    check("H1. every item done: 100, and the weights are 15, 20, 20, 15, 15 and 15",
      full.score === 100 && J(full.items.map(x => [x.key, x.weight, x.status])) === J([["basics", 15, "done"], ["profile", 20, "done"], ["listings", 20, "done"], ["posts", 15, "done"], ["connected", 15, "done"], ["fingerprint", 15, "done"]]), J(full.items.map(x => [x.key, x.weight, x.status])));
    check("H2. the board's words: \"Add your city and a short bio\", \"Your profile page on Google\" (bizforceai.net/@ana, a link to it), \"Your listings on Google\", \"Posts shown in Google\" (2 of 2), \"Bluesky connected\", \"Fingerprint complete\"",
      byKey(full, "basics").title === "Add your city and a short bio" && byKey(full, "profile").detail === "bizforceai.net/@ana with your name, city and work" && byKey(full, "profile").url === "/@ana" &&
      byKey(full, "listings").title === "Your listings on Google" && byKey(full, "posts").detail === "2 of 2 public posts" && byKey(full, "connected").title === "Bluesky connected" &&
      byKey(full, "connected").detail === "Your posts and approved replies go out from your account" && byKey(full, "fingerprint").title === "Fingerprint complete");
    const none = FS.compute({ profile: {}, listings: [], posts: [], connections: {}, fingerprint: null });
    check("H3. nothing done: 0, every item to do with its action (Add, Add, Add a listing, Post, Connect, Open Fingerprint)",
      none.score === 0 && none.items.every(x => x.status === "todo" && x.action) &&
      J(none.items.map(x => x.action.label)) === J(["Add", "Add", "Add a listing", "Post", "Connect", "Open Fingerprint"]) &&
      byKey(none, "basics").action.href === "/profile.html#edit-bio" && byKey(none, "listings").action.href === "/marketplace.html?create=product" &&
      byKey(none, "connected").action.href === "/agents/social.html" && byKey(none, "fingerprint").action.act === "fingerprint" && byKey(none, "posts").action.href === "/compose.html");
    const part = FS.compute(Object.assign({}, all, { profile: { username: "ana", bio: "x" }, posts: [{ id: uid(201), body: "a", search_visible: true }, { id: uid(202), body: "b", search_visible: false }, { id: uid(203), body: "c" }],
      connections: { bluesky: true, youtube: true, tiktok: true } }));
    check("H4. the gold to-do items first, then the done ones, then the waiting row; the score is the done weights (20 + 20 + 15 + 15 = 70)",
      part.score === 70 && J(part.items.map(x => x.status)) === J(["todo", "todo", "done", "done", "done", "done", "waiting"]) &&
      J(part.items.map(x => x.key)) === J(["basics", "posts", "profile", "listings", "connected", "fingerprint", "waiting"]), J(part.items.map(x => [x.key, x.status])));
    check("H5. a bio without a city: Add opens Settings, Local; posts: \"1 of 3 public posts. Turn on Show in Google for the other 2\", Fix (the in-page confirm), and the two posts to fix with their text",
      byKey(part, "basics").action.href === "/settings.html#local" &&
      byKey(FS.compute(Object.assign({}, all, { profile: { username: "ana", place_city: "Austin", bio: " " } })), "basics").status === "todo" &&
      byKey(FS.compute(Object.assign({}, all, { profile: { username: "ana", place_city: "Austin" } })), "basics").action.href === "/profile.html#edit-bio" && byKey(part, "posts").detail === "1 of 3 public posts. Turn on Show in Google for the other 2" &&
      byKey(part, "posts").action.act === "posts" && J(part.fix_posts) === J([{ id: uid(202), body: "b" }, { id: uid(203), body: "c" }]) &&
      FS.compute(Object.assign({}, all, { posts: [{ id: uid(1), search_visible: true }, { id: uid(2), search_visible: false }] })).items.find(x => x.key === "posts").detail.endsWith("for the last one"));
    check("H6. the waiting row: YouTube and TikTok \"Connected, waiting for each platform's approval\", grey, no weight; YouTube alone never counts as connected",
      J(byKey(part, "waiting")) === J({ key: "waiting", weight: 0, status: "waiting", title: "YouTube, TikTok", detail: "Connected, waiting for each platform's approval" }) &&
      byKey(FS.compute(Object.assign({}, all, { connections: { youtube: true, instagram: true, facebook: true } })), "connected").status === "todo" &&
      byKey(FS.compute(Object.assign({}, all, { connections: { threads: true } })), "connected").title === "Threads connected");
    const L = x => FS.compute(Object.assign({}, all, { listings: [Object.assign({ id: L1, title: "Garden design", description: "d", category_slug: "services", media: [{ url: PHOTO }], indexable: true }, x)] }));
    // NAMED (Nov 25 2026, LR-4B): BEFORE a USD price stood in for the description; AFTER it does not
    check("H7. a listing needs a photo, a category and a description (a USD price is no substitute): Fix names what is missing and opens that listing's edit",
      byKey(L({ media: [] }), "listings").detail === "“Garden design” needs a photo" && byKey(L({ media: [] }), "listings").action.href === "/marketplace.html?edit=" + L1 &&
      byKey(L({ category_slug: null }), "listings").detail === "“Garden design” needs a category" &&
      byKey(L({ description: "" }), "listings").detail === "“Garden design” needs a description" && byKey(L({ description: "", price_usd: 40 }), "listings").detail === "“Garden design” needs a description" &&
      byKey(L({ description: "", media: [], category_slug: null }), "listings").detail === "“Garden design” needs a photo, a category and a description");
    check("H8. the profile: done only while indexable; the switch off says so and opens Settings, Privacy; no handle asks for one",
      byKey(FS.compute(Object.assign({}, all, { profileIndexable: false, profileWhy: "switch_off" })), "profile").action.href === "/settings.html#privacy" &&
      byKey(FS.compute(Object.assign({}, all, { profileIndexable: false, profileWhy: "switch_off" })), "profile").status === "todo" &&
      byKey(FS.compute(Object.assign({}, all, { profile: { bio: "x", place_city: "y" } })), "profile").detail === "Choose a handle so your page has an address" &&
      byKey(FS.compute(Object.assign({}, all, { profileIndexable: false, profileWhy: "free" })), "profile").status === "todo" &&
      byKey(FS.compute(Object.assign({}, all, { profileIndexable: false, profileWhy: "suspended" })), "profile").status === "todo");
    const F = fp => byKey(FS.compute(Object.assign({}, all, { fingerprint: fp })), "fingerprint");
    check("H9. the Fingerprint: categories, a place or \"Online, anywhere\", and at least 5 words",
      F({ categories: ["a"], reach: "online", keywords: ["1", "2", "3", "4", "5"] }).status === "done" && F({ categories: [], reach: "online", keywords: ["1", "2", "3", "4", "5"] }).status === "todo" &&
      F({ categories: ["a"], reach: "city", place_city: null, keywords: ["1", "2", "3", "4", "5"] }).status === "todo" && F({ categories: ["a"], reach: "online", keywords: ["1", "2", "3", "4"] }).detail === "Add at least 5 words");
    // the route, over the database
    const s = seed();
    s.posts = [{ id: uid(201), author_id: ANA, body: "a", status: "published", audience: "public", search_visible: true, published_at: "2026-11-20" },
      { id: uid(202), author_id: ANA, body: "b", status: "published", audience: "public", search_visible: false, published_at: "2026-11-21" },
      { id: uid(203), author_id: ANA, body: "f", status: "published", audience: "followers", search_visible: false, published_at: "2026-11-22" }];
    s.lead_fingerprints = [{ user_id: ANA, categories: ["services"], reach: "city", place_city: "Austin", keywords: ["garden", "design", "lawn", "plants", "care"] }];
    const m = mount(memDb(s));
    const r = await m.call("GET /api/leads/found", { user: { id: ANA } });
    check("H10. GET /api/leads/found over the database: Ana 85 (posts 1 of 2 to do; the followers post never counts; the hidden listing never counts)",
      r.status === 200 && r.body.score === 85 && byKey(r.body, "posts").detail === "1 of 2 public posts. Turn on Show in Google for the last one" && byKey(r.body, "listings").status === "done" &&
      byKey(r.body, "waiting").title === "YouTube", J(r.body).slice(0, 500));
    const s2 = seed();
    s2.marketplace_listings = s2.marketplace_listings.filter(l => l.id !== L1 && l.id !== L6);   // only the hidden, complete L3 is left
    const r2 = await mount(memDb(s2)).call("GET /api/leads/found", { user: { id: ANA } });
    check("H11. a moderated hidden listing never counts, even when it is complete: \"Add a listing\"",
      r2.status === 200 && byKey(r2.body, "listings").status === "todo" && byKey(r2.body, "listings").action.label === "Add a listing", J(byKey(r2.body || { items: [] }, "listings")));
  }

  /* ── I ── */
  console.log("\n== I. the switch ==");
  {
    const db = memDb(seed());
    const m = mount(db);
    const g = await m.call("GET /api/me/google", { user: { id: ANA } });
    check("I1. GET: never chosen reads as on, with whether the page is indexable and its address",
      g.status === 200 && J(g.body) === J({ show_in_google: true, indexable: true, why: null, profile_url: "https://bizforceai.net/@ana" }), J(g.body));
    const bad = await Promise.all(["true", 1, null, undefined, "on"].map(v => m.call("PUT /api/me/google", { user: { id: ANA }, body: { show_in_google: v } })));
    check("I2. PUT takes a boolean only: \"true\", 1, null, missing or \"on\" is 400 and nothing is written", bad.every(x => x.status === 400) && db.writes().length === 0, J(bad.map(x => x.status)));
    const offR = await m.call("PUT /api/me/google", { user: { id: ANA }, body: { show_in_google: false } });
    const g2 = await m.call("GET /api/me/google", { user: { id: ANA } });
    const onR = await m.call("PUT /api/me/google", { user: { id: ANA }, body: { show_in_google: true } });
    check("I3. PUT false saves it (one user_preferences row, upserted on user_id), says so, and the page is noindex with why switch_off; PUT true turns it back on",
      offR.status === 200 && offR.body.saved === true && offR.body.message === GF.SWITCH_MESSAGES.saved_off && g2.body.show_in_google === false && g2.body.why === "switch_off" && g2.body.indexable === false &&
      onR.body.message === GF.SWITCH_MESSAGES.saved_on && db.t.user_preferences.filter(r => r.user_id === ANA).length === 1 && db.t.user_preferences.find(r => r.user_id === ANA).show_in_google === true);
    const dbm = memDb(seed(), { missingColumn: true });
    const mm = mount(dbm);
    const warn = console.warn; console.warn = () => {};
    const gm = await mm.call("GET /api/me/google", { user: { id: ANA } }), pm = await mm.call("GET /@:handle", { params: { handle: "ana" } });
    console.warn = warn;
    check("I4. before migration 206a (the column missing): the switch reads as on and the page is still served (index)", gm.status === 200 && gm.body.show_in_google === true && pm.status === 200 && robotsOf(pm.text) === "index, follow");
    const queued = [];
    const mi = mount(memDb(seed()), { env: { ENABLE_INDEXNOW: "true", INDEXNOW_KEY: "0123456789abcdef" }, indexNow: { queue: u => queued.push(u) } });
    await mi.call("PUT /api/me/google", { user: { id: ANA }, body: { show_in_google: true } });
    await new Promise(r => setTimeout(r, 20));
    check("I5. turning it on queues the member's addresses for IndexNow (when it is on); turning it off queues nothing", queued.length === 1 && queued[0].indexOf("https://bizforceai.net/@ana") !== -1);
    const st = FILES[SETTINGS] || "";
    check("I6. Settings, Privacy: \"Show my profile and listings in Google\", on by default (checked, and on unless the server says false), saved with PUT /api/me/google, put back on a failure",
      st.indexOf('<div class="toggle-title" id="googleTitle">Show my profile and listings in Google</div>') !== -1 && st.indexOf('<input type="checkbox" id="googleToggle" checked') !== -1 &&
      st.indexOf("googleToggle.checked = res.data.show_in_google !== false;") !== -1 && st.indexOf("body: JSON.stringify({ show_in_google: want })") !== -1 &&
      st.indexOf("if (!res.ok || res.data.saved !== true) { googleToggle.checked = !want;") !== -1 && st.indexOf('data-target="privacy"') !== -1);
  }

  /* ── J ── */
  console.log("\n== J. members only ==");
  {
    const m = mount(memDb(seed()));
    const f1 = await m.call("GET /api/leads/found", { user: { id: FRED } }), f2 = await m.call("GET /api/me/google", { user: { id: FRED } }), f3 = await m.call("PUT /api/me/google", { user: { id: FRED }, body: { show_in_google: true } });
    const so = await m.call("GET /api/leads/found", {});
    check("J1. a free account: 402 (the members panel) from all three member routes, and nothing written; signed out: 401",
      f1.status === 402 && f2.status === 402 && f3.status === 402 && so.status === 401, J([f1.status, f2.status, f3.status, so.status]));
    check("J2. the member routes use M (requireAuth then requireActiveSubscription), the public pages only the limiter",
      J(m.reg["GET /api/leads/found"].slice(0, 2).map(f => f.name || "fn")) === J(m.reg["PUT /api/me/google"].slice(0, 2).map(f => f.name || "fn")) &&
      m.reg["GET /api/leads/found"].length === 3 && m.reg["GET /api/me/google"].length === 3 && m.reg["PUT /api/me/google"].length === 3 && m.reg["GET /@:handle"].length === 1);
    const st = FILES[SETTINGS] || "";
    check("J3. Settings: a free account sees the members line, never the switch", st.indexOf("if (res.status === 402) { googleFree.hidden = false; return; }") !== -1 &&
      st.indexOf('<div class="toggle-row" id="googleRow" hidden>') !== -1);
    const lr = FILES[RADAR] || "";
    check("J4. Lead Radar's Get found: reads GET /api/leads/found; Fix for posts asks first, and only \"Turn on\" sends PATCH /api/posts/:id with the post's own text and search_visible true",
      lr.indexOf('call("GET", "/api/leads/found")') !== -1 && lr.indexOf('if (act === "posts") { GF.asking = true; drawFound();') !== -1 &&
      lr.indexOf('if (act === "posts-yes") { b.disabled = true; fixPosts(') !== -1 && lr.indexOf("{ body: p.body, search_visible: true }") !== -1 && lr.split("fixPosts(").length === 3);
  }

  /* ── K ── */
  console.log("\n== K. the lists and the words ==");
  {
    check("K1. Your data exports show_in_google, and backup and schemaCheck name indexnow_sent",
      (FILES[YD] || "").indexOf("updated_at, need_alerts, show_in_google\", onDelete") !== -1 && (FILES[YD] || "").indexOf("Whether your profile and listings may show in Google.") !== -1 &&
      /\n  indexnow_sent: +"/.test(FILES[BK] || "") && (FILES[SC] || "").indexOf('["indexnow_sent", "206_lr4_get_found.sql"]') !== -1);
    const priv = FILES[PRIV] || "";
    check("K2. the Privacy Policy: profiles and listings can appear in search engines while Show my profile and listings in Google is on, and how to turn it off (Settings, Privacy)",
      priv.indexOf("can appear in search engines such as Google while Show my profile and listings in Google is on") !== -1 && priv.indexOf("turn it off in Settings, Privacy") !== -1 &&
      priv.indexOf("IndexNow") !== -1);
    const rm = FILES[RM] || "";
    check("K3. README: ENABLE_INDEXNOW (off) and INDEXNOW_KEY, and how to set them", rm.indexOf("| `ENABLE_INDEXNOW` | off |") !== -1 && rm.indexOf("| `INDEXNOW_KEY` | none |") !== -1 && rm.indexOf("## Get found") !== -1);
    const red = FILES[REDIR] || "", lines = red.split("\n");
    const at = s2 => lines.findIndex(l => l.indexOf(s2) === 0);
    const catchAll = lines.findIndex(l => /^\/\*\s/.test(l));
    check("K4. _redirects: /@:handle and /listing/:id proxy to the backend, and the three sitemaps and the key file, all above every catch-all",
      at("/@:handle https://") !== -1 && at("/listing/:id https://") !== -1 && at("/sitemap-profiles.xml") !== -1 && at("/sitemap-listings.xml") !== -1 && at("/indexnow-key.txt") !== -1 &&
      [at("/@:handle https://"), at("/listing/:id https://"), at("/sitemap-profiles.xml"), at("/indexnow-key.txt")].every(i => catchAll === -1 || i < catchAll) &&
      /\/@:handle\s+https:\/\/[^\s]+\/@:handle\s+200/.test(red) && /\/indexnow-key\.txt\s+https:\/\/[^\s]+\/api\/indexnow\/key\.txt\s+200/.test(red), J([at("/@:handle https://"), catchAll]));
    check("K5. robots.txt allows /@ and /listing/ and names both sitemaps; sitemap.xml lists them",
      /\nAllow: \/@\n/.test(FILES[ROBOTS] || "") && /\nAllow: \/listing\/\n/.test(FILES[ROBOTS] || "") && (FILES[ROBOTS] || "").indexOf("Sitemap: https://bizforceai.net/sitemap-profiles.xml") !== -1 &&
      (FILES[SMAP] || "").indexOf("<loc>https://bizforceai.net/sitemap-profiles.xml</loc>") !== -1 && (FILES[SMAP] || "").indexOf("<loc>https://bizforceai.net/sitemap-listings.xml</loc>") !== -1);
  }

  finish();
})().catch(e => { check("the checks ran to the end without an error", false, (e && e.stack) || e); finish(); });
