"use strict";
/* ═════════════════════════════════════════════════════════════════════════════
   GET FOUND'S ROUTES (LR-4, Nov 25 2026). Mounted by server.js (mountGetFoundRoutes).

   Public (no sign-in; the page and sitemap limiter):
     GET  /@:handle                    a member's profile and storefront: seller.html with the head filled in
                                       (lib/publicPages.js); 404 when there is no such shown member
     GET  /listing/:id                 a listing by slug or id: listing.html with the head filled in; 404 when
                                       there is no such active, shown listing
     GET  /api/sitemap/profiles.xml    every indexable profile (lib/publicPages.js robotsFor), cached 10 minutes
     GET  /api/sitemap/listings.xml    every indexable listing, cached 10 minutes
     GET  /api/indexnow/key.txt        the IndexNow key, only while IndexNow is on (lib/indexNow.js); else 404
   Members only (M: requireActiveSubscription after requireAuth; a free account gets the members panel, 402):
     GET  /api/leads/found             the Found score and its checklist (lib/foundScore.js)
     GET  /api/me/google               the switch "Show my profile and listings in Google", and the profile's address
     PUT  /api/me/google               { show_in_google: true | false }: saved in user_preferences.show_in_google
                                       (migration 206a); the sitemaps are rebuilt on their next read at once

   deps: { sb, requireAuth, requireActiveSubscription, tierOf(userId) -> "member" | "free", hiddenAmong(sb, kind, ids),
     threadsState(userId) -> { state }, pageLimiter, env, indexNow (lib/indexNow.js createQueue), now() -> ms }
   ═════════════════════════════════════════════════════════════════════════════ */

const PP = require("./publicPages");
const FS = require("./foundScore");
const IX = require("./indexNow");
const CAT = require("./categories");

const SITEMAP_CACHE_MS = 10 * 60 * 1000;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SWITCH_MESSAGES = {
  type: "Show my profile and listings in Google is on or off.",
  saved_on: "Your profile and listings can show in Google.",
  saved_off: "Your profile and listings are out of Google. Search engines are told not to show them, and they are out of the sitemaps."
};

/* The switch's value: NULL (never chosen) reads as on. Before migration 206a is applied the column is missing, which
   also reads as never chosen (on), and says so in the log; any other read error throws. */
async function readSwitch(sb, userId) {
  const r = await sb.from("user_preferences").select("show_in_google").eq("user_id", userId).maybeSingle();
  if (r.error) {
    if (r.error.code === "42703" || /show_in_google/.test(String(r.error.message || ""))) { console.warn("[get found] user_preferences.show_in_google is missing (migration 206a); read as never chosen (on)."); return null; }
    throw r.error;
  }
  return r.data ? (r.data.show_in_google === true || r.data.show_in_google === false ? r.data.show_in_google : null) : null;
}

/* Every fact the robots rule reads, for one account. why: the first reason it is not indexable, or null. */
async function indexability(deps, userId) {
  const u = await deps.sb.from("users").select("id, banned_at, role").eq("id", userId).maybeSingle();
  if (u.error) throw u.error;
  const user = u.data || null;
  const facts = {
    member: (await deps.tierOf(userId)) === "member",
    pagePublic: !!user && user.role !== "deleted",
    suspended: !!(user && user.banned_at),
    profileHidden: (await deps.hiddenAmong(deps.sb, "profile", [userId])).has(userId),
    switchOn: PP.switchOn(await readSwitch(deps.sb, userId))
  };
  const why = !facts.pagePublic ? "not_public" : facts.suspended ? "suspended" : facts.profileHidden ? "hidden" : !facts.member ? "free" : !facts.switchOn ? "switch_off" : null;
  return Object.assign(facts, { indexable: PP.robotsFor(facts) === PP.INDEX, why: why });
}
function shown(idx) { return idx.pagePublic && !idx.suspended && !idx.profileHidden; }

/* The member's connected accounts: the public names a profile's sameAs uses, and true/false for the score. */
async function connections(deps, userId, soft) {
  const q = function (table, cols, extra) { let s = deps.sb.from(table).select(cols).eq("user_id", userId); if (extra) s = extra(s); return s.maybeSingle(); };
  const r = await Promise.all([
    q("member_social_connections", "handle, status", function (s) { return s.eq("platform", "bluesky"); }),
    q("threads_connections", "username, status, access_expires_at"),
    q("member_youtube_connections", "channel_id, status"),
    q("member_tiktok_connections", "status"),
    q("member_instagram_connections", "username, status"),
    q("member_facebook_pages", "status")
  ].map(function (p) { return Promise.resolve(p).catch(function (e) { return { error: e }; }); }));
  const ok = function (i) { if (r[i].error) { if (soft) return null; throw r[i].error; } return r[i].data && r[i].data.status === "connected" ? r[i].data : null; };
  const now = deps.now ? deps.now() : Date.now();
  const bs = ok(0), th = ok(1), yt = ok(2), tk = ok(3), ig = ok(4), fb = ok(5);
  const threadsLive = !!th && Date.parse(th.access_expires_at || "") > now;
  return {
    names: { bluesky: bs ? bs.handle : null, threads: threadsLive ? th.username : null, youtube: yt ? yt.channel_id : null, instagram: ig ? ig.username : null },
    on: { bluesky: !!bs, threads: threadsLive, youtube: !!yt, tiktok: !!tk, instagram: !!ig, facebook: !!fb }
  };
}

async function loadProfileView(deps, rawHandle) {
  const handle = PP.normalHandle(rawHandle);
  if (!handle) return null;
  const pr = await deps.sb.from("bf_profiles").select("user_id, username, display_name, bio, avatar_url, banner_url, place_city, place_region, place_country, show_products").eq("username", handle).maybeSingle();
  if (pr.error) throw pr.error;
  if (!pr.data) return null;
  const p = pr.data, idx = await indexability(deps, p.user_id);
  if (!shown(idx)) return null;
  let listings = [];
  if (p.show_products !== false) {
    const lr = await deps.sb.from("marketplace_listings").select("id, slug, title, description").eq("seller_id", p.user_id).eq("status", "active").order("created_at", { ascending: false }).limit(50);
    if (lr.error) throw lr.error;
    const hid = await deps.hiddenAmong(deps.sb, "listing", (lr.data || []).map(function (l) { return l.id; }));
    listings = (lr.data || []).filter(function (l) { return !hid.has(l.id); });
  }
  const biz = await deps.sb.from("business_profiles").select("business_name").eq("user_id", p.user_id).maybeSingle();
  const c = await connections(deps, p.user_id, true);
  return { profile: p, business: biz.error ? null : biz.data, listings: listings, sameAs: PP.sameAsFrom(c.names), robots: idx.indexable ? PP.INDEX : PP.NOINDEX };
}

async function loadListingView(deps, rawKey) {
  const key = PP.listingKey(rawKey);
  if (!key) return null;
  let q = deps.sb.from("marketplace_listings").select("id, slug, title, description, category, category_slug, media, status, seller_id");
  q = UUID_RE.test(key) ? q.eq("id", key) : q.eq("slug", key);
  const lr = await q.maybeSingle();
  if (lr.error) throw lr.error;
  const l = lr.data;
  if (!l || l.status !== "active") return null;
  if ((await deps.hiddenAmong(deps.sb, "listing", [l.id])).has(l.id)) return null;
  const idx = await indexability(deps, l.seller_id);
  if (!shown(idx)) return null;
  const s = await deps.sb.from("bf_profiles").select("username, display_name").eq("user_id", l.seller_id).maybeSingle();
  if (s.error) throw s.error;
  let categoryName = null;
  if (l.category_slug) { const c = await CAT.find(deps.sb, l.category_slug); categoryName = c ? c.name : null; }
  return { listing: l, seller: s.data || null, categoryName: categoryName,
    robots: PP.robotsFor(Object.assign({}, idx, { listing: { active: l.status === "active", hidden: false } })) };
}

/* The indexable addresses of one member: their profile (with a handle) and their active, shown listings. */
async function indexableUrls(deps, userId) {
  const idx = await indexability(deps, userId);
  if (!idx.indexable) return [];
  const out = [];
  const pr = await deps.sb.from("bf_profiles").select("username").eq("user_id", userId).maybeSingle();
  if (pr.error) throw pr.error;
  if (pr.data && PP.normalHandle(pr.data.username)) out.push(PP.profileUrl(pr.data.username));
  const lr = await deps.sb.from("marketplace_listings").select("id, slug").eq("seller_id", userId).eq("status", "active").limit(200);
  if (lr.error) throw lr.error;
  const hid = await deps.hiddenAmong(deps.sb, "listing", (lr.data || []).map(function (l) { return l.id; }));
  (lr.data || []).forEach(function (l) { if (!hid.has(l.id)) out.push(PP.listingUrl(l)); });
  return out;
}

function mountGetFoundRoutes(app, deps) {
  const M = [deps.requireAuth, deps.requireActiveSubscription];
  const L = deps.pageLimiter ? [deps.pageLimiter] : [];
  const cache = { profiles: { xml: null, at: 0 }, listings: { xml: null, at: 0 } };
  const now = function () { return deps.now ? deps.now() : Date.now(); };
  function resetSitemaps() { cache.profiles = { xml: null, at: 0 }; cache.listings = { xml: null, at: 0 }; }

  function sendPage(res, status, html) {
    const h = PP.pageHeaders();
    Object.keys(h).forEach(function (k) { res.set(k, h[k]); });
    return res.status(status).send(html);
  }

  app.get("/@:handle", L, async function (req, res) {
    try {
      const view = await loadProfileView(deps, req.params.handle);
      return sendPage(res, view ? 200 : 404, PP.renderProfilePage(view));
    } catch (err) {
      console.error("[profile page] " + ((err && err.message) || err));
      res.set("Retry-After", "60");
      return sendPage(res, 503, PP.renderProfilePage(null));
    }
  });

  app.get("/listing/:id", L, async function (req, res) {
    try {
      const view = await loadListingView(deps, req.params.id);
      return sendPage(res, view ? 200 : 404, PP.renderListingPage(view));
    } catch (err) {
      console.error("[listing page] " + ((err && err.message) || err));
      res.set("Retry-After", "60");
      return sendPage(res, 503, PP.renderListingPage(null));
    }
  });

  async function buildProfiles() {
    const r = await deps.sb.from("bf_profiles").select("user_id, username, updated_at").not("username", "is", null).limit(PP.SITEMAP_MAX);
    if (r.error) throw r.error;
    const out = [];
    for (const p of r.data || []) {
      if (!PP.normalHandle(p.username)) continue;
      if ((await indexability(deps, p.user_id)).indexable) out.push({ loc: PP.profileUrl(p.username), lastmod: p.updated_at });
    }
    return PP.sitemapXml(out);
  }
  async function buildListings() {
    const r = await deps.sb.from("marketplace_listings").select("id, slug, seller_id, updated_at").eq("status", "active").order("updated_at", { ascending: false }).limit(PP.SITEMAP_MAX);
    if (r.error) throw r.error;
    const rows = r.data || [];
    const hid = await deps.hiddenAmong(deps.sb, "listing", rows.map(function (l) { return l.id; }));
    const sellers = {};
    const out = [];
    for (const l of rows) {
      if (hid.has(l.id)) continue;
      if (!(l.seller_id in sellers)) sellers[l.seller_id] = (await indexability(deps, l.seller_id)).indexable;
      if (sellers[l.seller_id]) out.push({ loc: PP.listingUrl(l), lastmod: l.updated_at });
    }
    return PP.sitemapXml(out);
  }
  function sitemapRoute(name, build) {
    return async function (req, res) {
      try {
        if (!cache[name].xml || now() - cache[name].at > SITEMAP_CACHE_MS) cache[name] = { xml: await build(), at: now() };
        res.set("Content-Type", "application/xml; charset=utf-8");
        res.set("Cache-Control", "public, max-age=600");
        return res.status(200).send(cache[name].xml);
      } catch (err) {
        console.error("[sitemap/" + name + "] could not be built:", (err && err.message) || err);
        res.set("Retry-After", "600");
        return res.status(503).type("text/plain").send("The " + (name === "profiles" ? "profile" : "listing") + " sitemap could not be built just now.");
      }
    };
  }
  app.get("/api/sitemap/profiles.xml", L, sitemapRoute("profiles", buildProfiles));
  app.get("/api/sitemap/listings.xml", L, sitemapRoute("listings", buildListings));

  app.get("/api/indexnow/key.txt", L, function (req, res) {
    if (!IX.enabled(deps.env)) return res.status(404).type("text/plain").send("Not found");
    res.set("Cache-Control", "public, max-age=3600");
    return res.status(200).type("text/plain").send(IX.keyOf(deps.env));
  });

  app.get("/api/leads/found", M, async function (req, res, next) {
    try {
      const facts = await FS.gather({ sb: deps.sb, hiddenAmong: deps.hiddenAmong,
        indexability: function (id) { return indexability(deps, id); },
        connections: async function (id) { return (await connections(deps, id, false)).on; } }, req.user.id);
      return res.json(FS.compute(facts));
    } catch (err) { next(err); }
  });

  app.get("/api/me/google", M, async function (req, res, next) {
    try {
      const idx = await indexability(deps, req.user.id);
      const pr = await deps.sb.from("bf_profiles").select("username").eq("user_id", req.user.id).maybeSingle();
      if (pr.error) throw pr.error;
      const handle = pr.data && PP.normalHandle(pr.data.username);
      return res.json({ show_in_google: idx.switchOn, indexable: idx.indexable, why: idx.why, profile_url: handle ? PP.profileUrl(handle) : null });
    } catch (err) { next(err); }
  });

  app.put("/api/me/google", M, async function (req, res, next) {
    try {
      const v = req.body ? req.body.show_in_google : undefined;
      if (typeof v !== "boolean") return res.status(400).json({ error: SWITCH_MESSAGES.type, field: "show_in_google" });
      const w = await deps.sb.from("user_preferences").upsert({ user_id: req.user.id, show_in_google: v, updated_at: new Date(now()).toISOString() }, { onConflict: "user_id" });
      if (w.error) throw w.error;
      resetSitemaps();
      if (v && deps.indexNow && IX.enabled(deps.env)) {
        indexableUrls(deps, req.user.id).then(function (urls) { deps.indexNow.queue(urls); }).catch(function (e) { console.warn("[indexnow] " + ((e && e.message) || e)); });
      }
      return res.json({ saved: true, show_in_google: v, message: v ? SWITCH_MESSAGES.saved_on : SWITCH_MESSAGES.saved_off });
    } catch (err) { next(err); }
  });

  return { resetSitemaps: resetSitemaps, indexableUrls: function (id) { return indexableUrls(deps, id); }, indexability: function (id) { return indexability(deps, id); } };
}

module.exports = { SITEMAP_CACHE_MS, SWITCH_MESSAGES, readSwitch, indexability, connections, loadProfileView, loadListingView, indexableUrls, mountGetFoundRoutes };
