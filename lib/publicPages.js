"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   PAGES GOOGLE CAN READ (LR-4, Nov 25 2026): a member's profile and storefront
   (bizforceai.net/@handle) and a listing (bizforceai.net/listing/<slug or id>),
   served by the backend with the real head filled in, the way lib/postPage.js
   serves /p/<id> and lib/cardPage.js serves /c/<slug>.

   THE BODY IS THE FRONTEND'S OWN PAGE, UNCHANGED. Netlify proxies /@:handle and
   /listing/:id here (the frontend's _redirects). The page served is seller.html
   or listing.html exactly as the frontend has it (lib/publicShells.generated.js,
   written by scripts/buildPublicShells.js), and the app still runs on top of it:
   it draws the storefront or the listing in the browser from the same API as
   before. Only the head's static block (from the description line through
   <title>) is replaced, a JSON-LD script is added before </head>, and a
   <noscript> summary is added just inside <body>, which a browser running the
   page never draws. So the page looks exactly as before; only what a crawler
   reads changes. The static bf-canonical.js tag is left out of the served head:
   the server writes the one canonical address itself (the handle, or the
   listing's slug, else its id), so the script has nothing to correct.

   THE ROBOTS RULE (robotsFor). "index, follow" only when ALL of:
     the account is a member (a free account's profile and listings stay noindex),
     its pages are public (not deleted, not suspended: users.banned_at),
     moderation has not hidden the profile,
     the member's switch "Show my profile and listings in Google" is on
       (user_preferences.show_in_google; NULL, never chosen, reads as on),
   and for a listing, also: it is active and moderation has not hidden it.
   Everything else is "noindex". The sitemaps list exactly the pages this rule
   lets in, so a page is never in a sitemap that its own head calls noindex.

   WHAT THE HEAD SAYS
     profile  title "Name (@handle) on BizForce"; the description from the bio,
              else the business name and city; canonical /@handle; Open Graph and
              Twitter tags with the avatar, else the banner, else the site icon;
              JSON-LD Person, or LocalBusiness when the member has a place AND at
              least one active listing or service (name, url, image, description,
              the address's locality, region and country, and sameAs with the
              public addresses of the accounts they connected: Bluesky, Threads,
              YouTube, Instagram).
     listing  title "Listing title by Name | BizForce"; the description from the
              listing; canonical; Open Graph with the first photo; JSON-LD
              Product (name, description, image, category, the seller as brand)
              with offers ONLY when a USD price exists (price_usd, a whole number
              of dollars above 0; priceCurrency USD; availability from status).
              BizCash is not a currency Google knows: BFC is never in offers.
   EVERY value is escaped: HTML-escaped in tags and text, and in the JSON-LD
   "<", ">", "&" and the two line separators are written as \u escapes, so no
   member text can close the script or a tag.
   ══════════════════════════════════════════════════════════════════════════ */

var links = require("./supportLinks");
var SHELLS = require("./publicShells.generated");

var esc = links.escapeHtml;
var SITE = "https://bizforceai.net";
var DEFAULT_IMAGE = SITE + "/icons/icon-512.png";
var HANDLE_RE = /^[a-z0-9_][a-z0-9_-]{2,29}$/;
var UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
var SLUG_RE = /^[a-z0-9][a-z0-9-]{0,99}$/;
var TITLE_MAX = 70;
var DESCRIPTION_MAX = 160;
var NOSCRIPT_LISTINGS = 10;
var SITEMAP_MAX = 5000;
var INDEX = "index, follow";
var NOINDEX = "noindex";

/* ── small helpers ─────────────────────────────────────────────────────── */

function clean(text) { return String(text == null ? "" : text).replace(/\s+/g, " ").trim(); }
function cut(text, n) {
  var chars = Array.from(clean(text));
  return chars.length > n ? chars.slice(0, n - 3).join("").trim() + "..." : chars.join("");
}
function httpsUrl(url) { return typeof url === "string" && /^https:\/\/[^\s"'<>\\]+$/.test(url) && url.length < 501 ? url : null; }
function normalHandle(raw) { var h = String(raw || "").toLowerCase(); return HANDLE_RE.test(h) ? h : null; }
function listingKey(raw) { var k = String(raw || "").toLowerCase(); return UUID_RE.test(k) || SLUG_RE.test(k) ? k : null; }
function profileUrl(handle) { return SITE + "/@" + handle; }
function listingUrl(l) { return SITE + "/listing/" + (l.slug && SLUG_RE.test(l.slug) ? l.slug : l.id); }
function firstPhoto(media) {
  var list = Array.isArray(media) ? media : [];
  for (var i = 0; i < list.length; i++) { var u = list[i] && httpsUrl(list[i].url); if (u) return u; }
  return null;
}

/* JSON for a <script type="application/ld+json">: nothing in it can close the script. */
function jsonLd(data) {
  return JSON.stringify(data).replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
}

/* ── the robots rule ───────────────────────────────────────────────────── */

/* facts: { member, pagePublic, suspended, profileHidden, switchOn, listing: undefined | { active, hidden } } */
function robotsFor(facts) {
  var f = facts || {};
  if (f.member !== true || f.pagePublic !== true || f.suspended === true || f.profileHidden === true || f.switchOn !== true) return NOINDEX;
  if (f.listing !== undefined) {
    if (!f.listing || f.listing.active !== true || f.listing.hidden === true) return NOINDEX;
  }
  return INDEX;
}
/* The switch: NULL (never chosen) is on, false is off. */
function switchOn(value) { return value !== false; }

/* ── the profile ───────────────────────────────────────────────────────── */

function profileName(p) { return clean(p.display_name) || "@" + p.username; }
function profileTitle(p) { return cut(profileName(p) + " (@" + p.username + ") on BizForce", TITLE_MAX + 30); }
function placeText(p) { return [clean(p.place_city), clean(p.place_region)].filter(Boolean).join(", "); }
function profileDescription(p, business) {
  var bio = cut(p.bio, DESCRIPTION_MAX);
  if (bio) return bio;
  var name = clean(business && business.business_name), place = placeText(p);
  if (name && place) return cut(name + " in " + place + ", on BizForce.", DESCRIPTION_MAX);
  if (name) return cut(name + " on BizForce.", DESCRIPTION_MAX);
  if (place) return cut(profileName(p) + " in " + place + ", on BizForce.", DESCRIPTION_MAX);
  return cut(profileName(p) + " on BizForce: their profile and storefront.", DESCRIPTION_MAX);
}
function profileImage(p) { return httpsUrl(p.avatar_url) || httpsUrl(p.banner_url) || DEFAULT_IMAGE; }

/* Person, or LocalBusiness with a place and at least one active listing or service. */
function profileStructuredData(p, desc, sameAs, listingCount) {
  var url = profileUrl(p.username), image = profileImage(p);
  var local = !!clean(p.place_city) && listingCount > 0;
  var data = { "@context": "https://schema.org", "@type": local ? "LocalBusiness" : "Person", "@id": url, name: profileName(p), url: url, description: desc };
  if (image !== DEFAULT_IMAGE) data.image = image;
  if (local) {
    data.address = { "@type": "PostalAddress", addressLocality: clean(p.place_city) };
    if (clean(p.place_region)) data.address.addressRegion = clean(p.place_region);
    if (/^[A-Z]{2}$/.test(String(p.place_country || ""))) data.address.addressCountry = p.place_country;
  }
  var same = (sameAs || []).filter(httpsUrl);
  if (same.length) data.sameAs = same;
  return data;
}

/* The connected public accounts' own addresses, from what the connection rows hold. Only a value of the platform's
   own shape is used, so nothing a member typed elsewhere becomes a link here. */
function sameAsFrom(c) {
  var out = [];
  c = c || {};
  if (c.bluesky && /^[a-z0-9][a-z0-9.-]{1,252}$/i.test(String(c.bluesky).replace(/^@/, ""))) out.push("https://bsky.app/profile/" + String(c.bluesky).replace(/^@/, "").toLowerCase());
  if (c.threads && /^[a-z0-9._]{1,30}$/i.test(c.threads)) out.push("https://www.threads.net/@" + c.threads.toLowerCase());
  if (c.youtube && /^UC[A-Za-z0-9_-]{22}$/.test(c.youtube)) out.push("https://www.youtube.com/channel/" + c.youtube);
  if (c.instagram && /^[a-z0-9._]{1,30}$/i.test(c.instagram)) out.push("https://www.instagram.com/" + c.instagram.toLowerCase());
  return out;
}

function noscriptProfile(p, desc, listings) {
  var items = (listings || []).slice(0, NOSCRIPT_LISTINGS).map(function (l) {
    return '<li><a href="' + esc(listingUrl(l)) + '">' + esc(cut(l.title, 120) || "A listing") + "</a>" + (clean(l.description) ? ": " + esc(cut(l.description, 160)) : "") + "</li>";
  });
  return [
    "<noscript>",
    '<div class="bf-noscript">',
    "<h1>" + esc(profileName(p)) + " (@" + esc(p.username) + ")</h1>",
    "<p>" + esc(desc) + "</p>",
    placeText(p) ? "<p>" + esc(placeText(p)) + "</p>" : "",
    items.length ? "<h2>Listings</h2>\n<ul>\n" + items.join("\n") + "\n</ul>" : "",
    "</div>",
    "</noscript>"
  ].filter(Boolean).join("\n");
}

/* view: null (no such member, or not shown: 404), or { profile, business, listings, sameAs, robots } */
function profileHeadLines(view) {
  if (!view) return genericHead(SHELLS.SELLER_FALLBACK, NOINDEX);
  var p = view.profile, desc = profileDescription(p, view.business), url = profileUrl(p.username), image = profileImage(p);
  var title = profileTitle(p);
  return [
    '  <meta name="description" content="' + esc(desc) + '"/>',
    '  <meta name="robots" content="' + (view.robots === INDEX ? INDEX : NOINDEX) + '"/>',
    '  <link rel="canonical" href="' + esc(url) + '"/>',
    '  <meta property="og:type" content="profile"/>',
    '  <meta property="og:site_name" content="BizForce AI"/>',
    '  <meta property="og:title" content="' + esc(title) + '"/>',
    '  <meta property="og:description" content="' + esc(desc) + '"/>',
    '  <meta property="og:url" content="' + esc(url) + '"/>',
    '  <meta property="og:image" content="' + esc(image) + '"/>',
    '  <meta name="twitter:card" content="' + (image !== DEFAULT_IMAGE ? "summary_large_image" : "summary") + '"/>',
    '  <meta name="twitter:title" content="' + esc(title) + '"/>',
    '  <meta name="twitter:description" content="' + esc(desc) + '"/>',
    '  <meta name="twitter:image" content="' + esc(image) + '"/>',
    "  <title>" + esc(title) + "</title>"
  ];
}

function renderProfilePage(view) {
  var ld = view ? '  <script type="application/ld+json">' + jsonLd(profileStructuredData(view.profile, profileDescription(view.profile, view.business), view.sameAs, (view.listings || []).length)) + "</script>" : "";
  var ns = view ? noscriptProfile(view.profile, profileDescription(view.profile, view.business), view.listings) : "";
  return fill(SHELL_SELLER, profileHeadLines(view), ld, ns);
}

/* ── the listing ───────────────────────────────────────────────────────── */

function sellerName(s) { return (s && (clean(s.display_name) || (s.username ? "@" + s.username : ""))) || "a member"; }
function listingTitle(l, s) { return cut((clean(l.title) || "A listing") + " by " + sellerName(s) + " | BizForce", TITLE_MAX + 30); }
function listingDescription(l, s) {
  var d = cut(l.description, DESCRIPTION_MAX);
  return d || cut((clean(l.title) || "A listing") + ", offered by " + sellerName(s) + " on BizForce.", DESCRIPTION_MAX);
}
/* A USD price Google may be shown: a whole number of dollars above 0. Anything else (null, 0, BizCash only) is none. */
function usdPrice(l) { var n = l ? l.price_usd : null; return typeof n === "number" && Number.isInteger(n) && n > 0 ? n : null; }
var AVAILABILITY = { active: "https://schema.org/InStock", paused: "https://schema.org/OutOfStock", sold: "https://schema.org/SoldOut" };

function listingStructuredData(l, s, desc, categoryName) {
  var url = listingUrl(l), image = firstPhoto(l.media);
  var data = { "@context": "https://schema.org", "@type": "Product", "@id": url, name: clean(l.title) || "A listing", description: desc, url: url,
    brand: { "@type": "Brand", name: sellerName(s) } };
  if (image) data.image = image;
  if (clean(categoryName || l.category)) data.category = clean(categoryName || l.category);
  var usd = usdPrice(l);
  if (usd !== null) {
    data.offers = { "@type": "Offer", url: url, price: String(usd), priceCurrency: "USD", availability: AVAILABILITY[l.status] || AVAILABILITY.paused,
      seller: s && s.username ? { "@type": "Person", name: sellerName(s), url: profileUrl(s.username) } : { "@type": "Person", name: sellerName(s) } };
  }
  return data;
}

function noscriptListing(l, s, desc) {
  return [
    "<noscript>",
    '<div class="bf-noscript">',
    "<h1>" + esc(clean(l.title) || "A listing") + "</h1>",
    "<p>" + esc(desc) + "</p>",
    s && s.username ? '<p>Offered by <a href="' + esc(profileUrl(s.username)) + '">' + esc(sellerName(s)) + "</a></p>" : "<p>Offered by " + esc(sellerName(s)) + "</p>",
    "</div>",
    "</noscript>"
  ].join("\n");
}

/* view: null (no such active listing, or not shown: 404), or { listing, seller, categoryName, robots } */
function listingHeadLines(view) {
  if (!view) return genericHead(SHELLS.LISTING_FALLBACK, NOINDEX);
  var l = view.listing, s = view.seller, desc = listingDescription(l, s), url = listingUrl(l), title = listingTitle(l, s);
  var image = firstPhoto(l.media) || DEFAULT_IMAGE;
  return [
    '  <meta name="description" content="' + esc(desc) + '"/>',
    '  <meta name="robots" content="' + (view.robots === INDEX ? INDEX : NOINDEX) + '"/>',
    '  <link rel="canonical" href="' + esc(url) + '"/>',
    '  <meta property="og:type" content="product"/>',
    '  <meta property="og:site_name" content="BizForce AI"/>',
    '  <meta property="og:title" content="' + esc(title) + '"/>',
    '  <meta property="og:description" content="' + esc(desc) + '"/>',
    '  <meta property="og:url" content="' + esc(url) + '"/>',
    '  <meta property="og:image" content="' + esc(image) + '"/>',
    '  <meta name="twitter:card" content="' + (image !== DEFAULT_IMAGE ? "summary_large_image" : "summary") + '"/>',
    '  <meta name="twitter:title" content="' + esc(title) + '"/>',
    '  <meta name="twitter:description" content="' + esc(desc) + '"/>',
    '  <meta name="twitter:image" content="' + esc(image) + '"/>',
    "  <title>" + esc(title) + "</title>"
  ];
}

function renderListingPage(view) {
  var ld = view ? '  <script type="application/ld+json">' + jsonLd(listingStructuredData(view.listing, view.seller, listingDescription(view.listing, view.seller), view.categoryName)) + "</script>" : "";
  var ns = view ? noscriptListing(view.listing, view.seller, listingDescription(view.listing, view.seller)) : "";
  return fill(SHELL_LISTING, listingHeadLines(view), ld, ns);
}

/* ── the shells ────────────────────────────────────────────────────────── */

/* A page that is not shown keeps the page's own static description and title, and says noindex. */
function genericHead(fallback, robots) {
  return [
    '  <meta name="description" content="' + esc(fallback.description) + '"/>',
    '  <meta name="robots" content="' + robots + '"/>',
    "  <title>" + esc(fallback.title) + "</title>"
  ];
}

/* The shell split around its static head block (the description line through the <title> line) and just inside
   <body>. Each marker must be there exactly once, or this throws at load and no page is served from a shell it does
   not understand. */
function splitShell(shell, name) {
  var text = String(shell || "");
  var d = text.indexOf('\n  <meta name="description"'), t = text.indexOf("\n  <title>"), b = text.indexOf("\n<body>\n");
  var once = function (needle, at) { return at !== -1 && text.indexOf(needle, at + 1) === -1; };
  if (!once('\n  <meta name="description"', d) || !once("\n  <title>", t) || !once("\n<body>\n", b) || !(d < t && t < b) || text.indexOf("</head>") === -1) {
    throw new Error(name + " shell: expected one description line, one <title> line and one <body> line, in that order");
  }
  var tEnd = text.indexOf("\n", t + 1);
  var block = text.slice(d + 1, tEnd);
  if (block.indexOf("<script") !== -1 && !/^\s*<script src="\/scripts\/bf-canonical\.js"[^>]*><\/script>$/m.test(block)) throw new Error(name + " shell: an unexpected script in the head block");
  var head = text.indexOf("</head>");
  return { before: text.slice(0, d + 1), middle: text.slice(tEnd + 1, head), bodyOpen: text.slice(head, b + "\n<body>\n".length), after: text.slice(b + "\n<body>\n".length) };
}
var SHELL_SELLER = splitShell(SHELLS.SELLER, "seller.html");
var SHELL_LISTING = splitShell(SHELLS.LISTING, "listing.html");

function fill(shell, headLines, ldLine, noscript) {
  return shell.before + headLines.join("\n") + "\n" + shell.middle + (ldLine ? ldLine + "\n" : "") + shell.bodyOpen + (noscript ? noscript + "\n" : "") + shell.after;
}

/* The headers every served page carries: the frontend's own security headers (its _headers "/*" block, generated). */
function pageHeaders() {
  var out = {};
  Object.keys(SHELLS.HEADERS).forEach(function (k) { out[k] = SHELLS.HEADERS[k]; });
  out["Content-Type"] = "text/html; charset=utf-8";
  out["Cache-Control"] = "no-cache";   // the switch and moderation take effect at once
  return out;
}

/* ── the sitemaps ──────────────────────────────────────────────────────── */

function sitemapXml(entries) {
  return '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' +
    (entries || []).slice(0, SITEMAP_MAX).map(function (e) {
      var day = /^\d{4}-\d{2}-\d{2}/.test(String(e.lastmod || "")) ? String(e.lastmod).slice(0, 10) : "";
      return "  <url><loc>" + esc(e.loc) + "</loc>" + (day ? "<lastmod>" + day + "</lastmod>" : "") + "</url>\n";
    }).join("") + "</urlset>\n";
}

module.exports = {
  SITE, DEFAULT_IMAGE, INDEX, NOINDEX, NOSCRIPT_LISTINGS, SITEMAP_MAX, HANDLE_RE,
  clean, cut, httpsUrl, normalHandle, listingKey, profileUrl, listingUrl, firstPhoto, jsonLd,
  robotsFor, switchOn, profileName, profileTitle, profileDescription, profileImage, profileStructuredData, sameAsFrom,
  noscriptProfile, profileHeadLines, renderProfilePage,
  sellerName, listingTitle, listingDescription, usdPrice, listingStructuredData, noscriptListing, listingHeadLines, renderListingPage,
  splitShell, pageHeaders, sitemapXml
};
