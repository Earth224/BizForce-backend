/* ══════════════════════════════════════════════════════════════════════════
   lib/themes.js — a member's saved looks, which page wears which, and the
   closed schema every saved look is held to (migration 154).

   A THEME is five things a member picks in Settings → Theme: the top-left
   glow, the bottom-right glow, the middle backdrop (black, a colour, or their
   own photo with a dim), and whether the glows drift ("Alive corners"). It is
   stored as JSON in member_themes.theme, and the JSON is CLOSED: these keys
   and no others, each checked for exactly what it may hold.

     v             1
     glow_a        "#rrggbb"  lowercase hex, nothing else
     glow_a_alpha  number, clamped to 0 … 0.5
     glow_b        "#rrggbb"
     glow_b_alpha  number, clamped to 0 … 0.5
     middle        "black" | "colour" | "photo"
     bg            "#rrggbb"  the middle colour ("colour"; under the photo too)
     photo         null, or the member's OWN stored photo:
                   theme-photos/<their id>/<digits>.(jpg|png|webp)
     dim           number, clamped to 0 … 0.85 (how dark the photo is shaded)
     photo_luma    number, clamped to 0 … 1: the photo's brightest point,
                   read from a small canvas in the browser when it was saved
     alive         true | false

   Never raw CSS, never a URL. A colour that is not six lowercase hex digits,
   a key not on the list, a photo path in anyone else's folder, or any string
   with CSS in it is REFUSED, not cleaned: a refused save says which key.
   Numbers out of range are clamped, which is the one kind of repair made.

   WHICH PAGES. A page key is the app map's (lib/appMap.json) key for a page,
   its file name. Only pages that wear a theme can be given one: the app map's
   pages minus UNTHEMED below (public pages, which keep their owner's look
   and never the visitor's, and the pages with no backdrop at all).
   scripts/checkThemes.js proves UNTHEMED is exactly the map pages that do not
   load scripts/bf-theme.js.

   NOTHING HERE TALKS TO THE DATABASE OR THE NETWORK: pure functions, so
   scripts/checkThemes.js runs all of it directly.
   ══════════════════════════════════════════════════════════════════════════ */

var THEME_VERSION = 1;
var MAX_THEMES = 30;
var NAME_MAX = 60;
var PHOTO_MAX_BYTES = 5 * 1024 * 1024;
var PHOTO_FOLDER = "theme-photos";
var HEX = /^#[0-9a-f]{6}$/;
var MIDDLES = ["black", "colour", "photo"];
var SCOPES = ["all", "page", "pages"];

/* Today's look. Every key a theme can hold, at the value the app has always
   shown; a theme that leaves a key out gets this. */
var DEFAULT_THEME = {
  v: THEME_VERSION,
  glow_a: "#00e5ff",
  glow_a_alpha: 0.14,
  glow_b: "#a855f7",
  glow_b_alpha: 0.18,
  middle: "black",
  bg: "#070b18",
  photo: null,
  dim: 0.55,
  photo_luma: 0,
  alive: false
};
var KEYS = Object.keys(DEFAULT_THEME);
var RANGES = { glow_a_alpha: [0, 0.5], glow_b_alpha: [0, 0.5], dim: [0, 0.85], photo_luma: [0, 1] };

/* Pages in the app map that never wear a member's theme. Public pages show
   another member's things (or the public's), so they keep the OWNER's look:
   seller, support, card-view, the blog, a listing, the legal pages and the
   public landing pages. The rest have no backdrop to theme. */
var UNTHEMED = [
  "seller.html", "support.html", "card-view.html", "blogindex.html", "blogpost.html", "listing.html",
  "suppressed.html", "vitality.html", "terms.html", "privacy.html", "refund.html", "contact.html",
  "reset-password.html", "verify-email.html", "your-data.html", "xxl-xtreme.html"
];

/* The photo a member uploaded for themselves, and nothing else. */
function ownPhotoPath(value, userId) {
  if (typeof value !== "string" || !userId) return false;
  var m = /^theme-photos\/([0-9a-f-]{36})\/\d{10,16}\.(jpg|png|webp)$/.exec(value);
  return !!m && m[1] === String(userId).toLowerCase();
}

function clampNumber(value, range) {
  if (typeof value !== "number" || !isFinite(value)) return null;
  var n = Math.min(range[1], Math.max(range[0], value));
  return Math.round(n * 1000) / 1000;
}

/* One theme from a request body: { theme } or { error, key }. */
function validateTheme(input, userId) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return { error: "A theme must be an object.", key: null };
  var unknown = Object.keys(input).filter(function (k) { return KEYS.indexOf(k) === -1; });
  if (unknown.length) return { error: "Unknown theme key: " + unknown[0] + ".", key: unknown[0] };
  var out = {};
  for (var i = 0; i < KEYS.length; i++) {
    var k = KEYS[i];
    var has = Object.prototype.hasOwnProperty.call(input, k);
    var value = has ? input[k] : DEFAULT_THEME[k];
    if (k === "v") {
      if (value !== THEME_VERSION) return { error: "v must be " + THEME_VERSION + ".", key: k };
    } else if (k === "glow_a" || k === "glow_b" || k === "bg") {
      if (typeof value !== "string" || !HEX.test(value)) return { error: k + " must be a colour like #1a2b3c.", key: k };
    } else if (RANGES[k]) {
      value = clampNumber(value, RANGES[k]);
      if (value === null) return { error: k + " must be a number.", key: k };
    } else if (k === "middle") {
      if (MIDDLES.indexOf(value) === -1) return { error: "middle must be black, colour or photo.", key: k };
    } else if (k === "photo") {
      if (value !== null && !ownPhotoPath(value, userId)) return { error: "photo must be a photo you uploaded.", key: k };
    } else if (k === "alive") {
      if (typeof value !== "boolean") return { error: "alive must be true or false.", key: k };
    }
    out[k] = value;
  }
  if (out.middle === "photo" && !out.photo) return { error: "A photo backdrop needs a photo.", key: "photo" };
  return { theme: out };
}

/* A theme's name: plain text, 1 … NAME_MAX characters, control characters out. */
function validateName(value) {
  if (typeof value !== "string") return { error: "A theme needs a name." };
  var name = value.replace(/[\u0000-\u001f\u007f]/g, "").replace(/\s+/g, " ").trim();
  if (!name) return { error: "A theme needs a name." };
  if (name.length > NAME_MAX) return { error: "A theme name is at most " + NAME_MAX + " characters." };
  return { name: name };
}

/* The keys a theme may be given to: the app map's pages that wear one. */
function themedPages(appMap) {
  var keys = Object.keys((appMap && appMap.pages) || {});
  return keys.filter(function (k) { return UNTHEMED.indexOf(k) === -1; }).sort();
}

/* The studio's page checklist, from the app map: each themed page's key, the
   name its <title> gives it, and its group. Groups, in the studio's order:
   hq "Dashboard & HQ", agents "Agent pages", money "Money (wallet, billing,
   marketplace)", content "Content & tools", account "Account". */
var GROUPS = ["hq", "agents", "money", "content", "account"];
var GROUP_OF = {
  "dashboard.html": "hq", "executive-agent.html": "hq", "analytics-dashboard.html": "hq", "index.html": "hq",
  "wallet.html": "money", "billing.html": "money", "marketplace.html": "money", "my-purchases.html": "money",
  "receipts.html": "money", "garage-sale.html": "money", "campaigns.html": "money",
  "settings.html": "account", "profile.html": "account", "app.html": "account", "business-id.html": "account",
  "digital-cards.html": "account", "certifications.html": "account"
};
var NAME_OF = { "index.html": "Home page", "app.html": "Sign in" };
function pageGroup(key, entry) {
  if (GROUP_OF[key]) return GROUP_OF[key];
  var p = (entry && entry.p) || "";
  if (/^\/agents\//.test(p) || /-agent\.html$/.test(key) || key === "agents-hub.html" || key === "ai-agents.html") return "agents";
  return "content";
}
function pageName(key, entry) {
  if (NAME_OF[key]) return NAME_OF[key];
  var t = String((entry && entry.t) || "").replace(/^BizForce AI\s*[—-]\s*/, "").replace(/\s*[—-]\s*BizForce AI.*$/, "").trim();
  return t || key.replace(/\.html$/, "");
}
function themedPageList(appMap) {
  var pages = (appMap && appMap.pages) || {};
  return themedPages(appMap).map(function (k) {
    return { key: k, name: pageName(k, pages[k]), group: pageGroup(k, pages[k]) };
  }).sort(function (a, b) {
    return GROUPS.indexOf(a.group) - GROUPS.indexOf(b.group) || a.name.localeCompare(b.name);
  });
}

/* A list of page keys: { pages } (deduplicated) or { error }. */
function validatePages(list, allowed) {
  if (!Array.isArray(list) || !list.length) return { error: "Choose at least one page." };
  if (list.length > allowed.length) return { error: "Too many pages." };
  var out = [];
  for (var i = 0; i < list.length; i++) {
    var k = list[i];
    if (typeof k !== "string" || allowed.indexOf(k) === -1) return { error: "Not a page that can wear a theme: " + String(k).slice(0, 80) + "." };
    if (out.indexOf(k) === -1) out.push(k);
  }
  return { pages: out };
}

/* A stored page_themes value, kept to known pages and owned themes. */
function cleanPageThemes(value, allowed, ownedIds) {
  var out = {};
  if (!value || typeof value !== "object" || Array.isArray(value)) return out;
  Object.keys(value).forEach(function (k) {
    if (allowed.indexOf(k) !== -1 && ownedIds.indexOf(value[k]) !== -1) out[k] = value[k];
  });
  return out;
}

/* PUT /api/themes/apply. prefs { default_theme_id, page_themes }; body
   { theme_id, scope, pages }. Returns { prefs } (the new values) or { error }. */
function applyScope(prefs, body, allowed, ownedIds) {
  body = body || {};
  if (SCOPES.indexOf(body.scope) === -1) return { error: "scope must be all, page or pages." };
  if (ownedIds.indexOf(body.theme_id) === -1) return { error: "That theme is not one of yours." };
  var pageThemes = cleanPageThemes(prefs && prefs.page_themes, allowed, ownedIds);
  var main = prefs && ownedIds.indexOf(prefs.default_theme_id) !== -1 ? prefs.default_theme_id : null;
  if (body.scope === "all") return { prefs: { default_theme_id: body.theme_id, page_themes: pageThemes } };
  var pages = validatePages(body.pages, allowed);
  if (pages.error) return { error: pages.error };
  if (body.scope === "page" && pages.pages.length !== 1) return { error: "\"This page\" is one page." };
  pages.pages.forEach(function (k) { pageThemes[k] = body.theme_id; });
  return { prefs: { default_theme_id: main, page_themes: pageThemes } };
}

/* POST /api/themes/reset. scope "all" puts everything back to the original;
   "page" / "pages" puts those pages back on the main theme. */
function resetScope(prefs, body, allowed, ownedIds) {
  body = body || {};
  if (SCOPES.indexOf(body.scope) === -1) return { error: "scope must be all, page or pages." };
  if (body.scope === "all") return { prefs: { default_theme_id: null, page_themes: {} } };
  var pages = validatePages(body.pages, allowed);
  if (pages.error) return { error: pages.error };
  if (body.scope === "page" && pages.pages.length !== 1) return { error: "\"This page\" is one page." };
  var pageThemes = cleanPageThemes(prefs && prefs.page_themes, allowed, ownedIds);
  pages.pages.forEach(function (k) { delete pageThemes[k]; });
  var main = prefs && ownedIds.indexOf(prefs.default_theme_id) !== -1 ? prefs.default_theme_id : null;
  return { prefs: { default_theme_id: main, page_themes: pageThemes } };
}

/* Which theme a page wears: its own, else the main one, else none (today's look). */
function themeIdFor(prefs, pageKey) {
  var own = prefs && prefs.page_themes && prefs.page_themes[pageKey];
  return own || (prefs && prefs.default_theme_id) || null;
}

/* What a photo's first bytes say it is: "jpg", "png", "webp" or null. The
   declared type must agree with it, and the size must be within the limit. */
function sniffPhoto(buffer) {
  if (!buffer || buffer.length < 12) return null;
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return "jpg";
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47 &&
      buffer[4] === 0x0d && buffer[5] === 0x0a && buffer[6] === 0x1a && buffer[7] === 0x0a) return "png";
  if (buffer.toString("ascii", 0, 4) === "RIFF" && buffer.toString("ascii", 8, 12) === "WEBP") return "webp";
  return null;
}
var PHOTO_TYPES = { "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp" };
function checkPhoto(file) {
  if (!file || !file.buffer) return { error: "Choose a photo." };
  if (file.buffer.length > PHOTO_MAX_BYTES) return { error: "A backdrop photo is at most 5 MB." };
  var declared = PHOTO_TYPES[file.mimetype];
  if (!declared) return { error: "A backdrop photo must be a JPEG, PNG or WebP." };
  var actual = sniffPhoto(file.buffer);
  if (actual !== declared) return { error: "That file is not the JPEG, PNG or WebP it says it is." };
  return { ext: actual, contentType: file.mimetype };
}
function photoPathFor(userId, nowMs, ext) {
  return PHOTO_FOLDER + "/" + String(userId).toLowerCase() + "/" + String(nowMs) + "." + ext;
}

/* The photos the member's themes still use; any other theme photo is unused. */
function photosIn(rows) {
  var out = [];
  (rows || []).forEach(function (r) { var p = r && r.theme && r.theme.photo; if (p && out.indexOf(p) === -1) out.push(p); });
  return out;
}

module.exports = {
  THEME_VERSION: THEME_VERSION,
  MAX_THEMES: MAX_THEMES,
  NAME_MAX: NAME_MAX,
  PHOTO_MAX_BYTES: PHOTO_MAX_BYTES,
  PHOTO_FOLDER: PHOTO_FOLDER,
  DEFAULT_THEME: DEFAULT_THEME,
  UNTHEMED: UNTHEMED,
  SCOPES: SCOPES,
  ownPhotoPath: ownPhotoPath,
  validateTheme: validateTheme,
  validateName: validateName,
  themedPages: themedPages,
  GROUPS: GROUPS,
  themedPageList: themedPageList,
  validatePages: validatePages,
  cleanPageThemes: cleanPageThemes,
  applyScope: applyScope,
  resetScope: resetScope,
  themeIdFor: themeIdFor,
  sniffPhoto: sniffPhoto,
  checkPhoto: checkPhoto,
  photoPathFor: photoPathFor,
  photosIn: photosIn
};
