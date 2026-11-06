// ── A member's digital card page: bizforceai.net/c/<slug> and /card/<token> ──
//
// SERVED BY THE BACKEND, HEAD ONLY. Netlify proxies /c/:slug and /card/:token
// here (the frontend's _redirects). The BODY is the frontend's own
// card-view.html, unchanged: the page still draws the card in the browser
// from GET /api/cards/slug/:slug or GET /api/cards/share/:token. Only the
// HEAD is built here, so a link pasted into a message previews with the
// member's name, title and photo: crawlers do not run the page's script.
//
// THE SHELL reaches the backend as a generated file, lib/cardShell.generated.js,
// written by scripts/buildCardShell.js from the frontend's card-view.html and
// the "/*" block of its _headers. The frontend is the source; the generated
// copy is what this file serves. `node scripts/buildCardShell.js --check`
// fails when the copy differs, and scripts/checkCardUpgrades.js holds the two
// equal.
//
// WHAT THE HEAD SAYS, and nothing else: the card's name (og:title), its job
// title and company (the description, at most 200 characters), its public
// URL (canonical and og:url), and the owner's photo only when the card shows
// it and it is an https address, else BizForce's icon. Never the email or the
// phone. robots is noindex unless the member let search engines find the card.
// Every value is HTML-escaped.
//
// COUNTING stores nothing about a visitor. isCountableRequest reads the
// request's method and User-Agent at request time to leave out HEAD requests,
// requests with no User-Agent and the bots, link previewers and scripts named
// in BOT_RE; the User-Agent is never stored or logged. A count is one integer
// added to a per-card, per-UTC-day row (migration 171, bump_card_count).

var links = require("./supportLinks");
var GENERATED = require("./cardShell.generated");

var esc = links.escapeHtml;
var CARD_SITE = "https://bizforceai.net";
var DEFAULT_IMAGE = CARD_SITE + "/icons/icon-512.png";

var BOT_RE = /bot|crawl|spider|slurp|preview|facebookexternalhit|embedly|slack|twitter|discord|whatsapp|telegram|linkedin|skype|headless|curl|wget|python|go-http|java|okhttp|axios|node-fetch|libwww/i;

/* The six counters of card_view_counts, exactly migration 171's list. */
var COUNT_KINDS = ["views", "qr_views", "tel_taps", "email_taps", "save_taps", "support_taps"];
/* What the card page may report a tap of, and the counter each one adds to. */
var TAP_KINDS = { tel: "tel_taps", email: "email_taps", save: "save_taps", support: "support_taps" };
/* A share token as POST /api/digital-cards makes it: 16 random bytes, hex. */
var CARD_TOKEN_RE = /^[0-9a-f]{32}$/;

var MEDIA_URL_MAX = 500;
var MEDIA_URL_BAD = /[\s"'()\\<>]/;
var MEDIA_LAYOUT_MAX_BYTES = 4096;
var STATS_DAYS = 30;
var DAY_MS = 24 * 60 * 60 * 1000;

/* ── counting ───────────────────────────────────────────────────────────── */

/* True for a GET (a page view) or a POST (a tap) from something that says it
   is a browser. HEAD, no User-Agent, or a User-Agent BOT_RE matches: false. */
function isCountableRequest(req) {
  if (!req || (req.method !== "GET" && req.method !== "POST")) return false;
  var ua = req.headers ? req.headers["user-agent"] : undefined;
  if (typeof ua !== "string" || ua.trim() === "") return false;
  return !BOT_RE.test(ua);
}

/* The counter a tap kind adds to, or null for anything else. */
function tapColumn(kind) {
  return typeof kind === "string" && Object.prototype.hasOwnProperty.call(TAP_KINDS, kind) ? TAP_KINDS[kind] : null;
}

/* ── card media links ───────────────────────────────────────────────────── */

/* An https URL of at most 500 characters that new URL parses, holding no
   whitespace, quotes, parentheses, backslashes or angle brackets. Nothing in
   it can end a quoted CSS url("...") or an HTML attribute. */
function isSafeMediaUrl(value) {
  if (typeof value !== "string" || value.length > MEDIA_URL_MAX || value.indexOf("https://") !== 0 || MEDIA_URL_BAD.test(value)) return false;
  try {
    var u = new URL(value);
    return u.protocol === "https:" && !!u.hostname;
  } catch (e) {
    return false;
  }
}

var MEDIA_LABELS = { video_url: "video", bg_image_url: "background image", still_image_url: "still image", audio_url: "audio" };

/* A POST or PUT value for one of the four media columns: empty clears it
   (null), a safe https URL is kept as sent, anything else is refused. */
function validateCardMediaUrl(value, column) {
  if (value === null || value === undefined || (typeof value === "string" && value.trim() === "")) return { value: null };
  if (isSafeMediaUrl(value)) return { value: value };
  return { error: "The card's " + (MEDIA_LABELS[column] || "media") + " link must be an https address of at most " + MEDIA_URL_MAX +
    " characters, with no spaces, quotes, brackets or backslashes. Nothing was saved." };
}

/* ── media_layout ───────────────────────────────────────────────────────── */

var FONTS = ["default", "orbitron", "exo2", "rajdhani", "audiowide", "syncopate", "cormorant", "playfair", "cinzel", "imfell", "baskerville",
  "bebas", "oswald", "anton", "blackhan", "righteous", "dancing", "pacifico", "lobster", "satisfy", "greatvibes", "montserrat", "raleway",
  "poppins", "nunito", "lato", "courier", "vt323", "pressstart", "permanentmarker", "russoone", "bungee"];
var TEXT_KEYS = ["company", "name", "title", "tagline"];

function num(min, max) { return { type: "number", min: min, max: max }; }
function oneOf(list) { return { type: "enum", values: list }; }
var STRING = { type: "string", max: 200 };
var COLOR = { type: "color" };
var COLOR_OR_EMPTY = { type: "color", empty: true };
var BOOLEAN = { type: "boolean" };

/* Every key digital-cards.html writes (getFields) and digital-cards.html and
   card-view.html read, with the type and the range the editor's controls
   produce. bf-card.js reads none. Any other key is dropped. */
var MEDIA_LAYOUT_ALLOWLIST = {
  bg_pos_x: num(0, 100), bg_pos_y: num(0, 100), bg_zoom: num(100, 200), bg_fit: oneOf(["cover", "contain", "fill", "zoom"]),
  vid_pos_x: num(0, 100), vid_pos_y: num(0, 100), vid_scale: num(100, 200),
  card_font: oneOf(FONTS), text_color: COLOR_OR_EMPTY, accent_color: COLOR_OR_EMPTY,
  card_layout: oneOf(["classic", "centered", "minimal"]), bg_overlay: num(0, 100),
  border_style: oneOf(["none", "glow", "neon-pulse", "gold", "holo-rainbow"]), border_weight: oneOf(["12px", "16px", "20px", "28px"]),
  audio_track_name: STRING, orientation: oneOf(["horizontal", "vertical"]),
  vid_transition: oneOf(["fade", "blur-dissolve", "iris", "glitch", "swipe-left", "swipe-up", "zoom-in", "color-burn", "matrix", "shatter"]),
  tagline: STRING, still_bg_color: COLOR, still_overlay: num(0, 100),
  still_img_pos_x: num(0, 100), still_img_pos_y: num(0, 100), still_img_zoom: num(100, 300), still_img_mode: oneOf(["fill", "fit", "center"]),
  trim_start: num(0, 3600), trim_end: num(0, 3600), still_text_visible: BOOLEAN, card_bg_color: COLOR,
  text_positions: { type: "positions" }, text_sizes: { type: "sizes" }, free_position_mode: BOOLEAN,
  divider_style: oneOf(["none", "straight", "double", "dashed", "dotted", "diamond", "star", "ornate", "wave", "zigzag", "arrow", "bracket", "fleur"]),
  text_effect: oneOf(["none", "shadow", "outline", "glow", "emboss", "gradient"]),
  card_texture: oneOf(["none", "carbon", "metal", "leather", "marble", "circuit", "holo", "linen", "glass"]),
  corner_style: oneOf(["rounded", "sharp", "cut", "scalloped", "pillow"])
};

function plainObject(v) { return !!v && typeof v === "object" && !Array.isArray(v); }

function numberIn(v, min, max) {
  var n = typeof v === "number" ? v : (typeof v === "string" && /^-?\d+(\.\d+)?$/.test(v) ? Number(v) : NaN);
  return isFinite(n) && n >= min && n <= max ? n : undefined;
}

function cleanValue(rule, v) {
  if (rule.type === "number") return numberIn(v, rule.min, rule.max);
  if (rule.type === "enum") return typeof v === "string" && rule.values.indexOf(v) !== -1 ? v : undefined;
  if (rule.type === "string") return typeof v === "string" ? v.slice(0, rule.max) : undefined;
  if (rule.type === "color") return typeof v === "string" && (/^#[0-9a-fA-F]{6}$/.test(v) || (rule.empty && v === "")) ? v : undefined;
  if (rule.type === "boolean") return typeof v === "boolean" ? v : undefined;
  if (rule.type === "positions" || rule.type === "sizes") {
    if (!plainObject(v)) return undefined;
    var out = {}, any = false;
    TEXT_KEYS.forEach(function (k) {
      if (!Object.prototype.hasOwnProperty.call(v, k)) return;
      var c;
      if (rule.type === "sizes") c = numberIn(v[k], 6, 52);
      else if (plainObject(v[k])) {
        var x = numberIn(v[k].x, 0, 100), y = numberIn(v[k].y, 0, 100);
        c = x === undefined || y === undefined ? undefined : { x: x, y: y };
      }
      if (c !== undefined) { out[k] = c; any = true; }
    });
    return any ? out : undefined;
  }
  return undefined;
}

/* { value } with every allowed key kept that has a valid value and everything
   else dropped, or { error } when what was sent is over 4 KB serialized.
   Anything that is not an object is {}. */
function sanitizeMediaLayout(raw) {
  if (!plainObject(raw)) return { value: {} };
  var sent;
  try { sent = JSON.stringify(raw); } catch (e) { return { error: "The card's design settings could not be read. Nothing was saved." }; }
  if (Buffer.byteLength(sent, "utf8") > MEDIA_LAYOUT_MAX_BYTES) {
    return { error: "The card's design settings are larger than " + MEDIA_LAYOUT_MAX_BYTES + " bytes. Nothing was saved." };
  }
  var out = {};
  Object.keys(MEDIA_LAYOUT_ALLOWLIST).forEach(function (k) {
    if (!Object.prototype.hasOwnProperty.call(raw, k)) return;
    var c = cleanValue(MEDIA_LAYOUT_ALLOWLIST[k], raw[k]);
    if (c !== undefined) out[k] = c;
  });
  return { value: out };
}

/* ── the head ───────────────────────────────────────────────────────────── */

function imageOf(url) {
  return typeof url === "string" && /^https:\/\/[^\s"'<>]+$/.test(url) && url.length <= MEDIA_URL_MAX ? url : null;
}

function cardName(card) {
  return String(card.full_name || card.company || "Business Card").slice(0, 200);
}

/* The job title and the company, and nothing else. */
function cardDescription(card) {
  var parts = [String(card.job_title || "").trim(), String(card.company || "").trim()].filter(Boolean);
  var d = parts.length ? parts.join(" at ") : "A digital business card made with BizForce AI.";
  return d.length > 200 ? d.slice(0, 199) + "…" : d;
}

/* card: { full_name, job_title, company, public_url, photo_url, show_photo,
   discoverable }. Returns the head's tags as lines. */
function renderCardHead(card) {
  var name = cardName(card);
  var title = name + (card.full_name && card.company ? " — " + String(card.company).slice(0, 200) : "") + " — BizForce AI Card";
  var desc = cardDescription(card);
  var url = card.public_url || CARD_SITE + "/card-view.html";
  var image = (card.show_photo === true && imageOf(card.photo_url)) || DEFAULT_IMAGE;
  var robots = card.discoverable === true ? "index, follow" : "noindex";
  return [
    '  <title>' + esc(title) + '</title>',
    '  <meta name="description" content="' + esc(desc) + '"/>',
    '  <meta name="robots" content="' + robots + '"/>',
    '  <link rel="canonical" href="' + esc(url) + '"/>',
    '  <meta property="og:type" content="profile"/>',
    '  <meta property="og:site_name" content="BizForce AI"/>',
    '  <meta property="og:title" content="' + esc(name) + '"/>',
    '  <meta property="og:description" content="' + esc(desc) + '"/>',
    '  <meta property="og:url" content="' + esc(url) + '"/>',
    '  <meta property="og:image" content="' + esc(image) + '"/>',
    '  <meta name="twitter:card" content="summary"/>',
    '  <meta name="twitter:title" content="' + esc(name) + '"/>',
    '  <meta name="twitter:description" content="' + esc(desc) + '"/>',
    '  <meta name="twitter:image" content="' + esc(image) + '"/>'
  ];
}

/* The shell split around its static head tags: from the <title> line through
   the og:url line. Each must be there exactly once, or this throws at load,
   and no card page is served from a shell it does not understand. */
function splitShell(shell) {
  var text = String(shell || "");
  var t = text.indexOf("\n  <title>"), og = text.indexOf('<meta property="og:url"');
  if (t === -1 || og === -1 || text.indexOf("\n  <title>", t + 1) !== -1 || text.indexOf('<meta property="og:url"', og + 1) !== -1 || og < t) {
    throw new Error("card-view.html shell: expected one <title> line and one og:url line in its head");
  }
  var end = text.indexOf("\n", og);
  return { before: text.slice(0, t + 1), after: text.slice(end + 1) };
}

var SHELL = splitShell(GENERATED.SHELL);

function renderCardPage(card) {
  return SHELL.before + renderCardHead(card).join("\n") + "\n" + SHELL.after;
}

function renderNotFound() {
  return [
    '<!DOCTYPE html>',
    '<html lang="en">',
    '<head>',
    '  <meta charset="UTF-8"/>',
    '  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>',
    '  <title>Card not found — BizForce AI</title>',
    '  <meta name="robots" content="noindex"/>',
    '  <style>body{margin:0;background:#070b18;color:#e8e8ff;font:15px/1.55 system-ui,-apple-system,"Segoe UI",Arial,sans-serif}main{max-width:560px;margin:0 auto;padding:64px 16px;text-align:center}a{color:#22d3ee}</style>',
    '</head>',
    '<body>',
    '<main id="cardNotFound">',
    '  <h1>Card not found</h1>',
    '  <p>This link may be invalid or the card was removed.</p>',
    '  <p><a href="/">BizForce AI</a></p>',
    '</main>',
    '</body>',
    '</html>',
    ''
  ].join("\n");
}

/* The headers every card page answer carries: the frontend's own security
   headers for every page (its _headers "/*" block, generated), plus no-store,
   so every view reaches the counter and no cache keeps a lapsed card. */
function pageHeaders() {
  var out = {};
  Object.keys(GENERATED.HEADERS).forEach(function (k) { out[k] = GENERATED.HEADERS[k]; });
  out["Content-Type"] = "text/html; charset=utf-8";
  out["Cache-Control"] = "no-store";
  return out;
}

/* ── stats ──────────────────────────────────────────────────────────────── */

/* The last 30 UTC days, oldest first, ending today. */
function statsDays(now) {
  var d = now instanceof Date ? now : new Date(now || Date.now());
  var today = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
  var days = [];
  for (var i = STATS_DAYS - 1; i >= 0; i--) days.push(new Date(today - i * DAY_MS).toISOString().slice(0, 10));
  return days;
}

function emptyCounts() {
  var c = {};
  COUNT_KINDS.forEach(function (k) { c[k] = 0; });
  return c;
}

/* { days: 30 x { day, views, qr_views, tel_taps, email_taps, save_taps,
   support_taps }, every day present (a day with no row is zeros),
   totals: { last_7_days, last_30_days } }. Rows outside the 30 days are
   ignored. */
function buildStats(rows, now) {
  var byDay = {};
  (rows || []).forEach(function (r) {
    if (!r || typeof r.day !== "string") return;
    byDay[r.day.slice(0, 10)] = r;
  });
  var list = statsDays(now).map(function (day) {
    var r = byDay[day] || {}, out = { day: day };
    COUNT_KINDS.forEach(function (k) { var n = Number(r[k]); out[k] = isFinite(n) && n > 0 ? Math.floor(n) : 0; });
    return out;
  });
  var t7 = emptyCounts(), t30 = emptyCounts();
  list.forEach(function (d, i) {
    COUNT_KINDS.forEach(function (k) {
      t30[k] += d[k];
      if (i >= list.length - 7) t7[k] += d[k];
    });
  });
  return { days: list, totals: { last_7_days: t7, last_30_days: t30 } };
}

module.exports = {
  CARD_SITE, DEFAULT_IMAGE, BOT_RE, COUNT_KINDS, TAP_KINDS, CARD_TOKEN_RE, MEDIA_URL_MAX, MEDIA_LAYOUT_MAX_BYTES, STATS_DAYS,
  MEDIA_LAYOUT_ALLOWLIST, FONTS,
  isCountableRequest, tapColumn, isSafeMediaUrl, validateCardMediaUrl, sanitizeMediaLayout,
  cardDescription, renderCardHead, splitShell, renderCardPage, renderNotFound, pageHeaders, statsDays, buildStats
};
