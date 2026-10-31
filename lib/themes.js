/* ══════════════════════════════════════════════════════════════════════════
   lib/themes.js — a member's saved looks, which page wears which, and the
   closed schema every saved look is held to (migration 154).

   A THEME is five things a member picks in Settings → Theme: the top-left
   glow, the bottom-right glow, the middle backdrop (black, a colour, or their
   own photo with a dim), and whether the glows drift ("Alive corners"); and,
   since Block 4b, the colours of every other part of the look: the buttons,
   Termaximus's mist, the chat box's glow, the guide's lettering and the
   wordmark. It is stored as JSON in member_themes.theme, and the JSON is
   CLOSED: these keys and no others, each checked for exactly what it may hold.
   A theme saved before a key existed gets that key's default when read.

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

   and the ELEMENT PALETTES (Block 4b), each "#rrggbb" like the glows:

     btn_a, btn_b        a button's gradient, start and end
     btn_text            its lettering
     mist_core           Termaximus's star-heart and its bloom
     mist_haze           the three dark blobs it is made of
     mist_pulse          its slow inner colour cycle
     mist_spark          the gold sparkle stars
     mist_star           the white sparkle stars
     mist_dust           the gold streaks and dust
     mist_trail          the shooting star
     mist_whisper        the whispered word
     chat_glow_a, _b     the pulsing glow behind the chat box, inner and outer
     guide_a, guide_b    the guide's gradient lettering
     mark_a, mark_b      the "BizForce AI" wordmark's gradient
     match_all           true | false: "Match everything"

   MATCH EVERYTHING. With match_all on, every element colour above is DERIVED
   from the two corner glows, A (glow_a) and B (glow_b), by matchAll() below,
   and whatever the request held for them is replaced by the derived values;
   so the server and the page always agree on what a theme looks like. With it
   off, the values are kept as saved, so the derived colours are the starting
   point for tuning by hand. The rule, where mix(x, y, w) moves x a share w of
   the way to y in each sRGB channel (rounded), and W is white:
     buttons        A → B, lettering white (readability may change it)
     wordmark       A → B
     guide text     mix(A, W, .35) → mix(B, W, .35)
     chat glow      A inner, B outer
     mist           core A; haze B; pulse mix(mix(A, B, .5), W, .3);
                    gold sparks mix(A, W, .6); white stars mix(B, W, .85);
                    dust mix(B, W, .5); shooting star mix(A, W, .7);
                    whisper mix(B, W, .75)

   THREE-COLOUR SPECTRUMS, CORNERS, PHOTO AND MOTION (Block 4d), each a key of
   the same closed schema:

     glow_mid            the middle tone between corner A and corner B
     mid_auto            true | false: the middle tone is derived (midTone)
     glow_mid_alpha      number 0 … 1: a soft centre glow in the middle tone
                         (0, the default, shows none)
     glow_a_size,
     glow_b_size,
     glow_mid_size       number 10 … 100: how far each glow reaches, in % of
                         the page (38, 40 and 45 are today's)
     btn_mid, mark_mid, guide_mid, chat_glow_mid
                         each element gradient's middle stop
     accent_a, accent_mid, accent_b
                         "Headings and accents": every other place that drew
                         the original cyan and violet (titles, icon rings,
                         badges, chips, borders, glows, focus rings, links,
                         toggles, progress bars, tab underlines, charts)
     photo_fit           "fill" | "fit" | "custom"
     photo_zoom          number 50 … 300 (custom fit: the photo's width, in %)
     photo_x, photo_y    number 0 … 100: the focal point, in %
     photo_blur          number 0 … 20 (px)
     photo_feather       number 0 … 50: the blended edge's width, in % of each
                         side
     motion              "breathe" | "drift" | "aurora" | "nebula": the style
                         "Alive corners" moves in (breathe is the old drift)
     motion_speed        number 0.25 … 3 (1 is the style's own pace)
     motion_intensity    number 0 … 1 (0.6 is the default amplitude)

   MOVE WITH THE MUSIC (the music player, lib/music.js):

     music_move          true | false: while BizForce's own player plays, the
                         corners' motion follows the music (off by default;
                         it scales the Alive corners motion, so it needs it on)
     music_intensity     number 0 … 1: how strongly (0.6 by default)

   They draw nothing themselves and set no token: the page's engine
   (scripts/bf-theme.js) reads them to decide whether the player's live energy
   reaches setLiveEnergy. A legacy theme keeps them only when it sent them.

   The corner opacities glow_a_alpha and glow_b_alpha now run 0 … 1 (0 shows
   nothing, 1 is the colour itself at the glow's centre); "Strength" became
   "Opacity", the same number, so a saved theme reads the same.

   A MIDDLE STOP THAT IS ON THE LINE. Where a gradient's middle stop is the
   plain sRGB midpoint of its two ends (within 2 in each channel), it changes
   nothing: the page draws the two-stop gradient it always drew. So every
   default middle is that midpoint, and a theme saved before Block 4d (no
   glow_mid key: a LEGACY theme) has each missing middle set to its own ends'
   midpoint, its middle tone set the same way with mid_auto off, and its
   accents left at the original, even under Match everything. A legacy theme
   therefore draws exactly what it drew before, and it is stored as it came,
   without Block 4d's keys, so it stays legacy wherever it is read.

   THE MIDDLE TONE (midTone). The perceptual midpoint of A and B in OKLCH:
   lightness the mean of the two; chroma the mean, lifted by 15% so the
   middle never dulls toward grey; hue the midpoint along the shorter arc
   (a near-grey end, chroma under 0.02, gives no hue: the other end's is
   used, and two greys get no lift). The result is brought into sRGB by
   lowering its chroma, 0.002 at a time, and rounded to hex. With mid_auto on
   the middle tone is always this; turned off, the member's own is kept.

   Match everything, since Block 4d, also gives every middle and the accents
   from A, the middle tone M and B: btn_mid, mark_mid and chat_glow_mid M,
   guide_mid mix(M, W, .35), accents A, M and B, and the mist's pulse
   mix(M, W, .3) (for a legacy theme M is mix(A, B, .5), which is the old rule).
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
  alive: false,
  btn_a: "#06b6d4",
  btn_b: "#8b5cf6",
  btn_text: "#ffffff",
  mist_core: "#3c78ff",
  mist_haze: "#300c96",
  mist_pulse: "#500f6e",
  mist_spark: "#ffe896",
  mist_star: "#ffffff",
  mist_dust: "#f0c850",
  mist_trail: "#cddaff",
  mist_whisper: "#d7cdf5",
  chat_glow_a: "#00e5ff",
  chat_glow_b: "#7b2ff7",
  guide_a: "#22d3ee",
  guide_b: "#a855f7",
  mark_a: "#22d3ee",
  mark_b: "#a855f7",
  match_all: false,
  /* Block 4d. Every middle at its ends' sRGB midpoint (on the line, so it
     draws nothing new); the middle tone is midTone of the two default glows. */
  glow_mid: "#6eabff",
  mid_auto: true,
  glow_mid_alpha: 0,
  glow_a_size: 38,
  glow_b_size: 40,
  glow_mid_size: 45,
  btn_mid: "#4989e5",
  mark_mid: "#6594f3",
  guide_mid: "#6594f3",
  chat_glow_mid: "#3e8afb",
  accent_a: "#22d3ee",
  accent_mid: "#6594f3",
  accent_b: "#a855f7",
  photo_fit: "fill",
  photo_zoom: 100,
  photo_x: 50,
  photo_y: 50,
  photo_blur: 0,
  photo_feather: 0,
  motion: "breathe",
  motion_speed: 1,
  motion_intensity: 0.6,
  /* The music player (lib/music.js): the corners follow BizForce's own
     player while it plays, off by default. */
  music_move: false,
  music_intensity: 0.6
};
var KEYS = Object.keys(DEFAULT_THEME);
/* The keys Block 4d added: glow_mid … motion_intensity. */
var KEYS_4D = KEYS.slice(KEYS.indexOf("glow_mid"), KEYS.indexOf("motion_intensity") + 1);
/* The music player's two: kept on a legacy theme only when it sent them. */
var KEYS_MUSIC = ["music_move", "music_intensity"];
/* Each middle and the two ends it sits between. */
var MIDS = { btn_mid: ["btn_a", "btn_b"], mark_mid: ["mark_a", "mark_b"], guide_mid: ["guide_a", "guide_b"],
  chat_glow_mid: ["chat_glow_a", "chat_glow_b"], accent_mid: ["accent_a", "accent_b"] };
var ACCENT_KEYS = ["accent_a", "accent_mid", "accent_b"];
var FITS = ["fill", "fit", "custom"];
var MOTIONS = ["breathe", "drift", "aurora", "nebula"];

/* The element palettes, by the studio section each belongs to. A section at
   its original (every one of its keys at DEFAULT_THEME's value) sets no
   token, so each place in the app keeps the colour it has always had; the
   mist is taken colour by colour. */
var ELEMENTS = {
  buttons: ["btn_a", "btn_mid", "btn_b", "btn_text"],
  mist: ["mist_core", "mist_haze", "mist_pulse", "mist_spark", "mist_star", "mist_dust", "mist_trail", "mist_whisper"],
  chat: ["chat_glow_a", "chat_glow_mid", "chat_glow_b"],
  guide: ["guide_a", "guide_mid", "guide_b"],
  mark: ["mark_a", "mark_mid", "mark_b"],
  accent: ["accent_a", "accent_mid", "accent_b"]
};
var ELEMENT_KEYS = [].concat(ELEMENTS.buttons, ELEMENTS.mist, ELEMENTS.chat, ELEMENTS.guide, ELEMENTS.mark, ELEMENTS.accent);
var COLOUR_KEYS = ["glow_a", "glow_b", "bg", "glow_mid"].concat(ELEMENT_KEYS);

/* mix(x, y, w): x moved a share w of the way to y, per channel, rounded. */
function mixHex(x, y, w) {
  var a = [1, 3, 5].map(function (i) { return parseInt(x.slice(i, i + 2), 16); });
  var b = [1, 3, 5].map(function (i) { return parseInt(y.slice(i, i + 2), 16); });
  return "#" + a.map(function (c, i) {
    var v = Math.round(c + w * (b[i] - c));
    return (v < 16 ? "0" : "") + v.toString(16);
  }).join("");
}
/* ── OKLCH (Björn Ottosson's OKLab, in polar form) ─────────────────────────
   The same functions are in scripts/bf-theme.js; scripts/checkThemeSpectrums.js
   proves the two give the same answers. */
function toLinear(c) { c = c / 255; return c <= 0.04045 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4); }
function toGamma(x) { return x <= 0.0031308 ? 12.92 * x : 1.055 * Math.pow(x, 1 / 2.4) - 0.055; }
function oklabOf(hex) {
  var r = toLinear(parseInt(hex.slice(1, 3), 16)), g = toLinear(parseInt(hex.slice(3, 5), 16)), b = toLinear(parseInt(hex.slice(5, 7), 16));
  var l = Math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b);
  var m = Math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b);
  var s = Math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b);
  return [0.2104542553 * l + 0.7936177850 * m - 0.0040720468 * s,
    1.9779984951 * l - 2.4285922050 * m + 0.4505937099 * s,
    0.0259040371 * l + 0.7827717662 * m - 0.8086757660 * s];
}
function oklchOf(hex) {
  var p = oklabOf(hex), h = Math.atan2(p[2], p[1]) * 180 / Math.PI;
  return [p[0], Math.sqrt(p[1] * p[1] + p[2] * p[2]), h < 0 ? h + 360 : h];
}
function linearOfOklch(L, C, h) {
  var A = C * Math.cos(h * Math.PI / 180), B = C * Math.sin(h * Math.PI / 180);
  var l = L + 0.3963377774 * A + 0.2158037573 * B, m = L - 0.1055613458 * A - 0.0638541728 * B, s = L - 0.0894841775 * A - 1.2914855480 * B;
  l = l * l * l; m = m * m * m; s = s * s * s;
  return [4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
    -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
    -0.0041960863 * l - 0.7034186147 * m + 1.7076147010 * s];
}
/* An OKLCH colour as hex, its chroma lowered 0.002 at a time until it is in sRGB. */
function hexOfOklch(L, C, h) {
  var lin = linearOfOklch(L, C, h);
  while (C > 0 && lin.some(function (v) { return v < -0.0005 || v > 1.0005; })) { C = Math.max(0, C - 0.002); lin = linearOfOklch(L, C, h); }
  return "#" + lin.map(function (v) {
    var c = Math.round(Math.min(1, Math.max(0, toGamma(Math.min(1, Math.max(0, v))))) * 255);
    return (c < 16 ? "0" : "") + c.toString(16);
  }).join("");
}
/* The middle tone of A and B (the rule is in the header above). */
function midTone(a, b) {
  var p = oklchOf(a), q = oklchOf(b);
  var L = (p[0] + q[0]) / 2, C = (p[1] + q[1]) / 2, h;
  if (p[1] < 0.02 && q[1] < 0.02) h = p[2];
  else {
    C = C * 1.15;
    if (p[1] < 0.02) h = q[2];
    else if (q[1] < 0.02) h = p[2];
    else { var d = ((q[2] - p[2] + 540) % 360) - 180; h = (p[2] + d / 2 + 360) % 360; }
  }
  return hexOfOklch(L, C, h);
}
/* How far apart two colours are, in OKLab (the smoothness of a blend). */
function oklabDistance(x, y) {
  var p = oklabOf(x), q = oklabOf(y);
  return Math.sqrt(Math.pow(p[0] - q[0], 2) + Math.pow(p[1] - q[1], 2) + Math.pow(p[2] - q[2], 2));
}
/* Is `mid` the plain midpoint of `a` and `b` (within 2 in each channel)? */
function onTheLine(a, mid, b) {
  var line = mixHex(a, b, 0.5);
  return [1, 3, 5].every(function (i) { return Math.abs(parseInt(line.slice(i, i + 2), 16) - parseInt(mid.slice(i, i + 2), 16)) <= 2; });
}

/* "Match everything": every element colour from the two corners and the
   middle tone (the rule is in the header above; scripts/bf-theme.js has the
   same function). `mid` left out is mix(a, b, .5), the pre-4d rule. */
function matchAll(a, b, mid) {
  var W = "#ffffff";
  var m = mid || mixHex(a, b, 0.5);
  return {
    btn_a: a, btn_mid: m, btn_b: b, btn_text: W,
    mark_a: a, mark_mid: m, mark_b: b,
    guide_a: mixHex(a, W, 0.35), guide_mid: mixHex(m, W, 0.35), guide_b: mixHex(b, W, 0.35),
    chat_glow_a: a, chat_glow_mid: m, chat_glow_b: b,
    accent_a: a, accent_mid: m, accent_b: b,
    mist_core: a, mist_haze: b,
    mist_pulse: mixHex(m, W, 0.3),
    mist_spark: mixHex(a, W, 0.6),
    mist_star: mixHex(b, W, 0.85),
    mist_dust: mixHex(b, W, 0.5),
    mist_trail: mixHex(a, W, 0.7),
    mist_whisper: mixHex(b, W, 0.75)
  };
}
var RANGES = { glow_a_alpha: [0, 1], glow_b_alpha: [0, 1], dim: [0, 0.85], photo_luma: [0, 1],
  glow_mid_alpha: [0, 1], glow_a_size: [10, 100], glow_b_size: [10, 100], glow_mid_size: [10, 100],
  photo_zoom: [50, 300], photo_x: [0, 100], photo_y: [0, 100], photo_blur: [0, 20], photo_feather: [0, 50],
  motion_speed: [0.25, 3], motion_intensity: [0, 1], music_intensity: [0, 1] };

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
  var legacy = !Object.prototype.hasOwnProperty.call(input, "glow_mid");
  for (var i = 0; i < KEYS.length; i++) {
    var k = KEYS[i];
    var has = Object.prototype.hasOwnProperty.call(input, k);
    var value = has ? input[k] : DEFAULT_THEME[k];
    if (legacy && k === "mid_auto" && !has) value = false;
    if (k === "v") {
      if (value !== THEME_VERSION) return { error: "v must be " + THEME_VERSION + ".", key: k };
    } else if (COLOUR_KEYS.indexOf(k) !== -1) {
      if (typeof value !== "string" || !HEX.test(value)) return { error: k + " must be a colour like #1a2b3c.", key: k };
    } else if (RANGES[k]) {
      value = clampNumber(value, RANGES[k]);
      if (value === null) return { error: k + " must be a number.", key: k };
    } else if (k === "middle") {
      if (MIDDLES.indexOf(value) === -1) return { error: "middle must be black, colour or photo.", key: k };
    } else if (k === "photo") {
      if (value !== null && !ownPhotoPath(value, userId)) return { error: "photo must be a photo you uploaded.", key: k };
    } else if (k === "alive" || k === "match_all" || k === "mid_auto" || k === "music_move") {
      if (typeof value !== "boolean") return { error: k + " must be true or false.", key: k };
    } else if (k === "photo_fit") {
      if (FITS.indexOf(value) === -1) return { error: "photo_fit must be fill, fit or custom.", key: k };
    } else if (k === "motion") {
      if (MOTIONS.indexOf(value) === -1) return { error: "motion must be breathe, drift, aurora or nebula.", key: k };
    }
    out[k] = value;
  }
  /* A missing middle is its own ends' midpoint (on the line: nothing new
     drawn); a legacy theme's middle tone the same, kept as it is. */
  Object.keys(MIDS).forEach(function (mk) {
    if (!Object.prototype.hasOwnProperty.call(input, mk)) out[mk] = mixHex(out[MIDS[mk][0]], out[MIDS[mk][1]], 0.5);
  });
  if (legacy) out.glow_mid = mixHex(out.glow_a, out.glow_b, 0.5);
  if (out.middle === "photo" && !out.photo) return { error: "A photo backdrop needs a photo.", key: "photo" };
  derive(out, legacy);
  /* A legacy theme is stored as it came, without Block 4d's keys, so that
     wherever it is read again it is still legacy and draws what it drew. */
  if (legacy) KEYS_4D.forEach(function (k4) { delete out[k4]; });
  if (legacy) KEYS_MUSIC.forEach(function (km) { if (!Object.prototype.hasOwnProperty.call(input, km)) delete out[km]; });
  return { theme: out };
}
/* The derived colours: the middle tone (mid_auto), then Match everything. A
   legacy theme keeps its accents at the original. */
function derive(out, legacy) {
  if (out.mid_auto) out.glow_mid = midTone(out.glow_a, out.glow_b);
  if (out.match_all) {
    var derived = matchAll(out.glow_a, out.glow_b, out.glow_mid);
    Object.keys(derived).forEach(function (dk) { if (!(legacy && ACCENT_KEYS.indexOf(dk) !== -1)) out[dk] = derived[dk]; });
  }
  return out;
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
  ELEMENTS: ELEMENTS,
  ELEMENT_KEYS: ELEMENT_KEYS,
  mixHex: mixHex,
  matchAll: matchAll,
  oklchOf: oklchOf,
  oklabDistance: oklabDistance,
  hexOfOklch: hexOfOklch,
  midTone: midTone,
  onTheLine: onTheLine,
  MIDS: MIDS,
  FITS: FITS,
  MOTIONS: MOTIONS,
  RANGES: RANGES,
  KEYS_4D: KEYS_4D,
  KEYS_MUSIC: KEYS_MUSIC,
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
