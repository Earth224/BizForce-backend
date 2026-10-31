/* ══════════════════════════════════════════════════════════════════════════
   lib/profileDesign.js — how a member's public profile page looks, and the
   closed schema every saved design is held to (migration 156,
   bf_profiles.profile_design).

   A member designs their public profile in "Customise profile" on their own
   profile page: the page's theme, the banner, the profile photo, one of five
   layouts, the order of the sections and which are shown, and how the grid
   and the videos are laid out and ordered. Visitors see exactly that, on the
   profile, the support page and the storefront.

   THE DESIGN IS CLOSED. These keys and no others, each checked for exactly
   what it may hold. An enum outside its list, a key not on the list, a colour
   that is not six lowercase hex digits, a media path outside the member's own
   folder, or any string that is not one of the listed words is REFUSED, not
   cleaned, and the refusal names the key. Numbers out of range are clamped,
   the one kind of repair made. There is no raw CSS, no HTML and no URL
   anywhere in it: the page renders a design by mapping each value to a class
   or a token it already has, never by writing a member's string into style
   or markup.

     v            1
     theme        null (the page's own look), or a whole theme, validated by
                  lib/themes.js validateTheme exactly as a saved theme is: the
                  corners, the middle tone, opacity, size, the photo backdrop
                  with the photo editor, the Alive corners motion and every
                  element colour. Its photo, if any, is the member's own
                  theme-photos/<their id>/<digits>.(jpg|png|webp).
     layout       "standard" (today's page, the default) | "classic" (centred) |
                  "split" (split hero, the photo on the left) | "magazine" (a big
                  banner with the photo overlapping it) | "minimal" (text first)
     banner       height    "s" | "m" | "l" | "full" | "custom"
                  custom_px number 120 … 640 (used when height is "custom")
                  focus_x,
                  focus_y   number 0 … 100: the banner image's focal point, %
                  zoom      number 100 … 300 (%)
                  overlay   number 0 … 0.85: how dark the overlay is
                  feather   number 0 … 50: feathered edges, % of each side
     photo        size      "s" | "m" | "l" | "xl"
                  shape     "circle" | "rounded" | "square" | "hexagon" |
                            "octagon" | "shield" | "diamond" | "blob"
                  ring      "none" | "solid" | "gradient"
                  ring_width number 0 … 12 (px)
                  ring_glow  number 0 … 1
                  ring_color "#rrggbb" (the solid ring)
     sections     a list of { key, show }, every key once, in the order shown:
                  "links" | "about" | "support" | "listings" | "grid" |
                  "videos" | "music"; show true | false. A key left out is
                  added at the end, shown; a key twice is refused.
     grid         columns   2 | 3 | 4
                  style     "square" | "portrait" | "masonry"
                  gap       "s" | "m" | "l"
                  order     up to 200 item ids (uuids), the grid's order
     videos       layout    "carousel" | "grid"
                  featured  true | false: the first video large
                  order     up to 100 video ids (uuids), the lineup's order

   A part left out gets its default (DEFAULT_DESIGN). The orders hold ids
   only; on save the server keeps just the member's own items' ids, so a
   design can never name another member's work.

   NOTHING HERE TALKS TO THE DATABASE OR THE NETWORK: pure functions, so
   scripts/checkProfileDesign.js runs all of it directly.
   ══════════════════════════════════════════════════════════════════════════ */
var themes = require("./themes");

var DESIGN_VERSION = 1;
var HEX = /^#[0-9a-f]{6}$/;
var UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
var LAYOUTS = ["standard", "classic", "split", "magazine", "minimal"];
var BANNER_HEIGHTS = ["s", "m", "l", "full", "custom"];
var PHOTO_SIZES = ["s", "m", "l", "xl"];
var SHAPES = ["circle", "rounded", "square", "hexagon", "octagon", "shield", "diamond", "blob"];
var RINGS = ["none", "solid", "gradient"];
var SECTIONS = ["links", "about", "support", "listings", "grid", "videos", "music"];
var GRID_COLUMNS = [2, 3, 4];
var GRID_STYLES = ["square", "portrait", "masonry"];
var GAPS = ["s", "m", "l"];
var VIDEO_LAYOUTS = ["carousel", "grid"];
var GRID_ORDER_MAX = 200;
var VIDEO_ORDER_MAX = 100;
/* The stored JSON's ceiling, the migration's CHECK as well. */
var DESIGN_MAX_BYTES = 16384;

var DEFAULT_DESIGN = {
  v: DESIGN_VERSION,
  theme: null,
  layout: "standard",
  banner: { height: "m", custom_px: 300, focus_x: 50, focus_y: 50, zoom: 100, overlay: 0.35, feather: 0 },
  photo: { size: "m", shape: "circle", ring: "solid", ring_width: 3, ring_glow: 0.5, ring_color: "#22d3ee" },
  sections: SECTIONS.map(function (k) { return { key: k, show: true }; }),
  grid: { columns: 3, style: "square", gap: "m", order: [] },
  videos: { layout: "grid", featured: false, order: [] }
};

/* What each part may hold: an enum list, { range: [min, max] }, "hex",
   "bool" or "ids". */
var PARTS = {
  banner: { height: BANNER_HEIGHTS, custom_px: { range: [120, 640] }, focus_x: { range: [0, 100] }, focus_y: { range: [0, 100] },
    zoom: { range: [100, 300] }, overlay: { range: [0, 0.85] }, feather: { range: [0, 50] } },
  photo: { size: PHOTO_SIZES, shape: SHAPES, ring: RINGS, ring_width: { range: [0, 12] }, ring_glow: { range: [0, 1] }, ring_color: "hex" },
  grid: { columns: GRID_COLUMNS, style: GRID_STYLES, gap: GAPS, order: "ids" },
  videos: { layout: VIDEO_LAYOUTS, featured: "bool", order: "ids" }
};
var ORDER_MAX = { grid: GRID_ORDER_MAX, videos: VIDEO_ORDER_MAX };
var TOP_KEYS = ["v", "theme", "layout", "banner", "photo", "sections", "grid", "videos"];

function clone(x) { return JSON.parse(JSON.stringify(x)); }
function isObject(x) { return !!x && typeof x === "object" && !Array.isArray(x); }
function has(o, k) { return Object.prototype.hasOwnProperty.call(o, k); }
function refuse(error, key) { return { error: error, key: key }; }
function clampNumber(value, range) {
  if (typeof value !== "number" || !isFinite(value)) return null;
  var n = Math.min(range[1], Math.max(range[0], value));
  return Math.round(n * 1000) / 1000;
}

function checkPart(name, input, userId, ownIds) {
  var rules = PARTS[name], out = clone(DEFAULT_DESIGN[name]);
  if (input === undefined) return { value: out };
  if (!isObject(input)) return refuse(name + " must be an object.", name);
  var unknown = Object.keys(input).filter(function (k) { return !has(rules, k); });
  if (unknown.length) return refuse("Unknown " + name + " key: " + unknown[0] + ".", name + "." + unknown[0]);
  var keys = Object.keys(rules);
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i], rule = rules[k], key = name + "." + k;
    if (!has(input, k)) continue;
    var value = input[k];
    if (rule && rule.range) {
      value = clampNumber(value, rule.range);
      if (value === null) return refuse(key + " must be a number.", key);
    } else if (Array.isArray(rule)) {
      if (rule.indexOf(value) === -1) return refuse(key + " must be one of " + rule.join(", ") + ".", key);
    } else if (rule === "hex") {
      if (typeof value !== "string" || !HEX.test(value)) return refuse(key + " must be a colour like #1a2b3c.", key);
    } else if (rule === "bool") {
      if (typeof value !== "boolean") return refuse(key + " must be true or false.", key);
    } else if (rule === "ids") {
      if (!Array.isArray(value)) return refuse(key + " must be a list of item ids.", key);
      if (value.length > ORDER_MAX[name]) return refuse(key + " holds at most " + ORDER_MAX[name] + " items.", key);
      var seen = [];
      for (var j = 0; j < value.length; j++) {
        if (typeof value[j] !== "string" || !UUID.test(value[j])) return refuse(key + " must hold item ids only.", key);
        if (seen.indexOf(value[j]) === -1) seen.push(value[j]);
      }
      /* The server passes the member's own item ids; any other id is dropped. */
      if (ownIds && Array.isArray(ownIds[name])) seen = seen.filter(function (id) { return ownIds[name].indexOf(id) !== -1; });
      value = seen;
    }
    out[k] = value;
  }
  return { value: out };
}

function checkSections(input) {
  if (input === undefined) return { value: clone(DEFAULT_DESIGN.sections) };
  if (!Array.isArray(input)) return refuse("sections must be a list.", "sections");
  if (input.length > SECTIONS.length) return refuse("sections lists each section once.", "sections");
  var out = [], seen = [];
  for (var i = 0; i < input.length; i++) {
    var s = input[i];
    if (!isObject(s)) return refuse("Each section must be an object.", "sections");
    var extra = Object.keys(s).filter(function (k) { return k !== "key" && k !== "show"; });
    if (extra.length) return refuse("Unknown section key: " + extra[0] + ".", "sections." + extra[0]);
    if (SECTIONS.indexOf(s.key) === -1) return refuse("sections key must be one of " + SECTIONS.join(", ") + ".", "sections.key");
    if (seen.indexOf(s.key) !== -1) return refuse("sections lists " + s.key + " twice.", "sections.key");
    var show = has(s, "show") ? s.show : true;
    if (typeof show !== "boolean") return refuse("sections show must be true or false.", "sections.show");
    seen.push(s.key);
    out.push({ key: s.key, show: show });
  }
  SECTIONS.forEach(function (k) { if (seen.indexOf(k) === -1) out.push({ key: k, show: true }); });
  return { value: out };
}

/* One design from a request body: { design } or { error, key }. `ownIds`
   ({ grid: [...], videos: [...] }) keeps only the member's own items in the
   orders; leave it out where it is not known (a stored design read back). */
function validateDesign(input, userId, ownIds) {
  if (!isObject(input)) return refuse("A profile design must be an object.", null);
  var unknown = Object.keys(input).filter(function (k) { return TOP_KEYS.indexOf(k) === -1; });
  if (unknown.length) return refuse("Unknown profile design key: " + unknown[0] + ".", unknown[0]);
  if (has(input, "v") && input.v !== DESIGN_VERSION) return refuse("v must be " + DESIGN_VERSION + ".", "v");
  var out = { v: DESIGN_VERSION };
  if (!has(input, "theme") || input.theme === null) out.theme = null;
  else {
    var t = themes.validateTheme(input.theme, userId);
    if (t.error) return refuse("theme: " + t.error, "theme" + (t.key ? "." + t.key : ""));
    out.theme = t.theme;
  }
  var layout = has(input, "layout") ? input.layout : DEFAULT_DESIGN.layout;
  if (LAYOUTS.indexOf(layout) === -1) return refuse("layout must be one of " + LAYOUTS.join(", ") + ".", "layout");
  out.layout = layout;
  var parts = ["banner", "photo"];
  for (var i = 0; i < parts.length; i++) {
    var p = checkPart(parts[i], input[parts[i]], userId, ownIds);
    if (p.error) return p;
    out[parts[i]] = p.value;
  }
  var sec = checkSections(input.sections);
  if (sec.error) return sec;
  out.sections = sec.value;
  var rest = ["grid", "videos"];
  for (var r = 0; r < rest.length; r++) {
    var q = checkPart(rest[r], input[rest[r]], userId, ownIds);
    if (q.error) return q;
    out[rest[r]] = q.value;
  }
  if (Buffer.byteLength(JSON.stringify(out), "utf8") > DESIGN_MAX_BYTES) return refuse("That design is too large to save.", null);
  return { design: out };
}

/* What the public may see of a stored design: the design re-validated, or
   null (the page's default look) when there is none or it no longer passes.
   Nothing else of the column goes out. */
function publicDesign(stored, userId) {
  if (stored === null || stored === undefined) return null;
  var checked = validateDesign(stored, userId);
  return checked.error ? null : checked.design;
}

/* The member's own theme photo a design wears, or null. */
function photoOf(design) {
  return design && design.theme && design.theme.middle === "photo" && design.theme.photo ? design.theme.photo : null;
}

module.exports = {
  DESIGN_VERSION: DESIGN_VERSION,
  DESIGN_MAX_BYTES: DESIGN_MAX_BYTES,
  DEFAULT_DESIGN: DEFAULT_DESIGN,
  LAYOUTS: LAYOUTS,
  BANNER_HEIGHTS: BANNER_HEIGHTS,
  PHOTO_SIZES: PHOTO_SIZES,
  SHAPES: SHAPES,
  RINGS: RINGS,
  SECTIONS: SECTIONS,
  GRID_COLUMNS: GRID_COLUMNS,
  GRID_STYLES: GRID_STYLES,
  GAPS: GAPS,
  VIDEO_LAYOUTS: VIDEO_LAYOUTS,
  PARTS: PARTS,
  TOP_KEYS: TOP_KEYS,
  validateDesign: validateDesign,
  publicDesign: publicDesign,
  photoOf: photoOf
};
