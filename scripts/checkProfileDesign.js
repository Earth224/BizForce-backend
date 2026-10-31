"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkProfileDesign — a member designs their public profile, and visitors
   see exactly that design, held to a closed schema at every step.

   Backend "Profile designs: a closed, validated schema served with the
   public profile" (migration 156, lib/profileDesign.js, the routes in
   server.js) and frontend "Design your profile" (scripts/bf-profile-design.js,
   scripts/bf-profile-editor.js, profile.html, seller.html, the theme studio's
   "My public profile").

     A  the schema (lib/profileDesign.js, run directly): the default design
        passes; every enum is closed (five layouts, eight shapes, the banner
        heights, the photo sizes, the rings, the grid and video choices); an
        unknown key, raw CSS, HTML or a URL in any field, a colour that is not
        six lowercase hex digits, a duplicate section, and another member's
        theme photo are REFUSED with the key named; numbers are clamped;
        another member's item ids are dropped from the orders; a design over
        16384 bytes is refused; publicDesign re-checks a stored design and
        answers null for one that no longer passes
     B  migration 156: exactly its SQL, the only 156, after 155; the column
        in the public allow-list as a validated design only
     C  the routes, lifted from server.js over a fake database: PUT saves a
        checked design and refuses a bad one (writing nothing); { theme_id }
        takes one of the member's own saved themes and keeps the rest; another
        member's theme is refused; DELETE resets; GET /api/bfp/profile/:id
        answers only the allow-listed columns and only the validated design
        (a tampered stored design goes out as null); GET /me the same
     D  the renderer (jsdom, profile.html's markup): every enum becomes a
        data-pd-* attribute, every number a token it formats itself; tampered
        values fall back to the defaults; nothing a member wrote reaches a
        style (the injected stylesheet is this file's constant, every --pd-
        token is a number, a length, a percentage, a #hex or a var()); the
        section order and Show are followed; the grid and video orders are
        followed; the photo keeps its alt text; the layouts are responsive;
        the business card keeps its look
     E  the theme (jsdom, bf-theme.js): a visitor's own theme is never worn
        on someone else's profile; the OWNER's design theme is, with
        readability protection, and stays when the visitor's theme state is
        applied again; wear(null) lets go
     F  the editor (jsdom): "Customise profile" for the owner only; the six
        sections Theme · Banner · Photo · Layout · Sections · Grid & Videos;
        the live preview (profile.html?id=<own id>&bf_preview=1, Desktop and
        Phone); drag, Move up / Move down and the arrow keys reorder; Show
        hides; "Save" sends the draft to the real route, "Discard" goes back,
        "Reset profile design" asks twice then resets; the preview takes
        drafts from its parent window, same origin only
     G  the other pages: the support page carries the validated design as
        JSON data (no "</script" can break out) and draws it; seller.html
        orders and draws the design; the theme studio's "My public profile"
        scope; the guide tip

   No network, no model call, no database: the routes run over a fake one,
   the pages in jsdom with their own scripts stripped.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check. A mutation
   whose search text does not match exactly once is an ERROR.

   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const Module = require("module");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";

const SERVER = "server.js", LIB = "lib/profileDesign.js", SUPPORT = "lib/supportPage.js";
const MIG = "supabase/migrations/156_profile_design.sql";
const PD = "F:scripts/bf-profile-design.js", ED = "F:scripts/bf-profile-editor.js", THEME = "F:scripts/bf-theme.js";
const STUDIO = "F:scripts/bf-theme-studio.js", GUIDE = "F:scripts/termaximus-guide.js";
const PROFILE = "F:profile.html", SELLER = "F:seller.html", SETTINGS = "F:settings.html";

const MUTATIONS = {
  // raw CSS in a colour field is accepted (A)
  "raw-css-accepted": [[LIB, "      if (typeof value !== \"string\" || !HEX.test(value)) return refuse(key + \" must be a colour like #1a2b3c.\", key);",
    "      if (typeof value !== \"string\") return refuse(key + \" must be a colour like #1a2b3c.\", key);"]],
  // the theme photo is checked against the folder it names, not the member's own (A, C)
  "foreign-media-path-accepted": [[LIB, "    var t = themes.validateTheme(input.theme, userId);",
    "    var t = themes.validateTheme(input.theme, typeof input.theme.photo === \"string\" ? input.theme.photo.split(\"/\")[1] : userId);"]],
  // another member's item ids stay in the orders (A, C)
  "foreign-ids-kept": [[LIB, "      if (ownIds && Array.isArray(ownIds[name])) seen = seen.filter(function (id) { return ownIds[name].indexOf(id) !== -1; });", ""]],
  // the public route sends the stored design as it is (C)
  "public-route-unvalidated": [[SERVER, "    if (data) data.profile_design = design.design;\n    // Of the member's support settings", "    // Of the member's support settings"]],
  // the visitor's own theme is worn on someone else's profile (E)
  "visitors-theme-applied": [[THEME, "      return !!id && (id !== signedInId(win) || preview);", "      return false;"]],
  // a theme state applied later replaces the owner's pinned look (E)
  "pin-ignored": [[THEME, "    if (pinned) return false;   // a profile design's theme is worn here (wear)\n", ""]],
  // the section order is not followed (D)
  "section-order-ignored": [[PD, "      host.insertBefore(el, card && card.parentNode === host ? card : null);", "      void card;"]],
  // Show is ignored (D)
  "section-show-ignored": [[PD, "      if (d && s.show === false) el.setAttribute(\"data-pd-hidden\", \"true\");\n      else el.removeAttribute(\"data-pd-hidden\");", "      el.removeAttribute(\"data-pd-hidden\");"]],
  // the grid order is not followed (D, G)
  "grid-order-ignored": [[PD, "    if (!order.length) return list;", "    return list;"]],
  // a member's string is written into a style (D)
  "member-string-in-style": [
    [PD, "      if (part === \"photo\" && typeof src.ring_color === \"string\" && HEX.test(src.ring_color)) d.photo.ring_color = src.ring_color;",
      "      if (part === \"photo\" && typeof src.ring_color === \"string\") d.photo.ring_color = src.ring_color;"],
    [PD, "      \"--pd-ring-color\": HEX.test(p.ring_color) ? p.ring_color : DEFAULT.photo.ring_color,", "      \"--pd-ring-color\": p.ring_color,"]],
  // the preview takes drafts from any origin (F)
  "preview-any-origin": [[PD, "      if (e.origin !== window.location.origin || e.source !== window.parent) return;\n", ""]],
  // the preview frame of your own profile counts as the owner's page (F)
  "preview-is-owner": [[PROFILE, "  isOwner = (myUserId === viewUserId) && !bfPreview;", "  isOwner = (myUserId === viewUserId);"]],
  // Reset profile design resets on the first press (F)
  "reset-one-press": [[ED, "    if (b.getAttribute(\"data-confirm\") !== \"1\") { b.setAttribute(\"data-confirm\", \"1\"); b.textContent = MSG.confirmReset; return Promise.resolve(false); }\n", ""]],
  // the arrow keys do not move a row (F)
  "arrow-keys-dead": [[ED, "        if (move(li, e.key === \"ArrowUp\" ? -1 : 1)) handle.focus();", "        handle.focus();"]],
  // the support page's JSON can close its script tag (G)
  "support-json-unescaped": [[SUPPORT, ".replace(/</g, \"\\\\u003c\");", ";"]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

let JSDOM;
try { ({ JSDOM } = require("jsdom")); } catch (e) { console.log("    FAIL  jsdom could not be loaded: " + e.message); process.exit(1); }

const lf = t => t.replace(/\r\n/g, "\n");
const FILES = {};
function readFile(key) {
  const p = key.indexOf("F:") === 0 ? path.join(FRONTEND, key.slice(2)) : path.join(REPO, key);
  if (!fs.existsSync(p)) { console.log("    FAIL  file not found: " + p + (key.indexOf("F:") === 0 ? " (set BIZFORCE_FRONTEND_DIR)" : "")); process.exit(1); }
  return lf(fs.readFileSync(p, "utf8"));
}
[SERVER, LIB, SUPPORT, MIG, PD, ED, THEME, STUDIO, GUIDE, PROFILE, SELLER, SETTINGS].forEach(f => { FILES[f] = readFile(f); });

if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE);
}

let passes = 0, failures = 0, finished = false;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}
function finish() {
  if (finished) return;
  finished = true;
  console.log("\n" + (failures ? "CHECKS FAILED: " + failures + " of " + (passes + failures) : "ALL " + passes + " CHECKS PASSED") + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(failures ? 1 : 0);
}
process.on("unhandledRejection", err => { failures++; console.log("    FAIL  an unhandled rejection: " + (err && err.stack || err)); });

function compile(rel, text) {
  const file = path.join(REPO, rel);
  const m = new Module(file, module);
  m.filename = file;
  m.paths = Module._nodeModulePaths(path.dirname(file));
  m._compile(text, file);
  return m.exports;
}
let L, SP, THEMES;
try { L = compile(LIB, FILES[LIB]); SP = compile(SUPPORT, FILES[SUPPORT]); THEMES = require(path.join(REPO, "lib/themes.js")); }
catch (e) { console.log("    FAIL  a lib did not load: " + e.message); process.exit(1); }

const UID = "11111111-1111-4111-8111-111111111111";      // the owner
const OTHER = "22222222-2222-4222-8222-222222222222";    // another member
const VISITOR = "33333333-3333-4333-8333-333333333333";  // a signed-in visitor
const G1 = "aaaaaaaa-0000-4000-8000-000000000001", G2 = "aaaaaaaa-0000-4000-8000-000000000002", G3 = "aaaaaaaa-0000-4000-8000-000000000003";
const V1 = "bbbbbbbb-0000-4000-8000-000000000001", V2 = "bbbbbbbb-0000-4000-8000-000000000002";
const FOREIGN = "cccccccc-0000-4000-8000-000000000009";
const ORIGIN = "https://bizforce.test";
const clone = x => JSON.parse(JSON.stringify(x));
const tokenFor = id => "h." + Buffer.from(JSON.stringify({ id })).toString("base64") + ".s";
const EVIL = "red;}body{background:url(https://evil.test/x.png)}</style><script>alert(1)</script>";

/* ── A. the schema ──────────────────────────────────────────────────────── */
console.log("\n══ A. the closed schema (lib/profileDesign.js) ══");
const V = (d, uid, own) => L.validateDesign(d, uid || UID, own);
const ok0 = V(clone(L.DEFAULT_DESIGN));
check("A1. the default design passes and comes back as itself", !ok0.error && JSON.stringify(ok0.design) === JSON.stringify(L.DEFAULT_DESIGN), JSON.stringify(ok0));
check("A1. an empty object is the default design", JSON.stringify((V({}).design)) === JSON.stringify(L.DEFAULT_DESIGN));
check("A2. five layouts, standard (today's page) first and the default; at least four besides it",
  JSON.stringify(L.LAYOUTS) === JSON.stringify(["standard", "classic", "split", "magazine", "minimal"]) && L.DEFAULT_DESIGN.layout === "standard");
check("A2. eight photo shapes", JSON.stringify(L.SHAPES) === JSON.stringify(["circle", "rounded", "square", "hexagon", "octagon", "shield", "diamond", "blob"]));
check("A2. banner heights S/M/L/Full-bleed/custom, photo sizes S/M/L/XL, rings none/solid/gradient",
  JSON.stringify(L.BANNER_HEIGHTS) === JSON.stringify(["s", "m", "l", "full", "custom"]) && JSON.stringify(L.PHOTO_SIZES) === JSON.stringify(["s", "m", "l", "xl"]) &&
  JSON.stringify(L.RINGS) === JSON.stringify(["none", "solid", "gradient"]));
check("A2. grid 2/3/4 columns, square/portrait/masonry, gap s/m/l; videos carousel/grid",
  JSON.stringify(L.GRID_COLUMNS) === "[2,3,4]" && JSON.stringify(L.GRID_STYLES) === JSON.stringify(["square", "portrait", "masonry"]) &&
  JSON.stringify(L.GAPS) === JSON.stringify(["s", "m", "l"]) && JSON.stringify(L.VIDEO_LAYOUTS) === JSON.stringify(["carousel", "grid"]));
const every = [];
L.LAYOUTS.forEach(l => every.push(V({ layout: l })));
L.SHAPES.forEach(sh => every.push(V({ photo: { shape: sh } })));
L.BANNER_HEIGHTS.forEach(h => every.push(V({ banner: { height: h } })));
check("A2. every listed value passes", every.every(r => !r.error), JSON.stringify(every.filter(r => r.error)));
const refusals = [
  ["an unknown top key (css)", { css: "body{color:red}" }, "css"],
  ["an unknown banner key (style)", { banner: { style: "background:url(x)" } }, "banner.style"],
  ["a layout outside the list", { layout: "grid;}body{x:y" }, "layout"],
  ["a shape outside the list (a custom clip-path)", { photo: { shape: "polygon(0 0, 100% 0)" } }, "photo.shape"],
  ["raw CSS as the ring colour", { photo: { ring_color: EVIL } }, "photo.ring_color"],
  ["a named colour", { photo: { ring_color: "red" } }, "photo.ring_color"],
  ["an upper-case hex colour", { photo: { ring_color: "#22D3EE" } }, "photo.ring_color"],
  ["a URL as the ring colour", { photo: { ring_color: "url(https://evil.test/x.png)" } }, "photo.ring_color"],
  ["HTML in a section key", { sections: [{ key: "<img src=x onerror=alert(1)>", show: true }] }, "sections.key"],
  ["a section twice", { sections: [{ key: "about", show: true }, { key: "about", show: false }] }, "sections.key"],
  ["a string as a number", { banner: { zoom: "200%" } }, "banner.zoom"],
  ["a URL in an order", { grid: { order: ["https://evil.test/x"] } }, "grid.order"],
  ["a string as featured", { videos: { featured: "yes" } }, "videos.featured"],
  ["columns outside the list", { grid: { columns: 7 } }, "grid.columns"],
  ["another version", { v: 2 }, "v"]
];
refusals.forEach(([what, d, key]) => {
  const r = V(d);
  check("A3. refused, naming " + key + ": " + what, !!r.error && r.key === key && !r.design, JSON.stringify(r));
});
const clamped = V({ banner: { custom_px: 9999, focus_x: -40, zoom: 50, overlay: 3, feather: 80 }, photo: { ring_width: 40, ring_glow: -1 } }).design;
check("A4. numbers out of range are clamped (custom 640, focus 0, zoom 100, overlay 0.85, feather 50, ring 12, glow 0)",
  !!clamped && clamped.banner.custom_px === 640 && clamped.banner.focus_x === 0 && clamped.banner.zoom === 100 && clamped.banner.overlay === 0.85 &&
  clamped.banner.feather === 50 && clamped.photo.ring_width === 12 && clamped.photo.ring_glow === 0, JSON.stringify(clamped));
const ownPhoto = Object.assign({}, THEMES.DEFAULT_THEME, { middle: "photo", photo: "theme-photos/" + UID + "/1700000000000.jpg", photo_luma: 0.4 });
const foreignPhoto = Object.assign({}, THEMES.DEFAULT_THEME, { middle: "photo", photo: "theme-photos/" + OTHER + "/1700000000000.jpg", photo_luma: 0.4 });
const rOwn = V({ theme: ownPhoto }), rForeign = V({ theme: foreignPhoto });
check("A5. the member's own theme photo is accepted", !rOwn.error && rOwn.design.theme.photo === ownPhoto.photo && L.photoOf(rOwn.design) === ownPhoto.photo, JSON.stringify(rOwn).slice(0, 200));
check("A5. another member's theme photo (a foreign media path) is refused, naming the theme", !!rForeign.error && /^theme/.test(rForeign.key || ""), JSON.stringify(rForeign));
const rUrl = V({ theme: Object.assign({}, THEMES.DEFAULT_THEME, { middle: "photo", photo: "https://evil.test/x.jpg", photo_luma: 0.4 }) });
check("A5. a URL as the theme photo is refused", !!rUrl.error, JSON.stringify(rUrl));
const orders = V({ grid: { order: [G2, FOREIGN, G1, G2] }, videos: { order: [FOREIGN, V2] } }, UID, { grid: [G1, G2, G3], videos: [V1, V2] }).design;
check("A6. the orders keep only the member's own item ids, once each, in the order given",
  !!orders && JSON.stringify(orders.grid.order) === JSON.stringify([G2, G1]) && JSON.stringify(orders.videos.order) === JSON.stringify([V2]), JSON.stringify(orders && [orders.grid.order, orders.videos.order]));
const partial = V({ sections: [{ key: "music", show: false }, { key: "links" }] }).design;
check("A7. a section left out is added at the end, shown; the order given is kept",
  !!partial && partial.sections.map(x => x.key).join(",") === "music,links,about,support,listings,grid,videos" && partial.sections[0].show === false && partial.sections[6].show === true);
const many = []; for (let i = 0; i < 200; i++) many.push("dddddddd-0000-4000-8000-" + String(i).padStart(12, "0"));
const big = V({ grid: { order: many }, videos: { order: many.slice(0, 100) }, theme: THEMES.DEFAULT_THEME });
check("A8. the size ceiling is 16384 bytes, the migration's CHECK as well (" + (big.error ? "a full design refused" : "a full design fits") + ")",
  L.DESIGN_MAX_BYTES === 16384 && (!!big.error ? /too large/.test(big.error) : Buffer.byteLength(JSON.stringify(big.design)) <= 16384));
check("A9. publicDesign: null for none, the re-checked design for a good one, null for a tampered one",
  L.publicDesign(null, UID) === null && JSON.stringify(L.publicDesign(clone(L.DEFAULT_DESIGN), UID)) === JSON.stringify(L.DEFAULT_DESIGN) &&
  L.publicDesign(Object.assign(clone(L.DEFAULT_DESIGN), { css: "x" }), UID) === null &&
  L.publicDesign(Object.assign(clone(L.DEFAULT_DESIGN), { theme: foreignPhoto }), UID) === null);

/* ── B. migration 156 ───────────────────────────────────────────────────── */
console.log("\n══ B. migration 156 and the public allow-list ══");
const sqlBody = FILES[MIG].split("\n").filter(l => !/^\s*--/.test(l) && l.trim()).join("\n");
const SQL = [
  "ALTER TABLE public.bf_profiles",
  "  ADD COLUMN IF NOT EXISTS profile_design jsonb;",
  "ALTER TABLE public.bf_profiles",
  "  DROP CONSTRAINT IF EXISTS bf_profiles_profile_design_check;",
  "ALTER TABLE public.bf_profiles",
  "  ADD CONSTRAINT bf_profiles_profile_design_check CHECK (",
  "    profile_design IS NULL",
  "    OR (jsonb_typeof(profile_design) = 'object' AND octet_length(profile_design::text) <= 16384)",
  "  );"
].join("\n");
check("B1. 156_profile_design.sql is exactly: the jsonb column, and a CHECK that it is an object of at most 16384 bytes", sqlBody === SQL, sqlBody);
const migs = fs.readdirSync(path.join(REPO, "supabase/migrations")).filter(f => /^\d+_/.test(f));
check("B1. it is the only 156 and the latest, after 155", migs.filter(f => /^156_/.test(f)).length === 1 && migs.filter(f => /^155_/.test(f)).length === 1 &&
  Math.max(...migs.map(f => parseInt(f, 10))) === 156);
const cols = /const BF_PUBLIC_PROFILE_COLUMNS = \[([\s\S]*?)\];/.exec(FILES[SERVER]);
const COLS = cols ? cols[1].match(/"[a-z_]+"/g).map(x => x.slice(1, -1)) : [];
check("B2. profile_design is in the public allow-list, user_id and id are not", COLS.indexOf("profile_design") !== -1 && COLS.indexOf("user_id") === -1 && COLS.indexOf("id") === -1, COLS.join(","));

/* ── C. the routes over a fake database ─────────────────────────────────── */
function fakeDb(seed) {
  const db = Object.assign({ bf_profiles: [], member_themes: [], profile_portfolio: [], bf_videos: [] }, clone(seed || {}));
  db.writes = [];
  function from(table) {
    const st = { filters: [], op: "select", payload: null, cols: "*" };
    const pick = () => (db[table] || []).filter(r => st.filters.every(([c, v]) => r[c] === v));
    const shape = r => {
      if (st.cols === "*" || !st.cols) return clone(r);
      const o = {};
      st.cols.split(",").map(c => c.trim()).forEach(c => { if (Object.prototype.hasOwnProperty.call(r, c)) o[c] = clone(r[c]); });
      return o;
    };
    function run() {
      if (st.op === "select") return Promise.resolve({ data: pick().map(shape), error: null });
      db.writes.push({ table, op: st.op, payload: clone(st.payload) });
      if (st.op === "update") { const rows = pick(); rows.forEach(r => Object.assign(r, clone(st.payload))); return Promise.resolve({ data: rows.map(shape), error: null }); }
      if (st.op === "upsert") {
        const key = st.conflict || "id";
        let had = db[table].filter(r => r[key] === st.payload[key])[0];
        if (had) Object.assign(had, clone(st.payload)); else { had = clone(st.payload); db[table].push(had); }
        return Promise.resolve({ data: [shape(had)], error: null });
      }
      return Promise.resolve({ data: null, error: null });
    }
    const q = {
      select(c) { if (st.op === "select") st.cols = c || "*"; else st.cols = c || "*"; return q; },
      eq(c, v) { st.filters.push([c, v]); return q; },
      update(p) { st.op = "update"; st.payload = p; return q; },
      upsert(p, o) { st.op = "upsert"; st.payload = p; st.conflict = o && o.onConflict; return q; },
      maybeSingle() { return run().then(r => ({ data: (r.data && r.data[0]) || null, error: r.error })); },
      single() { return run().then(r => ({ data: r.data && r.data[0], error: r.error })); },
      then(a, b) { return run().then(a, b); }
    };
    return q;
  }
  const storage = { from: bucket => ({ getPublicUrl: p => ({ data: { publicUrl: "https://x.supabase.co/storage/v1/object/public/" + bucket + "/" + p } }) }) };
  return { db, client: { from, storage } };
}
function liftRoutes(fake) {
  const src = FILES[SERVER];
  const a = src.indexOf("app.get(\"/api/bfp/profile/me\", requireAuth,");
  const b0 = src.indexOf("app.get(\"/api/bfp/profile/:userId\"");
  const b = b0 === -1 ? -1 : src.indexOf("\n});\n", b0) + 5;
  if (a === -1 || b0 === -1 || b < b0 || b0 < a) throw new Error("the profile routes were not found in server.js");
  const routes = [];
  const ctx = {
    console: { log() {}, error() {}, warn() {} },
    require: name => { if (name === "./lib/profileDesign") return L; throw new Error("unexpected require " + name); },
    supabase: fake.client, Promise: Promise, Object: Object, Array: Array, String: String, JSON: JSON,
    requireAuth: (req, res, next) => next(), themesWriteLimiter: (req, res, next) => next(),
    THEME_ID_PATTERN: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    nowIso: () => "2026-10-31T00:00:00.000Z",
    safeText: (v, n) => v === undefined || v === null ? null : String(v).trim().slice(0, n || 5000),
    ownerPagePublic: async () => true, publicSupportLinks: async () => [],
    app: {}
  };
  ["get", "post", "put", "delete"].forEach(m => { ctx.app[m] = function (p) { const args = [].slice.call(arguments, 1); routes.push({ method: m, path: p, handler: args[args.length - 1] }); }; });
  vm.createContext(ctx);
  vm.runInContext(src.slice(a, b), ctx);
  return routes;
}
function callRoute(routes, method, url, body, uid) {
  return new Promise((resolve, reject) => {
    let hit = null, params = {};
    for (const r of routes) {
      if (r.method !== method) continue;
      const names = [];
      const re = new RegExp("^" + r.path.replace(/:([a-zA-Z_]+)/g, (m, nm) => { names.push(nm); return "([^/]+)"; }) + "$");
      const m = re.exec(url);
      if (m) { hit = r; names.forEach((nm, i) => { params[nm] = decodeURIComponent(m[i + 1]); }); break; }
    }
    if (!hit) return resolve({ status: 404, body: { error: "no route" } });
    const req = { user: { id: uid || UID }, params, body: body || {} };
    const res = { statusCode: 200, status(c) { this.statusCode = c; return this; }, json(b) { resolve({ status: this.statusCode, body: JSON.parse(JSON.stringify(b)) }); return this; } };
    const p = hit.handler(req, res, err => reject(err || new Error("next() with no error")));
    if (p && p.catch) p.catch(reject);
  });
}

const THEME_ROW = "eeeeeeee-0000-4000-8000-000000000001", OTHER_THEME = "eeeeeeee-0000-4000-8000-000000000002";
const SOLAR = Object.assign({}, THEMES.DEFAULT_THEME, { glow_a: "#ff8800", glow_b: "#ffdd00" });
function seed() {
  return {
    bf_profiles: [{ id: "row-1", user_id: UID, username: "alice", display_name: "Alice", bio: "Hi", accent_color: "#22d3ee", profile_design: null, created_at: "x", updated_at: "y" }],
    member_themes: [{ id: THEME_ROW, user_id: UID, name: "Solar", theme: SOLAR }, { id: OTHER_THEME, user_id: OTHER, name: "Theirs", theme: SOLAR }],
    profile_portfolio: [{ id: G1, user_id: UID }, { id: G2, user_id: UID }, { id: G3, user_id: UID }, { id: FOREIGN, user_id: OTHER }],
    bf_videos: [{ id: V1, user_id: UID }, { id: V2, user_id: UID }]
  };
}

async function routesSection() {
  console.log("\n══ C. the routes, lifted from server.js, over a fake database ══");
  const fake = fakeDb(seed());
  let routes;
  try { routes = liftRoutes(fake); } catch (e) { check("C0. the profile routes lift from server.js", false, e.message); return null; }
  check("C0. PUT and DELETE /api/bfp/profile/design are signed-in routes with the theme write limit",
    /app\.put\("\/api\/bfp\/profile\/design", requireAuth, themesWriteLimiter,/.test(FILES[SERVER]) && /app\.delete\("\/api\/bfp\/profile\/design", requireAuth, themesWriteLimiter,/.test(FILES[SERVER]));
  const draft = Object.assign(clone(L.DEFAULT_DESIGN), { layout: "split", grid: { columns: 2, style: "masonry", gap: "l", order: [G3, FOREIGN, G1] } });
  const put = await callRoute(routes, "put", "/api/bfp/profile/design", { design: draft });
  const stored = fake.db.bf_profiles[0].profile_design;
  check("C1. PUT { design } saves the checked design and answers it", put.status === 200 && put.body.profile_design && put.body.profile_design.layout === "split" &&
    JSON.stringify(stored) === JSON.stringify(put.body.profile_design), JSON.stringify(put));
  check("C1. ... keeping only the member's own grid ids (another member's item is dropped)", !!stored && JSON.stringify(stored.grid.order) === JSON.stringify([G3, G1]), JSON.stringify(stored && stored.grid.order));
  const writes = fake.db.writes.length;
  const bad = await callRoute(routes, "put", "/api/bfp/profile/design", { design: { photo: { ring_color: EVIL } } });
  check("C2. raw CSS is refused with 400, naming the key, and nothing is written", bad.status === 400 && bad.body.key === "photo.ring_color" && fake.db.writes.length === writes &&
    fake.db.bf_profiles[0].profile_design.layout === "split", JSON.stringify(bad));
  const badPhoto = await callRoute(routes, "put", "/api/bfp/profile/design", { design: { theme: foreignPhoto } });
  check("C2. another member's theme photo is refused with 400, and nothing is written", badPhoto.status === 400 && fake.db.writes.length === writes, JSON.stringify(badPhoto));
  const byTheme = await callRoute(routes, "put", "/api/bfp/profile/design", { theme_id: THEME_ROW });
  check("C3. PUT { theme_id }: one of the member's own saved themes becomes the profile's theme, the rest of the design kept",
    byTheme.status === 200 && byTheme.body.profile_design.theme && byTheme.body.profile_design.theme.glow_a === "#ff8800" && byTheme.body.profile_design.layout === "split", JSON.stringify(byTheme).slice(0, 300));
  const theirs = await callRoute(routes, "put", "/api/bfp/profile/design", { theme_id: OTHER_THEME });
  check("C3. another member's saved theme is refused (404) and nothing changes", theirs.status === 404 && fake.db.bf_profiles[0].profile_design.theme.glow_a === "#ff8800", JSON.stringify(theirs));
  const pub = await callRoute(routes, "get", "/api/bfp/profile/" + UID, null, VISITOR);
  const keys = pub.body.profile ? Object.keys(pub.body.profile) : [];
  check("C4. GET /api/bfp/profile/:id answers only allow-listed columns (no user_id, no id, no timestamps)",
    pub.status === 200 && keys.length > 0 && keys.every(k => COLS.indexOf(k) !== -1), keys.join(","));
  check("C4. ... with the validated design", JSON.stringify(pub.body.profile.profile_design) === JSON.stringify(L.publicDesign(fake.db.bf_profiles[0].profile_design, UID)) &&
    pub.body.profile.profile_design.layout === "split");
  fake.db.bf_profiles[0].profile_design = Object.assign(clone(L.DEFAULT_DESIGN), { layout: "classic", css: "body{background:url(https://evil.test)}" });
  const tampered = await callRoute(routes, "get", "/api/bfp/profile/" + UID, null, VISITOR);
  check("C5. a tampered stored design (an extra css key) goes out as null, never as stored", tampered.status === 200 && tampered.body.profile.profile_design === null,
    JSON.stringify(tampered.body.profile && tampered.body.profile.profile_design));
  fake.db.bf_profiles[0].profile_design = { v: 1, theme: ownPhoto, layout: "magazine" };
  const withPhoto = await callRoute(routes, "get", "/api/bfp/profile/" + UID, null, VISITOR);
  check("C6. the design's own theme photo goes out as its public storage URL", withPhoto.body.design_photo_url === "https://x.supabase.co/storage/v1/object/public/bf-public/" + ownPhoto.photo,
    withPhoto.body.design_photo_url);
  const me = await callRoute(routes, "get", "/api/bfp/profile/me");
  check("C7. GET /me answers the validated design too, with its photo URL", me.status === 200 && me.body.profile.profile_design.layout === "magazine" && me.body.design_photo_url === withPhoto.body.design_photo_url);
  const del = await callRoute(routes, "delete", "/api/bfp/profile/design");
  check("C8. DELETE resets the profile design to none", del.status === 200 && del.body.profile_design === null && fake.db.bf_profiles[0].profile_design === null);
  return routes;
}

/* ── the pages in jsdom ─────────────────────────────────────────────────── */
const stripScripts = html => html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "");
function page(html, url, opts) {
  opts = opts || {};
  const dom = new JSDOM(stripScripts(html), { url: url, runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window;
  w.matchMedia = w.matchMedia || (q => ({ matches: false, media: q, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} }));
  if (opts.token) w.localStorage.setItem("bf_token", opts.token);
  if (opts.cache) w.localStorage.setItem("bf_theme", JSON.stringify(opts.cache));
  w.console.error = () => {}; w.console.warn = () => {};
  (opts.scripts || []).forEach(k => w.eval(FILES[k]));
  return w;
}
const css = w => { const st = w.document.getElementById("bf-profile-design-style"); return st ? st.textContent : ""; };
const rootTokens = w => {
  const st = w.document.documentElement.style, out = {};
  for (let i = 0; i < st.length; i++) if (st[i].indexOf("--pd-") === 0) out[st[i]] = st.getPropertyValue(st[i]).trim();
  return out;
};
const SAFE_TOKEN = /^(-?\d+(\.\d+)?(px|%|vh)?( -?\d+(\.\d+)?%)?|#[0-9a-f]{6}|var\(--bf-accent-a, #22d3ee\))$/;

function rendererSection() {
  console.log("\n══ D. the renderer, on profile.html's markup ══");
  const w = page(FILES[PROFILE], ORIGIN + "/profile.html?id=" + UID, { scripts: [PD] });
  const P = w.BFProfileDesign, doc = w.document, root = doc.documentElement;
  check("D0. profile.html loads the renderer and the editor, after its own script", FILES[PROFILE].indexOf("<script src=\"/scripts/bf-profile-design.js\"></script>\n<script src=\"/scripts/bf-profile-editor.js\"></script>") !== -1 &&
    FILES[PROFILE].indexOf("<script src=\"/scripts/bf-profile-design.js\">") > FILES[PROFILE].indexOf("function applyProfileDesign()"));
  check("D0. the renderer mirrors the schema's lists exactly", !!P && JSON.stringify(P.LAYOUTS) === JSON.stringify(L.LAYOUTS) && JSON.stringify(P.SHAPES) === JSON.stringify(L.SHAPES) &&
    JSON.stringify(P.BANNER_HEIGHTS) === JSON.stringify(L.BANNER_HEIGHTS) && JSON.stringify(P.PHOTO_SIZES) === JSON.stringify(L.PHOTO_SIZES) && JSON.stringify(P.RINGS) === JSON.stringify(L.RINGS) &&
    JSON.stringify(P.SECTIONS) === JSON.stringify(L.SECTIONS) && JSON.stringify(P.GRID_COLUMNS) === JSON.stringify(L.GRID_COLUMNS) && JSON.stringify(P.GRID_STYLES) === JSON.stringify(L.GRID_STYLES) &&
    JSON.stringify(P.GAPS) === JSON.stringify(L.GAPS) && JSON.stringify(P.VIDEO_LAYOUTS) === JSON.stringify(L.VIDEO_LAYOUTS) && JSON.stringify(P.DEFAULT) === JSON.stringify(L.DEFAULT_DESIGN));
  check("D0. every section has its place on profile.html, links included (#sec-links holds #socialRow)",
    Object.keys(P.SECTION_IDS).every(k => !!doc.getElementById(P.SECTION_IDS[k]) && doc.getElementById(P.SECTION_IDS[k]).parentNode.classList.contains("pf-sections")) &&
    !!doc.querySelector("#sec-links #socialRow"));
  const D = Object.assign(clone(L.DEFAULT_DESIGN), {
    layout: "magazine",
    banner: { height: "custom", custom_px: 420, focus_x: 30, focus_y: 70, zoom: 150, overlay: 0.5, feather: 20 },
    photo: { size: "xl", shape: "hexagon", ring: "solid", ring_width: 6, ring_glow: 0.8, ring_color: "#ff8800" },
    grid: { columns: 4, style: "portrait", gap: "l", order: [G3, G1] },
    videos: { layout: "carousel", featured: true, order: [V2] }
  });
  P.apply(D, { page: "profile", name: "Alice" });
  const at = n => root.getAttribute(n);
  check("D1. each enum is a data-pd-* attribute on <html>",
    at("data-pd") === "on" && at("data-pd-layout") === "magazine" && at("data-pd-banner") === "custom" && at("data-pd-photo-size") === "xl" && at("data-pd-shape") === "hexagon" &&
    at("data-pd-ring") === "solid" && at("data-pd-grid-cols") === "4" && at("data-pd-grid-style") === "portrait" && at("data-pd-grid-gap") === "l" &&
    at("data-pd-video-layout") === "carousel" && at("data-pd-featured") === "on" && at("data-pd-feather") === "on");
  const tk = rootTokens(w);
  check("D2. each number is a token the renderer formats itself (banner 420px, focus 30% 70%, zoom 1.5, overlay 0.5, photo 220px, ring 6px, colour #ff8800)",
    tk["--pd-banner-h"] === "420px" && tk["--pd-focus"] === "30% 70%" && tk["--pd-zoom"] === "1.5" && tk["--pd-overlay"] === "0.5" && tk["--pd-photo"] === "220px" &&
    tk["--pd-ring-w"] === "6px" && tk["--pd-ring-color"] === "#ff8800" && tk["--pd-cols"] === "4" && tk["--pd-gap"] === "24px", JSON.stringify(tk));
  check("D3. the photo: ring, glow and clip classes; the picture's alt text given when it had none",
    doc.getElementById("avatarEl").classList.contains("pd-ring") && doc.getElementById("avatarEl").classList.contains("pd-clip") &&
    doc.getElementById("avatarEl").parentNode.classList.contains("pd-glow") && doc.getElementById("avatarImg").getAttribute("alt") === "Alice's profile photo");
  doc.getElementById("avatarImg").setAttribute("alt", "Alice at the studio");
  P.apply(D, { page: "profile", name: "Alice" });
  check("D3. ... and keeps alt text it already has", doc.getElementById("avatarImg").getAttribute("alt") === "Alice at the studio");
  const sheet = css(w);
  check("D4. eight shapes, each a constant clip-path in the renderer's own stylesheet",
    L.SHAPES.every(sh => sheet.indexOf("html[data-pd-shape=" + sh + "] .pd-clip{clip-path:" + P.CLIP[sh] + "}") !== -1) && Object.keys(P.CLIP).length === 8);
  check("D5. four layouts besides Standard, each with its rules, and phone rules for them (max-width:760px)",
    ["classic", "split", "magazine", "minimal"].every(l => sheet.indexOf("html[data-pd-layout=" + l + "]") !== -1) && /@media \(max-width:760px\)\{html\[data-pd-layout=split\]/.test(sheet) &&
    /html\[data-pd-layout=magazine\] \.pf-header\{margin-top:-80px\}/.test(sheet));
  check("D5. the grid falls to two columns and the photo and banner shrink on phones", /@media \(max-width:680px\)\{html\[data-pd-grid-cols="3"\] #portfolioGrid/.test(sheet) &&
    /@media \(max-width:680px\)\{html\[data-pd=on\] \.pd-ring\{width:calc\(var\(--pd-photo\) \* \.75\)/.test(sheet));
  check("D6. the business card keeps its look: the renderer's stylesheet never touches it, and it stays last",
    !/sec-card|pf-card|share-card|bizcard/i.test(sheet) && doc.querySelector(".pf-sections").lastElementChild.id === "sec-card");

  // the sections
  const order = ["music", "videos", "grid", "listings", "support", "about", "links"];
  P.apply(Object.assign(clone(D), { sections: order.map(k => ({ key: k, show: k !== "support" })) }), { page: "profile", name: "Alice" });
  const ids = Array.prototype.map.call(doc.querySelector(".pf-sections").children, el => el.id).filter(Boolean);
  check("D7. the sections follow the design's order, the business card last", JSON.stringify(ids) === JSON.stringify(order.map(k => P.SECTION_IDS[k]).concat(["sec-card"])), ids.join(","));
  check("D7. a section shown off is hidden (data-pd-hidden), the others shown", doc.getElementById("sec-support").getAttribute("data-pd-hidden") === "true" &&
    order.filter(k => k !== "support").every(k => !doc.getElementById(P.SECTION_IDS[k]).hasAttribute("data-pd-hidden")) && /\[data-pd-hidden=true\]\{display:none!important\}/.test(sheet));
  P.apply(null, { page: "profile" });
  const back = Array.prototype.map.call(doc.querySelector(".pf-sections").children, el => el.id).filter(Boolean);
  check("D7. no design: the page's own order, nothing hidden, no attributes or tokens",
    JSON.stringify(back) === JSON.stringify(L.SECTIONS.map(k => P.SECTION_IDS[k]).concat(["sec-card"])) && !doc.querySelector("[data-pd-hidden]") && !root.hasAttribute("data-pd") &&
    Object.keys(rootTokens(w)).length === 0, back.join(","));

  // the grid and videos
  const items = [{ id: G1, title: "One" }, { id: G2, title: "Two" }, { id: G3, title: "Three" }];
  const got = P.ordered(items, "grid", D).map(x => x.id);
  check("D8. the grid in the design's order: the ids it names first, then the rest as they came", JSON.stringify(got) === JSON.stringify([G3, G1, G2]), got.join(","));
  const vids = P.ordered([{ id: V1 }, { id: V2 }], "videos", D).map(x => x.id);
  check("D8. the videos in the design's order (featured first is the first of that order)", JSON.stringify(vids) === JSON.stringify([V2, V1]), vids.join(","));
  check("D8. profile.html renders the grid and the videos through that order", /function renderPortfolio\(\) \{\n  var grid = document\.getElementById\("portfolioGrid"\);\n  portfolio = pdOrdered\(portfolio, "grid"\);/.test(FILES[PROFILE]) &&
    /function renderVideos\(\) \{\n  var grid = document\.getElementById\("videosGrid"\);\n  videos = pdOrdered\(videos, "videos"\);/.test(FILES[PROFILE]));
  check("D8. the grid's columns, styles and gap, and the videos' carousel and featured video, are in the stylesheet",
    /html\[data-pd=on\] #portfolioGrid\{display:grid;grid-template-columns:repeat\(var\(--pd-cols\),minmax\(0,1fr\)\);gap:var\(--pd-gap\)\}/.test(sheet) &&
    /html\[data-pd-grid-style=masonry\] #portfolioGrid\{display:block;column-count:var\(--pd-cols\)/.test(sheet) &&
    /html\[data-pd-video-layout=carousel\] #videosGrid\{display:flex;overflow-x:auto;scroll-snap-type:x mandatory/.test(sheet) &&
    /html\[data-pd-video-layout=grid\]\[data-pd-featured=on\] #videosGrid>:first-child\{grid-column:1\/-1\}/.test(sheet));

  // nothing a member wrote reaches a style
  const sheetBefore = css(w);
  P.apply({ layout: EVIL, banner: { height: EVIL, zoom: EVIL, focus_x: "50%;x:y" }, photo: { shape: EVIL, ring: EVIL, ring_color: EVIL, size: EVIL },
    grid: { columns: EVIL, style: EVIL, gap: EVIL, order: [EVIL] }, videos: { layout: EVIL, featured: EVIL }, sections: [{ key: EVIL }] }, { page: "profile", name: EVIL });
  const styleAttr = root.getAttribute("style") || "";
  const tk2 = rootTokens(w);
  check("D9. a design full of member strings: every attribute falls back to its default",
    at("data-pd-layout") === "standard" && at("data-pd-banner") === "m" && at("data-pd-shape") === "circle" && at("data-pd-ring") === "solid" && at("data-pd-photo-size") === "m" &&
    at("data-pd-grid-cols") === "3" && at("data-pd-grid-style") === "square" && at("data-pd-video-layout") === "grid" && at("data-pd-featured") === "off");
  check("D9. ... no member string reaches a style: every --pd- token is a number, length, percentage, #hex or the accent var()",
    Object.keys(tk2).length === 12 && Object.keys(tk2).every(k => SAFE_TOKEN.test(tk2[k])) && !/evil|url\(|script|<|;x/.test(styleAttr), JSON.stringify(tk2));
  check("D9. ... the stylesheet is the renderer's own constant, unchanged, with nothing of the member's in it",
    css(w) === sheetBefore && css(w) === P.CSS.join("\n") && !/evil|alert/.test(css(w)) && doc.querySelectorAll("style#bf-profile-design-style").length === 1);
  check("D9. ... the name is used only as alt text (an attribute, never markup)", !doc.querySelector("script") && !/alert\(1\)/.test(doc.body.innerHTML.replace(/alt="[^"]*"/g, "")));
  check("D9. the renderer writes no innerHTML and no style text from a design", !/\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML|document\.write/.test(FILES[PD]) &&
    (FILES[PD].match(/\.textContent = /g) || []).length === 3);
  w.close();
}

function themeSection() {
  console.log("\n══ E. the theme: the owner's, never the visitor's ══");
  const cacheV = Number((/var CACHE_VERSION = (\d+);/.exec(FILES[THEME]) || [])[1]);
  const visitorTheme = Object.assign({}, THEMES.DEFAULT_THEME, { glow_a: "#00ff66", glow_b: "#0066ff" });
  const state = { themes: [{ id: "vvvvvvvv-0000-4000-8000-000000000001", name: "Mine", theme: visitorTheme, photo_url: null }], page_themes: {}, default_theme_id: "vvvvvvvv-0000-4000-8000-000000000001" };
  const cache = { v: cacheV, uid: VISITOR, fetched_at: Date.now(), state: state };
  const w = page(FILES[PROFILE], ORIGIN + "/profile.html?id=" + UID, { token: tokenFor(VISITOR), cache: cache, scripts: [THEME, PD] });
  const T = w.BFTheme, P = w.BFProfileDesign, root = w.document.documentElement;
  const glow = () => root.style.getPropertyValue("--bf-glow-a").trim();
  const visitorTokens = T.tokensFor(visitorTheme, null, w);
  check("E1. a signed-in visitor's own theme is not worn on someone else's profile", glow() === "" && T.worn() === null, glow());
  const owner = Object.assign({}, THEMES.DEFAULT_THEME, { middle: "colour", bg: "#f4f1a0", glow_a: "#ff8800", glow_b: "#ffdd00" });
  const ownerTokens = T.tokensFor(owner, null, w);
  P.apply(Object.assign(clone(L.DEFAULT_DESIGN), { theme: owner }), { page: "profile", name: "Alice" });
  check("E2. the owner's design theme is worn, through tokensFor", glow() === ownerTokens["--bf-glow-a"] && JSON.stringify(T.worn()) === JSON.stringify(ownerTokens) && glow() !== visitorTokens["--bf-glow-a"], glow());
  check("E3. with readability protection: a light middle tone is shaded", Number(ownerTokens["--bf-scrim"]) > 0 || Number(ownerTokens["--bf-bg-dim"]) > 0,
    JSON.stringify({ scrim: ownerTokens["--bf-scrim"], dim: ownerTokens["--bf-bg-dim"] }));
  T.applyState(state);
  check("E4. the visitor's theme state applied again leaves the owner's look", glow() === ownerTokens["--bf-glow-a"], glow());
  P.apply(Object.assign(clone(L.DEFAULT_DESIGN), { theme: null }), { page: "profile", name: "Alice" });
  check("E5. a design with no theme shows the original look (the default theme pinned), not the visitor's", glow() === T.tokensFor(T.DEFAULT_THEME, null, w)["--bf-glow-a"] && glow() !== visitorTokens["--bf-glow-a"], glow());
  P.apply(null, { page: "profile" });
  check("E6. no design: wear(null) lets go, and someone else's profile wears no theme at all", T.worn() === null && glow() === "", glow());
  w.close();
  const own = page(FILES[PROFILE], ORIGIN + "/profile.html?id=" + VISITOR + "&bf_preview=1", { token: tokenFor(VISITOR), cache: cache, scripts: [THEME] });
  check("E7. the editor's preview of your own profile is a public view: your own theme is not worn there", own.document.documentElement.style.getPropertyValue("--bf-glow-a").trim() === "" &&
    own.BFTheme.publicView("profile.html") === true);
  own.close();
  const mine = page(FILES[PROFILE], ORIGIN + "/profile.html?id=" + VISITOR, { token: tokenFor(VISITOR), cache: cache, scripts: [THEME] });
  check("E7. your own profile, not the preview, still wears your theme", mine.document.documentElement.style.getPropertyValue("--bf-glow-a").trim() === visitorTokens["--bf-glow-a"]);
  mine.close();
}

async function editorSection(routes) {
  console.log("\n══ F. the editor: Customise profile ══");
  check("F0. the button \"Customise profile\" starts hidden, and the editor is mounted only for the owner on their own page, never in the preview",
    /<button class="pf-nav-btn pf-nav-btn-share" id="customiseBtn" type="button" hidden>Customise profile<\/button>/.test(FILES[PROFILE]) &&
    /isOwner = \(myUserId === viewUserId\) && !bfPreview;/.test(FILES[PROFILE]) && /if \(isOwner && bfProfileLoadState === "ready" && window\.BFProfileEditor\) \{\n    window\.BFProfileEditor\.mount\(/.test(FILES[PROFILE]) &&
    (FILES[PROFILE].match(/BFProfileEditor\.mount\(/g) || []).length === 1);
  if (!routes) { check("F0. the routes lifted for the editor", false); return; }
  const fake = fakeDb(seed());
  const live = liftRoutes(fake);
  const calls = [];
  const w = page(FILES[PROFILE], ORIGIN + "/profile.html", { token: tokenFor(UID), scripts: [THEME, PD, ED] });
  const doc = w.document, E = w.BFProfileEditor;
  /* The editor's requests, to the API's one base, signed in as the owner, answered by the lifted routes. */
  const API = "https://dynamic-prosperity-production-5382.up.railway.app";
  const stray = [];
  w.fetch = (u, opts) => {
    const url = String(u), method = (opts && opts.method) || "GET";
    const body = opts && opts.body ? JSON.parse(opts.body) : undefined;
    if (url.indexOf(API + "/") !== 0 || !opts || opts.headers.Authorization !== "Bearer " + tokenFor(UID)) { stray.push(method + " " + url); return Promise.resolve({ ok: false, status: 404, json: () => Promise.resolve(null) }); }
    const p = url.slice(API.length);
    calls.push(method + " " + p + (body ? " " + JSON.stringify(body) : ""));
    if (p === "/api/themes") return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ themes: [] }) });
    return callRoute(live, method.toLowerCase(), p, body, UID).then(r => ({ ok: r.status < 300, status: r.status, json: () => Promise.resolve(r.body) }));
  };
  const btn = doc.getElementById("customiseBtn");
  check("F1. before mounting, \"Customise profile\" is hidden", btn.hidden === true);
  const grid = [{ id: G1, title: "One" }, { id: G2, title: "Two" }, { id: G3, title: "<b>Three</b>" }];
  E.mount({ userId: UID, name: "Alice", saved: null, savedPhotoUrl: null, grid: grid, videos: [{ id: V1, title: "Clip A" }, { id: V2, title: "Clip B" }], onSaved() {} });
  check("F1. mounted for the owner: the button shows", btn.hidden === false);
  btn.onclick();
  const panel = doc.getElementById("pdEditor");
  const frame = panel && panel.querySelector("iframe.pde-preview");
  const posts = [];
  if (frame && frame.contentWindow) { try { frame.contentWindow.postMessage = (m, o) => posts.push({ m: JSON.parse(JSON.stringify(m)), o }); } catch (e) { /* read below */ } }
  check("F2. the side panel opens, titled \"Customise profile\"", !!panel && panel.hidden === false && doc.getElementById("pdeTitle").textContent === "Customise profile");
  const tabs = Array.prototype.map.call(panel.querySelectorAll("[role=tab]"), b => b.textContent);
  check("F2. six sections: Theme · Banner · Photo · Layout · Sections · Grid & Videos", JSON.stringify(tabs) === JSON.stringify(["Theme", "Banner", "Photo", "Layout", "Sections", "Grid & Videos"]), tabs.join(" · "));
  const foot = Array.prototype.map.call(panel.querySelectorAll(".pde-foot button"), b => b.textContent);
  check("F2. \"Save\", \"Discard\" and \"Reset profile design\"", JSON.stringify(foot) === JSON.stringify(["Save", "Discard", "Reset profile design"]), foot.join(","));
  check("F3. the live preview is the public view of your own profile (profile.html?id=<you>&bf_preview=1)", !!frame && frame.getAttribute("src") === "/profile.html?id=" + UID + "&bf_preview=1" &&
    /Live preview of your public profile/.test(frame.getAttribute("title")));
  const viewBtns = Array.prototype.map.call(panel.querySelectorAll(".pde-views button"), b => b.textContent);
  panel.querySelector(".pde-views button[data-view=phone]").click();
  const phone = panel.getAttribute("data-view");
  panel.querySelector(".pde-views button[data-view=desktop]").click();
  check("F3. Desktop / Phone toggle the preview's width", JSON.stringify(viewBtns) === "[\"Desktop\",\"Phone\"]" && phone === "phone" && panel.getAttribute("data-view") === "desktop" &&
    /\.pde\[data-view=phone\] \.pde-preview\{width:390px;max-width:100%\}/.test(doc.getElementById("bf-profile-editor-style").textContent));
  // Layout
  panel.querySelector("#pde-tab-layout").click();
  const layouts = Array.prototype.map.call(panel.querySelectorAll("input[name=pde-layout]"), r => r.value);
  const split = panel.querySelector("#pde-layout-split"); split.checked = true; split.dispatchEvent(new w.Event("change"));
  check("F4. Layout: the five layouts, and choosing one changes the draft", JSON.stringify(layouts) === JSON.stringify(L.LAYOUTS) && E.draft().layout === "split");
  const lastPost = () => posts.length ? posts[posts.length - 1] : null;
  check("F4. every change is posted to the preview, same origin only", !!lastPost() && lastPost().m.type === "bf-profile-preview" && lastPost().m.design.layout === "split" && lastPost().o === ORIGIN,
    JSON.stringify(lastPost()).slice(0, 200));
  // Photo
  panel.querySelector("#pde-tab-photo").click();
  const shapes = Array.prototype.map.call(panel.querySelectorAll(".pde-shape"), b => b.getAttribute("data-shape"));
  panel.querySelector(".pde-shape[data-shape=shield]").click();
  check("F5. Photo: eight shapes as buttons, the chosen one pressed", JSON.stringify(shapes) === JSON.stringify(L.SHAPES) && E.draft().photo.shape === "shield" &&
    panel.querySelector(".pde-shape[data-shape=shield]").getAttribute("aria-pressed") === "true");
  // Banner: focal point by keyboard
  panel.querySelector("#pde-tab-banner").click();
  const pad = panel.querySelector(".pde-pad");
  pad.dispatchEvent(new w.KeyboardEvent("keydown", { key: "ArrowRight", shiftKey: true, bubbles: true }));
  pad.dispatchEvent(new w.KeyboardEvent("keydown", { key: "ArrowUp", bubbles: true }));
  pad.dispatchEvent(new w.KeyboardEvent("keydown", { key: "+", bubbles: true }));
  check("F6. Banner: the focal point moves with the arrow keys (Shift for 10) and + zooms", E.draft().banner.focus_x === 60 && E.draft().banner.focus_y === 49 && E.draft().banner.zoom === 110,
    JSON.stringify(E.draft().banner));
  // Sections
  panel.querySelector("#pde-tab-sections").click();
  const rows = () => Array.prototype.map.call(panel.querySelectorAll("ol[data-part=sections] > li"), li => li.getAttribute("data-id"));
  panel.querySelector("ol[data-part=sections] > li[data-id=links] [data-move=down]").click();
  const afterBtn = rows();
  panel.querySelector("ol[data-part=sections] > li[data-id=music] .pde-handle").dispatchEvent(new w.KeyboardEvent("keydown", { key: "ArrowUp", bubbles: true }));
  const afterKey = rows();
  check("F7. Sections: \"Move down\" moves a section", afterBtn.slice(0, 2).join(",") === "about,links", afterBtn.join(","));
  check("F7. ... and the arrow keys on its handle move it", afterKey.slice(-2).join(",") === "music,videos" && E.draft().sections.map(x => x.key).join(",") === afterKey.join(","), afterKey.join(","));
  const showSupport = panel.querySelector("ol[data-part=sections] > li[data-id=support] input.pde-show");
  showSupport.checked = false; showSupport.dispatchEvent(new w.Event("change"));
  check("F7. Show unticked hides the section in the draft", E.draft().sections.filter(x => x.key === "support")[0].show === false);
  const music = panel.querySelector("ol[data-part=sections] > li[data-id=music]"), about = panel.querySelector("ol[data-part=sections] > li[data-id=about]");
  const dt = { setData() {}, effectAllowed: "" };
  const drag = (el, type) => { const e = new w.Event(type, { bubbles: true, cancelable: true }); e.dataTransfer = dt; el.dispatchEvent(e); };
  drag(music, "dragstart"); drag(about, "dragover"); drag(about, "drop");
  check("F7. ... and a row can be dragged (music dropped on the first row)", rows()[0] === "music" && E.draft().sections[0].key === "music", rows().join(","));
  check("F7. every row has Move up and Move down buttons, and its handle names the arrow keys",
    Array.prototype.every.call(panel.querySelectorAll("ol[data-part=sections] > li"), li => !!li.querySelector("[data-move=up]") && !!li.querySelector("[data-move=down]") &&
      /Use the up and down arrow keys/.test(li.querySelector(".pde-handle").getAttribute("aria-label"))));
  // Grid & Videos
  panel.querySelector("#pde-tab-grid").click();
  const gridRows = () => Array.prototype.map.call(panel.querySelectorAll("ol[data-part=grid] > li"), li => li.getAttribute("data-id"));
  panel.querySelector("ol[data-part=grid] > li[data-id=\"" + G3 + "\"] [data-move=up]").click();
  panel.querySelector("ol[data-part=grid] > li[data-id=\"" + G3 + "\"] [data-move=up]").click();
  check("F8. Grid & Videos: the grid reorders, and its titles are text, never markup", gridRows()[0] === G3 && JSON.stringify(E.draft().grid.order) === JSON.stringify([G3, G1, G2]) &&
    !panel.querySelector("ol[data-part=grid] b") && /<b>Three<\/b>/.test(panel.querySelector("ol[data-part=grid] > li .pde-row-name").textContent), gridRows().join(","));
  panel.querySelector("ol[data-part=videos] > li[data-id=\"" + V2 + "\"] .pde-handle").dispatchEvent(new w.KeyboardEvent("keydown", { key: "ArrowUp", bubbles: true }));
  const masonry = panel.querySelector("#pde-gstyle-masonry"); masonry.checked = true; masonry.dispatchEvent(new w.Event("change"));
  const cols2 = panel.querySelector("#pde-cols-2"); cols2.checked = true; cols2.dispatchEvent(new w.Event("change"));
  const car = panel.querySelector("#pde-vlayout-carousel"); car.checked = true; car.dispatchEvent(new w.Event("change"));
  const feat = panel.querySelector("#pde-featured"); feat.checked = true; feat.dispatchEvent(new w.Event("change"));
  check("F8. ... the videos reorder by keyboard; columns, style, layout and featured are set",
    JSON.stringify(E.draft().videos.order) === JSON.stringify([V2, V1]) && E.draft().grid.style === "masonry" && E.draft().grid.columns === 2 && E.draft().videos.layout === "carousel" && E.draft().videos.featured === true,
    JSON.stringify([E.draft().grid, E.draft().videos]));
  // Theme
  panel.querySelector("#pde-tab-theme").click();
  const themeNames = Array.prototype.map.call(panel.querySelectorAll("input[name=pde-theme]"), r => r.parentNode.textContent.trim());
  check("F9. Theme: the original look and the presets to choose from, and a link to the full theme studio",
    themeNames[0] === "The original look" && themeNames.length >= 11 && !!panel.querySelector("a.pde-link[href=\"/settings.html\"]") && /My public profile/.test(panel.querySelector(".pde-body").textContent), themeNames.join("|"));
  const preset = panel.querySelectorAll("input[name=pde-theme]")[1]; preset.checked = true; preset.dispatchEvent(new w.Event("change"));
  check("F9. ... choosing one puts it in the draft, and the panel says what readability protection did", !!E.draft().theme && /Readab/.test(panel.querySelector(".pde-read").textContent));
  // Save
  const want = E.draft();
  await E.save();
  const stored = fake.db.bf_profiles[0].profile_design;
  const putCall = calls.filter(c => /^PUT \/api\/bfp\/profile\/design /.test(c)).pop() || "";
  check("F10. \"Save\" sends the draft to PUT /api/bfp/profile/design, and the real route stores it",
    !!stored && JSON.stringify(JSON.parse(putCall.slice(putCall.indexOf("{"))).design) === JSON.stringify(want) &&
    JSON.stringify(stored) === JSON.stringify(L.validateDesign(want, UID).design) && /Saved\. Visitors now see this design\./.test(panel.querySelector(".pde-status").textContent), putCall.slice(0, 160));
  // Discard
  panel.querySelector("#pde-tab-layout").click();
  const minimal = panel.querySelector("#pde-layout-minimal"); minimal.checked = true; minimal.dispatchEvent(new w.Event("change"));
  const changedTo = E.draft().layout;
  panel.querySelector("[data-act=discard]").click();
  check("F11. \"Discard\" goes back to what is saved", changedTo === "minimal" && E.draft().layout === "split" && /Changes discarded/.test(panel.querySelector(".pde-status").textContent));
  // Reset, asked twice
  const reset = panel.querySelector("[data-act=reset]");
  const before = calls.length;
  reset.click();
  await new Promise(r => setTimeout(r, 0));
  check("F12. \"Reset profile design\" asks first: one press resets nothing", calls.length === before && reset.textContent === "Confirm: back to the default design" && fake.db.bf_profiles[0].profile_design !== null);
  reset.click();
  await new Promise(r => setTimeout(r, 20));
  check("F12. ... the second press resets (DELETE), and the draft is the default design", calls[calls.length - 1] === "DELETE /api/bfp/profile/design" && fake.db.bf_profiles[0].profile_design === null &&
    JSON.stringify(E.draft()) === JSON.stringify(L.DEFAULT_DESIGN) && reset.textContent === "Reset profile design");
  check("F12. every request went to the API's one base, signed in as the member", stray.length === 0 && calls[0] === "GET /api/themes", stray.concat(calls.slice(0, 1)).join(" | "));
  doc.getElementById("pdEditor").dispatchEvent(new w.KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
  check("F13. Escape closes the panel and hands focus back to \"Customise profile\"", panel.hidden === true && doc.activeElement === btn);
  w.close();

  // the preview's side
  const pv = page(FILES[PROFILE], ORIGIN + "/profile.html?id=" + UID + "&bf_preview=1", { token: tokenFor(UID), scripts: [PD] });
  let redrawn = 0;
  pv.bfProfileDesignChanged = () => { redrawn++; };
  const draft = Object.assign(clone(L.DEFAULT_DESIGN), { layout: "minimal" });
  pv.dispatchEvent(new pv.MessageEvent("message", { data: { type: "bf-profile-preview", design: draft, photo_url: null, name: "Alice" }, origin: "https://evil.test", source: pv }));
  const fromEvil = pv.document.documentElement.getAttribute("data-pd-layout");
  pv.dispatchEvent(new pv.MessageEvent("message", { data: { type: "bf-profile-preview", design: draft, photo_url: null, name: "Alice" }, origin: ORIGIN, source: pv }));
  check("F14. the preview ignores a draft from another origin", fromEvil === null, fromEvil);
  check("F14. ... draws a draft from its parent, same origin, and redraws the grid and videos", pv.document.documentElement.getAttribute("data-pd-layout") === "minimal" && redrawn === 1);
  check("F14. ... and keeps the mist and the boombox out of the preview", Array.prototype.some.call(pv.document.querySelectorAll("style"), st => /#tmx-presence-root,#tmx-chat,\.bfm-float\{display:none!important\}/.test(st.textContent)));
  check("F14. profile.html draws the preview's draft, not the saved design, once its data is in",
    /function designNow\(\) \{\n  if \(bfPreview && window\.BFProfileDesign && window\.BFProfileDesign\.current\(\)\) return window\.BFProfileDesign\.current\(\);/.test(FILES[PROFILE]));
  pv.close();
}

async function pagesSection() {
  console.log("\n══ G. the support page, the storefront, the studio, the guide ══");
  const design = Object.assign(clone(L.DEFAULT_DESIGN), { photo: Object.assign(clone(L.DEFAULT_DESIGN.photo), { shape: "diamond" }) });
  const view = { state: "on", username: "alice", displayName: "Alice </script><script>alert(1)</script>", photo: null, headline: null, links: [], discoverable: false,
    design: { design: design, photo_url: null } };
  let html = "";
  try { html = SP.render(view); } catch (e) { check("G1. the support page renders with a design", false, e.message); }
  const tag = /<script type="application\/json" id="bfProfileDesign">([\s\S]*?)<\/script>/.exec(html);
  check("G1. the support page carries the validated design as JSON data, then loads the renderer",
    !!tag && JSON.stringify(JSON.parse(tag[1]).design) === JSON.stringify(design) && html.indexOf("<script src=\"/scripts/bf-profile-design.js\"></script>") > html.indexOf("id=\"bfProfileDesign\""));
  const sneaky = Object.assign({}, view, { design: { design: Object.assign(clone(design), { evil: "</script><script>alert(2)</script>" }), photo_url: null } });
  const h2 = SP.render(sneaky);
  check("G1. ... and no \"</script\" in the data can close its tag", !/alert\(2\)<\/script>/.test(h2.slice(h2.indexOf("id=\"bfProfileDesign\""), h2.indexOf("bf-profile-design.js"))) &&
    h2.indexOf("\\u003c/script>") !== -1);
  const noDesign = SP.render(Object.assign({}, view, { design: undefined }));
  check("G1. no design, no tags: the page is the shell's", noDesign.indexOf("bfProfileDesign") === -1 && noDesign.indexOf("bf-profile-design.js") === -1);
  const sw = new JSDOM(html.replace(/<script src=[^>]*><\/script>/g, ""), { url: ORIGIN + "/support/alice", runScripts: "outside-only" }).window;
  sw.eval(FILES[PD]);
  await new Promise(r => setTimeout(r, 30));   // jsdom fires DOMContentLoaded itself, after parsing
  check("G2. the support page draws the design on load (diamond photo, support page)", sw.document.documentElement.getAttribute("data-pd-page") === "support" &&
    sw.document.documentElement.getAttribute("data-pd-shape") === "diamond" && !!sw.document.querySelector(".pd-ring-host.pd-ring"));
  sw.close();
  check("G3. /support/:username sends the validated design (profileDesignReply) with the page",
    /Object\.assign\(view, \{ design: profileDesignReply\(designRead\.data\.profile_design, member\.user_id\) \}\);/.test(FILES[SERVER]));
  check("G4. seller.html loads the renderer, orders its grid and videos by the design, and draws it as the storefront",
    FILES[SELLER].indexOf("<script src=\"/scripts/bf-profile-design.js\"></script>") !== -1 && /if \(PD\) portfolio = PD\.ordered\(portfolio, "grid", design\);/.test(FILES[SELLER]) &&
    /if \(PD\) videos = PD\.ordered\(videos, "videos", design\);/.test(FILES[SELLER]) && /PD\.apply\(design, \{ page: "seller",/.test(FILES[SELLER]));
  check("G4. the storefront's route sends only the validated design", /const sellerDesign = profileDesignReply\(seller\.profile_design, seller\.user_id\);\n    seller\.profile_design = sellerDesign\.design;/.test(FILES[SERVER]));
  const sw2 = page(FILES[SELLER], ORIGIN + "/seller.html?u=alice", { scripts: [PD] });
  const sorted = sw2.BFProfileDesign.ordered([{ id: G1 }, { id: G2 }, { id: G3 }], "grid", Object.assign(clone(L.DEFAULT_DESIGN), { grid: { columns: 3, style: "square", gap: "m", order: [G2, G3] } })).map(x => x.id);
  sw2.BFProfileDesign.apply(Object.assign(clone(L.DEFAULT_DESIGN), { layout: "magazine", photo: Object.assign(clone(L.DEFAULT_DESIGN.photo), { shape: "octagon" }) }), { page: "seller", name: "Alice" });
  check("G4. on the storefront: the grid's order, the photo's shape, and the storefront's own layout", JSON.stringify(sorted) === JSON.stringify([G2, G3, G1]) &&
    sw2.document.documentElement.getAttribute("data-pd-shape") === "octagon" && sw2.document.documentElement.getAttribute("data-pd-layout") === "standard");
  sw2.close();
  check("G5. the theme studio: \"My public profile\" as a scope, applied with PUT /api/bfp/profile/design { theme_id }",
    /<label><input type="radio" name="tsScope" value="profile" \/> My public profile<\/label>/.test(FILES[SETTINGS]) &&
    /if \(s === "profile"\) \{\n      return call\("PUT", "\/api\/bfp\/profile\/design", \{ theme_id: editingId \}, "apply"\)/.test(FILES[STUDIO]));
  const entry = /"profile\.html": \[([\s\S]*?)\n    \]/.exec(FILES[GUIDE]);
  check("G6. the profile page's guide tells the member to press \"Customise profile\" and \"Save\"", !!entry && /\\"Customise profile\\"[^"\n]*previewed as visitors see it[^\n]*\\"Save\\"/.test(entry[1]), entry && entry[1].slice(0, 200));
}

(async function () {
  const routes = await routesSection();
  rendererSection();
  themeSection();
  await editorSection(routes);
  await pagesSection();
  finish();
})().catch(err => { failures++; console.log("    FAIL  checkProfileDesign crashed: " + (err && err.stack || err)); finish(); });
