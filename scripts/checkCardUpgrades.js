"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkCardUpgrades — Card upgrades C1 (migration 171, Nov 6 2026): the card
   page served with its own preview tags, an opt-in search switch, daily view
   and tap counts that store nothing about visitors, validated card media and
   layout, a card page limiter, and library pickers for the still image and
   the video.

   server.js's card routes are lifted and run in a vm against an in-memory
   database whose rpc only records its calls. lib/cardPage.js, its generated
   shell and lib/legalPages.js run for real, compiled from their (possibly
   mutated) text. card-view.html runs in jsdom. Nothing leaves the machine:
   every socket and DNS lookup is a tripwire.

   WHAT THIS PROVES
     U. URLs: /c/<slug>, else /card/<token>, in server.js and bf-card.js; the
        old card-view.html?token= link moves to /card/<token>, ?via= kept;
        _redirects proxies both and the cards sitemap above the catch-all.
     H. The head: name, title and company only (never the email or phone),
        escaped, the photo only when shown and https, noindex unless
        discoverable; the security headers equal _headers; no-store; the
        generated shell equals the frontend's card-view.html.
     S. States: 404 "Card not found" for a missing card, a lapsed owner and a
        lookup that throws, without a count.
     C. Counting: views and qr_views; nothing for HEAD, no User-Agent, every
        bot word or a lapsed owner; the rpc's kind allowlist; nothing about
        the visitor stored or logged; no cookie.
     T. Taps: the kinds, the refs, the limiter, the bot rule, 204; the page's
        beacons from Call, Email, Save Contact and Support never block them.
     Q. The QR codes encode the public URL with ?via=qr.
     D. Stats: owner only, 30 UTC days, zero-filled, the 7- and 30-day totals.
     M. The sitemap's rules and its cache, cleared by card writes.
     V. Media URL validation; the media_layout allowlist and its 4 KB limit;
        the card page's quoted, validated background.
     L. The library buttons, and that cleanup never removes a library file.
     E. The editor's panel: the switch, the line word for word, textContent.
     G. The privacy sentence in source and in the built pages; the terms
        version; the guide tips.
     R. The migration as run, and the registries.
     Z. Zero network.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check. A mutation
   whose search text does not match exactly once is an ERROR.

   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm"), Module = require("module"), net = require("net"), dns = require("dns");
const s = require("./_shared");

const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkCardUpgrades: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkCardUpgrades: no network"); };

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";

const SV = "server.js", CP = "lib/cardPage.js", GEN = "lib/cardShell.generated.js", LP_FILE = "lib/legalPages.js", MIG = "supabase/migrations/171_card_counts.sql";
const CV = "fe:card-view.html", DC = "fe:digital-cards.html", BFC = "fe:scripts/bf-card.js";

const MUTATIONS = {
  // a page view stores the visitor's address
  "count-stores-ip": [[SV, "    if (cardPage.isCountableRequest(req)) {\n      await bumpCardCount(row.id, \"views\");",
    "    if (cardPage.isCountableRequest(req)) {\n      await supabase.from(\"card_view_counts\").insert({ card_id: row.id, day: \"2026-11-06\", ip: req.ip });\n      await bumpCardCount(row.id, \"views\");"]],
  // a page view keeps the visitor's User-Agent, in the log
  "count-stores-ua": [[SV, "    if (cardPage.isCountableRequest(req)) {\n      await bumpCardCount(row.id, \"views\");",
    "    if (cardPage.isCountableRequest(req)) {\n      console.error(\"[card page] seen by \" + req.headers[\"user-agent\"]);\n      await bumpCardCount(row.id, \"views\");"]],
  // the card page sets a cookie
  "cookie-set": [[SV, "    return res.status(200).send(html);\n  } catch (pageErr) {", "    res.cookie(\"bf_seen\", \"1\");\n    return res.status(200).send(html);\n  } catch (pageErr) {"]],
  // a bot's view is counted
  "bot-counted": [[CP, "  return !BOT_RE.test(ua);", "  return true;"]],
  // a HEAD request is counted
  "head-counted": [[CP, "  if (!req || (req.method !== \"GET\" && req.method !== \"POST\")) return false;", "  if (!req) return false;"]],
  // a request with no User-Agent is counted
  "missing-ua-counted": [[CP, "  if (typeof ua !== \"string\" || ua.trim() === \"\") return false;\n", ""]],
  // a lapsed owner's card is served
  "lapsed-card-served": [[SV, "    if (!row || !visible) return res.status(404).send(cardPage.renderNotFound());", "    if (!row) return res.status(404).send(cardPage.renderNotFound());"]],
  // a lapsed owner's card is counted before it is refused
  "lapsed-card-counted": [[SV, "    if (!row || !visible) return res.status(404).send(cardPage.renderNotFound());",
    "    if (row && cardPage.isCountableRequest(req)) await bumpCardCount(row.id, \"views\");\n    if (!row || !visible) return res.status(404).send(cardPage.renderNotFound());"]],
  // a plan lookup that throws shows the card
  "lookup-throw-served": [[SV, "} catch (planErr) { visible = false; }", "} catch (planErr) { visible = true; }"]],
  // a card no one chose to list is indexable
  "noindex-ignored": [[CP, "  var robots = card.discoverable === true ? \"index, follow\" : \"noindex\";", "  var robots = \"index, follow\";"]],
  // the sitemap lists cards their members did not let search engines find
  "sitemap-includes-undiscoverable": [[SV, "      const findable = (listedCards.data || []).filter(function (r) { return r.discoverable === true && typeof r.slug",
    "      const findable = (listedCards.data || []).filter(function (r) { return typeof r.slug"],
    [SV, "        .eq(\"discoverable\", true).not(\"slug\", \"is\", null).limit(5000);", "        .not(\"slug\", \"is\", null).limit(5000);"]],
  // og:title is not escaped
  "og-unescaped": [[CP, "    '  <meta property=\"og:title\" content=\"' + esc(name) + '\"/>',", "    '  <meta property=\"og:title\" content=\"' + name + '\"/>',"]],
  // the email and phone reach the head
  "email-in-head": [[SV, "      full_name: shown.full_name, job_title: shown.job_title, company: shown.company,",
    "      full_name: shown.full_name, job_title: [shown.job_title, shown.email, shown.phone].join(\" \"), company: shown.company,"]],
  // a hidden photo is the preview image
  "hidden-photo-in-head": [[CP, "  var image = (card.show_photo === true && imageOf(card.photo_url)) || DEFAULT_IMAGE;", "  var image = imageOf(card.photo_url) || DEFAULT_IMAGE;"]],
  // a tap may name any counter
  "tap-any-kind": [[CP, "Object.prototype.hasOwnProperty.call(TAP_KINDS, kind) ? TAP_KINDS[kind] : null;", "Object.prototype.hasOwnProperty.call(TAP_KINDS, kind) ? TAP_KINDS[kind] : kind;"]],
  // a lapsed owner's card counts taps
  "tap-for-lapsed": [[SV, "    if (tapped && (await ownerPagePublic(tapped.user_id)) === true) await bumpCardCount(tapped.id, column);", "    if (tapped) await bumpCardCount(tapped.id, column);"]],
  // taps are not limited
  "tap-unlimited": [[SV, "app.post(\"/api/cards/tap\", cardTapLimiter, express.text(", "app.post(\"/api/cards/tap\", express.text("]],
  // a member reads another member's counts
  "stats-foreign-card": [[SV, ".select(\"id\").eq(\"user_id\", req.user.id).eq(\"id\", statsCardId).maybeSingle();", ".select(\"id\").eq(\"id\", statsCardId).maybeSingle();"]],
  // days with no visits are left out
  "stats-not-zero-filled": [[CP, "  return { days: list, totals: { last_7_days: t7, last_30_days: t30 } };",
    "  return { days: list.filter(function (d) { return !!byDay[d.day]; }), totals: { last_7_days: t7, last_30_days: t30 } };"]],
  // the card page may be cached
  "cache-public": [[CP, "  out[\"Cache-Control\"] = \"no-store\";", "  out[\"Cache-Control\"] = \"public, max-age=300\";"]],
  // the QR codes carry no via=qr
  "qr-without-via": [[BFC, "    return u + (u.indexOf(\"?\") === -1 ? \"?\" : \"&\") + \"via=qr\";", "    return u;"]],
  // the old card-view.html?token= link no longer reaches the card
  "legacy-token-link-broken": [[CV, "  window.location.replace(\"/card/\" + t + (via ? \"?via=\" + encodeURIComponent(via) : \"\"));\n", ""]],
  // the card page applies any background URL
  "bg-url-unvalidated": [[CV, "  if (c.bg_image_url && window.bfCard.isSafeMediaUrl(c.bg_image_url)) {", "  if (c.bg_image_url) {"]],
  // the background CSS value is unquoted
  "css-unquoted": [[CV, "    bgLayer.style.backgroundImage = 'url(\"' + c.bg_image_url + '\")';", "    bgLayer.style.backgroundImage = \"url(\" + c.bg_image_url + \")\";"]],
  // media_layout keeps keys the editor never writes
  "media-layout-unknown-key": [[CP, "  Object.keys(MEDIA_LAYOUT_ALLOWLIST).forEach(function (k) {\n    if (!Object.prototype.hasOwnProperty.call(raw, k)) return;",
    "  Object.keys(raw).forEach(function (k) {\n    if (!MEDIA_LAYOUT_ALLOWLIST[k]) { out[k] = raw[k]; return; }"]],
  // media_layout has no size limit
  "media-layout-oversize": [[CP, "  if (Buffer.byteLength(sent, \"utf8\") > MEDIA_LAYOUT_MAX_BYTES) {", "  if (false) {"]],
  // a call tap waits for, or stops, the call
  "beacon-blocks-tap": [[CV, "document.getElementById(\"pPhone\").addEventListener(\"click\", function () { if (this.getAttribute(\"href\")) sendTap(\"tel\"); });",
    "document.getElementById(\"pPhone\").addEventListener(\"click\", function (e) { e.preventDefault(); if (this.getAttribute(\"href\")) sendTap(\"tel\"); });"]],
  // the served headers drift from the frontend's
  "headers-drift": [[GEN, "\"X-Frame-Options\": \"DENY\"", "\"X-Frame-Options\": \"SAMEORIGIN\""]],
  // the Privacy Policy loses the card visits sentence
  "privacy-sentence-removed": [[LP_FILE, "      CARD_VISITS_PRIVACY_SENTENCE,\n", ""]],
  // the editor's stats list is parsed as HTML
  "innerHTML-new-code": [[DC, "      li.textContent = String(d.day || \"\") + \": \" + cardCountLine(d);", "      li.innerHTML = String(d.day || \"\") + \": \" + cardCountLine(d);"]],
  // ── earned by the code ──
  // every view also counts as a QR scan
  "qr-views-always": [[SV, "      if (req.query && req.query.via === \"qr\") await bumpCardCount(row.id, \"qr_views\");", "      if (req.query) await bumpCardCount(row.id, \"qr_views\");"]],
  // a card edit leaves the cards sitemap stale
  "sitemap-cache-not-cleared": [[SV, "    cardSitemapCache = { xml: null, at: 0 };\n    if (priorMedia) {\n      await removeDisplacedCardMedia(priorMedia, data, req.user.id);",
    "    if (priorMedia) {\n      await removeDisplacedCardMedia(priorMedia, data, req.user.id);"]],
  // saving a card removes a Media Library file it no longer uses
  "library-file-removed": [[SV, "    if (memberMedia.isLibraryKey(key)) continue;\n", ""]],
  // any media URL is saved
  "media-url-unvalidated": [[CP, "  if (isSafeMediaUrl(value)) return { value: value };\n  return { error:", "  return { value: value };\n  return { error:"]],
  // the card page is not rate-limited
  "page-not-rate-limited": [[SV, "app.get(\"/c/:slug\", cardPageLimiter, async function", "app.get(\"/c/:slug\", async function"]],
  // the search switch takes anything
  "discoverable-not-boolean": [[SV, "    if (typeof body.discoverable !== \"boolean\") return { error: \"Letting search engines find a card is true or false.\" };\n", ""]],
  // a page view counts nothing
  "views-not-counted": [[SV, "      await bumpCardCount(row.id, \"views\");\n      if (req.query", "      if (req.query"]],
  // the tap route counts a bot
  "tap-bot-counted": [[SV, "  if (!cardPage.isCountableRequest(req)) return res.status(204).end();\n", ""]],
  // the editor's QR has no via=qr
  "editor-qr-without-via": [[DC, "  var url = window.bfCard.qrUrl(cardQrUrl());", "  var url = cardQrUrl();"]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

/* ── the files ──────────────────────────────────────────────────────────── */
const lf = t => t.replace(/\r\n/g, "\n");
const ALL = {};
[SV, CP, GEN, "lib/supportLinks.js", "lib/scrollbars.js", LP_FILE, "lib/legal.js", "lib/yourData.js", "lib/backup.js", "lib/schemaCheck.js", MIG,
  "scripts/buildCardShell.js"].forEach(f => { ALL[f] = lf(fs.readFileSync(path.join(REPO, f), "utf8")); });
["card-view.html", "digital-cards.html", "scripts/bf-card.js", "scripts/media-picker.js", "_headers", "_redirects", "sitemap.xml", "privacy.html",
  "scripts/termaximus-guide.js"].forEach(f => {
  const p = path.join(FRONTEND, f);
  ALL["fe:" + f] = fs.existsSync(p) ? lf(fs.readFileSync(p, "utf8")) : null;
});
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) ALL[file] = s.replaceOnce(ALL[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}
const SRC = ALL[SV];
const fe = f => ALL["fe:" + f];

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}
const J = JSON.stringify;
const BS = String.fromCharCode(92), EM = String.fromCharCode(0x2014);

/* ── the libs, compiled from the (possibly mutated) text ─────────────────── */
const realRequire = Module.createRequire(path.join(REPO, "server.js"));
const LIB_CACHE = {};
function loadLib(rel) {
  if (LIB_CACHE[rel]) return LIB_CACHE[rel].exports;
  const file = path.join(REPO, rel);
  const m = new Module(file, module);
  m.filename = file;
  m.paths = Module._nodeModulePaths(path.dirname(file));
  LIB_CACHE[rel] = m;
  m.require = function (req) {
    if (req.indexOf("./") === 0 || req.indexOf("../") === 0) {
      const target = path.relative(REPO, path.join(path.dirname(file), req)).split(path.sep).join("/").replace(/(\.js)?$/, ".js");
      if (ALL[target] !== undefined) return loadLib(target);
      return realRequire(path.join(REPO, target));
    }
    return realRequire(req);
  };
  m._compile(ALL[rel], file);
  return m.exports;
}
let CPL = null, LP = null, LEGAL = null, YD = null, BK = null, SCH = null, BUILD = null, LIB_ERROR = null;
try {
  CPL = loadLib(CP); LP = loadLib(LP_FILE); LEGAL = loadLib("lib/legal.js"); YD = loadLib("lib/yourData.js"); BK = loadLib("lib/backup.js");
  SCH = loadLib("lib/schemaCheck.js"); BUILD = loadLib("scripts/buildCardShell.js");
} catch (e) { LIB_ERROR = e; }

/* ── an in-memory database; rpc only records ─────────────────────────────── */
let idSeq = 1;
const nextId = () => "00000000-0000-4000-8000-" + String(100000000000 + (idSeq++));
function project(rows, cols) {
  if (!cols || cols === "*") return rows.map(r => JSON.parse(JSON.stringify(r)));
  const names = cols.split(",").map(c => c.trim());
  return rows.map(r => { const o = {}; names.forEach(n => { o[n] = r[n] === undefined ? null : JSON.parse(JSON.stringify(r[n])); }); return o; });
}
const CARD_DEFAULTS = () => ({ slug: null, show_email: true, show_phone: true, show_photo: true, discoverable: false, media_layout: {}, video_url: null,
  bg_image_url: null, still_image_url: null, audio_url: null, holographic_style: false });
function makeDb(seed) {
  const t = JSON.parse(JSON.stringify(seed));
  const db = { t, reads: [], writes: [], rpcs: [], removed: [] };
  db.from = function (table) {
    const st = { op: "select", cols: null, ret: null, filters: [], orders: [], limit: null, row: null };
    function run() {
      db.reads.push(table + ":" + st.op);
      if (!t[table]) return Promise.resolve({ data: null, error: { code: "42P01", message: "relation " + table + " does not exist" } });
      if (st.op === "insert") {
        const rows = (Array.isArray(st.row) ? st.row : [st.row]).map(r => Object.assign(table === "digital_cards" ? CARD_DEFAULTS() : {}, { id: nextId() }, JSON.parse(JSON.stringify(r))));
        t[table].push(...rows);
        db.writes.push({ table, op: "insert", row: JSON.parse(JSON.stringify(st.row)) });
        return Promise.resolve({ data: st.ret ? project(rows, st.ret) : null, error: null });
      }
      let rows = t[table].filter(r => st.filters.every(f => f(r)));
      if (st.op === "update") {
        rows.forEach(r => Object.assign(r, JSON.parse(JSON.stringify(st.row))));
        if (rows.length) db.writes.push({ table, op: "update", row: JSON.parse(JSON.stringify(st.row)) });
        return Promise.resolve({ data: project(rows, st.ret || "*"), error: null });
      }
      if (st.op === "delete") {
        t[table] = t[table].filter(r => rows.indexOf(r) === -1);
        if (rows.length) db.writes.push({ table, op: "delete" });
        return Promise.resolve({ data: null, error: null });
      }
      rows = rows.slice().sort((x, y) => { for (const [c, asc] of st.orders) { if (x[c] < y[c]) return asc ? -1 : 1; if (x[c] > y[c]) return asc ? 1 : -1; } return 0; });
      if (st.limit != null) rows = rows.slice(0, st.limit);
      return Promise.resolve({ data: project(rows, st.cols), error: null });
    }
    const q = {
      select(c) { if (st.op === "select") st.cols = c || "*"; else st.ret = c || "*"; return q; },
      insert(r) { st.op = "insert"; st.row = r; return q; },
      update(p) { st.op = "update"; st.row = p; return q; },
      delete() { st.op = "delete"; return q; },
      eq(c, v) { st.filters.push(r => r[c] === v); return q; },
      neq(c, v) { st.filters.push(r => r[c] !== v); return q; },
      gte(c, v) { st.filters.push(r => r[c] >= v); return q; },
      in(c, vs) { st.filters.push(r => vs.indexOf(r[c]) !== -1); return q; },
      not(c, op, v) { st.filters.push(r => op === "is" && v === null ? r[c] !== null && r[c] !== undefined : true); return q; },
      order(c, o) { st.orders.push([c, !o || o.ascending !== false]); return q; },
      limit(n) { st.limit = n; return q; },
      maybeSingle() { return run().then(r => r.error ? r : r.data.length > 1 ? { data: null, error: { code: "PGRST116", message: r.data.length + " rows" } } : { data: r.data[0] || null, error: null }); },
      single() { return run().then(r => r.error ? r : r.data.length !== 1 ? { data: null, error: { code: "PGRST116", message: r.data.length + " rows" } } : { data: r.data[0], error: null }); },
      then(ok, bad) { return run().then(ok, bad); }
    };
    return q;
  };
  db.rpc = async function (fn, args) { db.rpcs.push({ fn, args: JSON.parse(JSON.stringify(args)) }); return db.rpcFails ? { data: null, error: { code: "XX000", message: "rpc down" } } : { data: null, error: null }; };
  return db;
}

/* ── the fixture ─────────────────────────────────────────────────────────── */
const OWNER = "0a0a0a0a-0000-4000-8000-000000000001", OTHER = "0b0b0b0b-0000-4000-8000-000000000002", LAPSED = "0c0c0c0c-0000-4000-8000-000000000003",
  THROWER = "0d0d0d0d-0000-4000-8000-000000000004";
const CID = { jane: "c0000000-0000-4000-8000-000000000001", hidden: "c0000000-0000-4000-8000-000000000002", token: "c0000000-0000-4000-8000-000000000003",
  lapsed: "c0000000-0000-4000-8000-000000000004", thrower: "c0000000-0000-4000-8000-000000000005", other: "c0000000-0000-4000-8000-000000000006",
  quiet: "c0000000-0000-4000-8000-000000000007" };
const TOK = { jane: "a".repeat(32), hidden: "b".repeat(32), token: "0123456789abcdef0123456789abcdef", lapsed: "c".repeat(32), thrower: "d".repeat(32),
  other: "e".repeat(32), quiet: "f".repeat(32) };
const SUPA = "https://proj.supabase.co";
const PUB = SUPA + "/storage/v1/object/public/bf-public/";
const HOSTILE_NAME = "Jane \"Q\" <b>Doe</b> & 'Co'";
const PRIVATE = { email: "jane+bftest@example.com", phone: "+1 555 0100" };
const PHOTO = PUB + "avatars/" + OWNER + "/me.jpg";
const LIB_IMG = PUB + "media/" + OWNER + "/" + "1".repeat(32) + ".jpg", LIB_VID = PUB + "media/" + OWNER + "/" + "2".repeat(32) + ".mp4";
const CARD_IMG = PUB + "card-media/" + OWNER + "/1730000000000_still.jpg";
const BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36";
function card(key, owner, extra) {
  return Object.assign(CARD_DEFAULTS(), { id: CID[key], user_id: owner, share_token: TOK[key], full_name: "Card " + key, job_title: "Title " + key, company: "Co " + key,
    email: key + "+bftest@example.com", phone: "+1 555 01" + String(Object.keys(CID).indexOf(key)).padStart(2, "0"), website: "", theme: "dark",
    created_at: "2026-11-01T10:00:00.000Z", updated_at: "2026-11-01T10:00:00.000Z" }, extra || {});
}
function seed() {
  return {
    digital_cards: [
      card("jane", OWNER, { slug: "jane-doe", full_name: HOSTILE_NAME, job_title: "Owner <i>&</i>", company: "Doe & Daughters", email: PRIVATE.email, phone: PRIVATE.phone,
        discoverable: false, still_image_url: CARD_IMG, bg_image_url: LIB_IMG }),
      card("hidden", OWNER, { slug: "hidden-photo", show_photo: false, discoverable: true }),
      card("token", OWNER, { slug: null, discoverable: true }),
      card("lapsed", LAPSED, { slug: "lapsed-card", discoverable: true }),
      card("thrower", THROWER, { slug: "thrower-card", discoverable: true }),
      card("other", OTHER, { slug: "other-card", discoverable: false }),
      card("quiet", OWNER, { slug: "quiet-card", discoverable: false })
    ],
    bf_profiles: [{ user_id: OWNER, avatar_url: PHOTO }, { user_id: OTHER, avatar_url: "http://insecure.example.com/x.jpg" }, { user_id: LAPSED, avatar_url: PHOTO }],
    card_view_counts: [],
    member_support: []
  };
}

/* ── server.js, lifted ───────────────────────────────────────────────────── */
function routeText(sig) {
  const start = SRC.indexOf(sig);
  if (start < 0 || SRC.indexOf(sig, start + 1) !== -1) return null;
  const end = s.braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("async function", start)));
  return SRC.slice(start, end) + ");";
}
function fnText(name) {
  const m = new RegExp("^(?:async )?function " + name + "\\(", "m").exec(SRC);
  if (!m) return null;
  return SRC.slice(m.index, s.braceMatch(SRC, SRC.indexOf(") {", m.index) + 2));
}
const R = {
  slugPage: routeText('app.get("/c/:slug",'),
  tokenPage: routeText('app.get("/card/:token",'),
  tap: routeText('app.post("/api/cards/tap",'),
  stats: routeText('app.get("/api/digital-cards/:id/stats",'),
  sitemap: routeText('app.get("/api/sitemap/cards.xml",'),
  create: routeText('app.post("/api/digital-cards",'),
  edit: routeText('app.put("/api/digital-cards/:id",'),
  remove: routeText('app.delete("/api/digital-cards/:id",')
};
const STUB = new Set(["supabase", "console", "process", "require", "module", "app", "requireAuth", "getUserPlan", "rateLimit", "express", "nowIso",
  "Date", "Math", "JSON", "Object", "Number", "String", "Array", "Promise", "Error", "Set", "Map", "URL", "Buffer"]);
function closure(root) {
  const have = new Map();
  const queue = [...new Set(root.match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || STUB.has(name)) continue;
    const def = s.definitionOf(SRC, name);
    if (!def) continue;
    try { new vm.Script(def); } catch (e) { continue; }
    have.set(name, def);
    new Set(def.match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !STUB.has(id)) queue.push(id); });
  }
  return [...have.values()].sort((x, y) => SRC.indexOf(x) - SRC.indexOf(y)).join("\n\n") + "\n\n" + root;
}
const NOW_ISO = "2026-11-06T15:00:00.000Z";
const LOGS = [];
let CUR = makeDb(seed());
const ROUTES = {};
const LIMITERS = [];
const PLAN = { [OWNER]: true, [OTHER]: true, [LAPSED]: false };
const CTX = {
  supabase: {
    from: t => CUR.from(t),
    rpc: (fn, args) => CUR.rpc(fn, args),
    storage: { from: bucket => ({ remove: async keys => { CUR.removed.push({ bucket, keys: keys.slice() }); return { data: null, error: null }; } }) }
  },
  console: { log() { LOGS.push([].slice.call(arguments).join(" ")); }, warn() { LOGS.push([].slice.call(arguments).join(" ")); }, error() { LOGS.push([].slice.call(arguments).join(" ")); } },
  process: { env: { SUPABASE_URL: SUPA } },
  require: function (p) {
    if (p.indexOf("./") === 0) { const rel = p.slice(2).replace(/(\.js)?$/, ".js"); if (ALL[rel] !== undefined) return loadLib(rel); return realRequire(p); }
    return realRequire(p);
  },
  requireAuth: function requireAuth(req, res, next) { if (!req.user) return res.status(401).json({ error: "Authentication required" }); next(); },
  getUserPlan: async function (id) {
    if (id === THROWER) throw new Error("plan lookup down");
    return PLAN[id] ? { active: true, plan: "all_access" } : { active: false, plan: null, inactive_reason: "no_subscription" };
  },
  rateLimit: function (opts) {
    const counts = {};
    const f = function limiter(req, res, next) {
      const k = req.ip || "none";
      counts[k] = (counts[k] || 0) + 1;
      if (counts[k] > opts.max) return res.status(429).json({ error: "limited" });
      next();
    };
    f.opts = opts; f.reset = () => { Object.keys(counts).forEach(k => delete counts[k]); };
    LIMITERS.push(f);
    return f;
  },
  express: { text: function (opts) { const f = function textParser(req, res, next) { next(); }; f.opts = opts; return f; } },
  nowIso: () => NOW_ISO,
  URL, URLSearchParams, Buffer,
  app: {}
};
["get", "post", "put", "delete", "use"].forEach(v => { CTX.app[v] = function (p) { ROUTES[v + " " + p] = Array.prototype.slice.call(arguments, 1); }; });
let LIFT_ERROR = null;
try {
  vm.createContext(CTX);
  const root = Object.values(R).concat([fnText("ownerPagePublic"), fnText("publicOwnersAmong"), fnText("removeDisplacedCardMedia")]).join("\n\n");
  vm.runInContext(closure(root), CTX);
} catch (e) { LIFT_ERROR = e; }
const resetLimits = () => LIMITERS.forEach(l => l.reset());

function mkRes() {
  return {
    statusCode: 200, body: undefined, text: undefined, headers: {}, ended: false, cookies: [],
    status(c) { this.statusCode = c; return this; },
    json(b) { this.body = JSON.parse(JSON.stringify(b)); this.ended = true; return this; },
    send(t) { this.text = String(t); this.ended = true; return this; },
    end() { this.ended = true; return this; },
    set(k, v) { if (k && typeof k === "object") Object.keys(k).forEach(n => { this.headers[n.toLowerCase()] = k[n]; }); else this.headers[String(k).toLowerCase()] = v; return this; },
    setHeader(k, v) { this.headers[String(k).toLowerCase()] = v; },
    cookie(n, v) { this.cookies.push(n + "=" + v); this.headers["set-cookie"] = n + "=" + v; return this; },
    type(v) { this.headers["content-type"] = v; return this; }
  };
}
async function hit(key, o) {
  o = o || {};
  const fns = ROUTES[key];
  if (!fns) return { status: 0, error: "no route " + key };
  const headers = Object.assign({}, o.headers || {});
  if (o.ua !== undefined) { if (o.ua !== null) headers["user-agent"] = o.ua; } else headers["user-agent"] = BROWSER_UA;
  const req = { method: o.method || key.split(" ")[0].toUpperCase(), user: o.user ? { id: o.user, role: "user" } : undefined, body: o.body === undefined ? {} : o.body,
    params: o.params || {}, query: o.query || {}, headers, ip: o.ip || "203.0.113.7" };
  const res = mkRes();
  let err = null;
  for (let i = 0; i < fns.length; i++) {
    let advanced = false;
    await fns[i](req, res, e => { if (e) err = e; else advanced = true; });
    if (err || !advanced || res.ended) break;
  }
  return { status: res.statusCode, body: res.body, text: res.text, headers: res.headers, cookies: res.cookies, err: err && (err.message || String(err)) };
}
const names = key => (ROUTES[key] || []).map(f => f.name);
const slugPage = (slug, o) => hit("get /c/:slug", Object.assign({ params: { slug } }, o || {}));
const tokenPage = (token, o) => hit("get /card/:token", Object.assign({ params: { token } }, o || {}));
const tap = (body, o) => hit("post /api/cards/tap", Object.assign({ body }, o || {}));
const rpcKinds = () => CUR.rpcs.map(r => r.args.p_kind + "@" + r.args.p_card);
const headOf = html => (/<head>[\s\S]*?<\/head>/.exec(html || "") || [""])[0];
function metaOf(html, attr, name) {
  const re = new RegExp("<meta " + attr + "=\"" + name.replace(/[.:]/g, m => BS + m) + "\" content=\"([^\"]*)\"/>");
  const m = re.exec(headOf(html));
  return m ? m[1] : null;
}
const unesc = t => String(t).replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, "\"").replace(/&#39;/g, "'").replace(/&amp;/g, "&");

/* ── jsdom ───────────────────────────────────────────────────────────────── */
let JSDOM = null, VirtualConsole = null;
try { const jd = realRequire("jsdom"); JSDOM = jd.JSDOM; VirtualConsole = jd.VirtualConsole; } catch (e) { JSDOM = null; }
const tick = () => new Promise(r => setTimeout(r, 0));
async function settle(n) { for (let i = 0; i < (n || 12); i++) await tick(); }
const stripScripts = html => html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/g, "");
function inlineMain(html) {
  const all = [...String(html).matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
  return all.find(t => t.indexOf("var API_URL") !== -1) || "";
}
/* card-view.html (or a served page) in jsdom, the card's API answer held until release(). */
function cardView(opts) {
  const vc = new VirtualConsole();
  const dom = new JSDOM(stripScripts(opts.html || fe("card-view.html")), { url: opts.url, runScripts: "outside-only", pretendToBeVisual: true, virtualConsole: vc });
  const w = dom.window, log = { beacons: [], fetches: [], qr: [], downloads: 0, errors: [] };
  w.QRCode = { toCanvas(canvas, text, o, cb) { log.qr.push({ id: canvas && canvas.id, text: String(text) }); if (cb) cb(null); } };
  const beacon = opts.beacon === "none" ? undefined : function (url, body) { if (opts.beacon === "throw") throw new Error("beacon down"); log.beacons.push({ url: String(url), body: String(body) }); return true; };
  Object.defineProperty(w.navigator, "sendBeacon", { value: beacon, configurable: true, writable: true });
  let release; const gate = new Promise(r => { release = r; });
  w.fetch = function (url, init) {
    log.fetches.push({ url: String(url), init: init || null });
    let p;
    if (/\/api\/cards\/(slug|share)\//.test(String(url))) p = gate.then(() => ({ ok: true, json: async () => ({ card: opts.card, support_links: opts.support_links || [] }) }));
    else p = Promise.resolve({ ok: false, blob: async () => ({ type: "", size: 0 }) });
    p.catch(() => {});
    return p;
  };
  w.URL.createObjectURL = () => "blob:card";
  w.URL.revokeObjectURL = () => {};
  w.HTMLAnchorElement.prototype.click = function () { if (this.download) log.downloads++; };
  if (opts.support) w.BFSupport = { mountPublic() {} };
  try { w.eval(fe("scripts/bf-card.js")); w.eval(inlineMain(opts.html || fe("card-view.html"))); } catch (e) { log.errors.push(e.message); }
  return { dom, w, doc: w.document, log, release };
}
/* A real click event (anchor .click() is stubbed for the vCard download). */
function tapEl(view, id) { const e = new view.w.MouseEvent("click", { bubbles: true, cancelable: true }); view.doc.getElementById(id).dispatchEvent(e); return e; }
/* The legacy redirect, run alone with a fake location. */
function legacyRedirect(pathname, search) {
  const text = inlineMain(fe("card-view.html"));
  const start = text.indexOf("(function () {\n  if (!/");
  const end = start === -1 ? -1 : text.indexOf("})();", start);
  const replaced = [];
  if (start === -1 || end === -1) return { found: false, replaced };
  vm.runInNewContext(text.slice(start, end + 5), { window: { location: { pathname, search, replace(u) { replaced.push(u); } } }, URLSearchParams, encodeURIComponent });
  return { found: true, replaced };
}

/* ── the migration as run ────────────────────────────────────────────────── */
const SQL_AS_RUN = [
  "ALTER TABLE public.digital_cards",
  "  ADD COLUMN IF NOT EXISTS discoverable boolean NOT NULL DEFAULT false;",
  "",
  "CREATE TABLE public.card_view_counts (",
  "  card_id uuid NOT NULL REFERENCES public.digital_cards(id) ON DELETE CASCADE,",
  "  day date NOT NULL,",
  "  views integer NOT NULL DEFAULT 0,",
  "  qr_views integer NOT NULL DEFAULT 0,",
  "  tel_taps integer NOT NULL DEFAULT 0,",
  "  email_taps integer NOT NULL DEFAULT 0,",
  "  save_taps integer NOT NULL DEFAULT 0,",
  "  support_taps integer NOT NULL DEFAULT 0,",
  "  PRIMARY KEY (card_id, day),",
  "  CONSTRAINT card_view_counts_nonneg_check CHECK (views >= 0 AND qr_views >= 0 AND tel_taps >= 0 AND email_taps >= 0 AND save_taps >= 0 AND support_taps >= 0)",
  ");",
  "",
  "ALTER TABLE public.card_view_counts ENABLE ROW LEVEL SECURITY;",
  "REVOKE ALL ON public.card_view_counts FROM anon, authenticated;",
  "",
  "CREATE OR REPLACE FUNCTION public.bump_card_count(p_card uuid, p_kind text)",
  "RETURNS void",
  "LANGUAGE plpgsql",
  "SECURITY DEFINER",
  "SET search_path = public",
  "AS $$",
  "BEGIN",
  "  IF p_kind NOT IN ('views', 'qr_views', 'tel_taps', 'email_taps', 'save_taps', 'support_taps') THEN",
  "    RAISE EXCEPTION 'unknown count kind';",
  "  END IF;",
  "  EXECUTE format(",
  "    'INSERT INTO public.card_view_counts (card_id, day, %1$I) VALUES ($1, (now() AT TIME ZONE ''utc'')::date, 1)",
  "     ON CONFLICT (card_id, day) DO UPDATE SET %1$I = public.card_view_counts.%1$I + 1',",
  "    p_kind",
  "  ) USING p_card;",
  "END",
  "$$;",
  "",
  "REVOKE ALL ON FUNCTION public.bump_card_count(uuid, text) FROM PUBLIC, anon, authenticated;",
  "GRANT EXECUTE ON FUNCTION public.bump_card_count(uuid, text) TO service_role;",
  ""
].join("\n");
const HEADER = "-- Applied by the owner by hand in the Supabase SQL editor on Nov 6, 2026. This file is the text as run.";

(async function main() {
  /* ════ R0. the lift ════ */
  console.log("\n══ R0. the routes, lifted ══");
  check("R0. lib/cardPage.js, the generated shell and the legal, data, backup and schema libs load", !LIB_ERROR, LIB_ERROR && LIB_ERROR.stack);
  check("R0. the card routes and their helpers were lifted from server.js and run", !LIFT_ERROR && Object.values(R).every(Boolean),
    LIFT_ERROR ? LIFT_ERROR.stack : Object.keys(R).filter(k => !R[k]).join(", "));
  if (LIB_ERROR || LIFT_ERROR) { console.log("\nCHECKS FAILED: the harness could not start"); process.exit(1); }

  /* ════ U. URLs ════ */
  console.log("\n══ U. the card's URLs ══");
  const pub = CTX.cardPublicUrl;
  check("U1. cardPublicUrl: /c/<slug> when there is a slug, else /card/<token>, else null",
    pub({ slug: "jane-doe", share_token: TOK.jane }) === "https://bizforceai.net/c/jane-doe" && pub({ share_token: TOK.token }) === "https://bizforceai.net/card/" + TOK.token && pub({}) === null);
  const w0 = { btoa: x => Buffer.from(x, "binary").toString("base64") };
  vm.runInNewContext(fe("scripts/bf-card.js"), { window: w0, unescape, encodeURIComponent, Uint8Array, String, Promise, URL });
  const BF = w0.bfCard || {};
  check("U2. bf-card.js publicUrl agrees: /c/<slug>, else /card/<token>",
    BF.publicUrl && BF.publicUrl({ slug: "jane-doe", share_token: "x" }) === "https://bizforceai.net/c/jane-doe" && BF.publicUrl({ share_token: TOK.token }) === "https://bizforceai.net/card/" + TOK.token);
  const lr1 = legacyRedirect("/card-view.html", "?token=" + TOK.token + "&via=qr"), lr2 = legacyRedirect("/card-view.html", "?token=" + TOK.token);
  const lr3 = legacyRedirect("/c/jane-doe", ""), lr4 = legacyRedirect("/card-view.html", "?token=not-a-token"), lr5 = legacyRedirect("/card-view", "?token=" + TOK.token);
  check("U3. the old card-view.html?token=<token> link replaces the location with /card/<token>, keeping ?via=",
    lr1.found && J(lr1.replaced) === J(["/card/" + TOK.token + "?via=qr"]) && J(lr2.replaced) === J(["/card/" + TOK.token]) && J(lr5.replaced) === J(["/card/" + TOK.token]), J([lr1, lr2, lr5]));
  check("U4. it does nothing on /c/<slug> or /card/<token> itself, or for a token that is not 32 hex characters (that link opens as before)",
    lr3.replaced.length === 0 && lr4.replaced.length === 0 && /var token = new URLSearchParams\(window\.location\.search\)\.get\("token"\);/.test(inlineMain(fe("card-view.html"))));
  const RD = fe("_redirects") || "";
  const at = l => RD.indexOf("\n" + l + "\n"), splat = RD.search(/^\/\*\s/m);
  const proxies = ["/c/:slug https://dynamic-prosperity-production-5382.up.railway.app/c/:slug 200", "/card/:token https://dynamic-prosperity-production-5382.up.railway.app/card/:token 200",
    "/sitemap-cards.xml https://dynamic-prosperity-production-5382.up.railway.app/api/sitemap/cards.xml 200"];
  check("U5. _redirects proxies /c/:slug, /card/:token and /sitemap-cards.xml to Railway, above the catch-all; the card-view rewrite is gone",
    proxies.every(l => at(l) !== -1 && at(l) < splat) && RD.indexOf("/c/:slug /card-view.html") === -1, proxies.map(at).join(",") + " / " + splat);
  check("U6. the sitemap index lists sitemap-cards.xml", (fe("sitemap.xml") || "").indexOf("<sitemap><loc>https://bizforceai.net/sitemap-cards.xml</loc></sitemap>") !== -1);
  check("U7. card-view.html opens from /c/<slug>, /card/<token> and ?token=", /var k = \/\^\\\/card\\\/\(\[0-9a-f\]\{32\}\)\\\/\?\$\/\.exec\(window\.location\.pathname\);/.test(inlineMain(fe("card-view.html"))) &&
    /if \(k\) return API_URL \+ "\/api\/cards\/share\/" \+ k\[1\];/.test(inlineMain(fe("card-view.html"))));

  /* ════ H. the head ════ */
  console.log("\n══ H. the head, the headers, the shell ══");
  resetLimits(); CUR = makeDb(seed()); LOGS.length = 0;
  const pj = await slugPage("jane-doe");
  const H = headOf(pj.text);
  check("H1. GET /c/jane-doe: 200, the card's page", pj.status === 200 && /<div id="cardViewport">/.test(pj.text || ""), pj.status + " " + (pj.text || "").slice(0, 80));
  const name = metaOf(pj.text, "property", "og:title");
  check("H2. og:title is the name, escaped: no raw <, > or quote anywhere in the head's values", name === "Jane &quot;Q&quot; &lt;b&gt;Doe&lt;/b&gt; &amp; &#39;Co&#39;" &&
    unesc(name) === HOSTILE_NAME && H.indexOf("<b>") === -1 && H.indexOf("<i>") === -1, name);
  const desc = metaOf(pj.text, "name", "description");
  check("H3. the description is the job title and the company only, escaped", unesc(desc) === "Owner <i>&</i> at Doe & Daughters" &&
    metaOf(pj.text, "property", "og:description") === desc && metaOf(pj.text, "name", "twitter:description") === desc, desc);
  check("H4. the head never carries the email or the phone", H.indexOf(PRIVATE.email) === -1 && H.indexOf("bftest") === -1 && H.indexOf("555 0100") === -1 && H.indexOf("5550100") === -1);
  check("H5. canonical and og:url are the public URL; og:type profile; twitter card summary",
    /<link rel="canonical" href="https:\/\/bizforceai\.net\/c\/jane-doe"\/>/.test(H) && metaOf(pj.text, "property", "og:url") === "https://bizforceai.net/c/jane-doe" &&
    metaOf(pj.text, "property", "og:type") === "profile" && metaOf(pj.text, "name", "twitter:card") === "summary" && (H.match(/<title>/g) || []).length === 1);
  check("H6. a shown https photo is og:image and twitter:image", metaOf(pj.text, "property", "og:image") === PHOTO && metaOf(pj.text, "name", "twitter:image") === PHOTO);
  check("H7. robots is noindex for a card not chosen for search", metaOf(pj.text, "name", "robots") === "noindex");
  const ph = await slugPage("hidden-photo");
  check("H8. a hidden photo: og:image is BizForce's icon; the card is discoverable, so robots allows indexing",
    metaOf(ph.text, "property", "og:image") === "https://bizforceai.net/icons/icon-512.png" && metaOf(ph.text, "name", "robots") === "index, follow", metaOf(ph.text, "property", "og:image"));
  const unit = CPL.renderCardHead({ full_name: "A", show_photo: false, photo_url: PHOTO, discoverable: false }).join("\n");
  const unit2 = CPL.renderCardHead({ full_name: "A", show_photo: true, photo_url: "http://x.example/a.jpg", discoverable: true }).join("\n");
  const unit3 = CPL.renderCardHead({ full_name: "A", show_photo: true, photo_url: "https://x.example/a\".jpg", discoverable: "true" }).join("\n");
  check("H9. renderCardHead: the photo only when show_photo is true and it is https (and quote-free); noindex unless discoverable is exactly true",
    unit.indexOf(PHOTO) === -1 && unit2.indexOf("http://x.example") === -1 && unit3.indexOf("x.example") === -1 && /content="noindex"/.test(unit) &&
    /content="index, follow"/.test(unit2) && /content="noindex"/.test(unit3));
  const long = CPL.cardDescription({ job_title: "T".repeat(150), company: "C".repeat(150) });
  check("H10. the description is at most 200 characters", long.length <= 200 && CPL.cardDescription({}).length > 0 && CPL.cardDescription({ email: PRIVATE.email }).indexOf("bftest") === -1, long.length);
  const pt = await tokenPage(TOK.token);
  check("H11. GET /card/<token> serves a card without a slug, canonical /card/<token>", pt.status === 200 &&
    metaOf(pt.text, "property", "og:url") === "https://bizforceai.net/card/" + TOK.token, pt.status);
  // the shell
  const shellNow = fe("card-view.html");
  const gen = BUILD.generate(shellNow, fe("_headers"));
  check("H12. lib/cardShell.generated.js is exactly what scripts/buildCardShell.js makes from card-view.html and _headers (the --check rule)", gen === ALL[GEN]);
  const tA = shellNow.indexOf("\n  <title>"), ogA = shellNow.indexOf("<meta property=\"og:url\""), ogEnd = shellNow.indexOf("\n", ogA);
  const pre = shellNow.slice(0, tA + 1), post = shellNow.slice(ogEnd + 1), served = pj.text || "";
  const middle = served.startsWith(pre) && served.endsWith(post) ? served.slice(pre.length, served.length - post.length) : null;
  check("H13. the served page is card-view.html with only its title, meta and canonical lines replaced",
    tA !== -1 && ogA > tA && middle !== null && middle.split("\n").filter(Boolean).every(l => /^  <(title>[^<]*<\/title|meta (name|property)="[a-z:_]+" content="[^"]*"\/|link rel="canonical" href="[^"]*"\/)>$/.test(l)), middle === null ? "prefix or suffix differs" : middle.slice(0, 300));
  check("H14. the static card-view.html keeps its own canonical and is not noindex (checkLaunchBlockB 12)",
    /<link rel="canonical" href="https:\/\/bizforceai\.net\/card-view\.html"\/>/.test(shellNow) && !/noindex/.test(headOf(shellNow)));
  // the headers
  const block = /^\/\*\n((?:[ \t]+[^\n]*\n?)+)/m.exec(fe("_headers") || "");
  const want = {};
  if (block) block[1].split("\n").forEach(l => { const m = /^\s+([A-Za-z-]+):\s*(.*)$/.exec(l); if (m) want[m[1].toLowerCase()] = m[2].trim(); });
  const got = Object.assign({}, pj.headers); delete got["content-type"]; delete got["cache-control"];
  check("H15. the page carries exactly the frontend's security headers for card-view (_headers \"/*\"), the CSP included",
    Object.keys(want).length >= 7 && J(Object.keys(got).sort()) === J(Object.keys(want).sort()) && Object.keys(want).every(k => got[k] === want[k]) &&
    /frame-ancestors 'none'/.test(got["content-security-policy"] || "") && /default-src 'self'/.test(got["content-security-policy-report-only"] || ""), J(got).slice(0, 300));
  check("H16. Cache-Control is no-store, and the type is HTML", pj.headers["cache-control"] === "no-store" && /^text\/html; charset=utf-8$/.test(pj.headers["content-type"] || ""));

  /* ════ S. states ════ */
  console.log("\n══ S. the page's states ══");
  CUR = makeDb(seed()); LOGS.length = 0; resetLimits();
  const st = {
    missing: await slugPage("no-such-card"), lapsed: await slugPage("lapsed-card"), thrower: await slugPage("thrower-card"), bad: await slugPage("-x-"),
    badTok: await tokenPage("not-hex"), lapsedTok: await tokenPage(TOK.lapsed), noTok: await tokenPage("9".repeat(32))
  };
  const nf = r => r.status === 404 && /<h1>Card not found<\/h1>/.test(r.text || "") && /<meta name="robots" content="noindex"\/>/.test(r.text || "") && r.headers["cache-control"] === "no-store" &&
    r.headers["x-frame-options"] === "DENY" && (r.text || "").indexOf("Card ") !== -1 && (r.text || "").indexOf("lapsed+bftest") === -1;
  check("S1. a missing card, a malformed slug and an unknown or malformed token: 404 \"Card not found\", noindex, no-store, the security headers",
    nf(st.missing) && nf(st.bad) && nf(st.badTok) && nf(st.noTok), J([st.missing.status, st.bad.status, st.badTok.status, st.noTok.status]));
  check("S2. a lapsed owner's card, by slug or token: the same 404, nothing of the card in it", nf(st.lapsed) && nf(st.lapsedTok) && (st.lapsed.text || "").indexOf("Card lapsed") === -1);
  check("S3. an owner whose plan lookup throws: the same 404 (ownerPagePublic fails closed)", nf(st.thrower));
  const realOPP = CTX.ownerPagePublic;
  CTX.ownerPagePublic = async () => { throw new Error("lookup exploded"); };
  const thrown = await slugPage("jane-doe");
  CTX.ownerPagePublic = realOPP;
  check("S4. a lookup that throws in the route itself: 404, not served, not counted", nf(thrown) && CUR.rpcs.length === 0, thrown.status + " " + J(CUR.rpcs));
  check("S5. none of those was counted", CUR.rpcs.length === 0, J(CUR.rpcs));
  const malformedReads = CUR.reads.length;
  await slugPage("A"); await tokenPage("zz");
  check("S6. an impossible slug or token is a 404 without a read", CUR.reads.length === malformedReads, CUR.reads.slice(malformedReads).join(","));

  /* ════ C. counting ════ */
  console.log("\n══ C. counting, and nothing about the visitor ══");
  CUR = makeDb(seed()); LOGS.length = 0; resetLimits();
  await slugPage("jane-doe", { ip: "198.51.100.23" });
  check("C1. a browser's GET of /c/<slug> adds one view, through bump_card_count with only the card and the kind",
    J(CUR.rpcs) === J([{ fn: "bump_card_count", args: { p_card: CID.jane, p_kind: "views" } }]), J(CUR.rpcs));
  CUR.rpcs.length = 0;
  await slugPage("jane-doe", { query: { via: "qr" } });
  await tokenPage(TOK.token, { query: { via: "qr" } });
  check("C2. ?via=qr adds a view and a QR view, by slug and by token", J(rpcKinds()) === J(["views@" + CID.jane, "qr_views@" + CID.jane, "views@" + CID.token, "qr_views@" + CID.token]), J(rpcKinds()));
  CUR.rpcs.length = 0;
  await slugPage("jane-doe", { query: { via: "link" } });
  check("C3. any other via is a plain view", J(rpcKinds()) === J(["views@" + CID.jane]), J(rpcKinds()));
  CUR.rpcs.length = 0;
  const head = await slugPage("jane-doe", { method: "HEAD" });
  const noUa = await slugPage("jane-doe", { ua: null }), blankUa = await slugPage("jane-doe", { ua: "   " });
  check("C4. a HEAD request, no User-Agent and a blank one: the page is served, nothing is counted",
    head.status === 200 && noUa.status === 200 && blankUa.status === 200 && CUR.rpcs.length === 0, J(CUR.rpcs));
  const BOT_WORDS = ["bot", "crawl", "spider", "slurp", "preview", "facebookexternalhit", "embedly", "slack", "twitter", "discord", "whatsapp", "telegram",
    "linkedin", "skype", "headless", "curl", "wget", "python", "go-http", "java", "okhttp", "axios", "node-fetch", "libwww"];
  const counted = [];
  for (const wd of BOT_WORDS) {
    CUR.rpcs.length = 0;
    const variant = BOT_WORDS.indexOf(wd) % 2 ? wd.toUpperCase() : wd;
    await slugPage("jane-doe", { ua: "Mozilla/5.0 (compatible; " + variant + "/2.1)" });
    if (CUR.rpcs.length) counted.push(wd);
  }
  check("C5. every one of the " + BOT_WORDS.length + " bot words in a User-Agent, in either case, is not counted", counted.length === 0, counted.join(","));
  check("C6. the bot pattern is exactly the decided list, case-insensitive", CPL.BOT_RE.source === BOT_WORDS.join("|") && CPL.BOT_RE.flags === "i", CPL.BOT_RE.source);
  check("C7. isCountableRequest: a browser GET or POST yes; HEAD, PUT, no request, no headers no",
    CPL.isCountableRequest({ method: "GET", headers: { "user-agent": BROWSER_UA } }) && CPL.isCountableRequest({ method: "POST", headers: { "user-agent": BROWSER_UA } }) &&
    !CPL.isCountableRequest({ method: "HEAD", headers: { "user-agent": BROWSER_UA } }) && !CPL.isCountableRequest({ method: "PUT", headers: { "user-agent": BROWSER_UA } }) &&
    !CPL.isCountableRequest(null) && !CPL.isCountableRequest({ method: "GET" }));
  CUR.rpcs.length = 0;
  await slugPage("lapsed-card"); await tokenPage(TOK.lapsed); await slugPage("thrower-card");
  check("C8. a lapsed owner's card and a lookup that throws: never counted", CUR.rpcs.length === 0, J(CUR.rpcs));
  // NAMED (Nov 6 2026, Google Wallet, migration 174): BEFORE the six kinds of 171. AFTER seven: wallet_taps added last (checkGoogleWallet).
  check("C9. bumpCardCount refuses a kind outside the seven, with no rpc", (await CTX.bumpCardCount(CID.jane, "ip")) === false && (await CTX.bumpCardCount(CID.jane, "user_agent")) === false &&
    CUR.rpcs.length === 0 && J(CPL.COUNT_KINDS) === J(["views", "qr_views", "tel_taps", "email_taps", "save_taps", "support_taps", "wallet_taps"]));
  // NAMED (Nov 6 2026, Google Wallet, migration 174): BEFORE 171's allowlist was the rpc's. AFTER 174 replaces the function:
  // its allowlist is COUNT_KINDS exactly, and 171's, as run, is the first six.
  const MIG174 = lf(fs.readFileSync(path.join(REPO, "supabase/migrations/174_card_wallet_count.sql"), "utf8"));
  const kindsOf = sql => ((/IF p_kind NOT IN \(([^)]*)\) THEN/.exec(sql) || [])[1] || "").split(",").map(x => x.trim().replace(/'/g, ""));
  const kindsSql = kindsOf(MIG174).join(", ");
  check("C10. the rpc's own allowlist (174) is the same seven kinds, 171's was the first six, and it raises on anything else",
    J(kindsOf(MIG174)) === J(CPL.COUNT_KINDS) && J(kindsOf(ALL[MIG])) === J(CPL.COUNT_KINDS.slice(0, 6)) &&
    /RAISE EXCEPTION 'unknown count kind';/.test(ALL[MIG]) && /RAISE EXCEPTION 'unknown count kind';/.test(MIG174), kindsSql);
  CUR.rpcFails = true; LOGS.length = 0;
  const failing = await slugPage("jane-doe");
  CUR.rpcFails = false;
  check("C11. a count that fails never breaks the page, and logs only a code", failing.status === 200 && LOGS.some(l => /^\[card count\] not counted: XX000$/.test(l)) &&
    !LOGS.some(l => /rpc down/.test(l)), J(LOGS));
  // nothing about the visitor
  CUR = makeDb(seed()); LOGS.length = 0; resetLimits();
  const VISITOR = { ip: "192.0.2.199", ua: "Mozilla/5.0 VisitorMarker-77 Safari/537.36", headers: { referer: "https://referrer-marker.example/x", cookie: "session=cookie-marker" } };
  const seen = [await slugPage("jane-doe", VISITOR), await tokenPage(TOK.token, VISITOR), await tap({ ref: "jane-doe", kind: "tel" }, VISITOR)];
  const stored = J(CUR.t) + J(CUR.writes) + J(CUR.rpcs) + J(LOGS);
  check("C12. after views and a tap: no write but bump_card_count, and its arguments are only the card and the kind",
    CUR.writes.length === 0 && CUR.rpcs.length === 3 && CUR.rpcs.every(r => r.fn === "bump_card_count" && J(Object.keys(r.args).sort()) === J(["p_card", "p_kind"])), J(CUR.writes) + J(CUR.rpcs));
  check("C13. the visitor's address, User-Agent, referrer and cookie are nowhere in the database, the rpc calls or the log",
    ["192.0.2.199", "VisitorMarker-77", "referrer-marker", "cookie-marker"].every(m => stored.indexOf(m) === -1), ["192.0.2.199", "VisitorMarker-77", "referrer-marker", "cookie-marker"].filter(m => stored.indexOf(m) !== -1).join(","));
  check("C14. no Set-Cookie on the page, the 404 or the tap, and no cookie set", seen.concat([st.missing]).every(r => !("set-cookie" in r.headers) && (!r.cookies || r.cookies.length === 0)),
    J(seen.map(r => r.headers["set-cookie"])));
  const tableCols = [...ALL[MIG].matchAll(/^  ([a-z_]+) (uuid|date|integer) /gm)].map(m => m[1]);
  check("C15. card_view_counts holds a card, a day and six integers, nothing that could name a visitor",
    J(tableCols) === J(["card_id", "day", "views", "qr_views", "tel_taps", "email_taps", "save_taps", "support_taps"]) && !/\b(ip|user_agent|referrer|referer|cookie|visitor)\b/i.test(ALL[MIG].replace(/^--.*$/m, "")), J(tableCols));
  const pageCode = [fnText("serveCardPage"), fnText("bumpCardCount"), R.tap].join("\n");
  check("C16. the page and tap code never reads req.ip, the referrer or cookies, and never sets a cookie",
    !/req\.ip|referer|referrer|req\.cookies|cookie\(|Set-Cookie/i.test(pageCode) && !/user-agent/i.test(fnText("serveCardPage") || ""), "");

  /* ════ T. taps ════ */
  console.log("\n══ T. taps ══");
  CUR = makeDb(seed()); LOGS.length = 0; resetLimits();
  // NAMED (Nov 6 2026, Google Wallet, migration 174): BEFORE four kinds. AFTER wallet too, a tap on "Add to Google Wallet".
  const kinds = { tel: "tel_taps", email: "email_taps", save: "save_taps", support: "support_taps", wallet: "wallet_taps" };
  const okTaps = [];
  for (const k of Object.keys(kinds)) okTaps.push(await tap({ ref: "jane-doe", kind: k }, { ip: "198.51.100." + (okTaps.length + 1) }));
  check("T1. each of tel, email, save, support and wallet adds one to its own counter, by slug, answering 204",
    okTaps.every(r => r.status === 204) && J(rpcKinds()) === J(Object.values(kinds).map(c => c + "@" + CID.jane)), J(rpcKinds()));
  CUR.rpcs.length = 0;
  const tokTap = await tap({ ref: TOK.token, kind: "save" });
  const textTap = await tap(J({ ref: "jane-doe", kind: "email" }));
  check("T2. by share token too; a text/plain beacon body is read", tokTap.status === 204 && textTap.status === 204 && J(rpcKinds()) === J(["save_taps@" + CID.token, "email_taps@" + CID.jane]), J(rpcKinds()));
  CUR.rpcs.length = 0;
  const badKinds = ["views", "qr_views", "tel_taps", "__proto__", "constructor", "toString", "", null, 3, "TEL"];
  const bk = [];
  for (const k of badKinds) bk.push((await tap({ ref: "jane-doe", kind: k })).status);
  const badRefs = ["Jane-Doe", "a", "-ab", "../x", "x".repeat(41), "A".repeat(32), "", null, { $ne: 1 }, "jane--doe"];
  const br = [];
  for (const r of badRefs) br.push((await tap({ ref: r, kind: "tel" })).status);
  const junk = [(await tap("not json")).status, (await tap(null)).status, (await tap([1, 2])).status];
  check("T3. any other kind, a malformed ref or an unreadable body: 400, nothing counted",
    bk.every(x => x === 400) && br.every(x => x === 400) && junk.every(x => x === 400) && CUR.rpcs.length === 0, J([bk, br, junk, CUR.rpcs]));
  check("T4. tapColumn maps exactly the five kinds", J(CPL.TAP_KINDS) === J(kinds) && CPL.tapColumn("toString") === null && CPL.tapColumn("views") === null);
  const skipped = [await tap({ ref: "jane-doe", kind: "tel" }, { ua: null }), await tap({ ref: "jane-doe", kind: "tel" }, { ua: "Slackbot-LinkExpanding 1.0" }),
    await tap({ ref: "lapsed-card", kind: "tel" }), await tap({ ref: TOK.lapsed, kind: "tel" }), await tap({ ref: "thrower-card", kind: "tel" }), await tap({ ref: "no-such-card", kind: "tel" })];
  check("T5. no User-Agent, a bot, a lapsed owner, a throwing lookup or an unknown card: 204, nothing counted", skipped.every(r => r.status === 204) && CUR.rpcs.length === 0, J(skipped.map(r => r.status)) + J(CUR.rpcs));
  const tapMw = ROUTES["post /api/cards/tap"] || [];
  const lim = tapMw.find(f => f.name === "limiter");
  check("T6. the tap route is limited to 60 per 10 minutes, keyed by IP (the default key, in memory)", !!lim && lim.opts.max === 60 && lim.opts.windowMs === 600000 && !lim.opts.keyGenerator, J(lim && lim.opts));
  resetLimits(); CUR.rpcs.length = 0;
  const burst = [];
  for (let i = 0; i < 61; i++) burst.push((await tap({ ref: "jane-doe", kind: "tel" }, { ip: "203.0.113.50" })).status);
  const other = await tap({ ref: "jane-doe", kind: "tel" }, { ip: "203.0.113.51" });
  check("T7. the 61st tap from one address in the window is refused; another address is not", burst.slice(0, 60).every(x => x === 204) && burst[60] === 429 && other.status === 204 && CUR.rpcs.length === 61,
    burst.slice(58).join(",") + " " + other.status);
  const textMw = tapMw.find(f => f.name === "textParser");
  check("T8. the tap route reads a text/plain body of at most 2 KB, and needs no account", !!textMw && textMw.opts.type === "text/plain" && textMw.opts.limit === "2kb" && names("post /api/cards/tap").indexOf("requireAuth") === -1);

  /* ════ T (page). the beacons ════ */
  console.log("\n══ T. the card page's beacons ══");
  if (JSDOM) {
    const CARD = { full_name: "Jane", job_title: "Owner", company: "Doe", email: "jane@example.com", phone: "+1 555 010 2030", website: "", theme: "dark",
      public_url: "https://bizforceai.net/c/jane-doe", photo_url: null, bg_image_url: null, media_layout: {} };
    const v = cardView({ url: "https://bizforceai.net/c/jane-doe", card: CARD, support: true, support_links: [{ label: "PayPal", url: "https://paypal.me/x", disclaimer: "d" }] });
    v.release(); await settle();
    check("T9. the page renders (jsdom)", v.log.errors.length === 0 && v.doc.getElementById("pName").textContent === "Jane", v.log.errors.join("; "));
    const ev = new v.w.MouseEvent("click", { bubbles: true, cancelable: true });
    v.doc.getElementById("pPhone").dispatchEvent(ev);
    const ev2 = new v.w.MouseEvent("click", { bubbles: true, cancelable: true });
    v.doc.getElementById("pEmail").dispatchEvent(ev2);
    await v.w.saveContact();
    v.doc.getElementById("cvSupportBtn").click();
    v.doc.getElementById("cvSupportBtn").click();
    const sent = v.log.beacons.map(b => { try { return JSON.parse(b.body); } catch (e) { return b.body; } });
    check("T10. Call, Email, Save Contact and Support (on opening) each send one beacon to /api/cards/tap naming the slug and the kind, and nothing else",
      v.log.beacons.every(b => b.url === "https://dynamic-prosperity-production-5382.up.railway.app/api/cards/tap") &&
      J(sent) === J([{ ref: "jane-doe", kind: "tel" }, { ref: "jane-doe", kind: "email" }, { ref: "jane-doe", kind: "save" }, { ref: "jane-doe", kind: "support" }]), J(sent));
    check("T11. a beacon never stops the tap: the Call and Email clicks are not prevented, and Save Contact still downloads",
      ev.defaultPrevented === false && ev2.defaultPrevented === false && v.log.downloads === 1);
    v.w.close();
    const v2 = cardView({ url: "https://bizforceai.net/card/" + TOK.token, card: CARD, beacon: "throw" });
    v2.release(); await settle();
    let threw = null;
    try { tapEl(v2, "pPhone"); await v2.w.saveContact(); } catch (e) { threw = e.message; }
    check("T12. with sendBeacon throwing, the tap goes on: no error, and Save Contact still downloads", threw === null && v2.log.downloads === 1, threw);
    v2.w.close();
    const v3 = cardView({ url: "https://bizforceai.net/card/" + TOK.token, card: CARD, beacon: "none" });
    v3.release(); await settle();
    tapEl(v3, "pPhone");
    const fb = v3.log.fetches.filter(f => /\/api\/cards\/tap$/.test(f.url));
    check("T13. without sendBeacon: one fetch, keepalive, no-cors, no credentials, text/plain, naming the token",
      fb.length === 1 && fb[0].init.keepalive === true && fb[0].init.mode === "no-cors" && fb[0].init.credentials === "omit" && fb[0].init.method === "POST" &&
      J(JSON.parse(fb[0].init.body)) === J({ ref: TOK.token, kind: "tel" }), J(fb.map(f => f.init)));
    v3.w.close();
    const v4 = cardView({ url: "https://bizforceai.net/c/jane-doe", card: Object.assign({}, CARD, { phone: "", email: "" }) });
    v4.release(); await settle();
    tapEl(v4, "pPhone"); tapEl(v4, "pEmail");
    check("T14. a hidden phone or email is plain text, and tapping it sends nothing", v4.log.beacons.length === 0 && !v4.doc.getElementById("pPhone").getAttribute("href"));
    v4.w.close();

    /* ════ Q. the QR ════ */
    console.log("\n══ Q. the QR codes ══");
    const q = cardView({ url: "https://bizforceai.net/c/jane-doe", card: CARD });
    q.release(); await settle();
    check("Q1. both QR codes on the card page encode the public URL with ?via=qr; the canonical stays the plain URL",
      J(q.log.qr.map(x => x.text)) === J(["https://bizforceai.net/c/jane-doe?via=qr", "https://bizforceai.net/c/jane-doe?via=qr"]) &&
      q.doc.querySelector('link[rel="canonical"]').getAttribute("href") === "https://bizforceai.net/c/jane-doe", J(q.log.qr));
    q.w.close();
    check("Q2. bf-card.js qrUrl adds via=qr with ? or &, and nothing for no URL", BF.qrUrl("https://bizforceai.net/card/" + TOK.token) === "https://bizforceai.net/card/" + TOK.token + "?via=qr" &&
      BF.qrUrl("https://x.example/?a=1") === "https://x.example/?a=1&via=qr" && BF.qrUrl(null) === null && BF.qrUrl("") === null);
    const ed = fe("digital-cards.html");
    check("Q3. the editor's QR codes encode qrUrl(cardQrUrl()); its vCard and Share link keep the plain URL",
      /async function generateQR\(\) \{\n  var url = window\.bfCard\.qrUrl\(cardQrUrl\(\)\);/.test(ed) && /public_url: cardQrUrl\(\)/.test(ed) &&
      /var url = window\.bfCard\.publicUrl\(\{ slug: activeSlug, share_token: st \}\);/.test(ed));

    /* ════ V (page). the background ════ */
    console.log("\n══ V. the card page's background ══");
    async function bgFor(url) {
      const b = cardView({ url: "https://bizforceai.net/c/jane-doe", card: Object.assign({}, CARD, { bg_image_url: url }) });
      const layer = b.doc.getElementById("cvBgLayer"), setTo = [];
      Object.defineProperty(layer.style, "backgroundImage", { set(x) { setTo.push(x); }, get() { return setTo[setTo.length - 1] || ""; }, configurable: true });
      b.release(); await settle();
      const out = { set: setTo.slice(), shown: layer.style.display === "block" };
      b.w.close();
      return out;
    }
    const good = await bgFor(LIB_IMG);
    check("V1. a safe https background is applied as a quoted CSS value: url(\"...\")", J(good.set) === J(["url(\"" + LIB_IMG + "\")"]) && good.shown, J(good));
    const hostile = [LIB_IMG + "\"), url(\"https://evil.example/x", "https://x.example/a b.png", "http://x.example/a.png", "javascript:alert(1)",
      "https://x.example/a" + BS + "b.png", "https://x.example/(a).png", "https://x.example/<a>.png", "https://x.example/" + "a".repeat(500) + ".png"];
    const hostileOut = [];
    for (const h of hostile) hostileOut.push(await bgFor(h));
    check("V2. a stored background that is not a safe https URL is not applied at all", hostileOut.every(o => o.set.length === 0 && !o.shown), J(hostileOut));
  } else check("T9. jsdom is installed", false);

  /* ════ D. stats ════ */
  console.log("\n══ D. stats ══");
  CUR = makeDb(seed()); LOGS.length = 0; resetLimits();
  const row = (card, day, o) => Object.assign({ card_id: card, day, views: 0, qr_views: 0, tel_taps: 0, email_taps: 0, save_taps: 0, support_taps: 0 }, o);
  CUR.t.card_view_counts.push(row(CID.jane, "2026-11-06", { views: 5, qr_views: 2, tel_taps: 1 }), row(CID.jane, "2026-10-31", { views: 3, save_taps: 2 }),
    row(CID.jane, "2026-10-30", { views: 7, email_taps: 4 }), row(CID.jane, "2026-10-08", { views: 11, support_taps: 1 }), row(CID.jane, "2026-10-07", { views: 100 }),
    row(CID.other, "2026-11-06", { views: 999 }));
  const sj = await hit("get /api/digital-cards/:id/stats", { user: OWNER, params: { id: CID.jane } });
  const days = (sj.body && sj.body.days) || [];
  check("D1. the owner gets 30 UTC days, oldest first, ending today (Nov 6), every day present", sj.status === 200 && days.length === 30 && days[0].day === "2026-10-08" &&
    days[29].day === "2026-11-06" && days.every((d, i) => i === 0 || Date.parse(d.day) - Date.parse(days[i - 1].day) === 86400000), sj.status + " " + J(days.slice(0, 2)));
  check("D2. each day has exactly day and the six counts; days without a row are zeros", days.every(d => J(Object.keys(d)) === J(["day"].concat(CPL.COUNT_KINDS))) &&
    days.filter(d => d.views === 0 && d.qr_views === 0 && d.tel_taps === 0).length === 26 && days[29].views === 5 && days[29].qr_views === 2 && days[0].views === 11, J(days[29]));
  const t7 = sj.body && sj.body.totals && sj.body.totals.last_7_days, t30 = sj.body && sj.body.totals && sj.body.totals.last_30_days;
  check("D3. the 7-day totals are Oct 31 to Nov 6; the 30-day totals Oct 8 to Nov 6; Oct 7 and the other card are left out",
    !!t7 && t7.views === 8 && t7.qr_views === 2 && t7.tel_taps === 1 && t7.save_taps === 2 && t7.email_taps === 0 &&
    !!t30 && t30.views === 26 && t30.email_taps === 4 && t30.support_taps === 1, J(sj.body && sj.body.totals));
  const foreign = await hit("get /api/digital-cards/:id/stats", { user: OTHER, params: { id: CID.jane } });
  const anon = await hit("get /api/digital-cards/:id/stats", { params: { id: CID.jane } });
  const bogus = await hit("get /api/digital-cards/:id/stats", { user: OWNER, params: { id: "not-a-uuid" } });
  check("D4. another member's card is a 404, signed out is a 401, a malformed id a 404", foreign.status === 404 && J(foreign.body) === J({ error: "Card not found" }) &&
    anon.status === 401 && bogus.status === 404, J([foreign.status, anon.status, bogus.status]));
  const empty = await hit("get /api/digital-cards/:id/stats", { user: OWNER, params: { id: CID.quiet } });
  check("D5. a card with no visits: 30 days of zeros and zero totals", empty.status === 200 && empty.body.days.length === 30 && empty.body.days.every(d => d.views === 0) &&
    CPL.COUNT_KINDS.every(k => empty.body.totals.last_7_days[k] === 0 && empty.body.totals.last_30_days[k] === 0));
  const built = CPL.buildStats([{ day: "2026-11-06", views: -3, tel_taps: "2" }], new Date("2026-11-06T23:59:59.000Z"));
  check("D6. buildStats: a negative or non-number count is 0, a text number is read; today is the UTC day", built.days[29].day === "2026-11-06" && built.days[29].views === 0 && built.days[29].tel_taps === 2);

  /* ════ M. the sitemap ════ */
  console.log("\n══ M. the cards sitemap ══");
  CUR = makeDb(seed()); LOGS.length = 0; resetLimits();
  CTX.cardSitemapCache = { xml: null, at: 0 };
  const sm1 = await hit("get /api/sitemap/cards.xml");
  const locs = x => [...String(x || "").matchAll(/<loc>([^<]+)<\/loc>/g)].map(m => m[1]);
  check("M1. it lists /c/<slug> for discoverable cards with a slug whose owner is public, and nothing else",
    sm1.status === 200 && J(locs(sm1.text)) === J(["https://bizforceai.net/c/hidden-photo"]) && /^application\/xml/.test(sm1.headers["content-type"] || ""), J(locs(sm1.text)));
  check("M2. not listed: a card not chosen for search, one without a slug, a lapsed owner's, one whose owner lookup throws",
    ["jane-doe", "quiet-card", "other-card", "lapsed-card", "thrower-card", TOK.token].every(x => (sm1.text || "").indexOf(x) === -1));
  const jane = CUR.t.digital_cards.find(r => r.id === CID.jane);
  jane.discoverable = true;
  const sm2 = await hit("get /api/sitemap/cards.xml");
  check("M3. the answer is cached: a change made outside the card routes is not seen yet", J(locs(sm2.text)) === J(locs(sm1.text)));
  jane.discoverable = false;
  const put1 = await hit("put /api/digital-cards/:id", { user: OWNER, params: { id: CID.jane }, body: { discoverable: true } });
  const sm3 = await hit("get /api/sitemap/cards.xml");
  check("M4. a card write clears the cache: the card PUT discoverable appears at once", put1.status === 200 && J(locs(sm3.text)) === J(["https://bizforceai.net/c/hidden-photo", "https://bizforceai.net/c/jane-doe"]), J(locs(sm3.text)));
  await hit("delete /api/digital-cards/:id", { user: OWNER, params: { id: CID.jane } });
  const sm4 = await hit("get /api/sitemap/cards.xml");
  const post1 = await hit("post /api/digital-cards", { user: OWNER, body: { full_name: "New", slug: "new-card", discoverable: true } });
  const sm5 = await hit("get /api/sitemap/cards.xml");
  check("M5. a DELETE and a POST clear it too", J(locs(sm4.text)) === J(["https://bizforceai.net/c/hidden-photo"]) && post1.status === 201 &&
    J(locs(sm5.text)) === J(["https://bizforceai.net/c/hidden-photo", "https://bizforceai.net/c/new-card"]), J([locs(sm4.text), post1.status, locs(sm5.text)]));
  check("M6. the sitemap and both card pages are limited to 120 per 10 minutes per IP, and so are both public card API GETs",
    ["get /api/sitemap/cards.xml", "get /c/:slug", "get /card/:token"].every(k => { const l = (ROUTES[k] || []).find(f => f.name === "limiter"); return l && l.opts.max === 120 && l.opts.windowMs === 600000; }) &&
    SRC.indexOf('app.get("/api/cards/share/:token", cardPageLimiter, async function') !== -1 && SRC.indexOf('app.get("/api/cards/slug/:slug", cardPageLimiter, async function') !== -1);

  /* ════ V. validation ════ */
  console.log("\n══ V. media links and media_layout ══");
  CUR = makeDb(seed()); LOGS.length = 0; resetLimits();
  const BAD = ["http://x.example/a.png", "https://x.example/a b.png", "https://x.example/a\".png", "https://x.example/a'.png", "https://x.example/(a).png",
    "https://x.example/a" + BS + "b.png", "https://x.example/<a>.png", "javascript:alert(1)", "https://", "https://" + "a".repeat(495) + ".png", " https://x.example/a.png", 5, { url: "x" }, true];
  const vbad = [];
  for (const col of ["video_url", "bg_image_url", "still_image_url", "audio_url"]) {
    for (const b of BAD) {
      const before = J(CUR.t.digital_cards);
      const r = await hit("put /api/digital-cards/:id", { user: OWNER, params: { id: CID.jane }, body: { [col]: b } });
      if (r.status !== 400 || !/must be an https address of at most 500 characters/.test((r.body || {}).error || "") || J(CUR.t.digital_cards) !== before) vbad.push(col + " " + J(b) + " " + r.status);
    }
  }
  check("V3. PUT: every media link that is not empty or a safe https URL is a 400 with a clear message, and nothing is written", vbad.length === 0, vbad.slice(0, 5).join(" | "));
  const pbad = await hit("post /api/digital-cards", { user: OWNER, body: { full_name: "X", video_url: "https://x.example/(a).mp4" } });
  check("V4. POST refuses the same, and creates nothing", pbad.status === 400 && CUR.t.digital_cards.length === 7);
  const put2 = await hit("put /api/digital-cards/:id", { user: OWNER, params: { id: CID.jane }, body: { video_url: LIB_VID, still_image_url: "", audio_url: null, bg_image_url: "   " } });
  const j2 = CUR.t.digital_cards.find(r => r.id === CID.jane);
  check("V5. a safe https URL is kept as sent; empty, blank or null clears the slot", put2.status === 200 && j2.video_url === LIB_VID && j2.still_image_url === null && j2.audio_url === null && j2.bg_image_url === null, J([put2.status, j2.video_url, j2.still_image_url]));
  check("V6. isSafeMediaUrl is the same rule in bf-card.js and lib/cardPage.js", BAD.concat([LIB_IMG, LIB_VID, "https://x.example/a.png?x=1&y=2"]).every(u => BF.isSafeMediaUrl(u) === CPL.isSafeMediaUrl(u)) &&
    CPL.isSafeMediaUrl(LIB_IMG) && !CPL.isSafeMediaUrl("https://" + "a".repeat(495) + ".png"));
  // discoverable
  const db1 = await hit("put /api/digital-cards/:id", { user: OWNER, params: { id: CID.quiet }, body: { discoverable: "yes" } });
  const db2 = await hit("put /api/digital-cards/:id", { user: OWNER, params: { id: CID.quiet }, body: { discoverable: 1 } });
  const db3 = await hit("put /api/digital-cards/:id", { user: OWNER, params: { id: CID.quiet }, body: { discoverable: true } });
  const post2 = await hit("post /api/digital-cards", { user: OWNER, body: { full_name: "Defaults" } });
  check("V7. discoverable is a boolean: \"yes\" or 1 is a 400; true is saved; a new card is not discoverable",
    db1.status === 400 && db2.status === 400 && db3.status === 200 && CUR.t.digital_cards.find(r => r.id === CID.quiet).discoverable === true && post2.status === 201 && post2.body.card.discoverable === false &&
    !("discoverable" in CUR.writes.filter(w => w.op === "insert").pop().row), J([db1.status, db2.status, db3.status]));
  // media_layout
  const keysIn = (text, re) => [...new Set([...String(text).matchAll(re)].map(m => m[1]))];
  const getFields = (/function getFields\(\) \{[\s\S]*?media_layout: \{([\s\S]*?)\n    \}\n  \};\n\}/.exec(fe("digital-cards.html")) || [])[1] || "";
  const written = keysIn(getFields, /(?:^|[\s,{])([a-z_]+):/g);
  const read = keysIn(fe("digital-cards.html") + "\n" + fe("card-view.html") + "\n" + fe("scripts/bf-card.js"), /\b(?:ml2?|cvMl|aml)\.([a-z_]+)\b/g)
    .concat(keysIn(fe("card-view.html") + fe("digital-cards.html"), /media_layout\.([a-z_]+)/g));
  const allow = Object.keys(CPL.MEDIA_LAYOUT_ALLOWLIST);
  check("V8. the allowlist is exactly the keys the editor writes, and covers every key the editor and the card page read (" + allow.length + " keys)",
    written.length === 35 && J(written.slice().sort()) === J(allow.slice().sort()) && read.every(k => allow.indexOf(k) !== -1), J({ written: written.length, missingRead: read.filter(k => allow.indexOf(k) === -1), extra: allow.filter(k => written.indexOf(k) === -1) }));
  const dirty = { bg_pos_x: 50, bg_pos_y: "25", bg_zoom: 250, bg_fit: "zoom", card_font: "lobster", text_color: "", accent_color: "#22d3ee", border_style: "gold", border_weight: "16px",
    tagline: "T".repeat(260), still_bg_color: "red", still_overlay: 40, still_img_mode: "fit", trim_end: 12.5, still_text_visible: "true", free_position_mode: true,
    text_positions: { name: { x: 10, y: 20 }, title: { x: 200, y: 1 }, evil: { x: 1, y: 1 } }, text_sizes: { name: 16, tagline: 99 }, corner_style: "cut",
    vid_transition: "matrix", orientation: "sideways", card_layout: "classic", divider_style: "fleur", text_effect: "<script>", card_texture: "glass",
    onload: "alert(1)", __proto__x: 1, border_weight_px: "9999px", style: "background:url(javascript:alert(1))" };
  const clean = CPL.sanitizeMediaLayout(dirty).value;
  check("V9. unknown keys are dropped; out-of-range numbers, bad colours, unknown enums and non-booleans are dropped; text over 200 is cut; a number in text is read",
    J(Object.keys(clean).sort()) === J(["accent_color", "bg_fit", "bg_pos_x", "bg_pos_y", "border_style", "border_weight", "card_font", "card_layout", "card_texture", "corner_style",
      "divider_style", "free_position_mode", "still_img_mode", "still_overlay", "tagline", "text_color", "text_positions", "text_sizes", "trim_end", "vid_transition"]) &&
    clean.bg_pos_y === 25 && clean.tagline.length === 200 && J(clean.text_positions) === J({ name: { x: 10, y: 20 } }) && J(clean.text_sizes) === J({ name: 16 }) && clean.text_color === "", J(clean));
  const big = { tagline: "x".repeat(150) }; for (let i = 0; i < 60; i++) big["pad_" + i] = "y".repeat(70);
  const over = CPL.sanitizeMediaLayout(big);
  const putBig = await hit("put /api/digital-cards/:id", { user: OWNER, params: { id: CID.jane }, body: { media_layout: big } });
  check("V10. a media_layout over 4 KB serialized is refused (400), and nothing is written", Buffer.byteLength(J(big)) > 4096 && !!over.error && putBig.status === 400 && /4096 bytes/.test((putBig.body || {}).error || ""));
  check("V11. a media_layout that is not an object is {}", J(CPL.sanitizeMediaLayout(null).value) === "{}" && J(CPL.sanitizeMediaLayout([1]).value) === "{}" && J(CPL.sanitizeMediaLayout("x").value) === "{}");
  const putOk = await hit("put /api/digital-cards/:id", { user: OWNER, params: { id: CID.jane }, body: { media_layout: dirty } });
  check("V12. PUT stores the cleaned layout, and the editor's own full layout round-trips unchanged", putOk.status === 200 && J(CUR.t.digital_cards.find(r => r.id === CID.jane).media_layout) === J(clean) &&
    (() => { const full = { bg_pos_x: 50, bg_pos_y: 50, bg_zoom: 100, bg_fit: "cover", vid_pos_x: 50, vid_pos_y: 50, vid_scale: 100, card_font: "default", text_color: "", accent_color: "",
      card_layout: "classic", bg_overlay: 0, border_style: "glow", border_weight: "16px", audio_track_name: "Audio Track", orientation: "horizontal", vid_transition: "fade", tagline: "Hi",
      still_bg_color: "#112233", still_overlay: 30, still_img_pos_x: 40, still_img_pos_y: 60, still_img_zoom: 150, still_img_mode: "center", trim_start: 1, trim_end: 20,
      still_text_visible: true, card_bg_color: "#070b18", text_positions: { company: { x: 5, y: 10 }, name: { x: 5, y: 30 }, title: { x: 5, y: 50 }, tagline: { x: 5, y: 70 } },
      text_sizes: { company: 10.4, name: 16, title: 10.4, tagline: 8.3 }, free_position_mode: true, divider_style: "diamond", text_effect: "glow", card_texture: "carbon", corner_style: "pillow" };
      return J(CPL.sanitizeMediaLayout(full).value) === J(full); })());
  check("V13. stored rows are not rewritten: no route reads media_layout to change it, and GET /api/digital-cards serves rows as stored",
    !/sanitizeMediaLayout/.test(fnText("publicCardFrom") || "") && !/\.update\([^)]*media_layout/.test(SRC.replace(/updates\.media_layout|out\.media_layout/g, "")));

  /* ════ L. the library ════ */
  console.log("\n══ L. the library pickers, and cleanup ══");
  const lib = fe("digital-cards.html");
  const stillRow = (/<button class="vid-upload-btn" onclick="document\.getElementById\('fi-still-img'\)\.click\(\)">Choose Image<\/button>\n\s*<button type="button" class="vid-upload-btn" id="stillImgLibraryBtn">Choose from my library<\/button>/.exec(lib));
  const vidRow = (/<button class="vid-upload-btn" onclick="document\.getElementById\('fi-pitch-vid'\)\.click\(\)">Choose MP4<\/button>\n\s*<button type="button" class="vid-upload-btn" id="pitchVidLibraryBtn">Choose from my library<\/button>/.exec(lib));
  check("L1. \"Choose from my library\" sits beside the still image's and the video's own upload buttons, which stay", !!stillRow && !!vidRow);
  check("L2. there is no library button for audio (the library holds no audio)", (lib.match(/>Choose from my library<\/button>/g) || []).length === 3 && !/audio[A-Za-z]*LibraryBtn/.test(lib));
  const pickerBlock = (() => { const a = lib.indexOf('<script src="/scripts/media-picker.js"></script>\n<script>'); if (a < 0) return ""; const b = lib.indexOf("</script>", a + 60); return lib.slice(a + 58, b); })();
  if (pickerBlock) {
    const listeners = {}, els = {};
    const el = id => els[id] || (els[id] = { id, textContent: "", style: {}, src: "", controls: true, setAttribute() {}, load() { this.loaded = true; }, addEventListener(t, f) { listeners[id] = f; } });
    const pickRes = { image: { url: LIB_IMG, type: "image", name: "Shop front" }, video: { url: LIB_VID, type: "video", name: "Tour" } };
    const asked = [];
    const ctx = { document: { getElementById: el }, BFMediaPicker: { open(o) { asked.push(o.kind); return Promise.resolve(pickRes[o.kind]); } }, URL: { revokeObjectURL() {} },
      setBgImage() {}, updatePosterDisplay() {}, _posterVisible() {}, _syncOverlay() {}, syncVidSliders() {}, applyVideoStyles() {}, videoMode: false,
      _stillBlobUrl: "blob:old", _videoBlobUrl: "blob:oldv", stillImageUrl: null, videoUrl: null, stillImgPosX: 10, stillImgPosY: 10, stillImgZoom: 200, stillImgMode: "fit", vidTrimStart: 3, vidTrimEnd: 9 };
    let ran = null;
    try { vm.runInNewContext(pickerBlock, ctx); listeners.stillImgLibraryBtn(); listeners.pitchVidLibraryBtn(); await settle(); } catch (e) { ran = e.message; }
    check("L3. choosing a library image makes it the still image (kind image), and a library video the pitch video (kind video), as an upload does",
      ran === null && J(asked) === J(["image", "video"]) && ctx.stillImageUrl === LIB_IMG && ctx.videoUrl === LIB_VID && els.stillImgName.textContent === "Shop front" &&
      els.pitchVidName.textContent === "Tour" && els.cardVideoPitch.src === LIB_VID && ctx._stillBlobUrl === null && ctx._videoBlobUrl === null && ctx.vidTrimEnd === null, ran || J([ctx.stillImageUrl, ctx.videoUrl]));
  } else check("L3. the media-picker script block is on the page", false);
  CUR = makeDb(seed()); LOGS.length = 0;
  await CTX.removeDisplacedCardMedia({ bg_image_url: LIB_IMG, still_image_url: CARD_IMG, video_url: LIB_VID, audio_url: null }, null, OWNER, "check");
  const removedKeys = CUR.removed.reduce((a, r) => a.concat(r.keys), []);
  check("L4. cleanup removes the card's own upload but never a Media Library file", J(removedKeys) === J(["card-media/" + OWNER + "/1730000000000_still.jpg"]), J(removedKeys));
  CUR.removed.length = 0;
  await hit("put /api/digital-cards/:id", { user: OWNER, params: { id: CID.jane }, body: { bg_image_url: CARD_IMG.replace("still", "bg"), still_image_url: LIB_IMG } });
  await hit("delete /api/digital-cards/:id", { user: OWNER, params: { id: CID.jane } });
  const after = CUR.removed.reduce((a, r) => a.concat(r.keys), []);
  check("L5. replacing a library background and deleting a card that holds a library still image remove no library file", after.every(k => k.indexOf("media/") !== 0) &&
    after.indexOf("card-media/" + OWNER + "/1730000000000_still.jpg") !== -1, J(after));

  /* ════ E. the editor's panel ════ */
  console.log("\n══ E. the editor's panel ══");
  const LINE = "These are visits, not people: the same person opening your card twice counts twice, and BizForce keeps nothing about who they are.";
  const section = (/<section id="cardStats"[\s\S]*?<\/section>/.exec(lib) || [""])[0];
  check("E1. under the card: \"Visits to your card\", the switch \"Let search engines find this card\", and the line word for word",
    section.indexOf(">Visits to your card</h2>") !== -1 && /<input type="checkbox" id="fDiscoverable"> Let search engines find this card<\/label>/.test(section) &&
    section.indexOf(">" + LINE + "</p>") !== -1 && lib.indexOf('<div class="save-status info" id="saveStatus"></div>\n      <section id="cardStats"') !== -1);
  check("E2. the switch is sent with the save and filled from the card", /body\.discoverable = document\.getElementById\("fDiscoverable"\)\.checked;/.test(lib) &&
    /document\.getElementById\("fDiscoverable"\)\.checked = data\.cards\[0\]\.discoverable === true;/.test(lib) && /document\.getElementById\("fDiscoverable"\)\.checked = saved\.discoverable === true;/.test(lib));
  const fnOf = (text, nm) => { const a = text.indexOf("function " + nm + "("); if (a < 0) return ""; return text.slice(text.lastIndexOf("\n", a) + 1, s.braceMatch(text, text.indexOf("{", a))); };
  const statsCode = fnOf(lib, "loadCardStats") + "\n" + fnOf(lib, "cardCountLine");
  check("E3. the panel's code writes with textContent only", statsCode.length > 200 && !/innerHTML|insertAdjacentHTML|outerHTML|document\.write/.test(statsCode) && /li\.textContent = /.test(statsCode));
  if (JSDOM) {
    const d = new JSDOM("<!DOCTYPE html><body>" + section + "</body>", { runScripts: "outside-only" });
    const evil = "<img src=x id=pwn>";
    const days30 = CPL.buildStats([{ day: "2026-11-06", views: 4, qr_views: 1 }], new Date(NOW_ISO));
    days30.days[0].day = evil;
    d.window.fetch = async (u, init) => { d.window.__asked = [String(u), init && init.headers && init.headers.Authorization]; return { ok: true, json: async () => days30 }; };
    d.window.eval("var API_URL = 'https://api.example'; var token = 'tok'; var activeCardId = '" + CID.jane + "';\n" + statsCode);
    await d.window.loadCardStats(); await settle();
    const items = d.window.document.querySelectorAll("#cardStatsDays li");
    check("E4. in jsdom: 30 days listed newest first, the totals in words, a hostile day shown as text, the request is the owner's own",
      items.length === 30 && /^2026-11-06: 4 opened \(1 by QR code\)/.test(items[0].textContent) && items[29].textContent.indexOf(evil) === 0 && !d.window.document.getElementById("pwn") &&
      /^Last 7 days: 4 opened/.test(d.window.document.getElementById("cardStatsTotals").textContent) &&
      J(d.window.__asked) === J(["https://api.example/api/digital-cards/" + CID.jane + "/stats", "Bearer tok"]), items.length + " " + (items[0] && items[0].textContent));
    d.window.fetch = async () => ({ ok: false, status: 500 });
    await d.window.loadCardStats();
    check("E5. a failed read says so, in words", /could not be loaded/.test(d.window.document.getElementById("cardStatsTotals").textContent));
    d.window.close();
  }
  const cvNew = [fnOf(inlineMain(fe("card-view.html")), "sendTap"), fnOf(inlineMain(fe("card-view.html")), "cardRef"), inlineMain(fe("card-view.html")).split("var API_URL")[0]].join("\n");
  check("E6. the card page's new code (the redirect, cardRef, sendTap) has no innerHTML", cvNew.length > 300 && !/innerHTML|insertAdjacentHTML|document\.write/.test(cvNew));

  /* ════ G. legal and the guide ════ */
  console.log("\n══ G. the Privacy Policy, the terms version, the guide ══");
  const SENT = "When someone opens your digital card or taps its buttons, BizForce adds to a daily count for that card that only you can see; it records nothing about the visitor, no address, device or cookie, and the counts are deleted with the card. If you let search engines find a card, they may list it.";
  check("G1. CARD_VISITS_PRIVACY_SENTENCE is word for word", LP.CARD_VISITS_PRIVACY_SENTENCE === SENT);
  const builtPages = LP.buildLegalPages();
  const escH = t => t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  const nextTo = h => { const a = h.indexOf(escH(LP.MEDIA_PRIVACY_SENTENCE)), b = h.indexOf(escH(SENT)); return a !== -1 && b > a && b - a - escH(LP.MEDIA_PRIVACY_SENTENCE).length < 20; };
  check("G2. the Privacy Policy carries it directly after the Media Library sentence, as built and on disk", nextTo(builtPages["privacy.html"]) && nextTo(fe("privacy.html") || ""));
  check("G3. TERMS_VERSION and TERMS_UPDATED are this change's date, Nov 6 2026", LEGAL.TERMS_VERSION === "2026-11-06" && LEGAL.TERMS_UPDATED === "Last updated November 6, 2026", LEGAL.TERMS_VERSION);
  const guide = fe("scripts/termaximus-guide.js") || "";
  // NAMED BEFORE → AFTER (Nov 6 2026, card upgrades C2): BEFORE the editor tip named the search switch and the card-view
  // tip said the owner never learns who you are. AFTER both still tell of the counts, and say truthfully that the owner
  // sees a visitor's name and contact only when they send them with "Leave your details" (checkCardLeads holds the leads).
  check("G4. the guide tells both pages about the counts, truthfully, and keeps five tips each",
    guide.indexOf("Under the card, \\\"Visits to your card\\\" counts 30 days of opens and taps; \\\"Leads\\\" lists what visitors leave once \\\"Let visitors leave their details\\\" is on.") !== -1 &&
    guide.indexOf("Nothing here can be edited; the owner sees daily counts of opens and taps, and your name and contact only if you send them with \\\"Leave your details\\\".") !== -1 &&
    ["digital-cards.html", "card-view.html"].every(p => { const m = new RegExp("\"" + p.replace(".", BS + ".") + "\": \\[([\\s\\S]*?)\\n    \\]").exec(guide); return m && (m[1].match(/^      "/gm) || []).length === 5; }));

  /* ════ R. the migration and the registries ════ */
  console.log("\n══ R. migration 171 and the registries ══");
  const migFiles = fs.readdirSync(path.join(REPO, "supabase/migrations")).filter(f => /^\d+_/.test(f));
  // NAMED BEFORE → AFTER (Nov 6 2026, card upgrades C2): BEFORE 171 was the highest. AFTER 172_card_leads.sql is, and
  // checkCardLeads R1 holds that; 171_card_counts.sql is still the only migration numbered 171.
  // NAMED BEFORE → AFTER (Nov 6 2026, Outlook sign-in, migration 173): BEFORE 172 was the highest. AFTER 173_mailbox_microsoft.sql
  // is, held by checkMailboxOutlook R1; above 171 only 172_card_leads.sql and 173_mailbox_microsoft.sql are allowed, by name.
  // NAMED BEFORE → AFTER (Nov 6 2026, Google Wallet, migration 174): BEFORE 173 was the highest. AFTER 174_card_wallet_count.sql
  // is, held by checkGoogleWallet R1; it is allowed above 171 by name too.
  // NAMED (Nov 6 2026, store changes, migration 175): BEFORE 174 was the highest. AFTER 175_store_changes.sql is, held by
  // checkStoreChanges R1; it is allowed above 171 by name too.
  check("R1. 171_card_counts.sql is the only migration numbered 171; the highest is 175 (checkStoreChanges R1), 170 the last before it",
    migFiles.filter(f => /^171_/.test(f)).length === 1 && migFiles.indexOf("171_card_counts.sql") !== -1 &&
    migFiles.every(f => f === "172_card_leads.sql" || f === "173_mailbox_microsoft.sql" || f === "174_card_wallet_count.sql" || f === "175_store_changes.sql" || Number(f.split("_")[0]) <= 171) && migFiles.some(f => /^170_/.test(f)));
  check("R2. its header says the owner applied it by hand on Nov 6, 2026, and the rest is the SQL as run, exactly", ALL[MIG] === HEADER + "\n\n" + SQL_AS_RUN, ALL[MIG].length + " vs " + (HEADER.length + 2 + SQL_AS_RUN.length));
  check("R3. RLS on, anon and authenticated revoked, the function SECURITY DEFINER with a fixed search_path, executable by service_role only",
    /ALTER TABLE public\.card_view_counts ENABLE ROW LEVEL SECURITY;/.test(ALL[MIG]) && /REVOKE ALL ON FUNCTION public\.bump_card_count\(uuid, text\) FROM PUBLIC, anon, authenticated;/.test(ALL[MIG]) &&
    /GRANT EXECUTE ON FUNCTION public\.bump_card_count\(uuid, text\) TO service_role;/.test(ALL[MIG]) && /SECURITY DEFINER\nSET search_path = public/.test(ALL[MIG]));
  check("R4. SCHEMA_TABLES names card_view_counts as 171's", ALL["lib/schemaCheck.js"].indexOf('["card_view_counts", "171_card_counts.sql"]') !== -1);
  check("R5. the backup leaves it out, saying why", BK.EXCLUDED_TABLES.card_view_counts === "daily visit counts for members' cards; a metric, not anyone's work or money" &&
    (BK.BACKUP_TABLES || []).indexOf("card_view_counts") === -1);
  const yd = (YD.DATA || []).filter(e => e.table === "card_view_counts");
  check("R6. Your data: one entry in profile, reached through card_id from the member's cards, deleted (and in DELETE_ORDER once, before digital_cards)",
    yd.length === 1 && yd[0].group === "profile" && /^Visit counts for your digital cards/.test(yd[0].what) && J(yd[0].via) === J({ column: "card_id", parent: "digital_cards" }) &&
    yd[0].onDelete === "delete" && J(yd[0].unique) === J(["card_id", "day"]) && YD.DELETE_ORDER.filter(t => t === "card_view_counts").length === 1 &&
    YD.DELETE_ORDER.indexOf("card_view_counts") < YD.DELETE_ORDER.indexOf("digital_cards"), J(yd));
  check("R7. the database deletes the counts with the card too", /REFERENCES public\.digital_cards\(id\) ON DELETE CASCADE/.test(ALL[MIG]));

  /* ════ Z. zero network ════ */
  console.log("\n══ Z. zero network ══");
  check("Z1. no socket was opened and no name was looked up", NETWORK.length === 0, NETWORK.join(","));

  console.log("\n" + (failures === 0 ? "ALL " + passes + " CHECKS PASSED" : "CHECKS FAILED: " + failures + " of " + (passes + failures)));
  process.exit(failures === 0 ? 0 : 1);
})().catch(e => { console.log("    FAIL  the check itself crashed: " + (e && e.stack)); console.log("\nCHECKS FAILED: crashed"); process.exit(1); });
