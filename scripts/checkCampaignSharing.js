"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkCampaignSharing — a crowdfunding campaign's public page,
   bizforceai.net/campaign/<share_id>, off by default, with a link its owner
   can replace; the owner's controls on campaigns.html; no owner id in the
   list (build list item 3, migration 166, Nov 4 2026).

   server.js's campaign routes are lifted and run in a vm against an in-memory
   database that enforces migration 166's CHECKs and unique index.
   lib/campaignShare.js, lib/supportLinks.js and lib/legalPages.js run for
   real, compiled from their (possibly mutated) text. The pages run in jsdom.
   Nothing leaves the machine: every socket and DNS lookup is a tripwire.

   WHAT THIS PROVES
     S. The share id: 16 base32 characters from 10 bytes of crypto.randomBytes,
        its pattern equal to 166's CHECK, a known vector, no Math.random.
     M. Migration 166: the header, the SQL as run, the policy, the highest.
     P. The page's four states (on, ended, off, none), a plan lapse, the
        limiter and the cache header.
     E. Escaping: a hostile title and description are inert in the body and
        in every meta tag.
     A. The allowlist: no owner id, campaign id, donor, donation, donor
        count, email or phone, on the page or from by-share.
     N. noindex unless shown and discoverable; the sitemap's rules and cache.
     L. Sharing on and off, a new link killing the old, owner-only and
        subscription-only share routes, a new campaign never shared.
     T. The status moves: every from and to.
     I. The list: is_own, no owner id; by-share: auth, shared and active only.
     F. campaigns.html and bf-campaign.js in jsdom: labels, textContent only,
        confirmations, the share panel, ?campaign=, the sign-in return.
     G. Privacy and Terms, word for word; the guide tip; _redirects; sitemap.
     Z. Zero network.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check. A mutation
   whose search text does not match exactly once is an ERROR.

   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm"), Module = require("module"), net = require("net"), dns = require("dns");
const s = require("./_shared");

const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkCampaignSharing: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkCampaignSharing: no network"); };

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";

const SV = "server.js", CS = "lib/campaignShare.js", LP_FILE = "lib/legalPages.js", MIG = "supabase/migrations/166_campaign_sharing.sql";
const CPAGE = "fe:campaigns.html", CJS = "fe:scripts/bf-campaign.js", APP = "fe:app.html";

const MUTATIONS = {
  // a new campaign is shared the moment it starts
  "share-on-by-default": [[SV, "        raised_bfc: 0, status: \"active\",\n", "        raised_bfc: 0, status: \"active\", share_on: true, share_id: campaignShare.newShareId(),\n"]],
  // the share id comes from Math.random
  "math-random-id": [[CS, "  var bytes = (randomBytes || crypto.randomBytes)(10);",
    "  var bytes = (randomBytes || function (n) { var a = []; for (var k = 0; k < n; k++) a.push(Math.floor(Math.random() * 256)); return a; })(10);"]],
  // a campaign with sharing off is served
  "page-when-off": [[CS, "  if (row.share_on !== true) return \"off\";\n", ""]],
  // a paused or cancelled campaign is served
  "page-when-paused": [[CS, "  if (row.status === \"completed\") return \"ended\";\n  return \"off\";", "  if (row.status === \"completed\") return \"ended\";\n  return \"on\";"]],
  // the page is served after the owner's plan lapses
  "page-when-plan-lapsed": [[SV, "    if (!shared || !(await ownerPagePublic(shared.owner_id))) return res.status(404).send(campaignShare.renderCampaignPage(\"none\"));",
    "    if (!shared) return res.status(404).send(campaignShare.renderCampaignPage(\"none\"));"]],
  // "Make a new link" keeps the old id
  "old-link-still-works": [[SV, "      .update({ share_id: campaignShare.newShareId(), share_changed_at: nowIso() })", "      .update({ share_changed_at: nowIso() })"]],
  // the list answers with each campaign's owner id
  "owner-id-in-list": [[SV, "    is_own: !!viewerId && row.owner_id === viewerId", "    owner_id: row.owner_id, is_own: !!viewerId && row.owner_id === viewerId"]],
  // the page carries the owner's account id
  "owner-id-on-page": [
    [CS, "    title: String(row.title || \"\"),\n", "    owner_id: row.owner_id,\n    title: String(row.title || \"\"),\n"],
    [CS, "'<main id=\"campaignPage\" data-state=\"' + state + '\"", "'<main id=\"campaignPage\" data-owner=\"' + esc(c.owner_id) + '\" data-state=\"' + state + '\""]],
  // the page names who donated
  "donor-shown": [[SV, "    const view = campaignShare.publicCampaignFrom(shared, campaignShare.ownerFrom(prof.data, support));\n",
    "    const gifts = await supabase.from(\"campaign_donations\").select(\"donor_id\").eq(\"owner_id\", shared.owner_id);\n" +
    "    const view = Object.assign(campaignShare.publicCampaignFrom(shared, campaignShare.ownerFrom(prof.data, support)), { description: String(shared.description || \"\") + \" Backed by \" + (gifts.data || []).length + \" donors: \" + (gifts.data || []).map(function (d) { return d.donor_id; }).join(\", \") });\n"]],
  // the og:title is written unescaped
  "og-unescaped": [[CS, "    '  <meta property=\"og:title\" content=\"' + esc(title) + '\"/>',", "    '  <meta property=\"og:title\" content=\"' + title + '\"/>',"]],
  // every campaign page is indexable
  "noindex-ignored": [[CS, "(index ? \"index, follow\" : \"noindex\")", "\"index, follow\""]],
  // the sitemap lists campaigns their owners did not let search engines find
  "sitemap-includes-undiscoverable": [
    [SV, ".eq(\"share_on\", true).eq(\"discoverable\", true).eq(\"status\", \"active\").limit(5000);", ".eq(\"share_on\", true).eq(\"status\", \"active\").limit(5000);"],
    [SV, "return r.share_on === true && r.discoverable === true && r.status === \"active\"", "return r.share_on === true && r.status === \"active\""]],
  // a cancelled campaign can be made active again
  "cancelled-reopened": [[SV, "  cancelled: []\n};", "  cancelled: [\"active\"]\n};"]],
  // a member can switch sharing on another member's campaign
  "non-owner-can-share": [
    [SV, "      .select(\"id, share_id\")\n      .eq(\"id\", req.params.id)\n      .eq(\"owner_id\", req.user.id)\n", "      .select(\"id, share_id\")\n      .eq(\"id\", req.params.id)\n"],
    [SV, "      .update(changes)\n      .eq(\"id\", req.params.id)\n      .eq(\"owner_id\", req.user.id)\n", "      .update(changes)\n      .eq(\"id\", req.params.id)\n"]],
  // sharing without a subscription
  "unsubscribed-can-share": [[SV, "app.put(\"/api/crowdfunding/campaigns/:id/share\", requireAuth, requireActiveSubscription, async", "app.put(\"/api/crowdfunding/campaigns/:id/share\", requireAuth, async"]],
  // by-share answers anyone
  "by-share-unauthed": [[SV, "app.get(\"/api/crowdfunding/campaigns/by-share/:shareId\", requireAuth, async", "app.get(\"/api/crowdfunding/campaigns/by-share/:shareId\", async"]],
  // by-share answers for a campaign that is not shared
  "by-share-unshared": [[SV, "if (!shared || shared.share_on !== true || shared.status !== \"active\") return res.status(404).json(notAvailable);",
    "if (!shared || shared.status !== \"active\") return res.status(404).json(notAvailable);"]],
  // the Privacy Policy loses the campaign sentence
  "privacy-sentence-removed": [[LP_FILE, "      CAMPAIGN_PRIVACY_SENTENCE,\n", ""]],
  // a campaign's title is parsed as HTML on campaigns.html
  "innerHTML-on-page": [[CPAGE, "  card.appendChild(el(\"h3\", { \"class\": \"campaign-title\" }, c.title));\n",
    "  var heading = el(\"h3\", { \"class\": \"campaign-title\" }); heading.innerHTML = c.title; card.appendChild(heading);\n"]],
  // ── earned by the code ──
  // an ended campaign still offers the donate button
  "ended-donate-shown": [[CS, "    state === \"on\" ? [\n      '  <section aria-labelledby=\"cmpDonateTitle\">',", "    state === \"on\" || state === \"ended\" ? [\n      '  <section aria-labelledby=\"cmpDonateTitle\">',"]],
  // the share route forgets to clear the sitemap's cache
  "share-cache-not-cleared": [[SV, "    campaignSitemapCache = { xml: null, at: 0 };\n    return res.json({\n      share_on:", "    return res.json({\n      share_on:"]],
  // the status route forgets to clear the sitemap's cache
  "status-cache-not-cleared": [[SV, "    campaignSitemapCache = { xml: null, at: 0 };\n    return res.json({ campaign: data });", "    return res.json({ campaign: data });"]],
  // the page is not rate-limited
  "page-not-rate-limited": [[SV, "app.get(\"/campaign/:shareId\", campaignPageLimiter, async function", "app.get(\"/campaign/:shareId\", async function"]],
  // the QR code encodes the address bar, not the page's link
  "qr-wrong-url": [[CJS, "root.QRCode.toCanvas(canvas, url,", "root.QRCode.toCanvas(canvas, window.location.href,"]],
  // signing in no longer comes back to the donate flow
  "signin-no-return": [[CJS, "    try { localStorage.setItem(\"bf_return_to\", window.location.origin + \"/campaigns.html?campaign=\" + shareId); } catch (e) {}\n", ""]],
  // app.html refuses to return to campaigns.html
  "return-refused": [[APP, "|c\\/[a-z0-9-]{1,80}|campaigns\\.html)$/i", "|c\\/[a-z0-9-]{1,80})$/i"]],
  // Cancel goes through without asking
  "cancel-unconfirmed": [[CPAGE, "  if (question && !window.confirm(question)) return;\n", ""]],
  // a new link is made without the warning
  "new-link-unconfirmed": [[CPAGE, "  if (!window.confirm(\"Your old link will stop working.\")) return;\n", ""]],
  // a malformed share id reaches the database
  "malformed-id-read": [[SV, "    if (!campaignShare.isShareId(shareId)) return res.status(404).send(campaignShare.renderCampaignPage(\"none\"));\n", ""]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

/* ── the files ──────────────────────────────────────────────────────────── */
const lf = t => t.replace(/\r\n/g, "\n");
const ALL = {};
[SV, CS, "lib/supportLinks.js", "lib/scrollbars.js", LP_FILE, "lib/legal.js", MIG].forEach(f => { ALL[f] = lf(fs.readFileSync(path.join(REPO, f), "utf8")); });
["campaigns.html", "scripts/bf-campaign.js", "scripts/bf-support.js", "scripts/bf-session.js", "app.html", "_redirects", "sitemap.xml",
  "terms.html", "privacy.html", "scripts/termaximus-guide.js"].forEach(f => {
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
      const target = path.relative(REPO, path.join(path.dirname(file), req)).replace(/\\/g, "/").replace(/(\.js)?$/, ".js");
      if (ALL[target] !== undefined) return loadLib(target);
      return realRequire(path.join(REPO, target));
    }
    return realRequire(req);
  };
  m._compile(ALL[rel], file);
  return m.exports;
}
const C = loadLib(CS), LINKS = loadLib("lib/supportLinks.js"), LP = loadLib(LP_FILE), LEGAL = loadLib("lib/legal.js");

/* ── an in-memory database, with migration 166's rules ───────────────────── */
let idSeq = 1;
const nextId = () => "00000000-0000-4000-8000-" + String(100000000000 + (idSeq++));
function project(rows, cols) {
  if (!cols || cols === "*") return rows.map(r => JSON.parse(JSON.stringify(r)));
  const names = cols.split(",").map(c => c.trim());
  return rows.map(r => { const o = {}; names.forEach(n => { o[n] = r[n] === undefined ? null : JSON.parse(JSON.stringify(r[n])); }); return o; });
}
const SHARE_SQL = /share_id IS NULL OR share_id ~ '([^']+)'/.exec(ALL[MIG]);
function rule166(t) {
  const rows = t.crowdfunding_campaigns || [];
  const re = new RegExp(SHARE_SQL ? SHARE_SQL[1] : "^$");
  for (const r of rows) {
    if (!(r.share_id == null || re.test(r.share_id))) return { code: "23514", message: "violates check constraint crowdfunding_campaigns_share_id_check" };
    if (!(r.share_on === false || r.share_id != null)) return { code: "23514", message: "violates check constraint crowdfunding_campaigns_share_needs_id_check" };
    if (["active", "paused", "completed", "cancelled"].indexOf(r.status) === -1) return { code: "23514", message: "violates check constraint crowdfunding_campaigns_status_check" };
  }
  const ids = rows.map(r => r.share_id).filter(x => x != null);
  if (new Set(ids).size !== ids.length) return { code: "23505", message: "duplicate key value violates unique constraint crowdfunding_campaigns_share_id_key" };
  return null;
}
const DEFAULTS = {
  crowdfunding_campaigns: () => ({ description: "", raised_bfc: 0, media: [], category: null, status: "active", share_id: null, share_on: false, discoverable: false, share_changed_at: null })
};
function makeDb(seed) {
  const t = JSON.parse(JSON.stringify(seed));
  const db = { t, reads: [], writes: [] };
  db.from = function (table) {
    const st = { op: "select", cols: null, ret: null, filters: [], orders: [], limit: null, row: null };
    function run() {
      db.reads.push(table + ":" + st.op);
      if (!t[table]) return Promise.resolve({ data: null, error: { code: "42P01", message: "relation " + table + " does not exist" } });
      const before = JSON.stringify(t[table]);
      if (st.op === "insert") {
        const rows = (Array.isArray(st.row) ? st.row : [st.row]).map(r => Object.assign((DEFAULTS[table] || (() => ({})))(), { id: nextId(), created_at: new Date().toISOString() }, JSON.parse(JSON.stringify(r))));
        t[table].push(...rows);
        const bad = rule166(t);
        if (bad) { t[table] = JSON.parse(before); return Promise.resolve({ data: null, error: bad }); }
        db.writes.push(table + ":insert");
        return Promise.resolve({ data: st.ret ? project(rows, st.ret) : null, error: null });
      }
      let rows = t[table].filter(r => st.filters.every(f => f(r)));
      if (st.op === "update") {
        rows.forEach(r => Object.assign(r, JSON.parse(JSON.stringify(st.row))));
        const bad = rule166(t);
        if (bad) { t[table] = JSON.parse(before); return Promise.resolve({ data: null, error: bad }); }
        if (rows.length) db.writes.push(table + ":update");
        return Promise.resolve({ data: project(rows, st.ret || "*"), error: null });
      }
      rows = rows.slice().sort((x, y) => { for (const [c, asc] of st.orders) { if (x[c] < y[c]) return asc ? -1 : 1; if (x[c] > y[c]) return asc ? 1 : -1; } return 0; });
      if (st.limit != null) rows = rows.slice(0, st.limit);
      return Promise.resolve({ data: project(rows, st.cols), error: null });
    }
    const q = {
      select(c) { if (st.op === "select") st.cols = c || "*"; else st.ret = c || "*"; return q; },
      insert(r) { st.op = "insert"; st.row = r; return q; },
      update(p) { st.op = "update"; st.row = p; return q; },
      eq(c, v) { st.filters.push(r => r[c] === v); return q; },
      neq(c, v) { st.filters.push(r => r[c] !== v); return q; },
      in(c, vs) { st.filters.push(r => vs.indexOf(r[c]) !== -1); return q; },
      order(c, o) { st.orders.push([c, !o || o.ascending !== false]); return q; },
      limit(n) { st.limit = n; return q; },
      maybeSingle() { return run().then(r => r.error ? r : r.data.length > 1 ? { data: null, error: { code: "PGRST116", message: r.data.length + " rows" } } : { data: r.data[0] || null, error: null }); },
      single() { return run().then(r => r.error ? r : r.data.length !== 1 ? { data: null, error: { code: "PGRST116", message: r.data.length + " rows" } } : { data: r.data[0], error: null }); },
      then(ok, bad) { return run().then(ok, bad); }
    };
    return q;
  };
  return db;
}

/* ── the fixture ─────────────────────────────────────────────────────────── */
const OWEN = "0e0e0e0e-0000-4000-8000-000000000001", DANA = "da0da0da-0000-4000-8000-000000000002", LOU = "10101010-0000-4000-8000-000000000003";
const INACTIVE = new Set([LOU]);
const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
const PRIVATE = { email: "owen+bftest@example.com", phone: "+1 555 0142" };
const HOSTILE_TITLE = "Kiln <script>alert(1)</script> \"fund\" & 'more'";
const HOSTILE_DESC = "A new kiln <img src=x onerror=alert(2)> for the studio. \"Quotes\" & <b>bold</b>";
const OWEN_PHOTO = "https://cdn.example.com/owen.jpg";
const IMG = "https://cdn.example.com/kiln.jpg";
const SID = { on: "aaaaaaaaaaaaaaaa", off: "bbbbbbbbbbbbbbbb", paused: "cccccccccccccccc", cancelled: "dddddddddddddddd", ended: "eeeeeeeeeeeeeeee",
  listed: "ffffffffffffffff", lapsed: "gggggggggggggggg", unknown: "hhhhhhhhhhhhhhhh" };
const CID = { on: "c0000000-0000-4000-8000-000000000001", off: "c0000000-0000-4000-8000-000000000002", paused: "c0000000-0000-4000-8000-000000000003",
  cancelled: "c0000000-0000-4000-8000-000000000004", ended: "c0000000-0000-4000-8000-000000000005", listed: "c0000000-0000-4000-8000-000000000006",
  lapsed: "c0000000-0000-4000-8000-000000000007", private: "c0000000-0000-4000-8000-000000000008" };
function camp(key, owner, status, shareOn, discoverable, extra) {
  return Object.assign({ id: CID[key], owner_id: owner, title: "Campaign " + key, description: "About " + key, goal_bfc: 1000, raised_bfc: 100, media: [], category: "Studio",
    status: status, share_id: SID[key] || null, share_on: shareOn, discoverable: discoverable, share_changed_at: null,
    created_at: "2026-11-0" + (1 + Object.keys(CID).indexOf(key) % 3) + "T10:00:00.000Z", updated_at: "2026-11-01T10:00:00.000Z" }, extra || {});
}
function seed() {
  return {
    crowdfunding_campaigns: [
      camp("on", OWEN, "active", true, false, { title: HOSTILE_TITLE, description: HOSTILE_DESC, goal_bfc: 1000, raised_bfc: 250,
        media: [{ url: IMG, type: "image/jpeg", name: "kiln.jpg" }, { url: "http://insecure.example.com/x.jpg", type: "image/jpeg", name: "x" }, { url: "javascript:alert(3)", type: "image/png", name: "y" }] }),
      camp("off", OWEN, "active", false, true),
      camp("paused", OWEN, "paused", true, true),
      camp("cancelled", OWEN, "cancelled", true, true),
      camp("ended", OWEN, "completed", true, true, { raised_bfc: 1200 }),
      camp("listed", OWEN, "active", true, true),
      camp("lapsed", LOU, "active", true, true),
      camp("private", DANA, "active", false, false, { share_id: null })
    ],
    campaign_donations: [{ id: "d-1", campaign_id: CID.on, donor_id: DANA, owner_id: OWEN, amount_bfc: 250, created_at: "2026-11-02T10:00:00.000Z" }],
    bf_profiles: [
      { user_id: OWEN, username: "owen", display_name: "Owen Oak", avatar_url: OWEN_PHOTO, email: PRIVATE.email, phone: PRIVATE.phone },
      { user_id: DANA, username: "dana", display_name: "Dana Donor", avatar_url: null },
      { user_id: LOU, username: "lou", display_name: "Lou Lapsed", avatar_url: null }
    ],
    member_support: [{ user_id: OWEN, links: [{ provider: "paypal", handle: "OwenOak" }], headline: null, page_on: true, discoverable: false }],
    gate_decisions: []
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
  list: routeText('app.get("/api/crowdfunding/campaigns",'),
  mine: routeText('app.get("/api/crowdfunding/my-campaigns",'),
  create: routeText('app.post("/api/crowdfunding/campaigns",'),
  edit: routeText('app.put("/api/crowdfunding/campaigns/:id",'),
  byShare: routeText('app.get("/api/crowdfunding/campaigns/by-share/:shareId",'),
  share: routeText('app.put("/api/crowdfunding/campaigns/:id/share",'),
  newLink: routeText('app.post("/api/crowdfunding/campaigns/:id/share/new-link",'),
  page: routeText('app.get("/campaign/:shareId",'),
  sitemap: routeText('app.get("/api/sitemap/campaigns.xml",')
};
const STUB = new Set(["supabase", "console", "process", "require", "module", "app", "requireAuth", "getUserPlan", "rateLimit",
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
let CUR = makeDb(seed());
const ROUTES = {};
const CTX = {
  supabase: { from: t => CUR.from(t), rpc: async () => ({ data: null, error: { code: "PGRST202", message: "no rpc in this check" } }) },
  console: { log() {}, warn() {}, error() {} },
  process: { env: {} },
  require: function (p) {
    if (p.indexOf("./") === 0) { const rel = p.slice(2).replace(/(\.js)?$/, ".js"); if (ALL[rel] !== undefined) return loadLib(rel); return realRequire(p); }
    return realRequire(p);
  },
  requireAuth: function requireAuth(req, res, next) { if (!req.user) return res.status(401).json({ error: "Authentication required" }); next(); },
  getUserPlan: async function (id) { return INACTIVE.has(id) ? { active: false, plan: null, subscription: null, inactive_reason: "no_subscription", access_reason: null } : { active: true, plan: "all_access", subscription: { status: "active" }, access_reason: "subscription" }; },
  rateLimit: function (opts) { const f = function limiter(req, res, next) { next(); }; f.opts = opts; return f; },
  app: {}
};
["get", "post", "put", "delete", "use"].forEach(v => { CTX.app[v] = function (p) { ROUTES[v + " " + p] = Array.prototype.slice.call(arguments, 1); }; });
let LIFT_ERROR = null;
try {
  vm.createContext(CTX);
  const root = Object.values(R).concat([fnText("requireActiveSubscription")]).join("\n\n");
  vm.runInContext(closure(root), CTX);
} catch (e) { LIFT_ERROR = e; }

function mkRes() {
  return {
    statusCode: 200, body: undefined, text: undefined, headers: {}, ended: false,
    status(c) { this.statusCode = c; return this; },
    json(b) { this.body = JSON.parse(JSON.stringify(b)); this.ended = true; return this; },
    send(t) { this.text = String(t); this.ended = true; return this; },
    set(k, v) { this.headers[k.toLowerCase()] = v; return this; },
    type(v) { this.headers["content-type"] = v; return this; }
  };
}
async function hit(key, user, body, params) {
  const fns = ROUTES[key];
  if (!fns) return { status: 0, error: "no route " + key };
  const req = { method: key.split(" ")[0].toUpperCase(), route: { path: key.split(" ")[1] }, user: user ? { id: user, role: "user" } : undefined, body: body || {}, params: params || {}, query: {}, headers: {} };
  const res = mkRes();
  let err = null;
  for (let i = 0; i < fns.length; i++) {
    let advanced = false;
    await fns[i](req, res, e => { if (e) err = e; else advanced = true; });
    if (err || !advanced || res.ended) break;
  }
  return { status: res.statusCode, body: res.body, text: res.text, headers: res.headers, err: err && (err.message || String(err)) };
}
const names = key => (ROUTES[key] || []).map(f => f.name);
const page = sid => hit("get /campaign/:shareId", null, {}, { shareId: sid });
const row = id => CUR.t.crowdfunding_campaigns.find(r => r.id === id);
const stateOf = html => (/<main id="campaignPage"[^>]*data-state="([a-z]+)"/.exec(html || "") || [])[1] || null;
const robotsOf = html => (/<meta name="robots" content="([^"]*)"/.exec(html || "") || [])[1] || null;

/* ── jsdom ───────────────────────────────────────────────────────────────── */
let JSDOM = null;
try { JSDOM = realRequire("jsdom").JSDOM; } catch (e) { JSDOM = null; }
const tick = () => new Promise(r => setTimeout(r, 0));
async function settle() { for (let i = 0; i < 12; i++) await tick(); }
const stripScripts = html => html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/g, "");

(async function main() {
  /* ════ S. the share id ════ */
  console.log("\n══ S. the share id ══");
  check("S0. the routes and their helpers were lifted from server.js and run", !LIFT_ERROR && Object.values(R).every(Boolean),
    LIFT_ERROR ? LIFT_ERROR.stack : Object.keys(R).filter(k => !R[k]).join(", "));
  check("S1. SHARE_ID_PATTERN equals migration 166's CHECK, character for character", !!SHARE_SQL && C.SHARE_ID_PATTERN === SHARE_SQL[1] &&
    C.SHARE_ID_PATTERN === "^[a-z2-7]{16}$" && C.SHARE_ID_RE.source === new RegExp(SHARE_SQL[1]).source, SHARE_SQL && SHARE_SQL[1]);
  const many = Array.from({ length: 300 }, () => C.newShareId());
  check("S2. 300 new ids each match the pattern, and no two are the same", many.every(x => C.SHARE_ID_RE.test(x)) && new Set(many).size === 300, many.slice(0, 3).join(","));
  let asked = [];
  const zeros = C.newShareId(n => { asked.push(n); return Buffer.alloc(n, 0); }), ones = C.newShareId(n => Buffer.alloc(n, 255));
  const vector = Buffer.from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
  let big = 0n; for (const b of vector) big = (big << 8n) | BigInt(b);
  let expect = ""; for (let i = 0; i < 16; i++) expect += "abcdefghijklmnopqrstuvwxyz234567"[Number((big >> BigInt(75 - 5 * i)) & 31n)];
  check("S3. 10 bytes become 16 base32 characters, 5 bits each (zeros, ones, and 00..09 against an independent BigInt encoding)",
    J(asked) === "[10]" && zeros === "aaaaaaaaaaaaaaaa" && ones === "7777777777777777" && C.newShareId(() => vector) === expect, zeros + " " + ones + " " + expect);
  const noComments = x => x.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  const csText = noComments(ALL[CS]), shareRoutes = [R.share, R.newLink, R.create].join("\n");
  check("S4. the id comes from crypto.randomBytes; no Math.random in lib/campaignShare.js, the share routes or the create route",
    /\(randomBytes \|\| crypto\.randomBytes\)\(10\)/.test(csText) && /const crypto = require\("crypto"\);/.test(csText) &&
    csText.indexOf("Math.random") === -1 && shareRoutes.indexOf("Math.random") === -1);
  check("S5. isShareId refuses the wrong length, capitals, 0, 1, 8, 9 and non-strings",
    C.isShareId("aaaaaaaaaaaaaaaa") && !C.isShareId("aaaaaaaaaaaaaaa") && !C.isShareId("aaaaaaaaaaaaaaaaa") && !C.isShareId("AAAAAAAAAAAAAAAA") &&
    !C.isShareId("aaaaaaaaaaaaaaa0") && !C.isShareId("aaaaaaaaaaaaaaa1") && !C.isShareId("aaaaaaaaaaaaaaa8") && !C.isShareId("aaaaaaaaaaaaaaa9") && !C.isShareId(null) && !C.isShareId(12));

  /* ════ M. migration 166 ════ */
  console.log("\n══ M. migration 166 ══");
  const SQL_AS_RUN = "ALTER TABLE public.crowdfunding_campaigns\n  ADD COLUMN IF NOT EXISTS share_id text,\n  ADD COLUMN IF NOT EXISTS share_on boolean NOT NULL DEFAULT false,\n" +
    "  ADD COLUMN IF NOT EXISTS discoverable boolean NOT NULL DEFAULT false,\n  ADD COLUMN IF NOT EXISTS share_changed_at timestamptz;\n\n" +
    "ALTER TABLE public.crowdfunding_campaigns\n  ADD CONSTRAINT crowdfunding_campaigns_share_id_check CHECK (share_id IS NULL OR share_id ~ '^[a-z2-7]{16}$'),\n" +
    "  ADD CONSTRAINT crowdfunding_campaigns_share_needs_id_check CHECK (share_on = false OR share_id IS NOT NULL);\n\n" +
    "CREATE UNIQUE INDEX IF NOT EXISTS crowdfunding_campaigns_share_id_key\n  ON public.crowdfunding_campaigns (share_id) WHERE share_id IS NOT NULL;\n\n" +
    "ALTER POLICY campaigns_select ON public.crowdfunding_campaigns\n  TO authenticated\n  USING (owner_id = auth.uid());\n";
  check("M1. 166_campaign_sharing.sql says the owner applied it by hand on Nov 4, 2026, and ends with the SQL as run, exactly",
    ALL[MIG].indexOf("Applied by the owner by hand in the Supabase SQL editor on Nov 4, 2026. This file is the text as run.") !== -1 && ALL[MIG].endsWith(SQL_AS_RUN) &&
    !/CREATE TABLE|DROP|UPDATE |DELETE /i.test(ALL[MIG].replace(/^--.*$/gm, "")));
  const migFiles = fs.readdirSync(path.join(REPO, "supabase/migrations")).filter(f => /^\d+_/.test(f));
  // NAMED (Nov 4 2026, the Media Library, migration 167): BEFORE "166 is the highest". AFTER 166 is still the only one
  // numbered 166, and every migration but 167_member_media.sql is at most 166; "the highest" is checkMediaLibrary M2's.
  // NAMED (Nov 5 2026, images in social posts, migration 168): BEFORE every migration but 167 at most 166. AFTER every migration but
  // 167 and 168_social_post_images.sql; "the highest" is checkSocialImages M2's.
  // NAMED (Nov 5 2026, mailbox connection, migration 169): BEFORE every migration but 167 and 168 at most 166. AFTER
  // 169_member_email_connections.sql too; "the highest" is checkMailboxConnect M2's.
  // NAMED (Nov 5 2026, mailbox replies, migration 170): BEFORE every migration but 167, 168 and 169 at most 166. AFTER
  // 170_member_email_replies.sql too; "the highest" is checkMailboxReply M2's.
  // NAMED (Nov 6 2026, card upgrades C1, migration 171): BEFORE every migration but 167, 168, 169 and 170 at most 166. AFTER
  // 171_card_counts.sql too; "the highest" is checkCardUpgrades R1's.
  // NAMED (Nov 6 2026, card upgrades C2, migration 172): BEFORE 171_card_counts.sql was the last allowed above 166. AFTER
  // 172_card_leads.sql too; "the highest" is checkCardLeads R1's.
  check("M2. 166_campaign_sharing.sql is the only migration numbered 166, and every other migration but 167_member_media.sql, 168_social_post_images.sql, 169_member_email_connections.sql, 170_member_email_replies.sql, 171_card_counts.sql and 172_card_leads.sql is at most 166",
    migFiles.filter(f => /^166_/.test(f)).length === 1 && migFiles.indexOf("166_campaign_sharing.sql") !== -1 &&
    migFiles.every(f => f === "167_member_media.sql" || f === "168_social_post_images.sql" || f === "169_member_email_connections.sql" || f === "170_member_email_replies.sql" || f === "171_card_counts.sql" || f === "172_card_leads.sql" || Number(f.split("_")[0]) <= 166) && migFiles.some(f => /^165_/.test(f)));
  check("M3. sharing and discovery default to off, and a signed-in member reads only their own rows directly",
    /share_on boolean NOT NULL DEFAULT false/.test(ALL[MIG]) && /discoverable boolean NOT NULL DEFAULT false/.test(ALL[MIG]) &&
    /ALTER POLICY campaigns_select ON public\.crowdfunding_campaigns\n  TO authenticated\n  USING \(owner_id = auth\.uid\(\)\);/.test(ALL[MIG]));

  /* ════ P. the page's states ════ */
  console.log("\n══ P. the page: on, ended, off, none ══");
  const on = await page(SID.on);
  check("P1. a shared, active campaign: 200, state on, cached 60 s", on.status === 200 && stateOf(on.text) === "on" &&
    on.headers["cache-control"] === "public, max-age=60" && /text\/html/.test(on.headers["content-type"] || "") && on.headers["x-content-type-options"] === "nosniff", on.status + " " + stateOf(on.text));
  check("P2. it shows the goal, the amount raised and a progress bar, the owner's name and photo, and a support link while that page is on",
    on.text.indexOf("250 of 1,000 BFC raised (25%)") !== -1 && /<div class="cmp-fill" style="width:25%"><\/div>/.test(on.text) && on.text.indexOf("By Owen Oak") !== -1 &&
    on.text.indexOf('<img class="cmp-photo" src="' + OWEN_PHOTO + '"') !== -1 && on.text.indexOf('<a id="cmpSupport" href="https://bizforceai.net/support/owen">Support Owen Oak directly</a>') !== -1);
  check("P3. the donate button goes to campaigns.html?campaign=<share id>; signed out it reads \"Sign in to donate\"",
    on.text.indexOf('<a class="cmp-btn" id="cmpDonate" href="/campaigns.html?campaign=' + SID.on + '" hidden>Donate BizCash</a>') !== -1 &&
    on.text.indexOf('<a class="cmp-btn" id="cmpSignIn" href="/app.html">Sign in to donate</a>') !== -1);
  check("P4. Share, Copy link and a QR code, with the card's QR library and the page scripts",
    /id="cmpShareBtn">Share<\/button>/.test(on.text) && /id="cmpCopyBtn">Copy link<\/button>/.test(on.text) && /<canvas id="cmpQr"/.test(on.text) &&
    on.text.indexOf(C.QR_SCRIPT) !== -1 && on.text.indexOf('<script src="/scripts/bf-support.js"></script>\n<script src="/scripts/bf-campaign.js"></script>') !== -1);
  check("P5. only https media is shown: the http and javascript: items are dropped", on.text.indexOf('src="' + IMG + '"') !== -1 &&
    on.text.indexOf("insecure.example.com") === -1 && on.text.indexOf("javascript:") === -1);
  const ended = await page(SID.ended);
  check("P6. a completed, shared campaign: 200, state ended, the final totals, \"This campaign has ended\", no donate button",
    ended.status === 200 && stateOf(ended.text) === "ended" && ended.text.indexOf("This campaign has ended") !== -1 && ended.text.indexOf("1,200 of 1,000 BFC raised (100%)") !== -1 &&
    ended.text.indexOf("cmpDonate") === -1 && ended.text.indexOf("Sign in to donate") === -1, stateOf(ended.text));
  for (const k of ["off", "paused", "cancelled"]) {
    const r = await page(SID[k]);
    check("P7. " + (k === "off" ? "sharing off" : k) + ": 200, \"This campaign isn't being shared right now\", and nothing of the campaign",
      r.status === 200 && stateOf(r.text) === "off" && r.text.indexOf("This campaign isn&#39;t being shared right now") !== -1 && r.text.indexOf("Campaign " + k) === -1 &&
      r.text.indexOf("About " + k) === -1 && r.text.indexOf("Owen") === -1, r.status + " " + stateOf(r.text));
  }
  const lapsed = await page(SID.lapsed);
  check("P8. an owner whose plan is not active: 404, \"No campaign found\"", lapsed.status === 404 && stateOf(lapsed.text) === "none" && lapsed.text.indexOf("Campaign lapsed") === -1);
  INACTIVE.add(OWEN);
  const lapsedOn = await page(SID.on);
  INACTIVE.delete(OWEN);
  check("P9. a plan lapse takes a shared, active campaign down at once: 404", lapsedOn.status === 404 && stateOf(lapsedOn.text) === "none" && lapsedOn.text.indexOf("Kiln") === -1);
  const unknown = await page(SID.unknown);
  const readsBefore = CUR.reads.length;
  const malformed = await Promise.all(["AAAAAAAAAAAAAAAA", "aaaa", "aaaaaaaaaaaaaaa1", "../../etc"].map(page));
  check("P10. an unknown id is 404; a malformed one is 404 without a single read", unknown.status === 404 && stateOf(unknown.text) === "none" &&
    malformed.every(r => r.status === 404 && stateOf(r.text) === "none") && CUR.reads.length === readsBefore, CUR.reads.slice(readsBefore).join(","));
  const pageMw = ROUTES["get /campaign/:shareId"] || [];
  check("P11. the page has its own limiter, 120 requests per 10 minutes per IP, like the support page's", pageMw.length === 2 && pageMw[0].opts &&
    pageMw[0].opts.max === 120 && pageMw[0].opts.windowMs === 600000 && /const campaignPageLimiter = rateLimit\(/.test(SRC), J(pageMw[0] && pageMw[0].opts));

  /* ════ E. escaping ════ */
  console.log("\n══ E. a hostile title and description are inert ══");
  check("E1. the raw markup is nowhere in the page", on.text.indexOf("<script>alert(1)") === -1 && on.text.indexOf("<img src=x") === -1 && on.text.indexOf("<b>bold") === -1 &&
    on.text.indexOf("Kiln &lt;script&gt;alert(1)&lt;/script&gt; &quot;fund&quot; &amp; &#39;more&#39;") !== -1);
  if (JSDOM) {
    const d = new JSDOM(on.text, { url: "https://bizforceai.net/campaign/" + SID.on });
    const doc = d.window.document;
    const meta = n => { const m = doc.querySelector('meta[property="' + n + '"]') || doc.querySelector('meta[name="' + n + '"]'); return m ? m.getAttribute("content") : null; };
    const scripts = Array.from(doc.querySelectorAll("script"));
    const allowed = ["https://cdn.jsdelivr.net/npm/qrcode@1.4.4/build/qrcode.min.js", "/scripts/bf-bfc-notice.js", "/scripts/bf-support.js", "/scripts/bf-campaign.js", "/scripts/bf-legal-footer.js"];
    check("E2. parsed, every script is one of the page's own five, none inline; no element carries an on* handler",
      scripts.every(x => allowed.indexOf(x.getAttribute("src")) !== -1 && !x.textContent.trim()) && scripts.length === 5 &&
      Array.from(doc.querySelectorAll("*")).every(n => Array.from(n.attributes).every(a => !/^on/i.test(a.name))), scripts.map(x => x.getAttribute("src") || "inline").join(","));
    const wantTitle = HOSTILE_TITLE + " — a campaign on BizForce";
    check("E3. <title>, og:title and twitter:title read back as the exact text", doc.title === wantTitle && meta("og:title") === wantTitle && meta("twitter:title") === wantTitle, doc.title);
    check("E4. the description meta tags read back as the text, unparsed", [meta("description"), meta("og:description"), meta("twitter:description")].every(v => v === HOSTILE_DESC), meta("og:description"));
    check("E5. the heading and description are the exact text", doc.getElementById("cmpTitle").textContent === HOSTILE_TITLE &&
      doc.querySelector(".cmp-desc").textContent === HOSTILE_DESC && doc.querySelectorAll("main img").length === 2, doc.querySelectorAll("main img").length);
    check("E6. og:image is the first https image, og:type website, og:url and canonical the share link", meta("og:image") === IMG && meta("og:type") === "website" &&
      meta("og:url") === "https://bizforceai.net/campaign/" + SID.on && doc.querySelector('link[rel="canonical"]').getAttribute("href") === "https://bizforceai.net/campaign/" + SID.on);
  } else check("E2. jsdom is installed", false);
  const longDesc = "x".repeat(500);
  const longView = C.publicCampaignFrom(Object.assign({}, row(CID.on), { description: longDesc, media: [] }), { displayName: "Owen Oak", photo: OWEN_PHOTO });
  const longPage = C.renderCampaignPage("on", { campaign: longView, discoverable: false });
  const descMeta = (/<meta name="description" content="([^"]*)"/.exec(longPage) || [])[1] || "";
  check("E7. the description tag holds at most 200 characters; with no image, og:image is the owner's photo, else the default icon",
    descMeta.length === 200 && /\.\.\.$/.test(descMeta) && longPage.indexOf('<meta property="og:image" content="' + OWEN_PHOTO + '"/>') !== -1 &&
    C.renderCampaignPage("on", { campaign: Object.assign({}, longView, { owner_photo: null }), discoverable: false }).indexOf('<meta property="og:image" content="' + C.DEFAULT_IMAGE + '"/>') !== -1, descMeta.length);

  /* ════ A. the allowlist ════ */
  console.log("\n══ A. what a stranger is served ══");
  const view = C.publicCampaignFrom(row(CID.on), C.ownerFrom({ username: "owen", display_name: "Owen Oak", avatar_url: OWEN_PHOTO, email: PRIVATE.email, phone: PRIVATE.phone }, { page_on: true, links: [] }));
  check("A1. publicCampaignFrom holds exactly the decided fields", J(Object.keys(view).sort()) === J(["category", "description", "goal_bfc", "media", "owner_display_name", "owner_photo", "raised_bfc", "support_url", "title", "url"]), J(Object.keys(view)));
  const pages = [on.text, ended.text];
  check("A2. no account or campaign id, no donor, donation or donor count, no email or phone, on any page", pages.every(t => !UUID.test(t) && t.indexOf(DANA) === -1 &&
    t.indexOf("Dana") === -1 && !/donor/i.test(t) && t.indexOf(PRIVATE.email) === -1 && t.indexOf(PRIVATE.phone) === -1 && t.indexOf(CID.on) === -1 && t.indexOf(OWEN) === -1),
    pages.map(t => (t.match(UUID) || [""])[0]).join(","));
  check("A3. serving the pages never read campaign_donations", CUR.reads.every(r => r.indexOf("campaign_donations") !== 0), CUR.reads.filter(r => /donation/.test(r)).join(","));
  check("A4. the owner's support link is shown only while their support page is on", C.ownerFrom({ username: "owen", display_name: "O" }, { page_on: false, links: [{ provider: "paypal", handle: "x" }] }).supportUrl === null &&
    C.ownerFrom({ username: "Owen", display_name: null }, { page_on: true, links: [] }).supportUrl === "https://bizforceai.net/support/owen" &&
    C.ownerFrom({ username: "Owen", display_name: null }, null).displayName === "Owen");

  /* ════ N. noindex and the sitemap ════ */
  console.log("\n══ N. noindex and the sitemap ══");
  check("N1. noindex for an undiscoverable shared page, index for a discoverable one, noindex for off and none",
    robotsOf(on.text) === "noindex" && robotsOf(ended.text) === "index, follow" && robotsOf((await page(SID.off)).text) === "noindex" && robotsOf(unknown.text) === "noindex" &&
    robotsOf(C.renderCampaignPage("off")) === "noindex" && robotsOf(C.renderCampaignPage("on", { campaign: view, discoverable: true })) === "index, follow" &&
    robotsOf(C.renderCampaignPage("on", { campaign: view, discoverable: false })) === "noindex");
  CTX.campaignSitemapCache = { xml: null, at: 0 };
  const sm1 = await hit("get /api/sitemap/campaigns.xml", null, {}, {});
  const locs = x => (String(x || "").match(/<loc>([^<]+)<\/loc>/g) || []).map(l => l.slice(5, -6));
  check("N2. the sitemap lists only the shared, discoverable, active campaign whose owner's plan is active",
    sm1.status === 200 && J(locs(sm1.text)) === J(["https://bizforceai.net/campaign/" + SID.listed]) && /application\/xml/.test(sm1.headers["content-type"] || ""), sm1.text);
  const r0 = CUR.reads.length;
  await hit("get /api/sitemap/campaigns.xml", null, {}, {});
  check("N3. a second request inside ten minutes is served from the cache, with no read", CUR.reads.length === r0, CUR.reads.slice(r0).join(","));
  const smMw = ROUTES["get /api/sitemap/campaigns.xml"] || [];
  check("N4. the sitemap shares the page's limiter", smMw.length === 2 && smMw[0] === pageMw[0]);

  /* ════ L. sharing ════ */
  console.log("\n══ L. sharing on and off, a new link, owners only ══");
  const made = await hit("post /api/crowdfunding/campaigns", OWEN, { title: "Glaze lab", description: "Glazes", goal_bfc: 500, category: "Studio", media: [] });
  const fresh = made.body && made.body.campaign ? row(made.body.campaign.id) : null;
  check("L1. a new campaign is not shared: share_on false, no share id, not discoverable", made.status === 201 && !!fresh && fresh.share_on === false && fresh.share_id == null && fresh.discoverable === false, J(fresh));
  CTX.campaignSitemapCache = { xml: "<cached/>", at: Date.now() };
  const turnOn = await hit("put /api/crowdfunding/campaigns/:id/share", OWEN, { share_on: true }, { id: fresh.id });
  const sid1 = fresh.share_id;
  check("L2. turning sharing on makes a share id matching 166, records share_changed_at, and answers { share_on, discoverable, url }",
    turnOn.status === 200 && C.isShareId(sid1) && !!fresh.share_changed_at && J(Object.keys(turnOn.body).sort()) === J(["discoverable", "share_on", "url"]) &&
    turnOn.body.share_on === true && turnOn.body.discoverable === false && turnOn.body.url === "https://bizforceai.net/campaign/" + sid1, J(turnOn.body));
  check("L3. the share route clears the sitemap's cache", CTX.campaignSitemapCache.xml === null, J(CTX.campaignSitemapCache));
  check("L4. the page is on at the new link", stateOf((await page(sid1)).text) === "on");
  await hit("put /api/crowdfunding/campaigns/:id/share", OWEN, { share_on: false }, { id: fresh.id });
  const offAgain = await page(sid1);
  await hit("put /api/crowdfunding/campaigns/:id/share", OWEN, { share_on: true }, { id: fresh.id });
  check("L5. off, the link answers \"off\" and keeps its id; on again, the same link works", stateOf(offAgain.text) === "off" && fresh.share_id === sid1 && stateOf((await page(sid1)).text) === "on");
  CTX.campaignSitemapCache = { xml: "<cached/>", at: Date.now() };
  const nl = await hit("post /api/crowdfunding/campaigns/:id/share/new-link", OWEN, {}, { id: fresh.id });
  const sid2 = fresh.share_id;
  const oldPage = await page(sid1), newPage = await page(sid2);
  check("L6. \"Make a new link\" replaces the id: the old link is \"No campaign found\" at once, the new one is on", nl.status === 200 && sid2 !== sid1 && C.isShareId(sid2) &&
    nl.body.url === "https://bizforceai.net/campaign/" + sid2 && J(Object.keys(nl.body)) === '["url"]' && oldPage.status === 404 && stateOf(oldPage.text) === "none" && stateOf(newPage.text) === "on", J(nl.body));
  check("L7. the new-link route clears the sitemap's cache", CTX.campaignSitemapCache.xml === null);
  const before = J(row(CID.on));
  const danaShare = await hit("put /api/crowdfunding/campaigns/:id/share", DANA, { share_on: false, discoverable: true }, { id: CID.on });
  const danaLink = await hit("post /api/crowdfunding/campaigns/:id/share/new-link", DANA, {}, { id: CID.on });
  check("L8. another member cannot switch sharing or make a new link: 404, the campaign unchanged", danaShare.status === 404 && danaLink.status === 404 && J(row(CID.on)) === before,
    danaShare.status + " " + danaLink.status);
  const louBefore = J(row(CID.lapsed));
  const louShare = await hit("put /api/crowdfunding/campaigns/:id/share", LOU, { share_on: false }, { id: CID.lapsed });
  const louLink = await hit("post /api/crowdfunding/campaigns/:id/share/new-link", LOU, {}, { id: CID.lapsed });
  check("L9. without a subscription, both share routes are 402 and nothing changes", louShare.status === 402 && louLink.status === 402 && J(row(CID.lapsed)) === louBefore, louShare.status + " " + louLink.status);
  check("L10. both share routes are requireAuth then requireActiveSubscription", J(names("put /api/crowdfunding/campaigns/:id/share").slice(0, 2)) === J(["requireAuth", "requireActiveSubscription"]) &&
    J(names("post /api/crowdfunding/campaigns/:id/share/new-link").slice(0, 2)) === J(["requireAuth", "requireActiveSubscription"]), J(names("put /api/crowdfunding/campaigns/:id/share")));
  const bad = await Promise.all([{ share_on: "yes" }, { discoverable: 1 }, {}, { share_on: true, share_id: "aaaaaaaaaaaaaaaa" }].map(b => hit("put /api/crowdfunding/campaigns/:id/share", OWEN, b, { id: fresh.id })));
  check("L11. a non-boolean, an empty body and any other field (a chosen share id included) are refused with 400", bad.every(r => r.status === 400) && fresh.share_id === sid2, bad.map(r => r.status).join(","));
  const disc = await hit("put /api/crowdfunding/campaigns/:id/share", OWEN, { discoverable: true }, { id: fresh.id });
  CTX.campaignSitemapCache = { xml: null, at: 0 };
  const sm2 = await hit("get /api/sitemap/campaigns.xml", null, {}, {});
  check("L12. letting search engines find it puts it in the sitemap and makes the page indexable", disc.status === 200 && disc.body.discoverable === true &&
    locs(sm2.text).indexOf("https://bizforceai.net/campaign/" + sid2) !== -1 && robotsOf((await page(sid2)).text) === "index, follow", sm2.text);

  /* ════ T. the status moves ════ */
  console.log("\n══ T. the status moves ══");
  const STATUSES = ["active", "paused", "completed", "cancelled"];
  const allowed = { active: ["active", "paused", "completed", "cancelled"], paused: ["active", "paused", "completed", "cancelled"], completed: ["completed"], cancelled: ["cancelled"] };
  const wrong = [];
  for (const from of STATUSES) for (const to of STATUSES.concat(["bogus", "draft"])) {
    row(CID.listed).status = from;
    const was = J(row(CID.listed));
    CTX.campaignSitemapCache = { xml: "<cached/>", at: Date.now() };
    const r = await hit("put /api/crowdfunding/campaigns/:id", OWEN, { status: to }, { id: CID.listed });
    const ok = (allowed[from] || []).indexOf(to) !== -1;
    const good = ok ? (r.status === 200 && row(CID.listed).status === to && CTX.campaignSitemapCache.xml === null) : (r.status === 400 && J(row(CID.listed)) === was && r.body.reason === "status_move_refused");
    if (!good) wrong.push(from + "->" + to + " " + r.status);
  }
  row(CID.listed).status = "active";
  check("T1. active and paused go to each other; either to completed or cancelled; completed and cancelled are final; an unknown status is 400; a refusal changes nothing; a move clears the sitemap's cache",
    wrong.length === 0, wrong.join(", "));
  const danaEdit = await hit("put /api/crowdfunding/campaigns/:id", DANA, { status: "paused" }, { id: CID.listed });
  check("T2. another member's status change is 404 and changes nothing", danaEdit.status === 404 && row(CID.listed).status === "active");
  const titleEdit = await hit("put /api/crowdfunding/campaigns/:id", OWEN, { title: "Kiln fund, round two" }, { id: CID.listed });
  check("T3. an edit without a status keeps the status and saves the text", titleEdit.status === 200 && row(CID.listed).title === "Kiln fund, round two" && row(CID.listed).status === "active");

  /* ════ I. the list and by-share ════ */
  console.log("\n══ I. the list, and by-share ══");
  const LIST_KEYS = J(["category", "created_at", "description", "goal_bfc", "id", "is_own", "media", "raised_bfc", "status", "title", "updated_at"]);
  const listD = await hit("get /api/crowdfunding/campaigns", DANA, {}, {});
  const listO = await hit("get /api/crowdfunding/campaigns", OWEN, {}, {});
  check("I1. the list: active campaigns only, each with exactly the list fields, is_own and no owner_id, share id or sharing switch",
    listD.status === 200 && listD.body.campaigns.length > 0 && listD.body.campaigns.every(c => J(Object.keys(c).sort()) === LIST_KEYS && c.status === "active" &&
      J(c).indexOf(OWEN) === -1 && J(c).indexOf(DANA) === -1 && J(c).indexOf(SID.on) === -1), J(listD.body.campaigns[0]));
  check("I2. is_own is true only on the viewer's own campaigns", listO.body.campaigns.filter(c => c.is_own).length === listO.body.campaigns.filter(c => row(c.id).owner_id === OWEN).length &&
    listD.body.campaigns.filter(c => c.is_own).map(c => c.id).join() === CID.private && listO.body.campaigns.some(c => c.is_own) && listD.body.campaigns.some(c => !c.is_own));
  const bsAnon = await hit("get /api/crowdfunding/campaigns/by-share/:shareId", null, {}, { shareId: SID.on });
  check("I3. by-share needs a signed-in member: 401 signed out, requireAuth first", bsAnon.status === 401 && names("get /api/crowdfunding/campaigns/by-share/:shareId")[0] === "requireAuth", bsAnon.status);
  const bsOn = await hit("get /api/crowdfunding/campaigns/by-share/:shareId", DANA, {}, { shareId: SID.on });
  check("I4. a shared, active campaign resolves to its list item: the id the donate route needs, is_own, no owner_id",
    bsOn.status === 200 && J(Object.keys(bsOn.body.campaign).sort()) === LIST_KEYS && bsOn.body.campaign.id === CID.on && bsOn.body.campaign.is_own === false &&
    J(bsOn.body).indexOf(OWEN) === -1 && J(bsOn.body).indexOf(SID.on) === -1, J(bsOn.body));
  const notAvail = await Promise.all([SID.off, SID.paused, SID.cancelled, SID.ended, SID.unknown, "ZZZZ"].map(x => hit("get /api/crowdfunding/campaigns/by-share/:shareId", DANA, {}, { shareId: x })));
  check("I5. not shared, paused, cancelled, completed, unknown or malformed: the same 404, \"This campaign isn't available.\"",
    notAvail.every(r => r.status === 404 && r.body.error === "This campaign isn't available." && J(Object.keys(r.body).sort()) === J(["error", "reason"])), notAvail.map(r => r.status).join(","));
  const mine = await hit("get /api/crowdfunding/my-campaigns", OWEN, {}, {});
  check("I6. my-campaigns gives the owner every status of their own, with share_on, discoverable and the share link", mine.status === 200 &&
    mine.body.campaigns.every(c => c.owner_id === OWEN) && mine.body.campaigns.some(c => c.status === "cancelled") &&
    mine.body.campaigns.find(c => c.id === CID.on).share_url === "https://bizforceai.net/campaign/" + SID.on);

  /* ════ F. the pages ════ */
  console.log("\n══ F. campaigns.html and bf-campaign.js ══");
  const cp = fe("campaigns.html") || "";
  check("F1. campaigns.html sets no innerHTML, decodes no token and compares no account id: it uses is_own",
    cp.indexOf("innerHTML") === -1 && cp.indexOf("atob(") === -1 && cp.indexOf("currentUserId") === -1 && cp.indexOf("owner_id") === -1 && /c\.is_own === true/.test(cp));
  const LABELS = ["Your campaigns", "Share this campaign", "Let search engines find it", "Copy link", "Make a new link", "Your old link will stop working.",
    "\"Edit\"", "\"Pause\"", "\"Resume\"", "\"Mark complete\"", "\"Cancel\"", "This campaign isn't available.", "/api/crowdfunding/campaigns/by-share/", "/api/crowdfunding/my-campaigns", "/share/new-link"];
  check("F2. the page carries every label and route it uses", LABELS.every(l => cp.indexOf(l) !== -1), LABELS.filter(l => cp.indexOf(l) === -1).join(" | "));
  check("F3. the QR library is the card's, with its SRI, and bf-support.js supplies Copy", cp.indexOf(C.QR_SCRIPT) !== -1 && cp.indexOf('<script src="/scripts/bf-support.js"></script>') !== -1);
  if (JSDOM) {
    const inline = (/<script>\nvar API_URL[\s\S]*?<\/script>/.exec(cp) || [""])[0].replace(/^<script>/, "").replace(/<\/script>$/, "");
    async function campaignsPage(opts) {
      const dom = new JSDOM(stripScripts(cp), { url: "https://bizforceai.net/campaigns.html" + (opts.search || ""), runScripts: "outside-only" });
      const w = dom.window;
      const log = { fetches: [], confirms: [], prompts: [], alerts: [], qr: [], copied: [] };
      w.localStorage.setItem("bf_token", "tok");
      w.confirm = q => { log.confirms.push(q); return opts.confirm !== false; };
      w.prompt = q => { log.prompts.push(q); return null; };
      w.alert = a => { log.alerts.push(a); };
      w.QRCode = { toCanvas: (c, t, o, cb) => { log.qr.push(t); if (cb) cb(null); } };
      w.BFSupport = { copyText: t => { log.copied.push(t); return Promise.resolve(); } };
      w.fetch = function (u, init) {
        log.fetches.push({ url: String(u), init: init || {} });
        const a = (opts.answers || []).find(x => String(u).indexOf(x.match) !== -1 && (!x.method || ((init && init.method) || "GET") === x.method));
        const status = a && a.status || 200;
        const p = Promise.resolve({ ok: status < 400, status: status, json: () => Promise.resolve(a ? JSON.parse(J(a.body)) : {}) });
        p.catch(() => {});
        return p;
      };
      w.eval(inline);
      await settle();
      return { w, doc: w.document, log };
    }
    const SHARED_URL = "https://bizforceai.net/campaign/" + SID.on;
    const LIST = { campaigns: [{ id: "x1", title: "<img src=x onerror=alert(9)>Kiln", description: "<b>hi</b>", category: "<i>c</i>", media: [], goal_bfc: 100, raised_bfc: 10, status: "active", created_at: "2026-11-01T00:00:00Z", is_own: false },
      { id: "x2", title: "Mine", description: "", media: [], goal_bfc: 100, raised_bfc: 0, status: "active", created_at: "2026-11-01T00:00:00Z", is_own: true }] };
    const MINE = { campaigns: [
      { id: "m1", title: "<svg onload=alert(1)>Shared", status: "active", share_on: true, discoverable: false, share_url: SHARED_URL, goal_bfc: 100, raised_bfc: 5, media: [] },
      { id: "m2", title: "Done", status: "completed", share_on: false, discoverable: false, share_url: null, goal_bfc: 100, raised_bfc: 100, media: [] },
      { id: "m3", title: "Resting", status: "paused", share_on: true, discoverable: true, share_url: "https://bizforceai.net/campaign/" + SID.paused, goal_bfc: 100, raised_bfc: 1, media: [] }] };
    const answers = [{ match: "/api/crowdfunding/my-campaigns", body: MINE }, { match: "/api/crowdfunding/campaigns", method: "GET", body: LIST }, { match: "/api/crowdfunding/campaigns/", method: "PUT", body: {} },
      { match: "/share/new-link", method: "POST", body: { url: SHARED_URL } }];
    const P1 = await campaignsPage({ answers });
    const grid = P1.doc.getElementById("campaignsGrid");
    check("F4. a hostile title, description and category are drawn as text: no element is made from them",
      grid.querySelectorAll("img[onerror], b, i").length === 0 && grid.querySelector(".campaign-title").textContent === "<img src=x onerror=alert(9)>Kiln" &&
      P1.doc.querySelectorAll("#myCampaigns svg, #campaignsGrid svg").length === 0 && P1.doc.getElementById("myCampaigns").textContent.indexOf("<svg onload=alert(1)>Shared") !== -1);
    check("F5. is_own: \"Your campaign\" on the viewer's own card, \"Donate BFC\" on the others",
      Array.from(grid.querySelectorAll(".campaign-card")).map(c => c.querySelector(".campaign-footer").lastChild.textContent).join("|") === "Donate BFC|Your campaign");
    const cards = Array.from(P1.doc.querySelectorAll("#myCampaigns .my-card"));
    const btns = c => Array.from(c.querySelectorAll("button")).map(b => b.textContent);
    check("F6. \"Your campaigns\" shows each status with the controls it allows", !P1.doc.getElementById("mySection").hidden && cards.length === 3 &&
      cards.map(c => c.querySelector(".my-status").textContent).join("|") === "Active|Completed|Paused" &&
      J(btns(cards[0])) === J(["Edit", "Pause", "Mark complete", "Cancel", "Copy link", "Make a new link"]) && J(btns(cards[1])) === "[]" &&
      J(btns(cards[2])) === J(["Edit", "Resume", "Mark complete", "Cancel", "Copy link", "Make a new link"]), btns(cards[0]).join(",") + " / " + btns(cards[2]).join(","));
    const toggles = c => Array.from(c.querySelectorAll("label.share-toggle")).map(l => l.textContent + "=" + l.querySelector("input").checked);
    check("F7. the Share panel: the two switches, the link as text, a QR code of it", J(toggles(cards[0])) === J(["Share this campaign=true", "Let search engines find it=false"]) &&
      cards[0].querySelector("a.share-link").textContent === SHARED_URL && cards[0].querySelector("a.share-link").getAttribute("href") === SHARED_URL &&
      P1.log.qr.indexOf(SHARED_URL) !== -1 && !cards[1].querySelector("a.share-link") && /Sharing is off/.test(cards[1].textContent), J(toggles(cards[0])));
    const fetchesOf = (L, pat, m) => L.fetches.filter(f => f.url.indexOf(pat) !== -1 && (f.init.method || "GET") === m);
    const P2 = await campaignsPage({ answers, confirm: false });
    const c2 = Array.from(P2.doc.querySelectorAll("#myCampaigns .my-card"))[0];
    const clickBtn = (card, label) => Array.from(card.querySelectorAll("button")).find(b => b.textContent === label).click();
    clickBtn(c2, "Cancel"); clickBtn(c2, "Mark complete"); clickBtn(c2, "Make a new link"); await settle();
    check("F8. Cancel, Mark complete and Make a new link each ask first; declined, nothing is sent",
      P2.log.confirms.length === 3 && /cannot be undone/.test(P2.log.confirms[0]) && /cannot be undone/.test(P2.log.confirms[1]) && P2.log.confirms[2] === "Your old link will stop working." &&
      fetchesOf(P2.log, "/api/crowdfunding/campaigns/m1", "PUT").length === 0 && fetchesOf(P2.log, "/share/new-link", "POST").length === 0, J(P2.log.confirms));
    const P3 = await campaignsPage({ answers, confirm: true });
    const c3 = Array.from(P3.doc.querySelectorAll("#myCampaigns .my-card"))[0];
    clickBtn(c3, "Cancel"); await settle();
    const c3b = Array.from(P3.doc.querySelectorAll("#myCampaigns .my-card"))[0];
    clickBtn(c3b, "Pause"); await settle();
    const c3c = Array.from(P3.doc.querySelectorAll("#myCampaigns .my-card"))[0];
    clickBtn(c3c, "Make a new link"); await settle();
    const puts = fetchesOf(P3.log, "/api/crowdfunding/campaigns/m1", "PUT").map(f => f.init.body);
    check("F9. confirmed, Cancel sends { status: cancelled }; Pause sends { status: paused } without asking; the new link is POSTed",
      J(puts) === J([J({ status: "cancelled" }), J({ status: "paused" })]) && P3.log.confirms.length === 2 && fetchesOf(P3.log, "/api/crowdfunding/campaigns/m1/share/new-link", "POST").length === 1, J(puts));
    const c3d = Array.from(P3.doc.querySelectorAll("#myCampaigns .my-card"))[0];
    const shareBox = c3d.querySelector("label.share-toggle input");
    shareBox.checked = false; shareBox.dispatchEvent(new P3.w.Event("change")); await settle();
    check("F10. switching \"Share this campaign\" off sends { share_on: false } to the share route",
      fetchesOf(P3.log, "/api/crowdfunding/campaigns/m1/share", "PUT").map(f => f.init.body).indexOf(J({ share_on: false })) !== -1);
    const P4 = await campaignsPage({ answers: [{ match: "/by-share/", body: { campaign: { id: "cid-9", title: "Kiln fund", is_own: false } } }].concat(answers), search: "?campaign=" + SID.on });
    const bs = P4.log.fetches.filter(f => f.url.indexOf("/api/crowdfunding/campaigns/by-share/" + SID.on) !== -1);
    check("F11. ?campaign=<share id> is resolved by by-share, signed in, and opens the donate flow for that campaign",
      bs.length === 1 && bs[0].init.headers.Authorization === "Bearer tok" && P4.log.prompts.length === 1 && /Kiln fund/.test(P4.log.prompts[0]) &&
      P4.w.location.search === "", J(P4.log.prompts));
    const P5 = await campaignsPage({ answers: [{ match: "/by-share/", status: 404, body: { error: "x" } }].concat(answers), search: "?campaign=" + SID.off });
    const P6 = await campaignsPage({ answers, search: "?campaign=NOT-AN-ID" });
    check("F12. not found or not shared, and a malformed id: \"This campaign isn't available.\", no donate prompt; a malformed id is never sent",
      P5.doc.getElementById("toast").textContent === "This campaign isn't available." && P5.log.prompts.length === 0 &&
      P6.doc.getElementById("toast").textContent === "This campaign isn't available." && P6.log.fetches.every(f => f.url.indexOf("by-share") === -1) && P6.log.prompts.length === 0);

    // bf-campaign.js on the served page
    const cjs = fe("scripts/bf-campaign.js") || "", sjs = fe("scripts/bf-support.js") || "";
    async function publicPage(html, signedIn) {
      const dom = new JSDOM(stripScripts(html), { url: "https://bizforceai.net/campaign/" + SID.on + "?ref=qr", runScripts: "outside-only" });
      const w = dom.window;
      const log = { qr: [], copied: [] };
      if (signedIn) w.localStorage.setItem("bf_token", "tok");
      Object.defineProperty(w.navigator, "clipboard", { configurable: true, value: { writeText: t => { log.copied.push(t); return Promise.resolve(); } } });
      w.QRCode = { toCanvas: (c, t, o, cb) => { log.qr.push({ id: c.id, t: t }); if (cb) cb(null); } };
      w.fetch = () => { const p = Promise.resolve({ ok: false, status: 401, json: () => Promise.resolve({}) }); p.catch(() => {}); return p; };
      w.eval(sjs); w.eval(cjs);
      await settle();
      return { w, doc: w.document, log };
    }
    const out = await publicPage(on.text, false);
    const signIn = out.doc.getElementById("cmpSignIn"), donate = out.doc.getElementById("cmpDonate");
    signIn.dispatchEvent(new out.w.MouseEvent("click", { bubbles: true, cancelable: true }));
    check("F13. signed out, \"Sign in to donate\" shows, and it keeps the donate flow to come back to", !signIn.hidden && donate.hidden &&
      out.w.localStorage.getItem("bf_return_to") === "https://bizforceai.net/campaigns.html?campaign=" + SID.on, out.w.localStorage.getItem("bf_return_to"));
    check("F14. the QR code encodes the page's share link", out.log.qr.length === 1 && out.log.qr[0].id === "cmpQr" && out.log.qr[0].t === "https://bizforceai.net/campaign/" + SID.on, J(out.log.qr));
    out.doc.getElementById("cmpCopyBtn").click(); await settle();
    check("F15. Copy link copies the share link and says \"Link copied\"", out.log.copied[0] === "https://bizforceai.net/campaign/" + SID.on && out.doc.getElementById("cmpShareStatus").textContent === "Link copied");
    const inn = await publicPage(on.text, true);
    check("F16. signed in, \"Donate BizCash\" shows instead", inn.doc.getElementById("cmpSignIn").hidden && !inn.doc.getElementById("cmpDonate").hidden);
    check("F17. bf-campaign.js draws nothing with innerHTML", cjs.indexOf("innerHTML") === -1 && cjs.indexOf("insertAdjacentHTML") === -1);
  } else check("F4. jsdom is installed", false);

  // app.html and bf-session.js: back to the donate flow after sign-in
  const app = fe("app.html") || "";
  const at = app.indexOf("  function signInReturnTo() {");
  let rt = null;
  try {
    const fn = app.slice(at, s.braceMatch(app, app.indexOf("{", at)));
    const returnTo = stored => {
      const store = { bf_return_to: stored };
      const ctx = { URL, window: { location: { origin: "https://bizforceai.net" } }, localStorage: { getItem: k => store[k] === undefined ? null : store[k], removeItem: k => { delete store[k]; } } };
      vm.createContext(ctx); vm.runInContext(fn + "\nthis.__r = signInReturnTo();", ctx); return ctx.__r;
    };
    rt = [returnTo("https://bizforceai.net/campaigns.html?campaign=" + SID.on), returnTo("/campaigns.html?campaign=" + SID.on), returnTo("https://evil.com/campaigns.html?campaign=" + SID.on),
      returnTo("https://bizforceai.net/support/rita")];
  } catch (e) { rt = String(e); }
  check("F18. app.html returns to campaigns.html?campaign=<id> after sign-in, and still to nothing off this site",
    Array.isArray(rt) && rt[0] === "/campaigns.html?campaign=" + SID.on && rt[1] === "/campaigns.html?campaign=" + SID.on && rt[2] === null && rt[3] === "/support/rita", J(rt));
  const sess = fe("scripts/bf-session.js") || "";
  check("F19. bf-session.js keeps a signed-out visitor's ?campaign=<id> as the page to return to, before sending them to sign in",
    /if \(!read\(TOKEN_KEY\)\) \{\n[\s\S]{0,400}?if \(window\.location\.pathname === "\/campaigns\.html" && \/\^\\\?campaign=\[a-z2-7\]\{16\}\$\/\.test\(window\.location\.search\)\) \{\n\s+write\("bf_return_to", window\.location\.pathname \+ window\.location\.search\);\n\s+\}\n\s+window\.location\.replace\(LOGIN_PAGE\);/.test(sess));

  /* ════ G. legal, guide, redirects ════ */
  console.log("\n══ G. Privacy and Terms, the guide, the redirects ══");
  const PRIVACY = "Signed-in members can see your active crowdfunding campaigns: the title, description, photos, category, goal and amount raised. If you turn sharing on for a campaign, anyone with its link can see those and your display name and photo, and if you also let search engines find it, they may list it; who donated is never shown. You can turn sharing off or make a new link at any time, and the old link then stops working.";
  const TERMS = "If you run or share a campaign, describe it truthfully and use what you raise for the purpose you describe.";
  check("G1. lib/legalPages.js: CAMPAIGN_PRIVACY_SENTENCE and CAMPAIGN_TERMS_SENTENCE are the brief's sentences, word for word", LP.CAMPAIGN_PRIVACY_SENTENCE === PRIVACY && LP.CAMPAIGN_TERMS_SENTENCE === TERMS);
  const built = LP.buildLegalPages();
  const esc = LEGAL.escapeHtml;
  const inOrder = (h, a, b) => h.indexOf(a) !== -1 && h.indexOf(b) !== -1 && h.indexOf(a) < h.indexOf(b);
  check("G2. the Privacy Policy carries it in the section with \"Other members see what you choose to publish\", after the support sentence, built and on disk",
    [built["privacy.html"], fe("privacy.html") || ""].every(h => inOrder(h, esc("Other members see what you choose to publish"), esc(LP.SUPPORT_PRIVACY_SENTENCE)) &&
      inOrder(h, esc(LP.SUPPORT_PRIVACY_SENTENCE), esc(PRIVACY))));
  const MARKET = "BizForce Market lets members trade with each other: buying and selling listings, sending BizCash, and donating to campaigns. These rules apply to every trade.";
  check("G3. the Terms carry the campaign sentence right after the BizForce Market sentence, built and on disk",
    [built["terms.html"], fe("terms.html") || ""].every(h => h.indexOf("<p>" + esc(MARKET) + "</p>\n<p>" + esc(TERMS) + "</p>") !== -1 || h.indexOf("<p>" + esc(MARKET) + "</p><p>" + esc(TERMS) + "</p>") !== -1 ||
      (inOrder(h, esc(MARKET), esc(TERMS)) && h.indexOf(esc(TERMS)) - h.indexOf(esc(MARKET)) < esc(MARKET).length + 40)));
  // NAMED (Nov 5 2026, images in social posts): BEFORE "2026-11-04", the version this change set. AFTER "2026-11-05", the version
  // the social images privacy sentence set.
  // NAMED (Nov 6 2026, card upgrades C1): BEFORE "2026-11-05" (images in social posts). AFTER "2026-11-06", the version the
  // card visits privacy sentence set.
  check("G4. TERMS_VERSION and TERMS_UPDATED are the latest change's, Nov 6 2026 (card visits; this change set Nov 4)", LEGAL.TERMS_VERSION === "2026-11-06" && LEGAL.TERMS_UPDATED === "Last updated November 6, 2026", LEGAL.TERMS_VERSION);
  const guide = fe("scripts/termaximus-guide.js") || "";
  const block = (/"campaigns\.html": \[\n([\s\S]*?)\n    \]/.exec(guide) || ["", ""])[1];
  const tips = (block.match(/"(?:[^"\\]|\\.)*"/g) || []).map(t => JSON.parse(t));
  const TIP = "Under \"Your campaigns\", turn on \"Share this campaign\" for a link anyone can open; \"Make a new link\" stops the old one.";
  check("G5. campaigns.html keeps 4 tips, tip 2 names sharing truthfully, and every label it quotes is on the page",
    tips.length === 4 && tips[1] === TIP && TIP.length <= 160 && ["Your campaigns", "Share this campaign", "Make a new link"].every(l => cp.indexOf(l) !== -1), J(tips));
  const redir = fe("_redirects") || "";
  const iCamp = redir.indexOf("\n/campaign/:shareId https://dynamic-prosperity-production-5382.up.railway.app/campaign/:shareId 200\n");
  const iMap = redir.indexOf("\n/sitemap-campaigns.xml https://dynamic-prosperity-production-5382.up.railway.app/api/sitemap/campaigns.xml 200\n");
  const iAll = redir.indexOf("\n/* /app.html 200");
  check("G6. Netlify proxies /campaign/:shareId and /sitemap-campaigns.xml to the backend, above the catch-all, like /support/:username",
    iCamp > 0 && iMap > 0 && iAll > 0 && iCamp < iAll && iMap < iAll && redir.indexOf("/support/:username https://dynamic-prosperity-production-5382.up.railway.app/support/:username 200") !== -1);
  check("G7. the sitemap index lists sitemap-campaigns.xml", (fe("sitemap.xml") || "").indexOf("<sitemap><loc>https://bizforceai.net/sitemap-campaigns.xml</loc></sitemap>") !== -1);

  /* ════ Z. no network ════ */
  console.log("\n══ Z. no network ══");
  check("Z. zero sockets and DNS lookups", NETWORK.length === 0, J(NETWORK));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures) + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : "")); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED" + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(0);
})().catch(function (err) {
  console.log("    FAIL  the check threw: " + ((err && err.stack) || err));
  process.exit(1);
});
