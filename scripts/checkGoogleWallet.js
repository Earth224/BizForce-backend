"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkGoogleWallet — "Add to Google Wallet" on public cards (build list item
   6, part 2; migration 174, Nov 6 2026). BizForce signs a "Save to Google
   Wallet" JWT offline (RS256) carrying one shared generic class and the
   card's object, and GET /api/cards/google-wallet answers 302 to
   pay.google.com. No Google API call, ever.

   No request leaves the machine. The RSA key is made here at run time
   (generateKeyPairSync) and never written anywhere; the database and the plan
   lookup are fakes; card-view.html runs in jsdom; a tripwire fails any socket
   or DNS lookup.

   SECTIONS
     A. configuration: missing, bad issuer, bad email, a key with literal \n,
        with real newlines, a non-RSA key, garbage; never a throw, never a value.
     B. the routes: 503 until configured (and no google_wallet in the card
        JSON then), 400 for a bad ref, 404 for a missing card, a lapsed owner and
        a throwing lookup, the 302 and no-store, and nothing written.
     C. the JWT: verified with the test public key, RS256, every claim, the
        class and the object ids (stable per card, different between cards,
        never the card id).
     D. the pass: hidden email and phone absent, the photo only when shown and
        in bf-public, the logo otherwise, the theme colour, the QR value and the
        mailto and tel links equal to bf-card.js, the length caps.
     E. counting: tap kind wallet, and the stats with wallet_taps.
     F. the page: the button only with google_wallet on Android, its click
        sending the beacon then going to the route, textContent only; the
        shell in sync; the editor's totals.
     G. legal, THIRD_PARTIES, README, the migration as run, R1.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const net = require("net");
const dns = require("dns");
const crypto = require("crypto");
const Module = require("module");
const s = require("./_shared");

/* ── the network tripwire ─────────────────────────────────────────────────── */
const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkGoogleWallet: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkGoogleWallet: no network"); };

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const BS = String.fromCharCode(92);

const MUTATIONS = {
  "shown-on-iphone": [["FE:card-view.html", "!/Android/i.test(navigator.userAgent || \"\")", "!/Android|iPhone/i.test(navigator.userAgent || \"\")"]],
  "shown-when-unconfigured": [["SRC", "  if (card && googleWallet.config()) card.google_wallet = true;\n", "  if (card) card.google_wallet = true;\n"]],
  "lapsed-pass-issued": [["SRC", "    if (!(await ownerPagePublic(walletRow.user_id))) return res.status(404).json({ error: googleWallet.MESSAGES.notFound });\n", ""]],
  "lookup-throw-issued": [["SRC", "    if (!(await ownerPagePublic(walletRow.user_id))) return",
    "    if (!(await ownerPagePublic(walletRow.user_id).catch(function () { return true; }))) return"]],
  "hidden-email-in-pass": [["GW", "[\"email\", \"Email\", card.email]", "[\"email\", \"Email\", row.email]"]],
  "hidden-phone-in-pass": [["GW", "[\"phone\", \"Phone\", card.phone]", "[\"phone\", \"Phone\", row.phone]"]],
  "photo-when-hidden": [["GW", "  if (!row || row.show_photo !== true || !photoPrefix) return null;\n", "  if (!row || row.show_photo === false || !photoPrefix) return null;\n"]],
  "foreign-photo-host": [["GW", "  if (url.indexOf(photoPrefix) !== 0 || url.length", "  if (url.indexOf(\"https://\") !== 0 || url.length"]],
  "object-id-is-card-id": [["GW", "  return issuer + \".c\" + crypto.createHmac(\"sha256\", k).update(String(cardId)).digest(\"hex\").slice(0, 32);\n",
    "  return issuer + \".c\" + String(cardId).replace(/-/g, \"\");\n"]],
  "object-id-unstable": [["GW", ".update(String(cardId)).digest(\"hex\")", ".update(String(cardId) + crypto.randomBytes(4).toString(\"hex\")).digest(\"hex\")"]],
  "aud-wrong": [["GW", "    aud: \"google\",\n", "    aud: \"google.com\",\n"]],
  "typ-wrong": [["GW", "    typ: \"savetowallet\",\n", "    typ: \"JWT\",\n"]],
  "origins-missing": [["GW", "    origins: ORIGINS.slice(),\n", ""]],
  "hs256-signing": [["GW", "sign(claims, key, { algorithm: \"RS256\" });", "sign(claims, \"bftest-hs-secret\", { algorithm: \"HS256\" });"]],
  "key-logged": [["GW", "  if (pem.indexOf(KEY_BEGIN) !== 0) return { error: \"sa_key_format\" };\n",
    "  deps.log(\"[google-wallet] key \" + pem);\n  if (pem.indexOf(KEY_BEGIN) !== 0) return { error: \"sa_key_format\" };\n"]],
  "jwt-logged": [["SRC", "    return res.redirect(302, googleWallet.saveUrl(walletObject, walletConfig, Date.now()));\n",
    "    const walletLink = googleWallet.saveUrl(walletObject, walletConfig, Date.now());\n    console.log(\"[google-wallet] link \" + walletLink);\n    return res.redirect(302, walletLink);\n"]],
  "literal-newline-unhandled": [["GW", "  var pem = rawKey.split(\"" + BS + BS + "n\").join(\"" + BS + "n\").trim();\n", "  var pem = rawKey.trim();\n"]],
  "non-rsa-accepted": [["GW", "  if (key.asymmetricKeyType !== \"rsa\") return { error: \"sa_key_type\" };\n", ""]],
  "route-writes": [["SRC", "    if (!walletObject) return res.status(404).json({ error: googleWallet.MESSAGES.notFound });\n",
    "    if (!walletObject) return res.status(404).json({ error: googleWallet.MESSAGES.notFound });\n    await bumpCardCount(walletRow.id, \"wallet_taps\");\n"]],
  "beacon-awaited": [["FE:card-view.html", "    sendTap(\"wallet\");\n    window.location.assign(API_URL + \"/api/cards/google-wallet?ref=\" + encodeURIComponent(cardRef()));\n",
    "    Promise.resolve(sendTap(\"wallet\")).then(function () { window.location.assign(API_URL + \"/api/cards/google-wallet?ref=\" + encodeURIComponent(cardRef())); });\n"]],
  "qr-value-drift": [["GW", "  return u + (u.indexOf(\"?\") === -1 ? \"?\" : \"&\") + \"via=qr\";\n", "  return u + (u.indexOf(\"?\") === -1 ? \"?\" : \"&\") + \"via=wallet\";\n"]],
  "theme-hex-wrong": [["GW", "midnight: \"#1a1040\"", "midnight: \"#0f1729\""]],
  "cache-public": [["SRC", "  res.set(\"Cache-Control\", \"no-store\");\n  const walletRef", "  res.set(\"Cache-Control\", \"public, max-age=600\");\n  const walletRef"]],
  "privacy-sentence-removed": [["LP", "      CARD_WALLET_PRIVACY_SENTENCE,\n", ""]],
  "innerHTML-on-page": [["FE:card-view.html", "  btn.hidden = false;\n  btn.addEventListener(\"click\", function () {\n    sendTap(\"wallet\");",
    "  btn.innerHTML = \"Add to Google Wallet\";\n  btn.hidden = false;\n  btn.addEventListener(\"click\", function () {\n    sendTap(\"wallet\");"]],
  // earned: the route answers 404, not 503, before Google Wallet is set up
  "unconfigured-not-503": [["SRC", "  if (!walletConfig) return res.status(503).json(", "  if (!walletConfig) return res.status(404).json("]],
  // earned: no object ids can be made without JWT_SECRET, yet Wallet counts as configured
  "jwt-secret-optional": [["GW", "  if (!jwtSecret) return { error: \"jwt_secret\" };\n", ""]],
  // earned: any address passes as the service account
  "sa-email-unchecked": [["GW", " || email.slice(-SA_SUFFIX.length) !== SA_SUFFIX) return { error: \"sa_email\" };", ") return { error: \"sa_email\" };"]],
  // earned: the tap route no longer takes kind wallet
  "tap-wallet-refused": [["CP", ", wallet: \"wallet_taps\" };", " };"]],
  // earned: the stats leave wallet_taps out of the read
  "stats-wallet-missing": [["SRC", "save_taps, support_taps, wallet_taps\")", "save_taps, support_taps\")"]],
  // earned: the editor leaves the wallet count out
  "editor-wallet-missing": [["FE:digital-cards.html", " + \" support opened, \" + n(\"wallet_taps\") + \" added to Google Wallet\";", " + \" support opened\";"]],
  // earned: a link to Google that is not the save URL
  "save-url-wrong": [["GW", "const SAVE_URL = \"https://pay.google.com/gp/v/save/\";", "const SAVE_URL = \"https://wallet.google.com/save/\";"]]
};
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

let passes = 0, failures = 0;
const lf = t => t.replace(/\r\n/g, "\n");
const clone = v => v === undefined ? undefined : JSON.parse(JSON.stringify(v));
const J = JSON.stringify;
const tick = () => new Promise(r => setTimeout(r, 0));
async function settle(n) { for (let i = 0; i < (n || 15); i++) await tick(); }

/* ── secrets the run makes: never printed ─────────────────────────────────── */
const SECRET_FORMS = [];
function secret(v) { if (v && SECRET_FORMS.indexOf(v) === -1) SECRET_FORMS.push(v); return v; }
const safe = x => { let t = typeof x === "string" ? x : J(x); SECRET_FORMS.forEach(f => { t = t.split(f).join("[secret]"); }); return t; };
const holdsSecret = text => SECRET_FORMS.some(f => String(text).indexOf(f) !== -1);
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + safe(String(detail)).slice(0, 300) + "]" : "")); }
}

/* ── the sources, mutated in memory ───────────────────────────────────────── */
const SOURCES = {
  SRC: lf(fs.readFileSync(path.join(REPO, "server.js"), "utf8")),
  GW: lf(fs.readFileSync(path.join(REPO, "lib/googleWallet.js"), "utf8")),
  CP: lf(fs.readFileSync(path.join(REPO, "lib/cardPage.js"), "utf8")),
  LP: lf(fs.readFileSync(path.join(REPO, "lib/legalPages.js"), "utf8"))
};
["card-view.html", "digital-cards.html", "scripts/bf-card.js", "privacy.html", "_headers"].forEach(f => { SOURCES["FE:" + f] = lf(fs.readFileSync(path.join(FRONTEND, f), "utf8")); });
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [where, from, to] of edits) SOURCES[where] = s.replaceOnce(SOURCES[where], from, to, MUTATE + " in " + where);
  console.log("\n!! MUTATION: " + MUTATE);
}
const SRC = SOURCES.SRC;
const FE = f => SOURCES["FE:" + f];

function loadLib(rel, text) {
  const file = path.join(REPO, rel);
  const m = new Module(file, module);
  m.filename = file;
  m.paths = Module._nodeModulePaths(path.dirname(file));
  require.cache[file] = m;
  m._compile(text, file);
  m.loaded = true;
  return m.exports;
}

/* ── the test configuration: a key made now, fake names ───────────────────── */
const ISSUER = "3388000000012345678";
const SA_EMAIL = "wallet-signer@bftest-project.iam.gserviceaccount.com";
const JWT_SECRET = secret("bftest-jwt-secret-for-wallet-object-ids-0001");
const SUPABASE_URL = "https://bftestproj.supabase.co";
const PUB = SUPABASE_URL + "/storage/v1/object/public/bf-public/";
const RSA = crypto.generateKeyPairSync("rsa", { modulusLength: 2048, privateKeyEncoding: { type: "pkcs8", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } });
const EC = crypto.generateKeyPairSync("ec", { namedCurve: "P-256", privateKeyEncoding: { type: "pkcs8", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } });
const keyLines = pem => pem.split("\n").filter(l => l && l.indexOf("-----") !== 0);
keyLines(RSA.privateKey).concat(keyLines(EC.privateKey)).forEach(secret);
secret(RSA.privateKey.trim()); secret(EC.privateKey.trim());
const KEY_LITERAL_NL = RSA.privateKey.trim().split("\n").join(BS + "n");
const ENV_OK = { GOOGLE_WALLET_ISSUER_ID: ISSUER, GOOGLE_WALLET_SA_EMAIL: SA_EMAIL, GOOGLE_WALLET_SA_KEY: KEY_LITERAL_NL, JWT_SECRET: JWT_SECRET, SUPABASE_URL: SUPABASE_URL };
const WALLET_VARS = ["GOOGLE_WALLET_ISSUER_ID", "GOOGLE_WALLET_SA_EMAIL", "GOOGLE_WALLET_SA_KEY"];
function configure(on) {
  WALLET_VARS.forEach(k => { if (on) process.env[k] = ENV_OK[k]; else delete process.env[k]; });
  process.env.JWT_SECRET = JWT_SECRET;
  process.env.SUPABASE_URL = SUPABASE_URL;
  GW.resetConfig();
}

const GW = loadLib("lib/googleWallet.js", SOURCES.GW);
const CPG = loadLib("lib/cardPage.js", SOURCES.CP);
const LP = loadLib("lib/legalPages.js", SOURCES.LP);
const YDATA = require(path.join(REPO, "lib/yourData.js"));
const jwtLib = require("jsonwebtoken");
const LOGS = [];
GW.deps.log = line => { LOGS.push(String(line)); };
let JSDOM = null, VirtualConsole = null;
try { ({ JSDOM, VirtualConsole } = require("jsdom")); } catch (e) { JSDOM = null; }

/* bf-card.js, the frontend's one rule for QR, mailto and tel */
const BF = (() => { const w = {}; vm.runInNewContext(FE("scripts/bf-card.js"), { window: w, self: w, URL, Blob: function () {}, FileReader: function () {}, fetch: () => Promise.reject(new Error("no")) }); return w.bfCard || {}; })();

/* ── the fake database ────────────────────────────────────────────────────── */
function fakeDb(seed) {
  const db = { t: clone(seed), writes: [], rpcs: [], reads: [], throwOn: null };
  const rows = n => db.t[n] || (db.t[n] = []);
  function project(r, cols) {
    if (!cols || cols.trim() === "*") return clone(r);
    const o = {}; cols.split(",").map(c => c.trim()).filter(Boolean).forEach(c => { o[c] = r[c] === undefined ? null : r[c]; }); return o;
  }
  function from(table) {
    const q = { table, cols: "*", filters: [], single: false };
    const run = () => {
      db.reads.push({ table, filters: clone(q.filters) });
      if (db.throwOn && db.throwOn(table, q.filters)) return Promise.reject(Object.assign(new Error("read failed"), { code: "XX000" }));
      const hit = rows(table).filter(r => q.filters.every(f => f[0] === "eq" ? r[f[1]] === f[2] : f[0] === "gte" ? String(r[f[1]]) >= String(f[2]) : true)).map(r => project(r, q.cols));
      if (q.single) return Promise.resolve(hit.length > 1 ? { data: null, error: { code: "PGRST116" } } : { data: hit[0] || null, error: null });
      return Promise.resolve({ data: hit, error: null });
    };
    const write = op => function () { db.writes.push({ table, op }); return b; };
    const b = {
      select(c) { q.cols = c || "*"; return b; },
      eq(c, v) { q.filters.push(["eq", c, v]); return b; },
      gte(c, v) { q.filters.push(["gte", c, v]); return b; },
      order() { return b; }, limit() { return b; }, not() { return b; },
      insert: write("insert"), update: write("update"), upsert: write("upsert"), delete: write("delete"),
      maybeSingle() { q.single = true; return run(); },
      single() { q.single = true; return run(); },
      then(res, rej) { return run().then(res, rej); }
    };
    return b;
  }
  db.client = { from, rpc: (fn, args) => { db.rpcs.push({ fn, args: clone(args) }); return Promise.resolve({ data: null, error: null }); } };
  return db;
}

/* ── server.js, lifted ────────────────────────────────────────────────────── */
const SPANS = [];
{
  const re = /^(?:(?:async )?function [A-Za-z_$][A-Za-z0-9_$]*[(]|app[.][a-z]+[(])/gm; let m;
  while ((m = re.exec(SRC))) { const end = s.braceMatch(SRC, SRC.indexOf("{", m.index)); if (end > 0) SPANS.push([m.index, end]); }
}
const FN_AT = new Map(), DECL_AT = new Map();
{
  let m;
  const fre = /^(?:async )?function ([A-Za-z_$][A-Za-z0-9_$]*)\(/gm;
  while ((m = fre.exec(SRC))) if (!FN_AT.has(m[1])) FN_AT.set(m[1], m.index);
  const dre = /^(?:var|const|let) ([A-Za-z_$][A-Za-z0-9_$]*)[ \t]*=[ \t]*/gm;
  while ((m = dre.exec(SRC))) {
    const at = m.index;
    if (!DECL_AT.has(m[1]) && !SPANS.some(([x, y]) => at > x && at < y)) DECL_AT.set(m[1], { index: at, length: m[0].length });
  }
}
function definitionOf(name) {
  if (FN_AT.has(name)) { const at = FN_AT.get(name); return SRC.slice(at, s.braceMatch(SRC, SRC.indexOf(") {", at) + 2)); }
  const d = DECL_AT.get(name);
  if (!d) return null;
  const brk = /;\n/g; brk.lastIndex = d.index + d.length;
  let b;
  while ((b = brk.exec(SRC))) {
    const next = SRC[b.index + b[0].length];
    if (next === undefined || next === "\n" || /[^\s]/.test(next)) return SRC.slice(d.index, b.index + 1);
  }
  return null;
}
const STUBS = new Set(["supabase", "nowIso", "console", "process", "require", "module", "app", "Buffer", "setTimeout", "fetch", "Date",
  "requireAuth", "requireActiveSubscription", "rateLimit", "ownerPagePublic", "publicSupportLinks", "getUserPlan", "anthropic", "Anthropic"]);
const uncommented = code => code.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
function closureParts(root) {
  const have = new Map();
  const queue = [...new Set(uncommented(root).match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || STUBS.has(name)) continue;
    const def = definitionOf(name);
    if (!def) continue;
    try { new vm.Script(def); } catch (e) { continue; }
    have.set(name, def);
    new Set(uncommented(def).match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !STUBS.has(id)) queue.push(id); });
  }
  return have;
}
function routeText(method, route) {
  const sig = "app." + method + "(\"" + route + "\"";
  const start = SRC.indexOf(sig);
  if (start < 0) throw new Error(method.toUpperCase() + " " + route + " not found");
  if (SRC.indexOf(sig, start + 1) !== -1) throw new Error(method.toUpperCase() + " " + route + " is defined twice");
  const open = SRC.indexOf("{", SRC.indexOf("async function (req, res", start));
  const end = s.braceMatch(SRC, open);
  if (SRC.slice(end, end + 2) !== ");") throw new Error(method.toUpperCase() + " " + route + " did not end where expected");
  return SRC.slice(start, end + 2);
}
const R = {
  wallet: ["get", "/api/cards/google-wallet"], share: ["get", "/api/cards/share/:token"], slug: ["get", "/api/cards/slug/:slug"],
  tap: ["post", "/api/cards/tap"], stats: ["get", "/api/digital-cards/:id/stats"]
};
let LIFTED, WALLET_ROUTE;
try {
  WALLET_ROUTE = routeText("get", "/api/cards/google-wallet");
  const root = Object.keys(R).map(k => routeText(R[k][0], R[k][1])).join("\n\n");
  LIFTED = [...closureParts(root).values()].sort((x, y) => SRC.indexOf(x) - SRC.indexOf(y)).join("\n\n") + "\n\n" + root;
} catch (e) {
  console.log("    FAIL  the routes could not be lifted from server.js: " + e.message);
  process.exit(1);
}

const NOW = Date.parse("2026-11-06T12:00:00.000Z");
function FakeDate() {
  const a = [].slice.call(arguments);
  return a.length ? new (Function.prototype.bind.apply(Date, [null].concat(a)))() : new Date(NOW);
}
FakeDate.now = () => NOW; FakeDate.parse = Date.parse; FakeDate.UTC = Date.UTC; FakeDate.prototype = Date.prototype;

const ALICE = "aaaaaaaa-0000-4000-8000-000000000001", BOB = "bbbbbbbb-0000-4000-8000-000000000002", CARL = "cccccccc-0000-4000-8000-000000000003";
const PUBLIC = new Set([ALICE]);
const CID = { jane: "11111111-1111-4111-8111-111111111111", hidden: "22222222-2222-4222-8222-222222222222", foreign: "33333333-3333-4333-8333-333333333333",
  lapsed: "44444444-4444-4444-8444-444444444444", thrower: "55555555-5555-4555-8555-555555555555", tok: "66666666-6666-4666-8666-666666666666",
  long: "77777777-7777-4777-8777-777777777777", nopic: "88888888-8888-4888-8888-888888888888" };
const TOK = { jane: "0123456789abcdef0123456789abcdef", tok: "fedcba9876543210fedcba9876543210", lapsed: "aaaabbbbccccddddeeeeffff00001111" };
const AVATAR = PUB + "avatars/" + ALICE + "/1730000000000_me.jpg";
const PRIV = { email: "jane+bftest@example.com", phone: "+1 (555) 010-2000" };
function card(id, over) {
  return Object.assign({ id: id, user_id: ALICE, slug: null, share_token: null, full_name: "Jane Doe", job_title: "Founder", company: "Doe Works", website: "https://jane.example.com",
    email: PRIV.email, phone: PRIV.phone, show_email: true, show_phone: true, show_photo: true, theme: "midnight", video_url: null, bg_image_url: null, still_image_url: null,
    audio_url: null, holographic_style: false, media_layout: {}, lead_form_on: false, discoverable: false }, over || {});
}
function seed() {
  return {
    digital_cards: [
      card(CID.jane, { slug: "jane-doe", share_token: TOK.jane }),
      card(CID.hidden, { slug: "hidden-card", show_email: false, show_phone: false, show_photo: null, theme: "neon" }),
      card(CID.foreign, { slug: "foreign-photo", user_id: CARL, theme: "forest" }),
      card(CID.lapsed, { slug: "lapsed-card", user_id: BOB, share_token: TOK.lapsed }),
      card(CID.thrower, { slug: "thrower-card", user_id: "99999999-9999-4999-8999-999999999999" }),
      card(CID.tok, { share_token: TOK.tok, theme: "ember", full_name: "Tok Owner", job_title: "", company: "", website: "", email: "", phone: "" }),
      card(CID.long, { slug: "long-card", full_name: "N".repeat(150), job_title: "T".repeat(150), company: "C".repeat(300), website: "not a url" }),
      card(CID.nopic, { slug: "no-photo", show_photo: false, theme: "dark" })
    ],
    bf_profiles: [{ user_id: ALICE, avatar_url: AVATAR }, { user_id: CARL, avatar_url: "https://cdn.example.net/me.jpg" }],
    card_view_counts: [{ card_id: CID.jane, day: "2026-11-06", views: 5, qr_views: 1, tel_taps: 1, email_taps: 0, save_taps: 2, support_taps: 0, wallet_taps: 3 },
      { card_id: CID.jane, day: "2026-10-20", views: 1, qr_views: 0, tel_taps: 0, email_taps: 0, save_taps: 0, support_taps: 0, wallet_taps: 4 }]
  };
}
PUBLIC.add(CARL);
const BROWSER_UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/130.0 Mobile Safari/537.36";
function build(db) {
  const ctx = {
    supabase: db.client, Date: FakeDate, JSON, Math, Promise, Number, Object, Array, String, Buffer, RegExp, Error, TypeError, Set, Map, URL, URLSearchParams, encodeURIComponent,
    nowIso: () => new Date(NOW).toISOString(),
    process: { env: { JWT_SECRET: JWT_SECRET, SUPABASE_URL: SUPABASE_URL } },
    require: p => p === "./lib/googleWallet" ? GW : p === "./lib/cardPage" ? CPG : p === "./lib/legalPages" ? LP : require(p.indexOf("./") === 0 ? path.join(REPO, p) : p),
    fetch: async (u) => { NETWORK.push("fetch " + u); throw new Error("no network"); },
    console: { log: (...a) => LOGS.push(a.join(" ")), error: (...a) => LOGS.push(a.join(" ")), warn: (...a) => LOGS.push(a.join(" ")), info: (...a) => LOGS.push(a.join(" ")) },
    setTimeout, clearTimeout, setImmediate,
    requireAuth: function requireAuth() {}, requireActiveSubscription: function requireActiveSubscription() {},
    rateLimit: function (o) { const f = function limiter() {}; f.opts = o; return f; },
    ownerPagePublic: async function (uid) { if (uid === "99999999-9999-4999-8999-999999999999") throw new Error("plan lookup down"); return PUBLIC.has(uid); },
    publicSupportLinks: async function () { return []; }
  };
  const routes = {};
  const mount = method => function (p) { routes[method + " " + p] = { handler: arguments[arguments.length - 1], middleware: [].slice.call(arguments, 1, -1) }; };
  ctx.app = { get: mount("get"), post: mount("post"), put: mount("put"), delete: mount("delete"), patch: mount("patch") };
  vm.createContext(ctx);
  vm.runInContext(LIFTED, ctx);
  async function hit(key, opts) {
    opts = opts || {};
    const [method, route] = R[key];
    const res = { code: 200, body: null, headers: {}, location: null, ended: false,
      status(x) { this.code = x; return this; }, json(x) { this.body = clone(x); return this; }, send(x) { this.body = x; return this; },
      end() { this.ended = true; return this; },
      set(k, v) { if (typeof k === "object") Object.keys(k).forEach(n => { this.headers[n.toLowerCase()] = k[n]; }); else this.headers[String(k).toLowerCase()] = v; return this; },
      redirect(a, b) { this.code = typeof a === "number" ? a : 302; this.location = typeof a === "number" ? b : a; return this; } };
    const req = { method: method.toUpperCase(), headers: { "user-agent": opts.ua === undefined ? BROWSER_UA : opts.ua }, query: opts.query || {}, params: opts.params || {},
      body: opts.body, user: opts.user ? { id: opts.user, role: "user" } : undefined };
    await routes[method + " " + route].handler(req, res, e => { res.error = e; res.code = 500; res.body = { error: "internal" }; });
    return res;
  }
  return { ctx, routes, hit, db };
}
const jwtOf = loc => String(loc || "").slice(GW.SAVE_URL.length);
function verified(token) {
  try { return { claims: jwtLib.verify(token, crypto.createPublicKey(RSA.publicKey), { algorithms: ["RS256"] }), header: jwtLib.decode(token, { complete: true }).header }; }
  catch (e) { return { error: e.name + ": " + e.message }; }
}

(async function main() {
  /* ════ A. configuration ════ */
  console.log("\n══ A. configuration ══");
  const loads = {
    ok: GW.loadConfig(ENV_OK),
    realNl: GW.loadConfig(Object.assign({}, ENV_OK, { GOOGLE_WALLET_SA_KEY: RSA.privateKey })),
    missing: GW.loadConfig({ JWT_SECRET: JWT_SECRET }),
    noIssuer: GW.loadConfig(Object.assign({}, ENV_OK, { GOOGLE_WALLET_ISSUER_ID: "" })),
    shortIssuer: GW.loadConfig(Object.assign({}, ENV_OK, { GOOGLE_WALLET_ISSUER_ID: "123456789" })),
    alphaIssuer: GW.loadConfig(Object.assign({}, ENV_OK, { GOOGLE_WALLET_ISSUER_ID: "12345678901x" })),
    longIssuer: GW.loadConfig(Object.assign({}, ENV_OK, { GOOGLE_WALLET_ISSUER_ID: "1".repeat(26) })),
    gmail: GW.loadConfig(Object.assign({}, ENV_OK, { GOOGLE_WALLET_SA_EMAIL: "someone+bftest@example.com" })),
    longEmail: GW.loadConfig(Object.assign({}, ENV_OK, { GOOGLE_WALLET_SA_EMAIL: "a".repeat(240) + "@x.iam.gserviceaccount.com" })),
    noAt: GW.loadConfig(Object.assign({}, ENV_OK, { GOOGLE_WALLET_SA_EMAIL: "x.iam.gserviceaccount.com" })),
    ec: GW.loadConfig(Object.assign({}, ENV_OK, { GOOGLE_WALLET_SA_KEY: EC.privateKey })),
    garbage: GW.loadConfig(Object.assign({}, ENV_OK, { GOOGLE_WALLET_SA_KEY: "-----BEGIN PRIVATE KEY-----" + BS + "nnot a key" + BS + "n-----END PRIVATE KEY-----" })),
    rsaOld: GW.loadConfig(Object.assign({}, ENV_OK, { GOOGLE_WALLET_SA_KEY: "-----BEGIN RSA PRIVATE KEY-----" + BS + "nabc" })),
    noKey: GW.loadConfig(Object.assign({}, ENV_OK, { GOOGLE_WALLET_SA_KEY: "" })),
    noJwt: GW.loadConfig(Object.assign({}, ENV_OK, { JWT_SECRET: "" }))
  };
  const cfgOk = loads.ok.config || {};
  check("A1. a key pasted with literal \\n (as the JSON key file writes it) is read: issuer, email, an RSA key object, the class id",
    !!loads.ok.config && cfgOk.issuerId === ISSUER && cfgOk.saEmail === SA_EMAIL && cfgOk.key && cfgOk.key.asymmetricKeyType === "rsa" && cfgOk.classId === ISSUER + ".bizforce_card_v1" &&
    cfgOk.photoPrefix === PUB, J(loads.ok.error));
  check("A2. a key with real newlines is read too", !!loads.realNl.config && loads.realNl.config.key.asymmetricKeyType === "rsa", J(loads.realNl.error));
  check("A3. nothing set: not configured (missing)", loads.missing.error === "missing" && !loads.missing.config);
  check("A4. the issuer must be 10 to 25 digits", ["noIssuer", "shortIssuer", "alphaIssuer", "longIssuer"].every(k => loads[k].error === "issuer_id"),
    J(["noIssuer", "shortIssuer", "alphaIssuer", "longIssuer"].map(k => loads[k].error)));
  check("A5. the email must be a service account address of at most 254 characters", ["gmail", "longEmail", "noAt"].every(k => loads[k].error === "sa_email"),
    J(["gmail", "longEmail", "noAt"].map(k => loads[k].error)));
  check("A6. a non-RSA key (P-256), an unreadable PEM, a PKCS#1 header and no key: not configured, each with its code",
    loads.ec.error === "sa_key_type" && loads.garbage.error === "sa_key_unreadable" && loads.rsaOld.error === "sa_key_format" && loads.noKey.error === "sa_key_format",
    J([loads.ec.error, loads.garbage.error, loads.rsaOld.error, loads.noKey.error]));
  check("A7. without JWT_SECRET there are no object ids, so it is not configured", loads.noJwt.error === "jwt_secret", J(loads.noJwt.error));
  check("A8. no answer holds the key, and nothing is logged while loading", Object.keys(loads).every(k => !holdsSecret(J(loads[k].error || ""))) && !holdsSecret(LOGS.join("\n")) &&
    LOGS.length === 0, LOGS.length);
  configure(false);
  const c0 = GW.config(), c0b = GW.config();
  check("A9. config(): read once from process.env, null when not configured, logged once with a code only",
    c0 === null && c0b === null && LOGS.filter(l => /^\[google-wallet\] not configured: missing$/.test(l)).length === 1 && !holdsSecret(LOGS.join("\n")), J(LOGS));
  process.env.GOOGLE_WALLET_SA_KEY = KEY_LITERAL_NL; process.env.GOOGLE_WALLET_ISSUER_ID = "nope"; process.env.GOOGLE_WALLET_SA_EMAIL = SA_EMAIL;
  GW.resetConfig(); LOGS.length = 0;
  const cBad = GW.config();
  check("A10. a bad value is not configured, never a throw, and the log names the code, not the value", cBad === null && J(LOGS) === J(["[google-wallet] not configured: issuer_id"]) && !holdsSecret(LOGS.join("")), J(LOGS));
  configure(true); LOGS.length = 0;
  check("A11. configured from process.env: the same issuer and class", !!GW.config() && GW.config().classId === ISSUER + ".bizforce_card_v1" && GW.config() === GW.config() && LOGS.length === 0);
  check("A12. the RS256 key is never handed to jwt.verify: server.js verifies only with JWT_SECRET, once, and lib/googleWallet.js never verifies",
    (SRC.match(/jwt\.verify\(/g) || []).length === 1 && SRC.indexOf("jwt.verify(token, process.env.JWT_SECRET)") !== -1 && !/verify\(/.test(SOURCES.GW) &&
    !/GOOGLE_WALLET_SA_KEY/.test(SRC));

  /* ════ B. the routes ════ */
  console.log("\n══ B. the routes ══");
  configure(false);
  let db = fakeDb(seed()), app = build(db);
  let r = await app.hit("wallet", { query: { ref: "jane-doe" } });
  const readsAfter503 = db.reads.length;
  const shareOff = await app.hit("share", { params: { token: TOK.jane } }), slugOff = await app.hit("slug", { params: { slug: "jane-doe" } });
  check("B1. not configured: 503 \"Google Wallet isn't set up yet.\", no-store, nothing read", r.code === 503 && J(r.body) === J({ error: "Google Wallet isn't set up yet." }) &&
    r.headers["cache-control"] === "no-store" && readsAfter503 === 0, J([r.code, r.body]));
  check("B2. not configured: the card JSON (share and slug) has no google_wallet at all", shareOff.code === 200 && slugOff.code === 200 &&
    !("google_wallet" in shareOff.body.card) && !("google_wallet" in slugOff.body.card), J(Object.keys(shareOff.body.card || {})));
  configure(true);
  db = fakeDb(seed()); app = build(db);
  const shareOn = await app.hit("share", { params: { token: TOK.jane } }), slugOn = await app.hit("slug", { params: { slug: "jane-doe" } });
  const offKeys = Object.keys(shareOff.body.card).sort(), onKeys = Object.keys(shareOn.body.card).sort();
  check("B3. configured: the card JSON gains google_wallet: true and nothing else", shareOn.body.card.google_wallet === true && slugOn.body.card.google_wallet === true &&
    J(onKeys) === J(offKeys.concat(["google_wallet"]).sort()), J(onKeys));
  const bad = [], readsBefore = db.reads.length;
  for (const ref of ["", "Jane-Doe", "a", "../x", "jane--doe", "A".repeat(32), "x".repeat(41)]) bad.push((await app.hit("wallet", { query: { ref: ref } })).code);
  bad.push((await app.hit("wallet", { query: {} })).code, (await app.hit("wallet", { query: { ref: ["jane-doe"] } })).code);
  check("B4. a ref that is not a slug or a share token: 400, nothing read", bad.every(x => x === 400) && db.reads.length === readsBefore, J(bad));
  db = fakeDb(seed()); app = build(db); LOGS.length = 0;
  const missing = await app.hit("wallet", { query: { ref: "no-such-card" } }), lapsed = await app.hit("wallet", { query: { ref: "lapsed-card" } }),
    lapsedTok = await app.hit("wallet", { query: { ref: TOK.lapsed } }), thrower = await app.hit("wallet", { query: { ref: "thrower-card" } });
  db.throwOn = (t) => t === "digital_cards";
  const readThrow = await app.hit("wallet", { query: { ref: "jane-doe" } });
  db.throwOn = null;
  const nf = x => x.code === 404 && J(x.body) === J({ error: "Card not found" }) && x.location === null && x.headers["cache-control"] === "no-store";
  check("B5. a missing card, a lapsed owner (by slug and by token), a plan lookup that throws and a card read that throws: 404 \"Card not found\", no link",
    [missing, lapsed, lapsedTok, thrower, readThrow].every(nf), J([missing, lapsed, lapsedTok, thrower, readThrow].map(x => [x.code, x.location ? "link" : null])));
  check("B6. a failed read logs only a code", LOGS.some(l => l === "[google-wallet] no pass: XX000") && !LOGS.some(l => /read failed|plan lookup down/.test(l)), J(LOGS));
  db = fakeDb(seed()); app = build(db);
  const ok = await app.hit("wallet", { query: { ref: "jane-doe" } });
  const okTok = await app.hit("wallet", { query: { ref: TOK.tok } });
  const T1 = secret(jwtOf(ok.location)), T2 = secret(jwtOf(okTok.location));
  check("B7. a public card: 302 to https://pay.google.com/gp/v/save/<JWT>, Cache-Control: no-store; by slug and by share token",
    ok.code === 302 && String(ok.location).indexOf("https://pay.google.com/gp/v/save/") === 0 && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(T1) &&
    ok.headers["cache-control"] === "no-store" && okTok.code === 302 && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(T2), J([ok.code, ok.headers["cache-control"], okTok.code]));
  check("B8. the route writes nothing: no insert, update, upsert, delete or rpc", db.writes.length === 0 && db.rpcs.length === 0, J([db.writes, db.rpcs]));
  const mw = (app.routes["get /api/cards/google-wallet"] || { middleware: [] }).middleware;
  const lim = mw.find(f => f.name === "limiter") || { opts: {} };
  check("B9. the route is public, behind cardPageLimiter (120 per 10 minutes)", mw.length === 1 && lim.opts.max === 120 && lim.opts.windowMs === 600000 &&
    WALLET_ROUTE.indexOf("app.get(\"/api/cards/google-wallet\", cardPageLimiter, async function (req, res) {") === 0);
  check("B10. the owner check is the serve guard, after the read, before the card's fields", /const walletRow = await cardRowFor\([\s\S]*?if \(!\(await ownerPagePublic\(walletRow\.user_id\)\)\) return res\.status\(404\)[\s\S]*?publicCardFrom\(walletRow, await cardOwnerPhoto\(walletRow\)\)/.test(WALLET_ROUTE));

  /* ════ C. the JWT ════ */
  console.log("\n══ C. the JWT ══");
  const v1 = verified(T1), v2 = verified(T2);
  const cl = v1.claims || {};
  check("C1. it verifies with the test public key under RS256 only, header alg RS256", !!v1.claims && v1.header.alg === "RS256" && !!v2.claims, v1.error);
  check("C2. the claims are iss, aud google, typ savetowallet, iat now, origins [https://bizforceai.net], payload; nothing else",
    J(Object.keys(cl).sort()) === J(["aud", "iat", "iss", "origins", "payload", "typ"]) && cl.iss === SA_EMAIL && cl.aud === "google" && cl.typ === "savetowallet" &&
    cl.iat === Math.floor(NOW / 1000) && J(cl.origins) === J(["https://bizforceai.net"]), J(Object.keys(cl)));
  const pl = cl.payload || {}, obj = (pl.genericObjects || [])[0] || {};
  check("C3. the payload is one shared class <issuer>.bizforce_card_v1 and one object of it", J(Object.keys(pl).sort()) === J(["genericClasses", "genericObjects"]) &&
    J(pl.genericClasses) === J([{ id: ISSUER + ".bizforce_card_v1" }]) && pl.genericObjects.length === 1 && obj.classId === ISSUER + ".bizforce_card_v1" && obj.state === "ACTIVE");
  const hk = Buffer.from(crypto.hkdfSync("sha256", JWT_SECRET, Buffer.alloc(0), "bizforce-wallet-object-v1", 32));
  const expectId = ISSUER + ".c" + crypto.createHmac("sha256", hk).update(CID.jane).digest("hex").slice(0, 32);
  const again = verified(secret(jwtOf((await app.hit("wallet", { query: { ref: "jane-doe" } })).location)));
  const otherId = (((verified(T2).claims || {}).payload || {}).genericObjects || [{}])[0].id;
  check("C4. the object id is <issuer>.c + 32 hex of HMAC-SHA256(HKDF(JWT_SECRET), card id): stable for a card, different for another",
    obj.id === expectId && /^3388000000012345678\.c[0-9a-f]{32}$/.test(obj.id) && ((again.claims || {}).payload || { genericObjects: [{}] }).genericObjects[0].id === obj.id &&
    otherId && otherId !== obj.id, J([obj.id === expectId, otherId !== obj.id]));
  const bareIds = [CID.jane, CID.jane.replace(/-/g, ""), TOK.jane, "jane-doe", ALICE, ALICE.replace(/-/g, "")];
  // The owner's photo URL is public already (the card page serves it), and its bf-public path names the owner; it is left out here.
  const clNoPhoto = J(cl).split(AVATAR).join("");
  check("C5. no BizForce id is in the JWT apart from the public photo URL: not the card id, its share token, or the owner's id",
    bareIds.slice(0, 3).concat(bareIds.slice(4)).every(x => clNoPhoto.indexOf(x) === -1) && obj.id.indexOf(CID.jane.slice(0, 8)) === -1);
  check("C6. the link holds the JWT only, and neither the link nor any log line holds the key", !holdsSecret(String(ok.location).replace(T1, "")) &&
    !keyLines(RSA.privateKey).some(l => LOGS.join("\n").indexOf(l) !== -1));

  /* ════ D. the pass ════ */
  console.log("\n══ D. the pass ══");
  check("D1. the card title, the header (name), the subheader (title), the colour for midnight",
    J(obj.cardTitle) === J({ defaultValue: { language: "en-US", value: "BizForceAI Card" } }) && J(obj.header) === J({ defaultValue: { language: "en-US", value: "Jane Doe" } }) &&
    J(obj.subheader) === J({ defaultValue: { language: "en-US", value: "Founder" } }) && obj.hexBackgroundColor === "#1a1040", J([obj.header, obj.hexBackgroundColor]));
  check("D2. the photo is the owner's bf-public photo when the card shows it", J(obj.logo) === J({ sourceUri: { uri: AVATAR }, contentDescription: { defaultValue: { language: "en-US", value: "Photo" } } }), J(obj.logo));
  check("D3. the QR is the card's public URL with via=qr, exactly bf-card.js qrUrl", J(obj.barcode) === J({ type: "QR_CODE", value: "https://bizforceai.net/c/jane-doe?via=qr" }) &&
    obj.barcode.value === BF.qrUrl("https://bizforceai.net/c/jane-doe"), J(obj.barcode));
  check("D4. Company, Email, Phone and Website, in that order, with fixed ids",
    J(obj.textModulesData) === J([{ id: "company", header: "Company", body: "Doe Works" }, { id: "email", header: "Email", body: PRIV.email }, { id: "phone", header: "Phone", body: PRIV.phone },
      { id: "website", header: "Website", body: "https://jane.example.com" }]), J((obj.textModulesData || []).map(t => t.id)));
  check("D5. links: Open card, the website, mailto: and tel: built as bf-card.js builds them",
    J(obj.linksModuleData) === J({ uris: [{ id: "card", uri: "https://bizforceai.net/c/jane-doe", description: "Open card" }, { id: "website", uri: "https://jane.example.com", description: "Website" },
      { id: "email", uri: BF.mailtoHref(PRIV.email), description: "Email" }, { id: "phone", uri: BF.telHref(PRIV.phone), description: "Call" }] }), J(obj.linksModuleData));
  async function passFor(ref) { const x = await app.hit("wallet", { query: { ref: ref } }); const t = secret(jwtOf(x.location)); const v = verified(t); return { res: x, obj: ((v.claims || {}).payload || { genericObjects: [{}] }).genericObjects[0], text: t ? J(v.claims || {}) : "" }; }
  const hid = await passFor("hidden-card");
  check("D6. a hidden email and phone are nowhere in the pass (no text, no link), and an unknown theme is dark",
    hid.res.code === 302 && hid.text.indexOf(PRIV.email) === -1 && hid.text.indexOf("555") === -1 && hid.text.indexOf("mailto:") === -1 && hid.text.indexOf("tel:") === -1 &&
    J((hid.obj.textModulesData || []).map(t => t.id)) === J(["company", "website"]) && hid.obj.hexBackgroundColor === "#0c1228", J((hid.obj.textModulesData || []).map(t => t.id)));
  check("D7. a photo the page would show (show_photo absent) is not in the pass: the logo instead",
    J(hid.obj.logo) === J({ sourceUri: { uri: "https://bizforceai.net/icons/icon-512.png" }, contentDescription: { defaultValue: { language: "en-US", value: "BizForceAI logo" } } }), J(hid.obj.logo));
  const foreign = await passFor("foreign-photo"), nopic = await passFor("no-photo");
  check("D8. a shown photo on another host, and a hidden photo: the logo; forest is #0a1f14, dark #0c1228",
    foreign.obj.logo && foreign.obj.logo.sourceUri.uri === GW.LOGO_URL && nopic.obj.logo && nopic.obj.logo.sourceUri.uri === GW.LOGO_URL && foreign.text.indexOf("cdn.example.net") === -1 &&
    foreign.obj.hexBackgroundColor === "#0a1f14" && nopic.obj.hexBackgroundColor === "#0c1228", J([foreign.obj.logo, nopic.obj.logo]));
  const tokPass = verified(T2).claims.payload.genericObjects[0];
  check("D9. a token card with nothing but a name: no subheader, no text modules, Open card only, ember is #220e06, the QR is its /card/ link",
    !("subheader" in tokPass) && !("textModulesData" in tokPass) && J(tokPass.linksModuleData) === J({ uris: [{ id: "card", uri: "https://bizforceai.net/card/" + TOK.tok, description: "Open card" }] }) &&
    tokPass.hexBackgroundColor === "#220e06" && tokPass.barcode.value === BF.qrUrl("https://bizforceai.net/card/" + TOK.tok), J(Object.keys(tokPass)));
  const lng = await passFor("long-card");
  check("D10. the caps: header and subheader at most 100 characters, text modules at most 200; a website that is not a URL is text only",
    lng.obj.header.defaultValue.value === "N".repeat(100) && lng.obj.subheader.defaultValue.value === "T".repeat(100) &&
    lng.obj.textModulesData.find(t => t.id === "company").body === "C".repeat(200) && !lng.obj.linksModuleData.uris.some(u => u.id === "website") &&
    lng.obj.textModulesData.find(t => t.id === "website").body === "not a url", J([lng.obj.header.defaultValue.value.length, lng.obj.textModulesData.find(t => t.id === "company").body.length]));
  check("D11. the theme colours are the four card backgrounds of card-view.html", J(GW.THEME_HEX) === J({ dark: "#0c1228", midnight: "#1a1040", forest: "#0a1f14", ember: "#220e06" }) &&
    ["dark", "midnight", "forest", "ember"].every(t => new RegExp("#cardPreview\\[data-theme=\"" + t + "\"\\]\\s*\\{background:linear-gradient\\(160deg," + GW.THEME_HEX[t] + " 0%").test(FE("card-view.html"))));
  const QR_IN = ["https://bizforceai.net/c/a-b", "https://bizforceai.net/card/" + TOK.jane, "https://x.example/p?q=1", "", null];
  const MAIL_IN = [PRIV.email, " a@b.co ", "no-at", "a@b", "<a@b.co>", "", null, "a b@c.de"];
  const TEL_IN = [PRIV.phone, "12", "+44 20 7946 0000", "(555) 123", "", null, "abc123"];
  check("D12. the server's qrValue, mailtoHref and telHref equal bf-card.js qrUrl, mailtoHref and telHref on every case",
    typeof BF.qrUrl === "function" && QR_IN.every(x => GW.qrValue(x) === BF.qrUrl(x)) && MAIL_IN.every(x => GW.mailtoHref(x) === BF.mailtoHref(x)) && TEL_IN.every(x => GW.telHref(x) === BF.telHref(x)));
  check("D13. the pass has no BizForce id, no share token as a field, and nothing publicCardFrom does not serve",
    !/user_id|share_token|lead_form|form_token|media_layout|holographic/.test(J(obj)) && J(Object.keys(obj).sort()) ===
    J(["barcode", "cardTitle", "classId", "header", "hexBackgroundColor", "id", "linksModuleData", "logo", "state", "subheader", "textModulesData"]));

  /* ════ E. counting ════ */
  console.log("\n══ E. counting ══");
  db = fakeDb(seed()); app = build(db);
  const tp = await app.hit("tap", { body: { ref: "jane-doe", kind: "wallet" } });
  const tpTok = await app.hit("tap", { body: J({ ref: TOK.jane, kind: "wallet" }) });
  check("E1. POST /api/cards/tap takes kind wallet: 204 and one bump_card_count of wallet_taps, by slug and by token",
    tp.code === 204 && tpTok.code === 204 && J(db.rpcs) === J([{ fn: "bump_card_count", args: { p_card: CID.jane, p_kind: "wallet_taps" } }, { fn: "bump_card_count", args: { p_card: CID.jane, p_kind: "wallet_taps" } }]), J([tp.code, db.rpcs]));
  check("E2. the kinds: TAP_KINDS wallet -> wallet_taps, COUNT_KINDS ends with wallet_taps", CPG.TAP_KINDS.wallet === "wallet_taps" && CPG.tapColumn("wallet") === "wallet_taps" &&
    J(CPG.COUNT_KINDS) === J(["views", "qr_views", "tel_taps", "email_taps", "save_taps", "support_taps", "wallet_taps"]));
  const st = await app.hit("stats", { params: { id: CID.jane }, user: ALICE });
  const day0 = (st.body && st.body.days || []).find(d => d.day === "2026-11-06") || {};
  check("E3. the owner's stats carry wallet_taps in each day and in the 7- and 30-day totals", st.code === 200 && day0.wallet_taps === 3 &&
    st.body.totals.last_7_days.wallet_taps === 3 && st.body.totals.last_30_days.wallet_taps === 7 && st.body.days.every(d => typeof d.wallet_taps === "number"), J([st.code, day0, st.body && st.body.totals]));

  /* ════ F. the page ════ */
  console.log("\n══ F. card-view.html and the editor ══");
  const CV = FE("card-view.html");
  const fnOf = (text, nm) => { const a = text.indexOf("function " + nm + "("); if (a < 0) return ""; return text.slice(text.lastIndexOf("\n", a) + 1, s.braceMatch(text, text.indexOf("{", a))); };
  check("F1. the button: hidden, in #cardActions directly after Save Contact, plain text \"Add to Google Wallet\", no image, no Google host",
    CV.indexOf("      Save Contact\n    </button>\n    <button class=\"cv-btn cv-btn-wallet\" id=\"cvWalletBtn\" type=\"button\" hidden>Add to Google Wallet</button>\n") !== -1 &&
    CV.indexOf("#cvWalletBtn[hidden]{display:none}") !== -1 && !/pay\.google\.com|googleusercontent|wallet[^"]*\.(png|svg)/i.test(CV) && !/gstatic/.test(CV.replace(/fonts\.gstatic\.com/g, "")));
  const walletCode = fnOf(CV, "renderCardWallet");
  check("F2. its code writes no HTML (textContent only), and the page calls it after the lead form", walletCode.length > 200 && !/innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(walletCode) &&
    CV.indexOf("    renderCardLead(cardData);\n    renderCardWallet(cardData);\n") !== -1);
  check("F3. the click sends the wallet beacon, then goes to the route with the encoded ref, without waiting",
    walletCode.indexOf("    sendTap(\"wallet\");\n    window.location.assign(API_URL + \"/api/cards/google-wallet?ref=\" + encodeURIComponent(cardRef()));\n") !== -1);
  check("F4. the CSP is unchanged: no Google host in _headers", !/google\.com|gstatic/.test(FE("_headers").replace(/fonts\.googleapis\.com|fonts\.gstatic\.com/g, "")));
  if (!JSDOM) check("F5. jsdom loads", false, "jsdom is not installed");
  else {
    const stripScripts = h => h.replace(/<script\b[^>]*>[\s\S]*?<\/script>/g, "");
    const inlineMain = h => ([...String(h).matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]).find(t => t.indexOf("var API_URL") !== -1) || "");
    function view(opts) {
      const vc = new VirtualConsole();
      const dom = new JSDOM(stripScripts(CV), { url: opts.url || "https://bizforceai.net/c/jane-doe", runScripts: "outside-only", pretendToBeVisual: true, virtualConsole: vc });
      const w = dom.window, log = { order: [], beacons: [], errors: [] };
      Object.defineProperty(w.navigator, "userAgent", { value: opts.ua, configurable: true });
      Object.defineProperty(w.navigator, "sendBeacon", { value: function (u, b) { log.order.push("beacon"); log.beacons.push({ url: String(u), body: String(b) }); return true; }, configurable: true, writable: true });
      w.QRCode = { toCanvas(c, t, o, cb) { if (cb) cb(null); } };
      w.__nav = function (u) { log.order.push("nav " + String(u)); };
      w.fetch = function (u) {
        if (/\/api\/cards\/(slug|share)\//.test(String(u))) return Promise.resolve({ ok: true, json: async () => ({ card: opts.card, support_links: [] }) });
        return Promise.resolve({ ok: false, json: async () => ({}), blob: async () => ({ type: "", size: 0 }) });
      };
      const main = inlineMain(CV).split("window.location.assign(").join("window.__nav(");
      try { w.eval(FE("scripts/bf-card.js")); w.eval(main); } catch (e) { log.errors.push(e.message); }
      return { w, doc: w.document, log };
    }
    const shown = Object.assign({}, shareOn.body.card);
    const ANDROID = BROWSER_UA, IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1",
      DESKTOP = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36";
    const vNo = view({ ua: ANDROID, card: Object.assign({}, shareOff.body.card) }); await settle();
    const vIph = view({ ua: IPHONE, card: shown }); await settle();
    const vDesk = view({ ua: DESKTOP, card: shown }); await settle();
    check("F5. hidden without google_wallet, on an iPhone and on a desktop", [vNo, vIph, vDesk].every(v => v.doc.getElementById("cvWalletBtn").hidden === true && v.log.errors.length === 0),
      J([vNo, vIph, vDesk].map(v => [v.doc.getElementById("cvWalletBtn").hidden, v.log.errors])));
    const vAnd = view({ ua: ANDROID, card: shown }); await settle();
    const btn = vAnd.doc.getElementById("cvWalletBtn");
    check("F6. shown on Android when google_wallet is true, labelled \"Add to Google Wallet\"", btn.hidden === false && btn.textContent === "Add to Google Wallet" && vAnd.log.errors.length === 0, J(vAnd.log.errors));
    btn.click();
    const orderNow = vAnd.log.order.slice();
    check("F7. a click sends the wallet beacon first, then goes at once (not after the beacon) to the route with the slug",
      J(orderNow) === J(["beacon", "nav https://dynamic-prosperity-production-5382.up.railway.app/api/cards/google-wallet?ref=jane-doe"]) &&
      J(JSON.parse(vAnd.log.beacons[0].body)) === J({ ref: "jane-doe", kind: "wallet" }) && /\/api\/cards\/tap$/.test(vAnd.log.beacons[0].url), J(orderNow));
    const vTok = view({ ua: ANDROID, card: shown, url: "https://bizforceai.net/card/" + TOK.jane }); await settle();
    vTok.doc.getElementById("cvWalletBtn").click();
    check("F8. from a /card/<token> page the ref is the token, encoded", vTok.log.order[1] === "nav https://dynamic-prosperity-production-5382.up.railway.app/api/cards/google-wallet?ref=" + encodeURIComponent(TOK.jane),
      J(vTok.log.order));
    const evil = Object.assign({}, shown, { full_name: "<img src=x id=pwn>" });
    const vEvil = view({ ua: ANDROID, card: evil }); await settle();
    check("F9. a hostile name on a card with the button stays text", !vEvil.doc.getElementById("pwn") && vEvil.doc.getElementById("cvWalletBtn").hidden === false);
  }
  const BUILD = require(path.join(REPO, "scripts/buildCardShell.js"));
  const GEN = lf(fs.readFileSync(path.join(REPO, "lib/cardShell.generated.js"), "utf8"));
  check("F10. lib/cardShell.generated.js is what buildCardShell.js makes from card-view.html and _headers, and carries the button",
    BUILD.generate(CV, FE("_headers")) === GEN && GEN.indexOf("cvWalletBtn") !== -1);
  const DC = FE("digital-cards.html");
  const lineCode = fnOf(DC, "cardCountLine");
  const lineFn = vm.runInNewContext("(" + lineCode.replace(/^function cardCountLine/, "function") + ")", {});
  const line = lineFn({ views: 5, qr_views: 1, tel_taps: 1, email_taps: 0, save_taps: 2, support_taps: 0, wallet_taps: 3 });
  check("F11. the editor's totals and each day: \"... support opened, 3 added to Google Wallet\"",
    line === "5 opened (1 by QR code), 1 calls, 0 emails, 2 contacts saved, 0 support opened, 3 added to Google Wallet" && lineFn({}).slice(-24) === "0 added to Google Wallet" &&
    /totals\.textContent = "Last 7 days: " \+ cardCountLine\(s\.totals\.last_7_days\) \+ "\. Last 30 days: " \+ cardCountLine\(s\.totals\.last_30_days\) \+ "\.";/.test(DC) &&
    /li\.textContent = String\(d\.day \|\| ""\) \+ ": " \+ cardCountLine\(d\);/.test(DC), line);

  /* ════ G. legal, registries, README, the migration ════ */
  console.log("\n══ G. legal, registries, README, the migration ══");
  const SENT = "If a visitor chooses Add to Google Wallet on your card, BizForce sends Google the details your card shows publicly (your name, title, company, the email, phone and photo you chose to show, and the card's link) to make the pass; nothing goes to Google before they choose, and a saved pass stays in their Google Wallet under Google's terms, where BizForce cannot change it.";
  const escH = t => t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  const after = (h, a, b) => { const i = h.indexOf(escH(a)), j = h.indexOf(escH(b)); return i !== -1 && j > i && j - i - escH(a).length < 20; };
  const built = LP.buildLegalPages();
  check("G1. CARD_WALLET_PRIVACY_SENTENCE is word for word", LP.CARD_WALLET_PRIVACY_SENTENCE === SENT);
  check("G2. the Privacy Policy carries it directly after the card visits sentence, as built and on disk",
    after(built["privacy.html"], LP.CARD_VISITS_PRIVACY_SENTENCE, SENT) && after(FE("privacy.html"), LP.CARD_VISITS_PRIVACY_SENTENCE, SENT));
  const gw = YDATA.THIRD_PARTIES.find(t => t.name === "Google Wallet");
  check("G3. THIRD_PARTIES names Google Wallet word for word, and the Privacy Policy lists it",
    !!gw && gw.for === "making a pass of a digital card, when a visitor chooses Add to Google Wallet" &&
    built["privacy.html"].indexOf(escH("Google Wallet: making a pass of a digital card, when a visitor chooses Add to Google Wallet.")) !== -1 &&
    FE("privacy.html").indexOf(escH("Google Wallet: making a pass of a digital card, when a visitor chooses Add to Google Wallet.")) !== -1);
  const README = lf(fs.readFileSync(path.join(REPO, "README.md"), "utf8"));
  const rowOf = n => README.split("\n").find(l => l.indexOf("| `" + n + "` |") === 0) || "";
  const setup = (README.split("## Google Wallet setup")[1] || "").split("\n## ")[0];
  check("G4. README: a Google Wallet env table with the three variables; the key row says private_key, pasted whole, literal \\n accepted, never committed",
    README.indexOf("### Google Wallet\n\n| Variable | Default | Effect |\n|---|---|---|\n") !== -1 && WALLET_VARS.every(v => /^\| `[A-Z_]+` \| none \| .{20,} \|$/.test(rowOf(v))) &&
    /`private_key` from its JSON key file, pasted whole/.test(rowOf("GOOGLE_WALLET_SA_KEY")) && rowOf("GOOGLE_WALLET_SA_KEY").indexOf("a literal `" + BS + "n`") !== -1 &&
    /never commit it/.test(rowOf("GOOGLE_WALLET_SA_KEY")));
  check("G5. README: the setup section names the issuer ID, the service account and its JSON key, the issuer user, the origin and publishing access",
    /Google Pay and Wallet Console/.test(setup) && /service account with a JSON key/.test(setup) && /added as a user of the issuer/.test(setup) &&
    setup.indexOf("`https://bizforceai.net`") !== -1 && /Publishing access/.test(setup));
  const MIG = lf(fs.readFileSync(path.join(REPO, "supabase/migrations/174_card_wallet_count.sql"), "utf8"));
  const SQL_AS_RUN = [
    "ALTER TABLE public.card_view_counts",
    "  ADD COLUMN IF NOT EXISTS wallet_taps integer NOT NULL DEFAULT 0;",
    "",
    "ALTER TABLE public.card_view_counts",
    "  DROP CONSTRAINT card_view_counts_nonneg_check;",
    "",
    "ALTER TABLE public.card_view_counts",
    "  ADD CONSTRAINT card_view_counts_nonneg_check CHECK (views >= 0 AND qr_views >= 0 AND tel_taps >= 0 AND email_taps >= 0 AND save_taps >= 0 AND support_taps >= 0 AND wallet_taps >= 0);",
    "",
    "CREATE OR REPLACE FUNCTION public.bump_card_count(p_card uuid, p_kind text)",
    "RETURNS void",
    "LANGUAGE plpgsql",
    "SECURITY DEFINER",
    "SET search_path = public",
    "AS $$",
    "BEGIN",
    "  IF p_kind NOT IN ('views', 'qr_views', 'tel_taps', 'email_taps', 'save_taps', 'support_taps', 'wallet_taps') THEN",
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
    ""].join("\n");
  check("G6. migration 174: the owner's header, then the SQL as run, exactly", MIG === "-- Applied by the owner by hand in the Supabase SQL editor on Nov 6, 2026. This file is the text as run.\n\n" + SQL_AS_RUN,
    MIG.length);
  const kinds174 = ((/IF p_kind NOT IN \(([^)]*)\) THEN/.exec(MIG) || [])[1] || "").split(",").map(x => x.trim().replace(/'/g, ""));
  check("G7. the rpc's allowlist is COUNT_KINDS exactly, and the stats read every counter", J(kinds174) === J(CPG.COUNT_KINDS) &&
    SRC.indexOf("select(\"day, " + CPG.COUNT_KINDS.join(", ") + "\")") !== -1, J(kinds174));
  const migFiles = fs.readdirSync(path.join(REPO, "supabase/migrations")).filter(f => /^\d+_/.test(f));
  check("R1. 174_card_wallet_count.sql is the only migration numbered 174, and the highest (173 the last before it)",
    migFiles.filter(f => /^174_/.test(f)).length === 1 && migFiles.indexOf("174_card_wallet_count.sql") !== -1 && migFiles.every(f => Number(f.split("_")[0]) <= 174) && migFiles.some(f => /^173_/.test(f)));
  check("R2. the route is in checkDormantRoutesDeleted ADDED and checkUnsubscribedSurface's serve-gated list",
    fs.readFileSync(path.join(__dirname, "checkDormantRoutesDeleted.js"), "utf8").indexOf("[\"get\", \"/api/cards/google-wallet\"]") !== -1 &&
    fs.readFileSync(path.join(__dirname, "checkUnsubscribedSurface.js"), "utf8").indexOf("\"get /api/cards/google-wallet\":           SERVE_GUARD") !== -1);
  check("R3. no Google API is called: no googleapis or walletobjects host, and no fetch, in lib/googleWallet.js or the route",
    !/googleapis|walletobjects|fetch\(|guardedFetch|https\.request/.test(SOURCES.GW + WALLET_ROUTE));
  check("R4. nothing secret in any log line, and no socket, DNS lookup or fetch left the process", !holdsSecret(LOGS.join("\n")) && NETWORK.length === 0, NETWORK.join(", "));

  console.log(failures ? "\nCHECKS FAILED: " + failures + " of " + (passes + failures) : "\nALL " + passes + " CHECKS PASSED");
  process.exit(failures ? 1 : 0);
})().catch(function (e) {
  console.log("    FAIL  threw: " + safe(String(e && e.stack || e)).slice(0, 600));
  process.exit(1);
});
