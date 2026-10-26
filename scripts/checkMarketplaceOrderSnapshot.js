"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkMarketplaceOrderSnapshot.js — a past order survives its listing, and a
   past USD order still shows in My Purchases.

   BizForce Market trades in BizCash only since 2026-10-26 (owner decision,
   option (i) of the USD marketplace recon in ae8e5db). One USD order was
   recorded before that, and it must keep rendering and downloading. Named
   entry by entry:

     where the snapshot is written
       BEFORE (ae8e5db)  the webhook's marketplace_usd branch copied the file
                         path and name onto each new USD order (migration 113)
       AFTER             no USD order is written any more
                         (checkMarketplaceUsdSold proves the refusal); orders
                         already written keep their snapshot
     GET /api/purchases/:orderId/download
       BEFORE and AFTER  the order's own snapshot first, the listing joined
                         through listing_id only as a fallback; a deleted
                         listing does not cost the buyer their file
     GET /api/purchases
       BEFORE and AFTER  the buyer's orders, USD and BFC, with amount_usd and
                         amount_bfc
     my-purchases.html
       BEFORE and AFTER  a USD order shows as "$1.00", a BFC order as
                         "500 BFC", a digital order offers Download

   HOW. The two routes are lifted from server.js into a vm against a fake
   database and fake storage, and my-purchases.html runs in jsdom with a fetch
   stub. It used to write fixture listings, orders and storage objects to the
   live database through the webhook; it writes nothing now. No database, no
   network, no BIZFORCE_CHECK_USER_ID.

   MUTATE=no-snapshot     the past order loses its snapshot, so the download
                          falls back to a listing that is gone. "served from
                          the snapshot" must go red with a 404.
   MUTATE=usd-order-hidden  my-purchases.html shows every amount in BFC, so
                          the past USD order reads "0 BFC". The rendering
                          assertions must go red.

   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */
const fs = require("fs");
const vm = require("vm");
const path = require("path");
const net = require("net");
const dns = require("dns");
const MUT = require("./_shared");

const MUTATIONS = ["no-snapshot", "usd-order-hidden"];
const MUTATE = process.env.MUTATE || "";
// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") MUT.runAllMutations(__filename, MUTATIONS);
if (MUTATE && MUTATIONS.indexOf(MUTATE) === -1) {
  console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + MUTATIONS.join(", "));
  process.exit(2);
}

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const SRC = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
let PURCHASES_HTML = fs.readFileSync(path.join(FRONTEND, "my-purchases.html"), "utf8").replace(/\r\n/g, "\n");
if (MUTATE === "usd-order-hidden") {
  PURCHASES_HTML = MUT.replaceOnce(PURCHASES_HTML,
    "  var isUsd = p.amount_usd !== null && p.amount_usd !== undefined;\n",
    "  var isUsd = false;\n", MUTATE);
}
if (MUTATE) console.log("\n!! MUTATION: " + MUTATE + " (in memory)");

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}

/* The one past USD order's shape, as the webhook wrote it: $1.00, digital,
   with the migration 113 snapshot. Its listing has since been deleted. */
const BUYER = "buyer-1";
const PAST_USD = {
  id: "order-usd", listing_id: null, buyer_id: BUYER, seller_id: "seller-1", amount_bfc: 0, amount_usd: 100,
  payment_method: "usd", status: "completed", listing_title: "Past USD purchase", is_digital: true,
  digital_file_path: "seller-1/past.pdf", digital_file_name: "past.pdf", delivered_at: "2026-07-25T10:00:00Z",
  stripe_session_id: "cs_past", created_at: "2026-07-25T10:00:00Z"
};
if (MUTATE === "no-snapshot") { PAST_USD.digital_file_path = null; PAST_USD.digital_file_name = null; }
const LEGACY = {
  id: "order-legacy", listing_id: "listing-legacy", buyer_id: BUYER, seller_id: "seller-1", amount_bfc: 0, amount_usd: 100,
  payment_method: "usd", status: "completed", listing_title: "Before 113", is_digital: true, created_at: "2026-06-01T10:00:00Z"
};
const ORPHAN = {
  id: "order-orphan", listing_id: null, buyer_id: BUYER, seller_id: "seller-1", amount_bfc: 0, amount_usd: 100,
  payment_method: "usd", status: "completed", listing_title: "No file", is_digital: true, created_at: "2026-06-02T10:00:00Z"
};
const BFC_ORDER = {
  id: "order-bfc", listing_id: "listing-bfc", buyer_id: BUYER, seller_id: "seller-2", amount_bfc: 500, amount_usd: null,
  status: "completed", listing_title: "BFC purchase", is_digital: false, created_at: "2026-10-01T10:00:00Z"
};
const ROWS = {
  marketplace_orders: [PAST_USD, LEGACY, ORPHAN, BFC_ORDER],
  marketplace_listings: [{ id: "listing-legacy", digital_file_path: "seller-1/legacy.pdf", digital_file_name: "legacy.pdf" }]
};

function fakeDb() {
  const calls = [];
  const signed = [];
  function from(table) {
    const q = { table: table, op: "select", filters: [] };
    const chain = {};
    ["select", "order", "limit"].forEach(function (op) { chain[op] = function () { return chain; }; });
    chain.eq = function (c, v) { q.filters.push([c, v]); return chain; };
    ["insert", "update", "upsert", "delete"].forEach(function (op) { chain[op] = function (p) { q.op = op; q.payload = p; return chain; }; });
    const hit = function () { calls.push(JSON.parse(JSON.stringify(q))); return (ROWS[table] || []).filter(function (r) { return q.filters.every(function (f) { return r[f[0]] === f[1]; }); }); };
    chain.maybeSingle = async function () { return { data: hit()[0] || null, error: null }; };
    chain.then = function (res, rej) { return Promise.resolve({ data: hit(), error: null }).then(res, rej); };
    return chain;
  }
  return {
    calls: calls, signed: signed,
    client: { from: from, storage: { from: function (b) { return { createSignedUrl: async function (p) { signed.push(b + "/" + p); return { data: { signedUrl: "https://signed/" + p }, error: null }; } }; } } }
  };
}
function lift(routePath, db) {
  const start = SRC.indexOf("app.get(\"" + routePath + "\",");
  if (start === -1) throw new Error("route not found: " + routePath);
  const end = MUT.braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("async function (req, res, next) {", start)));
  let handler = null;
  const ctx = { supabase: db.client, requireAuth: 0, console: { log() {}, warn() {}, error() {} },
    app: { get: function () { handler = arguments[arguments.length - 1]; } }, JSON: JSON, Object: Object, String: String, Promise: Promise };
  vm.createContext(ctx);
  vm.runInContext(SRC.slice(start, end + 2), ctx);
  return handler;
}
async function call(handler, params) {
  const res = { statusCode: 200, body: undefined, status: function (c) { this.statusCode = c; return this; }, json: function (b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
  await handler({ user: { id: BUYER }, params: params || {}, query: {}, body: {} }, res, function (e) { res.statusCode = 500; res.body = { error: String(e) }; });
  return { status: res.statusCode, body: res.body };
}

(async function main() {
  /* ── 1. the download route ─────────────────────────────────────────── */
  console.log("\n══ 1. GET /api/purchases/:orderId/download (snapshot first, the listing as fallback) ══");
  const db = fakeDb();
  const download = lift("/api/purchases/:orderId/download", db);
  let r = await call(download, { orderId: "order-usd" });
  check("the past USD order downloads though its listing is gone, served from its own snapshot",
    r.status === 200 && r.body.url === "https://signed/seller-1/past.pdf" && r.body.fileName === "past.pdf", r.status + " " + JSON.stringify(r.body));
  r = await call(download, { orderId: "order-legacy" });
  check("an order written before migration 113 still downloads through the listing join",
    r.status === 200 && r.body.fileName === "legacy.pdf", r.status + " " + JSON.stringify(r.body));
  r = await call(download, { orderId: "order-orphan" });
  check("an order with neither a snapshot nor a listing is a 404, said plainly", r.status === 404 && r.body.error === "Digital file not found", r.status + " " + JSON.stringify(r.body));
  r = await call(download, { orderId: "order-bfc" });
  check("an order with no digital good is a 403", r.status === 403, r.status);
  check("the download route writes nothing", db.calls.every(function (c) { return c.op === "select"; }), JSON.stringify(db.calls));

  /* ── 2. the purchases list ─────────────────────────────────────────── */
  console.log("\n══ 2. GET /api/purchases (USD and BFC orders) ══");
  const list = lift("/api/purchases", db);
  r = await call(list);
  const usd = ((r.body && r.body.purchases) || []).find(function (p) { return p.id === "order-usd"; });
  check("the past USD order is listed with its amount in cents", r.status === 200 && usd && usd.amount_usd === 100 && usd.is_digital === true, r.status + " " + JSON.stringify(usd));
  check("the route selects amount_usd and amount_bfc", /\.select\("id, listing_id, listing_title, amount_usd, amount_bfc, status, is_digital, delivered_at, created_at"\)/.test(SRC.slice(SRC.indexOf("app.get(\"/api/purchases\","), SRC.indexOf("app.get(\"/api/purchases/:orderId/download\","))));

  /* ── 3. my-purchases.html ──────────────────────────────────────────── */
  console.log("\n══ 3. my-purchases.html renders the past USD order ══");
  let JSDOM;
  try { JSDOM = require(require.resolve("jsdom", { paths: [REPO] })).JSDOM; } catch (e) { console.log("    FAIL  jsdom is not installed"); process.exit(1); }
  const purchases = r.body.purchases;
  const jsdomLib = require(require.resolve("jsdom", { paths: [REPO] }));
  // The page's sign-in redirect is a navigation jsdom does not implement; it is not under test.
  const virtualConsole = new jsdomLib.VirtualConsole();
  virtualConsole.on("jsdomError", function (e) { if (!/navigation/i.test(String(e && e.message))) console.log("    (jsdom) " + e.message); });
  const dom = new JSDOM(PURCHASES_HTML.replace(/<script src="[^"]*"><\/script>/g, ""), { runScripts: "outside-only", url: "https://bizforceai.net/my-purchases.html", virtualConsole: virtualConsole });
  const w = dom.window;
  const network = [];
  w.token = "check-token";
  w.fetch = function (url) {
    network.push(String(url));
    const p = String(url).indexOf("/api/purchases") !== -1
      ? Promise.resolve({ ok: true, status: 200, json: function () { return Promise.resolve({ purchases: purchases }); } })
      : Promise.reject(new Error("unexpected fetch " + url));
    p.catch(function () {});
    return p;
  };
  const inline = (PURCHASES_HTML.match(/<script>([\s\S]*?)<\/script>/g) || []).map(function (b) { return b.slice(8, -9); });
  inline.forEach(function (code) { w.eval(code); });
  for (let i = 0; i < 20; i++) await new Promise(function (res) { setImmediate(res); });
  const cards = Array.prototype.slice.call(w.document.querySelectorAll(".purchase-card"));
  const cardFor = function (title) { return cards.find(function (c) { return c.querySelector(".purchase-title").textContent === title; }); };
  const usdCard = cardFor("Past USD purchase");
  const bfcCard = cardFor("BFC purchase");
  check("every order is a card (" + purchases.length + ")", cards.length === purchases.length, cards.length);
  check("the past USD order reads \"$1.00\"", usdCard && usdCard.querySelector(".purchase-amount").textContent === "$1.00",
    usdCard && usdCard.querySelector(".purchase-amount").textContent);
  check("…and offers Download", usdCard && !!usdCard.querySelector(".btn-download"));
  check("a BFC order reads \"500 BFC\"", bfcCard && bfcCard.querySelector(".purchase-amount").textContent === "500 BFC",
    bfcCard && bfcCard.querySelector(".purchase-amount").textContent);
  check("the page fetched only /api/purchases", network.length === 1 && /\/api\/purchases$/.test(network[0]), JSON.stringify(network));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(function (e) { console.log("    FAIL  the check threw: " + ((e && e.stack) || e)); process.exit(1); });
