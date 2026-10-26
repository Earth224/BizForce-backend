"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkMarketplaceBfcOnly.js — BizForce Market is priced in BizCash only.

   Owner decision of 2026-10-26 (option (i) of the USD marketplace recon in
   ae8e5db): USD sales between members are switched off; BizCash (BFC) trades
   stay. This proves the server side, named entry by entry:

     POST /api/marketplace/listings/:id/checkout-usd
       BEFORE (ae8e5db)  a Stripe test-mode checkout for a listing's price_usd
       AFTER             no route registers it, nothing creates a Stripe
                         session for a listing (checkDormantRoutesDeleted
                         records it in REMOVED and proves the router)
     create and edit (POST and PUT /api/marketplace/listings)
       BEFORE            price_usd in cents accepted; a listing needed a BFC
                         price, a USD price, or both
       AFTER             price_usd above 0 is a 400 naming the field
                         ("Listings are priced in BizCash only."); null or 0
                         is stored as null; an active listing needs a BFC price
                         above 0; a pause is always allowed
     buying (POST /api/marketplace/listings/:id/buy)
       BEFORE            a listing with price_bfc 0 reached bfc_buy_listing
       AFTER             409 "Not for sale until the seller sets a BizCash
                         price", and bfc_buy_listing is not called
     the Store agent's executors (publish_listing, update_listing)
       BEFORE            the same USD rules as the routes
       AFTER             the same BFC-only rules as the routes
     the Store agent's proposals (generateStoreProposalsForUser)
       BEFORE            new listings were proposed with price_usd in cents
       AFTER             with price_bfc; a USD price in the model's answer is
                         never carried into a proposal
     the public storefront (GET /api/bfp/seller/:handle)
       BEFORE            currency "USD", price_usd / 100, purchasable by USD
       AFTER             currency "BFC", price_bfc, purchasable only with a
                         BFC price; price_usd is not read
     the public listing and the browse list
       AFTER             price_usd is not selected; the data stays in the table

   HOW. Each route handler and helper is lifted from server.js into a vm with
   the closure it needs, against a fake database that records every call. No
   database, no Stripe, no network.

   MUTATE=usd-route-restored   puts a checkout-usd route back into server.js
                               (in memory). Section 1 must go red.
   MUTATE=price-usd-accepted   listingPriceUsdRefused refuses nothing.
                               Sections 2 and 4 must go red.
   ══════════════════════════════════════════════════════════════════════════ */
const fs = require("fs");
const vm = require("vm");
const path = require("path");
const net = require("net");
const dns = require("dns");
const MUT = require("./_shared");

const MUTATIONS = ["usd-route-restored", "price-usd-accepted"];
const MUTATE = process.env.MUTATE || "";
// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") MUT.runAllMutations(__filename, MUTATIONS);
if (MUTATE && MUTATIONS.indexOf(MUTATE) === -1) {
  console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + MUTATIONS.join(", "));
  process.exit(2);
}

const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkMarketplaceBfcOnly: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkMarketplaceBfcOnly: no network"); };

const REPO = path.join(__dirname, "..");
let SRC = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
if (MUTATE === "usd-route-restored") {
  SRC = MUT.replaceOnce(SRC, "/* ── BIZFORCE MARKET IS PRICED IN BIZCASH ONLY ─",
    "app.post(\"/api/marketplace/listings/:id/checkout-usd\", requireAuth, async function (req, res, next) {\n" +
    "  const session = await stripe.checkout.sessions.create({ mode: \"payment\" });\n  return res.json({ url: session.url });\n});\n\n" +
    "/* ── BIZFORCE MARKET IS PRICED IN BIZCASH ONLY ─", MUTATE);
}
if (MUTATE === "price-usd-accepted") {
  SRC = MUT.replaceOnce(SRC, "  return value !== undefined && value !== null && value !== \"\" && Number(value) !== 0;\n",
    "  return false;\n", MUTATE);
}
if (MUTATE) console.log("\n!! MUTATION: " + MUTATE + " (server.js, in memory)");

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}

/* ── a fake database: rows by table, every call recorded ────────────────── */
function fakeDb(rows) {
  const calls = [];
  const tables = JSON.parse(JSON.stringify(rows || {}));
  function from(table) {
    const q = { table: table, op: "select", filters: [], payload: null };
    const chain = {};
    ["select", "order", "limit", "ilike", "or", "neq", "gt"].forEach(function (op) {
      chain[op] = function () { if (op === "ilike") q.filters.push(["ilike"].concat([].slice.call(arguments))); return chain; };
    });
    chain.eq = function (c, v) { q.filters.push(["eq", c, v]); return chain; };
    ["insert", "update", "upsert", "delete"].forEach(function (op) {
      chain[op] = function (payload) { q.op = op; q.payload = payload; return chain; };
    });
    const matching = function () {
      return (tables[table] || []).filter(function (r) {
        return q.filters.every(function (f) {
          if (f[0] === "eq") return r[f[1]] === f[2];
          if (f[0] === "ilike") return String(r[f[1]]).toLowerCase() === String(f[2]).toLowerCase();
          return true;
        });
      });
    };
    const answer = function (single) {
      calls.push(JSON.parse(JSON.stringify(q)));
      const hit = matching();
      if (q.op === "update") { const merged = hit.length ? Object.assign({}, hit[0], q.payload) : null; return { data: single ? merged : (merged ? [merged] : []), error: null }; }
      if (q.op !== "select") return { data: single ? q.payload : [q.payload], error: null };
      return { data: single ? (hit[0] || null) : hit, error: null };
    };
    chain.maybeSingle = async function () { return answer(true); };
    chain.single = async function () { return answer(true); };
    chain.then = function (res, rej) { return Promise.resolve(answer(false)).then(res, rej); };
    return chain;
  }
  const rpcCalls = [];
  return {
    calls: calls, rpcCalls: rpcCalls,
    client: { from: from, rpc: async function (name, args) { rpcCalls.push([name, args]); return { data: 1234, error: null }; } }
  };
}
const writes = function (db) { return db.calls.filter(function (c) { return c.op !== "select"; }); };

/* ── lifting ─────────────────────────────────────────────────────────────── */
["insertListingWithSlug", "refuseUnlessSubscribed", "ownerPagePublic"].forEach(function (n) { MUT.STUBS.add(n); });
function routeSource(method, routePath) {
  const sig = "app." + method + "(\"" + routePath + "\",";
  const start = SRC.indexOf(sig);
  if (start === -1) throw new Error("route not found: " + method + " " + routePath);
  const fnAt = SRC.indexOf("async function (req, res, next) {", start);
  const end = MUT.braceMatch(SRC, SRC.indexOf("{", fnAt));
  return SRC.slice(start, end + 2);
}
function context(db, extra) {
  const inserted = [];
  const ctx = Object.assign({
    supabase: db.client,
    nowIso: function () { return "2026-10-26T12:00:00.000Z"; },
    console: { log: function () {}, warn: function () {}, error: function () {} },
    process: { env: {} },
    requireAuth: 0, requireActiveSubscription: 0,
    refuseUnlessSubscribed: async function () { return false; },
    ownerPagePublic: async function () { return true; },
    insertListingWithSlug: async function (row) { inserted.push(JSON.parse(JSON.stringify(row))); return { data: Object.assign({ id: "new-listing" }, row), error: null }; },
    JSON: JSON, Object: Object, Array: Array, Number: Number, String: String, Math: Math, Promise: Promise, Error: Error, Date: Date
  }, extra || {});
  ctx.__inserted = inserted;
  return ctx;
}
function liftRoute(method, routePath, db, extra) {
  const root = routeSource(method, routePath);
  const ctx = context(db, extra);
  let handler = null;
  ctx.app = {}; ["get", "post", "put", "delete"].forEach(function (m) { ctx.app[m] = function () { handler = arguments[arguments.length - 1]; }; });
  vm.createContext(ctx);
  vm.runInContext(MUT.closureFor(SRC, root), ctx);
  return { handler: handler, ctx: ctx };
}
async function call(route, req) {
  const res = { statusCode: 200, body: undefined, status: function (c) { this.statusCode = c; return this; }, json: function (b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
  let nextErr = null;
  await route.handler(Object.assign({ user: { id: "seller-1" }, params: {}, query: {}, body: {} }, req), res, function (e) { nextErr = e || new Error("next"); });
  return { status: res.statusCode, body: res.body, nextErr: nextErr && String(nextErr.message || nextErr) };
}
function executor(name, db) {
  const start = SRC.indexOf("  " + name + ": async function (proposal) {");
  if (start === -1) throw new Error("executor not found: " + name);
  const end = MUT.braceMatch(SRC, SRC.indexOf("{", start));
  const fnSrc = SRC.slice(start + 2 + name.length + 2, end);
  const ctx = context(db);
  vm.createContext(ctx);
  vm.runInContext(MUT.closureFor(SRC, "this.__exec = " + fnSrc + ";"), ctx);
  return { run: ctx.__exec, ctx: ctx };
}

const LISTINGS = [
  { id: "usd-only", seller_id: "seller-1", title: "Old USD listing", price_bfc: 0, price_usd: 4900, status: "active", listing_kind: "product", category: "other", media: [] },
  { id: "priced", seller_id: "seller-1", title: "BFC listing", price_bfc: 500, price_usd: 2500, status: "active", listing_kind: "product", category: "other", media: [] }
];
const BFC_ONLY = "Listings are priced in BizCash only.";
const NFS = "Not for sale until the seller sets a BizCash price";

(async function main() {
  /* ── 1. the checkout-usd route ──────────────────────────────────────── */
  console.log("\n══ 1. POST …/checkout-usd (BEFORE: a Stripe test-mode checkout · AFTER: gone) ══");
  const code = SRC.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
  const usdRoutes = code.match(/app\.(get|post|put|patch|delete|all|use)\(\s*["'`][^"'`]*checkout-usd[^"'`]*["'`]/g) || [];
  check("no route registers checkout-usd", usdRoutes.length === 0, usdRoutes.join(", "));
  check("no code names checkout-usd at all", code.indexOf("checkout-usd") === -1);
  check("no Stripe checkout session is created anywhere but the subscription checkout",
    (code.match(/checkout\.sessions\.create\(/g) || []).length === 1 && code.indexOf("await stripe.checkout.sessions.create(sessionParams);") !== -1);
  check("no code creates a checkout for a listing's price", !/unit_amount:\s*listing\./.test(code));

  /* ── 2. create and edit ─────────────────────────────────────────────── */
  console.log("\n══ 2. create and edit (BEFORE: a USD price in cents · AFTER: refused, BFC required) ══");
  let db = fakeDb({ marketplace_listings: LISTINGS });
  let route = liftRoute("post", "/api/marketplace/listings", db);
  let r = await call(route, { body: { title: "Lamp", category: "other", price_bfc: 300, price_usd: 4900 } });
  check("create with price_usd 4900: 400 naming the field, \"" + BFC_ONLY + "\"",
    r.status === 400 && r.body.error === BFC_ONLY && r.body.field === "price_usd", r.status + " " + JSON.stringify(r.body));
  check("…and nothing is written", writes(db).length === 0 && route.ctx.__inserted.length === 0, JSON.stringify(route.ctx.__inserted));
  r = await call(route, { body: { title: "Lamp", category: "other", price_bfc: 300, price_usd: "12.50" } });
  check("create with price_usd \"12.50\": refused the same way", r.status === 400 && r.body.field === "price_usd", r.status + " " + JSON.stringify(r.body));
  r = await call(route, { body: { title: "Lamp", category: "other", price_bfc: 0 } });
  check("create with no BFC price: 400 naming price_bfc", r.status === 400 && r.body.field === "price_bfc" && r.body.error.indexOf(BFC_ONLY) !== -1, r.status + " " + JSON.stringify(r.body));
  r = await call(route, { body: { title: "Lamp", category: "other", price_bfc: 300, price_usd: null } });
  const okRow = route.ctx.__inserted[route.ctx.__inserted.length - 1] || {};
  check("create with price_bfc 300 and price_usd null: 201, stored with price_usd null",
    r.status === 201 && okRow.price_bfc === 300 && okRow.price_usd === null, r.status + " " + JSON.stringify(okRow));
  r = await call(route, { body: { title: "Lamp", category: "other", price_bfc: 300, price_usd: 0 } });
  check("create with price_usd 0: accepted, stored as null", r.status === 201 && route.ctx.__inserted[route.ctx.__inserted.length - 1].price_usd === null, r.status);

  db = fakeDb({ marketplace_listings: LISTINGS });
  route = liftRoute("put", "/api/marketplace/listings/:id", db);
  r = await call(route, { params: { id: "priced" }, body: { price_usd: 100 } });
  check("edit with price_usd 100: 400 naming the field, nothing written",
    r.status === 400 && r.body.error === BFC_ONLY && r.body.field === "price_usd" && writes(db).length === 0, r.status + " " + JSON.stringify(r.body));
  r = await call(route, { params: { id: "usd-only" }, body: { title: "Renamed" } });
  check("edit of an active listing with no BFC price: 400 naming price_bfc, nothing written",
    r.status === 400 && r.body.field === "price_bfc" && writes(db).length === 0, r.status + " " + JSON.stringify(r.body));
  r = await call(route, { params: { id: "usd-only" }, body: { status: "paused" } });
  check("a pause is always allowed, even with no BFC price", r.status === 200 && writes(db).length === 1 && writes(db)[0].payload.status === "paused", r.status + " " + JSON.stringify(writes(db)));
  r = await call(route, { params: { id: "usd-only" }, body: { price_bfc: 450 } });
  const setBfc = writes(db)[writes(db).length - 1];
  check("setting a BFC price on it is allowed, and the USD data is left alone",
    r.status === 200 && setBfc.payload.price_bfc === 450 && !("price_usd" in setBfc.payload), r.status + " " + JSON.stringify(setBfc));
  r = await call(route, { params: { id: "priced" }, body: { price_usd: null } });
  check("edit with price_usd null clears it", r.status === 200 && writes(db)[writes(db).length - 1].payload.price_usd === null, r.status);

  /* ── 3. buying ──────────────────────────────────────────────────────── */
  console.log("\n══ 3. buying (BEFORE: a 0-BFC listing reached bfc_buy_listing · AFTER: not for sale) ══");
  db = fakeDb({ marketplace_listings: LISTINGS });
  route = liftRoute("post", "/api/marketplace/listings/:id/buy", db);
  r = await call(route, { user: { id: "buyer-1" }, params: { id: "usd-only" } });
  check("a listing with no BFC price: 409 \"" + NFS + ".\"", r.status === 409 && r.body.error === NFS + "." && r.body.field === "price_bfc", r.status + " " + JSON.stringify(r.body));
  check("…and bfc_buy_listing is not called", db.rpcCalls.length === 0, JSON.stringify(db.rpcCalls));
  r = await call(route, { user: { id: "buyer-1" }, params: { id: "priced" } });
  check("a listing with a BFC price is bought through bfc_buy_listing", r.status === 200 && db.rpcCalls.length === 1 && db.rpcCalls[0][0] === "bfc_buy_listing", r.status + " " + JSON.stringify(db.rpcCalls));

  /* ── 4. the Store agent's executors ─────────────────────────────────── */
  console.log("\n══ 4. publish_listing and update_listing (the same rules as the routes) ══");
  db = fakeDb({ marketplace_listings: LISTINGS });
  let ex = executor("publish_listing", db);
  let err = null;
  try { await ex.run({ id: "p1", user_id: "seller-1", payload: { title: "Course", category: "other", price_usd: 4900, price_bfc: 100 } }); } catch (e) { err = e; }
  check("publish_listing with price_usd 4900 throws, naming the rule, and inserts nothing",
    err && err.message.indexOf("price_usd is refused") !== -1 && err.message.indexOf(BFC_ONLY) !== -1 && ex.ctx.__inserted.length === 0, err && err.message);
  err = null;
  try { await ex.run({ id: "p2", user_id: "seller-1", payload: { title: "Course", category: "other" } }); } catch (e) { err = e; }
  check("publish_listing with no BFC price throws", err && err.message.indexOf("price_bfc must be a whole number of BizCash above 0") !== -1, err && err.message);
  await ex.run({ id: "p3", user_id: "seller-1", payload: { title: "Course", category: "other", price_bfc: 250 } });
  check("publish_listing with price_bfc 250 inserts it with price_usd null",
    ex.ctx.__inserted.length === 1 && ex.ctx.__inserted[0].price_bfc === 250 && ex.ctx.__inserted[0].price_usd === null, JSON.stringify(ex.ctx.__inserted));
  ex = executor("update_listing", db);
  err = null;
  try { await ex.run({ id: "p4", user_id: "seller-1", payload: { listing_id: "priced", price_usd: 900 } }); } catch (e) { err = e; }
  check("update_listing with price_usd 900 throws and writes nothing",
    err && err.message.indexOf("price_usd is refused") !== -1 && writes(db).length === 0, (err && err.message) + " " + JSON.stringify(writes(db)));
  err = null;
  try { await ex.run({ id: "p5", user_id: "seller-1", payload: { listing_id: "usd-only", title: "Renamed" } }); } catch (e) { err = e; }
  check("update_listing leaving an active listing with no BFC price throws", err && err.message.indexOf("must keep a price_bfc above 0") !== -1, err && err.message);

  /* ── 5. the Store agent's proposals ─────────────────────────────────── */
  console.log("\n══ 5. the Store agent proposes BFC prices (BEFORE: price_usd in cents) ══");
  db = fakeDb({ marketplace_listings: LISTINGS, agent_proposals: [] });
  const storeRoot = MUT.definitionOf(SRC, "generateStoreProposalsForUser");
  let prompt = "";
  const sctx = context(db, {
    AGENT_SYSTEM_PROMPTS: { store: "STORE" },
    callAnthropicText: async function (p) {
      prompt = p;
      return { text: JSON.stringify([
        { kind: "publish_listing", title: "USD only offer", category: "other", price_usd: 4900, reasoning: "r" },
        { kind: "publish_listing", title: "BFC offer", category: "other", price_bfc: 700, price_usd: 4900, reasoning: "r" },
        { kind: "update_listing", listing_id: "priced", price_usd: 100, reasoning: "r" }
      ]) };
    }
  });
  vm.createContext(sctx);
  vm.runInContext(MUT.closureFor(SRC, storeRoot + "\nthis.__store = generateStoreProposalsForUser;"), sctx);
  await sctx.__store("seller-1");
  const proposed = (writes(db).find(function (w) { return w.table === "agent_proposals" && w.op === "insert"; }) || { payload: [] }).payload;
  check("the prompt asks for price_bfc and never for price_usd",
    prompt.indexOf("\"price_bfc\": a whole number of BizCash (BFC), greater than zero") !== -1 && prompt.indexOf("price_usd") === -1, prompt.slice(prompt.indexOf("For kind"), prompt.indexOf("For kind") + 200));
  check("one proposal is filed: the BFC-priced listing, with price_bfc 700 and no price_usd",
    proposed.length === 1 && proposed[0].payload.title === "BFC offer" && proposed[0].payload.price_bfc === 700 && !("price_usd" in proposed[0].payload),
    JSON.stringify(proposed));

  /* ── 6. what strangers see ──────────────────────────────────────────── */
  console.log("\n══ 6. the storefront and listing page (BEFORE: USD · AFTER: BFC only) ══");
  db = fakeDb({
    bf_profiles: [{ user_id: "seller-1", username: "maker", show_products: true }],
    marketplace_listings: LISTINGS, profile_portfolio: [], bf_music_tracks: [], bf_videos: []
  });
  route = liftRoute("get", "/api/bfp/seller/:handle", db);
  r = await call(route, { params: { handle: "maker" } });
  const prods = (r.body && r.body.products) || [];
  const pPriced = prods.find(function (p) { return p.id === "priced"; }) || {};
  const pUsd = prods.find(function (p) { return p.id === "usd-only"; }) || {};
  check("the storefront prices the BFC listing in BFC: 500, purchasable",
    pPriced.currency === "BFC" && pPriced.price === 500 && pPriced.is_purchasable === true, JSON.stringify(pPriced));
  check("the listing with only a USD price shows with no price and cannot be bought",
    pUsd.currency === "BFC" && pUsd.price === null && pUsd.is_purchasable === false, JSON.stringify(pUsd));
  const sellerSelect = db.calls.find(function (c) { return c.table === "marketplace_listings"; });
  check("the storefront route does not read price_usd", sellerSelect && routeSource("get", "/api/bfp/seller/:handle").indexOf("price_usd") === -1);
  check("the public listing route does not select price_usd", routeSource("get", "/api/marketplace/listings/:id").indexOf("price_usd") === -1);
  check("the browse list does not select price_usd", routeSource("get", "/api/marketplace/listings").indexOf("price_usd") === -1);

  check("zero network", NETWORK.length === 0, JSON.stringify(NETWORK));
  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(function (e) { console.log("    FAIL  the check threw: " + ((e && e.stack) || e)); process.exit(1); });
