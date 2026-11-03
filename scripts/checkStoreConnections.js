/* checkStoreConnections: store connections, read-only. Shopify and WooCommerce stock and order totals, no customer data.

   WHAT IT PROVES (lib/storeSync.js, its routes and cron in server.js, migration 163, the export and delete,
   the Privacy page and the Store agent page). Both platforms are stubbed: no request leaves this process.

     V. VALIDATION. A Shopify domain is *.myshopify.com and nothing else; a WooCommerce address is https only,
        with no IP address, no user or password and no other port.
     C. CONNECTING SHOPIFY, through the real route. A good read-only token is verified by one GET and stored
        ENCRYPTED (hex, decrypts to the token, never the token itself); the token is in no response and no log.
        A token with any write_ scope, one missing a read scope, one Shopify refuses, a bad domain or a server
        without its key stores nothing. The route is requireAuth, requireActiveSubscription and 5 an hour.
     W. CONNECTING WOOCOMMERCE. The route answers the store's own authorization page with scope=read. The
        callback refuses a key whose permission is not "read", a forged or expired state, a key the store
        refuses and a store on a private address, and stores nothing; a read key is verified by one GET and
        stored encrypted.
     S. STATUS answers safe fields only.
     Y. THE SYNC. Products, variants, SKUs, prices, costs and stock map into inventory_items marked with their
        source, across pages, with a 429 waited out (Retry-After) and retried; untracked stock is skipped, not
        written as 0; a member's own row with the same SKU is never overwritten; a second sync updates in place
        and keeps the member's reorder point. Order summaries hold exactly the summary keys and NO customer
        field, whatever the store sends. Every request is a GET.
     A. AN AUTH FAILURE marks needs_reconnect with ONE notice, after ONE request (no retry loop), and a second
        failure says nothing more; sync now on it is refused without a request.
     J. THE DAILY SYNC runs only with ENABLE_STORE_SYNC exactly "true", claims job_runs.store_sync for the UTC
        day (a second tick and a concurrent one run nothing), and skips a member without an active plan.
     D. DISCONNECT deletes the connection, its synced rows and its order summaries, and leaves manual rows; the
        account delete and the export cover both new tables, and the export never names the credentials.
     R. THE READERS. Stock & Margin (server.js measureStockAndMargin), the "Items at their reorder point"
        trigger (lib/triggerRunner.js) and the Store signature (lib/agentSignatures.js) all read synced stock,
        and the signature says where stock came from.
     N. NO WRITE CALL to either platform anywhere: lib/storeSync.js holds no POST, PUT, PATCH or DELETE and
        one fetch, with method "GET"; no other non-script file names a store's API host.
     L. THE PRIVACY SENTENCE is built into privacy.html; the Store page says "BizForce only reads your store."
        and has the steps for both platforms; the migration turns RLS on; no emoji in any new file.

   MUTATIONS — MUTATE=<name> applies one in memory; MUTATE=all runs each:
     plaintext-credentials     the connection is stored with the token in the clear
     write-scope-accepted      a token with a write_ scope is accepted
     customer-email-stored     an order summary keeps the customer's email
     manual-row-overwritten    a synced product takes over a member's own row with the same SKU
     auth-failure-retried      a 401 is retried like a 429
     shopify-write-call        a function that deletes a Shopify product is added
     double-run                the daily tick runs without claiming the day
     woo-not-read-only         a WooCommerce key with read_write permission is accepted
*/
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const crypto = require("crypto");
const Module = require("module");
const cp = require("child_process");
const MUT = require("./_shared");

const REPO = path.join(__dirname, "..");
const FE = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const read = (f) => fs.readFileSync(path.join(REPO, f), "utf8");
const readFe = (f) => fs.readFileSync(path.join(FE, f), "utf8");

const MUTATIONS = {
  "plaintext-credentials": ["sync",
    "  return { credentials_ciphertext: sealed.ciphertext, credentials_iv: sealed.iv, credentials_auth_tag: sealed.authTag };\n",
    "  return { credentials_ciphertext: plain, credentials_iv: sealed.iv, credentials_auth_tag: sealed.authTag };\n"],
  "write-scope-accepted": ["sync",
    "  if (scopes.some(function (s) { return /^write_/.test(s); })) {\n", "  if (false) {\n"],
  "customer-email-stored": ["sync",
    "    currency: currency,\n    line_items:", "    currency: currency,\n    email: o.email || (o.billing && o.billing.email) || null,\n    line_items:"],
  "manual-row-overwritten": ["sync",
    "      if (owner && !mine && owner.source == null) { result.skipped_sku_manual++; return; }\n",
    "      if (owner && !mine && owner.source == null) { supabase.from(\"inventory_items\").update({ name: it.name, quantity_on_hand: it.quantity_on_hand }).eq(\"id\", owner.id).then(function () {}); result.skipped_sku_manual++; return; }\n"],
  "auth-failure-retried": ["sync",
    "var RETRYABLE = [429, 500, 502, 503, 504];\n", "var RETRYABLE = [401, 429, 500, 502, 503, 504];\n"],
  "shopify-write-call": ["sync",
    "function shopifyUrl(domain, path) {\n",
    "function archiveShopifyProduct(deps, domain, token, id) {\n  return deps.fetch(\"https://\" + domain + \"/admin/api/2026-07/products/\" + id + \".json\", { method: \"DELETE\", headers: { \"X-Shopify-Access-Token\": token } });\n}\nfunction shopifyUrl(domain, path) {\n"],
  "double-run": ["sync",
    "    if (!(await claimStoreSyncDay(deps.supabase, startedMs))) {\n", "    if (false) {\n"],
  "woo-not-read-only": ["sync",
    "  if (b.key_permissions !== \"read\") return", "  if (b.key_permissions !== \"read\" && b.key_permissions !== \"read_write\") return"]
};
const NAMES = Object.keys(MUTATIONS);
const MUTATE = process.env.MUTATE || "";
if (MUTATE === "all") MUT.runAllMutations(__filename, NAMES);
if (MUTATE && NAMES.indexOf(MUTATE) === -1) { console.error("Unknown MUTATE=" + MUTATE + ". Known: " + NAMES.join(", ")); process.exit(2); }

let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}
const UNHANDLED = [];
process.on("unhandledRejection", function (e) { UNHANDLED.push(e); });

const FILES = {
  sync: read("lib/storeSync.js"),
  server: read("server.js"),
  migration: read("supabase/migrations/163_store_connections.sql"),
  yourData: read("lib/yourData.js"),
  legal: read("lib/legalPages.js"),
  readme: read("README.md"),
  privacy: readFe("privacy.html"),
  page: readFe("store-agent.html"),
  ui: readFe("scripts/store-connect.js"),
  profile: readFe("scripts/agent-profile.js")
};
if (MUTATE) {
  const m = MUTATIONS[MUTATE];
  FILES[m[0]] = MUT.replaceOnce(FILES[m[0]], m[1], m[2], MUTATE);
  console.log("\n!! MUTATION: " + MUTATE);
}

const J = JSON.stringify;
const SECRET_HEX = crypto.createHash("sha256").update("checkStoreConnections").digest("hex");
process.env.ENCRYPTION_SECRET = SECRET_HEX;
const realRequire = Module.createRequire(path.join(REPO, "server.js"));
const CRYPT = realRequire("./lib/apiKeyCrypto");
const GF = realRequire("./lib/guardedFetch");
function compile(src, file, map) {
  const m = { exports: {} };
  const fn = vm.compileFunction(src, ["module", "exports", "require"], { filename: path.join(REPO, file) });
  fn(m, m.exports, function (r) { return Object.prototype.hasOwnProperty.call(map, r) ? map[r] : realRequire(r); });
  return m.exports;
}
const SS = compile(FILES.sync, "lib/storeSync.js", {});

const USER = "00000000-0000-4000-8000-000000000001";
const OTHER = "00000000-0000-4000-8000-000000000002";
const SHOP = "demo-shop.myshopify.com";
const TOKEN = "shpat_" + "a1b2c3d4".repeat(4);
const WOO = "https://woo.example.com";
const CK = "ck_" + "f".repeat(40), CS = "cs_" + "e".repeat(40);
const CUSTOMER = { email: "buyer@example.com", phone: "+15551234567", first: "Jane", last: "Buyer", street: "12 Elm Street" };

/* ── an in-memory database ──────────────────────────────────────────────── */
function uuid() { return crypto.randomUUID(); }
function makeDb() {
  const t = { member_store_connections: [], inventory_items: [], inventory_movements: [], store_order_summaries: [], notifications: [], job_runs: [] };
  const log = [];
  function rows(name) { if (!t[name]) t[name] = []; return t[name]; }
  function uniqueViolation(name, row, except) {
    const others = rows(name).filter(function (r) { return r !== except; });
    if (name === "inventory_items") {
      if (row.sku && others.some(function (r) { return r.user_id === row.user_id && r.sku && String(r.sku).toLowerCase() === String(row.sku).toLowerCase(); })) return "inventory_items_user_sku_uniq";
      if (row.store_connection_id && others.some(function (r) { return r.store_connection_id === row.store_connection_id && r.external_id === row.external_id; })) return "inventory_items_store_external_unique";
    }
    if (name === "member_store_connections" && others.some(function (r) { return r.user_id === row.user_id && r.platform === row.platform && r.store_url === row.store_url; })) return "member_store_connections_unique";
    if (name === "store_order_summaries" && others.some(function (r) { return r.connection_id === row.connection_id && r.external_id === row.external_id; })) return "store_order_summaries_unique";
    if (name === "job_runs" && others.some(function (r) { return r.job_name === row.job_name; })) return "job_runs_pkey";
    return null;
  }
  function checkViolation(name, row) {
    if (name === "member_store_connections") {
      if (!/^[0-9a-f]+$/.test(row.credentials_ciphertext || "") || !/^[0-9a-f]{24}$/.test(row.credentials_iv || "") || !/^[0-9a-f]{32}$/.test(row.credentials_auth_tag || "")) return "member_store_connections_ciphertext_check";
    }
    if (name === "inventory_items") {
      const manual = row.source == null && row.store_connection_id == null && row.external_id == null;
      const synced = (row.source === "shopify" || row.source === "woocommerce") && row.store_connection_id && row.external_id;
      if (!manual && !synced) return "inventory_items_source_check";
    }
    if (name === "store_order_summaries" && !Array.isArray(row.line_items)) return "store_order_summaries_line_items_check";
    return null;
  }
  function defaults(name, row) {
    const now = new Date().toISOString();
    const r = Object.assign({ id: uuid(), created_at: now }, row);
    if (name === "member_store_connections" && r.status === undefined) r.status = "connected";
    if (name === "inventory_items") { if (r.status === undefined) r.status = "active"; if (r.unit === undefined) r.unit = "unit"; ["source", "store_connection_id", "external_id", "reorder_point", "unit_cost"].forEach(function (k) { if (r[k] === undefined) r[k] = null; }); }
    return r;
  }
  function project(r, cols) {
    if (!cols || cols.trim() === "*") return Object.assign({}, r);
    const o = {};
    cols.split(",").map(function (c) { return c.trim(); }).forEach(function (c) { o[c] = r[c] === undefined ? null : r[c]; });
    return o;
  }
  function from(name) {
    const q = { op: null, cols: null, count: false, head: false, filters: [], or: null, payload: null, onConflict: null, single: null, range: null, returning: false };
    const api = {
      select: function (cols, opts) { if (!q.op) q.op = "select"; else q.returning = true; q.cols = cols; if (opts && opts.count) q.count = true; if (opts && opts.head) q.head = true; return api; },
      insert: function (p) { q.op = "insert"; q.payload = p; return api; },
      update: function (p) { q.op = "update"; q.payload = p; return api; },
      upsert: function (p, o) { q.op = "upsert"; q.payload = p; q.onConflict = o && o.onConflict; return api; },
      delete: function () { q.op = "delete"; return api; },
      eq: function (c, v) { q.filters.push(["eq", c, v]); return api; },
      in: function (c, v) { q.filters.push(["in", c, v]); return api; },
      or: function (s) { q.or = s; return api; },
      order: function () { return api; }, limit: function () { return api; },
      range: function (a, b) { q.range = [a, b]; return api; },
      maybeSingle: function () { q.single = "maybe"; return api; },
      single: function () { q.single = "one"; return api; },
      then: function (ok, bad) { return Promise.resolve().then(run).then(ok, bad); }
    };
    function match(r) {
      if (!q.filters.every(function (f) {
        if (f[0] === "eq") return String(r[f[1]]) === String(f[2]);
        if (f[0] === "in") return f[2].map(String).indexOf(String(r[f[1]])) !== -1;
        return true;
      })) return false;
      if (q.or) { const d = /neq\.(\d{4}-\d{2}-\d{2})/.exec(q.or)[1]; return r.last_run_on == null || r.last_run_on !== d; }
      return true;
    }
    function shape(list) {
      const data = list.map(function (r) { return project(r, q.cols); });
      if (q.single === "maybe") return { data: data[0] || null, error: null };
      if (q.single === "one") return data.length === 1 ? { data: data[0], error: null } : { data: null, error: { code: "PGRST116", message: "not one row" } };
      return { data: q.op === "select" || q.returning ? data : null, error: null };
    }
    function run() {
      log.push({ table: name, op: q.op });
      const all = rows(name);
      if (q.op === "select") {
        let hit = all.filter(match);
        const total = hit.length;
        if (q.range) hit = hit.slice(q.range[0], q.range[1] + 1);
        const out = shape(hit);
        if (q.count) out.count = total;
        return out;
      }
      if (q.op === "insert") {
        const list = Array.isArray(q.payload) ? q.payload : [q.payload];
        const made = [];
        for (const p of list) {
          const r = defaults(name, p);
          const u = uniqueViolation(name, r, null); if (u) return { data: null, error: { code: "23505", message: "duplicate key value violates unique constraint \"" + u + "\"" } };
          const c = checkViolation(name, r); if (c) return { data: null, error: { code: "23514", message: "violates check constraint \"" + c + "\"" } };
          made.push(r);
        }
        made.forEach(function (r) { all.push(r); });
        return shape(made);
      }
      if (q.op === "update") {
        const hit = all.filter(match);
        for (const r of hit) {
          const next = Object.assign({}, r, q.payload);
          const u = uniqueViolation(name, next, r); if (u) return { data: null, error: { code: "23505", message: u } };
        }
        hit.forEach(function (r) { Object.assign(r, q.payload); });
        return shape(hit);
      }
      if (q.op === "upsert") {
        const keys = String(q.onConflict).split(",");
        const list = Array.isArray(q.payload) ? q.payload : [q.payload];
        const touched = [];
        for (const p of list) {
          const prev = all.find(function (r) { return keys.every(function (k) { return r[k] != null && String(r[k]) === String(p[k]); }); });
          if (prev) {
            const next = Object.assign({}, prev, p);
            const u = uniqueViolation(name, next, prev); if (u) return { data: null, error: { code: "23505", message: u } };
            const c = checkViolation(name, next); if (c) return { data: null, error: { code: "23514", message: c } };
            Object.assign(prev, p); touched.push(prev);
          } else {
            const r = defaults(name, p);
            const u = uniqueViolation(name, r, null); if (u) return { data: null, error: { code: "23505", message: u } };
            const c = checkViolation(name, r); if (c) return { data: null, error: { code: "23514", message: c } };
            all.push(r); touched.push(r);
          }
        }
        return shape(touched);
      }
      if (q.op === "delete") {
        const hit = all.filter(match);
        t[name] = all.filter(function (r) { return hit.indexOf(r) === -1; });
        if (name === "member_store_connections") {
          // ON DELETE CASCADE from store_order_summaries.connection_id
          const ids = hit.map(function (r) { return r.id; });
          t.store_order_summaries = t.store_order_summaries.filter(function (r) { return ids.indexOf(r.connection_id) === -1; });
        }
        return shape(hit);
      }
      return { data: null, error: { message: "fake: no op" } };
    }
    return api;
  }
  return { from: from, t: t, log: log };
}

/* ── the stores, stubbed ────────────────────────────────────────────────── */
function headers(obj) {
  const h = {}; Object.keys(obj || {}).forEach(function (k) { h[k.toLowerCase()] = String(obj[k]); });
  return { get: function (k) { return Object.prototype.hasOwnProperty.call(h, k.toLowerCase()) ? h[k.toLowerCase()] : null; } };
}
function reply(status, body, hdrs) {
  return { status: status, headers: headers(hdrs), json: function () { return Promise.resolve(body); } };
}
function makeStores(opts) {
  const o = Object.assign({ scopes: ["read_products", "read_inventory", "read_orders"], verifyStatus: 200, productsStatus: 200, first429: false, wooStatus: 200 }, opts || {});
  const calls = [];
  let sent429 = false;
  const orderBase = {
    email: CUSTOMER.email, phone: CUSTOMER.phone, contact_email: CUSTOMER.email,
    customer: { first_name: CUSTOMER.first, last_name: CUSTOMER.last, email: CUSTOMER.email, phone: CUSTOMER.phone },
    billing_address: { name: CUSTOMER.first + " " + CUSTOMER.last, address1: CUSTOMER.street, phone: CUSTOMER.phone },
    shipping_address: { name: CUSTOMER.first + " " + CUSTOMER.last, address1: CUSTOMER.street }
  };
  function fetchStub(url, init) {
    calls.push({ url: url, method: (init && init.method) || "GET", headers: (init && init.headers) || {}, redirect: init && init.redirect });
    const u = new URL(url);
    if (u.hostname === SHOP) {
      if (u.pathname === "/admin/oauth/access_scopes.json") {
        if (o.verifyStatus !== 200) return Promise.resolve(reply(o.verifyStatus, { errors: "Invalid API key or access token" }));
        return Promise.resolve(reply(200, { access_scopes: o.scopes.map(function (h) { return { handle: h }; }) }));
      }
      if (/\/products\.json$/.test(u.pathname)) {
        if (o.productsStatus !== 200) return Promise.resolve(reply(o.productsStatus, { errors: "[API] Invalid API key or access token" }));
        if (o.first429 && !sent429) { sent429 = true; return Promise.resolve(reply(429, { errors: "Exceeded 2 calls per second" }, { "Retry-After": "2" })); }
        if (u.searchParams.get("page_info") === "p2") {
          return Promise.resolve(reply(200, { products: [{ id: 2, title: "Scarf", variants: [
            { id: 21, title: "Default Title", sku: "SCARF", price: "18.00", inventory_quantity: 0, inventory_management: "shopify", inventory_item_id: 9021 },
            { id: 22, title: "Gift wrap", sku: "WRAP", price: "2.00", inventory_quantity: 0, inventory_management: null, inventory_item_id: 9022 }] }] }));
        }
        return Promise.resolve(reply(200, { products: [{ id: 1, title: "Wool Hat", variants: [
          { id: 11, title: "Red", sku: "HAT-RED", price: "25.00", inventory_quantity: 4, inventory_management: "shopify", inventory_item_id: 9011 },
          { id: 12, title: "Blue", sku: "manual-1", price: "25.00", inventory_quantity: 7, inventory_management: "shopify", inventory_item_id: 9012 }] }] },
          { Link: "<https://" + SHOP + "/admin/api/2026-07/products.json?limit=250&page_info=p2>; rel=\"next\"" }));
      }
      if (/\/inventory_items\.json$/.test(u.pathname)) {
        return Promise.resolve(reply(200, { inventory_items: [{ id: 9011, cost: "10.00" }, { id: 9012, cost: "9.00" }, { id: 9021, cost: null }] }));
      }
      if (/\/orders\.json$/.test(u.pathname)) {
        if (u.searchParams.get("page_info") === "o2") {
          return Promise.resolve(reply(200, { orders: [Object.assign({ id: 5002, created_at: "2026-11-02T09:00:00Z", total_price: "18.00", currency: "USD",
            line_items: [{ sku: "SCARF", quantity: 1, name: "Scarf", price: "18.00", vendor: "Demo" }] }, orderBase)] }));
        }
        return Promise.resolve(reply(200, { orders: [Object.assign({ id: 5001, created_at: "2026-11-01T10:00:00Z", total_price: "50.00", currency: "usd",
          line_items: [{ sku: "HAT-RED", quantity: 2, name: "Wool Hat - Red", price: "25.00" }] }, orderBase)] },
          { Link: "<https://" + SHOP + "/admin/api/2026-07/orders.json?limit=250&page_info=o2>; rel=\"next\"" }));
      }
    }
    if (u.origin === WOO) {
      if (o.wooStatus !== 200) return Promise.resolve(reply(o.wooStatus, { code: "woocommerce_rest_cannot_view" }));
      const page = Number(u.searchParams.get("page") || 1);
      if (u.pathname === "/wp-json/wc/v3/products" && u.searchParams.get("per_page") === "1") return Promise.resolve(reply(200, [{ id: 1 }]));
      if (u.pathname === "/wp-json/wc/v3/products") {
        if (page === 1) {
          const list = [];
          for (let i = 1; i <= 99; i++) list.push({ id: 100 + i, name: "Mug " + i, type: "simple", sku: "MUG-" + i, price: "12.00", stock_quantity: i, manage_stock: true });
          list.push({ id: 300, name: "T-shirt", type: "variable", sku: "", price: "20.00", stock_quantity: null, manage_stock: false });
          return Promise.resolve(reply(200, list, { "X-WP-TotalPages": "2" }));
        }
        return Promise.resolve(reply(200, [{ id: 400, name: "Poster", type: "simple", sku: "POSTER", price: "", stock_quantity: null, manage_stock: false }], { "X-WP-TotalPages": "2" }));
      }
      if (u.pathname === "/wp-json/wc/v3/products/300/variations") {
        return Promise.resolve(reply(200, [{ id: 301, sku: "TEE-M", price: "20.00", stock_quantity: 3, manage_stock: true, attributes: [{ name: "Size", option: "M" }] }], { "X-WP-TotalPages": "1" }));
      }
      if (u.pathname === "/wp-json/wc/v3/orders") {
        return Promise.resolve(reply(200, [{ id: 7001, date_created_gmt: "2026-11-01T08:00:00", total: "24.00", currency: "EUR", customer_id: 55,
          billing: { first_name: CUSTOMER.first, email: CUSTOMER.email, phone: CUSTOMER.phone, address_1: CUSTOMER.street },
          shipping: { first_name: CUSTOMER.first, address_1: CUSTOMER.street }, customer_note: "Leave at door",
          line_items: [{ sku: "MUG-1", quantity: 2, name: "Mug 1", price: 12 }] }], { "X-WP-TotalPages": "1" }));
      }
    }
    return Promise.resolve(reply(404, { error: "no stub for " + url }));
  }
  return { fetch: fetchStub, calls: calls };
}

/* ── the routes, run from server.js's own source ─────────────────────────── */
const START = "/* ── Store connections, read-only (migration 163, lib/storeSync.js) ──────────";
const END = "// The SEO writer used to answer in JSON, which meant embedding a whole HTML";
const SECTION = (function () {
  const a = FILES.server.indexOf(START), b = FILES.server.indexOf(END, a);
  return a === -1 || b === -1 ? "" : FILES.server.slice(a, b);
})();
function requireAuth() {} function requireActiveSubscription() {}
function mountRoutes(env) {
  const db = makeDb();
  const stores = makeStores(env.stores);
  const logs = [];
  const routes = {};
  const sleeps = [];
  const ctx = {
    supabase: db,
    process: { env: Object.assign({ ENCRYPTION_SECRET: SECRET_HEX }, env.env || {}) },
    console: { log: function () { logs.push([].slice.call(arguments).join(" ")); }, error: function () { logs.push([].slice.call(arguments).join(" ")); }, warn: function () { logs.push([].slice.call(arguments).join(" ")); } },
    rateLimit: function (o) { return { limiter: o }; },
    requireAuth: requireAuth, requireActiveSubscription: requireActiveSubscription,
    nowIso: function () { return new Date().toISOString(); },
    isValidUuid: function (v) { return /^[0-9a-f-]{36}$/.test(String(v)); },
    getUserPlan: async function (uid) { return { active: (env.inactive || []).indexOf(uid) === -1 }; },
    FRONTEND_URL: "https://bizforceai.net",
    fetch: stores.fetch,
    AbortSignal: { timeout: function () { return undefined; } },
    setTimeout: function (fn, ms) { sleeps.push(ms); fn(); return 0; },
    Promise: Promise, Buffer: Buffer, URL: URL, Date: Date, JSON: JSON, Object: Object, Array: Array, String: String, Number: Number, Math: Math,
    require: function (r) {
      if (r === "./lib/storeSync") return SS;
      if (r === "./lib/apiKeyCrypto") return { encrypt: function (p) { return CRYPT.encrypt(p); }, decrypt: function (x) { return CRYPT.decrypt(x); } };
      if (r === "./lib/guardedFetch") return GF;
      if (r === "dns") return { promises: { lookup: async function () { return env.lookup || [{ address: "93.184.216.34", family: 4 }]; } } };
      return realRequire(r);
    },
    app: {}
  };
  ["get", "post", "put", "delete"].forEach(function (m) {
    ctx.app[m] = function (p) { const args = [].slice.call(arguments, 1); routes[m + " " + p] = { middleware: args.slice(0, -1), handler: args[args.length - 1] }; };
  });
  if (ctx.process.env.ENCRYPTION_SECRET === null) delete ctx.process.env.ENCRYPTION_SECRET;
  const saved = process.env.ENCRYPTION_SECRET;
  vm.createContext(ctx);
  vm.runInContext(SECTION, ctx, { filename: "server.js (store section)" });
  return { db: db, stores: stores, logs: logs, routes: routes, sleeps: sleeps, ctx: ctx, saved: saved };
}
async function hit(m, key, req) {
  const r = m.routes[key];
  const res = { statusCode: 200, body: undefined, status: function (c) { this.statusCode = c; return this; }, json: function (b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
  let err = null;
  try { await r.handler(Object.assign({ user: { id: USER }, body: {}, params: {} }, req), res, function (e) { err = e || new Error("next"); }); }
  catch (e) { err = e; res.statusCode = 599; }
  return { status: res.statusCode, body: res.body || {}, err: err };
}
function noSecretIn(text, secrets) { return secrets.every(function (s) { return String(text).indexOf(s) === -1; }); }

/* lib-level deps for the sync and the tick */
function libDeps(db, stores, extra) {
  const sleeps = [];
  return Object.assign({
    supabase: db, env: {}, fetch: stores.fetch, now: function () { return Date.parse("2026-11-03T05:00:00.000Z"); },
    sleep: function (ms) { sleeps.push(ms); return Promise.resolve(); }, sleeps: sleeps,
    lookup: async function () { return [{ address: "93.184.216.34", family: 4 }]; }, isBlockedAddress: GF.isBlockedAddress,
    encrypt: CRYPT.encrypt, decrypt: CRYPT.decrypt,
    userPlan: async function () { return { plan: { active: true }, error: null }; }
  }, extra || {});
}
function shopifyConn(db, userId) {
  const sealed = SS.sealCredentials({ access_token: TOKEN }, CRYPT.encrypt);
  const row = Object.assign({ id: uuid(), user_id: userId || USER, platform: "shopify", store_url: SHOP, status: "connected", created_at: "2026-11-01T00:00:00.000Z" }, sealed);
  db.t.member_store_connections.push(row);
  return row;
}

(async function main() {
  check("the store section of server.js was found", SECTION.length > 1000);

  /* ── V ── */
  console.log("\n══ V. validation ══");
  check("V1. Shopify: only *.myshopify.com, with or without https:// and a path",
    SS.normalizeShopifyDomain("https://Demo-Shop.myshopify.com/admin") === SHOP && SS.normalizeShopifyDomain(SHOP) === SHOP &&
    SS.normalizeShopifyDomain("evil.com") === null && SS.normalizeShopifyDomain("demo.myshopify.com.evil.com") === null &&
    SS.normalizeShopifyDomain("demo@myshopify.com") === null && SS.normalizeShopifyDomain("") === null);
  check("V2. WooCommerce: https only; no IP, no user or password, no other port",
    SS.normalizeWooUrl("https://woo.example.com/shop/") === WOO && SS.normalizeWooUrl("http://woo.example.com") === null &&
    SS.normalizeWooUrl("https://127.0.0.1") === null && SS.normalizeWooUrl("https://user:pw@woo.example.com") === null &&
    SS.normalizeWooUrl("https://woo.example.com:8443") === null && SS.normalizeWooUrl("https://localhost") === null);

  /* ── C ── */
  console.log("\n══ C. connecting Shopify through the route ══");
  let m = mountRoutes({});
  const connect = m.routes["post /api/store/connections"];
  const lim = connect.middleware[2] && connect.middleware[2].limiter;
  check("C1. connect is requireAuth, requireActiveSubscription and 5 an hour",
    connect.middleware[0] === requireAuth && connect.middleware[1] === requireActiveSubscription && lim && lim.max === 5 && lim.windowMs === 3600000);
  let r = await hit(m, "post /api/store/connections", { body: { platform: "shopify", store_url: "https://" + SHOP, access_token: TOKEN } });
  const row = m.db.t.member_store_connections[0] || {};
  check("C2. a read-only token: 200, one GET to access_scopes, the connection stored", r.status === 200 && !!r.body && r.body.saved === true &&
    m.stores.calls.length === 1 && m.stores.calls[0].method === "GET" && /access_scopes\.json$/.test(m.stores.calls[0].url) && row.status === "connected" && row.store_url === SHOP, J([r.status, r.body, m.stores.calls.length]));
  let opened = null;
  try { opened = SS.openCredentials(row, CRYPT.decrypt); } catch (e) { opened = null; }
  check("C3. stored ENCRYPTED: hex columns without the token, which decrypt to it", /^[0-9a-f]+$/.test(row.credentials_ciphertext || "") &&
    noSecretIn(J(row), [TOKEN, "shpat_"]) && opened && opened.access_token === TOKEN, J(row).slice(0, 200));
  check("C4. the token is in no response and no log line", !!r.body && noSecretIn(J(r.body), [TOKEN, row.credentials_ciphertext || "x-none"]) && noSecretIn(m.logs.join("\n"), [TOKEN]),
    J(r.body));
  for (const [label, opts, code] of [
    ["a token with a write_ scope", { scopes: ["read_products", "read_inventory", "read_orders", "write_products"] }, "write_scope"],
    ["a token missing read_orders", { scopes: ["read_products", "read_inventory"] }, "missing_scope"],
    ["a token Shopify refuses (401)", { verifyStatus: 401 }, "shopify_rejected"]]) {
    const mm = mountRoutes({ stores: opts });
    const rr = await hit(mm, "post /api/store/connections", { body: { platform: "shopify", store_url: SHOP, access_token: TOKEN } });
    check("C5. " + label + ": refused (" + code + "), with a clear message, and NOTHING stored",
      rr.status === 400 && rr.body.code === code && rr.body.saved === false && typeof rr.body.error === "string" && rr.body.error.length > 30 &&
      mm.db.t.member_store_connections.length === 0 && mm.stores.calls.length === 1, J([rr.status, rr.body, mm.db.t.member_store_connections.length]));
  }
  const mw = mountRoutes({ stores: { scopes: ["read_products", "write_inventory"] } });
  const rw = await hit(mw, "post /api/store/connections", { body: { platform: "shopify", store_url: SHOP, access_token: TOKEN } });
  check("C6. ...the write-scope message says what to do", rw.body && /write_/.test(rw.body.error || "") && /read_products, read_inventory and read_orders/.test(rw.body.error || ""));
  const mb = mountRoutes({});
  const rb = await hit(mb, "post /api/store/connections", { body: { platform: "shopify", store_url: "evil.com", access_token: TOKEN } });
  check("C7. a domain that is not *.myshopify.com: 400 before any request", rb.status === 400 && rb.body.code === "shopify_domain" && mb.stores.calls.length === 0);
  const mn = mountRoutes({ env: { ENCRYPTION_SECRET: "" } });
  process.env.ENCRYPTION_SECRET = "";
  const rn = await hit(mn, "post /api/store/connections", { body: { platform: "shopify", store_url: SHOP, access_token: TOKEN } });
  process.env.ENCRYPTION_SECRET = SECRET_HEX;
  check("C8. a server without ENCRYPTION_SECRET: 503, nothing sent to Shopify, nothing stored",
    rn.status === 503 && rn.body.code === "no_encryption_key" && mn.stores.calls.length === 0 && mn.db.t.member_store_connections.length === 0, J([rn.status, rn.body]));

  /* ── W ── */
  console.log("\n══ W. connecting WooCommerce ══");
  m = mountRoutes({});
  r = await hit(m, "post /api/store/connections", { body: { platform: "woocommerce", store_url: "https://woo.example.com/" } });
  const auth = r.body && r.body.authorize_url ? new URL(r.body.authorize_url) : null;
  check("W1. the route answers the store's own authorization page, asking for scope=read, with BizForce's callback; nothing stored yet",
    r.status === 200 && auth && auth.origin === WOO && auth.pathname === "/wc-auth/v1/authorize" && auth.searchParams.get("scope") === "read" &&
    /\/api\/store\/woocommerce\/callback$/.test(auth.searchParams.get("callback_url")) && m.db.t.member_store_connections.length === 0 && m.stores.calls.length === 0, J(r.body));
  const state = auth ? auth.searchParams.get("user_id") : "";
  const rh = await hit(m, "post /api/store/connections", { body: { platform: "woocommerce", store_url: "http://woo.example.com" } });
  check("W2. an http address is refused", rh.status === 400 && rh.body.code === "woo_url");
  const cb = m.routes["post /api/store/woocommerce/callback"];
  check("W3. the callback is public (the store calls it) and rate-limited", cb.middleware.length === 1 && cb.middleware[0].limiter && cb.middleware[0].limiter.max === 30);
  for (const perm of ["read_write", "write"]) {
    const rr = await hit(m, "post /api/store/woocommerce/callback", { user: undefined, body: { user_id: state, key_permissions: perm, consumer_key: CK, consumer_secret: CS } });
    check("W4. a key with permission \"" + perm + "\": refused, nothing stored, no request", rr.status === 400 && rr.body.code === "not_read_only" &&
      m.db.t.member_store_connections.length === 0 && m.stores.calls.length === 0, J(rr.body));
  }
  const forged = state.split(".")[0] + "." + Buffer.from("x".repeat(32)).toString("base64url");
  const rf = await hit(m, "post /api/store/woocommerce/callback", { body: { user_id: forged, key_permissions: "read", consumer_key: CK, consumer_secret: CS } });
  const expired = SS.makeWooState(USER, WOO, Date.now() - 31 * 60 * 1000, SECRET_HEX);
  const re = await hit(m, "post /api/store/woocommerce/callback", { body: { user_id: expired, key_permissions: "read", consumer_key: CK, consumer_secret: CS } });
  check("W5. a forged state and an expired one: refused, nothing stored", rf.status === 400 && re.status === 400 && m.db.t.member_store_connections.length === 0);
  const mr = mountRoutes({ stores: { wooStatus: 401 } });
  const rr401 = await hit(mr, "post /api/store/woocommerce/callback", { body: { user_id: state, key_permissions: "read", consumer_key: CK, consumer_secret: CS } });
  check("W6. a read key the store refuses: nothing stored", rr401.status === 400 && mr.db.t.member_store_connections.length === 0 && mr.stores.calls.length === 1);
  const mp = mountRoutes({ lookup: [{ address: "10.0.0.5", family: 4 }] });
  const rpv = await hit(mp, "post /api/store/woocommerce/callback", { body: { user_id: state, key_permissions: "read", consumer_key: CK, consumer_secret: CS } });
  check("W7. a store that resolves to a private address: refused before any request, nothing stored", rpv.status === 400 && mp.stores.calls.length === 0 && mp.db.t.member_store_connections.length === 0);
  const rok = await hit(m, "post /api/store/woocommerce/callback", { body: { user_id: state, key_permissions: "read", consumer_key: CK, consumer_secret: CS } });
  const wrow = m.db.t.member_store_connections[0] || {};
  let wopen = null; try { wopen = SS.openCredentials(wrow, CRYPT.decrypt); } catch (e) { wopen = null; }
  check("W8. a read key: one GET to the store with Basic auth, stored encrypted for the member the state names",
    rok.status === 200 && m.stores.calls.length === 1 && m.stores.calls[0].method === "GET" && /^Basic /.test(m.stores.calls[0].headers.Authorization || "") &&
    wrow.user_id === USER && wrow.platform === "woocommerce" && wrow.store_url === WOO && wopen && wopen.consumer_key === CK && wopen.consumer_secret === CS &&
    noSecretIn(J(wrow), [CK, CS]), J([rok.status, m.stores.calls.length, wrow.user_id]));
  check("W9. the key and secret are in no response and no log", noSecretIn(J(rok.body), [CK, CS]) && noSecretIn(m.logs.join("\n"), [CK, CS]));

  /* ── S ── */
  console.log("\n══ S. status ══");
  r = await hit(m, "get /api/store/connections", {});
  const st = (r.body.connections || [])[0] || {};
  check("S1. status answers exactly the safe fields", J(Object.keys(st).sort()) === J(["connected_since", "id", "last_error_code", "last_sync_at", "platform", "platform_label", "status", "store"]) &&
    !/ciphertext|credential|auth_tag|_iv/.test(J(r.body)), J(r.body));
  check("S2. the list and disconnect need only a login (a member can always take their key back)",
    m.routes["get /api/store/connections"].middleware.length === 1 && m.routes["get /api/store/connections"].middleware[0] === requireAuth &&
    m.routes["delete /api/store/connections/:id"].middleware.length === 1 && m.routes["delete /api/store/connections/:id"].middleware[0] === requireAuth);

  /* ── Y ── */
  console.log("\n══ Y. the sync ══");
  m = mountRoutes({ stores: { first429: true } });
  const conn = shopifyConn(m.db);
  const manualSku = { id: uuid(), user_id: USER, name: "My own blue hat", sku: "MANUAL-1", quantity_on_hand: 99, reorder_point: 5, unit_cost: 3, unit_price: 30, source: null, store_connection_id: null, external_id: null, status: "active" };
  const manualNoSku = { id: uuid(), user_id: USER, name: "Hand-made sign", sku: null, quantity_on_hand: 2, reorder_point: 1, source: null, store_connection_id: null, external_id: null, status: "active" };
  const otherUser = { id: uuid(), user_id: OTHER, name: "Someone else's hat", sku: "HAT-RED", quantity_on_hand: 1, source: null, store_connection_id: null, external_id: null, status: "active" };
  m.db.t.inventory_items.push(Object.assign({}, manualSku), Object.assign({}, manualNoSku), Object.assign({}, otherUser));
  const sn = m.routes["post /api/store/connections/:id/sync"];
  check("Y0. sync now is requireAuth, requireActiveSubscription and 6 a day",
    sn.middleware[0] === requireAuth && sn.middleware[1] === requireActiveSubscription && sn.middleware[2].limiter.max === 6 && sn.middleware[2].limiter.windowMs === 86400000);
  r = await hit(m, "post /api/store/connections/:id/sync", { params: { id: conn.id } });
  const synced = m.db.t.inventory_items.filter(function (x) { return x.store_connection_id === conn.id; });
  const hat = synced.find(function (x) { return x.external_id === "variant:11"; }) || {};
  const scarf = synced.find(function (x) { return x.external_id === "variant:21"; }) || {};
  check("Y1. products and variants map: name, SKU, price, cost, stock, source shopify",
    r.status === 200 && hat.name === "Wool Hat - Red" && hat.sku === "HAT-RED" && hat.unit_price === 25 && hat.unit_cost === 10 && hat.quantity_on_hand === 4 && hat.source === "shopify" &&
    scarf.name === "Scarf" && scarf.quantity_on_hand === 0 && scarf.unit_cost === null && scarf.user_id === USER, J([r.status, r.body, hat, scarf]));
  check("Y2. both pages were read (the Link header was followed), and the stock the store does not track was skipped, not written as 0",
    m.stores.calls.some(function (c) { return /page_info=p2/.test(c.url); }) && !synced.some(function (x) { return x.external_id === "variant:22"; }) && r.body.synced && r.body.synced.skipped_untracked === 1, J(r.body));
  const mine1 = m.db.t.inventory_items.find(function (x) { return x.id === manualSku.id; });
  const mine2 = m.db.t.inventory_items.find(function (x) { return x.id === manualNoSku.id; });
  const theirs = m.db.t.inventory_items.find(function (x) { return x.id === otherUser.id; });
  check("Y3. the member's own row with the same SKU (manual-1 vs MANUAL-1) is left exactly as it was, and the store's product is skipped and counted",
    J(mine1) === J(manualSku) && J(mine2) === J(manualNoSku) && !synced.some(function (x) { return x.external_id === "variant:12"; }) && r.body.synced.skipped_sku_manual === 1 &&
    J(theirs) === J(otherUser), J([mine1, r.body.synced]));
  check("Y4. a 429 was waited out (Retry-After: 2 s) and retried, and the sync finished", m.sleeps.indexOf(2000) !== -1 && r.body.synced.items_written === 2, J(m.sleeps.slice(0, 8)));
  const orders = m.db.t.store_order_summaries;
  const allowed = ["connection_id", "created_at", "currency", "external_id", "id", "line_items", "ordered_at", "platform", "total", "updated_at", "user_id"];
  check("Y5. orders: two summaries, across two pages, with the total, the currency and the items as SKU and quantity",
    orders.length === 2 && orders.some(function (o) { return o.external_id === "5001" && o.total === 50 && o.currency === "USD" && J(o.line_items) === J([{ sku: "HAT-RED", quantity: 2 }]); }), J(orders));
  check("Y6. an order summary has exactly the summary columns, and NO customer field anywhere",
    orders.every(function (o) { return J(Object.keys(o).sort()) === J(allowed); }) &&
    noSecretIn(J(orders), [CUSTOMER.email, CUSTOMER.phone, CUSTOMER.first, CUSTOMER.last, CUSTOMER.street, "customer", "billing", "shipping"]), J(orders[0]));
  check("Y7. the orders were asked for with fields limited to id, date, total, currency and line items",
    m.stores.calls.filter(function (c) { return /orders\.json/.test(c.url) && !/page_info/.test(c.url); }).every(function (c) { return /fields=id,created_at,total_price,currency,line_items/.test(c.url); }));
  m.db.t.inventory_items.find(function (x) { return x.external_id === "variant:11"; }).reorder_point = 6;
  const before = m.db.t.inventory_items.length;
  r = await hit(m, "post /api/store/connections/:id/sync", { params: { id: conn.id } });
  const hat2 = m.db.t.inventory_items.find(function (x) { return x.external_id === "variant:11"; }) || {};
  check("Y8. a second sync updates in place: no duplicate rows or orders, and the member's reorder point on a synced row stays",
    r.status === 200 && m.db.t.inventory_items.length === before && m.db.t.store_order_summaries.length === 2 && hat2.reorder_point === 6, J([r.status, m.db.t.inventory_items.length, before]));
  check("Y9. every request to the store was a GET, never followed a redirect, and went only to the shop", m.stores.calls.length > 6 &&
    m.stores.calls.every(function (c) { return c.method === "GET" && c.redirect === "manual" && new URL(c.url).hostname === SHOP; }), J(m.stores.calls.map(function (c) { return c.method; })));
  check("Y10. the connection records the sync time, and no log line holds the token", !!(m.db.t.member_store_connections[0] || {}).last_sync_at && noSecretIn(m.logs.join("\n"), [TOKEN]));

  // WooCommerce through the lib
  const wdb = makeDb(), wst = makeStores({});
  const wsealed = SS.sealCredentials({ consumer_key: CK, consumer_secret: CS }, CRYPT.encrypt);
  const wconn = Object.assign({ id: uuid(), user_id: USER, platform: "woocommerce", store_url: WOO, status: "connected" }, wsealed);
  wdb.t.member_store_connections.push(wconn);
  const wres = await SS.syncConnection(libDeps(wdb, wst), wconn);
  const witems = wdb.t.inventory_items;
  const tee = witems.find(function (x) { return x.external_id === "variation:301"; }) || {};
  check("Y11. WooCommerce: 99 simple products and a variation across two pages, source woocommerce; unmanaged stock skipped",
    wres.ok === true && witems.length === 100 && tee.name === "T-shirt - M" && tee.quantity_on_hand === 3 && tee.source === "woocommerce" &&
    !witems.some(function (x) { return x.external_id === "product:400" || x.external_id === "product:300"; }) && wres.skipped_untracked === 1 &&
    wst.calls.some(function (c) { return /page=2/.test(c.url); }), J([wres, witems.length, tee]));
  const wo = wdb.t.store_order_summaries[0] || {};
  check("Y12. WooCommerce order summary: date (UTC), total, currency, SKU and quantity, and NO customer field",
    wdb.t.store_order_summaries.length === 1 && wo.ordered_at === "2026-11-01T08:00:00Z" && wo.total === 24 && wo.currency === "EUR" &&
    noSecretIn(J(wdb.t.store_order_summaries), [CUSTOMER.email, CUSTOMER.phone, CUSTOMER.first, CUSTOMER.street, "customer", "billing", "Leave at door"]), J(wo));
  check("Y13. every WooCommerce request was a GET to the store, with Basic auth", wst.calls.length > 3 &&
    wst.calls.every(function (c) { return c.method === "GET" && new URL(c.url).origin === WOO && /^Basic /.test(c.headers.Authorization); }));
  const sm = SS.summaryOf("shopify", { id: 1, created_at: "2026-11-01T00:00:00Z", total_price: "1.00", currency: "USD", email: "a@b.c", customer: { email: "a@b.c" }, line_items: [{ sku: "X", quantity: 1, name: "secret name" }] });
  check("Y14. summaryOf keeps exactly external_id, ordered_at, total, currency and line_items of SKU and quantity",
    J(Object.keys(sm).sort()) === J(SS.SUMMARY_KEYS.slice().sort()) && J(sm.line_items) === J([{ sku: "X", quantity: 1 }]) && J(sm).indexOf("a@b.c") === -1, J(sm));

  /* ── A ── */
  console.log("\n══ A. an auth failure: needs_reconnect, one notice, no retry loop ══");
  const adb = makeDb(), ast = makeStores({ productsStatus: 401 });
  const aconn = shopifyConn(adb);
  const ad = libDeps(adb, ast);
  const a1 = await SS.syncConnection(ad, aconn);
  const productCalls = ast.calls.filter(function (c) { return /products\.json/.test(c.url); }).length;
  check("A1. a 401: needs_reconnect, ONE request (no retry), one notice", a1.ok === false && a1.needs_reconnect === true && productCalls === 1 &&
    adb.t.member_store_connections[0].status === "needs_reconnect" && adb.t.notifications.length === 1 && adb.t.notifications[0].type === "store_reconnect", J([a1, productCalls, adb.t.notifications.length]));
  check("A2. the notice says what to do and holds no key", /Connect the store again on the Store Agent page/.test(adb.t.notifications[0] && adb.t.notifications[0].message) && noSecretIn(J(adb.t.notifications), [TOKEN]));
  const a2 = await SS.syncConnection(ad, Object.assign({}, aconn, { status: "connected" }));
  check("A3. a second failure finds nothing to mark and sends no second notice", a2.needs_reconnect === true && adb.t.notifications.length === 1, adb.t.notifications.length);
  const am = mountRoutes({});
  const amc = shopifyConn(am.db); amc.status = "needs_reconnect";
  const ar = await hit(am, "post /api/store/connections/:id/sync", { params: { id: amc.id } });
  check("A4. sync now on a store that needs reconnecting: 409, no request", ar.status === 409 && am.stores.calls.length === 0);
  const pass = await SS.runStoreSyncPass(libDeps(adb, ast));
  check("A5. the daily pass skips it (it reads connected stores only)", pass.stores === 0, J(pass));

  /* ── J ── */
  console.log("\n══ J. the daily sync: ENABLE_STORE_SYNC exactly \"true\", its own claim ══");
  check("J1. the gate: only exactly \"true\"", SS.storeSyncEnabled({ ENABLE_STORE_SYNC: "true" }) === true && SS.storeSyncEnabled({}) === false &&
    SS.storeSyncEnabled({ ENABLE_STORE_SYNC: "True" }) === false && SS.storeSyncEnabled({ ENABLE_STORE_SYNC: "1" }) === false);
  const jdb = makeDb(), jst = makeStores({});
  shopifyConn(jdb, USER);
  shopifyConn(jdb, OTHER).store_url = "other-shop.myshopify.com";
  const off = await SS.storeSyncTick(libDeps(jdb, jst, { env: {} }), Date.parse("2026-11-03T05:00:00Z"));
  check("J2. unset: nothing claimed, nothing read", off.claimed === false && jdb.t.job_runs.length === 0 && jst.calls.length === 0);
  const on = libDeps(jdb, jst, { env: { ENABLE_STORE_SYNC: "true" }, userPlan: async function (uid) { return uid === OTHER ? { plan: { active: false }, error: null } : { plan: { active: true }, error: null }; } });
  const t1 = await SS.storeSyncTick(on, Date.parse("2026-11-03T05:00:00Z"));
  const jr = jdb.t.job_runs.find(function (x) { return x.job_name === "store_sync"; }) || {};
  check("J3. \"true\": claims job_runs.store_sync for 2026-11-03 and syncs the entitled member's store only",
    t1.claimed === true && jr.last_run_on === "2026-11-03" && t1.summary.synced === 1 && t1.summary.skipped_not_entitled === 1 &&
    jst.calls.every(function (c) { return new URL(c.url).hostname === SHOP; }), J([t1, jr]));
  const n1 = jst.calls.length;
  const t2 = await SS.storeSyncTick(on, Date.parse("2026-11-03T05:30:00Z"));
  check("J4. a second tick the same day reads nothing", t2.claimed === false && jst.calls.length === n1);
  const both = await Promise.all([SS.storeSyncTick(on, Date.parse("2026-11-04T05:00:00Z")), SS.storeSyncTick(on, Date.parse("2026-11-04T05:00:00Z"))]);
  check("J5. the next day, two ticks at once: exactly one claims", both.filter(function (b) { return b.claimed; }).length === 1, J(both.map(function (b) { return b.claimed; })));
  const errPlan = libDeps(makeDb(), makeStores({}), { userPlan: async function () { return { plan: null, error: new Error("down") }; } });
  shopifyConn(errPlan.supabase);
  const ep = await SS.runStoreSyncPass(errPlan);
  check("J6. a plan lookup that fails skips the store; it never syncs", ep.skipped_not_entitled === 1 && ep.synced === 0);

  /* ── D ── */
  console.log("\n══ D. disconnect, account deletion and the export ══");
  m = mountRoutes({});
  const dconn = shopifyConn(m.db);
  m.db.t.inventory_items.push(Object.assign({}, manualSku));
  await hit(m, "post /api/store/connections/:id/sync", { params: { id: dconn.id } });
  const hadItems = m.db.t.inventory_items.filter(function (x) { return x.store_connection_id === dconn.id; }).length;
  const hadOrders = m.db.t.store_order_summaries.length;
  r = await hit(m, "delete /api/store/connections/:id", { params: { id: dconn.id } });
  check("D1. disconnect deletes the connection, its synced rows and its order summaries, and keeps the member's own rows",
    r.status === 200 && hadItems === 2 && hadOrders === 2 && m.db.t.member_store_connections.length === 0 && m.db.t.store_order_summaries.length === 0 &&
    m.db.t.inventory_items.length === 1 && m.db.t.inventory_items[0].id === manualSku.id, J([r.status, hadItems, hadOrders, m.db.t.inventory_items.length]));
  check("D2. ...and says how to revoke the key in the store", /uninstall the custom app/.test(r.body.note) && /REST API/.test(r.body.note));
  const r404 = await hit(m, "delete /api/store/connections/:id", { params: { id: uuid() } });
  check("D3. someone else's or an unknown connection: 404", r404.status === 404);
  const YD = realRequire("./lib/yourData");
  const entry = function (tname) { return (YD.DATA || []).find(function (e) { return e.table === tname; }); };
  const yd = FILES.yourData;
  const ce = entry("member_store_connections"), oe = entry("store_order_summaries");
  check("D4. the export: connections with safe fields only (never the credentials), order summaries without customer fields",
    ce && ce.onDelete === "delete" && /^platform, store_url, status, created_at, last_sync_at$/.test(ce.select) && oe && oe.onDelete === "delete" &&
    oe.select === "platform, external_id, ordered_at, total, currency, line_items", J([ce, oe]));
  check("D5. the account delete removes both: summaries in DELETE_ORDER, connections in FINAL_DELETES",
    /"inventory_items", "store_order_summaries", "calendar_events"/.test(yd) && /"member_social_connections", "member_store_connections",/.test(yd));
  const BK = realRequire("./lib/backup"), SC = realRequire("./lib/schemaCheck");
  check("D6. in the backup lists (the key excluded, the summaries skipped) and the schema list, tagged 163",
    !!BK.EXCLUDED_TABLES.member_store_connections && !!BK.SKIPPED_TABLES.store_order_summaries &&
    SC.migrationFor("member_store_connections") === "supabase/migrations/163_store_connections.sql" && SC.migrationFor("store_order_summaries") === "supabase/migrations/163_store_connections.sql");

  /* ── R ── */
  console.log("\n══ R. the readers read synced stock ══");
  const items = [
    { id: "i1", name: "Wool Hat - Red", sku: "HAT-RED", unit: "unit", quantity_on_hand: 2, reorder_point: 3, unit_cost: 10, unit_price: 25, status: "active", source: "shopify" },
    { id: "i2", name: "Mug 1", sku: "MUG-1", unit: "unit", quantity_on_hand: 1, reorder_point: 1, unit_cost: null, unit_price: 12, status: "active", source: "woocommerce" },
    { id: "i3", name: "Hand-made sign", sku: null, unit: "unit", quantity_on_hand: 9, reorder_point: 1, unit_cost: 2, unit_price: 5, status: "active", source: null }
  ];
  const measureSrc = MUT.definitionOf(FILES.server, "measureStockAndMargin");
  const helpers = ["storeStockFigure", "storeStockCents"].map(function (n) { return MUT.definitionOf(FILES.server, n); }).join("\n");
  const mctx = { STORE_STOCK_MIN_OUT_MOVEMENTS: 3 };
  vm.createContext(mctx);
  vm.runInContext(helpers + "\n" + measureSrc + "\nthis.measure = measureStockAndMargin;", mctx);
  const measured = mctx.measure(items, [], 30);
  check("R1. Stock & Margin measures synced items and names each one's source; both synced items are at their reorder point",
    measured.items === 3 && J(measured.stock.map(function (s) { return s.source; })) === J(["shopify", "woocommerce", "manual"]) &&
    measured.items_at_or_below_reorder_point === 2, J([measured.items, measured.stock.map(function (s) { return s.source; }), measured.items_at_or_below_reorder_point]));
  check("R2. its read selects source", /\.select\("id, name, sku, unit, quantity_on_hand, reorder_point, unit_cost, unit_price, status, source"\)\n/.test(FILES.server));
  const TR = realRequire("./lib/triggerRunner");
  const tdb = makeDb();
  items.forEach(function (it) { tdb.t.inventory_items.push(Object.assign({ user_id: USER }, it)); });
  const mv = await TR.metricValue({ supabase: tdb }, USER, { metric: "stock_at_reorder", window: "now" }, Date.now());
  check("R3. the \"Items at their reorder point\" trigger counts the synced items, from the member's own reorder points", mv && mv.value === 2, J(mv));
  const SIG = realRequire("./lib/agentSignatures");
  let sig = null;
  try { sig = SIG.build("store", { items: { rows: items }, trades: { rows: { trades: [] } } }, { measureStock: mctx.measure, pendingFor: 0 }); } catch (e) { sig = { error: String(e) }; }
  const sigStock = sig && (sig.stock || (sig.body && sig.body.stock));
  check("R4. the Store signature counts stock by source", sigStock && J(sigStock.sources) === J({ manual: 1, shopify: 1, woocommerce: 1 }), J(sig).slice(0, 300));
  check("R5. the live panel shows the stock's source (manual / Shopify / WooCommerce)",
    /sigTile\("Stock source"/.test(FILES.profile) && /"Manual " \+ src\.manual/.test(FILES.profile) && /"Shopify " \+ src\.shopify/.test(FILES.profile) && /"WooCommerce " \+ src\.woocommerce/.test(FILES.profile));
  check("R6. a movement on a synced item is refused (its stock belongs to the store)", /if \(syncedItem && syncedItem\.source\) \{/.test(FILES.server));

  /* ── N ── */
  console.log("\n══ N. no write call to either platform, anywhere ══");
  // A line comment starts at a // that is not part of a URL (https://...).
  const codeOnly = FILES.sync.replace(/(^|[^:])\/\/[^\n]*/g, "$1").replace(/\/\*[\s\S]*?\*\//g, "");
  // The method names in capitals (a variable named patch and the database's .delete() are not requests),
  // and any method: that is not "GET", in any case.
  const writeWord = codeOnly.match(/\b(POST|PUT|PATCH|DELETE)\b/) || codeOnly.match(/method\s*:\s*["'`](?!GET["'`])[A-Za-z]+/i);
  check("N1. lib/storeSync.js holds no POST, PUT, PATCH or DELETE, and no method but GET", !writeWord, writeWord && writeWord[0]);
  const fetchCalls = codeOnly.match(/\bfetch\(/g) || [];
  check("N2. ...and exactly one fetch call, and it sends method \"GET\"", fetchCalls.length === 1 && /deps\.fetch\(url, \{ method: "GET", /.test(codeOnly), fetchCalls.length);
  check("N3. the routes call no store themselves: the store section's only fetch is the GET-only wrapper handed to lib/storeSync.js",
    (SECTION.match(/\bfetch\(/g) || []).length === 1 && /fetch: function \(url, init\) \{ return fetch\(url, init\); \}/.test(SECTION));
  const files = cp.execFileSync("git", ["ls-files", "*.js"], { cwd: REPO }).toString().trim().split(/\r?\n/).filter(function (f) { return !/^scripts\//.test(f) && f !== "lib/storeSync.js"; });
  const named = files.filter(function (f) { return /myshopify\.com|\/wp-json\/wc\/|\/admin\/api\//.test(fs.readFileSync(path.join(REPO, f), "utf8")); });
  check("N4. no other non-script file names a store's API host or path", named.length === 0, named.join(", "));
  check("N5. the stubbed stores saw only GET in this whole run", [m.stores, wst, ast, jst].every(function (s) { return s.calls.every(function (c) { return c.method === "GET"; }); }));

  /* ── L ── */
  console.log("\n══ L. the Privacy page, the Store page, the migration, no emoji ══");
  const LP = realRequire("./lib/legalPages");
  const esc = function (t) { return String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"); };
  const sentence = LP.STORE_PRIVACY_SENTENCE || "";
  check("L1. the Privacy sentence says what is stored, never customer details, own agents only, deleted on disconnect or with the account",
    /encrypted/.test(sentence) && /never any customer's name, email, address or phone number/.test(sentence) && /used only for your own agents/.test(sentence) &&
    /deleted when you disconnect the store or delete your account/.test(sentence) && /never\s+changes anything in your store/.test(sentence));
  check("L2. privacy.html carries it once, as built", sentence.length > 100 && FILES.privacy.split(esc(sentence)).length === 2);
  check("L3. the Store page says \"BizForce only reads your store. It never changes your products, prices or orders.\" and loads the card's script",
    FILES.page.indexOf("BizForce only reads your store. It never changes your products, prices or orders.") !== -1 && /<script src="\/scripts\/store-connect\.js"><\/script>/.test(FILES.page) &&
    /id="storeConnect"/.test(FILES.page));
  check("L4. the steps: Shopify's three read scopes and the shpat_ token; WooCommerce's Read approval and where to revoke it",
    /read_products<\/code>, <code>read_inventory<\/code> and <code>read_orders<\/code>/.test(FILES.page) && /shpat_/.test(FILES.page) &&
    /approve Read access for BizForce AI/.test(FILES.page) && /Settings, Advanced, REST API/.test(FILES.page));
  check("L5. the card shows \"Connected to <store>\", Last synced, Sync now, Disconnect and the reconnect state",
    /"Connected to " \+ c\.store/.test(FILES.ui) && /"Last synced: "/.test(FILES.ui) && /"Sync now"/.test(FILES.ui) && /"Disconnect"/.test(FILES.ui) && /needs_reconnect/.test(FILES.ui) &&
    /tokenEl\.value = "";/.test(FILES.ui));
  check("L6. the migration turns RLS on for both tables and keeps credentials hex-only",
    /ALTER TABLE public\.member_store_connections ENABLE ROW LEVEL SECURITY;/.test(FILES.migration) && /ALTER TABLE public\.store_order_summaries ENABLE ROW LEVEL SECURITY;/.test(FILES.migration) &&
    /CHECK \(credentials_ciphertext ~ '\^\[0-9a-f\]\+\$'\)/.test(FILES.migration) && /UNIQUE \(user_id, platform, store_url\)/.test(FILES.migration));
  check("L7. README has the ENABLE_STORE_SYNC row and the job row", /\| `ENABLE_STORE_SYNC` \| off \| Exactly `true`/.test(FILES.readme) && /\| `storeSyncTick`: [^\n]*cron `0 5 \* \* \*`, UTC, claimed `store_sync`/.test(FILES.readme));
  const migFiles = fs.readdirSync(path.join(REPO, "supabase/migrations")).filter(function (f) { return /^\d+_/.test(f); });
  /* NAMED (the Bluesky Mentions inbox, Nov 3 2026): BEFORE "the only migration numbered 163, and the highest" (every number
     <= 163). AFTER 164_bluesky_reply_refs.sql follows it, so the pin is "the only one numbered 163, every other one but 164 is
     lower, and 162 came before it"; "the highest" is now checkBlueskyMentions M3's, for 164. */
  check("L9. 163_store_connections.sql is the only migration numbered 163, every one before it is lower (162 was the last before it)",
    migFiles.filter(function (f) { return /^163_/.test(f); }).length === 1 &&
    migFiles.filter(function (f) { return !/^164_bluesky_reply_refs\.sql$/.test(f); }).every(function (f) { return Number(f.split("_")[0]) <= 163; }) &&
    migFiles.some(function (f) { return /^162_/.test(f); }));
  const EMOJI = /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{1F000}-\u{1F2FF}\u{FE0F}]/u;
  const fresh = { "lib/storeSync.js": FILES.sync, "163_store_connections.sql": FILES.migration, "scripts/store-connect.js": FILES.ui, "store-agent.html": FILES.page };
  check("L8. no emoji in any new or edited store file", Object.keys(fresh).every(function (k) { return !EMOJI.test(fresh[k]); }), Object.keys(fresh).filter(function (k) { return EMOJI.test(fresh[k]); }).join(", "));

  check("no unhandled rejection", UNHANDLED.length === 0, UNHANDLED.map(String).join("; "));
  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(function (e) { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
