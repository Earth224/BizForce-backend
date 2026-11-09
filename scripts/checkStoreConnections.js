/* checkStoreConnections: store connections, read-only. Shopify and WooCommerce stock and order totals, no customer data.

   WHAT IT PROVES (lib/storeSync.js, its routes and cron in server.js, migration 163, the export and delete,
   the Privacy page and the Store agent page). Both platforms are stubbed: no request leaves this process.

     V. VALIDATION. A Shopify domain is *.myshopify.com and nothing else; a WooCommerce address is https only,
        with no IP address, no user or password and no other port.
     C. CONNECTING SHOPIFY. NAMED (Nov 7 2026, Shopify on OAuth, migration 176): BEFORE a pasted shpat_ token was
        verified by one GET to access_scopes.json and stored encrypted through POST /api/store/connections. AFTER
        that route answers 400 use_connect_shopify for a Shopify body, whatever token it carries, storing nothing
        and asking nothing; Connect Shopify is /api/store/shopify/start and /finish (requireAuth,
        requireActiveSubscription, 10 an hour), 503 without SHOPIFY_CLIENT_ID and SHOPIFY_CLIENT_SECRET, and the
        list says shopify_available. The OAuth flow itself is scripts/checkShopifyConnect.js's.
     W. CONNECTING WOOCOMMERCE. The route answers the store's own authorization page with scope=read. The
        callback refuses a key whose permission is not "read", a forged or expired state, a key the store
        refuses and a store on a private address, and stores nothing; a read key is verified by one GET and
        stored encrypted.
     S. STATUS answers safe fields only.
     Y. THE SYNC. Products, variants, SKUs, prices, costs and stock map into inventory_items marked with their
        source, across pages, with a 429 waited out (Retry-After) and retried; untracked stock is skipped, not
        written as 0; a member's own row with the same SKU is never overwritten; a second sync updates in place
        and keeps the member's reorder point. Order summaries hold exactly the summary keys and NO customer
        field, whatever the store sends. Every WooCommerce request is a GET; NAMED (Nov 7 2026, migration 176):
        BEFORE every Shopify request was a REST GET too. AFTER the sync reads a shop through lib/shopifyApi.js
        (deps.shopifyReader): each request a POST of a GraphQL "query" document to the shop's graphql.json, paged
        by cursor, never a mutation; the shop's currency is stored on the connection.
     A. AN AUTH FAILURE marks needs_reconnect with ONE notice, after ONE request (no retry loop), and a second
        failure says nothing more; sync now on it is refused without a request.
     J. THE DAILY SYNC runs only with ENABLE_STORE_SYNC exactly "true", claims job_runs.store_sync for the UTC
        day (a second tick and a concurrent one run nothing), and skips a member without an active plan.
     D. DISCONNECT deletes the connection, its synced rows and its order summaries, and leaves manual rows; the
        account delete and the export cover both new tables, and the export never names the credentials.
     R. THE READERS. Stock & Margin (server.js measureStockAndMargin), the "Items at their reorder point"
        trigger (lib/triggerRunner.js) and the Store signature (lib/agentSignatures.js) all read synced stock,
        and the signature says where stock came from.
     N. NO WRITE CALL from the sync: lib/storeSync.js holds no POST, PUT, PATCH or DELETE, no fetch,
        http.request or https.request, and one request call, deps.jsonRequest, with method "GET" (NAMED Nov 3
        2026: it was one fetch). NAMED (Nov 7 2026, migration 176): BEFORE lib/storeSync.js read Shopify itself and
        lib/storeWrite.js was the only other file that named a store's API path. AFTER lib/storeSync.js names no
        Shopify request at all; lib/shopifyApi.js has exactly two deps.jsonRequest calls (readQuery, which refuses
        any document but a query, and sendOnce) and the word "mutation" only inside writePrice and writeStock;
        lib/shopifyApi.js and lib/shopifyAuth.js may name the shop's paths, lib/storeWrite.js still names none.
     L. THE PRIVACY SENTENCE is built into privacy.html; the Store page says when BizForce changes something
        and has the steps for both platforms; the migration turns RLS on; no emoji in any new file.

   MUTATIONS — MUTATE=<name> applies one in memory; MUTATE=all runs each:
     plaintext-credentials     the connection is stored with the key in the clear
     customer-email-stored     an order summary keeps the customer's email
     manual-row-overwritten    a synced product takes over a member's own row with the same SKU
     auth-failure-retried      a Shopify 401 is retried like a 429
     shopify-write-call        a function that deletes a Shopify product is added to lib/storeSync.js
     double-run                the daily tick runs without claiming the day
     woo-not-read-only         a WooCommerce key with read_write permission is accepted
     NAMED (store connections security fix, Nov 3 2026), section G:
     woo-plain-fetch           WooCommerce pages are read with a plain fetch, not the guarded fetcher
     shopify-plain-fetch       Shopify reads are sent with a plain fetch
     redirect-followed         a redirect the guarded fetcher refused is followed with a plain fetch
     size-unbounded            the body limit asked for is raised past 8 MB
     too-large-retried         a body over the limit is retried
     guard-refusal-retried     a guard refusal (a blocked address, a refused option) is retried
     woo-orders-fields-widened WooCommerce orders ask for whole line items again
     NAMED (Nov 7 2026, Shopify on OAuth, migration 176): BEFORE write-scope-accepted (a pasted token with a
     write_ scope accepted), paging-header-dropped (the link header no longer exposed),
     shopify-page-size-reverted (SHOPIFY_PAGE_SIZE 250) and page-cap-shrunk (PAGE_CAPS shopifyProducts and
     shopifyOrders 40), all on REST code that is gone. AFTER:
     pasted-token-back         the old connect route takes a Shopify body again
     cursor-ignored            the variants are always asked from the first page, never by endCursor
     shopify-page-size-reverted  Shopify variants go back to 250 a page
     page-cap-shrunk           Shopify's page caps fall back to 40
     read-sends-mutation       readQuery stops refusing a document that is not a query

   G. THE GUARDED FETCHER (NAMED Nov 3 2026). Every store request, Shopify and WooCommerce, is a deps.jsonRequest
      call (lib/guardedFetch.js's guardedJsonRequest), 8 MB and 20 s. A name that answers a private or loopback
      address is refused by the fetcher's own lookup, once, never retried; a 3xx is refused and its target never
      asked; a page over 8 MB is too_large, asked once, recorded and logged as too_large with no URL, and the member
      is told what an unreachable store tells them. WooCommerce orders ask only line_items.sku and
      line_items.quantity, and WooCommerce pages are 100, 40 pages at most. NAMED (Nov 7 2026, migration 176):
      BEFORE every request was a GET exposing retry-after, link and x-wp-totalpages, and Shopify paged 50 a page by
      the link header, 200 pages of products and of orders. AFTER WooCommerce GETs expose retry-after and
      x-wp-totalpages; Shopify reads are POSTs of a query document exposing retry-after only, 50 variants a page and
      20 orders of at most 40 line items a page (Shopify's query cost cap), by cursor, 200 pages of each. A network
      tripwire fails the run if anything opens a socket, asks real DNS or fetches.
*/
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const crypto = require("crypto");
const Module = require("module");
const cp = require("child_process");
const MUT = require("./_shared");
const { EventEmitter } = require("events");
const { PassThrough } = require("stream");

const REPO = path.join(__dirname, "..");
const FE = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const read = (f) => fs.readFileSync(path.join(REPO, f), "utf8");
const readFe = (f) => fs.readFileSync(path.join(FE, f), "utf8");

const MUTATIONS = {
  "plaintext-credentials": ["sync",
    "  return { credentials_ciphertext: sealed.ciphertext, credentials_iv: sealed.iv, credentials_auth_tag: sealed.authTag };\n",
    "  return { credentials_ciphertext: plain, credentials_iv: sealed.iv, credentials_auth_tag: sealed.authTag };\n"],
  "customer-email-stored": ["sync",
    "    currency: currency,\n    line_items:", "    currency: currency,\n    email: o.email || (o.billing && o.billing.email) || null,\n    line_items:"],
  "manual-row-overwritten": ["sync",
    "      if (owner && !mine && owner.source == null) { result.skipped_sku_manual++; return; }\n",
    "      if (owner && !mine && owner.source == null) { supabase.from(\"inventory_items\").update({ name: it.name, quantity_on_hand: it.quantity_on_hand }).eq(\"id\", owner.id).then(function () {}); result.skipped_sku_manual++; return; }\n"],
  // NAMED (Nov 7 2026, migration 176): BEFORE on lib/storeSync.js's RETRYABLE, which read Shopify. AFTER on
  // lib/shopifyApi.js's, which does; A1 must still see one GraphQL request for a 401.
  "auth-failure-retried": ["api",
    "var RETRYABLE = [429, 500, 502, 503, 504];\n", "var RETRYABLE = [401, 429, 500, 502, 503, 504];\n"],
  // NAMED (Nov 7 2026, migration 176): BEFORE anchored on "function shopifyUrl(domain, path) {", which is gone. AFTER the
  // same added DELETE call, put just above the WooCommerce section of lib/storeSync.js; N1 must catch it.
  "shopify-write-call": ["sync",
    "/* ── WooCommerce ──",
    "function archiveShopifyProduct(deps, domain, token, id) {\n  return deps.fetch(\"https://\" + domain + \"/admin/api/2026-07/products/\" + id + \".json\", { method: \"DELETE\", headers: { \"X-Shopify-Access-Token\": token } });\n}\n/* ── WooCommerce ──"],
  "double-run": ["sync",
    "    if (!(await claimStoreSyncDay(deps.supabase, startedMs))) {\n", "    if (false) {\n"],
  // NAMED (Nov 6 2026, store changes, migration 175): BEFORE anchored on `if (b.key_permissions !== "read") return`. AFTER
  // checkWooKey compares the key with the permission the signed state asked for (want); the mutation still lets a
  // read_write key through when read was asked, which W4 must catch.
  "woo-not-read-only": ["sync",
    "  if (b.key_permissions !== want) {\n", "  if (b.key_permissions !== want && b.key_permissions !== \"read_write\") {\n"],
  // NAMED (store connections security fix, Nov 3 2026): every store request through the guarded fetcher (section G)
  "woo-plain-fetch": ["sync",
    "    var got = await request(deps, wooUrl(storeUrl, path + (path.indexOf(\"?\") === -1 ? \"?\" : \"&\") + \"per_page=100&page=\" + page), wooHeaders(creds));\n",
    "    var got = await (async function (u, h) { var r = await fetch(u, { method: \"GET\", headers: h, redirect: \"manual\" }); return { data: await r.json(), headers: r.headers }; })(wooUrl(storeUrl, path + (path.indexOf(\"?\") === -1 ? \"?\" : \"&\") + \"per_page=100&page=\" + page), wooHeaders(creds));\n"],
  // NAMED (Nov 7 2026, migration 176): BEFORE on the REST products read in lib/storeSync.js. AFTER on the one read request
  // in lib/shopifyApi.js's readQuery.
  "shopify-plain-fetch": ["api",
    "      answer = await deps.jsonRequest(graphqlUrl(shop), { method: \"POST\", headers: headersFor(token), body: { query: doc, variables: variables || {} },\n        exposeHeaders: EXPOSED_HEADERS, maxBytes: REQUEST_MAX_BODY_BYTES, timeoutMs: REQUEST_TIMEOUT_MS });\n",
    "      answer = await (async function (u, h, b) { var r = await fetch(u, { method: \"POST\", headers: h, body: JSON.stringify(b) }); return { status: r.status, json: await r.json(), headers: {} }; })(graphqlUrl(shop), headersFor(token), { query: doc, variables: variables || {} });\n"],
  "redirect-followed": ["sync",
    "      var guard = err && err.guardedFetch === true ? String(err.code) : null;\n",
    "      var guard = err && err.guardedFetch === true ? String(err.code) : null;\n      if (guard === \"redirected\") { var f = await fetch(url, { method: \"GET\", headers: headers, redirect: \"follow\" }); return { data: await f.json(), headers: headerReader({}) }; }\n"],
  "size-unbounded": ["sync",
    "var REQUEST_MAX_BODY_BYTES = 8 * 1024 * 1024;", "var REQUEST_MAX_BODY_BYTES = 64 * 1024 * 1024;"],
  "too-large-retried": ["sync",
    "var GUARD_RETRIED = [\"network\", \"timeout\"];", "var GUARD_RETRIED = [\"network\", \"timeout\", \"too_large\"];"],
  "guard-refusal-retried": ["sync",
    "      if (guard === null || GUARD_RETRIED.indexOf(guard) === -1) {\n", "      if (guard !== null && GUARD_RETRIED.indexOf(guard) === -1 && guard !== \"blocked\") {\n"],
  "woo-orders-fields-widened": ["sync",
    "var WOO_ORDER_FIELDS = \"id,date_created_gmt,total,currency,line_items.sku,line_items.quantity\";", "var WOO_ORDER_FIELDS = \"id,date_created_gmt,total,currency,line_items\";"],
  // NAMED (Nov 7 2026, Shopify on OAuth, migration 176): the REST mutations paging-header-dropped and
  // write-scope-accepted are gone with their code; these hold what replaced it.
  "pasted-token-back": ["server",
    "      if (body.platform === \"shopify\") {\n        return res.status(400).json({ error: require(\"./lib/shopifyAuth\").MESSAGES.useConnect, code: \"use_connect_shopify\", saved: false });\n      }\n",
    "      if (false) {\n        return res.status(400).json({ error: require(\"./lib/shopifyAuth\").MESSAGES.useConnect, code: \"use_connect_shopify\", saved: false });\n      }\n"],
  "cursor-ignored": ["api",
    "location ? { cursor: cursor, location: location } : { cursor: cursor });", "location ? { cursor: null, location: location } : { cursor: null });"],
  "shopify-page-size-reverted": ["api",
    "var PAGE_SIZE = 50;", "var PAGE_SIZE = 250;"],
  "page-cap-shrunk": ["api",
    "var PAGE_CAPS = { variants: 200, orders: 200 };", "var PAGE_CAPS = { variants: 40, orders: 40 };"],
  "read-sends-mutation": ["api",
    "  if (typeof doc !== \"string\" || !/^query\\b/.test(doc)) throw new SS.StoreRequestError(\"not_a_query\");\n",
    "  if (typeof doc !== \"string\") throw new SS.StoreRequestError(\"not_a_query\");\n"]
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
  // NAMED (Nov 7 2026, migration 176): Shopify's GraphQL reader and its OAuth helpers, compiled from these texts below.
  api: read("lib/shopifyApi.js"),
  auth: read("lib/shopifyAuth.js"),
  migration176: read("supabase/migrations/176_shopify_oauth.sql"),
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
// The same storeSync instance for both, so StoreAuthError and StoreRequestError are one class each.
const SA = compile(FILES.auth, "lib/shopifyAuth.js", {});
const SAPI = compile(FILES.api, "lib/shopifyApi.js", { "./storeSync": SS, "./shopifyAuth": SA });
const SHOPIFY_CONFIG = { clientId: "check-client-id", clientSecret: "check-client-secret-" + "9".repeat(20) };

const USER = "00000000-0000-4000-8000-000000000001";
const OTHER = "00000000-0000-4000-8000-000000000002";
const SHOP = "demo-shop.myshopify.com";
// NAMED (Nov 7 2026, migration 176): BEFORE a pasted shpat_ token. AFTER an expiring OAuth access token and its refresh token.
const TOKEN = "shpca_" + "a1b2c3d4".repeat(4);
const REFRESH = "shprt_" + "e5f6a7b8".repeat(4);
const GRAPHQL_PATH = "/admin/api/2026-07/graphql.json";
const LOCATION = "gid://shopify/Location/71";
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
      // NAMED (Nov 7 2026, migration 176): member_store_connections_token_shape_check, as the migration has it.
      const access = row.access_ciphertext != null && row.access_iv != null && row.access_auth_tag != null && row.access_expires_at != null;
      const none = row.access_ciphertext == null && row.access_iv == null && row.access_auth_tag == null && row.access_expires_at == null &&
        row.refresh_expires_at == null && row.location_id == null && row.location_name == null;
      if (!((row.platform === "shopify" && access) || (row.platform === "woocommerce" && none))) return "member_store_connections_token_shape_check";
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
      // NAMED (Nov 7 2026, migration 176): the Shopify routes filter with is, gt and lt too.
      is: function (c, v) { q.filters.push(["is", c, v]); return api; },
      gt: function (c, v) { q.filters.push(["gt", c, v]); return api; },
      lt: function (c, v) { q.filters.push(["lt", c, v]); return api; },
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
        if (f[0] === "is") return f[2] === null ? r[f[1]] == null : r[f[1]] === f[2];
        if (f[0] === "gt") return r[f[1]] != null && String(r[f[1]]) > String(f[2]);
        if (f[0] === "lt") return r[f[1]] != null && String(r[f[1]]) < String(f[2]);
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
/* NAMED (store connections security fix, Nov 3 2026): BEFORE the stores were a stand-in for fetch, handed to
   lib/storeSync.js as deps.fetch (and to the routes as the global fetch), with deps.lookup for the WooCommerce
   host check. AFTER every request goes through deps.jsonRequest, and deps.jsonRequest here is the REAL guarded
   fetcher (GF.createGuardedFetch) with only its two edges stood in: `resolve` (the DNS answer, public unless a
   test says otherwise) and `request` (https.request; it asks the fetcher's OWN lookup where to connect, exactly
   as Node does, and only a request that lookup allowed reaches the store's answer and is counted in calls). So
   the address check, the redirect refusal, the size limit and the exposed headers are the real ones. No socket
   is opened: the network tripwire below fails the run if anything tries. */
function headers(obj) {
  const h = {}; Object.keys(obj || {}).forEach(function (k) { h[k.toLowerCase()] = String(obj[k]); });
  return { get: function (k) { return Object.prototype.hasOwnProperty.call(h, k.toLowerCase()) ? h[k.toLowerCase()] : null; } };
}
function reply(status, body, hdrs) {
  const h = { "content-type": "application/json; charset=utf-8" };
  Object.keys(hdrs || {}).forEach(function (k) { h[k.toLowerCase()] = String(hdrs[k]); });
  return { status: status, headers: h, raw: Buffer.isBuffer(body) ? body : Buffer.from(JSON.stringify(body), "utf8") };
}
const PUBLIC_V4 = "93.184.216.34";
const OVER_8MB = function () { return Buffer.from("\"" + "a".repeat(8 * 1024 * 1024) + "\"", "utf8"); };
function makeStores(opts) {
  const o = Object.assign({ first429: false, wooStatus: 200 }, opts || {});
  const calls = [];       // requests the guarded fetcher let through to a store
  const asked = [];       // every deps.jsonRequest call: the url and the options storeSync passed
  const resolved = {};    // DNS questions, by name
  let sent429 = false;
  const orderBase = {
    email: CUSTOMER.email, phone: CUSTOMER.phone, contact_email: CUSTOMER.email,
    customer: { first_name: CUSTOMER.first, last_name: CUSTOMER.last, email: CUSTOMER.email, phone: CUSTOMER.phone },
    billing_address: { name: CUSTOMER.first + " " + CUSTOMER.last, address1: CUSTOMER.street, phone: CUSTOMER.phone },
    shipping_address: { name: CUSTOMER.first + " " + CUSTOMER.last, address1: CUSTOMER.street }
  };
  /* NAMED (Nov 7 2026, Shopify on OAuth, migration 176): BEFORE the shop answered REST GETs (access_scopes.json,
     products.json, inventory_items.json, orders.json) paged by a Link header. AFTER it answers what lib/shopifyApi.js
     sends: a POST of { query, variables } to graphql.json, by operation name (ShopInfo, Variants, VariantsAt, Orders),
     paged by endCursor; and the token endpoint, which refuses a refresh unless o.refreshOk. The same products, stock,
     costs and orders as before, and the same customer fields offered on every order. */
  function variant(id, productId, productTitle, title, sku, price, qty, itemId, tracked, cost) {
    return { id: "gid://shopify/ProductVariant/" + id, sku: sku, title: title, price: price, compareAtPrice: null, inventoryQuantity: qty,
      product: { id: "gid://shopify/Product/" + productId, title: productTitle },
      inventoryItem: { id: "gid://shopify/InventoryItem/" + itemId, tracked: tracked, unitCost: cost === null ? null : { amount: cost },
        inventoryLevel: { quantities: [{ name: "available", quantity: qty === null ? 0 : Math.max(0, qty - 1) }] } } };
  }
  function order(id, at, amount, lines) {
    return Object.assign({ id: "gid://shopify/Order/" + id, createdAt: at, totalPriceSet: { shopMoney: { amount: amount, currencyCode: "USD" } },
      lineItems: { nodes: lines } }, orderBase);
  }
  function graphql(op, vars) {
    if (o.shopStatus) return reply(o.shopStatus, { errors: "[API] Invalid API key or access token" });
    if (o.shopHuge) return reply(200, OVER_8MB());
    if (op === "ShopInfo") {
      return reply(200, { data: { shop: { currencyCode: "CAD" }, locations: { nodes: o.locations || [{ id: LOCATION, name: "Main warehouse", isActive: true }] } } });
    }
    if (op === "Variants" || op === "VariantsAt") {
      if (o.first429 && !sent429) { sent429 = true; return reply(429, { errors: "Exceeded 2 calls per second" }, { "Retry-After": "2" }); }
      if (o.variantsHuge) return reply(200, OVER_8MB());
      if (o.endless) {
        const n = Number(String(vars.cursor || "e0").slice(1));
        return reply(200, { data: { productVariants: { pageInfo: { hasNextPage: true, endCursor: "e" + (n + 1) },
          nodes: [variant(5000 + n, 1000 + n, "P" + n, "Default Title", "", "1.00", 1, 7000 + n, false, null)] } } });
      }
      if (vars.cursor === "c2") {
        return reply(200, { data: { productVariants: { pageInfo: { hasNextPage: false, endCursor: "c3" }, nodes: [
          variant(21, 2, "Scarf", "Default Title", "SCARF", "18.00", 0, 9021, true, null),
          variant(22, 2, "Gift wrap", "Default Title", "WRAP", "2.00", 0, 9022, false, null)] } } }, { "Set-Cookie": "_shopify_s=checkOnly" });
      }
      return reply(200, { data: { productVariants: { pageInfo: { hasNextPage: true, endCursor: "c2" }, nodes: [
        variant(11, 1, "Wool Hat", "Red", "HAT-RED", "25.00", 4, 9011, true, "10.00"),
        variant(12, 1, "Wool Hat", "Blue", "manual-1", "25.00", 7, 9012, true, "9.00")] } } });
    }
    if (op === "Orders") {
      if (o.endless) {
        const n = Number(String(vars.cursor || "e0").slice(1));
        return reply(200, { data: { orders: { pageInfo: { hasNextPage: true, endCursor: "e" + (n + 1) }, nodes: [order(80000 + n, "2026-11-01T10:00:00Z", "1.00", [])] } } });
      }
      if (vars.cursor === "o2") {
        return reply(200, { data: { orders: { pageInfo: { hasNextPage: false, endCursor: "o3" },
          nodes: [order(5002, "2026-11-02T09:00:00Z", "18.00", [{ sku: "SCARF", quantity: 1, name: "Scarf", vendor: "Demo" }])] } } });
      }
      return reply(200, { data: { orders: { pageInfo: { hasNextPage: true, endCursor: "o2" },
        nodes: [order(5001, "2026-11-01T10:00:00Z", "50.00", [{ sku: "HAT-RED", quantity: 2, name: "Wool Hat - Red" }])] } } });
    }
    return reply(200, { errors: [{ message: "no stub for " + op }] });
  }
  function answer(url, init) {
    let body = null;
    try { body = init && init.body ? JSON.parse(String(init.body)) : null; } catch (e) { body = null; }
    const opMatch = body && typeof body.query === "string" ? /^(query|mutation)\s+([A-Za-z]+)/.exec(body.query) : null;
    calls.push({ url: url, method: (init && init.method) || "GET", headers: (init && init.headers) || {}, body: body, op: opMatch ? opMatch[2] : null, kind: opMatch ? opMatch[1] : null });
    const u = new URL(url);
    if (o.networkDown) return { error: Object.assign(new Error("socket hang up"), { code: "ECONNRESET" }) };
    if (u.hostname === SHOP || u.hostname === "other-shop.myshopify.com") {
      if (u.pathname === "/admin/oauth/access_token") {
        if (!o.refreshOk) return reply(400, { error: "invalid_request", error_description: "refresh token expired or revoked" });
        return reply(200, { access_token: TOKEN + "n", refresh_token: REFRESH + "n", expires_in: 3600, refresh_token_expires_in: 7776000, scope: "read_products,read_inventory,read_orders,read_locations" });
      }
      if (u.pathname === GRAPHQL_PATH && (init && init.method) === "POST" && opMatch) return graphql(opMatch[2], (body && body.variables) || {});
    }
    if (u.origin === WOO) {
      if (o.wooStatus !== 200) return reply(o.wooStatus, { code: "woocommerce_rest_cannot_view" });
      if (o.wooRedirect) return { status: 302, headers: { location: "http://169.254.169.254/latest/meta-data/" }, raw: Buffer.alloc(0) };
      const page = Number(u.searchParams.get("page") || 1);
      if (u.pathname === "/wp-json/wc/v3/products" && u.searchParams.get("per_page") === "1") return reply(200, [{ id: 1 }]);
      if (u.pathname === "/wp-json/wc/v3/products") {
        if (o.wooEndless || o.wooOneFullPage) {
          const list = [];
          for (let i = 1; i <= 100; i++) list.push({ id: page * 1000 + i, name: "Row " + i, type: "simple", sku: "", price: "1.00", stock_quantity: null, manage_stock: false });
          return reply(200, list, { "X-WP-TotalPages": o.wooEndless ? "999" : "1" });
        }
        if (page === 1) {
          const list = [];
          for (let i = 1; i <= 99; i++) list.push({ id: 100 + i, name: "Mug " + i, type: "simple", sku: "MUG-" + i, price: "12.00", stock_quantity: i, manage_stock: true });
          list.push({ id: 300, name: "T-shirt", type: "variable", sku: "", price: "20.00", stock_quantity: null, manage_stock: false });
          return reply(200, list, { "X-WP-TotalPages": "2" });
        }
        return reply(200, [{ id: 400, name: "Poster", type: "simple", sku: "POSTER", price: "", stock_quantity: null, manage_stock: false }], { "X-WP-TotalPages": "2" });
      }
      // NAMED (Nov 7 2026, migration 176): the store's currency, read once a sync (best effort).
      if (u.pathname === "/wp-json/wc/v3/data/currencies/current") return reply(200, { code: "EUR", name: "Euro", symbol: "&euro;" });
      if (u.pathname === "/wp-json/wc/v3/products/300/variations") {
        return reply(200, [{ id: 301, sku: "TEE-M", price: "20.00", stock_quantity: 3, manage_stock: true, attributes: [{ name: "Size", option: "M" }] }], { "X-WP-TotalPages": "1" });
      }
      if (u.pathname === "/wp-json/wc/v3/orders") {
        if (o.wooOrdersHuge) return reply(200, OVER_8MB());
        return reply(200, [{ id: 7001, date_created_gmt: "2026-11-01T08:00:00", total: "24.00", currency: "EUR", customer_id: 55,
          billing: { first_name: CUSTOMER.first, email: CUSTOMER.email, phone: CUSTOMER.phone, address_1: CUSTOMER.street },
          shipping: { first_name: CUSTOMER.first, address_1: CUSTOMER.street }, customer_note: "Leave at door",
          line_items: [{ sku: "MUG-1", quantity: 2, name: "Mug 1", price: 12 }] }], { "X-WP-TotalPages": "1" });
      }
    }
    if (u.hostname === "169.254.169.254") return reply(200, { secret: "metadata" });
    return reply(404, { error: "no stub for " + url });
  }
  // the DNS stand-in: o.addresses answers for every name, else a public address
  function resolve(hostname, lookupOptions, cb) {
    resolved[hostname] = (resolved[hostname] || 0) + 1;
    const list = typeof o.addresses === "function" ? o.addresses(hostname) : o.addresses;
    return cb(null, list || [{ address: PUBLIC_V4, family: 4 }]);
  }
  // the https.request stand-in: the fetcher's own lookup decides; only then does the store answer
  function transport(options) {
    const req = new EventEmitter();
    req.destroy = function () {};
    // NAMED (Nov 7 2026, migration 176): the body the fetcher ends the request with is handed on (Shopify's reads are POSTs).
    req.end = function (payload) {
      process.nextTick(function () {
        options.lookup(options.hostname, { all: true }, function (err, addresses) {
          if (err) return req.emit("error", err);
          const url = "https://" + options.hostname + options.path;
          const r = answer(url, { method: options.method, headers: options.headers, body: payload ? Buffer.from(payload).toString("utf8") : null, address: Array.isArray(addresses) ? addresses[0].address : addresses });
          if (r.error) return req.emit("error", r.error);
          const res = new PassThrough();
          res.statusCode = r.status;
          res.headers = r.headers;
          req.emit("response", res);
          res.end(r.raw);
        });
      });
    };
    return req;
  }
  const guarded = GF.createGuardedFetch({ resolve: resolve, request: transport }).json;
  function jsonRequest(url, options) {
    asked.push({ url: url, options: JSON.parse(JSON.stringify(options || {})) });
    return guarded(url, options);
  }
  return { jsonRequest: jsonRequest, calls: calls, asked: asked, resolved: resolved };
}

/* THE NETWORK TRIPWIRE. Nothing in this run may open a socket, resolve a real name or call fetch: each is
   replaced by a function that records the attempt and fails. The check "nothing reached the network" reads it. */
const TRIPPED = [];
(function tripwire() {
  const http = require("http"), https = require("https"), net = require("net"), tls = require("tls"), dns = require("dns");
  function wire(obj, name, label) {
    obj[name] = function () { TRIPPED.push(label); throw new Error("checkStoreConnections: " + label + " is not allowed in this check"); };
  }
  wire(http, "request", "http.request"); wire(http, "get", "http.get");
  wire(https, "request", "https.request"); wire(https, "get", "https.get");
  wire(net, "connect", "net.connect"); wire(net, "createConnection", "net.createConnection");
  wire(tls, "connect", "tls.connect");
  wire(dns, "lookup", "dns.lookup"); wire(dns, "resolve", "dns.resolve"); wire(dns.promises, "lookup", "dns.promises.lookup");
  globalThis.fetch = function () { TRIPPED.push("fetch"); return Promise.reject(new Error("checkStoreConnections: fetch is not allowed in this check")); };
})();

/* ── the routes, run from server.js's own source ─────────────────────────── */
// NAMED (Nov 7 2026, Shopify on OAuth, migration 176): BEFORE the section began "Store connections, read-only
// (migration 163, ...)". AFTER changes are possible with approval and Shopify connects on OAuth, so it names the
// three migrations; the section is still the same block, from here to END.
const START = "/* ── Store connections (migrations 163, 175, 176; lib/storeSync.js) ──────────";
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
    // NAMED (store connections security fix): BEFORE the routes' global fetch was the store stand-in. AFTER it is the
    // tripwire's, and the stores are reached only through require("./lib/guardedFetch").guardedJsonRequest below.
    fetch: globalThis.fetch,
    setTimeout: function (fn, ms) { sleeps.push(ms); fn(); return 0; },
    Promise: Promise, Buffer: Buffer, URL: URL, Date: Date, JSON: JSON, Object: Object, Array: Array, String: String, Number: Number, Math: Math,
    require: function (r) {
      if (r === "./lib/storeSync") return SS;
      if (r === "./lib/apiKeyCrypto") return { encrypt: function (p) { return CRYPT.encrypt(p); }, decrypt: function (x) { return CRYPT.decrypt(x); } };
      if (r === "./lib/guardedFetch") return Object.assign({}, GF, { guardedJsonRequest: stores.jsonRequest });
      // NAMED (Nov 7 2026, migration 176): the Shopify routes and the sync's reader, compiled above from this run's texts.
      if (r === "./lib/shopifyApi") return SAPI;
      if (r === "./lib/shopifyAuth") return SA;
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
  const res = { statusCode: 200, body: undefined, headers: {}, set: function (k, v) { this.headers[k] = v; return this; },
    status: function (c) { this.statusCode = c; return this; }, json: function (b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
  let err = null;
  try { await r.handler(Object.assign({ user: { id: USER }, body: {}, params: {} }, req), res, function (e) { err = e || new Error("next"); }); }
  catch (e) { err = e; res.statusCode = 599; }
  return { status: res.statusCode, body: res.body || {}, err: err };
}
/* What each request must hand the guarded fetcher, and nothing else. NAMED (Nov 7 2026, migration 176): BEFORE one
   shape for both platforms: a GET exposing retry-after, link and x-wp-totalpages. AFTER WooCommerce (lib/storeSync.js)
   is a GET exposing retry-after and x-wp-totalpages; a Shopify read (lib/shopifyApi.js readQuery) is a POST whose body
   is { query, variables } with a "query" document, exposing retry-after only; a token request (lib/shopifyAuth.js) is
   a POST to the shop's /admin/oauth/access_token. Each 8 MB (the default for the token request) and 20 s or less. */
function optionsAsDecided(op) {
  return !!op && J(Object.keys(op).sort()) === J(["exposeHeaders", "headers", "maxBytes", "method", "timeoutMs"]) && op.method === "GET" &&
    J(op.exposeHeaders) === J(["retry-after", "x-wp-totalpages"]) && op.maxBytes === 8 * 1024 * 1024 && op.timeoutMs === 20000;
}
function shopifyReadAsDecided(a) {
  const op = a && a.options;
  return !!op && new URL(a.url).pathname === GRAPHQL_PATH && J(Object.keys(op).sort()) === J(["body", "exposeHeaders", "headers", "maxBytes", "method", "timeoutMs"]) &&
    op.method === "POST" && J(Object.keys(op.body).sort()) === J(["query", "variables"]) && /^query [A-Za-z]+/.test(op.body.query) && !/\bmutation\b/.test(op.body.query) &&
    J(op.exposeHeaders) === J(["retry-after"]) && op.maxBytes === 8 * 1024 * 1024 && op.timeoutMs === 20000 && op.headers["X-Shopify-Access-Token"] !== undefined;
}
function isTokenRequest(a) { return !!a && new URL(a.url).pathname === "/admin/oauth/access_token" && a.options && a.options.method === "POST"; }
function graphqlCalls(stores, op) { return stores.calls.filter(function (c) { return new URL(c.url).pathname === GRAPHQL_PATH && (!op || c.op === op); }); }
function noSecretIn(text, secrets) { return secrets.every(function (s) { return String(text).indexOf(s) === -1; }); }

/* lib-level deps for the sync and the tick */
function libDeps(db, stores, extra) {
  const sleeps = [];
  return Object.assign({
    supabase: db, env: {}, jsonRequest: stores.jsonRequest, now: function () { return Date.parse("2026-11-03T05:00:00.000Z"); },
    sleep: function (ms) { sleeps.push(ms); return Promise.resolve(); }, sleeps: sleeps,
    encrypt: CRYPT.encrypt, decrypt: CRYPT.decrypt,
    // NAMED (Nov 7 2026, migration 176): the sync reads Shopify through lib/shopifyApi.js, with the app's credentials for a refresh.
    shopifyReader: SAPI, shopifyConfig: function () { return SHOPIFY_CONFIG; },
    userPlan: async function () { return { plan: { active: true }, error: null }; }
  }, extra || {});
}
/* NAMED (Nov 7 2026, migration 176): BEFORE the row held a sealed { access_token } in credentials_*. AFTER the
   migration-176 shape: the access token sealed in access_* with its expiry (far off, so no refresh unless a test
   asks), the refresh token sealed in credentials_* as { refresh_token }, token_version 0, the read scopes granted. */
function shopifyConn(db, userId) {
  const sealed = SS.sealCredentials({ refresh_token: REFRESH }, CRYPT.encrypt);
  const access = CRYPT.encrypt(TOKEN);
  const row = Object.assign({ id: uuid(), user_id: userId || USER, platform: "shopify", store_url: SHOP, status: "connected", permission: "read",
    access_ciphertext: access.ciphertext, access_iv: access.iv, access_auth_tag: access.authTag,
    access_expires_at: "2027-06-01T00:00:00.000Z", refresh_expires_at: "2027-09-01T00:00:00.000Z", token_version: 0,
    granted_scopes: "read_products,read_inventory,read_orders,read_locations", location_id: null, location_name: null, currency: null,
    created_at: "2026-11-01T00:00:00.000Z" }, sealed);
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
  /* NAMED (Nov 7 2026, Shopify on OAuth, migration 176): BEFORE C2 to C8 connected a pasted shpat_ token through this route
     (one GET to access_scopes.json, stored encrypted; a write_ scope, a missing read scope, a 401, a bad domain or no
     ENCRYPTION_SECRET refused). AFTER the pasted-token path is removed: whatever a Shopify body carries, the route answers
     400 "Use Connect Shopify on the Store Agent page." (use_connect_shopify), asks nothing and stores nothing. The OAuth
     flow (state, HMAC, timestamp, code exchange, scopes, sealing) is scripts/checkShopifyConnect.js's. */
  let r = await hit(m, "post /api/store/connections", { body: { platform: "shopify", store_url: "https://" + SHOP, access_token: TOKEN } });
  check("C2. a Shopify body with a pasted token: 400 use_connect_shopify, the exact message, nothing asked, nothing stored",
    r.status === 400 && r.body.code === "use_connect_shopify" && r.body.error === "Use Connect Shopify on the Store Agent page." && r.body.saved === false &&
    m.stores.calls.length === 0 && m.db.t.member_store_connections.length === 0, J([r.status, r.body, m.stores.calls.length]));
  check("C3. ...and the token is in no response and no log line", noSecretIn(J(r.body), [TOKEN]) && noSecretIn(m.logs.join("\n"), [TOKEN]));
  const rbare = await hit(m, "post /api/store/connections", { body: { platform: "shopify", store_url: SHOP } });
  check("C4. a Shopify body with no token at all: the same 400", rbare.status === 400 && rbare.body.code === "use_connect_shopify" && m.db.t.member_store_connections.length === 0);
  const start = m.routes["post /api/store/shopify/start"], finish = m.routes["post /api/store/shopify/finish"];
  const sLim = start && start.middleware[2] && start.middleware[2].limiter, fLim = finish && finish.middleware[2] && finish.middleware[2].limiter;
  check("C5. Connect Shopify's start and finish are requireAuth, requireActiveSubscription and 10 an hour, one limiter keyed shopify-connect:<id>",
    !!start && !!finish && start.middleware[0] === requireAuth && start.middleware[1] === requireActiveSubscription &&
    finish.middleware[0] === requireAuth && finish.middleware[1] === requireActiveSubscription && sLim === fLim && sLim.max === 10 && sLim.windowMs === 3600000 &&
    sLim.keyGenerator({ user: { id: USER } }) === "shopify-connect:" + USER);
  const rs = await hit(m, "post /api/store/shopify/start", { body: { shop: SHOP } });
  const rl = await hit(m, "get /api/store/connections", {});
  check("C6. without SHOPIFY_CLIENT_ID and SHOPIFY_CLIENT_SECRET: start answers 503 \"Shopify connection isn't set up yet.\", nothing asked or stored, and the list says shopify_available false",
    rs.status === 503 && rs.body.error === "Shopify connection isn't set up yet." && m.stores.calls.length === 0 && m.db.t.member_store_connections.length === 0 &&
    rl.body.shopify_available === false, J([rs.status, rs.body, rl.body.shopify_available]));
  const mc = mountRoutes({ env: { SHOPIFY_CLIENT_ID: SHOPIFY_CONFIG.clientId, SHOPIFY_CLIENT_SECRET: SHOPIFY_CONFIG.clientSecret } });
  const rb = await hit(mc, "post /api/store/shopify/start", { body: { shop: "evil.com" } });
  const rlc = await hit(mc, "get /api/store/connections", {});
  check("C7. configured: a shop that is not *.myshopify.com is refused before any request, and the list says shopify_available true",
    rb.status === 400 && rb.body.code === "shopify_domain" && mc.stores.calls.length === 0 && rlc.body.shopify_available === true, J([rb.status, rb.body, rlc.body.shopify_available]));
  const rgo = await hit(mc, "post /api/store/shopify/start", { body: { shop: "https://" + SHOP + "/admin" } });
  const goUrl = rgo.body && rgo.body.authorize_url ? new URL(rgo.body.authorize_url) : null;
  check("C8. configured: start answers Shopify's own authorization page on the shop, read scopes only by default, nothing asked of the shop, nothing stored in member_store_connections",
    rgo.status === 200 && goUrl && goUrl.origin === "https://" + SHOP && goUrl.pathname === "/admin/oauth/authorize" &&
    goUrl.searchParams.get("scope") === "read_products,read_inventory,read_orders,read_locations" &&
    goUrl.searchParams.get("redirect_uri") === "https://bizforceai.net/store-agent.html" && mc.stores.calls.length === 0 && mc.db.t.member_store_connections.length === 0,
    J([rgo.status, rgo.body]));

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
  const mp = mountRoutes({ stores: { addresses: [{ address: "10.0.0.5", family: 4 }] } });
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
  // NAMED (Nov 6 2026, store changes, migration 175): BEFORE eight safe fields. AFTER permission too ("read" or
  // "read_write"), so the page can say "Read only" or "Changes allowed with your approval"; still never a credential.
  // NAMED (Nov 7 2026, Shopify on OAuth, migration 176): BEFORE nine fields. AFTER currency, location_id, location_name and
  // stock_scope too (Shopify's location for stock changes; the latter three null on WooCommerce); still never a credential or a token.
  // NAMED (Nov 8 2026, Etsy store connection, migration 181): BEFORE thirteen fields. AFTER shop_name too (an Etsy shop's name,
  // read from its https://www.etsy.com/shop/<ShopName> address; null on WooCommerce and Shopify); still never a credential or a token.
  // NAMED (Nov 8 2026, Amazon store connection, migration 182): BEFORE fourteen fields. AFTER marketplace_id, marketplace (its
  // label) and region too (null except on Amazon); still never a credential or a token.
  check("S1. status answers exactly the safe fields", J(Object.keys(st).sort()) === J(["connected_since", "currency", "id", "last_error_code", "last_sync_at", "location_id", "location_name", "marketplace", "marketplace_id", "permission", "platform", "platform_label", "region", "shop_name", "status", "stock_scope", "store"]) &&
    st.permission === "read" && st.location_id === null && st.stock_scope === null && st.shop_name === null &&
    st.marketplace_id === null && st.marketplace === null && st.region === null &&
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
  // NAMED (Nov 7 2026, migration 176): Y1 adds the inventory item id each row now keeps (Shopify's stock changes need it).
  check("Y1. products and variants map: name, SKU, price, cost, stock, source shopify, and the inventory item id",
    r.status === 200 && hat.name === "Wool Hat - Red" && hat.sku === "HAT-RED" && hat.unit_price === 25 && hat.unit_cost === 10 && hat.quantity_on_hand === 4 && hat.source === "shopify" &&
    hat.external_inventory_item_id === "9011" &&
    scarf.name === "Scarf" && scarf.quantity_on_hand === 0 && scarf.unit_cost === null && scarf.user_id === USER, J([r.status, r.body, hat, scarf]));
  // NAMED (Nov 7 2026, migration 176): BEFORE "the Link header was followed" (page_info=p2). AFTER the second page is asked
  // with the first page's endCursor (c2) as the cursor variable.
  check("Y2. both pages were read (the endCursor was followed), and the stock the store does not track was skipped, not written as 0",
    graphqlCalls(m.stores, "Variants").some(function (c) { return c.body.variables.cursor === "c2"; }) && !synced.some(function (x) { return x.external_id === "variant:22"; }) &&
    r.body.synced && r.body.synced.skipped_untracked === 1, J(r.body));
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
  /* NAMED (Nov 7 2026, migration 176): BEFORE the REST orders URL carried fields=id,created_at,total_price,currency,line_items.
     AFTER the Orders query names its fields: id, createdAt, the total and its currency, and line items' sku and quantity, and
     nothing about a customer; it asks only orders created in the window. */
  const orderAsks = graphqlCalls(m.stores, "Orders");
  check("Y7. the orders were asked for with fields limited to id, date, total, currency and line items' SKU and quantity, since the window's start",
    orderAsks.length >= 2 && orderAsks.every(function (c) {
      const q = c.body.query;
      return /nodes \{ id createdAt totalPriceSet \{ shopMoney \{ amount currencyCode \} \} lineItems\(first: 40\) \{ nodes \{ sku quantity \} \} \}/.test(q) &&
        !/customer|email|phone|billing|shipping|Address|note/i.test(q) && /^created_at:>='\d{4}-\d{2}-\d{2}T/.test(c.body.variables.search);
    }), J(orderAsks.map(function (c) { return c.body; })).slice(0, 400));
  check("Y7b. the shop's currency was read and stored on the connection", (m.db.t.member_store_connections[0] || {}).currency === "CAD" && graphqlCalls(m.stores, "ShopInfo").length >= 1);
  m.db.t.inventory_items.find(function (x) { return x.external_id === "variant:11"; }).reorder_point = 6;
  const before = m.db.t.inventory_items.length;
  r = await hit(m, "post /api/store/connections/:id/sync", { params: { id: conn.id } });
  const hat2 = m.db.t.inventory_items.find(function (x) { return x.external_id === "variant:11"; }) || {};
  check("Y8. a second sync updates in place: no duplicate rows or orders, and the member's reorder point on a synced row stays",
    r.status === 200 && m.db.t.inventory_items.length === before && m.db.t.store_order_summaries.length === 2 && hat2.reorder_point === 6, J([r.status, m.db.t.inventory_items.length, before]));
  /* NAMED (store connections security fix, Nov 3 2026): BEFORE "never followed a redirect" was read off each fetch
     call's redirect: "manual". AFTER there is no fetch: each request is a deps.jsonRequest call (the guarded fetcher,
     which never follows a redirect; G3 proves a 302 is refused and its target never asked), with exactly the options
     decided, and one request reached the shop for each call. Still GET only, still the shop only. */
  // NAMED (Nov 7 2026, migration 176): BEFORE every request was a GET. AFTER every Shopify read is a POST of a "query" document
  // to the shop's graphql.json, never a mutation, with the decided options.
  check("Y9. every request to the store was a POST of a GraphQL query (never a mutation) through deps.jsonRequest with the decided options, and went only to the shop's graphql.json",
    m.stores.calls.length > 6 &&
    m.stores.calls.every(function (c) { return c.method === "POST" && c.kind === "query" && new URL(c.url).hostname === SHOP && new URL(c.url).pathname === GRAPHQL_PATH; }) &&
    m.stores.asked.length === m.stores.calls.length && m.stores.asked.every(shopifyReadAsDecided),
    J([m.stores.calls.map(function (c) { return c.method + " " + c.op; }), m.stores.asked.length, m.stores.calls.length]));
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
  // NAMED (Nov 7 2026, migration 176): a chosen location. The stock is that location's "available", read with VariantsAt.
  const ldb = makeDb(), lst = makeStores({});
  const lconn = shopifyConn(ldb); lconn.location_id = LOCATION; lconn.location_name = "Main warehouse";
  const lres = await SS.syncConnection(libDeps(ldb, lst), lconn);
  const lhat = ldb.t.inventory_items.find(function (x) { return x.external_id === "variant:11"; }) || {};
  check("Y15. with a location chosen, the variants are read at it (VariantsAt, location variable) and the stock is its \"available\", not the total",
    lres.ok === true && lhat.quantity_on_hand === 3 && graphqlCalls(lst, "Variants").length === 0 &&
    graphqlCalls(lst, "VariantsAt").length === 2 && graphqlCalls(lst, "VariantsAt").every(function (c) { return c.body.variables.location === LOCATION; }), J([lres, lhat.quantity_on_hand]));

  /* ── G ── NAMED (store connections security fix, Nov 3 2026) */
  console.log("\n══ G. every store request through the guarded fetcher: no rebinding gap, size-limited, never redirected ══");
  const MB8 = 8 * 1024 * 1024;
  /* NAMED (Nov 7 2026, Shopify on OAuth, migration 176): BEFORE PAGE_CAPS { shopifyProducts: 200, shopifyOrders: 200,
     other: 40 }, SHOPIFY_PAGE_SIZE 50 and three exposed headers (link for Shopify's paging), all in lib/storeSync.js. AFTER
     lib/storeSync.js keeps WooCommerce's (other: 40; retry-after and x-wp-totalpages) and has no Shopify paging at all;
     lib/shopifyApi.js has Shopify's: 50 variants a page, 20 orders of at most 40 line items a page, 200 pages of each,
     8 MB, 20 s, retry-after only. */
  check("G1. the decided limits: WooCommerce 40 pages, Shopify 200 pages of variants and of orders; 8 MB (the guarded fetcher's ceiling); 20 s; WooCommerce exposes two headers, Shopify one",
    J(SS.PAGE_CAPS) === J({ other: 40 }) && SS.SHOPIFY_PAGE_SIZE === undefined && J(SAPI.PAGE_CAPS) === J({ variants: 200, orders: 200 }) &&
    SAPI.PAGE_SIZE === 50 && SAPI.ORDER_PAGE_SIZE === 20 && SAPI.ORDER_LINE_ITEMS === 40 &&
    SS.REQUEST_MAX_BODY_BYTES === MB8 && SAPI.REQUEST_MAX_BODY_BYTES === MB8 && GF.JSON_MAX_BODY_BYTES_CEILING === MB8 && SS.REQUEST_TIMEOUT_MS === 20000 &&
    SAPI.REQUEST_TIMEOUT_MS === 20000 && J(SS.REQUEST_EXPOSED_HEADERS) === J(["retry-after", "x-wp-totalpages"]) && !/\bMAX_PAGES\b/.test(FILES.sync),
    J([SS.PAGE_CAPS, SAPI.PAGE_CAPS, SAPI.PAGE_SIZE, SS.REQUEST_MAX_BODY_BYTES, SS.REQUEST_TIMEOUT_MS, SS.REQUEST_EXPOSED_HEADERS]));
  // NAMED (Nov 7 2026, migration 176): BEFORE the REST limit= parameters (50, 50, and 100 inventory items a call). AFTER the GraphQL first: arguments.
  const vq = (graphqlCalls(m.stores, "Variants")[0] || { body: { query: "" } }).body.query, oq = (graphqlCalls(m.stores, "Orders")[0] || { body: { query: "" } }).body.query;
  check("G2. Shopify asks for variants 50 a page and orders 20 a page with at most 40 line items each, by cursor",
    /productVariants\(first: 50, after: \$cursor\)/.test(vq) && /orders\(first: 20, after: \$cursor, query: \$search, sortKey: CREATED_AT\)/.test(oq) && /lineItems\(first: 40\)/.test(oq), J([vq, oq]).slice(0, 300));
  const wooUrls = wst.calls.map(function (c) { return new URL(c.url); });
  const wOrders = wooUrls.filter(function (u) { return u.pathname === "/wp-json/wc/v3/orders"; });
  // NAMED (Nov 7 2026, migration 176): the one currency read is not a paged request, so it is left out of G4's pages.
  const wPaged = wooUrls.filter(function (u) { return u.searchParams.get("per_page") !== "1" && u.pathname !== "/wp-json/wc/v3/data/currencies/current"; });
  check("G4b. WooCommerce's currency is read once a sync, by GET, and stored on the connection",
    wooUrls.filter(function (u) { return u.pathname === "/wp-json/wc/v3/data/currencies/current"; }).length === 1 && wconn.currency === "EUR" && wres.currency === "EUR", J([wres.currency, wconn.currency]));
  const wFields = wOrders.length ? String(wOrders[0].searchParams.get("_fields")).split(",") : [];
  check("G3. WooCommerce orders ask _fields=id,date_created_gmt,total,currency,line_items.sku,line_items.quantity: the line items' fields by name, never the whole line item",
    wOrders.length === 1 && wOrders[0].searchParams.get("_fields") === "id,date_created_gmt,total,currency,line_items.sku,line_items.quantity" &&
    SS.WOO_ORDER_FIELDS === wOrders[0].searchParams.get("_fields") &&
    wFields.filter(function (f) { return /^line_items/.test(f); }).every(function (f) { return /^line_items\.[a-z_]+$/.test(f); }) && wFields.indexOf("line_items") === -1,
    wOrders.length && wOrders[0].search);
  check("G4. WooCommerce still pages 100 at a time, for products, variations and orders",
    wPaged.length >= 4 && wPaged.every(function (u) { return u.searchParams.get("per_page") === "100"; }), J(wPaged.map(function (u) { return u.pathname + " " + u.searchParams.get("per_page"); })));
  // NAMED (Nov 7 2026, migration 176): one decided shape per platform (optionsAsDecided for WooCommerce, shopifyReadAsDecided for Shopify).
  check("G5. every WooCommerce and Shopify request in the syncs above went through deps.jsonRequest, with exactly the decided options",
    [[m.stores, shopifyReadAsDecided], [wst, function (a) { return optionsAsDecided(a.options); }]].every(function (p) {
      const s = p[0]; return s.asked.length > 0 && s.asked.length === s.calls.length && s.asked.every(p[1]);
    }), J([m.stores.asked.length, m.stores.calls.length, wst.asked.length, wst.calls.length]));

  async function wooSync(storeOpts) {
    const db = makeDb(), st = makeStores(storeOpts);
    const sealed = SS.sealCredentials({ consumer_key: CK, consumer_secret: CS }, CRYPT.encrypt);
    const c = Object.assign({ id: uuid(), user_id: USER, platform: "woocommerce", store_url: WOO, status: "connected" }, sealed);
    db.t.member_store_connections.push(c);
    const deps = libDeps(db, st);
    const lines = [];
    const saved = [console.error, console.log];
    console.error = function () { lines.push([].slice.call(arguments).join(" ")); };
    console.log = function () { lines.push([].slice.call(arguments).join(" ")); };
    let res;
    try { res = await SS.syncConnection(deps, c); } finally { console.error = saved[0]; console.log = saved[1]; }
    return { res: res, db: db, st: st, deps: deps, conn: db.t.member_store_connections[0] || {}, lines: lines };
  }
  async function shopSync(storeOpts) {
    const db = makeDb(), st = makeStores(storeOpts);
    const c = shopifyConn(db);
    const deps = libDeps(db, st);
    const lines = [];
    const saved = [console.error, console.log];
    console.error = function () { lines.push([].slice.call(arguments).join(" ")); };
    console.log = function () { lines.push([].slice.call(arguments).join(" ")); };
    let res;
    try { res = await SS.syncConnection(deps, c); } finally { console.error = saved[0]; console.log = saved[1]; }
    return { res: res, db: db, st: st, deps: deps, conn: db.t.member_store_connections[0] || {}, lines: lines };
  }
  const backoffs = function (deps) { return deps.sleeps.filter(function (ms) { return ms !== 500 && ms !== 0; }); };

  for (const [label, addrs] of [["loopback 127.0.0.1", [{ address: "127.0.0.1", family: 4 }]], ["private 10.0.0.5", [{ address: "10.0.0.5", family: 4 }]],
    ["loopback ::1", [{ address: "::1", family: 6 }]], ["a public address with a private one among them", [{ address: PUBLIC_V4, family: 4 }, { address: "192.168.1.9", family: 4 }]]]) {
    const w = await wooSync({ addresses: addrs });
    check("G6. WooCommerce: a store whose name answers " + label + " is refused by the guarded fetcher's own lookup: nothing reaches it, one question asked (no retry), recorded as blocked_address",
      w.res.ok === false && w.res.code === "blocked_address" && w.st.calls.length === 0 && w.st.resolved["woo.example.com"] === 1 && w.st.asked.length === 1 &&
      backoffs(w.deps).length === 0 && w.conn.last_error_code === "blocked_address", J([w.res, w.st.calls.length, w.st.resolved, w.deps.sleeps]));
  }
  const sLoop = await shopSync({ addresses: [{ address: "127.0.0.1", family: 4 }] });
  check("G7. Shopify too: a shop whose name answers 127.0.0.1 is refused, nothing reaches it, one question asked (no retry), recorded as blocked_address",
    sLoop.res.ok === false && sLoop.res.code === "blocked_address" && sLoop.st.calls.length === 0 && sLoop.st.resolved[SHOP] === 1 && backoffs(sLoop.deps).length === 0 &&
    sLoop.conn.last_error_code === "blocked_address", J([sLoop.res, sLoop.st.resolved]));
  /* NAMED (Nov 7 2026, migration 176): BEFORE connecting a pasted token to a shop answering ::1 was refused as
     store_unreachable. AFTER there is no pasted token; the live locations read (GET /api/store/connections/:id/locations)
     on such a shop answers 502 unreachable, nothing reaches it and the connection is not changed. The finish route's
     reads are scripts/checkShopifyConnect.js's. */
  const mLoop = mountRoutes({ stores: { addresses: [{ address: "::1", family: 6 }] } });
  const cLoop = shopifyConn(mLoop.db);
  const quietLoop = [console.error, console.log];
  const rLoop = await hit(mLoop, "get /api/store/connections/:id/locations", { params: { id: cLoop.id } });
  check("G8. the live locations read on a shop whose name answers ::1: 502 unreachable, nothing reaches it, the connection unchanged",
    rLoop.status === 502 && rLoop.body.code === "unreachable" && mLoop.stores.calls.length === 0 && mLoop.db.t.member_store_connections[0].status === "connected",
    J([rLoop.status, rLoop.body, mLoop.stores.calls.length, quietLoop.length]));

  const wRed = await wooSync({ wooRedirect: true });
  check("G9. a 302 from the store is refused as redirected and never followed: its target (169.254.169.254) is never asked, and it is not retried",
    wRed.res.ok === false && wRed.res.code === "redirected" && wRed.st.calls.length === 1 && wRed.st.asked.length === 1 &&
    !wRed.st.calls.some(function (c) { return /169\.254\./.test(c.url); }) && !wRed.st.resolved["169.254.169.254"] && TRIPPED.length === 0 &&
    wRed.conn.last_error_code === "redirected", J([wRed.res, wRed.st.calls.map(function (c) { return c.url; }), TRIPPED]));

  const wBig = await wooSync({ wooOrdersHuge: true });
  const bigOrderCalls = wBig.st.calls.filter(function (c) { return /\/orders/.test(c.url); }).length;
  const failLine = wBig.lines.filter(function (l) { return /^\[StoreSync\] /.test(l); });
  check("G10. a WooCommerce page over 8 MB fails as too_large: asked ONCE (never retried), recorded on the connection as too_large",
    wBig.res.ok === false && bigOrderCalls === 1 && wBig.conn.last_error_code === "too_large" && backoffs(wBig.deps).length === 0,
    J([wBig.res, bigOrderCalls, wBig.conn.last_error_code, wBig.deps.sleeps]));
  check("G11. ...the server log line says too_large, with no URL, no header and no key",
    failLine.length === 1 && failLine[0] === "[StoreSync] woocommerce connection " + wBig.conn.id + " failed: too_large" &&
    noSecretIn(wBig.lines.join("\n"), ["https://", "woo.example.com", "wp-json", "Basic", "Authorization", CK, CS]), J(wBig.lines));
  // NAMED (Nov 7 2026, migration 176): BEFORE the products.json page. AFTER the Variants query's answer.
  const sBig = await shopSync({ variantsHuge: true });
  check("G12. a Shopify answer over 8 MB: too_large the same way, asked once",
    sBig.res.ok === false && graphqlCalls(sBig.st, "Variants").length === 1 && sBig.conn.last_error_code === "too_large" &&
    noSecretIn(sBig.lines.join("\n"), ["https://", "admin/api", "graphql", TOKEN]), J([sBig.res, sBig.conn.last_error_code]));

  // the member's message: what an unreachable store tells them today, word for word
  // NAMED (Nov 7 2026, migration 176): BEFORE productsHuge (the first REST read). AFTER shopHuge: every GraphQL answer, so the first read, ShopInfo, is the one over 8 MB.
  const mHuge = mountRoutes({ stores: { shopHuge: true } }), mDown = mountRoutes({ stores: { networkDown: true } });
  const cHuge = shopifyConn(mHuge.db), cDown = shopifyConn(mDown.db);
  const quiet = [console.error, console.log];
  console.error = function () {}; console.log = function () {};
  let rHuge, rDown;
  try {
    rHuge = await hit(mHuge, "post /api/store/connections/:id/sync", { params: { id: cHuge.id } });
    rDown = await hit(mDown, "post /api/store/connections/:id/sync", { params: { id: cDown.id } });
  } finally { console.error = quiet[0]; console.log = quiet[1]; }
  check("G13. sync now on a store with an over-8 MB page tells the member exactly what an unreachable store tells them (502, the same message and code)",
    rHuge.status === 502 && rDown.status === 502 && J(rHuge.body) === J(rDown.body) &&
    rDown.body.error === "Your store could not be read just now (unreachable). Nothing was changed. Try again later." && rDown.body.code === "unreachable",
    J([rHuge.status, rHuge.body, rDown.status, rDown.body]));
  check("G14. ...and a network failure IS retried (4 attempts), while the over-8 MB page was asked once; each is recorded as itself",
    mDown.stores.calls.length === SS.MAX_ATTEMPTS && SAPI.MAX_ATTEMPTS === SS.MAX_ATTEMPTS && mHuge.stores.calls.length === 1 &&
    mHuge.db.t.member_store_connections[0].last_error_code === "too_large" && mDown.db.t.member_store_connections[0].last_error_code === "unreachable",
    J([mDown.stores.calls.length, mHuge.stores.calls.length]));
  /* NAMED (Nov 7 2026, migration 176): BEFORE G15 connected a pasted token whose access_scopes answer was over 8 MB (503,
     the unreachable body). AFTER the same rule on the live locations read: an over-8 MB answer gives the body a network
     failure gives (502 unreachable), asked once, and the connection stays as it was. */
  const mvHuge = mountRoutes({ stores: { shopHuge: true } }), mvDown = mountRoutes({ stores: { networkDown: true } });
  const cvHuge = shopifyConn(mvHuge.db), cvDown = shopifyConn(mvDown.db);
  console.error = function () {}; console.log = function () {};
  let vHuge, vDown;
  try {
    vHuge = await hit(mvHuge, "get /api/store/connections/:id/locations", { params: { id: cvHuge.id } });
    vDown = await hit(mvDown, "get /api/store/connections/:id/locations", { params: { id: cvDown.id } });
  } finally { console.error = quiet[0]; console.log = quiet[1]; }
  check("G15. the live locations read: an over-8 MB answer is the unreachable answer too (502, the same body), asked once, the connection unchanged",
    vHuge.status === 502 && J(vHuge.body) === J(vDown.body) && vHuge.body.code === "unreachable" && mvHuge.stores.calls.length === 1 &&
    mvHuge.db.t.member_store_connections[0].status === "connected", J([vHuge.status, vHuge.body, mvHuge.stores.calls.length]));

  let typeRefusals = 0;
  const refusingDeps = { sleep: async function () {}, jsonRequest: function () { typeRefusals++; return Promise.reject(new TypeError("guardedJsonRequest: maxBytes must be a whole number")); } };
  let refusedCode = null, apiRefused = null;
  // NAMED (Nov 7 2026, migration 176): BEFORE the URL was Shopify's access_scopes.json. AFTER a WooCommerce URL for
  // lib/storeSync.js, and the same rule for lib/shopifyApi.js's readQuery.
  try { await SS.request(refusingDeps, WOO + "/wp-json/wc/v3/products?per_page=1", {}); } catch (e) { refusedCode = e instanceof SS.StoreRequestError ? e.code : String(e); }
  try { await SAPI.readQuery(refusingDeps, SHOP, TOKEN, "query ShopInfo { shop { currencyCode } }", {}); } catch (e) { apiRefused = e instanceof SS.StoreRequestError ? e.code : String(e); }
  check("G16. a refusal by the guarded fetcher itself (a TypeError over its options) is never retried: one call each, guard_refused",
    typeRefusals === 2 && refusedCode === "guard_refused" && apiRefused === "guard_refused", J([typeRefusals, refusedCode, apiRefused]));

  const wOne = await wooSync({ wooOneFullPage: true });
  const pageTwo = wOne.st.calls.filter(function (c) { return /\/products\?/.test(c.url) && new URL(c.url).searchParams.get("page") === "2"; }).length;
  check("G17. paging reads the exposed X-WP-TotalPages: a full page of 100 that says it is the only page is the last one asked",
    wOne.res.ok === true && pageTwo === 0 && wOne.st.calls.some(function (c) { return /\/products\?/.test(c.url) && new URL(c.url).searchParams.get("page") === "1"; }),
    J([wOne.res.ok, pageTwo]));
  // NAMED (Nov 7 2026, migration 176): BEFORE the second page came from the exposed Link header. AFTER from the answer's endCursor.
  check("G18. ...and Y2's second Shopify page came from the first answer's endCursor (c2), on the same shop, and the first page was asked with no cursor",
    graphqlCalls(m.stores, "Variants").some(function (c) { return c.body.variables.cursor === "c2" && new URL(c.url).hostname === SHOP; }) &&
    graphqlCalls(m.stores, "Variants").some(function (c) { return c.body.variables.cursor === null; }));

  const sEnd = await shopSync({ endless: true });
  const prodPages = graphqlCalls(sEnd.st, "Variants").length;
  const ordPages = graphqlCalls(sEnd.st, "Orders").length;
  check("G19. a shop with no last page: 200 variants pages and 200 orders pages are read, and no more",
    sEnd.res.ok === true && prodPages === 200 && ordPages === 200, J([sEnd.res.ok, prodPages, ordPages]));
  const wEnd = await wooSync({ wooEndless: true });
  const wooProdPages = wEnd.st.calls.filter(function (c) { return /\/wp-json\/wc\/v3\/products\?/.test(c.url); }).length;
  check("G20. a WooCommerce store with no last page: 40 products pages, and no more", wEnd.res.ok === true && wooProdPages === 40, J([wEnd.res.ok, wooProdPages]));

  /* ── A ── */
  console.log("\n══ A. an auth failure: needs_reconnect, one notice, no retry loop ══");
  /* NAMED (Nov 7 2026, Shopify on OAuth, migration 176): BEFORE a 401 on products.json was ONE request and needs_reconnect.
     AFTER a 401 on a GraphQL read may refresh the token ONCE (lib/shopifyApi.js read): one GraphQL request, one token
     request, and when Shopify refuses the refresh, needs_reconnect with one notice; no retry loop either way. */
  const adb = makeDb(), ast = makeStores({ shopStatus: 401 });
  const aconn = shopifyConn(adb);
  const ad = libDeps(adb, ast);
  const a1 = await SS.syncConnection(ad, aconn);
  const productCalls = graphqlCalls(ast).length;
  const tokenCalls = ast.asked.filter(isTokenRequest).length;
  check("A1. a 401: ONE GraphQL request (no retry), ONE refresh asked and refused, needs_reconnect, one notice",
    a1.ok === false && a1.needs_reconnect === true && productCalls === 1 && tokenCalls === 1 && a1.code === "refresh_refused" &&
    adb.t.member_store_connections[0].status === "needs_reconnect" && adb.t.notifications.length === 1 && adb.t.notifications[0].type === "store_reconnect", J([a1, productCalls, tokenCalls, adb.t.notifications.length]));
  check("A2. the notice says what to do and holds no key or token", /Connect the store again on the Store Agent page/.test(adb.t.notifications[0] && adb.t.notifications[0].message) &&
    noSecretIn(J(adb.t.notifications), [TOKEN, REFRESH]));
  // A refresh Shopify accepts: the new pair is sealed and saved in one update, and the read is asked once more with it.
  const rdb = makeDb(), rst = makeStores({ shopStatus: 401, refreshOk: true });
  const rconn = shopifyConn(rdb);
  const r1 = await SS.syncConnection(libDeps(rdb, rst), rconn);
  const rrow = rdb.t.member_store_connections[0];
  let ropen = null; try { ropen = SS.openCredentials(rrow, CRYPT.decrypt); } catch (e) { ropen = null; }
  check("A1b. a refresh Shopify accepts: token_version 1, both new tokens sealed (never in the clear), and the read asked exactly once more, then given up",
    rrow.token_version === 1 && ropen && ropen.refresh_token === REFRESH + "n" && CRYPT.decrypt({ ciphertext: rrow.access_ciphertext, iv: rrow.access_iv, authTag: rrow.access_auth_tag }) === TOKEN + "n" &&
    noSecretIn(J(rrow), [TOKEN, REFRESH]) && graphqlCalls(rst).length === 2 && rst.asked.filter(isTokenRequest).length === 1 && r1.needs_reconnect === true,
    J([r1, rrow.token_version, graphqlCalls(rst).length]));
  const a2 = await SS.syncConnection(ad, Object.assign({}, aconn, { status: "connected" }));
  check("A3. a second failure finds nothing to mark and sends no second notice", a2.needs_reconnect === true && adb.t.notifications.length === 1, adb.t.notifications.length);
  const am = mountRoutes({});
  const amc = shopifyConn(am.db); amc.status = "needs_reconnect";
  const ar = await hit(am, "post /api/store/connections/:id/sync", { params: { id: amc.id } });
  check("A4. sync now on a store that needs reconnecting: 409, no request", ar.status === 409 && am.stores.calls.length === 0);
  const pass = await SS.runStoreSyncPass(libDeps(adb, ast));
  check("A5. the daily pass skips it (it reads connected stores only)", pass.stores === 0, J(pass));
  // NAMED (Nov 7 2026, migration 176): WooCommerce keeps A1's old rule, held here now that A1 is Shopify's refresh.
  const w401 = await wooSync({ wooStatus: 401 });
  check("A6. WooCommerce: a 401 is ONE request (no retry) and needs_reconnect", w401.res.needs_reconnect === true && w401.st.calls.length === 1 &&
    w401.conn.status === "needs_reconnect", J([w401.res, w401.st.calls.length]));

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
  /* NAMED (Nov 7 2026, Shopify on OAuth, migration 176): BEFORE one note for both platforms ("uninstall the custom app" and
     "REST API"). AFTER a Shopify disconnect says exactly how to remove the app from the Shopify admin, and a WooCommerce one
     still says where to revoke the key. */
  const wdel = Object.assign({ id: uuid(), user_id: USER, platform: "woocommerce", store_url: WOO, status: "connected" }, SS.sealCredentials({ consumer_key: CK, consumer_secret: CS }, CRYPT.encrypt));
  m.db.t.member_store_connections.push(wdel);
  const rwdel = await hit(m, "delete /api/store/connections/:id", { params: { id: wdel.id } });
  check("D2. ...and says how to remove BizForce from the store: Shopify's exact note, and WooCommerce's REST API line",
    r.body.note === "Disconnected. To remove BizForce from your Shopify admin too, uninstall the BizForce app under Settings, then Apps." &&
    rwdel.status === 200 && /Settings, Advanced, REST API/.test(rwdel.body.note || "") && !/custom app/.test(rwdel.body.note || ""), J([r.body.note, rwdel.body.note]));
  const r404 = await hit(m, "delete /api/store/connections/:id", { params: { id: uuid() } });
  check("D3. someone else's or an unknown connection: 404", r404.status === 404);
  const YD = realRequire("./lib/yourData");
  const entry = function (tname) { return (YD.DATA || []).find(function (e) { return e.table === tname; }); };
  const yd = FILES.yourData;
  const ce = entry("member_store_connections"), oe = entry("store_order_summaries");
  // NAMED (Nov 6 2026, store changes, migration 175): BEFORE the export selected platform, store_url, status, created_at,
  // last_sync_at. AFTER permission too, between status and created_at; still never the credentials.
  check("D4. the export: connections with safe fields only (never the credentials), order summaries without customer fields",
    // NAMED (Nov 7 2026, migration 176): BEFORE "platform, store_url, status, permission, created_at, last_sync_at". AFTER currency and
    // location_name too, after permission; still never a credential or a token.
    // NAMED (Nov 8 2026, Amazon store connection, migration 182): BEFORE "..., location_name, created_at, last_sync_at". AFTER
    // marketplace_id and region too, after location_name; still never a credential or a token.
    ce && ce.onDelete === "delete" && /^platform, store_url, status, permission, currency, location_name, marketplace_id, region, created_at, last_sync_at$/.test(ce.select) && oe && oe.onDelete === "delete" &&
    oe.select === "platform, external_id, ordered_at, total, currency, line_items", J([ce, oe]));
  // NAMED (Nov 6 2026, store changes, migration 175): BEFORE "store_order_summaries", "calendar_events" were adjacent.
  // AFTER store_change_log sits between them (checkStoreChanges G holds it).
  check("D5. the account delete removes both: summaries in DELETE_ORDER, connections in FINAL_DELETES",
    /"inventory_items", "store_order_summaries", "store_change_log", "calendar_events"/.test(yd) && /"member_social_connections", "member_store_connections",/.test(yd));
  const BK = realRequire("./lib/backup"), SC = realRequire("./lib/schemaCheck");
  // NAMED (Nov 7 2026, migration 176): shopify_webhook_events joins them: excluded from backups, and in the schema list tagged 176.
  check("D6. in the backup lists (the key excluded, the summaries skipped, the webhook receipts excluded) and the schema list, tagged 163 and 176",
    !!BK.EXCLUDED_TABLES.member_store_connections && !!BK.SKIPPED_TABLES.store_order_summaries &&
    BK.EXCLUDED_TABLES.shopify_webhook_events === "Shopify notification receipts, kept 30 days" &&
    SC.migrationFor("member_store_connections") === "supabase/migrations/163_store_connections.sql" && SC.migrationFor("store_order_summaries") === "supabase/migrations/163_store_connections.sql" &&
    SC.migrationFor("shopify_webhook_events") === "supabase/migrations/176_shopify_oauth.sql");

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
  // NAMED (Nov 8 2026, Etsy store connection, migration 181): BEFORE { manual: 1, shopify: 1, woocommerce: 1 }. AFTER etsy is the
  // third store source and is counted too (0 here: no Etsy row); checkEtsyConnect counts an Etsy row.
  // NAMED (Nov 8 2026, Amazon store connection, migration 182): BEFORE { manual: 1, shopify: 1, woocommerce: 1, etsy: 0 }. AFTER
  // amazon is counted too (0 here: no Amazon row); checkAmazonConnect counts an Amazon row.
  check("R4. the Store signature counts stock by source", sigStock && J(sigStock.sources) === J({ manual: 1, shopify: 1, woocommerce: 1, etsy: 0, amazon: 0 }), J(sig).slice(0, 300));
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
  /* NAMED (Nov 7 2026, Shopify on OAuth, migration 176): BEFORE "N1. lib/storeSync.js holds no POST, PUT, PATCH or DELETE, and no
     method but GET". AFTER the same, and it names no Shopify request at all (no graphql, no X-Shopify header, no mutation, no
     /admin/ path): it reads a shop only through deps.shopifyReader. */
  check("N1. lib/storeSync.js holds no POST, PUT, PATCH or DELETE, no method but GET, and no Shopify request of its own (it reads Shopify only through deps.shopifyReader)",
    !writeWord && !/graphql|X-Shopify|\bmutation\b|\/admin\//i.test(codeOnly) && /deps\.shopifyReader/.test(codeOnly), (writeWord && writeWord[0]) || "shopify request");
  /* NAMED (store connections security fix, Nov 3 2026): BEFORE N2 was "exactly one fetch call, and it sends method
     GET" (deps.fetch), and N3 "the store section's only fetch is the GET-only wrapper handed to lib/storeSync.js".
     AFTER there is NO fetch, http.request or https.request in lib/storeSync.js, and no module that opens a socket
     or resolves a name; its one request is deps.jsonRequest, sending method "GET". The store section has no fetch
     at all, and the jsonRequest it hands lib/storeSync.js is lib/guardedFetch.js's guardedJsonRequest. */
  const fetchCalls = codeOnly.match(/\bfetch\s*\(/g) || [];
  const rawCalls = codeOnly.match(/\b(https?)\.(request|get)\s*\(|require\(["'](https?|net|tls|dns|undici|node:https?|node:net|node:dns)["']\)/g) || [];
  const jsonCalls = codeOnly.match(/deps\.jsonRequest\(/g) || [];
  /* NAMED (Nov 7 2026, migration 176): BEFORE N2 held lib/storeSync.js alone, the one file that read a store. AFTER
     lib/shopifyApi.js reads Shopify, so it is held too: no fetch, http.request or https.request; exactly two
     deps.jsonRequest calls, readQuery's (which refuses any document but a "query") and sendOnce's; and the word
     "mutation" only inside writePrice and writeStock, the two writes lib/storeWrite.js makes after an approval. */
  const apiCode = FILES.api.replace(/(^|[^:])\/\/[^\n]*/g, "$1").replace(/\/\*[\s\S]*?\*\//g, "");
  const apiFetch = (apiCode.match(/\bfetch\s*\(/g) || []).length + (apiCode.match(/\b(https?)\.(request|get)\s*\(|require\(["'](https?|net|tls|dns|undici)["']\)/g) || []).length;
  const apiJson = (apiCode.match(/deps\.jsonRequest\(/g) || []).length;
  // The code only (comments are allowed to explain the rule), with the two write functions taken out.
  const withoutWrites = ["writePrice", "writeStock"].reduce(function (src, n) { return src.split(MUT.definitionOf(FILES.api, n)).join(""); }, FILES.api)
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1").replace(/\/\*[\s\S]*?\*\//g, "");
  check("N2. lib/storeSync.js: no fetch, http.request or https.request, nothing that opens a socket, exactly one request call, deps.jsonRequest, sending \"GET\"; lib/shopifyApi.js: none of those either, exactly two deps.jsonRequest calls (readQuery and sendOnce), and \"mutation\" only inside writePrice and writeStock",
    fetchCalls.length === 0 && rawCalls.length === 0 && jsonCalls.length === 1 && /deps\.jsonRequest\(url, \{ method: "GET", headers: headers, /.test(codeOnly) &&
    apiFetch === 0 && apiJson === 2 && /deps\.jsonRequest\(graphqlUrl\(shop\)/.test(MUT.definitionOf(FILES.api, "readQuery")) && /deps\.jsonRequest\(graphqlUrl\(shop\)/.test(MUT.definitionOf(FILES.api, "sendOnce")) &&
    !/\bmutation\b/i.test(withoutWrites) && ["writePrice", "writeStock"].every(function (n) { return /"mutation [A-Za-z]+\(/.test(MUT.definitionOf(FILES.api, n)); }),
    J([fetchCalls.length, rawCalls, jsonCalls.length, apiFetch, apiJson]));
  let notQuery = null; const beforeAsk = makeStores({});
  try { await SAPI.readQuery({ sleep: async function () {}, jsonRequest: beforeAsk.jsonRequest }, SHOP, TOKEN, "mutation X { productDelete(input: {}) { userErrors { message } } }", {}); } catch (e) { notQuery = e && e.code; }
  check("N6. readQuery refuses a document that is not a query before anything is sent (not_a_query)", notQuery === "not_a_query" && beforeAsk.asked.length === 0, J([notQuery, beforeAsk.asked.length]));
  check("N3. the routes call no store themselves: the store section has no fetch, and hands lib/storeSync.js the guarded fetcher's guardedJsonRequest",
    (SECTION.match(/\bfetch\s*\(/g) || []).length === 0 &&
    /jsonRequest: function \(url, options\) \{ return require\("\.\/lib\/guardedFetch"\)\.guardedJsonRequest\(url, options\); \}/.test(SECTION) &&
    !/\blookup:|isBlockedAddress|timeoutSignal/.test(MUT.definitionOf(FILES.server, "storeSyncDeps")));
  /* NAMED (Nov 6 2026, store changes, migration 175): BEFORE no non-script file but lib/storeSync.js named a store's API
     host or path. AFTER lib/storeWrite.js, the one file that writes to a store (approved WooCommerce changes), may too, and
     only it: it is listed in git or on disk, and every other non-script file still names none. lib/storeWrite.js is
     scanned, not exempted unread: it must name no Shopify host or Admin API path (checkStoreChanges S holds its writes). */
  /* NAMED (Nov 7 2026, Shopify on OAuth, migration 176): BEFORE "no other non-script file names a store's API host or path;
     lib/storeWrite.js alone may". AFTER lib/shopifyApi.js (the shop's graphql.json) and lib/shopifyAuth.js (its OAuth paths)
     may too, and are listed whether or not git knows them yet; lib/storeWrite.js may name WooCommerce's path and still names
     no Shopify host, Admin API path or Shopify header in its code: it writes to Shopify only through lib/shopifyApi.js. */
  const ALLOWED_NAMERS = ["lib/storeWrite.js", "lib/shopifyApi.js", "lib/shopifyAuth.js"];
  const files = cp.execFileSync("git", ["ls-files", "*.js"], { cwd: REPO }).toString().trim().split(/\r?\n/)
    .concat(ALLOWED_NAMERS.filter(function (f) { return fs.existsSync(path.join(REPO, f)); }))
    .filter(function (f, i, all) { return all.indexOf(f) === i && !/^scripts\//.test(f) && f !== "lib/storeSync.js"; });
  const named = files.filter(function (f) { return ALLOWED_NAMERS.indexOf(f) === -1 && /myshopify\.com|\/wp-json\/wc\/|\/admin\/api\/|\/admin\/oauth\//.test(fs.readFileSync(path.join(REPO, f), "utf8")); });
  const writeSrc = fs.existsSync(path.join(REPO, "lib/storeWrite.js")) ? fs.readFileSync(path.join(REPO, "lib/storeWrite.js"), "utf8") : "";
  const writeCode = writeSrc.replace(/(^|[^:])\/\/[^\n]*/g, "$1").replace(/\/\*[\s\S]*?\*\//g, "");
  check("N4. no non-script file but lib/storeWrite.js, lib/shopifyApi.js and lib/shopifyAuth.js names a store's API host or path, and lib/storeWrite.js's code names no Shopify host, Admin API path or Shopify header",
    named.length === 0 && writeSrc.length > 0 && !/myshopify\.com|\/admin\/api\/|\/admin\/oauth\/|X-Shopify|graphql/i.test(writeCode), named.join(", "));
  /* NAMED (Nov 7 2026, migration 176): BEFORE "the stubbed stores saw only GET in this whole run". AFTER WooCommerce saw only
     GET; Shopify saw only POSTs of GraphQL "query" documents to graphql.json and token POSTs to /admin/oauth/access_token,
     never a mutation. */
  check("N5. the stubbed stores saw only GET from WooCommerce, and from Shopify only GraphQL queries and token requests, never a mutation, in this whole run",
    [m.stores, wst, ast, jst, rst].every(function (s) {
      return s.calls.every(function (c) {
        const u = new URL(c.url);
        if (u.origin === WOO) return c.method === "GET";
        return c.method === "POST" && ((u.pathname === GRAPHQL_PATH && c.kind === "query") || u.pathname === "/admin/oauth/access_token");
      });
    }));

  /* ── L ── */
  console.log("\n══ L. the Privacy page, the Store page, the migration, no emoji ══");
  const LP = realRequire("./lib/legalPages");
  const esc = function (t) { return String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"); };
  const sentence = LP.STORE_PRIVACY_SENTENCE || "";
  /* NAMED (Nov 6 2026, store changes, migration 175): BEFORE the sentence said "the read-only key you made for it" and
     "BizForce never changes anything in your store". AFTER "the key you made for it", a change only when the member
     approves it and only if they allowed changes when connecting, a record of each change, and that record in the
     deletion list. The whole sentence is held word for word by checkStoreChanges L1. */
  /* NAMED (Nov 7 2026, Shopify on OAuth, migration 176): BEFORE "...are deleted when you disconnect the store or delete your
     account". AFTER uninstalling BizForce from Shopify deletes them too (the app/uninstalled webhook), and the sentence
     names the Shopify access approved on connecting, the currency and the location names. Held whole by checkShopifyConnect. */
  /* NAMED (Nov 8 2026, Etsy store connection, migration 181): BEFORE "...uninstall BizForce from Shopify, or delete your account"
     and "for Shopify, the access you approve when you connect". AFTER "...uninstall BizForce from Shopify, remove it from your
     Etsy account, or delete your account" and "for Shopify or Etsy, the access you approve when you connect", and the sentence
     opens "If you connect a Shopify, WooCommerce or Etsy store". Held whole by checkEtsyConnect. */
  /* NAMED (Nov 8 2026, Amazon store connection, migration 182): BEFORE "...remove it from your Etsy account, or delete your
     account", "for Shopify or Etsy, the access you approve when you connect" and "If you connect a Shopify, WooCommerce or Etsy
     store". AFTER "...remove it from your Etsy account or Amazon Seller Central, or delete your account", "for Shopify, Etsy or
     Amazon, the access you approve when you connect" and "If you connect a Shopify, WooCommerce, Etsy or Amazon store". Held
     whole by checkEtsyConnect and checkAmazonConnect. */
  check("L1. the Privacy sentence says what is stored, never customer details, own agents only, changes only with approval, deleted on disconnect, on uninstall or with the account",
    /encrypted/.test(sentence) && /never any customer's name, email, address or phone number/.test(sentence) && /used only for your own agents/.test(sentence) &&
    /the order summaries and the record of changes are deleted when you disconnect the store, uninstall BizForce from Shopify, remove it from your Etsy account or Amazon Seller Central, or delete your account/.test(sentence) &&
    /for Shopify, Etsy or Amazon, the access you approve when you connect/.test(sentence) && /^If you connect a Shopify, WooCommerce, Etsy or Amazon store,/.test(sentence) && /your store's currency and location names/.test(sentence) &&
    /BizForce changes a product's price or stock level in your store only when you approve that change, and only if you allowed changes when you connected the store/.test(sentence) &&
    !/read-only key|never changes anything/.test(sentence));
  check("L2. privacy.html carries it once, as built", sentence.length > 100 && FILES.privacy.split(esc(sentence)).length === 2);
  /* NAMED (Nov 6 2026, store changes, migration 175): BEFORE the page said "BizForce only reads your store. It never
     changes your products, prices or orders." AFTER the line names when it changes something, word for word, and the old
     line is gone from the page. */
  check("L3. the Store page says \"BizForce reads your store. It changes a price or stock level only when you approve that change, and only if you allowed changes when you connected.\" and loads the card's script",
    FILES.page.indexOf("BizForce reads your store. It changes a price or stock level only when you approve that change, and only if you allowed changes when you connected.") !== -1 &&
    FILES.page.indexOf("It never changes your products, prices or orders.") === -1 && /<script src="\/scripts\/store-connect\.js"><\/script>/.test(FILES.page) &&
    /id="storeConnect"/.test(FILES.page));
  /* NAMED (Nov 7 2026, Shopify on OAuth, migration 176): BEFORE L4 held Shopify's custom-app steps (three read scopes and a
     shpat_ token field) and L5 that the token field was cleared (tokenEl.value = ""). AFTER the Shopify part is the shop's
     address, the changes box and Connect Shopify, with no token field and no shpat_ anywhere on the page or in its script;
     the page clears the WooCommerce address after connecting instead. */
  check("L4. the steps: Shopify's own approval page, the shop address and Connect Shopify, no token field; WooCommerce's Read approval and where to revoke it",
    /You approve BizForce on Shopify's own page\. BizForce never sees your Shopify password\./.test(FILES.page) && /id="storeShop"/.test(FILES.page) &&
    /id="storeShopifyBtn">Connect Shopify</.test(FILES.page) && !/shpat_|id="storeToken"|access_token/.test(FILES.page + FILES.ui) &&
    /approve Read access for BizForce AI/.test(FILES.page) && /Settings, Advanced, REST API/.test(FILES.page));
  check("L5. the card shows \"Connected to <store>\", Last synced, Sync now, Disconnect and the reconnect state, and the address field is cleared after connecting",
    /"Connected to " \+ c\.store/.test(FILES.ui) && /"Last synced: "/.test(FILES.ui) && /"Sync now"/.test(FILES.ui) && /"Disconnect"/.test(FILES.ui) && /needs_reconnect/.test(FILES.ui) &&
    /byId\("storeUrl"\)\.value = "";/.test(FILES.ui));
  check("L6. the migration turns RLS on for both tables and keeps credentials hex-only",
    /ALTER TABLE public\.member_store_connections ENABLE ROW LEVEL SECURITY;/.test(FILES.migration) && /ALTER TABLE public\.store_order_summaries ENABLE ROW LEVEL SECURITY;/.test(FILES.migration) &&
    /CHECK \(credentials_ciphertext ~ '\^\[0-9a-f\]\+\$'\)/.test(FILES.migration) && /UNIQUE \(user_id, platform, store_url\)/.test(FILES.migration));
  check("L7. README has the ENABLE_STORE_SYNC row and the job row", /\| `ENABLE_STORE_SYNC` \| off \| Exactly `true`/.test(FILES.readme) && /\| `storeSyncTick`: [^\n]*cron `0 5 \* \* \*`, UTC, claimed `store_sync`/.test(FILES.readme));
  const migFiles = fs.readdirSync(path.join(REPO, "supabase/migrations")).filter(function (f) { return /^\d+_/.test(f); });
  /* NAMED (the Bluesky Mentions inbox, Nov 3 2026): BEFORE "the only migration numbered 163, and the highest" (every number
     <= 163). AFTER 164_bluesky_reply_refs.sql follows it, so the pin is "the only one numbered 163, every other one but 164 is
     lower, and 162 came before it"; "the highest" is now checkBlueskyMentions M3's, for 164.
     NAMED (Connect Mastodon, Nov 3 2026): BEFORE only 164 was allowed above 163. AFTER 164_bluesky_reply_refs.sql and
     165_member_mastodon_connections.sql; "the highest" is checkMastodonConnect M3's, for 165.
     NAMED (campaign sharing, Nov 4 2026): BEFORE 164 and 165 were allowed above 163. AFTER 164, 165 and
     166_campaign_sharing.sql; "the highest" is checkCampaignSharing M2's, for 166. */
  check("L9. 163_store_connections.sql is the only migration numbered 163, every one before it is lower (162 was the last before it)",
    migFiles.filter(function (f) { return /^163_/.test(f); }).length === 1 &&
    // NAMED (Nov 4 2026, the Media Library, migration 167): the allowlist adds 167_member_media.sql; "the highest" is checkMediaLibrary M2's.
    // NAMED (Nov 5 2026, images in social posts, migration 168): BEFORE 164 to 167 allowed above 163. AFTER 168_social_post_images.sql
    // too; "the highest" is checkSocialImages M2's.
    // NAMED (Nov 5 2026, mailbox connection, migration 169): the allowlist adds 169_member_email_connections.sql; "the highest" is checkMailboxConnect M2's.
    // NAMED (Nov 5 2026, mailbox replies, migration 170): the allowlist adds 170_member_email_replies.sql; "the highest" is checkMailboxReply M2's.
    // NAMED (Nov 6 2026, card upgrades C1, migration 171): the allowlist adds 171_card_counts.sql; "the highest" is checkCardUpgrades R1's.
    // NAMED (Nov 6 2026, card upgrades C2, migration 172): the allowlist adds 172_card_leads.sql; "the highest" is checkCardLeads R1's.
    // NAMED (Nov 6 2026, Outlook sign-in, migration 173): the allowlist adds 173_mailbox_microsoft.sql; "the highest" is checkMailboxOutlook R1's.
    // NAMED (Nov 6 2026, Google Wallet, migration 174): the allowlist adds 174_card_wallet_count.sql; "the highest" is checkGoogleWallet R1's.
    // NAMED (Nov 6 2026, store changes, migration 175): the allowlist adds 175_store_changes.sql; "the highest" is checkStoreChanges R1's.
    // NAMED (Nov 7 2026, Shopify on OAuth, migration 176): the allowlist adds 176_shopify_oauth.sql; "the highest" is checkShopifyConnect R1's.
    // NAMED (Nov 7 2026, YouTube uploads, migration 177): the allowlist adds 177_youtube_uploads.sql; "the highest" is checkYoutubeUploads R1's.
    // NAMED (Nov 7 2026, TikTok posting, migration 178): the allowlist adds 178_tiktok_posting.sql; "the highest" is checkTiktokPosting R1's.
    // NAMED (Nov 7 2026, Instagram posting, migration 179): the allowlist adds 179_instagram_posting.sql; "the highest" is checkInstagramPosting R1's.
    // NAMED (Nov 7 2026, Facebook Pages posting, migration 180): the allowlist adds 180_facebook_pages.sql; "the highest" is checkFacebookPages R1's.
    // NAMED (Nov 8 2026, Etsy store connection, migration 181): the allowlist adds 181_etsy_store.sql; "the highest" is checkEtsyConnect R1's. NAMED (Nov 8 2026, Amazon store connection, migration 182): it adds 182_amazon_store.sql too; "the highest" is checkAmazonConnect R1's.
    migFiles.filter(function (f) { return !/^(164_bluesky_reply_refs|165_member_mastodon_connections|166_campaign_sharing|167_member_media|168_social_post_images|169_member_email_connections|170_member_email_replies|171_card_counts|172_card_leads|173_mailbox_microsoft|174_card_wallet_count|175_store_changes|176_shopify_oauth|177_youtube_uploads|178_tiktok_posting|179_instagram_posting|180_facebook_pages|181_etsy_store|182_amazon_store)\.sql$/.test(f); }).every(function (f) { return Number(f.split("_")[0]) <= 163; }) &&
    migFiles.some(function (f) { return /^162_/.test(f); }));
  const EMOJI = /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{1F000}-\u{1F2FF}\u{FE0F}]/u;
  // NAMED (Nov 7 2026, migration 176): lib/shopifyApi.js, lib/shopifyAuth.js and 176_shopify_oauth.sql join the list.
  const fresh = { "lib/storeSync.js": FILES.sync, "163_store_connections.sql": FILES.migration, "scripts/store-connect.js": FILES.ui, "store-agent.html": FILES.page,
    "lib/shopifyApi.js": FILES.api, "lib/shopifyAuth.js": FILES.auth, "176_shopify_oauth.sql": FILES.migration176 };
  check("L8. no emoji in any new or edited store file", Object.keys(fresh).every(function (k) { return !EMOJI.test(fresh[k]); }), Object.keys(fresh).filter(function (k) { return EMOJI.test(fresh[k]); }).join(", "));

  check("nothing reached the network: no socket, no real DNS question and no fetch in this whole run (the tripwire)", TRIPPED.length === 0, TRIPPED.join(", "));
  check("no unhandled rejection", UNHANDLED.length === 0, UNHANDLED.map(String).join("; "));
  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(function (e) { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
