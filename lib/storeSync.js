// ── Store connections: Shopify and WooCommerce (migrations 163, 175, 176) ─────
//
// WHAT IT DOES. A member connects their own Shopify or WooCommerce store to the
// Store agent. A sync READS three things from it, and nothing else:
//   - products and variants: name, SKU, price, cost where the store has one,
//     and the stock level, written to the member's inventory_items as rows
//     marked with their source;
//   - orders: a SUMMARY of each order from the last ORDER_WINDOW_DAYS days, as
//     the store's order id, when it was placed, the total, the currency, and
//     the line items as SKU and quantity, written to store_order_summaries.
//     NAMED (Nov 11 2026, orbit stage 2, migration 183): and the order's status,
//     active, cancelled or refunded, from the platform's own order state
//     (orderStatusOf, below). Every reader counts active only, and
//     a re-sync updates the status of an order it reads again.
//     summaryOf builds the summary from a whitelist, so a customer's name,
//     email, address or phone can never be stored, whatever the store sends.
//
// THIS FILE NEVER WRITES TO THE STORE. Every request this file makes goes
// through request(), which sends GET and nothing else, to a WooCommerce store.
// A Shopify shop is read through deps.shopifyReader (server.js hands it
// lib/shopifyApi.js), whose readers send GraphQL "query" documents only. An
// Etsy shop (Nov 8 2026, migration 181) is read through deps.etsyReader
// (lib/etsyApi.js), whose readers send GET only. An Amazon seller account (Nov
// 8 2026, migration 182) is read through deps.amazonReader (lib/amazonApi.js),
// whose readers send GET only. Every branch on platform here names all four
// platforms; an unknown platform is refused, never read as WooCommerce.
// scripts/checkStoreConnections.js scans this file for any other method. The
// only writes to a store are in lib/storeWrite.js (migrations 175 and 176): a
// price or stock change the member proposed and approved, on a connection they
// connected with changes allowed.
//
// CREDENTIALS. Encrypted with lib/apiKeyCrypto.js (AES-256-GCM under
// ENCRYPTION_SECRET) before anything is sent to the store, stored only after
// the store accepts them, and never returned, logged or exported.
//   - Shopify (migration 176): the shop's *.myshopify.com domain and the
//     expiring offline token BizForce's Shopify app is given when the member
//     approves it on Shopify's own page (lib/shopifyAuth.js): the access token
//     in access_*, the refresh token sealed in credentials_* as
//     { refresh_token }. lib/shopifyApi.js refreshes it.
//   - WooCommerce: the store's https address. A WooCommerce key's permission
//     cannot be read back with a read call, so BizForce asks the store to make
//     the key: WooCommerce's own authorization page (/wc-auth/v1/authorize)
//     shows the member exactly what is asked, makes a REST API key when they
//     approve, and sends it to BizForce's callback with its permission. The
//     scope asked is read, or read_write only when the member ticked "Let
//     BizForce make changes I approve (prices and stock)" (migration 175); the
//     signed state carries which, and a key whose permission is not exactly
//     the one asked is refused. It is then verified by one read call before it
//     is stored, with its permission.
//
// RATE LIMITS. Each request is paced (REQUEST_GAP_MS), a 429 or a 5xx waits
// (the store's Retry-After, or 1, 2, 4 s) and is tried at most MAX_ATTEMPTS
// times, and pages are capped (PAGE_CAPS: WooCommerce 40 pages; Shopify's are
// lib/shopifyApi.js's, 200 pages). A page over REQUEST_MAX_BODY_BYTES (8 MB) fails as
// too_large, is never retried, is recorded on the connection and in the log,
// and the member is told the store could not be read, as for any unreachable store.
//
// AN AUTH FAILURE (401 or 403) is never retried: the connection is marked
// needs_reconnect with ONE in-app notice (the update is conditional on status
// connected, so a second failure finds nothing to mark and says nothing), and
// the sync of that store stops until the member connects again.
//
// A MEMBER'S OWN ROWS ARE NEVER TOUCHED. A sync upserts on (store_connection_id,
// external_id), which a manual row (both NULL) cannot match. A synced product
// whose SKU is already on one of the member's other rows is skipped and
// counted, never merged. Fields the member sets (reorder point, reorder
// quantity, notes, supplier, location, status) are never sent, so they stay.
// A product the store does not track stock for is skipped and counted: its
// stock is unknown, and an unknown figure is never written as 0.
//
// THE DAILY SYNC. 05:00 UTC (server.js), claimed through job_runs.store_sync
// for the UTC day, so two processes cannot both run it. OFF unless
// ENABLE_STORE_SYNC is exactly "true". Each connected store is synced only when
// its member's subscription is active (deps.userPlan; a failed lookup skips).
//
// EVERY STORE REQUEST GOES THROUGH THE GUARDED FETCHER. deps.jsonRequest is
// lib/guardedFetch.js's guardedJsonRequest (server.js storeSyncDeps): https on
// 443 only, every address the name resolves to checked against the private
// and loopback ranges inside the lookup the socket itself uses (so a name
// cannot answer public for the check and private for the connection), no
// redirect followed, a size and a time limit. Shopify and WooCommerce alike
// (lib/shopifyApi.js uses the same deps.jsonRequest). This file makes no
// request of its own.
//
// CURRENCY (migration 176). A Shopify sync stores the shop's currencyCode on
// the connection; a WooCommerce sync reads /data/currencies/current, after
// the products and orders, and stores the code when it is three capitals. A
// failed currency read changes nothing else.
//
// Everything outside (the Supabase client, the guarded request, the clock,
// sleep, encrypt and decrypt, the plan lookup) is injected, so a check drives
// it with stubs. It never requires server.js.
"use strict";

var crypto = require("crypto");

var STORE_SYNC_JOB_NAME = "store_sync";
// Etsy (Nov 8 2026, migration 181) is read through deps.etsyReader (lib/etsyApi.js),
// Amazon (Nov 8 2026, migration 182) through deps.amazonReader (lib/amazonApi.js).
var PLATFORMS = ["shopify", "woocommerce", "etsy", "amazon"];
var PLATFORM_LABEL = { shopify: "Shopify", woocommerce: "WooCommerce", etsy: "Etsy", amazon: "Amazon" };
var SHOPIFY_API_VERSION = "2026-07";
var ORDER_WINDOW_DAYS = 60;
// The most pages each paged WooCommerce request reads in one sync: pages of
// 100 rows of only the fields used; 40 is 4,000. Shopify's paging and caps are
// lib/shopifyApi.js's (GraphQL cursors, 200 pages).
var PAGE_CAPS = { other: 40 };
var MAX_ATTEMPTS = 4;
var RETRY_CAP_MS = 30000;
var REQUEST_GAP_MS = 500;
var REQUEST_TIMEOUT_MS = 20000;
// lib/guardedFetch.js's JSON_MAX_BODY_BYTES_CEILING. A page over it fails as too_large, never retried.
var REQUEST_MAX_BODY_BYTES = 8 * 1024 * 1024;
// The only answer headers read: the wait on a 429 and WooCommerce's page count.
var REQUEST_EXPOSED_HEADERS = ["retry-after", "x-wp-totalpages"];
var UPSERT_CHUNK = 200;
// What a sync reads of a connection: the sealed credentials, and for Shopify
// (migration 176) the sealed access token, its expiries, its version and the
// chosen location. Never returned to a member.
var SYNC_COLUMNS = "id, user_id, platform, store_url, status, permission, credentials_ciphertext, credentials_iv, credentials_auth_tag, " +
  "access_ciphertext, access_iv, access_auth_tag, access_expires_at, refresh_expires_at, token_version, location_id, location_name, currency, created_at, " +
  // Etsy (migration 181): the shop id, and the scopes that decide whether changes are allowed.
  "external_account_id, granted_scopes, " +
  // Amazon (migration 182): the marketplace chosen at connect, and its region.
  "marketplace_id, region";
var STATE_TTL_MS = 30 * 60 * 1000;
var TICK_CONNECTION_LIMIT = 500;
// Retried after a wait. 401 and 403 are not here: an auth failure is never retried.
var RETRYABLE = [429, 500, 502, 503, 504];

// The two permissions a connection can hold (migration 175). A Shopify
// connection is "read_write" only with both write scopes granted (176).
var PERMISSIONS = ["read", "read_write"];
var SHOPIFY_WRITE_SCOPES = ["write_products", "write_inventory"];
// An Etsy connection (migration 181) is "read_write" only with listings_w granted.
var ETSY_WRITE_SCOPES = ["listings_w"];

var MESSAGES = {
  readOnly: "BizForce only reads your store. It never changes your products, prices or orders.",
  readWrite: "BizForce reads your store. It changes a price or stock level only when you approve that change.",
  wooPermissionMismatch: "The key WooCommerce made does not have the access BizForce asked for, so BizForce did not save it. Connect again and approve the access shown.",
  shopifyDomain: "Enter your shop's myshopify.com address, for example yourstore.myshopify.com. It is shown in Shopify under Settings, Domains.",
  wooUrl: "Enter your store's address starting with https://, for example https://shop.example.com. WooCommerce keys are only sent over https.",
  wooNotReadOnly: "The key WooCommerce made is not read-only, so BizForce did not save it. Connect again and approve the Read access BizForce asks for.",
  wooRejected: "Your store did not accept the key it made, so nothing was saved. Try connecting again.",
  unreachable: "Your store did not answer just now, so nothing was saved. Try again in a few minutes.",
  noSecret: "Stores can't be connected on this server just now: its encryption key is not set. Nothing was sent to your store and nothing was saved."
};

/* "read" or "read_write"; anything else is "read". A Shopify row is
   "read_write" only when its permission says so AND both write scopes were
   granted (migration 176). A scope granted beyond what was asked never makes
   a "read" row writable: permission alone decides. An Amazon row (migration
   182) has no scopes (the SP-API grants roles to the app, not the member):
   the member's own "Let BizForce make changes" choice alone decides, as for
   WooCommerce. Four platforms, each named; any other is "read". */
function permissionOf(row) {
  if (!row || row.permission !== "read_write") return "read";
  var granted = String(row.granted_scopes || "").split(",");
  if (row.platform === "woocommerce") return "read_write";
  if (row.platform === "amazon") return "read_write";
  if (row.platform === "etsy") return ETSY_WRITE_SCOPES.every(function (s) { return granted.indexOf(s) !== -1; }) ? "read_write" : "read";
  if (row.platform === "shopify") return SHOPIFY_WRITE_SCOPES.every(function (s) { return granted.indexOf(s) !== -1; }) ? "read_write" : "read";
  return "read";
}
/* What a connection's answers say about changes: true to what it may do. */
function noteFor(permission) {
  return permission === "read_write" ? MESSAGES.readWrite : MESSAGES.readOnly;
}

function storeSyncEnabled(env) {
  return (env || process.env).ENABLE_STORE_SYNC === "true";
}

function cut(value, n) {
  var s = String(value == null ? "" : value);
  return s.length > n ? s.slice(0, n) : s;
}

/* "your-shop.myshopify.com", or null. Accepts the address with or without
   https:// and a trailing slash or path, and nothing but *.myshopify.com. */
function normalizeShopifyDomain(input) {
  if (typeof input !== "string") return null;
  var s = input.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  return /^[a-z0-9][a-z0-9-]{0,61}\.myshopify\.com$/.test(s) ? s : null;
}

/* "https://shop.example.com" (an origin, no path), or null. https only, the
   default port only, no user or password in it, a real dotted host name and
   never an IP address. */
function normalizeWooUrl(input) {
  if (typeof input !== "string") return null;
  var url;
  try { url = new URL(input.trim()); } catch (e) { return null; }
  if (url.protocol !== "https:") return null;
  if (url.username || url.password) return null;
  if (url.port && url.port !== "443") return null;
  var host = url.hostname.toLowerCase();
  if (!/^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(host)) return null;
  return "https://" + host;
}

/* ── credentials ─────────────────────────────────────────────────────────── */
function sealCredentials(creds, encrypt) {
  var plain = JSON.stringify(creds);
  var sealed = encrypt(plain);
  return { credentials_ciphertext: sealed.ciphertext, credentials_iv: sealed.iv, credentials_auth_tag: sealed.authTag };
}

function openCredentials(row, decrypt) {
  return JSON.parse(decrypt({ ciphertext: row.credentials_ciphertext, iv: row.credentials_iv, authTag: row.credentials_auth_tag }));
}

/* "ShopName" from "https://www.etsy.com/shop/ShopName", or null. */
function etsyShopName(storeUrl) {
  var m = /^https:\/\/www\.etsy\.com\/shop\/([A-Za-z0-9]{1,60})$/.exec(String(storeUrl || ""));
  return m ? m[1] : null;
}

/* An Amazon row's marketplace, from lib/amazonAuth.js's table: { id, code,
   region }, each null when the row's marketplace is not in the table. */
function amazonMarketplace(row) {
  var m = require("./amazonAuth").marketplaceOf(row && row.marketplace_id);
  return m && m.region === row.region ? { id: row.marketplace_id, code: m.code, region: m.region } : { id: null, code: null, region: null };
}

/* The only fields a status answer, a log line or the export ever carries. */
function statusOf(row) {
  return {
    id: row.id,
    platform: row.platform,
    platform_label: PLATFORM_LABEL[row.platform] || row.platform,
    store: row.store_url,
    status: row.status,
    permission: permissionOf(row),
    currency: typeof row.currency === "string" && /^[A-Z]{3}$/.test(row.currency) ? row.currency : null,
    // Shopify (migration 176): where stock changes apply, and what the synced stock counts.
    location_id: row.platform === "shopify" ? row.location_id || null : null,
    location_name: row.platform === "shopify" ? row.location_name || null : null,
    stock_scope: row.platform === "shopify" ? (row.location_id ? "location" : "total") : null,
    // Etsy (migration 181): the shop's name, the last part of its https://www.etsy.com/shop/<ShopName> address.
    shop_name: row.platform === "etsy" ? etsyShopName(row.store_url) : null,
    // Amazon (migration 182): the marketplace chosen at connect, its two-letter code and its region.
    marketplace_id: row.platform === "amazon" ? amazonMarketplace(row).id : null,
    marketplace: row.platform === "amazon" ? amazonMarketplace(row).code : null,
    region: row.platform === "amazon" ? amazonMarketplace(row).region : null,
    connected_since: row.created_at || null,
    last_sync_at: row.last_sync_at || null,
    last_error_code: row.last_error_code || null
  };
}

/* ── the one request function: GET only ─────────────────────────────────── */
function StoreAuthError(code) { this.name = "StoreAuthError"; this.code = code; this.message = "the store refused the credentials (" + code + ")"; }
StoreAuthError.prototype = Object.create(Error.prototype);
function StoreRequestError(code) { this.name = "StoreRequestError"; this.code = code; this.message = "store request failed (" + code + ")"; }
StoreRequestError.prototype = Object.create(Error.prototype);

function retryWaitMs(res, attempt) {
  var after = res && res.headers && typeof res.headers.get === "function" ? res.headers.get("retry-after") : null;
  var secs = Number(after);
  var ms = isFinite(secs) && secs >= 0 ? secs * 1000 : Math.pow(2, attempt) * 1000;
  return Math.min(ms, RETRY_CAP_MS);
}

/* The guarded fetcher hands back a plain object of the exposed headers; the
   callers read it through get(name), as they read a fetch Headers. */
function headerReader(plain) {
  var h = {};
  Object.keys(plain || {}).forEach(function (k) { h[String(k).toLowerCase()] = String(plain[k]); });
  return { get: function (k) { var n = String(k).toLowerCase(); return Object.prototype.hasOwnProperty.call(h, n) ? h[n] : null; } };
}

/* What the guarded fetcher's refusals and failures become here. Only a
   network failure or a timeout is worth trying again; a refusal (a private or
   loopback address, a bad address, a redirect, a body over the limit, an
   answer that is not JSON) is the same the next time, so it is never retried. */
var GUARD_RETRIED = ["network", "timeout"];
var GUARD_CODES = { blocked: "blocked_address", invalid_url: "invalid_url", redirected: "redirected", too_large: "too_large",
  unaccepted_type: "not_json", not_json: "not_json", dns: "dns", challenge: "not_json" };

/* One GET, paced, with backoff on 429 and 5xx, through the guarded fetcher
   (deps.jsonRequest, lib/guardedFetch.js's guardedJsonRequest in server.js):
   https on 443 only, DNS checked and pinned on the same lookup the socket
   uses (no rebinding gap), no redirect ever followed (a credential is never
   sent anywhere but the store it was made for), REQUEST_MAX_BODY_BYTES of body
   and REQUEST_TIMEOUT_MS in all. Resolves { data, headers }. A 401 or 403
   throws StoreAuthError at once; anything else that fails throws
   StoreRequestError. */
async function request(deps, url, headers) {
  for (var attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    await deps.sleep(attempt === 0 ? REQUEST_GAP_MS : 0);
    var res;
    try {
      var answer = await deps.jsonRequest(url, { method: "GET", headers: headers, exposeHeaders: REQUEST_EXPOSED_HEADERS,
        maxBytes: REQUEST_MAX_BODY_BYTES, timeoutMs: REQUEST_TIMEOUT_MS });
      res = { status: answer.status, json: answer.json, headers: headerReader(answer.headers) };
    } catch (err) {
      var guard = err && err.guardedFetch === true ? String(err.code) : null;
      if (guard === null || GUARD_RETRIED.indexOf(guard) === -1) {
        throw new StoreRequestError(guard === null ? "guard_refused" : GUARD_CODES[guard] || "unreachable");
      }
      if (attempt + 1 < MAX_ATTEMPTS) { await deps.sleep(Math.pow(2, attempt) * 1000); continue; }
      throw new StoreRequestError("unreachable");
    }
    if (RETRYABLE.indexOf(res.status) !== -1) {
      if (attempt + 1 < MAX_ATTEMPTS) { await deps.sleep(retryWaitMs(res, attempt)); continue; }
      throw new StoreRequestError(res.status === 429 ? "rate_limited" : "http_" + res.status);
    }
    if (res.status === 401 || res.status === 403) throw new StoreAuthError("http_" + res.status);
    if (res.status >= 300 && res.status < 400) throw new StoreRequestError("redirected");
    if (res.status < 200 || res.status >= 300) throw new StoreRequestError("http_" + res.status);
    if (res.json === null || res.json === undefined) throw new StoreRequestError("not_json");
    return { data: res.json, headers: res.headers };
  }
  throw new StoreRequestError("unreachable");
}

function money(v) {
  if (v === null || v === undefined || v === "") return null;
  var n = Number(v);
  return isFinite(n) ? Math.round(n * 100) / 100 : null;
}

/* ── Shopify ─────────────────────────────────────────────────────────────── */
// NAMED (Nov 7 2026, Shopify on OAuth, migration 176): BEFORE this file read a
// shop with REST GETs (products.json, inventory_items.json, orders.json) and a
// pasted shpat_ token. AFTER it holds no Shopify request at all: syncConnection
// calls deps.shopifyReader (lib/shopifyApi.js in server.js), GraphQL reads.

/* ── WooCommerce ─────────────────────────────────────────────────────────── */
function wooHeaders(creds) {
  return { "Authorization": "Basic " + Buffer.from(creds.consumer_key + ":" + creds.consumer_secret).toString("base64"), "Accept": "application/json" };
}
function wooUrl(storeUrl, path) {
  return storeUrl + "/wp-json/wc/v3" + path;
}

function stateKey(secret) {
  return crypto.createHash("sha256").update("bizforce-store-connect-state:" + String(secret || "")).digest();
}
/* The value WooCommerce hands back to the callback as user_id: who asked, for
   which store, with which permission, until when, signed so nobody else can
   make one. */
function makeWooState(userId, storeUrl, nowMs, secret, permission) {
  var p = permission === "read_write" ? "read_write" : "read";
  var body = Buffer.from(JSON.stringify({ u: userId, s: storeUrl, p: p, e: nowMs + STATE_TTL_MS })).toString("base64url");
  var sig = crypto.createHmac("sha256", stateKey(secret)).update(body).digest("base64url");
  return body + "." + sig;
}
function readWooState(token, nowMs, secret) {
  if (typeof token !== "string" || token.indexOf(".") === -1) return null;
  var parts = token.split(".");
  if (parts.length !== 2) return null;
  var want = crypto.createHmac("sha256", stateKey(secret)).update(parts[0]).digest();
  var got;
  try { got = Buffer.from(parts[1], "base64url"); } catch (e) { return null; }
  if (got.length !== want.length || !crypto.timingSafeEqual(got, want)) return null;
  var s;
  try { s = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")); } catch (e) { return null; }
  if (!s || typeof s.u !== "string" || typeof s.s !== "string" || typeof s.e !== "number" || nowMs > s.e) return null;
  if (normalizeWooUrl(s.s) !== s.s) return null;
  // A state made before migration 175 carries no p: it asked for read.
  var p = s.p === undefined ? "read" : s.p;
  if (PERMISSIONS.indexOf(p) === -1) return null;
  return { userId: s.u, storeUrl: s.s, permission: p };
}

/* WooCommerce's own authorization page, asking for Read access, or Read/Write
   only when the member allowed changes. */
function wooAuthorizeUrl(storeUrl, state, callbackUrl, returnUrl, permission) {
  return storeUrl + "/wc-auth/v1/authorize?app_name=" + encodeURIComponent("BizForce AI") +
    "&scope=" + (permission === "read_write" ? "read_write" : "read") + "&user_id=" + encodeURIComponent(state) +
    "&return_url=" + encodeURIComponent(returnUrl) + "&callback_url=" + encodeURIComponent(callbackUrl);
}

/* The callback's key: { ok: true, creds, permission } or { ok: false, code, error }.
   The key's permission must be exactly the one the signed state asked for. */
function checkWooKey(body, requested) {
  var b = body || {};
  var want = requested === "read_write" ? "read_write" : "read";
  if (b.key_permissions !== want) {
    return want === "read" ? { ok: false, code: "not_read_only", error: MESSAGES.wooNotReadOnly }
      : { ok: false, code: "permission_mismatch", error: MESSAGES.wooPermissionMismatch };
  }
  var key = typeof b.consumer_key === "string" ? b.consumer_key.trim() : "";
  var secret = typeof b.consumer_secret === "string" ? b.consumer_secret.trim() : "";
  if (!/^ck_[A-Za-z0-9]{20,100}$/.test(key) || !/^cs_[A-Za-z0-9]{20,100}$/.test(secret)) {
    return { ok: false, code: "key_format", error: MESSAGES.wooRejected };
  }
  return { ok: true, creds: { consumer_key: key, consumer_secret: secret }, permission: want };
}

/* One read call with the key. { ok: true } or { ok: false, code, error }. */
async function verifyWoo(deps, storeUrl, creds) {
  try {
    await request(deps, wooUrl(storeUrl, "/products?per_page=1&_fields=id"), wooHeaders(creds));
    return { ok: true };
  } catch (err) {
    if (err instanceof StoreAuthError) return { ok: false, code: "woo_rejected", error: MESSAGES.wooRejected };
    console.error("[StoreSync] woocommerce verify failed: " + (err instanceof StoreRequestError ? err.code : "request_failed"));
    return { ok: false, code: "store_unreachable", error: MESSAGES.unreachable };
  }
}

async function wooPages(deps, storeUrl, creds, path, each) {
  for (var page = 1; page <= PAGE_CAPS.other; page++) {
    var got = await request(deps, wooUrl(storeUrl, path + (path.indexOf("?") === -1 ? "?" : "&") + "per_page=100&page=" + page), wooHeaders(creds));
    var rows = Array.isArray(got.data) ? got.data : [];
    rows.forEach(each);
    var total = Number(got.headers && got.headers.get ? got.headers.get("x-wp-totalpages") : NaN);
    if (rows.length < 100 || (isFinite(total) && page >= total)) break;
  }
}

/* A variation's parent product id (migration 175), so an approved change can
   name /products/<parent>/variations/<id>; null for a simple product, and
   null for anything that is not a plain number. */
function parentIdOf(id) {
  var s = id == null ? "" : String(id);
  return /^[0-9]{1,100}$/.test(s) ? s : null;
}

function wooItem(externalId, name, row, parentId) {
  return {
    external_id: externalId,
    external_parent_id: parentId === undefined ? null : parentIdOf(parentId),
    name: cut(name, 200),
    sku: row.sku ? cut(String(row.sku).trim(), 100) || null : null,
    unit_price: money(row.price),
    unit_cost: null,
    quantity_on_hand: Math.trunc(row.stock_quantity)
  };
}

async function fetchWooItems(deps, storeUrl, creds) {
  var out = { items: [], skipped_untracked: 0 };
  var variable = [];
  await wooPages(deps, storeUrl, creds, "/products?_fields=id,name,type,sku,price,stock_quantity,manage_stock", function (p) {
    if (p.type === "variable") { variable.push(p); return; }
    if (p.manage_stock !== true || typeof p.stock_quantity !== "number") { out.skipped_untracked++; return; }
    out.items.push(wooItem("product:" + p.id, p.name || "Untitled", p));
  });
  for (var i = 0; i < variable.length; i++) {
    var parent = variable[i];
    await wooPages(deps, storeUrl, creds, "/products/" + encodeURIComponent(parent.id) + "/variations?_fields=id,sku,price,stock_quantity,manage_stock,attributes", function (v) {
      if (v.manage_stock !== true || typeof v.stock_quantity !== "number") { out.skipped_untracked++; return; }
      var label = (v.attributes || []).map(function (a) { return a && a.option; }).filter(Boolean).join(" / ");
      out.items.push(wooItem("variation:" + v.id, (parent.name || "Untitled") + (label ? " - " + label : ""), v, parent.id));
    });
  }
  return out;
}

/* Only the order fields summaryOf reads: the line items' SKU and quantity, never
   the whole line item (WordPress's _fields takes nested names), so a page of 100
   orders stays small. */
// NAMED (Nov 11 2026, orbit stage 2): status too (cancelled, failed and refunded orders never count).
var WOO_ORDER_FIELDS = "id,date_created_gmt,total,currency,status,line_items.sku,line_items.quantity";
async function fetchWooOrders(deps, storeUrl, creds, sinceIso) {
  var out = [];
  await wooPages(deps, storeUrl, creds, "/orders?after=" + encodeURIComponent(sinceIso) + "&_fields=" + WOO_ORDER_FIELDS, function (o) {
    out.push(summaryOf("woocommerce", o));
  });
  return out;
}

/* The store's currency code (migration 176), or null. One GET, after the
   products and orders; any failure, a refusal included, is null and changes
   nothing else, so a key that cannot read it still syncs. */
async function fetchWooCurrency(deps, storeUrl, creds) {
  try {
    var got = await request(deps, wooUrl(storeUrl, "/data/currencies/current"), wooHeaders(creds));
    var code = got.data && typeof got.data.code === "string" ? got.data.code : "";
    return /^[A-Z]{3}$/.test(code) ? code : null;
  } catch (err) {
    return null;
  }
}

/* ── the order summary: a whitelist, never a copy ───────────────────────── */
// NAMED (Nov 11 2026, orbit stage 2): THE ORDER'S STATUS (migration 183).
var ORDER_STATUSES = ["active", "cancelled", "refunded"];
/* The platform's own order state, as the reader hands it to summaryOf:
     shopify      cancelled_at (cancelledAt) set: cancelled; financial_status (displayFinancialStatus) REFUNDED: refunded
     woocommerce  status cancelled or failed: cancelled; refunded: refunded
     etsy         status Canceled: cancelled; Fully Refunded: refunded
     amazon       order_status (OrderStatus) Canceled: cancelled; refunds are not in Amazon's order list, so active
   Anything else is active. */
function orderStatusOf(platform, o) {
  var s = function (v) { return typeof v === "string" ? v.trim().toLowerCase() : ""; };
  if (platform === "shopify") {
    if (o && o.cancelled_at) return "cancelled";
    return s(o && o.financial_status) === "refunded" ? "refunded" : "active";
  }
  if (platform === "woocommerce") {
    var w = s(o && o.status);
    return w === "cancelled" || w === "failed" ? "cancelled" : w === "refunded" ? "refunded" : "active";
  }
  if (platform === "etsy") {
    var e = s(o && o.status);
    return e === "canceled" || e === "cancelled" ? "cancelled" : e === "fully refunded" ? "refunded" : "active";
  }
  if (platform === "amazon") return s(o && o.order_status) === "canceled" ? "cancelled" : "active";
  return "active";
}


// The only keys a stored order summary has. Nothing about the customer.
var SUMMARY_KEYS = ["external_id", "ordered_at", "total", "currency", "status", "line_items"];
function summaryOf(platform, o) {
  // Four platforms, each named; an unknown one is refused, never read as WooCommerce.
  var when, total;
  if (platform === "shopify") { when = o.created_at; total = o.total_price; }
  else if (platform === "etsy") { when = o.created_at; total = o.total; }
  else if (platform === "amazon") { when = o.created_at; total = o.total; }
  else if (platform === "woocommerce") { when = o.date_created_gmt ? String(o.date_created_gmt).replace(/Z?$/, "Z") : null; total = o.total; }
  else throw new StoreRequestError("unknown_platform");
  var currency = typeof o.currency === "string" && /^[A-Za-z]{3}$/.test(o.currency) ? o.currency.toUpperCase() : null;
  return {
    external_id: cut(String(o.id), 100),
    ordered_at: when,
    total: money(total),
    currency: currency,
    // NAMED (Nov 11 2026, orbit stage 2): the platform's own state, as active, cancelled or refunded (migration 183).
    status: orderStatusOf(platform, o),
    line_items: (o.line_items || []).map(function (li) {
      return { sku: li && li.sku ? cut(String(li.sku), 100) : null, quantity: li && typeof li.quantity === "number" ? li.quantity : null };
    })
  };
}

/* ── writing to BizForce's own tables ────────────────────────────────────── */
async function readAllRows(build) {
  var rows = [];
  for (var from = 0; ; from += 1000) {
    var got = await build().range(from, from + 999);
    if (got.error) throw got.error;
    rows = rows.concat(got.data || []);
    if ((got.data || []).length < 1000) break;
  }
  return rows;
}

/* The synced items into inventory_items. A SKU already on another of the
   member's rows (one they entered, or another store's) is skipped and counted. */
async function applyItems(supabase, conn, items, stamp) {
  var existing = await readAllRows(function () {
    return supabase.from("inventory_items").select("id, sku, source, store_connection_id, external_id")
      .eq("user_id", conn.user_id).order("id", { ascending: true });
  });
  var skuOwner = new Map();
  existing.forEach(function (r) { if (r.sku) skuOwner.set(String(r.sku).toLowerCase(), r); });
  var seen = new Set();
  var result = { written: 0, skipped_sku_conflict: 0, skipped_sku_manual: 0 };
  var withCost = [], withoutCost = [];
  items.forEach(function (it) {
    if (it.sku) {
      var key = it.sku.toLowerCase();
      var owner = skuOwner.get(key);
      var mine = owner && owner.store_connection_id === conn.id && owner.external_id === it.external_id;
      // A member's own row (no source) is never overwritten, merged or renamed.
      if (owner && !mine && owner.source == null) { result.skipped_sku_manual++; return; }
      if ((owner && !mine) || seen.has(key)) { result.skipped_sku_conflict++; return; }
      seen.add(key);
    }
    var row = {
      user_id: conn.user_id, source: conn.platform, store_connection_id: conn.id, external_id: it.external_id,
      external_parent_id: it.external_parent_id || null,
      // Shopify's inventory item (migration 176), so a stock change can name it; null for WooCommerce.
      external_inventory_item_id: it.external_inventory_item_id || null,
      name: it.name, sku: it.sku, unit_price: it.unit_price, quantity_on_hand: it.quantity_on_hand,
      synced_at: stamp, updated_at: stamp
    };
    // A cost the store does not have is not sent, so one the member typed on a synced row stays.
    if (it.unit_cost != null) { row.unit_cost = it.unit_cost; withCost.push(row); } else withoutCost.push(row);
  });
  var groups = [withCost, withoutCost];
  for (var g = 0; g < groups.length; g++) {
    for (var i = 0; i < groups[g].length; i += UPSERT_CHUNK) {
      var chunk = groups[g].slice(i, i + UPSERT_CHUNK);
      var up = await supabase.from("inventory_items").upsert(chunk, { onConflict: "store_connection_id,external_id" });
      if (up.error) throw up.error;
      result.written += chunk.length;
    }
  }
  return result;
}

async function applyOrders(supabase, conn, summaries, stamp) {
  var rows = summaries.filter(function (s) { return s.external_id && s.ordered_at; }).map(function (s) {
    var row = { user_id: conn.user_id, connection_id: conn.id, platform: conn.platform, updated_at: stamp };
    SUMMARY_KEYS.forEach(function (k) { row[k] = s[k]; });
    return row;
  });
  for (var i = 0; i < rows.length; i += UPSERT_CHUNK) {
    var up = await supabase.from("store_order_summaries").upsert(rows.slice(i, i + UPSERT_CHUNK), { onConflict: "connection_id,external_id" });
    if (up.error) throw up.error;
  }
  return rows.length;
}

/* Amazon (migration 182): every "submitted" change on this connection whose
   item the sync now reads with the change's new value becomes "confirmed".
   One conditional update per row (still submitted), so a row is promoted
   once. Resolves how many were. */
async function promoteSubmitted(supabase, conn, items) {
  var open = await supabase.from("store_change_log").select("id, external_id, field, new_value")
    .eq("connection_id", conn.id).eq("user_id", conn.user_id).eq("confirmation", "submitted");
  if (open.error) throw open.error;
  var byId = new Map();
  (items || []).forEach(function (it) { byId.set(it.external_id, it); });
  var promoted = 0;
  var rows = open.data || [];
  for (var i = 0; i < rows.length; i++) {
    var r = rows[i];
    var it = byId.get(r.external_id);
    if (!it) continue;
    var shows = r.field === "price" ? it.unit_price !== null && it.unit_price !== undefined && Number(it.unit_price).toFixed(2) === Number(r.new_value).toFixed(2)
      : r.field === "stock" ? it.quantity_on_hand === Math.trunc(Number(r.new_value)) : false;
    if (!shows) continue;
    var up = await supabase.from("store_change_log").update({ confirmation: "confirmed" })
      .eq("id", r.id).eq("connection_id", conn.id).eq("confirmation", "submitted").select("id");
    if (up.error) throw up.error;
    promoted += (up.data || []).length;
  }
  return promoted;
}

/* An auth failure: needs_reconnect and ONE notice, only when it was connected. Never throws. */
async function markNeedsReconnect(supabase, conn, code, stamp) {
  try {
    var marked = await supabase.from("member_store_connections")
      .update({ status: "needs_reconnect", last_error_code: cut(code, 60), last_error_at: stamp, updated_at: stamp })
      .eq("id", conn.id).eq("status", "connected").select("id");
    if (marked.error || !(marked.data || []).length) return false;
    var label = PLATFORM_LABEL[conn.platform] || conn.platform;
    var notice = await supabase.from("notifications").insert({
      user_id: conn.user_id,
      type: "store_reconnect",
      title: "Reconnect your " + label + " store",
      message: label + " refused the key BizForce saved for " + conn.store_url + ", so your stock was not read and nothing will be " +
        "tried again. Connect the store again on the Store Agent page.",
      read: false
    });
    if (notice.error) console.warn("[StoreSync] the reconnect notice could not be saved:", notice.error.message || notice.error);
    return true;
  } catch (err) {
    console.error("[StoreSync] marking a connection needs_reconnect failed:", (err && err.message) || err);
    return false;
  }
}

/* One store, read and written. Resolves { ok, ... }; never throws. */
async function syncConnection(deps, conn) {
  var supabase = deps.supabase;
  var stamp = new Date(deps.now()).toISOString();
  var since = new Date(deps.now() - ORDER_WINDOW_DAYS * 24 * 60 * 60 * 1000).toISOString();
  var creds = null;
  if (conn.platform === "woocommerce") {
    try { creds = openCredentials(conn, deps.decrypt); } catch (e) {
      await markNeedsReconnect(supabase, conn, "credentials_unreadable", stamp);
      return { ok: false, code: "credentials_unreadable", needs_reconnect: true };
    }
  }
  try {
    var fetched, orders, currency = null;
    if (conn.platform === "shopify") {
      // GraphQL reads through the injected reader (lib/shopifyApi.js); it opens and refreshes the token itself.
      var reader = deps.shopifyReader;
      if (!reader) throw new StoreRequestError("not_configured");
      var session = reader.session(conn);
      var info = await reader.shopInfo(deps, session);
      fetched = await reader.fetchItems(deps, session);
      orders = await reader.fetchOrders(deps, session, since);
      currency = info.currency;
    } else if (conn.platform === "etsy") {
      // GET reads through the injected reader (lib/etsyApi.js); it opens and refreshes the token itself.
      var etsyReader = deps.etsyReader;
      if (!etsyReader) throw new StoreRequestError("not_configured");
      var etsySession = etsyReader.session(conn);
      var shopNow = await etsyReader.shopInfo(deps, etsySession);
      fetched = await etsyReader.fetchItems(deps, etsySession);
      orders = await etsyReader.fetchOrders(deps, etsySession, since);
      currency = shopNow.currency;
    } else if (conn.platform === "amazon") {
      // GET reads through the injected reader (lib/amazonApi.js); it opens and refreshes the token itself.
      var amazonReader = deps.amazonReader;
      if (!amazonReader) throw new StoreRequestError("not_configured");
      var amazonSession = amazonReader.session(conn);
      var marketNow = await amazonReader.shopInfo(deps, amazonSession);
      fetched = await amazonReader.fetchItems(deps, amazonSession);
      orders = await amazonReader.fetchOrders(deps, amazonSession, since);
      currency = marketNow.currency;
    } else if (conn.platform === "woocommerce") {
      fetched = await fetchWooItems(deps, conn.store_url, creds);
      orders = await fetchWooOrders(deps, conn.store_url, creds, since);
      currency = await fetchWooCurrency(deps, conn.store_url, creds);
    } else {
      throw new StoreRequestError("unknown_platform");
    }
    creds = null;
    var items = await applyItems(supabase, conn, fetched.items, stamp);
    var orderCount = await applyOrders(supabase, conn, orders, stamp);
    // Amazon (migration 182): a change Amazon accepted but did not yet show is confirmed once the store shows it.
    var promoted = conn.platform === "amazon" ? await promoteSubmitted(supabase, conn, fetched.items) : 0;
    var finished ={ last_sync_at: stamp, last_error_code: null, last_error_at: null, updated_at: stamp };
    if (currency) finished.currency = currency;
    var done = await supabase.from("member_store_connections").update(finished).eq("id", conn.id);
    if (done.error) throw done.error;
    return { ok: true, items_written: items.written, skipped_sku_manual: items.skipped_sku_manual, skipped_sku_conflict: items.skipped_sku_conflict,
      skipped_untracked: fetched.skipped_untracked, skipped_not_at_location: fetched.skipped_not_at_location || 0,
      skipped_disabled: fetched.skipped_disabled || 0, skipped_id_too_long: fetched.skipped_id_too_long || 0, orders: orderCount,
      changes_confirmed: promoted, currency: currency, synced_at: stamp };
  } catch (err) {
    creds = null;
    if (err instanceof StoreAuthError) {
      var told = await markNeedsReconnect(supabase, conn, err.code, stamp);
      return { ok: false, code: err.code, needs_reconnect: true, told: told };
    }
    var code = err instanceof StoreRequestError ? err.code : "sync_failed";
    try {
      await supabase.from("member_store_connections").update({ last_error_code: cut(code, 60), last_error_at: stamp, updated_at: stamp }).eq("id", conn.id);
    } catch (e) { /* the result says what happened */ }
    console.error("[StoreSync] " + conn.platform + " connection " + conn.id + " failed: " + code);
    // A page over the size limit is recorded and logged as too_large; the member is told what an unreachable store tells them.
    return { ok: false, code: code === "too_large" ? "unreachable" : code };
  }
}

/* Disconnect: everything synced from the store, then the connection. */
async function deleteConnectionData(supabase, userId, connectionId) {
  var items = await readAllRows(function () {
    return supabase.from("inventory_items").select("id").eq("user_id", userId).eq("store_connection_id", connectionId).order("id", { ascending: true });
  });
  var ids = items.map(function (r) { return r.id; });
  for (var i = 0; i < ids.length; i += UPSERT_CHUNK) {
    var chunk = ids.slice(i, i + UPSERT_CHUNK);
    var mv = await supabase.from("inventory_movements").delete().in("item_id", chunk);
    if (mv.error) throw mv.error;
  }
  var gone = await supabase.from("inventory_items").delete().eq("user_id", userId).eq("store_connection_id", connectionId);
  if (gone.error) throw gone.error;
  var orders = await supabase.from("store_order_summaries").delete().eq("user_id", userId).eq("connection_id", connectionId);
  if (orders.error) throw orders.error;
  // The record of approved changes (migration 175) goes with the connection; ON DELETE CASCADE would too.
  var changes = await supabase.from("store_change_log").delete().eq("user_id", userId).eq("connection_id", connectionId);
  if (changes.error) throw changes.error;
  var conn = await supabase.from("member_store_connections").delete().eq("user_id", userId).eq("id", connectionId).select("id, platform");
  if (conn.error) throw conn.error;
  var gone = (conn.data || [])[0];
  return { items: ids.length, removed: !!gone, platform: gone ? gone.platform : null };
}

/* ── the daily sync ──────────────────────────────────────────────────────── */
function storeSyncClaimDay(nowMs) {
  return new Date(nowMs).toISOString().slice(0, 10);
}

async function claimStoreSyncDay(supabase, nowMs) {
  var today = storeSyncClaimDay(nowMs);
  var started = new Date(nowMs).toISOString();
  var inserted = await supabase
    .from("job_runs")
    .insert({ job_name: STORE_SYNC_JOB_NAME, last_run_on: today, started_at: started, finished_at: null, last_error: null })
    .select("job_name");
  if (!inserted.error) return true;
  // 23505 = unique_violation: the row exists. Anything else is a failure, never a claim.
  if (inserted.error.code !== "23505") {
    console.error("[StoreSync] Claim insert failed:", inserted.error.message);
    return false;
  }
  var updated = await supabase
    .from("job_runs")
    .update({ last_run_on: today, started_at: started, finished_at: null, last_error: null })
    .eq("job_name", STORE_SYNC_JOB_NAME)
    .or("last_run_on.is.null,last_run_on.neq." + today)
    .select("job_name");
  if (updated.error) {
    console.error("[StoreSync] Claim update failed:", updated.error.message);
    return false;
  }
  return (updated.data || []).length > 0;
}

async function finishStoreSync(supabase, errorMessage) {
  var patch = { finished_at: new Date().toISOString() };
  if (errorMessage) patch.last_error = String(errorMessage).slice(0, 2000);
  var result = await supabase.from("job_runs").update(patch).eq("job_name", STORE_SYNC_JOB_NAME);
  if (result.error) console.error("[StoreSync] Failed to record run completion:", result.error.message);
}

/* The pass: every connected store whose member is entitled, one at a time. */
async function runStoreSyncPass(deps) {
  var summary = { stores: 0, synced: 0, failed: 0, needs_reconnect: 0, skipped_not_entitled: 0, error: null };
  var read = await deps.supabase.from("member_store_connections")
    .select(SYNC_COLUMNS)
    .eq("status", "connected").order("id", { ascending: true }).limit(TICK_CONNECTION_LIMIT);
  if (read.error) { summary.error = "member_store_connections could not be read: " + (read.error.message || read.error); return summary; }
  var conns = read.data || [];
  for (var i = 0; i < conns.length; i++) {
    var conn = conns[i];
    summary.stores++;
    // Entitlement: an active subscription, read now. A failed lookup skips; it never syncs.
    var plan = await deps.userPlan(conn.user_id);
    if (!plan || plan.error || !plan.plan || plan.plan.active !== true) { summary.skipped_not_entitled++; continue; }
    var r = await syncConnection(deps, conn);
    if (r.ok) summary.synced++;
    else if (r.needs_reconnect) summary.needs_reconnect++;
    else summary.failed++;
  }
  console.log("[StoreSync] Pass finished: " + summary.stores + " store(s), " + summary.synced + " synced, " + summary.failed + " failed, " +
    summary.needs_reconnect + " need reconnecting, " + summary.skipped_not_entitled + " skipped (no active subscription).");
  return summary;
}

/* The 05:00 UTC cron: claim the day, run the pass, close the claim. Never rejects. */
async function storeSyncTick(deps, nowMs) {
  var startedMs = typeof nowMs === "number" ? nowMs : deps.now();
  try {
    if (!storeSyncEnabled(deps.env)) return { claimed: false, disabled: true };
    if (!(await claimStoreSyncDay(deps.supabase, startedMs))) {
      console.log("[StoreSync] Already claimed for " + storeSyncClaimDay(startedMs) + "; nothing to do.");
      return { claimed: false };
    }
    var summary = await runStoreSyncPass(deps);
    await finishStoreSync(deps.supabase, summary.error || (summary.failed ? summary.failed + " store(s) failed" : null));
    return { claimed: true, summary: summary };
  } catch (err) {
    console.error("[StoreSync] Pass error:", (err && err.message) || err);
    try { await finishStoreSync(deps.supabase, (err && err.message) || String(err)); } catch (e) { /* reported above */ }
    return { claimed: true, error: (err && err.message) || String(err) };
  }
}

module.exports = {
  STORE_SYNC_JOB_NAME: STORE_SYNC_JOB_NAME,
  PLATFORMS: PLATFORMS,
  PLATFORM_LABEL: PLATFORM_LABEL,
  SHOPIFY_API_VERSION: SHOPIFY_API_VERSION,
  SHOPIFY_WRITE_SCOPES: SHOPIFY_WRITE_SCOPES,
  ETSY_WRITE_SCOPES: ETSY_WRITE_SCOPES,
  SYNC_COLUMNS: SYNC_COLUMNS,
  REQUEST_GAP_MS: REQUEST_GAP_MS,
  ORDER_WINDOW_DAYS: ORDER_WINDOW_DAYS,
  ORDER_STATUSES: ORDER_STATUSES,
  orderStatusOf: orderStatusOf,
  MAX_ATTEMPTS: MAX_ATTEMPTS,
  PAGE_CAPS: PAGE_CAPS,
  REQUEST_TIMEOUT_MS: REQUEST_TIMEOUT_MS,
  REQUEST_MAX_BODY_BYTES: REQUEST_MAX_BODY_BYTES,
  REQUEST_EXPOSED_HEADERS: REQUEST_EXPOSED_HEADERS,
  WOO_ORDER_FIELDS: WOO_ORDER_FIELDS,
  SUMMARY_KEYS: SUMMARY_KEYS,
  MESSAGES: MESSAGES,
  PERMISSIONS: PERMISSIONS,
  permissionOf: permissionOf,
  noteFor: noteFor,
  // lib/storeWrite.js reuses these, so a write is addressed and signed exactly as a read is.
  wooHeaders: wooHeaders,
  wooUrl: wooUrl,
  parentIdOf: parentIdOf,
  storeSyncEnabled: storeSyncEnabled,
  normalizeShopifyDomain: normalizeShopifyDomain,
  normalizeWooUrl: normalizeWooUrl,
  sealCredentials: sealCredentials,
  openCredentials: openCredentials,
  statusOf: statusOf,
  etsyShopName: etsyShopName,
  request: request,
  verifyWoo: verifyWoo,
  fetchWooCurrency: fetchWooCurrency,
  checkWooKey: checkWooKey,
  makeWooState: makeWooState,
  readWooState: readWooState,
  wooAuthorizeUrl: wooAuthorizeUrl,
  summaryOf: summaryOf,
  syncConnection: syncConnection,
  promoteSubmitted: promoteSubmitted,
  markNeedsReconnect: markNeedsReconnect,
  deleteConnectionData: deleteConnectionData,
  claimStoreSyncDay: claimStoreSyncDay,
  runStoreSyncPass: runStoreSyncPass,
  storeSyncTick: storeSyncTick,
  StoreAuthError: StoreAuthError,
  StoreRequestError: StoreRequestError
};
