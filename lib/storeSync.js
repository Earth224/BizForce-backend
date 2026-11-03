// ── Store connections, read-only: Shopify and WooCommerce (migration 163) ─────
//
// WHAT IT DOES. A member connects their own Shopify or WooCommerce store to the
// Store agent. BizForce READS three things from it, and nothing else:
//   - products and variants: name, SKU, price, cost where the store has one,
//     and the stock level, written to the member's inventory_items as rows
//     marked with their source;
//   - orders: a SUMMARY of each order from the last ORDER_WINDOW_DAYS days, as
//     the store's order id, when it was placed, the total, the currency, and
//     the line items as SKU and quantity, written to store_order_summaries.
//     summaryOf builds the summary from a whitelist, so a customer's name,
//     email, address or phone can never be stored, whatever the store sends.
//
// IT NEVER WRITES TO THE STORE. Every request this file makes goes through
// request(), which sends GET and nothing else. scripts/checkStoreConnections.js
// scans this file and server.js for any other method aimed at a store.
//
// CREDENTIALS. Encrypted with lib/apiKeyCrypto.js (AES-256-GCM under
// ENCRYPTION_SECRET) before anything is sent to the store, stored only after
// the store accepts them, and never returned, logged or exported.
//   - Shopify: the shop's *.myshopify.com domain and an Admin API access token
//     from a custom app the member makes in their own Shopify admin, with the
//     scopes read_products, read_inventory and read_orders. Verified by one
//     read call (GET /admin/oauth/access_scopes.json); a token whose granted
//     scopes include any write_ scope is refused and nothing is stored.
//   - WooCommerce: the store's https address. A WooCommerce key's permission
//     cannot be read back with a read call, so BizForce asks the store to make
//     the key: WooCommerce's own authorization page (/wc-auth/v1/authorize,
//     scope=read) shows the member exactly what is asked, makes a REST API key
//     with Read permission when they approve, and sends it to BizForce's
//     callback with its permission. A key whose permission is not "read" is
//     refused. It is then verified by one read call before it is stored.
//
// RATE LIMITS. Each request is paced (REQUEST_GAP_MS), a 429 or a 5xx waits
// (the store's Retry-After, or 1, 2, 4 s) and is tried at most MAX_ATTEMPTS
// times, and pages are capped (MAX_PAGES).
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
// Everything outside (the Supabase client, fetch, the clock, sleep, DNS,
// encrypt and decrypt, the plan lookup) is injected, so a check drives it with
// stubs. It never requires server.js.
"use strict";

var crypto = require("crypto");

var STORE_SYNC_JOB_NAME = "store_sync";
var PLATFORMS = ["shopify", "woocommerce"];
var PLATFORM_LABEL = { shopify: "Shopify", woocommerce: "WooCommerce" };
var SHOPIFY_API_VERSION = "2026-07";
var SHOPIFY_REQUIRED_SCOPES = ["read_products", "read_inventory", "read_orders"];
var ORDER_WINDOW_DAYS = 60;
var MAX_PAGES = 40;
var MAX_ATTEMPTS = 4;
var RETRY_CAP_MS = 30000;
var REQUEST_GAP_MS = 500;
var REQUEST_TIMEOUT_MS = 20000;
var UPSERT_CHUNK = 200;
var STATE_TTL_MS = 30 * 60 * 1000;
var TICK_CONNECTION_LIMIT = 500;
// Retried after a wait. 401 and 403 are not here: an auth failure is never retried.
var RETRYABLE = [429, 500, 502, 503, 504];

var MESSAGES = {
  readOnly: "BizForce only reads your store. It never changes your products, prices or orders.",
  shopifyDomain: "Enter your shop's myshopify.com address, for example your-shop.myshopify.com. It is shown in Shopify under Settings, Domains.",
  shopifyToken: "Paste the Admin API access token from your custom app. It starts with shpat_.",
  shopifyWriteScope: "This token can change your store (it has a write_ permission), so BizForce did not save it. In your custom app, give it only read_products, read_inventory and read_orders, install it again, and paste the new token.",
  shopifyMissingScope: "This token is missing a permission BizForce needs to read your store. In your custom app, turn on read_products, read_inventory and read_orders, install it again, and paste the new token.",
  shopifyRejected: "Shopify did not accept this token for this shop, so nothing was saved. Check the shop address and copy the token again.",
  wooUrl: "Enter your store's address starting with https://, for example https://shop.example.com. WooCommerce keys are only sent over https.",
  wooNotReadOnly: "The key WooCommerce made is not read-only, so BizForce did not save it. Connect again and approve the Read access BizForce asks for.",
  wooRejected: "Your store did not accept the key it made, so nothing was saved. Try connecting again.",
  unreachable: "Your store did not answer just now, so nothing was saved. Try again in a few minutes.",
  noSecret: "Stores can't be connected on this server just now: its encryption key is not set. Nothing was sent to your store and nothing was saved."
};

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

function checkShopifyToken(input) {
  if (typeof input !== "string") return null;
  var t = input.trim();
  return /^shpat_[A-Za-z0-9]{16,200}$/.test(t) ? t : null;
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

/* The only fields a status answer, a log line or the export ever carries. */
function statusOf(row) {
  return {
    id: row.id,
    platform: row.platform,
    platform_label: PLATFORM_LABEL[row.platform] || row.platform,
    store: row.store_url,
    status: row.status,
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

/* One GET, paced, with backoff on 429 and 5xx, never following a redirect (a
   credential is never sent anywhere but the store it was made for). Resolves
   { data, headers }. A 401 or 403 throws StoreAuthError at once; anything else
   that fails throws StoreRequestError. */
async function request(deps, url, headers) {
  for (var attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    await deps.sleep(attempt === 0 ? REQUEST_GAP_MS : 0);
    var res;
    try {
      res = await deps.fetch(url, { method: "GET", headers: headers, redirect: "manual", signal: deps.timeoutSignal ? deps.timeoutSignal(REQUEST_TIMEOUT_MS) : undefined });
    } catch (err) {
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
    var data;
    try { data = await res.json(); } catch (e) { throw new StoreRequestError("not_json"); }
    return { data: data, headers: res.headers };
  }
  throw new StoreRequestError("unreachable");
}

/* A WooCommerce host must resolve to public addresses only (lib/guardedFetch.js's
   list), so a member cannot point the server at its own network. */
async function assertPublicHost(deps, storeUrl) {
  var host = new URL(storeUrl).hostname;
  var addresses;
  try { addresses = await deps.lookup(host); } catch (e) { throw new StoreRequestError("dns"); }
  if (!addresses || !addresses.length) throw new StoreRequestError("dns");
  for (var i = 0; i < addresses.length; i++) {
    if (deps.isBlockedAddress(addresses[i].address || addresses[i])) throw new StoreRequestError("blocked_address");
  }
}

/* ── Shopify ─────────────────────────────────────────────────────────────── */
function shopifyHeaders(token) {
  return { "X-Shopify-Access-Token": token, "Accept": "application/json" };
}
function shopifyUrl(domain, path) {
  return "https://" + domain + "/admin/api/" + SHOPIFY_API_VERSION + path;
}

/* Shopify's Link header: the next page, only on the same shop. */
function nextLink(linkHeader, domain) {
  if (!linkHeader) return null;
  var parts = String(linkHeader).split(",");
  for (var i = 0; i < parts.length; i++) {
    var m = /<([^>]+)>\s*;\s*rel="?next"?/.exec(parts[i]);
    if (!m) continue;
    try { if (new URL(m[1]).hostname === domain) return m[1]; } catch (e) { return null; }
  }
  return null;
}

/* One read call. { ok: true, scopes } or { ok: false, code, error }. */
async function verifyShopify(deps, domain, token) {
  var got;
  try {
    got = await request(deps, "https://" + domain + "/admin/oauth/access_scopes.json", shopifyHeaders(token));
  } catch (err) {
    if (err instanceof StoreAuthError) return { ok: false, code: "shopify_rejected", error: MESSAGES.shopifyRejected };
    return { ok: false, code: "store_unreachable", error: MESSAGES.unreachable };
  }
  var scopes = ((got.data && got.data.access_scopes) || []).map(function (s) { return String(s && s.handle); });
  if (scopes.some(function (s) { return /^write_/.test(s); })) {
    return { ok: false, code: "write_scope", error: MESSAGES.shopifyWriteScope, scopes: scopes };
  }
  var missing = SHOPIFY_REQUIRED_SCOPES.filter(function (s) { return scopes.indexOf(s) === -1; });
  if (missing.length) return { ok: false, code: "missing_scope", error: MESSAGES.shopifyMissingScope, missing: missing };
  return { ok: true, scopes: scopes };
}

function money(v) {
  if (v === null || v === undefined || v === "") return null;
  var n = Number(v);
  return isFinite(n) ? Math.round(n * 100) / 100 : null;
}

async function fetchShopifyItems(deps, domain, token) {
  var out = { items: [], skipped_untracked: 0 };
  var variants = [];
  var url = shopifyUrl(domain, "/products.json?limit=250&fields=id,title,variants");
  for (var page = 0; url && page < MAX_PAGES; page++) {
    var got = await request(deps, url, shopifyHeaders(token));
    ((got.data && got.data.products) || []).forEach(function (p) {
      (p.variants || []).forEach(function (v) { variants.push({ product: p, variant: v }); });
    });
    url = nextLink(got.headers && got.headers.get ? got.headers.get("link") : null, domain);
  }
  // Costs live on Shopify's inventory items (read_inventory), 100 ids a call.
  var costs = {};
  var ids = variants.map(function (x) { return x.variant.inventory_item_id; }).filter(function (id) { return id != null; });
  for (var i = 0; i < ids.length; i += 100) {
    var chunk = ids.slice(i, i + 100);
    var c = await request(deps, shopifyUrl(domain, "/inventory_items.json?limit=100&ids=" + chunk.join(",")), shopifyHeaders(token));
    ((c.data && c.data.inventory_items) || []).forEach(function (it) { costs[String(it.id)] = money(it.cost); });
  }
  variants.forEach(function (x) {
    var v = x.variant, p = x.product;
    if (v.inventory_management == null || typeof v.inventory_quantity !== "number") { out.skipped_untracked++; return; }
    var name = String(p.title || "Untitled") + (v.title && v.title !== "Default Title" ? " - " + v.title : "");
    out.items.push({
      external_id: "variant:" + v.id,
      name: cut(name, 200),
      sku: v.sku ? cut(String(v.sku).trim(), 100) || null : null,
      unit_price: money(v.price),
      unit_cost: v.inventory_item_id != null && costs[String(v.inventory_item_id)] != null ? costs[String(v.inventory_item_id)] : null,
      quantity_on_hand: Math.trunc(v.inventory_quantity)
    });
  });
  return out;
}

async function fetchShopifyOrders(deps, domain, token, sinceIso) {
  var out = [];
  var url = shopifyUrl(domain, "/orders.json?status=any&limit=250&created_at_min=" + encodeURIComponent(sinceIso) +
    "&fields=id,created_at,total_price,currency,line_items");
  for (var page = 0; url && page < MAX_PAGES; page++) {
    var got = await request(deps, url, shopifyHeaders(token));
    ((got.data && got.data.orders) || []).forEach(function (o) { out.push(summaryOf("shopify", o)); });
    url = nextLink(got.headers && got.headers.get ? got.headers.get("link") : null, domain);
  }
  return out;
}

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
   which store, until when, signed so nobody else can make one. */
function makeWooState(userId, storeUrl, nowMs, secret) {
  var body = Buffer.from(JSON.stringify({ u: userId, s: storeUrl, e: nowMs + STATE_TTL_MS })).toString("base64url");
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
  return { userId: s.u, storeUrl: s.s };
}

/* WooCommerce's own authorization page, asking for Read access only. */
function wooAuthorizeUrl(storeUrl, state, callbackUrl, returnUrl) {
  return storeUrl + "/wc-auth/v1/authorize?app_name=" + encodeURIComponent("BizForce AI") +
    "&scope=read&user_id=" + encodeURIComponent(state) +
    "&return_url=" + encodeURIComponent(returnUrl) + "&callback_url=" + encodeURIComponent(callbackUrl);
}

/* The callback's key: { ok: true, creds } or { ok: false, code, error }. */
function checkWooKey(body) {
  var b = body || {};
  if (b.key_permissions !== "read") return { ok: false, code: "not_read_only", error: MESSAGES.wooNotReadOnly };
  var key = typeof b.consumer_key === "string" ? b.consumer_key.trim() : "";
  var secret = typeof b.consumer_secret === "string" ? b.consumer_secret.trim() : "";
  if (!/^ck_[A-Za-z0-9]{20,100}$/.test(key) || !/^cs_[A-Za-z0-9]{20,100}$/.test(secret)) {
    return { ok: false, code: "key_format", error: MESSAGES.wooRejected };
  }
  return { ok: true, creds: { consumer_key: key, consumer_secret: secret } };
}

/* One read call with the key. { ok: true } or { ok: false, code, error }. */
async function verifyWoo(deps, storeUrl, creds) {
  try {
    await assertPublicHost(deps, storeUrl);
    await request(deps, wooUrl(storeUrl, "/products?per_page=1&_fields=id"), wooHeaders(creds));
    return { ok: true };
  } catch (err) {
    if (err instanceof StoreAuthError) return { ok: false, code: "woo_rejected", error: MESSAGES.wooRejected };
    return { ok: false, code: "store_unreachable", error: MESSAGES.unreachable };
  }
}

async function wooPages(deps, storeUrl, creds, path, each) {
  for (var page = 1; page <= MAX_PAGES; page++) {
    var got = await request(deps, wooUrl(storeUrl, path + (path.indexOf("?") === -1 ? "?" : "&") + "per_page=100&page=" + page), wooHeaders(creds));
    var rows = Array.isArray(got.data) ? got.data : [];
    rows.forEach(each);
    var total = Number(got.headers && got.headers.get ? got.headers.get("x-wp-totalpages") : NaN);
    if (rows.length < 100 || (isFinite(total) && page >= total)) break;
  }
}

function wooItem(externalId, name, row) {
  return {
    external_id: externalId,
    name: cut(name, 200),
    sku: row.sku ? cut(String(row.sku).trim(), 100) || null : null,
    unit_price: money(row.price),
    unit_cost: null,
    quantity_on_hand: Math.trunc(row.stock_quantity)
  };
}

async function fetchWooItems(deps, storeUrl, creds) {
  await assertPublicHost(deps, storeUrl);
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
      out.items.push(wooItem("variation:" + v.id, (parent.name || "Untitled") + (label ? " - " + label : ""), v));
    });
  }
  return out;
}

async function fetchWooOrders(deps, storeUrl, creds, sinceIso) {
  await assertPublicHost(deps, storeUrl);
  var out = [];
  await wooPages(deps, storeUrl, creds, "/orders?after=" + encodeURIComponent(sinceIso) + "&_fields=id,date_created_gmt,total,currency,line_items", function (o) {
    out.push(summaryOf("woocommerce", o));
  });
  return out;
}

/* ── the order summary: a whitelist, never a copy ───────────────────────── */
// The only keys a stored order summary has. Nothing about the customer.
var SUMMARY_KEYS = ["external_id", "ordered_at", "total", "currency", "line_items"];
function summaryOf(platform, o) {
  var when = platform === "shopify" ? o.created_at : (o.date_created_gmt ? String(o.date_created_gmt).replace(/Z?$/, "Z") : null);
  var currency = typeof o.currency === "string" && /^[A-Za-z]{3}$/.test(o.currency) ? o.currency.toUpperCase() : null;
  return {
    external_id: cut(String(o.id), 100),
    ordered_at: when,
    total: money(platform === "shopify" ? o.total_price : o.total),
    currency: currency,
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
  var creds;
  try { creds = openCredentials(conn, deps.decrypt); } catch (e) {
    await markNeedsReconnect(supabase, conn, "credentials_unreadable", stamp);
    return { ok: false, code: "credentials_unreadable", needs_reconnect: true };
  }
  try {
    var fetched, orders;
    if (conn.platform === "shopify") {
      fetched = await fetchShopifyItems(deps, conn.store_url, creds.access_token);
      orders = await fetchShopifyOrders(deps, conn.store_url, creds.access_token, since);
    } else {
      fetched = await fetchWooItems(deps, conn.store_url, creds);
      orders = await fetchWooOrders(deps, conn.store_url, creds, since);
    }
    creds = null;
    var items = await applyItems(supabase, conn, fetched.items, stamp);
    var orderCount = await applyOrders(supabase, conn, orders, stamp);
    var done = await supabase.from("member_store_connections")
      .update({ last_sync_at: stamp, last_error_code: null, last_error_at: null, updated_at: stamp }).eq("id", conn.id);
    if (done.error) throw done.error;
    return { ok: true, items_written: items.written, skipped_sku_manual: items.skipped_sku_manual, skipped_sku_conflict: items.skipped_sku_conflict,
      skipped_untracked: fetched.skipped_untracked, orders: orderCount, synced_at: stamp };
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
    return { ok: false, code: code };
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
  var conn = await supabase.from("member_store_connections").delete().eq("user_id", userId).eq("id", connectionId).select("id");
  if (conn.error) throw conn.error;
  return { items: ids.length, removed: (conn.data || []).length > 0 };
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
    .select("id, user_id, platform, store_url, status, credentials_ciphertext, credentials_iv, credentials_auth_tag, created_at")
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
  SHOPIFY_REQUIRED_SCOPES: SHOPIFY_REQUIRED_SCOPES,
  ORDER_WINDOW_DAYS: ORDER_WINDOW_DAYS,
  MAX_ATTEMPTS: MAX_ATTEMPTS,
  SUMMARY_KEYS: SUMMARY_KEYS,
  MESSAGES: MESSAGES,
  storeSyncEnabled: storeSyncEnabled,
  normalizeShopifyDomain: normalizeShopifyDomain,
  normalizeWooUrl: normalizeWooUrl,
  checkShopifyToken: checkShopifyToken,
  sealCredentials: sealCredentials,
  openCredentials: openCredentials,
  statusOf: statusOf,
  request: request,
  verifyShopify: verifyShopify,
  verifyWoo: verifyWoo,
  checkWooKey: checkWooKey,
  makeWooState: makeWooState,
  readWooState: readWooState,
  wooAuthorizeUrl: wooAuthorizeUrl,
  summaryOf: summaryOf,
  syncConnection: syncConnection,
  markNeedsReconnect: markNeedsReconnect,
  deleteConnectionData: deleteConnectionData,
  claimStoreSyncDay: claimStoreSyncDay,
  runStoreSyncPass: runStoreSyncPass,
  storeSyncTick: storeSyncTick,
  StoreAuthError: StoreAuthError,
  StoreRequestError: StoreRequestError
};
