"use strict";

/* ══════════════════════════════════════════════════════════════════════════
   SHOPIFY'S GRAPHQL ADMIN API, for a connected shop (migration 176).

   EVERY REQUEST is ONE deps.jsonRequest call (lib/guardedFetch.js
   guardedJsonRequest: https on 443 only, every address checked, no redirect
   followed, a size and a time limit), a POST of { query, variables } to
   https://<shop>/admin/api/2026-07/graphql.json with X-Shopify-Access-Token.
   There is no other transport.

   READS AND WRITES ARE KEPT APART.
     - readQuery sends a "query" document and nothing else (it refuses any
       other). Every reader here goes through it: the sync's variants and
       orders, the shop's currency and locations, and the live reads before
       and after a change. A read is paced, waits out a 429, a 5xx or a
       THROTTLED answer and tries again (MAX_ATTEMPTS), and is never retried
       on a 401 or 403, except that read() may refresh the token ONCE and ask
       once more when the token it used was not refreshed in this session.
     - The word "mutation" appears only in writePrice and writeStock, the two
       functions lib/storeWrite.js calls after the member approved a change.
       Each sends its document ONCE (sendOnce), never retried, whatever
       happens after it was sent (scripts/checkShopifyConnect.js holds both
       rules).

   TOKENS (expiring offline tokens). accessToken uses the stored access token
   while it is more than REFRESH_MARGIN_MS from its stored expiry; otherwise
   it refreshes: Shopify answers a new access token AND a new refresh token,
   and both are sealed and saved in ONE update, a compare-and-set on
   token_version (the update lands only where id, platform and the version
   read all still match). The loser of a race writes nothing, reads the row
   again and uses the winner's token. One refresh per connection runs at a
   time in this process (refreshesInFlight); that is only an optimisation.
   A refresh Shopify refuses, or a refresh token past refresh_expires_at, is a
   StoreAuthError, which every caller turns into needs_reconnect.

   Nothing here logs, and no token, code or answer body is ever put into an
   error, a result or a log line.
   ══════════════════════════════════════════════════════════════════════════ */

var SS = require("./storeSync");
var SA = require("./shopifyAuth");

var API_VERSION = SS.SHOPIFY_API_VERSION;
var PAGE_SIZE = 50;
/* Orders carry their line items, and Shopify caps one query's cost at 1000
   points, so an order page is smaller: 20 orders of at most 40 line items. */
var ORDER_PAGE_SIZE = 20;
var ORDER_LINE_ITEMS = 40;
var PAGE_CAPS = { variants: 200, orders: 200 };
var LOCATIONS_MAX = 50;
var MAX_ATTEMPTS = 4;
var RETRY_CAP_MS = 30000;
var REQUEST_GAP_MS = 500;
var REQUEST_TIMEOUT_MS = 20000;
var REQUEST_MAX_BODY_BYTES = 8 * 1024 * 1024;
var WRITE_TIMEOUT_MS = 20000;
var WRITE_MAX_BYTES = 1024 * 1024;
var EXPOSED_HEADERS = ["retry-after"];
var RETRYABLE = [429, 500, 502, 503, 504];
var GUARD_RETRIED = ["network", "timeout"];
var GUARD_CODES = { blocked: "blocked_address", invalid_url: "invalid_url", redirected: "redirected", too_large: "too_large",
  unaccepted_type: "not_json", not_json: "not_json", dns: "dns", challenge: "not_json" };
// Refusals by the guarded fetcher before a byte is sent: nothing reached the store.
var NOT_SENT = ["blocked", "invalid_url", "dns", "guard_refused"];
var CONNECTION_COLUMNS = "id, user_id, platform, store_url, status, permission, credentials_ciphertext, credentials_iv, credentials_auth_tag, " +
  "access_ciphertext, access_iv, access_auth_tag, access_expires_at, refresh_expires_at, token_version, granted_scopes, location_id, location_name, currency, created_at";

var refreshesInFlight = new Map();

function graphqlUrl(shop) {
  return "https://" + shop + "/admin/api/" + API_VERSION + "/graphql.json";
}
function headersFor(token) {
  return { "X-Shopify-Access-Token": token, "Accept": "application/json" };
}

/* "gid://shopify/ProductVariant/123" -> "123" for that type, else null. */
function numericId(gid, type) {
  var m = new RegExp("^gid://shopify/" + type + "/([0-9]{1,30})$").exec(String(gid == null ? "" : gid));
  return m ? m[1] : null;
}
function gidOf(type, id) {
  return /^[0-9]{1,30}$/.test(String(id == null ? "" : id)) ? "gid://shopify/" + type + "/" + id : null;
}

function money(v) {
  if (v === null || v === undefined || v === "") return null;
  var n = Number(v);
  return isFinite(n) ? Math.round(n * 100) / 100 : null;
}
function cut(value, n) {
  var s = String(value == null ? "" : value);
  return s.length > n ? s.slice(0, n) : s;
}
function currencyOf(v) {
  return typeof v === "string" && /^[A-Z]{3}$/.test(v) ? v : null;
}

function throttled(json) {
  return !!(json && Array.isArray(json.errors) && json.errors.some(function (e) { return e && e.extensions && e.extensions.code === "THROTTLED"; }));
}

/* ── the one read ──────────────────────────────────────────────────────── */
/* A query document, paced, with backoff on 429, 5xx and THROTTLED. Resolves
   the answer's data. A 401 or 403 throws StoreAuthError at once; anything else
   that fails throws StoreRequestError. */
async function readQuery(deps, shop, token, doc, variables) {
  if (typeof doc !== "string" || !/^query\b/.test(doc)) throw new SS.StoreRequestError("not_a_query");
  for (var attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    await deps.sleep(attempt === 0 ? REQUEST_GAP_MS : 0);
    var answer;
    try {
      answer = await deps.jsonRequest(graphqlUrl(shop), { method: "POST", headers: headersFor(token), body: { query: doc, variables: variables || {} },
        exposeHeaders: EXPOSED_HEADERS, maxBytes: REQUEST_MAX_BODY_BYTES, timeoutMs: REQUEST_TIMEOUT_MS });
    } catch (err) {
      var guard = err && err.guardedFetch === true ? String(err.code) : null;
      if (guard === null || GUARD_RETRIED.indexOf(guard) === -1) {
        throw new SS.StoreRequestError(guard === null ? "guard_refused" : GUARD_CODES[guard] || "unreachable");
      }
      if (attempt + 1 < MAX_ATTEMPTS) { await deps.sleep(Math.pow(2, attempt) * 1000); continue; }
      throw new SS.StoreRequestError("unreachable");
    }
    var status = answer && answer.status;
    if (RETRYABLE.indexOf(status) !== -1) {
      if (attempt + 1 < MAX_ATTEMPTS) {
        var after = Number(answer.headers && answer.headers["retry-after"]);
        await deps.sleep(Math.min(isFinite(after) && after >= 0 ? after * 1000 : Math.pow(2, attempt) * 1000, RETRY_CAP_MS));
        continue;
      }
      throw new SS.StoreRequestError(status === 429 ? "rate_limited" : "http_" + status);
    }
    if (status === 401 || status === 403) throw new SS.StoreAuthError("http_" + status);
    if (typeof status !== "number" || status < 200 || status >= 300) throw new SS.StoreRequestError("http_" + status);
    var json = answer.json;
    if (json === null || json === undefined || typeof json !== "object") throw new SS.StoreRequestError("not_json");
    if (throttled(json)) {
      if (attempt + 1 < MAX_ATTEMPTS) { await deps.sleep(Math.min(Math.pow(2, attempt + 1) * 1000, RETRY_CAP_MS)); continue; }
      throw new SS.StoreRequestError("rate_limited");
    }
    if (Array.isArray(json.errors) && json.errors.length) throw new SS.StoreRequestError("graphql_error");
    if (!json.data || typeof json.data !== "object") throw new SS.StoreRequestError("not_json");
    return json.data;
  }
  throw new SS.StoreRequestError("unreachable");
}

/* ── the access token ──────────────────────────────────────────────────── */
/* A session holds the connection row as it is now (a refresh replaces it). */
function session(conn) {
  return { row: conn, refreshed: false };
}

function sealedAccess(deps, row) {
  try {
    var t = deps.decrypt({ ciphertext: row.access_ciphertext, iv: row.access_iv, authTag: row.access_auth_tag });
    if (typeof t !== "string" || !t) throw new Error("empty");
    return t;
  } catch (err) {
    throw new SS.StoreAuthError("credentials_unreadable");
  }
}

function configFor(deps) {
  return typeof deps.shopifyConfig === "function" ? deps.shopifyConfig() : SA.configured(deps.env);
}

async function rereadRow(deps, row) {
  var again = await deps.supabase.from("member_store_connections").select(CONNECTION_COLUMNS).eq("id", row.id).eq("platform", "shopify").maybeSingle();
  if (again.error || !again.data) throw new SS.StoreRequestError("refresh_lost");
  return again.data;
}

async function refreshRow(deps, row) {
  var nowMs = deps.now();
  if (row.refresh_expires_at && !(Date.parse(row.refresh_expires_at) > nowMs)) throw new SS.StoreAuthError("refresh_expired");
  var config = configFor(deps);
  if (!config) throw new SS.StoreRequestError("not_configured");
  var refreshToken;
  try {
    refreshToken = SS.openCredentials(row, deps.decrypt).refresh_token;
  } catch (err) {
    throw new SS.StoreAuthError("credentials_unreadable");
  }
  if (typeof refreshToken !== "string" || !refreshToken) throw new SS.StoreAuthError("credentials_unreadable");
  var version = Number.isInteger(row.token_version) ? row.token_version : 0;
  var grant;
  try {
    grant = await SA.refreshTokens(config, row.store_url, refreshToken, deps.jsonRequest);
  } catch (err) {
    if (err && err.kind === "rejected") {
      /* Another process may have spent this refresh token first: its pair is
         then the stored one, with a higher token_version. Use it if so. */
      var now = await rereadRow(deps, row);
      if (Number(now.token_version) !== version && Date.parse(now.access_expires_at) > deps.now()) {
        return { token: sealedAccess(deps, now), row: now };
      }
      throw new SS.StoreAuthError("refresh_refused");
    }
    throw new SS.StoreRequestError("token_refresh");
  } finally {
    refreshToken = null;
  }
  var sealedRefresh = SS.sealCredentials({ refresh_token: grant.refreshToken }, deps.encrypt);
  var sealedAccessToken = deps.encrypt(grant.accessToken);
  var expiries = SA.expiriesFor(grant, deps.now());
  // The new access token and the new refresh token, together, in ONE update.
  var update = {
    credentials_ciphertext: sealedRefresh.credentials_ciphertext, credentials_iv: sealedRefresh.credentials_iv, credentials_auth_tag: sealedRefresh.credentials_auth_tag,
    access_ciphertext: sealedAccessToken.ciphertext, access_iv: sealedAccessToken.iv, access_auth_tag: sealedAccessToken.authTag,
    access_expires_at: expiries.access_expires_at, refresh_expires_at: expiries.refresh_expires_at,
    token_version: version + 1, updated_at: new Date(deps.now()).toISOString()
  };
  var swapped = await deps.supabase.from("member_store_connections").update(update)
    .eq("id", row.id).eq("platform", "shopify").eq("token_version", version).select("id");
  if (swapped.error) throw new SS.StoreRequestError("refresh_save_failed");
  if ((swapped.data || []).length === 1) {
    return { token: grant.accessToken, row: Object.assign({}, row, update) };
  }
  // Lost the race: nothing more is written. The winner's token is the one to use.
  grant = null;
  var current = await rereadRow(deps, row);
  return { token: sealedAccess(deps, current), row: current };
}

/* The access token to use now. force refreshes whatever the stored expiry says. */
async function accessToken(deps, s, force) {
  var row = s.row;
  var expires = Date.parse(row.access_expires_at);
  if (!force && isFinite(expires) && expires - deps.now() > SA.REFRESH_MARGIN_MS) return sealedAccess(deps, row);
  var key = row.id;
  var running = refreshesInFlight.get(key);
  var started = running || refreshRow(deps, row);
  if (!running) refreshesInFlight.set(key, started);
  try {
    var got = await started;
    s.row = got.row;
    s.refreshed = true;
    return got.token;
  } finally {
    if (refreshesInFlight.get(key) === started) refreshesInFlight.delete(key);
  }
}

/* One read for a session: a refused token that was not refreshed in this
   session is refreshed ONCE and the read asked ONCE more. Reads only: nothing
   was applied by a refused read. */
async function read(deps, s, doc, variables) {
  var token = await accessToken(deps, s, false);
  try {
    return await readQuery(deps, s.row.store_url, token, doc, variables);
  } catch (err) {
    if (!(err instanceof SS.StoreAuthError) || s.refreshed) throw err;
    token = await accessToken(deps, s, true);
    return await readQuery(deps, s.row.store_url, token, doc, variables);
  }
}

/* ── the readers ───────────────────────────────────────────────────────── */
var SHOP_QUERY = "query ShopInfo { shop { currencyCode } locations(first: " + LOCATIONS_MAX + ") { nodes { id name isActive } } }";
var VARIANT_FIELDS = "id sku title price compareAtPrice inventoryQuantity product { id title }";
var VARIANTS_QUERY = "query Variants($cursor: String) { productVariants(first: " + PAGE_SIZE + ", after: $cursor) { pageInfo { hasNextPage endCursor } " +
  "nodes { " + VARIANT_FIELDS + " inventoryItem { id tracked unitCost { amount } } } } }";
var VARIANTS_AT_QUERY = "query VariantsAt($cursor: String, $location: ID!) { productVariants(first: " + PAGE_SIZE + ", after: $cursor) { pageInfo { hasNextPage endCursor } " +
  "nodes { " + VARIANT_FIELDS + " inventoryItem { id tracked unitCost { amount } inventoryLevel(locationId: $location) { quantities(names: [\"available\"]) { name quantity } } } } } }";
var ORDERS_QUERY = "query Orders($cursor: String, $search: String) { orders(first: " + ORDER_PAGE_SIZE + ", after: $cursor, query: $search, sortKey: CREATED_AT) { " +
  "pageInfo { hasNextPage endCursor } nodes { id createdAt totalPriceSet { shopMoney { amount currencyCode } } lineItems(first: " + ORDER_LINE_ITEMS + ") { nodes { sku quantity } } } } }";
var LIVE_VARIANT_QUERY = "query LiveVariant($id: ID!) { productVariant(id: $id) { id price compareAtPrice product { id } inventoryItem { id tracked } } }";
var LIVE_LEVEL_QUERY = "query LiveLevel($item: ID!, $location: ID!) { inventoryItem(id: $item) { id tracked inventoryLevel(locationId: $location) { " +
  "quantities(names: [\"available\"]) { name quantity } } } }";

function activeLocations(data) {
  var nodes = (data && data.locations && Array.isArray(data.locations.nodes)) ? data.locations.nodes : [];
  return nodes.filter(function (l) { return l && l.isActive !== false && numericId(l.id, "Location") !== null; })
    .map(function (l) { return { id: String(l.id), name: cut(l.name || "Location", 200) }; });
}

/* The shop's currency and its active locations: { currency, locations }. */
async function shopInfo(deps, s) {
  var data = await read(deps, s, SHOP_QUERY, {});
  return { currency: currencyOf(data.shop && data.shop.currencyCode), locations: activeLocations(data) };
}

function availableOf(level) {
  var q = level && Array.isArray(level.quantities) ? level.quantities : [];
  for (var i = 0; i < q.length; i++) {
    if (q[i] && q[i].name === "available" && typeof q[i].quantity === "number" && Number.isInteger(q[i].quantity)) return q[i].quantity;
  }
  return null;
}

/* Every tracked variant, as inventory rows. quantity_on_hand is the chosen
   location's "available" when the connection has one, else the total across
   locations. */
async function fetchItems(deps, s) {
  var out = { items: [], skipped_untracked: 0, skipped_not_at_location: 0 };
  var location = s.row.location_id || null;
  var cursor = null;
  for (var page = 0; page < PAGE_CAPS.variants; page++) {
    var data = await read(deps, s, location ? VARIANTS_AT_QUERY : VARIANTS_QUERY, location ? { cursor: cursor, location: location } : { cursor: cursor });
    var conn = data.productVariants || {};
    (conn.nodes || []).forEach(function (v) {
      var variantId = numericId(v && v.id, "ProductVariant");
      var productId = numericId(v && v.product && v.product.id, "Product");
      var item = v && v.inventoryItem;
      var itemId = numericId(item && item.id, "InventoryItem");
      if (!variantId || !productId || !item || item.tracked !== true || !itemId) { out.skipped_untracked++; return; }
      var qty;
      if (location) {
        qty = availableOf(item.inventoryLevel);
        if (qty === null) { out.skipped_not_at_location++; return; }
      } else {
        if (typeof v.inventoryQuantity !== "number" || !Number.isInteger(v.inventoryQuantity)) { out.skipped_untracked++; return; }
        qty = v.inventoryQuantity;
      }
      var title = v.product.title || "Untitled";
      out.items.push({
        external_id: "variant:" + variantId,
        external_parent_id: productId,
        external_inventory_item_id: itemId,
        name: cut(String(title) + (v.title && v.title !== "Default Title" ? " - " + v.title : ""), 200),
        sku: v.sku ? cut(String(v.sku).trim(), 100) || null : null,
        unit_price: money(v.price),
        unit_cost: item.unitCost && item.unitCost.amount != null ? money(item.unitCost.amount) : null,
        quantity_on_hand: qty
      });
    });
    var info = conn.pageInfo || {};
    if (info.hasNextPage !== true || typeof info.endCursor !== "string" || !info.endCursor) break;
    cursor = info.endCursor;
  }
  return out;
}

/* Order summaries since sinceIso, through lib/storeSync.js's summaryOf
   whitelist: nothing about the customer is asked for or kept. */
async function fetchOrders(deps, s, sinceIso) {
  var out = [];
  var cursor = null;
  var search = "created_at:>='" + sinceIso + "'";
  for (var page = 0; page < PAGE_CAPS.orders; page++) {
    var data = await read(deps, s, ORDERS_QUERY, { cursor: cursor, search: search });
    var conn = data.orders || {};
    (conn.nodes || []).forEach(function (o) {
      var shopMoney = o && o.totalPriceSet && o.totalPriceSet.shopMoney ? o.totalPriceSet.shopMoney : {};
      out.push(SS.summaryOf("shopify", {
        id: numericId(o && o.id, "Order") || "",
        created_at: o && o.createdAt,
        total_price: shopMoney.amount,
        currency: shopMoney.currencyCode,
        line_items: (o && o.lineItems && Array.isArray(o.lineItems.nodes) ? o.lineItems.nodes : []).map(function (li) { return { sku: li && li.sku, quantity: li && li.quantity }; })
      }));
    });
    var info = conn.pageInfo || {};
    if (info.hasNextPage !== true || typeof info.endCursor !== "string" || !info.endCursor) break;
    cursor = info.endCursor;
  }
  return out;
}

/* The shop's active locations, live: [{ id, name }]. */
async function listLocations(deps, s) {
  return (await shopInfo(deps, s)).locations;
}

/* One variant, live: { price: "19.99" | null, compare_at: "30.00" | null, product_id, tracked } or null. */
async function liveVariant(deps, s, variantGid) {
  var data = await read(deps, s, LIVE_VARIANT_QUERY, { id: variantGid });
  var v = data.productVariant;
  if (!v || String(v.id) !== variantGid) return null;
  var p = money(v.price), c = money(v.compareAtPrice);
  return {
    price: p === null ? null : p.toFixed(2),
    compare_at: c === null || c <= 0 ? null : c.toFixed(2),
    product_id: v.product ? String(v.product.id) : null,
    tracked: !!(v.inventoryItem && v.inventoryItem.tracked === true)
  };
}

/* One inventory item's "available" at one location, live: { tracked, available } or null. */
async function liveAvailable(deps, s, itemGid, locationGid) {
  var data = await read(deps, s, LIVE_LEVEL_QUERY, { item: itemGid, location: locationGid });
  var it = data.inventoryItem;
  if (!it || String(it.id) !== itemGid) return null;
  return { tracked: it.tracked === true, available: availableOf(it.inventoryLevel) };
}

/* ── the two writes ────────────────────────────────────────────────────── */
/* ONE request, no loop, for writePrice and writeStock only. Resolves
   { ok: true, data } or { ok: false, code, sent, auth? }:
     not_sent     the guarded fetcher refused before a byte was sent
     auth         401 or 403
     throttled    Shopify answered THROTTLED: it did not run the document
     refused      a 4xx, a GraphQL error, or userErrors: nothing was changed
     changed      a userError on the compare field: the store changed first
     unconfirmed  anything after sending that does not show the outcome */
async function sendOnce(deps, shop, token, doc, variables, field) {
  var answer;
  try {
    answer = await deps.jsonRequest(graphqlUrl(shop), { method: "POST", headers: headersFor(token), body: { query: doc, variables: variables },
      exposeHeaders: EXPOSED_HEADERS, maxBytes: WRITE_MAX_BYTES, timeoutMs: WRITE_TIMEOUT_MS });
  } catch (err) {
    var code = err && err.guardedFetch === true ? String(err.code) : "guard_refused";
    if (NOT_SENT.indexOf(code) !== -1) return { ok: false, code: "not_sent", sent: false };
    return { ok: false, code: "unconfirmed", sent: true };
  }
  var status = answer && answer.status;
  if (status === 401 || status === 403) return { ok: false, code: "auth", sent: true, auth: true, status: status };
  if (typeof status === "number" && status >= 400 && status < 500 && status !== 408 && status !== 429) return { ok: false, code: "refused", sent: true };
  if (typeof status !== "number" || status < 200 || status >= 300) return { ok: false, code: "unconfirmed", sent: true };
  var json = answer.json;
  if (!json || typeof json !== "object") return { ok: false, code: "unconfirmed", sent: true };
  if (throttled(json)) return { ok: false, code: "throttled", sent: true };
  if (Array.isArray(json.errors) && json.errors.length) return { ok: false, code: "refused", sent: true };
  var payload = json.data && json.data[field];
  if (!payload || typeof payload !== "object") return { ok: false, code: "unconfirmed", sent: true };
  var errs = Array.isArray(payload.userErrors) ? payload.userErrors : [];
  if (errs.length) {
    var stale = errs.some(function (e) {
      var path = Array.isArray(e && e.field) ? e.field.join(".") : String((e && e.field) || "");
      return /changeFromQuantity|compareQuantity/.test(path) || /STALE|COMPARE|CHANGE_FROM/.test(String((e && e.code) || ""));
    });
    return { ok: false, code: stale ? "changed" : "refused", sent: true };
  }
  return { ok: true, data: payload };
}

/* The variant's price, and nothing else (never compareAtPrice). */
async function writePrice(deps, s, productGid, variantGid, price) {
  var token = await accessToken(deps, s, false);
  var doc = "mutation PriceSet($productId: ID!, $variants: [ProductVariantsBulkInput!]!) { productVariantsBulkUpdate(productId: $productId, variants: $variants) { " +
    "productVariants { id price } userErrors { field message } } }";
  return sendOnce(deps, s.row.store_url, token, doc, { productId: productGid, variants: [{ id: variantGid, price: price }] }, "productVariantsBulkUpdate");
}

/* "available" at one location, set from exactly `from` to `to`: Shopify
   refuses it when the live quantity is not `from` (changeFromQuantity), and
   the proposal id is its idempotency key, so a second delivery cannot apply twice. */
async function writeStock(deps, s, itemGid, locationGid, from, to, key) {
  var token = await accessToken(deps, s, false);
  var doc = "mutation StockSet($input: InventorySetQuantitiesInput!, $key: String!) { inventorySetQuantities(input: $input) @idempotent(key: $key) { " +
    "inventoryAdjustmentGroup { id } userErrors { field message code } } }";
  var input = { name: "available", reason: "correction",
    quantities: [{ inventoryItemId: itemGid, locationId: locationGid, quantity: to, changeFromQuantity: from }] };
  return sendOnce(deps, s.row.store_url, token, doc, { input: input, key: String(key) }, "inventorySetQuantities");
}

module.exports = {
  API_VERSION: API_VERSION,
  PAGE_SIZE: PAGE_SIZE,
  ORDER_PAGE_SIZE: ORDER_PAGE_SIZE,
  ORDER_LINE_ITEMS: ORDER_LINE_ITEMS,
  PAGE_CAPS: PAGE_CAPS,
  MAX_ATTEMPTS: MAX_ATTEMPTS,
  REQUEST_TIMEOUT_MS: REQUEST_TIMEOUT_MS,
  REQUEST_MAX_BODY_BYTES: REQUEST_MAX_BODY_BYTES,
  WRITE_TIMEOUT_MS: WRITE_TIMEOUT_MS,
  WRITE_MAX_BYTES: WRITE_MAX_BYTES,
  CONNECTION_COLUMNS: CONNECTION_COLUMNS,
  graphqlUrl: graphqlUrl,
  numericId: numericId,
  gidOf: gidOf,
  session: session,
  accessToken: accessToken,
  readQuery: readQuery,
  read: read,
  shopInfo: shopInfo,
  fetchItems: fetchItems,
  fetchOrders: fetchOrders,
  listLocations: listLocations,
  liveVariant: liveVariant,
  liveAvailable: liveAvailable,
  writePrice: writePrice,
  writeStock: writeStock
};
