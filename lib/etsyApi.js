"use strict";

/* ══════════════════════════════════════════════════════════════════════════
   ETSY OPEN API v3, for a connected Etsy shop (migration 181).

   EVERY REQUEST is ONE deps.jsonRequest call (lib/guardedFetch.js
   guardedJsonRequest: https on 443 only, every address checked, no redirect
   followed, a size and a time limit) to https://openapi.etsy.com/v3/application,
   with x-api-key "<keystring>:<shared secret>" (lib/etsyAuth.js apiKeyHeader)
   and Authorization: Bearer <access token>. There is no other transport.

   READS AND THE WRITE ARE KEPT APART.
     - readGet sends GET and nothing else. Every reader goes through it: the
       member (users/me), the shop, the listings, each listing's inventory,
       the receipts, and the live reads before and after a change. A read is
       paced (lib/storeSync.js REQUEST_GAP_MS), waits out a 429 or a 5xx and
       tries again (MAX_ATTEMPTS), and is never retried on a 401 or 403,
       except that read() may refresh the token ONCE and ask once more when
       the token it used was not refreshed in this session.
     - The word PUT appears only in writeInventory, the one function
       lib/storeWrite.js calls after the member approved a change. It sends
       its body ONCE, never retried, whatever happens after it was sent
       (scripts/checkEtsyConnect.js holds both rules).

   VARIATION IDENTITY. Etsy may give a listing's products and offerings NEW
   ids on every inventory update, so they are never stored. An item is named
   by what stays: "listing:<listing_id>" for a listing without variations,
   or "listing:<listing_id>:<every value_id of the product's property values,
   sorted ascending and joined with '.'>" for a variation (identityOf). A
   write re-reads the inventory and finds the product by that name again.
   An identity longer than 100 characters is skipped, with a log line that
   names only the code.

   THE WRITE (Etsy's PUT /listings/<id>/inventory replaces the WHOLE
   inventory). putBodyFor rebuilds every product exactly as the live read
   gave it (sku, property values, each offering's price, quantity and
   is_enabled, and the three *_on_property arrays), changing only the target
   value(s). When the listing's price (or quantity) does not vary by the
   properties a product has (price_on_property, quantity_on_property), one
   value applies to every product sharing it, and the change is written to all
   of them (targetsFor). confirmMatches then compares a fresh read with the
   read the body was built from: the targets hold the new value, and nothing
   else changed.

   RECEIPTS carry the buyer's name, email and address. receiptSummary takes
   only receipt_id, created_timestamp, grandtotal and each transaction's sku
   and quantity, straight off the answer, before anything else touches it;
   lib/storeSync.js summaryOf then keeps only its whitelist.

   TOKENS. accessToken uses the stored access token while it is more than
   lib/etsyAuth.js REFRESH_MARGIN_MS from its stored expiry; otherwise it
   refreshes: Etsy answers a new access token AND a new refresh token, and
   both are sealed and saved in ONE update, a compare-and-set on
   token_version (the update lands only where id, platform etsy and the
   version read all still match). The loser of a race writes nothing, reads
   the row again and uses the winner's token. One refresh per connection
   runs at a time in this process (refreshesInFlight). A refresh Etsy
   refuses, or a refresh token past refresh_expires_at, is a StoreAuthError,
   which every caller turns into needs_reconnect.

   Nothing here logs a token, a code, a secret or an answer body.
   ══════════════════════════════════════════════════════════════════════════ */

var SS = require("./storeSync");
var EA = require("./etsyAuth");

var API_BASE = "https://openapi.etsy.com/v3/application";
var PAGE_SIZE = 100;
// The most pages read in one sync: 40 pages of 100 listings, 40 of 100 receipts.
var PAGE_CAPS = { listings: 40, receipts: 40 };
var MAX_ATTEMPTS = 4;
// The pause before each read, as lib/storeSync.js's REQUEST_GAP_MS.
var REQUEST_GAP_MS = SS.REQUEST_GAP_MS;
var RETRY_CAP_MS = 30000;
var REQUEST_TIMEOUT_MS = 20000;
var REQUEST_MAX_BODY_BYTES = 8 * 1024 * 1024;
var WRITE_TIMEOUT_MS = 20000;
var WRITE_MAX_BYTES = 1024 * 1024;
var EXPOSED_HEADERS = ["retry-after"];
var RETRYABLE = [429, 500, 502, 503, 504];
var GUARD_RETRIED = ["network", "timeout"];
var GUARD_CODES = { blocked: "blocked_address", invalid_url: "invalid_url", redirected: "redirected", too_large: "too_large",
  unaccepted_type: "not_json", not_json: "not_json", dns: "dns", challenge: "not_json" };
// Refusals by the guarded fetcher before a byte is sent: nothing reached Etsy.
var NOT_SENT = ["blocked", "invalid_url", "dns", "guard_refused"];
// Etsy's largest quantity for one offering.
var QUANTITY_MAX = 999;
var ID_MAX = 100;
var CONNECTION_COLUMNS = "id, user_id, platform, store_url, status, permission, credentials_ciphertext, credentials_iv, credentials_auth_tag, " +
  "access_ciphertext, access_iv, access_auth_tag, access_expires_at, refresh_expires_at, token_version, granted_scopes, location_id, location_name, currency, " +
  "external_account_id, created_at";

var refreshesInFlight = new Map();

function digits(v) {
  var s = v == null ? "" : String(v);
  return /^[0-9]{1,30}$/.test(s) ? s : null;
}
function cut(value, n) {
  var s = String(value == null ? "" : value);
  return s.length > n ? s.slice(0, n) : s;
}
/* An Etsy money object { amount, divisor } as a number with two decimals, or null. */
function moneyOf(m) {
  if (!m || typeof m !== "object") return null;
  var amount = Number(m.amount), divisor = Number(m.divisor);
  if (!isFinite(amount) || !isFinite(divisor) || divisor <= 0 || amount < 0) return null;
  return Math.round(amount / divisor * 100) / 100;
}
function money2(m) {
  var n = moneyOf(m);
  return n === null ? null : n.toFixed(2);
}
function currencyOf(v) {
  return typeof v === "string" && /^[A-Z]{3}$/.test(v) ? v : null;
}

function configFor(deps) {
  return typeof deps.etsyConfig === "function" ? deps.etsyConfig() : EA.configured(deps.env);
}
function headersFor(config, token) {
  return { "x-api-key": EA.apiKeyHeader(config), "Authorization": "Bearer " + token, "Accept": "application/json" };
}

/* ── the one read ──────────────────────────────────────────────────────── */
/* One GET, paced, with backoff on 429 and 5xx. Resolves the answer's JSON.
   A 401 or 403 throws StoreAuthError at once; anything else that fails
   throws StoreRequestError. */
async function readGet(deps, config, token, path) {
  for (var attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    await deps.sleep(attempt === 0 ? REQUEST_GAP_MS : 0);
    var answer;
    try {
      answer = await deps.jsonRequest(API_BASE + path, { method: "GET", headers: headersFor(config, token),
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
    return json;
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

async function rereadRow(deps, row) {
  var again = await deps.supabase.from("member_store_connections").select(CONNECTION_COLUMNS).eq("id", row.id).eq("platform", "etsy").maybeSingle();
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
    grant = await EA.refreshTokens(config, refreshToken, deps.jsonRequest);
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
  var expiries = EA.expiriesFor(grant, deps.now());
  // The new access token and the new refresh token, together, in ONE update.
  var update = {
    credentials_ciphertext: sealedRefresh.credentials_ciphertext, credentials_iv: sealedRefresh.credentials_iv, credentials_auth_tag: sealedRefresh.credentials_auth_tag,
    access_ciphertext: sealedAccessToken.ciphertext, access_iv: sealedAccessToken.iv, access_auth_tag: sealedAccessToken.authTag,
    access_expires_at: expiries.access_expires_at, refresh_expires_at: expiries.refresh_expires_at,
    token_version: version + 1, updated_at: new Date(deps.now()).toISOString()
  };
  var swapped = await deps.supabase.from("member_store_connections").update(update)
    .eq("id", row.id).eq("platform", "etsy").eq("token_version", version).select("id");
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
  if (!force && isFinite(expires) && expires - deps.now() > EA.REFRESH_MARGIN_MS) return sealedAccess(deps, row);
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
   session is refreshed ONCE and the read asked ONCE more. Reads only. */
async function read(deps, s, path) {
  var config = configFor(deps);
  if (!config) throw new SS.StoreRequestError("not_configured");
  var token = await accessToken(deps, s, false);
  try {
    return await readGet(deps, config, token, path);
  } catch (err) {
    if (!(err instanceof SS.StoreAuthError) || s.refreshed) throw err;
    token = await accessToken(deps, s, true);
    return await readGet(deps, config, token, path);
  }
}

/* ── the readers ───────────────────────────────────────────────────────── */
/* The member's own user id and shop id: { user_id, shop_id } (shop_id null when the account has no shop). */
async function me(deps, s) {
  var data = await read(deps, s, "/users/me");
  return { user_id: digits(data.user_id), shop_id: digits(data.shop_id) };
}

/* One shop: { shop_name, currency, url } with url https://www.etsy.com/shop/<ShopName>, or null. */
async function shop(deps, s, shopId) {
  var id = digits(shopId);
  if (!id) throw new SS.StoreRequestError("no_shop");
  var data = await read(deps, s, "/shops/" + id);
  var name = typeof data.shop_name === "string" && /^[A-Za-z0-9]{1,60}$/.test(data.shop_name) ? data.shop_name : null;
  if (!name || digits(data.shop_id) !== id) return null;
  return { shop_name: name, currency: currencyOf(data.currency_code), url: "https://www.etsy.com/shop/" + name };
}

/* The connected shop's currency (what lib/storeSync.js stores on the connection). */
async function shopInfo(deps, s) {
  var info = await shop(deps, s, s.row.external_account_id);
  return { currency: info ? info.currency : null, shop_name: info ? info.shop_name : null };
}

/* Every value_id of a product's property values, sorted ascending, or null
   when one is not a whole number. */
function valueIdsOf(product) {
  var ids = [];
  var bad = false;
  (product && Array.isArray(product.property_values) ? product.property_values : []).forEach(function (pv) {
    (pv && Array.isArray(pv.value_ids) ? pv.value_ids : []).forEach(function (v) {
      var d = digits(v);
      if (d === null) bad = true; else ids.push(d);
    });
  });
  if (bad) return null;
  return ids.sort(function (a, b) { return Number(a) - Number(b) || (a < b ? -1 : a > b ? 1 : 0); });
}

/* "listing:<listing_id>" or "listing:<listing_id>:<value_ids sorted, joined with '.'>", or null. */
function identityOf(listingId, product) {
  var id = digits(listingId);
  var ids = valueIdsOf(product);
  if (!id || ids === null) return null;
  return ids.length ? "listing:" + id + ":" + ids.join(".") : "listing:" + id;
}

/* A product's property values ordered by property id, so a name or a
   comparison does not depend on the order Etsy lists them in. */
function byPropertyId(list) {
  return (Array.isArray(list) ? list : []).filter(function (pv) { return pv; }).slice().sort(function (a, b) {
    return Number(a.property_id) - Number(b.property_id);
  });
}
function valuesText(product) {
  var parts = [];
  byPropertyId(product && product.property_values).forEach(function (pv) {
    (pv && Array.isArray(pv.values) ? pv.values : []).forEach(function (v) { if (typeof v === "string" && v) parts.push(v); });
  });
  return parts.join(" / ");
}

/* The items of one listing's inventory: { items, skipped_untracked, skipped_disabled, skipped_id_too_long }. */
function itemsOfInventory(listingId, title, inventory) {
  var out = { items: [], skipped_untracked: 0, skipped_disabled: 0, skipped_id_too_long: 0 };
  var products = inventory && Array.isArray(inventory.products) ? inventory.products : [];
  var seen = {};
  products.forEach(function (p) {
    var identity = identityOf(listingId, p);
    if (identity === null) { out.skipped_untracked++; return; }
    if (identity.length > ID_MAX) {
      out.skipped_id_too_long++;
      console.warn("[StoreSync] an Etsy item was skipped: id_too_long");
      return;
    }
    if (seen[identity]) { out.skipped_untracked++; return; }
    seen[identity] = true;
    var offering = p && Array.isArray(p.offerings) ? p.offerings[0] : null;
    if (!offering) { out.skipped_untracked++; return; }
    if (offering.is_enabled === false) { out.skipped_disabled++; return; }
    if (typeof offering.quantity !== "number" || !Number.isInteger(offering.quantity) || offering.quantity < 0) { out.skipped_untracked++; return; }
    var values = valuesText(p);
    out.items.push({
      external_id: identity,
      external_parent_id: digits(listingId),
      external_inventory_item_id: null,
      name: cut(String(title || "Untitled") + (values ? " - " + values : ""), 200),
      sku: p.sku ? cut(String(p.sku).trim(), 100) || null : null,
      unit_price: moneyOf(offering.price),
      unit_cost: null,
      quantity_on_hand: offering.quantity
    });
  });
  return out;
}

/* Every active listing's products, as inventory rows. */
async function fetchItems(deps, s) {
  var out = { items: [], skipped_untracked: 0, skipped_disabled: 0, skipped_id_too_long: 0 };
  var shopId = digits(s.row.external_account_id);
  if (!shopId) throw new SS.StoreRequestError("no_shop");
  var listings = [];
  for (var page = 0; page < PAGE_CAPS.listings; page++) {
    var data = await read(deps, s, "/shops/" + shopId + "/listings?state=active&limit=" + PAGE_SIZE + "&offset=" + page * PAGE_SIZE);
    var rows = Array.isArray(data.results) ? data.results : [];
    rows.forEach(function (l) {
      var id = digits(l && l.listing_id);
      if (id) listings.push({ id: id, title: l.title });
    });
    if (rows.length < PAGE_SIZE) break;
  }
  for (var i = 0; i < listings.length; i++) {
    var inventory = await read(deps, s, "/listings/" + listings[i].id + "/inventory");
    var got = itemsOfInventory(listings[i].id, listings[i].title, inventory);
    inventory = null;
    got.items.forEach(function (it) { out.items.push(it); });
    out.skipped_untracked += got.skipped_untracked;
    out.skipped_disabled += got.skipped_disabled;
    out.skipped_id_too_long += got.skipped_id_too_long;
  }
  return out;
}

/* A receipt reduced to what a summary may hold, straight off Etsy's answer:
   the receipt's number, when it was made, its grand total and currency, and
   each transaction's sku and quantity. The buyer's name, email and address
   are never read. */
function receiptSummary(r) {
  var gt = r && r.grandtotal;
  var created = r && typeof r.created_timestamp === "number" && isFinite(r.created_timestamp) ? new Date(r.created_timestamp * 1000).toISOString() : null;
  var tx = r && Array.isArray(r.transactions) ? r.transactions : [];
  return {
    id: digits(r && r.receipt_id) || "",
    created_at: created,
    total: moneyOf(gt),
    currency: gt && typeof gt.currency_code === "string" ? gt.currency_code : null,
    line_items: tx.map(function (t) { return { sku: t && t.sku ? t.sku : null, quantity: t && t.quantity }; })
  };
}

/* Receipt summaries since sinceIso, through receiptSummary and lib/storeSync.js's summaryOf. */
async function fetchOrders(deps, s, sinceIso) {
  var out = [];
  var shopId = digits(s.row.external_account_id);
  if (!shopId) throw new SS.StoreRequestError("no_shop");
  var minCreated = Math.floor(Date.parse(sinceIso) / 1000);
  for (var page = 0; page < PAGE_CAPS.receipts; page++) {
    var data = await read(deps, s, "/shops/" + shopId + "/receipts?min_created=" + minCreated + "&limit=" + PAGE_SIZE + "&offset=" + page * PAGE_SIZE);
    var rows = Array.isArray(data.results) ? data.results.map(receiptSummary) : [];
    data = null;
    rows.forEach(function (r) { out.push(SS.summaryOf("etsy", r)); });
    if (rows.length < PAGE_SIZE) break;
  }
  return out;
}

/* One listing's inventory, live. */
async function liveInventory(deps, s, listingId) {
  var id = digits(listingId);
  if (!id) throw new SS.StoreRequestError("unaddressable");
  var data = await read(deps, s, "/listings/" + id + "/inventory");
  return { products: Array.isArray(data.products) ? data.products : [],
    price_on_property: Array.isArray(data.price_on_property) ? data.price_on_property : [],
    quantity_on_property: Array.isArray(data.quantity_on_property) ? data.quantity_on_property : [],
    sku_on_property: Array.isArray(data.sku_on_property) ? data.sku_on_property : [] };
}

/* The listing id an identity names, or null. */
function listingOf(identity) {
  var m = /^listing:([0-9]{1,30})(?::[0-9]{1,30}(?:\.[0-9]{1,30})*)?$/.exec(String(identity || ""));
  return m ? m[1] : null;
}

/* The value_ids of a product's property values for the given properties, sorted and joined. */
function groupKey(product, propertyIds) {
  var ids = [];
  (product && Array.isArray(product.property_values) ? product.property_values : []).forEach(function (pv) {
    if (!pv || propertyIds.indexOf(String(pv.property_id)) === -1) return;
    (Array.isArray(pv.value_ids) ? pv.value_ids : []).forEach(function (v) { ids.push(String(v)); });
  });
  return ids.sort(function (a, b) { return Number(a) - Number(b); }).join(".");
}

/* For a change to one field of the product an identity names: the products
   the new value applies to (indexes into inventory.products), and whether
   that is every product of a listing with variations. null when the identity
   names no product in this inventory. */
function targetsFor(inventory, identity, field) {
  var listingId = listingOf(identity);
  var products = inventory && Array.isArray(inventory.products) ? inventory.products : [];
  if (!listingId) return null;
  var at = -1;
  for (var i = 0; i < products.length; i++) {
    if (identityOf(listingId, products[i]) === identity) { if (at !== -1) return null; at = i; }
  }
  if (at === -1) return null;
  var onProperty = (field === "price" ? inventory.price_on_property : inventory.quantity_on_property) || [];
  var propertyIds = onProperty.map(function (p) { return String(p); });
  var key = groupKey(products[at], propertyIds);
  var indexes = [];
  products.forEach(function (p, i) { if (groupKey(p, propertyIds) === key) indexes.push(i); });
  return { index: at, indexes: indexes, every: products.length > 1 && indexes.length === products.length };
}

/* The live values of the product an identity names, in lib/storeWrite.js's
   shape: { ok: true, live, targets } or { ok: false, code }. */
function liveOf(inventory, identity, field) {
  var t = targetsFor(inventory, identity, field);
  if (!t) return { ok: false, code: "wrong_item" };
  var offering = (inventory.products[t.index].offerings || [])[0];
  if (!offering) return { ok: false, code: "wrong_item" };
  var qty = typeof offering.quantity === "number" && Number.isInteger(offering.quantity) ? offering.quantity : null;
  return { ok: true, targets: t, live: { regular_price: money2(offering.price), sale_price: null, compare_at: null, stock_quantity: qty,
    manage_stock: true, enabled: offering.is_enabled !== false } };
}

/* The whole inventory, rebuilt from the live read, with only the target value(s) changed. */
function putBodyFor(inventory, indexes, field, to) {
  return {
    products: inventory.products.map(function (p, i) {
      var target = indexes.indexOf(i) !== -1;
      return {
        sku: typeof p.sku === "string" ? p.sku : "",
        property_values: (Array.isArray(p.property_values) ? p.property_values : []).map(function (pv) {
          return { property_id: pv.property_id, value_ids: pv.value_ids, scale_id: pv.scale_id === undefined ? null : pv.scale_id,
            property_name: pv.property_name, values: pv.values };
        }),
        offerings: (Array.isArray(p.offerings) ? p.offerings : []).map(function (o) {
          return {
            price: target && field === "price" ? Number(to) : moneyOf(o.price),
            quantity: target && field === "stock" ? Number(to) : o.quantity,
            is_enabled: o.is_enabled !== false
          };
        })
      };
    }),
    price_on_property: inventory.price_on_property,
    quantity_on_property: inventory.quantity_on_property,
    sku_on_property: inventory.sku_on_property
  };
}

/* What the confirming read compares, product by product, by identity. */
function shapeOf(listingId, p) {
  return J({
    sku: typeof p.sku === "string" ? p.sku : "",
    // by property id: Etsy may list a product's properties in either order
    values: byPropertyId(p.property_values).map(function (pv) {
      return [String(pv.property_id), pv.property_name || null, (pv.value_ids || []).map(String), pv.values || []];
    }),
    offerings: (Array.isArray(p.offerings) ? p.offerings : []).map(function (o) {
      return [money2(o.price), o.quantity, o.is_enabled !== false];
    })
  });
}
function J(v) { return JSON.stringify(v); }

/* The confirming read: every target holds the new value in the changed field
   and everything else as before; every other product is exactly as before;
   no product came or went. */
function confirmMatches(before, after, listingId, indexes, field, to) {
  var b = before && Array.isArray(before.products) ? before.products : [];
  var a = after && Array.isArray(after.products) ? after.products : [];
  if (a.length !== b.length) return false;
  var byIdentity = {};
  for (var i = 0; i < a.length; i++) {
    var id = identityOf(listingId, a[i]);
    if (id === null || byIdentity[id]) return false;
    byIdentity[id] = a[i];
  }
  var expected = putBodyFor(before, indexes, field, to);
  for (var k = 0; k < b.length; k++) {
    var key = identityOf(listingId, b[k]);
    var now = key === null ? null : byIdentity[key];
    if (!now) return false;
    var want = expected.products[k];
    var wantShape = shapeOf(listingId, { sku: b[k].sku, property_values: b[k].property_values,
      offerings: want.offerings.map(function (o) { return { price: { amount: Math.round(o.price * 100), divisor: 100 }, quantity: o.quantity, is_enabled: o.is_enabled }; }) });
    if (shapeOf(listingId, now) !== wantShape) return false;
  }
  return true;
}

/* ── the one write ─────────────────────────────────────────────────────── */
/* ONE PUT of the whole inventory, no loop. Resolves { ok: true, data } or
   { ok: false, code, sent, auth? }:
     not_sent     the guarded fetcher refused before a byte was sent
     auth         401 or 403
     throttled    429: Etsy did not take it
     refused      another 4xx: nothing was changed
     unconfirmed  anything after sending that does not show the outcome */
async function writeInventory(deps, s, listingId, body) {
  var config = configFor(deps);
  if (!config) return { ok: false, code: "not_sent", sent: false };
  var id = digits(listingId);
  if (!id) return { ok: false, code: "not_sent", sent: false };
  var token = await accessToken(deps, s, false);
  var answer;
  try {
    answer = await deps.jsonRequest(API_BASE + "/listings/" + id + "/inventory", { method: "PUT", headers: headersFor(config, token), body: body,
      exposeHeaders: EXPOSED_HEADERS, maxBytes: WRITE_MAX_BYTES, timeoutMs: WRITE_TIMEOUT_MS });
  } catch (err) {
    var code = err && err.guardedFetch === true ? String(err.code) : "guard_refused";
    if (NOT_SENT.indexOf(code) !== -1) return { ok: false, code: "not_sent", sent: false };
    return { ok: false, code: "unconfirmed", sent: true };
  }
  var status = answer && answer.status;
  if (status === 401 || status === 403) return { ok: false, code: "auth", sent: true, auth: true };
  if (status === 429) return { ok: false, code: "throttled", sent: true };
  if (typeof status === "number" && status >= 400 && status < 500 && status !== 408) return { ok: false, code: "refused", sent: true };
  if (typeof status !== "number" || status < 200 || status >= 300) return { ok: false, code: "unconfirmed", sent: true };
  return { ok: true, data: answer.json };
}

module.exports = {
  API_BASE: API_BASE,
  PAGE_SIZE: PAGE_SIZE,
  PAGE_CAPS: PAGE_CAPS,
  MAX_ATTEMPTS: MAX_ATTEMPTS,
  QUANTITY_MAX: QUANTITY_MAX,
  ID_MAX: ID_MAX,
  REQUEST_TIMEOUT_MS: REQUEST_TIMEOUT_MS,
  REQUEST_MAX_BODY_BYTES: REQUEST_MAX_BODY_BYTES,
  WRITE_TIMEOUT_MS: WRITE_TIMEOUT_MS,
  WRITE_MAX_BYTES: WRITE_MAX_BYTES,
  CONNECTION_COLUMNS: CONNECTION_COLUMNS,
  moneyOf: moneyOf,
  money2: money2,
  session: session,
  accessToken: accessToken,
  readGet: readGet,
  read: read,
  me: me,
  shop: shop,
  shopInfo: shopInfo,
  valueIdsOf: valueIdsOf,
  identityOf: identityOf,
  listingOf: listingOf,
  itemsOfInventory: itemsOfInventory,
  fetchItems: fetchItems,
  receiptSummary: receiptSummary,
  fetchOrders: fetchOrders,
  liveInventory: liveInventory,
  targetsFor: targetsFor,
  liveOf: liveOf,
  putBodyFor: putBodyFor,
  confirmMatches: confirmMatches,
  writeInventory: writeInventory
};
