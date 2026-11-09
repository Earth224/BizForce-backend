"use strict";

/* ══════════════════════════════════════════════════════════════════════════
   AMAZON SELLING PARTNER API, for a connected seller account in ONE
   marketplace (migration 182).

   EVERY REQUEST is ONE deps.jsonRequest call (lib/guardedFetch.js
   guardedJsonRequest: https on 443 only, every address checked, no redirect
   followed, a size and a time limit) to the region's endpoint
   (lib/amazonAuth.js REGION_ENDPOINTS), with x-amz-access-token: <the LWA
   access token>. There is no other transport, and no request signing.

   READS AND THE WRITE ARE KEPT APART.
     - readGet sends GET and nothing else. Every reader goes through it: the
       marketplace participations, the listings search, one listing (the live
       reads before and after a change), the orders and each order's items.
       A read is paced (lib/storeSync.js REQUEST_GAP_MS), waits out a 429 or a
       5xx and tries again (MAX_ATTEMPTS), and is never retried on a 401 or
       403, except that read() may refresh the token ONCE and ask once more
       when the token it used was not refreshed in this session.
     - The word PATCH appears only in patchOnce, which only writeListing
       calls, which only lib/storeWrite.js calls after the member approved a
       change. writeListing sends the patch with mode=VALIDATION_PREVIEW
       first (Amazon checks it and changes nothing); any ERROR issue stops it
       there. Then it sends the patch for real ONCE, never retried, whatever
       happens after it was sent (scripts/checkAmazonConnect.js holds both
       rules).

   IDENTITY. An item is "sku:<marketplaceId>:<seller SKU>" (identityOf). The
   SKU is what the seller set and does not change; it is URL-encoded in every
   path. An identity over 100 characters is skipped, with a log line that
   names only the code. external_parent_id stays NULL.

   PRICE AND STOCK. The price is the B2C offer's in the connected
   marketplace. The stock is the seller-fulfilled quantity, the
   fulfillmentAvailability entry with fulfillmentChannelCode "DEFAULT". An item
   whose only channels are others is fulfilled by Amazon (FBA): its quantity is
   kept for display, and lib/storeWrite.js refuses a stock change for it.

   ORDERS. No Restricted Data Token is ever asked for, so Amazon sends no
   buyer name or address; whatever an order does carry, orderSummary takes
   only AmazonOrderId, PurchaseDate and OrderTotal, and each item's SellerSKU
   and QuantityOrdered, straight off the answer, before anything else touches
   it; lib/storeSync.js summaryOf then keeps only its whitelist. At most
   ORDER_CAP orders a sync; each order's items are read ORDER_ITEMS_GAP_MS
   apart (Amazon's getOrderItems allows about one call every two seconds).

   TOKENS. accessToken uses the stored access token while it is more than
   lib/amazonAuth.js REFRESH_MARGIN_MS from its stored expiry; otherwise it
   refreshes: the new access token (and a new refresh token, when LWA answers
   one) is sealed and saved in ONE update, a compare-and-set on token_version
   (the update lands only where id, platform amazon and the version read all
   still match). The loser of a race writes nothing, reads the row again and
   uses the winner's token. One refresh per connection runs at a time in this
   process (refreshesInFlight). invalid_grant is a StoreAuthError, which every
   caller turns into needs_reconnect.

   Nothing here logs a token, a code, a secret, a buyer field or an answer body.
   ══════════════════════════════════════════════════════════════════════════ */

var SS = require("./storeSync");
var AA = require("./amazonAuth");

var LISTINGS_PATH = "/listings/2021-08-01/items/";
var INCLUDED_DATA = "summaries,attributes,offers,fulfillmentAvailability";
var LISTINGS_PAGE_SIZE = 20;
// The most pages read in one sync: 40 pages of 20 listings, 40 of orders.
var PAGE_CAPS = { listings: 40, orders: 40, orderItems: 5 };
// The most orders a sync reads the items of.
var ORDER_CAP = 100;
var ORDERS_PAGE_SIZE = 100;
// getOrderItems: about one call every two seconds.
var ORDER_ITEMS_GAP_MS = 2000;
var MAX_ATTEMPTS = 4;
var REQUEST_GAP_MS = SS.REQUEST_GAP_MS;
var RETRY_CAP_MS = 30000;
var REQUEST_TIMEOUT_MS = 20000;
var REQUEST_MAX_BODY_BYTES = 8 * 1024 * 1024;
var WRITE_TIMEOUT_MS = 20000;
var WRITE_MAX_BYTES = 1024 * 1024;
// After the patch: one read every CONFIRM_EVERY_MS, at most CONFIRM_READS of them (60 seconds).
var CONFIRM_EVERY_MS = 10000;
var CONFIRM_READS = 6;
var ISSUE_MAX = 300;
var EXPOSED_HEADERS = ["retry-after", "x-amzn-ratelimit-limit", "x-amzn-requestid"];
var RETRYABLE = [429, 500, 502, 503, 504];
var GUARD_RETRIED = ["network", "timeout"];
var GUARD_CODES = { blocked: "blocked_address", invalid_url: "invalid_url", redirected: "redirected", too_large: "too_large",
  unaccepted_type: "not_json", not_json: "not_json", dns: "dns", challenge: "not_json" };
// Refusals by the guarded fetcher before a byte is sent: nothing reached Amazon.
var NOT_SENT = ["blocked", "invalid_url", "dns", "guard_refused"];
var ID_MAX = 100;
var SKU_MAX = 200;
var ORDER_ID_RE = /^[0-9]{3}-[0-9]{7}-[0-9]{7}$/;
var CONNECTION_COLUMNS = "id, user_id, platform, store_url, status, permission, credentials_ciphertext, credentials_iv, credentials_auth_tag, " +
  "access_ciphertext, access_iv, access_auth_tag, access_expires_at, refresh_expires_at, token_version, granted_scopes, location_id, location_name, currency, " +
  "external_account_id, marketplace_id, region, created_at";

var refreshesInFlight = new Map();

function cut(value, n) {
  var s = String(value == null ? "" : value);
  return s.length > n ? s.slice(0, n) : s;
}
/* An amount (a number or a decimal string) as a number with two decimals, or null. */
function moneyOf(v) {
  if (v === null || v === undefined || v === "") return null;
  if (typeof v !== "number" && !(typeof v === "string" && /^[0-9]{1,9}(\.[0-9]{1,6})?$/.test(v.trim()))) return null;
  var n = Number(v);
  if (!isFinite(n) || n < 0) return null;
  return Math.round(n * 100) / 100;
}
function money2(v) {
  var n = moneyOf(v);
  return n === null ? null : n.toFixed(2);
}
function currencyOf(v) {
  return typeof v === "string" && /^[A-Z]{3}$/.test(v) ? v : null;
}
function sellerOf(row) {
  var s = row && row.external_account_id;
  return typeof s === "string" && AA.SELLER_ID_RE.test(s) ? s : null;
}

function configFor(deps) {
  return typeof deps.amazonConfig === "function" ? deps.amazonConfig() : AA.configured(deps.env);
}
/* The connection's region endpoint and marketplace, which must agree with the table. */
function placeOf(row) {
  var m = AA.marketplaceOf(row && row.marketplace_id);
  var base = AA.endpointOf(row && row.region);
  if (!m || !base || m.region !== row.region) throw new SS.StoreRequestError("no_marketplace");
  return { base: base, marketplaceId: row.marketplace_id, market: m };
}
function headersFor(token) {
  return { "x-amz-access-token": token, "Accept": "application/json" };
}
/* The wait after a 429 or a 5xx: Retry-After when given, else the rate the
   answer states (x-amzn-RateLimit-Limit, requests a second), else 1, 2, 4 s. */
function waitMs(headers, attempt) {
  var after = Number(headers && headers["retry-after"]);
  if (isFinite(after) && after >= 0) return Math.min(after * 1000, RETRY_CAP_MS);
  var rate = Number(headers && headers["x-amzn-ratelimit-limit"]);
  var base = Math.pow(2, attempt) * 1000;
  if (isFinite(rate) && rate > 0) base = Math.max(base, Math.ceil(1000 / rate));
  return Math.min(base, RETRY_CAP_MS);
}

/* ── the one read ──────────────────────────────────────────────────────── */
/* One GET, paced, with backoff on 429 and 5xx. Resolves the answer's JSON.
   A 401 or 403 throws StoreAuthError at once; anything else that fails
   throws StoreRequestError. */
async function readGet(deps, base, token, path) {
  for (var attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    await deps.sleep(attempt === 0 ? REQUEST_GAP_MS : 0);
    var answer;
    try {
      answer = await deps.jsonRequest(base + path, { method: "GET", headers: headersFor(token),
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
      if (attempt + 1 < MAX_ATTEMPTS) { await deps.sleep(waitMs(answer.headers, attempt)); continue; }
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
  var again = await deps.supabase.from("member_store_connections").select(CONNECTION_COLUMNS).eq("id", row.id).eq("platform", "amazon").maybeSingle();
  if (again.error || !again.data) throw new SS.StoreRequestError("refresh_lost");
  return again.data;
}

async function refreshRow(deps, row) {
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
    grant = await AA.refreshTokens(config, refreshToken, deps.jsonRequest);
  } catch (err) {
    // invalid_grant: the seller took BizForce's access back (or it lapsed). Connect again.
    if (err && err.kind === "rejected") throw new SS.StoreAuthError("invalid_grant");
    throw new SS.StoreRequestError("token_refresh");
  } finally {
    refreshToken = null;
  }
  var sealedAccessToken = deps.encrypt(grant.accessToken);
  var expiries = AA.expiriesFor(grant, deps.now());
  var update = {
    access_ciphertext: sealedAccessToken.ciphertext, access_iv: sealedAccessToken.iv, access_auth_tag: sealedAccessToken.authTag,
    access_expires_at: expiries.access_expires_at, refresh_expires_at: null,
    token_version: version + 1, updated_at: new Date(deps.now()).toISOString()
  };
  // A new refresh token, when LWA answers one, is saved in the same update.
  if (grant.refreshToken) {
    var sealedRefresh = SS.sealCredentials({ refresh_token: grant.refreshToken }, deps.encrypt);
    update.credentials_ciphertext = sealedRefresh.credentials_ciphertext;
    update.credentials_iv = sealedRefresh.credentials_iv;
    update.credentials_auth_tag = sealedRefresh.credentials_auth_tag;
  }
  var swapped = await deps.supabase.from("member_store_connections").update(update)
    .eq("id", row.id).eq("platform", "amazon").eq("token_version", version).select("id");
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
  if (!force && isFinite(expires) && expires - deps.now() > AA.REFRESH_MARGIN_MS) return sealedAccess(deps, row);
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
  if (!configFor(deps)) throw new SS.StoreRequestError("not_configured");
  var place = placeOf(s.row);
  var token = await accessToken(deps, s, false);
  try {
    return await readGet(deps, place.base, token, path);
  } catch (err) {
    if (!(err instanceof SS.StoreAuthError) || s.refreshed) throw err;
    token = await accessToken(deps, s, true);
    return await readGet(deps, place.base, token, path);
  }
}

/* ── the readers ───────────────────────────────────────────────────────── */
/* The seller's marketplaces: [{ marketplace_id, participating, currency }]. */
async function participations(deps, s) {
  var data = await read(deps, s, "/sellers/v1/marketplaceParticipations");
  var list = Array.isArray(data.payload) ? data.payload : [];
  return list.map(function (p) {
    var m = p && p.marketplace && typeof p.marketplace === "object" ? p.marketplace : {};
    return {
      marketplace_id: typeof m.id === "string" ? m.id : null,
      participating: !!(p && p.participation && p.participation.isParticipating === true),
      currency: currencyOf(m.defaultCurrencyCode)
    };
  });
}

/* The connected marketplace's currency (what lib/storeSync.js stores on the connection). */
async function shopInfo(deps, s) {
  var list = await participations(deps, s);
  var mine = list.filter(function (p) { return p.marketplace_id === s.row.marketplace_id; })[0];
  return { currency: mine ? mine.currency : null };
}

/* "sku:<marketplaceId>:<sku>", or null. */
function identityOf(marketplaceId, sku) {
  if (typeof marketplaceId !== "string" || !/^[A-Z0-9]{8,20}$/.test(marketplaceId)) return null;
  if (typeof sku !== "string" || !sku || sku.length > SKU_MAX || /[\u0000-\u001f\u007f]/.test(sku)) return null;
  return "sku:" + marketplaceId + ":" + sku;
}
/* { marketplaceId, sku } from an identity, or null. */
function skuOf(identity) {
  var m = /^sku:([A-Z0-9]{8,20}):([\s\S]+)$/.exec(String(identity || ""));
  if (!m || /[\u0000-\u001f\u007f]/.test(m[2])) return null;
  return { marketplaceId: m[1], sku: m[2] };
}
function listingPath(sellerId, sku) {
  return LISTINGS_PATH + encodeURIComponent(sellerId) + "/" + encodeURIComponent(sku);
}

/* One listing as BizForce uses it: the name, the product type, the price of
   the B2C offer in this marketplace, the seller-fulfilled stock, and whether
   Amazon fulfils it (FBA). */
function listingOf(marketplaceId, l) {
  var item = l && typeof l === "object" ? l : {};
  var summaries = Array.isArray(item.summaries) ? item.summaries : [];
  var summary = summaries.filter(function (x) { return x && x.marketplaceId === marketplaceId; })[0] || summaries[0] || {};
  var offers = Array.isArray(item.offers) ? item.offers : [];
  var offer = offers.filter(function (o) { return o && o.marketplaceId === marketplaceId && o.offerType === "B2C"; })[0] || null;
  var price = offer && offer.price && typeof offer.price === "object" ? offer.price : null;
  var channels = Array.isArray(item.fulfillmentAvailability) ? item.fulfillmentAvailability : [];
  var mfn = channels.filter(function (c) { return c && c.fulfillmentChannelCode === "DEFAULT"; })[0] || null;
  var others = channels.filter(function (c) { return c && typeof c.fulfillmentChannelCode === "string" && c.fulfillmentChannelCode !== "DEFAULT"; });
  var fba = !mfn && others.length > 0;
  var qty = null;
  if (mfn) qty = Number.isInteger(mfn.quantity) && mfn.quantity >= 0 ? mfn.quantity : null;
  else if (fba) {
    qty = 0;
    others.forEach(function (c) { if (qty !== null && Number.isInteger(c.quantity) && c.quantity >= 0) qty += c.quantity; else qty = null; });
  }
  return {
    sku: typeof item.sku === "string" ? item.sku : null,
    name: typeof summary.itemName === "string" ? summary.itemName : null,
    product_type: typeof summary.productType === "string" && /^[A-Z0-9_]{1,80}$/.test(summary.productType) ? summary.productType : null,
    price: price ? money2(price.amount) : null,
    currency: price ? currencyOf(price.currencyCode || price.currency) : null,
    quantity: qty,
    fba: fba
  };
}

/* The items of one search page: { items, skipped_untracked, skipped_id_too_long }. */
function itemsOfPage(marketplaceId, list) {
  var out = { items: [], skipped_untracked: 0, skipped_id_too_long: 0 };
  (Array.isArray(list) ? list : []).forEach(function (l) {
    var it = listingOf(marketplaceId, l);
    var identity = identityOf(marketplaceId, it.sku);
    if (identity === null) { out.skipped_untracked++; return; }
    if (identity.length > ID_MAX) {
      out.skipped_id_too_long++;
      console.warn("[StoreSync] an Amazon item was skipped: id_too_long");
      return;
    }
    if (it.quantity === null) { out.skipped_untracked++; return; }
    out.items.push({
      external_id: identity,
      external_parent_id: null,
      external_inventory_item_id: null,
      name: cut(it.name || it.sku || "Untitled", 200),
      sku: cut(it.sku.trim(), 100) || null,
      unit_price: it.price === null ? null : Number(it.price),
      unit_cost: null,
      quantity_on_hand: it.quantity,
      fba: it.fba
    });
  });
  return out;
}

/* Every listing in the connected marketplace, as inventory rows. */
async function fetchItems(deps, s) {
  var out = { items: [], skipped_untracked: 0, skipped_disabled: 0, skipped_id_too_long: 0 };
  var seller = sellerOf(s.row);
  if (!seller) throw new SS.StoreRequestError("no_seller");
  var place = placeOf(s.row);
  var pageToken = null;
  for (var page = 0; page < PAGE_CAPS.listings; page++) {
    var data = await read(deps, s, LISTINGS_PATH + encodeURIComponent(seller) + "?marketplaceIds=" + encodeURIComponent(place.marketplaceId) +
      "&includedData=" + INCLUDED_DATA + "&pageSize=" + LISTINGS_PAGE_SIZE + (pageToken ? "&pageToken=" + encodeURIComponent(pageToken) : ""));
    var got = itemsOfPage(place.marketplaceId, data.items);
    got.items.forEach(function (it) { out.items.push(it); });
    out.skipped_untracked += got.skipped_untracked;
    out.skipped_id_too_long += got.skipped_id_too_long;
    pageToken = data.pagination && typeof data.pagination.nextToken === "string" && data.pagination.nextToken ? data.pagination.nextToken : null;
    data = null;
    if (!pageToken) break;
  }
  return out;
}

/* An order reduced to what a summary may hold, straight off Amazon's answer:
   its number, when it was placed, its total and currency. Nothing else of the
   order is read. */
function orderSummary(o) {
  var total = o && o.OrderTotal && typeof o.OrderTotal === "object" ? o.OrderTotal : null;
  var when = o && typeof o.PurchaseDate === "string" && !isNaN(Date.parse(o.PurchaseDate)) ? new Date(Date.parse(o.PurchaseDate)).toISOString() : null;
  return {
    id: o && typeof o.AmazonOrderId === "string" && ORDER_ID_RE.test(o.AmazonOrderId) ? o.AmazonOrderId : "",
    created_at: when,
    total: total ? moneyOf(total.Amount) : null,
    currency: total ? currencyOf(total.CurrencyCode) : null,
    line_items: []
  };
}
/* An order item reduced to its SKU and quantity. */
function orderLine(i) {
  return { sku: i && typeof i.SellerSKU === "string" ? i.SellerSKU : null, quantity: i && Number.isInteger(i.QuantityOrdered) ? i.QuantityOrdered : null };
}

/* Order summaries since sinceIso, at most ORDER_CAP, each with its items
   (read ORDER_ITEMS_GAP_MS apart), through orderSummary, orderLine and
   lib/storeSync.js's summaryOf. */
async function fetchOrders(deps, s, sinceIso) {
  var place = placeOf(s.row);
  var orders = [];
  var nextToken = null;
  for (var page = 0; page < PAGE_CAPS.orders && orders.length < ORDER_CAP; page++) {
    var data = await read(deps, s, "/orders/v0/orders?MarketplaceIds=" + encodeURIComponent(place.marketplaceId) +
      "&CreatedAfter=" + encodeURIComponent(sinceIso) + "&MaxResultsPerPage=" + ORDERS_PAGE_SIZE + (nextToken ? "&NextToken=" + encodeURIComponent(nextToken) : ""));
    var payload = data.payload && typeof data.payload === "object" ? data.payload : {};
    var rows = Array.isArray(payload.Orders) ? payload.Orders.map(orderSummary) : [];
    nextToken = typeof payload.NextToken === "string" && payload.NextToken ? payload.NextToken : null;
    data = null; payload = null;
    for (var i = 0; i < rows.length && orders.length < ORDER_CAP; i++) if (rows[i].id) orders.push(rows[i]);
    if (!nextToken) break;
  }
  var out = [];
  for (var k = 0; k < orders.length; k++) {
    var o = orders[k];
    var itemsToken = null;
    for (var ip = 0; ip < PAGE_CAPS.orderItems; ip++) {
      // getOrderItems allows about one call every two seconds.
      await deps.sleep(ORDER_ITEMS_GAP_MS);
      var items = await read(deps, s, "/orders/v0/orders/" + encodeURIComponent(o.id) + "/orderItems" + (itemsToken ? "?NextToken=" + encodeURIComponent(itemsToken) : ""));
      var ip2 = items.payload && typeof items.payload === "object" ? items.payload : {};
      (Array.isArray(ip2.OrderItems) ? ip2.OrderItems : []).forEach(function (it) { o.line_items.push(orderLine(it)); });
      itemsToken = typeof ip2.NextToken === "string" && ip2.NextToken ? ip2.NextToken : null;
      items = null; ip2 = null;
      if (!itemsToken) break;
    }
    out.push(SS.summaryOf("amazon", o));
  }
  return out;
}

/* One listing, live (getListingsItem), as listingOf gives it. */
async function liveItem(deps, s, identity) {
  var named = skuOf(identity);
  var seller = sellerOf(s.row);
  if (!named || !seller || named.marketplaceId !== s.row.marketplace_id) throw new SS.StoreRequestError("unaddressable");
  var data = await read(deps, s, listingPath(seller, named.sku) + "?marketplaceIds=" + encodeURIComponent(named.marketplaceId) + "&includedData=" + INCLUDED_DATA);
  var it = listingOf(named.marketplaceId, data);
  if (it.sku !== named.sku) throw new SS.StoreRequestError("wrong_item");
  return it;
}

/* The patch for one change, and nothing else. */
function patchBodyFor(field, productType, marketplaceId, currency, to) {
  if (field === "price") {
    return { productType: productType, patches: [{ op: "replace", path: "/attributes/purchasable_offer",
      value: [{ marketplace_id: marketplaceId, currency: currency, our_price: [{ schedule: [{ value_with_tax: Number(to) }] }] }] }] };
  }
  return { productType: productType, patches: [{ op: "replace", path: "/attributes/fulfillment_availability",
    value: [{ fulfillment_channel_code: "DEFAULT", quantity: Number(to) }] }] };
}

/* Does a live listing show the new value? */
function showsValue(field, live, to) {
  if (!live) return false;
  if (field === "price") return live.price !== null && live.price === money2(to);
  return !live.fba && live.quantity === Number(to);
}

/* The first ERROR issue's message, at most ISSUE_MAX characters, or null. */
function firstError(issues) {
  var list = Array.isArray(issues) ? issues : [];
  var e = list.filter(function (i) { return i && i.severity === "ERROR"; })[0];
  if (!e) return null;
  var text = typeof e.message === "string" ? e.message.replace(/[\u0000-\u001f\u007f]+/g, " ").trim() : "";
  return cut(text || "Amazon did not say why.", ISSUE_MAX);
}

/* ── the one write ─────────────────────────────────────────────────────── */
/* ONE PATCH, no loop. preview true adds mode=VALIDATION_PREVIEW: Amazon
   checks the patch and changes nothing. Resolves { ok: true, status, issues }
   or { ok: false, code, sent, auth? }. */
async function patchOnce(deps, s, identity, body, preview) {
  var named = skuOf(identity);
  var seller = sellerOf(s.row);
  if (!configFor(deps) || !named || !seller || named.marketplaceId !== s.row.marketplace_id) return { ok: false, code: "not_sent", sent: false };
  var place;
  try { place = placeOf(s.row); } catch (err) { return { ok: false, code: "not_sent", sent: false }; }
  var token = await accessToken(deps, s, false);
  var answer;
  try {
    answer = await deps.jsonRequest(place.base + listingPath(seller, named.sku) + "?marketplaceIds=" + encodeURIComponent(named.marketplaceId) +
      (preview ? "&mode=VALIDATION_PREVIEW" : ""), { method: "PATCH", headers: headersFor(token), body: body,
      exposeHeaders: EXPOSED_HEADERS, maxBytes: WRITE_MAX_BYTES, timeoutMs: WRITE_TIMEOUT_MS });
  } catch (err) {
    var code = err && err.guardedFetch === true ? String(err.code) : "guard_refused";
    if (NOT_SENT.indexOf(code) !== -1) return { ok: false, code: "not_sent", sent: false };
    return { ok: false, code: "unconfirmed", sent: true };
  }
  var status = answer && answer.status;
  var json = answer && answer.json && typeof answer.json === "object" ? answer.json : {};
  if (status === 401 || status === 403) return { ok: false, code: "auth", sent: true, auth: true };
  if (status === 429) return { ok: false, code: "throttled", sent: true };
  if (status === 400 && (json.status === "INVALID" || Array.isArray(json.issues))) return { ok: true, status: "INVALID", issues: json.issues || [] };
  if (typeof status === "number" && status >= 400 && status < 500 && status !== 408) return { ok: false, code: "refused", sent: true };
  if (typeof status !== "number" || status < 200 || status >= 300) return { ok: false, code: "unconfirmed", sent: true };
  var said = typeof json.status === "string" ? json.status : "";
  if (["ACCEPTED", "INVALID", "VALID"].indexOf(said) === -1) return { ok: false, code: "unconfirmed", sent: true };
  return { ok: true, status: said, issues: Array.isArray(json.issues) ? json.issues : [] };
}

/* The writer: the preview first, then the patch ONCE, never retried.
   Resolves:
     { ok: true, status: "ACCEPTED" }
     { ok: false, code: "preview_error" | "invalid", issue }   nothing was changed
     { ok: false, code, sent, auth? }                           patchOnce's failure */
async function writeListing(deps, s, identity, body) {
  var preview = await patchOnce(deps, s, identity, body, true);
  if (!preview.ok) return preview.sent === true ? { ok: false, code: "preview_failed", sent: false, auth: preview.auth } : preview;
  var previewIssue = firstError(preview.issues);
  if (previewIssue !== null || preview.status === "INVALID") return { ok: false, code: "preview_error", issue: previewIssue || "Amazon did not say why." };
  var sent = await patchOnce(deps, s, identity, body, false);
  if (!sent.ok) return sent;
  if (sent.status === "INVALID") return { ok: false, code: "invalid", issue: firstError(sent.issues) || "Amazon did not say why." };
  if (sent.status !== "ACCEPTED") return { ok: false, code: "unconfirmed", sent: true };
  return { ok: true, status: "ACCEPTED" };
}

/* After an accepted patch: one live read every CONFIRM_EVERY_MS, at most
   CONFIRM_READS of them. "confirmed" when one shows the new value, else
   "submitted" (Amazon applies changes in its own time). Never writes. */
async function confirmPoll(deps, s, identity, field, to) {
  for (var i = 0; i < CONFIRM_READS; i++) {
    await deps.sleep(CONFIRM_EVERY_MS);
    var live = null;
    try { live = await liveItem(deps, s, identity); } catch (err) { live = null; }
    if (showsValue(field, live, to)) return "confirmed";
  }
  return "submitted";
}

module.exports = {
  LISTINGS_PATH: LISTINGS_PATH,
  INCLUDED_DATA: INCLUDED_DATA,
  PAGE_CAPS: PAGE_CAPS,
  ORDER_CAP: ORDER_CAP,
  ORDER_ITEMS_GAP_MS: ORDER_ITEMS_GAP_MS,
  MAX_ATTEMPTS: MAX_ATTEMPTS,
  ID_MAX: ID_MAX,
  CONFIRM_EVERY_MS: CONFIRM_EVERY_MS,
  CONFIRM_READS: CONFIRM_READS,
  ISSUE_MAX: ISSUE_MAX,
  EXPOSED_HEADERS: EXPOSED_HEADERS,
  CONNECTION_COLUMNS: CONNECTION_COLUMNS,
  money2: money2,
  session: session,
  accessToken: accessToken,
  readGet: readGet,
  read: read,
  participations: participations,
  shopInfo: shopInfo,
  identityOf: identityOf,
  skuOf: skuOf,
  listingOf: listingOf,
  itemsOfPage: itemsOfPage,
  fetchItems: fetchItems,
  orderSummary: orderSummary,
  orderLine: orderLine,
  fetchOrders: fetchOrders,
  liveItem: liveItem,
  patchBodyFor: patchBodyFor,
  showsValue: showsValue,
  firstError: firstError,
  patchOnce: patchOnce,
  writeListing: writeListing,
  confirmPoll: confirmPoll
};
