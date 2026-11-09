// ── Store changes, through approval (migrations 175 and 176) ─────────────────
//
// WHAT IT DOES. A member who connected a store with "Let BizForce make changes
// I approve (prices and stock)" ticked (member_store_connections.permission
// "read_write"; for Shopify, with write_products and write_inventory granted
// too) can propose a new price or a new stock level for an item BizForce read
// from that store. Nothing changes in the store until the member approves the
// proposal; then the executor checks the store's live value again, writes the
// one field, checks the store's answer and records the change, which the
// member can undo by proposing it back.
//
// THE ONLY FILES THAT WRITE TO A STORE: this one (WooCommerce, below),
// lib/shopifyApi.js's writePrice and writeStock, and lib/etsyApi.js's
// writeInventory (Nov 8 2026, migration 181), and lib/amazonApi.js's
// writeListing (Nov 8 2026, migration 182), which only this file calls.
// lib/storeSync.js stays GET-only (scripts/checkStoreConnections.js N1, N2).
// Every path here refuses a connection that is not read_write.
//
// WHAT IS WRITTEN, AND NOTHING ELSE:
//   WooCommerce
//   - a price: { regular_price: "<2 decimals>" }. sale_price is never sent.
//   - a stock level: { stock_quantity: <whole number> }, only when the store's
//     live manage_stock is true.
//   To the item's own resource: /wp-json/wc/v3/products/<id> for a simple
//   product, /wp-json/wc/v3/products/<parent>/variations/<id> for a variation
//   (inventory_items.external_parent_id, stored by the sync since 175). As POST:
//   WordPress registers an update under POST, PUT and PATCH alike. The guarded
//   fetcher has sent PUT too since Nov 8 2026, for Etsy alone (below); a
//   WooCommerce change stays a POST.
//   Etsy (Nov 8 2026, migration 181, lib/etsyApi.js)
//   - Etsy's PUT /listings/<id>/inventory replaces the whole inventory, so the
//     body is rebuilt from a live read made just before it, with only the
//     target offering's price (a decimal) or quantity (0 to 999) changed. When
//     the listing's price or quantity does not vary by a property the product
//     has, the one value applies to every product sharing it, and all of them
//     change together, as one approved change the proposal names. ONE PUT,
//     never retried, then ONE confirming read: the targets hold the new value
//     and every other product is exactly as it was, or the change fails with
//     "Etsy shows other changes on this listing. Check it on Etsy before filing
//     again." and nothing is undone automatically.
//   Amazon (Nov 8 2026, migration 182, lib/amazonApi.js)
//   - one listing in the connected marketplace, named by its SKU. A live read
//     (getListingsItem) right before is the compare-and-set and gives the
//     product type. The patch replaces one attribute and nothing else: a
//     price as purchasable_offer (our_price, value_with_tax), a stock level as
//     fulfillment_availability with fulfillment_channel_code "DEFAULT". A
//     stock change for an item Amazon fulfils (FBA) is refused: "Amazon
//     manages the stock of items it ships for you (FBA). Change it in Seller
//     Central." The patch goes first with mode=VALIDATION_PREVIEW; an ERROR
//     issue fails the change with Amazon's first message and nothing is
//     sent. Then ONE patch, never retried; INVALID fails with its message.
//     Amazon applies an accepted patch in its own time, so a live read every
//     10 seconds, for at most 60, looks for the new value: the change is
//     logged "confirmed" when one shows it, else "submitted", and the next
//     sync confirms it once the listing shows it (lib/storeSync.js
//     promoteSubmitted).
//   Shopify (migration 176, GraphQL)
//   - a price: productVariantsBulkUpdate with the variant's price only;
//     compareAtPrice is never written (the proposal says when one is set).
//   - a stock level: inventorySetQuantities, "available" at the connection's
//     chosen location, with changeFromQuantity set to the value proposed from
//     and @idempotent keyed on the proposal id; no location, no stock change.
//
// COMPARE-AND-SET. The proposal records the store's value when it was filed
// (from). At execution one read gets the live item; if the live value is not
// exactly from (a price as a 2-decimal string, stock as a whole number),
// nothing is written and the proposal fails: "Your store changed since you
// proposed this. Propose it again." Shopify's stock write carries from as
// changeFromQuantity too, and after it ONE more read confirms the new value.
//
// NO RETRY AFTER A WRITE IS SENT. The write is ONE request, with no loop
// around it. A timeout or a network failure after it was sent, a 5xx, or a
// 2xx whose answer does not show the new value, is reported as "BizForce
// couldn't confirm the change. Check the item in your store; BizForce will not
// try again." and nothing is logged as executed.
//
// THE CAP. At most DAILY_CAP executed changes per connection in the last 24
// hours, counted from store_change_log at execution.
//
// Everything outside (the Supabase client, the guarded request, the clock,
// sleep, decrypt) is injected, as lib/storeSync.js's is, so a check drives it
// with stubs. The Basic auth header, the store URL and the credentials are
// lib/storeSync.js's own functions, not copies.
"use strict";

var SS = require("./storeSync");
var SAPI = require("./shopifyApi");
var EAPI = require("./etsyApi");
var AAPI = require("./amazonApi");
var AA = require("./amazonAuth");

var ACTION_TYPE = "update_store_item";
var FIELDS = ["price", "stock"];
var PRICE_MIN = 0.01;
var VALUE_MAX = 1000000;
var DAILY_CAP = 100;
var DAY_MS = 24 * 60 * 60 * 1000;
var LIVE_FIELDS = "id,regular_price,sale_price,stock_quantity,manage_stock";
var WRITE_TIMEOUT_MS = 20000;
var WRITE_MAX_BYTES = 1024 * 1024;
var LOG_PAGE = 50;
// Refusals by the guarded fetcher before a byte is sent: nothing reached the store.
var NOT_SENT = ["blocked", "invalid_url", "dns", "guard_refused"];
var UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Etsy's shop id too (migration 181), which lib/etsyApi.js reads its listings under.
// Amazon's seller id, marketplace and region too (migration 182).
var CONNECTION_COLUMNS = SAPI.CONNECTION_COLUMNS + ", external_account_id, marketplace_id, region";
var ITEM_COLUMNS = "id, user_id, name, source, store_connection_id, external_id, external_parent_id, external_inventory_item_id, unit_price, quantity_on_hand";
// confirmation (migration 182): "confirmed", or "submitted" for an Amazon change not yet shown.
var LOG_COLUMNS = "id, connection_id, inventory_item_id, external_id, item_name, field, old_value, new_value, currency, location_name, proposal_id, executed_at, confirmation";

var MESSAGES = {
  changed: "Your store changed since you proposed this. Propose it again.",
  untracked: "This item's stock isn't tracked in your store.",
  unconfirmed: "BizForce couldn't confirm the change. Check the item in your store; BizForce will not try again.",
  cap: "This store has reached today's limit of 100 changes.",
  sale: "A sale is running on this item, so shoppers see the sale price until it ends.",
  filed: "Filed for approval. Nothing has changed in your store yet.",
  readOnly: "This store was connected read-only. Connect it again with \"Let BizForce make changes I approve (prices and stock)\" ticked to propose changes.",
  noLocation: "Choose a location for stock changes first.",
  notConnected: "This store needs connecting again before BizForce can change anything in it.",
  notSynced: "This item is not one BizForce read from a store you connected.",
  resync: "BizForce can't tell which item this is in your store yet. Press Sync now on the Store Agent page, then try again.",
  same: "That is already the value in your store, so there is nothing to change.",
  noPrice: "This item has no regular price in your store, so BizForce can't change it from here.",
  negativeStock: "This item's stock in your store is below 0, so BizForce can't record a change from it. Change it in your store.",
  price: "Enter a price from 0.01 to 1000000, with at most 2 decimals.",
  stock: "Enter a stock level as a whole number from 0 to 1000000.",
  field: "Choose price or stock.",
  item: "Choose an item.",
  unreachable: "Your store did not answer just now, so nothing was changed. Try again in a few minutes.",
  notSent: "Your store could not be reached, so nothing was sent and nothing was changed.",
  refused: "Your store refused the change, so nothing was changed.",
  rejected: "Your store refused the saved key, so nothing was changed. Connect the store again on the Store Agent page.",
  gone: "That change is not in your list.",
  itemGone: "That item is no longer in your inventory, so the change can't be undone from here.",
  // Etsy (migration 181)
  etsyStock: "Etsy allows a stock level from 0 to 999.",
  etsyOther: "Etsy shows other changes on this listing. Check it on Etsy before filing again.",
  etsyAllPrice: "This price applies to every variation of this listing.",
  etsyAllStock: "This stock level applies to every variation of this listing.",
  // Amazon (migration 182)
  amazonFba: "Amazon manages the stock of items it ships for you (FBA). Change it in Seller Central.",
  amazonFbaPrice: "Amazon ships this item for you (FBA); only its price changes.",
  amazonRefused: "Amazon refused the change, so nothing was changed: ",
  amazonSubmitted: "Amazon accepted the change and applies it in its own time. The next sync confirms it."
};

/* The note an Etsy change carries when its one value applies to more than the
   one variation (price_on_property or quantity_on_property), or null. */
function etsyGroupNote(field, count, every) {
  if (!(count > 1)) return null;
  if (every) return field === "price" ? MESSAGES.etsyAllPrice : MESSAGES.etsyAllStock;
  return (field === "price" ? "This price applies to " : "This stock level applies to ") + count + " variations of this listing.";
}

/* The propose note when a Shopify variant has a compare-at price (migration 176). */
function compareAtNote(amount, currency) {
  return "This item has a compare-at price of " + amount + (currency ? " " + currency : "") + ", which stays as it is.";
}

function cut(value, n) {
  var s = String(value == null ? "" : value);
  return s.length > n ? s.slice(0, n) : s;
}

/* A price as the member typed it: "12.5" or 12.5 becomes "12.50". At most 2
   decimals and 7 whole digits; anything else is null. */
function money2(v) {
  var s = typeof v === "number" ? (isFinite(v) ? String(v) : "") : (typeof v === "string" ? v.trim() : "");
  if (!/^[0-9]{1,7}([.][0-9]{1,2})?$/.test(s)) return null;
  return (Math.round(Number(s) * 100) / 100).toFixed(2);
}

/* A price as the store holds it ("19.99", "20", or "" for none), as a
   2-decimal string, or null. */
function liveMoney(v) {
  if (v === null || v === undefined || v === "") return null;
  var n = Number(v);
  if (!isFinite(n) || n < 0) return null;
  return (Math.round(n * 100) / 100).toFixed(2);
}

/* A whole number from 0 to 9999999, given as a number or as digits; else null. */
function int(v) {
  if (typeof v === "number") return Number.isInteger(v) && v >= 0 && v <= 9999999 ? v : null;
  if (typeof v === "string" && /^[0-9]{1,7}$/.test(v.trim())) return Number(v.trim());
  return null;
}

/* The new value a member asked for: { ok: true, value } or { ok: false, code, error }.
   A price comes back as a 2-decimal string, a stock level as a whole number. */
function validateChange(field, to) {
  if (field === "price") {
    var m = money2(to);
    if (m === null || Number(m) < PRICE_MIN || Number(m) > VALUE_MAX) return { ok: false, code: "price_range", error: MESSAGES.price };
    return { ok: true, value: m };
  }
  if (field === "stock") {
    var n = int(to);
    if (n === null || n > VALUE_MAX) return { ok: false, code: "stock_range", error: MESSAGES.stock };
    return { ok: true, value: n };
  }
  return { ok: false, code: "field", error: MESSAGES.field };
}

/* The item's own path in the store's REST API, or null when the row cannot
   name it (a variation synced before migration 175 has no parent id). */
function itemPath(row) {
  var m = /^(product|variation):([0-9]{1,30})$/.exec(String((row && row.external_id) || ""));
  if (!m) return null;
  var parent = row.external_parent_id == null ? "" : String(row.external_parent_id);
  if (m[1] === "product") return parent === "" ? "/products/" + m[2] : null;
  if (!/^[0-9]{1,30}$/.test(parent)) return null;
  return "/products/" + parent + "/variations/" + m[2];
}
function storeIdOf(row) {
  return String((row && row.external_id) || "").split(":")[1] || "";
}

/* A Shopify row's ids as GraphQL ids (migration 176): the variant, its product
   and its inventory item, each null when the row does not hold it. */
function shopifyIds(row) {
  var m = /^variant:([0-9]{1,30})$/.exec(String((row && row.external_id) || ""));
  return {
    variant: m ? SAPI.gidOf("ProductVariant", m[1]) : null,
    product: SAPI.gidOf("Product", row && row.external_parent_id),
    item: SAPI.gidOf("InventoryItem", row && row.external_inventory_item_id)
  };
}
/* Can this row be addressed for this field? */
function addressable(platform, field, row) {
  if (platform === "woocommerce") return !!itemPath(row);
  if (platform === "etsy") {
    var listing = EAPI.listingOf(row && row.external_id);
    return listing !== null && String((row && row.external_parent_id) || "") === listing;
  }
  if (platform === "shopify") {
    var ids = shopifyIds(row);
    return field === "price" ? !!(ids.variant && ids.product) : !!ids.item;
  }
  if (platform === "amazon") return AAPI.skuOf(row && row.external_id) !== null && (row.external_parent_id == null || row.external_parent_id === "");
  return false;
}

/* The live value of one field, from a live item. */
function liveValue(field, live) {
  return field === "price" ? live.regular_price : live.stock_quantity;
}

/* Compare-and-set: the live item must still hold exactly `from`. A stock
   change also needs the store to track the item's stock. */
function compareLive(field, from, live) {
  if (field === "stock" && live.manage_stock !== true) return { ok: false, code: "untracked", error: MESSAGES.untracked };
  if (field === "price") {
    var want = money2(from);
    if (want === null || live.regular_price === null || live.regular_price !== want) return { ok: false, code: "changed", error: MESSAGES.changed };
    return { ok: true };
  }
  if (int(from) === null || live.stock_quantity === null || live.stock_quantity !== int(from)) return { ok: false, code: "changed", error: MESSAGES.changed };
  return { ok: true };
}

/* One GET of the live item, through lib/storeSync.js's GET-only request. */
async function readLiveWooItem(deps, conn, creds, row) {
  var path = itemPath(row);
  if (!path) return { ok: false, code: "unaddressable", error: MESSAGES.resync };
  var got;
  try {
    got = await SS.request(deps, SS.wooUrl(conn.store_url, path + "?_fields=" + LIVE_FIELDS), SS.wooHeaders(creds));
  } catch (err) {
    if (err instanceof SS.StoreAuthError) return { ok: false, code: err.code, auth: true, error: MESSAGES.rejected };
    return { ok: false, code: err instanceof SS.StoreRequestError ? err.code : "unreachable", error: MESSAGES.unreachable };
  }
  var d = got.data && typeof got.data === "object" ? got.data : {};
  if (String(d.id) !== storeIdOf(row)) return { ok: false, code: "wrong_item", error: MESSAGES.unreachable };
  return { ok: true, live: {
    regular_price: liveMoney(d.regular_price),
    sale_price: liveMoney(d.sale_price),
    stock_quantity: typeof d.stock_quantity === "number" && Number.isInteger(d.stock_quantity) ? d.stock_quantity : null,
    manage_stock: d.manage_stock === true
  } };
}

/* One live read of a Shopify item for one field (lib/shopifyApi.js, a query),
   in the same shape as the WooCommerce one: a price as regular_price (Shopify's
   price is what shoppers pay; compare_at is shown, never written), stock as
   "available" at the connection's location. */
async function readLiveShopifyItem(deps, s, field, row) {
  var ids = shopifyIds(row);
  try {
    if (field === "price") {
      if (!ids.variant || !ids.product) return { ok: false, code: "unaddressable", error: MESSAGES.resync };
      var v = await SAPI.liveVariant(deps, s, ids.variant);
      if (!v || v.product_id !== ids.product) return { ok: false, code: "wrong_item", error: MESSAGES.unreachable };
      return { ok: true, live: { regular_price: v.price, sale_price: null, compare_at: v.compare_at, stock_quantity: null, manage_stock: v.tracked } };
    }
    if (!ids.item) return { ok: false, code: "unaddressable", error: MESSAGES.resync };
    if (!s.row.location_id) return { ok: false, code: "no_location", error: MESSAGES.noLocation };
    var a = await SAPI.liveAvailable(deps, s, ids.item, s.row.location_id);
    if (!a) return { ok: false, code: "wrong_item", error: MESSAGES.unreachable };
    return { ok: true, live: { regular_price: null, sale_price: null, compare_at: null, stock_quantity: a.available, manage_stock: a.tracked } };
  } catch (err) {
    if (err && err.name === "StoreAuthError") return { ok: false, code: err.code, auth: true, error: MESSAGES.rejected };
    return { ok: false, code: err && err.name === "StoreRequestError" ? err.code : "unreachable", error: MESSAGES.unreachable };
  }
}

/* The write: ONE request, never retried. { ok: true, data } or
   { ok: false, code, sent, auth?, error }. */
async function writeWooItem(deps, conn, creds, row, body) {
  var path = itemPath(row);
  if (!path) return { ok: false, code: "unaddressable", sent: false, error: MESSAGES.resync };
  var answer;
  try {
    answer = await deps.jsonRequest(SS.wooUrl(conn.store_url, path), { method: "POST", headers: SS.wooHeaders(creds), body: body,
      exposeHeaders: ["retry-after"], maxBytes: WRITE_MAX_BYTES, timeoutMs: WRITE_TIMEOUT_MS });
  } catch (err) {
    var code = err && err.guardedFetch === true ? String(err.code) : "guard_refused";
    if (NOT_SENT.indexOf(code) !== -1) return { ok: false, code: "not_sent", sent: false, error: MESSAGES.notSent };
    return { ok: false, code: "unconfirmed", sent: true, error: MESSAGES.unconfirmed };
  }
  var status = answer && answer.status;
  if (status === 401 || status === 403) return { ok: false, code: "http_" + status, sent: true, auth: true, error: MESSAGES.rejected };
  if (status >= 200 && status < 300) return { ok: true, data: answer.json };
  if (status >= 400 && status < 500 && status !== 408 && status !== 429) return { ok: false, code: "refused_" + status, sent: true, error: MESSAGES.refused };
  return { ok: false, code: "unconfirmed", sent: true, error: MESSAGES.unconfirmed };
}

/* The store's answer must show the item and the new value. */
function echoMatches(field, to, row, data) {
  var d = data && typeof data === "object" ? data : {};
  if (String(d.id) !== storeIdOf(row)) return false;
  if (field === "price") return liveMoney(d.regular_price) === money2(to);
  return typeof d.stock_quantity === "number" && d.stock_quantity === int(to);
}

/* What one change sends: one field, nothing else. */
function writeBody(field, to) {
  return field === "price" ? { regular_price: money2(to) } : { stock_quantity: int(to) };
}

/* lib/shopifyApi.js's sendOnce outcome, as the member is told it. */
var SHOPIFY_OUTCOME = { not_sent: "notSent", auth: "rejected", throttled: "unreachable", refused: "refused", changed: "changed", unconfirmed: "unconfirmed" };

/* The Shopify write, ONE request (lib/shopifyApi.js), never retried, then the
   echo for a price or ONE confirming read for stock. { ok: true } or
   { ok: false, auth?, error }. */
async function writeShopifyItem(deps, s, field, row, from, to, proposalId) {
  var ids = shopifyIds(row);
  var sent;
  try {
    sent = field === "price"
      ? await SAPI.writePrice(deps, s, ids.product, ids.variant, money2(to))
      : await SAPI.writeStock(deps, s, ids.item, s.row.location_id, int(from), int(to), proposalId);
  } catch (err) {
    // Only getting the token can throw here (a refresh refused or unreachable); nothing was sent.
    if (err && err.name === "StoreAuthError") return { ok: false, auth: true, code: err.code, error: MESSAGES.rejected };
    return { ok: false, code: "not_sent", error: MESSAGES.notSent };
  }
  if (!sent.ok) return { ok: false, auth: sent.code === "auth", code: sent.code, error: MESSAGES[SHOPIFY_OUTCOME[sent.code] || "unconfirmed"] };
  if (field === "price") {
    var list = sent.data && Array.isArray(sent.data.productVariants) ? sent.data.productVariants : [];
    var echoed = list.some(function (v) { return v && String(v.id) === ids.variant && liveMoney(v.price) === money2(to); });
    return echoed ? { ok: true } : { ok: false, code: "unconfirmed", error: MESSAGES.unconfirmed };
  }
  var after;
  try { after = await SAPI.liveAvailable(deps, s, ids.item, s.row.location_id); } catch (err) { after = null; }
  return after && after.available === int(to) ? { ok: true } : { ok: false, code: "unconfirmed", error: MESSAGES.unconfirmed };
}

/* One live read of an Etsy listing's inventory (lib/etsyApi.js, a GET), for
   the product an item names, in the same shape as the others, plus the whole
   inventory and the products the new value applies to. The value must be the
   same on every one of them, or the listing is not what it was. */
async function readLiveEtsyItem(deps, s, field, row) {
  if (!addressable("etsy", field, row)) return { ok: false, code: "unaddressable", error: MESSAGES.resync };
  var inventory;
  try {
    inventory = await EAPI.liveInventory(deps, s, row.external_parent_id);
  } catch (err) {
    if (err && err.name === "StoreAuthError") return { ok: false, code: err.code, auth: true, error: MESSAGES.rejected };
    return { ok: false, code: err && err.name === "StoreRequestError" ? err.code : "unreachable", error: MESSAGES.unreachable };
  }
  var got = EAPI.liveOf(inventory, row.external_id, field);
  if (!got.ok) return { ok: false, code: "wrong_item", error: MESSAGES.resync };
  var mine = liveValue(field, got.live);
  var uniform = got.targets.indexes.every(function (i) {
    var o = (inventory.products[i].offerings || [])[0];
    return !!o && (field === "price" ? EAPI.money2(o.price) : o.quantity) === mine;
  });
  if (!uniform) return { ok: false, code: "changed", error: MESSAGES.changed };
  return { ok: true, live: got.live, inventory: inventory, targets: got.targets };
}

/* lib/etsyApi.js's writeInventory outcome, as the member is told it. */
var ETSY_OUTCOME = { not_sent: "notSent", auth: "rejected", throttled: "unreachable", refused: "refused", unconfirmed: "unconfirmed" };

/* The Etsy write: the whole inventory rebuilt from `before` with only the
   targets changed, ONE PUT (lib/etsyApi.js), never retried, then ONE
   confirming read compared with `before`. { ok: true, after } or
   { ok: false, auth?, code, error }. */
async function writeEtsyItem(deps, s, row, before, indexes, field, to) {
  var listingId = String(row.external_parent_id);
  var etsySent;
  try {
    etsySent = await EAPI.writeInventory(deps, s, listingId, EAPI.putBodyFor(before, indexes, field, to));
  } catch (err) {
    // Only getting the token can throw here (a refresh refused or unreachable); nothing was sent.
    if (err && err.name === "StoreAuthError") return { ok: false, auth: true, code: err.code, error: MESSAGES.rejected };
    return { ok: false, code: "not_sent", error: MESSAGES.notSent };
  }
  if (!etsySent.ok) return { ok: false, auth: etsySent.code === "auth", code: etsySent.code, error: MESSAGES[ETSY_OUTCOME[etsySent.code] || "unconfirmed"] };
  var after;
  try { after = await EAPI.liveInventory(deps, s, listingId); } catch (err) { after = null; }
  if (!after) return { ok: false, code: "unconfirmed", error: MESSAGES.unconfirmed };
  if (!EAPI.confirmMatches(before, after, listingId, indexes, field, to)) return { ok: false, code: "other_changes", error: MESSAGES.etsyOther };
  return { ok: true, after: after };
}

/* One live read of an Amazon listing (lib/amazonApi.js, a GET), in the same
   shape as the others, plus the product type a patch names and whether
   Amazon fulfils the item (FBA). An FBA item's stock is not BizForce's to
   change, so manage_stock is false for it. */
async function readLiveAmazonItem(deps, s, field, row) {
  if (!addressable("amazon", field, row)) return { ok: false, code: "unaddressable", error: MESSAGES.resync };
  var it;
  try {
    it = await AAPI.liveItem(deps, s, row.external_id);
  } catch (err) {
    if (err && err.name === "StoreAuthError") return { ok: false, code: err.code, auth: true, error: MESSAGES.rejected };
    var code = err && err.name === "StoreRequestError" ? err.code : "unreachable";
    return { ok: false, code: code, error: code === "http_404" || code === "wrong_item" || code === "unaddressable" ? MESSAGES.resync : MESSAGES.unreachable };
  }
  return { ok: true, fba: it.fba === true, product_type: it.product_type, offer_currency: it.currency,
    live: { regular_price: it.price, sale_price: null, compare_at: null, stock_quantity: it.quantity, manage_stock: it.fba !== true && it.quantity !== null } };
}

/* lib/amazonApi.js's writeListing outcome, as the member is told it. */
var AMAZON_OUTCOME = { not_sent: "notSent", preview_failed: "unreachable", auth: "rejected", throttled: "unreachable", refused: "refused", unconfirmed: "unconfirmed" };

/* The Amazon write: the preview, then ONE patch (lib/amazonApi.js
   writeListing), never retried, then the bounded confirmation.
   { ok: true, confirmation: "confirmed" | "submitted" } or
   { ok: false, auth?, code, error }. */
async function writeAmazonItem(deps, s, row, field, productType, currency, to) {
  var body = AAPI.patchBodyFor(field, productType, s.row.marketplace_id, currency, to);
  var sent;
  try {
    sent = await AAPI.writeListing(deps, s, row.external_id, body);
  } catch (err) {
    // Only getting the token can throw here (a refresh refused or unreachable); nothing was sent.
    if (err && err.name === "StoreAuthError") return { ok: false, auth: true, code: err.code, error: MESSAGES.rejected };
    return { ok: false, code: "not_sent", error: MESSAGES.notSent };
  }
  if (!sent.ok) {
    if (sent.code === "preview_error" || sent.code === "invalid") return { ok: false, code: sent.code, error: MESSAGES.amazonRefused + sent.issue };
    return { ok: false, auth: sent.code === "auth" || sent.auth === true, code: sent.code, error: MESSAGES[AMAZON_OUTCOME[sent.code] || "unconfirmed"] };
  }
  var confirmation = await AAPI.confirmPoll(deps, s, row.external_id, field, to);
  return { ok: true, confirmation: confirmation === "confirmed" ? "confirmed" : "submitted" };
}

/* Changes executed on a connection in the last 24 hours, or null when they
   could not be counted. */
async function changesInLastDay(deps, connectionId) {
  var since = new Date(deps.now() - DAY_MS).toISOString();
  var counted = await deps.supabase.from("store_change_log").select("id", { count: "exact", head: true })
    .eq("connection_id", connectionId).gte("executed_at", since);
  if (counted.error || typeof counted.count !== "number") return null;
  return counted.count;
}

/* The member's connection, and whether it may be changed. { ok, conn } or { ok: false, status, code, error }. */
async function readWritableConnection(deps, userId, connectionId) {
  if (typeof connectionId !== "string" || !UUID_RE.test(connectionId)) return { ok: false, status: 409, code: "not_synced", error: MESSAGES.notSynced };
  var read = await deps.supabase.from("member_store_connections").select(CONNECTION_COLUMNS)
    .eq("id", connectionId).eq("user_id", userId).maybeSingle();
  if (read.error) throw read.error;
  var conn = read.data;
  if (!conn || SS.PLATFORMS.indexOf(conn.platform) === -1) return { ok: false, status: 409, code: "not_synced", error: MESSAGES.notSynced };
  if (SS.permissionOf(conn) !== "read_write") return { ok: false, status: 409, code: "read_only", error: MESSAGES.readOnly };
  if (conn.status !== "connected") return { ok: false, status: 409, code: "needs_reconnect", error: MESSAGES.notConnected };
  return { ok: true, conn: conn };
}

async function readItem(deps, userId, itemId) {
  var read = await deps.supabase.from("inventory_items").select(ITEM_COLUMNS).eq("id", itemId).eq("user_id", userId).maybeSingle();
  if (read.error) throw read.error;
  return read.data || null;
}

function shown(field, v) {
  return field === "price" ? money2(v) : String(int(v));
}

/* The live item for a proposal or an execution, by platform. */
async function readLive(deps, conn, s, field, item) {
  if (conn.platform === "shopify") return readLiveShopifyItem(deps, s, field, item);
  if (conn.platform === "etsy") return readLiveEtsyItem(deps, s, field, item);
  if (conn.platform === "amazon") return readLiveAmazonItem(deps, s, field, item);
  if (conn.platform !== "woocommerce") return { ok: false, code: "not_synced", error: MESSAGES.notSynced };
  var creds;
  try { creds = SS.openCredentials(conn, deps.decrypt); } catch (e) {
    return { ok: false, code: "credentials_unreadable", auth: true, error: MESSAGES.notConnected };
  }
  var got = await readLiveWooItem(deps, conn, creds, item);
  creds = null;
  return got;
}

/* POST /api/store/changes/propose: { status, body }. Reads the live value as
   from, and files a pending update_store_item proposal. Never runs it. */
async function proposeChange(deps, userId, input) {
  var b = input || {};
  var field = b.field;
  if (FIELDS.indexOf(field) === -1) return { status: 400, body: { error: MESSAGES.field, code: "field", field: "field" } };
  if (typeof b.item_id !== "string" || !UUID_RE.test(b.item_id)) return { status: 400, body: { error: MESSAGES.item, code: "item", field: "item_id" } };
  var item = await readItem(deps, userId, b.item_id);
  if (!item) return { status: 404, body: { error: "Item not found", code: "not_found" } };
  if (item.source !== "woocommerce" && item.source !== "shopify" && item.source !== "etsy" && item.source !== "amazon") return { status: 409, body: { error: MESSAGES.notSynced, code: "not_synced" } };
  var c = await readWritableConnection(deps, userId, item.store_connection_id);
  if (!c.ok) return { status: c.status, body: { error: c.error, code: c.code } };
  var platform = c.conn.platform;
  if (item.source !== platform) return { status: 409, body: { error: MESSAGES.notSynced, code: "not_synced" } };
  var v = validateChange(field, b.to);
  if (!v.ok) return { status: 400, body: { error: v.error, code: v.code, field: "to" } };
  if (platform === "etsy" && field === "stock" && v.value > EAPI.QUANTITY_MAX) return { status: 400, body: { error: MESSAGES.etsyStock, code: "stock_range", field: "to" } };
  if (!addressable(platform, field, item)) return { status: 409, body: { error: MESSAGES.resync, code: "unaddressable" } };
  if (platform === "shopify" && field === "stock" && !c.conn.location_id) return { status: 409, body: { error: MESSAGES.noLocation, code: "no_location" } };

  // Amazon (migration 182): the item must be in the connection's own marketplace.
  if (platform === "amazon" && (AAPI.skuOf(item.external_id) || {}).marketplaceId !== c.conn.marketplace_id) return { status: 409, body: { error: MESSAGES.resync, code: "unaddressable" } };

  var s = platform === "shopify" ? SAPI.session(c.conn) : platform === "etsy" ? EAPI.session(c.conn) : platform === "amazon" ? AAPI.session(c.conn) : null;
  var got = await readLive(deps, c.conn, s, field, item);
  if (!got.ok) {
    if (got.auth) {
      await SS.markNeedsReconnect(deps.supabase, c.conn, got.code, new Date(deps.now()).toISOString());
      return { status: 409, body: { error: got.code === "credentials_unreadable" ? MESSAGES.notConnected : MESSAGES.rejected, code: "needs_reconnect" } };
    }
    return { status: got.code === "unaddressable" || got.code === "no_location" ? 409 : 503, body: { error: got.error, code: got.code } };
  }
  var live = got.live;
  if (platform === "amazon" && field === "stock" && got.fba) return { status: 409, body: { error: MESSAGES.amazonFba, code: "fba_stock" } };
  if (platform === "amazon" && !got.product_type) return { status: 409, body: { error: MESSAGES.resync, code: "no_product_type" } };
  if (field === "stock" && live.manage_stock !== true) return { status: 409, body: { error: MESSAGES.untracked, code: "untracked" } };
  var from = liveValue(field, live);
  if (field === "price" && from === null) return { status: 409, body: { error: MESSAGES.noPrice, code: "no_price" } };
  if (field === "stock" && (from === null || from < 0)) return { status: 409, body: { error: MESSAGES.negativeStock, code: "negative_stock" } };
  if (from === v.value) return { status: 400, body: { error: MESSAGES.same, code: "same", field: "to" } };

  var currency = typeof c.conn.currency === "string" && /^[A-Z]{3}$/.test(c.conn.currency) ? c.conn.currency : null;
  var name = cut(item.name || "Untitled", 200);
  var payload = {
    connection_id: c.conn.id, item_id: item.id, external_id: item.external_id, external_parent_id: item.external_parent_id || null,
    item_name: name, field: field, from: from, to: v.value, automatic: false,
    platform: platform, currency: currency
  };
  if (platform === "shopify") {
    payload.external_inventory_item_id = item.external_inventory_item_id || null;
    if (field === "stock") { payload.location_id = c.conn.location_id; payload.location_name = c.conn.location_name || null; }
  }
  // Etsy (migration 181): how many variations the one value applies to, and the note that says so.
  var groupNote = null;
  if (platform === "etsy") {
    payload.target_count = got.targets.indexes.length;
    groupNote = etsyGroupNote(field, got.targets.indexes.length, got.targets.every);
    payload.variations_note = groupNote;
  }
  // Amazon (migration 182): the marketplace, and whether Amazon fulfils the item (FBA).
  var fbaNote = null;
  if (platform === "amazon") {
    var market = AA.marketplaceOf(c.conn.marketplace_id);
    payload.marketplace_id = c.conn.marketplace_id;
    payload.marketplace = market ? market.code : null;
    payload.fba = got.fba === true;
    fbaNote = got.fba === true ? MESSAGES.amazonFbaPrice : null;
    payload.fba_note = fbaNote;
  }
  var title = cut("Change " + name + " " + field + " from " + shown(field, from) + " to " + shown(field, v.value), 200);
  var ins = await deps.supabase.from("agent_proposals").insert({
    user_id: userId, agent_type: "store", action_type: ACTION_TYPE, title: title, target: platform, payload: payload,
    cost_amount: 0, cost_currency: "USD", reversible: true, status: "pending", created_at: new Date(deps.now()).toISOString()
  }).select("*").single();
  if (ins.error) throw ins.error;
  var sale = live.sale_price !== null && Number(live.sale_price) > 0;
  var note = MESSAGES.filed + (field === "price" && sale ? " " + MESSAGES.sale : "");
  if (field === "price" && live.compare_at) note += " " + compareAtNote(live.compare_at, currency);
  if (groupNote) note += " " + groupNote;
  if (fbaNote) note += " " + fbaNote;
  return { status: 201, body: { proposal: ins.data, sale_running: sale, compare_at_price: field === "price" ? live.compare_at || null : null, note: note } };
}

function fail(message) { return new Error(message); }

/* The update_store_item executor. One argument, the claimed proposal; throws
   with the member's message on any failure. Trusts nothing stored: the
   connection and the item are read again, scoped by proposal.user_id, and must
   agree with the payload; the ranges and the cap are checked again; then the
   live compare-and-set, the one write, and the store's echo. A replay finds
   this proposal's log row and writes nothing. */
async function executeChange(deps, proposal) {
  var p = proposal || {};
  var ownerId = p.user_id;
  var pl = p.payload || {};
  if (FIELDS.indexOf(pl.field) === -1 || typeof pl.item_id !== "string" || !UUID_RE.test(pl.item_id) || typeof pl.external_id !== "string") {
    throw fail("This proposal does not name an item and a field. Nothing was changed.");
  }
  var field = pl.field;
  var v = validateChange(field, pl.to);
  if (!v.ok) throw fail(v.error);
  var from = field === "price" ? money2(pl.from) : int(pl.from);
  if (from === null) throw fail(MESSAGES.changed);

  var prior = await deps.supabase.from("store_change_log").select(LOG_COLUMNS).eq("proposal_id", p.id).eq("user_id", ownerId).limit(1);
  if (prior.error) throw fail("The change log could not be read, so nothing was changed.");
  if (prior.data && prior.data.length) {
    var done = prior.data[0];
    return { already_applied: true, already_published: true, change_id: done.id, field: done.field, executed_at: done.executed_at };
  }

  var c = await readWritableConnection(deps, ownerId, pl.connection_id);
  if (!c.ok) throw fail(c.error);
  var conn = c.conn;
  var platform = conn.platform;
  var item = await readItem(deps, ownerId, pl.item_id);
  if (!item || item.source !== platform || item.store_connection_id !== conn.id || item.external_id !== pl.external_id ||
      (item.external_parent_id || null) !== (pl.external_parent_id || null) ||
      (platform === "shopify" && (item.external_inventory_item_id || null) !== (pl.external_inventory_item_id || null))) {
    throw fail("This item is no longer the one that was proposed, so nothing was changed.");
  }
  // A Shopify stock change applies at the location it was proposed for, and only there.
  if (platform === "shopify" && field === "stock" && (!conn.location_id || conn.location_id !== pl.location_id)) throw fail(MESSAGES.changed);

  var count = await changesInLastDay(deps, conn.id);
  if (count === null) throw fail("Today's changes could not be counted, so nothing was changed.");
  if (count >= DAILY_CAP) throw fail(MESSAGES.cap);

  var stamp;
  var siblings = [];
  // Every platform but Amazon confirms before it returns; an Amazon change may be "submitted" (migration 182).
  var confirmation = "confirmed";
  if (platform === "shopify") {
    var s = SAPI.session(conn);
    var live = await readLiveShopifyItem(deps, s, field, item);
    if (!live.ok) {
      if (live.auth) await SS.markNeedsReconnect(deps.supabase, conn, live.code, new Date(deps.now()).toISOString());
      throw fail(live.error);
    }
    var check = compareLive(field, from, live.live);
    if (!check.ok) throw fail(check.error);
    var result = await writeShopifyItem(deps, s, field, item, from, v.value, p.id);
    if (!result.ok) {
      if (result.auth) await SS.markNeedsReconnect(deps.supabase, conn, String(result.code || "auth"), new Date(deps.now()).toISOString());
      throw fail(result.error);
    }
  } else if (platform === "etsy") {
    if (field === "stock" && v.value > EAPI.QUANTITY_MAX) throw fail(MESSAGES.etsyStock);
    var es = EAPI.session(conn);
    var etsyLive = await readLiveEtsyItem(deps, es, field, item);
    if (!etsyLive.ok) {
      if (etsyLive.auth) await SS.markNeedsReconnect(deps.supabase, conn, etsyLive.code, new Date(deps.now()).toISOString());
      throw fail(etsyLive.error);
    }
    var etsyCheck = compareLive(field, from, etsyLive.live);
    if (!etsyCheck.ok) throw fail(etsyCheck.error);
    // The one value must still apply to exactly the variations the proposal named.
    if (etsyLive.targets.indexes.length !== (Number.isInteger(pl.target_count) ? pl.target_count : 1)) throw fail(MESSAGES.changed);
    var etsySent = await writeEtsyItem(deps, es, item, etsyLive.inventory, etsyLive.targets.indexes, field, v.value);
    if (!etsySent.ok) {
      if (etsySent.auth) await SS.markNeedsReconnect(deps.supabase, conn, String(etsySent.code || "auth"), new Date(deps.now()).toISOString());
      throw fail(etsySent.error);
    }
    // The other variations the one value applies to, as BizForce holds them.
    siblings = etsyLive.targets.indexes.map(function (i) { return EAPI.identityOf(item.external_parent_id, etsyLive.inventory.products[i]); })
      .filter(function (id) { return id && id !== item.external_id; });
  } else if (platform === "amazon") {
    // The item must be in the connection's own marketplace, and the proposal must name it.
    if ((AAPI.skuOf(item.external_id) || {}).marketplaceId !== conn.marketplace_id || (pl.marketplace_id !== undefined && pl.marketplace_id !== conn.marketplace_id)) throw fail(MESSAGES.changed);
    var as = AAPI.session(conn);
    var amazonLive = await readLiveAmazonItem(deps, as, field, item);
    if (!amazonLive.ok) {
      if (amazonLive.auth) await SS.markNeedsReconnect(deps.supabase, conn, amazonLive.code, new Date(deps.now()).toISOString());
      throw fail(amazonLive.error);
    }
    if (field === "stock" && amazonLive.fba) throw fail(MESSAGES.amazonFba);
    if (!amazonLive.product_type) throw fail(MESSAGES.resync);
    var amazonCheck = compareLive(field, from, amazonLive.live);
    if (!amazonCheck.ok) throw fail(amazonCheck.error);
    var amazonCurrency = typeof conn.currency === "string" && /^[A-Z]{3}$/.test(conn.currency) ? conn.currency : amazonLive.offer_currency;
    if (field === "price" && !amazonCurrency) throw fail(MESSAGES.resync);
    var amazonSent = await writeAmazonItem(deps, as, item, field, amazonLive.product_type, amazonCurrency, v.value);
    if (!amazonSent.ok) {
      if (amazonSent.auth) await SS.markNeedsReconnect(deps.supabase, conn, String(amazonSent.code || "auth"), new Date(deps.now()).toISOString());
      throw fail(amazonSent.error);
    }
    confirmation = amazonSent.confirmation;
  } else if (platform === "woocommerce") {
    var creds;
    try { creds = SS.openCredentials(conn, deps.decrypt); } catch (e) {
      await SS.markNeedsReconnect(deps.supabase, conn, "credentials_unreadable", new Date(deps.now()).toISOString());
      throw fail(MESSAGES.notConnected);
    }
    var got = await readLiveWooItem(deps, conn, creds, item);
    if (!got.ok) {
      creds = null;
      if (got.auth) await SS.markNeedsReconnect(deps.supabase, conn, got.code, new Date(deps.now()).toISOString());
      throw fail(got.error);
    }
    var cas = compareLive(field, from, got.live);
    if (!cas.ok) { creds = null; throw fail(cas.error); }

    var wrote = await writeWooItem(deps, conn, creds, item, writeBody(field, v.value));
    creds = null;
    if (!wrote.ok) {
      if (wrote.auth) await SS.markNeedsReconnect(deps.supabase, conn, wrote.code, new Date(deps.now()).toISOString());
      throw fail(wrote.error);
    }
    if (!echoMatches(field, v.value, item, wrote.data)) throw fail(MESSAGES.unconfirmed);
  } else {
    throw fail(MESSAGES.notSynced);
  }

  stamp = new Date(deps.now()).toISOString();
  var patch = field === "price" ? { unit_price: Number(v.value) } : { quantity_on_hand: v.value };
  patch.synced_at = stamp; patch.updated_at = stamp;
  var up = await deps.supabase.from("inventory_items").update(patch).eq("id", item.id).eq("user_id", ownerId);
  if (up.error) console.error("[StoreWrite] the item row could not be updated after the change: " + (up.error.code || "error"));
  if (siblings.length) {
    var also = await deps.supabase.from("inventory_items").update(patch).eq("user_id", ownerId).eq("store_connection_id", conn.id).in("external_id", siblings);
    if (also.error) console.error("[StoreWrite] the other variations' rows could not be updated after the change: " + (also.error.code || "error"));
  }
  var currency = typeof conn.currency === "string" && /^[A-Z]{3}$/.test(conn.currency) ? conn.currency : null;
  var log = await deps.supabase.from("store_change_log").insert({
    user_id: ownerId, connection_id: conn.id, inventory_item_id: item.id, external_id: item.external_id, item_name: cut(item.name || "", 200),
    field: field, old_value: Number(from), new_value: Number(v.value), currency: currency,
    location_name: platform === "shopify" && field === "stock" ? cut(conn.location_name || "", 200) || null : null,
    proposal_id: p.id, executed_at: stamp, confirmation: confirmation
  }).select("id").single();
  if (log.error) throw fail("Your store was changed, but BizForce could not record the change (" + (log.error.code || "error") + "). Check the item in your store.");
  var outcome = { applied: true, change_id: log.data.id, item_name: cut(item.name || "", 200), field: field, from: from, to: v.value, currency: currency, executed_at: stamp,
    confirmation: confirmation };
  if (confirmation === "submitted") outcome.note = MESSAGES.amazonSubmitted;
  return outcome;
}

/* POST /api/store/changes/:id/undo: files a NEW proposal from the live value
   back to the change's old value, through proposeChange. Writes nothing to the store. */
async function undoChange(deps, userId, changeId) {
  if (typeof changeId !== "string" || !UUID_RE.test(changeId)) return { status: 404, body: { error: MESSAGES.gone, code: "not_found" } };
  var read = await deps.supabase.from("store_change_log").select(LOG_COLUMNS).eq("id", changeId).eq("user_id", userId).maybeSingle();
  if (read.error) throw read.error;
  var row = read.data;
  if (!row) return { status: 404, body: { error: MESSAGES.gone, code: "not_found" } };
  if (!row.inventory_item_id) return { status: 409, body: { error: MESSAGES.itemGone, code: "item_gone" } };
  var to = row.field === "price" ? Number(row.old_value).toFixed(2) : Math.trunc(Number(row.old_value));
  return proposeChange(deps, userId, { item_id: row.inventory_item_id, field: row.field, to: to });
}

/* GET /api/store/changes?before=: the member's own log, newest first, LOG_PAGE a page. */
async function listChanges(deps, userId, before) {
  var q = deps.supabase.from("store_change_log").select(LOG_COLUMNS).eq("user_id", userId);
  if (typeof before === "string" && before && !isNaN(Date.parse(before))) q = q.lt("executed_at", new Date(Date.parse(before)).toISOString());
  var read = await q.order("executed_at", { ascending: false }).limit(LOG_PAGE + 1);
  if (read.error) throw read.error;
  var rows = read.data || [];
  var page = rows.slice(0, LOG_PAGE).map(function (r) {
    return { id: r.id, connection_id: r.connection_id, item_id: r.inventory_item_id, item_name: r.item_name, field: r.field,
      old_value: r.field === "price" ? Number(r.old_value).toFixed(2) : Math.trunc(Number(r.old_value)),
      new_value: r.field === "price" ? Number(r.new_value).toFixed(2) : Math.trunc(Number(r.new_value)),
      currency: r.currency || null, location_name: r.location_name || null,
      executed_at: r.executed_at, confirmation: r.confirmation === "submitted" ? "submitted" : "confirmed" };
  });
  return { changes: page, has_more: rows.length > LOG_PAGE, next_before: rows.length > LOG_PAGE ? page[page.length - 1].executed_at : null };
}

module.exports = {
  ACTION_TYPE: ACTION_TYPE,
  FIELDS: FIELDS,
  PRICE_MIN: PRICE_MIN,
  VALUE_MAX: VALUE_MAX,
  DAILY_CAP: DAILY_CAP,
  LIVE_FIELDS: LIVE_FIELDS,
  WRITE_TIMEOUT_MS: WRITE_TIMEOUT_MS,
  WRITE_MAX_BYTES: WRITE_MAX_BYTES,
  LOG_PAGE: LOG_PAGE,
  MESSAGES: MESSAGES,
  compareAtNote: compareAtNote,
  money2: money2,
  liveMoney: liveMoney,
  int: int,
  validateChange: validateChange,
  itemPath: itemPath,
  shopifyIds: shopifyIds,
  compareLive: compareLive,
  readLiveWooItem: readLiveWooItem,
  readLiveShopifyItem: readLiveShopifyItem,
  readLiveEtsyItem: readLiveEtsyItem,
  writeWooItem: writeWooItem,
  writeShopifyItem: writeShopifyItem,
  writeEtsyItem: writeEtsyItem,
  readLiveAmazonItem: readLiveAmazonItem,
  writeAmazonItem: writeAmazonItem,
  etsyGroupNote: etsyGroupNote,
  addressable: addressable,
  echoMatches: echoMatches,
  writeBody: writeBody,
  changesInLastDay: changesInLastDay,
  proposeChange: proposeChange,
  executeChange: executeChange,
  undoChange: undoChange,
  listChanges: listChanges
};
