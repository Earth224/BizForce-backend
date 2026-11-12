/* checkShopifyConnect: Connect Shopify on OAuth (migration 176). The app install, expiring tokens with rotation, the
   HMAC-verified callback and webhooks, the GraphQL sync, and Shopify price and stock changes through approval.

   WHAT IT PROVES (lib/shopifyAuth.js, lib/shopifyApi.js, lib/storeWrite.js's Shopify half, the Connect Shopify, location
   and webhook routes in server.js, migration 176, the Store Agent page). Shopify is a stub behind the REAL guarded
   fetcher's JSON mode (lib/guardedFetch.js createGuardedFetch, with only its DNS answer and its https.request stood in):
   its OAuth token endpoint, its GraphQL Admin API answered by operation name, and its webhooks. The database is in
   memory and enforces migration 176's CHECKs and the one-shop-one-member index. A network tripwire fails the run if
   anything opens a socket, asks real DNS or fetches. Nothing here calls Shopify.

     S. START. requireAuth, requireActiveSubscription, 10 an hour; 503 without SHOPIFY_CLIENT_ID and
        SHOPIFY_CLIENT_SECRET; the shop normalized; 409 for a shop another member holds; the read scopes, plus
        write_products and write_inventory only when allow_changes is exactly true; the authorize URL exactly; the
        state stored only as its sha256, purpose store_shopify, with flow_context { shop, permission }, 10 minutes.
     F. FINISH. The HMAC (valid, tampered, missing, another secret; constant time), the timestamp edges, the shop
        the state was made for, the state consumed once (another member's, an expired one and a used one refused
        with the same answer and no reason), expiring: 1 in the exchange, a missing refresh token or expiry refused,
        scopes missing refused, extra scopes stored and never used, both tokens sealed before any GraphQL request, the
        row against the token_shape CHECK, one location chosen by itself, the currency stored, nothing logged.
     T. TOKENS. A token near its expiry is refreshed; the new access token and the new refresh token are saved in ONE
        compare-and-set update on token_version; the loser of a race writes nothing and uses the winner's token; one
        refresh per connection at a time; a refused refresh is needs_reconnect; a refresh token past its expiry is
        never sent; a 401 on a read refreshes once and asks once more, never again.
     Y. THE SYNC through GraphQL: query documents only, the variant, product and inventory item ids stored, tracked
        variants only, the chosen location's "available" versus the total, the page cap, THROTTLED waited out, a
        GraphQL error a failure that writes nothing.
     W. WRITES. Price: the live compare-and-set, the echo, compareAtPrice never written, the compare-at note. Stock:
        refused without a location, the live compare-and-set, changeFromQuantity and @idempotent keyed by the proposal
        id, the confirming read, no retry after a request was sent. Refused without permission read_write or without
        both write scopes.
     H. WEBHOOKS. 503 unconfigured; the HMAC over the raw body (express.raw); a bad HMAC refused; a repeat delivery
        does nothing; app/uninstalled and shop/redact remove the connection as disconnect does; the customer topics
        are recorded only; processed_at; receipts purged after 30 days.
     L. LOCATIONS: listed live, chosen from the list, a foreign one refused.
     P. THE PAGES: the lines word for word, the callback query POSTed whole and the address bar cleared with
        replaceState, the app-URL landing, textContent only, the currency shown.
     G. THE PASTED-TOKEN PATH is gone; the mailbox disconnect deletes only its own sign-in states; the legal and
        yourData text, README and the registries.

   MUTATIONS: MUTATE=<name> applies one in memory; MUTATE=all runs each in its own process. The 36 the brief named,
   then the ones the code earned (write-scopes-ignored, read-401-refresh-twice, refresh-not-single-flight,
   processed-not-marked, foreign-location-accepted, webhook-receipts-kept). */
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const crypto = require("crypto");
const Module = require("module");
const MUT = require("./_shared");
const { EventEmitter } = require("events");
const { PassThrough } = require("stream");

const REPO = path.join(__dirname, "..");
const FE = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const read = (f) => fs.readFileSync(path.join(REPO, f), "utf8");
const readFe = (f) => fs.readFileSync(path.join(FE, f), "utf8");

const MUTATIONS = {
  "callback-hmac-unchecked": ["server",
    "      if (!sa.callbackHmacValid(params, config.clientSecret)) return invalid();\n", ""],
  "callback-hmac-not-timing-safe": ["auth",
    "  var got = Buffer.from(given, \"hex\");\n  return got.length === want.length && crypto.timingSafeEqual(got, want);\n",
    "  return given === want.toString(\"hex\");\n"],
  "timestamp-unchecked": ["server",
    "      if (!sa.timestampFresh(params.timestamp, nowMs)) return invalid();\n", ""],
  "shop-mismatch-accepted": ["server",
    "if (!context || context.shop !== shop || ss.PERMISSIONS.indexOf(context.permission) === -1) return invalid();",
    "if (!context || ss.PERMISSIONS.indexOf(context.permission) === -1) return invalid();"],
  "state-reusable": ["server",
    "var consumed = await supabase.from(\"oauth_states\").update({ consumed_at: stampNow })",
    "var consumed = await supabase.from(\"oauth_states\").update({ consumed_at: null })"],
  "expiring-flag-missing": ["auth",
    "code: code, expiring: 1 }", "code: code }"],
  "refresh-token-optional": ["auth",
    "  if (typeof j.refresh_token !== \"string\" || !j.refresh_token) throw new ShopifyAuthError(\"no_access\", \"no_refresh_token\");\n", ""],
  "scope-missing-accepted": ["server",
    "      if (!sa.grantCovers(grant.scopes, sa.scopesFor(permission))) {\n", "      if (false) {\n"],
  "extra-scope-used": ["server",
    "        user_id: req.user.id, platform: \"shopify\", store_url: shop, status: \"connected\", permission: permission,\n",
    "        user_id: req.user.id, platform: \"shopify\", store_url: shop, status: \"connected\", permission: /write_products/.test(grantedScopes) && /write_inventory/.test(grantedScopes) ? \"read_write\" : permission,\n"],
  "token-logged": ["server",
    "      // Sealed first: both tokens are encrypted before Shopify's GraphQL API is asked anything.\n",
    "      console.log(\"[store/shopify/finish] granted \" + grant.accessToken + \" \" + grant.refreshToken);\n      // Sealed first: both tokens are encrypted before Shopify's GraphQL API is asked anything.\n"],
  "unsealed-before-graphql": ["server",
    "      // Sealed first: both tokens are encrypted before Shopify's GraphQL API is asked anything.\n",
    "      await api.readQuery(deps, shop, grant.accessToken, \"query ShopInfo { shop { currencyCode } locations(first: 50) { nodes { id name isActive } } }\", {});\n"],
  "refresh-cas-missing": ["api",
    "    .eq(\"id\", row.id).eq(\"platform\", \"shopify\").eq(\"token_version\", version).select(\"id\");",
    "    .eq(\"id\", row.id).eq(\"platform\", \"shopify\").select(\"id\");"],
  "refresh-pair-split": ["api",
    "    credentials_ciphertext: sealedRefresh.credentials_ciphertext, credentials_iv: sealedRefresh.credentials_iv, credentials_auth_tag: sealedRefresh.credentials_auth_tag,\n", ""],
  "refresh-forever": ["api",
    "  if (row.refresh_expires_at && !(Date.parse(row.refresh_expires_at) > nowMs)) throw new SS.StoreAuthError(\"refresh_expired\");\n", ""],
  "sync-sends-mutation": ["api",
    "    var data = await read(deps, s, location ? VARIANTS_AT_QUERY : VARIANTS_QUERY, location ? { cursor: cursor, location: location } : { cursor: cursor });\n",
    "    if (page === 0) await sendOnce(deps, s.row.store_url, await accessToken(deps, s, false), \"mutation Touch { productVariantsBulkUpdate(productId: \\\"gid://shopify/Product/1\\\", variants: []) { userErrors { field } } }\", {}, \"productVariantsBulkUpdate\");\n" +
    "    var data = await read(deps, s, location ? VARIANTS_AT_QUERY : VARIANTS_QUERY, location ? { cursor: cursor, location: location } : { cursor: cursor });\n"],
  "untracked-stored": ["api",
    "if (!variantId || !productId || !item || item.tracked !== true || !itemId) { out.skipped_untracked++; return; }",
    "if (!variantId || !productId || !item || !itemId) { out.skipped_untracked++; return; }"],
  "location-total-mislabelled": ["api",
    "        qty = availableOf(item.inventoryLevel);\n", "        qty = v.inventoryQuantity;\n"],
  "price-cas-skipped": ["write",
    "    var check = compareLive(field, from, live.live);\n    if (!check.ok) throw fail(check.error);\n", "    var check = compareLive(field, from, live.live);\n"],
  "compare-at-written": ["api",
    "variants: [{ id: variantGid, price: price }]", "variants: [{ id: variantGid, price: price, compareAtPrice: null }]"],
  "stock-without-location": ["write",
    "    if (!s.row.location_id) return { ok: false, code: \"no_location\", error: MESSAGES.noLocation };\n", ""],
  "change-from-missing": ["api",
    "quantity: to, changeFromQuantity: from }", "quantity: to }"],
  "idempotent-missing": ["api",
    " @idempotent(key: $key)", ""],
  "retry-after-send": ["write",
    "  if (!sent.ok) return { ok: false, auth: sent.code === \"auth\", code: sent.code, error: MESSAGES[SHOPIFY_OUTCOME[sent.code] || \"unconfirmed\"] };\n",
    "  if (!sent.ok && sent.sent) sent = field === \"price\" ? await SAPI.writePrice(deps, s, ids.product, ids.variant, money2(to)) : await SAPI.writeStock(deps, s, ids.item, s.row.location_id, int(from), int(to), proposalId);\n" +
    "  if (!sent.ok) return { ok: false, auth: sent.code === \"auth\", code: sent.code, error: MESSAGES[SHOPIFY_OUTCOME[sent.code] || \"unconfirmed\"] };\n"],
  "write-without-permission": ["write",
    "  if (SS.permissionOf(conn) !== \"read_write\") return { ok: false, status: 409, code: \"read_only\", error: MESSAGES.readOnly };\n", ""],
  "webhook-hmac-unchecked": ["server",
    "    if (!raw || !sa.webhookHmacValid(raw, req.get(\"X-Shopify-Hmac-Sha256\") || \"\", config.clientSecret)) {\n", "    if (!raw) {\n"],
  "webhook-parsed-json-hmac": ["server",
    "    var raw = Buffer.isBuffer(req.body) ? req.body : null;\n",
    "    var raw = Buffer.isBuffer(req.body) ? Buffer.from(JSON.stringify(JSON.parse(req.body.toString(\"utf8\"))), \"utf8\") : null;\n"],
  "webhook-dedupe-missing": ["server",
    "        if (before.data && before.data.processed_at) return res.status(200).json({ received: true, duplicate: true });\n", ""],
  "uninstall-ignored": ["server",
    "      if (topic === \"app/uninstalled\" || topic === \"shop/redact\") await removeShopifyShop(shop);\n",
    "      if (topic === \"shop/redact\") await removeShopifyShop(shop);\n"],
  "shop-redact-ignored": ["server",
    "      if (topic === \"app/uninstalled\" || topic === \"shop/redact\") await removeShopifyShop(shop);\n",
    "      if (topic === \"app/uninstalled\") await removeShopifyShop(shop);\n"],
  "second-member-same-shop": ["server",
    "      if ((held.data || []).some(function (r) { return r.user_id !== req.user.id; })) {\n", "      if (false) {\n"],
  "paste-token-accepted": ["server",
    "      if (body.platform === \"shopify\") {\n        return res.status(400).json({ error: require(\"./lib/shopifyAuth\").MESSAGES.useConnect, code: \"use_connect_shopify\", saved: false });\n      }\n", ""],
  "mailbox-disconnect-deletes-shopify-state": ["server",
    "var statesDropped = await supabase.from(\"oauth_states\").delete().eq(\"user_id\", req.user.id).eq(\"purpose\", \"mailbox_microsoft\");",
    "var statesDropped = await supabase.from(\"oauth_states\").delete().eq(\"user_id\", req.user.id);"],
  "unconfigured-not-503": ["server",
    "      var ss = require(\"./lib/storeSync\");\n      var config = sa.configured(process.env);\n      if (!config) return res.status(503).json({ error: sa.MESSAGES.notConfigured, code: \"not_configured\", saved: false });\n",
    "      var ss = require(\"./lib/storeSync\");\n      var config = sa.configured(process.env) || { clientId: \"\", clientSecret: \"\" };\n"],
  "replacestate-skipped": ["ui",
    "    }).then(function (res) {\n      stripQuery();\n", "    }).then(function (res) {\n"],
  // NAMED (Nov 8 2026, Etsy store connection, migration 181): BEFORE anchored on "...uninstall BizForce from Shopify, or delete
  // your account.". AFTER the sentence names Etsy's removal too, so the anchor is the line as it now reads; the stale text is the same.
  // NAMED (Nov 8 2026, Amazon store connection, migration 182): BEFORE anchored on "...remove it from your Etsy account, or delete
  // your account.". AFTER the sentence names Amazon Seller Central too, so the anchor is the line as it now reads; the stale text is the same.
  "privacy-sentence-stale": ["legal",
    "\"deleted when you disconnect the store, uninstall BizForce from Shopify, remove it from your Etsy account or Amazon Seller Central, or delete your account.\"",
    "\"deleted when you disconnect the store or delete your account.\""],
  "innerHTML-on-page": ["ui",
    "    if (text !== undefined) e.textContent = text;\n", "    if (text !== undefined) e.innerHTML = text;\n"],
  // the others the code earns
  "write-scopes-ignored": ["sync",
    "  if (row.platform === \"woocommerce\") return \"read_write\";\n", "  if (row.platform === \"woocommerce\" || row.platform === \"shopify\") return \"read_write\";\n"],
  "read-401-refresh-twice": ["api",
    "    if (!(err instanceof SS.StoreAuthError) || s.refreshed) throw err;\n", "    if (!(err instanceof SS.StoreAuthError)) throw err;\n"],
  "refresh-not-single-flight": ["api",
    "  var running = refreshesInFlight.get(key);\n", "  var running = null;\n"],
  "processed-not-marked": ["server",
    "      var processed = await supabase.from(\"shopify_webhook_events\").update({ processed_at: new Date().toISOString() }).eq(\"webhook_id\", webhookId);\n",
    "      var processed = { error: null };\n"],
  "foreign-location-accepted": ["server",
    "    if (!found) return res.status(400).json({ error: \"That location is not one of your store's active locations.\", code: \"location_unknown\", field: \"location_id\" });\n",
    "    if (!found) found = { id: wanted, name: \"Location\" };\n"],
  "webhook-receipts-kept": ["auth",
    "    var removed = await supabase.from(\"shopify_webhook_events\").delete().lt(\"received_at\", cutoff).select(\"id\");\n",
    "    var removed = await supabase.from(\"shopify_webhook_events\").delete().lt(\"received_at\", \"1970-01-01T00:00:00.000Z\").select(\"id\");\n"]
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
  server: read("server.js"),
  auth: read("lib/shopifyAuth.js"),
  api: read("lib/shopifyApi.js"),
  sync: read("lib/storeSync.js"),
  write: read("lib/storeWrite.js"),
  legal: read("lib/legalPages.js"),
  migration176: read("supabase/migrations/176_shopify_oauth.sql"),
  yourData: read("lib/yourData.js"),
  backup: read("lib/backup.js"),
  readme: read("README.md"),
  privacy: readFe("privacy.html"),
  page: readFe("store-agent.html"),
  ui: readFe("scripts/store-connect.js"),
  changesUi: readFe("scripts/store-changes.js")
};
if (MUTATE) {
  const m = MUTATIONS[MUTATE];
  FILES[m[0]] = MUT.replaceOnce(FILES[m[0]], m[1], m[2], MUTATE);
  console.log("\n!! MUTATION: " + MUTATE);
}

const J = JSON.stringify;
const SECRET_HEX = crypto.createHash("sha256").update("checkShopifyConnect").digest("hex");
process.env.ENCRYPTION_SECRET = SECRET_HEX;
const realRequire = Module.createRequire(path.join(REPO, "server.js"));
const CRYPT = realRequire("./lib/apiKeyCrypto");
const GF = realRequire("./lib/guardedFetch");
function compile(src, file, map) {
  const m = { exports: {} };
  const fn = vm.compileFunction(src, ["module", "exports", "require", "__dirname", "__filename"], { filename: path.join(REPO, file) });
  const localRequire = Module.createRequire(path.join(REPO, file));
  fn(m, m.exports, function (r) { return Object.prototype.hasOwnProperty.call(map, r) ? map[r] : localRequire(r); }, path.dirname(path.join(REPO, file)), path.join(REPO, file));
  return m.exports;
}
const SS = compile(FILES.sync, "lib/storeSync.js", {});
const SA = compile(FILES.auth, "lib/shopifyAuth.js", {});
const SAPI = compile(FILES.api, "lib/shopifyApi.js", { "./storeSync": SS, "./shopifyAuth": SA });
const SW = compile(FILES.write, "lib/storeWrite.js", { "./storeSync": SS, "./shopifyApi": SAPI });
const LP = compile(FILES.legal, "lib/legalPages.js", {});

const SHOPIFY_CONFIG = { clientId: "check-client-id", clientSecret: "check-client-secret-" + "7".repeat(20) };
const CONFIGURED = { SHOPIFY_CLIENT_ID: SHOPIFY_CONFIG.clientId, SHOPIFY_CLIENT_SECRET: SHOPIFY_CONFIG.clientSecret };
const USER = "00000000-0000-4000-8000-000000000001";
const OTHER = "00000000-0000-4000-8000-000000000002";
const SHOP = "demo-shop.myshopify.com";
const OTHER_SHOP = "other-shop.myshopify.com";
const TOKEN = "shpca_" + "a1b2c3d4".repeat(4);
const REFRESH = "shprt_" + "e5f6a7b8".repeat(4);
const TOKEN2 = "shpca_" + "c3d4e5f6".repeat(4);
const REFRESH2 = "shprt_" + "a7b8c9d0".repeat(4);
const WINNER = "shpca_" + "0f1e2d3c".repeat(4);
const CODE = "0123abcd".repeat(4);
const GRAPHQL_PATH = "/admin/api/2026-07/graphql.json";
const LOCATION = "gid://shopify/Location/71";
const LOCATION2 = "gid://shopify/Location/72";
const VARIANT = "gid://shopify/ProductVariant/11";
const PRODUCT = "gid://shopify/Product/1";
const ITEM = "gid://shopify/InventoryItem/9011";
const READ_SCOPES = "read_products,read_inventory,read_orders,read_locations";
const ALL_SCOPES = READ_SCOPES + ",write_products,write_inventory";
const NOW = Date.parse("2026-11-07T12:00:00.000Z");
const SECRETS = [TOKEN, REFRESH, TOKEN2, REFRESH2, CODE, SHOPIFY_CONFIG.clientSecret];
function noSecretIn(text) { return SECRETS.every(function (s) { return String(text).indexOf(s) === -1; }); }
const EMOJI = /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{1F000}-\u{1F2FF}\u{FE0F}]/u;

/* ── an in-memory database, with migration 176's CHECKs and indexes ───────── */
function uuid() { return crypto.randomUUID(); }
const HEX = /^[0-9a-f]+$/;
function makeDb() {
  const t = { member_store_connections: [], inventory_items: [], inventory_movements: [], store_order_summaries: [], store_change_log: [],
    notifications: [], job_runs: [], oauth_states: [], shopify_webhook_events: [], agent_proposals: [] };
  const log = [];
  function rows(name) { if (!t[name]) t[name] = []; return t[name]; }
  function uniqueViolation(name, row, except) {
    const others = rows(name).filter(function (r) { return r !== except; });
    if (name === "inventory_items") {
      if (row.sku && others.some(function (r) { return r.user_id === row.user_id && r.sku && String(r.sku).toLowerCase() === String(row.sku).toLowerCase(); })) return "inventory_items_user_sku_uniq";
      if (row.store_connection_id && others.some(function (r) { return r.store_connection_id === row.store_connection_id && r.external_id === row.external_id; })) return "inventory_items_store_external_unique";
    }
    if (name === "member_store_connections") {
      if (others.some(function (r) { return r.user_id === row.user_id && r.platform === row.platform && r.store_url === row.store_url; })) return "member_store_connections_unique";
      // member_store_connections_shopify_shop_key: one shop, one member
      if (row.platform === "shopify" && others.some(function (r) { return r.platform === "shopify" && String(r.store_url).toLowerCase() === String(row.store_url).toLowerCase(); })) return "member_store_connections_shopify_shop_key";
    }
    if (name === "store_order_summaries" && others.some(function (r) { return r.connection_id === row.connection_id && r.external_id === row.external_id; })) return "store_order_summaries_unique";
    if (name === "job_runs" && others.some(function (r) { return r.job_name === row.job_name; })) return "job_runs_pkey";
    if (name === "shopify_webhook_events" && others.some(function (r) { return r.webhook_id === row.webhook_id; })) return "shopify_webhook_events_webhook_id_key";
    if (name === "store_change_log" && row.proposal_id && others.some(function (r) { return r.proposal_id === row.proposal_id; })) return "store_change_log_proposal_key";
    return null;
  }
  function checkViolation(name, row) {
    if (name === "member_store_connections") {
      if (!HEX.test(row.credentials_ciphertext || "") || !/^[0-9a-f]{24}$/.test(row.credentials_iv || "") || !/^[0-9a-f]{32}$/.test(row.credentials_auth_tag || "")) return "member_store_connections_ciphertext_check";
      if (row.access_ciphertext != null && !HEX.test(row.access_ciphertext)) return "member_store_connections_access_ciphertext_check";
      if (row.access_iv != null && !/^[0-9a-f]{24}$/.test(row.access_iv)) return "member_store_connections_access_iv_check";
      if (row.access_auth_tag != null && !/^[0-9a-f]{32}$/.test(row.access_auth_tag)) return "member_store_connections_access_tag_check";
      if (!(Number.isInteger(row.token_version) && row.token_version >= 0)) return "member_store_connections_token_version_check";
      if (row.granted_scopes != null && !(String(row.granted_scopes).length <= 500 && /^[a-z_,]*$/.test(row.granted_scopes))) return "member_store_connections_scopes_check";
      if (row.location_id != null && !/^gid:\/\/shopify\/Location\/[0-9]+$/.test(row.location_id)) return "member_store_connections_location_id_check";
      if (row.location_name != null && String(row.location_name).length > 200) return "member_store_connections_location_name_check";
      if (row.currency != null && !/^[A-Z]{3}$/.test(row.currency)) return "member_store_connections_currency_check";
      const access = row.access_ciphertext != null && row.access_iv != null && row.access_auth_tag != null && row.access_expires_at != null;
      const none = row.access_ciphertext == null && row.access_iv == null && row.access_auth_tag == null && row.access_expires_at == null &&
        row.refresh_expires_at == null && row.location_id == null && row.location_name == null;
      if (!((row.platform === "shopify" && access) || (row.platform === "woocommerce" && none))) return "member_store_connections_token_shape_check";
    }
    if (name === "inventory_items") {
      const manual = row.source == null && row.store_connection_id == null && row.external_id == null;
      const synced = (row.source === "shopify" || row.source === "woocommerce") && row.store_connection_id && row.external_id;
      if (!manual && !synced) return "inventory_items_source_check";
      if (row.external_inventory_item_id != null && !/^[0-9]{1,100}$/.test(row.external_inventory_item_id)) return "inventory_items_external_inventory_item_id_check";
    }
    if (name === "store_order_summaries" && !Array.isArray(row.line_items)) return "store_order_summaries_line_items_check";
    // NAMED (Nov 11 2026, orbit stage 2, migration 183): an order's status is active, cancelled or refunded (absent: the default, active).
    if (name === "store_order_summaries" && row.status !== undefined && ["active", "cancelled", "refunded"].indexOf(row.status) === -1) return "store_order_summaries_status_check";
    if (name === "store_change_log") {
      if (row.currency != null && !/^[A-Z]{3}$/.test(row.currency)) return "store_change_log_currency_check";
      if (row.location_name != null && String(row.location_name).length > 200) return "store_change_log_location_name_check";
    }
    if (name === "oauth_states") {
      if (["mailbox_microsoft", "store_shopify"].indexOf(row.purpose) === -1) return "oauth_states_purpose_check";
      if (row.purpose === "mailbox_microsoft" && (row.verifier_ciphertext == null || row.verifier_iv == null || row.verifier_auth_tag == null)) return "oauth_states_verifier_shape_check";
      if ((row.purpose === "store_shopify") !== (row.flow_context != null)) return "oauth_states_context_check";
      if (row.flow_context != null && Buffer.byteLength(J(row.flow_context)) > 1000) return "oauth_states_context_check";
    }
    if (name === "shopify_webhook_events") {
      if (!(String(row.webhook_id || "").length >= 1 && String(row.webhook_id).length <= 200)) return "shopify_webhook_events_id_check";
      if (["app/uninstalled", "customers/data_request", "customers/redact", "shop/redact"].indexOf(row.topic) === -1) return "shopify_webhook_events_topic_check";
      if (!(String(row.shop_domain || "").length >= 4 && String(row.shop_domain).length <= 253)) return "shopify_webhook_events_shop_check";
    }
    return null;
  }
  function defaults(name, row) {
    const now = new Date().toISOString();
    const r = Object.assign({ id: uuid(), created_at: now }, row);
    if (name === "member_store_connections") {
      if (r.status === undefined) r.status = "connected";
      if (r.token_version === undefined) r.token_version = 0;
      ["access_ciphertext", "access_iv", "access_auth_tag", "access_expires_at", "refresh_expires_at", "granted_scopes", "location_id", "location_name", "currency"].forEach(function (k) { if (r[k] === undefined) r[k] = null; });
    }
    if (name === "inventory_items") { if (r.status === undefined) r.status = "active"; if (r.unit === undefined) r.unit = "unit"; ["source", "store_connection_id", "external_id", "external_parent_id", "external_inventory_item_id", "reorder_point", "unit_cost"].forEach(function (k) { if (r[k] === undefined) r[k] = null; }); }
    if (name === "oauth_states" && r.consumed_at === undefined) r.consumed_at = null;
    if (name === "shopify_webhook_events") { if (r.received_at === undefined) r.received_at = now; if (r.processed_at === undefined) r.processed_at = null; }
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
      is: function (c, v) { q.filters.push(["is", c, v]); return api; },
      gt: function (c, v) { q.filters.push(["gt", c, v]); return api; },
      gte: function (c, v) { q.filters.push(["gte", c, v]); return api; },
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
        if (f[0] === "gte") return r[f[1]] != null && String(r[f[1]]) >= String(f[2]);
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
      log.push({ table: name, op: q.op, payload: q.payload });
      const all = rows(name);
      if (q.op === "select") {
        let hit = all.filter(match);
        const total = hit.length;
        if (q.range) hit = hit.slice(q.range[0], q.range[1] + 1);
        const out = q.head ? { data: null, error: null } : shape(hit);
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
          const c = checkViolation(name, next); if (c) return { data: null, error: { code: "23514", message: c } };
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

/* ── Shopify, stubbed behind the real guarded fetcher ───────────────────── */
function reply(status, body, hdrs) {
  const h = { "content-type": "application/json; charset=utf-8" };
  Object.keys(hdrs || {}).forEach(function (k) { h[k.toLowerCase()] = String(hdrs[k]); });
  return { status: status, headers: h, raw: Buffer.from(JSON.stringify(body), "utf8") };
}
function headerOf(hdrs, name) {
  const k = Object.keys(hdrs || {}).filter(function (x) { return x.toLowerCase() === name.toLowerCase(); })[0];
  return k ? String(hdrs[k]) : null;
}
const PUBLIC_V4 = "93.184.216.34";
function makeShop(opts, events) {
  const o = Object.assign({}, opts || {});
  const ev = events || [];
  const state = { available: o.available === undefined ? 4 : o.available, price: o.price || "25.00", compareAt: o.compareAt || null, throttled: {}, moved: false };
  const calls = [];   // requests that reached the shop
  const asked = [];   // every deps.jsonRequest call
  function variant(id, productId, title, sku, price, total, itemId, tracked, atLocation) {
    return { id: "gid://shopify/ProductVariant/" + id, sku: sku, title: title, price: price, compareAtPrice: null, inventoryQuantity: total,
      product: { id: "gid://shopify/Product/" + productId, title: "Wool Hat" },
      inventoryItem: { id: "gid://shopify/InventoryItem/" + itemId, tracked: tracked, unitCost: { amount: "10.00" },
        inventoryLevel: atLocation === null ? null : { quantities: [{ name: "available", quantity: atLocation }] } } };
  }
  function graphql(op, vars) {
    if (o.opStatus && o.opStatus[op]) return reply(o.opStatus[op], { errors: "Internal error" });
    if (o.opDown && o.opDown[op]) return { error: Object.assign(new Error("socket hang up"), { code: "ECONNRESET" }) };
    if (o.throttleOnce && o.throttleOnce[op] && !state.throttled[op]) {
      state.throttled[op] = true;
      return reply(200, { errors: [{ message: "Throttled", extensions: { code: "THROTTLED" } }] });
    }
    if (o.gqlError && o.gqlError[op]) return reply(200, { errors: [{ message: "Field 'nope' doesn't exist on type 'Query'" }] });
    if (op === "ShopInfo") {
      return reply(200, { data: { shop: { currencyCode: o.currency === undefined ? "CAD" : o.currency },
        locations: { nodes: o.locations || [{ id: LOCATION, name: "Main warehouse", isActive: true }] } } });
    }
    if (op === "Variants" || op === "VariantsAt") {
      if (o.endless) {
        const n = Number(String(vars.cursor || "e0").slice(1));
        return reply(200, { data: { productVariants: { pageInfo: { hasNextPage: true, endCursor: "e" + (n + 1) },
          nodes: [variant(5000 + n, 1000 + n, "Default Title", "", "1.00", 1, 7000 + n, false, null)] } } });
      }
      if (vars.cursor === "c2") {
        return reply(200, { data: { productVariants: { pageInfo: { hasNextPage: false, endCursor: "c3" },
          nodes: [variant(21, 2, "Green", "HAT-GREEN", "25.00", 6, 9021, true, null)] } } });
      }
      return reply(200, { data: { productVariants: { pageInfo: { hasNextPage: true, endCursor: "c2" }, nodes: [
        variant(11, 1, "Red", "HAT-RED", "25.00", 10, 9011, true, 4),
        variant(12, 1, "Blue", "HAT-BLUE", "25.00", 7, 9012, false, 7)] } } });
    }
    if (op === "Orders") {
      return reply(200, { data: { orders: { pageInfo: { hasNextPage: false, endCursor: "o2" }, nodes: [{ id: "gid://shopify/Order/5001", createdAt: "2026-11-06T10:00:00Z",
        email: "buyer@example.com", customer: { email: "buyer@example.com", firstName: "Jane" },
        totalPriceSet: { shopMoney: { amount: "50.00", currencyCode: "CAD" } }, lineItems: { nodes: [{ sku: "HAT-RED", quantity: 2, name: "Wool Hat - Red" }] } }] } } });
    }
    if (op === "LiveVariant") {
      if (vars.id !== VARIANT) return reply(200, { data: { productVariant: null } });
      return reply(200, { data: { productVariant: { id: VARIANT, price: state.price, compareAtPrice: state.compareAt, product: { id: PRODUCT },
        inventoryItem: { id: ITEM, tracked: true } } } });
    }
    if (op === "LiveLevel") {
      return reply(200, { data: { inventoryItem: { id: vars.item, tracked: !o.untracked,
        inventoryLevel: vars.location === LOCATION ? { quantities: [{ name: "available", quantity: state.available }] } : null } } });
    }
    if (op === "PriceSet") {
      const v = (vars.variants || [])[0] || {};
      if (o.priceUserError) return reply(200, { data: { productVariantsBulkUpdate: { productVariants: null, userErrors: [{ field: ["variants", "0", "price"], message: "Price is invalid" }] } } });
      if (o.priceEcho === "wrong") return reply(200, { data: { productVariantsBulkUpdate: { productVariants: [{ id: v.id, price: "0.01" }], userErrors: [] } } });
      state.price = v.price;
      return reply(200, { data: { productVariantsBulkUpdate: { productVariants: [{ id: v.id, price: state.price }], userErrors: [] } } });
    }
    if (op === "StockSet") {
      const q = ((vars.input || {}).quantities || [])[0] || {};
      if (o.moveBeforeStockSet && !state.moved) { state.moved = true; state.available += 1; }
      if (q.changeFromQuantity !== state.available) {
        return reply(200, { data: { inventorySetQuantities: { inventoryAdjustmentGroup: null,
          userErrors: [{ field: ["input", "quantities", "0", "changeFromQuantity"], message: "The quantity changed", code: "CHANGE_FROM_QUANTITY_STALE" }] } } });
      }
      state.available = q.quantity;
      return reply(200, { data: { inventorySetQuantities: { inventoryAdjustmentGroup: { id: "gid://shopify/InventoryAdjustmentGroup/1" }, userErrors: [] } } });
    }
    return reply(200, { errors: [{ message: "no stub for " + op }] });
  }
  function answer(url, init) {
    let body = null;
    try { body = init && init.body ? JSON.parse(String(init.body)) : null; } catch (e) { body = null; }
    const opMatch = body && typeof body.query === "string" ? /^(query|mutation)\s+([A-Za-z]+)/.exec(body.query) : null;
    const u = new URL(url);
    const token = headerOf(init && init.headers, "X-Shopify-Access-Token");
    calls.push({ url: url, host: u.hostname, path: u.pathname, method: (init && init.method) || "GET", body: body, op: opMatch ? opMatch[2] : null, kind: opMatch ? opMatch[1] : null, token: token });
    if (u.hostname !== SHOP && u.hostname !== OTHER_SHOP) return reply(404, { error: "no such host" });
    if (u.pathname === "/admin/oauth/access_token" && init.method === "POST") {
      if (body && body.grant_type === "refresh_token") {
        ev.push("token:refresh");
        if (typeof o.onRefresh === "function") o.onRefresh(body);
        if (o.refresh === "refuse") return reply(400, { error: "invalid_request", error_description: "refresh token expired or revoked" });
        if (o.refresh === "down") return reply(503, { error: "unavailable" });
        return reply(200, { access_token: TOKEN2, refresh_token: REFRESH2, expires_in: 3600, refresh_token_expires_in: 7776000, scope: o.scope || READ_SCOPES });
      }
      ev.push("token:exchange");
      if (o.exchangeStatus) return reply(o.exchangeStatus, { error: "invalid_request" });
      const grant = { access_token: TOKEN, refresh_token: REFRESH, expires_in: 3600, refresh_token_expires_in: 7776000, scope: o.scope || READ_SCOPES };
      (o.grantOmit || []).forEach(function (k) { delete grant[k]; });
      return reply(200, grant);
    }
    if (u.pathname === GRAPHQL_PATH && init.method === "POST" && opMatch) {
      ev.push("graphql:" + opMatch[2]);
      if (o.reject && o.reject.indexOf(token) !== -1) return reply(401, { errors: "[API] Invalid API key or access token (unrecognized login or wrong password)" });
      return graphql(opMatch[2], (body && body.variables) || {});
    }
    return reply(404, { error: "no stub for " + u.pathname });
  }
  function resolve(hostname, lookupOptions, cb) { return cb(null, [{ address: PUBLIC_V4, family: 4 }]); }
  function transport(options) {
    const req = new EventEmitter();
    req.destroy = function () {};
    req.end = function (payload) {
      process.nextTick(function () {
        options.lookup(options.hostname, { all: true }, function (err) {
          if (err) return req.emit("error", err);
          const r = answer("https://" + options.hostname + options.path, { method: options.method, headers: options.headers, body: payload ? Buffer.from(payload).toString("utf8") : null });
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
  function ops(name) { return calls.filter(function (c) { return c.path === GRAPHQL_PATH && (!name || c.op === name); }); }
  function tokenCalls(kind) { return calls.filter(function (c) { return c.path === "/admin/oauth/access_token" && (!kind || (kind === "refresh") === !!(c.body && c.body.grant_type === "refresh_token")); }); }
  return { jsonRequest: jsonRequest, calls: calls, asked: asked, state: state, opts: o, ops: ops, tokenCalls: tokenCalls };
}

/* THE NETWORK TRIPWIRE: no socket, no real DNS question, no fetch, in this whole run. */
const TRIPPED = [];
(function tripwire() {
  const http = require("http"), https = require("https"), net = require("net"), tls = require("tls"), dns = require("dns");
  function wire(obj, name, label) {
    obj[name] = function () { TRIPPED.push(label); throw new Error("checkShopifyConnect: " + label + " is not allowed in this check"); };
  }
  wire(http, "request", "http.request"); wire(http, "get", "http.get");
  wire(https, "request", "https.request"); wire(https, "get", "https.get");
  wire(net, "connect", "net.connect"); wire(net, "createConnection", "net.createConnection");
  wire(tls, "connect", "tls.connect");
  wire(dns, "lookup", "dns.lookup"); wire(dns, "resolve", "dns.resolve"); wire(dns.promises, "lookup", "dns.promises.lookup");
  globalThis.fetch = function () { TRIPPED.push("fetch"); return Promise.reject(new Error("checkShopifyConnect: fetch is not allowed in this check")); };
})();

/* ── the routes, run from server.js's own source ─────────────────────────── */
function sliceOf(src, start, end) {
  const a = src.indexOf(start), b = src.indexOf(end, a);
  return a === -1 || b === -1 ? "" : src.slice(a, b);
}
const STORE_SECTION = sliceOf(FILES.server, "/* ── Store connections (migrations 163, 175, 176; lib/storeSync.js) ──────────",
  "// The SEO writer used to answer in JSON, which meant embedding a whole HTML");
const WEBHOOK_SECTION = sliceOf(FILES.server, "/* ── Shopify webhooks (migration 176, lib/shopifyAuth.js) ────────────────",
  "app.use(express.json({ limit: \"5mb\" }));");
function requireAuth() {} function requireActiveSubscription() {}
function mountRoutes(env) {
  env = env || {};
  const db = env.db || makeDb();
  const events = [];
  const shop = makeShop(env.shop, events);
  const logs = [];
  const routes = {};
  const crypt = {
    encrypt: function (p) {
      events.push(p === TOKEN ? "encrypt:access" : (String(p).indexOf(REFRESH) !== -1 ? "encrypt:refresh" : "encrypt:other"));
      return CRYPT.encrypt(p);
    },
    decrypt: function (x) { return CRYPT.decrypt(x); }
  };
  const ctx = {
    supabase: db,
    process: { env: Object.assign({ ENCRYPTION_SECRET: SECRET_HEX }, env.env || {}) },
    console: { log: function () { logs.push([].slice.call(arguments).join(" ")); }, error: function () { logs.push([].slice.call(arguments).join(" ")); }, warn: function () { logs.push([].slice.call(arguments).join(" ")); } },
    rateLimit: function (o) { return { limiter: o }; },
    express: { raw: function (o) { return { raw: o }; }, json: function (o) { return { json: o }; } },
    requireAuth: requireAuth, requireActiveSubscription: requireActiveSubscription,
    nowIso: function () { return new Date().toISOString(); },
    isValidUuid: function (v) { return /^[0-9a-f-]{36}$/.test(String(v)); },
    getUserPlan: async function () { return { active: true }; },
    FRONTEND_URL: "https://bizforceai.net",
    fetch: globalThis.fetch,
    setTimeout: function (fn) { fn(); return 0; },
    Promise: Promise, Buffer: Buffer, URL: URL, Date: Date, JSON: JSON, Object: Object, Array: Array, String: String, Number: Number, Math: Math,
    require: function (r) {
      if (r === "./lib/storeSync") return SS;
      if (r === "./lib/apiKeyCrypto") return crypt;
      if (r === "./lib/guardedFetch") return Object.assign({}, GF, { guardedJsonRequest: shop.jsonRequest });
      if (r === "./lib/shopifyApi") return SAPI;
      if (r === "./lib/shopifyAuth") return SA;
      if (r === "./lib/storeWrite") return SW;
      return realRequire(r);
    },
    app: {}
  };
  ["get", "post", "put", "delete"].forEach(function (m) {
    ctx.app[m] = function (p) { const args = [].slice.call(arguments, 1); routes[m + " " + p] = { middleware: args.slice(0, -1), handler: args[args.length - 1] }; };
  });
  if (ctx.process.env.ENCRYPTION_SECRET === null) delete ctx.process.env.ENCRYPTION_SECRET;
  vm.createContext(ctx);
  vm.runInContext(WEBHOOK_SECTION, ctx, { filename: "server.js (Shopify webhooks)" });
  vm.runInContext(STORE_SECTION, ctx, { filename: "server.js (store section)" });
  return { db: db, shop: shop, logs: logs, routes: routes, events: events, ctx: ctx };
}
async function hit(m, key, req) {
  const r = m.routes[key];
  const res = { statusCode: 200, body: undefined, headers: {}, set: function (k, v) { this.headers[k] = v; return this; },
    status: function (c) { this.statusCode = c; return this; }, json: function (b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
  let err = null;
  try { await r.handler(Object.assign({ user: { id: USER }, body: {}, params: {} }, req), res, function (e) { err = e || new Error("next"); }); }
  catch (e) { err = e; res.statusCode = 599; }
  return { status: res.statusCode, body: res.body || {}, headers: res.headers, err: err };
}
function sign(params, secret) {
  const message = Object.keys(params).filter(function (k) { return k !== "hmac"; }).sort().map(function (k) { return k + "=" + params[k]; }).join("&");
  return crypto.createHmac("sha256", secret).update(message, "utf8").digest("hex");
}
async function begin(m, body) {
  const r = await hit(m, "post /api/store/shopify/start", { body: Object.assign({ shop: SHOP }, body || {}) });
  const url = r.body && r.body.authorize_url ? new URL(r.body.authorize_url) : null;
  return { r: r, url: url, state: url ? url.searchParams.get("state") : null };
}
function callback(state, over, secret) {
  const p = Object.assign({ code: CODE, host: "ZGVtby1zaG9wLm15c2hvcGlmeS5jb20vYWRtaW4", shop: SHOP, state: state, timestamp: String(Math.floor(Date.now() / 1000)) }, over || {});
  p.hmac = sign(p, secret || SHOPIFY_CONFIG.clientSecret);
  return p;
}
function finish(m, params) { return hit(m, "post /api/store/shopify/finish", { body: { params: params } }); }
function webhook(m, topic, body, opts) {
  opts = opts || {};
  const raw = Buffer.from(body, "utf8");
  const h = {
    "X-Shopify-Topic": topic, "X-Shopify-Shop-Domain": opts.shop || SHOP, "X-Shopify-Webhook-Id": opts.id || uuid(),
    "X-Shopify-Hmac-Sha256": opts.hmac !== undefined ? opts.hmac : crypto.createHmac("sha256", opts.secret || SHOPIFY_CONFIG.clientSecret).update(opts.signed ? Buffer.from(opts.signed, "utf8") : raw).digest("base64")
  };
  if (opts.hmac === null) delete h["X-Shopify-Hmac-Sha256"];
  return hit(m, "post /api/webhooks/shopify", { body: raw, get: function (n) { return headerOf(h, n); } });
}
const INVALID = { error: "That Shopify connection link has expired or was already used. Start again.", code: "state_invalid", saved: false };

/* lib-level deps */
function libDeps(db, shop, extra) {
  const sleeps = [];
  return Object.assign({
    supabase: db, env: {}, jsonRequest: shop.jsonRequest, now: function () { return NOW; },
    sleep: function (ms) { sleeps.push(ms); return Promise.resolve(); }, sleeps: sleeps,
    encrypt: CRYPT.encrypt, decrypt: CRYPT.decrypt,
    shopifyReader: SAPI, shopifyConfig: function () { return SHOPIFY_CONFIG; },
    userPlan: async function () { return { plan: { active: true }, error: null }; }
  }, extra || {});
}
function shopifyConn(db, over) {
  const sealed = SS.sealCredentials({ refresh_token: REFRESH }, CRYPT.encrypt);
  const access = CRYPT.encrypt(TOKEN);
  const row = Object.assign({ id: uuid(), user_id: USER, platform: "shopify", store_url: SHOP, status: "connected", permission: "read",
    access_ciphertext: access.ciphertext, access_iv: access.iv, access_auth_tag: access.authTag,
    access_expires_at: new Date(NOW + 50 * 60 * 1000).toISOString(), refresh_expires_at: new Date(NOW + 90 * 86400000).toISOString(), token_version: 0,
    granted_scopes: READ_SCOPES, location_id: null, location_name: null, currency: null, created_at: "2026-11-01T00:00:00.000Z" }, sealed, over || {});
  db.t.member_store_connections.push(row);
  return row;
}
function writableConn(db, over) {
  return shopifyConn(db, Object.assign({ permission: "read_write", granted_scopes: ALL_SCOPES, location_id: LOCATION, location_name: "Main warehouse", currency: "CAD" }, over || {}));
}
function shopifyItem(db, conn, over) {
  const row = Object.assign({ id: uuid(), user_id: conn.user_id, name: "Wool Hat - Red", source: "shopify", store_connection_id: conn.id, external_id: "variant:11",
    external_parent_id: "1", external_inventory_item_id: "9011", unit_price: 25, quantity_on_hand: 4, sku: "HAT-RED", status: "active" }, over || {});
  db.t.inventory_items.push(row);
  return row;
}
function accessOf(row) { try { return CRYPT.decrypt({ ciphertext: row.access_ciphertext, iv: row.access_iv, authTag: row.access_auth_tag }); } catch (e) { return null; } }
function refreshOf(row) { try { return SS.openCredentials(row, CRYPT.decrypt).refresh_token; } catch (e) { return null; } }
async function attempt(p) { try { return { ok: true, v: await p }; } catch (e) { return { ok: false, msg: e && e.message, name: e && e.name, code: e && e.code }; } }
function updatesOf(db, table) { return db.log.filter(function (l) { return l.table === table && l.op === "update"; }).length; }
function stripComments(src) { return String(src).replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, ""); }
function fnBody(src, name) {
  const a = src.search(new RegExp("^(?:async )?function " + name + "\\(", "m"));
  if (a === -1) return "";
  const b = src.indexOf("\n}\n", a);
  return src.slice(a, b === -1 ? src.length : b + 2);
}

/* ── the Store Agent page in a fake DOM ──────────────────────────────────── */
const API = "https://dynamic-prosperity-production-5382.up.railway.app";
const CONN_VIEW = { id: "11111111-1111-4111-8111-111111111111", platform: "shopify", platform_label: "Shopify", store: SHOP, status: "connected", permission: "read_write",
  currency: "CAD", location_id: LOCATION, location_name: "Main warehouse", stock_scope: "location", connected_since: "2026-11-07T10:00:00Z", last_sync_at: null, last_error_code: null };
function runPage(search, answers) {
  const dom = { els: {}, fetches: [], events: [], innerHTML: [], assigned: [] };
  function node(tag) {
    const n = { tagName: tag, children: [], _t: "", className: "", hidden: false, disabled: false, value: "", checked: false, type: "", id: "", attrs: {}, listeners: {}, selected: false,
      appendChild: function (c) { this.children.push(c); return c; },
      setAttribute: function (k, v) { this.attrs[k] = String(v); },
      addEventListener: function (t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); },
      click: function () { (this.listeners.click || []).forEach(function (f) { f({}); }); } };
    Object.defineProperty(n, "textContent", { get: function () { return this._t + this.children.map(function (c) { return c.textContent; }).join(""); },
      set: function (v) { this._t = String(v); this.children = []; } });
    Object.defineProperty(n, "innerHTML", { get: function () { return this._t; }, set: function (v) { dom.innerHTML.push(String(v)); this._t = String(v); this.children = []; } });
    return n;
  }
  const document = { readyState: "complete", addEventListener: function () {},
    getElementById: function (id) { if (!dom.els[id]) { dom.els[id] = node("div"); dom.els[id].id = id; } return dom.els[id]; },
    createElement: node, createTextNode: function (t) { return { textContent: String(t), children: [] }; } };
  dom.get = function (id) { return document.getElementById(id); };
  const location = { search: search, assign: function (u) { dom.assigned.push(u); } };
  Object.defineProperty(location, "href", { set: function (u) { dom.assigned.push(u); }, get: function () { return "https://bizforceai.net/store-agent.html" + search; } });
  const window = { location: location, history: { replaceState: function (s, t, u) { dom.events.push("replaceState:" + u); } } };
  function fetch(url, init) {
    const p = String(url).replace(API, "");
    const method = (init && init.method) || "GET";
    dom.fetches.push({ path: p, method: method, body: init && init.body ? JSON.parse(init.body) : undefined });
    dom.events.push("fetch:" + method + " " + p);
    const a = answers(p, method);
    if (a === "reject") return Promise.reject(new Error("offline"));
    return Promise.resolve({ ok: a.status < 300, status: a.status, json: function () { return Promise.resolve(a.body); } });
  }
  const ctx = { window: window, document: document, localStorage: { getItem: function () { return "tok"; } }, fetch: fetch, URLSearchParams: URLSearchParams,
    console: { log: function () {}, error: function () {}, warn: function () {} }, Promise: Promise, JSON: JSON, String: String, Array: Array, Date: Date };
  vm.createContext(ctx);
  vm.runInContext(FILES.ui, ctx, { filename: "scripts/store-connect.js" });
  return dom;
}
async function flush() { for (let i = 0; i < 40; i++) await new Promise(function (r) { setImmediate(r); }); }
function listAnswers(over) {
  return function (p, method) {
    if (over && over[method + " " + p] !== undefined) return over[method + " " + p];
    if (p === "/api/store/connections" && method === "GET") return { status: 200, body: { connections: [CONN_VIEW], note: "", shopify_available: true } };
    if (p === "/api/store/shopify/start") return { status: 200, body: { authorize_url: "https://" + SHOP + "/admin/oauth/authorize?client_id=x", permission: "read", saved: false } };
    if (p === "/api/store/shopify/finish") return { status: 200, body: { saved: true, connection: CONN_VIEW, locations: 1 } };
    return { status: 404, body: { error: "Not found" } };
  };
}

(async function main() {
  check("the store section and the Shopify webhook section of server.js were found", STORE_SECTION.length > 1000 && WEBHOOK_SECTION.length > 500);

  /* ── S ── */
  console.log("\n══ S. start ══");
  let m = mountRoutes({});
  const start = m.routes["post /api/store/shopify/start"], fin = m.routes["post /api/store/shopify/finish"];
  const sLim = start.middleware[2] && start.middleware[2].limiter;
  check("S1. start and finish are requireAuth, requireActiveSubscription and one limiter, 10 an hour, keyed shopify-connect:<id>",
    start.middleware[0] === requireAuth && start.middleware[1] === requireActiveSubscription && fin.middleware[0] === requireAuth &&
    fin.middleware[1] === requireActiveSubscription && fin.middleware[2] === start.middleware[2] && sLim.max === 10 && sLim.windowMs === 3600000 &&
    sLim.keyGenerator({ user: { id: USER } }) === "shopify-connect:" + USER);
  let r = await hit(m, "post /api/store/shopify/start", { body: { shop: SHOP } });
  let rf = await finish(m, callback("A".repeat(43)));
  check("S2. without SHOPIFY_CLIENT_ID and SHOPIFY_CLIENT_SECRET: start and finish answer 503 \"Shopify connection isn't set up yet.\", nothing asked, nothing stored",
    r.status === 503 && r.body.error === "Shopify connection isn't set up yet." && r.body.code === "not_configured" && rf.status === 503 &&
    m.shop.calls.length === 0 && m.db.t.oauth_states.length === 0, J([r.status, r.body.code, rf.status]));
  m = mountRoutes({ env: { SHOPIFY_CLIENT_ID: SHOPIFY_CONFIG.clientId } });
  r = await hit(m, "post /api/store/shopify/start", { body: { shop: SHOP } });
  check("S2b. one of the two set is not configured: 503", r.status === 503 && m.db.t.oauth_states.length === 0, r.status);

  m = mountRoutes({ env: CONFIGURED });
  m.db.t.oauth_states.push({ id: uuid(), user_id: USER, purpose: "store_shopify", state_hash: "a".repeat(64), flow_context: { shop: SHOP, permission: "read" },
    created_at: new Date(Date.now() - 2 * 86400000).toISOString(), expires_at: new Date(Date.now() - 2 * 86400000 + 600000).toISOString(), consumed_at: null });
  m.db.t.oauth_states.push({ id: uuid(), user_id: USER, purpose: "mailbox_microsoft", state_hash: "b".repeat(64), verifier_ciphertext: "00", verifier_iv: "0".repeat(24), verifier_auth_tag: "0".repeat(32),
    created_at: new Date(Date.now() - 2 * 86400000).toISOString(), expires_at: new Date(Date.now() - 2 * 86400000 + 600000).toISOString(), consumed_at: null });
  m.db.t.oauth_states.push({ id: uuid(), user_id: OTHER, purpose: "store_shopify", state_hash: "c".repeat(64), flow_context: { shop: OTHER_SHOP, permission: "read" },
    created_at: new Date(Date.now() - 2 * 86400000).toISOString(), expires_at: new Date(Date.now() - 2 * 86400000 + 600000).toISOString(), consumed_at: null });
  let b = await begin(m, { shop: "https://Demo-Shop.myshopify.com/admin" });
  const expectUrl = "https://" + SHOP + "/admin/oauth/authorize?client_id=check-client-id&scope=read_products%2Cread_inventory%2Cread_orders%2Cread_locations" +
    "&redirect_uri=https%3A%2F%2Fbizforceai.net%2Fstore-agent.html&state=" + b.state;
  check("S3. configured: the shop is normalized and the authorize URL is exactly Shopify's page on it: client_id, the read scopes, the redirect, the state",
    b.r.status === 200 && b.r.body.authorize_url === expectUrl && b.r.body.permission === "read" && b.r.body.saved === false && /^[A-Za-z0-9_-]{43}$/.test(b.state || ""), b.r.status);
  check("S4. ...answered no-store, with nothing asked of the shop", b.r.headers["Cache-Control"] === "no-store" && m.shop.calls.length === 0);
  const st = m.db.t.oauth_states.filter(function (s) { return s.state_hash === crypto.createHash("sha256").update(b.state || "").digest("hex"); })[0];
  check("S5. the state is stored only as its sha256: purpose store_shopify, this member, flow_context { shop, permission }, 10 minutes, unconsumed",
    !!st && st.user_id === USER && st.purpose === "store_shopify" && J(st.flow_context) === J({ shop: SHOP, permission: "read" }) && st.consumed_at === null &&
    Date.parse(st.expires_at) - Date.parse(st.created_at) === 600000 && J(m.db.t.oauth_states).indexOf(b.state) === -1);
  check("S6. start tidies only this member's Shopify states older than a day: the old mailbox state and another member's stay",
    m.db.t.oauth_states.filter(function (s) { return s.state_hash === "a".repeat(64); }).length === 0 &&
    m.db.t.oauth_states.filter(function (s) { return s.state_hash === "b".repeat(64) || s.state_hash === "c".repeat(64); }).length === 2);
  b = await begin(m, { allow_changes: true });
  check("S7. allow_changes exactly true asks the read scopes plus write_products and write_inventory, and the state says read_write",
    b.url && b.url.searchParams.get("scope") === ALL_SCOPES && b.r.body.permission === "read_write" &&
    m.db.t.oauth_states.some(function (s) { return s.flow_context && s.flow_context.permission === "read_write"; }));
  r = await hit(m, "post /api/store/shopify/start", { body: { shop: SHOP, allow_changes: "yes" } });
  const rEvil = await hit(m, "post /api/store/shopify/start", { body: { shop: "evil.com" } });
  check("S8. allow_changes that is not a boolean, and a shop that is not *.myshopify.com, are refused (400) before anything is stored",
    r.status === 400 && r.body.code === "allow_changes" && rEvil.status === 400 && rEvil.body.code === "shopify_domain", J([r.status, rEvil.status]));
  m = mountRoutes({ env: Object.assign({ ENCRYPTION_SECRET: null }, CONFIGURED) });
  r = await hit(m, "post /api/store/shopify/start", { body: { shop: SHOP } });
  check("S9. no ENCRYPTION_SECRET: 503 no_encryption_key, no state stored", r.status === 503 && r.body.code === "no_encryption_key" && m.db.t.oauth_states.length === 0, r.status);
  m = mountRoutes({ env: CONFIGURED });
  shopifyConn(m.db, { user_id: OTHER });
  r = await hit(m, "post /api/store/shopify/start", { body: { shop: SHOP } });
  check("S10. a shop another member has connected: 409 \"This store is already connected to another BizForce account.\", no state stored",
    r.status === 409 && r.body.code === "shop_taken" && r.body.error === "This store is already connected to another BizForce account." && m.db.t.oauth_states.length === 0, J([r.status, r.body.code]));
  m = mountRoutes({ env: CONFIGURED });
  shopifyConn(m.db, {});
  b = await begin(m);
  check("S11. the member's own connected shop may be connected again (reconnect)", b.r.status === 200 && !!b.state, b.r.status);

  /* ── F ── */
  console.log("\n══ F. finish ══");
  check("F0. callbackHmacValid: the hex HMAC over the sorted parameters; one character changed, upper case, missing or another secret is false",
    (function () {
      const p = callback("B".repeat(43));
      const flipped = Object.assign({}, p, { hmac: (p.hmac[0] === "a" ? "b" : "a") + p.hmac.slice(1) });
      return SA.callbackHmacValid(p, SHOPIFY_CONFIG.clientSecret) === true && SA.callbackHmacValid(flipped, SHOPIFY_CONFIG.clientSecret) === false &&
        SA.callbackHmacValid(Object.assign({}, p, { hmac: p.hmac.toUpperCase() }), SHOPIFY_CONFIG.clientSecret) === false &&
        SA.callbackHmacValid(Object.assign({}, p, { hmac: undefined }), SHOPIFY_CONFIG.clientSecret) === false &&
        SA.callbackHmacValid(p, "another-secret") === false && SA.callbackHmacValid(Object.assign({}, p, { code: "x" + p.code }), SHOPIFY_CONFIG.clientSecret) === false;
    })());
  const cbBody = fnBody(stripComments(FILES.auth), "callbackHmacValid"), whBody = fnBody(stripComments(FILES.auth), "webhookHmacValid");
  check("F0b. both HMAC checks compare in constant time (crypto.timingSafeEqual on equal lengths), never with ===",
    /crypto\.timingSafeEqual\(got, want\)/.test(cbBody) && /crypto\.timingSafeEqual\(got, want\)/.test(whBody) && !/given\s*===|===\s*given|===\s*want\.toString|want\.toString\([^)]*\)\s*===/.test(cbBody + whBody));
  check("F0c. timestampFresh: exactly 10 minutes either way is fresh, one second more is not, and only digits",
    SA.timestampFresh(String(NOW / 1000 - 600), NOW) && SA.timestampFresh(String(NOW / 1000 + 600), NOW) &&
    !SA.timestampFresh(String(NOW / 1000 - 601), NOW) && !SA.timestampFresh(String(NOW / 1000 + 601), NOW) && !SA.timestampFresh("1e9", NOW) && !SA.timestampFresh("", NOW));

  m = mountRoutes({ env: CONFIGURED });
  b = await begin(m);
  rf = await finish(m, Object.assign(callback(b.state), { code: CODE + "x" }));
  const stillOpen = m.db.t.oauth_states.filter(function (s) { return s.consumed_at === null; }).length;
  check("F1. a tampered callback (the code changed after Shopify signed it): 400 state_invalid, nothing exchanged, the state not consumed",
    rf.status === 400 && J(rf.body) === J(INVALID) && m.shop.calls.length === 0 && stillOpen === 1, J([rf.status, rf.body.code]));
  const noHmac = callback(b.state); delete noHmac.hmac;
  rf = await finish(m, noHmac);
  const r2 = await finish(m, callback(b.state, {}, "another-secret"));
  check("F2. no hmac, or one made with another secret: the same 400, nothing exchanged",
    rf.status === 400 && J(rf.body) === J(INVALID) && r2.status === 400 && J(r2.body) === J(INVALID) && m.shop.calls.length === 0);
  rf = await finish(m, callback(b.state, { timestamp: String(Math.floor(Date.now() / 1000) - 11 * 60) }));
  const rFut = await finish(m, callback(b.state, { timestamp: String(Math.floor(Date.now() / 1000) + 11 * 60) }));
  const rOk9 = SA.timestampFresh(String(Math.floor(Date.now() / 1000) - 9 * 60), Date.now());
  check("F3. a callback signed 11 minutes ago, or 11 minutes ahead: the same 400, nothing exchanged (9 minutes is fresh)",
    rf.status === 400 && J(rf.body) === J(INVALID) && rFut.status === 400 && J(rFut.body) === J(INVALID) && rOk9 && m.shop.calls.length === 0);
  rf = await finish(m, callback(b.state, { shop: OTHER_SHOP }));
  const rCase = await finish(m, callback(b.state, { shop: "Demo-Shop.myshopify.com" }));
  check("F4. a validly signed callback for another shop than the state was made for, or the shop not as normalized: the same 400, nothing exchanged",
    rf.status === 400 && J(rf.body) === J(INVALID) && rCase.status === 400 && J(rCase.body) === J(INVALID) && m.shop.calls.length === 0);

  m = mountRoutes({ env: CONFIGURED });
  b = await begin(m);
  const goodParams = callback(b.state);
  rf = await finish(m, goodParams);
  const row = m.db.t.member_store_connections[0];
  check("F5. a good callback: 200 saved, one Shopify row for this member, connected, read",
    rf.status === 200 && rf.body.saved === true && m.db.t.member_store_connections.length === 1 && row.user_id === USER && row.platform === "shopify" &&
    row.store_url === SHOP && row.status === "connected" && row.permission === "read" && rf.body.connection && rf.body.connection.permission === "read", J([rf.status, rf.body.code]));
  const ex = m.shop.tokenCalls("exchange")[0];
  check("F6. the exchange is ONE POST to the shop's /admin/oauth/access_token with client_id, client_secret, the code and expiring: 1, nothing else",
    m.shop.tokenCalls().length === 1 && !!ex && ex.host === SHOP && ex.method === "POST" && ex.body && J(Object.keys(ex.body).sort()) === J(["client_id", "client_secret", "code", "expiring"]) &&
    ex.body.expiring === 1 && ex.body.client_id === SHOPIFY_CONFIG.clientId && ex.body.client_secret === SHOPIFY_CONFIG.clientSecret && ex.body.code === CODE);
  check("F7. the access token is stored sealed in access_*, the refresh token sealed in credentials_* as { refresh_token }, token_version 0",
    accessOf(row) === TOKEN && refreshOf(row) === REFRESH && row.token_version === 0 && J(row).indexOf(TOKEN) === -1 && J(row).indexOf(REFRESH) === -1);
  check("F8. the expiries: the access token's a minute before Shopify's (3600 s), the refresh token's as Shopify gave it",
    Math.abs(Date.parse(row.access_expires_at) - (Date.now() + 3540000)) < 10000 && Math.abs(Date.parse(row.refresh_expires_at) - (Date.now() + 7776000000)) < 10000);
  const firstGql = m.events.findIndex(function (e) { return /^graphql:/.test(e); });
  check("F9. both tokens are sealed BEFORE Shopify's GraphQL API is asked anything, and that first request uses the new access token",
    firstGql > m.events.indexOf("encrypt:access") && firstGql > m.events.indexOf("encrypt:refresh") && m.events.indexOf("encrypt:access") !== -1 &&
    m.events.indexOf("encrypt:refresh") !== -1 && m.events.indexOf("token:exchange") < m.events.indexOf("encrypt:access") && m.shop.ops()[0] && m.shop.ops()[0].token === TOKEN, m.events.join(","));
  check("F10. the shop's currency is stored (CAD), and its one active location is chosen by itself",
    row.currency === "CAD" && row.location_id === LOCATION && row.location_name === "Main warehouse" && rf.body.connection.stock_scope === "location" && rf.body.locations === 1);
  check("F11. the stored row passes the token_shape CHECK and the scopes CHECK (the fake database enforces migration 176's)",
    row.granted_scopes === READ_SCOPES && row.access_iv && row.access_auth_tag && row.access_expires_at);
  check("F12. no token, code or client secret in the answer or any log line", noSecretIn(J(rf.body)) && noSecretIn(m.logs.join("\n")));
  const consumedRow = m.db.t.oauth_states[0];
  check("F13. the state is consumed (consumed_at set)", !!consumedRow && consumedRow.consumed_at !== null);
  rf = await finish(m, goodParams);
  check("F14. the same callback again: the same 400, no second exchange", rf.status === 400 && J(rf.body) === J(INVALID) && m.shop.tokenCalls().length === 1, J([rf.status, m.shop.tokenCalls().length]));

  m = mountRoutes({ env: CONFIGURED });
  b = await begin(m);
  m.db.t.oauth_states[0].user_id = OTHER;
  rf = await finish(m, callback(b.state));
  const otherUntouched = m.db.t.oauth_states[0].consumed_at === null;
  m.db.t.oauth_states[0].user_id = USER;
  m.db.t.oauth_states[0].expires_at = new Date(Date.now() - 1000).toISOString();
  const rExp = await finish(m, callback(b.state));
  check("F15. another member's state, or an expired one: the same 400 with no reason, nothing exchanged, and the other member's state left as it was",
    rf.status === 400 && J(rf.body) === J(INVALID) && rExp.status === 400 && J(rExp.body) === J(INVALID) && otherUntouched && m.shop.calls.length === 0);

  m = mountRoutes({ env: CONFIGURED, shop: { grantOmit: ["refresh_token"] } });
  b = await begin(m);
  rf = await finish(m, callback(b.state));
  check("F16. an answer with no refresh token (a non-expiring token): 422, nothing stored, no GraphQL request",
    rf.status === 422 && rf.body.code === "no_access" && m.db.t.member_store_connections.length === 0 && m.shop.ops().length === 0, J([rf.status, rf.body.code]));
  m = mountRoutes({ env: CONFIGURED, shop: { grantOmit: ["expires_in"] } });
  b = await begin(m);
  rf = await finish(m, callback(b.state));
  check("F17. an answer with no expires_in: 422, nothing stored", rf.status === 422 && m.db.t.member_store_connections.length === 0, rf.status);
  m = mountRoutes({ env: CONFIGURED, shop: { scope: READ_SCOPES } });
  b = await begin(m, { allow_changes: true });
  rf = await finish(m, callback(b.state));
  check("F18. changes asked for but the write scopes not granted: 422 \"Shopify didn't grant the access needed...\", nothing stored, no GraphQL request",
    rf.status === 422 && rf.body.code === "scopes_missing" && rf.body.error === "Shopify didn't grant the access needed. Connect again and approve all permissions." &&
    m.db.t.member_store_connections.length === 0 && m.shop.ops().length === 0, J([rf.status, rf.body.code]));
  m = mountRoutes({ env: CONFIGURED, shop: { scope: "read_products,read_inventory,read_orders" } });
  b = await begin(m);
  rf = await finish(m, callback(b.state));
  check("F19. a read scope missing (read_locations): 422, nothing stored", rf.status === 422 && m.db.t.member_store_connections.length === 0, rf.status);
  m = mountRoutes({ env: CONFIGURED, shop: { scope: ALL_SCOPES } });
  b = await begin(m);
  rf = await finish(m, callback(b.state));
  const extraRow = m.db.t.member_store_connections[0];
  check("F20. read asked, the write scopes granted as extras: stored in granted_scopes, but the connection stays read and the answer says read",
    rf.status === 200 && extraRow && extraRow.granted_scopes === ALL_SCOPES && extraRow.permission === "read" && rf.body.connection.permission === "read" &&
    SS.permissionOf(extraRow) === "read", J([rf.status, extraRow && extraRow.permission]));
  m = mountRoutes({ env: CONFIGURED, shop: { scope: "write_products,write_inventory,read_orders,read_locations" } });
  b = await begin(m, { allow_changes: true });
  rf = await finish(m, callback(b.state));
  check("F21. a write scope stands for its read twin (Shopify may omit read_ when write_ is granted): read_write connected",
    rf.status === 200 && m.db.t.member_store_connections[0] && m.db.t.member_store_connections[0].permission === "read_write" && rf.body.connection.permission === "read_write", rf.status);
  m = mountRoutes({ env: CONFIGURED, shop: { exchangeStatus: 400 } });
  b = await begin(m);
  rf = await finish(m, callback(b.state));
  const r502 = await (async function () { const mm = mountRoutes({ env: CONFIGURED, shop: { exchangeStatus: 500 } }); const bb = await begin(mm); return finish(mm, callback(bb.state)); })();
  check("F22. Shopify refusing the code: the same 400 as a bad state; Shopify failing: 502, \"Nothing was saved.\"; nothing stored either way",
    rf.status === 400 && J(rf.body) === J(INVALID) && r502.status === 502 && /Nothing was saved\.$/.test(r502.body.error) && m.db.t.member_store_connections.length === 0, J([rf.status, r502.status]));
  m = mountRoutes({ env: CONFIGURED, shop: { locations: [{ id: LOCATION, name: "Main warehouse", isActive: true }, { id: LOCATION2, name: "Pop-up", isActive: true }], currency: "cad" } });
  b = await begin(m);
  rf = await finish(m, callback(b.state));
  const two = m.db.t.member_store_connections[0];
  check("F23. two active locations: none chosen (stock read as the total), and a currency that is not three capitals is stored as null",
    rf.status === 200 && two.location_id === null && two.location_name === null && two.currency === null && rf.body.connection.stock_scope === "total", rf.status);
  two.location_id = LOCATION2; two.location_name = "Pop-up";
  b = await begin(m);
  rf = await finish(m, callback(b.state));
  check("F24. connecting again keeps the location chosen before while it is still active", rf.status === 200 && m.db.t.member_store_connections.length === 1 &&
    m.db.t.member_store_connections[0].location_id === LOCATION2, rf.status);
  m = mountRoutes({ env: CONFIGURED });
  b = await begin(m);
  shopifyConn(m.db, { user_id: OTHER });
  rf = await finish(m, callback(b.state));
  check("F25. another member connects the shop between start and finish: the unique shop index answers, 409 shop_taken, nothing stored for this member",
    rf.status === 409 && rf.body.code === "shop_taken" && m.db.t.member_store_connections.filter(function (x) { return x.user_id === USER; }).length === 0, J([rf.status, rf.body.code]));
  m = mountRoutes({ env: CONFIGURED });
  rf = await finish(m, { params: "x" });
  const rArr = await hit(m, "post /api/store/shopify/finish", { body: { params: { code: CODE } } });
  check("F26. a finish body that is not the callback's query: the same 400", rf.status === 400 && J(rArr.body) === J(INVALID), J([rf.status, rArr.status]));

  /* ── T ── */
  console.log("\n══ T. tokens: refresh, rotation, compare-and-set ══");
  let db = makeDb(), shop = makeShop({}), deps = libDeps(db, shop);
  let conn = shopifyConn(db, {});
  await SAPI.shopInfo(deps, SAPI.session(Object.assign({}, conn)));
  check("T1. a token 50 minutes from its expiry is used as it is: no refresh", shop.tokenCalls().length === 0 && shop.ops()[0].token === TOKEN);
  db = makeDb(); shop = makeShop({}); deps = libDeps(db, shop);
  conn = shopifyConn(db, { access_expires_at: new Date(NOW + 2 * 60000).toISOString() });
  const before = db.log.length;
  let s = SAPI.session(Object.assign({}, conn));
  await SAPI.shopInfo(deps, s);
  const rq = shop.tokenCalls("refresh")[0];
  check("T2. a token 2 minutes from its expiry is refreshed first: ONE POST with client_id, client_secret, grant_type refresh_token and the stored refresh token",
    shop.tokenCalls().length === 1 && rq && J(Object.keys(rq.body).sort()) === J(["client_id", "client_secret", "grant_type", "refresh_token"]) &&
    rq.body.grant_type === "refresh_token" && rq.body.refresh_token === REFRESH && rq.body.client_secret === SHOPIFY_CONFIG.clientSecret);
  check("T3. the new pair is saved together in ONE update: the new access token, the new refresh token, token_version 1, the new expiry",
    db.log.slice(before).filter(function (l) { return l.table === "member_store_connections" && l.op === "update"; }).length === 1 &&
    accessOf(conn) === TOKEN2 && refreshOf(conn) === REFRESH2 && conn.token_version === 1 && Date.parse(conn.access_expires_at) === NOW + 3540000);
  check("T4. ...and the read used the new access token", shop.ops("ShopInfo").length === 1 && shop.ops("ShopInfo")[0].token === TOKEN2 && s.refreshed === true);

  db = makeDb(); deps = null;
  conn = shopifyConn(db, { access_expires_at: new Date(NOW + 60000).toISOString() });
  shop = makeShop({ onRefresh: function () {
    const w = CRYPT.encrypt(WINNER);
    Object.assign(conn, { access_ciphertext: w.ciphertext, access_iv: w.iv, access_auth_tag: w.authTag, token_version: 1, access_expires_at: new Date(NOW + 3600000).toISOString() });
  } });
  deps = libDeps(db, shop);
  await SAPI.shopInfo(deps, SAPI.session(Object.assign({}, conn)));
  check("T5. losing the race (another process rotated first): the compare-and-set on token_version writes nothing, and the read uses the winner's token",
    accessOf(conn) === WINNER && conn.token_version === 1 && refreshOf(conn) === REFRESH && shop.ops("ShopInfo")[0].token === WINNER);

  db = makeDb();
  conn = shopifyConn(db, { access_expires_at: new Date(NOW + 60000).toISOString() });
  shop = makeShop({ refresh: "refuse", onRefresh: function () {
    const w = CRYPT.encrypt(WINNER);
    Object.assign(conn, { access_ciphertext: w.ciphertext, access_iv: w.iv, access_auth_tag: w.authTag, token_version: 1, access_expires_at: new Date(NOW + 3600000).toISOString() });
  } });
  deps = libDeps(db, shop);
  let at = await attempt(SAPI.shopInfo(deps, SAPI.session(Object.assign({}, conn))));
  check("T6. a refresh refused because another process spent the refresh token first: the row is read again and the winner's token used",
    at.ok && shop.ops("ShopInfo")[0].token === WINNER, J([at.ok, at.code]));

  db = makeDb(); shop = makeShop({}); deps = libDeps(db, shop);
  conn = shopifyConn(db, { access_expires_at: new Date(NOW + 60000).toISOString() });
  const toks = await Promise.all([SAPI.accessToken(deps, SAPI.session(Object.assign({}, conn)), false), SAPI.accessToken(deps, SAPI.session(Object.assign({}, conn)), false)]);
  check("T7. two reads at once on one connection: ONE refresh, both use the new token", shop.tokenCalls().length === 1 && toks[0] === TOKEN2 && toks[1] === TOKEN2, shop.tokenCalls().length);

  db = makeDb(); shop = makeShop({ refresh: "refuse" }); deps = libDeps(db, shop);
  conn = shopifyConn(db, { access_expires_at: new Date(NOW + 60000).toISOString() });
  let sync = await SS.syncConnection(deps, conn);
  check("T8. a refresh Shopify refuses: the sync is needs_reconnect, ONE notice, nothing asked of GraphQL, the stored tokens untouched",
    sync.ok === false && sync.needs_reconnect === true && conn.status === "needs_reconnect" && db.t.notifications.length === 1 && shop.ops().length === 0 &&
    accessOf(conn) === TOKEN && refreshOf(conn) === REFRESH, J([sync.ok, sync.code]));
  db = makeDb(); shop = makeShop({}); deps = libDeps(db, shop);
  conn = shopifyConn(db, { access_expires_at: new Date(NOW - 60000).toISOString(), refresh_expires_at: new Date(NOW - 1000).toISOString() });
  at = await attempt(SAPI.shopInfo(deps, SAPI.session(Object.assign({}, conn))));
  check("T9. a refresh token past its expiry is never sent: StoreAuthError refresh_expired, no request at all",
    !at.ok && at.name === "StoreAuthError" && at.code === "refresh_expired" && shop.calls.length === 0, J([at.ok, at.code, shop.calls.length]));
  db = makeDb(); shop = makeShop({ refresh: "down" }); deps = libDeps(db, shop);
  conn = shopifyConn(db, { access_expires_at: new Date(NOW + 60000).toISOString() });
  sync = await SS.syncConnection(deps, conn);
  check("T10. Shopify failing a refresh (503) is not needs_reconnect: the sync fails, the connection stays connected",
    sync.ok === false && !sync.needs_reconnect && conn.status === "connected", J([sync.ok, sync.code, conn.status]));

  db = makeDb(); shop = makeShop({ reject: [TOKEN] }); deps = libDeps(db, shop);
  conn = shopifyConn(db, {});
  at = await attempt(SAPI.shopInfo(deps, SAPI.session(Object.assign({}, conn))));
  check("T11. a 401 on a read with a token not refreshed in this session: ONE refresh and ONE more read, which succeeds",
    at.ok && shop.ops("ShopInfo").length === 2 && shop.tokenCalls().length === 1 && shop.ops("ShopInfo")[1].token === TOKEN2, J([at.ok, shop.ops().length, shop.tokenCalls().length]));
  db = makeDb(); shop = makeShop({ reject: [TOKEN, TOKEN2] }); deps = libDeps(db, shop);
  conn = shopifyConn(db, {});
  at = await attempt(SAPI.shopInfo(deps, SAPI.session(Object.assign({}, conn))));
  check("T12. ...and when the new token is refused too: StoreAuthError after exactly two reads and one refresh, never a third",
    !at.ok && at.name === "StoreAuthError" && shop.ops().length === 2 && shop.tokenCalls().length === 1, J([at.ok, shop.ops().length, shop.tokenCalls().length]));
  db = makeDb(); shop = makeShop({ reject: [TOKEN2] }); deps = libDeps(db, shop);
  conn = shopifyConn(db, { access_expires_at: new Date(NOW + 60000).toISOString() });
  at = await attempt(SAPI.shopInfo(deps, SAPI.session(Object.assign({}, conn))));
  check("T13. a 401 right after this session refreshed: no second refresh, one read",
    !at.ok && at.name === "StoreAuthError" && shop.ops().length === 1 && shop.tokenCalls().length === 1, J([at.ok, shop.ops().length, shop.tokenCalls().length]));

  /* ── Y ── */
  console.log("\n══ Y. the sync through GraphQL ══");
  db = makeDb(); shop = makeShop({}); deps = libDeps(db, shop);
  conn = shopifyConn(db, {});
  sync = await SS.syncConnection(deps, conn);
  const items = db.t.inventory_items;
  const red = items.filter(function (i) { return i.external_id === "variant:11"; })[0], green = items.filter(function (i) { return i.external_id === "variant:21"; })[0];
  check("Y1. the sync succeeds and stores tracked variants only: the untracked one is skipped, never written as 0",
    sync.ok === true && items.length === 2 && !items.some(function (i) { return i.external_id === "variant:12"; }), J([sync.ok, items.length]));
  check("Y2. each row holds the variant, product and inventory item ids, marked shopify on this connection",
    !!red && red.source === "shopify" && red.store_connection_id === conn.id && String(red.external_parent_id) === "1" && red.external_inventory_item_id === "9011" &&
    !!green && green.external_inventory_item_id === "9021");
  check("Y3. no location chosen: the stock is the total across locations (10 and 6)", red && red.quantity_on_hand === 10 && green && green.quantity_on_hand === 6, J([red && red.quantity_on_hand, green && green.quantity_on_hand]));
  check("Y4. every request is a POST of a GraphQL query document to graphql.json: never a mutation",
    shop.calls.length > 0 && shop.calls.every(function (c) { return c.path === GRAPHQL_PATH && c.method === "POST" && c.kind === "query" && !/\bmutation\b/.test(J(c.body)); }),
    shop.calls.map(function (c) { return c.kind + ":" + c.op; }).join(","));
  check("Y5. the variants are paged by endCursor, and the shop's currency is stored on the connection",
    shop.ops("Variants").length === 2 && shop.ops("Variants")[1].body.variables.cursor === "c2" && conn.currency === "CAD");
  check("Y6. order summaries hold no customer field", db.t.store_order_summaries.length === 1 && !/buyer@example\.com|Jane/.test(J(db.t.store_order_summaries)));
  db = makeDb(); shop = makeShop({}); deps = libDeps(db, shop);
  conn = shopifyConn(db, { location_id: LOCATION, location_name: "Main warehouse" });
  sync = await SS.syncConnection(deps, conn);
  const atLoc = db.t.inventory_items.filter(function (i) { return i.external_id === "variant:11"; })[0];
  check("Y7. a chosen location: VariantsAt with that location, the stock is its \"available\" (4, not the total 10), a variant not stocked there is skipped",
    sync.ok && shop.ops("VariantsAt").length === 2 && shop.ops("VariantsAt")[0].body.variables.location === LOCATION && atLoc && atLoc.quantity_on_hand === 4 &&
    !db.t.inventory_items.some(function (i) { return i.external_id === "variant:21"; }), J([sync.ok, atLoc && atLoc.quantity_on_hand]));
  db = makeDb(); shop = makeShop({ throttleOnce: { Variants: true } }); deps = libDeps(db, shop);
  conn = shopifyConn(db, {});
  sync = await SS.syncConnection(deps, conn);
  check("Y8. a THROTTLED answer is waited out and the page asked again", sync.ok && shop.ops("Variants").length === 3 && deps.sleeps.some(function (ms) { return ms >= 2000; }), J([sync.ok, shop.ops("Variants").length]));
  db = makeDb(); shop = makeShop({ gqlError: { Variants: true } }); deps = libDeps(db, shop);
  conn = shopifyConn(db, {});
  sync = await SS.syncConnection(deps, conn);
  check("Y9. a GraphQL error is a failure: asked once, nothing written, the connection still connected",
    sync.ok === false && sync.code === "graphql_error" && shop.ops("Variants").length === 1 && db.t.inventory_items.length === 0 && conn.status === "connected", J([sync.ok, sync.code]));
  db = makeDb(); shop = makeShop({ endless: true }); deps = libDeps(db, shop);
  conn = shopifyConn(db, {});
  await SAPI.fetchItems(deps, SAPI.session(conn));
  check("Y10. a shop that never ends is read for 200 pages of variants and no more", shop.ops("Variants").length === 200, shop.ops("Variants").length);
  const apiCode = stripComments(FILES.api);
  const spans = ["writePrice", "writeStock"].map(function (n) { const a = apiCode.search(new RegExp("^async function " + n + "\\(", "m")); return [a, apiCode.indexOf("\n}\n", a)]; });
  const mutationAt = []; apiCode.replace(/\bmutation\b/g, function (w, i) { mutationAt.push(i); return w; });
  check("Y11. the word \"mutation\" appears in lib/shopifyApi.js's code only inside writePrice and writeStock",
    mutationAt.length === 2 && mutationAt.every(function (i) { return spans.some(function (sp) { return sp[0] !== -1 && i > sp[0] && i < sp[1]; }); }), mutationAt.length);
  check("Y12. sendOnce is called only by writePrice and writeStock, and lib/shopifyApi.js has exactly two deps.jsonRequest calls",
    (apiCode.match(/sendOnce\(/g) || []).length === 3 && (apiCode.match(/deps\.jsonRequest\(/g) || []).length === 2);

  /* ── W ── */
  console.log("\n══ W. Shopify price and stock changes through approval ══");
  db = makeDb(); shop = makeShop({ compareAt: "30.00" }); deps = libDeps(db, shop);
  conn = writableConn(db);
  let it = shopifyItem(db, conn);
  let pr = await SW.proposeChange(deps, USER, { item_id: it.id, field: "price", to: "21.5" });
  const pp = pr.body.proposal && pr.body.proposal.payload;
  check("W1. a price proposal: from the live price (25.00) to 21.50, platform shopify, the store's currency, filed and not run",
    pr.status === 201 && pp && pp.from === "25.00" && pp.to === "21.50" && pp.platform === "shopify" && pp.currency === "CAD" && pr.body.proposal.status === "pending" &&
    shop.ops("PriceSet").length === 0, J([pr.status, pr.body.code]));
  check("W2. ...the compare-at price is shown, and the note says it stays as it is",
    pr.body.compare_at_price === "30.00" && pr.body.note.indexOf("This item has a compare-at price of 30.00 CAD, which stays as it is.") !== -1, pr.body.note);
  let ex1 = await attempt(SW.executeChange(deps, pr.body.proposal));
  const ps = shop.ops("PriceSet")[0];
  check("W3. approved: ONE PriceSet with the product id and the variant's id and price only, never compareAtPrice",
    ex1.ok && shop.ops("PriceSet").length === 1 && ps.kind === "mutation" && ps.body.variables.productId === PRODUCT &&
    J(ps.body.variables.variants) === J([{ id: VARIANT, price: "21.50" }]) && !/compareAtPrice/.test(ps.body.query), J([ex1.ok, ex1.msg]));
  check("W4. ...after the live compare-and-set read, the change logged with the currency, and the item updated",
    shop.ops("LiveVariant").length === 2 && db.t.store_change_log.length === 1 && db.t.store_change_log[0].currency === "CAD" && it.unit_price === 21.5);
  db = makeDb(); shop = makeShop({}); deps = libDeps(db, shop);
  conn = writableConn(db); it = shopifyItem(db, conn);
  pr = await SW.proposeChange(deps, USER, { item_id: it.id, field: "price", to: "21.50" });
  shop.state.price = "26.00";
  ex1 = await attempt(SW.executeChange(deps, pr.body.proposal));
  check("W5. the price changed in the store since the proposal: \"Your store changed since you proposed this. Propose it again.\", nothing sent",
    !ex1.ok && ex1.msg === "Your store changed since you proposed this. Propose it again." && shop.ops("PriceSet").length === 0 && db.t.store_change_log.length === 0, ex1.msg);
  db = makeDb(); shop = makeShop({ priceEcho: "wrong" }); deps = libDeps(db, shop);
  conn = writableConn(db); it = shopifyItem(db, conn);
  pr = await SW.proposeChange(deps, USER, { item_id: it.id, field: "price", to: "21.50" });
  ex1 = await attempt(SW.executeChange(deps, pr.body.proposal));
  check("W6. an answer that does not echo the new price: \"BizForce couldn't confirm the change...\", sent once, nothing logged",
    !ex1.ok && /couldn't confirm the change/.test(ex1.msg) && shop.ops("PriceSet").length === 1 && db.t.store_change_log.length === 0, ex1.msg);

  db = makeDb(); shop = makeShop({}); deps = libDeps(db, shop);
  conn = writableConn(db, { location_id: null, location_name: null }); it = shopifyItem(db, conn);
  pr = await SW.proposeChange(deps, USER, { item_id: it.id, field: "stock", to: 9 });
  const direct = await SW.readLiveShopifyItem(deps, SAPI.session(conn), "stock", it);
  check("W7. no location chosen: a stock proposal is refused, 409 \"Choose a location for stock changes first.\", and the live read asks nothing",
    pr.status === 409 && pr.body.code === "no_location" && pr.body.error === "Choose a location for stock changes first." && !direct.ok && direct.code === "no_location" &&
    shop.calls.length === 0, J([pr.status, direct.code, shop.calls.length]));
  db = makeDb(); shop = makeShop({}); deps = libDeps(db, shop);
  conn = writableConn(db); it = shopifyItem(db, conn);
  pr = await SW.proposeChange(deps, USER, { item_id: it.id, field: "stock", to: 9 });
  check("W8. a stock proposal: from the location's live \"available\" (4), the location in the payload",
    pr.status === 201 && pr.body.proposal.payload.from === 4 && pr.body.proposal.payload.location_id === LOCATION && pr.body.proposal.payload.location_name === "Main warehouse", pr.status);
  ex1 = await attempt(SW.executeChange(deps, pr.body.proposal));
  const ss1 = shop.ops("StockSet")[0];
  const q1 = ss1 && ss1.body.variables.input.quantities[0];
  check("W9. approved: ONE StockSet, name available, the item at the chosen location, quantity 9 with changeFromQuantity 4",
    ex1.ok && shop.ops("StockSet").length === 1 && ss1.body.variables.input.name === "available" &&
    J(q1) === J({ inventoryItemId: ITEM, locationId: LOCATION, quantity: 9, changeFromQuantity: 4 }), J([ex1.ok, ex1.msg]));
  check("W10. ...@idempotent keyed by the proposal id", /inventorySetQuantities\(input: \$input\) @idempotent\(key: \$key\)/.test(ss1.body.query) && ss1.body.variables.key === pr.body.proposal.id);
  check("W11. ...then ONE confirming read, and the change logged with the location",
    shop.ops("LiveLevel").length === 3 && db.t.store_change_log.length === 1 && db.t.store_change_log[0].location_name === "Main warehouse" && it.quantity_on_hand === 9);
  db = makeDb(); shop = makeShop({}); deps = libDeps(db, shop);
  conn = writableConn(db); it = shopifyItem(db, conn);
  pr = await SW.proposeChange(deps, USER, { item_id: it.id, field: "stock", to: 9 });
  shop.state.available = 6;
  ex1 = await attempt(SW.executeChange(deps, pr.body.proposal));
  check("W12. the stock changed before approval: the live compare-and-set refuses, nothing sent", !ex1.ok && /Your store changed/.test(ex1.msg) && shop.ops("StockSet").length === 0, ex1.msg);
  db = makeDb(); shop = makeShop({ moveBeforeStockSet: true }); deps = libDeps(db, shop);
  conn = writableConn(db); it = shopifyItem(db, conn);
  pr = await SW.proposeChange(deps, USER, { item_id: it.id, field: "stock", to: 9 });
  ex1 = await attempt(SW.executeChange(deps, pr.body.proposal));
  check("W13. the stock moved between the read and the write: Shopify's changeFromQuantity refuses it, \"Your store changed...\", sent once, nothing logged",
    !ex1.ok && /Your store changed/.test(ex1.msg) && shop.ops("StockSet").length === 1 && db.t.store_change_log.length === 0, ex1.msg);
  db = makeDb(); shop = makeShop({ opStatus: { StockSet: 500 } }); deps = libDeps(db, shop);
  conn = writableConn(db); it = shopifyItem(db, conn);
  pr = await SW.proposeChange(deps, USER, { item_id: it.id, field: "stock", to: 9 });
  ex1 = await attempt(SW.executeChange(deps, pr.body.proposal));
  check("W14. a 500 after the stock write was sent: never retried, \"BizForce couldn't confirm the change... will not try again.\"",
    !ex1.ok && /will not try again/.test(ex1.msg) && shop.ops("StockSet").length === 1, J([ex1.msg, shop.ops("StockSet").length]));
  db = makeDb(); shop = makeShop({ opDown: { PriceSet: true } }); deps = libDeps(db, shop);
  conn = writableConn(db); it = shopifyItem(db, conn);
  pr = await SW.proposeChange(deps, USER, { item_id: it.id, field: "price", to: "21.50" });
  ex1 = await attempt(SW.executeChange(deps, pr.body.proposal));
  check("W15. the connection dropping after the price write was sent: never retried, unconfirmed", !ex1.ok && /will not try again/.test(ex1.msg) && shop.ops("PriceSet").length === 1,
    J([ex1.msg, shop.ops("PriceSet").length]));
  db = makeDb(); shop = makeShop({ priceUserError: true }); deps = libDeps(db, shop);
  conn = writableConn(db); it = shopifyItem(db, conn);
  pr = await SW.proposeChange(deps, USER, { item_id: it.id, field: "price", to: "21.50" });
  ex1 = await attempt(SW.executeChange(deps, pr.body.proposal));
  check("W16. userErrors on the price write: \"Your store refused the change, so nothing was changed.\", sent once",
    !ex1.ok && ex1.msg === "Your store refused the change, so nothing was changed." && shop.ops("PriceSet").length === 1, ex1.msg);

  db = makeDb(); shop = makeShop({}); deps = libDeps(db, shop);
  conn = writableConn(db); it = shopifyItem(db, conn);
  pr = await SW.proposeChange(deps, USER, { item_id: it.id, field: "price", to: "21.50" });
  conn.permission = "read";
  ex1 = await attempt(SW.executeChange(deps, pr.body.proposal));
  check("W17. a connection that is not read_write: the executor refuses with the read-only message, nothing asked of Shopify",
    !ex1.ok && /connected read-only/.test(ex1.msg) && shop.ops("PriceSet").length === 0 && shop.ops("LiveVariant").length === 1, ex1.msg);
  conn.permission = "read_write"; conn.granted_scopes = READ_SCOPES + ",write_products";
  ex1 = await attempt(SW.executeChange(deps, pr.body.proposal));
  const prRead = await SW.proposeChange(deps, USER, { item_id: it.id, field: "price", to: "22.00" });
  check("W18. read_write but write_inventory not granted: refused as read-only, by the executor and at proposing, nothing sent",
    !ex1.ok && /connected read-only/.test(ex1.msg) && prRead.status === 409 && prRead.body.code === "read_only" && shop.ops("PriceSet").length === 0, J([ex1.msg, prRead.status]));
  db = makeDb(); shop = makeShop({}); deps = libDeps(db, shop);
  conn = writableConn(db); it = shopifyItem(db, conn);
  pr = await SW.proposeChange(deps, USER, { item_id: it.id, field: "stock", to: 9 });
  conn.location_id = LOCATION2; conn.location_name = "Pop-up";
  ex1 = await attempt(SW.executeChange(deps, pr.body.proposal));
  check("W19. the location changed after the proposal: refused, nothing sent", !ex1.ok && /Your store changed/.test(ex1.msg) && shop.ops("StockSet").length === 0, ex1.msg);

  /* ── H ── */
  console.log("\n══ H. webhooks ══");
  m = mountRoutes({});
  const wh = m.routes["post /api/webhooks/shopify"];
  let rw = await webhook(m, "app/uninstalled", "{ \"id\": 1 }");
  check("H1. unconfigured: 503, nothing recorded", rw.status === 503 && m.db.t.shopify_webhook_events.length === 0, rw.status);
  const rawMw = wh.middleware[0] && wh.middleware[0].raw;
  check("H2. the route takes the RAW body (express.raw for any content type, 1mb), so the HMAC is over the bytes Shopify sent",
    wh.middleware.length === 1 && !!rawMw && rawMw.limit === "1mb" && typeof rawMw.type === "function" && rawMw.type({ headers: { "content-type": "application/json" } }) === true &&
    FILES.server.indexOf("\"/api/webhooks/shopify\",\n  express.raw(") !== -1 && FILES.server.indexOf("\"/api/webhooks/shopify\"") < FILES.server.indexOf("app.use(express.json({ limit: \"5mb\" }));"));
  m = mountRoutes({ env: CONFIGURED });
  const c1 = shopifyConn(m.db, {});
  const keepOther = shopifyConn(m.db, { user_id: OTHER, store_url: OTHER_SHOP });
  shopifyItem(m.db, c1);
  m.db.t.inventory_items.push({ id: uuid(), user_id: USER, name: "Manual mug", source: null, store_connection_id: null, external_id: null, sku: "MUG", quantity_on_hand: 3 });
  m.db.t.store_order_summaries.push({ id: uuid(), user_id: USER, connection_id: c1.id, external_id: "5001", line_items: [] });
  m.db.t.store_change_log.push({ id: uuid(), user_id: USER, connection_id: c1.id, field: "price" });
  const body = "{\n  \"id\": 690933842,\n  \"domain\": \"demo-shop.myshopify.com\"\n}";
  rw = await webhook(m, "app/uninstalled", body, { hmac: crypto.createHmac("sha256", SHOPIFY_CONFIG.clientSecret).update(body + " ").digest("base64") });
  const rNo = await webhook(m, "app/uninstalled", body, { hmac: null });
  const rSec = await webhook(m, "app/uninstalled", body, { secret: "another-secret" });
  check("H3. an HMAC over other bytes, none, or under another secret: 401, nothing recorded, nothing removed",
    rw.status === 401 && rNo.status === 401 && rSec.status === 401 && m.db.t.shopify_webhook_events.length === 0 && m.db.t.member_store_connections.length === 2, J([rw.status, rNo.status, rSec.status]));
  const WID = "b54557e4-bdd9-4b37-8a5f-bf7d70bcd043";
  rw = await webhook(m, "app/uninstalled", body, { id: WID });
  check("H4. app/uninstalled, signed over the raw body: 200, and the shop's connection, synced items, order summaries and change record are removed as disconnect removes them",
    rw.status === 200 && m.db.t.member_store_connections.length === 1 && m.db.t.member_store_connections[0] === keepOther &&
    m.db.t.inventory_items.length === 1 && m.db.t.inventory_items[0].name === "Manual mug" && m.db.t.store_order_summaries.length === 0 && m.db.t.store_change_log.length === 0, rw.status);
  const rec = m.db.t.shopify_webhook_events[0];
  check("H5. the delivery is recorded once, with processed_at, and no body", m.db.t.shopify_webhook_events.length === 1 && rec.webhook_id === WID && rec.topic === "app/uninstalled" &&
    rec.shop_domain === SHOP && rec.processed_at !== null && J(rec).indexOf("690933842") === -1);
  const again = shopifyConn(m.db, {});
  rw = await webhook(m, "app/uninstalled", body, { id: WID });
  check("H6. the same delivery again (the member has since connected again): 200 duplicate, nothing removed",
    rw.status === 200 && rw.body.duplicate === true && m.db.t.member_store_connections.indexOf(again) !== -1 && m.db.t.shopify_webhook_events.length === 1, J([rw.status, rw.body]));
  rw = await webhook(m, "shop/redact", "{ \"shop_id\": 1 }");
  check("H7. shop/redact removes the shop's connection too", rw.status === 200 && m.db.t.member_store_connections.indexOf(again) === -1 && m.db.t.member_store_connections.length === 1, rw.status);
  const c3 = shopifyConn(m.db, {});
  shopifyItem(m.db, c3);
  const rr = await webhook(m, "customers/redact", "{ \"customer\": { \"id\": 1 } }");
  const rd = await webhook(m, "customers/data_request", "{ \"customer\": { \"id\": 1 } }");
  check("H8. customers/redact and customers/data_request: 200, recorded and processed, and nothing else touched",
    rr.status === 200 && rd.status === 200 && m.db.t.member_store_connections.indexOf(c3) !== -1 && m.db.t.inventory_items.some(function (i) { return i.store_connection_id === c3.id; }) &&
    m.db.t.shopify_webhook_events.filter(function (e) { return /^customers\//.test(e.topic) && e.processed_at; }).length === 2);
  const n = m.db.t.shopify_webhook_events.length;
  rw = await webhook(m, "orders/create", "{}");
  check("H9. a topic BizForce did not subscribe to: 200 ignored, nothing recorded", rw.status === 200 && rw.body.ignored === true && m.db.t.shopify_webhook_events.length === n);
  m.db.t.shopify_webhook_events.push({ id: uuid(), webhook_id: "retry-1", topic: "app/uninstalled", shop_domain: SHOP, received_at: new Date().toISOString(), processed_at: null });
  rw = await webhook(m, "app/uninstalled", "{}", { id: "retry-1" });
  check("H10. a delivery recorded but not processed last time (a failure) is processed on redelivery",
    rw.status === 200 && !rw.body.duplicate && m.db.t.member_store_connections.indexOf(c3) === -1 &&
    m.db.t.shopify_webhook_events.filter(function (e) { return e.webhook_id === "retry-1"; })[0].processed_at !== null);
  check("H11. no webhook body in any log line", m.logs.join("\n").indexOf("690933842") === -1);
  db = makeDb();
  db.t.shopify_webhook_events.push({ id: uuid(), webhook_id: "old", topic: "app/uninstalled", shop_domain: SHOP, received_at: new Date(NOW - 31 * 86400000).toISOString(), processed_at: null });
  db.t.shopify_webhook_events.push({ id: uuid(), webhook_id: "new", topic: "app/uninstalled", shop_domain: SHOP, received_at: new Date(NOW - 29 * 86400000).toISOString(), processed_at: null });
  const pg = await SA.webhookEventsPurgeTick(db, NOW);
  const pg2 = await SA.webhookEventsPurgeTick(db, NOW + 3600000);
  check("H12. the purge deletes receipts older than 30 days and keeps the rest, claimed once a day through job_runs",
    pg.claimed === true && pg.deleted === 1 && db.t.shopify_webhook_events.length === 1 && db.t.shopify_webhook_events[0].webhook_id === "new" &&
    db.t.job_runs.length === 1 && db.t.job_runs[0].job_name === "shopify_webhook_events_purge" && pg2.claimed === false, J([pg, pg2]));
  check("H13. the 04:45 UTC chain runs it", FILES.server.indexOf("return require(\"./lib/shopifyAuth\").webhookEventsPurgeTick(supabase);") !== -1);

  /* ── L ── */
  console.log("\n══ L. locations ══");
  m = mountRoutes({ env: CONFIGURED, shop: { locations: [{ id: LOCATION, name: "Main warehouse", isActive: true }, { id: LOCATION2, name: "Pop-up", isActive: true },
    { id: "gid://shopify/Location/73", name: "Closed", isActive: false }] } });
  const lc = writableConn(m.db, { location_id: null, location_name: null });
  let rl = await hit(m, "get /api/store/connections/:id/locations", { params: { id: lc.id } });
  check("L1. the shop's active locations, read live", rl.status === 200 && J(rl.body.locations) === J([{ id: LOCATION, name: "Main warehouse" }, { id: LOCATION2, name: "Pop-up" }]) &&
    rl.body.location_id === null && m.shop.ops("ShopInfo").length === 1, rl.status);
  rl = await hit(m, "put /api/store/connections/:id/location", { params: { id: lc.id }, body: { location_id: LOCATION2 } });
  check("L2. choosing one from the list: saved, and the note says where stock changes apply and what the sync reads",
    rl.status === 200 && lc.location_id === LOCATION2 && lc.location_name === "Pop-up" && rl.body.note === "Stock changes apply at Pop-up. The next sync reads stock at Pop-up." &&
    rl.body.connection.stock_scope === "location", rl.status);
  rl = await hit(m, "put /api/store/connections/:id/location", { params: { id: lc.id }, body: { location_id: "gid://shopify/Location/99" } });
  const rClosed = await hit(m, "put /api/store/connections/:id/location", { params: { id: lc.id }, body: { location_id: "gid://shopify/Location/73" } });
  check("L3. a location not among the shop's active ones (unknown, or inactive): 400 location_unknown, nothing changed",
    rl.status === 400 && rl.body.code === "location_unknown" && rClosed.status === 400 && lc.location_id === LOCATION2, J([rl.status, rClosed.status]));
  rl = await hit(m, "put /api/store/connections/:id/location", { params: { id: lc.id }, body: { location_id: "Main warehouse" } });
  check("L4. a location_id that is not a Location gid: 400, nothing asked", rl.status === 400 && rl.body.code === "location");
  const foreign = writableConn(m.db, { user_id: OTHER, store_url: OTHER_SHOP });
  rl = await hit(m, "get /api/store/connections/:id/locations", { params: { id: foreign.id } });
  check("L5. another member's connection: 404", rl.status === 404, rl.status);

  /* ── P ── */
  console.log("\n══ P. the pages ══");
  const P = FILES.page;
  check("P1. the Store Agent page's Shopify lines, word for word",
    P.indexOf("<p class=\"store-quiet\">You approve BizForce on Shopify's own page. BizForce never sees your Shopify password.</p>") !== -1 &&
    P.indexOf("placeholder=\"yourstore.myshopify.com\"") !== -1 &&
    P.indexOf("<label class=\"store-allow\"><input type=\"checkbox\" id=\"storeShopifyAllow\" /> Let BizForce make changes I approve (prices and stock)</label>") !== -1 &&
    P.indexOf("<button type=\"button\" class=\"action-btn\" id=\"storeShopifyBtn\">Connect Shopify</button>") !== -1 &&
    P.indexOf("<p class=\"store-msg\" id=\"storeShopifyUnset\" hidden>Shopify connection isn't set up yet.</p>") !== -1 &&
    !/shpat_|Admin API access token/i.test(P));
  const q = "?code=" + CODE + "&hmac=" + "f".repeat(64) + "&host=aG9zdA&shop=" + SHOP + "&state=" + "S".repeat(43) + "&timestamp=1794052800";
  let dom = runPage(q, listAnswers());
  await flush();
  const fz = dom.fetches.filter(function (f) { return f.path === "/api/store/shopify/finish"; });
  check("P2. back from Shopify: the whole callback query is POSTed to /api/store/shopify/finish, as Shopify sent it",
    fz.length === 1 && fz[0].method === "POST" && J(fz[0].body) === J({ params: { code: CODE, hmac: "f".repeat(64), host: "aG9zdA", shop: SHOP, state: "S".repeat(43), timestamp: "1794052800" } }));
  const fi = dom.events.indexOf("fetch:POST /api/store/shopify/finish"), ri = dom.events.indexOf("replaceState:/store-agent.html");
  check("P3. ...the address bar is cleared with replaceState once the answer is in, then the list is loaded",
    ri > fi && fi !== -1 && dom.events.indexOf("fetch:GET /api/store/connections") > ri, dom.events.join(","));
  check("P4. ...and the member is told, with textContent", dom.els.storeConnectMsg.textContent === "Connected to " + SHOP + ". Press \"Sync now\" to read your products, stock and orders.",
    dom.els.storeConnectMsg.textContent);
  const box = dom.els.storeConnections.textContent;
  check("P5. the connection shows its currency, where stock changes apply and what the stock counts",
    box.indexOf("Currency: CAD") !== -1 && box.indexOf("Stock changes apply at Main warehouse.") !== -1 && box.indexOf("Stock shown is what is available at Main warehouse.") !== -1 &&
    box.indexOf("Changes allowed with your approval") !== -1, box.slice(0, 200));
  dom = runPage(q, listAnswers({ "POST /api/store/shopify/finish": { status: 400, body: INVALID } }));
  await flush();
  check("P6. a refused finish: the server's message shown as written, and the address bar cleared all the same",
    dom.els.storeConnectMsg.textContent === INVALID.error && /err/.test(dom.els.storeConnectMsg.className) && dom.events.indexOf("replaceState:/store-agent.html") !== -1);
  dom = runPage(q, listAnswers({ "POST /api/store/shopify/finish": "reject" }));
  await flush();
  check("P7. the request failing: \"The request failed. Nothing was saved.\", and the address bar cleared",
    dom.els.storeConnectMsg.textContent === "The request failed. Nothing was saved." && dom.events.indexOf("replaceState:/store-agent.html") !== -1);
  dom = runPage("?hmac=" + "e".repeat(64) + "&host=aG9zdA&shop=" + SHOP + "&timestamp=1794052800", listAnswers());
  await flush();
  check("P8. Shopify opening the app's URL (?shop and ?hmac, no code): the shop filled in, \"Press Connect Shopify to finish connecting.\", nothing POSTed, the address bar cleared",
    dom.els.storeShop.value === SHOP && dom.els.storeConnectMsg.textContent === "Press Connect Shopify to finish connecting." &&
    !dom.fetches.some(function (f) { return f.method === "POST"; }) && dom.events.indexOf("replaceState:/store-agent.html") !== -1);
  dom = runPage("", listAnswers({ "GET /api/store/connections": { status: 200, body: { connections: [], note: "", shopify_available: false } } }));
  await flush();
  check("P9. the app not set up: Connect Shopify disabled and \"Shopify connection isn't set up yet.\" shown",
    dom.els.storeShopifyBtn.disabled === true && dom.els.storeShopifyUnset.hidden === false && dom.els.storeShopifyUnset.textContent === "Shopify connection isn't set up yet.");
  dom = runPage("", listAnswers());
  await flush();
  dom.get("storeShop").value = SHOP; dom.get("storeShopifyAllow").checked = true;
  dom.get("storeShopifyBtn").click();
  await flush();
  const sf = dom.fetches.filter(function (f) { return f.path === "/api/store/shopify/start"; })[0];
  check("P10. Connect Shopify posts the shop and the box to start and goes to the page it answers",
    !!sf && J(sf.body) === J({ shop: SHOP, allow_changes: true }) && dom.assigned.length === 1 && dom.assigned[0].indexOf("https://" + SHOP + "/admin/oauth/authorize") === 0);
  check("P11. no innerHTML anywhere: nothing set with it in any of these runs, and neither script assigns it",
    dom.innerHTML.length === 0 && !/\.innerHTML\s*=/.test(FILES.ui) && !/\.innerHTML\s*=/.test(FILES.changesUi));
  check("P12. the Store changes panel shows the store's currency with a price",
    FILES.changesUi.indexOf("\"Store price: \" + priceText(shownPrice, conn.currency)") !== -1 && FILES.changesUi.indexOf("currency ? \"New price (\" + currency + \")\" : \"New price\"") !== -1);

  /* ── G ── */
  console.log("\n══ G. the pasted-token path, the mailbox states, legal, registries ══");
  m = mountRoutes({ env: CONFIGURED });
  r = await hit(m, "post /api/store/connections", { body: { platform: "shopify", store_url: SHOP, access_token: TOKEN } });
  check("G1. the pasted-token path is gone: a Shopify body answers 400 \"Use Connect Shopify on the Store Agent page.\", nothing asked or stored",
    r.status === 400 && r.body.code === "use_connect_shopify" && r.body.error === "Use Connect Shopify on the Store Agent page." && m.shop.calls.length === 0 &&
    m.db.t.member_store_connections.length === 0, J([r.status, r.body.code]));
  check("G2. lib/storeSync.js keeps no Shopify token check (no access_scopes.json, no shpat_)", !/access_scopes\.json|shpat_/.test(stripComments(FILES.sync)));
  check("G3. the mailbox disconnect deletes only its own sign-in states (purpose mailbox_microsoft), never a Connect Shopify in progress",
    FILES.server.indexOf("var statesDropped = await supabase.from(\"oauth_states\").delete().eq(\"user_id\", req.user.id).eq(\"purpose\", \"mailbox_microsoft\");") !== -1);
  /* NAMED (Nov 8 2026, Etsy store connection, migration 181): BEFORE "a Shopify or WooCommerce store", "for Shopify, the access
     you approve when you connect" and "uninstall BizForce from Shopify, or delete your account". AFTER the three replacements the
     Etsy brief decided, word for word, and nothing else changed. */
  /* NAMED (Nov 8 2026, Amazon store connection, migration 182): BEFORE "a Shopify, WooCommerce or Etsy store", "for Shopify or Etsy,
     the access you approve" and "remove it from your Etsy account, or delete your account". AFTER the three replacements the Amazon
     brief decided, word for word, and nothing else changed. */
  const PRIVACY = "If you connect a Shopify, WooCommerce, Etsy or Amazon store, BizForce stores the store's address and the access it is given, encrypted (for WooCommerce, " +
    "the key you made for it; for Shopify, Etsy or Amazon, the access you approve when you connect), and reads from the store only your products (name, SKU, price, " +
    "cost where the store has one), your stock levels, your store's currency and location names, and summaries of your orders (each order's number, " +
    "date, total, currency, and its items as SKU and quantity), never any customer's name, email, address or phone number; BizForce changes a " +
    "product's price or stock level in your store only when you approve that change, and only if you allowed changes when you connected the store, " +
    "and it keeps a record of each change (the item, the old and new value, and when). What it reads is used only for your own agents, the store's " +
    "key or access is never shown back to you or exported, and it, the products, the stock, the order summaries and the record of changes are " +
    "deleted when you disconnect the store, uninstall BizForce from Shopify, remove it from your Etsy account or Amazon Seller Central, or delete your account.";
  const esc = function (t) { return String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"); };
  check("G4. the privacy sentence is word for word the decided one, held whole in lib/legalPages.js", LP.STORE_PRIVACY_SENTENCE === PRIVACY);
  check("G5. privacy.html carries it once, as built", FILES.privacy.split(esc(PRIVACY)).length === 2);
  const LEGAL = realRequire("./lib/legal");
  // NAMED (Nov 8 2026, Etsy store connection, migration 181): BEFORE Nov 7 2026. AFTER the privacy sentence changed again (Etsy), so
  // the terms date is Nov 8 2026 by the rule in lib/legal.js.
  check("G6. TERMS_VERSION and TERMS_UPDATED are Nov 8 2026", LEGAL.TERMS_VERSION === "2026-11-08" && LEGAL.TERMS_UPDATED === "Last updated November 8, 2026", LEGAL.TERMS_VERSION);
  // NAMED (Nov 7 2026, YouTube uploads, migration 177): the sign-in states line now also names Connect YouTube;
  // Connect Shopify is still required in it.
  // NAMED (Nov 7 2026, TikTok posting, migration 178): BEFORE "..., Connect Shopify and Connect YouTube". AFTER the line
  // names Connect TikTok last; Connect Shopify is still required in it.
  // NAMED (Nov 7 2026, Instagram posting, migration 179): BEFORE "..., Connect YouTube and Connect TikTok". AFTER the line names
  // Connect Instagram last; Connect Shopify is still required in it.
  // NAMED (Nov 7 2026, item 8 part 3b, Facebook Pages): BEFORE "..., Connect TikTok and Connect Instagram". AFTER the line names Connect Facebook last; Connect
  // Shopify is still required in it.
  // NAMED (Nov 8 2026, Etsy store connection, migration 181): BEFORE "..., Connect Instagram and Connect Facebook". AFTER the line names
  // Connect Etsy last (all seven sign-ins); Connect Shopify is still required in it.
  // NAMED (Nov 8 2026, Amazon store connection, migration 182): BEFORE "..., Connect Facebook and Connect Etsy". AFTER the line
  // names Connect Amazon last (all eight sign-ins); Connect Shopify is still required in it.
  check("G7. yourData: the sign-in states name Connect Shopify (and Connect YouTube, Connect TikTok, Connect Instagram, Connect Facebook, Connect Etsy and Connect Amazon), the receipts are not member data, and Shopify is a third party",
    FILES.yourData.indexOf("Temporary sign-in states for Sign in with Microsoft, Connect Shopify, Connect YouTube, Connect TikTok, Connect Instagram, Connect Facebook, Connect Etsy and Connect Amazon") !== -1 &&
    FILES.yourData.indexOf("shopify_webhook_events: \"Shopify's notifications about app installs and privacy requests, kept 30 days\"") !== -1 &&
    FILES.yourData.indexOf("{ name: \"Shopify\", for: \"connecting your Shopify store, reading it and making the changes you approve, when you connect one\" }") !== -1);
  check("G8. README: the two env vars, the Shopify app setup section and the webhook address",
    /\|\s*`?SHOPIFY_CLIENT_ID`?\s*\|/.test(FILES.readme) && /\|\s*`?SHOPIFY_CLIENT_SECRET`?\s*\|/.test(FILES.readme) && FILES.readme.indexOf("## Shopify app setup") !== -1 &&
    FILES.readme.indexOf("/api/webhooks/shopify") !== -1);
  const SC = realRequire("./lib/schemaCheck");
  check("G9. the registries: SCHEMA_TABLES has shopify_webhook_events at 176, the backup leaves it out as receipts kept 30 days",
    SC.SCHEMA_TABLES.some(function (e) { return e[0] === "shopify_webhook_events" && e[1] === "176_shopify_oauth.sql"; }) &&
    FILES.backup.indexOf("shopify_webhook_events: \"Shopify notification receipts, kept 30 days\"") !== -1);
  check("G10. the receipts table has RLS on and nothing granted to anon or authenticated",
    FILES.migration176.indexOf("ALTER TABLE public.shopify_webhook_events ENABLE ROW LEVEL SECURITY;") !== -1 &&
    FILES.migration176.indexOf("REVOKE ALL ON public.shopify_webhook_events FROM anon, authenticated;") !== -1);
  const migFiles = fs.readdirSync(path.join(REPO, "supabase", "migrations")).filter(function (f) { return /^\d{3}_.*\.sql$/.test(f); });
  const highest = migFiles.map(function (f) { return Number(f.slice(0, 3)); }).reduce(function (a, x) { return Math.max(a, x); }, 0);
  /* NAMED (Nov 7 2026, YouTube uploads, migration 177): BEFORE "176_shopify_oauth.sql is the highest migration, and the only
     176". AFTER it is the only 176, and every migration but 177_youtube_uploads.sql is 176 or lower; "the highest" is
     checkYoutubeUploads R1's, for 177. */
  /* NAMED (Nov 7 2026, TikTok posting, migration 178): BEFORE the highest was 177 and only 177_youtube_uploads.sql was
     above 176. AFTER the highest is 178 and 178_tiktok_posting.sql is above 176 too, by name; "the highest" is
     checkTiktokPosting R1's, for 178. */
  /* NAMED (Nov 7 2026, Instagram posting, migration 179): BEFORE the highest was 178. AFTER the highest is 179 and
     179_instagram_posting.sql is above 176 too, by name; "the highest" is checkInstagramPosting R1's, for 179. */
  /* NAMED (Nov 7 2026, Facebook Pages posting, migration 180): BEFORE the highest was 179. AFTER the highest is 180 and
     180_facebook_pages.sql is above 176 too, by name; "the highest" is checkFacebookPages R1's, for 180. */
  /* NAMED (Nov 8 2026, Etsy store connection, migration 181): BEFORE the highest was 180. AFTER the highest is 181 and
     181_etsy_store.sql is above 176 too, by name; "the highest" is checkEtsyConnect R1's, for 181. */
  /* NAMED (Nov 8 2026, Amazon store connection, migration 182): BEFORE the highest was 181. AFTER the highest is 182 and
     182_amazon_store.sql is above 176 too, by name; "the highest" is checkAmazonConnect R1's, for 182. */
  // NAMED (Nov 11 2026, orbit stage 2), migration 183): it adds 183_weekly_goal_and_order_status.sql above, by name; "the highest" is checkOrbitStage2 R1's.
  check("G11. R1. 176_shopify_oauth.sql is the only 176, and every migration but 177_youtube_uploads.sql, 178_tiktok_posting.sql, 179_instagram_posting.sql, 180_facebook_pages.sql, 181_etsy_store.sql, 182_amazon_store.sql and 183_weekly_goal_and_order_status.sql is 176 or lower (checkOrbitStage2 R1)",
    highest === 183 && migFiles.filter(function (f) { return /^177_/.test(f); }).join() === "177_youtube_uploads.sql" &&
    migFiles.filter(function (f) { return /^178_/.test(f); }).join() === "178_tiktok_posting.sql" &&
    migFiles.filter(function (f) { return /^179_/.test(f); }).join() === "179_instagram_posting.sql" &&
    migFiles.filter(function (f) { return /^180_/.test(f); }).join() === "180_facebook_pages.sql" &&
    migFiles.filter(function (f) { return /^181_/.test(f); }).join() === "181_etsy_store.sql" &&
    migFiles.filter(function (f) { return /^182_/.test(f); }).join() === "182_amazon_store.sql" &&
    migFiles.filter(function (f) { return /^183_/.test(f); }).join() === "183_weekly_goal_and_order_status.sql" &&
    migFiles.filter(function (f) { return f !== "177_youtube_uploads.sql" && f !== "178_tiktok_posting.sql" && f !== "179_instagram_posting.sql" && f !== "180_facebook_pages.sql" && f !== "181_etsy_store.sql" && f !== "182_amazon_store.sql" && f !== "183_weekly_goal_and_order_status.sql"; }).every(function (f) { return Number(f.slice(0, 3)) <= 176; }) &&
    migFiles.filter(function (f) { return /^176_/.test(f); }).join() === "176_shopify_oauth.sql",
    highest);
  const fresh = { "lib/shopifyAuth.js": FILES.auth, "lib/shopifyApi.js": FILES.api, "176_shopify_oauth.sql": FILES.migration176, "scripts/store-connect.js": FILES.ui,
    "store-agent.html": FILES.page, "scripts/checkShopifyConnect.js": fs.readFileSync(__filename, "utf8") };
  check("G12. no emoji in any new or edited Shopify file", Object.keys(fresh).every(function (k) { return !EMOJI.test(fresh[k]); }),
    Object.keys(fresh).filter(function (k) { return EMOJI.test(fresh[k]); }).join(", "));

  check("nothing reached the network: no socket, no real DNS question and no fetch in this whole run (the tripwire)", TRIPPED.length === 0, TRIPPED.join(", "));
  check("no unhandled rejection", UNHANDLED.length === 0, UNHANDLED.map(String).join("; "));
  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(function (e) { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
