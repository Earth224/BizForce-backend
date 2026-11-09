/* checkEtsyConnect: Etsy as the third store on the Store agent (migration 181, lib/etsyAuth.js, lib/etsyApi.js).

   WHAT IT PROVES. No request leaves this process and nothing calls Etsy: Etsy is a fake behind lib/guardedFetch.js's
   REAL JSON mode (only its DNS answer and its https.request are stood in), the database is a fake that enforces
   migration 181's CHECKs and its one-shop-one-member index, and a network tripwire fails the run if anything opens a
   socket, asks real DNS or fetches.

     A. SIGN-IN (lib/etsyAuth.js). x-api-key is "<keystring>:<shared secret>" on every request, the token endpoint
        included; the token endpoint gets JSON, never a form; PKCE is S256; Etsy's authorize page gets response_type,
        client_id, the redirect, the space-separated scopes (listings_w only with changes allowed), state and the
        challenge.
     B. THE ROUTES (server.js, run from its own source). Unconfigured: 503 "Etsy connection isn't set up yet." and
        etsy_available false. Start stores only the state's hash, the verifier sealed and flow_context {permission}.
        Finish spends the state once, exchanges the code with the verifier, seals both tokens before Etsy's API is
        asked anything, reads users/me and the shop, and stores the shop id, the shop's address and currency and the
        granted scopes (from the token answer, or the asked set when it lists none). One Etsy shop, one member: 409.
     C. THE SYNC. Listings paged by offset (40 pages at most), each listing's inventory, a listing without variations
        as "listing:<id>" and a variation as "listing:<id>:<value_ids sorted>", stable when Etsy reorders properties
        and renumbers products; a disabled offering and an over-long id skipped; receipts reduced to number, time,
        total, currency and SKU and quantity before anything else touches them; the shop's currency; 429 waited out.
     D. TOKENS. A refresh within 5 minutes of expiry; the new pair saved together in one compare-and-set update on
        token_version; the loser of a race uses the winner's token; one refresh at a time; a refused refresh, or one
        past refresh_expires_at, marks needs_reconnect with one notice.
     E. CHANGES. Only with listings_w granted; stock 0 to 999; a live read right before the write is the
        compare-and-set; the PUT carries the whole inventory with only the targets changed; it is sent once, never
        retried; one confirming read must show the targets changed and nothing else, or "Etsy shows other changes on
        this listing. Check it on Etsy before filing again."; a value that applies to every variation is written to
        all of them, with the note; replay writes nothing.
     F. THE PAGES. The Store page's Etsy block word for word, the button disabled when unconfigured, the return
        marker (an Etsy return needs it; code and state without it ask to start again; replaceState always), a
        Shopify return still known by its shop and hmac, textContent only; the Approvals card names Etsy, escaped;
        the guide's Store tip names Etsy and the Storefront tips never do.
     G. THE WORDS AND THE REGISTRIES. The privacy sentence word for word, THIRD_PARTIES, the export lines, the terms
        version, the README, the route lists, the migration as run and 181 the highest (R1), no new env var, no emoji.

   MUTATIONS: MUTATE=<name> applies one in memory; MUTATE=all runs each in its own process (see MUTATIONS below).
*/
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
const read = (f) => fs.readFileSync(path.join(REPO, f), "utf8").replace(/\r\n/g, "\n");
const readFe = (f) => fs.readFileSync(path.join(FE, f), "utf8").replace(/\r\n/g, "\n");

/* name -> list of [file key, anchor (exactly once), replacement] */
const MUTATIONS = {
  "header-without-secret": [["auth", "  return String(config.keystring) + \":\" + String(config.sharedSecret);", "  return String(config.keystring);"]],
  "form-token-exchange": [["auth",
    "      { method: \"POST\", headers: { \"x-api-key\": apiKeyHeader(config) }, body: body, timeoutMs: TOKEN_TIMEOUT_MS });",
    "      { method: \"POST\", headers: { \"x-api-key\": apiKeyHeader(config) }, body: body, form: true, timeoutMs: TOKEN_TIMEOUT_MS });"]],
  "pkce-plain": [["auth",
    "function challengeFor(verifier) { return base64url(crypto.createHash(\"sha256\").update(String(verifier), \"ascii\").digest()); }",
    "function challengeFor(verifier) { return String(verifier); }"]],
  "state-reusable": [["server", ".is(\"consumed_at\", null).gt(\"expires_at\", spentAt)", ".gt(\"expires_at\", spentAt)"]],
  "unsealed-before-call": [["server",
    "      // Sealed first: both tokens are encrypted before Etsy's API is asked anything.\n",
    "      await deps.jsonRequest(eapi.API_BASE + \"/users/me\", { method: \"GET\", headers: { \"x-api-key\": ea.apiKeyHeader(etsyConfig), \"Authorization\": \"Bearer \" + etsyGrant.accessToken } });\n"]],
  "second-member-same-shop": [["server", "      if (heldRows.some(function (r) { return r.user_id !== req.user.id; })) {", "      if (false) {"]],
  "refresh-pair-split": [["api",
    "    credentials_ciphertext: sealedRefresh.credentials_ciphertext, credentials_iv: sealedRefresh.credentials_iv, credentials_auth_tag: sealedRefresh.credentials_auth_tag,\n", ""]],
  "refresh-cas-missing": [["api", "    .eq(\"id\", row.id).eq(\"platform\", \"etsy\").eq(\"token_version\", version).select(\"id\");", "    .eq(\"id\", row.id).eq(\"platform\", \"etsy\").select(\"id\");"]],
  "buyer-name-stored": [["api", "    id: digits(r && r.receipt_id) || \"\",\n", "    id: digits(r && r.receipt_id) || \"\",\n    buyer_name: r && r.name,\n"]],
  "buyer-email-stored": [["api",
    "    line_items: tx.map(function (t) { return { sku: t && t.sku ? t.sku : null, quantity: t && t.quantity }; })",
    "    line_items: tx.map(function (t) { return { sku: t && t.sku ? t.sku : null, quantity: t && t.quantity, buyer_email: r && r.buyer_email }; })"]],
  "variation-id-unstable": [["api", "  return ids.sort(function (a, b) { return Number(a) - Number(b) || (a < b ? -1 : a > b ? 1 : 0); });", "  return ids;"]],
  "product-id-as-identity": [["api",
    "  return ids.length ? \"listing:\" + id + \":\" + ids.join(\".\") : \"listing:\" + id;",
    "  return ids.length ? \"listing:\" + id + \":\" + String(product.product_id) : \"listing:\" + id;"]],
  "cas-skipped": [["write", "    var etsyCheck = compareLive(field, from, etsyLive.live);\n", "    var etsyCheck = { ok: true };\n"]],
  "put-changes-others": [["api", "      var target = indexes.indexOf(i) !== -1;", "      var target = true;"]],
  "put-retried": [["write",
    "    etsySent = await EAPI.writeInventory(deps, s, listingId, EAPI.putBodyFor(before, indexes, field, to));\n",
    "    etsySent = await EAPI.writeInventory(deps, s, listingId, EAPI.putBodyFor(before, indexes, field, to));\n" +
    "    if (!etsySent.ok && etsySent.sent) etsySent = await EAPI.writeInventory(deps, s, listingId, EAPI.putBodyFor(before, indexes, field, to));\n"]],
  "confirm-read-skipped": [["write",
    "  try { after = await EAPI.liveInventory(deps, s, listingId); } catch (err) { after = null; }\n" +
    "  if (!after) return { ok: false, code: \"unconfirmed\", error: MESSAGES.unconfirmed };\n" +
    "  if (!EAPI.confirmMatches(before, after, listingId, indexes, field, to)) return { ok: false, code: \"other_changes\", error: MESSAGES.etsyOther };\n", ""]],
  "on-property-partial": [["api", "  products.forEach(function (p, i) { if (groupKey(p, propertyIds) === key) indexes.push(i); });", "  indexes.push(at);"]],
  "quantity-over-cap": [["write",
    "  if (platform === \"etsy\" && field === \"stock\" && v.value > EAPI.QUANTITY_MAX) return { status: 400, body: { error: MESSAGES.etsyStock, code: \"stock_range\", field: \"to\" } };\n", ""]],
  "write-without-permission": [["sync",
    "  if (row.platform === \"etsy\") return ETSY_WRITE_SCOPES.every(function (s) { return granted.indexOf(s) !== -1; }) ? \"read_write\" : \"read\";",
    "  if (row.platform === \"etsy\") return \"read_write\";"]],
  // NAMED (Nov 8 2026, Amazon store connection, migration 182): BEFORE the anchor was the Etsy line and the not-WooCommerce
  // line, adjacent, both removed. AFTER the Amazon line sits between them, so the anchor spans all three and the replacement
  // keeps the Amazon line: Etsy still falls through to WooCommerce, and nothing else changes.
  "etsy-falls-to-woocommerce": [["write",
    "  if (conn.platform === \"etsy\") return readLiveEtsyItem(deps, s, field, item);\n" +
    "  if (conn.platform === \"amazon\") return readLiveAmazonItem(deps, s, field, item);\n" +
    "  if (conn.platform !== \"woocommerce\") return { ok: false, code: \"not_synced\", error: MESSAGES.notSynced };\n",
    "  if (conn.platform === \"amazon\") return readLiveAmazonItem(deps, s, field, item);\n"]],
  "read-sends-put": [["api",
    "      answer = await deps.jsonRequest(API_BASE + path, { method: \"GET\", headers: headersFor(config, token),",
    "      answer = await deps.jsonRequest(API_BASE + path, { method: \"PUT\", headers: headersFor(config, token),"]],
  "wrong-return-marker": [["ui",
    "    if (marker === \"etsy\" && q.get(\"code\") && q.get(\"state\")) { handleEtsyReturn(q); return; }",
    "    if (q.get(\"code\") && q.get(\"state\")) { handleEtsyReturn(q); return; }"]],
  "unconfigured-not-503": [["server",
    "      if (!etsyConfig) return res.status(503).json({ error: ea.MESSAGES.notConfigured, code: \"not_configured\", saved: false });",
    "      if (!etsyConfig) etsyConfig = { keystring: \"\", sharedSecret: \"\" };"]],
  "storefront-mentions-etsy": [["guide",
    "\"\\\"Pricing Strategy\\\" works out the range, median and your margin from comparable listings you type in, then writes a rationale.\",",
    "\"\\\"Pricing Strategy\\\" works out the range, median and your margin from comparable Etsy listings you type in, then writes a rationale.\","]],
  // NAMED (Nov 8 2026, Amazon store connection, migration 182): BEFORE anchored on "...remove it from your Etsy account, or delete
  // your account."; AFTER the sentence names Amazon Seller Central too, so the anchor is the sentence's end as it now reads.
  "privacy-sentence-stale": [["legal",
    "uninstall BizForce from Shopify, remove it from your Etsy account or Amazon Seller Central, or delete your account.\";",
    "uninstall BizForce from Shopify, or delete your account.\";"]],
  "innerHTML-on-page": [["ui", "    if (text !== undefined) e.textContent = text;\n", "    if (text !== undefined) e.innerHTML = text;\n"]],
  // the others the code earns
  "refresh-not-single-flight": [["api", "  var running = refreshesInFlight.get(key);\n", "  var running = null;\n"]],
  "refresh-expiry-ignored": [["api", "  if (row.refresh_expires_at && !(Date.parse(row.refresh_expires_at) > nowMs)) throw new SS.StoreAuthError(\"refresh_expired\");\n", ""]],
  "disabled-offering-synced": [["api", "    if (offering.is_enabled === false) { out.skipped_disabled++; return; }\n", ""]],
  "long-id-kept": [["api", "    if (identity.length > ID_MAX) {", "    if (false) {"]],
  "allow-changes-default-on": [["server",
    "      var etsyPermission = body.allow_changes === true ? \"read_write\" : \"read\";",
    "      var etsyPermission = body.allow_changes === false ? \"read\" : \"read_write\";"]],
  "card-unescaped": [["proposals", "escapeHtml(payload.variations_note)", "payload.variations_note"]],
  "token-user-unchecked": [["server", "        if (!who.user_id || who.user_id !== tokenUser) return", "        if (!who.user_id) return"]],
  "stock-cap-unchecked-at-execution": [["write", "    if (field === \"stock\" && v.value > EAPI.QUANTITY_MAX) throw fail(MESSAGES.etsyStock);\n", ""]],
  "properties-compared-in-order": [["api", "    values: byPropertyId(p.property_values).map(function (pv) {", "    values: (p.property_values || []).map(function (pv) {"]],
  "name-in-etsy-order": [["api", "  byPropertyId(product && product.property_values).forEach(function (pv) {", "  ((product && product.property_values) || []).forEach(function (pv) {"]],
  "target-count-unchecked": [["write",
    "    if (etsyLive.targets.indexes.length !== (Number.isInteger(pl.target_count) ? pl.target_count : 1)) throw fail(MESSAGES.changed);\n", ""]]
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
// Every line this run logs, to prove no secret is in any of them.
const LOGS = [];
["log", "warn", "error"].forEach(function (k) {
  const orig = console[k].bind(console);
  console[k] = function () { const line = [].slice.call(arguments).map(String).join(" "); if (!/^\s+(pass|FAIL)  /.test(line)) LOGS.push(line); orig.apply(null, arguments); };
});

const FILES = {
  server: read("server.js"),
  auth: read("lib/etsyAuth.js"),
  api: read("lib/etsyApi.js"),
  sync: read("lib/storeSync.js"),
  write: read("lib/storeWrite.js"),
  shopifyAuth: read("lib/shopifyAuth.js"),
  shopifyApi: read("lib/shopifyApi.js"),
  legal: read("lib/legalPages.js"),
  yourData: read("lib/yourData.js"),
  backup: read("lib/backup.js"),
  triggers: read("lib/triggers.js"),
  signatures: read("lib/agentSignatures.js"),
  guarded: read("lib/guardedFetch.js"),
  readme: read("README.md"),
  migration: read("supabase/migrations/181_etsy_store.sql"),
  dormant: read("scripts/checkDormantRoutesDeleted.js"),
  surface: read("scripts/checkUnsubscribedSurface.js"),
  privacy: readFe("privacy.html"),
  page: readFe("store-agent.html"),
  ui: readFe("scripts/store-connect.js"),
  changesUi: readFe("scripts/store-changes.js"),
  proposals: readFe("proposals.html"),
  guide: readFe("scripts/termaximus-guide.js"),
  session: readFe("scripts/bf-session.js"),
  profile: readFe("scripts/agent-profile.js")
};
if (MUTATE) {
  MUTATIONS[MUTATE].forEach(function (m) { FILES[m[0]] = MUT.replaceOnce(FILES[m[0]], m[1], m[2], MUTATE); });
  console.log("\n!! MUTATION: " + MUTATE);
}

const J = JSON.stringify;
const SECRET_HEX = crypto.createHash("sha256").update("checkEtsyConnect").digest("hex");
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
const EA = compile(FILES.auth, "lib/etsyAuth.js", {});
const EAPI = compile(FILES.api, "lib/etsyApi.js", { "./storeSync": SS, "./etsyAuth": EA });
const SA = compile(FILES.shopifyAuth, "lib/shopifyAuth.js", {});
const SAPI = compile(FILES.shopifyApi, "lib/shopifyApi.js", { "./storeSync": SS, "./shopifyAuth": SA });
const SW = compile(FILES.write, "lib/storeWrite.js", { "./storeSync": SS, "./shopifyApi": SAPI, "./etsyApi": EAPI });
const LP = compile(FILES.legal, "lib/legalPages.js", {});

const KEY = "checkkeystring" + "7".repeat(10);
const SECRET = "checksharedsecret" + "9".repeat(10);
const CONFIG = { keystring: KEY, sharedSecret: SECRET };
const CONFIGURED = { ETSY_KEYSTRING: KEY, ETSY_SHARED_SECRET: SECRET };
const USER = "00000000-0000-4000-8000-000000000001";
const OTHER = "00000000-0000-4000-8000-000000000002";
const ETSY_USER = "424242";
const SHOP_ID = "31415926";
const SHOP_NAME = "WoolAndCo";
const SHOP_URL = "https://www.etsy.com/shop/" + SHOP_NAME;
const TOKEN = ETSY_USER + "." + "a1b2c3d4".repeat(5);
const REFRESH = ETSY_USER + "." + "e5f6a7b8".repeat(5);
const TOKEN2 = ETSY_USER + "." + "c3d4e5f6".repeat(5);
const REFRESH2 = ETSY_USER + "." + "a7b8c9d0".repeat(5);
const WINNER = ETSY_USER + "." + "0f1e2d3c".repeat(5);
const CODE = "etsycode" + "0123abcd".repeat(4);
const REDIRECT = "https://bizforceai.net/store-agent.html";
const READ_SCOPES = "shops_r,listings_r,transactions_r";
const ALL_SCOPES = READ_SCOPES + ",listings_w";
const NOW = Date.parse("2026-11-08T12:00:00.000Z");
const BUYER_EMAIL = "jane.buyer" + "@example.com";
const SECRETS = [TOKEN, REFRESH, TOKEN2, REFRESH2, WINNER, CODE, SECRET, BUYER_EMAIL];
function noSecretIn(text) { return SECRETS.every(function (s) { return String(text).indexOf(s) === -1; }); }
const EMOJI = /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{1F000}-\u{1F2FF}\u{FE0F}]/u;
const HOSTILE = "<img src=x onerror=alert(1)>";
function b64url(buf) { return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function s256(v) { return b64url(crypto.createHash("sha256").update(String(v), "ascii").digest()); }
function stripComments(src) { return String(src).replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, ""); }
function braceMatch(src, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < src.length; i++) { const c = src[i]; if (c === "{") depth++; else if (c === "}") { depth--; if (depth === 0) return i + 1; } }
  return -1;
}
function fnSource(src, name) {
  const a = src.indexOf("function " + name + "(");
  if (a === -1) return "";
  return src.slice(a, braceMatch(src, src.indexOf("{", a)));
}

/* ── an in-memory database with migration 181's rules ───────────────────── */
function uuid() { return crypto.randomUUID(); }
const HEX = /^[0-9a-f]+$/;
function makeDb() {
  const t = { member_store_connections: [], inventory_items: [], inventory_movements: [], store_order_summaries: [], store_change_log: [],
    notifications: [], job_runs: [], oauth_states: [], agent_proposals: [] };
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
      // migration 181: member_store_connections_etsy_shop_key, one Etsy shop, one member
      if (row.platform === "etsy" && others.some(function (r) { return r.platform === "etsy" && r.external_account_id === row.external_account_id; })) return "member_store_connections_etsy_shop_key";
    }
    if (name === "store_order_summaries" && others.some(function (r) { return r.connection_id === row.connection_id && r.external_id === row.external_id; })) return "store_order_summaries_unique";
    if (name === "store_change_log" && row.proposal_id && others.some(function (r) { return r.proposal_id === row.proposal_id; })) return "store_change_log_proposal_key";
    return null;
  }
  function checkViolation(name, row) {
    if (name === "member_store_connections") {
      if (["shopify", "woocommerce", "etsy"].indexOf(row.platform) === -1) return "member_store_connections_platform_check";
      if (!HEX.test(row.credentials_ciphertext || "") || !/^[0-9a-f]{24}$/.test(row.credentials_iv || "") || !/^[0-9a-f]{32}$/.test(row.credentials_auth_tag || "")) return "member_store_connections_ciphertext_check";
      if (row.access_ciphertext != null && !HEX.test(row.access_ciphertext)) return "member_store_connections_access_ciphertext_check";
      if (!(Number.isInteger(row.token_version) && row.token_version >= 0)) return "member_store_connections_token_version_check";
      if (row.granted_scopes != null && !(String(row.granted_scopes).length <= 500 && /^[a-z_,]*$/.test(row.granted_scopes))) return "member_store_connections_scopes_check";
      if (row.currency != null && !/^[A-Z]{3}$/.test(row.currency)) return "member_store_connections_currency_check";
      if (row.external_account_id != null && !/^[0-9]{1,30}$/.test(row.external_account_id)) return "member_store_connections_external_account_check";
      if (["read", "read_write"].indexOf(row.permission) === -1) return "member_store_connections_permission_check";
      const access = row.access_ciphertext != null && row.access_iv != null && row.access_auth_tag != null && row.access_expires_at != null;
      const shapeOk = (row.platform === "shopify" && access && row.external_account_id == null) ||
        (row.platform === "woocommerce" && row.access_ciphertext == null && row.external_account_id == null) ||
        (row.platform === "etsy" && access && row.location_id == null && row.location_name == null && row.external_account_id != null);
      if (!shapeOk) return "member_store_connections_token_shape_check";
    }
    if (name === "inventory_items") {
      const manual = row.source == null && row.store_connection_id == null && row.external_id == null;
      const synced = ["shopify", "woocommerce", "etsy"].indexOf(row.source) !== -1 && row.store_connection_id && row.external_id && String(row.external_id).length <= 100;
      if (!manual && !synced) return "inventory_items_source_check";
    }
    if (name === "store_order_summaries") {
      if (["shopify", "woocommerce", "etsy"].indexOf(row.platform) === -1) return "store_order_summaries_platform_check";
      if (!Array.isArray(row.line_items)) return "store_order_summaries_line_items_check";
    }
    if (name === "store_change_log" && row.currency != null && !/^[A-Z]{3}$/.test(row.currency)) return "store_change_log_currency_check";
    if (name === "oauth_states") {
      if (["mailbox_microsoft", "store_shopify", "youtube_google", "tiktok_login", "instagram_login", "facebook_login", "store_etsy"].indexOf(row.purpose) === -1) return "oauth_states_purpose_check";
      if (["store_shopify", "store_etsy"].indexOf(row.purpose) !== -1 !== (row.flow_context != null)) return "oauth_states_context_check";
      if (row.flow_context != null && Buffer.byteLength(J(row.flow_context)) > 1000) return "oauth_states_context_check";
      if (row.purpose === "store_etsy" && (row.verifier_ciphertext == null || row.verifier_iv == null || row.verifier_auth_tag == null)) return "oauth_states_verifier_shape_check";
    }
    return null;
  }
  function defaults(name, row) {
    const now = new Date().toISOString();
    const r = Object.assign({ id: uuid(), created_at: now }, row);
    if (name === "member_store_connections") {
      if (r.status === undefined) r.status = "connected";
      if (r.token_version === undefined) r.token_version = 0;
      ["access_ciphertext", "access_iv", "access_auth_tag", "access_expires_at", "refresh_expires_at", "granted_scopes", "location_id", "location_name", "currency", "external_account_id"].forEach(function (k) { if (r[k] === undefined) r[k] = null; });
    }
    if (name === "inventory_items") { if (r.status === undefined) r.status = "active"; ["source", "store_connection_id", "external_id", "external_parent_id", "external_inventory_item_id", "unit_cost"].forEach(function (k) { if (r[k] === undefined) r[k] = null; }); }
    if (name === "oauth_states" && r.consumed_at === undefined) r.consumed_at = null;
    return r;
  }
  function project(r, cols) {
    if (!cols || cols.trim() === "*") return Object.assign({}, r);
    const o = {};
    cols.split(",").map(function (c) { return c.trim(); }).forEach(function (c) { o[c] = r[c] === undefined ? null : r[c]; });
    return o;
  }
  function from(name) {
    const q = { op: null, cols: null, count: false, head: false, filters: [], payload: null, onConflict: null, single: null, range: null, returning: false };
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
      or: function () { return api; }, order: function () { return api; }, limit: function () { return api; },
      range: function (a, b) { q.range = [a, b]; return api; },
      maybeSingle: function () { q.single = "maybe"; return api; },
      single: function () { q.single = "one"; return api; },
      then: function (ok, bad) { return Promise.resolve().then(run).then(ok, bad); }
    };
    function match(r) {
      return q.filters.every(function (f) {
        if (f[0] === "eq") return String(r[f[1]]) === String(f[2]);
        if (f[0] === "in") return f[2].map(String).indexOf(String(r[f[1]])) !== -1;
        if (f[0] === "is") return f[2] === null ? r[f[1]] == null : r[f[1]] === f[2];
        if (f[0] === "gt") return r[f[1]] != null && String(r[f[1]]) > String(f[2]);
        if (f[0] === "gte") return r[f[1]] != null && String(r[f[1]]) >= String(f[2]);
        if (f[0] === "lt") return r[f[1]] != null && String(r[f[1]]) < String(f[2]);
        return true;
      });
    }
    function shape(list) {
      const data = list.map(function (r) { return project(r, q.cols); });
      if (q.single === "maybe") return { data: data[0] || null, error: null };
      if (q.single === "one") return data.length === 1 ? { data: data[0], error: null } : { data: null, error: { code: "PGRST116", message: "not one row" } };
      return { data: q.op === "select" || q.returning ? data : null, error: null };
    }
    function run() {
      log.push({ table: name, op: q.op, payload: q.payload, filters: q.filters.slice() });
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
        return shape(hit);
      }
      return { data: null, error: { message: "fake: no op" } };
    }
    return api;
  }
  return { from: from, t: t, log: log };
}

/* ── Etsy, stubbed behind the real guarded fetcher ─────────────────────── */
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
// Properties: size (100: S 513, L 514) and colour (200: Red 52, Blue 53). The value ids are chosen so that a string sort
// ("513" before "52") and a numeric sort (52 before 513) disagree.
function pv(pid, pname, vids, vals) { return { pid: pid, pname: pname, vids: vids, vals: vals }; }
const SIZE_S = pv(100, "Size", [513], ["S"]), SIZE_L = pv(100, "Size", [514], ["L"]), RED = pv(200, "Primary color", [52], ["Red"]), BLUE = pv(200, "Primary color", [53], ["Blue"]);
function freshInventories() {
  return {
    "1001": { title: "Stoneware Mug", products: [{ sku: "MUG-1", pvs: [], price: 1800, qty: 5, enabled: true }], pop: [], qop: [], sop: [] },
    "1002": { title: "Wool Hat", products: [
      { sku: "HAT-S-RED", pvs: [SIZE_S, RED], price: 2500, qty: 3, enabled: true },
      { sku: "HAT-S-BLUE", pvs: [SIZE_S, BLUE], price: 2500, qty: 4, enabled: true },
      { sku: "HAT-L-RED", pvs: [SIZE_L, RED], price: 3000, qty: 2, enabled: true },
      { sku: "HAT-L-BLUE", pvs: [SIZE_L, BLUE], price: 3000, qty: 0, enabled: true }], pop: [100], qop: [100, 200], sop: [100, 200] },
    "1003": { title: "Scarf", products: [
      { sku: "SCARF-RED", pvs: [RED], price: 1200, qty: 6, enabled: true },
      { sku: "SCARF-BLUE", pvs: [BLUE], price: 1200, qty: 1, enabled: false }], pop: [], qop: [200], sop: [200] },
    "1004": { title: "Charm Bracelet", products: [
      { sku: "", pvs: [pv(300, "Charms", Array.from({ length: 20 }, function (_, i) { return 700000 + i; }), ["many"])], price: 900, qty: 9, enabled: true }], pop: [], qop: [], sop: [] }
  };
}
function makeEtsy(opts, events) {
  const o = Object.assign({}, opts || {});
  const ev = events || [];
  const state = { inv: freshInventories(), reads: 0, ids: 9000000, throttled: false, puts: [] };
  const calls = [];
  const asked = [];
  function nextId() { state.ids += 7; return state.ids; }
  function render(listingId) {
    const L = state.inv[listingId];
    state.reads++;
    const flip = state.reads % 2 === 0;   // Etsy may list a product's properties in either order
    return {
      listing_id: Number(listingId),
      products: L.products.map(function (p) {
        const pvs = flip ? p.pvs.slice().reverse() : p.pvs;
        return { product_id: nextId(), sku: p.sku, is_deleted: false,
          property_values: pvs.map(function (v) { return { property_id: v.pid, property_name: v.pname, scale_id: null, scale_name: null, value_ids: v.vids.slice(), values: v.vals.slice() }; }),
          offerings: [{ offering_id: nextId(), quantity: p.qty, is_enabled: p.enabled, is_deleted: false, price: { amount: p.price, divisor: 100, currency_code: "USD" } }] };
      }),
      price_on_property: L.pop.slice(), quantity_on_property: L.qop.slice(), sku_on_property: L.sop.slice()
    };
  }
  function receipts() {
    return { count: 1, results: [{ receipt_id: 777001, receipt_type: 0, seller_user_id: Number(ETSY_USER), buyer_user_id: 88, name: "Jane Buyer", first_line: "1 Main Street",
      city: "Leeds", zip: "LS1", buyer_email: BUYER_EMAIL, message_from_buyer: "Please gift wrap", created_timestamp: Math.floor(NOW / 1000) - 3600,
      grandtotal: { amount: 5500, divisor: 100, currency_code: "USD" },
      transactions: [{ transaction_id: 1, title: "Wool Hat", sku: "HAT-S-RED", quantity: 2, buyer_user_id: 88 }, { transaction_id: 2, title: "Mug", sku: "MUG-1", quantity: 1, buyer_user_id: 88 }] }] };
  }
  function applyPut(listingId, body) {
    const L = state.inv[listingId];
    if (!body || !Array.isArray(body.products) || !Array.isArray(body.price_on_property) || !Array.isArray(body.quantity_on_property) || !Array.isArray(body.sku_on_property)) {
      return reply(400, { error: "products, price_on_property, quantity_on_property and sku_on_property are required" });
    }
    const next = [];
    for (const p of body.products) {
      const off = (p.offerings || [])[0];
      if (typeof p.sku !== "string" || !Array.isArray(p.property_values) || !off || typeof off.price !== "number" || !Number.isInteger(off.quantity) ||
          typeof off.is_enabled !== "boolean" || off.quantity > 999 || "product_id" in p || "offering_id" in off) {
        return reply(400, { error: "invalid product" });
      }
      next.push({ sku: p.sku, pvs: p.property_values.map(function (v) { return pv(v.property_id, v.property_name, v.value_ids, v.values); }),
        price: Math.round(off.price * 100), qty: off.quantity, enabled: off.is_enabled });
    }
    L.products = next; L.pop = body.price_on_property.slice(); L.qop = body.quantity_on_property.slice(); L.sop = body.sku_on_property.slice();
    if (o.putAlsoChange) { const other = L.products.filter(function (p) { return p.sku === o.putAlsoChange; })[0]; if (other) other.qty += 1; }
    return reply(200, render(listingId));
  }
  function answer(url, init) {
    const u = new URL(url);
    const method = (init && init.method) || "GET";
    let body = null;
    try { body = init && init.body ? JSON.parse(String(init.body)) : null; } catch (e) { body = "(not json)"; }
    const auth = headerOf(init && init.headers, "Authorization");
    const call = { url: url, host: u.hostname, path: u.pathname, query: u.searchParams, method: method, body: body, raw: init && init.body,
      apiKey: headerOf(init && init.headers, "x-api-key"), contentType: headerOf(init && init.headers, "Content-Type"), bearer: auth ? auth.replace(/^Bearer /, "") : null };
    calls.push(call);
    if (call.apiKey !== KEY + ":" + SECRET) return reply(403, { error: "Invalid API key" });
    if (u.hostname === "api.etsy.com" && u.pathname === "/v3/public/oauth/token" && method === "POST") {
      if (!/^application\/json/.test(call.contentType || "") || typeof body !== "object" || body === null) return reply(400, { error: "invalid_request", error_description: "form bodies are not read" });
      if (body.grant_type === "refresh_token") {
        ev.push("token:refresh");
        if (o.refresh === "refuse") return reply(400, { error: "invalid_grant" });
        if (o.refresh === "down") return reply(503, { error: "unavailable" });
        if (body.client_id !== KEY) return reply(400, { error: "invalid_client" });
        return reply(200, { access_token: TOKEN2, refresh_token: REFRESH2, expires_in: 3600, token_type: "Bearer" });
      }
      ev.push("token:exchange");
      if (o.exchangeStatus) return reply(o.exchangeStatus, { error: "invalid_grant" });
      if (body.grant_type !== "authorization_code" || body.code !== CODE || body.client_id !== KEY || body.redirect_uri !== REDIRECT ||
          typeof body.code_verifier !== "string" || (o.challenge && s256(body.code_verifier) !== o.challenge)) return reply(400, { error: "invalid_grant" });
      const grant = { access_token: o.tokenUser ? o.tokenUser + "." + "a1b2c3d4".repeat(5) : TOKEN, refresh_token: REFRESH, expires_in: 3600, token_type: "Bearer" };
      if (o.scope !== undefined) grant.scope = o.scope;
      return reply(200, grant);
    }
    if (u.hostname !== "openapi.etsy.com" || u.pathname.indexOf("/v3/application/") !== 0) return reply(404, { error: "no such address" });
    const p = u.pathname.slice("/v3/application".length);
    ev.push("api:" + method + " " + p);
    if (!call.bearer || (o.reject || []).indexOf(call.bearer) !== -1 || [TOKEN, TOKEN2, WINNER].indexOf(call.bearer) === -1) return reply(401, { error: "invalid_token" });
    if (method === "PUT") {
      const m = /^\/listings\/(\d+)\/inventory$/.exec(p);
      state.puts.push({ listing: m && m[1], body: body, contentType: call.contentType });
      if (!m || !state.inv[m[1]]) return reply(404, { error: "not found" });
      if (o.putStatus) return reply(o.putStatus, { error: "server error" });
      return applyPut(m[1], body);
    }
    if (method !== "GET") return reply(405, { error: "method" });
    if (p === "/users/me") return reply(200, { user_id: Number(o.meUser || ETSY_USER), shop_id: o.noShop ? null : Number(SHOP_ID) });
    if (p === "/shops/" + SHOP_ID) return reply(200, { shop_id: Number(SHOP_ID), shop_name: o.shopName || SHOP_NAME, currency_code: "USD", url: SHOP_URL + "?ref=x" });
    if (p === "/shops/" + SHOP_ID + "/listings") {
      if (o.throttleOnce && !state.throttled) { state.throttled = true; return reply(429, { error: "Too many requests" }, { "Retry-After": "2" }); }
      const offset = Number(u.searchParams.get("offset"));
      if (o.endless) return reply(200, { count: 99999, results: Array.from({ length: 100 }, function (_, i) { return { listing_id: 1001, title: "Same", state: "active", i: offset + i }; }) });
      const all = Object.keys(state.inv).map(function (id) { return { listing_id: Number(id), title: state.inv[id].title, state: "active", price: { amount: 1, divisor: 100 } }; });
      return reply(200, { count: all.length, results: all.slice(offset, offset + 100) });
    }
    const inv = /^\/listings\/(\d+)\/inventory$/.exec(p);
    if (inv) { if (!state.inv[inv[1]]) return reply(404, { error: "not found" }); return reply(200, render(inv[1])); }
    if (p === "/shops/" + SHOP_ID + "/receipts") return reply(200, receipts());
    return reply(404, { error: "no stub for " + p });
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
    asked.push({ url: url, method: (options && options.method) || "GET" });
    return guarded(url, options);
  }
  function api(method, pathRe) { return calls.filter(function (c) { return c.host === "openapi.etsy.com" && (!method || c.method === method) && (!pathRe || pathRe.test(c.path)); }); }
  function tokenCalls(kind) { return calls.filter(function (c) { return c.host === "api.etsy.com" && (!kind || (kind === "refresh") === !!(c.body && c.body.grant_type === "refresh_token")); }); }
  return { jsonRequest: jsonRequest, calls: calls, asked: asked, state: state, opts: o, api: api, tokenCalls: tokenCalls };
}

/* THE NETWORK TRIPWIRE: no socket, no real DNS question, no fetch, in this whole run. */
const TRIPPED = [];
(function tripwire() {
  const http = require("http"), https = require("https"), net = require("net"), tls = require("tls"), dns = require("dns");
  function wire(obj, name, label) { obj[name] = function () { TRIPPED.push(label); throw new Error("checkEtsyConnect: " + label + " is not allowed in this check"); }; }
  wire(http, "request", "http.request"); wire(http, "get", "http.get");
  wire(https, "request", "https.request"); wire(https, "get", "https.get");
  wire(net, "connect", "net.connect"); wire(net, "createConnection", "net.createConnection");
  wire(tls, "connect", "tls.connect");
  wire(dns, "lookup", "dns.lookup"); wire(dns, "resolve", "dns.resolve"); wire(dns.promises, "lookup", "dns.promises.lookup");
  globalThis.fetch = function () { TRIPPED.push("fetch"); return Promise.reject(new Error("checkEtsyConnect: fetch is not allowed in this check")); };
})();

/* ── the routes, run from server.js's own source ─────────────────────────── */
function sliceOf(src, start, end) { const a = src.indexOf(start), b = src.indexOf(end, a); return a === -1 || b === -1 ? "" : src.slice(a, b); }
const STORE_SECTION = sliceOf(FILES.server, "/* ── Store connections (migrations 163, 175, 176; lib/storeSync.js) ──────────",
  "// The SEO writer used to answer in JSON, which meant embedding a whole HTML");
function requireAuth() {} function requireActiveSubscription() {}
function mountRoutes(env) {
  env = env || {};
  const db = env.db || makeDb();
  const events = [];
  const etsy = makeEtsy(env.etsy, events);
  const logs = [];
  const routes = {};
  const crypt = {
    encrypt: function (p) {
      events.push(String(p).indexOf(REFRESH) !== -1 ? "encrypt:refresh" : (/^\d+\.[0-9a-f]{40}$/.test(String(p)) ? "encrypt:access" : "encrypt:other"));
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
      if (r === "./lib/guardedFetch") return Object.assign({}, GF, { guardedJsonRequest: etsy.jsonRequest });
      if (r === "./lib/etsyAuth") return EA;
      if (r === "./lib/etsyApi") return EAPI;
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
  vm.createContext(ctx);
  vm.runInContext(STORE_SECTION, ctx, { filename: "server.js (store section)" });
  return { db: db, etsy: etsy, logs: logs, routes: routes, events: events, ctx: ctx };
}
async function hit(m, key, req) {
  const r = m.routes[key];
  const res = { statusCode: 200, body: undefined, headers: {}, set: function (k, v) { this.headers[k] = v; return this; },
    status: function (c) { this.statusCode = c; return this; }, json: function (b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
  let err = null;
  try { await r.handler(Object.assign({ user: { id: USER }, body: {}, params: {} }, req), res, function (e) { err = e || new Error("next"); }); }
  catch (e) { err = e; res.statusCode = 599; }
  if (err && res.statusCode === 200) res.statusCode = 599;
  return { status: res.statusCode, body: res.body || {}, headers: res.headers, err: err };
}
async function begin(m, body, user) {
  const r = await hit(m, "post /api/store/etsy/start", { body: body || {}, user: { id: user || USER } });
  const url = r.body && r.body.authorize_url ? new URL(r.body.authorize_url) : null;
  if (url) m.etsy.opts.challenge = url.searchParams.get("code_challenge");
  return { r: r, url: url, state: url ? url.searchParams.get("state") : null };
}
function finish(m, state, user, code) { return hit(m, "post /api/store/etsy/finish", { body: { code: code || CODE, state: state }, user: { id: user || USER } }); }
const INVALID = { error: "That Etsy connection link has expired or was already used. Start again.", code: "state_invalid", saved: false };

/* lib-level deps and a connected Etsy row */
function libDeps(db, etsy, extra) {
  const sleeps = [];
  return Object.assign({
    supabase: db, env: {}, jsonRequest: etsy.jsonRequest, now: function () { return NOW; },
    sleep: function (ms) { sleeps.push(ms); return Promise.resolve(); }, sleeps: sleeps,
    encrypt: CRYPT.encrypt, decrypt: CRYPT.decrypt,
    etsyReader: EAPI, etsyConfig: function () { return CONFIG; }, shopifyReader: SAPI,
    userPlan: async function () { return { plan: { active: true }, error: null }; }
  }, extra || {});
}
function etsyConn(db, over) {
  const sealed = SS.sealCredentials({ refresh_token: REFRESH }, CRYPT.encrypt);
  const access = CRYPT.encrypt((over && over.__token) || TOKEN);
  const row = Object.assign({ id: uuid(), user_id: USER, platform: "etsy", store_url: SHOP_URL, status: "connected", permission: "read_write",
    access_ciphertext: access.ciphertext, access_iv: access.iv, access_auth_tag: access.authTag,
    access_expires_at: new Date(NOW + 50 * 60 * 1000).toISOString(), refresh_expires_at: new Date(NOW + 80 * 86400000).toISOString(), token_version: 0,
    granted_scopes: ALL_SCOPES, location_id: null, location_name: null, currency: "USD", external_account_id: SHOP_ID, created_at: "2026-11-08T00:00:00.000Z" }, sealed, over || {});
  delete row.__token;
  db.t.member_store_connections.push(row);
  return row;
}
function accessOf(row) { try { return CRYPT.decrypt({ ciphertext: row.access_ciphertext, iv: row.access_iv, authTag: row.access_auth_tag }); } catch (e) { return null; } }
function refreshOf(row) { try { return SS.openCredentials(row, CRYPT.decrypt).refresh_token; } catch (e) { return null; } }
async function attempt(p) { try { return { ok: true, v: await p }; } catch (e) { return { ok: false, msg: e && e.message, name: e && e.name, code: e && e.code }; } }
function itemOf(db, externalId) { return db.t.inventory_items.filter(function (r) { return r.external_id === externalId; })[0]; }
async function synced(over, etsyOpts) {
  const db = makeDb(), etsy = makeEtsy(etsyOpts);
  const conn = etsyConn(db, over);
  const deps = libDeps(db, etsy);
  const r = await SS.syncConnection(deps, conn);
  return { db: db, etsy: etsy, conn: conn, deps: deps, r: r };
}

/* ── the Store page in a fake DOM, with sessionStorage ─────────────────── */
const API = "https://dynamic-prosperity-production-5382.up.railway.app";
const ETSY_VIEW = { id: "22222222-2222-4222-8222-222222222222", platform: "etsy", platform_label: "Etsy", store: SHOP_URL, status: "connected", permission: "read",
  currency: "USD", location_id: null, location_name: null, stock_scope: null, shop_name: SHOP_NAME, connected_since: "2026-11-08T10:00:00Z", last_sync_at: null, last_error_code: null };
function runPage(search, answers, marker) {
  const dom = { els: {}, fetches: [], events: [], innerHTML: [], assigned: [], store: {} };
  if (marker !== undefined) dom.store.bf_store_return = marker;
  function node(tag) {
    const n = { tagName: tag, children: [], _t: "", className: "", hidden: false, disabled: false, value: "", checked: false, type: "", id: "", attrs: {}, listeners: {},
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
  const location = { search: search, assign: function (u) { dom.assigned.push(u); } };
  Object.defineProperty(location, "href", { set: function (u) { dom.assigned.push(u); }, get: function () { return "https://bizforceai.net/store-agent.html" + search; } });
  const sessionStorage = {
    getItem: function (k) { dom.events.push("session:get " + k); return Object.prototype.hasOwnProperty.call(dom.store, k) ? dom.store[k] : null; },
    setItem: function (k, v) { dom.events.push("session:set " + k + "=" + v); dom.store[k] = String(v); },
    removeItem: function (k) { dom.events.push("session:remove " + k); delete dom.store[k]; }
  };
  const window = { location: location, sessionStorage: sessionStorage, history: { replaceState: function (s, t, u) { dom.events.push("replaceState:" + u); } } };
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
    if (p === "/api/store/connections" && method === "GET") return { status: 200, body: { connections: [ETSY_VIEW], note: "", shopify_available: true, etsy_available: true } };
    if (p === "/api/store/etsy/start") return { status: 200, body: { authorize_url: "https://www.etsy.com/oauth/connect?client_id=x", permission: "read", saved: false } };
    if (p === "/api/store/etsy/finish") return { status: 200, body: { saved: true, connection: ETSY_VIEW } };
    if (p === "/api/store/shopify/finish") return { status: 200, body: { saved: true } };
    return { status: 404, body: { error: "Not found" } };
  };
}
function allText(n) { return n ? n.textContent : ""; }

(async function main() {
  let r, m;

  /* ── A. sign-in ─────────────────────────────────────────────────────────── */
  console.log("\n══ A. sign-in (lib/etsyAuth.js) ══");
  check("A1. configured: both ETSY_KEYSTRING and ETSY_SHARED_SECRET, or null", J(EA.configured(CONFIGURED)) === J(CONFIG) && EA.configured({ ETSY_KEYSTRING: KEY }) === null &&
    EA.configured({ ETSY_SHARED_SECRET: SECRET }) === null && EA.configured({}) === null);
  check("A2. x-api-key is \"<keystring>:<shared secret>\"", EA.apiKeyHeader(CONFIG) === KEY + ":" + SECRET);
  const v1 = EA.newVerifier(), st1 = EA.newState();
  check("A3. PKCE is S256: the challenge is base64url(sha256(verifier)), never the verifier; state and verifier are 43 characters",
    EA.challengeFor(v1) === s256(v1) && EA.challengeFor(v1) !== v1 && /^[A-Za-z0-9_-]{43}$/.test(v1) && /^[A-Za-z0-9_-]{43}$/.test(st1) && st1 !== v1);
  const au = new URL(EA.authorizeUrl(CONFIG, "read", REDIRECT, st1, EA.challengeFor(v1)));
  const auw = new URL(EA.authorizeUrl(CONFIG, "read_write", REDIRECT, st1, EA.challengeFor(v1)));
  check("A4. Etsy's authorize page: response_type=code, client_id the keystring, the redirect, space-separated read scopes, state, challenge, S256",
    au.origin + au.pathname === "https://www.etsy.com/oauth/connect" && au.searchParams.get("response_type") === "code" && au.searchParams.get("client_id") === KEY &&
    au.searchParams.get("redirect_uri") === REDIRECT && au.searchParams.get("scope") === "shops_r listings_r transactions_r" && au.searchParams.get("state") === st1 &&
    au.searchParams.get("code_challenge") === s256(v1) && au.searchParams.get("code_challenge_method") === "S256" && /scope=shops_r%20listings_r%20transactions_r&/.test(au.search) &&
    au.search.indexOf(SECRET) === -1, au.search);
  check("A5. ...listings_w only when changes are allowed", auw.searchParams.get("scope") === "shops_r listings_r transactions_r listings_w");
  {
    const e = makeEtsy({}), toks = await attempt(EA.exchangeCode(CONFIG, CODE, v1, REDIRECT, e.jsonRequest));
    const c = e.tokenCalls()[0] || {};
    check("A6. the code exchange is ONE JSON POST to api.etsy.com/v3/public/oauth/token with x-api-key, grant_type, client_id, redirect_uri, code and code_verifier",
      toks.ok && e.tokenCalls().length === 1 && c.method === "POST" && /^application\/json/.test(c.contentType || "") && c.apiKey === KEY + ":" + SECRET &&
      J(Object.keys(c.body || {}).sort()) === J(["client_id", "code", "code_verifier", "grant_type", "redirect_uri"]) && c.body.code_verifier === v1 &&
      toks.v.userId === ETSY_USER && toks.v.scopes === null && toks.v.expiresIn === 3600, J([toks, c.contentType, c.body && Object.keys(c.body)]));
    const e2 = makeEtsy({}), ref = await attempt(EA.refreshTokens(CONFIG, REFRESH, e2.jsonRequest));
    const c2 = e2.tokenCalls()[0] || {};
    check("A7. a refresh is ONE JSON POST with grant_type refresh_token, client_id and refresh_token, x-api-key included, and returns the NEW pair",
      ref.ok && ref.v.accessToken === TOKEN2 && ref.v.refreshToken === REFRESH2 && /^application\/json/.test(c2.contentType || "") && c2.apiKey === KEY + ":" + SECRET &&
      J(Object.keys(c2.body || {}).sort()) === J(["client_id", "grant_type", "refresh_token"]));
    const e3 = makeEtsy({ refresh: "refuse" }), bad = await attempt(EA.refreshTokens(CONFIG, REFRESH, e3.jsonRequest));
    const e4 = makeEtsy({ refresh: "down" }), down = await attempt(EA.refreshTokens(CONFIG, REFRESH, e4.jsonRequest));
    check("A8. a refused refresh is kind rejected; Etsy failing is unreachable; neither error carries a token", !bad.ok && /rejected/.test(bad.msg) && !down.ok && /unreachable/.test(down.msg) &&
      noSecretIn(bad.msg) && noSecretIn(down.msg));
    check("A9. a token answer without the \"<user_id>.\" prefix, a refresh token or expires_in is refused",
      (function () { try { EA.grantFrom({ access_token: "abc", refresh_token: "r", expires_in: 3600 }); return false; } catch (e) { return true; } })() &&
      (function () { try { EA.grantFrom({ access_token: TOKEN, expires_in: 3600 }); return false; } catch (e) { return true; } })() &&
      (function () { try { EA.grantFrom({ access_token: TOKEN, refresh_token: REFRESH }); return false; } catch (e) { return true; } })());
    check("A10. the finish body: a code and a 43-character state, nothing else accepted", EA.finishShape({ code: CODE, state: st1 }).ok === true &&
      EA.finishShape({ code: CODE, state: "short" }).ok === false && EA.finishShape({ code: "a b", state: st1 }).ok === false && EA.finishShape({ state: st1 }).ok === false);
  }

  /* ── B. the routes ──────────────────────────────────────────────────────── */
  console.log("\n══ B. the routes (server.js) ══");
  ["post /api/store/etsy/start", "post /api/store/etsy/finish"].forEach(function (k) {
    const mm = mountRoutes({ env: CONFIGURED }), route = mm.routes[k];
    check("B0. " + k + " is requireAuth, requireActiveSubscription and Connect Shopify's limiter", !!route && route.middleware.length === 3 && route.middleware[0] === requireAuth &&
      route.middleware[1] === requireActiveSubscription && route.middleware[2] === mm.routes["post /api/store/shopify/start"].middleware[2] && !!route.middleware[2].limiter);
  });
  m = mountRoutes({});
  r = await hit(m, "post /api/store/etsy/start", { body: { allow_changes: true } });
  const rf = await hit(m, "post /api/store/etsy/finish", { body: { code: CODE, state: st1 } });
  const rl = await hit(m, "get /api/store/connections", {});
  check("B1. unconfigured: start and finish answer 503 \"Etsy connection isn't set up yet.\"; nothing asked or stored; the list says etsy_available false",
    r.status === 503 && r.body.error === "Etsy connection isn't set up yet." && rf.status === 503 && rf.body.error === "Etsy connection isn't set up yet." &&
    m.etsy.calls.length === 0 && m.db.t.oauth_states.length === 0 && rl.body.etsy_available === false, J([r.status, rf.status, rl.body.etsy_available]));
  m = mountRoutes({ env: CONFIGURED });
  r = await hit(m, "post /api/store/etsy/start", { body: { allow_changes: "yes" } });
  check("B2. allow_changes that is not true or false is refused, nothing stored", r.status === 400 && r.body.code === "allow_changes" && m.db.t.oauth_states.length === 0);
  let b = await begin(m, {});
  const stateRow = m.db.t.oauth_states[0] || {};
  let verifier = null;
  try { verifier = CRYPT.decrypt({ ciphertext: stateRow.verifier_ciphertext, iv: stateRow.verifier_iv, authTag: stateRow.verifier_auth_tag }); } catch (e) { verifier = null; }
  check("B3. start: Etsy's page with the read scopes; only the state's sha256 stored, purpose store_etsy, 10 minutes, flow_context {permission: read}; the verifier sealed and its S256 challenge sent",
    b.r.status === 200 && b.url && b.url.searchParams.get("scope") === "shops_r listings_r transactions_r" && b.url.searchParams.get("redirect_uri") === REDIRECT &&
    m.db.t.oauth_states.length === 1 && stateRow.purpose === "store_etsy" && stateRow.state_hash === crypto.createHash("sha256").update(b.state).digest("hex") &&
    J(stateRow).indexOf(b.state) === -1 && J(stateRow.flow_context) === J({ permission: "read" }) && typeof verifier === "string" && J(stateRow).indexOf(verifier) === -1 &&
    b.url.searchParams.get("code_challenge") === s256(verifier) && Date.parse(stateRow.expires_at) - Date.parse(stateRow.created_at) === 10 * 60 * 1000 &&
    b.r.headers["Cache-Control"] === "no-store" && m.etsy.calls.length === 0, J([b.r.status, stateRow.purpose, stateRow.flow_context]));
  r = await finish(m, b.state);
  const row = m.db.t.member_store_connections[0] || {};
  const firstApi = m.events.findIndex(function (e) { return /^api:/.test(e); });
  check("B4. finish: the code exchanged with the verifier, both tokens sealed BEFORE Etsy's API is asked anything, users/me then the shop read",
    r.status === 200 && r.body.saved === true && m.etsy.tokenCalls("exchange").length === 1 && m.events.indexOf("encrypt:access") !== -1 && m.events.indexOf("encrypt:refresh") !== -1 &&
    firstApi > m.events.indexOf("encrypt:access") && firstApi > m.events.indexOf("encrypt:refresh") &&
    J(m.events.filter(function (e) { return /^api:/.test(e); })) === J(["api:GET /users/me", "api:GET /shops/" + SHOP_ID]), J([r.status, r.body, m.events]));
  check("B5. every request to Etsy carried x-api-key \"<keystring>:<shared secret>\", the token endpoint included", m.etsy.calls.length >= 3 &&
    m.etsy.calls.every(function (c) { return c.apiKey === KEY + ":" + SECRET; }));
  check("B6. the row: platform etsy, the shop id in external_account_id, https://www.etsy.com/shop/<ShopName>, USD, read, the asked scopes (Etsy's answer listed none), tokens sealed",
    row.platform === "etsy" && row.external_account_id === SHOP_ID && row.store_url === SHOP_URL && row.currency === "USD" && row.permission === "read" &&
    row.granted_scopes === READ_SCOPES && accessOf(row) === TOKEN && refreshOf(row) === REFRESH && row.token_version === 0 && J(row).indexOf(TOKEN) === -1 &&
    J(row).indexOf(REFRESH) === -1 && row.location_id === null, J([row.platform, row.external_account_id, row.store_url, row.granted_scopes]));
  check("B7. the answer: the connection's safe fields with the shop name, never a token", r.body.connection && r.body.connection.shop_name === SHOP_NAME && r.body.connection.platform_label === "Etsy" &&
    r.body.connection.permission === "read" && noSecretIn(J(r.body)) && !/ciphertext|_iv|auth_tag/.test(J(r.body)), J(r.body));
  const r2 = await finish(m, b.state);
  check("B8. the state is spent: a second finish with it is the same 400, nothing exchanged again", r2.status === 400 && J(r2.body) === J(INVALID) && m.etsy.tokenCalls("exchange").length === 1, J([r2.status, r2.body]));
  // granted scopes from Etsy's answer, and changes allowed
  m = mountRoutes({ env: CONFIGURED, etsy: { scope: "shops_r listings_r transactions_r listings_w" } });
  b = await begin(m, { allow_changes: true });
  r = await finish(m, b.state);
  check("B9. allow_changes true: listings_w asked; Etsy's listed scopes stored as granted_scopes; permission read_write",
    b.url.searchParams.get("scope") === "shops_r listings_r transactions_r listings_w" && J(m.db.t.oauth_states[0].flow_context) === J({ permission: "read_write" }) &&
    r.status === 200 && m.db.t.member_store_connections[0].granted_scopes === ALL_SCOPES && m.db.t.member_store_connections[0].permission === "read_write" &&
    r.body.connection.permission === "read_write");
  m = mountRoutes({ env: CONFIGURED, etsy: { scope: "shops_r listings_r transactions_r" } });
  b = await begin(m, { allow_changes: true });
  r = await finish(m, b.state);
  check("B10. changes asked but listings_w not granted: 422, nothing stored", r.status === 422 && r.body.code === "scopes_missing" && m.db.t.member_store_connections.length === 0);
  // one Etsy shop, one member
  m = mountRoutes({ env: CONFIGURED });
  b = await begin(m, {}); await finish(m, b.state);
  const firstRow = Object.assign({}, m.db.t.member_store_connections[0]);
  b = await begin(m, {}, OTHER);
  r = await finish(m, b.state, OTHER);
  check("B11. the same Etsy shop for another member: 409 \"This Etsy shop is already connected to another BizForce account.\", the first row untouched",
    r.status === 409 && r.body.error === "This Etsy shop is already connected to another BizForce account." && m.db.t.member_store_connections.length === 1 &&
    J(m.db.t.member_store_connections[0]) === J(firstRow), J([r.status, r.body]));
  b = await begin(m, { allow_changes: true });
  m.etsy.opts.scope = "shops_r listings_r transactions_r listings_w";
  r = await finish(m, b.state);
  check("B12. the same member connecting the same shop again: one row, updated in place with the new access", r.status === 200 && m.db.t.member_store_connections.length === 1 &&
    m.db.t.member_store_connections[0].id === firstRow.id && m.db.t.member_store_connections[0].permission === "read_write", J([r.status, r.body]));
  // the state belongs to its member, and failures
  m = mountRoutes({ env: CONFIGURED });
  b = await begin(m, {});
  r = await finish(m, b.state, OTHER);
  check("B13. another member's state: the same 400, nothing exchanged", r.status === 400 && J(r.body) === J(INVALID) && m.etsy.tokenCalls().length === 0);
  m = mountRoutes({ env: CONFIGURED, etsy: { exchangeStatus: 400 } });
  b = await begin(m, {}); r = await finish(m, b.state);
  const m2 = mountRoutes({ env: CONFIGURED, etsy: { exchangeStatus: 503 } });
  const b2 = await begin(m2, {}); const r3 = await finish(m2, b2.state);
  check("B14. Etsy refusing the code: the same 400 as a bad state; Etsy failing: 502; nothing stored either way",
    r.status === 400 && J(r.body) === J(INVALID) && r3.status === 502 && m.db.t.member_store_connections.length === 0 && m2.db.t.member_store_connections.length === 0);
  m = mountRoutes({ env: CONFIGURED, etsy: { meUser: "999" } });
  b = await begin(m, {}); r = await finish(m, b.state);
  check("B15. users/me naming another user than the token: 502, nothing stored", r.status === 502 && m.db.t.member_store_connections.length === 0, J([r.status, r.body]));
  m = mountRoutes({ env: CONFIGURED, etsy: { noShop: true } });
  b = await begin(m, {}); r = await finish(m, b.state);
  check("B16. an Etsy account with no shop: 422, nothing stored, the shop never asked for", r.status === 422 && r.body.code === "no_shop" && m.db.t.member_store_connections.length === 0 &&
    m.etsy.api("GET", /^\/v3\/application\/shops\//).length === 0);
  m = mountRoutes({ env: CONFIGURED, etsy: { shopName: "Bad Name/../x" } });
  b = await begin(m, {}); r = await finish(m, b.state);
  check("B17. a shop name that is not letters and digits never becomes an address: 502, nothing stored", r.status === 502 && m.db.t.member_store_connections.length === 0);
  m = mountRoutes({ env: CONFIGURED });
  r = await hit(m, "post /api/store/connections", { body: { platform: "etsy" } });
  check("B18. POST /api/store/connections with platform etsy: 400 \"Use Connect Etsy on the Store Agent page.\"", r.status === 400 && r.body.code === "use_connect_etsy" &&
    r.body.error === "Use Connect Etsy on the Store Agent page.");
  b = await begin(m, {}); await finish(m, b.state);
  r = await hit(m, "get /api/store/connections", {});
  check("B19. the list: etsy_available true, the Etsy connection with its shop name, read only, USD", r.body.etsy_available === true && r.body.connections.length === 1 &&
    r.body.connections[0].shop_name === SHOP_NAME && r.body.connections[0].permission === "read" && r.body.connections[0].currency === "USD" && noSecretIn(J(r.body)));
  r = await hit(m, "delete /api/store/connections/:id", { params: { id: m.db.t.member_store_connections[0].id } });
  check("B20. disconnect: the row gone, and the note \"Disconnected. To remove BizForce from Etsy too, open your Etsy account settings, then Apps.\"",
    r.status === 200 && r.body.note === "Disconnected. To remove BizForce from Etsy too, open your Etsy account settings, then Apps." && m.db.t.member_store_connections.length === 0);
  check("B21. no route log line carries a token, a code, a secret or an email", m.logs.every(noSecretIn), J(m.logs.filter(function (l) { return !noSecretIn(l); }).slice(0, 2)));

  /* ── C. the sync ────────────────────────────────────────────────────────── */
  console.log("\n══ C. the sync ══");
  let s = await synced({ permission: "read", granted_scopes: READ_SCOPES });
  const ids = s.db.t.inventory_items.map(function (x) { return x.external_id; }).sort();
  check("C1. a listing without variations is listing:<id>; each variation is listing:<id>:<value_ids sorted as numbers, joined with '.'>",
    J(ids) === J(["listing:1001", "listing:1002:52.513", "listing:1002:52.514", "listing:1002:53.513", "listing:1002:53.514", "listing:1003:52"].sort()), J(ids));
  const hatSR = itemOf(s.db, "listing:1002:52.513") || {};
  check("C2. an item: the listing as its parent, the name with its values, the SKU, the price as amount/divisor, the quantity; source etsy",
    hatSR.external_parent_id === "1002" && hatSR.name === "Wool Hat - S / Red" && hatSR.sku === "HAT-S-RED" && hatSR.unit_price === 25 && hatSR.quantity_on_hand === 3 &&
    hatSR.source === "etsy" && hatSR.external_inventory_item_id === null, J(hatSR));
  check("C3. a disabled offering and an id over 100 characters are skipped and counted; the long one is logged by its code only",
    s.r.ok === true && s.r.skipped_disabled === 1 && s.r.skipped_id_too_long === 1 && !itemOf(s.db, "listing:1003:53") &&
    s.db.t.inventory_items.every(function (x) { return x.external_id.length <= 100; }) && LOGS.some(function (l) { return l === "[StoreSync] an Etsy item was skipped: id_too_long"; }), J(s.r));
  check("C4. Etsy's quantities are always tracked: every synced Etsy item has a whole-number stock", s.db.t.inventory_items.length === 6 &&
    s.db.t.inventory_items.every(function (x) { return Number.isInteger(x.quantity_on_hand); }));
  const sum = s.db.t.store_order_summaries[0] || {};
  check("C5. a receipt is stored as its number, time, total, currency and SKU and quantity only: no buyer name, email, address or message",
    s.db.t.store_order_summaries.length === 1 && sum.external_id === "777001" && sum.total === 55 && sum.currency === "USD" && sum.platform === "etsy" &&
    J(sum.line_items) === J([{ sku: "HAT-S-RED", quantity: 2 }, { sku: "MUG-1", quantity: 1 }]) && !/Jane|Main Street|gift wrap|example\.com|Leeds/.test(J(s.db.t)), J(sum));
  const rs = EAPI.receiptSummary({ receipt_id: 5, created_timestamp: 1, name: "Jane Buyer", buyer_email: BUYER_EMAIL, first_line: "x",
    grandtotal: { amount: 100, divisor: 100, currency_code: "USD" }, transactions: [{ sku: "A", quantity: 1, title: "t", buyer_user_id: 1 }] });
  check("C6. receiptSummary keeps exactly id, created_at, total, currency and line_items of sku and quantity, before anything else touches the receipt",
    J(Object.keys(rs).sort()) === J(["created_at", "currency", "id", "line_items", "total"]) && J(rs.line_items) === J([{ sku: "A", quantity: 1 }]) && noSecretIn(J(rs)), J(rs));
  check("C7. receipts asked for the last 60 days (min_created), 100 a page", s.etsy.api("GET", /\/receipts$/).length === 1 &&
    Number(s.etsy.api("GET", /\/receipts$/)[0].query.get("min_created")) === Math.floor((NOW - 60 * 86400000) / 1000) && s.etsy.api("GET", /\/receipts$/)[0].query.get("limit") === "100");
  check("C8. the shop's currency is stored; every read was a GET with x-api-key and the Bearer token; no PUT",
    s.db.t.member_store_connections[0].currency === "USD" && s.etsy.calls.every(function (c) { return c.method === "GET" && c.apiKey === KEY + ":" + SECRET && c.bearer === TOKEN; }) &&
    s.etsy.state.puts.length === 0 && s.etsy.asked.every(function (a) { return a.method === "GET"; }));
  check("C9. listings read by offset (state=active, limit=100), each listing's inventory read once", s.etsy.api("GET", /\/listings$/).length === 1 &&
    s.etsy.api("GET", /\/listings$/)[0].query.get("state") === "active" && s.etsy.api("GET", /\/listings$/)[0].query.get("offset") === "0" &&
    s.etsy.api("GET", /\/inventory$/).length === 4);
  const before = ids.slice();
  const namesBefore = s.db.t.inventory_items.map(function (x) { return x.external_id + "=" + x.name; }).sort();
  const again = await SS.syncConnection(s.deps, s.db.t.member_store_connections[0]);
  check("C10. a second sync (Etsy renumbered every product and listed the properties in the other order) finds the same items with the same names: updated in place, none added",
    again.ok && J(s.db.t.inventory_items.map(function (x) { return x.external_id; }).sort()) === J(before) && s.db.t.inventory_items.length === 6 &&
    J(s.db.t.inventory_items.map(function (x) { return x.external_id + "=" + x.name; }).sort()) === J(namesBefore), J(again));
  s = await synced({}, { throttleOnce: true });
  check("C11. a 429 is waited out (Retry-After 2 s) and asked again", s.r.ok && s.deps.sleeps.indexOf(2000) !== -1 && s.etsy.api("GET", /\/listings$/).length === 2, J(s.deps.sleeps));
  s = await synced({}, { endless: true });
  check("C12. listings are read 40 pages of 100 at most", s.etsy.api("GET", /\/listings$/).length === 40 && s.etsy.api("GET", /\/listings$/)[39].query.get("offset") === "3900",
    s.etsy.api("GET", /\/listings$/).length);
  const pass = await (async function () {
    const db = makeDb(), etsy = makeEtsy({});
    etsyConn(db, {});
    const sum2 = await SS.runStoreSyncPass(libDeps(db, etsy));
    return { sum: sum2, items: db.t.inventory_items.length };
  })();
  check("C13. Etsy joins the daily sync pass", pass.sum.synced === 1 && pass.items === 6, J(pass.sum));

  /* ── D. tokens ──────────────────────────────────────────────────────────── */
  console.log("\n══ D. tokens ══");
  s = await synced({ access_expires_at: new Date(NOW + 2 * 60 * 1000).toISOString() });
  let crow = s.db.t.member_store_connections[0];
  const updatesWithTokens = s.db.log.filter(function (l) { return l.table === "member_store_connections" && l.op === "update" && l.payload && l.payload.access_ciphertext; });
  check("D1. within 5 minutes of expiry the token is refreshed first, once; the new access and refresh tokens saved together in ONE update; token_version 1",
    s.r.ok && s.etsy.tokenCalls("refresh").length === 1 && accessOf(crow) === TOKEN2 && refreshOf(crow) === REFRESH2 && crow.token_version === 1 &&
    updatesWithTokens.length === 1 && !!updatesWithTokens[0].payload.credentials_ciphertext && s.etsy.api("GET").every(function (c) { return c.bearer === TOKEN2; }), J(s.r));
  check("D2. ...the update is a compare-and-set: on id, platform etsy and the token_version read", updatesWithTokens.length === 1 &&
    J(updatesWithTokens[0].filters) === J([["eq", "id", crow.id], ["eq", "platform", "etsy"], ["eq", "token_version", 0]]), J(updatesWithTokens[0] && updatesWithTokens[0].filters));
  {
    // another process refreshed first: the stored row has its token at version 1; this session still holds version 0
    const db = makeDb(), etsy = makeEtsy({});
    const stored = etsyConn(db, { __token: WINNER, token_version: 1, access_expires_at: new Date(NOW + 50 * 60 * 1000).toISOString() });
    const stale = Object.assign({}, stored, { token_version: 0, access_expires_at: new Date(NOW + 60 * 1000).toISOString() });
    const ses = EAPI.session(stale);
    const got = await attempt(EAPI.me(libDeps(db, etsy), ses));
    check("D3. losing the race writes nothing: the winner's token stays stored and is the one used", got.ok && accessOf(db.t.member_store_connections[0]) === WINNER &&
      db.t.member_store_connections[0].token_version === 1 && etsy.api("GET").every(function (c) { return c.bearer === WINNER; }), J([got, db.t.member_store_connections[0].token_version]));
  }
  {
    const db = makeDb(), etsy = makeEtsy({});
    const c = etsyConn(db, { access_expires_at: new Date(NOW + 60 * 1000).toISOString() });
    const deps = libDeps(db, etsy);
    const both = await Promise.all([EAPI.accessToken(deps, EAPI.session(c), false), EAPI.accessToken(deps, EAPI.session(c), false)]);
    check("D4. two reads at once on one connection share ONE refresh", both[0] === TOKEN2 && both[1] === TOKEN2 && etsy.tokenCalls("refresh").length === 1, etsy.tokenCalls("refresh").length);
  }
  s = await synced({ access_expires_at: new Date(NOW + 60 * 1000).toISOString() }, { refresh: "refuse" });
  crow = s.db.t.member_store_connections[0];
  const again2 = await SS.syncConnection(s.deps, Object.assign({}, crow, { status: "connected" }));
  check("D5. a refused refresh: needs_reconnect and ONE notice; a second failure sends no second notice", s.r.ok === false && s.r.needs_reconnect === true && crow.status === "needs_reconnect" &&
    s.db.t.notifications.length === 1 && /Reconnect your Etsy store/.test(s.db.t.notifications[0].title) && again2.needs_reconnect === true && s.db.t.notifications.length === 1, J(s.r));
  s = await synced({ access_expires_at: new Date(NOW - 60 * 1000).toISOString(), refresh_expires_at: new Date(NOW - 1000).toISOString() });
  check("D6. a refresh token past refresh_expires_at: needs_reconnect without asking Etsy", s.r.needs_reconnect === true && s.etsy.tokenCalls().length === 0 && s.etsy.api().length === 0, J(s.r));
  s = await synced({}, { reject: [TOKEN] });
  check("D7. a 401 on a fresh token: refreshed ONCE and asked once more, then the sync goes on with the new token", s.r.ok === true && s.etsy.tokenCalls("refresh").length === 1 &&
    accessOf(s.db.t.member_store_connections[0]) === TOKEN2, J(s.r));
  s = await synced({}, { reject: [TOKEN, TOKEN2] });
  check("D8. a 401 again after the refresh: needs_reconnect, one refresh only (no loop)", s.r.needs_reconnect === true && s.etsy.tokenCalls("refresh").length === 1, J(s.r));

  /* ── E. changes ─────────────────────────────────────────────────────────── */
  console.log("\n══ E. changes, through approval ══");
  async function world(etsyOpts, over) {
    const w = await synced(over || {}, etsyOpts || {});
    w.deps = libDeps(w.db, w.etsy);
    w.item = function (id) { return itemOf(w.db, id); };
    w.propose = function (id, field, to) { return SW.proposeChange(w.deps, USER, { item_id: w.item(id).id, field: field, to: to }); };
    return w;
  }
  let w = await world({}, { permission: "read_write", granted_scopes: READ_SCOPES });
  r = await w.propose("listing:1002:52.513", "price", "27.50");
  check("E1. a connection without listings_w is read only: 409, nothing filed, no PUT", r.status === 409 && r.body.code === "read_only" && w.db.t.agent_proposals.length === 0 &&
    w.etsy.state.puts.length === 0, J(r));
  w = await world();
  r = await w.propose("listing:1001", "stock", 1000);
  check("E2. Etsy's stock is 0 to 999: 1000 is refused, \"Etsy allows a stock level from 0 to 999.\", nothing filed", r.status === 400 && r.body.error === "Etsy allows a stock level from 0 to 999." &&
    w.db.t.agent_proposals.length === 0, J(r));
  const getsBefore = w.etsy.api("GET").length;
  r = await w.propose("listing:1002:52.513", "price", "27.50");
  const prop = r.body.proposal || {};
  check("E3. a proposal: from the live value (one GET), filed pending for the store agent with the platform, the currency and how many variations it applies to; no PUT",
    r.status === 201 && prop.status === "pending" && prop.agent_type === "store" && prop.action_type === "update_store_item" && prop.payload.platform === "etsy" &&
    prop.payload.currency === "USD" && prop.payload.from === "25.00" && prop.payload.to === "27.50" && prop.payload.target_count === 2 &&
    prop.payload.variations_note === "This price applies to 2 variations of this listing." && /This price applies to 2 variations of this listing\./.test(r.body.note) &&
    w.etsy.api("GET").length === getsBefore + 1 && w.etsy.state.puts.length === 0, J(r.body));
  const getsBeforeRun = w.etsy.api("GET").length;
  let done = await attempt(SW.executeChange(w.deps, prop));
  const put = w.etsy.state.puts[0] || {};
  const bySku = {};
  ((put.body || {}).products || []).forEach(function (p) { bySku[p.sku] = p; });
  check("E4. executed: ONE PUT of the whole inventory as JSON, with no product or offering ids", done.ok && w.etsy.state.puts.length === 1 && /^application\/json/.test(put.contentType || "") &&
    Object.keys(bySku).length === 4 && !/product_id|offering_id/.test(J(put.body)), J([done, put.body && Object.keys(put.body)]));
  check("E5. ...only the targets changed: the two S hats at 27.5; the L hats' prices, every quantity, every SKU, property and is_enabled as read; the *_on_property arrays as read",
    bySku["HAT-S-RED"] && bySku["HAT-S-RED"].offerings[0].price === 27.5 && bySku["HAT-S-BLUE"].offerings[0].price === 27.5 &&
    bySku["HAT-L-RED"].offerings[0].price === 30 && bySku["HAT-L-BLUE"].offerings[0].price === 30 &&
    J(["HAT-S-RED", "HAT-S-BLUE", "HAT-L-RED", "HAT-L-BLUE"].map(function (k) { return bySku[k].offerings[0].quantity; })) === J([3, 4, 2, 0]) &&
    Object.keys(bySku).every(function (k) { return bySku[k].offerings[0].is_enabled === true && bySku[k].property_values.length === 2; }) &&
    J(put.body.price_on_property) === J([100]) && J(put.body.quantity_on_property) === J([100, 200]) && J(put.body.sku_on_property) === J([100, 200]), J(put.body));
  check("E6. ...a live read right before the PUT and ONE confirming read after it", w.etsy.api("GET", /\/listings\/1002\/inventory$/).length >= 2 &&
    w.etsy.api("GET").length === getsBeforeRun + 2, w.etsy.api("GET").length - getsBeforeRun);
  check("E7. ...the item and its sibling variation updated to 27.5, the change logged once with USD", w.item("listing:1002:52.513").unit_price === 27.5 &&
    w.item("listing:1002:53.513").unit_price === 27.5 && w.item("listing:1002:52.514").unit_price === 30 && w.db.t.store_change_log.length === 1 &&
    w.db.t.store_change_log[0].currency === "USD" && w.db.t.store_change_log[0].old_value === 25 && w.db.t.store_change_log[0].new_value === 27.5, J(w.db.t.store_change_log));
  done = await attempt(SW.executeChange(w.deps, prop));
  check("E8. a replay writes nothing: already applied, no second PUT", done.ok && done.v.already_applied === true && w.etsy.state.puts.length === 1);
  // compare-and-set
  w = await world();
  r = await w.propose("listing:1002:52.514", "price", "33.00");
  w.etsy.state.inv["1002"].products.forEach(function (p) { if (p.sku === "HAT-L-RED" || p.sku === "HAT-L-BLUE") p.price = 3100; });
  done = await attempt(SW.executeChange(w.deps, r.body.proposal));
  check("E9. the live price moved since the proposal: \"Your store changed since you proposed this. Propose it again.\", no PUT", !done.ok &&
    done.msg === "Your store changed since you proposed this. Propose it again." && w.etsy.state.puts.length === 0 && w.db.t.store_change_log.length === 0, J(done));
  // stock, per variation
  w = await world();
  r = await w.propose("listing:1002:52.513", "stock", 12);
  done = await attempt(SW.executeChange(w.deps, r.body.proposal));
  const sput = (w.etsy.state.puts[0] || {}).body || { products: [] };
  check("E10. a stock change where quantity varies by every property: that variation only, 12; every other quantity as read; no variations note",
    r.status === 201 && r.body.proposal.payload.target_count === 1 && r.body.proposal.payload.variations_note === null && done.ok &&
    J(sput.products.map(function (p) { return p.offerings[0].quantity; })) === J([12, 4, 2, 0]) && w.item("listing:1002:52.513").quantity_on_hand === 12, J([r.body, done]));
  // one value for every variation
  w = await world();
  r = await w.propose("listing:1003:52", "price", "15.00");
  done = await attempt(SW.executeChange(w.deps, r.body.proposal));
  const aput = (w.etsy.state.puts[0] || {}).body || { products: [] };
  check("E11. a price that does not vary by any property applies to every variation: written to all of them as one change, with \"This price applies to every variation of this listing.\"",
    r.status === 201 && r.body.proposal.payload.variations_note === "This price applies to every variation of this listing." && done.ok &&
    J(aput.products.map(function (p) { return p.offerings[0].price; })) === J([15, 15]) && J(aput.products.map(function (p) { return p.offerings[0].is_enabled; })) === J([true, false]), J([r.body, aput]));
  check("E12. the stock note for a quantity that applies to every variation", SW.etsyGroupNote("stock", 3, true) === "This stock level applies to every variation of this listing." &&
    SW.etsyGroupNote("price", 1, false) === null);
  // no retry, confirm read
  w = await world({ putStatus: 500 });
  r = await w.propose("listing:1001", "price", "19.00");
  done = await attempt(SW.executeChange(w.deps, r.body.proposal));
  check("E13. a 5xx after sending: ONE PUT, never retried; \"BizForce couldn't confirm the change...\"; nothing logged", !done.ok && w.etsy.state.puts.length === 1 &&
    done.msg === "BizForce couldn't confirm the change. Check the item in your store; BizForce will not try again." && w.db.t.store_change_log.length === 0, J(done));
  w = await world({ putAlsoChange: "HAT-L-BLUE" });
  r = await w.propose("listing:1002:52.513", "price", "26.00");
  done = await attempt(SW.executeChange(w.deps, r.body.proposal));
  check("E14. the confirming read shows another product changed too: \"Etsy shows other changes on this listing. Check it on Etsy before filing again.\", nothing logged, no undo PUT",
    !done.ok && done.msg === "Etsy shows other changes on this listing. Check it on Etsy before filing again." && w.etsy.state.puts.length === 1 && w.db.t.store_change_log.length === 0, J(done));
  // the item's variation set changed since filing
  w = await world();
  r = await w.propose("listing:1002:52.513", "price", "26.00");
  // every hat at one price, so only the count of variations (2 named, 4 now) tells the difference
  w.etsy.state.inv["1002"].pop = [];
  w.etsy.state.inv["1002"].products.forEach(function (p) { p.price = 2500; });
  done = await attempt(SW.executeChange(w.deps, r.body.proposal));
  check("E15. the price now applies to more variations than the proposal named: refused as changed, no PUT", !done.ok && done.msg === "Your store changed since you proposed this. Propose it again." &&
    w.etsy.state.puts.length === 0, J(done));
  w = await world();
  r = await w.propose("listing:1001", "stock", 5);
  check("E16. the same value as the store's: 400, nothing filed", r.status === 400 && r.body.code === "same");
  const capProp = { id: uuid(), user_id: USER, payload: { connection_id: w.conn.id, item_id: w.item("listing:1001").id, external_id: "listing:1001", external_parent_id: "1001",
    field: "stock", from: 5, to: 1000, platform: "etsy", target_count: 1 } };
  done = await attempt(SW.executeChange(w.deps, capProp));
  check("E17. the executor checks the 0 to 999 cap again, before any read", !done.ok && done.msg === "Etsy allows a stock level from 0 to 999." && w.etsy.state.puts.length === 0, J(done));
  check("E18. an Etsy item is addressable only as listing:<id>[:values] under its own listing", SW.addressable("etsy", "price", { external_id: "listing:1002:52.513", external_parent_id: "1002" }) === true &&
    SW.addressable("etsy", "price", { external_id: "listing:1002:52.513", external_parent_id: "1003" }) === false && SW.addressable("etsy", "price", { external_id: "variation:5", external_parent_id: "1" }) === false &&
    SW.addressable("bogus", "price", { external_id: "listing:1", external_parent_id: "1" }) === false);
  check("E19. an unknown platform is refused by summaryOf and syncConnection, never read as WooCommerce",
    (function () { try { SS.summaryOf("ebay", { id: 1 }); return false; } catch (e) { return e.code === "unknown_platform"; } })() &&
    (await SS.syncConnection(libDeps(makeDb(), makeEtsy({})), { id: uuid(), user_id: USER, platform: "ebay", store_url: "x" })).code === "unknown_platform");
  check("E20. lib/etsyApi.js: the word PUT appears only in writeInventory; every reader goes through readGet (method GET)",
    (stripComments(FILES.api).match(/"PUT"/g) || []).length === 1 && fnSource(FILES.api, "writeInventory").indexOf("method: \"PUT\"") !== -1 &&
    /method: "GET"/.test(fnSource(FILES.api, "readGet")) && (stripComments(FILES.api).match(/deps\.jsonRequest\(/g) || []).length === 2);
  check("E21. lib/storeSync.js stays GET-only: no PUT, POST, PATCH or DELETE in its code", !/\b(PUT|POST|PATCH|DELETE)\b/.test(stripComments(FILES.sync).replace(/\/\/.*$/gm, "")));

  /* ── F. the pages ───────────────────────────────────────────────────────── */
  console.log("\n══ F. the pages ══");
  const P = FILES.page;
  check("F1. the Store page: an Etsy choice, \"Connect Etsy\", the changes checkbox, and the line word for word",
    P.indexOf("<button type=\"button\" class=\"action-btn action-btn--ghost\" id=\"storePickEtsy\" aria-pressed=\"false\">Etsy</button>") !== -1 &&
    P.indexOf("<p class=\"store-quiet\">You approve BizForce on Etsy's own page. BizForce never sees your Etsy password.</p>") !== -1 &&
    P.indexOf("<label class=\"store-allow\"><input type=\"checkbox\" id=\"storeEtsyAllow\" /> Let BizForce make changes I approve (prices and stock)</label>") !== -1 &&
    P.indexOf("<button type=\"button\" class=\"action-btn\" id=\"storeEtsyBtn\">Connect Etsy</button>") !== -1 &&
    P.indexOf("<p class=\"store-msg\" id=\"storeEtsyUnset\" hidden>Etsy connection isn't set up yet.</p>") !== -1 &&
    // NAMED (Nov 8 2026, Amazon store connection, migration 182): BEFORE "Shopify, WooCommerce or Etsy store"; AFTER Amazon too.
    P.indexOf("Connect your own Shopify, WooCommerce, Etsy or Amazon store and Stock") !== -1);
  let dom = runPage("", listAnswers({ "GET /api/store/connections": { status: 200, body: { connections: [], note: "", shopify_available: true, etsy_available: false } } }));
  await flush();
  check("F2. unconfigured: Connect Etsy disabled and \"Etsy connection isn't set up yet.\" shown", dom.els.storeEtsyBtn.disabled === true && dom.els.storeEtsyUnset.hidden === false &&
    dom.els.storeEtsyUnset.textContent === "Etsy connection isn't set up yet.");
  dom = runPage("", listAnswers());
  await flush();
  dom.els.storePickEtsy.click();
  dom.els.storeEtsyAllow.checked = true;
  dom.els.storeEtsyBtn.click();
  await flush();
  const startCall = dom.fetches.filter(function (f) { return f.path === "/api/store/etsy/start"; })[0];
  check("F3. Connect Etsy: POST start with allow_changes, the \"etsy\" marker set in sessionStorage BEFORE leaving, then Etsy's page",
    dom.els.storeEtsySection.hidden === false && !!startCall && J(startCall.body) === J({ allow_changes: true }) && dom.store.bf_store_return === "etsy" &&
    dom.assigned[0] === "https://www.etsy.com/oauth/connect?client_id=x" && dom.events.indexOf("session:set bf_store_return=etsy") !== -1, J([startCall, dom.assigned]));
  const q = "?code=" + CODE + "&state=" + "S".repeat(43);
  dom = runPage(q, listAnswers(), "etsy");
  await flush();
  const fin = dom.fetches.filter(function (f) { return f.path === "/api/store/etsy/finish"; })[0];
  check("F4. back from Etsy with the marker: the address bar cleared first, then code and state POSTed to finish, the marker removed, the shop named",
    !!fin && J(fin.body) === J({ code: CODE, state: "S".repeat(43) }) && dom.events.indexOf("replaceState:/store-agent.html") !== -1 &&
    dom.events.indexOf("replaceState:/store-agent.html") < dom.events.indexOf("fetch:POST /api/store/etsy/finish") && !("bf_store_return" in dom.store) &&
    /Connected to your Etsy shop WoolAndCo/.test(dom.els.storeConnectMsg.textContent), J([fin, dom.events]));
  dom = runPage(q, listAnswers());
  await flush();
  check("F5. code and state with no marker: \"Start the connection again.\", nothing POSTed, the address bar cleared",
    dom.els.storeConnectMsg.textContent === "Start the connection again." && !dom.fetches.some(function (f) { return f.method === "POST"; }) &&
    dom.events.indexOf("replaceState:/store-agent.html") !== -1, J([dom.els.storeConnectMsg.textContent, dom.fetches]));
  dom = runPage(q, listAnswers(), "shopify");
  await flush();
  check("F6. code and state with the \"shopify\" marker but no shop and hmac: not Etsy's, nothing POSTed", dom.els.storeConnectMsg.textContent === "Start the connection again." &&
    !dom.fetches.some(function (f) { return f.method === "POST"; }));
  dom = runPage("?code=" + CODE + "&hmac=" + "f".repeat(64) + "&shop=demo-shop.myshopify.com&state=" + "S".repeat(43) + "&timestamp=1794052800", listAnswers(), "etsy");
  await flush();
  check("F7. a Shopify return is still known by its shop and hmac, whatever the marker, and the marker is spent",
    dom.fetches.some(function (f) { return f.path === "/api/store/shopify/finish" && f.method === "POST"; }) && !dom.fetches.some(function (f) { return f.path === "/api/store/etsy/finish"; }) &&
    !("bf_store_return" in dom.store));
  dom = runPage("?error=access_denied&state=" + "S".repeat(43), listAnswers(), "etsy");
  await flush();
  check("F8. Etsy declined (error, with the marker): \"Etsy did not connect your shop, so nothing was saved.\", nothing POSTed",
    dom.els.storeConnectMsg.textContent === "Etsy did not connect your shop, so nothing was saved." && !dom.fetches.some(function (f) { return f.method === "POST"; }));
  const hostileView = Object.assign({}, ETSY_VIEW, { shop_name: HOSTILE, store: "https://www.etsy.com/shop/" + HOSTILE });
  dom = runPage("", listAnswers({ "GET /api/store/connections": { status: 200, body: { connections: [hostileView], note: "", shopify_available: true, etsy_available: true } } }));
  await flush();
  const listed = allText(dom.els.storeConnections);
  check("F9. the connection row: the shop name, Read only, the currency; set with textContent only (a hostile name stays text)",
    listed.indexOf("Etsy shop: " + HOSTILE) !== -1 && listed.indexOf("Read only") !== -1 && listed.indexOf("Currency: USD") !== -1 && listed.indexOf("(Etsy, since") !== -1 &&
    dom.innerHTML.length === 0, listed.slice(0, 300));
  check("F10. the sessionStorage key is on checkOfflineMode's KEPT list and named in bf-session.js's LEFT ON PURPOSE comment",
    // NAMED (Nov 8 2026, Amazon store connection, migration 182): BEFORE "etsy or shopify"; AFTER "etsy, amazon or shopify".
    /bf_store_return: "/.test(read("scripts/checkOfflineMode.js")) && /bf_store_return\n\s+\(sessionStorage: which store's page, etsy, amazon or shopify/.test(FILES.session) &&
    /var RETURN_KEY = "bf_store_return";/.test(FILES.ui));
  const cardFns = ["escapeHtml", "storeChangeText", "storeChangePayloadFields"].map(function (n) { return fnSource(FILES.proposals, n); });
  let card = "";
  try { const cx = { String: String }; vm.createContext(cx); vm.runInContext(cardFns.join("\n"), cx);
    card = cx.storeChangePayloadFields({ platform: "etsy", item_name: HOSTILE, field: "price", from: "25.00", to: "27.50", currency: "USD", variations_note: "<b>x</b> This price applies to 2 variations of this listing." });
  } catch (e) { card = "error: " + e.message; }
  check("F11. the Approvals card names Etsy, the currency and the variations note, every value escaped",
    card.indexOf("Change &lt;img src=x onerror=alert(1)&gt; price in your Etsy store from 25.00 USD to 27.50 USD") !== -1 && card.indexOf("your Etsy store, connected with changes allowed") !== -1 &&
    card.indexOf("&lt;b&gt;x&lt;/b&gt; This price applies to 2 variations of this listing.") !== -1 && card.indexOf("<img") === -1 && card.indexOf("<b>") === -1, card.slice(0, 300));
  // NAMED (Nov 8 2026, Amazon store connection, migration 182): BEFORE the writable list ended with etsy; AFTER amazon follows it.
  check("F12. the propose control: an Etsy connection with changes allowed is writable, with \"Etsy allows a stock level from 0 to 999.\"",
    /c\.platform === "etsy" \|\| c\.platform === "amazon"\) && c\.permission === "read_write"/.test(FILES.changesUi) && FILES.changesUi.indexOf("\"Etsy allows a stock level from 0 to 999.\"") !== -1);
  const guideStore = (/"store-agent\.html": \[([\s\S]*?)\]/.exec(FILES.guide) || [])[1] || "";
  const guideFront = (/"etsy-agent\.html": \[([\s\S]*?)\]/.exec(FILES.guide) || [])[1] || "";
  // NAMED (Nov 8 2026, Amazon store connection, migration 182): BEFORE "reads Shopify, WooCommerce or Etsy;"; AFTER the tip names
  // Amazon too (159 characters; checkAmazonConnect holds it).
  check("F13. the guide: the Store tip says it reads Shopify, WooCommerce, Etsy or Amazon (within 160 characters); the Storefront tips never say Etsy",
    guideStore.indexOf("\"\\\"Connect your store\\\" reads Shopify, WooCommerce, Etsy or Amazon; audits are written from your Business Profile and what you tell it, not your store's own data.\"") !== -1 &&
    guideFront.length > 100 && !/etsy/i.test(guideFront.replace(/"etsy-agent\.html"/g, "")), guideFront.slice(0, 200));
  check("F14. the Storefront agent's name is \"Storefront\" in lib/triggers.js (never \"Etsy\")", /etsy: "Storefront"/.test(FILES.triggers) && !/etsy: "Etsy"/.test(FILES.triggers));
  // NAMED (Nov 8 2026, Amazon store connection, migration 182): BEFORE { manual, shopify, woocommerce, etsy }; AFTER amazon too.
  check("F15. the Store signature counts Etsy stock, and the live panel names it", /var s = \{ manual: 0, shopify: 0, woocommerce: 0, etsy: 0, amazon: 0 \};/.test(FILES.signatures) &&
    /if \(src\.etsy\) srcParts\.push\("Etsy " \+ src\.etsy\);/.test(FILES.profile));

  /* ── G. the words and the registries ───────────────────────────────────── */
  console.log("\n══ G. the words and the registries ══");
  // NAMED (Nov 8 2026, Amazon store connection, migration 182): BEFORE the sentence named Shopify, WooCommerce or Etsy; AFTER it
  // names Amazon in its three places too (checkAmazonConnect holds it word for word as well).
  const PRIVACY = "If you connect a Shopify, WooCommerce, Etsy or Amazon store, BizForce stores the store's address and the access it is given, encrypted (for WooCommerce, " +
    "the key you made for it; for Shopify, Etsy or Amazon, the access you approve when you connect), and reads from the store only your products (name, SKU, price, " +
    "cost where the store has one), your stock levels, your store's currency and location names, and summaries of your orders (each order's number, " +
    "date, total, currency, and its items as SKU and quantity), never any customer's name, email, address or phone number; BizForce changes a " +
    "product's price or stock level in your store only when you approve that change, and only if you allowed changes when you connected the store, " +
    "and it keeps a record of each change (the item, the old and new value, and when). What it reads is used only for your own agents, the store's " +
    "key or access is never shown back to you or exported, and it, the products, the stock, the order summaries and the record of changes are " +
    "deleted when you disconnect the store, uninstall BizForce from Shopify, remove it from your Etsy account or Amazon Seller Central, or delete your account.";
  const esc = function (t) { return String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"); };
  check("G1. the privacy sentence word for word, and privacy.html carries it once, as built", LP.STORE_PRIVACY_SENTENCE === PRIVACY && FILES.privacy.split(esc(PRIVACY)).length === 2, LP.STORE_PRIVACY_SENTENCE);
  check("G2. Etsy is a named third party, word for word, on the privacy page too",
    FILES.yourData.indexOf("{ name: \"Etsy\", for: \"connecting your Etsy shop, reading it and making the changes you approve, when you connect one\" }") !== -1 &&
    FILES.privacy.indexOf(esc("Etsy (connecting your Etsy shop, reading it and making the changes you approve, when you connect one)")) !== -1);
  // NAMED (Nov 8 2026, Amazon store connection, migration 182): BEFORE seven sign-ins ending "and Connect Etsy", the store lines
  // naming Shopify, WooCommerce or Etsy, and "Shopify and Etsy access". AFTER eight sign-ins ending "Connect Etsy and Connect
  // Amazon", the lines name Amazon too, and "Shopify, Etsy and Amazon access" (checkAmazonConnect holds them as well).
  check("G3. yourData: the sign-in states name all eight sign-ins; the connections and the change log name Etsy; the backup note names Etsy access",
    FILES.yourData.indexOf("Temporary sign-in states for Sign in with Microsoft, Connect Shopify, Connect YouTube, Connect TikTok, Connect Instagram, Connect Facebook, Connect Etsy and Connect Amazon,") !== -1 &&
    FILES.yourData.indexOf("connected to each Shopify, WooCommerce, Etsy or Amazon store") !== -1 && FILES.yourData.indexOf("or the access Shopify, Etsy or Amazon granted when you connected") !== -1 &&
    FILES.yourData.indexOf("Changes BizForce made to your store with your approval, on Shopify, WooCommerce, Etsy or Amazon:") !== -1 &&
    FILES.backup.indexOf("member_store_connections: \"members' WooCommerce store keys and Shopify, Etsy and Amazon access (encrypted); members connect again\",") !== -1);
  const LEGAL = realRequire("./lib/legal");
  check("G4. TERMS_VERSION and TERMS_UPDATED are Nov 8 2026", LEGAL.TERMS_VERSION === "2026-11-08" && LEGAL.TERMS_UPDATED === "Last updated November 8, 2026", LEGAL.TERMS_VERSION);
  const ets = (FILES.readme.split("## Etsy app setup")[1] || "").split("\n## ")[0];
  check("G5. README: the two env var rows, and the Etsy app setup (the keystring and shared secret on Railway, the redirect exactly, the four scopes, the access tiers, x-api-key)",
    /\n\| `ETSY_KEYSTRING` \| none \| /.test(FILES.readme) && /\n\| `ETSY_SHARED_SECRET` \| none \| [^\n]*A secret; set it on Railway/.test(FILES.readme) &&
    ets.indexOf("exactly: `https://bizforceai.net/store-agent.html`") !== -1 && /`shops_r`, `listings_r` and `transactions_r`; [^\n]*`listings_w`/.test(ets) &&
    /personal access/.test(ets) && /commercial access/.test(ets) && ets.indexOf("`x-api-key: <keystring>:<shared secret>`") !== -1 && /Railway only/.test(ets));
  check("G6. the route lists: both routes in checkDormantRoutesDeleted's ADDED (485 -> 487) and checkUnsubscribedSurface's gated list (122 -> 124)",
    FILES.dormant.indexOf("[\"post\", \"/api/store/etsy/start\"],") !== -1 && FILES.dormant.indexOf("[\"post\", \"/api/store/etsy/finish\"]") !== -1 && /\(486 -> 487\)/.test(FILES.dormant) &&
    FILES.surface.indexOf("\"post /api/store/etsy/start\", \"post /api/store/etsy/finish\"") !== -1 && /gated 122 -> 124/.test(FILES.surface));
  check("G7. migration 181 as run: the header, etsy in the platform, source and summary CHECKs, the shop id column and its CHECK, the token shape, the index, store_etsy",
    FILES.migration.indexOf("-- Applied by the owner by hand in the Supabase SQL editor on Nov 8, 2026. This file is the text as run.\n") === 0 &&
    FILES.migration.indexOf("CHECK (platform IN ('shopify', 'woocommerce', 'etsy'))") !== -1 && FILES.migration.indexOf("ADD COLUMN IF NOT EXISTS external_account_id text;") !== -1 &&
    FILES.migration.indexOf("external_account_id IS NULL OR external_account_id ~ '^[0-9]{1,30}$'") !== -1 &&
    FILES.migration.indexOf("CREATE UNIQUE INDEX IF NOT EXISTS member_store_connections_etsy_shop_key\n  ON public.member_store_connections (external_account_id) WHERE platform = 'etsy';") !== -1 &&
    FILES.migration.indexOf("source IN ('shopify', 'woocommerce', 'etsy')") !== -1 && FILES.migration.indexOf("'facebook_login', 'store_etsy'))") !== -1 &&
    FILES.migration.indexOf("((purpose IN ('store_shopify', 'store_etsy')) = (flow_context IS NOT NULL))") !== -1);
  const migFiles = fs.readdirSync(path.join(REPO, "supabase", "migrations")).filter(function (x) { return /^\d{3}_.*\.sql$/.test(x); });
  const highest = migFiles.map(function (x) { return Number(x.slice(0, 3)); }).reduce(function (acc, x) { return Math.max(acc, x); }, 0);
  // NAMED (Nov 8 2026, Amazon store connection, migration 182): BEFORE 181_etsy_store.sql was the highest. AFTER it is the only
  // 181 and only 182_amazon_store.sql is above it, by name; "the highest" is checkAmazonConnect R1's.
  check("R1. 181_etsy_store.sql is the only 181, and only 182_amazon_store.sql is above it (checkAmazonConnect R1)", highest === 182 &&
    migFiles.filter(function (x) { return /^181_/.test(x); }).join() === "181_etsy_store.sql" &&
    migFiles.filter(function (x) { return Number(x.slice(0, 3)) > 181; }).join() === "182_amazon_store.sql", highest);
  check("G8. no other new env var: lib/etsyAuth.js reads only ETSY_KEYSTRING and ETSY_SHARED_SECRET, lib/etsyApi.js reads none",
    (stripComments(FILES.auth).match(/env\.[A-Z_]+/g) || []).sort().join() === "env.ETSY_KEYSTRING,env.ETSY_KEYSTRING,env.ETSY_SHARED_SECRET,env.ETSY_SHARED_SECRET" &&
    !/process\.env|env\.[A-Z]/.test(stripComments(FILES.api)));
  // NAMED (Nov 8 2026, Amazon store connection, migration 182): BEFORE GET, POST, PUT or DELETE and "a PUT carries one JSON
  // object body". AFTER PATCH joins (Amazon's listings patch) under the PUT's own rule: "a PUT or a PATCH carries one JSON object body".
  check("G9. the guarded fetcher's PUT carries one JSON object and nothing else (checkGuardedFetch 13b proves it)", /const JSON_METHODS = \["GET", "POST", "PUT", "PATCH", "DELETE"\];/.test(FILES.guarded) &&
    FILES.guarded.indexOf("guardedJsonRequest: a PUT or a PATCH carries one JSON object body") !== -1);
  const etsySection = sliceOf(FILES.server, "/* ── Connect Etsy (Nov 8 2026, migration 181", "app.get(\"/api/store/connections\"");
  check("G10. no emoji in any Etsy file", [FILES.auth, FILES.api, FILES.migration, FILES.ui, etsySection, fs.readFileSync(__filename, "utf8")].every(function (x) { return !EMOJI.test(x); }) && etsySection.length > 2000);
  check("G11. no secret, token, code or buyer email in any log line of this run", LOGS.every(noSecretIn), J(LOGS.filter(function (l) { return !noSecretIn(l); }).slice(0, 2)));
  check("G12. the network tripwire never fired, and no promise was left rejected", TRIPPED.length === 0 && UNHANDLED.length === 0, J(TRIPPED.concat(UNHANDLED.map(function (e) { return String(e && e.message); }))));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(function (e) { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
