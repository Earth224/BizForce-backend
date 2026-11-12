/* checkAmazonConnect: Amazon as the fourth store on the Store agent (migration 182, lib/amazonAuth.js, lib/amazonApi.js).

   WHAT IT PROVES. No request leaves this process and nothing calls Amazon: Amazon (Login with Amazon and the
   Selling Partner API) is a fake behind lib/guardedFetch.js's REAL JSON mode (only its DNS answer and its
   https.request are stood in), the database is a fake that enforces migration 182's CHECKs and its one seller
   and marketplace, one member index, the clock is fixed, and a network tripwire fails the run if anything opens
   a socket, asks real DNS or fetches.

     A. SIGN-IN (lib/amazonAuth.js). The marketplace table held equal to the build brief's, entry by entry; the
        consent page on the chosen marketplace's own Seller Central host, with version=beta in draft (unset or
        anything but exactly "false") and without it when published; the LWA token endpoint gets a FORM, with
        client_id and client_secret, for the code exchange and the refresh; invalid_grant is "rejected".
     B. THE ROUTES (server.js, run from its own source). Unconfigured: 503 "Amazon connection isn't set up yet."
        and amazon_available false. Start takes one marketplace and stores only the state's hash and
        flow_context { marketplace_id, region, permission } (no verifier: no PKCE here). Finish checks the
        seller id's shape before anything is spent, spends the state once, exchanges the code, seals both
        tokens before the SP-API is asked anything, requires the chosen marketplace to be one the seller
        sells in, and stores the storefront address, the seller id, the marketplace, the region and the
        currency, granted_scopes NULL. One seller account and marketplace, one member: 409, refused before
        any write.
     C. THE SYNC. Listings paged by nextToken (40 pages at most), "sku:<marketplaceId>:<sku>", an id over 100
        characters skipped with a code-only log, the B2C offer's price, the DEFAULT channel's stock, an FBA
        item's stock kept for display; orders over 60 days, 100 at most, each order's items read 2 s apart,
        reduced at the edge to number, date, total, currency and SKU and quantity: no buyer field is stored or
        logged; 429 waited out by the rate Amazon states.
     D. TOKENS. A refresh within 5 minutes of expiry, a form to LWA; the new token (and a new refresh token
        when LWA answers one) saved in ONE compare-and-set update on token_version; the loser of a race uses
        the winner's token; one refresh at a time; invalid_grant marks needs_reconnect with one notice.
     E. CHANGES. Only with changes allowed; the live read is the compare-and-set; the PATCH bodies exactly the
        brief's; a VALIDATION_PREVIEW first, whose ERROR stops everything with Amazon's first message (300
        characters at most); then ONE PATCH, never retried; INVALID fails; a read every 10 s for 60 s at most
        logs "confirmed" or "submitted"; the next sync promotes "submitted" to "confirmed"; undo for both; an
        FBA stock change refused at proposal and at execution; the daily cap; a replay writes nothing.
     F. THE PAGES. The Store page's Amazon block word for word, the marketplace picker with no default, the
        draft line, the button disabled when unconfigured, the "amazon" return marker (spapi_oauth_code, state
        and selling_partner_id; replaceState always), textContent only; the Approvals card and result escaped;
        "Submitted to Amazon, not yet confirmed"; the Store tip names Amazon and the Storefront never does.
     G. THE WORDS AND THE REGISTRIES. The privacy sentence word for word, THIRD_PARTIES, the export lines, the
        terms version, the README, the route lists, the migration as run and 182 the highest (R1), the four env
        vars and no other, no AWS SDK and no new package, no emoji.

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
  "draft-flag-ignored": [["auth", "  return envText(env, \"AMAZON_SPAPI_DRAFT\") !== \"false\";", "  return false;"]],
  "marketplace-table-drift": [["auth",
    "  A1F83G8C2ARO7P: market(\"UK\", \"eu\", EU_CENTRAL, \"www.amazon.co.uk\"),",
    "  A1F83G8C2ARO7P: market(\"UK\", \"eu\", \"sellercentral.amazon.co.uk\", \"www.amazon.co.uk\"),"]],
  "wrong-consent-host": [["auth", "  return \"https://\" + m.sellerCentral + CONSENT_PATH +", "  return \"https://sellercentral.amazon.com\" + CONSENT_PATH +"]],
  "state-reusable": [["server", ".is(\"consumed_at\", null).gt(\"expires_at\", amazonSpentAt)", ".gt(\"expires_at\", amazonSpentAt)"]],
  "seller-id-unchecked": [["auth", "  if (!SELLER_ID_RE.test(seller)) return { ok: false };\n", ""]],
  "unsealed-before-call": [["server",
    "      // Sealed first: both tokens are encrypted before the SP-API is asked anything.\n",
    "      await deps.jsonRequest(aa.REGION_ENDPOINTS[amazonMarket.region] + \"/sellers/v1/marketplaceParticipations\", { method: \"GET\", headers: { \"x-amz-access-token\": amazonGrant.accessToken } });\n"]],
  "participation-unchecked": [["server",
    "      if (!chosen) return res.status(422).json({ error: aa.MESSAGES.notParticipating, code: \"not_participating\", saved: false });\n",
    "      if (!chosen) chosen = { currency: null };\n"]],
  "second-member-same-seller": [["server", "      if ((amazonHeld.data || []).some(function (r) { return r.user_id !== req.user.id; })) {", "      if (false) {"]],
  "refresh-cas-missing": [["api", "    .eq(\"id\", row.id).eq(\"platform\", \"amazon\").eq(\"token_version\", version).select(\"id\");", "    .eq(\"id\", row.id).eq(\"platform\", \"amazon\").select(\"id\");"]],
  "invalid-grant-ignored": [["api", "    if (err && err.kind === \"rejected\") throw new SS.StoreAuthError(\"invalid_grant\");\n", ""]],
  "buyer-name-stored": [["api",
    "    id: o && typeof o.AmazonOrderId === \"string\" && ORDER_ID_RE.test(o.AmazonOrderId) ? o.AmazonOrderId : \"\",\n",
    "    id: o && typeof o.AmazonOrderId === \"string\" && ORDER_ID_RE.test(o.AmazonOrderId) ? o.AmazonOrderId : \"\",\n    buyer_name: o && o.BuyerInfo ? o.BuyerInfo.BuyerName : null,\n"]],
  "buyer-address-stored": [["api", "    line_items: []\n", "    line_items: [],\n    ship_to: o && o.ShippingAddress ? o.ShippingAddress.AddressLine1 : null\n"]],
  "orders-uncapped": [["api", "var ORDER_CAP = 100;", "var ORDER_CAP = 100000;"]],
  "order-items-unpaced": [["api", "      await deps.sleep(ORDER_ITEMS_GAP_MS);\n", ""]],
  "fba-stock-written": [["write", "    if (field === \"stock\" && amazonLive.fba) throw fail(MESSAGES.amazonFba);\n", ""]],
  "cas-skipped": [["write", "    var amazonCheck = compareLive(field, from, amazonLive.live);\n", "    var amazonCheck = { ok: true };\n"]],
  "preview-skipped": [["api", "  var preview = await patchOnce(deps, s, identity, body, true);\n", "  var preview = { ok: true, status: \"VALID\", issues: [] };\n"]],
  "preview-error-ignored": [["api",
    "  if (previewIssue !== null || preview.status === \"INVALID\") return { ok: false, code: \"preview_error\", issue: previewIssue || \"Amazon did not say why.\" };\n", ""]],
  "patch-retried": [["api",
    "  var sent = await patchOnce(deps, s, identity, body, false);\n",
    "  var sent = await patchOnce(deps, s, identity, body, false);\n  if (!sent.ok && sent.sent) sent = await patchOnce(deps, s, identity, body, false);\n"]],
  "patch-body-wrong-path": [["api", "\"/attributes/purchasable_offer\"", "\"/attributes/list_price\""]],
  "confirmed-without-match": [["api", "    if (showsValue(field, live, to)) return \"confirmed\";", "    if (live) return \"confirmed\";"]],
  "submitted-never-promoted": [["sync", "    var promoted = conn.platform === \"amazon\" ? await promoteSubmitted(supabase, conn, fetched.items) : 0;", "    var promoted = 0;"]],
  "amazon-falls-through": [["write",
    "  if (conn.platform === \"amazon\") return readLiveAmazonItem(deps, s, field, item);\n" +
    "  if (conn.platform !== \"woocommerce\") return { ok: false, code: \"not_synced\", error: MESSAGES.notSynced };\n", ""]],
  "read-sends-patch": [["api",
    "      answer = await deps.jsonRequest(base + path, { method: \"GET\", headers: headersFor(token),",
    "      answer = await deps.jsonRequest(base + path, { method: \"PATCH\", headers: headersFor(token),"]],
  "wrong-return-marker": [["ui",
    "    if (marker === \"amazon\" && q.get(\"spapi_oauth_code\") && q.get(\"state\") && q.get(\"selling_partner_id\")) { handleAmazonReturn(q); return; }",
    "    if (q.get(\"spapi_oauth_code\") && q.get(\"state\") && q.get(\"selling_partner_id\")) { handleAmazonReturn(q); return; }"]],
  "unconfigured-not-503": [["server",
    "      if (!amazonConfig) return res.status(503).json({ error: aa.MESSAGES.notConfigured, code: \"not_configured\", saved: false });",
    "      if (!amazonConfig) amazonConfig = { appId: \"\", clientId: \"\", clientSecret: \"\", draft: true };"]],
  "storefront-mentions-amazon": [["guide",
    "\"\\\"Pricing Strategy\\\" works out the range, median and your margin from comparable listings you type in, then writes a rationale.\",",
    "\"\\\"Pricing Strategy\\\" works out the range, median and your margin from comparable Amazon listings you type in, then writes a rationale.\","]],
  "privacy-sentence-stale": [["legal",
    "uninstall BizForce from Shopify, remove it from your Etsy account or Amazon Seller Central, or delete your account.\";",
    "uninstall BizForce from Shopify, remove it from your Etsy account, or delete your account.\";"]],
  "innerHTML-on-page": [["ui", "    if (text !== undefined) e.textContent = text;\n", "    if (text !== undefined) e.innerHTML = text;\n"]],
  // the others the code earns
  "token-exchange-json": [["auth",
    "(TOKEN_URL, { method: \"POST\", form: form, timeoutMs: TOKEN_TIMEOUT_MS });",
    "(TOKEN_URL, { method: \"POST\", body: form, timeoutMs: TOKEN_TIMEOUT_MS });"]],
  "refresh-not-single-flight": [["api", "  var running = refreshesInFlight.get(key);\n", "  var running = null;\n"]],
  "long-id-kept": [["api", "    if (identity.length > ID_MAX) {", "    if (false) {"]],
  "allow-changes-default-on": [["server",
    "      var amazonPermission = body.allow_changes === true ? \"read_write\" : \"read\";",
    "      var amazonPermission = body.allow_changes === false ? \"read\" : \"read_write\";"]],
  "fba-propose-unchecked": [["write",
    "  if (platform === \"amazon\" && field === \"stock\" && got.fba) return { status: 409, body: { error: MESSAGES.amazonFba, code: \"fba_stock\" } };\n", ""]],
  "b2b-price-read": [["api", "o.marketplaceId === marketplaceId && o.offerType === \"B2C\"; })[0]", "o.marketplaceId === marketplaceId; })[0]"]],
  "preview-mode-missing": [["api", "(preview ? \"&mode=VALIDATION_PREVIEW\" : \"\")", "\"\""]],
  "issue-not-cut": [["api", "  return cut(text || \"Amazon did not say why.\", ISSUE_MAX);", "  return text || \"Amazon did not say why.\";"]],
  "currency-not-from-participation": [["server", "        store_url: amazonStoreUrl, currency: chosen.currency,", "        store_url: amazonStoreUrl, currency: null,"]],
  "card-unescaped": [["proposals", "escapeHtml(payload.fba_note)", "payload.fba_note"]],
  "draft-line-hidden": [["ui", "    byId(\"storeAmazonDraft\").hidden = draft === false;", "    byId(\"storeAmazonDraft\").hidden = true;"]],
  "refresh-token-dropped": [["api", "  if (grant.refreshToken) {\n", "  if (false) {\n"]]
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
// Every line this run logs, to prove no secret and no buyer field is in any of them.
const LOGS = [];
["log", "warn", "error"].forEach(function (k) {
  const orig = console[k].bind(console);
  console[k] = function () { const line = [].slice.call(arguments).map(String).join(" "); if (!/^\s+(pass|FAIL)  /.test(line)) LOGS.push(line); orig.apply(null, arguments); };
});

const FILES = {
  server: read("server.js"),
  auth: read("lib/amazonAuth.js"),
  api: read("lib/amazonApi.js"),
  sync: read("lib/storeSync.js"),
  write: read("lib/storeWrite.js"),
  etsyAuth: read("lib/etsyAuth.js"),
  etsyApi: read("lib/etsyApi.js"),
  shopifyAuth: read("lib/shopifyAuth.js"),
  shopifyApi: read("lib/shopifyApi.js"),
  legal: read("lib/legalPages.js"),
  yourData: read("lib/yourData.js"),
  backup: read("lib/backup.js"),
  triggers: read("lib/triggers.js"),
  signatures: read("lib/agentSignatures.js"),
  guarded: read("lib/guardedFetch.js"),
  readme: read("README.md"),
  pkg: read("package.json"),
  migration: read("supabase/migrations/182_amazon_store.sql"),
  dormant: read("scripts/checkDormantRoutesDeleted.js"),
  surface: read("scripts/checkUnsubscribedSurface.js"),
  privacy: readFe("privacy.html"),
  page: readFe("store-agent.html"),
  storefront: readFe("etsy-agent.html"),
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
const SECRET_HEX = crypto.createHash("sha256").update("checkAmazonConnect").digest("hex");
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
const AA = compile(FILES.auth, "lib/amazonAuth.js", {});
const SS = compile(FILES.sync, "lib/storeSync.js", { "./amazonAuth": AA });
const AAPI = compile(FILES.api, "lib/amazonApi.js", { "./storeSync": SS, "./amazonAuth": AA });
const EA = compile(FILES.etsyAuth, "lib/etsyAuth.js", {});
const EAPI = compile(FILES.etsyApi, "lib/etsyApi.js", { "./storeSync": SS, "./etsyAuth": EA });
const SA = compile(FILES.shopifyAuth, "lib/shopifyAuth.js", {});
const SAPI = compile(FILES.shopifyApi, "lib/shopifyApi.js", { "./storeSync": SS, "./shopifyAuth": SA });
const SW = compile(FILES.write, "lib/storeWrite.js", { "./storeSync": SS, "./shopifyApi": SAPI, "./etsyApi": EAPI, "./amazonApi": AAPI, "./amazonAuth": AA });
const LP = compile(FILES.legal, "lib/legalPages.js", {});

const APP_ID = "amzn1.sp.solution.0f1e2d3c-1111-4222-8333-444455556666";
const CLIENT_ID = "amzn1.application-oa2-client." + "0123456789abcdef".repeat(2);
const CLIENT_SECRET = "amzn1.oa2-cs.v1." + "9f8e7d6c".repeat(8);
const CONFIGURED = { AMAZON_SPAPI_APP_ID: APP_ID, AMAZON_LWA_CLIENT_ID: CLIENT_ID, AMAZON_LWA_CLIENT_SECRET: CLIENT_SECRET };
const CONFIG = { appId: APP_ID, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, draft: true };
const USER = "00000000-0000-4000-8000-000000000001";
const OTHER = "00000000-0000-4000-8000-000000000002";
const SELLER = "A3SELLERX0EXAMPLE";
const US = "ATVPDKIKX0DER", UK = "A1F83G8C2ARO7P", DE = "A1PA6795UKMFR9", CA = "A2EUQ1WTGCTBG2";
const TOKEN = "Atza|" + "IwEBIa1b2c3d4".repeat(4);
const TOKEN2 = "Atza|" + "IwEBIc3d4e5f6".repeat(4);
const WINNER = "Atza|" + "IwEBI0f1e2d3c".repeat(4);
const REFRESH = "Atzr|" + "IwEBIe5f6a7b8".repeat(4);
const REFRESH2 = "Atzr|" + "IwEBIa7b8c9d0".repeat(4);
const CODE = "ANdNAVhLhGYWYfGyF" + "0123abcd".repeat(3);
const NOW = Date.parse("2026-11-08T12:00:00.000Z");
const BUYER_EMAIL = "jane.buyer" + "@marketplace.amazon.com";
const BUYER_BITS = /Jane|Main Street|Leeds|LS1 1AA|marketplace\.amazon\.com|Happy birthday|07700/;
const SECRETS = [TOKEN, TOKEN2, WINNER, REFRESH, REFRESH2, CODE, CLIENT_SECRET, BUYER_EMAIL];
function noSecretIn(text) { return SECRETS.every(function (s) { return String(text).indexOf(s) === -1; }) && !BUYER_BITS.test(String(text)); }
const EMOJI = /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{1F000}-\u{1F2FF}\u{FE0F}]/u;
const HOSTILE = "<img src=x onerror=alert(1)>";
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

/* THE BRIEF'S MARKETPLACE TABLE, as the build brief wrote it: code, id, Seller Central host, storefront host, region. */
const EU_HOST = "sellercentral-europe.amazon.com";
const BRIEF_MARKETPLACES = [
  ["US", "ATVPDKIKX0DER", "sellercentral.amazon.com", "www.amazon.com", "na"],
  ["CA", "A2EUQ1WTGCTBG2", "sellercentral.amazon.ca", "www.amazon.ca", "na"],
  ["MX", "A1AM78C64UM0Y8", "sellercentral.amazon.com.mx", "www.amazon.com.mx", "na"],
  ["BR", "A2Q3Y263D00KWC", "sellercentral.amazon.com.br", "www.amazon.com.br", "na"],
  ["UK", "A1F83G8C2ARO7P", EU_HOST, "www.amazon.co.uk", "eu"],
  ["DE", "A1PA6795UKMFR9", EU_HOST, "www.amazon.de", "eu"],
  ["FR", "A13V1IB3VIYZZH", EU_HOST, "www.amazon.fr", "eu"],
  ["IT", "APJ6JRA9NG5V4", EU_HOST, "www.amazon.it", "eu"],
  ["ES", "A1RKKUPIHCS9HS", EU_HOST, "www.amazon.es", "eu"],
  ["NL", "A1805IZSGTT6HS", EU_HOST, "www.amazon.nl", "eu"],
  ["SE", "A2NODRKZP88ZB9", EU_HOST, "www.amazon.se", "eu"],
  ["PL", "A1C3SOZRARQ6R3", EU_HOST, "www.amazon.pl", "eu"],
  ["BE", "AMEN7PMS3EDWL", EU_HOST, "www.amazon.com.be", "eu"],
  ["TR", "A33AVAJ2PDY3EV", "sellercentral.amazon.com.tr", "www.amazon.com.tr", "eu"],
  ["AE", "A2VIGQ35RCS4UG", "sellercentral.amazon.ae", "www.amazon.ae", "eu"],
  ["SA", "A17E79C6D8DWNP", "sellercentral.amazon.sa", "www.amazon.sa", "eu"],
  ["IN", "A21TJRUUN4KGV", "sellercentral.amazon.in", "www.amazon.in", "eu"],
  ["JP", "A1VC38T7YXB528", "sellercentral.amazon.co.jp", "www.amazon.co.jp", "fe"],
  ["AU", "A39IBJ37TRP1C6", "sellercentral.amazon.com.au", "www.amazon.com.au", "fe"],
  ["SG", "A19VAU5U5O7RUS", "sellercentral.amazon.sg", "www.amazon.sg", "fe"]
];
const BRIEF_ENDPOINTS = { na: "https://sellingpartnerapi-na.amazon.com", eu: "https://sellingpartnerapi-eu.amazon.com", fe: "https://sellingpartnerapi-fe.amazon.com" };

/* ── an in-memory database with migration 182's rules ───────────────────── */
function uuid() { return crypto.randomUUID(); }
const HEX = /^[0-9a-f]+$/;
const PLATFORMS4 = ["shopify", "woocommerce", "etsy", "amazon"];
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
      if (row.platform === "etsy" && others.some(function (r) { return r.platform === "etsy" && r.external_account_id === row.external_account_id; })) return "member_store_connections_etsy_shop_key";
      // migration 182: member_store_connections_amazon_seller_key, one seller account and marketplace, one member
      if (row.platform === "amazon" && others.some(function (r) { return r.platform === "amazon" && r.external_account_id === row.external_account_id && r.marketplace_id === row.marketplace_id; })) return "member_store_connections_amazon_seller_key";
    }
    if (name === "store_order_summaries" && others.some(function (r) { return r.connection_id === row.connection_id && r.external_id === row.external_id; })) return "store_order_summaries_unique";
    if (name === "store_change_log" && row.proposal_id && others.some(function (r) { return r.proposal_id === row.proposal_id; })) return "store_change_log_proposal_key";
    return null;
  }
  function checkViolation(name, row) {
    if (name === "member_store_connections") {
      if (PLATFORMS4.indexOf(row.platform) === -1) return "member_store_connections_platform_check";
      if (!HEX.test(row.credentials_ciphertext || "") || !/^[0-9a-f]{24}$/.test(row.credentials_iv || "") || !/^[0-9a-f]{32}$/.test(row.credentials_auth_tag || "")) return "member_store_connections_ciphertext_check";
      if (row.access_ciphertext != null && !HEX.test(row.access_ciphertext)) return "member_store_connections_access_ciphertext_check";
      if (!(Number.isInteger(row.token_version) && row.token_version >= 0)) return "member_store_connections_token_version_check";
      if (row.granted_scopes != null && !(String(row.granted_scopes).length <= 500 && /^[a-z_,]*$/.test(row.granted_scopes))) return "member_store_connections_scopes_check";
      if (row.currency != null && !/^[A-Z]{3}$/.test(row.currency)) return "member_store_connections_currency_check";
      if (!(row.external_account_id == null || (row.platform === "etsy" && /^[0-9]{1,30}$/.test(row.external_account_id)) ||
          (row.platform === "amazon" && /^[A-Z0-9]{8,20}$/.test(row.external_account_id)))) return "member_store_connections_external_account_check";
      if (row.marketplace_id != null && !/^[A-Z0-9]{8,20}$/.test(row.marketplace_id)) return "member_store_connections_marketplace_check";
      if (row.region != null && ["na", "eu", "fe"].indexOf(row.region) === -1) return "member_store_connections_region_check";
      if (["read", "read_write"].indexOf(row.permission) === -1) return "member_store_connections_permission_check";
      const access = row.access_ciphertext != null && row.access_iv != null && row.access_auth_tag != null && row.access_expires_at != null;
      const noAccess = row.access_ciphertext == null && row.access_iv == null && row.access_auth_tag == null && row.access_expires_at == null;
      const noMarket = row.marketplace_id == null && row.region == null;
      const shapeOk = (row.platform === "shopify" && access && row.external_account_id == null && noMarket) ||
        (row.platform === "woocommerce" && noAccess && row.refresh_expires_at == null && row.location_id == null && row.location_name == null && row.external_account_id == null && noMarket) ||
        (row.platform === "etsy" && access && row.location_id == null && row.location_name == null && row.external_account_id != null && noMarket) ||
        (row.platform === "amazon" && access && row.location_id == null && row.location_name == null && row.external_account_id != null && row.marketplace_id != null && row.region != null);
      if (!shapeOk) return "member_store_connections_token_shape_check";
    }
    if (name === "inventory_items") {
      const manual = row.source == null && row.store_connection_id == null && row.external_id == null;
      const synced = PLATFORMS4.indexOf(row.source) !== -1 && row.store_connection_id && row.external_id && String(row.external_id).length <= 100;
      if (!manual && !synced) return "inventory_items_source_check";
    }
    if (name === "store_order_summaries") {
      if (PLATFORMS4.indexOf(row.platform) === -1) return "store_order_summaries_platform_check";
      if (!Array.isArray(row.line_items)) return "store_order_summaries_line_items_check";
      // NAMED (Nov 11 2026, orbit stage 2, migration 183): an order's status is active, cancelled or refunded (absent: the default, active).
      if (name === "store_order_summaries" && row.status !== undefined && ["active", "cancelled", "refunded"].indexOf(row.status) === -1) return "store_order_summaries_status_check";
    }
    if (name === "store_change_log") {
      if (row.currency != null && !/^[A-Z]{3}$/.test(row.currency)) return "store_change_log_currency_check";
      if (["confirmed", "submitted"].indexOf(row.confirmation) === -1) return "store_change_log_confirmation_check";
    }
    if (name === "oauth_states") {
      if (["mailbox_microsoft", "store_shopify", "youtube_google", "tiktok_login", "instagram_login", "facebook_login", "store_etsy", "store_amazon"].indexOf(row.purpose) === -1) return "oauth_states_purpose_check";
      if (["store_shopify", "store_etsy", "store_amazon"].indexOf(row.purpose) !== -1 !== (row.flow_context != null)) return "oauth_states_context_check";
      if (row.flow_context != null && Buffer.byteLength(J(row.flow_context)) > 1000) return "oauth_states_context_check";
      if (["store_shopify", "tiktok_login", "instagram_login", "facebook_login", "store_amazon"].indexOf(row.purpose) === -1 &&
          (row.verifier_ciphertext == null || row.verifier_iv == null || row.verifier_auth_tag == null)) return "oauth_states_verifier_shape_check";
    }
    return null;
  }
  function defaults(name, row) {
    const now = new Date().toISOString();
    const r = Object.assign({ id: uuid(), created_at: now }, row);
    if (name === "member_store_connections") {
      if (r.status === undefined) r.status = "connected";
      if (r.token_version === undefined) r.token_version = 0;
      ["access_ciphertext", "access_iv", "access_auth_tag", "access_expires_at", "refresh_expires_at", "granted_scopes", "location_id", "location_name", "currency",
        "external_account_id", "marketplace_id", "region"].forEach(function (k) { if (r[k] === undefined) r[k] = null; });
    }
    if (name === "inventory_items") { if (r.status === undefined) r.status = "active"; ["source", "store_connection_id", "external_id", "external_parent_id", "external_inventory_item_id", "unit_cost"].forEach(function (k) { if (r[k] === undefined) r[k] = null; }); }
    if (name === "store_change_log" && r.confirmation === undefined) r.confirmation = "confirmed";
    if (name === "oauth_states") { ["consumed_at", "verifier_ciphertext", "verifier_iv", "verifier_auth_tag"].forEach(function (k) { if (r[k] === undefined) r[k] = null; }); }
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

/* ── Amazon (LWA and the SP-API), stubbed behind the real guarded fetcher ── */
function reply(status, body, hdrs) {
  const h = { "content-type": "application/json; charset=utf-8", "x-amzn-requestid": "req-" + Math.floor(Math.random() * 1e9) };
  Object.keys(hdrs || {}).forEach(function (k) { h[k.toLowerCase()] = String(hdrs[k]); });
  return { status: status, headers: h, raw: Buffer.from(JSON.stringify(body), "utf8") };
}
function headerOf(hdrs, name) {
  const k = Object.keys(hdrs || {}).filter(function (x) { return x.toLowerCase() === name.toLowerCase(); })[0];
  return k ? String(hdrs[k]) : null;
}
const PUBLIC_V4 = "93.184.216.34";
const LONG_SKU = "X".repeat(90);   // "sku:ATVPDKIKX0DER:" is 18 characters, so its identity is 108
const HAT = "HAT RED/L";             // a space and a slash: URL-encoded in every path
function freshListings() {
  return {
    "MUG-1": { name: "Stoneware Mug", type: "HOME", price: 18, mfn: 5, fba: null },
    [HAT]: { name: "Wool Hat", type: "HAT", price: 25, mfn: 3, fba: null },
    "FBA-SCARF": { name: "Scarf", type: "APPAREL", price: 12, mfn: null, fba: 7 },
    [LONG_SKU]: { name: "Long", type: "HOME", price: 1, mfn: 1, fba: null },
    "NOQTY-1": { name: "No stock read", type: "HOME", price: 2, mfn: null, fba: null }
  };
}
const MARKETS = {
  [US]: { countryCode: "US", currency: "USD" }, [CA]: { countryCode: "CA", currency: "CAD" },
  [UK]: { countryCode: "GB", currency: "GBP" }, [DE]: { countryCode: "DE", currency: "EUR" }
};
function orderId(n) { return "111-" + String(1000000 + n).slice(-7) + "-" + String(2000000 + n).slice(-7); }
function makeAmazon(opts, events) {
  const o = Object.assign({ participating: [US, DE, CA], orders: 2 }, opts || {});
  const ev = events || [];
  const state = { listings: freshListings(), patches: [], pending: [], throttled: false };
  const calls = [];
  const asked = [];
  function render(sku, m) {
    const L = state.listings[sku];
    const channels = L.mfn !== null ? [{ fulfillmentChannelCode: "DEFAULT", quantity: L.mfn }] : (L.fba !== null ? [{ fulfillmentChannelCode: "AMAZON_NA", quantity: L.fba }] : []);
    return { sku: sku,
      summaries: [{ marketplaceId: m, asin: "B0TEST" + String(sku.length).padStart(4, "0"), productType: L.type, itemName: L.name, status: ["BUYABLE", "DISCOVERABLE"] }],
      attributes: { item_name: [{ value: L.name, marketplace_id: m }] },
      // the B2B offer first, so only a reader that asks for B2C gets the right price
      offers: [{ marketplaceId: m, offerType: "B2B", price: { currencyCode: "USD", amount: "1.00" } }, { marketplaceId: m, offerType: "B2C", price: { currencyCode: "USD", amount: L.price.toFixed(2) } }],
      fulfillmentAvailability: channels };
  }
  function orders() {
    return Array.from({ length: o.orders }, function (_, i) {
      return { AmazonOrderId: orderId(i), PurchaseDate: new Date(NOW - 3600000 - i * 60000).toISOString(), OrderStatus: "Shipped",
        OrderTotal: { CurrencyCode: "USD", Amount: "55.00" }, BuyerInfo: { BuyerEmail: BUYER_EMAIL, BuyerName: "Jane Buyer" },
        ShippingAddress: { Name: "Jane Buyer", AddressLine1: "1 Main Street", City: "Leeds", PostalCode: "LS1 1AA", Phone: "07700900000" } };
    });
  }
  function applyPatch(p) {
    const L = state.listings[p.sku];
    if (p.field === "price") L.price = p.value; else L.mfn = p.value;
  }
  function patchProblem(sku, m, body) {
    const L = state.listings[sku];
    if (!body || typeof body !== "object" || body.productType !== L.type || !Array.isArray(body.patches) || body.patches.length !== 1) return { problem: "body" };
    const p = body.patches[0];
    if (p.op !== "replace" || !Array.isArray(p.value) || p.value.length !== 1) return { problem: "op" };
    const v = p.value[0];
    if (p.path === "/attributes/purchasable_offer") {
      const s = v && v.our_price && v.our_price[0] && v.our_price[0].schedule && v.our_price[0].schedule[0];
      if (v.marketplace_id !== m || v.currency !== "USD" || !s || typeof s.value_with_tax !== "number") return { problem: "price" };
      return { field: "price", value: s.value_with_tax };
    }
    if (p.path === "/attributes/fulfillment_availability") {
      if (v.fulfillment_channel_code !== "DEFAULT" || !Number.isInteger(v.quantity) || v.quantity < 0) return { problem: "quantity" };
      return { field: "stock", value: v.quantity };
    }
    return { problem: "path" };
  }
  function answer(url, init) {
    const u = new URL(url);
    const method = (init && init.method) || "GET";
    const contentType = headerOf(init && init.headers, "Content-Type");
    let body = null, form = null;
    if (init && init.body) {
      if (/^application\/x-www-form-urlencoded/.test(contentType || "")) form = new URLSearchParams(String(init.body));
      else { try { body = JSON.parse(String(init.body)); } catch (e) { body = "(not json)"; } }
    }
    const call = { url: url, host: u.hostname, path: u.pathname, query: u.searchParams, method: method, body: body, form: form, raw: init && init.body,
      contentType: contentType, token: headerOf(init && init.headers, "x-amz-access-token") };
    calls.push(call);
    if (u.hostname === "api.amazon.com" && u.pathname === "/auth/o2/token" && method === "POST") {
      if (!form) return reply(400, { error: "invalid_request", error_description: "the token endpoint reads a form" });
      if (form.get("client_id") !== CLIENT_ID || form.get("client_secret") !== CLIENT_SECRET) return reply(401, { error: "invalid_client" });
      if (form.get("grant_type") === "refresh_token") {
        ev.push("token:refresh");
        if (o.refresh === "refuse") return reply(400, { error: "invalid_grant", error_description: "The request has an invalid grant parameter" });
        if (o.refresh === "down") return reply(503, { error: "server_error" });
        if (form.get("refresh_token") !== REFRESH && form.get("refresh_token") !== REFRESH2) return reply(400, { error: "invalid_grant" });
        const g = { access_token: TOKEN2, token_type: "bearer", expires_in: 3600 };
        if (o.rotate) g.refresh_token = REFRESH2;
        return reply(200, g);
      }
      ev.push("token:exchange");
      if (o.exchangeStatus) return reply(o.exchangeStatus, { error: o.exchangeStatus === 400 ? "invalid_grant" : "server_error" });
      if (form.get("grant_type") !== "authorization_code" || form.get("code") !== CODE) return reply(400, { error: "invalid_grant" });
      return reply(200, { access_token: TOKEN, refresh_token: REFRESH, token_type: "bearer", expires_in: 3600 });
    }
    const region = /^sellingpartnerapi-(na|eu|fe)\.amazon\.com$/.exec(u.hostname);
    if (!region) return reply(404, { errors: [{ code: "NotFound", message: "no such address" }] });
    ev.push("api:" + method + " " + u.pathname);
    if (!call.token || (o.reject || []).indexOf(call.token) !== -1 || [TOKEN, TOKEN2, WINNER].indexOf(call.token) === -1) {
      return reply(403, { errors: [{ code: "Unauthorized", message: "Access to requested resource is denied." }] });
    }
    const p = u.pathname;
    const m = u.searchParams.get("marketplaceIds");
    const prefix = "/listings/2021-08-01/items/" + SELLER;
    if (method === "PATCH") {
      const sku = p.indexOf(prefix + "/") === 0 ? decodeURIComponent(p.slice(prefix.length + 1)) : null;
      const preview = u.searchParams.get("mode") === "VALIDATION_PREVIEW";
      state.patches.push({ sku: sku, preview: preview, body: body, query: u.search, contentType: contentType, token: call.token, host: u.hostname });
      if (!sku || !state.listings[sku] || m !== US) return reply(404, { errors: [{ code: "NOT_FOUND", message: "no such listing" }] });
      const what = patchProblem(sku, m, body);
      if (preview) {
        if (o.previewError) return reply(200, { sku: sku, status: "INVALID", submissionId: "s-preview",
          issues: [{ code: "90220", severity: "WARNING", message: "a warning only" }, { code: "8541", severity: "ERROR", message: o.previewError, attributeNames: ["purchasable_offer"] }] });
        if (what.problem) return reply(200, { sku: sku, status: "INVALID", submissionId: "s-preview", issues: [{ code: "4000", severity: "ERROR", message: "The patch is not valid: " + what.problem }] });
        return reply(200, { sku: sku, status: "VALID", submissionId: "s-preview", issues: o.previewWarning ? [{ code: "18027", severity: "WARNING", message: "Prices this low sell fast." }] : [] });
      }
      if (o.patchStatus) return reply(o.patchStatus, { errors: [{ code: "InternalFailure", message: "We encountered an internal error." }] });
      if (o.realInvalid) return reply(200, { sku: sku, status: "INVALID", submissionId: "s-real", issues: [{ code: "8105", severity: "ERROR", message: o.realInvalid }] });
      if (what.problem) return reply(200, { sku: sku, status: "INVALID", submissionId: "s-real", issues: [{ code: "4000", severity: "ERROR", message: "The patch is not valid: " + what.problem }] });
      const change = { sku: sku, field: what.field, value: what.value, after: o.applyAfterReads || 0 };
      if (o.neverApply) state.pending.push(change);
      else if (change.after > 0) state.pending.push(change);
      else applyPatch(change);
      return reply(200, { sku: sku, status: "ACCEPTED", submissionId: "s-real", issues: [] });
    }
    if (method !== "GET") return reply(405, { errors: [{ code: "MethodNotAllowed", message: "method" }] });
    if (p === "/sellers/v1/marketplaceParticipations") {
      if (o.partStatus) return reply(o.partStatus, { errors: [{ code: "InternalFailure" }] });
      return reply(200, { payload: Object.keys(MARKETS).map(function (id) {
        return { marketplace: { id: id, countryCode: MARKETS[id].countryCode, name: "Amazon " + MARKETS[id].countryCode, defaultCurrencyCode: MARKETS[id].currency, defaultLanguageCode: "en_US", domainName: "www.amazon.test" },
          participation: { isParticipating: o.participating.indexOf(id) !== -1, hasSuspendedListings: false }, storeName: "Wool and Co" };
      }) });
    }
    if (p === prefix) {
      if (o.throttleOnce && !state.throttled) { state.throttled = true; return reply(429, { errors: [{ code: "QuotaExceeded" }] }, { "x-amzn-RateLimit-Limit": "0.2" }); }
      const all = Object.keys(state.listings);
      if (o.endless) return reply(200, { numberOfResults: 99999, pagination: { nextToken: "again" }, items: [render("MUG-1", m)] });
      const tok = u.searchParams.get("pageToken");
      const page = tok === "p2" ? all.slice(3) : all.slice(0, 3);
      return reply(200, { numberOfResults: all.length, pagination: tok === "p2" ? {} : { nextToken: "p2" }, items: page.map(function (s) { return render(s, m); }) });
    }
    if (p.indexOf(prefix + "/") === 0) {
      const sku = decodeURIComponent(p.slice(prefix.length + 1));
      if (!state.listings[sku]) return reply(404, { errors: [{ code: "NOT_FOUND", message: "no such listing" }] });
      state.pending = state.pending.filter(function (c) {
        if (c.sku !== sku || o.neverApply) return true;
        c.after--; if (c.after > 0) return true;
        applyPatch(c); return false;
      });
      return reply(200, render(sku, m));
    }
    if (p === "/orders/v0/orders") {
      const all = orders();
      const start = u.searchParams.get("NextToken") ? Number(u.searchParams.get("NextToken").slice(1)) : 0;
      const pageRows = all.slice(start, start + 100);
      const payload = { Orders: pageRows, CreatedBefore: new Date(NOW).toISOString() };
      if (start + 100 < all.length) payload.NextToken = "o" + (start + 100);
      return reply(200, { payload: payload });
    }
    const oi = /^\/orders\/v0\/orders\/([0-9-]+)\/orderItems$/.exec(p);
    if (oi) return reply(200, { payload: { AmazonOrderId: oi[1], OrderItems: [
      { SellerSKU: "MUG-1", QuantityOrdered: 2, Title: "Stoneware Mug", ASIN: "B0TEST0005", BuyerInfo: { GiftMessageText: "Happy birthday Jane" } },
      { SellerSKU: HAT, QuantityOrdered: 1, Title: "Wool Hat", ASIN: "B0TEST0009" }] } });
    return reply(404, { errors: [{ code: "NotFound", message: "no stub for " + p }] });
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
    asked.push({ url: url, method: (options && options.method) || "GET", options: options });
    return guarded(url, options);
  }
  function api(method, pathRe) { return calls.filter(function (c) { return /^sellingpartnerapi-/.test(c.host) && (!method || c.method === method) && (!pathRe || pathRe.test(c.path)); }); }
  function tokenCalls(kind) { return calls.filter(function (c) { return c.host === "api.amazon.com" && (!kind || (kind === "refresh") === !!(c.form && c.form.get("grant_type") === "refresh_token")); }); }
  function applyPending() { state.pending.forEach(applyPatch); state.pending = []; }
  return { jsonRequest: jsonRequest, calls: calls, asked: asked, state: state, opts: o, api: api, tokenCalls: tokenCalls, events: ev, applyPending: applyPending };
}

/* THE NETWORK TRIPWIRE: no socket, no real DNS question, no fetch, in this whole run. */
const TRIPPED = [];
(function tripwire() {
  const http = require("http"), https = require("https"), net = require("net"), tls = require("tls"), dns = require("dns");
  function wire(obj, name, label) { obj[name] = function () { TRIPPED.push(label); throw new Error("checkAmazonConnect: " + label + " is not allowed in this check"); }; }
  wire(http, "request", "http.request"); wire(http, "get", "http.get");
  wire(https, "request", "https.request"); wire(https, "get", "https.get");
  wire(net, "connect", "net.connect"); wire(net, "createConnection", "net.createConnection");
  wire(tls, "connect", "tls.connect");
  wire(dns, "lookup", "dns.lookup"); wire(dns, "resolve", "dns.resolve"); wire(dns.promises, "lookup", "dns.promises.lookup");
  globalThis.fetch = function () { TRIPPED.push("fetch"); return Promise.reject(new Error("checkAmazonConnect: fetch is not allowed in this check")); };
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
  const amazon = makeAmazon(env.amazon, events);
  const logs = [];
  const routes = {};
  const crypt = {
    encrypt: function (p) {
      events.push(String(p).indexOf(REFRESH) !== -1 ? "encrypt:refresh" : (/^Atza\|/.test(String(p)) ? "encrypt:access" : "encrypt:other"));
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
      if (r === "./lib/guardedFetch") return Object.assign({}, GF, { guardedJsonRequest: amazon.jsonRequest });
      if (r === "./lib/amazonAuth") return AA;
      if (r === "./lib/amazonApi") return AAPI;
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
  return { db: db, amazon: amazon, logs: logs, routes: routes, events: events, ctx: ctx };
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
  const r = await hit(m, "post /api/store/amazon/start", { body: body || { marketplace_id: US }, user: { id: user || USER } });
  const url = r.body && r.body.authorize_url ? new URL(r.body.authorize_url) : null;
  return { r: r, url: url, state: url ? url.searchParams.get("state") : null };
}
function finish(m, state, user, over) {
  return hit(m, "post /api/store/amazon/finish", { body: Object.assign({ spapi_oauth_code: CODE, state: state, selling_partner_id: SELLER }, over || {}), user: { id: user || USER } });
}
const INVALID = { error: "That Amazon connection link has expired or was already used. Start again.", code: "state_invalid", saved: false };
function consumed(m) { return m.db.t.oauth_states.filter(function (s) { return s.consumed_at != null; }).length; }
function connWrites(db) { return db.log.filter(function (l) { return l.table === "member_store_connections" && (l.op === "insert" || l.op === "update" || l.op === "upsert"); }).length; }

/* lib-level deps and a connected Amazon row */
function libDeps(db, amazon, extra) {
  const sleeps = [];
  return Object.assign({
    supabase: db, env: {}, jsonRequest: amazon.jsonRequest, now: function () { return NOW; },
    sleep: function (ms) { sleeps.push(ms); amazon.events.push("sleep:" + ms); return Promise.resolve(); }, sleeps: sleeps,
    encrypt: CRYPT.encrypt, decrypt: CRYPT.decrypt,
    amazonReader: AAPI, amazonConfig: function () { return CONFIG; }, etsyReader: EAPI, shopifyReader: SAPI,
    userPlan: async function () { return { plan: { active: true }, error: null }; }
  }, extra || {});
}
function amazonConn(db, over) {
  const sealed = SS.sealCredentials({ refresh_token: REFRESH }, CRYPT.encrypt);
  const access = CRYPT.encrypt((over && over.__token) || TOKEN);
  const row = Object.assign({ id: uuid(), user_id: USER, platform: "amazon", store_url: "https://www.amazon.com", status: "connected", permission: "read_write",
    access_ciphertext: access.ciphertext, access_iv: access.iv, access_auth_tag: access.authTag,
    access_expires_at: new Date(NOW + 50 * 60 * 1000).toISOString(), refresh_expires_at: null, token_version: 0,
    granted_scopes: null, location_id: null, location_name: null, currency: "USD", external_account_id: SELLER, marketplace_id: US, region: "na",
    created_at: "2026-11-08T00:00:00.000Z" }, sealed, over || {});
  delete row.__token;
  db.t.member_store_connections.push(row);
  return row;
}
function accessOf(row) { try { return CRYPT.decrypt({ ciphertext: row.access_ciphertext, iv: row.access_iv, authTag: row.access_auth_tag }); } catch (e) { return null; } }
function refreshOf(row) { try { return SS.openCredentials(row, CRYPT.decrypt).refresh_token; } catch (e) { return null; } }
async function attempt(p) { try { return { ok: true, v: await p }; } catch (e) { return { ok: false, msg: e && e.message, name: e && e.name, code: e && e.code }; } }
function itemOf(db, externalId) { return db.t.inventory_items.filter(function (r) { return r.external_id === externalId; })[0]; }
function idOf(sku) { return "sku:" + US + ":" + sku; }
async function synced(over, amazonOpts) {
  const db = makeDb(), amazon = makeAmazon(amazonOpts);
  const conn = amazonConn(db, over);
  const deps = libDeps(db, amazon);
  const r = await SS.syncConnection(deps, conn);
  return { db: db, amazon: amazon, conn: conn, deps: deps, r: r };
}
/* every orderItems read has a 2 s sleep between it and the read before it */
function pacedOrderItems(events) {
  let sincePrev = [], seen = 0, ok = true;
  events.forEach(function (e) {
    if (/^sleep:/.test(e)) { sincePrev.push(e); return; }
    if (/^api:GET \/orders\/v0\/orders\/[^/]+\/orderItems$/.test(e)) { seen++; if (sincePrev.indexOf("sleep:2000") === -1) ok = false; }
    if (/^api:/.test(e)) sincePrev = [];
  });
  return { ok: ok && seen > 0, seen: seen };
}

/* ── the Store page in a fake DOM, with sessionStorage ─────────────────── */
const API = "https://dynamic-prosperity-production-5382.up.railway.app";
const AMAZON_VIEW = { id: "33333333-3333-4333-8333-333333333333", platform: "amazon", platform_label: "Amazon", store: "https://www.amazon.com", status: "connected", permission: "read",
  currency: "USD", location_id: null, location_name: null, stock_scope: null, shop_name: null, marketplace_id: US, marketplace: "US", region: "na",
  connected_since: "2026-11-08T10:00:00Z", last_sync_at: null, last_error_code: null };
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
  const location = { search: search, assign: function (u) { dom.events.push("assign"); dom.assigned.push(u); } };
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
    if (p === "/api/store/connections" && method === "GET") return { status: 200, body: { connections: [AMAZON_VIEW], note: "", shopify_available: true, etsy_available: true, amazon_available: true, amazon_draft: true } };
    if (p === "/api/store/amazon/start") return { status: 200, body: { authorize_url: "https://sellercentral-europe.amazon.com/apps/authorize/consent?application_id=x&state=y", permission: "read", saved: false } };
    if (p === "/api/store/amazon/finish") return { status: 200, body: { saved: true, connection: AMAZON_VIEW } };
    if (p === "/api/store/etsy/finish") return { status: 200, body: { saved: true } };
    if (p === "/api/store/shopify/finish") return { status: 200, body: { saved: true } };
    return { status: 404, body: { error: "Not found" } };
  };
}
function allText(n) { return n ? n.textContent : ""; }
const SELLER_Q = "?spapi_oauth_code=" + CODE + "&state=" + "S".repeat(43) + "&selling_partner_id=" + SELLER;

(async function main() {
  let r, m;

  /* ── A. sign-in ─────────────────────────────────────────────────────────── */
  console.log("\n══ A. sign-in (lib/amazonAuth.js) ══");
  check("A1. configured: all three of AMAZON_SPAPI_APP_ID, AMAZON_LWA_CLIENT_ID and AMAZON_LWA_CLIENT_SECRET, or null",
    J(AA.configured(CONFIGURED)) === J(CONFIG) && AA.configured({ AMAZON_SPAPI_APP_ID: APP_ID, AMAZON_LWA_CLIENT_ID: CLIENT_ID }) === null &&
    AA.configured({ AMAZON_LWA_CLIENT_ID: CLIENT_ID, AMAZON_LWA_CLIENT_SECRET: CLIENT_SECRET }) === null && AA.configured({}) === null);
  check("A2. draft unless AMAZON_SPAPI_DRAFT is exactly \"false\": unset, \"FALSE\", \"0\", \"no\" and \"true\" are draft",
    AA.isDraft({}) === true && AA.isDraft({ AMAZON_SPAPI_DRAFT: "false" }) === false && AA.isDraft({ AMAZON_SPAPI_DRAFT: "FALSE" }) === true &&
    AA.isDraft({ AMAZON_SPAPI_DRAFT: "0" }) === true && AA.isDraft({ AMAZON_SPAPI_DRAFT: "no" }) === true && AA.isDraft({ AMAZON_SPAPI_DRAFT: "true" }) === true &&
    AA.configured(Object.assign({ AMAZON_SPAPI_DRAFT: "false" }, CONFIGURED)).draft === false);
  const tableNow = Object.keys(AA.MARKETPLACES).map(function (id) { const x = AA.MARKETPLACES[id]; return [x.code, id, x.sellerCentral, x.storefront, x.region]; });
  check("A3. the marketplace table is the brief's, entry for entry and in order: 20 marketplaces, each id, Seller Central host, storefront host and region",
    J(tableNow) === J(BRIEF_MARKETPLACES), J(tableNow.filter(function (x, i) { return J(x) !== J(BRIEF_MARKETPLACES[i]); })));
  check("A4. the three SP-API endpoints are the brief's, and every marketplace's region has one", J(AA.REGION_ENDPOINTS) === J(BRIEF_ENDPOINTS) &&
    BRIEF_MARKETPLACES.every(function (b) { return AA.endpointOf(b[4]) === BRIEF_ENDPOINTS[b[4]]; }) && AA.endpointOf("xx") === null && AA.marketplaceOf("ZZZZZZZZZZ") === null &&
    AA.marketplaceOf("constructor") === null);
  const st1 = AA.newState();
  const hostsOk = BRIEF_MARKETPLACES.every(function (b) {
    const d = new URL(AA.consentUrl(CONFIG, b[1], st1)), p = new URL(AA.consentUrl(Object.assign({}, CONFIG, { draft: false }), b[1], st1));
    return d.origin === "https://" + b[2] && d.pathname === "/apps/authorize/consent" && d.searchParams.get("application_id") === APP_ID && d.searchParams.get("state") === st1 &&
      d.searchParams.get("version") === "beta" && p.origin === "https://" + b[2] && p.searchParams.get("version") === null && J([...p.searchParams.keys()]) === J(["application_id", "state"]);
  });
  check("A5. the consent page: each marketplace's own Seller Central host, /apps/authorize/consent, application_id and state, version=beta in draft only",
    hostsOk && /^[A-Za-z0-9_-]{43}$/.test(st1) && AA.stateHash(st1) === crypto.createHash("sha256").update(st1).digest("hex"));
  {
    const a = makeAmazon({}), toks = await attempt(AA.exchangeCode(CONFIG, CODE, a.jsonRequest));
    const c = a.tokenCalls()[0] || {};
    check("A6. the code exchange is ONE form POST to https://api.amazon.com/auth/o2/token: grant_type authorization_code, code, client_id, client_secret",
      toks.ok && a.tokenCalls().length === 1 && c.method === "POST" && c.host === "api.amazon.com" && c.path === "/auth/o2/token" &&
      /^application\/x-www-form-urlencoded/.test(c.contentType || "") && c.form && J([...c.form.keys()].sort()) === J(["client_id", "client_secret", "code", "grant_type"]) &&
      c.form.get("grant_type") === "authorization_code" && toks.v.accessToken === TOKEN && toks.v.refreshToken === REFRESH && toks.v.expiresIn === 3600, J([toks.ok, c.contentType]));
    const a2 = makeAmazon({}), ref = await attempt(AA.refreshTokens(CONFIG, REFRESH, a2.jsonRequest));
    const c2 = a2.tokenCalls()[0] || {};
    check("A7. a refresh is ONE form POST: grant_type refresh_token, refresh_token, client_id, client_secret; the refresh token may stay the same",
      ref.ok && ref.v.accessToken === TOKEN2 && ref.v.refreshToken === null && /^application\/x-www-form-urlencoded/.test(c2.contentType || "") &&
      J([...c2.form.keys()].sort()) === J(["client_id", "client_secret", "grant_type", "refresh_token"]) && c2.form.get("refresh_token") === REFRESH);
    const bad = await attempt(AA.refreshTokens(CONFIG, REFRESH, makeAmazon({ refresh: "refuse" }).jsonRequest));
    const down = await attempt(AA.refreshTokens(CONFIG, REFRESH, makeAmazon({ refresh: "down" }).jsonRequest));
    const wrongClient = await attempt(AA.exchangeCode(Object.assign({}, CONFIG, { clientSecret: "nope" }), CODE, makeAmazon({}).jsonRequest));
    check("A8. invalid_grant is kind rejected; LWA failing is unreachable; LWA refusing the client is refused; no error carries a token, code or secret",
      !bad.ok && /rejected/.test(bad.msg) && !down.ok && /unreachable/.test(down.msg) && !wrongClient.ok && /refused/.test(wrongClient.msg) &&
      [bad.msg, down.msg, wrongClient.msg].every(noSecretIn), J([bad.msg, down.msg, wrongClient.msg]));
    check("A9. a token answer without an access token, a refresh token (on the exchange) or expires_in is refused",
      (function () { try { AA.grantFrom({ refresh_token: "r", expires_in: 3600 }, true); return false; } catch (e) { return true; } })() &&
      (function () { try { AA.grantFrom({ access_token: TOKEN, expires_in: 3600 }, true); return false; } catch (e) { return true; } })() &&
      (function () { try { AA.grantFrom({ access_token: TOKEN, refresh_token: REFRESH }, true); return false; } catch (e) { return true; } })() &&
      AA.grantFrom({ access_token: TOKEN, expires_in: 3600 }, false).refreshToken === null);
    const shape = function (o) { return AA.finishShape(Object.assign({ spapi_oauth_code: CODE, state: st1, selling_partner_id: SELLER }, o)).ok; };
    check("A10. the finish body: spapi_oauth_code, a 43-character state and a seller id matching ^[A-Z0-9]{8,20}$", shape({}) === true &&
      shape({ selling_partner_id: "a3sellerx0example" }) === false && shape({ selling_partner_id: "A3SELL" }) === false && shape({ selling_partner_id: "A".repeat(21) }) === false &&
      shape({ selling_partner_id: "A3SELLER X0EXAMPLE" }) === false && shape({ selling_partner_id: undefined }) === false && shape({ state: "short" }) === false &&
      shape({ spapi_oauth_code: "a b" }) === false && shape({ spapi_oauth_code: "" }) === false);
    check("A11. the access token is stored as expiring 60 s early; the refresh token has no expiry (refresh_expires_at NULL)",
      J(AA.expiriesFor({ expiresIn: 3600 }, NOW)) === J({ access_expires_at: new Date(NOW + 3540000).toISOString(), refresh_expires_at: null }));
  }

  /* ── B. the routes ──────────────────────────────────────────────────────── */
  console.log("\n══ B. the routes (server.js) ══");
  ["post /api/store/amazon/start", "post /api/store/amazon/finish"].forEach(function (k) {
    const mm = mountRoutes({ env: CONFIGURED }), route = mm.routes[k];
    check("B0. " + k + " is requireAuth, requireActiveSubscription and the other store connects' limiter", !!route && route.middleware.length === 3 && route.middleware[0] === requireAuth &&
      route.middleware[1] === requireActiveSubscription && route.middleware[2] === mm.routes["post /api/store/etsy/start"].middleware[2] &&
      route.middleware[2] === mm.routes["post /api/store/shopify/start"].middleware[2] && !!route.middleware[2].limiter);
  });
  for (const env of [{}, { AMAZON_SPAPI_APP_ID: APP_ID, AMAZON_LWA_CLIENT_ID: CLIENT_ID }]) {
    m = mountRoutes({ env: env });
    r = await hit(m, "post /api/store/amazon/start", { body: { marketplace_id: US } });
    const rf = await hit(m, "post /api/store/amazon/finish", { body: { spapi_oauth_code: CODE, state: st1, selling_partner_id: SELLER } });
    const rl = await hit(m, "get /api/store/connections", {});
    check("B1. unconfigured (" + Object.keys(env).length + " of 3 set): start and finish answer 503 \"Amazon connection isn't set up yet.\"; nothing asked or stored; amazon_available false",
      r.status === 503 && r.body.error === "Amazon connection isn't set up yet." && rf.status === 503 && rf.body.error === "Amazon connection isn't set up yet." &&
      m.amazon.calls.length === 0 && m.db.t.oauth_states.length === 0 && rl.body.amazon_available === false, J([r.status, rf.status, rl.body.amazon_available]));
  }
  m = mountRoutes({ env: CONFIGURED });
  const noMarket = await hit(m, "post /api/store/amazon/start", { body: { allow_changes: true } });
  const badMarket = await hit(m, "post /api/store/amazon/start", { body: { marketplace_id: "A1B2C3D4E5F6G7" } });
  const badAllow = await hit(m, "post /api/store/amazon/start", { body: { marketplace_id: US, allow_changes: "yes" } });
  check("B2. no marketplace, or one not in the table: 400 \"Choose the Amazon marketplace you sell in.\"; allow_changes not true or false: 400; nothing stored",
    noMarket.status === 400 && noMarket.body.error === "Choose the Amazon marketplace you sell in." && badMarket.status === 400 && badMarket.body.code === "marketplace" &&
    badAllow.status === 400 && badAllow.body.code === "allow_changes" && m.db.t.oauth_states.length === 0);
  let b = await begin(m);
  const stateRow = m.db.t.oauth_states[0] || {};
  check("B3. start: Seller Central's consent page for the US (sellercentral.amazon.com) with version=beta in draft; only the state's sha256 stored, purpose store_amazon, 10 minutes, flow_context exactly {marketplace_id, region na, permission read}, no verifier",
    b.r.status === 200 && b.url && b.url.origin === "https://sellercentral.amazon.com" && b.url.pathname === "/apps/authorize/consent" && b.url.searchParams.get("application_id") === APP_ID &&
    b.url.searchParams.get("version") === "beta" && b.r.body.draft === true && b.r.body.marketplace_id === US && m.db.t.oauth_states.length === 1 && stateRow.purpose === "store_amazon" &&
    stateRow.state_hash === crypto.createHash("sha256").update(b.state).digest("hex") && J(stateRow).indexOf(b.state) === -1 &&
    J(stateRow.flow_context) === J({ marketplace_id: US, region: "na", permission: "read" }) && stateRow.verifier_ciphertext == null &&
    Date.parse(stateRow.expires_at) - Date.parse(stateRow.created_at) === 10 * 60 * 1000 && b.r.headers["Cache-Control"] === "no-store" && m.amazon.calls.length === 0,
    J([b.r.status, b.r.body, stateRow.flow_context]));
  {
    const mp = mountRoutes({ env: Object.assign({ AMAZON_SPAPI_DRAFT: "false" }, CONFIGURED) });
    const uk = await begin(mp, { marketplace_id: UK, allow_changes: true });
    const jp = await begin(mp, { marketplace_id: "A1VC38T7YXB528" });
    const tr = await begin(mp, { marketplace_id: "A33AVAJ2PDY3EV" });
    check("B4. published: no version=beta; the UK on sellercentral-europe.amazon.com (region eu), Japan on sellercentral.amazon.co.jp (fe), Turkey on its own host",
      uk.url.origin === "https://sellercentral-europe.amazon.com" && uk.url.searchParams.get("version") === null && uk.r.body.draft === false &&
      J(mp.db.t.oauth_states[0].flow_context) === J({ marketplace_id: UK, region: "eu", permission: "read_write" }) &&
      jp.url.origin === "https://sellercentral.amazon.co.jp" && mp.db.t.oauth_states[1].flow_context.region === "fe" && tr.url.origin === "https://sellercentral.amazon.com.tr",
      J([uk.url && uk.url.href, jp.url && jp.url.origin, tr.url && tr.url.origin]));
  }
  r = await finish(m, b.state);
  const row = m.db.t.member_store_connections[0] || {};
  const firstApi = m.events.findIndex(function (e) { return /^api:/.test(e); });
  const exch = m.amazon.tokenCalls()[0] || {};
  check("B5. finish: the code exchanged as a form with the client id and secret, both tokens sealed BEFORE the SP-API is asked anything, then only the participations read, on the na endpoint",
    r.status === 200 && r.body.saved === true && m.amazon.tokenCalls().length === 1 && /^application\/x-www-form-urlencoded/.test(exch.contentType || "") &&
    exch.form && exch.form.get("code") === CODE && exch.form.get("client_secret") === CLIENT_SECRET &&
    m.events.indexOf("encrypt:access") !== -1 && m.events.indexOf("encrypt:refresh") !== -1 && firstApi > m.events.indexOf("encrypt:access") && firstApi > m.events.indexOf("encrypt:refresh") &&
    J(m.events.filter(function (e) { return /^api:/.test(e); })) === J(["api:GET /sellers/v1/marketplaceParticipations"]) &&
    m.amazon.api().every(function (c) { return c.host === "sellingpartnerapi-na.amazon.com" && c.token === TOKEN; }), J([r.status, r.body, m.events]));
  check("B6. the row: platform amazon, the seller id, the US marketplace and region na, https://www.amazon.com, USD from the participation, read, granted_scopes NULL, refresh_expires_at NULL, tokens sealed",
    row.platform === "amazon" && row.external_account_id === SELLER && row.marketplace_id === US && row.region === "na" && row.store_url === "https://www.amazon.com" &&
    row.currency === "USD" && row.permission === "read" && row.granted_scopes === null && row.refresh_expires_at === null && row.token_version === 0 &&
    accessOf(row) === TOKEN && refreshOf(row) === REFRESH && row.location_id === null && J(row).indexOf(TOKEN) === -1 && J(row).indexOf(REFRESH) === -1 &&
    Math.abs(Date.parse(row.access_expires_at) - (Date.now() + 3540000)) < 60000, J([row.platform, row.marketplace_id, row.region, row.currency, row.granted_scopes]));
  check("B7. the answer: the safe fields with the marketplace (US) and region, Amazon's label, never a token", r.body.connection && r.body.connection.platform_label === "Amazon" &&
    r.body.connection.marketplace === "US" && r.body.connection.marketplace_id === US && r.body.connection.region === "na" && r.body.connection.permission === "read" &&
    noSecretIn(J(r.body)) && !/ciphertext|_iv|auth_tag/.test(J(r.body)), J(r.body));
  const r2 = await finish(m, b.state);
  check("B8. the state is spent: a second finish with it is the same 400, nothing exchanged again", r2.status === 400 && J(r2.body) === J(INVALID) && m.amazon.tokenCalls().length === 1, J([r2.status, r2.body]));
  {
    const ms = mountRoutes({ env: CONFIGURED });
    const bs = await begin(ms);
    const tries = [];
    for (const bad of ["a3sellerx0example", "A3SELL", "A3SELLER X0EXAMPLE", "A3SELLER-0EXAMPLE", "A".repeat(21)]) tries.push(await finish(ms, bs.state, USER, { selling_partner_id: bad }));
    const good = await finish(ms, bs.state);
    check("B9. a selling_partner_id not matching ^[A-Z0-9]{8,20}$: the same 400, the state NOT spent, nothing exchanged; the right one then connects",
      tries.every(function (t) { return t.status === 400 && J(t.body) === J(INVALID); }) && good.status === 200 && ms.amazon.tokenCalls().length === 1 &&
      ms.db.t.member_store_connections.length === 1, J(tries.map(function (t) { return t.status; }).concat([good.status])));
  }
  {
    const mn = mountRoutes({ env: CONFIGURED, amazon: { participating: [US] } });
    const bn = await begin(mn, { marketplace_id: DE });
    const rn = await finish(mn, bn.state);
    check("B10. a marketplace the seller does not sell in: 422 \"Your seller account doesn't sell in that marketplace. Choose another and connect again.\", nothing stored",
      rn.status === 422 && rn.body.error === "Your seller account doesn't sell in that marketplace. Choose another and connect again." && rn.body.code === "not_participating" &&
      mn.db.t.member_store_connections.length === 0 && mn.amazon.api().every(function (c) { return c.host === "sellingpartnerapi-eu.amazon.com"; }), J([rn.status, rn.body]));
  }
  // one seller account and marketplace, one member
  m = mountRoutes({ env: CONFIGURED });
  b = await begin(m); await finish(m, b.state);
  const firstRow = Object.assign({}, m.db.t.member_store_connections[0]);
  const writesBefore = connWrites(m.db);
  b = await begin(m, { marketplace_id: US }, OTHER);
  r = await finish(m, b.state, OTHER);
  check("B11. the same seller account and marketplace for another member: 409 \"This Amazon seller account and marketplace are already connected to another BizForce account.\", refused before any write, the first row untouched",
    r.status === 409 && r.body.error === "This Amazon seller account and marketplace are already connected to another BizForce account." && r.body.code === "seller_taken" &&
    m.db.t.member_store_connections.length === 1 && J(m.db.t.member_store_connections[0]) === J(firstRow) && connWrites(m.db) === writesBefore, J([r.status, r.body, connWrites(m.db) - writesBefore]));
  b = await begin(m, { marketplace_id: CA }, OTHER);
  r = await finish(m, b.state, OTHER);
  check("B12. the same seller in another marketplace is another connection (the index is seller and marketplace)", r.status === 200 && m.db.t.member_store_connections.length === 2 &&
    m.db.t.member_store_connections[1].store_url === "https://www.amazon.ca" && m.db.t.member_store_connections[1].currency === "CAD", J([r.status, r.body]));
  b = await begin(m, { marketplace_id: US, allow_changes: true });
  r = await finish(m, b.state);
  check("B13. the same member connecting the same marketplace again: one row, updated in place, changes now allowed", r.status === 200 &&
    m.db.t.member_store_connections.filter(function (x) { return x.user_id === USER; }).length === 1 && m.db.t.member_store_connections[0].id === firstRow.id &&
    m.db.t.member_store_connections[0].permission === "read_write" && r.body.connection.permission === "read_write", J([r.status, r.body]));
  m = mountRoutes({ env: CONFIGURED });
  b = await begin(m);
  r = await finish(m, b.state, OTHER);
  check("B14. another member's state: the same 400, nothing exchanged", r.status === 400 && J(r.body) === J(INVALID) && m.amazon.tokenCalls().length === 0);
  m = mountRoutes({ env: CONFIGURED, amazon: { exchangeStatus: 400 } });
  b = await begin(m); r = await finish(m, b.state);
  const m2 = mountRoutes({ env: CONFIGURED, amazon: { exchangeStatus: 503 } });
  const b2 = await begin(m2); const r3 = await finish(m2, b2.state);
  const m3 = mountRoutes({ env: CONFIGURED, amazon: { partStatus: 500 } });
  const b3 = await begin(m3); const r4 = await finish(m3, b3.state);
  check("B15. LWA refusing the code: the same 400 as a bad state; LWA failing: 502; the participations failing: 502; nothing stored in any",
    r.status === 400 && J(r.body) === J(INVALID) && r3.status === 502 && r4.status === 502 && r4.body.code === "unreachable" &&
    m.db.t.member_store_connections.length === 0 && m2.db.t.member_store_connections.length === 0 && m3.db.t.member_store_connections.length === 0, J([r.status, r3.status, r4.status]));
  m = mountRoutes({ env: CONFIGURED });
  r = await hit(m, "post /api/store/connections", { body: { platform: "amazon" } });
  check("B16. POST /api/store/connections with platform amazon: 400 \"Use Connect Amazon on the Store Agent page.\"", r.status === 400 && r.body.code === "use_connect_amazon" &&
    r.body.error === "Use Connect Amazon on the Store Agent page.");
  b = await begin(m); await finish(m, b.state);
  r = await hit(m, "get /api/store/connections", {});
  const rp = await hit(mountRoutes({ env: Object.assign({ AMAZON_SPAPI_DRAFT: "false" }, CONFIGURED) }), "get /api/store/connections", {});
  check("B17. the list: amazon_available true, amazon_draft true (false once published), the connection with its marketplace", r.body.amazon_available === true && r.body.amazon_draft === true &&
    rp.body.amazon_draft === false && r.body.connections.length === 1 && r.body.connections[0].marketplace === "US" && noSecretIn(J(r.body)));
  r = await hit(m, "delete /api/store/connections/:id", { params: { id: m.db.t.member_store_connections[0].id } });
  check("B18. disconnect: the row gone, and the note \"Disconnected. To remove BizForce from Amazon too, open Seller Central, then Apps and Services, then Manage Your Apps.\"",
    r.status === 200 && r.body.note === "Disconnected. To remove BizForce from Amazon too, open Seller Central, then Apps and Services, then Manage Your Apps." &&
    m.db.t.member_store_connections.length === 0, J(r.body));
  check("B19. no route log line carries a token, a code, a secret or a buyer field", m.logs.every(noSecretIn), J(m.logs.filter(function (l) { return !noSecretIn(l); }).slice(0, 2)));

  /* ── C. the sync ────────────────────────────────────────────────────────── */
  console.log("\n══ C. the sync ══");
  let s = await synced({ permission: "read", currency: null });
  const ids = s.db.t.inventory_items.map(function (x) { return x.external_id; }).sort();
  check("C1. every item is sku:<marketplaceId>:<sku>, the SKU as the seller set it; external_parent_id NULL",
    J(ids) === J([idOf("FBA-SCARF"), idOf(HAT), idOf("MUG-1")].sort()) && s.db.t.inventory_items.every(function (x) { return x.external_parent_id === null && x.source === "amazon"; }), J(ids));
  const mug = itemOf(s.db, idOf("MUG-1")) || {};
  check("C2. an item: the summary's name, the SKU, the B2C offer's price (never the B2B one), the DEFAULT channel's stock", mug.name === "Stoneware Mug" && mug.sku === "MUG-1" &&
    mug.unit_price === 18 && mug.quantity_on_hand === 5 && (itemOf(s.db, idOf(HAT)) || {}).unit_price === 25, J(mug));
  check("C3. an FBA item (no DEFAULT channel) keeps Amazon's stock for display", (itemOf(s.db, idOf("FBA-SCARF")) || {}).quantity_on_hand === 7 &&
    AAPI.listingOf(US, { sku: "x", fulfillmentAvailability: [{ fulfillmentChannelCode: "AMAZON_EU", quantity: 4 }] }).fba === true &&
    AAPI.listingOf(US, { sku: "x", fulfillmentAvailability: [{ fulfillmentChannelCode: "DEFAULT", quantity: 4 }] }).fba === false);
  check("C4. an identity over 100 characters is skipped and logged by its code only; an item with no stock read is skipped as untracked",
    s.r.ok === true && s.r.skipped_id_too_long === 1 && s.r.skipped_untracked === 1 && !itemOf(s.db, idOf(LONG_SKU)) &&
    LOGS.some(function (l) { return l === "[StoreSync] an Amazon item was skipped: id_too_long"; }) && !LOGS.some(function (l) { return l.indexOf(LONG_SKU) !== -1; }), J(s.r));
  const search = s.amazon.api("GET", /^\/listings\/2021-08-01\/items\/[A-Z0-9]+$/);
  check("C5. listings: searchListingsItems for the seller in the marketplace, includedData summaries,attributes,offers,fulfillmentAvailability, pageSize 20, then nextToken as pageToken",
    search.length === 2 && search[0].path === "/listings/2021-08-01/items/" + SELLER && search[0].query.get("marketplaceIds") === US &&
    search[0].query.get("includedData") === "summaries,attributes,offers,fulfillmentAvailability" && search[0].query.get("pageSize") === "20" &&
    search[0].query.get("pageToken") === null && search[1].query.get("pageToken") === "p2", J(search.map(function (c) { return c.url; })));
  const sums = s.db.t.store_order_summaries;
  check("C6. orders stored as number, date, total, currency and SKU and quantity only: no buyer name, email, address, phone or gift message anywhere in the database",
    sums.length === 2 && sums[0].platform === "amazon" && sums[0].external_id === orderId(0) && sums[0].total === 55 && sums[0].currency === "USD" &&
    J(sums[0].line_items) === J([{ sku: "MUG-1", quantity: 2 }, { sku: HAT, quantity: 1 }]) && !BUYER_BITS.test(J(s.db.t)), J(sums[0]));
  const rawOrder = { AmazonOrderId: orderId(7), PurchaseDate: "2026-11-01T10:00:00Z", OrderTotal: { CurrencyCode: "USD", Amount: "9.50" }, BuyerInfo: { BuyerEmail: BUYER_EMAIL, BuyerName: "Jane Buyer" },
    ShippingAddress: { Name: "Jane Buyer", AddressLine1: "1 Main Street", City: "Leeds", Phone: "07700900000" } };
  const os = AAPI.orderSummary(rawOrder);
  const ol = AAPI.orderLine({ SellerSKU: "A", QuantityOrdered: 1, Title: "t", BuyerInfo: { GiftMessageText: "Happy birthday Jane" } });
  // NAMED (Nov 11 2026, orbit stage 2): BEFORE five keys. AFTER order_status too (OrderStatus), for the order's status; still no buyer field.
  check("C7. orderSummary keeps exactly id, created_at, total, currency, order_status and line_items; orderLine exactly sku and quantity; neither carries a buyer field",
    J(Object.keys(os).sort()) === J(["created_at", "currency", "id", "line_items", "order_status", "total"]) && J(Object.keys(ol).sort()) === J(["quantity", "sku"]) &&
    os.total === 9.5 && os.currency === "USD" && os.created_at === "2026-11-01T10:00:00.000Z" && noSecretIn(J([os, ol])), J([os, ol]));
  const ordersAsked = s.amazon.api("GET", /^\/orders\/v0\/orders$/);
  check("C8. orders asked for the marketplace over the last 60 days, 100 a page", ordersAsked.length === 1 && ordersAsked[0].query.get("MarketplaceIds") === US &&
    ordersAsked[0].query.get("CreatedAfter") === new Date(NOW - 60 * 86400000).toISOString() && ordersAsked[0].query.get("MaxResultsPerPage") === "100", ordersAsked[0] && ordersAsked[0].url);
  const paced = pacedOrderItems(s.amazon.events);
  check("C9. each order's items are read 2 s after the read before (getOrderItems is about 0.5 a second)", paced.ok && paced.seen === 2 &&
    s.amazon.api("GET", /\/orderItems$/).length === 2, J(paced));
  check("C10. every read was a GET to the na endpoint with x-amz-access-token, exposing x-amzn-ratelimit-limit and x-amzn-requestid; no PATCH",
    s.amazon.calls.every(function (c) { return c.method === "GET" && c.host === "sellingpartnerapi-na.amazon.com" && c.token === TOKEN; }) && s.amazon.state.patches.length === 0 &&
    s.amazon.asked.every(function (a) { return a.method === "GET" && Array.isArray(a.options.exposeHeaders) && a.options.exposeHeaders.indexOf("x-amzn-ratelimit-limit") !== -1 &&
      a.options.exposeHeaders.indexOf("x-amzn-requestid") !== -1; }));
  check("C11. the connected marketplace's currency, from the participations, is stored on the connection", s.db.t.member_store_connections[0].currency === "USD" && s.r.currency === "USD");
  {
    const one = await AAPI.liveItem(s.deps, AAPI.session(s.db.t.member_store_connections[0]), idOf(HAT));
    const last = s.amazon.api("GET").slice(-1)[0] || {};
    check("C12. getListingsItem: the SKU URL-encoded in the path (\"HAT RED/L\" as HAT%20RED%2FL), the marketplace and includedData; the product type from the summary",
      last.url.indexOf("/listings/2021-08-01/items/" + SELLER + "/HAT%20RED%2FL?marketplaceIds=" + US + "&includedData=summaries,attributes,offers,fulfillmentAvailability") !== -1 &&
      one.product_type === "HAT" && one.price === "25.00" && one.quantity === 3 && one.fba === false, last.url);
  }
  const before = ids.slice();
  const again = await SS.syncConnection(s.deps, s.db.t.member_store_connections[0]);
  check("C13. a second sync finds the same items, updated in place, none added, and the same order summaries", again.ok && s.db.t.inventory_items.length === 3 &&
    J(s.db.t.inventory_items.map(function (x) { return x.external_id; }).sort()) === J(before) && s.db.t.store_order_summaries.length === 2, J(again));
  s = await synced({}, { throttleOnce: true });
  check("C14. a 429 is waited out at the rate Amazon states (x-amzn-RateLimit-Limit 0.2 a second: 5 s) and asked again", s.r.ok && s.deps.sleeps.indexOf(5000) !== -1 &&
    s.amazon.api("GET", /^\/listings\/2021-08-01\/items\/[A-Z0-9]+$/).length === 3, J(s.deps.sleeps.filter(function (x) { return x > 2000; })));
  s = await synced({}, { endless: true, orders: 0 });
  check("C15. listings are read 40 pages at most", s.amazon.api("GET", /^\/listings\/2021-08-01\/items\/[A-Z0-9]+$/).length === 40, s.amazon.api("GET", /^\/listings/).length);
  s = await synced({}, { orders: 250 });
  check("C16. at most 100 orders a sync: 100 summaries, 100 order-item reads, one page of orders, each paced", s.r.ok && s.db.t.store_order_summaries.length === 100 &&
    s.amazon.api("GET", /\/orderItems$/).length === 100 && s.amazon.api("GET", /^\/orders\/v0\/orders$/).length === 1 && pacedOrderItems(s.amazon.events).seen === 100 &&
    pacedOrderItems(s.amazon.events).ok, J([s.db.t.store_order_summaries.length, s.amazon.api("GET", /\/orderItems$/).length]));
  const pass = await (async function () {
    const db = makeDb(), amazon = makeAmazon({});
    amazonConn(db, {});
    const sum2 = await SS.runStoreSyncPass(libDeps(db, amazon));
    return { sum: sum2, items: db.t.inventory_items.length };
  })();
  check("C17. Amazon joins the daily sync pass", pass.sum.synced === 1 && pass.items === 3, J(pass.sum));

  /* ── D. tokens ──────────────────────────────────────────────────────────── */
  console.log("\n══ D. tokens ══");
  s = await synced({ access_expires_at: new Date(NOW + 4 * 60 * 1000).toISOString() });
  let crow = s.db.t.member_store_connections[0];
  const tokenUpdates = function (db) { return db.log.filter(function (l) { return l.table === "member_store_connections" && l.op === "update" && l.payload && l.payload.access_ciphertext; }); };
  let ups = tokenUpdates(s.db);
  const rc = s.amazon.tokenCalls("refresh")[0] || {};
  check("D1. within 5 minutes of expiry the token is refreshed first, once, as a form with client_id and client_secret; the new token saved in ONE update; token_version 1; refresh_expires_at stays NULL",
    s.r.ok && s.amazon.tokenCalls("refresh").length === 1 && /^application\/x-www-form-urlencoded/.test(rc.contentType || "") && rc.form.get("client_secret") === CLIENT_SECRET &&
    accessOf(crow) === TOKEN2 && refreshOf(crow) === REFRESH && crow.token_version === 1 && crow.refresh_expires_at === null && ups.length === 1 &&
    s.amazon.api("GET").every(function (c) { return c.token === TOKEN2; }), J(s.r));
  check("D2. ...the update is a compare-and-set: on id, platform amazon and the token_version read", ups.length === 1 &&
    J(ups[0].filters) === J([["eq", "id", crow.id], ["eq", "platform", "amazon"], ["eq", "token_version", 0]]), J(ups[0] && ups[0].filters));
  s = await synced({ access_expires_at: new Date(NOW + 60 * 1000).toISOString() }, { rotate: true });
  crow = s.db.t.member_store_connections[0];
  ups = tokenUpdates(s.db);
  check("D3. when LWA answers a new refresh token, it is sealed and saved in the same one update as the access token", s.r.ok && ups.length === 1 && !!ups[0].payload.credentials_ciphertext &&
    refreshOf(crow) === REFRESH2 && accessOf(crow) === TOKEN2, J(s.r));
  {
    const db = makeDb(), amazon = makeAmazon({});
    const stored = amazonConn(db, { __token: WINNER, token_version: 1, access_expires_at: new Date(NOW + 50 * 60 * 1000).toISOString() });
    const stale = Object.assign({}, stored, { token_version: 0, access_expires_at: new Date(NOW + 60 * 1000).toISOString() });
    const got = await attempt(AAPI.participations(libDeps(db, amazon), AAPI.session(stale)));
    check("D4. losing the race writes nothing: the winner's token stays stored and is the one used", got.ok && accessOf(db.t.member_store_connections[0]) === WINNER &&
      db.t.member_store_connections[0].token_version === 1 && amazon.api("GET").length === 1 && amazon.api("GET").every(function (c) { return c.token === WINNER; }),
      J([got.ok, got.msg, db.t.member_store_connections[0].token_version]));
  }
  {
    const db = makeDb(), amazon = makeAmazon({});
    const c = amazonConn(db, { access_expires_at: new Date(NOW + 60 * 1000).toISOString() });
    const deps = libDeps(db, amazon);
    const both = await Promise.all([AAPI.accessToken(deps, AAPI.session(c), false), AAPI.accessToken(deps, AAPI.session(c), false)]);
    check("D5. two reads at once on one connection share ONE refresh", both[0] === TOKEN2 && both[1] === TOKEN2 && amazon.tokenCalls("refresh").length === 1, amazon.tokenCalls("refresh").length);
  }
  s = await synced({ access_expires_at: new Date(NOW + 60 * 1000).toISOString() }, { refresh: "refuse" });
  crow = s.db.t.member_store_connections[0];
  const again2 = await SS.syncConnection(s.deps, Object.assign({}, crow, { status: "connected" }));
  check("D6. invalid_grant: needs_reconnect and ONE notice; a second failure sends no second notice; nothing read from the SP-API",
    s.r.ok === false && s.r.needs_reconnect === true && s.r.code === "invalid_grant" && crow.status === "needs_reconnect" && s.db.t.notifications.length === 1 &&
    /Reconnect your Amazon store/.test(s.db.t.notifications[0].title) && again2.needs_reconnect === true && s.db.t.notifications.length === 1 && s.amazon.api().length === 0, J(s.r));
  s = await synced({ access_expires_at: new Date(NOW + 60 * 1000).toISOString() }, { refresh: "down" });
  check("D7. LWA down: the sync fails as token_refresh, the connection stays connected, no notice", s.r.ok === false && s.r.code === "token_refresh" && !s.r.needs_reconnect &&
    s.db.t.member_store_connections[0].status === "connected" && s.db.t.notifications.length === 0, J(s.r));
  s = await synced({}, { reject: [TOKEN] });
  check("D8. a 403 on a fresh token: refreshed ONCE and asked once more, then the sync goes on with the new token", s.r.ok === true && s.amazon.tokenCalls("refresh").length === 1 &&
    accessOf(s.db.t.member_store_connections[0]) === TOKEN2, J(s.r));
  s = await synced({}, { reject: [TOKEN, TOKEN2] });
  check("D9. a 403 again after the refresh: needs_reconnect, one refresh only (no loop)", s.r.needs_reconnect === true && s.amazon.tokenCalls("refresh").length === 1, J(s.r));

  /* ── E. changes ─────────────────────────────────────────────────────────── */
  console.log("\n══ E. changes, through approval ══");
  async function world(amazonOpts, over) {
    const w = await synced(over || {}, amazonOpts || {});
    w.deps = libDeps(w.db, w.amazon);
    w.item = function (sku) { return itemOf(w.db, idOf(sku)); };
    w.propose = function (sku, field, to) { return SW.proposeChange(w.deps, USER, { item_id: w.item(sku).id, field: field, to: to }); };
    w.patches = function (preview) { return w.amazon.state.patches.filter(function (p) { return preview === undefined || p.preview === preview; }); };
    w.liveReads = function (sku) { return w.amazon.api("GET", new RegExp("^/listings/2021-08-01/items/" + SELLER + "/" + encodeURIComponent(sku).replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "$")).length; };
    return w;
  }
  const PRICE_BODY = { productType: "HOME", patches: [{ op: "replace", path: "/attributes/purchasable_offer",
    value: [{ marketplace_id: US, currency: "USD", our_price: [{ schedule: [{ value_with_tax: 20 }] }] }] }] };
  const STOCK_BODY = { productType: "HAT", patches: [{ op: "replace", path: "/attributes/fulfillment_availability",
    value: [{ fulfillment_channel_code: "DEFAULT", quantity: 9 }] }] };
  let w = await world({}, { permission: "read" });
  r = await w.propose("MUG-1", "price", "20.00");
  check("E1. a connection without changes allowed is read only: 409, nothing filed, no PATCH (the checkbox alone decides; no scopes)",
    r.status === 409 && r.body.code === "read_only" && w.db.t.agent_proposals.length === 0 && w.patches().length === 0 &&
    SS.permissionOf({ platform: "amazon", permission: "read_write", granted_scopes: null }) === "read_write" && SS.permissionOf({ platform: "amazon", permission: "read" }) === "read", J(r));
  w = await world();
  const readsBefore = w.liveReads("MUG-1");
  r = await w.propose("MUG-1", "price", "20.00");
  const prop = r.body.proposal || {};
  check("E2. a proposal: from the live value (one getListingsItem), filed pending for the store agent naming amazon, USD, the marketplace (US) and that Amazon does not ship it; no PATCH",
    r.status === 201 && prop.status === "pending" && prop.agent_type === "store" && prop.action_type === "update_store_item" && prop.payload.platform === "amazon" &&
    prop.payload.currency === "USD" && prop.payload.marketplace_id === US && prop.payload.marketplace === "US" && prop.payload.fba === false && prop.payload.fba_note === null &&
    prop.payload.from === "18.00" && prop.payload.to === "20.00" && w.liveReads("MUG-1") === readsBefore + 1 && w.patches().length === 0, J(r.body));
  let done = await attempt(SW.executeChange(w.deps, prop));
  const pv = w.patches(true)[0] || {}, pr = w.patches(false)[0] || {};
  check("E3. executed: a VALIDATION_PREVIEW PATCH first, then ONE real PATCH, both to the item's path in the marketplace, as JSON with the access token",
    done.ok && w.patches().length === 2 && w.patches()[0].preview === true && w.patches()[1].preview === false && /[?&]mode=VALIDATION_PREVIEW(&|$)/.test(pv.query) &&
    !/mode=/.test(pr.query) && /[?&]marketplaceIds=ATVPDKIKX0DER(&|$)/.test(pr.query) && pr.sku === "MUG-1" && /^application\/json/.test(pr.contentType || "") && pr.token === TOKEN &&
    pr.host === "sellingpartnerapi-na.amazon.com", J([done, w.patches().map(function (p) { return [p.preview, p.query]; })]));
  check("E4. ...the price patch is exactly the brief's: replace /attributes/purchasable_offer with marketplace_id, currency and our_price[0].schedule[0].value_with_tax, the product type from the summary",
    J(pr.body) === J(PRICE_BODY) && J(pv.body) === J(PRICE_BODY), J(pr.body));
  check("E5. ...Amazon showed it on the first read 10 s later: logged \"confirmed\", the item updated, no note", done.ok && done.v.confirmation === "confirmed" && done.v.note === undefined &&
    w.db.t.store_change_log.length === 1 && w.db.t.store_change_log[0].confirmation === "confirmed" && w.db.t.store_change_log[0].currency === "USD" &&
    w.db.t.store_change_log[0].old_value === 18 && w.db.t.store_change_log[0].new_value === 20 && w.item("MUG-1").unit_price === 20 &&
    w.deps.sleeps.filter(function (x) { return x === 10000; }).length === 1, J([done.v, w.db.t.store_change_log]));
  done = await attempt(SW.executeChange(w.deps, prop));
  check("E6. a replay writes nothing: already applied, no third PATCH", done.ok && done.v.already_applied === true && w.patches().length === 2);
  w = await world();
  r = await w.propose(HAT, "stock", 9);
  done = await attempt(SW.executeChange(w.deps, r.body.proposal));
  const sp = w.patches(false)[0] || {};
  check("E7. the quantity patch is exactly the brief's: replace /attributes/fulfillment_availability, DEFAULT, the integer; the SKU URL-encoded in the PATCH path",
    r.status === 201 && done.ok && J(sp.body) === J(STOCK_BODY) && sp.sku === HAT && w.item(HAT).quantity_on_hand === 9 &&
    w.amazon.calls.some(function (c) { return c.method === "PATCH" && c.path === "/listings/2021-08-01/items/" + SELLER + "/HAT%20RED%2FL"; }), J([r.body, done, sp.body]));
  // compare-and-set
  w = await world();
  r = await w.propose("MUG-1", "price", "21.00");
  w.amazon.state.listings["MUG-1"].price = 19;
  done = await attempt(SW.executeChange(w.deps, r.body.proposal));
  check("E8. the live price moved since the proposal: \"Your store changed since you proposed this. Propose it again.\", no PATCH, nothing logged",
    !done.ok && done.msg === "Your store changed since you proposed this. Propose it again." && w.patches().length === 0 && w.db.t.store_change_log.length === 0, J(done));
  // the preview's ERROR
  const LONG_ISSUE = "The price you entered\n is below the minimum allowed for this product. " + "Review the price rules for this category. ".repeat(12);
  w = await world({ previewError: LONG_ISSUE });
  r = await w.propose("MUG-1", "price", "0.50");
  done = await attempt(SW.executeChange(w.deps, r.body.proposal));
  const shownIssue = LONG_ISSUE.replace(/[\u0000-\u001f\u007f]+/g, " ").trim().slice(0, 300);
  check("E9. a preview with an ERROR issue: fails with \"Amazon refused the change, so nothing was changed: \" and the first ERROR's message (300 characters at most, a warning ignored); only the preview sent, nothing logged",
    !done.ok && done.msg === "Amazon refused the change, so nothing was changed: " + shownIssue && shownIssue.length === 300 && w.patches().length === 1 && w.patches()[0].preview === true &&
    w.db.t.store_change_log.length === 0 && w.item("MUG-1").unit_price === 18, J([done.msg && done.msg.length, w.patches().length]));
  w = await world({ previewWarning: true });
  r = await w.propose("MUG-1", "price", "17.00");
  done = await attempt(SW.executeChange(w.deps, r.body.proposal));
  check("E10. a preview with only a WARNING goes ahead", done.ok && w.patches().length === 2 && done.v.confirmation === "confirmed", J(done));
  // never retried
  w = await world({ patchStatus: 500 });
  r = await w.propose("MUG-1", "price", "19.00");
  done = await attempt(SW.executeChange(w.deps, r.body.proposal));
  check("E11. a 5xx after the real PATCH was sent: that ONE PATCH, never retried; \"BizForce couldn't confirm the change...\"; nothing logged",
    !done.ok && w.patches(false).length === 1 && w.patches(true).length === 1 &&
    done.msg === "BizForce couldn't confirm the change. Check the item in your store; BizForce will not try again." && w.db.t.store_change_log.length === 0, J(done));
  w = await world({ realInvalid: "The SKU's offer is not available in this marketplace." });
  r = await w.propose("MUG-1", "price", "19.00");
  done = await attempt(SW.executeChange(w.deps, r.body.proposal));
  check("E12. the real PATCH answered INVALID: fails with Amazon's message, nothing logged, no second PATCH", !done.ok &&
    done.msg === "Amazon refused the change, so nothing was changed: The SKU's offer is not available in this marketplace." && w.patches(false).length === 1 &&
    w.db.t.store_change_log.length === 0, J(done));
  // the bounded confirmation
  w = await world({ neverApply: true });
  r = await w.propose("MUG-1", "price", "22.00");
  const liveBefore = w.liveReads("MUG-1");
  done = await attempt(SW.executeChange(w.deps, r.body.proposal));
  check("E13. ACCEPTED but not shown within 60 s: six reads, 10 s apart, then logged \"submitted\" with \"Amazon accepted the change and applies it in its own time. The next sync confirms it.\"",
    done.ok && done.v.confirmation === "submitted" && done.v.note === "Amazon accepted the change and applies it in its own time. The next sync confirms it." &&
    w.liveReads("MUG-1") - liveBefore === 7 && w.deps.sleeps.filter(function (x) { return x === 10000; }).length === 6 && w.patches(false).length === 1 &&
    w.db.t.store_change_log.length === 1 && w.db.t.store_change_log[0].confirmation === "submitted", J([done, w.liveReads("MUG-1") - liveBefore]));
  const logId = w.db.t.store_change_log[0] && w.db.t.store_change_log[0].id;
  const listed = await SW.listChanges(w.deps, USER);
  check("E14. the change list says submitted", listed.changes.length === 1 && listed.changes[0].confirmation === "submitted", J(listed));
  let ws = await SS.syncConnection(w.deps, w.db.t.member_store_connections[0]);
  check("E15. a sync while Amazon still shows the old price: the row stays \"submitted\"", ws.ok && ws.changes_confirmed === 0 && w.db.t.store_change_log[0].confirmation === "submitted", J(ws));
  w.amazon.applyPending();
  ws = await SS.syncConnection(w.deps, w.db.t.member_store_connections[0]);
  const ws2 = await SS.syncConnection(w.deps, w.db.t.member_store_connections[0]);
  check("E16. the next sync that reads the new price turns \"submitted\" into \"confirmed\", once", ws.ok && ws.changes_confirmed === 1 && w.db.t.store_change_log[0].confirmation === "confirmed" &&
    ws2.changes_confirmed === 0, J([ws, ws2.changes_confirmed]));
  const undo = await SW.undoChange(w.deps, USER, logId);
  check("E17. undo of that change files a new proposal from the live value back to the old one", undo.status === 201 && undo.body.proposal.payload.from === "22.00" &&
    undo.body.proposal.payload.to === "18.00" && undo.body.proposal.payload.platform === "amazon", J(undo));
  w = await world({ applyAfterReads: 3 });
  r = await w.propose("MUG-1", "price", "23.00");
  done = await attempt(SW.executeChange(w.deps, r.body.proposal));
  check("E18. shown on the third read: \"confirmed\" after three reads, no more", done.ok && done.v.confirmation === "confirmed" && w.deps.sleeps.filter(function (x) { return x === 10000; }).length === 3 &&
    w.db.t.store_change_log[0].confirmation === "confirmed", J(done));
  const subUndo = await (async function () {
    const x = await world({ neverApply: true });
    const p1 = await x.propose(HAT, "stock", 8);
    await attempt(SW.executeChange(x.deps, p1.body.proposal));
    x.amazon.applyPending();
    const u = await SW.undoChange(x.deps, USER, x.db.t.store_change_log[0].id);
    return { u: u, still: x.db.t.store_change_log[0].confirmation };
  })();
  check("E19. undo of a change still logged \"submitted\" (Amazon has since applied it) files a new proposal from 8 back to 3",
    subUndo.still === "submitted" && subUndo.u.status === 201 && subUndo.u.body.proposal.payload.from === 8 && subUndo.u.body.proposal.payload.to === 3, J(subUndo));
  // FBA
  w = await world();
  r = await w.propose("FBA-SCARF", "stock", 3);
  const rfp = await w.propose("FBA-SCARF", "price", "14.00");
  check("E20. an FBA item: a stock change refused with \"Amazon manages the stock of items it ships for you (FBA). Change it in Seller Central.\"; a price change filed with the FBA note",
    r.status === 409 && r.body.code === "fba_stock" && r.body.error === "Amazon manages the stock of items it ships for you (FBA). Change it in Seller Central." &&
    rfp.status === 201 && rfp.body.proposal.payload.fba === true && rfp.body.proposal.payload.fba_note === "Amazon ships this item for you (FBA); only its price changes." &&
    /Amazon ships this item for you \(FBA\); only its price changes\./.test(rfp.body.note) && w.patches().length === 0, J([r, rfp.body.note]));
  const fbaProp = { id: uuid(), user_id: USER, payload: { connection_id: w.conn.id, item_id: w.item("FBA-SCARF").id, external_id: idOf("FBA-SCARF"), external_parent_id: null,
    field: "stock", from: 7, to: 3, platform: "amazon", marketplace_id: US } };
  done = await attempt(SW.executeChange(w.deps, fbaProp));
  check("E21. the executor refuses an FBA stock change too, from the live read, before any PATCH", !done.ok && done.msg === "Amazon manages the stock of items it ships for you (FBA). Change it in Seller Central." &&
    w.patches().length === 0, J(done));
  done = await attempt(SW.executeChange(w.deps, rfp.body.proposal));
  check("E22. an FBA item's price change goes through", done.ok && J((w.patches(false)[0] || {}).body) === J({ productType: "APPAREL", patches: [{ op: "replace", path: "/attributes/purchasable_offer",
    value: [{ marketplace_id: US, currency: "USD", our_price: [{ schedule: [{ value_with_tax: 14 }] }] }] }] }), J(done));
  // the daily cap
  w = await world();
  r = await w.propose("MUG-1", "price", "24.00");
  for (let i = 0; i < SW.DAILY_CAP; i++) w.db.t.store_change_log.push({ id: uuid(), user_id: USER, connection_id: w.conn.id, field: "price", old_value: 1, new_value: 2, executed_at: new Date(NOW - 3600000).toISOString(), confirmation: "confirmed" });
  done = await attempt(SW.executeChange(w.deps, r.body.proposal));
  check("E23. the daily cap holds for Amazon: refused with the cap's message, no PATCH", !done.ok && done.msg === SW.MESSAGES.cap && w.patches().length === 0, J(done));
  // marketplace
  w = await world();
  const other = w.item("MUG-1");
  other.external_id = "sku:" + UK + ":MUG-1";
  r = await SW.proposeChange(w.deps, USER, { item_id: other.id, field: "price", to: "30.00" });
  check("E24. an item of another marketplace than the connection's: 409, nothing read or filed", r.status === 409 && r.body.code === "unaddressable" && w.db.t.agent_proposals.length === 0, J(r));
  check("E25. an Amazon item is addressable only as sku:<marketplaceId>:<sku> with no parent", SW.addressable("amazon", "price", { external_id: idOf("MUG-1"), external_parent_id: null }) === true &&
    SW.addressable("amazon", "price", { external_id: idOf("MUG-1"), external_parent_id: "1" }) === false && SW.addressable("amazon", "stock", { external_id: "listing:1", external_parent_id: null }) === false &&
    AAPI.skuOf(idOf(HAT)).sku === HAT && AAPI.identityOf(US, "a\nb") === null && AAPI.identityOf("bad", "x") === null);
  check("E26. four platforms, each named: an unknown platform is refused by summaryOf, syncConnection and permissionOf, never read as another",
    (function () { try { SS.summaryOf("ebay", { id: 1 }); return false; } catch (e) { return e.code === "unknown_platform"; } })() &&
    (await SS.syncConnection(libDeps(makeDb(), makeAmazon({})), { id: uuid(), user_id: USER, platform: "ebay", store_url: "x" })).code === "unknown_platform" &&
    SS.permissionOf({ platform: "ebay", permission: "read_write" }) === "read" && J(SS.PLATFORMS) === J(["shopify", "woocommerce", "etsy", "amazon"]));
  check("E27. lib/amazonApi.js: the word PATCH appears only in patchOnce, which only writeListing calls; every reader goes through readGet (method GET); two jsonRequest calls in all",
    (stripComments(FILES.api).match(/"PATCH"/g) || []).length === 1 && fnSource(FILES.api, "patchOnce").indexOf("method: \"PATCH\"") !== -1 &&
    /method: "GET"/.test(fnSource(FILES.api, "readGet")) && (stripComments(FILES.api).match(/deps\.jsonRequest\(/g) || []).length === 2 &&
    (stripComments(FILES.api).match(/patchOnce\(/g) || []).length === 3 && (stripComments(FILES.write).match(/AAPI\.writeListing\(/g) || []).length === 1);
  check("E28. lib/storeSync.js stays GET-only: no PUT, POST, PATCH or DELETE in its code", !/\b(PUT|POST|PATCH|DELETE)\b/.test(stripComments(FILES.sync).replace(/\/\/.*$/gm, "")));

  /* ── F. the pages ───────────────────────────────────────────────────────── */
  console.log("\n══ F. the pages ══");
  const P = FILES.page;
  const amazonBlock = sliceOf(P, "<div id=\"storeAmazonSection\" hidden>", "id=\"storeAmazonUnset\"");
  const optionIds = (amazonBlock.match(/<option value="[A-Z0-9]*">/g) || []).map(function (x) { return /value="([A-Z0-9]*)"/.exec(x)[1]; });
  const groups = (amazonBlock.match(/<optgroup label="[^"]+">/g) || []).join("|");
  check("F1. the Store page: an Amazon choice, the two lines word for word, the box, \"Connect Amazon\" and the unset line",
    P.indexOf("<button type=\"button\" class=\"action-btn action-btn--ghost\" id=\"storePickAmazon\" aria-pressed=\"false\">Amazon</button>") !== -1 &&
    amazonBlock.indexOf("<p class=\"store-quiet\">You approve BizForce on Amazon Seller Central's own page. BizForce never sees your Amazon password.</p>") !== -1 &&
    amazonBlock.indexOf("<p class=\"store-quiet\" id=\"storeAmazonDraft\" hidden>Until Amazon approves BizForce, only the account that registered BizForce can connect.</p>") !== -1 &&
    amazonBlock.indexOf("<label class=\"store-allow\"><input type=\"checkbox\" id=\"storeAmazonAllow\" /> Let BizForce make changes I approve (prices and stock)</label>") !== -1 &&
    amazonBlock.indexOf("<button type=\"button\" class=\"action-btn\" id=\"storeAmazonBtn\">Connect Amazon</button>") !== -1 &&
    P.indexOf("<p class=\"store-msg\" id=\"storeAmazonUnset\" hidden>Amazon connection isn't set up yet.</p>") !== -1 &&
    P.indexOf("Connect your own Shopify, WooCommerce, Etsy or Amazon store and Stock") !== -1, amazonBlock.slice(0, 300));
  check("F2. the marketplace picker: no default (an empty first choice), grouped North America, Europe, Far East, the brief's 20 ids in the table's order",
    optionIds[0] === "" && /<option value="">Choose a marketplace<\/option>/.test(amazonBlock) && !/selected/.test(amazonBlock) &&
    J(optionIds.slice(1)) === J(BRIEF_MARKETPLACES.map(function (x) { return x[1]; })) && groups === "<optgroup label=\"North America\">|<optgroup label=\"Europe\">|<optgroup label=\"Far East\">",
    J([optionIds.length, groups]));
  let dom = runPage("", listAnswers({ "GET /api/store/connections": { status: 200, body: { connections: [], note: "", shopify_available: true, etsy_available: true, amazon_available: false, amazon_draft: true } } }));
  await flush();
  check("F3. unconfigured: Connect Amazon disabled and \"Amazon connection isn't set up yet.\" shown", dom.els.storeAmazonBtn.disabled === true && dom.els.storeAmazonUnset.hidden === false &&
    dom.els.storeAmazonUnset.textContent === "Amazon connection isn't set up yet.");
  dom = runPage("", listAnswers());
  await flush();
  const draftShown = dom.els.storeAmazonDraft.hidden === false;
  const domPub = runPage("", listAnswers({ "GET /api/store/connections": { status: 200, body: { connections: [], note: "", amazon_available: true, amazon_draft: false } } }));
  await flush();
  check("F4. the draft line shows while BizForce's Amazon app is a draft, and hides once it is published", draftShown && domPub.els.storeAmazonDraft.hidden === true &&
    dom.els.storeAmazonBtn.disabled === false);
  dom.els.storePickAmazon.click();
  dom.els.storeAmazonBtn.click();
  await flush();
  check("F5. Connect Amazon with no marketplace chosen: \"Choose the Amazon marketplace you sell in.\", nothing sent, no marker", dom.els.storeAmazonSection.hidden === false &&
    dom.els.storeConnectMsg.textContent === "Choose the Amazon marketplace you sell in." && !dom.fetches.some(function (f) { return f.method === "POST"; }) && !("bf_store_return" in dom.store));
  dom.els.storeAmazonMarket.value = DE;
  dom.els.storeAmazonAllow.checked = true;
  dom.els.storeAmazonBtn.click();
  await flush();
  const startCall = dom.fetches.filter(function (f) { return f.path === "/api/store/amazon/start"; })[0];
  check("F6. Connect Amazon: POST start with the marketplace and allow_changes, the \"amazon\" marker set BEFORE leaving, then Seller Central's page",
    !!startCall && J(startCall.body) === J({ marketplace_id: DE, allow_changes: true }) && dom.store.bf_store_return === "amazon" &&
    dom.assigned[0] === "https://sellercentral-europe.amazon.com/apps/authorize/consent?application_id=x&state=y" &&
    dom.events.indexOf("session:set bf_store_return=amazon") !== -1 && dom.events.indexOf("session:set bf_store_return=amazon") < dom.events.indexOf("assign"), J([startCall, dom.assigned]));
  dom = runPage(SELLER_Q, listAnswers(), "amazon");
  await flush();
  const fin = dom.fetches.filter(function (f) { return f.path === "/api/store/amazon/finish"; })[0];
  check("F7. back from Amazon with the marker: the address bar cleared first, then spapi_oauth_code, state and selling_partner_id POSTed, the marker removed, the marketplace named",
    !!fin && J(fin.body) === J({ spapi_oauth_code: CODE, state: "S".repeat(43), selling_partner_id: SELLER }) && dom.events.indexOf("replaceState:/store-agent.html") !== -1 &&
    dom.events.indexOf("replaceState:/store-agent.html") < dom.events.indexOf("fetch:POST /api/store/amazon/finish") && !("bf_store_return" in dom.store) &&
    /Connected to your Amazon seller account in marketplace US/.test(dom.els.storeConnectMsg.textContent), J([fin, dom.events]));
  dom = runPage(SELLER_Q, listAnswers());
  await flush();
  const noMarker = dom.els.storeConnectMsg.textContent === "Start the connection again." && !dom.fetches.some(function (f) { return f.method === "POST"; }) &&
    dom.events.indexOf("replaceState:/store-agent.html") !== -1;
  dom = runPage(SELLER_Q, listAnswers(), "etsy");
  await flush();
  check("F8. Amazon's parameters with no marker, or with Etsy's: \"Start the connection again.\", nothing POSTed, the address bar cleared", noMarker &&
    dom.els.storeConnectMsg.textContent === "Start the connection again." && !dom.fetches.some(function (f) { return f.method === "POST"; }));
  dom = runPage("?spapi_oauth_code=" + CODE + "&state=" + "S".repeat(43), listAnswers(), "amazon");
  await flush();
  check("F9. a return missing selling_partner_id is not Amazon's: nothing POSTed", !dom.fetches.some(function (f) { return f.method === "POST"; }) &&
    dom.els.storeConnectMsg.textContent === "Start the connection again.");
  dom = runPage("?error=access_denied&state=" + "S".repeat(43), listAnswers(), "amazon");
  await flush();
  check("F10. Amazon declined (error, with the marker): \"Amazon did not connect your seller account, so nothing was saved.\", nothing POSTed",
    dom.els.storeConnectMsg.textContent === "Amazon did not connect your seller account, so nothing was saved." && !dom.fetches.some(function (f) { return f.method === "POST"; }));
  dom = runPage("?code=" + CODE + "&hmac=" + "f".repeat(64) + "&shop=demo-shop.myshopify.com&state=" + "S".repeat(43) + "&timestamp=1794052800", listAnswers(), "amazon");
  await flush();
  check("F11. a Shopify return is still known by its shop and hmac, whatever the marker, and the marker is spent",
    dom.fetches.some(function (f) { return f.path === "/api/store/shopify/finish" && f.method === "POST"; }) && !dom.fetches.some(function (f) { return f.path === "/api/store/amazon/finish"; }) &&
    !("bf_store_return" in dom.store));
  const hostileView = Object.assign({}, AMAZON_VIEW, { marketplace: HOSTILE, store: "https://www.amazon.com/" + HOSTILE });
  dom = runPage("", listAnswers({ "GET /api/store/connections": { status: 200, body: { connections: [hostileView], note: "", amazon_available: true, amazon_draft: false } } }));
  await flush();
  const listedText = allText(dom.els.storeConnections);
  check("F12. the connection row: \"Amazon marketplace: <code>\", Read only, the currency; set with textContent only (a hostile value stays text)",
    listedText.indexOf("Amazon marketplace: " + HOSTILE) !== -1 && listedText.indexOf("Read only") !== -1 && listedText.indexOf("Currency: USD") !== -1 &&
    listedText.indexOf("(Amazon, since") !== -1 && dom.innerHTML.length === 0, listedText.slice(0, 300));
  check("F13. the sessionStorage key is named in bf-session.js's LEFT ON PURPOSE comment with amazon", /bf_store_return\n\s+\(sessionStorage: which store's page, etsy, amazon or shopify/.test(FILES.session) &&
    /var RETURN_KEY = "bf_store_return";/.test(FILES.ui));
  const cardFns = ["escapeHtml", "formatTime", "storeChangeText", "storeChangePayloadFields", "storeChangeResultHtml"].map(function (n) { return fnSource(FILES.proposals, n); });
  let card = "", resSub = "", resDone = "";
  try { const cx = { String: String, Date: Date, isNaN: isNaN, Number: Number }; vm.createContext(cx); vm.runInContext(cardFns.join("\n"), cx);
    card = cx.storeChangePayloadFields({ platform: "amazon", item_name: HOSTILE, field: "price", from: "12.00", to: "14.00", currency: "USD", marketplace_id: US, marketplace: "<b>US</b>",
      fba: true, fba_note: "<i>x</i> Amazon ships this item for you (FBA); only its price changes." });
    resSub = cx.storeChangeResultHtml({ confirmation: "submitted", executed_at: "2026-11-08T12:00:00Z" });
    resDone = cx.storeChangeResultHtml({ confirmation: "confirmed", executed_at: "2026-11-08T12:00:00Z" });
  } catch (e) { card = "error: " + e.message; }
  check("F14. the Approvals card names Amazon, the marketplace, the currency and the FBA note, every value escaped",
    card.indexOf("Change &lt;img src=x onerror=alert(1)&gt; price in your Amazon store from 12.00 USD to 14.00 USD") !== -1 && card.indexOf("your Amazon store, connected with changes allowed") !== -1 &&
    card.indexOf("&lt;b&gt;US&lt;/b&gt;") !== -1 && card.indexOf("&lt;i&gt;x&lt;/i&gt; Amazon ships this item for you (FBA); only its price changes.") !== -1 &&
    card.indexOf("<img") === -1 && card.indexOf("<b>") === -1 && card.indexOf("<i>") === -1, card.slice(0, 400));
  check("F15. the approved result says \"Submitted to Amazon, not yet confirmed\" for a submitted change, \"Changed in your store\" otherwise; the change log line word for word",
    resSub.indexOf(">Submitted to Amazon, not yet confirmed<") !== -1 && resDone.indexOf(">Changed in your store<") !== -1 && resDone.indexOf("Submitted") === -1 &&
    FILES.changesUi.indexOf("if (c.confirmation === \"submitted\") row.appendChild(el(\"p\", \"store-warn store-change-submitted\", \"Submitted to Amazon, not yet confirmed\"));") !== -1, resSub);
  check("F16. the propose control: an Amazon connection with changes allowed is writable, with the FBA line",
    /c\.platform === "etsy" \|\| c\.platform === "amazon"\) && c\.permission === "read_write"/.test(FILES.changesUi) &&
    FILES.changesUi.indexOf("\"Stock changes apply to items you ship yourself; Amazon keeps the stock of items it ships for you (FBA).\"") !== -1);
  const guideStore = (/"store-agent\.html": \[([\s\S]*?)\]/.exec(FILES.guide) || [])[1] || "";
  const guideFront = (/"etsy-agent\.html": \[([\s\S]*?)\]/.exec(FILES.guide) || [])[1] || "";
  const TIP = "\"Connect your store\" reads Shopify, WooCommerce, Etsy or Amazon; audits are written from your Business Profile and what you tell it, not your store's own data.";
  check("F17. the guide: the Store tip names Amazon, within 160 characters; the Storefront tips and the Storefront page never say Amazon",
    guideStore.indexOf(J(TIP)) !== -1 && TIP.length <= 160 && guideFront.length > 100 && !/amazon/i.test(guideFront) && !/amazon/i.test(FILES.storefront) &&
    /etsy: "Storefront"/.test(FILES.triggers), J([TIP.length, guideFront.slice(0, 120)]));
  check("F18. the Store signature counts Amazon stock, and the live panel names it", /var s = \{ manual: 0, shopify: 0, woocommerce: 0, etsy: 0, amazon: 0 \};/.test(FILES.signatures) &&
    /if \(src\.amazon\) srcParts\.push\("Amazon " \+ src\.amazon\);/.test(FILES.profile));

  /* ── G. the words and the registries ───────────────────────────────────── */
  console.log("\n══ G. the words and the registries ══");
  const PRIVACY = "If you connect a Shopify, WooCommerce, Etsy or Amazon store, BizForce stores the store's address and the access it is given, encrypted (for WooCommerce, " +
    "the key you made for it; for Shopify, Etsy or Amazon, the access you approve when you connect), and reads from the store only your products (name, SKU, price, " +
    "cost where the store has one), your stock levels, your store's currency and location names, and summaries of your orders (each order's number, " +
    "date, total, currency, and its items as SKU and quantity), never any customer's name, email, address or phone number; BizForce changes a " +
    "product's price or stock level in your store only when you approve that change, and only if you allowed changes when you connected the store, " +
    "and it keeps a record of each change (the item, the old and new value, and when). What it reads is used only for your own agents, the store's " +
    "key or access is never shown back to you or exported, and it, the products, the stock, the order summaries and the record of changes are " +
    "deleted when you disconnect the store, uninstall BizForce from Shopify, remove it from your Etsy account or Amazon Seller Central, or delete your account.";
  const esc = function (t) { return String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"); };
  check("G1. the privacy sentence word for word (the brief's three replacements), and privacy.html carries it once, as built", LP.STORE_PRIVACY_SENTENCE === PRIVACY &&
    FILES.privacy.split(esc(PRIVACY)).length === 2, LP.STORE_PRIVACY_SENTENCE);
  check("G2. Amazon is a named third party, word for word, on the privacy page too",
    FILES.yourData.indexOf("{ name: \"Amazon\", for: \"connecting your Amazon seller account, reading it and making the changes you approve, when you connect one\" }") !== -1 &&
    FILES.privacy.indexOf(esc("Amazon (connecting your Amazon seller account, reading it and making the changes you approve, when you connect one)")) !== -1);
  check("G3. yourData: the sign-in states name all eight sign-ins; the connections name Amazon, the marketplace and region, and export them; the change log names Amazon and exports confirmation; the backup note",
    FILES.yourData.indexOf("Temporary sign-in states for Sign in with Microsoft, Connect Shopify, Connect YouTube, Connect TikTok, Connect Instagram, Connect Facebook, Connect Etsy and Connect Amazon,") !== -1 &&
    FILES.yourData.indexOf("connected to each Shopify, WooCommerce, Etsy or Amazon store") !== -1 && FILES.yourData.indexOf("the Amazon marketplace and region you connected") !== -1 &&
    FILES.yourData.indexOf("select: \"platform, store_url, status, permission, currency, location_name, marketplace_id, region, created_at, last_sync_at\"") !== -1 &&
    FILES.yourData.indexOf("Changes BizForce made to your store with your approval, on Shopify, WooCommerce, Etsy or Amazon:") !== -1 &&
    FILES.yourData.indexOf("select: \"item_name, field, old_value, new_value, currency, location_name, executed_at, confirmation\"") !== -1 &&
    FILES.backup.indexOf("member_store_connections: \"members' WooCommerce store keys and Shopify, Etsy and Amazon access (encrypted); members connect again\",") !== -1);
  const LEGAL = realRequire("./lib/legal");
  check("G4. TERMS_VERSION and TERMS_UPDATED are Nov 8 2026", LEGAL.TERMS_VERSION === "2026-11-08" && LEGAL.TERMS_UPDATED === "Last updated November 8, 2026", LEGAL.TERMS_VERSION);
  const amz = (FILES.readme.split("## Amazon app setup")[1] || "").split("\n## ")[0];
  check("G5. README: the four env var rows, and the Amazon app setup (registration, the draft app and its four roles, the LWA client id and secret and the app id on Railway, the redirect exactly, draft mode, the Data Protection Policy, the fees)",
    /\n\| `AMAZON_SPAPI_APP_ID` \| none \| /.test(FILES.readme) && /\n\| `AMAZON_LWA_CLIENT_ID` \| none \| /.test(FILES.readme) &&
    /\n\| `AMAZON_LWA_CLIENT_SECRET` \| none \| [^\n]*A secret; set it on Railway/.test(FILES.readme) && /\n\| `AMAZON_SPAPI_DRAFT` \| unset \(draft\) \| /.test(FILES.readme) &&
    /register as a developer/.test(amz) && amz.indexOf("**Product Listing**, **Pricing**, **Inventory** and **Order Tracking**") !== -1 && /no restricted role/.test(amz) &&
    amz.indexOf("`AMAZON_LWA_CLIENT_ID`") !== -1 && amz.indexOf("`AMAZON_LWA_CLIENT_SECRET`") !== -1 && amz.indexOf("`AMAZON_SPAPI_APP_ID`") !== -1 && /Railway only/.test(amz) &&
    amz.indexOf("exactly: `https://bizforceai.net/store-agent.html`") !== -1 && amz.indexOf("`version=beta`") !== -1 && amz.indexOf("`AMAZON_SPAPI_DRAFT=false`") !== -1 &&
    /Data Protection Policy/.test(amz) && amz.indexOf("Amazon cancelled its planned SP-API developer fees on May 12, 2026") !== -1, amz.slice(0, 200));
  check("G6. the route lists: both routes in checkDormantRoutesDeleted's ADDED (487 -> 489) and checkUnsubscribedSurface's gated list (124 -> 126)",
    FILES.dormant.indexOf("[\"post\", \"/api/store/amazon/start\"],") !== -1 && FILES.dormant.indexOf("[\"post\", \"/api/store/amazon/finish\"]") !== -1 && /\(488 -> 489\)/.test(FILES.dormant) &&
    FILES.surface.indexOf("\"post /api/store/amazon/start\", \"post /api/store/amazon/finish\"") !== -1 && /gated 124 -> 126/.test(FILES.surface));
  const SQL_LINES = [
    "  ADD CONSTRAINT member_store_connections_platform_check CHECK (platform IN ('shopify', 'woocommerce', 'etsy', 'amazon')),",
    "    OR (platform = 'amazon' AND external_account_id ~ '^[A-Z0-9]{8,20}$')",
    "  ADD CONSTRAINT member_store_connections_marketplace_check CHECK (marketplace_id IS NULL OR marketplace_id ~ '^[A-Z0-9]{8,20}$'),",
    "  ADD CONSTRAINT member_store_connections_region_check CHECK (region IS NULL OR region IN ('na', 'eu', 'fe')),",
    "      AND location_id IS NULL AND location_name IS NULL AND external_account_id IS NOT NULL AND marketplace_id IS NOT NULL AND region IS NOT NULL)",
    "CREATE UNIQUE INDEX IF NOT EXISTS member_store_connections_amazon_seller_key\n  ON public.member_store_connections (external_account_id, marketplace_id) WHERE platform = 'amazon';",
    "    OR (source IN ('shopify', 'woocommerce', 'etsy', 'amazon') AND store_connection_id IS NOT NULL AND external_id IS NOT NULL AND char_length(external_id) <= 100)",
    "  ADD CONSTRAINT store_order_summaries_platform_check CHECK (platform IN ('shopify', 'woocommerce', 'etsy', 'amazon'));",
    "  ADD COLUMN IF NOT EXISTS confirmation text NOT NULL DEFAULT 'confirmed';",
    "  ADD CONSTRAINT store_change_log_confirmation_check CHECK (confirmation IN ('confirmed', 'submitted'));",
    "'facebook_login', 'store_etsy', 'store_amazon')),",
    "    purpose IN ('store_shopify', 'tiktok_login', 'instagram_login', 'facebook_login', 'store_amazon')",
    "    ((purpose IN ('store_shopify', 'store_etsy', 'store_amazon')) = (flow_context IS NOT NULL))"
  ];
  check("G7. migration 182 as run: the header, amazon in the platform, source and summary CHECKs, the seller id, marketplace and region CHECKs, the token shape, the index, confirmation, store_amazon",
    FILES.migration.indexOf("-- Applied by the owner by hand in the Supabase SQL editor on Nov 8, 2026. This file is the text as run.\n") === 0 &&
    SQL_LINES.every(function (l) { return FILES.migration.indexOf(l) !== -1; }), SQL_LINES.filter(function (l) { return FILES.migration.indexOf(l) === -1; })[0]);
  const migFiles = fs.readdirSync(path.join(REPO, "supabase", "migrations")).filter(function (x) { return /^\d{3}_.*\.sql$/.test(x); });
  const highest = migFiles.map(function (x) { return Number(x.slice(0, 3)); }).reduce(function (acc, x) { return Math.max(acc, x); }, 0);
  // NAMED (Nov 11 2026, orbit stage 2), migration 183): BEFORE 182_amazon_store.sql was the highest. AFTER it is the only 182 and only
  // 183_weekly_goal_and_order_status.sql is above it, by name; "the highest" is checkOrbitStage2 R1's.
  check("R1. 182_amazon_store.sql is the only 182, and only 183_weekly_goal_and_order_status.sql is above it (checkOrbitStage2 R1)", highest === 183 && migFiles.filter(function (x) { return /^182_/.test(x); }).join() === "182_amazon_store.sql" &&
    migFiles.filter(function (x) { return Number(x.slice(0, 3)) > 182; }).join() === "183_weekly_goal_and_order_status.sql", highest);
  check("G8. the four approved env vars and no other: lib/amazonAuth.js reads only AMAZON_SPAPI_APP_ID, AMAZON_LWA_CLIENT_ID, AMAZON_LWA_CLIENT_SECRET and AMAZON_SPAPI_DRAFT; lib/amazonApi.js reads none",
    J((stripComments(FILES.auth).match(/"AMAZON_[A-Z_]+"/g) || []).filter(function (x, i, a) { return a.indexOf(x) === i; }).sort()) ===
      J(["\"AMAZON_LWA_CLIENT_ID\"", "\"AMAZON_LWA_CLIENT_SECRET\"", "\"AMAZON_SPAPI_APP_ID\"", "\"AMAZON_SPAPI_DRAFT\""]) &&
    !/process\.env\.[A-Z]|env\.[A-Z]/.test(stripComments(FILES.auth)) && !/process\.env|env\.[A-Z]|"AMAZON_/.test(stripComments(FILES.api)));
  const requiresOf = function (src) { return (stripComments(src).match(/require\("([^"]+)"\)/g) || []).map(function (x) { return /"([^"]+)"/.exec(x)[1]; }).sort(); };
  check("G9. no AWS SDK and no new package: the Amazon files require only crypto, ./guardedFetch, ./storeSync and ./amazonAuth; package.json names no aws or amazon package",
    J(requiresOf(FILES.auth)) === J(["./guardedFetch", "crypto"]) && J(requiresOf(FILES.api)) === J(["./amazonAuth", "./storeSync"]) && !/aws|amazon|sp-api|selling-partner/i.test(FILES.pkg));
  check("G10. the guarded fetcher sends a PATCH with one JSON object, under the PUT's own rule (checkGuardedFetch 13b proves it)",
    /const JSON_METHODS = \["GET", "POST", "PUT", "PATCH", "DELETE"\];/.test(FILES.guarded) && FILES.guarded.indexOf("guardedJsonRequest: a PUT or a PATCH carries one JSON object body") !== -1 &&
    J(AAPI.EXPOSED_HEADERS) === J(["retry-after", "x-amzn-ratelimit-limit", "x-amzn-requestid"]));
  const amazonSection = sliceOf(FILES.server, "/* ── Connect Amazon (Nov 8 2026, migration 182", "app.get(\"/api/store/connections\"");
  check("G11. no emoji in any Amazon file", [FILES.auth, FILES.api, FILES.migration, FILES.ui, amazonSection, fs.readFileSync(__filename, "utf8")].every(function (x) { return !EMOJI.test(x); }) &&
    amazonSection.length > 3000);
  check("G12. no secret, token, code, client secret or buyer field in any log line of this run", LOGS.every(noSecretIn), J(LOGS.filter(function (l) { return !noSecretIn(l); }).slice(0, 2)));
  check("G13. the network tripwire never fired, and no promise was left rejected", TRIPPED.length === 0 && UNHANDLED.length === 0, J(TRIPPED.concat(UNHANDLED.map(function (e) { return String(e && e.message); }))));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(function (e) { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
