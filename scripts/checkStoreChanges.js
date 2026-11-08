/* checkStoreChanges: WooCommerce price and stock changes, only through approval (migration 175, lib/storeWrite.js).

   WHAT IT PROVES. No request leaves this process: WooCommerce is a fake behind lib/guardedFetch.js's REAL JSON mode
   (only its DNS answer and its https.request are stood in), the database is a fake that enforces migration 175's
   CHECKs and foreign keys, and a network tripwire fails the run if anything opens a socket, asks real DNS or fetches.

     P. PERMISSION IS OPT-IN. Connecting WooCommerce asks for scope=read unless allow_changes is exactly true, then
        scope=read_write; the signed state carries it; the callback stores a key only when its key_permissions is
        exactly what was asked, and stores that permission. NAMED (Nov 7 2026, Shopify on OAuth, migration 176): BEFORE
        Shopify was always "read" (175's CHECK). AFTER 176 drops that CHECK, Connect Shopify stores the permission asked
        for, and a Shopify connection is read_write only with write_products and write_inventory granted (P8). Shopify's
        own change path (GraphQL, location, compare-and-set) is scripts/checkShopifyConnect.js's; this check stays on
        WooCommerce and on what both platforms share.
     X. PROPOSING. POST /api/store/changes/propose is requireAuth, requireActiveSubscription and 30 an hour keyed
        store-change:<uid>. It refuses a foreign item, a manual item, an item on a read-only Shopify connection (NAMED,
        migration 176: it was any Shopify item), a read-only or disconnected
        connection, a value out of range or equal to the store's, and an item whose stock is untracked, each before
        or without a write. A good proposal reads the live value with ONE GET, files a pending update_store_item
        proposal with exactly the decided payload and title, says when a sale is running, and changes nothing.
     E. EXECUTING. The executor re-reads and re-checks everything, enforces 100 changes a connection a day, compares
        the live value exactly, sends ONE POST with exactly one field (never sale_price), never retries after
        sending, checks the store's echo, then updates the item and logs the change. A replay writes nothing. A 401
        marks the connection needs_reconnect. A variation is written under its parent.
     U. UNDO AND THE LOG. Undo files a new proposal back to the old value and writes nothing; the log is the member's
        own, newest first, 50 a page.
     S. THE SERVER. The executor is registered and gated, the generic POST /api/proposals refuses the action, nothing
        auto-executes it, gateRules names the "store" channel, lib/storeSync.js stays GET-only, and a synced row's
        store fields cannot be edited locally.
     Y. THE SYNC stores each variation's parent id, and none for a simple product.
     M. THE MIGRATION AND THE REGISTRIES. 175 as run, the schema check, the backup lists, the export and delete, the
        route lists, and 175 the highest migration (R1).
     L. THE WORDS AND THE PAGES. The privacy and terms sentences as built, the Store page's line, checkbox, labels and
        Store changes section, the page script's textContent-only rendering with a confirmed Undo, the inventory
        controls, and the escaped Approvals card.

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

const MUTATIONS = {
  "write-without-permission": ["write",
    "  if (SS.permissionOf(conn) !== \"read_write\") return {", "  if (false && SS.permissionOf(conn) !== \"read_write\") return {"],
  "read-key-accepted-for-write": ["sync",
    "  if (b.key_permissions !== want) {\n", "  if (b.key_permissions !== want && !(want === \"read_write\" && b.key_permissions === \"read\")) {\n"],
  "permission-mismatch-accepted": ["server",
    "    var key = ss.checkWooKey(body, state.permission);\n", "    var key = ss.checkWooKey(body, body.key_permissions);\n"],
  "cas-skipped": ["write",
    "  var cas = compareLive(field, from, got.live);\n", "  var cas = { ok: true };\n"],
  "cas-loose-compare": ["write",
    "live.regular_price !== want) return", "Math.abs(Number(live.regular_price) - Number(want)) > 0.5) return"],
  "sale-price-written": ["write",
    "  return field === \"price\" ? { regular_price: money2(to) } :", "  return field === \"price\" ? { regular_price: money2(to), sale_price: \"\" } :"],
  "stock-untracked-written": ["write",
    "  if (field === \"stock\" && live.manage_stock !== true) return { ok: false, code: \"untracked\", error: MESSAGES.untracked };\n", ""],
  "retry-after-send": ["write",
    "  var wrote = await writeWooItem(deps, conn, creds, item, writeBody(field, v.value));\n",
    "  var wrote = await writeWooItem(deps, conn, creds, item, writeBody(field, v.value));\n  if (!wrote.ok && wrote.sent) wrote = await writeWooItem(deps, conn, creds, item, writeBody(field, v.value));\n"],
  "echo-unchecked": ["write",
    "  if (!echoMatches(field, v.value, item, wrote.data)) throw fail(MESSAGES.unconfirmed);\n", ""],
  "log-missing": ["write",
    "  var log = await deps.supabase.from(\"store_change_log\").insert({", "  var log = await deps.supabase.from(\"store_change_log_draft\").insert({"],
  "inventory-not-updated": ["write",
    "  var up = await deps.supabase.from(\"inventory_items\").update(patch)", "  var up = await deps.supabase.from(\"inventory_items\").update({ synced_at: stamp })"],
  "cap-missing": ["write",
    "  if (count >= DAILY_CAP) throw fail(MESSAGES.cap);\n", ""],
  "cap-off-by-one": ["write",
    "  if (count >= DAILY_CAP)", "  if (count > DAILY_CAP)"],
  "replay-writes-again": ["write",
    "  if (prior.data && prior.data.length) {\n", "  if (false) {\n"],
  "auto-executed": ["write",
    "  if (ins.error) throw ins.error;\n", "  if (ins.error) throw ins.error;\n  await executeChange(deps, ins.data).catch(function () {});\n"],
  "filed-through-generic-route": ["server",
    "    if (actionType === \"update_store_item\") {\n", "    if (false) {\n"],
  "foreign-item-proposed": ["write",
    ".eq(\"id\", itemId).eq(\"user_id\", userId).maybeSingle();", ".eq(\"id\", itemId).maybeSingle();"],
  "variation-path-wrong": ["write",
    "  return \"/products/\" + parent + \"/variations/\" + m[2];", "  return \"/products/\" + m[2];"],
  /* NAMED (Nov 7 2026, Shopify on OAuth, migration 176): BEFORE anchored on the "not_woocommerce" refusal, which is gone:
     Shopify changes are allowed now, on a connection made with changes allowed. AFTER the mutation lets a Shopify
     connection through without that permission; X9 and E18 (a read-only Shopify connection) must catch it. */
  "shopify-write-allowed": ["write",
    "  if (SS.permissionOf(conn) !== \"read_write\") return {", "  if (conn.platform !== \"shopify\" && SS.permissionOf(conn) !== \"read_write\") return {"],
  // NAMED (Nov 7 2026, migration 176): BEFORE anchored on "function shopifyUrl(domain, path) {", which is gone. AFTER the same
  // added POST, just above lib/storeSync.js's WooCommerce section.
  "storesync-writes": ["sync",
    "/* ── WooCommerce ──",
    "function wooWrite(deps, url, headers, body) {\n  return deps.jsonRequest(url, { method: \"POST\", headers: headers, body: body });\n}\n/* ── WooCommerce ──"],
  "local-edit-allowed": ["server",
    "        if (storeFieldChanged) {\n", "        if (false) {\n"],
  "undo-writes-directly": ["write",
    "  return proposeChange(deps, userId, { item_id: row.inventory_item_id, field: row.field, to: to });\n",
    "  var filed = await proposeChange(deps, userId, { item_id: row.inventory_item_id, field: row.field, to: to });\n  if (filed.status === 201) await executeChange(deps, filed.body.proposal);\n  return filed;\n"],
  // NAMED (Nov 7 2026, migration 176): BEFORE "...record of changes are deleted" sat on one source line. AFTER the 176 sentence
  // breaks its source line after "are", so the anchor ends there; the mutation still drops the record of changes.
  "privacy-sentence-stale": ["legal",
    "the order summaries and the record of changes are \" +", "the order summaries are \" +"],
  "innerHTML-on-page": ["changesUi",
    "    if (text !== undefined) e.textContent = text;\n", "    if (text !== undefined) e.innerHTML = text;\n"],
  // the others the code earns
  "store-card-unescaped": ["proposals",
    "escapeHtml(storeChangeText(payload))", "storeChangeText(payload)"],
  "sync-parent-dropped": ["sync",
    "    external_parent_id: parentId === undefined ? null : parentIdOf(parentId),\n", "    external_parent_id: null,\n"],
  "scope-not-requested": ["sync",
    "\"&scope=\" + (permission === \"read_write\" ? \"read_write\" : \"read\")", "\"&scope=\" + \"read\""],
  "allow-changes-default-on": ["server",
    "var wooPermission = body.allow_changes === true ? \"read_write\" : \"read\";", "var wooPermission = body.allow_changes === false ? \"read\" : \"read_write\";"],
  "auth-not-marked": ["write",
    "    if (wrote.auth) await SS.markNeedsReconnect(", "    if (false) await SS.markNeedsReconnect("],
  "range-unchecked": ["write",
    "Number(m) > VALUE_MAX) return", "Number(m) > VALUE_MAX * 100) return"],
  // NAMED (Nov 7 2026, YouTube uploads, migration 177): the gated list now goes on past update_store_item
  // with the two YouTube actions; the mutation still removes update_store_item alone.
  // NAMED (Nov 7 2026, TikTok posting, migration 178): the list goes on with publish_tiktok_post; still update_store_item alone removed.
  "approve-ungated": ["server",
    "  \"update_store_item\", \"publish_youtube_video\", \"delete_youtube_video\", \"publish_tiktok_post\"];", "  \"publish_youtube_video\", \"delete_youtube_video\", \"publish_tiktok_post\"];"],
  "limiter-raised": ["server",
    "  max: 30,\n  keyGenerator: function (req) { return \"store-change:\"", "  max: 300,\n  keyGenerator: function (req) { return \"store-change:\""],
  "propose-ungated": ["server",
    "app.post(\"/api/store/changes/propose\", requireAuth, requireActiveSubscription, storeChangeLimiter,", "app.post(\"/api/store/changes/propose\", requireAuth, storeChangeLimiter,"],
  "foreign-log-listed": ["write",
    ".select(LOG_COLUMNS).eq(\"user_id\", userId);", ".select(LOG_COLUMNS);"],
  "foreign-undo": ["write",
    ".eq(\"id\", changeId).eq(\"user_id\", userId).maybeSingle();", ".eq(\"id\", changeId).maybeSingle();"],
  // NAMED (Nov 7 2026, migration 176): BEFORE proposeControl(itemId, prefill). AFTER it takes the connection first, to label
  // the price with the store's currency and name a Shopify location.
  "readonly-row-offered": ["changesUi",
    "    if (writable(conn)) return proposeControl(conn, itemId, prefill);\n", "    return proposeControl(conn, itemId, prefill);\n"],
  "undo-unconfirmed": ["changesUi",
    "          undo.hidden = true; sure.hidden = false; cancel.hidden = false;\n", "          undo.hidden = true; sure.hidden = false; cancel.hidden = false; sure.click();\n"]
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
  write: read("lib/storeWrite.js"),
  sync: read("lib/storeSync.js"),
  server: read("server.js"),
  migration: read("supabase/migrations/175_store_changes.sql"),
  // NAMED (Nov 7 2026, migration 176): the migration that drops 175's Shopify CHECK, and the Shopify module lib/storeWrite.js requires.
  migration176: read("supabase/migrations/176_shopify_oauth.sql"),
  api: read("lib/shopifyApi.js"),
  legal: read("lib/legalPages.js"),
  gateRules: read("lib/gateRules.js"),
  privacy: readFe("privacy.html"),
  terms: readFe("terms.html"),
  page: readFe("store-agent.html"),
  ui: readFe("scripts/store-connect.js"),
  changesUi: readFe("scripts/store-changes.js"),
  inventory: readFe("inventory.html"),
  proposals: readFe("proposals.html")
};
if (MUTATE) {
  const m = MUTATIONS[MUTATE];
  FILES[m[0]] = MUT.replaceOnce(FILES[m[0]], m[1], m[2], MUTATE);
  console.log("\n!! MUTATION: " + MUTATE);
}

const J = JSON.stringify;
const SECRET_HEX = crypto.createHash("sha256").update("checkStoreChanges").digest("hex");
process.env.ENCRYPTION_SECRET = SECRET_HEX;
const realRequire = Module.createRequire(path.join(REPO, "server.js"));
const CRYPT = realRequire("./lib/apiKeyCrypto");
const GF = realRequire("./lib/guardedFetch");
function compile(src, file, map) {
  const m = { exports: {} };
  const req = Module.createRequire(path.join(REPO, file));
  const fn = vm.compileFunction(src, ["module", "exports", "require", "__dirname", "__filename"], { filename: path.join(REPO, file) });
  fn(m, m.exports, function (r) { return Object.prototype.hasOwnProperty.call(map, r) ? map[r] : req(r); }, path.dirname(path.join(REPO, file)), path.join(REPO, file));
  return m.exports;
}
const SS = compile(FILES.sync, "lib/storeSync.js", {});
// NAMED (Nov 7 2026, migration 176): lib/storeWrite.js requires ./shopifyApi, compiled here against the same storeSync.
const SAPI = compile(FILES.api, "lib/shopifyApi.js", { "./storeSync": SS });
const SW = compile(FILES.write, "lib/storeWrite.js", { "./storeSync": SS, "./shopifyApi": SAPI });
const GR = compile(FILES.gateRules, "lib/gateRules.js", {});
function braceMatch(src, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < src.length; i++) {
    const c = src[i];
    if (c === "{") depth++;
    else if (c === "}") { depth--; if (depth === 0) return i + 1; }
  }
  return -1;
}
function fnSource(src, name) {
  const a = src.indexOf("function " + name + "(");
  if (a === -1) return "";
  const open = src.indexOf("{", a);
  return src.slice(a, braceMatch(src, open));
}

const USER = "00000000-0000-4000-8000-000000000001";
const OTHER = "00000000-0000-4000-8000-000000000002";
const WOO = "https://woo.example.com";
const WOO_RO = "https://shop2.example.com";
const SHOP = "demo-shop.myshopify.com";
const CK = "ck_" + "f".repeat(40), CS = "cs_" + "e".repeat(40);
const M = SW.MESSAGES;

/* ── a fake database that enforces migration 175 ─────────────────────────── */
function uuid() { return crypto.randomUUID(); }
function makeDb() {
  const t = { member_store_connections: [], inventory_items: [], inventory_movements: [], store_order_summaries: [], store_change_log: [], agent_proposals: [], notifications: [], job_runs: [] };
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
    return null;
  }
  // migration 163's and 175's CHECKs and the 175 foreign keys
  function checkViolation(name, r) {
    if (name === "member_store_connections") {
      if (!/^[0-9a-f]+$/.test(r.credentials_ciphertext || "") || !/^[0-9a-f]{24}$/.test(r.credentials_iv || "") || !/^[0-9a-f]{32}$/.test(r.credentials_auth_tag || "")) return "member_store_connections_ciphertext_check";
      if (["read", "read_write"].indexOf(r.permission) === -1) return "member_store_connections_permission_check";
      // NAMED (Nov 7 2026, migration 176): BEFORE member_store_connections_write_platform_check (permission = 'read' OR
      // platform = 'woocommerce') was enforced here. AFTER migration 176 drops it, so this fake no longer has it (P8).
    }
    if (name === "inventory_items") {
      const manual = r.source == null && r.store_connection_id == null && r.external_id == null;
      const synced = (r.source === "shopify" || r.source === "woocommerce") && r.store_connection_id && r.external_id;
      if (!manual && !synced) return "inventory_items_source_check";
      if (!(r.external_parent_id == null || (String(r.external_parent_id).length <= 100 && /^[0-9]+$/.test(String(r.external_parent_id))))) return "inventory_items_external_parent_id_check";
    }
    if (name === "store_change_log") {
      if (!r.user_id || !r.connection_id) return "store_change_log_not_null";
      if (!rows("member_store_connections").some(function (c) { return c.id === r.connection_id; })) return "store_change_log_connection_id_fkey";
      if (r.inventory_item_id != null && !rows("inventory_items").some(function (i) { return i.id === r.inventory_item_id; })) return "store_change_log_inventory_item_id_fkey";
      if (["price", "stock"].indexOf(r.field) === -1) return "store_change_log_field_check";
      if (typeof r.external_id !== "string" || r.external_id.length < 1 || r.external_id.length > 100) return "store_change_log_external_id_check";
      if (String(r.item_name).length > 200) return "store_change_log_item_name_check";
      if (typeof r.old_value !== "number" || typeof r.new_value !== "number" || !(r.old_value >= 0 && r.new_value >= 0 && r.new_value <= 1000000)) return "store_change_log_values_check";
    }
    if (name === "store_order_summaries" && !Array.isArray(r.line_items)) return "store_order_summaries_line_items_check";
    return null;
  }
  function defaults(name, row) {
    const now = new Date().toISOString();
    const r = Object.assign({ id: uuid(), created_at: now }, row);
    if (name === "member_store_connections") { if (r.status === undefined) r.status = "connected"; if (r.permission === undefined) r.permission = "read"; }
    if (name === "inventory_items") { if (r.status === undefined) r.status = "active"; if (r.unit === undefined) r.unit = "unit"; ["source", "store_connection_id", "external_id", "external_parent_id", "reorder_point", "unit_cost"].forEach(function (k) { if (r[k] === undefined) r[k] = null; }); }
    if (name === "store_change_log") { if (r.item_name === undefined) r.item_name = ""; if (r.executed_at === undefined) r.executed_at = now; if (r.inventory_item_id === undefined) r.inventory_item_id = null; if (r.proposal_id === undefined) r.proposal_id = null; }
    return r;
  }
  function project(r, cols) {
    if (!cols || cols.trim() === "*") return Object.assign({}, r);
    const o = {};
    cols.split(",").map(function (c) { return c.trim(); }).forEach(function (c) { o[c] = r[c] === undefined ? null : r[c]; });
    return o;
  }
  function from(name) {
    const q = { op: null, cols: null, count: false, head: false, filters: [], payload: null, onConflict: null, single: null, range: null, returning: false, order: null, limit: null };
    const api = {
      select: function (cols, opts) { if (!q.op) q.op = "select"; else q.returning = true; q.cols = cols; if (opts && opts.count) q.count = true; if (opts && opts.head) q.head = true; return api; },
      insert: function (p) { q.op = "insert"; q.payload = p; return api; },
      update: function (p) { q.op = "update"; q.payload = p; return api; },
      upsert: function (p, o) { q.op = "upsert"; q.payload = p; q.onConflict = o && o.onConflict; return api; },
      delete: function () { q.op = "delete"; return api; },
      eq: function (c, v) { q.filters.push(["eq", c, v]); return api; },
      in: function (c, v) { q.filters.push(["in", c, v]); return api; },
      gte: function (c, v) { q.filters.push(["gte", c, v]); return api; },
      lt: function (c, v) { q.filters.push(["lt", c, v]); return api; },
      order: function (c, o) { q.order = [c, !(o && o.ascending === false)]; return api; },
      limit: function (n) { q.limit = n; return api; },
      range: function (a, b) { q.range = [a, b]; return api; },
      maybeSingle: function () { q.single = "maybe"; return api; },
      single: function () { q.single = "one"; return api; },
      then: function (ok, bad) { return Promise.resolve().then(run).then(ok, bad); }
    };
    function match(r) {
      return q.filters.every(function (f) {
        if (f[0] === "eq") return String(r[f[1]]) === String(f[2]);
        if (f[0] === "in") return f[2].map(String).indexOf(String(r[f[1]])) !== -1;
        if (f[0] === "gte") return r[f[1]] != null && String(r[f[1]]) >= String(f[2]);
        if (f[0] === "lt") return r[f[1]] != null && String(r[f[1]]) < String(f[2]);
        return true;
      });
    }
    function shape(list) {
      const data = list.map(function (r) { return project(r, q.cols); });
      if (q.single === "maybe") return { data: data[0] || null, error: null };
      if (q.single === "one") return data.length === 1 ? { data: data[0], error: null } : { data: null, error: { code: "PGRST116", message: "not one row" } };
      return { data: q.op === "select" ? (q.head ? null : data) : (q.returning ? data : null), error: null };
    }
    function run() {
      log.push({ table: name, op: q.op, filters: q.filters.slice() });
      const all = rows(name);
      if (q.op === "select") {
        let hit = all.filter(match);
        const total = hit.length;
        if (q.order) { const c = q.order[0], asc = q.order[1]; hit = hit.slice().sort(function (a, b) { const x = String(a[c]), y = String(b[c]); return (x < y ? -1 : x > y ? 1 : 0) * (asc ? 1 : -1); }); }
        if (q.range) hit = hit.slice(q.range[0], q.range[1] + 1);
        if (q.limit != null) hit = hit.slice(0, q.limit);
        const out = shape(hit);
        if (q.count) out.count = total;
        return out;
      }
      if (q.op === "insert") {
        const list = Array.isArray(q.payload) ? q.payload : [q.payload];
        const made = [];
        for (const p of list) {
          const r = defaults(name, p);
          const u = uniqueViolation(name, r, null); if (u) return { data: null, error: { code: "23505", message: u } };
          const c = checkViolation(name, r); if (c) return { data: null, error: { code: "23514", message: c } };
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
        const ids = hit.map(function (r) { return r.id; });
        if (name === "member_store_connections") {
          // ON DELETE CASCADE: store_order_summaries.connection_id (163), store_change_log.connection_id (175)
          t.store_order_summaries = t.store_order_summaries.filter(function (r) { return ids.indexOf(r.connection_id) === -1; });
          t.store_change_log = t.store_change_log.filter(function (r) { return ids.indexOf(r.connection_id) === -1; });
        }
        if (name === "inventory_items") {
          // ON DELETE SET NULL: store_change_log.inventory_item_id (175)
          t.store_change_log.forEach(function (r) { if (ids.indexOf(r.inventory_item_id) !== -1) r.inventory_item_id = null; });
        }
        return shape(hit);
      }
      return { data: null, error: { message: "fake: no op" } };
    }
    return api;
  }
  return { from: from, t: t, log: log };
}

/* ── a fake WooCommerce, behind the REAL guarded fetcher ─────────────────── */
function reply(status, body, hdrs) {
  const h = { "content-type": "application/json; charset=utf-8" };
  Object.keys(hdrs || {}).forEach(function (k) { h[k.toLowerCase()] = String(hdrs[k]); });
  return { status: status, headers: h, raw: Buffer.from(JSON.stringify(body), "utf8") };
}
const PUBLIC_V4 = "93.184.216.34";
function makeWoo(opts) {
  const o = Object.assign({}, opts || {});
  const calls = [];   // requests that reached the store
  const asked = [];   // every deps.jsonRequest call
  const state = {
    products: {
      101: { id: 101, name: "Mug", type: "simple", sku: "MUG", regular_price: "19.99", sale_price: "", price: "19.99", stock_quantity: 5, manage_stock: true },
      102: { id: 102, name: "Poster", type: "simple", sku: "POSTER", regular_price: "10.00", sale_price: "8.00", price: "8.00", stock_quantity: null, manage_stock: false },
      300: { id: 300, name: "T-shirt", type: "variable", sku: "", regular_price: "", sale_price: "", price: "20.00", stock_quantity: null, manage_stock: false }
    },
    variations: {
      301: { id: 301, parent: 300, sku: "TEE-M", regular_price: "20.00", sale_price: "", price: "20.00", stock_quantity: 3, manage_stock: true, attributes: [{ name: "Size", option: "M" }] },
      302: { id: 302, parent: 300, sku: "TEE-L", regular_price: "20.00", sale_price: "", price: "20.00", stock_quantity: 2, manage_stock: true, attributes: [{ name: "Size", option: "L" }] }
    }
  };
  function shown(x) { const c = Object.assign({}, x); delete c.parent; return c; }
  function apply(x, body) {
    if (Object.prototype.hasOwnProperty.call(body, "regular_price")) { x.regular_price = String(body.regular_price); if (!x.sale_price) x.price = x.regular_price; }
    if (Object.prototype.hasOwnProperty.call(body, "sale_price")) { x.sale_price = String(body.sale_price); if (!x.sale_price) x.price = x.regular_price; }
    if (Object.prototype.hasOwnProperty.call(body, "stock_quantity")) x.stock_quantity = body.stock_quantity;
  }
  function answer(url, method, payload, authHeader) {
    const u = new URL(url);
    let body = null;
    if (payload) { try { body = JSON.parse(payload.toString("utf8")); } catch (e) { body = { unparsed: true }; } }
    calls.push({ url: url, host: u.hostname, method: method, path: u.pathname, query: u.search, body: body, auth: authHeader || "" });
    const p = u.pathname.replace(/^\/wp-json\/wc\/v3/, "");
    let m;
    if (method === "GET") {
      if (o.getStatus) return reply(o.getStatus, { code: "woocommerce_rest_cannot_view" });
      if (p === "/products" && u.searchParams.get("per_page") === "1") return reply(200, [{ id: 1 }]);
      if (p === "/products") return reply(200, Object.keys(state.products).map(function (k) { return shown(state.products[k]); }), { "X-WP-TotalPages": "1" });
      if ((m = /^\/products\/(\d+)\/variations$/.exec(p))) {
        const pid = Number(m[1]);
        return reply(200, Object.keys(state.variations).map(function (k) { return state.variations[k]; }).filter(function (v) { return v.parent === pid; }).map(shown), { "X-WP-TotalPages": "1" });
      }
      if (p === "/orders") return reply(200, [], { "X-WP-TotalPages": "1" });
      if ((m = /^\/products\/(\d+)$/.exec(p)) && state.products[m[1]]) return reply(200, shown(state.products[m[1]]));
      if ((m = /^\/products\/(\d+)\/variations\/(\d+)$/.exec(p)) && state.variations[m[2]] && state.variations[m[2]].parent === Number(m[1])) return reply(200, shown(state.variations[m[2]]));
      return reply(404, { code: "woocommerce_rest_product_invalid_id" });
    }
    if (method === "POST") {
      let target = null;
      if ((m = /^\/products\/(\d+)$/.exec(p)) && state.products[m[1]]) target = state.products[m[1]];
      if ((m = /^\/products\/(\d+)\/variations\/(\d+)$/.exec(p)) && state.variations[m[2]] && state.variations[m[2]].parent === Number(m[1])) target = state.variations[m[2]];
      if (!target) return reply(404, { code: "woocommerce_rest_product_invalid_id" });
      if (o.postStatus) return reply(o.postStatus, { code: "error" });
      if (o.echoStale) return reply(200, shown(target));
      apply(target, body || {});
      if (o.postDropAfterApply) return { error: Object.assign(new Error("socket hang up"), { code: "ECONNRESET" }) };
      return reply(200, shown(target));
    }
    return reply(405, { code: "rest_no_route" });
  }
  function resolve(hostname, lookupOptions, cb) {
    return cb(null, o.addresses || [{ address: PUBLIC_V4, family: 4 }]);
  }
  function transport(options) {
    const req = new EventEmitter();
    req.destroy = function () {};
    req.write = function () { throw new Error("checkStoreChanges: the fake store expects the body in end()"); };
    req.end = function (payload) {
      process.nextTick(function () {
        options.lookup(options.hostname, { all: true }, function (err) {
          if (err) return req.emit("error", err);
          const url = "https://" + options.hostname + options.path;
          const hdrs = options.headers || {};
          const auth = hdrs.Authorization || hdrs.authorization || "";
          const r = answer(url, options.method || "GET", payload, auth);
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
    if (o.postTimeout && options && options.method === "POST") {
      // the guarded fetcher's own timeout, after the request was sent
      return Promise.reject(Object.assign(new Error("timeout: no complete answer within 20000 ms"), { name: "GuardedFetchError", code: "timeout", guardedFetch: true, connected: true }));
    }
    return guarded(url, options);
  }
  return { jsonRequest: jsonRequest, calls: calls, asked: asked, state: state, opts: o,
    posts: function () { return calls.filter(function (c) { return c.method === "POST"; }); },
    gets: function () { return calls.filter(function (c) { return c.method === "GET"; }); } };
}

/* THE NETWORK TRIPWIRE */
const TRIPPED = [];
(function tripwire() {
  const http = require("http"), https = require("https"), net = require("net"), tls = require("tls"), dns = require("dns");
  function wire(obj, name, label) {
    obj[name] = function () { TRIPPED.push(label); throw new Error("checkStoreChanges: " + label + " is not allowed in this check"); };
  }
  wire(http, "request", "http.request"); wire(http, "get", "http.get");
  wire(https, "request", "https.request"); wire(https, "get", "https.get");
  wire(net, "connect", "net.connect"); wire(net, "createConnection", "net.createConnection");
  wire(tls, "connect", "tls.connect");
  wire(dns, "lookup", "dns.lookup"); wire(dns, "resolve", "dns.resolve"); wire(dns.promises, "lookup", "dns.promises.lookup");
  globalThis.fetch = function () { TRIPPED.push("fetch"); return Promise.reject(new Error("checkStoreChanges: fetch is not allowed in this check")); };
})();

/* ── fixtures ────────────────────────────────────────────────────────────── */
function sealed() { return SS.sealCredentials({ consumer_key: CK, consumer_secret: CS }, CRYPT.encrypt); }
function seed(db) {
  function conn(userId, platform, url, permission, status) {
    // NAMED (Nov 7 2026, migration 176): BEFORE a Shopify row held a sealed pasted { access_token }. AFTER the OAuth shape:
    // a sealed { refresh_token } in credentials_* and the sealed access token in access_*, with the read scopes granted.
    const s = platform === "shopify" ? Object.assign(SS.sealCredentials({ refresh_token: "shprt_" + "a1b2c3d4".repeat(4) }, CRYPT.encrypt), (function () {
      const a = CRYPT.encrypt("shpca_" + "a1b2c3d4".repeat(4));
      return { access_ciphertext: a.ciphertext, access_iv: a.iv, access_auth_tag: a.authTag, access_expires_at: "2027-06-01T00:00:00.000Z", token_version: 0,
        granted_scopes: "read_products,read_inventory,read_orders,read_locations" };
    })()) : sealed();
    const r = Object.assign({ id: uuid(), user_id: userId, platform: platform, store_url: url, status: status || "connected", permission: permission, created_at: "2026-11-06T00:00:00.000Z" }, s);
    db.t.member_store_connections.push(r);
    return r;
  }
  function item(userId, c, externalId, parent, name, price, qty) {
    const r = { id: uuid(), user_id: userId, name: name, sku: null, unit: "unit", status: "active", unit_price: price, unit_cost: null, quantity_on_hand: qty, reorder_point: 2,
      source: c ? c.platform : null, store_connection_id: c ? c.id : null, external_id: externalId, external_parent_id: parent, synced_at: "2026-11-06T00:00:00.000Z", created_at: "2026-11-06T00:00:00.000Z" };
    db.t.inventory_items.push(r);
    return r;
  }
  const rw = conn(USER, "woocommerce", WOO, "read_write");
  const ro = conn(USER, "woocommerce", WOO_RO, "read");
  const shop = conn(USER, "shopify", SHOP, "read");
  const otherConn = conn(OTHER, "woocommerce", WOO, "read_write");
  return {
    rw: rw, ro: ro, shop: shop, otherConn: otherConn,
    mug: item(USER, rw, "product:101", null, "Mug", 19.99, 5),
    poster: item(USER, rw, "product:102", null, "Poster", 8, 0),
    tee: item(USER, rw, "variation:301", "300", "T-shirt - M", 20, 3),
    teeOld: item(USER, rw, "variation:302", null, "T-shirt - L", 20, 2),
    roMug: item(USER, ro, "product:101", null, "Mug (second store)", 19.99, 5),
    shopItem: item(USER, shop, "variant:11", null, "Wool Hat", 25, 4),
    manual: item(USER, null, null, null, "Hand-made card", 3, 10),
    foreign: item(OTHER, otherConn, "product:101", null, "Someone else's mug", 19.99, 5)
  };
}
function libDeps(db, woo) {
  return { supabase: db, env: {}, jsonRequest: woo.jsonRequest, now: function () { return Date.now(); },
    sleep: function () { return Promise.resolve(); }, encrypt: CRYPT.encrypt, decrypt: CRYPT.decrypt,
    userPlan: async function () { return { plan: { active: true }, error: null }; } };
}
function setup(wooOpts) {
  const db = makeDb();
  const f = seed(db);
  const woo = makeWoo(wooOpts);
  return { db: db, f: f, woo: woo, deps: libDeps(db, woo) };
}
async function propose(s, itemId, field, to) { return SW.proposeChange(s.deps, USER, { item_id: itemId, field: field, to: to }); }
async function runExec(s, proposal) {
  try { return { ok: true, result: await SW.executeChange(s.deps, proposal) }; } catch (e) { return { ok: false, error: e && e.message }; }
}
function seedLog(db, conn, n, ageMs) {
  for (let i = 0; i < n; i++) {
    db.t.store_change_log.push({ id: uuid(), user_id: conn.user_id, connection_id: conn.id, inventory_item_id: null, external_id: "product:9" + i, item_name: "Old " + i,
      field: "price", old_value: 1, new_value: 2, proposal_id: uuid(), executed_at: new Date(Date.now() - ageMs - i * 1000).toISOString() });
  }
}

/* ── the routes, run from server.js's own source ─────────────────────────── */
// NAMED (Nov 7 2026, Shopify on OAuth, migration 176): BEFORE the section began "Store connections, read-only
// (migration 163, ...)". AFTER it names migrations 163, 175 and 176; the same block, from here to END.
const START = "/* ── Store connections (migrations 163, 175, 176; lib/storeSync.js) ──────────";
const END = "// The SEO writer used to answer in JSON, which meant embedding a whole HTML";
const SECTION = (function () {
  const a = FILES.server.indexOf(START), b = FILES.server.indexOf(END, a);
  return a === -1 || b === -1 ? "" : FILES.server.slice(a, b);
})();
function requireAuth() {} function requireActiveSubscription() {}
function mountRoutes(woo, db) {
  const routes = {};
  const logs = [];
  const ctx = {
    supabase: db,
    process: { env: { ENCRYPTION_SECRET: SECRET_HEX } },
    console: { log: function () { logs.push([].slice.call(arguments).join(" ")); }, error: function () { logs.push([].slice.call(arguments).join(" ")); }, warn: function () { logs.push([].slice.call(arguments).join(" ")); } },
    rateLimit: function (o) { return { limiter: o }; },
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
      if (r === "./lib/storeWrite") return SW;
      if (r === "./lib/shopifyApi") return SAPI;
      if (r === "./lib/apiKeyCrypto") return { encrypt: function (p) { return CRYPT.encrypt(p); }, decrypt: function (x) { return CRYPT.decrypt(x); } };
      if (r === "./lib/guardedFetch") return Object.assign({}, GF, { guardedJsonRequest: woo.jsonRequest });
      return realRequire(r);
    },
    app: {}
  };
  ["get", "post", "put", "delete"].forEach(function (m) {
    ctx.app[m] = function (p) { const args = [].slice.call(arguments, 1); routes[m + " " + p] = { middleware: args.slice(0, -1), handler: args[args.length - 1] }; };
  });
  vm.createContext(ctx);
  vm.runInContext(SECTION, ctx, { filename: "server.js (store section)" });
  return { routes: routes, ctx: ctx, logs: logs };
}
async function hit(m, key, req) {
  const r = m.routes[key];
  if (!r) return { status: 0, body: {}, err: new Error("no route " + key) };
  const res = { statusCode: 200, body: undefined, set: function () { return this; }, status: function (c) { this.statusCode = c; return this; }, json: function (b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
  let err = null;
  try { await r.handler(Object.assign({ user: { id: USER }, body: {}, params: {}, query: {} }, req), res, function (e) { err = e || new Error("next"); }); }
  catch (e) { err = e; res.statusCode = 599; }
  return { status: res.statusCode, body: res.body || {}, err: err };
}

/* ── a small DOM for the page script ─────────────────────────────────────── */
const HTML_SET = [];
class El {
  constructor(tag) { this.tagName = String(tag).toUpperCase(); this.children = []; this.attrs = {}; this.listeners = {}; this._t = ""; this.className = ""; this.hidden = false; this.disabled = false; this.value = ""; this.parent = null; this.type = ""; }
  get textContent() { return this._t + this.children.map(function (c) { return c.textContent; }).join(""); }
  set textContent(v) { this._t = String(v); this.children = []; }
  set innerHTML(v) { HTML_SET.push(String(v)); this._t = String(v); this.children = []; }
  get innerHTML() { return this._t; }
  appendChild(c) { this.children.push(c); c.parent = this; return c; }
  addEventListener(type, fn) { this.listeners[type] = fn; }
  click() { if (this.listeners.click) this.listeners.click({ target: this }); }
  remove() { if (this.parent) { const i = this.parent.children.indexOf(this); if (i !== -1) this.parent.children.splice(i, 1); this.parent = null; } }
  getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attrs, k) ? this.attrs[k] : null; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  all() { let out = []; this.children.forEach(function (c) { out.push(c); out = out.concat(c.all()); }); return out; }
  querySelectorAll(sel) { const m = /^\[([a-z-]+)\]$/.exec(sel); return m ? this.all().filter(function (e) { return e.getAttribute(m[1]) !== null; }) : []; }
}
function find(root, pred) { return root.all().filter(pred); }
const flush = async function () { for (let i = 0; i < 12; i++) await new Promise(function (r) { setImmediate(r); }); };
function loadPageScript(answers) {
  const calls = [];
  const win = {};
  const ctx = {
    window: win, console: console, Array: Array, Date: Date, JSON: JSON, String: String, encodeURIComponent: encodeURIComponent, Promise: Promise,
    localStorage: { getItem: function () { return "token-for-check"; } },
    document: { readyState: "complete", createElement: function (t) { return new El(t); }, getElementById: function () { return null; }, addEventListener: function () {} },
    fetch: function (url, init) {
      const method = (init && init.method) || "GET";
      const body = init && init.body ? JSON.parse(init.body) : undefined;
      calls.push({ url: url, method: method, body: body });
      const pathOnly = String(url).replace(/^https:\/\/[^/]+/, "");
      const a = answers(method, pathOnly, body) || { status: 404, data: {} };
      return Promise.resolve({ ok: a.status >= 200 && a.status < 300, status: a.status, json: function () { return Promise.resolve(a.data); } });
    }
  };
  vm.createContext(ctx);
  vm.runInContext(FILES.changesUi, ctx, { filename: "scripts/store-changes.js" });
  return { win: win, calls: calls };
}

(async function main() {
  check("the store section of server.js was found, and it holds the store-changes routes", SECTION.length > 1000 && SECTION.indexOf("/api/store/changes/propose") !== -1);

  /* ── P ── */
  console.log("\n══ P. write permission is opt-in, per connection ══");
  {
    const db = makeDb(); const woo = makeWoo(); const m = mountRoutes(woo, db);
    const plain = await hit(m, "post /api/store/connections", { body: { platform: "woocommerce", store_url: WOO } });
    const pUrl = new URL(plain.body.authorize_url || "https://x.invalid/");
    const pState = SS.readWooState(pUrl.searchParams.get("user_id"), Date.now(), SECRET_HEX);
    check("P1. connecting without allow_changes asks for scope=read, and the signed state carries read",
      plain.status === 200 && pUrl.searchParams.get("scope") === "read" && plain.body.permission === "read" && !!pState && pState.permission === "read", J(plain.body).slice(0, 200));
    const allowed = await hit(m, "post /api/store/connections", { body: { platform: "woocommerce", store_url: WOO, allow_changes: true } });
    const aUrl = new URL(allowed.body.authorize_url || "https://x.invalid/");
    const aState = SS.readWooState(aUrl.searchParams.get("user_id"), Date.now(), SECRET_HEX);
    check("P2. allow_changes true asks for scope=read_write, and the signed state carries read_write",
      allowed.status === 200 && aUrl.searchParams.get("scope") === "read_write" && allowed.body.permission === "read_write" && !!aState && aState.permission === "read_write");
    const off = await hit(m, "post /api/store/connections", { body: { platform: "woocommerce", store_url: WOO, allow_changes: false } });
    check("P2. allow_changes false asks for scope=read", off.status === 200 && new URL(off.body.authorize_url).searchParams.get("scope") === "read");
    const bad = await hit(m, "post /api/store/connections", { body: { platform: "woocommerce", store_url: WOO, allow_changes: "yes" } });
    check("P3. allow_changes that is not a boolean is a 400 and nothing is asked", bad.status === 400 && bad.body.code === "allow_changes" && woo.calls.length === 0);

    const rwState = SS.makeWooState(USER, WOO, Date.now(), SECRET_HEX, "read_write");
    const roState = SS.makeWooState(USER, WOO_RO, Date.now(), SECRET_HEX, "read");
    const cb = function (state, perm) { return hit(m, "post /api/store/woocommerce/callback", { user: undefined, body: { user_id: state, consumer_key: CK, consumer_secret: CS, key_permissions: perm } }); };
    const readForWrite = await cb(rwState, "read");
    check("P5. a read key when read_write was asked is refused, and nothing is stored",
      readForWrite.status === 400 && readForWrite.body.code === "permission_mismatch" && db.t.member_store_connections.length === 0, J(readForWrite.body));
    const writeForRead = await cb(roState, "read_write");
    check("P6. a read_write key when read was asked is refused, and nothing is stored",
      writeForRead.status === 400 && writeForRead.body.code === "not_read_only" && db.t.member_store_connections.length === 0, J(writeForRead.body));
    const goodRw = await cb(rwState, "read_write");
    const rwRow = db.t.member_store_connections.find(function (r) { return r.store_url === WOO; });
    check("P4. a read_write key when read_write was asked is verified by one GET and stored with permission read_write",
      goodRw.status === 200 && goodRw.body.saved === true && !!rwRow && rwRow.permission === "read_write" && woo.calls.length === 1 && woo.calls[0].method === "GET");
    const goodRo = await cb(roState, "read");
    const roRow = db.t.member_store_connections.find(function (r) { return r.store_url === WOO_RO; });
    check("P7. a read key when read was asked is stored with permission read", goodRo.status === 200 && !!roRow && roRow.permission === "read");
    const list = await hit(m, "get /api/store/connections", {});
    const perms = (list.body.connections || []).map(function (c) { return c.store + "=" + c.permission; }).sort();
    check("P9. the list names each connection's permission, and the note says changes happen only with approval",
      J(perms) === J([WOO_RO + "=read", WOO + "=read_write"]) && list.body.note === SS.MESSAGES.readWrite);
    /* NAMED (Nov 7 2026, Shopify on OAuth, migration 176): BEFORE P8 held that the database refused a Shopify read_write
       connection (175's write_platform_check) and that Shopify connect saved "read". AFTER migration 176 drops that CHECK:
       Shopify changes are opt-in like WooCommerce's. Connect Shopify stores the permission the signed state asked for, and
       a Shopify connection counts as read_write only when Shopify also granted write_products and write_inventory. */
    const scopesAll = "read_products,read_inventory,read_orders,read_locations,write_products,write_inventory";
    check("P8. migration 176 drops 175's Shopify CHECK; Connect Shopify stores the permission the state asked for; a Shopify connection is read_write only with both write scopes granted",
      FILES.migration176.indexOf("DROP CONSTRAINT member_store_connections_write_platform_check;") !== -1 &&
      FILES.server.indexOf("var permission = body.allow_changes === true ? \"read_write\" : \"read\";") !== -1 &&
      FILES.server.indexOf("user_id: req.user.id, platform: \"shopify\", store_url: shop, status: \"connected\", permission: permission,") !== -1 &&
      SS.permissionOf({ platform: "shopify", permission: "read_write", granted_scopes: scopesAll }) === "read_write" &&
      SS.permissionOf({ platform: "shopify", permission: "read_write", granted_scopes: "read_products,read_inventory,read_orders,read_locations,write_products" }) === "read" &&
      SS.permissionOf({ platform: "shopify", permission: "read", granted_scopes: scopesAll }) === "read" &&
      SS.permissionOf({ platform: "shopify", permission: "read_write", granted_scopes: null }) === "read");
    check("P10. the permission cannot be raised by editing the state: a read state rewritten to read_write fails its signature",
      (function () {
        const st = SS.makeWooState(USER, WOO, Date.now(), SECRET_HEX, "read");
        const parts = st.split(".");
        const claims = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
        claims.p = "read_write";
        const raised = Buffer.from(JSON.stringify(claims)).toString("base64url") + "." + parts[1];
        return SS.readWooState(st, Date.now(), SECRET_HEX).permission === "read" && SS.readWooState(raised, Date.now(), SECRET_HEX) === null;
      })());
  }

  /* ── X ── */
  console.log("\n══ X. proposing a change: one live read, a pending proposal, nothing changed ══");
  {
    const s = setup();
    const out = await propose(s, s.f.mug.id, "price", "24");
    const prop = out.body.proposal || {};
    // NAMED (Nov 7 2026, migration 176): BEFORE nine payload keys. AFTER the platform and the store's currency too (null until a sync
    // reads it), so the Approvals card can name them; a Shopify payload adds its own ids (checkShopifyConnect holds those).
    const want = { connection_id: s.f.rw.id, item_id: s.f.mug.id, external_id: "product:101", external_parent_id: null, item_name: "Mug", field: "price", from: "19.99", to: "24.00", automatic: false,
      platform: "woocommerce", currency: null };
    check("X1. a price proposal files a pending update_store_item proposal, agent store, with exactly the decided payload",
      out.status === 201 && prop.status === "pending" && prop.action_type === "update_store_item" && prop.agent_type === "store" && J(prop.payload) === J(want), J(out.body).slice(0, 300));
    check("X1. its title is \"Change Mug price from 19.99 to 24.00\"", prop.title === "Change Mug price from 19.99 to 24.00", prop.title);
    check("X1. it read the store with exactly ONE GET of the item, with the decided _fields, and sent nothing else",
      s.woo.calls.length === 1 && s.woo.calls[0].method === "GET" && s.woo.calls[0].path === "/wp-json/wc/v3/products/101" &&
      decodeURIComponent(s.woo.calls[0].query) === "?_fields=id,regular_price,sale_price,stock_quantity,manage_stock");
    check("X1. it never runs: the store, the item and the log are unchanged, and the note says nothing changed yet",
      s.woo.posts().length === 0 && s.woo.state.products[101].regular_price === "19.99" && s.f.mug.unit_price === 19.99 && s.db.t.store_change_log.length === 0 &&
      out.body.note === M.filed && out.body.sale_running === false);
    const stock = await propose(s, s.f.mug.id, "stock", 9);
    check("X1. a stock proposal carries whole numbers, and its title names stock", stock.status === 201 && stock.body.proposal.payload.from === 5 && stock.body.proposal.payload.to === 9 &&
      stock.body.proposal.title === "Change Mug stock from 5 to 9");

    const sale = await propose(s, s.f.poster.id, "price", "12");
    check("X2. while a sale is running, the note says \"" + M.sale + "\"", sale.status === 201 && sale.body.sale_running === true && sale.body.note === M.filed + " " + M.sale && sale.body.proposal.payload.from === "10.00");
    const untracked = await propose(s, s.f.poster.id, "stock", 4);
    check("X2. an item whose stock the store does not track cannot have a stock change proposed", untracked.status === 409 && untracked.body.code === "untracked" && untracked.body.error === M.untracked);

    const before = s.woo.calls.length;
    const bad = [["price", "0"], ["price", "0.001"], ["price", "1000000.01"], ["price", "abc"], ["price", 1000001], ["price", -1], ["stock", -1], ["stock", 1.5], ["stock", "1000001"], ["stock", "two"], ["colour", "red"]];
    const answers = [];
    for (const b of bad) answers.push(await propose(s, s.f.mug.id, b[0], b[1]));
    check("X3. out-of-range values are 400 with the decided words, and nothing is read",
      answers.every(function (a) { return a.status === 400; }) && answers.slice(0, 6).every(function (a) { return a.body.error === M.price; }) &&
      answers.slice(6, 10).every(function (a) { return a.body.error === M.stock; }) && answers[10].body.code === "field" && s.woo.calls.length === before, J(answers.map(function (a) { return a.status + ":" + a.body.code; })));
    const edges = [await propose(s, s.f.mug.id, "price", "0.01"), await propose(s, s.f.mug.id, "price", "1000000"), await propose(s, s.f.mug.id, "stock", 0), await propose(s, s.f.mug.id, "stock", "1000000")];
    check("X3. the edges are allowed: 0.01, 1000000, stock 0 and 1000000", edges.every(function (a) { return a.status === 201; }), J(edges.map(function (a) { return a.status; })));
    const same = await propose(s, s.f.mug.id, "price", "19.99");
    check("X4. a value equal to the store's is refused", same.status === 400 && same.body.code === "same" && same.body.error === M.same);

    const n0 = s.woo.calls.length;
    const ro = await propose(s, s.f.roMug.id, "price", "24");
    check("X5. an item on a read-only connection is refused, with nothing read", ro.status === 409 && ro.body.code === "read_only" && ro.body.error === M.readOnly && s.woo.calls.length === n0);
    const man = await propose(s, s.f.manual.id, "price", "4");
    check("X7. a manual item is refused", man.status === 409 && man.body.code === "not_synced");
    const foreign = await propose(s, s.f.foreign.id, "price", "24");
    check("X8. another member's item is not found, and nothing is read", foreign.status === 404 && s.woo.calls.length === n0 && s.db.t.agent_proposals.every(function (p) { return p.payload.item_id !== s.f.foreign.id; }));
    const shop = await propose(s, s.f.shopItem.id, "price", "30");
    // NAMED (Nov 7 2026, migration 176): BEFORE "a Shopify item is refused: Shopify stays read-only" (not_woocommerce). AFTER
    // Shopify changes are allowed with permission, so an item on a READ-ONLY Shopify connection is refused like WooCommerce's.
    check("X9. an item on a read-only Shopify connection is refused (read_only), with nothing read",
      shop.status === 409 && shop.body.code === "read_only" && shop.body.error === M.readOnly && s.woo.calls.length === n0, J(shop.body));
    const old = await propose(s, s.f.teeOld.id, "price", "22");
    check("X11. a variation synced before 175 (no parent id) asks for a sync, with nothing read", old.status === 409 && old.body.code === "unaddressable" && s.woo.calls.length === n0);
    const tee = await propose(s, s.f.tee.id, "stock", 6);
    check("X10. a variation is read under its parent, and its payload carries the parent id",
      tee.status === 201 && tee.body.proposal.payload.external_parent_id === "300" && s.woo.calls[s.woo.calls.length - 1].path === "/wp-json/wc/v3/products/300/variations/301");
    s.f.rw.status = "needs_reconnect";
    const nr = await propose(s, s.f.mug.id, "price", "24");
    s.f.rw.status = "connected";
    check("X6. a connection that needs reconnecting is refused", nr.status === 409 && nr.body.code === "needs_reconnect");

    const s401 = setup({ getStatus: 401 });
    const r401 = await propose(s401, s401.f.mug.id, "price", "24");
    check("X12. a 401 on the live read marks the connection needs_reconnect, with one notice, and files nothing",
      r401.status === 409 && s401.f.rw.status === "needs_reconnect" && s401.db.t.notifications.length === 1 && s401.db.t.agent_proposals.length === 0);
  }

  /* ── E ── */
  console.log("\n══ E. executing an approved change ══");
  {
    const s = setup();
    const filed = (await propose(s, s.f.mug.id, "price", "24")).body.proposal;
    const r = await runExec(s, filed);
    const posts = s.woo.posts();
    check("E1. an approved price change sends exactly ONE POST to the item's own resource",
      r.ok && posts.length === 1 && posts[0].path === "/wp-json/wc/v3/products/101", J(r));
    check("E1. its body is exactly { regular_price: \"24.00\" }, never sale_price", posts.length === 1 && J(posts[0].body) === J({ regular_price: "24.00" }));
    const asked = s.woo.asked.filter(function (a) { return a.options.method === "POST"; });
    check("E1. through the guarded fetcher's JSON mode: POST, 1 MB, 20 s, Basic auth, no other option",
      asked.length === 1 && J(Object.keys(asked[0].options).sort()) === J(["body", "exposeHeaders", "headers", "maxBytes", "method", "timeoutMs"]) &&
      asked[0].options.maxBytes === 1024 * 1024 && asked[0].options.timeoutMs === 20000 && /^Basic /.test(posts[0].auth));
    check("E1. the store holds the new price, the item row is updated, and the result says applied",
      s.woo.state.products[101].regular_price === "24.00" && s.f.mug.unit_price === 24 && r.result.applied === true && r.result.from === "19.99" && r.result.to === "24.00");
    const logRow = s.db.t.store_change_log[0] || {};
    check("E1. one change is logged: the item, price, 19.99 to 24, and the proposal",
      s.db.t.store_change_log.length === 1 && logRow.user_id === USER && logRow.connection_id === s.f.rw.id && logRow.inventory_item_id === s.f.mug.id &&
      logRow.field === "price" && logRow.old_value === 19.99 && logRow.new_value === 24 && logRow.proposal_id === filed.id && logRow.item_name === "Mug" && r.result.change_id === logRow.id);
    const again = await runExec(s, filed);
    check("E3. a replay of the same proposal writes nothing and answers already_applied",
      again.ok && again.result.already_applied === true && s.woo.posts().length === 1 && s.db.t.store_change_log.length === 1);

    const st = setup();
    const sp = (await propose(st, st.f.mug.id, "stock", 7)).body.proposal;
    const sr = await runExec(st, sp);
    check("E2. an approved stock change sends exactly { stock_quantity: 7 } and updates quantity_on_hand",
      sr.ok && st.woo.posts().length === 1 && J(st.woo.posts()[0].body) === J({ stock_quantity: 7 }) && st.f.mug.quantity_on_hand === 7 && st.db.t.store_change_log[0].field === "stock");

    const ss2 = setup();
    const pp = (await propose(ss2, ss2.f.poster.id, "price", "12")).body.proposal;
    const pr = await runExec(ss2, pp);
    check("E1. during a sale, only regular_price is sent and the store's sale price is untouched",
      pr.ok && J(ss2.woo.posts()[0].body) === J({ regular_price: "12.00" }) && ss2.woo.state.products[102].sale_price === "8.00");

    const sc = setup();
    const cp = (await propose(sc, sc.f.mug.id, "price", "24")).body.proposal;
    sc.woo.state.products[101].regular_price = "21.00";
    const cr = await runExec(sc, cp);
    check("E4. the store changed since the proposal: \"" + M.changed + "\", nothing written or logged",
      !cr.ok && cr.error === M.changed && sc.woo.posts().length === 0 && sc.db.t.store_change_log.length === 0);
    const sl = setup();
    const lp = (await propose(sl, sl.f.mug.id, "price", "24")).body.proposal;
    sl.woo.state.products[101].regular_price = "20.00";
    const lr = await runExec(sl, lp);
    const sk = setup();
    const kp = (await propose(sk, sk.f.mug.id, "stock", 9)).body.proposal;
    sk.woo.state.products[101].stock_quantity = 6;
    const kr = await runExec(sk, kp);
    check("E5. the compare is exact: 19.99 against a live 20.00, and stock 5 against a live 6, both refused",
      !lr.ok && lr.error === M.changed && !kr.ok && kr.error === M.changed && sl.woo.posts().length === 0 && sk.woo.posts().length === 0);
    const su = setup();
    const up = (await propose(su, su.f.mug.id, "stock", 9)).body.proposal;
    su.woo.state.products[101].manage_stock = false;
    const ur = await runExec(su, up);
    check("E6. a stock change on an item the store stopped tracking: \"" + M.untracked + "\", nothing written",
      !ur.ok && ur.error === M.untracked && su.woo.posts().length === 0);

    async function failedWrite(opts) {
      const x = setup(opts);
      const p = (await propose(x, x.f.mug.id, "price", "24")).body.proposal;
      const res = await runExec(x, p);
      return { x: x, res: res };
    }
    const f503 = await failedWrite({ postStatus: 503 });
    check("E7. a 503 after sending: \"" + M.unconfirmed + "\", ONE POST, never retried, nothing logged, the item untouched",
      !f503.res.ok && f503.res.error === M.unconfirmed && f503.x.woo.posts().length === 1 && f503.x.db.t.store_change_log.length === 0 && f503.x.f.mug.unit_price === 19.99);
    const drop = await failedWrite({ postDropAfterApply: true });
    check("E8. the connection drops after the store applied it: unconfirmed, ONE POST, never retried, nothing logged",
      !drop.res.ok && drop.res.error === M.unconfirmed && drop.x.woo.posts().length === 1 && drop.x.db.t.store_change_log.length === 0);
    const slow = await failedWrite({ postTimeout: true });
    check("E9. a timeout after sending: unconfirmed, one write asked, never retried",
      !slow.res.ok && slow.res.error === M.unconfirmed && slow.x.woo.asked.filter(function (a) { return a.options.method === "POST"; }).length === 1 && slow.x.db.t.store_change_log.length === 0);
    const stale = await failedWrite({ echoStale: true });
    check("E10. a 200 whose answer does not show the new price: unconfirmed, nothing logged, the item untouched",
      !stale.res.ok && stale.res.error === M.unconfirmed && stale.x.db.t.store_change_log.length === 0 && stale.x.f.mug.unit_price === 19.99 && stale.x.woo.posts().length === 1);
    const f401 = await failedWrite({ postStatus: 401 });
    check("E11. a 401 on the write marks the connection needs_reconnect, with one notice, and logs nothing",
      !f401.res.ok && f401.res.error === M.rejected && f401.x.f.rw.status === "needs_reconnect" && f401.x.db.t.notifications.length === 1 && f401.x.db.t.store_change_log.length === 0 && f401.x.woo.posts().length === 1);
    const f400 = await failedWrite({ postStatus: 400 });
    check("E12. a 400 is \"" + M.refused + "\", nothing logged", !f400.res.ok && f400.res.error === M.refused && f400.x.db.t.store_change_log.length === 0);

    async function capRun(n, ageMs) {
      const x = setup();
      const p = (await propose(x, x.f.mug.id, "price", "24")).body.proposal;
      seedLog(x.db, x.f.rw, n, ageMs);
      const before = x.woo.calls.length;
      const res = await runExec(x, p);
      return { res: res, x: x, before: before };
    }
    const c100 = await capRun(100, 60 * 1000);
    check("E14. 100 changes in the last 24 hours: \"" + M.cap + "\", and nothing is read or written",
      !c100.res.ok && c100.res.error === M.cap && c100.x.woo.calls.length === c100.before);
    const c99 = await capRun(99, 60 * 1000);
    check("E14. 99 changes in the last 24 hours: the 100th goes ahead", c99.res.ok && c99.x.woo.posts().length === 1);
    const cOld = await capRun(150, 25 * 60 * 60 * 1000);
    check("E14. changes older than 24 hours do not count", cOld.res.ok);
    const cOther = await (async function () {
      const x = setup();
      const p = (await propose(x, x.f.mug.id, "price", "24")).body.proposal;
      seedLog(x.db, x.f.otherConn, 100, 60 * 1000);
      return runExec(x, p);
    })();
    check("E14. the cap is per connection: another connection's 100 do not count", cOther.ok);

    const sv = setup();
    const vp = (await propose(sv, sv.f.tee.id, "price", "22")).body.proposal;
    const vr = await runExec(sv, vp);
    check("E17. a variation is written under its parent: POST /products/300/variations/301",
      vr.ok && sv.woo.posts().length === 1 && sv.woo.posts()[0].path === "/wp-json/wc/v3/products/300/variations/301" && sv.woo.state.variations[301].regular_price === "22.00");

    const sr2 = setup();
    const rp = (await propose(sr2, sr2.f.mug.id, "price", "24")).body.proposal;
    sr2.f.rw.permission = "read";
    const n1 = sr2.woo.calls.length;
    const rr = await runExec(sr2, rp);
    check("E15. permission withdrawn after the proposal: \"" + M.readOnly.slice(0, 40) + "...\", nothing read or written",
      !rr.ok && rr.error === M.readOnly && sr2.woo.calls.length === n1);
    const sm = setup();
    const mp = (await propose(sm, sm.f.mug.id, "price", "24")).body.proposal;
    const forged = JSON.parse(JSON.stringify(mp)); forged.payload.external_id = "product:102";
    const n2 = sm.woo.calls.length;
    const mr = await runExec(sm, forged);
    check("E16. a payload that no longer matches the item is refused, nothing read or written", !mr.ok && sm.woo.calls.length === n2);
    const foreignRun = await runExec(sm, Object.assign({}, mp, { user_id: OTHER }));
    check("E16. a proposal is read only as its owner's: another member's id finds nothing to change", !foreignRun.ok && sm.woo.posts().length === 0);
    const shopRun = await runExec(sm, { id: uuid(), user_id: USER, payload: { connection_id: sm.f.shop.id, item_id: sm.f.shopItem.id, external_id: "variant:11", external_parent_id: null, item_name: "Wool Hat", field: "price", from: "25.00", to: "30.00", automatic: false } });
    // NAMED (Nov 7 2026, migration 176): BEFORE any Shopify connection was refused (MESSAGES.notWoo, now gone). AFTER a
    // read-only Shopify connection is refused by the executor itself with the read-only message.
    check("E18. a read-only Shopify connection is refused by the executor itself: \"" + M.readOnly.slice(0, 40) + "...\", nothing read or written",
      !shopRun.ok && shopRun.error === M.readOnly && sm.woo.calls.length === n2 && M.notWoo === undefined);
    const rangeRun = await runExec(sm, Object.assign({}, mp, { payload: Object.assign({}, mp.payload, { to: "1000000.01" }) }));
    check("E16. the executor checks the range again", !rangeRun.ok && rangeRun.error === M.price && sm.woo.calls.length === n2);

    // through server.js: the executor registered there is lib/storeWrite.js's
    const se = setup();
    const m = mountRoutes(se.woo, se.db);
    const pr2 = await hit(m, "post /api/store/changes/propose", { body: { item_id: se.f.mug.id, field: "price", to: "24" } });
    let ex = null;
    try { ex = await m.ctx.executeUpdateStoreItem(se.db.t.agent_proposals[0]); } catch (e) { ex = { error: e.message }; }
    check("E19. through server.js: the propose route files it, and executeUpdateStoreItem makes the change once",
      pr2.status === 201 && !!ex && ex.applied === true && se.woo.posts().length === 1 && se.db.t.store_change_log.length === 1, J(ex));
  }

  /* ── U ── */
  console.log("\n══ U. undo and the record of changes ══");
  {
    const s = setup();
    const filed = (await propose(s, s.f.mug.id, "price", "24")).body.proposal;
    await runExec(s, filed);
    const change = s.db.t.store_change_log[0];
    const posts = s.woo.posts().length;
    const undo = await SW.undoChange(s.deps, USER, change.id);
    const back = undo.body.proposal || {};
    check("U1. undo files a NEW pending proposal from the live 24.00 back to 19.99, and writes nothing",
      undo.status === 201 && back.id !== filed.id && back.status === "pending" && back.payload.from === "24.00" && back.payload.to === "19.99" &&
      s.woo.posts().length === posts && s.woo.state.products[101].regular_price === "24.00" && s.db.t.store_change_log.length === 1, J(undo.body).slice(0, 200));
    const foreignUndo = await SW.undoChange(s.deps, OTHER, change.id);
    check("U2. another member cannot undo it: \"" + M.gone + "\"", foreignUndo.status === 404 && foreignUndo.body.error === M.gone);
    await s.db.from("inventory_items").delete().eq("id", s.f.mug.id);
    const goneUndo = await SW.undoChange(s.deps, USER, change.id);
    check("U3. once the item is gone, undo says so", goneUndo.status === 409 && goneUndo.body.code === "item_gone" && s.db.t.store_change_log[0].inventory_item_id === null);

    const sl = setup();
    seedLog(sl.db, sl.f.rw, 55, 60 * 1000);
    seedLog(sl.db, sl.f.otherConn, 3, 1000);
    const page1 = await SW.listChanges(sl.deps, USER, null);
    const times = page1.changes.map(function (c) { return c.executed_at; });
    const sorted = times.slice().sort().reverse();
    check("U4. the log is the member's own, newest first, 50 a page, with the next page's cursor",
      page1.changes.length === 50 && page1.has_more === true && J(times) === J(sorted) && page1.next_before === times[49] &&
      page1.changes.every(function (c) { return c.connection_id === sl.f.rw.id; }) && page1.changes[0].old_value === "1.00");
    const page2 = await SW.listChanges(sl.deps, USER, page1.next_before);
    check("U4. the second page holds the other 5, and no more", page2.changes.length === 5 && page2.has_more === false && page2.next_before === null);
    const m = mountRoutes(sl.woo, sl.db);
    const viaRoute = await hit(m, "get /api/store/changes", { query: {} });
    check("U4. GET /api/store/changes answers the same", viaRoute.status === 200 && (viaRoute.body.changes || []).length === 50);

    const sd = setup();
    const fp = (await propose(sd, sd.f.mug.id, "price", "24")).body.proposal;
    await runExec(sd, fp);
    const md = mountRoutes(sd.woo, sd.db);
    const gone = await hit(md, "delete /api/store/connections/:id", { params: { id: sd.f.rw.id } });
    check("U5. disconnecting deletes the record of changes with the connection", gone.status === 200 && sd.db.t.store_change_log.length === 0 && /record of changes/.test(gone.body.note || ""));
  }

  /* ── S ── */
  console.log("\n══ S. the server: registered, gated, never automatic, GET-only sync, no local edits ══");
  {
    const m = mountRoutes(makeWoo(), makeDb());
    const mw = function (k) { const r = m.routes[k]; return r ? r.middleware : []; };
    const lim = mw("post /api/store/changes/propose")[2];
    check("S0. propose is requireAuth, requireActiveSubscription and 30 an hour keyed store-change:<uid>",
      mw("post /api/store/changes/propose").length === 3 && mw("post /api/store/changes/propose")[0] === requireAuth && mw("post /api/store/changes/propose")[1] === requireActiveSubscription &&
      !!lim && lim.limiter.max === 30 && lim.limiter.windowMs === 60 * 60 * 1000 && lim.limiter.keyGenerator({ user: { id: USER } }) === "store-change:" + USER);
    check("S0. undo has the same guards and the same limiter; the log is requireAuth only",
      mw("post /api/store/changes/:id/undo").length === 3 && mw("post /api/store/changes/:id/undo")[1] === requireActiveSubscription && mw("post /api/store/changes/:id/undo")[2] === lim &&
      mw("get /api/store/changes").length === 1 && mw("get /api/store/changes")[0] === requireAuth);
    const execStart = FILES.server.indexOf("const PROPOSAL_EXECUTORS = {");
    const execMap = execStart === -1 ? "" : FILES.server.slice(execStart, braceMatch(FILES.server, FILES.server.indexOf("{", execStart)));
    check("S1. PROPOSAL_EXECUTORS runs update_store_item with executeUpdateStoreItem", /\n  update_store_item: executeUpdateStoreItem,\n/.test(execMap));
    const gs = FILES.server.indexOf("const SUBSCRIPTION_GATED_PROPOSAL_ACTIONS = [");
    const gated = gs === -1 ? [] : vm.runInNewContext(FILES.server.slice(gs + "const SUBSCRIPTION_GATED_PROPOSAL_ACTIONS = ".length, FILES.server.indexOf("];", gs) + 1));
    check("S2. approving it needs a subscription (SUBSCRIPTION_GATED_PROPOSAL_ACTIONS)", gated.indexOf("update_store_item") !== -1, J(gated));
    const gen = FILES.server.indexOf("app.post(\"/api/proposals\", requireAuth");
    const genSrc = gen === -1 ? "" : FILES.server.slice(gen, FILES.server.indexOf("\napp.", gen + 10));
    const refuse = genSrc.indexOf("if (actionType === \"update_store_item\") {\n      return res.status(400).json(");
    check("S3. the generic POST /api/proposals refuses update_store_item before it inserts anything",
      refuse !== -1 && refuse < genSrc.indexOf(".from(\"agent_proposals\")"));
    check("S4. nothing runs it automatically: no autoExecuteFiledProposal call names it, and proposing never executes (X1)",
      !/autoExecuteFiledProposal\([^)]*executeUpdateStoreItem/.test(FILES.server) && (FILES.server.match(/executeUpdateStoreItem\(/g) || []).length === 1 &&
      fnSource(FILES.write, "proposeChange").indexOf("executeChange") === -1 && fnSource(FILES.write, "undoChange").indexOf("executeChange") === -1);
    check("S5. gateRules: update_store_item is an action type on the \"store\" channel",
      GR.ACTION_TYPES.indexOf("update_store_item") !== -1 && GR.CHANNELS.indexOf("store") !== -1 && GR.channelFor("update_store_item") === "store");
    const syncCalls = FILES.sync.match(/deps\.jsonRequest\(/g) || [];
    /* NAMED (Nov 7 2026, Shopify on OAuth, migration 176): BEFORE "lib/storeSync.js stays GET-only: one deps.jsonRequest,
       method GET, no POST, PUT, PATCH or DELETE". AFTER the same, and it holds no Shopify request either: the sync reads a
       shop only through deps.shopifyReader (lib/shopifyApi.js's query-only reads). */
    check("S6. lib/storeSync.js stays GET-only: one deps.jsonRequest, method GET, no POST, PUT, PATCH or DELETE, and no Shopify request of its own",
      syncCalls.length === 1 && /deps\.jsonRequest\(url, \{ method: "GET",/.test(FILES.sync) && !/method:\s*"(POST|PUT|PATCH|DELETE)"/.test(FILES.sync) &&
      !/\bfetch\(|graphql|X-Shopify/i.test(FILES.sync.replace(/\/\/.*$/gm, "").replace(/\/\*[\s\S]*?\*\//g, "")));
    const writeCalls = FILES.write.match(/deps\.jsonRequest\(/g) || [];
    const execSrc = fnSource(FILES.write, "executeChange");
    const shopifyWriteSrc = fnSource(FILES.write, "writeShopifyItem");
    /* NAMED (Nov 7 2026, migration 176): BEFORE "lib/storeWrite.js writes with ONE deps.jsonRequest POST, called once in the
       executor, and names no Shopify API". AFTER WooCommerce is still that one POST, called once; Shopify is written only
       through lib/shopifyApi.js, writePrice or writeStock, each named once in writeShopifyItem, which the executor calls once
       and which holds no loop; lib/storeWrite.js still names no Shopify host, Admin API path, header or mutation itself. */
    check("S6. lib/storeWrite.js writes WooCommerce with ONE deps.jsonRequest POST and Shopify only through lib/shopifyApi.js's writePrice or writeStock, each called once by the executor, never in a loop, and names no Shopify API itself",
      writeCalls.length === 1 && /deps\.jsonRequest\(SS\.wooUrl\(conn\.store_url, path\), \{ method: "POST",/.test(FILES.write) &&
      (execSrc.match(/writeWooItem\(/g) || []).length === 1 && !/\b(for|while)\s*\(/.test(fnSource(FILES.write, "writeWooItem")) &&
      (execSrc.match(/writeShopifyItem\(/g) || []).length === 1 && !/\b(for|while)\s*\(/.test(shopifyWriteSrc) &&
      (shopifyWriteSrc.match(/SAPI\.writePrice\(/g) || []).length === 1 && (shopifyWriteSrc.match(/SAPI\.writeStock\(/g) || []).length === 1 &&
      (FILES.write.match(/SAPI\.write(Price|Stock)\(/g) || []).length === 2 &&
      !/myshopify|\/admin\/api\/|X-Shopify|\bmutation\b/.test(FILES.write.replace(/\/\/.*$/gm, "").replace(/\/\*[\s\S]*?\*\//g, "")) && !/method:\s*"(PUT|PATCH|DELETE)"/.test(FILES.write));

    // PUT /api/inventory/items/:id: the synced-row guard, run from server.js's own text
    const putAt = FILES.server.indexOf("app.put(\"/api/inventory/items/:id\"");
    const a = FILES.server.indexOf("        var body = req.body || {};\n        var storeFieldChanged", putAt);
    const endMark = "            code: \"synced_item\"\n          });\n        }\n";
    const b = a === -1 ? -1 : FILES.server.indexOf(endMark, a);
    let guard = null;
    if (a !== -1 && b !== -1) {
      guard = vm.runInNewContext("(function (req, res, validated, editedItem) {\n" + FILES.server.slice(a, b + endMark.length) + "\n return null; })", { Object: Object, String: String, Number: Number });
    }
    const resp = function () { return { code: null, body: null, status: function (c) { this.code = c; return this; }, json: function (bd) { this.body = bd; return this; } }; };
    const synced = { name: "Mug", sku: "MUG", unit_price: 19.99, unit_cost: null, quantity_on_hand: 5, source: "woocommerce" };
    function tryPut(body, fields) { const r = resp(); const out = guard(body ? { body: body } : { body: {} }, r, { fields: fields || body }, synced); return out ? r : null; }
    const priceEdit = guard ? tryPut({ unit_price: 25 }) : null;
    const sameSave = guard ? tryPut({ name: "Mug", sku: "MUG", unit_price: "19.99", unit_cost: "", quantity_on_hand: "5", reorder_point: 3 }, { name: "Mug", sku: "MUG", unit_price: 19.99, unit_cost: null, quantity_on_hand: 5, reorder_point: 3 }) : "x";
    const stockEdit = guard ? tryPut({ quantity_on_hand: 9 }) : null;
    const nameEdit = guard ? tryPut({ name: "Big Mug" }) : null;
    const ownField = guard ? tryPut({ reorder_point: 4, notes: "top shelf" }) : "x";
    check("S7. a synced row's price, stock or name cannot be edited locally: 409 with the decided words",
      !!priceEdit && priceEdit.code === 409 && priceEdit.body.error === "This item comes from your store. Change it in your store, or propose a change." && priceEdit.body.code === "synced_item" &&
      !!stockEdit && stockEdit.code === 409 && !!nameEdit && nameEdit.code === 409);
    check("S7. saving the same values, or the member's own fields, still goes through", sameSave === null && ownField === null);
    check("S8. Stock & Margin names a synced row's item, so the page can offer a change",
      FILES.server.indexOf("    if (row.source !== \"manual\" && it.id) row.store_item_id = it.id;\n") !== -1);
  }

  /* ── Y ── */
  console.log("\n══ Y. the sync stores each variation's parent ══");
  {
    const db = makeDb();
    const conn = Object.assign({ id: uuid(), user_id: USER, platform: "woocommerce", store_url: WOO, status: "connected", permission: "read_write", created_at: "2026-11-06T00:00:00.000Z" }, sealed());
    db.t.member_store_connections.push(conn);
    const woo = makeWoo();
    const out = await SS.syncConnection(libDeps(db, woo), conn);
    const v = db.t.inventory_items.find(function (r) { return r.external_id === "variation:301"; }) || {};
    const p = db.t.inventory_items.find(function (r) { return r.external_id === "product:101"; }) || {};
    check("Y1. a variation is stored with its parent id, a simple product with none, through the CHECK",
      out && out.ok !== false && v.external_parent_id === "300" && p.external_parent_id === null, J(out));
    check("Y2. the sync sent only GETs", woo.calls.length > 0 && woo.calls.every(function (c) { return c.method === "GET"; }));
  }

  /* ── M ── */
  console.log("\n══ M. the migration and the registries ══");
  {
    const mig = FILES.migration;
    check("M1. migration 175 starts with the owner's header", mig.indexOf("-- Applied by the owner by hand in the Supabase SQL editor on Nov 6, 2026. This file is the text as run.\n\n") === 0);
    check("M1. it adds permission (default read, read or read_write, read unless woocommerce) and external_parent_id (digits, 100 at most)",
      mig.indexOf("ADD COLUMN IF NOT EXISTS permission text NOT NULL DEFAULT 'read';") !== -1 &&
      mig.indexOf("CHECK (permission IN ('read', 'read_write'))") !== -1 && mig.indexOf("CHECK (permission = 'read' OR platform = 'woocommerce')") !== -1 &&
      mig.indexOf("ADD COLUMN IF NOT EXISTS external_parent_id text;") !== -1 && mig.indexOf("external_parent_id ~ '^[0-9]+$'") !== -1);
    check("M1. store_change_log: connection cascade, item set null, field price or stock, values 0 to 1000000, RLS on, no anon or authenticated access",
      mig.indexOf("CREATE TABLE public.store_change_log (") !== -1 && mig.indexOf("REFERENCES public.member_store_connections(id) ON DELETE CASCADE") !== -1 &&
      mig.indexOf("REFERENCES public.inventory_items(id) ON DELETE SET NULL") !== -1 && mig.indexOf("CHECK (field IN ('price', 'stock'))") !== -1 &&
      mig.indexOf("new_value <= 1000000") !== -1 && mig.indexOf("ALTER TABLE public.store_change_log ENABLE ROW LEVEL SECURITY;") !== -1 &&
      mig.indexOf("REVOKE ALL ON public.store_change_log FROM anon, authenticated;") !== -1);
    const SC = realRequire("./lib/schemaCheck");
    const scText = read("lib/schemaCheck.js");
    check("M2. the schema check knows store_change_log from 175", scText.indexOf("[\"store_change_log\", \"175_store_changes.sql\"]") !== -1 && !!SC);
    const BK = realRequire("./lib/backup");
    check("M2. the backup skips it, with the reason (its connection is excluded), and never lists it to restore",
      typeof BK.SKIPPED_TABLES.store_change_log === "string" && /store connection, which is excluded/.test(BK.SKIPPED_TABLES.store_change_log) &&
      BK.BACKUP_TABLES.indexOf("store_change_log") === -1 && "member_store_connections" in BK.EXCLUDED_TABLES);
    const YD = realRequire("./lib/yourData");
    const entry = YD.DATA.find(function (d) { return d.table === "store_change_log"; }) || {};
    const connEntry = YD.DATA.find(function (d) { return d.table === "member_store_connections"; }) || {};
    check("M2. the export holds the record of changes in the business group, and names each connection's permission",
      entry.group === "business" && /^Changes BizForce made to your store with your approval/.test(entry.what || "") && /old_value/.test(entry.select || "") &&
      /permission/.test(connEntry.select || "") && /allowed BizForce to make changes you approve/.test(connEntry.what || "") && !/credentials/.test(connEntry.select || ""));
    check("M2. the account delete removes it before the store connections", YD.DELETE_ORDER.indexOf("store_change_log") !== -1 && YD.FINAL_DELETES.indexOf("member_store_connections") !== -1);
    const migFiles = fs.readdirSync(path.join(REPO, "supabase/migrations")).filter(function (f) { return /^\d+_/.test(f); });
    /* NAMED (Nov 7 2026, Shopify on OAuth, migration 176): BEFORE "the only migration numbered 175, and the highest". AFTER
       176_shopify_oauth.sql follows it, so the pin is "the only one numbered 175, every other one but 176 is lower, and 174
       came before it"; "the highest" is checkShopifyConnect R1's, for 176. */
    /* NAMED (Nov 7 2026, YouTube uploads, migration 177): BEFORE only 176_shopify_oauth.sql was excepted. AFTER
       177_youtube_uploads.sql is excepted too, by name; "the highest" is checkYoutubeUploads R1's, for 177. */
    /* NAMED (Nov 7 2026, TikTok posting, migration 178): 178_tiktok_posting.sql is excepted too, by name; "the highest" is
       checkTiktokPosting R1's, for 178. */
    check("R1. 175_store_changes.sql is the only migration numbered 175, every one but 176_shopify_oauth.sql, 177_youtube_uploads.sql and 178_tiktok_posting.sql is lower (174 the last before it)",
      migFiles.filter(function (f) { return /^175_/.test(f); }).length === 1 && migFiles.indexOf("175_store_changes.sql") !== -1 &&
      migFiles.filter(function (f) { return !/^(176_shopify_oauth|177_youtube_uploads|178_tiktok_posting)\.sql$/.test(f); }).every(function (f) { return Number(f.split("_")[0]) <= 175; }) && migFiles.some(function (f) { return /^174_/.test(f); }));
    check("M1b. migration 176 drops 175's Shopify CHECK and adds currency and location_name to store_change_log",
      FILES.migration176.indexOf("ALTER TABLE public.member_store_connections\n  DROP CONSTRAINT member_store_connections_write_platform_check;") !== -1 &&
      FILES.migration176.indexOf("ALTER TABLE public.store_change_log\n  ADD COLUMN IF NOT EXISTS currency text,\n  ADD COLUMN IF NOT EXISTS location_name text;") !== -1);
    const dormant = read("scripts/checkDormantRoutesDeleted.js"), surface = read("scripts/checkUnsubscribedSurface.js");
    check("M3. the three routes are in checkDormantRoutesDeleted ADDED, and propose and undo in checkUnsubscribedSurface's gated list",
      ["[\"post\", \"/api/store/changes/propose\"]", "[\"get\", \"/api/store/changes\"]", "[\"post\", \"/api/store/changes/:id/undo\"]"].every(function (s) { return dormant.indexOf(s) !== -1; }) &&
      surface.indexOf("\"post /api/store/changes/propose\", \"post /api/store/changes/:id/undo\"") !== -1);
  }

  /* ── L ── */
  console.log("\n══ L. the words and the pages ══");
  {
    const LP = compile(FILES.legal, "lib/legalPages.js", {});
    const esc = function (t) { return String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"); };
    /* NAMED (Nov 7 2026, Shopify on OAuth, migration 176): BEFORE the 175 sentence ("the key you made for it, encrypted", "the
       key is never shown back", "deleted when you disconnect the store or delete your account"). AFTER the owner's sentence
       for 176, word for word: the access given (WooCommerce's key or Shopify's approved access), the currency and location
       names, and deletion on uninstall too. */
    const PRIVACY = "If you connect a Shopify or WooCommerce store, BizForce stores the store's address and the access it is given, encrypted (for WooCommerce, the key you made for it; for Shopify, the access you approve when you connect), and reads from the store only your products (name, SKU, price, cost where the store has one), your stock levels, your store's currency and location names, and summaries of your orders (each order's number, date, total, currency, and its items as SKU and quantity), never any customer's name, email, address or phone number; BizForce changes a product's price or stock level in your store only when you approve that change, and only if you allowed changes when you connected the store, and it keeps a record of each change (the item, the old and new value, and when). What it reads is used only for your own agents, the store's key or access is never shown back to you or exported, and it, the products, the stock, the order summaries and the record of changes are deleted when you disconnect the store, uninstall BizForce from Shopify, or delete your account.";
    check("L1. the privacy sentence is word for word the decided one, the record of changes in the deletion list", LP.STORE_PRIVACY_SENTENCE === PRIVACY, LP.STORE_PRIVACY_SENTENCE);
    check("L1. privacy.html carries it once, as built", FILES.privacy.split(esc(PRIVACY)).length === 2);
    const TERMS = "If you let BizForce change your store, you are responsible for the prices and stock levels you approve.";
    const ti = FILES.terms.indexOf(esc(TERMS)), li = FILES.terms.indexOf(esc(LP.CARD_LEADS_TERMS_SENTENCE || "~"));
    check("L2. the terms sentence is the decided one, built into terms.html once, right after the card leads sentence",
      LP.STORE_TERMS_SENTENCE === TERMS && FILES.terms.split(esc(TERMS)).length === 2 && li !== -1 && ti > li &&
      /^<\/p>\s*<p>$/.test(FILES.terms.slice(li + esc(LP.CARD_LEADS_TERMS_SENTENCE).length, ti)));
    const LINE = "BizForce reads your store. It changes a price or stock level only when you approve that change, and only if you allowed changes when you connected.";
    check("L3. the Store page says the decided line, and no longer \"BizForce only reads your store.\"", FILES.page.indexOf(LINE) !== -1 && FILES.page.indexOf("BizForce only reads your store.") === -1);
    /* NAMED (Nov 7 2026, Shopify on OAuth, migration 176): BEFORE one opt-in box, shown for WooCommerce only. AFTER each platform
       has its own box with the same words, unticked: WooCommerce's inside its section (hidden unless WooCommerce is chosen, and
       cleared when another is), and Shopify's sent as allow_changes to /api/store/shopify/start. */
    check("L3. each platform has its own opt-in box, unticked, with the decided words, and each sends allow_changes exactly true or false",
      FILES.page.indexOf("<input type=\"checkbox\" id=\"storeAllowChanges\" /> Let BizForce make changes I approve (prices and stock)</label>") !== -1 &&
      FILES.page.indexOf("<input type=\"checkbox\" id=\"storeShopifyAllow\" /> Let BizForce make changes I approve (prices and stock)</label>") !== -1 &&
      !/id="(storeAllowChanges|storeShopifyAllow)"[^>]*checked/.test(FILES.page) && FILES.ui.indexOf("byId(\"storeWooSection\").hidden = p !== \"woocommerce\";") !== -1 &&
      FILES.ui.indexOf("if (p !== \"woocommerce\") byId(\"storeAllowChanges\").checked = false;") !== -1 &&
      FILES.ui.indexOf("allow_changes: byId(\"storeAllowChanges\").checked === true") !== -1 && FILES.ui.indexOf("allow_changes: byId(\"storeShopifyAllow\").checked === true") !== -1);
    check("L3. each connection is labelled \"Read only\" or \"Changes allowed with your approval\"",
      FILES.ui.indexOf("var PERMISSION_LABEL = { read: \"Read only\", read_write: \"Changes allowed with your approval\" };") !== -1);
    check("L3. a Store changes section, and the page script loaded before store-connect.js",
      FILES.page.indexOf("id=\"storeChangesCard\"") !== -1 && FILES.page.indexOf("<div id=\"storeChanges\"") !== -1 &&
      FILES.page.indexOf("<script src=\"/scripts/store-changes.js\"></script>") !== -1 &&
      FILES.page.indexOf("<script src=\"/scripts/store-changes.js\"></script>") < FILES.page.indexOf("<script src=\"/scripts/store-connect.js\"></script>"));
    const codeOnly = FILES.changesUi.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
    check("L4. scripts/store-changes.js sets no innerHTML, outerHTML or insertAdjacentHTML, and writes no document",
      !/\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write/.test(codeOnly));

    // the page script, run against a small DOM
    const RW = uuid(), RO = uuid(), CHG = uuid();
    const HOSTILE = "<img src=x onerror=alert(1)>";
    const page = loadPageScript(function (method, p, body) {
      if (method === "GET" && p === "/api/store/connections") return { status: 200, data: { connections: [
        { id: RW, platform: "woocommerce", permission: "read_write", status: "connected" }, { id: RO, platform: "woocommerce", permission: "read", status: "connected" }] } };
      if (method === "GET" && p.indexOf("/api/store/changes") === 0) return { status: 200, data: { changes: [{ id: CHG, item_name: HOSTILE, field: "price", old_value: "19.99", new_value: "24.00", executed_at: "2026-11-06T10:00:00.000Z" }], has_more: false } };
      if (method === "POST" && p === "/api/store/changes/" + CHG + "/undo") return { status: 201, data: { note: M.filed } };
      if (method === "POST" && p === "/api/store/changes/propose") return { status: 201, data: { note: M.filed, echo: body } };
      return null;
    });
    const SC = page.win.bfStoreChanges;
    const box = new El("div");
    SC.renderLog(box, null);
    await flush();
    const entry = find(box, function (e) { return /store-change-what/.test(e.className); })[0];
    check("L5. the log shows a hostile item name as text, and no innerHTML is ever set",
      !!entry && entry.textContent === HOSTILE + ": price 19.99 to 24.00" && HTML_SET.length === 0, entry && entry.textContent);
    const button = function (root, label) { return find(root, function (e) { return e.tagName === "BUTTON" && e.textContent === label; })[0]; };
    const undoBtn = button(box, "Undo"), yes = button(box, "Yes, propose changing it back");
    const postsBefore = page.calls.filter(function (c) { return c.method === "POST"; }).length;
    if (undoBtn) undoBtn.click();
    await flush();
    const afterFirst = page.calls.filter(function (c) { return c.method === "POST"; }).length;
    check("L5. Undo asks first: the first press sends nothing and shows \"Yes, propose changing it back\"",
      !!undoBtn && !!yes && afterFirst === postsBefore && yes.hidden === false);
    if (yes) yes.click();
    await flush();
    const undoPosts = page.calls.filter(function (c) { return c.method === "POST" && /\/undo$/.test(c.url); });
    check("L5. confirming sends one POST /api/store/changes/:id/undo", undoPosts.length === 1 && undoPosts[0].url.indexOf("/api/store/changes/" + CHG + "/undo") !== -1);

    const list = new El("div");
    const slotRw = list.appendChild(new El("div")); slotRw.setAttribute("data-store-item", "item-rw"); slotRw.setAttribute("data-store-conn", RW); slotRw.setAttribute("data-store-price", "19.99");
    const slotRo = list.appendChild(new El("div")); slotRo.setAttribute("data-store-item", "item-ro"); slotRo.setAttribute("data-store-conn", RO); slotRo.setAttribute("data-store-price", "5");
    SC.reset();
    SC.decorateInventory(list);
    await flush();
    check("L6. a read-only row says \"Read only: reconnect with changes allowed to propose changes\", with no control",
      slotRo.textContent === "Read only: reconnect with changes allowed to propose changes" && !button(slotRo, "Propose a change"));
    const openBtn = button(slotRw, "Propose a change"), send = button(slotRw, "Propose");
    const input = find(slotRw, function (e) { return e.tagName === "INPUT"; })[0];
    check("L6. a writable row offers \"Propose a change\", pre-filled with the price", !!openBtn && !!send && !!input && input.value === "19.99");
    if (input) input.value = "24";
    if (send) send.click();
    await flush();
    const proposed = page.calls.filter(function (c) { return c.method === "POST" && /\/api\/store\/changes\/propose$/.test(c.url); });
    check("L6. Propose sends { item_id, field, to } to POST /api/store/changes/propose, and nothing else changes",
      proposed.length === 1 && J(proposed[0].body) === J({ item_id: "item-rw", field: "price", to: "24" }) && HTML_SET.length === 0);
    check("L7. the inventory page leaves a slot on synced rows, loads the script, and makes store fields read-only",
      FILES.inventory.indexOf("<div class=\"iv-store-slot\" data-store-item=\"' + id + '\" data-store-conn=\"' + escapeHtml(it.store_connection_id || \"\") +") !== -1 &&
      FILES.inventory.indexOf("<script src=\"/scripts/store-changes.js\"></script>") !== -1 &&
      FILES.inventory.indexOf("input.title = on ? \"This comes from your store. Change it in your store, or propose a change.\" : \"\";") !== -1);

    // the Approvals card, run from proposals.html's own functions
    const fns = ["escapeHtml", "storeChangeText", "storeChangePayloadFields"].map(function (n) { return fnSource(FILES.proposals, n); });
    let card = "";
    try {
      const cx = { String: String };
      vm.createContext(cx);
      vm.runInContext(fns.join("\n"), cx);
      card = cx.storeChangePayloadFields({ item_name: HOSTILE, field: "price", from: "19.99", to: "24.00" });
    } catch (e) { card = "error: " + e.message; }
    check("L8. the Approvals card says \"Change <item> price in your store from 19.99 to 24.00\", escaped",
      card.indexOf("Change &lt;img src=x onerror=alert(1)&gt; price in your store from 19.99 to 24.00") !== -1 && card.indexOf("<img") === -1, card.slice(0, 200));
    check("L8. the card is wired for update_store_item, payload and result",
      FILES.proposals.indexOf("} else if (p.action_type === \"update_store_item\") {\n        fieldsHtml = storeChangePayloadFields(p.payload || {});") !== -1 &&
      /p\.action_type === "update_store_item" && p\.execution_result[^\n]*\n\s*execHtml = storeChangeResultHtml\(p\.execution_result\);/.test(FILES.proposals));
    const EMOJI = /[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}\u{FE0F}]/u;
    check("L9. no emoji in the new files", [FILES.write, FILES.migration, FILES.changesUi, fs.readFileSync(__filename, "utf8")].every(function (t) { return !EMOJI.test(t); }));
  }

  check("N. nothing reached the network: no socket, no real DNS, no fetch", TRIPPED.length === 0, TRIPPED.join(", "));
  check("N. no unhandled rejection", UNHANDLED.length === 0, UNHANDLED.map(function (e) { return e && e.message; }).join(" | "));
  console.log("\n" + passes + " passed, " + failures + " failed");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
})().catch(function (e) { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
