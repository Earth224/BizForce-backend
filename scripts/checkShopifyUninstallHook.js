/* checkShopifyUninstallHook: app/uninstalled, subscribed per shop through the Admin API (W-T4, migration 185).

   WHY. The app keeps use_legacy_install_flow = true, and Shopify refuses app-specific webhook subscriptions in
   shopify.app.toml with that flow, so lib/shopifyUninstallHook.js subscribes each connected shop to APP_UNINSTALLED
   (GraphQL 2026-07: the input field is uri; format JSON), after the connect and on later syncs until
   member_store_connections.uninstall_hook_at is set.

   WHAT IT PROVES. server.js's store section (the connect, the sync-now route, storeSyncDeps and the address) runs from
   its own source in a vm; lib/storeSync.js, lib/shopifyApi.js and lib/shopifyUninstallHook.js are compiled from
   source. The shop is a fake GraphQL endpoint behind deps.jsonRequest that keeps its own webhook subscriptions and
   checks the access token. The database is in memory and returns only the columns asked for. Nothing here calls
   Shopify or the live database.

     A. A NEW CONNECT answers first, then creates exactly one APP_UNINSTALLED subscription with uri = the address and
        format JSON, and stamps uninstall_hook_at; the Store tab's connection does not carry the stamp.
     B. AN EXISTING CORRECT subscription is left alone: no mutation is sent; the stamp is set.
     C. A BizForce subscription with an OLD ADDRESS is updated to the address, not duplicated.
     D. AN UNRELATED ADDRESS is never touched; ours is created beside it.
     E. A userError, a network failure and a 500: the connect's answer is unchanged and uninstall_hook_at stays null.
     F. THE SYNC (the sync-now route and the 05:00 pass) retries a null stamp and sets it; a row with the stamp is never
        asked again; a failed attempt leaves it null and does not fail the sync.
     G. THE ADDRESS is STORE_API_BASE + "/api/webhooks/shopify" (RAILWAY_PUBLIC_DOMAIN, else the Railway address).
     H. "mutation" still appears in lib/shopifyApi.js only inside writePrice and writeStock.
     I. No token or secret reaches any log line.
     R. Migration 185 is the highest, and adds only uninstall_hook_at.

   MUTATIONS: MUTATE=<name> applies one in memory; MUTATE=all runs each in its own process. */
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const crypto = require("crypto");
const Module = require("module");
const MUT = require("./_shared");

const REPO = path.join(__dirname, "..");
const read = (f) => fs.readFileSync(path.join(REPO, f), "utf8").replace(/\r\n/g, "\n");

const ROUTE_ANSWER = "      res.json({ saved: true, connection: ss.statusOf(saved.data), locations: info.locations.length,\n";
const MUTATIONS = {
  "exists-recreated": ["hook",
    "    if (nodes.some(function (n) { return n.uri === address; })) return { ok: true, action: \"exists\" };\n", ""],
  "create-callbackUrl": ["hook",
    "    var input = { uri: address, format: \"JSON\" };", "    var input = { callbackUrl: address, format: \"JSON\" };"],
  "format-dropped": ["hook",
    "    var input = { uri: address, format: \"JSON\" };", "    var input = { uri: address };"],
  "update-unrelated": ["hook",
    "  if (!host) return false;\n  return host === hostOf(address) ||", "  if (!host) return false;\n  return true ||"],
  "old-address-created": ["hook",
    "    var ours = nodes.filter(function (n) { return isBizforceUri(n.uri, address); })[0];", "    var ours = null;"],
  "user-error-ok": ["hook",
    "  if (Array.isArray(payload.userErrors) && payload.userErrors.length) return { ok: false, code: \"user_error\" };",
    "  if (Array.isArray(payload.userErrors) && payload.userErrors.length) return { ok: true };"],
  "network-ok": ["hook",
    "    return { ok: false, code: NOT_SENT.indexOf(g) !== -1 ? \"not_sent\" : \"unconfirmed\" };", "    return { ok: true };"],
  // The catch runs before the finally that drops the token, so this is where a careless code would carry it.
  "token-in-code": ["hook",
    "    return { ok: false, code: NOT_SENT.indexOf(g) !== -1 ? \"not_sent\" : \"unconfirmed\" };", "    return { ok: false, code: \"unconfirmed \" + token };"],
  "connect-not-recorded": ["hook",
    "    var saved = await deps.supabase.from(\"member_store_connections\").update({ uninstall_hook_at: stamp })",
    "    var saved = await deps.supabase.from(\"member_store_connections\").select(\"id\")"],
  "hook-before-answer": ["server", ROUTE_ANSWER,
    "      await require(\"./lib/shopifyUninstallHook\").recordUninstallWebhook(storeSyncDeps(), Object.assign({}, row, { id: saved.data.id }), SHOPIFY_WEBHOOK_ADDRESS);\n" + ROUTE_ANSWER],
  "hook-failure-fails-connect": ["server", ROUTE_ANSWER,
    "      var hk = await require(\"./lib/shopifyUninstallHook\").recordUninstallWebhook(storeSyncDeps(), Object.assign({}, row, { id: saved.data.id }), SHOPIFY_WEBHOOK_ADDRESS);\n" +
    "      if (!hk.ok) return res.status(502).json({ saved: false, code: hk.code });\n" + ROUTE_ANSWER],
  "address-wrong": ["server",
    "const SHOPIFY_WEBHOOK_ADDRESS = STORE_API_BASE + \"/api/webhooks/shopify\";", "const SHOPIFY_WEBHOOK_ADDRESS = STORE_API_BASE + \"/api/webhook\";"],
  "sync-not-wired": ["server", "    shopifyHook: require(\"./lib/shopifyUninstallHook\"),\n", ""],
  "status-exposes-hook": ["server",
    "marketplace_id, region, created_at, last_sync_at, last_error_code\";", "marketplace_id, region, created_at, last_sync_at, last_error_code, uninstall_hook_at\";"],
  "sync-every-time": ["sync", "if (!conn.uninstall_hook_at && deps.shopifyHook", "if (deps.shopifyHook"],
  "sync-stamp-on-failure": ["sync", "    if (hooked && hooked.ok) finished.uninstall_hook_at = stamp;", "    if (hooked) finished.uninstall_hook_at = stamp;"],
  "sync-columns-missing": ["sync",
    "  \"marketplace_id, region, \" +\n  // Shopify (W-T4, migration 185): when app/uninstalled was confirmed subscribed on the shop; null means ask again.\n  \"uninstall_hook_at\";",
    "  \"marketplace_id, region\";"],
  "mutation-in-api": ["api", "var PAGE_SIZE = 50;", "var PAGE_SIZE = 50; var TOUCH = \"mutation Touch { shop { id } }\";"]
};
const NAMES = Object.keys(MUTATIONS);
const MUTATE = process.env.MUTATE || "";
if (MUTATE === "all") MUT.runAllMutations(__filename, NAMES);
if (MUTATE && MUTATE !== "all" && NAMES.indexOf(MUTATE) === -1) { console.error("Unknown MUTATE=" + MUTATE + ". Known: " + NAMES.join(", ")); process.exit(2); }

/* Every console line from the code under test is kept (I checks it); this check's own lines go to stdout directly. */
const LOGS = [];
const say = function (s) { process.stdout.write(s + "\n"); };
["log", "warn", "error", "info"].forEach(function (k) { console[k] = function () { LOGS.push([].slice.call(arguments).map(String).join(" ")); }; });

let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; say("    pass  " + label); }
  else { failures++; say("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}
const UNHANDLED = [];
process.on("unhandledRejection", function (e) { UNHANDLED.push(e); });

const FILES = {
  server: read("server.js"),
  hook: read("lib/shopifyUninstallHook.js"),
  sync: read("lib/storeSync.js"),
  api: read("lib/shopifyApi.js"),
  auth: read("lib/shopifyAuth.js")
};
if (MUTATE && MUTATE !== "all") {
  const m = MUTATIONS[MUTATE];
  FILES[m[0]] = MUT.replaceOnce(FILES[m[0]], m[1], m[2], MUTATE);
  say("\n!! MUTATION: " + MUTATE);
}

const J = JSON.stringify;
const SECRET_HEX = crypto.createHash("sha256").update("checkShopifyUninstallHook").digest("hex");
process.env.ENCRYPTION_SECRET = SECRET_HEX;
const realRequire = Module.createRequire(path.join(REPO, "server.js"));
const CRYPT = realRequire("./lib/apiKeyCrypto");
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
const HOOK = compile(FILES.hook, "lib/shopifyUninstallHook.js", { "./shopifyApi": SAPI });

const CLIENT_SECRET = "check-client-secret-" + "9".repeat(20);
const CONFIGURED = { SHOPIFY_CLIENT_ID: "check-client-id", SHOPIFY_CLIENT_SECRET: CLIENT_SECRET, ENCRYPTION_SECRET: SECRET_HEX };
const USER = "00000000-0000-4000-8000-000000000001";
const SHOP = "demo-shop.myshopify.com";
const TOKEN = "shpca_" + "a1b2c3d4".repeat(4);
const REFRESH = "shprt_" + "e5f6a7b8".repeat(4);
const CODE = "0123abcd".repeat(4);
const ADDRESS = "https://dynamic-prosperity-production-5382.up.railway.app/api/webhooks/shopify";
const OLD_ADDRESS = "https://dynamic-prosperity-staging-1.up.railway.app/api/webhooks/shopify";
const UNRELATED = "https://hooks.example.test/shopify/uninstalled";
const GRAPHQL_PATH = "/admin/api/2026-07/graphql.json";
const READ_SCOPES = "read_products,read_inventory,read_orders,read_locations";
const SECRETS = [TOKEN, REFRESH, CODE, CLIENT_SECRET, SECRET_HEX];
const EMOJI = /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{1F000}-\u{1F2FF}\u{FE0F}]/u;
function uuid() { return crypto.randomUUID(); }

/* ── an in-memory database: only the columns asked for come back ─────────── */
function makeDb() {
  const t = { member_store_connections: [], oauth_states: [], inventory_items: [], store_order_summaries: [], store_change_log: [], notifications: [], job_runs: [] };
  function project(r, cols) {
    if (!cols || cols.trim() === "*") return JSON.parse(J(r));
    const o = {};
    cols.split(",").map(function (c) { return c.trim(); }).filter(Boolean).forEach(function (c) { o[c] = r[c] === undefined ? null : JSON.parse(J(r[c])); });
    return o;
  }
  function from(name) {
    if (!t[name]) t[name] = [];
    const q = { op: null, cols: null, filters: [], payload: null, single: null, returning: false, conflict: null, range: null, limit: null };
    const api = {
      select: function (cols) { if (!q.op) q.op = "select"; else q.returning = true; q.cols = cols; return api; },
      insert: function (p) { q.op = "insert"; q.payload = p; return api; },
      update: function (p) { q.op = "update"; q.payload = p; return api; },
      upsert: function (p, o) { q.op = "upsert"; q.payload = p; q.conflict = (o && o.onConflict) || null; return api; },
      delete: function () { q.op = "delete"; return api; },
      eq: function (c, v) { q.filters.push(["eq", c, v]); return api; },
      neq: function (c, v) { q.filters.push(["neq", c, v]); return api; },
      in: function (c, v) { q.filters.push(["in", c, v]); return api; },
      is: function (c, v) { q.filters.push(["is", c, v]); return api; },
      lt: function (c, v) { q.filters.push(["lt", c, v]); return api; },
      gt: function (c, v) { q.filters.push(["gt", c, v]); return api; },
      order: function () { return api; },
      range: function (a, b) { q.range = [a, b]; return api; },
      limit: function (n) { q.limit = n; return api; },
      maybeSingle: function () { q.single = "maybe"; return api; },
      single: function () { q.single = "one"; return api; },
      then: function (ok, bad) { return Promise.resolve().then(run).then(ok, bad); }
    };
    function match(r) {
      return q.filters.every(function (f) {
        const v = r[f[1]];
        if (f[0] === "eq") return v != null && String(v) === String(f[2]);
        if (f[0] === "neq") return v != null && String(v) !== String(f[2]);
        if (f[0] === "in") return v != null && f[2].map(String).indexOf(String(v)) !== -1;
        if (f[0] === "is") return f[2] === null ? v == null : v === f[2];
        if (f[0] === "lt") return v != null && String(v) < String(f[2]);
        if (f[0] === "gt") return v != null && String(v) > String(f[2]);
        throw new Error("fake db: filter " + f[0]);
      });
    }
    function shape(list) {
      const data = list.map(function (r) { return project(r, q.cols); });
      if (q.single === "maybe") return { data: data[0] || null, error: null };
      if (q.single === "one") return data.length === 1 ? { data: data[0], error: null } : { data: null, error: { code: "PGRST116" } };
      return { data: q.op === "select" || q.returning ? data : null, error: null };
    }
    function run() {
      const rows = t[name];
      if (q.op === "select") {
        let hit = rows.filter(match);
        if (q.range) hit = hit.slice(q.range[0], q.range[1] + 1);
        if (q.limit !== null) hit = hit.slice(0, q.limit);
        return shape(hit);
      }
      if (q.op === "insert") {
        const made = (Array.isArray(q.payload) ? q.payload : [q.payload]).map(function (p) { return Object.assign({ id: uuid() }, JSON.parse(J(p))); });
        made.forEach(function (r) { rows.push(r); });
        return shape(made);
      }
      if (q.op === "upsert") {
        const keys = String(q.conflict || "id").split(",").map(function (s) { return s.trim(); });
        const out = (Array.isArray(q.payload) ? q.payload : [q.payload]).map(function (p) {
          const v = JSON.parse(J(p));
          const old = rows.filter(function (r) { return keys.every(function (k) { return String(r[k]) === String(v[k]); }); })[0];
          if (old) { Object.assign(old, v); return old; }
          const made = Object.assign({ id: uuid(), uninstall_hook_at: null, created_at: new Date().toISOString() }, v);
          rows.push(made); return made;
        });
        return shape(out);
      }
      if (q.op === "update") {
        const hit = rows.filter(match);
        hit.forEach(function (r) { Object.assign(r, JSON.parse(J(q.payload))); });
        return shape(hit);
      }
      if (q.op === "delete") {
        const hit = rows.filter(match);
        t[name] = rows.filter(function (r) { return hit.indexOf(r) === -1; });
        return shape(hit);
      }
      return { data: null, error: { message: "fake: no op" } };
    }
    return api;
  }
  return { from: from, t: t };
}

/* ── the shop: a fake GraphQL endpoint with its own webhook subscriptions ─── */
function makeShop(opts) {
  const o = Object.assign({ subs: [] }, opts || {});
  const subs = o.subs.map(function (s) { return Object.assign({}, s); });
  const calls = [];
  let next = 100;
  function ok(json) { return { status: 200, headers: {}, json: json }; }
  async function jsonRequest(url, options) {
    const u = new URL(url);
    const body = options && options.body ? JSON.parse(J(options.body)) : null;
    const m = body && typeof body.query === "string" ? /^(query|mutation)\s+([A-Za-z]+)/.exec(body.query) : null;
    const token = options && options.headers ? options.headers["X-Shopify-Access-Token"] : null;
    calls.push({ path: u.pathname, op: m ? m[2] : null, kind: m ? m[1] : null, body: body, token: token });
    if (u.hostname !== SHOP) return { status: 404, headers: {}, json: { error: "no such host" } };
    if (u.pathname === "/admin/oauth/access_token") {
      return ok({ access_token: TOKEN, refresh_token: REFRESH, expires_in: 86400, refresh_token_expires_in: 7776000, scope: READ_SCOPES });
    }
    if (u.pathname !== GRAPHQL_PATH || !m) return { status: 404, headers: {}, json: { error: "no stub" } };
    if (token !== TOKEN) return { status: 401, headers: {}, json: { errors: "[API] Invalid API key or access token" } };
    const op = m[2], v = body.variables || {};
    if (op === "ShopInfo") return ok({ data: { shop: { currencyCode: "CAD" }, locations: { nodes: [{ id: "gid://shopify/Location/71", name: "Main", isActive: true }] } } });
    if (op === "Variants" || op === "VariantsAt") return ok({ data: { productVariants: { pageInfo: { hasNextPage: false, endCursor: null }, nodes: [] } } });
    if (op === "Orders") return ok({ data: { orders: { pageInfo: { hasNextPage: false, endCursor: null }, nodes: [] } } });
    if (op === "UninstallHooks") {
      if (o.listError) return ok({ errors: [{ message: "Access denied for webhookSubscriptions field." }] });
      return ok({ data: { webhookSubscriptions: { edges: subs.map(function (s) { return { node: { id: s.id, topic: s.topic, uri: s.uri } }; }) } } });
    }
    if (op === "UninstallHookCreate" || op === "UninstallHookUpdate") {
      const field = op === "UninstallHookCreate" ? "webhookSubscriptionCreate" : "webhookSubscriptionUpdate";
      if (o.network) { const e = new Error("socket hang up"); e.guardedFetch = true; e.code = "network"; throw e; }
      if (o.status500) return { status: 500, headers: {}, json: { errors: "Internal error" } };
      const input = v.webhookSubscription || {};
      // 2026-07: uri is the address field; anything else is not an address here.
      if (o.userError || typeof input.uri !== "string" || !input.uri) {
        return ok({ data: { [field]: { webhookSubscription: null, userErrors: [{ field: ["webhookSubscription", "uri"], message: "Address for this topic has already been taken" }] } } });
      }
      let sub;
      if (op === "UninstallHookCreate") {
        sub = { id: "gid://shopify/WebhookSubscription/" + (next++), topic: v.topic, uri: input.uri, format: input.format || null };
        subs.push(sub);
      } else {
        sub = subs.filter(function (s) { return s.id === v.id; })[0];
        if (!sub) return ok({ data: { [field]: { webhookSubscription: null, userErrors: [{ field: ["id"], message: "Webhook subscription does not exist" }] } } });
        sub.uri = input.uri; sub.format = input.format || sub.format;
      }
      return ok({ data: { [field]: { webhookSubscription: { id: sub.id, uri: sub.uri }, userErrors: [] } } });
    }
    return ok({ errors: [{ message: "no stub for " + op }] });
  }
  function ops(name) { return calls.filter(function (c) { return c.op === name; }); }
  function mutations() { return calls.filter(function (c) { return c.kind === "mutation"; }); }
  return { jsonRequest: jsonRequest, calls: calls, subs: subs, opts: o, ops: ops, mutations: mutations };
}

/* ── server.js's store section, run from its own source ──────────────────── */
function sliceOf(src, start, end) {
  const a = src.indexOf(start), b = src.indexOf(end, a);
  return a === -1 || b === -1 ? "" : src.slice(a, b);
}
const STORE_SECTION = sliceOf(FILES.server, "/* ── Store connections (migrations 163, 175, 176; lib/storeSync.js) ──────────",
  "// The SEO writer used to answer in JSON, which meant embedding a whole HTML");
function requireAuth() {} function requireActiveSubscription() {}
function mount(opts) {
  opts = opts || {};
  const db = opts.db || makeDb();
  const shop = opts.shop || makeShop({});
  const routes = {};
  const ctx = {
    supabase: db,
    process: { env: Object.assign({}, CONFIGURED, opts.env || {}) },
    console: console,
    rateLimit: function (o) { return { limiter: o }; },
    express: { raw: function (o) { return { raw: o }; }, json: function (o) { return { json: o }; } },
    requireAuth: requireAuth, requireActiveSubscription: requireActiveSubscription,
    nowIso: function () { return new Date().toISOString(); },
    isValidUuid: function (v) { return /^[0-9a-f-]{36}$/.test(String(v)); },
    getUserPlan: async function () { return { active: true }; },
    dashboardTopCache: new Map(),
    FRONTEND_URL: "https://bizforceai.net",
    setTimeout: function (fn) { fn(); return 0; },
    setImmediate: setImmediate,
    Promise: Promise, Buffer: Buffer, URL: URL, Date: Date, JSON: JSON, Object: Object, Array: Array, String: String, Number: Number, Math: Math,
    require: function (r) {
      if (r === "./lib/storeSync") return SS;
      if (r === "./lib/apiKeyCrypto") return CRYPT;
      if (r === "./lib/guardedFetch") return { guardedJsonRequest: shop.jsonRequest };
      if (r === "./lib/shopifyApi") return SAPI;
      if (r === "./lib/shopifyAuth") return SA;
      if (r === "./lib/shopifyUninstallHook") return HOOK;
      return realRequire(r);
    },
    app: {}
  };
  ["get", "post", "put", "delete"].forEach(function (m) {
    ctx.app[m] = function (p) { const args = [].slice.call(arguments, 1); routes[m + " " + p] = { handler: args[args.length - 1] }; };
  });
  vm.createContext(ctx);
  vm.runInContext(STORE_SECTION, ctx, { filename: "server.js (store section)" });
  return { db: db, shop: shop, routes: routes, ctx: ctx };
}
async function hit(m, key, req) {
  const r = m.routes[key];
  const res = { statusCode: 200, body: undefined, opsAtAnswer: null, set: function () { return this; },
    status: function (c) { this.statusCode = c; return this; },
    json: function (b) { this.opsAtAnswer = m.shop.calls.filter(function (c) { return /^UninstallHook/.test(c.op || ""); }).length; this.body = JSON.parse(J(b)); return this; } };
  let err = null;
  try { await r.handler(Object.assign({ user: { id: USER }, body: {}, params: {} }, req), res, function (e) { err = e || new Error("next"); }); }
  catch (e) { err = e; res.statusCode = 599; }
  return { status: res.statusCode, body: res.body || {}, opsAtAnswer: res.opsAtAnswer, err: err };
}
function sign(params) {
  const message = Object.keys(params).filter(function (k) { return k !== "hmac"; }).sort().map(function (k) { return k + "=" + params[k]; }).join("&");
  return crypto.createHmac("sha256", CLIENT_SECRET).update(message, "utf8").digest("hex");
}
/* A connect from the callback on: a fresh state for this member and shop, then the finish route as Shopify sent it. */
async function connect(m) {
  const state = crypto.randomBytes(32).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  m.db.t.oauth_states.push({ id: uuid(), user_id: USER, purpose: SA.PURPOSE, state_hash: SA.stateHash(state), flow_context: { shop: SHOP, permission: "read" },
    consumed_at: null, expires_at: new Date(Date.now() + 600000).toISOString(), created_at: new Date().toISOString() });
  const p = { code: CODE, host: "ZGVtby1zaG9wLm15c2hvcGlmeS5jb20vYWRtaW4", shop: SHOP, state: state, timestamp: String(Math.floor(Date.now() / 1000)) };
  p.hmac = sign(p);
  return hit(m, "post /api/store/shopify/finish", { body: { params: p } });
}
async function settle() { for (let i = 0; i < 30; i++) await new Promise(function (r) { setImmediate(r); }); }
function row(m) { return m.db.t.member_store_connections.filter(function (r) { return r.store_url === SHOP; })[0]; }
function hookOps(m) { return m.shop.calls.filter(function (c) { return /^UninstallHook/.test(c.op || ""); }); }
async function syncNow(m) { return hit(m, "post /api/store/connections/:id/sync", { params: { id: row(m).id } }); }

(async function () {
  say("checkShopifyUninstallHook: W-T4, migration 185");
  check("server.js's store section was found and holds the connect, the sync route and the address",
    STORE_SECTION.indexOf("app.post(\"/api/store/shopify/finish\"") !== -1 && STORE_SECTION.indexOf("app.post(\"/api/store/connections/:id/sync\"") !== -1 &&
    STORE_SECTION.indexOf("const SHOPIFY_WEBHOOK_ADDRESS") !== -1);

  /* ── A ── */
  say("\n== A. a new connect ==");
  let m = mount({});
  const a = await connect(m);
  check("A1. the connect answers 200 saved:true", a.status === 200 && a.body.saved === true, J([a.status, a.body, a.err && String(a.err)]));
  check("A2. ... before anything was asked about the webhook (the subscription runs after the answer)", a.opsAtAnswer === 0, a.opsAtAnswer);
  await settle();
  const subsA = m.shop.subs.filter(function (s) { return s.topic === "APP_UNINSTALLED"; });
  check("A3. exactly one APP_UNINSTALLED subscription is created, with uri = the address and format JSON",
    subsA.length === 1 && subsA[0].uri === ADDRESS && subsA[0].format === "JSON" && m.shop.ops("UninstallHookCreate").length === 1, J(m.shop.subs));
  const create = m.shop.ops("UninstallHookCreate")[0];
  check("A4. the create is webhookSubscriptionCreate(topic: APP_UNINSTALLED, webhookSubscription: { uri, format }) with no callbackUrl, on the shop's 2026-07 graphql.json with the stored token",
    !!create && create.path === GRAPHQL_PATH && create.token === TOKEN && create.body.variables.topic === "APP_UNINSTALLED" &&
    J(Object.keys(create.body.variables.webhookSubscription).sort()) === J(["format", "uri"]) && /webhookSubscriptionCreate\(topic: \$topic, webhookSubscription: \$webhookSubscription\)/.test(create.body.query),
    create && J(create.body));
  check("A5. uninstall_hook_at is stamped on the row", typeof row(m).uninstall_hook_at === "string" && !isNaN(Date.parse(row(m).uninstall_hook_at)), row(m).uninstall_hook_at);
  check("A6. the connection the Store tab gets back does not carry uninstall_hook_at", a.body.connection && !("uninstall_hook_at" in a.body.connection), J(a.body.connection));
  const again = await connect(m);
  await settle();
  check("A7. connecting the same shop again: still exactly one subscription, no second create",
    again.status === 200 && m.shop.subs.length === 1 && m.shop.ops("UninstallHookCreate").length === 1, J(m.shop.subs));

  /* ── B ── */
  say("\n== B. an existing correct subscription ==");
  m = mount({ shop: makeShop({ subs: [{ id: "gid://shopify/WebhookSubscription/7", topic: "APP_UNINSTALLED", uri: ADDRESS, format: "JSON" }] }) });
  const b = await connect(m);
  await settle();
  check("B1. it is left alone: listed once, no mutation sent, still one subscription",
    b.status === 200 && m.shop.ops("UninstallHooks").length === 1 && m.shop.mutations().length === 0 && m.shop.subs.length === 1, J(hookOps(m).map(function (c) { return c.op; })));
  check("B2. ... and uninstall_hook_at is stamped", typeof row(m).uninstall_hook_at === "string");

  /* ── C ── */
  say("\n== C. a BizForce subscription with an old address ==");
  m = mount({ shop: makeShop({ subs: [{ id: "gid://shopify/WebhookSubscription/8", topic: "APP_UNINSTALLED", uri: OLD_ADDRESS, format: "JSON" }] }) });
  const c = await connect(m);
  await settle();
  check("C1. it is updated to the address (webhookSubscriptionUpdate on its id), not duplicated",
    c.status === 200 && m.shop.ops("UninstallHookUpdate").length === 1 && m.shop.ops("UninstallHookCreate").length === 0 &&
    m.shop.subs.length === 1 && m.shop.subs[0].id === "gid://shopify/WebhookSubscription/8" && m.shop.subs[0].uri === ADDRESS, J(m.shop.subs));
  check("C2. ... and uninstall_hook_at is stamped", typeof row(m).uninstall_hook_at === "string");
  check("C3. bizforceai.net counts as BizForce; another host does not",
    HOOK.isBizforceUri("https://api.bizforceai.net/api/webhooks/shopify", ADDRESS) && HOOK.isBizforceUri("https://bizforceai.net/x", ADDRESS) &&
    !HOOK.isBizforceUri(UNRELATED, ADDRESS) && !HOOK.isBizforceUri("https://bizforceai.net.evil.test/x", ADDRESS) && !HOOK.isBizforceUri("not a url", ADDRESS));

  /* ── D ── */
  say("\n== D. an unrelated address ==");
  m = mount({ shop: makeShop({ subs: [{ id: "gid://shopify/WebhookSubscription/9", topic: "APP_UNINSTALLED", uri: UNRELATED, format: "JSON" }] }) });
  const d = await connect(m);
  await settle();
  const unrelated = m.shop.subs.filter(function (s) { return s.id === "gid://shopify/WebhookSubscription/9"; })[0];
  check("D1. it is never touched (no update), and ours is created beside it",
    d.status === 200 && m.shop.ops("UninstallHookUpdate").length === 0 && unrelated && unrelated.uri === UNRELATED &&
    m.shop.subs.filter(function (s) { return s.uri === ADDRESS; }).length === 1, J(m.shop.subs));

  /* ── E ── */
  say("\n== E. a failure never changes the connect ==");
  const fresh = mount({});
  const baseline = await connect(fresh);
  await settle();
  const results = {};
  for (const mode of ["userError", "network", "status500", "listError"]) {
    const mm = mount({ shop: makeShop({ [mode]: true }) });
    const r = await connect(mm);
    await settle();
    results[mode] = { status: r.status, saved: r.body.saved, note: r.body.note, stamp: row(mm).uninstall_hook_at, subs: mm.shop.subs.length };
  }
  check("E1. a userError: the connect answers exactly what a clean connect answers, and uninstall_hook_at stays null",
    results.userError.status === 200 && results.userError.saved === true && results.userError.note === baseline.body.note && results.userError.stamp === null && results.userError.subs === 0,
    J(results.userError));
  check("E2. a network failure on the create: the same 200 saved:true, and uninstall_hook_at stays null",
    results.network.status === 200 && results.network.saved === true && results.network.stamp === null, J(results.network));
  check("E3. a 500 on the create: the same, and uninstall_hook_at stays null", results.status500.status === 200 && results.status500.saved === true && results.status500.stamp === null, J(results.status500));
  check("E4. a GraphQL error on the listing: the same, nothing created, and uninstall_hook_at stays null",
    results.listError.status === 200 && results.listError.saved === true && results.listError.stamp === null && results.listError.subs === 0, J(results.listError));
  check("E5. the failures were logged with a short code only", LOGS.some(function (l) { return /\[ShopifyHook\] connection [0-9a-f-]{36} not subscribed to app\/uninstalled: user_error /.test(l); }) &&
    LOGS.some(function (l) { return /not subscribed to app\/uninstalled: unconfirmed /.test(l); }) && LOGS.some(function (l) { return /not subscribed to app\/uninstalled: http_500 /.test(l); }),
    J(LOGS.filter(function (l) { return /ShopifyHook/.test(l); })));

  /* ── F ── */
  say("\n== F. the sync retries until it is recorded ==");
  m = mount({ shop: makeShop({ userError: true }) });
  await connect(m);
  await settle();
  check("F0. after a failed attempt at connect, uninstall_hook_at is null", row(m).uninstall_hook_at === null);
  const s1 = await syncNow(m);
  check("F1. a sync while it still fails: the sync itself succeeds, it asked once, and uninstall_hook_at stays null",
    s1.status === 200 && s1.body.synced && s1.body.synced.ok === true && row(m).uninstall_hook_at === null && m.shop.ops("UninstallHookCreate").length === 2,
    J([s1.status, s1.body, m.shop.ops("UninstallHookCreate").length]));
  m.shop.opts.userError = false;
  const s2 = await syncNow(m);
  check("F2. the next sync retries, creates exactly one subscription with uri = the address, and sets uninstall_hook_at",
    s2.status === 200 && m.shop.subs.length === 1 && m.shop.subs[0].uri === ADDRESS && typeof row(m).uninstall_hook_at === "string", J([s2.status, m.shop.subs, row(m).uninstall_hook_at]));
  const asked = hookOps(m).length, stamp = row(m).uninstall_hook_at;
  const s3 = await syncNow(m);
  const s4 = await syncNow(m);
  check("F3. later syncs never ask again: no listing, no mutation, the stamp unchanged",
    s3.status === 200 && s4.status === 200 && hookOps(m).length === asked && row(m).uninstall_hook_at === stamp, J([hookOps(m).length, asked]));
  check("F4. the sync result carries nothing about the webhook", s2.body.synced && !("uninstall_hook_at" in s2.body.synced) && J(s2.body).indexOf("Uninstall") === -1);
  // The 05:00 pass, through the same storeSyncDeps.
  const p = mount({ shop: makeShop({ network: true }) });
  await connect(p);
  await settle();
  p.shop.opts.network = false;
  const pass1 = await SS.runStoreSyncPass(p.ctx.storeSyncDeps());
  const afterPass = hookOps(p).length;
  const pass2 = await SS.runStoreSyncPass(p.ctx.storeSyncDeps());
  check("F5. the 05:00 pass (storeSyncDeps) does the same: it sets uninstall_hook_at once, and the next pass does not ask",
    pass1.synced === 1 && typeof row(p).uninstall_hook_at === "string" && p.shop.subs.length === 1 && pass2.synced === 1 && hookOps(p).length === afterPass,
    J([pass1, pass2, p.shop.subs]));
  const deps = p.ctx.storeSyncDeps();
  check("F6. storeSyncDeps hands the sync lib/shopifyUninstallHook.js and the address", deps.shopifyHook === HOOK && deps.shopifyWebhookAddress === ADDRESS, deps.shopifyWebhookAddress);
  check("F7. SYNC_COLUMNS reads uninstall_hook_at; STORE_STATUS_COLUMNS (what members see) does not",
    /\buninstall_hook_at\b/.test(SS.SYNC_COLUMNS) && !/uninstall_hook_at/.test(sliceOf(FILES.server, "const STORE_STATUS_COLUMNS = ", "\n")));

  /* ── G ── */
  say("\n== G. the address ==");
  const g = mount({ env: { RAILWAY_PUBLIC_DOMAIN: "bizforce-api.example.test" } });
  check("G1. it is STORE_API_BASE + \"/api/webhooks/shopify\": the Railway address by default, RAILWAY_PUBLIC_DOMAIN when it is set",
    mount({}).ctx.storeSyncDeps().shopifyWebhookAddress === ADDRESS && g.ctx.storeSyncDeps().shopifyWebhookAddress === "https://bizforce-api.example.test/api/webhooks/shopify");
  const gs = await connect(g);
  await settle();
  check("G2. ... and the connect subscribes that address", gs.status === 200 && g.shop.subs.length === 1 && g.shop.subs[0].uri === "https://bizforce-api.example.test/api/webhooks/shopify", J(g.shop.subs));
  check("G3. the route that receives it is the existing webhook route", FILES.server.indexOf("\"/api/webhooks/shopify\",\n  express.raw(") !== -1);

  /* ── H ── */
  say("\n== H. the read-only promise of lib/shopifyApi.js ==");
  const apiCode = FILES.api.replace(/\/\*[\s\S]*?\*\//g, function (s) { return s.replace(/[^\n]/g, " "); });
  function spanOf(name) { const i = apiCode.indexOf("async function " + name + "("); return i === -1 ? [-1, -1] : [i, MUT.braceMatch(apiCode, apiCode.indexOf(") {", i) + 2)]; }
  const spans = [spanOf("writePrice"), spanOf("writeStock")];
  const at = []; apiCode.replace(/\bmutation\b/g, function (w, i) { at.push(i); return w; });
  check("H1. \"mutation\" appears in lib/shopifyApi.js's code only inside writePrice and writeStock",
    at.length === 2 && at.every(function (i) { return spans.some(function (sp) { return sp[0] !== -1 && i > sp[0] && i < sp[1]; }); }), at.length);
  check("H2. the new documents live in lib/shopifyUninstallHook.js and use the 2026-07 field uri, never callbackUrl",
    /mutation UninstallHookCreate/.test(FILES.hook) && /mutation UninstallHookUpdate/.test(FILES.hook) && !/callbackUrl:/.test(FILES.hook.replace(/\/\*[\s\S]*?\*\//g, "")));

  /* ── I ── */
  say("\n== I. no secrets in logs ==");
  check("I1. no token, refresh token, code, client secret or encryption key in any log line (" + LOGS.length + " lines)",
    LOGS.length > 0 && LOGS.every(function (l) { return SECRETS.every(function (s) { return l.indexOf(s) === -1; }); }) &&
    LOGS.every(function (l) { return !/shpca_|shprt_/.test(l); }), J(LOGS.filter(function (l) { return /shpca_|shprt_/.test(l); }).slice(0, 3)));

  /* ── R ── */
  say("\n== R. migration 185 ==");
  const migDir = path.join(REPO, "supabase", "migrations");
  const migFiles = fs.readdirSync(migDir).filter(function (x) { return /^\d{3}_.*\.sql$/.test(x); });
  const highest = migFiles.map(function (x) { return Number(x.slice(0, 3)); }).reduce(function (x, y) { return Math.max(x, y); }, 0);
  const mig = read("supabase/migrations/185_shopify_uninstall_hook.sql");
  // NAMED (Nov 17 2026, TK1, migration 186): BEFORE 185 was the highest. AFTER only 186_member_videos_duration.sql is above it, by name;
  // "the highest" is checkTiktokPosting G15's.
  // NAMED (Nov 18 2026, BV1, migration 187): BEFORE 186 was the highest. AFTER 187_member_video_parts.sql is above it too, by name; "the highest" is checkYoutubeUploads G14's.
  check("R1. 185_shopify_uninstall_hook.sql is the only 185, only 186_member_videos_duration.sql and 187_member_video_parts.sql are above it (checkYoutubeUploads G14); its VERIFY query is verify/185_verify.sql",
    highest === 187 && migFiles.filter(function (x) { return /^185_/.test(x); }).join() === "185_shopify_uninstall_hook.sql" &&
    migFiles.filter(function (x) { return Number(x.slice(0, 3)) > 185; }).join() === "186_member_videos_duration.sql,187_member_video_parts.sql" &&
    fs.existsSync(path.join(migDir, "verify", "185_verify.sql")), highest);
  check("R2. migration 185 adds only uninstall_hook_at timestamptz NULL to member_store_connections, in BEGIN/COMMIT, and drops nothing",
    /ALTER TABLE public\.member_store_connections\n  ADD COLUMN IF NOT EXISTS uninstall_hook_at timestamptz NULL;/.test(mig) &&
    (mig.replace(/^--.*$/gm, "").match(/ADD COLUMN/g) || []).length === 1 && /\nBEGIN;\n/.test(mig) && /\nCOMMIT;\n?$/.test(mig) && !/\bDROP\b/i.test(mig.replace(/^--.*$/gm, "")));
  check("R3. no emoji in any file this change touches",
    [FILES.server, FILES.hook, FILES.sync, mig, fs.readFileSync(__filename, "utf8")].every(function (s) { return !EMOJI.test(s); }));

  await settle();
  check("no unhandled rejection", UNHANDLED.length === 0, UNHANDLED.map(String).join("; "));
  say("");
  if (failures) { say("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  say("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(function (e) { say("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
