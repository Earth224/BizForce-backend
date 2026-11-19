/* checkShopifyWebhooks: Shopify webhooks answer first, the retry sweep, the privacy requests and shop/redact (W2,
   migration 184).

   WHAT IT PROVES (POST /api/webhooks/shopify and its helpers in server.js, lib/shopifyWebhooks.js, the purge in
   lib/shopifyAuth.js, apiLimiter's skip, the admin data-request routes, the 04:45 UTC chain and the 5-minute sweep).
   The webhook section and the admin routes are run from server.js's own source in a vm; requests are signed with a
   real HMAC-SHA256 under the test client secret, over the raw body, built with crypto. The database is in memory and
   enforces the receipt's unique webhook_id. The owner's email goes to a recording stub of lib/opsAlert.js's sender.
   The limiter is the real express-rate-limit, on a real express app on 127.0.0.1, with server.js's own options.
   Nothing here calls Shopify, Resend or the live database.

     A. A bad, missing or foreign-secret HMAC: 401, nothing recorded, no work.
     B. ANSWER FIRST: app/uninstalled answers 200 before the removal starts (a held stub proves the order); processed_at
        only after the work; the connection ids recorded in request_details first. A receipt that cannot be written is 500.
     C. THE LIMITER: skips POST /api/webhooks/shopify only; another /api route is still limited.
     D. customers/data_request: request_details holds the customer id, the order ids (numbers and gids, as numeric
        strings) and the data request id, never the email, phone or name; a bad body is 200 with request_details null.
        The owner is emailed once with the orders BizForce holds in that shop, the deadline and the statement;
        owner_notified_at is set; a failed send leaves it null and the sweep sends again; no address, no email.
     E. customers/redact deletes only the named orders, only in that shop; again, it deletes nothing more.
     F. shop/redact anonymises that shop's update_store_item proposals, found through the ids an earlier
        app/uninstall recorded, and leaves other shops', other users' and other types' proposals alone; it deletes that
        shop's sign-in states only.
     G. THE SWEEP reprocesses an unprocessed receipt older than 2 minutes, skips processed and newer ones, and is
        single flight.
     H. THE PURGE: an unanswered data request is kept; an answered one goes 30 days after answered_at; an unprocessed
        receipt is never purged; other processed receipts go 30 days after receipt.
     I. A DUPLICATE webhook_id that was processed does nothing.
     J. THE REMINDER: once, at 23 days, for an unanswered request; claimed once a day through job_runs.
     K. THE ADMIN ROUTES: admin only; the list with deadlines; marking answered for data requests only.
     L. THE WIRING: the sweep every 5 minutes only when server.js is the program; the reminder in the 04:45 chain;
        lib/jobSchedules.js lists both.
     P. THE WORDS (W3): privacy.html's Shopify notice sentence is what lib/legalPages.js builds, its days are the purge's own,
        and it, lib/yourData.js and lib/backup.js state the purge rule and what a data request record holds.

   MUTATIONS: MUTATE=<name> applies one in memory; MUTATE=all runs each in its own process. */
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const http = require("http");
const crypto = require("crypto");
const Module = require("module");
const MUT = require("./_shared");

const REPO = path.join(__dirname, "..");
const read = (f) => fs.readFileSync(path.join(REPO, f), "utf8").replace(/\r\n/g, "\n");

const MUTATIONS = {
  "hmac-unchecked": ["server",
    "    if (!raw || !sa.webhookHmacValid(raw, req.get(\"X-Shopify-Hmac-Sha256\") || \"\", config.clientSecret)) {\n", "    if (!raw) {\n"],
  "work-before-answer": ["server",
    "      res.status(200).json({ received: true });\n      if (receipt) scheduleShopifyWebhookWork(receipt);\n",
    "      if (receipt) await shopifyWebhookWork(receipt);\n      res.status(200).json({ received: true });\n"],
  "insert-failure-answered-200": ["server",
    "        if (recorded.error.code !== \"23505\") throw recorded.error;\n",
    "        if (recorded.error.code !== \"23505\") return res.status(200).json({ received: true });\n"],
  "details-not-stored": ["server",
    "shop_domain: shop, request_details: details })", "shop_domain: shop, request_details: null })"],
  "limiter-no-skip": ["server",
    "  skip: function (req) { return req.method === \"POST\" && req.path === \"/api/webhooks/shopify\"; }\n", "  skip: function () { return false; }\n"],
  "limiter-skips-all-api": ["server",
    "  skip: function (req) { return req.method === \"POST\" && req.path === \"/api/webhooks/shopify\"; }\n", "  skip: function (req) { return /^\\/api\\//.test(req.path); }\n"],
  "details-keep-email": ["hooks",
    "return { customer_id: numericIdOf(customer.id, \"Customer\"), orders_requested:", "return { email: customer.email, phone: customer.phone, customer_id: numericIdOf(customer.id, \"Customer\"), orders_requested:"],
  "order-gid-ignored": ["hooks",
    "  var m = new RegExp(\"^gid://shopify/\" + type + \"/([0-9]{1,30})$\").exec(s);\n  return m ? m[1] : null;\n", "  return null;\n"],
  // NAMED (Nov 15 2026, W3): BEFORE "email-resent-when-notified" removed processData's `if (row.owner_notified_at) return` and D14 caught
  // it. AFTER retired: the claim below (update ... is("owner_notified_at", null)) refuses an already-notified row by itself, so
  // without the early return the outcome is the same (no email, processed_at set); D14 and D16 hold that, and
  // email-sent-twice-on-race is the mutation that removes the guard that matters.
  // NAMED (Nov 15 2026, W3): the first email now CLAIMS owner_notified_at before sending, so these two moved to the claim.
  "notified-not-recorded": ["hooks",
    "  var claim = await deps.supabase.from(TABLE).update({ owner_notified_at: claimedAt }).eq(\"id\", row.id).is(\"owner_notified_at\", null).select(\"id\");\n",
    "  var claim = { error: null, data: [{ id: row.id }] };\n"],
  "claim-not-released-on-failure": ["hooks",
    "      var released = await deps.supabase.from(TABLE).update({ owner_notified_at: null }).eq(\"id\", row.id).eq(\"owner_notified_at\", claimedAt);\n",
    "      var released = { error: null };\n"],
  "email-sent-twice-on-race": ["hooks",
    "update({ owner_notified_at: claimedAt }).eq(\"id\", row.id).is(\"owner_notified_at\", null).select(\"id\");", "update({ owner_notified_at: claimedAt }).eq(\"id\", row.id).select(\"id\");"],
  "reminded-at-on-failure": ["hooks",
    "    if (!(await sendRequestEmail(deps, to, row, true))) return { sent: false, reason: \"send_failed\" };\n", "    await sendRequestEmail(deps, to, row, true);\n"],
  "reminder-not-retried": ["hooks",
    "      .is(\"request_details->>reminded_at\", null).lte(\"received_at\", to)",
    "      .is(\"request_details->>reminded_at\", null).gte(\"received_at\", iso(startMs - (REMINDER_AFTER_DAYS + 1) * DAY_MS)).lte(\"received_at\", to)"],
  "unreadable-redact-not-alerted": ["hooks", "    await alertRedactUnreadable(deps, row);\n", ""],
  "alert-carries-details": ["hooks",
    "      error: \"Shop \" + row.shop_domain + \", receipt \" + row.id + \": no order ids", "      error: \"Shop \" + row.shop_domain + \", receipt \" + row.id + \" \" + JSON.stringify(row) + \": no order ids"],
  "email-without-page-link": ["hooks",
    "  lines.push(\"\", \"Open requests, and the button to mark this one answered: \" + REQUESTS_PAGE_URL,", "  lines.push(\"\", \"Open requests: the admin routes\","],
  "sweep-skips-unsent-email": ["hooks",
    "    if (ownerAddress(deps.env)) {\n", "    if (false) {\n"],
  "redact-every-shop": ["hooks",
    "delete().eq(\"platform\", \"shopify\").in(\"connection_id\", conns).in(\"external_id\", ids)", "delete().eq(\"platform\", \"shopify\").in(\"external_id\", ids)"],
  "redact-every-order": ["hooks",
    "delete().eq(\"platform\", \"shopify\").in(\"connection_id\", conns).in(\"external_id\", ids)", "delete().eq(\"platform\", \"shopify\").in(\"connection_id\", conns)"],
  "uninstall-ids-not-recorded": ["server",
    "  if (receiptId && connectionIds.length) await require(\"./lib/shopifyWebhooks\").recordConnectionIds(supabase, receiptId, connectionIds);\n", ""],
  "redact-every-proposal": ["hooks",
    "      .eq(\"action_type\", \"update_store_item\").in(\"payload->>connection_id\", ids).select(\"id\");", "      .eq(\"action_type\", \"update_store_item\").select(\"id\");"],
  "redact-other-types": ["hooks",
    "      .eq(\"action_type\", \"update_store_item\").in(\"payload->>connection_id\", ids).select(\"id\");", "      .in(\"payload->>connection_id\", ids).select(\"id\");"],
  "redact-keeps-status-lost": ["hooks",
    "update({ payload: REDACTED, execution_result: REDACTED, title: REDACTED_TITLE })", "update({ payload: REDACTED, execution_result: REDACTED, title: REDACTED_TITLE, status: \"rejected\" })"],
  "states-of-every-shop": ["hooks",
    ".eq(\"purpose\", \"store_shopify\").eq(\"flow_context->>shop\", row.shop_domain)", ".eq(\"purpose\", \"store_shopify\")"],
  "sweep-takes-processed": ["hooks",
    "select(ROW_COLUMNS).is(\"processed_at\", null).lt(\"received_at\", cutoff)", "select(ROW_COLUMNS).lt(\"received_at\", cutoff)"],
  "sweep-no-min-age": ["hooks",
    "select(ROW_COLUMNS).is(\"processed_at\", null).lt(\"received_at\", cutoff)", "select(ROW_COLUMNS).is(\"processed_at\", null)"],
  "sweep-not-single-flight": ["hooks",
    "  if (sweeping) return { skipped: \"running\" };\n", ""],
  "processed-on-failure": ["hooks",
    "    logError(deps, \"[ShopifyWebhooks] \" + row.topic + \" work failed: \"",
    "    await deps.supabase.from(TABLE).update({ processed_at: iso(nowOf(deps)) }).eq(\"id\", row.id);\n    logError(deps, \"[ShopifyWebhooks] \" + row.topic + \" work failed: \""],
  "purge-unanswered-request": ["auth",
    "      .neq(\"topic\", \"customers/data_request\").select(\"id\");", "      .select(\"id\");"],
  "purge-unprocessed": ["auth",
    "delete().lt(\"received_at\", cutoff).not(\"processed_at\", \"is\", null)\n", "delete().lt(\"received_at\", cutoff)\n"],
  "purge-answered-never": ["auth",
    "      .lt(\"answered_at\", cutoff).not(\"processed_at\", \"is\", null).select(\"id\");", "      .lt(\"answered_at\", \"1970-01-01T00:00:00.000Z\").not(\"processed_at\", \"is\", null).select(\"id\");"],
  "purge-answered-at-once": ["auth",
    "      .lt(\"answered_at\", cutoff).not(\"processed_at\", \"is\", null).select(\"id\");", "      .not(\"answered_at\", \"is\", null).not(\"processed_at\", \"is\", null).select(\"id\");"],
  "duplicate-reprocessed": ["server",
    "        if (before.data && before.data.processed_at) return res.status(200).json({ received: true, duplicate: true });\n", ""],
  // NAMED (Nov 15 2026, W3): the reminder now reads every unanswered, unreminded request 23 or more days old.
  "reminder-every-day": ["hooks",
    "      .is(\"request_details->>reminded_at\", null).lte(\"received_at\", to)", "      .lte(\"received_at\", to)"],
  "reminder-answered-too": ["hooks",
    ".eq(\"topic\", DATA_REQUEST).is(\"answered_at\", null)\n      .is(\"request_details->>reminded_at\", null)", ".eq(\"topic\", DATA_REQUEST)\n      .is(\"request_details->>reminded_at\", null)"],
  "admin-list-not-admin": ["server",
    "app.get(\"/api/admin/shopify-data-requests\", requireAuth, requireAdmin, ", "app.get(\"/api/admin/shopify-data-requests\", requireAuth, "],
  "answered-any-topic": ["hooks",
    ".update({ answered_at: iso(nowMs) }).eq(\"id\", id).eq(\"topic\", DATA_REQUEST).is(\"answered_at\", null)", ".update({ answered_at: iso(nowMs) }).eq(\"id\", id).is(\"answered_at\", null)"],
  "sweep-every-50-minutes": ["server",
    "shutdownControl.trackInterval(\"shopifyWebhookSweepTick\", setInterval(shopifyWebhookSweepTick, 300000));", "shutdownControl.trackInterval(\"shopifyWebhookSweepTick\", setInterval(shopifyWebhookSweepTick, 3000000));"],
  "reminder-off-chain": ["server",
    "        .then(shopifyDataRequestReminderTick);\n", ";\n"],
  // P (W3): the privacy sentence and the yourData / backup wording.
  "privacy-fields-dropped": ["legal",
    "\"the order ids it names and the request id, never the customer's name, email or phone number.\"", "\"the request id, never the customer's name, email or phone number.\""],
  "privacy-days-typed": ["legal",
    "Each notice is kept \" + days(noticeDays) + \"; a customer", "Each notice is kept 30 days; a customer"],
  "your-data-old-rule": ["yourData",
    "Each is kept 30 days; a customer data request is kept until 30 days \" +\n    \"after it is answered, and a notification not yet processed is kept until it is processed. A data", "Each is kept 30 days. \" +\n    \"A data"],
  "backup-old-rule": ["backup",
    "kept 30 days, a customer data request until 30 days after it is answered, one not yet processed until it is processed\"", "kept 30 days\""]
};
const NAMES = Object.keys(MUTATIONS);
const MUTATE = process.env.MUTATE || "";
if (MUTATE === "all") MUT.runAllMutations(__filename, NAMES);
if (MUTATE && MUTATE !== "all" && NAMES.indexOf(MUTATE) === -1) { console.error("Unknown MUTATE=" + MUTATE + ". Known: " + NAMES.join(", ")); process.exit(2); }

let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}
const UNHANDLED = [];
process.on("unhandledRejection", function (e) { UNHANDLED.push(e); });

const FILES = {
  server: read("server.js"),
  hooks: read("lib/shopifyWebhooks.js"),
  auth: read("lib/shopifyAuth.js"),
  jobs: read("lib/jobSchedules.js"),
  ops: read("lib/opsAlert.js"),
  legal: read("lib/legalPages.js"),
  yourData: read("lib/yourData.js"),
  backup: read("lib/backup.js")
};
if (MUTATE && MUTATE !== "all") {
  const m = MUTATIONS[MUTATE];
  FILES[m[0]] = MUT.replaceOnce(FILES[m[0]], m[1], m[2], MUTATE);
  console.log("\n!! MUTATION: " + MUTATE);
}

const J = JSON.stringify;
const realRequire = Module.createRequire(path.join(REPO, "server.js"));
function compile(src, file, map) {
  const m = { exports: {} };
  const fn = vm.compileFunction(src, ["module", "exports", "require", "__dirname", "__filename"], { filename: path.join(REPO, file) });
  const localRequire = Module.createRequire(path.join(REPO, file));
  fn(m, m.exports, function (r) { return Object.prototype.hasOwnProperty.call(map, r) ? map[r] : localRequire(r); }, path.dirname(path.join(REPO, file)), path.join(REPO, file));
  return m.exports;
}
const SS = realRequire("./lib/storeSync");
const SA = compile(FILES.auth, "lib/shopifyAuth.js", {});
const OPS_REAL = compile(FILES.ops, "lib/opsAlert.js", {});

/* The owner's email: lib/opsAlert.js's real recipient rule and sending address; the sender records instead of sending. */
const MAIL = { sent: [], fail: 0, calls: 0 };
const OPS = {
  opsAlertRecipient: OPS_REAL.opsAlertRecipient,
  FROM_EMAIL: OPS_REAL.FROM_EMAIL,
  resendSend: async function (message) {
    MAIL.calls++;
    if (MAIL.fail > 0) { MAIL.fail--; return { ok: false, error: "provider said no" }; }
    MAIL.sent.push(message);
    return { ok: true, id: "msg-" + MAIL.sent.length };
  }
};
function loadHooks() { return compile(FILES.hooks, "lib/shopifyWebhooks.js", { "./opsAlert": OPS }); }
let SW = loadHooks();

const SECRET = "check-webhook-secret-" + "5".repeat(20);
const CONFIGURED = { SHOPIFY_CLIENT_ID: "check-client-id", SHOPIFY_CLIENT_SECRET: SECRET, OPS_ALERT_EMAIL: "owner@example.test" };
const SHOP = "demo-shop.myshopify.com";
const OTHER_SHOP = "other-shop.myshopify.com";
const U1 = "00000000-0000-4000-8000-000000000001";
const U2 = "00000000-0000-4000-8000-000000000002";
const DAY = 86400000;
const EMOJI = /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{1F000}-\u{1F2FF}\u{FE0F}]/u;
function uuid() { return crypto.randomUUID(); }
function iso(ms) { return new Date(ms).toISOString(); }

/* ── an in-memory database ─────────────────────────────────────────────── */
function valueAt(r, col) {
  const m = /^([a-z_]+)->>([a-z_]+)$/.exec(col);
  if (!m) return r[col];
  const obj = r[m[1]];
  return obj && typeof obj === "object" && obj[m[2]] !== undefined && obj[m[2]] !== null ? String(obj[m[2]]) : null;
}
function makeDb() {
  const t = { shopify_webhook_events: [], member_store_connections: [], store_order_summaries: [], agent_proposals: [], oauth_states: [], job_runs: [] };
  const log = [];
  const db = { t: t, log: log, failInsert: null };
  function defaults(name, p) {
    const r = Object.assign({}, p);
    if (r.id === undefined) r.id = uuid();
    if (name === "shopify_webhook_events") {
      ["processed_at", "request_details", "answered_at", "owner_notified_at"].forEach(function (k) { if (r[k] === undefined) r[k] = null; });
      if (r.received_at === undefined) r.received_at = iso(Date.now());
    }
    return r;
  }
  function project(r, cols) {
    if (!cols || cols.trim() === "*") return JSON.parse(J(r));
    const o = {};
    cols.split(",").map(function (c) { return c.trim(); }).forEach(function (c) { o[c] = r[c] === undefined ? null : JSON.parse(J(r[c])); });
    return o;
  }
  db.from = function (name) {
    const q = { op: null, cols: null, filters: [], or: null, payload: null, single: null, returning: false, order: null, limit: null };
    const api = {
      select: function (cols) { if (!q.op) q.op = "select"; else q.returning = true; q.cols = cols; return api; },
      insert: function (p) { q.op = "insert"; q.payload = p; return api; },
      update: function (p) { q.op = "update"; q.payload = p; return api; },
      delete: function () { q.op = "delete"; return api; },
      eq: function (c, v) { q.filters.push(["eq", c, v]); return api; },
      neq: function (c, v) { q.filters.push(["neq", c, v]); return api; },
      in: function (c, v) { q.filters.push(["in", c, v]); return api; },
      is: function (c, v) { q.filters.push(["is", c, v]); return api; },
      not: function (c, op, v) { q.filters.push(["not_" + op, c, v]); return api; },
      lt: function (c, v) { q.filters.push(["lt", c, v]); return api; },
      lte: function (c, v) { q.filters.push(["lte", c, v]); return api; },
      gte: function (c, v) { q.filters.push(["gte", c, v]); return api; },
      or: function (s) { q.or = s; return api; },
      order: function (c, o) { q.order = [c, !(o && o.ascending === false)]; return api; },
      limit: function (n) { q.limit = n; return api; },
      maybeSingle: function () { q.single = "maybe"; return api; },
      single: function () { q.single = "one"; return api; },
      then: function (ok, bad) { return Promise.resolve().then(run).then(ok, bad); }
    };
    function match(r) {
      const all = q.filters.every(function (f) {
        const v = valueAt(r, f[1]);
        if (f[0] === "eq") return v != null && String(v) === String(f[2]);
        if (f[0] === "neq") return v != null && String(v) !== String(f[2]);
        if (f[0] === "in") return v != null && f[2].map(String).indexOf(String(v)) !== -1;
        if (f[0] === "is") return f[2] === null ? v == null : v === f[2];
        if (f[0] === "not_is") return f[2] === null ? v != null : v !== f[2];
        if (f[0] === "lt") return v != null && String(v) < String(f[2]);
        if (f[0] === "lte") return v != null && String(v) <= String(f[2]);
        if (f[0] === "gte") return v != null && String(v) >= String(f[2]);
        throw new Error("fake db: filter " + f[0]);
      });
      if (!all) return false;
      if (q.or) { const d = /neq\.(\d{4}-\d{2}-\d{2})/.exec(q.or)[1]; return r.last_run_on == null || r.last_run_on !== d; }
      return true;
    }
    function shape(list) {
      const data = list.map(function (r) { return project(r, q.cols); });
      if (q.single === "maybe") return { data: data[0] || null, error: null };
      if (q.single === "one") return data.length === 1 ? { data: data[0], error: null } : { data: null, error: { code: "PGRST116" } };
      return { data: q.op === "select" || q.returning ? data : null, error: null };
    }
    function run() {
      log.push({ table: name, op: q.op, filters: q.filters.slice(), payload: q.payload });
      const rows = t[name];
      if (!rows) return { data: null, error: { code: "42P01", message: "no table " + name } };
      if (q.op === "select") {
        let hit = rows.filter(match);
        if (q.order) { const c = q.order[0], asc = q.order[1]; hit = hit.slice().sort(function (a, b) { return (String(a[c]) < String(b[c]) ? -1 : String(a[c]) > String(b[c]) ? 1 : 0) * (asc ? 1 : -1); }); }
        if (q.limit !== null) hit = hit.slice(0, q.limit);
        return shape(hit);
      }
      if (q.op === "insert") {
        if (db.failInsert === name) return { data: null, error: { code: "08006", message: "connection lost" } };
        const list = Array.isArray(q.payload) ? q.payload : [q.payload];
        const made = [];
        for (const p of list) {
          const r = defaults(name, p);
          if (name === "shopify_webhook_events" && rows.some(function (x) { return x.webhook_id === r.webhook_id; })) return { data: null, error: { code: "23505" } };
          if (name === "job_runs" && rows.some(function (x) { return x.job_name === r.job_name; })) return { data: null, error: { code: "23505" } };
          made.push(r);
        }
        made.forEach(function (r) { rows.push(r); });
        return shape(made);
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
  };
  return db;
}

/* ── server.js's webhook section and admin routes, run from source ───────── */
function sliceOf(src, start, end) {
  const a = src.indexOf(start), b = src.indexOf(end, a);
  return a === -1 || b === -1 ? "" : src.slice(a, b);
}
const WEBHOOK_SECTION = sliceOf(FILES.server, "/* ── Shopify webhooks (migration 176, lib/shopifyAuth.js) ────────────────",
  "app.use(express.json({ limit: \"5mb\" }));");
const ADMIN_SECTION = sliceOf(FILES.server, "/* ── Shopify data requests, for the owner (W2, Nov 15 2026, migration 184) ──",
  "/* ── end of Shopify data requests ── */");
const LIMITER_DEF = sliceOf(FILES.server, "const apiLimiter = rateLimit({", "\nconst authLimiter");

function requireAuth() {} function requireAdmin() {}
function mount(opts) {
  opts = opts || {};
  const db = opts.db || makeDb();
  const logs = [];
  const events = [];
  const removals = [];
  const routes = {};
  // deleteConnectionData stands in for lib/storeSync.js's: it removes the connection and its order summaries, and can
  // be held (opts.hold) so a check can see what was answered before the removal ran.
  const gate = { open: !opts.hold, waiters: [] };
  const storeSync = {
    normalizeShopifyDomain: SS.normalizeShopifyDomain,
    deleteConnectionData: async function (supabase, userId, connectionId) {
      events.push("remove-start");
      if (opts.throwOnRemove) throw Object.assign(new Error("db down"), { code: "08006" });
      if (!gate.open) await new Promise(function (r) { gate.waiters.push(r); });
      removals.push(connectionId);
      const before = db.t.member_store_connections.length;
      db.t.member_store_connections = db.t.member_store_connections.filter(function (c) { return !(c.id === connectionId && c.user_id === userId); });
      db.t.store_order_summaries = db.t.store_order_summaries.filter(function (o) { return o.connection_id !== connectionId; });
      events.push("remove-done");
      return { removed: db.t.member_store_connections.length < before };
    }
  };
  const ctx = {
    supabase: db,
    process: { env: Object.assign({}, opts.env || CONFIGURED) },
    console: { log: function () { logs.push([].slice.call(arguments).join(" ")); }, error: function () { logs.push([].slice.call(arguments).join(" ")); } },
    express: { raw: function (o) { return { raw: o }; }, json: function (o) { return { json: o }; } },
    requireAuth: requireAuth, requireAdmin: requireAdmin,
    // W3: lib/opsAlert.js's raise, recording instead of emailing (server.js shopifyWebhookDeps hands it to the work).
    opsAlerts: { raise: async function (key, info) { ALERTS.push({ key: key, info: JSON.parse(J(info)) }); return { sent: true, reason: "sent" }; } },
    setImmediate: setImmediate, Date: Date, Buffer: Buffer, Promise: Promise, JSON: JSON, String: String, Object: Object, Array: Array, Number: Number,
    require: function (r) {
      if (r === "./lib/storeSync") return storeSync;
      if (r === "./lib/shopifyAuth") return SA;
      if (r === "./lib/shopifyWebhooks") return SW;
      if (r === "./lib/opsAlert") return OPS;
      return realRequire(r);
    },
    app: {}
  };
  ["get", "post"].forEach(function (m) {
    ctx.app[m] = function (p) { const args = [].slice.call(arguments, 1); routes[m + " " + p] = { middleware: args.slice(0, -1), handler: args[args.length - 1] }; };
  });
  vm.createContext(ctx);
  vm.runInContext(WEBHOOK_SECTION, ctx, { filename: "server.js (Shopify webhooks)" });
  vm.runInContext(ADMIN_SECTION, ctx, { filename: "server.js (Shopify data requests)" });
  return { db: db, logs: logs, events: events, removals: removals, routes: routes, ctx: ctx,
    release: function () { gate.open = true; gate.waiters.splice(0).forEach(function (r) { r(); }); } };
}
async function hit(m, key, req) {
  const r = m.routes[key];
  const res = { statusCode: 200, body: undefined, sent: 0, status: function (c) { this.statusCode = c; return this; },
    json: function (b) { this.sent++; m.events.push("answered:" + this.statusCode); this.body = JSON.parse(J(b)); return this; } };
  let err = null;
  try { await r.handler(Object.assign({ user: { id: U1, role: "admin" }, body: {}, params: {} }, req), res, function (e) { err = e || new Error("next"); }); }
  catch (e) { err = e; res.statusCode = 599; }
  return { status: res.statusCode, body: res.body || {}, sent: res.sent, err: err };
}
function webhook(m, topic, body, opts) {
  opts = opts || {};
  const raw = Buffer.from(body, "utf8");
  const h = {
    "x-shopify-topic": topic, "x-shopify-shop-domain": opts.shop || SHOP, "x-shopify-webhook-id": opts.id || uuid(),
    "x-shopify-hmac-sha256": opts.hmac !== undefined ? opts.hmac : crypto.createHmac("sha256", opts.secret || SECRET).update(opts.signed !== undefined ? Buffer.from(opts.signed, "utf8") : raw).digest("base64")
  };
  if (opts.hmac === null) delete h["x-shopify-hmac-sha256"];
  return hit(m, "post /api/webhooks/shopify", { body: raw, get: function (n) { const v = h[String(n).toLowerCase()]; return v === undefined ? undefined : v; } });
}
/* Lets the work scheduled with setImmediate, and every promise it chains, finish. */
async function settle() { for (let i = 0; i < 6; i++) await new Promise(function (r) { setImmediate(r); }); }
function receipt(db, webhookId) { return db.t.shopify_webhook_events.filter(function (e) { return e.webhook_id === webhookId; })[0]; }
function conn(db, user, shop) { const c = { id: uuid(), user_id: user, platform: "shopify", store_url: shop }; db.t.member_store_connections.push(c); return c; }
function order(db, c, externalId, extra) {
  const o = Object.assign({ id: uuid(), user_id: c.user_id, connection_id: c.id, platform: "shopify", external_id: externalId, ordered_at: "2026-10-01T10:00:00.000Z",
    total: 42.5, currency: "USD", status: "active", line_items: [{ sku: "HAT-1", quantity: 2 }] }, extra || {});
  db.t.store_order_summaries.push(o); return o;
}
const ALERTS = [];
function sweepDeps(m, nowMs) {
  return { supabase: m.db, env: m.ctx.process.env, now: function () { return nowMs; }, removeShopifyShop: m.ctx.removeShopifyShop, console: { error: function (l) { m.logs.push(l); } },
    raiseAlert: m.ctx.shopifyWebhookDeps().raiseAlert };
}
function resetMail() { MAIL.sent = []; MAIL.fail = 0; MAIL.calls = 0; }

/* ── the limiter: server.js's own options, on a real express app ────────── */
async function limiterProbe() {
  const express = realRequire("express");
  const rateLimit = realRequire("express-rate-limit");
  const ctx = { rateLimit: function (o) { return rateLimit(Object.assign({}, o, { max: 2 })); } };
  vm.createContext(ctx);
  vm.runInContext(LIMITER_DEF.replace("const apiLimiter", "this.apiLimiter"), ctx, { filename: "server.js (apiLimiter)" });
  const app = express();
  app.use(ctx.apiLimiter);
  app.post("/api/webhooks/shopify", function (req, res) { res.status(200).json({ ok: true }); });
  app.get("/api/store/connections", function (req, res) { res.status(200).json({ ok: true }); });
  const server = await new Promise(function (r) { const s = app.listen(0, "127.0.0.1", function () { r(s); }); });
  const port = server.address().port;
  function call(method, p) {
    return new Promise(function (resolve, reject) {
      const req = http.request({ host: "127.0.0.1", port: port, method: method, path: p, headers: { "content-type": "application/json" } }, function (res) { res.resume(); res.on("end", function () { resolve(res.statusCode); }); });
      req.on("error", reject); req.end(method === "POST" ? "{}" : undefined);
    });
  }
  const hooks = [], others = [];
  for (let i = 0; i < 5; i++) hooks.push(await call("POST", "/api/webhooks/shopify"));
  for (let i = 0; i < 4; i++) others.push(await call("GET", "/api/store/connections"));
  await new Promise(function (r) { server.close(r); });
  return { hooks: hooks, others: others };
}

(async function () {
  console.log("checkShopifyWebhooks: W2, migration 184");
  check("the webhook section, the admin routes and apiLimiter were found in server.js", WEBHOOK_SECTION.length > 1000 && ADMIN_SECTION.length > 300 && LIMITER_DEF.length > 50);

  /* ── A ── */
  console.log("\n== A. the HMAC ==");
  let m = mount({});
  conn(m.db, U1, SHOP);
  const body0 = "{\"id\":1,\"domain\":\"demo-shop.myshopify.com\"}";
  const a1 = await webhook(m, "app/uninstalled", body0, { signed: body0 + " " });
  const a2 = await webhook(m, "app/uninstalled", body0, { hmac: null });
  const a3 = await webhook(m, "app/uninstalled", body0, { secret: "another-secret" });
  await settle();
  check("A1. an HMAC over other bytes, none, or under another secret: 401 each, nothing recorded, no work run",
    a1.status === 401 && a2.status === 401 && a3.status === 401 && m.db.t.shopify_webhook_events.length === 0 && m.removals.length === 0 &&
    m.events.indexOf("remove-start") === -1, J([a1.status, a2.status, a3.status, m.db.t.shopify_webhook_events.length]));

  /* ── B ── */
  console.log("\n== B. answer first, work after ==");
  m = mount({ hold: true });
  const cB = conn(m.db, U1, SHOP);
  const keep = conn(m.db, U2, OTHER_SHOP);
  order(m.db, cB, "5001");
  const WID = "b-" + uuid();
  // A handler that waits for the held removal never answers: the race turns that into a failing check, not a hang.
  const b1 = await Promise.race([webhook(m, "app/uninstalled", body0, { id: WID }),
    new Promise(function (r) { setTimeout(function () { r({ status: "no answer within 2 s", body: {} }); }, 2000); })]);
  const atAnswer = { conns: m.db.t.member_store_connections.length, processed: receipt(m.db, WID) && receipt(m.db, WID).processed_at, events: m.events.slice() };
  check("B1. a valid app/uninstalled answers 200 while the shop's connection is still there and before the removal has started",
    b1.status === 200 && b1.body.received === true && atAnswer.conns === 2 && atAnswer.events[0] === "answered:200" && atAnswer.events.indexOf("remove-start") === -1,
    J([b1.status, atAnswer]));
  check("B2. at the answer the receipt is recorded and NOT yet processed", !!receipt(m.db, WID) && atAnswer.processed === null);
  await settle();
  check("B3. the removal starts after the answer and is held (the stub): still not processed", m.events.indexOf("remove-start") > m.events.indexOf("answered:200") &&
    receipt(m.db, WID).processed_at === null, J(m.events));
  check("B4. the connection id was recorded in the receipt's request_details before anything was removed",
    J(receipt(m.db, WID).request_details) === J({ connection_ids: [cB.id] }) && m.removals.length === 0);
  m.release();
  await settle();
  check("B5. once the removal finishes: the shop's connection and orders are gone, the other shop's kept, and processed_at is set",
    m.db.t.member_store_connections.length === 1 && m.db.t.member_store_connections[0] === keep && m.db.t.store_order_summaries.length === 0 &&
    typeof receipt(m.db, WID).processed_at === "string" && m.events.join(",") === "answered:200,remove-start,remove-done", J(m.events));
  m = mount({ throwOnRemove: true });
  conn(m.db, U1, SHOP);
  const WF = "f-" + uuid();
  const b6 = await webhook(m, "app/uninstalled", body0, { id: WF });
  await settle();
  check("B6. work that fails after the answer leaves processed_at null (for the sweep), and the answer was still 200",
    b6.status === 200 && receipt(m.db, WF).processed_at === null);
  m = mount({});
  m.db.failInsert = "shopify_webhook_events";
  conn(m.db, U1, SHOP);
  const b7 = await webhook(m, "app/uninstalled", body0);
  await settle();
  check("B7. a receipt that cannot be written: 500 (Shopify delivers again), and no work runs", b7.status === 500 && m.events.indexOf("remove-start") === -1, b7.status);

  /* ── C ── */
  console.log("\n== C. the rate limit ==");
  const lim = await limiterProbe();
  check("C1. apiLimiter (its max set to 2 here) never limits POST /api/webhooks/shopify: five deliveries, five 200s", J(lim.hooks) === J([200, 200, 200, 200, 200]), J(lim.hooks));
  check("C2. ... and still limits another /api route: the third request is 429", lim.others[0] === 200 && lim.others[1] === 200 && lim.others[2] === 429 && lim.others[3] === 429, J(lim.others));
  check("C3. app.use(apiLimiter) is still mounted before the webhook route, unchanged otherwise (300 per 15 minutes)",
    FILES.server.indexOf("app.use(apiLimiter);") !== -1 && FILES.server.indexOf("app.use(apiLimiter);") < FILES.server.indexOf("\"/api/webhooks/shopify\",\n  express.raw(") &&
    /windowMs: 15 \* 60 \* 1000,\n  max: 300,/.test(LIMITER_DEF));

  /* ── D ── */
  console.log("\n== D. customers/data_request ==");
  resetMail();
  m = mount({});
  const cD = conn(m.db, U1, SHOP);
  const cOther = conn(m.db, U2, OTHER_SHOP);
  order(m.db, cD, "450789469", { line_items: [{ sku: "HAT-1", quantity: 2 }, { sku: null, quantity: 1 }] });
  order(m.db, cD, "999");
  order(m.db, cOther, "690933842");
  const EMAIL = "jane." + "doe@example.test", PHONE = "555-0" + "142", FIRST = "Janeqz", LAST = "Doerqz";
  const drBody = J({ shop_id: 954889, shop_domain: SHOP, orders_requested: [450789469, "gid://shopify/Order/690933842", "nonsense"],
    customer: { id: 191167, email: EMAIL, phone: PHONE, first_name: FIRST, last_name: LAST }, data_request: { id: 9999 } });
  const DR = "dr-" + uuid();
  const d1 = await webhook(m, "customers/data_request", drBody, { id: DR });
  const atD = receipt(m.db, DR) ? JSON.parse(J(receipt(m.db, DR))) : null;
  check("D1. 200, and request_details is stored at the answer: customer id, order ids as numeric strings (a number and a gid), data request id",
    d1.status === 200 && atD && J(atD.request_details) === J({ customer_id: "191167", orders_requested: ["450789469", "690933842"], data_request_id: "9999" }),
    atD && J(atD.request_details));
  check("D2. the receipt holds NO email, phone or name", atD && [EMAIL, PHONE, FIRST, LAST].every(function (s) { return J(atD).indexOf(s) === -1; }), atD && J(atD));
  await settle();
  const recD = receipt(m.db, DR);
  check("D3. the owner is emailed once, at OPS_ALERT_EMAIL, from the ops alerts' address, and owner_notified_at and processed_at are set",
    MAIL.sent.length === 1 && J(MAIL.sent[0].to) === J(["owner@example.test"]) && MAIL.sent[0].from === OPS_REAL.FROM_EMAIL &&
    typeof recD.owner_notified_at === "string" && typeof recD.processed_at === "string", J([MAIL.sent.length, recD.owner_notified_at]));
  const mail = MAIL.sent[0] || { subject: "", text: "" };
  const deadline = iso(Date.parse(recD.received_at) + 30 * DAY);
  check("D4. the email names the shop, the data request id, the date received and the deadline (received + 30 days)",
    mail.subject.indexOf(SHOP) !== -1 && mail.subject.indexOf(deadline.slice(0, 10)) !== -1 && mail.text.indexOf("Data request id: 9999") !== -1 &&
    mail.text.indexOf("Received: " + recD.received_at) !== -1 && mail.text.indexOf("Deadline: " + deadline) !== -1, mail.subject);
  check("D5. it lists what BizForce holds for the requested orders in THAT shop only (order 450789469 with its items), not the other shop's 690933842, nor unrequested 999",
    mail.text.indexOf("order 450789469, placed 2026-10-01T10:00:00.000Z, total 42.5 USD, status active, line items: SKU HAT-1 x 2; SKU (none) x 1") !== -1 &&
    mail.text.indexOf("order 690933842") === -1 && mail.text.indexOf("order 999") === -1, mail.text);
  check("D6. the statement for the store owner says BizForce holds no customer names, emails, addresses or phone numbers and lists what it holds",
    mail.text.indexOf("BizForce holds no customer names, emails, addresses or phone numbers. For the orders in this request it holds only: order 450789469") !== -1);
  check("D7. the email is plain text, has no emoji, and carries no email, phone or name from the payload",
    !EMOJI.test(mail.subject + mail.text) && [EMAIL, PHONE, FIRST, LAST].every(function (s) { return (mail.subject + mail.text).indexOf(s) === -1; }) && mail.html === undefined);
  const d8 = await webhook(m, "customers/data_request", drBody, { id: DR });
  await settle();
  check("D8. the same delivery again: 200 duplicate, no second email", d8.body.duplicate === true && MAIL.sent.length === 1, J([d8.body, MAIL.sent.length]));
  const NONE = "dn-" + uuid();
  await webhook(m, "customers/data_request", J({ orders_requested: [12345], customer: { id: 5 }, data_request: { id: 77 } }), { id: NONE });
  await settle();
  const noneMail = MAIL.sent[1] || { text: "" };
  check("D9. nothing held for the requested orders: \"none\", and the statement says it holds nothing",
    noneMail.text.indexOf("What BizForce holds for those orders in this shop:\nnone") !== -1 &&
    noneMail.text.indexOf("It holds nothing for the orders in this request.") !== -1, noneMail.text);
  const BAD = "db-" + uuid();
  const d10 = await webhook(m, "customers/data_request", "{not json", { id: BAD });
  await settle();
  check("D10. a body that is not JSON: still 200 and recorded, with request_details null", d10.status === 200 && receipt(m.db, BAD) && receipt(m.db, BAD).request_details === null);

  resetMail();
  m = mount({});
  conn(m.db, U1, SHOP);
  MAIL.fail = 1;
  const FAIL = "dx-" + uuid();
  await webhook(m, "customers/data_request", J({ orders_requested: [], customer: { id: 5 }, data_request: { id: 78 } }), { id: FAIL });
  await settle();
  check("D11. a failed send: owner_notified_at stays null (processed_at is set: the request is recorded)",
    MAIL.calls === 1 && MAIL.sent.length === 0 && receipt(m.db, FAIL).owner_notified_at === null && typeof receipt(m.db, FAIL).processed_at === "string");
  const later = Date.now() + 3 * 60000;
  const s1 = await SW.sweepTick(sweepDeps(m, later));
  check("D12. the sweep sends it again and sets owner_notified_at", MAIL.sent.length === 1 && typeof receipt(m.db, FAIL).owner_notified_at === "string", J(s1));
  await SW.sweepTick(sweepDeps(m, later + 60000));
  check("D13. ... and not a third time", MAIL.sent.length === 1 && MAIL.calls === 2, MAIL.calls);
  m.db.t.shopify_webhook_events.push({ id: uuid(), webhook_id: "dz", topic: "customers/data_request", shop_domain: SHOP, received_at: iso(Date.now() - 10 * 60000),
    processed_at: null, request_details: null, answered_at: null, owner_notified_at: iso(Date.now() - 9 * 60000) });
  await SW.sweepTick(sweepDeps(m, later + 120000));
  check("D14. a receipt whose owner email already went is never emailed again, even when its processed_at is missing",
    MAIL.calls === 2 && typeof receipt(m.db, "dz").processed_at === "string", MAIL.calls);
  resetMail();
  m = mount({ env: { SHOPIFY_CLIENT_ID: "check-client-id", SHOPIFY_CLIENT_SECRET: SECRET } });
  const NOADDR = "dq-" + uuid();
  const d15 = await webhook(m, "customers/data_request", drBody, { id: NOADDR });
  await settle();
  await SW.sweepTick(sweepDeps(m, later));
  check("D15. no owner address (neither OPS_ALERT_EMAIL nor BACKUP_EMAIL_TO): 200, recorded and processed, no email, owner_notified_at null, nothing fails",
    d15.status === 200 && MAIL.calls === 0 && typeof receipt(m.db, NOADDR).processed_at === "string" && receipt(m.db, NOADDR).owner_notified_at === null);
  // NAMED (Nov 15 2026, W3): the claim. Two processes (two loaded copies of lib/shopifyWebhooks.js, each with its own
  // in-process guard) take the same unsent request at once: exactly one email.
  resetMail();
  m = mount({});
  conn(m.db, U1, SHOP);
  const RACE = { id: uuid(), webhook_id: "race", topic: "customers/data_request", shop_domain: SHOP, received_at: iso(Date.now() - 10 * 60000), processed_at: null,
    request_details: { customer_id: "5", orders_requested: [], data_request_id: "79" }, answered_at: null, owner_notified_at: null };
  m.db.t.shopify_webhook_events.push(RACE);
  const other = loadHooks();
  const raced = await Promise.all([SW.processReceipt(sweepDeps(m, Date.now()), JSON.parse(J(RACE))), other.processReceipt(sweepDeps(m, Date.now()), JSON.parse(J(RACE)))]);
  check("D16. two runs take the same unsent request at once: ONE email (the claim), owner_notified_at set, both runs succeed",
    MAIL.sent.length === 1 && MAIL.calls === 1 && typeof RACE.owner_notified_at === "string" && raced.every(function (r) { return r.ok === true; }) &&
    raced.some(function (r) { return r.reason === "already_claimed"; }), J([MAIL.calls, raced]));
  check("D17. the email names the owner's page, https://bizforceai.net/shopify-requests.html, on its own line",
    (MAIL.sent[0] || { text: "" }).text.split("\n").indexOf("Open requests, and the button to mark this one answered: https://bizforceai.net/shopify-requests.html") !== -1,
    (MAIL.sent[0] || { text: "" }).text);

  /* ── E ── */
  console.log("\n== E. customers/redact ==");
  m = mount({});
  const cE = conn(m.db, U1, SHOP), cE2 = conn(m.db, U2, OTHER_SHOP);
  order(m.db, cE, "1001"); order(m.db, cE, "1002"); const kept3 = order(m.db, cE, "1003"); const keptOther = order(m.db, cE2, "1001");
  const RED = "r-" + uuid();
  const redBody = J({ shop_domain: SHOP, customer: { id: 1, email: EMAIL, phone: PHONE }, orders_to_redact: [1001, "gid://shopify/Order/1002"] });
  const e1 = await webhook(m, "customers/redact", redBody, { id: RED });
  await settle();
  check("E1. 200; request_details holds the customer id and the orders to redact as numeric strings, and no email or phone",
    e1.status === 200 && J(receipt(m.db, RED).request_details) === J({ customer_id: "1", orders_to_redact: ["1001", "1002"] }) &&
    J(receipt(m.db, RED)).indexOf(EMAIL) === -1 && J(receipt(m.db, RED)).indexOf(PHONE) === -1, J(receipt(m.db, RED).request_details));
  check("E2. only orders 1001 and 1002 of THAT shop are deleted: its 1003 and the other shop's 1001 are kept; processed",
    m.db.t.store_order_summaries.length === 2 && m.db.t.store_order_summaries.indexOf(kept3) !== -1 && m.db.t.store_order_summaries.indexOf(keptOther) !== -1 &&
    typeof receipt(m.db, RED).processed_at === "string", J(m.db.t.store_order_summaries.map(function (o) { return o.external_id; })));
  const again = await SW.processReceipt(sweepDeps(m, Date.now()), receipt(m.db, RED));
  check("E3. idempotent: run again, it deletes nothing more", again.ok === true && again.deleted === 0 && m.db.t.store_order_summaries.length === 2, J(again));
  // NAMED (Nov 15 2026, W3): an unreadable customers/redact reaches the owner as ONE ops alert, by shop and receipt id only.
  check("E4. a readable customers/redact raises no alert", ALERTS.length === 0, J(ALERTS));
  const UNR1 = "ru-" + uuid(), UNR2 = "rv-" + uuid();
  await webhook(m, "customers/redact", "{not json", { id: UNR1 });
  await webhook(m, "customers/redact", J({ shop_domain: SHOP, customer: { id: 1, email: EMAIL, phone: PHONE }, orders_to_redact: ["nonsense"] }), { id: UNR2 });
  await settle();
  const u1 = receipt(m.db, UNR1), u2 = receipt(m.db, UNR2);
  check("E5. a body that is not JSON, and one whose order ids cannot be read: one shopify_redact_unreadable alert each (fingerprint = receipt id), nothing deleted, both processed",
    ALERTS.length === 2 && ALERTS.every(function (a) { return a.key === "shopify_redact_unreadable"; }) && ALERTS[0].info.fingerprint === u1.id && ALERTS[1].info.fingerprint === u2.id &&
    m.db.t.store_order_summaries.length === 2 && typeof u1.processed_at === "string" && typeof u2.processed_at === "string", J(ALERTS));
  const alertText = J(ALERTS);
  check("E6. the alert names the shop and the receipt id, and nothing from the request (no email, phone or customer id)",
    ALERTS.every(function (a, i) { return a.info.error.indexOf("Shop " + SHOP + ", receipt " + [u1, u2][i].id + ":") === 0; }) &&
    alertText.indexOf(EMAIL) === -1 && alertText.indexOf(PHONE) === -1 && alertText.indexOf("customer_id") === -1 && alertText.indexOf("nonsense") === -1, alertText);
  check("E7. server.js hands lib/opsAlert.js's raise to the work (shopifyWebhookDeps().raiseAlert)",
    /raiseAlert: function \(key, info\) \{ return opsAlerts\.raise\(key, info\); \}/.test(FILES.server) && typeof m.ctx.shopifyWebhookDeps().raiseAlert === "function");
  check("E4. nothing but store_order_summaries was deleted", m.db.log.filter(function (l) { return l.op === "delete"; }).every(function (l) { return l.table === "store_order_summaries"; }));

  /* ── F ── */
  console.log("\n== F. shop/redact ==");
  m = mount({});
  const cF = conn(m.db, U1, SHOP), cG = conn(m.db, U2, OTHER_SHOP);
  function proposal(user, action, connectionId) {
    const p = { id: uuid(), user_id: user, agent_type: "store", action_type: action, title: "Change Wool Hat price from 25.00 to 30.00", target: "shopify",
      payload: { connection_id: connectionId, item_id: uuid(), external_id: "11", item_name: "Wool Hat", field: "price", from: 25, to: 30, platform: "shopify" },
      status: "executed", created_at: "2026-11-01T00:00:00.000Z", decided_at: "2026-11-01T00:01:00.000Z", executed_at: "2026-11-01T00:02:00.000Z",
      execution_result: { applied: true, change_id: uuid(), item_name: "Wool Hat", field: "price", from: 25, to: 30 } };
    m.db.t.agent_proposals.push(p); return p;
  }
  const pMine = proposal(U1, "update_store_item", cF.id);
  const pPending = proposal(U1, "update_store_item", cF.id); pPending.status = "pending";
  const pOtherShop = proposal(U2, "update_store_item", cG.id);
  const pOtherType = proposal(U1, "publish_social_post", cF.id);
  const pOtherSnap = J([pOtherShop, pOtherType]);
  const stMine = { id: uuid(), user_id: U1, purpose: "store_shopify", flow_context: { shop: SHOP, permission: "read" } };
  const stOther = { id: uuid(), user_id: U2, purpose: "store_shopify", flow_context: { shop: OTHER_SHOP, permission: "read" } };
  const stMail = { id: uuid(), user_id: U1, purpose: "mailbox_microsoft", flow_context: null };
  m.db.t.oauth_states.push(stMine, stOther, stMail);
  const UN = "u-" + uuid();
  await webhook(m, "app/uninstalled", "{}", { id: UN });
  await settle();
  check("F1. the app/uninstall removed the connection and recorded its id in its receipt",
    m.db.t.member_store_connections.indexOf(cF) === -1 && J(receipt(m.db, UN).request_details) === J({ connection_ids: [cF.id] }));
  const SR = "s-" + uuid();
  const f2 = await webhook(m, "shop/redact", J({ shop_id: 954889, shop_domain: SHOP }), { id: SR });
  await settle();
  const red = [pMine, pPending].map(function (p) { return m.db.t.agent_proposals.filter(function (x) { return x.id === p.id; })[0]; });
  check("F2. shop/redact (after the uninstall deleted the connection) anonymises that shop's update_store_item proposals, found through the recorded id",
    f2.status === 200 && red.every(function (p) {
      return J(p.payload) === J({ redacted: true, reason: "shop/redact" }) && J(p.execution_result) === J({ redacted: true, reason: "shop/redact" }) &&
        p.title === "Store change (removed after the store asked for its data to be erased)";
    }), J(red.map(function (p) { return [p.title, p.payload]; })));
  check("F3. ... keeping id, user_id, type, status and timestamps",
    red[0].id === pMine.id && red[0].user_id === U1 && red[0].action_type === "update_store_item" && red[0].status === "executed" && red[1].status === "pending" &&
    red[0].created_at === "2026-11-01T00:00:00.000Z" && red[0].decided_at === "2026-11-01T00:01:00.000Z" && red[0].executed_at === "2026-11-01T00:02:00.000Z");
  check("F4. another shop's (another user's) proposal and another type of proposal are untouched", J([pOtherShop, pOtherType]) === pOtherSnap);
  check("F5. that shop's sign-in state is deleted; another shop's and a mailbox state are kept",
    m.db.t.oauth_states.indexOf(stMine) === -1 && m.db.t.oauth_states.indexOf(stOther) !== -1 && m.db.t.oauth_states.indexOf(stMail) !== -1);
  check("F6. the shop/redact receipt is processed", typeof receipt(m.db, SR).processed_at === "string");
  const snapAll = J(m.db.t.agent_proposals);
  const f7 = await SW.processReceipt(sweepDeps(m, Date.now()), receipt(m.db, SR));
  check("F7. idempotent: again, the same proposals stay anonymised and nothing else changes", f7.ok === true && J(m.db.t.agent_proposals) === snapAll, J(f7));
  m = mount({});
  const cH = conn(m.db, U1, SHOP);
  const pDirect = { id: uuid(), user_id: U1, action_type: "update_store_item", title: "t", payload: { connection_id: cH.id }, status: "pending", execution_result: null };
  m.db.t.agent_proposals.push(pDirect);
  await webhook(m, "shop/redact", "{}");
  await settle();
  check("F8. a shop/redact with no earlier uninstall: the current connection's id is recorded and its proposal anonymised",
    J(pDirect.payload) === J({ redacted: true, reason: "shop/redact" }) && m.db.t.member_store_connections.length === 0);

  /* ── G ── */
  console.log("\n== G. the sweep ==");
  m = mount({});
  const now = Date.now();
  const cS1 = conn(m.db, U1, SHOP), cS2 = conn(m.db, U2, OTHER_SHOP), cS3 = conn(m.db, U2, "third-shop.myshopify.com");
  m.db.t.shopify_webhook_events.push(
    { id: uuid(), webhook_id: "old-unprocessed", topic: "app/uninstalled", shop_domain: SHOP, received_at: iso(now - 10 * 60000), processed_at: null, request_details: null, answered_at: null, owner_notified_at: null },
    { id: uuid(), webhook_id: "old-processed", topic: "app/uninstalled", shop_domain: OTHER_SHOP, received_at: iso(now - 20 * 60000), processed_at: iso(now - 19 * 60000), request_details: null, answered_at: null, owner_notified_at: null },
    { id: uuid(), webhook_id: "fresh-unprocessed", topic: "app/uninstalled", shop_domain: "third-shop.myshopify.com", received_at: iso(now - 60000), processed_at: null, request_details: null, answered_at: null, owner_notified_at: null });
  const g1 = await SW.sweepTick(sweepDeps(m, now));
  check("G1. the sweep reprocesses the unprocessed receipt older than 2 minutes: its shop removed, processed_at set",
    m.db.t.member_store_connections.indexOf(cS1) === -1 && typeof receipt(m.db, "old-unprocessed").processed_at === "string", J(g1));
  check("G2. it skips a processed receipt (its shop is untouched) and one newer than 2 minutes",
    m.db.t.member_store_connections.indexOf(cS2) !== -1 && m.db.t.member_store_connections.indexOf(cS3) !== -1 && receipt(m.db, "fresh-unprocessed").processed_at === null &&
    receipt(m.db, "old-processed").processed_at === iso(now - 19 * 60000), J(m.removals));
  check("G3. it reads oldest first, at most 50, on the unprocessed receipts (the partial index's predicate)",
    m.db.log.some(function (l) { return l.table === "shopify_webhook_events" && l.op === "select" && J(l.filters).indexOf("[\"is\",\"processed_at\",null]") !== -1; }) &&
    /\.is\("processed_at", null\)\.lt\("received_at", cutoff\)\n      \.order\("received_at", \{ ascending: true \}\)\.limit\(SWEEP_BATCH\)/.test(FILES.hooks) && /const SWEEP_BATCH = 50;/.test(FILES.hooks) &&
    /const SWEEP_MIN_AGE_MS = 2 \* 60 \* 1000;/.test(FILES.hooks));
  m = mount({ hold: true });
  conn(m.db, U1, SHOP);
  m.db.t.shopify_webhook_events.push({ id: uuid(), webhook_id: "slow", topic: "app/uninstalled", shop_domain: SHOP, received_at: iso(now - 10 * 60000), processed_at: null, request_details: null, answered_at: null, owner_notified_at: null });
  const first = SW.sweepTick(sweepDeps(m, now));
  await settle();
  const second = await SW.sweepTick(sweepDeps(m, now));
  m.release();
  const firstOut = await first;
  check("G4. single flight: a sweep that finds one still running does nothing", second.skipped === "running" && firstOut.ok === 1 && m.removals.length === 1, J([second, firstOut]));

  /* ── H ── */
  console.log("\n== H. the purge ==");
  const db = makeDb();
  const P = Date.parse("2026-11-15T04:45:00.000Z");
  function ev(id, topic, receivedDaysAgo, processed, answeredDaysAgo) {
    db.t.shopify_webhook_events.push({ id: uuid(), webhook_id: id, topic: topic, shop_domain: SHOP, received_at: iso(P - receivedDaysAgo * DAY),
      processed_at: processed ? iso(P - receivedDaysAgo * DAY + 1000) : null, request_details: null,
      answered_at: answeredDaysAgo === undefined ? null : iso(P - answeredDaysAgo * DAY), owner_notified_at: null });
  }
  ev("dr-unanswered-60d", "customers/data_request", 60, true);
  ev("dr-answered-31d", "customers/data_request", 50, true, 31);
  ev("dr-answered-10d", "customers/data_request", 50, true, 10);
  ev("dr-recent-answered-today", "customers/data_request", 2, true, 0);
  ev("un-processed-31d", "app/uninstalled", 31, true);
  ev("un-unprocessed-31d", "app/uninstalled", 31, false);
  ev("redact-processed-29d", "customers/redact", 29, true);
  const pg = await SA.webhookEventsPurgeTick(db, P);
  const left = db.t.shopify_webhook_events.map(function (e) { return e.webhook_id; }).sort();
  check("H1. an unanswered data request is kept, however old", left.indexOf("dr-unanswered-60d") !== -1, J(left));
  check("H2. an answered data request goes 30 days after answered_at, not before", left.indexOf("dr-answered-31d") === -1 && left.indexOf("dr-answered-10d") !== -1 &&
    left.indexOf("dr-recent-answered-today") !== -1, J(left));
  check("H3. an unprocessed receipt is never purged; a processed one older than 30 days is; a newer one is kept",
    left.indexOf("un-unprocessed-31d") !== -1 && left.indexOf("un-processed-31d") === -1 && left.indexOf("redact-processed-29d") !== -1, J(left));
  check("H4. claimed once a day through job_runs, with the count", pg.claimed === true && pg.deleted === 2 && !pg.error &&
    db.t.job_runs.length === 1 && db.t.job_runs[0].job_name === "shopify_webhook_events_purge", J(pg));

  /* ── I ── */
  console.log("\n== I. duplicates ==");
  m = mount({});
  const cI = conn(m.db, U1, SHOP);
  const DUP = "dup-" + uuid();
  await webhook(m, "app/uninstalled", "{}", { id: DUP });
  await settle();
  const cI2 = conn(m.db, U1, SHOP);
  const i1 = await webhook(m, "app/uninstalled", "{}", { id: DUP });
  await settle();
  check("I1. a processed webhook_id delivered again: 200 duplicate, one receipt, and the shop connected since is NOT removed",
    i1.status === 200 && i1.body.duplicate === true && m.db.t.shopify_webhook_events.length === 1 && m.db.t.member_store_connections.indexOf(cI2) !== -1 &&
    m.db.t.member_store_connections.indexOf(cI) === -1, J(i1.body));
  const n0 = m.db.t.shopify_webhook_events.length;
  const i2 = await webhook(m, "orders/create", "{}");
  check("I2. a topic BizForce did not subscribe to: 200 ignored, nothing recorded", i2.body.ignored === true && m.db.t.shopify_webhook_events.length === n0);

  /* ── J ── */
  console.log("\n== J. the 23-day reminder ==");
  resetMail();
  m = mount({});
  const R0 = Date.parse("2026-11-15T04:45:00.000Z");
  function dr(id, receivedMs, answered) {
    m.db.t.shopify_webhook_events.push({ id: uuid(), webhook_id: id, topic: "customers/data_request", shop_domain: SHOP, received_at: iso(receivedMs), processed_at: iso(receivedMs),
      request_details: { customer_id: "1", orders_requested: [], data_request_id: "5" }, answered_at: answered ? iso(receivedMs + DAY) : null, owner_notified_at: iso(receivedMs) });
  }
  // NAMED (Nov 15 2026, W3): BEFORE a run reminded only the requests that turned 23 days old since the last run, so a
  // failed send was never tried again. AFTER every unanswered request 23 or more days old with no
  // request_details.reminded_at is due, and reminded_at is set only after a send that succeeded.
  function jrow(id) { return m.db.t.shopify_webhook_events.filter(function (e) { return e.webhook_id === id; })[0]; }
  dr("due", R0 - 23 * DAY - 3600000, false);
  dr("due-but-answered", R0 - 23 * DAY - 7200000, true);
  dr("too-young", R0 - 22 * DAY, false);
  dr("long-past", R0 - 40 * DAY, false);
  const j1 = await SW.reminderTick(sweepDeps(m, R0), R0);
  check("J1. a reminder for each unanswered request 23 or more days old with no reminder yet (23 days and 40 days); none for an answered or a younger one",
    j1.claimed === true && j1.sent === 2 && MAIL.sent.length === 2 && MAIL.sent.every(function (x) { return x.subject.indexOf("Reminder: ") === 0 && x.text.indexOf("Data request id: 5") !== -1; }) &&
    !jrow("due-but-answered").request_details.reminded_at && !jrow("too-young").request_details.reminded_at, J(j1));
  check("J1b. reminded_at is set on each reminded request, as the run's time, and the ids in request_details are kept",
    jrow("due").request_details.reminded_at === iso(R0) && jrow("long-past").request_details.reminded_at === iso(R0) &&
    J(Object.keys(jrow("due").request_details).sort()) === J(["customer_id", "data_request_id", "orders_requested", "reminded_at"]) && jrow("due").request_details.data_request_id === "5",
    J(jrow("due").request_details));
  const j2 = await SW.reminderTick(sweepDeps(m, R0 + 3600000), R0 + 3600000);
  check("J2. a second run the same day is not claimed and sends nothing", j2.claimed === false && MAIL.sent.length === 2, J(j2));
  const j3 = await SW.reminderTick(sweepDeps(m, R0 + DAY), R0 + DAY);
  check("J3. the next day: the request that is now exactly 23 days old is reminded; the two already reminded are not",
    j3.claimed === true && j3.sent === 1 && MAIL.sent.length === 3 && jrow("too-young").request_details.reminded_at === iso(R0 + DAY), J([j3, MAIL.sent.length]));
  const jr = m.db.t.job_runs.filter(function (r) { return r.job_name === "shopify_data_request_reminder"; });
  check("J4. recorded in job_runs as shopify_data_request_reminder, finished, no error", jr.length === 1 && !!jr[0].finished_at && jr[0].last_error == null, J(jr));
  dr("retry", R0 + 2 * DAY - 24 * DAY, false);
  MAIL.fail = 1;
  const j5 = await SW.reminderTick(sweepDeps(m, R0 + 2 * DAY), R0 + 2 * DAY);
  check("J5. a reminder that fails to send: reminded_at stays unset, and the run records the error in job_runs (the ops alert scan reads it)",
    j5.claimed === true && j5.due === 1 && j5.failed === 1 && MAIL.sent.length === 3 && !jrow("retry").request_details.reminded_at && /1 Shopify data request reminder\(s\) not sent/.test(jr[0].last_error || ""),
    J([j5, jr[0].last_error]));
  const j6 = await SW.reminderTick(sweepDeps(m, R0 + 3 * DAY), R0 + 3 * DAY);
  check("J6. the next day's run sends it again, then sets reminded_at; the error clears",
    j6.claimed === true && j6.sent === 1 && MAIL.sent.length === 4 && jrow("retry").request_details.reminded_at === iso(R0 + 3 * DAY) && jr[0].last_error == null, J([j6, jr[0].last_error]));
  const j7 = await SW.reminderTick(sweepDeps(m, R0 + 4 * DAY), R0 + 4 * DAY);
  check("J7. and never a third time", j7.claimed === true && j7.due === 0 && MAIL.sent.length === 4, J(j7));

  /* ── K ── */
  console.log("\n== K. the admin routes ==");
  m = mount({});
  const KN = Date.now();
  const open1 = { id: uuid(), webhook_id: "k1", topic: "customers/data_request", shop_domain: SHOP, received_at: iso(KN - 5 * DAY), processed_at: iso(KN), request_details: { customer_id: "1", orders_requested: ["2"], data_request_id: "3" }, answered_at: null, owner_notified_at: iso(KN) };
  const oldAnswered = { id: uuid(), webhook_id: "k2", topic: "customers/data_request", shop_domain: SHOP, received_at: iso(KN - 80 * DAY), processed_at: iso(KN), request_details: null, answered_at: iso(KN - 40 * DAY), owner_notified_at: null };
  const uninstall = { id: uuid(), webhook_id: "k3", topic: "app/uninstalled", shop_domain: SHOP, received_at: iso(KN), processed_at: iso(KN), request_details: null, answered_at: null, owner_notified_at: null };
  m.db.t.shopify_webhook_events.push(open1, oldAnswered, uninstall);
  const listRoute = m.routes["get /api/admin/shopify-data-requests"], markRoute = m.routes["post /api/admin/shopify-data-requests/:id/answered"];
  check("K1. both routes are behind requireAuth and requireAdmin", !!listRoute && !!markRoute &&
    listRoute.middleware[0] === requireAuth && listRoute.middleware[1] === requireAdmin && markRoute.middleware[0] === requireAuth && markRoute.middleware[1] === requireAdmin);
  const k2 = await hit(m, "get /api/admin/shopify-data-requests", {});
  const row1 = (k2.body.requests || [])[0] || {};
  check("K2. the list: open requests with the shop, received_at, deadline (+30 days), owner_notified_at, answered_at and request_details; not old answered ones or other topics",
    k2.status === 200 && k2.body.requests.length === 1 && k2.body.open === 1 && row1.id === open1.id && row1.shop === SHOP && row1.deadline === iso(KN - 5 * DAY + 30 * DAY) &&
    row1.owner_notified_at === open1.owner_notified_at && row1.answered_at === null && J(row1.request_details) === J(open1.request_details), J(k2.body));
  const k3 = await hit(m, "post /api/admin/shopify-data-requests/:id/answered", { params: { id: open1.id } });
  check("K3. marking it answered sets answered_at", k3.status === 200 && typeof open1.answered_at === "string" && k3.body.request.answered_at === open1.answered_at, J(k3));
  const k4 = await hit(m, "post /api/admin/shopify-data-requests/:id/answered", { params: { id: open1.id } });
  check("K4. again: already answered, answered_at unchanged", k4.status === 200 && k4.body.already_answered === true && k4.body.request.answered_at === open1.answered_at);
  const k5 = await hit(m, "post /api/admin/shopify-data-requests/:id/answered", { params: { id: uninstall.id } });
  const k6 = await hit(m, "post /api/admin/shopify-data-requests/:id/answered", { params: { id: "not-a-uuid" } });
  check("K5. another topic's receipt, or a bad id: 404 and nothing set", k5.status === 404 && uninstall.answered_at === null && k6.status === 404, J([k5.status, k6.status]));

  /* ── L ── */
  console.log("\n== L. the wiring ==");
  const mainBlock = /if \(require\.main === module\) \{\n    shutdownControl\.trackInterval\("shopifyWebhookSweepTick", setInterval\(shopifyWebhookSweepTick, 300000\)\);/.test(FILES.server);
  check("L1. the sweep runs every 5 minutes (300000 ms) through shutdownControl.trackInterval, only when server.js is the program", mainBlock);
  check("L2. the reminder is a step of the 04:45 UTC chain, after the renewal emails",
    FILES.server.indexOf(".then(renewalEmailsTick)\n        .then(shopifyDataRequestReminderTick);\n    }, {") !== -1);
  check("L3. lib/jobSchedules.js lists the sweep (every 300000 ms) and the reminder's job_runs row in the 04:45 entry",
    FILES.jobs.indexOf("{ tick: \"shopifyWebhookSweepTick\", every_ms: 300000, jobs: [] }") !== -1 && FILES.jobs.indexOf("\"shopify_data_request_reminder\"] },") !== -1);
  check("L4. the owner address is the ops alerts' own (OPS_ALERT_EMAIL, else BACKUP_EMAIL_TO): no new variable",
    FILES.hooks.indexOf("require(\"./opsAlert\").opsAlertRecipient(env || {})") !== -1 && !/process\.env\.[A-Z_]*EMAIL/.test(FILES.hooks) &&
    OPS_REAL.opsAlertRecipient({ BACKUP_EMAIL_TO: "b@example.test" }) === "b@example.test");
  check("L5. the HMAC check over the raw body is unchanged",
    FILES.server.indexOf("    var raw = Buffer.isBuffer(req.body) ? req.body : null;\n    if (!raw || !sa.webhookHmacValid(raw, req.get(\"X-Shopify-Hmac-Sha256\") || \"\", config.clientSecret)) {\n      return res.status(401).json({ error: \"Unauthorized\" });\n    }") !== -1);
  const migDir = path.join(REPO, "supabase", "migrations");
  const migFiles = fs.readdirSync(migDir).filter(function (x) { return /^\d{3}_.*\.sql$/.test(x); });
  const highest = migFiles.map(function (x) { return Number(x.slice(0, 3)); }).reduce(function (a, x) { return Math.max(a, x); }, 0);
  const mig = read("supabase/migrations/184_shopify_webhook_requests.sql");
  // NAMED (Nov 15 2026, W-T4, migration 185): BEFORE 184 was the highest. AFTER 185_shopify_uninstall_hook.sql is above it, by name; "the highest" is checkShopifyUninstallHook R1's.
  // NAMED (Nov 17 2026, TK1, migration 186): BEFORE 185 was the highest. AFTER 186_member_videos_duration.sql is above it too, by name; "the highest" is checkTiktokPosting G15's.
  // NAMED (Nov 18 2026, BV1, migration 187): BEFORE 186 was the highest. AFTER 187_member_video_parts.sql is above it too, by name; "the highest" is checkYoutubeUploads G14's.
  check("R1. 184_shopify_webhook_requests.sql is the only 184, only 185_shopify_uninstall_hook.sql, 186_member_videos_duration.sql and 187_member_video_parts.sql are above it (checkYoutubeUploads G14); its VERIFY query is verify/184_verify.sql",
    highest === 187 && migFiles.filter(function (x) { return Number(x.slice(0, 3)) > 184; }).join() === "185_shopify_uninstall_hook.sql,186_member_videos_duration.sql,187_member_video_parts.sql" &&
    migFiles.filter(function (x) { return /^184_/.test(x); }).join() === "184_shopify_webhook_requests.sql" &&
    fs.existsSync(path.join(migDir, "verify", "184_verify.sql")), highest);
  check("R2. migration 184 adds request_details, answered_at, owner_notified_at and the partial index on received_at WHERE processed_at IS NULL, in BEGIN/COMMIT, and drops nothing",
    /ADD COLUMN IF NOT EXISTS request_details jsonb NULL/.test(mig) && /ADD COLUMN IF NOT EXISTS answered_at timestamptz NULL/.test(mig) &&
    /ADD COLUMN IF NOT EXISTS owner_notified_at timestamptz NULL/.test(mig) && /ON public\.shopify_webhook_events \(received_at\)\n  WHERE processed_at IS NULL;/.test(mig) &&
    /\nBEGIN;\n/.test(mig) && /\nCOMMIT;\n?$/.test(mig) && !/\bDROP\b/i.test(mig.replace(/^--.*$/gm, "")));
  check("L6. no emoji in any file this change touches", [FILES.server, FILES.hooks, FILES.auth, FILES.jobs, fs.readFileSync(__filename, "utf8")].every(function (s) { return !EMOJI.test(s); }));

  /* ── P. THE WORDS (W3) ─────────────────────────────────────────────────────
     The Privacy Policy, Your Data and the backup list say what the purge does and what a request holds. */
  const LEGAL = compile(FILES.legal, "lib/legalPages.js", {});
  const noticeDays = Math.round(SA.WEBHOOK_RETENTION_MS / (24 * 60 * 60 * 1000));
  const sentence = LEGAL.shopifyNoticesPrivacySentence(noticeDays);
  const FE_PRIVACY = fs.readFileSync(path.join(REPO, "..", "BizForce-fronyend", "privacy.html"), "utf8").replace(/\r\n/g, "\n");
  const decode = function (h) { return h.replace(/&#39;/g, "'").replace(/&quot;/g, "\"").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&"); };
  const privacyText = decode(FE_PRIVACY.replace(/<[^>]+>/g, " ")).replace(/\s+/g, " ");
  check("P1. the frontend's privacy.html states the Shopify notice sentence, as lib/legalPages.js builds it, exactly once",
    privacyText.split(sentence).length === 2, privacyText.split(sentence).length - 1);
  check("P2. its days are the purge's own (lib/shopifyAuth.js WEBHOOK_RETENTION_MS), never typed in: built for 17 days it says 17 and not " + noticeDays,
    noticeDays === 30 && LEGAL.shopifyNoticesPrivacySentence(17).indexOf("Each notice is kept 17 days; a customer data request is kept until 17 days after it is answered") !== -1 &&
    LEGAL.shopifyNoticesPrivacySentence(17).indexOf(noticeDays + " days") === -1, noticeDays);
  check("P3. it says a notice not yet processed is kept until it is processed (the purge skips processed_at null)",
    sentence.indexOf("a notice not yet processed is kept until it is processed") !== -1 && FILES.auth.indexOf(".not(\"processed_at\", \"is\", null)") !== -1);
  const drDetails = SW.requestDetailsOf("customers/data_request", JSON.stringify({ customer: { id: 7, email: "c@example.test", phone: "555", first_name: "N" }, orders_requested: [11, 12], data_request_id: 1, data_request: { id: 99 } }));
  check("P4. a data request record holds exactly what the sentence names: the customer id, the order ids and the request id",
    J(Object.keys(drDetails || {}).sort()) === J(["customer_id", "data_request_id", "orders_requested"]) &&
    sentence.indexOf("holds only the Shopify customer id, the order ids it names and the request id, never the customer's name, email or phone number") !== -1, J(drDetails));
  check("P5. lib/yourData.js says the same rule and fields for shopify_webhook_events",
    FILES.yourData.indexOf("Each is kept 30 days; a customer data request is kept until 30 days \" +\n    \"after it is answered, and a notification not yet processed is kept until it is processed. A data request record holds only the Shopify customer id, \" +\n    \"the order ids it names and the request id, never a name, email or phone number\"") !== -1);
  check("P6. lib/backup.js's excluded-table reason says the same rule",
    FILES.backup.indexOf("shopify_webhook_events: \"Shopify notification receipts: kept 30 days, a customer data request until 30 days after it is answered, one not yet processed until it is processed\"") !== -1);

  await settle();
  check("no unhandled rejection", UNHANDLED.length === 0, UNHANDLED.map(String).join("; "));
  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(function (e) { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
