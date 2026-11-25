#!/usr/bin/env node
"use strict";
/* ═════════════════════════════════════════════════════════════════════════════
   checkInbound.js — LR-3 (Nov 24 2026): Inbound, everything coming to a member.
     node scripts/checkInbound.js              the checks
     MUTATE=<name> node scripts/checkInbound.js   one mutation, in memory (a check must FAIL)
     MUTATE=all node scripts/checkInbound.js      every mutation, each in its own process

   Everything here runs on fakes: an in-memory database (memDb) that keeps rows and enforces inbound_items' unique key
   and its one-per-conversation index, a fake app for the routes, a fake page for the storefront button. No network,
   no model, no live write, no message, email or SMS.

   A. migration 205: the table, its named checks, the unique key, the conversation index, RLS with no policies, revoked,
      paste-safe (no <= or >=, no DO blocks, no BEGIN or COMMIT), in parts 205a, 205b, 205c
   B. each kind is made once and only once, never for the member's own action, one item per conversation
   C. a sale and a donation: the in-app notice (types sale and donation, object types order and campaign) and its push,
      no email and no SMS; the server's helpers run after the action and are never awaited by it
   D. replies on Bluesky: a reply to the member's own Lead Radar reply, once, and the lead becomes replied (never over won)
   E. the routes: members only (M), the member's own items only, the status moves, the list and its filter
   F. Add to my customers: a won item only, once, even when two taps race
   G. the Leads tab's won: leads won plus items won, a lead_reply whose lead is also won counted once
   H. never throws and never delays: every writer survives a failing or throwing database
   I. the storefront's Message button by account type: member, free, signed out, own
   J. the backfill: a dry run writes nothing, --apply writes each item once, a second run writes nothing
   K. the data lists and the page: export and deletion name inbound_items; the Inbound tab's requests
   ═════════════════════════════════════════════════════════════════════════════ */
const path = require("path");
const vm = require("vm");
const H = require("./_p21Harness");
const SH = require("./_shared");

const LIB = "@lib/inbound.js", ROUTES = "@lib/inboundRoutes.js", SERVER = "@server.js", ACCESS = "@lib/routeAccess.js", LEADR = "@lib/leadRoutes.js";
const BACKFILL = "@scripts/oneoff/lr3Backfill.js", MIG = "@supabase/migrations/205_lr3_inbound.sql", YD = "@lib/yourData.js", BK = "@lib/backup.js";
const SELLER = "seller.html", BFA = "scripts/bf-access.js", RADAR = "agents/lead-radar.html", PRIV = "privacy.html";

const MUTATIONS = {
  // lib/inbound.js
  "not-won-at-once": [[LIB, `const WON_AT_ONCE = ["sale", "campaign", "tip"];`, `const WON_AT_ONCE = [];`]],
  "own-action": [[LIB, `  if (other && other === x.userId) return null;\n`, ``]],
  "every-message": [[LIB, `  if ((earlier.data || []).length) return { row: null, reason: "not_first" };\n`, ``]],
  "any-need": [[LIB, `r.data.author_id !== receiverId || `, ``]],
  "exists-is-error": [[LIB, `      if (r.error.code === "23505") return { created: false, reason: "exists" };\n`, ``]],
  "no-push": [[LIB, `    try { await push(row.user_id, { title: row.title, body: row.message, url: row.link || "/inbox.html?tab=notifications" }); }`, `    try { }`]],
  "sale-type": [[LIB, `type: "sale", title: "You made a sale"`, `type: "message", title: "You made a sale"`]],
  "donation-object": [[LIB, `object_type: "campaign", object_id: isUuid(d.campaign_id)`, `object_type: "post", object_id: isUuid(d.campaign_id)`]],
  "double-won": [[LIB, `  return (leads.count || 0) + (items.count || 0) - both;`, `  return (leads.count || 0) + (items.count || 0);`]],
  "replied-over-won": [[LIB, `.eq("user_id", userId).not("status", "in", "(won,lost,replied)");`, `.eq("user_id", userId);`]],
  "any-notification": [[LIB, `if (!n || n.reason !== "reply" || `, `if (!n || `]],
  "summary-unclipped": [[LIB, `summary: clip(x.summary, SUMMARY_MAX),`, `summary: String(x.summary || ""),`]],
  "sale-opens-inbox": [[LIB, `  if (i.kind === "sale") return { href: "/receipts.html", external: false };\n`, ``]],
  "card-lead-name-lost": [[LIB, `const name = i.kind === "card_lead" && c.name ? clip(c.name, 150) : generic`, `const name = generic`]],
  "record-throws": [[LIB, `  } catch (e) { warn("an item could not be written", e); return { created: false, reason: "error" }; }\n}`, `  } catch (e) { throw e; }\n}`]],
  // lib/inboundRoutes.js
  "routes-not-m": [[ROUTES, `const M = [deps.requireAuth, deps.requireActiveSubscription];`, `const M = [deps.requireAuth];`]],
  "status-anyones": [[ROUTES, `.update({ status: status, updated_at: now() }).eq("id", id).eq("user_id", req.user.id)`, `.update({ status: status, updated_at: now() }).eq("id", id)`]],
  "status-any-word": [[ROUTES, `if (typeof status !== "string" || IB.STATUSES.indexOf(status) === -1) return res.status(400)`, `if (typeof status !== "string") return res.status(400)`]],
  "customer-not-won": [[ROUTES, `      if (item.status !== "won") return res.status(409)`, `      if (false) return res.status(409)`]],
  "customer-twice": [[ROUTES, `      if (item.customer_id) return res.json({ created: false, customer: { id: item.customer_id }, item: IB.view(item) });\n`, ``]],
  "customer-race": [[ROUTES, `.eq("id", id).eq("user_id", userId).is("customer_id", null).select(IB.FIELDS);`, `.eq("id", id).eq("user_id", userId).select(IB.FIELDS);`]],
  "list-anyones": [[ROUTES, `let q = sb.from(IB.TABLE).select(IB.FIELDS).eq("user_id", userId);`, `let q = sb.from(IB.TABLE).select(IB.FIELDS);`]],
  "list-no-filter": [[ROUTES, `      if (status !== "all") q = q.eq("status", status);\n`, ``]],
  // server.js
  "sale-own": [[SERVER, `    if (order.seller_id === buyerId) return;\n`, ``]],
  "sale-no-notice": [[SERVER, `    await IB.notify(supabase, sendPushToUser, IB.saleNotice(order));\n`, ``]],
  "donation-no-item": [[SERVER, `    await IB.fromDonation(supabase, donation, title);\n`, ``]],
  "sale-awaited": [[SERVER, `    inboundAfterSale(req.user.id, listingId);`, `    await inboundAfterSale(req.user.id, listingId);`]],
  "message-hook-gone": [[SERVER, `    require("./lib/inbound").fire(require("./lib/inbound").fromMessage(supabase, data, { categoryName: inboundCategoryName }));\n`, ``]],
  "mentions-platform": [[SERVER, `      if (account.kind === "member") require("./lib/inbound").fire(`, `      require("./lib/inbound").fire(`]],
  "tip-hook-gone": [[SERVER, `          inboundAfterTip(req.user.id, member.user_id, me.data.username);`, ``]],
  "routes-not-listed": [[ACCESS, `"post /api/inbound/:id/customer",`, ``]],
  "leads-won-old": [[LEADR, `require("./inbound").wonCount(deps.sb, userId)`, `require("./inbound").wonCount(deps.sb, "00000000-0000-4000-8000-000000000000")`]],
  // the storefront
  "own-shows": [[SELLER, `  if (tok && me && me === seller.user_id) return;\n`, ``]],
  "self-shows": [[SELLER, `var msg = document.getElementById("sfMessage"); if (msg) msg.hidden = true; }`, `}`]],
  "own-from-profile": [[SELLER, `me = tok ? JSON.parse(atob(tok.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))).id || null : null;`, `me = (JSON.parse(localStorage.getItem("bf_user") || "null") || {}).id || null;`]],
  "signed-out-sends": [[SELLER, `if (!tok) signInPrompt(name); else composeMessage(seller, name, tok);`, `composeMessage(seller, name, tok);`]],
  "free-no-panel": [[SELLER, `d.close(); window.bfAccess.showPanel(); return; }`, `}`]],
  "no-return": [[SELLER, `d.el.querySelector("#sfDlgSignIn").addEventListener("click", function () { try { localStorage.setItem("bf_return_to", window.location.pathname + window.location.search); }`,
    `d.el.querySelector("#sfDlgSignIn").addEventListener("click", function () { try { void 0; }`]],
  "selector-gone": [[BFA, `".btn-message", "#sfMessage", "[data-members-only]"]`, `".btn-message", "[data-members-only]"]`]],
  // the backfill
  "backfill-writes-dry": [[BACKFILL, `    if (o.apply) {\n      const w = await IB.record(sb, row);`, `    if (true) {\n      const w = await IB.record(sb, row);`]],
  "backfill-every-message": [[BACKFILL, `    if (!first && !IB.needLinkIn(m.content)) continue;\n`, ``]],
  "backfill-conv-twice": [[BACKFILL, `    if (isConv && convPlanned.has(convKey)) { k.already++; continue; }\n`, ``]],
  "backfill-90": [[BACKFILL, `const BACKFILL_DAYS = 90;`, `const BACKFILL_DAYS = 900;`]],
  // the page and the data lists
  "page-no-move": [[RADAR, `return call("POST", "/api/inbound/" + encodeURIComponent(id) + "/status", { status: to })`, `return call("POST", "/api/inbound/" + encodeURIComponent(id) + "/move", { status: to })`]],
  "delete-forgets": [[YD, `"prospects", "inbound_items", "crm_activities"`, `"prospects", "crm_activities"`]],
  "migration-open": [[MIG, `REVOKE ALL ON public.inbound_items FROM anon, authenticated;\n`, ``]],
  "migration-no-conv": [[MIG, `CREATE UNIQUE INDEX IF NOT EXISTS inbound_items_one_per_conversation`, `CREATE INDEX IF NOT EXISTS inbound_items_one_per_conversation`]]
};

const T = H.setup(__filename, MUTATIONS, [LIB, ROUTES, "@lib/inbox.js", SERVER, ACCESS, LEADR, BACKFILL, MIG, YD, BK, SELLER, BFA, RADAR, PRIV]);
const { FILES, check, finish, J } = T;

/* ── an in-memory database: keeps rows, applies filters, enforces inbound_items' unique key and conversation index ── */
let idSeq = 0;
const uid = n => "00000000-0000-4000-8000-" + String(n).padStart(12, "0");
function memDb(seed, opts) {
  const o = opts || {};
  const t = {}; Object.keys(seed || {}).forEach(k => { t[k] = seed[k].map(r => Object.assign({}, r)); });
  const log = [];
  const rows = name => (t[name] = t[name] || []);
  function orParse(expr) { // "and(a.eq.x,b.eq.y),and(...)"
    return [...String(expr).matchAll(/and\(([^)]*)\)/g)].map(m => m[1].split(",").map(p => { const i = p.indexOf(".eq."); return [p.slice(0, i), p.slice(i + 4)]; }));
  }
  function matches(r, f) {
    const [m, c, v, w] = f;
    if (m === "eq") return String(r[c]) === String(v);
    if (m === "neq") return String(r[c]) !== String(v);
    if (m === "in") return v.map(String).indexOf(String(r[c])) !== -1;
    if (m === "is") return v === null ? r[c] == null : r[c] === v;
    if (m === "not" && v === "in") return String(w).replace(/[()]/g, "").split(",").indexOf(String(r[c])) === -1;
    if (m === "lt") return String(r[c]) < String(v);
    if (m === "lte") return String(r[c]) <= String(v);
    if (m === "gt") return String(r[c]) > String(v);
    if (m === "gte") return String(r[c]) >= String(v);
    if (m === "or") return orParse(c).some(group => group.every(([col, val]) => String(r[col]) === val));
    return true;
  }
  function conflict(name, row, except) {
    if (name !== "inbound_items") return false;
    return rows(name).some(x => x !== except && ((x.user_id === row.user_id && x.kind === row.kind && x.source_id === row.source_id) ||
      (UNIQUE_CONV && ["message", "i_can_help"].indexOf(x.kind) !== -1 && ["message", "i_can_help"].indexOf(row.kind) !== -1 && x.counterpart_user_id && x.user_id === row.user_id && x.counterpart_user_id === row.counterpart_user_id)));
  }
  const client = {
    from(name) {
      const q = { table: name, op: "select", payload: null, filters: [], order: null, limit: null, range: null, head: false, count: false, returning: false };
      log.push(q);
      const b = {};
      ["eq", "neq", "in", "is", "not", "lt", "lte", "gt", "gte"].forEach(m => { b[m] = function () { q.filters.push([m].concat([].slice.call(arguments))); return b; }; });
      b.or = function (expr) { q.filters.push(["or", expr]); return b; };
      b.order = function (c, oo) { q.order = [c, !(oo && oo.ascending === false)]; return b; };
      b.limit = function (n) { q.limit = n; return b; };
      b.range = function (a, z) { q.range = [a, z]; return b; };
      b.select = function (cols, so) { if (q.op === "select") { if (so && so.head) q.head = true; if (so && so.count) q.count = true; } else q.returning = true; return b; };
      ["insert", "update", "upsert", "delete"].forEach(m => { b[m] = function (p) { q.op = m; q.payload = p; return b; }; });
      function run(terminal) {
        if (o.boom && o.boom(name, q.op)) throw new Error("boom");
        if (o.fail && o.fail(name, q.op)) return { data: null, error: { code: "XX000", message: "down" } };
        const all = rows(name);
        if (q.op === "insert") {
          const list = (Array.isArray(q.payload) ? q.payload : [q.payload]).map(r => Object.assign({ id: uid(++idSeq) }, r));
          for (const r of list) if (conflict(name, r)) return { data: null, error: { code: "23505", message: "duplicate key" } };
          list.forEach(r => all.push(r));
          const out = list.map(r => Object.assign({}, r));
          return { data: q.returning ? (terminal ? out[0] : out) : null, error: null };
        }
        let hit = all.filter(r => q.filters.every(f => matches(r, f)));
        if (q.op === "update") {
          for (const r of hit) { const next = Object.assign({}, r, q.payload); if (conflict(name, next, r)) return { data: null, error: { code: "23505" } }; }
          hit.forEach(r => Object.assign(r, q.payload));
          return { data: q.returning ? hit.map(r => Object.assign({}, r)) : null, error: null };
        }
        if (q.op === "delete") { t[name] = all.filter(r => hit.indexOf(r) === -1); return { data: null, error: null }; }
        if (q.order) { const [c, asc] = q.order; hit = hit.slice().sort((a, z) => (String(a[c]) < String(z[c]) ? -1 : String(a[c]) > String(z[c]) ? 1 : 0) * (asc ? 1 : -1)); }
        if (q.range) hit = hit.slice(q.range[0], q.range[1] + 1);
        if (q.limit != null) hit = hit.slice(0, q.limit);
        if (q.head) return { data: null, error: null, count: hit.length };
        const data = hit.map(r => Object.assign({}, r));
        if (terminal === "single") return data.length === 1 ? { data: data[0], error: null } : { data: null, error: { code: "PGRST116" } };
        if (terminal === "maybeSingle") return { data: data[0] || null, error: null };
        return { data, error: null, count: q.count ? data.length : undefined };
      }
      const later = terminal => new Promise((res, rej) => setImmediate(() => { try { res(run(terminal)); } catch (e) { rej(e); } }));
      b.single = () => later("single");
      b.maybeSingle = () => later("maybeSingle");
      b.then = (res, rej) => later(null).then(res, rej);
      return b;
    }
  };
  return { client, log, t, rows };
}
// the migration's conversation index, as written (a mutation that drops UNIQUE also drops it here)
const UNIQUE_CONV = /CREATE UNIQUE INDEX IF NOT EXISTS inbound_items_one_per_conversation\s+ON public\.inbound_items \(user_id, counterpart_user_id\) WHERE kind IN \('message', 'i_can_help'\);/.test(FILES[MIG] || "");

const IB = T.libRequire("./inbound");
const A = uid(901), B = uid(902), C = uid(903), D = uid(904);   // A: the member; B, C, D: other people
const NEED = uid(950), POST = uid(951);
const items = (db, who) => db.rows("inbound_items").filter(r => !who || r.user_id === who);
const tick = () => new Promise(r => setImmediate(r));
async function settle(n) { for (let i = 0; i < (n || 30); i++) await tick(); }
const people = { bf_profiles: [{ user_id: B, username: "anap", display_name: "Ana Perez" }, { user_id: C, username: "dionk", display_name: "Dion Kay" }, { user_id: A, username: "me", display_name: "Me Member" }], profiles: [] };

/* ── the server's helpers (the INBOUND block), run in a vm on the fake database and a recorded push ── */
function serverHelpers(db, pushes) {
  const src = FILES[SERVER] || "";
  const from = src.indexOf("async function inboundCategoryName(");
  const lastAt = src.indexOf("function inboundAfterCardLead(");
  const end = lastAt < 0 ? -1 : SH.braceMatch(src, src.indexOf("{", lastAt));
  if (from < 0 || end < 0) return null;
  const ctx = { supabase: db.client, sendPushToUser: async (u, p) => { pushes.push([u, p]); return { sent: 1 }; }, require: T.libRequire, console: { log() {}, warn() {}, error() {} }, Promise, Date };
  vm.createContext(ctx);
  vm.runInContext(src.slice(from, end + 1), ctx);
  return ctx;
}

/* ── a fake app for the routes: middlewares run in order (a free account stops at requireActiveSubscription) ── */
function mountRoutes(db) {
  const reg = {};
  const app = {};
  ["get", "post"].forEach(m => { app[m] = function (p) { const fns = [].slice.call(arguments, 1).flat(); reg[m + " " + p] = fns; }; });
  const requireAuth = (req, res, next) => (req.user ? next() : res.status(401).json({ error: "Sign in" }));
  const requireActiveSubscription = (req, res, next) => (req.user.tier === "free" ? res.status(402).json({ members_only: true }) : next());
  T.libRequire("./inboundRoutes").mountInboundRoutes(app, { sb: db.client, requireAuth, requireActiveSubscription, now: () => "2026-11-24T12:00:00.000Z" });
  return async function call(key, req) {
    const fns = reg[key];
    if (!fns) return { status: 0, body: null, missing: true };
    const r = Object.assign({ user: { id: A }, params: {}, query: {}, body: {} }, req);
    const res = { statusCode: 200, body: undefined, headers: {}, status(c) { this.statusCode = c; return this; }, json(b) { this.body = JSON.parse(JSON.stringify(b)); return this; }, set(k, v) { this.headers[k] = v; return this; } };
    let err = null;
    for (const fn of fns) {
      let went = false;
      await fn(r, res, e => { if (e) err = e; else went = true; });
      if (err || !went) break;
    }
    return { status: res.statusCode, body: res.body, err, routes: Object.keys(reg) };
  };
}

(async function main() {
  /* ── A. migration 205 ── */
  console.log("\n== A. migration 205 ==");
  const mig = FILES[MIG] || "";
  const sql = mig.split("\n").filter(l => !/^\s*--/.test(l)).join("\n");
  check("A1. three parts, 205a, 205b and 205c, in order; no BEGIN, COMMIT or DO block; no <= or >=",
    /PART 205a[\s\S]*PART 205b[\s\S]*PART 205c/.test(mig) && !/\bBEGIN\b|\bCOMMIT\b|\bDO\s*(\$\$|\$[a-z_]*\$)/i.test(sql) && !/<=|>=/.test(mig));
  check("A2. inbound_items: id, user_id, kind, source_id, counterpart_user_id (nullable), counterpart_label, summary, amount_bfc (nullable integer), status, created_at, updated_at",
    /CREATE TABLE IF NOT EXISTS public\.inbound_items \(/.test(sql) && ["id uuid PRIMARY KEY", "user_id uuid NOT NULL", "kind text NOT NULL", "source_id uuid NOT NULL", "counterpart_user_id uuid REFERENCES",
      "counterpart_label text NOT NULL", "summary text NOT NULL", "amount_bfc integer,", "status text NOT NULL DEFAULT 'new'", "created_at timestamptz NOT NULL", "updated_at timestamptz NOT NULL"].every(x => sql.indexOf(x) !== -1));
  const named = ["kind_check", "status_check", "text_check", "amount_check", "not_self_check", "user_kind_source_key"];
  check("A3. every named constraint is dropped IF EXISTS before it is added; the seven kinds and four statuses; the summary up to 200",
    named.every(n => { const d = sql.indexOf("DROP CONSTRAINT IF EXISTS inbound_items_" + n + ";"), a = sql.indexOf("ADD CONSTRAINT inbound_items_" + n); return d !== -1 && a > d; }) &&
    sql.indexOf("CHECK (kind IN ('message', 'i_can_help', 'sale', 'card_lead', 'campaign', 'tip', 'lead_reply'))") !== -1 &&
    sql.indexOf("CHECK (status IN ('new', 'talking', 'won', 'lost'))") !== -1 && sql.indexOf("char_length(summary) < 201") !== -1 &&
    J(IB.KINDS) === J(["message", "i_can_help", "sale", "card_lead", "campaign", "tip", "lead_reply"]) && IB.SUMMARY_MAX === 200);
  check("A4. unique (user_id, kind, source_id); one item per conversation (a unique partial index); the list's indexes by status and by time",
    sql.indexOf("UNIQUE (user_id, kind, source_id)") !== -1 && UNIQUE_CONV &&
    sql.indexOf("CREATE INDEX IF NOT EXISTS inbound_items_user_status_idx ON public.inbound_items (user_id, status, created_at DESC);") !== -1 &&
    sql.indexOf("CREATE INDEX IF NOT EXISTS inbound_items_user_created_idx ON public.inbound_items (user_id, created_at DESC);") !== -1);
  check("A5. RLS on with no policies; ALL revoked from anon and authenticated",
    sql.indexOf("ALTER TABLE public.inbound_items ENABLE ROW LEVEL SECURITY;") !== -1 && !/CREATE POLICY/i.test(sql) &&
    sql.indexOf("REVOKE ALL ON public.inbound_items FROM anon, authenticated;") !== -1);

  /* ── B. each kind once, never the member's own, one per conversation ── */
  console.log("\n== B. what makes an item ==");
  {
    const db = memDb(Object.assign({ messages: [], posts: [{ id: NEED, author_id: A, intent: "need", category: "photography" }, { id: POST, author_id: C, intent: "need", category: "x" }] }, people));
    const send = async (id, from, to, content, at) => { const m = { id: uid(id), sender_id: from, receiver_id: to, content, created_at: at }; db.rows("messages").push(m); return IB.fromMessage(db.client, m, { categoryName: async s => (s === "photography" ? "Photography" : null) }); };
    const r1 = await send(1, B, A, "Do you have openings next Friday?", "2026-11-24T10:00:00.000Z");
    const r2 = await send(2, B, A, "Also, how much?", "2026-11-24T10:01:00.000Z");
    const r3 = await send(3, A, B, "Yes I do", "2026-11-24T10:02:00.000Z");
    const mine = items(db, A), theirs = items(db, B);
    check("B1. message: the first message of a conversation someone else began makes ONE item for the receiver; the next message and the reply make none",
      r1.created === true && r2.created === false && r3.created === false && mine.length === 1 && theirs.length === 0 &&
      mine[0].kind === "message" && mine[0].status === "new" && mine[0].counterpart_user_id === B && mine[0].counterpart_label === "Ana P." && mine[0].summary === "Do you have openings next Friday?",
      J({ r1, r2, r3, mine, theirs }));
    const r4 = await send(4, C, A, "Hi, I saw your Need: https://bizforceai.net/p/" + NEED, "2026-11-24T11:00:00.000Z");
    const ich = items(db, A).filter(i => i.kind === "i_can_help");
    check("B2. i_can_help: a message linking the receiver's own Need makes an I can help item, its summary naming the Need's category",
      r4.created === true && ich.length === 1 && ich[0].counterpart_user_id === C && ich[0].summary === "Replied to your Need in Photography." && ich[0].status === "new", J({ r4, ich }));
    const r5 = await send(5, D, A, "About this: https://bizforceai.net/p/" + POST, "2026-11-24T11:05:00.000Z");
    check("B3. ...a link to someone else's Need is a plain first message, not I can help", r5.created === true && items(db, A).filter(i => i.counterpart_user_id === D).map(i => i.kind).join() === "message");
    const r6 = await send(6, C, A, "And again https://bizforceai.net/p/" + NEED, "2026-11-24T11:10:00.000Z");
    check("B4. one item per conversation: a second I can help in the same conversation makes nothing", r6.created === false && items(db, A).filter(i => i.counterpart_user_id === C).length === 1, J(r6));
    const r7 = await send(7, A, A, "note to self", "2026-11-24T11:20:00.000Z");
    check("B5. never the member's own action: a message to yourself makes nothing", r7.created === false && items(db, A).length === 3, J(r7));
    // two first messages that race: the conversation index keeps one
    const ra = await IB.record(db.client, IB.itemRow({ userId: B, kind: "message", sourceId: uid(60), counterpartId: D, label: "x", summary: "one" }));
    const rb = await IB.record(db.client, IB.itemRow({ userId: B, kind: "message", sourceId: uid(61), counterpartId: D, label: "x", summary: "two" }));
    const rc = await IB.record(db.client, IB.itemRow({ userId: B, kind: "message", sourceId: uid(60), counterpartId: D, label: "x", summary: "one" }));
    check("B6. a second copy is refused, never an error: the same source again, or a second first message that raced the first (reason exists)",
      ra.created === true && rb.created === false && rb.reason === "exists" && rc.created === false && rc.reason === "exists", J({ ra, rb, rc }));
    const long = IB.itemRow({ userId: A, kind: "card_lead", sourceId: uid(62), label: "y".repeat(300), summary: "z".repeat(500) });
    check("B7. the summary is up to 200 and the label up to 80, as the table holds them", long.summary.length === 200 && long.counterpart_label.length === 80, J([long.summary.length, long.counterpart_label.length]));
    check("B8. a bad kind or id makes nothing", IB.itemRow({ userId: A, kind: "gift", sourceId: uid(63) }) === null && IB.itemRow({ userId: "x", kind: "sale", sourceId: uid(63) }) === null);
    check("B9. the row itself refuses the member's own action, whatever the writer (counterpart = the member)",
      IB.KINDS.every(k => IB.itemRow({ userId: A, kind: k, sourceId: uid(64), counterpartId: A }) === null) && IB.itemRow({ userId: A, kind: "tip", sourceId: uid(64), counterpartId: B }) !== null);
  }

  /* ── C. sales, donations, tips and card leads through the server's helpers ── */
  console.log("\n== C. a sale, a donation, a tip, a card lead ==");
  {
    const O1 = uid(100), O2 = uid(101), DN = uid(110), DN2 = uid(111), CAMP = uid(120), TP = uid(130), TP2 = uid(131), CARD = uid(140), CL = uid(141), LST = uid(150);
    const db = memDb(Object.assign({
      marketplace_orders: [{ id: O1, buyer_id: B, seller_id: A, listing_id: LST, listing_title: "Aftercare Kit", amount_bfc: 40, status: "paid", created_at: "2026-11-24T09:00:00.000Z" },
        { id: O2, buyer_id: A, seller_id: A, listing_id: uid(151), listing_title: "Mine", amount_bfc: 5, status: "paid", created_at: "2026-11-24T09:01:00.000Z" }],
      campaign_donations: [{ id: DN, campaign_id: CAMP, donor_id: B, owner_id: A, amount_bfc: 25, created_at: "2026-11-24T09:02:00.000Z" },
        { id: DN2, campaign_id: CAMP, donor_id: A, owner_id: A, amount_bfc: 3, created_at: "2026-11-24T09:03:00.000Z" }],
      crowdfunding_campaigns: [{ id: CAMP, title: "New Studio Chairs" }],
      bfc_transfers: [{ id: TP, sender_id: B, recipient_id: A, amount_bfc: 10, note: "thanks!", kind: "support", created_at: "2026-11-24T09:04:00.000Z" },
        { id: TP2, sender_id: A, recipient_id: A, amount_bfc: 10, note: "", kind: "support", created_at: "2026-11-24T09:05:00.000Z" }],
      card_leads: [{ id: CL, card_id: CARD, user_id: A, name: "Kim Lee", email: "kim@example.com", phone: "555-0100", message: "prices?", created_at: "2026-11-24T09:06:00.000Z" }],
      notifications: []
    }, people));
    const pushes = [];
    const S = serverHelpers(db, pushes);
    check("C0. server.js holds the INBOUND helpers (inboundAfterSale, inboundAfterDonation, inboundAfterTip, inboundAfterCardLead)", !!S && ["inboundAfterSale", "inboundAfterDonation", "inboundAfterTip", "inboundAfterCardLead"].every(n => typeof S[n] === "function"));
    if (S) {
      S.inboundAfterSale(B, LST); S.inboundAfterSale(A, uid(151));
      S.inboundAfterDonation(B, CAMP); S.inboundAfterDonation(A, CAMP);
      S.inboundAfterTip(B, A, "anap"); S.inboundAfterTip(A, A, "me");
      S.inboundAfterCardLead(CARD, A, "2026-11-24T09:06:00.000Z");
      await settle(60);
    }
    const it = k => items(db, A).filter(i => i.kind === k);
    const notes = db.rows("notifications");
    check("C1. sale: one item for the seller, won at once, \"Bought: Aftercare Kit · 40 BFC\", from \"a buyer\"; none for buying your own listing",
      it("sale").length === 1 && it("sale")[0].status === "won" && it("sale")[0].summary === "Bought: Aftercare Kit · 40 BFC" && it("sale")[0].counterpart_label === "a buyer" && it("sale")[0].amount_bfc === 40 && it("sale")[0].source_id === O1, J(it("sale")));
    check("C2. campaign: one item for the owner, won at once, \"Gave 25 BFC to New Studio Chairs.\"; none for giving to your own campaign",
      it("campaign").length === 1 && it("campaign")[0].status === "won" && it("campaign")[0].summary === "Gave 25 BFC to New Studio Chairs." && it("campaign")[0].source_id === DN, J(it("campaign")));
    check("C3. tip: one item for the member it went to, won at once, from @anap; none for a tip to yourself",
      it("tip").length === 1 && it("tip")[0].status === "won" && it("tip")[0].counterpart_label === "@anap" && it("tip")[0].summary === "Sent you 10 BFC: thanks!", J(it("tip")));
    check("C4. card_lead: one item, New, from \"your digital card\", naming what they left", it("card_lead").length === 1 && it("card_lead")[0].status === "new" &&
      it("card_lead")[0].counterpart_label === "your digital card" && it("card_lead")[0].summary === "Left a phone number and an email: prices?", J(it("card_lead")));
    const sale = notes.find(n => n.type === "sale"), don = notes.find(n => n.type === "donation");
    check("C5. the sale notice: type sale, object type order, for the seller, \"You made a sale\", linking /receipts.html; one only (none for your own purchase)",
      notes.filter(n => n.type === "sale").length === 1 && !!sale && sale.user_id === A && sale.object_type === "order" && sale.object_id === O1 && sale.title === "You made a sale" && sale.link === "/receipts.html" && sale.read === false, J(notes));
    check("C6. the donation notice: type donation, object type campaign, for the owner, linking /campaigns.html; one only",
      notes.filter(n => n.type === "donation").length === 1 && !!don && don.user_id === A && don.object_type === "campaign" && don.object_id === CAMP && don.link === "/campaigns.html", J(notes));
    check("C7. ...each pushed the way a like or a comment is (sendPushToUser with its title, body and link), two pushes only",
      pushes.length === 2 && pushes.every(p => p[0] === A && typeof p[1].title === "string" && typeof p[1].body === "string" && typeof p[1].url === "string") &&
      pushes.map(p => p[1].url).sort().join() === "/campaigns.html,/receipts.html", J(pushes));
    const libCode = FILES[LIB] || "";
    check("C8. no email and no SMS: lib/inbound.js and the INBOUND block send neither", !/sendEmail|sendMail|resend|twilio|sendSms|\bsms\b/i.test(libCode.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "")) &&
      !/sendEmail|twilio|sendSms/i.test(((FILES[SERVER] || "").split("/* ── INBOUND (LR-3")[1] || "").split("app.post(\"/api/content-library\"")[0]));
    const src = FILES[SERVER] || "";
    const at = (anchor, before) => { const i = src.indexOf(anchor); return i !== -1 && src.slice(Math.max(0, i - 3000), i).indexOf(before) !== -1; };
    check("C9. each hook runs after its action has succeeded, and none is awaited (it never delays or fails the action)",
      at("    inboundAfterSale(req.user.id, listingId);", "bfc_buy_listing") && at("    inboundAfterDonation(req.user.id, campaign.id);", "bfc_donate") &&
      at("inboundAfterTip(req.user.id, member.user_id, me.data.username);", "support") && at("    inboundAfterCardLead(leadCard.id, leadCard.user_id, new Date(leadNowMs).toISOString());", "if (storedLead.error) throw storedLead.error;") &&
      at("    require(\"./lib/inbound\").fire(require(\"./lib/inbound\").fromMessage(supabase, data, { categoryName: inboundCategoryName }));", "await policyQueue(screened, \"message\", data.id, req.user.id);") &&
      !/await\s+inboundAfter/.test(src) && !/await\s+require\("\.\/lib\/inbound"\)\.fire/.test(src));
    // the card lead keeps its own hourly-capped notice
    check("C10. a card lead keeps its existing notice (noticeCardLead) and adds no second one", /await noticeCardLead\(leadCard\.user_id, leadNowMs\);\n    inboundAfterCardLead\(/.test(src) && notes.filter(n => n.object_type === "card_lead").length === 0);
  }

  /* ── D. replies on Bluesky ── */
  console.log("\n== D. a reply to the member's Lead Radar reply ==");
  {
    const R1 = uid(200), R2 = uid(201), L1 = uid(210), L2 = uid(211);
    const P1 = "at://did:plc:abc/app.bsky.feed.post/3kaaa", P2 = "at://did:plc:abc/app.bsky.feed.post/3kbbb", P3 = "at://did:plc:abc/app.bsky.feed.post/3kddd";
    const db = memDb({
      member_lead_replies: [{ id: R1, user_id: A, member_lead_id: L1, platform: "bluesky", platform_uri: P1 }, { id: R2, user_id: A, member_lead_id: L2, platform: "bluesky", platform_uri: P2 },
        { id: uid(203), user_id: A, member_lead_id: null, platform: "bluesky", platform_uri: P3 },
        { id: uid(202), user_id: B, member_lead_id: uid(212), platform: "bluesky", platform_uri: "at://did:plc:zzz/app.bsky.feed.post/3kccc" }],
      member_leads: [{ id: L1, user_id: A, status: "new" }, { id: L2, user_id: A, status: "won" }, { id: uid(212), user_id: B, status: "new" }]
    });
    const notif = (reason, parent, handle) => ({ reason, author: { handle }, indexedAt: "2026-11-24T08:00:00.000Z", record: { reply: { parent: { uri: parent } } } });
    const list = [notif("reply", P1, "sam.bsky.social"), notif("reply", P2, "lee.bsky.social"), notif("mention", P3, "x.bsky.social"), notif("reply", "at://did:plc:zzz/app.bsky.feed.post/3kccc", "y.bsky.social")];
    const r = await IB.fromMentions(db.client, A, list);
    const again = await IB.fromMentions(db.client, A, list);
    const mine = items(db, A);
    check("D1. a reply to the member's own reply makes one lead_reply item (source: their member_lead_replies row), with the replier's handle; a mention or someone else's reply makes none",
      r.created === 2 && mine.length === 2 && mine.every(i => i.kind === "lead_reply" && i.status === "new" && i.summary === "Replied to your reply on Bluesky.") &&
      mine.map(i => i.source_id).sort().join() === [R1, R2].sort().join() && mine.some(i => i.counterpart_label === "@sam.bsky.social") && items(db, B).length === 0, J({ r, mine }));
    check("D2. ...once: the same replies read again make nothing", again.created === 0 && items(db).length === 2, J(again));
    const leads = db.rows("member_leads");
    check("D3. the linked lead becomes replied, but a won lead stays won (and someone else's lead is untouched)",
      leads.find(l => l.id === L1).status === "replied" && leads.find(l => l.id === L2).status === "won" && leads.find(l => l.id === uid(212)).status === "new", J(leads));
    check("D4. only a member's own account reads into Inbound (the platform account's mentions never do)",
      /if \(account\.kind === "member"\) require\("\.\/lib\/inbound"\)\.fire\(require\("\.\/lib\/inbound"\)\.fromMentions\(supabase, userId, data\.notifications\)\);/.test(FILES[SERVER] || ""));
    const v = IB.view({ kind: "lead_reply", status: "new" }, P1);
    check("D5. tapping it opens the reply on bsky.app in a new tab", v.open.href === "https://bsky.app/profile/did:plc:abc/post/3kaaa" && v.open.external === true, J(v.open));
  }

  /* ── E. the routes ── */
  console.log("\n== E. the routes ==");
  const mkItem = (n, o) => Object.assign({ id: uid(n), user_id: A, kind: "message", source_id: uid(n + 5000), counterpart_user_id: B, counterpart_label: "Ana P.", summary: "s" + n, amount_bfc: null, status: "new", customer_id: null,
    created_at: "2026-11-24T0" + (n % 10) + ":00:00.000Z", updated_at: "2026-11-24T00:00:00.000Z" }, o || {});
  {
    const db = memDb({ inbound_items: [mkItem(1), mkItem(2, { status: "talking", kind: "i_can_help", counterpart_user_id: C }), mkItem(3, { status: "won", kind: "sale", counterpart_label: "a buyer", amount_bfc: 40 }), mkItem(4, { user_id: B, counterpart_user_id: C })], member_lead_replies: [] });
    const call = mountRoutes(db);
    const keys = ["get /api/inbound", "get /api/inbound/summary", "post /api/inbound/:id/status", "post /api/inbound/:id/customer"];
    const free = [];
    for (const k of keys) free.push(await call(k, { user: { id: A, tier: "free" }, params: { id: uid(1) }, body: { status: "won" } }));
    const before = db.log.length;
    const out = [];
    for (const k of keys) out.push(await call(k, { user: null, params: { id: uid(1) } }));
    const acc = T.libRequire("./routeAccess");
    check("E1. members only: the four routes are M in lib/routeAccess.js, and a free account (402) or no account (401) never reaches them",
      keys.every(k => acc.MEMBER.indexOf(k) !== -1) && free.every(r => r.status === 402) && out.every(r => r.status === 401) && db.log.length === before && items(db).every(i => i.status === mkItem(1).status || i.id !== uid(1)),
      J({ free: free.map(r => r.status), out: out.map(r => r.status), M: keys.map(k => acc.MEMBER.indexOf(k) !== -1) }));
    const all = await call("get /api/inbound", {});
    const won = await call("get /api/inbound", { query: { status: "won" } });
    const bad = await call("get /api/inbound", { query: { status: "maybe" } });
    check("E2. the list: the member's own items only, newest first, with the counts; ?status filters; a bad status is 400",
      all.status === 200 && all.body.items.map(i => i.id).join() === [uid(3), uid(2), uid(1)].join() && J(all.body.counts) === J({ new: 1, talking: 1, won: 1, lost: 0 }) &&
      won.body.items.length === 1 && won.body.items[0].kind === "sale" && won.body.items[0].can_add_customer === true && won.body.items[0].open.href === "/receipts.html" && bad.status === 400, J({ all: all.body, won: won.body }));
    const pg = await call("get /api/inbound", { query: { limit: "2" } });
    check("E3. ...paged: ?limit and next_before", pg.body.items.length === 2 && pg.body.next_before === pg.body.items[1].created_at, J(pg.body));
    const mv = [];
    for (const s of ["talking", "won", "lost", "new"]) { const r = await call("post /api/inbound/:id/status", { params: { id: uid(1) }, body: { status: s } }); mv.push([r.status, r.body && r.body.item && r.body.item.status, db.rows("inbound_items").find(i => i.id === uid(1)).status]); }
    check("E4. the status moves: Talking, Won, Lost, back to New, each saved", J(mv) === J([[200, "talking", "talking"], [200, "won", "won"], [200, "lost", "lost"], [200, "new", "new"]]), J(mv));
    const wrong = await call("post /api/inbound/:id/status", { params: { id: uid(1) }, body: { status: "archived" } });
    const theirs = await call("post /api/inbound/:id/status", { params: { id: uid(4) }, body: { status: "won" } });
    const junk = await call("post /api/inbound/:id/status", { params: { id: "abc" }, body: { status: "won" } });
    check("E5. ownership: someone else's item is a 404 and stays as it was; a bad id is 404; a bad status is 400",
      theirs.status === 404 && db.rows("inbound_items").find(i => i.id === uid(4)).status === "new" && junk.status === 404 && wrong.status === 400, J([theirs, junk.status, wrong.status]));
    const s1 = await call("get /api/inbound/summary", {});
    check("E6. the summary: the counts and the won total", s1.status === 200 && J(s1.body.counts) === J({ new: 1, talking: 1, won: 1, lost: 0 }) && s1.body.won_total === 1, J(s1.body));
  }

  /* ── F. Add to my customers ── */
  console.log("\n== F. Add to my customers ==");
  {
    const CL = uid(300);
    const db = memDb({ inbound_items: [mkItem(1, { status: "won", kind: "sale", counterpart_label: "a buyer", summary: "Bought: Kit · 40 BFC" }), mkItem(2), mkItem(3, { status: "won", kind: "card_lead", source_id: CL, counterpart_user_id: null, counterpart_label: "your digital card" }), mkItem(4, { user_id: B, status: "won" })],
      card_leads: [{ id: CL, user_id: A, name: "Kim Lee", email: "kim@example.com", phone: "555-0100" }], crm_customers: [] });
    const call = mountRoutes(db);
    const c1 = await call("post /api/inbound/:id/customer", { params: { id: uid(1) } });
    const c2 = await call("post /api/inbound/:id/customer", { params: { id: uid(1) } });
    const cust = db.rows("crm_customers");
    check("F0. ...the second tap on an item already added writes no customer at all (not one made and removed)", db.log.filter(q => q.table === "crm_customers" && q.op !== "select").length === 1,
      J(db.log.filter(q => q.table === "crm_customers").map(q => q.op)));
    check("F1. a won item makes ONE crm_customers row (201), the member's own, active, sourced from Inbound; the second tap makes none",
      c1.status === 201 && c1.body.created === true && c2.status === 200 && c2.body.created === false && cust.length === 1 && cust[0].user_id === A && cust[0].status === "active" &&
      cust[0].name === "A buyer" && cust[0].source === "Lead Radar Inbound: Sale" && c1.body.item.customer_added === true && c1.body.item.can_add_customer === false, J({ c1: c1.body, c2: c2.body, cust }));
    const nw = await call("post /api/inbound/:id/customer", { params: { id: uid(2) } });
    const th = await call("post /api/inbound/:id/customer", { params: { id: uid(4) } });
    check("F2. an item not won is 409 not_won; someone else's is 404; neither makes a customer", nw.status === 409 && nw.body.code === "not_won" && th.status === 404 && db.rows("crm_customers").length === 1, J([nw, th.status]));
    const c3 = await call("post /api/inbound/:id/customer", { params: { id: uid(3) } });
    const kim = db.rows("crm_customers").find(c => c.name === "Kim Lee");
    check("F3. a card lead's customer carries the lead's own name, email and phone", c3.status === 201 && !!kim && kim.email === "kim@example.com" && kim.phone === "555-0100", J(db.rows("crm_customers")));
    // two taps racing: the second's link finds the item already linked and removes its own row
    const db2 = memDb({ inbound_items: [mkItem(1, { status: "won" })], crm_customers: [] });
    const call2 = mountRoutes(db2);
    const [x, y] = await Promise.all([call2("post /api/inbound/:id/customer", { params: { id: uid(1) } }), call2("post /api/inbound/:id/customer", { params: { id: uid(1) } })]);
    check("F4. two taps at once still make one customer", db2.rows("crm_customers").length === 1 && [x.body.created, y.body.created].filter(Boolean).length === 1 &&
      db2.rows("inbound_items")[0].customer_id === db2.rows("crm_customers")[0].id, J({ x: x.body, y: y.body, c: db2.rows("crm_customers") }));
  }

  /* ── G. the Leads tab's won ── */
  console.log("\n== G. won, counted once ==");
  {
    const R1 = uid(400), L1 = uid(410), L2 = uid(411);
    const db = memDb({
      member_leads: [{ id: L1, user_id: A, status: "won" }, { id: L2, user_id: A, status: "won" }, { id: uid(412), user_id: A, status: "new" }, { id: uid(413), user_id: B, status: "won" }],
      member_lead_replies: [{ id: R1, user_id: A, member_lead_id: L1 }, { id: uid(401), user_id: A, member_lead_id: uid(412) }],
      inbound_items: [mkItem(1, { status: "won", kind: "sale" }), mkItem(2, { status: "won", kind: "lead_reply", source_id: R1, counterpart_user_id: null }),
        mkItem(3, { status: "won", kind: "lead_reply", source_id: uid(401), counterpart_user_id: null }), mkItem(4, { status: "new" }), mkItem(5, { user_id: B, status: "won" })]
    });
    const n = await IB.wonCount(db.client, A);
    check("G1. won = leads won (2) + items won (3) - the lead_reply whose lead is also won (1) = 4", n === 4, J(n));
    const lr = FILES[LEADR] || "";
    check("G2. GET /api/leads' won stat is that same count (lib/leadRoutes.js)", /require\("\.\/inbound"\)\.wonCount\(deps\.sb, userId\)\.then\(/.test(lr));
  }

  /* ── H. never throws, never delays ── */
  console.log("\n== H. never throws ==");
  {
    const boom = memDb(people, { boom: () => true });
    const down = memDb(Object.assign({ messages: [] }, people), { fail: (t, op) => t === "inbound_items" || t === "notifications" });
    let threw = null;
    const out = [];
    try {
      out.push(await IB.record(boom.client, IB.itemRow({ userId: A, kind: "sale", sourceId: uid(1), counterpartId: B })));
      out.push(await IB.fromMessage(boom.client, { id: uid(2), sender_id: B, receiver_id: A, content: "hi" }));
      out.push(await IB.fromOrder(down.client, { id: uid(3), buyer_id: B, seller_id: A, listing_title: "x", amount_bfc: 2 }));
      out.push(await IB.fromMentions(boom.client, A, [{ reason: "reply", record: { reply: { parent: { uri: "at://x" } } } }]));
      out.push(await IB.notify(down.client, async () => { throw new Error("push down"); }, IB.saleNotice({ id: uid(4), seller_id: A, amount_bfc: 2 })));
      out.push(await IB.notify(memDb({}).client, async () => { throw new Error("push down"); }, IB.saleNotice({ id: uid(4), seller_id: A, amount_bfc: 2 })));
      IB.fire(Promise.reject(new Error("late")));
      await settle(5);
    } catch (e) { threw = e.message; }
    check("H1. every writer answers instead of throwing when the database throws or fails, and a failed push still keeps the notice",
      threw === null && out[0].created === false && out[0].reason === "error" && out[1].created === false && out[2].created === false && out[3].created === 0 && out[4] === false && out[5] === true, J({ threw, out }));
  }

  /* ── I. the storefront's Message button ── */
  console.log("\n== I. the storefront's Message button ==");
  {
    const page = FILES[SELLER] || "";
    const grab = name => { const at = page.indexOf("function " + name + "("); if (at < 0) return ""; const end = SH.braceMatch(page, page.indexOf("{", at)); return end < 0 ? "" : page.slice(at, end + 1); };
    const code = ["esc", "mountMessage", "sfDialog", "signInPrompt", "composeMessage"].map(grab).join("\n");
    const SELLER_ID = uid(500);
    function el(tag) {
      return { tag, id: "", className: "", type: "", href: "", children: [], kids: {}, handlers: {}, textContent: "", value: "", disabled: false, parentNode: null, innerHTML: "",
        addEventListener(t, f) { (this.handlers[t] = this.handlers[t] || []).push(f); },
        appendChild(c) { c.parentNode = this; this.children.push(c); return c; },
        insertBefore(c, ref) { c.parentNode = this; const i = ref ? this.children.indexOf(ref) : -1; if (i < 0) this.children.push(c); else this.children.splice(i, 0, c); return c; },
        removeChild(c) { this.children = this.children.filter(x => x !== c); c.parentNode = null; },
        querySelector(sel) { const m = /^#(\w+)$/.exec(sel); if (m && this.innerHTML.indexOf('id="' + m[1] + '"') !== -1) return this.kids[m[1]] || (this.kids[m[1]] = Object.assign(el("x"), { id: m[1] })); return null; },
        focus() {}, closest() { return null; } };
    }
    async function visit(account) {
      const head = el("div"), follow = Object.assign(el("button"), { id: "sfFollow" }), body = el("body");
      head.appendChild(follow);
      // the token as the server signs it (its payload carries the member's id); bf_user is the profile row, whose id is another
      const store = {}; if (account.tok) store.bf_token = "x." + Buffer.from(JSON.stringify({ id: account.me })).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_") + ".y";
      store.bf_user = JSON.stringify({ id: uid(599), user_id: account.me });
      const fetches = [], panel = [];
      const win = { location: { href: "/seller.html?u=anap", pathname: "/seller.html", search: "?u=anap" }, bfAccess: { showPanel() { panel.push(1); } } };
      const find = id => { const walk = n => (n.id === id ? n : n.children.map(walk).find(Boolean)); return walk(head) || walk(body) || null; };
      const ctx = { window: win, localStorage: { getItem: k => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = v; } }, API_URL: "https://api.example",
        JSON, String, encodeURIComponent, setTimeout, atob: s => Buffer.from(s, "base64").toString("binary"),
        fetch: (url, o) => { fetches.push([url, o]); return Promise.resolve({ ok: account.answer === 200, status: account.answer, json: () => Promise.resolve(account.answer === 403 ? { reason: "members_only", error: "Members start conversations." } : {}) }); },
        document: { body, activeElement: null, querySelector: s => (s === ".sf-header" ? head : null), getElementById: find, createElement: el, addEventListener() {}, removeEventListener() {} } };
      vm.createContext(ctx);
      vm.runInContext(code + "\nmountMessage({ user_id: " + J(SELLER_ID) + ", display_name: \"Ana Perez\", username: \"anap\" });", ctx);
      const btn = find("sfMessage");
      const r = { btn: !!btn, beforeFollow: !!btn && head.children.indexOf(btn) === head.children.indexOf(follow) - 1, fetches, panel, store, win, dialog: null };
      if (btn) {
        btn.handlers.click.forEach(f => f({}));
        const veil = body.children[0];
        r.dialog = veil ? veil.innerHTML : null;
        if (veil && account.tok) {
          veil.querySelector("#sfDlgBody").value = "  Do you ship?  ";
          veil.querySelector("#sfDlgSend").handlers.click.forEach(f => f({}));
          await settle(10);
          r.open = !!body.children.length;
        } else if (veil) {
          veil.querySelector("#sfDlgSignIn").handlers.click.forEach(f => f({}));
          r.signIn = veil.querySelector("#sfDlgSignIn");
        }
      }
      return r;
    }
    const member = await visit({ tok: true, me: uid(501), answer: 200 });
    const sent = member.fetches[0] || [];
    check("I1. a member: Message sits before Follow, opens a writing box, and sends through the existing POST /api/messages to the seller, then opens the conversation",
      member.btn && member.beforeFollow && /Message Ana Perez/.test(member.dialog || "") && sent[0] === "https://api.example/api/messages" && sent[1].method === "POST" &&
      J(JSON.parse(sent[1].body)) === J({ receiver_id: SELLER_ID, content: "Do you ship?" }) && member.win.location.href === "/inbox.html?with=" + SELLER_ID, J({ member: Object.assign({}, member, { win: member.win.location }) }));
    const freeAcct = await visit({ tok: true, me: uid(502), answer: 403 });
    const bfa = FILES[BFA] || "";
    check("I2. a free account: bf-access.js MEMBER_ACTIONS holds \"#sfMessage\" (the members panel opens before anything is written); a 403 members_only that gets through opens the panel too",
      /var MEMBER_ACTIONS = \[[^\n]*"#sfMessage"[^\n]*\];/.test(bfa) && freeAcct.panel.length === 1 && freeAcct.open === false && freeAcct.win.location.href === "/seller.html?u=anap", J({ panel: freeAcct.panel, open: freeAcct.open }));
    const out = await visit({ tok: false, answer: 0 });
    check("I3. signed out: the sign-in prompt, which comes back here (bf_return_to), and nothing is sent",
      out.btn && /Sign in to message Ana Perez/.test(out.dialog || "") && /href="\/app\.html"/.test(out.dialog || "") && out.fetches.length === 0 && out.store.bf_return_to === "/seller.html?u=anap", J({ dialog: out.dialog, store: out.store }));
    const own = await visit({ tok: true, me: SELLER_ID, answer: 200 });
    check("I4. your own storefront: no Message button (the member's id from their own token); and when the server's follow counts say it is yours, Follow and Message both hide",
      own.btn === false && /if \(state\.self\) \{ btn\.hidden = true; var msg = document\.getElementById\("sfMessage"\); if \(msg\) msg\.hidden = true; \}/.test(page));
    check("I5. seller.html mounts it beside Follow", /if \(seller\.user_id\) mountFollow\(seller\.user_id\);\n  mountMessage\(seller\);/.test(page));
  }

  /* ── J. the backfill ── */
  console.log("\n== J. the backfill ==");
  {
    const src = FILES[BACKFILL] || "";
    const mod = { exports: {} };
    const req = n => (n === "../../lib/inbound" ? IB : require(n));
    new vm.Script("(function (module, exports, require, __dirname) {" + src.replace(/^#!.*\n/, "") + "\n})", { filename: "lr3Backfill.js" }).runInThisContext()(mod, mod.exports, req, path.join(H.REPO, "scripts", "oneoff"));
    const BF = mod.exports;
    const NOW = Date.parse("2026-11-24T12:00:00.000Z"), old = "2026-07-01T00:00:00.000Z", recent = d => "2026-11-" + String(d).padStart(2, "0") + "T10:00:00.000Z";
    const seed = () => Object.assign({
      messages: [{ id: uid(601), sender_id: B, receiver_id: A, content: "first", created_at: recent(10) }, { id: uid(602), sender_id: A, receiver_id: B, content: "reply", created_at: recent(11) },
        { id: uid(603), sender_id: B, receiver_id: A, content: "again", created_at: recent(12) }, { id: uid(604), sender_id: C, receiver_id: A, content: "old", created_at: old },
        { id: uid(605), sender_id: C, receiver_id: A, content: "new after old", created_at: recent(13) }, { id: uid(606), sender_id: A, receiver_id: A, content: "self", created_at: recent(14) },
        { id: uid(607), sender_id: B, receiver_id: A, content: "I can help: https://bizforceai.net/p/" + uid(650), created_at: recent(19) }],
      posts: [{ id: uid(650), author_id: A, intent: "need", category: null }], card_leads: [{ id: uid(610), user_id: A, name: "K", email: "k@example.com", phone: null, message: "", created_at: recent(15) }],
      marketplace_orders: [{ id: uid(620), buyer_id: B, seller_id: A, listing_title: "Kit", amount_bfc: 40, created_at: recent(16) }, { id: uid(621), buyer_id: A, seller_id: A, listing_title: "Mine", amount_bfc: 1, created_at: recent(16) },
        { id: uid(622), buyer_id: B, seller_id: A, listing_title: "Old", amount_bfc: 9, created_at: old }],
      campaign_donations: [{ id: uid(630), campaign_id: uid(631), donor_id: C, owner_id: A, amount_bfc: 25, created_at: recent(17) }], crowdfunding_campaigns: [{ id: uid(631), title: "Chairs" }],
      bfc_transfers: [{ id: uid(640), sender_id: B, recipient_id: A, amount_bfc: 5, note: "", kind: "support", created_at: recent(18) }, { id: uid(641), sender_id: B, recipient_id: A, amount_bfc: 5, note: "", kind: "transfer", created_at: recent(18) }],
      inbound_items: []
    }, people);
    const db = memDb(seed());
    const dry = await BF.run(db.client, { nowMs: NOW });
    const wrote = db.log.filter(q => q.op !== "select").length;
    const one = await BF.run(db.client, { apply: true, nowMs: NOW });
    const after1 = items(db).length;
    const two = await BF.run(db.client, { apply: true, nowMs: NOW });
    const sum = (r, k) => Object.keys(r.kinds).reduce((n, x) => n + r.kinds[x][k], 0);
    check("J1. a dry run writes nothing and counts what it would make", wrote === 0 && sum(dry, "planned") === 5 && sum(dry, "created") === 0, J({ wrote, dry: dry.kinds }));
    check("J2. --apply makes each item once: the first message of each conversation in the last 90 days (B's; C's first in the window is not its first ever, so none), the card lead, the sale (not your own, not older), the donation and the support tip (not a plain transfer)",
      sum(one, "created") === 5 && after1 === 5 && J(items(db).map(i => i.kind).sort()) === J(["campaign", "card_lead", "message", "sale", "tip"]) &&
      items(db).find(i => i.kind === "message").source_id === uid(601) && items(db).filter(i => i.status === "won").length === 3, J({ one: one.kinds, items: items(db).map(i => [i.kind, i.source_id]) }));
    check("J3. a second run makes nothing (already there; the later I can help in B's conversation is that conversation's item already)", sum(two, "created") === 0 && sum(two, "already") === 6 && items(db).length === 5, J(two.kinds));
    const convReads = memDb(seed());
    await BF.run(convReads.client, { nowMs: NOW });
    const asked = convReads.log.filter(q => q.table === "messages" && q.filters.some(f => f[0] === "or")).length;
    check("J6. it asks about a conversation's earlier messages only for each conversation's first message in the window (two here), never for every message", asked === 2, J(asked));
    check("J4. the last 90 days; prints counts only, never a name, an address or a message", BF.BACKFILL_DAYS === 90 && dry.since === new Date(NOW - 90 * 86400000).toISOString() &&
      !/console\.log\([^)]*(\.name|\.email|\.phone|\.content|\.summary|counterpart_label)/.test(src));
    const missing = memDb({ messages: [] }, { fail: t => t === "inbound_items" });
    let refused = null;
    try { await BF.run(missing.client, { nowMs: NOW }); } catch (e) { refused = e.code || e.message; }
    check("J5. it never writes in a dry run, even with nothing to compare against", missing.log.filter(q => q.op !== "select").length === 0, J(refused));
  }

  /* ── K. the data lists, privacy and the page ── */
  console.log("\n== K. your data and the page ==");
  {
    const yd = FILES[YD] || "", bk = FILES[BK] || "", priv = FILES[PRIV] || "", lr = FILES[RADAR] || "";
    check("K1. lib/yourData.js exports inbound_items (the member's own and where they are the other person) and deletes it; lib/backup.js backs it up",
      /table: "inbound_items"[^\n]*owner: \["user_id"\][^\n]*members: \["counterpart_user_id"\]/.test(yd.replace(/\n\s+/g, " ")) && /DELETE_ORDER[\s\S]*"inbound_items",/.test(yd) && bk.indexOf('"inbound_items"') !== -1, "");
    check("K2. privacy.html names Inbound", /Inbound/.test(priv) && /inbound_items|Inbound list/.test(priv));
    check("K3. the Inbound tab reads GET /api/inbound by status, moves with POST /status and adds with POST /customer",
      lr.indexOf('call("GET", "/api/inbound?status=" + encodeURIComponent(IN.status))') !== -1 && lr.indexOf('return call("POST", "/api/inbound/" + encodeURIComponent(id) + "/status", { status: to })') !== -1 &&
      lr.indexOf('call("POST", "/api/inbound/" + encodeURIComponent(id) + "/customer", {})') !== -1);
    check("K4. a tap opens the source (its href; a reply on Bluesky in a new tab)", lr.indexOf('<a class="lr-open" href="\' + esc(o.href || "/inbox.html") + \'"\' + (o.external ? \' target="_blank" rel="noopener noreferrer"\' : "")') !== -1);
  }

  finish();
})().catch(e => { check("the check itself ran", false, e && e.stack); finish(); });
