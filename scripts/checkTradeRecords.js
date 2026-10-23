"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkTradeRecords — every BizCash trade is recorded, with a ledger and a
   yearly statement for each member.

   lib/trades.js lists each member's trades (purchases and sales from
   marketplace_orders, donations from campaign_donations, transfers from
   bfc_transfers, migration 145), the BizCash BizForce issued them (apart),
   and reconciles both against the wallet ledger. server.js serves it at
   GET /api/me/trades, /api/me/trades.csv and /api/me/trade-statement.

   WHAT THIS PROVES, against an in-memory database written the way the SQL
   functions write it (each trade's two ledger rows at the trade's instant):
     A. Every trade type appears for both parties, with the right sign, the
        right counterparty username ("a deleted member" for a deleted one),
        the item, and a reference both parties share; oldest first.
     B. BizCash issued by BizForce (rewards, the forfeiture) is listed apart
        and never as a trade; a USD order is never a trade.
     C. The reconciliation: received − sent + issued = the ledger's total,
        for all time, for a year and for a date range; and it reports a
        missing trade record instead of hiding it.
     D. The CSV and the statement carry the same totals as the JSON; the
        statement has its note; no "$" or "USD" appears in any output.
     E. No other member's private data: no id, email, Stripe id or their own
        ledger rows.
     F. The routes: requireAuth and a rate limit, never a subscription gate,
        and they answer a member whose subscription has lapsed; bad dates
        and years are refused; a read failure is a 503, never an empty list.
     G. Migration 145 records transfers (table, bfc_send, backfill); the
        Your data description and the export include the trade ledger.

   MUTATE=<name> edits lib/trades.js or server.js IN MEMORY. MUTATE=all runs
   each in its own process and passes only if every one fails at least one
   check. A mutation whose search text does not match exactly once is an
   ERROR, never counted as caught.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), vm = require("vm"), path = require("path"), net = require("net"), dns = require("dns"), Module = require("module");
const s = require("./_shared");

const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkTradeRecords: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkTradeRecords: no network"); };

const REPO = path.join(__dirname, "..");
const MUTATE = process.env.MUTATE || "";
const lf = t => t.replace(/\r\n/g, "\n");

const MUTATIONS = {
  // a sale counted with the wrong sign
  "sale-wrong-sign": ["lib/trades.js", "type: TYPE.sale, other: o.buyer_id, item: o.listing_title || null, bfc: o.amount_bfc,",
    "type: TYPE.sale, other: o.buyer_id, item: o.listing_title || null, bfc: -o.amount_bfc,"],
  // issued BFC counted as a trade
  "issued-as-trade": ["lib/trades.js", "    if (isIssued(row)) issued.push(entry);\n",
    "    if (isIssued(row)) trades.push({ date: entry.date, type: TYPE.transferReceived, counterparty: \"BizForce\", item: entry.description, bfc: entry.bfc, reference: entry.reference });\n"],
  // a counterparty shown by id instead of username
  "counterparty-by-id": ["lib/trades.js", "counterparty: names[r.other] || \"a deleted member\",", "counterparty: r.other,"],
  // a dollar value added to the statement
  "dollar-value": ["lib/trades.js", "\" BFC</td></tr>\";", "\" BFC ($\" + st.totals_by_type[t].bfc + \")</td></tr>\";"],
  // a USD order read as a trade
  "usd-order-traded": ["lib/trades.js", "var bfc = function (q) { return q.eq(\"payment_method\", \"bfc\"); };",
    "var bfc = function (q) { return q; };"],
  // the period's last day left out
  "to-day-excluded": ["lib/trades.js", "p.to = query.to; p.toIso = new Date(t.getTime() + 86400000).toISOString();", "p.to = query.to; p.toIso = t.toISOString();"],
  // a forfeiture counted as an unmatched entry rather than issued
  "forfeit-not-issued": ["lib/trades.js", "return row.type === \"reward\" || (row.type === \"debit\" && row.description === yourData.FORFEIT_DESCRIPTION);",
    "return row.type === \"reward\";"],
  // the statement loses its note
  "no-statement-note": ["lib/trades.js", "\"<p class=\\\"note\\\">\" + esc(st.note) + \"</p>\\n", "\"<p class=\\\"note\\\"></p>\\n"],
  // the CSV leaves issued BFC out
  "csv-drops-issued": ["lib/trades.js", "  result.issued.forEach(function (x) { lines.push([x.date, ISSUED_LABEL, x.description, \"\", \"\", x.bfc, x.reference].map(cell).join(\",\")); });\n", ""],
  // the trades route gated by subscription
  "route-gated": ["server.js", "app.get(\"/api/me/trades\", requireAuth, tradesLimiter, async function (req, res) {",
    "app.get(\"/api/me/trades\", requireAuth, requireActiveSubscription, tradesLimiter, async function (req, res) {"],
  // a read failure answered as no trades
  "failure-as-empty": ["server.js", "    console.error(\"[trades] list FAILED for user \" + req.user.id + \": \" + (error.message || error));\n    return res.status(503).json({ error: TRADES_UNREADABLE });\n",
    "    return res.json({ trades: [], issued: [], unmatched: [] });\n"]
};
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

const SRC = { "lib/trades.js": lf(fs.readFileSync(path.join(REPO, "lib/trades.js"), "utf8")), "server.js": lf(fs.readFileSync(path.join(REPO, "server.js"), "utf8")) };
if (MUTATE) {
  const m = MUTATIONS[MUTATE];
  if (!m) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  SRC[m[0]] = s.replaceOnce(SRC[m[0]], m[1], m[2], MUTATE + " in " + m[0]);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}

// lib/trades.js as it stands (or mutated), requiring the real lib/yourData.js.
const YD = require(path.join(REPO, "lib/yourData.js"));
function loadTrades(src) {
  const m = new Module(path.join(REPO, "lib/trades.js"), module);
  m.filename = path.join(REPO, "lib/trades.js");
  m.paths = Module._nodeModulePaths(path.join(REPO, "lib"));
  m._compile(src, m.filename);
  return m.exports;
}
const T = loadTrades(SRC["lib/trades.js"]);
// The export requires ./trades lazily: point that at the same (possibly mutated) module.
require.cache[require.resolve(path.join(REPO, "lib/trades.js"))] = { id: "trades", filename: path.join(REPO, "lib/trades.js"), loaded: true, exports: T };

/* ── an in-memory database ──────────────────────────────────────────────── */
function fakeDb(tables, opts) {
  opts = opts || {};
  const reads = [];
  function from(table) {
    let rows = (tables[table] || []).slice(), cols = null, orders = [], range = null;
    const q = {
      select(c) { cols = c; return q; },
      eq(col, v) { rows = rows.filter(r => r[col] === v); return q; },
      in(col, vs) { rows = rows.filter(r => vs.indexOf(r[col]) !== -1); return q; },
      gte(col, v) { rows = rows.filter(r => r[col] >= v); return q; },
      lt(col, v) { rows = rows.filter(r => r[col] < v); return q; },
      order(col, o) { orders.push([col, !o || o.ascending !== false]); return q; },
      range(a, b) { range = [a, b]; return q; },
      then(res, rej) {
        reads.push(table);
        if (opts.failTable === table) return Promise.resolve({ data: null, error: { message: "relation unavailable" } }).then(res, rej);
        let out = rows.slice();
        out.sort((x, y) => { for (const [c, asc] of orders) { if (x[c] < y[c]) return asc ? -1 : 1; if (x[c] > y[c]) return asc ? 1 : -1; } return 0; });
        if (range) out = out.slice(range[0], range[1] + 1);
        if (cols && cols !== "*") { const names = cols.split(",").map(c => c.trim()); out = out.map(r => { const o = {}; names.forEach(n => { o[n] = r[n]; }); return o; }); }
        return Promise.resolve({ data: out, error: null }).then(res, rej);
      }
    };
    return q;
  }
  return { from, reads };
}

/* ── the fixture: what the SQL functions write ─────────────────────────── */
const A = "aaaaaaaa-0000-4000-8000-00000000000a", B = "bbbbbbbb-0000-4000-8000-00000000000b", C = "cccccccc-0000-4000-8000-00000000000c";
const D = "dddddddd-0000-4000-8000-00000000000d";
const EMAIL = { [A]: "alice+bftest@example.com", [B]: "bob+bftest@example.com", [C]: "deleted-c@deleted.invalid", [D]: "dave+bftest@example.com" };
function fixture() {
  const t = {
    users: [{ id: A, role: "user", email: EMAIL[A] }, { id: B, role: "user", email: EMAIL[B] }, { id: C, role: "deleted", email: EMAIL[C] }, { id: D, role: "user", email: EMAIL[D] }],
    bf_profiles: [{ user_id: A, username: "alice" }, { user_id: B, username: "bob" }, { user_id: D, username: "dave" }],
    subscriptions: [{ user_id: A, status: "canceled", plan: "all_access", stripe_customer_id: "cus_LAPSED1" }],
    marketplace_orders: [], campaign_donations: [], bfc_transfers: [], wallet_transactions: [],
    crowdfunding_campaigns: [{ id: "camp-c1", owner_id: C, title: "Community garden" }, { id: "camp-a1", owner_id: A, title: "Studio fund" }]
  };
  let n = 0;
  const leg = (user, type, amount, description, at) => t.wallet_transactions.push({ id: "wtx-" + (++n) + "-" + user.slice(0, 1), user_id: user, type, amount, description, created_at: at });
  const order = (id, buyer, seller, amount, title, at) => {
    t.marketplace_orders.push({ id, listing_id: "lst-" + id, buyer_id: buyer, seller_id: seller, amount_bfc: amount, listing_title: title, status: "completed", payment_method: "bfc", amount_usd: null, stripe_session_id: null, created_at: at });
    leg(buyer, "debit", amount, "Marketplace purchase: " + title, at); leg(seller, "credit", amount, "Marketplace purchase: " + title, at);
  };
  const transfer = (id, from, to, amount, at) => {
    t.bfc_transfers.push({ id, sender_id: from, recipient_id: to, amount_bfc: amount, created_at: at });
    leg(from, "debit", amount, "Transfer", at); leg(to, "credit", amount, "Transfer", at);
  };
  const donate = (id, campaign, donor, owner, amount, title, at) => {
    t.campaign_donations.push({ id, campaign_id: campaign, donor_id: donor, owner_id: owner, amount_bfc: amount, created_at: at });
    leg(donor, "debit", amount, "Donation: " + title, at); leg(owner, "credit", amount, "Donation: " + title, at);
  };
  leg(A, "reward", 1000, "Welcome bonus", "2025-11-02T10:00:00.000Z");
  leg(B, "reward", 1000, "Welcome bonus", "2025-11-03T10:00:00.000Z");
  transfer("tr-0", A, B, 10, "2025-12-31T23:59:59.000Z");
  leg(A, "reward", 100, "Certification earned: seo", "2026-01-15T09:00:00.000Z");
  order("ord-1", A, B, 300, "Logo design", "2026-02-01T12:00:00.000Z");
  transfer("tr-1", B, A, 120, "2026-03-05T08:30:00.000Z");
  donate("don-1", "camp-c1", A, C, 50, "Community garden", "2026-04-10T16:00:00.000Z");
  order("ord-2", C, A, 80, "Ebook", "2026-05-20T11:00:00.000Z");
  transfer("tr-2", A, B, 40, "2026-06-01T00:00:00.000Z");
  donate("don-2", "camp-a1", B, A, 25, "Studio fund", "2026-07-01T07:00:00.000Z");
  // A USD sale: Stripe paid it, no BFC moved, no ledger row.
  t.marketplace_orders.push({ id: "ord-usd", listing_id: "lst-usd", buyer_id: B, seller_id: A, amount_bfc: 0, listing_title: "Consulting hour", status: "completed",
    payment_method: "usd", amount_usd: 1500, stripe_session_id: "cs_test_USD1", created_at: "2026-08-01T10:00:00.000Z" });
  // C's balance forfeited when C deleted the account.
  leg(C, "debit", 50, YD.FORFEIT_DESCRIPTION, "2026-09-01T00:00:00.000Z");
  return t;
}

(async function main() {
  const db = fakeDb(fixture());
  const all = T.periodFrom({});
  const a = await T.listTrades(db, A, all), b = await T.listTrades(db, B, all), c = await T.listTrades(db, C, all);
  const pick = (r, ref) => r.trades.filter(t => t.reference === ref);
  const one = (r, ref, type, who, bfc, item) => { const x = pick(r, ref); return x.length === 1 && x[0].type === type && x[0].counterparty === who && x[0].bfc === bfc && x[0].item === item; };

  // ════ A ════
  console.log("\n══ A. every trade, for both parties ══");
  check("A1. a purchase is −300 for the buyer and a sale +300 for the seller, each naming the other by username, with the item",
    one(a, "ord-1", "purchase", "@bob", -300, "Logo design") && one(b, "ord-1", "sale", "@alice", 300, "Logo design"), JSON.stringify(pick(a, "ord-1").concat(pick(b, "ord-1"))));
  check("A2. a transfer is \"transfer sent\" −120 for the sender and \"transfer received\" +120 for the recipient",
    one(b, "tr-1", "transfer sent", "@alice", -120, null) && one(a, "tr-1", "transfer received", "@bob", 120, null));
  check("A3. a donation is \"donation given\" −25 for the donor and \"donation received\" +25 for the campaign owner, with the campaign's title",
    one(b, "don-2", "donation given", "@alice", -25, "Studio fund") && one(a, "don-2", "donation received", "@bob", 25, "Studio fund"));
  check("A4. a deleted member is shown as \"a deleted member\", on both sides of their trades",
    one(a, "don-1", "donation given", "a deleted member", -50, "Community garden") && one(a, "ord-2", "sale", "a deleted member", 80, "Ebook") &&
    one(c, "don-1", "donation received", "@alice", 50, "Community garden") && one(c, "ord-2", "purchase", "@alice", -80, "Ebook"));
  check("A5. every one of the six types appears, and a member's list is exactly their trades",
    T.TYPES.every(ty => a.trades.concat(b.trades).some(t => t.type === ty)) && a.trades.length === 7 && b.trades.length === 5 && c.trades.length === 2,
    a.trades.length + "/" + b.trades.length + "/" + c.trades.length);
  check("A6. oldest first, each dated in UTC (ISO, ending Z)", a.trades.every((t, i) => /Z$/.test(t.date) && (i === 0 || a.trades[i - 1].date <= t.date)) && a.trades[0].reference === "tr-0");
  check("A7. a member with no trades gets an empty list that still reconciles", (await T.listTrades(db, D, all)).trades.length === 0);

  // ════ B ════
  console.log("\n══ B. BizCash issued by BizForce is apart ══");
  check("B1. the welcome bonus and the certification credit are listed as issued, never as trades",
    a.issued.length === 2 && a.issued.map(x => x.description).join("|") === "Welcome bonus|Certification earned: seo" && a.issued.every(x => x.bfc > 0) &&
    !a.trades.some(t => /Welcome|Certification/.test(String(t.item) + t.counterparty)));
  check("B2. the forfeiture on deleting an account is issued (−50), not a trade and not unmatched", c.issued.length === 1 && c.issued[0].bfc === -50 && c.unmatched.length === 0);
  check("B3. a USD order is never a trade, for either party", !a.trades.concat(b.trades).some(t => t.reference === "ord-usd"));
  check("B4. no trade is with BizForce, and none is with oneself", a.trades.concat(b.trades, c.trades).every(t => !/BizForce|you/i.test(t.counterparty)));

  // ════ C ════
  console.log("\n══ C. the reconciliation ══");
  const holds = r => r.reconciliation.holds && r.reconciliation.difference_bfc === 0 &&
    r.totals.received_bfc - r.totals.sent_bfc + r.totals.issued_bfc === r.reconciliation.ledger_net_bfc;
  const ledgerSum = (user, from, to) => fixture().wallet_transactions.filter(w => w.user_id === user && (!from || w.created_at >= from) && (!to || w.created_at < to))
    .reduce((n, w) => n + (w.type === "debit" ? -w.amount : w.amount), 0);
  check("C1. received − sent + issued = the ledger's total, for each member, all time", holds(a) && holds(b) && holds(c) && a.reconciliation.ledger_net_bfc === ledgerSum(A) && a.reconciliation.ledger_net_bfc === 925,
    JSON.stringify(a.reconciliation));
  const y26 = await T.listTrades(db, A, T.yearPeriod("2026", new Date("2026-10-22T00:00:00Z")));
  const y25 = await T.listTrades(db, A, T.yearPeriod("2025", new Date("2026-10-22T00:00:00Z")));
  check("C2. ... for a year: 2025 holds the one 23:59:59 transfer and the bonus; 2026 the rest", holds(y26) && holds(y25) && y25.trades.length === 1 && y25.trades[0].reference === "tr-0" &&
    y26.trades.length === 6 && y26.reconciliation.ledger_net_bfc === ledgerSum(A, "2026-01-01T00:00:00.000Z", "2027-01-01T00:00:00.000Z"), y25.trades.length + "/" + y26.trades.length);
  const range = await T.listTrades(db, A, T.periodFrom({ from: "2026-03-05", to: "2026-06-01" }));
  check("C3. ... for a date range, both days included (the 1 June transfer at 00:00 is in)", holds(range) && range.trades.map(t => t.reference).join(",") === "tr-1,don-1,ord-2,tr-2", range.trades.map(t => t.reference).join(","));
  const broken = fixture(); broken.bfc_transfers = broken.bfc_transfers.filter(x => x.id !== "tr-1");
  const br = await T.listTrades(fakeDb(broken), A, all);
  check("C4. a trade with no record does not reconcile, and says by how much (+120)", br.reconciliation.holds === false && br.reconciliation.difference_bfc === 120);
  const odd = fixture(); odd.wallet_transactions.push({ id: "wtx-odd", user_id: A, type: "credit", amount: 7, description: "Adjustment", created_at: "2026-09-09T00:00:00.000Z" });
  const od = await T.listTrades(fakeDb(odd), A, all);
  check("C5. a ledger row that is neither a trade nor issued is listed as unmatched, never hidden", od.unmatched.length === 1 && od.unmatched[0].bfc === 7 && od.reconciliation.difference_bfc === 7);

  // ════ D ════
  console.log("\n══ D. CSV and statement ══");
  function parseCsv(text) {
    const rows = []; let row = [], cell = "", q = false;
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (q) { if (ch === "\"" && text[i + 1] === "\"") { cell += "\""; i++; } else if (ch === "\"") q = false; else cell += ch; }
      else if (ch === "\"") q = true; else if (ch === ",") { row.push(cell); cell = ""; }
      else if (ch === "\r") continue; else if (ch === "\n") { row.push(cell); rows.push(row); row = []; cell = ""; } else cell += ch;
    }
    return rows;
  }
  const csv = parseCsv(T.tradesCsv(a));
  const head = csv[0], body = csv.slice(1), col = k => head.indexOf(k);
  const tr = body.filter(r => r[col("kind")] === "trade"), iss = body.filter(r => r[col("kind")] === T.ISSUED_LABEL);
  check("D1. the CSV has one row per trade and per issued entry, and its BFC column sums to the JSON's totals",
    tr.length === a.trades.length && iss.length === a.issued.length &&
    tr.reduce((n, r) => n + Number(r[col("bfc")]), 0) === a.totals.trades_net_bfc && iss.reduce((n, r) => n + Number(r[col("bfc")]), 0) === a.totals.issued_bfc &&
    tr.map(r => r[col("reference")]).join() === a.trades.map(t => t.reference).join());
  const nasty = { trades: [{ date: "2026-01-01T00:00:00.000Z", type: "sale", counterparty: "@x", item: "=HYPERLINK(\"http://x\",\"a, b\")", bfc: 5, reference: "r1" }], issued: [], unmatched: [] };
  const nr = parseCsv(T.tradesCsv(nasty))[1];
  check("D2. a title that starts like a formula is written as text, and commas and quotes survive", nr[4] === "'=HYPERLINK(\"http://x\",\"a, b\")");
  const st = T.statementOf(y26, 2026), html = T.statementHtml(st);
  const typeSum = Object.keys(st.totals_by_type).reduce((n, k) => n + st.totals_by_type[k].count, 0);
  check("D3. the statement's totals equal the JSON's: trades, each type's count and BFC, received, sent, issued",
    st.trades === y26.trades.length && typeSum === y26.trades.length && st.received_bfc === y26.totals.received_bfc && st.sent_bfc === y26.totals.sent_bfc &&
    st.issued.bfc === y26.totals.issued_bfc && T.TYPES.every(ty => st.totals_by_type[ty].bfc === y26.trades.filter(t => t.type === ty).reduce((n, t) => n + Math.abs(t.bfc), 0)));
  check("D4. ... and the counterparties by username", JSON.stringify(st.counterparties) === JSON.stringify(["@bob", "a deleted member"]), st.counterparties.join(","));
  const NOTE = "BizCash (BFC) is an in-app trade credit with no cash value. This statement records your BFC trades on BizForceAI for your own records. Bartered goods and services can count as income for tax purposes; ask a tax professional how this applies to you.";
  check("D5. the statement carries the note, word for word, in the JSON and the printable HTML", st.note === NOTE && html.indexOf("<p class=\"note\">" + NOTE + "</p>") !== -1);
  check("D6. the HTML shows each type's count and BFC, and the reconciliation", T.TYPES.every(ty => html.indexOf("<td>" + ty + "</td><td class=\"num\">" + st.totals_by_type[ty].count + "</td>") !== -1) &&
    /add up to the ledger's total/.test(html));
  const outputs = [JSON.stringify(a), JSON.stringify(b), JSON.stringify(c), T.tradesCsv(a), T.tradesCsv(b), JSON.stringify(st), html, T.statementHtml(T.statementOf(b, 2026))].join("\n");
  check("D7. no \"$\" and no \"USD\" in any output: JSON, CSV, statement JSON and HTML", !/\$|\bUSD\b|usd/i.test(outputs), (outputs.match(/.{20}(\$|USD|usd).{20}/i) || [""])[0]);
  check("D8. a title is escaped in the HTML", T.statementHtml(Object.assign({}, st, { counterparties: ["@<b>x</b>"] })).indexOf("@&lt;b&gt;x&lt;/b&gt;") !== -1);

  // ════ E ════
  console.log("\n══ E. no other member's private data ══");
  const aOut = JSON.stringify(a) + T.tradesCsv(a) + T.statementHtml(T.statementOf(a, 2026));
  const bLedgerIds = fixture().wallet_transactions.filter(w => w.user_id !== A).map(w => w.id);
  const leaks = [B, C, D, EMAIL[B], EMAIL[C], "cus_LAPSED1", "cs_test_USD1", "1500"].concat(bLedgerIds).filter(x => aOut.indexOf(x) !== -1);
  check("E1. a member's output holds no other member's id, email or ledger rows, and no Stripe id", leaks.length === 0, leaks.join(","));
  check("E2. each trade carries exactly date, type, counterparty, item, BFC and reference", a.trades.every(t => Object.keys(t).join() === "date,type,counterparty,item,bfc,reference"));
  check("E3. the order read selects no USD or Stripe column", !/amount_usd|stripe/.test(SRC["lib/trades.js"].split("var orderCols = ")[1].split(";")[0]));

  // ════ F ════
  console.log("\n══ F. the routes ══");
  {
    const SV = SRC["server.js"];
    const start = SV.indexOf("const tradesLimiter = rateLimit({"), end = SV.indexOf("const yourDataDeleteLimiter = rateLimit({");
    const code = start === -1 || end === -1 ? "" : SV.slice(start, end);
    const routes = {};
    const limiterOpts = [];
    const requireAuth = function requireAuth(req, res, next) { req.user = { id: req.headers["x-user"] }; next(); };
    const requireActiveSubscription = function requireActiveSubscription(req, res) { res.status(402).json({ error: "subscription required" }); };
    let dbNow = fakeDb(fixture());
    const ctx = { app: { get: (p, ...h) => { routes[p] = h; } }, requireAuth, requireActiveSubscription, console: { error() {}, log() {} }, Date,
      rateLimit: o => { limiterOpts.push(o); const mw = function tradesLimiterMw(req, res, next) { next(); }; mw.opts = o; return mw; },
      tradeRecords: T, get supabase() { return dbNow; } };
    vm.createContext(ctx);
    let loaded = true;
    try { vm.runInContext(code, ctx); } catch (e) { loaded = false; console.log("    (route code: " + e.message + ")"); }
    const call = async (p, query, user) => {
      const res = { statusCode: 200, headers: {}, body: undefined, status(c) { this.statusCode = c; return this; }, setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
        json(b) { this.body = b; this.headers["content-type"] = this.headers["content-type"] || "application/json"; return this; }, send(b) { this.body = b; return this; } };
      const req = { query: query || {}, headers: { "x-user": user || A } };
      const chain = routes[p] || [];
      let i = 0;
      // Middleware calls next() without awaiting it, as Express's does; the answer is awaited instead.
      const done = new Promise(resolve => { const j = res.json, sd = res.send; res.json = function (b) { j.call(this, b); resolve(); return this; }; res.send = function (b) { sd.call(this, b); resolve(); return this; }; });
      const next = () => { const h = chain[i++]; if (h) return Promise.resolve(h(req, res, next)); return Promise.resolve(); };
      next();
      await Promise.race([done, new Promise(r => setTimeout(r, 5000))]);
      return res;
    };
    const P = ["/api/me/trades", "/api/me/trades.csv", "/api/me/trade-statement"];
    check("F1. the three routes exist, each behind requireAuth and a rate limit, and none behind a subscription gate",
      loaded && P.every(p => routes[p] && routes[p].length === 3 && routes[p][0] === requireAuth && routes[p][1].name === "tradesLimiterMw") &&
      !/requireActiveSubscription|requireEntitlement/.test(code), P.map(p => (routes[p] || []).map(h => h.name).join("+")).join(" | "));
    check("F2. the limit is per member: 60 requests in 15 minutes", limiterOpts.length === 1 && limiterOpts[0].max === 60 && limiterOpts[0].windowMs === 900000 &&
      limiterOpts[0].keyGenerator({ user: { id: A } }) === "trades:" + A);
    const authSrc = SV.slice(SV.indexOf("async function requireAuth(req, res, next) {"), s.braceMatch(SV, SV.indexOf("{", SV.indexOf("async function requireAuth(req, res, next) {"))));
    check("F3. requireAuth itself reads no subscription or plan", authSrc.length > 200 && !/subscription|getUserPlan|entitle/i.test(authSrc));
    const j = await call("/api/me/trades", {});
    check("F4. a member whose subscription lapsed (canceled) gets their trades", j.statusCode === 200 && j.body && j.body.trades && j.body.trades.length === 7 && j.body.reconciliation.holds, j.statusCode);
    const cv = await call("/api/me/trades.csv", { from: "2026-01-01", to: "2026-12-31" });
    check("F5. the CSV route answers text/csv as a download, named by the period", cv.statusCode === 200 && /^text\/csv/.test(cv.headers["content-type"]) &&
      /attachment; filename="bizforce-trades-2026-01-01-to-2026-12-31\.csv"/.test(cv.headers["content-disposition"]) && parseCsv(cv.body).length === 1 + 6 + 1);
    const sj = await call("/api/me/trade-statement", { year: "2026", format: "json" });
    const sh = await call("/api/me/trade-statement", { year: "2026" });
    check("F6. the statement route answers JSON with ?format=json and printable HTML otherwise, the same totals", sj.statusCode === 200 && sj.body.trades === 6 && sj.body.note === NOTE &&
      sh.statusCode === 200 && /^text\/html/.test(sh.headers["content-type"]) && /<title>BizCash trade statement 2026<\/title>/.test(sh.body) && !/\$|USD/.test(sh.body));
    const bad = await Promise.all([call("/api/me/trades", { from: "2026-02-30" }), call("/api/me/trades", { from: "2026-05-01", to: "2026-04-01" }),
      call("/api/me/trade-statement", { year: "1999" }), call("/api/me/trade-statement", { year: "20x6" }), call("/api/me/trades.csv", { to: "tomorrow" })]);
    check("F7. an impossible date, a reversed range, and a bad year are refused with 400 and a reason", bad.every(r => r.statusCode === 400 && /YYYY|before|year/.test(r.body.error)), bad.map(r => r.statusCode).join(","));
    dbNow = fakeDb(fixture(), { failTable: "bfc_transfers" });
    const f = await Promise.all(P.map(p => call(p, p === P[2] ? { year: "2026" } : {})));
    check("F8. when a record cannot be read, every route answers 503 with a reason, never an empty list", f.every(r => r.statusCode === 503 && /could not be read/.test(r.body.error)), f.map(r => r.statusCode).join(","));
  }

  // ════ G ════
  console.log("\n══ G. the record and the description ══");
  {
    const MIG = lf(fs.readFileSync(path.join(REPO, "supabase/migrations/145_bfc_transfers.sql"), "utf8"));
    check("G1. migration 145 creates bfc_transfers with both parties, the amount and the time, and turns on row level security",
      /CREATE TABLE IF NOT EXISTS public\.bfc_transfers \(\s*id\s+uuid\s+PRIMARY KEY DEFAULT gen_random_uuid\(\),\s*sender_id\s+uuid\s+NOT NULL REFERENCES public\.users\(id\),\s*recipient_id\s+uuid\s+NOT NULL REFERENCES public\.users\(id\),\s*amount_bfc\s+integer\s+NOT NULL CHECK \(amount_bfc > 0\),\s*created_at\s+timestamptz NOT NULL DEFAULT now\(\)/.test(MIG) &&
      /alter table public\.bfc_transfers enable row level security;/.test(MIG));
    check("G2. bfc_send records every transfer it makes, in the same transaction, after bfc_transfer",
      /v_balance := bfc_transfer\(p_from, p_to, p_amount, 'Transfer'\);\n\ninsert into bfc_transfers \(sender_id, recipient_id, amount_bfc\)\nvalues \(p_from, p_to, p_amount\);\n\nreturn v_balance;/.test(MIG) &&
      /rpc\("bfc_send"/.test(SRC["server.js"]));
    check("G3. earlier transfers are recovered only from an unambiguous pair of 'Transfer' ledger rows at one instant",
      /from public\.wallet_transactions d\njoin public\.wallet_transactions c\n  on c\.created_at = d\.created_at\n and c\.amount = d\.amount/.test(MIG) && (MIG.match(/\) = 1\n/g) || []).length === 2 &&
      /on conflict \(sender_id, recipient_id, created_at\) do nothing;/.test(MIG));
    const e = YD.DATA.find(x => x.table === "bfc_transfers");
    check("G4. Your data lists bfc_transfers (by username only, kept on delete) and says the download holds the trade ledger",
      !!e && JSON.stringify(e.members) === "[\"sender_id\",\"recipient_id\"]" && e.onDelete === "keep" &&
      /The download also holds your trade ledger/.test(YD.DATA.find(x => x.table === "wallet_transactions").what));
    let out = "";
    const manifest = await YD.exportAccountData({ supabase: fakeDb(fixture()), userId: A, write: t => { out += t; }, now: new Date("2026-10-22T00:00:00Z") });
    let doc = null; try { doc = JSON.parse(out); } catch (x) { /* checked below */ }
    check("G5. the export holds the trade ledger, the same as GET /api/me/trades, and the manifest says so",
      !!doc && JSON.stringify(doc.trade_ledger) === JSON.stringify(a) && manifest.trade_ledger && manifest.trade_ledger.status === "complete" && manifest.trade_ledger.trades === 7 && manifest.trade_ledger.reconciled === true);
    let out2 = "";
    const m2 = await YD.exportAccountData({ supabase: fakeDb(fixture(), { failTable: "bfc_transfers" }), userId: A, write: t => { out2 += t; } });
    check("G6. a trade ledger that cannot be read makes the export say it is incomplete", m2.complete === false && m2.trade_ledger.status === "unreadable" && JSON.parse(out2).trade_ledger === null);
  }

  check("no network was touched", NETWORK.length === 0, NETWORK.join(","));
  console.log("\n" + (failures ? "CHECKS FAILED: " + failures + " of " + (passes + failures) : "ALL " + passes + " CHECKS PASSED") + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(failures ? 1 : 0);
})().catch(function (err) {
  // A crash is a failure, never the mutation-anchor exit (3).
  console.log("    FAIL  checkTradeRecords crashed: " + (err && err.stack || err));
  process.exit(1);
});
