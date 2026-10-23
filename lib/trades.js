/* ══════════════════════════════════════════════════════════════════════════
   lib/trades.js — each member's BizCash trade records.

   BizForce Market is a member trade system and BizCash (BFC) its closed-loop
   trade credit. Every BFC that changes hands between two members is a trade,
   and each member can list their trades, download them as CSV, and print a
   yearly statement. BFC amounts only: no dollar value appears anywhere here,
   because none has been chosen.

   WHERE A TRADE IS RECORDED (both parties, what, how much, when):
     purchase / sale              marketplace_orders, payment_method 'bfc' only
                                  (buyer_id, seller_id, amount_bfc,
                                  listing_title); written by bfc_buy_listing.
                                  A USD order is not a BFC trade and is never
                                  read here.
     donation given / received    campaign_donations (donor_id, owner_id,
                                  amount_bfc; the title from
                                  crowdfunding_campaigns); written by bfc_donate.
     transfer sent / received     bfc_transfers (sender_id, recipient_id,
                                  amount_bfc); written by bfc_send (migration
                                  145, which also recovered earlier transfers
                                  from the ledger).
   Each of those calls bfc_transfer, which writes the two wallet_transactions
   rows (the ledger) in the same transaction, so a trade and its ledger rows
   carry the same instant.

   ISSUED BY BIZFORCE, NEVER A TRADE: a ledger row of type 'reward' (the
   certification credit and the welcome bonus, both written by bfc_credit) and
   the forfeiture written when an account is deleted. These are listed apart.

   THE RECONCILIATION. Two independent records of the same money are compared
   for the period: the trades (from the tables above) and the wallet ledger
   (wallet_transactions; credit and reward add, debit takes away).
       BFC received in trades − BFC sent in trades + BFC issued by BizForce
         = the ledger's total for the period
   The answer says whether it holds and by how much it does not, and lists any
   ledger row that is neither a trade's nor issued, rather than hiding it.

   A counterparty appears by username only ("@name"), or as "a deleted
   member", from lib/yourData.js's memberNames: never by id, email or name.
   ══════════════════════════════════════════════════════════════════════════ */

const yourData = require("./yourData");

const TYPE = {
  purchase: "purchase", sale: "sale",
  transferSent: "transfer sent", transferReceived: "transfer received",
  donationGiven: "donation given", donationReceived: "donation received"
};
const TYPES = [TYPE.purchase, TYPE.sale, TYPE.transferSent, TYPE.transferReceived, TYPE.donationGiven, TYPE.donationReceived];
const ISSUED_LABEL = "issued by BizForce";
const UNMATCHED_LABEL = "ledger entry not matched to a trade";

const STATEMENT_NOTE = "BizCash (BFC) is an in-app trade credit with no cash value. This statement records your BFC trades on BizForceAI " +
  "for your own records. Bartered goods and services can count as income for tax purposes; ask a tax professional how this applies to you.";

const PAGE_SIZE = 1000;
const MAX_PAGES = 200;
const IN_CHUNK = 100;

function fail(what, error) {
  var e = new Error(what + ": " + ((error && error.message) || error));
  e.step = what;
  return e;
}

/* ── the period ──────────────────────────────────────────────────────────
   from and to are dates, YYYY-MM-DD, in UTC, both inclusive; either may be
   left out. */
const DAY = /^(\d{4})-(\d{2})-(\d{2})$/;
function dayStart(text) {
  var m = DAY.exec(String(text));
  if (!m) return null;
  var d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3]));
  return d.getUTCFullYear() === +m[1] && d.getUTCMonth() === +m[2] - 1 && d.getUTCDate() === +m[3] ? d : null;
}
function periodFrom(query) {
  query = query || {};
  var p = { from: null, to: null, fromIso: null, toIso: null };
  if (query.from !== undefined && query.from !== "") {
    var f = dayStart(query.from);
    if (!f) return { error: "from must be a date written YYYY-MM-DD." };
    p.from = query.from; p.fromIso = f.toISOString();
  }
  if (query.to !== undefined && query.to !== "") {
    var t = dayStart(query.to);
    if (!t) return { error: "to must be a date written YYYY-MM-DD." };
    p.to = query.to; p.toIso = new Date(t.getTime() + 86400000).toISOString();
  }
  if (p.fromIso && p.toIso && p.fromIso >= p.toIso) return { error: "from must be on or before to." };
  return p;
}
function yearPeriod(year, now) {
  var y = Number(year), current = (now || new Date()).getUTCFullYear();
  if (!/^\d{4}$/.test(String(year)) || y < 2020 || y > current) return { error: "year must be a year from 2020 to " + current + ", written YYYY." };
  return periodFrom({ from: y + "-01-01", to: y + "-12-31" });
}

/* ── reading ───────────────────────────────────────────────────────────── */
async function readAll(supabase, table, cols, filter, p) {
  var out = [];
  for (var page = 0; page < MAX_PAGES; page++) {
    var q = filter(supabase.from(table).select(cols));
    if (p.fromIso) q = q.gte("created_at", p.fromIso);
    if (p.toIso) q = q.lt("created_at", p.toIso);
    var r = await q.order("created_at", { ascending: true }).order("id", { ascending: true }).range(page * PAGE_SIZE, page * PAGE_SIZE + PAGE_SIZE - 1);
    if (r.error) throw fail(table + " could not be read", r.error);
    var rows = r.data || [];
    out = out.concat(rows);
    if (rows.length < PAGE_SIZE) return out;
  }
  throw fail(table + " could not be read", "more than " + (MAX_PAGES * PAGE_SIZE) + " rows");
}

async function campaignTitles(supabase, ids) {
  var titles = {};
  var todo = ids.filter(function (id, i) { return id && ids.indexOf(id) === i; });
  for (var i = 0; i < todo.length; i += IN_CHUNK) {
    var r = await supabase.from("crowdfunding_campaigns").select("id, title").in("id", todo.slice(i, i + IN_CHUNK));
    if (r.error) throw fail("crowdfunding_campaigns could not be read", r.error);
    (r.data || []).forEach(function (c) { titles[c.id] = c.title; });
  }
  return titles;
}

function ledgerSign(row) { return row.type === "debit" ? -row.amount : row.amount; }
function isIssued(row) { return row.type === "reward" || (row.type === "debit" && row.description === yourData.FORFEIT_DESCRIPTION); }
// The descriptions bfc_transfer is given by bfc_send (and the transfer route before it), bfc_buy_listing and bfc_donate.
function isTradeLeg(row) {
  var d = String(row.description || "");
  return d === "Transfer" || d === "Transfer sent" || d === "Transfer received" || d.indexOf("Marketplace purchase: ") === 0 || d.indexOf("Donation: ") === 0;
}
function iso(t) { return new Date(t).toISOString(); }

/* Every member-to-member exchange the user was part of, oldest first, and
   the BFC BizForce issued, apart. */
async function listTrades(supabase, userId, p) {
  p = p || periodFrom({});
  var bfc = function (q) { return q.eq("payment_method", "bfc"); };
  var orderCols = "id, buyer_id, seller_id, amount_bfc, listing_title, payment_method, created_at";
  var bought = await readAll(supabase, "marketplace_orders", orderCols, function (q) { return bfc(q.eq("buyer_id", userId)); }, p);
  var sold = await readAll(supabase, "marketplace_orders", orderCols, function (q) { return bfc(q.eq("seller_id", userId)); }, p);
  var donCols = "id, campaign_id, donor_id, owner_id, amount_bfc, created_at";
  var given = await readAll(supabase, "campaign_donations", donCols, function (q) { return q.eq("donor_id", userId); }, p);
  var got = await readAll(supabase, "campaign_donations", donCols, function (q) { return q.eq("owner_id", userId); }, p);
  var trCols = "id, sender_id, recipient_id, amount_bfc, created_at";
  var sent = await readAll(supabase, "bfc_transfers", trCols, function (q) { return q.eq("sender_id", userId); }, p);
  var received = await readAll(supabase, "bfc_transfers", trCols, function (q) { return q.eq("recipient_id", userId); }, p);
  var ledger = await readAll(supabase, "wallet_transactions", "id, type, amount, description, created_at", function (q) { return q.eq("user_id", userId); }, p);

  var raw = [];
  bought.forEach(function (o) { if (o.seller_id !== userId) raw.push({ at: o.created_at, type: TYPE.purchase, other: o.seller_id, item: o.listing_title || null, bfc: -o.amount_bfc, reference: o.id }); });
  sold.forEach(function (o) { if (o.buyer_id !== userId) raw.push({ at: o.created_at, type: TYPE.sale, other: o.buyer_id, item: o.listing_title || null, bfc: o.amount_bfc, reference: o.id }); });
  var titles = await campaignTitles(supabase, given.concat(got).map(function (d) { return d.campaign_id; }));
  given.forEach(function (d) { if (d.owner_id !== userId) raw.push({ at: d.created_at, type: TYPE.donationGiven, other: d.owner_id, item: titles[d.campaign_id] || null, bfc: -d.amount_bfc, reference: d.id }); });
  got.forEach(function (d) { if (d.donor_id !== userId) raw.push({ at: d.created_at, type: TYPE.donationReceived, other: d.donor_id, item: titles[d.campaign_id] || null, bfc: d.amount_bfc, reference: d.id }); });
  sent.forEach(function (t) { if (t.recipient_id !== userId) raw.push({ at: t.created_at, type: TYPE.transferSent, other: t.recipient_id, item: null, bfc: -t.amount_bfc, reference: t.id }); });
  received.forEach(function (t) { if (t.sender_id !== userId) raw.push({ at: t.created_at, type: TYPE.transferReceived, other: t.sender_id, item: null, bfc: t.amount_bfc, reference: t.id }); });

  var others = [];
  raw.forEach(function (r) { if (r.other && others.indexOf(r.other) === -1) others.push(r.other); });
  var names = others.length ? await yourData.memberNames(supabase, others) : {};

  var byTime = function (a, b) { return a.date < b.date ? -1 : a.date > b.date ? 1 : (a.reference < b.reference ? -1 : a.reference > b.reference ? 1 : 0); };
  var trades = raw.map(function (r) {
    return { date: iso(r.at), type: r.type, counterparty: names[r.other] || "a deleted member", item: r.item, bfc: r.bfc, reference: r.reference };
  }).sort(byTime);
  var issued = [], unmatched = [];
  ledger.forEach(function (row) {
    var entry = { date: iso(row.created_at), description: row.description || "", bfc: ledgerSign(row), reference: row.id };
    if (isIssued(row)) issued.push(entry);
    else if (!isTradeLeg(row)) unmatched.push(entry);
  });
  issued.sort(byTime); unmatched.sort(byTime);

  var sum = function (list) { return list.reduce(function (n, x) { return n + x.bfc; }, 0); };
  var receivedBfc = trades.filter(function (t) { return t.bfc > 0; }).reduce(function (n, t) { return n + t.bfc; }, 0);
  var sentBfc = trades.filter(function (t) { return t.bfc < 0; }).reduce(function (n, t) { return n - t.bfc; }, 0);
  var issuedBfc = sum(issued);
  var ledgerNet = ledger.reduce(function (n, row) { return n + ledgerSign(row); }, 0);
  var tradesNet = receivedBfc - sentBfc;
  return {
    period: { from: p.from, to: p.to },
    trades: trades,
    issued: issued,
    unmatched: unmatched,
    totals: { trades: trades.length, received_bfc: receivedBfc, sent_bfc: sentBfc, trades_net_bfc: tradesNet, issued_bfc: issuedBfc },
    reconciliation: {
      rule: "BFC received in trades − BFC sent in trades + BFC issued by BizForce = the wallet ledger's total for the period",
      ledger_net_bfc: ledgerNet, trades_net_bfc: tradesNet, issued_bfc: issuedBfc,
      holds: tradesNet + issuedBfc === ledgerNet, difference_bfc: ledgerNet - (tradesNet + issuedBfc)
    }
  };
}

/* ── the yearly statement ──────────────────────────────────────────────── */
function statementOf(result, year) {
  var byType = {};
  TYPES.forEach(function (t) { byType[t] = { count: 0, bfc: 0 }; });
  var counterparties = [];
  result.trades.forEach(function (t) {
    byType[t.type].count++;
    byType[t.type].bfc += Math.abs(t.bfc);
    if (counterparties.indexOf(t.counterparty) === -1) counterparties.push(t.counterparty);
  });
  counterparties.sort();
  return {
    year: Number(year),
    period: result.period,
    trades: result.totals.trades,
    totals_by_type: byType,
    received_bfc: result.totals.received_bfc,
    sent_bfc: result.totals.sent_bfc,
    trades_net_bfc: result.totals.trades_net_bfc,
    issued: { count: result.issued.length, bfc: result.totals.issued_bfc },
    counterparties: counterparties,
    reconciliation: result.reconciliation,
    note: STATEMENT_NOTE
  };
}

function esc(v) {
  return String(v === null || v === undefined ? "" : v).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function n(v) { return String(v).replace(/\B(?=(\d{3})+(?!\d))/g, ","); }

function statementHtml(st, member) {
  var rows = TYPES.map(function (t) {
    return "<tr><td>" + esc(t) + "</td><td class=\"num\">" + n(st.totals_by_type[t].count) + "</td><td class=\"num\">" + n(st.totals_by_type[t].bfc) + " BFC</td></tr>";
  }).join("\n");
  var rec = st.reconciliation;
  return "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"UTF-8\">\n<title>BizCash trade statement " + esc(st.year) + "</title>\n" +
    "<style>body{font:15px/1.5 system-ui,-apple-system,'Segoe UI',Arial,sans-serif;color:#111;max-width:760px;margin:32px auto;padding:0 16px}" +
    "h1{font-size:1.5rem;margin:0 0 4px}table{border-collapse:collapse;width:100%;margin:12px 0}td,th{border-bottom:1px solid #ccc;padding:6px 8px;text-align:left}" +
    ".num{text-align:right}.note{margin-top:24px;padding:12px;border:1px solid #999}@media print{body{margin:0}}</style>\n</head>\n<body>\n" +
    "<h1>BizCash trade statement " + esc(st.year) + "</h1>\n" +
    "<p>" + (member ? esc(member) + " — " : "") + "1 January to 31 December " + esc(st.year) + " (UTC). BFC amounts only.</p>\n" +
    "<table>\n<tr><th>Type</th><th class=\"num\">Trades</th><th class=\"num\">BFC</th></tr>\n" + rows + "\n</table>\n" +
    "<p>Trades: " + n(st.trades) + ". BFC received in trades: " + n(st.received_bfc) + ". BFC sent in trades: " + n(st.sent_bfc) +
    ". BFC issued by BizForce (not trades): " + n(st.issued.bfc) + " in " + n(st.issued.count) + " entr" + (st.issued.count === 1 ? "y" : "ies") + ".</p>\n" +
    "<p>Counterparties: " + (st.counterparties.length ? st.counterparties.map(esc).join(", ") : "none") + ".</p>\n" +
    "<p>Checked against your wallet ledger: " + (rec.holds ? "the trades and issued BFC add up to the ledger's total, " + n(rec.ledger_net_bfc) + " BFC."
      : "they do not add up: the ledger's total is " + n(rec.ledger_net_bfc) + " BFC, " + n(rec.difference_bfc) + " BFC away from the trades and issued BFC. Some ledger entries are not matched to a trade; your full trade list shows them.") + "</p>\n" +
    "<p class=\"note\">" + esc(st.note) + "</p>\n</body>\n</html>\n";
}

/* ── CSV ───────────────────────────────────────────────────────────────── */
function cell(v) {
  if (typeof v === "number") return String(v);
  var s = String(v === null || v === undefined ? "" : v);
  // A spreadsheet runs a cell that starts like a formula; text never does here.
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return /[",\n\r]/.test(s) ? "\"" + s.replace(/"/g, "\"\"") + "\"" : s;
}
function tradesCsv(result) {
  var lines = [["date", "kind", "type", "counterparty", "item", "bfc", "reference"].join(",")];
  result.trades.forEach(function (t) { lines.push([t.date, "trade", t.type, t.counterparty, t.item || "", t.bfc, t.reference].map(cell).join(",")); });
  result.issued.forEach(function (x) { lines.push([x.date, ISSUED_LABEL, x.description, "", "", x.bfc, x.reference].map(cell).join(",")); });
  result.unmatched.forEach(function (x) { lines.push([x.date, UNMATCHED_LABEL, x.description, "", "", x.bfc, x.reference].map(cell).join(",")); });
  return lines.join("\r\n") + "\r\n";
}

module.exports = { TYPE, TYPES, ISSUED_LABEL, UNMATCHED_LABEL, STATEMENT_NOTE, periodFrom, yearPeriod, listTrades, statementOf, statementHtml, tradesCsv, isIssued, isTradeLeg };
