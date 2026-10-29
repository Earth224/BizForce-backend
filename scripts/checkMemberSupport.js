"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkMemberSupport — members support each other with BizCash, list their
   own donation links, and share a support page; no USD passes through
   BizForce.

   Backend "Members can support each other with BizCash, list donation links,
   and share a support page" (migration 150, lib/supportLinks.js,
   lib/supportPage.js, POST /api/wallet/support, GET/PUT /api/support/me,
   GET /support/:username, GET /api/sitemap/support.xml) and frontend
   "Support section, shareable support page, Terms updated"
   (scripts/bf-support.js, support.html, profile, storefront, card, wallet).

   WHAT THIS PROVES
     A. POST /api/wallet/support, its route RUN in a vm against an in-memory
        database and a model of migration 150's bfc_send: it goes through
        requireAuth, requireActiveSubscription (a 402 without a subscription,
        nothing moved) and a per-account rate limit; the recipient is named
        by username and no account id is in any answer; support obeys the
        per-transfer maximum, the new-account hold and ONE 24-hour total
        shared with transfers and donations — each refused with its reason,
        "Nothing was sent", nothing moved and bfc_send never reached; no
        self-support; the note is plain text, at most 140 characters, stored
        escaped; the row is kind 'support' with the note, the ledger legs are
        'Transfer' (so the shared total counts them), and the recipient is
        notified "@X supported you with N BFC" with the note. A plain transfer
        still calls bfc_send with its six arguments and is kind 'transfer'.
     B. lib/trades.js: "support given" is −N and "support received" +N, each
        naming the other member by username, with the note only in those two
        members' own records; the statement totals them, the CSV carries the
        note, and the reconciliation still holds.
     C. lib/supportLinks.js: each provider's valid forms are accepted and the
        URL is REBUILT from provider and handle; tricky invalid ones are
        refused with their reason (paypa1.me, paypal.me.evil.com, http,
        javascript:, Unicode look-alikes, a login or port, extra path
        segments, query strings and fragments, reserved names, Stripe test
        links); at most five, no duplicates; PUT /api/support/me stores
        { provider, handle } only.
     D. The public answers: the profile, storefront and card routes add only
        support_links from publicSupportLinks, whose links carry exactly
        provider, label, handle, url and disclaimer; no note is in any public
        answer.
     E. The support page (GET /support/:username, lib/supportPage.js): on,
        off ("This member's support page is off") and none ("No member
        found", 404, also for an invalid username, read nothing) states; the
        buttons open in a new tab with rel="noopener noreferrer" under the
        provider's disclaimer; nothing private (email, phone, account id,
        note); OG, Twitter and canonical tags; noindex unless the member chose
        discovery, and the support sitemap lists only those; rate-limited;
        support.html is the same template's shell.
     F. scripts/bf-support.js RUN in jsdom on the page: signed out it offers
        "Sign in to support with BizCash" and remembers the page to return
        to (app.html returns only to this site's public pages); signed in the
        confirm step reads "Send N BFC to <name> (@user) as support?" and only
        Send posts; never on the member's own page; Share uses the share sheet
        or copies ("Link copied"); the QR code encodes the page's exact URL
        with the card's QR library; the profile, storefront, card and wallet
        are wired, and the member's own pages show "Your support link".
     G. The Terms carry "Member support" and TERMS_VERSION moved past
        PRE_SUPPORT's; the Privacy Policy says what is public and that notes
        are private; the guide has a support.html entry and reads the page's
        own key; lib/appMap.json is fresh; migration 150's SQL by its text.

   Nothing here touches the network or a real database.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check. A mutation
   whose search text does not match exactly once is an ERROR.

   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm"), Module = require("module");
const { execFileSync, spawnSync } = require("child_process");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
// The backend commit before member support: the Terms version it carried.
const PRE_SUPPORT = "a75de87";
const MIG_FILE = "supabase/migrations/150_member_support.sql";

const SV_FILE = "server.js", LINKS = "lib/supportLinks.js", PAGE = "lib/supportPage.js", TRADES = "lib/trades.js", LEGAL = "lib/legal.js";
const SUPJS = "fe:scripts/bf-support.js", TERMS = "fe:terms.html";

const MUTATIONS = {
  // support is let past the 24-hour total that transfers and donations share
  "support-skips-daily-total": [[SV_FILE, "if (sentLast24h + amount > limits.dailyCap) {", "if (!send.support && sentLast24h + amount > limits.dailyCap) {"]],
  // support is let past the per-transfer maximum
  "support-skips-max": [[SV_FILE, "    if (amount > limits.max) {\n      return res.status(400).json({\n        error: \"One transfer can move at most \"",
    "    if (!send.support && amount > limits.max) {\n      return res.status(400).json({\n        error: \"One transfer can move at most \""]],
  // support is let past the new-account hold
  "support-skips-hold": [[SV_FILE, "    const openedMs = sender.data ? Date.parse(sender.data.created_at) : NaN;\n    const sendableFromMs = openedMs + limits.holdDays * 24 * 60 * 60 * 1000;\n    // NaN fails this test too, so an account whose age cannot be read is held.\n    if (!(Date.now() >= sendableFromMs)) {",
    "    const openedMs = sender.data ? Date.parse(sender.data.created_at) : NaN;\n    const sendableFromMs = openedMs + limits.holdDays * 24 * 60 * 60 * 1000;\n    // NaN fails this test too, so an account whose age cannot be read is held.\n    if (!send.support && !(Date.now() >= sendableFromMs)) {"]],
  // a member can support themself
  "self-support-allowed": [[SV_FILE, "    if (member.user_id === req.user.id) {\n      return res.status(400).json({ error: \"You cannot support yourself.", "    if (false) {\n      return res.status(400).json({ error: \"You cannot support yourself."]],
  // support without a subscription
  "support-no-subscription": [[SV_FILE, 'app.post("/api/wallet/support", requireAuth, requireActiveSubscription, bfcSupportLimiter,', 'app.post("/api/wallet/support", requireAuth, bfcSupportLimiter,']],
  // the answer names the recipient's account id
  "recipient-id-leaked": [[SV_FILE, 'support: { to: "@" + member.username,', 'support: { id: member.user_id, to: "@" + member.username,']],
  // the note is stored as typed, not as escaped plain text
  "note-not-escaped": [[SV_FILE, "    const note = supportLinks.noteForStorage(req.body.note);\n", "    const note = { note: req.body.note || null };\n"]],
  // the support page shows the notes members sent
  "note-in-public-response": [[SV_FILE, "    const view = supportPage.viewFor(member, got.row);\n",
    "    const notes = await supabase.from(\"bfc_transfers\").select(\"note\").eq(\"recipient_id\", member.user_id);\n" +
    "    const view = supportPage.viewFor(member, Object.assign({}, got.row, { headline: ((notes.data || []).map(function (t) { return t.note; }).filter(Boolean).join(\" \")) || (got.row && got.row.headline) }));\n"]],
  // the support page is not rate-limited
  "page-not-rate-limited": [[SV_FILE, 'app.get("/support/:username", supportPageLimiter, async function', 'app.get("/support/:username", async function']],
  // a look-alike domain that starts with the provider's host is accepted
  "lookalike-domain-accepted": [[LINKS, "  if (p.hosts.indexOf(host) === -1) return refusal(\"wrong_host\",",
    "  if (!p.hosts.some(function (h) { return host.indexOf(h) === 0; })) return refusal(\"wrong_host\","]],
  // Unicode is let through
  "unicode-accepted": [[LINKS, "  if (!/^[\\x21-\\x7e]+$/.test(raw)) return refusal(\"not_ascii\",", "  if (false) return refusal(\"not_ascii\","]],
  // the URL the member typed is stored
  "raw-url-stored": [[LINKS, "  return { link: { provider: key, handle: handle } };", "  return { link: { provider: key, handle: handle, url: raw } };"]],
  // a stored URL is shown instead of the rebuilt one
  "raw-url-shown": [[LINKS, "url: p.url(stored.handle), disclaimer:", "url: stored.url || p.url(stored.handle), disclaimer:"]],
  // the off switch is ignored when the member has links
  "off-switch-ignored": [[LINKS, "  if (row.page_on === false) return false;\n", ""]],
  // the page's buttons lose the disclaimer
  "disclaimer-removed": [[PAGE, "      '<span class=\"sup-disclaimer\">' + esc(l.disclaimer) + '</span></li>';", "      '</li>';"]],
  // the profile/storefront/card block loses the disclaimer
  "disclaimer-removed-block": [[SUPJS, "      li.appendChild(el(\"span\", { \"class\": \"sup-disclaimer\" }, l.disclaimer));\n", ""]],
  // the page's buttons lose rel="noopener noreferrer"
  "rel-dropped": [[PAGE, "target=\"_blank\" rel=\"noopener noreferrer\">Support on ", "target=\"_blank\">Support on "]],
  // the support page shows the member's email
  "support-page-shows-email": [
    [PAGE, "    photo: profile.avatar_url || null,\n", "    photo: profile.avatar_url || null,\n    email: profile.email || null,\n"],
    [PAGE, "(view.username ? \"@\" + esc(view.username) : \"\") + '</p></div>',", "(view.username ? \"@\" + esc(view.username) : \"\") + '</p>' + (view.email ? '<p>' + esc(view.email) + '</p>' : \"\") + '</div>',"]],
  // every support page is indexable
  "index-always": [[PAGE, "(index ? \"index, follow\" : \"noindex\")", "\"index, follow\""]],
  // the canonical tag is gone
  "canonical-missing": [[PAGE, "    '  <link rel=\"canonical\" href=\"' + esc(url) + '\"/>',\n", ""]],
  // support given is counted as BFC received
  "trades-sign-flipped": [[TRADES, "type: isSupport(t) ? TYPE.supportGiven : TYPE.transferSent, other: t.recipient_id, item: null, bfc: -t.amount_bfc,",
    "type: isSupport(t) ? TYPE.supportGiven : TYPE.transferSent, other: t.recipient_id, item: null, bfc: isSupport(t) ? t.amount_bfc : -t.amount_bfc,"]],
  // the QR code encodes the address bar, not the page's own URL
  "qr-wrong-url": [[SUPJS, "root.QRCode.toCanvas(canvas, url,", "root.QRCode.toCanvas(canvas, window.location.href,"]],
  // signing in no longer comes back to the page
  "signin-no-return": [[SUPJS, "try { localStorage.setItem(\"bf_return_to\", window.location.href); } catch (e) {}", ""]],
  // Share without a share sheet does nothing
  "share-no-fallback": [[SUPJS, "    if (navigator.share) {\n", "    if (true) {\n"]],
  // the confirm step is skipped
  "no-confirm-step": [[SUPJS, "      parts.confirmBtn.focus();\n", "      parts.confirmBtn.focus();\n      parts.confirmBtn.click();\n"]],
  // the Terms page loses the section
  "terms-section-removed": [[TERMS, "  <h3 id=\"support\">Member support</h3>\n", ""]],
  // the Terms version is not bumped
  "terms-version-not-bumped": [[LEGAL, "const TERMS_VERSION = \"2026-10-28\";", "const TERMS_VERSION = \"2026-10-26\";"]],
  // support's ledger legs are described differently, so the shared total in SQL misses them
  "support-debit-not-transfer": [["mig", "v_balance := bfc_transfer(p_from, p_to, p_amount, 'Transfer');", "v_balance := bfc_transfer(p_from, p_to, p_amount, case when p_kind = 'support' then 'Support' else 'Transfer' end);"]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

/* ── the files ──────────────────────────────────────────────────────────── */
const lf = t => t.replace(/\r\n/g, "\n");
const SRC = {};
[SV_FILE, LINKS, PAGE, TRADES, LEGAL, "lib/legalPages.js"].forEach(f => { SRC[f] = lf(fs.readFileSync(path.join(REPO, f), "utf8")); });
SRC.mig = lf(fs.readFileSync(path.join(REPO, MIG_FILE), "utf8"));
const FE = {};
["scripts/bf-support.js", "support.html", "profile.html", "seller.html", "card-view.html", "wallet.html", "digital-cards.html", "app.html",
  "_redirects", "sitemap.xml", "terms.html", "privacy.html", "scripts/termaximus-guide.js", "scripts/termaximus-presence.js"].forEach(f => {
  const p = path.join(FRONTEND, f);
  FE["fe:" + f] = fs.existsSync(p) ? lf(fs.readFileSync(p, "utf8")) : null;
});
const ALL = Object.assign({}, SRC, FE);
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) ALL[file] = s.replaceOnce(ALL[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}
const SV = ALL[SV_FILE];
const fe = f => ALL["fe:" + f];

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}

/* ── the libs, compiled from the (possibly mutated) text ─────────────────── */
const realRequire = Module.createRequire(path.join(REPO, "server.js"));
const LIB_CACHE = {};
function loadLib(rel) {
  if (LIB_CACHE[rel]) return LIB_CACHE[rel].exports;
  const file = path.join(REPO, rel);
  const m = new Module(file, module);
  m.filename = file;
  m.paths = Module._nodeModulePaths(path.dirname(file));
  LIB_CACHE[rel] = m;
  m.require = function (req) {
    if (req.indexOf("./") === 0 || req.indexOf("../") === 0) {
      const target = path.relative(REPO, path.join(path.dirname(file), req)).replace(/\\/g, "/").replace(/(\.js)?$/, ".js");
      if (ALL[target] !== undefined) return loadLib(target);
      return realRequire(path.join(REPO, target));
    }
    return realRequire(req);
  };
  m._compile(ALL[rel], file);
  return m.exports;
}
const L = loadLib(LINKS), P = loadLib(PAGE), T = loadLib(TRADES);
const LIMITS = realRequire("./lib/bfcTransferLimits");

/* ── an in-memory database ───────────────────────────────────────────────── */
let idSeq = 1;
const nextId = () => "row-" + (idSeq++);
function likeMatch(text, pattern) {
  const BS = String.fromCharCode(92);
  const toks = [];
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === BS && i + 1 < pattern.length) toks.push({ lit: pattern[++i].toLowerCase() });
    else if (ch === "%") toks.push({ any: true });
    else if (ch === "_") toks.push({ one: true });
    else toks.push({ lit: ch.toLowerCase() });
  }
  const str = String(text).toLowerCase();
  const m = (i, j) => {
    if (j === toks.length) return i === str.length;
    const t = toks[j];
    if (t.any) return m(i, j + 1) || (i < str.length && m(i + 1, j));
    if (i >= str.length) return false;
    return (t.one || t.lit === str[i]) && m(i + 1, j + 1);
  };
  return m(0, 0);
}
const DEFAULTS = { member_support: () => ({ links: [], headline: null, page_on: null, discoverable: false }) };
function project(rows, cols) {
  if (!cols || cols === "*") return rows.map(r => JSON.parse(JSON.stringify(r)));
  const names = cols.split(",").map(c => c.trim());
  return rows.map(r => { const o = {}; names.forEach(n => { o[n] = r[n] === undefined ? null : JSON.parse(JSON.stringify(r[n])); }); return o; });
}
function makeDb(seed) {
  const t = JSON.parse(JSON.stringify(seed));
  const db = { t, reads: [], rpcCalls: [] };
  db.from = function (table) {
    const st = { op: "select", cols: null, ret: null, filters: [], orders: [], range: null, limit: null, row: null, conflict: null };
    function run() {
      db.reads.push(table + ":" + st.op);
      if (!t[table]) return Promise.resolve({ data: null, error: { code: "42P01", message: "relation " + table + " does not exist" } });
      if (st.op === "insert") {
        const rows = (Array.isArray(st.row) ? st.row : [st.row]).map(r => Object.assign({ id: nextId(), created_at: new Date().toISOString() }, JSON.parse(JSON.stringify(r))));
        t[table].push(...rows);
        return Promise.resolve({ data: st.ret ? project(rows, st.ret) : null, error: null });
      }
      if (st.op === "upsert") {
        const key = st.conflict;
        let ex = t[table].find(r => r[key] === st.row[key]);
        if (ex) Object.assign(ex, JSON.parse(JSON.stringify(st.row)));
        else { ex = Object.assign((DEFAULTS[table] || (() => ({})))(), JSON.parse(JSON.stringify(st.row))); t[table].push(ex); }
        return Promise.resolve({ data: project([ex], st.ret || "*"), error: null });
      }
      let rows = t[table].filter(r => st.filters.every(f => f(r)));
      if (st.op === "update") { rows.forEach(r => Object.assign(r, st.row)); return Promise.resolve({ data: project(rows, st.ret || "*"), error: null }); }
      rows = rows.slice().sort((x, y) => { for (const [c, asc] of st.orders) { if (x[c] < y[c]) return asc ? -1 : 1; if (x[c] > y[c]) return asc ? 1 : -1; } return 0; });
      if (st.range) rows = rows.slice(st.range[0], st.range[1] + 1);
      if (st.limit != null) rows = rows.slice(0, st.limit);
      return Promise.resolve({ data: project(rows, st.cols), error: null });
    }
    const q = {
      select(c) { if (st.op === "select") st.cols = c || "*"; else st.ret = c || "*"; return q; },
      insert(r) { st.op = "insert"; st.row = r; return q; },
      upsert(r, o) { st.op = "upsert"; st.row = r; st.conflict = (o && o.onConflict) || "id"; return q; },
      update(p) { st.op = "update"; st.row = p; return q; },
      eq(c, v) { st.filters.push(r => r[c] === v); return q; },
      neq(c, v) { st.filters.push(r => r[c] !== v); return q; },
      gte(c, v) { st.filters.push(r => r[c] >= v); return q; },
      gt(c, v) { st.filters.push(r => r[c] > v); return q; },
      lt(c, v) { st.filters.push(r => r[c] < v); return q; },
      in(c, vs) { st.filters.push(r => vs.indexOf(r[c]) !== -1); return q; },
      ilike(c, p) { st.filters.push(r => r[c] != null && likeMatch(r[c], p)); return q; },
      order(c, o) { st.orders.push([c, !o || o.ascending !== false]); return q; },
      range(a, b) { st.range = [a, b]; return q; },
      limit(n) { st.limit = n; return q; },
      maybeSingle() { return run().then(r => r.error ? r : r.data.length > 1 ? { data: null, error: { code: "PGRST116", message: r.data.length + " rows" } } : { data: r.data[0] || null, error: null }); },
      single() { return run().then(r => r.error ? r : r.data.length !== 1 ? { data: null, error: { code: "PGRST116", message: r.data.length + " rows" } } : { data: r.data[0], error: null }); },
      then(ok, bad) { return run().then(ok, bad); }
    };
    return q;
  };
  db.rpc = async function (name, args) {
    db.rpcCalls.push({ name, args: JSON.parse(JSON.stringify(args)) });
    if (name !== "bfc_send") return { data: null, error: { code: "PGRST202", message: "Could not find the function public." + name } };
    try { return { data: bfcSend150(t, args), error: null }; } catch (e) { return { data: null, error: { message: e.message } }; }
  };
  return db;
}
/* Migration 150's bfc_send, modelled: 148's limits, then the kind and note. */
const DAY_MS = 24 * 60 * 60 * 1000;
function bfcSend150(t, a) {
  if (!(a.p_max_per_transfer >= 1 && a.p_daily_cap >= 1 && a.p_hold_days >= 0)) throw new Error("limits_invalid: every transfer limit must be given");
  const kind = a.p_kind === undefined ? "transfer" : a.p_kind, note = a.p_note === undefined ? null : a.p_note;
  if (kind == null || ["transfer", "support"].indexOf(kind) === -1 || (note !== null && kind !== "support")) throw new Error("invalid_kind: a transfer is a transfer or support");
  if (note !== null && !(note.length >= 1 && note.length <= 840)) throw new Error("violates check constraint bfc_transfers_note_check");
  if (a.p_from === a.p_to) throw new Error("cannot transfer to self");
  if (!(a.p_amount > 0)) throw new Error("amount must be positive");
  if (a.p_amount > a.p_max_per_transfer) throw new Error("over_per_transfer_max: too much for one transfer");
  if (!t.users.some(u => u.id === a.p_to)) throw new Error("unknown_recipient: no account has the id " + a.p_to);
  const sender = t.users.find(u => u.id === a.p_from);
  if (!sender) throw new Error("unknown_sender: no account has the id " + a.p_from);
  if (Date.parse(sender.created_at) > Date.now() - a.p_hold_days * DAY_MS) throw new Error("new_account_hold: too new");
  const since = new Date(Date.now() - DAY_MS).toISOString();
  const sent = t.wallet_transactions.filter(x => x.user_id === a.p_from && x.type === "debit" && (x.description === "Transfer" || x.description.indexOf("Donation: ") === 0) && x.created_at > since)
    .reduce((n, x) => n + x.amount, 0);
  if (sent + a.p_amount > a.p_daily_cap) throw new Error("over_daily_cap: " + sent + " BFC sent in the last 24 hours");
  const fw = t.user_wallets.find(w => w.user_id === a.p_from);
  if (!fw || fw.balance < a.p_amount) throw new Error("insufficient balance");
  let tw = t.user_wallets.find(w => w.user_id === a.p_to);
  if (!tw) { tw = { user_id: a.p_to, balance: 0 }; t.user_wallets.push(tw); }
  fw.balance -= a.p_amount; tw.balance += a.p_amount;
  const at = new Date().toISOString();
  t.wallet_transactions.push({ id: nextId(), user_id: a.p_from, type: "debit", amount: a.p_amount, description: "Transfer", created_at: at });
  t.wallet_transactions.push({ id: nextId(), user_id: a.p_to, type: "credit", amount: a.p_amount, description: "Transfer", created_at: at });
  t.bfc_transfers.push({ id: nextId(), sender_id: a.p_from, recipient_id: a.p_to, amount_bfc: a.p_amount, kind, note, created_at: at });
  return fw.balance;
}

/* ── the fixture ─────────────────────────────────────────────────────────── */
const SAM = "5a5a5a5a-0000-4000-8000-000000000001", RITA = "7e7e7e7e-0000-4000-8000-000000000002", NINA = "9c9c9c9c-0000-4000-8000-000000000003";
const LOU = "1d1d1d1d-0000-4000-8000-000000000004", ANON = "2b2b2b2b-0000-4000-8000-000000000005", OTTO = "3c3c3c3c-0000-4000-8000-000000000006";
const NED = "4e4e4e4e-0000-4000-8000-000000000007", PAT = "6f6f6f6f-0000-4000-8000-000000000008";
const INACTIVE = new Set([LOU, PAT]);
const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
const PRIVATE = { email: "rita+bftest@example.com", phone: "+1 555 0100", contact: "rita.private@example.com" };
const NOTE = "Thanks for the kiln tips <3";
const RITA_PHOTO = "https://cdn.example.com/rita.jpg";
function daysAgo(n) { return new Date(Date.now() - n * DAY_MS).toISOString(); }
function seed() {
  const users = [[SAM, 30], [RITA, 30], [NINA, 2], [LOU, 30], [ANON, 30], [OTTO, 30], [NED, 30], [PAT, 30]].map(([id, d]) => ({ id, role: "user", created_at: daysAgo(d), email: id === RITA ? PRIVATE.email : id.slice(0, 4) + "+bftest@example.com" }));
  const t = {
    users,
    user_wallets: users.map(u => ({ user_id: u.id, balance: 5000 })),
    wallet_transactions: users.map(u => ({ id: nextId(), user_id: u.id, type: "reward", amount: 5000, description: "Welcome bonus", created_at: daysAgo(20) })),
    bfc_transfers: [], notifications: [], marketplace_orders: [], campaign_donations: [], crowdfunding_campaigns: [],
    bf_profiles: [
      { user_id: SAM, username: "sam", display_name: "Sam Stone", avatar_url: null },
      { user_id: RITA, username: "rita", display_name: "Rita Reyes", avatar_url: RITA_PHOTO, phone: PRIVATE.phone, contact_email: PRIVATE.contact, email: PRIVATE.email },
      { user_id: NINA, username: "nina", display_name: "Nina New", avatar_url: null },
      { user_id: LOU, username: "lou", display_name: "Lou Lapsed", avatar_url: null },
      { user_id: OTTO, username: "otto", display_name: "Otto Off", avatar_url: null },
      { user_id: NED, username: "ned", display_name: "Ned None", avatar_url: null },
      { user_id: PAT, username: "pat", display_name: "Pat Paused", avatar_url: null }
    ],
    member_support: [
      { user_id: RITA, links: [{ provider: "paypal", handle: "RitaR" }, { provider: "kofi", handle: "rita_r" }], headline: "Potter, teacher, kiln fixer", page_on: null, discoverable: false },
      { user_id: OTTO, links: [{ provider: "paypal", handle: "OttoO" }], headline: null, page_on: false, discoverable: true },
      { user_id: PAT, links: [{ provider: "paypal", handle: "PatP" }], headline: null, page_on: true, discoverable: true }
    ]
  };
  return t;
}

/* ── server.js, lifted ───────────────────────────────────────────────────── */
function routeText(sig) {
  const start = SV.indexOf(sig);
  if (start < 0 || SV.indexOf(sig, start + 1) !== -1) return null;
  const end = s.braceMatch(SV, SV.indexOf("{", SV.indexOf("async function", start)));
  return SV.slice(start, end) + ");";
}
function fnText(name) {
  const m = new RegExp("^(?:async )?function " + name + "\\(", "m").exec(SV);
  if (!m) return null;
  return SV.slice(m.index, s.braceMatch(SV, SV.indexOf(") {", m.index) + 2));
}
const R = {
  transfer: routeText('app.post("/api/wallet/transfer",'),
  support: routeText('app.post("/api/wallet/support",'),
  meGet: routeText('app.get("/api/support/me",'),
  mePut: routeText('app.put("/api/support/me",'),
  page: routeText('app.get("/support/:username",'),
  sitemap: routeText('app.get("/api/sitemap/support.xml",')
};
const STUB = new Set(["supabase", "console", "process", "require", "module", "app", "requireAuth", "getUserPlan", "rateLimit",
  "bfcTransferLimits", "bfcCountsTowardDailyCap", "Date", "Math", "JSON", "Object", "Number", "String", "Array", "Promise", "Error", "Set", "Map", "URL", "Buffer"]);
function closure(root) {
  const have = new Map();
  const queue = [...new Set(root.match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || STUB.has(name)) continue;
    const def = s.definitionOf(SV, name);
    if (!def) continue;
    try { new vm.Script(def); } catch (e) { continue; }
    have.set(name, def);
    new Set(def.match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !STUB.has(id)) queue.push(id); });
  }
  return [...have.values()].sort((x, y) => SV.indexOf(x) - SV.indexOf(y)).join("\n\n") + "\n\n" + root;
}
let CUR = makeDb(seed());
const LIMITER_OPTS = [];
const ROUTES = {};
const CTX = {
  supabase: { from: t => CUR.from(t), rpc: (n, a) => CUR.rpc(n, a) },
  console: { log() {}, warn() {}, error() {} },
  process: { env: {} },
  require: function (p) {
    if (p.indexOf("./") === 0) { const rel = p.slice(2).replace(/(\.js)?$/, ".js"); if (ALL[rel] !== undefined) return loadLib(rel); return realRequire(p); }
    return realRequire(p);
  },
  requireAuth: function requireAuth(req, res, next) { next(); },
  getUserPlan: async function (id) { return INACTIVE.has(id) ? { active: false, plan: null, subscription: null, inactive_reason: "no_subscription", access_reason: null } : { active: true, plan: "all_access", subscription: { status: "active" }, access_reason: "subscription" }; },
  rateLimit: function (opts) { const f = function limiter(req, res, next) { next(); }; f.opts = opts; LIMITER_OPTS.push(opts); return f; },
  bfcTransferLimits: LIMITS.bfcTransferLimits, bfcCountsTowardDailyCap: LIMITS.bfcCountsTowardDailyCap,
  app: {}
};
["get", "post", "put", "delete", "use"].forEach(v => { CTX.app[v] = function (p) { ROUTES[v + " " + p] = Array.prototype.slice.call(arguments, 1); }; });
let LIFT_ERROR = null;
try {
  vm.createContext(CTX);
  const root = [R.transfer, R.support, R.meGet, R.mePut, R.page, R.sitemap, fnText("publicSupportLinks"), fnText("requireActiveSubscription")].join("\n\n");
  vm.runInContext(closure(root), CTX);
} catch (e) { LIFT_ERROR = e; }

function mkRes() {
  return {
    statusCode: 200, body: undefined, text: undefined, headers: {}, ended: false,
    status(c) { this.statusCode = c; return this; },
    json(b) { this.body = JSON.parse(JSON.stringify(b)); this.ended = true; return this; },
    send(t) { this.text = String(t); this.ended = true; return this; },
    set(k, v) { this.headers[k.toLowerCase()] = v; return this; },
    type(v) { this.headers["content-type"] = v; return this; }
  };
}
async function hit(key, user, body, params) {
  const fns = ROUTES[key];
  if (!fns) return { status: 0, error: "no route " + key };
  const req = { method: key.split(" ")[0].toUpperCase(), route: { path: key.split(" ")[1] }, user: user ? { id: user } : undefined, body: body || {}, params: params || {}, query: {}, headers: {} };
  const res = mkRes();
  let err = null, reached = false;
  for (let i = 0; i < fns.length; i++) {
    let advanced = false;
    if (i === fns.length - 1) reached = true;
    await fns[i](req, res, e => { if (e) err = e; else advanced = true; });
    if (err || !advanced || res.ended) break;
  }
  return { status: res.statusCode, body: res.body, text: res.text, headers: res.headers, err: err && (err.message || String(err)), reached };
}
const snap = () => JSON.stringify([CUR.t.user_wallets, CUR.t.wallet_transactions, CUR.t.bfc_transfers, CUR.t.notifications]);
const support = (from, username, amount, note) => hit("post /api/wallet/support", from, note === undefined ? { username, amount } : { username, amount, note });
const debitsOf = id => CUR.t.wallet_transactions.filter(x => x.user_id === id && x.type === "debit");

/* ── jsdom ───────────────────────────────────────────────────────────────── */
let JSDOM = null;
try { JSDOM = realRequire("jsdom").JSDOM; } catch (e) { JSDOM = null; }
const tick = () => new Promise(r => setTimeout(r, 0));
async function settle() { for (let i = 0; i < 8; i++) await tick(); }
function pageDom(html, url, opts) {
  opts = opts || {};
  const dom = new JSDOM(html, { url: url, runScripts: "outside-only" });
  const w = dom.window;
  const log = { fetches: [], copied: [], shared: [], qr: [], exec: [] };
  if (opts.token) w.localStorage.setItem("bf_token", opts.token);
  w.fetch = function (u, init) {
    log.fetches.push({ url: String(u), init: init || {} });
    const answer = (opts.answers || []).find(a => String(u).indexOf(a.match) !== -1 && (!a.method || (init && init.method) === a.method));
    const body = answer ? answer.body : {};
    const p = Promise.resolve({ ok: !answer || answer.status === undefined || answer.status < 400, status: answer && answer.status || 200, json: () => Promise.resolve(body) });
    p.catch(() => {});
    return p;
  };
  if (opts.clipboard !== false) Object.defineProperty(w.navigator, "clipboard", { configurable: true, value: { writeText: t => { log.copied.push(t); return Promise.resolve(); } } });
  if (opts.share) Object.defineProperty(w.navigator, "share", { configurable: true, value: d => { log.shared.push(d); return Promise.resolve(); } });
  w.document.execCommand = function (c) { log.exec.push(c); return true; };
  w.QRCode = { toCanvas: function (canvas, text, o, cb) { log.qr.push({ id: canvas && canvas.id, text: text, opts: o }); if (cb) cb(null); } };
  w.API_URL = "https://api.example.test";
  return { dom, w, log, run(src) { w.eval(src); } };
}

(async function main() {
  /* ════ A. POST /api/wallet/support ════ */
  console.log("\n══ A. BizCash support: the transfer path, with its kind and note ══");
  check("A0. the routes and their helpers were lifted from server.js and run", !LIFT_ERROR && Object.values(R).every(Boolean) && !!ROUTES["post /api/wallet/support"],
    LIFT_ERROR ? LIFT_ERROR.stack : Object.keys(R).filter(k => !R[k]).join(", "));
  check("A1. the route is POST /api/wallet/support behind requireAuth, requireActiveSubscription and bfcSupportLimiter, in that order",
    /^app\.post\("\/api\/wallet\/support", requireAuth, requireActiveSubscription, bfcSupportLimiter, async function \(req, res, next\) \{/.test(R.support || ""));
  const supLim = LIMITER_OPTS.find(o => o.message && o.message.reason === "rate_limited" && /support/i.test(o.message.error));
  check("A1. the rate limit: 20 support payments in 10 minutes per account, refused with \"Nothing was sent\"",
    !!supLim && supLim.max === 20 && supLim.windowMs === 600000 && supLim.keyGenerator({ user: { id: "u1" } }) === "bfc-support:u1" && /Nothing was sent/.test(supLim.message.error), JSON.stringify(supLim));

  // a support payment, end to end
  CUR = makeDb(seed());
  let r = await support(SAM, "@Rita", 100, NOTE);
  const row = CUR.t.bfc_transfers[CUR.t.bfc_transfers.length - 1];
  check("A2. support of 100 BFC to @Rita goes through: 200 with the balance, bfcDisclaimer and { to: \"@rita\", display_name, amount_bfc }",
    r.status === 200 && r.body && r.body.balance === 4900 && typeof r.body.bfcDisclaimer === "string" && r.body.bfcDisclaimer.length > 40 &&
    JSON.stringify(r.body.support) === JSON.stringify({ to: "@rita", display_name: "Rita Reyes", amount_bfc: 100 }), JSON.stringify(r));
  check("A2. the recipient is named by username: no account id anywhere in the answer", r.body && !UUID.test(JSON.stringify(r.body)), JSON.stringify(r.body));
  check("A2. recorded in bfc_transfers as kind 'support' with the note stored escaped", !!row && row.kind === "support" && row.sender_id === SAM && row.recipient_id === RITA &&
    row.amount_bfc === 100 && row.note === "Thanks for the kiln tips &lt;3", JSON.stringify(row));
  const supCall = CUR.rpcCalls.find(c => c.name === "bfc_send");
  check("A2. bfc_send is called with every limit, p_kind \"support\" and p_note", !!supCall && supCall.args.p_kind === "support" && supCall.args.p_note === "Thanks for the kiln tips &lt;3" &&
    supCall.args.p_max_per_transfer === 1000 && supCall.args.p_daily_cap === 2000 && supCall.args.p_hold_days === 7 && supCall.args.p_amount === 100, JSON.stringify(supCall));
  const legs = CUR.t.wallet_transactions.filter(x => x.amount === 100);
  check("A2. its ledger legs are 'Transfer', so the shared 24-hour total counts them", legs.length === 2 && legs.every(x => x.description === "Transfer") &&
    LIMITS.bfcCountsTowardDailyCap("Transfer"), JSON.stringify(legs));
  const note1 = CUR.t.notifications[0];
  check("A3. the recipient is notified: \"@sam supported you with 100 BFC\", with the note", CUR.t.notifications.length === 1 && note1.user_id === RITA && note1.type === "support" &&
    note1.title === "@sam supported you with 100 BFC" && note1.message === "Thanks for the kiln tips &lt;3" && note1.read === false, JSON.stringify(CUR.t.notifications));
  const blank = await support(SAM, "rita", 5, "   ");
  check("A3. a blank note is no note", blank.status === 200 && CUR.t.bfc_transfers[CUR.t.bfc_transfers.length - 1].note === null && CUR.t.notifications[1].message === null, JSON.stringify(blank));

  // a plain transfer is unchanged
  const tr = await hit("post /api/wallet/transfer", SAM, { recipientUsername: "rita", amount: 50 });
  const trCall = CUR.rpcCalls[CUR.rpcCalls.length - 1];
  check("A4. a transfer still answers { balance, bfcDisclaimer }, calls bfc_send with its six arguments, and is kind 'transfer'",
    tr.status === 200 && JSON.stringify(Object.keys(tr.body)) === JSON.stringify(["balance", "bfcDisclaimer"]) &&
    JSON.stringify(Object.keys(trCall.args).sort()) === JSON.stringify(["p_amount", "p_daily_cap", "p_from", "p_hold_days", "p_max_per_transfer", "p_to"]) &&
    CUR.t.bfc_transfers[CUR.t.bfc_transfers.length - 1].kind === "transfer" && CUR.t.bfc_transfers[CUR.t.bfc_transfers.length - 1].note === null, JSON.stringify(tr));

  // every refusal: its reason, "Nothing was sent", nothing moved, bfc_send never reached
  async function refused(label, from, username, amount, note, status, reason) {
    const before = snap(), calls = CUR.rpcCalls.length;
    const x = await support(from, username, amount, note);
    check("A5. " + label + ": refused " + status + " with reason " + reason + ", \"Nothing was sent\", nothing moved, bfc_send not reached, no id in the answer",
      x.status === status && x.body && x.body.reason === reason && /Nothing was sent/.test(x.body.error) && snap() === before && CUR.rpcCalls.length === calls &&
      !UUID.test(JSON.stringify(x.body)), JSON.stringify(x) + " rpc+" + (CUR.rpcCalls.length - calls));
    return x;
  }
  CUR = makeDb(seed());
  await refused("over the per-transfer maximum (1,001)", SAM, "rita", 1001, undefined, 400, "over_per_transfer_max");
  await refused("from an account opened 2 days ago", NINA, "rita", 10, undefined, 403, "new_account_hold");
  await refused("to oneself", SAM, "sam", 10, undefined, 400, "self_support");
  await refused("to oneself, by another spelling", SAM, "@SAM", 10, undefined, 400, "self_support");
  const unk = await refused("to an unknown username", SAM, "nobody_here", 10, undefined, 404, "unknown_recipient");
  check("A5. the unknown-username refusal says \"No member with that username.\"", unk.body && unk.body.error === "No member with that username. Nothing was sent.", JSON.stringify(unk.body));
  await refused("to a malformed username", SAM, "<script>", 10, undefined, 404, "unknown_recipient");
  for (const bad of [0, -5, 1.5, "5", null]) await refused("an amount of " + JSON.stringify(bad), SAM, "rita", bad, undefined, 400, "invalid_amount");
  await refused("a 141-character note", SAM, "rita", 10, "x".repeat(141), 400, "note_too_long");
  await refused("a note with a control character", SAM, "rita", 10, "hi\u0007there", 400, "invalid_note");
  await refused("a note with a right-to-left override", SAM, "rita", 10, "hi‮there", 400, "invalid_note");
  await refused("a note that is not text", SAM, "rita", 10, { html: "<b>" }, 400, "invalid_note");
  await refused("from a member with no username", ANON, "rita", 10, undefined, 400, "no_username");
  const ok140 = await support(SAM, "rita", 1, "é".repeat(140));
  check("A5. a 140-character note (of 2-byte letters) is accepted", ok140.status === 200, JSON.stringify(ok140.body));

  // the 24-hour total, shared with transfers and donations
  CUR = makeDb(seed());
  await hit("post /api/wallet/transfer", SAM, { recipientUsername: "rita", amount: 900 });
  CUR.t.wallet_transactions.push({ id: nextId(), user_id: SAM, type: "debit", amount: 500, description: "Donation: Kiln fund", created_at: new Date().toISOString() });
  const fits = await support(SAM, "rita", 400);
  check("A6. after a 900 transfer and a 500 donation, 400 support still fits (1,800 of 2,000)", fits.status === 200, JSON.stringify(fits));
  const capped = await refused("300 more support, past the 2,000 total that transfers, donations and support share", SAM, "rita", 300, undefined, 400, "over_daily_cap");
  check("A6. the refusal counts all three: sent_last_24h 1,800", capped.body && capped.body.sent_last_24h === 1800 && capped.body.limit === 2000, JSON.stringify(capped.body));
  const before6 = snap();
  const trCapped = await hit("post /api/wallet/transfer", SAM, { recipientUsername: "rita", amount: 300 });
  check("A6. and a transfer of 300 is refused too: support counts against the transfer's total", trCapped.status === 400 && trCapped.body.reason === "over_daily_cap" && snap() === before6, JSON.stringify(trCapped));
  const old = makeDb(seed());
  old.t.wallet_transactions.push({ id: nextId(), user_id: SAM, type: "debit", amount: 1900, description: "Transfer", created_at: daysAgo(1.1) });
  CUR = old;
  check("A6. sends older than 24 hours do not count", (await support(SAM, "rita", 1000)).status === 200);

  // no subscription
  CUR = makeDb(seed());
  const before7 = snap(), calls7 = CUR.rpcCalls.length;
  const lapsed = await support(LOU, "rita", 10);
  check("A7. without a subscription: 402, the handler never runs, nothing moved", lapsed.status === 402 && !lapsed.reached && snap() === before7 && CUR.rpcCalls.length === calls7,
    JSON.stringify(lapsed));

  /* ════ B. trades ════ */
  console.log("\n══ B. trade records: support given and support received ══");
  CUR = makeDb(seed());
  await support(SAM, "rita", 120, NOTE);
  await hit("post /api/wallet/transfer", SAM, { recipientUsername: "rita", amount: 30 });
  const all = T.periodFrom({});
  const tS = await T.listTrades(CUR, SAM, all), tR = await T.listTrades(CUR, RITA, all), tN = await T.listTrades(CUR, NINA, all);
  const gS = tS.trades.find(x => x.type === "support given"), gR = tR.trades.find(x => x.type === "support received");
  check("B1. the types are listed: \"support given\" and \"support received\"", T.TYPES.indexOf("support given") !== -1 && T.TYPES.indexOf("support received") !== -1 && T.TYPE.supportGiven === "support given");
  check("B1. support given is −120 for the supporter, naming @rita, with the note unescaped", !!gS && gS.bfc === -120 && gS.counterparty === "@rita" && gS.note === NOTE, JSON.stringify(tS.trades));
  check("B1. support received is +120 for the member, naming @sam, with the note", !!gR && gR.bfc === 120 && gR.counterparty === "@sam" && gR.note === NOTE, JSON.stringify(tR.trades));
  check("B1. the transfer beside it is still \"transfer sent\" / \"transfer received\", with no note", tS.trades.some(x => x.type === "transfer sent" && x.bfc === -30 && !("note" in x)) &&
    tR.trades.some(x => x.type === "transfer received" && x.bfc === 30 && !("note" in x)));
  check("B1. a third member's records hold neither the support nor the note", tN.trades.length === 0 && JSON.stringify(tN).indexOf("kiln") === -1, JSON.stringify(tN.trades));
  check("B2. the reconciliation still holds for both members", tS.reconciliation.holds === true && tR.reconciliation.holds === true,
    JSON.stringify([tS.reconciliation, tR.reconciliation]));
  const stS = T.statementOf(tS, new Date().getUTCFullYear()), stR = T.statementOf(tR, new Date().getUTCFullYear());
  check("B2. the statement totals support given and received", stS.totals_by_type["support given"].count === 1 && stS.totals_by_type["support given"].bfc === 120 &&
    stR.totals_by_type["support received"].bfc === 120 && stS.sent_bfc === 150 && stR.received_bfc === 150, JSON.stringify([stS.totals_by_type, stS.sent_bfc, stR.received_bfc]));
  const csvS = T.tradesCsv(tS), csvR = T.tradesCsv(tR);
  check("B3. the CSV's last column is the note, filled on the support line for each party",
    csvS.split("\n")[0].split(",").pop().trim() === "note" && csvS.indexOf("support given") !== -1 && csvS.indexOf("Thanks for the kiln tips <3") !== -1 &&
    csvR.indexOf("support received") !== -1 && csvR.indexOf("Thanks for the kiln tips <3") !== -1, csvS);

  /* ════ C. the allow-list ════ */
  console.log("\n══ C. support links: allow-listed, normalized, rebuilt ══");
  const ACCEPT = [
    ["paypal", "https://paypal.me/JaneDoe", "JaneDoe", "https://paypal.me/JaneDoe"], ["paypal", "paypal.me/janedoe/", "janedoe", "https://paypal.me/janedoe"],
    ["paypal", "https://www.paypal.me/jd2026", "jd2026", "https://paypal.me/jd2026"], ["paypal", "JaneDoe", "JaneDoe", "https://paypal.me/JaneDoe"],
    ["cashapp", "https://cash.app/$JaneDoe", "JaneDoe", "https://cash.app/$JaneDoe"], ["cashapp", "$jd99", "jd99", "https://cash.app/$jd99"],
    ["venmo", "https://venmo.com/u/Jane-Doe", "Jane-Doe", "https://venmo.com/u/Jane-Doe"], ["venmo", "venmo.com/Jane_Doe", "Jane_Doe", "https://venmo.com/u/Jane_Doe"],
    ["venmo", "@jane-doe", "jane-doe", "https://venmo.com/u/jane-doe"], ["venmo", "https://account.venmo.com/u/jane-doe", "jane-doe", "https://venmo.com/u/jane-doe"],
    ["kofi", "https://ko-fi.com/janedoe", "janedoe", "https://ko-fi.com/janedoe"], ["kofi", "ko-fi.com/jane_doe", "jane_doe", "https://ko-fi.com/jane_doe"],
    ["buymeacoffee", "https://buymeacoffee.com/janedoe", "janedoe", "https://buymeacoffee.com/janedoe"], ["buymeacoffee", "www.buymeacoffee.com/jane_doe", "jane_doe", "https://buymeacoffee.com/jane_doe"],
    ["patreon", "https://www.patreon.com/janedoe", "janedoe", "https://patreon.com/janedoe"], ["patreon", "patreon.com/jane_doe", "jane_doe", "https://patreon.com/jane_doe"],
    ["stripe", "https://buy.stripe.com/28o5kD0Ab1cd2Ef3gh", "28o5kD0Ab1cd2Ef3gh", "https://buy.stripe.com/28o5kD0Ab1cd2Ef3gh"], ["stripe", "buy.stripe.com/aBcD1234", "aBcD1234", "https://buy.stripe.com/aBcD1234"]
  ];
  const badAccept = ACCEPT.filter(([p, v, h, u]) => { const n = L.normalizeLink({ provider: p, value: v }); return !n.link || n.link.handle !== h || JSON.stringify(Object.keys(n.link)) !== '["provider","handle"]' || L.publicLink(n.link).url !== u; });
  check("C1. each provider's valid forms are accepted, stored as { provider, handle } only, and the URL is rebuilt (" + ACCEPT.length + ")", badAccept.length === 0,
    badAccept.map(a => a[1] + " -> " + JSON.stringify(L.normalizeLink({ provider: a[0], value: a[1] }))).join(" | "));
  check("C1. every provider has a working example", L.PROVIDER_KEYS.length === 7 && L.PROVIDER_KEYS.every(k => !!L.normalizeLink({ provider: k, value: L.PROVIDERS[k].example }).link));
  const REFUSE = [
    ["paypal", "https://paypa1.me/jane", "wrong_host"], ["paypal", "https://paypal.me.evil.com/jane", "wrong_host"], ["paypal", "paypal.me.evil.com/jane", "wrong_host"],
    ["paypal", "https://evil.com/paypal.me/jane", "wrong_host"], ["paypal", "http://paypal.me/jane", "not_https"], ["paypal", "javascript:alert(1)", "invalid_url"],
    ["paypal", "JaVaScRiPt://paypal.me/jane", "not_https"], ["paypal", "data:text/html,<script>alert(1)</script>", "invalid_url"],
    ["paypal", "https://pаypal.me/jane", "not_ascii"], ["paypal", "https://paypal．me/jane", "not_ascii"], ["paypal", "https://paypal.me/janе", "not_ascii"],
    ["paypal", "https://paypal.me@evil.com/jane", "invalid_host"], ["paypal", "https://paypal.me:8443/jane", "invalid_host"],
    ["paypal", "https://paypal.me/jane/extra", "invalid_path"], ["paypal", "https://paypal.me/jane?amount=5", "extra_parts"], ["paypal", "https://paypal.me/jane#x", "extra_parts"],
    ["paypal", "https://paypal.me/<script>", "invalid_handle"], ["paypal", "https://paypal.me/jane doe", "not_ascii"],
    ["cashapp", "https://cash.app/JaneDoe", "invalid_path"], ["cashapp", "$12345", "invalid_handle"],
    ["venmo", "venmo.com/u/abc", "invalid_handle"], ["venmo", "https://venmo.com/signup", "invalid_handle"], ["venmo", "https://venmo.com/u/jane/pay", "invalid_path"],
    ["kofi", "ko-fi.com/jane.doe", "invalid_handle"], ["patreon", "https://patreon.com/c/jane", "invalid_path"], ["patreon", "https://patreon.com/login", "invalid_handle"],
    ["stripe", "https://buy.stripe.com/test_abc12345", "invalid_handle"], ["stripe", "https://checkout.stripe.com/c/pay/abc12345", "wrong_host"],
    ["gofundme", "https://gofundme.com/f/jane", "unknown_provider"], ["paypal", "", "missing_value"]
  ];
  const badRefuse = REFUSE.filter(([p, v, why]) => { const n = L.normalizeLink({ provider: p, value: v }); return n.link || n.reason !== why || !n.error; });
  check("C2. tricky invalid links are refused, each with its reason (" + REFUSE.length + ")", badRefuse.length === 0,
    badRefuse.map(a => a[1] + " -> " + JSON.stringify(L.normalizeLink({ provider: a[0], value: a[1] }))).join(" | "));
  const six = L.normalizeLinks(Array.from({ length: 6 }, (_, i) => ({ provider: "paypal", value: "jane" + i })));
  const dup = L.normalizeLinks([{ provider: "paypal", value: "Jane" }, { provider: "paypal", value: "https://paypal.me/jane" }]);
  const second = L.normalizeLinks([{ provider: "paypal", value: "jane" }, { provider: "paypal", value: "http://paypal.me/x" }]);
  check("C3. at most five, no duplicates (in any case), and a refusal names the link", six.reason === "too_many_links" && dup.reason === "duplicate_link" && dup.field === "links[1]" &&
    second.reason === "not_https" && second.field === "links[1]", JSON.stringify([six, dup, second]));
  const forged = L.publicLinks([{ provider: "paypal", handle: "RitaR", url: "https://evil.com/steal", note: "x", label: "Evil" }, { provider: "paypal", handle: "a/../b" }, { provider: "zelle", handle: "x" }]);
  check("C4. a stored row is shown only rebuilt: the URL from provider and handle, nothing else carried, a row that no longer passes dropped",
    forged.length === 1 && forged[0].url === "https://paypal.me/RitaR" && forged[0].label === "PayPal" &&
    JSON.stringify(Object.keys(forged[0])) === '["provider","label","handle","url","disclaimer"]', JSON.stringify(forged));

  // PUT /api/support/me
  CUR = makeDb(seed());
  const put = await hit("put /api/support/me", SAM, { links: [{ provider: "paypal", value: "https://www.paypal.me/SamS" }, { provider: "kofi", value: "ko-fi.com/sam_s" }], headline: "  Making   bowls  ", page_on: true });
  const stored = CUR.t.member_support.find(x => x.user_id === SAM);
  check("C5. PUT /api/support/me stores { provider, handle } only, the headline as plain text, and answers the links rebuilt with the support URL",
    put.status === 200 && !!stored && JSON.stringify(stored.links) === '[{"provider":"paypal","handle":"SamS"},{"provider":"kofi","handle":"sam_s"}]' && stored.headline === "Making bowls" &&
    put.body.links[0].url === "https://paypal.me/SamS" && put.body.support_url === "https://bizforceai.net/support/sam" && put.body.page_live === true, JSON.stringify([put, stored]));
  const before8 = JSON.stringify(CUR.t.member_support);
  const putBad = await hit("put /api/support/me", SAM, { links: [{ provider: "paypal", value: "SamS" }, { provider: "paypal", value: "https://paypal.me.evil.com/x" }] });
  const putExtra = await hit("put /api/support/me", SAM, { links: [], user_id: RITA });
  const putLong = await hit("put /api/support/me", SAM, { headline: "h".repeat(121) });
  check("C5. a refused link, an unknown field or a 121-character headline saves nothing and says why",
    putBad.status === 400 && putBad.body.reason === "wrong_host" && putBad.body.field === "links[1]" && putExtra.status === 400 && putExtra.body.reason === "unknown_field" &&
    putLong.status === 400 && putLong.body.reason === "headline_too_long" && JSON.stringify(CUR.t.member_support) === before8, JSON.stringify([putBad.body, putExtra.body, putLong.body]));
  check("C5. GET and PUT /api/support/me need only sign-in (requireAuth): the member's own settings", /^app\.get\("\/api\/support\/me", requireAuth, async function/.test(R.meGet || "") &&
    /^app\.put\("\/api\/support\/me", requireAuth, async function/.test(R.mePut || ""));

  /* ════ D. the public answers ════ */
  console.log("\n══ D. public answers carry only the normalized links ══");
  CUR = makeDb(seed());
  await support(SAM, "rita", 100, NOTE);
  const pub = await CTX.publicSupportLinks(RITA);
  check("D1. publicSupportLinks answers the member's links rebuilt, each exactly provider, label, handle, url, disclaimer",
    pub.length === 2 && pub.every(l => JSON.stringify(Object.keys(l)) === '["provider","label","handle","url","disclaimer"]') && pub[0].url === "https://paypal.me/RitaR" && pub[1].url === "https://ko-fi.com/rita_r", JSON.stringify(pub));
  const PUBLIC_ROUTES = ['app.get("/api/cards/share/:token"', 'app.get("/api/cards/slug/:slug"', 'app.get("/api/bfp/profile/:userId"', 'app.get("/api/bfp/seller/:handle"'];
  const pubTexts = PUBLIC_ROUTES.map(sig => { const a = SV.indexOf(sig); return a < 0 ? "" : SV.slice(a, s.braceMatch(SV, SV.indexOf("{", SV.indexOf("async function", a)))); });
  check("D2. the profile, storefront and both card routes add support_links from publicSupportLinks, and nothing else about support",
    pubTexts.every(x => (x.match(/support_links: (?:data \? )?await publicSupportLinks\(/g) || []).length === 1 && !/member_support|bfc_transfers|note/.test(x.replace(/support_links: [^\n]*\n/, ""))),
    PUBLIC_ROUTES.filter((sig, i) => !/support_links: (?:data \? )?await publicSupportLinks\(/.test(pubTexts[i])).join(", "));
  check("D3. publicSupportLinks reads member_support's links only, through readMemberSupport", /supportLinks\.publicLinks\(got\.row && got\.row\.links\)/.test(fnText("publicSupportLinks") || "") &&
    /\.select\("user_id, links, headline, page_on, discoverable"\)/.test(fnText("readMemberSupport") || ""));
  const ritaPage = await hit("get /support/:username", null, {}, { username: "rita" });
  const smap0 = await hit("get /api/sitemap/support.xml", null, {}, {});
  check("D4. the note is in no public answer: not the links, not the support page, not the sitemap",
    [JSON.stringify(pub), ritaPage.text || "", smap0.text || ""].every(x => x.indexOf("kiln tips") === -1 && x.indexOf("Thanks for") === -1), (ritaPage.text || "").slice(0, 200));

  /* ════ E. the support page ════ */
  console.log("\n══ E. the support page: bizforceai.net/support/<username> ══");
  const html = ritaPage.text || "";
  check("E1. GET /support/rita: 200, HTML, nosniff, the name, photo, @username and headline", ritaPage.status === 200 && /text\/html/.test(ritaPage.headers["content-type"] || "") &&
    ritaPage.headers["x-content-type-options"] === "nosniff" && html.indexOf('<h1 id="supName">Rita Reyes</h1>') !== -1 && html.indexOf('src="' + RITA_PHOTO + '"') !== -1 &&
    html.indexOf("@rita") !== -1 && html.indexOf('<p class="sup-headline">Potter, teacher, kiln fixer</p>') !== -1, html.slice(0, 300));
  const anchors = [...html.matchAll(/<a class="sup-link" href="([^"]*)"([^>]*)>([^<]*)<\/a>(<span class="sup-disclaimer">([^<]*)<\/span>)?/g)];
  check("E2. each link a provider-labelled button: target=_blank, rel=\"noopener noreferrer\", the rebuilt URL, and the provider's disclaimer beside it",
    anchors.length === 2 && anchors[0][1] === "https://paypal.me/RitaR" && anchors[0][3] === "Support on PayPal" && anchors[1][3] === "Support on Ko-fi" &&
    anchors.every(a => /^ target="_blank" rel="noopener noreferrer"$/.test(a[2])) &&
    anchors[0][5] === "Payments go directly to this member through PayPal. BizForce does not handle, hold or refund them." &&
    anchors[1][5] === "Payments go directly to this member through Ko-fi. BizForce does not handle, hold or refund them.", JSON.stringify(anchors.map(a => a[0])));
  check("E2. the disclaimer is the brief's sentence, word for word", L.disclaimer("Venmo") === "Payments go directly to this member through Venmo. BizForce does not handle, hold or refund them.");
  const meta = (attr, name) => { const m = new RegExp('<meta ' + attr + '="' + name.replace(/[.:]/g, "\\$&") + '" content="([^"]*)"/>').exec(html); return m && m[1]; };
  check("E3. title, og:title and twitter:title are \"Support Rita Reyes on BizForce\"; description from the headline; og:image the photo",
    /<title>Support Rita Reyes on BizForce<\/title>/.test(html) && meta("property", "og:title") === "Support Rita Reyes on BizForce" && meta("name", "twitter:title") === "Support Rita Reyes on BizForce" &&
    meta("name", "description") === "Potter, teacher, kiln fixer" && meta("property", "og:description") === "Potter, teacher, kiln fixer" && meta("property", "og:image") === RITA_PHOTO &&
    meta("name", "twitter:image") === RITA_PHOTO, [meta("property", "og:title"), meta("name", "description"), meta("property", "og:image")].join(" | "));
  check("E3. canonical and og:url are https://bizforceai.net/support/rita", html.indexOf('<link rel="canonical" href="https://bizforceai.net/support/rita"/>') !== -1 && meta("property", "og:url") === "https://bizforceai.net/support/rita");
  check("E4. not discoverable: noindex", meta("name", "robots") === "noindex");
  const noPhoto = P.render(P.viewFor({ username: "sam", display_name: "Sam" }, { links: [{ provider: "paypal", handle: "SamS" }] }));
  check("E3. with no photo, the BizForce default image", noPhoto.indexOf('<meta property="og:image" content="https://bizforceai.net/icons/icon-512.png"/>') !== -1);
  const leaks = [PRIVATE.email, PRIVATE.phone, PRIVATE.contact, RITA, "5000", "4900", "balance"].filter(v => html.indexOf(v) !== -1);
  const full = P.render(P.viewFor({ user_id: RITA, username: "rita", display_name: "Rita Reyes", avatar_url: RITA_PHOTO, email: PRIVATE.email, phone: PRIVATE.phone, contact_email: PRIVATE.contact },
    CUR.t.member_support[0]));
  const leaks2 = [PRIVATE.email, PRIVATE.phone, PRIVATE.contact, RITA].filter(v => full.indexOf(v) !== -1);
  check("E5. nothing private: no email, phone, account id or balance on the page, even when the profile row given to the template holds them",
    leaks.length === 0 && leaks2.length === 0 && !UUID.test(html), leaks.concat(leaks2).join(", "));
  check("E5. the member is read by findMemberByUsername (user_id, username, display_name, avatar_url) and their support row only",
    /const member = await findMemberByUsername\(raw\);/.test(R.page || "") && /\.select\("user_id, username, display_name, avatar_url"\)/.test(fnText("findMemberByUsername") || ""));
  check("E6. the page carries Support with BizCash, the sign-in offer, Share, Copy link and the QR canvas, and its scripts",
    ["<h2 id=\"supBfcTitle\">Support with BizCash</h2>", ">Sign in to support with BizCash</a>", 'id="supShareBtn">Share</button>', 'id="supCopyBtn">Copy link</button>',
      '<canvas id="supQr"', '<script src="/scripts/bf-support.js"></script>', P.QR_SCRIPT].every(x => html.indexOf(x) !== -1));
  const cardQr = /<script src="https:\/\/cdn\.jsdelivr\.net\/npm\/qrcode@1\.4\.4\/build\/qrcode\.min\.js" integrity="sha384-[^"]+" crossorigin="anonymous"><\/script>/.exec(fe("digital-cards.html") || "");
  check("E6. the QR library is the card's, with its SRI hash", !!cardQr && cardQr[0] === P.QR_SCRIPT, cardQr && cardQr[0]);

  // off, none, invalid, not public
  const ottoPage = await hit("get /support/:username", null, {}, { username: "otto" });
  check("E7. the off switch: a member with links who turned the page off gets \"This member's support page is off\", no links, noindex",
    ottoPage.status === 200 && /<h1>This member's support page is off<\/h1>/.test(ottoPage.text || "") && (ottoPage.text || "").indexOf("paypal.me") === -1 &&
    /<meta name="robots" content="noindex"\/>/.test(ottoPage.text || ""), (ottoPage.text || "").slice(0, 400));
  const nedPage = await hit("get /support/:username", null, {}, { username: "ned" });
  check("E7. off until the member adds a link or turns it on: no settings row is the off page", nedPage.status === 200 && /This member's support page is off/.test(nedPage.text || ""));
  check("E7. pageIsOn: off with no row, with links and no choice on, explicit off wins over links, explicit on with no links on",
    L.pageIsOn(null) === false && L.pageIsOn({ links: [{ provider: "paypal", handle: "x" }], page_on: null }) === true &&
    L.pageIsOn({ links: [{ provider: "paypal", handle: "x" }], page_on: false }) === false && L.pageIsOn({ links: [], page_on: true }) === true && L.pageIsOn({ links: [], page_on: null }) === false);
  for (const [label, uname] of [["an unknown username", "nobody"], ["a member whose subscription lapsed (their pages are not public)", "pat"]]) {
    const x = await hit("get /support/:username", null, {}, { username: uname });
    check("E8. " + label + ": 404 \"No member found\", noindex", x.status === 404 && /<h1>No member found<\/h1>/.test(x.text || "") && /<meta name="robots" content="noindex"\/>/.test(x.text || ""), x.status + " " + (x.text || "").slice(0, 200));
  }
  for (const uname of ["bad name!", "a".repeat(41), "../etc", "%3Cscript%3E", ""]) {
    const reads = CUR.reads.length;
    const x = await hit("get /support/:username", null, {}, { username: uname });
    check("E8. the invalid username " + JSON.stringify(uname.slice(0, 12)) + ": 404 \"No member found\" without a read", x.status === 404 && /No member found/.test(x.text || "") && CUR.reads.length === reads);
  }
  const pageLim = LIMITER_OPTS.find(o => o.max === 120);
  check("E9. the page and its sitemap are rate-limited per IP: 120 in 10 minutes", !!pageLim && pageLim.windowMs === 600000 &&
    /^app\.get\("\/support\/:username", supportPageLimiter, async function/.test(R.page || "") && /^app\.get\("\/api\/sitemap\/support\.xml", supportPageLimiter, async function/.test(R.sitemap || ""));

  // discovery
  check("E10. the support sitemap lists no one who did not opt in", (smap0.text || "").indexOf("<loc>") === -1 && /<urlset xmlns="http:\/\/www\.sitemaps\.org\/schemas\/sitemap\/0\.9">/.test(smap0.text || ""), smap0.text);
  await hit("put /api/support/me", RITA, { discoverable: true });
  const ritaIdx = await hit("get /support/:username", null, {}, { username: "rita" });
  const smap1 = await hit("get /api/sitemap/support.xml", null, {}, {});
  check("E10. opted in: the page is indexable and listed; the off page (otto, opted in) and a lapsed member (pat, opted in) are not",
    /<meta name="robots" content="index, follow"\/>/.test(ritaIdx.text || "") && (smap1.text || "").indexOf("<loc>https://bizforceai.net/support/rita</loc>") !== -1 &&
    (smap1.text.match(/<loc>/g) || []).length === 1, smap1.text);

  // the shell
  check("E11. support.html is the same template's shell (scripts/buildSupportPage.js), carrying data-bf-page and noindex",
    fe("support.html") === P.render({ state: "shell" }) && /<html lang="en" data-bf-page="support.html">/.test(fe("support.html") || "") &&
    /<meta name="robots" content="noindex"\/>/.test(fe("support.html") || ""));
  const redir = (fe("_redirects") || "").split("\n");
  const iSup = redir.indexOf("/support/:username https://dynamic-prosperity-production-5382.up.railway.app/support/:username 200");
  const iMap = redir.indexOf("/sitemap-support.xml https://dynamic-prosperity-production-5382.up.railway.app/api/sitemap/support.xml 200");
  const iAll = redir.indexOf("/* /app.html 200");
  check("E12. Netlify proxies /support/:username and /sitemap-support.xml to the backend, above the catch-all; the sitemap index lists it",
    iSup > 0 && iMap > 0 && iSup < iAll && iMap < iAll && (fe("sitemap.xml") || "").indexOf("<sitemap><loc>https://bizforceai.net/sitemap-support.xml</loc></sitemap>") !== -1);

  /* ════ F. the page's script ════ */
  console.log("\n══ F. scripts/bf-support.js, run in jsdom ══");
  if (!JSDOM) { check("F0. jsdom is installed", false); }
  else {
    const SUP = fe("scripts/bf-support.js");
    const URL0 = "https://bizforceai.net/support/Rita?ref=share";
    // signed out
    let d = pageDom(html, URL0);
    d.run(SUP); await settle();
    const signIn = d.w.document.getElementById("supSignIn"), form = d.w.document.getElementById("supBfcForm");
    check("F1. signed out: \"Sign in to support with BizCash\" shows and the form does not", !signIn.hidden && form.hidden && signIn.textContent === "Sign in to support with BizCash" && signIn.getAttribute("href") === "/app.html");
    signIn.dispatchEvent(new d.w.Event("click", { cancelable: true }));
    check("F1. pressing it remembers this page to come back to (bf_return_to)", d.w.localStorage.getItem("bf_return_to") === URL0, d.w.localStorage.getItem("bf_return_to"));
    check("F2. the QR code is drawn on #supQr with the page's exact URL, not the address bar's", d.log.qr.length === 1 && d.log.qr[0].id === "supQr" && d.log.qr[0].text === "https://bizforceai.net/support/rita",
      JSON.stringify(d.log.qr));
    d.w.document.getElementById("supShareBtn").click(); await settle();
    check("F3. Share with no share sheet copies the link and says \"Link copied\"", d.log.copied[0] === "https://bizforceai.net/support/rita" && d.w.document.getElementById("supShareStatus").textContent === "Link copied",
      JSON.stringify(d.log.copied));
    d = pageDom(html, URL0, { share: true });
    d.run(SUP); await settle();
    d.w.document.getElementById("supShareBtn").click(); await settle();
    check("F3. Share with a share sheet opens it with the title and the page's URL", d.log.shared.length === 1 && d.log.shared[0].url === "https://bizforceai.net/support/rita" &&
      d.log.shared[0].title === "Support Rita Reyes on BizForce" && d.log.copied.length === 0, JSON.stringify(d.log.shared));
    d = pageDom(html, URL0, { clipboard: false });
    d.run(SUP); await settle();
    d.w.document.getElementById("supCopyBtn").click(); await settle();
    check("F3. Copy link with no Clipboard API falls back to a copy command, then \"Link copied\"", d.log.exec.indexOf("copy") !== -1 && d.w.document.getElementById("supShareStatus").textContent === "Link copied");

    // signed in, not the owner
    d = pageDom(html, URL0, { token: "tok", answers: [{ match: "/api/support/me", body: { support_url: "https://bizforceai.net/support/sam" } },
      { match: "/api/wallet/support", method: "POST", body: { balance: 4975, support: { to: "@rita" } } }] });
    d.run(SUP); await settle();
    const doc = d.w.document;
    check("F4. signed in: the form shows, the sign-in offer does not", !doc.getElementById("supBfcForm").hidden && doc.getElementById("supSignIn").hidden);
    doc.getElementById("supAmount").value = "25"; doc.getElementById("supNote").value = "for the glaze";
    doc.getElementById("supBfcForm").dispatchEvent(new d.w.Event("submit", { cancelable: true })); await settle();
    const posted0 = d.log.fetches.filter(f => /\/api\/wallet\/support$/.test(f.url));
    check("F4. the confirm step reads \"Send 25 BFC to Rita Reyes (@rita) as support?\" and nothing is sent yet",
      doc.getElementById("supConfirmText").textContent === "Send 25 BFC to Rita Reyes (@rita) as support?" && !doc.getElementById("supConfirm").hidden && posted0.length === 0,
      doc.getElementById("supConfirmText").textContent + " / posts " + posted0.length);
    doc.getElementById("supConfirmBtn").click(); await settle();
    const posted = d.log.fetches.filter(f => /\/api\/wallet\/support$/.test(f.url));
    check("F4. Send posts exactly { username, amount, note } to POST /api/wallet/support, and says so", posted.length === 1 && posted[0].init.method === "POST" &&
      posted[0].init.body === JSON.stringify({ username: "rita", amount: 25, note: "for the glaze" }) && doc.getElementById("supBfcStatus").textContent === "Sent 25 BFC to @rita as support. Thank you.",
      JSON.stringify(posted) + " " + doc.getElementById("supBfcStatus").textContent);
    // the owner
    d = pageDom(html, URL0, { token: "tok", answers: [{ match: "/api/support/me", body: { support_url: "https://bizforceai.net/support/rita" } }] });
    d.run(SUP); await settle();
    check("F5. never on the member's own page: no form, no sign-in offer", d.w.document.getElementById("supBfcForm").hidden && d.w.document.getElementById("supSignIn").hidden);

    // the block on the profile, storefront and card
    const blockPage = "<!DOCTYPE html><html><head></head><body><div id=\"box\"></div></body></html>";
    d = pageDom(blockPage, "https://bizforceai.net/profile.html?u=rita");
    d.run(SUP);
    d.w.BFSupport.mountPublic(d.w.document.getElementById("box"), { username: "rita", displayName: "Rita Reyes", links: pub.concat([{ provider: "x", label: "Evil", url: "javascript:alert(1)", disclaimer: "" }]), bizcash: true });
    await settle();
    const box = d.w.document.getElementById("box");
    const as = [...box.querySelectorAll("a.sup-link")];
    check("F6. the profile/storefront block: provider buttons in a new tab, rel=\"noopener noreferrer\", each under its disclaimer; a non-https URL is not drawn",
      as.length === 2 && as.every(a => a.getAttribute("target") === "_blank" && a.getAttribute("rel") === "noopener noreferrer" && /^https:\/\//.test(a.getAttribute("href")) &&
        a.nextElementSibling && a.nextElementSibling.className === "sup-disclaimer" && /^Payments go directly to this member through (PayPal|Ko-fi)\. BizForce does not handle, hold or refund them\.$/.test(a.nextElementSibling.textContent)),
      box.innerHTML.slice(0, 400));
    check("F6. signed out, the block offers \"Sign in to support with BizCash\" and links the support page", box.textContent.indexOf("Sign in to support with BizCash") !== -1 &&
      !!box.querySelector('a[href="https://bizforceai.net/support/rita"]'));
    d.w.BFSupport.mountPublic(d.w.document.getElementById("box"), { displayName: "Otto", links: [], bizcash: false });
    check("F6. off unless the member adds links: no links and no BizCash draws nothing", box.hidden === true && box.textContent === "");
    // your support link
    d = pageDom(blockPage, "https://bizforceai.net/wallet.html", { token: "tok", answers: [{ match: "/api/support/me", body: { support_url: "https://bizforceai.net/support/sam", page_live: true } }] });
    d.run(SUP);
    d.w.BFSupport.mountOwnLink(d.w.document.getElementById("box")); await settle();
    const own = d.w.document.getElementById("box");
    const ownBtns = [...own.querySelectorAll("button")].map(b => b.textContent);
    check("F7. \"Your support link\" with the URL, Copy and Share", own.querySelector("h3").textContent === "Your support link" && own.querySelector("a").textContent === "https://bizforceai.net/support/sam" &&
      JSON.stringify(ownBtns) === '["Copy","Share"]', own.innerHTML.slice(0, 300));
    own.querySelectorAll("button")[0].click(); await settle();
    check("F7. Copy copies it and says \"Link copied\"", d.log.copied[0] === "https://bizforceai.net/support/sam" && own.querySelector(".sup-status").textContent === "Link copied");

    // app.html: back to the page after sign-in, and only to this site's public pages
    const app = fe("app.html") || "";
    const at = app.indexOf("  function signInReturnTo() {");
    let fn = null;
    try { fn = at < 0 ? null : app.slice(at, s.braceMatch(app, app.indexOf("{", at)) + 0); } catch (e) { fn = null; }
    function returnTo(stored) {
      const store = { bf_return_to: stored };
      const ctx = { URL, window: { location: { origin: "https://bizforceai.net" } }, localStorage: { getItem: k => store[k] === undefined ? null : store[k], removeItem: k => { delete store[k]; } } };
      vm.createContext(ctx);
      vm.runInContext(fn + "\nthis.__r = signInReturnTo();", ctx);
      return { r: ctx.__r, left: store.bf_return_to };
    }
    let rt = null;
    try {
      rt = [returnTo("https://bizforceai.net/support/rita"), returnTo("https://bizforceai.net/seller.html?u=rita"), returnTo("https://evil.com/support/rita"),
        returnTo("https://bizforceai.net/dashboard.html"), returnTo("javascript:alert(1)"), returnTo("//evil.com/support/rita")];
    } catch (e) { rt = String(e); }
    check("F8. after sign-in, app.html returns to the support page (or storefront), once, and to nothing off this site's public pages",
      Array.isArray(rt) && rt[0].r === "/support/rita" && rt[0].left === undefined && rt[1].r === "/seller.html?u=rita" && rt.slice(2).every(x => x.r === null) &&
      /window\.location\.href = signInReturnTo\(\) \|\| "\/dashboard\.html";/.test(app), JSON.stringify(rt));
  }

  // the pages are wired
  const prof = fe("profile.html") || "", sel = fe("seller.html") || "", cv = fe("card-view.html") || "", wal = fe("wallet.html") || "", dc = fe("digital-cards.html") || "";
  const TAG = '<script src="/scripts/bf-support.js"></script>';
  check("F9. profile: visitors get the block with Support with BizCash; the owner gets their support link and the settings instead",
    prof.indexOf(TAG) !== -1 && /supportLinksData = Array\.isArray\(pBody\.support_links\) \? pBody\.support_links : \[\];/.test(prof) &&
    /if \(isOwner\) \{\n    document\.getElementById\("supportOwn"\)\.hidden = false;\n    window\.BFSupport\.mountOwnLink\(document\.getElementById\("supportOwnLink"\)\);\n    window\.BFSupport\.mountSettings\(document\.getElementById\("supportSettings"\)\);\n    return;\n  \}/.test(prof) &&
    /links: supportLinksData, bizcash: true/.test(prof));
  check("F9. storefront: the seller's links and Support with BizCash from data.support_links", sel.indexOf(TAG) !== -1 && sel.indexOf('<div class="sf-section" id="sec-support" hidden></div>') !== -1 &&
    /mountPublic\(document\.getElementById\("sec-support"\), \{\n    username: seller\.username, displayName: seller\.display_name \|\| seller\.username, links: data\.support_links \|\| \[\], bizcash: true/.test(sel));
  check("F9. card: a Support button opens the owner's links only (no BizCash)", cv.indexOf(TAG) !== -1 && /renderCardSupport\(d\.support_links \|\| \[\]\);/.test(cv) &&
    /mountPublic\(panel, \{ displayName: cardData && cardData\.full_name, links: links, bizcash: false \}\);/.test(cv) && cv.indexOf('id="cvSupportBtn"') !== -1);
  check("F9. card editor and wallet: \"Your support link\" (mountOwnLink)", [dc, wal].every(x => x.indexOf(TAG) !== -1 && /window\.BFSupport\.mountOwnLink\(document\.getElementById\("supportOwnLink"\)\)/.test(x) &&
    x.indexOf('id="supportOwnLink"') !== -1));
  const recv = (() => { const a = wal.indexOf("async function loadSupportReceived() {"); return a < 0 ? "" : wal.slice(a, s.braceMatch(wal, wal.indexOf("{", a))); })();
  check("F10. wallet: \"Support received\" from GET /api/notifications (type support), drawn as text; a trade line shows its note",
    wal.indexOf('<div class="trades-sub">Support received</div>') !== -1 && /\/api\/notifications/.test(recv) && /n\.type === "support"/.test(recv) && /textContent/.test(recv) && !/innerHTML/.test(recv) &&
    /\(t\.note \? " \\u2014 \\u201c" \+ t\.note \+ "\\u201d" : ""\)/.test(wal) && /app\.get\("\/api\/notifications", requireAuth,/.test(SV));

  /* ════ G. legal, guide, app map, migration ════ */
  console.log("\n══ G. Terms, Privacy, guide, app map, migration 150 ══");
  const terms = fe("terms.html") || "", priv = fe("privacy.html") || "";
  const LP = realRequire("./lib/legalPages");
  const escH = t => t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  check("G1. the Terms carry \"Member support\" with its five points", terms.indexOf('<h3 id="support">Member support</h3>') !== -1 && LP.MEMBER_SUPPORT_TERMS.length === 5 &&
    LP.MEMBER_SUPPORT_TERMS.every(b => terms.indexOf("<li>" + escH(b) + "</li>") !== -1) && /does not handle, hold or refund the money/.test(LP.MEMBER_SUPPORT_TERMS.join(" ")));
  const versionOf = t => { const m = /const TERMS_VERSION = "(\d{4}-\d{2}-\d{2})";/.exec(t); return m && m[1]; };
  let preVersion = null;
  try { preVersion = versionOf(execFileSync("git", ["show", PRE_SUPPORT + ":lib/legal.js"], { cwd: REPO, encoding: "utf8" })); } catch (e) { preVersion = null; }
  const nowVersion = versionOf(ALL[LEGAL]);
  check("G1. TERMS_VERSION moved past " + PRE_SUPPORT + "'s (" + preVersion + "), so members are asked to accept again", !!preVersion && !!nowVersion && nowVersion > preVersion, nowVersion);
  check("G2. Privacy: support data is public when the page is on, notes private to the two members", priv.indexOf(escH(LP.SUPPORT_PRIVACY_SENTENCE)) !== -1 &&
    /public on your support page/.test(LP.SUPPORT_PRIVACY_SENTENCE) && /seen only by you and the member you support/.test(LP.SUPPORT_PRIVACY_SENTENCE));
  const guide = fe("scripts/termaximus-guide.js") || "", pres = fe("scripts/termaximus-presence.js") || "";
  check("G3. the guide has a support.html entry, and the guide and the mist read the page's own key (data-bf-page)", /\n    "support\.html": \[\n/.test(guide) &&
    [guide, pres].every(x => /var named = document\.documentElement\.getAttribute\("data-bf-page"\);\n    if \(named\) return named\.toLowerCase\(\);/.test(x)));
  const mapRun = spawnSync(process.execPath, [path.join(REPO, "scripts/buildAppMap.js"), "--check"], { cwd: REPO, encoding: "utf8", env: Object.assign({}, process.env, { BIZFORCE_FRONTEND_DIR: FRONTEND }) });
  const appMap = fs.readFileSync(path.join(REPO, "lib/appMap.json"), "utf8");
  check("G4. lib/appMap.json is fresh, and maps support.html", mapRun.status === 0 && appMap.indexOf('"support.html"') !== -1, (mapRun.stdout || "") + (mapRun.stderr || ""));

  const MIG = ALL.mig;
  const migs = fs.readdirSync(path.join(REPO, "supabase/migrations")).filter(f => /^\d+_/.test(f)).map(f => Number(f.split("_")[0]));
  // NAMED (Oct 28 2026, the learning loop): BEFORE "migration 150 is the next free number", the highest of all.
  // AFTER migration 151 follows it, so 150 is asserted unique and next after 149, not the highest.
  check("G5. migration 150 is unique and the next number after 149", migs.filter(n => n === 150).length === 1 && Math.max(...migs.filter(n => n < 150)) === 149);
  check("G5. bfc_transfers gains kind (default 'transfer', so every existing row is a transfer) and note, allowed only on support",
    MIG.indexOf("ALTER TABLE public.bfc_transfers ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'transfer';") !== -1 &&
    MIG.indexOf("ALTER TABLE public.bfc_transfers ADD COLUMN IF NOT EXISTS note text;") !== -1 &&
    MIG.indexOf("CHECK (kind IN ('transfer', 'support'))") !== -1 && MIG.indexOf("CHECK (note IS NULL OR (kind = 'support' AND char_length(note) BETWEEN 1 AND 840))") !== -1);
  check("G5. bfc_send: the six-argument function dropped, the eight-argument one defaulted to a transfer, service_role only",
    MIG.indexOf("DROP FUNCTION IF EXISTS public.bfc_send(uuid, uuid, integer, integer, integer, integer);") !== -1 &&
    MIG.indexOf("p_hold_days integer, p_kind text DEFAULT 'transfer', p_note text DEFAULT NULL)") !== -1 &&
    MIG.indexOf("revoke execute on function public.bfc_send(uuid, uuid, integer, integer, integer, integer, text, text) from public, anon, authenticated;") !== -1 &&
    MIG.indexOf("grant  execute on function public.bfc_send(uuid, uuid, integer, integer, integer, integer, text, text) to service_role;") !== -1);
  check("G5. support's ledger legs are 'Transfer', inside the 24-hour total that counts 'Transfer' and 'Donation: ' debits, under the wallet lock",
    MIG.indexOf("v_balance := bfc_transfer(p_from, p_to, p_amount, 'Transfer');") !== -1 && MIG.indexOf("and (description = 'Transfer' or description like 'Donation: %')") !== -1 &&
    MIG.indexOf("perform 1 from user_wallets where user_id = p_from for update;") < MIG.indexOf("select coalesce(sum(amount), 0) into v_sent") &&
    MIG.indexOf("insert into bfc_transfers (sender_id, recipient_id, amount_bfc, kind, note)\nvalues (p_from, p_to, p_amount, p_kind, p_note);") !== -1);
  check("G5. member_support: one row per member, at most five links, a 120-character headline, discovery off by default, row level security on",
    /CREATE TABLE IF NOT EXISTS public\.member_support \(\n  user_id      uuid        PRIMARY KEY REFERENCES public\.users\(id\) ON DELETE CASCADE,/.test(MIG) &&
    MIG.indexOf("jsonb_array_length(links) <= 5") !== -1 && MIG.indexOf("char_length(headline) BETWEEN 1 AND 120") !== -1 &&
    MIG.indexOf("discoverable boolean     NOT NULL DEFAULT false,") !== -1 && MIG.indexOf("alter table public.member_support enable row level security;") !== -1);

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
