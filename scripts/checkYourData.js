/* ══════════════════════════════════════════════════════════════════════════
   checkYourData — every member can see, download and delete their data, and
   what your-data.html says about it is true.

   Runs lib/yourData.js, and the three routes lifted out of server.js, against
   in-memory tables. A stubbed session, no network, no database.

     A. The one description. Every table in lib/backup.js's three lists and
        every live table the migrations create is either in DATA or in
        NOT_MEMBER_DATA. Every table the delete deletes is in the delete order
        exactly once.
     B. The export (GET /api/me/export, run through the route):
        - every one of the caller's rows, in every listed table, and none of
          another member's;
        - no password hash, session secret, key material or API key;
        - another member by username only;
        - manifest counts that match the file;
        - the route needs a session but no subscription, allows 3 a day, and
          logs counts but not contents.
     C. The delete refuses (POST /api/me/delete, run through the route), and
        changes nothing, when:
        - the username is not typed exactly;
        - the password is wrong;
        - the subscription is active or past_due;
        - the account is an admin's.
     D. After the delete:
        - the member's private rows are gone;
        - shared records are kept, unchanged, and show "a deleted member";
        - consent evidence is kept and hashed;
        - the ledger still adds up;
        - every session is gone;
        - sign-in fails (requireAuth and the login route, lifted from
          server.js);
        - the email can open a new account;
        - a second delete changes nothing.
     E. A failure part-way is reported with what was done and what failed. A
        retry finishes it.
     F. your-data.html, run against a fake page:
        - every statement it shows is the description's;
        - with no description, it shows none;
        - its own markup makes no claim;
        - the links to it are in place.
     G. Every protection claim is tied to a fact asserted here.

   MUTATE=<name> applies one mutation and must fail; MUTATE=all runs each.
   ══════════════════════════════════════════════════════════════════════════ */
"use strict";

const fs = require("fs");
const path = require("path");
const Module = require("module");
const bcrypt = require("bcryptjs");
const MUT = require("./_shared");
const { braceMatch } = MUT;
const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");

const MUTATIONS = ["export-leaks-other-user", "export-includes-password-hash", "export-shows-counterparty-id",
  "delete-skips-password", "delete-hard-deletes-shared-order", "delete-during-active-subscription", "ledger-unbalanced",
  "consent-evidence-deleted", "tombstone-keeps-email", "requireauth-admits-deleted", "page-hardcodes-claim", "unbacked-claim"];
const MUTATE = process.env.MUTATE || "";
// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") MUT.runAllMutations(__filename, MUTATIONS);
if (MUTATE && MUTATIONS.indexOf(MUTATE) === -1) {
  console.error("Unknown MUTATE=" + MUTATE + ". Known: " + MUTATIONS.join(", "));
  process.exit(2);
}

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

const lf = s => s.replace(/\r\n/g, "\n");
const read = rel => lf(fs.readFileSync(path.join(REPO, rel), "utf8"));
let LIB = read("lib/yourData.js");
let SERVER = read("server.js");
let PAGE = lf(fs.readFileSync(path.join(FRONTEND, "your-data.html"), "utf8"));

if (MUTATE === "export-leaks-other-user") LIB = MUT.replaceOnce(LIB, "return q.eq(col, userId);", "return q;", MUTATE);
if (MUTATE === "export-includes-password-hash") LIB = MUT.replaceOnce(LIB, "select: \"id, email, business_name", "select: \"id, email, password_hash, business_name", MUTATE);
if (MUTATE === "export-shows-counterparty-id") LIB = MUT.replaceOnce(LIB, "row[col] = mine ? \"you\" : names[row[col]];", "row[col] = mine ? \"you\" : row[col];", MUTATE);
if (MUTATE === "delete-skips-password") LIB = MUT.replaceOnce(LIB, "if (!passwordOk) return", "if (false) return", MUTATE);
if (MUTATE === "delete-hard-deletes-shared-order") LIB = MUT.replaceOnce(LIB, "\"bizdoc_documents\", \"marketplace_listings\",", "\"bizdoc_documents\", \"marketplace_listings\", \"marketplace_orders\",", MUTATE);
if (MUTATE === "delete-during-active-subscription") LIB = MUT.replaceOnce(LIB, "if (paying.length) {", "if (false) {", MUTATE);
if (MUTATE === "ledger-unbalanced") LIB = MUT.replaceOnce(LIB, "var r = await supabase.rpc(\"bfc_debit\", { p_user_id: userId, p_amount: balance, p_description: FORFEIT_DESCRIPTION });",
  "var r = await supabase.from(\"user_wallets\").update({ balance: 0 }).eq(\"user_id\", userId);", MUTATE);
if (MUTATE === "consent-evidence-deleted") LIB = MUT.replaceOnce(LIB, "var dropped = contacts.filter(function (id) { return withConsent.indexOf(id) === -1; });", "var dropped = contacts.slice();", MUTATE);
if (MUTATE === "tombstone-keeps-email") LIB = MUT.replaceOnce(LIB, "email: \"deleted-\" + userId + DELETED_EMAIL_DOMAIN, ", "", MUTATE);
if (MUTATE === "requireauth-admits-deleted") SERVER = MUT.replaceOnce(SERVER, "    if (user.role === \"deleted\") {\n      return res.status(401).json({ error: \"Account deleted\" });", "    if (false) {\n      return res.status(401).json({ error: \"Account deleted\" });", MUTATE);
if (MUTATE === "page-hardcodes-claim") PAGE = MUT.replaceOnce(PAGE, "<ul id=\"protections\"></ul>", "<ul id=\"protections\"><li>Military-grade encryption keeps your data safe.</li></ul>", MUTATE);
if (MUTATE === "unbacked-claim") LIB = MUT.replaceOnce(LIB, "const PROTECTIONS = [\n", "const PROTECTIONS = [\n  { key: \"e2e\", text: \"End-to-end encrypted.\" },\n", MUTATE);

/* A module loaded from (possibly mutated) source text, resolving its own requires from its real path. */
function loadFrom(rel, src) {
  const file = path.join(REPO, rel);
  const m = new Module(file, module);
  m.filename = file;
  m.paths = Module._nodeModulePaths(path.dirname(file));
  m._compile(src, file);
  return m.exports;
}
function sliceFrom(src, sig, what) {
  const start = src.indexOf(sig);
  if (start === -1) throw new Error(what + " was not found in server.js");
  const end = braceMatch(src, src.indexOf("{", start + sig.length - 1));
  return src.slice(start, end);
}
// The handler of a route: from "function (req, res" (async or not) to its closing brace.
function handlerSource(src, sig) {
  const start = src.indexOf(sig);
  if (start === -1) throw new Error("route " + sig + " was not found in server.js");
  const lineEnd = src.indexOf("\n", start);
  let fnAt = src.indexOf("function (req, res", start);
  if (fnAt === -1 || fnAt > lineEnd) throw new Error("route " + sig + " has no handler on its first line");
  if (src.slice(fnAt - 6, fnAt) === "async ") fnAt -= 6;
  const end = braceMatch(src, src.indexOf("{", fnAt));
  return src.slice(fnAt, end);
}

// ── in-memory tables ─────────────────────────────────────────────────────────
function makeDb(tables) {
  const db = { tables: tables, failOn: null, seq: 0, writes: 0 };
  function rowsOf(t) { return db.tables[t] || (db.tables[t] = []); }
  function matches(row, filters) {
    return filters.every(function (f) {
      if (f.op === "eq") return row[f.col] === f.val;
      if (f.op === "in") return f.val.indexOf(row[f.col]) !== -1;
      if (f.op === "is") return (row[f.col] === undefined ? null : row[f.col]) === f.val;
      return false;
    });
  }
  function project(row, cols, table) {
    if (cols === "*") return Object.assign({}, row);
    const out = {}, parts = [];
    let depth = 0, cur = "";
    for (const ch of cols) { if (ch === "(") depth++; if (ch === ")") depth--; if (ch === "," && depth === 0) { parts.push(cur); cur = ""; } else cur += ch; }
    parts.push(cur);
    parts.map(s => s.trim()).filter(Boolean).forEach(function (c) {
      const embed = /^(\w+)\((.*)\)$/.exec(c);
      if (embed) {
        const u = rowsOf(embed[1]).find(r => r.id === row.user_id);
        out[embed[1]] = u ? project(u, embed[2], embed[1]) : null;
      } else out[c] = row[c] === undefined ? null : row[c];
    });
    return out;
  }
  function query(table) {
    const q = { table: table, op: "select", cols: "*", filters: [], orderKey: null, from: null, to: null, single: false, patch: null };
    const api = {
      select(cols) { if (q.op === "select") q.cols = cols || "*"; return api; },
      update(patch) { q.op = "update"; q.patch = patch; return api; },
      delete() { q.op = "delete"; return api; },
      eq(col, val) { q.filters.push({ op: "eq", col: col, val: val }); return api; },
      in(col, val) { q.filters.push({ op: "in", col: col, val: val }); return api; },
      is(col, val) { q.filters.push({ op: "is", col: col, val: val }); return api; },
      order(key) { q.orderKey = key; return api; },
      range(a, b) { q.from = a; q.to = b; return api; },
      limit(n) { q.from = 0; q.to = n - 1; return api; },
      maybeSingle() { q.single = true; return api; },
      then(resolve, reject) { return Promise.resolve().then(run).then(resolve, reject); }
    };
    function run() {
      if (db.failOn) { const e = db.failOn(table, q.op); if (e) return { data: null, error: { message: e } }; }
      const all = rowsOf(table);
      let hit = all.filter(r => matches(r, q.filters));
      if (q.op === "select") {
        if (q.orderKey) hit = hit.slice().sort((x, y) => String(x[q.orderKey]) < String(y[q.orderKey]) ? -1 : String(x[q.orderKey]) > String(y[q.orderKey]) ? 1 : 0);
        if (q.from !== null) hit = hit.slice(q.from, q.to + 1);
        const data = hit.map(r => project(r, q.cols, table));
        if (q.single) { if (data.length > 1) return { data: null, error: { message: "more than one row" } }; return { data: data[0] || null, error: null }; }
        return { data: data, error: null };
      }
      db.writes++;
      if (q.op === "update") { hit.forEach(r => Object.assign(r, q.patch)); return { data: null, error: null }; }
      if (q.op === "delete") { db.tables[table] = all.filter(r => hit.indexOf(r) === -1); return { data: null, error: null }; }
      return { data: null, error: { message: "unsupported" } };
    }
    return api;
  }
  db.client = {
    from: query,
    async rpc(name, args) {
      if (db.failOn) { const e = db.failOn("rpc:" + name, "rpc"); if (e) return { data: null, error: { message: e } }; }
      if (name !== "bfc_debit") return { data: null, error: { message: "unknown function " + name } };
      db.writes++;
      // migration 121, as written there.
      if (!(args.p_amount > 0)) return { data: null, error: { message: "amount must be positive" } };
      const w = rowsOf("user_wallets").find(r => r.user_id === args.p_user_id);
      if (!w) return { data: null, error: { message: "wallet not found" } };
      if (w.balance < args.p_amount) return { data: null, error: { message: "insufficient balance" } };
      w.balance -= args.p_amount;
      rowsOf("wallet_transactions").push({ id: "wt-new-" + (++db.seq), user_id: args.p_user_id, type: "debit", amount: args.p_amount, description: args.p_description || "", created_at: "2026-10-21T12:00:00Z" });
      return { data: w.balance, error: null };
    }
  };
  db.rows = rowsOf;
  db.snapshot = function () { return JSON.stringify(db.tables, Object.keys(db.tables).sort().reduce((a, t) => a, undefined)); };
  return db;
}
const clone = v => JSON.parse(JSON.stringify(v));
const canon = tables => JSON.stringify(Object.keys(tables).sort().map(t => [t, tables[t].slice().sort((x, y) => JSON.stringify(x) < JSON.stringify(y) ? -1 : 1)]));

(async function main() {
  const YD = loadFrom("lib/yourData.js", LIB);
  const backup = require(path.join(REPO, "lib/backup.js"));

  // ── the people ──
  const A = "aaaaaaaa-0000-4000-8000-00000000000a";   // the caller
  const B = "bbbbbbbb-0000-4000-8000-00000000000b";   // another member, @bob
  const C = "cccccccc-0000-4000-8000-00000000000c";   // a member deleted earlier
  const ADMIN = "dddddddd-0000-4000-8000-00000000000d";
  const A_EMAIL = "alice+bftest@bizforceai.invalid", B_EMAIL = "bob+bftest@bizforceai.invalid";
  const A_PASSWORD = "correct horse battery";
  const A_HASH = await bcrypt.hash(A_PASSWORD, 4), B_HASH = await bcrypt.hash("bob's password", 4);
  const SECRETS = { hash: A_HASH, refresh: "REFRESH-HASH-SECRET-A", cipher: "CIPHERTEXT-SECRET-A", iv: "IV-SECRET-A", tag: "AUTHTAG-SECRET-A",
    pubkey: "PUBLIC-KEY-SECRET-A", credential: "CREDENTIAL-ID-SECRET-A", endpoint: "https://push.example/ENDPOINT-SECRET-A", p256: "P256DH-SECRET-A",
    pushauth: "PUSHAUTH-SECRET-A", verify: "VERIFY-TOKEN-SECRET-A", reset: "RESET-TOKEN-SECRET-A", challenge: "CHALLENGE-SECRET-A" };

  /* Every DATA table gets rows for A and for B, by its owner column or through
     its parent. Ids carry the owner, so a leak is visible in the file. */
  function seed() {
    const t = {};
    const put = (table, row) => (t[table] = t[table] || []).push(row);
    put("users", { id: A, email: A_EMAIL, password_hash: A_HASH, business_name: "Alice Co", industry: "bakery", bio: "Alice's bio", avatar_url: "a.png",
      subscription_status: "canceled", subscription_id: "sub_A", created_at: "2026-01-01T00:00:00Z", role: "user", verification_status: "none", banned_at: null,
      email_verification_token: SECRETS.verify, signup_ip: "10.0.0.1", updated_at: "2026-01-01T00:00:00Z", password_reset_token: SECRETS.reset,
      password_reset_expires_at: "2026-12-01T00:00:00Z", last_login_at: "2026-10-01T00:00:00Z", last_login_ip: "10.0.0.2", email_verified_at: "2026-01-02T00:00:00Z",
      email_verification_expires_at: null });
    put("users", { id: B, email: B_EMAIL, password_hash: B_HASH, business_name: "Bob Co", role: "user", created_at: "2026-01-01T00:00:00Z", signup_ip: "10.9.9.9" });
    put("users", { id: C, email: "deleted-" + C + "@deleted.invalid", password_hash: "!deleted", role: "deleted", created_at: "2025-01-01T00:00:00Z" });
    put("users", { id: ADMIN, email: "owner+bftest@bizforceai.invalid", password_hash: B_HASH, role: "admin", created_at: "2025-01-01T00:00:00Z" });
    put("profiles", { id: "profiles-A", user_id: A, username: "alice", full_name: "Alice A" });
    put("profiles", { id: "profiles-B", user_id: B, username: "bob", full_name: "Bob B" });
    put("profiles", { id: "profiles-ADMIN", user_id: ADMIN, username: "owner" });
    put("bf_profiles", { id: "bf_profiles-A", user_id: A, username: "alice", display_name: "Alice" });
    put("bf_profiles", { id: "bf_profiles-B", user_id: B, username: "bob", display_name: "Bob" });
    put("bf_profiles", { id: "bf_profiles-ADMIN", user_id: ADMIN, username: "owner" });
    put("auth_sessions", { id: "auth_sessions-A", user_id: A, refresh_token_hash: SECRETS.refresh, issued_at: "2026-10-20T00:00:00Z", expires_at: "2099-01-01T00:00:00Z", last_used_at: null, revoked_at: null, user_agent: "UA", ip: "10.0.0.3" });
    put("auth_sessions", { id: "auth_sessions-B", user_id: B, refresh_token_hash: "REFRESH-B", issued_at: "2026-10-20T00:00:00Z", expires_at: "2099-01-01T00:00:00Z", revoked_at: null });
    put("webauthn_credentials", { id: "webauthn_credentials-A", user_id: A, credential_id: SECRETS.credential, public_key: SECRETS.pubkey, sign_count: 3, nickname: "Laptop", aaguid: "x", backed_up: true, created_at: "2026-02-01T00:00:00Z", last_used_at: null });
    put("webauthn_credentials", { id: "webauthn_credentials-B", user_id: B, credential_id: "CRED-B", public_key: "PK-B", nickname: "Phone" });
    put("webauthn_challenges", { id: "webauthn_challenges-A", user_id: A, challenge: SECRETS.challenge });
    put("push_subscriptions", { id: "push_subscriptions-A", user_id: A, endpoint: SECRETS.endpoint, p256dh: SECRETS.p256, auth: SECRETS.pushauth, user_agent: "UA", created_at: "2026-03-01T00:00:00Z", last_used_at: null });
    put("user_api_keys", { id: "user_api_keys-A", user_id: A, provider: "anthropic", ciphertext: SECRETS.cipher, iv: SECRETS.iv, auth_tag: SECRETS.tag, created_at: "2026-04-01T00:00:00Z", updated_at: "2026-04-02T00:00:00Z" });
    put("user_api_keys", { id: "user_api_keys-B", user_id: B, provider: "anthropic", ciphertext: "CIPHER-B", iv: "IV-B", auth_tag: "TAG-B" });

    const special = ["users", "profiles", "bf_profiles", "auth_sessions", "webauthn_credentials", "webauthn_challenges", "push_subscriptions", "user_api_keys",
      "contacts", "consent_events", "email_sends", "lead_captures", "sms_subscribers", "sms_send_log", "email_sequence_enrollments", "user_wallets", "wallet_transactions",
      "marketplace_orders", "campaign_donations", "messages", "moderation_logs", "admin_flags", "bizdoc_signatures", "subscriptions", "crm_customers", "crm_activities", "ai_tasks"];
    YD.DATA.forEach(function (e) {
      if (special.indexOf(e.table) !== -1 || e.via) return;
      [["A", A], ["B", B]].forEach(function (pair) {
        const key = e.key || "id";
        const row = { mark: e.table + "-" + pair[0] + "-private" };
        if (key !== "id" || !e.owner || e.owner[0] !== key) row.id = e.table + "-" + pair[0];
        e.owner.forEach(c => { row[c] = pair[1]; });
        if (key !== "id") row[key] = pair[1];
        put(e.table, row);
      });
    });
    // through a parent: the parents above are A's and B's rows of that table
    YD.DATA.filter(e => e.via && e.table !== "email_sends" && e.table !== "consent_events" && e.table !== "email_sequence_enrollments" && e.table !== "bizdoc_signatures" && e.table !== "crm_activities")
      .forEach(function (e) {
        ["A", "B"].forEach(function (who) { put(e.table, { id: e.table + "-" + who, [e.via.column]: e.via.parent + "-" + who, mark: e.table + "-" + who + "-private" }); });
      });
    // many rows, so the export pages (1,000 a page) and chunks its "in" lists (100 at a time)
    for (let i = 0; i < 2345; i++) put("ai_tasks", { id: "ai_tasks-A-" + String(i).padStart(5, "0"), user_id: A, mark: "ai_tasks-A-private" });
    put("ai_tasks", { id: "ai_tasks-B", user_id: B, mark: "ai_tasks-B-private" });
    for (let i = 0; i < 250; i++) {
      put("crm_customers", { id: "crm_customers-A-" + String(i).padStart(3, "0"), user_id: A, mark: "crm_customers-A-private" });
      put("crm_activities", { id: "crm_activities-A-" + String(i).padStart(3, "0"), customer_id: "crm_customers-A-" + String(i).padStart(3, "0"), mark: "crm_activities-A-private" });
    }
    put("crm_customers", { id: "crm_customers-B", user_id: B, mark: "crm_customers-B-private" });
    put("crm_activities", { id: "crm_activities-B", customer_id: "crm_customers-B", mark: "crm_activities-B-private" });

    // contacts and consent: one with consent, one without, the member's own; B's untouched
    put("contacts", { id: "contacts-A-consent", owner_id: A, email: "carol+bftest@bizforceai.invalid", phone: "+15550001", name: "Carol", source: "form" });
    put("contacts", { id: "contacts-A-plain", owner_id: A, email: "dave+bftest@bizforceai.invalid", phone: null, name: "Dave", source: "import" });
    put("contacts", { id: "contacts-A-self", owner_id: A, email: A_EMAIL, phone: null, name: null, source: "account" });
    put("contacts", { id: "contacts-B", owner_id: B, email: "erin+bftest@bizforceai.invalid", phone: "+15550002", name: "Erin", source: "form" });
    put("consent_events", { id: "consent_events-A", contact_id: "contacts-A-consent", channel: "email", action: "granted", ip_address: "10.1.1.1", occurred_at: "2026-05-01T00:00:00Z" });
    put("consent_events", { id: "consent_events-B", contact_id: "contacts-B", channel: "email", action: "granted" });
    put("email_sends", { id: "email_sends-A-consent", contact_id: "contacts-A-consent", to_email: "carol+bftest@bizforceai.invalid", status: "sent", subject: "Hi" });
    put("email_sends", { id: "email_sends-A-bounced", contact_id: "contacts-A-plain", to_email: "dave+bftest@bizforceai.invalid", status: "bounced", subject: "Hi" });
    put("email_sends", { id: "email_sends-A-plain", contact_id: "contacts-A-plain", to_email: "dave+bftest@bizforceai.invalid", status: "sent", subject: "Hi" });
    put("email_sends", { id: "email_sends-A-self", contact_id: "contacts-A-self", to_email: A_EMAIL, status: "sent", subject: "Welcome" });
    put("email_sends", { id: "email_sends-B", contact_id: "contacts-B", to_email: "erin+bftest@bizforceai.invalid", status: "sent" });
    put("email_sequence_enrollments", { id: "email_sequence_enrollments-A", sequence_id: "email_sequences-A", contact_id: "contacts-A-consent" });
    put("email_sequence_enrollments", { id: "email_sequence_enrollments-B", sequence_id: "email_sequences-B", contact_id: "contacts-B" });
    put("lead_captures", { id: "lead_captures-A-consent", owner_id: A, email: "fay+bftest@bizforceai.invalid", phone: "+15550003", name: "Fay", sms_consent: true, email_consent: false, consent_ip: "10.2.2.2" });
    put("lead_captures", { id: "lead_captures-A-none", owner_id: A, email: "gus+bftest@bizforceai.invalid", phone: null, name: "Gus", sms_consent: false, email_consent: false });
    put("lead_captures", { id: "lead_captures-B", owner_id: B, email: "hal+bftest@bizforceai.invalid", name: "Hal", sms_consent: true });
    put("sms_subscribers", { id: "sms_subscribers-A", user_id: A, phone_number: "+15550004", customer_name: "Ivy", product_purchased: "Bread", consent_status: "granted" });
    put("sms_subscribers", { id: "sms_subscribers-B", user_id: B, phone_number: "+15550005", customer_name: "Jo" });
    put("sms_send_log", { id: "sms_send_log-A", user_id: A, phone_number: "+15550004", message_body: "Fresh bread today" });
    put("sms_send_log", { id: "sms_send_log-B", user_id: B, phone_number: "+15550005", message_body: "Hi" });

    // money: balance 150 = 200 in - 50 out; B received the 50
    put("user_wallets", { id: "user_wallets-A", user_id: A, balance: 150 });
    put("user_wallets", { id: "user_wallets-B", user_id: B, balance: 50 });
    put("wallet_transactions", { id: "wallet_transactions-A-1", user_id: A, type: "credit", amount: 200, description: "Certification reward" });
    put("wallet_transactions", { id: "wallet_transactions-A-2", user_id: A, type: "debit", amount: 50, description: "Transfer" });
    put("wallet_transactions", { id: "wallet_transactions-B-1", user_id: B, type: "credit", amount: 50, description: "Transfer" });
    put("subscriptions", { id: "subscriptions-A", user_id: A, status: "canceled", plan: "all_access", stripe_subscription_id: "sub_A" });
    put("subscriptions", { id: "subscriptions-B", user_id: B, status: "active", plan: "all_access" });
    // shared records
    put("marketplace_orders", { id: "order-A-buys-from-B", buyer_id: A, seller_id: B, listing_id: "marketplace_listings-B", listing_title: "Bob's ebook", amount: 10 });
    put("marketplace_orders", { id: "order-B-buys-from-A", buyer_id: B, seller_id: A, listing_id: "marketplace_listings-A", listing_title: "Alice's guide", amount: 20 });
    put("marketplace_orders", { id: "order-A-buys-from-C", buyer_id: A, seller_id: C, listing_title: "Old item", amount: 5 });
    put("marketplace_orders", { id: "order-B-buys-from-C", buyer_id: B, seller_id: C, listing_title: "Not A's", amount: 7 });
    put("campaign_donations", { id: "donation-B-to-A", donor_id: B, owner_id: A, campaign_id: "crowdfunding_campaigns-A", amount: 15 });
    put("campaign_donations", { id: "donation-B-to-B", donor_id: B, owner_id: B, campaign_id: "crowdfunding_campaigns-B", amount: 3 });
    put("messages", { id: "message-A-to-B", sender_id: A, receiver_id: B, body: "Hello Bob" });
    put("messages", { id: "message-B-to-A", sender_id: B, receiver_id: A, body: "Hello Alice" });
    put("messages", { id: "message-B-to-C", sender_id: B, receiver_id: C, body: "Not A's" });
    put("moderation_logs", { id: "moderation-A", target_user_id: A, admin_id: ADMIN, action: "warn", reason: "spam" });
    put("admin_flags", { id: "admin_flags-A", user_id: A, flagged_by: ADMIN, reason: "check" });
    put("bizdoc_signatures", { id: "sig-B-on-A-doc", document_id: "bizdoc_documents-A", signer_id: B, signer_name: "Bob B", signer_email: B_EMAIL, signature_data: "BOB-INK", ip_address: "10.9.9.8", user_agent: "BOB-UA" });
    put("bizdoc_signatures", { id: "sig-A-on-B-doc", document_id: "bizdoc_documents-B", signer_id: A, signer_name: "Alice A", signer_email: A_EMAIL, signature_data: "ALICE-INK" });
    put("bizdoc_signatures", { id: "sig-B-on-B-doc", document_id: "bizdoc_documents-B", signer_id: B, signer_name: "Bob B", signature_data: "BOB-INK-2" });
    return t;
  }

  // ── the reference: which rows are A's, computed here, independently ──
  function ownedBy(tables, entry, uid) {
    const rows = tables[entry.table] || [];
    const parentIds = entry.via ? (tables[entry.via.parent] || []).filter(p => (YD.DATA.find(d => d.table === entry.via.parent).owner || []).some(c => p[c] === uid)).map(p => p[YD.DATA.find(d => d.table === entry.via.parent).key || "id"]) : [];
    return rows.filter(r => (entry.owner || []).some(c => r[c] === uid) || (entry.via && parentIds.indexOf(r[entry.via.column]) !== -1));
  }

  // ── the routes, lifted from server.js ──
  function runRoute(handlerSrc, deps) {
    const names = Object.keys(deps);
    return new Function(...names, "return (" + handlerSrc + ");")(...names.map(n => deps[n]));
  }
  const EXPORT_SIG = "app.get(\"/api/me/export\"";
  const DELETE_SIG = "app.post(\"/api/me/delete\"";
  const DESCRIBE_SIG = "app.get(\"/api/your-data\"";
  function fakeRes() {
    return { statusCode: 200, headers: {}, chunks: [], body: undefined, ended: false,
      status(c) { this.statusCode = c; return this; }, setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
      write(t) { this.chunks.push(String(t)); return true; }, end() { this.ended = true; return this; },
      json(b) { this.body = clone(b); return this; } };
  }
  function quietConsole(lines) {
    return { log: m => lines.push(["log", String(m)]), error: m => lines.push(["error", String(m)]), warn: m => lines.push(["warn", String(m)]) };
  }
  async function doExport(db, uid) {
    const lines = [];
    const handler = runRoute(handlerSource(SERVER, EXPORT_SIG), { yourData: YD, supabase: db.client, console: quietConsole(lines) });
    const res = fakeRes();
    await handler({ user: { id: uid } }, res);
    const text = res.chunks.join("");
    let file = null; try { file = JSON.parse(text); } catch (e) { file = null; }
    return { res, text, file, lines };
  }
  function activeSubscriptionsFrom(db) {
    return async function (uid) { return db.rows("subscriptions").filter(s => s.user_id === uid && ["active", "trialing", "past_due"].indexOf(s.status) !== -1); };
  }
  async function doDelete(db, uid, body) {
    const lines = [];
    const handler = runRoute(handlerSource(SERVER, DELETE_SIG), { yourData: YD, supabase: db.client, console: quietConsole(lines), bcrypt: bcrypt,
      getActiveSubscriptions: activeSubscriptionsFrom(db), OWNER_ACCOUNT_ID: "eeeeeeee-0000-4000-8000-00000000000e" });
    const res = fakeRes();
    await handler({ user: { id: uid }, body: body }, res);
    return { status: res.statusCode, body: res.body || {}, lines };
  }

  // ════ A. the one description ════
  console.log("\n══ A. one description covers every table ══");
  const covered = YD.DATA.map(e => e.table).concat(Object.keys(YD.NOT_MEMBER_DATA));
  const backupTables = [].concat(backup.BACKUP_TABLES, Object.keys(backup.SKIPPED_TABLES), Object.keys(backup.EXCLUDED_TABLES));
  const missingBackup = backupTables.filter(t => covered.indexOf(t) === -1);
  check("A1. every table in lib/backup.js's three lists (" + backupTables.length + ") is in DATA or NOT_MEMBER_DATA", missingBackup.length === 0, missingBackup.join(", "));
  const MIG = path.join(REPO, "supabase", "migrations");
  const live = new Set();
  fs.readdirSync(MIG).filter(f => /\.sql$/.test(f)).sort().forEach(function (f) {
    const sql = lf(fs.readFileSync(path.join(MIG, f), "utf8")).replace(/--[^\n]*/g, "");
    const events = [];
    let m; const cre = /create table (?:if not exists )?(?:public\.)?"?([a-z_0-9]+)"?\s*\(/gi;
    while ((m = cre.exec(sql))) events.push([m.index, "create", m[1].toLowerCase()]);
    const dro = /drop table (?:if exists )?(?:public\.)?"?([a-z_0-9]+)"?/gi;
    while ((m = dro.exec(sql))) events.push([m.index, "drop", m[1].toLowerCase()]);
    events.sort((x, y) => x[0] - y[0]).forEach(ev => { if (ev[1] === "create") live.add(ev[2]); else live.delete(ev[2]); });
  });
  const uncovered = [...live].filter(t => covered.indexOf(t) === -1);
  const notLive = covered.filter(t => !live.has(t));
  check("A2. every live table the migrations create (" + live.size + ") is in DATA or NOT_MEMBER_DATA", uncovered.length === 0, uncovered.join(", "));
  check("A3. and nothing in them names a table that does not exist", notLive.length === 0, notLive.join(", "));
  check("A4. no table is in both", YD.DATA.every(e => !YD.NOT_MEMBER_DATA[e.table]));
  const delTables = YD.DATA.filter(e => e.onDelete === "delete").map(e => e.table);
  const ordered = YD.DELETE_ORDER.concat(YD.FINAL_DELETES);
  check("A5. every table the delete deletes is in the delete order exactly once, and nothing else is",
    delTables.every(t => ordered.filter(x => x === t).length === 1) && ordered.every(t => delTables.indexOf(t) !== -1),
    delTables.filter(t => ordered.filter(x => x === t).length !== 1).concat(ordered.filter(t => delTables.indexOf(t) === -1)).join(", "));
  check("A6. every kept table says why", YD.DATA.every(e => e.onDelete === "delete" || (e.why && e.why.length > 10)),
    YD.DATA.filter(e => e.onDelete !== "delete" && !e.why).map(e => e.table).join(", "));
  {
    const res = fakeRes();
    runRoute(handlerSource(SERVER, DESCRIBE_SIG), { yourData: YD })({}, res);
    check("A7. GET /api/your-data serves the description itself", JSON.stringify(res.body) === JSON.stringify(YD.describe()));
  }

  // ════ B. the export ════
  console.log("\n══ B. the export ══");
  {
    const db = makeDb(seed());
    const before = clone(db.tables);
    const ex = await doExport(db, A);
    check("B1. the file is one JSON document, written in more than one piece", !!ex.file && ex.res.chunks.length > 10, ex.res.chunks.length + " pieces");
    check("B2. it is sent as a download", /attachment; filename="bizforce-your-data-\d{4}-\d{2}-\d{2}\.json"/.test(ex.res.headers["content-disposition"] || "") && ex.res.ended);
    const tablesOut = (ex.file && ex.file.tables) || {};
    const wrong = [];
    YD.DATA.forEach(function (e) {
      const mine = ownedBy(before, e, A);
      if (e.export === false) { if (tablesOut[e.table]) wrong.push(e.table + " is exported but should not be"); return; }
      const got = tablesOut[e.table] || [];
      const key = e.key || "id";
      const wantIds = mine.map(r => r[key]).sort(), gotIds = got.map(r => r[key]).sort();
      if (JSON.stringify(wantIds) !== JSON.stringify(gotIds)) wrong.push(e.table + " " + gotIds.length + "/" + wantIds.length);
    });
    check("B3. every one of the caller's rows, in every one of the " + YD.DATA.filter(e => e.export !== false).length + " exported tables", wrong.length === 0, wrong.slice(0, 6).join("; "));
    check("B4. the paged table came through whole (2,345 agent runs, more than two pages)", (tablesOut.ai_tasks || []).length === 2345, (tablesOut.ai_tasks || []).length);
    check("B5. the table read through 250 parents came through whole (in-lists chunked)", (tablesOut.crm_activities || []).length === 250, (tablesOut.crm_activities || []).length);
    const leaks = [B, ADMIN, C, B_EMAIL, "-B-private", "\"profiles-B\"", "Erin", "CIPHER-B", "BOB-INK", "BOB-UA", "10.9.9.8", "Not A's"].filter(s => ex.text.indexOf(s) !== -1);
    check("B6. none of another member's rows or private fields: no other member's id, email, row or signature", leaks.length === 0, leaks.join(", "));
    const secrets = Object.keys(SECRETS).filter(k => ex.text.indexOf(SECRETS[k]) !== -1);
    check("B7. no password hash, session secret, token, key material or API key ciphertext", secrets.length === 0 && ex.text.indexOf("$2a$") === -1 && ex.text.indexOf("password_hash") === -1, secrets.join(", "));
    const key = (tablesOut.user_api_keys || [])[0] || {};
    check("B8. API keys are listed by provider and date only", JSON.stringify(Object.keys(key).sort()) === JSON.stringify(["created_at", "id", "provider", "updated_at"]), Object.keys(key).join(","));
    const order = (tablesOut.marketplace_orders || []).find(o => o.id === "order-A-buys-from-B") || {};
    const sold = (tablesOut.marketplace_orders || []).find(o => o.id === "order-B-buys-from-A") || {};
    const fromC = (tablesOut.marketplace_orders || []).find(o => o.id === "order-A-buys-from-C") || {};
    check("B9. a counterparty is shown by username only", order.buyer_id === "you" && order.seller_id === "@bob" && sold.buyer_id === "@bob" && sold.seller_id === "you",
      JSON.stringify([order.buyer_id, order.seller_id, sold.buyer_id, sold.seller_id]));
    check("B10. a deleted counterparty is \"a deleted member\"", fromC.seller_id === "a deleted member", fromC.seller_id);
    const msgs = tablesOut.messages || [], mod = (tablesOut.moderation_logs || [])[0] || {}, don = (tablesOut.campaign_donations || [])[0] || {};
    check("B11. messages, donations and moderation records name the other side by username", msgs.length === 2 && msgs.every(m => ["you", "@bob"].indexOf(m.sender_id) !== -1 && ["you", "@bob"].indexOf(m.receiver_id) !== -1) &&
      don.donor_id === "@bob" && don.owner_id === "you" && mod.admin_id === "@owner" && mod.target_user_id === "you", JSON.stringify([don.donor_id, mod.admin_id]));
    const sigs = tablesOut.bizdoc_signatures || [];
    const bobSig = sigs.find(s => s.id === "sig-B-on-A-doc") || {}, mySig = sigs.find(s => s.id === "sig-A-on-B-doc") || {};
    check("B12. a signature on the caller's document shows the signer by username and nothing else of theirs",
      sigs.length === 2 && bobSig.signer_id === "@bob" && !("signer_email" in bobSig) && !("signer_name" in bobSig) && !("signature_data" in bobSig) && !("ip_address" in bobSig) && mySig.signer_id === "you" && mySig.signature_data === "ALICE-INK",
      JSON.stringify(bobSig));
    const man = (ex.file && ex.file.manifest) || {};
    const manWrong = (man.tables || []).filter(t => t.status !== "not exported" && t.rows !== (tablesOut[t.table] || []).length).map(t => t.table);
    check("B13. the manifest lists every table, its count matching the file, with the time it was made", (man.tables || []).length === YD.DATA.length && manWrong.length === 0 &&
      man.complete === true && !isNaN(Date.parse(man.generated_at)) && Object.keys(tablesOut).length === YD.DATA.filter(e => e.export !== false).length, manWrong.join(", "));
    check("B14. the manifest says what was left out, and why the not-exported table is not there", Array.isArray(man.not_exported) && man.not_exported.length === YD.NEVER_EXPORTED.length &&
      (man.tables || []).some(t => t.table === "webauthn_challenges" && t.status === "not exported" && t.why));
    const logText = ex.lines.map(l => l[1]).join("\n");
    check("B15. the export is logged as an event, with counts and no contents", /\[your-data\] export user=\S+ tables=\d+ rows=\d+ complete=true/.test(logText) &&
      [A_EMAIL, "Alice Co", "-A-private", "Hello Bob"].every(s => logText.indexOf(s) === -1), logText.slice(0, 200));
    check("B16. reading changed nothing", canon(db.tables) === canon(before) && db.writes === 0);
    // a table that cannot be read is named, never silently missing
    const db2 = makeDb(seed());
    db2.failOn = (t, op) => t === "ai_reports" && op === "select" ? "relation unavailable" : null;
    const ex2 = await doExport(db2, A);
    const m2 = (ex2.file && ex2.file.manifest) || {};
    check("B17. a table that cannot be read is named in the manifest and the file says it is incomplete", m2.complete === false &&
      (m2.tables || []).some(t => t.table === "ai_reports" && t.status === "unreadable") && ex2.lines.some(l => l[0] === "error" && /INCOMPLETE.*ai_reports/.test(l[1])));
    // the route itself
    const routeLine = SERVER.slice(SERVER.indexOf(EXPORT_SIG), SERVER.indexOf("{", SERVER.indexOf(EXPORT_SIG)));
    check("B18. the route needs a session, not a subscription, and is rate-limited", /requireAuth, yourDataExportLimiter, async function/.test(routeLine) && !/requireActiveSubscription/.test(routeLine));
    const limiter = sliceFrom(SERVER, "const yourDataExportLimiter = rateLimit(", "the export limiter");
    check("B19. 3 a day, per account", /windowMs: 24 \* 60 \* 60 \* 1000,/.test(limiter) && /max: 3,/.test(limiter) && /req\.user && req\.user\.id/.test(limiter));
  }

  // ════ C. the delete refuses ════
  console.log("\n══ C. the delete refuses, and changes nothing ══");
  {
    const db = makeDb(seed());
    const before = canon(db.tables);
    const r1 = await doDelete(db, A, { username: "Alice", password: A_PASSWORD });
    check("C1. a username not typed exactly (\"Alice\" for \"alice\") is refused", r1.status === 400 && r1.body.reason === "username_mismatch", r1.status + " " + r1.body.reason);
    const r2 = await doDelete(db, A, { password: A_PASSWORD });
    check("C2. no username is refused", r2.status === 400 && r2.body.reason === "username_mismatch", r2.status);
    const r3 = await doDelete(db, A, { username: "alice", password: "wrong password" });
    check("C3. a wrong password is refused", r3.status === 403 && r3.body.reason === "password_incorrect", r3.status + " " + r3.body.reason);
    const r4 = await doDelete(db, A, { username: "alice" });
    check("C4. no password is refused", r4.status === 403 && r4.body.reason === "password_incorrect", r4.status);
    check("C5. and none of these changed anything", canon(db.tables) === before && db.writes === 0);
    for (const status of ["active", "past_due", "trialing"]) {
      const dbs = makeDb(seed());
      dbs.rows("subscriptions").find(s => s.user_id === A).status = status;
      const snap = canon(dbs.tables);
      const r = await doDelete(dbs, A, { username: "alice", password: A_PASSWORD });
      check("C6. a subscription that is " + status + " is refused, says to cancel first via the billing link, and changes nothing",
        r.status === 409 && r.body.reason === "subscription_active" && r.body.billing_url === "/billing.html" && /Cancel it first on Billing/.test(r.body.error) &&
        canon(dbs.tables) === snap && dbs.writes === 0, r.status + " " + r.body.reason);
    }
    const dbu = makeDb(seed());
    dbu.failOn = (t, op) => t === "subscriptions" ? "timeout" : null;
    const ru = await (async () => { const lines = []; const h = runRoute(handlerSource(SERVER, DELETE_SIG), { yourData: YD, supabase: dbu.client, console: quietConsole(lines), bcrypt: bcrypt,
      getActiveSubscriptions: async () => { throw new Error("timeout"); }, OWNER_ACCOUNT_ID: "x" }); const res = fakeRes(); await h({ user: { id: A }, body: { username: "alice", password: A_PASSWORD } }, res); return res; })();
    check("C7. a subscription that cannot be read refuses (503), never treated as none", ru.statusCode === 503 && ru.body.reason === "subscription_unreadable" && dbu.writes === 0, ru.statusCode);
    const dba = makeDb(seed());
    const ra = await doDelete(dba, ADMIN, { username: "owner", password: "bob's password" });
    check("C8. an admin account cannot be deleted here", ra.status === 403 && ra.body.reason === "admin_account" && dba.writes === 0, ra.status + " " + ra.body.reason);
    const routeLine = SERVER.slice(SERVER.indexOf(DELETE_SIG), SERVER.indexOf("{", SERVER.indexOf(DELETE_SIG)));
    check("C9. the delete route needs a session", /requireAuth, yourDataDeleteLimiter, async function/.test(routeLine));
  }

  // ════ D. after the delete ════
  console.log("\n══ D. after the delete ══");
  {
    const db = makeDb(seed());
    const before = clone(db.tables);
    const r = await doDelete(db, A, { username: "alice", password: A_PASSWORD });
    check("D1. the delete succeeds", r.status === 200 && r.body.deleted === true, r.status + " " + JSON.stringify(r.body).slice(0, 300));
    const T = db.tables;
    const leftover = YD.DATA.filter(e => e.onDelete === "delete").filter(e => ownedBy(before, e, A).some(row => (T[e.table] || []).some(x => JSON.stringify(x) === JSON.stringify(row))))
      .map(e => e.table);
    check("D2. every private row in the " + YD.DATA.filter(e => e.onDelete === "delete").length + " deleted tables is gone", leftover.length === 0, leftover.join(", "));
    // everything not A's is exactly as it was
    const aIds = new Set();
    YD.DATA.forEach(e => ownedBy(before, e, A).forEach(row => aIds.add(e.table + "|" + JSON.stringify(row))));
    const othersChanged = Object.keys(before).filter(t => before[t].filter(row => !aIds.has(t + "|" + JSON.stringify(row)))
      .some(row => !(T[t] || []).some(x => JSON.stringify(x) === JSON.stringify(row))));
    check("D3. every other member's row is exactly as it was (including bob's contact, consent and signatures)", othersChanged.length === 0, othersChanged.join(", "));
    const keptSame = ["marketplace_orders", "campaign_donations", "messages", "moderation_logs", "admin_flags", "wallet_transactions", "subscriptions", "revenue_events", "model_calls", "youtube_api_calls"]
      .filter(t => (before[t] || []).some(row => !(T[t] || []).some(x => JSON.stringify(x) === JSON.stringify(row))));
    check("D4. shared records are kept unchanged: orders, donations, messages, moderation, ledger rows, billing", keptSame.length === 0, keptSame.join(", "));
    check("D5. the order bob bought from alice is still there", (T.marketplace_orders || []).some(o => o.id === "order-B-buys-from-A" && o.seller_id === A && o.listing_title === "Alice's guide"));
    check("D6. alice's signature on bob's document stays; bob's signature on alice's document went with it",
      (T.bizdoc_signatures || []).some(s => s.id === "sig-A-on-B-doc") && !(T.bizdoc_signatures || []).some(s => s.id === "sig-B-on-A-doc"));
    const exB = await doExport(db, B);
    const bOrders = (exB.file && exB.file.tables.marketplace_orders) || [];
    const bMsgs = (exB.file && exB.file.tables.messages) || [];
    check("D7. de-identified: bob now sees alice as \"a deleted member\", and alice's id, name or email nowhere in his export",
      bOrders.some(o => o.id === "order-B-buys-from-A" && o.seller_id === "a deleted member") && bMsgs.some(m => m.id === "message-A-to-B" && m.sender_id === "a deleted member") &&
      [A, A_EMAIL, "Alice Co", "@alice"].every(s => exB.text.indexOf(s) === -1), JSON.stringify(bOrders.map(o => o.seller_id)));
    // the account row
    const u = (T.users || []).find(x => x.id === A) || {};
    const ALLOWED = ["id", "created_at", "updated_at", "role", "verification_status", "subscription_status", "subscription_id", "last_login_at", "banned_at", "email", "password_hash"];
    const stillSet = Object.keys(u).filter(k => u[k] !== null && u[k] !== undefined && ALLOWED.indexOf(k) === -1);
    check("D8. the account row is emptied: only its id, dates, role and billing status stay", u.role === "deleted" && stillSet.length === 0, stillSet.join(", "));
    check("D9. its email is no longer alice's, and nothing holds alice's email as an account", u.email === "deleted-" + A + YD.DELETED_EMAIL_DOMAIN && !(T.users || []).some(x => x.email === A_EMAIL), u.email);
    check("D10. its password is gone: the old password no longer matches", u.password_hash !== A_HASH && !(await bcrypt.compare(A_PASSWORD, u.password_hash || "")));
    check("D11. every session, passkey, challenge, push subscription and API key is gone",
      ["auth_sessions", "webauthn_credentials", "webauthn_challenges", "push_subscriptions", "user_api_keys"].every(t => !(T[t] || []).some(x => x.user_id === A)));
    check("D12. the username is released", !(T.profiles || []).some(p => p.username === "alice") && !(T.bf_profiles || []).some(p => p.username === "alice"));
    // the ledger
    const mine = (T.wallet_transactions || []).filter(x => x.user_id === A);
    const sum = mine.reduce((n, x) => n + (x.type === "credit" ? x.amount : -x.amount), 0);
    const wallet = (T.user_wallets || []).find(w => w.user_id === A) || {};
    const forfeit = mine.find(x => x.description === YD.FORFEIT_DESCRIPTION);
    check("D13. the balance is forfeited as a final ledger row of 150", !!forfeit && forfeit.type === "debit" && forfeit.amount === 150, JSON.stringify(forfeit));
    check("D14. balance = sum of the ledger still holds (0 = 200 - 50 - 150)", wallet.balance === 0 && sum === wallet.balance, "balance " + wallet.balance + ", ledger " + sum);
    const bWallet = (T.user_wallets || []).find(w => w.user_id === B) || {};
    const bSum = (T.wallet_transactions || []).filter(x => x.user_id === B).reduce((n, x) => n + (x.type === "credit" ? x.amount : -x.amount), 0);
    check("D15. the transfer stays on both sides, and bob's ledger still adds up", bWallet.balance === 50 && bSum === 50 && mine.some(x => x.id === "wallet_transactions-A-2"));
    // consent evidence
    const cKept = (T.contacts || []).find(c => c.id === "contacts-A-consent") || {};
    check("D16. a contact with a consent record is kept, its email and phone hashed and its name removed",
      /^sha256:[0-9a-f]{64}$/.test(cKept.email || "") && /^sha256:[0-9a-f]{64}$/.test(cKept.phone || "") && cKept.name === null, JSON.stringify(cKept));
    check("D17. its consent record is kept unchanged", (T.consent_events || []).some(e => JSON.stringify(e) === JSON.stringify(before.consent_events.find(x => x.id === "consent_events-A"))));
    check("D18. contacts without consent are deleted, alice's own included", !(T.contacts || []).some(c => c.id === "contacts-A-plain" || c.id === "contacts-A-self"));
    const bounced = (T.email_sends || []).find(s => s.id === "email_sends-A-bounced") || {};
    check("D19. a bounced send is kept with its address, so mail to that address stays stopped", bounced.to_email === "dave+bftest@bizforceai.invalid" && bounced.status === "bounced");
    const sentKept = (T.email_sends || []).find(s => s.id === "email_sends-A-consent") || {};
    check("D20. a send to a kept contact is kept hashed; sends to deleted contacts are deleted",
      /^sha256:/.test(sentKept.to_email || "") && !(T.email_sends || []).some(s => s.id === "email_sends-A-plain" || s.id === "email_sends-A-self"));
    const lc = (T.lead_captures || []).find(x => x.id === "lead_captures-A-consent") || {};
    check("D21. a lead capture with consent is kept hashed; one without is deleted", /^sha256:/.test(lc.email || "") && /^sha256:/.test(lc.phone || "") && lc.name === null &&
      lc.sms_consent === true && !(T.lead_captures || []).some(x => x.id === "lead_captures-A-none"));
    const sub = (T.sms_subscribers || []).find(x => x.id === "sms_subscribers-A") || {}, sl = (T.sms_send_log || []).find(x => x.id === "sms_send_log-A") || {};
    check("D22. SMS subscribers and the send log are kept with phone numbers hashed and names removed", /^sha256:/.test(sub.phone_number || "") && sub.customer_name === null &&
      sub.consent_status === "granted" && /^sha256:/.test(sl.phone_number || "") && sl.message_body === "Fresh bread today");
    const plain = JSON.stringify(T).match(/carol\+bftest|\+15550001|\+15550003|\+15550004|fay\+bftest|"Carol"|"Ivy"/g) || [];
    check("D23. no kept evidence still holds a contact's email, phone or name in the clear (the bounce aside)", plain.length === 0, plain.join(", "));
    // sign-in
    const reqAuthSrc = sliceFrom(SERVER, "async function requireAuth(req, res, next) {", "requireAuth");
    async function authAs(tables, sid) {
      const authDb = makeDb(tables);
      const fn = new Function("jwt", "supabase", "getUserById", "touchSession", "process", reqAuthSrc + "\nreturn requireAuth;")(
        { verify: () => ({ id: A, sid: sid }) }, authDb.client, async () => null, () => {}, { env: { JWT_SECRET: "x" } });
      const res = fakeRes(); let passed = false;
      await fn({ headers: { authorization: "Bearer token" } }, res, () => { passed = true; });
      return { passed, status: res.statusCode, body: res.body };
    }
    const a1 = await authAs(clone(T), "auth_sessions-A");
    check("D24. alice's session is refused (it no longer exists)", !a1.passed && a1.status === 401, a1.status + " " + JSON.stringify(a1.body));
    const outlived = clone(T);
    outlived.auth_sessions.push(clone(before.auth_sessions.find(s => s.id === "auth_sessions-A")));
    const a2 = await authAs(outlived, "auth_sessions-A");
    check("D25. a session row that outlived the delete is refused too: the account is deleted", !a2.passed && a2.status === 401 && a2.body && a2.body.error === "Account deleted", a2.status + " " + JSON.stringify(a2.body));
    const control = await authAs(clone(before), "auth_sessions-A");
    check("D26. (control: the same session before the delete is let through)", control.passed);
    const loginSrc = handlerSource(SERVER, "app.post(\"/api/auth/login\"");
    async function login(tables, email, password) {
      const ldb = makeDb(tables);
      const fn = runRoute(loginSrc, { supabase: ldb.client, bcrypt: bcrypt, normalizeEmail: e => String(e || "").trim().toLowerCase(), nowIso: () => "2026-10-21T12:00:00Z" });
      const res = fakeRes(); let err = null;
      await fn({ body: { email: email, password: password }, ip: "10.0.0.9" }, res, e => { err = e; });
      return { status: res.statusCode, body: res.body, gotPast: ldb.writes > 0 };
    }
    const l1 = await login(clone(T), A_EMAIL, A_PASSWORD);
    const l2 = await login(clone(T), "deleted-" + A + YD.DELETED_EMAIL_DOMAIN, A_PASSWORD);
    const l3 = await login(clone(T), "deleted-" + A + YD.DELETED_EMAIL_DOMAIN, YD.DELETED_PASSWORD);
    check("D27. sign-in fails with alice's email and password, and with the emptied account's email", l1.status === 401 && !l1.gotPast && l2.status === 401 && !l2.gotPast && l3.status === 401 && !l3.gotPast,
      [l1.status, l2.status, l3.status].join(","));
    const l0 = await login(clone(before), A_EMAIL, A_PASSWORD);
    check("D28. (control: before the delete, the same sign-in gets past the password)", l0.gotPast);
    // the email is free for a new account
    const registerSrc = sliceFrom(SERVER, "app.post(\"/api/auth/register\"", "the register route");
    const dupCheck = /\.from\("users"\)\s*\.select\([^)]*\)\s*\.eq\("email", email\)/.test(registerSrc);
    check("D29. the email can open a new account: register refuses only an email a users row holds, and none holds alice's now", dupCheck && !(T.users || []).some(x => String(x.email).toLowerCase() === A_EMAIL));
    // idempotent
    const snap = canon(T);
    const again = await doDelete(db, A, { username: "alice", password: A_PASSWORD });
    check("D30. a second delete changes nothing and says the account no longer exists", again.status === 404 && again.body.reason === "already_deleted" && canon(db.tables) === snap, again.status);
    check("D31. the delete is logged with its outcome only", r.lines.some(l => /\[your-data\] delete user=\S+ status=200 reason=deleted/.test(l[1])) && r.lines.every(l => l[1].indexOf(A_PASSWORD) === -1 && l[1].indexOf(A_EMAIL) === -1));
    check("D32. transfers to a deleted account are refused (the recipient check drops it)", /const found = await supabase\.from\("users"\)\.select\("id, role"\)\.eq\("id", recipientId\)\.maybeSingle\(\);/.test(SERVER) &&
      /if \(recipient && recipient\.role === "deleted"\) recipient = null;/.test(SERVER));
    check("D33. no storage file is touched (the page says uploaded files are not deleted)", !/\.storage\b/.test(LIB) && YD.DELETE_NOTES.some(n => /Files you uploaded .* are not deleted by this button/.test(n)));
  }

  // ════ E. a failure part-way ════
  console.log("\n══ E. a failure part-way is reported and finished by a retry ══");
  {
    const db = makeDb(seed());
    let failing = true;
    db.failOn = (t, op) => failing && t === "ai_reports" && op === "delete" ? "connection reset" : null;
    const r1 = await doDelete(db, A, { username: "alice", password: A_PASSWORD });
    const u1 = db.rows("users").find(x => x.id === A);
    check("E1. it stops, says what was done and what failed, and says to press Delete again", r1.status === 500 && r1.body.reason === "incomplete" && /ai_reports/.test(r1.body.failed) &&
      Array.isArray(r1.body.done) && r1.body.done.length > 0 && /Press Delete again/.test(r1.body.error), r1.status + " " + JSON.stringify(r1.body).slice(0, 200));
    check("E2. the member is still signed in and the account is untouched", u1.role === "user" && u1.email === A_EMAIL && db.rows("auth_sessions").some(s => s.user_id === A));
    check("E3. it is logged as a failure", r1.lines.some(l => l[0] === "error" && /status=500 reason=incomplete failed=/.test(l[1])));
    failing = false;
    const r2 = await doDelete(db, A, { username: "alice", password: A_PASSWORD });
    const forfeits = db.rows("wallet_transactions").filter(x => x.user_id === A && x.description === YD.FORFEIT_DESCRIPTION);
    check("E4. pressing Delete again finishes it, and the balance is forfeited once, not twice", r2.status === 200 && forfeits.length === 1 && db.rows("user_wallets").find(w => w.user_id === A).balance === 0,
      r2.status + " forfeits " + forfeits.length);
    // the last step: sessions are gone, the account row cannot be emptied
    const db3 = makeDb(seed());
    let failUsers = true;
    db3.failOn = (t, op) => failUsers && t === "users" && op === "update" ? "deadlock" : null;
    const r3 = await doDelete(db3, A, { username: "alice", password: A_PASSWORD });
    const u3 = db3.rows("users").find(x => x.id === A);
    check("E5. if the account row cannot be emptied, it says so, says to sign in again and press Delete, and sign-in still works",
      r3.status === 500 && r3.body.reason === "incomplete_signed_out" && /Sign in again/.test(r3.body.error) && u3.email === A_EMAIL && await bcrypt.compare(A_PASSWORD, u3.password_hash), r3.status + " " + r3.body.reason);
    failUsers = false;
    const r4 = await doDelete(db3, A, { username: "alice", password: A_PASSWORD });
    check("E6. after the username is gone, the email confirms instead, and the retry finishes", r4.status === 400 && /type your email address/.test(r4.body.error || ""), r4.status);
    const r5 = await doDelete(db3, A, { username: A_EMAIL, password: A_PASSWORD });
    check("E7. ... and with the email, it does", r5.status === 200 && db3.rows("users").find(x => x.id === A).role === "deleted", r5.status);
  }

  // ════ F. the page ════
  console.log("\n══ F. your-data.html ══");
  {
    function runPage(token, fetchImpl) {
      const nodes = {};
      function node(tag, id) {
        const n = { tag: tag, id: id, _text: "", children: [], hidden: false, className: "", href: "", value: "", disabled: false, listeners: {}, parentNode: null,
          get textContent() { return this._text + this.children.map(c => c.textContent).join(""); }, set textContent(v) { this._text = String(v); this.children = []; },
          appendChild(c) { c.parentNode = this; this.children.push(c); return c; }, addEventListener(ev, fn) { this.listeners[ev] = fn; }, remove() {}, click() {} };
        return n;
      }
      const idRe = /<(\w+)([^>]*)\sid="([^"]+)"([^>]*)>/g; let m;
      while ((m = idRe.exec(PAGE))) { const n = node(m[1], m[3]); n.hidden = /\shidden(\s|$|>)/.test(" " + m[2] + " " + m[4] + " "); nodes[m[3]] = n; }
      Object.keys(nodes).forEach(id => { if (["loadStatus", "deleteForm", "downloadStatus", "deleteStatus"].indexOf(id) !== -1) return; });
      const documentStub = { getElementById: id => nodes[id] || null, createElement: tag => node(tag), body: node("body") };
      const scripts = PAGE.match(/<script>([\s\S]*?)<\/script>/g).map(s => s.slice(8, -9));
      const main = scripts[scripts.length - 1];
      const storage = { getItem: k => (k === "bf_token" ? token : null), removeItem() {} };
      const win = {};
      new Function("document", "window", "localStorage", "fetch", "URL", "Blob", "setTimeout", main)(documentStub, win, storage, fetchImpl, {}, function () {}, () => {});
      return nodes;
    }
    const settle = () => new Promise(r => setImmediate(r));
    const described = YD.describe();
    const okFetch = async () => ({ ok: true, json: async () => clone(described) });
    const page = runPage("token", okFetch);
    for (let i = 0; i < 5; i++) await settle();
    const lis = n => n.children.map(c => c.textContent);
    check("F1. the protections shown are exactly the description's", JSON.stringify(lis(page.protections)) === JSON.stringify(YD.PROTECTIONS.map(p => p.text)), lis(page.protections).length);
    const groupsText = page.groups.textContent;
    const missingWhat = YD.DATA.filter(e => groupsText.indexOf(e.what) === -1 || groupsText.indexOf(YD.onDeleteText(e)) === -1).map(e => e.table);
    check("F2. every table's line, and what deleting does to it, is shown from the description", missingWhat.length === 0, missingWhat.join(", "));
    check("F3. what the download leaves out, and the delete notes, are the description's", JSON.stringify(lis(page.neverExported)) === JSON.stringify(YD.NEVER_EXPORTED) &&
      JSON.stringify(lis(page.deleteNotes)) === JSON.stringify(YD.DELETE_NOTES));
    check("F4. signed in, the download and delete are offered", !page.described.hidden && !page.downloadSignedIn.hidden && !page.deleteForm.hidden && page.deleteSignedOut.hidden);
    const out = runPage(null, okFetch);
    for (let i = 0; i < 5; i++) await settle();
    check("F5. signed out, the description shows and the download and delete ask to sign in", !out.described.hidden && out.downloadSignedIn.hidden && out.deleteForm.hidden && !out.deleteSignedOut.hidden);
    const down = runPage("token", async () => { throw new Error("offline"); });
    for (let i = 0; i < 5; i++) await settle();
    check("F6. with no description, the page claims nothing and says why", down.described.hidden && down.protections.children.length === 0 && /could not be loaded/.test(down.loadStatus.textContent));
    const visible = PAGE.replace(/<!--[\s\S]*?-->/g, "").replace(/<script[\s\S]*?<\/script>/g, "").replace(/<style[\s\S]*?<\/style>/g, "").replace(/<[^>]+>/g, " ");
    const claims = visible.match(/encrypt\w*|military|bank[- ]level|grade|secure\w*|sell|sold|GDPR|privacy|safe/gi) || [];
    check("F7. the page's own markup makes no protection claim: every one comes from the description", claims.length === 0, claims.join(", "));
    check("F8. the lists the description fills are empty in the markup", /<ul id="protections"><\/ul>/.test(PAGE) && /<ul id="neverExported"><\/ul>/.test(PAGE) && /<ul id="deleteNotes"><\/ul>/.test(PAGE) && /<div id="groups"><\/div>/.test(PAGE));
    const fe = f => lf(fs.readFileSync(path.join(FRONTEND, f), "utf8"));
    check("F9. it is linked from settings (Account), the profile page and the footers",
      /id="panel-account"[\s\S]*href="your-data\.html"[\s\S]*id="signOutBtn"/.test(fe("settings.html")) && /<nav class="pf-nav">[\s\S]*?href="your-data\.html"[\s\S]*?<\/nav>/.test(fe("profile.html")) &&
      /<footer class="site-foot">[\s\S]*?href="your-data\.html"[\s\S]*?<\/footer>/.test(fe("index.html")) && /<footer class="site-foot">[\s\S]*?href="\/your-data\.html"[\s\S]*?<\/footer>/.test(fe("suppressed.html")));
    check("F10. it calls the three routes the server has", ["/api/your-data\"", "/api/me/export\"", "/api/me/delete\""].every(r => PAGE.indexOf(r) !== -1) &&
      [DESCRIBE_SIG, EXPORT_SIG, DELETE_SIG].every(s => SERVER.indexOf(s) !== -1));
  }

  // ════ G. every protection claim is backed ════
  console.log("\n══ G. every protection claim is backed by a fact asserted here ══");
  {
    const pkg = JSON.parse(read("package.json"));
    const pages = fs.readdirSync(FRONTEND).filter(f => /\.html$/.test(f));
    const pageSrc = f => lf(fs.readFileSync(path.join(FRONTEND, f), "utf8"));
    const backupSrc = read("lib/backup.js"), cryptoSrc = read("lib/apiKeyCrypto.js");
    /* What each dependency is for. A new dependency fails here until it is given a purpose,
       and the no_sale claim names every service a purpose sends data to. */
    const PURPOSE = {
      "@anthropic-ai/sdk": "Anthropic", "@atproto/api": "Bluesky", "@simplewebauthn/server": null, "@supabase/supabase-js": "Supabase", "astronomy-engine": null,
      bcryptjs: null, "city-timezones": null, compression: null, cors: null, dotenv: null, entities: null, "epub-gen-memory": null, express: null,
      "express-rate-limit": null, helmet: null, jsonwebtoken: null, luxon: null, mammoth: null, multer: null, "node-cron": null, "pdf-parse": null, pdfkit: null,
      resend: "Resend", stripe: "Stripe", svix: null, twilio: "Twilio", "web-push": "push service"
    };
    const text = k => (YD.PROTECTIONS.find(p => p.key === k) || {}).text || "";
    const TRACKERS = /googletagmanager\.com|google-analytics\.com|\bgtag\(|connect\.facebook\.net|\bfbq\(|hotjar\.com|segment\.(com|io)|mixpanel\.com|amplitude\.com|clarity\.ms|doubleclick\.net|adservice\.google|plausible\.io|posthog\.com/;
    const FACTS = {
      transit: () => {
        const apiUrls = pages.map(f => (pageSrc(f).match(/API_URL\s*=\s*"([^"]+)"/g) || [])).reduce((a, b) => a.concat(b), []);
        return apiUrls.length > 20 && apiUrls.every(u => /"https:\/\//.test(u)) && /app\.use\(\s*helmet\(/.test(SERVER) && !/hsts:\s*false/.test(SERVER) &&
          text("transit") === "Encrypted in transit (HTTPS).";
      },
      at_rest: () => /createClient\(/.test(SERVER) && /process\.env\.SUPABASE_URL/.test(SERVER) && /Supabase/.test(text("at_rest")) && /claims nothing/.test(text("at_rest")) &&
        !/\bencrypts\b|\bencrypted at rest\b|\bis encrypted\.|\bare encrypted\b/.test(text("at_rest")),
      passwords: () => {
        const writes = SERVER.match(/password_hash:\s*[^,\n}]+/g) || [];
        return writes.length >= 2 && writes.every(w => /password_hash:\s*passwordHash\b/.test(w)) && (SERVER.match(/const passwordHash = await bcrypt\.hash\(password, 12\);/g) || []).length >= 2;
      },
      api_keys: () => /const ALGORITHM = "aes-256-gcm";/.test(cryptoSrc) && /const \{ ciphertext, iv, authTag \} = encrypt\(apiKey\);/.test(SERVER) &&
        (SERVER.match(/\.from\("user_api_keys"\)\s*\.(upsert|insert)\(/g) || []).length === 1 && /AES-256-GCM/.test(text("api_keys")),
      backups: () => backup.CIPHER === "aes-256-gcm" && backup.parseBackupKey("").ok === false && backup.parseBackupKey("").reason === "key_missing" &&
        ["auth_sessions", "webauthn_challenges", "user_api_keys", "push_subscriptions"].every(t => backup.EXCLUDED_TABLES[t]) &&
        /Backups are encrypted \(AES-256-GCM\) with a key held by the owner/.test(text("backups")),
      not_e2e: () => /decrypt\(/.test(SERVER) && /require\("\.\/lib\/apiKeyCrypto"\)/.test(SERVER) &&
        text("not_e2e") === "Not end-to-end encrypted: BizForce's servers can read your data so the agents can work with it.",
      no_sale: () => {
        const deps = Object.keys(pkg.dependencies || {});
        const unknown = deps.filter(d => !(d in PURPOSE));
        const named = deps.map(d => PURPOSE[d]).filter(Boolean).every(s => text("no_sale").indexOf(s) !== -1);
        const tracked = pages.filter(f => TRACKERS.test(pageSrc(f))).concat(TRACKERS.test(SERVER) ? ["server.js"] : []);
        const extScripts = pages.map(f => (pageSrc(f).match(/<script[^>]+src="(https?:)?\/\/[^"]+"/g) || [])).reduce((a, b) => a.concat(b), [])
          .filter(s => !/src="https:\/\/(cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com)\//.test(s));
        const outbound = (/MASTODON_INSTANCE/.test(SERVER) ? /Mastodon/.test(text("no_sale")) : true) && (/guardedFetch\(/.test(SERVER) ? /web page an agent is asked to read/.test(text("no_sale")) : true);
        return unknown.length === 0 && named && tracked.length === 0 && extScripts.length === 0 && outbound && /^We do not sell your data\./.test(text("no_sale"));
      }
    };
    YD.PROTECTIONS.forEach(function (p) {
      let ok = false, why = "no fact is asserted for this claim";
      if (FACTS[p.key]) { try { ok = !!FACTS[p.key](); why = ok ? undefined : "the fact does not hold"; } catch (e) { why = String(e.message || e); } }
      check("G. \"" + p.text.slice(0, 70) + (p.text.length > 70 ? "…" : "") + "\" is backed", ok, why);
    });
    const bad = YD.PROTECTIONS.filter(p => /military|bank[- ]level|unhackable|100%|fully secure|end-to-end encrypted\b(?!:)/i.test(p.text.replace("Not end-to-end encrypted:", "")));
    check("G. no claim says military-grade, bank-level, unhackable or end-to-end", bad.length === 0, bad.map(p => p.key).join(", "));
  }

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : "")); process.exit(1); }
  console.log("ALL CHECKS PASSED" + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(0);
})().catch(function (err) {
  // A crash is a failure, never the mutation-anchor exit (3).
  console.log("    FAIL  the check threw: " + ((err && err.stack) || err));
  process.exit(1);
});
