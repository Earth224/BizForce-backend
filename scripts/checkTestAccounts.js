/* ══════════════════════════════════════════════════════════════════════════
   checkTestAccounts.js — test accounts never count as subscribers or revenue,
   and still pass the gate (launch audit #14).

   THE DEFECT. The audit found 11 "active" subscriptions. All 11 belong to
   accounts on the reserved @bizforceai.invalid domain: the entitled check
   account (supabase/seeds/check_entitled_account.sql) and ten clean-run
   harness accounts from the model comparison of 2026-10-02/03. Not one is a
   customer, and a subscriber, revenue or MRR figure that counts them reports
   people who do not exist.

   WHAT THIS PROVES
     1. ONE DEFINITION. lib/testAccounts.js holds the only list: the check
        suite's subject id (the same id checkRunResidue's SUGGESTED_SUBJECT_ID
        names) and the +bftest and @bizforceai.invalid email patterns. It is
        tried on accounts that are tests and on look-alikes that are not, and
        no other file in server.js or lib/ spells either pattern.
     2. EVERY COUNT EXCLUDES THEM. Self-review's revenue figures are the only
        revenue read in the codebase. Run on in-memory tables: a real account's
        revenue is counted; a test account's is 0, by email or by id, without
        revenue_events being read; an account that cannot be identified gets
        null revenue named in `unreadable`, never a guess.
     3. NO NEW COUNT CAN SKIP IT. Every read of subscriptions or revenue_events
        in server.js and lib/ is listed and must be a write, a read scoped to
        one account or one Stripe object, or go through lib/testAccounts.js. A
        read across accounts that does not fails here.
     4. STILL ENTITLED. getUserPlan, subscriptionEntitlement and
        requireActiveSubscription never ask whether an account is a test, and
        only lib/selfReview.js requires lib/testAccounts.js.
     5. THE CLEANUP FILE (supabase/cleanups/cancel_test_subscriptions.sql, and
        the owner's copy in Downloads, byte for byte the same). Its preview,
        guard and update name exactly the ten clean-run rows; it never names
        the check account's row, which checkRunResidue requires 'active'; it
        deletes nothing and sets only status and updated_at; and, modelled over
        the 14 live rows the recon read, it changes exactly the ten — and
        refuses, changing nothing, when the count is not ten.

   No database, no network, nothing written.

   MUTATIONS (MUTATE=<name>, or MUTATE=all):
     selfreview-counts-test-accounts  self-review counts a test account's revenue
     unscoped-subscriber-count        a new count of active subscriptions across accounts
     unscoped-revenue-sum             a new revenue sum across accounts
     gate-refuses-test-accounts       getUserPlan refuses a test account
     cleanup-adds-seed-row            the update also cancels the check account's row
     cleanup-no-count-guard           the update runs whatever the count
   ══════════════════════════════════════════════════════════════════════════ */

"use strict";

const fs = require("fs");
const path = require("path");
const Module = require("module");
const MUT = require("./_shared");
const { braceMatch } = MUT;
const REPO = path.join(__dirname, "..");

const MUTATIONS = ["selfreview-counts-test-accounts", "unscoped-subscriber-count", "unscoped-revenue-sum",
  "gate-refuses-test-accounts", "cleanup-adds-seed-row", "cleanup-no-count-guard"];
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
let SERVER = read("server.js");
const TEST_ACCOUNTS_SRC = read("lib/testAccounts.js");
let SELF_REVIEW_SRC = read("lib/selfReview.js");
const RESIDUE_SRC = read("scripts/checkRunResidue.js");
const CLEANUP_REL = "supabase/cleanups/cancel_test_subscriptions.sql";
let CLEANUP = read(CLEANUP_REL);
const CLEANUP_RAW = fs.readFileSync(path.join(REPO, CLEANUP_REL));
const OWNER_COPY = "C:/Users/ALGORITHM/Downloads/cleanup-test-subscriptions.sql";
const LIB_FILES = fs.readdirSync(path.join(REPO, "lib")).filter(f => /\.js$/.test(f)).sort();
const LIB = {};
LIB_FILES.forEach(f => { LIB["lib/" + f] = read("lib/" + f); });

if (MUTATE === "selfreview-counts-test-accounts") {
  SELF_REVIEW_SRC = MUT.replaceOnce(SELF_REVIEW_SRC, "var revenueCounted = testAccount === false;", "var revenueCounted = testAccount !== null;", MUTATE);
}
if (MUTATE === "unscoped-subscriber-count") {
  SERVER = MUT.replaceOnce(SERVER, "async function hasActivePlan(userId, plan) {",
    "async function countActiveSubscribers() {\n  const { count } = await supabase.from(\"subscriptions\").select(\"id\", { count: \"exact\", head: true })" +
    ".in(\"status\", [\"active\", \"trialing\"]);\n  return count;\n}\n\nasync function hasActivePlan(userId, plan) {", MUTATE);
}
if (MUTATE === "unscoped-revenue-sum") {
  SERVER = MUT.replaceOnce(SERVER, "async function hasActivePlan(userId, plan) {",
    "async function platformRevenue() {\n  const { data } = await supabase.from(\"revenue_events\").select(\"amount\").gte(\"created_at\", \"2026-01-01\");\n" +
    "  return (data || []).reduce(function (n, r) { return n + Number(r.amount); }, 0);\n}\n\nasync function hasActivePlan(userId, plan) {", MUTATE);
}
if (MUTATE === "gate-refuses-test-accounts") {
  SERVER = MUT.replaceOnce(SERVER, "  const subscription = await getActiveSubscription(userId);\n\n  if (isExemptRole(subject)) {",
    "  if (require(\"./lib/testAccounts\").isTestAccount(subject || { id: userId })) return { active: false, inactive_reason: \"test_account\" };\n" +
    "  const subscription = await getActiveSubscription(userId);\n\n  if (isExemptRole(subject)) {", MUTATE);
}
if (MUTATE === "cleanup-adds-seed-row") {
  CLEANUP = MUT.replaceOnce(CLEANUP,
    "  update public.subscriptions s\n     set status = 'canceled', updated_at = now()\n    from public.users u\n   where u.id = s.user_id\n     and s.id in (\n",
    "  update public.subscriptions s\n     set status = 'canceled', updated_at = now()\n    from public.users u\n   where u.id = s.user_id\n     and s.id in (\n" +
    "           '88239d99-4303-4350-aa61-c0c9d6b01b94',\n", MUTATE);
}
if (MUTATE === "cleanup-no-count-guard") {
  CLEANUP = MUT.replaceOnce(CLEANUP,
    "  if n <> 10 then\n    raise exception 'cleanup refused: expected 10 matching rows, found %. Nothing was changed.', n;\n  end if;\n", "", MUTATE);
}

/* A module loaded from (possibly mutated) source text, resolving its own requires from its real path. */
function loadFrom(rel, src) {
  const file = path.join(REPO, rel);
  const m = new Module(file, module);
  m.filename = file;
  m.paths = Module._nodeModulePaths(path.dirname(file));
  m._compile(src, file);
  return m.exports;
}
function functionSource(src, name) {
  const re = new RegExp("^(?:async )?function " + name + "\\(", "m");
  const m = re.exec(src);
  if (!m) throw new Error("function " + name + " was not found");
  return src.slice(m.index, braceMatch(src, src.indexOf(") {", m.index) + 2));
}

/* The ten clean-run rows, the check account's row, and the three others the recon read on 2026-10-21. */
const TEN = [
  "fc3489ed-9fb7-43b4-a519-09da23d67c5e", "54b28acb-99fc-45aa-b337-e1a3567c1f9e", "6877d019-e4e8-4031-89b7-cf622d78b78c",
  "db387ea2-28d0-46e1-a6e8-551a5299e8cf", "b4e2d9e3-f15c-42fc-b91c-5ce54be1aec3", "5249f289-381e-4316-9f3b-05528a3ed2c0",
  "5e323ea9-3bf8-49e1-b749-34882df97aa8", "e0577090-2bf7-4fce-af5c-bcdaa835e2a0", "3bf9ecfe-072d-4743-84be-675ea83f9c3d",
  "740fc7ee-d8a1-4602-91a2-0d5a784f8287"
];
const SEED_ROW = "88239d99-4303-4350-aa61-c0c9d6b01b94";
const LIVE_ROWS = [
  { id: "6a07a178-b8f4-4cd6-ae85-e341eca7e9ca", status: "past_due", stripe: true, invalidEmail: false },   // the owner
  { id: "ad5c2dc9-6ace-4d7d-8cda-0d55fbb340d4", status: "canceled", stripe: true, invalidEmail: false },   // +bftest2
  { id: "ae3b99b6-7148-4ca3-9bfa-79f20f659f8d", status: "past_due", stripe: true, invalidEmail: false },   // +bftest3
  { id: SEED_ROW, status: "active", stripe: false, invalidEmail: true }                                    // the check account
].concat(TEN.map(id => ({ id: id, status: "active", stripe: false, invalidEmail: true })));

(async function main() {
  console.log("\n══ code under test: " + (MUTATE ? "MUTATED (" + MUTATE + ")" : "as it stands") + " ══");

  /* ── 1. one definition ──────────────────────────────────────────────────── */
  console.log("\n══ 1. lib/testAccounts.js is the one definition ══");
  const TA = loadFrom("lib/testAccounts.js", TEST_ACCOUNTS_SRC);
  const subject = (/const SUGGESTED_SUBJECT_ID = "([0-9a-f-]{36})";/.exec(RESIDUE_SRC) || [])[1];
  check("1. its ids are the check suite's subject account, the one checkRunResidue names",
    !!subject && JSON.stringify(TA.TEST_ACCOUNTS.ids) === JSON.stringify([subject]), JSON.stringify(TA.TEST_ACCOUNTS.ids) + " vs " + subject);
  const cases = [
    [{ id: subject }, true, "the subject account, by id alone"],
    [{ id: subject.toUpperCase() }, true, "the subject id in capitals"],
    [{ id: "x", email: "owner+bftest2@gmail.com" }, true, "a +bftest sign-up"],
    [{ id: "x", email: "Owner+BFTest@Gmail.com" }, true, "+bftest in any case"],
    [{ id: "x", email: "check-entitled@bizforceai.invalid" }, true, "the entitled check account"],
    [{ id: "x", email: "clean-run-1@BizForceAI.invalid" }, true, "a clean-run harness account"],
    [{ id: "x", email: "someone@gmail.com" }, false, "an ordinary member"],
    [{ id: "x", email: "bftest@gmail.com" }, false, "bftest without the +"],
    [{ id: "x", email: "x@bizforceai.invalid.example.com" }, false, ".invalid that is not the end of the address"],
    [{ id: "x", email: "bizforceai.invalid@example.com" }, false, "the domain as a local part"],
    [null, false, "no account at all"]
  ];
  cases.forEach(([user, want, what]) => check("1. " + what + ": " + (want ? "a test" : "not a test"), TA.isTestAccount(user) === want));
  const spellers = Object.keys(LIB).concat(["server.js"]).filter(f => f !== "lib/testAccounts.js" &&
    /bftest|bizforceai\\\.invalid/.test(f === "server.js" ? SERVER : LIB[f]));
  check("1. no other file in server.js or lib/ holds either pattern as a regular expression", spellers.length === 0, spellers.join(", "));

  /* ── 2. self-review's revenue figures ───────────────────────────────────── */
  console.log("\n══ 2. self-review counts no revenue for a test account ══");
  {
    const SR = loadFrom("lib/selfReview.js", SELF_REVIEW_SRC);
    const real = "11111111-1111-4111-8111-111111111111", byEmail = "22222222-2222-4222-8222-222222222222",
      harness = "33333333-3333-4333-8333-333333333333", missing = "44444444-4444-4444-8444-444444444444";
    const at = "2026-10-03T12:00:00.000Z";
    const tables = {
      users: [{ id: real, email: "member@example.com" }, { id: byEmail, email: "owner+bftest3@gmail.com" },
        { id: harness, email: "clean-run-2@bizforceai.invalid" }],
      revenue_events: [real, byEmail, harness, subject, missing].flatMap(u =>
        [{ user_id: u, amount: "10", currency: "usd", created_at: at }, { user_id: u, amount: 15.5, currency: "usd", created_at: at }]),
      ai_tasks: [real, byEmail].map(u => ({ user_id: u, created_at: at }))
    };
    function fakeClient(failUsers) {
      const reads = [];
      const client = {
        reads: reads,
        from(table) {
          const q = { table: table, filters: [], head: false, counting: false, range: null, single: false };
          const api = {
            select(cols, opts) { q.counting = !!(opts && opts.count); q.head = !!(opts && opts.head); return api; },
            eq(c, v) { q.filters.push(r => r[c] === v); return api; },
            gte(c, v) { q.filters.push(r => r[c] >= v); return api; },
            lt(c, v) { q.filters.push(r => r[c] < v); return api; },
            order() { return api; },
            range(a, b) { q.range = [a, b]; return api; },
            maybeSingle() { q.single = true; return api; },
            then(resolve, reject) {
              reads.push(table);
              let out;
              if (table === "users" && failUsers) out = { data: null, error: { message: "users is unreachable" } };
              else {
                let rows = (tables[table] || []).filter(r => q.filters.every(f => f(r)));
                const count = rows.length;
                if (q.range) rows = rows.slice(q.range[0], q.range[1] + 1);
                out = q.single ? { data: rows[0] || null, error: null } : { data: q.head ? null : rows, count: q.counting ? count : null, error: null };
              }
              return Promise.resolve(out).then(resolve, reject);
            }
          };
          return api;
        }
      };
      return client;
    }
    const start = new Date("2026-10-01T00:00:00.000Z"), end = new Date("2026-10-08T00:00:00.000Z");
    const errs = [];
    const realConsole = console.error;
    console.error = function () { errs.push(Array.prototype.join.call(arguments, " ")); };
    const run = async (userId, failUsers) => {
      const client = fakeClient(failUsers);
      const r = await SR.gatherReviewMetrics({ supabase: client, userId: userId, start: start, end: end });
      return { m: r.metrics, unreadable: r.unreadable, reads: client.reads };
    };
    let realR, emailR, harnessR, subjectR, failR;
    try {
      realR = await run(real); emailR = await run(byEmail); harnessR = await run(harness); subjectR = await run(subject);
      failR = await run(real, true);
    } finally { console.error = realConsole; }
    const show = r => "revenueEvents " + r.m.revenueEvents + ", revenueTotal " + r.m.revenueTotal + ", aiTasks " + r.m.aiTasks +
      ", unreadable [" + r.unreadable.join(",") + "], revenue_events reads " + r.reads.filter(t => t === "revenue_events").length;
    console.log("    a member:              " + show(realR));
    console.log("    a +bftest account:     " + show(emailR));
    console.log("    a harness account:     " + show(harnessR));
    console.log("    the subject (by id):   " + show(subjectR));
    console.log("    identity unreadable:   " + show(failR));
    check("2. a member's revenue is counted: 2 events, 25.5", realR.m.revenueEvents === 2 && realR.m.revenueTotal === 25.5, show(realR));
    for (const [what, r] of [["a +bftest account", emailR], ["a harness account (@bizforceai.invalid)", harnessR], ["the subject account, known by id", subjectR]]) {
      check("2. " + what + ": 0 revenue events and 0 revenue, though it has 25.5 in rows",
        r.m.revenueEvents === 0 && r.m.revenueTotal === 0 && r.unreadable.length === 0, show(r));
      check("2. " + what + ": revenue_events is not read for it", r.reads.indexOf("revenue_events") === -1, r.reads.join(","));
    }
    check("2. the exclusion touches revenue only: a test account's other counts are still counted", emailR.m.aiTasks === 1, show(emailR));
    check("2. when the account cannot be identified, both revenue figures are null and named unreadable, and revenue_events is not read",
      failR.m.revenueEvents === null && failR.m.revenueTotal === null &&
      failR.unreadable.indexOf("revenueEvents") !== -1 && failR.unreadable.indexOf("revenueTotal") !== -1 &&
      failR.reads.indexOf("revenue_events") === -1 && failR.m.aiTasks === 1, show(failR));
    check("2. and the log says why", errs.some(e => /revenueTotal test-account read failed for user .*users is unreachable/.test(e)), errs.join(" | ").slice(0, 300));
  }

  /* ── 3. every read of subscriptions and revenue_events ─────────────────── */
  console.log("\n══ 3. every subscriptions and revenue_events read in server.js and lib/ ══");
  {
    const files = Object.assign({ "server.js": SERVER }, LIB);
    const reads = [];
    Object.keys(files).forEach(function (file) {
      const src = files[file];
      const re = /\.from\((?:"(subscriptions|revenue_events)"|(REVENUE_TABLE)|(source\.table))\)/g;
      let m;
      while ((m = re.exec(src))) {
        const stmt = src.slice(m.index, src.indexOf(";", m.index) + 1);
        const line = src.slice(0, m.index).split("\n").length;
        let kind;
        if (/^\.from\([^)]*\)\s*\.(insert|upsert|update|delete)\(/.test(stmt)) kind = "write";
        else if (/\.eq\(\s*("user_id"|"stripe_subscription_id"|"stripe_customer_id"|"stripe_event_id"|REVENUE_OWNER_COLUMN)\s*,/.test(stmt)) kind = "one account or one Stripe object";
        else if (m[3] && file === "lib/selfReview.js") kind = "self-review count source";
        else if (/isTestAccount|TEST_ACCOUNTS/.test(src.slice(Math.max(0, m.index - 2000), m.index + stmt.length))) kind = "across accounts, through lib/testAccounts.js";
        else kind = "ACROSS ACCOUNTS, test accounts included";
        reads.push({ where: file + ":" + line, table: m[1] || m[2] || m[3], kind: kind });
      }
    });
    reads.forEach(r => console.log("    " + r.where.padEnd(22) + " " + String(r.table).padEnd(15) + " " + r.kind));
    const bad = reads.filter(r => /^ACROSS/.test(r.kind));
    check("3. the reads are found (" + reads.length + ")", reads.length >= 15, reads.length);
    check("3. no read counts across accounts without leaving test accounts out", bad.length === 0, bad.map(r => r.where).join(", "));
    // The one read that is not a literal table: self-review's count sources, each scoped by its owner column.
    check("3. self-review's count sources are each read for one account, and revenue_events only when the account is not a test",
      /\{ key: "revenueEvents",\s+table: "revenue_events",\s+ownerColumn: "user_id",/.test(SELF_REVIEW_SRC) &&
      /if \(source\.ownerColumn\) \{\n      query = query\.eq\(source\.ownerColumn, userId\);/.test(SELF_REVIEW_SRC) &&
      /return source\.table !== REVENUE_TABLE \|\| revenueCounted;/.test(SELF_REVIEW_SRC) &&
      /var revenueRead = revenueCounted\n    \? readRevenueRows\(/.test(SELF_REVIEW_SRC));
  }

  /* ── 4. still entitled ──────────────────────────────────────────────────── */
  console.log("\n══ 4. a test account still passes the gate ══");
  {
    const gate = ["getUserPlan", "subscriptionEntitlement", "requireActiveSubscription", "getActiveSubscription", "getActiveSubscriptions"];
    const asks = gate.filter(n => /isTestAccount|TEST_ACCOUNTS|testAccounts|bftest|\.invalid/.test(functionSource(SERVER, n)));
    check("4. " + gate.join(", ") + " never ask whether an account is a test", asks.length === 0, asks.join(", "));
    const requirers = Object.keys(LIB).concat(["server.js"]).filter(f => /require\("\.\/(lib\/)?testAccounts"\)/.test(f === "server.js" ? SERVER : LIB[f]));
    check("4. only lib/selfReview.js requires lib/testAccounts.js", JSON.stringify(requirers) === JSON.stringify(["lib/selfReview.js"]), requirers.join(", "));
    check("4. the cleanup leaves the check account's subscription, which checkRunResidue requires active",
      /if \(s\.status !== "active"\) \{\n    problems\.push\("its subscription's status is "/.test(RESIDUE_SRC) && CLEANUP.indexOf(SEED_ROW) !== -1 &&
      !new RegExp("STEP 2[\\s\\S]*" + SEED_ROW + "[\\s\\S]*STEP 3").test(CLEANUP));
  }

  /* ── 5. the cleanup file ────────────────────────────────────────────────── */
  console.log("\n══ 5. " + CLEANUP_REL + " ══");
  {
    if (fs.existsSync(OWNER_COPY)) {
      check("5. the owner's copy in Downloads is byte for byte this file", Buffer.compare(fs.readFileSync(OWNER_COPY), CLEANUP_RAW) === 0);
    } else {
      console.log("    note  the owner's copy is not in Downloads; only the repository copy is checked");
    }
    const step = n => {
      const a = CLEANUP.indexOf("-- STEP " + n + ".");
      const b = n < 3 ? CLEANUP.indexOf("-- STEP " + (n + 1) + ".") : CLEANUP.length;
      return a === -1 || b === -1 ? "" : CLEANUP.slice(a, b);
    };
    const [preview, change, verify] = [step(1), step(2), step(3)];
    const lists = text => (text.match(/s\.id in \(([^)]*)\)/g) || []).map(l => (l.match(/'([0-9a-f-]{36})'/g) || []).map(q => q.slice(1, -1)));
    const pl = lists(preview), cl = lists(change), vl = lists(verify);
    const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
    console.log("    preview lists " + pl.map(l => l.length).join(",") + "; change lists " + cl.map(l => l.length).join(",") + "; verify lists " + vl.map(l => l.length).join(","));
    check("5. the preview names exactly the ten clean-run rows", pl.length === 1 && same(pl[0], TEN), JSON.stringify(pl));
    check("5. the guard and the update name the same ten, and nothing else", cl.length === 2 && same(cl[0], TEN) && same(cl[1], TEN), JSON.stringify(cl));
    check("5. neither names the check account's row", cl.every(l => l.indexOf(SEED_ROW) === -1) && pl.every(l => l.indexOf(SEED_ROW) === -1));
    check("5. the verify reads the ten and the check account's row", vl.length === 1 && same(vl[0], TEN.concat([SEED_ROW])), JSON.stringify(vl));
    const COND = ["s.status = 'active'", "s.stripe_subscription_id is null", "s.stripe_customer_id is null", "lower(u.email) like '%@bizforceai.invalid'"];
    const condCount = text => COND.map(c => text.split(c).length - 1);
    check("5. preview, guard and update apply the same four conditions",
      same(condCount(preview), [1, 1, 1, 1]) && same(condCount(change), [2, 2, 2, 2]), JSON.stringify([condCount(preview), condCount(change)]));
    check("5. nothing is deleted", !/\bdelete\b/i.test(CLEANUP.replace(/^--.*$/gm, "")));
    const updates = CLEANUP.match(/\bupdate public\.\w+/g) || [];
    check("5. one update, of subscriptions, setting status = 'canceled' and updated_at only",
      same(updates, ["update public.subscriptions"]) && /update public\.subscriptions s\n     set status = 'canceled', updated_at = now\(\)\n    from public\.users u\n/.test(change));
    const guardRe = /if n <> 10 then\n    raise exception 'cleanup refused: expected 10 matching rows, found %\. Nothing was changed\.', n;\n  end if;\n\n  update public\.subscriptions/;
    const afterRe = /get diagnostics n = row_count;\n  if n <> 10 then\n    raise exception 'cleanup refused: the update matched % rows, not 10\. Nothing was changed\.', n;/;
    check("5. the count is checked before the update, and refuses when it is not 10", guardRe.test(change));
    check("5. the rows the update changed are counted, and anything but 10 refuses", afterRe.test(change));
    check("5. inside one transaction: begin before, commit after", /\nbegin;\n\ndo \$\$\n/.test(change) && /\nend\n\$\$;\n\ncommit;\n/.test(change));

    /* The change, modelled over the 14 rows the recon read, as the file's text says it runs. */
    const guardOn = /if n <> (\d+) then\n    raise exception 'cleanup refused: expected/.exec(change);
    const afterOn = afterRe.test(change);
    const matches = (row, list) => list.indexOf(row.id) !== -1 && row.status === "active" && !row.stripe && row.invalidEmail;
    function runModel(rows) {
      const table = rows.map(r => Object.assign({}, r));
      const n = table.filter(r => matches(r, cl[0] || [])).length;
      if (guardOn && n !== Number(guardOn[1])) return { refused: "expected " + guardOn[1] + ", found " + n, table: rows.map(r => Object.assign({}, r)) };
      const hit = table.filter(r => matches(r, cl[1] || []));
      hit.forEach(r => { r.status = "canceled"; });
      if (afterOn && hit.length !== 10) return { refused: "the update matched " + hit.length, table: rows.map(r => Object.assign({}, r)) };
      return { refused: null, table: table };
    }
    const changed = (before, after) => after.filter((r, i) => r.status !== before[i].status).map(r => r.id);
    const live = runModel(LIVE_ROWS);
    console.log("    over the live rows: " + (live.refused ? "refused (" + live.refused + ")" : changed(LIVE_ROWS, live.table).length + " rows canceled"));
    check("5. over the live rows it cancels exactly the ten, and the check account's row stays active",
      !live.refused && same(changed(LIVE_ROWS, live.table).sort(), TEN.slice().sort()) &&
      live.table.find(r => r.id === SEED_ROW).status === "active", live.refused || changed(LIVE_ROWS, live.table).join(","));
    const oneGone = LIVE_ROWS.map(r => r.id === TEN[3] ? Object.assign({}, r, { status: "canceled" }) : r);
    const short = runModel(oneGone);
    console.log("    with one of the ten already canceled: " + (short.refused ? "refused (" + short.refused + ")" : changed(oneGone, short.table).length + " rows canceled"));
    check("5. when only nine match, it refuses and changes nothing", !!short.refused && changed(oneGone, short.table).length === 0, short.refused);
    const again = runModel(live.table);
    check("5. run a second time, it refuses and changes nothing", !!again.refused && changed(live.table, again.table).length === 0, again.refused);
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
