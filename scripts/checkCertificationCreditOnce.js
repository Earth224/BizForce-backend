/* ══════════════════════════════════════════════════════════════════════════
   checkCertificationCreditOnce.js — a certification pays once, not per pass.

   THE DEFECT. POST /api/certifications/award upserted the record and then
   credited 100 BFC whenever the submission passed. Re-passing a quiz already
   earned paid again, every time, into a currency that transfer, donation and
   marketplace purchase can spend.

   WHAT THIS PROVES
     1. A first-time pass credits exactly 100 and writes one wallet transaction.
     2. A repeat pass of the same certification credits nothing and writes no
        transaction.
     3. A different certification for the same user credits again.
     4. The repeat pass still answers success, the record stays earned, and the
        response says already_earned: true, credited: false.
     5. A fail after earning does not un-earn it, so pass, fail, pass does not
        pay twice.
     6. A pass after an earlier fail is still a first pass and credits once.
     7. Two passing submissions arriving together are paid once, not twice.
     8. THE FIRST-TIME PATH IS UNCHANGED. The pre-fix route (8b5afc7) and this
        one are both run on a fresh certification and must move the wallet the
        same way: HTTP 201, success true, +100, one "reward" transaction with the
        same description.
     9. TWO CREDITS AT THE SAME MOMENT BOTH LAND. creditWallet used to read the
        balance and write back what it read plus 100, so two credits that read
        before either wrote left the wallet +100 with two transaction rows. It
        now calls bfc_credit, one atomic upsert. Two creditWallet calls for two
        different certifications must move the balance by 200 and write two
        rows. The wallet READ is held behind a barrier until both calls have
        made it — without that the race is left to network timing and the old
        code would lose a credit only sometimes. The atomic version makes no
        read, so the barrier never engages.
    10. A SINGLE CREDIT IS UNCHANGED. creditWallet as it was at eaadbfe and as
        it is now each credit once: the same +100, one row, same user, type,
        amount and description, with a created_at.

   THE ROUTE RUNS AS ITSELF, OUT OF THE SOURCE. The handler, creditWallet,
   safeText and nowIso are lifted out of server.js and run in a vm against the
   real database, the way scripts/_shared.js runs the tool routes. server.js is
   not required, so no listener, cron or radar starts. The mutations are
   applied to that lifted source, never to the file.

   MUTATE=credit-every-pass puts back `if (passed)` as the credit guard, which
   is the defect with the new write logic left around it.
   MUTATE=old-handler runs the whole pre-fix route from 8b5afc7.
   Both must turn 2, 4c, 5b and 7 red. old-handler also turns 5a red, because
   its upsert lets a fail reset an earned record to passed = false.
   MUTATE=read-then-write swaps in creditWallet from eaadbfe, the read-then-
   write version, everywhere this script uses it. 9 must go red.

   Fixtures are written under the subject account and removed with a verified
   read-back. A wallet the subject already had is put back to its starting
   balance; one this run created is deleted.
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const { createResidueGuard, resolveSubjectAccount } = require("./checkRunResidue");
const SUBJECT_USER_ID = resolveSubjectAccount();

const fs = require("fs");
const vm = require("vm");
const path = require("path");
const { execSync } = require("child_process");
const { braceMatch } = require("./_shared");
const REPO = path.join(__dirname, "..");

const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY
);

const residue = createResidueGuard({
  supabase: supabase,
  name: "certificationCreditOnce",
  subject: SUBJECT_USER_ID,
  tables: ["user_certifications", "wallet_transactions", "user_wallets"]
});
residue.install();

const MUTATIONS = ["credit-every-pass", "old-handler", "read-then-write"];
const MUTATE = process.env.MUTATE || "";
if (MUTATE && MUTATIONS.indexOf(MUTATE) === -1) {
  console.error("Unknown MUTATE=" + MUTATE + ". Known: " + MUTATIONS.join(", "));
  process.exit(2);
}

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

/* ── the route, lifted out of the source ─────────────────────────────────── */
const BEFORE_FIX = "8b5afc7";
const SRC_NOW = fs.readFileSync(path.join(REPO, "server.js"), "utf8");
const SRC_OLD = execSync("git show " + BEFORE_FIX + ":server.js", { cwd: REPO, maxBuffer: 64 * 1024 * 1024 }).toString("utf8");

function routeSource(src) {
  const sig = 'app.post("/api/certifications/award"';
  const start = src.indexOf(sig);
  if (start < 0) throw new Error("the certification route was not found");
  const end = braceMatch(src, src.indexOf("{", start + sig.length));
  if (src.slice(end, end + 2) !== ");") throw new Error("the route did not end where expected");
  return src.slice(start, end + 2);
}

function functionSource(src, name) {
  const m = new RegExp("^(?:async )?function " + name + "\\(", "m").exec(src);
  if (!m) throw new Error("function " + name + " was not found");
  const body = src.indexOf(") {", m.index) + 2;
  return src.slice(m.index, braceMatch(src, body));
}

/* creditWallet before it became atomic. Used by 10 as the "before", and by
   MUTATE=read-then-write in place of the current one everywhere. */
const BEFORE_ATOMIC = "eaadbfe";
const SRC_RTW = execSync("git show " + BEFORE_ATOMIC + ":server.js", { cwd: REPO, maxBuffer: 64 * 1024 * 1024 }).toString("utf8");
const CREDIT_SRC = MUTATE === "read-then-write" ? SRC_RTW : SRC_NOW;

/* The same helpers for both handlers, taken from the current file (or, under
   read-then-write, with the pre-atomic creditWallet). */
const HELPERS = [functionSource(SRC_NOW, "nowIso"), functionSource(SRC_NOW, "safeText"), functionSource(CREDIT_SRC, "creditWallet")].join("\n\n");

/* creditWallet on its own, against a given client. */
function buildCreditWallet(src, client) {
  const ctx = { supabase: client, console: { log: function () {}, warn: function () {}, error: function () {} } };
  vm.createContext(ctx);
  vm.runInContext(functionSource(SRC_NOW, "nowIso") + "\n\n" + functionSource(src, "creditWallet"), ctx);
  if (typeof ctx.creditWallet !== "function") throw new Error("creditWallet was not captured");
  return ctx.creditWallet;
}

/* THE BARRIER. A client whose user_wallets read does not return until `n`
   such reads have been made (or 3s have passed, so a code path that reads
   only once cannot hang the run). Everything else passes straight through to
   the real client. This is what makes "both read before either writes"
   certain rather than likely. */
function barrierClient(n) {
  let arrived = 0, release;
  const gate = new Promise(function (r) { release = r; });
  const stats = { reads: 0 };
  return {
    stats: stats,
    rpc: function () { return supabase.rpc.apply(supabase, arguments); },
    from: function (table) {
      const q = supabase.from(table);
      if (table !== "user_wallets") return q;
      const select = q.select.bind(q);
      q.select = function () {
        const b = select.apply(null, arguments);
        const maybeSingle = b.maybeSingle.bind(b);
        b.maybeSingle = function () {
          return maybeSingle().then(async function (res) {
            stats.reads++;
            arrived++;
            if (arrived >= n) release(); else setTimeout(release, 3000);
            await gate;
            return res;
          });
        };
        return b;
      };
      return q;
    }
  };
}

function buildHandler(which) {
  let route = which === "old" ? routeSource(SRC_OLD) : routeSource(SRC_NOW);

  if (which === "new" && MUTATE === "credit-every-pass") {
    const guard = "if (becameEarned) {";
    if (route.split(guard).length !== 2) throw new Error("mutation target not found exactly once: " + guard);
    route = route.replace(guard, "if (passed) {");
  }
  if (which === "new" && MUTATE === "old-handler") route = routeSource(SRC_OLD);

  let handler = null;
  const ctx = {
    supabase: supabase,
    console: { log: function () {}, warn: function () {}, error: function () {} },
    requireAuth: 0,
    app: { post: function () { handler = arguments[arguments.length - 1]; } }
  };
  vm.createContext(ctx);
  vm.runInContext(HELPERS + "\n\n" + route, ctx);
  if (!handler) throw new Error("the handler was not captured");
  return handler;
}

async function submit(handler, certId, passed, score) {
  const res = {
    statusCode: 200, body: undefined,
    status: function (c) { this.statusCode = c; return this; },
    json: function (b) { this.body = JSON.parse(JSON.stringify(b)); return this; }
  };
  let nextErr = null;
  await handler(
    { user: { id: SUBJECT_USER_ID }, body: { cert_id: certId, category: "CHECK", score: score, passed: passed } },
    res,
    function (e) { nextErr = e || new Error("next() called"); }
  );
  const row = await certRow(certId);
  return { status: res.statusCode, body: res.body, nextErr: nextErr, row: row };
}

/* ── reads, each recording what it finds for the residue guard ──────────── */
async function certRow(certId) {
  const r = await supabase.from("user_certifications").select("id, user_id, passed, score")
    .eq("user_id", SUBJECT_USER_ID).eq("cert_id", certId).maybeSingle();
  if (r.error) throw new Error("could not read the certification: " + r.error.message);
  if (r.data) residue.record("user_certifications", r.data.id);
  return r.data;
}

async function certTxns(certId) {
  const r = await supabase.from("wallet_transactions").select("id, user_id, type, amount, description")
    .eq("user_id", SUBJECT_USER_ID).eq("description", "Certification earned: " + certId);
  if (r.error) throw new Error("could not read the transactions: " + r.error.message);
  (r.data || []).forEach(function (t) { residue.record("wallet_transactions", t.id); });
  return r.data || [];
}

let STARTING_WALLET = null;
async function balance() {
  const r = await supabase.from("user_wallets").select("id, balance").eq("user_id", SUBJECT_USER_ID).maybeSingle();
  if (r.error) throw new Error("could not read the wallet: " + r.error.message);
  if (r.data && !STARTING_WALLET) residue.record("user_wallets", r.data.id);   /* created by this run */
  return r.data ? r.data.balance : 0;
}

const stamp = Date.now();
const cert = function (tag) { return "check-cert-" + tag + "-" + stamp; };

(async function main() {
  await residue.sweepPrevious(SUBJECT_USER_ID);

  const w = await supabase.from("user_wallets").select("id, balance").eq("user_id", SUBJECT_USER_ID).maybeSingle();
  if (w.error) throw new Error("could not read the starting wallet: " + w.error.message);
  STARTING_WALLET = w.data || null;
  console.log("\n══ subject wallet at start: " + (STARTING_WALLET ? STARTING_WALLET.balance + " BFC" : "none") + " ══");
  console.log("══ handler under test: " + (MUTATE ? "MUTATED (" + MUTATE + ")" : "server.js as it stands") + " ══");

  const H = buildHandler("new");

  try {
    /* ── 1. first-time pass ──────────────────────────────────────────────── */
    console.log("\n══ 1. a first-time pass ══");
    const A = cert("a");
    let b0 = await balance();
    const first = await submit(H, A, true, 90);
    let b1 = await balance();
    let txA = await certTxns(A);
    console.log("    HTTP " + first.status + " " + JSON.stringify(Object.assign({}, first.body, { certification: "…" })));
    check("1. credits exactly 100", b1 - b0 === 100, "delta " + (b1 - b0));
    check("1. and writes one wallet transaction", txA.length === 1, txA.length + " transaction(s)");
    check("1. a reward of 100", txA.length === 1 && txA[0].type === "reward" && txA[0].amount === 100, JSON.stringify(txA[0]));

    /* ── 2 and 4. repeat pass ────────────────────────────────────────────── */
    console.log("\n══ 2. the same certification passed again ══");
    const repeat = await submit(H, A, true, 95);
    const b2 = await balance();
    txA = await certTxns(A);
    console.log("    HTTP " + repeat.status + " " + JSON.stringify(Object.assign({}, repeat.body, { certification: "…" })));
    check("2. credits nothing", b2 - b1 === 0, "delta " + (b2 - b1));
    check("2. and writes no transaction", txA.length === 1, txA.length + " transaction(s) for this certification");

    console.log("\n══ 4. the repeat is still a success ══");
    check("4a. it answers success, not an error", !repeat.nextErr && repeat.status < 300 && repeat.body && repeat.body.success === true,
      repeat.nextErr ? String(repeat.nextErr.message || repeat.nextErr) : repeat.status + " " + JSON.stringify(repeat.body && repeat.body.success));
    check("4b. the record stays earned", repeat.row && repeat.row.passed === true, JSON.stringify(repeat.row));
    check("4c. the response says already_earned: true, credited: false",
      repeat.body && repeat.body.already_earned === true && repeat.body.credited === false,
      JSON.stringify({ already_earned: repeat.body && repeat.body.already_earned, credited: repeat.body && repeat.body.credited }));

    /* ── 3. a different certification ────────────────────────────────────── */
    console.log("\n══ 3. a different certification for the same user ══");
    const B = cert("b");
    const b3 = await balance();
    await submit(H, B, true, 85);
    const b4 = await balance();
    const txB = await certTxns(B);
    check("3. credits 100 again", b4 - b3 === 100, "delta " + (b4 - b3));
    check("3. with its own transaction", txB.length === 1, txB.length + " transaction(s)");

    /* ── 5. pass, fail, pass ─────────────────────────────────────────────── */
    console.log("\n══ 5. a fail after earning, then a pass ══");
    const failAfter = await submit(H, A, false, 10);
    check("5a. the fail does not un-earn the certification", failAfter.row && failAfter.row.passed === true, JSON.stringify(failAfter.row));
    const b5 = await balance();
    await submit(H, A, true, 90);
    const b6 = await balance();
    txA = await certTxns(A);
    check("5b. and the pass after it pays nothing", b6 - b5 === 0 && txA.length === 1,
      "delta " + (b6 - b5) + ", " + txA.length + " transaction(s)");

    /* ── 6. fail first, then pass ────────────────────────────────────────── */
    console.log("\n══ 6. a first attempt that fails, then a pass ══");
    const C = cert("c");
    const b7 = await balance();
    const failFirst = await submit(H, C, false, 40);
    const b8 = await balance();
    check("6a. the failed attempt is recorded, not earned, and pays nothing",
      failFirst.row && failFirst.row.passed === false && b8 - b7 === 0, JSON.stringify(failFirst.row) + " delta " + (b8 - b7));
    const passLater = await submit(H, C, true, 90);
    const b9 = await balance();
    const txC = await certTxns(C);
    check("6b. the later pass is a first pass: earned, +100, one transaction",
      passLater.row && passLater.row.passed === true && b9 - b8 === 100 && txC.length === 1,
      JSON.stringify(passLater.row) + " delta " + (b9 - b8) + ", " + txC.length + " transaction(s)");

    /* ── 7. two passes at once ───────────────────────────────────────────── */
    console.log("\n══ 7. two passing submissions arriving together ══");
    const D = cert("d");
    const b10 = await balance();
    const both = await Promise.all([submit(H, D, true, 90), submit(H, D, true, 91)]);
    const b11 = await balance();
    const txD = await certTxns(D);
    console.log("    statuses: " + both.map(function (r) { return r.status; }).join(", "));
    check("7. paid once, not twice", b11 - b10 === 100 && txD.length === 1,
      "delta " + (b11 - b10) + ", " + txD.length + " transaction(s)");
    check("7. and both answered success", both.every(function (r) { return !r.nextErr && r.body && r.body.success === true; }),
      JSON.stringify(both.map(function (r) { return r.nextErr ? String(r.nextErr.message) : r.status; })));

    /* ── 8. the first-time path, before and after ────────────────────────── */
    console.log("\n══ 8. the first-time path against the pre-fix route (" + BEFORE_FIX + ") ══");
    const OLD = buildHandler("old");
    const E = cert("e-old"), F = cert("f-new");

    const e0 = await balance();
    const oldRun = await submit(OLD, E, true, 88);
    const e1 = await balance();
    const txE = await certTxns(E);

    const f0 = await balance();
    const newRun = await submit(H, F, true, 88);
    const f1 = await balance();
    const txF = await certTxns(F);

    const shape = function (run, delta, tx) {
      return {
        status: run.status, success: run.body && run.body.success,
        has_certification: !!(run.body && run.body.certification && run.body.certification.passed === true),
        delta: delta, transactions: tx.length,
        tx: tx[0] ? { type: tx[0].type, amount: tx[0].amount, description: tx[0].description.replace(/-(e-old|f-new)-\d+$/, "-X") } : null
      };
    };
    const oldShape = shape(oldRun, e1 - e0, txE);
    const newShape = shape(newRun, f1 - f0, txF);
    console.log("    pre-fix:  " + JSON.stringify(oldShape));
    console.log("    now:      " + JSON.stringify(newShape));
    console.log("    fields the response now adds: " + JSON.stringify({ already_earned: newRun.body && newRun.body.already_earned, credited: newRun.body && newRun.body.credited }));
    check("8. a first-time pass moves the wallet exactly as it did before the fix",
      JSON.stringify(oldShape) === JSON.stringify(newShape), "they differ");
    check("8. and the pre-fix route really was the one that paid, so this compared something", oldShape.delta === 100, "delta " + oldShape.delta);

    /* ── 9. two credits at the same moment ───────────────────────────────── */
    console.log("\n══ 9. two credits landing at the same moment (creditWallet " + (MUTATE === "read-then-write" ? "from " + BEFORE_ATOMIC + ", read-then-write" : "as it stands") + ") ══");
    const G1 = cert("g1"), G2 = cert("g2");
    const racer = barrierClient(2);
    const racingCredit = buildCreditWallet(CREDIT_SRC, racer);
    const g0 = await balance();
    const raced = await Promise.allSettled([
      racingCredit(SUBJECT_USER_ID, 100, "Certification earned: " + G1),
      racingCredit(SUBJECT_USER_ID, 100, "Certification earned: " + G2)
    ]);
    const g1 = await balance();
    const txG = (await certTxns(G1)).concat(await certTxns(G2));
    console.log("    both calls: " + raced.map(function (r) { return r.status; }).join(", ") +
      " | wallet reads held at the barrier: " + racer.stats.reads + " | delta " + (g1 - g0) + " | transaction rows " + txG.length);
    check("9. both calls completed without error", raced.every(function (r) { return r.status === "fulfilled"; }),
      JSON.stringify(raced.map(function (r) { return r.status === "rejected" ? String(r.reason && r.reason.message) : "ok"; })));
    check("9. the balance moved by the sum of both credits (+200)", g1 - g0 === 200, "delta " + (g1 - g0));
    check("9. and two transaction rows exist", txG.length === 2, txG.length + " row(s)");

    /* ── 10. a single credit, before and after ───────────────────────────── */
    console.log("\n══ 10. a single credit, creditWallet at " + BEFORE_ATOMIC + " vs now ══");
    const H1 = cert("h-old"), H2 = cert("h-new");
    const oneCredit = async function (fn, certId) {
      const before = await balance();
      await fn(SUBJECT_USER_ID, 100, "Certification earned: " + certId);
      const after = await balance();
      const r = await supabase.from("wallet_transactions").select("id, user_id, type, amount, description, created_at")
        .eq("user_id", SUBJECT_USER_ID).eq("description", "Certification earned: " + certId);
      if (r.error) throw new Error("could not read the transactions: " + r.error.message);
      (r.data || []).forEach(function (t) { residue.record("wallet_transactions", t.id); });
      const t = (r.data || [])[0];
      return {
        delta: after - before, rows: (r.data || []).length,
        row: t ? { user_is_subject: t.user_id === SUBJECT_USER_ID, type: t.type, amount: t.amount,
                   description: t.description.replace(/-(h-old|h-new)-\d+$/, "-X"), has_created_at: !!t.created_at } : null
      };
    };
    const beforeShape = await oneCredit(buildCreditWallet(SRC_RTW, supabase), H1);
    const nowShape    = await oneCredit(buildCreditWallet(CREDIT_SRC, supabase), H2);
    console.log("    " + BEFORE_ATOMIC + ": " + JSON.stringify(beforeShape));
    console.log("    now:     " + JSON.stringify(nowShape));
    check("10. a single credit moves the balance and writes the row exactly as before",
      JSON.stringify(beforeShape) === JSON.stringify(nowShape), "they differ");
    check("10. and that is +100 with one reward row", nowShape.delta === 100 && nowShape.rows === 1 && nowShape.row && nowShape.row.type === "reward" && nowShape.row.amount === 100,
      JSON.stringify(nowShape));
  } finally {
    console.log("\n══ cleanup ══");
    if (STARTING_WALLET) {
      const put = await supabase.from("user_wallets").update({ balance: STARTING_WALLET.balance }).eq("id", STARTING_WALLET.id);
      const back = await supabase.from("user_wallets").select("balance").eq("id", STARTING_WALLET.id).single();
      const ok = !put.error && !back.error && back.data.balance === STARTING_WALLET.balance;
      console.log("    [fixture] the subject's wallet put back to " + STARTING_WALLET.balance + " BFC: " + (ok ? "yes" : "NO"));
      if (!ok) failures++;
    }
    const cleanupResult = await residue.cleanup("end of run");
    if (cleanupResult.leftovers.length) failures++;
  }

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
})().catch(function (err) {
  console.error("\nThe check threw: " + ((err && err.stack) || err));
  process.exit(1);
});
