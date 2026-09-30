/* ══════════════════════════════════════════════════════════════════════════
   checkRemainingSpendPaths.js — the last four model-calling paths that never
   asked whether the account was paying.

     POST /api/assignments/:id/start          platform key, requireAuth only
     POST /api/agents/store/generate-proposals BYOK w/ silent platform fallback
     runSalesAutoConvert                      ENABLE_SALES_AUTOLOOP, default off
     runStoreProposalPass                     ENABLE_STORE_PROPOSAL_JOB, ditto

   The two routes are tested the way 18e035d's five were: by walking the route's
   real layer stack with requireAuth's req.user substituted, and stopping at the
   gate. The two passes are tested by running the real exported functions and
   reading back every table they can write.

   ── TWO THINGS THIS SCRIPT DOES TO KEEP A TEST FROM DOING REAL WORK ─────────

   OUTREACH_MIN_INTENT IS RAISED TO 100 BEFORE server.js LOADS. runSalesAutoConvert
   drafts up to five leads per user per pass, and there are real eligible leads
   in the database right now (two, both scoring 62). Every gate above the
   drafting loop still runs exactly as it does in production; the loop underneath
   simply finds nothing to draft. Without this the "entitled account passes"
   case would prove the gate by generating real outreach drafts on the owner's
   live account, which is not a trade worth making for a green tick.

   THE LEAD READ IS INTERCEPTED, AND DRY RUN IS FORCED. The intent floor above
   is a threshold, not a wall: a lead scoring exactly 100 still passes it, and
   bsky_leads is filled continuously by LeadRadar. And DRY RUN is not "writes
   nothing" — convertSingleLead still calls the model and writes ai_tasks and
   sales_lead_pipeline rows under the owner in a dry run; only the send and the
   remaining writes are held back. Nor was DRY RUN this script's choice: it came
   from SALES_AUTOLOOP_DRY_RUN being unset, and set to "false" the pass would
   have POSTED the stub's text as a reply from the owner's accounts. So every
   Supabase client server.js creates in this process answers the bsky_leads
   read with no rows — the pass still runs every gate, reaches the read (which
   is asserted), and has nothing to draft — and SALES_AUTOLOOP_DRY_RUN is set to
   "true" here, before each sales run, whatever the environment says.

   THE STORE PASS IS KEPT TO THE SUBJECT. runStoreProposalPass takes every
   account with store autonomy on, and the owner has it on. It skipped them only
   because they hold no stored Anthropic key; store one and this check would
   have written agent_proposals under them. The plan lookup the pass asks before
   the key read now refuses every account but the subject
   (checkRunResidue.js, passScope), under MUTATE as well.

   THE OWNER'S ACCOUNT IS READ, NEVER CLEANED. scripts/checkRunResidue.js
   refuses to build a guard whose subject is the owner — deliberately, since
   that guard deletes by time window. So the owner's rows are counted before and
   after and any change at all is a hard failure naming the ids, rather than
   something this script would try to tidy up itself.

   MUTATE=ungate strips the entitlement middleware off both routes and tells
   both passes that everybody is entitled — which is exactly how all four
   behaved before this commit. Every refusal assertion must go red.
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const { createResidueGuard, resolveSubjectAccount, resolveEntitledAccount, passScope, refuseEveryPlan,
  OWNER_ACCOUNT_ID } = require("./checkRunResidue");
const SUBJECT_USER_ID = resolveSubjectAccount();

/* Before server.js reads it. See the header. */
process.env.OUTREACH_MIN_INTENT = "100";

/* Forced, not inherited. Re-checked before every sales run below. */
const SALES_DRY_RUN_FROM_ENV = process.env.SALES_AUTOLOOP_DRY_RUN;
process.env.SALES_AUTOLOOP_DRY_RUN = "true";
function forceSalesDryRun() {
  process.env.SALES_AUTOLOOP_DRY_RUN = "true";
  if (process.env.SALES_AUTOLOOP_DRY_RUN !== "true") {
    console.error("REFUSING TO RUN the sales pass: SALES_AUTOLOOP_DRY_RUN could not be forced to \"true\". Nothing was run.");
    process.exit(1);
  }
}

const path = require("path");
const REPO = path.join(__dirname, "..");

const SDK_PATH = require.resolve("@anthropic-ai/sdk", { paths: [REPO] });
const RealAnthropic = require(SDK_PATH);
let modelCalls = [];

function FakeAnthropic(options) {
  const instance = new RealAnthropic(options);
  instance.messages = {
    create: async function (args) {
      modelCalls.push({ model: (args && args.model) || "stubbed" });
      return {
        id: "msg_check_" + modelCalls.length,
        model: (args && args.model) || "stubbed",
        content: [{ type: "text", text: "{}" }],
        stop_reason: "end_turn",
        usage: { input_tokens: 1, output_tokens: 1 }
      };
    }
  };
  return instance;
}
Object.keys(RealAnthropic).forEach(function (k) { FakeAnthropic[k] = RealAnthropic[k]; });
require.cache[SDK_PATH].exports = FakeAnthropic;

/* The lead read, answered with nothing. See the header. Every client made
   after this point — server.js's included — gets it. */
const SUPABASE_JS_PATH = require.resolve("@supabase/supabase-js", { paths: [REPO] });
const realSupabaseJs = require(SUPABASE_JS_PATH);
let leadReads = 0;
function noRows() {
  const q = new Proxy(function () {}, {
    get: function (target, key) {
      if (key === "then") {
        return function (resolve, reject) { return Promise.resolve({ data: [], error: null, count: 0 }).then(resolve, reject); };
      }
      return function () { return q; };
    }
  });
  return q;
}
require.cache[SUPABASE_JS_PATH].exports = Object.assign({}, realSupabaseJs, {
  createClient: function () {
    const client = realSupabaseJs.createClient.apply(this, arguments);
    const realFrom = client.from.bind(client);
    client.from = function (table) {
      if (table === "bsky_leads") { leadReads++; return noRows(); }
      return realFrom(table);
    };
    return client;
  }
});

const EXPRESS_PATH = require.resolve("express", { paths: [REPO] });
const realExpress = require(EXPRESS_PATH);
let app = null;
const expressWrapper = function () {
  const made = realExpress.apply(this, arguments);
  if (!app) app = made;
  return made;
};
Object.keys(realExpress).forEach(function (k) { expressWrapper[k] = realExpress[k]; });
require.cache[EXPRESS_PATH].exports = expressWrapper;

process.env.PORT = process.env.CHECK_PORT || "0";
const server = require(path.join(REPO, "server.js"));
/* Until an account is named, every pass refuses every account. */
server.__setPassPlanLookup(refuseEveryPlan);

const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY
);

/* Every table the four paths can write between them. */
const SPEND_TABLES = ["ai_tasks", "model_calls", "agent_proposals"];

const residue = createResidueGuard({
  supabase: supabase,
  name: "remainingSpendPaths",
  subject: SUBJECT_USER_ID,
  /* agent_autonomy: the store enrolment this script creates for the subject.
     Removed by hand at the end; recorded here so a crash cannot leave the
     subject enrolled in a nightly pass. */
  tables: SPEND_TABLES.concat(["agent_autonomy"])
});
residue.install();

const MUTATING = process.env.MUTATE === "ungate";

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

/* ── route plumbing, as in checkEntitlementGate.js ───────────────────────── */
function layerFor(routePath, method) {
  const found = app._router.stack.filter(function (l) {
    return l.route && l.route.path === routePath && l.route.methods[method];
  });
  if (!found.length) throw new Error("route not mounted: " + method.toUpperCase() + " " + routePath);
  return found[0];
}

function chainNames(routePath, method) {
  return layerFor(routePath, method).route.stack.map(function (l) { return l.handle.name || "(anonymous)"; });
}

async function runToGate(routePath, method, user) {
  const stack = layerFor(routePath, method).route.stack;
  const names = chainNames(routePath, method);
  const gateIdx = names.indexOf("requireActiveSubscription");
  if (gateIdx === -1) return { gated: false };

  const req = {
    user: user, body: {}, params: { id: "00000000-0000-0000-0000-000000000000" },
    query: {}, headers: {}, ip: "127.0.0.1", method: method.toUpperCase(),
    originalUrl: routePath, get: function () { return undefined; }
  };
  let sent = null;
  let reachedGateNext = false;
  const res = {
    statusCode: 200, headersSent: false,
    status: function (c) { this.statusCode = c; return this; },
    set: function () { return this; }, setHeader: function () { return this; },
    json: function (p) { sent = { status: this.statusCode, body: p }; this.headersSent = true; return this; },
    send: function (p) { sent = { status: this.statusCode, body: p }; this.headersSent = true; return this; },
    end: function () { this.headersSent = true; return this; }
  };

  for (let i = 0; i <= gateIdx; i++) {
    const handle = stack[i].handle;
    if (handle.name === "requireAuth") continue;
    let nextErr = null, nexted = false;
    await new Promise(function (resolve) {
      let done = false;
      const fin = function () { if (!done) { done = true; resolve(); } };
      try {
        Promise.resolve(handle(req, res, function (e) { nexted = true; nextErr = e || null; fin(); })).then(fin, function (e) { nextErr = e; fin(); });
      } catch (e) { nextErr = e; fin(); }
    });
    if (nextErr) return { gated: true, error: nextErr, sent: sent, passed: false };
    if (sent) return { gated: true, sent: sent, passed: false, stoppedAt: names[i] };
    if (i === gateIdx && nexted) reachedGateNext = true;
  }
  return { gated: true, passed: reachedGateNext, req: req };
}

async function countsFor(userId) {
  const out = {};
  for (const t of SPEND_TABLES) {
    const r = await supabase.from(t).select("id", { count: "exact", head: true }).eq("user_id", userId);
    out[t] = r.error ? "n/a" : r.count;
  }
  return out;
}

function deltaLine(label, before, after) {
  return "  " + label.padEnd(11) + SPEND_TABLES.map(function (t) {
    const d = (typeof after[t] === "number" && typeof before[t] === "number") ? after[t] - before[t] : "?";
    return t + ": " + after[t] + " (" + (d >= 0 ? "+" : "") + d + ")";
  }).join("   ");
}

async function recordNewRows(userId, sinceIso) {
  for (const t of SPEND_TABLES) {
    const r = await supabase.from(t).select("id").eq("user_id", userId).gte("created_at", sinceIso);
    (r.data || []).forEach(function (row) { residue.record(t, row.id); });
  }
}

(async function main() {
  await residue.sweepPrevious(SUBJECT_USER_ID);

  console.log("\n══ subjects ══");
  const usersResult = await supabase.from("users").select("id, email, role");
  if (usersResult.error) throw usersResult.error;

  const unentitled = (usersResult.data || []).filter(function (u) { return u.id === SUBJECT_USER_ID; })[0];
  /* The seed account, by email. Refuses and exits — no search — if it is not. */
  const paying = await resolveEntitledAccount(supabase);
  const admin = (usersResult.data || []).filter(function (u) { return String(u.role).toLowerCase() === "admin"; })[0];
  if (!unentitled || !admin) { console.error("could not find the subject account and the admin account"); process.exit(1); }
  console.log("  SALES_AUTOLOOP_DRY_RUN from the environment: " + JSON.stringify(SALES_DRY_RUN_FROM_ENV) + " — forced to \"true\" here");

  console.log("  unentitled : " + unentitled.id + "  (" + unentitled.email + ")");
  console.log("  paying     : " + paying.id + "  (" + paying.email + ")");
  console.log("  admin      : " + admin.id + "  (" + admin.email + ", role " + admin.role + ")");
  if (MUTATING) console.log("\n!! MUTATION: the gate is removed from both routes and both passes must stop refusing.");

  const ownerBefore = await countsFor(admin.id);
  console.log("\n══ owner row counts BEFORE (read-only account for this check) ══");
  console.log("  " + SPEND_TABLES.map(function (t) { return t + ": " + ownerBefore[t]; }).join("   "));

  /* ════ 1 & 2: the two routes ═══════════════════════════════════════════ */
  const ROUTES = [
    { path: "/api/assignments/:id/start", method: "post" },
    { path: "/api/agents/store/generate-proposals", method: "post" }
  ];

  for (const route of ROUTES) {
    console.log("\n══ " + route.method.toUpperCase() + " " + route.path + " ══");

    if (MUTATING) {
      const victim = layerFor(route.path, route.method);
      const idx = victim.route.stack.map(function (l) { return l.handle.name; }).indexOf("requireActiveSubscription");
      if (idx !== -1) victim.route.stack.splice(idx, 1);
    }

    const names = chainNames(route.path, route.method);
    console.log("    layers: " + names.join(" → "));
    const gateIdx = names.indexOf("requireActiveSubscription");
    check("the route is gated", gateIdx !== -1, names.join(", "));
    if (gateIdx === -1) continue;

    const ahead = names.slice(0, gateIdx).filter(function (n) { return n !== "requireAuth"; });
    check("nothing but requireAuth runs before the gate", ahead.length === 0, ahead.join(", "));

    const refused = await runToGate(route.path, route.method, unentitled);
    check("an unentitled account is refused", !!refused.sent && refused.sent.status === 402,
      refused.sent ? ("status " + refused.sent.status) : ("nothing sent; passed=" + refused.passed));
    check("the refusal came from the gate", refused.stoppedAt === "requireActiveSubscription", refused.stoppedAt);

    const paid = await runToGate(route.path, route.method, paying);
    check("a paying account passes", paid.passed === true,
      paid.sent ? ("refused " + paid.sent.status) : ("passed=" + paid.passed));

    const owner = await runToGate(route.path, route.method, admin);
    check("an admin passes, by exemption", owner.passed === true && owner.req && owner.req.planExempt === true,
      owner.sent ? ("refused " + owner.sent.status) : ("passed=" + owner.passed));
  }

  /* ════ 3: runSalesAutoConvert ══════════════════════════════════════════ */
  console.log("\n══ runSalesAutoConvert ══");
  console.log("    the pass only ever processes OUTREACH_CREDENTIAL_OWNER_ID, which is the");
  console.log("    admin account — so the unentitled case is simulated through the plan");
  console.log("    lookup rather than with a second account. There is no second account it");
  console.log("    would ever reach.");

  const salesBefore = await countsFor(admin.id);
  let sinceIso = new Date(Date.now() - 2000).toISOString();

  /* (a) entitled — the real answer, admin exemption and all. The lead read
     comes back empty, so getting through the gate drafts nothing. */
  server.__setPassPlanLookup(null);
  forceSalesDryRun();
  const leadReadsBefore = leadReads;
  const salesEntitled = await server.__runSalesAutoConvert();
  console.log("    entitled run: " + JSON.stringify(salesEntitled));
  check("the admin is processed rather than skipped",
    salesEntitled.processed === 1 && salesEntitled.skippedNotEntitled === 0,
    "processed=" + salesEntitled.processed + " skippedNotEntitled=" + salesEntitled.skippedNotEntitled);
  check("the summary reports a skippedNotEntitled count at all",
    Object.prototype.hasOwnProperty.call(salesEntitled, "skippedNotEntitled"),
    Object.keys(salesEntitled).join(", "));
  check("it reached its lead read, and the read was intercepted — no lead could be drafted",
    leadReads > leadReadsBefore, "intercepted bsky_leads reads: " + (leadReads - leadReadsBefore));

  /* (b) not entitled. Under MUTATE the gate is gone, so this must fail. */
  server.__setPassPlanLookup(async function () {
    return MUTATING
      ? { active: true, exempt: false, inactive_reason: null, access_reason: null }
      : { active: false, exempt: false, inactive_reason: "no_subscription", access_reason: null };
  });
  forceSalesDryRun();
  const salesRefused = await server.__runSalesAutoConvert();
  console.log("    unentitled run: " + JSON.stringify(salesRefused));
  check("an unentitled account is skipped", salesRefused.skippedNotEntitled === 1,
    "skippedNotEntitled=" + salesRefused.skippedNotEntitled);
  check("and nothing was processed for it", salesRefused.processed === 0,
    "processed=" + salesRefused.processed);

  /* (c) the plan cannot be read — fail closed, and counted as a failure. */
  server.__setPassPlanLookup(async function () { throw new Error("simulated entitlement read failure"); });
  forceSalesDryRun();
  const salesBroken = await server.__runSalesAutoConvert();
  console.log("    unreadable-plan run: " + JSON.stringify(salesBroken));
  check("an unreadable plan fails closed — skipped", salesBroken.skippedNotEntitled === 1,
    "skippedNotEntitled=" + salesBroken.skippedNotEntitled);
  check("an unreadable plan counts as a failure, so the pass cannot close clean",
    salesBroken.failed >= 1, "failed=" + salesBroken.failed);
  server.__setPassPlanLookup(refuseEveryPlan);

  const salesAfter = await countsFor(admin.id);
  console.log("\n    owner rows across all three sales runs:");
  console.log("    " + deltaLine("admin", salesBefore, salesAfter).trim());
  check("no model call was made by any sales run", modelCalls.length === 0, "model calls: " + modelCalls.length);
  SPEND_TABLES.forEach(function (t) {
    check("sales pass wrote zero " + t + " rows", salesAfter[t] === salesBefore[t],
      salesBefore[t] + " → " + salesAfter[t]);
  });

  /* ════ 4: runStoreProposalPass ═════════════════════════════════════════ */
  console.log("\n══ runStoreProposalPass ══");

  const storeBefore = { unentitled: await countsFor(unentitled.id), admin: await countsFor(admin.id) };
  sinceIso = new Date(Date.now() - 2000).toISOString();

  /* The unentitled account is enrolled for real — consent, which is all this
     pass used to ask for. Removed again below whatever happens. */
  let enrolledStore = false;
  const existingStore = await supabase.from("agent_autonomy")
    .select("enabled").eq("user_id", unentitled.id).eq("agent_type", "store").maybeSingle();
  if (!existingStore.data) {
    const ins = await supabase.from("agent_autonomy")
      .insert({ user_id: unentitled.id, agent_type: "store", enabled: true }).select("id").single();
    if (ins.error) throw new Error("could not enrol the subject in store autonomy: " + ins.error.message);
    residue.record("agent_autonomy", ins.data.id);
    enrolledStore = true;
  }

  try {
    /* The subject only. The owner, enrolled of their own accord, is turned
       away before their key is read. Under MUTATE the subject is told it is
       entitled; everyone else is still refused. */
    const storeScope = passScope([unentitled.id], MUTATING
      ? async function () { return { active: true, exempt: false, inactive_reason: null, access_reason: null }; }
      : function (userId) { return server.__selfReviewPlanFor(userId); });
    server.__setPassPlanLookup(storeScope.lookup);
    const storeSummary = await server.__runStoreProposalPass();
    console.log("    summary: " + JSON.stringify(storeSummary));
    server.__setPassPlanLookup(refuseEveryPlan);
    console.log("    turned away by the scope: " + storeScope.refused.size + " account(s)" +
      (storeScope.refused.has(OWNER_ACCOUNT_ID) ? ", the owner among them" : ""));

    check("the summary reports a skippedNotEntitled count",
      Object.prototype.hasOwnProperty.call(storeSummary, "skippedNotEntitled"),
      Object.keys(storeSummary).join(", "));
    check("the unentitled account is skipped for entitlement",
      storeSummary.skippedNotEntitled >= 1, "skippedNotEntitled=" + storeSummary.skippedNotEntitled);
    check("every account beyond the subject was refused by the scope, before its key was read",
      storeSummary.users - 1 === storeScope.refused.size && !storeScope.refused.has(unentitled.id),
      "users=" + storeSummary.users + " refused by scope=" + storeScope.refused.size);
    check("the subject is the one account the gate itself refused",
      storeSummary.skippedNotEntitled - storeScope.refused.size === 1,
      "skippedNotEntitled=" + storeSummary.skippedNotEntitled + " minus " + storeScope.refused.size +
      " refused by scope (expected exactly 1)");

    await recordNewRows(unentitled.id, sinceIso);
    const storeAfter = { unentitled: await countsFor(unentitled.id), admin: await countsFor(admin.id) };
    console.log(deltaLine("unentitled", storeBefore.unentitled, storeAfter.unentitled));
    console.log(deltaLine("admin", storeBefore.admin, storeAfter.admin));
    SPEND_TABLES.forEach(function (t) {
      check("store pass wrote zero " + t + " rows for the unentitled account",
        storeAfter.unentitled[t] === storeBefore.unentitled[t],
        storeBefore.unentitled[t] + " → " + storeAfter.unentitled[t]);
    });
  } finally {
    if (enrolledStore) {
      await supabase.from("agent_autonomy").delete()
        .eq("user_id", unentitled.id).eq("agent_type", "store");
      console.log("    [fixture] store autonomy enrolment removed");
    }
  }

  /* ════ the owner's account, start to finish ════════════════════════════ */
  console.log("\n══ the owner's account, across the whole run ══");
  const ownerAfter = await countsFor(admin.id);
  console.log(deltaLine("admin", ownerBefore, ownerAfter));
  for (const t of SPEND_TABLES) {
    const same = ownerAfter[t] === ownerBefore[t];
    check("the owner's " + t + " is untouched", same, ownerBefore[t] + " → " + ownerAfter[t]);
    if (!same) {
      /* NOT CLEANED UP. checkRunResidue refuses to build a guard over the owner
         on purpose, so anything here is reported for a human to remove. */
      const rows = await supabase.from(t).select("id").eq("user_id", admin.id).gte("created_at", sinceIso);
      console.error("    REMOVE BY HAND — " + t + ": " + (rows.data || []).map(function (r) { return r.id; }).join(", "));
    }
  }

  console.log("\n══ cleanup ══");
  const cleanupResult = await residue.cleanup("end of run");
  if (cleanupResult.leftovers.length) failures++;

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
})().catch(function (err) {
  console.error("\nThe check threw: " + ((err && err.stack) || err));
  process.exit(1);
});
