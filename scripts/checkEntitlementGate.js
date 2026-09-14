/* ══════════════════════════════════════════════════════════════════════════
   checkEntitlementGate.js — the five routes that spent the platform's key for
   free, and the proof they no longer do.

   WHAT WAS WRONG. POST /api/oracle, GET /api/oracle/invocation,
   POST /api/oracle/chat, POST /api/self-reviews/run and
   POST /api/leads/draft-reply were authenticated but not entitlement-gated.
   Any account with a valid token — never subscribed, cancelled, lapsed —
   could call them, and every one of them calls Anthropic on the platform's
   key. There is no free tier in this product, so that was straightforwardly
   somebody else's model spend.

   WHY THIS RUNS THE MIDDLEWARE AND NOT THE HANDLER. The other check scripts
   reach past the middleware and invoke the route's final handler directly,
   which is right for testing what a handler does with a model reply. It is
   exactly wrong here: the middleware IS the thing under test. So this walks
   the route's real layer stack, skips requireAuth (substituting the req.user
   it would have attached — the genuine users row, role included, read from
   the database rather than invented), and runs every layer up to and
   including requireActiveSubscription.

   IT DELIBERATELY STOPS THERE. Running on into the handler would call a
   model and write an ai_tasks row, which is the spend this file exists to
   prevent. The question being asked is only ever "does the gate let this
   account through", and the answer is visible at the gate.

   THE ORDERING IS ASSERTED, NOT ASSUMED. A gate that sits after the model
   call would pass a naive "did it refuse" test while refusing too late to
   matter, so each route is also checked for the gate standing ahead of every
   other layer on it — the rate limiter, multer's upload buffering, and the
   handler itself.
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

/* Nothing here should write a row. The guard is installed anyway: if some
   layer ever does, it is cleaned up on every way out rather than left in a
   real account. See scripts/checkRunResidue.js. */
const { createResidueGuard, resolveSubjectAccount } = require("./checkRunResidue");
const SUBJECT_USER_ID = resolveSubjectAccount();

const path = require("path");
const REPO = path.join(__dirname, "..");

/* The SDK is replaced before server.js loads. NOT because a model call is
   expected — the run fails loudly if one happens — but because a stub that
   records the attempt turns "no model was called" from an assumption into a
   measurement. */
const SDK_PATH = require.resolve("@anthropic-ai/sdk", { paths: [REPO] });
const RealAnthropic = require(SDK_PATH);
let modelCallsAttempted = [];

function FakeAnthropic(options) {
  const instance = new RealAnthropic(options);
  instance.messages = {
    create: async function (args) {
      modelCallsAttempted.push((args && args.model) || "unknown");
      throw new Error("checkEntitlementGate: a model call was attempted — the gate did not stop it");
    }
  };
  return instance;
}
Object.keys(RealAnthropic).forEach(function (k) { FakeAnthropic[k] = RealAnthropic[k]; });
require.cache[SDK_PATH].exports = FakeAnthropic;

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
require(path.join(REPO, "server.js"));

const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY
);

const residue = createResidueGuard({
  supabase: supabase,
  name: "entitlementGate",
  subject: SUBJECT_USER_ID,
  tables: ["ai_tasks", "model_calls"]
});
residue.install();

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

/* The five, with the method each is registered under. */
const ROUTES = [
  { path: "/api/oracle",            method: "post" },
  { path: "/api/oracle/invocation", method: "get"  },
  { path: "/api/oracle/chat",       method: "post" },
  { path: "/api/self-reviews/run",  method: "post" },
  { path: "/api/leads/draft-reply", method: "post" }
];

function layerFor(routePath, method) {
  const found = app._router.stack.filter(function (l) {
    return l.route && l.route.path === routePath && l.route.methods[method];
  });
  if (!found.length) throw new Error("route not mounted: " + method.toUpperCase() + " " + routePath);
  return found[0];
}

function chainNames(routePath, method) {
  return layerFor(routePath, method).route.stack.map(function (l) {
    return l.handle.name || "(anonymous)";
  });
}

/* Runs the route's real layers up to and including the entitlement gate, with
   requireAuth replaced by the req.user it would have attached. Returns what
   the gate did: a response it sent, or the fact that it called next(). */
async function runToGate(routePath, method, user) {
  const layer = layerFor(routePath, method);
  const stack = layer.route.stack;
  const names = chainNames(routePath, method);
  const gateIdx = names.indexOf("requireActiveSubscription");
  if (gateIdx === -1) return { gated: false };

  const req = {
    user: user,
    body: {},
    params: {},
    query: {},
    headers: {},
    ip: "127.0.0.1",
    method: method.toUpperCase(),
    originalUrl: routePath,
    get: function () { return undefined; }
  };

  let sent = null;
  let reachedGateNext = false;
  const res = {
    statusCode: 200,
    headersSent: false,
    status: function (code) { this.statusCode = code; return this; },
    set: function () { return this; },
    setHeader: function () { return this; },
    json: function (payload) { sent = { status: this.statusCode, body: payload }; this.headersSent = true; return this; },
    send: function (payload) { sent = { status: this.statusCode, body: payload }; this.headersSent = true; return this; },
    end: function () { this.headersSent = true; return this; }
  };

  for (let i = 0; i <= gateIdx; i++) {
    const handle = stack[i].handle;
    /* requireAuth is the one layer deliberately not run: this harness has no
       bearer token to offer it. req.user above is what it would have set. */
    if (handle.name === "requireAuth") continue;

    let nextErr = null;
    let nexted = false;
    await new Promise(function (resolve) {
      let done = false;
      const fin = function () { if (!done) { done = true; resolve(); } };
      try {
        Promise.resolve(handle(req, res, function (err) { nexted = true; nextErr = err || null; fin(); }))
          .then(fin, function (err) { nextErr = err; fin(); });
      } catch (err) { nextErr = err; fin(); }
    });

    if (nextErr) return { gated: true, error: nextErr, sent: sent, passed: false };
    if (sent) return { gated: true, sent: sent, passed: false, stoppedAt: names[i] };
    if (i === gateIdx && nexted) reachedGateNext = true;
  }

  return { gated: true, sent: sent, passed: reachedGateNext, req: req };
}

async function countsFor(userId) {
  const tasks = await supabase.from("ai_tasks").select("id", { count: "exact", head: true }).eq("user_id", userId);
  const calls = await supabase.from("model_calls").select("id", { count: "exact", head: true }).eq("user_id", userId);
  return { ai_tasks: tasks.count, model_calls: calls.count };
}

(async function main() {
  await residue.sweepPrevious(SUBJECT_USER_ID);

  /* CAN THESE CHECKS EVEN FAIL? A green suite that has never been seen red is
     a claim about itself, not about the code. MUTATE=ungate-one strips the
     gate layer off the first route in the list and runs everything unchanged;
     the refusal checks for that route must go red. Run it after any edit to
     this file. */
  if (process.env.MUTATE === "ungate-one") {
    const victim = layerFor(ROUTES[0].path, ROUTES[0].method);
    const idx = victim.route.stack.map(function (l) { return l.handle.name; }).indexOf("requireActiveSubscription");
    if (idx !== -1) {
      victim.route.stack.splice(idx, 1);
      console.log("\n!! MUTATION: requireActiveSubscription removed from " +
        ROUTES[0].method.toUpperCase() + " " + ROUTES[0].path + " — the checks below must fail.");
    }
  }

  console.log("\n══ subjects ══");

  /* Discovered, not hardcoded: a check that names ids inline goes quietly
     wrong the day somebody's subscription changes. */
  const usersResult = await supabase.from("users").select("id, email, role");
  if (usersResult.error) throw usersResult.error;
  const subsResult = await supabase.from("subscriptions").select("user_id, plan, status");
  if (subsResult.error) throw subsResult.error;

  const activeSubUserIds = (subsResult.data || [])
    .filter(function (r) { return ["active", "trialing"].indexOf(r.status) !== -1; })
    .map(function (r) { return r.user_id; });

  const unentitled = (usersResult.data || []).filter(function (u) { return u.id === SUBJECT_USER_ID; })[0];
  const paying = (usersResult.data || []).filter(function (u) {
    return activeSubUserIds.indexOf(u.id) !== -1 && String(u.role).toLowerCase() !== "admin";
  })[0];
  const admin = (usersResult.data || []).filter(function (u) {
    return String(u.role).toLowerCase() === "admin";
  })[0];

  if (!unentitled) { console.error("The subject account " + SUBJECT_USER_ID + " is not in users."); process.exit(1); }
  if (!paying) { console.error("No non-admin account with an active subscription to test the entitled path with."); process.exit(1); }
  if (!admin) { console.error("No account with role 'admin' to test the exemption with."); process.exit(1); }

  console.log("  unentitled : " + unentitled.id + "  (" + unentitled.email + ", role " + unentitled.role + ")");
  console.log("  paying     : " + paying.id + "  (" + paying.email + ", role " + paying.role + ")");
  console.log("  admin      : " + admin.id + "  (" + admin.email + ", role " + admin.role + ")");

  /* THE PREMISE IS CHECKED BEFORE THE CHECKS. If the "unentitled" account
     turned out to be entitled, every refusal below would be measuring
     nothing and still printing green. */
  console.log("\n══ the premises these checks rest on ══");
  const unentitledPlan = await getUserPlanSafely(unentitled);
  const payingPlan = await getUserPlanSafely(paying);
  const adminPlan = await getUserPlanSafely(admin);
  check("the unentitled account really is unentitled", unentitledPlan && unentitledPlan.active === false,
    unentitledPlan && ("active=" + unentitledPlan.active + " reason=" + unentitledPlan.inactive_reason));
  check("the paying account really is entitled, and not by exemption",
    payingPlan && payingPlan.active === true && payingPlan.exempt === false,
    payingPlan && ("active=" + payingPlan.active + " exempt=" + payingPlan.exempt));
  check("the admin account passes by exemption",
    adminPlan && adminPlan.active === true && adminPlan.exempt === true && adminPlan.access_reason === "admin",
    adminPlan && ("active=" + adminPlan.active + " exempt=" + adminPlan.exempt + " reason=" + adminPlan.access_reason));

  const before = {
    unentitled: await countsFor(unentitled.id),
    paying: await countsFor(paying.id),
    admin: await countsFor(admin.id)
  };
  console.log("\n══ row counts BEFORE ══");
  Object.keys(before).forEach(function (k) {
    console.log("  " + k.padEnd(11) + " ai_tasks: " + before[k].ai_tasks + "   model_calls: " + before[k].model_calls);
  });

  for (const route of ROUTES) {
    const label = route.method.toUpperCase() + " " + route.path;
    console.log("\n══ " + label + " ══");

    const names = chainNames(route.path, route.method);
    console.log("    layers: " + names.join(" → "));

    const gateIdx = names.indexOf("requireActiveSubscription");
    check("the route is gated at all", gateIdx !== -1, names.join(", "));
    if (gateIdx === -1) continue;

    /* Ahead of EVERYTHING else on the route, not merely present on it. */
    const after = names.slice(gateIdx + 1);
    const before_ = names.slice(0, gateIdx).filter(function (n) { return n !== "requireAuth"; });
    check("nothing but requireAuth runs before the gate", before_.length === 0, before_.join(", "));
    check("the handler is behind the gate", after.length >= 1, "layers after the gate: " + after.join(", "));

    const refused = await runToGate(route.path, route.method, unentitled);
    check("an unentitled account is refused", !!refused.sent && refused.sent.status === 402,
      refused.sent ? ("status " + refused.sent.status) : "nothing was sent; passed=" + refused.passed);
    check("the refusal says what to do about it",
      !!refused.sent && refused.sent.body && refused.sent.body.upgrade_required === true,
      refused.sent && JSON.stringify(refused.sent.body));
    check("the refusal came from the gate, not from something further on",
      refused.stoppedAt === "requireActiveSubscription", refused.stoppedAt);

    const paid = await runToGate(route.path, route.method, paying);
    check("a paying account passes the gate", paid.passed === true,
      paid.sent ? ("refused with " + paid.sent.status + " " + JSON.stringify(paid.sent.body)) : ("passed=" + paid.passed));

    const owner = await runToGate(route.path, route.method, admin);
    check("an admin passes the gate", owner.passed === true,
      owner.sent ? ("refused with " + owner.sent.status + " " + JSON.stringify(owner.sent.body)) : ("passed=" + owner.passed));
    check("and passes as exempt rather than as a subscriber",
      !!owner.req && owner.req.planExempt === true && owner.req.planAccessReason === "admin",
      owner.req && ("exempt=" + owner.req.planExempt + " reason=" + owner.req.planAccessReason));
  }

  console.log("\n══ nothing was spent ══");
  check("no model call was attempted by any of it", modelCallsAttempted.length === 0, modelCallsAttempted.join(", "));

  const after = {
    unentitled: await countsFor(unentitled.id),
    paying: await countsFor(paying.id),
    admin: await countsFor(admin.id)
  };
  console.log("\n══ row counts AFTER ══");
  Object.keys(after).forEach(function (k) {
    console.log("  " + k.padEnd(11) + " ai_tasks: " + after[k].ai_tasks + "   model_calls: " + after[k].model_calls +
      "   (delta " + (after[k].ai_tasks - before[k].ai_tasks) + " / " + (after[k].model_calls - before[k].model_calls) + ")");
  });
  Object.keys(after).forEach(function (k) {
    check(k + ": zero ai_tasks rows written", after[k].ai_tasks === before[k].ai_tasks,
      before[k].ai_tasks + " → " + after[k].ai_tasks);
    check(k + ": zero model_calls rows written", after[k].model_calls === before[k].model_calls,
      before[k].model_calls + " → " + after[k].model_calls);
  });

  console.log("");
  const cleanupResult = await residue.cleanup("end of run");
  const leftovers = cleanupResult.leftovers.map(function (l) { return l.table + ": " + l.ids.join(", "); });
  if (leftovers.length) failures++;

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
})();

/* getUserPlan lives in server.js's module scope and is not exported, so the
   premise checks reach it the same way the gate does: by running the gate and
   reading what it put on the request. A refusal is reported as the plan state
   it implies rather than guessed at. */
async function getUserPlanSafely(user) {
  const probe = await runToGate("/api/oracle/chat", "post", user);
  if (probe.sent && probe.sent.status === 402) {
    return { active: false, exempt: false, inactive_reason: probe.sent.body && probe.sent.body.reason, access_reason: null };
  }
  if (probe.passed && probe.req) {
    return { active: true, exempt: probe.req.planExempt === true, inactive_reason: null, access_reason: probe.req.planAccessReason };
  }
  return null;
}
