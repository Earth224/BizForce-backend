/* ══════════════════════════════════════════════════════════════════════════
   checkAuthMeShape.js — what GET /api/auth/me returns, pinned.

   REPLACES auth-me.test.js. That harness was written to verify the September
   11 change that added `access` to this response, by comparing the committed
   HEAD with the working copy. Once the change was committed, HEAD and the
   working copy were the same code, so it compared the route with itself and
   failed 4 of 9 on a clean tree. A differential only means something while
   its change is uncommitted.

   THIS IS A CHARACTERISATION CHECK. It asserts what the route returns today,
   not what changed:
     1. the top-level keys are exactly access, profile, subscription, user
     2. the user object's keys are EXACTLY the pinned list below. An added or
        removed field turns this red, which is the point: the user object feeds
        dashboard.html, billing.html and bf_user, and a shape change should be
        a decision someone makes on purpose, recorded by editing this list
     3. subscription_status, subscription_plan and subscription_active follow
        the subscriptions row: "free" / "free" / false with no row
     4. access carries exactly active, exempt, access_reason, inactive_reason
     5. access is null, not false, when getUserPlan throws or returns nothing,
        with one log line naming the user, and the rest of the response intact
     6. the same shape comes back for a real account, read live: the subject's
        users row selected with the exact column list requireAuth uses (parsed
        from requireAuth's own source, so it follows that code), and its real
        profile and subscription rows. Read-only.

   Cases 1-5 run the route out of the source in a vm with the three lookups
   stubbed. Case 6 runs it against the real database. Nothing is written.

   MUTATE=add-field adds a field to publicUser. Assertion 2 must go red.
   MUTATE=drop-field removes banned_at from publicUser. Assertion 2 must go red.
   The mutations are applied to the extracted source, never to server.js.
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const { createResidueGuard, resolveSubjectAccount } = require("./checkRunResidue");
const SUBJECT_USER_ID = resolveSubjectAccount();

const fs = require("fs");
const vm = require("vm");
const path = require("path");
const { braceMatch } = require("./_shared");
const REPO = path.join(__dirname, "..");

const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY
);

/* Nothing here writes. The guard is installed for its exit handling and its
   final read-back, with no table of its own to clean. */
const residue = createResidueGuard({ supabase: supabase, name: "authMeShape", subject: SUBJECT_USER_ID, tables: [] });
residue.install();

const MUTATIONS = ["add-field", "drop-field"];
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

/* ── THE PINNED SHAPE ─────────────────────────────────────────────────────
   Change these lists when the response changes on purpose, in the same
   commit as the change. */
const TOP_KEYS = ["access", "profile", "subscription", "user"];
const USER_KEYS = ["banned_at", "created_at", "email", "id", "role", "subscription_active", "subscription_plan", "subscription_status"];
const ACCESS_KEYS = ["access_reason", "active", "exempt", "inactive_reason"];

/* ── the route, out of the source ─────────────────────────────────────────── */
const SRC = fs.readFileSync(path.join(REPO, "server.js"), "utf8");

function routeSource(src) {
  const sig = 'app.get("/api/auth/me"';
  const start = src.indexOf(sig);
  if (start < 0) throw new Error("GET /api/auth/me not found");
  const end = braceMatch(src, src.indexOf("{", start + sig.length));
  if (src.slice(end, end + 2) !== ");") throw new Error("the route did not end where expected");
  return src.slice(start, end + 2);
}
function functionSource(src, name) {
  const m = new RegExp("^(?:async )?function " + name + "\\(", "m").exec(src);
  if (!m) throw new Error("function " + name + " was not found");
  return src.slice(m.index, braceMatch(src, src.indexOf(") {", m.index) + 2));
}
function mutate(src, from, to) {
  if (src.split(from).length !== 2) throw new Error("mutation target not found exactly once: " + from);
  return src.replace(from, to);
}

let PUBLIC_USER = functionSource(SRC, "publicUser");
if (MUTATE === "add-field") PUBLIC_USER = mutate(PUBLIC_USER, "    id: user.id,", "    id: user.id,\n    mutated_extra_field: true,");
if (MUTATE === "drop-field") PUBLIC_USER = mutate(PUBLIC_USER, "    banned_at: user.banned_at || null,", "");

/* The users columns requireAuth selects, read from requireAuth itself. */
const REQUIRE_AUTH = functionSource(SRC, "requireAuth");
/* Anchored on the .select("...") string: requireAuth's comments also say
   "users(id)", and matching the first users( would read that instead. */
const embed = /\.select\("[^"]*\busers\(([^)]*)\)[^"]*"\)/.exec(REQUIRE_AUTH);
if (!embed) throw new Error("could not find requireAuth's users(...) embed");
const REQUIRE_AUTH_USER_COLUMNS = embed[1];

function build(lookups) {
  let handler = null;
  const logs = [];
  const ctx = Object.assign({
    console: { log: function (m) { logs.push(String(m)); }, error: function (m) { logs.push(String(m)); }, warn: function (m) { logs.push(String(m)); } },
    requireAuth: 0,
    app: { get: function () { handler = arguments[arguments.length - 1]; } }
  }, lookups);
  vm.createContext(ctx);
  vm.runInContext(PUBLIC_USER + "\n\n" + routeSource(SRC), ctx);
  if (!handler) throw new Error("handler not captured");
  return { handler: handler, logs: logs };
}

async function call(handler, user) {
  const res = { statusCode: 200, body: undefined,
    status: function (c) { this.statusCode = c; return this; },
    json: function (b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
  let nextErr = null;
  await handler({ user: user }, res, function (e) { nextErr = e || new Error("next() called"); });
  return { status: res.statusCode, body: res.body, nextErr: nextErr };
}

const keys = function (o) { return o && typeof o === "object" ? Object.keys(o).sort() : null; };
const same = function (a, b) { return JSON.stringify(a) === JSON.stringify(b); };

const USER = { id: "u-shape", email: "shape@example.invalid", role: "user", banned_at: null, created_at: "2026-09-01T00:00:00.000Z" };
const PROFILE = { id: "u-shape", user_id: "u-shape", business_name: "Shape Co" };
const PLAN_OK = { active: true, exempt: false, access_reason: "subscription", inactive_reason: null, plan: "all_access" };

function shapeChecks(tag, r) {
  check(tag + " answers 200 without calling next", r.status === 200 && !r.nextErr, r.nextErr ? String(r.nextErr.message) : r.status);
  check(tag + " top-level keys are exactly " + TOP_KEYS.join(", "), same(keys(r.body), TOP_KEYS), JSON.stringify(keys(r.body)));
  check(tag + " user keys are exactly the pinned list", same(keys(r.body && r.body.user), USER_KEYS),
    "got " + JSON.stringify(keys(r.body && r.body.user)));
}

(async function main() {
  await residue.sweepPrevious(SUBJECT_USER_ID);
  console.log("\n══ source under test: " + (MUTATE ? "MUTATED (" + MUTATE + ")" : "server.js as it stands") + " ══");
  console.log("    pinned user keys: " + USER_KEYS.join(", "));
  console.log("    requireAuth selects users(" + REQUIRE_AUTH_USER_COLUMNS + ")");

  try {
    console.log("\n══ 1-4. an active subscription ══");
    const active = build({
      getProfileByUserId: async function () { return PROFILE; },
      getActiveSubscription: async function () { return { user_id: "u-shape", status: "active", plan: "All_Access" }; },
      getUserPlan: async function () { return PLAN_OK; }
    });
    const rA = await call(active.handler, USER);
    shapeChecks("1-2.", rA);
    check("3. subscription fields follow the row (status active, plan lower-cased, active true)",
      rA.body && rA.body.user.subscription_status === "active" && rA.body.user.subscription_plan === "all_access" && rA.body.user.subscription_active === true,
      JSON.stringify(rA.body && rA.body.user));
    check("4. access carries exactly " + ACCESS_KEYS.join(", "), same(keys(rA.body && rA.body.access), ACCESS_KEYS), JSON.stringify(keys(rA.body && rA.body.access)));
    check("4. and nothing extra from getUserPlan leaks into it (plan is not copied)", rA.body && rA.body.access && rA.body.access.plan === undefined);
    check("the user fields come from req.user unchanged", rA.body && rA.body.user.id === USER.id && rA.body.user.email === USER.email && rA.body.user.role === "user");

    console.log("\n══ 3. no subscription row ══");
    const none = build({
      getProfileByUserId: async function () { return PROFILE; },
      getActiveSubscription: async function () { return null; },
      getUserPlan: async function () { return { active: false, exempt: false, access_reason: null, inactive_reason: "no_subscription" }; }
    });
    const rN = await call(none.handler, USER);
    shapeChecks("3.", rN);
    check("3. no row: subscription null, status \"free\", plan \"free\", active false",
      rN.body && rN.body.subscription === null && rN.body.user.subscription_status === "free" && rN.body.user.subscription_plan === "free" && rN.body.user.subscription_active === false,
      JSON.stringify(rN.body && rN.body.user));

    for (const [label, planFn] of [["throws", async function () { throw new Error("plan-db-down"); }], ["returns nothing", async function () { return null; }]]) {
      console.log("\n══ 5. getUserPlan " + label + " ══");
      const h = build({
        getProfileByUserId: async function () { return PROFILE; },
        getActiveSubscription: async function () { return { status: "active", plan: "all_access" }; },
        getUserPlan: planFn
      });
      const r = await call(h.handler, USER);
      shapeChecks("5.", r);
      check("5. access is null, not false", r.body && r.body.access === null, JSON.stringify(r.body && r.body.access));
      check("5. exactly one log line, naming the user", h.logs.length === 1 && h.logs[0].indexOf(USER.id) !== -1, JSON.stringify(h.logs));
    }

    console.log("\n══ 6. a real account, read live ══");
    const liveUser = await supabase.from("users").select(REQUIRE_AUTH_USER_COLUMNS).eq("id", SUBJECT_USER_ID).single();
    if (liveUser.error) throw new Error("could not read the subject as requireAuth would: " + liveUser.error.message);
    /* The two real lookups, extracted and bound to the real client. */
    const lookCtx = { supabase: supabase };
    vm.createContext(lookCtx);
    vm.runInContext(functionSource(SRC, "getProfileByUserId") + "\n" + functionSource(SRC, "getActiveSubscription"), lookCtx);
    const liveHandler = build({
      getProfileByUserId: lookCtx.getProfileByUserId,
      getActiveSubscription: lookCtx.getActiveSubscription,
      getUserPlan: async function () { return PLAN_OK; }
    }).handler;
    const rL = await call(liveHandler, liveUser.data);
    console.log("    req.user as requireAuth builds it: " + JSON.stringify(keys(liveUser.data)));
    console.log("    live user object keys: " + JSON.stringify(keys(rL.body && rL.body.user)));
    shapeChecks("6.", rL);
    check("6. and the account is the subject", rL.body && rL.body.user.id === SUBJECT_USER_ID, rL.body && rL.body.user.id);
  } finally {
    console.log("\n══ cleanup ══");
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
