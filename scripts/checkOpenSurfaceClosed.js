/* ══════════════════════════════════════════════════════════════════════════
   checkOpenSurfaceClosed.js — two live endpoints with no UI stay closed.

   THE DEFECTS
     - POST /api/sms/send sent any message to any number through the company
       Twilio number for any signed-in account: no subscription, no limiter,
       no verified email, and an unknown number was sent to regardless of
       consent. It wrote nothing to the database. It is now behind
       SMS_DIRECT_SEND_ENABLED = false.
     - GET /api/search/businesses interpolated q into a PostgREST .or(...), so
       q could add its own conditions: measured, a crafted q returned every
       public profile for a term that matches none. It is now a quoted value.

   WHAT THIS PROVES, against the live database, on the subject account only:
     1. sms/send answers 503 "Direct SMS sending is unavailable." and never
        reaches Twilio — the Twilio client is a recorder, and the Twilio
        credentials are set, so an open route WOULD call it.
     2. Search: with the subject's profile private, neither its own name nor a
        crafted q returns it; a crafted q is matched as literal text (0 rows);
        and with the profile public, an ordinary search by name still finds
        it.

   WHAT THIS DELIBERATELY DOES NOT CHECK — AND WHY
     An earlier draft of this script also asserted that POST /api/follow
     notifies only on a new follow and that GET /api/feed hides posts from
     private profiles. Both were removed, not left red, because both ROUTES ARE
     BROKEN AGAINST THE LIVE SCHEMA and have never worked:
       - follows has no created_at column. POST /api/follow writes it, and
         GET /api/followers and /following order by it, so all three fail
         (PGRST204 / 42703) on every call. The "New follower" notification
         after the write has therefore never been reached.
       - there is no foreign key between posts and profiles, so GET /api/feed's
         embed profile:profiles(...) fails with PGRST200 on every call. And
         posts has only id, user_id, content, created_at, so POST /api/posts
         (media_url, post_type, updated_at) fails too.
     Making them work is a product decision about the dormant social feature,
     not a security fix, so neither route was changed. If they are ever
     brought back, the follow notification must fire once per NEW follow
     (insert, and treat 23505 on follows_pkey as "already following"), and the
     feed must apply the search route's .eq("profile_visibility", "public").

   MUTATE=sms-open             runs sms/send as it was at 8092a1c. 1 must go red.
   MUTATE=search-interpolated  runs search as it was at 8092a1c. 2 must go red.
   Each touches only its own route; mutations are applied to extracted source.

   RESTORED AFTERWARDS: the subject's profile_visibility, business_name and
   updated_at are read first and written back, then read back.
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const { createResidueGuard, resolveSubjectAccount } = require("./checkRunResidue");
const SUBJECT_USER_ID = resolveSubjectAccount();

const fs = require("fs");
const vm = require("vm");
const path = require("path");
const crypto = require("crypto");
const { execSync } = require("child_process");
const { braceMatch } = require("./_shared");
const REPO = path.join(__dirname, "..");

const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY
);

/* This run creates no rows: it only updates the subject's own profile and
   puts it back. The guard is installed for its read-back and exit handling. */
const residue = createResidueGuard({ supabase: supabase, name: "openSurfaceClosed", subject: SUBJECT_USER_ID, tables: [] });
residue.install();

const MUTATIONS = ["sms-open", "search-interpolated"];
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

/* ── the routes, lifted ──────────────────────────────────────────────────── */
const BEFORE = "8092a1c";
const SRC_NOW = fs.readFileSync(path.join(REPO, "server.js"), "utf8");
const SRC_OLD = execSync("git show " + BEFORE + ":server.js", { cwd: REPO, maxBuffer: 64 * 1024 * 1024 }).toString("utf8");

function routeSource(src, method, route) {
  const sig = "app." + method + '("' + route + '"';
  const start = src.indexOf(sig);
  if (start < 0) throw new Error("route not found: " + route);
  const end = braceMatch(src, src.indexOf("{", src.indexOf("async function", start)));
  if (src.slice(end, end + 2) !== ");") throw new Error("route did not end where expected: " + route);
  return src.slice(start, end + 2);
}
function functionSource(src, name) {
  const m = new RegExp("^(?:async )?function " + name + "\\(", "m").exec(src);
  if (!m) throw new Error("function " + name + " was not found");
  return src.slice(m.index, braceMatch(src, src.indexOf(") {", m.index) + 2));
}

function build(route, ctxExtra) {
  let handler = null;
  const ctx = Object.assign({
    console: { log: function () {}, warn: function () {}, error: function () {} },
    requireAuth: 0,
    // smsConsentFromLedger reads the owner's consent ledger (read-only); without
    // this an ungated sms/send stops at that lookup instead of reaching Twilio.
    CAPTURE_OWNER_ID: require("../lib/ownerAccount").OWNER_ACCOUNT_ID,
    app: {
      get: function () { handler = arguments[arguments.length - 1]; },
      post: function () { handler = arguments[arguments.length - 1]; }
    }
  }, ctxExtra);
  vm.createContext(ctx);
  const helpers = ["nowIso", "safeText", "canonicalPhone", "smsConsentFromLedger"].map(function (n) { return functionSource(SRC_NOW, n); }).join("\n\n");
  const gate = /^const SMS_DIRECT_SEND_ENABLED = (true|false);$/m.exec(SRC_NOW);
  vm.runInContext(helpers + "\n\n" + (gate ? gate[0] : "") + "\n\n" + route, ctx);
  if (!handler) throw new Error("handler not captured");
  return handler;
}

async function call(handler, req) {
  const res = { statusCode: 200, body: undefined,
    status: function (c) { this.statusCode = c; return this; },
    json: function (b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
  let nextErr = null;
  await handler(Object.assign({ user: { id: SUBJECT_USER_ID }, body: {}, params: {}, query: {}, headers: {}, get: function () { return ""; } }, req), res,
    function (e) { nextErr = e || new Error("next() called"); });
  return { status: nextErr ? 500 : res.statusCode, body: res.body, nextErr: nextErr };
}

const R_SMS    = routeSource(MUTATE === "sms-open" ? SRC_OLD : SRC_NOW, "post", "/api/sms/send");
const R_SEARCH = routeSource(MUTATE === "search-interpolated" ? SRC_OLD : SRC_NOW, "get", "/api/search/businesses");

/* ── the subject's profile, the only thing this run changes ─────────────── */
async function profileRow() {
  const r = await supabase.from("profiles").select("id, profile_visibility, business_name, updated_at").eq("user_id", SUBJECT_USER_ID).single();
  if (r.error) throw new Error("could not read the subject's profile: " + r.error.message);
  return r.data;
}
async function setProfile(fields) {
  const r = await supabase.from("profiles").update(fields).eq("user_id", SUBJECT_USER_ID);
  if (r.error) throw new Error("could not set the subject's profile: " + r.error.message);
}

(async function main() {
  await residue.sweepPrevious(SUBJECT_USER_ID);
  const ORIGINAL = await profileRow();
  const stamp = crypto.randomBytes(4).toString("hex");
  const MARK = "zzcheck" + stamp;          // a name no other profile carries
  console.log("\n══ subject profile before: " + JSON.stringify({ visibility: ORIGINAL.profile_visibility, business_name: ORIGINAL.business_name }) + " ══");
  console.log("══ routes under test: " + (MUTATE ? "MUTATED (" + MUTATE + ")" : "server.js as it stands") + " ══");

  try {
    /* ── 1. sms/send ─────────────────────────────────────────────────── */
    console.log("\n══ 1. POST /api/sms/send ══");
    const twilioCalls = [];
    const smsHandler = build(R_SMS, {
      supabase: supabase,
      process: { env: { TWILIO_ACCOUNT_SID: "ACcheck", TWILIO_AUTH_TOKEN: "check", TWILIO_PHONE_NUMBER: "+15005550006" } },
      twilio: function () { return { messages: { create: async function (o) { twilioCalls.push(o); return { sid: "SMcheck", status: "queued" }; } } }; }
    });
    const s1 = await call(smsHandler, { body: { to: "+15005550009", message: "check message " + stamp } });
    console.log("    HTTP " + s1.status + " " + JSON.stringify(s1.body || (s1.nextErr && s1.nextErr.message)) + " | Twilio calls: " + twilioCalls.length);
    check("1. answers 503 \"Direct SMS sending is unavailable.\"", s1.status === 503 && s1.body && s1.body.error === "Direct SMS sending is unavailable.", s1.status + " " + JSON.stringify(s1.body));
    check("1. and never reaches Twilio", twilioCalls.length === 0, twilioCalls.length + " call(s)");

    /* ── 2. search ───────────────────────────────────────────────────── */
    console.log("\n══ 2. GET /api/search/businesses ══");
    const searchHandler = build(R_SEARCH, { supabase: supabase });
    await setProfile({ business_name: MARK, profile_visibility: "private" });
    const CRAFTED = "zzqq,id.not.is.null,business_name.ilike.zz";
    const byName  = await call(searchHandler, { query: { q: MARK } });
    const crafted = await call(searchHandler, { query: { q: CRAFTED } });
    const hasSubject = function (r) { return !!(r.body && r.body.businesses && r.body.businesses.find(function (b) { return b.user_id === SUBJECT_USER_ID; })); };
    console.log("    profile private — by its own name: " + (byName.body ? byName.body.businesses.length + " rows" : "HTTP " + byName.status) +
      " | crafted q: " + (crafted.body && crafted.body.businesses ? crafted.body.businesses.length + " rows" : "HTTP " + crafted.status));
    check("2. a private profile is not returned by its own name", byName.status === 200 && !hasSubject(byName), byName.status);
    check("2. nor by a crafted q", !hasSubject(crafted), crafted.status);
    check("2. a crafted q is matched as literal text (0 rows), not as filter syntax",
      crafted.status === 200 && crafted.body.businesses.length === 0, crafted.status + " " + (crafted.body && crafted.body.businesses ? crafted.body.businesses.length + " rows" : ""));
    await setProfile({ profile_visibility: "public" });
    const ordinary = await call(searchHandler, { query: { q: MARK.slice(0, 11) } });
    console.log("    profile public — ordinary search by name: " + (ordinary.body ? ordinary.body.businesses.length + " rows" : "HTTP " + ordinary.status));
    check("2. an ordinary search by name still finds a public profile", ordinary.status === 200 && hasSubject(ordinary), ordinary.status);
  } finally {
    console.log("\n══ cleanup ══");
    const put = await supabase.from("profiles").update({ profile_visibility: ORIGINAL.profile_visibility, business_name: ORIGINAL.business_name, updated_at: ORIGINAL.updated_at }).eq("user_id", SUBJECT_USER_ID);
    const back = await profileRow();
    const profOk = !put.error && back.profile_visibility === ORIGINAL.profile_visibility && back.business_name === ORIGINAL.business_name && Date.parse(back.updated_at) === Date.parse(ORIGINAL.updated_at);
    console.log("    [fixture] profile put back (" + ORIGINAL.profile_visibility + ", " + JSON.stringify(ORIGINAL.business_name) + "): " + (profOk ? "yes" : "NO"));
    if (!profOk) failures++;
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
