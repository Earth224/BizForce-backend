/* ══════════════════════════════════════════════════════════════════════════
   checkOpenSurfaceClosed.js — POST /api/sms/send stays shut.

   THE DEFECT. POST /api/sms/send sent any message to any number through the
   company Twilio number for any signed-in account: no subscription, no
   limiter, no verified email, and an unknown number was sent to regardless of
   consent. It wrote nothing to the database. It is behind
   SMS_DIRECT_SEND_ENABLED = false.

   WHAT THIS PROVES
     1. sms/send answers 503 "Direct SMS sending is unavailable." and never
        reaches Twilio — the Twilio client is a recorder, and the Twilio
        credentials are set, so an open route WOULD call it.

   WHAT THIS NO LONGER CHECKS — AND WHY
     - GET /api/search/businesses. f045991 quoted its q so it could not be
       read as PostgREST filter syntax, and this script proved that. The route
       was then DELETED, with twenty other routes no page ever called, in the
       commit "Delete twenty-one routes no page has ever called";
       scripts/checkDormantRoutesDeleted.js proves it answers 404. There is
       nothing left here to harden.
     - POST /api/follow and GET /api/feed were never checked here: both were
       broken against the schema of the time (follows had no created_at; posts
       had no foreign key to profiles and lacked media_url, post_type,
       updated_at). Both routes were deleted in af4d434, and the follows and
       posts tables were dropped by migration 123.

   MUTATE=sms-open  runs sms/send as it was at 8092a1c. 1 must go red.
   The mutation is applied to extracted source, never to server.js.
   Nothing here writes to the database; the ungated route's consent lookups
   are reads.
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const { resolveSubjectAccount } = require("./checkRunResidue");
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

const MUTATIONS = ["sms-open"];
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
    app: { post: function () { handler = arguments[arguments.length - 1]; } }
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

const R_SMS = routeSource(MUTATE === "sms-open" ? SRC_OLD : SRC_NOW, "post", "/api/sms/send");

(async function main() {
  console.log("\n══ route under test: " + (MUTATE ? "MUTATED (" + MUTATE + ")" : "server.js as it stands") + " ══");
  console.log("\n══ 1. POST /api/sms/send ══");
  const twilioCalls = [];
  const smsHandler = build(R_SMS, {
    supabase: supabase,
    process: { env: { TWILIO_ACCOUNT_SID: "ACcheck", TWILIO_AUTH_TOKEN: "check", TWILIO_PHONE_NUMBER: "+15005550006" } },
    twilio: function () { return { messages: { create: async function (o) { twilioCalls.push(o); return { sid: "SMcheck", status: "queued" }; } } }; }
  });
  const s1 = await call(smsHandler, { body: { to: "+15005550009", message: "check message " + crypto.randomBytes(4).toString("hex") } });
  console.log("    HTTP " + s1.status + " " + JSON.stringify(s1.body || (s1.nextErr && s1.nextErr.message)) + " | Twilio calls: " + twilioCalls.length);
  check("1. answers 503 \"Direct SMS sending is unavailable.\"", s1.status === 503 && s1.body && s1.body.error === "Direct SMS sending is unavailable.", s1.status + " " + JSON.stringify(s1.body));
  check("1. and never reaches Twilio", twilioCalls.length === 0, twilioCalls.length + " call(s)");

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
})().catch(function (err) {
  console.error("\nThe check threw: " + ((err && err.stack) || err));
  process.exit(1);
});
