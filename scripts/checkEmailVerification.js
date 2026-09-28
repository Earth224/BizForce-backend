/* ══════════════════════════════════════════════════════════════════════════
   checkEmailVerification.js — the verification email is sent, and the link
   records something when it is used.

   THE DEFECT. Registration minted email_verification_token and stored it on
   every signup, and nothing sent it, so POST /api/auth/verify-email could not
   be reached. And when it was called it cleared the token and answered success
   without recording anything: email_verified was stripped in April because no
   migration had created it. Migration 122 added email_verified_at and
   email_verification_expires_at.

   WHAT THIS PROVES
     1. Registration stores a token AND an expiry, one hour out (the reset
        path's window).
     2. Registration attempts a send, with the token in the link.
     3. A send failure does not fail registration: the user is created and the
        response is unchanged, whether sendEmail reports failure or throws.
        The response is compared with the pre-change route's (66e6c64).
     4. A valid token sets email_verified_at, clears the token and its expiry,
        and leaves verification_status untouched.
     5. A wrong token, and an already-used one, error and change nothing.
     6. An expired token is rejected, with a message distinct from an invalid
        one, and changes nothing.
     7. A token with a NULL expiry is rejected. That is every account created
        before migration 122.

   TWO HALVES, BECAUSE REGISTRATION WOULD SEND REAL MAIL.
   Registration (1-3) runs out of the source in a vm against a recording fake
   Supabase with sendEmail stubbed: no account is created and nothing is
   mailed. verify-email (4-7) runs out of the source in a vm against the REAL
   database, on the subject account's users row only. Every value it changes
   there is read first and written back at the end, then read back again.

   MUTATE=no-send         replaces the sendEmail call with a no-op. 2 must go red.
   MUTATE=old-verify      runs verify-email from 66e6c64. 4 must go red.
   MUTATE=no-expiry-check removes the expiry refusal. 6 and 7 must go red.
   The mutations are applied to the extracted source, never to server.js.
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

/* This run creates no rows: registration runs against a fake, and the
   verify-email half only updates the subject's existing users row and puts it
   back. The guard is installed for its final read-back and its exit handling,
   with nothing of its own to delete. */
const residue = createResidueGuard({ supabase: supabase, name: "emailVerification", subject: SUBJECT_USER_ID, tables: [] });
residue.install();

const MUTATIONS = ["no-send", "old-verify", "no-expiry-check"];
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

/* ── the source, now and before ──────────────────────────────────────────── */
const BEFORE = "66e6c64";
const SRC_NOW = fs.readFileSync(path.join(REPO, "server.js"), "utf8");
const SRC_OLD = execSync("git show " + BEFORE + ":server.js", { cwd: REPO, maxBuffer: 64 * 1024 * 1024 }).toString("utf8");

function routeSource(src, route) {
  const sig = 'app.post("' + route + '"';
  const start = src.indexOf(sig);
  if (start < 0) throw new Error("route not found: " + route);
  const end = braceMatch(src, src.indexOf("{", start + sig.length));
  if (src.slice(end, end + 2) !== ");") throw new Error("route did not end where expected: " + route);
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

const HELPERS = ["nowIso", "safeText", "normalizeEmail", "normalizeUrl", "normalizeUsername", "publicUser"]
  .map(function (n) { return functionSource(SRC_NOW, n); }).join("\n\n");

function capture(source, extra) {
  let handler = null;
  const logs = [];
  const ctx = Object.assign({
    console: { log: function (m) { logs.push(String(m)); }, warn: function (m) { logs.push(String(m)); }, error: function (m) { logs.push(String(m)); } },
    authLimiter: 0,
    app: { post: function () { handler = arguments[arguments.length - 1]; } }
  }, extra);
  vm.createContext(ctx);
  vm.runInContext(HELPERS + "\n\n" + source, ctx);
  if (!handler) throw new Error("handler not captured");
  return { handler: handler, logs: logs };
}

async function call(handler, body) {
  const res = { statusCode: 200, body: undefined,
    status: function (c) { this.statusCode = c; return this; },
    json: function (b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
  let nextErr = null;
  await handler({ body: body, ip: "127.0.0.1", headers: {} }, res, function (e) { nextErr = e || new Error("next() called"); });
  return { status: res.statusCode, body: res.body, nextErr: nextErr };
}

/* ── part one: registration, against a recording fake ────────────────────── */
function fakeDb() {
  const inserts = [];
  function builder(table) {
    const st = { table: table, op: "select", payload: null };
    const q = {
      select: function () { return q; }, eq: function () { return q; }, limit: function () { return q; },
      insert: function (p) { st.op = "insert"; st.payload = p; inserts.push({ table: table, payload: p }); return q; },
      update: function (p) { st.op = "update"; st.payload = p; return q; },
      maybeSingle: async function () { return { data: st.op === "insert" ? rowFor(st) : null, error: null }; },
      single: async function () { return { data: rowFor(st), error: null }; },
      then: function (r) { return Promise.resolve({ data: null, error: null }).then(r); }
    };
    return q;
  }
  function rowFor(st) {
    if (st.table === "users") return { id: "user-new", email: st.payload.email, role: "user", banned_at: null, created_at: "2026-09-28T00:00:00.000Z" };
    if (st.table === "profiles") return Object.assign({}, st.payload);
    return null;
  }
  return { client: { from: builder }, inserts: inserts };
}

function buildRegister(source, sendBehaviour) {
  const db = fakeDb();
  const sends = [];
  const cap = capture(source, {
    supabase: db.client,
    crypto: crypto,
    bcrypt: { hash: async function () { return "hashed"; } },
    FRONTEND_URL: "https://bizforceai.net",
    findOrCreateUserContact: async function () { return "contact-1"; },
    createSession: async function () { return { sessionId: "sid-1", refreshToken: "refresh-1" }; },
    createToken: function () { return "jwt-1"; },
    sendEmail: async function (opts) {
      sends.push(opts);
      if (sendBehaviour === "throws") throw new Error("provider exploded");
      if (sendBehaviour === "fails") return { sent: false, reason: "provider_error" };
      return { sent: true, id: "send-1" };
    }
  });
  return { handler: cap.handler, logs: cap.logs, db: db, sends: sends };
}

const REG_BODY = { email: "Check.Person@example.invalid", password: "long-enough-password", business_name: "Check Business" };
const shape = function (r) { return JSON.stringify({ status: r.status, keys: Object.keys(r.body || {}).sort(), email_verification_required: r.body && r.body.email_verification_required, token: r.body && r.body.token, refresh_token: r.body && r.body.refresh_token }); };

/* ── part two: verify-email, against the subject's real row ─────────────── */
const COLS = "id, email_verification_token, email_verification_expires_at, email_verified_at, verification_status, updated_at";
let ORIGINAL = null;

async function readSubject() {
  const r = await supabase.from("users").select(COLS).eq("id", SUBJECT_USER_ID).single();
  if (r.error) throw new Error("could not read the subject row: " + r.error.message);
  return r.data;
}
async function setSubject(values) {
  const r = await supabase.from("users").update(values).eq("id", SUBJECT_USER_ID);
  if (r.error) throw new Error("could not set the subject row: " + r.error.message);
}
async function restoreSubject() {
  if (!ORIGINAL) return true;
  await supabase.from("users").update({
    email_verification_token: ORIGINAL.email_verification_token,
    email_verification_expires_at: ORIGINAL.email_verification_expires_at,
    email_verified_at: ORIGINAL.email_verified_at,
    verification_status: ORIGINAL.verification_status,
    updated_at: ORIGINAL.updated_at
  }).eq("id", SUBJECT_USER_ID);
  const back = await readSubject();
  return JSON.stringify(back) === JSON.stringify(ORIGINAL);
}
const snap = function (row) { const c = Object.assign({}, row); delete c.updated_at; return JSON.stringify(c); };
const newToken = function () { return "check_" + crypto.randomBytes(24).toString("hex"); };

(async function main() {
  await residue.sweepPrevious(SUBJECT_USER_ID);
  console.log("\n══ source under test: " + (MUTATE ? "MUTATED (" + MUTATE + ")" : "server.js as it stands") + " ══");

  /* ── 1-3 registration ─────────────────────────────────────────────────── */
  let regSrc = routeSource(SRC_NOW, "/api/auth/register");
  if (MUTATE === "no-send") regSrc = mutate(regSrc, "await sendEmail({", "await (async function () { return null; })({");

  console.log("\n══ 1. registration stores a token and an expiry ══");
  const ok = buildRegister(regSrc, "sends");
  const before = Date.now();
  const okRes = await call(ok.handler, REG_BODY);
  const userInsert = (ok.db.inserts.find(function (i) { return i.table === "users"; }) || {}).payload || {};
  const expMs = Date.parse(userInsert.email_verification_expires_at || "");
  console.log("    HTTP " + okRes.status + " | token " + (userInsert.email_verification_token ? "set (" + String(userInsert.email_verification_token).length + " chars)" : "absent") + " | expires " + userInsert.email_verification_expires_at);
  check("1. a token is stored", /^[0-9a-f]{64}$/.test(String(userInsert.email_verification_token || "")), String(userInsert.email_verification_token));
  check("1. with an expiry one hour out", Number.isFinite(expMs) && Math.abs(expMs - (before + 3600000)) < 10000,
    "expiry " + userInsert.email_verification_expires_at);

  console.log("\n══ 2. registration sends the link ══");
  const s = ok.sends[0] || {};
  const link = "https://bizforceai.net/verify-email?token=" + encodeURIComponent(userInsert.email_verification_token || "");
  console.log("    sends attempted: " + ok.sends.length + (s.template ? " | template " + s.template + " | subject " + JSON.stringify(s.subject) : ""));
  check("2. one send is attempted", ok.sends.length === 1, ok.sends.length + " sends");
  check("2. with the token in the link, in both the html and the text",
    ok.sends.length === 1 && String(s.html).indexOf(link) !== -1 && String(s.text).indexOf(link) !== -1, link);
  check("2. as template email_verification, skipConsentCheck, to the new address, attributed to the contact",
    s.template === "email_verification" && s.skipConsentCheck === true && s.to === "check.person@example.invalid" && s.contactId === "contact-1",
    JSON.stringify({ template: s.template, skip: s.skipConsentCheck, to: s.to, contact: s.contactId }));

  console.log("\n══ 3. a failed send does not fail registration ══");
  const old = buildRegister(routeSource(SRC_OLD, "/api/auth/register"), "sends");
  const oldRes = await call(old.handler, REG_BODY);
  for (const behaviour of ["fails", "throws"]) {
    const f = buildRegister(regSrc, behaviour);
    const fRes = await call(f.handler, REG_BODY);
    const created = f.db.inserts.some(function (i) { return i.table === "users"; });
    const logged = f.logs.some(function (l) { return /Verification mail (NOT sent|THREW)/.test(l); });
    console.log("    sendEmail " + behaviour + ": HTTP " + fRes.status + " | user inserted " + created + " | logged " + logged);
    check("3. sendEmail " + behaviour + ": the user is still created and the answer is 201", created && fRes.status === 201 && !fRes.nextErr,
      fRes.nextErr ? String(fRes.nextErr.message) : "HTTP " + fRes.status);
    check("3. sendEmail " + behaviour + ": the response is the same as the pre-change route's", shape(fRes) === shape(oldRes),
      shape(fRes) + " vs " + shape(oldRes));
    if (MUTATE !== "no-send") check("3. sendEmail " + behaviour + ": and the failure is logged", logged, f.logs.join(" | ").slice(0, 160));
  }

  /* ── 4-7 verify-email ─────────────────────────────────────────────────── */
  ORIGINAL = await readSubject();
  console.log("\n══ subject row before: " + JSON.stringify({ token: ORIGINAL.email_verification_token ? "set" : null, expires: ORIGINAL.email_verification_expires_at, verified_at: ORIGINAL.email_verified_at, verification_status: ORIGINAL.verification_status }) + " ══");

  let verifySrc = routeSource(MUTATE === "old-verify" ? SRC_OLD : SRC_NOW, "/api/auth/verify-email");
  if (MUTATE === "no-expiry-check") verifySrc = mutate(verifySrc, "if (!Number.isFinite(expiresAtMs) || expiresAtMs <= Date.now()) {", "if (false) {");
  const V = capture(verifySrc, { supabase: supabase }).handler;

  try {
    console.log("\n══ 4. a valid token ══");
    const t1 = newToken();
    await setSubject({ email_verification_token: t1, email_verification_expires_at: new Date(Date.now() + 3600000).toISOString(), email_verified_at: null });
    const v1 = await call(V, { token: t1 });
    const r1 = await readSubject();
    console.log("    HTTP " + v1.status + " " + JSON.stringify(v1.body) + " | after: " + JSON.stringify({ token: r1.email_verification_token, expires: r1.email_verification_expires_at, verified_at: r1.email_verified_at, verification_status: r1.verification_status }));
    check("4. answers success", v1.status === 200 && v1.body && v1.body.success === true, v1.status);
    check("4. sets email_verified_at", !!r1.email_verified_at && Math.abs(Date.parse(r1.email_verified_at) - Date.now()) < 60000, String(r1.email_verified_at));
    check("4. clears the token and its expiry", r1.email_verification_token === null && r1.email_verification_expires_at === null,
      JSON.stringify({ token: r1.email_verification_token, expires: r1.email_verification_expires_at }));
    check("4. leaves verification_status untouched", r1.verification_status === ORIGINAL.verification_status, r1.verification_status);

    console.log("\n══ 5. a wrong token, and an already-used one ══");
    const beforeWrong = await readSubject();
    const v2 = await call(V, { token: newToken() });
    const r2 = await readSubject();
    console.log("    wrong:        HTTP " + v2.status + " " + JSON.stringify(v2.body));
    check("5. a wrong token errors", v2.status === 400, v2.status);
    check("5. and changes nothing", snap(r2) === snap(beforeWrong));
    const v3 = await call(V, { token: t1 });
    const r3 = await readSubject();
    console.log("    already used: HTTP " + v3.status + " " + JSON.stringify(v3.body));
    check("5. an already-used token errors", v3.status === 400, v3.status);
    check("5. and changes nothing", snap(r3) === snap(r2));

    console.log("\n══ 6. an expired token ══");
    const t2 = newToken();
    await setSubject({ email_verification_token: t2, email_verification_expires_at: new Date(Date.now() - 60000).toISOString(), email_verified_at: null });
    const beforeExpired = await readSubject();
    const v4 = await call(V, { token: t2 });
    const r4 = await readSubject();
    console.log("    HTTP " + v4.status + " " + JSON.stringify(v4.body));
    check("6. is rejected", v4.status === 400, v4.status);
    check("6. with a message distinct from an invalid token's",
      !!(v4.body && v2.body && v4.body.error && v4.body.error !== v2.body.error && v4.body.reason === "expired"),
      JSON.stringify({ expired: v4.body, invalid: v2.body }));
    check("6. and changes nothing", snap(r4) === snap(beforeExpired));

    console.log("\n══ 7. a token with no expiry (every account before migration 122) ══");
    const t3 = newToken();
    await setSubject({ email_verification_token: t3, email_verification_expires_at: null, email_verified_at: null });
    const beforeNull = await readSubject();
    const v5 = await call(V, { token: t3 });
    const r5 = await readSubject();
    console.log("    HTTP " + v5.status + " " + JSON.stringify(v5.body));
    check("7. is rejected as expired", v5.status === 400 && v5.body && v5.body.reason === "expired", JSON.stringify(v5.body));
    check("7. and changes nothing", snap(r5) === snap(beforeNull));
  } finally {
    console.log("\n══ cleanup ══");
    const restored = await restoreSubject();
    console.log("    [fixture] subject users row put back exactly as it was read: " + (restored ? "yes" : "NO"));
    if (!restored) failures++;
    const cleanupResult = await residue.cleanup("end of run");
    if (cleanupResult.leftovers.length) failures++;
  }

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
})().catch(async function (err) {
  console.error("\nThe check threw: " + ((err && err.stack) || err));
  try { const ok = await restoreSubject(); console.error("subject row restored: " + ok); } catch (e) { /* reported below */ }
  process.exit(1);
});
