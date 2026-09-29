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
     8. Resend on an unverified account mints a NEW token and a fresh expiry,
        attempts a send, and reports a failed send as an error.
     9. The token from before a resend stops working; the new one verifies.
    10. Resend on a verified account sends nothing and mints nothing.
    11. Resend requires auth: requireAuth runs first and turns away a request
        with no token.
    12. The resend limiter allows three an hour per account, keyed by account
        rather than IP.

   TWO HALVES, BECAUSE REGISTRATION WOULD SEND REAL MAIL.
   Registration (1-3) runs out of the source in a vm against a recording fake
   Supabase with sendEmail stubbed: no account is created and nothing is
   mailed. verify-email (4-7) runs out of the source in a vm against the REAL
   database, on the subject account's users row only. Every value it changes
   there is read first and written back at the end, then read back again.

   MUTATE=no-send         replaces the sendEmail call with a no-op. 2 must go red.
   MUTATE=old-verify      runs verify-email from 66e6c64. 4 must go red.
   MUTATE=no-expiry-check removes the expiry refusal. 6 and 7 must go red.
   MUTATE=resend-when-verified lets resend mint and send for an account that
   is already verified. 10 must go red.
   MUTATE=no-send now applies to sendVerificationEmail, the one body both
   routes send through.
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

const MUTATIONS = ["no-send", "old-verify", "no-expiry-check", "resend-when-verified"];
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

/* sendVerificationEmail is the one body both routes send through, so the
   no-send mutation is applied to it rather than to either route. */
let SEND_FN = functionSource(SRC_NOW, "sendVerificationEmail");
if (MUTATE === "no-send") SEND_FN = mutate(SEND_FN, "await sendEmail({", "await (async function () { return null; })({");

const HELPERS = ["nowIso", "safeText", "normalizeEmail", "normalizeUrl", "normalizeUsername", "publicUser"]
  .map(function (n) { return functionSource(SRC_NOW, n); }).join("\n\n") + "\n\n" + SEND_FN;

function capture(source, extra) {
  let handler = null, middleware = null;
  const logs = [];
  const ctx = Object.assign({
    console: { log: function (m) { logs.push(String(m)); }, warn: function (m) { logs.push(String(m)); }, error: function (m) { logs.push(String(m)); } },
    authLimiter: 0,
    app: { post: function () { handler = arguments[arguments.length - 1]; middleware = Array.prototype.slice.call(arguments, 1, -1); } }
  }, extra);
  vm.createContext(ctx);
  vm.runInContext(HELPERS + "\n\n" + source, ctx);
  if (!handler) throw new Error("handler not captured");
  return { handler: handler, logs: logs, middleware: middleware, ctx: ctx };
}

async function call(handler, body, user) {
  const res = { statusCode: 200, body: undefined,
    status: function (c) { this.statusCode = c; return this; },
    json: function (b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
  let nextErr = null;
  await handler({ body: body, ip: "127.0.0.1", headers: {}, user: user }, res, function (e) { nextErr = e || new Error("next() called"); });
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
  const regSrc = routeSource(SRC_NOW, "/api/auth/register");

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

    /* ── 8-12 resend-verification, on the same real row ──────────────────
       sendEmail and findOrCreateUserContact are stubbed: no mail goes out and
       no contacts row is written. The token writes and reads are real. */
    let resendSrc = routeSource(SRC_NOW, "/api/auth/resend-verification");
    if (MUTATE === "resend-when-verified") {
      resendSrc = mutate(resendSrc, "if (account.email_verified_at) {", "if (false) {");
      resendSrc = mutate(resendSrc, '.is("email_verified_at", null)', "");
    }
    const resendSends = [];
    let resendBehaviour = "sends";
    const R = capture(resendSrc, {
      supabase: supabase, crypto: crypto, FRONTEND_URL: "https://bizforceai.net",
      requireAuth: "REQUIRE_AUTH", verificationResendLimiter: "RESEND_LIMITER",
      findOrCreateUserContact: async function () { return "contact-1"; },
      sendEmail: async function (opts) { resendSends.push(opts); return resendBehaviour === "fails" ? { sent: false, reason: "provider_error" } : { sent: true, id: "send-2" }; }
    });
    const ME = { id: SUBJECT_USER_ID };

    console.log("\n══ 8. resend on an unverified account ══");
    const tOld = newToken();
    const oldExpiry = new Date(Date.now() + 10 * 60000).toISOString();
    await setSubject({ email_verification_token: tOld, email_verification_expires_at: oldExpiry, email_verified_at: null });
    const sendStart = Date.now();
    const s8 = await call(R.handler, {}, ME);
    const r8 = await readSubject();
    const rs = resendSends[0] || {};
    const newLink = "https://bizforceai.net/verify-email?token=" + encodeURIComponent(r8.email_verification_token || "");
    console.log("    HTTP " + s8.status + " " + JSON.stringify(s8.body) + " | sends " + resendSends.length);
    check("8. answers success and says it sent", s8.status === 200 && s8.body && s8.body.sent === true && s8.body.already_verified === false, JSON.stringify(s8.body));
    check("8. mints a NEW token", /^[0-9a-f]{64}$/.test(String(r8.email_verification_token)) && r8.email_verification_token !== tOld, String(r8.email_verification_token));
    check("8. with a fresh expiry one hour out", Math.abs(Date.parse(r8.email_verification_expires_at) - (sendStart + 3600000)) < 60000, r8.email_verification_expires_at);
    check("8. and attempts one send, with the new token in the link and the resend wording",
      resendSends.length === 1 && String(rs.html).indexOf(newLink) !== -1 && String(rs.text).indexOf(newLink) !== -1 &&
      rs.template === "email_verification" && /asked for a new link/.test(String(rs.text)),
      resendSends.length + " sends");

    resendBehaviour = "fails";
    const s8f = await call(R.handler, {}, ME);
    resendBehaviour = "sends";
    console.log("    with the send failing: HTTP " + s8f.status + " " + JSON.stringify(s8f.body));
    check("8. a failed send is reported as an error, unlike registration", s8f.status === 502 && s8f.body && !!s8f.body.error, s8f.status);

    console.log("\n══ 9. the old token stops working ══");
    const r9pre = await readSubject();
    const v9old = await call(V, { token: tOld });
    const r9 = await readSubject();
    console.log("    old token: HTTP " + v9old.status + " " + JSON.stringify(v9old.body));
    check("9. the token from before the resend is refused as invalid", v9old.status === 400 && v9old.body && v9old.body.reason === "invalid", JSON.stringify(v9old.body));
    check("9. and changes nothing", snap(r9) === snap(r9pre));
    const v9new = await call(V, { token: r9.email_verification_token });
    console.log("    new token: HTTP " + v9new.status + " " + JSON.stringify(v9new.body));
    check("9. while the newest token verifies", v9new.status === 200 && v9new.body && v9new.body.success === true, v9new.status);

    console.log("\n══ 10. resend on a verified account ══");
    const r10pre = await readSubject();
    const sendsBefore = resendSends.length;
    const s10 = await call(R.handler, {}, ME);
    const r10 = await readSubject();
    console.log("    verified_at " + r10pre.email_verified_at + " | HTTP " + s10.status + " " + JSON.stringify(s10.body));
    check("10. the account is verified going in", !!r10pre.email_verified_at, String(r10pre.email_verified_at));
    check("10. answers success, already verified, nothing sent", s10.status === 200 && s10.body && s10.body.already_verified === true && s10.body.sent === false, JSON.stringify(s10.body));
    check("10. sends nothing", resendSends.length === sendsBefore, (resendSends.length - sendsBefore) + " sends");
    check("10. mints nothing: the row is unchanged", snap(r10) === snap(r10pre),
      JSON.stringify({ token: r10.email_verification_token ? "set" : null, expires: r10.email_verification_expires_at }));

    console.log("\n══ 11. resend requires auth ══");
    check("11. requireAuth is the first middleware on the route, before the limiter",
      JSON.stringify(R.middleware) === JSON.stringify(["REQUIRE_AUTH", "RESEND_LIMITER"]), JSON.stringify(R.middleware));
    const authCtx = { supabase: supabase, jwt: {}, process: { env: {} }, getUserById: null, noteLegacyToken: null, touchSession: null, console: { log: function () {}, error: function () {} } };
    vm.createContext(authCtx);
    vm.runInContext(functionSource(SRC_NOW, "requireAuth"), authCtx);
    const authRes = { statusCode: 200, body: undefined, status: function (c) { this.statusCode = c; return this; }, json: function (b) { this.body = b; return this; } };
    let reachedHandler = false;
    await authCtx.requireAuth({ headers: {} }, authRes, function () { reachedHandler = true; });
    console.log("    no Authorization header: HTTP " + authRes.statusCode + " " + JSON.stringify(authRes.body));
    check("11. and requireAuth turns away a request with no token before the handler runs", authRes.statusCode === 401 && !reachedHandler,
      authRes.statusCode + (reachedHandler ? " (handler reached)" : ""));

    console.log("\n══ 12. the resend limiter, per account ══");
    const limiterStmt = SRC_NOW.match(/const verificationResendLimiter = rateLimit\(\{[\s\S]*?\n\}\);/)[0];
    const limCtx = { rateLimit: require(require.resolve("express-rate-limit", { paths: [REPO] })) };
    vm.createContext(limCtx);
    vm.runInContext(limiterStmt.replace("const verificationResendLimiter", "verificationResendLimiter"), limCtx);
    async function hit(userId) {
      return new Promise(function (resolve) {
        const res = { statusCode: 200, headers: {}, setHeader: function (k, v) { this.headers[k] = v; }, status: function (c) { this.statusCode = c; return this; },
          send: function () { resolve(this.statusCode); return this; }, json: function () { resolve(this.statusCode); return this; }, end: function () { resolve(this.statusCode); } };
        limCtx.verificationResendLimiter({ user: { id: userId }, ip: "203.0.113.9", headers: {}, app: { get: function () { return false; } } }, res, function () { resolve(200); });
      });
    }
    const codes = [];
    for (let i = 0; i < 4; i++) codes.push(await hit("limit-user-a"));
    const otherUser = await hit("limit-user-b");
    console.log("    account A, four requests: " + codes.join(", ") + " | account B, first request (same IP): " + otherUser);
    check("12. three per hour per account, the fourth refused with 429", JSON.stringify(codes) === JSON.stringify([200, 200, 200, 429]), codes.join(","));
    check("12. keyed per account, not per IP: another account from the same IP is not blocked", otherUser === 200, otherUser);
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
