"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkRequireAuthSidGrace.js — what requireAuth does with a token that
   verifies but carries no `sid`, and with a session lookup that errors.

   THE GRACE IS CLOSED (launch audit #12, backend "Subscribers keep access
   through a failed card's grace, and cannot be charged twice"). This file
   used to pin the exposure — a sid-less token accepted, a failed lookup
   falling through to token-only auth — and said so, so that the fix would
   turn it red. It did, and every pin the fix changed is recorded below by
   name, BEFORE → AFTER:

     1. sid-less token          BEFORE accepted: next() called, req.user from
                                getUserById(decoded.id), no error body.
                                AFTER  refused: 401 "Session required" with a
                                "sign in again" message; next() not called;
                                getUserById not called.
     2. req.sessionId           BEFORE null on the grace path.
                                AFTER  never set on that path (the request is
                                refused before req is touched).
     4. once-per-user logging   BEFORE noteLegacyToken logged once per user.
                                AFTER  noteLegacyToken is deleted, and with it
     5. the log cap             LEGACY_TOKEN_GRACE_LOGGED and
                                LEGACY_TOKEN_GRACE_LOG_CAP (item 5's cap).
                                Asserted absent from server.js.
     8. NEW: lookup error       BEFORE (pinned nowhere; the code "FAILS OPEN,
                                DELIBERATELY") fell through to getUserById and
                                authenticated, revocation unenforced.
                                AFTER  FAILS CLOSED: 401 "Session could not be
                                checked" with a "try again" message; next()
                                not called; getUserById not called; logged.
   UNCHANGED and still pinned: 3 (touchSession tolerates a null session),
   6 (the sid path), 7 (writes per path) and the residue section. Item 9 is
   new and pins the three session refusals (not found, revoked, expired).

   HOW MANY USERS THIS SIGNS OUT: none that can still be signed in. Every
   createToken call passes the id createSession just wrote (createSession
   throws rather than return none), access tokens live 7 days, and the
   sessions table opened on 2026-09-08; a sid-less token stopped verifying by
   2026-09-15 at the latest.

   HOW IT WORKS. requireAuth and touchSession (and the constant it closes
   over) are extracted from the WORKING COPY of server.js with _shared.js's
   definitionOf and run in a fresh vm context per scenario. jwt.verify,
   getUserById, the Supabase client and console are stubs. NO NETWORK. NO
   DATABASE: the Supabase client records calls and returns canned data, and the
   residue section proves nothing reached anything real.

   MUTATION. Each must turn a specific item red:
     MUTATE=accept-sidless   restores the grace: a sid-less token proceeds to
                             getUserById. Items 1 and 2 must fail.
     MUTATE=fail-open        restores the fail-open lookup: an error falls
                             through to token-only auth. Item 8 must fail.
     MUTATE=revoked-allowed  a revoked session is honoured. Item 9 must fail.
   ══════════════════════════════════════════════════════════════════════════ */

const vm = require("vm");
const { after, definitionOf } = require("./_shared.js");

const MUTATE = process.env.MUTATE || "";
const MUTATIONS = ["accept-sidless", "fail-open", "revoked-allowed"];
const MUT = require("./_shared");
// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") MUT.runAllMutations(__filename, MUTATIONS);
if (MUTATE && MUTATIONS.indexOf(MUTATE) === -1) {
  console.error("Unknown MUTATE value: " + MUTATE + " (use " + MUTATIONS.join(", ") + ")");
  process.exit(64);
}

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

/* ── extraction, from the working copy ──────────────────────────────────── */
const NAMES = ["SESSION_TOUCH_INTERVAL_MS", "touchSession", "requireAuth"];
const parts = {};
for (const n of NAMES) {
  const def = definitionOf(after, n);
  if (!def) { console.error("EXTRACTION FAILED: " + n + " not found in the working copy of server.js"); process.exit(3); }
  parts[n] = def;
}

if (MUTATE === "accept-sidless") {
  parts.requireAuth = MUT.replaceOnce(parts.requireAuth,
    "    } else {\n      /* No sid: signed before sessions existed, or not by createToken at all. */\n      return res.status(401).json({\n" +
    "        error: \"Session required\",\n        message: \"This sign-in can no longer be used. Sign in again.\"\n      });\n    }",
    "    }", "accept-sidless");
  console.log("\n!! MUTATION: the sid-less grace restored — items 1 and 2 must fail.");
} else if (MUTATE === "fail-open") {
  parts.requireAuth = MUT.replaceOnce(parts.requireAuth,
    "        return res.status(401).json({\n          error: \"Session could not be checked\",",
    "        if (true) { /* token-only auth, as before */ } else return res.status(401).json({\n          error: \"Session could not be checked\",", "fail-open");
  parts.requireAuth = MUT.replaceOnce(parts.requireAuth, "      session = sessionResult.data;\n",
    "      if (!sessionResult.error) { session = sessionResult.data;\n", "fail-open (2)");
  parts.requireAuth = MUT.replaceOnce(parts.requireAuth, "      user = session.users || null;\n",
    "      user = session.users || null; }\n", "fail-open (3)");
  console.log("\n!! MUTATION: a failed session lookup falls through to token-only auth — item 8 must fail.");
} else if (MUTATE === "revoked-allowed") {
  parts.requireAuth = MUT.replaceOnce(parts.requireAuth,
    "      if (session.revoked_at) {\n        return res.status(401).json({ error: \"Session revoked\" });\n      }\n", "", "revoked-allowed");
  console.log("\n!! MUTATION: a revoked session is honoured — item 9 must fail.");
}

const SOURCE = NAMES.map(n => parts[n]).join("\n\n");

/* ── one fresh context per scenario ─────────────────────────────────────── */
function build(plan) {
  plan = plan || {};
  const logs = [];
  const dbCalls = [];          // every Supabase call, for the residue assertion
  const userLookups = [];
  const ctx = {
    process: { env: { JWT_SECRET: "test-secret" } },
    console: {
      log: m => logs.push(["log", String(m)]),
      warn: m => logs.push(["warn", String(m)]),
      error: m => logs.push(["error", String(m)])
    },
    nowIso: () => "2026-09-19T12:00:00.000Z",
    jwt: {
      verify() {
        if (plan.verifyThrows) throw new Error("jwt expired");
        return plan.decoded;
      }
    },
    getUserById: async id => { userLookups.push(id); return plan.user === undefined ? { id: id, email: "u@x.test" } : plan.user; },
    supabase: {
      from(table) {
        const q = {
          select() { dbCalls.push({ op: "select", table }); return q; },
          eq() { return q; },
          insert(p) { dbCalls.push({ op: "insert", table, payload: p }); return q; },
          update(p) { dbCalls.push({ op: "update", table, payload: p }); return q; },
          upsert(p) { dbCalls.push({ op: "upsert", table, payload: p }); return q; },
          delete() { dbCalls.push({ op: "delete", table }); return q; },
          is() { return q; },
          maybeSingle: async () => plan.sessionResult || { data: null, error: null },
          then(r) { return Promise.resolve({ data: null, error: null }).then(r); }
        };
        return q;
      }
    }
  };
  vm.createContext(ctx);
  vm.runInContext(SOURCE, ctx);
  return { ctx, logs, dbCalls, userLookups };
}

async function runAuth(env) {
  const req = { headers: { authorization: "Bearer a-token" } };
  const res = {
    statusCode: 200, body: undefined,
    status(c) { this.statusCode = c; return this; },
    json(b) { this.body = b; return this; }
  };
  let nextCalled = false;
  await env.ctx.requireAuth(req, res, () => { nextCalled = true; });
  return { req, status: res.statusCode, body: res.body, nextCalled };
}

const liveSession = (extra) => ({
  data: Object.assign({
    id: "sess-42", revoked_at: null,
    expires_at: "2030-01-01T00:00:00.000Z",
    last_used_at: "2026-09-19T11:59:00.000Z",
    users: { id: "u1", email: "u@x.test" }
  }, extra || {}),
  error: null
});

(async () => {
  console.log("checkRequireAuthSidGrace — working copy of server.js, no network, no database\n");

  /* ── 1. a sid-less token is REFUSED ─────────────────────────────────── */
  console.log("══ 1. a verifying token with no sid is refused (was: accepted) ══");
  let env = build({ decoded: { id: "u1" }, user: { id: "u1", email: "u@x.test" } });
  const sidlessEnv = env;
  let r = await runAuth(env);
  check("401 is produced", r.status === 401, "status " + r.status);
  check("the error is \"Session required\" and the message says to sign in again",
    r.body && r.body.error === "Session required" && /Sign in again/.test(r.body.message || ""), JSON.stringify(r.body));
  check("next() was NOT called — the request does not proceed", r.nextCalled === false);
  check("getUserById was NOT called — no token-only authentication", env.userLookups.length === 0, JSON.stringify(env.userLookups));
  check("req.user is not set", r.req.user === undefined, JSON.stringify(r.req.user));

  /* ── 2. req.sessionId on that path ─────────────────────────────────────── */
  console.log("\n══ 2. nothing is set on the request (was: req.sessionId null) ══");
  check("req.sessionId is never set", !("sessionId" in r.req), String(r.req.sessionId));

  /* ── 3. touchSession ───────────────────────────────────────────────────── */
  console.log("\n══ 3. touchSession tolerates a null session (unchanged) ══");
  check("no auth_sessions update was attempted on the sid-less path", env.dbCalls.filter(c => c.op === "update").length === 0);
  let threw = null;
  try { env.ctx.touchSession(null); } catch (e) { threw = e; }
  check("touchSession(null) does not throw", threw === null, threw && threw.message);
  threw = null;
  try { env.ctx.touchSession({ id: null }); } catch (e) { threw = e; }
  check("touchSession({id:null}) does not throw either", threw === null, threw && threw.message);
  check("still no write after those calls", env.dbCalls.filter(c => c.op === "update").length === 0);

  /* ── 4 and 5. the grace's logging is gone ───────────────────────────── */
  console.log("\n══ 4–5. the grace's logging and its cap are deleted (was: once per user, capped Set) ══");
  ["noteLegacyToken", "LEGACY_TOKEN_GRACE_LOGGED", "LEGACY_TOKEN_GRACE_LOG_CAP"].forEach(function (name) {
    check(name + " no longer exists in server.js", after.indexOf(name) === -1, after.indexOf(name));
  });
  check("no \"accepted under grace\" log line is written", sidlessEnv.logs.every(l => l[1].indexOf("under grace") === -1), JSON.stringify(sidlessEnv.logs));

  /* ── 6. the sid path ───────────────────────────────────────────────────── */
  console.log("\n══ 6. a token WITH a sid takes the session path (unchanged) ══");
  env = build({ decoded: { id: "u1", sid: "sess-42" }, sessionResult: liveSession() });
  const sidEnv = env;
  r = await runAuth(env);
  check("no 401 is produced", r.status === 200, "status " + r.status);
  check("next() was called", r.nextCalled === true);
  check("req.sessionId is the session id", r.req.sessionId === "sess-42", String(r.req.sessionId));
  check("req.user came from the embedded session row, not getUserById",
    env.userLookups.length === 0 && r.req.user && r.req.user.id === "u1", JSON.stringify(env.userLookups));

  /* ── 7. writes, per path ──────────────────────────────────────────────── */
  console.log("\n══ 7. writes attempted, per path (unchanged) ══");
  const kinds = c => ["insert", "update", "upsert", "delete"].indexOf(c.op) !== -1;
  const sidlessWrites = sidlessEnv.dbCalls.filter(kinds);
  const sidWrites = sidEnv.dbCalls.filter(kinds);
  check("the sid-less path attempts no write at all", sidlessWrites.length === 0, JSON.stringify(sidlessWrites));
  check("the sid path attempts exactly one", sidWrites.length === 1, JSON.stringify(sidWrites.map(w => w.op)));
  check("and it is auth_sessions.last_used_at, from touchSession",
    sidWrites.length === 1 && sidWrites[0].op === "update" && sidWrites[0].table === "auth_sessions" &&
    Object.keys(sidWrites[0].payload).length === 1 && "last_used_at" in sidWrites[0].payload,
    JSON.stringify(sidWrites[0]));

  /* ── 8. a lookup that errors FAILS CLOSED ─────────────────────────────── */
  console.log("\n══ 8. the database is unreachable: refused, never treated as valid (was: token-only auth) ══");
  env = build({ decoded: { id: "u1", sid: "sess-42" }, sessionResult: { data: null, error: { message: "fetch failed: ECONNREFUSED" } } });
  const downEnv = env;
  r = await runAuth(env);
  check("401 is produced", r.status === 401, "status " + r.status);
  check("the error says the session could not be checked, and the message says to try again",
    r.body && r.body.error === "Session could not be checked" && /Try again/.test(r.body.message || ""), JSON.stringify(r.body));
  check("next() was NOT called", r.nextCalled === false);
  check("getUserById was NOT called — no fall-through to token-only auth", env.userLookups.length === 0, JSON.stringify(env.userLookups));
  check("req.user is not set", r.req.user === undefined);
  check("the failure is logged as a refusal", env.logs.some(l => l[0] === "error" && /Session lookup FAILED/.test(l[1]) && /REFUSED \(fail closed\)/.test(l[1])),
    JSON.stringify(env.logs));
  check("and nothing is written", env.dbCalls.filter(kinds).length === 0);

  /* ── 9. the three session refusals ───────────────────────────────────── */
  console.log("\n══ 9. a missing, revoked or expired session is refused ══");
  const refusals = [
    ["not found", { data: null, error: null }, "Session not found"],
    ["revoked", liveSession({ revoked_at: "2026-09-18T00:00:00.000Z" }), "Session revoked"],
    ["expired", liveSession({ expires_at: "2026-01-01T00:00:00.000Z" }), "Session expired"]
  ];
  for (const [label, result, error] of refusals) {
    const e9 = build({ decoded: { id: "u1", sid: "sess-42" }, sessionResult: result });
    const r9 = await runAuth(e9);
    check(label + ": 401 \"" + error + "\", next() not called", r9.status === 401 && r9.body && r9.body.error === error && r9.nextCalled === false,
      r9.status + " " + JSON.stringify(r9.body));
  }

  /* ── residue ───────────────────────────────────────────────────────────── */
  console.log("\n══ residue: no database was reachable, so nothing can outlive the run ══");
  const allCalls = sidlessEnv.dbCalls.concat(sidEnv.dbCalls, downEnv.dbCalls);
  check("the Supabase client is this harness's stub, not a real one",
    sidlessEnv.ctx.supabase && typeof sidlessEnv.ctx.supabase.from === "function" &&
    !("rest" in sidlessEnv.ctx.supabase) && !("auth" in sidlessEnv.ctx.supabase));
  check("every recorded call is accounted for by an assertion above",
    allCalls.every(c => c.op === "select" || (c.op === "update" && c.table === "auth_sessions")),
    JSON.stringify(allCalls.map(c => c.op + ":" + c.table)));
  check("no insert, upsert or delete anywhere in the run",
    allCalls.every(c => ["insert", "upsert", "delete"].indexOf(c.op) === -1));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED — no sid, no access; a failed lookup refuses.");
  process.exit(0);
})().catch(e => { console.error("HARNESS ERROR: " + (e && e.stack || e)); process.exit(3); });
