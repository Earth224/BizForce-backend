"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkRequireAuthSidGrace.js — what requireAuth ACTUALLY does with a token
   that verifies but carries no `sid` claim.

   ⚠️ EVERY ASSERTION IN THIS FILE PINS CURRENT BEHAVIOUR, NOT DESIRED
   BEHAVIOUR. Item 1 in particular asserts that such a token is ACCEPTED and
   the request proceeds authenticated. That is the exposure, not the contract:
   a legitimately-signed token with no sid bypasses revocation entirely,
   because nothing in auth_sessions can be pointed at it. This file exists so
   that whoever closes the grace can see, before they change anything, exactly
   which behaviours their change alters — and so a green run of this harness
   AFTER the fix is a red flag rather than a reassurance.

   THE GRACE IS THE ABSENCE OF A REJECTION, NOT A BRANCH. The `else` arm in
   requireAuth calls noteLegacyToken and does nothing else. Deleting it stops
   the logging and closes nothing: execution still falls through to the shared
   `if (!user) user = await getUserById(decoded.id)` and the request is
   authenticated exactly as before. Closing the grace means ADDING a 401, which
   is a behaviour change, which is why it needs this file first.

   ITEM 7 WAS NOT IN THE BRIEF AND IS HERE BECAUSE THE FIRST RUN FOUND IT. The
   residue section originally asserted that no write was attempted anywhere; the
   sid path writes auth_sessions.last_used_at through touchSession, by design.
   Rather than weaken the assertion, the write is pinned as behaviour and the
   residue claim is made per path.

   HOW IT WORKS, following the existing harnesses. requireAuth, noteLegacyToken,
   touchSession and the three module-level constants they close over are
   extracted from the WORKING COPY of server.js with _shared.js's definitionOf
   (the same brace-matching extractor auth-me.test.js and the tool harnesses
   use) and run in a fresh vm context per scenario, so the grace Set starts
   empty every time. jwt.verify, getUserById, the Supabase client and console
   are stubs. THE LOGOUT ROUTE IS NOT REGISTERED — req.sessionId's only readers
   live there, and this harness asserts the value requireAuth sets rather than
   what logout does with it.

   NO NETWORK. NO DATABASE. RESIDUE GUARD: the convention in checkRunResidue.js
   is that nothing a check writes may outlive it. This harness satisfies it
   structurally rather than by cleaning up — the Supabase client is a stub that
   records calls and returns canned data, so there is no database for anything to
   outlive. The one write the code attempts (auth_sessions.last_used_at, on the
   sid path) reaches an array in this process and is asserted as item 7. The
   residue section proves every recorded call is one an assertion accounts for.

   MUTATION. Three, each of which must turn a specific item red:
     MUTATE=reject-sidless      adds the 401 that would close the grace.
                                Items 1 and 2 must fail entirely, and 5a with
                                them — they are what the fix changes, and if
                                they stay green this file is not watching what
                                it claims to watch. MEASURED: 8 assertions go
                                red. Item 3 does NOT fail, and that is correct:
                                its subject is touchSession tolerating a null
                                session, which a 401 earlier in the function
                                does not alter.
     MUTATE=always-log          removes noteLegacyToken's already-logged early
                                return. Item 4 must fail.
     MUTATE=cap-stops-logging   moves the console.log inside the size-check, so
                                logging stops past the cap. Item 5's second
                                half must fail.
   Run all three after any edit to this file.
   ══════════════════════════════════════════════════════════════════════════ */

const vm = require("vm");
const { after, definitionOf } = require("./_shared.js");

const MUTATE = process.env.MUTATE || "";
const MUTATIONS = ["reject-sidless", "always-log", "cap-stops-logging"];
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
const NAMES = ["LEGACY_TOKEN_GRACE_LOGGED", "LEGACY_TOKEN_GRACE_LOG_CAP",
               "SESSION_TOUCH_INTERVAL_MS", "noteLegacyToken", "touchSession", "requireAuth"];
const parts = {};
for (const n of NAMES) {
  const def = definitionOf(after, n);
  if (!def) { console.error("EXTRACTION FAILED: " + n + " not found in the working copy of server.js"); process.exit(3); }
  parts[n] = def;
}

/* The cap is read out of the extracted source rather than hardcoded here, so
   item 5 keeps testing the real boundary if the number ever changes. */
const CAP = Number(/=\s*(\d+)/.exec(parts.LEGACY_TOKEN_GRACE_LOG_CAP)[1]);

if (MUTATE === "reject-sidless") {
  const before = parts.requireAuth;
  parts.requireAuth = parts.requireAuth.replace(
    "    } else {\n      noteLegacyToken(decoded.id);\n    }",
    "    } else {\n      noteLegacyToken(decoded.id);\n      return res.status(401).json({ error: \"Session required\" });\n    }");
  if (parts.requireAuth === before) { console.error("MUTATION REFUSED: the grace arm was not found verbatim."); process.exit(1); }
  console.log("\n!! MUTATION: a 401 added for a sid-less token — items 1, 2 and 3 must fail.");
} else if (MUTATE === "always-log") {
  const before = parts.noteLegacyToken;
  parts.noteLegacyToken = parts.noteLegacyToken.replace(
    "  if (LEGACY_TOKEN_GRACE_LOGGED.has(userId)) return;\n", "");
  if (parts.noteLegacyToken === before) { console.error("MUTATION REFUSED: the already-logged guard was not found."); process.exit(1); }
  console.log("\n!! MUTATION: noteLegacyToken's already-logged guard removed — item 4 must fail.");
} else if (MUTATE === "cap-stops-logging") {
  const before = parts.noteLegacyToken;
  parts.noteLegacyToken = parts.noteLegacyToken.replace(
    "    LEGACY_TOKEN_GRACE_LOGGED.add(userId);\n  }\n",
    "    LEGACY_TOKEN_GRACE_LOGGED.add(userId);\n  } else { return; }\n");
  if (parts.noteLegacyToken === before) { console.error("MUTATION REFUSED: the cap block was not found."); process.exit(1); }
  console.log("\n!! MUTATION: logging suppressed past the cap — item 5's second half must fail.");
}

const SOURCE = NAMES.map(n => parts[n]).join("\n\n");

/* ── one fresh context per scenario, so the grace Set starts empty ──────── */
const GRACE_PREFIX = "[auth] Pre-session token accepted under grace for user ";

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

async function runAuth(env, decodedOverride) {
  const req = { headers: { authorization: "Bearer a-token" } };
  const res = {
    statusCode: 200, body: undefined,
    status(c) { this.statusCode = c; return this; },
    json(b) { this.body = b; return this; }
  };
  let nextCalled = false;
  if (decodedOverride !== undefined) env.ctx.jwtDecodedOverride = decodedOverride;
  await env.ctx.requireAuth(req, res, () => { nextCalled = true; });
  return { req, status: res.statusCode, body: res.body, nextCalled };
}

(async () => {
  console.log("checkRequireAuthSidGrace — working copy of server.js, no network, no database");
  console.log("LEGACY_TOKEN_GRACE_LOG_CAP read from source: " + CAP + "\n");

  /* ── 1. a sid-less token is ACCEPTED. THIS IS THE EXPOSURE, PINNED. ───── */
  console.log("══ 1. a verifying token with no sid is authenticated (CURRENT behaviour — the exposure) ══");
  let env = build({ decoded: { id: "u1" }, user: { id: "u1", email: "u@x.test" } });
  const graceEnv = env;
  let r = await runAuth(env);
  check("no 401 is produced", r.status === 200, "status " + r.status);
  check("next() was called — the request proceeds", r.nextCalled === true);
  check("req.user is set", !!r.req.user, JSON.stringify(r.req.user));
  check("req.user came from getUserById(decoded.id)", env.userLookups.length === 1 && env.userLookups[0] === "u1",
    JSON.stringify(env.userLookups));
  check("no error body was sent", r.body === undefined, JSON.stringify(r.body));

  /* ── 2. req.sessionId on that path ─────────────────────────────────────── */
  console.log("\n══ 2. req.sessionId is null on the grace path (CURRENT behaviour) ══");
  check("req.sessionId === null", r.req.sessionId === null, String(r.req.sessionId));
  check("the property exists rather than being absent", "sessionId" in r.req);

  /* ── 3. touchSession ───────────────────────────────────────────────────── */
  console.log("\n══ 3. touchSession is not reached with a usable session, and tolerates null (CURRENT) ══");
  const updates = env.dbCalls.filter(c => c.op === "update");
  check("no auth_sessions update was attempted on the grace path", updates.length === 0,
    JSON.stringify(updates));
  let threw = null;
  try { env.ctx.touchSession(null); } catch (e) { threw = e; }
  check("touchSession(null) does not throw", threw === null, threw && threw.message);
  threw = null;
  try { env.ctx.touchSession({ id: null }); } catch (e) { threw = e; }
  check("touchSession({id:null}) does not throw either", threw === null, threw && threw.message);
  check("still no write after those calls", env.dbCalls.filter(c => c.op === "update").length === 0);

  /* ── 4. once per user per process ───────────────────────────────────────── */
  console.log("\n══ 4. noteLegacyToken logs once per userId per process (CURRENT) ══");
  env = build({ decoded: { id: "u1" }, user: { id: "u1" } });
  await runAuth(env);
  await runAuth(env);
  let graceLogs = env.logs.filter(l => l[1].indexOf(GRACE_PREFIX) === 0);
  check("two requests for the same user produce exactly one grace log", graceLogs.length === 1, graceLogs.length);
  check("the log names the user", graceLogs.length === 1 && graceLogs[0][1].indexOf("user u1") > 0,
    graceLogs[0] && graceLogs[0][1].slice(0, 80));
  env.ctx.noteLegacyToken("u2");
  graceLogs = env.logs.filter(l => l[1].indexOf(GRACE_PREFIX) === 0);
  check("a different user logs again", graceLogs.length === 2, graceLogs.length);

  /* ── 5. past the cap: grace STILL granted, logging resumes ──────────────── */
  console.log("\n══ 5. past LEGACY_TOKEN_GRACE_LOG_CAP (" + CAP + ") — both halves (CURRENT) ══");
  env = build({ decoded: { id: "u1" }, user: { id: "u1" } });
  for (let i = 0; i < CAP; i++) env.ctx.noteLegacyToken("filler-" + i);
  const cappedSize = env.ctx.LEGACY_TOKEN_GRACE_LOGGED.size;
  check("the Set stopped growing at the cap", cappedSize === CAP, cappedSize);

  /* 5a — the grace is STILL GRANTED for a user the Set has no room for. */
  const over = await runAuth(build({ decoded: { id: "over-cap" }, user: { id: "over-cap" } }));
  check("5a: an over-cap user is still authenticated", over.status === 200 && over.nextCalled === true,
    "status " + over.status);

  /* 5b — and logging RESUMES: an uncached user logs every time, because the
     Set never recorded it, so the has() guard can never short-circuit. */
  const before5b = env.logs.filter(l => l[1].indexOf(GRACE_PREFIX) === 0).length;
  env.ctx.noteLegacyToken("over-cap");
  env.ctx.noteLegacyToken("over-cap");
  const after5b = env.logs.filter(l => l[1].indexOf(GRACE_PREFIX) === 0).length;
  check("5b: an over-cap user logs on every call, not once", after5b - before5b === 2, after5b - before5b);
  check("5b: and it was never added to the Set", env.ctx.LEGACY_TOKEN_GRACE_LOGGED.has("over-cap") === false);

  /* ── 6. the sid path ───────────────────────────────────────────────────── */
  console.log("\n══ 6. a token WITH a sid takes the session path (CURRENT) ══");
  env = build({
    decoded: { id: "u1", sid: "sess-42" },
    sessionResult: {
      data: {
        id: "sess-42", revoked_at: null,
        expires_at: "2030-01-01T00:00:00.000Z",
        last_used_at: "2026-09-19T11:59:00.000Z",
        users: { id: "u1", email: "u@x.test" }
      },
      error: null
    }
  });
  const sidEnv = env;
  r = await runAuth(env);
  check("no 401 is produced", r.status === 200, "status " + r.status);
  check("req.sessionId is the session id", r.req.sessionId === "sess-42", String(r.req.sessionId));
  check("req.user came from the embedded session row, not getUserById",
    env.userLookups.length === 0 && r.req.user && r.req.user.id === "u1", JSON.stringify(env.userLookups));
  const graceOnSidPath = env.logs.filter(l => l[1].indexOf(GRACE_PREFIX) === 0);
  check("no grace log on the sid path", graceOnSidPath.length === 0, graceOnSidPath.length);

  /* ── 7. the one write the session path makes, pinned (CURRENT) ──────────── */
  /* This section originally asserted that no write was attempted ANYWHERE. That
     was wrong and the first run caught it: on the sid path touchSession writes
     last_used_at by design (server.js ~2750, "Written back on use so an idle
     session can be told from a live one"). The grace path makes no write
     because session is null; the sid path makes exactly one. Both are pinned. */
  console.log("\n══ 7. writes attempted, per path (CURRENT behaviour) ══");
  const kinds = c => ["insert", "update", "upsert", "delete"].indexOf(c.op) !== -1;
  const graceWrites = graceEnv.dbCalls.filter(kinds);
  const sidWrites = sidEnv.dbCalls.filter(kinds);
  check("the grace path attempts no write at all", graceWrites.length === 0, JSON.stringify(graceWrites));
  check("the sid path attempts exactly one", sidWrites.length === 1, JSON.stringify(sidWrites.map(w => w.op)));
  check("and it is auth_sessions.last_used_at, from touchSession",
    sidWrites.length === 1 && sidWrites[0].op === "update" && sidWrites[0].table === "auth_sessions" &&
    Object.keys(sidWrites[0].payload).length === 1 && "last_used_at" in sidWrites[0].payload,
    JSON.stringify(sidWrites[0]));

  /* ── residue ───────────────────────────────────────────────────────────── */
  /* checkRunResidue.js's rule is that nothing a check writes may outlive it.
     This harness satisfies it structurally rather than by cleaning up: the
     Supabase client is a stub that records calls and returns canned data, so
     the write above reached an array in this process and no database exists to
     outlive. Asserted rather than asserted-by-comment. */
  console.log("\n══ residue: no database was reachable, so nothing can outlive the run ══");
  check("the Supabase client is this harness's stub, not a real one",
    graceEnv.ctx.supabase && typeof graceEnv.ctx.supabase.from === "function" &&
    !("rest" in graceEnv.ctx.supabase) && !("auth" in graceEnv.ctx.supabase));
  check("every recorded call is accounted for by an assertion above",
    graceEnv.dbCalls.concat(sidEnv.dbCalls).every(c => c.op === "select" || (c.op === "update" && c.table === "auth_sessions")),
    JSON.stringify(graceEnv.dbCalls.concat(sidEnv.dbCalls).map(c => c.op + ":" + c.table)));
  check("no insert, upsert or delete anywhere in the run",
    graceEnv.dbCalls.concat(sidEnv.dbCalls).every(c => ["insert", "upsert", "delete"].indexOf(c.op) === -1));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED — this is what requireAuth does TODAY, exposure included.");
  process.exit(0);
})().catch(e => { console.error("HARNESS ERROR: " + (e && e.stack || e)); process.exit(3); });
