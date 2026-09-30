/* ══════════════════════════════════════════════════════════════════════════
   checkAdminVerifyRecords.js — POST /api/admin/verify/:userId records the
   verification it announces.

   THE DEFECT. The route updated only updated_at on users and on profiles,
   then sent a "Business verified" notification. b4fbb11 (April) stripped
   verification_status: "verified" from both updates: correctly for profiles,
   which has no such column (42703 live), and wrongly for users, where
   verification_status exists (migration 000, text default 'pending').

   WHAT THIS PROVES, against the live database, on the subject account only:
     1. A verification sets users.verification_status to 'verified'.
     2. A failed users update answers an error, sends no notification, and
        writes nothing to profiles.
     3. A successful verification sends the "Business verified" notification.
     4. email_verified_at is untouched: email confirmation is a different fact
        in a different column.
     5. profiles is NOT sent verification_status: its update carries
        updated_at only, and the live write answers without error. (The
        column does not exist; writing it would fail every call.)

   HOW. The route is lifted out of server.js and run in a vm, the way
   checkCertificationCreditOnce runs its route. Its supabase is the real
   client behind a recorder that notes every update payload by table, so 5
   can see exactly which columns were sent. For 2, the users update is made
   to answer with an error without reaching the database; everything else
   still goes through.

   RESTORED AFTERWARDS. The subject's users.verification_status and
   updated_at, and its profiles.updated_at, are read first and written back
   at the end, then read back again. Notifications this run creates are
   recorded with the residue guard and removed.

   MUTATE=stripped       runs the route as it was at d407816, which wrote
                         only updated_at. 1 must go red.
   MUTATE=write-profiles adds verification_status to the profiles update.
                         5 must go red.
   The mutations are applied to the extracted source, never to server.js.
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

const residue = createResidueGuard({ supabase: supabase, name: "adminVerifyRecords", subject: SUBJECT_USER_ID, tables: ["notifications"] });
residue.install();

const MUTATIONS = ["stripped", "write-profiles"];
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
const STRIPPED = "d407816";
// LF whatever the checkout: a core.autocrlf=true working copy is CRLF, and the
// boundaries and anchors below are written with \n.
const SRC_NOW = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
const SRC_OLD = execSync("git show " + STRIPPED + ":server.js", { cwd: REPO, maxBuffer: 64 * 1024 * 1024 }).toString("utf8");

function routeSource(src) {
  const sig = 'app.post("/api/admin/verify/:userId"';
  const start = src.indexOf(sig);
  if (start < 0) throw new Error("the verify route was not found");
  const end = braceMatch(src, src.indexOf("{", src.indexOf("async function", start)));
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

let ROUTE = MUTATE === "stripped" ? routeSource(SRC_OLD) : routeSource(SRC_NOW);
if (MUTATE === "write-profiles") {
  ROUTE = mutate(ROUTE, '.from("profiles")\n      .update({\n        updated_at: nowIso()',
                        '.from("profiles")\n      .update({\n        verification_status: "verified",\n        updated_at: nowIso()');
}

/* The real client behind a recorder: every update payload is noted by table.
   With failUsersUpdate, the users update answers an error without reaching
   the database. */
function recordingClient(opts) {
  const updates = [];
  const inserts = [];
  return {
    updates: updates,
    inserts: inserts,
    from: function (table) {
      const q = supabase.from(table);
      const update = q.update.bind(q);
      const insert = q.insert.bind(q);
      q.update = function (payload) {
        updates.push({ table: table, keys: Object.keys(payload).sort(), payload: payload });
        if (opts && opts.failUsersUpdate && table === "users") {
          const failed = { data: null, error: { code: "XX000", message: "simulated users update failure" } };
          const chain = {
            eq: function () { return chain; }, select: function () { return chain; },
            single: function () { return Promise.resolve(failed); },
            then: function (r, j) { return Promise.resolve(failed).then(r, j); }
          };
          return chain;
        }
        return update(payload);
      };
      q.insert = function (payload) { inserts.push({ table: table, payload: payload }); return insert(payload); };
      return q;
    }
  };
}

function buildHandler(client) {
  let handler = null;
  const ctx = {
    supabase: client,
    console: { log: function () {}, warn: function () {}, error: function () {} },
    requireAuth: 0, requireAdmin: 0,
    app: { post: function () { handler = arguments[arguments.length - 1]; } }
  };
  vm.createContext(ctx);
  vm.runInContext(functionSource(SRC_NOW, "nowIso") + "\n\n" + ROUTE, ctx);
  if (!handler) throw new Error("the handler was not captured");
  return handler;
}

async function call(handler) {
  const res = { statusCode: 200, body: undefined,
    status: function (c) { this.statusCode = c; return this; },
    json: function (b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
  let nextErr = null;
  await handler({ params: { userId: SUBJECT_USER_ID }, user: { id: "admin-check" }, body: {}, headers: {} }, res,
    function (e) { nextErr = e || new Error("next() called"); });
  return { status: nextErr ? 500 : res.statusCode, body: res.body, nextErr: nextErr };
}

/* ── reads ───────────────────────────────────────────────────────────────── */
async function userRow() {
  const r = await supabase.from("users").select("id, verification_status, email_verified_at, updated_at").eq("id", SUBJECT_USER_ID).single();
  if (r.error) throw new Error("could not read the subject's users row: " + r.error.message);
  return r.data;
}
async function profileRow() {
  const r = await supabase.from("profiles").select("id, updated_at").eq("user_id", SUBJECT_USER_ID).maybeSingle();
  if (r.error) throw new Error("could not read the subject's profile: " + r.error.message);
  return r.data;
}
async function verificationNotifications(since) {
  const r = await supabase.from("notifications").select("id, user_id, type, title, message, created_at")
    .eq("user_id", SUBJECT_USER_ID).eq("type", "verification").gte("created_at", since);
  if (r.error) throw new Error("could not read notifications: " + r.error.message);
  (r.data || []).forEach(function (n) { residue.record("notifications", n.id); });
  return r.data || [];
}

(async function main() {
  await residue.sweepPrevious(SUBJECT_USER_ID);

  const ORIGINAL_USER = await userRow();
  const ORIGINAL_PROFILE = await profileRow();
  console.log("\n══ subject before: " + JSON.stringify({ verification_status: ORIGINAL_USER.verification_status, email_verified_at: ORIGINAL_USER.email_verified_at, has_profile: !!ORIGINAL_PROFILE }) + " ══");
  console.log("══ route under test: " + (MUTATE ? "MUTATED (" + MUTATE + ")" : "server.js as it stands") + " ══");

  try {
    /* Start from 'pending' so 1 can only pass if this run wrote 'verified'. */
    const reset = await supabase.from("users").update({ verification_status: "pending" }).eq("id", SUBJECT_USER_ID);
    if (reset.error) throw new Error("could not set the starting state: " + reset.error.message);

    /* ── 2. a failed users update ──────────────────────────────────────── */
    console.log("\n══ 2. the users update fails ══");
    const t2 = new Date(Date.now() - 1000).toISOString();
    const failing = recordingClient({ failUsersUpdate: true });
    const r2 = await call(buildHandler(failing));
    const n2 = await verificationNotifications(t2);
    const u2 = await userRow();
    console.log("    HTTP " + r2.status + " " + JSON.stringify(r2.body || (r2.nextErr && r2.nextErr.message)) +
      " | updates sent: " + JSON.stringify(failing.updates.map(function (u) { return u.table; })) + " | notifications: " + n2.length);
    check("2. answers an error, not success", r2.status >= 400 && !(r2.body && r2.body.user), r2.status);
    check("2. sends no notification", n2.length === 0 && failing.inserts.length === 0, n2.length + " notification(s)");
    check("2. and records nothing: users still 'pending', profiles not written",
      u2.verification_status === "pending" && failing.updates.every(function (u) { return u.table === "users"; }),
      JSON.stringify({ status: u2.verification_status, tables: failing.updates.map(function (u) { return u.table; }) }));

    /* ── 1, 3, 4, 5. a successful verification ─────────────────────────── */
    console.log("\n══ 1, 3, 4, 5. a verification that succeeds ══");
    const t1 = new Date(Date.now() - 1000).toISOString();
    const rec = recordingClient();
    const r1 = await call(buildHandler(rec));
    const u1 = await userRow();
    const n1 = await verificationNotifications(t1);
    const profileUpdate = rec.updates.find(function (u) { return u.table === "profiles"; });
    console.log("    HTTP " + r1.status + " " + JSON.stringify(r1.body) + (r1.nextErr ? " next(" + r1.nextErr.message + ")" : ""));
    console.log("    updates sent: " + JSON.stringify(rec.updates.map(function (u) { return { table: u.table, keys: u.keys }; })));
    console.log("    users after: " + JSON.stringify({ verification_status: u1.verification_status, email_verified_at: u1.email_verified_at }) +
      " | notifications: " + JSON.stringify(n1.map(function (n) { return n.title + " — " + n.message; })));

    check("1. users.verification_status is 'verified'", u1.verification_status === "verified", u1.verification_status);
    check("1. and the route answered success", r1.status === 200 && r1.body && r1.body.user && r1.body.user.id === SUBJECT_USER_ID, r1.status);
    check("3. the \"Business verified\" notification was sent", n1.length === 1 && n1[0].title === "Business verified", n1.length + " notification(s)");
    check("4. email_verified_at is untouched", u1.email_verified_at === ORIGINAL_USER.email_verified_at,
      JSON.stringify({ before: ORIGINAL_USER.email_verified_at, after: u1.email_verified_at }));
    check("4. and no update this route sent names email_verified_at", rec.updates.every(function (u) { return u.keys.indexOf("email_verified_at") === -1; }));
    check("5. profiles is sent updated_at only, never verification_status",
      !!profileUpdate && JSON.stringify(profileUpdate.keys) === JSON.stringify(["updated_at"]),
      profileUpdate ? JSON.stringify(profileUpdate.keys) : "no profiles update");
    check("5. and the live profiles write answered without error (profile_updated: true)",
      r1.body && r1.body.profile_updated === true, JSON.stringify(r1.body && r1.body.profile_updated));
  } finally {
    console.log("\n══ cleanup ══");
    const put = await supabase.from("users").update({ verification_status: ORIGINAL_USER.verification_status, updated_at: ORIGINAL_USER.updated_at }).eq("id", SUBJECT_USER_ID);
    const back = await userRow();
    const userOk = !put.error && back.verification_status === ORIGINAL_USER.verification_status &&
      back.email_verified_at === ORIGINAL_USER.email_verified_at && Date.parse(back.updated_at) === Date.parse(ORIGINAL_USER.updated_at);
    console.log("    [fixture] users row put back (verification_status " + ORIGINAL_USER.verification_status + ", updated_at, email_verified_at unchanged): " + (userOk ? "yes" : "NO"));
    if (!userOk) failures++;
    if (ORIGINAL_PROFILE) {
      const pput = await supabase.from("profiles").update({ updated_at: ORIGINAL_PROFILE.updated_at }).eq("id", ORIGINAL_PROFILE.id);
      const pback = await profileRow();
      const profOk = !pput.error && Date.parse(pback.updated_at) === Date.parse(ORIGINAL_PROFILE.updated_at);
      console.log("    [fixture] profiles.updated_at put back: " + (profOk ? "yes" : "NO"));
      if (!profOk) failures++;
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
