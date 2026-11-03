/* checkSchemaCheck: a missing table is named the day it goes missing, with the migration to run.

   WHAT IT PROVES (lib/schemaCheck.js, and its use in lib/backup.js, lib/opsAlert.js and server.js):

     S. THE LIST IS COMPLETE. SCHEMA_TABLES equals what the migrations folder creates minus what a
        later migration drops, each tagged with the first file that creates it; it equals the union
        of lib/backup.js's three lists; and it holds every table a non-script file reads with a
        literal .from("...").
     G. BOTH FORMS OF THE SIGNAL. A head count with no error and a null count, and PGRST205, are
        "missing"; a count of 0 is present; any other error is "unreadable", never "missing".
     P. READ-ONLY. A pass is exactly one head count per listed table and nothing else: no row
        fetched, nothing inserted, updated, upserted or deleted.
     R. ONE ALERT PER MISSING TABLE. The real lib/opsAlert.js, on an in-memory ops_alerts: one email
        per missing table naming the table and its migration file; none on a second pass a day later
        (past the 6-hour dedupe), none from a fresh process (the open key is read back from
        ops_alerts), and one "resolved" when the table is there again.
     B. THE BACKUP SAYS WHICH TABLE AND WHICH MIGRATION. runNightlyBackup on a database missing
        member_support (both signal forms): backup_runs.error, the result's failure line, the email
        body, job_runs.last_error and the backup_failed alert all name
        "member_support (run supabase/migrations/150_member_support.sql)".
     J. ITS OWN CLAIM, NO DOUBLE RUN. The 06:00 tick claims job_runs.schema_check for the UTC day;
        a second tick that day, and a concurrent one, run nothing; the next day claims again. The
        boot run runs once per process.
     H. THE WIRING. server.js schedules "0 6 * * *" UTC behind schemaCheckEnabled, runs the boot
        pass 60 s after boot only as the program, and serves the schema line on /api/admin/health
        behind requireAuth and requireAdmin; the public /health does not mention it. The gate is on
        unless exactly "false". README has the variable and the job.

   No network, no database: every Supabase call goes to an in-memory fake that logs it.

   MUTATIONS — MUTATE=<name> applies one in memory; MUTATE=all runs each:
     table-left-off-list         member_support is dropped from SCHEMA_TABLES
     null-count-ignored          a null count with no error is treated as present
     pgrst205-ignored            PGRST205 is treated as an ordinary error
     duplicate-alerts            an open key is raised again on every pass
     backup-message-without-migration  the backup's failure names the table but not its migration
     probe-fetches-rows          the probe asks for rows instead of a head count
     claim-skipped               the daily tick runs without claiming the day
     boot-runs-every-call        the boot run runs on every call
*/
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const Module = require("module");
const cp = require("child_process");
const MUT = require("./_shared");

const REPO = path.join(__dirname, "..");
const read = (f) => fs.readFileSync(path.join(REPO, f), "utf8");

const MUTATIONS = {
  "table-left-off-list": ["schema",
    "  [\"member_support\", \"150_member_support.sql\"],\n", ""],
  "null-count-ignored": ["schema",
    "  return typeof res.count !== \"number\";\n", "  return false;\n"],
  "pgrst205-ignored": ["schema",
    "  if (res.error) return res.error.code === \"PGRST205\";\n", "  if (res.error) return false;\n"],
  "duplicate-alerts": ["schema",
    "    if (openKeys.has(key) || raisedHere.has(key)) continue;\n", ""],
  "backup-message-without-migration": ["backup",
    "bits.push(\"missing tables: \" + missing.map(function (m) { return schemaCheck.missingTableText(m.table); }).join(\"; \"));",
    "bits.push(\"missing tables: \" + missing.map(function (m) { return m.table; }).join(\"; \"));"],
  "probe-fetches-rows": ["schema",
    "    var res = await supabase.from(table).select(\"*\", { count: \"exact\", head: true });\n",
    "    var res = await supabase.from(table).select(\"*\", { count: \"exact\" });\n"],
  "claim-skipped": ["schema",
    "    if (!(await claimSchemaCheckDay(supabase, startedMs))) {\n", "    if (false) {\n"],
  "boot-runs-every-call": ["schema",
    "  if (bootRan) return { ran: false };\n", ""]
};
const NAMES = Object.keys(MUTATIONS);
const MUTATE = process.env.MUTATE || "";
if (MUTATE === "all") MUT.runAllMutations(__filename, NAMES);
if (MUTATE && NAMES.indexOf(MUTATE) === -1) { console.error("Unknown MUTATE=" + MUTATE + ". Known: " + NAMES.join(", ")); process.exit(2); }

let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}
const UNHANDLED = [];
process.on("unhandledRejection", function (e) { UNHANDLED.push(e); });

const FILES = {
  schema: read("lib/schemaCheck.js"),
  backup: read("lib/backup.js"),
  ops: read("lib/opsAlert.js"),
  server: read("server.js"),
  readme: read("README.md")
};
if (MUTATE) {
  const m = MUTATIONS[MUTATE];
  FILES[m[0]] = MUT.replaceOnce(FILES[m[0]], m[1], m[2], MUTATE);
  console.log("\n!! MUTATION: " + MUTATE);
}

const J = JSON.stringify;
const realRequire = Module.createRequire(path.join(REPO, "server.js"));
function compile(src, file, map) {
  const m = { exports: {} };
  const fn = vm.compileFunction(src, ["module", "exports", "require"], { filename: path.join(REPO, file) });
  fn(m, m.exports, function (r) { return Object.prototype.hasOwnProperty.call(map, r) ? map[r] : realRequire(r); });
  return m.exports;
}
// A fresh schemaCheck module is a fresh process: its boot flag and remembered raises start empty.
function freshSchema() { return compile(FILES.schema, "lib/schemaCheck.js", {}); }
const S = freshSchema();
const BK = compile(FILES.backup, "lib/backup.js", { "./schemaCheck": S });
const OPS = compile(FILES.ops, "lib/opsAlert.js", {});

/* ── an in-memory Supabase that logs every call ─────────────────────────── */
// gone: { table: "null" | "205" | "denied" }: how a head count on that table answers.
function makeDb(gone) {
  const state = { gone: Object.assign({}, gone || {}), tables: { job_runs: [], ops_alerts: [], backup_runs: [] }, log: [] };
  function rowsOf(t) { if (!state.tables[t]) state.tables[t] = []; return state.tables[t]; }
  function from(table) {
    const q = { table: table, op: null, head: false, count: null, filters: [], or: null, payload: null, onConflict: null };
    const api = {
      select: function (cols, opts) {
        if (!q.op) q.op = "select";
        if (opts && opts.head) q.head = true;
        if (opts && opts.count) q.count = opts.count;
        return api;
      },
      insert: function (row) { q.op = "insert"; q.payload = row; return api; },
      update: function (patch) { q.op = "update"; q.payload = patch; return api; },
      upsert: function (row, opts) { q.op = "upsert"; q.payload = row; q.onConflict = opts && opts.onConflict; return api; },
      delete: function () { q.op = "delete"; return api; },
      eq: function (c, v) { q.filters.push([c, v]); return api; },
      or: function (s) { q.or = s; return api; },
      range: function () { return api; }, order: function () { return api; }, limit: function () { return api; }, in: function () { return api; },
      then: function (ok, bad) { return Promise.resolve().then(run).then(ok, bad); }
    };
    function match(r) {
      if (!q.filters.every(function (f) { return String(r[f[0]]) === String(f[1]); })) return false;
      if (q.or) {
        const today = /last_run_on\.neq\.(\d{4}-\d{2}-\d{2})/.exec(q.or)[1];
        return r.last_run_on == null || r.last_run_on !== today;
      }
      return true;
    }
    function run() {
      state.log.push({ table: table, op: q.op, head: q.head, count: q.count });
      const how = state.gone[table];
      if (q.op === "select" && how) {
        if (how === "null") return { data: null, error: null, count: null, status: 204 };
        if (how === "205") return { data: null, error: { code: "PGRST205", message: "Could not find the table 'public." + table + "' in the schema cache" }, count: null, status: 404 };
        return { data: null, error: { code: "42501", message: "permission denied for table " + table }, count: null, status: 403 };
      }
      const rows = rowsOf(table);
      if (q.op === "select") {
        const hit = rows.filter(match);
        return q.head ? { data: null, error: null, count: hit.length, status: 200 } : { data: hit.map(function (r) { return Object.assign({}, r); }), error: null, count: q.count ? hit.length : null };
      }
      if (q.op === "insert") {
        if (table === "job_runs" && rows.some(function (r) { return r.job_name === q.payload.job_name; })) {
          return { data: null, error: { code: "23505", message: "duplicate key value violates unique constraint \"job_runs_pkey\"" } };
        }
        rows.push(Object.assign({}, q.payload));
        return { data: [Object.assign({}, q.payload)], error: null };
      }
      if (q.op === "update") {
        const hit = rows.filter(match);
        hit.forEach(function (r) { Object.assign(r, q.payload); });
        return { data: hit.map(function (r) { return Object.assign({}, r); }), error: null };
      }
      if (q.op === "upsert") {
        const key = q.onConflict;
        const prev = rows.find(function (r) { return r[key] === q.payload[key]; });
        if (prev) Object.assign(prev, q.payload); else rows.push(Object.assign({}, q.payload));
        return { data: null, error: null };
      }
      if (q.op === "delete") {
        const keep = rows.filter(function (r) { return !match(r); });
        state.tables[table] = keep;
        return { data: null, error: null };
      }
      return { data: null, error: { message: "fake: no operation" } };
    }
    return api;
  }
  return { from: from, state: state };
}

let CLOCK = Date.parse("2026-11-03T06:00:00.000Z");
function makeOps(db) {
  const emails = [];
  const ops = OPS.createOpsAlerts({
    supabase: db, env: { OPS_ALERT_EMAIL: "ops@example.test" }, now: function () { return CLOCK; },
    send: function (message) { emails.push(message); return Promise.resolve({ ok: true }); },
    log: { log: function () {}, error: function () {}, warn: function () {} }
  });
  return { ops: ops, emails: emails };
}
const quiet = { log: console.log, error: console.error };
function hush(fn) {
  return async function () {
    const l = console.log, e = console.error;
    console.log = function () {}; console.error = function () {};
    try { return await fn.apply(null, arguments); } finally { console.log = l; console.error = e; }
  };
}
const MIG150 = "supabase/migrations/150_member_support.sql";
const NAMED = "member_support (run " + MIG150 + ")";

(async function main() {
  /* ── S. the list ──────────────────────────────────────────────────────── */
  console.log("\n══ S. the list is every table the code relies on, each with its migration ══");
  const dir = path.join(REPO, "supabase", "migrations");
  const created = new Map(), dropped = new Map();
  for (const f of fs.readdirSync(dir).filter(function (x) { return /\.sql$/.test(x); }).sort()) {
    const sql = fs.readFileSync(path.join(dir, f), "utf8").split("\n").filter(function (l) { return !/^\s*--/.test(l); }).join("\n");
    const ev = [];
    for (const m of sql.matchAll(/create table (?:if not exists )?(?:public\.)?"?([a-z0-9_]+)"?/gi)) ev.push([m.index, "c", m[1].toLowerCase()]);
    for (const m of sql.matchAll(/drop table (?:if exists )?(?:public\.)?"?([a-z0-9_]+)"?/gi)) ev.push([m.index, "d", m[1].toLowerCase()]);
    ev.sort(function (a, b) { return a[0] - b[0]; });
    for (const e of ev) {
      if (e[1] === "c") { if (!created.has(e[2]) || dropped.has(e[2])) { created.set(e[2], f); dropped.delete(e[2]); } }
      else if (created.has(e[2])) dropped.set(e[2], f);
    }
  }
  const derived = [...created.entries()].filter(function (e) { return !dropped.has(e[0]); }).sort(function (a, b) { return a[0] < b[0] ? -1 : 1; });
  const listed = S.SCHEMA_TABLES.map(function (e) { return e[0] + " @ " + e[1]; });
  const want = derived.map(function (e) { return e[0] + " @ " + e[1]; });
  check("S1. SCHEMA_TABLES is exactly the migrations' created tables minus the dropped ones (" + want.length + "), each tagged with the file that creates it",
    J(listed) === J(want), "missing " + J(want.filter(function (x) { return listed.indexOf(x) === -1; })) + ", extra " + J(listed.filter(function (x) { return want.indexOf(x) === -1; })));
  check("S2. ...the dropped tables are not on it (053 and 123 drop " + dropped.size + ")",
    dropped.size === 8 && S.SCHEMA_TABLES.every(function (e) { return !dropped.has(e[0]); }), J([...dropped.keys()]));
  const union = new Set([].concat(BK.BACKUP_TABLES, Object.keys(BK.SKIPPED_TABLES), Object.keys(BK.EXCLUDED_TABLES)));
  const names = S.SCHEMA_TABLES.map(function (e) { return e[0]; });
  check("S3. it is exactly the union of lib/backup.js's BACKUP_TABLES, SKIPPED_TABLES and EXCLUDED_TABLES (" + union.size + ")",
    names.length === union.size && names.every(function (t) { return union.has(t); }),
    "not on the list: " + J([...union].filter(function (t) { return names.indexOf(t) === -1; })) + "; not in backup: " + J(names.filter(function (t) { return !union.has(t); })));
  const files = cp.execFileSync("git", ["ls-files", "*.js"], { cwd: REPO }).toString().trim().split(/\r?\n/).filter(function (f) { return !/^scripts\//.test(f); });
  const reads = new Map();
  for (const f of files) {
    const src = fs.readFileSync(path.join(REPO, f), "utf8");
    for (const m of src.matchAll(/([A-Za-z_$][\w$]*)?(\s*\.\s*)from\(\s*["'`]([A-Za-z0-9_]+)["'`]\s*\)/g)) {
      if (m[1] === "storage" || m[1] === "Buffer" || m[1] === "Array") continue;
      if (!reads.has(m[3])) reads.set(m[3], f);
    }
  }
  const unlisted = [...reads.keys()].filter(function (t) { return names.indexOf(t) === -1; });
  check("S4. every table a non-script file reads with a literal .from(\"...\") is on the list (" + reads.size + " read)",
    reads.size > 80 && unlisted.length === 0, unlisted.map(function (t) { return t + " in " + reads.get(t); }).join("; "));
  check("S5. each tag names a file in supabase/migrations whose SQL creates that table",
    S.SCHEMA_TABLES.every(function (e) {
      const p = path.join(dir, e[1]);
      return fs.existsSync(p) && new RegExp("create table (if not exists )?(public\\.)?\"?" + e[0] + "\"?[\\s(]", "i").test(fs.readFileSync(p, "utf8"));
    }));
  check("S6. no table appears twice", new Set(names).size === names.length);
  check("S7. migrationFor names the path to run", S.migrationFor("member_support") === MIG150 && S.migrationFor("member_gates") === "supabase/migrations/159_member_gates.sql" && S.migrationFor("nope") === null,
    J([S.migrationFor("member_support"), S.migrationFor("member_gates")]));

  /* ── G. the signal ────────────────────────────────────────────────────── */
  console.log("\n══ G. both forms of the missing-table signal ══");
  check("G1. a head count with no error and a null count (PostgREST's 204 for a missing table) is missing",
    S.isMissingSignal({ data: null, error: null, count: null, status: 204 }) === true);
  check("G2. PGRST205 is missing", S.isMissingSignal({ error: { code: "PGRST205", message: "Could not find the table" }, count: null }) === true);
  check("G3. a count of 0 is present; another error code is not \"missing\"",
    S.isMissingSignal({ error: null, count: 0 }) === false && S.isMissingSignal({ error: { code: "42501" }, count: null }) === false);
  const gdb = makeDb({ a_null: "null", a_205: "205", a_denied: "denied" });
  const probes = await Promise.all(["a_null", "a_205", "a_denied", "a_here"].map(function (t) { return S.probeTable(gdb, t); }));
  check("G4. probeTable: null count -> missing, PGRST205 -> missing, permission denied -> unreadable (with the error), a real table -> present",
    probes[0].state === "missing" && probes[1].state === "missing" && probes[2].state === "unreadable" && /permission denied/.test(probes[2].error) && probes[3].state === "present", J(probes));

  /* ── P. read-only ─────────────────────────────────────────────────────── */
  console.log("\n══ P. a pass is read-only head counts ══");
  const pdb = makeDb({ member_support: "null", member_gates: "205", plan_cycles: "denied" });
  const pass = await hush(S.runSchemaCheckPass)(pdb, CLOCK);
  check("P1. member_support (null count) and member_gates (PGRST205) are missing, each with its migration; plan_cycles is unreadable, not missing",
    J(pass.missing) === J([{ table: "member_gates", migration: "supabase/migrations/159_member_gates.sql" }, { table: "member_support", migration: MIG150 }]) &&
    pass.unreadable.length === 1 && pass.unreadable[0].table === "plan_cycles" && pass.checked === S.SCHEMA_TABLES.length, J(pass));
  const ops = pdb.state.log;
  check("P2. exactly one call per listed table, each a head count with count \"exact\"",
    ops.length === S.SCHEMA_TABLES.length && ops.every(function (o) { return o.op === "select" && o.head === true && o.count === "exact"; }) &&
    J(ops.map(function (o) { return o.table; })) === J(names), J(ops.filter(function (o) { return !(o.op === "select" && o.head); }).slice(0, 3)));
  check("P3. nothing was written: no insert, update, upsert or delete",
    !ops.some(function (o) { return o.op !== "select"; }) && pdb.state.tables.job_runs.length === 0 && pdb.state.tables.ops_alerts.length === 0);
  check("P4. the status line names each missing table and its migration",
    /^Schema: MISSING member_gates \(run supabase\/migrations\/159_member_gates\.sql\); member_support \(run supabase\/migrations\/150_member_support\.sql\)/.test(S.schemaStatusLine(pass)) &&
    /^Schema: all 105 tables present/.test(S.schemaStatusLine({ checked_at: "x", checked: 105, missing: [], unreadable: [] })), S.schemaStatusLine(pass));

  /* ── R. one alert per missing table ───────────────────────────────────── */
  console.log("\n══ R. one email per missing table, through the real lib/opsAlert.js ══");
  const rdb = makeDb({ member_support: "null" });
  const R1 = freshSchema();
  const o1 = makeOps(rdb);
  const first = await hush(R1.runSchemaCheckPass)(rdb, CLOCK);
  const n1 = await hush(R1.noteSchemaResult)(o1.ops, first);
  check("R1. the first pass: one email, for member_support, naming the migration file to run",
    o1.emails.length === 1 && J(n1.raised) === J(["member_support"]) && /member_support/.test(o1.emails[0].subject + o1.emails[0].text) &&
    o1.emails[0].text.indexOf(MIG150) !== -1, J(o1.emails.map(function (e) { return e.subject; })));
  check("R2. ...the alert is open as schema_missing:member_support and recorded in ops_alerts",
    rdb.state.tables.ops_alerts.length === 1 && rdb.state.tables.ops_alerts[0].alert_key === "schema_missing:member_support", J(rdb.state.tables.ops_alerts));
  CLOCK += 25 * 60 * 60 * 1000;
  const second = await hush(R1.runSchemaCheckPass)(rdb, CLOCK);
  await hush(R1.noteSchemaResult)(o1.ops, second);
  await hush(R1.noteSchemaResult)(o1.ops, second);
  check("R3. two more passes a day later (past the 6-hour dedupe): still one email", o1.emails.length === 1, o1.emails.length);
  const R2 = freshSchema();
  const o2 = makeOps(rdb);
  const third = await hush(R2.runSchemaCheckPass)(rdb, CLOCK);
  const n3 = await hush(R2.noteSchemaResult)(o2.ops, third);
  check("R4. a fresh process (new module, new ops alerts, same ops_alerts table): no email, the open key is read back",
    o2.emails.length === 0 && n3.raised.length === 0, J(o2.emails.map(function (e) { return e.subject; })));
  rdb.state.gone = {};
  const fourth = await hush(R2.runSchemaCheckPass)(rdb, CLOCK);
  const n4 = await hush(R2.noteSchemaResult)(o2.ops, fourth);
  check("R5. when the table is there again: one \"resolved\" email and the key is closed",
    o2.emails.length === 1 && /resolved/i.test(o2.emails[0].subject) && J(n4.resolved) === J(["member_support"]) && rdb.state.tables.ops_alerts.length === 0,
    J([o2.emails.map(function (e) { return e.subject; }), rdb.state.tables.ops_alerts]));
  const pdb2 = makeDb({ member_support: "null", member_gates: "205" });
  const R3 = freshSchema();
  const o3 = makeOps(pdb2);
  await hush(R3.noteSchemaResult)(o3.ops, await hush(R3.runSchemaCheckPass)(pdb2, CLOCK));
  check("R6. two missing tables: two emails, one each", o3.emails.length === 2 &&
    o3.emails.some(function (e) { return e.text.indexOf(MIG150) !== -1; }) && o3.emails.some(function (e) { return e.text.indexOf("159_member_gates.sql") !== -1; }),
    J(o3.emails.map(function (e) { return e.subject; })));

  /* ── B. the backup names the table and the migration ──────────────────── */
  console.log("\n══ B. the backup's failure names the missing table and its migration ══");
  for (const form of ["null", "205"]) {
    const bdb = makeDb({ member_support: form });
    const sent = [];
    const bres = await hush(BK.runNightlyBackup)({
      supabase: bdb, env: { BACKUP_ENCRYPTION_KEY: Buffer.alloc(32, 7).toString("base64"), BACKUP_EMAIL_TO: "backup@example.test" },
      send: function (m) { sent.push(m); return Promise.resolve({ data: { id: "msg_" + sent.length }, error: null }); },
      log: { log: function () {}, error: function () {} }, now: function () { return CLOCK; }
    });
    const row = bdb.state.tables.backup_runs[0] || {};
    const label = form === "null" ? "a null count" : "PGRST205";
    check("B1(" + form + "). member_support missing as " + label + ": the run is sent, not complete, and its failure line is \"missing tables: " + NAMED + "\"",
      bres.sent === true && bres.complete === false && bres.failure === "missing tables: " + NAMED && J(bres.missing) === J([{ table: "member_support", migration: MIG150 }]), J({ failure: bres.failure, missing: bres.missing }));
    check("B2(" + form + "). backup_runs.error names the table and the migration, not just \"incomplete\"",
      row.reason === "incomplete" && row.error === "missing tables: " + NAMED && J(row.problems) === J({ incomplete: [], errored: ["member_support"] }), J({ reason: row.reason, error: row.error }));
    check("B3(" + form + "). the backup email says MISSING: " + NAMED,
      sent.length > 0 && sent[0].text.indexOf("MISSING: " + NAMED) !== -1, sent[0] && sent[0].text.split("\n").filter(function (l) { return /MISSING|ERRORED/.test(l); }).join(" | "));
    if (form === "null") {
      const ob = makeOps(bdb);
      await ob.ops.backupFinished(bres, CLOCK);
      const jr = bdb.state.tables.job_runs.find(function (r) { return r.job_name === "nightly_backup"; }) || {};
      check("B4. job_runs.last_error and the backup_failed email both name the migration",
        jr.last_error === "sent incomplete: missing tables: " + NAMED && ob.emails.length === 1 && ob.emails[0].text.indexOf(NAMED) !== -1,
        J([jr.last_error, ob.emails.map(function (e) { return e.text.split("\n").filter(function (l) { return /member_support/.test(l); }).join(" | "); })]));
    }
  }
  check("B5. a table that errors for another reason is named as uncounted, without a migration",
    BK.backupFailureText([], ["member_support", "plan_cycles"], [{ table: "member_support", migration: MIG150 }]) ===
      "missing tables: " + NAMED + "; tables that could not be counted: plan_cycles" && BK.backupFailureText([], [], []) === null,
    BK.backupFailureText([], ["member_support", "plan_cycles"], [{ table: "member_support", migration: MIG150 }]));

  /* ── J. its own claim, no double run ──────────────────────────────────── */
  console.log("\n══ J. job_runs.schema_check is claimed for the UTC day; the boot run is once per process ══");
  const jdb = makeDb({ member_support: "null" });
  const JS = freshSchema();
  const oj = makeOps(jdb);
  const day1 = Date.parse("2026-11-04T06:00:00.000Z");
  const t1 = await hush(JS.schemaCheckTick)(jdb, oj.ops, day1);
  const heads1 = jdb.state.log.filter(function (o) { return o.head; }).length;
  const jrow = jdb.state.tables.job_runs.find(function (r) { return r.job_name === "schema_check"; }) || {};
  check("J1. the first tick claims job_runs.schema_check for 2026-11-04 and runs the pass",
    t1.claimed === true && jrow.last_run_on === "2026-11-04" && heads1 === S.SCHEMA_TABLES.length, J([t1.claimed, jrow, heads1]));
  check("J2. ...and its last_error names the missing table and the migration",
    jrow.last_error === "missing tables: " + NAMED && !!jrow.finished_at, jrow.last_error);
  const t2 = await hush(JS.schemaCheckTick)(jdb, oj.ops, day1 + 60000);
  const heads2 = jdb.state.log.filter(function (o) { return o.head; }).length;
  check("J3. a second tick the same day runs nothing", t2.claimed === false && heads2 === heads1, J([t2.claimed, heads2 - heads1]));
  const day2 = day1 + 24 * 60 * 60 * 1000;
  const both = await Promise.all([hush(JS.schemaCheckTick)(jdb, oj.ops, day2), hush(JS.schemaCheckTick)(jdb, oj.ops, day2)]);
  const heads3 = jdb.state.log.filter(function (o) { return o.head; }).length;
  check("J4. the next day, two ticks at once: exactly one claims and runs",
    both.filter(function (b) { return b.claimed; }).length === 1 && heads3 - heads2 === S.SCHEMA_TABLES.length, J([both.map(function (b) { return b.claimed; }), heads3 - heads2]));
  check("J5. across all of it, one email for member_support", oj.emails.length === 1, oj.emails.length);
  const BS = freshSchema();
  const bdb2 = makeDb({});
  const b1 = await hush(BS.schemaCheckBoot)(bdb2, null, CLOCK);
  const b2 = await hush(BS.schemaCheckBoot)(bdb2, null, CLOCK);
  check("J6. the boot run runs once per process; a second call does nothing",
    b1.ran === true && b2.ran === false && bdb2.state.log.length === S.SCHEMA_TABLES.length, J([b1.ran, b2.ran, bdb2.state.log.length]));
  check("J7. the boot run claims nothing and writes nothing", !bdb2.state.log.some(function (o) { return o.op !== "select"; }));

  /* ── H. the wiring ────────────────────────────────────────────────────── */
  console.log("\n══ H. server.js, the gate and the README ══");
  const SRC = FILES.server;
  const healthHead = "app.get(\"/health\", async (req, res) => {";
  const healthAt = SRC.indexOf(healthHead);
  const health = healthAt === -1 ? "" : SRC.slice(healthAt, SRC.indexOf("\n});\n", healthAt) + 5);
  check("H1. the public /health says nothing about the schema",
    healthAt !== -1 && SRC.split(healthHead).length === 2 && /probeDatabase/.test(health) && !/schema/i.test(health), health.slice(0, 200));
  check("H2. /api/admin/health is requireAuth and requireAdmin, and carries the schema line",
    /app\.get\("\/api\/admin\/health", requireAuth, requireAdmin, async function \(req, res\) \{[\s\S]{0,700}schema: schemaCheck\.schemaStatusLine\(\),/.test(SRC));
  check("H3. the 06:00 UTC cron runs schemaCheckTick, behind schemaCheckEnabled",
    /if \(require\("\.\/lib\/schemaCheck"\)\.schemaCheckEnabled\(process\.env\)\) \{\n    cron\.schedule\("0 6 \* \* \*", function \(\) \{\n      require\("\.\/lib\/schemaCheck"\)\.schemaCheckTick\(supabase, opsAlerts\)[\s\S]{0,200}\}, \{\n      timezone: "UTC"\n    \}\);/.test(SRC));
  check("H4. the boot run is 60 s after boot, only when server.js is the program, and registered for shutdown",
    /    if \(require\.main === module\) \{\n      shutdownControl\.trackInterval\("schemaCheckBoot", setTimeout\(function \(\) \{\n        require\("\.\/lib\/schemaCheck"\)\.schemaCheckBoot\(supabase, opsAlerts\)[\s\S]{0,200}\}, 60000\)\);\n    \}/.test(SRC));
  check("H5. the gate: on when unset or \"False\", off only for exactly \"false\"",
    S.schemaCheckEnabled({}) === true && S.schemaCheckEnabled({ ENABLE_SCHEMA_CHECK: "False" }) === true && S.schemaCheckEnabled({ ENABLE_SCHEMA_CHECK: "true" }) === true &&
    S.schemaCheckEnabled({ ENABLE_SCHEMA_CHECK: "false" }) === false);
  check("H6. README has the ENABLE_SCHEMA_CHECK row and the job row",
    /\n\| `ENABLE_SCHEMA_CHECK` \| on \| On unless exactly `false`/.test(FILES.readme) &&
    /\n\| `schemaCheckTick`: [^\n]*\| cron `0 6 \* \* \*`, UTC, claimed `schema_check`; and once 60 s after boot \| on unless `ENABLE_SCHEMA_CHECK` is exactly `false` \|/.test(FILES.readme));
  check("H7. lib/schemaCheck.js does not require server.js or lib/backup.js",
    !/require\(["'][^"']*(server|backup)["']\)/.test(FILES.schema));

  check("no unhandled rejection", UNHANDLED.length === 0, UNHANDLED.map(String).join("; "));
  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(function (e) { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
