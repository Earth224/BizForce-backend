"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkBackupRestore.js — the nightly backup is encrypted, complete and
   proven restorable (launch audit #5).

   WHAT THIS PROVES, on the real lib/backup.js, lib/opsAlert.js and
   scripts/restoreBackup.js:
     V. COVERAGE. Every table the migrations leave standing is in exactly one
        of BACKUP_TABLES, SKIPPED_TABLES or EXCLUDED_TABLES, and every listed
        table exists; a new table in a migration that none of them names FAILS
        this check. BACKUP_TABLES lists every parent before its children.
     D. THE DRILL. A fixture database (every MUST table, with nested JSON,
        nulls, numbers and unicode, and ai_tasks over two pages) is backed up
        with a small part limit, so it goes out as several parts and ai_tasks
        is split by rows. The emailed parts are restored into an empty
        database, and every row of every MUST table matches the fixture.
        SKIPPED and EXCLUDED tables are never read. backup_runs records the
        run with the manifest's counts.
     F. THE FILE. Version, cipher, a fresh IV per part, an auth tag and a
        manifest (table names, row counts, sha256 per table, created time,
        commit). Each part opens on its own. The key, the Resend key and the
        service key are in no file, email or log line, and no row's text is
        anywhere in an email, before or after base64.
     T. TAMPERING. A wrong key fails, a changed byte of data fails the auth
        tag, a changed byte of the manifest fails the auth tag, and a table
        re-encrypted with changed rows fails its sha256. None of them writes.
     P. THE PRODUCTION GUARD. A target equal to the production SUPABASE_URL
        (any case, trailing slash) is refused unless --i-mean-production; an
        unknown production URL is refused.
     R. RESTORE RULES. --dry-run verifies and writes nothing; a missing part
        is refused; a target table that already has rows blocks the restore
        before anything is written.
     K. THE KEY. No key: nothing is read, nothing is sent, and the owner gets
        "Backup not encrypted: key missing". A malformed key: the same, and
        the key's text is not logged.
     S. SIZE. Resend's 40 MB per email, after base64, holds a full part; a
        single row too big for a part sends nothing and says a second
        destination is needed; a part is never cut short.
     I. AN INCOMPLETE NIGHT. An unreadable table: the rest is sent, the run
        is not a success (no finished_at), the owner is alerted, and the
        restore refuses the set.

   NO NETWORK. NO DATABASE. Supabase and Resend are in-memory stubs.

   MUTATE=<name> edits lib/backup.js, lib/opsAlert.js or
   scripts/restoreBackup.js IN MEMORY. MUTATE=all runs each in its own process
   (scripts/_shared.js): a search text that does not match exactly once is an
   ERROR, never a catch.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const crypto = require("crypto");
const Module = require("module");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const PATHS = {
  lib: path.join(REPO, "lib", "backup.js"),
  ops: path.join(REPO, "lib", "opsAlert.js"),
  restore: path.join(REPO, "scripts", "restoreBackup.js")
};
const MIGRATIONS = path.join(REPO, "supabase", "migrations");
const MUTATE = process.env.MUTATE || "";

const MUTATIONS = {
  // no key: the backup goes out unencrypted
  "plaintext-fallback": [
    ["lib", "  if (!keyInfo.ok) {\n    log.error(FAIL + \" \" + keyInfo.problem", "  if (!keyInfo.ok && false) {\n    log.error(FAIL + \" \" + keyInfo.problem"],
    ["lib", "  var cipher = crypto.createCipheriv(CIPHER, key, iv, { authTagLength: TAG_BYTES });\n",
      "  if (!key) return Buffer.concat([aad, Buffer.alloc(TAG_BYTES), plain]);\n  var cipher = crypto.createCipheriv(CIPHER, key, iv, { authTagLength: TAG_BYTES });\n"]],
  // the auth tag is never checked
  "skip-auth-tag": [["lib", "    plain = Buffer.concat([decipher.update(p.ciphertext), decipher.final()]);\n", "    plain = decipher.update(p.ciphertext);\n"]],
  // a restore into production is not refused
  "production-guard-removed": [["restore", "  if (sameSupabaseUrl(opts.targetUrl, prodUrl) && !opts.iMeanProduction) {\n", "  if (false) {\n"]],
  // a MUST table falls out of the list
  "must-table-dropped": [["lib", "  \"wallet_transactions\",         // every BizCash movement: money, and the history behind each balance\n", ""]],
  // a table too big for a part is cut short instead of split
  "truncate-instead-of-split": [["lib",
    "  return splitRows(table, rows.slice(0, half), budget).concat(splitRows(table, rows.slice(half), budget));\n",
    "  return splitRows(table, rows.slice(0, half), budget);\n"],
    ["lib", "    if (kept !== c.rows.length) {\n", "    if (false) {\n"]],
  // a table whose rows changed passes
  "sha-unchecked": [["lib", "    if (sha256Hex(JSON.stringify(rows)) !== unit.sha256) {\n", "    if (false) {\n"]],
  // the manifest is not covered by the auth tag
  "manifest-unauthenticated": [["lib", "  cipher.setAAD(aad);\n", ""], ["lib", "  decipher.setAAD(p.aad);\n", ""]],
  // every part uses the same IV
  "iv-reused": [["lib", "    var iv = randomBytes(IV_BYTES);\n", "    var iv = Buffer.alloc(IV_BYTES);\n"]],
  // --dry-run goes on to write
  "dry-run-writes": [["restore", "  if (opts.dryRun) {\n", "  if (false) {\n"]],
  // a target that already holds rows is written into
  "nonempty-target-allowed": [["restore", "    else if (head.count !== 0) blocked.push(", "    else if (false) blocked.push("]],
  // a missing part is not noticed
  "missing-parts-ignored": [["lib", "  if (missing.length) problems.push(", "  if (false) problems.push("]],
  // a backup sent with a table missing counts as a success
  "incomplete-counts-as-success": [["ops", "    return !!(result && result.sent && result.complete !== false);\n", "    return !!(result && result.sent);\n"]],
  // a key of the wrong length is accepted
  "key-length-unchecked": [["lib", "  if (key.length !== KEY_BYTES) {\n", "  if (false) {\n"]],
  // the key's text is written to the log
  "key-in-log": [["lib", "  return { ok: false, reason: \"key_malformed\", problem: \"BACKUP_ENCRYPTION_KEY is not valid base64\" };",
    "  return { ok: false, reason: \"key_malformed\", problem: \"BACKUP_ENCRYPTION_KEY is not valid base64: \" + text };"]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));
if (MUTATE && !MUTATIONS[MUTATE]) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }

const SRC = {};
for (const k of Object.keys(PATHS)) SRC[k] = fs.readFileSync(PATHS[k], "utf8").replace(/\r\n/g, "\n");
if (MUTATE) {
  for (const [file, from, to] of MUTATIONS[MUTATE]) SRC[file] = s.replaceOnce(SRC[file], from, to, MUTATE);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}

/* Each module compiled from the (possibly mutated) text at its own path. */
function compile(key) {
  const file = PATHS[key];
  const mod = new Module(file, null);
  mod.filename = file;
  mod.paths = Module._nodeModulePaths(path.dirname(file));
  mod._compile(SRC[key], file);
  return mod.exports;
}
const lib = compile("lib");
const ops = compile("ops");
const restore = compile("restore");

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}
const rejections = [];
process.on("unhandledRejection", function (reason) { rejections.push(String((reason && reason.message) || reason)); });

/* ── the migrations ─────────────────────────────────────────────────────── */
function migrationFiles() {
  return fs.readdirSync(MIGRATIONS).filter(f => f.endsWith(".sql")).sort()
    .map(f => ({ name: f, sql: fs.readFileSync(path.join(MIGRATIONS, f), "utf8") }));
}
function stripSql(sql) { return sql.replace(/--[^\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, ""); }

/* The tables the migrations leave standing: created, minus dropped, with
   renames followed. */
function tablesInMigrations(files) {
  const live = new Set();
  for (const f of files) {
    const re = /\b(create\s+table(?:\s+if\s+not\s+exists)?|drop\s+table(?:\s+if\s+exists)?|alter\s+table(?:\s+if\s+exists)?(?:\s+only)?)\s+(?:"?public"?\.)?"?([a-z_][a-z0-9_]*)"?((?:\s*,\s*(?:public\.)?[a-z_][a-z0-9_]*)*)(\s+rename\s+to\s+"?([a-z_][a-z0-9_]*)"?)?/gi;
    const sql = stripSql(f.sql);
    let m;
    while ((m = re.exec(sql))) {
      const kind = m[1].toLowerCase();
      const name = m[2].toLowerCase();
      if (kind.startsWith("create")) live.add(name);
      else if (kind.startsWith("drop")) {
        [name].concat((m[3] || "").split(",").map(x => x.trim().replace(/^public\./, "")).filter(Boolean)).forEach(n => live.delete(n));
      } else if (m[5]) { live.delete(name); live.add(m[5].toLowerCase()); }
    }
  }
  return live;
}

/* child -> parent foreign keys, from create table bodies and alter table. */
function foreignKeys(files) {
  const edges = [];
  for (const f of files) {
    for (const st of stripSql(f.sql).split(";")) {
      const m = /(?:create\s+table(?:\s+if\s+not\s+exists)?|alter\s+table(?:\s+if\s+exists)?(?:\s+only)?)\s+(?:"?public"?\.)?"?([a-z_0-9]+)"?/i.exec(st);
      if (!m) continue;
      const re = /references\s+(?:"?public"?\.)?"?([a-z_0-9]+)"?/gi;
      let r;
      while ((r = re.exec(st))) if (r[1].toLowerCase() !== m[1].toLowerCase()) edges.push([m[1].toLowerCase(), r[1].toLowerCase()]);
    }
  }
  return edges;
}

/* THE COVERAGE CHECK: what is in the migrations but in no list, what a list
   names that the migrations do not have, and what two lists both name. */
function coverage(live, b) {
  const must = b.BACKUP_TABLES, skip = Object.keys(b.SKIPPED_TABLES), excl = Object.keys(b.EXCLUDED_TABLES);
  const all = must.concat(skip, excl);
  const counts = new Map();
  all.forEach(t => counts.set(t, (counts.get(t) || 0) + 1));
  return {
    unclassified: Array.from(live).filter(t => !counts.has(t)).sort(),
    unknown: all.filter(t => !live.has(t)).sort(),
    duplicated: Array.from(counts).filter(([, n]) => n > 1).map(([t]) => t).sort()
  };
}

/* ── stubs ───────────────────────────────────────────────────────────────── */
/* A Supabase stub holding tables in memory. opts.errorTables: tables whose
   reads fail. Every call is recorded. */
function fakeDb(initial, opts) {
  opts = opts || {};
  const data = new Map();
  for (const [t, rows] of Object.entries(initial)) data.set(t, rows.map(r => JSON.parse(JSON.stringify(r))));
  const calls = [];
  function failure(table) {
    if (!data.has(table)) return { message: "relation \"public." + table + "\" does not exist" };
    if ((opts.errorTables || []).includes(table)) return { message: "permission denied for table " + table };
    return null;
  }
  return {
    data, calls,
    from(table) {
      return {
        select(cols, o) {
          const head = !!(o && o.head);
          calls.push({ op: "select", table, head });
          const whole = () => {
            const err = failure(table);
            if (err) return { data: null, count: null, error: err };
            return head ? { data: null, count: data.get(table).length, error: null } : { data: data.get(table).slice(), error: null };
          };
          return {
            range(a, b) {
              calls.push({ op: "range", table, a, b });
              const err = failure(table);
              if (err) return Promise.resolve({ data: null, error: err });
              return Promise.resolve({ data: JSON.parse(JSON.stringify(data.get(table).slice(a, b + 1))), error: null });
            },
            then(res, rej) { return Promise.resolve(whole()).then(res, rej); }
          };
        },
        insert(rows) {
          const list = Array.isArray(rows) ? rows : [rows];
          calls.push({ op: "insert", table, n: list.length });
          if (!data.has(table)) return Promise.resolve({ error: { message: "relation \"public." + table + "\" does not exist" } });
          list.forEach(r => data.get(table).push(JSON.parse(JSON.stringify(r))));
          return Promise.resolve({ error: null });
        }
      };
    }
  };
}

/* The ops-alert side: job_runs and ops_alerts writes recorded, reads empty. */
function opsDb() {
  const writes = [];
  const done = v => Promise.resolve(v);
  return {
    writes,
    from(table) {
      return {
        select() { return done({ data: [], error: null }); },
        upsert(row) { writes.push({ table, op: "upsert", row }); return done({ error: null }); },
        delete() { return { eq() { writes.push({ table, op: "delete" }); return done({ error: null }); } }; }
      };
    }
  };
}
function opsHarness() {
  const db = opsDb();
  const sent = [];
  const alerts = ops.createOpsAlerts({
    supabase: db, env: { OPS_ALERT_EMAIL: "owner@example.test", RESEND_API_KEY: "re_test" }, now: () => T0,
    send: async m => { sent.push(m); return { ok: true, id: "a" + sent.length }; },
    log: { log() {}, error() {}, warn() {} }
  });
  return { alerts, db, sent };
}

function logger() {
  const lines = [];
  return { lines, log: m => lines.push(String(m)), error: m => lines.push(String(m)), warn: m => lines.push(String(m)) };
}

/* ── the fixture ────────────────────────────────────────────────────────── */
const T0 = Date.parse("2026-10-20T15:00:00.000Z");
const KEY = crypto.createHash("sha256").update("checkBackupRestore fixture key").digest();
const KEY_B64 = KEY.toString("base64");
const OTHER_KEY_B64 = crypto.createHash("sha256").update("some other key").digest().toString("base64");
const RESEND_SECRET = "re_SECRET_resend_key_value_4417";
const SERVICE_SECRET = "sb_SECRET_service_key_value_9921";
const PROD_URL = "https://prodref0000.supabase.co";
const SCRATCH_URL = "https://scratch1111.supabase.co";
const PART_LIMIT = 60000;
const MARK = "PLAINTEXT-ROW-MARK";

let seed = 12345;
function rand() { seed = (seed * 1103515245 + 12345) % 2147483648; return seed; }
function noise(n) { let out = ""; while (out.length < n) out += rand().toString(36); return out.slice(0, n); }

/* Every table the migrations leave standing, minus the two lists that are not
   backed up: built from the MIGRATIONS, not from BACKUP_TABLES, so a table
   dropped from that list is a table the drill finds missing. */
const FILES = migrationFiles();
const LIVE = tablesInMigrations(FILES);
const MUST = Array.from(LIVE).filter(t => !(t in lib.SKIPPED_TABLES) && !(t in lib.EXCLUDED_TABLES)).sort();

function fixture() {
  seed = 12345;
  const db = {};
  for (const t of MUST) {
    db[t] = [0, 1, 2].map(i => ({
      id: t + "-" + i, user_id: "u-" + i, title: MARK + "-" + t + "-" + i + " café ✓", amount: 12.5 + i, count: i,
      nested: { tags: ["a", i], deep: { ok: true } }, empty: null, flag: i % 2 === 0, created_at: "2026-10-0" + (i + 1) + "T00:00:00.000Z"
    }));
  }
  db.ai_tasks = [];
  for (let i = 0; i < 1200; i++) db.ai_tasks.push({ id: "task-" + i, user_id: "u-" + (i % 7), result: MARK + "-task-" + i + " " + noise(60), status: "done" });
  db.contacts.push({ id: "contacts-3", user_id: "u-1", title: "", amount: 0, count: -1, nested: [], empty: null, flag: false, created_at: null });
  db.users.length = 2;
  db.backup_runs = [];
  // Not backed up: secret-shaped rows that must never be read.
  for (const t of Object.keys(lib.SKIPPED_TABLES).concat(Object.keys(lib.EXCLUDED_TABLES))) {
    if (t !== "backup_runs") db[t] = [{ id: t + "-x", secret: MARK + "-NOT-BACKED-UP-" + t }];
  }
  return db;
}
function emptyTarget() {
  const db = {};
  for (const t of LIVE) db[t] = [];
  return db;
}
const baseEnv = () => ({ BACKUP_ENCRYPTION_KEY: KEY_B64, BACKUP_EMAIL_TO: "owner@example.test", RESEND_API_KEY: RESEND_SECRET,
  SUPABASE_SERVICE_KEY: SERVICE_SECRET, SUPABASE_URL: PROD_URL, RAILWAY_GIT_COMMIT_SHA: "abc1234def5678" });

async function backUp(db, opts) {
  opts = opts || {};
  const sent = [];
  const log = logger();
  const result = await lib.runNightlyBackup({
    supabase: db, env: opts.env || baseEnv(), log, now: () => T0, partMaxBytes: opts.limit || PART_LIMIT,
    send: async m => { sent.push(JSON.parse(JSON.stringify(m))); return { data: { id: "msg_" + sent.length }, error: null }; }
  });
  const files = {};
  sent.forEach(m => m.attachments.forEach(a => { files[a.filename] = Buffer.from(a.content, "base64"); }));
  return { result, sent, log, files };
}

async function runRestore(args, files, opts) {
  opts = opts || {};
  const log = logger();
  const created = [];
  const target = opts.target || fakeDb(emptyTarget());
  const store = Object.assign({ "key.txt": Buffer.from(KEY_B64 + "\n"), "other.txt": Buffer.from(OTHER_KEY_B64) }, files);
  const code = await restore.main(args, {
    backup: lib, log,
    readFile: f => { if (!(f in store)) { const e = new Error("ENOENT " + f); e.code = "ENOENT"; throw e; } return store[f]; },
    createClient: (url, key) => { created.push(url); return target; },
    productionUrl: "productionUrl" in opts ? opts.productionUrl : PROD_URL
  });
  return { code, log, created, target, inserts: target.calls.filter(c => c.op === "insert").length };
}

(async () => {
  /* ── V. coverage ───────────────────────────────────────────────────── */
  console.log("\n══ V. every table in the migrations is classified ══");
  const cov = coverage(LIVE, lib);
  check("V1. no table in the migrations is in none of the lists", cov.unclassified.length === 0, "unclassified: " + cov.unclassified.join(", "));
  check("V2. no list names a table the migrations do not have", cov.unknown.length === 0, "unknown: " + cov.unknown.join(", "));
  check("V3. no table is in two lists", cov.duplicated.length === 0, cov.duplicated.join(", "));
  const withNew = FILES.concat([{ name: "999_new.sql", sql: "create table if not exists public.brand_new_ledger (id uuid primary key);\n" }]);
  const covNew = coverage(tablesInMigrations(withNew), lib);
  check("V4. a new migration's table in no list FAILS the coverage check", covNew.unclassified.length === 1 && covNew.unclassified[0] === "brand_new_ledger", JSON.stringify(covNew));
  const withDrop = withNew.concat([{ name: "1000_drop.sql", sql: "drop table if exists public.brand_new_ledger;\n" }]);
  check("V5. ...and a dropped one is no longer expected", coverage(tablesInMigrations(withDrop), lib).unclassified.length === 0);
  check("V6. the lists cover the live schema's sizes: MUST, SKIP, EXCLUDE",
    lib.BACKUP_TABLES.length === MUST.length && LIVE.size === MUST.length + Object.keys(lib.SKIPPED_TABLES).length + Object.keys(lib.EXCLUDED_TABLES).length,
    lib.BACKUP_TABLES.length + " listed vs " + MUST.length + " MUST in the migrations, " + LIVE.size + " live");
  const idx = new Map(lib.BACKUP_TABLES.map((t, i) => [t, i]));
  const misordered = foreignKeys(FILES).filter(([child, parent]) => idx.has(child) && LIVE.has(parent) && (!idx.has(parent) || idx.get(parent) > idx.get(child)));
  check("V7. BACKUP_TABLES puts every parent before its children (restore order), and no MUST table hangs off one that is not backed up",
    misordered.length === 0, misordered.map(e => e.join(" -> ")).join(", "));
  check("V8. the excluded tables are the credentials", ["auth_sessions", "user_api_keys", "push_subscriptions", "webauthn_challenges"].every(t => t in lib.EXCLUDED_TABLES));

  /* ── D. the drill ──────────────────────────────────────────────────── */
  console.log("\n══ D. back up a fixture, restore it into an empty database ══");
  const FIX = fixture();
  const src = fakeDb(FIX);
  const run = await backUp(src);
  const names = Object.keys(run.files).sort();
  check("D1. the backup was sent and is complete", run.result.sent === true && run.result.complete === true, JSON.stringify(run.result).slice(0, 300));
  check("D2. it went out as several parts, one email each, one attachment each",
    run.sent.length >= 2 && run.sent.length === run.result.parts && run.sent.every(m => m.attachments.length === 1) && names.length === run.sent.length, run.sent.length);
  const readTables = new Set(src.calls.map(c => c.table));
  const notBacked = Object.keys(lib.SKIPPED_TABLES).concat(Object.keys(lib.EXCLUDED_TABLES)).filter(t => t !== "backup_runs");
  check("D3. no SKIPPED or EXCLUDED table was read", notBacked.every(t => !readTables.has(t)), notBacked.filter(t => readTables.has(t)).join(", "));
  check("D4. ai_tasks was read in two pages (1200 rows, 1000 a page)", src.calls.filter(c => c.op === "range" && c.table === "ai_tasks").length === 2);
  const restored = await runRestore(["--key-file", "key.txt", "--target-url", SCRATCH_URL, "--target-key", "svc"].concat(names), run.files);
  check("D5. the restore exits 0", restored.code === 0, restored.code + " " + restored.log.lines.filter(l => /FAIL|REFUSED|PROBLEM|BLOCKED|MISMATCH/.test(l)).join(" | "));
  const diffs = MUST.filter(t => JSON.stringify(restored.target.data.get(t)) !== JSON.stringify(FIX[t]));
  check("D6. EVERY ROW OF EVERY MUST TABLE matches the fixture (" + MUST.length + " tables)", diffs.length === 0, "differs: " + diffs.join(", "));
  check("D7. nothing was written to a SKIPPED or EXCLUDED table", notBacked.every(t => restored.target.data.get(t).length === 0));
  const insertOrder = [];
  restored.target.calls.filter(c => c.op === "insert").forEach(c => { if (insertOrder[insertOrder.length - 1] !== c.table) insertOrder.push(c.table); });
  check("D8. tables were inserted in BACKUP_TABLES order, ai_tasks in batches of 500",
    JSON.stringify(insertOrder) === JSON.stringify(lib.BACKUP_TABLES.filter(t => FIX[t] && FIX[t].length)) &&
    restored.target.calls.filter(c => c.op === "insert" && c.table === "ai_tasks").map(c => c.n).join(",") === "500,500,200", insertOrder.slice(0, 5).join(","));
  check("D9. the report compares every table's restored count with the manifest", restored.log.lines.some(l => /^RESTORED: \d+ tables, every count matches the manifest\.$/.test(l)) &&
    restored.log.lines.some(l => /^\s+ai_tasks\s+1200\s+1200$/.test(l)), restored.log.lines.slice(-3).join(" | "));
  check("D10. ...and prints the setval for sequence-backed ids", restored.log.lines.some(l => l.indexOf("select setval(pg_get_serial_sequence('public.model_calls', 'id'), (select max(id) from public.model_calls));") !== -1));
  const rec = src.data.get("backup_runs");
  const expectCounts = {};
  lib.BACKUP_TABLES.forEach(t => { expectCounts[t] = FIX[t].length; });
  check("D11. backup_runs records the run: ok, parts, rows, and every table's count", rec.length === 1 && rec[0].ok === true && rec[0].sent === true &&
    rec[0].parts === run.result.parts && rec[0].total_rows === run.result.totalRows && JSON.stringify(rec[0].counts) === JSON.stringify(expectCounts) &&
    rec[0].backup_id === run.result.backupId && rec[0].commit === "abc1234def5678" && rec[0].started_at === new Date(T0).toISOString(), JSON.stringify(rec[0]).slice(0, 300));
  let h = opsHarness();
  await h.alerts.backupFinished(run.result, T0 - 60000);
  const okRow = h.db.writes.find(w => w.table === "job_runs");
  check("D12. the a61eb4c record: job_runs.nightly_backup gets finished_at, so the staleness alert sees a success",
    !!okRow && okRow.row.job_name === "nightly_backup" && !!okRow.row.finished_at && okRow.row.last_error === null && h.sent.length === 0, JSON.stringify(okRow));

  /* ── F. the file ───────────────────────────────────────────────────── */
  console.log("\n══ F. the file, the emails, the logs ══");
  const headers = names.map(n => lib.readPartHeader(run.files[n]).header);
  const m1 = headers[0].manifest;
  check("F1. each part: format version 2, aes-256-gcm, a 12-byte IV, a 16-byte auth tag",
    headers.every(x => x.format === "bizforce-backup" && x.version === 2 && x.cipher === "aes-256-gcm" && Buffer.from(x.iv, "base64").length === 12) &&
    names.every(n => lib.readPartHeader(run.files[n]).tag.length === 16));
  check("F2. a fresh IV for every part", new Set(headers.map(x => x.iv)).size === headers.length, headers.map(x => x.iv).join(","));
  check("F3. the manifest: backup id, created time, commit, part of parts", headers.every((x, i) => x.manifest.backup_id === run.result.backupId &&
    x.manifest.created_at === "2026-10-20T15:00:00.000Z" && x.manifest.commit === "abc1234def5678" && x.manifest.parts === headers.length) &&
    headers.map(x => x.manifest.part).sort((a, b) => a - b).join(",") === headers.map((x, i) => i + 1).join(","));
  const units = [].concat(...headers.map(x => x.manifest.units));
  check("F4. ...every table's name, row count and sha256 of its rows as JSON",
    lib.BACKUP_TABLES.every(t => m1.tables[t] && m1.tables[t].rows === FIX[t].length && m1.tables[t].status === "OK") &&
    units.every(u => /^[0-9a-f]{64}$/.test(u.sha256)) &&
    units.filter(u => u.table === "users").every(u => u.sha256 === crypto.createHash("sha256").update(JSON.stringify(FIX.users)).digest("hex")), JSON.stringify(units[0]));
  const aiUnits = units.filter(u => u.table === "ai_tasks");
  check("F5. ai_tasks, too big for one part, is split by rows into chunks that add up to 1200",
    aiUnits.length > 1 && aiUnits.every(u => u.chunks === aiUnits.length) && aiUnits.reduce((n, u) => n + u.rows, 0) === 1200, aiUnits.map(u => u.rows).join(","));
  check("F6. every part is within the part limit", names.every(n => run.files[n].length <= PART_LIMIT), names.map(n => run.files[n].length).join(","));
  const opened = names.map(n => { try { return lib.openPart(run.files[n], KEY); } catch (e) { return null; } });
  check("F7. each part opens and verifies ON ITS OWN", opened.every(Boolean));
  const payload = JSON.stringify(run.sent);
  const decoded = run.sent.map(m => Buffer.from(m.attachments[0].content, "base64").toString("latin1")).join("");
  check("F8. no row's text anywhere in the emails, as sent or base64-decoded", payload.indexOf(MARK) === -1 && decoded.indexOf(MARK) === -1 &&
    payload.indexOf("café") === -1 && decoded.indexOf("task-1") === -1);
  const gunzips = names.filter(n => { const p = lib.readPartHeader(run.files[n]); try { zlib.gunzipSync(p.ciphertext); return true; } catch (e) { return false; } });
  check("F9. the data is not merely gzipped: no part's body gunzips without the key", gunzips.length === 0, gunzips.join(","));
  const secrets = [KEY_B64, RESEND_SECRET, SERVICE_SECRET];
  const keyHex = KEY.toString("hex");
  check("F10. the key, the Resend key and the service key are in no file, no email and no log line",
    secrets.every(x => payload.indexOf(x) === -1 && decoded.indexOf(x) === -1 && run.log.lines.join("\n").indexOf(x) === -1) &&
    names.every(n => run.files[n].indexOf(KEY) === -1) && payload.indexOf(keyHex) === -1);
  check("F11. the subject says the date, the rows and the part", /^BizForce backup 2026-10-20 — \d+ rows — part 1 of \d+$/.test(run.sent[0].subject), run.sent[0].subject);

  /* ── T. tampering ──────────────────────────────────────────────────── */
  console.log("\n══ T. a wrong key and every kind of tampering fail ══");
  const one = run.files[names[0]];
  const codeOf = (buf, key) => { try { lib.openPart(buf, key); return "opened"; } catch (e) { return e.code || e.message; } };
  check("T1. a wrong key fails authentication", codeOf(one, Buffer.from(OTHER_KEY_B64, "base64")) === "auth_failed", codeOf(one, Buffer.from(OTHER_KEY_B64, "base64")));
  const flipData = Buffer.from(one); flipData[flipData.length - 5] ^= 0x01;
  check("T2. one changed byte of data fails the auth tag", codeOf(flipData, KEY) === "auth_failed", codeOf(flipData, KEY));
  const flipHead = Buffer.from(one); const at = flipHead.indexOf("abc1234def5678"); flipHead[at + 13] = "9".charCodeAt(0);
  check("T3. one changed byte of the manifest (the commit) fails the auth tag", at > 0 && codeOf(flipHead, KEY) === "auth_failed", codeOf(flipHead, KEY));
  const parsed = lib.readPartHeader(one);
  const real = lib.openPart(one, KEY);
  const forgedUnits = real.units.map(u => JSON.parse(JSON.stringify(u.rows)));
  forgedUnits[0][0].title = "changed after the fact";
  const forgedHeader = JSON.parse(JSON.stringify(parsed.header));
  forgedHeader.iv = crypto.randomBytes(12).toString("base64");
  const forged = lib.sealPart(forgedHeader, forgedUnits, KEY, Buffer.from(forgedHeader.iv, "base64"));
  check("T4. a table re-encrypted with the key but with changed rows fails its sha256", codeOf(forged, KEY) === "sha_mismatch", codeOf(forged, KEY));
  check("T5. a file that is not a backup is named as such", codeOf(Buffer.from("hello"), KEY) === "not_a_backup");
  const cut = one.subarray(0, 40);
  check("T6. a file cut off inside its header is refused", codeOf(cut, KEY) === "not_a_backup", codeOf(cut, KEY));
  let r = await runRestore(["--key-file", "other.txt", "--target-url", SCRATCH_URL, "--target-key", "svc"].concat(names), run.files);
  check("T7. restore with the wrong key: exit 1, nothing connected, nothing written", r.code === 1 && r.created.length === 0 && r.inserts === 0, r.code);
  const tampered = Object.assign({}, run.files, { [names[0]]: flipData });
  r = await runRestore(["--key-file", "key.txt", "--target-url", SCRATCH_URL, "--target-key", "svc"].concat(names), tampered);
  check("T8. restore with a tampered part: exit 1, nothing written", r.code === 1 && r.inserts === 0 && r.log.lines.some(l => /failed authentication/.test(l)), r.code);
  r = await runRestore(["--key-file", "key.txt", "--target-url", SCRATCH_URL, "--target-key", "svc"].concat(names), Object.assign({}, run.files, { [names[0]]: forged }));
  check("T9. restore with a forged table: exit 1, nothing written", r.code === 1 && r.inserts === 0 && r.log.lines.some(l => /sha_mismatch/.test(l)), r.code);

  /* ── P. production guard ───────────────────────────────────────────── */
  console.log("\n══ P. never production by accident ══");
  r = await runRestore(["--key-file", "key.txt", "--target-url", PROD_URL, "--target-key", "svc"].concat(names), run.files);
  check("P1. target = production SUPABASE_URL: refused, nothing connected, nothing written", r.code === 2 && r.created.length === 0 && r.inserts === 0 &&
    r.log.lines.some(l => /REFUSED: the target is the PRODUCTION database/.test(l)), r.code);
  r = await runRestore(["--key-file", "key.txt", "--target-url", "HTTPS://PRODREF0000.supabase.co/", "--target-key", "svc"].concat(names), run.files);
  check("P2. ...in another case with a trailing slash: still refused", r.code === 2 && r.created.length === 0, r.code);
  r = await runRestore(["--key-file", "key.txt", "--target-url", PROD_URL, "--target-key", "svc", "--i-mean-production"].concat(names), run.files);
  check("P3. --i-mean-production: allowed", r.code === 0 && r.created.length === 1 && r.inserts > 0, r.code);
  r = await runRestore(["--key-file", "key.txt", "--target-url", SCRATCH_URL, "--target-key", "svc"].concat(names), run.files, { productionUrl: null });
  check("P4. production URL unknown: refused, nothing connected", r.code === 2 && r.created.length === 0, r.code);
  const src2 = fs.readFileSync(PATHS.restore, "utf8");
  check("P5. the target comes only from arguments: restoreBackup.js never reads a target from process.env",
    !/process\.env\.(?!SUPABASE_URL\b)/.test(src2) && /process\.env\.SUPABASE_URL\) return process\.env\.SUPABASE_URL;/.test(src2));

  /* ── R. restore rules ──────────────────────────────────────────────── */
  console.log("\n══ R. dry run, missing parts, non-empty targets ══");
  r = await runRestore(["--key-file", "key.txt", "--target-url", SCRATCH_URL, "--target-key", "svc", "--dry-run"].concat(names), run.files);
  check("R1. --dry-run: decrypts and verifies, exit 0", r.code === 0 && r.log.lines.some(l => /^DRY RUN: every part decrypted and verified/.test(l)), r.code);
  check("R2. ...and connects to nothing and writes nothing", r.created.length === 0 && r.inserts === 0);
  r = await runRestore(["--key-file", "key.txt", "--dry-run"].concat(names), run.files);
  check("R3. --dry-run needs no target at all", r.code === 0, r.code);
  r = await runRestore(["--key-file", "key.txt", "--target-url", SCRATCH_URL, "--target-key", "svc"].concat(names.slice(1)), run.files);
  check("R4. a missing part: refused, nothing written", r.code === 1 && r.inserts === 0 && r.log.lines.some(l => /parts missing: \d/.test(l)), r.code + " " + r.log.lines.slice(-2).join(" | "));
  r = await runRestore(["--key-file", "key.txt", "--dry-run", names[1]], run.files);
  check("R5. one part alone verifies (its line says so) but is not a whole backup", r.code === 1 &&
    r.log.lines.some(l => l.indexOf("verified  " + names[1]) === 0 && /auth tag and sha256 OK/.test(l)), r.code);
  const busy = emptyTarget(); busy.users = [{ id: "already-here" }];
  r = await runRestore(["--key-file", "key.txt", "--target-url", SCRATCH_URL, "--target-key", "svc"].concat(names), run.files, { target: fakeDb(busy) });
  check("R6. a target table that already has rows: refused BEFORE anything is written", r.code === 1 && r.inserts === 0 &&
    r.log.lines.some(l => /BLOCKED\s+users already has 1 rows/.test(l)), r.code);
  r = await runRestore(["--key-file", "key.txt", "--target-url", SCRATCH_URL].concat(names), run.files);
  check("R7. a target without its service key: refused", r.code === 2 && r.created.length === 0);

  /* ── K. the key ────────────────────────────────────────────────────── */
  console.log("\n══ K. no key, no backup ══");
  const noKeyDb = fakeDb(fixture());
  const env0 = baseEnv(); delete env0.BACKUP_ENCRYPTION_KEY;
  let k = await backUp(noKeyDb, { env: env0 });
  check("K1. no key: nothing sent", k.result.sent === false && k.result.reason === "key_missing" && k.sent.length === 0, JSON.stringify(k.result));
  check("K2. ...and not one table read", noKeyDb.calls.filter(c => c.table !== "backup_runs").length === 0, noKeyDb.calls.length);
  check("K3. ...the run is recorded as failed in backup_runs", noKeyDb.data.get("backup_runs").length === 1 && noKeyDb.data.get("backup_runs")[0].ok === false &&
    noKeyDb.data.get("backup_runs")[0].reason === "key_missing");
  h = opsHarness();
  await h.alerts.backupFinished(k.result, T0);
  check("K4. ...and the owner is alerted: \"Backup not encrypted: key missing\"", h.sent.length === 1 && /Backup not encrypted: key missing/.test(h.sent[0].subject), h.sent.map(m => m.subject).join(" | "));
  const shortKey = crypto.randomBytes(31).toString("base64");
  for (const [label, bad] of [["31 bytes", shortKey], ["not base64", "this is not base64!!"]]) {
    const db = fakeDb(fixture());
    const envBad = Object.assign(baseEnv(), { BACKUP_ENCRYPTION_KEY: bad });
    k = await backUp(db, { env: envBad });
    check("K5. a malformed key (" + label + "): nothing read, nothing sent, the reason named, the key not logged",
      k.result.sent === false && k.result.reason === "key_malformed" && k.sent.length === 0 && db.calls.filter(c => c.table !== "backup_runs").length === 0 &&
      k.log.lines.some(l => /BACKUP_ENCRYPTION_KEY (is not valid base64|decodes to 31 bytes)/.test(l)) && k.log.lines.join("\n").indexOf(bad) === -1,
      JSON.stringify(k.result) + " " + k.log.lines[0]);
  }
  h = opsHarness();
  await h.alerts.backupFinished(k.result, T0);
  check("K6. ...alerted as \"Backup not encrypted: key malformed\"", h.sent.length === 1 && /Backup not encrypted: key malformed/.test(h.sent[0].subject));
  check("K7. restore refuses a malformed key", (await runRestore(["--key", "abc", "--dry-run"].concat(names), run.files)).code === 2);

  /* ── S. size ───────────────────────────────────────────────────────── */
  console.log("\n══ S. size: split, never truncate ══");
  check("S1. a full part, base64-encoded, plus 1 MB of text fits Resend's 40 MB per email",
    lib.RESEND_EMAIL_LIMIT_BYTES === 40000000 && Math.ceil(lib.PART_MAX_BYTES / 3) * 4 + 1000000 <= lib.RESEND_EMAIL_LIMIT_BYTES, lib.PART_MAX_BYTES);
  const huge = fixture();
  huge.ai_tasks.push({ id: "task-huge", result: noise(200000) });
  const hugeDb = fakeDb(huge);
  const big = await backUp(hugeDb);
  check("S2. one row too big for any part: nothing sent at all", big.result.sent === false && big.result.reason === "row_too_large" && big.sent.length === 0, JSON.stringify(big.result).slice(0, 200));
  check("S3. ...and it says a second destination is needed", /a second destination is needed/.test(big.result.error || "") && big.log.lines.some(l => /NOTHING WAS SENT/.test(l)));
  check("S4. ...recorded as failed", hugeDb.data.get("backup_runs")[0].ok === false && hugeDb.data.get("backup_runs")[0].reason === "row_too_large");
  const roomy = await backUp(fakeDb(fixture()), { limit: lib.PART_MAX_BYTES });
  check("S5. at the real limit today's-size fixture is one part", roomy.result.sent === true && roomy.result.parts === 1 && roomy.sent.length === 1, roomy.result.parts);

  /* ── I. an incomplete night ────────────────────────────────────────── */
  console.log("\n══ I. one table unreadable ══");
  const partialDb = fakeDb(fixture(), { errorTables: ["wallet_transactions"] });
  const partial = await backUp(partialDb);
  check("I1. the other tables are still sent, and the run says it is incomplete",
    partial.result.sent === true && partial.result.complete === false && partial.result.errored.join() === "wallet_transactions", JSON.stringify(partial.result).slice(0, 200));
  check("I2. ...the subject says so", /ERRORED: wallet_transactions/.test(partial.sent[0].subject), partial.sent[0].subject);
  check("I3. ...backup_runs: sent, not ok, reason incomplete", partialDb.data.get("backup_runs")[0].ok === false && partialDb.data.get("backup_runs")[0].sent === true &&
    partialDb.data.get("backup_runs")[0].reason === "incomplete");
  h = opsHarness();
  await h.alerts.backupFinished(partial.result, T0);
  const pRow = h.db.writes.find(w => w.table === "job_runs");
  check("I4. ...not a success: job_runs gets last_error and NO finished_at", !!pRow && !("finished_at" in pRow.row) && /wallet_transactions/.test(pRow.row.last_error), JSON.stringify(pRow && pRow.row));
  check("I5. ...and the owner is alerted", h.sent.length === 1 && /The nightly backup was sent incomplete/.test(h.sent[0].subject), h.sent.map(m => m.subject).join(" | "));
  r = await runRestore(["--key-file", "key.txt", "--target-url", SCRATCH_URL, "--target-key", "svc"].concat(Object.keys(partial.files)), partial.files);
  check("I6. the restore refuses a set with a table missing", r.code === 1 && r.inserts === 0 && r.log.lines.some(l => /wallet_transactions was not captured/.test(l)), r.code);

  check("Z. no unhandled rejection in the whole run", rejections.length === 0, rejections.join(" | "));

  console.log("\n" + passes + " passed, " + failures + " failed");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
/* A crash is a FAIL (exit 1), not exit 3: 3 is _shared.js's "mutation anchor did not match". */
})().catch(e => { console.log("    FAIL  the harness stopped: " + ((e && e.message) || e)); console.error((e && e.stack) || e); process.exit(1); });
