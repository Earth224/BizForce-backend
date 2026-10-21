"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   buildScratchSchema.js — every migration in supabase/migrations, in number
   order, as ONE .sql file to paste into a scratch Supabase project before a
   restore drill (scripts/restoreBackup.js). RUN BY HAND; nothing calls it.
   It reads files and writes one file. It connects to nothing.

   node scripts/buildScratchSchema.js [--out <file>]
     default --out: <home>/Downloads/bizforce-schema-all.sql

   THE FILE
     A header naming how many migrations it holds and the last one, then each
     migration verbatim under a "-- ═══ [n/N] <file> ═══" marker. Two changes
     only, both listed in the header: a migration whose text does not end in
     ";" gets one (or its last statement would run into the next file's
     first), and CREATE INDEX CONCURRENTLY loses CONCURRENTLY (the SQL editor
     runs a pasted script as one transaction, where CONCURRENTLY is an error;
     on empty tables it changes nothing). There are none of either today.

   THE FINDINGS, printed and written into the header
     BLOCKING — would stop the pasted file on a fresh database:
       - an object created twice with no guard (table, index, policy,
         trigger, function, type);
       - a statement on a table that no earlier migration created and that is
         not created by the same statement (it existed only in production).
     PRODUCTION DATA — top-level UPDATE or DELETE, INSERT ... SELECT, or a
       literal uuid: on a scratch database it does nothing or something else.
     NOT IDEMPOTENT — fine pasted once into an empty project, an error or a
       duplicate if run twice: CREATE without IF NOT EXISTS or OR REPLACE,
       CREATE POLICY or TRIGGER without a DROP ... IF EXISTS before it, ADD
       CONSTRAINT, RENAME, DROP without IF EXISTS, INSERT without ON CONFLICT.
     Function bodies and DO blocks ($$ ... $$) are not judged: their insides
     run only when called, and a DO block's guards are its own.

   Exit 0 when the file was written with no BLOCKING finding, 1 otherwise
   (the file is still written, so the findings can be read in it).
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const os = require("os");
const path = require("path");

const MIGRATIONS_DIR = path.join(__dirname, "..", "supabase", "migrations");
const DEFAULT_OUT = path.join(os.homedir(), "Downloads", "bizforce-schema-all.sql");
// Schemas every Supabase project has before any migration runs.
const PLATFORM_SCHEMAS = ["auth", "storage", "extensions", "cron", "net", "vault", "realtime", "pg_catalog", "information_schema"];

/* Migration files in number order: the leading digits as a number, then the
   name. A file that does not start with digits and end in .sql is not one. */
function listMigrations(dir) {
  dir = dir || MIGRATIONS_DIR;
  return fs.readdirSync(dir)
    .filter(function (f) { return /^\d+_.*\.sql$/i.test(f); })
    .sort(function (a, b) { return (parseInt(a, 10) - parseInt(b, 10)) || (a < b ? -1 : a > b ? 1 : 0); });
}

/* Top-level statements of one file. Comments go; quoted strings stay; each
   dollar-quoted body becomes $BODY$ so what runs only when called is not
   judged as if it ran now. */
function splitStatements(sql) {
  var out = [], cur = "", line = 1, startLine = 0, i = 0, n = sql.length;
  function push() {
    if (cur.trim()) out.push({ text: cur.trim(), line: startLine });
    cur = ""; startLine = 0;
  }
  function add(s) {
    if (!startLine && s.trim()) startLine = line;
    cur += s;
  }
  while (i < n) {
    var c = sql[i], two = sql.substr(i, 2);
    if (two === "--") {
      var nl = sql.indexOf("\n", i);
      i = nl < 0 ? n : nl;
      continue;
    }
    if (two === "/*") {
      var depth = 0;
      while (i < n) {
        if (sql.substr(i, 2) === "/*") { depth++; i += 2; continue; }
        if (sql.substr(i, 2) === "*/") { depth--; i += 2; if (!depth) break; continue; }
        if (sql[i] === "\n") line++;
        i++;
      }
      add(" ");
      continue;
    }
    if (c === "'" || c === "\"") {
      var escaped = c === "'" && /[eE]/.test(sql[i - 1] || "") && !/[A-Za-z0-9_]/.test(sql[i - 2] || "");
      var j = i + 1;
      while (j < n) {
        if (escaped && sql[j] === "\\") { j += 2; continue; }
        if (sql[j] === c) { if (sql[j + 1] === c) { j += 2; continue; } break; }
        j++;
      }
      var lit = sql.slice(i, j + 1);
      add(lit);
      line += (lit.match(/\n/g) || []).length;
      i = j + 1;
      continue;
    }
    if (c === "$") {
      var tag = /^\$[A-Za-z_]*\$/.exec(sql.slice(i, i + 64));
      if (tag) {
        var end = sql.indexOf(tag[0], i + tag[0].length);
        if (end < 0) end = n - tag[0].length;
        line += (sql.slice(i, end).match(/\n/g) || []).length;
        add(" $BODY$ ");
        i = end + tag[0].length;
        continue;
      }
    }
    if (c === ";") { push(); i++; continue; }
    if (c === "\n") line++;
    add(c);
    i++;
  }
  push();
  return out;
}

function bareName(raw) {
  return String(raw).replace(/"/g, "").replace(/^public\./i, "").toLowerCase();
}
var NAME = "((?:\"?[A-Za-z_][A-Za-z0-9_$]*\"?\\.)?\"?[A-Za-z_][A-Za-z0-9_$]*\"?)";

/* What every statement creates, needs and does, judged in sequence across all
   files: a table is "known" once some earlier statement created it. */
function analyzeMigrations(files) {
  var findings = [];
  var tables = new Set(), created = new Map();
  function find(kind, file, line, text) { findings.push({ kind: kind, file: file, line: line, text: text }); }

  files.forEach(function (f) {
    var dropped = new Set();   // "policy name on table" / "trigger name on table" dropped IF EXISTS earlier in this file
    var lastText = f.sql.replace(/--[^\n]*|\/\*[\s\S]*?\*\//g, "").trim();
    if (lastText && lastText[lastText.length - 1] !== ";") find("FIXED", f.name, 0, "the file does not end in \";\": one was added after it");
    splitStatements(f.sql).forEach(function (st) {
      var s = st.text.replace(/\s+/g, " ");
      var low = s.toLowerCase();
      var at = function (kind, text) { find(kind, f.name, st.line, text + ": " + s.slice(0, 140)); };
      var m;

      if (/\bconcurrently\b/.test(low)) at("FIXED", "CONCURRENTLY was removed for the pasted file");

      // ── what it creates ────────────────────────────────────────────────
      var guarded = /\bif not exists\b|\bor replace\b/.test(low);
      if ((m = new RegExp("^create (?:unlogged |temp |temporary )?table (?:if not exists )?" + NAME, "i").exec(s))) {
        var t = bareName(m[1]);
        if (!guarded) at("NOT IDEMPOTENT", "CREATE TABLE without IF NOT EXISTS");
        if (tables.has(t) && !guarded) at("BLOCKING", "table " + t + " is created a second time without IF NOT EXISTS");
        tables.add(t);
      }
      var kinds = [
        ["index", new RegExp("^create (?:unique )?index (?:concurrently )?(?:if not exists )?" + NAME + " on (?:only )?" + NAME, "i")],
        ["policy", new RegExp("^create policy (\"[^\"]+\"|[A-Za-z_][A-Za-z0-9_]*) on " + NAME, "i")],
        ["trigger", new RegExp("^create (?:or replace )?(?:constraint )?trigger " + NAME + " .*? on " + NAME, "i")],
        ["function", new RegExp("^create (?:or replace )?(?:function|procedure) " + NAME, "i")],
        ["type", new RegExp("^create type " + NAME, "i")],
        ["view", new RegExp("^create (?:or replace )?(?:materialized )?view (?:if not exists )?" + NAME, "i")],
        ["sequence", new RegExp("^create sequence (?:if not exists )?" + NAME, "i")]
      ];
      kinds.forEach(function (k) {
        var mm = k[1].exec(s);
        if (!mm) return;
        var key = k[0] + " " + bareName(mm[1]) + (k[0] === "policy" || k[0] === "trigger" ? " on " + bareName(mm[2]) : "");
        var safe = guarded || dropped.has(key);
        if (!safe) at("NOT IDEMPOTENT", "CREATE " + k[0].toUpperCase() + " with no guard");
        if (created.has(key) && !safe && k[0] !== "function") at("BLOCKING", key + " was already created in " + created.get(key));
        if (k[0] === "function" && created.has(key) && !guarded) at("BLOCKING", key + " was already created in " + created.get(key) + " and this is not OR REPLACE");
        created.set(key, f.name);
        if (k[0] === "index" || k[0] === "policy" || k[0] === "trigger") need(bareName(mm[2]));
      });
      if ((m = /^drop (policy|trigger) if exists ("[^"]+"|[a-z_][a-z0-9_]*) on ((?:"?[a-z_][a-z0-9_]*"?\.)?"?[a-z_][a-z0-9_]*"?)/i.exec(s))) {
        dropped.add(m[1].toLowerCase() + " " + bareName(m[2]) + " on " + bareName(m[3]));
        created.delete(m[1].toLowerCase() + " " + bareName(m[2]) + " on " + bareName(m[3]));
      }
      if ((m = new RegExp("^drop table (?:if exists )?" + NAME, "i").exec(s))) tables.delete(bareName(m[1]));

      // ── what it needs ──────────────────────────────────────────────────
      function need(t) {
        if (!t || PLATFORM_SCHEMAS.indexOf(t.split(".")[0]) !== -1 && t.indexOf(".") !== -1) return;
        if (t.indexOf(".") !== -1) return;
        if (!tables.has(t)) at("BLOCKING", "table " + t + " does not exist yet at this point: no earlier migration creates it");
      }
      if ((m = new RegExp("^alter table (?:if exists )?(?:only )?" + NAME, "i").exec(s)) && !/^alter table if exists/i.test(s)) need(bareName(m[1]));
      if ((m = new RegExp("^comment on (?:table|column) " + NAME, "i").exec(s))) {
        var target = bareName(m[1]);
        need(/^comment on column/i.test(s) ? target.split(".").slice(0, -1).join(".") || target : target);
      }
      var refRe = new RegExp("\\breferences " + NAME, "gi"), r;
      while ((r = refRe.exec(s))) {
        var ref = r[1].replace(/"/g, "").toLowerCase();
        if (/^(auth|storage)\./.test(ref)) continue;
        need(bareName(ref));
      }

      // ── what it does to data ───────────────────────────────────────────
      if (/^(update|delete from) /i.test(s)) at("PRODUCTION DATA", "changes existing rows (on a scratch database there are none)");
      if (/^insert into /i.test(s) && /\bselect\b/i.test(s)) at("PRODUCTION DATA", "INSERT ... SELECT copies existing rows");
      if (/'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'/i.test(s)) at("PRODUCTION DATA", "a literal uuid names one production row");
      if (/^insert into /i.test(s) && !/\bon conflict\b/i.test(s)) at("NOT IDEMPOTENT", "INSERT without ON CONFLICT");
      if (/^alter table .* add (constraint|primary key|foreign key|unique|check)\b/i.test(s)) at("NOT IDEMPOTENT", "ADD CONSTRAINT has no IF NOT EXISTS");
      if (/^alter table .* add (?!column if not exists|if not exists|constraint|primary key|foreign key|unique|check)/i.test(s)) at("NOT IDEMPOTENT", "ADD COLUMN without IF NOT EXISTS");
      if (/^alter (table|index|function|type) .* rename\b/i.test(s)) at("NOT IDEMPOTENT", "RENAME");
      if (/^drop (?!.*\bif exists\b)/i.test(s) || /\bdrop (column|constraint) (?!if exists)/i.test(s)) at("NOT IDEMPOTENT", "DROP without IF EXISTS");
      if (/\bcron\.(schedule|unschedule)\b/i.test(s)) at("PRODUCTION DATA", "a pg_cron job: needs the pg_cron extension");
    });
  });
  return findings;
}

/* The one file: header, then every migration under its marker. */
function buildSchema(files, info) {
  info = info || {};
  var findings = analyzeMigrations(files);
  var counts = {};
  findings.forEach(function (x) { counts[x.kind] = (counts[x.kind] || 0) + 1; });
  var last = files.length ? files[files.length - 1].name : "(none)";
  var head = [
    "-- ════════════════════════════════════════════════════════════════════════",
    "-- BizForce schema for a restore drill: every migration, in number order.",
    "-- " + files.length + " migrations, " + (files.length ? files[0].name : "(none)") + " through " + last + ".",
    "-- Last migration: " + last,
    info.commit ? "-- Built from commit " + info.commit + "." : null,
    "-- Paste this whole file into a SCRATCH Supabase project's SQL editor and run it once,",
    "-- then: node scripts/restoreBackup.js --dry-run first, then with --target-url/--target-key.",
    "-- Findings: " + ["BLOCKING", "PRODUCTION DATA", "NOT IDEMPOTENT", "FIXED"].map(function (k) { return k + " " + (counts[k] || 0); }).join(", ") + ".",
    "-- ════════════════════════════════════════════════════════════════════════"
  ].filter(function (l) { return l !== null; });
  findings.filter(function (x) { return x.kind !== "NOT IDEMPOTENT"; }).forEach(function (x) {
    head.push("--   " + x.kind + "  " + x.file + (x.line ? ":" + x.line : "") + "  " + x.text.replace(/\n/g, " "));
  });
  var body = files.map(function (f, i) {
    var sql = f.sql.replace(/\r\n/g, "\n");
    // Only where a real statement has it (a comment may say the words), and only at a line's start.
    var concurrent = findings.some(function (x) { return x.file === f.name && x.kind === "FIXED" && /CONCURRENTLY/.test(x.text); });
    if (concurrent) sql = sql.replace(/^(\s*)create (unique )?index concurrently\b/gim, function (all, sp, u) { return sp + "create " + (u || "") + "index"; });
    var bare = sql.replace(/--[^\n]*|\/\*[\s\S]*?\*\//g, "").trim();
    if (bare && bare[bare.length - 1] !== ";") sql = sql.replace(/\s*$/, "") + "\n;";
    return "\n-- ═══ [" + (i + 1) + "/" + files.length + "] " + f.name + " ═══\n" + sql.replace(/\s*$/, "") + "\n";
  }).join("");
  return { text: head.join("\n") + "\n" + body, findings: findings, counts: counts, last: last, count: files.length };
}

function main(argv, deps) {
  deps = deps || {};
  var out = deps.log || console;
  var dir = deps.dir || MIGRATIONS_DIR;
  var target = DEFAULT_OUT;
  for (var i = 0; i < argv.length; i++) {
    if (argv[i] === "--out" && argv[i + 1]) target = argv[++i];
    else { out.error("usage: node scripts/buildScratchSchema.js [--out <file>]"); return 2; }
  }
  var names = listMigrations(dir);
  var files = names.map(function (name) { return { name: name, sql: fs.readFileSync(path.join(dir, name), "utf8") }; });
  var commit = deps.commit !== undefined ? deps.commit : (function () {
    try { return require("child_process").execFileSync("git", ["rev-parse", "--short", "HEAD"], { cwd: path.join(__dirname, "..") }).toString().trim(); }
    catch (e) { return null; }
  })();
  var built = buildSchema(files, { commit: commit });
  (deps.writeFile || fs.writeFileSync)(target, built.text);
  out.log("wrote " + target + ": " + built.count + " migrations, last " + built.last + ", " + Buffer.byteLength(built.text) + " bytes");
  ["BLOCKING", "PRODUCTION DATA", "FIXED"].forEach(function (k) {
    built.findings.filter(function (x) { return x.kind === k; }).forEach(function (x) {
      out.log("  " + k + "  " + x.file + (x.line ? ":" + x.line : "") + "  " + x.text);
    });
  });
  var perFile = {};
  built.findings.filter(function (x) { return x.kind === "NOT IDEMPOTENT"; }).forEach(function (x) { perFile[x.file] = (perFile[x.file] || 0) + 1; });
  out.log("  NOT IDEMPOTENT  " + (built.counts["NOT IDEMPOTENT"] || 0) + " statement(s) in " + Object.keys(perFile).length +
    " migration(s): fine pasted once into an empty project, not safe to run twice.");
  return built.counts.BLOCKING ? 1 : 0;
}

module.exports = { listMigrations, splitStatements, analyzeMigrations, buildSchema, main, DEFAULT_OUT };

if (require.main === module) process.exit(main(process.argv.slice(2)));
