"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkScratchSchema — scripts/buildScratchSchema.js puts EVERY migration,
   in number order and verbatim, into the one file a restore drill pastes
   into a scratch project, and reports what would not run there.

   WHAT THIS PROVES (the builder is loaded from its source, so a mutation can
   edit it in memory; nothing is written but a temporary fixture folder)
     S1. The real build: one marker per migration file, in number order, each
         file's text verbatim and in that order, the header's count and last
         migration equal to an independent listing of supabase/migrations.
     S2. The real findings: no BLOCKING, the two PRODUCTION DATA statements
         (040's username backfill, 145's transfer backfill), nothing FIXED.
     S3. The rules bite, on fixtures: comments and $$ bodies are not judged;
         a table created twice, and a statement on a table no earlier
         migration created, are BLOCKING; UPDATE, INSERT ... SELECT and a
         literal uuid are PRODUCTION DATA; an unguarded CREATE POLICY is NOT
         IDEMPOTENT and a DROP POLICY IF EXISTS before it makes it fine; a
         missing final ";" is added; CONCURRENTLY is removed.
     S4. main(): writes Downloads/bizforce-schema-all.sql by default, orders
         9_ before 10_, exits 1 on a BLOCKING finding and still writes.
     S5. The restore steps (scripts/restoreBackup.js) name the builder and
         the file.

   MUTATE=<name> edits the builder's source IN MEMORY. MUTATE=all runs each in
   its own process and passes only if every one fails. A search text that does
   not match exactly once is an ERROR, never counted as caught.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const os = require("os");
const path = require("path");
const Module = require("module");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const MIG = path.join(REPO, "supabase", "migrations");
const BUILDER = path.join(__dirname, "buildScratchSchema.js");
const MUTATE = process.env.MUTATE || "";

const MUTATIONS = {
  // the schema builder skips a migration
  "skip-a-migration": [[".filter(function (f) { return /^\\d+_.*\\.sql$/i.test(f); })",
    ".filter(function (f, i) { return /^\\d+_.*\\.sql$/i.test(f) && i !== 40; })"]],
  // a migration's marker is written but its text is not
  "body-dropped": [["\" ═══\\n\" + sql.replace(/\\s*$/, \"\") + \"\\n\";", "\" ═══\\n\" + (i === 7 ? \"\" : sql.replace(/\\s*$/, \"\")) + \"\\n\";"]],
  // files sorted as text: 10_ before 9_
  "lexical-sort": [["(parseInt(a, 10) - parseInt(b, 10)) || ", ""]],
  // a table created twice goes unreported
  "duplicate-unflagged": [["if (tables.has(t) && !guarded) at(\"BLOCKING\"", "if (false) at(\"BLOCKING\""]],
  // a table that does not exist yet goes unreported
  "missing-table-unflagged": [["if (!tables.has(t)) at(\"BLOCKING\"", "if (false) at(\"BLOCKING\""]],
  // a literal uuid goes unreported
  "uuid-unflagged": [["at(\"PRODUCTION DATA\", \"a literal uuid names one production row\");", "void 0;"]],
  // function bodies are judged as if they ran now
  "bodies-judged": [["add(\" $BODY$ \");", "add(sql.slice(i, end + tag[0].length));"]],
  // comments are judged as statements
  "comments-judged": [["if (two === \"--\") {", "if (false) {"]],
  // a BLOCKING finding still exits 0
  "blocking-exit-zero": [["return built.counts.BLOCKING ? 1 : 0;", "return 0;"]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}

let src = fs.readFileSync(BUILDER, "utf8").replace(/\r\n/g, "\n");
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [from, to] of edits) src = s.replaceOnce(src, from, to, MUTATE);
  console.log("\n!! MUTATION: " + MUTATE + " (builder source, in memory)");
}
const mod = new Module(BUILDER, module);
mod.filename = BUILDER;
mod.paths = Module._nodeModulePaths(__dirname);
mod._compile(src, BUILDER);
const B = mod.exports;

function kinds(findings, kind) { return findings.filter(f => f.kind === kind); }
function analyze(list) { return B.analyzeMigrations(list.map(([name, sql]) => ({ name, sql }))); }

(async () => {
  console.log((MUTATE ? "" : "\n") + "══ S1. the real build ══");
  // An independent listing: every NNN_*.sql, by number.
  const expected = fs.readdirSync(MIG).filter(f => /^\d+_.*\.sql$/.test(f)).sort((a, b) => Number(a.split("_")[0]) - Number(b.split("_")[0]));
  const files = B.listMigrations(MIG).map(name => ({ name, sql: fs.readFileSync(path.join(MIG, name), "utf8") }));
  check("S1. the builder lists every migration, in number order", JSON.stringify(files.map(f => f.name)) === JSON.stringify(expected),
    expected.filter(n => !files.some(f => f.name === n)).join(", ") || files.map(f => f.name).join(","));
  const built = B.buildSchema(files, { commit: "abc1234" });
  const text = built.text;
  const markers = [...text.matchAll(/^-- ═══ \[(\d+)\/(\d+)\] (\S+) ═══$/gm)].map(m => ({ n: Number(m[1]), of: Number(m[2]), name: m[3] }));
  check("S1. one marker per migration, numbered 1.." + expected.length, markers.length === expected.length &&
    markers.every((m, i) => m.n === i + 1 && m.of === expected.length && m.name === expected[i]), markers.length + " markers");
  let at = 0, lost = [];
  for (const name of expected) {
    const body = fs.readFileSync(path.join(MIG, name), "utf8").replace(/\r\n/g, "\n").replace(/\s*$/, "");
    const i = text.indexOf(body, at);
    if (i < 0) lost.push(name); else at = i + body.length;
  }
  check("S1. every migration's text is in the file verbatim, in order", lost.length === 0, lost.join(", "));
  check("S1. the header names the count and the last migration", text.indexOf("-- " + expected.length + " migrations, " + expected[0] + " through " + expected[expected.length - 1] + ".") !== -1 &&
    text.indexOf("-- Last migration: " + expected[expected.length - 1]) !== -1, text.split("\n").slice(0, 5).join(" / "));
  check("S1. built.count and built.last agree", built.count === expected.length && built.last === expected[expected.length - 1], built.count + " " + built.last);
  console.log("    " + built.count + " migrations, last " + built.last + ", " + Buffer.byteLength(text) + " bytes");

  console.log("\n══ S2. the real findings ══");
  const blocking = kinds(built.findings, "BLOCKING"), prod = kinds(built.findings, "PRODUCTION DATA"), fixed = kinds(built.findings, "FIXED");
  check("S2. no BLOCKING finding: the file runs on a fresh database", blocking.length === 0, blocking.map(f => f.file + ":" + f.line + " " + f.text).join(" | "));
  /* BEFORE (backend 48334d9): exactly one PRODUCTION DATA statement, 040's username backfill.
     AFTER (migration 145): a second, 145's backfill of bfc_transfers from existing 'Transfer' ledger pairs (INSERT ... SELECT,
     ON CONFLICT DO NOTHING). It reads production rows on purpose; on a scratch database it inserts nothing. */
  check("S2. two PRODUCTION DATA statements: 040's username backfill and 145's transfer backfill",
    prod.length === 2 && prod[0].file === "040_bf_profiles_username.sql" && /^changes existing rows/.test(prod[0].text) &&
    prod[1].file === "145_bfc_transfers.sql" && /^INSERT \.\.\. SELECT copies existing rows/.test(prod[1].text),
    prod.map(f => f.file + ":" + f.line + " " + f.text).join(", "));
  check("S2. nothing needed fixing", fixed.length === 0, fixed.map(f => f.file + " " + f.text).join(" | "));
  check("S2. the header lists the findings", /-- Findings: BLOCKING 0, PRODUCTION DATA 2, NOT IDEMPOTENT \d+, FIXED 0\./.test(text) && /--   PRODUCTION DATA  040_bf_profiles_username\.sql:\d+/.test(text) &&
    /--   PRODUCTION DATA  145_bfc_transfers\.sql:\d+/.test(text));

  console.log("\n══ S3. the rules, on fixtures ══");
  const split = B.splitStatements("-- create table nope (id int);\ncreate table a (id int); /* drop table a; */\n" +
    "create function f() returns void language plpgsql as $$ begin update a set id = 1; delete from a; end $$;\ninsert into a values ('x;y');");
  check("S3. comments are dropped, $$ bodies are one placeholder, a ; inside a string does not split",
    JSON.stringify(split.map(x => x.text.replace(/\s+/g, " ").trim())) === JSON.stringify(["create table a (id int)", "create function f() returns void language plpgsql as $BODY$", "insert into a values ('x;y')"]),
    JSON.stringify(split.map(x => x.text)));
  check("S3. each statement knows its line", split.map(x => x.line).join(",") === "2,3,4", split.map(x => x.line).join(","));
  let f = analyze([["001_a.sql", "create table a (id int);"], ["002_b.sql", "create table a (id int);"]]);
  check("S3. a table created twice without IF NOT EXISTS is BLOCKING", kinds(f, "BLOCKING").length === 1 && kinds(f, "BLOCKING")[0].file === "002_b.sql", JSON.stringify(f));
  f = analyze([["001_a.sql", "create table if not exists a (id int);"], ["002_b.sql", "create table if not exists a (id int);"]]);
  check("S3. ...and with IF NOT EXISTS it is not", kinds(f, "BLOCKING").length === 0, JSON.stringify(kinds(f, "BLOCKING")));
  f = analyze([["001_a.sql", "create table a (id int, b_id int references public.b(id));\nalter table c add column x int;\ncreate index c_x on c (x);\nalter table if exists d enable row level security;\ncreate table e (u uuid references auth.users(id));"]]);
  const missing = kinds(f, "BLOCKING").map(x => (/table (\w+) does not exist/.exec(x.text) || [])[1]);
  check("S3. a reference, ALTER or index on a table no earlier migration created is BLOCKING (IF EXISTS and auth.* are not)",
    JSON.stringify(missing) === JSON.stringify(["b", "c", "c"]), JSON.stringify(missing));
  f = analyze([["001_a.sql", "create table a (id uuid);\nupdate a set id = null;\ndelete from a;\ninsert into a select id from a;\ninsert into a values ('5bbb4ddf-0b4d-4553-a50f-7c089deeaf57');"]]);
  check("S3. UPDATE, DELETE, INSERT ... SELECT and a literal uuid are PRODUCTION DATA", kinds(f, "PRODUCTION DATA").length === 4, JSON.stringify(kinds(f, "PRODUCTION DATA").map(x => x.text.slice(0, 40))));
  f = analyze([["001_a.sql", "create table a (id uuid);\ncreate function g() returns void language plpgsql as $fn$ begin update a set id = '5bbb4ddf-0b4d-4553-a50f-7c089deeaf57'; end $fn$;\n-- update a set id = null;\ndo $$ begin delete from a; end $$;"]]);
  check("S3. inside a function body, a DO block or a comment nothing is judged", kinds(f, "PRODUCTION DATA").length === 0, JSON.stringify(kinds(f, "PRODUCTION DATA")));
  f = analyze([["001_a.sql", "create table if not exists a (id int);\ncreate policy p on a for select using (true);"]]);
  check("S3. CREATE POLICY with no DROP before it is NOT IDEMPOTENT", kinds(f, "NOT IDEMPOTENT").some(x => /CREATE POLICY/.test(x.text)), JSON.stringify(f));
  f = analyze([["001_a.sql", "create table if not exists a (id int);\ndrop policy if exists p on a;\ncreate policy p on a for select using (true);"]]);
  check("S3. ...and with DROP POLICY IF EXISTS before it, it is fine", kinds(f, "NOT IDEMPOTENT").length === 0, JSON.stringify(kinds(f, "NOT IDEMPOTENT")));
  f = analyze([["001_a.sql", "create table if not exists a (id int);\ncreate policy p on a for select using (true);"], ["002_b.sql", "create policy p on a for select using (true);"]]);
  check("S3. the same policy created twice is BLOCKING", kinds(f, "BLOCKING").length === 1 && kinds(f, "BLOCKING")[0].file === "002_b.sql", JSON.stringify(kinds(f, "BLOCKING")));
  const nosemi = B.buildSchema([{ name: "001_a.sql", sql: "create table if not exists a (id int)\n-- the end" }, { name: "002_b.sql", sql: "create index concurrently if not exists a_id on a (id);" }]);
  check("S3. a file without a final \";\" gets one, so it cannot run into the next file", /create table if not exists a \(id int\)\n-- the end\n;\n/.test(nosemi.text) && kinds(nosemi.findings, "FIXED").some(x => x.file === "001_a.sql"), nosemi.text.slice(-200));
  check("S3. CONCURRENTLY is removed and reported", /create index if not exists a_id on a \(id\);/.test(nosemi.text) && !/concurrently/i.test(nosemi.text.split("═══ [2/2]")[1]) &&
    kinds(nosemi.findings, "FIXED").some(x => x.file === "002_b.sql"), JSON.stringify(kinds(nosemi.findings, "FIXED")));
  const said = "-- NOT CONCURRENTLY: CREATE INDEX CONCURRENTLY cannot run in a transaction.\ncreate index if not exists a_id on a (id);";
  const commented = B.buildSchema([{ name: "001_a.sql", sql: "create table if not exists a (id int);" }, { name: "002_b.sql", sql: said }]);
  check("S3. a comment that only says CONCURRENTLY is left exactly as written", commented.text.indexOf(said) !== -1 && kinds(commented.findings, "FIXED").length === 0, JSON.stringify(commented.findings));

  console.log("\n══ S4. main() ══");
  const written = [], log = { lines: [], log(l) { this.lines.push(String(l)); }, error(l) { this.lines.push(String(l)); } };
  const code = B.main([], { log, commit: "abc1234", writeFile: (p, t) => written.push({ p, t }) });
  check("S4. it writes " + B.DEFAULT_OUT, written.length === 1 && written[0].p === path.join(os.homedir(), "Downloads", "bizforce-schema-all.sql"), written.map(w => w.p).join(", "));
  check("S4. what it writes is the build", written.length === 1 && written[0].t === B.buildSchema(files, { commit: "abc1234" }).text);
  check("S4. it exits 0 and says how many migrations", code === 0 && log.lines.some(l => l.indexOf(expected.length + " migrations, last " + expected[expected.length - 1]) !== -1), code + " " + log.lines[0]);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "scratchschema-"));
  try {
    fs.writeFileSync(path.join(tmp, "9_a.sql"), "create table a (id int);\n");
    fs.writeFileSync(path.join(tmp, "10_b.sql"), "create table a (id int);\n");
    fs.writeFileSync(path.join(tmp, "notes.txt"), "not a migration");
    const out = [], quiet = { log() {}, error() {} };
    const bad = B.main(["--out", path.join(tmp, "out.sql")], { dir: tmp, log: quiet, commit: null, writeFile: (p, t) => out.push({ p, t }) });
    check("S4. 9_ comes before 10_ (by number, not as text), and only .sql files count", out.length === 1 && out[0].t.indexOf("[1/2] 9_a.sql") !== -1 && out[0].t.indexOf("[2/2] 10_b.sql") !== -1, out.length && out[0].t.slice(0, 600));
    check("S4. a BLOCKING finding exits 1, and the file is still written", bad === 1 && out.length === 1, bad);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  check("S4. the builder connects to nothing", !/require\(["'](https?|net|dns|@supabase\/supabase-js|pg)["']\)|fetch\(/.test(src));

  console.log("\n══ S5. the restore steps ══");
  const restore = fs.readFileSync(path.join(__dirname, "restoreBackup.js"), "utf8");
  check("S5. restoreBackup.js's steps name the builder and the one file", /node scripts\/buildScratchSchema\.js/.test(restore) && /bizforce-schema-all\.sql/.test(restore));

  console.log("\n" + passes + " passed, " + failures + " failed");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
/* A crash is a FAIL (exit 1), not exit 3: 3 is _shared.js's "mutation anchor did not match". */
})().catch(e => { console.log("    FAIL  the harness stopped: " + ((e && e.message) || e)); console.error((e && e.stack) || e); process.exit(1); });
