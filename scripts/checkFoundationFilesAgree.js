/* ══════════════════════════════════════════════════════════════════════════
   checkFoundationFilesAgree.js — 000 and 071 define the same twenty tables.

   WHY TWO FILES. 071_transcribe_foundation_tables.sql transcribed the
   foundation tables from the live database but is numbered after ten files
   that depend on them, so a fresh run halted at 040. 000_foundation_tables.sql
   is a verbatim copy of 071's executable body placed at the front of the
   sequence. Two files that define the same twenty tables will drift the first
   time somebody edits one of them, and the drift is invisible until a rebuild
   — which is exactly when it costs the most.

   WHAT THIS ASSERTS, in two layers:

     1. TABLES AND COLUMNS. Each file's CREATE TABLE statements are parsed
        into table -> [column name, type, NOT NULL, DEFAULT]. The two maps
        must be identical: same tables, same columns in the same order with
        the same definition. This is the assertion the file was asked for and
        it is what a rebuild depends on.

     2. THE WHOLE EXECUTABLE BODY. Beyond CREATE TABLE, both files carry the
        same constraints, indexes, RLS statements and policies. Every
        executable statement in each file (comments stripped, whitespace
        normalised) is compared as a multiset. If the two ever differ by one
        statement, this names it.

   No database is touched. This reads two files and compares them.

   MUTATION. MUTATE=drift-column removes one column line from 000's copy of
   ai_tasks before parsing; MUTATE=drift-statement drops one policy DO block
   from 000's copy. Each must turn the corresponding layer red, and the
   other layer's result is printed so it can be seen which layer caught it.
   Run one of them after any edit to this file.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");

const DIR = path.join(__dirname, "..", "supabase", "migrations");
const FILE_000 = path.join(DIR, "000_foundation_tables.sql");
const FILE_071 = path.join(DIR, "071_transcribe_foundation_tables.sql");
const MUTATE = process.env.MUTATE || "";

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

function strip(sql) {
  return sql.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/--[^\n]*/g, " ");
}

/* Splits on top-level semicolons, keeping DO $$ ... $$ blocks and string
   literals whole. */
function statements(sql) {
  const out = []; let i = 0, cur = "", dollar = null, str = false;
  while (i < sql.length) {
    const ch = sql[i];
    if (dollar) { if (sql.startsWith(dollar, i)) { cur += dollar; i += dollar.length; dollar = null; continue; } cur += ch; i++; continue; }
    if (str) { cur += ch; if (ch === "'") str = false; i++; continue; }
    const dm = sql.slice(i).match(/^\$[a-z_]*\$/i);
    if (dm) { dollar = dm[0]; cur += dm[0]; i += dm[0].length; continue; }
    if (ch === "'") { str = true; cur += ch; i++; continue; }
    if (ch === ";") { out.push(cur.trim()); cur = ""; i++; continue; }
    cur += ch; i++;
  }
  if (cur.trim()) out.push(cur.trim());
  return out.filter(Boolean).map(s => s.replace(/\s+/g, " ").trim());
}

function balanced(s, idx) {
  let d = 0, i = idx;
  for (; i < s.length; i++) { if (s[i] === "(") d++; else if (s[i] === ")") { d--; if (!d) break; } }
  return s.slice(idx + 1, i);
}
function splitTop(body) {
  const items = []; let d = 0, cur = "";
  for (const ch of body) { if (ch === "(") d++; if (ch === ")") d--; if (ch === "," && d === 0) { items.push(cur); cur = ""; } else cur += ch; }
  items.push(cur);
  return items.map(x => x.trim()).filter(Boolean);
}

/* table -> [{ name, def }] where def is the normalised remainder of the
   column line (type, NOT NULL, DEFAULT ...). Table-level constraint items are
   not columns and are compared in layer 2 instead. */
function tables(sql) {
  const out = {};
  const re = /create\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?"?([a-z_]+)"?\s*\(/gi;
  let m;
  while ((m = re.exec(sql))) {
    const name = m[1].toLowerCase();
    const body = balanced(sql, re.lastIndex - 1);
    const cols = [];
    for (const it of splitTop(body)) {
      const tok = it.split(/\s+/)[0].toLowerCase();
      if (/^(constraint|primary|unique|check|foreign|exclude|like)$/.test(tok)) continue;
      const cm = it.match(/^"?([a-z_][a-z0-9_]*)"?\s+([\s\S]+)$/i);
      if (!cm) continue;
      cols.push({ name: cm[1].toLowerCase(), def: cm[2].replace(/\s+/g, " ").trim().toLowerCase() });
    }
    out[name] = cols;
  }
  return out;
}

function load(file) { return strip(fs.readFileSync(file, "utf8")); }

let sql000 = load(FILE_000);
const sql071 = load(FILE_071);

/* ── the mutation, applied to 000's text before parsing ─────────────────── */
if (MUTATE === "drift-column") {
  const before = sql000;
  sql000 = sql000.replace(/(create table if not exists public\.ai_tasks \([\s\S]*?)\n\s*result text,?\n/i, "$1\n");
  if (sql000 === before) { console.error("MUTATION REFUSED: could not find ai_tasks.result to remove."); process.exit(1); }
  console.log("\n!! MUTATION: ai_tasks.result removed from 000's copy — layer 1 must fail.");
} else if (MUTATE === "drift-statement") {
  const before = sql000;
  const idx = sql000.search(/do \$\$ begin if not exists \(select 1 from pg_policy where polname = 'Public read videos'/i);
  if (idx === -1) { console.error("MUTATION REFUSED: could not find the 'Public read videos' policy block."); process.exit(1); }
  const end = sql000.indexOf("end $$;", idx) + "end $$;".length;
  sql000 = sql000.slice(0, idx) + sql000.slice(end);
  if (sql000 === before) { console.error("MUTATION REFUSED: nothing removed."); process.exit(1); }
  console.log("\n!! MUTATION: the 'Public read videos' policy removed from 000's copy — layer 2 must fail.");
} else if (MUTATE) {
  console.error("Unknown MUTATE value: " + MUTATE + " (use drift-column or drift-statement)");
  process.exit(1);
}

/* ── layer 1: tables and columns ────────────────────────────────────────── */
console.log("\n══ 1. tables and columns ══");
const t000 = tables(sql000), t071 = tables(sql071);
const n000 = Object.keys(t000).sort(), n071 = Object.keys(t071).sort();
console.log("    000 defines " + n000.length + " tables; 071 defines " + n071.length + ".");
check("071 defines exactly twenty tables", n071.length === 20, String(n071.length));
check("000 defines the same set of tables", JSON.stringify(n000) === JSON.stringify(n071),
  "only in 000: " + n000.filter(x => !n071.includes(x)).join(",") + " | only in 071: " + n071.filter(x => !n000.includes(x)).join(","));

let columnsCompared = 0;
for (const t of n071) {
  const a = t000[t] || [], b = t071[t];
  const sa = a.map(c => c.name + " " + c.def), sb = b.map(c => c.name + " " + c.def);
  columnsCompared += b.length;
  const same = JSON.stringify(sa) === JSON.stringify(sb);
  if (!same) {
    const onlyA = sa.filter(x => !sb.includes(x)), onlyB = sb.filter(x => !sa.includes(x));
    check(t + ": same columns, same order, same definitions", false,
      (onlyA.length ? "only in 000: " + onlyA.join("; ") : "") + (onlyB.length ? " | only in 071: " + onlyB.join("; ") : "") +
      (!onlyA.length && !onlyB.length ? "same columns, different order" : ""));
  }
}
const allColumnsMatch = n071.every(t =>
  JSON.stringify((t000[t] || []).map(c => c.name + " " + c.def)) === JSON.stringify(t071[t].map(c => c.name + " " + c.def)));
check("every column of every table matches (" + columnsCompared + " columns compared)", allColumnsMatch);

/* ── layer 2: every executable statement ────────────────────────────────── */
console.log("\n══ 2. every executable statement ══");
const s000 = statements(sql000), s071 = statements(sql071);
console.log("    000 has " + s000.length + " statements; 071 has " + s071.length + ".");
const count = arr => arr.reduce((m, s) => { m[s] = (m[s] || 0) + 1; return m; }, {});
const c000 = count(s000), c071 = count(s071);
const only000 = Object.keys(c000).filter(s => (c071[s] || 0) < c000[s]);
const only071 = Object.keys(c071).filter(s => (c000[s] || 0) < c071[s]);
check("same number of statements", s000.length === s071.length, s000.length + " vs " + s071.length);
check("no statement is only in 000", only000.length === 0, only000.map(s => s.slice(0, 90)).join(" || "));
check("no statement is only in 071", only071.length === 0, only071.map(s => s.slice(0, 90)).join(" || "));
check("statements are in the same order", JSON.stringify(s000) === JSON.stringify(s071));

const kinds = arr => arr.reduce((m, s) => { const k = s.match(/^(create table|create unique index|create index|create extension|set search_path|alter table [a-z_.]+ enable row level security|do \$\$)/i); const key = k ? k[1].toLowerCase().replace(/alter table [a-z_.]+ /, "alter table … ") : "other"; m[key] = (m[key] || 0) + 1; return m; }, {});
console.log("    by kind (071): " + JSON.stringify(kinds(s071)));

console.log("");
if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
console.log("ALL CHECKS PASSED");
process.exit(0);
