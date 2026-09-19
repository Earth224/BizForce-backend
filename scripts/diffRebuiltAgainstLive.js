/* ══════════════════════════════════════════════════════════════════════════
   diffRebuiltAgainstLive.js — compare a rebuilt scratch schema against live.

   WHY THIS EXISTS. A green rebuild proves only that no file errors. It cannot
   see a file that ran as a silent no-op on the rebuild while having done real
   work on live: the premise is absent, the guard is false, nothing is created,
   and nothing complains. The evidence for one of those is a column live has
   and the rebuild does not, or a type that differs. That is what this finds.

   USAGE
     node scripts/diffRebuiltAgainstLive.js <scratch-env-file> [constraints.csv]

   THREE SOURCES, because no single one can see everything:

     scratch      SQL over the pooler. Sees everything: types, nullability,
                  defaults, pg_constraint.
     live         PostgREST's OpenAPI document, using SUPABASE_URL and
                  SUPABASE_SERVICE_KEY from the repo's .env. Sees column names,
                  types and most defaults. It CANNOT see nullability for a
                  column that has a default -- `required` lists only the
                  columns that are NOT NULL *and* have no default -- so those
                  are reported as unknown per column rather than as a match.
     csv          supabase/live_constraints_2026-09-15.csv, 225 rows read from
                  pg_constraint on the live database on 2026-09-15. PostgREST
                  cannot expose constraints at all, so this is the only view of
                  the live constraint set, and it is a snapshot with a date on
                  it rather than a live read.

   EXPECTED DIFFERENCES. Three are recorded supersets -- the migration
   directory declares them and live has not had them applied -- and are counted
   separately from the unexpected ones. See EXPECTED below.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const { Client } = require("pg");

const REPO = path.join(__dirname, "..");
const ENV_FILE = process.argv[2];
const CSV = process.argv[3] || path.join(REPO, "supabase", "live_constraints_2026-09-15.csv");

if (!ENV_FILE || !fs.existsSync(ENV_FILE)) {
  console.error("usage: node scripts/diffRebuiltAgainstLive.js <scratch-env-file> [constraints.csv]");
  process.exit(64);
}

/* Differences that are already understood and recorded. Anything not on this
   list is unexpected and is what the report is for. */
const EXPECTED = [
  { table: "agent_memory",      column: "assignment_id" },
  { table: "business_profiles", column: "business_goals" },
  { table: "business_profiles", column: "competitors" },
];
const isExpected = (t, c) => EXPECTED.some(e => e.table === t && e.column === c);

function readEnv(file) {
  const out = {};
  for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    const i = line.indexOf("=");
    if (i > 0) out[line.slice(0, i)] = line.slice(i + 1).trim();
  }
  return out;
}

/* RFC4180-ish: quoted fields, doubled quotes inside them. */
function parseCsv(text) {
  const rows = []; let row = [], cur = "", q = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (q) {
      if (ch === '"') { if (text[i + 1] === '"') { cur += '"'; i++; } else q = false; }
      else cur += ch;
    } else if (ch === '"') q = true;
    else if (ch === ",") { row.push(cur); cur = ""; }
    else if (ch === "\n") { row.push(cur); rows.push(row); row = []; cur = ""; }
    else if (ch !== "\r") cur += ch;
  }
  if (cur || row.length) { row.push(cur); rows.push(row); }
  return rows.filter(r => r.length > 1 || (r.length === 1 && r[0] !== ""));
}

/* Defaults are compared with casts and whitespace normalised away, so that
   '{}'::jsonb and '{}' do not read as a difference. Both raw values are
   printed whenever a difference is reported. */
function normDefault(d) {
  if (d === null || d === undefined) return null;  // '' is a real default, not an absent one
  let s = String(d).trim().toLowerCase();
  /* A stored default holds a function OID, not text; what we read back is that
     OID rendered under the reading session's search_path. 000 puts extensions
     on the path, so the rebuild renders usage_logs.id's default as
     uuid_generate_v4() while live, read without it, renders the same OID as
     extensions.uuid_generate_v4(). Same function, two renderings. */
  s = s.replace(/\bextensions\./g, "");
  s = s.replace(/::[a-z_ ]+(\[\])?/g, "");
  s = s.replace(/^\((.*)\)$/, "$1");
  s = s.replace(/\s+/g, " ").replace(/'/g, "");
  return s;
}
function normType(t) {
  return String(t || "").trim().toLowerCase().replace(/\s+/g, " ");
}

const scratchEnv = readEnv(ENV_FILE);
const liveEnv = readEnv(path.join(REPO, ".env"));

(async () => {
  /* ── source 1: the rebuilt scratch schema, over SQL ───────────────────── */
  const client = new Client({
    host: process.env.SCRATCH_DB_HOST || "aws-0-us-east-1.pooler.supabase.com",
    port: 5432, user: "postgres." + scratchEnv.SCRATCH_REF, password: scratchEnv.SCRATCH_DB_URL,
    database: "postgres", ssl: { rejectUnauthorized: false }, connectionTimeoutMillis: 20000,
  });
  await client.connect();

  const sTables = (await client.query(
    "select table_name from information_schema.tables " +
    "where table_schema='public' and table_type='BASE TABLE' order by 1")).rows.map(r => r.table_name);

  /* format_type gives text[] and character varying(255) the way a human writes
     them, which is closer to what PostgREST reports than data_type is. */
  const sCols = {};
  for (const r of (await client.query(
    "select c.relname as table_name, a.attname as column_name, " +
    "       format_type(a.atttypid, a.atttypmod) as type, " +
    "       not a.attnotnull as nullable, " +
    "       pg_get_expr(d.adbin, d.adrelid) as default_expr " +
    "  from pg_attribute a " +
    "  join pg_class c on c.oid = a.attrelid " +
    "  join pg_namespace n on n.oid = c.relnamespace " +
    "  left join pg_attrdef d on d.adrelid = a.attrelid and d.adnum = a.attnum " +
    " where n.nspname='public' and c.relkind='r' and a.attnum > 0 and not a.attisdropped " +
    " order by 1, a.attnum")).rows) {
    (sCols[r.table_name] = sCols[r.table_name] || {})[r.column_name] =
      { type: r.type, nullable: r.nullable, def: r.default_expr };
  }

  const sCons = {};
  for (const r of (await client.query(
    "select c.conrelid::regclass::text as table_name, c.conname, c.contype, " +
    "       pg_get_constraintdef(c.oid, true) as definition " +
    "  from pg_constraint c " +
    "  join pg_namespace n on n.oid = c.connamespace " +
    " where n.nspname='public' order by 1,2")).rows) {
    const t = r.table_name.replace(/^public\./, "").replace(/"/g, "");
    sCons[t + "|" + r.conname] = { table: t, name: r.conname, type: r.contype, def: r.definition };
  }
  await client.end();

  /* ── source 2: live, over PostgREST ───────────────────────────────────── */
  const res = await fetch(liveEnv.SUPABASE_URL + "/rest/v1/", {
    headers: { apikey: liveEnv.SUPABASE_SERVICE_KEY, Authorization: "Bearer " + liveEnv.SUPABASE_SERVICE_KEY },
  });
  if (!res.ok) { console.error("live PostgREST returned " + res.status + " -- cannot read the column layer"); process.exit(3); }
  const api = await res.json();
  const defs = api.definitions || {};
  const lTables = Object.keys(defs).sort();

  /* Which types live never exposes a default for. PostgREST reports defaults
     for text, uuid, timestamps, integers, booleans and numerics, but for jsonb
     (35 columns) and text[] (3) it reports none at all -- not one across the
     whole database. For those types an absent live default means "cannot see
     it", not "there is none", and saying otherwise would invent differences.
     Derived from the document rather than hardcoded, so it stays true if
     PostgREST's behaviour changes. */
  const defaultsSeenFor = {}, columnsOfFormat = {};
  for (const d of Object.values(defs)) {
    for (const p of Object.values(d.properties || {})) {
      columnsOfFormat[p.format] = (columnsOfFormat[p.format] || 0) + 1;
      if (p.default !== undefined) defaultsSeenFor[p.format] = (defaultsSeenFor[p.format] || 0) + 1;
    }
  }
  const defaultBlind = f => (columnsOfFormat[f] || 0) > 0 && !defaultsSeenFor[f];

  const lCols = {};
  for (const [t, d] of Object.entries(defs)) {
    const required = new Set(d.required || []);
    lCols[t] = {};
    for (const [c, p] of Object.entries(d.properties || {})) {
      let type = p.format;
      if (p.maxLength !== undefined) type += "(" + p.maxLength + ")";
      const hasDefault = p.default !== undefined;
      lCols[t][c] = {
        type,
        def: hasDefault ? String(p.default) : null,
        /* required means NOT NULL and no default. Absent from required with a
           default means PostgREST simply cannot say. */
        nullable: required.has(c) ? false : (hasDefault ? null : true),
      };
    }
  }

  /* ── source 3: the constraint snapshot ────────────────────────────────── */
  const csvRows = parseCsv(fs.readFileSync(CSV, "utf8"));
  const header = csvRows.shift();
  const HEADER_LINE = header.join(",");
  const csvArtifacts = [];
  const idx = n => header.indexOf(n);
  const cCons = {};
  for (const r of csvRows) {
    /* One row carries the export's own header glued to the end of its
       definition, because the snapshot was stitched from two pages and the
       second page's header line lost its newline. Strip it and say so; the
       alternative is reporting a schema difference that is really a flaw in
       how the file was captured. */
    let def = r[idx("definition")];
    const rest = r.slice(idx("definition") + 1).join(",");
    if (rest) def = def + "," + rest;
    if (def.endsWith(HEADER_LINE)) {
      def = def.slice(0, -HEADER_LINE.length);
      csvArtifacts.push(r[idx("table_name")] + "." + r[idx("conname")]);
    }
    cCons[r[idx("table_name")] + "|" + r[idx("conname")]] =
      { table: r[idx("table_name")], name: r[idx("conname")], type: r[idx("contype")], def };
  }
  if (csvArtifacts.length) {
    console.log("NOTE  the constraint snapshot carries its own header glued into " +
      csvArtifacts.length + " definition(s): " + csvArtifacts.join(", ") +
      "\n      -- stripped for comparison; the csv is left as it was read.\n");
  }

  /* ── layer 1: tables ──────────────────────────────────────────────────── */
  const onlyScratchT = sTables.filter(t => !lTables.includes(t));
  const onlyLiveT = lTables.filter(t => !sTables.includes(t));

  /* ── layer 2: columns ─────────────────────────────────────────────────── */
  const colOnlyScratch = [], colOnlyLive = [], typeDiff = [], typeInvisible = [], defDiff = [], defNotVisible = [], nullDiff = [], nullUnknown = [];
  let columnsCompared = 0;
  for (const t of sTables.filter(t => lTables.includes(t))) {
    const s = sCols[t] || {}, l = lCols[t] || {};
    for (const c of Object.keys(s)) {
      if (!(c in l)) { colOnlyScratch.push({ t, c, d: s[c] }); continue; }
      columnsCompared++;
      const a = s[c], b = l[c];
      const ta = normType(a.type), tb = normType(b.type);
      if (ta !== tb) {
        /* PostgREST strips every type modifier, so numeric(12,2) reaches us as
           numeric. That is not a difference we can see, and reporting it as one
           would be reporting a mismatch we cannot actually observe. */
        if (ta.replace(/\([^)]*\)/g, "") === tb) typeInvisible.push({ t, c, scratch: a.type, live: b.type });
        else typeDiff.push({ t, c, scratch: a.type, live: b.type });
      }
      const na = normDefault(a.def), nb = normDefault(b.def);
      if (na !== nb) {
        if (nb === null && defaultBlind(b.type)) defNotVisible.push({ t, c, scratch: a.def, type: b.type });
        else defDiff.push({ t, c, scratch: a.def, live: b.def });
      }
      if (b.nullable === null) nullUnknown.push({ t, c, scratch: a.nullable ? "nullable" : "not null" });
      else if (a.nullable !== b.nullable) nullDiff.push({ t, c, scratch: a.nullable, live: b.nullable });
    }
    for (const c of Object.keys(l)) if (!(c in s)) colOnlyLive.push({ t, c, d: l[c] });
  }

  /* ── layer 3: constraints ─────────────────────────────────────────────── */
  const sKeys = Object.keys(sCons), cKeys = Object.keys(cCons);
  const conOnlyScratch = sKeys.filter(k => !(k in cCons)).map(k => sCons[k]);
  const conOnlyLive = cKeys.filter(k => !(k in sCons)).map(k => cCons[k]);
  const conDiff = sKeys.filter(k => k in cCons)
    .filter(k => sCons[k].def.replace(/\s+/g, " ").trim() !== cCons[k].def.replace(/\s+/g, " ").trim())
    .map(k => ({ table: sCons[k].table, name: sCons[k].name, scratch: sCons[k].def, live: cCons[k].def }));

  /* ── report ───────────────────────────────────────────────────────────── */
  const unexpectedCols = [...colOnlyScratch, ...colOnlyLive].filter(x => !isExpected(x.t, x.c));
  const expectedCols = [...colOnlyScratch, ...colOnlyLive].filter(x => isExpected(x.t, x.c));

  const line = s => console.log(s);
  line("COUNTS");
  line("  layer 1 tables      : " + sTables.length + " scratch, " + lTables.length + " live  ->  " +
       onlyScratchT.length + " only-scratch, " + onlyLiveT.length + " only-live");
  line("  layer 2 columns     : " + columnsCompared + " compared  ->  " +
       unexpectedCols.length + " unexpected presence, " + expectedCols.length + " expected presence, " +
       typeDiff.length + " type, " + defDiff.length + " default, " + nullDiff.length + " nullability");
  line("                        (PostgREST cannot show: " + nullUnknown.length + " live nullabilities, " +
       typeInvisible.length + " type modifiers, " + defNotVisible.length + " defaults on jsonb/array columns)");
  line("  layer 3 constraints : " + sKeys.length + " scratch, " + cKeys.length + " csv  ->  " +
       conOnlyScratch.length + " only-scratch, " + conOnlyLive.length + " only-live, " + conDiff.length + " differing");

  const sect = (title, rows, fmt) => {
    line("\n── " + title + " (" + rows.length + ") ──");
    if (!rows.length) { line("  none"); return; }
    rows.forEach(r => line("  " + fmt(r)));
  };

  sect("layer 1: tables only in the rebuild", onlyScratchT, t => t);
  sect("layer 1: tables only on live", onlyLiveT, t => t);
  sect("layer 2: columns only in the rebuild -- UNEXPECTED",
    colOnlyScratch.filter(x => !isExpected(x.t, x.c)), x => x.t + "." + x.c + "  " + x.d.type);
  sect("layer 2: columns only on live -- UNEXPECTED (a file that no-opped on the rebuild)",
    colOnlyLive.filter(x => !isExpected(x.t, x.c)), x => x.t + "." + x.c + "  " + x.d.type);
  sect("layer 2: columns differing by presence -- EXPECTED, recorded supersets",
    expectedCols, x => x.t + "." + x.c + "  " + x.d.type);
  sect("layer 2: type differences", typeDiff, x => x.t + "." + x.c + "  scratch=" + x.scratch + "  live=" + x.live);
  sect("layer 2: type modifiers PostgREST cannot show -- NOT a reported match", typeInvisible,
    x => x.t + "." + x.c + "  scratch=" + x.scratch + "  live=" + x.live + " (modifier not visible)");
  sect("layer 2: default differences", defDiff,
    x => x.t + "." + x.c + "  scratch=" + JSON.stringify(x.scratch) + "  live=" + JSON.stringify(x.live));
  sect("layer 2: defaults on types whose live default PostgREST never shows -- NOT a reported match", defNotVisible,
    x => x.t + "." + x.c + "  scratch=" + JSON.stringify(x.scratch) + "  live=(" + x.type + ", not visible)");
  sect("layer 2: nullability differences", nullDiff,
    x => x.t + "." + x.c + "  scratch=" + (x.scratch ? "nullable" : "not null") + "  live=" + (x.live ? "nullable" : "not null"));
  sect("layer 3: constraints only in the rebuild", conOnlyScratch, c => c.table + "  " + c.name + "  " + c.def);
  sect("layer 3: constraints only on live (csv)", conOnlyLive, c => c.table + "  " + c.name + "  " + c.def);
  sect("layer 3: constraints whose definition differs", conDiff,
    c => c.table + "  " + c.name + "\n        scratch: " + c.scratch + "\n        live   : " + c.live);

  const unexpected = onlyScratchT.length + onlyLiveT.length + unexpectedCols.length +
    typeDiff.length + defDiff.length + nullDiff.length +
    conOnlyScratch.length + conOnlyLive.length + conDiff.length;
  line("\nUNEXPECTED DIFFERENCES: " + unexpected);
  process.exit(unexpected ? 1 : 0);
})().catch(e => { console.error("DIFF ERROR: " + e.message); process.exit(3); });
