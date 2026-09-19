/* ══════════════════════════════════════════════════════════════════════════
   diffRebuiltAgainstLive.js — compare a rebuilt scratch schema against live.

   WHY THIS EXISTS. A green rebuild proves only that no file errors. It cannot
   see a file that ran as a silent no-op on the rebuild while having done real
   work on live: the premise is absent, the guard is false, nothing is created,
   and nothing complains. The evidence for one of those is a column live has
   and the rebuild does not, or a type or attribute that differs.

   USAGE
     node scripts/diffRebuiltAgainstLive.js <scratch-env-file> [constraints.csv] [columns.csv]

   ── WHAT POSTGREST CAN AND CANNOT ESTABLISH ─────────────────────────────────

   The live column layer is read from PostgREST's OpenAPI document, because that
   is what a service key reaches. It is not an information_schema substitute, and
   an earlier version of this script treated it as one and invented 22 attribute
   differences that did not exist. The document states, per column:

     name      exact.
     type      base type only. Every modifier is stripped, so numeric(12,2)
               arrives as numeric and varchar(n) as character varying.
     required  documented as the columns required on INSERT: NOT NULL *and*
               without a default. It is NOT a nullability report, and on this
               database it does not even match its own documentation -- see
               MEASURED below.
     default   present for some columns. ABSENCE PROVES NOTHING -- jsonb and
               text[] columns never state one, and text columns that are
               NOT NULL DEFAULT '' on live have been observed without one.

   From that, exactly two live facts are knowable, and this script derives them
   rather than assuming them -- see requiredMeansNoDefault below:

     c IN required      ->  NOT NULL. True whether `required` means "NOT NULL" or
                            "NOT NULL and no default", so this survives even
                            when the derivation below refuses. Whether it also
                            implies NO default depends on which reading holds.
     c NOT IN required  ->  nullability UNKNOWN. The column is either nullable
                            or NOT NULL with a default, and the document cannot
                            say which. If it states a default, the default is
                            known; if it states none, that is unknown too.

   MEASURED ON THIS DATABASE, the strict reading does not hold: 265 of 451
   required columns state a default, so `required` here is closer to plain
   NOT NULL. Worse, it is incomplete -- it lists only id for digital_cards while
   live's information_schema reports ten NOT NULL columns on that table -- so it
   is treated as a source of positives only, never of negatives.

   So on PostgREST alone this script establishes: the table set, the column set,
   base types, and the defaults of columns that state one. It CANNOT establish
   nullability for any column outside `required`, any type modifier, or the
   absence of a default. Those go to not-established buckets and are counted as
   neither agreement nor difference.

   WHAT IT WOULD TAKE to close the gap: a read-only SQL connection to live,
   which makes the live column layer the same information_schema read already
   done on scratch. Short of that, pass a columns.csv exported from live's
   information_schema (table_name,column_name,data_type,is_nullable,
   column_default); this script uses it for every table it covers and falls
   back to PostgREST for the rest.

   THE OTHER TWO SOURCES
     scratch   SQL over the pooler. Sees everything.
     csv       supabase/live_constraints_2026-09-15.csv, 225 live constraints
               read from pg_constraint on 2026-09-15. PostgREST cannot expose
               constraints at all, so this is the only view of them, and it is
               a dated snapshot rather than a live read.

   MUTATION. Three, each of which must change the result:
     MUTATE=nullability-from-absence  restores the misread this file was
                                      rewritten to eliminate: a column absent
                                      from `required` stating no default is
                                      called nullable, which makes every
                                      NOT NULL column carrying a default look
                                      nullable. Must produce nullability
                                      differences the correct reading does not.
     MUTATE=default-from-absence      treats an absent default as no default.
                                      Must produce default differences.
     MUTATE=break-required-invariant  states a default on a column that is in
                                      `required`. The derivation must refuse,
                                      and with it the inference that a required
                                      column has no default -- moving defaults
                                      into the not-established bucket. On this
                                      database the derivation already refuses
                                      on its own, so this mutation is a
                                      regression guard for a database where it
                                      would otherwise hold.
   Run all three after any edit to the column layer.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const { Client } = require("pg");

const REPO = path.join(__dirname, "..");
const ENV_FILE = process.argv[2];
const CSV = process.argv[3] || path.join(REPO, "supabase", "live_constraints_2026-09-15.csv");
const COLS_CSV = process.argv[4] || null;
const MUTATE = process.env.MUTATE || "";
const MUTATIONS = ["nullability-from-absence", "default-from-absence", "break-required-invariant"];

if (!ENV_FILE || !fs.existsSync(ENV_FILE)) {
  console.error("usage: node scripts/diffRebuiltAgainstLive.js <scratch-env-file> [constraints.csv] [columns.csv]");
  process.exit(64);
}
if (MUTATE && !MUTATIONS.includes(MUTATE)) {
  console.error("Unknown MUTATE value: " + MUTATE + " (use " + MUTATIONS.join(", ") + ")");
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
  const DQ = String.fromCharCode(34);
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (q) {
      if (ch === DQ) { if (text[i + 1] === DQ) { cur += DQ; i++; } else q = false; }
      else cur += ch;
    } else if (ch === DQ) q = true;
    else if (ch === ",") { row.push(cur); cur = ""; }
    else if (ch === "\n") { row.push(cur); rows.push(row); row = []; cur = ""; }
    else if (ch !== "\r") cur += ch;
  }
  if (cur || row.length) { row.push(cur); rows.push(row); }
  return rows.filter(r => r.length > 1 || (r.length === 1 && r[0] !== ""));
}

function normDefault(d) {
  if (d === null || d === undefined) return null;  // '' is a real default, not an absent one
  let s = String(d).trim().toLowerCase();
  /* A stored default holds a function OID, not text; what comes back is that
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
  if (MUTATE) console.log("!! MUTATION ACTIVE: " + MUTATE + "\n");

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

  /* ── source 2: live columns, over PostgREST ───────────────────────────── */
  const res = await fetch(liveEnv.SUPABASE_URL + "/rest/v1/", {
    headers: { apikey: liveEnv.SUPABASE_SERVICE_KEY, Authorization: "Bearer " + liveEnv.SUPABASE_SERVICE_KEY },
  });
  if (!res.ok) { console.error("live PostgREST returned " + res.status + " -- cannot read the column layer"); process.exit(3); }
  const api = await res.json();
  const defs = api.definitions || {};
  const lTables = Object.keys(defs).sort();

  if (MUTATE === "break-required-invariant") {
    for (const d of Object.values(defs)) {
      const c = (d.required || [])[0];
      if (c && d.properties && d.properties[c]) { d.properties[c].default = "mutated"; break; }
    }
  }

  /* WHAT `required` MEANS, derived rather than assumed. PostgREST documents it
     as NOT NULL *and* without a default. If that holds, no column can appear in
     `required` while also stating a default -- so the document can be asked
     whether it holds instead of being taken on faith. Every nullability
     conclusion below rests on this, so a breach is loud and the nullability
     comparison stands down rather than guessing. */
  let requiredTotal = 0, requiredWithDefault = 0;
  const breaches = [];
  for (const [t, d] of Object.entries(defs)) {
    for (const c of (d.required || [])) {
      requiredTotal++;
      const p = (d.properties || {})[c];
      if (p && p.default !== undefined) { requiredWithDefault++; breaches.push(t + "." + c); }
    }
  }
  const requiredMeansNoDefault = requiredTotal > 0 && requiredWithDefault === 0;
  console.log("PostgREST `required` semantics: " + requiredTotal + " required columns, " +
    requiredWithDefault + " of them stating a default");
  if (requiredMeansNoDefault) {
    console.log("  -> holds: `required` means NOT NULL and no default, so membership also");
    console.log("     establishes that a column has no default.\n");
  } else {
    console.log("  -> REFUSED: " + breaches.slice(0, 3).join(", ") + " are in `required` while");
    console.log("     stating a default, so membership does NOT establish the absence of one.");
    console.log("     Defaults are only read where the document states them. Membership still");
    console.log("     implies NOT NULL, which is true under either reading, so that is kept.\n");
  }

  /* Per-format default statistics, kept as printed evidence: they are the
     reason an absent default cannot be read as "no default". */
  const defaultsSeenFor = {}, columnsOfFormat = {};
  for (const d of Object.values(defs)) {
    for (const p of Object.values(d.properties || {})) {
      columnsOfFormat[p.format] = (columnsOfFormat[p.format] || 0) + 1;
      if (p.default !== undefined) defaultsSeenFor[p.format] = (defaultsSeenFor[p.format] || 0) + 1;
    }
  }
  const blindFormats = Object.keys(columnsOfFormat).filter(f => !defaultsSeenFor[f]);

  const lCols = {};
  for (const [t, d] of Object.entries(defs)) {
    const required = new Set(d.required || []);
    lCols[t] = {};
    for (const [c, p] of Object.entries(d.properties || {})) {
      let type = p.format;
      if (p.maxLength !== undefined) type += "(" + p.maxLength + ")";
      const hasDefault = p.default !== undefined;
      const inRequired = required.has(c);

      /* Membership in `required` implies NOT NULL under either reading of it,
         so it is the one live nullability fact that survives the invariant
         failing. Non-membership implies nothing and never yields a value. */
      let nullKnown = inRequired;
      let defKnown = hasDefault || (inRequired && requiredMeansNoDefault);

      if (MUTATE === "nullability-from-absence") nullKnown = inRequired || !hasDefault;
      if (MUTATE === "default-from-absence") defKnown = true;

      lCols[t][c] = {
        type, nullKnown, defKnown,
        nullable: inRequired ? false : true,
        def: hasDefault ? String(p.default) : null,
        source: "postgrest",
      };
    }
  }

  /* ── source 2b: live columns from an information_schema export, if given ── */
  if (COLS_CSV) {
    if (!fs.existsSync(COLS_CSV)) { console.error("no such columns csv: " + COLS_CSV); process.exit(64); }
    const rows = parseCsv(fs.readFileSync(COLS_CSV, "utf8"));
    const h = rows.shift().map(x => x.trim().toLowerCase());
    const at = n => h.indexOf(n);
    for (const n of ["table_name", "column_name", "data_type", "is_nullable", "column_default"]) {
      if (at(n) < 0) { console.error("columns csv is missing the " + n + " column"); process.exit(64); }
    }
    const seen = {}; let count = 0;
    for (const r of rows) {
      const t = r[at("table_name")], c = r[at("column_name")];
      if (!t || !c) continue;
      seen[t] = true; count++;
      const def = r[at("column_default")];
      (lCols[t] = lCols[t] || {})[c] = {
        type: r[at("data_type")],
        nullKnown: true, defKnown: true,
        nullable: /^yes$/i.test(r[at("is_nullable")]),
        def: (def === "" || def === undefined) ? null : def,
        source: "information_schema",
      };
    }
    console.log("live columns: " + count + " exact values from " + path.basename(COLS_CSV) +
      " covering " + Object.keys(seen).length + " table(s); PostgREST for the rest\n");
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
  const colOnlyScratch = [], colOnlyLive = [], typeDiff = [], typeInvisible = [];
  const defDiff = [], defNotVisible = [], nullDiff = [], nullUnknown = [];
  let columnsCompared = 0;
  for (const t of sTables.filter(x => lTables.includes(x))) {
    const s = sCols[t] || {}, l = lCols[t] || {};
    for (const c of Object.keys(s)) {
      if (!(c in l)) { colOnlyScratch.push({ t, c, d: s[c] }); continue; }
      columnsCompared++;
      const a = s[c], b = l[c];

      const ta = normType(a.type), tb = normType(b.type);
      if (ta !== tb) {
        /* PostgREST strips every type modifier, so numeric(12,2) reaches us as
           numeric. Not a difference anyone can see from here. */
        if (ta.replace(/\([^)]*\)/g, "") === tb) typeInvisible.push({ t, c, scratch: a.type, live: b.type });
        else typeDiff.push({ t, c, scratch: a.type, live: b.type });
      }

      if (!b.defKnown) defNotVisible.push({ t, c, scratch: a.def, type: b.type });
      else if (normDefault(a.def) !== normDefault(b.def)) defDiff.push({ t, c, scratch: a.def, live: b.def });

      if (!b.nullKnown) nullUnknown.push({ t, c, scratch: a.nullable ? "nullable" : "not null" });
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
  line("                        not established by the live source: " + nullUnknown.length +
       " nullabilities, " + typeInvisible.length + " type modifiers, " + defNotVisible.length + " defaults");
  line("                        (types that state no default anywhere on live: " +
       (blindFormats.length ? blindFormats.join(", ") : "none") + ")");
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
  sect("layer 2: nullability differences", nullDiff,
    x => x.t + "." + x.c + "  scratch=" + (x.scratch ? "nullable" : "not null") + "  live=" + (x.live ? "nullable" : "not null"));
  sect("layer 2: default differences", defDiff,
    x => x.t + "." + x.c + "  scratch=" + JSON.stringify(x.scratch) + "  live=" + JSON.stringify(x.live));
  sect("layer 3: constraints only in the rebuild", conOnlyScratch, c => c.table + "  " + c.name + "  " + c.def);
  sect("layer 3: constraints only on live (csv)", conOnlyLive, c => c.table + "  " + c.name + "  " + c.def);
  sect("layer 3: constraints whose definition differs", conDiff,
    c => c.table + "  " + c.name + "\n        scratch: " + c.scratch + "\n        live   : " + c.live);

  line("\n── not established by the live source: neither agreement nor difference ──");
  line("  nullability : " + nullUnknown.length + " columns outside PostgREST's `required`");
  line("  defaults    : " + defNotVisible.length + " columns stating none, which does not mean none");
  line("  modifiers   : " + typeInvisible.length + " columns whose live type modifier is stripped");

  const unexpected = onlyScratchT.length + onlyLiveT.length + unexpectedCols.length +
    typeDiff.length + defDiff.length + nullDiff.length +
    conOnlyScratch.length + conOnlyLive.length + conDiff.length;
  line("\nUNEXPECTED DIFFERENCES: " + unexpected);
  process.exit(unexpected ? 1 : 0);
})().catch(e => { console.error("DIFF ERROR: " + e.message); process.exit(3); });
