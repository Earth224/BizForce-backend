"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkRlsEveryTable — every table the migrations create has row level
   security enabled by the migrations, and nothing can read one directly.

   Migration 142 enables RLS on the eight tables the migrations created
   without it (content_library, marketplace_orders, oracle_sync,
   oracle_messages, push_subscriptions, inner_iq_results, agent_autonomy,
   job_runs) and adds no policy. The server uses the service role, which
   bypasses RLS; no frontend page reads Supabase directly.

   WHAT THIS PROVES (migrations read as statements, comments removed, by
   scripts/buildScratchSchema.js splitStatements, so a comment that says
   "enable row level security" counts for nothing)
     R1. Every table created and not dropped has an ENABLE ROW LEVEL SECURITY
         and no later DISABLE. A NEW MIGRATION THAT CREATES A TABLE WITHOUT IT
         FAILS THIS CHECK; R6 proves that on a fixture.
     R2. 142 enables it on exactly the eight, and nothing in 142 adds a
         policy or grants to anon or authenticated.
     R3. No migration creates a policy on one of the eight.
     R4. No frontend file talks to Supabase: no supabase-js, no createClient,
         no /rest/v1, no supabase.co, no JWT-shaped key.
     R5. server.js and lib/ never read SUPABASE_ANON_KEY.
     R6. The rule bites: a fixture migration creating a table without RLS is
         reported, one that enables it is not, a later DISABLE is reported.

   MUTATE=<name> edits the migrations or frontend IN MEMORY; MUTATE=all runs
   each in its own process and passes only if every one fails. A search text
   that does not match exactly once is an ERROR, never counted as caught.
   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const s = require("./_shared");
const { splitStatements, listMigrations } = require("./buildScratchSchema");

const REPO = path.join(__dirname, "..");
const MIG = path.join(REPO, "supabase", "migrations");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const M142 = "142_enable_rls_remaining_tables.sql";
const EIGHT = ["content_library", "marketplace_orders", "oracle_sync", "oracle_messages", "push_subscriptions",
  "inner_iq_results", "agent_autonomy", "job_runs"];

const MUTATIONS = {
  // RLS removed from one table
  "rls-removed-one-table": [["mig", M142, "alter table if exists public.oracle_messages    enable row level security;\n", ""]],
  // a permissive policy is added
  "permissive-policy": [["mig", M142, "alter table if exists public.job_runs           enable row level security;\n",
    "alter table if exists public.job_runs           enable row level security;\ncreate policy anyone_reads on public.oracle_messages for select using (true);\n"]],
  // a later migration turns it off again
  "rls-disabled-later": [["mig", M142, "alter table if exists public.job_runs           enable row level security;\n",
    "alter table if exists public.job_runs           enable row level security;\nalter table public.push_subscriptions disable row level security;\n"]],
  // a frontend page reads a table with the anon key
  "frontend-reads-supabase": [["fe", "vitality.html", "<link rel=\"stylesheet\" href=\"/css/bizforce-ui.css\"/>",
    "<link rel=\"stylesheet\" href=\"/css/bizforce-ui.css\"/>\n<script>const sb = supabase.createClient(\"https://x.supabase.co\", \"anon\"); sb.from(\"oracle_messages\").select(\"*\");</script>"]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}

/* ── the files, in memory ─────────────────────────────────────────────── */
const files = listMigrations(MIG).map(name => ({ name, sql: fs.readFileSync(path.join(MIG, name), "utf8").replace(/\r\n/g, "\n") }));
const FE = {};
(function walk(dir) {
  fs.readdirSync(dir, { withFileTypes: true }).forEach(d => {
    const p = path.join(dir, d.name);
    if (d.isDirectory()) { if (!/^\.|node_modules/.test(d.name)) walk(p); }
    else if (/\.(html|js|json|xml|txt)$/.test(d.name) || d.name === "_redirects") FE[path.relative(FRONTEND, p).replace(/\\/g, "/")] = fs.readFileSync(p, "utf8").replace(/\r\n/g, "\n");
  });
})(FRONTEND);
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [where, file, from, to] of edits) {
    if (where === "mig") { const f = files.find(x => x.name === file); f.sql = s.replaceOnce(f.sql, from, to, MUTATE + " in " + file); }
    else FE[file] = s.replaceOnce(FE[file], from, to, MUTATE + " in " + file);
  }
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}

/* ── the rule ─────────────────────────────────────────────────────────── */
const ID = "(?:\"?public\"?\\.)?\"?([a-z_][a-z0-9_]*)\"?";
function rlsState(migs) {
  const tables = new Map();   // name -> { file, rls: file|null, disabled: file|null }
  const policies = [];
  for (const f of migs) {
    for (const st of splitStatements(f.sql)) {
      const t = st.text.replace(/\s+/g, " ").toLowerCase();
      let m;
      if ((m = new RegExp("^create (?:unlogged )?table (?:if not exists )?" + ID).exec(t)) && !tables.has(m[1])) tables.set(m[1], { file: f.name, rls: null, disabled: null });
      if ((m = new RegExp("^drop table (?:if exists )?" + ID).exec(t))) tables.delete(m[1]);
      if ((m = new RegExp("^alter table (?:if exists )?(?:only )?" + ID + " enable row level security$").exec(t)) && tables.has(m[1])) {
        tables.get(m[1]).rls = f.name; tables.get(m[1]).disabled = null;
      }
      if ((m = new RegExp("^alter table (?:if exists )?(?:only )?" + ID + " disable row level security$").exec(t)) && tables.has(m[1])) tables.get(m[1]).disabled = f.name;
      if ((m = new RegExp("^create policy (\"[^\"]+\"|[a-z_][a-z0-9_]*) on " + ID).exec(t))) policies.push({ file: f.name, table: m[2], text: t });
    }
  }
  return { tables, policies };
}
function missingRls(state) {
  return [...state.tables].filter(([, v]) => !v.rls || v.disabled).map(([k, v]) => k + (v.disabled ? " (disabled in " + v.disabled + ")" : " (created in " + v.file + ")"));
}

(async () => {
  console.log((MUTATE ? "" : "\n") + "══ R1. every table the migrations create has RLS ══");
  const state = rlsState(files);
  const missing = missingRls(state);
  console.log("    " + state.tables.size + " tables live at the end of " + files.length + " migrations");
  check("R1. the migrations create tables at all", state.tables.size >= 80, state.tables.size);
  check("R1. every one has RLS enabled and not disabled later", missing.length === 0, missing.join(", "));
  check("R1. each of the eight is among them", EIGHT.every(t => state.tables.has(t)), EIGHT.filter(t => !state.tables.has(t)).join(", "));

  console.log("\n══ R2. migration 142 ══");
  const m142 = files.find(f => f.name === M142);
  check("R2. " + M142 + " is a migration", !!m142);
  const st142 = m142 ? splitStatements(m142.sql).map(x => x.text.replace(/\s+/g, " ").toLowerCase()) : [];
  const enabled = st142.map(t => (new RegExp("^alter table if exists " + ID + " enable row level security$").exec(t) || [])[1]).filter(Boolean);
  check("R2. it enables RLS on exactly the eight", JSON.stringify(enabled.slice().sort()) === JSON.stringify(EIGHT.slice().sort()), enabled.join(", "));
  check("R2. every statement in it is an ENABLE (no policy, grant, revoke or anything else)", st142.length === EIGHT.length && st142.every(t => / enable row level security$/.test(t)), st142.filter(t => !/ enable row level security$/.test(t)).join(" | "));
  check("R2. it is the last migration to touch these tables' RLS", EIGHT.every(t => state.tables.get(t) && state.tables.get(t).rls === M142), EIGHT.map(t => t + "=" + (state.tables.get(t) || {}).rls).join(", "));

  console.log("\n══ R3. no policy on the eight ══");
  const onEight = state.policies.filter(p => EIGHT.indexOf(p.table) !== -1);
  check("R3. no migration creates a policy on any of the eight", onEight.length === 0, onEight.map(p => p.file + ": " + p.text.slice(0, 80)).join(" | "));
  check("R3. no migration grants a table to anon", files.every(f => !splitStatements(f.sql).some(x => /^grant .* to .*\banon\b/i.test(x.text.replace(/\s+/g, " ")))),
    files.filter(f => splitStatements(f.sql).some(x => /^grant .* to .*\banon\b/i.test(x.text.replace(/\s+/g, " ")))).map(f => f.name).join(", "));

  console.log("\n══ R4. no frontend file talks to Supabase ══");
  const feNames = Object.keys(FE);
  check("R4. the frontend checkout was read", feNames.length >= 50 && FE["index.html"] !== undefined, feNames.length);
  const SUPA = [/supabase/i, /createClient\s*\(/, /\/rest\/v1\b/, /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/];
  const hits = feNames.filter(n => SUPA.some(re => re.test(FE[n])));
  check("R4. no page or script mentions supabase, createClient, /rest/v1 or a JWT-shaped key", hits.length === 0, hits.join(", "));

  console.log("\n══ R5. the server never uses the anon key ══");
  const serverFiles = ["server.js"].concat(fs.readdirSync(path.join(REPO, "lib")).filter(f => f.endsWith(".js")).map(f => "lib/" + f));
  const anonReaders = serverFiles.filter(f => /SUPABASE_ANON_KEY/.test(fs.readFileSync(path.join(REPO, f), "utf8")));
  check("R5. server.js and lib/*.js never read SUPABASE_ANON_KEY", anonReaders.length === 0, anonReaders.join(", "));

  console.log("\n══ R6. the rule bites on a new migration ══");
  const fresh = { name: "999_fixture.sql", sql: "-- alter table public.fixture_a enable row level security;\ncreate table if not exists public.fixture_a (id uuid primary key, user_id uuid);\n" +
    "create table public.fixture_b (id uuid primary key);\nalter table public.fixture_b enable row level security;\n" };
  const withFresh = missingRls(rlsState(files.concat([fresh])));
  check("R6. a new table without RLS is reported (a comment saying it is enabled does not count)", withFresh.length === 1 && /^fixture_a /.test(withFresh[0]), withFresh.join(", "));
  const off = { name: "998_fixture.sql", sql: "alter table public.users disable row level security;\n" };
  const withOff = missingRls(rlsState(files.concat([off])));
  check("R6. a later DISABLE is reported", withOff.length === 1 && /^users \(disabled in 998_fixture\.sql\)/.test(withOff[0]), withOff.join(", "));
  const dropped = { name: "997_fixture.sql", sql: "create table public.fixture_c (id int);\ndrop table if exists public.fixture_c;\n" };
  check("R6. a table created and dropped again is not required to have it", missingRls(rlsState(files.concat([dropped]))).length === 0);

  console.log("\n" + passes + " passed, " + failures + " failed");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
/* A crash is a FAIL (exit 1), not exit 3: 3 is _shared.js's "mutation anchor did not match". */
})().catch(e => { console.log("    FAIL  the harness stopped: " + ((e && e.message) || e)); console.error((e && e.stack) || e); process.exit(1); });
