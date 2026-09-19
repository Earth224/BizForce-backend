/* ══════════════════════════════════════════════════════════════════════════
   rebuildFromScratch.js — reset a scratch Supabase project to an empty public
   schema, then apply every file in supabase/migrations in filename order, one
   file per transaction, halting at the first failure.

   WHAT IT IS FOR. The live database predates this migration directory, so a
   file can depend on a state that only live has and that a fresh run never
   reproduces. Two such files have been found that way -- 000's search_path put
   uuid-ossp out of reach, and 012 converted two columns that 011 now creates
   already converted -- and neither is visible by reading the SQL. Only a run
   against an empty database finds them.

   USAGE
     node scripts/rebuildFromScratch.js <path-to-scratch-env-file>

   The env file needs two keys:
     SCRATCH_REF      the scratch project ref (20 lowercase letters)
     SCRATCH_DB_URL   the database password for that project
                      (the key is named URL for historical reasons; the value
                      is a bare password, not a connection string)

   THE RESET IS THE DANGEROUS PART, so it is fenced by four assertions that run
   immediately before the DROP, on the same connection that will issue it, and
   one that verifies the result afterwards. Any one of them refuses the whole
   run; nothing is dropped and nothing is applied.

     R1  the connection is built from the env file's ref and nothing else
     R2  the live ref -- read from the repo's own .env -- appears nowhere in
         the connection, and an unknown live ref refuses rather than guesses
     R3  the server reports auth.users empty; a live project has real accounts
     R4  public carries this ref's stamp, no comment, or Postgres' stock
         "standard public schema"; a stamp naming another project refuses
     R5  public is empty after the reset, before any file is applied

   R1 and R2 run BEFORE connecting, so a misaimed run never opens a socket.

   TESTING THE R2 REFUSAL. It is the guard that matters, so it is meant to be
   exercised, and doing so is safe -- it refuses before dialling anything:

     printf 'SCRATCH_REF=<the live ref>\nSCRATCH_DB_URL=x\n' > /tmp/fake-live.env
     node scripts/rebuildFromScratch.js /tmp/fake-live.env

   Expected: R1 passes, R2 prints REFUSE, and the run stops with "Refused
   before connecting. Nothing dropped, nothing applied." Take the live ref from
   SUPABASE_URL in .env. Delete the file afterwards; it holds no secret.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const { Client } = require("pg");

const ENV_FILE = process.argv[2];
if (!ENV_FILE) {
  console.error("usage: node scripts/rebuildFromScratch.js <path-to-scratch-env-file>");
  process.exit(64);
}
if (!fs.existsSync(ENV_FILE)) {
  console.error("no such env file: " + ENV_FILE);
  process.exit(64);
}

const REPO = path.join(__dirname, "..");
const DIR = path.join(REPO, "supabase", "migrations");
const HOST = process.env.SCRATCH_DB_HOST || "aws-0-us-east-1.pooler.supabase.com";

function readEnv(file) {
  const out = {};
  for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    const i = line.indexOf("=");
    if (i > 0) out[line.slice(0, i)] = line.slice(i + 1).trim();
  }
  return out;
}

const env = readEnv(ENV_FILE);
const REF = env.SCRATCH_REF;
const PASSWORD = env.SCRATCH_DB_URL;
const USER = "postgres." + REF;
const STAMP = "BIZFORCE_SCRATCH_REBUILD_TARGET " + REF;

/* The live project's ref, read only to prove we are not pointed at it. The
   repo's .env is never loaded into this process beyond this one comparison. */
let LIVE_REF = null;
try {
  const m = fs.readFileSync(path.join(REPO, ".env"), "utf8").match(/^SUPABASE_URL=(.*)$/m);
  if (m) LIVE_REF = new URL(m[1].trim()).hostname.split(".")[0];
} catch (e) { /* handled by R2: an unknown live ref refuses */ }

let refused = false;
function guard(n, label, ok, detail) {
  console.log("  " + (ok ? "pass  " : "REFUSE") + "  " + n + ": " + label + (detail ? "  [" + detail + "]" : ""));
  if (!ok) refused = true;
}

(async () => {
  console.log("RESET GUARDS");

  guard("R1", "connection is built from the env file's ref",
    typeof REF === "string" && /^[a-z]{20}$/.test(REF) && USER === "postgres." + REF && !!PASSWORD,
    USER + " @ " + HOST);

  guard("R2", "the live ref appears nowhere in this connection",
    LIVE_REF !== null && REF !== LIVE_REF && !USER.includes(LIVE_REF) && !HOST.includes(LIVE_REF),
    LIVE_REF === null ? "live ref unknown -- refusing rather than guessing" : "live=" + LIVE_REF + " scratch=" + REF);

  if (refused) { console.log("\nRefused before connecting. Nothing dropped, nothing applied."); process.exit(2); }

  const client = new Client({
    host: HOST, port: 5432, user: USER, password: PASSWORD, database: "postgres",
    ssl: { rejectUnauthorized: false }, connectionTimeoutMillis: 20000,
    statement_timeout: 120000,
  });
  await client.connect();

  /* R3: a live project has real accounts. An empty auth.users is the strongest
     server-side evidence that this database is nobody's production. */
  let users = -1;
  try { users = (await client.query("select count(*)::int as n from auth.users")).rows[0].n; }
  catch (e) { users = -1; }
  guard("R3", "the server reports no real accounts", users === 0,
    users < 0 ? "auth.users unreadable -- refusing" : users + " rows in auth.users");

  /* R4: our own previous reset stamps the schema with this ref. A stamp naming
     a different project means we are looking at someone else's database and is
     an outright refusal. Two comments count as "not stamped by us yet" and let
     R3 carry the weight: no comment at all, and Postgres' own stock "standard
     public schema", which is what a project that has never been reset carries. */
  const VIRGIN = "standard public schema";
  const st = await client.query(
    "select d.description from pg_namespace n " +
    "left join pg_description d on d.objoid = n.oid and d.classoid = 'pg_namespace'::regclass " +
    "where n.nspname = 'public'");
  const stamp = st.rows.length ? st.rows[0].description : null;
  guard("R4", "public carries this ref's stamp, or no stamp of ours yet",
    stamp === null || stamp === VIRGIN || stamp === STAMP,
    stamp === null ? "no comment (first run)" : stamp);

  if (refused) {
    await client.end();
    console.log("\nRefused. Nothing dropped, nothing applied.");
    process.exit(2);
  }

  /* ── reset ────────────────────────────────────────────────────────────── */
  const had = (await client.query(
    "select count(*)::int as n from information_schema.tables " +
    "where table_schema = 'public' and table_type = 'BASE TABLE'")).rows[0].n;
  console.log("\nRESET  dropping public (" + had + " tables) and recreating it");
  await client.query("drop schema if exists public cascade");
  await client.query("create schema public");
  for (const g of ["grant usage on schema public to postgres, anon, authenticated, service_role",
                   "grant all on schema public to postgres, service_role"]) {
    try { await client.query(g); } catch (e) { console.log("       (grant skipped: " + e.message + ")"); }
  }
  await client.query("comment on schema public is " + client.escapeLiteral(STAMP));

  const after = (await client.query(
    "select count(*)::int as n from information_schema.tables " +
    "where table_schema = 'public' and table_type = 'BASE TABLE'")).rows[0].n;
  guard("R5", "public is empty after the reset", after === 0, after + " tables");
  if (refused) { await client.end(); console.log("\nReset did not leave a clean schema."); process.exit(2); }

  const files = fs.readdirSync(DIR).filter(f => f.endsWith(".sql")).sort();
  console.log("\nAPPLYING " + files.length + " files\n");

  for (const f of files) {
    const sql = fs.readFileSync(path.join(DIR, f), "utf8");
    const started = Date.now();
    try {
      await client.query("begin");
      await client.query(sql);
      await client.query("commit");
      console.log("  ok    " + f + "  (" + (Date.now() - started) + "ms)");
    } catch (e) {
      try { await client.query("rollback"); } catch (_) {}
      console.log("\n  FAIL  " + f);
      console.log("        " + (e.severity || "ERROR") + " " + (e.code || "") + ": " + e.message);
      if (e.detail) console.log("        detail: " + e.detail);
      if (e.hint) console.log("        hint: " + e.hint);
      if (e.where) console.log("        where: " + e.where);
      if (e.position) {
        const pos = parseInt(e.position, 10);
        const line = sql.slice(0, pos).split("\n").length;
        console.log("        at line " + line + " of " + f);
        const lines = sql.split("\n");
        for (let i = Math.max(0, line - 4); i < Math.min(lines.length, line + 2); i++) {
          console.log("        " + String(i + 1).padStart(4) + " | " + lines[i]);
        }
      }
      await client.end();
      console.log("\nHalted at the first error. " + files.indexOf(f) + " of " + files.length + " files applied before it.");
      process.exit(1);
    }
  }

  await client.end();
  console.log("\nAll " + files.length + " files applied with no error.");
})().catch(e => { console.error("RUNNER ERROR: " + e.message); process.exit(3); });
