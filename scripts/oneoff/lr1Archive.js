/* ════════════════════════════════════════════════════════════════════════════
   scripts/oneoff/lr1Archive.js — LR-1 (Nov 23 2026): archive the stranded leads.

     node scripts/oneoff/lr1Archive.js            dry run: reads only, writes nothing
     node scripts/oneoff/lr1Archive.js --apply    sets status 'archived' on the rows below

   WHAT IS ARCHIVED (status becomes 'archived'; nothing else on the row changes):
     A. every bsky_leads row with source 'mastodon' (Mastodon lead search is removed);
     B. bsky_leads Bluesky rows in 'score_failed' or 'skipped', created before 2026-08-20;
     C. bsky_leads Bluesky rows in 'scored' with outreach_safe null (never screened),
        created before 2026-08-20;
     D. sales_lead_pipeline rows in 'drafted' last updated before 2026-09-01 (untouched
        since August). Needs migration 203a, which allows 'archived' there.

   WHAT IS NEVER DONE: no row is re-scored (no model call of any kind), no row is
   deleted, no YouTube row is touched (its 30-day retention handles 'signal' rows),
   and no Bluesky row created on or after 2026-08-20 is touched. Every update filters
   on the row's current status, so a second run finds nothing left to change
   (idempotent).

   BEFORE IT WRITES, --apply saves every row id it will change with its previous
   status (ids and statuses only, no post text) to a JSON file, so the archive can be
   undone row by row. The file goes to LR1_ARCHIVE_RECORD, or to Downloads.

   ORDER. The pipeline (D) goes first: if migration 203a is not applied its CHECK
   refuses 'archived' (23514), the script stops there, and no lead row is touched.
   ════════════════════════════════════════════════════════════════════════════ */
"use strict";
const path = require("path");
const fs = require("fs");
const os = require("os");
process.chdir(path.join(__dirname, "..", ".."));
require("dotenv").config();
const { createClient } = require("@supabase/supabase-js");

const APPLY = process.argv.indexOf("--apply") !== -1;
const BLUESKY_CUTOFF = "2026-08-20T00:00:00.000Z";
const PIPELINE_CUTOFF = "2026-09-01T00:00:00.000Z";

const RULES = [
  { key: "A", what: "bsky_leads: every Mastodon row", table: "bsky_leads",
    where: q => q.eq("source", "mastodon").neq("status", "archived") },
  { key: "B", what: "bsky_leads: Bluesky score_failed or skipped, created before 2026-08-20", table: "bsky_leads",
    where: q => q.eq("source", "bluesky").in("status", ["score_failed", "skipped"]).lt("created_at", BLUESKY_CUTOFF) },
  { key: "C", what: "bsky_leads: Bluesky scored with outreach_safe null, created before 2026-08-20", table: "bsky_leads",
    where: q => q.eq("source", "bluesky").eq("status", "scored").is("outreach_safe", null).lt("created_at", BLUESKY_CUTOFF) },
  { key: "D", what: "sales_lead_pipeline: drafted, last updated before 2026-09-01", table: "sales_lead_pipeline",
    where: q => q.eq("status", "drafted").lt("updated_at", PIPELINE_CUTOFF) }
];

function sb() {
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_KEY) throw new Error("SUPABASE_URL and SUPABASE_SERVICE_KEY must be set.");
  return createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY, { auth: { persistSession: false } });
}

async function readAll(db, table, cols, where) {
  const out = [];
  for (let from = 0; ; from += 1000) {
    let q = db.from(table).select(cols).order("id", { ascending: true }).range(from, from + 999);
    if (where) q = where(q);
    const r = await q;
    if (r.error) throw new Error(table + ": " + r.error.message);
    out.push(...r.data);
    if (r.data.length < 1000) return out;
  }
}

function tally(rows, key) {
  return rows.reduce((m, r) => { const k = key(r); m[k] = (m[k] || 0) + 1; return m; }, {});
}

async function counts(db) {
  const leads = await readAll(db, "bsky_leads", "id, source, status");
  const pipe = await readAll(db, "sales_lead_pipeline", "id, status");
  return { leads: tally(leads, r => r.source + " | " + r.status), pipeline: tally(pipe, r => r.status) };
}

function printCounts(label, c) {
  console.log(label);
  Object.keys(c.leads).sort().forEach(k => console.log("  bsky_leads " + k + ": " + c.leads[k]));
  Object.keys(c.pipeline).sort().forEach(k => console.log("  sales_lead_pipeline " + k + ": " + c.pipeline[k]));
}

async function main(db) {
  console.log("LR-1 archive, " + (APPLY ? "APPLY" : "DRY RUN (nothing is written)") + ", " + new Date().toISOString());
  printCounts("BEFORE, by source and status:", await counts(db));

  const plan = [];
  for (const rule of RULES) {
    const cols = rule.table === "bsky_leads" ? "id, source, status, created_at, outreach_safe" : "id, status, updated_at";
    const rows = await readAll(db, rule.table, cols, rule.where);
    // The guards the filters already hold, checked again on what came back.
    const bad = rows.filter(r => (rule.table === "bsky_leads" && (r.source === "youtube" ||
      (r.source === "bluesky" && !(r.created_at < BLUESKY_CUTOFF)))) || r.status === "archived");
    if (bad.length) throw new Error("rule " + rule.key + " matched " + bad.length + " row(s) it must never touch; nothing was written.");
    const dates = rows.map(r => r.created_at || r.updated_at).filter(Boolean).sort();
    console.log("RULE " + rule.key + ": " + rule.what + " -> " + rows.length + " row(s)" +
      (rows.length ? ", by status " + JSON.stringify(tally(rows, r => r.status)) + ", dated " + dates[0].slice(0, 10) + " to " + dates[dates.length - 1].slice(0, 10) : ""));
    plan.push({ rule, rows });
  }
  const total = plan.reduce((n, p) => n + p.rows.length, 0);
  console.log("TOTAL to archive: " + total);

  if (!APPLY) { console.log("Dry run: nothing written. Run with --apply to archive these rows."); return; }
  if (!total) { console.log("Nothing to archive: every row is already archived or out of scope. Nothing written."); return; }

  const record = path.join(process.env.LR1_ARCHIVE_RECORD || path.join(os.homedir(), "Downloads"),
    "lr1-archive-before-" + new Date().toISOString().replace(/[:.]/g, "-") + ".json");
  fs.writeFileSync(record, JSON.stringify(plan.map(p => ({ rule: p.rule.key, table: p.rule.table,
    rows: p.rows.map(r => ({ id: r.id, status: r.status })) })), null, 1));
  console.log("Saved the ids and previous statuses to " + record);

  const ordered = plan.slice().sort((a, b) => (a.rule.key === "D" ? -1 : 0) - (b.rule.key === "D" ? -1 : 0));
  for (const p of ordered) {
    let changed = 0;
    for (let i = 0; i < p.rows.length; i += 200) {
      const ids = p.rows.slice(i, i + 200).map(r => r.id);
      const u = await p.rule.where(db.from(p.rule.table).update({ status: "archived" }).in("id", ids)).select("id");
      if (u.error) {
        if (u.error.code === "23514") throw new Error("migration 203a is not applied (the pipeline CHECK refused 'archived'). Stopped; " +
          (p.rule.key === "D" && i === 0 ? "nothing was written." : "rules already done are listed above."));
        throw new Error("rule " + p.rule.key + ": " + u.error.message);
      }
      changed += (u.data || []).length;
    }
    console.log("APPLIED rule " + p.rule.key + ": " + changed + " row(s) archived");
  }
  printCounts("AFTER, by source and status:", await counts(db));
}

if (require.main === module) {
  main(sb()).catch(e => { console.error("STOPPED: " + (e.message || e)); process.exit(1); });
}
module.exports = { RULES, BLUESKY_CUTOFF, PIPELINE_CUTOFF, main };
