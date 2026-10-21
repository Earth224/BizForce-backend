"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   restoreBackup.js — opens a nightly backup (lib/backup.js, format version 2)
   and restores it into a Supabase project. RUN BY HAND ONLY; nothing calls it.

   node scripts/restoreBackup.js --key-file <file holding the base64 key>
        --target-url <https://xxxx.supabase.co> --target-key <service key>
        [--dry-run] [--i-mean-production] <part file> [<part file> ...]

   --key <base64> works in place of --key-file, but leaves the key in shell
   history. The target URL and key come ONLY from these arguments, never from
   the app's environment, so this cannot reach production by default.

   WHAT IT DOES, in order, stopping at the first thing that does not hold:
     1. every part's auth tag is checked (wrong key, or any byte altered), then
        every table's row count and sha256 against the manifest;
     2. the parts must be one backup, every part present once, every table's
        chunks all there and adding up to the manifest's count;
     3. --dry-run stops here: nothing connects, nothing is written;
     4. the target must not be production (the SUPABASE_URL in the app's env or
        .env) unless --i-mean-production is passed;
     5. every table it will fill must be EMPTY in the target, or nothing is
        written at all;
     6. tables are inserted parents first (lib/backup.js BACKUP_TABLES order),
        500 rows per request;
     7. each table is counted again in the target and compared with the
        manifest, and the setval lines for sequence-backed ids are printed.
   Exit 0 only when every table was restored with the manifest's count.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");

const INSERT_BATCH = 500;
const USAGE = "usage: node scripts/restoreBackup.js (--key-file <file> | --key <base64>) " +
  "[--target-url <url> --target-key <service key>] [--dry-run] [--i-mean-production] <part files...>";

function parseArgs(argv) {
  var opts = { files: [], dryRun: false, iMeanProduction: false };
  for (var i = 0; i < argv.length; i++) {
    var a = argv[i];
    if (a === "--dry-run") opts.dryRun = true;
    else if (a === "--i-mean-production") opts.iMeanProduction = true;
    else if (a === "--key" || a === "--key-file" || a === "--target-url" || a === "--target-key") {
      if (i + 1 >= argv.length) return { error: a + " needs a value" };
      var v = argv[++i];
      if (a === "--key") opts.key = v;
      else if (a === "--key-file") opts.keyFile = v;
      else if (a === "--target-url") opts.targetUrl = v;
      else opts.targetKey = v;
    } else if (a.indexOf("--") === 0) return { error: "unknown option " + a };
    else opts.files.push(a);
  }
  if (!opts.files.length) return { error: "no backup part files were given" };
  if (!opts.key && !opts.keyFile) return { error: "the key is required: --key-file <file> or --key <base64>" };
  if (!opts.dryRun && (!opts.targetUrl || !opts.targetKey)) return { error: "--target-url and --target-key are required unless --dry-run" };
  return opts;
}

/* Two Supabase URLs name the same project when their hosts match. */
function sameSupabaseUrl(a, b) {
  function host(u) {
    var text = String(u || "").trim().toLowerCase();
    try { return new URL(text).host; } catch (e) { return text.replace(/\/+$/, ""); }
  }
  return !!host(a) && host(a) === host(b);
}

/* The production URL to refuse: SUPABASE_URL from this process, else from the
   repo's .env (read, not loaded into the environment). */
function productionUrlFromEnv() {
  if (process.env.SUPABASE_URL) return process.env.SUPABASE_URL;
  try {
    var parsed = require("dotenv").parse(fs.readFileSync(path.join(__dirname, "..", ".env")));
    return parsed.SUPABASE_URL || null;
  } catch (e) {
    return null;
  }
}

async function main(argv, deps) {
  deps = deps || {};
  var backup = deps.backup || require("../lib/backup");
  var out = deps.log || console;
  var readFile = deps.readFile || function (f) { return fs.readFileSync(f); };

  var opts = parseArgs(argv);
  if (opts.error) { out.error("REFUSED: " + opts.error + "\n" + USAGE); return 2; }

  var keyText;
  try {
    keyText = opts.keyFile ? String(readFile(opts.keyFile)) : opts.key;
  } catch (error) {
    out.error("REFUSED: the key file could not be read (" + (error.code || "error") + ")");
    return 2;
  }
  var keyInfo = backup.parseBackupKey(keyText);
  if (!keyInfo.ok) { out.error("REFUSED: " + keyInfo.problem.replace("BACKUP_ENCRYPTION_KEY", "the key")); return 2; }

  // ── 1. open and verify every part ───────────────────────────────────────
  var opened = [];
  for (var i = 0; i < opts.files.length; i++) {
    var file = opts.files[i];
    try {
      var part = backup.openPart(readFile(file), keyInfo.key);
      opened.push(part);
      out.log("verified  " + path.basename(file) + ": part " + part.manifest.part + " of " + part.manifest.parts +
        ", backup " + part.manifest.backup_id + ", " + part.units.length + " table chunk(s), auth tag and sha256 OK");
    } catch (error) {
      out.error("FAILED    " + path.basename(file) + ": " + error.message + (error.code ? " [" + error.code + "]" : ""));
      return 1;
    }
  }

  // ── 2. one whole backup ─────────────────────────────────────────────────
  var set = backup.assembleParts(opened);
  out.log("backup " + set.manifest.backup_id + ", created " + set.manifest.created_at + ", commit " + (set.manifest.commit || "unknown"));
  var order = backup.restoreOrder(Array.from(set.tables.keys()));
  if (set.problems.length) {
    set.problems.forEach(function (p) { out.error("PROBLEM   " + p); });
    out.error("REFUSED: the parts given are not one whole, verified backup. Nothing was written.");
    return 1;
  }

  // ── 3. dry run: verified, nothing else ──────────────────────────────────
  if (opts.dryRun) {
    order.forEach(function (t) { out.log("  " + t + ": " + set.tables.get(t).length + " rows verified"); });
    out.log("DRY RUN: every part decrypted and verified; " + order.length + " tables. Nothing was connected to and nothing was written.");
    return 0;
  }

  // ── 4. never production by accident ─────────────────────────────────────
  var prodUrl = deps.productionUrl !== undefined ? deps.productionUrl : productionUrlFromEnv();
  if (!prodUrl && !opts.iMeanProduction) {
    out.error("REFUSED: the production SUPABASE_URL is unknown (not in this environment or .env), so the target cannot be " +
      "checked against it. Run from the backend repo with its .env, or pass --i-mean-production to accept the risk.");
    return 2;
  }
  if (sameSupabaseUrl(opts.targetUrl, prodUrl) && !opts.iMeanProduction) {
    out.error("REFUSED: the target is the PRODUCTION database (" + opts.targetUrl + "). Restore into a scratch project, " +
      "or pass --i-mean-production if overwriting production is truly intended.");
    return 2;
  }
  var createClient = deps.createClient || require("@supabase/supabase-js").createClient;
  var target = createClient(opts.targetUrl, opts.targetKey, { auth: { persistSession: false } });

  // ── 5. every table to fill must be empty ────────────────────────────────
  var blocked = [];
  for (var t of order) {
    if (!set.tables.get(t).length) continue;
    var head = await target.from(t).select("*", { count: "exact", head: true });
    if (head.error) blocked.push(t + " cannot be read in the target (" + (head.error.message || head.error) + "): apply the migrations first");
    else if (head.count !== 0) blocked.push(t + " already has " + head.count + " rows in the target");
  }
  if (blocked.length) {
    blocked.forEach(function (b) { out.error("BLOCKED   " + b); });
    out.error("REFUSED: restore only into empty tables. Nothing was written.");
    return 1;
  }

  // ── 6. insert, parents first ────────────────────────────────────────────
  for (var name of order) {
    var rows = set.tables.get(name);
    for (var at = 0; at < rows.length; at += INSERT_BATCH) {
      var res = await target.from(name).insert(rows.slice(at, at + INSERT_BATCH));
      if (res && res.error) {
        out.error("FAILED    inserting " + name + " rows " + at + "-" + Math.min(at + INSERT_BATCH, rows.length) + ": " +
          (res.error.message || res.error) + ". Tables before it in the order were restored; this one is partial.");
        return 1;
      }
    }
  }

  // ── 7. count again, against the manifest ────────────────────────────────
  var bad = 0;
  out.log("table                          manifest  restored");
  for (var n of order) {
    var expected = set.tables.get(n).length;
    var after = await target.from(n).select("*", { count: "exact", head: true });
    var got = after.error ? "unreadable" : after.count;
    if (got !== expected) bad++;
    out.log("  " + (n + "                              ").slice(0, 30) + String(expected).padStart(8) + String(got).padStart(10) + (got === expected ? "" : "  MISMATCH"));
  }
  var seq = backup.SEQUENCE_TABLES.filter(function (s) { return set.tables.has(s) && set.tables.get(s).length; });
  if (seq.length) {
    out.log("\nRun these in the target's SQL editor so new rows do not reuse restored ids:");
    seq.forEach(function (s) {
      out.log("  select setval(pg_get_serial_sequence('public." + s + "', 'id'), (select max(id) from public." + s + "));");
    });
  }
  if (bad) { out.error("RESTORE FINISHED WITH " + bad + " MISMATCH(ES)."); return 1; }
  out.log("RESTORED: " + order.length + " tables, every count matches the manifest.");
  return 0;
}

module.exports = { main, parseArgs, sameSupabaseUrl };

if (require.main === module) {
  main(process.argv.slice(2)).then(function (code) { process.exit(code); }, function (error) {
    console.error("FAILED: " + ((error && error.stack) || error));
    process.exit(1);
  });
}
