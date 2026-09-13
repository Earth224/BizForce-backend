/* ══════════════════════════════════════════════════════════════════════════
   checkRunResidue.js — nothing a check run writes may outlive it.

   THE HOLE THIS CLOSES. Each check script wrote rows to ai_tasks and to the
   model_calls spend ledger, then deleted them at the end. Twice a script
   crashed before reaching the end — once on a body that did not satisfy a
   route's required inputs — and the rows stayed: six ledger rows and three
   task rows under a real account, invisible until somebody went looking.
   Cleanup that only runs on the happy path is not cleanup; it is a wish.

   WHAT THIS GIVES EVERY SCRIPT:

     record(table, id)     the ids this run caused, written to a journal on
                           disk as they happen, so a hard crash still leaves a
                           list of exactly what to remove
     install()             cleanup on EVERY exit: normal return, a thrown
                           error, an unhandled rejection, SIGINT (Ctrl-C) or
                           SIGTERM
     sweepPrevious()       at startup, before anything is written: remove what
                           a previous crashed run left, and say what was found
     cleanup()             delete the recorded ids, then READ THE TABLES BACK
                           and report what actually remains

   THE JOURNAL IS THE POINT. An in-memory list dies with the process. A file
   written synchronously on every insert survives a kill -9, so the next run of
   the same script can finish the job — and it names ids rather than guessing
   from timestamps, so it can never remove a row somebody else wrote.

   It lives in the OS temp directory, not the repo: it is per-machine runtime
   state, and a stray journal in a commit would be noise at best.

   IF CLEANUP ITSELF FAILS, the script says which ids in which table are still
   there and exits non-zero. A residue nobody is told about is the thing this
   file exists to prevent, and a green run that left rows behind would be worse
   than a red one that named them.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const os = require("os");
const path = require("path");

function journalPath(name) {
  return path.join(os.tmpdir(), "bizforce-check-residue-" + name + ".json");
}
/* ══════════════════════════════════════════════════════════════════════════
   WHOSE ACCOUNT THESE SCRIPTS ARE ALLOWED TO TOUCH.

   The scripts used to take the first row out of the users table with no ORDER
   BY and write their rows under it. That was untidy while cleanup only
   inserted; it became dangerous the moment cleanup learned to delete every
   ai_tasks row for that account created since the run began. An unordered
   LIMIT 1 comes back in whatever order the heap hands over, and that can
   change after any update or vacuum — so the pick was never stable, only
   lucky. A run that landed on the owner would have deleted real task rows, and
   that account holds 7,943 of them.

   So the subject is named explicitly, in the environment, and there is no
   fallback. An unset variable stops the run: guessing is the bug.
   ══════════════════════════════════════════════════════════════════════════ */

/* The owner's live account. Never a subject, under any circumstances. */
const OWNER_ACCOUNT_ID = "ea887c6e-e278-4a15-b7e9-cd78a9949b78";
const SUBJECT_ENV = "BIZFORCE_CHECK_USER_ID";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/* The account these checks are meant to run under: nobody can sign in as it
   (its password_hash is the literal string "hash123", and /api/auth/login is
   bcrypt.compare, which that can never satisfy) and it owns no rows in any
   table the checks touch. Named here only so the refusal can suggest it. */
const SUGGESTED_SUBJECT_ID = "53e6b330-d31c-4958-a10b-516397e7b9c9";

function refuse(lines) {
  console.error("");
  lines.forEach(function (l) { console.error("[residue] " + l); });
  console.error("");
  process.exit(1);
}

/* CALL THIS BEFORE ANYTHING ELSE. It either returns the id that every write
   and every delete in the run is confined to, or it ends the process having
   touched nothing. There is deliberately no default and no table read. */
function resolveSubjectAccount() {
  const raw = (process.env[SUBJECT_ENV] || "").trim();

  if (!raw) {
    refuse([
      "REFUSING TO RUN: no subject account was named.",
      "",
      "These checks write rows to ai_tasks and to the model_calls spend ledger",
      "and then delete them. Which account that happens to be is not something",
      "worth guessing at, so it is no longer guessed at.",
      "",
      "Set " + SUBJECT_ENV + " to the user id the checks may use:",
      "",
      "  PowerShell:  $env:" + SUBJECT_ENV + " = \"" + SUGGESTED_SUBJECT_ID + "\"",
      "  bash:        export " + SUBJECT_ENV + "=" + SUGGESTED_SUBJECT_ID,
      "",
      "Nothing has been written or deleted."
    ]);
  }

  if (!UUID_RE.test(raw)) {
    refuse([
      "REFUSING TO RUN: " + SUBJECT_ENV + " is not a uuid (" + raw + ").",
      "Nothing has been written or deleted."
    ]);
  }

  assertNotOwner(raw, SUBJECT_ENV + " names the owner's account");
  return raw.toLowerCase();
}

/* THE HARD REFUSAL. Called before every write path and before every sweep,
   rather than once at startup: a single check at the top is a check that a
   later code path can walk around. */
function assertNotOwner(id, context) {
  if (!id) return;
  if (String(id).toLowerCase() !== OWNER_ACCOUNT_ID) return;
  refuse([
    "REFUSING TO RUN: " + context + ".",
    "",
    OWNER_ACCOUNT_ID + " is the owner's live account. These checks delete every",
    "ai_tasks row for their subject created since the run began, so pointing",
    "them at it would destroy real work.",
    "",
    "Nothing has been written or deleted."
  ]);
}

/* PER ROW, NOT PER QUERY. A filter in a query is a request; this is the check.
   Any row that comes back belonging to somebody else is left alone and said
   out loud, because a delete list that quietly contains one row it should not
   is the exact failure this file exists to prevent. */
function isSubjectRow(row, subject, table) {
  if (!row) return false;
  const owner = String(row.user_id || "").toLowerCase();
  if (owner && owner === String(subject).toLowerCase()) return true;
  console.error("[residue] REFUSING to delete " + table + " row " + row.id +
    ": it belongs to " + (owner || "nobody") + ", not to the subject account " + subject + ".");
  return false;
}


function createResidueGuard(options) {
  const supabase = options.supabase;
  const name = options.name;
  const tables = options.tables || ["ai_tasks", "model_calls"];
  const file = journalPath(name);

  /* THE ONE ACCOUNT THIS RUN MAY TOUCH, fixed at construction. Every delete
     below is checked against it row by row, so a query that somehow returns
     somebody else's row cannot become a deletion. */
  const subject = String(options.subject || "").toLowerCase();
  if (!subject) {
    refuse([
      "REFUSING TO RUN: createResidueGuard was given no subject account.",
      "Call resolveSubjectAccount() and pass the result as options.subject.",
      "Nothing has been written or deleted."
    ]);
  }
  assertNotOwner(subject, "the residue guard was pointed at the owner's account");

  const state = {
    name: name,
    started_at: new Date().toISOString(),
    user_id: null,
    ledger_mark: 0,
    ids: {}
  };
  tables.forEach(function (t) { state.ids[t] = []; });

  let installed = false;
  let cleaning = false;
  let finished = false;

  function persist() {
    try {
      fs.writeFileSync(file, JSON.stringify(state, null, 2), "utf8");
    } catch (e) {
      /* A journal that cannot be written is worth saying out loud: from here
         on, a crash would leave rows nobody can find by id. */
      console.error("[residue] Could not write the run journal (" + file + "): " +
        ((e && e.message) || e) + ". A crash from here would leave rows with no list to clean them by.");
    }
  }

  function forget() {
    try { if (fs.existsSync(file)) fs.unlinkSync(file); } catch (e) { /* nothing to do */ }
  }

  /* ── what a previous run left ────────────────────────────────────────────── */
  async function sweepPrevious(userId) {
    /* Before the first read, let alone the first delete. */
    assertNotOwner(userId, "the startup sweep was pointed at the owner's account");
    if (userId && String(userId).toLowerCase() !== subject) {
      refuse([
        "REFUSING TO RUN: the sweep was given " + userId + " but this run's subject is " + subject + ".",
        "Nothing has been written or deleted."
      ]);
    }

    const found = { journal: null, rows: {}, removed: 0, failed: [] };
    tables.forEach(function (t) { found.rows[t] = []; });

    let previous = null;
    let previousLastSeen = null;
    try {
      if (fs.existsSync(file)) {
        previous = JSON.parse(fs.readFileSync(file, "utf8"));
        /* THE LAST MOMENT THE CRASHED RUN WAS DEMONSTRABLY ALIVE. It rewrites
           the journal on every row it records, so its mtime is the latest
           instant it can have written anything. The window sweep below is
           bounded by it: rows created after that are not its doing, and a
           sweep reaching past the crash would delete somebody else's work. */
        previousLastSeen = fs.statSync(file).mtime.toISOString();
      }
    } catch (e) {
      console.error("[residue] A journal exists at " + file + " but could not be read: " +
        ((e && e.message) || e) + ". Falling back to the ledger high-water sweep.");
    }

    if (previous && previous.user_id && String(previous.user_id).toLowerCase() !== subject) {
      /* A JOURNAL IS NOT AUTHORITY OVER SOMEBODY ELSE'S ROWS. Older journals
         predate the subject rule and can name whichever account the unordered
         pick happened to land on. Such a journal is reported, kept, and not
         acted on: deleting rows under an account this run was never allowed to
         touch is the thing being prevented, and a stale file is no reason to
         do it. */
      console.error("[residue] The journal at " + file + " belongs to " + previous.user_id +
        ", not to this run's subject " + subject + ". NOT sweeping it.");
      console.error("[residue] If those rows are residue, remove them by hand — ids:");
      tables.forEach(function (t) {
        const ids = (previous.ids && previous.ids[t]) || [];
        if (ids.length) console.error("[residue]   " + t + ": " + ids.join(", "));
      });
      previous = null;
    }

    if (previous) {
      found.journal = { started_at: previous.started_at, user_id: previous.user_id };
      for (const table of tables) {
        const ids = (previous.ids && previous.ids[table]) || [];
        if (!ids.length) continue;
        /* Re-read before deleting: a journal is a record of intent, and rows
           belonging to somebody else are never removed on its say-so. */
        const { data, error } = await supabase.from(table).select("id, user_id").in("id", ids);
        if (error) { found.failed.push(table + ": could not read (" + error.message + ")"); continue; }
        const mine = (data || []).filter(function (r) { return isSubjectRow(r, subject, table); });
        if (!mine.length) continue;
        const mineIds = mine.map(function (r) { return r.id; });
        found.rows[table] = found.rows[table].concat(mineIds);
        const del = await supabase.from(table).delete().in("id", mineIds);
        if (del.error) found.failed.push(table + ": could not delete " + mineIds.join(", ") + " (" + del.error.message + ")");
        else found.removed += mineIds.length;
      }

      /* Anything the journal missed: ledger rows written after the mark that
         run recorded, under the account it was using. */
      if (previous.user_id && typeof previous.ledger_mark === "number" && tables.indexOf("model_calls") !== -1) {
        const { data, error } = await supabase.from("model_calls")
          .select("id, user_id").eq("user_id", previous.user_id).gt("id", previous.ledger_mark);
        if (!error && data && data.length) {
          const extra = data.filter(function (r) { return isSubjectRow(r, subject, "model_calls"); })
            .map(function (r) { return r.id; })
            .filter(function (id) { return found.rows.model_calls.indexOf(id) === -1; });
          if (extra.length) {
            found.rows.model_calls = found.rows.model_calls.concat(extra);
            const del = await supabase.from("model_calls").delete().in("id", extra);
            if (del.error) found.failed.push("model_calls: could not delete " + extra.join(", ") + " (" + del.error.message + ")");
            else found.removed += extra.length;
          }
        }
      }
      /* AND THE ROW THAT NEVER REACHED THE JOURNAL. A crash can land between
         the insert returning and record() being called — that is how a killed
         run stranded an ai_tasks row the journal had never heard of. A table
         keyed by a uuid has no high-water mark to sweep by, so the window is
         time: from the crashed run's own start to the last moment it was
         alive, under the account it was using. Both ends and the account come
         from the crashed run itself; nothing outside that box is touched. */
      if (previous.user_id && previous.started_at && previousLastSeen) {
        const until = new Date(new Date(previousLastSeen).getTime() + 60000).toISOString();
        for (const table of tables) {
          if (table === "model_calls") continue;   /* swept by id, just above */
          const { data, error } = await supabase.from(table).select("id, user_id")
            .eq("user_id", previous.user_id)
            .gte("created_at", previous.started_at)
            .lte("created_at", until);
          if (error) { found.failed.push(table + ": could not read the crash window (" + error.message + ")"); continue; }
          const extra = (data || []).filter(function (r) { return isSubjectRow(r, subject, table); })
            .map(function (r) { return r.id; })
            .filter(function (id) { return found.rows[table].indexOf(id) === -1; });
          if (!extra.length) continue;
          found.rows[table] = found.rows[table].concat(extra);
          const del = await supabase.from(table).delete().in("id", extra);
          if (del.error) found.failed.push(table + ": could not delete " + extra.join(", ") + " (" + del.error.message + ")");
          else found.removed += extra.length;
        }
      }

      forget();
    }

    const total = tables.reduce(function (n, t) { return n + found.rows[t].length; }, 0);
    if (!total && !found.failed.length) {
      console.log("[residue] startup sweep: nothing left by a previous run.");
    } else {
      console.log("[residue] startup sweep: found " + total + " row(s) left by a previous run" +
        (found.journal ? " started " + found.journal.started_at : "") + ":");
      tables.forEach(function (t) {
        if (found.rows[t].length) console.log("[residue]   " + t + ": " + found.rows[t].join(", "));
      });
      console.log("[residue]   removed " + found.removed + " of " + total + ".");
      found.failed.forEach(function (f) { console.error("[residue]   COULD NOT REMOVE — " + f); });
    }

    state.user_id = userId || null;
    persist();
    return found;
  }

  /* ── what this run is causing ────────────────────────────────────────────── */
  function record(table, id) {
    if (id === undefined || id === null) return;
    if (!state.ids[table]) state.ids[table] = [];
    if (state.ids[table].indexOf(id) !== -1) return;
    state.ids[table].push(id);
    persist();
  }

  /* THE BASELINE IS SET ONCE AND NEVER MOVES. It is the highest model_calls id
     that existed BEFORE this run wrote anything, and the window sweep uses it to
     mean "everything after this is mine". Scripts also track a running mark of
     their own as they read new rows, and they pass it here — so this keeps the
     first value and ignores the rest. Letting it advance was a real bug: the
     baseline overtook rows the run had written, the sweep looked only above it,
     and two ledger rows survived a crash. */
  function setLedgerMark(id) {
    if (typeof id !== "number") return;
    if (state.ledger_mark === 0 || id < state.ledger_mark) {
      state.ledger_mark = id;
      persist();
    }
  }

  function counts() {
    const out = {};
    tables.forEach(function (t) { out[t] = state.ids[t].length; });
    return out;
  }

  /* ── the removal, and the read-back that is the only real report ─────────── */

  /* WHAT THE JOURNAL CANNOT KNOW. When a run crashes, the work already in
     flight keeps going: a route call that was mid-handler writes its ai_tasks
     row AFTER cleanup has read its id list, and that row belongs to nobody's
     list. The first crash test proved it — two rows survived a cleanup that
     reported itself clean.

     So the id sweep is followed by a WINDOW sweep: everything under the account
     this run borrowed, written since this run started. That is safe precisely
     because of what the run is — it borrows an account and is the only thing
     writing to it for the duration. It is bounded by the run's own start time
     and the ledger id it recorded before writing anything, so it can never
     reach a row that predates the run. */
  async function sweepOwnWindow() {
    const caught = [];
    if (!state.user_id) return caught;

    /* This is the sweep that deletes by time rather than by id, so it is the
       one with the most to lose from a wrong account. Checked again here,
       immediately before the deletes, and then row by row below. */
    assertNotOwner(state.user_id, "the cleanup window sweep was pointed at the owner's account");

    /* ai_tasks: this user, created at or after the run began. */
    const tasks = await supabase.from("ai_tasks")
      .select("id, user_id").eq("user_id", state.user_id).gte("created_at", state.started_at);
    if (!tasks.error && tasks.data && tasks.data.length) {
      const ids = tasks.data.filter(function (r) { return isSubjectRow(r, subject, "ai_tasks"); })
        .map(function (r) { return r.id; });
      if (ids.length) {
        const del = await supabase.from("ai_tasks").delete().in("id", ids);
        caught.push({ table: "ai_tasks", ids: ids, removed: !del.error, why: del.error ? del.error.message : null });
      }
    }

    /* model_calls: this user, above the id that existed before the run. */
    const calls = await supabase.from("model_calls")
      .select("id, user_id").eq("user_id", state.user_id).gt("id", state.ledger_mark);
    if (!calls.error && calls.data && calls.data.length) {
      const ids = calls.data.filter(function (r) { return isSubjectRow(r, subject, "model_calls"); })
        .map(function (r) { return r.id; });
      if (ids.length) {
        const del = await supabase.from("model_calls").delete().in("id", ids);
        caught.push({ table: "model_calls", ids: ids, removed: !del.error, why: del.error ? del.error.message : null });
      }
    }

    return caught;
  }

  let cleaningPromise = null;

  /* A SECOND WAY OUT MUST WAIT FOR THE FIRST, NOT WALK PAST IT. A crash rarely
     arrives alone: the work already in flight rejects moments later, and that
     second handler used to get an instant "already cleaning" back and call
     process.exit() out from under the cleanup still running — killing it
     mid-delete and leaving the journal behind. Handing every caller the SAME
     promise means the second one exits only once the first has finished, and
     on the first one's verdict. */
  function cleanup(reason) {
    if (cleaningPromise) return cleaningPromise;
    cleaning = true;
    cleaningPromise = runCleanup(reason);
    return cleaningPromise;
  }

  async function runCleanup(reason) {

    const leftovers = [];
    for (const table of tables) {
      const ids = state.ids[table];
      if (!ids.length) { console.log("[residue] " + table + ": nothing to delete"); continue; }

      /* Even here, where the ids came from this run's own journal: read the
         rows back and delete only those the subject actually owns. */
      const owners = await supabase.from(table).select("id, user_id").in("id", ids);
      const deletable = owners.error ? ids
        : (owners.data || []).filter(function (r) { return isSubjectRow(r, subject, table); })
            .map(function (r) { return r.id; });
      if (!owners.error && !deletable.length) { console.log("[residue] " + table + ": nothing of the subject's to delete"); continue; }

      const del = await supabase.from(table).delete().in("id", deletable);
      if (del.error) console.error("[residue] " + table + ": delete reported " + del.error.message);

      const { count, error } = await supabase.from(table).select("id", { count: "exact", head: true }).in("id", ids);
      if (error) {
        console.error("[residue] " + table + ": COULD NOT VERIFY (" + error.message + ") — assume these are still there: " + ids.join(", "));
        leftovers.push({ table: table, ids: ids.slice(), why: "verification failed: " + error.message });
        continue;
      }
      console.log("[residue] " + table + ": " + ids.length + " written, " + count + " still present after deletion");
      if (count > 0) {
        const stuck = await supabase.from(table).select("id").in("id", ids);
        leftovers.push({ table: table, ids: (stuck.data || []).map(function (r) { return r.id; }), why: "still present after delete" });
      }
    }

    /* SWEEP UNTIL QUIET. Work already in flight keeps finishing while cleanup
       runs, so one pass is not enough: each pass waits a beat, removes whatever
       the window now holds, and stops as soon as a pass finds nothing. Bounded
       at three so a script that somehow keeps writing cannot spin here. */
    if (state.user_id) {
      for (var pass = 1; pass <= 3; pass++) {
        await new Promise(function (resolve) { setTimeout(resolve, pass === 1 ? 1200 : 800); });
        const caught = await sweepOwnWindow();
        if (!caught.length) break;
        caught.forEach(function (c) {
          if (c.removed) {
            console.log("[residue] " + c.table + ": " + c.ids.length +
              " further row(s) written while the run was stopping — removed (" + c.ids.join(", ") + ")");
          } else {
            console.error("[residue] " + c.table + ": could not remove " + c.ids.join(", ") + " — " + c.why);
          }
        });
      }
    }

    /* THE VERDICT IS THE FINAL READ-BACK AND NOTHING ELSE. An id that was still
       present midway through cleanup but has since been removed by the window
       sweep is not residue; reporting it as such would cry wolf on every
       crashed run and teach the next reader to ignore the warning. */
    const stillThere = [];
    if (state.user_id) {
      const stuckTasks = await supabase.from("ai_tasks")
        .select("id").eq("user_id", state.user_id).gte("created_at", state.started_at);
      const stuckCalls = await supabase.from("model_calls")
        .select("id").eq("user_id", state.user_id).gt("id", state.ledger_mark);
      const taskIds = (stuckTasks.data || []).map(function (r) { return r.id; });
      const callIds = (stuckCalls.data || []).map(function (r) { return r.id; });
      console.log("[residue] final read-back — ai_tasks from this run: " + taskIds.length +
        ", model_calls from this run: " + callIds.length);
      if (taskIds.length) stillThere.push({ table: "ai_tasks", ids: taskIds, why: "still present in the run window" });
      if (callIds.length) stillThere.push({ table: "model_calls", ids: callIds, why: "still present in the run window" });
    } else {
      /* No account recorded: the id list is the only evidence available. */
      leftovers.forEach(function (l) { stillThere.push(l); });
    }

    leftovers.length = 0;
    stillThere.forEach(function (l) { leftovers.push(l); });

    if (leftovers.length) {
      console.error("\n[residue] RESIDUE LEFT BEHIND by this run (" + (reason || "end of run") + ") — remove by hand:");
      leftovers.forEach(function (l) {
        console.error("[residue]   " + l.table + ": " + l.ids.join(", ") + "   (" + l.why + ")");
      });
      console.error("[residue]   the journal is kept at " + file + " so the next run will try again.");
      persist();
    } else {
      console.log("[residue] verified by reading the tables back: 0 rows from this run remain.");
      forget();
    }

    finished = true;
    cleaning = false;
    return { leftovers: leftovers };
  }

  /* ── cleanup on every way out ────────────────────────────────────────────── */
  function install() {
    if (installed) return;
    installed = true;

    async function bail(reason, err, code) {
      if (err) console.error("\n[residue] " + reason + ": " + ((err && err.stack) || err));
      else console.error("\n[residue] " + reason + " — cleaning up before exit.");
      let result = { leftovers: [] };
      try {
        result = await cleanup(reason);
      } catch (cleanupErr) {
        console.error("[residue] CLEANUP ITSELF FAILED (" + ((cleanupErr && cleanupErr.message) || cleanupErr) + ").");
        console.error("[residue] These may still be in the database:");
        tables.forEach(function (t) {
          if (state.ids[t].length) console.error("[residue]   " + t + ": " + state.ids[t].join(", "));
        });
        console.error("[residue] the journal is at " + file);
        process.exit(code || 1);
      }
      process.exit(result.leftovers.length ? 1 : (code || 1));
    }

    process.on("uncaughtException", function (err) { bail("The run threw", err, 1); });
    process.on("unhandledRejection", function (err) { bail("A promise rejected with nobody to catch it", err, 1); });
    process.on("SIGINT", function () { bail("Interrupted (Ctrl-C)", null, 130); });
    process.on("SIGTERM", function () { bail("Terminated", null, 143); });

    /* A script that simply runs off the end without calling cleanup is a bug,
       but it must not be a bug that leaves rows. */
    process.on("beforeExit", function () {
      if (finished || cleaning) return;
      const total = tables.reduce(function (n, t) { return n + state.ids[t].length; }, 0);
      if (!total) { forget(); return; }
      console.error("[residue] The run ended without cleaning up. Doing it now.");
      cleanup("ended without cleanup").then(function (r) {
        process.exit(r.leftovers.length ? 1 : 0);
      });
    });
  }

  return {
    record: record,
    setLedgerMark: setLedgerMark,
    sweepPrevious: sweepPrevious,
    cleanup: cleanup,
    install: install,
    counts: counts,
    journalPath: file,
    ids: state.ids
  };
}

module.exports = {
  createResidueGuard: createResidueGuard,
  journalPath: journalPath,
  resolveSubjectAccount: resolveSubjectAccount,
  assertNotOwner: assertNotOwner,
  isSubjectRow: isSubjectRow,
  OWNER_ACCOUNT_ID: OWNER_ACCOUNT_ID,
  SUBJECT_ENV: SUBJECT_ENV
};
