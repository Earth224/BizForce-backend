"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   runChecks — one honest way to run the checks.

     node scripts/runChecks.js [--mutate] [--out <file>] [--timeout <s>]
                               [--mutate-timeout <s>] [--dir <folder>]

   Runs every real check in scripts/check*.js ONE PROCESS AT A TIME and prints
   a pass/fail line for each and "N of M real checks passed". Exits non-zero on
   any failure.

   REFUSES TO START WITHOUT BIZFORCE_CHECK_USER_ID. Checks that write rows do so
   under that account and remove them again (scripts/checkRunResidue.js); with
   it unset they would refuse one by one, and a run of refusals is not a run.

   BLUESKY IS BLANKED IN EVERY CHILD. BLUESKY_IDENTIFIER and
   BLUESKY_APP_PASSWORD are set to "" in the child environment. Set to empty,
   not deleted: the checks call require("dotenv").config(), which fills any
   variable that is ABSENT from .env, and .env holds the real credentials. An
   empty variable is present, so dotenv leaves it alone.

   HELPERS ARE NOT CHECKS. A check*.js file that assigns module.exports AND is
   require()d by another script under scripts/ is a helper module (today:
   checkRunResidue.js, which 31 checks require). Run on its own it defines
   functions and exits 0, which would count as a pass for nothing. Each one
   excluded is listed with the reason.

   A TIMEOUT IS A FAILURE, NEVER A HANG. Each script gets --timeout seconds
   (default 900); --mutate runs get --mutate-timeout (default 3600). On expiry
   the whole process tree is killed and the script is reported as failed.

   --mutate also runs MUTATE=all for every check that supports it (it calls
   runAllMutations), and reads its "MUTATION SUMMARY" line: caught, survived,
   errors. Any survived mutation, any error, a missing summary or a non-zero
   exit fails the run.

   --out <file> writes the whole report there too, including the output of
   every failed script.

   --dir <folder> runs the check*.js files in another folder (the fixtures in
   scripts/checkRunChecks.js use it). Default: this script's folder.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const { spawn, spawnSync } = require("child_process");

const BLANKED = ["BLUESKY_IDENTIFIER", "BLUESKY_APP_PASSWORD"];
const SUBJECT_ENV = "BIZFORCE_CHECK_USER_ID";

function parseArgs(argv) {
  const o = { mutate: false, out: null, timeout: 900, mutateTimeout: 3600, dir: __dirname };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const value = () => { if (i + 1 >= argv.length) throw new Error(a + " needs a value"); return argv[++i]; };
    if (a === "--mutate") o.mutate = true;
    else if (a === "--out") o.out = value();
    else if (a === "--timeout") o.timeout = Number(value());
    else if (a === "--mutate-timeout") o.mutateTimeout = Number(value());
    else if (a === "--dir") o.dir = path.resolve(value());
    else throw new Error("Unknown argument " + a);
  }
  if (!(o.timeout > 0) || !(o.mutateTimeout > 0)) throw new Error("timeouts must be positive numbers of seconds");
  return o;
}

/* Which check*.js files are real checks, and which are helpers (and why). */
function classify(dir) {
  const all = fs.readdirSync(dir).filter(f => /\.js$/.test(f)).sort();
  const sources = {};
  all.forEach(f => { sources[f] = fs.readFileSync(path.join(dir, f), "utf8"); });
  const checks = all.filter(f => /^check.*\.js$/.test(f));
  const real = [], helpers = [];
  checks.forEach(f => {
    const name = f.replace(/\.js$/, "");
    const exportsSomething = /(^|[^.\w])module\.exports\s*=|(^|[^.\w])exports\.\w+\s*=/m.test(sources[f]);
    const requiredBy = all.filter(other => other !== f &&
      new RegExp("require\\(\\s*[\"']\\./" + name + "(\\.js)?[\"']\\s*\\)").test(sources[other]));
    if (exportsSomething && requiredBy.length) {
      helpers.push({ file: f, reason: "assigns module.exports and is require()d by " + requiredBy.length + " script(s) (" +
        requiredBy.slice(0, 3).join(", ") + (requiredBy.length > 3 ? ", …" : "") + "); it runs no checks of its own" });
    } else {
      real.push({ file: f, mutate: /runAllMutations\(/.test(sources[f]) });
    }
  });
  return { real, helpers };
}

/* The real checks that write rows under the check account: the ones that
   require ./checkRunResidue. These are what BIZFORCE_CHECK_USER_ID is for. */
function liveRowChecks(dir) {
  return classify(dir).real.map(c => c.file)
    .filter(f => /require\(\s*["']\.\/checkRunResidue(\.js)?["']\s*\)/.test(fs.readFileSync(path.join(dir, f), "utf8")));
}

function childEnv(extra) {
  const env = Object.assign({}, process.env, extra || {});
  BLANKED.forEach(k => { env[k] = ""; });
  return env;
}

function killTree(child) {
  try {
    if (process.platform === "win32") spawnSync("taskkill", ["/pid", String(child.pid), "/T", "/F"], { stdio: "ignore" });
    else process.kill(-child.pid, "SIGKILL");
  } catch (e) {
    try { child.kill("SIGKILL"); } catch (e2) { /* already gone */ }
  }
}

function runOne(dir, file, env, seconds) {
  return new Promise(resolve => {
    const started = Date.now();
    const child = spawn(process.execPath, [path.join(dir, file)], {
      cwd: path.join(dir, ".."), env, stdio: ["ignore", "pipe", "pipe"], detached: process.platform !== "win32", windowsHide: true
    });
    let out = "";
    child.stdout.on("data", d => { out += d; });
    child.stderr.on("data", d => { out += d; });
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; killTree(child); }, seconds * 1000);
    child.on("close", code => {
      clearTimeout(timer);
      resolve({ code: timedOut ? null : code, timedOut, out, secs: (Date.now() - started) / 1000 });
    });
    child.on("error", err => { clearTimeout(timer); resolve({ code: null, timedOut: false, out: out + "\n" + err.message, secs: 0 }); });
  });
}

function firstFailure(out) {
  const lines = out.split(/\r?\n/);
  return (lines.find(l => /^\s*FAIL\b/.test(l)) || lines.find(l => /Error/.test(l)) || lines.filter(Boolean).pop() || "").trim().slice(0, 200);
}

async function main() {
  let opts;
  try { opts = parseArgs(process.argv.slice(2)); } catch (e) { console.error(e.message); process.exit(2); }
  if (!String(process.env[SUBJECT_ENV] || "").trim()) {
    const live = liveRowChecks(opts.dir);
    console.error("REFUSED: " + SUBJECT_ENV + " is not set: set it to run the " + live.length + " live-row checks. " +
      "Set it to the check account's id before running the checks; checks that write rows do so under that account " +
      "and remove them afterwards (scripts/checkRunResidue.js).\n" +
      "  PowerShell:  $env:" + SUBJECT_ENV + " = \"<the check account's user id>\"\n" +
      "  bash:        export " + SUBJECT_ENV + "=<the check account's user id>");
    process.exit(2);
  }

  const report = [];
  const say = (line) => { console.log(line); report.push(line); };
  const { real, helpers } = classify(opts.dir);
  const env = childEnv();

  say("BizForce checks, " + new Date().toISOString());
  say("Folder: " + opts.dir);
  say(SUBJECT_ENV + " set; " + BLANKED.join(" and ") + " blanked in every child.");
  say("Excluded (helpers, not checks):" + (helpers.length ? "" : " none"));
  helpers.forEach(h => say("  - " + h.file + ": " + h.reason));
  say("");
  say("== " + real.length + " real checks, one process at a time (timeout " + opts.timeout + "s each) ==");

  const failures = [];
  let passed = 0;
  for (const c of real) {
    const r = await runOne(opts.dir, c.file, env, opts.timeout);
    if (r.code === 0) {
      passed++;
      say("PASS  " + c.file + "  (" + r.secs.toFixed(1) + "s)");
    } else {
      const why = r.timedOut ? "TIMED OUT after " + opts.timeout + "s" : "exit " + r.code + ": " + firstFailure(r.out);
      say("FAIL  " + c.file + "  (" + r.secs.toFixed(1) + "s)  " + why);
      failures.push({ file: c.file, out: r.out, why });
    }
  }
  say("");
  say(passed + " of " + real.length + " real checks passed");

  let mutateFailed = false;
  const mutateDetail = [];
  if (opts.mutate) {
    const withMutations = real.filter(c => c.mutate);
    say("");
    say("== MUTATE=all for the " + withMutations.length + " checks that support it (timeout " + opts.mutateTimeout + "s each) ==");
    const total = { mutations: 0, caught: 0, survived: 0, errors: 0 };
    for (const c of withMutations) {
      const r = await runOne(opts.dir, c.file, childEnv({ MUTATE: "all" }), opts.mutateTimeout);
      const m = /MUTATION SUMMARY: mutations=(\d+) caught=(\d+) survived=(\d+) errors=(\d+)/.exec(r.out);
      let line;
      if (r.timedOut) {
        line = "FAIL  " + c.file + "  TIMED OUT after " + opts.mutateTimeout + "s";
      } else if (!m) {
        line = "FAIL  " + c.file + "  no MUTATION SUMMARY line (exit " + r.code + "): " + firstFailure(r.out);
      } else {
        const [mutations, caught, survived, errors] = m.slice(1).map(Number);
        total.mutations += mutations; total.caught += caught; total.survived += survived; total.errors += errors;
        const ok = survived === 0 && errors === 0 && r.code === 0;
        line = (ok ? "PASS  " : "FAIL  ") + c.file + "  caught=" + caught + " survived=" + survived + " errors=" + errors + " of " + mutations +
          (ok ? "" : "  (exit " + r.code + ")");
      }
      say(line);
      if (/^FAIL/.test(line)) { mutateFailed = true; mutateDetail.push({ file: c.file + " (MUTATE=all)", out: r.out, why: line }); }
    }
    say("");
    say("Mutations: " + total.caught + " caught, " + total.survived + " survived, " + total.errors + " errors, of " + total.mutations +
      " across " + withMutations.length + " checks");
  }

  const ok = failures.length === 0 && !mutateFailed;
  say("");
  say(ok ? "RESULT: PASS" : "RESULT: FAIL");

  if (opts.out) {
    const full = report.slice();
    failures.concat(mutateDetail).forEach(f => {
      full.push("", "──── output of " + f.file + " ────", f.out.trimEnd());
    });
    fs.writeFileSync(opts.out, full.join("\n") + "\n");
    console.log("Report written to " + opts.out);
  }
  process.exit(ok ? 0 : 1);
}

main();
