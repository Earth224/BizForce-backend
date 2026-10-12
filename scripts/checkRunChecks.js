"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkRunChecks — the suite runner tells the truth, and a malformed run id
   never reaches the database.

   scripts/runChecks.js is run as its own process against tiny fixture checks
   written to a temp folder: a pass, a fail, a helper module and the check that
   requires it, a check that hangs, and checks that report mutations. The
   fixtures record what they saw (their environment, after dotenv has loaded a
   .env holding Bluesky credentials) and when they started and ended. No
   network, no model call, no database.

   WHAT THIS PROVES
     1. Without BIZFORCE_CHECK_USER_ID the runner refuses, exit 2, and runs
        nothing.
     2. A helper (assigns module.exports, required by another script) is
        excluded and listed with its reason, and is never run or counted.
     3. BLUESKY_IDENTIFIER and BLUESKY_APP_PASSWORD are empty in every child,
        even when the parent has them and the child loads a .env that has
        them.
     4. Checks run one at a time; "N of M real checks passed" counts exactly;
        any failure or a timeout exits 1, and a timeout is reported as a
        failure without hanging the run; all passing exits 0; --out writes the
        report with the failing output.
     5. --mutate reads each MUTATION SUMMARY: a survived mutation fails the run
        even when the script exits 0; a script without MUTATE support is not
        run with MUTATE=all; all caught exits 0.
     6. GET /api/ai/tasks/:id (lifted from server.js) answers a malformed id
        with the same 404 { error: "Task not found" } as a missing one, and
        makes no database call for it.

   MUTATE=<name> edits the runner or server.js IN MEMORY (the runner is run
   from a temp copy). MUTATE=all runs each in its own process and passes only
   if every one fails at least one check. A mutation whose search text does
   not match exactly once is an ERROR, never counted as caught.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const os = require("os");
const path = require("path");
const vm = require("vm");
const { spawnSync } = require("child_process");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const MUTATE = process.env.MUTATE || "";
const RUNNER = "runner", SERVER = "server";

const MUTATIONS = {
  // helpers are run and counted as checks
  "include-helpers": [[RUNNER, "    if (exportsSomething && requiredBy.length) {\n", "    if (false) {\n"]],
  // the Bluesky variables reach the children
  "stop-blanking-bluesky": [[RUNNER, "  BLANKED.forEach(k => { env[k] = \"\"; });\n", ""]],
  // a survived mutation counts as a pass
  "survived-as-pass": [[RUNNER, "        const ok = survived === 0 && errors === 0 && r.code === 0;\n", "        const ok = errors === 0 && r.code === 0;\n"]],
  // a malformed id is sent to the database
  "malformed-id-reaches-db": [[SERVER, "    if (!isValidUuid(req.params.id)) {\n      return res.status(404).json({ error: \"Task not found\" });\n    }\n", ""]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}

const SOURCES = {
  [RUNNER]: fs.readFileSync(path.join(__dirname, "runChecks.js"), "utf8").replace(/\r\n/g, "\n"),
  [SERVER]: fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n")
};
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) SOURCES[file] = s.replaceOnce(SOURCES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}

/* ── the fixtures ───────────────────────────────────────────────────────── */
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "bf-runchecks-"));
const RUNNER_COPY = path.join(TMP, "runChecks.js");
fs.writeFileSync(RUNNER_COPY, SOURCES[RUNNER]);
const DOTENV = require.resolve("dotenv", { paths: [REPO] });

// Every fixture loads a .env that holds Bluesky credentials, as the real checks do, then logs what it sees.
const PRELUDE = (name) =>
  "require(" + JSON.stringify(DOTENV) + ").config({ path: require(\"path\").join(__dirname, \"..\", \".env\") });\n" +
  "const __log = (o) => require(\"fs\").appendFileSync(process.env.FIXTURE_LOG, JSON.stringify(Object.assign({ name: " + JSON.stringify(name) + ", t: Date.now() }, o)) + \"\\n\");\n" +
  "__log({ phase: \"start\", has: Object.prototype.hasOwnProperty.call(process.env, \"BLUESKY_IDENTIFIER\"), id: process.env.BLUESKY_IDENTIFIER, pw: process.env.BLUESKY_APP_PASSWORD, mutate: process.env.MUTATE || null });\n";
const FIXTURES = {
  checkPass: PRELUDE("checkPass") + "setTimeout(() => { __log({ phase: \"end\" }); console.log(\"    pass  fine\\nALL PASS\"); process.exit(0); }, 300);\n",
  checkFail: PRELUDE("checkFail") + "setTimeout(() => { __log({ phase: \"end\" }); console.log(\"    FAIL  the fixture failed on purpose\"); process.exit(1); }, 300);\n",
  checkHelper: PRELUDE("checkHelper") + "module.exports = { helps: true };\n",
  checkUsesHelper: PRELUDE("checkUsesHelper") + "const h = require(\"./checkHelper\");\n" +
    "setTimeout(() => { __log({ phase: \"end\" }); console.log(h.helps ? \"ALL PASS\" : \"FAIL\"); process.exit(h.helps ? 0 : 1); }, 300);\n",
  checkHang: PRELUDE("checkHang") + "setInterval(() => {}, 1000);\n",
  checkMutCaught: PRELUDE("checkMutCaught") + "function runAllMutations() {}\n" +
    "if (process.env.MUTATE === \"all\") { console.log(\"MUTATION SUMMARY: mutations=2 caught=2 survived=0 errors=0\"); process.exit(0); }\n" +
    "__log({ phase: \"end\" }); console.log(\"ALL PASS\"); process.exit(0);\n",
  // Exits 0 even though a mutation survived: the runner must read the summary, not just the exit code.
  checkMutSurvived: PRELUDE("checkMutSurvived") + "function runAllMutations() {}\n" +
    "if (process.env.MUTATE === \"all\") { console.log(\"MUTATION SUMMARY: mutations=3 caught=2 survived=1 errors=0\"); process.exit(0); }\n" +
    "__log({ phase: \"end\" }); console.log(\"ALL PASS\"); process.exit(0);\n",
  checkNoMutate: PRELUDE("checkNoMutate") + "__log({ phase: \"end\" }); console.log(\"ALL PASS\"); process.exit(0);\n"
};
function folder(name, files) {
  const root = path.join(TMP, name);
  fs.mkdirSync(path.join(root, "scripts"), { recursive: true });
  fs.writeFileSync(path.join(root, ".env"), "BLUESKY_IDENTIFIER=leaked-from-dotenv\nBLUESKY_APP_PASSWORD=leaked-password\n");
  files.forEach(f => fs.writeFileSync(path.join(root, "scripts", f + ".js"), FIXTURES[f]));
  return path.join(root, "scripts");
}
function run(dir, args, envExtra, unset) {
  const log = path.join(TMP, "log-" + Math.random().toString(36).slice(2) + ".jsonl");
  fs.writeFileSync(log, "");
  const env = Object.assign({}, process.env, { FIXTURE_LOG: log, BIZFORCE_CHECK_USER_ID: "fixture-account",
    BLUESKY_IDENTIFIER: "parent-identifier", BLUESKY_APP_PASSWORD: "parent-password" }, envExtra || {});
  (unset || []).forEach(k => { delete env[k]; });
  const started = Date.now();
  const r = spawnSync(process.execPath, [RUNNER_COPY, "--dir", dir].concat(args || []), { env, encoding: "utf8", timeout: 120000 });
  const entries = fs.readFileSync(log, "utf8").split("\n").filter(Boolean).map(l => JSON.parse(l));
  return { code: r.status, out: String(r.stdout || "") + String(r.stderr || ""), entries, secs: (Date.now() - started) / 1000 };
}

/* ── the route, lifted ──────────────────────────────────────────────────── */
function liftTaskRoute() {
  const SRC = SOURCES[SERVER];
  const sig = "app.get(\"/api/ai/tasks/:id\",";
  const start = SRC.indexOf(sig);
  if (start < 0 || SRC.indexOf(sig, start + 1) >= 0) throw new Error("GET /api/ai/tasks/:id not found exactly once");
  const end = s.braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("function (req, res, next)", start)));
  const fnStart = SRC.indexOf("function isValidUuid(");
  const isValidUuid = SRC.slice(fnStart, s.braceMatch(SRC, SRC.indexOf("{", fnStart)) + 1);
  return isValidUuid + "\n" + SRC.slice(start, end + 2);
}

(async function main() {
  try {
    /* ── 1. refuses without the check account ─────────────────────────────── */
    console.log("\n══ 1. no BIZFORCE_CHECK_USER_ID, no run ══");
    const basic = folder("basic", ["checkPass", "checkFail", "checkHelper", "checkUsesHelper", "checkHang"]);
    let r = run(basic, [], {}, ["BIZFORCE_CHECK_USER_ID"]);
    check("unset: refused with exit 2 and the reason, and no check ran",
      r.code === 2 && /REFUSED: BIZFORCE_CHECK_USER_ID is not set/.test(r.out) && r.entries.length === 0, r.code + " " + r.out);
    r = run(basic, [], { BIZFORCE_CHECK_USER_ID: "   " });
    check("blank: refused the same way", r.code === 2 && /REFUSED/.test(r.out) && r.entries.length === 0, r.code + " " + r.out);

    /* ── 2-4. a mixed run ─────────────────────────────────────────────────── */
    console.log("\n══ 2-4. helpers, Bluesky, one at a time, counting, timeout ══");
    const outFile = path.join(TMP, "report.md");
    r = run(basic, ["--timeout", "3", "--out", outFile]);
    check("the helper is listed as excluded, with its reason",
      /Excluded \(helpers, not checks\):\n  - checkHelper\.js: assigns module\.exports and is require\(\)d by 1 script\(s\) \(checkUsesHelper\.js\); it runs no checks of its own/.test(r.out), r.out);
    check("…and is never run or counted as a check",
      // It starts only when checkUsesHelper requires it, never on its own.
      !/(PASS|FAIL)  checkHelper\.js/.test(r.out) &&
      r.entries.filter(e => e.name === "checkHelper").length === r.entries.filter(e => e.name === "checkUsesHelper" && e.phase === "start").length &&
      / 4 real checks, one process at a time/.test(r.out), r.out);
    const starts = r.entries.filter(e => e.phase === "start");
    check("every child saw BLUESKY_IDENTIFIER and BLUESKY_APP_PASSWORD present and empty, though the parent and .env held values",
      starts.length >= 4 && starts.every(e => e.has === true && e.id === "" && e.pw === ""), JSON.stringify(starts.map(e => [e.name, e.id, e.pw])));
    const runs = ["checkFail", "checkPass", "checkUsesHelper"].map(n => ({ n, s: (r.entries.find(e => e.name === n && e.phase === "start") || {}).t,
      e: (r.entries.find(e => e.name === n && e.phase === "end") || {}).t }));
    const ordered = runs.slice().sort((a, b) => a.s - b.s);
    check("one process at a time: no check started before the previous one ended",
      runs.every(x => x.s && x.e) && ordered.every((x, i) => i === 0 || x.s >= ordered[i - 1].e), JSON.stringify(runs));
    check("a pass line and a fail line per script, the fail naming its first FAIL",
      /PASS  checkPass\.js/.test(r.out) && /PASS  checkUsesHelper\.js/.test(r.out) && /FAIL  checkFail\.js .*exit 1: FAIL  the fixture failed on purpose/.test(r.out), r.out);
    check("a hanging check is killed at the timeout and reported as a failure, and the run does not hang",
      /FAIL  checkHang\.js .*TIMED OUT after 3s/.test(r.out) && r.secs < 60, r.secs + "s " + r.out);
    check("\"2 of 4 real checks passed\", RESULT: FAIL, exit 1", /\n2 of 4 real checks passed\n/.test(r.out) && /RESULT: FAIL/.test(r.out) && r.code === 1, r.code + " " + r.out);
    const written = fs.existsSync(outFile) ? fs.readFileSync(outFile, "utf8") : "";
    check("--out writes the report, with the failing script's output",
      /2 of 4 real checks passed/.test(written) && /──── output of checkFail\.js ────\n    FAIL  the fixture failed on purpose/.test(written), written.slice(0, 300));

    const green = folder("green", ["checkPass", "checkHelper", "checkUsesHelper"]);
    r = run(green);
    check("all passing: \"2 of 2 real checks passed\", RESULT: PASS, exit 0",
      r.code === 0 && /\n2 of 2 real checks passed\n/.test(r.out) && /RESULT: PASS/.test(r.out), r.code + " " + r.out);

    /* ── 5. --mutate ──────────────────────────────────────────────────────── */
    console.log("\n══ 5. --mutate ══");
    const mut = folder("mutate", ["checkMutCaught", "checkMutSurvived", "checkNoMutate"]);
    r = run(mut, ["--mutate"]);
    check("each supporting check is run with MUTATE=all and its summary reported",
      /PASS  checkMutCaught\.js  caught=2 survived=0 errors=0 of 2/.test(r.out) && /FAIL  checkMutSurvived\.js  caught=2 survived=1 errors=0 of 3/.test(r.out), r.out);
    check("a survived mutation fails the run even though that script exited 0",
      r.code === 1 && /RESULT: FAIL/.test(r.out) && /3 of 3 real checks passed/.test(r.out), r.code + " " + r.out);
    check("a check without MUTATE support is not run with MUTATE=all; the total is reported",
      !r.entries.some(e => e.name === "checkNoMutate" && e.mutate === "all") && /== MUTATE=all for the 2 checks that support it/.test(r.out) &&
      /Mutations: 4 caught, 1 survived, 0 errors, of 5 across 2 checks/.test(r.out), r.out);
    const mutGreen = folder("mutate-green", ["checkMutCaught", "checkNoMutate"]);
    r = run(mutGreen, ["--mutate"]);
    check("every mutation caught: exit 0", r.code === 0 && /RESULT: PASS/.test(r.out), r.code + " " + r.out);

    /* ── 6. the run-id route ──────────────────────────────────────────────── */
    console.log("\n══ 6. GET /api/ai/tasks/:id and a malformed id ══");
    const OWNER = "aaaaaaaa-0000-4000-8000-000000000001";
    const TASK = "71111111-1111-4111-8111-000000000001";
    const reads = [];
    const supabase = { from(table) {
      const q = { table, filters: [] }; reads.push(q);
      const b = { select() { return b; }, eq(k, v) { q.filters.push([k, v]); return b; },
        maybeSingle() { const id = (q.filters.find(f => f[0] === "id") || [])[1]; const user = (q.filters.find(f => f[0] === "user_id") || [])[1];
          return Promise.resolve({ data: id === TASK && user === OWNER ? { id: TASK, user_id: OWNER, status: "completed" } : null, error: null }); } };
      return b;
    } };
    const routes = {};
    const ctx = { supabase, requireAuth: (req, res, next) => next(), app: { get(p) { routes[p] = [].slice.call(arguments, 1); } }, JSON };
    vm.createContext(ctx);
    vm.runInContext(liftTaskRoute(), ctx);
    async function get(idValue) {
      const res = { code: 200, body: null, status(x) { this.code = x; return this; }, json(x) { this.body = x; return this; } };
      const chain = routes["/api/ai/tasks/:id"];
      let error = null;
      await chain[1]({ params: { id: idValue }, user: { id: OWNER } }, res, (e) => { error = e; });
      return { code: error ? 500 : res.code, body: res.body };
    }
    const missing = await get("71111111-1111-4111-8111-00000000ffff");
    check("a well-formed id that is not there: 404 { error: \"Task not found\" } after one read",
      missing.code === 404 && JSON.stringify(missing.body) === "{\"error\":\"Task not found\"}" && reads.length === 1, JSON.stringify(missing) + " reads=" + reads.length);
    const found = await get(TASK);
    check("the caller's own id: 200 { task }", found.code === 200 && found.body.task && found.body.task.id === TASK, JSON.stringify(found));
    for (const bad of ["not-a-uuid", "123", "' or 1=1 --", TASK + "x", "", "71111111-1111-4111-8111-00000000000g"]) {
      const before = reads.length;
      const got = await get(bad);
      check("malformed id " + JSON.stringify(bad) + ": the same 404, and no database call",
        got.code === 404 && JSON.stringify(got.body) === "{\"error\":\"Task not found\"}" && reads.length === before, JSON.stringify(got) + " reads+" + (reads.length - before));
    }
  } finally {
    fs.rmSync(TMP, { recursive: true, force: true });
  }

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
