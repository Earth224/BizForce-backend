"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkCronJobs — the six wall-clock jobs fire when server.js says they fire,
   across daylight-saving changes, and loading server.js as a check runs no
   job and no reminder pass.

   NAMED BEFORE → AFTER (YouTube retention build, Oct 2026, assertions changed
   on purpose). There were five cron.schedule calls, all off unless their
   variable is exactly "true", and loading server.js with the gates unset
   registered no task. A sixth, youtubeRetentionTick (09:00 UTC), is ON BY
   DEFAULT: only ENABLE_YOUTUBE_RETENTION="false" turns it off, because it
   is how stored YouTube data stays within YouTube's 30-day rule. So "exactly
   five calls" is now six; "gates unset: no task" is now "gates unset:
   exactly the retention task, and the five say disabled"; "gates set:
   exactly the five" is now the six; and new loads prove that only
   ENABLE_YOUTUBE_RETENTION="false" removes the task ("False" does not).
   Still no job RUNS while server.js loads.

   THE HOST IS UTC, as production's is (no TZ is set on the Railway service and
   the container's clock is UTC). Every schedule is proved there, across both
   daylight-saving changes. The child's zone is checked, so a host zone that did
   not take effect fails rather than passing silently (Windows Node honours
   TZ=UTC but ignores other IANA names and falls back to the system zone).

   KNOWN, AND NOT ASSERTED: ON A HOST WHOSE OWN CLOCK OBSERVES DAYLIGHT TIME
   (America/Los_Angeles was measured), each node-cron version misses one run of
   the two hourly UTC jobs ("0 * * * *", { timezone: "UTC" }); the three daily
   Los Angeles jobs run correctly there under both versions.
     - node-cron 3.0.3, at the spring-forward: 2027-03-14T03:00:00Z is skipped
       (71 of 72 runs in the 72 hours around it, no spinning). TimeMatcher.apply
       formats the instant in the task's zone and re-parses the text as
       host-local time; "03/14/2027, 02:00" does not exist in Los Angeles and
       becomes 03:00 PDT, the same instant "…, 03:00" becomes, so the 03:00Z
       tick fails lastExecution < date_tmp and does not run.
     - node-cron 4.6.0, at the fall-back: 2026-11-01T09:00:00Z is skipped and
       the scheduler busy-spins through the repeated hour (71 of 72 runs,
       72,071 timer callbacks; node-cron logs "missed execution"). It sleeps
       until the next match computed in host-local time and, at the host's own
       fall-back, keeps re-arming at the same instant. This is why node-cron
       stays on 3.0.3.
   On a UTC host both versions run every one of these.

   THE SCHEDULES ARE READ FROM server.js, NOT RETYPED. Every cron.schedule(...)
   call is found in the source; its expression and its { timezone } are
   resolved from the literals or the variables they name (a variable read from
   the environment resolves to its default, and the variable is reported).

   THE REAL node-cron, A CONTROLLED CLOCK. Each schedule runs in a child process
   that replaces Date, setTimeout/clearTimeout and process.hrtime with one
   controllable clock BEFORE requiring node-cron; nothing node-cron provides is
   stubbed. Time only moves forward, and each timer callback costs 50 ms, as
   real work does, so a scheduler that re-arms at the same instant shows up as
   spinning rather than freezing the run. Each schedule is run for 72 hours
   around the end (2026-11-01) and the start (2027-03-14) of US daylight time,
   on a UTC host (the child's TZ, verified). The
   instants it ran are compared with every minute in the window whose
   wall-clock time IN THE DECLARED TIMEZONE matches node-cron's own reading of
   the expression (its convert-expression module).

   server.js IS LOADED THE WAY A CHECK LOADS IT, in a child with every outbound
   connection (http, https, net, tls, fetch) blocked and recorded: with the five
   ENABLE_* gates unset, as the suite runs, it registers only the default-on
   YouTube retention task; with ENABLE_YOUTUBE_RETENTION="false" as well, none;
   with all five set, exactly the six the source declares; it runs none; and in neither case does it run a reminder pass. server.js IS ALSO RUN
   AS THE PROGRAM (node -r <blocker> server.js, the on-disk file, network
   blocked, Bluesky blanked), where the reminder pass does start: that is the
   production path, package.json "start" being "node server.js".

   WHAT THIS PROVES
     1. server.js has exactly six cron.schedule calls; each passes only
        { timezone }, names a real IANA timezone, keeps no returned task, and
        sets none of scheduled, runOnInit or recoverMissedExecutions; nothing
        else calls cron.*.
     2. node-cron 3.0.3 is installed and accepts each expression.
     3. Under the controlled clock each task runs once at exactly each matching
        minute in its timezone, at no other, without spinning (at most one timer
        callback per simulated second), on a UTC host, across both changes; and
        a non-UTC job's minutes differ from the same expression read in UTC.
     4. Loading server.js as a check schedules none of the five opt-in jobs
        unless its gate is set, schedules the retention job unless its variable
        is exactly "false", registers exactly the declared six with the gates
        set, runs none, and runs no reminder pass. Running server.js as the program starts the
        reminder pass.

   MUTATE=<name> edits server.js IN MEMORY (the load children compile the edited
   text at server.js's own path; the as-the-program run uses the file on disk).
   MUTATE=all runs each in its own process and passes only if every one fails
   at least one check. A mutation whose search text does not match exactly once
   is an ERROR, never counted as caught.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const SERVER_PATH = path.join(REPO, "server.js");
const CRON_DIR = path.join(REPO, "node_modules", "node-cron");
const MUTATE = process.env.MUTATE || "";
const GATES = ["ENABLE_STORE_PROPOSAL_JOB", "ENABLE_SELF_REVIEW", "ENABLE_AGENT_SCHEDULES", "ENABLE_EMAIL_SEQUENCES", "ENABLE_NIGHTLY_BACKUP"];
// On by default: only the exact value "false" turns it off (lib/youtubeRetention.js).
const RETENTION_GATE = "ENABLE_YOUTUBE_RETENTION";

const MUTATIONS = {
  // the self-review job loses its timezone and runs on the host's clock
  "drop-a-timezone": ["    }, {\n      timezone: SELF_REVIEW_TIMEZONE\n    });\n", "    });\n"],
  // one expression is corrupted
  "corrupt-an-expression": ["    cron.schedule(\"0 7 * * *\", function () {\n", "    cron.schedule(\"0 77 * * *\", function () {\n"],
  // the reminder pass runs whenever server.js is loaded, a check included
  "unguard-reminders": ["if (require.main === module) {\n  setInterval(reminderTick, 60000);\n", "if (true) {\n  setInterval(reminderTick, 60000);\n"]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}

let SRC = fs.readFileSync(SERVER_PATH, "utf8").replace(/\r\n/g, "\n");
if (MUTATE) {
  const edit = MUTATIONS[MUTATE];
  if (!edit) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  SRC = s.replaceOnce(SRC, edit[0], edit[1], MUTATE);
  console.log("\n!! MUTATION: " + MUTATE + " (server.js, in memory)");
}

const cron = require(CRON_DIR);
// node-cron's own reading of an expression: six space-separated fields of comma lists.
const convertExpression = require(path.join(CRON_DIR, "src", "convert-expression"));
const { DateTime } = require(path.join(REPO, "node_modules", "luxon"));
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "bf-cronjobs-"));

/* ── reading the schedules from the source ─────────────────────────────── */
// The text of the argument list of a call starting at `open` (the "(" index).
function argsAt(src, open) {
  const close = s.braceMatch(src.replace(/\(/g, "{").replace(/\)/g, "}"), open);
  return src.slice(open + 1, close - 1);
}
function resolveValue(expr) {
  expr = expr.trim();
  let m = /^"([^"\\]*)"$/.exec(expr);
  if (m) return { value: m[1], from: "literal" };
  if (!/^[A-Za-z_$][\w$]*$/.test(expr)) return { value: null, from: "unresolvable: " + expr };
  const re = new RegExp("(?:^|\\n)\\s*(?:var|const|let)\\s+" + expr + "\\s*=\\s*([^;\\n]+);", "g");
  const defs = [...SRC.matchAll(re)].map(x => x[1].trim());
  if (defs.length !== 1) return { value: null, from: expr + " defined " + defs.length + " times" };
  m = /^"([^"\\]*)"$/.exec(defs[0]);
  if (m) return { value: m[1], from: expr };
  m = /^process\.env\.([A-Z_]+)\s*\|\|\s*"([^"\\]*)"$/.exec(defs[0]);
  if (m) return { value: m[2], from: expr + " (process.env." + m[1] + ", default)", env: m[1] };
  return { value: null, from: expr + " = " + defs[0] };
}
const calls = [];
{
  const re = /cron\.schedule\(/g; let m;
  while ((m = re.exec(SRC))) {
    const open = m.index + "cron.schedule".length;
    const args = argsAt(SRC, open);
    const first = args.slice(0, args.indexOf(","));
    const optMatch = /\},\s*(\{[\s\S]*\})\s*$/.exec(args);
    const optText = optMatch ? optMatch[1] : null;
    const tz = optText ? /^\{\s*timezone:\s*([^,\s}]+)\s*\}$/.exec(optText) : null;
    const lineStart = SRC.lastIndexOf("\n", m.index) + 1;
    calls.push({
      line: SRC.slice(0, m.index).split("\n").length,
      expression: resolveValue(first),
      optionsText: optText,
      timezone: tz ? resolveValue(tz[1]) : { value: null, from: optText ? "options without exactly one timezone: " + optText : "no options object" },
      isStatement: SRC.slice(lineStart, m.index).trim() === ""
    });
  }
}
function fieldsOf(expression) {
  try {
    const six = convertExpression(expression).split(" ");
    if (six.length !== 6) return null;
    return six.map(f => f.split(",").map(Number));
  } catch (e) { return null; }
}
function valid(expression) {
  try { return cron.validate(expression) === true; } catch (e) { return false; }
}

/* ── the controlled clock, in a child ──────────────────────────────────── */
const CLOCK_CHILD = `
const RealDate = Date;
const job = JSON.parse(process.argv[2]);
let NOW = RealDate.parse(job.start);
class FakeDate extends RealDate {
  constructor(...a) { if (a.length === 0) super(NOW); else super(...a); }
  static now() { return NOW; }
}
global.Date = FakeDate;
// process.hrtime on the same clock (node-cron 3 measures elapsed time with it).
const toHr = (ms) => [Math.floor(ms / 1000), Math.round((ms % 1000) * 1e6)];
const fakeHrtime = (prev) => {
  const now = toHr(NOW);
  if (!prev) return now;
  let s = now[0] - prev[0], n = now[1] - prev[1];
  if (n < 0) { s -= 1; n += 1e9; }
  return [s, n];
};
fakeHrtime.bigint = () => BigInt(NOW) * 1000000n;
process.hrtime = fakeHrtime;
let seq = 0; const timers = new Map();
const handle = (id) => ({ id, unref() { return this; }, ref() { return this; }, hasRef() { return false; }, refresh() { return this; }, [Symbol.toPrimitive]() { return id; } });
global.setTimeout = (fn, ms, ...args) => { const id = ++seq; timers.set(id, { due: NOW + Math.max(0, Number(ms) || 0), fn, args }); return handle(id); };
global.clearTimeout = (h) => { if (h) timers.delete(typeof h === "object" ? h.id : h); };
const cron = require(${JSON.stringify(CRON_DIR)});
const fired = [];
let task;
try {
  task = cron.schedule(job.expression, () => { fired.push(NOW); }, job.timezone ? { timezone: job.timezone } : undefined);
} catch (e) { process.stdout.write(JSON.stringify({ error: String(e && e.message || e) })); process.exit(0); }
const end = NOW + job.hours * 3600000;
let callbacks = 0;
for (;;) {
  let next = null;
  for (const [id, t] of timers) if (t.due <= end && (!next || t.due < next[1].due)) next = [id, t];
  if (!next) break;
  if (++callbacks > 600000) break;
  timers.delete(next[0]); NOW = Math.max(NOW, next[1].due);
  next[1].fn(...next[1].args);
  NOW += 50;
}
const tz = task.options && task.options.timezone;
task.stop();
process.stdout.write(JSON.stringify({ fired, timezone: tz, callbacks, hostZone: Intl.DateTimeFormat().resolvedOptions().timeZone }));
`;
const CLOCK_FILE = path.join(TMP, "clock.js");
fs.writeFileSync(CLOCK_FILE, CLOCK_CHILD);
// hostTz is the timezone of the machine running the scheduler (the child's TZ).
function runUnderClock(expression, timezone, start, hours, hostTz) {
  const env = Object.assign({}, process.env, { TZ: hostTz });
  const r = spawnSync(process.execPath, [CLOCK_FILE, JSON.stringify({ expression, timezone, start, hours })], { env, encoding: "utf8", timeout: 600000 });
  try { return JSON.parse(r.stdout); } catch (e) { return { error: "child: " + (r.stdout + r.stderr).slice(0, 300) }; }
}
// Every minute in the window whose wall-clock time in `zone` matches node-cron's own reading of the expression.
function expectedMinutes(expression, zone, start, hours) {
  const f = fieldsOf(expression);
  if (!f) return null;
  const [sec, min, hour, dom, month, dow] = f;
  const out = [];
  const t0 = Date.parse(start), end = t0 + hours * 3600000;
  for (let ms = Math.ceil(t0 / 60000) * 60000; ms <= end; ms += 60000) {
    const d = DateTime.fromMillis(ms, { zone });
    if (sec.includes(0) && min.includes(d.minute) && hour.includes(d.hour) && dom.includes(d.day) && month.includes(d.month) &&
      dow.includes(d.weekday % 7)) out.push(ms);
  }
  return out;
}

/* ── server.js loaded as a check loads it, in a child ───────────────────── */
const BLOCKER = `
const attempts = [];
const block = (what) => function () { attempts.push(what); throw new Error("network blocked by checkCronJobs: " + what); };
for (const [mod, fns] of [["http", ["request", "get"]], ["https", ["request", "get"]], ["net", ["connect", "createConnection"]], ["tls", ["connect"]]]) {
  const m = require(mod); fns.forEach(f => { m[f] = block(mod + "." + f); });
}
globalThis.fetch = (u) => { attempts.push("fetch " + String(u).split("?")[0]); return Promise.reject(new Error("network blocked by checkCronJobs: fetch")); };
const logs = [], out = process.stdout.write.bind(process.stdout);
console.log = (...a) => { logs.push(a.join(" ")); };
console.error = (...a) => { logs.push("ERR " + a.join(" ")); };
console.warn = (...a) => { logs.push("WARN " + a.join(" ")); };
process.env.PORT = "0";
global.__checkCronJobs = { attempts, logs, out };
`;
const LOAD_CHILD = `
require(${JSON.stringify(path.join(TMP, "blocker.js"))});
const { attempts, logs, out } = global.__checkCronJobs;
const path = require("path"), Module = require("module");
let crashed = null;
process.on("uncaughtException", (e) => { crashed = String(e && e.message || e); });
const cron = require(${JSON.stringify(CRON_DIR)});
// A passthrough count of task runs: node-cron's own method, still called.
const ScheduledTask = require(${JSON.stringify(path.join(CRON_DIR, "src", "scheduled-task"))});
let runs = 0;
const realNow = ScheduledTask.prototype.now;
ScheduledTask.prototype.now = function () { runs++; return realNow.apply(this, arguments); };
const file = ${JSON.stringify(SERVER_PATH)};
const m = new Module(file, module); m.filename = file; m.paths = Module._nodeModulePaths(path.dirname(file));
try { m._compile(require("fs").readFileSync(process.argv[2], "utf8"), file); } catch (e) { crashed = "load: " + (e && e.message || e); }
const t0 = Date.now();
(function wait() {
  const listened = logs.some(l => /BizForce AI server running/.test(l));
  if (!listened && !crashed && Date.now() - t0 < 30000) return setTimeout(wait, 50);
  setTimeout(() => {
    const tasks = [...cron.getTasks().values()].map(t => ({ pattern: t._scheduler && t._scheduler.timeMatcher.pattern, timezone: (t.options && t.options.timezone) || null }));
    out(JSON.stringify({ listened, crashed, tasks, runs, attempts,
      reminderLogs: logs.filter(l => /reminderScheduler|reminder scheduler/.test(l)),
      gates: logs.filter(l => /\\[startup\\] (storeProposalTick|selfReviewTick|agentScheduleTick|emailSequenceTick|runNightlyBackup|youtubeRetentionTick) /.test(l)) }));
    process.exit(0);
  }, 1500);
})();
`;
// server.js as the program: the blocker preloaded, then node runs the file on disk.
const PROGRAM_PRELOAD = `
require(${JSON.stringify(path.join(TMP, "blocker.js"))});
const { attempts, logs, out } = global.__checkCronJobs;
const realSetTimeout = setTimeout;
const t0 = Date.now();
(function wait() {
  const listened = logs.some(l => /BizForce AI server running/.test(l));
  if (!listened && Date.now() - t0 < 30000) return realSetTimeout(wait, 50);
  realSetTimeout(() => {
    out(JSON.stringify({ listened, isMain: true, attempts, reminderLogs: logs.filter(l => /reminderScheduler|reminder scheduler/.test(l)) }));
    process.exit(0);
  }, 1500);
})();
`;
fs.writeFileSync(path.join(TMP, "blocker.js"), BLOCKER);
const LOAD_FILE = path.join(TMP, "load.js");
const PROGRAM_FILE = path.join(TMP, "program.js");
const SRC_FILE = path.join(TMP, "server.src.js");
fs.writeFileSync(LOAD_FILE, LOAD_CHILD);
fs.writeFileSync(PROGRAM_FILE, PROGRAM_PRELOAD);
fs.writeFileSync(SRC_FILE, SRC);
function childEnv(gatesOn, retention) {
  const env = Object.assign({}, process.env, { BLUESKY_IDENTIFIER: "", BLUESKY_APP_PASSWORD: "" });
  GATES.forEach(g => { if (gatesOn) env[g] = "true"; else delete env[g]; });
  if (retention === undefined) delete env[RETENTION_GATE]; else env[RETENTION_GATE] = retention;
  delete env.BACKUP_CRON; delete env.BACKUP_TIMEZONE;
  return env;
}
function parseChild(r) {
  try { return JSON.parse(r.stdout); } catch (e) { return { error: "child: " + (String(r.stdout) + String(r.stderr)).slice(0, 400) }; }
}
function loadServer(gatesOn, retention) {
  return parseChild(spawnSync(process.execPath, [LOAD_FILE, SRC_FILE], { cwd: REPO, env: childEnv(gatesOn, retention), encoding: "utf8", timeout: 120000 }));
}
function runServerAsProgram() {
  return parseChild(spawnSync(process.execPath, ["-r", PROGRAM_FILE, SERVER_PATH], { cwd: REPO, env: childEnv(false), encoding: "utf8", timeout: 120000 }));
}
const reminderRead = (attempts) => (attempts || []).some(a => /calendar_events/.test(a));

(async function main() {
  try {
    /* ── 1. the calls ─────────────────────────────────────────────────────── */
    console.log("\n══ 1. the cron.schedule calls in server.js ══");
    calls.forEach(c => console.log("    server.js:" + c.line + "  " + JSON.stringify(c.expression.value) + " from " + c.expression.from +
      ", timezone " + JSON.stringify(c.timezone.value) + " from " + c.timezone.from));
    // NAMED BEFORE → AFTER: was "exactly five"; the sixth is the YouTube retention job.
    check("server.js has exactly six cron.schedule calls", calls.length === 6, calls.length);
    check("each expression resolves from the source", calls.every(c => typeof c.expression.value === "string"), JSON.stringify(calls.map(c => c.expression)));
    check("each passes exactly one option, a timezone, resolved from the source",
      calls.every(c => typeof c.timezone.value === "string" && c.timezone.value.length > 0), JSON.stringify(calls.map(c => [c.line, c.timezone.from])));
    check("each timezone is a real IANA zone", calls.every(c => c.timezone.value && DateTime.now().setZone(c.timezone.value).isValid),
      calls.map(c => c.timezone.value).join(", "));
    const otherCron = [...SRC.matchAll(/\bcron\.([A-Za-z]+)/g)].map(m => m[1]).filter(n => n !== "schedule");
    check("nothing else calls cron.* (no validate, getTasks or task handling)", otherCron.length === 0, otherCron.join(", "));
    check("no call keeps the returned task (no now, start/stop or task events)", calls.every(c => c.isStatement));
    check("none sets scheduled, runOnInit or recoverMissedExecutions",
      !/\b(runOnInit|recoverMissedExecutions)\b/.test(SRC) && calls.every(c => !c.optionsText || !/scheduled\s*:/.test(c.optionsText)));

    /* ── 2. the installed library ─────────────────────────────────────────── */
    console.log("\n══ 2. node-cron 3.0.3 accepts them ══");
    const installed = require(path.join(CRON_DIR, "package.json")).version;
    const pkg = JSON.parse(fs.readFileSync(path.join(REPO, "package.json"), "utf8"));
    const lock = JSON.parse(fs.readFileSync(path.join(REPO, "package-lock.json"), "utf8"));
    check("node-cron 3.0.3 is installed and locked (package.json allows " + pkg.dependencies["node-cron"] + ")",
      installed === "3.0.3" && lock.packages["node_modules/node-cron"].version === "3.0.3", installed + " / lock " + lock.packages["node_modules/node-cron"].version);
    calls.forEach(c => check("server.js:" + c.line + " " + JSON.stringify(c.expression.value) + " is a valid node-cron expression",
      typeof c.expression.value === "string" && valid(c.expression.value) && fieldsOf(c.expression.value) !== null));

    /* ── 3. the controlled clock ──────────────────────────────────────────── */
    // A UTC host, as production's. The DST-observing host is recorded in the header, not asserted.
    const HOSTS = ["UTC"];
    const WINDOWS = [["2026-10-30T23:59:30.000Z", "the end of daylight time"], ["2027-03-12T23:59:30.000Z", "the start of daylight time"]];
    const HOURS = 72;
    console.log("\n══ 3. under a controlled clock, " + HOURS + " hours around each DST change, on a UTC host ══");
    const minute = (ms) => Math.floor(ms / 60000) * 60000;
    const iso = (list) => (list || []).map(ms => new Date(ms).toISOString());
    for (const c of calls) {
      const label = "server.js:" + c.line + " " + JSON.stringify(c.expression.value) + " in " + JSON.stringify(c.timezone.value);
      if (typeof c.expression.value !== "string" || !c.timezone.value || !valid(c.expression.value)) {
        check(label + " runs at exactly its matching minutes", false, "no usable expression or timezone");
        continue;
      }
      if (c.timezone.value !== "UTC") {
        const want = expectedMinutes(c.expression.value, c.timezone.value, WINDOWS[0][0], HOURS);
        const asUtc = expectedMinutes(c.expression.value, "UTC", WINDOWS[0][0], HOURS);
        check(label + ": the timezone matters (its minutes differ from the same expression read in UTC)", JSON.stringify(asUtc) !== JSON.stringify(want));
      }
      for (const host of HOSTS) {
        for (const [start, what] of WINDOWS) {
          const ran = runUnderClock(c.expression.value, c.timezone.value, start, HOURS, host);
          const want = expectedMinutes(c.expression.value, c.timezone.value, start, HOURS) || [];
          const got = (ran.fired || []).map(minute);
          // At most one timer callback per simulated second (node-cron 3 polls once a second); more is the scheduler spinning.
          const spinning = typeof ran.callbacks !== "number" || ran.callbacks > HOURS * 3600 + 2 * want.length + 10;
          check(label + " on a " + host + " host, across " + what + ": runs once at each of the " + want.length +
            " matching minutes, at no other, without spinning",
            !ran.error && ran.hostZone === host && ran.timezone === c.timezone.value && want.length > 0 && JSON.stringify(got) === JSON.stringify(want) && !spinning,
            (ran.error || "") + (ran.hostZone !== host ? "the host zone did not take effect (TZ=" + host + " ran as " + ran.hostZone + "); " : "") + " ran " + got.length + " times, " + ran.callbacks + " timer callbacks; missing " +
            JSON.stringify(iso(want.filter(ms => got.indexOf(ms) === -1)).slice(0, 4)) + ", extra " + JSON.stringify(iso(got.filter(ms => want.indexOf(ms) === -1)).slice(0, 4)));
        }
      }
    }

    /* ── 4. loading server.js, and running it ─────────────────────────────── */
    console.log("\n══ 4. loading server.js the way a check does (network blocked), and running it as the program ══");
    const off = loadServer(false);
    const retentionCall = calls.find(c => c.expression.value === "0 9 * * *" && c.timezone.value === "UTC");
    const retentionDeclared = retentionCall ? convertExpression(retentionCall.expression.value) + " @ UTC" : null;
    // NAMED BEFORE → AFTER: was "gates unset: registers no node-cron task" and "each of the five says it is disabled".
    check("gates unset, as the suite runs: the server comes up and registers exactly one task, the YouTube retention job at 09:00 UTC (on by default)",
      off.listened === true && !off.crashed && Array.isArray(off.tasks) && off.tasks.length === 1 && !!retentionDeclared &&
      off.tasks[0].pattern + " @ " + off.tasks[0].timezone === retentionDeclared, JSON.stringify(off).slice(0, 400));
    check("…each of the five opt-in jobs says it is disabled, and the retention job says it is scheduled",
      Array.isArray(off.gates) && off.gates.length === 6 && off.gates.filter(l => / disabled /.test(l)).length === 5 &&
      off.gates.some(l => /youtubeRetentionTick scheduled — 09:00 UTC daily/.test(l)), JSON.stringify(off.gates));
    const retentionOff = loadServer(false, "false");
    check("ENABLE_YOUTUBE_RETENTION exactly \"false\": no task at all, and the retention job says it is disabled",
      retentionOff.listened === true && !retentionOff.crashed && Array.isArray(retentionOff.tasks) && retentionOff.tasks.length === 0 &&
      (retentionOff.gates || []).some(l => /youtubeRetentionTick disabled/.test(l)), JSON.stringify(retentionOff).slice(0, 400));
    const retentionFalsey = loadServer(false, "False");
    check("ENABLE_YOUTUBE_RETENTION \"False\" (not exactly \"false\"): the retention task is still registered",
      retentionFalsey.listened === true && (retentionFalsey.tasks || []).length === 1, JSON.stringify(retentionFalsey.tasks));
    check("…and it runs no reminder pass (no calendar_events read, no pass logged; the guard says so)",
      off.listened === true && !reminderRead(off.attempts) && (off.reminderLogs || []).length === 1 && /reminder scheduler not started/.test(off.reminderLogs[0]),
      JSON.stringify({ attempts: off.attempts, reminderLogs: off.reminderLogs }));
    const on = loadServer(true);
    const declared = calls.map(c => (fieldsOf(c.expression.value) ? convertExpression(c.expression.value) : c.expression.value) + " @ " + c.timezone.value).sort();
    const registered = (on.tasks || []).map(t => t.pattern + " @ " + t.timezone).sort();
    // NAMED BEFORE → AFTER: was "exactly the five declared schedules".
    check("gates set: exactly the six declared schedules are registered, with their expressions and timezones",
      on.listened === true && !on.crashed && registered.length === 6 && JSON.stringify(registered) === JSON.stringify(declared),
      JSON.stringify(on.crashed || on.error || registered.map(r => r.slice(0, 40))) + " vs " + JSON.stringify(declared.map(r => r.slice(0, 40))));
    check("…none of them ran while server.js loaded, and still no reminder pass",
      on.listened === true && on.runs === 0 && off.runs === 0 && !reminderRead(on.attempts), JSON.stringify({ runs: on.runs, offRuns: off.runs, attempts: on.attempts }));
    const prog = runServerAsProgram();
    check("run as the program (node server.js, as production starts it): the reminder pass starts (it reads calendar_events, blocked here)",
      prog.listened === true && reminderRead(prog.attempts) && !(prog.reminderLogs || []).some(l => /not started/.test(l)),
      JSON.stringify(prog).slice(0, 400));
    const net = [...new Set((off.attempts || []).concat(on.attempts || []))];
    console.log("    note  outbound attempts blocked while server.js loaded as a check: " + (net.join(", ") || "none"));
  } finally {
    fs.rmSync(TMP, { recursive: true, force: true });
  }

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); try { fs.rmSync(TMP, { recursive: true, force: true }); } catch (x) {} process.exit(1); });
