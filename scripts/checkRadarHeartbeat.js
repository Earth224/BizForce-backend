"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   checkRadarHeartbeat — the lead radar says it is alive, in the database.

   leadRadar.js writes public.radar_status (migration 135), source 'bluesky':
   when the radar starts, and at the end of every tick with what the tick's
   Bluesky part did. This loads leadRadar.js in a vm with a stubbed BskyAgent,
   a stub member radar that returns a scripted tick, a fake clock and a fake
   Supabase that records every write: no network, no database, no Bluesky.

   NAMED (Nov 23 2026, LR-2): BEFORE the tick was leadRadar.js's own capture
   (runLeadRadarOnce), its row carried resumes_at from the gate, a skipped
   back-off tick wrote null counts, and YouTube wrote a second row (source
   'youtube', F). AFTER radarTick runs lib/memberRadar.js runTick for every
   member and writes ONE row, the tick's, built by tickHeartbeat from the
   tick's Bluesky result (searched, captured, stopped, or an error). YouTube
   writes no row of its own any more, and resumes_at is null (the member
   radar does not report it). The original is in git (65c0825).

   WHAT THIS PROVES
     A. Starting the radar writes process_started_at, once, at the start, then
        the first tick's row.
     B. tickHeartbeat maps every outcome: captured (a count), nothing_new,
        backoff (a 429), no_credentials, login_failed (stopped with nothing
        searched), and error with last_error; a tick with no Bluesky part
        (no member searching Bluesky) is nothing_new with 0 and 0.
     C. Uncounted values stay null, never 0: an error tick has null searches
        and captured.
     D. A heartbeat write that fails (an error answer or a throw) never stops
        or fails the tick; it is logged.
     E. A radar loaded but not started writes no heartbeat; one with no member
        radar handed in (setMemberRadarDeps) writes no tick row; and server.js
        starts it only when it is the program.
     F. Only the 'bluesky' row is written: no source 'youtube', whatever the
        YouTube switch says.

   MUTATE=<name> edits leadRadar.js IN MEMORY; MUTATE=all runs each in its own
   process; an unmatched search text is an ERROR, never a catch.
   ═══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm");
const REPO = path.join(__dirname, "..");
const MUTATE = process.env.MUTATE || "";
const MUT = require("./_shared");

const RADAR = "leadRadar.js", GATE = "lib/bskyGate.js", SERVER = "server.js";
const MUTATIONS = {
  // a failed heartbeat write throws into the tick
  "heartbeat-throws": [[RADAR, "  } catch (heartbeatErr) {\n    console.error(\"[LeadRadar] heartbeat (\"", "  } catch (heartbeatErr) {\n    throw heartbeatErr;\n    console.error(\"[LeadRadar] heartbeat (\""]],
  // a radar that was never started writes the heartbeat anyway
  "heartbeat-without-start": [[RADAR, "async function writeRadarHeartbeat(fields, when, source) {\n  if (!radarStarted) return;\n", "async function writeRadarHeartbeat(fields, when, source) {\n"]],
  // NAMED (Nov 23 2026, LR-2): an error tick writes 0 and 0 (uncounted written as counted)
  "zero-for-uncounted": [[RADAR, "  if (b.error) { row.last_outcome = \"error\"; row.last_error = String(b.error).slice(0, 1000); return row; }",
    "  if (b.error) { row.last_outcome = \"error\"; row.last_error = String(b.error).slice(0, 1000); row.searches = 0; row.captured = 0; return row; }"]],
  // NAMED (Nov 23 2026, LR-2): a 429 tick is recorded as nothing_new
  "nothing-new-in-backoff": [[RADAR, "  if (b.stopped === \"rate_limited\") row.last_outcome = \"backoff\";\n  else ", "  "]],
  // NAMED (Nov 23 2026, LR-2): a tick that throws writes no row
  "error-tick-silent": [[RADAR, "    if (memberDeps) await writeRadarHeartbeat(tickHeartbeat(startedAt, result), \"tick\");", "    if (memberDeps && result && !(result.bluesky && result.bluesky.error)) await writeRadarHeartbeat(tickHeartbeat(startedAt, result), \"tick\");"]]
};
if (MUTATE === "all") MUT.runAllMutations(__filename, Object.keys(MUTATIONS));

const FILES = {};
[RADAR, GATE, SERVER].forEach(f => { FILES[f] = fs.readFileSync(path.join(REPO, f), "utf8").replace(/\r\n/g, "\n"); });
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = MUT.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE);
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}
const J = JSON.stringify;
let CLOCK = Date.parse("2026-11-23T12:00:00.000Z");
class FakeDate extends Date { constructor(...a) { if (a.length === 0) super(CLOCK); else super(...a); } static now() { return CLOCK; } }
class FakeBskyAgent { constructor() { this.app = { bsky: { feed: { searchPosts: async () => ({ data: { posts: [] } }) } } }; this.login = async () => ({}); } }
const flush = async () => { for (let i = 0; i < 20; i++) await new Promise(r => setImmediate(r)); };

function loadModule(source, filename, requireFn, ctxExtra) {
  const m = { exports: {} };
  const ctx = Object.assign({ module: m, exports: m.exports, require: requireFn, __filename: filename, __dirname: path.dirname(filename),
    Date: FakeDate, setTimeout: () => 0, setInterval: () => 0, clearInterval() {}, Promise, JSON, Math, Buffer, URL, String, Object, Array, Number, Error }, ctxExtra);
  vm.createContext(ctx);
  vm.runInContext(source, ctx, { filename });
  return m.exports;
}

/* The radar, with a stub member radar whose runTick returns o.tick (or throws it), and a Supabase that records upserts. */
function radar(o) {
  o = o || {};
  const state = { heartbeats: [], logs: [], ticks: 0 };
  const logger = { log: (...a) => state.logs.push(a.join(" ")), error: (...a) => state.logs.push(a.join(" ")), warn: (...a) => state.logs.push(a.join(" ")) };
  const proc = { env: Object.assign({ BLUESKY_IDENTIFIER: "us.bsky.social", BLUESKY_APP_PASSWORD: "x", SUPABASE_URL: "http://fake", SUPABASE_SERVICE_KEY: "x" }, o.env || {}) };
  const sb = { from(t) { const b = { upsert(row) { if (t === "radar_status") state.heartbeats.push(row); return b; },
    then(res, rej) { if (o.writeThrows) return Promise.reject(new Error("socket closed")).then(res, rej); return Promise.resolve(o.writeError ? { error: { message: "permission denied" } } : { error: null }).then(res, rej); } }; return b; } };
  const gateModule = loadModule(FILES[GATE], path.join(REPO, GATE), require, { console: logger, process: proc });
  const memberStub = { AGENT_TYPE: "lead_radar", SCORE_ROUTE: "memberRadarScore",
    runTick: async () => { state.ticks++; if (o.tick instanceof Error) throw o.tick; return o.tick === undefined ? { bluesky: { searched: 4, captured: 2, carried: 0, stopped: null } } : o.tick; } };
  const requireFn = (name) => {
    if (name === "dotenv") return { config() {} };
    if (name === "@supabase/supabase-js") return { createClient: () => sb };
    if (name === "@atproto/api") return { BskyAgent: FakeBskyAgent };
    if (name === "./lib/bskyGate") return gateModule;
    if (name === "./lib/memberRadar") return memberStub;   // NAMED (Nov 23 2026, LR-2)
    if (name === "./youtubeRadar") return { memberYoutubeDeps: () => ({ youtube: true }) };
    throw new Error("unexpected require in leadRadar.js: " + name);
  };
  const mod = loadModule(FILES[RADAR], path.join(REPO, RADAR), requireFn, { console: logger, process: proc });
  if (o.deps !== false) mod.setMemberRadarDeps({ tierOf: async () => "member", callModel: async () => ({ text: "" }) });
  return { mod, state };
}

(async function main() {
  /* ── A ── */
  console.log("\n══ A. starting the radar ══");
  let R = radar();
  await R.mod.startLeadRadar(); await flush();
  check("A. the first write is process_started_at alone, once", R.state.heartbeats.length === 2 && !!R.state.heartbeats[0].process_started_at && Object.keys(R.state.heartbeats[0]).sort().join() === "process_started_at,source" &&
    R.state.heartbeats.filter(h => h.process_started_at).length === 1, J(R.state.heartbeats));
  const first = R.state.heartbeats[1] || {};
  check("A. then the first tick's row: captured, 4 searches, 2 captured, started and finished", first.last_outcome === "captured" && first.searches === 4 && first.captured === 2 &&
    !!first.last_tick_started_at && !!first.last_tick_finished_at && first.last_error === null && first.resumes_at === null && first.source === "bluesky", J(first));

  /* ── B, C ── */
  console.log("\n══ B. every outcome, and C. nothing uncounted is a 0 ══");
  const T = (b) => R.mod.tickHeartbeat("2026-11-23T12:00:00.000Z", b === undefined ? null : { bluesky: b });
  const cases = [
    ["captured", T({ searched: 3, captured: 5, stopped: null }), r => r.last_outcome === "captured" && r.searches === 3 && r.captured === 5],
    ["nothing_new", T({ searched: 3, captured: 0, stopped: null }), r => r.last_outcome === "nothing_new" && r.searches === 3 && r.captured === 0],
    ["backoff (a 429 met)", T({ searched: 1, captured: 0, stopped: "rate_limited" }), r => r.last_outcome === "backoff" && r.searches === 1],
    ["no_credentials", T({ searched: 0, captured: 0, stopped: "no_credentials" }), r => r.last_outcome === "no_credentials"],
    ["login_failed (stopped, nothing searched)", T({ searched: 0, captured: 0, stopped: "login_failed" }), r => r.last_outcome === "login_failed"],
    ["error, with its message, and null counts (C)", T({ error: "member_leads upsert failed" }), r => r.last_outcome === "error" && r.last_error === "member_leads upsert failed" && r.searches === null && r.captured === null],
    ["no Bluesky part (no member searches Bluesky): nothing_new, 0 and 0", T(undefined), r => r.last_outcome === "nothing_new" && r.searches === 0 && r.captured === 0]
  ];
  cases.forEach(([n, row, f]) => check("B. " + n, f(row), J(row)));
  R = radar({ tick: new Error("member_leads read failed") });
  await R.mod.startLeadRadar(); await flush();
  const thrown = R.state.heartbeats.slice(-1)[0] || {};
  check("B. a tick that throws: still a row, outcome error, its message, null counts", thrown.last_outcome === "error" && /member_leads read failed/.test(thrown.last_error || "") && thrown.searches === null && thrown.captured === null, J(R.state.heartbeats));

  /* ── D ── */
  console.log("\n══ D. a failed heartbeat write never stops the tick ══");
  for (const how of ["writeError", "writeThrows"]) {
    R = radar({ [how]: true });
    let threw = null;
    try { await R.mod.startLeadRadar(); await flush(); await R.mod.radarTick(); } catch (e) { threw = e; }
    check("D. " + (how === "writeError" ? "an error answer" : "a throw") + ": the ticks still ran and nothing threw, and it is logged",
      threw === null && R.state.ticks === 2 && R.state.logs.some(l => /heartbeat \(tick\) not written/.test(l)), J({ threw: threw && threw.message, ticks: R.state.ticks, logs: R.state.logs.slice(-3) }));
  }

  /* ── E ── */
  console.log("\n══ E. no heartbeat from a radar that was not started ══");
  R = radar();
  await R.mod.radarTick();
  check("E. loaded, ticked, never started: not one radar_status write", R.state.ticks === 1 && R.state.heartbeats.length === 0, J(R.state.heartbeats));
  R = radar({ deps: false });
  await R.mod.startLeadRadar(); await flush();
  check("E. started with no member radar handed in: process_started_at only, no tick row, no tick", R.state.heartbeats.length === 1 && !!R.state.heartbeats[0].process_started_at && R.state.ticks === 0, J(R.state.heartbeats));
  const startSite = FILES[SERVER].indexOf("    startLeadRadar(shutdownControl.trackInterval).catch(function (err) {");
  const guard = FILES[SERVER].lastIndexOf("  if (require.main === module) {\n", startSite);
  // NAMED (Nov 23 2026, LR-2): BEFORE the setModelLedger hand-in sat between guard and start (under 300). AFTER setMemberRadarDeps does, under 600.
  const handIn = FILES[SERVER].indexOf("    require(\"./leadRadar\").setMemberRadarDeps(leadRadarMemberDeps);\n", guard);
  check("E. server.js starts the radar only when it is the program, handing in the member radar first",
    startSite > 0 && guard > 0 && startSite - guard < 600 && handIn > guard && handIn < startSite && FILES[SERVER].slice(guard, startSite).indexOf("\n  }") === -1 &&
    (FILES[SERVER].match(/startLeadRadar\(/g) || []).length === 1, startSite + " / " + guard + " / " + handIn);

  /* ── F ── */
  console.log("\n══ F. one row, the tick's ══");
  R = radar({ env: { ENABLE_YOUTUBE_RADAR: "true" }, tick: { bluesky: { searched: 2, captured: 0, stopped: null }, youtube: { searched: 3, captured: 1 } } });
  await R.mod.startLeadRadar(); await flush();
  check("F. YouTube switched on: every row is source bluesky, none youtube (BEFORE LR-2 a youtube row was written)", R.state.heartbeats.length === 2 && R.state.heartbeats.every(h => h.source === "bluesky"), J(R.state.heartbeats.map(h => h.source)));
  check("F. leadRadar.js passes no source but the default to writeRadarHeartbeat", !/writeRadarHeartbeat\([^)]*,\s*"[^"]*",\s*"/.test(FILES[RADAR]));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.error("\nThe check threw: " + (e && e.stack || e)); process.exit(1); });
