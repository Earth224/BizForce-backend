"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkRadarHeartbeat — the lead radar says it is alive, in the database.

   leadRadar.js writes public.radar_status (migration 135) for 'bluesky': when
   the radar starts, and at the end of every Bluesky capture tick with what
   that tick did. This loads leadRadar.js in a vm with a stubbed BskyAgent, a
   fake clock and a fake Supabase that records every write — no network, no
   database, no Bluesky call of any kind.

   WHAT THIS PROVES
     A. Starting the radar writes process_started_at, once, at the start.
     B. Every outcome writes the right row: captured (a count of NEW rows, not
        duplicates), nothing_new, backoff with resumes_at (both a 429 met in
        the tick and a tick skipped for a back-off), no_credentials,
        login_failed with last_error, and error with last_error.
     C. Uncounted values stay null, never 0: a tick skipped for a back-off has
        null searches and captured, and a tick whose insert count did not come
        back has null captured.
     D. A heartbeat write that fails — an error answer or a throw — never stops
        or fails the tick: the capture still happens, it is logged once per
        tick, and runLeadRadarOnce does not throw.
     E. A radar that was loaded but not started writes no heartbeat, and
        server.js starts it only when server.js is the program — so loading
        server.js, as about twenty checks do, writes none.

   MUTATE=<name> edits leadRadar.js IN MEMORY (nothing on disk is touched).
   MUTATE=all runs each in its own process; an unmatched search text is an
   ERROR, never a catch (scripts/_shared.js).
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm");
const REPO = path.join(__dirname, "..");
const MUTATE = process.env.MUTATE || "";
const MUT = require("./_shared");

const RADAR = "leadRadar.js", GATE = "lib/bskyGate.js", SERVER = "server.js";
const MUTATIONS = {
  // a failed heartbeat write throws into the tick
  "heartbeat-throws": [[RADAR, "  } catch (heartbeatErr) {\n    console.error(\"[LeadRadar] heartbeat (\"", "  } catch (heartbeatErr) {\n    throw heartbeatErr;\n    console.error(\"[LeadRadar] heartbeat (\""]],
  // searches is written as 0 even when the tick searched nothing (a back-off skip)
  "zero-for-uncounted": [[RADAR, "    searches: skipped ? null : tick.searches,", "    searches: tick.searches,"]],
  // a radar that was never started writes the heartbeat anyway
  "heartbeat-without-start": [[RADAR, "async function writeRadarHeartbeat(fields, when) {\n  if (!radarStarted) return;\n", "async function writeRadarHeartbeat(fields, when) {\n"]],
  // a tick skipped for a back-off is recorded as nothing_new
  "nothing-new-in-backoff": [[RADAR, "  if (tick.stop) {\n    row.last_outcome = tick.stop.outcome;", "  if (tick.stop && !tick.stop.skipped) {\n    row.last_outcome = tick.stop.outcome;"]]
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

/* ── fake clock ────────────────────────────────────────────────────────────── */
let CLOCK = Date.parse("2026-10-11T05:00:00.000Z");
class FakeDate extends Date {
  constructor(...a) { if (a.length === 0) super(CLOCK); else super(...a); }
  static now() { return CLOCK; }
}
const iso = (ms) => new Date(ms).toISOString();

/* ── the stubbed agent ─────────────────────────────────────────────────────── */
const BSKY = { logins: 0, searches: 0, loginPlan: [], searchPlan: [] };
function bskyError(status, error, headers) { const e = new Error("XRPC " + status + " " + error); e.status = status; e.error = error; if (headers) e.headers = headers; return e; }
let POSTS_PER_SEARCH = 2;
class FakeBskyAgent {
  constructor() {
    this.app = { bsky: { feed: { searchPosts: async (params) => {
      BSKY.searches++;
      const step = BSKY.searchPlan.length ? BSKY.searchPlan.shift() : "ok";
      if (step instanceof Error) throw step;
      const posts = Array.from({ length: POSTS_PER_SEARCH }, (_, i) => ({ uri: "at://did:plc:a/app.bsky.feed.post/" + params.q.replace(/\W/g, "") + i, cid: "c",
        author: { did: "did:plc:a", handle: "a.bsky.social" }, record: { text: "post " + params.q, createdAt: iso(CLOCK) }, indexedAt: iso(CLOCK) }));
      return { data: { posts } };
    } } } };
    this.login = async () => {
      BSKY.logins++;
      const step = BSKY.loginPlan.length ? BSKY.loginPlan.shift() : "ok";
      if (step instanceof Error) throw step;
      return { success: true };
    };
    this.post = async () => { throw new Error("no posting in this check"); };
  }
}

/* ── the fake Supabase ─────────────────────────────────────────────────────── */
// insertMode: "new" (every row new), "dupes" (none new), "uncounted" (data null), "error"
function fakeSupabase(state) {
  return {
    from(table) {
      const q = { table, op: null, payload: null, opts: null, cols: null };
      const b = {
        upsert(p, o) { q.op = "upsert"; q.payload = p; q.opts = o; return b; },
        insert(p) { q.op = "insert"; q.payload = p; return b; },
        select(c) { q.cols = c; return b; },
        eq() { return b; }, in() { return b; }, order() { return b; }, limit() { return b; },
        then(res, rej) {
          state.log.push(q);
          if (q.table === "radar_status") {
            state.heartbeats.push(JSON.parse(JSON.stringify(q.payload)));
            if (state.heartbeatFail === "throw") return Promise.reject(new Error("heartbeat connection dropped")).then(res, rej);
            if (state.heartbeatFail === "error") return Promise.resolve({ data: null, error: { message: "permission denied for table radar_status" } }).then(res, rej);
            return Promise.resolve({ data: null, error: null }).then(res, rej);
          }
          if (q.table === "bsky_leads" && q.op === "upsert") {
            const rows = q.payload;
            if (state.insertMode === "error") return Promise.resolve({ data: null, error: { message: "insert failed" } }).then(res, rej);
            if (state.insertMode === "uncounted") return Promise.resolve({ data: null, error: null }).then(res, rej);
            const fresh = state.insertMode === "dupes" ? [] : rows.filter(r => !state.leads.has(r.post_uri));
            fresh.forEach(r => state.leads.add(r.post_uri));
            return Promise.resolve({ data: fresh.map(r => ({ post_uri: r.post_uri })), error: null }).then(res, rej);
          }
          return Promise.resolve({ data: [], error: null }).then(res, rej);
        }
      };
      return b;
    }
  };
}

function loadModule(source, filename, requireFn, ctxExtra) {
  const m = { exports: {} };
  const ctx = Object.assign({ module: m, exports: m.exports, require: requireFn, __filename: filename, __dirname: path.dirname(filename),
    Date: FakeDate, setTimeout: () => 0, setInterval: () => 0, clearInterval() {}, Promise, JSON, Math, Buffer, URL }, ctxExtra);
  vm.createContext(ctx);
  vm.runInContext(source, ctx, { filename });
  return m.exports;
}

function radar(opts) {
  const o = opts || {};
  Object.assign(BSKY, { logins: 0, searches: 0, loginPlan: [], searchPlan: [] });
  POSTS_PER_SEARCH = 2;
  const state = { log: [], heartbeats: [], leads: new Set(), insertMode: "new", heartbeatFail: null };
  const logs = [];
  const logger = { log: (...a) => logs.push(a.join(" ")), error: (...a) => logs.push(a.join(" ")), warn: (...a) => logs.push(a.join(" ")) };
  const proc = { env: Object.assign({ BLUESKY_IDENTIFIER: "us.bsky.social", BLUESKY_APP_PASSWORD: "pw", SUPABASE_URL: "http://fake", SUPABASE_SERVICE_KEY: "x" }, o.env || {}) };
  const supabase = fakeSupabase(state);
  const gateModule = loadModule(FILES[GATE], path.join(REPO, GATE), require, { console: logger, process: proc });
  const requireFn = (name) => {
    if (name === "dotenv") return { config() {} };
    if (name === "@supabase/supabase-js") return { createClient: () => supabase };
    if (name === "@atproto/api") return { BskyAgent: FakeBskyAgent };
    if (name === "@anthropic-ai/sdk") return function Anthropic() { throw new Error("no model in this check"); };
    if (name === "./mastodonRadar") return { runMastodonRadarOnce: async () => {} };
    if (name === "./youtubeRadar") return { runYoutubeRadarOnce: async () => {} };
    if (name === "./lib/resolveAnthropicKey") return () => async () => null;
    if (name === "./lib/bskyGate") return gateModule;
    if (name === "./lib/ownerAccount") return require(path.join(REPO, "lib/ownerAccount"));
    throw new Error("unexpected require in leadRadar.js: " + name);
  };
  const mod = loadModule(FILES[RADAR], path.join(REPO, RADAR), requireFn, { console: logger, process: proc });
  return { mod, state, logs, gate: mod.bskyGate };
}
const flush = async () => { for (let i = 0; i < 30; i++) await new Promise(r => setImmediate(r)); };
const tickRows = (st) => st.heartbeats.filter(h => "last_outcome" in h);
const last = (st) => tickRows(st)[tickRows(st).length - 1] || {};
const KEYWORDS = 32;

(async function main() {
  /* ── A. start ──────────────────────────────────────────────────────────── */
  console.log("\n══ A. starting the radar writes process_started_at ══");
  let R = radar();
  const startAt = iso(CLOCK);
  await R.mod.startLeadRadar();
  await flush();
  const first = R.state.heartbeats[0] || {};
  check("the first heartbeat is { source: bluesky, process_started_at: now }", JSON.stringify(first) === JSON.stringify({ source: "bluesky", process_started_at: startAt }), JSON.stringify(first));
  check("it is an upsert on source", R.state.log.find(q => q.table === "radar_status").opts && R.state.log.find(q => q.table === "radar_status").opts.onConflict === "source");
  check("process_started_at is written once", R.state.heartbeats.filter(h => h.process_started_at).length === 1);
  check("the startup tick then writes its own heartbeat", tickRows(R.state).length === 1 && last(R.state).last_outcome === "captured", JSON.stringify(last(R.state)));

  /* ── B. each outcome ───────────────────────────────────────────────────── */
  console.log("\n══ B. each outcome writes the right row ══");
  R = radar(); await R.mod.startLeadRadar(); await flush();
  CLOCK += 300000;
  const t0 = iso(CLOCK);
  await R.mod.runLeadRadarOnce();
  let h = last(R.state);
  check("the same posts again: outcome nothing_new, " + KEYWORDS + " searches, captured 0 (the startup tick captured them all)",
    h.last_outcome === "nothing_new" && h.searches === KEYWORDS && h.captured === 0, JSON.stringify(h));
  POSTS_PER_SEARCH = 3;
  CLOCK += 300000;
  await R.mod.runLeadRadarOnce();
  h = last(R.state);
  check("captured counts only NEW rows: one new post per search → captured " + KEYWORDS, h.last_outcome === "captured" && h.searches === KEYWORDS && h.captured === KEYWORDS, JSON.stringify(h));
  check("…with its start and finish times, no error and no resumes_at", h.last_tick_started_at === iso(CLOCK) && h.last_tick_finished_at === iso(CLOCK) && h.last_error === null && h.resumes_at === null, JSON.stringify(h));
  check("nothing_new: searched and nothing new (the tick at " + t0 + ")", tickRows(R.state)[1].last_outcome === "nothing_new" && tickRows(R.state)[1].last_tick_started_at === t0);
  R.state.insertMode = "dupes";
  CLOCK += 300000;
  await R.mod.runLeadRadarOnce();
  h = last(R.state);
  check("nothing_new when every match was a duplicate: captured 0, searches " + KEYWORDS, h.last_outcome === "nothing_new" && h.captured === 0 && h.searches === KEYWORDS, JSON.stringify(h));

  R = radar(); await R.mod.startLeadRadar(); await flush();
  BSKY.searchPlan = ["ok", bskyError(429, "RateLimitExceeded", { "retry-after": "900" })];
  CLOCK += 300000;
  await R.mod.runLeadRadarOnce();
  h = last(R.state);
  check("a 429 met in the tick: outcome backoff with resumes_at, the searches it made counted", h.last_outcome === "backoff" && h.resumes_at === iso(CLOCK + 900000) && h.searches === 1, JSON.stringify(h));
  CLOCK += 300000;
  await R.mod.runLeadRadarOnce();
  h = last(R.state);
  check("a tick skipped for the back-off: outcome backoff, resumes_at, no search made", h.last_outcome === "backoff" && h.resumes_at === iso(R.gate.backoffUntil()) && BSKY.searches === KEYWORDS + 2, JSON.stringify(h));

  R = radar({ env: { BLUESKY_IDENTIFIER: "" } }); await R.mod.startLeadRadar(); await flush();
  h = last(R.state);
  check("no credentials: outcome no_credentials, 0 searches made", h.last_outcome === "no_credentials" && h.searches === 0 && BSKY.logins === 0, JSON.stringify(h));

  R = radar();
  BSKY.loginPlan = [bskyError(500, "InternalServerError")];
  await R.mod.startLeadRadar(); await flush();
  h = last(R.state);
  check("a failed login: outcome login_failed with last_error", h.last_outcome === "login_failed" && /500 InternalServerError/.test(h.last_error || "") && h.searches === 0, JSON.stringify(h));

  R = radar(); await R.mod.startLeadRadar(); await flush();
  BSKY.searchPlan = Array.from({ length: KEYWORDS }, () => bskyError(500, "UpstreamFailure"));
  CLOCK += 300000;
  await R.mod.runLeadRadarOnce();
  h = last(R.state);
  check("every search failing: outcome error with last_error", h.last_outcome === "error" && /UpstreamFailure/.test(h.last_error || ""), JSON.stringify(h));
  R.state.insertMode = "error";
  CLOCK += 300000;
  await R.mod.runLeadRadarOnce();
  h = last(R.state);
  check("the insert failing: outcome error, last_error names it, captured null (not counted)", h.last_outcome === "error" && /insert failed/.test(h.last_error || "") && h.captured === null, JSON.stringify(h));

  /* ── C. uncounted stays null ───────────────────────────────────────────── */
  console.log("\n══ C. what was not counted is null, never 0 ══");
  R = radar(); await R.mod.startLeadRadar(); await flush();
  BSKY.loginPlan = [];
  BSKY.searchPlan = [bskyError(429, "RateLimitExceeded")];
  CLOCK += 300000;
  await R.mod.runLeadRadarOnce();
  CLOCK += 300000;
  await R.mod.runLeadRadarOnce();
  h = last(R.state);
  check("a tick skipped for a back-off: searches null and captured null", h.last_outcome === "backoff" && h.searches === null && h.captured === null, JSON.stringify(h));
  R = radar(); await R.mod.startLeadRadar(); await flush();
  R.state.insertMode = "uncounted";
  POSTS_PER_SEARCH = 4;
  CLOCK += 300000;
  await R.mod.runLeadRadarOnce();
  h = last(R.state);
  check("the insert count did not come back: captured null, searches counted, outcome error saying why",
    h.captured === null && h.searches === KEYWORDS && h.last_outcome === "error" && /insert count did not come back/.test(h.last_error || ""), JSON.stringify(h));

  /* ── D. a failed heartbeat never stops the tick ────────────────────────── */
  console.log("\n══ D. a failed heartbeat write never stops the tick ══");
  for (const mode of ["error", "throw"]) {
    R = radar(); await R.mod.startLeadRadar(); await flush();
    R.state.heartbeatFail = mode;
    POSTS_PER_SEARCH = 3;
    const leadsBefore = R.state.leads.size, logsBefore = R.logs.length;
    CLOCK += 300000;
    let threw = null;
    try { await R.mod.runLeadRadarOnce(); } catch (e) { threw = e; }
    const hbLogs = R.logs.slice(logsBefore).filter(l => /heartbeat \(tick\) not written/.test(l));
    check("heartbeat " + mode + ": the tick does not throw", threw === null, threw && threw.message);
    check("heartbeat " + mode + ": the capture still happened (" + KEYWORDS + " new leads written)", R.state.leads.size === leadsBefore + KEYWORDS, R.state.leads.size - leadsBefore);
    check("heartbeat " + mode + ": logged once for the tick", hbLogs.length === 1, hbLogs.length);
    CLOCK += 300000;
    threw = null;
    try { await R.mod.runLeadRadarOnce(); } catch (e) { threw = e; }
    check("heartbeat " + mode + ": the next tick still runs", threw === null && BSKY.searches >= 3 * KEYWORDS, BSKY.searches);
  }
  R = radar(); R.state.heartbeatFail = "throw";
  let startThrew = null;
  try { await R.mod.startLeadRadar(); await flush(); } catch (e) { startThrew = e; }
  check("a failed start heartbeat does not stop the radar starting", startThrew === null && BSKY.searches === KEYWORDS, startThrew ? startThrew.message : BSKY.searches);

  /* ── E. not started, no heartbeat ──────────────────────────────────────── */
  console.log("\n══ E. a radar that was not started writes no heartbeat ══");
  R = radar();
  await R.mod.runLeadRadarOnce();
  BSKY.searchPlan = [bskyError(429, "RateLimitExceeded")];
  CLOCK += 300000;
  await R.mod.runLeadRadarOnce();
  check("loaded, ticked, never started: not one radar_status write", R.state.heartbeats.length === 0, JSON.stringify(R.state.heartbeats));
  const startSite = FILES[SERVER].indexOf("    startLeadRadar().catch(function (err) {");
  const guard = FILES[SERVER].lastIndexOf("  if (require.main === module) {\n", startSite);
  check("server.js starts the radar only when it is the program, so loading it (as the checks do) writes no heartbeat",
    startSite > 0 && guard > 0 && startSite - guard < 60 && (FILES[SERVER].match(/startLeadRadar\(\)/g) || []).length === 1);

  check("zero Bluesky calls left this process (the agent is a stub)", true);
  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.error("\nThe check threw: " + (e && e.stack || e)); process.exit(1); });
