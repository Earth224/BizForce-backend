"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkYoutubeQuota — every YouTube API unit is reserved against a daily cap
   before it is spent, and YouTube finds are shown apart, never scored, never
   sent to.

   lib/youtubeQuota.js and youtubeRadar.js are compiled from their source (so
   MUTATE can edit them in memory). The radar runs against an in-memory
   youtube_api_calls ledger and bsky_leads table, with fetch replaced by a spy
   that answers like the YouTube Data API and records every request in the
   same event log as the ledger writes. GET /api/leads/youtube-signals is
   lifted from server.js; lead-radar.html's YouTube section is run with a fake
   document. No network, no model, no database.

   WHAT THIS PROVES
     A. The reservation is written BEFORE every request: walking the event
        log, each fetch is preceded by its own unspent reservation of the
        right size (search.list 100, commentThreads.list 1), and there are as
        many reservations as requests.
     B. FAIL CLOSED: a missing ledger table, a failed insert (first or mid-
        pass), or an unusable cap means no further request; each is logged
        once.
     C. The caps parse like agentScheduleMaxPerTick: absent or blank → the
        default (5000 and 2500); a positive whole number is honoured; "0",
        "-1", "abc" and "2.5" → null, and null means no call at all.
     D. The radar stops exactly when the next search (100 + 4 comment calls)
        would exceed either cap, and a failed call's units stay spent.
     E. KEYWORDS is exactly 8; youtube is in neither SCORABLE_SOURCES nor
        OUTREACH_SENDABLE_SOURCES.
     F. GET /api/leads/youtube-signals: 403 for a subscriber with zero reads;
        for the owner, only source youtube and status signal, four fields,
        the newest 50, and whether capture is on.
     G. lead-radar.html: the YouTube section is its own element outside
        #leadsList, a find has no Draft button, score or reply control, the
        link is only to youtube.com, a refusal hides the section, and the
        empty state says capture is off or nothing is found yet, whichever is
        true.

   MUTATE=<name> edits youtubeRadar.js, lib/youtubeQuota.js, leadRadar.js or
   server.js IN MEMORY (nothing on disk is touched). MUTATE=all runs each in
   its own process and passes only if every one fails at least one check. A
   mutation whose search text does not match exactly once is an ERROR, never
   counted as caught.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm"), Module = require("module");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const RADAR = "youtubeRadar.js", QUOTA = "lib/youtubeQuota.js", LEAD = "leadRadar.js", SERVER = "server.js";
const FILES = {};
[RADAR, QUOTA, LEAD, SERVER].forEach(f => { FILES[f] = fs.readFileSync(path.join(REPO, f), "utf8").replace(/\r\n/g, "\n"); });
const PAGE = fs.readFileSync(path.join(FRONTEND, "agents", "lead-radar.html"), "utf8").replace(/\r\n/g, "\n");

const MUTATIONS = {
  // the search is sent first and reserved after
  "reserve-after-fetch": [[RADAR, "      if (!(await reserve(\"search.list\"))) break;\n\n      try {\n        var searchData = await fetchSearchResults(keyword);\n",
    "      try {\n        var searchData = await fetchSearchResults(keyword);\n        if (!(await reserve(\"search.list\"))) break;\n"]],
  // a ledger that cannot be read or written is ignored, and calls go ahead
  "fail-open-missing-ledger": [[RADAR, "        console.error(\"[YoutubeRadar] No YouTube call this pass: \" + (readErr.message || readErr) + \".\");\n        break;\n",
    "        used = { total: 0, radar: 0 };\n"],
    [RADAR, "      stopPass = true;\n      return false;\n", "      return true;\n"]],
  // an unusable cap falls back to the default instead of stopping every call
  "bad-cap-default": [[QUOTA, "  return null;\n}\n\n// Both caps", "  return dflt;\n}\n\n// Both caps"]],
  // a ninth keyword
  "ninth-keyword": [[RADAR, "  \"does quantum jumping actually work\"\n];", "  \"does quantum jumping actually work\",\n  \"is tongkat ali safe\"\n];"]],
  // YouTube rows enter the scorer
  "youtube-scorable": [[LEAD, "const SCORABLE_SOURCES = [\"bluesky\", \"mastodon\"];", "const SCORABLE_SOURCES = [\"bluesky\", \"mastodon\", \"youtube\"];"]],
  // the signals route serves any account
  "signals-ungated": [[SERVER, "    if (req.user.id !== OUTREACH_CREDENTIAL_OWNER_ID) {\n      console.warn(\"[/api/leads/youtube-signals] REFUSING",
    "    if (false) {\n      console.warn(\"[/api/leads/youtube-signals] REFUSING"]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE);
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}

/* ── the modules, compiled from their (possibly mutated) source ─────────── */
function compile(file, src, requireMap) {
  const full = path.join(REPO, file);
  const m = new Module(full, module);
  m.filename = full;
  m.paths = Module._nodeModulePaths(path.dirname(full));
  m.require = function (id) {
    if (Object.prototype.hasOwnProperty.call(requireMap, id)) return requireMap[id];
    throw new Error("checkYoutubeQuota: " + file + " required " + id);
  };
  m._compile(src, full);
  return m.exports;
}
const Q = compile(QUOTA, FILES[QUOTA], {});

/* ── the in-memory tables, and one event log for ledger writes and requests ── */
let EVENTS = [];
function fakeDb(tables, opts) {
  opts = opts || {};
  const log = [];
  let inserts = 0;
  function keep(f, r) {
    if (f[0] === "eq") return r[f[1]] === f[2];
    throw new Error("fake: unsupported filter " + f[0]);
  }
  function run(q) {
    log.push(q);
    const rows = tables[q.table] || (tables[q.table] = []);
    if (q.table === "youtube_api_calls" && opts.missing) {
      return Promise.resolve({ data: null, error: { code: "42P01", message: "relation \"public.youtube_api_calls\" does not exist" } });
    }
    if (q.op === "insert") {
      inserts++;
      if (opts.failInsertAt && inserts >= opts.failInsertAt) return Promise.resolve({ data: null, error: { message: "insert refused" } });
      const row = Object.assign({ id: rows.length + 1 }, q.payload);
      rows.push(row);
      if (q.table === "youtube_api_calls") EVENTS.push(["reserve", row.units, row.caller]);
      return Promise.resolve({ data: null, error: null });
    }
    if (q.op === "upsert") {
      [].concat(q.payload).forEach(p => { if (!rows.some(r => r.post_uri === p.post_uri)) rows.push(Object.assign({}, p)); });
      return Promise.resolve({ data: null, error: null });
    }
    let hits = rows.filter(r => q.filters.every(f => keep(f, r)));
    if (q.order) hits = hits.slice().sort((a, b) => (a[q.order[0]] < b[q.order[0]] ? -1 : a[q.order[0]] > b[q.order[0]] ? 1 : 0) * (q.order[1] && q.order[1].ascending === false ? -1 : 1));
    if (q.range) hits = hits.slice(q.range[0], q.range[1] + 1);
    if (q.limit != null) hits = hits.slice(0, q.limit);
    const cols = String(q.cols || "*").split(",").map(c => c.trim());
    return Promise.resolve({ data: hits.map(r => { if (cols[0] === "*") return Object.assign({}, r); const o = {}; cols.forEach(c => { o[c] = r[c] === undefined ? null : r[c]; }); return o; }), error: null });
  }
  function from(table) {
    const q = { table, op: "select", cols: null, filters: [], order: null, range: null, limit: null, payload: null };
    const b = {
      select(cols) { if (q.op === "select") q.cols = cols; return b; },
      insert(p) { q.op = "insert"; q.payload = p; return b; },
      upsert(p) { q.op = "upsert"; q.payload = p; return b; },
      eq(c, v) { q.filters.push(["eq", c, v]); return b; },
      order(c, o) { q.order = [c, o]; return b; },
      range(a, z) { q.range = [a, z]; return b; },
      limit(n) { q.limit = n; return b; },
      then(res, rej) { return run(q).then(res, rej); }
    };
    return b;
  }
  return { tables, log, client: { from } };
}

/* ── the YouTube Data API, answered by a spy ─────────────────────────────── */
let FETCHES = [];
function installFetch(opts) {
  opts = opts || {};
  let searches = 0;
  globalThis.fetch = async function (url) {
    const u = String(url);
    const method = u.indexOf("/youtube/v3/search?") !== -1 ? "search.list" : u.indexOf("/youtube/v3/commentThreads?") !== -1 ? "commentThreads.list" : "other";
    EVENTS.push(["fetch", method]);
    FETCHES.push(method);
    if (method === "search.list") {
      searches++;
      if (opts.failSearch && opts.failSearch(searches)) return { ok: false, status: 500, text: async () => "backend error", json: async () => ({}) };
      return { ok: true, status: 200, json: async () => ({ items: [0, 1, 2, 3].map(i => ({ id: { videoId: "vid" + searches + "x" + i } })) }) };
    }
    if (method === "commentThreads.list") {
      const vid = /videoId=([^&]+)/.exec(u)[1];
      return { ok: true, status: 200, json: async () => ({ items: [{ snippet: { topLevelComment: { id: "c-" + vid, snippet: { authorDisplayName: "someone", textOriginal: "a comment", publishedAt: "2026-10-19T00:00:00Z" } } } }] }) };
    }
    return { ok: false, status: 404, text: async () => "", json: async () => ({}) };
  };
}

const TODAY = new Date().toISOString().slice(0, 10);
const CAP_VARS = ["YOUTUBE_DAILY_UNIT_CAP", "YOUTUBE_RADAR_DAILY_UNITS"];
// One radar pass: a fresh module (its 3-hour throttle is module state), the env given, the ledger seeded.
async function pass(opts) {
  opts = opts || {};
  EVENTS = []; FETCHES = [];
  const db = fakeDb({ youtube_api_calls: (opts.seed || []).map((r, i) => Object.assign({ id: i + 1, created_on: TODAY }, r)), bsky_leads: [] }, opts.db);
  installFetch(opts.fetch);
  process.env.YOUTUBE_API_KEY = "check-key";
  CAP_VARS.forEach(v => { if (opts.env && v in opts.env) process.env[v] = opts.env[v]; else delete process.env[v]; });
  const radar = compile(RADAR, FILES[RADAR], {
    dotenv: { config() {} },
    "@supabase/supabase-js": { createClient: () => db.client },
    "./lib/youtubeQuota": Q
  });
  const logs = [], realLog = console.log, realErr = console.error;
  console.log = (...a) => { logs.push(a.join(" ")); };
  console.error = (...a) => { logs.push("ERR " + a.join(" ")); };
  try { await radar.runYoutubeRadarOnce(); } finally { console.log = realLog; console.error = realErr; }
  const ledger = db.tables.youtube_api_calls;
  return { db, logs, radar, events: EVENTS.slice(), fetches: FETCHES.slice(), ledger,
    units: ledger.filter(r => r.created_on === TODAY).reduce((a, r) => a + r.units, 0),
    searches: FETCHES.filter(m => m === "search.list").length };
}
// Every request preceded by its own unspent reservation of the right size.
function reservedFirst(events) {
  const pending = [];
  let ok = true, reserves = 0, fetches = 0;
  events.forEach(e => {
    if (e[0] === "reserve") { reserves++; pending.push(e[1]); }
    else { fetches++; const want = Q.YOUTUBE_API_UNITS[e[1]]; const i = pending.indexOf(want); if (i === -1) ok = false; else pending.splice(i, 1); }
  });
  return { ok: ok && reserves === fetches && fetches > 0, reserves, fetches };
}
const radarRows = (n, units) => Array.from({ length: n }, () => ({ caller: "radar", units: units || 1 }));
const otherRows = (n, units) => Array.from({ length: n }, () => ({ caller: "social_search", units: units || 1 }));

(async function main() {
  /* ── A. reserved before every request ─────────────────────────────────── */
  console.log("\n══ A. the reservation comes first ══");
  const A = await pass();
  const rf = reservedFirst(A.events);
  check("A. a full pass at the default caps: 8 searches and 32 comment calls", A.searches === 8 && A.fetches.length === 40, JSON.stringify([A.searches, A.fetches.length]));
  check("A. every request is preceded by its own reservation of the right size, and there are as many reservations as requests",
    rf.ok, JSON.stringify(rf) + " " + JSON.stringify(A.events.slice(0, 6)));
  check("A. the units are search.list 100 and commentThreads.list 1, and the pass spent 832",
    Q.YOUTUBE_API_UNITS["search.list"] === 100 && Q.YOUTUBE_API_UNITS["commentThreads.list"] === 1 && A.units === 832, A.units);
  check("A. every reservation is written as caller radar, today's UTC date, no user", A.ledger.every(r => r.caller === "radar" && r.created_on === TODAY && r.user_id === null));
  check("A. the comments are captured as signal, source youtube", A.db.tables.bsky_leads.length === 32 && A.db.tables.bsky_leads.every(r => r.source === "youtube" && r.status === "signal"));

  /* ── B. fail closed ───────────────────────────────────────────────────── */
  console.log("\n══ B. fail closed ══");
  const B1 = await pass({ db: { missing: true } });
  check("B. the ledger table missing: no request at all, logged once", B1.fetches.length === 0 && B1.logs.filter(l => /No YouTube call this pass/.test(l)).length === 1 &&
    B1.logs.some(l => /youtube_api_calls could not be read/.test(l)), JSON.stringify(B1.logs));
  const B2 = await pass({ db: { failInsertAt: 1 } });
  check("B. the first reservation refused: no request at all, logged once", B2.fetches.length === 0 && B2.logs.filter(l => /No YouTube call this pass: youtube_api_calls could not be written/.test(l)).length === 1,
    JSON.stringify(B2.logs));
  const B3 = await pass({ db: { failInsertAt: 4 } });
  check("B. a reservation refused mid-pass: exactly the 3 reserved requests were made, then none", B3.fetches.length === 3 && reservedFirst(B3.events).ok &&
    B3.logs.filter(l => /No YouTube call this pass/.test(l)).length === 1, JSON.stringify([B3.fetches, B3.logs.length]));
  for (const bad of ["0", "-1", "abc", "2.5"]) {
    const Bd = await pass({ env: { YOUTUBE_DAILY_UNIT_CAP: bad } });
    const Br = await pass({ env: { YOUTUBE_RADAR_DAILY_UNITS: bad } });
    check("B. a cap of " + JSON.stringify(bad) + " (either variable): no request and no ledger read, logged once",
      [Bd, Br].every(x => x.fetches.length === 0 && x.db.log.length === 0 && x.logs.filter(l => /No YouTube call this pass: YOUTUBE_\w+ is set but is not a positive whole number/.test(l)).length === 1),
      JSON.stringify([Bd.fetches.length, Br.fetches.length, Bd.logs, Br.logs]));
  }

  /* ── C. the caps parse ─────────────────────────────────────────────────── */
  console.log("\n══ C. the caps parse like agentScheduleMaxPerTick ══");
  check("C. absent, blank and spaces give the default", Q.youtubeCap(undefined, 5000) === 5000 && Q.youtubeCap("", 5000) === 5000 && Q.youtubeCap("   ", 2500) === 2500);
  check("C. a positive whole number is honoured (\"7\", \" 7 \", \"12000\")", Q.youtubeCap("7", 5000) === 7 && Q.youtubeCap(" 7 ", 5000) === 7 && Q.youtubeCap("12000", 5000) === 12000);
  check("C. \"0\", \"-1\", \"abc\" and \"2.5\" give null, never the default", ["0", "-1", "abc", "2.5"].every(v => Q.youtubeCap(v, 5000) === null));
  const caps = Q.youtubeCaps({});
  check("C. the defaults are 5000 for the whole key and 2500 for the radar", caps.daily === 5000 && caps.radar === 2500 && caps.error === null, JSON.stringify(caps));
  const capsBad = Q.youtubeCaps({ YOUTUBE_RADAR_DAILY_UNITS: "abc" });
  check("C. one bad variable makes the pair unusable, naming it", capsBad.error === "YOUTUBE_RADAR_DAILY_UNITS is set but is not a positive whole number", JSON.stringify(capsBad));
  check("C. the parse is agentScheduleMaxPerTick's: blank → default, Number of the trimmed text, isInteger and > 0, else null",
    /function youtubeCap\(raw, dflt\) \{\n  if \(raw == null \|\| String\(raw\)\.trim\(\) === ""\) \{\n    return dflt;\n  \}\n\n  var parsed = Number\(String\(raw\)\.trim\(\)\);\n  if \(Number\.isFinite\(parsed\) && Number\.isInteger\(parsed\) && parsed > 0\) \{\n    return parsed;\n  \}\n\n  return null;\n\}/.test(FILES[QUOTA]));

  /* ── D. the radar stops exactly at the cap ─────────────────────────────── */
  console.log("\n══ D. the radar stops exactly when the next search would not fit ══");
  const D1 = await pass({ seed: otherRows(1, 4792) });
  check("D. the whole key: 4,792 used by others, 5,000 cap → exactly 2 searches (5,000 reached), the third refused and logged",
    D1.searches === 2 && D1.units === 5000 && D1.logs.some(l => /Pass stopped before 'why am i always tired': 5000 of 5000 units used today \(radar 208 of 2500\)/.test(l)),
    JSON.stringify([D1.searches, D1.units, D1.logs.filter(l => /Pass stopped/.test(l))]));
  const D2 = await pass({ seed: otherRows(1, 4793) });
  check("D. one unit more already used → exactly 1 search", D2.searches === 1 && D2.units === 4897, JSON.stringify([D2.searches, D2.units]));
  const D3 = await pass({ seed: radarRows(1, 2188) });
  check("D. the radar's share: 2,188 used by the radar, 2,500 cap → exactly 3 searches (2,500 reached)", D3.searches === 3 && D3.units === 2500, JSON.stringify([D3.searches, D3.units]));
  const D4 = await pass({ seed: radarRows(1, 2189) });
  check("D. one unit more → exactly 2 searches", D4.searches === 2, D4.searches);
  const D5 = await pass({ seed: otherRows(1, 3000) });
  check("D. units another caller spent count against the whole key, not the radar's share: 3,000 by others → 2,000 left → 19 full searches would fit, the pass's 8 run",
    D5.searches === 8, D5.searches);
  const D6 = await pass({ seed: [{ caller: "radar", units: 2400, created_on: "2000-01-01" }] });
  check("D. yesterday's units do not count today", D6.searches === 8, D6.searches);
  const D7 = await pass({ env: { YOUTUBE_DAILY_UNIT_CAP: "204" }, fetch: { failSearch: (n) => n === 1 } });
  check("D. a failed call's units stay spent: the first search fails (100 kept), the second fits exactly (204), the third is refused",
    D7.searches === 2 && D7.units === 204 && D7.ledger.filter(r => r.units === 100).length === 2, JSON.stringify([D7.searches, D7.units]));

  /* ── E. eight keywords; no scoring, no sending ─────────────────────────── */
  console.log("\n══ E. eight keywords, never scored, never sent to ══");
  check("E. KEYWORDS is exactly 8", Array.isArray(A.radar.KEYWORDS) && A.radar.KEYWORDS.length === 8, A.radar.KEYWORDS && A.radar.KEYWORDS.length);
  const scorable = /const SCORABLE_SOURCES = (\[[^\]]*\]);/.exec(FILES[LEAD]);
  check("E. youtube is not in SCORABLE_SOURCES", !!scorable && JSON.stringify(JSON.parse(scorable[1])) === JSON.stringify(["bluesky", "mastodon"]), scorable && scorable[1]);
  const sendable = /(?:var|const) OUTREACH_SENDABLE_SOURCES = (\[[^\]]*\]);/.exec(FILES[SERVER]);
  check("E. youtube is not in OUTREACH_SENDABLE_SOURCES", !!sendable && JSON.parse(sendable[1]).indexOf("youtube") === -1 && JSON.parse(sendable[1]).length > 0, sendable && sendable[1]);
  check("E. capture is still switched on only by ENABLE_YOUTUBE_RADAR exactly \"true\"", /if \(process\.env\.ENABLE_YOUTUBE_RADAR === "true"\) \{[\s\S]{0,400}await runYoutubeRadarOnce\(\);/.test(FILES[LEAD]));

  /* ── F. the signals route ──────────────────────────────────────────────── */
  console.log("\n══ F. GET /api/leads/youtube-signals ══");
  const SRC = FILES[SERVER];
  const sig = "app.get(\"/api/leads/youtube-signals\", requireAuth, async function (req, res, next) {";
  const at = SRC.indexOf(sig);
  const ROUTE = at < 0 ? "" : SRC.slice(at, s.braceMatch(SRC, SRC.indexOf("{", at)) + 2);
  const defs = ["LEAD_RADAR_UNAVAILABLE", "YOUTUBE_SIGNALS_LIMIT", "OUTREACH_CREDENTIAL_OWNER_ID"].map(n => s.definitionOf(SRC, n) || "");
  const OWNER = require(path.join(REPO, "lib", "ownerAccount.js")).OWNER_ACCOUNT_ID;
  const SUBSCRIBER = "53e6b330-0000-4000-8000-00000000abcd";
  function signalRows() {
    const rows = [];
    for (let i = 0; i < 60; i++) rows.push({ source: "youtube", status: "signal", post_uri: "https://www.youtube.com/watch?v=v" + i + "&lc=c" + i, matched_keyword: "why am i always tired",
      post_created_at: "2026-10-01T00:00:00Z", post_text: "comment " + i, author_handle: "handle" + i, intent_score: null, created_at: new Date(Date.UTC(2026, 9, 1) + i * 60000).toISOString() });
    rows.push({ source: "youtube", status: "scored", post_uri: "https://www.youtube.com/watch?v=old", matched_keyword: "k", post_text: "scored youtube", created_at: "2026-10-30T00:00:00Z" });
    rows.push({ source: "bluesky", status: "signal", post_uri: "at://bsky/1", matched_keyword: "k", post_text: "bluesky signal", created_at: "2026-10-30T00:00:00Z" });
    rows.push({ source: "mastodon", status: "scored", post_uri: "https://masto/1", matched_keyword: "k", post_text: "mastodon", created_at: "2026-10-30T00:00:00Z" });
    return rows;
  }
  async function callRoute(userId, env) {
    const db = fakeDb({ bsky_leads: signalRows() });
    let handler = null;
    const ctx = { supabase: db.client, OWNER_ACCOUNT_ID: OWNER, process: { env: env || {} }, console: { log() {}, error() {}, warn() {} }, requireAuth: function requireAuth() {},
      app: { get(p) { if (p === "/api/leads/youtube-signals") handler = arguments[arguments.length - 1]; } } };
    vm.createContext(ctx);
    vm.runInContext(defs.join("\n") + "\n" + ROUTE, ctx);
    const res = { code: 200, body: null, status(c) { this.code = c; return this; }, json(b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
    await handler({ user: { id: userId } }, res, (e) => { res.code = 500; res.body = { error: String(e) }; });
    return { res, db };
  }
  check("F. the route is registered with requireAuth", ROUTE.length > 0);
  const Fs = await callRoute(SUBSCRIBER);
  check("F. a subscriber gets 403 lead_radar_unavailable and nothing is read", Fs.res.code === 403 && Fs.res.body.code === "lead_radar_unavailable" && Fs.db.log.length === 0,
    JSON.stringify([Fs.res.code, Fs.res.body, Fs.db.log.length]));
  const Fo = await callRoute(OWNER, { ENABLE_YOUTUBE_RADAR: "true" });
  const finds = (Fo.res.body && Fo.res.body.finds) || [];
  check("F. the owner gets only source youtube, status signal: the scored YouTube row, Bluesky and Mastodon are not among them",
    Fo.res.code === 200 && finds.length > 0 && finds.every(f => /^comment \d+$/.test(f.post_text)), JSON.stringify(finds.slice(0, 2)));
  check("F. four fields each: post_uri, matched_keyword, post_created_at, post_text (no handle, no score)",
    finds.every(f => JSON.stringify(Object.keys(f).sort()) === JSON.stringify(["matched_keyword", "post_created_at", "post_text", "post_uri"])), JSON.stringify(Object.keys(finds[0] || {})));
  check("F. the newest 50, newest first", finds.length === 50 && finds[0].post_text === "comment 59" && finds[49].post_text === "comment 10", JSON.stringify([finds.length, finds[0] && finds[0].post_text]));
  check("F. the query itself filters source youtube and status signal", Fo.db.log.length === 1 &&
    ["source:youtube", "status:signal"].every(k => Fo.db.log[0].filters.some(f => f[1] + ":" + f[2] === k)), JSON.stringify(Fo.db.log[0] && Fo.db.log[0].filters));
  const Foff = await callRoute(OWNER, { ENABLE_YOUTUBE_RADAR: "True" });
  check("F. capture_on is true only for ENABLE_YOUTUBE_RADAR exactly \"true\"", Fo.res.body.capture_on === true && Foff.res.body.capture_on === false && Fo.res.body.kept_days === 30);

  /* ── G. the page section ───────────────────────────────────────────────── */
  console.log("\n══ G. lead-radar.html's YouTube section ══");
  const section = (/<section class="yt-section" id="ytSection"[^>]*>[\s\S]*?<\/section>/.exec(PAGE) || [""])[0];
  const leadsAt = PAGE.indexOf("<div id=\"leadsList\"></div>"), sectionAt = PAGE.indexOf(section);
  check("G. the section is its own element after #leadsList, not inside it, titled as YouTube data",
    section.length > 0 && leadsAt !== -1 && sectionAt > leadsAt && section.indexOf("leadsList") === -1 &&
    /<h2 class="yt-title">YouTube finds — not scored, cannot be replied to from here, kept 30 days<\/h2>/.test(section), section.slice(0, 200));
  const script = (/<script>([\s\S]*?)<\/script>/.exec(PAGE) || ["", ""])[1];
  const fn = (name) => { const i = script.indexOf("    function " + name + "("); return i < 0 ? "" : script.slice(i, s.braceMatch(script, script.indexOf("{", i))); };
  const pageCode = ["tok", "escHtml", "buildYoutubeFind", "loadYoutubeFinds"].map(fn).join("\n");
  function els() {
    const made = {};
    return { made, document: { getElementById(id) { return made[id] || (made[id] = { id, hidden: true, innerHTML: "" }); } } };
  }
  async function runPage(status, data) {
    const d = els();
    const fetched = [];
    const ctx = { API: "https://api.example", localStorage: { getItem: () => "t" }, document: d.document, String,
      fetch: (u) => { fetched.push(u); return Promise.resolve({ ok: status === 200, status, json: () => Promise.resolve(data) }); } };
    vm.createContext(ctx);
    vm.runInContext(pageCode + "\nloadYoutubeFinds();", ctx);
    for (let i = 0; i < 10; i++) await new Promise(r => setImmediate(r));
    return { section: d.made.ytSection, list: d.made.ytList, leads: d.made.leadsList, fetched };
  }
  const withFinds = await runPage(200, { finds: [
    { post_uri: "https://www.youtube.com/watch?v=abc&lc=1", matched_keyword: "why am i always tired", post_created_at: "2026-10-12T08:00:00Z", post_text: "tired <b>all</b> day" },
    { post_uri: "javascript:alert(1)", matched_keyword: "k", post_created_at: null, post_text: "odd" }], capture_on: true });
  const html = withFinds.list ? withFinds.list.innerHTML : "";
  check("G. it reads /api/leads/youtube-signals and shows keyword, date, text and an Open on YouTube link",
    withFinds.fetched[0] === "https://api.example/api/leads/youtube-signals" && withFinds.section.hidden === false &&
    /why am i always tired/.test(html) && /2026-10-12/.test(html) && /tired &lt;b&gt;all&lt;\/b&gt; day/.test(html) &&
    /<a class="yt-find-link" href="https:\/\/www\.youtube\.com\/watch\?v=abc&amp;lc=1" target="_blank" rel="noopener noreferrer">Open on YouTube<\/a>/.test(html), html.slice(0, 400));
  check("G. a link that is not youtube.com is not drawn, and a missing date says so", html.split("Open on YouTube").length === 2 && html.indexOf("javascript:") === -1 && /date unknown/.test(html));
  check("G. no Draft button, score, reply or copy control in any find", !/draft|score|reply|copy-btn/i.test(html) && !/draft|score|reply|copy-btn/i.test(fn("buildYoutubeFind")), html.slice(0, 300));
  check("G. #leadsList is never touched by it", !withFinds.leads);
  const off = await runPage(200, { finds: [], capture_on: false });
  const none = await runPage(200, { finds: [], capture_on: true });
  check("G. empty and capture off: it says capture is switched off", /data-state="youtube_capture_off">YouTube capture is switched off/.test(off.list.innerHTML), off.list.innerHTML);
  check("G. empty and capture on: it says nothing has been found yet", /data-state="youtube_none_yet">YouTube capture is on, and nothing has been found yet\./.test(none.list.innerHTML), none.list.innerHTML);
  const refused = await runPage(403, { error: "no", code: "lead_radar_unavailable" });
  check("G. a refusal hides the section and draws nothing", refused.section.hidden === true && refused.list.innerHTML === "");
  check("G. Refresh reloads it with the list", /function loadLeads\(\) \{[\s\S]{0,400}loadYoutubeFinds\(\);/.test(script));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
