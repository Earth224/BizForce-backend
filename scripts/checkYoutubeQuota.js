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

   NAMED (Nov 23 2026, LR-2): BEFORE one platform pass (runYoutubeRadarOnce) searched the owner's 8 fixed
   KEYWORDS into bsky_leads as signals, shown by GET /api/leads/youtube-signals and lead-radar.html. AFTER those
   are removed (the original is in git, 65c0825): youtubeRadar.js is a member helper (searchComments,
   unitsUsedBy, unitsToday, memberYoutubeDeps) and lib/memberRadar.js captureYoutube searches ONE of a member's
   words at most every 3 hours, inside the whole key's cap, the radar's cap and the member's EQUAL SHARE of the
   radar's units (youtubeShare). Every pass below runs the real captureYoutube over the real helper, compiled
   from source, with the ledger and the YouTube Data API faked.

   WHAT THIS PROVES
     A. The reservation is written BEFORE every request, under the member's id: each fetch is preceded by its
        own reservation of the right size (search.list 100, commentThreads.list 1); one member's search is 104.
     B. FAIL CLOSED: a ledger that cannot be read, a refused reservation (first or mid-search) or an unusable
        cap means no further request.
     C. The caps parse like agentScheduleMaxPerTick (unchanged).
     D. A search runs only when its worst case (104) fits the whole key's cap, the radar's cap and the
        member's share, exactly at each edge; the share divides the radar's units equally among the members
        with YouTube on; a member is searched at most every 3 hours; a failed call's units stay spent.
     E. YouTube is never scored and never replied to, and capture runs only when ENABLE_YOUTUBE_RADAR is
        exactly "true".
     F. The signals route and its limits are removed.

   NAMED BEFORE → AFTER (YouTube filter build, Oct 2026, fixtures changed on
   purpose): the spy's comment text was "a comment" and the route's rows were
   "comment <n>". lib/youtubeFilter.js now drops both (too short, off topic)
   at capture and at display, so the spy answers with an on-topic comment
   that names the searched keyword, and the route's rows read "comment <n>:
   I have been tired for weeks and nothing seems to help". F's text tests
   match the new prefix. The filter itself is proved by checkYoutubeFilter.js.

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
const RADAR = "youtubeRadar.js", QUOTA = "lib/youtubeQuota.js", LEAD = "leadRadar.js", SERVER = "server.js", MEMBER_RADAR = "lib/memberRadar.js", REPLIES = "lib/leadReplies.js";
const FILES = {};
[RADAR, QUOTA, LEAD, SERVER, MEMBER_RADAR, REPLIES].forEach(f => { FILES[f] = fs.readFileSync(path.join(REPO, f), "utf8").replace(/\r\n/g, "\n"); });

// NAMED (Nov 23 2026, LR-2): every mutation re-anchored on the member helper and captureYoutube (BEFORE runYoutubeRadarOnce,
// KEYWORDS, SCORABLE_SOURCES and the signals route, all removed).
const MUTATIONS = {
  // the search is sent first and reserved after
  "reserve-after-fetch": [[RADAR, "  if (!(await reserve(\"search.list\"))) return out;\n  var searchData;\n  try { searchData = await fetchSearchResults(keyword); }",
    "  var searchData;\n  try { searchData = await fetchSearchResults(keyword); if (!(await reserve(\"search.list\"))) return out; }"]],
  // a ledger that cannot be read or written is ignored, and calls go ahead
  "fail-open-missing-ledger": [[MEMBER_RADAR, "    if (used === null || used + deps.youtube.worstCase > share) continue;", "    if (used !== null && used + deps.youtube.worstCase > share) continue;"],
    [MEMBER_RADAR, "    if (!today || today.total + deps.youtube.worstCase > caps.daily", "    if (today && today.total + deps.youtube.worstCase > caps.daily"],
    [RADAR, "catch (ledgerErr) { console.error(\"[YoutubeRadar] No YouTube call: \" + (ledgerErr.message || ledgerErr) + \".\"); return false; }", "catch (ledgerErr) { return true; }"]],
  // an unusable cap falls back to the default instead of stopping every call
  "bad-cap-default": [[QUOTA, "  return null;\n}\n\n// Both caps", "  return dflt;\n}\n\n// Both caps"]],
  // the member's share is ignored: one member may spend the radar's whole cap
  "share-ignored": [[MEMBER_RADAR, "  var share = youtubeShare(caps.radar, on.length, caps.radar);", "  var share = caps.radar;"]],
  // a member is searched every tick, not every 3 hours
  "unthrottled": [[MEMBER_RADAR, "    if (youtubeLast[m.user_id] && youtubeLast[m.user_id] > nowMs - YOUTUBE_MEMBER_INTERVAL_MS) continue;\n", ""]],
  // YouTube comments enter the scorer
  "youtube-scorable": [[MEMBER_RADAR, "const SCORED_SOURCES = [\"bluesky\", \"threads\"];", "const SCORED_SOURCES = [\"bluesky\", \"threads\", \"youtube\"];"]]
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
const YF = compile("lib/youtubeFilter.js", fs.readFileSync(path.join(REPO, "lib", "youtubeFilter.js"), "utf8").replace(/\r\n/g, "\n"), {});

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
  let searches = 0, lastQuery = "";
  globalThis.fetch = async function (url) {
    const u = String(url);
    const method = u.indexOf("/youtube/v3/search?") !== -1 ? "search.list" : u.indexOf("/youtube/v3/commentThreads?") !== -1 ? "commentThreads.list" : "other";
    EVENTS.push(["fetch", method]);
    FETCHES.push(method);
    if (method === "search.list") {
      searches++;
      lastQuery = decodeURIComponent((/[?&]q=([^&]+)/.exec(u) || ["", ""])[1]);
      if (opts.failSearch && opts.failSearch(searches)) return { ok: false, status: 500, text: async () => "backend error", json: async () => ({}) };
      return { ok: true, status: 200, json: async () => ({ items: [0, 1, 2, 3].map(i => ({ id: { videoId: "vid" + searches + "x" + i } })) }) };
    }
    if (method === "commentThreads.list") {
      const vid = /videoId=([^&]+)/.exec(u)[1];
      return { ok: true, status: 200, json: async () => ({ items: [{ snippet: { topLevelComment: { id: "c-" + vid, snippet: { authorDisplayName: "someone", textOriginal: "Has anyone found that '" + lastQuery + "' has an answer after a month?", publishedAt: new Date(Date.now() - 3600000).toISOString() } } } }] }) };   // NAMED (Nov 23 2026, LR-2): BEFORE a fixed Oct 19 date; AFTER an hour ago, so the member radar keeps it (fresh)
    }
    return { ok: false, status: 404, text: async () => "", json: async () => ({}) };
  };
}

const NOW = Date.now();
const TODAY = new Date(NOW).toISOString().slice(0, 10);
const CAP_VARS = ["YOUTUBE_DAILY_UNIT_CAP", "YOUTUBE_RADAR_DAILY_UNITS"];
const FPMOD = require(path.join(REPO, "lib", "leadFingerprint.js"));
const member = (id, words) => ({ user_id: id, fp: FPMOD.shape({ keywords: words || ["why am i always tired"], sources: { youtube: true } }) });
/* One YouTube tick: fresh modules (the 3-hour throttle is module state), the env given, the ledger seeded; the real captureYoutube
   over the real memberYoutubeDeps. opts.members (default one member, "m1"), opts.ticks (extra tick times, in ms after NOW). */
async function pass(opts) {
  opts = opts || {};
  EVENTS = []; FETCHES = [];
  const db = fakeDb({ youtube_api_calls: (opts.seed || []).map((r, i) => Object.assign({ id: i + 1, created_on: TODAY }, r)), member_leads: [] }, opts.db);
  const inserted = [];
  const sb = { from() { const b = { upsert(rows) { inserted.push.apply(inserted, rows); return b; }, select() { return b; }, then(res, rej) { return Promise.resolve({ data: [], error: null }).then(res, rej); } }; return b; } };
  installFetch(opts.fetch);
  process.env.YOUTUBE_API_KEY = "check-key";
  CAP_VARS.forEach(v => { if (opts.env && v in opts.env) process.env[v] = opts.env[v]; else delete process.env[v]; });
  const radar = compile(RADAR, FILES[RADAR], { dotenv: { config() {} }, "@supabase/supabase-js": { createClient: () => db.client }, "./lib/youtubeQuota": Q, "./lib/youtubeFilter": YF });
  const MRM = compile(MEMBER_RADAR, FILES[MEMBER_RADAR], { "./leadFingerprint": FPMOD });
  const logs = [], realLog = console.log, realErr = console.error, realWarn = console.warn;
  console.log = (...a) => { logs.push(a.join(" ")); }; console.error = (...a) => { logs.push("ERR " + a.join(" ")); }; console.warn = (...a) => { logs.push("WARN " + a.join(" ")); };
  const results = [];
  try {
    for (const at of [0].concat(opts.ticks || [])) results.push(await MRM.captureYoutube({ sb, youtube: radar.memberYoutubeDeps() }, opts.members || [member("m1")], NOW + at));
  } finally { console.log = realLog; console.error = realErr; console.warn = realWarn; }
  const ledger = db.tables.youtube_api_calls;
  return { db, logs, radar, MRM, results, inserted, events: EVENTS.slice(), fetches: FETCHES.slice(), ledger,
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
const radarRows = (n, units, uid) => Array.from({ length: n }, () => ({ caller: "radar", units: units || 1, user_id: uid || null }));
const otherRows = (n, units) => Array.from({ length: n }, () => ({ caller: "social_search", units: units || 1 }));
const J = JSON.stringify;

(async function main() {
  /* ── A ── */
  console.log("\n══ A. the reservation comes first, under the member's id ══");
  const A = await pass();
  const rf = reservedFirst(A.events);
  check("A. one member's search at the default caps: 1 search and 4 comment calls, 104 units (the helper's worst case)",
    A.searches === 1 && A.fetches.length === 5 && A.units === 104 && A.radar.SEARCH_WORST_CASE_UNITS === 104, J([A.searches, A.fetches.length, A.units]));
  check("A. every request is preceded by its own reservation of the right size, and there are as many reservations as requests", rf.ok, J(rf));
  check("A. the units are search.list 100 and commentThreads.list 1", Q.YOUTUBE_API_UNITS["search.list"] === 100 && Q.YOUTUBE_API_UNITS["commentThreads.list"] === 1);
  check("A. every reservation is caller radar, today's UTC date, the member's id", A.ledger.length === 5 && A.ledger.every(r => r.caller === "radar" && r.created_on === TODAY && r.user_id === "m1"), J(A.ledger));
  check("A. the search is the member's own word", A.inserted.length > 0 && A.inserted.every(x => x.user_id === "m1" && x.source === "youtube" && x.matched_keyword === "why am i always tired"), J(A.inserted.slice(0, 1)));

  /* ── B ── */
  console.log("\n══ B. fail closed ══");
  const B1 = await pass({ db: { missing: true } });
  check("B. the ledger table missing (the member's use cannot be read): no request at all", B1.fetches.length === 0, J(B1.fetches));
  const B2 = await pass({ db: { failInsertAt: 1 } });
  check("B. the first reservation refused: no request at all, logged", B2.fetches.length === 0 && B2.logs.some(l => /No YouTube call: youtube_api_calls could not be written/.test(l)), J(B2.logs));
  const B3 = await pass({ db: { failInsertAt: 3 } });
  check("B. a reservation refused mid-search: exactly the 2 reserved requests were made, then none", B3.fetches.length === 2 && reservedFirst(B3.events).ok, J(B3.fetches));
  for (const bad of ["0", "-1", "abc", "2.5"]) {
    const Bd = await pass({ env: { YOUTUBE_DAILY_UNIT_CAP: bad } }), Br = await pass({ env: { YOUTUBE_RADAR_DAILY_UNITS: bad } });
    check("B. a cap of " + J(bad) + " (either variable): no request and no ledger read, logged",
      [Bd, Br].every(x => x.fetches.length === 0 && x.db.log.length === 0 && x.logs.some(l => /YouTube: YOUTUBE_\w+ is set but is not a positive whole number; no call made/.test(l))), J([Bd.logs, Br.logs]));
  }

  /* ── C ── */
  console.log("\n══ C. the caps parse like agentScheduleMaxPerTick ══");
  check("C. absent, blank and spaces give the default", Q.youtubeCap(undefined, 5000) === 5000 && Q.youtubeCap("", 5000) === 5000 && Q.youtubeCap("   ", 2500) === 2500);
  check("C. a positive whole number is honoured", Q.youtubeCap("7", 5000) === 7 && Q.youtubeCap(" 7 ", 5000) === 7 && Q.youtubeCap("12000", 5000) === 12000);
  check("C. \"0\", \"-1\", \"abc\" and \"2.5\" give null, never the default", ["0", "-1", "abc", "2.5"].every(v => Q.youtubeCap(v, 5000) === null));
  const caps = Q.youtubeCaps({});
  check("C. the defaults are 5000 for the whole key and 2500 for the radar", caps.daily === 5000 && caps.radar === 2500 && caps.error === null, J(caps));
  check("C. one bad variable makes the pair unusable, naming it", Q.youtubeCaps({ YOUTUBE_RADAR_DAILY_UNITS: "abc" }).error === "YOUTUBE_RADAR_DAILY_UNITS is set but is not a positive whole number");

  /* ── D ── */
  console.log("\n══ D. a search runs only when its worst case fits every cap ══");
  const D1 = await pass({ seed: otherRows(1, 4896) }), D2 = await pass({ seed: otherRows(1, 4897) });
  check("D. the whole key: 4,896 used by others → the search runs (5,000 reached); 4,897 → none", D1.searches === 1 && D1.units === 5000 && D2.searches === 0, J([D1.searches, D1.units, D2.searches]));
  const D3 = await pass({ seed: radarRows(1, 2396, "other") }), D4 = await pass({ seed: radarRows(1, 2397, "other") });
  check("D. the radar's cap: 2,396 radar units used by another member → the search runs (2,500 reached); 2,397 → none", D3.searches === 1 && D3.units === 2500 && D4.searches === 0, J([D3.searches, D4.searches]));
  const two = [member("m1"), member("m2", ["does manifestation actually work"])];
  const share = A.MRM.youtubeShare(2500, 2, 2500);
  check("D. the share: the radar's 2,500 units divided equally between the 2 members with YouTube on (1,250 each)", share === 1250 && A.MRM.youtubeShare(2500, 3, 2500) === 833, share);
  const D5 = await pass({ members: two, seed: radarRows(1, share - 104, "m1") }), D6 = await pass({ members: two, seed: radarRows(1, share - 103, "m1") });
  check("D. the member's share: m1 at 1,146 still searches (1,250 reached), at 1,147 m1 is skipped and m2 still searches",
    D5.searches === 2 && D6.searches === 1 && D6.ledger.filter(x => x.user_id === "m2").length === 5 && D6.ledger.filter(x => x.user_id === "m1" && x.units < 1000).length === 0, J([D5.searches, D6.searches]));
  const D7 = await pass({ ticks: [5 * 60000, 3 * 3600000 - 1, 3 * 3600000] });
  check("D. one member is searched at most every 3 hours: ticks at 0, 5 minutes and just under 3 hours make one search; at 3 hours, a second", D7.searches === 2, D7.searches);
  const D8 = await pass({ fetch: { failSearch: (n) => n === 1 } });
  check("D. a failed call's units stay spent: the search fails, its 100 units stay reserved, no comment call", D8.searches === 1 && D8.units === 100 && D8.fetches.length === 1, J([D8.fetches, D8.units]));
  const D9 = await pass({ seed: [{ caller: "radar", units: 2400, created_on: "2000-01-01", user_id: "m1" }] });
  check("D. yesterday's units do not count today", D9.searches === 1, D9.searches);

  /* ── E ── */
  console.log("\n══ E. never scored, never replied to ══");
  check("E. youtube is not in SCORED_SOURCES", JSON.stringify(A.MRM.SCORED_SOURCES) === JSON.stringify(["bluesky", "threads"]), J(A.MRM.SCORED_SOURCES));
  check("E. a YouTube lead is stored as found (Good match on the word, scored_at set), never sent to a model", A.inserted.length > 0 && A.inserted.every(x => /^Good match: "/.test(x.match_reason) && !!x.scored_at));
  const LRP = compile(REPLIES, FILES[REPLIES], { "@atproto/api": require(require.resolve("@atproto/api", { paths: [REPO] })) });
  check("E. youtube is not in REPLY_PLATFORMS, and a YouTube lead is refused (no_reply_path)", LRP.REPLY_PLATFORMS.indexOf("youtube") === -1 &&
    (LRP.replyRefusal({ source: "youtube", outreach_safe: true, reply_invited: true, posted_at: new Date(NOW).toISOString() }, NOW) || {}).code === "no_reply_path");
  check("E. capture runs only when ENABLE_YOUTUBE_RADAR is exactly \"true\"", /youtube: process\.env\.ENABLE_YOUTUBE_RADAR === "true" \? require\("\.\/youtubeRadar"\)\.memberYoutubeDeps\(\) : null/.test(FILES[LEAD]));

  /* ── F ── */
  console.log("\n══ F. the signals route is removed ══");
  check("F. GET /api/leads/youtube-signals, its limits and runYoutubeRadarOnce are removed",
    FILES[SERVER].indexOf("app.get(\"/api/leads/youtube-signals\"") === -1 && !/\nconst YOUTUBE_SIGNALS_(LIMIT|PAGE|MAX_READ) =/.test(FILES[SERVER]) && !/runYoutubeRadarOnce/.test(FILES[RADAR] + FILES[LEAD]));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
