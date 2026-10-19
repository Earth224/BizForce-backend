"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkYoutubeFilter — YouTube finds drop link spam, one-liners and off-topic
   comments, at capture and at display, by one deterministic filter.

   lib/youtubeFilter.js and youtubeRadar.js are compiled from their source (so
   MUTATE can edit them in memory). The radar runs against an in-memory
   ledger and bsky_leads table with fetch replaced by a spy that answers like
   the YouTube Data API. GET /api/leads/youtube-signals is lifted from
   server.js and run against stored rows; lead-radar.html's YouTube section is
   run with a fake document. No network, no model, no database.

   WHAT THIS PROVES
     A. The filter, on the real shapes from the first live pass (Oct 19):
        link spam → link, "Correct" and a 5-word reply → too_short, a
        Portuguese reply under a libido video → off_topic, real-shaped
        questions → kept. "2.5 mg" and a sentence's full stop are not links;
        emoji are not words; "supplements" matches "supplement". The order
        is link, too_short, off_topic.
     B. The topic terms of each of the 8 KEYWORDS, and the stopword list.
     C. No model call: the filter requires nothing and calls nothing, and a
        capture pass makes only YouTube Data API requests.
     D. Capture stores only kept comments; each keyword logs fetched, kept
        and dropped by reason, and the counts add up; the units ledger is
        exactly what an unfiltered pass reserves.
     E. Display applies the filter to rows already stored: the newest 50
        KEPT rows (paged past 1,000 hidden ones), hidden_counts exact for the
        rows read, and no hidden row's text in the response.
     F. The page says "N hidden: X with links, Y too short, Z off topic",
        states the three rules, offers no way to reveal hidden rows, and
        draws no link from comment text: only "Open on YouTube".
     G. The guide tip states the three rules, with the filter's own minimum.

   MUTATE=<name> edits lib/youtubeFilter.js, youtubeRadar.js or server.js IN
   MEMORY (nothing on disk is touched). MUTATE=all runs each in its own
   process and passes only if every one fails at least one check. A mutation
   whose search text does not match exactly once is an ERROR, never counted
   as caught.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm"), Module = require("module");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const FILTER = "lib/youtubeFilter.js", QUOTA = "lib/youtubeQuota.js", RADAR = "youtubeRadar.js", SERVER = "server.js";
const FILES = {};
[FILTER, QUOTA, RADAR, SERVER].forEach(f => { FILES[f] = fs.readFileSync(path.join(REPO, f), "utf8").replace(/\r\n/g, "\n"); });
const PAGE = fs.readFileSync(path.join(FRONTEND, "agents", "lead-radar.html"), "utf8").replace(/\r\n/g, "\n");
const GUIDE = fs.readFileSync(path.join(FRONTEND, "scripts", "termaximus-guide.js"), "utf8").replace(/\r\n/g, "\n");

const MUTATIONS = {
  // the link test is dropped
  "drop-link-test": [[FILTER, "  if (youtubeHasLink(t)) return { keep: false, reason: \"link\" };\n", ""]],
  // emoji and punctuation count as words
  "emoji-are-words": [[FILTER, ".filter(function (t) { return /[\\p{L}\\p{N}]/u.test(t); })", ".filter(function (t) { return t.length > 0; })"]],
  // no plural or -ing tolerance
  "no-plural-tolerance": [[FILTER, "  if (w.length > 5 && /ing$/.test(w)) w = w.slice(0, -3);\n  else if (w.length > 3 && /s$/.test(w) && !/ss$/.test(w)) w = w.slice(0, -1);\n", ""]],
  // capture stores every comment
  "capture-unfiltered": [[RADAR, "              if (!verdict.keep) { dropped[verdict.reason]++; return; }\n", ""]],
  // display skips the filter
  "display-unfiltered": [[SERVER, "        if (verdict.keep) finds.push(page[i]); else hidden[verdict.reason]++;\n", "        finds.push(page[i]);\n"]],
  // the display limit is applied to the query, before the filter
  "limit-before-filter": [[SERVER, "        .range(offset, offset + YOUTUBE_SIGNALS_PAGE - 1);\n", "        .limit(YOUTUBE_SIGNALS_LIMIT);\n"]]
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
    throw new Error("checkYoutubeFilter: " + file + " required " + id);
  };
  m._compile(src, full);
  return m.exports;
}
// requireMap {}: the filter may require nothing at all.
const YF = compile(FILTER, FILES[FILTER], {});
const Q = compile(QUOTA, FILES[QUOTA], {});

/* ── an in-memory Supabase ───────────────────────────────────────────────── */
function fakeDb(tables) {
  const log = [];
  function run(q) {
    log.push(q);
    const rows = tables[q.table] || (tables[q.table] = []);
    if (q.op === "insert") { rows.push(Object.assign({ id: rows.length + 1 }, q.payload)); return Promise.resolve({ data: null, error: null }); }
    if (q.op === "upsert") {
      [].concat(q.payload).forEach(p => { if (!rows.some(r => r.post_uri === p.post_uri)) rows.push(Object.assign({}, p)); });
      return Promise.resolve({ data: null, error: null });
    }
    let hits = rows.filter(r => q.filters.every(f => r[f[0]] === f[1]));
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
      eq(c, v) { q.filters.push([c, v]); return b; },
      order(c, o) { q.order = [c, o]; return b; },
      range(a, z) { q.range = [a, z]; return b; },
      limit(n) { q.limit = n; return b; },
      then(res, rej) { return run(q).then(res, rej); }
    };
    return b;
  }
  return { tables, log, client: { from } };
}

/* ── the live-pass shapes ─────────────────────────────────────────────────── */
const LIBIDO = "how to increase libido naturally";
const SPAM_1 = "👉 Official Website: https://siteoficial.cloud/EchoXen";
const SPAM_2 = "Buy Here https://siteoficial.cloud/ProstaviveOficial";
const ONE_WORD = "Correct";
const FIVE_WORDS = "É verdade mesmo minha querida";
const PORTUGUESE = "Obrigado pela gentileza meu amor ❤️❤️❤️. Tou bem graças Deus";
const QUESTION = "Has anyone tried tongkat ali for low libido, did it help after a month?";
const DECIMAL = "I take 2.5 mg of zinc daily for energy and it helps a lot.";
const EMOJI_SHORT = "libido tips 🔥 🔥 🔥 👍";

(async function main() {
  /* ── A. the filter ─────────────────────────────────────────────────────── */
  console.log("\n══ A. the filter, on the live pass's shapes ══");
  const v = (t, k) => YF.isUsefulYoutubeComment(t, k);
  const is = (t, k, reason) => { const r = v(t, k); return reason === null ? r.keep === true && r.reason === null : r.keep === false && r.reason === reason; };
  check("A. \"👉 Official Website: https://siteoficial.cloud/EchoXen\" → link", is(SPAM_1, "does tongkat ali actually work", "link"), JSON.stringify(v(SPAM_1, "does tongkat ali actually work")));
  check("A. \"Buy Here https://siteoficial.cloud/ProstaviveOficial\" → link", is(SPAM_2, "what supplements actually work", "link"), JSON.stringify(v(SPAM_2, "what supplements actually work")));
  check("A. a bare domain with a path, \"siteoficial.cloud/EchoXen\", in an otherwise on-topic comment → link",
    is("You can get it for libido at siteoficial.cloud/EchoXen before it sells out", LIBIDO, "link"));
  check("A. www. and a known TLD without a path (\"gmail.com\") → link",
    is("Look at www.example.org for more libido advice from real doctors", LIBIDO, "link") && is("Write to helpdesk@gmail.com about libido supplements and more", LIBIDO, "link"));
  check("A. \"Correct\" → too_short", is(ONE_WORD, "why am i always tired", "too_short"), JSON.stringify(v(ONE_WORD, "why am i always tired")));
  check("A. \"É verdade mesmo minha querida\" (5 words) → too_short", is(FIVE_WORDS, LIBIDO, "too_short"), JSON.stringify(v(FIVE_WORDS, LIBIDO)));
  check("A. the Portuguese reply under \"how to increase libido naturally\" → off_topic", is(PORTUGUESE, LIBIDO, "off_topic"), JSON.stringify(v(PORTUGUESE, LIBIDO)));
  check("A. \"Has anyone tried tongkat ali for low libido, did it help after a month?\" under \"does tongkat ali actually work\" → kept",
    is(QUESTION, "does tongkat ali actually work", null), JSON.stringify(v(QUESTION, "does tongkat ali actually work")));
  check("A. \"I take 2.5 mg of zinc daily for energy…\" under \"how to boost energy naturally\" → kept (2.5 is not a link)",
    is(DECIMAL, "how to boost energy naturally", null) && YF.youtubeHasLink(DECIMAL) === false, JSON.stringify(v(DECIMAL, "how to boost energy naturally")));
  check("A. plain sentences ending in a full stop are not links",
    ["This really works for me.", "I was tired. Then I slept. Now I am fine.", "Done.", "It helps... a lot."].every(t => YF.youtubeHasLink(t) === false));
  check("A. decimals are not links: \"2.5 mg\", \"0.75\", \"v1.2\"", ["2.5 mg", "take 0.75 grams", "version v1.2 is out"].every(t => YF.youtubeHasLink(t) === false));
  check("A. \"supplements\" matches \"supplement\", both ways",
    is("Which supplement is best for someone who sleeps badly?", "what supplements actually work", null) &&
    is("I tried three supplements this year and only one helped me", "best supplement for sleep", null));
  check("A. -ing and -s tolerance: \"jump\" matches \"jumping\", \"increasing\" matches \"increase\"",
    is("Can you really jump to another reality by thinking about it?", "does quantum jumping actually work", null) &&
    is("Is increasing it with food alone ever enough for most people?", LIBIDO, null));
  check("A. whole words only: \"tiredness\" is not \"tired\"", is("This tiredness of mine has lasted for months now", "why am i always tired", "off_topic"));
  check("A. emoji are not words: \"libido tips 🔥 🔥 🔥 👍\" has 2 words → too_short",
    YF.youtubeWordCount(EMOJI_SHORT) === 2 && YF.youtubeWordCount("❤️❤️❤️. 👉 !!") === 0 && is(EMOJI_SHORT, LIBIDO, "too_short"), YF.youtubeWordCount(EMOJI_SHORT));
  check("A. the order is link, then too_short, then off_topic: the first failing test is the reason",
    is("www.x.com", LIBIDO, "link") && is("hi https://a.cloud/x", LIBIDO, "link") && is("ok", "nothing here matches", "too_short") &&
    is("Obrigado pela gentileza meu amor querida", LIBIDO, "off_topic"));
  check("A. a missing text is too_short; a keyword with no topic terms keeps nothing",
    is(null, LIBIDO, "too_short") && is(undefined, LIBIDO, "too_short") && is("how to do it when it is what it is", "how to do it", "off_topic"));
  check("A. the minimum is 6 words: 5 words dropped, 6 kept", YF.YOUTUBE_MIN_WORDS === 6 &&
    is("libido is low these days", LIBIDO, "too_short") && is("my libido is low these days", LIBIDO, null));

  /* ── B. topic terms and stopwords ──────────────────────────────────────── */
  console.log("\n══ B. topic terms of the 8 keywords ══");
  const radarForKeywords = compile(RADAR, FILES[RADAR], { dotenv: { config() {} }, "@supabase/supabase-js": { createClient: () => fakeDb({}).client },
    "./lib/youtubeQuota": Q, "./lib/youtubeFilter": YF });
  const EXPECTED_TERMS = {
    "does tongkat ali actually work": ["tongkat", "ali"],
    "how to increase libido naturally": ["increase", "libido"],
    "why am i always tired": ["tired"],
    "what supplements actually work": ["supplements"],
    "how to boost energy naturally": ["boost", "energy"],
    "why isn't my manifestation working": ["manifestation"],
    "does manifestation actually work": ["manifestation"],
    "does quantum jumping actually work": ["quantum", "jumping"]
  };
  const KW = radarForKeywords.KEYWORDS;
  check("B. the radar's 8 KEYWORDS are the ones listed here", Array.isArray(KW) && KW.length === 8 && JSON.stringify(KW.slice().sort()) === JSON.stringify(Object.keys(EXPECTED_TERMS).sort()), JSON.stringify(KW));
  KW.forEach(k => {
    const got = YF.youtubeTopicTerms(k);
    check("B. \"" + k + "\" → " + JSON.stringify(EXPECTED_TERMS[k]), JSON.stringify(got) === JSON.stringify(EXPECTED_TERMS[k]), JSON.stringify(got));
  });
  const REQUIRED_STOP = ["how", "to", "why", "am", "i", "always", "what", "actually", "do", "does", "work", "naturally", "the", "a", "is", "are", "for", "it", "and", "isn't", "my"];
  check("B. the stopword list holds every word the spec names", REQUIRED_STOP.every(w => YF.YOUTUBE_STOPWORDS.indexOf(w) !== -1), REQUIRED_STOP.filter(w => YF.YOUTUBE_STOPWORDS.indexOf(w) === -1).join(","));
  check("B. no topic term of any keyword is a stopword", KW.every(k => YF.youtubeTopicTerms(k).every(t => YF.YOUTUBE_STOPWORDS.indexOf(t) === -1)));

  /* ── C. no model call ──────────────────────────────────────────────────── */
  console.log("\n══ C. no model call ══");
  const MODEL = /anthropic|openai|claude|gpt|generativelanguage|callModel|messages\.create|fetch\(/i;
  check("C. lib/youtubeFilter.js requires nothing and calls no model or network (compiled with an empty require map)",
    !/\brequire\(/.test(FILES[FILTER]) && !MODEL.test(FILES[FILTER]));
  const routeAt = FILES[SERVER].indexOf("app.get(\"/api/leads/youtube-signals\", requireAuth, async function (req, res, next) {");
  const ROUTE = routeAt < 0 ? "" : FILES[SERVER].slice(routeAt, s.braceMatch(FILES[SERVER], FILES[SERVER].indexOf("{", routeAt)) + 2);
  check("C. the signals route calls no model", ROUTE.length > 0 && !/anthropic|openai|callModel|messages\.create|fetch\(/i.test(ROUTE));

  /* ── D. capture ────────────────────────────────────────────────────────── */
  console.log("\n══ D. capture stores only kept comments ══");
  // Per video: two kept, one link, two too_short, one off_topic.
  function commentsFor(kw, vid, unfiltered) {
    const texts = unfiltered
      ? ["Has anyone found that '" + kw + "' has an answer after a month?", "Honestly '" + kw + "' is the question I asked my doctor too",
         "Still asking '" + kw + "' after reading every single reply here", "Me too, '" + kw + "' is what I searched for this morning",
         "A third question about '" + kw + "' from a different viewer today", "A fourth note on '" + kw + "' from yet another viewer here"]
      : ["Has anyone found that '" + kw + "' has an answer after a month?", "Honestly '" + kw + "' is the question I asked my doctor too",
         SPAM_1, ONE_WORD, EMOJI_SHORT, PORTUGUESE];
    return texts.map((t, i) => ({ snippet: { topLevelComment: { id: "c-" + vid + "-" + i, snippet: { authorDisplayName: "someone", textOriginal: t, publishedAt: "2026-10-19T00:00:00Z" } } } }));
  }
  async function capturePass(unfiltered) {
    const events = [], urls = [];
    const db = fakeDb({ youtube_api_calls: [], bsky_leads: [] });
    const realInsert = db.client.from;
    db.client.from = function (table) { const b = realInsert(table); const ins = b.insert; b.insert = function (p) { if (table === "youtube_api_calls") events.push(p.units); return ins.call(b, p); }; return b; };
    let searches = 0, lastQuery = "";
    globalThis.fetch = async function (url) {
      const u = String(url); urls.push(u);
      if (u.indexOf("/youtube/v3/search?") !== -1) {
        searches++; lastQuery = decodeURIComponent((/[?&]q=([^&]+)/.exec(u) || ["", ""])[1]);
        return { ok: true, status: 200, json: async () => ({ items: [0, 1, 2, 3].map(i => ({ id: { videoId: "v" + searches + "x" + i } })) }) };
      }
      const vid = /videoId=([^&]+)/.exec(u)[1];
      return { ok: true, status: 200, json: async () => ({ items: commentsFor(lastQuery, vid, unfiltered) }) };
    };
    process.env.YOUTUBE_API_KEY = "check-key";
    delete process.env.YOUTUBE_DAILY_UNIT_CAP; delete process.env.YOUTUBE_RADAR_DAILY_UNITS;
    const radar = compile(RADAR, FILES[RADAR], { dotenv: { config() {} }, "@supabase/supabase-js": { createClient: () => db.client },
      "./lib/youtubeQuota": Q, "./lib/youtubeFilter": YF });
    const logs = [], realLog = console.log, realErr = console.error;
    console.log = (...a) => { logs.push(a.join(" ")); };
    console.error = (...a) => { logs.push("ERR " + a.join(" ")); };
    try { await radar.runYoutubeRadarOnce(); } finally { console.log = realLog; console.error = realErr; }
    return { db, logs, urls, events, stored: db.tables.bsky_leads, units: db.tables.youtube_api_calls.reduce((a, r) => a + r.units, 0) };
  }
  const D = await capturePass(false);
  check("D. a full pass fetched 8 × 4 × 6 = 192 comments and stored only the 64 kept", D.stored.length === 64, D.stored.length);
  check("D. every stored row passes the filter; no link spam, one-liner or off-topic text is stored",
    D.stored.every(r => YF.isUsefulYoutubeComment(r.post_text, r.matched_keyword).keep) &&
    D.stored.every(r => [SPAM_1, ONE_WORD, EMOJI_SHORT, PORTUGUESE].indexOf(r.post_text) === -1));
  const LINE = /^\[YoutubeRadar\] (.+): fetched (\d+), kept (\d+), dropped (\d+) \(link (\d+), too_short (\d+), off_topic (\d+)\)$/;
  const lines = D.logs.map(l => LINE.exec(l)).filter(Boolean);
  check("D. one count line per keyword, in KEYWORDS order", lines.length === 8 && lines.every((m, i) => m[1] === KW[i]), JSON.stringify(D.logs.slice(0, 3)));
  check("D. each line: fetched 24, kept 8, dropped 16 (link 4, too_short 8, off_topic 4)",
    lines.every(m => m.slice(2).join(",") === "24,8,16,4,8,4"), JSON.stringify(lines.map(m => m.slice(2).join(","))));
  check("D. the counts add up on every line: fetched = kept + dropped, dropped = link + too_short + off_topic",
    lines.length === 8 && lines.every(m => +m[2] === +m[3] + +m[4] && +m[4] === +m[5] + +m[6] + +m[7]));
  check("D. the lines sum to the pass: 192 fetched, 64 kept = rows stored",
    lines.reduce((a, m) => a + +m[2], 0) === 192 && lines.reduce((a, m) => a + +m[3], 0) === D.stored.length);
  const U = await capturePass(true);
  check("D. the units ledger is unchanged by the filter: the same 832 units, the same 40 reservations in the same order as a pass where every comment is kept",
    D.units === 832 && U.units === 832 && JSON.stringify(D.events) === JSON.stringify(U.events) && D.events.length === 40 && U.stored.length === 192,
    JSON.stringify([D.units, U.units, D.events.length, U.events.length, U.stored.length]));
  check("C. a capture pass makes only YouTube Data API requests (no model endpoint)",
    D.urls.length === 40 && D.urls.every(u => u.indexOf("https://www.googleapis.com/youtube/v3/") === 0), JSON.stringify(D.urls.filter(u => u.indexOf("https://www.googleapis.com/youtube/v3/") !== 0)));

  /* ── E. display ────────────────────────────────────────────────────────── */
  console.log("\n══ E. display filters rows already stored ══");
  const defs = ["LEAD_RADAR_UNAVAILABLE", "YOUTUBE_SIGNALS_LIMIT", "YOUTUBE_SIGNALS_PAGE", "YOUTUBE_SIGNALS_MAX_READ", "OUTREACH_CREDENTIAL_OWNER_ID"].map(n => s.definitionOf(FILES[SERVER], n) || "");
  const OWNER = require(path.join(REPO, "lib", "ownerAccount.js")).OWNER_ACCOUNT_ID;
  async function callRoute(rows) {
    const db = fakeDb({ bsky_leads: rows });
    let handler = null;
    const ctx = { supabase: db.client, OWNER_ACCOUNT_ID: OWNER, isUsefulYoutubeComment: YF.isUsefulYoutubeComment, process: { env: { ENABLE_YOUTUBE_RADAR: "true" } },
      console: { log() {}, error() {}, warn() {} }, requireAuth: function requireAuth() {},
      app: { get(p) { if (p === "/api/leads/youtube-signals") handler = arguments[arguments.length - 1]; } } };
    vm.createContext(ctx);
    vm.runInContext(defs.join("\n") + "\n" + ROUTE, ctx);
    const res = { code: 200, body: null, raw: "", status(c) { this.code = c; return this; }, json(b) { this.raw = JSON.stringify(b); this.body = JSON.parse(this.raw); return this; } };
    await handler({ user: { id: OWNER } }, res, (e) => { res.code = 500; res.body = { error: String(e) }; });
    return { res, db };
  }
  // Stored before this build: 1,100 hidden rows (newest), then 400 that pass. created_at descending = index order.
  const HIDDEN_TEXT = [SPAM_2, FIVE_WORDS, PORTUGUESE];
  function storedRows() {
    const rows = [];
    for (let i = 0; i < 1500; i++) {
      const hiddenKind = i < 500 ? 0 : i < 900 ? 1 : i < 1100 ? 2 : -1;
      rows.push({ source: "youtube", status: "signal", post_uri: "https://www.youtube.com/watch?v=s" + i + "&lc=c" + i, matched_keyword: LIBIDO,
        post_created_at: "2026-10-19T00:00:00Z", post_text: hiddenKind === -1 ? "Stored " + i + ": my libido dropped after the new job, any advice?" : HIDDEN_TEXT[hiddenKind],
        created_at: new Date(Date.UTC(2026, 9, 19, 12) - i * 1000).toISOString() });
    }
    return rows;
  }
  const E = await callRoute(storedRows());
  const finds = (E.res.body && E.res.body.finds) || [];
  check("E. the newest 50 KEPT rows are shown, newest first, though 1,100 newer rows are hidden",
    E.res.code === 200 && finds.length === 50 && /^Stored 1100:/.test(finds[0].post_text) && /^Stored 1149:/.test(finds[49].post_text),
    JSON.stringify([E.res.code, finds.length, finds[0] && finds[0].post_text]));
  check("E. every row shown passes the filter", finds.length > 0 && finds.every(f => YF.isUsefulYoutubeComment(f.post_text, f.matched_keyword).keep));
  check("E. hidden_counts are exact for the rows read: link 500, too_short 400, off_topic 200; rows_read 1,150",
    JSON.stringify(E.res.body.hidden_counts) === JSON.stringify({ link: 500, too_short: 400, off_topic: 200 }) && E.res.body.rows_read === 1150,
    JSON.stringify([E.res.body.hidden_counts, E.res.body.rows_read]));
  check("E. the rows were read a page at a time (two pages of 1,000), never limited to 50 before filtering",
    E.db.log.length === 2 && E.db.log.every(q => q.limit === null && q.range && q.range[1] - q.range[0] === 999) && E.db.log[1].range[0] === 1000,
    JSON.stringify(E.db.log.map(q => [q.range, q.limit])));
  check("E. no hidden row's text is in the response", HIDDEN_TEXT.every(t => E.res.raw.indexOf(JSON.stringify(t).slice(1, -1)) === -1) && E.res.raw.indexOf("siteoficial") === -1);
  const small = storedRows().slice(1090, 1105).concat(storedRows().slice(0, 3));
  const E2 = await callRoute(small);
  check("E. fewer than 50 kept: every row is read once, all kept rows shown, hidden_counts exact (link 3, off_topic 10)",
    E2.res.body.finds.length === 5 && JSON.stringify(E2.res.body.hidden_counts) === JSON.stringify({ link: 3, too_short: 0, off_topic: 10 }) && E2.res.body.rows_read === 18 && E2.db.log.length === 1,
    JSON.stringify([E2.res.body.finds.length, E2.res.body.hidden_counts, E2.res.body.rows_read]));
  check("E. the response still has finds, capture_on and kept_days, now with hidden_counts and rows_read",
    JSON.stringify(Object.keys(E.res.body).sort()) === JSON.stringify(["capture_on", "finds", "hidden_counts", "kept_days", "rows_read"]), JSON.stringify(Object.keys(E.res.body)));

  /* ── F. the page ───────────────────────────────────────────────────────── */
  console.log("\n══ F. lead-radar.html says what was hidden, and reveals nothing ══");
  const section = (/<section class="yt-section" id="ytSection"[^>]*>[\s\S]*?<\/section>/.exec(PAGE) || [""])[0];
  check("F. the section states the three rules",
    /<p class="yt-rules" id="ytRules">Only comments that pass three rules are shown: no link, at least 6 words, and a word from the search they matched\. Link spam, one-liners and off-topic comments are hidden\.<\/p>/.test(section), section.slice(0, 400));
  const script = (/<script>([\s\S]*?)<\/script>/.exec(PAGE) || ["", ""])[1];
  const fn = (name) => { const i = script.indexOf("    function " + name + "("); return i < 0 ? "" : script.slice(i, s.braceMatch(script, script.indexOf("{", i))); };
  const pageCode = ["tok", "escHtml", "buildYoutubeFind", "youtubeHiddenLine", "loadYoutubeFinds"].map(fn).join("\n");
  async function runPage(status, data) {
    const made = {};
    const document = { getElementById(id) { return made[id] || (made[id] = { id, hidden: true, innerHTML: "", textContent: "" }); } };
    const ctx = { API: "https://api.example", localStorage: { getItem: () => "t" }, document, String, Number,
      fetch: () => Promise.resolve({ ok: status === 200, status, json: () => Promise.resolve(data) }) };
    vm.createContext(ctx);
    vm.runInContext(pageCode + "\nloadYoutubeFinds();", ctx);
    for (let i = 0; i < 10; i++) await new Promise(r => setImmediate(r));
    return made;
  }
  const P = await runPage(200, { finds: [{ post_uri: "https://www.youtube.com/watch?v=abc&lc=1", matched_keyword: LIBIDO, post_created_at: "2026-10-19T08:00:00Z",
    post_text: "My libido came back after I read https://evil.example/x and www.other.example too" }], hidden_counts: { link: 3, too_short: 2, off_topic: 1 }, rows_read: 7, capture_on: true });
  check("F. it shows \"6 hidden: 3 with links, 2 too short, 1 off topic\"", P.ytHidden && P.ytHidden.hidden === false && P.ytHidden.textContent === "6 hidden: 3 with links, 2 too short, 1 off topic",
    P.ytHidden && P.ytHidden.textContent);
  const listHtml = P.ytList ? P.ytList.innerHTML : "";
  check("F. no link is drawn from comment text: the only anchor is \"Open on YouTube\" to youtube.com",
    (listHtml.match(/<a /g) || []).length === 1 && /<a class="yt-find-link" href="https:\/\/www\.youtube\.com\/watch\?v=abc&amp;lc=1"[^>]*>Open on YouTube<\/a>/.test(listHtml) &&
    listHtml.indexOf("href=\"https://evil") === -1, listHtml.slice(0, 400));
  check("F. no way to reveal hidden rows: no button, toggle or \"show\" control in the section, and no code asks for them",
    !/<button|<input|<details|<select/i.test(section) && !/reveal|show hidden|show_hidden|include_hidden|showHidden/i.test(PAGE.replace(/\/\*[\s\S]*?\*\//g, "").replace(/<!--[\s\S]*?-->/g, "")), section.slice(0, 200));
  const none = await runPage(200, { finds: [], hidden_counts: { link: 4, too_short: 0, off_topic: 0 }, rows_read: 4, capture_on: true });
  check("F. nothing kept but some hidden: it says no stored comment passes the rules, and shows the count",
    /data-state="youtube_none_kept">No stored YouTube comment passes the three rules yet\./.test(none.ytList.innerHTML) && none.ytHidden.textContent === "4 hidden: 4 with links, 0 too short, 0 off topic",
    none.ytList.innerHTML);
  const empty = await runPage(200, { finds: [], hidden_counts: { link: 0, too_short: 0, off_topic: 0 }, rows_read: 0, capture_on: true });
  check("F. nothing stored at all: the old \"nothing has been found yet\" state, with \"0 hidden\"",
    /data-state="youtube_none_yet"/.test(empty.ytList.innerHTML) && /^0 hidden:/.test(empty.ytHidden.textContent));
  const refused = await runPage(403, { error: "no", code: "lead_radar_unavailable" });
  check("F. a refusal hides the section and the count", refused.ytSection.hidden === true && refused.ytHidden.hidden === true && refused.ytHidden.textContent === "");

  /* ── G. the guide tip ──────────────────────────────────────────────────── */
  console.log("\n══ G. the guide tip states the rules ══");
  check("G. the Lead Radar tip says: no link, at least " + YF.YOUTUBE_MIN_WORDS + " words, a word from the search it matched, and that the section counts what was hidden",
    GUIDE.indexOf("A YouTube comment is shown only if it has no link, at least " + YF.YOUTUBE_MIN_WORDS + " words, and a word from the search it matched; the section says how many were hidden and why.") !== -1);

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
