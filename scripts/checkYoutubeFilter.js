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

   NAMED (Nov 23 2026, LR-2): BEFORE youtubeRadar.js searched the owner's 8 fixed KEYWORDS into bsky_leads, GET
   /api/leads/youtube-signals filtered stored rows for display, and lead-radar.html showed the hidden counts (D to G).
   AFTER the 8 KEYWORDS, runYoutubeRadarOnce, the signals route and that page section are removed (the original is in
   git, 65c0825). YouTube is a source of each member's own Lead Radar: lib/memberRadar.js captureYoutube searches one
   of the member's words (youtubeRadar.js searchComments) and keeps a comment only if the SAME filter keeps it. A, the
   filter, holds unchanged; B now takes its keywords as words a member might enter (the old 8 among them); C, no model
   call, holds; D runs the real captureYoutube; E proves the display route is gone, so nothing unfiltered is shown,
   because nothing unfiltered is stored. F and G (the page and the guide) belong to the page checks now.

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
const MEMBER_RADAR = "lib/memberRadar.js";   // NAMED (Nov 23 2026, LR-2): the page and guide are no longer read here
FILES[MEMBER_RADAR] = fs.readFileSync(path.join(REPO, MEMBER_RADAR), "utf8").replace(/\r\n/g, "\n");

const MUTATIONS = {
  // the link test is dropped
  "drop-link-test": [[FILTER, "  if (youtubeHasLink(t)) return { keep: false, reason: \"link\" };\n", ""]],
  // emoji and punctuation count as words
  "emoji-are-words": [[FILTER, ".filter(function (t) { return /[\\p{L}\\p{N}]/u.test(t); })", ".filter(function (t) { return t.length > 0; })"]],
  // no plural or -ing tolerance
  "no-plural-tolerance": [[FILTER, "  if (w.length > 5 && /ing$/.test(w)) w = w.slice(0, -3);\n  else if (w.length > 3 && /s$/.test(w) && !/ss$/.test(w)) w = w.slice(0, -1);\n", ""]],
  // capture stores every comment (NAMED (Nov 23 2026, LR-2): BEFORE youtubeRadar.js's own loop; AFTER captureYoutube's filter line)
  "capture-unfiltered": [[MEMBER_RADAR, "      if (deps.youtube.useful && !deps.youtube.useful(cm.text, word).keep) return;\n", ""]],
  // NAMED (Nov 23 2026, LR-2): the member helper hands the radar no filter
  "helper-no-filter": [[RADAR, "    useful: isUsefulYoutubeComment", "    useful: null"]]
  // NAMED (Nov 23 2026, LR-2): display-unfiltered and limit-before-filter are removed with GET /api/leads/youtube-signals (E proves it is gone)
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
  console.log("\n══ B. topic terms of a member's words ══");
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
  // NAMED (Nov 23 2026, LR-2): BEFORE these were youtubeRadar.js KEYWORDS (removed); AFTER they are words a member might enter.
  const KW = Object.keys(EXPECTED_TERMS);
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
  check("C. youtubeRadar.js calls no model: its only network calls are the YouTube Data API",
    !/anthropic|openai|callModel|messages\.create/i.test(FILES[RADAR]) && (FILES[RADAR].match(/fetch\(/g) || []).length > 0 &&
    (FILES[RADAR].match(/https:\/\/[^"']+/g) || []).every(u => u.indexOf("https://www.googleapis.com/youtube/v3/") === 0 || u.indexOf("https://www.youtube.com/") === 0), JSON.stringify(FILES[RADAR].match(/https:\/\/[^"']+/g)));

  /* ── D. capture stores only kept comments ─────────────────────────────── */
  // NAMED (Nov 23 2026, LR-2): the real lib/memberRadar.js captureYoutube, its deps the real memberYoutubeDeps' filter.
  console.log("\n══ D. capture stores only kept comments ══");
  const RAD = compile(RADAR, FILES[RADAR], { dotenv: { config() {} }, "@supabase/supabase-js": { createClient: () => fakeDb({}).client }, "./lib/youtubeQuota": Q, "./lib/youtubeFilter": YF });
  const MRM = compile(MEMBER_RADAR, FILES[MEMBER_RADAR], { "./leadFingerprint": require(path.join(REPO, "lib", "leadFingerprint.js")) });
  const helperFilter = RAD.memberYoutubeDeps ? (() => { try { return RAD.memberYoutubeDeps().useful; } catch (e) { return undefined; } })() : undefined;
  check("D. the member helper hands the radar the filter itself", helperFilter === YF.isUsefulYoutubeComment);
  const NOW = Date.parse("2026-11-23T12:00:00Z"), ago = h => new Date(NOW - h * 3600000).toISOString();
  // Each dropped comment names the member's word, so the member radar's own word match would keep it: only the filter drops it.
  const COMMENTS = ["Tongkat ali here: " + SPAM_1, "tongkat ali", "tongkat ali is great stuff", QUESTION, "Buy tongkat ali " + SPAM_2, "Obrigado tongkat ali querida amor"].map((text, i) => ({ id: "c" + i, text, author: "Viewer " + i, url: "https://www.youtube.com/watch?v=v&lc=c" + i, published_at: ago(2) }));
  const inserted = [];
  const sbD = { from() { const b = { upsert(rows) { inserted.push.apply(inserted, rows); return b; }, select() { return b; }, then(res, rej) { return Promise.resolve({ data: inserted.map((x, i) => ({ id: i })), error: null }).then(res, rej); } }; return b; } };
  const fpD = require(path.join(REPO, "lib", "leadFingerprint.js")).shape({ keywords: ["tongkat ali"], sources: { youtube: true } });
  const ytDeps = { caps: () => ({ daily: 9000, radar: 4000 }), worstCase: 106, unitsUsedBy: async () => 0, unitsToday: async () => ({ total: 0, radar: 0 }),
    searchComments: async () => COMMENTS, useful: helperFilter };
  MRM.resetMemory && MRM.resetMemory();
  const D = await MRM.captureYoutube({ sb: sbD, youtube: ytDeps }, [{ user_id: "u1", fp: fpD }], NOW);
  check("D. of six comments naming the word (two links, three too short, one question) only the question is stored",
    inserted.length === 1 && inserted[0].text === QUESTION && inserted[0].source === "youtube" && inserted[0].user_id === "u1", JSON.stringify(inserted.map(x => x.text)));
  check("D. it is stored as found, never scored by a model: Good match on the word, scored_at set", inserted.length === 1 && inserted[0].match_reason === "Good match: \"tongkat ali\"" && !!inserted[0].scored_at, JSON.stringify(inserted[0]));

  /* ── E. nothing unfiltered is shown ───────────────────────────────────── */
  console.log("\n══ E. the display route is gone ══");
  check("E. GET /api/leads/youtube-signals and its limits are removed: a member's YouTube leads are only what capture kept",
    FILES[SERVER].indexOf("app.get(\"/api/leads/youtube-signals\"") === -1 && !/\nconst YOUTUBE_SIGNALS_(LIMIT|PAGE|MAX_READ) =/.test(FILES[SERVER]));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
