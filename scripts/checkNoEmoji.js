"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkNoEmoji — BizForce shows no emoji. Not on a page, not in a script or a
   stylesheet, not in a guide tip, a legal page, a server or lib message, an
   email or notification, the agents' brain or the app map.

   The owner's rule (Oct 30 2026, "no emojis"): BizForce is professional
   software. Ratings are words and drawn icons ("Helpful", "Not helpful", an
   inline SVG in currentColor), other icons are drawn SVG, and everything
   else is said in words. What the agents and Termaximus write for a member
   follows config/brain.js NO_EMOJI_RULE: no emoji unless the member asks.

   WHAT IS AN EMOJI HERE: any Extended_Pictographic code point, a regional
   indicator (flags), the keycap mark U+20E3, or the emoji presentation
   selector U+FE0F. Found in any of these forms:
     a character             written as itself;
     an HTML entity          a hex or decimal character reference, or a named
                             one that decodes to one (copy, reg, trade, hearts,
                             spades, clubs, diams);
     a CSS escape            a backslash and four to six hex digits (in a
                             stylesheet's content, or in a JS string);
     a JS escape             backslash-u with braces, a surrogate pair, or a
                             four-digit backslash-u. One inside a regex
                             character class (a range a filter strips, such as
                             the content page's U+2600 to U+27BF) is not shown,
                             and is not counted.
   This file builds every vector it tests from parts and code point numbers,
   so it holds none of the forms it looks for.

   THE FILE SET, all read from disk:
     frontend   every .html, .js, .css and .json (pages, page scripts,
                stylesheets, the manifest; the built legal pages among them);
     backend    server.js and the radars beside it (leadRadar, mastodonRadar,
                redditRadar, youtubeRadar: the notifications they send), every
                lib/ file (lib/legalPages.js, lib/appMap.json and the email
                and notification text among them), config/brain.js and the
                other config files, and every scripts/ file.
   Member content is never scanned: no database row, no upload, nothing a
   member wrote.

   THE ONE ALLOW-LIST: fixtures in check scripts that stand for content
   somebody else wrote (a YouTube comment, a member's Bluesky post), counted
   exactly, so one more emoji there, or one fewer (a stale entry), fails.

     N1  the file set was read, and holds what it must;
     N2  no emoji in any file, in any form;
     N3  the allow-list: check scripts only, exact counts, nothing stale;
     N4  the guide's tips and common line, evaluated, carry none;
     N5  the readers find each form, and leave regex ranges and plain
         typography (✓ « » → •) alone;
     N6  the rule for what is written: config/brain.js NO_EMOJI_RULE is last
         in BRAIN_DIRECTIVES, so in every agent prompt once; in the guide's
         persona and in the Oracle's prompt.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check.
   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const Module = require("module");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";

// Built from code points, so this file holds none of what it looks for.
const cp = n => String.fromCodePoint(n);
const THUMB = cp(0x1F44D), CLIP = cp(0x1F4CE), ROCKET = cp(0x1F680), HEART = cp(0x2764);

const GUIDE = "fe:scripts/termaximus-guide.js", AP = "fe:scripts/agent-profile.js", PRESENCE = "fe:scripts/termaximus-presence.js";
const PRIVACY = "fe:privacy.html", EXEC = "fe:executive-agent.html";
const BRAIN = "be:config/brain.js", GUIDE_ASK = "be:lib/guideAsk.js", SERVER = "be:server.js", MAPF = "be:lib/appMap.json";
const LEARN = "be:lib/learningLoop.js", LEGAL = "be:lib/legalPages.js", YT = "be:scripts/checkYoutubeFilter.js";

/* THE ALLOW-LIST. Each entry: a check script, why its emoji are there, and exactly how many. */
const ALLOW = {
  "be:scripts/checkYoutubeFilter.js": { count: 23, why: "YouTube comments as their authors wrote them: the spam filter is proved on real comment text, emoji and all" },
  "be:scripts/checkBskyGate.js": { count: 1, why: "a member's Bluesky post of emoji, to prove the gate counts graphemes, not UTF-16 units" },
  "be:scripts/checkBlueskyConnect.js": { count: 3, why: "a member's post holding one family emoji (three code points joined), to prove the 300-grapheme limit" },
  "be:scripts/checkSocialBlueskyPublish.js": { count: 3, why: "the same member's post with a family emoji, as the publisher counts it" },
  "be:scripts/checkSocialPublishPage.js": { count: 3, why: "the same member's post with a family emoji, as the page counts it" },
  "be:scripts/checkSocialSearch.js": { count: 1, why: "a YouTube video title as its poster wrote it, to prove a title is cut by graphemes" }
};

const MUTATIONS = {
  // an emoji in a guide tip (N2, N4)
  "guide-tip-emoji": [[GUIDE, "\"On \\\"Plans\\\", \\\"Run next\\\" sends one assignment per press;", "\"On \\\"Plans\\\", \\\"Run next\\\" " + THUMB + " sends one assignment per press;"]],
  // the rating button back to a thumb in place of its drawn icon and word (N2)
  "rating-reverted-to-emoji": [[AP, "RATE_ICON_UP + '<span class=\"ap-rate-word\">Helpful</span></button>'", "'" + THUMB + "</button>'"]],
  // the attach button back to its entity (N2)
  "entity-in-script": [[PRESENCE, "aria-label=\"Attach files\"><svg ", "aria-label=\"Attach files\">&#x" + "1F4CE;<svg "]],
  // a CSS escape in a page's stylesheet (N2)
  "css-escape-in-page": [[EXEC, "    .deck-badge { ", "    .deck-badge::before { content: \"\\" + "1F514\"; }\n    .deck-badge { "]],
  // an astral JS escape in a server message (N2)
  "astral-escape-in-server": [[SERVER, "  // The owner's no-emoji rule (config/brain.js NO_EMOJI_RULE), last,", "  console.log(\"\\u{" + "1F680} started\");\n  // The owner's no-emoji rule (config/brain.js NO_EMOJI_RULE), last,"]],
  // a surrogate pair in a lib label (N2)
  "surrogate-in-lib": [[LEARN, "\"% helpful\"", "\"% \\u" + "D83D\\u" + "DC4D\""]],
  // a BMP escape in the brain (N2)
  "bmp-escape-in-brain": [[BRAIN, "const NO_EMOJI_RULE =\n", "const HEARTS = \"\\u" + "2764\";\nconst NO_EMOJI_RULE =\n"]],
  // a keycap in the built privacy page (N2)
  "keycap-in-legal": [[PRIVACY, "<strong>Your agents and what they did</strong>", "<strong>1" + cp(0xFE0F) + cp(0x20E3) + " Your agents and what they did</strong>"]],
  // an emoji in the app map (N2)
  "emoji-in-app-map": [[MAPF, "\"Open full run\"", "\"Open full run " + ROCKET + "\""]],
  // one more emoji in an allow-listed fixture file (N3)
  "fixture-overflow": [[YT, "const EMOJI_SHORT = \"libido tips ", "const EXTRA = \"" + HEART + "\";\nconst EMOJI_SHORT = \"libido tips "]],
  // the brain's rule dropped from BRAIN_DIRECTIVES (N6)
  "brain-rule-dropped": [[BRAIN, " +\n  \"\\n\\n\" + NO_EMOJI_RULE;\n", ";\n"]],
  // the rule dropped from the guide's persona (N6)
  "persona-rule-dropped": [[GUIDE_ASK, " +\n  \"6. \" + require(\"../config/brain\").NO_EMOJI_RULE;", ";"]],
  // the rule dropped from the Oracle's prompt (N6)
  "oracle-rule-dropped": [[SERVER, " +\n    \"\\n\\n\" + NO_EMOJI_RULE;\n}", ";\n}"]],
  // the rule loses the member's exception, so a member who asks is refused (N6)
  "rule-without-exception": [[BRAIN, "The one exception is the member's own instruction: only when the member explicitly asks for emoji in this request may you use them, and then for emoji alone; every other rule you hold still applies.", "Never use them."]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));
if (MUTATE && !MUTATIONS[MUTATE]) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined && detail !== "" ? "  [" + String(detail).slice(0, 600) + "]" : "")); }
}

/* ── the file set ── */
const FILES = {};
function walk(root, prefix, rel, exts, out) {
  const dir = path.join(root, rel);
  if (!fs.existsSync(dir)) return out;
  fs.readdirSync(dir, { withFileTypes: true }).forEach(d => {
    if (d.name === "node_modules" || d.name.startsWith(".")) return;
    const r = rel ? rel + "/" + d.name : d.name;
    if (d.isDirectory()) walk(root, prefix, r, exts, out);
    else if (exts.some(e => d.name.endsWith(e))) out.push(prefix + r);
  });
  return out;
}
if (!fs.existsSync(FRONTEND)) { console.error("Frontend not found: " + FRONTEND + " (set BIZFORCE_FRONTEND_DIR)."); process.exit(2); }
const FRONT = walk(FRONTEND, "fe:", "", [".html", ".js", ".css", ".json"], []);
const BACK = ["be:server.js", "be:leadRadar.js", "be:mastodonRadar.js", "be:redditRadar.js", "be:youtubeRadar.js"]
  .concat(walk(REPO, "be:", "lib", [".js", ".json"], []), walk(REPO, "be:", "config", [".js", ".json"], []), walk(REPO, "be:", "scripts", [".js"], []));
const SET = FRONT.concat(BACK);
const diskOf = k => k.startsWith("fe:") ? path.join(FRONTEND, k.slice(3)) : path.join(REPO, k.slice(3));
SET.forEach(k => { FILES[k] = fs.readFileSync(diskOf(k), "utf8").replace(/\r\n/g, "\n"); });
if (MUTATE) {
  for (const [file, from, to] of MUTATIONS[MUTATE]) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}

/* ── the readers ── */
const PICT = /[\p{Extended_Pictographic}\u{1F1E6}-\u{1F1FF}\u{20E3}\u{FE0F}]/u;
const PICT_ALL = /[\p{Extended_Pictographic}\u{1F1E6}-\u{1F1FF}\u{20E3}\u{FE0F}]/gu;
const isPict = n => n > 0 && n <= 0x10FFFF && PICT.test(cp(n));
const NAMED = { copy: 0xA9, reg: 0xAE, trade: 0x2122, hearts: 0x2665, spades: 0x2660, clubs: 0x2663, diams: 0x2666 };
const hex = t => "U+" + t.toString(16).toUpperCase();

// Is the match at index i inside a regex literal's character class on its line? ("/[ ... \u2600-\u27BF ... ]/")
function inRegexClass(line, i) {
  const open = line.lastIndexOf("[", i), close = line.lastIndexOf("]", i);
  if (open === -1 || close > open) return false;
  const slash = line.lastIndexOf("/", open);
  return slash !== -1 && /(^|[=(,:!&|?{};\s])\/$/.test(line.slice(0, slash + 1)) || /\/\[$/.test(line.slice(0, open + 1));
}

function findingsIn(text) {
  const out = [];
  const lines = text.split("\n");
  lines.forEach((line, n) => {
    const at = (kind, what) => out.push({ line: n + 1, kind, what, text: line.trim().slice(0, 120) });
    let m;
    PICT_ALL.lastIndex = 0;
    while ((m = PICT_ALL.exec(line))) at("character", hex(m[0].codePointAt(0)));
    const ent = /&#x([0-9a-f]{1,6});|&#([0-9]{1,7});|&([a-z]+);/gi;
    while ((m = ent.exec(line))) {
      const v = m[1] ? parseInt(m[1], 16) : m[2] ? parseInt(m[2], 10) : NAMED[m[3]];
      if (v && isPict(v)) at("HTML entity", m[0]);
    }
    const css = /\\([0-9a-fA-F]{4,6})(?![0-9a-fA-F])/g;
    while ((m = css.exec(line))) if (isPict(parseInt(m[1], 16))) at("CSS escape", m[0]);
    const astral = /\\u\{([0-9a-fA-F]{1,6})\}/g;
    while ((m = astral.exec(line))) if (isPict(parseInt(m[1], 16)) && !inRegexClass(line, m.index)) at("JS escape", m[0]);
    const pair = /\\u([dD][89abAB][0-9a-fA-F]{2})\\u([dD][c-fC-F][0-9a-fA-F]{2})/g;
    while ((m = pair.exec(line))) {
      const hi = parseInt(m[1], 16), lo = parseInt(m[2], 16);
      if (isPict((hi - 0xD800) * 0x400 + (lo - 0xDC00) + 0x10000) && !inRegexClass(line, m.index)) at("JS escape", m[0]);
    }
    const bmp = /\\u([0-9a-fA-F]{4})/g;
    while ((m = bmp.exec(line))) if (isPict(parseInt(m[1], 16)) && !inRegexClass(line, m.index)) at("JS escape", m[0]);
  });
  return out;
}

/* ── N1. the file set ── */
console.log("\n══ N1. the file set ══");
const must = [GUIDE, AP, PRESENCE, PRIVACY, EXEC, "fe:terms.html", "fe:run.html", "fe:scripts/bf-exec-deck.js", "fe:scripts/bf-hq.js",
  SERVER, BRAIN, GUIDE_ASK, MAPF, LEARN, LEGAL, "be:lib/yourData.js", YT];
const missing = must.filter(k => FILES[k] === undefined);
check("N1. the set was read: " + FRONT.length + " frontend files and " + BACK.length + " backend files, the pages, scripts, guide, legal pages, server, lib, brain and app map among them",
  missing.length === 0 && FRONT.filter(k => k.endsWith(".html")).length >= 60 && FRONT.filter(k => k.endsWith(".css") || k.endsWith(".js")).length >= 20 && BACK.length >= 150,
  missing.join(", "));
check("N1. no member content is in the set: no upload folder, no database export", !SET.some(k => /\/(uploads?|exports?|backups?)\//i.test(k) || /\.(csv|sql)$/.test(k)));

/* ── N2 and N3. every file ── */
console.log("\n══ N2. no emoji in any file, in any form ══");
const found = {};
SET.forEach(k => { const f = findingsIn(FILES[k]); if (f.length) found[k] = f; });
const shown = Object.keys(found).filter(k => !ALLOW[k]);
check("N2. no emoji, pictograph, keycap, flag or presentation selector in any file outside the allow-list",
  shown.length === 0,
  shown.map(k => found[k].map(f => k.slice(3) + ":" + f.line + " " + f.kind + " " + f.what + " | " + f.text).join(" || ")).join(" || "));
["character", "HTML entity", "CSS escape", "JS escape"].forEach(kind => {
  const bad = shown.filter(k => found[k].some(f => f.kind === kind));
  check("N2. ... none written as a" + (kind === "HTML entity" ? "n " : " ") + kind, bad.length === 0, bad.map(k => k.slice(3)).join(", "));
});

console.log("\n══ N3. the allow-list: fixtures in check scripts, counted ══");
const allowBad = Object.keys(ALLOW).filter(k => !/^be:scripts\/check[A-Za-z]+\.js$/.test(k) || FILES[k] === undefined);
check("N3. every allow-listed file is a check script that exists", allowBad.length === 0, allowBad.join(", "));
const counts = Object.keys(ALLOW).map(k => [k, (found[k] || []).length, ALLOW[k].count]);
check("N3. each holds exactly its listed count (one more, or a stale entry, fails)", counts.every(([, n, want]) => n === want), JSON.stringify(counts));
const notFixture = Object.keys(ALLOW).filter(k => (found[k] || []).some(f => !/["'`]/.test(f.text) || /^\s*(\/\/|\/\*|\*)/.test(f.text)));
check("N3. ...and every one of them is inside a string (a fixture), never in a comment or code", notFixture.length === 0,
  notFixture.map(k => (found[k] || []).filter(f => !/["'`]/.test(f.text) || /^\s*(\/\/|\/\*|\*)/.test(f.text)).map(f => k.slice(3) + ":" + f.line).join(", ")).join(" | "));
check("N3. the allow-list names only content written by somebody else", Object.keys(ALLOW).every(k => /comment|member|post/.test(ALLOW[k].why)));

/* ── N4. the guide, evaluated ── */
console.log("\n══ N4. the guide's tips, evaluated ══");
const G = FILES[GUIDE];
const gi = G.indexOf("var PAGE_GUIDANCE = {"), gj = G.indexOf("\n  };", gi);
let TIPS = null;
try { TIPS = vm.runInNewContext("(" + G.slice(G.indexOf("{", gi), gj + 4) + ")"); } catch (e) { TIPS = null; }
const COMMON_SRC = (/\n  var GUIDE_COMMON = ("(?:[^"\\]|\\.)*");/.exec(G) || [])[1];
const COMMON = COMMON_SRC ? vm.runInNewContext(COMMON_SRC) : null;
const allTips = TIPS ? Object.keys(TIPS).reduce((a, k) => a.concat((TIPS[k] || []).map(t => [k, t])), []) : [];
check("N4. the guide's tips were read: at least 200 tips over at least 50 pages, and the common line", allTips.length >= 200 && Object.keys(TIPS || {}).length >= 50 && !!COMMON, allTips.length);
const emojiTips = allTips.filter(([, t]) => PICT.test(String(t)));
check("N4. no tip, evaluated, carries an emoji", emojiTips.length === 0, emojiTips.map(([k, t]) => k + ": " + t).join(" | "));
check("N4. the common line carries none, and says the ratings in words", !!COMMON && !PICT.test(COMMON) && /Helpful or Not helpful/.test(COMMON), COMMON);
const ex = (TIPS && TIPS["executive-agent.html"]) || [];
check("N4. the Executive's tips name its tabs, in words", ["Command", "Plans", "History", "Approvals", "Agents", "Settings"].every(t => ex.some(x => x.indexOf("\"" + t + "\"") !== -1)), ex.join(" | "));

/* ── N5. the readers themselves ── */
console.log("\n══ N5. the readers find each form, and only those ══");
const kinds = t => findingsIn(t).map(f => f.kind);
const forms = [
  ["a character", "Done " + THUMB, "character"],
  ["a keycap", "1" + cp(0xFE0F) + cp(0x20E3), "character"],
  ["a flag's regional indicators", cp(0x1F1EC) + cp(0x1F1E7), "character"],
  ["a hex entity", "<b>&#x" + "1F4CE;</b>", "HTML entity"],
  ["a decimal entity", "<b>&#" + "128077;</b>", "HTML entity"],
  ["a named entity", "&" + "trade;", "HTML entity"],
  ["a CSS escape", ".x::before{content:\"\\" + "1F44D\"}", "CSS escape"],
  ["an astral JS escape", "var a = \"\\u{" + "1F44D}\";", "JS escape"],
  ["a surrogate pair", "var a = \"\\u" + "D83D\\u" + "DC4D\";", "JS escape"],
  ["a BMP JS escape", "var a = \"\\u" + "2764\";", "JS escape"]
];
forms.forEach(([what, t, kind]) => check("N5. finds " + what, kinds(t).indexOf(kind) !== -1, JSON.stringify(kinds(t))));
const clean = ["  .replace(/[\\u" + "2600-\\u" + "27BF]/g, \"\")", "var RE = /[\\p{Extended_Pictographic}]|[\\u" + "FE0F\\u200D\\u" + "20E3]/u;",
  "Done \u2713 \u00AB more \u00BB \u2192 next \u2022 item \u2014 dash \u00D7 2", "&rarr; &larr; &times; &middot;", "\\bface", "&#x2713;"];
const flagged = clean.filter(t => findingsIn(t).length);
check("N5. leaves regex ranges and plain typography alone (\u2713 \u00AB \u00BB \u2192 \u2022 \u2014 \u00D7, &rarr;, \\bface)", flagged.length === 0, flagged.join(" | "));

/* ── N6. the rule for what is written ── */
console.log("\n══ N6. no emoji in what the agents and Termaximus write, unless the member asks ══");
function compile(key, extraRequire) {
  const file = diskOf(key);
  const m = new Module(file, module); m.filename = file; m.paths = Module._nodeModulePaths(path.dirname(file));
  m._compile(FILES[key], file);
  return m.exports;
}
let brain = null;
try { brain = compile(BRAIN); } catch (e) { check("N6. config/brain.js compiles", false, e.message); }
const RULE = brain && brain.NO_EMOJI_RULE;
check("N6. config/brain.js exports NO_EMOJI_RULE: no emoji for the member, and the member's own explicit request is the one exception",
  typeof RULE === "string" && /^NO EMOJI\./.test(RULE) && /Do not use emoji, pictographs or emoji-style symbols in anything you write for the member/.test(RULE) &&
  /only when the member explicitly asks for emoji in this request may you use them/.test(RULE) && !PICT.test(RULE), RULE);
const dirs = brain && brain.BRAIN_DIRECTIVES;
check("N6. it is last in BRAIN_DIRECTIVES, after OUTPUT CHARACTERS' ban on emoji, so the two never disagree",
  typeof dirs === "string" && !!RULE && dirs.endsWith("\n\n" + RULE) && dirs.indexOf("OUTPUT CHARACTERS") !== -1 && dirs.indexOf("OUTPUT CHARACTERS") < dirs.indexOf(RULE));
let prompt = "";
try { prompt = brain.buildAgentSystemPrompt("AGENT", {}, {}, []); } catch (e) { prompt = ""; }
check("N6. every agent's prompt carries it exactly once", !!RULE && prompt.split(RULE).length === 2, prompt.length);
let persona = "";
try {
  const g = { exports: {} };
  vm.runInNewContext(FILES[GUIDE_ASK], { module: g, exports: g.exports, require: Module.createRequire(diskOf(GUIDE_ASK)), Number, JSON, Object, Array, String }, { filename: "lib/guideAsk.js" });
  persona = g.exports.GUIDE_PERSONA || "";
} catch (e) { persona = ""; }
check("N6. Termaximus's guide persona (lib/guideAsk.js) ends with it, as rule 6",
  !!RULE && persona.endsWith("\n6. " + RULE) && FILES[GUIDE_ASK].indexOf("\"6. \" + require(\"../config/brain\").NO_EMOJI_RULE;") !== -1, persona.slice(-200));
const SV = FILES[SERVER];
const oracleAt = SV.indexOf("\nfunction oracleSystemPrompt() {");
const oracle = oracleAt === -1 ? "" : SV.slice(oracleAt, s.braceMatch(SV, SV.indexOf("{", oracleAt)));
check("N6. the Oracle's prompt (server.js oracleSystemPrompt) ends with it, taken from server.js's require of config/brain",
  /\+\n    "\\n\\n" \+ NO_EMOJI_RULE;\n\}$/.test(oracle) && /^const \{ [^}]*\bNO_EMOJI_RULE \} = require\("\.\/config\/brain"\);$/m.test(SV), oracle.slice(-200));

console.log("");
if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
console.log("ALL " + passes + " CHECKS PASSED");
process.exit(0);
