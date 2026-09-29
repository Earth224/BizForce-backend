/* ══════════════════════════════════════════════════════════════════════════
   checkAgentCountCopy.js — every typed agent count in the frontend equals the
   number of agent types the backend registers.

   THE DEFECT. AGENT_SYSTEM_PROMPTS registered 18 agent types while the
   frontend said 17 in thirteen places, because each of those is typed copy
   that nothing derives. Frontend c3ba607 corrected them; this keeps them
   correct the next time an agent is added or removed.

   HOW EACH SITE IS FOUND. By the text around the number, never by line: the
   lines moved once already (dashboard.html's pill was at 138 in the audit and
   175 when it was fixed). Each anchor is a regular expression with one
   capture for the count, and must match EXACTLY ONCE in its file — no match
   means the copy was reworded and this list needs updating, two means the
   anchor is ambiguous. Either is a failure, not a skip.

   THE COUNT IS READ AS DIGITS OR A WORD. "18" and "eighteen" (any case) both
   parse; anything else in the count position fails as unreadable.

   WHAT THIS PROVES
     1. AGENT_SYSTEM_PROMPTS is found in server.js and its keys are counted.
     2. Each of the thirteen sites is found exactly once by its anchor.
     3. Each site's count equals the key count.

   MUTATE=digit-count  rewrites index.html's "18 Agents" pill to one fewer, in
                       memory. That site must go red and only that site.
   MUTATE=word-count   rewrites index.html's "Eighteen specialists" title to
                       one fewer, as a word, in memory. That site must go red
                       and only that site.
   MUTATE=extra-agent  adds a 19th key to the extracted AGENT_SYSTEM_PROMPTS.
                       All thirteen must go red.
   Nothing is written to either repo.

   BIZFORCE_FRONTEND_DIR overrides the frontend location (default: the
   BizForce-fronyend checkout beside this repo).
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const vm = require("vm");
const path = require("path");
const { braceMatch } = require("./_shared");
const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");

const MUTATIONS = ["digit-count", "word-count", "extra-agent"];
const MUTATE = process.env.MUTATE || "";
if (MUTATE && MUTATIONS.indexOf(MUTATE) === -1) {
  console.error("Unknown MUTATE=" + MUTATE + ". Known: " + MUTATIONS.join(", "));
  process.exit(2);
}

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

const WORDS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
  "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen",
  "twenty", "twenty-one", "twenty-two", "twenty-three", "twenty-four", "twenty-five"];
function parseCount(token) {
  if (/^\d+$/.test(token)) return Number(token);
  const i = WORDS.indexOf(String(token).toLowerCase());
  return i >= 0 ? i : NaN;
}
function asWord(n, like) {
  const w = WORDS[n];
  return like[0] === like[0].toUpperCase() ? w[0].toUpperCase() + w.slice(1) : w;
}

/* The count capture is ([A-Za-z-]+|\d+): a digit run, or a word (hyphenated
   for twenty-one and up). */
const N = "(\\d+|[A-Za-z]+(?:-[A-Za-z]+)?)";
const SITES = [
  { file: "index.html", what: "meta description",       re: new RegExp('<meta name="description" content="One subscription, ' + N + ' AI specialists') },
  { file: "index.html", what: "hero lede",              re: new RegExp("BizForce AI is " + N + " specialists that read the same business profile") },
  { file: "index.html", what: "hero CTA note",          re: new RegExp('<p class="cta-note">One subscription\\. All ' + N + " agents\\. Every platform tool\\.</p>") },
  { file: "index.html", what: "agent section title",    re: new RegExp('<h2 class="section-title">' + N + " specialists, one business profile</h2>") },
  { file: "index.html", what: "agent section pill",     re: new RegExp('<span class="pill">' + N + " Agents</span>") },
  { file: "index.html", what: "pricing feature list",   re: new RegExp("<li>All " + N + " AI Business Agents \\(SEO, Sales, Content") },
  { file: "index.html", what: "pricing note",           re: new RegExp("^\\s*All " + N + " agents\\. Unlimited task runs\\. Every platform tool\\.", "m") },
  { file: "app.html",   what: "subscription line",      re: new RegExp("One subscription unlocks all " + N + " AI business agents and all platform tools") },
  { file: "app.html",   what: "fine print",             re: new RegExp("PR, and R&amp;D — " + N + " specialists in all") },
  { file: "billing.html", what: "plan feature list",    re: new RegExp("<li>All " + N + " AI Business Agents \\(SEO, Sales, Content") },
  { file: "dashboard.html", what: "topbar pill fallback", re: new RegExp('<span class="topbar-agents-num">' + N + "</span>") },
  { file: "scripts/termaximus-guide.js", what: "ai-agents tip, directory", re: new RegExp("The full directory of all " + N + " AI agents") },
  { file: "scripts/termaximus-guide.js", what: "ai-agents tip, shortlist", re: new RegExp("with " + N + " to choose from, a shortlist") }
];

/* ── 1. the registered roster ─────────────────────────────────────────────── */
console.log((MUTATE ? "\n>>> MUTATE=" + MUTATE + "\n" : "") + "\n══ 1. AGENT_SYSTEM_PROMPTS ══");
const SRC = fs.readFileSync(path.join(REPO, "server.js"), "utf8");
const decl = /^(?:const|var|let) AGENT_SYSTEM_PROMPTS\s*=\s*\{/m.exec(SRC);
if (!decl) { console.log("    FAIL  AGENT_SYSTEM_PROMPTS not found in server.js"); process.exit(1); }
const open = SRC.indexOf("{", decl.index);
let literal = SRC.slice(open, braceMatch(SRC, open));
if (MUTATE === "extra-agent") literal = literal.replace(/\}\s*$/, ', check_extra_agent: "added by MUTATE=extra-agent" }');
const keys = Object.keys(vm.runInNewContext("(" + literal + ")", {}));
const EXPECTED = keys.length;
const declLine = SRC.slice(0, decl.index).split("\n").length;
console.log("    server.js:" + declLine + " — " + EXPECTED + " keys: " + keys.join(", "));
check("1. AGENT_SYSTEM_PROMPTS has keys", EXPECTED > 0, EXPECTED);

/* ── 2 & 3. every typed count ─────────────────────────────────────────────── */
console.log("\n══ 2 & 3. the thirteen typed counts, expected " + EXPECTED + " ══");
const cache = {};
function read(file) {
  if (cache[file] === undefined) {
    const p = path.join(FRONTEND, file);
    if (!fs.existsSync(p)) { console.error("Frontend file not found: " + p + " (set BIZFORCE_FRONTEND_DIR)."); process.exit(1); }
    cache[file] = fs.readFileSync(p, "utf8");
  }
  return cache[file];
}

/* The mutations change the frontend text in memory only, by the same anchor
   the site is checked with, so they can never hit the wrong occurrence. */
function mutateSite(file, what, n) {
  const site = SITES.find(function (s) { return s.file === file && s.what === what; });
  const text = read(file);
  const m = site.re.exec(text);
  const token = m[1];
  const replacement = /^\d+$/.test(token) ? String(n) : asWord(n, token);
  const whole = m[0].replace(token, replacement);
  cache[file] = text.slice(0, m.index) + whole + text.slice(m.index + m[0].length);
}
if (MUTATE === "digit-count") mutateSite("index.html", "agent section pill", EXPECTED - 1);
if (MUTATE === "word-count")  mutateSite("index.html", "agent section title", EXPECTED - 1);

SITES.forEach(function (site) {
  const text = read(site.file);
  const g = new RegExp(site.re.source, site.re.flags.indexOf("g") >= 0 ? site.re.flags : site.re.flags + "g");
  const matches = [];
  let m;
  while ((m = g.exec(text))) matches.push(m);
  const label = site.file + " — " + site.what;
  if (matches.length !== 1) {
    check(label + ": anchor found exactly once", false, matches.length + " matches");
    return;
  }
  const line = text.slice(0, matches[0].index + matches[0][0].indexOf(matches[0][1])).split("\n").length;
  const token = matches[0][1];
  const n = parseCount(token);
  check(label + " (line " + line + ", reads \"" + token + "\")", n === EXPECTED,
    isNaN(n) ? "count unreadable: " + token : "says " + n + ", registry has " + EXPECTED);
});

console.log("\n" + (failures ? failures + " FAILED" : "ALL PASS") + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
process.exit(failures ? 1 : 0);
