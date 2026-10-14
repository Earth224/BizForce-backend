"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkReputationTips — the Reputation page's Termaximus tips say what the
   agent really does.

   Frontend "The Reputation tips say what the agent really does" rewrote the
   reputation-agent.html entry in scripts/termaximus-guide.js. Its first tip
   used to say the agent "watches reviews, sentiment, and mentions, and flags
   Risks early", and its last sent people to a Risks panel the page does not
   have. Nothing on this platform watches anything: it reads no review site
   and holds no mentions or sentiment feed, and the sentiment_report
   instruction in server.js says so.

   The tips and the page's AGENT_PROFILE_CONFIG are read from the frontend
   checkout the way checkStorefrontPage.js reads them (the entry's array and
   the config object evaluated in vm); server.js is read from this repo for
   the claims the tips make about what each tool does. No DOM, no network, no
   model call, no database.

   WHAT THIS PROVES
     1. The entry says none of "watches", "monitors", "tracks", "alerts",
        "flags risks early", "real-time", "sentiment score", a Risks panel or
        an early-warning system, and no tip but the does-not-watch sentence
        uses watch, monitor, track or alert in any form.
     2. The entry states plainly that this agent does not watch or monitor
        mentions, reviews or sentiment anywhere.
     3. Every feature the tips name is offered by reputation-agent.html, and
        both tools and the two scoring task types are named.
     4. What the tips say each tool does is what server.js does: the two
        routes exist, the reply is scanned for disputing phrasing and the
        request for incentives, and the audit and sentiment instructions say
        nothing is read and no score is measured.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check. A mutation
   whose search text does not match exactly once is an ERROR.

   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const PAGE = "reputation-agent.html", GUIDE = "scripts/termaximus-guide.js", SERVER = "server.js";

const NEW_FIRST_TIP = '      "This agent does not watch or monitor mentions, reviews or sentiment anywhere. It works only from what you paste in or type, and from your Business Profile.",';

const MUTATIONS = {
  // the old first tip is back
  "restore-watches-tip": [[GUIDE, NEW_FIRST_TIP,
    '      "This agent watches reviews, sentiment, and mentions, and flags Risks early — built as much for recovery as for monitoring.",']],
  // the tips send people to a Risks panel again
  "restore-risks-panel": [[GUIDE,
    '      "Review Strategy, Brand Trust Plan and Crisis Response write plans from your request and Business Profile. Run Crisis Response once before you need it, so the plan is ready."',
    '      "Check the Risks panel regularly; it\'s this agent\'s early-warning system, not an afterthought."']],
  // a tip says the agent keeps an eye on reviews, without any listed word
  "tip-claims-tracking": [[GUIDE,
    '"Review Request builds a request sequence for a moment you choose, and flags incentive wording that breaks review-platform rules."',
    '"Review Request builds a request sequence for a moment you choose, and keeps tracking your reviews afterwards."']],
  // the page stops offering a tool the tips name
  "page-drops-review-request": [[PAGE, '"label": "Review Request",', '"label": "Review Ask",']]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

const FILES = {};
[[PAGE, FRONTEND], [GUIDE, FRONTEND], [SERVER, REPO]].forEach(([f, dir]) => {
  const p = path.join(dir, f);
  if (!fs.existsSync(p)) { console.error("File not found: " + p + " (set BIZFORCE_FRONTEND_DIR)."); process.exit(1); }
  FILES[f] = fs.readFileSync(p, "utf8").replace(/\r\n/g, "\n");
});
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE);
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}

const tipsSrc = /"reputation-agent\.html": (\[[\s\S]*?\n    \])/.exec(FILES[GUIDE]);
const tips = tipsSrc ? vm.runInNewContext(tipsSrc[1]) : [];
const tipText = tips.join("\n");
const cfgSrc = /window\.AGENT_PROFILE_CONFIG = (\{[\s\S]*?\n\});/.exec(FILES[PAGE]);
const cfg = cfgSrc ? vm.runInNewContext("(" + cfgSrc[1] + ")") : { taskTypes: [], tools: [] };

/* ── 1. no watching ─────────────────────────────────────────────────────── */
console.log("\n══ 1. no claim of watching ══");
check("1. the reputation entry's tips were found", tips.length >= 4, tips.length);
const FORBIDDEN = [/\bwatches\b/i, /\bmonitors\b/i, /\btracks\b/i, /\balerts\b/i, /flags risks early/i, /real-?time/i, /sentiment score/i,
  /risks panel/i, /early[- ]warning/i];
check("1. the entry says none of watches, monitors, tracks, alerts, flags risks early, real-time, sentiment score, Risks panel, early-warning",
  FORBIDDEN.every(re => !re.test(tipText)), FORBIDDEN.filter(re => re.test(tipText)).join(" "));
const DOES_NOT = /this agent does not watch or monitor mentions, reviews or sentiment anywhere/i;
const others = tips.filter(t => !DOES_NOT.test(t));
check("1. no other tip uses watch, monitor, track or alert in any form",
  others.every(t => !/\b(watch|monitor|track|alert)/i.test(t)), others.filter(t => /\b(watch|monitor|track|alert)/i.test(t)).join(" | "));
check("1. no tip claims to read a site, feed or account",
  tips.every(t => !/\b(reads|pulls|fetches|scans|checks) (your |the )?(reviews|review sites?|feeds?|accounts?|mentions|google|yelp|trustpilot)\b/i.test(t)),
  tips.filter(t => /\b(reads|pulls|fetches|scans|checks) (your |the )?(reviews|review sites?|feeds?|accounts?|mentions|google|yelp|trustpilot)\b/i.test(t)).join(" | "));

/* ── 2. the does-not-watch sentence ─────────────────────────────────────── */
console.log("\n══ 2. it says it does not watch ══");
check("2. a tip says \"This agent does not watch or monitor mentions, reviews or sentiment anywhere\"", tips.some(t => DOES_NOT.test(t)));

/* ── 3. every named feature is offered ──────────────────────────────────── */
console.log("\n══ 3. the tips name only what the page offers ══");
const taskLabels = cfg.taskTypes.map(t => t.label), toolLabels = cfg.tools.map(t => t.label);
const offered = taskLabels.concat(toolLabels);
check("3. the page offers the six task types and two tools the tips were written against",
  JSON.stringify(cfg.taskTypes.map(t => t.value)) === JSON.stringify(["reputation_audit", "review_strategy", "brand_trust", "crisis_response", "sentiment_report", "general"]) &&
  JSON.stringify(cfg.tools.map(t => t.id)) === JSON.stringify(["review-response", "review-request"]),
  JSON.stringify(cfg.taskTypes.map(t => t.value)) + " " + JSON.stringify(cfg.tools.map(t => t.id)));
// Every feature name a reputation tip has used, or could plausibly use, offered or not.
const CANDIDATES = offered.concat(["Reputation Plan", "Reputation Management Plan", "Risks", "Mentions", "Sentiment Tracker", "Review Monitor",
  "Brand Monitoring", "Alerts", "Dashboard", "Testimonial", "Brand Authority"]);
const named = CANDIDATES.filter((n, i) => CANDIDATES.indexOf(n) === i && tipText.indexOf(n) !== -1);
check("3. every feature the tips name is offered on the page", named.every(n => offered.indexOf(n) !== -1),
  named.filter(n => offered.indexOf(n) === -1).join(", "));
check("3. the tips name both tools, Review Response and Review Request", ["Review Response", "Review Request"].every(n => tipText.indexOf(n) !== -1 && toolLabels.indexOf(n) !== -1));
check("3. the tips name Reputation Audit and Sentiment Report as the page labels them",
  ["Reputation Audit", "Sentiment Report"].every(n => tipText.indexOf(n) !== -1 && taskLabels.indexOf(n) !== -1));
check("3. the audit and sentiment tip says they read no review site and give no measured score",
  tips.some(t => /Reputation Audit/.test(t) && /Sentiment Report/.test(t) && /read no review site/.test(t) && /no measured score/.test(t)));

/* ── 4. the tips match what server.js does ──────────────────────────────── */
console.log("\n══ 4. what the tips say each tool does is what the server does ══");
const SRV = FILES[SERVER];
check("4. POST /api/agents/reputation/review-response and review-request exist",
  /app\.post\("\/api\/agents\/reputation\/review-response"/.test(SRV) && /app\.post\("\/api\/agents\/reputation\/review-request"/.test(SRV));
check("4. Review Response: the server scans the reply for phrasing that disputes or blames the reviewer",
  /function scanReviewResponse\(/.test(SRV) && /assigning fault to the reviewer/.test(SRV) && /denying the account/.test(SRV));
check("4. Review Request: the server scans the sequence for incentives and states the platform rules",
  /function scanReviewIncentives\(/.test(SRV) && /INCENTIVISING REVIEWS BREACHES THE TERMS OF EVERY MAJOR PLATFORM/.test(SRV));
check("4. reputation_audit says this platform reads no review site",
  /reputation_audit: "[^"\n]*This platform reads no review site/.test(SRV));
check("4. sentiment_report says there is no feed and no number is a measured sentiment",
  /sentiment_report: "[^"\n]*holds no review data, no social listening and no sentiment feed[^"\n]*never state a number/.test(SRV));
check("4. no reputation route reads a review site or mentions feed (only the two input-only routes exist)",
  (SRV.match(/app\.(get|post)\("\/api\/agents\/reputation\//g) || []).length === 2);

console.log("\n" + (failures ? "CHECKS FAILED: " + failures + " of " + (passes + failures) : "ALL " + passes + " CHECKS PASSED") + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
process.exit(failures ? 1 : 0);
