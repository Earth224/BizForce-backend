"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkDashboardHonest — the dashboard invents nothing.

   Frontend "Remove the dashboard's invented sprint and dead simulation" took
   out the Executive sprint simulation (its engine, its five-second timer, the
   test and stress buttons, the canned outcomes, the Efficiency Score, the plan
   estimates, the Executive Command Center panel and its runtime panels) and the
   dead content simulation, and stopped agents/content.html reading the
   leftover store those generators wrote. This reads the frontend checkout.

   WHAT THIS PROVES
     1. None of the invented figures or their controls remain anywhere in the
        frontend: "127 keywords", "32 assets", "14 qualified leads", "improved
        brand score", "Efficiency Score", "Run Full Sprint", "agentOutcomes",
        "contentHashSeed", "engagementForecast", "reachForecast", "Executive
        Command Center".
     2. Every inline script in dashboard.html parses.
     3. No code in dashboard.html references a function that was declared at
        BASELINE and is declared nowhere now: no call, no window export, no
        window.X read. Found by comparing BASELINE's declarations with today's.
     4. What live code still uses is still there (the KEPT list), and the real
        executive task still records its assignments and its run, with no
        sprint created.
     5. agents/content.html reads neither contentAgent nor bf_executive_memory
        nor bf_executive_agent_memory, and shows no "Last run".

   generateSeoExecutiveReport, generateCommunityReportFromParts and
   generateCommunityReport were named as live code to keep. They are not in
   either repo at BASELINE or now (removed in earlier commits), so this checks
   the functions this change actually kept for live callers instead.

   MUTATE=<name> edits the frontend files IN MEMORY. MUTATE=all runs each in its
   own process and passes only if every one fails. A mutation whose search text
   does not match exactly once is an ERROR, never counted as caught.

   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), vm = require("vm"), path = require("path");
const { execSync } = require("child_process");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const BASELINE = "5ad489e";
const MUTATE = process.env.MUTATE || "";
const DASH = "dashboard.html", CONTENT = "agents/content.html";

const MUTATIONS = {
  // a canned outcome line comes back
  "restore-canned-outcome": [[DASH, "    delete store.sprints;\n    delete store.kpis;\n",
    "    delete store.sprints;\n    delete store.kpis;\n    var agentOutcomes = { seo: \"SEO generated 127 keywords.\" };\n"]],
  // the five-second sprint timer comes back
  "restore-5s-timer": [[DASH, "    delete store.sprints;\n    delete store.kpis;\n",
    "    delete store.sprints;\n    delete store.kpis;\n    setInterval(tickExecutiveRuntimeScheduler, 5000);\n"]],
  // a call to a removed function is left behind
  "call-removed-function": [[DASH, "        saveExecutiveAssignmentMemories(created, item);\n",
    "        saveExecutiveAssignmentMemories(created, item);\n        createExecutiveSprintFromAssignments(item, sprintId);\n"]],
  // content.html reads the leftover store again
  "content-reads-store": [[CONTENT, "    function refreshPage() {\n",
    "    function refreshPage() {\n      var memory = JSON.parse(localStorage.getItem(\"bf_executive_memory\") || \"null\");\n"]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

/* ── the frontend ───────────────────────────────────────────────────────── */
const FILES = {};
(function walk(dir) {
  fs.readdirSync(dir, { withFileTypes: true }).forEach(d => {
    const p = path.join(dir, d.name);
    if (d.isDirectory()) { if (!/^\.|node_modules/.test(d.name)) walk(p); }
    else if (/\.(html|js|css)$/.test(d.name)) FILES[path.relative(FRONTEND, p).replace(/\\/g, "/")] = fs.readFileSync(p, "utf8").replace(/\r\n/g, "\n");
  });
})(FRONTEND);
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (frontend, in memory)");
}
const BASE_DASH = execSync("git show " + BASELINE + ":" + DASH, { cwd: FRONTEND, maxBuffer: 1 << 27 }).toString("utf8").replace(/\r\n/g, "\n");

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}

/* ── a small tokenizer: identifiers, with comments, strings and regexes skipped ── */
const inlineScripts = (html) => {
  const out = []; const re = /<script(\s[^>]*)?>([\s\S]*?)<\/script>/g; let m;
  while ((m = re.exec(html))) if (!(m[1] && /\bsrc=/.test(m[1]))) out.push(m[2]);
  return out;
};
function tokens(code) {
  const out = []; let i = 0, prevSig = "";
  // Template literals nest: `a ${ b ? `c` : 'd' } e`. Each open ${ pushes the
  // brace depth it started at, and the } that returns to it resumes the template.
  const templateStack = [];
  let depth = 0;
  const regexOk = () => prevSig === "" || /[(,=:[!&|?{};+\-*%<>~^]$/.test(prevSig) || /\b(return|typeof|case|in|of|new|delete|void|throw)$/.test(prevSig);
  function readTemplate(from) {
    // from: index just after a backtick, or just after the } closing a ${ }
    let j = from, text = "";
    while (j < code.length) {
      if (code[j] === "\\") { text += code.slice(j, j + 2); j += 2; continue; }
      if (code[j] === "`") { out.push({ str: text }); return { end: j + 1, open: false }; }
      if (code[j] === "$" && code[j + 1] === "{") { out.push({ str: text }); templateStack.push(depth); depth++; return { end: j + 2, open: true }; }
      text += code[j]; j++;
    }
    out.push({ str: text }); return { end: code.length, open: false };
  }
  while (i < code.length) {
    const c = code[i], n = code[i + 1];
    if (c === "/" && n === "/") { while (i < code.length && code[i] !== "\n") i++; continue; }
    if (c === "/" && n === "*") { const e = code.indexOf("*/", i + 2); i = e < 0 ? code.length : e + 2; continue; }
    if (c === "`") { const r = readTemplate(i + 1); i = r.end; prevSig = r.open ? "{" : "s"; continue; }
    if (c === "{") { depth++; prevSig = c; out.push({ p: c }); i++; continue; }
    if (c === "}") {
      depth--;
      if (templateStack.length && templateStack[templateStack.length - 1] === depth) {
        templateStack.pop();
        const r = readTemplate(i + 1); i = r.end; prevSig = r.open ? "{" : "s"; continue;
      }
      prevSig = c; out.push({ p: c }); i++; continue;
    }
    if (c === "'" || c === "\"") {
      const q = c; let j = i + 1;
      while (j < code.length && code[j] !== q && code[j] !== "\n") { if (code[j] === "\\") j++; j++; }
      out.push({ str: code.slice(i + 1, j) }); i = j + 1; prevSig = "s"; continue;
    }
    if (c === "/" && regexOk()) {
      let j = i + 1, cls = false;
      while (j < code.length && code[j] !== "\n") { if (code[j] === "\\") { j += 2; continue; } if (code[j] === "[") cls = true; else if (code[j] === "]") cls = false; else if (code[j] === "/" && !cls) break; j++; }
      i = j + 1; while (/[a-z]/i.test(code[i] || "")) i++; prevSig = "r"; continue;
    }
    if (/[A-Za-z_$]/.test(c)) {
      let j = i; while (j < code.length && /[\w$]/.test(code[j])) j++;
      const word = code.slice(i, j);
      let k = i - 1; while (k >= 0 && /\s/.test(code[k])) k--;
      const dot = code[k] === ".";
      let obj = ""; if (dot) { let e = k - 1; while (e >= 0 && /\s/.test(code[e])) e--; let b = e; while (b >= 0 && /[\w$]/.test(code[b])) b--; obj = code.slice(b + 1, e + 1); }
      let a = j; while (a < code.length && /[ \t]/.test(code[a])) a++;
      const assigned = code[a] === "=" && code[a + 1] !== "=";
      out.push({ id: word, dot, obj, assigned });
      i = j; prevSig = word; continue;
    }
    if (!/\s/.test(c)) { prevSig = c; out.push({ p: c }); }
    i++;
  }
  return out;
}
const declared = (codes) => {
  const set = new Set();
  codes.forEach(code => { tokens(code).forEach((t, i, all) => { if (t.id === "function" && all[i + 1] && all[i + 1].id) set.add(all[i + 1].id); }); });
  return set;
};

(function main() {
  /* ── 1. the invented figures ──────────────────────────────────────────── */
  console.log("\n══ 1. nothing invented remains ══");
  const BANNED = ["127 keywords", "32 assets", "14 qualified leads", "improved brand score", "Efficiency Score", "Run Full Sprint",
    "agentOutcomes", "contentHashSeed", "engagementForecast", "reachForecast", "Executive Command Center"];
  BANNED.forEach(p => {
    const where = Object.keys(FILES).filter(f => FILES[f].indexOf(p) !== -1);
    check("\"" + p + "\" appears nowhere in the frontend", where.length === 0, where.join(", "));
  });

  /* ── 2. every inline script parses ────────────────────────────────────── */
  console.log("\n══ 2. dashboard.html parses ══");
  const scripts = inlineScripts(FILES[DASH]);
  const bad = []; scripts.forEach((code, i) => { try { new vm.Script(code); } catch (e) { bad.push(i + ": " + e.message); } });
  check("all " + scripts.length + " inline scripts in dashboard.html parse", scripts.length >= 10 && bad.length === 0, bad.join(" | "));

  /* ── 3. no reference to anything removed ──────────────────────────────── */
  console.log("\n══ 3. nothing references a removed function ══");
  const before = declared(inlineScripts(BASE_DASH)), now = declared(scripts);
  const removedNames = [...before].filter(n => !now.has(n));
  check("the removal took out hundreds of functions (" + removedNames.length + ")", removedNames.length > 250, removedNames.length);
  const removed = new Set(removedNames);
  const refs = [];
  scripts.forEach(code => tokens(code).forEach(t => {
    if (!t.id || !removed.has(t.id)) return;
    if (t.dot && !(t.obj === "window" && !t.assigned)) return;   // someone else's property
    refs.push((t.dot ? "window." : "") + t.id);
  }));
  check("no call, export or window read of a removed function remains", refs.length === 0, [...new Set(refs)].slice(0, 12).join(", "));
  const markupRefs = removedNames.filter(n => new RegExp("\\b" + n + "\\b").test(FILES[DASH].replace(/<script(\s[^>]*)?>[\s\S]*?<\/script>/g, "")));
  check("no markup handler names a removed function", markupRefs.length === 0, markupRefs.join(", "));
  check("the five-second sprint timer is gone", !/setInterval\(\s*tickExecutiveRuntimeScheduler/.test(FILES[DASH]) && !/executiveRuntimeSchedulerState/.test(FILES[DASH]));
  check("the Command Center panel and its toggle are gone",
    ["executiveCommandCenterSection", "toggleExecutiveRuntime", "executiveRuntimePanels", "executiveRuntimeTestControls"].every(id => FILES[DASH].indexOf(id) === -1));

  /* ── 4. what live code uses is still there ────────────────────────────── */
  console.log("\n══ 4. what live code uses stays ══");
  const KEPT = ["saveAgentMemory", "loadExecutiveMemory", "saveExecutiveMemory", "initializeExecutiveMemory", "loadExecutiveProject",
    "normalizeAgentMessagingName", "sendAgentMessage", "broadcastAgentMessage", "getAgentInbox", "ensureExecutiveAutonomyEngineStore",
    "getExecutiveAutonomyEngineMemory", "getExecutiveAutonomyEngineSummary", "getLiveSeoBusinessProfileContext", "getAgentBusinessContext",
    "processExecutiveAssignmentsFromReport", "saveExecutiveAssignmentMemories", "recordExecutiveRunToStore", "updateExecutiveAgentStats"];
  const missing = KEPT.filter(n => !now.has(n));
  check("every function live code still calls is still declared (" + KEPT.length + ")", missing.length === 0, missing.join(", "));
  const proc = (FILES[DASH].match(/function processExecutiveAssignmentsFromReport\([\s\S]*?\n\}\n/) || [""])[0];
  check("the real executive task still saves its assignment memories and records its run",
    proc.indexOf("saveExecutiveAssignmentMemories(created, item);") !== -1 && proc.indexOf("recordExecutiveRunToStore(item, sprintId, created);") !== -1, proc.length);
  check("…and creates no sprint", !/createExecutiveSprint/.test(proc));
  const statsFn = (FILES[DASH].match(/function updateExecutiveAgentStats\([\s\S]*?\n\}\n/) || [""])[0];
  check("the executive stats carry no sprint KPI and clear any left behind",
    /delete stats\.efficiencyScore;/.test(statsFn) && !/stats\.efficiencyScore =/.test(statsFn) && !/stats\.sprintsRun =/.test(statsFn));

  /* ── 5. content.html ──────────────────────────────────────────────────── */
  console.log("\n══ 5. agents/content.html ══");
  const contentCode = inlineScripts(FILES[CONTENT]).map(code => tokens(code)).flat();
  const strs = contentCode.filter(t => t.str !== undefined).map(t => t.str);
  const ids = contentCode.filter(t => t.id).map(t => t.id);
  check("it reads no bf_executive_memory or bf_executive_agent_memory key", !strs.some(x => /bf_executive_(agent_)?memory/.test(x)), strs.filter(x => /bf_executive/.test(x)).join(","));
  check("it reads no contentAgent store", !strs.some(x => x === "contentAgent") && ids.indexOf("contentAgent") === -1);
  check("there is no \"Last run\" left to fill from it", FILES[CONTENT].indexOf("lastRunText") === -1 && FILES[CONTENT].indexOf("Last run:") === -1);
  check("the business context comes from /api/business-profile, with a failure message",
    /window\.loadBusinessProfile = function[\s\S]*?\/api\/business-profile[\s\S]*?Could not load profile/.test(FILES[CONTENT]));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})();
