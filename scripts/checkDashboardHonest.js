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
     4. The Agent Work Queue is gone (launch audit #22a): no section, card or
        button for it, none of its functions or the executive store it fed,
        and no file naming its localStorage key. Every localStorage key the
        dashboard uses is on a short list that says what each one is, so a new
        local-only store fails here. The AI Agent Tasks mailbox reads the
        server's task list.
     5. agents/content.html reads neither contentAgent nor bf_executive_memory
        nor bf_executive_agent_memory, and shows no "Last run".
     6. Every function declared in dashboard.html is reachable from page code,
        an inline handler or a script the page loads (launch audit #22b); a
        function kept only by exporting itself counts as unreachable.

   Before launch audit #22, section 4 pinned a KEPT list and the executive
   store's run record; frontend "The dashboard shows only what is real"
   removed both with the queue (see section 4).

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

/* Launch audit #22 removed the code the first three mutations were anchored in
   (persistExecutiveAgentResult and processExecutiveAssignmentsFromReport), so
   they now land at the top of the agents-count sync, which stays. */
const LIVE_ANCHOR = "(function syncAgentsNavCountFromApi() {\n";
const MUTATIONS = {
  // a canned outcome line comes back
  "restore-canned-outcome": [[DASH, LIVE_ANCHOR, "var agentOutcomes = { seo: \"SEO generated 127 keywords.\" };\n" + LIVE_ANCHOR]],
  // the five-second sprint timer comes back
  "restore-5s-timer": [[DASH, LIVE_ANCHOR, "setInterval(tickExecutiveRuntimeScheduler, 5000);\n" + LIVE_ANCHOR]],
  // a call to a removed function is left behind
  "call-removed-function": [[DASH, LIVE_ANCHOR, "createExecutiveSprintFromAssignments(null, null);\n" + LIVE_ANCHOR]],
  // the Agent Work Queue reads this browser's localStorage again
  "work-queue-reads-localStorage": [[DASH, LIVE_ANCHOR,
    "var agentAssignments = JSON.parse(localStorage.getItem(\"bizforce_agent_assignments\") || \"[]\");\n" + LIVE_ANCHOR]],
  // a new local-only store appears under a key nobody listed
  "new-local-key": [[DASH, LIVE_ANCHOR, "var AGENT_QUEUE_KEY = \"bf_agent_queue\";\nlocalStorage.setItem(AGENT_QUEUE_KEY, \"[]\");\n" + LIVE_ANCHOR]],
  // the queue's section comes back in the markup
  "queue-section-returns": [[DASH, "<section id=\"agentMemorySection\"",
    "<section id=\"agentAssignmentsSection\" class=\"bf-section\"><h2>Agent Work Queue</h2></section>\n<section id=\"agentMemorySection\""]],
  // a function nothing calls is added
  "dead-function-added": [[DASH, LIVE_ANCHOR, "function renderAssignmentHistory() {\n    return [];\n}\n" + LIVE_ANCHOR]],
  // a dead function is kept alive only by exporting itself
  "dead-function-exported": [[DASH, LIVE_ANCHOR, "function clearAssignmentQueue() {\n    return 0;\n}\nwindow.clearAssignmentQueue = clearAssignmentQueue;\n" + LIVE_ANCHOR]],
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

/* ── reachability: which declared functions anything can reach ──────────────
   A function is a node. The roots are code outside every named function, the
   page's inline on*="" handler attributes, and the text of the scripts the page
   loads by src. A function is reached when a reached node names it: as an
   identifier, or as a word inside a string or template (innerHTML handlers).
   `window.X = X;` is an export, not a use, so a function cannot keep itself
   alive by exporting itself. A named function expression is reached when the
   code around it is. Over-approximates (any same-named word counts), so what
   it calls unreachable is unreachable. */
const KW_BEFORE_REGEX = new Set(["return", "typeof", "case", "in", "of", "new", "delete", "void", "throw", "instanceof", "else", "do", "yield", "await"]);
function reachTokens(src) {
  const toks = []; let i = 0, depth = 0; const stack = [];
  const regexAllowed = () => {
    const p = toks[toks.length - 1]; if (!p) return true;
    if (p.t === "id") return KW_BEFORE_REGEX.has(p.v);
    if (p.t !== "p") return false;
    return !(p.v === ")" || p.v === "]" || p.v === "}");
  };
  const readTemplate = () => {
    while (i < src.length) {
      const c = src[i];
      if (c === "\\") { i += 2; continue; }
      if (c === "`") { i++; return "end"; }
      if (c === "$" && src[i + 1] === "{") { i += 2; return "expr"; }
      i++;
    }
    return "end";
  };
  while (i < src.length) {
    const c = src[i], start = i;
    if (/\s/.test(c)) { i++; continue; }
    if (c === "/" && src[i + 1] === "/") { const n = src.indexOf("\n", i); i = n < 0 ? src.length : n; continue; }
    if (c === "/" && src[i + 1] === "*") { const n = src.indexOf("*/", i + 2); i = n < 0 ? src.length : n + 2; continue; }
    if (c === "'" || c === "\"") {
      i++; while (i < src.length && src[i] !== c) { if (src[i] === "\\") i++; i++; } i++;
      toks.push({ t: "str", v: src.slice(start + 1, i - 1) }); continue;
    }
    if (c === "`") { i++; const r = readTemplate(); toks.push({ t: "str", v: src.slice(start + 1, i) }); if (r === "expr") { stack.push(depth); depth++; } continue; }
    if (c === "}" && stack.length && depth - 1 === stack[stack.length - 1]) {
      stack.pop(); depth--; i++; const s2 = i; const r = readTemplate();
      toks.push({ t: "str", v: src.slice(s2, i) }); if (r === "expr") { stack.push(depth); depth++; } continue;
    }
    if (c === "/" && regexAllowed()) {
      i++; let cls = false;
      while (i < src.length) { const d = src[i]; if (d === "\\") { i += 2; continue; } if (d === "[") cls = true; else if (d === "]") cls = false; else if ((d === "/" && !cls) || d === "\n") break; i++; }
      i++; while (/[a-z]/i.test(src[i] || "")) i++;
      toks.push({ t: "regex", v: src.slice(start, i) }); continue;
    }
    if (/[A-Za-z_$]/.test(c)) { while (i < src.length && /[\w$]/.test(src[i])) i++; toks.push({ t: "id", v: src.slice(start, i) }); continue; }
    if (/[0-9]/.test(c)) { while (i < src.length && /[\w.]/.test(src[i])) i++; toks.push({ t: "num", v: src.slice(start, i) }); continue; }
    if (c === "{") depth++; if (c === "}") depth--;
    toks.push({ t: "p", v: c }); i++;
  }
  return toks;
}
function reachability(html, externals) {
  const toks = [].concat(...inlineScripts(html).map(reachTokens));
  const matchFrom = (k, open, close) => { let d = 0; for (let j = k; j < toks.length; j++) { if (toks[j].t === "p" && toks[j].v === open) d++; else if (toks[j].t === "p" && toks[j].v === close) { d--; if (!d) return j; } } return toks.length - 1; };
  const decls = [];
  for (let k = 0; k < toks.length; k++) {
    const t = toks[k];
    if (t.t === "id" && t.v === "function" && toks[k + 1] && toks[k + 1].t === "id" && toks[k + 2] && toks[k + 2].v === "(") {
      const open = matchFrom(k + 2, "(", ")") + 1;
      if (!toks[open] || toks[open].v !== "{") continue;
      const prev = toks[k - 1], isAsync = prev && prev.t === "id" && prev.v === "async", before = isAsync ? toks[k - 2] : prev;
      if (before && before.t === "p" && before.v === "=") continue;   // an assignment, handled below
      const isExpr = before && before.t === "p" && /[(,:?!&|]/.test(before.v);
      decls.push({ name: toks[k + 1].v, nameTok: k + 1, start: isAsync ? k - 1 : k, close: matchFrom(open, "{", "}"), expr: isExpr });
    }
    if (t.t === "p" && t.v === "=" && toks[k - 1] && toks[k - 1].t === "id" && toks[k + 1] &&
        (toks[k + 1].v === "function" || (toks[k + 1].v === "async" && toks[k + 2] && toks[k + 2].v === "function"))) {
      const fnAt = toks[k + 1].v === "function" ? k + 1 : k + 2;
      let p = fnAt + 1; if (toks[p] && toks[p].t === "id") p++;
      if (!toks[p] || toks[p].v !== "(") continue;
      const open = matchFrom(p, "(", ")") + 1;
      if (!toks[open] || toks[open].v !== "{") continue;
      const isWin = toks[k - 2] && toks[k - 2].v === "." && toks[k - 3] && toks[k - 3].v === "window";
      const isVar = toks[k - 2] && toks[k - 2].t === "id" && /^(var|let|const)$/.test(toks[k - 2].v);
      if (!isWin && !isVar) continue;
      decls.push({ name: toks[k - 1].v, nameTok: k - 1, innerName: toks[fnAt + 1].t === "id" ? fnAt + 1 : -1, start: isWin ? k - 3 : k - 2, close: matchFrom(open, "{", "}"), expr: false });
    }
  }
  decls.sort((a, b) => a.start - b.start);
  const owner = new Array(toks.length).fill(-1);
  decls.forEach((d, di) => { for (let j = d.start; j <= d.close; j++) owner[j] = di; });
  decls.forEach((d, di) => { d.parent = -1; decls.forEach((o, oi) => { if (oi !== di && o.start <= d.start && o.close >= d.close && (d.parent < 0 || decls[d.parent].start <= o.start)) d.parent = oi; }); });
  const exportTok = new Set();
  for (let k = 0; k + 5 < toks.length; k++) {
    if (toks[k].v === "window" && toks[k + 1].v === "." && toks[k + 2].t === "id" && toks[k + 3].v === "=" && toks[k + 4].t === "id" &&
        toks[k + 4].v === toks[k + 2].v && (toks[k + 5].v === ";" || toks[k + 5].v === "}")) { exportTok.add(k + 2); exportTok.add(k + 4); }
  }
  const byName = new Map(); decls.forEach((d, di) => { if (!byName.has(d.name)) byName.set(d.name, []); byName.get(d.name).push(di); });
  const refs = new Map(); const addRef = (node, name) => { if (!refs.has(node)) refs.set(node, new Set()); refs.get(node).add(name); };
  toks.forEach((t, k) => {
    const node = owner[k];
    if (t.t === "id") { if (exportTok.has(k) || (node >= 0 && (decls[node].nameTok === k || decls[node].innerName === k))) return; addRef(node, t.v); }
    else if (t.t === "str") (t.v.match(/[A-Za-z_$][\w$]*/g) || []).forEach(w => addRef(node, w));
  });
  const roots = new Set();
  (html.replace(/<script[\s\S]*?<\/script>/gi, "").match(/\son[a-z]+\s*=\s*"[^"]*"/gi) || []).forEach(a => (a.match(/[A-Za-z_$][\w$]*/g) || []).forEach(w => roots.add(w)));
  externals.forEach(text => (text.match(/[A-Za-z_$][\w$]*/g) || []).forEach(w => roots.add(w)));
  const live = new Set(), queue = [];
  function mark(di) {
    if (live.has(di)) return;
    if (decls[di].parent >= 0 && !live.has(decls[di].parent)) { decls[di].pending = true; return; }
    live.add(di); queue.push(di);
    decls.forEach((c, ci) => { if (c.parent === di && (c.expr || c.pending)) mark(ci); });
  }
  const reach = name => (byName.get(name) || []).forEach(mark);
  decls.forEach((c, ci) => { if (c.parent < 0 && c.expr) mark(ci); });
  (refs.get(-1) || new Set()).forEach(reach);
  roots.forEach(reach);
  while (queue.length) (refs.get(queue.shift()) || new Set()).forEach(reach);
  return { total: decls.length, dead: decls.filter((d, di) => !live.has(di) && (d.parent < 0 || live.has(d.parent))).map(d => d.name) };
}

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
  /* NAMED (Block 3a, Oct 29 2026): the Command Center's inline script moved into
     scripts/bf-command-center.js (shared with executive-agent.html), so the page
     has one inline script fewer. Before: scripts.length >= 10. After: >= 9, and the
     shared script is pinned as loaded right after its section and parsing. */
  check("all " + scripts.length + " inline scripts in dashboard.html parse", scripts.length >= 9 && bad.length === 0, bad.join(" | "));
  const CC_SRC = '</section>\n<script src="/scripts/bf-command-center.js"></script>';
  let ccParses = true; try { new vm.Script(FILES["scripts/bf-command-center.js"] || ""); } catch (e) { ccParses = false; }
  check("the Command Center is scripts/bf-command-center.js, loaded right after its section, and it parses",
    FILES[DASH].indexOf(CC_SRC) !== -1 && FILES[DASH].indexOf("(function commandCenter() {") === -1 && ccParses &&
    (FILES["scripts/bf-command-center.js"] || "").indexOf("(function commandCenter() {") !== -1);

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

  /* ── 4. the Agent Work Queue is gone (launch audit #22a) ──────────────── */
  console.log("\n══ 4. the Agent Work Queue is gone, and every local key is listed ══");
  /* This section held a KEPT list (loadExecutiveMemory, saveExecutiveMemory,
     processExecutiveAssignmentsFromReport, recordExecutiveRunToStore) and three
     asserts on the executive store: "the real executive task still records its
     run", "…and creates no sprint", and "the executive store keeps no stats".
     Launch audit #22a removed the Agent Work Queue: a list kept only in this
     browser's localStorage, filled by parsing Executive reports in the page,
     whose status changes and Clear Queue reached no server. Those four
     functions and the store existed to fill it and to project it into
     bf_executive_memory, which no page reads. The real records already have
     panels: AI Agent Tasks reads GET /api/ai/tasks, and the Command Center
     shows executive plans and dispatches them (checkCommandCenterPage). */
  const QUEUE_GONE = ["processExecutiveAssignmentsFromReport", "recordExecutiveRunToStore", "persistExecutiveAgentResult",
    "dispatchExecutiveQueueParsing", "renderAssignmentDashboard", "loadAssignmentsLocal", "saveAssignmentsLocal",
    "loadExecutiveMemory", "saveExecutiveMemory", "updateExecutiveAgentStats", "updateActiveQueueSummary"];
  const stillDeclared = QUEUE_GONE.filter(n => now.has(n));
  check("the queue's functions and the executive store are declared nowhere (" + QUEUE_GONE.length + ")", stillDeclared.length === 0, stillDeclared.join(", "));
  const dashMarkup = FILES[DASH].replace(/<script(\s[^>]*)?>[\s\S]*?<\/script>/g, "");
  const queueIds = ["agentAssignmentsSection", "activeQueueSummary", "viewQueueBtn", "activeAssignmentsList", "clearAssignmentQueue"]
    .filter(id => new RegExp("id=\"" + id + "\"").test(dashMarkup));
  check("no Agent Work Queue section, Active Queue card, View Queue or Clear Queue button in the markup", queueIds.length === 0, queueIds.join(", "));
  const queueWords = Object.keys(FILES).filter(f => /bizforce_agent_assignments|Agent Work Queue assignments|View Queue/.test(FILES[f]));
  check("no file in the frontend names the queue's key or its controls", queueWords.length === 0, queueWords.join(", "));
  check("the AI Agent Tasks mailbox reads the server's task list (GET /api/ai/tasks)",
    /async function loadMailboxReports\(\)[\s\S]{0,400}?fetch\(API_URL \+ "\/api\/ai\/tasks\?limit=25"/.test(FILES[DASH]));

  /* Every key the dashboard's code reads or writes, resolved through the page's
     own `var NAME = "key"` constants. A key not on this list is a new store
     kept only in this browser, and fails here until someone says what it is. */
  const LOCAL_KEYS = {
    bf_token: "the session token", bf_refresh: "the refresh token (removed at logout)", bf_user: "the signed-in profile row",
    tmx_presence_active: "Termaximus presence on/off, this browser's own choice",
    bizforce_ai_mailbox: "a cache of the AI Agent Tasks mailbox, refilled from GET /api/ai/tasks",
    bf_agent_memories: "a cache of Agent Memory, refilled from GET /api/memory"
    /* BEFORE (backend 48334d9): bf_offline_copy was listed, because logout() removed it by name.
       AFTER: logout() calls scripts/bf-session.js clearDevice(), which clears it with every other
       per-member key (checkOfflineMode IV), so the dashboard no longer names it. */
  };
  const dashCode = inlineScripts(FILES[DASH]).join("\n");
  const consts = {};
  (dashCode.match(/\bvar\s+[A-Za-z_$][\w$]*\s*=\s*"[^"]*"\s*;/g) || []).forEach(d => { const m = /var\s+([\w$]+)\s*=\s*"([^"]*)"/.exec(d); consts[m[1]] = m[2]; });
  const used = [], unresolved = [];
  for (const m of dashCode.matchAll(/localStorage\.(?:getItem|setItem|removeItem)\(\s*([^,)]+)/g)) {
    const arg = m[1].trim(), lit = /^["']([^"']*)["']$/.exec(arg);
    if (lit) used.push(lit[1]); else if (Object.prototype.hasOwnProperty.call(consts, arg)) used.push(consts[arg]); else unresolved.push(arg);
  }
  check("every localStorage key the dashboard uses is a literal or a page constant", used.length > 5 && unresolved.length === 0, unresolved.join(", "));
  const unlisted = [...new Set(used)].filter(k => !Object.prototype.hasOwnProperty.call(LOCAL_KEYS, k));
  check("every localStorage key is on the list (" + Object.keys(LOCAL_KEYS).length + "); none is a local-only store", unlisted.length === 0, unlisted.join(", "));
  check("the dashboard calls localStorage only through getItem, setItem and removeItem",
    !/localStorage\s*\[|localStorage\.(?!getItem|setItem|removeItem)\w/.test(dashCode));

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

  /* ── 6. nothing in dashboard.html is unreachable (launch audit #22b) ───── */
  console.log("\n══ 6. every function in dashboard.html is reached ══");
  const srcs = [...FILES[DASH].matchAll(/<script[^>]*\bsrc="([^"]+)"/g)].map(m => m[1].replace(/^\//, ""));
  const missingSrc = srcs.filter(p => !/^https?:/.test(p) && FILES[p] === undefined);
  check("every script the page loads is in the frontend (" + srcs.length + ")", srcs.length > 3 && missingSrc.length === 0, missingSrc.join(", "));
  const reached = reachability(FILES[DASH], srcs.filter(p => FILES[p] !== undefined).map(p => FILES[p]));
  check("every function declared in dashboard.html is reached from page code, a handler or a loaded script (" + reached.total + ")",
    reached.total > 40 && reached.dead.length === 0, reached.dead.join(", "));
  const before22 = reachability(BASE_DASH, []);
  check("the analysis finds dead code where there was some (" + before22.dead.length + " unreachable at BASELINE)", before22.dead.length > 50, before22.dead.length);

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})();
