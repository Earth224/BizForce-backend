"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkAgentTabs — every agent page in tab folders (Nov 11 2026, agent tabs).

   Frontend "Agent pages in tab folders (Run, Schedule, Activity, Learning,
   Business), duplicate Live Status removed" made scripts/agent-profile.js
   build one scripts/bf-tabs.js panel under the Live Activity strip and the
   Refresh Data / Open Dashboard row on every agent page but the Executive
   command deck, which has its own tabs and is left exactly as it was.

   THE PAGES RUN IN JSDOM with their own scripts (the config, bf-tabs.js,
   bf-paywall.js, agent-profile.js and the page's own), every request answered
   500, so nothing depends on data. No network.

     T1  the tabs, in order: Run, Schedule, Activity, Learning, Business, and
         a page-specific tab only where AGENT_PROFILE_CONFIG.specificTab says;
     T2  every original section in exactly one tab, in its place: the
         launcher, Saved Prompts and tools in Run; Autonomous mode and
         Scheduled runs in Schedule; Agent Stats, Task History (and the
         Approval Queue) in Activity; "How this agent learns" in Learning; the
         Business Profile Context in Business; the page's own sections in its
         tab, in their order. Nothing lost, nothing twice, nothing left
         outside but the back link, the header, the strip and the button row;
     T3  the Live Status panel is gone everywhere;
     T4  ARIA tablist / tab / tabpanel, arrows, Home and End;
     T5  the hashes #ag-<tab>, a tab press writes its hash;
     T6  the tab is remembered per page in sessionStorage bf_ag_tab_<agent>,
         no localStorage key; the default is Run;
     T7  hidden truly hides: the [hidden] override is in place;
     T8  in-page links open their tab: the Next card's "#ap-live-schedule",
         a "#tool=<id>" address, a plain link to a section in another tab, and
         Recent runs' "Open ..." (sigPress) reveal before they scroll;
     T9  the Executive page is untouched: its file, the deck's scripts and the
         page agent-profile.js draws on it are PRE_TABS's, output for output.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check.
   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
// The frontend commit before the agent tabs (the orbit's approved look).
const PRE_TABS = "ecfd367";

const AP = "scripts/agent-profile.js", TABS_JS = "scripts/bf-tabs.js", EXEC = "executive-agent.html", DECK = "scripts/bf-exec-deck.js";
const PAGES = ["ads-agent.html", "broker-agent.html", "community-agent.html", "email-agent.html", "etsy-agent.html", "executive-agent.html",
  "influencer-agent.html", "operations-agent.html", "publicist-agent.html", "rd-agent.html", "reputation-agent.html", "store-agent.html",
  "vertical-marketing-agent.html", "agents/analytics.html", "agents/content.html", "agents/sales.html", "agents/seo.html", "agents/social.html"];
// The page-specific tabs, as briefed: named for the agent's work, holding the page's own sections in their order.
const SPECIFIC = {
  "email-agent.html": ["Sequences", ["esPanel"]],
  "store-agent.html": ["Store", ["storeConnect", "storeChangesCard"]],
  "agents/content.html": ["Publishing", ["contentLaunchPanel", "smsLaunchPanel", "contentLibrarySection", "contentSocialAccounts"]],
  "agents/sales.html": ["Leads", ["salesTopStrip", "salesTarget", "salesModules"]],
  "agents/seo.html": ["Audits", ["seoOptimizeCard", "seoBlogCard"]],
  "agents/social.html": ["Accounts", ["bskyConnect", "bskyMentions", "mastoConnect", "ytConnect", "ttConnect", "igConnect", "fbConnect"]]
};
const SHARED = ["Run", "Schedule", "Activity", "Learning", "Business"];

const MUTATIONS = {
  // a section left out of its tab (T2)
  "section-lost": [[AP, "    if (key === \"learning\") return [document.getElementById(\"apLearnSection\")];\n", "    if (key === \"learning\") return [];\n"]],
  // a section copied into its tab, the original left where it was (T2)
  "section-duplicated": [[AP, "agTabSections(t.key).forEach(function (n) { if (n && panel) panel.appendChild(n); });", "agTabSections(t.key).forEach(function (n) { if (n && panel) panel.appendChild(n.cloneNode(true)); });"]],
  // the Live Status panel drawn again (T3)
  "live-status-back": [[AP, "      /* ── 2. Live status ── REMOVED (Nov 11 2026, agent tabs) on every page:\n",
    "      DECK ? '' : '<div class=\"ap-section\"><div class=\"ap-card\"><h2 class=\"ap-section-label\">Live Status</h2><div class=\"ap-dot idle\" id=\"apDot\"></div></div></div>',\n      /* ── 2. Live status ── REMOVED (Nov 11 2026, agent tabs) on every page:\n"]],
  // a page rule that shows every panel whatever hidden says (T7)
  "hidden-overridden": [[AP, "      \"#agTabs .ag-panel[hidden],#agTabs .deck-panel[hidden]{display:none !important}\" +\n", "      \"#agTabs .ag-panel{display:block !important}\" +\n"]],
  // the tab not remembered (T6)
  "tab-not-remembered": [[AP, "      storage: { kind: \"session\", key: AG_TAB_KEY },\n", "      storage: { kind: \"session\", key: AG_TAB_KEY + \"_\" + Math.random() },\n"]],
  // #ag-<tab> not read (T5)
  "hash-ignored": [[AP, "      nameOf: function (h) { var m = /^ag-([a-z0-9-]+)$/.exec(h); return m ? m[1] : null; },\n", "      nameOf: function () { return null; },\n"]],
  // an in-page link scrolls to a section in a hidden tab (T8)
  "link-lands-in-hidden-tab": [[AP, "    if (k && k !== agTabs.current()) agTabs.select(k, { push: true });\n", ""]],
  // the command deck given these tabs too (T9)
  "executive-changed": [[AP, "    if (DECK || !window.BFTabs || typeof window.BFTabs.create", "    if (!window.BFTabs || typeof window.BFTabs.create"]],
  // a page-specific tab on every page (T1)
  "specific-tab-everywhere": [[AP, "cfg.specificTab.sectionIds.length ? cfg.specificTab : null;", "cfg.specificTab.sectionIds.length ? cfg.specificTab : { name: \"More\", sectionIds: [] };"]],
  // the tab kept in localStorage (T6)
  "local-storage-used": [[AP, "      storage: { kind: \"session\", key: AG_TAB_KEY },\n", "      storage: { kind: \"local\", key: AG_TAB_KEY },\n"]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));
if (MUTATE && !MUTATIONS[MUTATE]) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }

const lf = t => t.replace(/\r\n/g, "\n");
const FILES = {};
function file(f) {
  if (FILES[f] === undefined) {
    const p = path.join(FRONTEND, f);
    if (!fs.existsSync(p)) { console.error("Frontend file not found: " + p + " (set BIZFORCE_FRONTEND_DIR)."); process.exit(2); }
    FILES[f] = lf(fs.readFileSync(p, "utf8"));
  }
  return FILES[f];
}
[AP, TABS_JS, EXEC, DECK].concat(PAGES).forEach(file);
if (MUTATE) {
  for (const [f, from, to] of MUTATIONS[MUTATE]) FILES[f] = s.replaceOnce(file(f), from, to, MUTATE + " in " + f);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}
const gitShow = f => lf(execFileSync("git", ["show", PRE_TABS + ":" + f], { cwd: FRONTEND, maxBuffer: 1 << 27 }).toString("utf8"));

let JSDOM;
try { ({ JSDOM } = require("jsdom")); } catch (e) { console.log("    FAIL  jsdom could not be loaded: " + e.message); process.exit(1); }

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined && detail !== "" ? "  [" + String(detail).slice(0, 500) + "]" : "")); }
}
process.on("unhandledRejection", e => check("no page request is left unhandled", false, (e && e.message) || e));

const SKIP = /bf-theme|bf-session|bf-offline|termaximus|bf-legal-footer|cdn\.jsdelivr|^https?:/;
// The page's scripts in order, inline ones as their text, local ones by path (from the page's own folder).
function scripts(raw, page) {
  const out = [], re = /<script(?:\s+src="([^"]+)")?[^>]*>([\s\S]*?)<\/script>/g; let m;
  while ((m = re.exec(raw))) {
    if (m[1]) { if (SKIP.test(m[1])) continue; out.push({ src: path.posix.normalize(m[1].charAt(0) === "/" ? m[1].slice(1) : path.posix.join(path.posix.dirname(page), m[1])) }); }
    else out.push({ code: m[2] });
  }
  return out;
}
const settle = ms => new Promise(r => setTimeout(r, ms || 40));

/* One agent page, mounted with its own scripts. o.hash, o.session, o.files (overrides), o.answer(url) */
async function mount(page, o) {
  o = o || {};
  const files = Object.assign({}, FILES, o.files || {});
  const raw = files[page] !== undefined ? files[page] : file(page);
  const dom = new JSDOM(raw.replace(/<script[\s\S]*?<\/script>/g, ""), { url: "https://bizforceai.net/" + page + (o.hash || ""), runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window;
  try { w.localStorage.setItem("bf_token", "check-token"); } catch (e) { /* none */ }
  try { Object.keys(o.session || {}).forEach(k => w.sessionStorage.setItem(k, o.session[k])); } catch (e) { /* none */ }
  w.fetch = url => {
    const r = o.answer ? o.answer(String(url)) : null;
    const p = Promise.resolve(r || { ok: false, status: 500, json: () => Promise.resolve({ error: "check" }) });
    p.catch(() => {});
    return p;
  };
  w.HTMLElement.prototype.scrollIntoView = function () { (w.__scrolled = w.__scrolled || []).push(this); };
  w.console.error = () => {}; w.console.warn = () => {};
  const errors = [];
  for (const sc of scripts(raw, page)) {
    try {
      if (sc.code !== undefined) { w.eval(sc.code); continue; }
      const code = files[sc.src] !== undefined ? files[sc.src] : (fs.existsSync(path.join(FRONTEND, sc.src)) ? lf(fs.readFileSync(path.join(FRONTEND, sc.src), "utf8")) : null);
      if (code !== null) w.eval(code);
    } catch (e) { errors.push(sc.src + ": " + e.message); }
  }
  if (w.document.readyState === "loading") await new Promise(r => w.document.addEventListener("DOMContentLoaded", r));
  await settle(o.wait || 40);
  return { w, d: w.document, errors };
}
const tabNames = d => Array.prototype.map.call(d.querySelectorAll("#agTabs [role='tab']"), t => t.textContent);
const selected = d => { const t = d.querySelector("#agTabs [role='tab'][aria-selected='true']"); return t ? t.getAttribute("data-ag-tab") : null; };
const shown = d => Array.prototype.filter.call(d.querySelectorAll("#agTabs [role='tabpanel']"), p => !p.hidden).map(p => p.id.replace("agPanel-", ""));
const panelOf = (d, node) => { for (let n = node; n && n !== d; n = n.parentNode) if (n.getAttribute && n.getAttribute("role") === "tabpanel") return n.id.replace("agPanel-", ""); return null; };
const keyOf = name => name.toLowerCase().replace(/[^a-z0-9]+/g, "-");
const agentTypeOf = raw => (/agentType:\s*"([a-z_]+)"/.exec(raw) || [])[1];

(async () => {
  const TABBED = PAGES.filter(p => p !== EXEC);

  /* ── T1-T3, per page ── */
  console.log("\n══ T1-T3. the tabs, every section in exactly one, no Live Status ══");
  for (const page of TABBED) {
    const P = await mount(page);
    const d = P.d;
    const spec = SPECIFIC[page];
    const want = SHARED.concat(spec ? [spec[0]] : []);
    check(page + ": its scripts run without an error", P.errors.length === 0, P.errors.join(" | "));
    check(page + ": T1 the tabs are " + want.join(", ") + (spec ? "" : " (no page-specific tab)"), JSON.stringify(tabNames(d)) === JSON.stringify(want), tabNames(d).join(","));
    // T2: where each section is
    const where = id => { const n = d.getElementById(id); return n ? panelOf(d, n) : "missing"; };
    const places = {
      apTaskType: "run", apTaskPrompt: "run", apLaunchBtn: "run", apMsg: "run",
      apAutoToggle: "schedule", "ap-live-schedule": "schedule", apSchedForm: "schedule", apSchedEditBtn: "schedule", apSchedDeleteBtn: "schedule",
      apStatTotal: "activity", apStatDone: "activity", apStatFailed: "activity", apStatLast: "activity", apChart: "activity", apHistory: "activity",
      apLearn: "learning", businessContextGrid: "business"
    };
    if (/social_media_drafts/.test(FILES[page])) places.apApprovalQueue = "activity";
    const wrong = Object.keys(places).filter(id => where(id) !== places[id]).map(id => id + "@" + where(id));
    check(page + ": T2 the launcher in Run; Autonomous mode and Scheduled runs in Schedule; Agent Stats and Task History in Activity; the learning section in Learning; the Business Profile in Business",
      wrong.length === 0, wrong.join(", "));
    const saved = d.querySelector("a[href='/saved-prompts.html']");
    const tools = d.querySelectorAll("[data-tool-toggle]");
    check(page + ": T2 the Saved Prompts link and every tool of this agent (" + tools.length + ") in Run", !!saved && panelOf(d, saved) === "run" &&
      Array.prototype.every.call(tools, t => panelOf(d, t) === "run") && (/\btools:\s*\[/.test(FILES[page]) === (tools.length > 0)), tools.length);
    const dupes = Object.keys(places).concat(spec ? spec[1] : []).filter(id => d.querySelectorAll("[id='" + id + "']").length !== 1);
    check(page + ": T2 nothing lost and nothing twice: each of those ids, and the page's own sections, once", dupes.length === 0, dupes.join(", "));
    const panels = Array.prototype.map.call(d.querySelectorAll("#agTabs [role='tabpanel']"), p => [p.id.replace("agPanel-", ""), Array.prototype.map.call(p.children, c => c.id || (c.querySelector("#apHistory") ? "history" : c.querySelector("#apApprovalQueue") ? "approvals" : c.querySelector("#businessContextGrid") ? "business-card" : c.id === "liveAgentStats" ? "liveAgentStats" : c.className))]);
    const wantPanels = [["run", ["apRunSection"]], ["schedule", ["apScheduleSection"]],
      ["activity", ["apStatsSection", "history"].concat(places.apApprovalQueue ? ["approvals"] : [])], ["learning", ["apLearnSection"]],
      ["business", (page === "agents/sales.html" ? [] : []).concat(["business-card"])]].concat(spec ? [[keyOf(spec[0]), spec[1]]] : []);
    const gotPanels = panels.map(([k, kids]) => [k, kids.filter(x => x !== "liveAgentStats")]);
    check(page + ": T2 each tab holds exactly its sections, in order", JSON.stringify(gotPanels) === JSON.stringify(wantPanels), JSON.stringify(gotPanels));
    // what is left outside the tabs: the back link's row, the header, the strip, the button row (and Sales' hidden legacy grid)
    const holder = d.getElementById("agTabs");
    const shell = d.querySelector(".mc-shell");
    const outside = Array.prototype.map.call(holder.parentNode.children, c => c.id || c.className.split(" ")[0] || c.tagName)
      .concat(shell ? Array.prototype.map.call(shell.children, c => c.id || c.className.split(" ")[0] || c.tagName) : []);
    // Sales keeps its header row in .mc-shell, and its button row and the old report grid hidden (mc-legacy-hidden), as before.
    const allowed = ["top-nav", "agent-header", "apLive", "toolbar", "agTabs", "reportsGrid", "mc-shell", "bp-modal-overlay", "bp-status"];
    check(page + ": T2 outside the tabs only the back link, the header, the Live Activity strip and the Refresh Data / Open Dashboard row",
      outside.every(x => allowed.indexOf(x) !== -1) && outside.indexOf("apLive") !== -1 && outside.indexOf("agent-header") !== -1 && !d.querySelector(".page > .ap-section, .page > .context-card, .mc-shell > .ap-section, .mc-shell > .context-card"), outside.join(","));
    const tb = d.querySelector(".toolbar");
    check(page + ": T2 above the tabs: the strip after the header, then the button row with Refresh Data and Open Dashboard",
      d.querySelector(".agent-header").nextElementSibling === d.getElementById("apLive") && !!tb && tb.nextElementSibling === holder &&
      !!tb.querySelector("#refreshBtn") && /Refresh Data/.test(tb.textContent) && /Open Dashboard/.test(tb.textContent) &&
      (holder.compareDocumentPosition(d.getElementById("apLive")) & 2) === 2);
    // T3
    const heads = Array.prototype.map.call(d.querySelectorAll("h1,h2,h3,h4"), h => h.textContent.trim());
    check(page + ": T3 no Live Status panel (no heading, no #apDot, #apLiveLabel or #apLiveMeta)", heads.indexOf("Live Status") === -1 && !d.getElementById("apDot") && !d.getElementById("apLiveLabel") && !d.getElementById("apLiveMeta"));
    P.w.close();
  }
  check("T1 the page-specific tab only on the six pages configured, and its config names exist on the page",
    TABBED.filter(p => /specificTab:/.test(FILES[p])).sort().join(",") === Object.keys(SPECIFIC).sort().join(",") &&
    Object.keys(SPECIFIC).every(p => SPECIFIC[p][1].every(id => id === "esPanel" ? /section\.id = "esPanel";/.test(file("scripts/email-sequences.js")) : FILES[p].split("id=\"" + id + "\"").length === 2)));
  check("T3 agent-profile.js draws no Live Status for any page", !/Live Status<\/h2>/.test(FILES[AP]) && !/id="apDot"/.test(FILES[AP]));
  check("T3 a task launched here reports on the Now card, the Live Status ids are nowhere", /function setLive\(dotCls, label, meta\) \{\n    liveSet\("now", /.test(FILES[AP]) &&
    !PAGES.some(p => /apDot|apLiveLabel|apLiveMeta/.test(FILES[p])));

  /* ── T4-T7 on Ads ── */
  console.log("\n══ T4-T7. ARIA and keys, hashes, remembering, hidden ══");
  const A = await mount("ads-agent.html");
  const d = A.d;
  const list = d.querySelector("#agTabs [role='tablist']");
  const tabs = Array.prototype.slice.call(d.querySelectorAll("#agTabs [role='tab']"));
  check("T4 one tablist; each tab a button with aria-controls its tabpanel, which is aria-labelledby it",
    !!list && d.querySelectorAll("[role='tablist']").length === 1 && tabs.length === 5 && tabs.every(t => t.tagName === "BUTTON" && t.parentNode === list &&
      d.getElementById(t.getAttribute("aria-controls")) && d.getElementById(t.getAttribute("aria-controls")).getAttribute("role") === "tabpanel" &&
      d.getElementById(t.getAttribute("aria-controls")).getAttribute("aria-labelledby") === t.id));
  check("T6 the default is Run: selected, the only panel shown, the only tab in the tab order", selected(d) === "run" && JSON.stringify(shown(d)) === "[\"run\"]" &&
    tabs.filter(t => t.getAttribute("tabindex") === "0").length === 1 && tabs[0].getAttribute("tabindex") === "0");
  const key = (k, from) => { const t = d.getElementById("agTab-" + from); t.focus(); t.dispatchEvent(new A.w.KeyboardEvent("keydown", { key: k, bubbles: true })); return selected(d); };
  check("T4 Right from Run is Schedule, Left from Run wraps to Business, End is Business, Home is Run",
    key("ArrowRight", "run") === "schedule" && key("ArrowLeft", "run") === "business" && key("End", "schedule") === "business" && key("Home", "business") === "run" &&
    d.activeElement === d.getElementById("agTab-run"), selected(d));
  d.getElementById("agTab-activity").click();
  check("T5 pressing a tab shows its panel alone and writes #ag-activity", selected(d) === "activity" && JSON.stringify(shown(d)) === "[\"activity\"]" && A.w.location.hash === "#ag-activity", A.w.location.hash);
  check("T6 the tab is remembered in sessionStorage bf_ag_tab_ads, and nothing is kept in localStorage", A.w.sessionStorage.getItem("bf_ag_tab_ads") === "activity" &&
    Object.keys(A.w.localStorage).every(k => !/bf_ag_tab/.test(k)) && !/localStorage[^\n]*bf_ag_tab|kind: "local", key: AG_TAB_KEY/.test(FILES[AP]), Object.keys(A.w.localStorage).join(","));
  const style = (d.querySelector("#agTabs > style") || {}).textContent || "";
  check("T7 hidden truly hides: '#agTabs .ag-panel[hidden]' is display:none !important, and no rule gives a panel a display of its own",
    /#agTabs \.ag-panel\[hidden\],#agTabs \.deck-panel\[hidden\]\{display:none !important\}/.test(style) && !/\.ag-panel\{[^}]*display/.test(style) &&
    FILES[TABS_JS].indexOf(".deck-panel[hidden] { display: none !important; }") !== -1 &&
    Array.prototype.every.call(d.querySelectorAll("#agTabs [role='tabpanel']"), p => p.hidden === (p.id !== "agPanel-activity")), style);
  check("T7 the tab row scrolls sideways on a narrow screen (deck-tabs-scroll)", list.classList.contains("deck-tabs-scroll"));
  A.w.close();

  const H = await mount("ads-agent.html", { hash: "#ag-learning" });
  check("T5 an address #ag-learning opens Learning", selected(H.d) === "learning" && JSON.stringify(shown(H.d)) === "[\"learning\"]", selected(H.d));
  H.w.close();
  const R = await mount("ads-agent.html", { session: { bf_ag_tab_ads: "business" } });
  check("T6 a page opened again in the same tab comes back to the remembered tab (Business)", selected(R.d) === "business", selected(R.d));
  R.w.close();
  const R2 = await mount("agents/seo.html", { session: { bf_ag_tab_ads: "business" } });
  check("T6 remembered per page: Ads' tab does not move SEO off Run", selected(R2.d) === "run", selected(R2.d));
  R2.w.close();
  const R3 = await mount("ads-agent.html", { session: { bf_ag_tab_ads: "business" }, hash: "#ag-schedule" });
  check("T5 the address wins over the remembered tab", selected(R3.d) === "schedule", selected(R3.d));
  R3.w.close();
  check("T5 every tab's hash opens it, the page-specific one too (#ag-leads on Sales)", await (async () => {
    for (const t of ["run", "schedule", "activity", "learning", "business", "leads"]) {
      const M = await mount("agents/sales.html", { hash: "#ag-" + t });
      const ok = selected(M.d) === t; M.w.close(); if (!ok) return false;
    }
    return true;
  })());

  /* ── T8. in-page links ── */
  console.log("\n══ T8. in-page links open the right tab ══");
  const L = await mount("ads-agent.html", { session: { bf_ag_tab_ads: "activity" } });
  const next = L.d.getElementById("apLive_next");
  next.innerHTML = "<a href=\"#ap-live-schedule\">No schedule</a>";
  L.w.__scrolled = [];
  next.querySelector("a").click();
  check("T8 the Next card's link (\"Set one in Scheduled runs\") opens Schedule and brings the schedule card into view", selected(L.d) === "schedule" &&
    !L.d.getElementById("agPanel-schedule").hidden && (L.w.__scrolled || []).some(n => n.classList && n.classList.contains("ap-sched")), selected(L.d));
  L.d.getElementById("agTab-run").click();
  const a = L.d.createElement("a"); a.href = "#apHistory"; a.textContent = "history"; L.d.getElementById("apLive").appendChild(a);
  a.click();
  check("T8 a plain link to a section in another tab (#apHistory) opens that tab", selected(L.d) === "activity", selected(L.d));
  L.w.close();
  const T = await mount("ads-agent.html", { session: { bf_ag_tab_ads: "learning" }, hash: "#tool=copy&prefill=Spring%20tea" });
  const body = T.d.getElementById("apTool_copy_body");
  check("T8 an address #tool=copy (Executive Headquarters' link) opens Run and the Ad Copy tool there", selected(T.d) === "run" && !!body && !body.hidden && panelOf(T.d, body) === "run", selected(T.d));
  T.w.close();
  // Recent runs' "Open Ad Copy" (sigPress): it reveals the tool's tab before it scrolls and presses.
  const press = (/function sigPress\(selector, label\) \{[\s\S]*?\n  \}/.exec(FILES[AP]) || [""])[0];
  check("T8 Recent runs' \"Open ...\" reveals the tool's tab before it scrolls to it and presses it",
    /revealInTab\(target\);[^\n]*\n      if \(target\.scrollIntoView\) target\.scrollIntoView\(\{ block: "center" \}\);\n      target\.click\(\);/.test(press), press.slice(0, 300));
  // and the reveal itself, from another tab, as the press calls it: the node's tab is opened
  const S = await mount("ads-agent.html", { session: { bf_ag_tab_ads: "business" } });
  const toggle = S.d.querySelector("[data-tool-toggle='copy']");
  const nextLink = S.d.getElementById("apLive_next");
  nextLink.innerHTML = "<a href=\"#tool=copy\">x</a>";
  check("T8 Ad Copy's toggle is in Run, so the press opens Run", !!toggle && panelOf(S.d, toggle) === "run" && selected(S.d) === "business");
  S.w.close();

  /* ── T9. the Executive page, untouched ── */
  console.log("\n══ T9. the Executive page untouched ══");
  check("T9 executive-agent.html, bf-exec-deck.js and bf-tabs.js are PRE_TABS's byte for byte", FILES[EXEC] === gitShow(EXEC) && FILES[DECK] === gitShow(DECK) && FILES[TABS_JS] === gitShow(TABS_JS));
  // NAMED (Nov 11 2026, polish): BEFORE the deck was drawn by PRE_TABS's agent-profile.js as it stood. AFTER the same file
  // with the one rule the polish added (the live status line wraps below 560 px) placed after its 560 px grid rule, exactly
  // as the page has it; everything else drawn must still be PRE_TABS's, output for output.
  const POLISH_GRID = "        '@media (max-width:560px){.ap-live-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}' +\n";
  const POLISH_WRAP = "        '@media (max-width:560px){.ap-live-status{white-space:normal;overflow-wrap:anywhere;min-width:0}}' +\n";
  const preAp = gitShow(AP);
  const beforeAp = preAp.split(POLISH_GRID).length === 2 ? preAp.split(POLISH_GRID).join(POLISH_GRID + POLISH_WRAP) : "/* the PRE_TABS 560 px grid rule moved */";
  const before = await mount(EXEC, { files: { [AP]: beforeAp }, wait: 120 });
  const after = await mount(EXEC, { wait: 120 });
  const norm = d0 => d0.body.innerHTML.replace(/\d{1,2}:\d{2}:\d{2}(\s?[AP]M)?/g, "T");
  check("T9 the command deck as drawn: the page agent-profile.js and the deck draw is PRE_TABS's, output for output (no tabs of ours, no Live Status, its launcher-less card)",
    before.errors.length === 0 && after.errors.length === 0 && norm(before.d) === norm(after.d) && !after.d.getElementById("agTabs") && !!after.d.getElementById("apSettingsSection"),
    (before.errors.concat(after.errors)).join(" | ") || (function () { const x = norm(before.d), y = norm(after.d); let i = 0; while (i < x.length && x[i] === y[i]) i++; return "differs at " + i + ": " + JSON.stringify(x.slice(i - 60, i + 120)) + " vs " + JSON.stringify(y.slice(i - 60, i + 120)); })());
  before.w.close(); after.w.close();
  const agentTypes = TABBED.map(p => agentTypeOf(FILES[p]));
  check("T1 all seventeen other agent pages load bf-tabs.js before agent-profile.js", TABBED.every(p => { const o = scripts(FILES[p], p).map(x => x.src || "inline"); return o.indexOf(TABS_JS) !== -1 && o.indexOf(TABS_JS) < o.indexOf(AP); }) &&
    agentTypes.length === 17 && new Set(agentTypes).size === 17, agentTypes.join(","));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the harness stopped: " + ((e && e.stack) || e)); process.exit(1); });
