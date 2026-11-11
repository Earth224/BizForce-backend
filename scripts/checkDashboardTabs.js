"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkDashboardTabs — the dashboard's Command Center in tabs (Nov 10 2026,
   dashboard tabs), and the Executive deck unchanged on the same tab component.

   Frontend "Dashboard Command Center in tabs, self-limiting; shared tab
   component for the dashboard and Executive Headquarters" made the dashboard's
   Command Center one scripts/bf-tabs.js panel of seven tabs (Command, Plans,
   Activity, Autopilot, Outbound, System, Memory), drawn by
   scripts/bf-command-center.js in its tabbed mode (data-cc-mode="tabs") from
   ONE GET /api/command-center read, and moved the Executive deck's tab code
   into scripts/bf-tabs.js with no change in what it does.

   THE PAGES RUN IN JSDOM: dashboard.html's markup with bf-tabs.js and
   bf-command-center.js, and executive-agent.html's markup with bf-tabs.js and
   bf-exec-deck.js, over fixture answers. No network, no database.

     T1  the top half: everything in dashboard.html above the Command Center,
         and everything after it, is byte for byte what it was at BASELINE;
         the Agent Memory markup is byte for byte the same, inside its tab;
     T2  the tabs: a tablist with roles, aria-selected, aria-controls and
         aria-labelledby; Right, Left (wrapping), Home and End; #cc-<tab> in
         the address and hashchange; the last tab in sessionStorage bf_cc_tab
         (a failing store still opens Command), never in localStorage; the
         row scrolls sideways (deck-tabs-scroll and its overflow-x rule);
     T3  one fetch: every tab draws from the one read, the first time it is
         opened; Refresh reads once more;
     T4  caps and folds over large fixtures (200 runs, 50 plans, 40 jobs, 20
         social drafts, 20 articles): 3 proposals and 3 failed runs, 10 active
         plans, steps behind "Show steps", "Past plans (N)" folded with 5, 5
         runs then "Show more" up to 20, 3 of each outbound type;
     T5  the empty states word for word, and empty types left out;
     T6  System: spend for everyone; the jobs, grouped hourly families and the
         radar for an admin only; only the jobs that need attention listed;
     T7  Memory works in its tab;
     T8  new DOM is built with textContent: the CC-TABS block has no
         innerHTML, and a title carrying markup stays text;
     T9  the Executive deck: six tabs, plain hashes, #tool=plan, element
         links, localStorage bf_exec_tab, the keys, hashchange; and the shared
         renderer still draws its Headquarters panels the old way.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check.
   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
// The frontend commit before the tabs (Brief 3's readable artist pop-up).
const BASELINE = "b6be965";

const DASH = "dashboard.html", EXEC = "executive-agent.html", CC = "scripts/bf-command-center.js", TABS_JS = "scripts/bf-tabs.js", DECK = "scripts/bf-exec-deck.js";
// NAMED (Nov 10 2026, real-browser fix and essentials): the site stylesheet, read for T11's static [hidden] rule.
const UI_CSS = "css/bizforce-ui.css";
const CC_COMMENT = "<!-- COMMAND CENTER. Everything in it is read from GET /api/command-center,";
const CC_TAG = "<script src=\"/scripts/bf-command-center.js\"></script>";

const MUTATIONS = {
  // something above the Command Center changes (T1)
  "top-half-changed": [[DASH, CC_COMMENT, "<p class=\"cc-muted\">A new line above the Command Center.</p>\n" + CC_COMMENT]],
  // the tab row loses its tablist role (T2)
  "tabs-not-aria": [[DASH, "<div class=\"deck-tabs deck-tabs-scroll\" role=\"tablist\" aria-label=\"Command Center\">",
    "<div class=\"deck-tabs deck-tabs-scroll\" aria-label=\"Command Center\">"]],
  // #cc-<tab> in the address is ignored (T2)
  "hash-ignored": [[CC, "nameOf: function (h) { var m = /^cc-([a-z]+)$/.exec(h); return m ? m[1] : null; },", "nameOf: function (h) { return null; },"]],
  // the remembered tab is never read back (T2)
  "tab-not-remembered": [[TABS_JS, "    function remembered() { try { return store().getItem(o.storage.key); }", "    function remembered() { try { return null; }"]],
  // the dashboard keeps its tab in localStorage (T2)
  "local-storage-used": [[CC, "storage: { kind: \"session\", key: \"bf_cc_tab\" },", "storage: { kind: \"local\", key: \"bf_cc_tab\" },"]],
  // each tab reads the route again when opened (T3)
  "fetch-per-tab": [[CC, "                onSelect: draw,\n", "                onSelect: function (n) { draw(n); if (n !== \"command\" && window.BFCommandCenter) { window.BFCommandCenter.load(); } },\n"]],
  // Activity shows every run at once (T4)
  "runs-uncapped": [[CC, "runs: 5, runsMore: 20,", "runs: 500, runsMore: 20,"]],
  // "Show more" shows all 200 (T4)
  "show-more-uncapped": [[CC, "runs: 5, runsMore: 20,", "runs: 5, runsMore: 2000,"]],
  /* NAMED BEFORE → AFTER (Nov 10 2026, real-browser fix and essentials): five anchors moved with the code they edit,
     the same mutant each time. past-plans-not-folded: BEFORE `past.hidden = true;`, AFTER the past fold drawn as a
     plain heading instead of a toggle (toggle() now hides every fold itself). jobs-listed-when-healthy and
     empty-state-missing: BEFORE el("p", …), AFTER line(…). system-shown-to-member: BEFORE the hasOwnProperty test,
     AFTER isAdmin(). */
  // past plans open from the start (T4)
  "past-plans-not-folded": [[CC, "                out.appendChild(toggle(\"Past plans (\" + d.past_count + \")\", past));\n",
    "                out.appendChild(el(\"div\", \"cc-sub\", \"Past plans (\" + d.past_count + \")\"));\n"]],
  // the 24 hourly rows counted one by one (T6)
  "hourly-not-grouped": [[CC, "                if (m && v.cadence === \"hourly\") {\n", "                if (false) {\n"]],
  // a healthy system still lists every job (T6)
  "jobs-listed-when-healthy": [[CC, "            else if (!bad.length) { out.appendChild(line(\"All \" + units.length + \" background jobs ran on time\", \"cc-clear\")); }\n",
    "            else if (!bad.length) { out.appendChild(line(\"All \" + units.length + \" background jobs ran on time\", \"cc-clear\")); out.appendChild(list(units, function (u) { return el(\"li\", null, u.text); })); }\n"]],
  // Command's empty state loses its words (T5)
  "empty-state-missing": [[CC, "out.appendChild(line(\"Nothing needs you right now.\", \"cc-clear\"));", "out.appendChild(line(\"\", \"cc-clear\"));"]],
  // every agent listed under Automatic, manual ones too (T5)
  "manual-agents-listed": [[CC, "            var on = d.autonomy.filter(function (r) { return r.enabled === true; });\n", "            var on = d.autonomy.slice();\n"]],
  // an empty outbound type still shown (T5)
  "outbound-empty-types-shown": [[CC, "            if (d.email_sequences.length) {\n", "            if (true) {\n"]],
  // a member's System tab tries to show the jobs (T6)
  "system-shown-to-member": [[CC, "            if (!isAdmin()) { return; }\n", ""]],
  // the Executive deck's hashes change (T9)
  "executive-deck-changed": [[DECK, "    hash: function (n) { return \"#\" + n; },\n", "    hash: function (n) { return \"#deck-\" + n; },\n"]],
  // new code writes markup (T8)
  "innerHTML-in-new-code": [[CC, "        function clear(node) { while (node && node.firstChild) { node.removeChild(node.firstChild); } }\n",
    "        function clear(node) { if (node) { node.innerHTML = \"\"; } }\n"]],
  // ── Nov 10 2026, real-browser fix and essentials ──
  // the deck's [hidden] override removed, so .bf-panel and .cc-panel ul show every panel and fold again (T11)
  "hidden-overridden": [[DASH, "#ccDeck [hidden]{display:none !important}\n", ""]],
  // a tab press no longer hides the other panels (T2)
  "panels-all-visible": [[TABS_JS, "        if (panel) panel.hidden = !on;\n", "        if (panel) panel.hidden = false;\n"]],
  // a fold starts open (T4, T6)
  "fold-starts-open": [[CC, "            target.hidden = true;\n", ""]],
  // the held sender's reasons back on Command (T5)
  "email-sender-on-command": [[CC, "            if (p.count === 0 && f.count === 0) {\n",
    "            if (d.email_sender && d.email_sender.blocked_by.length) { out.appendChild(line(\"Email sender: sequence mail is held\")); }\n            if (p.count === 0 && f.count === 0) {\n"]],
  // the sales dry-run sentence back in Activity (T10)
  "dry-run-sentence-shown": [[CC, "            var runs = d.newest_runs_20.slice(0, CC_SHOW.runsMore);\n",
    "            out.appendChild(line(\"Sales dry runs in the last 30 days, counted apart: \" + d.sales_dry_runs + \" — drafts that were never sent.\"));\n            var runs = d.newest_runs_20.slice(0, CC_SHOW.runsMore);\n"]],
  // "Active plans (0)" drawn with nothing under it (T5)
  "empty-heading-shown": [[CC, "            if (active.length) {\n                out.appendChild(el(\"div\", \"cc-sub\", \"Active plans (\" + active.length + \")\"));\n",
    "            out.appendChild(el(\"div\", \"cc-sub\", \"Active plans (\" + active.length + \")\"));\n            if (active.length) {\n"]],
  // "Articles: 0 in the last 30 days" while articles are listed (T5)
  "articles-zero-line-with-list": [[CC, "(d.content_published_30d.count > 0 ? d.content_published_30d.count + \" in the last 30 days\" : \"\")",
    "(d.content_published_30d.count + \" in the last 30 days\")"]],
  // the pricing note printed under the spend line instead of in its tooltip (T6, T10)
  "pricing-note-inline": [[CC, "                spend.title = note.filter(Boolean).join(\" \");\n                out.appendChild(spend);\n",
    "                out.appendChild(spend);\n                out.appendChild(line(note.filter(Boolean).join(\" \"), \"cc-muted\"));\n"]],
  // "Show all jobs" open from the start (T6)
  "jobs-list-open": [[CC, "            out.appendChild(toggle(\"Show all jobs (\" + d.job_runs.length + \")\", all));\n",
    "            out.appendChild(toggle(\"Show all jobs (\" + d.job_runs.length + \")\", all));\n            all.hidden = false;\n"]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));
if (MUTATE && !MUTATIONS[MUTATE]) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }

const lf = t => t.replace(/\r\n/g, "\n");
const FILES = {};
[DASH, EXEC, CC, TABS_JS, DECK, UI_CSS].forEach(f => {
  const p = path.join(FRONTEND, f);
  if (!fs.existsSync(p)) { console.error("Frontend file not found: " + p + " (set BIZFORCE_FRONTEND_DIR)."); process.exit(2); }
  FILES[f] = lf(fs.readFileSync(p, "utf8"));
});
if (MUTATE) {
  for (const [file, from, to] of MUTATIONS[MUTATE]) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}
const BASE_DASH = lf(execSync("git show " + BASELINE + ":" + DASH, { cwd: FRONTEND, maxBuffer: 1 << 27 }).toString("utf8"));

let JSDOM;
try { ({ JSDOM } = require("jsdom")); } catch (e) { console.log("    FAIL  jsdom could not be loaded: " + e.message); process.exit(1); }

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined && detail !== "" ? "  [" + String(detail).slice(0, 500) + "]" : "")); }
}
process.on("unhandledRejection", e => check("no page request is left unhandled", false, (e && e.message) || e));

/* ── the fixtures ── */
const NOW = Date.now();
const ago = h => new Date(NOW - h * 3600000).toISOString();
const uid = n => "aaaaaaaa-0000-4000-8000-" + String(n).padStart(12, "0");
const HOSTILE = "<img src=x id=ccHostile>";
const PRICING_NOTE = "Figures are estimates from token counts at list prices.";

function bigBody(o) {
  o = o || {};
  const plan = (n, status, hoursAgo) => ({ id: uid(5000 + n), goal: "Plan goal " + n, status, created_at: ago(hoursAgo),
    assignments: [{ id: 1, agent: "social", tool: "calendar", task: "Step one of plan " + n, is_dispatchable: true, latest_dispatch: "not dispatched" }] });
  const runs = []; for (let i = 0; i < 200; i++) runs.push({ id: uid(1000 + i), agent_type: i % 2 ? "seo" : "social", task_type: "general", status: "completed", created_at: ago(i) });
  const active = []; for (let i = 0; i < 50; i++) active.push(plan(i, "processing", i + 1));
  const past = []; for (let i = 0; i < 20; i++) past.push({ id: uid(6000 + i), goal: "Past plan " + i, status: "completed", created_at: ago(24 * (30 + i)), finished_at: ago(24 * (20 + i)), finished_from: "runs" });
  const social = []; for (let i = 0; i < 20; i++) social.push({ id: uid(7000 + i), status: i < 12 ? "draft" : "posted", platform: "bluesky", preview: "Social draft " + i, created_at: ago(i) });
  const articles = []; for (let i = 0; i < 20; i++) articles.push({ id: uid(8000 + i), title: "Article " + i, status: "published", published_at: ago(i), created_at: ago(i + 1) });
  const proposals = []; for (let i = 0; i < 7; i++) proposals.push({ title: i === 0 ? HOSTILE : "Proposal " + i, agent_type: "social", created_at: ago(i) });
  const failed = []; for (let i = 0; i < 9; i++) failed.push({ id: uid(9000 + i), agent_type: "seo", task_type: "audit", created_at: ago(i) });
  const verdicts = [], jobRuns = [];
  for (let h = 0; h < 24; h++) {
    const name = "hourly_triggers_h" + String(h).padStart(2, "0");
    const late = !o.healthy && h === 5;
    verdicts.push({ job_name: name, cadence: "hourly", on_time: !late, reason: late ? "late: it has not finished within its hourly schedule" : null });
    jobRuns.push({ job_name: name, last_run_on: "2026-11-10", finished_at: ago(1), last_error: null });
  }
  for (let i = 0; i < 16; i++) {
    const name = "daily_job_" + String(i).padStart(2, "0");
    const bad = !o.healthy && i === 3;
    verdicts.push({ job_name: name, cadence: "daily", on_time: !bad, reason: bad ? "the last run failed" : null });
    jobRuns.push({ job_name: name, last_run_on: "2026-11-10", finished_at: ago(2), last_error: bad ? "the store answered 500" : null });
  }
  const body = {
    generated_at: new Date(NOW).toISOString(), chaining_on: true,
    needs_you: { ok: true, data: { pending_proposals: { count: 7, rows: proposals }, failed_runs_7d: { count: 9, rows: failed }, email_sender: { blocked_by: o.blocked ? ["enabled"] : [] } } },
    plans: { ok: true, data: [plan(100, "completed", 30), plan(101, "completed", 24 * 20)] },
    plan_lists: { ok: true, data: { active, past_count: 37, past_after_days: 14, past_latest: past } },
    activity: { ok: true, data: { counts_7d: { seo: { completed: 40, failed: 2 }, social: { completed: 60 }, store: {} }, newest_runs: runs.slice(0, 10), newest_runs_20: runs, sales_dry_runs: 4 } },
    autopilot: { ok: true, data: {
      autonomy: [{ agent_type: "seo", enabled: true, updated_at: ago(5) }, { agent_type: "social", enabled: true, updated_at: ago(6) },
        { agent_type: "store", enabled: false, updated_at: ago(7) }, { agent_type: "email", enabled: false, updated_at: ago(8) }, { agent_type: "ads", enabled: false, updated_at: ago(9) }],
      schedules: [{ agent_type: "seo", task_type: "audit", cadence: "weekly", hour_utc: 9, enabled: true, last_run_on: "2026-11-09" },
        { agent_type: "store", task_type: "sync", cadence: "daily", hour_utc: 4, enabled: true, last_run_on: null }] } },
    outbound: { ok: true, data: { email_sequences: [], social_drafts_by_status: { draft: 12, posted: 8 }, content_published_30d: { count: 20 }, social_latest: social, articles_latest: articles } },
    spend: { ok: true, data: { usd: 12.5, monthly_cap_usd: 60, resets_at: "2026-12-01T00:00:00.000Z", note: PRICING_NOTE } },
    usage: { ok: true, data: { model_calls_today: 41, model_calls_daily_cap: 250, model_calls_unavailable: null, subscription_active: true } }
  };
  if (o.admin !== false) body.platform = { ok: true, data: { job_runs: jobRuns, jobs_on_time: verdicts, job_cadence: {},
    radar_status: [{ source: "news", last_tick_finished_at: ago(1), last_outcome: "ok", last_error: null }], ceiling: { spent_usd: 3, cap_usd: 50 } } };
  return body;
}
function emptyBody() {
  return {
    generated_at: new Date(NOW).toISOString(), chaining_on: true,
    needs_you: { ok: true, data: { pending_proposals: { count: 0, rows: [] }, failed_runs_7d: { count: 0, rows: [] }, email_sender: { blocked_by: [] } } },
    plans: { ok: true, data: [] },
    plan_lists: { ok: true, data: { active: [], past_count: 0, past_after_days: 14, past_latest: [] } },
    activity: { ok: true, data: { counts_7d: {}, newest_runs: [], newest_runs_20: [], sales_dry_runs: 0 } },
    autopilot: { ok: true, data: { autonomy: [{ agent_type: "seo", enabled: false, updated_at: ago(5) }], schedules: [] } },
    outbound: { ok: true, data: { email_sequences: [], social_drafts_by_status: {}, content_published_30d: { count: 0 }, social_latest: [], articles_latest: [] } },
    spend: { ok: true, data: { usd: 0, monthly_cap_usd: 60 } },
    usage: { ok: true, data: { model_calls_today: 0, model_calls_daily_cap: 250, model_calls_unavailable: null, subscription_active: true } }
  };
}

/* ── one page in jsdom ── */
const settle = async (n) => { for (let i = 0; i < (n || 12); i++) await new Promise(r => setImmediate(r)); };
const stripScripts = html => html.replace(/<script[\s\S]*?<\/script>/g, "");

async function mountDash(o) {
  o = o || {};
  const dom = new JSDOM(stripScripts(FILES[DASH]), { url: "https://bizforceai.com/dashboard.html" + (o.hash || ""), runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window;
  w.HTMLElement.prototype.scrollIntoView = function () {};
  w.localStorage.setItem("bf_token", "check-token");
  if (o.session) w.sessionStorage.setItem("bf_cc_tab", o.session);
  if (o.brokenSession) Object.defineProperty(w, "sessionStorage", { get() { throw new Error("blocked"); } });
  const calls = [];
  const bodies = o.bodies || [bigBody(o)];
  w.fetch = (u, init) => {
    calls.push({ url: String(u), method: (init && init.method) || "GET" });
    const b = bodies[Math.min(calls.filter(c => /\/api\/command-center$/.test(c.url)).length - 1, bodies.length - 1)];
    return Promise.resolve({ ok: true, status: 200, json: async () => JSON.parse(JSON.stringify(b)), text: async () => JSON.stringify(b) });
  };
  w.eval(FILES[TABS_JS]);
  w.eval(FILES[CC]);
  // The dashboard's own Agent Memory toggle, as dashboard.html wires it.
  const toggle = /    var memoryToggle = document\.getElementById\("toggleAgentMemory"\);[\s\S]*?\n    }\n/.exec(FILES[DASH]);
  if (toggle) w.eval(toggle[0]);
  await settle();
  const d = w.document;
  const $ = id => d.getElementById(id);
  const ccCalls = () => calls.filter(c => /\/api\/command-center$/.test(c.url)).length;
  const open = async name => { $("ccTab-" + name).click(); await settle(4); };
  const key = async (name, k) => { $("ccTab-" + name).dispatchEvent(new w.KeyboardEvent("keydown", { key: k, bubbles: true })); await settle(4); };
  const current = () => { const on = [...d.querySelectorAll("[data-cc-tab]")].filter(t => t.getAttribute("aria-selected") === "true"); return on.length === 1 ? on[0].getAttribute("data-cc-tab") : on.length; };
  const text = id => ($(id) ? $(id).textContent.replace(/\s+/g, " ").trim() : null);
  return { w, d, $, calls, ccCalls, open, key, current, text };
}

async function mountExec(o) {
  o = o || {};
  const dom = new JSDOM(stripScripts(FILES[EXEC]), { url: "https://bizforceai.com/executive-agent.html" + (o.hash || ""), runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window;
  w.HTMLElement.prototype.scrollIntoView = function () {};
  w.localStorage.setItem("bf_token", "check-token");
  if (o.tab) w.localStorage.setItem("bf_exec_tab", o.tab);
  const calls = [];
  w.fetch = (u) => {
    calls.push(String(u));
    const p = new URL(String(u)).pathname;
    const b = p === "/api/command-center" ? bigBody() : p === "/api/ai/tasks" ? { tasks: [] } : {};
    return Promise.resolve({ ok: true, status: 200, json: async () => JSON.parse(JSON.stringify(b)), text: async () => JSON.stringify(b) });
  };
  w.eval(FILES[TABS_JS]);
  w.eval(FILES[CC]);
  w.eval(FILES[DECK]);
  await settle();
  const d = w.document;
  const current = () => { const on = [...d.querySelectorAll("[data-deck-tab]")].filter(t => t.getAttribute("aria-selected") === "true"); return on.length === 1 ? on[0].getAttribute("data-deck-tab") : on.length; };
  return { w, d, calls, current };
}

(async () => {
  /* ── T1. the top half ── */
  console.log("\n══ T1. everything around the Command Center is unchanged ══");
  const cur = FILES[DASH];
  const baseTop = BASE_DASH.slice(0, BASE_DASH.indexOf(CC_COMMENT));
  check("dashboard.html above the Command Center is byte for byte " + BASELINE + "'s (" + baseTop.length + " characters)",
    baseTop.length > 1000 && cur.slice(0, cur.indexOf(CC_COMMENT)) === baseTop, cur.slice(0, cur.indexOf(CC_COMMENT)).length + " vs " + baseTop.length);
  const memA = BASE_DASH.indexOf("<section id=\"agentMemorySection\""), memB = BASE_DASH.indexOf("</section>", memA) + "</section>".length;
  const baseMemory = BASE_DASH.slice(memA, memB), baseRest = BASE_DASH.slice(memB);
  check("everything after the Command Center and Agent Memory is byte for byte " + BASELINE + "'s", baseRest.length > 1000 && cur.endsWith(baseRest));
  check("the Agent Memory markup is byte for byte " + BASELINE + "'s, once", cur.split(baseMemory).length === 2);
  check("the heading, the Read stamp and Refresh are kept", /<h2 class="bf-section-title">Command Center<\/h2>/.test(cur) && /id="ccStatus">Loading…</.test(cur) && /id="ccRefresh">Refresh</.test(cur));
  check("bf-tabs.js loads before the section and bf-command-center.js right after it",
    cur.indexOf("<script src=\"/scripts/bf-tabs.js\"></script>") !== -1 && cur.indexOf("<script src=\"/scripts/bf-tabs.js\"></script>") < cur.indexOf("<section id=\"commandCenterSection\"") &&
    cur.indexOf("</section>\n" + CC_TAG) !== -1);

  /* ── T2. the tabs ── */
  console.log("\n══ T2. the tabs: roles, keys, the address and the session ══");
  let p = await mountDash();
  const TABS = ["command", "plans", "activity", "autopilot", "outbound", "system", "memory"];
  const list = p.d.querySelector("#ccDeck [role=tablist]");
  const tabs = [...p.d.querySelectorAll("#ccDeck [data-cc-tab]")];
  check("one tablist of seven tabs in order: Command, Plans, Activity, Autopilot, Outbound, System, Memory",
    !!list && tabs.length === 7 && tabs.map(t => t.getAttribute("data-cc-tab")).join() === TABS.join() &&
    tabs.map(t => t.textContent).join() === "Command,Plans,Activity,Autopilot,Outbound,System,Memory", tabs.map(t => t.textContent).join());
  check("each tab is role=tab with aria-controls naming its tabpanel, which names it back",
    tabs.length === 7 && tabs.every(t => t.getAttribute("role") === "tab" && t.parentNode === list && (() => {
      const panel = p.$(t.getAttribute("aria-controls"));
      return panel && panel.getAttribute("role") === "tabpanel" && panel.getAttribute("aria-labelledby") === t.id;
    })()));
  check("with no address and no session, Command is open and the only panel shown",
    p.current() === "command" && TABS.every(n => p.$("ccPanel-" + n).hidden === (n !== "command")) && p.$("ccTab-command").getAttribute("tabindex") === "0");
  await p.key("command", "ArrowRight");
  check("Right moves to Plans and focuses it", p.current() === "plans" && p.d.activeElement === p.$("ccTab-plans"));
  await p.key("plans", "End");
  check("End goes to Memory", p.current() === "memory");
  await p.key("memory", "ArrowRight");
  check("Right from Memory wraps to Command", p.current() === "command");
  await p.key("command", "ArrowLeft");
  check("Left from Command wraps to Memory", p.current() === "memory");
  await p.key("memory", "Home");
  check("Home goes to Command", p.current() === "command");
  await p.open("activity");
  check("a tab pressed puts #cc-<tab> in the address", p.w.location.hash === "#cc-activity", p.w.location.hash);
  check("the tab is kept in sessionStorage bf_cc_tab", p.w.sessionStorage.getItem("bf_cc_tab") === "activity", p.w.sessionStorage.getItem("bf_cc_tab"));
  check("and never in localStorage (no bf_cc_tab, no new key)", p.w.localStorage.getItem("bf_cc_tab") === null && p.w.localStorage.length === 1,
    JSON.stringify(Object.keys(p.w.localStorage)));
  p.w.location.hash = "#cc-outbound";
  await settle(6);
  check("hashchange to #cc-outbound opens Outbound", p.current() === "outbound");
  p = await mountDash({ hash: "#cc-system" });
  check("an address of #cc-system opens System", p.current() === "system");
  p = await mountDash({ session: "autopilot" });
  check("with no address, the session's tab opens (Autopilot)", p.current() === "autopilot");
  p = await mountDash({ session: "bogus" });
  check("an unknown remembered tab falls back to Command", p.current() === "command");
  p = await mountDash({ brokenSession: true });
  check("a store that throws still opens Command", p.current() === "command" && /Proposals waiting/.test(p.text("ccCommand")));
  check("the tab row scrolls sideways on a narrow screen (deck-tabs-scroll, overflow-x auto, no wrap)",
    list && list.classList.contains("deck-tabs-scroll") && /\.deck-tabs\.deck-tabs-scroll \{ flex-wrap: nowrap; overflow-x: auto;/.test(FILES[TABS_JS]) &&
    /\.deck-tabs\.deck-tabs-scroll \.deck-tab \{ flex: 0 0 auto; white-space: nowrap; \}/.test(FILES[TABS_JS]));

  /* ── T3. one fetch ── */
  console.log("\n══ T3. one read for every tab ══");
  p = await mountDash();
  check("Command is drawn at once; the other tabs wait to be opened",
    /Proposals waiting/.test(p.text("ccCommand")) && p.text("ccPlansTab") === "Loading…" && p.text("ccActivityTab") === "Loading…" && p.text("ccSystemTab") === "Loading…");
  for (const n of TABS) await p.open(n);
  check("opening all seven tabs reads GET /api/command-center once", p.ccCalls() === 1 && p.calls.length === 1, p.calls.map(c => c.url).join(" | "));
  // NAMED (Nov 10 2026, real-browser fix and essentials): BEFORE /Newest runs/ in Activity; AFTER /Last 7 days:/ (the heading is gone).
  check("each tab was drawn when opened", /Active plans/.test(p.text("ccPlansTab")) && /Last 7 days:/.test(p.text("ccActivityTab")) && /Automatic/.test(p.text("ccAutopilotTab")) &&
    /Social posts/.test(p.text("ccOutboundTab")) && /Spend/.test(p.text("ccSystemTab")));
  check("the Read stamp is set from the read", /^Read /.test(p.text("ccStatus")), p.text("ccStatus"));
  p.$("ccRefresh").click();
  await settle();
  check("Refresh reads once more and redraws the open tab", p.ccCalls() === 2 && /Agent Memory/.test(p.text("ccPanel-memory")));

  /* ── T4. caps and folds ── */
  console.log("\n══ T4. caps and folds over large fixtures ══");
  p = await mountDash();
  const cmd = p.$("ccCommand");
  const cmdLists = [...cmd.querySelectorAll("ul")];
  /* NAMED BEFORE → AFTER (Nov 10 2026, real-browser fix and essentials): BEFORE "Proposals waiting for you (7)" with
     "and 4 more on Proposals", and "Runs that failed in the last 7 days (9)"; AFTER "Proposals waiting (7)" and
     "Failed in the last 7 days (9)", each with its 3 newest and no "more" line. */
  check("Command: \"Proposals waiting (7)\" with the 3 newest, linked, and no other line", /^Proposals waiting \(7\)$/.test(cmd.querySelector(".cc-sub").textContent) && cmdLists[0] &&
    cmdLists[0].querySelectorAll("li").length === 3 && cmdLists[0].querySelectorAll("a[href='proposals.html']").length === 3 && !/more/.test(p.text("ccCommand")) &&
    [...cmd.children].map(c => c.tagName).join() === "DIV,UL,DIV,UL", [...cmd.children].map(c => c.tagName).join());
  check("Command: \"Failed in the last 7 days (9)\" with the 3 newest, each to run.html", /Failed in the last 7 days \(9\)/.test(p.text("ccCommand")) && cmdLists[1] &&
    [...cmdLists[1].querySelectorAll("a")].map(a => a.getAttribute("href")).join() === [0, 1, 2].map(i => "run.html?id=" + uid(9000 + i)).join());
  check("Command: no email sender line", !/Email/.test(p.text("ccCommand")));
  const chips = [...p.$("ccChips").querySelectorAll(".cc-chip")].map(c => c.textContent);
  check("Command chips: model calls, subscription, spend and the admin's platform ceiling",
    chips.join(" | ") === "Model calls today: 41 of 250 | Subscription active | Spend this month: $12.50 of $60.00 | Platform ceiling today: $3.00 of $50.00", chips.join(" | "));
  await p.open("plans");
  const plansTab = p.$("ccPlansTab");
  const activeCards = [...plansTab.querySelectorAll(".cc-plan")].filter(c => /Plan goal \d+$/.test(c.querySelector(".cc-plan-head strong").textContent) &&
    Number(/\d+$/.exec(c.querySelector(".cc-plan-head strong").textContent)[0]) < 50);
  check("Plans: 10 of 50 active plans", /Active plans \(10\)/.test(p.text("ccPlansTab")) && activeCards.length === 10, activeCards.length);
  check("Plans: steps are behind \"Show steps\", closed", activeCards.length && activeCards.every(c => {
    const b = c.querySelector("button.cc-toggle"), st = c.querySelector(".cc-steps");
    return b && b.textContent === "Show steps" && b.getAttribute("aria-expanded") === "false" && st.hidden && st.textContent === "";
  }));
  activeCards[0].querySelector("button.cc-toggle").click();
  check("\"Show steps\" opens the plan's steps (the shared renderer's)", !activeCards[0].querySelector(".cc-steps").hidden &&
    /Step one of plan 0/.test(activeCards[0].querySelector(".cc-steps").textContent) && activeCards[0].querySelector("button.cc-toggle").textContent === "Hide steps");
  // NAMED (Nov 10 2026, real-browser fix and essentials): BEFORE a "Recent plans" list of the last 14 days; AFTER none (active and past only).
  check("Plans: only active plans and the past fold (no recent-plans list)", !/Plan goal 10[01]|Recent plans/.test(p.text("ccPlansTab")));
  const pastToggle = [...plansTab.querySelectorAll("button")].find(b => /^Past plans/.test(b.textContent));
  const pastFold = p.$("ccPastPlans");
  check("Plans: \"Past plans (37)\" is folded", pastToggle && pastToggle.textContent === "Past plans (37)" && pastToggle.getAttribute("aria-expanded") === "false" && pastFold && pastFold.hidden);
  pastToggle.click();
  check("opened: the 5 newest past plans and a link to executive-agent.html#plans", !pastFold.hidden && pastFold.querySelectorAll("li").length === 5 &&
    !!pastFold.querySelector("a[href='executive-agent.html#plans']") && /Past plan 0/.test(pastFold.textContent) && !/Past plan 5/.test(pastFold.textContent));
  await p.open("activity");
  const act = p.$("ccActivityTab");
  // NAMED (Nov 10 2026, real-browser fix and essentials): BEFORE one list item per agent with its statuses; AFTER one line.
  check("Activity: \"Last 7 days:\" one line of counts, agents with runs only (store has none)", act.firstChild && act.firstChild.tagName === "P" &&
    act.firstChild.textContent === "Last 7 days: seo 42, social 60", act.firstChild && act.firstChild.textContent);
  const runRows = () => [...act.querySelectorAll("a[href^='run.html']")].filter(a => !a.closest("[hidden]"));
  check("Activity: the 5 newest runs of 200", runRows().length === 5 && runRows()[0].getAttribute("href") === "run.html?id=" + uid(1000), runRows().length);
  const more = [...act.querySelectorAll("button")].find(b => b.textContent === "Show more");
  check("Activity: \"Show more\" is there", !!more && more.getAttribute("aria-expanded") === "false");
  if (more) more.click();
  check("\"Show more\" shows 20 in all, never more", runRows().length === 20 && more.textContent === "Show fewer", runRows().length);
  check("Activity: \"Full history\" links to executive-agent.html#history", !!act.querySelector("a[href='executive-agent.html#history']") &&
    act.querySelector("a[href='executive-agent.html#history']").textContent === "Full history");
  await p.open("outbound");
  const ob = p.$("ccOutboundTab");
  /* NAMED BEFORE → AFTER (Nov 10 2026, real-browser fix and essentials): BEFORE a heading, a status line and a list per
     type; AFTER one line per type, and the 3 latest of each behind one "Show latest" fold. */
  const obLines = [...ob.children].filter(c => c.tagName === "P").map(c => c.textContent);
  check("Outbound: one line per type with something in it", obLines.length === 2 && obLines[0] === "Social posts: 12 draft, 8 posted" &&
    /^Articles: 20 in the last 30 days, latest \S+$/.test(obLines[1]), obLines.join(" | "));
  const latestFold = p.$("ccOutboundLatest"), latestBtn = [...ob.querySelectorAll("button")].find(b => b.textContent === "Show latest");
  const obLists = latestFold ? [...latestFold.querySelectorAll("ul")] : [];
  check("Outbound: \"Show latest\" is folded", !!latestBtn && latestBtn.getAttribute("aria-expanded") === "false" && latestFold.hidden);
  if (latestBtn) latestBtn.click();
  check("opened: the 3 latest social posts and the 3 latest articles", !!latestFold && !latestFold.hidden && obLists.length === 2 && obLists[0].querySelectorAll("li").length === 3 &&
    /Social draft 0/.test(obLists[0].textContent) && !/Social draft 3/.test(obLists[0].textContent) && obLists[1].querySelectorAll("li").length === 3 && /Article 0/.test(obLists[1].textContent));

  /* ── T5. empty states ── */
  console.log("\n══ T5. the empty states, word for word ══");
  p = await mountDash({ bodies: [emptyBody()] });
  check("Command: \"Nothing needs you right now.\"", p.text("ccCommand") === "Nothing needs you right now.", p.text("ccCommand"));
  check("Command: no Platform chip for a member", ![...p.$("ccChips").querySelectorAll(".cc-chip")].some(c => /Platform/.test(c.textContent)));
  await p.open("autopilot");
  const apLines = [...p.$("ccAutopilotTab").children].map(c => c.textContent);
  check("Autopilot: \"No agents run automatically.\" and \"1 agent manual\"", apLines.join(" | ") === "No agents run automatically. | 1 agent manual", apLines.join(" | "));
  await p.open("outbound");
  check("Outbound: with nothing sent, \"Nothing has gone out yet.\"", p.text("ccOutboundTab") === "Nothing has gone out yet.", p.text("ccOutboundTab"));
  await p.open("plans");
  check("Plans: \"No executive plans yet.\" and the \"Make a plan\" link", p.text("ccPlansTab") === "No executive plans yet. Make a plan" &&
    !!p.$("ccPlansTab").querySelector("a[href='executive-agent.html#tool=plan']"), p.text("ccPlansTab"));
  await p.open("activity");
  // NAMED (Nov 10 2026, real-browser fix and essentials): BEFORE also "No runs yet." under a "Newest runs" heading; AFTER the one line and the link.
  const emptyAct = [...p.$("ccActivityTab").children].map(c => c.textContent);
  check("Activity: \"No runs in the last 7 days.\" and \"Full history\", nothing else", emptyAct.join(" | ") === "No runs in the last 7 days. | Full history", emptyAct.join(" | "));
  p = await mountDash({ bodies: [(() => { const b = bigBody(); b.plan_lists.data.active = []; b.outbound.data.content_published_30d.count = 0;
    b.outbound.data.social_drafts_by_status = {}; b.outbound.data.social_latest = []; return b; })()] });
  await p.open("plans");
  check("Plans: with no active plan, no \"Active plans\" heading, only \"Past plans (37)\"", !/Active plans/.test(p.text("ccPlansTab")) && /^Past plans \(37\)/.test(p.text("ccPlansTab")),
    p.text("ccPlansTab"));
  await p.open("outbound");
  const zeroLines = [...p.$("ccOutboundTab").children].filter(c => c.tagName === "P").map(c => c.textContent);
  check("Outbound: articles listed with none in the last 30 days: \"Articles: latest <date>\", no zero count", zeroLines.length === 1 && /^Articles: latest \S+$/.test(zeroLines[0]) &&
    !/\b0 (articles|in the last)/.test(p.text("ccOutboundTab")), zeroLines.join(" | "));
  for (const n of TABS) await p.open(n);
  // Every heading has something under it: the next element is not a heading and not empty.
  const emptyHeads = [...p.d.querySelectorAll("#ccDeck .cc-sub")].filter(h => { const n = h.nextElementSibling; return !n || n.classList.contains("cc-sub") || !n.textContent.trim(); });
  check("no heading with nothing under it, on any tab", emptyHeads.length === 0, emptyHeads.map(h => h.textContent).join(", "));
  p = await mountDash();
  await p.open("autopilot");
  const ap = p.text("ccAutopilotTab");
  check("Autopilot: the Automatic-on agents one line each, with only their schedules", p.$("ccAutopilotTab").querySelectorAll("ul")[0].querySelectorAll("li").length === 2 &&
    /seo: Automatic on/.test(ap) && /social: Automatic on/.test(ap) && /seo · audit · weekly at 9:00 UTC/.test(ap) && !/sync/.test(ap) && !p.$("ccAutopilotTab").querySelector(".cc-sub"), ap);
  check("Autopilot: the manual ones as a count only (\"3 agents manual\"), not by name", /3 agents manual$/.test(ap) && !/store|email|ads/.test(ap), ap);
  await p.open("outbound");
  check("Outbound: an empty type (email sequences) is left out", !/Email sequences/.test(p.text("ccOutboundTab")));
  /* NAMED BEFORE → AFTER (Nov 10 2026, real-browser fix and essentials): BEFORE the held sender's reasons on Command;
     AFTER one short "Email sending: held (…)" line on an admin's System tab, never on Command. */
  p = await mountDash({ blocked: true });
  check("Command: no email sender text, even while sending is held", !/Email|sequence mail|held/.test(p.text("ccCommand")), p.text("ccCommand"));
  await p.open("system");
  check("admin System: \"Email sending: held (switched off on the server)\" while held", [...p.$("ccSystemTab").children].some(c => c.textContent === "Email sending: held (switched off on the server)"),
    p.text("ccSystemTab"));
  p = await mountDash({ blocked: true, admin: false });
  await p.open("system");
  check("member System: no email sending line", !/Email/.test(p.text("ccSystemTab")), p.text("ccSystemTab"));
  p = await mountDash();
  await p.open("system");
  check("admin System: no email sending line while it is not held", !/Email/.test(p.text("ccSystemTab")), p.text("ccSystemTab"));

  /* ── T6. System ── */
  console.log("\n══ T6. System: spend for everyone, jobs for an admin ══");
  p = await mountDash();
  await p.open("system");
  const sys = p.$("ccSystemTab");
  const visible = node => [...node.querySelectorAll("li")].filter(l => !l.closest("[hidden]"));
  /* NAMED BEFORE → AFTER (Nov 10 2026, real-browser fix and essentials): BEFORE the shared renderSpend's three lines
     (figures, the pricing note, "Resets …"); AFTER one line, the note as its title tooltip. */
  const resetsDay = new Date("2026-12-01T00:00:00.000Z").toLocaleDateString();
  check("admin: \"Spend: $12.50 of $60.00 this month (resets <date>)\" as one line, the pricing note as its tooltip",
    p.$("ccSystemSpend") && p.$("ccSystemSpend").tagName === "P" && p.text("ccSystemSpend") === "Spend: $12.50 of $60.00 this month (resets " + resetsDay + ")" &&
    p.$("ccSystemSpend").title === PRICING_NOTE && p.$("ccSystemTab").textContent.indexOf(PRICING_NOTE) === -1, p.text("ccSystemSpend") + " / " + (p.$("ccSystemSpend") || {}).title);
  check("admin: one health line, \"2 of 17 background jobs need attention\" (the 24 hourly triggers one job)", /2 of 17 background jobs need attention/.test(p.text("ccSystemTab")), p.text("ccSystemTab"));
  check("admin: only the job that needs attention is listed", visible(sys).length === 1 && /^daily_job_03: the last run failed$/.test(visible(sys)[0].textContent),
    visible(sys).map(l => l.textContent).join(" | "));
  check("admin: \"Hourly triggers: 23 of 24 on time\" as one row", /Hourly triggers: 23 of 24 on time/.test(p.text("ccSystemTab")) && !/hourly_triggers_h05/.test(visible(sys).map(l => l.textContent).join(" ")));
  check("admin: the radar heartbeat in one line", /Radar heartbeat: news last tick/.test(p.text("ccSystemTab")));
  const allJobs = [...sys.querySelectorAll("button")].find(b => /^Show all jobs/.test(b.textContent));
  check("admin: \"Show all jobs (40)\" is folded", allJobs && allJobs.textContent === "Show all jobs (40)" && p.$("ccAllJobs").hidden);
  if (allJobs) allJobs.click();
  check("\"Show all jobs\" lists all 40", !p.$("ccAllJobs").hidden && p.$("ccAllJobs").querySelectorAll(":scope > li").length === 40);
  p = await mountDash({ healthy: true });
  await p.open("system");
  check("healthy: \"All 17 background jobs ran on time\" and nothing listed", /All 17 background jobs ran on time/.test(p.text("ccSystemTab")) && visible(p.$("ccSystemTab")).length === 0 &&
    /Hourly triggers: 24 of 24 on time/.test(p.text("ccSystemTab")), visible(p.$("ccSystemTab")).map(l => l.textContent).join(" | "));
  p = await mountDash({ admin: false });
  await p.open("system");
  check("member: spend only, the one line (no jobs, no radar, no error)", p.$("ccSystemTab").children.length === 1 && /^Spend: \$12\.50 of \$60\.00 this month/.test(p.text("ccSystemTab")) &&
    !/background jobs|Radar|Hourly|Could not read/i.test(p.text("ccSystemTab")), p.text("ccSystemTab"));

  /* ── T7. Memory ── */
  console.log("\n══ T7. Agent Memory in its tab ══");
  p = await mountDash();
  const memSection = p.$("agentMemorySection");
  check("the Agent Memory section is inside the Memory tab, hidden until it is opened",
    memSection && memSection.closest("[role=tabpanel]") === p.$("ccPanel-memory") && p.$("ccPanel-memory").hidden);
  await p.open("memory");
  check("the Memory tab shows it with its filter, search, toggle and list",
    !p.$("ccPanel-memory").hidden && ["agentMemoryFilter", "agentMemorySearch", "toggleAgentMemory", "agentMemoryList"].every(i => p.$(i) && p.$("ccPanel-memory").contains(p.$(i))));
  p.$("toggleAgentMemory").click();
  check("\"View memories\" still opens the list there", memSection.classList.contains("is-memory-open") && p.$("toggleAgentMemory").textContent === "Hide memories");
  p = await mountDash({ hash: "#agentMemorySearch" });
  check("an in-page link to an element inside a tab opens that tab", p.current() === "memory");

  /* ── T8. textContent ── */
  console.log("\n══ T8. new DOM by textContent ══");
  const block = FILES[CC].slice(FILES[CC].indexOf("CC-TABS: THE DASHBOARD'S TABBED MODE"), FILES[CC].indexOf("/* ══ end CC-TABS ══ */"));
  check("the CC-TABS block writes no markup (no innerHTML, outerHTML or insertAdjacentHTML)", block.length > 5000 && !/innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(block));
  // NAMED (Nov 10 2026, real-browser fix and essentials): BEFORE two setPanel calls (renderPlans, renderSpend); AFTER one (the spend is a line now).
  check("its only HTML is the shared renderer's escaped output: setPanel with renderPlans",
    (block.match(/setPanel\(/g) || []).length === 1 && /setPanel\(steps\.id, renderPlans\(\[plan\]\)\)/.test(block));
  p = await mountDash();
  check("a proposal title with markup is shown as text", !p.$("ccHostile") && p.$("ccCommand").textContent.indexOf(HOSTILE) !== -1);

  /* ── T10. the removed sentences are nowhere on the dashboard ── */
  console.log("\n══ T10. only the essential lines ══");
  const REMOVED = [/dry runs?/i, /drafts that were never sent/, /Email sender/, /sequence mail is held/, /articles published in the last 30 days/, /Proposals waiting for you/,
    /Runs that failed in the last 7 days/, /Newest runs/, /Recent plans/, /and \d+ more/, /Resets /, new RegExp(PRICING_NOTE.replace(/\./g, "\\."))];
  for (const o of [{ blocked: true }, { blocked: true, admin: false }, { bodies: [emptyBody()] }]) {
    p = await mountDash(o);
    for (const n of TABS) await p.open(n);
    const all = p.d.body.textContent;
    const back = REMOVED.filter(r => r.test(all));
    check("no removed sentence anywhere on the dashboard (" + (o.bodies ? "empty" : o.admin === false ? "member" : "admin") + ", every tab drawn)", back.length === 0,
      back.map(String).join(", "));
  }

  /* ── T11. hidden means hidden (a static rule: jsdom applies no stylesheet) ── */
  console.log("\n══ T11. no display rule beats [hidden] in the deck ══");
  {
    const ccStyle = (/style\.textContent = ("(?:[^"\\]|\\.)*");/.exec(FILES[CC]) || [])[1];
    const tabsStyle = (/css\.textContent =\s*([\s\S]*?);\n/.exec(FILES[TABS_JS]) || [])[1];
    const sheets = {
      "css/bizforce-ui.css": FILES[UI_CSS],
      "dashboard.html style#ccTabsStyle": (/<style id="ccTabsStyle">([\s\S]*?)<\/style>/.exec(FILES[DASH]) || [])[1] || "",
      "bf-command-center.js style": ccStyle ? JSON.parse(ccStyle) : "",
      "bf-tabs.js style": tabsStyle ? tabsStyle.split("\n").map(l => (/"((?:[^"\\]|\\.)*)"/.exec(l) || [])[1] || "").map(t => JSON.parse('"' + t + '"')).join("") : ""
    };
    check("the four stylesheets were read", Object.values(sheets).every(t => t.length > 50), Object.keys(sheets).filter(k => sheets[k].length <= 50).join(", "));
    const rules = [];
    for (const [name, css] of Object.entries(sheets)) {
      const flat = css.replace(/\/\*[\s\S]*?\*\//g, "").replace(/@media[^{]*\{([\s\S]*?\})\s*\}/g, "$1");
      for (const m of flat.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
        const d = /(?:^|;)\s*display\s*:\s*([^;!]+?)\s*(!important)?\s*(?:;|$)/.exec(m[2]);
        if (d) rules.push({ sheet: name, selector: m[1].trim(), value: d[1].trim(), important: !!d[2] });
      }
    }
    p = await mountDash();
    for (const n of TABS) await p.open(n);
    const actBtn = [...p.$("ccActivityTab").querySelectorAll("button")].find(b => b.textContent === "Show more"); void actBtn;
    // Every element the deck hides: each panel (all hidden but one, so look at the markup) and each fold.
    const targets = TABS.map(n => p.$("ccPanel-" + n)).concat(["ccMoreRuns", "ccAllJobs", "ccPastPlans", "ccOutboundLatest"].map(i => p.$(i)).filter(Boolean),
      [...p.d.querySelectorAll("#ccDeck .cc-steps")]);
    const override = rules.find(r => r.sheet === "dashboard.html style#ccTabsStyle" && r.selector === "#ccDeck [hidden]" && r.value === "none" && r.important);
    const hits = [];
    rules.filter(r => r.value !== "none").forEach(r => r.selector.split(",").forEach(sel => {
      let matches = [];
      try { matches = targets.filter(t => t.matches(sel.trim())); } catch (e) { matches = []; }
      if (matches.length) hits.push({ rule: r.sheet + "  " + sel.trim() + " { display: " + r.value + (r.important ? " !important" : "") + " }", important: r.important, ids: matches.map(t => t.id) });
    }));
    check("the deck's own override is there: #ccDeck [hidden] { display: none !important }", !!override);
    check("every display rule that reaches a deck panel or fold is beaten by it (none is !important): " + hits.length + " found",
      !!override && hits.every(h => !h.important), hits.map(h => h.rule + " -> " + h.ids.join("/")).join(" | "));
    check("and the rules that DO reach them are the two that hid nothing before (.bf-panel, .cc-panel ul)",
      hits.some(h => /\.bf-panel /.test(h.rule + " ") && h.ids.indexOf("ccPanel-plans") !== -1) && hits.some(h => /\.cc-panel ul/.test(h.rule) && h.ids.indexOf("ccMoreRuns") !== -1),
      hits.map(h => h.rule).join(" | "));
    check("the shared tab stylesheet hides a hidden .deck-panel whatever its classes", /\.deck-panel\[hidden\] \{ display: none !important; \}/.test(sheets["bf-tabs.js style"]));
  }

  /* ── T9. the Executive deck ── */
  console.log("\n══ T9. the Executive deck on the shared component, unchanged ══");
  let e = await mountExec();
  const etabs = [...e.d.querySelectorAll("[data-deck-tab]")];
  check("six tabs: Command, Plans, Agents, Approvals, History, Settings", etabs.map(t => t.getAttribute("data-deck-tab")).join() === "command,plans,agents,approvals,history,settings");
  check("Command opens first", e.current() === "command");
  e.d.getElementById("deckTab-plans").click(); await settle(4);
  check("a tab pressed puts the plain hash in the address (#plans)", e.current() === "plans" && e.w.location.hash === "#plans", e.w.location.hash);
  check("and keeps it in localStorage bf_exec_tab, not sessionStorage", e.w.localStorage.getItem("bf_exec_tab") === "plans" && e.w.sessionStorage.length === 0);
  e.d.getElementById("deckTab-plans").dispatchEvent(new e.w.KeyboardEvent("keydown", { key: "End", bubbles: true })); await settle(4);
  check("End goes to Settings", e.current() === "settings");
  e.d.getElementById("deckTab-settings").dispatchEvent(new e.w.KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true })); await settle(4);
  check("Right wraps to Command", e.current() === "command");
  e.w.location.hash = "#history"; await settle(6);
  check("hashchange to #history opens History", e.current() === "history");
  e = await mountExec({ tab: "approvals" });
  check("the remembered tab opens with no address", e.current() === "approvals");
  e = await mountExec({ hash: "#tool=plan&prefill=Grow%20sales" });
  check("#tool=plan opens Command", e.current() === "command");
  check("the Executive page's Command Center is drawn the old way (no tabs, its own panels)",
    !e.d.querySelector("[data-cc-tab]") && /Proposals waiting for you/.test(e.d.getElementById("ccNeedsYou").textContent) && /Spend|\$12\.50/.test(e.d.getElementById("ccSpend").textContent));
  check("the deck's call: six tabs, \"#\" + name, localStorage bf_exec_tab",
    /tabs: TABS,\n/.test(FILES[DECK]) && /hash: function \(n\) \{ return "#" \+ n; \},/.test(FILES[DECK]) && /storage: \{ kind: "local", key: TAB_KEY \},/.test(FILES[DECK]) &&
    /var TAB_KEY = "bf_exec_tab";/.test(FILES[DECK]));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
