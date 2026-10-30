"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkExecutiveDeck — the Executive command deck (executive-agent.html,
   scripts/bf-exec-deck.js, with bf-hq.js, bf-command-center.js and
   agent-profile.js), one stats truth on all 18 agent pages, and the readable
   result in the deck's drawer and on run.html.

   Frontend "Executive command deck: six clear tabs, one command box, readable
   results; words and drawn icons instead of emojis" made the page one deck of
   six tabs (Command, Plans, Agents, Approvals, History, Settings), took out
   the duplicates (the agent panel's own launcher, Live Status and Task
   History; a second "Command Center" heading; the toolbar's Last run; the
   Command Center's plans panel beside the plan board), moved every agent
   page's figures onto /live, and gave stored runs a readable result.

   THE PAGES RUN IN JSDOM with their own scripts, in the page's own order, over
   answers built by lib/agentLive.js buildLive from fixture rows. No network,
   no model call, no database.

     D1  one command box, one Send, one voice button that only fills the box;
     D2  what 6bb046a's box did still holds: a typed task is one POST per Send,
         a plan one POST to the plan route with Horizon and Constraints shown
         only in "Make a plan", an acting tool never posts and points at its
         page, and a refusal says its name;
     D3  plans once: the Plans tab's board is the page's only plan view;
     D4  live state once: one shared live panel, no Live Status, no Task
         History list of the agent panel's own;
     D5  "Command Center" is a heading at most once;
     D6  the tabs: a tablist of six tabs with roles, aria-selected and
         aria-controls; Left, Right, Home and End; a hash route per tab; the
         last tab remembered on this device (bf_exec_tab); every in-page link,
         and every alert, lands on a tab or on an element inside one; the old
         #tool=plan link opens "Make a plan" with its goal and sends nothing;
     D7  History: dry runs left out, 10 a page, Prev and Next, each row opening
         the drawer, which reads the run by id and offers "Open full run";
     D8  one stats truth: on all 18 pages Agent Stats are /live's runs_7d,
         completed_7d and failed_7d, which count ai_tasks over 7 days with dry
         runs left out; no page reads ai_agents.tasks_completed or shows
         "Tasks Completed"; the weekday chart shows only with runs, else "No
         runs this week";
     D9  the readable result (drawer and run.html): a plain summary first,
         each entry a card of labelled rows, the provenance collapsed to one
         line that opens to the full notice, unchanged;
     D10 the rating: "Helpful" and "Not helpful" as drawn SVG icons
         (currentColor, aria-hidden) with their words visible, accessible
         names and aria-pressed; "Use this as an example" still there;
     D11 no emoji on the deck or in its tips, and config/brain.js's rule
         present (checkNoEmoji holds the rest).

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

const EXEC = "executive-agent.html", RUN = "run.html", AP = "scripts/agent-profile.js", HQ = "scripts/bf-hq.js", CC = "scripts/bf-command-center.js";
const DECK = "scripts/bf-exec-deck.js", PAYWALL = "scripts/bf-paywall.js", GUIDE = "scripts/termaximus-guide.js", SESSION = "scripts/bf-session.js";
const LIB = "lib/agentLive.js", BRAIN = "config/brain.js";
const AGENT_PAGES = ["ads-agent.html", "broker-agent.html", "community-agent.html", "email-agent.html", "etsy-agent.html", "executive-agent.html",
  "influencer-agent.html", "operations-agent.html", "publicist-agent.html", "rd-agent.html", "reputation-agent.html", "store-agent.html",
  "vertical-marketing-agent.html", "agents/analytics.html", "agents/content.html", "agents/sales.html", "agents/seo.html", "agents/social.html"];
const THUMB = String.fromCodePoint(0x1F44D);

const MUTATIONS = {
  // the agent panel's own launcher comes back beside the deck's box (D1)
  "second-command-box": [[EXEC, "  deck: true,\n", ""]],
  // the Command Center's plans panel back beside the plan board (D3)
  "plans-rendered-twice": [[EXEC, "              <div class=\"bf-card bf-panel cc-panel\"><h3>Agent activity</h3>",
    "              <div class=\"bf-card bf-panel cc-panel\"><h3>Executive plans</h3><div id=\"ccPlans\">Loading…</div></div>\n              <div class=\"bf-card bf-panel cc-panel\"><h3>Agent activity</h3>"]],
  // the live panel draws its Plans module on the deck too (D3)
  "live-plans-on-deck": [[AP, "    if (DECK && s && s.kind === \"executive\") draw = null;\n", ""]],
  // the stale counter shown again on an agent page (D8)
  "stale-counter-shown": [[EXEC, "             from /api/agents/<type>/live: ai_tasks, dry runs left out. */\n",
    "             from /api/agents/<type>/live: ai_tasks, dry runs left out. */\n          var liveStatsEl = liveStatsSlot();\n          if (liveStatsEl) {\n" +
    "            var tile1 = document.createElement(\"div\"); tile1.className = \"context-item\";\n            var label1 = document.createElement(\"label\"); label1.textContent = \"Tasks Completed\";\n" +
    "            var value1 = document.createElement(\"span\"); value1.textContent = String(agent.tasks_completed != null ? agent.tasks_completed : 0);\n" +
    "            tile1.appendChild(label1); tile1.appendChild(value1); liveStatsEl.appendChild(tile1);\n          }\n"]],
  // /live counts dry runs among an agent's runs (D8)
  "stats-count-dry-runs": [[LIB, "  return read.rows.filter(function (r) { return r && r.agent_type === type && r.status !== \"dry_run\"; });\n",
    "  return read.rows.filter(function (r) { return r && r.agent_type === type; });\n"]],
  // the provenance removed rather than collapsed (D9)
  "provenance-removed": [[AP, "      how ? '<details class=\"ap-read-how\"><summary>'", "      false ? '<details class=\"ap-read-how\"><summary>'"]],
  // the provenance open by default, so not collapsed (D9)
  "provenance-not-collapsed": [[AP, "      how ? '<details class=\"ap-read-how\"><summary>'", "      how ? '<details class=\"ap-read-how\" open><summary>'"]],
  // the summary dropped from the readable result (D9)
  "no-summary": [[AP, "      readSummaryOf(data, keys),\n", ""]],
  // an acting tool posted from the box (D2)
  "acting-tool-dispatched-from-box": [[HQ, "      if (acting) {\n        // Never from here: the page's own approval flow runs it.\n",
    "      if (acting) {\n        api(\"POST\", \"/api/agents/\" + agent + \"/\" + toolId, {});\n        // Never from here: the page's own approval flow runs it.\n"]],
  // a tab link that lands nowhere (D6)
  "tab-link-lands-nowhere": [[HQ, "\" in 7 days\", href: \"#approvals\" });", "\" in 7 days\", href: \"#approval\" });"],
    [EXEC, "on the <a href=\"#history\">History tab</a>", "on the <a href=\"#histroy\">History tab</a>"]],
  // the arrow keys do nothing (D6)
  "arrow-keys-off": [[DECK, "    if (e.key === \"ArrowRight\") next = TABS[(i + 1) % TABS.length];\n", "    if (e.key === \"ArrowRight\") next = TABS[i];\n"]],
  // the last tab is not remembered (D6)
  "tab-not-remembered": [[DECK, "  function remember(name) { try { localStorage.setItem(TAB_KEY, name); }", "  function remember(name) { try { void name; }"]],
  // History shows 20 a page (D7)
  "history-twenty-a-page": [[DECK, "  var PAGE_SIZE = 10;\n", "  var PAGE_SIZE = 20;\n"]],
  // History lists dry runs (D7)
  "history-shows-dry-runs": [[DECK, "history_rows_filter", "history_rows_filter"]],
  // an emoji added to a guide tip (D11)
  "emoji-in-guide-tip": [[GUIDE, "\"On \\\"Plans\\\", \\\"Run next\\\" sends one assignment per press;", "\"On \\\"Plans\\\", \\\"Run next\\\" " + THUMB + " sends one assignment per press;"]],
  // the rating reverted to an emoji (D10)
  "rating-reverted-to-emoji": [[AP, "RATE_ICON_UP + '<span class=\"ap-rate-word\">Helpful</span></button>'", "'" + THUMB + "</button>'"]]
};
// The dry-run filter's own line in bf-exec-deck.js, named once here so the mutation and the code agree.
MUTATIONS["history-shows-dry-runs"] = [[DECK, "        runs.rows = body.tasks.filter(function (t) { return t && t.status !== \"dry_run\"; });\n",
  "        runs.rows = body.tasks.filter(function (t) { return !!t; });\n"]];

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));
if (MUTATE && !MUTATIONS[MUTATE]) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }

const lf = t => t.replace(/\r\n/g, "\n");
const FILES = {};
[LIB, BRAIN].forEach(f => { FILES[f] = lf(fs.readFileSync(path.join(REPO, f), "utf8")); });
[EXEC, RUN, AP, HQ, CC, DECK, PAYWALL, GUIDE, SESSION].concat(AGENT_PAGES).forEach(f => {
  if (FILES[f] !== undefined) return;
  const p = path.join(FRONTEND, f);
  if (!fs.existsSync(p)) { console.error("Frontend file not found: " + p + " (set BIZFORCE_FRONTEND_DIR)."); process.exit(2); }
  FILES[f] = lf(fs.readFileSync(p, "utf8"));
});
if (MUTATE) {
  for (const [file, from, to] of MUTATIONS[MUTATE]) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}

let JSDOM;
try { ({ JSDOM } = require("jsdom")); } catch (e) { console.log("    FAIL  jsdom could not be loaded: " + e.message); process.exit(1); }

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined && detail !== "" ? "  [" + String(detail).slice(0, 500) + "]" : "")); }
}
process.on("unhandledRejection", e => check("no page request is left unhandled", false, (e && e.message) || e));

function compile(rel) {
  const file = path.join(REPO, rel);
  const m = new Module(file, module); m.filename = file; m.paths = Module._nodeModulePaths(path.dirname(file));
  m._compile(FILES[rel], file);
  return m.exports;
}
const LIVE = compile(LIB);

/* ── a fixed clock and the member's rows ── */
const NOW = Date.parse("2027-01-20T10:20:00.000Z");
const ago = h => new Date(NOW - h * 3600000).toISOString();
const id = n => "aaaaaaaa-0000-4000-8000-" + String(n).padStart(12, "0");
// The Executive's week: 13 real runs (12 completed, 1 failed), one dry run, and one 9 days old.
function execRows() {
  const rows = [];
  for (let i = 0; i < 12; i++) rows.push({ id: id(100 + i), agent_type: "executive", status: "completed", task_type: i % 2 ? "executive_briefing" : "general",
    prompt: "Briefing number " + (i + 1) + "\nwith a second line", result: "## Summary\nThe week went well.\n\nMore detail here.", created_at: ago(2 + i * 11) });
  rows.push({ id: id(200), agent_type: "executive", status: "failed", task_type: "kpi_review", prompt: "KPI review", error: "the model timed out", created_at: ago(30) });
  rows.push({ id: id(300), agent_type: "executive", status: "dry_run", task_type: "general", prompt: "DRY RUN ROW", created_at: ago(5) });
  rows.push({ id: id(400), agent_type: "executive", status: "completed", task_type: "general", prompt: "Old run", created_at: ago(24 * 9) });
  return rows;
}
const RECENT_FROM = NOW - 7 * 86400000;
function readsFor(rows) {
  const recent = rows.filter(r => Date.parse(r.created_at) >= RECENT_FROM);
  const out = { processing: { rows: [] }, recent: { rows: recent }, last: { rows: rows.slice() }, autonomy: { rows: [] }, schedules: { rows: [] },
    proposals: { rows: [] }, feedback: { rows: [] }, spend: { rows: [] } };
  // One schedule (Social's), so a tile carries Pause.
  out.schedules.rows.push({ agent_type: "social", cadence: "weekly", hour_utc: 9, enabled: true, paused: false, consecutive_failures: 0 });
  return out;
}
const liveOpts = (types, rows) => ({ types, reads: readsFor(rows), now: new Date(NOW), isDue: () => false, costOf: () => ({ usd: 0 }), schedulerOn: true,
  subscriptionActive: true, dailyCalls: { used: 3, limit: 250 } });

/* The Command Center: two plans, the first with a done, a running and a not-dispatchable assignment. */
const PLAN_A = "bbbbbbbb-0000-4000-8000-000000000001", PLAN_B = "bbbbbbbb-0000-4000-8000-000000000002";
function centerBody() {
  return {
    generated_at: new Date(NOW).toISOString(), chaining_on: true,
    needs_you: { ok: true, data: { pending_proposals: { count: 1, rows: [{ title: "Post the spring plan", agent_type: "social", created_at: ago(3) }] },
      failed_runs_7d: { count: 1, rows: [{ id: id(200), agent_type: "executive", task_type: "kpi_review", created_at: ago(30) }] }, email_sender: { blocked_by: [] } } },
    plans: { ok: true, data: [
      { id: PLAN_A, goal: "Fill the spring workshop", created_at: ago(20), assignments: [
        { id: 1, agent: "social", tool: "calendar", task: "Plan the posts", is_dispatchable: true, latest_dispatch: { outcome: "ran", tool_task_id: id(900), tool_task_status: "completed" } },
        { id: 2, agent: "email", tool: "sequence", task: "Write the emails", is_dispatchable: true, latest_dispatch: { outcome: "ran", tool_task_id: id(901), tool_task_status: "processing" } },
        { id: 3, agent: "store", tool: null, task: "Price the seats", is_dispatchable: false, latest_dispatch: "not dispatched" }] },
      { id: PLAN_B, goal: "Open a second shop", created_at: ago(40), assignments: [
        { id: 1, agent: "seo", tool: "audit", task: "Audit the site", is_dispatchable: true, latest_dispatch: "not dispatched" }] }] },
    activity: { ok: false, error: "not in this fixture" }, autopilot: { ok: false, error: "not in this fixture" },
    outbound: { ok: false, error: "not in this fixture" }, spend: { ok: true, data: { usd: 1.5, monthly_cap_usd: 60 } }
  };
}
// The social calendar run the Done card opens: a stored tool run, as the route records it.
const SOCIAL_RUN = { id: id(900), agent_type: "social", task_type: "social/calendar", status: "completed", prompt: "Fill the spring workshop", created_at: ago(19),
  output: { success: true, goal: "Fill the spring workshop", cadence: "three times a week", weeks_planned: 1,
    entries: [
      { day: 1, week: 1, platform: "Instagram", platform_is_measurable: true, format: "Carousel", hook: "Three things to bring", purpose: "Awareness" },
      { day: 3, week: 1, platform: "Bluesky", platform_is_measurable: true, format: "Text post", hook: "Why spring is the season", purpose: "Interest" },
      { day: 5, week: 1, platform: "Instagram", platform_is_measurable: true, format: "Reel", hook: "Seats are going", purpose: "Sign-ups" }],
    measured: { entry_count: 3, entries_with_an_unreadable_day: 0, first_day: 1, last_day: 5, span_days: 5, posts_per_week: { week_1: 3 },
      posts_per_platform: { Instagram: 2, Bluesky: 1 }, average_posts_per_week: 3, note: "Every entry has a day as a whole number, and the plan is sorted by it." },
    provenance: { measured_from: ["The number of entries, the first and last day, and the span"], inferred_by_model: ["The plan itself — every day, format, hook and purpose"],
      external_data_sources_read: [], caveat: "No social platform was read.", social_platform_contacted: false, account_data_read: false, follower_data_read: false, engagement_data_read: false } } };

/* ── one page in jsdom ── */
const GO_LINE = "  function go(url) { window.location.assign(url); }\n";
const settle = async (n) => { for (let i = 0; i < (n || 12); i++) await new Promise(r => setImmediate(r)); };
const inlineScripts = html => (html.match(/<script>([\s\S]*?)<\/script>/g) || []).map(t => t.replace(/^<script>/, "").replace(/<\/script>$/, ""));
const scriptOrder = html => (html.match(/<script(?: src="([^"]+)")?>/g) || []).map(t => (/src="\/?([^"]+)"/.exec(t) || [null, "inline"])[1]);

async function mount(page, o) {
  o = o || {};
  const raw = FILES[page];
  const html = raw.replace(/<script[\s\S]*?<\/script>/g, "");
  const url = "https://bizforceai.com/" + page + (o.hash || "");
  const dom = new JSDOM(html, { url, runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window;
  const timers = []; w.setTimeout = (fn, ms) => { timers.push({ fn, ms }); return timers.length; }; w.clearTimeout = () => {};
  w.setInterval = w.setTimeout; w.clearInterval = () => {};
  w.matchMedia = () => ({ matches: false, addListener() {}, removeListener() {} });
  w.HTMLElement.prototype.scrollIntoView = function () {};
  w.localStorage.setItem("bf_token", "check-token");
  if (o.tab) w.localStorage.setItem("bf_exec_tab", o.tab);
  const calls = [];
  const type = (/agentType:\s*"([a-z_]+)"/.exec(raw) || [])[1];
  const rows = o.rows || [];
  const reply = r => Promise.resolve({ ok: r.status >= 200 && r.status < 300, status: r.status,
    json: async () => JSON.parse(JSON.stringify(r.body)), text: async () => JSON.stringify(r.body) });
  w.fetch = (u, init) => {
    u = String(u); const method = (init && init.method) || "GET";
    const call = { url: u, method, body: init && typeof init.body === "string" ? JSON.parse(init.body) : null };
    calls.push(call);
    const p = new URL(u).pathname, q = new URL(u).searchParams;
    let r = o.api ? o.api(method, p, call.body, q) : null;
    if (r) return reply(r);
    if (method === "GET" && p === "/api/agents/live") r = { status: 200, body: LIVE.buildLive(liveOpts(LIVE.AGENT_KEYS, rows)) };
    else if (method === "GET" && /^\/api\/agents\/[a-z_]+\/live$/.test(p)) {
      r = { status: 200, body: LIVE.buildLive(liveOpts([p.split("/")[3]], rows)) };
      // server.js fills the signature after buildLive; the Executive's is its plans (lib/agentSignatures.js), none here.
      if (p.split("/")[3] === "executive") r.body.agent.signature = { kind: "executive", plans: [] };
    }
    else if (method === "GET" && p === "/api/command-center") r = { status: 200, body: centerBody() };
    else if (method === "GET" && p === "/api/proposals") r = { status: 200, body: { proposals: [{ id: "pp1", agent_type: "social", title: "Post the spring plan", status: "pending", created_at: ago(3) }] } };
    else if (method === "GET" && p === "/api/ai/tasks") r = { status: 200, body: { tasks: rows.filter(t => !q.get("agent_type") || t.agent_type === q.get("agent_type")).slice(0, Number(q.get("limit") || 50)) } };
    else if (method === "GET" && /^\/api\/ai\/tasks\/[^/]+$/.test(p)) { const t = rows.concat([SOCIAL_RUN]).find(x => x.id === p.split("/").pop()); r = t ? { status: 200, body: { task: t } } : { status: 404, body: { error: "not found" } }; }
    else if (method === "GET" && p === "/api/agents/" + type) r = { status: 200, body: { agent: { display_name: null, tasks_completed: 0 } } };
    else if (method === "GET" && /^\/api\/agents\/feedback\//.test(p)) r = { status: 200, body: { feedback: null, outcome: null } };
    else r = { status: 404, body: { error: "not in this fixture" } };
    return reply(r);
  };
  const went = [];
  w.__go = u => went.push(u);
  const errors = [];
  const order = scriptOrder(raw);
  const inline = inlineScripts(raw);
  let k = 0;
  for (const src of order) {
    try {
      if (src === "inline") { w.eval(inline[k++]); continue; }
      if (/bf-theme|bf-session|bf-offline|termaximus|bf-legal-footer/.test(src)) continue;
      const key = src.replace(/^\//, "");
      const code = FILES[key] !== undefined ? FILES[key] : lf(fs.readFileSync(path.join(FRONTEND, key), "utf8"));
      w.eval(key === HQ ? code.replace(GO_LINE, GO_LINE.replace("window.location.assign(url)", "window.__go(url)")) : code);
    } catch (e) { errors.push(src + ": " + e.message); }
  }
  await settle(30);
  const doc = w.document;
  const text = el => (el ? el.textContent.replace(/\s+/g, " ").trim() : "");
  return { w, doc, calls, went, errors, text, posts: () => calls.filter(c => c.method !== "GET") };
}
const visible = (doc, el) => { for (let n = el; n && n !== doc; n = n.parentNode) if (n.hidden) return false; return true; };

(async () => {
  const rows = execRows();
  const deck = await mount(EXEC, { rows });
  const doc = deck.doc;
  check("the deck page runs its scripts without an error", deck.errors.length === 0 && !!deck.w.BFExecDeck && !!deck.w.BFHeadquarters, deck.errors.join(" | "));
  const order = scriptOrder(FILES[EXEC]);
  check("its scripts load in order: the config, the paywall, agent-profile, Headquarters, the Command Center, the deck",
    ["inline", "scripts/bf-paywall.js", "scripts/agent-profile.js", "scripts/bf-hq.js", "scripts/bf-command-center.js", "scripts/bf-exec-deck.js"]
      .every((x, i, a) => i === 0 || order.lastIndexOf(x) > order.lastIndexOf(a[i - 1])) && order.indexOf("scripts/bf-exec-deck.js") !== -1, order.join(", "));

  /* ── D1 ── */
  console.log("\n══ D1. one command box, one Send, one voice button ══");
  const sends = [...doc.querySelectorAll("button")].filter(b => b.textContent.trim() === "Send");
  const speak = [...doc.querySelectorAll("button")].filter(b => /^Speak$/.test(b.textContent.trim()));
  check("D1. one command box (#hqCommand), and no other place to type a task: no agent-panel launcher (#apTaskPrompt, #apLaunchBtn)",
    doc.querySelectorAll("#hqCommand").length === 1 && !doc.getElementById("apTaskPrompt") && !doc.getElementById("apLaunchBtn") &&
    doc.querySelectorAll("textarea.hq-command, textarea#apTaskPrompt").length === 1);
  check("D1. one Send, and it is the box's", sends.length === 1 && sends[0].id === "hqSend", sends.map(b => b.id).join(","));
  check("D1. one voice button, \"Speak\", and its note says it only fills the box", speak.length === 1 && speak[0].id === "hqMic" &&
    /Voice only fills the box/.test(deck.text(doc.getElementById("hqMicNote"))) && /nothing is sent until you press Send/.test(deck.text(doc.getElementById("hqMicNote"))));
  check("D1. the box sits on the Command tab", !!doc.getElementById("hqCommand").closest("#deckPanel-command"));

  /* ── D2 ── */
  console.log("\n══ D2. the box still does what 6bb046a's did ══");
  {
    const m = await mount(EXEC, { rows, api: (method, p) => method === "POST" && p === "/api/ai/tasks" ? { status: 202, body: { task: { id: id(777) } } } : null });
    const mode = w => m.doc.querySelector("[data-hq-mode='" + w + "']");
    check("D2. it opens in \"Make a plan\" (Executive decides): Horizon and Constraints shown, the tool picker hidden",
      mode("plan").getAttribute("aria-pressed") === "true" && !m.doc.getElementById("hqPlanExtras").hidden && m.doc.getElementById("hqToolWrap").hidden);
    mode("task").click(); await settle();
    check("D2. \"Do a task\" hides Horizon and Constraints and shows the tool picker", mode("task").getAttribute("aria-pressed") === "true" &&
      m.doc.getElementById("hqPlanExtras").hidden && !m.doc.getElementById("hqToolWrap").hidden && m.doc.getElementById("hqAgent").value === "executive");
    m.doc.getElementById("hqCommand").value = "Brief me on the week";
    m.doc.getElementById("hqSend").click(); m.doc.getElementById("hqSend").click(); await settle();
    const tasks = m.posts().filter(c => /\/api\/ai\/tasks$/.test(c.url));
    check("D2. a typed task: one POST /api/ai/tasks per Send however many clicks, with the Executive and the words",
      tasks.length === 1 && tasks[0].body.agent_type === "executive" && tasks[0].body.prompt === "Brief me on the week", JSON.stringify(m.posts()));
    const p2 = await mount(EXEC, { rows, api: (method, p) => method === "POST" && p === "/api/agents/executive/plan" ? { status: 200, body: { task_id: "plan-new", assignments: [{ id: 1, agent: "seo", tool: "audit", is_dispatchable: true }] } } : null });
    p2.doc.getElementById("hqCommand").value = "Grow the list"; p2.doc.getElementById("hqHorizon").value = "30 days";
    p2.doc.getElementById("hqSend").click(); await settle();
    const plans = p2.posts().filter(c => /\/api\/agents\/executive\/plan$/.test(c.url));
    check("D2. \"Make a plan\": one POST /api/agents/executive/plan with the goal and the horizon, and the answer points at the Plans tab",
      plans.length === 1 && JSON.stringify(plans[0].body) === JSON.stringify({ goal: "Grow the list", horizon: "30 days" }) &&
      !!p2.doc.querySelector("#hqCommandMsg a[href='#plans']"), JSON.stringify(p2.posts()));
    const a = await mount(EXEC, { rows });
    a.doc.querySelector("[data-hq-chip='social']").click(); await settle();
    const tool = a.doc.getElementById("hqTool");
    const acting = [...tool.options].find(op => /goes through approval/.test(op.textContent));
    if (acting) tool.value = acting.value;
    a.doc.getElementById("hqSend").click(); await settle();
    check("D2. an acting tool never posts from the box: it names its own page and its approval",
      !!acting && a.posts().length === 0 && /This one goes through approval on its own page\./.test(a.text(a.doc.getElementById("hqCommandMsg"))), JSON.stringify(a.posts()));
    const r = await mount(EXEC, { rows, api: (method, p) => method === "POST" && p === "/api/ai/tasks" ? { status: 402, body: { error: "Active subscription required", message: "Running agents needs an active subscription.", billing_url: "/billing.html" } } : null });
    r.doc.querySelector("[data-hq-mode='task']").click(); await settle();
    r.doc.getElementById("hqCommand").value = "Anything"; r.doc.getElementById("hqSend").click(); await settle();
    check("D2. a refusal is named: a 402 says \"Subscription required\" in the server's words", /^Subscription required\. Running agents needs an active subscription\./.test(r.text(r.doc.getElementById("hqCommandMsg"))),
      r.text(r.doc.getElementById("hqCommandMsg")));
  }

  /* ── D3, D4, D5 ── */
  console.log("\n══ D3. plans once · D4. live state once · D5. one Command Center heading ══");
  const planCards = doc.querySelectorAll("[data-hq-plan]");
  check("D3. the Plans tab holds the plan board: both plans, one shown at a time, a picker because there are two",
    planCards.length === 2 && [...planCards].filter(c => !c.hidden).length === 1 && !doc.getElementById("hqPlanPickWrap").hidden &&
    doc.getElementById("hqPlanPick").options.length === 2 && !!doc.getElementById("hqPlans").closest("#deckPanel-plans"));
  check("D3. no second plan view: no Command Center plans panel, and no Plans module in the live panel",
    !doc.getElementById("ccPlans") && !doc.querySelector("#apLiveSignature [data-sig]") &&
    [...doc.querySelectorAll("h2, h3")].filter(h => /plan/i.test(h.textContent)).map(h => h.textContent.trim()).join("|") === "Plans");
  doc.getElementById("hqPlanPick").value = PLAN_B; doc.getElementById("hqPlanPick").dispatchEvent(new deck.w.Event("change", { bubbles: true })); await settle();
  check("D3. the picker shows the other plan", !doc.querySelector("[data-hq-plan='" + PLAN_B + "']").hidden && doc.querySelector("[data-hq-plan='" + PLAN_A + "']").hidden);
  check("D3. \"Run next\" and the progress line are on the board", !!doc.querySelector("[data-hq-plan='" + PLAN_B + "'] [data-hq-run-next]") &&
    /0 of 1 done/.test(deck.text(doc.querySelector("[data-hq-plan='" + PLAN_B + "'] .hq-progress"))));
  check("D4. one shared live panel, at the top, above the deck", doc.querySelectorAll("#apLive").length === 1 &&
    !!(doc.getElementById("apLive").compareDocumentPosition(doc.getElementById("hq")) & 4));
  // (#apLiveStatus is the shared live panel's own connection line, not the old section.)
  check("D4. no Live Status and no Task History of the agent panel's own", !doc.getElementById("apHistory") &&
    ![...doc.querySelectorAll("h1, h2, h3, h4")].some(h => /^(Live Status|Task History)$/i.test(h.textContent.trim())));
  check("D4. no toolbar Last run line (the History tab lists every run)", !doc.getElementById("lastRunText") && !/Last run:/.test(doc.body.textContent));
  const ccHeads = [...doc.querySelectorAll("h1, h2, h3, h4")].filter(h => h.textContent.trim() === "Command Center");
  check("D5. \"Command Center\" is a heading at most once", ccHeads.length <= 1, ccHeads.length);

  /* ── D6 ── */
  console.log("\n══ D6. the tabs ══");
  const TABS = ["command", "plans", "agents", "approvals", "history", "settings"], WORDS = ["Command", "Plans", "Agents", "Approvals", "History", "Settings"];
  const list = doc.querySelector("[role='tablist']");
  const tabs = [...doc.querySelectorAll("[role='tab']")];
  check("D6. one tablist of six tabs, in order, each with its word, aria-controls and a panel labelled by it",
    doc.querySelectorAll("[role='tablist']").length === 1 && !!list.getAttribute("aria-label") && tabs.length === 6 &&
    tabs.every((t, i) => t.id === "deckTab-" + TABS[i] && t.textContent.trim().indexOf(WORDS[i]) === 0 && t.getAttribute("aria-controls") === "deckPanel-" + TABS[i] &&
      doc.getElementById("deckPanel-" + TABS[i]).getAttribute("role") === "tabpanel" && doc.getElementById("deckPanel-" + TABS[i]).getAttribute("aria-labelledby") === t.id),
    tabs.map(t => t.id + ":" + t.textContent.trim()).join(","));
  const selected = d => [...d.querySelectorAll("[role='tab']")].filter(t => t.getAttribute("aria-selected") === "true").map(t => t.id.replace("deckTab-", ""));
  const shownPanels = d => TABS.filter(t => !d.getElementById("deckPanel-" + t).hidden);
  check("D6. it opens on Command: one tab selected, its panel the only one shown, roving tabindex",
    selected(doc).join() === "command" && shownPanels(doc).join() === "command" && tabs.filter(t => t.getAttribute("tabindex") === "0").length === 1);
  const key = async (d, w, k) => { d.activeElement.dispatchEvent(new w.KeyboardEvent("keydown", { key: k, bubbles: true })); await settle(2); };
  doc.getElementById("deckTab-command").focus();
  await key(doc, deck.w, "ArrowRight"); const r1 = selected(doc).join() + "/" + doc.activeElement.id;
  await key(doc, deck.w, "ArrowLeft"); const r2 = selected(doc).join();
  await key(doc, deck.w, "ArrowLeft"); const r3 = selected(doc).join();
  await key(doc, deck.w, "Home"); const r4 = selected(doc).join();
  await key(doc, deck.w, "End"); const r5 = selected(doc).join() + "/" + doc.activeElement.id;
  check("D6. Right, Left (wrapping), Home and End move the selection and the focus",
    r1 === "plans/deckTab-plans" && r2 === "command" && r3 === "settings" && r4 === "command" && r5 === "settings/deckTab-settings", [r1, r2, r3, r4, r5].join(" "));
  check("D6. each choice is its hash route", deck.w.location.hash === "#settings", deck.w.location.hash);
  doc.getElementById("deckTab-approvals").click(); await settle();
  check("D6. a click selects the tab, shows its panel, and remembers it on this device (bf_exec_tab)",
    selected(doc).join() === "approvals" && shownPanels(doc).join() === "approvals" && deck.w.localStorage.getItem("bf_exec_tab") === "approvals" && deck.w.location.hash === "#approvals");
  const remembered = await mount(EXEC, { rows, tab: "history" });
  check("D6. with no tab in the address, the remembered one opens", selected(remembered.doc).join() === "history" && shownPanels(remembered.doc).join() === "history");
  const hashed = await mount(EXEC, { rows, tab: "history", hash: "#agents" });
  check("D6. a tab in the address wins over the remembered one", selected(hashed.doc).join() === "agents");
  const inner = await mount(EXEC, { rows, hash: "#commandCenterSection" });
  check("D6. a link to an element inside a tab opens that tab (#commandCenterSection: History)", selected(inner.doc).join() === "history");
  const old = await mount(EXEC, { rows, hash: "#tool=plan&prefill=" + encodeURIComponent("Open a pop-up shop") });
  check("D6. the old #tool=plan link opens Command in \"Make a plan\" with its goal, and sends nothing",
    selected(old.doc).join() === "command" && old.doc.querySelector("[data-hq-mode='plan']").getAttribute("aria-pressed") === "true" &&
    old.doc.getElementById("hqCommand").value === "Open a pop-up shop" && old.posts().length === 0);
  // A tab, an element inside one (the deck opens its tab), an element outside the deck (always shown), or the old #tool= link.
  const lands = (d, h) => { const t = h.slice(1); return TABS.indexOf(t) !== -1 || !!d.getElementById(t) || t.indexOf("tool=") === 0; };
  const pageLinks = [...doc.querySelectorAll("a[href^='#']")].map(a => a.getAttribute("href")).filter(h => h.length > 1);
  check("D6. every in-page link on the deck lands on a tab or on an element inside one", pageLinks.length >= 1 && pageLinks.every(h => lands(doc, h)), pageLinks.join(","));
  const alerts = [...doc.querySelectorAll("#hqAlerts a.hq-alert")].map(a => a.getAttribute("href")).filter(h => h && h[0] === "#");
  check("D6. every alert that links in the page lands on a tab (failed runs and approvals: Approvals; spend: History)",
    alerts.length >= 2 && alerts.every(h => lands(doc, h)) && alerts.indexOf("#approvals") !== -1 && alerts.indexOf("#history") !== -1, alerts.join(","));
  const alertA = doc.querySelector("#hqAlerts a.hq-alert[href='#history']");
  deck.w.location.hash = "#history"; deck.w.dispatchEvent(new deck.w.HashChangeEvent("hashchange")); await settle();
  check("D6. following an alert's link opens its tab", !!alertA && selected(doc).join() === "history");
  const badge = doc.getElementById("deckApprovalsCount");
  check("D6. the Approvals tab carries the queue's count", !badge.hidden && badge.textContent === "1" && doc.getElementById("deckTab-approvals").getAttribute("aria-label") === "Approvals, 1 waiting");
  check("D6. Approvals holds the queue and \"Needs you\", the proposals shown once (Needs you points at the queue)",
    !!doc.getElementById("hqQueue").closest("#deckPanel-approvals") && !!doc.getElementById("ccNeedsYou").closest("#deckPanel-approvals") &&
    doc.querySelectorAll("#deckPanel-approvals [data-proposal]").length === 1 && /1 proposal waits in the approval queue above\./.test(deck.text(doc.getElementById("ccNeedsYou"))) &&
    !/Post the spring plan/.test(deck.text(doc.getElementById("ccNeedsYou"))));
  const sched = doc.querySelector("a[href='#ap-live-schedule']");
  check("D6. the live panel's \"Next run\" link lands on Scheduled runs, and on the deck opens Settings",
    !!sched && !!doc.getElementById("ap-live-schedule") && !!doc.getElementById("ap-live-schedule").closest("#deckPanel-settings"));
  check("D6. Agents holds the 18 tiles, the filters, the sort, Automatic and Pause", doc.querySelectorAll("#deckPanel-agents .hq-tile").length === 18 &&
    doc.querySelectorAll("#deckPanel-agents [data-hq-filter]").length === 5 && !!doc.querySelector("#deckPanel-agents #hqSort") &&
    doc.querySelectorAll("#deckPanel-agents [data-hq-ctl='autonomy']").length === 18 && doc.querySelectorAll("#deckPanel-agents [data-hq-ctl='pause'], #deckPanel-agents [data-hq-ctl='resume']").length >= 1);
  check("D6. Settings holds Autonomous mode, Scheduled runs and \"How this agent learns\"",
    !!doc.querySelector("#deckPanel-settings #apAutoToggle") && !!doc.querySelector("#deckPanel-settings .ap-sched") && !!doc.querySelector("#deckPanel-settings #apLearn"));
  check("D6. bf_exec_tab is in the kept inventory: bf-session.js's LEFT ON PURPOSE list names it", /bf_exec_tab \(the Executive command deck's last tab on this device\)/.test(FILES[SESSION]));

  /* ── D7 ── */
  console.log("\n══ D7. History: 10 a page, each row opening the drawer ══");
  const hist = await mount(EXEC, { rows: rows.concat(Array.from({ length: 10 }, (_, i) => ({ id: id(500 + i), agent_type: "executive", status: "completed", task_type: "general",
    prompt: "Extra run " + (i + 1), result: "Done.", created_at: ago(60 + i) }))), hash: "#history" });
  const hd = hist.doc;
  const runRows = () => [...hd.querySelectorAll("#deckHistoryList [data-deck-run]")];
  const real = 13 + 1 + 10;   // 13 this week, 1 old, 10 extra; the dry run left out
  check("D7. History read GET /api/ai/tasks?agent_type=executive&limit=100", hist.calls.some(c => /\/api\/ai\/tasks\?agent_type=executive&limit=100$/.test(c.url)));
  check("D7. 10 rows a page, dry runs left out, and the page line counts every real run",
    runRows().length === 10 && !/DRY RUN ROW/.test(hd.getElementById("deckHistoryList").textContent) && !hd.getElementById("deckHistoryPager").hidden &&
    hist.text(hd.getElementById("deckHistoryAt")) === "Page 1 of 3 · " + real + " runs" && hd.getElementById("deckHistoryPrev").disabled, hist.text(hd.getElementById("deckHistoryAt")));
  const r0 = runRows()[0];
  check("D7. a row is a title on one line, a date and a status pill", !!r0.querySelector(".deck-run-title") && r0.querySelector(".deck-run-title").textContent === "Briefing number 1" &&
    !!r0.querySelector(".deck-run-date") && r0.querySelector(".deck-pill").textContent === "Completed", r0.textContent);
  hd.getElementById("deckHistoryNext").click(); await settle(); const p2 = runRows().length + " " + hist.text(hd.getElementById("deckHistoryAt"));
  hd.getElementById("deckHistoryNext").click(); await settle(); const p3 = runRows().length + " " + hd.getElementById("deckHistoryNext").disabled;
  hd.getElementById("deckHistoryPrev").click(); await settle(); const back = hist.text(hd.getElementById("deckHistoryAt"));
  check("D7. Next and Prev page through it (10, 10, 4), and stop at the ends", p2 === "10 Page 2 of 3 · " + real + " runs" && p3 === "4 true" && back === "Page 2 of 3 · " + real + " runs", [p2, p3, back].join(" | "));
  const failedRow = runRows().concat([]).find(b => /KPI review/.test(b.textContent)) || null;
  hd.getElementById("deckHistoryPrev").click(); await settle();
  const first = runRows()[0]; first.click(); await settle(20);
  const drawer = hd.getElementById("deckDrawer");
  check("D7. a row opens the drawer, which reads that run by id", !drawer.hidden && hist.calls.some(c => c.url.endsWith("/api/ai/tasks/" + id(100))) &&
    hd.getElementById("deckDrawerTitle").textContent === "Briefing number 1", hd.getElementById("deckDrawerTitle").textContent);
  check("D7. the drawer has the plain summary first, the full text, its rating bar and \"Open full run\"",
    hd.querySelector("#deckDrawerBody .ap-read-summary") && hd.querySelector("#deckDrawerBody .ap-read-summary").textContent === "Summary The week went well." &&
    /More detail here\./.test(hd.querySelector("#deckDrawerBody .deck-pre").textContent) && !!hd.querySelector("#deckDrawerBody .ap-rate[data-rate-task='" + id(100) + "']") &&
    hd.getElementById("deckDrawerFull").getAttribute("href") === "/run.html?id=" + id(100), hist.text(hd.getElementById("deckDrawerBody")).slice(0, 200));
  drawer.dispatchEvent(new hist.w.KeyboardEvent("keydown", { key: "Escape", bubbles: true })); await settle();
  check("D7. Escape closes the drawer and gives the focus back to the row", drawer.hidden && hd.activeElement === first);
  void failedRow;
  // The Plans tab's Done card: "View result" opens the same drawer.
  const done = doc.querySelector("[data-hq-plan='" + PLAN_A + "'] [data-hq-view='" + id(900) + "']");
  if (done) { done.click(); await settle(20); }
  check("D7. a Done card's \"View result\" opens the drawer on the page, with \"Open full run\" inside it",
    !!done && done.textContent === "View result" && !doc.getElementById("deckDrawer").hidden && deck.went.length === 0 &&
    doc.getElementById("deckDrawerFull").getAttribute("href") === "/run.html?id=" + id(900) && !!doc.getElementById("deckDrawerFull").closest("#deckDrawer"));

  /* ── D9 and D10: the social calendar result in the drawer ── */
  console.log("\n══ D9. the readable result ══");
  const body = doc.getElementById("deckDrawerBody");
  const read = body.querySelector(".ap-read");
  const kids = read ? [...read.children].map(c => c.className || c.tagName) : [];
  check("D9. it leads with a plain summary, before the entries", !!read && /ap-read-summary/.test(kids[0] || "") &&
    deck.text(read.querySelector(".ap-read-summary")) === "Entries: 3 entries, each below.", kids.join(" > "));
  const cards = [...body.querySelectorAll(".ap-read-card")].filter(c => c.querySelector(".ap-read-card-title"));
  const rowsOf = c => [...c.querySelectorAll(".ap-read-row")].map(r => r.querySelector("dt").textContent + "=" + r.querySelector("dd").textContent);
  check("D9. each entry is a card: its hook as the title, then labelled rows (Day, Week, Platform, Format, Purpose)",
    cards.length === 3 && cards[0].querySelector(".ap-read-card-title").textContent === "Three things to bring" &&
    ["day=1", "week=1", "platform=Instagram", "format=Carousel", "purpose=Awareness"].every(x => rowsOf(cards[0]).map(r => r.toLowerCase()).indexOf(x.toLowerCase()) !== -1) &&
    !/Day: 1 · Hook:/.test(body.textContent), JSON.stringify(cards.map(rowsOf)));
  const how = body.querySelector("details.ap-read-how");
  check("D9. the provenance is one collapsed line, \"Written from the model’s own knowledge — nothing was looked up. How this was made\"",
    !!how && !how.open && !how.hasAttribute("open") && deck.text(how.querySelector("summary")) === "Written from the model’s own knowledge — nothing was looked up. How this was made",
    how ? deck.text(how.querySelector("summary")) : "no details");
  check("D9. ...which opens to the full notice, unchanged: \"Nothing was looked up.\", the flags not read, the counted and written split",
    !!how && !!how.querySelector(".ap-nothing-read") && /Nothing was looked up\. This tool read no external source/.test(deck.text(how.querySelector(".ap-nothing-read"))) &&
    /social platform contacted/i.test(deck.text(how)) && /The plan itself/.test(deck.text(how)));
  check("D9. the measured counts stay open beside it, outside the fold", !!read.querySelector(".ap-measured, .ap-zone") && !read.querySelector("details .ap-measured"));
  // run.html: the same renderer, and a text run's summary first.
  const runPage = async (task) => {
    const r = await mount(RUN, { rows: [task], hash: "" });
    return r;
  };
  void runPage;
  {
    const raw = FILES[RUN];
    const dom = new JSDOM(raw.replace(/<script[\s\S]*?<\/script>/g, ""), { url: "https://bizforceai.com/run.html?id=" + id(900), runScripts: "outside-only" });
    const w = dom.window; w.localStorage.setItem("bf_token", "t");
    w.setTimeout = () => 0; w.setInterval = () => 0; w.clearTimeout = () => {}; w.clearInterval = () => {};
    w.matchMedia = () => ({ matches: false, addListener() {}, removeListener() {} });
    const tasks = { [id(900)]: SOCIAL_RUN, [id(100)]: rows[0] };
    w.fetch = (u) => { const p = new URL(String(u)).pathname; const t = tasks[p.split("/").pop()];
      const r = /^\/api\/ai\/tasks\//.test(p) && t ? { status: 200, body: { task: t } } : /\/api\/agents\/feedback\//.test(p) ? { status: 200, body: { feedback: null } } : { status: 404, body: {} };
      return Promise.resolve({ ok: r.status === 200, status: r.status, json: async () => JSON.parse(JSON.stringify(r.body)), text: async () => JSON.stringify(r.body) }); };
    const errs = [];
    [FILES[PAYWALL], FILES[AP]].concat(inlineScripts(raw)).forEach(c => { try { w.eval(c); } catch (e) { errs.push(e.message); } });
    await settle(20);
    const v = w.document.getElementById("runView");
    const rh = v.querySelector("details.ap-read-how");
    check("D9. run.html draws the same readable result for any agent's stored run: summary, cards, one collapsed provenance line",
      errs.length === 0 && !!v.querySelector(".ap-read > .ap-read-summary") && v.querySelectorAll(".ap-read-card-title").length === 3 && !!rh && !rh.open &&
      /^Written from the model’s own knowledge — nothing was looked up\./.test(rh.querySelector("summary").textContent), errs.join(" | ") || v.textContent.slice(0, 200));
    const bar = v.querySelector(".ap-rate");
    const up = bar && bar.querySelector("[data-rate='up']"), down = bar && bar.querySelector("[data-rate='down']");
    console.log("\n══ D10. the rating, in words and drawn icons ══");
    check("D10. two buttons, each a drawn SVG in currentColor (aria-hidden) and its visible word, named \"Helpful\" and \"Not helpful\", with aria-pressed",
      !!up && !!down && [[up, "Helpful"], [down, "Not helpful"]].every(([b, word]) => {
        const svg = b.querySelector("svg");
        return !!svg && svg.getAttribute("stroke") === "currentColor" && svg.getAttribute("aria-hidden") === "true" && b.getAttribute("aria-label") === word &&
          b.querySelector(".ap-rate-word") && b.querySelector(".ap-rate-word").textContent === word && b.getAttribute("aria-pressed") === "false" && b.textContent.trim() === word;
      }), bar ? bar.innerHTML.slice(0, 300) : "no bar");
    check("D10. \"Use this as an example\" is still there (shown once a run is rated Helpful), and the reason and comment too",
      !!bar.querySelector(".ap-rate-pin") && bar.querySelector(".ap-rate-pin").textContent === "Use this as an example" && !!bar.querySelector(".ap-rate-reason") && !!bar.querySelector(".ap-rate-comment"));
    let putBody = null;
    w.fetch = (u, init) => { if (init && init.method === "PUT") putBody = JSON.parse(init.body);
      return Promise.resolve({ ok: true, status: 200, json: async () => ({ feedback: { rating: "up", pinned: false } }), text: async () => "{}" }); };
    up.querySelector("svg").dispatchEvent(new w.MouseEvent("click", { bubbles: true })); await settle(10);
    check("D10. a press on the drawn icon is the button's: it saves Helpful, and aria-pressed follows",
      !!putBody && putBody.rating === "up" && up.getAttribute("aria-pressed") === "true" && down.getAttribute("aria-pressed") === "false" && !bar.querySelector(".ap-rate-pin").hidden);
    // a text run on run.html: its summary first, then the whole text
    const dom2 = new JSDOM(raw.replace(/<script[\s\S]*?<\/script>/g, ""), { url: "https://bizforceai.com/run.html?id=" + id(100), runScripts: "outside-only" });
    const w2 = dom2.window; w2.localStorage.setItem("bf_token", "t"); w2.setTimeout = () => 0; w2.setInterval = () => 0; w2.clearTimeout = () => {}; w2.clearInterval = () => {};
    w2.matchMedia = w.matchMedia; w2.fetch = (u) => { const p = new URL(String(u)).pathname; const t = tasks[p.split("/").pop()];
      const r = t ? { status: 200, body: { task: t } } : { status: 200, body: { feedback: null } };
      return Promise.resolve({ ok: true, status: r.status, json: async () => JSON.parse(JSON.stringify(r.body)), text: async () => JSON.stringify(r.body) }); };
    [FILES[PAYWALL], FILES[AP]].concat(inlineScripts(raw)).forEach(c => { try { w2.eval(c); } catch (e) { errs.push(e.message); } });
    await settle(20);
    const v2 = w2.document.getElementById("runView");
    const res = [...v2.querySelectorAll(".rv-card")].find(c => /Result/.test(c.querySelector(".rv-label") ? c.querySelector(".rv-label").textContent : ""));
    check("D9. run.html: a text result reads its plain summary first, then the whole text unchanged",
      !!res && res.children[1] && res.children[1].className === "ap-read-summary" && res.children[1].textContent === "Summary The week went well." &&
      res.querySelector(".rv-result").textContent === rows[0].result, res ? res.innerHTML.slice(0, 200) : "no result card");
  }

  /* ── D8 ── */
  console.log("\n══ D8. one stats truth on all 18 pages ══");
  const one = LIVE.buildLive(liveOpts(["executive"], rows)).agent.runs;
  check("D8. /live counts the member's ai_tasks over 7 days with dry runs left out: 13 runs, 12 completed, 1 failed, by day",
    one.runs_7d === 13 && one.completed_7d === 12 && one.failed_7d === 1 && Array.isArray(one.days_ago_7d) && one.days_ago_7d.reduce((a, b) => a + b, 0) === 13, JSON.stringify(one));
  const codeOf = html => inlineScripts(html).join("\n").replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
  const stale = AGENT_PAGES.filter(f => /tasks_completed/.test(codeOf(FILES[f])) || /Tasks Completed/.test(FILES[f].replace(/\/\*[\s\S]*?\*\//g, "")));
  check("D8. no agent page reads ai_agents.tasks_completed or says \"Tasks Completed\"", stale.length === 0, stale.join(", "));
  check("D8. agent-profile.js keeps no counter of its own: no renderStats over a page of /api/ai/tasks", !/function renderStats\(/.test(FILES[AP]) && /function renderLiveStats\(a\)/.test(FILES[AP]));
  const bad = [];
  for (const f of AGENT_PAGES) {
    const type = (/agentType:\s*"([a-z_]+)"/.exec(FILES[f]) || [])[1];
    const pr = rows.map(r => Object.assign({}, r, { agent_type: type }));
    const m = await mount(f, { rows: pr });
    const want = LIVE.buildLive(liveOpts([type], pr)).agent.runs;
    const got = ["apStatTotal", "apStatDone", "apStatFailed"].map(i => m.text(m.doc.getElementById(i)));
    const chart = m.doc.getElementById("apChart");
    if (m.errors.length || got.join() !== [want.runs_7d, want.completed_7d, want.failed_7d].join() || got.join() !== "13,12,1" ||
        /Tasks Completed/.test(m.doc.body.textContent) || !chart || chart.hidden || m.doc.getElementById("apChartEmpty").hidden !== true) bad.push(f + " " + got.join("/") + " " + m.errors.join(";"));
  }
  check("D8. on all 18 pages Agent Stats equal /live: 13 runs, 12 completed, 1 failed, the chart drawn, no stale tile", bad.length === 0, bad.join(" | "));
  const empty = await mount("ads-agent.html", { rows: [] });
  check("D8. with no runs this week the chart is not drawn, and it says \"No runs this week\"",
    empty.doc.getElementById("apChart").hidden && !empty.doc.getElementById("apChartEmpty").hidden && empty.text(empty.doc.getElementById("apChartEmpty")) === "No runs this week" &&
    empty.text(empty.doc.getElementById("apStatTotal")) === "0");
  check("D8. the deck shows Agent Stats once, on the History tab", doc.querySelectorAll("#apStatsSection").length === 1 && !!doc.getElementById("apStatsSection").closest("#deckPanel-history") &&
    [...doc.querySelectorAll("h2, h3")].filter(h => h.textContent.trim() === "Agent Stats").length === 1);

  /* ── D11 ── */
  console.log("\n══ D11. no emoji ══");
  const PICT = /[\p{Extended_Pictographic}\u{1F1E6}-\u{1F1FF}\u{20E3}\u{FE0F}]/u;
  check("D11. the deck, rendered, holds no emoji (text and attributes)", !PICT.test(doc.documentElement.outerHTML));
  const G = FILES[GUIDE];
  const gi = G.indexOf("var PAGE_GUIDANCE = {"), gj = G.indexOf("\n  };", gi);
  let tips = [];
  try { tips = vm.runInNewContext("(" + G.slice(G.indexOf("{", gi), gj + 4) + ")")["executive-agent.html"] || []; } catch (e) { tips = []; }
  check("D11. the Executive's guide tips name the tabs and hold no emoji", tips.length >= 4 && tips.every(t => !PICT.test(t)) &&
    ["\"Command\"", "\"Plans\"", "\"History\"", "\"Approvals\"", "\"Agents\"", "\"Settings\""].every(w => tips.some(t => t.indexOf(w) !== -1)), tips.join(" | "));
  const brain = compile(BRAIN);
  check("D11. config/brain.js tells every agent no emoji unless the member asks (NO_EMOJI_RULE, last in BRAIN_DIRECTIVES)",
    typeof brain.NO_EMOJI_RULE === "string" && brain.BRAIN_DIRECTIVES.endsWith(brain.NO_EMOJI_RULE) && /explicitly asks for emoji/.test(brain.NO_EMOJI_RULE));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
