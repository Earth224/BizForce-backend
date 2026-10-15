"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkGuideTipClaims — every Termaximus tip that claimed to watch, monitor,
   track, alert, run in real time, or pointed at a panel or section, says
   only what is true; and no tip anywhere in the guide names a removed report
   section, a goals field that does not exist, or a live view nothing drives.

   Frontend "Every Termaximus tip that claims to watch something has been
   checked" verified nine tips in scripts/termaximus-guide.js against the
   pages they describe and the server, kept the one that proved true
   (billing.html's cancellation banner) byte-for-byte, and rewrote the false
   parts of the other eight:

     analytics-dashboard.html  "real-time": the page reads its two endpoints
                               once, on load; nothing polls or streams.
     agents/sales.html         a Sales Pipeline panel exists; no Opportunities
                               panel and no code that finds a stalled deal.
     agents/analytics.html     no Warnings anywhere (the report cards were
                               removed in frontend bda6ecf); Revenue Forecast
                               builds a method and produces no figure.
     agents/lead-radar.html    the radars search fixed lists in their own
                               code and never read business_profiles.
     broker-agent.html (x2)    nothing tracks a pipeline; the Pipeline report
                               section was removed in bda6ecf.
     publicist-agent.html      the Coverage and Media Outreach reports were
                               removed in bda6ecf; nothing measures coverage.
     community-agent.html      the Engagement and Growth Plans sections were
                               removed in bda6ecf; nothing measures them.

   Frontend "The guide stops pointing at sections, fields and live views that
   are gone" then fixed the Oct 14 audit's groups 1–5:

     1  tips naming a report section removed in bda6ecf (seo x2, analytics x2,
        email, store, influencer "Trending Creators", rd-agent's score fields,
        social "content pillars", sales "recommendations") now point to the
        Last run link or to what the page offers;
     2  rd-agent's "Market Goals and Research Goals" (removed in ed6d5d1) now
        names the Business Profile fields the agent is given;
     3  "live" and "real-time" with nothing driving them: the dashboard tip and
        subtitle, the Lead Radar tip, and agents/sales.html's two "Live Leads"
        headings (its "Live Activity" stays: it polls every 20 s);
     4  Lead Radar: Bluesky capture runs every 5 minutes; Mastodon, YouTube and
        scoring run only when their switches are on, and YouTube rows are not
        shown — in tips 145 and 146 and the page subtitle;
     5  social connect, publish and schedule are off: content tips 125, 127,
        128, social tip 134, and content.html's static #connectIntro.

   The guide-wide guards (G1–G3) caught four tips outside that list, rewritten
   in the same commit: seo "SEO Audit, … Competitor Analysis" (no such labels;
   Competitor Analysis is a removed rd-agent section title), operations "SOPs"
   x2 (a removed operations section title; the label is "SOP Document"),
   digital-cards "live-previewed" and business-id "live-rendered" (no timer or
   stream drives either).

   NAMED BEFORE → AFTER (assertions changed on purpose by that commit):
     L  "the tip says the radar searches fixed buyer-intent phrases and
        hashtags on Bluesky, Mastodon and YouTube" → "the tip says it searches
        fixed buyer-intent phrases on Bluesky, and that Mastodon and YouTube
        run only when switched on, YouTube finds not shown". The old sentence
        was proven by the lists existing, not by the searches running.
     M  restore-lead-radar-tip's anchor is the new tip text (same mutation:
        the Business Profile claim comes back).

   Tips and AGENT_PROFILE_CONFIG are read the way checkReputationTips.js reads
   them (regex extraction, evaluated in vm); page markup and server code are
   read as text; the removed report section titles are read from git
   (`git show bda6ecf~1:<page>` for every page bda6ecf touched). No DOM, no
   network, no model call, no database.

   WHAT THIS PROVES
     K. The kept tip's evidence still exists: billing.html's #cancelWarn
        banner, shown from sub.cancel_at_period_end, and /api/auth/me
        returning the whole subscriptions row.
     R. Each rewritten tip: the old false wording is gone, no watching word
        is used, and every feature it names is offered by its page (task
        type, tool, panel heading or element), and what it says is not there
        is still not there (no polling, no stall logic, no report sections).
     L. Lead Radar: no radar file reads business_profiles or a business
        profile, the search lists are fixed constants, the tip mentions the
        Business Profile only to say the radar does not read it, Bluesky runs
        every 5 minutes, and Mastodon, YouTube and scoring are each gated by
        their own flag — which the tips and the subtitle say, and never claim
        unconditionally.
     A. The Oct 14 audit's groups 1–5 and the four guard catches: each old
        untrue wording is gone, each new wording is there, and every label,
        field, link or behaviour it names exists.
     G. Guide-wide, over EVERY tip: no removed REPORT_SECTIONS title (read
        from git) is named, no Market/Research/Shop Goals, and no "live",
        "real-time" or "auto-refresh" except an allowlisted, asserted use.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check. A mutation
   whose search text does not match exactly once is an ERROR.

   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm"), { execFileSync } = require("child_process");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const GUIDE = "scripts/termaximus-guide.js", AP = "scripts/agent-profile.js";
const DASH = "analytics-dashboard.html", BILLING = "billing.html", SALES = "agents/sales.html", ANALYTICS = "agents/analytics.html",
  RADAR_PAGE = "agents/lead-radar.html", BROKER = "broker-agent.html", PUBLICIST = "publicist-agent.html", COMMUNITY = "community-agent.html";
const SEO = "agents/seo.html", CONTENT = "agents/content.html", SOCIAL = "agents/social.html", EMAIL = "email-agent.html", STORE = "store-agent.html",
  INFLUENCER = "influencer-agent.html", OPERATIONS = "operations-agent.html", RD = "rd-agent.html", CARDS = "digital-cards.html", BIZID = "business-id.html";
const SERVER = "server.js", BRAIN = "config/brain.js", RADARS = ["leadRadar.js", "mastodonRadar.js", "youtubeRadar.js"];
// The guide's keys are bare filenames; these seven pages live in agents/.
const IN_AGENTS = ["seo.html", "sales.html", "content.html", "social.html", "analytics.html", "lead-radar.html", "sms.html"];
const fileOfKey = k => IN_AGENTS.indexOf(k) !== -1 ? "agents/" + k : k;

const MUTATIONS = {
  // Lead Radar's tip claims the Business Profile again
  "restore-lead-radar-tip": [[GUIDE,
    '"It searches a fixed set of buyer-intent phrases on Bluesky, set in the radar\'s own code; Mastodon and YouTube searches run only when switched on, and YouTube finds are not shown here. It does not read your Business Profile, so editing your profile does not change what it finds."',
    '"It tracks against your Business Profile\'s Competitors and Industry — keep those current so the radar is watching the conversations that actually matter to you."']],
  // the broker tip points at the removed Pipeline report section again
  "restore-broker-pipeline-section": [[GUIDE,
    '"Each run is saved — open your latest from the Last run link on this page; the agent keeps no record of where your deals stand, so keep that yourself."',
    '"Track the Pipeline report section as your single source of truth for where every deal actually stands."']],
  // the kept billing tip loses its evidence: the banner is gone from the page
  "remove-cancel-banner": [[BILLING, '<div class="warn-banner" id="cancelWarn">', '<div class="warn-banner">']],
  // a radar starts reading the business profile, so the rewritten tip would be false
  "radar-reads-profile": [["leadRadar.js", "const KEYWORDS = [", 'const PROFILE_READ = () => supabase.from("business_profiles").select("*");\nconst KEYWORDS = [']],
  // the dashboard rewrite says "read once"; a poll would make that false
  "dashboard-polls": [[DASH, "    loadAnalytics();\n    loadActivity();", "    loadAnalytics();\n    loadActivity();\n    setInterval(loadAnalytics, 30000);"]],
  // seo line 114 points at the removed report sections again
  "restore-seo-114": [[GUIDE,
    '"Each run is saved — open your latest from the Last run link on this page; Refresh Data updates that link and your Business Profile after a new run."',
    '"Refresh Data after each run to pull the latest report into Website Audits, Keyword Research, and Opportunities."']],
  // rd-agent line 216 names the removed goals fields again
  "restore-rd-research-goals": [[GUIDE,
    '"Keep your Business Profile\'s Industry, Description, Target Audience, Business Goals and Competitors current (edit it from the Content Agent); I read them to decide what\'s actually worth researching."',
    '"Set your Market Goals and Research Goals directly; I read them alongside your Business Profile to decide what\'s actually worth researching."']],
  // the dashboard subtitle claims real time again
  "restore-dashboard-realtime": [[DASH, '<p class="agent-subtitle">Your business intelligence, read when the page opens.</p>',
    '<p class="agent-subtitle">Your real-time business intelligence.</p>']],
  // line 146 claims Mastodon and YouTube unconditionally again
  "restore-radar-146-unconditional": [[GUIDE,
    "It searches a fixed set of buyer-intent phrases on Bluesky, set in the radar's own code; Mastodon and YouTube searches run only when switched on, and YouTube finds are not shown here. It does not read",
    "It searches a fixed set of buyer-intent phrases and hashtags on Bluesky, Mastodon and YouTube, set in the radar's own code; it does not read"]],
  // a removed section ("Warnings", analytics) is named in another page's tip that no per-tip check covers:
  // only the guide-wide guard G1 can catch it
  "warnings-panel-elsewhere": [[GUIDE, '"Sequence your requests — document a workflow before you automate it;',
    '"Check the Warnings panel, then sequence your requests — document a workflow before you automate it;']],
  // Mastodon capture loses its switch: the "only when switched on" wording would be false
  "mastodon-ungated": [["leadRadar.js", 'if (process.env.ENABLE_MASTODON_RADAR === "true") {', "if (true) {"]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

const FILES = {};
function readFrontend(f) {
  const p = path.join(FRONTEND, f);
  if (!fs.existsSync(p)) { console.error("Frontend file not found: " + p + " (set BIZFORCE_FRONTEND_DIR)."); process.exit(1); }
  FILES[f] = fs.readFileSync(p, "utf8").replace(/\r\n/g, "\n");
}
[GUIDE, AP, DASH, BILLING, SALES, ANALYTICS, RADAR_PAGE, BROKER, PUBLICIST, COMMUNITY,
 SEO, CONTENT, SOCIAL, EMAIL, STORE, INFLUENCER, OPERATIONS, RD, CARDS, BIZID].forEach(readFrontend);
[SERVER, BRAIN].concat(RADARS).forEach(f => { FILES[f] = fs.readFileSync(path.join(REPO, f), "utf8").replace(/\r\n/g, "\n"); });
// Every page the guide has an entry for, for the guide-wide guards (read before any mutation, so a mutation can target one).
const GUIDE_KEYS = (FILES[GUIDE].match(/\n    "([a-z0-9-]+\.html)": \[/g) || []).map(m => /"([^"]+)"/.exec(m)[1]);
GUIDE_KEYS.forEach(k => { if (!FILES[fileOfKey(k)]) readFrontend(fileOfKey(k)); });
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

// A guide entry's tips, by its page key (the key the guide uses, without "agents/").
function tipsFor(key) {
  const esc = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const m = new RegExp('"' + esc + '": (\\[[\\s\\S]*?\\n    \\])').exec(FILES[GUIDE]);
  return m ? vm.runInNewContext(m[1]) : [];
}
function configOf(file) {
  const m = /window\.AGENT_PROFILE_CONFIG = (\{[\s\S]*?\n\});/.exec(FILES[file]);
  return m ? vm.runInNewContext("(" + m[1] + ")") : { taskTypes: [], tools: [] };
}
function offeredOn(file) {
  const c = configOf(file);
  return c.taskTypes.map(t => t.label).concat((c.tools || []).map(t => t.label));
}
// A name is offered when a task-type or tool label is it, or starts with it ("Competitor Comparison (from your profile)").
function offers(file, name) {
  return offeredOn(file).some(l => l === name || l.indexOf(name + " ") === 0);
}
const WATCHING = /\b(watch|monitor|track|alert)\w*|real-?time|early[- ]warning/i;
// A tip found by a fragment of its text, or "" (never several).
function tipWith(tips, fragment) {
  const found = tips.filter(t => t.indexOf(fragment) !== -1);
  return found.length === 1 ? found[0] : "";
}
// Tips that point to the Last run link: the page carries #lastRunText and agent-profile.js links it to run.html.
function lastRunOffered(file) {
  return /id="lastRunText"/.test(FILES[file]) && /function loadLastRun\(\)/.test(FILES[AP]) && /\/run\.html\?id=/.test(FILES[AP]);
}
// The Edit Profile form's field labels (agents/content.html is the only page with it).
const PROFILE_FIELDS = (FILES[CONTENT].match(/<label class="bp-label" for="bp\w+">[^<]+</g) || []).map(m => />([^<]+)</.exec(m)[1].trim());

/* ── K. billing.html: kept, byte-identical ─────────────────────────────── */
console.log("\n══ K. billing.html — kept (TRUE) ══");
const billingTips = tipsFor("billing.html");
const KEPT = "Watch for the cancellation warning banner — if it's showing, your access has an end date, and you'll want to resubscribe before it hits.";
check("K. the billing tip is unchanged, byte for byte", billingTips.indexOf(KEPT) !== -1, JSON.stringify(billingTips));
check("K. billing.html has the #cancelWarn banner with its end-of-access text",
  /<div class="warn-banner" id="cancelWarn">\s*Your subscription will not renew — access ends at the period end date\./.test(FILES[BILLING]));
check("K. the banner is shown from the subscription's cancel_at_period_end",
  /document\.getElementById\("cancelWarn"\)\.style\.display\s*=\s*sub\.cancel_at_period_end \? "block" : "none"/.test(FILES[BILLING]));
check("K. the server's /api/auth/me returns the subscriptions row (select *), which carries cancel_at_period_end",
  /app\.get\("\/api\/auth\/me"/.test(FILES[SERVER]) &&
  /async function getActiveSubscription\(userId\) \{\s*const \{ data, error \} = await supabase\s*\.from\("subscriptions"\)\s*\.select\("\*"\)/.test(FILES[SERVER]));

/* ── R1. analytics-dashboard.html ──────────────────────────────────────── */
console.log("\n══ R1. analytics-dashboard.html — \"real-time\" rewritten ══");
const dashTip = tipWith(tipsFor("analytics-dashboard.html"), "business intelligence command center");
check("R1. the tip no longer says real-time", !!dashTip && !/real-?time/i.test(dashTip), dashTip);
check("R1. the tip says the page is read once when it opens", /read once when the page opens/.test(dashTip));
check("R1. the page fetches its data on load and never again: no setInterval, EventSource or WebSocket",
  /\n    loadAnalytics\(\);\n    loadActivity\(\);/.test(FILES[DASH]) && !/setInterval|EventSource|WebSocket/.test(FILES[DASH]));
const DASH_NAMED = { "Tasks Run": "statTasksRun", "Tasks Completed": "statTasksCompleted", "Content Items": "statContentItems",
  "SMS Subscribers": "statSubscribers", "Opted-In": "statOptedIn", "SMS Campaigns": "statCampaigns", "Content Breakdown": "chartContent", "Tasks by Agent": "chartAgents" };
check("R1. every tile and chart the tip names is on the page, by label and element id",
  Object.keys(DASH_NAMED).every(n => dashTip.indexOf(n) !== -1 && FILES[DASH].indexOf(">" + n + "<") !== -1 && FILES[DASH].indexOf('id="' + DASH_NAMED[n] + '"') !== -1),
  Object.keys(DASH_NAMED).filter(n => !(dashTip.indexOf(n) !== -1 && FILES[DASH].indexOf(">" + n + "<") !== -1 && FILES[DASH].indexOf('id="' + DASH_NAMED[n] + '"') !== -1)).join(", "));

/* ── R2. agents/sales.html ─────────────────────────────────────────────── */
console.log("\n══ R2. sales.html — Pipeline and Opportunities rewritten ══");
const salesTips = tipsFor("sales.html");
const salesTip = tipWith(salesTips, "Sales Pipeline panel");
check("R2. the old \"Pipeline and Opportunities panels … flag where deals are stalling\" tip is gone",
  salesTips.every(t => !/Opportunities panel|flag where deals are stalling/.test(t)) && !!salesTip, JSON.stringify(salesTips));
check("R2. the new tip uses no watching word", !WATCHING.test(salesTip), salesTip);
check("R2. the Sales Pipeline panel exists: its heading and #salesPipelineBoard",
  /<h2 class="section-label">Sales Pipeline<\/h2>\s*<div class="sales-pipeline-board" id="salesPipelineBoard"><\/div>/.test(FILES[SALES]));
check("R2. its stages are the five the tip names, in order",
  /var STATUS_LABELS = \{ new: "New", drafted: "Drafted", contacted: "Contacted", replied: "Replied", converted: "Converted" \};/.test(FILES[SALES]) &&
  /New, Drafted, Contacted, Replied, Converted/.test(salesTip));
check("R2. a lead's stage can be moved: each card has a stage select and the board handles its change",
  /class="sales-pipeline-item-select"/.test(FILES[SALES]) && /board\.addEventListener\("change"/.test(FILES[SALES]));
check("R2. still no Opportunities panel and no stalled-deal logic on the page or the server (the tip says so)",
  !/Opportunities<\/h2>|id="[^"]*[Oo]pportunit/.test(FILES[SALES]) && !/\bstall(ed|ing)\b/i.test(FILES[SALES]) && !/\bstall(ed|ing)[ _]deal/i.test(FILES[SERVER]) &&
  /nothing here judges which deals are stalling/.test(salesTip));

/* ── R3. agents/analytics.html ─────────────────────────────────────────── */
console.log("\n══ R3. analytics.html — Warnings rewritten ══");
const anTips = tipsFor("analytics.html");
const anTip = tipWith(anTips, "KPI and forecasting layer");
check("R3. the old \"Warnings that flag risk\" wording is gone from that tip", !!anTip && !/Warnings that flag risk|insights, revenue forecasts/.test(anTip), anTip);
check("R3. the new tip uses no watching word", !WATCHING.test(anTip), anTip);
const anOffered = offeredOn(ANALYTICS);
check("R3. every feature the tip names is offered: KPI Review, Funnel Analysis, Revenue Forecast",
  ["KPI Review", "Funnel Analysis", "Revenue Forecast"].every(n => anTip.indexOf(n) !== -1 && anOffered.indexOf(n) !== -1), JSON.stringify(anOffered));
check("R3. the page has no Warnings section, and the tip names none",
  !/Warnings/.test(FILES[ANALYTICS]) && !/Warnings/.test(anTip));
check("R3. revenue_forecast still produces no revenue figure (the tip says it reads no revenue data)",
  /revenue_forecast: "[^"\n]*This platform reads no sales, revenue or pipeline data, so produce no revenue figure/.test(FILES[SERVER]) &&
  /reads no revenue data of its own/.test(anTip));

/* ── L. agents/lead-radar.html ─────────────────────────────────────────── */
console.log("\n══ L. lead-radar.html — Business Profile claim and switches ══");
const lrTips = tipsFor("lead-radar.html");
const lrTip = tipWith(lrTips, "fixed set of buyer-intent phrases");
check("L. the old \"tracks against your Business Profile's Competitors and Industry\" tip is gone",
  lrTips.every(t => !/tracks against your Business Profile|Competitors and Industry/.test(t)) && !!lrTip, JSON.stringify(lrTips));
// NAMED BEFORE → AFTER: was "…phrases and hashtags on Bluesky, Mastodon and YouTube".
check("L. the tip says it searches a fixed set of buyer-intent phrases on Bluesky (named after: was \"on Bluesky, Mastodon and YouTube\")",
  /fixed set of buyer-intent phrases on Bluesky, set in the radar's own code/.test(lrTip) && !/on Bluesky, Mastodon and YouTube/.test(lrTip), lrTip);
check("L. the tip says Mastodon and YouTube searches run only when switched on, and YouTube finds are not shown here",
  /Mastodon and YouTube searches run only when switched on/.test(lrTip) && /YouTube finds are not shown here/.test(lrTip), lrTip);
check("L. the tip says it does not read your Business Profile", /does not read your Business Profile/.test(lrTip));
check("L. no Lead Radar tip makes a Business Profile claim: the profile is named only in that denial",
  lrTips.every(t => t.replace(/does not read your Business Profile/g, "").search(/Business Profile|\bprofile's\b|Competitors|Industry/) === -1 ||
    t === lrTip && t.replace(/does not read your Business Profile/g, "").replace(/editing your profile does not change what it finds/, "").search(/Business Profile|profile|Competitors|Industry/) === -1),
  lrTips.filter(t => t.replace(/does not read your Business Profile/g, "").replace(/editing your profile does not change what it finds/, "").search(/Business Profile|profile|Competitors|Industry/) !== -1).join(" | "));
check("L. the rewritten tip uses no watching word", !WATCHING.test(lrTip), lrTip);
// A read, not a mention: leadRadar.js's scorer prompt describes BizForce as "eighteen AI agents working from one business profile".
const PROFILE_READ = /business_profiles|businessProfile|bfLoadBusinessContext/;
check("L. no radar file reads business_profiles or a business profile",
  RADARS.every(f => !PROFILE_READ.test(FILES[f])), RADARS.filter(f => PROFILE_READ.test(FILES[f])).join(", "));
check("L. the searches are fixed lists in code: KEYWORDS and BIZFORCE_KEYWORDS, HASHTAGS, and YouTube's KEYWORDS",
  /\nconst KEYWORDS = \[/.test(FILES["leadRadar.js"]) && /\nconst BIZFORCE_KEYWORDS = \[/.test(FILES["leadRadar.js"]) &&
  /\nconst HASHTAGS = \[/.test(FILES["mastodonRadar.js"]) && /\nconst KEYWORDS = \[/.test(FILES["youtubeRadar.js"]));
check("L. the Lead Radar page itself reads no business profile", !/business_profile|bfLoadBusinessContext|\/api\/business/i.test(FILES[RADAR_PAGE]));
// The switches, from leadRadar.js's radarTick: Bluesky unconditional, the rest each behind its own flag.
const LR = FILES["leadRadar.js"];
const tickStart = LR.indexOf("async function radarTick() {");
const tick = tickStart === -1 ? "" : LR.slice(tickStart, LR.indexOf("\n}\n", tickStart));
function gated(flag, call) {
  const g = tick.indexOf('if (process.env.' + flag + ' === "true") {');
  const c = g === -1 ? -1 : tick.indexOf(call, g);   // the call after the gate: a comment above it may name the call too
  return g !== -1 && c > g && tick.slice(g, c).split("{").length - tick.slice(g, c).split("}").length >= 1;
}
check("L. Bluesky capture runs on every tick, ungated: radarTick calls runLeadRadarOnce() first",
  /radarRunning = true;\s*try \{\s*await runLeadRadarOnce\(\);/.test(tick));
check("L. ticks run every 5 minutes: setInterval(radarTick, 300000)", /setInterval\(radarTick, 300000\)/.test(LR));
check("L. Mastodon capture is gated by ENABLE_MASTODON_RADAR", gated("ENABLE_MASTODON_RADAR", "runMastodonRadarOnce()"));
check("L. YouTube capture is gated by ENABLE_YOUTUBE_RADAR", gated("ENABLE_YOUTUBE_RADAR", "runYoutubeRadarOnce") || gated("ENABLE_YOUTUBE_RADAR", "YoutubeRadar"),
  (/if \(process\.env\.ENABLE_YOUTUBE_RADAR === "true"\) \{[\s\S]{0,600}/.exec(tick) || [""])[0].slice(0, 200));
check("L. intent scoring is gated by ENABLE_LEAD_SCORING", gated("ENABLE_LEAD_SCORING", "scoreNewLeads()"));
check("L. YouTube rows are not shown on the page: /api/leads lists only status \"scored\" rows, and YouTube rows are written as \"signal\"",
  /status:\s+"signal"/.test(FILES["youtubeRadar.js"]) && /app\.get\("\/api\/leads", [\s\S]{0,2000}?\.eq\("status", "scored"\)/.test(FILES[SERVER]));
const radarSub = (/<p class="agent-subtitle">([^<]*)<\/p>/.exec(FILES[RADAR_PAGE]) || ["", ""])[1];
const UNCONDITIONAL = /Mastodon &amp; YouTube every|Bluesky, Mastodon(,| and| &amp;) YouTube|(?:and|,) scored by intent|scores them,|\bscans? Mastodon|\bscans? YouTube/i;
check("L. the subtitle says Bluesky every 5 minutes and that Mastodon capture and intent scoring run only when switched on",
  /captured from Bluesky every 5 minutes; Mastodon capture and intent scoring run only when switched on\./.test(radarSub), radarSub);
check("L. no Lead Radar tip and not the subtitle claims Mastodon, YouTube or scoring unconditionally",
  !UNCONDITIONAL.test(radarSub) && lrTips.every(t => !UNCONDITIONAL.test(t)), [radarSub].concat(lrTips).filter(t => UNCONDITIONAL.test(t)).join(" | "));

/* ── R4–R7. the template pages whose report sections were removed ──────── */
console.log("\n══ R4–R7. broker, publicist, community — report sections rewritten ══");
const brTips = tipsFor("broker-agent.html");
const brIntro = tipWith(brTips, "deal flow and partnerships");
check("R4. broker: \"manages deal flow … pipeline tracking\" is gone", !!brIntro && !/pipeline tracking|manages deal flow/.test(brIntro), brIntro);
check("R4. broker: the intro names Deal Pipeline as the page offers it", /Deal Pipeline analysis/.test(brIntro) && offeredOn(BROKER).indexOf("Deal Pipeline") !== -1);
check("R5. broker: \"Track the Pipeline report section\" is gone", brTips.every(t => !/Pipeline report section/.test(t)), JSON.stringify(brTips));
const pubTips = tipsFor("publicist-agent.html");
check("R6. publicist: \"Track Coverage and Media Outreach reports\" is gone", pubTips.every(t => !/Coverage and Media Outreach reports/.test(t)), JSON.stringify(pubTips));
const comTips = tipsFor("community-agent.html");
check("R7. community: \"Watch the Engagement and Growth Plans sections\" is gone", comTips.every(t => !/Engagement and Growth Plans sections/.test(t)), JSON.stringify(comTips));
[[BROKER, brTips, "R5", "the agent keeps no record of where your deals stand"],
 [PUBLICIST, pubTips, "R6", "nothing here measures coverage"],
 [COMMUNITY, comTips, "R7", "nothing here measures engagement or growth"]].forEach(([file, tips, id, says]) => {
  const t = tipWith(tips, "Last run link");
  check(id + ". " + file + ": the new tip points to the Last run link, which the page offers and links to run.html", !!t && lastRunOffered(file), t);
  check(id + ". " + file + ": the new tip says what is not measured, and uses no watching word", t.indexOf(says) !== -1 && !WATCHING.test(t), t);
  check(id + ". " + file + ": the page still renders no report sections (REPORT_SECTIONS, #reportsGrid)", !/REPORT_SECTIONS|reportsGrid/.test(FILES[file]));
});
check("R4–R7. no tip on these three pages uses a watching word", brTips.concat(pubTips, comTips).every(t => !WATCHING.test(t)),
  brTips.concat(pubTips, comTips).filter(t => WATCHING.test(t)).join(" | "));

/* ── A. the Oct 14 audit, groups 1–5, and the guard catches ────────────── */
console.log("\n══ A. audit groups 1–5 and guard catches — old wording gone, new names real ══");
// Each rewrite: its page key, a fragment that finds the new tip, the old untrue wording that must be gone from the
// whole entry, and what the new wording names, each proven against the page or the server.
const seoTips = tipsFor("seo.html"), anaTips = anTips, emTips = tipsFor("email-agent.html"), stTips = tipsFor("store-agent.html");
const infTips = tipsFor("influencer-agent.html"), rdTips = tipsFor("rd-agent.html"), socTips = tipsFor("social.html"), conTips = tipsFor("content.html");
const opsTips = tipsFor("operations-agent.html"), dashTips = tipsFor("analytics-dashboard.html"), cardTips = tipsFor("digital-cards.html"), idTips = tipsFor("business-id.html");
const REFRESH_FN = (/function refreshPage\(\) \{([\s\S]*?)\n    \}/.exec(FILES[SEO]) || ["", ""])[1];
const A = [
  // group 1 — removed report sections
  ["1 seo 114", seoTips, "Refresh Data updates that link", /pull the latest report|Website Audits|and Opportunities/,
    () => lastRunOffered(SEO) && /id="refreshBtn">Refresh Data</.test(FILES[SEO]) && /bfLoadLastRun\(\)/.test(REFRESH_FN) && /bfLoadBusinessContext\(\)/.test(REFRESH_FN)],
  ["1 seo 115", seoTips, "Treat your saved runs as your standing SEO playbook", /Executive Reports|Recommendations/, () => true],
  ["1 analytics 140", anaTips, "nothing here checks your figures for anomalies", /Warnings panel|catch anomalies early/, () => lastRunOffered(ANALYTICS)],
  ["1 analytics 142", anaTips, "Enter current figures in KPI Review and Funnel Analysis", /Executive Reports|Refresh Data before big decisions/,
    () => (configOf(ANALYTICS).tools || []).map(t => t.label).filter(l => l === "KPI Review" || l === "Funnel Analysis").length === 2],
  ["1 email 156", emTips, "nothing here measures opens, clicks or delivery", /Check Sequences and Insights|after each send/,
    () => lastRunOffered(EMAIL) && /no open-rate, click-rate or /.test(FILES[SERVER])],
  ["1 store 163", stTips, "this agent reads no sales, traffic or channel data", /Analytics report section|channel performance gaps show up first/,
    () => lastRunOffered(STORE) && /store_audit: "[^"\n]*does not fetch or open the store and measures nothing about it/.test(FILES[SERVER]) &&
      /conversion_audit: "[^"\n]*reads no analytics, traffic, checkout or conversion data/.test(FILES[SERVER])],
  ["1 influencer 204", infTips, "Re-run Creator List when your audience or goals change", /Trending Creators|last month's list/,
    () => offers(INFLUENCER, "Creator List") && /creator_list: "[^"\n]*ideal creator archetypes[^"\n]*scoring rubric to evaluate fit/.test(FILES[SERVER]) && !/Trending Creators|trendingCreators/.test(FILES[INFLUENCER])],
  ["1 rd 215", rdTips, "innovation briefs with a written feasibility assessment", /scored with real confidence|feasibility metrics/,
    () => offers(RD, "Innovation Brief") && /innovation_brief: "[^"\n]*feasibility assessment/.test(FILES[SERVER]) &&
      !/feasibility_?score|confidence_?score|differentiation_?score|feasibilityScore|confidenceScore|differentiationScore/i.test(FILES[SERVER] + FILES[RD])],
  ["1 rd 217", rdTips, "your differentiation is clearer", /differentiation scores/, () => offers(RD, "Market Research") && offers(RD, "Competitive Intelligence")],
  ["1 social 132", socTips, "strategic planning layer", /content pillars/i,
    () => ["Social Campaign", "Content Calendar", "Engagement Strategy", "Platform Playbook", "Audience Growth Plan"].every(n => offers(SOCIAL, n))],
  ["1 sales 119", salesTips, "The leads and pipeline on this page come from Lead Radar", /pipeline recommendations/,
    () => offers(SALES, "Lead Generation") && RADARS.every(f => !PROFILE_READ.test(FILES[f]))],
  // group 2 — a field that does not exist
  ["2 rd 216", rdTips, "I read them to decide what's actually worth researching", /Market Goals|Research Goals/,
    () => ["Industry", "Description", "Target Audience", "Business Goals", "Competitors"].every(f => PROFILE_FIELDS.indexOf(f) !== -1) &&
      ["p.industry", "p.description", "p.target_audience", "p.primary_goal", "p.top_competitors"].every(c => FILES[BRAIN].indexOf(c) !== -1) &&
      !/market_goals|research_goals|marketGoals|researchGoals/.test(FILES[SERVER] + FILES[RD])],
  // group 3 — live with no mechanism
  ["3 dashboard 36", dashTips, "read once when the page opens (reload for fresh numbers)", /live read-only summary/,
    () => !/setInterval|EventSource|WebSocket/.test(FILES[DASH])],
  // groups 3 and 4 — Lead Radar 145 (146 is proven in L)
  ["3/4 lead-radar 145", lrTips, "when intent scoring is switched on, it scores them", /\blive Bluesky|by matched keyword|scans for buying-intent posts every 5 minutes, scores them/,
    () => /id="refreshBtn" onclick="loadLeads\(\)">Refresh</.test(FILES[RADAR_PAGE]) &&
      /l\.suggested_product && l\.suggested_product !== "none" && \(l\.intent_score \|\| 0\) >= 40/.test(FILES[RADAR_PAGE]) &&
      !/setInterval|EventSource|WebSocket/.test(FILES[RADAR_PAGE]) && gated("ENABLE_LEAD_SCORING", "scoreNewLeads()")],
  // group 5 — social connect, publish and schedule are off
  ["5 content 125", conTips, "approved drafts are saved, not published or scheduled", /approve and schedule/,
    () => /status:\s*"not_published",\s*scheduled_for:\s*null,/.test(FILES[SERVER]) && /\nconst SOCIAL_ACCOUNTS_SCOPED = false;/.test(FILES[SERVER])],
  ["5 content 127", conTips, "approving saves it to the Approval Queue as an unpublished draft", /before it goes live/,
    () => /<h2 class="section-label">Generate SEO Article<\/h2>/.test(FILES[CONTENT]) && /<h2 class="section-label">Generate SMS Campaign<\/h2>/.test(FILES[CONTENT]) &&
      offers(CONTENT, "Social Media Drafts") && /<h2 class="ap-section-label">Approval Queue<\/h2>/.test(FILES[AP]) && /status:\s*"not_published"/.test(FILES[SERVER])],
  ["5 content 128", conTips, "cannot be connected on this platform at present", /Connect your social accounts|directly on this page so approved content has somewhere to go/,
    () => /\nconst SOCIAL_ACCOUNTS_SCOPED = false;/.test(FILES[SERVER]) && /if \(!SOCIAL_ACCOUNTS_SCOPED\) \{\s*return res\.status\(503\)\.json\(\{ error: "Social account connections are temporarily unavailable\." \}\);/.test(FILES[SERVER])],
  ["5 social 134", socTips, "posts cannot be scheduled and social accounts cannot be connected at present", /drafting and scheduling posts|account connections live/,
    () => offers(SOCIAL, "Content Calendar") && offers(SOCIAL, "Platform Playbook") && offers(CONTENT, "Social Media Drafts") && /\nconst SOCIAL_ACCOUNTS_SCOPED = false;/.test(FILES[SERVER])],
  // guard catches outside the list
  ["G seo 113", seoTips, "and the Page Audit tool", /SEO Audit|Competitor Analysis/,
    () => ["Keyword Research", "Competitor Comparison", "Local SEO Plan", "Page Audit"].every(n => offers(SEO, n))],
  ["G operations 209", opsTips, "SOP Documents and Efficiency Audits are shaped", /\bSOPs\b/, () => offers(OPERATIONS, "SOP Document") && offers(OPERATIONS, "Efficiency Audit")],
  ["G operations 212", opsTips, "Revisit your SOP Documents periodically", /\bSOPs\b/, () => offers(OPERATIONS, "SOP Document")],
  ["G digital-cards 79", cardTips, "all shown in the card preview", /live-previewed/, () => /addEventListener\("input", updatePreview\)/.test(FILES[CARDS])],
  ["G business-id 86", idTips, "redrawn each time you save, plus a \"BizForce AI Member\" badge", /live-rendered|verified member/,
    () => /<\/svg>BizForce AI Member<\/div>/.test(FILES[BIZID]) && /profile = data\.profile;\s*renderCard\(profile\);\s*status\.textContent = "Saved successfully!";/.test(FILES[BIZID])]
];
A.forEach(([id, tips, fragment, old, proof]) => {
  const t = tipWith(tips, fragment);
  check("A. " + id + ": the new wording is there", !!t, fragment);
  check("A. " + id + ": the old untrue wording is gone from the whole entry", tips.every(x => !old.test(x)), tips.filter(x => old.test(x)).join(" | "));
  check("A. " + id + ": what it names exists and what it says happens", !!t && proof());
  check("A. " + id + ": no watching or automatic claim", !!t && !WATCHING.test(t) && !/\bautomatically\b/i.test(t), t);
});

console.log("\n── A. page copy ──");
check("A. 3 analytics-dashboard.html subtitle: \"real-time\" gone, says it is read when the page opens",
  /<p class="agent-subtitle">Your business intelligence, read when the page opens\.<\/p>/.test(FILES[DASH]) && !/real-?time/i.test(FILES[DASH]));
check("A. 3 sales.html: \"Live Leads & Activity\" and \"Live Leads from Lead Radar\" are now \"Leads & Activity\" and \"Leads from Lead Radar\"",
  !/>[^<>\n]*Live Leads[^<>\n]*<|aria-label="Live Leads/.test(FILES[SALES]) && /<span class="mc-module-title">Leads &amp; Activity<\/span>/.test(FILES[SALES]) &&
  /aria-label="Leads and Activity"/.test(FILES[SALES]) && />Leads from Lead Radar<\/h2>/.test(FILES[SALES]));
const MC_REFRESH = (/async function mcRefreshConsole\(\) \{([\s\S]*?)\n      \}\n/.exec(FILES[SALES]) || ["", ""])[1];
check("A. 3 sales.html: the lead list is not polled — it loads once and on its Refresh button; the 20 s poll does not call loadLeads",
  /id="salesLeadsRefreshBtn">Refresh</.test(FILES[SALES]) && !!MC_REFRESH && !/loadLeads/.test(MC_REFRESH));
check("A. 3 sales.html: \"Live Activity\" is kept, and a 20 s setInterval renders its feed (#mcActivityFeed via mcRenderFeed)",
  /<h2 class="section-label">Live Activity<\/h2>\s*<div id="mcActivityFeed">/.test(FILES[SALES]) &&
  /mcTaskTimer = setInterval\(mcRefreshConsole, 20000\);/.test(FILES[SALES]) && /mcRenderFeed\(tasks\);/.test(MC_REFRESH) &&
  /function mcRenderFeed\(tasks\) \{\s*var feed = document\.getElementById\("mcActivityFeed"\);/.test(FILES[SALES]));
const DYNAMIC_INTRO = (/intro\.textContent = "([^"]+)";/.exec(FILES[CONTENT]) || ["", ""])[1];
const STATIC_INTRO = (/<p id="connectIntro"[^>]*>([^<]*)<\/p>/.exec(FILES[CONTENT]) || ["", ""])[1];
check("A. 5 content.html #connectIntro: the static text no longer offers connecting or scheduling",
  !!STATIC_INTRO && !/Connect your social accounts|direct scheduling/.test(STATIC_INTRO), STATIC_INTRO);
check("A. 5 content.html #connectIntro: the static text says connecting is off and approved drafts are not published — true when the accounts read fails",
  /Connecting social accounts is turned off for now/.test(STATIC_INTRO) && /Approved drafts are saved, not published\./.test(STATIC_INTRO) &&
  STATIC_INTRO === DYNAMIC_INTRO && /\.catch\(function \(\) \{\}\);\n  \}\n\n  loadConnectedAccounts\(\);/.test(FILES[CONTENT]), STATIC_INTRO);

/* ── G. guide-wide guards, over EVERY tip ───────────────────────────────── */
console.log("\n══ G. guide-wide guards ══");
const ALL = [];
GUIDE_KEYS.forEach(k => tipsFor(k).forEach((t, i) => ALL.push({ key: k, file: fileOfKey(k), i, t })));
check("G. the guide's entries were read: " + GUIDE_KEYS.length + " pages, " + ALL.length + " tips", GUIDE_KEYS.length >= 30 && ALL.length >= 140, GUIDE_KEYS.length + "/" + ALL.length);

// G1. The REPORT_SECTIONS titles, read from git as every page stood just before bda6ecf removed them.
let TITLES = {}, gitError = "";
try {
  const git = args => execFileSync("git", args, { cwd: FRONTEND, maxBuffer: 64 * 1024 * 1024 }).toString("utf8").replace(/\r\n/g, "\n");
  git(["show", "--format=", "--name-only", "bda6ecf"]).split("\n").filter(Boolean).forEach(p => {
    const m = /REPORT_SECTIONS\s*=\s*\[([\s\S]*?)\];/.exec(git(["show", "bda6ecf~1:" + p]));
    const re = /"?title"?\s*:\s*"([^"]+)"/g; let r; const t = [];
    while (m && (r = re.exec(m[1]))) t.push(r[1]);
    if (t.length) TITLES[p] = t;
  });
} catch (e) { gitError = e.message; }
const TITLE_LIST = Object.keys(TITLES).reduce((a, p) => a.concat(TITLES[p].filter(t => a.indexOf(t) === -1)), []);
check("G1. the removed section titles were read from git: 18 pages, at least 50 distinct titles", !gitError && Object.keys(TITLES).length === 18 && TITLE_LIST.length >= 50,
  gitError || Object.keys(TITLES).length + " pages, " + TITLE_LIST.length + " titles");
check("G1. the titles include the ones the audit found (Warnings, Website Audits, Executive Reports, Content Pillars, Innovation Opportunities, Sequences, Analytics)",
  ["Warnings", "Website Audits", "Executive Reports", "Content Pillars", "Innovation Opportunities", "Sequences", "Analytics"].every(t => TITLE_LIST.indexOf(t) !== -1));
console.log("      titles: " + TITLE_LIST.join(" | "));
// A title counts as named unless the tip's own page offers that exact text today: a task-type or tool label, a visible
// element's text, or an Edit Profile field. Those are stripped first, case-insensitively, longest first ("Keyword
// Research" is a live seo task type as well as a removed seo section). Then a multi-word title matches in any case; a
// one-word title matches as a capitalised name, or in any case when called a section, panel, report, tab or card.
function presentOn(file) {
  const out = offeredOn(file).slice();
  const re = />\s*([^<>{}\n]{2,60}?)\s*</g; let m;
  while ((m = re.exec(FILES[file]))) out.push(m[1].replace(/&amp;/g, "&"));
  return out.concat(PROFILE_FIELDS).filter(Boolean).sort((a, b) => b.length - a.length);
}
function stripCI(text, phrase) {
  const re = new RegExp(phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
  return text.replace(re, () => "\u0000");
}
function titlesNamed(tip, file) {
  let t = tip; presentOn(file).forEach(p => { t = stripCI(t, p); });
  return TITLE_LIST.filter(T => {
    const e = T.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (/\s/.test(T)) return new RegExp("\\b" + e + "\\b", "i").test(t);
    return new RegExp("\\b" + e + "\\b").test(t) || new RegExp("\\b" + e + "\\s+(report\\s+)?(section|panel|reports?|tab|cards?)\\b", "i").test(t);
  });
}
const G1_HITS = ALL.map(x => ({ x, hits: titlesNamed(x.t, x.file) })).filter(h => h.hits.length);
check("G1. no tip anywhere in the guide names a report section title removed in bda6ecf",
  G1_HITS.length === 0, G1_HITS.map(h => h.x.key + "#" + h.x.i + " " + h.hits.join(",")).join(" | "));

// G2. Goals fields that do not exist on any form.
const GOALS = /\b(Market Goals|Research Goals|Shop Goals)\b/i;
check("G2. no tip names Market Goals, Research Goals or Shop Goals", ALL.every(x => !GOALS.test(x.t)),
  ALL.filter(x => GOALS.test(x.t)).map(x => x.key + "#" + x.i).join(", "));

// G3. "live", "real-time", "auto-refresh": only where a timer or stream drives the thing named. Each allowed use is
// listed with its reason and asserted; any other use fails.
const LIVE = /\blive\b|\blive-|real-?time|auto-?refresh/i;
const LIVE_ALLOWED = [
  // the verb: "your data and agent history live under one account" says where data is kept, not that a view updates
  { key: "app.html", phrase: "history live under one account", proof: () => true }
];
const liveHits = ALL.filter(x => LIVE.test(x.t) && !LIVE_ALLOWED.some(a => a.key === x.key && x.t.indexOf(a.phrase) !== -1 &&
  !LIVE.test(x.t.split(a.phrase).join("")) && a.proof()));
check("G3. no tip says live, real-time or auto-refresh unless allowlisted with its mechanism",
  liveHits.length === 0, liveHits.map(x => x.key + "#" + x.i + ": " + x.t.slice(0, 90)).join(" | "));
check("G3. the allowlist is not stale: each allowed phrase is still in its tip",
  LIVE_ALLOWED.every(a => tipsFor(a.key).some(t => t.indexOf(a.phrase) !== -1)));
// Page copy is not a tip, but the pages this block edited keep only "live" text that something drives:
//   sales.html "Live Activity"           — a 20 s setInterval renders #mcActivityFeed (asserted in A);
//   sales.html "Run Task & Live Status"  — agent-profile.js's startPoll polls the running task with setInterval.
const LIVE_COPY = f => FILES[f].match(/>[^<>\n]*\b(Live|live|real-?time|Real-?time)\b[^<>\n]*</g) || [];
check("G3. agent-profile.js's Live Status polls the running task: startPoll sets an interval that fetches /api/ai/tasks/<id>",
  /function startPoll\(taskId, promptText\) \{\s*if \(pollTimer\) clearInterval\(pollTimer\);\s*var ticks = 0;\s*pollTimer = setInterval\(function \(\) \{[\s\S]{0,600}?fetch\(API_URL \+ "\/api\/ai\/tasks\/" \+ taskId/.test(FILES[AP]));
check("G3. the only \"live\" copy left on analytics-dashboard, sales and lead-radar is sales.html's \"Live Activity\" and \"Run Task & Live Status\"",
  [DASH, SALES, RADAR_PAGE].every(f => LIVE_COPY(f).every(m => m === ">Live Activity<" || m === ">Run Task &amp; Live Status<")) &&
  LIVE_COPY(SALES).indexOf(">Live Activity<") !== -1 && !/>[^<>\n]*\breal-?time\b/i.test(FILES[CONTENT]),
  [DASH, SALES, RADAR_PAGE].map(f => LIVE_COPY(f).join(",")).join(" / "));

console.log("\n" + (failures ? "CHECKS FAILED: " + failures + " of " + (passes + failures) : "ALL " + passes + " CHECKS PASSED") + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
process.exit(failures ? 1 : 0);
