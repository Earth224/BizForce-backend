"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkGuideTipClaims — every Termaximus tip that claimed to watch, monitor,
   track, alert, run in real time, or pointed at a panel or section, says
   only what is true; and no tip anywhere in the guide names a removed report
   section, a goals field that does not exist, a live view nothing drives, an
   automatic behaviour nothing performs, or a BFC amount nothing pays; every
   agent page has its own entry, and the home page's agent cards say what
   their pages say.

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

   Frontend "The guide and pages stop claiming data, payouts and controls
   that don't exist" then fixed the Oct 14 audit's groups 6–10:

     6  data no agent reads: seo 111, analytics 139 and 141, email 152 and
        154, store 159–161, influencer 201 and 203; the email, store,
        publicist, community and sales subtitles; seo.html's "Google SEO
        Report" (the route fetches the site itself); agent-profile.js's
        Autonomous mode, which no longer says the agent acts on what it finds;
     7  the wallet: tips 66–69 and certifications 75, and wallet.html's hero —
        BFC is credited only for a first certification pass while subscribed
        and as a one-time 1,000 BFC welcome bonus; the history is the latest 50;
     8  controls: marketplace 62 (nothing sends a status), certifications 76
        (Try Again / Start Assessment), lead-radar 147 (no sort control; Copy
        writes to the clipboard only);
     9  the directory: ai-agents 29 and 31 and its hero (descriptions are
        seeded empty);
    10  the dashboard: tips 17 (the Business Profile, not Business Identity),
        18 (Recent Activity is gone) and 19 (Agent Hub shows all 18).

   Frontend "The guide's last untrue tips are fixed and every agent has its
   own guide" then finished the audit:

    11  one-off tips: analytics-dashboard 38 (0 means none yet; "—" means
        loading or unreadable), business-id 89 (the card is drawn only for its
        owner), business-chat 92 and 95 (one thread; answers read the last 20
        messages), card-view 98 (the QR codes hold a vCard; ?token= opens the
        page), sales 118 and 122 (a task reads no pipeline), content 129 (the
        library is articles and SMS campaigns), lead-radar 148 (a count of
        leads, not intent), broker 175 (a framework, not an execution
        document), rd 218 and 219, oracle 225 (.docx only) and 226 (the
        numbers are fixed by birth name and date), and the Oracle's insight;
        the app.html entry, which could never display (the guide returns
        early there), is removed;
        index.html's agent card subtitles now equal their pages' (sales,
        email, community, store, publicist, vertical marketing), and
        wallet.html's earn cards say first pass while subscribed, and paid
        when the subscription goes active;
        oracle.html's picker offers only what POST /api/oracle accepts (.doc
        and image/* removed: the server takes .docx and four image types);
        new entries for ads-agent, executive-agent, vertical-marketing-agent
        and agents/sms.html, each tip proved against its page and routes.

   NAMED BEFORE → AFTER (assertions changed on purpose by that commit):
     L  "the tip says the radar searches fixed buyer-intent phrases and
        hashtags on Bluesky, Mastodon and YouTube" → "the tip says it searches
        fixed buyer-intent phrases on Bluesky, and that Mastodon and YouTube
        run only when switched on, YouTube finds not shown". The old sentence
        was proven by the lists existing, not by the searches running.
     M  restore-lead-radar-tip's anchor is the new tip text (same mutation:
        the Business Profile claim comes back).
     G3 LIVE_ALLOWED held one phrase, app.html's "history live under one
        account"; that entry is gone, so the allowlist is empty (and stays
        checked for staleness).
     M  automatic-in-business-chat → automatic-in-agents-hub: business-chat
        tip 92 now has its own per-tip checks, so the G3-only mutation moved to
        a tip no per-tip check covers.

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
     B. The Oct 14 audit's groups 6–10, tips and page copy, with A's four
        assertions each: new wording there, old wording gone from the whole
        entry or page, everything named exists, no watching or automatic claim.
     G. Guide-wide, over EVERY tip: no removed REPORT_SECTIONS title (read
        from git) is named, no Market/Research/Shop Goals, no "live",
        "real-time" or "auto-refresh" and no "automatically", "instantly" or
        "auto-" except an allowlisted use whose mechanism is asserted (G3), and
        no BFC amount that is not a constant or label in server.js or
        wallet.html (G4).
     C. The audit's group 11, block B's leftovers and the four new entries,
        with the same four assertions per tip and per copy line; and the
        Oracle's picker and the server's allowed upload types agree both ways.
    G5. Every registered agent page (AGENT_SYSTEM_PROMPTS through
        AGENT_PAGE_URLS) and agents/sms.html loads the guide and has its own
        entry, and no entry is for a page where the guide never displays.
    G6. Every index.html agent card subtitle equals its page's subtitle.
     D. Block C's leftovers. The sms, ads and executive subtitles name only
        what their pages offer (A's four assertions each), dashboard.html's
        SMS Drip card says what agents/sms.html says, and the vertical
        marketing config comment is true of allowedTaskTypes and
        taskInstructions. The Oracle's uploads are RUN, not read:
        oracle.html's ORACLE_UPLOAD_TYPES is the one list, and the picker's
        accept list and the filter on every picked or dropped file are built
        from it (the attach block runs in a stub DOM: a dropped .doc is never
        attached and never sent, and the refusal names the file and the
        accepted types); the server's fileFilter runs through a stub multer,
        its tables equal that list, it takes .csv as application/vnd.ms-excel
        and .md with an empty MIME, refuses .doc, .svg and a .csv labelled
        image/png, and over a grid of names and labels takes nothing outside
        the nine types and no alias but the ones the rule names for .csv and
        .md. That rule is POST /api/oracle's alone (oracleChatUpload): the
        shared oracleUpload the marketplace, BizBook, cover, cover-wrap and
        editor routes use still decides by MIME type alone.

   NAMED BEFORE → AFTER (block D, assertions changed on purpose):
     C  "the Oracle's server refuses any type it does not list, and lists 9"
        read the fileFilter's source (ORACLE_UPLOAD_ALLOWED_MIME[file.mimetype])
        → removed; D runs the filter instead (9 types, 10 extensions, grid).
     C  "nothing the picker offers is refused by the server" and "everything
        the server accepts is offered by the picker" read oracle.html's static
        accept="..." attribute → removed with the attribute; D reads the
        accept list the page's script sets from ORACLE_UPLOAD_TYPES and checks
        the picker, the drop filter and the server against each other.
     M  restore-picker-doc: anchor accept=".pdf,.docx, → a .doc entry is put
        back into ORACLE_UPLOAD_TYPES. picker-image-wildcard: anchor the
        accept attribute → image/* is appended to the accept list the script
        sets. Same intent, new place for the list.

   NAMED BEFORE → AFTER (Claims Scan on the Vertical Marketing page, Oct 16
   2026, assertions changed on purpose):
     C  "new vertical 1" proved "nothing about the industry is researched" in
        part by counting exactly 2 vertical_marketing routes → 3, the third
        being claims-scan, which reads only the caller's own copy and fetches
        nothing.
     C  "the four new entries have 4–5 tips each" → ads, executive and sms
        stay at 4–5; the vertical entry has exactly 6, the sixth being the
        Claims Scan tip.
     C  new row "vertical 6" proves the Claims Scan tip, so "every tip of the
        four new entries is covered by a row above" still holds.

   NAMED BEFORE → AFTER (SEO writer clinical-marker rail, Oct 17 2026,
   assertion changed on purpose):
     C  row "vertical 6" pinned claimsScanText(profile, text) →
        claimsScanText(profile, text, cautions); the third parameter collects
        caution-only FDA matches. Nothing else in the row changed.

   NAMED BEFORE → AFTER (Audience Ledger on the Community page, Oct 17 2026,
   assertion changed on purpose):
     R7 the community Last-run tip had to say "nothing here measures
        engagement or growth" → "nothing here measures engagement, and
        Audience Ledger counts sign-ups rather than activity". The ledger
        counts new sign-ups by month, so "nothing measures growth" stopped
        being true; it still reads no engagement.

   NAMED BEFORE → AFTER (YouTube filter build, Oct 2026, assertions changed on
   purpose):
     L  the Lead Radar tip gains "A YouTube comment is shown only if it has no
        link, at least 6 words, and a word from the search it matched; the
        section says how many were hidden and why." (lib/youtubeFilter.js, at
        capture and at display). New evidence: the filter's own minimum, the
        route's hidden_counts and the page's #ytHidden line.
        restore-lead-radar-tip and restore-radar-146-unconditional are
        re-anchored on the new tip text.

   NAMED BEFORE → AFTER (YouTube quota build, Oct 2026, assertions changed on
   purpose):
     L  the Lead Radar tip had to say "…and YouTube capture is switched off.
        YouTube finds are kept for at most 30 days…" → "Mastodon and YouTube
        searches run only when switched on. YouTube finds are listed in their
        own section below the scored list: not scored, not replyable from
        here, and kept for at most 30 days; a Sales pipeline entry built on
        one is removed with it". YouTube capture is now spend-capped
        (lib/youtubeQuota.js) and meant to be switched back on, so "is
        switched off" and "not currently captured" would turn false the day
        the owner sets ENABLE_YOUTUBE_RADAR. The subtitle now says "YouTube
        capture also runs only when switched on; its finds are listed apart,
        never scored, and kept for at most 30 days", and the Sales Pipeline
        note "…and YouTube capture runs only when switched on". New evidence:
        the section, its route and the absence of any Draft button in it.
        restore-lead-radar-tip and restore-radar-146-unconditional are
        re-anchored on the new tip text.

   NAMED BEFORE → AFTER (YouTube retention build, Oct 2026, assertions changed
   on purpose):
     L  the Lead Radar tip had to say "Older scored YouTube finds can appear
        in the list; new YouTube finds are not scored or shown" → "YouTube
        finds are kept for at most 30 days, and a Sales pipeline entry built
        on one is removed with it". lib/youtubeRetention.js now deletes
        YouTube rows older than 30 days, and the pipeline rows on them, every
        day unless ENABLE_YOUTUBE_RETENTION is exactly "false"; the 2,169
        stored YouTube rows were all older than 30 days. The check that read
        "older scored YouTube finds can appear: /api/leads never filters on
        source" now proves the new sentence from the module and its schedule.
        The lead-radar.html subtitle and the Sales Pipeline gain the same
        statement. restore-lead-radar-tip and restore-radar-146-unconditional
        are re-anchored on the new tip text; retention-keeps-pipeline is new.

   NAMED BEFORE → AFTER (Social Search build, Oct 2026, assertions changed on
   purpose):
     L  the Lead Radar tip had to say "YouTube finds are not shown here" →
        "YouTube capture is switched off. Older scored YouTube finds can
        appear in the list; new YouTube finds are not scored or shown". The
        old sentence was false: GET /api/leads filters on status only, and
        674 YouTube rows scored before SCORABLE_SOURCES left youtube out are
        status "scored" (9 of the top 100 on Oct 18 2026). The check that
        read "YouTube rows are not shown" now proves the new sentence: no
        source filter on /api/leads, new rows written as "signal", youtube
        not in SCORABLE_SOURCES. "Switched off" is the Railway setting,
        which no check can read; what is proved is that capture is off
        unless ENABLE_YOUTUBE_RADAR is exactly "true".
     M  restore-lead-radar-tip and restore-radar-146-unconditional are
        anchored on the new tip text (the same mutations).

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
const RETENTION = "lib/youtubeRetention.js";
// The guide's keys are bare filenames; these seven pages live in agents/.
const IN_AGENTS = ["seo.html", "sales.html", "content.html", "social.html", "analytics.html", "lead-radar.html", "sms.html"];
const fileOfKey = k => IN_AGENTS.indexOf(k) !== -1 ? "agents/" + k : k;

const MUTATIONS = {
  // Lead Radar's tip claims the Business Profile again
  "restore-lead-radar-tip": [[GUIDE,
    '"It searches a fixed set of buyer-intent phrases on Bluesky, set in the radar\'s own code; Mastodon and YouTube searches run only when switched on. YouTube finds are listed in their own section below the scored list: not scored, not replyable from here, and kept for at most 30 days; a Sales pipeline entry built on one is removed with it. A YouTube comment is shown only if it has no link, at least 6 words, and a word from the search it matched; the section says how many were hidden and why. It does not read your Business Profile, so editing your profile does not change what it finds."',
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
    "It searches a fixed set of buyer-intent phrases on Bluesky, set in the radar's own code; Mastodon and YouTube searches run only when switched on. YouTube finds are listed in their own section below the scored list: not scored, not replyable from here, and kept for at most 30 days; a Sales pipeline entry built on one is removed with it. A YouTube comment is shown only if it has no link, at least 6 words, and a word from the search it matched; the section says how many were hidden and why. It does not read",
    "It searches a fixed set of buyer-intent phrases and hashtags on Bluesky, Mastodon and YouTube, set in the radar's own code; it does not read"]],
  // the retention job stops deleting the pipeline rows built on a YouTube find: the tip's new sentence would be false
  "retention-keeps-pipeline": [[RETENTION, "      .from(\"sales_lead_pipeline\")\n      .delete()\n", "      .from(\"sales_lead_pipeline\")\n      .select(\"id\")\n"]],
  // a removed section ("Warnings", analytics) is named in another page's tip that no per-tip check covers:
  // only the guide-wide guard G1 can catch it
  "warnings-panel-elsewhere": [[GUIDE, '"Sequence your requests — document a workflow before you automate it;',
    '"Check the Warnings panel, then sequence your requests — document a workflow before you automate it;']],
  // Mastodon capture loses its switch: the "only when switched on" wording would be false
  "mastodon-ungated": [["leadRadar.js", 'if (process.env.ENABLE_MASTODON_RADAR === "true") {', "if (true) {"]],
  // ── groups 6–10 ──
  // wallet tip 68 states the invented payouts again
  "restore-wallet-68-amounts": [[GUIDE,
    "your first pass of each certification pays 100 BFC while you're subscribed, and a one-time 1,000 BFC welcome bonus lands when your subscription goes active. Running agent tasks and posting listings pay nothing.",
    "certifications (+100), agent tasks (+50), marketplace listings (+25), and the welcome bonus (+200) are all real, stackable ways to build balance."]],
  // wallet tip 67 says credits accumulate automatically again
  "restore-credits-automatic": [[GUIDE,
    "the one action here is Send BFC, which sends credits to another member by their user ID; using the platform earns nothing by itself.",
    "it's a read-only ledger; credits accumulate automatically as you use the platform."]],
  // store tip 159 claims to manage inventory across every channel again
  "restore-store-159": [[GUIDE,
    "This agent writes commerce plans — store audits, inventory plans, omnichannel strategy, conversion audits, and product launch plans — from your Business Profile and what you tell it; it connects to no store or channel.",
    "This agent manages multi-store commerce intelligence — inventory, product performance, and omnichannel strategy across every channel you sell on."]],
  // the SEO report is called a Google report again
  "restore-google-seo-report": [[SEO, '<h3 class="seo-opt-report-title">Website SEO Report</h3>', '<h3 class="seo-opt-report-title">Google SEO Report</h3>']],
  // the directory promises a customisable team again
  "restore-ai-agents-338": [["ai-agents.html", "Eighteen AI business specialists — open any one to go to its own page.",
    "Build your own customizable team of AI business specialists."]],
  // "automatically" in a tip no per-tip check covers: only the widened G3 can catch it
  "automatic-in-agents-hub": [[GUIDE, "each card opens that agent's dedicated workspace", "each card automatically opens that agent's dedicated workspace"]],
  // an invented BFC amount in a tip no per-tip check covers: only G4 can catch it
  "invented-bfc-amount": [[GUIDE, "a complete listing gets found faster than a bare one.", "a complete listing earns +500 BFC and gets found faster than a bare one."]],
  // the server starts paying for agent tasks: "running agent tasks … pay nothing" would be false
  "task-pays-bfc": [[SERVER, "const WELCOME_BONUS_BFC = 1000;",
    "const WELCOME_BONUS_BFC = 1000;\nasync function payForTask(userId) { await creditWallet(userId, 50, \"Agent task\"); }"]],
  // the wallet reads its whole history: "your latest 50 transactions" would be false
  "history-unlimited": [[SERVER, ".select(\"id, type, amount, description, created_at\")\n      .eq(\"user_id\", req.user.id)\n      .order(\"created_at\", { ascending: false })\n      .limit(50);",
    ".select(\"id, type, amount, description, created_at\")\n      .eq(\"user_id\", req.user.id)\n      .order(\"created_at\", { ascending: false });"]],
  // the marketplace edit sends a status: "nothing sends a status" would be false
  "marketplace-sends-status": [["marketplace.html", "tags: tagsRaw, media: listingMedia };", "tags: tagsRaw, media: listingMedia, status: \"paused\" };"]],
  // the Autonomous mode copy claims the agent acts on what it finds again
  "restore-act-on-findings": [[AP, "' carry out its scheduled runs below in the ',\n                  'background, without you launching them. Off means it ',",
    "' start its own tasks in the background ',\n                  'without you launching them, and act on what it finds. Off means it ',"]],
  // certifications tip 76 names Retake Assessment for a failed attempt again
  "restore-retake-76": [[GUIDE, "If you don't pass the first time, press Try Again on the result screen, or Start Assessment on the card later — there's no penalty for trying again.",
    "Use Retake Assessment if you don't pass the first time — there's no penalty for trying again."]],
  // the dashboard tip points at the removed Recent Activity feed again
  "restore-recent-activity": [[GUIDE, "Use the Active Queue card and its View Queue button to see your active assignments",
    "Use the Active Queue card and Recent Activity feed to see what's actually running"]],
  // ── group 11, the leftovers, G5 and G6 ──
  // oracle tip 226 says the numbers sharpen with time again
  "restore-226-sharpen": [[GUIDE, "Your Life Path, Expression, Soul Urge, and Birthday numbers are fixed by your birth name and date and do not change with time; your current location, your path and your story can, and the Oracle reads them with every question.", "Your Life Path, Expression, Soul Urge, and Birthday numbers only sharpen with time, and the Oracle's counsel sharpens with them."]],
  // sales tip 118 claims pipeline intelligence from your business data again
  "restore-sales-118": [[GUIDE, "\"This agent writes sales material — funnels, lead generation, outreach scripts, offers, and objection handling — from your Business Profile and what you tell it; its tasks read none of the leads or pipeline on this page.\",", "\"This agent builds pipeline and revenue intelligence — funnels, lead generation, outreach scripts, offers, and objection handling — from your business data.\","]],
  // the Oracle's picker offers .doc again, which the server refuses
  "restore-picker-doc": [["oracle.html", "      { ext: \".docx\", mime:", "      { ext: \".doc\",  mime: \"application/msword\" },\n      { ext: \".docx\", mime:"]],
  // the picker offers every image type again; the server takes four
  "picker-image-wildcard": [["oracle.html", "attachFileInput.accept = ORACLE_UPLOAD_EXTS.join(\",\");", "attachFileInput.accept = ORACLE_UPLOAD_EXTS.join(\",\") + \",image/*\";"]],
  // the server starts taking .doc: the picker would no longer offer all it accepts, and 225 would be false
  "server-accepts-doc": [[SERVER, "  \"text/plain\": true,   // .txt\n", "  \"application/msword\": true,\n  \"text/plain\": true,   // .txt\n"]],
  // index.html's sales card gets its old subtitle back (G6)
  "restore-index-sales-subtitle": [["index.html", "<p>Funnels, outreach scripts, and offers from your business profile, plus the leads Lead Radar captures.</p>", "<p>Pipeline, leads, and revenue intelligence from your business profile.</p>"]],
  // an agent page's subtitle changes and the home page card does not (G6, from the page side)
  "page-subtitle-drifts": [["vertical-marketing-agent.html", "<p class=\"agent-subtitle\">Marketing built for one industry vertical — its language, its channels, its objections.</p>", "<p class=\"agent-subtitle\">Marketing built for one industry: its positioning, language, channels, and objections.</p>"]],
  // the ads-agent entry is deleted (G5)
  "delete-ads-entry": [[GUIDE, "    \"ads-agent.html\": [\n      \"This agent writes ad campaigns and ad copy from your Business Profile and what you tell it; it connects to no ad account and reads no ad results, so nothing here buys, runs or measures an ad.\",\n      \"Ad Copy writes for a Google Responsive Search Ad or a Meta feed ad and measures every asset against that platform's limits — Google's 30-character headlines and 90-character descriptions are hard limits, rejected at upload if longer; Meta's are the points where the feed cuts text short.\",\n      \"Ad Copy also runs what it writes through the policy scan, so wording that gets ads rejected is flagged in the same result.\",\n      \"Policy Check scans copy you paste for wording that gets ads rejected — cure claims, before-and-after results, guaranteed results, addressing a personal attribute — and for FDA disease claims; a clean scan is not approval, and with Suggest rewrites unchecked it makes no model call at all.\",\n      \"Use Ad Campaign for a whole plan — audience, offer, hooks, creative angles, copy, budget guidance, and a testing plan — then write each ad's assets in Ad Copy.\"\n    ],\n", ""]],
  // an app.html entry comes back, on a page where the guide returns early (G5)
  "readd-app-entry": [[GUIDE, "    \"seo.html\": [\n", "    \"app.html\": [\n      \"The front door — sign in or create an account here.\"\n    ],\n    \"seo.html\": [\n"]],
  // the wallet's certification card promises BFC for any pass again
  "restore-wallet-cert-card": [["wallet.html", "Paid for your first pass of each certification, while you're subscribed</div>", "Pass any certification quiz to earn BFC rewards</div>"]],
  // the drip engine leaves dry-run mode: the sms tips would be false
  "drip-engine-sends": [[SERVER, "    var DRY_RUN = true;\n", "    var DRY_RUN = false;\n"]],
  // direct SMS sending opens: sms tip 5 would be false
  "direct-sms-opens": [[SERVER, "\nconst SMS_DIRECT_SEND_ENABLED = false;", "\nconst SMS_DIRECT_SEND_ENABLED = true;"]],
  // ── D, block C's leftovers ──
  // agents/sms.html's subtitle claims to reach customers with automated drip campaigns again
  "restore-sms-subtitle": [["agents/sms.html", "<p class=\"agent-subtitle\">SMS subscribers and consent, drip campaigns built message by message, enrollment, and a dry-run log of what would go out — no text is sent.</p>",
    "<p class=\"agent-subtitle\">Reach customers directly with targeted SMS sequences, subscriber management, and automated drip campaigns.</p>"]],
  // a dropped (or picked) file is attached whatever its type, so a .doc is sent
  "remove-drop-filter": [["oracle.html", "        if (oracleTakesFile(fileList[i])) attachedFiles.push(fileList[i]);\n        else refused.push(fileList[i].name || \"file\");\n",
    "        attachedFiles.push(fileList[i]);\n"]],
  // the server stops taking a .csv that Windows labels as Excel's
  "server-refuses-excel-csv": [[SERVER, "  \".csv\": [\"application/vnd.ms-excel\", \"text/plain\",", "  \".csv\": [\"text/plain\","]],
  // the server is widened to take .doc, by extension and by type
  "server-widens-to-doc": [[SERVER, "  \".docx\": \"application/vnd", "  \".doc\": \"application/msword\",\n  \".docx\": \"application/vnd"],
    [SERVER, "  \"text/plain\": true,   // .txt\n", "  \"application/msword\": true,\n  \"text/plain\": true,   // .txt\n"]],
  // POST /api/oracle goes back to the shared MIME-only multer: the browser's label decides again
  "oracle-route-on-shared-filter": [[SERVER, "requireActiveSubscription, oracleChatUpload.array(\"files\", 8), async", "requireActiveSubscription, oracleUpload.array(\"files\", 8), async"]],
  // the shared multer takes the extension rule too, narrowing the marketplace, BizBook, cover and editor uploads
  "shared-filter-by-extension": [[SERVER, "  fileFilter: function (req, file, cb) {\n    if (ORACLE_UPLOAD_ALLOWED_MIME[file.mimetype]) {\n", "  fileFilter: function (req, file, cb) {\n    if (oracleUploadType(file)) {\n"]],
  // the vertical marketing comment says the three types do not exist again
  "vertical-comment-false-again": [["vertical-marketing-agent.html", "     allowedTaskTypes also lists vertical_positioning, channel_research and\n",
    "     Three task types this agent genuinely wants do NOT exist server-side:\n     vertical_positioning, channel_research and\n"]]
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
[SERVER, BRAIN, RETENTION].concat(RADARS).forEach(f => { FILES[f] = fs.readFileSync(path.join(REPO, f), "utf8").replace(/\r\n/g, "\n"); });
// Every page the guide has an entry for, for the guide-wide guards (read before any mutation, so a mutation can target one).
const GUIDE_KEYS = (FILES[GUIDE].match(/\n    "([a-z0-9-]+\.html)": \[/g) || []).map(m => /"([^"]+)"/.exec(m)[1]);
GUIDE_KEYS.forEach(k => { if (!FILES[fileOfKey(k)]) readFrontend(fileOfKey(k)); });
// Every page in the frontend, for G5 (which pages load the guide) and the business-id check; index.html among them, for G6.
const HTML_PAGES = [];
(function walk(dir) {
  fs.readdirSync(path.join(FRONTEND, dir), { withFileTypes: true }).forEach(d => {
    const rel = dir ? dir + "/" + d.name : d.name;
    if (d.isDirectory()) { if (!/^(\.|node_modules$)/.test(d.name)) walk(rel); }
    else if (/\.html$/i.test(d.name)) HTML_PAGES.push(rel);
  });
})("");
HTML_PAGES.forEach(f => { if (!FILES[f]) readFrontend(f); });
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
// NAMED BEFORE → AFTER (YouTube retention build): the board may now follow the retention note under the heading.
check("R2. the Sales Pipeline panel exists: its heading and #salesPipelineBoard",
  /<h2 class="section-label">Sales Pipeline<\/h2>\s*(?:<p class="sales-pipeline-note">[^<]*<\/p>\s*)?<div class="sales-pipeline-board" id="salesPipelineBoard"><\/div>/.test(FILES[SALES]));
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
// NAMED BEFORE → AFTER: was "…and YouTube finds are not shown here", which was false; then (Social Search build)
// "Older scored YouTube finds can appear in the list; new YouTube finds are not scored or shown", until the retention job.
// NAMED BEFORE → AFTER (YouTube quota build): was "…and YouTube capture is switched off. YouTube finds are kept for at
// most 30 days, and a Sales pipeline entry built on one is removed with it."
check("L. the tip says Mastodon and YouTube searches run only when switched on, and YouTube finds have their own section: not scored, not replyable, kept at most 30 days, a pipeline entry removed with one",
  /Mastodon and YouTube searches run only when switched on\. YouTube finds are listed in their own section below the scored list: not scored, not replyable from here, and kept for at most 30 days; a Sales pipeline entry built on one is removed with it\./.test(lrTip) &&
  !/YouTube capture is switched off/.test(lrTip) &&
  !/Older scored YouTube finds can appear/.test(lrTip) && !/YouTube finds are not shown here/.test(lrTip), lrTip);
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
const radarSub0 = () => (/<p class="agent-subtitle">([^<]*)<\/p>/.exec(FILES[RADAR_PAGE]) || ["", ""])[1];
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
// NAMED BEFORE → AFTER: was "YouTube rows are not shown on the page"; older scored ones were, until the retention job.
const LEADS_ROUTE = (function (sv) { const i = sv.indexOf('app.get("/api/leads", '); return i === -1 ? "" : sv.slice(i, sv.indexOf("\n});\n", i)); })(FILES[SERVER]);
check("L. new YouTube finds are not shown: they are written as \"signal\", /api/leads lists only status \"scored\", and youtube is not a scored source",
  /status:\s+"signal"/.test(FILES["youtubeRadar.js"]) && /\.eq\("status", "scored"\)/.test(LEADS_ROUTE) &&
  /const SCORABLE_SOURCES = \["bluesky", "mastodon"\];/.test(LR));
// NAMED BEFORE → AFTER: was "older scored YouTube finds can appear: /api/leads never filters on source", the evidence
// for a sentence the tip no longer has. Now the evidence for "kept for at most 30 days" and "removed with it".
const RET = FILES[RETENTION];
check("L. YouTube finds are kept for at most 30 days: the retention job deletes source youtube older than 30 days, daily at 09:00 UTC, on unless ENABLE_YOUTUBE_RETENTION is exactly \"false\"",
  /var YOUTUBE_RETENTION_DAYS = 30;/.test(RET) && /\.from\("bsky_leads"\)\n      \.delete\(\)[\s\S]{0,120}\.eq\("source", "youtube"\)/.test(RET) &&
  /ENABLE_YOUTUBE_RETENTION !== "false"/.test(RET) && /if \(youtubeRetentionEnabled\(process\.env\)\) \{\n    cron\.schedule\("0 9 \* \* \*"/.test(FILES[SERVER]));
check("L. a Sales pipeline entry built on a YouTube find is removed with it: the job deletes sales_lead_pipeline rows on the batch's leads before the leads",
  /\.from\("sales_lead_pipeline"\)\n      \.delete\(\)\n      \.in\("lead_post_uri", deletableUris\)/.test(RET) &&
  RET.indexOf(".from(\"sales_lead_pipeline\")") < RET.indexOf("// (b) THE LEADS."));
// NAMED BEFORE → AFTER (YouTube quota build): both said "…and are not currently captured".
check("L. the subtitle and the Sales Pipeline say the same: capture only when switched on, kept for at most 30 days, a pipeline entry removed with it",
  /YouTube capture also runs only when switched on; its finds are listed apart, never scored, and kept for at most 30 days\./.test(radarSub0()) &&
  /<p class="sales-pipeline-note">YouTube finds are kept for at most 30 days, and YouTube capture runs only when switched on\. A pipeline entry built on a YouTube find is removed with it\.<\/p>/.test(FILES[SALES]) &&
  !/not currently captured/.test(radarSub0() + FILES[SALES]), radarSub0());
// The section the tip and the subtitle name: its own route, its own list, no Draft button.
const ytSection = (/<section class="yt-section" id="ytSection"[^>]*>[\s\S]*?<\/section>/.exec(FILES[RADAR_PAGE]) || [""])[0];
const ytBuilder = (/function buildYoutubeFind\(find\) \{[\s\S]*?\n    \}\n/.exec(FILES[RADAR_PAGE]) || [""])[0];
check("L. lead-radar.html has the YouTube section, titled as the tip says, outside #leadsList, fed by /api/leads/youtube-signals",
  /<h2 class="yt-title">YouTube finds — not scored, cannot be replied to from here, kept 30 days<\/h2>/.test(ytSection) &&
  ytSection.indexOf('id="leadsList"') === -1 && /fetch\(API \+ "\/api\/leads\/youtube-signals"/.test(FILES[RADAR_PAGE]) &&
  /app\.get\("\/api\/leads\/youtube-signals", requireAuth,/.test(FILES[SERVER]), ytSection.slice(0, 200));
check("L. a YouTube find has no Draft button, no score and no reply control", ytBuilder.length > 0 && !/draft|score|reply|copy-btn/i.test(ytBuilder), ytBuilder.slice(0, 300));
// NAMED BEFORE → AFTER (YouTube filter build): new. Each rule the tip names is the filter's, and the count it names is shown.
const YT_FILTER = fs.readFileSync(path.join(REPO, "lib", "youtubeFilter.js"), "utf8");
check("L. the tip states the three YouTube rules and the hidden count, and each is real: the filter's link test, its 6-word minimum, its topic test, used at capture and display, and the page's count line",
  /A YouTube comment is shown only if it has no link, at least 6 words, and a word from the search it matched; the section says how many were hidden and why\./.test(lrTip) &&
  /var YOUTUBE_MIN_WORDS = 6;/.test(YT_FILTER) && /reason: "link"/.test(YT_FILTER) && /reason: "off_topic"/.test(YT_FILTER) &&
  /isUsefulYoutubeComment\(commentText, keyword\)/.test(FILES["youtubeRadar.js"]) && /isUsefulYoutubeComment\(page\[i\]\.post_text, page\[i\]\.matched_keyword\)/.test(FILES[SERVER]) &&
  /id="ytHidden"/.test(ytSection) && /" hidden: " \+ link \+ " with links, " \+ short \+ " too short, " \+ off \+ " off topic"/.test(FILES[RADAR_PAGE]), lrTip);
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
 [COMMUNITY, comTips, "R7", "nothing here measures engagement, and Audience Ledger counts sign-ups rather than activity"]].forEach(([file, tips, id, says]) => {
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

/* ── B. the Oct 14 audit, groups 6–10 ──────────────────────────────────── */
console.log("\n══ B. audit groups 6–10 — invented data, payouts and controls ══");
// The same four assertions as A, per rewrite. Pages these checks read that A does not are guide keys, read above.
const DASHBOARD = "dashboard.html", HUB = "agents-hub.html", DIRECTORY = "ai-agents.html", MARKET = "marketplace.html",
  WALLET = "wallet.html", CERTS = "certifications.html";
const hqTips = tipsFor("dashboard.html"), dirTips = tipsFor("ai-agents.html"), mkTips = tipsFor("marketplace.html");
const walTips = tipsFor("wallet.html"), certTips = tipsFor("certifications.html");
const SV = FILES[SERVER];
// The only paths that credit a wallet: creditWallet, called twice (a certification, the welcome bonus), and the one
// bfc_credit RPC inside it. Transfers, purchases and donations move BFC between members; nothing else mints it.
const CERT_CREDIT = /if \(becameEarned\) \{[\s\S]{0,400}?if \(creditPlan && creditPlan\.active === true\) \{\s*try \{\s*await creditWallet\(req\.user\.id, 100, "Certification earned: " \+ certId\);/;
const WELCOME = () => /\nconst WELCOME_BONUS_BFC = 1000;/.test(SV) && /\.eq\("description", WELCOME_BONUS_DESCRIPTION\)/.test(SV) &&
  /await creditWallet\(userId, WELCOME_BONUS_BFC, WELCOME_BONUS_DESCRIPTION\);/.test(SV) &&
  /The welcome bonus, now that the subscription row says active\.[\s\S]{0,400}?await grantWelcomeBonusOnce\(userId\);/.test(SV);
const ONLY_TWO_CREDITS = () => (SV.match(/creditWallet\(/g) || []).length === 3 && (SV.match(/async function creditWallet\(/g) || []).length === 1 &&
  (SV.match(/rpc\("bfc_credit"/g) || []).length === 1;
const HISTORY_50 = () => /\.from\("wallet_transactions"\)\s*\.select\("id, type, amount, description, created_at"\)\s*\.eq\("user_id", req\.user\.id\)\s*\.order\("created_at", \{ ascending: false \}\)\s*\.limit\(50\);/.test(SV) &&
  /var txns = data\.transactions \|\| \[\];[\s\S]{0,200}?txns\.forEach\(function\(t\) \{\s*if \(t\.type === "credit" \|\| t\.type === "reward"\) earned \+= t\.amount;\s*else if \(t\.type === "debit"\) spent \+= t\.amount;/.test(FILES[WALLET]);
const SEND_BFC = () => /<button type="button" id="send-btn" class="send-btn">Send BFC<\/button>/.test(FILES[WALLET]) &&
  /placeholder="Recipient user ID"/.test(FILES[WALLET]) && /fetch\(API_URL \+ "\/api\/wallet\/transfer"/.test(FILES[WALLET]) &&
  // Since the transfer limits (migration 139), the route calls bfc_send, which checks the limits and then calls bfc_transfer.
  /app\.post\("\/api\/wallet\/transfer", requireAuth, requireActiveSubscription,[\s\S]{0,8000}?rpc\("bfc_send"/.test(SV);
const taskPrompt = key => (new RegExp("\\n  " + key + ": \"([^\"\\n]*)\"").exec(SV) || ["", ""])[1];
const AP_FILE = FILES[AP];
const B = [
  // group 10 — dashboard
  ["10 dashboard 17", hqTips, "edit it here under Expand Profile or on the Content Agent's Edit Profile", /Business Identity page|keep both current/,
    () => /var nameField = document\.getElementById\("business_name"\);[\s\S]{0,300}?var goalField = document\.getElementById\("primary_goal"\);/.test(FILES[DASHBOARD]) &&
      /id="businessProfileSummaryIndustry"/.test(FILES[DASHBOARD]) && /id="businessProfileSummaryGoal"/.test(FILES[DASHBOARD]) &&
      /<span class="bf-profile-expand-label">Expand Profile<\/span>/.test(FILES[DASHBOARD]) &&
      (FILES[DASHBOARD].match(/fetch\(API_URL \+ "\/api\/business-profile"/g) || []).length === 2 &&
      /id="editProfileBtn"[^>]*>Edit Profile<\/button>/.test(FILES[CONTENT]) && /fetch\(BP_API \+ "\/api\/business-profile"/.test(FILES[CONTENT]) &&
      /fetch\(API_URL \+ "\/api\/profile\/me"/.test(FILES[BIZID]) && !/business-profile/.test(FILES[BIZID])],
  ["10 dashboard 18", hqTips, "the Active Queue card and its View Queue button", /Recent Activity/,
    () => /<h3>Active Queue<\/h3>\s*<p class="bf-summary-status" id="activeQueueSummaryStatus">No active assignments<\/p>\s*<button type="button" id="viewQueueBtn" class="bf-btn bf-btn-ghost">View Queue<\/button>/.test(FILES[DASHBOARD]) &&
      !/>[^<>]*Recent Activity[^<>]*</.test(FILES[DASHBOARD]) && !/id="recentActivity/i.test(FILES[DASHBOARD])],
  ["10 dashboard 19", hqTips, "Agent Hub and Full Directory each list all 18 agents", /curated set/,
    () => /onclick="window\.location\.href='agents-hub\.html';">Agent Hub<\/button>/.test(FILES[DASHBOARD]) &&
      /onclick="window\.location\.href='ai-agents\.html';">Full Directory<\/button>/.test(FILES[DASHBOARD]) &&
      (FILES[HUB].match(/class="agent-card/g) || []).length === 18 && /agents\.forEach\(function \(agent\) \{/.test(FILES[DIRECTORY])],
  // group 9 — the directory: ai_agents.description is seeded empty, so a card shows a name and a link
  ["9 ai-agents 29", dirTips, "each card shows the agent's name and an Open Agent button to its own page", /one-line description|specializes in|descriptions are specific/,
    () => /display_name: agentDisplayName\(type\),\s*description: "",/.test(SV) && /name\.textContent = agent\.display_name \|\| "";/.test(FILES[DIRECTORY]) &&
      /var href = agent\.page_url \|\| "agents-hub\.html";/.test(FILES[DIRECTORY]) && /link\.textContent = "Open Agent";/.test(FILES[DIRECTORY])],
  ["9 ai-agents 31", dirTips, "find it by name and press Open Agent", /which agent fits a task — the descriptions/,
    () => /link\.textContent = "Open Agent";/.test(FILES[DIRECTORY])],
  // group 8 — controls that do not exist under that name
  ["8 marketplace 62", mkTips, "with Edit and Delete buttons", /manage status|Active\/Paused\/Sold/,
    () => /'<button type="button" class="btn-sm btn-edit"' \+ idAttr \+ '>Edit<\/button>'/.test(FILES[MARKET]) &&
      /'<button type="button" class="btn-sm btn-delete"' \+ idAttr \+ '>Delete<\/button>'/.test(FILES[MARKET]) &&
      /var statusHtml = isOwn \? '<span class="status-badge status-'/.test(FILES[MARKET]) &&
      /var body = \{ title, description: desc, category, price_bfc: price, price_usd: priceUsd, tags: tagsRaw, media: listingMedia \};/.test(FILES[MARKET]) &&
      !/\bstatus\s*:\s*"(active|paused|sold)"|body\.status\b/.test(FILES[MARKET])],
  ["8 certifications 76", certTips, "press Try Again on the result screen, or Start Assessment on the card", /Retake Assessment/,
    () => /<button class="result-retry-btn" id="resultRetryBtn">Try Again<\/button>/.test(FILES[CERTS]) &&
      /if \(earned\) \{\s*html \+= '<button class="cert-btn cert-btn-retry"[^\n]*>Retake Assessment<\/button>';\s*\} else \{\s*html \+= '<button class="cert-btn cert-btn-start"[^\n]*>Start Assessment<\/button>';/.test(FILES[CERTS]) &&
      // A fail shows the result screen, with Try Again on it. The server grades now, so it is the server's fail.
      /if \(!result\.passed\) \{\s*render\(pct, false, null, res\.data\.already_earned === true \? "kept" : null\);/.test(FILES[CERTS]) &&
      !/cooldown|max_?attempts|attempt_?limit|lockout/i.test(SV.slice(SV.indexOf('app.post("/api/certifications/award"'), SV.indexOf("async function creditWallet(")))],
  ["8 lead-radar 147", lrTips, "Copy it to your clipboard and post it on Bluesky yourself", /Sort by score|Copy it straight to Bluesky/,
    () => /leads\.sort\(function \(a, b\) \{ return \(b\.intent_score \|\| 0\) - \(a\.intent_score \|\| 0\); \}\);/.test(FILES[RADAR_PAGE]) &&
      !/<select|>[^<>\n]*\bSort\b[^<>\n]*</i.test(FILES[RADAR_PAGE]) &&
      /return \(l\.intent_score \|\| 0\) >= 60;/.test(FILES[RADAR_PAGE]) && /label: "High-Intent"/.test(FILES[RADAR_PAGE]) &&
      /function copyReply\(idx\) \{[\s\S]{0,200}?navigator\.clipboard\.writeText\(text\)/.test(FILES[RADAR_PAGE]) && />Draft Engagement<\/button>/.test(FILES[RADAR_PAGE]) &&
      !/bsky\.social|createRecord|app\.bsky/.test(FILES[RADAR_PAGE])],
  // group 7 — wallet and certification payouts
  ["7 wallet 66", walTips, "The history shows your latest 50 transactions", /full Transaction History/,
    () => HISTORY_50() && ["Available Balance", "Total Earned", "Total Spent"].every(l => FILES[WALLET].indexOf(">" + l + "<") !== -1) && /\n    Transaction History\n/.test(FILES[WALLET])],
  ["7 wallet 67", walTips, "the one action here is Send BFC", /accumulate automatically|read-only ledger/, () => SEND_BFC() && ONLY_TWO_CREDITS()],
  ["7 wallet 68", walTips, "a one-time 1,000 BFC welcome bonus lands when your subscription goes active", /\+50|\+25|\+200|agent tasks \(|stackable/,
    () => CERT_CREDIT.test(SV) && WELCOME() && ONLY_TWO_CREDITS() && /How to Earn BFC/.test(FILES[WALLET])],
  ["7 wallet 69", walTips, "not how much you use the platform", /rewards real engagement|how actively you're using/,
    () => ONLY_TWO_CREDITS() && ["bfc_send", "bfc_buy_listing", "bfc_donate"].every(r => SV.indexOf('rpc("' + r + '"') !== -1)],
  ["7 certifications 75", certTips, "Your first pass of each certification pays 100 BFC to your Wallet while you're subscribed", /Passing pays out BFC/,
    () => CERT_CREDIT.test(SV) && /AN EARNED RECORD IS NEVER WRITTEN AGAIN/.test(SV)],
  // group 6 — data no agent reads
  ["6 seo 111", seoTips, "keyword research, content plans, local SEO plans, and page audits", /rankings|forecasts/,
    () => ["Keyword Research", "Content Plan", "Local SEO Plan", "Page Audit"].every(n => offers(SEO, n)) && /knows no search volume, competition, difficulty or ranking/.test(taskPrompt("keyword_research"))],
  ["6 analytics 139", anaTips, "the context every analytics task is written from", /thin forecasts|Accuracy depends/,
    () => ["Industry", "Website", "Competitors"].every(f => PROFILE_FIELDS.indexOf(f) !== -1) &&
      ["\"Industry: \"", "\"Website: \"", "\"Competitors: \""].every(l => FILES[BRAIN].indexOf(l) !== -1) &&
      /var profileResult = await supabase\s*\.from\("business_profiles"\)/.test(SV) && /buildAgentSystemPrompt\(agentBrain, businessProfile,/.test(SV)],
  ["6 analytics 141", anaTips, "enter each metric's Now and Before figures and it works out the change", /trend lines actually mean|on a schedule/,
    () => /"name": "current",\s*"label": "Now",/.test(FILES[ANALYTICS]) && /"name": "previous",\s*"label": "Before",/.test(FILES[ANALYTICS]) &&
      /var change = hasPrevious \? current - previous : null;/.test(SV)],
  ["6 email 152", emTips, "it writes the copy and reads no delivery data", /deliverability/i,
    () => ["Email Campaign", "Email Sequence", "Winback Flow", "Nurture Campaign", "Subject Line Testing"].every(n => offers(EMAIL, n)) && /no open-rate, click-rate or /.test(SV)],
  ["6 email 154", emTips, "notes which to A/B test first, and the test itself runs in your own email platform", /lives and dies/,
    () => offers(EMAIL, "Subject Line Testing") && /Note which to A\/B test first\./.test(taskPrompt("subject_lines"))],
  ["6 store 159", stTips, "it connects to no store or channel", /manages multi-store|across every channel|commerce intelligence/,
    () => ["Store Audit", "Inventory Plan", "Omnichannel Strategy", "Conversion Audit", "Product Launch Plan"].every(n => offers(STORE, n)) &&
      /does not fetch or open the store/.test(taskPrompt("store_audit")) && !/shopify|woocommerce|bigcommerce/i.test(FILES[STORE])],
  ["6 store 160", stTips, "are written from that context, not from your store's own data", /compare you against/,
    () => /reads no analytics, traffic, checkout or conversion data/.test(taskPrompt("conversion_audit"))],
  ["6 store 161", stTips, "it plans your channel mix, inventory sync approach, and a consistent customer experience", /coordinating across stores|edge is/,
    () => /channel mix/.test(taskPrompt("omnichannel_strategy")) && /inventory sync approach/.test(taskPrompt("omnichannel_strategy")) && /customer experience consistency/.test(taskPrompt("omnichannel_strategy"))],
  ["6 influencer 201", infTips, "drafts the work of creator partnerships", /end to end|forecasting ROI/,
    () => ["Influencer Outreach", "Campaign Plan", "Partnership Offer", "ROI Forecast"].every(n => offers(INFLUENCER, n)) && /^Build an influencer ROI model the owner can fill in/.test(taskPrompt("roi_forecast"))],
  ["6 influencer 203", infTips, "builds the return model and break-even from figures you supply", /expected return/,
    () => /a break-even calculation/.test(taskPrompt("roi_forecast")) && /use only numbers the user supplies/.test(taskPrompt("roi_forecast"))]
];
const NO_CLAIM = t => !WATCHING.test(t) && !/\bautomatic(ally)?\b|\binstant(ly)?\b|\bauto-/i.test(t);
B.forEach(([id, tips, fragment, old, proof]) => {
  const t = tipWith(tips, fragment);
  check("B. " + id + ": the new wording is there", !!t, fragment);
  check("B. " + id + ": the old untrue wording is gone from the whole entry", tips.every(x => !old.test(x)), tips.filter(x => old.test(x)).join(" | "));
  check("B. " + id + ": what it names exists and what it says happens", !!t && proof());
  check("B. " + id + ": no watching or automatic claim", !!t && NO_CLAIM(t), t);
});

console.log("\n── B. page copy ──");
// Each agent's static subtitle stands alone (ai_agents.description is empty): it names only task types the page offers.
const subtitle = f => (/<p class="agent-subtitle">([^<]*)<\/p>/.exec(FILES[f]) || ["", ""])[1];
const OPTIMIZE = SV.slice(SV.indexOf('app.post("/api/agents/seo/optimize"'), SV.indexOf("\napp.", SV.indexOf('app.post("/api/agents/seo/optimize"') + 10));
const BCOPY = [
  // [id, file, the new text as it stands in the file, old untrue wording (absent from the page's visible text), proof]
  ["6 email-agent.html subtitle", EMAIL, '<p class="agent-subtitle">Email campaigns, sequences, win-back and nurture flows, and subject lines.</p>', /deliverability/i,
    () => ["Email Campaign", "Email Sequence", "Winback Flow", "Nurture Campaign", "Subject Line Testing"].every(n => offers(EMAIL, n))],
  ["6 store-agent.html subtitle", STORE, '<p class="agent-subtitle">Store audits, inventory plans, omnichannel strategy, and launch plans.</p>', /Multi-store|sales intelligence/i,
    () => ["Store Audit", "Inventory Plan", "Omnichannel Strategy", "Product Launch Plan"].every(n => offers(STORE, n))],
  ["6 publicist-agent.html subtitle", PUBLICIST, '<p class="agent-subtitle">Press releases, media pitches, PR campaigns, and brand narrative.</p>', /visibility intelligence/i,
    () => ["Press Release", "Media Pitch", "PR Campaign", "Brand Narrative"].every(n => offers(PUBLICIST, n))],
  ["6 community-agent.html subtitle", COMMUNITY, '<p class="agent-subtitle">Community growth plans, engagement strategy, referral loops, and retention systems.</p>', /Community health|growth intelligence/i,
    () => ["Community Growth Plan", "Engagement Strategy", "Referral Loop", "Retention System"].every(n => offers(COMMUNITY, n))],
  ["6 sales.html subtitle", SALES, '<p class="agent-subtitle">Funnels, outreach scripts, and offers from your business profile, plus the leads Lead Radar captures.</p>', /revenue intelligence/i,
    () => ["Sales Funnel", "Outreach Script", "Offer Builder"].every(n => offers(SALES, n)) && />Leads from Lead Radar<\/h2>/.test(FILES[SALES])],
  // the optimize route fetches the site itself (guardedFetch) and reads nothing from Google
  ["6 seo.html report heading", SEO, '<h3 class="seo-opt-report-title">Website SEO Report</h3>', /Google SEO Report/,
    () => /guardedFetch/.test(OPTIMIZE) && /EXTRACTED ON-PAGE DATA \(fetched live from the URL above\)/.test(OPTIMIZE) && !/googleapis|google\.com|search ?console|serpapi|pagespeed/i.test(OPTIMIZE)],
  // a scheduled run goes through handleAiTaskRequest like a pressed one, only with autonomy on; nothing acts on its result
  ["6 agent-profile.js Autonomous mode", AP, "'Lets the ' + esc(AGENT_LABEL) + ' carry out its scheduled runs below in the ',\n                  'background, without you launching them. Off means it ',", /act on what it finds/,
    () => /'<div class="ap-sched-title">Scheduled runs<\/div>',/.test(AP_FILE) && /function runScheduledAgentTask\(schedule\) \{[\s\S]{0,1200}?handleAiTaskRequest\(req, res, next\)/.test(SV) &&
      /var skippedNoAutonomy\s+= 0;/.test(SV) && /if \(process\.env\.ENABLE_AGENT_SCHEDULES === "true"\) \{\s*cron\.schedule\("0 \* \* \* \*", function \(\) \{\s*agentScheduleTick\(\)/.test(SV)],
  ["7 wallet.html hero", WALLET, '<p class="hero-sub">Earn BFC by passing certifications while subscribed, plus a one-time welcome bonus when your subscription goes active.</p>',
    /platform milestones/i, () => CERT_CREDIT.test(SV) && WELCOME() && ONLY_TWO_CREDITS()],
  ["9 ai-agents.html description", DIRECTORY, "        Eighteen AI business specialists — open any one to go to its own page.\n", /customizable|Build your own/i,
    () => /link\.textContent = "Open Agent";/.test(FILES[DIRECTORY]) && /var href = agent\.page_url \|\| "agents-hub\.html";/.test(FILES[DIRECTORY])]
];
BCOPY.forEach(([id, file, text, old, proof]) => {
  // agent-profile.js builds its copy in strings, so its whole source is the text checked
  const visible = file === AP ? FILES[file] : (FILES[file].match(/>[^<>]*</g) || []).join(" ");
  check("B. " + id + ": the new wording is there", FILES[file].indexOf(text) !== -1, text);
  check("B. " + id + ": the old untrue wording is gone from the page", !old.test(visible), (visible.match(old) || [""])[0]);
  check("B. " + id + ": what it names exists and what it says happens", proof());
  check("B. " + id + ": no watching or automatic claim", NO_CLAIM(text), text);
});

/* ── C. the Oct 14 audit, group 11, block B's leftovers, and the four new entries ── */
console.log("\n══ C. audit group 11, the leftovers, the Oracle's picker, and four new entries ══");
// The same four assertions as A and B. For a new tip there is no old wording, so the second assertion is that the
// entry makes none of the claims its page cannot back.
const ORACLE = "oracle.html", INDEX = "index.html", CHAT = "business-chat.html", CARDVIEW = "card-view.html", ADS = "ads-agent.html", EXEC = "executive-agent.html",
  VERT = "vertical-marketing-agent.html", SMS = "agents/sms.html";
const chatTips = tipsFor("business-chat.html"), cvTips = tipsFor("card-view.html"), orTips = tipsFor("oracle.html");
const adsTips = tipsFor("ads-agent.html"), exTips = tipsFor("executive-agent.html"), vmTips = tipsFor("vertical-marketing-agent.html"), smsTips = tipsFor("sms.html");
// A server slice: from a start marker to the first end marker after it ("" when the start is missing).
function svSlice(start, end) {
  const i = SV.indexOf(start); if (i === -1) return "";
  const j = SV.indexOf(end, i + start.length); return SV.slice(i, j === -1 ? SV.length : j);
}
const TASK_ROUTE = svSlice("async function handleAiTaskRequest(", "\napp."), LIVE_STATS = svSlice("async function getLiveStats(", "\n}\n"),
  TASK_COUNTS = svSlice("async function countTasksByAgent(", "\n}\n"), NOTES = svSlice("async function fetchSpecialistNotes(", "\n}\n");
const CHAT_POST = svSlice('app.post("/api/business-chat"', "\napp."), CHAT_GET = svSlice('app.get("/api/business-chat"', "\n});\n");
const ORACLE_POST = svSlice('app.post("/api/oracle",', "\napp.");
const EXEC_PLAN = svSlice('app.post("/api/agents/executive/plan"', "\napp."), DISPATCH = svSlice('app.post("/api/assignments/dispatch"', "\napp.");
const ADS_COPY = svSlice('app.post("/api/agents/ads/copy"', "\napp."), ADS_POLICY = svSlice('app.post("/api/agents/ads/policy-check"', "\napp.");
const VERT_POS = svSlice('app.post("/api/agents/vertical_marketing/positioning"', "\napp."), VERT_OBJ = svSlice('app.post("/api/agents/vertical_marketing/objections"', "\napp.");
const VERT_CLAIMS = svSlice('app.post("/api/agents/vertical_marketing/claims-scan"', "\n// ── Content Agent tools");
const ENGINE = svSlice("async function runDripEngine(userId) {", "\nasync function runDripForAllUsers()"), ENROLL = svSlice('app.post("/api/sms/campaigns/:id/enroll"', "\napp.");
const tablesRead = text => (text.match(/\.from\("(\w+)"\)/g) || []).map(m => /"(\w+)"/.exec(m)[1]).filter((t, i, a) => a.indexOf(t) === i).sort();
// What any agent task's prompt is built from: the Business Profile, counts, earlier runs and notes, and the request.
// No table that holds a lead or the pipeline is read.
const TASK_TABLES = tablesRead(TASK_ROUTE + LIVE_STATS + TASK_COUNTS + NOTES).join(",");
const NO_PIPELINE = () => TASK_TABLES === "agent_memory,ai_tasks,business_profiles,content_library,sms_campaigns,sms_subscribers,social_post_drafts" &&
  /buildAgentSystemPrompt\(agentBrain, businessProfile, liveStats, combinedMemoriesForBrain, specialistNotes\);/.test(TASK_ROUTE) &&
  /"\\n\\nUSER REQUEST:\\n" \+ userPrompt;/.test(TASK_ROUTE) && />Leads from Lead Radar<\/h2>/.test(FILES[SALES]);
const DOCX_ONLY = () => /"application\/vnd\.openxmlformats-officedocument\.wordprocessingml\.document": true, \/\/ \.docx/.test(SV) && !/application\/msword/.test(SV);
const C = [
  // group 11 — one-off tips
  ["11 analytics-dashboard 38", dashTips, "If a tile shows 0, there's nothing of that kind on your account yet", /hasn't loaded or hasn't been generated/,
    () => (FILES[DASH].match(/<span class="stat-number" id="stat\w+">—<\/span>/g) || []).length >= 6 &&
      /\.textContent\s+= s\.tasksRun\s+!= null \? s\.tasksRun\s+: "—";/.test(FILES[DASH]) &&
      (LIVE_STATS.match(/return result\.count \|\| 0;/g) || []).length === 2 && /Could not load analytics data\./.test(FILES[DASH])],
  ["11 business-id 89", idTips, "the card is drawn only on this page, for you — nothing on the platform shows it to other members", /first impression other members/,
    () => /function renderCard\(p\) \{/.test(FILES[BIZID]) && /fetch\(API_URL \+ "\/api\/profile\/me", \{\s*headers: \{ "Authorization": "Bearer " \+ token \}/.test(FILES[BIZID]) &&
      /app\.get\("\/api\/profile\/me", requireAuth,/.test(SV) && HTML_PAGES.filter(f => f !== BIZID && /id-card-watermark|BizForce AI Member/.test(FILES[f])).length === 0],
  ["11 business-chat 92", chatTips, "each answer is written from the last 20 messages of it", /remembers the conversation across sessions/,
    () => /role: "user",[\s\S]*?\.eq\("user_id", req\.user\.id\)\s*\.order\("created_at", \{ ascending: false \}\)\s*\.limit\(20\);[\s\S]*?role: "assistant",/.test(CHAT_POST)],
  ["11 business-chat 95", chatTips, "There is one thread, not a list of past threads", /Revisit past threads/,
    () => /\.eq\("user_id", req\.user\.id\)\s*\.order\("created_at", \{ ascending: true \}\);/.test(CHAT_GET) && !/\.limit\(/.test(CHAT_GET) &&
      !/thread_id|conversation_id/.test(CHAT_POST + CHAT_GET) && /data\.messages\.forEach\(function\(msg\) \{\s*addMessage\(msg\.role, msg\.content\);/.test(FILES[CHAT])],
  ["11 card-view 98", cvTips, "the card's QR codes hold a vCard contact, not a link to this page", /via a shared link or QR code/,
    () => [FILES[CARDVIEW], FILES[CARDS]].every(p => /QRCode\.toCanvas\(document\.getElementById\("qrCanvas"\), vcard \|\| "BizForce AI"/.test(p) &&
      /QRCode\.toCanvas\(document\.getElementById\("qrVideoCanvas"\), vcard \|\| "BizForce AI"/.test(p) && /"BEGIN:VCARD"/.test(p)) &&
      /new URLSearchParams\(window\.location\.search\)\.get\("token"\)/.test(FILES[CARDVIEW]) && /"https:\/\/bizforceai\.net\/card-view\.html\?token=" \+ st/.test(FILES[CARDS])],
  ["11 sales 118", salesTips, "its tasks read none of the leads or pipeline on this page", /revenue intelligence|from your business data/,
    () => NO_PIPELINE() && ["Sales Funnel", "Lead Generation", "Outreach Script", "Offer Builder", "Objection Handling"].every(n => offers(SALES, n))],
  ["11 sales 122", salesTips, "a task's prompt carries no pipeline data", /stale pipeline data/, NO_PIPELINE],
  ["11 content 129", conTips, "its saved articles and SMS campaigns", /delete drafts so your queue/,
    () => /fetch\(CL_API \+ "\/api\/content-library\?type=blog"/.test(FILES[CONTENT]) && /fetch\(CL_API \+ "\/api\/content-library\?type=sms"/.test(FILES[CONTENT]) &&
      ["data-expand=", "data-copy=", 'class=\\"cl-delete-btn\\"'].every(a => FILES[CONTENT].indexOf(a) !== -1) &&
      /fetch\(API \+ "\/api\/social-drafts"/.test(FILES[CONTENT]) && />Content Library<\/h2>/.test(FILES[CONTENT])],
  ["11 lead-radar 148", lrTips, "Product Breakdown counts leads, it does not measure intent", /pulling the most buying intent/,
    () => /productCounts\[p\] = \(productCounts\[p\] \|\| 0\) \+ 1;/.test(FILES[RADAR_PAGE]) &&
      /<span class=\\"chart-title\\">Product Breakdown<\/span>/.test(FILES[RADAR_PAGE]) && /<span class=\\"chart-title\\">Score Distribution<\/span>/.test(FILES[RADAR_PAGE])],
  ["11 broker 175", brTips, "they give you a checklist and a framework to take to a lawyer, not execution documents", /real execution documents/,
    () => ["Due Diligence Checklist", "Term Sheet Draft", "Term Sheet Framework"].every(n => offers(BROKER, n)) &&
      /A framework, not a legal document\./.test(FILES[BROKER]) && /"THIS IS A FRAMEWORK, NOT A LEGAL DOCUMENT, AND NO LAWYER HAS SEEN IT\./.test(SV) &&
      /Take this to a lawyer before/.test(SV) && /^Draft a term sheet framework/.test(taskPrompt("term_sheet")) && /^Build a due diligence checklist/.test(taskPrompt("due_diligence"))],
  ["11 rd 218", rdTips, "screen ideas by feasibility before you invest", /feasibility and impact/,
    () => offers(RD, "Innovation Brief") && /feasibility assessment/.test(taskPrompt("innovation_brief")) && !/impact/i.test(taskPrompt("innovation_brief"))],
  ["11 rd 219", rdTips, "the only earlier runs it sees are excerpts of your last 5 R&D runs", /summarize everything else/,
    () => offers(RD, "Executive Briefing") && (SV.match(/executive_briefing/g) || []).length === 2 &&
      /\.from\("ai_tasks"\)\s*\.select\("agent_type, prompt, result, status, created_at"\)\s*\.eq\("user_id", userId\)\s*\.eq\("agent_type", agentType\)\s*\.order\("created_at", \{ ascending: false \}\)\s*\.limit\(5\);/.test(TASK_ROUTE) &&
      /excerptWithMarker\(task\.result, PRIOR_TASK_RESULT_CAP\)/.test(TASK_ROUTE)],
  ["11 oracle 225", orTips, "PDFs, Word files (.docx only), plain text", /Word files(?! \(\.docx only\))/, DOCX_ONLY],
  ["11 oracle 226", orTips, "are fixed by your birth name and date and do not change with time", /sharpen with time/,
    () => /calculateLifePath\(oracleSync\.birth_date\)/.test(ORACLE_POST) && /calculateNameNumber\(oracleSync\.birth_name, false\)/.test(ORACLE_POST) &&
      /calculateNameNumber\(oracleSync\.birth_name, true\)/.test(ORACLE_POST) && /extractBirthday\(oracleSync\.birth_date\)/.test(ORACLE_POST) &&
      /"Current Location: " \+ \(oracleSync\.current_location/.test(ORACLE_POST) && /"Path & Focus: "\s+\+ \(oracleSync\.path_focus/.test(ORACLE_POST) &&
      /oracleSync\.life_details/.test(ORACLE_POST)]
];
// The four new entries. Each row's second field is what the whole entry must never claim.
const ADS_FALSE = /\b(manages?|optimi[sz]es?|launch(es)?|publish(es)?|runs?) (your )?(ads?|ad account|campaigns?|budget)\b|\bROAS\b|ad performance|connects? to your/i;
const EXEC_FALSE = /\b(assigns?|dispatch(es)?|launch(es)?|runs?) (the )?(tasks?|work|agents?|assignments?) (for you|on its own|itself)|coordinates all (the )?other agents/i;
const VERT_FALSE = /\bresearch(es|ed)? (the|your|this) (industry|market|vertical|trade)|real (market|industry) data|verified (terms|terminology)/i;
const SMS_FALSE = /\bsends? (your )?(texts?|messages?|SMS) (to|on)\b|automated drip|\bdelivers?\b|reach(es)? (your )?customers/i;
const ADS_ROUTES = () => (SV.match(/app\.post\("\/api\/agents\/ads\//g) || []).length === 2 && !/graph\.facebook\.com|googleads\.googleapis|adwords/i.test(SV);
const DRY = () => (SV.match(/var DRY_RUN = true;/g) || []).length === 1 && /var DRY_RUN = true;/.test(ENGINE);
const CN = [
  ["ads 1", adsTips, "it connects to no ad account and reads no ad results", ADS_FALSE,
    () => ADS_ROUTES() && offers(ADS, "Ad Campaign") && offers(ADS, "Ad Copy") && /buildAgentSystemPrompt\(adsBrain, businessProfile, \{\}, \[\]\)/.test(ADS_COPY)],
  ["ads 2", adsTips, "measures every asset against that platform's limits", ADS_FALSE,
    () => /HEADLINE:\s+\{ max: 30, kind: "hard",[\s\S]{0,200}?DESCRIPTION: \{ max: 90, kind: "hard",/.test(SV) &&
      /PRIMARY_TEXT: \{ max: 125, kind: "truncation",/.test(SV) && /function measureAdAsset\(assetType, text, spec\)/.test(SV) &&
      /"label": "Google Responsive Search Ad \(30 \/ 90, enforced\)"/.test(FILES[ADS]) && /"label": "Meta feed ad \(125 primary text, truncated\)"/.test(FILES[ADS])],
  ["ads 3", adsTips, "Ad Copy also runs what it writes through the policy scan", ADS_FALSE,
    () => /var policyFindings = scanAdPolicy\(assets\.map\(function \(a\) \{ return a\.text; \}\)\.join\("\\n"\)\);/.test(ADS_COPY)],
  ["ads 4", adsTips, "a clean scan is not approval, and with Suggest rewrites unchecked it makes no model call at all", ADS_FALSE,
    () => ["cure_or_treat_claims", "before_and_after", "guaranteed_results", "personal_attributes", "fda_disease_claims"].every(id => SV.indexOf('id: "' + id + '"') !== -1) &&
      /var wantRewrites = req\.body\.suggest_rewrites !== false;/.test(ADS_POLICY) && /if \(findings\.length && wantRewrites\) \{/.test(ADS_POLICY) &&
      /"A CLEAN SCAN IS NOT APPROVAL FROM ANYBODY\./.test(SV) && /"label": "Suggest rewrites"/.test(FILES[ADS]) && offers(ADS, "Policy Check")],
  ["ads 5", adsTips, "Use Ad Campaign for a whole plan", ADS_FALSE,
    () => /audience, offer, hooks, creative angles, copy, budget guidance, testing plan/.test(taskPrompt("ad_campaign")) && offers(ADS, "Ad Campaign")],
  ["executive 1", exTips, "it runs none of them itself", EXEC_FALSE,
    () => !!EXEC_PLAN && !/dispatchToolCall\(|handleAiTaskRequest\(/.test(EXEC_PLAN) && /'">Run this assignment<\/button>'/.test(AP_FILE) &&
      /return fetch\(API_URL \+ "\/api\/assignments\/dispatch", \{/.test(AP_FILE)],
  ["executive 2", exTips, "is checked against the tools that really exist", EXEC_FALSE,
    () => /is_dispatchable: !!toolExists && problems\.length === 0 && inputCheck\.missing\.length === 0/.test(EXEC_PLAN) && /<span>Not runnable<\/span>/.test(AP_FILE) &&
      offers(EXEC, "Executive Plan") && configOf(EXEC).tools[0].fields.map(f => f.label).join("|") === "The goal|Horizon|Constraints"],
  ["executive 3", exTips, "Begin with the Start here list", EXEC_FALSE,
    () => /'<div class="ap-zone-label">Start here<\/div>'/.test(AP_FILE) && /'<div class="ap-zone-label">Order<\/div>'/.test(AP_FILE) &&
      /Nothing can start yet — every assignment waits on another\./.test(AP_FILE) && /function orderExecutiveAssignments\(assignments\)/.test(SV) && /can_start_now: ordering\.waves\.length \? ordering\.waves\[0\] : \[\],/.test(EXEC_PLAN)],
  ["executive 4", exTips, "Assignments marked your own work are yours to do", EXEC_FALSE,
    () => /'<span class="ap-asg-yours">your own work<\/span>'/.test(AP_FILE) && /if \(a\.is_dispatchable !== true\) return planNotRunnableLine\(a\);/.test(AP_FILE) &&
      /YOU is not dispatchable and has no route/.test(SV)],
  ["executive 5", exTips, "only the Executive Plan tool's assignments can be run", EXEC_FALSE,
    () => /if \(row\.task_type !== "executive\/plan"\) \{\s*return dispatchRefusal\(res, "not_an_executive_plan",/.test(DISPATCH) && /taskType: "executive\/plan",/.test(EXEC_PLAN) &&
      ["Executive Command Plan", "Agent Coordination", "Executive Briefing", "KPI Review"].every(n => offers(EXEC, n))],
  ["vertical 1", vmTips, "nothing about the industry is researched", VERT_FALSE,
    () => /industry_research_performed: false,/.test(SV) && /web_search_performed: false/.test(SV) && /"NOTHING ABOUT THIS INDUSTRY WAS RESEARCHED\./.test(SV) &&
      (SV.match(/app\.post\("\/api\/agents\/vertical_marketing\//g) || []).length === 3 && !!VERT_CLAIMS && !/fetch\(|safeFetch|guardedFetch/.test(VERT_CLAIMS)],
  ["vertical 2", vmTips, "Vertical Positioning takes the industry", VERT_FALSE,
    () => /labels: \["POSITIONING", "TRADE_LANGUAGE", "CHANNELS", "WHAT_NOT_TO_SAY", "CONFIDENCE", "VERIFY_WITH_A_PRACTITIONER"\]/.test(VERT_POS) &&
      configOf(VERT).tools[0].label === "Vertical Positioning" && configOf(VERT).tools[0].fields.map(f => f.name + (f.required ? "*" : "")).join("|") === "industry*|offering|audience"],
  ["vertical 3", vmTips, "Objection Handling takes the industry and the offer", VERT_FALSE,
    () => /\["OBJECTION", "WHAT_IS_BEHIND_IT", "ANSWER", "PROOF_THAT_HELPS", "LIKELIHOOD"\]/.test(VERT_OBJ) && /\["CONFIDENCE", "VERIFY_WITH_A_PRACTITIONER"\]/.test(VERT_OBJ) &&
      /An industry is required — the vertical whose objections you want\./.test(VERT_OBJ) && /An offer is required — what is being sold to that industry\./.test(VERT_OBJ) && offers(VERT, "Objection Handling")],
  ["vertical 4", vmTips, "the model's own estimate of how well it knows the trade, not a measurement", VERT_FALSE,
    () => /treat the confidence level below as the model's own estimate of its recall/.test(SV) && /Have a practitioner read this before/.test(SV)],
  ["vertical 5", vmTips, "Vertical Campaign Plan, for one, runs the creator-partnership campaign instruction", VERT_FALSE,
    () => /\{ value: "campaign_plan",\s+label: "Vertical Campaign Plan" \}/.test(FILES[VERT]) && /partner selection criteria/.test(taskPrompt("campaign_plan")) && /usage rights/.test(taskPrompt("campaign_plan"))],
  ["vertical 6", vmTips, "Claims Scan runs the supplement claim rules and the ad-policy rules over copy you paste", VERT_FALSE,
    () => !!VERT_CLAIMS && !/callAnthropicText\(|toolGenerateWithOneRetry\(/.test(VERT_CLAIMS) && /model_call_made: false,/.test(VERT_CLAIMS) &&
      /statement: AD_POLICY_NOT_APPROVAL,/.test(VERT_CLAIMS) && /function claimsScanText\(profile, text, cautions\)/.test(SV) && /scanAdPolicy\(scanned\)/.test(SV) &&
      /complianceRequiredTextPresent\(profile, whole\)/.test(SV) && offers(VERT, "Claims Scan") &&
      /"checkboxLabel": "Also scan everything I've stored on BizForce"/.test(FILES[VERT])],
  ["sms 1", smsTips, "This page is not an agent", SMS_FALSE,
    () => !/agents\/sms\.html/.test(svSlice("const AGENT_PAGE_URLS = {", "\n};")) && !/AGENT_PROFILE_CONFIG/.test(FILES[SMS]) &&
      ['id="sms-add-btn" class="sms-add-btn">Add<', 'id="sms-bulk-btn" class="sms-add-btn">Import<', 'id="sms-camp-create-btn" class="sms-add-btn">Create<',
       'id="sms-msg-add-btn" class="sms-add-btn">Add Message<', 'id="enroll-all-btn" class="sms-ghost-btn">Enroll All Subscribers<'].every(b => FILES[SMS].indexOf(b) !== -1)],
  ["sms 2", smsTips, "the first message's delay is not used", SMS_FALSE,
    () => /var delayHours = \(msgs\[newStep\]\.delay_hours != null \? msgs\[newStep\]\.delay_hours : 0\);\s*var nextDate = new Date\(Date\.now\(\) \+ delayHours \* 60 \* 60 \* 1000\);/.test(ENGINE) &&
      /if \(enrollment\.next_send_at && new Date\(enrollment\.next_send_at\) > new Date\(\)\) \{/.test(ENGINE) && !!ENROLL && !/next_send_at/.test(ENROLL) &&
      /<span class="sms-msg-field-label">Delay \(hours\)<\/span>/.test(FILES[SMS])],
  ["sms 3", smsTips, "The drip engine is fixed in dry-run mode", SMS_FALSE,
    () => DRY() && /status:\s+DRY_RUN \? "dry_run" : "sent",/.test(ENGINE) && /twilio_sid:\s+null,/.test(ENGINE) && !/twilio\.|messages\.create|api\.twilio/i.test(ENGINE) &&
      /id="run-engine-btn" class="sms-ghost-btn">Run Drip Engine \(Dry Run\)</.test(FILES[SMS]) && /"Sent: "\s+\+ \(r\.sent/.test(FILES[SMS]) && />Send Log</.test(FILES[SMS])],
  ["sms 4", smsTips, "A dry run moves no enrollment forward", SMS_FALSE,
    () => DRY() && /if \(DRY_RUN\) \{[\s\S]{0,600}?summary\.sent\+\+;\s*continue;\s*\}\s*var \{ error: advanceErr \} = await supabase\s*\.from\("sms_campaign_enrollments"\)\s*\.update\(\{ current_step: newStep, next_send_at: nextSendAt \}\)/.test(ENGINE)],
  ["sms 5", smsTips, "direct SMS sending is shut on this platform", SMS_FALSE,
    () => /\nconst SMS_DIRECT_SEND_ENABLED = false;/.test(SV) && /if \(!SMS_DIRECT_SEND_ENABLED\) \{\s*return res\.status\(503\)/.test(SV) &&
      /subscriber\.consent_status !== "opted_in"/.test(ENGINE) && !/\/api\/sms\/send["']/.test(FILES[SMS])]
];
C.forEach(([id, tips, fragment, old, proof]) => {
  const t = tipWith(tips, fragment);
  check("C. " + id + ": the new wording is there", !!t, fragment);
  check("C. " + id + ": the old untrue wording is gone from the whole entry", tips.every(x => !old.test(x)), tips.filter(x => old.test(x)).join(" | "));
  check("C. " + id + ": what it names exists and what it says happens", !!t && proof());
  check("C. " + id + ": no watching or automatic claim", !!t && NO_CLAIM(t), t);
});
check("C. the four new entries have 4–5 tips each, and the vertical entry exactly 6 with Claims Scan", [adsTips, exTips, smsTips].every(t => t.length >= 4 && t.length <= 5) && vmTips.length === 6,
  [adsTips, exTips, vmTips, smsTips].map(t => t.length).join(","));
CN.forEach(([id, tips, fragment, never, proof]) => {
  const t = tipWith(tips, fragment);
  check("C. new " + id + ": the new wording is there", !!t, fragment);
  check("C. new " + id + ": the entry makes none of the claims its page cannot back", tips.length > 0 && tips.every(x => !never.test(x)), tips.filter(x => never.test(x)).join(" | "));
  check("C. new " + id + ": what it names exists and what it says happens", !!t && proof());
  check("C. new " + id + ": no watching or automatic claim", !!t && NO_CLAIM(t), t);
});
check("C. every tip of the four new entries is covered by a row above", [["ads", adsTips], ["executive", exTips], ["vertical", vmTips], ["sms", smsTips]].every(([p, tips]) =>
  tips.every(t => CN.some(r => r[0].indexOf(p + " ") === 0 && t.indexOf(r[2]) !== -1))));

console.log("\n── C. page copy ──");
const INSIGHT_ORACLE = (/var PAGE_INSIGHT = \{\s*"oracle\.html":\s*"((?:[^"\\]|\\.)*)"/.exec(FILES[GUIDE]) || ["", ""])[1];
const visibleOf = f => (FILES[f].match(/>[^<>]*</g) || []).join(" ");
const CCOPY = [
  // [id, the text checked, the new text as it stands, old untrue wording (absent from that text), proof]
  ["11 oracle insight: no comparable platform", () => INSIGHT_ORACLE, "a numerology-grounded advisory layer. For businesses", /no comparable platform offers/, () => true],
  ["11 oracle insight: Word files", () => INSIGHT_ORACLE, "contracts, PDFs, Word (.docx) files, images", /Word files/, DOCX_ONLY],
  ["B-left wallet.html certification card", () => visibleOf(WALLET), "<strong>+100 BFC per cert</strong>Paid for your first pass of each certification, while you're subscribed</div>",
    /Pass any certification quiz/, () => CERT_CREDIT.test(SV)],
  ["B-left wallet.html welcome card", () => visibleOf(WALLET), "<strong>+1,000 BFC bonus</strong>One-time welcome bonus, paid when your subscription goes active</div>",
    /welcome credit for new members/, () => WELCOME() && ONLY_TWO_CREDITS()]
];
CCOPY.forEach(([id, where, text, old, proof]) => {
  const src = id.indexOf("wallet") !== -1 ? FILES[WALLET] : where();
  check("C. " + id + ": the new wording is there", src.indexOf(text) !== -1, text);
  check("C. " + id + ": the old untrue wording is gone", !old.test(where()), (where().match(old) || [""])[0]);
  check("C. " + id + ": what it names exists and what it says happens", proof());
  check("C. " + id + ": no watching or automatic claim", NO_CLAIM(text), text);
});

check("C. no text on oracle.html offers .doc", !/\.doc\b/.test(FILES[ORACLE]), (FILES[ORACLE].match(/.{0,40}\.doc\b.{0,20}/) || [""])[0]);

/* ── D. Block C's leftovers: three subtitles, the Oracle's uploads, and a stale comment ── */
console.log("\n══ D. three subtitles, the Oracle's uploads, and the vertical marketing comment ══");
// The three subtitles, with A's four assertions each. "old" is tested against the page's visible text.
const ALLOWED_TYPES = vm.runInNewContext((/\nvar allowedTaskTypes = (\[[^\]]*\]);/.exec(SV) || ["", "[]"])[1]);
const SMS_SUB = "SMS subscribers and consent, drip campaigns built message by message, enrollment, and a dry-run log of what would go out — no text is sent.";
const D = [
  ["agents/sms.html subtitle", SMS, '<p class="agent-subtitle">' + SMS_SUB + "</p>", /Reach customers|targeted SMS sequences|automated drip/i,
    () => /id="sms-add-btn"/.test(FILES[SMS]) && /id="sms-bulk-btn"/.test(FILES[SMS]) && /<select id="sms-add-consent">/.test(FILES[SMS]) &&
      /id="sms-camp-create-btn"/.test(FILES[SMS]) && /id="sms-msg-add-btn"/.test(FILES[SMS]) && /id="enroll-all-btn"/.test(FILES[SMS]) && !!ENROLL &&
      />Run Drip Engine \(Dry Run\)<\/button>/.test(FILES[SMS]) && DRY() && /status:\s+DRY_RUN \? "dry_run" : "sent",/.test(ENGINE) &&
      /\nconst SMS_DIRECT_SEND_ENABLED = false;/.test(SV)],
  ["ads-agent.html subtitle", ADS, '<p class="agent-subtitle">Ad campaigns, audience growth, ad copy, and policy checks.</p>', /performance intelligence|paid traffic/i,
    () => ["Ad Campaign", "Audience Growth", "Ad Copy", "Policy Check"].every(n => offers(ADS, n)) && !!ADS_COPY && !!ADS_POLICY &&
      ["ad_campaign", "audience_growth"].every(t => ALLOWED_TYPES.indexOf(t) !== -1)],
  ["executive-agent.html subtitle", EXEC, '<p class="agent-subtitle">Executive plans of assignments for the other agents, plus coordination, briefings, and KPI reviews.</p>',
    /oversight intelligence|Cross-agent coordination, reporting/i,
    () => ["Executive Plan", "Agent Coordination", "Executive Briefing", "KPI Review"].every(n => offers(EXEC, n)) && !!EXEC_PLAN &&
      ["executive_plan", "agent_coordination", "executive_briefing", "kpi_review"].every(t => ALLOWED_TYPES.indexOf(t) !== -1)]
];
D.forEach(([id, file, text, old, proof]) => {
  const visible = (FILES[file].match(/>[^<>]*</g) || []).join(" ");
  check("D. " + id + ": the new wording is there", FILES[file].indexOf(text) !== -1, text);
  check("D. " + id + ": the old untrue wording is gone from the page", !old.test(visible), (visible.match(old) || [""])[0]);
  check("D. " + id + ": what it names is offered by the page and its routes", proof());
  check("D. " + id + ": no watching or automatic claim", NO_CLAIM(text), text);
});
// agents/sms.html has no index.html card (G6 covers ads and executive); its card is on dashboard.html.
const SMS_CARD = (/<div class="bf-feature-card card bf-card" data-card="sms-drip"[^>]*>[\s\S]*?<h3>SMS Drip<\/h3>\s*<p>([^<]*)<\/p>/.exec(FILES["dashboard.html"]) || ["", ""])[1];
check("D. dashboard.html's SMS Drip card says what agents/sms.html's subtitle says", !!SMS_CARD && SMS_CARD === subtitle(SMS), SMS_CARD);
check("D. no page anywhere still carries the three old subtitles",
  HTML_PAGES.filter(f => !/^oracle\.backup/.test(f) && /Reach customers directly with targeted SMS|advertising performance intelligence|executive oversight intelligence/.test(FILES[f])).length === 0,
  HTML_PAGES.filter(f => /Reach customers directly with targeted SMS|advertising performance intelligence|executive oversight intelligence/.test(FILES[f])).join(", "));

// vertical-marketing-agent.html's config comment: true of allowedTaskTypes and taskInstructions.
const VERT_COMMENT = (/\n  \/\* Every value below[\s\S]*?\*\//.exec(FILES[VERT]) || [""])[0];
const VERT_CFG = configOf(VERT);
check("D. the vertical marketing comment says the three types are listed but have no instruction of their own",
  /allowedTaskTypes also lists vertical_positioning, channel_research and\s+objection_handling, but none of the three has an instruction of its own in\s+taskInstructions/.test(VERT_COMMENT), VERT_COMMENT.slice(0, 200));
check("D. the vertical marketing comment no longer says they do not exist, or points at a stale line number",
  !!VERT_COMMENT && !/do NOT exist|no vertical or industry|server\.js:\d/.test(VERT_COMMENT), (VERT_COMMENT.match(/do NOT exist|server\.js:\d+/) || [""])[0]);
check("D. what the comment says is so: all three listed, none in taskInstructions, every dropdown value listed, the two named stand-ins have instructions, both tools have routes",
  ["vertical_positioning", "channel_research", "objection_handling"].every(t => ALLOWED_TYPES.indexOf(t) !== -1 && taskPrompt(t) === "") &&
    VERT_CFG.taskTypes.length > 0 && VERT_CFG.taskTypes.every(t => ALLOWED_TYPES.indexOf(t.value) !== -1) &&
    ["brand_narrative", "content_plan"].every(t => VERT_CFG.taskTypes.some(x => x.value === t) && taskPrompt(t) !== "") &&
    /var taskInstruction = taskInstructions\[taskType\] \|\| taskInstructions\["general"\];/.test(SV) &&
    ["positioning", "objections"].every(id => (VERT_CFG.tools || []).some(t => t.id === id)) && !!VERT_POS && !!VERT_OBJ);

// The Oracle's uploads. oracle.html's ORACLE_UPLOAD_TYPES is the ONE list: the picker's accept list and the filter on
// every picked or dropped file are built from it, and the server's tables must equal it. Both sides are RUN: the page's
// attach block in a stub DOM, the server's fileFilter through a stub multer.
const ORACLE_TYPES = vm.runInNewContext((/\n    var ORACLE_UPLOAD_TYPES = (\[[\s\S]*?\n    \]);/.exec(FILES[ORACLE]) || ["", "[]"])[1]);
const TYPE_EXTS = ORACLE_TYPES.map(t => t.ext), TYPE_MIMES = ORACLE_TYPES.map(t => t.mime).filter((m, i, a) => a.indexOf(m) === i);
check("D. oracle.html's ORACLE_UPLOAD_TYPES was read: 10 extensions, 9 types", TYPE_EXTS.length === 10 && TYPE_MIMES.length === 9, TYPE_EXTS.join(","));
const ATTACH_SRC = (() => {
  const t = FILES[ORACLE], i = t.indexOf("    /* ── File attach"), j = t.indexOf("    function setLoading(", i);
  return i === -1 || j === -1 ? "" : t.slice(i, j);
})();
// One run of the attach block: picked or dropped files go in, then a message is sent; returns what the request carried.
function oracleAttachRun(how, names) {
  const el = id => ({ id, textContent: "", innerHTML: "", value: "", accept: "", disabled: false, files: null, listeners: {},
    classList: { add() {}, remove() {}, toggle() {} }, addEventListener(t, f) { this.listeners[t] = f; },
    appendChild() {}, setAttribute() {}, click() {}, remove() {}, scrollTop: 0, scrollHeight: 0 });
  const els = {}, sent = [];
  const ctx = {
    document: { getElementById: id => els[id] || (els[id] = el(id)), createElement: () => el("") },
    messageArea: el("messageArea"), chatInput: el("chatInput"), sendBtn: el("sendBtn"), token: "t", API_URL: "https://api.test",
    chatHistory: [], appendMsg() {}, setLoading() {}, String, Math,
    FormData: function () { this.parts = []; this.append = (k, v) => { this.parts.push([k, v]); }; },
    fetch: (url, opts) => { sent.push({ url, parts: opts.body.parts }); return new Promise(() => {}); }
  };
  try { vm.runInNewContext(ATTACH_SRC, ctx); } catch (e) { return { error: e.message }; }
  const files = names.map(n => ({ name: n }));
  try {
    if (how === "drop") ctx.messageArea.listeners.drop({ preventDefault() {}, dataTransfer: { files } });
    else { els.attachFileInput.files = files; els.attachFileInput.listeners.change(); }
    ctx.chatInput.value = "read these";
    ctx.sendMessage();
  } catch (e) { return { error: e.message }; }
  const req = sent[0] || { url: "", parts: [] };
  return { accept: els.attachFileInput.accept, notice: els.attachNotice ? els.attachNotice.textContent : "",
    url: req.url, sentFiles: req.parts.filter(p => p[0] === "files").map(p => p[1].name) };
}
const OTHER_EXTS = [".doc", ".svg", ".exe", ".html", ".zip", ".csv.exe", ""];
const dropTakes = ext => { const r = oracleAttachRun("drop", ["file" + ext]); return !r.error && r.sentFiles.length === 1; };
const DROP1 = oracleAttachRun("drop", ["notes.doc", "Brief.PDF"]);
check("D. oracle.html's file input carries no accept list of its own; the page sets it from ORACLE_UPLOAD_TYPES",
  /<input type="file" id="attachFileInput" multiple style="display:none;" \/>/.test(FILES[ORACLE]) && !/id="attachFileInput"[^>]*accept=/.test(FILES[ORACLE]) &&
  !DROP1.error && DROP1.accept === TYPE_EXTS.join(","), DROP1.error || DROP1.accept);
check("D. a dropped .doc is not sent; the .pdf dropped with it is", !DROP1.error && DROP1.url === "https://api.test/api/oracle" &&
  JSON.stringify(DROP1.sentFiles) === '["Brief.PDF"]', DROP1.error || JSON.stringify(DROP1));
check("D. the refusal is a plain message naming the file and every accepted type",
  !DROP1.error && /^Not attached: notes\.doc\. The Oracle accepts /.test(DROP1.notice) && TYPE_EXTS.every(x => DROP1.notice.indexOf(x) !== -1), DROP1.notice);
const PICK1 = oracleAttachRun("pick", ["notes.doc", "data.csv"]);
check("D. the picker's files pass the same filter: a picked .doc is not sent, a .csv is",
  !PICK1.error && JSON.stringify(PICK1.sentFiles) === '["data.csv"]' && /notes\.doc/.test(PICK1.notice), PICK1.error || JSON.stringify(PICK1));
const dropWrong = TYPE_EXTS.filter(x => !dropTakes(x) || !dropTakes(x.toUpperCase())).concat(OTHER_EXTS.filter(dropTakes));
check("D. the drop filter takes exactly the list's extensions (any case) and nothing else", dropWrong.length === 0, dropWrong.join(","));

// The server: its tables and its fileFilter, run through a stub multer.
const UPLOAD_SRC = svSlice("var ORACLE_UPLOAD_ALLOWED_MIME = {", "\n// Extracts plain text");
const SVU = { multer: Object.assign(o => o, { memoryStorage: () => ({}) }) };
let svuError = "";
try { vm.runInNewContext(UPLOAD_SRC, SVU); } catch (e) { svuError = e.message; }
// POST /api/oracle has its own multer, oracleChatUpload; the shared oracleUpload (marketplace, BizBook, covers, editor) keeps its MIME-only filter.
const FILTER = SVU.oracleChatUpload && SVU.oracleChatUpload.fileFilter;
const SHARED_FILTER = SVU.oracleUpload && SVU.oracleUpload.fileFilter;
function serverTakes(name, mime) {
  if (!FILTER) return { ok: false, err: "no filter" };
  const file = { originalname: name, mimetype: mime }; let out = { ok: false, err: "no callback" };
  FILTER({}, file, (err, ok) => { out = err ? { ok: false, err: err.message } : { ok: !!ok, as: file.mimetype }; });
  return out;
}
const SV_ALLOWED = Object.keys(SVU.ORACLE_UPLOAD_ALLOWED_MIME || {}).filter(k => SVU.ORACLE_UPLOAD_ALLOWED_MIME[k] === true);
const SV_EXT = SVU.ORACLE_UPLOAD_EXT_MIME || {};
check("D. the server's upload rule was read and runs: 9 allowed types, 10 extensions, each extension's type among the nine",
  !svuError && !!FILTER && SV_ALLOWED.length === 9 && Object.keys(SV_EXT).length === 10 && Object.keys(SV_EXT).every(x => SV_ALLOWED.indexOf(SV_EXT[x]) !== -1),
  svuError || SV_ALLOWED.join(","));
check("D. the server's extension table equals ORACLE_UPLOAD_TYPES pair for pair, and its allowed types are exactly the list's types",
  JSON.stringify(Object.keys(SV_EXT).sort().map(x => x + "=" + SV_EXT[x])) === JSON.stringify(ORACLE_TYPES.map(t => t.ext + "=" + t.mime).sort()) &&
  JSON.stringify(SV_ALLOWED.slice().sort()) === JSON.stringify(TYPE_MIMES.slice().sort()));
const refusedByServer = ORACLE_TYPES.filter(t => { const r = serverTakes("file" + t.ext, t.mime); return !r.ok || r.as !== t.mime; });
check("D. the server takes every file the picker and the drop filter take, labelled with its own type", refusedByServer.length === 0,
  refusedByServer.map(t => t.ext).join(","));
// The standard label of each other extension, for the three-way agreement.
const OTHER_LABEL = { ".doc": "application/msword", ".svg": "image/svg+xml", ".exe": "application/x-msdownload", ".html": "text/html",
  ".zip": "application/zip", ".csv.exe": "application/x-msdownload", "": "application/octet-stream" };
const disagree = ORACLE_TYPES.map(t => [t.ext, t.mime]).concat(OTHER_EXTS.map(x => [x, OTHER_LABEL[x]]))
  .filter(([x, m]) => dropTakes(x) !== serverTakes("file" + x, m).ok || dropTakes(x) !== (TYPE_EXTS.indexOf(x) !== -1));
check("D. the picker, the drop filter and the server agree on every extension, listed or not", disagree.length === 0, disagree.map(d => d[0] || "(none)").join(","));
const XLS = serverTakes("Q3 numbers.csv", "application/vnd.ms-excel"), MD0 = serverTakes("notes.md", "");
check("D. the server accepts .csv sent as application/vnd.ms-excel, and parses it as text/csv", XLS.ok && XLS.as === "text/csv", JSON.stringify(XLS));
check("D. the server accepts .md with an empty MIME, and parses it as text/markdown", MD0.ok && MD0.as === "text/markdown", JSON.stringify(MD0));
const ALIASES_OK = [["a.csv", "text/plain"], ["a.csv", "application/octet-stream"], ["a.csv", ""], ["a.md", "text/x-markdown"], ["a.md", "text/plain"],
  ["a.md", "application/octet-stream"], ["A.CSV", "application/vnd.ms-excel"]].filter(([n, m]) => { const r = serverTakes(n, m); return !r.ok || r.as !== (/\.csv$/i.test(n) ? "text/csv" : "text/markdown"); });
check("D. every other alias the rule names for .csv and .md is accepted", ALIASES_OK.length === 0, ALIASES_OK.map(a => a.join(" as ")).join(", "));
const STILL_REFUSED = [["a.doc", "application/msword"], ["a.doc", "text/plain"], ["a.doc", "application/octet-stream"], ["a.svg", "image/svg+xml"],
  ["a.svg", "image/png"], ["a.csv", "image/png"], ["a.md", "image/png"], ["a.txt", "application/octet-stream"], ["a.pdf", ""]]
  .filter(([n, m]) => { const r = serverTakes(n, m); return r.ok || !/^Unsupported file type: /.test(r.err || ""); });
check("D. the server still refuses .doc, .svg and a .csv labelled image/png (and gives no other extension an alias)", STILL_REFUSED.length === 0,
  STILL_REFUSED.map(a => a.join(" as ")).join(", "));
// Never wider than the nine: over a grid of names and labels, an accepted file is always labelled one of the nine, a name
// with an extension outside the table is never accepted, and only .csv and .md take a label that is not their own.
const GRID_MIMES = SV_ALLOWED.concat(["application/msword", "image/svg+xml", "application/vnd.ms-excel", "text/x-markdown", "application/octet-stream", "",
  "text/html", "application/zip", "application/x-msdownload", "constructor", "toString"]);
const GRID_NAMES = TYPE_EXTS.concat(OTHER_EXTS).map(x => "file" + x).concat(["constructor", ".constructor", "a.constructor", "a.__proto__"]);
// The aliases as the rule is written (the report quotes it); the server may take no other label for a listed extension.
const RULE_ALIASES = { ".csv": ["application/vnd.ms-excel", "text/plain", "application/octet-stream", ""], ".md": ["text/x-markdown", "text/plain", "application/octet-stream", ""] };
const wide = [];
GRID_NAMES.forEach(n => GRID_MIMES.forEach(m => {
  const r = serverTakes(n, m); if (!r.ok) return;
  const dot = n.lastIndexOf("."), x = dot === -1 ? "" : n.slice(dot).toLowerCase();
  const fine = SV_ALLOWED.indexOf(r.as) !== -1 && (x === "" ? m === r.as : (SV_EXT[x] === r.as && (m === r.as || (RULE_ALIASES[x] || []).indexOf(m) !== -1)));
  if (!fine) wide.push(n + " as " + JSON.stringify(m) + " -> " + r.as);
}));
check("D. over " + GRID_NAMES.length * GRID_MIMES.length + " name/label pairs the server accepts nothing outside the nine types and no alias but .csv's and .md's",
  GRID_NAMES.length * GRID_MIMES.length > 300 && wide.length === 0, wide.join(" | "));
check("D. POST /api/oracle uploads through oracleChatUpload, and no other route does",
  (SV.match(/oracleChatUpload\.(array|single|fields)\(/g) || []).length === 1 &&
  /app\.post\("\/api\/oracle", requireAuth, requireActiveSubscription, oracleChatUpload\.array\("files", 8\), async function/.test(SV));
const sharedTakes = (name, mime) => { let ok = null; if (SHARED_FILTER) SHARED_FILTER({}, { originalname: name, mimetype: mime }, (err, y) => { ok = !err && !!y; }); return ok; };
const sharedWrong = SV_ALLOWED.map(m => ["x.bin", m, true]).concat([["cover.jfif", "image/jpeg", true], ["a.png", "image/jpeg", true], ["blob", "image/png", true],
  ["a.csv", "application/vnd.ms-excel", false], ["a.md", "", false], ["a.doc", "application/msword", false], ["a.svg", "image/svg+xml", false]])
  .filter(([n, m, want]) => sharedTakes(n, m) !== want);
check("D. the shared oracleUpload the other five routes use still decides by MIME type alone, exactly as before", !!SHARED_FILTER && sharedWrong.length === 0,
  sharedWrong.map(a => a[0] + " as " + a[1]).join(", "));
check("D. size, storage and the parser are unchanged: 20MB, 8 files, memory storage, parsed by type, in both multers",
  (UPLOAD_SRC.match(/storage: multer\.memoryStorage\(\),\s*limits: \{\s*fileSize: 20 \* 1024 \* 1024, \/\/ 20MB per file\s*files: 8\s*\},/g) || []).length === 2 &&
  /if \(file\.mimetype === "text\/plain" \|\| file\.mimetype === "text\/markdown" \|\| file\.mimetype === "text\/csv"\) \{/.test(SV));

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
// Its one entry was app.html's "history live under one account"; that entry is gone (the guide never displays there).
const LIVE_ALLOWED = [];
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

// G3, widened: "automatically", "instantly" and "auto-" claims, over every tip. Each allowed use is listed with the
// mechanism that makes it true, asserted in code; any other use fails. None is allowed today.
const AUTO = /\bautomatic(ally)?\b|\binstant(ly)?\b|\bauto-/i;
const AUTO_ALLOWED = [];
const autoHits = ALL.filter(x => AUTO.test(x.t) && !AUTO_ALLOWED.some(a => a.key === x.key && x.t.indexOf(a.phrase) !== -1 &&
  !AUTO.test(x.t.split(a.phrase).join("")) && a.proof()));
check("G3. no tip says automatically, instantly or auto- unless allowlisted with its mechanism",
  autoHits.length === 0, autoHits.map(x => x.key + "#" + x.i + ": " + x.t.slice(0, 90)).join(" | "));
check("G3. the automatic-claim allowlist is not stale: each allowed phrase is still in its tip and its mechanism holds",
  AUTO_ALLOWED.every(a => tipsFor(a.key).some(t => t.indexOf(a.phrase) !== -1) && a.proof()));

// G4. No tip states a BFC amount that is not a constant or a label in server.js or wallet.html. An amount is a number
// written with a plus sign ("+50") or followed by BFC ("1,000 BFC"), in any tip.
const num = s => Number(String(s).replace(/,/g, ""));
const BFC_KNOWN = [];
[[SV, /await creditWallet\([^,]+,\s*(\d+),/g], [SV, /\nconst WELCOME_BONUS_BFC = (\d+);/g], [FILES[WALLET], /<strong>\+([\d,]+) BFC/g]].forEach(([text, re]) => {
  let m; while ((m = re.exec(text))) if (BFC_KNOWN.indexOf(num(m[1])) === -1) BFC_KNOWN.push(num(m[1]));
});
check("G4. the BFC amounts were read from the code: the certification credit, the welcome bonus and the wallet's labels (100 and 1000)",
  BFC_KNOWN.slice().sort((a, b) => a - b).join(",") === "100,1000", BFC_KNOWN.join(","));
const amountsIn = t => (t.match(/\+\s?\d[\d,]*|\b\d[\d,]*\s*BFC\b/g) || []).map(a => num(a.replace(/[+\sA-Z]/g, "")));
const bfcHits = ALL.filter(x => amountsIn(x.t).some(a => BFC_KNOWN.indexOf(a) === -1));
check("G4. no tip states a BFC amount that is not a constant or label in server.js or wallet.html",
  bfcHits.length === 0, bfcHits.map(x => x.key + "#" + x.i + " " + amountsIn(x.t).join(",")).join(" | "));
check("G4. the amount reader finds the wallet tip's 100 and 1,000 (so a passing G4 read something)",
  walTips.some(t => amountsIn(t).join(",") === "100,1000"));
// G5. Every page that loads the guide AND is a registered agent page (the 18 AGENT_SYSTEM_PROMPTS keys, through
// AGENT_PAGE_URLS), plus agents/sms.html, has its own entry; and no entry, in PAGE_GUIDANCE or PAGE_INSIGHT, is for a
// page where the guide never displays — one that does not load it, or one the guide's own early return skips. The
// keys are read from the guide as it stands after any mutation, not from GUIDE_KEYS above.
const objectPairs = name => {
  const out = {}; svSlice("\nconst " + name + " = {", "\n};").split("\n").forEach(l => { const m = /^\s*(\w+):\s*"([^"]+)"/.exec(l); if (m) out[m[1]] = m[2]; });
  return out;
};
const PROMPT_KEYS = Object.keys(objectPairs("AGENT_SYSTEM_PROMPTS")), PAGE_URLS = objectPairs("AGENT_PAGE_URLS"), DISPLAY = objectPairs("AGENT_DISPLAY_NAMES");
check("G5. the registry was read: 18 agent types, each with a page URL and a display name, and no other URL",
  PROMPT_KEYS.length === 18 && PROMPT_KEYS.every(k => PAGE_URLS[k] && DISPLAY[k]) && Object.keys(PAGE_URLS).length === 18,
  PROMPT_KEYS.length + " types, " + Object.keys(PAGE_URLS).length + " URLs");
const GUIDE_TAG = /<script src="\/scripts\/termaximus-guide\.js"><\/script>/;
const EARLY = (/var _tmxLogin = [^;\n]*?\|\| (\/[^\n]*?\/)\.test\(_tmxPath\);/.exec(FILES[GUIDE]) || ["", ""])[1];
const EARLY_RE = EARLY ? vm.runInNewContext(EARLY) : null;
const guideShows = f => !!FILES[f] && GUIDE_TAG.test(FILES[f]) && !!EARLY_RE && !EARLY_RE.test("/" + f.toLowerCase());
check("G5. the guide's early return was read: it never displays on app.html, and does on every agent page",
  !!EARLY_RE && EARLY_RE.test("/app.html") && !EARLY_RE.test("/ads-agent.html"), EARLY);
const NEED = Object.keys(PAGE_URLS).map(k => PAGE_URLS[k]).concat(SMS);
const KEYS_NOW = (FILES[GUIDE].match(/\n    "([a-z0-9-]+\.html)": \[/g) || []).map(m => /"([^"]+)"/.exec(m)[1]);
const INSIGHT_KEYS = ((/var PAGE_INSIGHT = \{([\s\S]*?)\n  \};/.exec(FILES[GUIDE]) || ["", ""])[1].match(/\n    "([a-z0-9-]+\.html)":/g) || []).map(m => /"([^"]+)"/.exec(m)[1]);
check("G5. all 18 agent pages and agents/sms.html load the guide, and it displays on each",
  NEED.length === 19 && NEED.every(guideShows), NEED.filter(f => !guideShows(f)).join(", "));
const noEntry = NEED.filter(f => !KEYS_NOW.some(k => fileOfKey(k) === f));
check("G5. every agent page, and agents/sms.html, has its own guide entry", noEntry.length === 0, noEntry.join(", "));
const neverShown = KEYS_NOW.concat(INSIGHT_KEYS).filter(k => !guideShows(fileOfKey(k)));
check("G5. no guide entry exists for a page where the guide never displays", KEYS_NOW.length > 0 && neverShown.length === 0, neverShown.join(", "));

// G6. Every agent card on index.html carries the subtitle that agent's own page carries, so the two cannot drift. A
// card is matched to its agent by its heading and AGENT_DISPLAY_NAMES (the hub's names).
const CARDS_IDX = [];
{
  const grid = (/<section class="section" id="agents">[\s\S]*?<div class="agent-grid">([\s\S]*?)\n    <\/div>\n  <\/section>/.exec(FILES[INDEX]) || ["", ""])[1];
  const re = /<div class="bf-card">\s*<h3>([^<]+)<\/h3>\s*<p>([^<]*)<\/p>\s*<\/div>/g; let m;
  while ((m = re.exec(grid))) CARDS_IDX.push({ name: m[1].replace(/&amp;/g, "&"), sub: m[2] });
}
const typeOfName = n => PROMPT_KEYS.filter(k => DISPLAY[k] === n)[0];
check("G6. index.html's agent grid was read: 18 cards, one per agent type",
  CARDS_IDX.length === 18 && PROMPT_KEYS.every(k => CARDS_IDX.filter(c => typeOfName(c.name) === k).length === 1), CARDS_IDX.map(c => c.name).join(", "));
const drift = CARDS_IDX.filter(c => { const k = typeOfName(c.name); return !k || !subtitle(PAGE_URLS[k]) || subtitle(PAGE_URLS[k]) !== c.sub; });
check("G6. every index.html agent card subtitle equals that agent page's own subtitle", CARDS_IDX.length > 0 && drift.length === 0,
  drift.map(c => c.name + ': "' + c.sub + '" ≠ "' + (typeOfName(c.name) ? subtitle(PAGE_URLS[typeOfName(c.name)]) : "?") + '"').join(" | "));
console.log("\n" + (failures ? "CHECKS FAILED: " + failures + " of " + (passes + failures) : "ALL " + passes + " CHECKS PASSED") + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
process.exit(failures ? 1 : 0);
