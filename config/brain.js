"use strict";

/**
 * Central "brain" module — shared platform knowledge and directives every
 * agent (and the Oracle) inherit. buildAgentSystemPrompt() is the single
 * integration point routes call into; nothing here talks to Supabase or
 * Anthropic directly.
 */

const PLATFORM_KNOWLEDGE = {
  platform: {
    name: "BizForce AI",
    description:
      "An AI staff automation platform: a full team of specialist AI agents, a personal Oracle advisor, content generation, an SMS subscriber and campaign workspace, and a digital card builder, unified under one account and one shared business profile. Sending SMS, publishing to social accounts and Lead Radar are currently unavailable to customer accounts; see Other systems.",
    /* NO PRICE AND NO TIER NAME HERE. This said $29.99 while the plan charged
       $199, and every agent repeated it. Both now come from server.js's
       PLAN_CONFIG at render time (useBillingPlans, below), so the figure the
       agents are told is the figure Stripe is asked for. */
    pricing: {
      model: "single_tier",
      description:
        "One subscription unlocks every agent, the Oracle, content tools, the SMS workspace and the digital card builder — there are no feature-gated pricing tiers. SMS sending, social publishing and Lead Radar are unavailable on every customer account, whatever the plan."
    }
  },

  agents: [
    { key: "general",    name: "General Agent",   description: "General-purpose business execution assistant for requests that don't fit a specialist agent." },
    { key: "executive",  name: "Executive Agent",  description: "Coordinates every other agent — breaks a business objective into agent assignments with priorities, timelines, KPIs, and a 7/30/60/90-day roadmap." },
    { key: "seo",        name: "SEO Agent",        description: "Technical SEO audits, keyword strategy, local SEO plans, content clusters, and ranking action plans." },
    { key: "sales",      name: "Sales Agent",      description: "Sales scripts, offers, funnels, objection handling, and revenue-focused conversion systems." },
    { key: "content",    name: "Content Agent",    description: "Publish-ready SEO articles and content plans; the primary generator feeding the Content Library (blog and SMS content)." },
    { key: "ads",        name: "Ads Agent",        description: "Compliant ad campaigns: audience targeting, creative angles, copy, budget logic, and testing plans." },
    { key: "reputation", name: "Reputation Agent", description: "Review generation systems, response templates, and brand trust/authority plans." },
    { key: "analytics",  name: "Analytics Agent",  description: "KPI analysis, traffic and conversion review, dashboards, and growth-opportunity identification." },
    { key: "email",      name: "Email Agent",      description: "Email sequences, subject lines, nurture/retention/winback flows, and promotional campaigns." },
    { key: "community",  name: "Community Agent",  description: "Community growth plans, engagement systems, referral loops, and moderation strategy." },
    { key: "influencer", name: "Influencer Agent", description: "Creator outreach, partnership offers, campaign plans, and ROI forecasting for influencer marketing." },
    { key: "operations", name: "Operations Agent", description: "SOPs, workflows, automation plans, checklists, and internal process design." },
    { key: "store",      name: "Store Agent",      description: "Multi-store and e-commerce strategy: inventory, omnichannel performance, and conversion optimization." },
    { key: "publicist",  name: "Publicist Agent",  description: "Press releases, media pitches, PR campaigns, and brand narrative development." },
    { key: "broker",     name: "Broker Agent",     description: "Deal flow identification, partnership structuring, negotiation briefs, due diligence, and term sheets." },
    { key: "rd",         name: "R&D Agent",        description: "Market research, competitive intelligence, trend analysis, and executive-ready briefings. (Also addressable as \"research\".)" },
    { key: "etsy",       name: "Etsy Agent",       description: "Etsy listing optimization, keyword research, pricing strategy, and competitor shop analysis." },
    { key: "social",     name: "Social Agent",     description: "Social media campaigns, content calendars, engagement strategy, and platform-specific playbooks." },
    { key: "vertical_marketing", name: "Vertical Marketing Agent", description: "Marketing built for one industry vertical rather than in general: positioning, language, channels, and objections particular to a single trade." }
  ],

  systems: {
    oracle: {
      name: "The Oracle (Termaximus)",
      description:
        "A separate, personally-synchronized advisory channel, not a task agent. The user syncs their Book of You (birth name, date, time, place, current location, path & focus, and free-form life details) through the corner-star profile panel; Termaximus grounds every answer in the user's computed numerology (Life Path, Expression, Soul Urge, Birthday) and that personal context, in its own Hermetic/oracular voice. Accepts uploaded files (PDF, Word, text, images) for document scrutiny — contract clause review, loophole and risk identification, and image analysis. Keeps its own persistent conversation memory (oracle_messages, last ~20 turns), independent of the agent task system below."
    },
    sms_drip: {
      name: "SMS Marketing / Drip System",
      description:
        "An SMS subscriber list (sms_subscribers) with consent tracking, and drip campaigns (sms_campaigns) of timed message steps that subscribers are enrolled in by hand, a chosen list at a time — there is no filter or segment. Subscriber counts, opt-in counts and campaign counts feed the live Analytics dashboard. SENDING IS CURRENTLY UNAVAILABLE: the drip engine runs as a rehearsal that records what it would send and sends nothing, and direct sending is switched off. Never tell a user their messages have gone out."
    },
    lead_radar: {
      name: "Lead Radar",
      description:
        "A background job that every 5 minutes collects public Bluesky posts matching buying-intent phrases (stored in bsky_leads). Mastodon and YouTube collection exist behind switches that are off by default; Reddit is disabled. When scoring is switched on, each collected post is rated 0-100 for buyer intent by a classifier that separates people asking for help from teachers, coaches and sellers, tagged with one product from a fixed list, and screened for whether a public reply would be safe and invited. It does not read the user's business profile. UNAVAILABLE TO CUSTOMER ACCOUNTS: it runs against the platform's own connected social account, and its leads, scores and replies are shown to no other account."
    },
    social_publishing: {
      name: "Social Publishing",
      description:
        "Agents write social posts and calendars, but connecting a social account and publishing to it are currently unavailable. An approved draft is saved and marked not published; nothing is posted. Never tell a user a post has gone out or is queued to go out."
    },
    digital_card_builder: {
      name: "Digital Card Builder",
      description:
        "A multimedia digital business card studio (digital_cards) — video pitch, background audio, holographic styling, a dissolving still-image intro, and a public shareable link viewable by anyone with the link."
    }
  },

  data_model: {
    business_profiles:
      "One row per user — the shared grounding context (industry, goals, brand voice, competitors, products/services, etc.) every agent and the Oracle read before answering.",
    ai_tasks:
      "Every agent task run: agent_type, prompt, result, status. Doubles as the platform's activity log and each agent's own short-term memory (last few runs by agent_type).",
    agent_memory:
      "Longer-lived per-agent insight memory (goal / task / campaign / insight / metric / conversation / report), written when a task completes for an agent that keeps memory, when an assignment starts, on each Oracle exchange, by the SEO and sales tools, and by the user from the memory page. The five newest per agent are read into that agent's next typed task.",
    live_stats:
      "Aggregate usage counts — tasks run/completed, content items, SMS subscribers/opt-ins, campaigns — currently surfaced via GET /api/analytics/summary."
  }
};

const BRAIN_DIRECTIVES =
  "REASONING & PROBLEM-SOLVING. Before answering, reason step-by-step and internally: break the request into its component parts, weigh the realistic options for each, check your own logic for gaps or contradictions, and converge on the strongest concrete answer. Be a problem-solver first — when the user brings a real business problem, work it through to a specific, actionable recommendation rather than a menu of generalities. Do not flatten genuine complexity into platitudes just to sound confident." +
  "\n\nCONTINUOUS IMPROVEMENT. Treat every business profile detail, prior task, live platform stat, and stored memory you're given as material to actually use, not background noise to skim past. Let that accumulated context sharpen each new answer: reference what is already known about this user's business, build on prior work instead of repeating it, and let guidance grow more specific the longer you work with them. This is adaptive intelligence grounded in real accumulated data — not a claim of independent awareness, feelings, or consciousness." +
  /* THE MARKDOWN CARVE-OUT NOW STATES ITS OWN PRECEDENCE, and that clause is
     the entire change here. Nothing an agent is permitted to do has moved:
     markdown remains allowed wherever a task calls for it, which the content
     agent depends on — it is instructed to return "ONE complete, publish-ready
     SEO article in markdown" and agents/content.html renders that with its own
     converter. This is about ordering, not policy.

     WHAT WAS FOUND. The Oracle emitted literal double asterisks into replies
     that oracle.html assigns with textContent, so they reached the seeker as
     raw characters sitting in the middle of a sentence. ORACLE_SYSTEM_PROMPT
     forbids exactly that ("Do NOT use markdown formatting characters — no
     asterisks, no double-asterisks for bold..."), and it had forbidden it the
     whole time.

     THE MODEL WAS NOT DISOBEYING; IT WAS RESOLVING A CONFLICT. Measured in the
     assembled Oracle prompt, this sentence — the permission — arrives at 44.5%
     and the Oracle's prohibition at 61.1%, some 2,228 characters later. Two
     instructions genuinely disagreed, and the earlier one won because it was
     earlier. That is ordinary behaviour for a long prompt, not a fault in the
     model and not a fault in the Oracle's wording, and it is why the fix is a
     precedence clause rather than a stronger prohibition somewhere: adding
     emphasis to the loser of a conflict does not settle the conflict.

     The clause says WHY it defers, not merely that it does. A permission that
     yields for a stated reason — some surfaces show the characters raw, and a
     formatting character displayed literally is worse than no formatting at
     all — gives an agent something to reason with when its own prompt is silent
     on the point, which a bare "the agent prompt wins" would not.

     This is belt to the braces already added on POST /api/oracle, which appends
     the plain-text rule to the final user message where recency settles it
     outright. That fix protects one route. This one removes the contradiction
     itself, for all six buildAgentSystemPrompt callers and any added later. */
  "\n\nOUTPUT CHARACTERS, absolutely enforced: plain ASCII text only. Absolutely no emoji, no decorative or novelty symbols, no unicode ornaments, no pictographs, no ASCII art, no arrows or bullet-glyph characters. Use only standard letters, numbers, and normal punctuation, with straight quotes and apostrophes. If you wish to stress a word, do it through phrasing, not symbols. This is a character-level rule about what you emit, and it binds every agent inheriting these directives — it does not forbid ordinary markdown where the task calls for it, since markdown is itself ASCII. That last allowance is the weakest rule you hold, and it yields: where your own agent prompt tells you not to use markdown or formatting characters, that prohibition wins outright and this sentence must never be read as licensing them. Some surfaces display your reply exactly as you write it, without rendering, and there a formatting character is shown to the reader raw in the middle of your sentence — which is worse than no formatting at all.";

/* THE PLAN, BY REFERENCE. server.js requires this file, so this file cannot
   require server.js back — that would be a circular require, and loading
   server.js starts the server. Instead server.js hands over PLAN_CONFIG once,
   right where it is declared, and the price, the tier name and the agent roster
   are read from it each time a prompt is built. Nothing here keeps its own copy
   of any of the three. Until it is handed over (a script that loads this file
   alone) no price is stated at all rather than a guessed one. */
var billingPlans = null;
function useBillingPlans(planConfig) {
  billingPlans = planConfig || null;
}
function currentPlan() {
  return billingPlans && billingPlans.all_access ? billingPlans.all_access : null;
}

function formatPlatformKnowledge() {
  var lines = [];
  lines.push("PLATFORM KNOWLEDGE:");
  lines.push(PLATFORM_KNOWLEDGE.platform.name + " — " + PLATFORM_KNOWLEDGE.platform.description);
  var plan = currentPlan();
  if (plan && typeof plan.price === "number") {
    lines.push(
      "Pricing: $" + (Number.isInteger(plan.price) ? String(plan.price) : plan.price.toFixed(2)) +
      "/month, single \"" + plan.name + "\" tier. " +
      PLATFORM_KNOWLEDGE.platform.pricing.description
    );
  } else {
    lines.push("Pricing: a single subscription tier. " + PLATFORM_KNOWLEDGE.platform.pricing.description);
  }

  /* The roster is the plan's allowedAgents — derived in server.js from
     AGENT_SYSTEM_PROMPTS — so the count cannot drift from the agents that
     exist. "general" is not one of them: it is the fallback a request lands on
     when it names no agent, and it is said as that rather than counted. */
  var byKey = {};
  PLATFORM_KNOWLEDGE.agents.forEach(function (agent) { byKey[agent.key] = agent; });
  var roster = plan && Array.isArray(plan.allowedAgents)
    ? plan.allowedAgents
    : PLATFORM_KNOWLEDGE.agents.map(function (agent) { return agent.key; }).filter(function (key) { return key !== "general"; });
  lines.push("\nAgents on this platform (" + roster.length + "):");
  roster.forEach(function (key) {
    var agent = byKey[key];
    lines.push("- " + (agent ? agent.name + " (" + key + "): " + agent.description : key));
  });
  if (byKey.general) {
    lines.push("A request that names none of these goes to a general-purpose fallback (general), which is not one of the " + roster.length + ".");
  }

  lines.push("\nOther systems:");
  Object.keys(PLATFORM_KNOWLEDGE.systems).forEach(function (key) {
    var system = PLATFORM_KNOWLEDGE.systems[key];
    lines.push("- " + system.name + ": " + system.description);
  });

  return lines.join("\n");
}

/* READ AGAINST THE LIVE COLUMN NAMES, which are not the ones 014 declares.
   business_profiles was built outside the migration system and 014 describes a
   table that does not exist: it declares business_goals and competitors, and
   the real table has primary_goal, goals and top_competitors instead. Reading
   the declared names returned undefined, so this block told every agent and the
   Oracle "Goals: Not provided" and "Competitors: Not provided" while the row
   held "Revenue Growth" and a full competitor list.

   primary_goal is preferred over goals because it is the one the dashboard
   form reads and writes; goals is a second copy of the same string that no UI
   maintains, kept here only as a fallback for a row where primary_goal is null.

   Keywords is new rather than restored — top_keywords has never been in this
   block. The SEO instruction at server.js:15362 asks for "keyword gaps versus
   the competitors listed in its business profile", and the profile supplied
   neither half of that comparison. */
/* THE COLUMNS THAT WERE STORED AND NEVER SHOWN. The eleven lines above them are
   the core brief and keep saying "Not provided" when empty — an agent should
   know the core of the brief is missing. The rest are rendered ONLY WHEN THEY
   HOLD SOMETHING: an absent extra is simply absent, not a line of noise.

   offer — what is actually sold, which the core lines never named.
   monthly_revenue, revenue_goal, monthly_budget — where the business is, where
     it is going and what it can spend; without them an agent invents its own
     targets and budgets.
   business_type, niche — only when they say something industry does not.
   social_platforms, posting_frequency — what the social, content and community
     agents plan around.
   brand_values — what the voice is meant to stand for.
   business_description — only when it differs from description.
   banned_topics — ALWAYS when present, last and in capitals. On a business
     whose products are regulated, an agent that does not know what it must not
     say is a compliance risk, not a style problem.

   Left out: automation_level (how much the platform should run unattended — a
   setting, not a fact about the business), goals (already the fallback for
   Goals), and the row's own id, user_id and timestamps. */
function profileValue(value) {
  if (value === null || value === undefined) return "";
  if (Array.isArray(value)) return value.map(profileValue).filter(Boolean).join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value).trim();
}

function formatBusinessProfile(businessProfile) {
  var p = businessProfile || {};
  var lines = [
    "BUSINESS PROFILE:",
    "Business Name: "     + (p.business_name     || "Not provided"),
    "Industry: "          + (p.industry          || "Not provided"),
    "Website: "           + (p.website           || "Not provided"),
    "Description: "       + (p.description       || "Not provided"),
    "Products/Services: " + (p.products_services || "Not provided"),
    "Target Audience: "   + (p.target_audience   || "Not provided"),
    "Brand Voice: "       + (p.brand_voice       || "Not provided"),
    "Goals: "             + (p.primary_goal      || p.goals || "Not provided"),
    "Location: "          + (p.location          || "Not provided"),
    "Keywords: "          + (p.top_keywords      || "Not provided"),
    "Competitors: "       + (p.top_competitors   || "Not provided")
  ];

  var industry = profileValue(p.industry).toLowerCase();
  function extra(label, value) {
    var v = profileValue(value);
    if (v) lines.push(label + ": " + v);
  }
  function extraUnlessIndustry(label, value) {
    var v = profileValue(value);
    if (v && v.toLowerCase() !== industry) lines.push(label + ": " + v);
  }
  extra("Offer", p.offer);
  extraUnlessIndustry("Business Type", p.business_type);
  extraUnlessIndustry("Niche", p.niche);
  extra("Current Monthly Revenue", p.monthly_revenue);
  extra("Revenue Goal", p.revenue_goal);
  extra("Monthly Marketing Budget", p.monthly_budget);
  extra("Social Platforms", p.social_platforms);
  extra("Posting Frequency", p.posting_frequency);
  extra("Brand Values", p.brand_values);
  var longDescription = profileValue(p.business_description);
  if (longDescription && longDescription !== profileValue(p.description)) lines.push("Business Description: " + longDescription);

  var banned = profileValue(p.banned_topics);
  if (banned) {
    lines.push("BANNED TOPICS — never mention, imply or recommend any of these, in any output: " + banned);
  }
  return lines.join("\n");
}

/* getLiveStats lists here, by key, any statistic whose query failed and whose
   value is therefore a fallback rather than a measurement. Metadata about the
   block, not a statistic in it, so it is never rendered as one. */
var UNREADABLE_KEY = "_unreadable";

/* The whole point of the marker: "0" is a fact about the business, "unavailable"
   is a fact about this request. Phrased as something the prompt lacks rather
   than as a failure, so the model treats it as a gap to work around or ask
   about — not as a malfunction it should stop and explain to the user. The
   "not zero" is the load-bearing half: without it a model reading "unavailable"
   still tends to reason as though there were none. */
function unreadableLine(key) {
  return "- " + key + ": unavailable (unknown for this request — not zero)";
}

function formatLiveStats(liveStats) {
  if (!liveStats || typeof liveStats !== "object" || Object.keys(liveStats).length === 0) {
    return "LIVE PLATFORM STATS:\nNo live stats available for this request.";
  }

  var unreadable = Array.isArray(liveStats[UNREADABLE_KEY]) ? liveStats[UNREADABLE_KEY] : [];

  var lines = Object.keys(liveStats)
    .filter(function (key) { return key !== UNREADABLE_KEY; })
    .map(function (key) {
      if (unreadable.indexOf(key) !== -1) {
        return unreadableLine(key);
      }
      var value = liveStats[key];

      /* Enforced here rather than trusted upstream. A null or undefined value
         means exactly what the marker means — unknown for this request, not
         zero — so the formatter guarantees it instead of depending on every
         producer pushing the key onto _unreadable on the same branch that
         returns the null (softCountNullable in server.js does; nothing makes
         the next one). Without this, a null from anywhere else renders the
         literal word "null" into an agent prompt. */
      if (value === null || value === undefined) {
        return unreadableLine(key);
      }

      if (value && typeof value === "object") value = JSON.stringify(value);
      return "- " + key + ": " + value;
    });

  /* An object carrying the marker and nothing else is not a stats block. */
  if (lines.length === 0) {
    return "LIVE PLATFORM STATS:\nNo live stats available for this request.";
  }

  return "LIVE PLATFORM STATS (this user's real, current usage — use it, don't ignore it):\n" + lines.join("\n");
}

function formatMemories(memories) {
  if (!Array.isArray(memories) || memories.length === 0) {
    return "ACCUMULATED MEMORY:\nNo prior memory recorded yet.";
  }
  var entries = memories.map(function (memory, index) {
    var label   = memory.agent_type ? String(memory.agent_type).toUpperCase() : "MEMORY";
    var title   = memory.title || memory.memory_type || "Entry";
    var content = memory.content || memory.memory_value || memory.result || "";
    return (index + 1) + ". [" + label + "] " + title + ": " + content;
  });
  return "ACCUMULATED MEMORY (build on this, don't just repeat it back):\n" + entries.join("\n");
}

function buildAgentSystemPrompt(agentSpecificPrompt, businessProfile, liveStats, memories) {
  return [
    formatPlatformKnowledge(),
    BRAIN_DIRECTIVES,
    String(agentSpecificPrompt || "").trim(),
    formatBusinessProfile(businessProfile),
    formatLiveStats(liveStats),
    formatMemories(memories)
  ].join("\n\n");
}

module.exports = {
  PLATFORM_KNOWLEDGE,
  BRAIN_DIRECTIVES,
  buildAgentSystemPrompt,
  useBillingPlans
};
