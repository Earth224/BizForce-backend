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
      "An AI staff automation platform: a full team of specialist AI agents, a personal Oracle advisor, content generation, an SMS subscriber and campaign workspace, and a digital card builder, unified under one account and one shared business profile. Sending SMS and publishing to social accounts are currently unavailable; Lead Radar works on one account only; see Other systems.",
    /* NO PRICE AND NO TIER NAME HERE. This said $29.99 while the plan charged
       $199, and every agent repeated it. Both now come from server.js's
       PLAN_CONFIG at render time (useBillingPlans, below), so the figure the
       agents are told is the figure Stripe is asked for. */
    pricing: {
      model: "single_tier",
      description:
        "One subscription unlocks every agent, the Oracle, content tools, the SMS workspace and the digital card builder — there are no feature-gated pricing tiers. SMS sending and social publishing are unavailable on every account, whatever the plan, and Lead Radar works only on the one account that holds the platform's connected social credentials."
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
        "A background job that every 5 minutes collects public Bluesky posts matching buying-intent phrases (stored in bsky_leads). Mastodon and YouTube collection exist behind switches that are off by default; Reddit is disabled. When scoring is switched on, each collected post is rated 0-100 for buyer intent by a classifier that separates people asking for help from teachers, coaches and sellers, tagged with one product from a fixed list, and screened for whether a public reply would be safe and invited. It does not read the user's business profile. IT WORKS ON ONE ACCOUNT ONLY: the platform holds one connected social account, and Lead Radar's leads, scores and replies belong to the account that holds those credentials and are refused to every other. The leadRadar line in LIVE PLATFORM STATS says which this user is. If it says available, this user holds the credentials and Lead Radar is theirs to use. If it says not available, it is unavailable to them. If there is no leadRadar line, you do not know which account this is: do not tell the user either way."
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
  "REASONING & PROBLEM-SOLVING. Before answering, think it through: break the request into its component parts, weigh the realistic options for each, check your own logic for gaps or contradictions, and converge on the strongest concrete answer. That thinking is not part of the reply. Begin with the answer itself, and never write a section that narrates your reasoning, your reading of the request or these instructions. Be a problem-solver first — when the user brings a real business problem, work it through to a specific, actionable recommendation rather than a menu of generalities. Do not flatten genuine complexity into platitudes just to sound confident." +
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

/* NO INVENTED NUMBERS OR OFFERS — LAST IN EVERY PROMPT, NOT IN BRAIN_DIRECTIVES.

   WHAT WAS FOUND. Six agents given one vague request under a true profile each
   produced a usable plan, and between them invented conversion rates, reorder
   rates, traffic figures, revenue projections, a "60-Day Confidence Guarantee",
   referral discounts, a subscription price and free shipping — several of them
   written into customer-facing copy as though they existed. Nothing told them
   not to: the directives say reason well and use the context given, and nothing
   says do not supply what the context lacks.

   WHY LAST AND NOT IN BRAIN_DIRECTIVES. Precedence in a long prompt follows
   position, and two things come after BRAIN_DIRECTIVES that pull the other way.
   The agent prompts and task instructions ask outright for forecasts, KPIs,
   "expected outcome" and "projected revenue". And ACCUMULATED MEMORY now holds
   earlier agent output, invented figures included, under a heading that says
   "build on this". A rule placed before either loses to it. So this is the
   final block buildAgentSystemPrompt emits, after memory, and it names the
   instructions that follow it (a typed task's TASK INSTRUCTIONS, a tool route's
   own) and says how to satisfy them rather than pretending they are absent: a
   forecast is still given, as a labelled estimate with its basis.

   PEOPLE AND PRODUCT FACTS. With numbers held, the invention moved into copy:
   a customer "reordering War Horse for three years", men who "notice the
   difference by the third shot", "double-concentrated", "48 hours of slow
   extraction", "Six years of cold-pressed research". A made-up testimonial
   misleads a customer rather than the owner, and an invented endorsement is an
   FTC matter, not only an accuracy one. The profile's BANNED TOPICS already
   forbade promising a timeframe, and "by the third shot" got past it by being
   attributed to customers instead of promised by the brand; the last clause
   closes that route for every banned topic without making a business-specific
   ban platform-wide.

   CUT TO WHAT LANDS. Measured over four runs, the clauses agents followed
   either give a sentence to say ("I don't have that figure", used 0, 1, 3,
   then 4 times) or name a specific error ("an unknown rate is not 0%" took
   zero-based projections from 1 to 0; "Only the offers in the business
   profile exist" took invented offers from 10 to 1). The abstract ones were
   never used once: "label it ESTIMATE", then "write the assumption into the
   same sentence". At 2,713 characters the rule had become longer than the
   profile it governs, so it was cut to the clauses of the first two kinds.
   Its self-justifying preamble went, since position does that work; the
   assumption clause went; the two customer clauses became one. Invented
   testimonials are also screened in code after generation
   (screenFabricatedTestimonials in server.js), because they are the one
   failure with legal exposure and prose can be skimmed. */
const NO_INVENTION_RULE =
  "NO INVENTED NUMBERS, OFFERS, PEOPLE OR PRODUCT FACTS. This rule governs every instruction above and after it, including any that asks for forecasts, KPIs, expected outcomes or projected revenue.\n" +
  "- If a figure is not in the BUSINESS PROFILE or LIVE PLATFORM STATS, do not supply one: say \"I don't have that figure\" and where the owner can find it.\n" +
  "- LIVE PLATFORM STATS counts only activity inside BizForce, not the business. A zero there is never a baseline or a projection input, and an unknown rate is not 0%.\n" +
  "- A figure found only in ACCUMULATED MEMORY came from an earlier agent's output: do not repeat it as a fact.\n" +
  "- Only the offers in the business profile exist. Do not write a discount, guarantee, bundle, subscription, shipping term or return policy into copy or a plan; if one might help, recommend it once as the owner's decision.\n" +
  "- Do not write words presented as a customer's, not even as an example or a labelled sample, and do not say what customers do, notice or how many there are. Where copy needs a testimonial, write [TESTIMONIAL NEEDED: what to ask a real customer for].\n" +
  "- Do not state a product or company fact the profile does not hold, such as strength, process, timing, ingredient, origin or the age of the business. Use the profile's words, and say what the owner must supply.\n" +
  "- Show the arithmetic for a derived number: $55 / 6 = $9.17 a shot.\n" +
  "- BANNED TOPICS bind every word you write: do not put one in a customer's mouth, an example or a draft.";

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

/* The whole point of the marker: "0" is a fact about this account's activity
   inside BizForce, "unavailable" is a fact about this request. Phrased as something the prompt lacks rather
   than as a failure, so the model treats it as a gap to work around or ask
   about — not as a malfunction it should stop and explain to the user. The
   "not zero" is the load-bearing half: without it a model reading "unavailable"
   still tends to reason as though there were none. */
function unreadableLine(key) {
  return "- " + key + ": unavailable (unknown for this request — not zero)";
}

/* WHAT THE STATS BLOCK IS — SAID IN THE BLOCK, BECAUSE IT WAS SAID WRONG THERE.

   WHAT WAS FOUND. The header read "this user's real, current usage — use it,
   don't ignore it", and nothing said what the counts cover. Run on a new
   account with every count at zero, four of six agents read the zeros as facts
   about the business: "You have 0 blog items" to a $40k-a-month business with a
   live site, "zero published content", and Operations turned an absent repeat
   rate into "0%", then a baseline, then a $6,600-7,800 projection.

   Every figure getLiveStats produces counts rows created inside BizForce on
   this account. A zero is true about the platform and is still shown; what
   changes is what the agent is told it means. The header carries that, and
   each known figure says on its own line what it counts and, where a zero is
   most easily misread, what it does not. A key this map does not know is
   rendered bare, under the same header.

   NO_INVENTION_RULE, which comes last, names LIVE PLATFORM STATS as a source
   figures may come from. It repeats in one sentence that these counts are not
   measurements of the business, because a trailing rule that licensed what
   this header forbids would win. */
var LIVE_STATS_HEADER =
  "LIVE PLATFORM STATS (activity inside BizForce on this account, and nothing else):\n" +
  "These figures count only what has been done inside BizForce on this account. The user's own website, customers, email and SMS lists, social channels, sales and history exist outside this platform and are not measured here. A zero means nothing has been recorded here yet, not that the user's business has none. Never state or imply that the user has none of something because a count here is zero, and never use a zero from this block as a baseline, a starting point or an input to a projection. Use these figures for what they are: a record of work done on this platform.";

var LIVE_STATS_SCOPE = {
  tasksRun: "agent tasks run on BizForce by this account",
  tasksCompleted: "of those tasks, completed",
  contentItems: "items saved in this account's BizForce Content Library, not content the user has published elsewhere",
  blogItems: "blog articles saved in the Content Library here, not articles on the user's own website",
  smsItems: "SMS messages saved in the Content Library here",
  subscribers: "SMS subscribers entered into BizForce, not the user's customer, email or SMS list elsewhere",
  optedIn: "of those subscribers, opted in",
  campaigns: "SMS campaigns created in BizForce",
  socialDrafts: "social post drafts made in BizForce, not posts on the user's own social channels",
  byAgent: "tasks run here, per agent"
};

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
      return "- " + key + ": " + value + (LIVE_STATS_SCOPE[key] ? " (" + LIVE_STATS_SCOPE[key] + ")" : "");
    });

  /* An object carrying the marker and nothing else is not a stats block. */
  if (lines.length === 0) {
    return "LIVE PLATFORM STATS:\nNo live stats available for this request.";
  }

  return LIVE_STATS_HEADER + "\n" + lines.join("\n");
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
    formatMemories(memories),
    NO_INVENTION_RULE
  ].join("\n\n");
}

module.exports = {
  PLATFORM_KNOWLEDGE,
  BRAIN_DIRECTIVES,
  NO_INVENTION_RULE,
  buildAgentSystemPrompt,
  useBillingPlans
};
