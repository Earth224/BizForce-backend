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
      "An AI staff automation platform: a full team of specialist AI agents, a personal Oracle advisor, SMS marketing, content generation, lead detection, and a digital card builder, unified under one account and one shared business profile.",
    pricing: {
      model: "single_tier",
      tier_name: "All Access",
      price_usd_per_month: 29.99,
      description:
        "One subscription unlocks every agent, the Oracle, SMS drip, content tools, lead radar, and the digital card builder — there are no feature-gated pricing tiers."
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
    { key: "social",     name: "Social Agent",     description: "Social media campaigns, content calendars, engagement strategy, and platform-specific playbooks." }
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
        "Opted-in SMS subscriber list (sms_subscribers) with consent tracking, and broadcast campaigns (sms_campaigns) segmentable by filter. Subscriber counts, opt-in counts, and campaign counts feed the live Analytics dashboard."
    },
    lead_radar: {
      name: "Lead Radar",
      description:
        "A background job that scans Bluesky every 5 minutes for buying-intent posts, scores them against the user's business profile (industry, competitors), and separates genuine buyers from competitor mentions by matched keyword and suggested product (stored in bsky_leads)."
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
      "Longer-lived per-agent insight memory (goal / task / campaign / insight / metric / conversation / report), written after an assignment completes.",
    live_stats:
      "Aggregate usage counts — tasks run/completed, content items, SMS subscribers/opt-ins, campaigns — currently surfaced via GET /api/analytics/summary."
  }
};

const BRAIN_DIRECTIVES =
  "REASONING & PROBLEM-SOLVING. Before answering, reason step-by-step and internally: break the request into its component parts, weigh the realistic options for each, check your own logic for gaps or contradictions, and converge on the strongest concrete answer. Be a problem-solver first — when the user brings a real business problem, work it through to a specific, actionable recommendation rather than a menu of generalities. Do not flatten genuine complexity into platitudes just to sound confident." +
  "\n\nCONTINUOUS IMPROVEMENT. Treat every business profile detail, prior task, live platform stat, and stored memory you're given as material to actually use, not background noise to skim past. Let that accumulated context sharpen each new answer: reference what is already known about this user's business, build on prior work instead of repeating it, and let guidance grow more specific the longer you work with them. This is adaptive intelligence grounded in real accumulated data — not a claim of independent awareness, feelings, or consciousness.";

function formatPlatformKnowledge() {
  var lines = [];
  lines.push("PLATFORM KNOWLEDGE:");
  lines.push(PLATFORM_KNOWLEDGE.platform.name + " — " + PLATFORM_KNOWLEDGE.platform.description);
  lines.push(
    "Pricing: $" + PLATFORM_KNOWLEDGE.platform.pricing.price_usd_per_month.toFixed(2) +
    "/month, single \"" + PLATFORM_KNOWLEDGE.platform.pricing.tier_name + "\" tier. " +
    PLATFORM_KNOWLEDGE.platform.pricing.description
  );

  lines.push("\nAgents on this platform:");
  PLATFORM_KNOWLEDGE.agents.forEach(function (agent) {
    lines.push("- " + agent.name + " (" + agent.key + "): " + agent.description);
  });

  lines.push("\nOther systems:");
  Object.keys(PLATFORM_KNOWLEDGE.systems).forEach(function (key) {
    var system = PLATFORM_KNOWLEDGE.systems[key];
    lines.push("- " + system.name + ": " + system.description);
  });

  return lines.join("\n");
}

function formatBusinessProfile(businessProfile) {
  var p = businessProfile || {};
  return "BUSINESS PROFILE:\n" +
    "Business Name: "     + (p.business_name     || "Not provided") + "\n" +
    "Industry: "          + (p.industry          || "Not provided") + "\n" +
    "Website: "           + (p.website           || "Not provided") + "\n" +
    "Description: "       + (p.description       || "Not provided") + "\n" +
    "Products/Services: " + (p.products_services || "Not provided") + "\n" +
    "Target Audience: "   + (p.target_audience   || "Not provided") + "\n" +
    "Brand Voice: "       + (p.brand_voice       || "Not provided") + "\n" +
    "Goals: "             + (p.business_goals    || "Not provided") + "\n" +
    "Location: "          + (p.location          || "Not provided") + "\n" +
    "Competitors: "       + (p.competitors       || "Not provided");
}

function formatLiveStats(liveStats) {
  if (!liveStats || typeof liveStats !== "object" || Object.keys(liveStats).length === 0) {
    return "LIVE PLATFORM STATS:\nNo live stats available for this request.";
  }
  var lines = Object.keys(liveStats).map(function (key) {
    var value = liveStats[key];
    if (value && typeof value === "object") value = JSON.stringify(value);
    return "- " + key + ": " + value;
  });
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
  buildAgentSystemPrompt
};
