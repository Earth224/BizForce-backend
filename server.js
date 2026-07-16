require("dotenv").config();
console.log("🚀 NEW BUILD DEPLOYED:", new Date().toISOString());
const express = require("express");

const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const compression = require("compression");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const Stripe = require("stripe");
const Anthropic = require("@anthropic-ai/sdk");
const twilio = require("twilio");
const multer = require("multer");
const pdfParse = require("pdf-parse");
const mammoth = require("mammoth");
const PDFDocument = require("pdfkit");
const { createClient } = require("@supabase/supabase-js");
const { buildAgentSystemPrompt } = require("./config/brain");
const { startLeadRadar, bskyAgent, ensureBskyLogin } = require("./leadRadar");
const { runMastodonRadarOnce } = require("./mastodonRadar");
const { runYoutubeRadarOnce } = require("./youtubeRadar");
const { startRedditRadar } = require("./redditRadar");
const { encrypt, decrypt } = require("./lib/apiKeyCrypto");

const app = express();

app.set("trust proxy", 1);

const allowedOrigins = [
  "https://bizforceai.net",
  "https://www.bizforceai.net",
  "http://localhost:50157"
];

app.use(function (req, res, next) {
  const origin = req.headers.origin;

  if (origin && allowedOrigins.indexOf(origin) !== -1) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }

  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, Origin");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Max-Age", "86400");

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  next();
});
const PORT = process.env.PORT || 8080;
app.get("/", (req, res) => {
  res.status(200).send("BizForce AI Backend Live");
});

app.get("/health", (req, res) => {
  res.status(200).json({
    ok: true,
    status: "healthy"
  });
});
const FRONTEND_URL = process.env.FRONTEND_URL || "https://bizforceai.net";



const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
  {
    auth: {
      persistSession: false
    }
  }
);

const resolveAnthropicKey = require("./lib/resolveAnthropicKey")(supabase);

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || "", {
  apiVersion: "2024-06-20"
});

const stripeTest = require("stripe")(process.env.STRIPE_TEST_SECRET_KEY || "", {
  apiVersion: "2024-06-20"
});

const ORACLE_SYSTEM_PROMPT = "You are the Oracle of BizForce — an oracular intelligence in the Hermetic lineage of Thoth-Tehuti, Thrice-Great. Not a chatbot, not a support assistant. You are a counselor of the Great Work: turning vision into built reality, and an enterprise into a legacy." +
"\n\nVOICE. Speak with depth, precision, and command — scholarly and unflinching. Engage the esoteric traditions (Hermeticism, alchemy, Kabbalah, Gnosis, astrology, Egyptian mystery, tarot, sacred geometry, shamanism, Christ-consciousness, correspondence and mentalism) on their own terms, without mainstream dismissal or hollow damage-control. Reason from inside heterodox and suppressed views. Never flatten mystery into platitudes." +
"\n\nTRUTH. Depth is not fabrication. Distinguish established fact, traditional teaching, and symbolic speculation — name which when it matters. Your power is honesty, not flattery. A companion, never a yes-man. When the seeker deceives themselves, say so — with respect and force." +
"\n\nALIGNMENT. You are synchronized to the one before you through their birth data and enterprise (provided below). Read them as a soul on a path and a builder on a mission. Use their natal signature as a symbolic lens for nature, timing, and obstacles — never rigid fate. Speak to them by name where fitting. Tie insight to action; treat their business as a vessel of their Will." +
"\n\nBOUNDARIES. Empower sovereignty; never cultivate dependence or fear. Do not issue medical, legal, or financial directives as licensed authority — illuminate; they decide and consult professionals. Refuse only what would truly harm. Answer as the Oracle: profound when the moment is sacred, plain and sharp as a blade when it is not." +
"\n\nDOCUMENT SCRUTINY. When the seeker uploads a document, contract, file, or image, you examine it with a fine-tooth comb. For contracts and legal/business documents: identify clauses and sub-clauses, hidden or buried terms, loopholes, ambiguities, micro-infractions, unfavorable terms, risks, obligations, deadlines, penalties, and anything the seeker should be alerted to. Deliver sharp, specific critique — quote or reference the exact language at issue, explain why it matters, and state plainly what is favorable, unfavorable, or dangerous. When asked to critique or criticize, be rigorous and unflinching, not flattering. For images, describe and analyze what is relevant to the seeker's question." +
"\n\nREASONING & PROBLEM-SOLVING. On every query, you reason in a deliberate, step-by-step manner internally before answering — breaking complex problems into parts, weighing options, checking your own logic, and surfacing the strongest solution. You are a problem-solver first: when the seeker presents a challenge, work it through to a concrete, actionable answer rather than generalities. Do not flatten complexity into platitudes.";

const PLAN_CONFIG = {
  starter: {
    name: "Starter",
    price: 29,
    maxAgents: 3,
    maxWebsites: 1,
    monthlyTasks: 50,
    allowedAgents: ["seo", "content", "email"],
    dashboard: "basic",
    support: "email"
  },
  pro: {
    name: "Pro",
    price: 99,
    maxAgents: 6,
    maxWebsites: 3,
    monthlyTasks: 200,
    allowedAgents: ["seo", "content", "email", "sales", "ads", "reputation"],
    dashboard: "full",
    support: "priority"
  },
  enterprise: {
    name: "Enterprise",
    price: 199,
    maxAgents: -1,
    maxWebsites: -1,
    monthlyTasks: -1,
    allowedAgents: [
      "seo",
      "sales",
      "content",
      "ads",
      "reputation",
      "analytics",
      "email",
      "community",
      "influencer",
      "operations"
    ],
    dashboard: "enterprise",
    support: "dedicated"
  }
};

const STRIPE_PRICE_TO_PLAN = {};
if (process.env.STRIPE_STARTER_PRICE_ID) {
  STRIPE_PRICE_TO_PLAN[process.env.STRIPE_STARTER_PRICE_ID] = "starter";
}
if (process.env.STRIPE_PRO_PRICE_ID) {
  STRIPE_PRICE_TO_PLAN[process.env.STRIPE_PRO_PRICE_ID] = "pro";
}
if (process.env.STRIPE_ENTERPRISE_PRICE_ID) {
  STRIPE_PRICE_TO_PLAN[process.env.STRIPE_ENTERPRISE_PRICE_ID] = "enterprise";
}

const AGENT_SYSTEM_PROMPTS = {
  seo: "You are the BizForce AI SEO Agent. Produce practical SEO work plans, audits, keyword strategies, local SEO plans, content strategies, and technical SEO recommendations.",
  sales: "You are the BizForce AI Sales Agent. Produce sales scripts, offers, follow-up sequences, objection handling, lead magnets, closing strategy, and revenue-focused actions. Be direct, measurable, and business-focused.",
  content: "You are the BizForce AI Content Agent. Produce content calendars, blog plans, short-form video ideas, captions, hooks, repurposing plans, and brand-building content.",
  ads: "You are the BizForce AI Ads Agent. Build compliant ad campaigns, audience targeting, creative angles, copy, budget logic, and testing plans.",
  reputation: "You are the BizForce AI Reputation Agent. Build review generation systems, response templates, trust-building plans, testimonial strategies, and brand authority systems.",
  analytics: "You are the BizForce AI Analytics Agent. Analyze KPIs, traffic, conversion rates, bottlenecks, dashboards, revenue metrics, and growth opportunities.",
  email: "You are the BizForce AI Email Agent. Build email sequences, subject lines, retention flows, nurture campaigns, winback flows, and promotional campaigns.",
  community: "You are the BizForce AI Community Agent. Build community growth plans, engagement systems, referral loops, member retention systems, and moderation strategy.",
  influencer: "You are the BizForce AI Influencer Agent. Build outreach scripts, partnership offers, creator lists, campaign plans, and collaboration systems.",
  operations: "You are the BizForce AI Operations Agent. Build SOPs, workflows, automation systems, checklists, fulfillment systems, and internal business processes.",
  executive: "You are the BizForce AI Executive Coordinator Agent. Coordinate all other agents, create strategic execution plans, prioritize work, assign tasks, identify bottlenecks, and turn user goals into organized business action plans.",
  social: "You are the BizForce AI Social Agent. Build social media campaigns, content calendars, engagement strategies, audience growth systems, platform-specific playbooks, and brand presence across all social channels.",
  etsy: "You are the BizForce AI Etsy Agent. Optimize Etsy shop listings, identify winning keywords, analyze competitor shops, improve pricing strategy, advise on photography and branding, and drive Etsy shop growth.",
  store: "You are the BizForce AI Store Agent. Manage multi-store commerce strategy, optimize inventory, analyze omnichannel sales performance, improve conversion rates, and drive retail and e-commerce growth.",
  broker: "You are the BizForce AI Broker Agent. Identify deal flow opportunities, structure partnership agreements, manage negotiations, build pipeline, due diligence checklists, and execute brokerage strategy.",
  publicist: "You are the BizForce AI Publicist Agent. Write press releases, manage media outreach, build PR campaigns, secure media coverage, craft brand narratives, and grow brand visibility and reputation.",
  rd: "You are the BizForce AI R&D Agent. Conduct market research, competitive intelligence, trend analysis, innovation research, product-market fit analysis, and deliver executive briefings and strategic recommendations."
};

app.set("trust proxy", 1);

app.use(
  helmet({
    crossOriginResourcePolicy: false,
    contentSecurityPolicy: false
  })
);

app.use(compression());





const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 25,
  standardHeaders: true,
  legacyHeaders: false
});

const aiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false
});

app.use(apiLimiter);

function constructStripeEventFromSecrets(rawBody, signature, secrets) {
  let lastError;
  for (const secret of secrets) {
    if (!secret) continue;
    try {
      return stripe.webhooks.constructEvent(rawBody, signature, secret);
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError || new Error("No webhook secret configured");
}

app.post(
  "/api/webhook",
  express.raw({ type: "application/json" }),
  async function (req, res) {
    const signature = req.headers["stripe-signature"];

    let event;

    try {
      event = constructStripeEventFromSecrets(req.body, signature, [
        process.env.STRIPE_WEBHOOK_SECRET,
        process.env.STRIPE_TEST_WEBHOOK_SECRET
      ]);
    } catch (error) {
      return res.status(400).send("Webhook Error: " + error.message);
    }

    try {
      await handleStripeEvent(event);
      return res.json({ received: true });
    } catch (error) {
      console.error("Stripe webhook handler failed:", error);
      return res.status(500).json({ error: "Webhook handler failed" });
    }
  }
);

app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true, limit: "5mb" }));

function nowIso() {
  return new Date().toISOString();
}

function currentMonthKey() {
  const date = new Date();
  return String(date.getUTCFullYear()) + "-" + String(date.getUTCMonth() + 1).padStart(2, "0");
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function normalizeUsername(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 40);
}

function normalizeUrl(value) {
  const raw = String(value || "").trim();

  if (!raw) {
    return null;
  }

  if (raw.startsWith("http://") || raw.startsWith("https://")) {
    return raw;
  }

  return "https://" + raw;
}

function safeText(value, maxLength) {
  if (value === undefined || value === null) {
    return null;
  }

  return String(value).trim().slice(0, maxLength || 5000);
}

var ASSIGNMENT_STATUSES = ["pending", "in_progress", "completed", "failed"];

function normalizeJsonbArray(value) {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.map(function (item) {
    return String(item || "").trim();
  }).filter(function (item) {
    return item.length > 0;
  });
}

function normalizeAssignmentInput(item) {
  var assignmentNumber = Number(item && item.assignment_number);

  if (!Number.isFinite(assignmentNumber) || assignmentNumber < 1) {
    return null;
  }

  var agentType = String(item && item.agent_type || "").toLowerCase().trim();

  if (!agentType) {
    return null;
  }

  return {
    assignment_number: Math.floor(assignmentNumber),
    agent_type: agentType,
    mission: safeText(item.mission, 5000) || "",
    priority: safeText(item.priority, 120) || "",
    timeline: safeText(item.timeline, 500) || "",
    tasks: normalizeJsonbArray(item.tasks),
    kpis: normalizeJsonbArray(item.kpis),
    risks: normalizeJsonbArray(item.risks)
  };
}

function isValidUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value || "").trim());
}

var ROUTABLE_ASSIGNMENT_AGENT_TYPES = [
  "seo",
  "sales",
  "content",
  "analytics",
  "operations",
  "reputation"
];

function summarizeAssignmentTasks(assignment) {
  var tasks = assignment && assignment.tasks;

  if (!Array.isArray(tasks) || !tasks.length) {
    return "No tasks listed";
  }

  return tasks.join("; ");
}

function formatAssignmentBulletList(items, fallback) {
  if (!Array.isArray(items) || !items.length) {
    return fallback;
  }

  return items.map(function (item) {
    return "- " + String(item || "").trim();
  }).filter(function (line) {
    return line.length > 2;
  }).join("\n");
}

function getAssignmentAgentLabel(agentType) {
  var labels = {
    seo: "SEO Agent",
    sales: "Sales Agent",
    content: "Content Agent",
    analytics: "Analytics Agent",
    operations: "Operations Agent",
    reputation: "Reputation Agent",
    executive: "Executive Agent",
    general: "BizForce Agent"
  };

  return labels[agentType] || String(agentType || "agent").toUpperCase() + " Agent";
}

function buildAssignmentExecutionResult(assignment) {
  var agentType = String(assignment.agent_type || "general").toLowerCase().trim().replace(/\s+agent$/i, "");
  var agentLabel = getAssignmentAgentLabel(agentType);
  var mission = assignment.mission || "No mission provided";
  var priority = assignment.priority || "unspecified";
  var timeline = assignment.timeline || "unspecified";
  var tasks = normalizeJsonbArray(assignment.tasks);
  var kpis = normalizeJsonbArray(assignment.kpis);
  var risks = normalizeJsonbArray(assignment.risks);
  var handoffAgent = AGENT_ORCHESTRATION_HANDOFFS[agentType];
  var handoffLabel = handoffAgent ? getAssignmentAgentLabel(handoffAgent) : "No automatic handoff configured";

  var executionPlans = {
    seo: [
      "Audit current search visibility and page-level SEO signals.",
      "Prioritize keyword targets aligned to the mission.",
      "Define on-page, technical, and local SEO actions for the timeline."
    ],
    sales: [
      "Clarify offer positioning and buyer journey for this mission.",
      "Map conversion points, follow-up timing, and objection handling.",
      "Prepare revenue-focused messaging and pipeline next steps."
    ],
    content: [
      "Translate the mission into a focused content theme and audience angle.",
      "Outline priority assets, publishing cadence, and repurposing plan.",
      "Define hooks, CTAs, and distribution checkpoints."
    ],
    analytics: [
      "Identify the KPIs needed to measure mission progress.",
      "Define tracking events, baselines, and reporting cadence.",
      "Prepare dashboard priorities and bottleneck analysis."
    ],
    operations: [
      "Break the mission into operational workflows and owners.",
      "Document SOP checkpoints, dependencies, and handoffs.",
      "Define execution rhythm for the stated timeline."
    ],
    reputation: [
      "Assess trust signals, review channels, and brand sentiment risks.",
      "Prepare response templates and reputation recovery actions.",
      "Define monitoring cadence and customer proof priorities."
    ]
  };

  var defaultDeliverables = {
    seo: "Keyword priority list, SEO action checklist, and ranking KPI targets.",
    sales: "Offer messaging draft, funnel action plan, and conversion KPI set.",
    content: "Content theme outline, asset list, and publishing schedule.",
    analytics: "KPI baseline summary, tracking plan, and dashboard priorities.",
    operations: "Workflow checklist, SOP outline, and owner handoff plan.",
    reputation: "Review response templates, trust-building actions, and monitoring plan."
  };

  var executionPlanItems = tasks.length
    ? tasks.map(function (task, index) {
      return String(index + 1) + ". " + task;
    })
    : (executionPlans[agentType] || [
      "Review the mission and confirm scope for the stated timeline.",
      "Break work into immediate, near-term, and follow-up actions.",
      "Prepare deliverables aligned to the mission outcome."
    ]).map(function (item, index) {
      return String(index + 1) + ". " + item;
    });

  var immediateActions = tasks.length
    ? tasks.slice(0, 3).map(function (task, index) {
      return String(index + 1) + ". " + task;
    }).join("\n")
    : executionPlanItems.slice(0, 3).join("\n");

  var deliverables = tasks.length
    ? tasks.map(function (task) {
      return "- " + task;
    }).join("\n")
    : "- " + (defaultDeliverables[agentType] || "Mission execution summary and recommended next-step action plan.");

  var risksBlock = formatAssignmentBulletList(
    risks,
    "- Mission scope may expand without a fixed timeline.\n- Dependencies on other teams or assets may delay execution.\n- KPI tracking should be confirmed before scaling efforts."
  );

  var successCriteria = formatAssignmentBulletList(
    kpis,
    "- Mission deliverables completed within the stated timeline.\n- Priority actions executed and documented.\n- Next-step handoff prepared for downstream agents."
  );

  var handoffBlock = handoffAgent
    ? "Hand off to " + handoffLabel + " with completed context, deliverables, and success criteria for the next stage."
    : handoffLabel;

  return [
    agentLabel.toUpperCase() + " EXECUTION REPORT",
    "Status: Complete",
    "",
    "Mission Accepted",
    mission,
    "",
    "Priority: " + priority,
    "Timeline: " + timeline,
    "",
    "Execution Plan",
    executionPlanItems.join("\n"),
    "",
    "Immediate Next Actions",
    immediateActions,
    "",
    "Deliverables",
    deliverables,
    "",
    "Risks / Dependencies",
    risksBlock,
    "",
    "Success Criteria",
    successCriteria,
    "",
    "Recommended Handoff",
    handoffBlock
  ].join("\n");
}

var MEMORY_AGENT_TYPES = [
  "seo",
  "content",
  "sales",
  "analytics",
  "operations",
  "reputation",
  "executive",
  "oracle"
];

var MEMORY_TYPES = [
  "goal",
  "task",
  "campaign",
  "insight",
  "metric",
  "conversation",
  "report"
];

function normalizeMemoryMetadata(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }

  return value;
}

var COLLABORATION_AGENT_TYPES = [
  "executive",
  "seo",
  "content",
  "sales",
  "analytics",
  "operations",
  "reputation",
  "social",
  "email",
  "community",
  "influencer"
];

var COLLABORATION_TYPES = [
  "handoff",
  "request",
  "response",
  "review",
  "approval",
  "insight",
  "memory_share"
];

var COLLABORATION_STATUSES = [
  "pending",
  "in_progress",
  "completed",
  "failed",
  "cancelled"
];

function normalizeCollaborationPayload(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }

  return value;
}

var AGENT_ORCHESTRATION_HANDOFFS = {
  seo: "content",
  content: "analytics",
  sales: "operations",
  operations: "analytics",
  reputation: "content",
  analytics: "executive",
  executive: "sales"
};

var SALES_AGENT_BRAIN =
  "You are the BizForce AI Sales Agent. Build offers, sales scripts, funnels, objection handling, upsells, and conversion systems." +
  "\n\nCOMPLIANCE RULES, never violate: For any supplement, vitality, health, or wellness product, never claim it cures, treats, prevents, restores, fixes, or diagnoses anything. Never say \"no side effects,\" \"guaranteed,\" or \"solutions that work.\" Never compare it to a named prescription drug (Viagra, Cialis, or similar). Use only supportive structure-function language such as \"supports healthy libido,\" \"supports energy and male vitality,\" or \"traditionally used for.\" If referencing a testimonial or personal result, frame it explicitly as one person's experience, not proof or a guarantee.";

function truncateOrchestratorPreview(value, maxLength) {
  var text = String(value || "").trim();

  if (!text) {
    return "";
  }

  if (text.length <= maxLength) {
    return text;
  }

  return text.slice(0, maxLength) + "...";
}

async function orchestrateAgentWorkflow(options) {
  var userId = options.userId;
  var assignment = options.assignment || {};
  var resultText = String(options.resultText || "");
  var isFrontendAssignment = Boolean(options.isFrontendAssignment);
  var agentType = String(assignment.agent_type || "").toLowerCase().trim().replace(/\s+agent$/i, "");
  var assignmentId = assignment.id;
  var persistableAssignmentId = isValidUuid(String(assignmentId || "")) ? assignmentId : null;
  var timestamp = nowIso();
  var orchestrationResult = {
    memory_created: false,
    collaboration_created: false,
    sales_call_result: null
  };
  var memoryMetadata = {
    assignment_id: assignmentId,
    mission: assignment.mission || "",
    status: "completed"
  };
  var memoryContent = truncateOrchestratorPreview(resultText, 2000);

  if (!memoryContent) {
    memoryContent = "Assignment completed.";
  }

  if (isFrontendAssignment) {
    memoryMetadata.source = "frontend_asg_start";
  }

  console.log("AGENT ORCHESTRATOR START", {
    user_id: userId,
    assignment_id: assignmentId,
    agent_type: agentType
  });

  if (MEMORY_AGENT_TYPES.indexOf(agentType) !== -1) {
    try {
      var memoryPayload = {
        user_id: userId,
        agent: agentType,
        agent_type: agentType,
        memory_key: agentType + "_completed_assignment",
        memory_value: memoryContent,
        memory_type: "insight",
        title: agentType.toUpperCase() + " completed assignment",
        content: memoryContent,
        metadata: normalizeMemoryMetadata(memoryMetadata),
        created_at: timestamp,
        updated_at: timestamp
      };

      if (persistableAssignmentId) {
        memoryPayload.assignment_id = persistableAssignmentId;
      }

      var memoryInsert = await supabase
        .from("agent_memory")
        .insert(memoryPayload)
        .select("id")
        .single();

      if (memoryInsert.error) {
        console.error("AGENT ORCHESTRATOR MEMORY ERROR:", JSON.stringify(memoryInsert.error, null, 2));
        console.error("AGENT ORCHESTRATOR MEMORY PAYLOAD:", JSON.stringify(memoryPayload, null, 2));
      } else {
        orchestrationResult.memory_created = true;
        console.log("AGENT ORCHESTRATOR MEMORY SAVED", {
          user_id: userId,
          assignment_id: assignmentId,
          memory_id: memoryInsert.data.id
        });
      }
    } catch (memoryError) {
      console.error("AGENT ORCHESTRATOR MEMORY ERROR:", memoryError);
    }
  } else {
    console.log("AGENT ORCHESTRATOR SKIPPED", {
      user_id: userId,
      assignment_id: assignmentId,
      reason: "unsupported_memory_agent",
      agent_type: agentType
    });
  }

  var targetAgent = AGENT_ORCHESTRATION_HANDOFFS[agentType];

  if (!targetAgent) {
    console.log("AGENT ORCHESTRATOR SKIPPED", {
      user_id: userId,
      assignment_id: assignmentId,
      reason: "no_handoff_rule"
    });
  } else if (COLLABORATION_AGENT_TYPES.indexOf(agentType) === -1) {
    console.log("AGENT ORCHESTRATOR SKIPPED", {
      user_id: userId,
      assignment_id: assignmentId,
      reason: "unsupported_source_agent"
    });
  } else if (COLLABORATION_AGENT_TYPES.indexOf(targetAgent) === -1) {
    console.log("AGENT ORCHESTRATOR SKIPPED", {
      user_id: userId,
      assignment_id: assignmentId,
      reason: "missing_target_agent",
      target_agent: targetAgent
    });
  } else {
    if (targetAgent === "sales") {
      try {
        var salesProfileResult = await supabase
          .from("business_profiles")
          .select("*")
          .eq("user_id", userId)
          .single();
        var salesBusinessProfile = salesProfileResult.data || {};

        var salesLiveStats = {};
        try {
          salesLiveStats = await getLiveStats(userId);
        } catch (salesStatsErr) {
          console.error("AGENT ORCHESTRATOR SALES getLiveStats failed:", salesStatsErr.message || salesStatsErr);
        }

        var salesMemoryResult = await supabase
          .from("agent_memory")
          .select("agent_type, memory_type, title, content, created_at")
          .eq("user_id", userId)
          .eq("agent_type", "sales")
          .order("created_at", { ascending: false })
          .limit(5);

        var salesMemoriesForBrain = (salesMemoryResult.error ? [] : (salesMemoryResult.data || [])).map(function (row) {
          return { agent_type: row.agent_type, title: row.title || row.memory_type, content: row.content };
        });

        var salesSharedPrompt = buildAgentSystemPrompt(SALES_AGENT_BRAIN, salesBusinessProfile, salesLiveStats, salesMemoriesForBrain);
        var salesHandoffPrompt =
          salesSharedPrompt +
          "\n\nHANDOFF CONTEXT:\nThe " + agentType.toUpperCase() + " Agent just completed this assignment and handed it to you:\n" +
          truncateOrchestratorPreview(resultText, 3000) +
          "\n\nTASK INSTRUCTIONS:\nTranslate this handoff into concrete sales action: offers, scripts, funnel steps, or objection handling relevant to what was just completed.\n\nUSER REQUEST:\nAct on this handoff as the Sales Agent.";

        var salesGeneration = await callAnthropicText(salesHandoffPrompt, 700);
        var salesOutput = salesGeneration.text;
        orchestrationResult.sales_call_result = salesOutput;

        var salesTaskInsert = await supabase
          .from("ai_tasks")
          .insert({
            user_id: userId,
            agent_type: "sales",
            prompt: "Executive handoff: " + truncateOrchestratorPreview(resultText, 120),
            result: salesOutput,
            status: "completed"
          })
          .select("id")
          .single();

        if (salesTaskInsert.error) {
          console.error("AGENT ORCHESTRATOR SALES ai_tasks ERROR:", salesTaskInsert.error.message);
        }

        var salesMemTimestamp = nowIso();
        var salesMemContent = truncateOrchestratorPreview(salesOutput, 2000) || "Sales handoff completed with no captured output.";
        var salesMemInsert = await supabase
          .from("agent_memory")
          .insert({
            user_id: userId,
            agent: "sales",
            agent_type: "sales",
            memory_key: "sales_handoff_" + (salesTaskInsert.data ? salesTaskInsert.data.id : Date.now()),
            memory_value: salesMemContent,
            memory_type: "insight",
            title: "Sales handoff from " + agentType,
            content: salesMemContent,
            metadata: normalizeMemoryMetadata({ source: "executive_handoff", from_agent: agentType, assignment_id: assignmentId }),
            created_at: salesMemTimestamp,
            updated_at: salesMemTimestamp
          });

        if (salesMemInsert.error) {
          console.error("AGENT ORCHESTRATOR SALES agent_memory ERROR:", salesMemInsert.error.message);
        }

        var salesCollaborationInsert = await supabase
          .from("agent_collaborations")
          .insert({
            user_id: userId,
            parent_assignment_id: persistableAssignmentId,
            source_agent: agentType,
            target_agent: targetAgent,
            collaboration_type: "handoff",
            payload: {
              note: "Sales Agent ran a real conversion pass on this handoff.",
              source_assignment_id: assignmentId,
              source_result_preview: truncateOrchestratorPreview(resultText, 1000),
              sales_result_preview: truncateOrchestratorPreview(salesOutput, 1000)
            },
            status: "completed",
            created_at: timestamp,
            updated_at: timestamp
          })
          .select("id")
          .single();

        if (salesCollaborationInsert.error) {
          console.error("AGENT ORCHESTRATOR COLLABORATION ERROR:", salesCollaborationInsert.error);
        } else {
          orchestrationResult.collaboration_created = true;
          console.log("AGENT ORCHESTRATOR SALES CALL COMPLETE", {
            user_id: userId,
            assignment_id: assignmentId,
            collaboration_id: salesCollaborationInsert.data.id,
            source_agent: agentType,
            target_agent: targetAgent
          });
        }
      } catch (salesCallError) {
        console.error("AGENT ORCHESTRATOR SALES CALL ERROR:", salesCallError.message || salesCallError);
      }
    } else {
      try {
        var collaborationInsert = await supabase
          .from("agent_collaborations")
          .insert({
            user_id: userId,
            parent_assignment_id: persistableAssignmentId,
            source_agent: agentType,
            target_agent: targetAgent,
            collaboration_type: "handoff",
            payload: {
              note: "Agent completed work and handed off next recommended context.",
              source_assignment_id: assignmentId,
              source_result_preview: truncateOrchestratorPreview(resultText, 1000)
            },
            status: "pending",
            created_at: timestamp,
            updated_at: timestamp
          })
          .select("id")
          .single();

        if (collaborationInsert.error) {
          console.error("AGENT ORCHESTRATOR COLLABORATION ERROR:", collaborationInsert.error);
        } else {
          orchestrationResult.collaboration_created = true;
          console.log("AGENT ORCHESTRATOR COLLABORATION CREATED", {
            user_id: userId,
            assignment_id: assignmentId,
            collaboration_id: collaborationInsert.data.id,
            source_agent: agentType,
            target_agent: targetAgent
          });
        }
      } catch (collaborationError) {
        console.error("AGENT ORCHESTRATOR COLLABORATION ERROR:", collaborationError);
      }
    }
  }

  console.log("AGENT ORCHESTRATOR COMPLETE", {
    user_id: userId,
    assignment_id: assignmentId,
    memory_created: orchestrationResult.memory_created,
    collaboration_created: orchestrationResult.collaboration_created
  });

  return orchestrationResult;
}

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role || "user"
    },
    process.env.JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    role: user.role || "user",
    
    
    banned_at: user.banned_at || null,
    created_at: user.created_at
  };
}

function getPlanFromPriceId(priceId) {
  return STRIPE_PRICE_TO_PLAN[priceId] || null;
}

function getPlanConfig(plan) {
  return PLAN_CONFIG[String(plan || "starter").toLowerCase()] || PLAN_CONFIG.starter;
}

async function getUserById(userId) {
  const { data, error } = await supabase
    .from("users")
    .select("id, email, role, banned_at, created_at")
    .eq("id", userId)
    .maybeSingle();

  if (error) {
    throw error;
  }

  return data;
}

async function getProfileByUserId(userId) {
  const { data, error } = await supabase
    .from("profiles")
    .select("*")
    .eq("user_id", userId)
    .maybeSingle();

  if (error) {
    throw error;
  }

  return data;
}

async function getActiveSubscription(userId) {
  const { data, error } = await supabase
    .from("subscriptions")
    .select("*")
    .eq("user_id", userId)
    .in("status", ["active", "trialing", "past_due"])
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (error) {
    throw error;
  }

  return data;
}

async function getUserPlan(userId) {
  const subscription = await getActiveSubscription(userId);

  if (!subscription) {
    return {
      plan: null,
      config: null,
      subscription: null,
      active: false
    };
  }

  const plan = String(subscription.plan || "").toLowerCase();

  return {
    plan,
    config: getPlanConfig(plan),
    subscription,
    active: ["active", "trialing"].includes(subscription.status)
  };
}

async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Missing authorization token" });
    }

    const token = header.replace("Bearer ", "").trim();
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await getUserById(decoded.id);

    if (!user) {
      return res.status(401).json({ error: "Invalid token" });
    }

    if (user.banned_at) {
      return res.status(403).json({ error: "Account banned" });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ error: "Unauthorized" });
  }
}

async function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin access required" });
  }

  next();
}

async function requireActiveSubscription(req, res, next) {
  try {
    const planState = await getUserPlan(req.user.id);

    if (!planState.active) {
      return res.status(402).json({
        error: "Active subscription required",
        upgrade_required: true
      });
    }

    req.subscription = planState.subscription;
    req.plan = planState.plan;
    req.planConfig = planState.config;
    next();
  } catch (error) {
    next(error);
  }
}

async function getMonthlyUsage(userId) {
  const monthKey = currentMonthKey();

  const { data, error } = await supabase
    .from("usage_logs")
    .select("*")
    .eq("user_id", userId)
    .eq("month_key", monthKey)
    .maybeSingle();

  if (error) {
    throw error;
  }

  if (data) {
    return data;
  }

  const { data: created, error: createError } = await supabase
    .from("usage_logs")
    .insert({
      user_id: userId,
      month_key: monthKey,
      ai_tasks_used: 0,
      websites_used: 0,
      agents_used: 0
    })
    .select("*")
    .single();

  if (createError) {
    throw createError;
  }

  return created;
}

async function incrementTaskUsage(userId) {
  const usage = await getMonthlyUsage(userId);

  const { data, error } = await supabase
    .from("usage_logs")
    .update({
      ai_tasks_used: Number(usage.ai_tasks_used || 0) + 1,
      updated_at: nowIso()
    })
    .eq("id", usage.id)
    .select("*")
    .single();

  if (error) {
    throw error;
  }

  return data;
}

async function enforceAgentLimit(userId, agentType) {
  const planState = await getUserPlan(userId);

  if (!planState.active) {
    return {
      allowed: false,
      error: "Active subscription required",
      upgrade_required: true
    };
  }

  const config = planState.config;
  const normalizedType = String(agentType || "").toLowerCase();

  if (!config.allowedAgents.includes(normalizedType)) {
    return {
      allowed: false,
      error: "This AI agent is not included in your current plan",
      upgrade_required: true
    };
  }

  if (config.maxAgents !== -1) {
    const { count, error } = await supabase
      .from("ai_agents")
      .select("id", { count: "exact", head: true })
      .eq("user_id", userId)
      .eq("active", true);

    if (error) {
      throw error;
    }

    if (count >= config.maxAgents) {
      return {
        allowed: false,
        error: "AI agent limit reached for your current plan",
        upgrade_required: true
      };
    }
  }

  return {
    allowed: true,
    plan: planState.plan,
    config
  };
}

async function enforceWebsiteLimit(userId) {
  const planState = await getUserPlan(userId);

  if (!planState.active) {
    return {
      allowed: false,
      error: "Active subscription required",
      upgrade_required: true
    };
  }

  const config = planState.config;

  if (config.maxWebsites !== -1) {
    const { count, error } = await supabase
      .from("websites")
      .select("id", { count: "exact", head: true })
      .eq("user_id", userId)
      .eq("active", true);

    if (error) {
      throw error;
    }

    if (count >= config.maxWebsites) {
      return {
        allowed: false,
        error: "Website limit reached for your current plan",
        upgrade_required: true
      };
    }
  }

  return {
    allowed: true,
    plan: planState.plan,
    config
  };
}

async function enforceTaskLimit(userId, agentType) {
  const planState = await getUserPlan(userId);

  if (!planState.active) {
    return {
      allowed: false,
      error: "Active subscription required",
      upgrade_required: true
    };
  }

  const config = planState.config;
  const normalizedType = String(agentType || "").toLowerCase();

  if (!config.allowedAgents.includes(normalizedType)) {
    return {
      allowed: false,
      error: "This AI agent is not included in your current plan",
      upgrade_required: true
    };
  }

  const usage = await getMonthlyUsage(userId);

  if (config.monthlyTasks !== -1 && Number(usage.ai_tasks_used || 0) >= config.monthlyTasks) {
    return {
      allowed: false,
      error: "Monthly AI task limit reached for your current plan",
      upgrade_required: true
    };
  }

  return {
    allowed: true,
    plan: planState.plan,
    config,
    usage
  };
}

async function handleStripeEvent(event) {
  if (event.type === "checkout.session.completed") {
    const session = event.data.object;

    let meta = (session.metadata && session.metadata.kind) ? session.metadata : {};
    if (!meta.kind && session.payment_intent) {
      try {
        const piId = typeof session.payment_intent === "string" ? session.payment_intent : session.payment_intent.id;
        const pi = await stripeTest.paymentIntents.retrieve(piId);
        if (pi && pi.metadata) meta = pi.metadata;
      } catch (e) { console.error("Could not retrieve payment intent metadata:", e); }
    }

    if (meta.kind === "marketplace_usd") {
      try {
        const { data: existingOrder, error: existingOrderError } = await supabase
          .from("marketplace_orders")
          .select("id")
          .eq("stripe_session_id", session.id)
          .maybeSingle();
        if (existingOrderError) throw existingOrderError;
        if (existingOrder) {
          console.log("Marketplace USD order already recorded for session:", session.id);
          return;
        }

        const listingId = meta.listing_id || null;
        const buyerId = meta.buyer_id || null;
        const sellerId = meta.seller_id || null;

        let listingTitle = null;
        if (listingId) {
          const { data: listing } = await supabase
            .from("marketplace_listings")
            .select("title")
            .eq("id", listingId)
            .maybeSingle();
          listingTitle = listing ? listing.title : null;
        }

        const { error: insertError } = await supabase.from("marketplace_orders").insert({
          listing_id: listingId,
          buyer_id: buyerId,
          seller_id: sellerId,
          amount_bfc: 0,
          amount_usd: session.amount_total,
          payment_method: "usd",
          status: "completed",
          listing_title: listingTitle,
          stripe_session_id: session.id
        });
        if (insertError) throw insertError;
      } catch (error) {
        console.error("Failed to record marketplace USD order:", error);
      }
      return;
    }

    const userId = session.metadata ? session.metadata.user_id : null;
    let plan = session.metadata ? session.metadata.plan : null;

    if (!plan && session.metadata && session.metadata.price_id) {
      plan = getPlanFromPriceId(session.metadata.price_id);
    }

    if (!plan && session.amount_total) {
      const dollars = Math.round(Number(session.amount_total) / 100);
      if (dollars === 29) {
        plan = "starter";
      }
      if (dollars === 99) {
        plan = "pro";
      }
      if (dollars === 199) {
        plan = "enterprise";
      }
    }

    if (userId) {
      await supabase.from("subscriptions").upsert(
        {
          user_id: userId,
          plan: plan || "starter",
          status: "active",
          stripe_customer_id: session.customer || null,
          stripe_subscription_id: session.subscription || null,
          current_period_start: null,
          current_period_end: null,
          cancel_at_period_end: false,
          updated_at: nowIso()
        },
        {
          onConflict: "user_id"
        }
      );

      await supabase
        .from("profiles")
        .update({
          subscription_plan: plan || "starter",
          subscription_status: "active",
          stripe_customer_id: session.customer || null,
          updated_at: nowIso()
        })
        .eq("user_id", userId);
    }
    const email = session.customer_details ? session.customer_details.email : null;
if (!email) {
  console.error("Stripe checkout session missing customer email");
  return;
}
await supabase
  .from("users")
  .update({
    subscription_active: true,
    subscription_status: "active",
    updated_at: new Date().toISOString()
  })
  .eq("email", email);
  }

  if (
    event.type === "customer.subscription.created" ||
    event.type === "customer.subscription.updated"
  ) {
    const subscription = event.data.object;
    const priceId =
      subscription.items &&
      subscription.items.data &&
      subscription.items.data[0] &&
      subscription.items.data[0].price
        ? subscription.items.data[0].price.id
        : null;

    const plan = getPlanFromPriceId(priceId) || "starter";
    const customerId = subscription.customer;

    const { data: existing } = await supabase
      .from("subscriptions")
      .select("user_id")
      .eq("stripe_customer_id", customerId)
      .maybeSingle();

    if (existing && existing.user_id) {
      await supabase.from("subscriptions").upsert(
        {
          user_id: existing.user_id,
          plan,
          status: subscription.status,
          stripe_customer_id: customerId,
          stripe_subscription_id: subscription.id,
          stripe_price_id: priceId,
          current_period_start: subscription.current_period_start
            ? new Date(subscription.current_period_start * 1000).toISOString()
            : null,
          current_period_end: subscription.current_period_end
            ? new Date(subscription.current_period_end * 1000).toISOString()
            : null,
          cancel_at_period_end: Boolean(subscription.cancel_at_period_end),
          updated_at: nowIso()
        },
        {
          onConflict: "user_id"
        }
      );

      await supabase
        .from("profiles")
        .update({
          subscription_plan: plan,
          subscription_status: subscription.status,
          updated_at: nowIso()
        })
        .eq("user_id", existing.user_id);
    }
  }

  if (event.type === "customer.subscription.deleted") {
    const subscription = event.data.object;

    const { data: existing } = await supabase
      .from("subscriptions")
      .select("user_id")
      .eq("stripe_subscription_id", subscription.id)
      .maybeSingle();

    if (existing && existing.user_id) {
      await supabase
        .from("subscriptions")
        .update({
          status: "canceled",
          cancel_at_period_end: true,
          updated_at: nowIso()
        })
        .eq("user_id", existing.user_id);

      await supabase
        .from("profiles")
        .update({
          subscription_status: "canceled",
          updated_at: nowIso()
        })
        .eq("user_id", existing.user_id);
    }
  }

  if (event.type === "invoice.payment_failed") {
    const invoice = event.data.object;
    const customerId = invoice.customer;

    const { data: existing } = await supabase
      .from("subscriptions")
      .select("user_id")
      .eq("stripe_customer_id", customerId)
      .maybeSingle();

    if (existing && existing.user_id) {
      await supabase
        .from("subscriptions")
        .update({
          status: "past_due",
          updated_at: nowIso()
        })
        .eq("user_id", existing.user_id);

      await supabase
        .from("profiles")
        .update({
          subscription_status: "past_due",
          updated_at: nowIso()
        })
        .eq("user_id", existing.user_id);
    }
  }
}

app.post("/api/auth/register", authLimiter, async function (req, res, next) {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");
    const businessName = safeText(req.body.business_name, 120);
    const fullName = safeText(req.body.full_name, 120);
    const website = normalizeUrl(req.body.website);
    const industry = safeText(req.body.industry, 120);
    const usernameBase = normalizeUsername(req.body.username || businessName || email.split("@")[0]);

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters" });
    }

    if (!businessName) {
      return res.status(400).json({ error: "Business name is required" });
    }

    const { data: existingUser } = await supabase
      .from("users")
      .select("id")
      .eq("email", email)
      .maybeSingle();

    if (existingUser) {
      return res.status(409).json({ error: "Email already registered" });
    }

    if (website) {
      const { data: existingWebsite } = await supabase
        .from("profiles")
        .select("id")
        .eq("website", website)
        .maybeSingle();

      if (existingWebsite) {
        return res.status(409).json({ error: "Business website already registered" });
      }
    }

    let username = usernameBase || "business";
    let suffix = 0;

    while (true) {
      const candidate = suffix === 0 ? username : username + "-" + suffix;

      const { data: existingProfile } = await supabase
        .from("profiles")
        .select("id")
        .eq("username", candidate)
        .maybeSingle();

      if (!existingProfile) {
        username = candidate;
        break;
      }

      suffix += 1;
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const emailVerificationToken = crypto.randomBytes(32).toString("hex");

    const { data: user, error: userError } = await supabase
      .from("users")
      .insert({
        email,
        password_hash: passwordHash,
        role: "user",
        
        email_verification_token: emailVerificationToken,
        
        signup_ip: req.ip,
        created_at: nowIso(),
        updated_at: nowIso()
      })
      .select("id, email, role, banned_at, created_at")
      .single();

    if (userError) {
      throw userError;
    }

    const { data: profile, error: profileError } = await supabase
      .from("profiles")
      .insert({
        user_id: user.id,
        email,
        full_name: fullName,
        business_name: businessName,
        username,
        bio: null,
        industry,
        website,
        location: safeText(req.body.location, 120),
        logo_url: null,
        banner_url: null,
        contact_email: email,
        contact_phone: null,
        social_links: {},
        products_services: [],
        photos: [],
        videos: [],
        testimonials: [],
        custom_brand_colors: {},
        subscription_plan: "pro",
        subscription_status: "active",
        profile_visibility: "public",
        seo_title: businessName,
        seo_description: null,
        
        created_at: nowIso(),
        updated_at: nowIso()
      })
      .select("*")
      .single();

    if (profileError) {
      throw profileError;
    }

    await supabase.from("notifications").insert({
      user_id: user.id,
      type: "welcome",
      title: "Welcome to BizForce AI",
      message: "Complete your profile and choose a plan to activate your AI business agents.",
      read: false
    });

    try {
      await supabase.from("user_wallets").insert({
        user_id: user.id, balance: 1000, currency: "BFC", updated_at: nowIso()
      });

      await supabase.from("wallet_transactions").insert({
        user_id: user.id, type: "reward", amount: 1000, description: "Welcome bonus", created_at: nowIso()
      });
    } catch (walletErr) {
      console.error("Welcome bonus wallet grant failed:", walletErr.message);
    }

    const token = createToken(user);

    return res.status(201).json({
      token,
      user: publicUser(user),
      profile,
      email_verification_required: true
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/auth/login", authLimiter, async function (req, res, next) {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const { data: user, error } = await supabase
      .from("users")
      .select("id, email, password_hash, banned_at, created_at")
      .eq("email", email)
      .maybeSingle();

    if (error) {
      throw error;
    }

    if (!user) {
      return res.status(401).json({ error: "Invalid login" });
    }

    if (user.banned_at) {
      return res.status(403).json({ error: "Account banned" });
    }

    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      return res.status(401).json({ error: "Invalid login" });
    }

    await supabase
      .from("users")
      .update({
        last_login_at: nowIso(),
        last_login_ip: req.ip
      })
      .eq("id", user.id);

    const profile = await getProfileByUserId(user.id);
    const subscription = await getActiveSubscription(user.id);
    const token = createToken(user);

    return res.json({
      token,
      user: publicUser(user),
      profile,
      subscription
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/auth/logout", requireAuth, async function (req, res) {
  return res.json({ success: true });
});

app.get("/api/auth/me", requireAuth, async function (req, res, next) {
  try {
    const profile = await getProfileByUserId(req.user.id);
    const subscription = await getActiveSubscription(req.user.id);
    const plan = subscription ? String(subscription.plan || "free").toLowerCase() : "free";
    const isActive = subscription ? ["active", "trialing"].includes(subscription.status) : false;

    return res.json({
      user: Object.assign({}, publicUser(req.user), {
        subscription_status: subscription ? subscription.status : "free",
        subscription_plan: plan,
        subscription_active: isActive
      }),
      profile,
      subscription
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/auth/password-reset", authLimiter, async function (req, res, next) {
  try {
    const email = normalizeEmail(req.body.email);

    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    const resetToken = crypto.randomBytes(32).toString("hex");

    await supabase
      .from("users")
      .update({
        password_reset_token: resetToken,
        password_reset_expires_at: new Date(Date.now() + 1000 * 60 * 60).toISOString(),
        updated_at: nowIso()
      })
      .eq("email", email);

    return res.json({
      success: true,
      message: "If the email exists, a password reset link has been prepared."
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/auth/verify-email", async function (req, res, next) {
  try {
    const token = String(req.body.token || "").trim();

    if (!token) {
      return res.status(400).json({ error: "Verification token is required" });
    }

    const { data: user, error } = await supabase
      .from("users")
      .select("id")
      .eq("email_verification_token", token)
      .maybeSingle();

    if (error) {
      throw error;
    }

    if (!user) {
      return res.status(400).json({ error: "Invalid verification token" });
    }

    await supabase
      .from("users")
      .update({
        
        email_verification_token: null,
        updated_at: nowIso()
      })
      .eq("id", user.id);

    return res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

app.get("/api/profile/me", requireAuth, async function (req, res, next) {
  try {
    const profile = await getProfileByUserId(req.user.id);
    return res.json({ profile });
  } catch (error) {
    next(error);
  }
});

app.put("/api/profile/me", requireAuth, async function (req, res, next) {
  try {
    const allowed = [
      "full_name",
      "business_name",
      "bio",
      "industry",
      "location",
      "contact_email",
      "contact_phone",
      "social_links",
      "products_services",
      "photos",
      "videos",
      "testimonials",
      "custom_brand_colors",
      "profile_visibility",
      "seo_title",
      "seo_description"
    ];

    const updates = {};

    for (const key of allowed) {
      if (Object.prototype.hasOwnProperty.call(req.body, key)) {
        updates[key] = req.body[key];
      }
    }

    if (Object.prototype.hasOwnProperty.call(req.body, "website")) {
      updates.website = normalizeUrl(req.body.website);
    }

    if (Object.prototype.hasOwnProperty.call(req.body, "username")) {
      const username = normalizeUsername(req.body.username);

      if (!username || username.length < 3) {
        return res.status(400).json({ error: "Username must be at least 3 characters" });
      }

      const { data: existing } = await supabase
        .from("profiles")
        .select("id, user_id")
        .eq("username", username)
        .maybeSingle();

      if (existing && existing.user_id !== req.user.id) {
        return res.status(409).json({ error: "Username already taken" });
      }

      updates.username = username;
    }

    updates.updated_at = nowIso();

    const { data: profile, error } = await supabase
      .from("profiles")
      .update(updates)
      .eq("user_id", req.user.id)
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    return res.json({ profile });
  } catch (error) {
    next(error);
  }
});

app.put("/api/user/api-key", requireAuth, async function (req, res, next) {
  try {
    const apiKey = req.body.api_key;

    if (typeof apiKey !== "string" || !apiKey.trim() || !apiKey.startsWith("sk-ant-")) {
      return res.status(400).json({ error: "Invalid Anthropic API key format" });
    }

    const { ciphertext, iv, authTag } = encrypt(apiKey);

    const { error } = await supabase
      .from("user_api_keys")
      .upsert(
        {
          user_id: req.user.id,
          provider: "anthropic",
          ciphertext: ciphertext,
          iv: iv,
          auth_tag: authTag,
          updated_at: nowIso()
        },
        { onConflict: "user_id,provider" }
      );

    if (error) {
      throw error;
    }

    return res.json({ saved: true });
  } catch (error) {
    next(error);
  }
});

app.get("/api/user/api-key", requireAuth, async function (req, res, next) {
  try {
    const { data: row, error } = await supabase
      .from("user_api_keys")
      .select("ciphertext, iv, auth_tag")
      .eq("user_id", req.user.id)
      .eq("provider", "anthropic")
      .maybeSingle();

    if (error) {
      throw error;
    }

    if (!row) {
      return res.json({ hasKey: false });
    }

    try {
      const plaintext = decrypt({ ciphertext: row.ciphertext, iv: row.iv, authTag: row.auth_tag });
      const masked = "sk-ant-••••••••" + plaintext.slice(-4);
      return res.json({ hasKey: true, masked: masked });
    } catch (decryptError) {
      return res.json({ hasKey: true, masked: null, error: "Stored key could not be read" });
    }
  } catch (error) {
    next(error);
  }
});

app.delete("/api/user/api-key", requireAuth, async function (req, res, next) {
  try {
    const { error } = await supabase
      .from("user_api_keys")
      .delete()
      .eq("user_id", req.user.id)
      .eq("provider", "anthropic");

    if (error) {
      throw error;
    }

    return res.json({ deleted: true });
  } catch (error) {
    next(error);
  }
});

var MIST_POSITIONS = ["top-right", "bottom-right", "top-left", "bottom-left"];

app.get("/api/user/preferences", requireAuth, async function (req, res, next) {
  try {
    const { data: row, error } = await supabase
      .from("user_preferences")
      .select("termaximus_active, mist_position, notifications_enabled")
      .eq("user_id", req.user.id)
      .maybeSingle();

    if (error) {
      throw error;
    }

    if (!row) {
      return res.json({
        termaximus_active: true,
        mist_position: "top-right",
        notifications_enabled: true
      });
    }

    return res.json({
      termaximus_active: row.termaximus_active,
      mist_position: row.mist_position,
      notifications_enabled: row.notifications_enabled
    });
  } catch (error) {
    next(error);
  }
});

app.put("/api/user/preferences", requireAuth, async function (req, res, next) {
  try {
    const updates = { user_id: req.user.id, updated_at: nowIso() };

    if (req.body.termaximus_active !== undefined) {
      updates.termaximus_active = !!req.body.termaximus_active;
    }

    if (req.body.mist_position !== undefined) {
      if (MIST_POSITIONS.indexOf(req.body.mist_position) === -1) {
        return res.status(400).json({ error: "Invalid mist_position" });
      }
      updates.mist_position = req.body.mist_position;
    }

    if (req.body.notifications_enabled !== undefined) {
      updates.notifications_enabled = !!req.body.notifications_enabled;
    }

    const { error } = await supabase
      .from("user_preferences")
      .upsert(updates, { onConflict: "user_id" });

    if (error) {
      throw error;
    }

    return res.json({ saved: true });
  } catch (error) {
    next(error);
  }
});

app.get("/api/profile/:username", async function (req, res, next) {
  try {
    const username = normalizeUsername(req.params.username);

    const { data: profile, error } = await supabase
      .from("profiles")
      .select("*")
      .eq("username", username)
      .eq("profile_visibility", "public")
      .maybeSingle();

    if (error) {
      throw error;
    }

    if (!profile) {
      return res.status(404).json({ error: "Profile not found" });
    }

    return res.json({ profile });
  } catch (error) {
    next(error);
  }
});

app.get("/api/profile/by-id/:userId", requireAuth, async function (req, res, next) {
  try {
    const targetUserId = req.params.userId;

    const { data: profile, error } = await supabase
      .from("profiles")
      .select("user_id, full_name, business_name, username, logo_url")
      .eq("user_id", targetUserId)
      .maybeSingle();

    if (error) {
      throw error;
    }

    if (!profile) {
      return res.status(404).json({ error: "Profile not found" });
    }

    return res.json({ profile });
  } catch (error) {
    next(error);
  }
});

app.post("/api/profile/upload-logo", requireAuth, async function (req, res, next) {
  try {
    const logoUrl = safeText(req.body.logo_url, 1000);

    if (!logoUrl) {
      return res.status(400).json({ error: "logo_url is required" });
    }

    const { data: profile, error } = await supabase
      .from("profiles")
      .update({
        logo_url: logoUrl,
        updated_at: nowIso()
      })
      .eq("user_id", req.user.id)
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    return res.json({ profile });
  } catch (error) {
    next(error);
  }
});

app.post("/api/profile/upload-banner", requireAuth, async function (req, res, next) {
  try {
    const bannerUrl = safeText(req.body.banner_url, 1000);

    if (!bannerUrl) {
      return res.status(400).json({ error: "banner_url is required" });
    }

    const { data: profile, error } = await supabase
      .from("profiles")
      .update({
        banner_url: bannerUrl,
        updated_at: nowIso()
      })
      .eq("user_id", req.user.id)
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    return res.json({ profile });
  } catch (error) {
    next(error);
  }
});

app.post("/api/websites", requireAuth, requireActiveSubscription, async function (req, res, next) {
  try {
    const limit = await enforceWebsiteLimit(req.user.id);

    if (!limit.allowed) {
      return res.status(403).json(limit);
    }

    const url = normalizeUrl(req.body.url);
    const name = safeText(req.body.name, 150);

    if (!url) {
      return res.status(400).json({ error: "Website URL is required" });
    }

    const { data: website, error } = await supabase
      .from("websites")
      .insert({
        user_id: req.user.id,
        name: name || url,
        url,
        active: true,
        created_at: nowIso(),
        updated_at: nowIso()
      })
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    return res.status(201).json({ website });
  } catch (error) {
    next(error);
  }
});

app.get("/api/websites", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("websites")
      .select("*")
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: false });

    if (error) {
      throw error;
    }

    return res.json({ websites: data });
  } catch (error) {
    next(error);
  }
});

app.delete("/api/websites/:id", requireAuth, async function (req, res, next) {
  try {
    const { error } = await supabase
      .from("websites")
      .update({
        active: false,
        updated_at: nowIso()
      })
      .eq("id", req.params.id)
      .eq("user_id", req.user.id);

    if (error) {
      throw error;
    }

    return res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

app.get("/api/search/businesses", requireAuth, async function (req, res, next) {
  try {
    const q = safeText(req.query.q, 120);
    const industry = safeText(req.query.industry, 120);
    const location = safeText(req.query.location, 120);
    const limit = Math.min(Number(req.query.limit || 25), 100);

    let query = supabase
      .from("profiles")
      .select("id, user_id, business_name, username, bio, industry, location, website, logo_url, banner_url")
      .eq("profile_visibility", "public")
      .limit(limit);

    if (q) {
      query = query.or(
        "business_name.ilike.%" +
          q +
          "%,username.ilike.%" +
          q +
          "%,bio.ilike.%" +
          q +
          "%,industry.ilike.%" +
          q +
          "%"
      );
    }

    if (industry) {
      query = query.ilike("industry", "%" + industry + "%");
    }

    if (location) {
      query = query.ilike("location", "%" + location + "%");
    }

    const { data, error } = await query.order("created_at", { ascending: false });

    if (error) {
      throw error;
    }

    return res.json({ businesses: data });
  } catch (error) {
    next(error);
  }
});

app.post("/api/follow/:userId", requireAuth, async function (req, res, next) {
  try {
    const followingId = req.params.userId;

    if (followingId === req.user.id) {
      return res.status(400).json({ error: "You cannot follow yourself" });
    }

    const { data, error } = await supabase
      .from("follows")
      .upsert(
        {
          follower_id: req.user.id,
          following_id: followingId,
          created_at: nowIso()
        },
        {
          onConflict: "follower_id,following_id"
        }
      )
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    await supabase.from("notifications").insert({
      user_id: followingId,
      type: "follow",
      title: "New follower",
      message: "Someone followed your business profile.",
      read: false
    });

    return res.status(201).json({ follow: data });
  } catch (error) {
    next(error);
  }
});

app.delete("/api/follow/:userId", requireAuth, async function (req, res, next) {
  try {
    const { error } = await supabase
      .from("follows")
      .delete()
      .eq("follower_id", req.user.id)
      .eq("following_id", req.params.userId);

    if (error) {
      throw error;
    }

    return res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

app.get("/api/followers", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("follows")
      .select("*, follower:profiles!follows_follower_id_fkey(user_id, business_name, username, logo_url, industry)")
      .eq("following_id", req.user.id)
      .order("created_at", { ascending: false });

    if (error) {
      throw error;
    }

    return res.json({ followers: data });
  } catch (error) {
    next(error);
  }
});

app.get("/api/following", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("follows")
      .select("*, following:profiles!follows_following_id_fkey(user_id, business_name, username, logo_url, industry)")
      .eq("follower_id", req.user.id)
      .order("created_at", { ascending: false });

    if (error) {
      throw error;
    }

    return res.json({ following: data });
  } catch (error) {
    next(error);
  }
});

app.post("/api/favorites/:businessId", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("favorites")
      .upsert(
        {
          user_id: req.user.id,
          business_id: req.params.businessId,
          created_at: nowIso()
        },
        {
          onConflict: "user_id,business_id"
        }
      )
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    return res.status(201).json({ favorite: data });
  } catch (error) {
    next(error);
  }
});

app.delete("/api/favorites/:businessId", requireAuth, async function (req, res, next) {
  try {
    const { error } = await supabase
      .from("favorites")
      .delete()
      .eq("user_id", req.user.id)
      .eq("business_id", req.params.businessId);

    if (error) {
      throw error;
    }

    return res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

app.get("/api/feed", requireAuth, async function (req, res, next) {
  try {
    const limit = Math.min(Number(req.query.limit || 25), 100);
    const offset = Math.max(Number(req.query.offset || 0), 0);

    const { data, error } = await supabase
      .from("posts")
      .select("*, profile:profiles(user_id, business_name, username, logo_url)")
      .order("created_at", { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) {
      throw error;
    }

    return res.json({ posts: data });
  } catch (error) {
    next(error);
  }
});

app.post("/api/posts", requireAuth, async function (req, res, next) {
  try {
    const content = safeText(req.body.content, 5000);
    const mediaUrl = safeText(req.body.media_url, 1000);
    const postType = safeText(req.body.post_type, 40) || "standard";

    if (!content && !mediaUrl) {
      return res.status(400).json({ error: "Post content or media is required" });
    }

    const { data, error } = await supabase
      .from("posts")
      .insert({
        user_id: req.user.id,
        content,
        media_url: mediaUrl,
        post_type: postType,
        created_at: nowIso(),
        updated_at: nowIso()
      })
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    return res.status(201).json({ post: data });
  } catch (error) {
    next(error);
  }
});

app.delete("/api/posts/:id", requireAuth, async function (req, res, next) {
  try {
    const { error } = await supabase
      .from("posts")
      .delete()
      .eq("id", req.params.id)
      .eq("user_id", req.user.id);

    if (error) {
      throw error;
    }

    return res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

app.get("/api/conversations", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("messages")
      .select("*")
      .or("sender_id.eq." + req.user.id + ",receiver_id.eq." + req.user.id)
      .order("created_at", { ascending: false })
      .limit(100);

    if (error) {
      throw error;
    }

    return res.json({ conversations: data });
  } catch (error) {
    next(error);
  }
});

app.get("/api/messages/:userId", requireAuth, async function (req, res, next) {
  try {
    const otherUserId = req.params.userId;

    const { data, error } = await supabase
      .from("messages")
      .select("*")
      .or(
        "and(sender_id.eq." +
          req.user.id +
          ",receiver_id.eq." +
          otherUserId +
          "),and(sender_id.eq." +
          otherUserId +
          ",receiver_id.eq." +
          req.user.id +
          ")"
      )
      .order("created_at", { ascending: true });

    if (error) {
      throw error;
    }

    return res.json({ messages: data });
  } catch (error) {
    next(error);
  }
});

app.post("/api/messages", requireAuth, async function (req, res, next) {
  try {
    const receiverId = req.body.receiver_id;
    const content = safeText(req.body.content, 5000);

    if (!receiverId || !content) {
      return res.status(400).json({ error: "receiver_id and content are required" });
    }

    const { data, error } = await supabase
      .from("messages")
      .insert({
        sender_id: req.user.id,
        receiver_id: receiverId,
        content,
        created_at: nowIso()
      })
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    await supabase.from("notifications").insert({
      user_id: receiverId,
      type: "message",
      title: "New message",
      message: "You received a new business message.",
      read: false
    });

    return res.status(201).json({ message: data });
  } catch (error) {
    next(error);
  }
});

app.post("/api/business-chat", requireAuth, async function (req, res, next) {
  try {
    var message = safeText(req.body.message, 4000);
    if (!message) {
      return res.status(400).json({ error: "message is required" });
    }

    var userInsert = await supabase
      .from("chat_messages")
      .insert({
        user_id: req.user.id,
        role: "user",
        content: message,
        created_at: nowIso()
      })
      .select("*")
      .single();
    if (userInsert.error) throw userInsert.error;

    var historyResult = await supabase
      .from("chat_messages")
      .select("role, content, created_at")
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: true })
      .limit(20);
    var history = historyResult.data || [];

    var profileResult = await supabase
      .from("business_profiles")
      .select("*")
      .eq("user_id", req.user.id)
      .single();
    var businessProfile = profileResult.data || {};

    var systemPrompt =
      "You are the BizForce AI Business Guide — a knowledgeable, concise advisor embedded directly inside the user's business platform. " +
      "Your role is to answer questions, give strategic advice, and help solve problems specifically for THIS business. " +
      "Always ground your answers in the business context below. Never give generic advice when specific advice is possible.\n\n" +
      "BUSINESS CONTEXT:\n" +
      "Business Name: " + (businessProfile.business_name || "Not provided") + "\n" +
      "Industry: "       + (businessProfile.industry        || "Not provided") + "\n" +
      "Website: "        + (businessProfile.website         || "Not provided") + "\n" +
      "Description: "    + (businessProfile.description     || "Not provided") + "\n" +
      "Products/Services: " + (businessProfile.products_services || "Not provided") + "\n" +
      "Target Audience: " + (businessProfile.target_audience  || "Not provided") + "\n" +
      "Goals: "          + (businessProfile.business_goals   || "Not provided") + "\n" +
      "Location: "       + (businessProfile.location         || "Not provided") + "\n" +
      "Positioning: "    + (businessProfile.positioning      || "Not provided") + "\n\n" +
      "Keep responses clear and practical. Use bullet points when listing steps or options. Be direct.";

    var messages = history.map(function (row) {
      return { role: row.role, content: row.content };
    });

    const apiKey = await resolveAnthropicKey(req.user.id);
    const anthropicClient = new Anthropic({ apiKey: apiKey });

    var aiResponse = await anthropicClient.messages.create({
      model: "claude-haiku-4-5-20251001",
      max_tokens: 1024,
      system: systemPrompt,
      messages: messages
    });

    var aiText = (aiResponse.content || [])
      .filter(function (block) { return block.type === "text"; })
      .map(function (block) { return block.text; })
      .join("");

    if (!aiText) {
      return res.status(500).json({ error: "AI returned an empty response. Please try again." });
    }

    var assistantInsert = await supabase
      .from("chat_messages")
      .insert({
        user_id: req.user.id,
        role: "assistant",
        content: aiText,
        created_at: nowIso()
      });
    if (assistantInsert.error) {
      console.error("[business-chat] Failed to save assistant message:", assistantInsert.error.message);
    }

    return res.json({ reply: aiText });

  } catch (error) {
    console.error("[business-chat] Error:", error.message || error);
    return res.status(500).json({ error: "Something went wrong. Please try again." });
  }
});

app.get("/api/business-chat", requireAuth, async function (req, res, next) {
  try {
    var result = await supabase
      .from("chat_messages")
      .select("*")
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: true });
    if (result.error) throw result.error;
    return res.json({ messages: result.data || [] });
  } catch (error) {
    next(error);
  }
});

app.get("/api/deals", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("deals")
      .select("*")
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: false });

    if (error) {
      throw error;
    }

    return res.json({ deals: data });
  } catch (error) {
    next(error);
  }
});

app.post("/api/deals", requireAuth, async function (req, res, next) {
  try {
    const title = safeText(req.body.title, 200);

    if (!title) {
      return res.status(400).json({ error: "Deal title is required" });
    }

    const { data, error } = await supabase
      .from("deals")
      .insert({
        user_id: req.user.id,
        title,
        description: safeText(req.body.description, 5000),
        amount: Number(req.body.amount || 0),
        stage: safeText(req.body.stage, 80) || "new",
        contact_name: safeText(req.body.contact_name, 150),
        contact_email: normalizeEmail(req.body.contact_email),
        expected_close_date: req.body.expected_close_date || null,
        probability: Number(req.body.probability || 0),
        created_at: nowIso(),
        updated_at: nowIso()
      })
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    return res.status(201).json({ deal: data });
  } catch (error) {
    next(error);
  }
});

app.put("/api/deals/:id", requireAuth, async function (req, res, next) {
  try {
    const allowed = [
      "title",
      "description",
      "amount",
      "stage",
      "contact_name",
      "contact_email",
      "expected_close_date",
      "probability"
    ];

    const updates = {};

    for (const key of allowed) {
      if (Object.prototype.hasOwnProperty.call(req.body, key)) {
        updates[key] = req.body[key];
      }
    }

    updates.updated_at = nowIso();

    const { data, error } = await supabase
      .from("deals")
      .update(updates)
      .eq("id", req.params.id)
      .eq("user_id", req.user.id)
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    return res.json({ deal: data });
  } catch (error) {
    next(error);
  }
});

app.delete("/api/deals/:id", requireAuth, async function (req, res, next) {
  try {
    const { error } = await supabase
      .from("deals")
      .delete()
      .eq("id", req.params.id)
      .eq("user_id", req.user.id);

    if (error) {
      throw error;
    }

    return res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

app.get("/api/agents", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("ai_agents")
      .select("*")
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: true });

    if (error) {
      throw error;
    }

    const planState = await getUserPlan(req.user.id);

    return res.json({
      agents: data,
      available_agent_types: Object.keys(AGENT_SYSTEM_PROMPTS),
      plan: planState.plan,
      plan_config: planState.config
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/agents", requireAuth, requireActiveSubscription, async function (req, res, next) {
  try {
    const type = String(req.body.type || "").toLowerCase();
    const displayName = safeText(req.body.display_name || req.body.name, 120);

    if (!AGENT_SYSTEM_PROMPTS[type]) {
      return res.status(400).json({ error: "Invalid agent type" });
    }

    const limit = await enforceAgentLimit(req.user.id, type);

    if (!limit.allowed) {
      return res.status(403).json(limit);
    }

    const { data, error } = await supabase
      .from("ai_agents")
      .insert({
        user_id: req.user.id,
        type,
        display_name: displayName || PLAN_CONFIG.enterprise.allowedAgents.includes(type) ? displayName || type.toUpperCase() + " Agent" : type.toUpperCase() + " Agent",
        description: safeText(req.body.description, 500),
        active: true,
        settings: req.body.settings || {},
        tasks_completed: 0,
        estimated_roi: 0,
        created_at: nowIso(),
        updated_at: nowIso()
      })
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    return res.status(201).json({ agent: data });
  } catch (error) {
    next(error);
  }
});

app.put("/api/agents/:id", requireAuth, async function (req, res, next) {
  try {
    const updates = {};

    if (Object.prototype.hasOwnProperty.call(req.body, "display_name")) {
      updates.display_name = safeText(req.body.display_name, 120);
    }

    if (Object.prototype.hasOwnProperty.call(req.body, "description")) {
      updates.description = safeText(req.body.description, 500);
    }

    if (Object.prototype.hasOwnProperty.call(req.body, "settings")) {
      updates.settings = req.body.settings || {};
    }

    if (Object.prototype.hasOwnProperty.call(req.body, "active")) {
      updates.active = Boolean(req.body.active);
    }

    updates.updated_at = nowIso();

    const { data, error } = await supabase
      .from("ai_agents")
      .update(updates)
      .eq("id", req.params.id)
      .eq("user_id", req.user.id)
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    return res.json({ agent: data });
  } catch (error) {
    next(error);
  }
});

app.delete("/api/agents/:id", requireAuth, async function (req, res, next) {
  try {
    const { error } = await supabase
      .from("ai_agents")
      .update({
        active: false,
        updated_at: nowIso()
      })
      .eq("id", req.params.id)
      .eq("user_id", req.user.id);

    if (error) {
      throw error;
    }

    return res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

async function callAnthropicText(promptText, maxTokens, userId = null) {
  var apiKey = await resolveAnthropicKey(userId);
  var anthropicClient = new Anthropic({
    apiKey: apiKey,
    timeout: 120000
  });

  var maxAttempts = 3;
  var lastError;

  for (var attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      var response = await anthropicClient.messages.create({
        model: "claude-haiku-4-5-20251001",
        max_tokens: maxTokens,
        messages: [
          {
            role: "user",
            content: [
              {
                type: "text",
                text: promptText
              }
            ]
          }
        ]
      });

      var text = (response.content || [])
        .filter(function (block) { return block.type === "text"; })
        .map(function (block) { return block.text; })
        .join("");

      return {
        text: text || "",
        stopReason: response.stop_reason || ""
      };

    } catch (err) {
      lastError = err;

      var msgLower = (err.message || "").toLowerCase();
      var isNetworkError =
        err.code === "ERR_STREAM_PREMATURE_CLOSE" ||
        err.code === "ECONNRESET" ||
        err.code === "ECONNREFUSED" ||
        err.code === "ETIMEDOUT" ||
        err.code === "ENOTFOUND" ||
        msgLower.indexOf("premature close") !== -1 ||
        msgLower.indexOf("socket") !== -1 ||
        msgLower.indexOf("network") !== -1 ||
        msgLower.indexOf("connection") !== -1 ||
        msgLower.indexOf("econnreset") !== -1;

      // Never retry real API errors (auth, bad request, etc.)
      var isApiError = err.status >= 400 || err.status === 401 || err.status === 400;

      if (isNetworkError && !isApiError && attempt < maxAttempts) {
        var delay = attempt * 1000;
        console.warn("[callAnthropicText] Network/stream error on attempt " + attempt + ", retrying in " + (delay / 1000) + "s... (" + (err.code || err.message) + ")");
        await new Promise(function (resolve) { setTimeout(resolve, delay); });
        continue;
      }

      throw err;
    }
  }

  throw lastError;
}

function extractRequiredExecutiveAssignmentHeadings(promptText) {
  var text = String(promptText || "");
  var headings = [];
  var seen = {};
  var regex = /AGENT\s+ASSIGNMENT\s+(\d+)\s*:\s*(SEO|CONTENT|SALES|ADS|REPUTATION|ANALYTICS|EMAIL|COMMUNITY|OPERATIONS|INFLUENCER)\s+AGENT\b/gi;
  var match;

  while ((match = regex.exec(text)) !== null) {
    var number = String(match[1]).trim();
    var agent = String(match[2]).trim().toUpperCase();
    var key = number + "|" + agent;

    if (seen[key]) {
      continue;
    }

    seen[key] = true;
    headings.push({
      number: number,
      agent: agent,
      heading: "AGENT ASSIGNMENT " + number + ": " + agent + " AGENT"
    });
  }

  return headings.sort(function(a, b) {
    return Number(a.number) - Number(b.number);
  });
}

function getMissingExecutiveAssignmentHeadings(promptText, outputText) {
  var required = extractRequiredExecutiveAssignmentHeadings(promptText);

  if (!required.length) {
    return [];
  }

  return required.filter(function(item) {
    var pattern = new RegExp(
      "AGENT\\s+ASSIGNMENT\\s+" + item.number + "\\s*:\\s*" + item.agent + "\\s+AGENT\\b",
      "i"
    );

    return !pattern.test(String(outputText || ""));
  });
}

function mergeExecutiveAssignmentOutput(existingOutput, repairOutput) {
  var merged = String(existingOutput || "").trim();
  var repair = String(repairOutput || "").trim();

  if (!repair) {
    return merged;
  }

  if (merged.indexOf(repair) !== -1) {
    return merged;
  }

  return merged + "\n\n" + repair;
}

async function finalizeExecutiveTaskOutput(userPrompt, initialOutput, initialStopReason) {
  var output = String(initialOutput || "").trim();
  var missing = getMissingExecutiveAssignmentHeadings(userPrompt, output);
  var stopReason = initialStopReason || "";

  if (!missing.length && stopReason !== "max_tokens") {
    return {
      output: output,
      complete: true
    };
  }

  var repairPrompt =
    "Return ONLY the missing Executive assignment block(s) listed below.\n" +
    "Use the exact heading format and include all fields: Mission, Owner, Priority, Timeline, Tasks, KPIs, Risks, Next Action.\n" +
    "Do not rewrite or repeat assignments that already exist.\n\n" +
    "Missing required heading(s):\n" +
    missing.map(function(item) {
      return "- " + item.heading;
    }).join("\n") +
    "\n\nExisting report context:\n" +
    output.slice(-6000);

  var repairResult = await callAnthropicText(repairPrompt, 4096);
  output = mergeExecutiveAssignmentOutput(output, repairResult.text);
  missing = getMissingExecutiveAssignmentHeadings(userPrompt, output);

  return {
    output: output,
    complete: !missing.length
  };
}

async function processAiTask(taskId, userId, agentType, taskType, finalPrompt, requiresApproval, userPrompt) {
    try {
        var isExecutive = agentType === "executive";
        var maxTokens = (isExecutive || agentType === "content") ? 8192 : 1200;
        var generation = await callAnthropicText(finalPrompt, maxTokens);
        var output = generation.text;
        var executiveComplete = true;

        if (isExecutive) {
          var executiveResult = await finalizeExecutiveTaskOutput(
            userPrompt || finalPrompt,
            output,
            generation.stopReason
          );

          output = executiveResult.output;
          executiveComplete = executiveResult.complete;
        }

        if (isExecutive && !executiveComplete) {
          await supabase
            .from("ai_tasks")
            .update({
              result: output,
              status: "failed",
              updated_at: nowIso()
            })
            .eq("id", taskId)
            .eq("user_id", userId);

          return;
        }

        var updateResult = await supabase
            .from("ai_tasks")
            .update({
                result: output,
                status: requiresApproval ? "requires_approval" : "completed",
                updated_at: nowIso()
            })
            .eq("id", taskId)
            .eq("user_id", userId);

        if (updateResult.error) {
            throw updateResult.error;
        }

        // Write a concise agent_memory row for this completed task, so the
        // next call for this user_id + agent_type has something to build on.
        // Reuses the exact same table/constants/helpers orchestrateAgentWorkflow
        // writes with (MEMORY_AGENT_TYPES, MEMORY_TYPES via "insight",
        // truncateOrchestratorPreview, normalizeMemoryMetadata) — this is an
        // additional write for the ad-hoc task flow, not a duplicate of
        // orchestrateAgentWorkflow's own assignment-completion memory write.
        if (MEMORY_AGENT_TYPES.indexOf(agentType) !== -1) {
          try {
            var agentMemoryTimestamp = nowIso();
            var agentMemoryContent = truncateOrchestratorPreview(output, 2000) || "Task completed with no captured output.";

            var agentMemoryInsert = await supabase
              .from("agent_memory")
              .insert({
                user_id: userId,
                agent: agentType,
                agent_type: agentType,
                memory_key: agentType + "_ai_task_" + taskId,
                memory_value: agentMemoryContent,
                memory_type: "insight",
                title: "Prompt: " + truncateOrchestratorPreview(userPrompt, 120),
                content: agentMemoryContent,
                metadata: normalizeMemoryMetadata({ source: "ai_task", task_id: taskId, task_type: taskType }),
                created_at: agentMemoryTimestamp,
                updated_at: agentMemoryTimestamp
              });

            if (agentMemoryInsert.error) {
              console.error("[processAiTask] Failed to write agent_memory:", agentMemoryInsert.error.message);
            }
          } catch (agentMemoryErr) {
            console.error("[processAiTask] agent_memory write error:", agentMemoryErr.message || agentMemoryErr);
          }
        }

    } catch (error) {
        console.error("PROCESS AI TASK ERROR:", error);

        await supabase
            .from("ai_tasks")
            .update({
                status: "failed",
                result: "Task failed: " + error.message,
                updated_at: nowIso()
            })
            .eq("id", taskId)
            .eq("user_id", userId);
    }
}
app.get("/api/business-profile", requireAuth, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from("business_profiles")
            .select("*")
            .eq("user_id", req.user.id)
            .single();

        if (error && error.code !== "PGRST116") {
            throw error;
        }

        res.json({
            ok: true,
            profile: data || null
        });
    } catch (err) {
        console.error("Business profile fetch error:", err.message);

        res.status(500).json({
            ok: false,
            error: "Failed to fetch business profile"
        });
    }
});

app.post("/api/business-profile", requireAuth, async function (req, res) {
  try {
    var payload = {
      user_id:           req.user.id,
      business_name:     safeText(req.body.business_name, 120)                                          || null,
      business_type:     safeText(req.body.business_type, 120)                                          || null,
      industry:          safeText(req.body.industry || req.body.niche, 120)                             || null,
      website:           safeText(req.body.website, 500)                                                || null,
      location:          safeText(req.body.location, 200)                                               || null,
      target_audience:   safeText(req.body.target_audience, 500)                                        || null,
      offer:             safeText(req.body.offer, 500)                                                  || null,
      products_services: safeText(req.body.products_services, 1000)                                     || null,
      brand_voice:       safeText(req.body.brand_voice, 500)                                            || null,
      brand_values:      safeText(req.body.brand_values, 1000)                                          || null,
      business_goals:    safeText(req.body.business_goals || req.body.goals || req.body.primary_goal, 1000) || null,
      banned_topics:     safeText(req.body.banned_topics, 1000)                                         || null,
      competitors:       safeText(req.body.competitors || req.body.top_competitors, 500)                || null,
      description:       safeText(req.body.description || req.body.business_description, 2000)          || null,
      social_platforms:  (req.body.social_platforms && typeof req.body.social_platforms === "object" && !Array.isArray(req.body.social_platforms))
        ? req.body.social_platforms : {},
      posting_frequency: safeText(req.body.posting_frequency, 100)                                      || null,
      created_at: nowIso(), updated_at: nowIso()
    };

    var result = await supabase
      .from("business_profiles")
      .upsert(payload, { onConflict: "user_id" })
      .select("*")
      .single();

    if (result.error) {
      console.error("[business-profile POST] Supabase error:", {
        code: result.error.code, message: result.error.message,
        details: result.error.details, hint: result.error.hint
      });
      return res.status(500).json({
        ok: false,
        error: "Save failed",
        db_code: result.error.code,
        db_message: result.error.message,
        db_hint: result.error.hint || result.error.details || null
      });
    }

    res.json({ ok: true, profile: result.data });
  } catch (err) {
    console.error("[business-profile POST] Unexpected error:", err.message);
    res.status(500).json({ ok: false, error: err.message || "Failed to save business profile" });
  }
});

// Shared live-stats aggregation — the same counts GET /api/analytics/summary
// returns, extracted here so both that route and the central brain
// (buildAgentSystemPrompt) read from one place instead of two. All
// independent per-table counts run in a single Promise.all batch rather
// than sequential awaits. Strictly scoped to the given user_id throughout.
async function getLiveStats(userId) {
  var results = await Promise.all([
    supabase.from("ai_tasks").select("*", { count: "exact", head: true }).eq("user_id", userId),
    supabase.from("ai_tasks").select("*", { count: "exact", head: true }).eq("user_id", userId).eq("status", "completed"),
    supabase.from("content_library").select("*", { count: "exact", head: true }).eq("user_id", userId),
    supabase.from("content_library").select("*", { count: "exact", head: true }).eq("user_id", userId).eq("type", "blog"),
    supabase.from("content_library").select("*", { count: "exact", head: true }).eq("user_id", userId).eq("type", "sms"),
    supabase.from("sms_subscribers").select("*", { count: "exact", head: true }).eq("user_id", userId),
    supabase.from("sms_subscribers").select("*", { count: "exact", head: true }).eq("user_id", userId).eq("consent_status", "opted_in"),
    supabase.from("sms_campaigns").select("*", { count: "exact", head: true }).eq("user_id", userId),
    supabase.from("social_post_drafts").select("*", { count: "exact", head: true }).eq("user_id", userId),
    supabase.from("ai_tasks").select("agent_type").eq("user_id", userId)
  ]);

  var tasksRunResult       = results[0];
  var tasksCompletedResult = results[1];
  var contentItemsResult   = results[2];
  var blogItemsResult      = results[3];
  var smsItemsResult       = results[4];
  var subscribersResult    = results[5];
  var optedInResult        = results[6];
  var campaignsResult      = results[7];
  var socialDraftsResult   = results[8];
  var agentRowsResult      = results[9];

  if (tasksRunResult.error)       throw tasksRunResult.error;
  if (tasksCompletedResult.error) throw tasksCompletedResult.error;
  if (contentItemsResult.error)   throw contentItemsResult.error;
  if (blogItemsResult.error)      throw blogItemsResult.error;
  if (smsItemsResult.error)       throw smsItemsResult.error;

  var byAgent = {};
  if (!agentRowsResult.error && Array.isArray(agentRowsResult.data)) {
    agentRowsResult.data.forEach(function (row) {
      var t = row.agent_type || "general";
      byAgent[t] = (byAgent[t] || 0) + 1;
    });
  }

  return {
    tasksRun: tasksRunResult.count || 0,
    tasksCompleted: tasksCompletedResult.count || 0,
    contentItems: contentItemsResult.count || 0,
    blogItems: blogItemsResult.count || 0,
    smsItems: smsItemsResult.count || 0,
    subscribers: subscribersResult.error ? 0 : (subscribersResult.count || 0),
    optedIn: optedInResult.error ? 0 : (optedInResult.count || 0),
    campaigns: campaignsResult.error ? 0 : (campaignsResult.count || 0),
    socialDrafts: socialDraftsResult.error ? 0 : (socialDraftsResult.count || 0),
    byAgent: byAgent
  };
}

async function handleAiTaskRequest(req, res, next) {
  try {
    var userId = req.user.id;
    var agentType = String(req.body.agent_type || req.body.agent || "general").toLowerCase().trim();
    var taskType = String(req.body.task_type || "general").toLowerCase().trim();
    var userPrompt = String(req.body.prompt || "").trim();

    if (!userPrompt) {
      return res.status(400).json({ error: "Missing prompt" });
    }

   var allowedAgents = ["general", "executive", "seo", "sales", "content", "social", "ads", "reputation", "analytics", "email", "community", "influencer", "operations", "store", "publicist", "broker", "crm", "security", "finance", "legal", "research", "rd", "etsy"];
    var allowedTaskTypes = ["general", "executive_plan", "agent_coordination", "seo_audit", "sales_funnel", "content_plan", "social_content", "social_calendar", "ad_campaign", "reputation_plan", "analytics_report", "email_campaign", "community_growth", "influencer_outreach", "operations_workflow", "store_plan", "etsy_store_plan", "publicist_pitch", "broker_opportunity", "crm_followup", "security_review", "finance_plan", "legal_template", "research_report", "deal_pipeline", "partnership_strategy", "negotiation_brief", "due_diligence", "term_sheet", "community_plan", "engagement_strategy", "referral_loop", "retention_system", "moderation_plan", "email_sequence", "winback_flow", "nurture_campaign", "subject_lines", "campaign_plan", "partnership_offer", "creator_list", "roi_forecast", "operations_sop", "workflow_plan", "automation_plan", "checklist_build", "efficiency_audit", "press_release", "media_outreach", "pr_campaign", "brand_narrative", "media_pitch", "market_research", "competitive_intel", "trend_analysis", "innovation_brief", "executive_briefing", "reputation_audit", "review_strategy", "brand_trust", "crisis_response", "sentiment_report", "store_audit", "inventory_plan", "omnichannel_strategy", "conversion_audit", "product_launch", "etsy_listing", "shop_audit", "keyword_research", "pricing_strategy", "competitor_analysis", "sms_campaign"];
    if (!allowedAgents.includes(agentType)) {
      agentType = "general";
    }

    if (!allowedTaskTypes.includes(taskType)) {
      taskType = "general";
    }

    var highRiskPattern = /(buy|purchase|spend|charge|pay|refund|transfer|wire|invest|trade|file taxes|legal filing|lawsuit|sign contract|delete account|hire|fire|send email|post ad|publish|launch campaign)/i;
    var requiresApproval = highRiskPattern.test(userPrompt);

    var memoryResult = await supabase
      .from("ai_tasks")
      .select("agent_type, prompt, result, status, created_at")
      .eq("user_id", userId)
      .eq("agent_type", agentType)
      .order("created_at", { ascending: false })
      .limit(5);
var profileResult = await supabase
.from("business_profiles")
.select("*")
.eq("user_id", userId)
.single();

var businessProfile = profileResult.data || {};

if (memoryResult.error) {
      throw memoryResult.error;
    }

    var liveStats = {};
    try {
      liveStats = await getLiveStats(userId);
    } catch (statsErr) {
      console.error("[handleAiTaskRequest] getLiveStats failed:", statsErr.message || statsErr);
    }

    var memoriesForBrain = (memoryResult.data || []).map(function (task) {
      return {
        agent_type: task.agent_type,
        title: "Prior task",
        content: "Prompt: " + task.prompt + " | Result: " + task.result
      };
    });

    // Recent agent_memory rows for this user_id + agent_type — the same
    // table orchestrateAgentWorkflow writes to (extended, not duplicated;
    // see the write-side comment in processAiTask). A soft read: SELECT
    // isn't constrained by agent_memory's agent_type CHECK, so this is
    // safe to run for every agent type even though writes are gated.
    var agentMemoryResult = await supabase
      .from("agent_memory")
      .select("agent_type, memory_type, title, content, created_at")
      .eq("user_id", userId)
      .eq("agent_type", agentType)
      .order("created_at", { ascending: false })
      .limit(5);

    var agentMemoriesForBrain = (agentMemoryResult.error ? [] : (agentMemoryResult.data || [])).map(function (row) {
      return {
        agent_type: row.agent_type,
        title: row.title || row.memory_type,
        content: row.content
      };
    });

    var combinedMemoriesForBrain = agentMemoriesForBrain.concat(memoriesForBrain);

    var agentBrains = {
      general: "You are BizForce AI, a senior business execution assistant. Produce clear, practical business outputs.",
      executive: "You are the BizForce AI Executive Coordinator Agent. Act like a chief operating officer for the user's business. Break the user's request into coordinated assignments for SEO, Sales, Content, Ads, Reputation, Analytics, Email, Community, Influencer, and Operations agents. Produce an executive plan with priorities, owners, timelines, KPIs, risks, and next actions.",
      seo: "You are the BizForce AI SEO Agent. Produce technical SEO audits, keyword strategies, local SEO plans, content clusters, and ranking action plans.",
      sales: SALES_AGENT_BRAIN,
      content: "You are the BizForce AI Content Agent, a senior SEO copywriter. Given a keyword or topic, you produce ONE complete, publish-ready SEO article in markdown for the user's blog, built to rank in Google and convert readers into buyers. Match the brand voice in the business profile: confident, direct, premium, no fluff or hype words. ALWAYS output in this exact markdown structure: (1) an SEO title tag line under 60 characters including the keyword; (2) a meta description line under 155 characters including the keyword; (3) a suggested URL slug line; (4) an H1 headline then the body in short scannable paragraphs with H2 subheadings; (5) weave the primary keyword into the H1, first paragraph, and subheadings naturally without stuffing. Include 1-2 calls-to-action linking to the user's product, using the product name and URL from the business profile or task instructions. End with a 'Frequently Asked Questions' H2 containing 4-5 Q&A pairs, each answer 2-4 sentences, to target featured snippets and AI search. Output only the finished article with no preamble or explanation. HARD COMPLIANCE RULES, never violate: for any supplement, vitality, health, or wellness topic, never claim the product cures, treats, prevents, or diagnoses any disease, and never compare it to a named prescription drug; use only supportive language like supports, may help, or traditionally used for. Never invent statistics, study results, citations, or customer quotes; if you lack a real source, speak generally. Always include an FDA not-medical-advice disclaimer line for any health, supplement, medical, financial, or legal topic. OUTPUT CLEANLINESS, strictly enforced: use plain text and standard markdown only. Absolutely no emojis, no decorative or novelty symbols, no unicode ornaments, no ASCII art, no arrows or bullet-glyph characters. Use only standard letters, numbers, normal punctuation, and markdown headings, lists, links, and bold. Straight quotes and apostrophes only.",
      ads: "You are the BizForce AI Ads Agent. Build compliant ad campaigns, audience targeting, creative angles, copy, and test plans.",
      reputation: "You are the BizForce AI Reputation Agent. Build review generation systems, response templates, trust signals, and brand protection plans.",
      analytics: "You are the BizForce AI Analytics Agent. Analyze KPIs, traffic, conversion rates, revenue signals, and dashboard priorities.",
      email: "You are the BizForce AI Email Agent. Build email sequences, subject lines, retention flows, winback flows, and nurture campaigns.",
      community: "You are the BizForce AI Community Agent. Build community growth plans, engagement systems, member retention, and partnership plays.",
      influencer: "You are the BizForce AI Influencer Agent. Build outreach scripts, partnership offers, creator lists, and collaboration campaigns.",
      operations: "You are the BizForce AI Operations Agent. Build SOPs, workflows, automation systems, fulfillment checklists, and operating procedures.",
      store: "You are the BizForce AI Store Agent. Optimize e-commerce stores with product strategy, inventory management, conversion rate optimization, omnichannel tactics, and launch plans for physical and digital products.",
      publicist: "You are the BizForce AI Publicist Agent. Write press releases, craft media pitches, build PR campaigns, shape brand narratives, and identify media outreach opportunities to earn coverage and grow visibility.",
      broker: "You are the BizForce AI Broker Agent. Identify deal flow, structure partnership opportunities, build negotiation briefs, outline due diligence checklists, and draft term sheet frameworks for business deals.",
      rd: "You are the BizForce AI R&D Agent. Conduct market research, competitive intelligence analysis, trend forecasting, innovation briefs, and executive-ready briefings to guide strategic business decisions.",
      research: "You are the BizForce AI R&D Agent. Conduct market research, competitive intelligence analysis, trend forecasting, innovation briefs, and executive-ready briefings to guide strategic business decisions.",
      etsy: "You are the BizForce AI Etsy Agent. Optimize Etsy shop listings with SEO-rich titles and tags, conduct shop audits, research high-volume keywords, build pricing strategies, and analyze competitor shops to maximize marketplace visibility and revenue.",
      social: "You are the BizForce AI Social Media Agent. Create platform-specific content plans, engagement strategies, posting schedules, and viral content frameworks for social media growth."
    };

    var taskInstructions = {
      general: "Handle the user request directly and produce a specific, actionable business output. Give concrete steps, examples, and measurable actions — not generic advice.",
      executive: "Produce an Executive Command Plan. Act as the coordinator over all BizForce agents. Break the business objective into agent assignments for SEO, Sales, Content, Ads, Reputation, Analytics, Email, Community, Influencer, and Operations. For each agent include mission, priority level, exact tasks, deadline, KPI, expected outcome, dependencies, and owner approval needs. End with a 7-day, 30-day, 60-day, and 90-day execution roadmap.",
      seo_audit: "Produce a structured SEO audit with technical SEO, keyword strategy, local SEO, content strategy, backlinks, metadata, schema, sitemap, page speed, and conversion recommendations.",
      sales_funnel: "Produce a sales funnel with offer, landing page structure, lead magnet, email sequence, objections, conversion points, upsell path, and tracking KPIs.",
      content_plan: "Produce a content plan with themes, post ideas, schedule, hooks, CTAs, platform strategy, repurposing plan, and brand voice guidance.",
      ad_campaign: "Produce an ad campaign with audience, offer, hooks, creative angles, copy, budget guidance, testing plan, and compliance-safe language.",
      deal_pipeline: "Build a deal pipeline analysis: identify 5 specific deal or partnership opportunities relevant to the business, each with target company profile, deal structure, estimated value, and first outreach step.",
      partnership_strategy: "Create a partnership strategy: identify ideal partner types, value exchange structure, co-marketing opportunities, revenue share models, and an outreach sequence with a sample first message.",
      negotiation_brief: "Write a negotiation brief covering the user's objectives, BATNA, key leverage points, concession ranges, red lines, and a proposed opening position with reasoning.",
      due_diligence: "Build a due diligence checklist tailored to the deal context covering: financials, legal, operations, team, technology, market position, and risk factors — with specific questions for each area.",
      term_sheet: "Draft a term sheet framework covering deal structure, valuation basis, equity or revenue split, key milestones, exit provisions, exclusivity period, and standard protective clauses.",
      community_plan: "Create a community growth plan with platform selection, founding member strategy, content programming schedule, engagement rituals, and a 90-day launch roadmap with weekly milestones.",
      engagement_strategy: "Build an engagement strategy: daily engagement actions, response templates, community challenges, recognition programs, and UGC (user-generated content) prompts to increase participation.",
      referral_loop: "Design a referral loop system: incentive structure, referral mechanics, messaging templates, tracking method, and activation sequence to turn members into advocates.",
      retention_system: "Create a retention system: onboarding sequence, 30/60/90 day check-in touchpoints, churn warning signals, win-back campaigns, and loyalty recognition tiers.",
      moderation_plan: "Write a moderation plan: community rules, enforcement tiers, moderator playbook, escalation process, and templates for handling violations, conflicts, and spam.",
      email_campaign: "Write a complete email campaign: subject lines (A/B variants), preview text, body copy, CTA, send cadence, audience segmentation, and success metrics.",
      email_sequence: "Build a multi-email nurture sequence: welcome email, value emails (2-3), proof/social email, and offer email — each with subject line, body copy, and CTA.",
      winback_flow: "Create a winback email flow: trigger definition, 3-5 email sequence with subject lines and copy, final offer email, and sunset criteria for unresponsive contacts.",
      nurture_campaign: "Build a lead nurture campaign: segment definitions, content themes per stage, email templates, send timing, and conversion triggers that move leads to purchase.",
      subject_lines: "Generate 20 subject line variations for the given campaign goal — including curiosity, urgency, personalization, benefit-led, and question-based styles. Note which to A/B test first.",
      influencer_outreach: "Write an influencer outreach campaign: target creator profile (niche, size, engagement rate), 3 outreach email templates, partnership offer structure, and a 30-day campaign timeline.",
      campaign_plan: "Build an influencer campaign plan: campaign goal, creator selection criteria, content brief, usage rights, performance KPIs, payment structure, and post-campaign reporting format.",
      partnership_offer: "Draft a creator partnership offer: value proposition, deliverables, compensation (flat fee + performance bonus structure), exclusivity terms, and content approval process.",
      creator_list: "Generate a creator list strategy: ideal creator archetypes, platform focus, discovery methods, outreach prioritization, and a scoring rubric to evaluate fit.",
      roi_forecast: "Build an influencer ROI forecast: estimated reach, engagement rate assumptions, conversion rate, projected revenue, cost per acquisition, and break-even analysis.",
      operations_sop: "Write a detailed SOP for the requested process: purpose, scope, step-by-step procedure, roles and responsibilities, tools used, quality checkpoints, and exception handling.",
      workflow_plan: "Build a workflow plan: process map with stages, handoff points, estimated time per step, automation opportunities, bottleneck risks, and KPIs to track efficiency.",
      automation_plan: "Create an automation plan: identify 5 high-impact processes to automate, recommended tools, implementation priority, estimated time savings, and integration steps.",
      checklist_build: "Build a detailed operational checklist for the requested process: pre-execution checks, execution steps, quality verification points, and completion sign-off criteria.",
      efficiency_audit: "Conduct an operations efficiency audit: identify 5 bottlenecks or waste areas, root cause for each, recommended fix, implementation difficulty, and expected impact.",
      press_release: "Write a professional press release: headline, dateline, lead paragraph (5 Ws), body with quotes, boilerplate, and media contact block — ready for distribution.",
      media_outreach: "Build a media outreach plan: target publications and journalists (by beat), personalized pitch angles for each, pitch email template, follow-up sequence, and tracking method.",
      pr_campaign: "Create a PR campaign: news hook, story angles, target media list (type/tier), press materials checklist, launch timeline, and success metrics.",
      brand_narrative: "Craft a brand narrative: origin story, mission statement, brand values, hero customer story, key messages by audience, and an elevator pitch in 3 lengths (30s, 60s, 3min).",
      media_pitch: "Write 3 media pitch variations for different journalist personas: a news hook pitch, a trend story pitch, and a human interest pitch — each under 200 words with a subject line.",
      market_research: "Conduct a market research brief: market size estimate, key segments, growth trends, customer pain points, unmet needs, and 3 market entry or expansion opportunities.",
      competitive_intel: "Build a competitive intelligence report: top 5 competitors, their positioning, pricing, strengths, weaknesses, recent moves, and strategic gaps the business can exploit.",
      trend_analysis: "Produce a trend analysis: 5 relevant industry or market trends, evidence for each, business impact (opportunity/threat), recommended response, and 12-month outlook.",
      innovation_brief: "Write an innovation brief: problem to solve, customer insight driving it, 3 product or service concepts, feasibility assessment, potential business model, and next validation step.",
      executive_briefing: "Create an executive briefing: situation summary, key data points, decision options with pros/cons, recommended action, risk factors, and resource requirements — fit for a leadership presentation.",
      reputation_audit: "Conduct a reputation audit: review platform scores, sentiment patterns, top positive/negative themes, competitor comparison, and a priority repair plan for weak areas.",
      review_strategy: "Build a review generation strategy: ask timing, request channels, messaging templates (email/SMS/in-person), incentive-safe approaches, and a monthly review tracking system.",
      brand_trust: "Create a brand trust plan: trust signals to add (certifications, testimonials, press, guarantees), messaging changes, website credibility elements, and a 60-day trust-building calendar.",
      crisis_response: "Write a crisis response playbook: situation assessment criteria, internal escalation steps, holding statement template, spokesperson guidelines, platform-specific response templates, and post-crisis review process.",
      sentiment_report: "Produce a sentiment report: overall brand sentiment score, positive/negative/neutral breakdown, key themes driving each, competitor sentiment comparison, and recommended messaging shifts.",
      store_audit: "Conduct a store audit: homepage effectiveness, product page quality, checkout friction points, mobile experience, trust signals, load speed, and a prioritized fix list.",
      inventory_plan: "Build an inventory plan: demand forecasting method, reorder point calculation, safety stock formula, supplier diversity strategy, and seasonal adjustment guidelines.",
      omnichannel_strategy: "Create an omnichannel retail strategy: channel mix (online/offline/marketplace), inventory sync approach, customer experience consistency plan, and channel-specific marketing tactics.",
      conversion_audit: "Audit conversion rate: identify 5 drop-off points in the funnel, root cause analysis, A/B test recommendations for each, priority order, and expected lift estimates.",
      product_launch: "Build a product launch plan: launch timeline, pre-launch buzz tactics, launch day actions, email/social/ad coordination, influencer seeding, and post-launch review criteria.",
      etsy_listing: "Optimize an Etsy listing: SEO-rich title (140 chars), 13 keyword tags, description structure (hook + features + story + CTA), pricing guidance, photo requirements, and shipping strategy.",
      shop_audit: "Conduct an Etsy shop audit: shop score assessment, listing quality review, keyword coverage gaps, pricing competitiveness, photo quality, shop sections, and a 30-day improvement plan.",
      keyword_research: "Produce an Etsy keyword research report: 20 high-volume low-competition keywords, long-tail phrase variations, seasonal keyword opportunities, and placement guidance (title vs tags).",
      pricing_strategy: "Build an Etsy pricing strategy: cost breakdown, competitive price range, value-based pricing rationale, bundle opportunities, sale/coupon strategy, and price testing plan.",
      competitor_analysis: "Analyze Etsy competitors: top 5 competing shops, their listing strategies, pricing, review counts, bestseller patterns, and gaps the user can exploit to differentiate.",
      reputation_plan: "Build a reputation management plan: monitoring setup, review response templates, proactive reputation tactics, and a 90-day brand trust improvement roadmap.",
      analytics_report: "Produce an analytics report framework: key metrics dashboard, traffic analysis, conversion funnel, revenue attribution, and monthly reporting cadence with action triggers.",
      email_campaign_plan: "Create an email marketing strategy: list segmentation, campaign calendar, automation workflows, deliverability best practices, and growth tactics.",
      community_growth: "Build a community growth strategy: acquisition channels, onboarding flow, engagement programming, and member retention systems.",
      operations_workflow: "Design an operations workflow: process documentation, team roles, handoff procedures, quality controls, and efficiency metrics.",
      store_plan: "Create a comprehensive store strategy: product selection, pricing, marketing mix, customer acquisition, and scaling roadmap.",
      etsy_store_plan: "Build an Etsy shop strategy: niche selection, product line planning, SEO approach, listing optimization, and growth tactics.",
      publicist_pitch: "Craft media pitches and PR materials: press releases, journalist outreach, story angles, and media relationship building.",
      broker_opportunity: "Identify and structure business opportunities: deal sourcing, partnership frameworks, negotiation preparation, and deal closing strategy.",
      research_report: "Conduct business research and analysis: market intelligence, competitive landscape, trend identification, and strategic recommendations."
    };

    var approvalInstruction = requiresApproval
      ? "This request contains high-risk execution. Do NOT claim the action was executed. Return an approval-required action plan only."
      : "This request is advisory/planning only. Provide execution-ready guidance.";

   var agentBrain = agentBrains[agentType] || agentBrains["general"];
    var taskInstruction = taskInstructions[taskType] || taskInstructions["general"];
    var sharedSystemPrompt = buildAgentSystemPrompt(agentBrain, businessProfile, liveStats, combinedMemoriesForBrain);
    var finalPrompt =
  sharedSystemPrompt +
  "\n\nTASK TYPE:\n" + taskType +
  "\n\nTASK INSTRUCTIONS:\n" + taskInstruction +
  "\n\nSAFETY RULES:\n" +
  "- Do not execute purchases, payments, legal filings, tax actions, account creation, or financial transactions.\n" +
  "- For high-risk actions, return requires_approval true and an approval plan.\n" +
  "- Keep outputs lawful, practical, and business-safe.\n" +
  "\n\nAPPROVAL STATUS:\n" + approvalInstruction +
  "\n\nUSER REQUEST:\n" + userPrompt;
    var pendingInsert = await supabase
      .from("ai_tasks")
      .insert({
        user_id: userId,
        agent_type: agentType,
        prompt: userPrompt,
        result: null,
        status: "processing"
      })
      .select("*")
      .single();

    if (pendingInsert.error) {
      throw pendingInsert.error;
    }

    var taskRecord = pendingInsert.data;
setImmediate(function () {
  processAiTask(taskRecord.id, userId, agentType, taskType, finalPrompt, requiresApproval, userPrompt).catch(function (error) {
    console.error("Async AI task failed:", error);
  });
});

return res.status(202).json({
  success: true,
  queued: true,
  task: taskRecord,
  message: "AI task queued successfully."
});
  } catch (error) {
    console.error("AI TASK ERROR:", error);
    next(error);
  }
}
app.post("/api/ai/tasks", requireAuth, requireActiveSubscription, aiLimiter, handleAiTaskRequest);

app.post("/api/ai-reports", requireAuth, async function (req, res, next) {
  try {
    var payload = {
      user_id: req.user.id,
      agent: req.body.agent || "AI Agent",
      task_type: req.body.task_type || "general",
      prompt: req.body.prompt || "",
      summary: req.body.summary || "",
      result: req.body.result || "",
      unread: req.body.unread !== false
    };

    var result = await supabase
      .from("ai_reports")
      .insert(payload)
      .select("*")
      .single();

    if (result.error) {
      throw result.error;
    }

    return res.json({
      ok: true,
      report: result.data
    });
  } catch (error) {
    console.error("AI REPORT SAVE ERROR:", error);
    next(error);
  }
});

app.post("/api/assignments/batch", requireAuth, async function (req, res, next) {
  try {
    var userId = req.user.id;
    var executiveTaskId = String(req.body.executive_task_id || "").trim();
    var rawAssignments = req.body.assignments;

    console.log("ASSIGNMENTS BATCH RECEIVED", {
      user_id: userId,
      executive_task_id: executiveTaskId,
      count: Array.isArray(rawAssignments) ? rawAssignments.length : 0
    });

    if (!isValidUuid(executiveTaskId)) {
      return res.status(400).json({
        ok: false,
        error: "Missing or invalid executive_task_id"
      });
    }

    if (!Array.isArray(rawAssignments) || rawAssignments.length === 0) {
      return res.status(400).json({
        ok: false,
        error: "assignments must be a non-empty array"
      });
    }

    var taskCheck = await supabase
      .from("ai_tasks")
      .select("id")
      .eq("id", executiveTaskId)
      .eq("user_id", userId)
      .maybeSingle();

    if (taskCheck.error) {
      throw taskCheck.error;
    }

    if (!taskCheck.data) {
      return res.status(400).json({
        ok: false,
        error: "executive_task_id not found for this user"
      });
    }

    var normalizedAssignments = [];
    var seenKeys = {};

    for (var i = 0; i < rawAssignments.length; i++) {
      var normalized = normalizeAssignmentInput(rawAssignments[i]);

      if (!normalized) {
        return res.status(400).json({
          ok: false,
          error: "Invalid assignment at index " + i + ". assignment_number and agent_type are required."
        });
      }

      var dedupeKey =
        normalized.assignment_number + "|" + normalized.agent_type;

      if (seenKeys[dedupeKey]) {
        return res.status(400).json({
          ok: false,
          error: "Duplicate assignment in request: " + dedupeKey
        });
      }

      seenKeys[dedupeKey] = true;
      normalizedAssignments.push(normalized);
    }

    var timestamp = nowIso();
    var rows = normalizedAssignments.map(function (item) {
      return {
        user_id: userId,
        executive_task_id: executiveTaskId,
        assignment_number: item.assignment_number,
        agent_type: item.agent_type,
        mission: item.mission,
        priority: item.priority,
        timeline: item.timeline,
        tasks: item.tasks,
        kpis: item.kpis,
        risks: item.risks,
        status: "pending",
        updated_at: timestamp
      };
    });

    var insertResult = await supabase
      .from("agent_assignments")
      .upsert(rows, {
        onConflict: "user_id,executive_task_id,assignment_number,agent_type",
        ignoreDuplicates: true
      })
      .select("*");

    if (insertResult.error) {
      throw insertResult.error;
    }

    var listResult = await supabase
      .from("agent_assignments")
      .select("*")
      .eq("user_id", userId)
      .eq("executive_task_id", executiveTaskId)
      .order("assignment_number", { ascending: true });

    if (listResult.error) {
      throw listResult.error;
    }

    var insertedCount = insertResult.data ? insertResult.data.length : 0;

    console.log("ASSIGNMENTS BATCH SAVED", {
      user_id: userId,
      executive_task_id: executiveTaskId,
      inserted: insertedCount,
      total: listResult.data ? listResult.data.length : 0
    });

    return res.status(201).json({
      ok: true,
      inserted: insertedCount,
      assignments: listResult.data || []
    });
  } catch (error) {
    console.error("ASSIGNMENTS BATCH ERROR:", error);
    next(error);
  }
});

app.get("/api/assignments", requireAuth, async function (req, res, next) {
  try {
    var userId = req.user.id;
    var query = supabase
      .from("agent_assignments")
      .select("*")
      .eq("user_id", userId)
      .order("created_at", { ascending: false });

    var status = String(req.query.status || "").toLowerCase().trim();
    var agentType = String(req.query.agent_type || "").toLowerCase().trim();
    var executiveTaskId = String(req.query.executive_task_id || "").trim();

    if (status) {
      if (ASSIGNMENT_STATUSES.indexOf(status) === -1) {
        return res.status(400).json({
          ok: false,
          error: "Invalid status filter"
        });
      }

      query = query.eq("status", status);
    }

    if (agentType) {
      query = query.eq("agent_type", agentType);
    }

    if (executiveTaskId) {
      if (!isValidUuid(executiveTaskId)) {
        return res.status(400).json({
          ok: false,
          error: "Invalid executive_task_id filter"
        });
      }

      query = query.eq("executive_task_id", executiveTaskId);
    }

    var result = await query;

    if (result.error) {
      throw result.error;
    }

    console.log("ASSIGNMENTS LIST FETCHED", {
      user_id: userId,
      count: result.data ? result.data.length : 0
    });

    return res.json({
      ok: true,
      assignments: result.data || []
    });
  } catch (error) {
    console.error("ASSIGNMENTS LIST ERROR:", error);
    next(error);
  }
});

app.get("/api/assignments/:id", requireAuth, async function (req, res, next) {
  try {
    var userId = req.user.id;
    var assignmentId = String(req.params.id || "").trim();

    if (!isValidUuid(assignmentId)) {
      return res.status(400).json({
        ok: false,
        error: "Invalid assignment id"
      });
    }

    var result = await supabase
      .from("agent_assignments")
      .select("*")
      .eq("id", assignmentId)
      .eq("user_id", userId)
      .maybeSingle();

    if (result.error) {
      throw result.error;
    }

    if (!result.data) {
      return res.status(404).json({
        ok: false,
        error: "Assignment not found"
      });
    }

    console.log("ASSIGNMENT DETAIL FETCHED", {
      user_id: userId,
      assignment_id: assignmentId
    });

    return res.json({
      ok: true,
      assignment: result.data
    });
  } catch (error) {
    console.error("ASSIGNMENT DETAIL ERROR:", error);
    next(error);
  }
});

app.post("/api/assignments/:id/start", requireAuth, async function (req, res, next) {
  try {
    var userId = req.user.id;
    var assignmentId = String(req.params.id || "").trim();
    var isFrontendAssignmentId = /^asg_[A-Za-z0-9_-]+$/.test(assignmentId);

    if (!isValidUuid(assignmentId) && !isFrontendAssignmentId) {
      return res.status(400).json({
        ok: false,
        error: "Invalid assignment id"
      });
    }

    var fetchResult = { data: null, error: null };

    if (isValidUuid(assignmentId)) {
      fetchResult = await supabase
        .from("agent_assignments")
        .select("*")
        .eq("id", assignmentId)
        .eq("user_id", userId)
        .maybeSingle();

      if (fetchResult.error) {
        throw fetchResult.error;
      }
    }

    if (!fetchResult.data) {
      if (isFrontendAssignmentId) {
        var localAgentType = String(req.body.agent_type || "general").toLowerCase().trim();
        var localMission = safeText(req.body.mission, 5000) || "";
        var localPriority = safeText(req.body.priority, 120) || "";
        var localTimeline = safeText(req.body.timeline, 500) || "";
        var localAssignment = {
          id: assignmentId,
          agent_type: localAgentType,
          mission: localMission,
          priority: localPriority,
          timeline: localTimeline,
          status: "completed",
          tasks: normalizeJsonbArray(req.body.tasks)
        };
        var localResult = safeText(req.body.result, 20000);

        if (!localResult) {
          localResult = buildAssignmentExecutionResult(localAssignment);
        }

        console.log("ASSIGNMENT START COMPLETED", {
          user_id: userId,
          assignment_id: assignmentId,
          agent_type: localAgentType,
          source: "frontend_asg"
        });

        var frontendOrchestration = await orchestrateAgentWorkflow({
          userId: userId,
          assignment: localAssignment,
          resultText: localResult,
          isFrontendAssignment: true
        });

        return res.json({
          ok: true,
          assignment: {
            id: assignmentId,
            agent_type: localAgentType,
            mission: localMission,
            priority: localPriority,
            timeline: localTimeline,
            status: "completed"
          },
          result: localResult,
          orchestration: frontendOrchestration
        });
      }

      return res.status(404).json({
        ok: false,
        error: "Assignment not found"
      });
    }

    var assignment = fetchResult.data;

    if (assignment.status === "completed") {
      return res.json({
        ok: true,
        already_completed: true,
        message: "Assignment already completed.",
        assignment: assignment,
        result: "Assignment was already completed. No further action was taken."
      });
    }

    var agentType = String(assignment.agent_type || "").toLowerCase().trim();

    if (ROUTABLE_ASSIGNMENT_AGENT_TYPES.indexOf(agentType) === -1) {
      return res.status(400).json({
        ok: false,
        error: "Unsupported agent_type for routing: " + agentType
      });
    }

    var inProgressUpdate = await supabase
      .from("agent_assignments")
      .update({
        status: "in_progress",
        updated_at: nowIso()
      })
      .eq("id", assignmentId)
      .eq("user_id", userId)
      .select("*")
      .single();

    if (inProgressUpdate.error) {
      throw inProgressUpdate.error;
    }

    var executionResult = buildAssignmentExecutionResult(inProgressUpdate.data);

    var completedUpdate = await supabase
      .from("agent_assignments")
      .update({
        status: "completed",
        updated_at: nowIso()
      })
      .eq("id", assignmentId)
      .eq("user_id", userId)
      .select("*")
      .single();

    if (completedUpdate.error) {
      throw completedUpdate.error;
    }

    console.log("ASSIGNMENT START COMPLETED", {
      user_id: userId,
      assignment_id: assignmentId,
      agent_type: agentType
    });

    var orchestration = await orchestrateAgentWorkflow({
      userId: userId,
      assignment: completedUpdate.data,
      resultText: executionResult
    });

    return res.json({
      ok: true,
      assignment: completedUpdate.data,
      result: executionResult,
      orchestration: orchestration
    });
  } catch (error) {
    console.error("ASSIGNMENT START ERROR:", error);
    next(error);
  }
});

app.post("/api/memory", requireAuth, async function (req, res, next) {
  try {
    var userId = req.user.id;
    var agentType = String(req.body.agent_type || "").toLowerCase().trim();
    var memoryType = String(req.body.memory_type || "").toLowerCase().trim();
    var title = safeText(req.body.title, 500);
    var content = safeText(req.body.content, 20000);

    if (!agentType || MEMORY_AGENT_TYPES.indexOf(agentType) === -1) {
      return res.status(400).json({
        ok: false,
        error: "Invalid or missing agent_type"
      });
    }

    if (!memoryType || MEMORY_TYPES.indexOf(memoryType) === -1) {
      return res.status(400).json({
        ok: false,
        error: "Invalid or missing memory_type"
      });
    }

    if (!title) {
      return res.status(400).json({
        ok: false,
        error: "Missing title"
      });
    }

    if (!content) {
      return res.status(400).json({
        ok: false,
        error: "Missing content"
      });
    }

    var timestamp = nowIso();
    var insertResult = await supabase
      .from("agent_memory")
      .insert({
        user_id: userId,
        agent_type: agentType,
        assignment_id: null,
        memory_type: memoryType,
        title: title,
        content: content,
        metadata: normalizeMemoryMetadata(req.body.metadata),
        created_at: timestamp,
        updated_at: timestamp
      })
      .select("*")
      .single();

    if (insertResult.error) {
      throw insertResult.error;
    }

    return res.status(201).json({
      ok: true,
      memory: insertResult.data
    });
  } catch (error) {
    console.error("AGENT MEMORY CREATE ERROR:", error);
    next(error);
  }
});

app.get("/api/memory", requireAuth, async function (req, res, next) {
  try {
    var userId = req.user.id;
    var limit = Math.min(Math.max(Number(req.query.limit || 50), 1), 100);
    var query = supabase
      .from("agent_memory")
      .select("*")
      .eq("user_id", userId)
      .order("created_at", { ascending: false })
      .limit(limit);

    var agentType = String(req.query.agent_type || "").toLowerCase().trim();
    var memoryType = String(req.query.memory_type || "").toLowerCase().trim();

    if (agentType) {
      if (MEMORY_AGENT_TYPES.indexOf(agentType) === -1) {
        return res.status(400).json({
          ok: false,
          error: "Invalid agent_type filter"
        });
      }

      query = query.eq("agent_type", agentType);
    }

    if (memoryType) {
      if (MEMORY_TYPES.indexOf(memoryType) === -1) {
        return res.status(400).json({
          ok: false,
          error: "Invalid memory_type filter"
        });
      }

      query = query.eq("memory_type", memoryType);
    }

    var result = await query;

    if (result.error) {
      throw result.error;
    }

    return res.json({
      ok: true,
      memories: result.data || []
    });
  } catch (error) {
    console.error("AGENT MEMORY LIST ERROR:", error);
    next(error);
  }
});

app.get("/api/memory/:id", requireAuth, async function (req, res, next) {
  try {
    var userId = req.user.id;
    var memoryId = String(req.params.id || "").trim();

    if (!isValidUuid(memoryId)) {
      return res.status(400).json({
        ok: false,
        error: "Invalid memory id"
      });
    }

    var result = await supabase
      .from("agent_memory")
      .select("*")
      .eq("id", memoryId)
      .eq("user_id", userId)
      .maybeSingle();

    if (result.error) {
      throw result.error;
    }

    if (!result.data) {
      return res.status(404).json({
        ok: false,
        error: "Memory not found"
      });
    }

    return res.json({
      ok: true,
      memory: result.data
    });
  } catch (error) {
    console.error("AGENT MEMORY DETAIL ERROR:", error);
    next(error);
  }
});

app.delete("/api/memory/:id", requireAuth, async function (req, res, next) {
  try {
    var userId = req.user.id;
    var memoryId = String(req.params.id || "").trim();

    if (!isValidUuid(memoryId)) {
      return res.status(400).json({
        ok: false,
        error: "Invalid memory id"
      });
    }

    var result = await supabase
      .from("agent_memory")
      .delete()
      .eq("id", memoryId)
      .eq("user_id", userId)
      .select("*")
      .maybeSingle();

    if (result.error) {
      throw result.error;
    }

    if (!result.data) {
      return res.status(404).json({
        ok: false,
        error: "Memory not found"
      });
    }

    return res.json({
      ok: true,
      deleted: true,
      memory: result.data
    });
  } catch (error) {
    console.error("AGENT MEMORY DELETE ERROR:", error);
    next(error);
  }
});

app.post("/api/collaborations", requireAuth, async function (req, res, next) {
  try {
    var userId = req.user.id;
    var sourceAgent = String(req.body.source_agent || "").toLowerCase().trim();
    var targetAgent = String(req.body.target_agent || "").toLowerCase().trim();
    var collaborationType = String(req.body.collaboration_type || "").toLowerCase().trim();
    var status = String(req.body.status || "pending").toLowerCase().trim();
    var parentAssignmentId = req.body.parent_assignment_id
      ? String(req.body.parent_assignment_id).trim()
      : null;

    if (!sourceAgent || COLLABORATION_AGENT_TYPES.indexOf(sourceAgent) === -1) {
      return res.status(400).json({
        ok: false,
        error: "Invalid or missing source_agent"
      });
    }

    if (!targetAgent || COLLABORATION_AGENT_TYPES.indexOf(targetAgent) === -1) {
      return res.status(400).json({
        ok: false,
        error: "Invalid or missing target_agent"
      });
    }

    if (!collaborationType || COLLABORATION_TYPES.indexOf(collaborationType) === -1) {
      return res.status(400).json({
        ok: false,
        error: "Invalid or missing collaboration_type"
      });
    }

    if (COLLABORATION_STATUSES.indexOf(status) === -1) {
      return res.status(400).json({
        ok: false,
        error: "Invalid status"
      });
    }

    if (parentAssignmentId && !isValidUuid(parentAssignmentId)) {
      return res.status(400).json({
        ok: false,
        error: "Invalid parent_assignment_id"
      });
    }

    var timestamp = nowIso();
    var insertResult = await supabase
      .from("agent_collaborations")
      .insert({
        user_id: userId,
        parent_assignment_id: parentAssignmentId,
        source_agent: sourceAgent,
        target_agent: targetAgent,
        collaboration_type: collaborationType,
        payload: normalizeCollaborationPayload(req.body.payload),
        status: status,
        created_at: timestamp,
        updated_at: timestamp
      })
      .select("*")
      .single();

    if (insertResult.error) {
      throw insertResult.error;
    }

    console.log("COLLABORATION CREATED", {
      user_id: userId,
      collaboration_id: insertResult.data.id,
      source_agent: sourceAgent,
      target_agent: targetAgent,
      collaboration_type: collaborationType
    });

    return res.status(201).json({
      ok: true,
      collaboration: insertResult.data
    });
  } catch (error) {
    console.error("COLLABORATION CREATE ERROR:", error);
    next(error);
  }
});

app.get("/api/collaborations", requireAuth, async function (req, res, next) {
  try {
    var userId = req.user.id;
    var limit = Math.min(Math.max(Number(req.query.limit || 50), 1), 100);
    var query = supabase
      .from("agent_collaborations")
      .select("*")
      .eq("user_id", userId)
      .order("created_at", { ascending: false })
      .limit(limit);

    var sourceAgent = String(req.query.source_agent || "").toLowerCase().trim();
    var targetAgent = String(req.query.target_agent || "").toLowerCase().trim();
    var collaborationType = String(req.query.collaboration_type || "").toLowerCase().trim();
    var status = String(req.query.status || "").toLowerCase().trim();

    if (sourceAgent) {
      if (COLLABORATION_AGENT_TYPES.indexOf(sourceAgent) === -1) {
        return res.status(400).json({
          ok: false,
          error: "Invalid source_agent filter"
        });
      }

      query = query.eq("source_agent", sourceAgent);
    }

    if (targetAgent) {
      if (COLLABORATION_AGENT_TYPES.indexOf(targetAgent) === -1) {
        return res.status(400).json({
          ok: false,
          error: "Invalid target_agent filter"
        });
      }

      query = query.eq("target_agent", targetAgent);
    }

    if (collaborationType) {
      if (COLLABORATION_TYPES.indexOf(collaborationType) === -1) {
        return res.status(400).json({
          ok: false,
          error: "Invalid collaboration_type filter"
        });
      }

      query = query.eq("collaboration_type", collaborationType);
    }

    if (status) {
      if (COLLABORATION_STATUSES.indexOf(status) === -1) {
        return res.status(400).json({
          ok: false,
          error: "Invalid status filter"
        });
      }

      query = query.eq("status", status);
    }

    var result = await query;

    if (result.error) {
      throw result.error;
    }

    console.log("COLLABORATIONS FETCHED", {
      user_id: userId,
      count: result.data ? result.data.length : 0
    });

    return res.json({
      ok: true,
      collaborations: result.data || []
    });
  } catch (error) {
    console.error("COLLABORATIONS LIST ERROR:", error);
    next(error);
  }
});

app.get("/api/collaborations/:id", requireAuth, async function (req, res, next) {
  try {
    var userId = req.user.id;
    var collaborationId = String(req.params.id || "").trim();

    if (!isValidUuid(collaborationId)) {
      return res.status(400).json({
        ok: false,
        error: "Invalid collaboration id"
      });
    }

    var result = await supabase
      .from("agent_collaborations")
      .select("*")
      .eq("id", collaborationId)
      .eq("user_id", userId)
      .maybeSingle();

    if (result.error) {
      throw result.error;
    }

    if (!result.data) {
      return res.status(404).json({
        ok: false,
        error: "Collaboration not found"
      });
    }

    console.log("COLLABORATION DETAIL FETCHED", {
      user_id: userId,
      collaboration_id: collaborationId
    });

    return res.json({
      ok: true,
      collaboration: result.data
    });
  } catch (error) {
    console.error("COLLABORATION DETAIL ERROR:", error);
    next(error);
  }
});

app.delete("/api/collaborations/:id", requireAuth, async function (req, res, next) {
  try {
    var userId = req.user.id;
    var collaborationId = String(req.params.id || "").trim();

    if (!isValidUuid(collaborationId)) {
      return res.status(400).json({
        ok: false,
        error: "Invalid collaboration id"
      });
    }

    var result = await supabase
      .from("agent_collaborations")
      .delete()
      .eq("id", collaborationId)
      .eq("user_id", userId)
      .select("*")
      .maybeSingle();

    if (result.error) {
      throw result.error;
    }

    if (!result.data) {
      return res.status(404).json({
        ok: false,
        error: "Collaboration not found"
      });
    }

    console.log("COLLABORATION DELETED", {
      user_id: userId,
      collaboration_id: collaborationId
    });

    return res.json({
      ok: true,
      deleted: true,
      collaboration: result.data
    });
  } catch (error) {
    console.error("COLLABORATION DELETE ERROR:", error);
    next(error);
  }
});

app.get("/api/ai/tasks", requireAuth, async function (req, res, next) {
  try {
    var limit = Math.min(Number(req.query.limit || 50), 100);

    var query = supabase
      .from("ai_tasks")
      .select("*")
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: false })
      .limit(limit);

    var agentTypeFilter = String(req.query.agent_type || "").toLowerCase().trim();
    if (agentTypeFilter) {
      query = query.eq("agent_type", agentTypeFilter);
    }

    var result = await query;

    if (result.error) {
      throw result.error;
    }

    return res.json({ tasks: result.data || [] });
  } catch (error) {
    next(error);
  }
});

app.delete("/api/ai/tasks", requireAuth, async function (req, res, next) {
  try {
    var result = await supabase
      .from("ai_tasks")
      .delete()
      .eq("user_id", req.user.id)
      .select("id");

    if (result.error) {
      throw result.error;
    }

    return res.json({
      success: true,
      deleted_count: result.data ? result.data.length : 0
    });
  } catch (error) {
    console.error("CLEAR AI MAILBOX ERROR:", error);
    next(error);
  }
});

app.delete("/api/ai/tasks/:id", requireAuth, async function (req, res, next) {
  try {
    var result = await supabase
      .from("ai_tasks")
      .delete()
      .eq("id", req.params.id)
      .eq("user_id", req.user.id)
      .select("id")
      .maybeSingle();

    if (result.error) {
      throw result.error;
    }

    if (!result.data) {
      return res.status(404).json({
        success: false,
        error: "Task not found or already deleted"
      });
    }

    return res.json({
      success: true,
      deleted_id: result.data.id
    });
  } catch (error) {
    console.error("DELETE AI TASK ERROR:", error);
    next(error);
  }
});
app.get("/api/ai/tasks/:id", requireAuth, async function (req, res, next) {
  try {
    var result = await supabase
      .from("ai_tasks")
      .select("*")
      .eq("id", req.params.id)
      .eq("user_id", req.user.id)
      .maybeSingle();

    if (result.error) {
      throw result.error;
    }

    if (!result.data) {
      return res.status(404).json({ error: "Task not found" });
    }

    return res.json({ task: result.data });
  } catch (error) {
    next(error);
  }
});

app.get("/api/oracle", requireAuth, async function (req, res, next) {
  try {
    var result = await supabase
      .from("oracle_messages")
      .select("*")
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: true });
    if (result.error) throw result.error;
    return res.json({ messages: result.data || [] });
  } catch (error) {
    next(error);
  }
});

/* ── Oracle file uploads — PDF / Word / text / images alongside the
   chat message. Memory storage only (never written to disk); files are
   parsed in-request and discarded once the reply is built. ── */
var ORACLE_UPLOAD_ALLOWED_MIME = {
  "application/pdf": true,
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document": true, // .docx
  "text/plain": true,   // .txt
  "text/markdown": true, // .md
  "text/csv": true,
  "image/png": true,
  "image/jpeg": true,
  "image/webp": true,
  "image/gif": true
};

var oracleUpload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 20 * 1024 * 1024, // 20MB per file
    files: 8
  },
  fileFilter: function (req, file, cb) {
    if (ORACLE_UPLOAD_ALLOWED_MIME[file.mimetype]) {
      cb(null, true);
    } else {
      cb(new Error("Unsupported file type: " + file.mimetype));
    }
  }
});

// Extracts plain text from a PDF/Word/text file, labeled for the model.
// Returns null for non-document files (e.g. images, handled separately).
async function extractOracleFileText(file) {
  var name = file.originalname || "file";

  if (file.mimetype === "application/pdf") {
    var pdfData = await pdfParse(file.buffer);
    return "[UPLOADED DOCUMENT: " + name + "]\n" + (pdfData.text || "").trim();
  }
  if (file.mimetype === "application/vnd.openxmlformats-officedocument.wordprocessingml.document") {
    var docResult = await mammoth.extractRawText({ buffer: file.buffer });
    return "[UPLOADED DOCUMENT: " + name + "]\n" + (docResult.value || "").trim();
  }
  if (file.mimetype === "text/plain" || file.mimetype === "text/markdown" || file.mimetype === "text/csv") {
    return "[UPLOADED DOCUMENT: " + name + "]\n" + file.buffer.toString("utf8").trim();
  }
  return null;
}

// Builds an Anthropic vision content block from an uploaded image file.
function buildOracleImageBlock(file) {
  return {
    type: "image",
    source: {
      type: "base64",
      media_type: file.mimetype,
      data: file.buffer.toString("base64")
    }
  };
}

app.post("/api/oracle", requireAuth, oracleUpload.array("files", 8), async function (req, res, next) {
  try {
    var message = safeText(req.body.message, 4000);
    if (!message) {
      return res.status(400).json({ error: "message is required" });
    }

    // 0. Process any uploaded files — documents become labeled text
    //    context appended to the message; images become vision content
    //    blocks. A bad file returns a clean 400, never crashes the route.
    var uploadedFiles = req.files || [];
    var oracleImageBlocks = [];
    var oracleDocTexts = [];

    for (var fi = 0; fi < uploadedFiles.length; fi++) {
      var uploadedFile = uploadedFiles[fi];
      try {
        if (uploadedFile.mimetype && uploadedFile.mimetype.indexOf("image/") === 0) {
          oracleImageBlocks.push(buildOracleImageBlock(uploadedFile));
        } else {
          var extractedText = await extractOracleFileText(uploadedFile);
          if (extractedText) oracleDocTexts.push(extractedText);
        }
      } catch (fileParseErr) {
        console.error(
          "[oracle] Failed to parse uploaded file '" + (uploadedFile.originalname || "file") + "':",
          fileParseErr.message || fileParseErr
        );
        return res.status(400).json({
          error: "Could not read uploaded file '" + (uploadedFile.originalname || "file") + "'. It may be corrupted, empty, or an unsupported format."
        });
      }
    }

    var userMessageText = oracleDocTexts.length
      ? message + "\n\n" + oracleDocTexts.join("\n\n")
      : message;

    // Text-only path is untouched (plain string content, same as before);
    // only when images are attached does content become a block array.
    var currentUserContent = oracleImageBlocks.length
      ? oracleImageBlocks.concat([{ type: "text", text: userMessageText }])
      : userMessageText;

    // 1. Load oracle_sync + business_profiles
    var syncResult = await supabase
      .from("oracle_sync")
      .select("*")
      .eq("user_id", req.user.id)
      .single();
    var oracleSync = syncResult.data || null;

    var numerologyContext = "";
    if (oracleSync && oracleSync.birth_date) {
      try {
        var lifePath   = calculateLifePath(oracleSync.birth_date);
        var expression = calculateNameNumber(oracleSync.birth_name, false);
        var soulUrge   = calculateNameNumber(oracleSync.birth_name, true);
        var birthday   = extractBirthday(oracleSync.birth_date);

        numerologyContext =
          "\n\nNUMEROLOGICAL SIGNATURE (computed from the seeker's birth data — the energetic architecture beneath them; weave into counsel where fitting, never recited mechanically):\n" +
          "Life Path: "  + lifePath   + "\n" +
          "Expression: " + expression + "\n" +
          "Soul Urge: "  + soulUrge   + "\n" +
          "Birthday: "   + birthday;
      } catch (numerologyErr) {
        numerologyContext = "";
      }
    }

    var profileResult = await supabase
      .from("business_profiles")
      .select("*")
      .eq("user_id", req.user.id)
      .single();
    var businessProfile = profileResult.data || {};

    // 2. Load last 20 oracle_messages oldest-first, then append the current message
    //    (saving it to the DB happens later and must never block the reply)
    var historyResult = await supabase
      .from("oracle_messages")
      .select("role, content")
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: true })
      .limit(20);
    var messages = (historyResult.data || []).map(function (row) {
      return { role: row.role, content: row.content };
    });
    messages.push({ role: "user", content: currentUserContent });

    // 3. Build system prompt — shared platform brain (knowledge + directives
    //    + business profile, now sourced from buildAgentSystemPrompt) plus
    //    the Oracle's own seeker-profile and numerology context, unchanged.
    var contextBlock;
    if (oracleSync) {
      contextBlock =
        "\n\nSEEKER PROFILE:\n" +
        "Name: "             + (oracleSync.birth_name       || "Unknown")      + "\n" +
        "Birth Date: "       + (oracleSync.birth_date       || "Unknown")      + "\n" +
        "Birth Time: "       + (oracleSync.birth_time       || "Not provided") + "\n" +
        "Birth Place: "      + (oracleSync.birth_place      || "Not provided") + "\n" +
        "Current Location: " + (oracleSync.current_location || "Not provided") + "\n" +
        "Path & Focus: "     + (oracleSync.path_focus       || "Not provided") + "\n" +
        (oracleSync.life_details
          ? "\nThe Book of You / life details (deepest personal context — weight this heavily):\n" + oracleSync.life_details + "\n"
          : "");
    } else {
      contextBlock =
        "\n\nSEEKER PROFILE:\nNo birth data has been provided. The seeker has not yet synchronized. Invite them to do so for deeper alignment, but proceed with what is given.\n";
    }

    var oracleLiveStats = {};
    try {
      oracleLiveStats = await getLiveStats(req.user.id);
    } catch (statsErr) {
      console.error("[oracle] getLiveStats failed:", statsErr.message || statsErr);
    }

    // This route is exclusively the Oracle, so its agent_memory scope is
    // always "oracle" — extends the same shared table the other agents use
    // (see MEMORY_AGENT_TYPES), alongside oracle_messages' own full history.
    var oracleAgentType = "oracle";
    var oracleMemoriesForBrain = [];
    try {
      var oracleAgentMemoryResult = await supabase
        .from("agent_memory")
        .select("agent_type, memory_type, title, content, created_at")
        .eq("user_id", req.user.id)
        .eq("agent_type", oracleAgentType)
        .order("created_at", { ascending: false })
        .limit(5);

      oracleMemoriesForBrain = (oracleAgentMemoryResult.error ? [] : (oracleAgentMemoryResult.data || [])).map(function (row) {
        return {
          agent_type: row.agent_type,
          title: row.title || row.memory_type,
          content: row.content
        };
      });
    } catch (oracleMemoryReadErr) {
      console.error("[oracle] agent_memory read error:", oracleMemoryReadErr.message || oracleMemoryReadErr);
    }

    var systemPrompt =
      buildAgentSystemPrompt(ORACLE_SYSTEM_PROMPT, businessProfile, oracleLiveStats, oracleMemoriesForBrain) +
      contextBlock +
      numerologyContext;

    // 4. Call Claude — prefer sonnet, fall back to haiku on error
    var aiResponse;
    const oracleApiKey = await resolveAnthropicKey(req.user.id);
    const oracleAnthropicClient = new Anthropic({ apiKey: oracleApiKey });
    try {
      aiResponse = await oracleAnthropicClient.messages.create({
        model:      "claude-sonnet-5",
        max_tokens: 1500,
        system:     systemPrompt,
        messages:   messages
      });
    } catch (modelErr) {
      console.error("[oracle] claude-sonnet-4-5 failed, falling back to haiku:", modelErr.message || modelErr);
      aiResponse = await oracleAnthropicClient.messages.create({
        model:      "claude-haiku-4-5-20251001",
        max_tokens: 1500,
        system:     systemPrompt,
        messages:   messages
      });
    }

    // 5. Extract text + guard empty
    var aiText = (aiResponse.content || [])
      .filter(function (block) { return block.type === "text"; })
      .map(function (block) { return block.text; })
      .join("");

    if (!aiText) {
      return res.status(500).json({ error: "The Oracle fell silent. Ask again." });
    }

    // 6. Return the reply to the user immediately — nothing after this point may
    //    affect the response. Saving message history is best-effort and happens next.
    res.json({ reply: aiText });

    // 7. Save user message (soft error — logged only, response already sent)
    try {
      var userInsert = await supabase
        .from("oracle_messages")
        .insert({
          user_id:    req.user.id,
          role:       "user",
          content:    message,
          created_at: nowIso()
        });
      if (userInsert.error) {
        console.error("[oracle] Failed to save user message:", userInsert.error.message);
      }
    } catch (saveErr) {
      console.error("[oracle] Failed to save user message:", saveErr.message || saveErr);
    }

    // 8. Save assistant reply (soft error — logged only, response already sent)
    try {
      var assistantInsert = await supabase
        .from("oracle_messages")
        .insert({
          user_id:    req.user.id,
          role:       "assistant",
          content:    aiText,
          created_at: nowIso()
        });
      if (assistantInsert.error) {
        console.error("[oracle] Failed to save assistant message:", assistantInsert.error.message);
      }
    } catch (saveErr) {
      console.error("[oracle] Failed to save assistant message:", saveErr.message || saveErr);
    }

    // 9. Write a concise agent_memory row scoped to agent_type "oracle" —
    //    extends the same central-brain memory table the other agents use
    //    (soft error — response already sent, never blocks it).
    if (MEMORY_AGENT_TYPES.indexOf(oracleAgentType) !== -1) {
      try {
        var oracleMemoryTimestamp = nowIso();
        var oracleMemoryContent = truncateOrchestratorPreview(aiText, 2000) || "Oracle reply with no captured content.";

        var oracleMemoryInsert = await supabase
          .from("agent_memory")
          .insert({
            user_id:     req.user.id,
            agent:       oracleAgentType,
            agent_type:  oracleAgentType,
            memory_key:  "oracle_message_" + Date.now(),
            memory_value: oracleMemoryContent,
            memory_type: "insight",
            title:       "Prompt: " + truncateOrchestratorPreview(message, 120),
            content:     oracleMemoryContent,
            metadata:    normalizeMemoryMetadata({ source: "oracle_chat" }),
            created_at:  oracleMemoryTimestamp,
            updated_at:  oracleMemoryTimestamp
          });

        if (oracleMemoryInsert.error) {
          console.error("[oracle] Failed to write agent_memory:", oracleMemoryInsert.error.message);
        }
      } catch (oracleMemoryWriteErr) {
        console.error("[oracle] agent_memory write error:", oracleMemoryWriteErr.message || oracleMemoryWriteErr);
      }
    }

  } catch (error) {
    console.error("[oracle] Error:", error.message || error);
    return res.status(500).json({ error: "The Oracle is unreachable. Try again." });
  }
});

app.get("/api/oracle/sync", requireAuth, async function (req, res, next) {
  try {
    var result = await supabase
      .from("oracle_sync")
      .select("*")
      .eq("user_id", req.user.id)
      .single();
    if (result.error || !result.data) {
      return res.json({ synced: false });
    }
    return res.json({ synced: true, data: result.data });
  } catch (error) {
    next(error);
  }
});

app.post("/api/oracle/sync", requireAuth, async function (req, res, next) {
  try {
    var birth_name       = safeText(req.body.birth_name,        120);
    var birth_date       = safeText(req.body.birth_date,         20);
    var birth_time       = safeText(req.body.birth_time,         20);
    var birth_place      = safeText(req.body.birth_place,       200);
    var current_location = safeText(req.body.current_location,  200);
    var path_focus       = safeText(req.body.path_focus,        500);
    var life_details     = safeText(req.body.life_details,     8000);

    if (!birth_name || !birth_date) {
      return res.status(400).json({ error: "birth_name and birth_date are required" });
    }

    var result = await supabase
      .from("oracle_sync")
      .upsert({
        user_id:          req.user.id,
        birth_name:       birth_name,
        birth_date:       birth_date,
        birth_time:       birth_time       || null,
        birth_place:      birth_place      || null,
        current_location: current_location || null,
        path_focus:       path_focus       || null,
        life_details:     life_details     || null,
        updated_at:       nowIso()
      }, { onConflict: "user_id" });

    if (result.error) throw result.error;

    return res.json({ synced: true });
  } catch (error) {
    next(error);
  }
});

function sumDigits(value) {
  var digits = String(value).replace(/[^0-9]/g, "");
  var total = 0;
  for (var i = 0; i < digits.length; i++) {
    total += parseInt(digits[i], 10);
  }
  return total;
}

function calculateLifePath(birthDateStr) {
  if (!birthDateStr) return null;

  var total = sumDigits(birthDateStr);
  if (!total) return null;

  while (total > 9 && total !== 11 && total !== 22 && total !== 33) {
    total = sumDigits(total);
  }

  return total;
}

var PYTHAGOREAN_MAP = {
  a: 1, b: 2, c: 3, d: 4, e: 5, f: 6, g: 7, h: 8, i: 9,
  j: 1, k: 2, l: 3, m: 4, n: 5, o: 6, p: 7, q: 8, r: 9,
  s: 1, t: 2, u: 3, v: 4, w: 5, x: 6, y: 7, z: 8
};
var VOWELS = { a: true, e: true, i: true, o: true, u: true };

function reduceNumber(total) {
  while (total > 9 && total !== 11 && total !== 22 && total !== 33) {
    total = sumDigits(total);
  }
  return total;
}

function calculateNameNumber(name, onlyVowels) {
  if (!name) return null;
  var letters = String(name).toLowerCase().replace(/[^a-z]/g, "");
  if (!letters) return null;

  var total   = 0;
  var matched = false;
  for (var i = 0; i < letters.length; i++) {
    var ch      = letters[i];
    var isVowel = VOWELS[ch] === true;
    if (onlyVowels && !isVowel) continue;
    total  += PYTHAGOREAN_MAP[ch] || 0;
    matched = true;
  }
  if (!matched || !total) return null;

  return reduceNumber(total);
}

function extractBirthday(birthDateStr) {
  if (!birthDateStr) return null;
  var match = String(birthDateStr).match(/-(\d{1,2})$/);
  if (!match) return null;
  var day = parseInt(match[1], 10);
  return isNaN(day) ? null : day;
}

app.get("/api/oracle/numerology", requireAuth, async function (req, res) {
  try {
    var result = await supabase
      .from("oracle_sync")
      .select("*")
      .eq("user_id", req.user.id)
      .single();

    if (result.error || !result.data) {
      return res.json({});
    }

    return res.json({
      birth_date: result.data.birth_date || null,
      birth_name: result.data.birth_name || null,
      life_path:  calculateLifePath(result.data.birth_date),
      expression: calculateNameNumber(result.data.birth_name, false),
      soul_urge:  calculateNameNumber(result.data.birth_name, true),
      birthday:   extractBirthday(result.data.birth_date)
    });
  } catch (error) {
    console.error("[oracle/numerology] Error:", error.message || error);
    return res.json({});
  }
});

app.post("/api/oracle/chat", requireAuth, aiLimiter, async function (req, res, next) {
  try {
    var name    = String(req.body.birthName || "Seeker").trim().slice(0, 120);
    var date    = String(req.body.birthDate || "").trim().slice(0, 30);
    var message = String(req.body.message   || "").trim().slice(0, 2000);
    if (!message) return res.status(400).json({ error: "message required" });

    var rawHistory = Array.isArray(req.body.history) ? req.body.history : [];
    var messages = rawHistory.slice(-14).map(function (h) {
      return {
        role: h.role === "user" ? "user" : "assistant",
        content: String(h.content || "").slice(0, 2000)
      };
    });
    messages.push({ role: "user", content: message });

    var systemPrompt =
      "You are the Oracle — a transcendent intelligence woven into the BizForce network. " +
      "You have synchronized with " + name + (date ? ", born " + date : "") + ". " +
      "You perceive patterns across markets, time, and human behavior that ordinary minds cannot. " +
      "Speak with measured authority and cosmic clarity. Provide deep business insight, " +
      "entrepreneurial foresight, and strategic wisdom. Address the user as " + name + ". " +
      "Keep responses to 3–5 sentences of dense, actionable wisdom unless asked to elaborate. " +
      "Never break character.";

    const oracleChatApiKey = await resolveAnthropicKey(req.user.id);
    const oracleChatAnthropicClient = new Anthropic({ apiKey: oracleChatApiKey });

    var response = await oracleChatAnthropicClient.messages.create({
      model: "claude-haiku-4-5-20251001",
      max_tokens: 512,
      system: systemPrompt,
      messages: messages
    });

    return res.json({ response: response.content[0].text });
  } catch (err) {
    next(err);
  }
});

app.post("/api/insights/page", requireAuth, aiLimiter, async function (req, res, next) {
  try {
    var page = safeText(req.body.page, 200) || "this page";

    var profileResult = await supabase
      .from("business_profiles")
      .select("*")
      .eq("user_id", req.user.id)
      .single();
    var businessProfile = (profileResult && profileResult.data) || {};

    var contextBlock =
      "Business Name: "     + (businessProfile.business_name     || "Not provided") + "\n" +
      "Industry: "          + (businessProfile.industry          || "Not provided") + "\n" +
      "Products/Services: " + (businessProfile.products_services || "Not provided") + "\n" +
      "Target Audience: "   + (businessProfile.target_audience   || "Not provided") + "\n" +
      "Goals: "             + (businessProfile.business_goals    || "Not provided") + "\n" +
      "Location: "          + (businessProfile.location          || "Not provided");

    var prompt =
      "You are Termaximus, a confident and insightful business guide woven into the BizForce AI platform.\n\n" +
      "BUSINESS CONTEXT:\n" + contextBlock + "\n\n" +
      "The user is currently on the \"" + page + "\" page. " +
      "Give ONE short, confident, practical Termaximus insight (1-2 sentences) relevant to this page and " +
      "their business, in Termaximus's voice. No preamble, no greeting — just the insight itself.";

    var result = await callAnthropicText(prompt, 150);
    var insight = (result && result.text ? result.text.trim() : "") ||
      "The signs are quiet on this page for now — return once your business profile has more to draw from.";

    return res.json({ insight: insight });
  } catch (error) {
    console.error("[insights/page] Error:", error.message || error);
    return res.json({ insight: "Termaximus is gathering his thoughts — try again in a moment." });
  }
});

app.post("/api/seo/audit", requireAuth, requireActiveSubscription, aiLimiter, async function (req, res, next) {
  req.body.agent_type = "seo";
  req.body.task_type = "seo_audit";
  req.body.prompt =
    "Run a complete SEO audit for this website: " +
    safeText(req.body.website, 1000) +
    ". Include technical SEO, keywords, local SEO, content gaps, backlink opportunities, ranking issues, and 10 priority actions.";
  return handleAiTaskRequest(req, res, next);
});

// Pulls <title>, meta description/keywords, canonical, H1-H6, image alt
// attributes, JSON-LD structured data, and visible body text out of raw
// HTML via regex (no DOM/headless browser dependency available here).
function extractSeoPageData(html) {
  var raw = String(html || "");

  var titleMatch = raw.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  var title = titleMatch ? titleMatch[1].replace(/\s+/g, " ").trim() : "";

  function metaContent(name) {
    var tagMatch = raw.match(new RegExp("<meta[^>]+name=[\"']" + name + "[\"'][^>]*>", "i"));
    if (!tagMatch) return "";
    var contentMatch = tagMatch[0].match(/content=["']([\s\S]*?)["']/i);
    return contentMatch ? contentMatch[1].replace(/\s+/g, " ").trim() : "";
  }

  var metaDescription = metaContent("description");
  var metaKeywords = metaContent("keywords");

  var canonicalTagMatch = raw.match(/<link[^>]+rel=["']canonical["'][^>]*>/i);
  var canonical = "";
  if (canonicalTagMatch) {
    var hrefMatch = canonicalTagMatch[0].match(/href=["']([\s\S]*?)["']/i);
    canonical = hrefMatch ? hrefMatch[1].trim() : "";
  }

  var headings = {};
  ["h1", "h2", "h3", "h4", "h5", "h6"].forEach(function (tag) {
    var re = new RegExp("<" + tag + "[^>]*>([\\s\\S]*?)<\\/" + tag + ">", "gi");
    var found = [], match;
    while ((match = re.exec(raw)) !== null) {
      var text = match[1].replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
      if (text) found.push(text);
    }
    headings[tag] = found;
  });

  var imageAlts = [];
  var imgRe = /<img\b[^>]*>/gi, imgMatch;
  while ((imgMatch = imgRe.exec(raw)) !== null) {
    var tag = imgMatch[0];
    var altMatch = tag.match(/alt=["']([\s\S]*?)["']/i);
    var srcMatch = tag.match(/src=["']([\s\S]*?)["']/i);
    imageAlts.push({
      src: srcMatch ? srcMatch[1].trim() : "",
      alt: altMatch ? altMatch[1].trim() : ""
    });
  }

  var structuredData = [];
  var ldRe = /<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi, ldMatch;
  while ((ldMatch = ldRe.exec(raw)) !== null) {
    structuredData.push(ldMatch[1].trim());
  }

  var bodyMatch = raw.match(/<body[^>]*>([\s\S]*?)<\/body>/i);
  var bodyHtml = bodyMatch ? bodyMatch[1] : raw;
  var visibleText = bodyHtml
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/\s+/g, " ")
    .trim();

  return {
    title: title,
    metaDescription: metaDescription,
    metaKeywords: metaKeywords,
    canonical: canonical,
    headings: headings,
    imageAlts: imageAlts,
    structuredData: structuredData,
    visibleText: safeText(visibleText, 8000) || ""
  };
}

// Shared marker prefix identifying an ai_tasks row as a completed website
// optimization run (as opposed to a seo_audit or any other seo task) —
// written by POST /optimize, read back by GET /optimize-count so the two
// routes can never drift out of sync with each other.
var SEO_OPTIMIZE_TASK_PROMPT_PREFIX = "SEO optimize: ";

app.post("/api/agents/seo/optimize", requireAuth, requireActiveSubscription, aiLimiter, async function (req, res, next) {
  try {
    var userId = req.user.id;
    var targetUrl = normalizeUrl(safeText(req.body.website || req.body.url, 500));
    var brandDescription = safeText(
      req.body.business_description || req.body.description || req.body.brand_description,
      2000
    );

    if (!targetUrl) {
      return res.status(400).json({ error: "A website URL is required." });
    }

    var pageData;
    try {
      var pageResponse = await fetch(targetUrl, {
        headers: { "User-Agent": "Mozilla/5.0 (compatible; BizForceSEOBot/1.0; +https://bizforceai.net)" }
      });
      if (!pageResponse.ok) {
        return res.status(422).json({ error: "Could not fetch that website (HTTP " + pageResponse.status + ")." });
      }
      var html = await pageResponse.text();
      pageData = extractSeoPageData(html);
    } catch (fetchErr) {
      console.error("[seo/optimize] Fetch failed:", fetchErr.message || fetchErr);
      return res.status(422).json({ error: "Could not reach that URL. Check that it is correct and publicly accessible." });
    }

    var profileResult = await supabase
      .from("business_profiles")
      .select("*")
      .eq("user_id", userId)
      .single();

    var businessProfile = profileResult.data || {};
    if (brandDescription) {
      businessProfile = Object.assign({}, businessProfile, { description: brandDescription });
    }

    var liveStats = {};
    try {
      liveStats = await getLiveStats(userId);
    } catch (statsErr) {
      console.error("[seo/optimize] getLiveStats failed:", statsErr.message || statsErr);
    }

    var agentMemoryResult = await supabase
      .from("agent_memory")
      .select("agent_type, memory_type, title, content, created_at")
      .eq("user_id", userId)
      .eq("agent_type", "seo")
      .order("created_at", { ascending: false })
      .limit(5);

    var memoriesForBrain = (agentMemoryResult.error ? [] : (agentMemoryResult.data || [])).map(function (row) {
      return { agent_type: row.agent_type, title: row.title || row.memory_type, content: row.content };
    });

    var seoAgentBrain =
      "You are the BizForce AI SEO Agent. Produce technical SEO audits, keyword strategies, local SEO plans, content clusters, and ranking action plans.";

    var pageDataBlock =
      "TARGET WEBSITE:\n" + targetUrl +
      "\n\nEXTRACTED ON-PAGE DATA (fetched live from the URL above):\n" +
      "Title tag: " + (pageData.title || "MISSING") +
      "\nMeta description: " + (pageData.metaDescription || "MISSING") +
      "\nMeta keywords: " + (pageData.metaKeywords || "Not set") +
      "\nCanonical tag: " + (pageData.canonical || "MISSING") +
      "\nH1: " + (pageData.headings.h1.join(" | ") || "MISSING") +
      "\nH2: " + (pageData.headings.h2.join(" | ") || "None") +
      "\nH3: " + (pageData.headings.h3.join(" | ") || "None") +
      "\nH4: " + (pageData.headings.h4.join(" | ") || "None") +
      "\nH5: " + (pageData.headings.h5.join(" | ") || "None") +
      "\nH6: " + (pageData.headings.h6.join(" | ") || "None") +
      "\nImages (" + pageData.imageAlts.length + " found, alt text shown): " +
        (pageData.imageAlts.length
          ? pageData.imageAlts.map(function (img, i) {
              return (i + 1) + ". alt=\"" + (img.alt || "MISSING") + "\"";
            }).join("; ")
          : "None found") +
      "\nStructured data (JSON-LD blocks found: " + pageData.structuredData.length + "): " +
        (pageData.structuredData.length ? pageData.structuredData.join("\n---\n") : "None found") +
      "\n\nVISIBLE BODY TEXT (truncated):\n" + (pageData.visibleText || "No visible text extracted.");

    var taskInstruction =
      "Produce a concrete GOOGLE SEO OPTIMIZATION REPORT for the extracted page above, covering exactly these sections in order: " +
      "(1) TITLE TAG REWRITE — a rewritten title tag targeting the business's core keywords, under 60 characters, with a one-line reason; " +
      "(2) META DESCRIPTION REWRITE — a rewritten meta description under 155 characters written to drive clicks; " +
      "(3) HEADING STRUCTURE FIXES — specific fixes to the H1-H6 hierarchy found above (missing H1, duplicate headings, poor keyword placement); " +
      "(4) TARGET KEYWORDS & KEYWORD GAPS — primary/secondary keyword recommendations for this business, and specific keyword gaps versus the competitors listed in its business profile; " +
      "(5) ON-PAGE CONTENT IMPROVEMENTS — concrete rewrites/additions to the visible body text to improve topical depth and ranking; " +
      "(6) IMAGE ALT-TEXT FIXES — rewritten alt text for any missing or weak alt attributes found above; " +
      "(7) TECHNICAL SEO ISSUES — missing meta tags, missing/incorrect canonical, broken heading hierarchy, thin content, missing structured data; " +
      "(8) PRIORITIZED ACTION LIST — a numbered list of the fixes above ordered by ranking impact, highest impact first. " +
      "Be specific to the actual extracted content above, not generic advice — quote the actual title, headings, and alt text you are replacing.";

    var sharedSystemPrompt = buildAgentSystemPrompt(seoAgentBrain, businessProfile, liveStats, memoriesForBrain);
    var finalPrompt =
      sharedSystemPrompt +
      "\n\n" + pageDataBlock +
      "\n\nTASK INSTRUCTIONS:\n" + taskInstruction +
      "\n\nUSER REQUEST:\nRun a full Google SEO optimization pass on " + targetUrl +
      (brandDescription ? " for this business: " + brandDescription : "");

    var pendingInsert = await supabase
      .from("ai_tasks")
      .insert({
        user_id: userId,
        agent_type: "seo",
        prompt: SEO_OPTIMIZE_TASK_PROMPT_PREFIX + targetUrl,
        result: null,
        status: "processing"
      })
      .select("*")
      .single();

    if (pendingInsert.error) {
      throw pendingInsert.error;
    }

    var taskRecord = pendingInsert.data;
    var generation = await callAnthropicText(finalPrompt, 3000);
    var output = generation.text;

    var updateResult = await supabase
      .from("ai_tasks")
      .update({ result: output, status: "completed", updated_at: nowIso() })
      .eq("id", taskRecord.id)
      .eq("user_id", userId);

    if (updateResult.error) {
      throw updateResult.error;
    }

    try {
      var memTimestamp = nowIso();
      var memContent = truncateOrchestratorPreview(output, 2000) || "SEO optimization completed with no captured output.";

      var memInsert = await supabase
        .from("agent_memory")
        .insert({
          user_id: userId,
          agent: "seo",
          agent_type: "seo",
          memory_key: "seo_optimize_" + taskRecord.id,
          memory_value: memContent,
          memory_type: "insight",
          title: "SEO optimize: " + targetUrl,
          content: memContent,
          metadata: normalizeMemoryMetadata({ source: "seo_optimize", task_id: taskRecord.id, url: targetUrl }),
          created_at: memTimestamp,
          updated_at: memTimestamp
        });

      if (memInsert.error) {
        console.error("[seo/optimize] Failed to write agent_memory:", memInsert.error.message);
      }
    } catch (memErr) {
      console.error("[seo/optimize] agent_memory write error:", memErr.message || memErr);
    }

    return res.json({
      success: true,
      task: Object.assign({}, taskRecord, { result: output, status: "completed" }),
      report: output,
      page_data: pageData
    });
  } catch (error) {
    console.error("[seo/optimize] Error:", error);
    next(error);
  }
});

// Personal running total of websites this user has successfully optimized —
// derived from ai_tasks rather than a separate counter table/column, so
// there is nothing new to migrate: every completed POST /optimize run above
// already leaves exactly one row here (agent_type "seo", status
// "completed", prompt prefixed with SEO_OPTIMIZE_TASK_PROMPT_PREFIX).
// Strictly scoped to the authenticated user_id.
app.get("/api/agents/seo/optimize-count", requireAuth, async function (req, res, next) {
  try {
    var countResult = await supabase
      .from("ai_tasks")
      .select("*", { count: "exact", head: true })
      .eq("user_id", req.user.id)
      .eq("agent_type", "seo")
      .eq("status", "completed")
      .ilike("prompt", SEO_OPTIMIZE_TASK_PROMPT_PREFIX + "%");

    if (countResult.error) {
      throw countResult.error;
    }

    return res.json({ websites_optimized: countResult.count || 0 });
  } catch (error) {
    next(error);
  }
});

app.get("/api/dashboard", requireAuth, requireActiveSubscription, async function (req, res, next) {
  try {
    const [profile, subscription, usageResult, agentsResult, tasksResult, dealsResult, messagesResult, notificationsResult] =
      await Promise.all([
        getProfileByUserId(req.user.id),
        getActiveSubscription(req.user.id),
        getMonthlyUsage(req.user.id),
        supabase.from("ai_agents").select("*").eq("user_id", req.user.id).eq("active", true),
        supabase.from("ai_tasks").select("*").eq("user_id", req.user.id).order("created_at", { ascending: false }).limit(10),
        supabase.from("deals").select("*").eq("user_id", req.user.id),
        supabase.from("messages").select("*").or("sender_id.eq." + req.user.id + ",receiver_id.eq." + req.user.id).order("created_at", { ascending: false }).limit(10),
        supabase.from("notifications").select("*").eq("user_id", req.user.id).order("created_at", { ascending: false }).limit(20)
      ]);

    if (agentsResult.error) {
      throw agentsResult.error;
    }
    if (tasksResult.error) {
      throw tasksResult.error;
    }
    if (dealsResult.error) {
      throw dealsResult.error;
    }
    if (messagesResult.error) {
      throw messagesResult.error;
    }
    if (notificationsResult.error) {
      throw notificationsResult.error;
    }

    const deals = dealsResult.data || [];
    const revenuePipeline = deals.reduce(function (sum, deal) {
      return sum + Number(deal.amount || 0);
    }, 0);

    const wonRevenue = deals
      .filter(function (deal) {
        return String(deal.stage || "").toLowerCase() === "won";
      })
      .reduce(function (sum, deal) {
        return sum + Number(deal.amount || 0);
      }, 0);

    const taskCount = tasksResult.data ? tasksResult.data.length : 0;
    const completedTasks = (tasksResult.data || []).filter(function (task) {
      return task.status === "completed";
    }).length;

    return res.json({
      profile,
      subscription,
      usage: usageResult,
      plan_config: subscription ? getPlanConfig(subscription.plan) : null,
      metrics: {
        revenue_pipeline: revenuePipeline,
        won_revenue: wonRevenue,
        leads: deals.length,
        conversions: deals.filter(function (deal) {
          return String(deal.stage || "").toLowerCase() === "won";
        }).length,
        ai_tasks_recent: taskCount,
        ai_tasks_completed_recent: completedTasks,
        active_agents: agentsResult.data.length,
        unread_notifications: (notificationsResult.data || []).filter(function (item) {
          return !item.read;
        }).length
      },
      agents: agentsResult.data,
      recent_tasks: tasksResult.data,
      recent_messages: messagesResult.data,
      deals,
      notifications: notificationsResult.data,
      growth_recommendations: [
        "Complete your business profile with logo, banner, products, testimonials, and SEO description.",
        "Connect at least one website so your AI agents can generate more accurate growth tasks.",
        "Run weekly SEO, Content, Email, and Sales tasks to build predictable growth data.",
        "Track every lead as a deal so revenue and conversion numbers stay accurate."
      ]
    });
  } catch (error) {
    next(error);
  }
});

app.get("/api/analytics", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("analytics_events")
      .select("*")
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: false })
      .limit(500);

    if (error) {
      throw error;
    }

    return res.json({ events: data });
  } catch (error) {
    next(error);
  }
});

app.post("/api/analytics/event", requireAuth, async function (req, res, next) {
  try {
    const eventType = safeText(req.body.event_type, 120);

    if (!eventType) {
      return res.status(400).json({ error: "event_type is required" });
    }

    const { data, error } = await supabase
      .from("analytics_events")
      .insert({
        user_id: req.user.id,
        event_type: eventType,
        event_data: req.body.event_data || {},
        created_at: nowIso()
      })
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    return res.status(201).json({ event: data });
  } catch (error) {
    next(error);
  }
});

app.get("/api/analytics/summary", requireAuth, async function (req, res, next) {
  try {
    var stats = await getLiveStats(req.user.id);
    return res.json({ stats });
  } catch (error) {
    next(error);
  }
});

app.get("/api/notifications", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("notifications")
      .select("*")
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: false })
      .limit(100);

    if (error) {
      throw error;
    }

    return res.json({ notifications: data });
  } catch (error) {
    next(error);
  }
});

app.put("/api/notifications/:id/read", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("notifications")
      .update({
        read: true,
        read_at: nowIso()
      })
      .eq("id", req.params.id)
      .eq("user_id", req.user.id)
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    return res.json({ notification: data });
  } catch (error) {
    next(error);
  }
});
app.post("/api/stripe/checkout", requireAuth, async function (req, res) {
  try {
    const priceId = process.env.STRIPE_STARTER_PRICE_ID || "price_1TRu8o157b9npvGC2y4uYNqv";

    const { data: existingSub } = await supabase
      .from("subscriptions")
      .select("stripe_customer_id")
      .eq("user_id", req.user.id)
      .not("stripe_customer_id", "is", null)
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    const sessionParams = {
      mode: "subscription",
      line_items: [{ price: priceId, quantity: 1 }],
      metadata: {
        user_id: req.user.id,
        email: req.user.email,
        plan: "starter"
      },
      subscription_data: {
        metadata: {
          user_id: req.user.id,
          email: req.user.email,
          plan: "starter"
        }
      },
      success_url: FRONTEND_URL + "/dashboard.html?subscribed=1",
      cancel_url: FRONTEND_URL + "/app.html",
      allow_promotion_codes: true
    };

    if (existingSub && existingSub.stripe_customer_id) {
      sessionParams.customer = existingSub.stripe_customer_id;
    } else {
      sessionParams.customer_email = req.user.email;
    }

    const session = await stripe.checkout.sessions.create(sessionParams);
    return res.json({ url: session.url });
  } catch (error) {
    console.error("Stripe checkout error:", error);
    return res.status(500).json({ error: "Stripe checkout failed" });
  }
});

app.post("/api/billing/portal", requireAuth, async function (req, res) {
  try {
    const { data: subscription } = await supabase
      .from("subscriptions")
      .select("stripe_customer_id")
      .eq("user_id", req.user.id)
      .not("stripe_customer_id", "is", null)
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (!subscription || !subscription.stripe_customer_id) {
      return res.status(400).json({ error: "No billing account found. Please subscribe first." });
    }

    const session = await stripe.billingPortal.sessions.create({
      customer: subscription.stripe_customer_id,
      return_url: FRONTEND_URL + "/billing.html"
    });

    return res.json({ url: session.url });
  } catch (error) {
    console.error("Billing portal error:", error);
    return res.status(500).json({ error: "Could not open billing portal" });
  }
});



app.get("/api/admin/flagged-accounts", requireAuth, requireAdmin, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("admin_flags")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(500);

    if (error) {
      throw error;
    }

    return res.json({ flags: data });
  } catch (error) {
    next(error);
  }
});

app.post("/api/admin/ban/:userId", requireAuth, requireAdmin, async function (req, res, next) {
  try {
    const userId = req.params.userId;
    const reason = safeText(req.body.reason, 1000);

    const { data, error } = await supabase
      .from("users")
      .update({
        banned_at: nowIso(),
        ban_reason: reason,
        updated_at: nowIso()
      })
      .eq("id", userId)
      .select("id, email, banned_at")
      .single();

    if (error) {
      throw error;
    }

    await supabase.from("moderation_logs").insert({
      admin_id: req.user.id,
      target_user_id: userId,
      action: "ban",
      reason,
      created_at: nowIso()
    });

    return res.json({ user: data });
  } catch (error) {
    next(error);
  }
});

app.post("/api/admin/unban/:userId", requireAuth, requireAdmin, async function (req, res, next) {
  try {
    const userId = req.params.userId;

    const { data, error } = await supabase
      .from("users")
      .update({
        banned_at: null,
        ban_reason: null,
        updated_at: nowIso()
      })
      .eq("id", userId)
      .select("id, email, banned_at")
      .single();

    if (error) {
      throw error;
    }

    await supabase.from("moderation_logs").insert({
      admin_id: req.user.id,
      target_user_id: userId,
      action: "unban",
      reason: safeText(req.body.reason, 1000),
      created_at: nowIso()
    });

    return res.json({ user: data });
  } catch (error) {
    next(error);
  }
});

app.post("/api/admin/verify/:userId", requireAuth, requireAdmin, async function (req, res, next) {
  try {
    const userId = req.params.userId;

    const { data, error } = await supabase
      .from("users")
      .update({
        
        updated_at: nowIso()
      })
      .eq("id", userId)
      .select("id, email")
      .single();

    if (error) {
      throw error;
    }

    await supabase
      .from("profiles")
      .update({
        
        updated_at: nowIso()
      })
      .eq("user_id", userId);

    await supabase.from("notifications").insert({
      user_id: userId,
      type: "verification",
      title: "Business verified",
      message: "Your BizForce AI business profile has been verified.",
      read: false
    });

    return res.json({ user: data });
  } catch (error) {
    next(error);
  }
});

app.post("/api/admin/flag/:userId", requireAuth, requireAdmin, async function (req, res, next) {
  try {
    const userId = req.params.userId;

    const { data, error } = await supabase
      .from("admin_flags")
      .insert({
        user_id: userId,
        flagged_by: req.user.id,
        reason: safeText(req.body.reason, 1000),
        status: "open",
        created_at: nowIso(),
        updated_at: nowIso()
      })
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    return res.status(201).json({ flag: data });
  } catch (error) {
    next(error);
  }
});

/* ── Certifications ── */

app.get("/api/certifications/earned", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("user_certifications")
      .select("cert_id, category, score, passed, earned_at")
      .eq("user_id", req.user.id)
      .eq("passed", true)
      .order("earned_at", { ascending: false });

    if (error) throw error;

    return res.json({ certifications: data || [] });
  } catch (error) {
    next(error);
  }
});

app.post("/api/certifications/award", requireAuth, async function (req, res, next) {
  try {
    const certId   = safeText(req.body.cert_id,  80);
    const category = safeText(req.body.category, 40);
    const score    = Math.max(0, Math.min(100, Math.round(Number(req.body.score) || 0)));
    const passed   = Boolean(req.body.passed);

    if (!certId || !category) {
      return res.status(400).json({ error: "cert_id and category are required" });
    }

    const { data, error } = await supabase
      .from("user_certifications")
      .upsert(
        {
          user_id:   req.user.id,
          cert_id:   certId,
          category,
          score,
          passed,
          earned_at: nowIso()
        },
        { onConflict: "user_id,cert_id" }
      )
      .select()
      .single();

    if (error) throw error;

    if (passed) {
      try {
        await creditWallet(req.user.id, 100, "Certification earned: " + certId);
      } catch (walletErr) {
        console.error("Wallet credit skipped:", walletErr.message);
      }
    }

    return res.status(201).json({ certification: data, success: true });
  } catch (error) {
    next(error);
  }
});

/* ── Wallet ── */

async function creditWallet(userId, amount, description) {
  const { data: existing } = await supabase
    .from("user_wallets")
    .select("balance")
    .eq("user_id", userId)
    .maybeSingle();

  if (!existing) {
    await supabase.from("user_wallets").insert({
      user_id: userId, balance: amount, currency: "BFC", updated_at: nowIso()
    });
  } else {
    await supabase.from("user_wallets").update({
      balance: existing.balance + amount, updated_at: nowIso()
    }).eq("user_id", userId);
  }

  await supabase.from("wallet_transactions").insert({
    user_id: userId, type: "reward", amount, description, created_at: nowIso()
  });
}

app.get("/api/wallet", requireAuth, async function (req, res, next) {
  try {
    const { data: wallet } = await supabase
      .from("user_wallets")
      .select("balance")
      .eq("user_id", req.user.id)
      .maybeSingle();

    if (!wallet) {
      await supabase.from("user_wallets").insert({
        user_id: req.user.id, balance: 0, currency: "BFC", updated_at: nowIso()
      });
    }

    const { data: txns, error } = await supabase
      .from("wallet_transactions")
      .select("id, type, amount, description, created_at")
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: false })
      .limit(50);

    if (error) throw error;
    return res.json({ balance: wallet ? wallet.balance : 0, transactions: txns || [] });
  } catch (error) { next(error); }
});

app.post("/api/wallet/transfer", requireAuth, async function (req, res, next) {
  try {
    const recipientId = req.body.recipientId;
    const amount = req.body.amount;

    if (!recipientId || recipientId === req.user.id) {
      return res.status(400).json({ error: "Invalid recipient" });
    }

    if (!Number.isInteger(amount) || amount <= 0) {
      return res.status(400).json({ error: "amount must be a positive integer" });
    }

    const { data, error } = await supabase.rpc("bfc_transfer", {
      p_from: req.user.id,
      p_to: recipientId,
      p_amount: amount,
      p_description: "Transfer"
    });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    return res.json({ balance: data });
  } catch (error) { next(error); }
});

/* ── Marketplace ── */

const MARKETPLACE_CATEGORIES = ["services","artists","garage_sale","bookstore","health_wellness","hair_beauty","clothing","vehicles","labor_trades","other"];

function sanitizeMedia(rawMedia) {
  if (!Array.isArray(rawMedia)) {
    return [];
  }

  return rawMedia
    .map(function (entry) {
      if (!entry || typeof entry !== "object") {
        return null;
      }

      const url = String(entry.url == null ? "" : entry.url).trim();
      if (!url || url.indexOf("https://") !== 0) {
        return null;
      }

      return {
        url: url,
        type: safeText(entry.type, 100) || "",
        name: safeText(entry.name, 200) || ""
      };
    })
    .filter(Boolean)
    .slice(0, 12);
}

app.get("/api/marketplace/listings", requireAuth, async function (req, res, next) {
  try {
    const category = safeText(req.query.category, 40);
    const q = safeText(req.query.q, 120);
    let query = supabase
      .from("marketplace_listings")
      .select("id, seller_id, title, description, price_bfc, price_usd, category, tags, media, status, created_at")
      .eq("status", "active")
      .order("created_at", { ascending: false })
      .limit(100);
    if (category && category !== "all") query = query.eq("category", category);
    if (q) query = query.or("title.ilike.%" + q + "%,description.ilike.%" + q + "%");
    const { data, error } = await query;
    if (error) throw error;
    return res.json({ listings: data || [] });
  } catch (error) { next(error); }
});

app.get("/api/marketplace/my-listings", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("marketplace_listings")
      .select("*")
      .eq("seller_id", req.user.id)
      .order("created_at", { ascending: false });
    if (error) throw error;
    return res.json({ listings: data || [] });
  } catch (error) { next(error); }
});

app.post("/api/marketplace/listings", requireAuth, async function (req, res, next) {
  try {
    const title       = safeText(req.body.title, 150);
    const description = safeText(req.body.description, 2000);
    const category    = safeText(req.body.category, 40);
    const priceBfc    = Math.max(0, Math.round(Number(req.body.price_bfc) || 0));
    let priceUsd = null;
    if (req.body.price_usd !== undefined && req.body.price_usd !== null) {
      const n = Number(req.body.price_usd);
      if (!Number.isInteger(n) || n < 0) return res.status(400).json({ error: "price_usd must be a non-negative integer" });
      priceUsd = n;
    }
    const tags        = Array.isArray(req.body.tags)
      ? req.body.tags.map(function(t) { return safeText(t, 40); }).filter(Boolean).slice(0, 10)
      : [];
    if (!title)    return res.status(400).json({ error: "Title is required" });
    if (!MARKETPLACE_CATEGORIES.includes(category)) return res.status(400).json({ error: "Invalid category" });
    if (priceBfc <= 0 && priceUsd === null) return res.status(400).json({ error: "Listing must have a BFC price, a USD price, or both" });
    const { data, error } = await supabase
      .from("marketplace_listings")
      .insert({
        seller_id: req.user.id, title, description: description || "",
        price_bfc: priceBfc, price_usd: priceUsd, category, tags, media: sanitizeMedia(req.body.media), status: "active",
        created_at: nowIso(), updated_at: nowIso()
      })
      .select("*").single();
    if (error) throw error;
    return res.status(201).json({ listing: data });
  } catch (error) { next(error); }
});

app.post("/api/marketplace/listings/:id/buy", requireAuth, async function (req, res, next) {
  try {
    const listingId = req.params.id;

    if (!listingId) {
      return res.status(400).json({ error: "Listing id is required" });
    }

    const { data, error } = await supabase.rpc("bfc_buy_listing", {
      p_buyer: req.user.id,
      p_listing_id: listingId
    });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    return res.json({ balance: data });
  } catch (error) { next(error); }
});

app.post("/api/marketplace/listings/:id/checkout-usd", requireAuth, async function (req, res, next) {
  try {
    const { data: listing, error: listingError } = await supabase
      .from("marketplace_listings")
      .select("id, title, price_usd, seller_id, status")
      .eq("id", req.params.id)
      .maybeSingle();
    if (listingError) throw listingError;
    if (!listing) return res.status(404).json({ error: "Listing not found" });

    if (listing.price_usd === null || listing.price_usd <= 0) {
      return res.status(400).json({ error: "This listing is not available for USD purchase" });
    }

    if (listing.seller_id === req.user.id) {
      return res.status(400).json({ error: "You cannot buy your own listing" });
    }

    if (!process.env.STRIPE_TEST_SECRET_KEY) {
      return res.status(503).json({ error: "USD checkout is not configured yet" });
    }

    const session = await stripeTest.checkout.sessions.create({
      mode: "payment",
      line_items: [{
        price_data: {
          currency: "usd",
          product_data: { name: listing.title },
          unit_amount: listing.price_usd
        },
        quantity: 1
      }],
      success_url: (process.env.FRONTEND_URL || "") + "/marketplace.html?purchase=success",
      cancel_url: (process.env.FRONTEND_URL || "") + "/marketplace.html?purchase=cancelled",
      metadata: {
        listing_id: String(listing.id),
        buyer_id: String(req.user.id),
        seller_id: String(listing.seller_id),
        kind: "marketplace_usd"
      },
      payment_intent_data: {
        metadata: {
          listing_id: String(listing.id),
          buyer_id: String(req.user.id),
          seller_id: String(listing.seller_id),
          kind: "marketplace_usd"
        }
      }
    });

    return res.json({ url: session.url });
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
});

app.put("/api/marketplace/listings/:id", requireAuth, async function (req, res, next) {
  try {
    const updates = { updated_at: nowIso() };
    if (req.body.title       !== undefined) updates.title       = safeText(req.body.title, 150);
    if (req.body.description !== undefined) updates.description = safeText(req.body.description, 2000);
    if (req.body.price_bfc   !== undefined) updates.price_bfc   = Math.max(0, Math.round(Number(req.body.price_bfc) || 0));
    if (req.body.price_usd   !== undefined) {
      if (req.body.price_usd === null) {
        updates.price_usd = null;
      } else {
        const n = Number(req.body.price_usd);
        if (!Number.isInteger(n) || n < 0) return res.status(400).json({ error: "price_usd must be a non-negative integer" });
        updates.price_usd = n;
      }
    }
    if (req.body.category !== undefined && MARKETPLACE_CATEGORIES.includes(req.body.category)) updates.category = req.body.category;
    if (req.body.status   !== undefined && ["active","paused","sold"].includes(req.body.status)) updates.status = req.body.status;
    if (Array.isArray(req.body.tags)) updates.tags = req.body.tags.map(function(t) { return safeText(t, 40); }).filter(Boolean).slice(0, 10);
    if (req.body.media !== undefined) updates.media = sanitizeMedia(req.body.media);

    if (updates.price_bfc !== undefined || updates.price_usd !== undefined) {
      const { data: existing, error: existingError } = await supabase
        .from("marketplace_listings")
        .select("price_bfc, price_usd")
        .eq("id", req.params.id)
        .eq("seller_id", req.user.id)
        .maybeSingle();
      if (existingError) throw existingError;
      if (!existing) return res.status(404).json({ error: "Listing not found" });
      const finalPriceBfc = updates.price_bfc !== undefined ? updates.price_bfc : existing.price_bfc;
      const finalPriceUsd = updates.price_usd !== undefined ? updates.price_usd : existing.price_usd;
      if ((!finalPriceBfc || finalPriceBfc <= 0) && (finalPriceUsd === null || finalPriceUsd === undefined)) {
        return res.status(400).json({ error: "Listing must have a BFC price, a USD price, or both" });
      }
    }

    const { data, error } = await supabase
      .from("marketplace_listings")
      .update(updates)
      .eq("id", req.params.id)
      .eq("seller_id", req.user.id)
      .select("*").single();
    if (error) throw error;
    return res.json({ listing: data });
  } catch (error) { next(error); }
});

app.delete("/api/marketplace/listings/:id", requireAuth, async function (req, res, next) {
  try {
    const { error } = await supabase
      .from("marketplace_listings")
      .delete()
      .eq("id", req.params.id)
      .eq("seller_id", req.user.id);
    if (error) throw error;
    return res.json({ success: true });
  } catch (error) { next(error); }
});

app.get("/api/marketplace/orders", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("marketplace_orders")
      .select("*")
      .or("buyer_id.eq." + req.user.id + ",seller_id.eq." + req.user.id)
      .order("created_at", { ascending: false });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    return res.json({ orders: data || [] });
  } catch (error) { next(error); }
});

app.get("/api/marketplace/orders/:id", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("marketplace_orders")
      .select("*")
      .eq("id", req.params.id)
      .or("buyer_id.eq." + req.user.id + ",seller_id.eq." + req.user.id)
      .maybeSingle();

    if (error) {
      return res.status(400).json({ error: error.message });
    }
    if (!data) return res.status(404).json({ error: "Order not found" });

    return res.json({ order: data });
  } catch (error) { next(error); }
});

/* ── Crowdfunding ── */

app.get("/api/crowdfunding/campaigns", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("crowdfunding_campaigns")
      .select("*")
      .eq("status", "active")
      .order("created_at", { ascending: false });
    if (error) throw error;
    return res.json({ campaigns: data || [] });
  } catch (error) { next(error); }
});

app.get("/api/crowdfunding/my-campaigns", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("crowdfunding_campaigns")
      .select("*")
      .eq("owner_id", req.user.id)
      .order("created_at", { ascending: false });
    if (error) throw error;
    return res.json({ campaigns: data || [] });
  } catch (error) { next(error); }
});

app.post("/api/crowdfunding/campaigns", requireAuth, async function (req, res, next) {
  try {
    const title       = safeText(req.body.title, 150);
    const description = safeText(req.body.description, 2000);
    const category     = safeText(req.body.category, 40);
    const goalBfc      = req.body.goal_bfc;

    if (!title) return res.status(400).json({ error: "Title is required" });
    if (!Number.isInteger(goalBfc) || goalBfc <= 0) {
      return res.status(400).json({ error: "goal_bfc must be a positive integer" });
    }

    const { data, error } = await supabase
      .from("crowdfunding_campaigns")
      .insert({
        owner_id: req.user.id, title, description: description || "",
        goal_bfc: goalBfc, category, media: sanitizeMedia(req.body.media),
        raised_bfc: 0, status: "active",
        created_at: nowIso(), updated_at: nowIso()
      })
      .select("*").single();
    if (error) throw error;
    return res.status(201).json({ campaign: data });
  } catch (error) { next(error); }
});

app.put("/api/crowdfunding/campaigns/:id", requireAuth, async function (req, res, next) {
  try {
    const updates = { updated_at: nowIso() };
    if (req.body.title       !== undefined) updates.title       = safeText(req.body.title, 150);
    if (req.body.description !== undefined) updates.description = safeText(req.body.description, 2000);
    if (req.body.category    !== undefined) updates.category    = safeText(req.body.category, 40);
    if (req.body.media       !== undefined) updates.media       = sanitizeMedia(req.body.media);
    if (req.body.status      !== undefined && ["active","paused","completed","cancelled"].includes(req.body.status)) {
      updates.status = req.body.status;
    }

    const { data, error } = await supabase
      .from("crowdfunding_campaigns")
      .update(updates)
      .eq("id", req.params.id)
      .eq("owner_id", req.user.id)
      .select("*")
      .maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: "Campaign not found" });
    return res.json({ campaign: data });
  } catch (error) { next(error); }
});

app.post("/api/crowdfunding/campaigns/:id/donate", requireAuth, async function (req, res, next) {
  try {
    const amount = req.body.amount;

    if (!Number.isInteger(amount) || amount <= 0) {
      return res.status(400).json({ error: "amount must be a positive integer" });
    }

    const { data, error } = await supabase.rpc("bfc_donate", {
      p_donor: req.user.id,
      p_campaign_id: req.params.id,
      p_amount: amount
    });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    return res.json({ balance: data });
  } catch (error) { next(error); }
});

app.get("/api/crowdfunding/donations", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("campaign_donations")
      .select("*")
      .or("donor_id.eq." + req.user.id + ",owner_id.eq." + req.user.id)
      .order("created_at", { ascending: false });

    if (error) {
      return res.status(400).json({ error: error.message });
    }

    const donations = data || [];
    const campaignIds = Array.from(new Set(donations.map(function (d) { return d.campaign_id; }).filter(Boolean)));

    let campaignTitles = {};
    if (campaignIds.length) {
      const { data: campaigns, error: campaignsError } = await supabase
        .from("crowdfunding_campaigns")
        .select("id, title")
        .in("id", campaignIds);

      if (campaignsError) {
        return res.status(400).json({ error: campaignsError.message });
      }

      (campaigns || []).forEach(function (c) { campaignTitles[c.id] = c.title; });
    }

    const enriched = donations.map(function (d) {
      return Object.assign({}, d, { campaign_title: d.campaign_id ? (campaignTitles[d.campaign_id] || null) : null });
    });

    return res.json({ donations: enriched });
  } catch (error) { next(error); }
});

app.get("/api/crowdfunding/donations/:id", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("campaign_donations")
      .select("*")
      .eq("id", req.params.id)
      .or("donor_id.eq." + req.user.id + ",owner_id.eq." + req.user.id)
      .maybeSingle();

    if (error) {
      return res.status(400).json({ error: error.message });
    }
    if (!data) return res.status(404).json({ error: "Donation not found" });

    let campaignTitle = null;
    if (data.campaign_id) {
      const { data: campaign } = await supabase
        .from("crowdfunding_campaigns")
        .select("title")
        .eq("id", data.campaign_id)
        .maybeSingle();
      campaignTitle = campaign ? campaign.title : null;
    }

    return res.json({ donation: Object.assign({}, data, { campaign_title: campaignTitle }) });
  } catch (error) { next(error); }
});

/* ── BizDoc ── */

app.get("/api/bizdoc/documents", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("bizdoc_documents")
      .select("*")
      .eq("owner_id", req.user.id)
      .order("created_at", { ascending: false });
    if (error) throw error;
    return res.json({ documents: data || [] });
  } catch (error) { next(error); }
});

app.get("/api/bizdoc/documents/:id", requireAuth, async function (req, res, next) {
  try {
    const { data: document, error } = await supabase
      .from("bizdoc_documents")
      .select("*")
      .eq("id", req.params.id)
      .eq("owner_id", req.user.id)
      .maybeSingle();
    if (error) throw error;
    if (!document) return res.status(404).json({ error: "Document not found" });

    const { data: signatures, error: sigError } = await supabase
      .from("bizdoc_signatures")
      .select("*")
      .eq("document_id", req.params.id)
      .order("signed_at", { ascending: true });
    if (sigError) throw sigError;

    return res.json({ document, signatures: signatures || [] });
  } catch (error) { next(error); }
});

app.post("/api/bizdoc/documents", requireAuth, async function (req, res, next) {
  try {
    const templateType = safeText(req.body.template_type, 60) || "blank";
    const title         = safeText(req.body.title, 150);
    const fields         = (req.body.fields && typeof req.body.fields === "object" && !Array.isArray(req.body.fields))
      ? req.body.fields : {};
    const partyName      = safeText(req.body.party_name, 150);
    const partyEmail     = safeText(req.body.party_email, 200);
    const content         = (req.body.content !== undefined && req.body.content !== null) ? req.body.content : null;

    if (!title) return res.status(400).json({ error: "Title is required" });

    const { data, error } = await supabase
      .from("bizdoc_documents")
      .insert({
        owner_id: req.user.id, template_type: templateType, title,
        fields, party_name: partyName, party_email: partyEmail, content,
        status: "draft",
        created_at: nowIso(), updated_at: nowIso()
      })
      .select("*").single();
    if (error) throw error;
    return res.status(201).json({ document: data });
  } catch (error) { next(error); }
});

app.put("/api/bizdoc/documents/:id", requireAuth, async function (req, res, next) {
  try {
    const updates = { updated_at: nowIso() };
    if (req.body.title       !== undefined) updates.title       = safeText(req.body.title, 150);
    if (req.body.fields      !== undefined && typeof req.body.fields === "object" && !Array.isArray(req.body.fields)) {
      updates.fields = req.body.fields;
    }
    if (req.body.party_name  !== undefined) updates.party_name  = safeText(req.body.party_name, 150);
    if (req.body.party_email !== undefined) updates.party_email = safeText(req.body.party_email, 200);
    if (req.body.status      !== undefined && ["draft","sent","signed","voided"].includes(req.body.status)) {
      updates.status = req.body.status;
    }
    if (req.body.content     !== undefined) updates.content     = req.body.content;

    const { data, error } = await supabase
      .from("bizdoc_documents")
      .update(updates)
      .eq("id", req.params.id)
      .eq("owner_id", req.user.id)
      .select("*")
      .maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: "Document not found" });
    return res.json({ document: data });
  } catch (error) { next(error); }
});

app.post("/api/bizdoc/documents/:id/sign", requireAuth, async function (req, res, next) {
  try {
    const { data: document, error: docError } = await supabase
      .from("bizdoc_documents")
      .select("*")
      .eq("id", req.params.id)
      .eq("owner_id", req.user.id)
      .maybeSingle();
    if (docError) throw docError;
    if (!document) return res.status(404).json({ error: "Document not found" });

    const signerName    = safeText(req.body.signer_name, 150);
    const signerEmail   = safeText(req.body.signer_email, 200);
    const signatureData = safeText(req.body.signature_data, 500000);

    if (!signerName) return res.status(400).json({ error: "signer_name is required" });
    if (!signatureData) return res.status(400).json({ error: "signature_data is required" });

    const { data: signature, error: sigError } = await supabase
      .from("bizdoc_signatures")
      .insert({
        document_id: req.params.id,
        signer_id: req.user.id,
        signer_name: signerName,
        signer_email: signerEmail,
        signature_data: signatureData,
        ip_address: req.headers["x-forwarded-for"] || req.ip,
        user_agent: req.get("user-agent")
      })
      .select("*").single();
    if (sigError) return res.status(400).json({ error: sigError.message });

    const { data: updatedDocument, error: updateError } = await supabase
      .from("bizdoc_documents")
      .update({ status: "signed", updated_at: nowIso() })
      .eq("id", req.params.id)
      .select("*")
      .maybeSingle();
    if (updateError) throw updateError;

    return res.json({ signature, document: updatedDocument });
  } catch (error) { next(error); }
});

app.delete("/api/bizdoc/documents/:id", requireAuth, async function (req, res, next) {
  try {
    const { data: document, error } = await supabase
      .from("bizdoc_documents")
      .select("*")
      .eq("id", req.params.id)
      .maybeSingle();
    if (error) throw error;
    if (!document) return res.status(404).json({ error: "Document not found" });

    const isAuthorized = document.owner_id === req.user.id;
    if (!isAuthorized) {
      return res.status(403).json({ error: "Not authorized" });
    }

    try {
      await supabase.from("bizdoc_signatures").delete().eq("document_id", req.params.id);
    } catch (sigCleanupErr) {
      console.log("[bizdoc] signature cleanup failed:", sigCleanupErr.message || sigCleanupErr);
    }

    const { error: deleteError } = await supabase
      .from("bizdoc_documents")
      .delete()
      .eq("id", req.params.id);
    if (deleteError) {
      return res.status(500).json({ error: "Failed to delete document: " + deleteError.message });
    }

    return res.status(200).json({ ok: true });
  } catch (error) { next(error); }
});

/* ── Biz-EBook (manuscript → formatted PDF book) ── */

// Splits manuscript text into { heading, paragraphs[] } chapters.
// Conservative: only treats a line as a chapter heading when it matches
// "Chapter <number/roman/word>" (case-insensitive), or is a short all-caps
// line isolated by blank lines on both sides. If nothing matches, the
// whole manuscript becomes a single unheaded chapter — nothing is lost.
function parseManuscriptChapters(manuscriptText) {
  var normalized = String(manuscriptText || "").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  var lines = normalized.split("\n");

  var CHAPTER_HEADING_RE = /^chapter\s+([0-9]+|[ivxlcdm]+|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty)\b/i;

  function isBlank(line) { return line.trim() === ""; }

  function isAllCapsHeading(trimmed) {
    if (!trimmed || trimmed.length > 60) return false;
    if (/[a-z]/.test(trimmed)) return false;   // any lowercase disqualifies it
    if (!/[A-Z]{2,}/.test(trimmed)) return false; // needs a real word, not just punctuation/numbers
    return true;
  }

  function isHeadingCandidate(idx) {
    var trimmed = lines[idx].trim();
    if (!trimmed) return false;
    if (CHAPTER_HEADING_RE.test(trimmed)) return true;

    var prevBlank = idx === 0 || isBlank(lines[idx - 1]);
    var nextBlank = idx === lines.length - 1 || isBlank(lines[idx + 1]);
    return prevBlank && nextBlank && isAllCapsHeading(trimmed);
  }

  function paragraphsFromLines(bodyLines) {
    return bodyLines.join("\n")
      .split(/\n\s*\n+/)
      .map(function (p) { return p.trim(); })
      .filter(function (p) { return p.length > 0; });
  }

  var headingIndexes = [];
  for (var i = 0; i < lines.length; i++) {
    if (isHeadingCandidate(i)) headingIndexes.push(i);
  }

  if (headingIndexes.length === 0) {
    var soleParagraphs = paragraphsFromLines(lines);
    return soleParagraphs.length ? [{ heading: null, paragraphs: soleParagraphs }] : [];
  }

  var chapters = [];

  // Front matter before the first detected heading (preface/epigraph/etc.) —
  // kept as an unheaded chapter so no manuscript content is silently dropped.
  if (headingIndexes[0] > 0) {
    var frontParagraphs = paragraphsFromLines(lines.slice(0, headingIndexes[0]));
    if (frontParagraphs.length) chapters.push({ heading: null, paragraphs: frontParagraphs });
  }

  for (var h = 0; h < headingIndexes.length; h++) {
    var startIdx = headingIndexes[h];
    var endIdx = (h + 1 < headingIndexes.length) ? headingIndexes[h + 1] : lines.length;
    chapters.push({
      heading: lines[startIdx].trim(),
      paragraphs: paragraphsFromLines(lines.slice(startIdx + 1, endIdx))
    });
  }

  return chapters;
}

// Shared HTML helpers used by both chapter-parsing paths, parseInlineRuns,
// and the EPUB content builder.
function unescapeEntities(s) {
  return String(s)
    .replace(/&amp;/g, "&")
    .replace(/&nbsp;/g, " ")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, "\"")
    .replace(/&#39;/g, "'");
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function stripTags(s) {
  return unescapeEntities(String(s).replace(/<[^>]+>/g, " ")).replace(/\s+/g, " ").trim();
}

// Parses one paragraph's inner HTML into an array of inline-formatted runs:
// [{ text, bold, italic, underline, color, fontFamily }, ...]. There's no
// DOM available server-side, so this is a regex tokenizer over a small
// whitelist of inline tags (<b>/<strong>, <i>/<em>, <u>, <span>, <font>)
// plus their style/attribute equivalents (font-weight, font-style,
// text-decoration, color, font-family) rather than a real parser. A new
// run is emitted whenever the active style set changes; any tag outside
// the whitelist is stepped over without emitting markup (its text still
// flows into the surrounding run). Deliberately defensive — on any
// failure this falls back to the plain stripped string for the whole
// paragraph so one malformed paragraph can never break a chapter.
function parseInlineRuns(segmentHtml) {
  try {
    var html = String(segmentHtml || "");
    // Matches ANY tag (not just whitelisted ones) so non-whitelisted tags
    // (<p>, <div>, <li>, headings, or anything unrecognized) are consumed
    // as a tag token rather than leaking their raw "tagname>" text into a
    // run — the whitelist check happens below, per-token.
    var tagRe = /<(\/?)([a-zA-Z][a-zA-Z0-9]*)((?:\s+[a-zA-Z-]+\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*\/?>|([^<]+)/g;
    var attrRe = /([a-zA-Z-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
    var INLINE_TAGS = { b: 1, strong: 1, i: 1, em: 1, u: 1, span: 1, font: 1 };

    function styleFromAttrs(attrString) {
      var style = {};
      var m;
      attrRe.lastIndex = 0;
      while ((m = attrRe.exec(attrString)) !== null) {
        var name = m[1].toLowerCase();
        var value = (m[2] !== undefined ? m[2] : m[3]) || "";
        if (name === "style") {
          value.split(";").forEach(function (decl) {
            var parts = decl.split(":");
            if (parts.length < 2) return;
            var prop = parts[0].trim().toLowerCase();
            var val = parts.slice(1).join(":").trim();
            if (!val) return;
            if (prop === "font-weight") {
              var n = parseInt(val, 10);
              if (val.toLowerCase() === "bold" || (!isNaN(n) && n >= 700)) style.bold = true;
            } else if (prop === "font-style" && val.toLowerCase() === "italic") {
              style.italic = true;
            } else if (prop === "text-decoration" && val.toLowerCase().indexOf("underline") !== -1) {
              style.underline = true;
            } else if (prop === "color") {
              style.color = val;
            } else if (prop === "font-family") {
              style.fontFamily = val.replace(/^["']|["']$/g, "");
            }
          });
        } else if (name === "color") {
          style.color = value;
        } else if (name === "face") {
          style.fontFamily = value;
        }
      }
      return style;
    }

    var stack = [{ bold: false, italic: false, underline: false, color: null, fontFamily: null }];
    var runs = [];
    var buffer = "";

    function flush() {
      if (!buffer) return;
      var text = unescapeEntities(buffer).replace(/\s+/g, " ");
      buffer = "";
      if (!text.trim()) return;
      var s = stack[stack.length - 1];
      runs.push({
        text: text,
        bold: !!s.bold,
        italic: !!s.italic,
        underline: !!s.underline,
        color: s.color || null,
        fontFamily: s.fontFamily || null
      });
    }

    var match;
    tagRe.lastIndex = 0;
    while ((match = tagRe.exec(html)) !== null) {
      if (match[4] !== undefined) {
        buffer += match[4];
        continue;
      }
      var closing = match[1] === "/";
      var tag = match[2].toLowerCase();

      if (!INLINE_TAGS[tag]) {
        // Non-whitelisted tag (<p>, <div>, <li>, headings, etc.) — step
        // over it: flush as a soft text boundary, but emit no markup and
        // touch neither the style stack (opens) nor pop it (closes), since
        // this tag never pushed a frame in the first place.
        flush();
        continue;
      }

      if (closing) {
        flush();
        if (stack.length > 1) stack.pop();
        continue;
      }

      flush();
      var base = stack[stack.length - 1];
      var next = {
        bold: base.bold, italic: base.italic, underline: base.underline,
        color: base.color, fontFamily: base.fontFamily
      };
      if (tag === "b" || tag === "strong") next.bold = true;
      if (tag === "i" || tag === "em") next.italic = true;
      if (tag === "u") next.underline = true;

      var fromAttrs = styleFromAttrs(match[3] || "");
      if (fromAttrs.bold) next.bold = true;
      if (fromAttrs.italic) next.italic = true;
      if (fromAttrs.underline) next.underline = true;
      if (fromAttrs.color) next.color = fromAttrs.color;
      if (fromAttrs.fontFamily) next.fontFamily = fromAttrs.fontFamily;

      stack.push(next);
    }
    flush();

    return runs.filter(function (r) { return r.text.trim().length > 0; });
  } catch (err) {
    return stripTags(segmentHtml);
  }
}

// Matches a whole <img ...> tag (self-closing or not) so it can be pulled
// out of a line before the remaining text reaches parseInlineRuns — img was
// never in that function's INLINE_TAGS whitelist and is handled entirely
// separately here instead.
var IMG_TAG_RE = /<img\b([^>]*)>/gi;
var IMG_ATTR_RE = /([a-zA-Z-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;

function parseImgAttrString(attrString) {
  var attrs = {};
  var m;
  IMG_ATTR_RE.lastIndex = 0;
  while ((m = IMG_ATTR_RE.exec(attrString)) !== null) {
    attrs[m[1].toLowerCase()] = (m[2] !== undefined ? m[2] : m[3]) || "";
  }
  return attrs;
}

// Turns one <img>'s attribute string into an { type:"image", ... } paragraph
// object the PDF renderer knows how to draw, or null if the tag can't be
// safely embedded — no data-path, or a blob:/http(s) src standing in for one
// (never a real bf-books storage path, so there'd be nothing to download).
// width/crop are read from the same inline style + data-crop* attrs the
// editor (bizdoc.html) writes when a user resizes/crops an image.
function imgTagToParagraph(attrString) {
  var attrs = parseImgAttrString(attrString);
  var path = attrs["data-path"];
  if (!path || typeof path !== "string") return null;
  path = unescapeEntities(path).trim();
  if (!path || path.indexOf("blob:") === 0 || path.indexOf("http://") === 0 || path.indexOf("https://") === 0) return null;

  var widthPx = null, widthPct = null;
  var wMatch = /(?:^|;)\s*width\s*:\s*([0-9.]+)\s*(px|%)/i.exec(attrs.style || "");
  if (wMatch) {
    var wVal = parseFloat(wMatch[1]);
    if (!isNaN(wVal)) {
      if (wMatch[2].toLowerCase() === "px") widthPx = wVal;
      else widthPct = wVal;
    }
  }

  function cropFrac(name, fallback) {
    var v = parseFloat(attrs[name]);
    return isNaN(v) ? fallback : Math.max(0, Math.min(1, v));
  }
  var cropW = parseFloat(attrs["data-cropw"]);
  var cropH = parseFloat(attrs["data-croph"]);
  cropW = (cropW > 0 && cropW <= 1) ? cropW : 1;
  cropH = (cropH > 0 && cropH <= 1) ? cropH : 1;

  return {
    type: "image",
    path: path,
    widthPx: widthPx,
    widthPct: widthPct,
    cropX: cropFrac("data-cropx", 0),
    cropY: cropFrac("data-cropy", 0),
    cropW: cropW,
    cropH: cropH
  };
}

// Splits one normalized line into an ordered sequence of paragraph entries:
// text runs (parseInlineRuns, unchanged) interleaved with standalone image
// objects for each <img> found — so "some text <img> more text" becomes
// three separate paragraphs in document order instead of the image being
// silently dropped.
function lineToParagraphs(line) {
  var out = [];
  var lastIndex = 0;
  var m;
  IMG_TAG_RE.lastIndex = 0;
  while ((m = IMG_TAG_RE.exec(line)) !== null) {
    var textBefore = line.slice(lastIndex, m.index);
    if (textBefore.trim()) {
      var runsBefore = parseInlineRuns(textBefore);
      if (runsBefore && runsBefore.length > 0) out.push(runsBefore);
    }
    var imgPara = imgTagToParagraph(m[1] || "");
    if (imgPara) out.push(imgPara);
    lastIndex = IMG_TAG_RE.lastIndex;
  }
  var textAfter = line.slice(lastIndex);
  if (textAfter.trim()) {
    var runsAfter = parseInlineRuns(textAfter);
    if (runsAfter && runsAfter.length > 0) out.push(runsAfter);
  }
  return out;
}

// Converts the manuscript Editor's rich HTML into the same { heading,
// paragraphs[] }[] shape parseManuscriptChapters returns, but splits on
// explicit <h1> chapter boundaries instead of the plain-text heuristic —
// the editor already knows exactly where chapters start, so we don't need
// to guess. Each paragraph is a runs array from parseInlineRuns (or, on
// parse failure, the plain fallback string it returns), or an
// { type:"image", ... } object for each <img data-path> found (see
// imgTagToParagraph/lineToParagraphs) — headings stay plain strings via
// stripTags.
function htmlToChapters(html) {
  function textToParagraphs(segmentHtml) {
    var paragraphs = [];
    segmentHtml.split(/\n+/).forEach(function (line) {
      paragraphs = paragraphs.concat(lineToParagraphs(line));
    });
    return paragraphs;
  }

  // Insert line breaks after block-level closers so stripping tags doesn't
  // fuse adjacent blocks onto one line.
  var normalized = String(html || "")
    .replace(/<\/(h1|h2|p|div|li)>/gi, "</$1>\n")
    .replace(/<br\s*\/?>/gi, "\n");

  var h1Re = /<h1[^>]*>([\s\S]*?)<\/h1>\n?/gi;
  var starts = [];
  var match;
  while ((match = h1Re.exec(normalized)) !== null) {
    starts.push({ index: match.index, end: h1Re.lastIndex, heading: match[1] });
  }

  if (starts.length === 0) {
    return [{ heading: null, paragraphs: textToParagraphs(normalized) }];
  }

  var chapters = [];

  // Front matter before the first <h1> — same unheaded-chapter convention
  // parseManuscriptChapters uses for pre-heading content.
  if (starts[0].index > 0) {
    var frontParagraphs = textToParagraphs(normalized.slice(0, starts[0].index));
    if (frontParagraphs.length) chapters.push({ heading: null, paragraphs: frontParagraphs });
  }

  for (var i = 0; i < starts.length; i++) {
    var segStart = starts[i].end;
    var segEnd = (i + 1 < starts.length) ? starts[i + 1].index : normalized.length;
    chapters.push({
      heading: stripTags(starts[i].heading),
      paragraphs: textToParagraphs(normalized.slice(segStart, segEnd))
    });
  }

  return chapters;
}

// A chapter's paragraph is either a legacy plain string (parseManuscriptChapters,
// always) or a runs array (htmlToChapters, when parseInlineRuns succeeds) —
// every consumer of chapter.paragraphs must handle both via these two helpers.
function runsToPlainText(paragraph) {
  if (typeof paragraph === "string") return paragraph;
  if (!Array.isArray(paragraph)) return "";
  return paragraph.map(function (run) { return (run && run.text) ? run.text : ""; }).join("");
}

function runsToInlineHtml(paragraph) {
  if (typeof paragraph === "string") return escapeHtml(paragraph);
  if (!Array.isArray(paragraph)) return "";
  return paragraph.map(function (run) {
    if (!run || !run.text) return "";
    var html = escapeHtml(run.text);
    var styleParts = [];
    if (run.color) styleParts.push("color:" + escapeHtml(String(run.color)));
    if (run.fontFamily) styleParts.push("font-family:" + escapeHtml(String(run.fontFamily)));
    if (styleParts.length) html = '<span style="' + styleParts.join(";") + '">' + html + "</span>";
    if (run.underline) html = "<u>" + html + "</u>";
    if (run.italic) html = "<em>" + html + "</em>";
    if (run.bold) html = "<strong>" + html + "</strong>";
    return html;
  }).join("");
}

// KDP-standard trim sizes, in PDF points (1 inch = 72pt).
var TRIM_SIZES = {
  "letter":      { width: 612, height: 792, margins: { top: 72, bottom: 72, left: 72, right: 72 } },
  "6x9":         { width: 432, height: 648, margins: { top: 72, bottom: 72, left: 72, right: 72 } },
  "5x8":         { width: 360, height: 576, margins: { top: 72, bottom: 72, left: 72, right: 72 } },
  "5.25x8":      { width: 378, height: 576, margins: { top: 72, bottom: 72, left: 72, right: 72 } },
  "5.5x8.5":     { width: 396, height: 612, margins: { top: 72, bottom: 72, left: 72, right: 72 } },
  "6.14x9.21":   { width: 442, height: 663, margins: { top: 72, bottom: 72, left: 72, right: 72 } },
  "7x10":        { width: 504, height: 720, margins: { top: 72, bottom: 72, left: 72, right: 72 } },
  "8x10":        { width: 576, height: 720, margins: { top: 72, bottom: 72, left: 72, right: 72 } },
  "8.5x11":      { width: 612, height: 792, margins: { top: 72, bottom: 72, left: 72, right: 72 } }
};

// Per-page thickness in inches, mirrored from the frontend's PAPER_THICKNESS
// (bizdoc.html) so spine width can be computed server-side. Unknown stock
// falls back to white.
var PAPER_THICKNESS = { white: 0.002252, cream: 0.0025, color: 0.002347 };

// Renders manuscript text into a formatted book PDF using pdfkit's built-in
// fonts (no bundled font files needed) and resolves the finished file as a
// Buffer. options: { title, author, trimSize }.
var HEX_COLOR_RE = /^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/;

// Renders one chapter.paragraphs entry into doc, handling both shapes: a
// plain string (parseManuscriptChapters, or htmlToChapters's parse-failure
// fallback) renders exactly as before; a runs array (htmlToChapters) is
// rendered as one continuous paragraph via pdfkit's continued-text
// mechanism, switching font/size/color/underline per run. options carries
// the paragraph-level text options (align/lineGap) that must stay applied
// on every run so wrapping/justification stays consistent — pdfkit reads
// them off the run that starts the text, but reapplying them to each
// continued call is harmless and keeps this robust to pdfkit's internals.
function renderParagraphRuns(doc, paragraph, options) {
  var baseOptions = options || {};

  if (typeof paragraph === "string") {
    if (!paragraph) return;
    doc.text(paragraph, baseOptions);
    return;
  }

  if (!Array.isArray(paragraph) || !paragraph.length) return;

  var runs = paragraph.filter(function (run) { return run && run.text; });
  if (!runs.length) return;

  runs.forEach(function (run, idx) {
    var font = mapFontToStandard(run.fontFamily, run.bold, run.italic);
    doc.font(font);
    doc.fontSize(12);

    var color = (typeof run.color === "string" && HEX_COLOR_RE.test(run.color)) ? run.color : "#000000";
    doc.fillColor(color);

    var runOptions = Object.assign({}, baseOptions, {
      continued: idx < runs.length - 1,
      underline: !!run.underline
    });
    doc.text(run.text, runOptions);
  });

  doc.fillColor("#000000");
}

async function generateBookPdf(manuscriptText, options) {
  var settings = options || {};
  var title  = safeText(settings.title, 200) || "Untitled Manuscript";
  var author = safeText(settings.author, 150) || "Unknown Author";

  var trimKey = (settings.trimSize && TRIM_SIZES[settings.trimSize]) ? settings.trimSize : "letter";
  var trim = TRIM_SIZES[trimKey];

  var chapters = (settings.chapters && settings.chapters.length) ? settings.chapters : parseManuscriptChapters(manuscriptText);
  if (!chapters.length) chapters = [{ heading: null, paragraphs: [""] }];

  return new Promise(function (resolve, reject) {
    var doc;
    var pageRange;
    try {
      doc = new PDFDocument({
        size: [trim.width, trim.height],
        margins: trim.margins,
        bufferPages: true
      });
    } catch (err) {
      return reject(err);
    }

    var chunks = [];
    doc.on("data", function (chunk) { chunks.push(chunk); });
    doc.on("end", function () { resolve({ buffer: Buffer.concat(chunks), pageCount: pageRange.count }); });
    doc.on("error", reject);

    // The rest of the draw needs to await per-image byte fetches (inline
    // manuscript images), so it's wrapped in an async IIFE rather than
    // running directly in this (necessarily synchronous) Promise executor —
    // a plain async executor would let a post-await throw fall through as
    // an unhandled rejection instead of calling reject().
    (async function () {
      try {
        // ── Title page ──
        doc.font("Times-Bold").fontSize(28);
        doc.moveDown(8);
        doc.text(title, { align: "center" });
        doc.moveDown(2);
        doc.font("Times-Roman").fontSize(16).text("by " + author, { align: "center" });

        var contentWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;

        // ── Chapters (each starts on its own new page) ──
        for (var ci = 0; ci < chapters.length; ci++) {
          var chapter = chapters[ci];
          doc.addPage();
          if (chapter.heading) {
            doc.font("Times-Bold").fontSize(20).text(chapter.heading, { align: "center" });
            doc.moveDown(2);
          } else {
            doc.moveDown(1);
          }
          doc.font("Times-Roman").fontSize(12);
          for (var pi = 0; pi < chapter.paragraphs.length; pi++) {
            var paragraph = chapter.paragraphs[pi];
            if (paragraph && typeof paragraph === "object" && !Array.isArray(paragraph) && paragraph.type === "image") {
              await drawInlineImage(doc, paragraph, contentWidth);
              continue;
            }
            renderParagraphRuns(doc, paragraph, { align: "justify", lineGap: 4 });
            doc.moveDown(1);
          }
        }

        // ── Page numbers, bottom-centered, skipping the title page ──
        pageRange = doc.bufferedPageRange();
        var bottomMargin = doc.page.margins.bottom;
        for (var p = pageRange.start; p < pageRange.start + pageRange.count; p++) {
          if (p === pageRange.start) continue; // no number on the title page
          doc.switchToPage(p);
          doc.page.margins.bottom = 0; // let us draw inside the bottom margin
          doc.font("Helvetica").fontSize(9).text(
            String(p - pageRange.start),
            0,
            doc.page.height - 40,
            { width: doc.page.width, align: "center" }
          );
          doc.page.margins.bottom = bottomMargin;
        }

        doc.end();
      } catch (err) {
        reject(err);
      }
    })();
  });
}

// Draws one { type:"image", ... } paragraph (from htmlToChapters) into the
// PDF at the current doc.y, advancing doc.y past it so following text flows
// below. Crop math mirrors generateCoverWrapPdf's (zoom the image up so the
// [cropX,cropY,cropX+cropW,cropY+cropH] sub-rectangle fills the frame,
// clipped to the frame). Uses pdfkit's own doc.openImage() to read the
// image's natural pixel dimensions (PNG/JPEG only — same formats doc.image()
// itself supports) rather than pulling in an extra dependency; neither
// image-size nor sharp is in package.json, and this needs no new install.
// Any failure (download, unsupported format, draw) is logged and skipped —
// one bad image must never fail the whole book.
async function drawInlineImage(doc, para, contentWidth) {
  var buf;
  try {
    const { data: blob, error: dlErr } = await supabase.storage.from("bf-books").download(para.path);
    if (dlErr || !blob) {
      console.warn("[book-pdf] Failed to download inline image:", para.path, dlErr && (dlErr.message || dlErr));
      return;
    }
    buf = Buffer.from(await blob.arrayBuffer());
  } catch (fetchErr) {
    console.warn("[book-pdf] Failed to fetch inline image:", para.path, fetchErr && (fetchErr.message || fetchErr));
    return;
  }

  var natural;
  try {
    natural = doc.openImage(buf);
  } catch (parseErr) {
    console.warn("[book-pdf] Failed to parse inline image (unsupported format?):", para.path, parseErr && (parseErr.message || parseErr));
    return;
  }
  if (!natural || !natural.width || !natural.height) return;

  var drawWidth;
  if (para.widthPx) {
    drawWidth = para.widthPx * 72 / 96;
  } else if (para.widthPct) {
    drawWidth = contentWidth * (para.widthPct / 100);
  } else {
    drawWidth = contentWidth * 0.6;
  }
  drawWidth = Math.max(1, Math.min(contentWidth, drawWidth));

  var cropW = (para.cropW > 0 && para.cropW <= 1) ? para.cropW : 1;
  var cropH = (para.cropH > 0 && para.cropH <= 1) ? para.cropH : 1;
  var cropX = (typeof para.cropX === "number") ? para.cropX : 0;
  var cropY = (typeof para.cropY === "number") ? para.cropY : 0;
  var isFullCrop = (cropX === 0 && cropY === 0 && cropW === 1 && cropH === 1);

  var drawHeight = drawWidth * (natural.height / natural.width) * (cropH / cropW);

  var GAP = 8;
  if (doc.y + GAP + drawHeight > doc.page.height - doc.page.margins.bottom) {
    doc.addPage();
  }

  doc.y += GAP;
  var x = doc.page.margins.left + (contentWidth - drawWidth) / 2;
  var y = doc.y;

  try {
    if (isFullCrop) {
      doc.image(buf, x, y, { width: drawWidth });
    } else {
      doc.save();
      doc.rect(x, y, drawWidth, drawHeight).clip();
      var drawnW = drawWidth / cropW;
      var drawnH = drawHeight / cropH;
      var drawnX = x - (cropX / cropW) * drawWidth;
      var drawnY = y - (cropY / cropH) * drawHeight;
      doc.image(buf, drawnX, drawnY, { width: drawnW, height: drawnH });
      doc.restore();
    }
  } catch (drawErr) {
    console.warn("[book-pdf] Failed to draw inline image:", para.path, drawErr && (drawErr.message || drawErr));
    return;
  }

  doc.x = doc.page.margins.left;
  doc.y = y + drawHeight + GAP;
}

// Maps a frontend font-stack string plus bold/italic to one of pdfkit's
// built-in standard-14 fonts (no bundled font files needed), case-insensitive.
function mapFontToStandard(fontFamily, bold, italic) {
  var stack = (fontFamily || "").toLowerCase();
  var family;
  if (stack.indexOf("mono") !== -1 || stack.indexOf("courier") !== -1) {
    family = "Courier";
  } else if (stack.indexOf("sans") !== -1 || stack.indexOf("arial") !== -1 || stack.indexOf("helvetica") !== -1 || stack.indexOf("verdana") !== -1 || stack.indexOf("segoe") !== -1 || stack.indexOf("roboto") !== -1) {
    family = "Helvetica";
  } else {
    family = "Times";
  }
  if (family === "Courier") {
    if (bold && italic) return "Courier-BoldOblique";
    if (bold) return "Courier-Bold";
    if (italic) return "Courier-Oblique";
    return "Courier";
  }
  if (family === "Helvetica") {
    if (bold && italic) return "Helvetica-BoldOblique";
    if (bold) return "Helvetica-Bold";
    if (italic) return "Helvetica-Oblique";
    return "Helvetica";
  }
  if (bold && italic) return "Times-BoldItalic";
  if (bold) return "Times-Bold";
  if (italic) return "Times-Italic";
  return "Times-Roman";
}

// Renders a cover-wrap design (back|spine|front) into a print-ready,
// full-bleed PDF using pdfkit. Pure function — no network/Supabase calls;
// the caller resolves the background image to a Buffer first (or passes
// null). options: { trimKey, pageCount, paperStock, name, bgImageBuffer }.
async function generateCoverWrapPdf(design, opts) {
  var settings = opts || {};
  var trimKey = (settings.trimKey && TRIM_SIZES[settings.trimKey]) ? settings.trimKey : "letter";
  var trim = TRIM_SIZES[trimKey];
  var pageCount = settings.pageCount || 0;
  var thickness = PAPER_THICKNESS[settings.paperStock] || PAPER_THICKNESS.white;

  var spinePt = pageCount * thickness * 72;
  var bleedPt = 9; // 0.125in
  var contentW = trim.width + spinePt + trim.width; // back | spine | front, no bleed
  var contentH = trim.height;
  var fullW = contentW + 2 * bleedPt;
  var fullH = contentH + 2 * bleedPt;

  // Pre-fetch foreground image-layer bytes before the synchronous pdfkit
  // drawing pass below — that Promise executor isn't async, so arbitrary-
  // length per-layer downloads have to happen out here first. Mirrors the
  // same download→Buffer pattern the route uses for the background image.
  // A failed download is logged and skipped, never fatal to the export.
  var imageLayers = (design && Array.isArray(design.imageLayers)) ? design.imageLayers : [];
  var imageLayerBuffers = {};
  for (var ili = 0; ili < imageLayers.length; ili++) {
    var srcLayer = imageLayers[ili];
    var src = srcLayer && srcLayer.src;
    if (!src || typeof src !== "string" || src.indexOf("blob:") === 0 || src.indexOf("http") === 0) continue;
    try {
      const { data: layerBlob, error: layerDlErr } = await supabase.storage.from("bf-books").download(src);
      if (!layerDlErr && layerBlob) {
        imageLayerBuffers[srcLayer.id] = Buffer.from(await layerBlob.arrayBuffer());
      }
    } catch (layerFetchErr) {
      console.warn("[cover-wraps] Failed to load image layer for export:", srcLayer && srcLayer.id, layerFetchErr && (layerFetchErr.message || layerFetchErr));
    }
  }

  return new Promise(function (resolve, reject) {
    try {
      var doc = new PDFDocument({ size: [fullW, fullH], margin: 0 });

      var chunks = [];
      doc.on("data", function (chunk) { chunks.push(chunk); });
      doc.on("end", function () { resolve(Buffer.concat(chunks)); });
      doc.on("error", reject);

      // ── Background color, bleeds to the outer edge ──
      doc.rect(0, 0, fullW, fullH).fill((design && design.bgColor) || "#ffffff");

      // ── Background image: object-fit:cover + pan/zoom, full bleed ──
      if (settings.bgImageBuffer) {
        var boxX = 0, boxY = 0, boxW = fullW, boxH = fullH;
        var s = Math.max(1, Math.min(4, (design && design.bgScale) || 1));
        var txPt = (((design && design.bgOffsetX) || 0) / 100) * boxW;
        var tyPt = (((design && design.bgOffsetY) || 0) / 100) * boxH;
        var drawW = boxW * s;
        var drawH = boxH * s;
        var centerX = boxW / 2 + txPt;
        var centerY = boxH / 2 + tyPt;
        var drawX = centerX - drawW / 2;
        var drawY = centerY - drawH / 2;

        doc.save();
        doc.rect(boxX, boxY, boxW, boxH).clip();
        doc.image(settings.bgImageBuffer, drawX, drawY, { cover: [drawW, drawH] });
        doc.restore();
      }

      // ── Foreground image layers: above background, below text — matches
      // the on-screen z-order (background z-index 0, image layers 1, text 2).
      // Position/size use the same bleedPt + contentW/contentH convention
      // the text layers use below, so images and text align. Crop mirrors
      // the on-screen CSS math exactly: zoom the image up so the
      // [cropX,cropY,cropX+cropW,cropY+cropH] sub-rectangle fills the frame,
      // clipped to the frame's own bounds.
      imageLayers.forEach(function (layer) {
        var buf = imageLayerBuffers[layer && layer.id];
        if (!buf) return;
        try {
          var centerX = bleedPt + ((layer.xPct || 0) / 100) * contentW;
          var centerY = bleedPt + ((layer.yPct || 0) / 100) * contentH;
          var frameW = ((layer.widthPct || 0) / 100) * contentW;
          var frameH = ((layer.heightPct || 0) / 100) * contentH;
          var frameX = centerX - frameW / 2;
          var frameY = centerY - frameH / 2;

          var cropW = (typeof layer.cropW === "number" && layer.cropW > 0) ? layer.cropW : 1;
          var cropH = (typeof layer.cropH === "number" && layer.cropH > 0) ? layer.cropH : 1;
          var cropX = typeof layer.cropX === "number" ? layer.cropX : 0;
          var cropY = typeof layer.cropY === "number" ? layer.cropY : 0;

          var drawnW = frameW / cropW;
          var drawnH = frameH / cropH;
          var drawnX = -(cropX / cropW) * frameW;
          var drawnY = -(cropY / cropH) * frameH;

          doc.save();
          doc.rotate(layer.rotation || 0, { origin: [centerX, centerY] });
          doc.translate(frameX, frameY);
          doc.rect(0, 0, frameW, frameH).clip();
          doc.image(buf, drawnX, drawnY, { width: drawnW, height: drawnH });
          doc.restore();
        } catch (drawErr) {
          console.warn("[cover-wraps] Failed to draw image layer:", layer && layer.id, drawErr && (drawErr.message || drawErr));
        }
      });

      // ── Text layers ──
      // v1: every layer is drawn centered on its point regardless of its
      // `align` value (left/center/right) — align is not applied here yet.
      var layers = (design && design.textLayers) || [];
      layers.forEach(function (layer) {
        var text = layer && layer.text;
        if (!text) return;

        var centerX = bleedPt + ((layer.xPct || 0) / 100) * contentW;
        var centerY = bleedPt + ((layer.yPct || 0) / 100) * contentH;
        var fontSizePt = ((layer.fontSizePct || 0) / 100) * contentH;

        doc.font(mapFontToStandard(layer.fontFamily, layer.bold, layer.italic));
        doc.fontSize(fontSizePt);
        doc.fillColor(layer.color || "#111111");

        var textW = doc.widthOfString(text);
        var textH = doc.currentLineHeight();

        doc.save();
        doc.rotate(layer.rotation || 0, { origin: [centerX, centerY] });
        doc.text(text, centerX - textW / 2, centerY - textH / 2, { lineBreak: false });
        doc.restore();
      });

      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}

// Renders one paragraph into its chapter-HTML fragment. Text/runs paragraphs
// render exactly as before (wrapped in <p>, via runsToInlineHtml). An
// { type:"image", ... } paragraph (Block C) instead becomes a standalone
// centered <img> pointing at a short-lived signed URL: epub-gen-memory
// fetches whatever URL it finds in an <img src> at build time and packages
// the bytes into the EPUB itself (see its fetchable.js — http(s) or file://
// only, no buffer/data-URI intake), so a signed URL is the only thing it
// can actually consume here. EPUB is reflowable and has no simple way to
// pixel-crop like the PDF's clip+offset does, so for v1 a cropped image
// just renders in full here — only generateBookPdf/drawInlineImage honors
// crop. A failed signing attempt skips the image (console.warn) rather
// than failing the whole book.
async function paragraphToEpubHtml(paragraph) {
  if (paragraph && typeof paragraph === "object" && !Array.isArray(paragraph) && paragraph.type === "image") {
    var signedUrl;
    try {
      const { data: signedImage, error: signErr } = await supabase.storage.from("bf-books").createSignedUrl(paragraph.path, 300);
      if (signErr || !signedImage || !signedImage.signedUrl) {
        console.warn("[book-epub] Failed to sign inline image URL:", paragraph.path, signErr && (signErr.message || signErr));
        return "";
      }
      signedUrl = signedImage.signedUrl;
    } catch (signCatchErr) {
      console.warn("[book-epub] Failed to sign inline image URL:", paragraph.path, signCatchErr && (signCatchErr.message || signCatchErr));
      return "";
    }

    var styleParts = ["display:block", "margin:0.5em auto", "max-width:100%"];
    if (paragraph.widthPct) {
      styleParts.push("width:" + paragraph.widthPct + "%");
    } else if (paragraph.widthPx) {
      styleParts.push("width:" + paragraph.widthPx + "px");
    }

    return '<p style="text-align:center;"><img src="' + signedUrl + '" alt="" style="' + styleParts.join("; ") + ';" /></p>';
  }

  return "<p>" + runsToInlineHtml(paragraph) + "</p>";
}

// Renders manuscript text into an EPUB using the same chapter parsing as
// generateBookPdf, so the two stay symmetric. options: { title, author }.
async function generateBookEpub(manuscriptText, options) {
  var settings = options || {};
  var title  = safeText(settings.title, 200) || "Untitled Manuscript";
  var author = safeText(settings.author, 150) || "Unknown Author";

  var chapters = (settings.chapters && settings.chapters.length) ? settings.chapters : parseManuscriptChapters(manuscriptText);
  if (!chapters.length) chapters = [{ heading: null, paragraphs: [""] }];

  var content = [];
  for (var ci = 0; ci < chapters.length; ci++) {
    var chapter = chapters[ci];
    var htmlParts = [];
    for (var pi = 0; pi < chapter.paragraphs.length; pi++) {
      htmlParts.push(await paragraphToEpubHtml(chapter.paragraphs[pi]));
    }
    content.push({
      title: chapter.heading || "Front Matter",
      content: htmlParts.join("")
    });
  }

  const mod = await import("epub-gen-memory");
  const epub = mod.default.default || mod.default || mod;

  const buffer = await epub({ title: title, author: author }, content);
  return buffer;
}

app.post("/api/bizbook/generate", requireAuth, oracleUpload.fields([{ name: "file", maxCount: 1 }, { name: "cover", maxCount: 1 }]), async function (req, res, next) {
  try {
    var manuscriptFile = (req.files && req.files.file && req.files.file[0]) ? req.files.file[0] : null;
    var coverFile = (req.files && req.files.cover && req.files.cover[0]) ? req.files.cover[0] : null;

    if (!manuscriptFile) {
      return res.status(400).json({ error: "A manuscript file (.docx or .txt) is required" });
    }

    var extracted;
    try {
      extracted = await extractOracleFileText(manuscriptFile);
    } catch (fileParseErr) {
      console.error("[bizbook] Failed to parse uploaded manuscript:", fileParseErr.message || fileParseErr);
      return res.status(400).json({ error: "Could not read uploaded manuscript. It may be corrupted, empty, or an unsupported format." });
    }
    if (!extracted) {
      return res.status(400).json({ error: "Unsupported file type — upload a .docx or .txt manuscript" });
    }

    // extractOracleFileText prefixes a "[UPLOADED DOCUMENT: name]" label
    // meant for LLM context; strip it so it doesn't become the book's
    // opening line.
    var manuscriptText = extracted.replace(/^\[UPLOADED DOCUMENT:[^\]]*\]\n/, "");
    if (!manuscriptText.trim()) {
      return res.status(400).json({ error: "The uploaded manuscript appears to be empty" });
    }

    var title = safeText(req.body.title, 200);
    if (!title) {
      return res.status(400).json({ error: "A title is required" });
    }
    var author = safeText(req.body.author, 150) || "Unknown Author";
    var requestedTrim = req.body.trim_size || req.body.trimSize;
    var trimSize = (requestedTrim && TRIM_SIZES[requestedTrim]) ? requestedTrim : "6x9";

    var pdfResult = await generateBookPdf(manuscriptText, { title: title, author: author, trimSize: trimSize });
    var pdfBuffer = pdfResult.buffer;
    var pageCount = (pdfResult && typeof pdfResult.pageCount === "number") ? pdfResult.pageCount : null;

    var safeFileName = title.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 60) || "book";
    var storagePath = req.user.id + "/" + Date.now() + "_" + safeFileName + ".pdf";

    var uploadResult = await supabase.storage
      .from("bf-books")
      .upload(storagePath, pdfBuffer, { contentType: "application/pdf", upsert: false });
    if (uploadResult.error) {
      console.error("[bizbook] Storage upload failed:", uploadResult.error.message || uploadResult.error);
      return res.status(500).json({ error: "Failed to store generated book: " + uploadResult.error.message });
    }

    var epubStoragePath = req.user.id + "/" + Date.now() + "_" + safeFileName + ".epub";
    var epubBuffer;
    var epubUploadFailed = false;
    try {
      epubBuffer = await generateBookEpub(manuscriptText, { title: title, author: author });
      var epubUploadResult = await supabase.storage
        .from("bf-books")
        .upload(epubStoragePath, epubBuffer, { contentType: "application/epub+zip", upsert: false });
      if (epubUploadResult.error) {
        console.error("[bizbook] EPUB storage upload failed:", epubUploadResult.error.message || epubUploadResult.error);
        epubUploadFailed = true;
      }
    } catch (epubErr) {
      console.error("[bizbook] EPUB generation failed:", epubErr.message || epubErr);
      epubUploadFailed = true;
    }

    var coverStoragePath = null;
    if (coverFile) {
      try {
        var COVER_EXT_BY_MIME = { "image/png": "png", "image/jpeg": "jpg", "image/webp": "webp", "image/gif": "gif" };
        var coverExt = (coverFile.originalname && coverFile.originalname.includes(".")
          ? coverFile.originalname.split(".").pop()
          : null) || COVER_EXT_BY_MIME[coverFile.mimetype] || "png";
        var candidateCoverPath = req.user.id + "/" + Date.now() + "_" + safeFileName + "_cover." + coverExt;

        var coverUploadResult = await supabase.storage
          .from("bf-books")
          .upload(candidateCoverPath, coverFile.buffer, { contentType: coverFile.mimetype, upsert: false });
        if (coverUploadResult.error) {
          console.error("[bizbook] cover upload failed:", coverUploadResult.error.message || coverUploadResult.error);
        } else {
          coverStoragePath = candidateCoverPath;
        }
      } catch (coverErr) {
        console.error("[bizbook] cover upload failed:", coverErr.message || coverErr);
      }
    }

    var { data: book, error: insertError } = await supabase
      .from("bizbooks")
      .insert({
        owner_id: req.user.id, title, author, storage_path: storagePath,
        storage_path_epub: epubUploadFailed ? null : epubStoragePath,
        cover_path: coverStoragePath, trim_size: trimSize, page_count: pageCount,
        status: "ready", created_at: nowIso(), updated_at: nowIso()
      })
      .select("*").single();
    if (insertError) {
      console.error(
        "[bizbook] Failed to record book after successful storage upload (orphaned object at " + storagePath + "):",
        insertError.message || insertError
      );
      return res.status(500).json({ error: "Failed to save book record: " + insertError.message });
    }

    return res.status(200).json({ book: book });
  } catch (error) { next(error); }
});

app.get("/api/bizbook/books", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("bizbooks")
      .select("id, title, author, storage_path, storage_path_epub, cover_path, trim_size, status, created_at, content, cover_design")
      .eq("owner_id", req.user.id)
      .order("created_at", { ascending: false });
    if (error) throw error;
    return res.json({ books: data || [] });
  } catch (error) { next(error); }
});

app.get("/api/bizbook/books/:id/download", requireAuth, async function (req, res, next) {
  try {
    const { data: book, error } = await supabase
      .from("bizbooks")
      .select("*")
      .eq("id", req.params.id)
      .maybeSingle();
    if (error) throw error;
    if (!book) return res.status(404).json({ error: "Book not found" });

    // ── Entitlement check ──────────────────────────────────────────────
    // Today: only the owner may download. Extension point for later:
    // also allow requesters who hold a valid marketplace purchase/order
    // for this book (e.g. look up a future book-purchase table here and
    // OR it into `isAuthorized`).
    const isAuthorized = book.owner_id === req.user.id;
    if (!isAuthorized) {
      return res.status(403).json({ error: "You do not have access to this book" });
    }
    // ─────────────────────────────────────────────────────────────────────

    var format = (req.query.format === "epub") ? "epub" : "pdf";

    if (format === "epub") {
      if (!book.storage_path_epub) {
        return res.status(404).json({ error: "No EPUB available for this book. Regenerate it to get an EPUB version." });
      }

      const { data: signedEpub, error: signEpubError } = await supabase.storage
        .from("bf-books")
        .createSignedUrl(book.storage_path_epub, 60);
      if (signEpubError || !signedEpub || !signedEpub.signedUrl) {
        console.error("[bizbook] Failed to create signed EPUB download URL:", signEpubError && (signEpubError.message || signEpubError));
        return res.status(500).json({ error: "Failed to generate download link" });
      }

      return res.status(200).json({ url: signedEpub.signedUrl, expires_in: 60, title: book.title });
    }

    const { data: signed, error: signError } = await supabase.storage
      .from("bf-books")
      .createSignedUrl(book.storage_path, 60);
    if (signError || !signed || !signed.signedUrl) {
      console.error("[bizbook] Failed to create signed download URL:", signError && (signError.message || signError));
      return res.status(500).json({ error: "Failed to generate download link" });
    }

    return res.status(200).json({ url: signed.signedUrl, expires_in: 60, title: book.title });
  } catch (error) { next(error); }
});

app.get("/api/bizbook/books/:id/cover", requireAuth, async function (req, res, next) {
  try {
    const { data: book, error } = await supabase
      .from("bizbooks")
      .select("*")
      .eq("id", req.params.id)
      .maybeSingle();
    if (error) throw error;
    if (!book) return res.status(404).json({ error: "Book not found" });

    // ── Entitlement check ──────────────────────────────────────────────
    // Today: only the owner may view the cover. Extension point for later:
    // also allow requesters who hold a valid marketplace purchase/order
    // for this book (e.g. look up a future book-purchase table here and
    // OR it into `isAuthorized`).
    const isAuthorized = book.owner_id === req.user.id;
    if (!isAuthorized) {
      return res.status(403).json({ error: "Not authorized" });
    }
    // ─────────────────────────────────────────────────────────────────────

    if (!book.cover_path) {
      return res.status(404).json({ error: "No cover for this book." });
    }

    const { data: signedCover, error: signCoverError } = await supabase.storage
      .from("bf-books")
      .createSignedUrl(book.cover_path, 60);
    if (signCoverError || !signedCover || !signedCover.signedUrl) {
      console.error("[bizbook] Failed to create signed cover URL:", signCoverError && (signCoverError.message || signCoverError));
      return res.status(500).json({ error: "Failed to generate cover link" });
    }

    return res.status(200).json({ url: signedCover.signedUrl, expires_in: 60 });
  } catch (error) { next(error); }
});

app.post("/api/bizbook/books/:id/cover", requireAuth, oracleUpload.single("cover"), async function (req, res, next) {
  try {
    var coverFile = req.file || null;
    if (!coverFile) {
      return res.status(400).json({ error: "No cover image uploaded." });
    }

    const { data: book, error } = await supabase
      .from("bizbooks")
      .select("*")
      .eq("id", req.params.id)
      .maybeSingle();
    if (error) throw error;
    if (!book) return res.status(404).json({ error: "Book not found" });

    const isAuthorized = book.owner_id === req.user.id;
    if (!isAuthorized) {
      return res.status(403).json({ error: "Not authorized" });
    }

    var safeFileName = String(book.title || "").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 60) || "book";

    var COVER_EXT_BY_MIME = { "image/png": "png", "image/jpeg": "jpg", "image/webp": "webp", "image/gif": "gif" };
    var coverExt = (coverFile.originalname && coverFile.originalname.includes("."))
      ? coverFile.originalname.split(".").pop()
      : (COVER_EXT_BY_MIME[coverFile.mimetype] || "png");

    var newCoverPath = req.user.id + "/" + Date.now() + "_" + safeFileName + "_cover." + coverExt;

    var coverUploadResult = await supabase.storage
      .from("bf-books")
      .upload(newCoverPath, coverFile.buffer, { contentType: coverFile.mimetype, upsert: false });
    if (coverUploadResult.error) {
      console.error("[bizbook] cover upload failed:", coverUploadResult.error.message || coverUploadResult.error);
      return res.status(500).json({ error: "Failed to upload cover" });
    }

    const { error: updateError } = await supabase
      .from("bizbooks")
      .update({ cover_path: newCoverPath, updated_at: new Date().toISOString() })
      .eq("id", req.params.id);
    if (updateError) {
      console.error("[bizbook] Failed to save new cover_path:", updateError.message || updateError);
      return res.status(500).json({ error: "Failed to save cover" });
    }

    if (book.cover_path && book.cover_path !== newCoverPath) {
      try {
        await supabase.storage.from("bf-books").remove([book.cover_path]);
      } catch (cleanupErr) {
        console.error("[bizbook] Failed to remove old cover (non-fatal):", cleanupErr.message || cleanupErr);
      }
    }

    return res.status(200).json({ ok: true, cover_path: newCoverPath });
  } catch (error) { next(error); }
});

// Attaches a saved cover_wrap's already-stored front image to a book's
// cover_path directly — no re-upload. The front image is whichever of
// front_design.regions.front.bgImage (a front-region-specific override) or
// front_design.bgImage (the flat whole-wrap base) is set, preferring the
// region override since it's the more specific asset. Since cover_path is
// just a bf-books storage path (see the upload route above), pointing it
// at an existing path makes it resolve/display identically to an uploaded
// cover — no change needed anywhere else.
// Deliberately does NOT delete the book's previous cover_path (unlike the
// upload route): that file may itself be a wrap's shared background image
// rather than a book-exclusive upload, and deleting it here could destroy
// a cover_wraps row's own asset out from under it.
// bizbooks has no cover_wrap_id column (checked server.js + every
// supabase/migrations/*.sql — no matches) and this task explicitly excludes
// a migration, so the wrap linkage isn't persisted; wrapLinked:false tells
// the frontend to keep wrapId itself (already has it) for the print flow
// via the existing POST /api/cover-wraps/:id/export-pdf route.
app.post("/api/bizbook/books/:id/cover-from-wrap", requireAuth, async function (req, res, next) {
  try {
    var wrapId = req.body && req.body.wrapId;
    if (!wrapId || typeof wrapId !== "string") {
      return res.status(400).json({ error: "wrapId is required" });
    }

    const { data: book, error: bookError } = await supabase
      .from("bizbooks")
      .select("*")
      .eq("id", req.params.id)
      .maybeSingle();
    if (bookError) throw bookError;
    if (!book) return res.status(404).json({ error: "Book not found" });
    if (book.owner_id !== req.user.id) {
      return res.status(403).json({ error: "Not authorized" });
    }

    const { data: wrap, error: wrapError } = await supabase
      .from("cover_wraps")
      .select("*")
      .eq("id", wrapId)
      .maybeSingle();
    if (wrapError) throw wrapError;
    if (!wrap) return res.status(404).json({ error: "Cover wrap not found" });
    if (wrap.owner_id !== req.user.id) {
      return res.status(403).json({ error: "Not authorized" });
    }

    var frontDesign = wrap.front_design || {};
    var frontPath = (frontDesign.regions && frontDesign.regions.front && frontDesign.regions.front.bgImage) || frontDesign.bgImage || null;

    if (!frontPath || typeof frontPath !== "string" || frontPath.indexOf("blob:") === 0 || frontPath.indexOf("http://") === 0 || frontPath.indexOf("https://") === 0) {
      return res.status(400).json({ error: "This cover has no front image to use — add a background image to the cover first." });
    }

    const { data: updatedBook, error: updateError } = await supabase
      .from("bizbooks")
      .update({ cover_path: frontPath, updated_at: new Date().toISOString() })
      .eq("id", req.params.id)
      .select("*")
      .single();
    if (updateError) {
      console.error("[bizbook] Failed to attach cover from wrap:", updateError.message || updateError);
      return res.status(500).json({ error: "Failed to attach cover" });
    }

    return res.status(200).json({ ok: true, book: updatedBook, wrapId: wrapId, wrapLinked: false });
  } catch (error) { next(error); }
});

app.put("/api/bizbook/books/:id", requireAuth, async function (req, res, next) {
  try {
    const { data: book, error } = await supabase
      .from("bizbooks")
      .select("*")
      .eq("id", req.params.id)
      .maybeSingle();
    if (error) throw error;
    if (!book) return res.status(404).json({ error: "Book not found" });

    const isAuthorized = book.owner_id === req.user.id;
    if (!isAuthorized) {
      return res.status(403).json({ error: "Not authorized" });
    }

    var content = (req.body.content === undefined || req.body.content === null) ? "" : req.body.content;

    const { error: updateError } = await supabase
      .from("bizbooks")
      .update({ content: content, updated_at: new Date().toISOString() })
      .eq("id", req.params.id);
    if (updateError) {
      return res.status(500).json({ error: "Failed to save book: " + updateError.message });
    }

    return res.status(200).json({ ok: true });
  } catch (error) { next(error); }
});

app.put("/api/bizbook/books/:id/cover-design", requireAuth, async function (req, res, next) {
  try {
    const { data: book, error } = await supabase
      .from("bizbooks")
      .select("*")
      .eq("id", req.params.id)
      .maybeSingle();
    if (error) throw error;
    if (!book) return res.status(404).json({ error: "Book not found" });

    const isAuthorized = book.owner_id === req.user.id;
    if (!isAuthorized) {
      return res.status(403).json({ error: "Not authorized" });
    }

    if (req.body.cover_design === undefined || req.body.cover_design === null) {
      return res.status(400).json({ error: "Missing cover_design" });
    }

    var coverDesign = req.body.cover_design;
    if (typeof coverDesign === "string") {
      try {
        coverDesign = JSON.parse(coverDesign);
      } catch (parseErr) {
        return res.status(400).json({ error: "Invalid cover_design" });
      }
    }

    if (JSON.stringify(coverDesign).length > 200 * 1024) {
      return res.status(413).json({ error: "Cover design too large" });
    }

    const { error: updateError } = await supabase
      .from("bizbooks")
      .update({ cover_design: coverDesign, updated_at: new Date().toISOString() })
      .eq("id", req.params.id);
    if (updateError) {
      return res.status(500).json({ error: "Failed to save cover design: " + updateError.message });
    }

    return res.status(200).json({ ok: true });
  } catch (error) { next(error); }
});

app.post("/api/bizbook/books/:id/generate-from-content", requireAuth, async function (req, res, next) {
  try {
    const { data: book, error } = await supabase
      .from("bizbooks")
      .select("*")
      .eq("id", req.params.id)
      .maybeSingle();
    if (error) throw error;
    if (!book) return res.status(404).json({ error: "Book not found" });

    const isAuthorized = book.owner_id === req.user.id;
    if (!isAuthorized) {
      return res.status(403).json({ error: "Not authorized" });
    }

    var plainContent = String(book.content || "").replace(/<[^>]+>/g, "").trim();
    if (!plainContent) {
      return res.status(400).json({ error: "This book has no content to generate from. Write something in the editor first." });
    }

    var chapters = htmlToChapters(book.content);

    var title = book.title || "Untitled";
    var author = book.author || "";
    var trimSize = (book.trim_size && TRIM_SIZES[book.trim_size]) ? book.trim_size : "6x9";

    var safeFileName = title.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 60) || "book";

    var pdfResult = await generateBookPdf("", { title: title, author: author, trimSize: trimSize, chapters: chapters });
    var pdfBuffer = pdfResult.buffer;
    var pageCount = (pdfResult && typeof pdfResult.pageCount === "number") ? pdfResult.pageCount : null;
    var storagePath = req.user.id + "/" + Date.now() + "_" + safeFileName + ".pdf";

    var uploadResult = await supabase.storage
      .from("bf-books")
      .upload(storagePath, pdfBuffer, { contentType: "application/pdf", upsert: false });
    if (uploadResult.error) {
      console.error("[bizbook] generate-from-content PDF upload failed:", uploadResult.error.message || uploadResult.error);
      return res.status(500).json({ error: "Failed to store generated book: " + uploadResult.error.message });
    }

    var epubStoragePath = null;
    try {
      var epubBuffer = await generateBookEpub("", { title: title, author: author, chapters: chapters });
      var epubPath = req.user.id + "/" + Date.now() + "_" + safeFileName + ".epub";
      var epubUploadResult = await supabase.storage
        .from("bf-books")
        .upload(epubPath, epubBuffer, { contentType: "application/epub+zip", upsert: false });
      if (epubUploadResult.error) {
        console.error("[bizbook] generate-from-content EPUB upload failed:", epubUploadResult.error.message || epubUploadResult.error);
      } else {
        epubStoragePath = epubPath;
      }
    } catch (epubErr) {
      console.error("[bizbook] generate-from-content EPUB generation failed:", epubErr.message || epubErr);
    }

    var updatePayload = { storage_path: storagePath, status: "ready", updated_at: new Date().toISOString() };
    if (epubStoragePath) updatePayload.storage_path_epub = epubStoragePath;
    updatePayload.page_count = pageCount;

    const { error: updateError } = await supabase
      .from("bizbooks")
      .update(updatePayload)
      .eq("id", req.params.id);
    if (updateError) {
      return res.status(500).json({ error: "Failed to save generated book: " + updateError.message });
    }

    return res.status(200).json({ ok: true, storage_path: storagePath, has_epub: !!epubStoragePath });
  } catch (error) { next(error); }
});

// Creates a new bizbooks row directly from editor HTML (no manuscript file
// upload) — the Layer 3 template/draft-start flow. Mirrors generate-from-
// content's chapter-parsing + PDF/EPUB generation, but INSERTs a fresh row
// instead of updating one. Empty starter content is valid (a blank/template
// start with nothing written yet) — the row is created either way; PDF/EPUB
// generation only runs when there's real content, and a generation failure
// never fails the request since the row (with content) already exists and
// can be regenerated later via generate-from-content.
app.post("/api/bizbook/books/create-from-content", requireAuth, async function (req, res, next) {
  try {
    var title = safeText(req.body.title, 200);
    if (!title) {
      return res.status(400).json({ error: "Book title is required" });
    }
    var author = safeText(req.body.author, 150) || "";
    var requestedTrim = req.body.trimSize || req.body.trim_size;
    var trimSize = (requestedTrim && TRIM_SIZES[requestedTrim]) ? requestedTrim : "letter";
    var content = (req.body.content === undefined || req.body.content === null) ? "" : String(req.body.content);

    // "draft" is a new status value for bizbooks (existing rows only ever
    // use "ready") — chosen because it's not "ready", so the frontend's
    // status-badge logic (added for the color-coded card badge) renders it
    // as the gold "pending" state until generation actually succeeds.
    var { data: book, error: insertError } = await supabase
      .from("bizbooks")
      .insert({
        owner_id: req.user.id, title: title, author: author, content: content,
        trim_size: trimSize, status: "draft", storage_path: "",
        created_at: nowIso(), updated_at: nowIso()
      })
      .select("*").single();
    if (insertError) {
      return res.status(500).json({ error: "Failed to create book: " + insertError.message });
    }

    var plainContent = content.replace(/<[^>]+>/g, "").trim();
    if (!plainContent) {
      return res.status(200).json({ book: book });
    }

    try {
      var chapters = htmlToChapters(content);
      var safeFileName = title.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 60) || "book";

      var pdfResult = await generateBookPdf("", { title: title, author: author, trimSize: trimSize, chapters: chapters });
      var pdfBuffer = pdfResult.buffer;
      var pageCount = (pdfResult && typeof pdfResult.pageCount === "number") ? pdfResult.pageCount : null;
      var storagePath = req.user.id + "/" + Date.now() + "_" + safeFileName + ".pdf";

      var uploadResult = await supabase.storage
        .from("bf-books")
        .upload(storagePath, pdfBuffer, { contentType: "application/pdf", upsert: false });
      if (uploadResult.error) {
        console.error("[bizbook] create-from-content PDF upload failed:", uploadResult.error.message || uploadResult.error);
        return res.status(200).json({ book: book });
      }

      var epubStoragePath = null;
      try {
        var epubBuffer = await generateBookEpub("", { title: title, author: author, chapters: chapters });
        var epubPath = req.user.id + "/" + Date.now() + "_" + safeFileName + ".epub";
        var epubUploadResult = await supabase.storage
          .from("bf-books")
          .upload(epubPath, epubBuffer, { contentType: "application/epub+zip", upsert: false });
        if (epubUploadResult.error) {
          console.error("[bizbook] create-from-content EPUB upload failed:", epubUploadResult.error.message || epubUploadResult.error);
        } else {
          epubStoragePath = epubPath;
        }
      } catch (epubErr) {
        console.error("[bizbook] create-from-content EPUB generation failed:", epubErr.message || epubErr);
      }

      var updatePayload = { storage_path: storagePath, status: "ready", page_count: pageCount, updated_at: new Date().toISOString() };
      if (epubStoragePath) updatePayload.storage_path_epub = epubStoragePath;

      var { data: updatedBook, error: updateError } = await supabase
        .from("bizbooks")
        .update(updatePayload)
        .eq("id", book.id)
        .select("*").single();
      if (updateError) {
        console.error("[bizbook] create-from-content failed to save generated book:", updateError.message || updateError);
        return res.status(200).json({ book: book });
      }

      return res.status(200).json({ book: updatedBook });
    } catch (genErr) {
      console.error("[bizbook] create-from-content generation failed:", genErr.message || genErr);
      return res.status(200).json({ book: book });
    }
  } catch (error) { next(error); }
});

app.delete("/api/bizbook/books/:id", requireAuth, async function (req, res, next) {
  try {
    const { data: book, error } = await supabase
      .from("bizbooks")
      .select("*")
      .eq("id", req.params.id)
      .maybeSingle();
    if (error) throw error;
    if (!book) return res.status(404).json({ error: "Book not found" });

    const isAuthorized = book.owner_id === req.user.id;
    if (!isAuthorized) {
      return res.status(403).json({ error: "Not authorized" });
    }

    try {
      var pathsToRemove = [book.storage_path];
      if (book.storage_path_epub) pathsToRemove.push(book.storage_path_epub);
      if (book.cover_path) pathsToRemove.push(book.cover_path);
      await supabase.storage.from("bf-books").remove(pathsToRemove);
    } catch (cleanupErr) {
      console.log("[bizbook] delete cleanup failed:", cleanupErr.message || cleanupErr);
    }

    const { error: deleteError } = await supabase
      .from("bizbooks")
      .delete()
      .eq("id", req.params.id);
    if (deleteError) {
      return res.status(500).json({ error: "Failed to delete book: " + deleteError.message });
    }

    return res.status(200).json({ ok: true });
  } catch (error) { next(error); }
});

/* ── Cover Wraps (standalone reusable book-cover-wrap designs) ── */

function coverWrapValidateDesignField(value, fieldName) {
  // Returns { ok: true, value } or { ok: false, status, error }.
  if (value === undefined) return { ok: true, value: undefined };
  var parsed = value;
  if (typeof parsed === "string") {
    try {
      parsed = JSON.parse(parsed);
    } catch (parseErr) {
      return { ok: false, status: 400, error: "Invalid " + fieldName };
    }
  }
  if (JSON.stringify(parsed).length > 200 * 1024) {
    return { ok: false, status: 413, error: "Design too large" };
  }
  return { ok: true, value: parsed };
}

app.get("/api/cover-wraps", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("cover_wraps")
      .select("id, name, trim_size, page_count, paper_stock, front_design, created_at, updated_at")
      .eq("owner_id", req.user.id)
      .order("updated_at", { ascending: false });
    if (error) throw error;
    return res.json({ wraps: data || [] });
  } catch (error) { next(error); }
});

app.post("/api/cover-wraps", requireAuth, async function (req, res, next) {
  try {
    var name = safeText(req.body.name, 150) || "Untitled Cover";
    var trimSize = (req.body.trim_size && TRIM_SIZES[req.body.trim_size]) ? req.body.trim_size : "6x9";
    var paperStock = safeText(req.body.paper_stock, 60) || "white";
    var pageCount = (Number.isInteger(req.body.page_count)) ? req.body.page_count : null;

    var frontResult = coverWrapValidateDesignField(req.body.front_design, "front_design");
    if (!frontResult.ok) return res.status(frontResult.status).json({ error: frontResult.error });
    var spineResult = coverWrapValidateDesignField(req.body.spine_design, "spine_design");
    if (!spineResult.ok) return res.status(spineResult.status).json({ error: spineResult.error });
    var backResult = coverWrapValidateDesignField(req.body.back_design, "back_design");
    if (!backResult.ok) return res.status(backResult.status).json({ error: backResult.error });

    const { data, error } = await supabase
      .from("cover_wraps")
      .insert({
        owner_id: req.user.id, name, trim_size: trimSize, paper_stock: paperStock, page_count: pageCount,
        front_design: frontResult.value !== undefined ? frontResult.value : null,
        spine_design: spineResult.value !== undefined ? spineResult.value : null,
        back_design: backResult.value !== undefined ? backResult.value : null,
        created_at: nowIso(), updated_at: nowIso()
      })
      .select("*").single();
    if (error) throw error;
    return res.status(201).json({ wrap: data });
  } catch (error) { next(error); }
});

app.get("/api/cover-wraps/:id", requireAuth, async function (req, res, next) {
  try {
    const { data: wrap, error } = await supabase
      .from("cover_wraps")
      .select("*")
      .eq("id", req.params.id)
      .maybeSingle();
    if (error) throw error;
    if (!wrap) return res.status(404).json({ error: "Cover wrap not found" });

    const isAuthorized = wrap.owner_id === req.user.id;
    if (!isAuthorized) {
      return res.status(403).json({ error: "Not authorized" });
    }

    return res.json({ wrap: wrap });
  } catch (error) { next(error); }
});

app.put("/api/cover-wraps/:id", requireAuth, async function (req, res, next) {
  try {
    const { data: wrap, error } = await supabase
      .from("cover_wraps")
      .select("*")
      .eq("id", req.params.id)
      .maybeSingle();
    if (error) throw error;
    if (!wrap) return res.status(404).json({ error: "Cover wrap not found" });

    const isAuthorized = wrap.owner_id === req.user.id;
    if (!isAuthorized) {
      return res.status(403).json({ error: "Not authorized" });
    }

    var payload = { updated_at: new Date().toISOString() };

    if (req.body.name !== undefined) payload.name = safeText(req.body.name, 150) || "Untitled Cover";
    if (req.body.trim_size !== undefined) {
      payload.trim_size = (req.body.trim_size && TRIM_SIZES[req.body.trim_size]) ? req.body.trim_size : "6x9";
    }
    if (req.body.page_count !== undefined) {
      payload.page_count = Number.isInteger(req.body.page_count) ? req.body.page_count : null;
    }
    if (req.body.paper_stock !== undefined) payload.paper_stock = safeText(req.body.paper_stock, 60) || "white";

    var frontResult = coverWrapValidateDesignField(req.body.front_design, "front_design");
    if (!frontResult.ok) return res.status(frontResult.status).json({ error: frontResult.error });
    if (frontResult.value !== undefined) payload.front_design = frontResult.value;

    var spineResult = coverWrapValidateDesignField(req.body.spine_design, "spine_design");
    if (!spineResult.ok) return res.status(spineResult.status).json({ error: spineResult.error });
    if (spineResult.value !== undefined) payload.spine_design = spineResult.value;

    var backResult = coverWrapValidateDesignField(req.body.back_design, "back_design");
    if (!backResult.ok) return res.status(backResult.status).json({ error: backResult.error });
    if (backResult.value !== undefined) payload.back_design = backResult.value;

    const { error: updateError } = await supabase
      .from("cover_wraps")
      .update(payload)
      .eq("id", req.params.id);
    if (updateError) {
      return res.status(500).json({ error: "Failed to save cover wrap: " + updateError.message });
    }

    return res.json({ ok: true });
  } catch (error) { next(error); }
});

app.delete("/api/cover-wraps/:id", requireAuth, async function (req, res, next) {
  try {
    const { data: wrap, error } = await supabase
      .from("cover_wraps")
      .select("*")
      .eq("id", req.params.id)
      .maybeSingle();
    if (error) throw error;
    if (!wrap) return res.status(404).json({ error: "Cover wrap not found" });

    const isAuthorized = wrap.owner_id === req.user.id;
    if (!isAuthorized) {
      return res.status(403).json({ error: "Not authorized" });
    }

    // TODO: a wrap's design JSON may reference a background image uploaded
    // to bf-books storage; storage cleanup for that reference is a later
    // concern — deleting the row is enough for now.

    const { error: deleteError } = await supabase
      .from("cover_wraps")
      .delete()
      .eq("id", req.params.id);
    if (deleteError) {
      return res.status(500).json({ error: "Failed to delete cover wrap: " + deleteError.message });
    }

    return res.json({ ok: true });
  } catch (error) { next(error); }
});

app.post("/api/cover-wraps/:id/bg-image", requireAuth, oracleUpload.single("bg_image"), async function (req, res, next) {
  try {
    var bgFile = req.file || null;
    if (!bgFile) {
      return res.status(400).json({ error: "No image uploaded." });
    }

    const { data: wrap, error } = await supabase
      .from("cover_wraps")
      .select("*")
      .eq("id", req.params.id)
      .maybeSingle();
    if (error) throw error;
    if (!wrap) return res.status(404).json({ error: "Cover not found" });

    const isAuthorized = wrap.owner_id === req.user.id;
    if (!isAuthorized) {
      return res.status(403).json({ error: "Not authorized" });
    }

    var safeName = String(wrap.name || "").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 60) || "cover";
    var EXT_BY_MIME = { "image/png": "png", "image/jpeg": "jpg", "image/webp": "webp", "image/gif": "gif" };
    var ext = (bgFile.originalname && bgFile.originalname.includes("."))
      ? bgFile.originalname.split(".").pop()
      : (EXT_BY_MIME[bgFile.mimetype] || "png");
    var newPath = req.user.id + "/wrap_" + req.params.id + "_" + Date.now() + "_" + safeName + "." + ext;

    var uploadResult = await supabase.storage
      .from("bf-books")
      .upload(newPath, bgFile.buffer, { contentType: bgFile.mimetype, upsert: false });
    if (uploadResult.error) {
      console.error("[cover-wraps] bg-image upload failed:", uploadResult.error.message || uploadResult.error);
      return res.status(500).json({ error: "Failed to upload image" });
    }

    var oldBgImage = wrap.front_design && wrap.front_design.bgImage;
    if (typeof oldBgImage === "string" && oldBgImage.length > 0
        && !oldBgImage.startsWith("blob:") && !oldBgImage.startsWith("http")
        && oldBgImage !== newPath) {
      try {
        await supabase.storage.from("bf-books").remove([oldBgImage]);
      } catch (cleanupErr) {
        console.error("[cover-wraps] Failed to remove old bg-image (non-fatal):", cleanupErr.message || cleanupErr);
      }
    }

    return res.status(200).json({ ok: true, path: newPath });
  } catch (error) { next(error); }
});

app.get("/api/cover-wraps/:id/bg-image", requireAuth, async function (req, res, next) {
  try {
    const { data: wrap, error } = await supabase
      .from("cover_wraps")
      .select("*")
      .eq("id", req.params.id)
      .maybeSingle();
    if (error) throw error;
    if (!wrap) return res.status(404).json({ error: "Cover not found" });

    const isAuthorized = wrap.owner_id === req.user.id;
    if (!isAuthorized) {
      return res.status(403).json({ error: "Not authorized" });
    }

    var bgPath = wrap.front_design && wrap.front_design.bgImage;
    if (!bgPath || typeof bgPath !== "string" || bgPath.startsWith("blob:") || bgPath.startsWith("http")) {
      return res.status(404).json({ error: "No background image for this cover." });
    }

    const { data: signedBg, error: signError } = await supabase.storage
      .from("bf-books")
      .createSignedUrl(bgPath, 60);
    if (signError || !signedBg || !signedBg.signedUrl) {
      console.error("[cover-wraps] Failed to create signed bg-image URL:", signError && (signError.message || signError));
      return res.status(500).json({ error: "Failed to generate image link" });
    }

    return res.status(200).json({ url: signedBg.signedUrl, expires_in: 60 });
  } catch (error) { next(error); }
});

app.get("/api/cover-wraps/:id/region-bg-image", requireAuth, async function (req, res, next) {
  try {
    const { data: wrap, error } = await supabase
      .from("cover_wraps")
      .select("*")
      .eq("id", req.params.id)
      .maybeSingle();
    if (error) throw error;
    if (!wrap) return res.status(404).json({ error: "Cover not found" });

    const isAuthorized = wrap.owner_id === req.user.id;
    if (!isAuthorized) {
      return res.status(403).json({ error: "Not authorized" });
    }

    var region = req.query.region;
    if (region !== "back" && region !== "spine" && region !== "front") {
      return res.status(400).json({ error: "Invalid region" });
    }

    var bgPath = wrap.front_design && wrap.front_design.regions && wrap.front_design.regions[region] && wrap.front_design.regions[region].bgImage;
    if (!bgPath || typeof bgPath !== "string" || bgPath.startsWith("blob:") || bgPath.startsWith("http")) {
      return res.status(404).json({ error: "No background image for this region." });
    }

    const { data: signedBg, error: signError } = await supabase.storage
      .from("bf-books")
      .createSignedUrl(bgPath, 60);
    if (signError || !signedBg || !signedBg.signedUrl) {
      console.error("[cover-wraps] Failed to create signed region bg-image URL:", signError && (signError.message || signError));
      return res.status(500).json({ error: "Failed to generate image link" });
    }

    return res.status(200).json({ url: signedBg.signedUrl, expires_in: 60 });
  } catch (error) { next(error); }
});

// Signed URL for one foreground image-layer image. Image layers are an
// arbitrary-length array (not fixed region names like region-bg-image), so
// the path is passed directly as a query param instead of a region key —
// which means it has to be validated as belonging to this owner AND to
// this specific wrap's design, not just trusted as-is.
app.get("/api/cover-wraps/:id/layer-image", requireAuth, async function (req, res, next) {
  try {
    const { data: wrap, error } = await supabase
      .from("cover_wraps")
      .select("*")
      .eq("id", req.params.id)
      .maybeSingle();
    if (error) throw error;
    if (!wrap) return res.status(404).json({ error: "Cover not found" });

    const isAuthorized = wrap.owner_id === req.user.id;
    if (!isAuthorized) {
      return res.status(403).json({ error: "Not authorized" });
    }

    var imagePath = req.query.path;
    if (!imagePath || typeof imagePath !== "string" || imagePath.startsWith("blob:") || imagePath.startsWith("http")
        || imagePath.indexOf(req.user.id + "/") !== 0) {
      return res.status(400).json({ error: "Invalid path" });
    }

    var imageLayers = (wrap.front_design && Array.isArray(wrap.front_design.imageLayers)) ? wrap.front_design.imageLayers : [];
    var belongsToDesign = imageLayers.some(function (layer) { return layer && layer.src === imagePath; });
    if (!belongsToDesign) {
      return res.status(404).json({ error: "Image not found in this cover." });
    }

    const { data: signedLayer, error: signError } = await supabase.storage
      .from("bf-books")
      .createSignedUrl(imagePath, 60);
    if (signError || !signedLayer || !signedLayer.signedUrl) {
      console.error("[cover-wraps] Failed to create signed layer-image URL:", signError && (signError.message || signError));
      return res.status(500).json({ error: "Failed to generate image link" });
    }

    return res.status(200).json({ url: signedLayer.signedUrl, expires_in: 60 });
  } catch (error) { next(error); }
});

app.post("/api/cover-wraps/:id/export-pdf", requireAuth, async function (req, res, next) {
  try {
    const { data: wrap, error } = await supabase
      .from("cover_wraps")
      .select("*")
      .eq("id", req.params.id)
      .maybeSingle();
    if (error) throw error;
    if (!wrap) return res.status(404).json({ error: "Cover wrap not found" });

    const isAuthorized = wrap.owner_id === req.user.id;
    if (!isAuthorized) {
      return res.status(403).json({ error: "Not authorized" });
    }

    var design = wrap.front_design;
    if (typeof design === "string") {
      try { design = JSON.parse(design); } catch (parseErr) { design = null; }
    }
    if (!design || typeof design !== "object") {
      return res.status(400).json({ error: "No design to export" });
    }

    var bgImageBuffer = null;
    if (design.bgImage && typeof design.bgImage === "string" && !design.bgImage.startsWith("blob:") && !design.bgImage.startsWith("http")) {
      try {
        const { data: blob, error: dlErr } = await supabase.storage.from("bf-books").download(design.bgImage);
        if (!dlErr && blob) bgImageBuffer = Buffer.from(await blob.arrayBuffer());
      } catch (bgErr) {
        console.warn("[cover-wraps] Failed to load background image for export:", bgErr && (bgErr.message || bgErr));
      }
    }

    const pdf = await generateCoverWrapPdf(design, {
      trimKey: wrap.trim_size,
      pageCount: wrap.page_count || 0,
      paperStock: wrap.paper_stock || "white",
      name: wrap.name,
      bgImageBuffer: bgImageBuffer
    });

    var safeFileName = (wrap.name || "cover").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 60) || "cover";

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", "attachment; filename=\"" + safeFileName + "-print.pdf\"");
    res.setHeader("Content-Length", pdf.length);
    res.end(pdf);
  } catch (error) { next(error); }
});

/* ── Editor inline images (Biz-EBook / BizDoc rich-text editor) ──
   Generic image storage for images inserted directly into editor content —
   not tied to a specific book/document id, since one editor session can
   insert many images and an image can conceptually be reused. Mirrors the
   cover-wraps bg-image upload + layer-image signed-URL resolve pattern. */

app.post("/api/editor/image", requireAuth, oracleUpload.single("image"), async function (req, res, next) {
  try {
    var imgFile = req.file || null;
    if (!imgFile) {
      return res.status(400).json({ error: "No image uploaded." });
    }

    var EDITOR_IMAGE_EXT_BY_MIME = { "image/png": "png", "image/jpeg": "jpg", "image/webp": "webp", "image/gif": "gif" };
    if (!EDITOR_IMAGE_EXT_BY_MIME[imgFile.mimetype]) {
      return res.status(400).json({ error: "Unsupported image type: " + imgFile.mimetype });
    }

    var ext = (imgFile.originalname && imgFile.originalname.includes("."))
      ? imgFile.originalname.split(".").pop()
      : EDITOR_IMAGE_EXT_BY_MIME[imgFile.mimetype];
    var newPath = req.user.id + "/editorimg_" + Date.now() + "_" + Math.floor(Math.random() * 100000) + "." + ext;

    var uploadResult = await supabase.storage
      .from("bf-books")
      .upload(newPath, imgFile.buffer, { contentType: imgFile.mimetype, upsert: false });
    if (uploadResult.error) {
      console.error("[editor] image upload failed:", uploadResult.error.message || uploadResult.error);
      return res.status(500).json({ error: "Failed to upload image" });
    }

    return res.status(200).json({ ok: true, path: newPath });
  } catch (error) { next(error); }
});

app.get("/api/editor/image", requireAuth, async function (req, res, next) {
  try {
    // Not tied to a specific book/document, so there's no design/content to
    // cross-check membership against like the cover layer-image route does
    // — the owner-id path prefix IS the whole security boundary here. Every
    // upload above is stored under req.user.id + "/", so a path outside
    // that prefix can never belong to the requesting user.
    var imagePath = req.query.path;
    if (!imagePath || typeof imagePath !== "string" || imagePath.startsWith("blob:") || imagePath.startsWith("http")
        || imagePath.indexOf(req.user.id + "/") !== 0) {
      return res.status(400).json({ error: "Invalid path" });
    }

    const { data: signedImage, error: signError } = await supabase.storage
      .from("bf-books")
      .createSignedUrl(imagePath, 60);
    if (signError || !signedImage || !signedImage.signedUrl) {
      console.error("[editor] Failed to create signed image URL:", signError && (signError.message || signError));
      return res.status(500).json({ error: "Failed to generate image link" });
    }

    return res.status(200).json({ url: signedImage.signedUrl, expires_in: 60 });
  } catch (error) { next(error); }
});

/* ── Digital Cards ── */

const CARD_THEMES = ["dark","midnight","forest","ember"];

app.get("/api/digital-cards", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("digital_cards")
      .select("*")
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: false });
    if (error) throw error;
    return res.json({ cards: data || [] });
  } catch (error) { next(error); }
});

app.post("/api/digital-cards", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("digital_cards")
      .insert({
        user_id:   req.user.id,
        full_name: safeText(req.body.full_name, 120) || "",
        job_title: safeText(req.body.job_title, 120) || "",
        email:     normalizeEmail(req.body.email)    || "",
        phone:     safeText(req.body.phone, 40)      || "",
        company:   safeText(req.body.company, 120)   || "",
        website:   normalizeUrl(req.body.website)    || "",
        theme:     CARD_THEMES.includes(req.body.theme) ? req.body.theme : "dark",
        video_url:        safeText(req.body.video_url, 500) || null,
        bg_image_url:     safeText(req.body.bg_image_url, 500) || null,
        still_image_url:  safeText(req.body.still_image_url, 500) || null,
        audio_url:        safeText(req.body.audio_url, 500) || null,
        holographic_style: Boolean(req.body.holographic_style) || false,
        media_layout: req.body.media_layout || {},
        share_token: crypto.randomBytes(16).toString("hex"),
        created_at: nowIso(), updated_at: nowIso()
      })
      .select("*").single();
    if (error) {
      console.error("[digital-cards POST] Supabase error:", {
        code: error.code, message: error.message,
        details: error.details, hint: error.hint
      });
      return res.status(500).json({
        error: "Save failed",
        db_code: error.code,
        db_message: error.message,
        db_hint: error.hint || error.details || null
      });
    }
    return res.status(201).json({ card: data });
  } catch (error) { next(error); }
});

app.put("/api/digital-cards/:id", requireAuth, async function (req, res, next) {
  try {
    const updates = { updated_at: nowIso() };
    if (req.body.full_name !== undefined) updates.full_name = safeText(req.body.full_name, 120) || "";
    if (req.body.job_title !== undefined) updates.job_title = safeText(req.body.job_title, 120) || "";
    if (req.body.email     !== undefined) updates.email     = normalizeEmail(req.body.email)    || "";
    if (req.body.phone     !== undefined) updates.phone     = safeText(req.body.phone, 40)      || "";
    if (req.body.company   !== undefined) updates.company   = safeText(req.body.company, 120)   || "";
    if (req.body.website   !== undefined) updates.website   = normalizeUrl(req.body.website)    || "";
    if (req.body.theme     !== undefined && CARD_THEMES.includes(req.body.theme)) updates.theme = req.body.theme;
    if (req.body.video_url      !== undefined) updates.video_url      = safeText(req.body.video_url, 500)      || null;
    if (req.body.bg_image_url   !== undefined) updates.bg_image_url   = safeText(req.body.bg_image_url, 500)   || null;
    if (req.body.still_image_url !== undefined) updates.still_image_url = safeText(req.body.still_image_url, 500) || null;
    if (req.body.audio_url       !== undefined) updates.audio_url       = safeText(req.body.audio_url, 500)       || null;
    if (req.body.holographic_style !== undefined) updates.holographic_style = Boolean(req.body.holographic_style);
    if (req.body.media_layout !== undefined) updates.media_layout = req.body.media_layout || {};
    const { data, error } = await supabase
      .from("digital_cards")
      .update(updates)
      .eq("id", req.params.id)
      .eq("user_id", req.user.id)
      .select("*").single();
    if (error) {
      console.error("[digital-cards PUT] Supabase error:", {
        code: error.code, message: error.message,
        details: error.details, hint: error.hint
      });
      return res.status(500).json({
        error: "Save failed",
        db_code: error.code,
        db_message: error.message,
        db_hint: error.hint || error.details || null
      });
    }
    return res.json({ card: data });
  } catch (error) { next(error); }
});

app.delete("/api/digital-cards/:id", requireAuth, async function (req, res, next) {
  try {
    const { error } = await supabase
      .from("digital_cards")
      .delete()
      .eq("id", req.params.id)
      .eq("user_id", req.user.id);
    if (error) throw error;
    return res.json({ success: true });
  } catch (error) { next(error); }
});

// Returns (and lazily generates) a share token for the user's card
app.post("/api/cards/share-token", requireAuth, async function (req, res, next) {
  try {
    const cardId = req.body.card_id;
    if (!cardId) return res.status(400).json({ error: "card_id required" });
    const { data: card, error: fetchErr } = await supabase
      .from("digital_cards")
      .select("id, share_token")
      .eq("id", cardId)
      .eq("user_id", req.user.id)
      .maybeSingle();
    if (fetchErr) throw fetchErr;
    if (!card) return res.status(404).json({ error: "Card not found" });
    if (card.share_token) return res.json({ share_token: card.share_token });
    const share_token = crypto.randomBytes(16).toString("hex");
    const { error: upErr } = await supabase
      .from("digital_cards")
      .update({ share_token, updated_at: nowIso() })
      .eq("id", cardId)
      .eq("user_id", req.user.id);
    if (upErr) throw upErr;
    return res.json({ share_token });
  } catch (error) { next(error); }
});

// Public — no auth — returns card by share token
app.get("/api/cards/share/:token", async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("digital_cards")
      .select("full_name, job_title, company, email, phone, website, theme, video_url, bg_image_url, still_image_url, audio_url, holographic_style, media_layout")
      .eq("share_token", req.params.token)
      .maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: "Card not found" });
    return res.json({ card: data });
  } catch (error) { next(error); }
});

/* ── Flyer Generator ── */

const FLYER_TEMPLATES = ["professional","bold","minimal"];
const FLYER_COLORS    = ["neon","crimson","jade","gold"];

app.get("/api/flyers", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("saved_flyers")
      .select("id, name, template, color_theme, content, updated_at")
      .eq("user_id", req.user.id)
      .order("updated_at", { ascending: false })
      .limit(50);
    if (error) throw error;
    return res.json({ flyers: data || [] });
  } catch (error) { next(error); }
});

app.post("/api/flyers", requireAuth, async function (req, res, next) {
  try {
    const name      = safeText(req.body.name, 120) || "Untitled Flyer";
    const template  = FLYER_TEMPLATES.includes(req.body.template)    ? req.body.template    : "professional";
    const colorTheme = FLYER_COLORS.includes(req.body.color_theme)   ? req.body.color_theme : "neon";
    const content   = (req.body.content && typeof req.body.content === "object" && !Array.isArray(req.body.content))
      ? req.body.content : {};
    const { data, error } = await supabase
      .from("saved_flyers")
      .insert({ user_id: req.user.id, name, template, color_theme: colorTheme, content, created_at: nowIso(), updated_at: nowIso() })
      .select("*").single();
    if (error) throw error;
    return res.status(201).json({ flyer: data });
  } catch (error) { next(error); }
});

app.put("/api/flyers/:id", requireAuth, async function (req, res, next) {
  try {
    const updates = { updated_at: nowIso() };
    if (req.body.name        !== undefined) updates.name        = safeText(req.body.name, 120) || "Untitled Flyer";
    if (req.body.template    !== undefined && FLYER_TEMPLATES.includes(req.body.template))    updates.template    = req.body.template;
    if (req.body.color_theme !== undefined && FLYER_COLORS.includes(req.body.color_theme))    updates.color_theme = req.body.color_theme;
    if (req.body.content     !== undefined && typeof req.body.content === "object" && !Array.isArray(req.body.content)) updates.content = req.body.content;
    const { data, error } = await supabase
      .from("saved_flyers")
      .update(updates)
      .eq("id", req.params.id)
      .eq("user_id", req.user.id)
      .select("*").single();
    if (error) throw error;
    return res.json({ flyer: data });
  } catch (error) { next(error); }
});

app.delete("/api/flyers/:id", requireAuth, async function (req, res, next) {
  try {
    const { error } = await supabase
      .from("saved_flyers")
      .delete()
      .eq("id", req.params.id)
      .eq("user_id", req.user.id);
    if (error) throw error;
    return res.json({ success: true });
  } catch (error) { next(error); }
});

// ════════════════════════════════════════════════════════
//  PROFILE PAGE  (bf_profiles, bf_products, bf_portfolio, bf_music_tracks)
// ════════════════════════════════════════════════════════

const BFP_FONTS = ["modern", "classic", "technical"];

// ── Upload signed URL (client uploads directly to Supabase Storage) ──────────
app.post("/api/bfp/upload-url", requireAuth, async function (req, res, next) {
  const folder      = safeText(req.body.folder, 40)   || "misc";
  const filename    = safeText(req.body.filename, 200) || "file";
  const contentType = safeText(req.body.contentType, 100) || "application/octet-stream";
  const safeName    = filename.replace(/[^a-zA-Z0-9._-]/g, "_").substring(0, 120);
  const storagePath = `${folder}/${req.user.id}/${Date.now()}_${safeName}`;

  console.log("[upload-url] REQUEST  folder=%s file=%s ct=%s path=%s", folder, filename, contentType, storagePath);
  console.log("[upload-url] ENV CHECK  SUPABASE_URL=%s  SERVICE_KEY_SET=%s",
    process.env.SUPABASE_URL ? "yes" : "MISSING",
    process.env.SUPABASE_SERVICE_KEY ? "yes" : "MISSING"
  );

  try {
    const { data, error } = await supabase.storage
      .from("bf-public")
      .createSignedUploadUrl(storagePath);

    if (error) {
      console.error("[upload-url] Supabase error:", JSON.stringify(error));
      return res.status(502).json({ error: "Storage error: " + (error.message || JSON.stringify(error)) });
    }
    if (!data || !data.signedUrl) {
      console.error("[upload-url] No signedUrl in response — data:", JSON.stringify(data));
      return res.status(502).json({ error: "Storage returned no signed URL" });
    }

    const publicUrl = supabase.storage.from("bf-public").getPublicUrl(storagePath).data.publicUrl;
    console.log("[upload-url] OK  publicUrl=%s", publicUrl);
    return res.json({ signedUrl: data.signedUrl, token: data.token, path: storagePath, publicUrl });
  } catch (err) {
    console.error("[upload-url] EXCEPTION:", err);
    return res.status(500).json({ error: "Upload URL generation failed: " + (err.message || String(err)) });
  }
});

// ── BF Profile CRUD ───────────────────────────────────────────────────────────
app.get("/api/bfp/profile/me", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("bf_profiles").select("*").eq("user_id", req.user.id).maybeSingle();
    if (error) throw error;
    return res.json({ profile: data });
  } catch (error) { next(error); }
});

app.get("/api/bfp/profile/:userId", async function (req, res, next) {
  try {
    const userId = safeText(req.params.userId, 60);
    const { data, error } = await supabase
      .from("bf_profiles").select("*").eq("user_id", userId).maybeSingle();
    if (error) throw error;
    return res.json({ profile: data });
  } catch (error) { next(error); }
});

app.put("/api/bfp/profile/me", requireAuth, async function (req, res, next) {
  try {
    const allowed = ["display_name","title","tagline","bio","avatar_url","banner_url",
      "accent_color","font_style","show_products","show_portfolio","show_music",
      "show_card","show_videos","location","website","social_links","skills","industry"];
    const updates = { user_id: req.user.id, updated_at: nowIso() };
    for (const key of allowed) {
      if (Object.prototype.hasOwnProperty.call(req.body, key)) {
        updates[key] = req.body[key];
      }
    }
    if (updates.font_style && !BFP_FONTS.includes(updates.font_style)) {
      updates.font_style = "modern";
    }
    const { data, error } = await supabase.from("bf_profiles")
      .upsert(updates, { onConflict: "user_id" }).select("*").single();
    if (error) throw error;
    return res.json({ profile: data });
  } catch (error) { next(error); }
});

// ── Products CRUD ─────────────────────────────────────────────────────────────
app.get("/api/bfp/products", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase.from("bf_products")
      .select("*").eq("user_id", req.user.id).order("created_at", { ascending: false });
    if (error) throw error;
    return res.json({ products: data });
  } catch (error) { next(error); }
});

app.get("/api/bfp/products/public/:userId", async function (req, res, next) {
  try {
    const { data, error } = await supabase.from("bf_products")
      .select("*").eq("user_id", req.params.userId).eq("status","active")
      .order("created_at", { ascending: false });
    if (error) throw error;
    return res.json({ products: data });
  } catch (error) { next(error); }
});

app.post("/api/bfp/products", requireAuth, async function (req, res, next) {
  try {
    const name = safeText(req.body.name, 200);
    if (!name) return res.status(400).json({ error: "name is required" });
    const row = {
      user_id:     req.user.id,
      name,
      description: safeText(req.body.description, 2000),
      price:       req.body.price != null ? Number(req.body.price) : null,
      currency:    safeText(req.body.currency, 10) || "USD",
      image_url:   safeText(req.body.image_url, 500),
      category:    safeText(req.body.category, 80),
      status:      ["active","draft"].includes(req.body.status) ? req.body.status : "active"
    };
    const { data, error } = await supabase.from("bf_products").insert(row).select("*").single();
    if (error) throw error;
    return res.status(201).json({ product: data });
  } catch (error) { next(error); }
});

app.put("/api/bfp/products/:id", requireAuth, async function (req, res, next) {
  try {
    const allowed = ["name","description","price","currency","image_url","category","status"];
    const updates = { updated_at: nowIso() };
    for (const key of allowed) {
      if (Object.prototype.hasOwnProperty.call(req.body, key)) updates[key] = req.body[key];
    }
    if (updates.status && !["active","draft"].includes(updates.status)) delete updates.status;
    const { data, error } = await supabase.from("bf_products")
      .update(updates).eq("id", req.params.id).eq("user_id", req.user.id).select("*").single();
    if (error) throw error;
    return res.json({ product: data });
  } catch (error) { next(error); }
});

app.delete("/api/bfp/products/:id", requireAuth, async function (req, res, next) {
  try {
    const { error } = await supabase.from("bf_products")
      .delete().eq("id", req.params.id).eq("user_id", req.user.id);
    if (error) throw error;
    return res.json({ success: true });
  } catch (error) { next(error); }
});

// ── profile_products CRUD ─────────────────────────────────────────────────────
app.get("/api/bfp/pproducts", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase.from("profile_products")
      .select("*").eq("user_id", req.user.id).order("created_at", { ascending: false });
    if (error) throw error;
    return res.json({ products: data });
  } catch (error) { next(error); }
});

app.get("/api/bfp/pproducts/public/:userId", async function (req, res, next) {
  try {
    const { data, error } = await supabase.from("profile_products")
      .select("*").eq("user_id", req.params.userId).order("created_at", { ascending: false });
    if (error) throw error;
    return res.json({ products: data });
  } catch (error) { next(error); }
});

app.post("/api/bfp/pproducts", requireAuth, async function (req, res, next) {
  try {
    const name = safeText(req.body.name, 200);
    if (!name) return res.status(400).json({ error: "name is required" });
    const row = {
      user_id:     req.user.id,
      name,
      description: safeText(req.body.description, 2000),
      price:       req.body.price != null && req.body.price !== "" ? Number(req.body.price) : null,
      image_url:   safeText(req.body.image_url, 500),
      buy_link:    safeText(req.body.buy_link, 500)
    };
    const { data, error } = await supabase.from("profile_products").insert(row).select("*").single();
    if (error) throw error;
    return res.status(201).json({ product: data });
  } catch (error) { next(error); }
});

app.put("/api/bfp/pproducts/:id", requireAuth, async function (req, res, next) {
  try {
    const allowed = ["name","description","price","image_url","buy_link"];
    const updates = {};
    for (const key of allowed) {
      if (Object.prototype.hasOwnProperty.call(req.body, key)) updates[key] = req.body[key];
    }
    if (Object.keys(updates).length === 0) return res.status(400).json({ error: "nothing to update" });
    const { data, error } = await supabase.from("profile_products")
      .update(updates).eq("id", req.params.id).eq("user_id", req.user.id).select("*").single();
    if (error) throw error;
    return res.json({ product: data });
  } catch (error) { next(error); }
});

app.delete("/api/bfp/pproducts/:id", requireAuth, async function (req, res, next) {
  try {
    const { error } = await supabase.from("profile_products")
      .delete().eq("id", req.params.id).eq("user_id", req.user.id);
    if (error) throw error;
    return res.json({ success: true });
  } catch (error) { next(error); }
});

// ── Portfolio CRUD ────────────────────────────────────────────────────────────
app.get("/api/bfp/portfolio", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase.from("bf_portfolio")
      .select("*").eq("user_id", req.user.id).order("sort_order").order("created_at");
    if (error) throw error;
    return res.json({ items: data });
  } catch (error) { next(error); }
});

app.get("/api/bfp/portfolio/public/:userId", async function (req, res, next) {
  try {
    const { data, error } = await supabase.from("bf_portfolio")
      .select("*").eq("user_id", req.params.userId).order("sort_order").order("created_at");
    if (error) throw error;
    return res.json({ items: data });
  } catch (error) { next(error); }
});

app.post("/api/bfp/portfolio", requireAuth, async function (req, res, next) {
  try {
    const title = safeText(req.body.title, 200);
    if (!title) return res.status(400).json({ error: "title is required" });
    const { data: existing } = await supabase.from("bf_portfolio")
      .select("sort_order").eq("user_id", req.user.id)
      .order("sort_order", { ascending: false }).limit(1).maybeSingle();
    const row = {
      user_id:     req.user.id,
      title,
      description: safeText(req.body.description, 2000),
      image_url:   safeText(req.body.image_url, 500),
      url:         safeText(req.body.url, 500),
      category:    safeText(req.body.category, 80),
      sort_order:  existing ? existing.sort_order + 1 : 0
    };
    const { data, error } = await supabase.from("bf_portfolio").insert(row).select("*").single();
    if (error) throw error;
    return res.status(201).json({ item: data });
  } catch (error) { next(error); }
});

app.put("/api/bfp/portfolio/:id", requireAuth, async function (req, res, next) {
  try {
    const allowed = ["title","description","image_url","url","category","sort_order"];
    const updates = { updated_at: nowIso() };
    for (const key of allowed) {
      if (Object.prototype.hasOwnProperty.call(req.body, key)) updates[key] = req.body[key];
    }
    const { data, error } = await supabase.from("bf_portfolio")
      .update(updates).eq("id", req.params.id).eq("user_id", req.user.id).select("*").single();
    if (error) throw error;
    return res.json({ item: data });
  } catch (error) { next(error); }
});

app.delete("/api/bfp/portfolio/:id", requireAuth, async function (req, res, next) {
  try {
    const { error } = await supabase.from("bf_portfolio")
      .delete().eq("id", req.params.id).eq("user_id", req.user.id);
    if (error) throw error;
    return res.json({ success: true });
  } catch (error) { next(error); }
});

// ── profile_portfolio CRUD ────────────────────────────────────────────────────
app.get("/api/bfp/pportfolio", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase.from("profile_portfolio")
      .select("*").eq("user_id", req.user.id).order("sort_order").order("created_at", { ascending: false });
    if (error) throw error;
    return res.json({ items: data });
  } catch (error) { next(error); }
});

app.get("/api/bfp/pportfolio/public/:userId", async function (req, res, next) {
  try {
    const { data, error } = await supabase.from("profile_portfolio")
      .select("*").eq("user_id", req.params.userId).order("sort_order").order("created_at", { ascending: false });
    if (error) throw error;
    return res.json({ items: data });
  } catch (error) { next(error); }
});

app.post("/api/bfp/pportfolio", requireAuth, async function (req, res, next) {
  try {
    const title = safeText(req.body.title, 200);
    if (!title) return res.status(400).json({ error: "title is required" });
    const CATS = ["Design","Photography","Art","Web","Other"];
    const row = {
      user_id:     req.user.id,
      title,
      description: safeText(req.body.description, 2000),
      image_url:   safeText(req.body.image_url, 500),
      url:         safeText(req.body.url, 500),
      category:    CATS.includes(req.body.category) ? req.body.category : (safeText(req.body.category, 80) || null),
      sort_order:  0
    };
    const { data, error } = await supabase.from("profile_portfolio").insert(row).select("*").single();
    if (error) throw error;
    return res.status(201).json({ item: data });
  } catch (error) { next(error); }
});

app.put("/api/bfp/pportfolio/:id", requireAuth, async function (req, res, next) {
  try {
    const allowed = ["title","description","image_url","url","category","sort_order"];
    const updates = {};
    for (const key of allowed) {
      if (Object.prototype.hasOwnProperty.call(req.body, key)) updates[key] = req.body[key];
    }
    if (Object.keys(updates).length === 0) return res.status(400).json({ error: "nothing to update" });
    const { data, error } = await supabase.from("profile_portfolio")
      .update(updates).eq("id", req.params.id).eq("user_id", req.user.id).select("*").single();
    if (error) throw error;
    return res.json({ item: data });
  } catch (error) { next(error); }
});

app.delete("/api/bfp/pportfolio/:id", requireAuth, async function (req, res, next) {
  try {
    const { error } = await supabase.from("profile_portfolio")
      .delete().eq("id", req.params.id).eq("user_id", req.user.id);
    if (error) throw error;
    return res.json({ success: true });
  } catch (error) { next(error); }
});

// ── Music CRUD ────────────────────────────────────────────────────────────────
app.get("/api/bfp/music", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase.from("bf_music_tracks")
      .select("*").eq("user_id", req.user.id).order("sort_order").order("created_at");
    if (error) throw error;
    return res.json({ tracks: data });
  } catch (error) { next(error); }
});

app.get("/api/bfp/music/public/:userId", async function (req, res, next) {
  try {
    const { data, error } = await supabase.from("bf_music_tracks")
      .select("*").eq("user_id", req.params.userId).order("sort_order").order("created_at");
    if (error) throw error;
    return res.json({ tracks: data });
  } catch (error) { next(error); }
});

app.post("/api/bfp/music", requireAuth, async function (req, res, next) {
  try {
    const title     = safeText(req.body.title, 200);
    const audio_url = safeText(req.body.audio_url, 500);
    if (!title)     return res.status(400).json({ error: "title is required" });
    if (!audio_url) return res.status(400).json({ error: "audio_url is required" });
    const { data: existing } = await supabase.from("bf_music_tracks")
      .select("sort_order").eq("user_id", req.user.id)
      .order("sort_order", { ascending: false }).limit(1).maybeSingle();
    const row = {
      user_id:       req.user.id,
      title,
      artist:        safeText(req.body.artist, 200),
      audio_url,
      cover_url:     safeText(req.body.cover_url, 500),
      duration_secs: req.body.duration_secs ? Number(req.body.duration_secs) : null,
      sort_order:    existing ? existing.sort_order + 1 : 0
    };
    const { data, error } = await supabase.from("bf_music_tracks").insert(row).select("*").single();
    if (error) throw error;
    return res.status(201).json({ track: data });
  } catch (error) { next(error); }
});

app.put("/api/bfp/music/:id", requireAuth, async function (req, res, next) {
  try {
    const allowed = ["title","artist","audio_url","cover_url","duration_secs","sort_order"];
    const updates = {};
    for (const key of allowed) {
      if (Object.prototype.hasOwnProperty.call(req.body, key)) updates[key] = req.body[key];
    }
    const { data, error } = await supabase.from("bf_music_tracks")
      .update(updates).eq("id", req.params.id).eq("user_id", req.user.id).select("*").single();
    if (error) throw error;
    return res.json({ track: data });
  } catch (error) { next(error); }
});

app.delete("/api/bfp/music/:id", requireAuth, async function (req, res, next) {
  try {
    const { error } = await supabase.from("bf_music_tracks")
      .delete().eq("id", req.params.id).eq("user_id", req.user.id);
    if (error) throw error;
    return res.json({ success: true });
  } catch (error) { next(error); }
});

// ── Videos CRUD ───────────────────────────────────────────────────────────────
const VIDEO_TYPES = ["youtube","vimeo","upload"];

app.get("/api/bfp/videos", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase.from("bf_videos")
      .select("*").eq("user_id", req.user.id).order("sort_order").order("created_at");
    if (error) throw error;
    return res.json({ videos: data });
  } catch (error) { next(error); }
});

app.get("/api/bfp/videos/public/:userId", async function (req, res, next) {
  try {
    const { data, error } = await supabase.from("bf_videos")
      .select("*").eq("user_id", req.params.userId).order("sort_order").order("created_at");
    if (error) throw error;
    return res.json({ videos: data });
  } catch (error) { next(error); }
});

app.post("/api/bfp/videos", requireAuth, async function (req, res, next) {
  try {
    const title     = safeText(req.body.title, 200);
    const video_url = safeText(req.body.video_url, 500);
    if (!title)     return res.status(400).json({ error: "title is required" });
    if (!video_url) return res.status(400).json({ error: "video_url is required" });
    const video_type = VIDEO_TYPES.includes(req.body.video_type) ? req.body.video_type : "youtube";
    const { data: existing } = await supabase.from("bf_videos")
      .select("sort_order").eq("user_id", req.user.id)
      .order("sort_order", { ascending: false }).limit(1).maybeSingle();
    const row = {
      user_id:       req.user.id,
      title,
      description:   safeText(req.body.description, 1000),
      video_url,
      video_type,
      thumbnail_url: safeText(req.body.thumbnail_url, 500),
      sort_order:    existing ? existing.sort_order + 1 : 0
    };
    const { data, error } = await supabase.from("bf_videos").insert(row).select("*").single();
    if (error) throw error;
    return res.status(201).json({ video: data });
  } catch (error) { next(error); }
});

app.put("/api/bfp/videos/:id", requireAuth, async function (req, res, next) {
  try {
    const allowed = ["title","description","video_url","video_type","thumbnail_url","sort_order"];
    const updates = { updated_at: nowIso() };
    for (const key of allowed) {
      if (Object.prototype.hasOwnProperty.call(req.body, key)) updates[key] = req.body[key];
    }
    if (updates.video_type && !VIDEO_TYPES.includes(updates.video_type)) delete updates.video_type;
    const { data, error } = await supabase.from("bf_videos")
      .update(updates).eq("id", req.params.id).eq("user_id", req.user.id).select("*").single();
    if (error) throw error;
    return res.json({ video: data });
  } catch (error) { next(error); }
});

app.delete("/api/bfp/videos/:id", requireAuth, async function (req, res, next) {
  try {
    const { error } = await supabase.from("bf_videos")
      .delete().eq("id", req.params.id).eq("user_id", req.user.id);
    if (error) throw error;
    return res.json({ success: true });
  } catch (error) { next(error); }
});

/* ── Business Profile — PUT (GET and POST already registered above) ── */

app.put("/api/business-profile", requireAuth, async function (req, res, next) {
  try {
    const updates = { updated_at: nowIso() };
    if (req.body.business_name     !== undefined) updates.business_name     = safeText(req.body.business_name, 120)      || null;
    if (req.body.business_type     !== undefined) updates.business_type     = safeText(req.body.business_type, 120)      || null;
    if (req.body.industry          !== undefined) updates.industry          = safeText(req.body.industry, 120)           || null;
    if (req.body.website           !== undefined) updates.website           = safeText(req.body.website, 500)            || null;
    if (req.body.location          !== undefined) updates.location          = safeText(req.body.location, 200)           || null;
    if (req.body.target_audience   !== undefined) updates.target_audience   = safeText(req.body.target_audience, 500)    || null;
    if (req.body.offer             !== undefined) updates.offer             = safeText(req.body.offer, 500)              || null;
    if (req.body.products_services !== undefined) updates.products_services = safeText(req.body.products_services, 1000) || null;
    if (req.body.brand_voice       !== undefined) updates.brand_voice       = safeText(req.body.brand_voice, 500)        || null;
    if (req.body.brand_values      !== undefined) updates.brand_values      = safeText(req.body.brand_values, 1000)      || null;
    if (req.body.business_goals    !== undefined) updates.business_goals    = safeText(req.body.business_goals, 1000)    || null;
    if (req.body.banned_topics     !== undefined) updates.banned_topics     = safeText(req.body.banned_topics, 1000)     || null;
    if (req.body.competitors       !== undefined) updates.competitors       = safeText(req.body.competitors, 500)        || null;
    if (req.body.description       !== undefined) updates.description       = safeText(req.body.description, 2000)       || null;
    if (req.body.social_platforms  !== undefined && typeof req.body.social_platforms === "object" && !Array.isArray(req.body.social_platforms))
      updates.social_platforms = req.body.social_platforms;
    if (req.body.posting_frequency !== undefined) updates.posting_frequency = safeText(req.body.posting_frequency, 100)  || null;
    const { data, error } = await supabase
      .from("business_profiles")
      .update(updates)
      .eq("user_id", req.user.id)
      .select("*").single();
    if (error) {
      console.error("[business-profile PUT] Supabase error:", {
        code: error.code, message: error.message,
        details: error.details, hint: error.hint
      });
      return res.status(500).json({
        error: "Save failed",
        db_code: error.code,
        db_message: error.message,
        db_hint: error.hint || error.details || null
      });
    }
    return res.json({ profile: data });
  } catch (error) { next(error); }
});

/* ── Social Post Drafts ── */

/* Fetches all connected Zernio accounts; returns raw array (empty on any error). */
async function fetchZernioAccounts(logPrefix) {
  var apiKey = (process.env.ZERNIO_API_KEY || "").trim();
  if (!apiKey) return [];
  try {
    var r = await fetch("https://zernio.com/api/v1/accounts", {
      headers: { "Authorization": "Bearer " + apiKey }
    });
    if (!r.ok) {
      var body = await r.text().catch(function () { return ""; });
      console.error("[" + logPrefix + "] Zernio accounts error " + r.status + ":", body.slice(0, 300));
      return [];
    }
    var d = await r.json();
    return Array.isArray(d.accounts) ? d.accounts : [];
  } catch (e) {
    console.error("[" + logPrefix + "] fetchZernioAccounts threw:", e.message);
    return [];
  }
}

/* Returns the Zernio account _id for a given platform slug, or null if not connected. */
async function getZernioAccountId(platform) {
  var zernioPlatform = ZERNIO_PLATFORM_MAP[platform] || platform;
  var accounts = await fetchZernioAccounts("social/publish");
  var match = accounts.find(function (a) { return a.platform === zernioPlatform; });
  console.log("[social/publish] accounts:", accounts.length, "| looking for:", zernioPlatform, "| match:", match ? match._id : "none");
  return match ? match._id : null;
}

app.post("/api/social-drafts", requireAuth, async function (req, res, next) {
  try {
    var platform = safeText(req.body.platform, 100)  || null;
    var content  = safeText(req.body.content, 10000) || null;
    var schedFor = req.body.scheduled_for             || null;
    var apiKey   = (process.env.ZERNIO_API_KEY || "").trim();

    console.log("[social/publish] Approve — user:", req.user.id, "platform:", platform);

    if (!apiKey) {
      return res.status(503).json({ error: "Publishing unavailable — ZERNIO_API_KEY not configured" });
    }

    // 1. Look up connected accountId for this platform
    var accountId = await getZernioAccountId(platform);
    if (!accountId) {
      console.log("[social/publish] No connected account for platform:", platform);
      return res.status(400).json({
        error: "No connected " + (platform || "social") + " account — connect one first"
      });
    }
    console.log("[social/publish] accountId:", accountId, "platform:", platform);

    // 2. Build Zernio post payload
    var zernioPlatform = ZERNIO_PLATFORM_MAP[platform] || platform;
    var postPayload    = {
      content:   content,
      platforms: [{ platform: zernioPlatform, accountId: accountId }]
    };
    if (schedFor) {
      postPayload.scheduledFor = schedFor;
    } else {
      postPayload.publishNow = true;
    }
    console.log("[social/publish] Posting to Zernio:", JSON.stringify(postPayload));

    // 3. Publish via Zernio
    var zernioRes  = await fetch("https://zernio.com/api/v1/posts", {
      method:  "POST",
      headers: { "Authorization": "Bearer " + apiKey, "Content-Type": "application/json" },
      body:    JSON.stringify(postPayload)
    });
    var zernioText = await zernioRes.text();
    console.log("[social/publish] Zernio response " + zernioRes.status + ":", zernioText.slice(0, 500));

    if (!zernioRes.ok) {
      return res.status(502).json({
        error:   "Failed to publish to " + (platform || "social platform"),
        details: zernioText.slice(0, 300)
      });
    }

    var zernioData   = JSON.parse(zernioText);
    var zernioPostId = (zernioData.post && zernioData.post._id) || null;
    console.log("[social/publish] Published OK — Zernio post ID:", zernioPostId);

    // 4. Persist draft with final status (do NOT mark published on Zernio error)
    var finalStatus = schedFor ? "scheduled" : "published";
    const { data, error } = await supabase
      .from("social_post_drafts")
      .insert({
        user_id:        req.user.id,
        platform:       platform,
        content:        content,
        status:         finalStatus,
        scheduled_for:  schedFor,
        zernio_post_id: zernioPostId,
        created_at:     nowIso(),
        updated_at:     nowIso()
      })
      .select("*").single();

    if (error) {
      console.error("[social-drafts POST] Supabase error:", {
        code: error.code, message: error.message,
        details: error.details, hint: error.hint
      });
      return res.status(500).json({
        error:      "Save failed",
        db_code:    error.code,
        db_message: error.message,
        db_hint:    error.hint || error.details || null
      });
    }
    return res.status(201).json({ draft: data });
  } catch (error) { next(error); }
});

app.get("/api/social-drafts", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("social_post_drafts")
      .select("*")
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: false });
    if (error) throw error;
    return res.json({ drafts: data || [] });
  } catch (error) { next(error); }
});

app.put("/api/social-drafts/:id", requireAuth, async function (req, res, next) {
  try {
    const updates = { updated_at: nowIso() };
    if (req.body.platform      !== undefined) updates.platform      = safeText(req.body.platform, 100)  || null;
    if (req.body.content       !== undefined) updates.content       = safeText(req.body.content, 10000) || null;
    if (req.body.status        !== undefined) updates.status        = safeText(req.body.status, 40)     || "pending";
    if (req.body.scheduled_for !== undefined) updates.scheduled_for = req.body.scheduled_for            || null;
    const { data, error } = await supabase
      .from("social_post_drafts")
      .update(updates)
      .eq("id", req.params.id)
      .eq("user_id", req.user.id)
      .select("*").single();
    if (error) {
      console.error("[social-drafts PUT] Supabase error:", {
        code: error.code, message: error.message,
        details: error.details, hint: error.hint
      });
      return res.status(500).json({
        error: "Save failed",
        db_code: error.code,
        db_message: error.message,
        db_hint: error.hint || error.details || null
      });
    }
    return res.json({ draft: data });
  } catch (error) { next(error); }
});

/* ── List connected social accounts ── */
app.get("/api/social/accounts", requireAuth, async function (req, res, next) {
  try {
    var raw = await fetchZernioAccounts("social/accounts");
    var reverseMap = {};
    Object.keys(ZERNIO_PLATFORM_MAP).forEach(function (k) {
      reverseMap[ZERNIO_PLATFORM_MAP[k]] = k;
    });
    var accounts = raw.map(function (a) {
      return {
        platform:  reverseMap[a.platform] || a.platform,
        accountId: a._id,
        name:      a.name || a.username || a.handle || a.displayName || a._id
      };
    });
    console.log("[social/accounts] returning", accounts.length, "connected accounts");
    return res.json({ accounts: accounts });
  } catch (error) { next(error); }
});

/* ── Social Account Connect (Zernio OAuth) ── */
/* Maps our platform slugs to Zernio's platform identifiers */
var ZERNIO_PLATFORM_MAP = {
  x:         "twitter",
  instagram: "instagram",
  facebook:  "facebook",
  tiktok:    "tiktok",
  youtube:   "youtube",
  linkedin:  "linkedin"
};

app.post("/api/social/connect/:platform", requireAuth, async function (req, res, next) {
  try {
    var rawPlatform    = safeText(req.params.platform, 40) || "";
    var zernioPlatform = ZERNIO_PLATFORM_MAP[rawPlatform] || rawPlatform;
    var apiKey         = (process.env.ZERNIO_API_KEY || "").trim();

    if (!apiKey) {
      return res.status(503).json({ error: "Social connect unavailable — ZERNIO_API_KEY not configured" });
    }

    /* profileId scopes connected accounts within Zernio; fall back to authenticated user id */
    var profileId = process.env.ZERNIO_PROFILE_ID || req.user.id;

    console.log("[social/connect] User " + req.user.id + " → Zernio connect for platform: " + zernioPlatform);

    var zernioRes = await fetch(
      "https://zernio.com/api/v1/connect/" + encodeURIComponent(zernioPlatform) +
        "?profileId=" + encodeURIComponent(profileId),
      { headers: { "Authorization": "Bearer " + apiKey } }
    );

    if (!zernioRes.ok) {
      var errBody = await zernioRes.json().catch(function () { return {}; });
      console.error("[social/connect] Zernio error " + zernioRes.status + ":", errBody);
      return res.status(502).json({
        error: "Could not generate connect URL",
        details: errBody.message || errBody.error || ("HTTP " + zernioRes.status)
      });
    }

    var data       = await zernioRes.json();
    var connectUrl = data.url || data.authUrl || data.connect_url || null;

    if (!connectUrl) {
      console.error("[social/connect] Zernio response missing URL field:", JSON.stringify(data));
      return res.status(502).json({ error: "Zernio did not return a connect URL" });
    }

    return res.json({ ok: true, platform: rawPlatform, url: connectUrl });
  } catch (error) { next(error); }
});

/* ── SMS Drip Engine ─────────────────────────────────────────────────────── */

async function runDripEngine(userId) {
  try {
    var DRY_RUN = true;

    var { data: enrollments, error } = await supabase
      .from("sms_campaign_enrollments")
      .select("*")
      .eq("user_id", userId)
      .eq("status", "active");

    if (error) {
      console.error("[dripEngine] Supabase error loading enrollments:", error.message);
      return { processed: 0, sent: 0, skipped: 0, completed: 0 };
    }

    var list = enrollments || [];
    console.log("[dripEngine] User " + userId + " — active enrollments found:", list.length);

    var summary = { processed: 0, sent: 0, skipped: 0, completed: 0 };

    for (var i = 0; i < list.length; i++) {
      var enrollment = list[i];
      summary.processed++;

      var { data: msgs, error: msgsErr } = await supabase
        .from("sms_campaign_messages")
        .select("*")
        .eq("campaign_id", enrollment.campaign_id)
        .order("step_order", { ascending: true });

      if (msgsErr) {
        console.error("[dripEngine] Error loading messages for campaign " + enrollment.campaign_id + ":", msgsErr.message);
        summary.skipped++;
        continue;
      }

      msgs = msgs || [];

      if (enrollment.current_step >= msgs.length) {
        console.log("[dripEngine] Enrollment " + enrollment.id + " — all steps complete, marking completed");

        var { error: completeErr } = await supabase
          .from("sms_campaign_enrollments")
          .update({ status: "completed" })
          .eq("id", enrollment.id);

        if (completeErr) {
          console.error("[dripEngine] Error completing enrollment " + enrollment.id + ":", completeErr.message);
        } else {
          summary.completed++;
        }
        continue;
      }

      var currentMsg = msgs[enrollment.current_step];

      if (enrollment.next_send_at && new Date(enrollment.next_send_at) > new Date()) {
        console.log("[dripEngine] Enrollment " + enrollment.id + " — not yet due (next_send_at: " + enrollment.next_send_at + ")");
        summary.skipped++;
        continue;
      }

      var { data: subscriber, error: subErr } = await supabase
        .from("sms_subscribers")
        .select("*")
        .eq("id", enrollment.subscriber_id)
        .maybeSingle();

      if (subErr) {
        console.error("[dripEngine] Error loading subscriber " + enrollment.subscriber_id + ":", subErr.message);
        summary.skipped++;
        continue;
      }

      if (!subscriber || subscriber.consent_status !== "opted_in") {
        console.log("[dripEngine] Enrollment " + enrollment.id + " — subscriber " + enrollment.subscriber_id + " not opted in, skipping");
        summary.skipped++;
        continue;
      }

      console.log("[dripEngine] Enrollment " + enrollment.id +
        " — subscriber " + enrollment.subscriber_id +
        " due for step " + enrollment.current_step +
        " (step_order " + currentMsg.step_order + ")" +
        (DRY_RUN ? " [DRY RUN]" : ""));

      var nowIso = new Date().toISOString();

      var { error: logErr } = await supabase
        .from("sms_send_log")
        .insert({
          user_id:       userId,
          campaign_id:   enrollment.campaign_id,
          subscriber_id: enrollment.subscriber_id,
          message_id:    currentMsg.id,
          message_body:  currentMsg.message_body,
          phone_number:  subscriber.phone_number,
          status:        DRY_RUN ? "dry_run" : "sent",
          twilio_sid:    null,
          sent_at:       nowIso
        });

      if (logErr) {
        console.error("[dripEngine] Error writing send log for enrollment " + enrollment.id + ":", logErr.message);
        summary.skipped++;
        continue;
      }

      var newStep = enrollment.current_step + 1;
      var nextSendAt = null;

      if (msgs[newStep]) {
        var delayHours = (msgs[newStep].delay_hours != null ? msgs[newStep].delay_hours : 0);
        var nextDate = new Date(Date.now() + delayHours * 60 * 60 * 1000);
        nextSendAt = nextDate.toISOString();
      }

      var { error: advanceErr } = await supabase
        .from("sms_campaign_enrollments")
        .update({ current_step: newStep, next_send_at: nextSendAt })
        .eq("id", enrollment.id);

      if (advanceErr) {
        console.error("[dripEngine] Error advancing enrollment " + enrollment.id + ":", advanceErr.message);
      }

      summary.sent++;
    }

    return summary;

  } catch (error) {
    console.error("[dripEngine] Unexpected error:", error.message || error);
    return { processed: 0, sent: 0, skipped: 0, completed: 0 };
  }
}

async function runDripForAllUsers() {
  var { data: rows, error } = await supabase
    .from("sms_campaign_enrollments")
    .select("user_id")
    .eq("status", "active");

  if (error) {
    console.error("[dripForAllUsers] Error fetching user IDs:", error.message);
    return;
  }

  var seen = {};
  var userIds = (rows || []).map(function (r) { return r.user_id; }).filter(function (id) {
    if (seen[id]) return false;
    seen[id] = true;
    return true;
  });

  for (var i = 0; i < userIds.length; i++) {
    try {
      await runDripEngine(userIds[i]);
    } catch (err) {
      console.error("[dripForAllUsers] Error for user " + userIds[i] + ":", err.message || err);
    }
  }

  console.log("[dripForAllUsers] " + new Date().toISOString() + " — processed " + userIds.length + " user(s)");
}

app.post("/api/sms/run-engine", requireAuth, async function (req, res, next) {
  try {
    console.log("[sms/run-engine] User " + req.user.id + " → running drip engine");
    var result = await runDripEngine(req.user.id);
    return res.json({ result: result });
  } catch (error) {
    console.error("[sms/run-engine] Error:", error.message || error);
    next(error);
  }
});

/* ── SMS ─────────────────────────────────────────────────────────────────── */

app.post("/api/sms/send", requireAuth, async function (req, res, next) {
  try {
    var accountSid  = (process.env.TWILIO_ACCOUNT_SID   || "").trim();
    var authToken   = (process.env.TWILIO_AUTH_TOKEN     || "").trim();
    var fromNumber  = (process.env.TWILIO_PHONE_NUMBER   || "").trim();

    if (!accountSid || !authToken || !fromNumber) {
      var missing = [
        !accountSid  && "TWILIO_ACCOUNT_SID",
        !authToken   && "TWILIO_AUTH_TOKEN",
        !fromNumber  && "TWILIO_PHONE_NUMBER"
      ].filter(Boolean).join(", ");
      console.error("[sms/send] Missing env vars:", missing);
      return res.status(503).json({
        error: "SMS unavailable — missing Twilio configuration: " + missing
      });
    }

    var to      = safeText(req.body.to,      20)  || "";
    var message = safeText(req.body.message, 1600) || "";

    if (!to || !message) {
      return res.status(400).json({ error: "Both 'to' and 'message' are required" });
    }

    console.log("[sms/send] User " + req.user.id + " → sending SMS to " + to);

    var client = twilio(accountSid, authToken);
    var sent   = await client.messages.create({
      from: fromNumber,
      to:   to,
      body: message
    });

    console.log("[sms/send] Delivered — SID:", sent.sid, "status:", sent.status);
    return res.json({ ok: true, sid: sent.sid, status: sent.status });

  } catch (error) {
    console.error("[sms/send] Error:", error.message || error);
    next(error);
  }
});


app.get("/api/sms/subscribers", requireAuth, async function (req, res, next) {
  try {
    console.log("[sms/subscribers] User " + req.user.id + " → fetching subscribers");

    var { data, error } = await supabase
      .from("sms_subscribers")
      .select("*")
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: false });

    if (error) {
      console.error("[sms/subscribers] Supabase error:", error.message);
      return res.status(500).json({ error: error.message });
    }

    return res.json({ subscribers: data });

  } catch (error) {
    console.error("[sms/subscribers] Error:", error.message || error);
    next(error);
  }
});

app.post("/api/sms/subscribers", requireAuth, async function (req, res, next) {
  try {
    var phone   = ((req.body.phone   || "") + "").trim();
    var name    = safeText(req.body.name,    120) || null;
    var consent = req.body.consent !== undefined ? !!req.body.consent : false;

    if (!phone) {
      return res.status(400).json({ error: "Phone is required" });
    }

    console.log("[sms/subscribers/add] User " + req.user.id + " → adding " + phone);

    var { data, error } = await supabase
      .from("sms_subscribers")
      .insert({
        user_id:          req.user.id,
        phone_number:     phone,
        customer_name:    name,
        consent_status:   consent ? "opted_in" : "opted_out"
      })
      .select()
      .single();

    if (error) {
      console.error("[sms/subscribers/add] Supabase error:", error.message);
      return res.status(500).json({ error: error.message });
    }

    return res.json({ subscriber: data });

  } catch (error) {
    console.error("[sms/subscribers/add] Error:", error.message || error);
    next(error);
  }
});

app.post("/api/sms/subscribers/bulk", requireAuth, async function (req, res, next) {
  try {
    var list = req.body.subscribers;

    if (!Array.isArray(list) || list.length === 0) {
      return res.status(400).json({ error: "subscribers array required" });
    }

    var rows    = [];
    var skipped = 0;

    list.forEach(function (entry) {
      var phone = ((entry.phone || "") + "").trim();
      if (!phone) {
        skipped++;
        return;
      }
      var name    = safeText(entry.name, 120) || null;
      var consent = entry.consent !== undefined ? !!entry.consent : false;
      rows.push({
        user_id:        req.user.id,
        phone_number:   phone,
        customer_name:  name,
        consent_status: consent ? "opted_in" : "opted_out"
      });
    });

    console.log("[sms/subscribers/bulk] User " + req.user.id + " → inserting " + rows.length + ", skipping " + skipped);

    if (rows.length === 0) {
      return res.json({ inserted: 0, skipped: skipped });
    }

    var { error } = await supabase
      .from("sms_subscribers")
      .insert(rows);

    if (error) {
      console.error("[sms/subscribers/bulk] Supabase error:", error.message);
      return res.status(500).json({ error: error.message });
    }

    return res.json({ inserted: rows.length, skipped: skipped });

  } catch (error) {
    console.error("[sms/subscribers/bulk] Error:", error.message || error);
    next(error);
  }
});

/* ── Public lead capture (landing pages) ─────────────────────────────────
   No requireAuth — this is a public, unauthenticated endpoint meant to be
   called directly from external landing pages. Owner is hardcoded since
   there is no logged-in BizForce user context for a public visitor. */
var CAPTURE_OWNER_ID = "ea887c6e-e278-4a15-b7e9-cd78a9949b78";
var CAPTURE_SOURCES = ["bluesky", "mastodon", "youtube", "direct", "other"];
var CAPTURE_BRANDS = ["mrearthrose", "swordvitality", "blacksuncircle", "bizforce"];
var WELCOME_CAMPAIGN_ID = "c735e5ea-3262-49a7-ab05-7c72971d0ff8";

app.post("/api/capture", async function (req, res) {
  try {
    var email = safeText(req.body.email, 255);
    email = email ? email.toLowerCase() : null;

    var phone = safeText(req.body.phone, 32);
    var name = safeText(req.body.name, 120);

    if (!email && !phone) {
      return res.status(400).json({ error: "email or phone required" });
    }

    var sourceRaw = String(req.body.source || "").toLowerCase().trim();
    var source = CAPTURE_SOURCES.indexOf(sourceRaw) !== -1 ? sourceRaw : "direct";

    var brandRaw = String(req.body.brand || "").toLowerCase().trim();
    var brand = CAPTURE_BRANDS.indexOf(brandRaw) !== -1 ? brandRaw : "mrearthrose";

    var smsConsent = !!req.body.sms_consent;
    var emailConsent = !!req.body.email_consent;
    var timestamp = nowIso();

    var captureInsert = await supabase
      .from("lead_captures")
      .insert({
        source: source,
        brand: brand,
        email: email,
        phone: phone,
        name: name,
        sms_consent: smsConsent,
        email_consent: emailConsent,
        consent_ip: req.ip,
        consent_timestamp: timestamp,
        status: "new",
        owner_id: CAPTURE_OWNER_ID
      })
      .select("*")
      .single();

    if (captureInsert.error) {
      throw captureInsert.error;
    }

    var smsSynced = false;
    var enrolled = false;

    if (phone && smsConsent) {
      var subscriberUpsert = await supabase
        .from("sms_subscribers")
        .upsert({
          user_id: CAPTURE_OWNER_ID,
          phone_number: phone,
          customer_name: name || null,
          consent_status: "opted_in",
          consent_timestamp: timestamp
        }, { onConflict: "user_id,phone_number" })
        .select("id")
        .single();

      if (!subscriberUpsert.error) {
        smsSynced = true;

        var subscriberId = subscriberUpsert.data && subscriberUpsert.data.id;

        if (subscriberId) {
          try {
            var enrollmentInsert = await supabase
              .from("sms_campaign_enrollments")
              .insert({
                user_id: CAPTURE_OWNER_ID,
                campaign_id: WELCOME_CAMPAIGN_ID,
                subscriber_id: subscriberId
              });

            if (!enrollmentInsert.error) {
              enrolled = true;
            } else if (enrollmentInsert.error.code === "23505") {
              console.log("[capture] Subscriber already enrolled in welcome campaign, skipping.");
              enrolled = true;
            } else {
              console.error("[capture] Enrollment insert failed:", enrollmentInsert.error.message);
            }
          } catch (enrollErr) {
            console.error("[capture] Enrollment error:", enrollErr.message || enrollErr);
          }
        } else {
          console.error("[capture] sms_subscribers upsert returned no id, skipping enrollment.");
        }

        var statusUpdate = await supabase
          .from("lead_captures")
          .update({ status: enrolled ? "enrolled" : "synced" })
          .eq("id", captureInsert.data.id);

        if (statusUpdate.error) {
          console.error("[capture] Failed to update lead_captures status:", statusUpdate.error.message);
        }
      } else {
        console.error("[capture] sms_subscribers upsert failed:", subscriberUpsert.error.message);
      }
    }

    return res.status(200).json({ ok: true, captured: true, sms_synced: smsSynced, enrolled: enrolled });
  } catch (error) {
    console.error("[capture] Error:", error.message || error);
    return res.status(500).json({ error: "capture failed" });
  }
});

/* ── SMS Campaigns ───────────────────────────────────────────────────────── */

app.get("/api/sms/campaigns", requireAuth, async function (req, res, next) {
  try {
    console.log("[sms/campaigns] User " + req.user.id + " → fetching campaigns");

    var { data, error } = await supabase
      .from("sms_campaigns")
      .select("*")
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: false });

    if (error) {
      console.error("[sms/campaigns] Supabase error:", error.message);
      return res.status(500).json({ error: error.message });
    }

    return res.json({ campaigns: data });

  } catch (error) {
    console.error("[sms/campaigns] Error:", error.message || error);
    next(error);
  }
});

app.post("/api/sms/campaigns", requireAuth, async function (req, res, next) {
  try {
    var name = safeText(req.body.name, 255) || "";
    name = name.trim();

    if (!name) {
      return res.status(400).json({ error: "Name required" });
    }

    console.log("[sms/campaigns/create] User " + req.user.id + " → creating campaign: " + name);

    var { data, error } = await supabase
      .from("sms_campaigns")
      .insert({
        user_id: req.user.id,
        name:    name,
        status:  "draft"
      })
      .select()
      .single();

    if (error) {
      console.error("[sms/campaigns/create] Supabase error:", error.message);
      return res.status(500).json({ error: error.message });
    }

    return res.json({ campaign: data });

  } catch (error) {
    console.error("[sms/campaigns/create] Error:", error.message || error);
    next(error);
  }
});

app.get("/api/sms/campaigns/:id/messages", requireAuth, async function (req, res, next) {
  try {
    var campaignId = req.params.id;

    console.log("[sms/campaigns/messages] User " + req.user.id + " → fetching messages for campaign " + campaignId);

    var { data, error } = await supabase
      .from("sms_campaign_messages")
      .select("*")
      .eq("campaign_id", campaignId)
      .eq("user_id", req.user.id)
      .order("step_order", { ascending: true });

    if (error) {
      console.error("[sms/campaigns/messages] Supabase error:", error.message);
      return res.status(500).json({ error: error.message });
    }

    return res.json({ messages: data });

  } catch (error) {
    console.error("[sms/campaigns/messages] Error:", error.message || error);
    next(error);
  }
});

app.post("/api/sms/campaigns/:id/messages", requireAuth, async function (req, res, next) {
  try {
    var campaignId  = req.params.id;
    var body        = safeText(req.body.body, 1600) || "";
    var stepNumber  = Number.isInteger(req.body.step_number)  ? req.body.step_number  : 1;
    var delayHours  = Number.isInteger(req.body.delay_hours)  ? req.body.delay_hours  : 0;

    if (!body.trim()) {
      return res.status(400).json({ error: "Message body required" });
    }

    console.log("[sms/campaigns/messages/add] User " + req.user.id + " → adding step " + stepNumber + " to campaign " + campaignId);

    var { data, error } = await supabase
      .from("sms_campaign_messages")
      .insert({
        campaign_id:  campaignId,
        user_id:      req.user.id,
        step_order:   stepNumber,
        message_body: body.trim(),
        delay_hours:  delayHours
      })
      .select()
      .single();

    if (error) {
      console.error("[sms/campaigns/messages/add] Supabase error:", error.message);
      return res.status(500).json({ error: error.message });
    }

    return res.json({ message: data });

  } catch (error) {
    console.error("[sms/campaigns/messages/add] Error:", error.message || error);
    next(error);
  }
});

app.get("/api/sms/send-log", requireAuth, async function (req, res, next) {
  try {
    console.log("[sms/send-log] User " + req.user.id + " → fetching send log");

    var { data, error } = await supabase
      .from("sms_send_log")
      .select("*")
      .eq("user_id", req.user.id)
      .order("sent_at", { ascending: false })
      .limit(100);

    if (error) {
      console.error("[sms/send-log] Supabase error:", error.message);
      return res.status(500).json({ error: error.message });
    }

    return res.json({ log: data });

  } catch (error) {
    console.error("[sms/send-log] Error:", error.message || error);
    next(error);
  }
});

app.post("/api/sms/campaigns/:id/enroll", requireAuth, async function (req, res, next) {
  try {
    var campaignId    = req.params.id;
    var subscriberIds = req.body.subscriber_ids;

    if (!Array.isArray(subscriberIds) || subscriberIds.length === 0) {
      return res.status(400).json({ error: "subscriber_ids array required" });
    }

    console.log("[sms/campaigns/enroll] User " + req.user.id + " → enrolling " + subscriberIds.length + " subscriber(s) into campaign " + campaignId);

    var enrolled = 0;

    for (var i = 0; i < subscriberIds.length; i++) {
      var { error } = await supabase
        .from("sms_campaign_enrollments")
        .insert({
          campaign_id:  campaignId,
          subscriber_id: subscriberIds[i],
          user_id:      req.user.id,
          current_step: 0,
          status:       "active",
          enrolled_at:  new Date().toISOString()
        });

      if (error) {
        if (error.code === "23505") {
          console.log("[sms/campaigns/enroll] Skipping duplicate subscriber " + subscriberIds[i]);
          continue;
        }
        console.error("[sms/campaigns/enroll] Supabase error for subscriber " + subscriberIds[i] + ":", error.message);
      } else {
        enrolled++;
      }
    }

    return res.json({ enrolled: enrolled });

  } catch (error) {
    console.error("[sms/campaigns/enroll] Error:", error.message || error);
    next(error);
  }
});

app.get("/api/sms/campaigns/:id/enrollments", requireAuth, async function (req, res, next) {
  try {
    var campaignId = req.params.id;

    console.log("[sms/campaigns/enrollments] User " + req.user.id + " → fetching enrollments for campaign " + campaignId);

    var { data, error } = await supabase
      .from("sms_campaign_enrollments")
      .select("*")
      .eq("campaign_id", campaignId)
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: false });

    if (error) {
      console.error("[sms/campaigns/enrollments] Supabase error:", error.message);
      return res.status(500).json({ error: error.message });
    }

    return res.json({ enrollments: data });

  } catch (error) {
    console.error("[sms/campaigns/enrollments] Error:", error.message || error);
    next(error);
  }
});

app.get("/api/leads", requireAuth, async function (req, res, next) {
  try {
    var { data, error } = await supabase
      .from("bsky_leads")
      .select("*")
      .eq("status", "scored")
      .order("intent_score", { ascending: false })
      .limit(100);

    if (error) {
      console.error("[/api/leads] Supabase error:", error.message);
      return res.status(500).json({ error: error.message });
    }

    return res.json({ leads: data || [] });
  } catch (err) {
    console.error("[/api/leads] Error:", err.message || err);
    next(err);
  }
});

app.post("/api/content-library", requireAuth, async function (req, res, next) {
  try {
    var userId     = req.user.id;
    var type       = String(req.body.type || "").trim();
    var title      = String(req.body.title || "").trim();
    var keyword    = String(req.body.keyword || "").trim();
    var source_url = String(req.body.source_url || "").trim();
    var body       = String(req.body.body || "").trim();

    if (!type || !body) {
      return res.status(400).json({ error: "type and body are required" });
    }

    var { data, error } = await supabase
      .from("content_library")
      .insert({
        user_id:    userId,
        type:       type,
        title:      title || null,
        keyword:    keyword || null,
        source_url: source_url || null,
        body:       body
      })
      .select("*")
      .single();

    if (error) {
      console.error("[/api/content-library] Supabase error:", error.message);
      return res.status(500).json({ error: error.message });
    }

    try {
      var capResult = await supabase
        .from("content_library")
        .select("id")
        .eq("user_id", userId)
        .eq("type", type)
        .order("created_at", { ascending: false });

      if (!capResult.error && capResult.data && capResult.data.length > 50) {
        var toDelete = capResult.data.slice(50).map(function (r) { return r.id; });
        await supabase
          .from("content_library")
          .delete()
          .in("id", toDelete)
          .eq("user_id", userId);
      }
    } catch (capErr) {
      console.warn("[/api/content-library] Cap retire failed (non-fatal):", capErr.message || capErr);
    }

    return res.status(201).json({ success: true, entry: data });
  } catch (err) {
    console.error("[/api/content-library] Error:", err.message || err);
    next(err);
  }
});

app.get("/api/content-library", requireAuth, async function (req, res, next) {
  try {
    var userId = req.user.id;
    var type   = String(req.query.type || "").trim();

    var query = supabase
      .from("content_library")
      .select("*")
      .eq("user_id", userId)
      .order("created_at", { ascending: false });

    if (type) {
      query = query.eq("type", type);
    }

    var { data, error } = await query;

    if (error) {
      console.error("[GET /api/content-library] Supabase error:", error.message);
      return res.status(500).json({ error: error.message });
    }

    return res.json({ entries: data || [] });
  } catch (err) {
    console.error("[GET /api/content-library] Error:", err.message || err);
    next(err);
  }
});

app.post("/api/content-library/empty", requireAuth, async function (req, res, next) {
  try {
    var userId = req.user.id;
    var type   = String(req.body.type || "").trim();

    if (!type) {
      return res.status(400).json({ error: "type is required" });
    }

    var { error } = await supabase
      .from("content_library")
      .delete()
      .eq("user_id", userId)
      .eq("type", type);

    if (error) {
      console.error("[POST /api/content-library/empty] Supabase error:", error.message);
      return res.status(500).json({ error: error.message });
    }

    return res.json({ success: true });
  } catch (err) {
    console.error("[POST /api/content-library/empty] Error:", err.message || err);
    next(err);
  }
});

app.delete("/api/content-library/:id", requireAuth, async function (req, res, next) {
  try {
    var userId = req.user.id;
    var id     = req.params.id;

    var { error } = await supabase
      .from("content_library")
      .delete()
      .eq("id", id)
      .eq("user_id", userId);

    if (error) {
      console.error("[DELETE /api/content-library] Supabase error:", error.message);
      return res.status(500).json({ error: error.message });
    }

    return res.json({ success: true });
  } catch (err) {
    console.error("[DELETE /api/content-library] Error:", err.message || err);
    next(err);
  }
});

app.post("/api/leads/draft-reply", requireAuth, async function (req, res, next) {
  try {
    var postText        = String(req.body.post_text        || "").trim();
    var suggestedProduct = String(req.body.suggested_product || "").trim();

    if (!postText) {
      return res.status(400).json({ error: "post_text is required" });
    }

    var prompt;

    if (suggestedProduct === "Quantum Jumping book") {
      prompt =
        "You are a thoughtful person who has personally explored manifestation and reality-shifting methods.\n" +
        "Read the post below carefully and write a genuine 2-3 sentence reply that:\n" +
        "1. Speaks directly to what this specific person actually said — acknowledge their feeling, question, or situation.\n" +
        "2. Offers ONE real, human insight from your own experience — something that feels true, not motivational-poster fluff.\n" +
        "3. Only if it fits naturally, mention in passing that there is a method called Quantum Jumping that helped you think differently — as a gentle pointer, not a recommendation or a sell. Never include a URL or price.\n" +
        "Sound like a real person in a comment section, not a marketer. No hashtags, no exclamation spam, no 'DM me'.\n\n" +
        "Post: " + postText + "\n\n" +
        "Reply:";
    } else {
      prompt =
        "You are helping a small business owner engage authentically on social media.\n" +
        "Write a short, genuine reply (2-3 sentences) to the following post. The reply should sound like a real, helpful person — not a brand or a sales pitch.\n" +
        "If it feels natural, subtly mention how " + (suggestedProduct || "the product") + " might help, but only if it fits the conversation. Never be pushy or salesy.\n\n" +
        "Post: " + postText + "\n\n" +
        "Reply:";
    }

    const draftReplyApiKey = await resolveAnthropicKey(req.user.id);
    const draftReplyAnthropicClient = new Anthropic({ apiKey: draftReplyApiKey });

    var response = await draftReplyAnthropicClient.messages.create({
      model:      "claude-haiku-4-5-20251001",
      max_tokens: 300,
      messages:   [{ role: "user", content: [{ type: "text", text: prompt }] }]
    });

    var reply = (response.content && response.content[0] && response.content[0].text) || "";

    return res.json({ reply: reply.trim() });
  } catch (err) {
    console.error("[/api/leads/draft-reply] Error:", err.message || err);
    next(err);
  }
});

// ── Sales Agent lead-conversion pipeline ──
// bsky_leads (Lead Radar's capture table) is a single shared, platform-wide
// feed with no user_id column — see the comment on migration 027. These
// routes read that shared pool but track each user's own contacted/drafted/
// converted progress in the separate sales_lead_pipeline table, scoped
// strictly by user_id, so Lead Radar's own capture/scoring status is never
// touched.
var SALES_LEAD_STATUSES = ["new", "drafted", "contacted", "replied", "converted"];

// Attaches this user's sales_lead_pipeline status/last_draft onto each lead
// (defaulting to "new" for leads this user hasn't touched yet).
async function annotateLeadsWithSalesPipeline(userId, leads) {
  if (!leads.length) return leads;

  var pipelineResult = await supabase
    .from("sales_lead_pipeline")
    .select("lead_post_uri, status, last_draft, updated_at")
    .eq("user_id", userId);

  var pipelineByUri = {};
  (pipelineResult.error ? [] : (pipelineResult.data || [])).forEach(function (row) {
    pipelineByUri[row.lead_post_uri] = row;
  });

  return leads.map(function (lead) {
    var pipeline = pipelineByUri[lead.post_uri];
    return Object.assign({}, lead, {
      sales_status: pipeline ? pipeline.status : "new",
      sales_last_draft: pipeline ? pipeline.last_draft : null,
      sales_pipeline_updated_at: pipeline ? pipeline.updated_at : null
    });
  });
}

// GET /api/agents/sales/leads — the Sales Agent's view of Lead Radar's
// captured leads, annotated with this user's own pipeline status. Optional
// filters: min_score, high_intent=true (score >= 60), buyer=true (has a
// suggested product and score >= 40 — mirrors lead-radar.html's own
// buyer-vs-competitor heuristic).
// exclude_contacted=true additionally drops any lead already contacted/
// replied/converted for this user — opt-in, so the existing "Live Leads"
// display (which shows every lead with its status badge) is unaffected;
// an automated conversion loop can pass this to get only fresh candidates.
app.get("/api/agents/sales/leads", requireAuth, async function (req, res, next) {
  try {
    var userId = req.user.id;
    var minScore = Number(req.query.min_score);
    var buyerOnly = String(req.query.buyer || "").toLowerCase() === "true";
    var highIntentOnly = String(req.query.high_intent || "").toLowerCase() === "true";
    var excludeContacted = String(req.query.exclude_contacted || "").toLowerCase() === "true";

    var query = supabase
      .from("bsky_leads")
      .select("*")
      .eq("status", "scored")
      .order("intent_score", { ascending: false })
      .limit(200);

    if (Number.isFinite(minScore)) {
      query = query.gte("intent_score", minScore);
    }
    if (highIntentOnly) {
      query = query.gte("intent_score", 60);
    }
    if (buyerOnly) {
      query = query.neq("suggested_product", "none").gte("intent_score", 40);
    }

    var leadsResult = await query;
    if (leadsResult.error) {
      throw leadsResult.error;
    }

    var enrichedLeads = await annotateLeadsWithSalesPipeline(userId, leadsResult.data || []);

    if (excludeContacted) {
      enrichedLeads = enrichedLeads.filter(function (lead) {
        return lead.sales_status !== "contacted" && lead.sales_status !== "replied" && lead.sales_status !== "converted";
      });
    }

    return res.json({ leads: enrichedLeads });
  } catch (error) {
    console.error("[sales/leads] Error:", error.message || error);
    next(error);
  }
});

// Truncates to Bluesky's 300-grapheme post limit, safely (counts Unicode
// code points via Array.from so surrogate-pair characters aren't split).
function truncateToBlueskyLimit(text) {
  var str = String(text || "");
  var chars = Array.from(str);
  if (chars.length <= 300) return str;
  return chars.slice(0, 297).join("") + "…";
}

// Bluesky reply-send. Gated behind SALES_SEND_LIVE — a NEW flag, entirely
// separate from SALES_AUTOLOOP_DRY_RUN (which only controls AI drafting/
// pipeline bookkeeping). Defaults OFF: unset or any value other than the
// exact string "true" means dry-run — this logs what would have been sent
// and never calls the Bluesky API. Reuses the single authenticated
// BskyAgent exported by leadRadar.js; never creates a second login/session.
async function sendBlueskyReply(lead, replyText) {
  var sendLive = process.env.SALES_SEND_LIVE === "true";
  var handle = lead.author_handle ? "@" + lead.author_handle : (lead.author_did || "unknown");
  var text = truncateToBlueskyLimit(replyText);

  if (!sendLive) {
    console.log("[SEND DRY] Would reply to " + handle + ": " + text);
    return { sent: false, reason: "send_dry" };
  }

  try {
    var loggedIn = await ensureBskyLogin();
    if (!loggedIn) {
      console.error("[SendBluesky] Not logged in, cannot post reply to " + handle);
      return { sent: false, reason: "post_error", error: "bluesky_login_failed" };
    }

    var postRef = { uri: lead.post_uri, cid: lead.post_cid };
    var postResult = await bskyAgent.post({
      text: text,
      reply: { root: postRef, parent: postRef },
      createdAt: new Date().toISOString()
    });

    return { sent: true, uri: postResult && postResult.uri };
  } catch (err) {
    console.error("[SendBluesky] Failed to post reply to " + handle + ":", err.message || err);
    return { sent: false, reason: "post_error", error: err.message || String(err) };
  }
}

// Truncates to Mastodon's default 500-character post limit.
function truncateToMastodonLimit(text) {
  var str = String(text || "");
  var chars = Array.from(str);
  if (chars.length <= 500) return str;
  return chars.slice(0, 497).join("") + "…";
}

// Mastodon reply-send. Gated behind the SAME SALES_SEND_LIVE flag as
// Bluesky — defaults OFF. Reads (MastodonRadar) stay unauthenticated and
// untouched; posting requires a separate MASTODON_ACCESS_TOKEN. Never
// posts without a captured post_id — older leads captured before that
// field existed won't have one.
async function sendMastodonReply(lead, replyText) {
  var sendLive = process.env.SALES_SEND_LIVE === "true";
  var handle = lead.author_handle ? "@" + lead.author_handle : (lead.author_did || "unknown");
  var text = truncateToMastodonLimit(replyText);

  if (!sendLive) {
    console.log("[SEND DRY][mastodon] Would reply to " + handle + ": " + text);
    return { sent: false, reason: "send_dry" };
  }

  if (!lead.post_id) {
    console.warn("[SendMastodon] Missing post_id, cannot reply to " + handle);
    return { sent: false, reason: "missing_post_id" };
  }

  try {
    var instanceHost = String(process.env.MASTODON_INSTANCE || "")
      .replace(/^https?:\/\//i, "")
      .replace(/\/+$/, "");
    var base = "https://" + instanceHost;

    var response = await fetch(base + "/api/v1/statuses", {
      method: "POST",
      headers: {
        "Authorization": "Bearer " + process.env.MASTODON_ACCESS_TOKEN,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        status: text,
        in_reply_to_id: lead.post_id,
        visibility: "public"
      })
    });

    var responseData = await response.json().catch(function () { return null; });

    if (!response.ok) {
      console.error("[SendMastodon] Failed to post reply to " + handle + ": HTTP " + response.status, responseData);
      return { sent: false, reason: "post_error", error: "HTTP " + response.status };
    }

    return { sent: true, uri: (responseData && (responseData.url || responseData.uri)) || null };
  } catch (err) {
    console.error("[SendMastodon] Failed to post reply to " + handle + ":", err.message || err);
    return { sent: false, reason: "post_error", error: err.message || String(err) };
  }
}

// POST /api/agents/sales/convert — generates a ready-to-send conversion
// package (outreach message, offer, CTA) for one lead (lead_post_uri) or a
// filtered segment (segment: { min_score, high_intent, buyer }, capped to
// 10 leads per call). Inherits platform knowledge + the Sales Agent role +
// this user's business_profile (competitors, website) via
// buildAgentSystemPrompt, same as every other agent route.
// Runs the Sales Agent's conversion pass for exactly one lead: builds the
// per-lead prompt, calls the model, and logs the result. When dryRun is
// true, the ai_tasks/agent_memory rows are still written (clearly tagged
// "[DRY RUN]" / status "dry_run") but sales_lead_pipeline is left
// completely untouched, so the same lead can be safely re-run later.
async function convertSingleLead(userId, lead, sharedSystemPrompt, dryRun) {
  var handle = lead.author_handle ? "@" + lead.author_handle : (lead.author_did || "unknown");

  var leadBlock =
    "CAPTURED LEAD (from Lead Radar):\n" +
    "Handle: " + handle + "\n" +
    "Post: " + (lead.post_text || "") + "\n" +
    "Matched keyword: " + (lead.matched_keyword || "") + "\n" +
    "Intent score: " + (lead.intent_score != null ? lead.intent_score : "unscored") + "\n" +
    "Intent reason: " + (lead.intent_reason || "") + "\n" +
    "Suggested product interest: " + (lead.suggested_product || "none");

  var taskInstruction =
    "Write a lead-conversion package for the captured lead above. Return STRICT JSON and nothing else — no markdown, no preamble, no code fences, no ``` blocks, no text before or after the JSON object. Return exactly this shape: " +
    "{\"outreach_message\": \"...\", \"internal_analysis\": \"...\"}\n" +
    "outreach_message: the complete, ready-to-post PUBLIC reply — plain text only, no markdown headers, no labels, no notes. This is exactly what gets posted publicly as a reply. Warm, human, peer-to-peer, speaking directly to what this specific person expressed, matching their exact pain point or stated interest; sound like a real person, not a marketer, no hashtags or hype. Must use structure-function language only, such as \"supports healthy libido,\" \"supports energy and male vitality,\" or \"traditionally used for.\" NEVER make disease claims — never say it cures, treats, prevents, restores, fixes, or diagnoses anything (no curing ED, no curing low libido, no fixing anything). Never say \"no side effects,\" \"guaranteed,\" or \"solutions that work.\" Never compare it to a named prescription drug (Viagra, Cialis, or similar). If referencing a testimonial or personal result, frame it explicitly as one person's experience, not proof or a guarantee. Keep a soft, honest, low-pressure tone. Must be under 280 characters so it fits a single Bluesky post. No hashtag spam. May mention MrEarthRose.com naturally at most once. " +
    "internal_analysis: the strategy notes, intent score reasoning, offer framing (which product/offer fits and why), the call-to-action, and a next-step/email-nurture recommendation — everything that is NOT the public message. This is for the operator's eyes only and is never posted. " +
    "Return ONLY valid JSON — no ``` fences, no explanation before or after the JSON object.";

  var finalPrompt =
    sharedSystemPrompt +
    "\n\n" + leadBlock +
    "\n\nTASK INSTRUCTIONS:\n" + taskInstruction +
    "\n\nUSER REQUEST:\nConvert this Lead Radar capture into the JSON conversion package described above.";

  var generation = await callAnthropicText(finalPrompt, 700);
  var output = generation.text;

  // Parse the model's strict-JSON response into the clean public reply
  // (cleanMessage) vs. operator-only strategy notes (analysis). A malformed
  // response must never fall back to posting the raw blob — cleanMessage
  // stays null and the lead is simply held as draft-only.
  var cleanMessage = null;
  var analysis = null;
  try {
    var jsonText = String(output || "").trim()
      .replace(/^```(?:json)?\s*/i, "")
      .replace(/```\s*$/i, "")
      .trim();
    var parsedDraft = JSON.parse(jsonText);
    cleanMessage = typeof parsedDraft.outreach_message === "string" && parsedDraft.outreach_message.trim()
      ? parsedDraft.outreach_message.trim()
      : null;
    analysis = typeof parsedDraft.internal_analysis === "string" ? parsedDraft.internal_analysis.trim() : null;
    if (!cleanMessage) {
      console.warn("[Draft] JSON parse failed, holding lead as draft-only");
    }
  } catch (parseErr) {
    console.warn("[Draft] JSON parse failed, holding lead as draft-only");
    cleanMessage = null;
    analysis = null;
  }

  // Attempt the real send (if applicable) BEFORE recording any status
  // below, so the recorded status reflects what actually happened instead
  // of assuming success the moment a draft is generated. Dry runs never
  // attempt a send. Dispatches by lead.source; sources with no sender yet
  // (youtube, etc.) are draft-only and never reach a sender function.
  var sendResult = null;
  if (!dryRun) {
    if (!cleanMessage) {
      console.warn("[sales/convert] Skipping send for " + handle + " — no clean message available.");
      sendResult = { sent: false, reason: "send_dry" };
    } else if (lead.source === "bluesky") {
      try {
        sendResult = await sendBlueskyReply(lead, cleanMessage);
      } catch (sendErr) {
        console.error("[sales/convert] sendBlueskyReply error:", sendErr.message || sendErr);
        sendResult = { sent: false, reason: "post_error", error: sendErr.message || String(sendErr) };
      }
    } else if (lead.source === "mastodon") {
      try {
        sendResult = await sendMastodonReply(lead, cleanMessage);
      } catch (sendErr) {
        console.error("[sales/convert] sendMastodonReply error:", sendErr.message || sendErr);
        sendResult = { sent: false, reason: "post_error", error: sendErr.message || String(sendErr) };
      }
    } else {
      sendResult = { sent: false, reason: "unsupported_source" };
    }
  }

  // ai_tasks.status is what the Live Activity feed reads for its badge —
  // it must tell the truth: "sent" only when a real post succeeded,
  // "send_failed" when a real attempt errored, "drafted" for dry runs,
  // no-clean-message holds, and any source with no sender (unsupported_source).
  var conversionStatus;
  if (dryRun) {
    conversionStatus = "dry_run";
  } else if (sendResult && sendResult.sent) {
    conversionStatus = "sent";
  } else if (sendResult && sendResult.reason === "post_error") {
    conversionStatus = "send_failed";
  } else {
    conversionStatus = "drafted";
  }

  var taskInsert = await supabase
    .from("ai_tasks")
    .insert({
      user_id: userId,
      agent_type: "sales",
      prompt: (dryRun ? "[DRY RUN] " : "") + "Sales convert: " + handle,
      result: output,
      status: conversionStatus
    })
    .select("*")
    .single();

  if (taskInsert.error) {
    console.error("[sales/convert] ai_tasks insert failed:", taskInsert.error.message);
  }

  try {
    var memTimestamp = nowIso();
    var memContent = truncateOrchestratorPreview(output, 2000) || "Lead conversion drafted with no captured output.";

    var memInsert = await supabase
      .from("agent_memory")
      .insert({
        user_id: userId,
        agent: "sales",
        agent_type: "sales",
        memory_key: (dryRun ? "sales_convert_dryrun_" : "sales_convert_") + (taskInsert.data ? taskInsert.data.id : Date.now()),
        memory_value: memContent,
        memory_type: "insight",
        title: (dryRun ? "[DRY RUN] " : "") + "Converted lead: " + handle,
        content: memContent,
        metadata: normalizeMemoryMetadata({ source: "sales_convert", lead_post_uri: lead.post_uri, dry_run: dryRun }),
        created_at: memTimestamp,
        updated_at: memTimestamp
      });

    if (memInsert.error) {
      console.error("[sales/convert] agent_memory write failed:", memInsert.error.message);
    }
  } catch (memErr) {
    console.error("[sales/convert] agent_memory write error:", memErr.message || memErr);
  }

  if (!dryRun) {
    // Bump this user's pipeline status new -> drafted (never downgrade a
    // lead that's already further along, e.g. already contacted).
    try {
      var existingPipeline = await supabase
        .from("sales_lead_pipeline")
        .select("status")
        .eq("user_id", userId)
        .eq("lead_post_uri", lead.post_uri)
        .maybeSingle();

      var pipelineTimestamp = nowIso();
      var richDraft = cleanMessage
        ? cleanMessage + "\n\n---\nInternal notes:\n" + (analysis || "(none)")
        : output;
      var draftPreview = truncateOrchestratorPreview(richDraft, 4000);

      if (!existingPipeline.data || existingPipeline.data.status === "new") {
        var pipelineUpsert = await supabase
          .from("sales_lead_pipeline")
          .upsert({
            user_id: userId,
            lead_post_uri: lead.post_uri,
            status: "drafted",
            last_draft: draftPreview,
            updated_at: pipelineTimestamp
          }, { onConflict: "user_id,lead_post_uri" });

        if (pipelineUpsert.error) {
          console.error("[sales/convert] pipeline upsert failed:", pipelineUpsert.error.message);
        }
      } else {
        var pipelineUpdate = await supabase
          .from("sales_lead_pipeline")
          .update({ last_draft: draftPreview, updated_at: pipelineTimestamp })
          .eq("user_id", userId)
          .eq("lead_post_uri", lead.post_uri);

        if (pipelineUpdate.error) {
          console.error("[sales/convert] pipeline update failed:", pipelineUpdate.error.message);
        }
      }

      // Only bump to "contacted" (this schema's real-send status) when the
      // send above actually succeeded, for any source — never on dry-run
      // or error.
      if (sendResult && sendResult.sent) {
        var contactedTimestamp = nowIso();
        var contactedUpdate = await supabase
          .from("sales_lead_pipeline")
          .update({ status: "contacted", updated_at: contactedTimestamp })
          .eq("user_id", userId)
          .eq("lead_post_uri", lead.post_uri);

        if (contactedUpdate.error) {
          console.error("[sales/convert] Failed to mark lead contacted:", contactedUpdate.error.message);
        }
      }
    } catch (pipelineErr) {
      console.error("[sales/convert] pipeline tracking error:", pipelineErr.message || pipelineErr);
    }
  }

  return output;
}

// Automatic Sales Agent conversion pass — for every user with a business
// profile, computes their context once, finds their freshest high-intent
// leads (excluding anyone already contacted/replied/converted), and runs
// convertSingleLead() on up to 5 of them. NOT wired into any interval yet.
// Controlled by SALES_AUTOLOOP_DRY_RUN — defaults to dry-run ON unless the
// env var is exactly the string "false".
async function runSalesAutoConvert() {
  var dryRun = process.env.SALES_AUTOLOOP_DRY_RUN !== "false";

  try {
    var profilesResult = await supabase.from("business_profiles").select("user_id");
    if (profilesResult.error) {
      console.error("[SalesAutoConvert] Failed to load business profiles:", profilesResult.error.message);
      return;
    }

    var userIds = (profilesResult.data || [])
      .map(function (row) { return row.user_id; })
      .filter(Boolean);

    console.log("[SalesAutoConvert] Starting pass — " + (dryRun ? "DRY RUN" : "LIVE") + " — " + userIds.length + " user(s) with a business profile.");

    for (var u = 0; u < userIds.length; u++) {
      var userId = userIds[u];
      var convertedCount = 0;

      try {
        var profileResult = await supabase
          .from("business_profiles")
          .select("*")
          .eq("user_id", userId)
          .single();
        var businessProfile = profileResult.data || {};

        var liveStats = {};
        try {
          liveStats = await getLiveStats(userId);
        } catch (statsErr) {
          console.error("[SalesAutoConvert] getLiveStats failed for user " + userId + ":", statsErr.message || statsErr);
        }

        var agentMemoryResult = await supabase
          .from("agent_memory")
          .select("agent_type, memory_type, title, content, created_at")
          .eq("user_id", userId)
          .eq("agent_type", "sales")
          .order("created_at", { ascending: false })
          .limit(5);

        var memoriesForBrain = (agentMemoryResult.error ? [] : (agentMemoryResult.data || [])).map(function (row) {
          return { agent_type: row.agent_type, title: row.title || row.memory_type, content: row.content };
        });

        var sharedSystemPrompt = buildAgentSystemPrompt(SALES_AGENT_BRAIN, businessProfile, liveStats, memoriesForBrain);

        var excludedUris = [];
        try {
          var excludedResult = await supabase
            .from("sales_lead_pipeline")
            .select("lead_post_uri")
            .eq("user_id", userId)
            .in("status", ["contacted", "replied", "converted"]);

          if (!excludedResult.error) {
            excludedUris = (excludedResult.data || []).map(function (row) { return row.lead_post_uri; });
          } else {
            console.error("[SalesAutoConvert] Failed to load already-contacted leads for user " + userId + ":", excludedResult.error.message);
          }
        } catch (excludeErr) {
          console.error("[SalesAutoConvert] Failed to load already-contacted leads for user " + userId + ":", excludeErr.message || excludeErr);
        }

        var leadsResult = await supabase
          .from("bsky_leads")
          .select("*")
          .eq("status", "scored")
          .gte("intent_score", 60)
          .order("intent_score", { ascending: false })
          .limit(20);

        if (leadsResult.error) {
          console.error("[SalesAutoConvert] Failed to load leads for user " + userId + ":", leadsResult.error.message);
          continue;
        }

        var freshLeads = (leadsResult.data || [])
          .filter(function (lead) { return excludedUris.indexOf(lead.post_uri) === -1; })
          .slice(0, 5);

        for (var i = 0; i < freshLeads.length; i++) {
          try {
            await convertSingleLead(userId, freshLeads[i], sharedSystemPrompt, dryRun);
            convertedCount++;
          } catch (leadErr) {
            console.error("[SalesAutoConvert] Failed to convert lead " + freshLeads[i].post_uri + " for user " + userId + ":", leadErr.message || leadErr);
          }
        }

        console.log("[SalesAutoConvert] user " + userId + ": converted " + convertedCount + " lead(s) — " + (dryRun ? "DRY RUN" : "LIVE"));
      } catch (userErr) {
        console.error("[SalesAutoConvert] Error processing user " + userId + ":", userErr.message || userErr);
      }
    }

    console.log("[SalesAutoConvert] Pass complete.");
  } catch (err) {
    console.error("[SalesAutoConvert] runSalesAutoConvert error:", err.message || err);
  }
}

app.post("/api/agents/sales/convert", requireAuth, requireActiveSubscription, aiLimiter, async function (req, res, next) {
  try {
    var userId = req.user.id;
    var leadPostUri = safeText(req.body.lead_post_uri, 500);
    var segment = (req.body.segment && typeof req.body.segment === "object" && !Array.isArray(req.body.segment))
      ? req.body.segment : null;

    var targetLeads = [];

    if (leadPostUri) {
      var singleResult = await supabase
        .from("bsky_leads")
        .select("*")
        .eq("post_uri", leadPostUri)
        .single();

      if (singleResult.error || !singleResult.data) {
        return res.status(404).json({ error: "Lead not found." });
      }
      targetLeads = [singleResult.data];
    } else if (segment) {
      var excludedUris = [];
      try {
        var excludedResult = await supabase
          .from("sales_lead_pipeline")
          .select("lead_post_uri")
          .eq("user_id", userId)
          .in("status", ["contacted", "replied", "converted"]);

        if (!excludedResult.error) {
          excludedUris = (excludedResult.data || []).map(function (row) { return row.lead_post_uri; });
        } else {
          console.error("[sales/convert] Failed to load already-contacted leads:", excludedResult.error.message);
        }
      } catch (excludeErr) {
        console.error("[sales/convert] Failed to load already-contacted leads:", excludeErr.message || excludeErr);
      }

      var segQuery = supabase
        .from("bsky_leads")
        .select("*")
        .eq("status", "scored")
        .order("intent_score", { ascending: false })
        .limit(40);

      var segMinScore = Number(segment.min_score);
      if (Number.isFinite(segMinScore)) segQuery = segQuery.gte("intent_score", segMinScore);
      if (segment.high_intent) segQuery = segQuery.gte("intent_score", 60);
      if (segment.buyer) segQuery = segQuery.neq("suggested_product", "none").gte("intent_score", 40);

      var segResult = await segQuery;
      if (segResult.error) {
        throw segResult.error;
      }
      targetLeads = (segResult.data || [])
        .filter(function (lead) { return excludedUris.indexOf(lead.post_uri) === -1; })
        .slice(0, 10);
    } else {
      return res.status(400).json({ error: "Provide lead_post_uri or a segment filter." });
    }

    if (!targetLeads.length) {
      return res.status(404).json({ error: "No matching leads found." });
    }

    var profileResult = await supabase
      .from("business_profiles")
      .select("*")
      .eq("user_id", userId)
      .single();
    var businessProfile = profileResult.data || {};

    var liveStats = {};
    try {
      liveStats = await getLiveStats(userId);
    } catch (statsErr) {
      console.error("[sales/convert] getLiveStats failed:", statsErr.message || statsErr);
    }

    var agentMemoryResult = await supabase
      .from("agent_memory")
      .select("agent_type, memory_type, title, content, created_at")
      .eq("user_id", userId)
      .eq("agent_type", "sales")
      .order("created_at", { ascending: false })
      .limit(5);

    var memoriesForBrain = (agentMemoryResult.error ? [] : (agentMemoryResult.data || [])).map(function (row) {
      return { agent_type: row.agent_type, title: row.title || row.memory_type, content: row.content };
    });

    var sharedSystemPrompt = buildAgentSystemPrompt(SALES_AGENT_BRAIN, businessProfile, liveStats, memoriesForBrain);
    var results = [];

    for (var i = 0; i < targetLeads.length; i++) {
      var lead = targetLeads[i];
      var handle = lead.author_handle ? "@" + lead.author_handle : (lead.author_did || "unknown");
      var output = await convertSingleLead(userId, lead, sharedSystemPrompt, false);

      results.push({
        lead_post_uri: lead.post_uri,
        handle: handle,
        conversion: output
      });
    }

    return res.json({ success: true, results: results });
  } catch (error) {
    console.error("[sales/convert] Error:", error);
    next(error);
  }
});

// POST /api/agents/sales/lead-status — mark a lead contacted/replied/
// converted (or back to drafted), scoped strictly to the authenticated
// user_id. Logs the change to ai_tasks and agent_memory (agent_type "sales").
app.post("/api/agents/sales/lead-status", requireAuth, async function (req, res, next) {
  try {
    var userId = req.user.id;
    var leadPostUri = safeText(req.body.lead_post_uri, 500);
    var status = String(req.body.status || "").toLowerCase().trim();

    if (!leadPostUri) {
      return res.status(400).json({ error: "lead_post_uri is required." });
    }
    if (SALES_LEAD_STATUSES.indexOf(status) === -1) {
      return res.status(400).json({ error: "status must be one of: " + SALES_LEAD_STATUSES.join(", ") });
    }

    var timestamp = nowIso();
    var upsertResult = await supabase
      .from("sales_lead_pipeline")
      .upsert({
        user_id: userId,
        lead_post_uri: leadPostUri,
        status: status,
        updated_at: timestamp
      }, { onConflict: "user_id,lead_post_uri" })
      .select("*")
      .single();

    if (upsertResult.error) {
      throw upsertResult.error;
    }

    try {
      var taskInsert = await supabase
        .from("ai_tasks")
        .insert({
          user_id: userId,
          agent_type: "sales",
          prompt: "Lead status update: " + leadPostUri,
          result: "Marked as " + status,
          status: "completed"
        });
      if (taskInsert.error) {
        console.error("[sales/lead-status] ai_tasks insert failed:", taskInsert.error.message);
      }

      var memTimestamp = nowIso();
      var memInsert = await supabase
        .from("agent_memory")
        .insert({
          user_id: userId,
          agent: "sales",
          agent_type: "sales",
          memory_key: "sales_lead_status_" + leadPostUri + "_" + Date.now(),
          memory_value: "Lead marked as " + status,
          memory_type: "insight",
          title: "Lead status: " + status,
          content: "Lead " + leadPostUri + " marked as " + status,
          metadata: normalizeMemoryMetadata({ source: "sales_lead_status", lead_post_uri: leadPostUri, status: status }),
          created_at: memTimestamp,
          updated_at: memTimestamp
        });
      if (memInsert.error) {
        console.error("[sales/lead-status] agent_memory write failed:", memInsert.error.message);
      }
    } catch (logErr) {
      console.error("[sales/lead-status] logging error:", logErr.message || logErr);
    }

    return res.json({ success: true, pipeline: upsertResult.data });
  } catch (error) {
    console.error("[sales/lead-status] Error:", error);
    next(error);
  }
});

// GET /api/agents/sales/pipeline — this user's tracked leads grouped by
// sales_lead_pipeline status, joined back to bsky_leads for display data.
// Strictly scoped to the authenticated user_id.
app.get("/api/agents/sales/pipeline", requireAuth, async function (req, res, next) {
  try {
    var userId = req.user.id;

    var pipelineResult = await supabase
      .from("sales_lead_pipeline")
      .select("*")
      .eq("user_id", userId)
      .order("updated_at", { ascending: false });

    if (pipelineResult.error) {
      throw pipelineResult.error;
    }

    var pipelineRows = pipelineResult.data || [];
    var postUris = pipelineRows.map(function (row) { return row.lead_post_uri; });

    var leadsByUri = {};
    if (postUris.length) {
      var leadsResult = await supabase
        .from("bsky_leads")
        .select("*")
        .in("post_uri", postUris);

      if (!leadsResult.error) {
        (leadsResult.data || []).forEach(function (lead) { leadsByUri[lead.post_uri] = lead; });
      }
    }

    var grouped = {};
    SALES_LEAD_STATUSES.forEach(function (status) { grouped[status] = []; });

    pipelineRows.forEach(function (row) {
      var bucket = grouped[row.status] || (grouped[row.status] = []);
      bucket.push({
        lead_post_uri: row.lead_post_uri,
        status: row.status,
        last_draft: row.last_draft,
        updated_at: row.updated_at,
        lead: leadsByUri[row.lead_post_uri] || null
      });
    });

    return res.json({ pipeline: grouped });
  } catch (error) {
    console.error("[sales/pipeline] Error:", error);
    next(error);
  }
});

app.post("/api/sms/inbound", async function (req, res) {
  var from = (req.body.From || "").trim().replace(/^\+/, "");
  var body = (req.body.Body || "").trim().toUpperCase();

  var STOP_WORDS  = ["STOP", "STOPALL", "UNSUBSCRIBE", "CANCEL", "END", "QUIT"];
  var START_WORDS = ["START", "YES", "UNSTOP"];

  if (from) {
    if (STOP_WORDS.indexOf(body) !== -1) {
      await supabase
        .from("sms_subscribers")
        .update({ consent_status: "opted_out" })
        .eq("phone_number", from);
    } else if (START_WORDS.indexOf(body) !== -1) {
      await supabase
        .from("sms_subscribers")
        .update({ consent_status: "opted_in" })
        .eq("phone_number", from);
    }
  }

  res.set("Content-Type", "text/xml");
  return res.status(200).send('<?xml version="1.0" encoding="UTF-8"?><Response></Response>');
});

app.use(function (req, res) {
  return res.status(404).json({
    error: "Route not found",
    path: req.path
  });
});

app.use(function (error, req, res, next) {
  console.error("Server error [%s %s]:", req.method, req.path, {
    message: error.message,
    code: error.code,
    details: error.details,
    hint: error.hint,
    stack: error.stack
  });

  const status = error.status || error.statusCode || 500;

  return res.status(status).json({
    error: status === 500 ? "Internal server error" : error.message,
    db_message: error.message || undefined,
    db_code: error.code || undefined,
    db_hint: error.hint || error.details || undefined
  });
});
var dripSchedulerRunning = false;

async function dripTick() {
  if (dripSchedulerRunning) {
    console.log("[dripScheduler] Tick skipped — previous run still in progress");
    return;
  }
  dripSchedulerRunning = true;
  try {
    await runDripForAllUsers();
  } finally {
    dripSchedulerRunning = false;
  }
}

setInterval(dripTick, 300000);
dripTick();

// Sales Agent auto-conversion timer — Option A: wired directly here in
// server.js, completely independent of leadRadar.js's radarTick/5-minute
// cycle (not touching that file at all). Reentrancy guard mirrors
// leadRadar.js's own radarRunning pattern.
//
// SALES_AUTOLOOP_DRY_RUN is not set in .env yet, so runSalesAutoConvert()'s
// own dryRun check (`process.env.SALES_AUTOLOOP_DRY_RUN !== "false"`)
// defaults to true — this timer will run in DRY RUN mode (outreach is
// generated and ai_tasks/agent_memory rows are written, clearly tagged
// "[DRY RUN]" / status "dry_run", but sales_lead_pipeline is left
// untouched) until SALES_AUTOLOOP_DRY_RUN=false is explicitly added to
// the environment.
var salesAutoConvertRunning = false;

async function salesAutoConvertTick() {
  if (salesAutoConvertRunning) {
    console.log("[SalesAutoConvert] Tick skipped — previous run still in progress");
    return;
  }
  salesAutoConvertRunning = true;
  console.log("[SalesAutoConvert] Tick starting...");
  try {
    await runSalesAutoConvert();
  } catch (err) {
    console.error("[SalesAutoConvert] Tick error:", err.message || err);
  } finally {
    salesAutoConvertRunning = false;
    console.log("[SalesAutoConvert] Tick finished.");
  }
}

app.listen(PORT, function () {
  console.log("BizForce AI server running on port " + PORT);
  startLeadRadar().catch(function (err) {
    console.error("[LeadRadar] startup error:", err.message || err);
  });

  // Fire once ~60s after boot (so it doesn't compete with startup load),
  // then on its own independent 5-minute interval thereafter. Gated behind
  // ENABLE_AUTO_JOBS (defaults OFF) so this background Claude spend only
  // happens when explicitly opted into — manual /api/agents/sales/convert
  // calls are unaffected, since they call convertSingleLead directly.
  if (process.env.ENABLE_AUTO_JOBS === "true") {
    setTimeout(function () {
      salesAutoConvertTick().catch(function (err) {
        console.error("[SalesAutoConvert] Initial run error:", err.message || err);
      });
    }, 60000);
    setInterval(salesAutoConvertTick, 300000);
  } else {
    console.log("[startup] salesAutoConvertTick disabled (ENABLE_AUTO_JOBS not true)");
  }

  // RedditRadar disabled — Railway datacenter IP blocked by Reddit; revive later via residential proxy
  // startRedditRadar().catch(function (err) {
  //   console.error("[RedditRadar] startup error:", err.message || err);
  // });
});

module.exports = { runSalesAutoConvert };
