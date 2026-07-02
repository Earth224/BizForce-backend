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
const { createClient } = require("@supabase/supabase-js");
const { startLeadRadar } = require("./leadRadar");
const { startRedditRadar } = require("./redditRadar");

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

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || "", {
  apiVersion: "2024-06-20"
});

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY || ""
});

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

app.post(
  "/api/webhook",
  express.raw({ type: "application/json" }),
  async function (req, res) {
    const signature = req.headers["stripe-signature"];

    let event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        signature,
        process.env.STRIPE_WEBHOOK_SECRET
      );
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
  "executive"
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
  analytics: "executive"
};

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
    collaboration_created: false
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
        read: false,
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

async function callAnthropicText(promptText, maxTokens) {
  var anthropicClient = new Anthropic({
    apiKey: process.env.ANTHROPIC_API_KEY,
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
    var allowedTaskTypes = ["general", "executive_plan", "agent_coordination", "seo_audit", "sales_funnel", "content_plan", "social_content", "social_calendar", "ad_campaign", "reputation_plan", "analytics_report", "email_campaign", "community_growth", "influencer_outreach", "operations_workflow", "store_plan", "etsy_store_plan", "publicist_pitch", "broker_opportunity", "crm_followup", "security_review", "finance_plan", "legal_template", "research_report", "deal_pipeline", "partnership_strategy", "negotiation_brief", "due_diligence", "term_sheet", "community_plan", "engagement_strategy", "referral_loop", "retention_system", "moderation_plan", "email_sequence", "winback_flow", "nurture_campaign", "subject_lines", "campaign_plan", "partnership_offer", "creator_list", "roi_forecast", "operations_sop", "workflow_plan", "automation_plan", "checklist_build", "efficiency_audit", "press_release", "media_outreach", "pr_campaign", "brand_narrative", "media_pitch", "market_research", "competitive_intel", "trend_analysis", "innovation_brief", "executive_briefing", "reputation_audit", "review_strategy", "brand_trust", "crisis_response", "sentiment_report", "store_audit", "inventory_plan", "omnichannel_strategy", "conversion_audit", "product_launch", "etsy_listing", "shop_audit", "keyword_research", "pricing_strategy", "competitor_analysis"];
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

var businessContext = `
BUSINESS PROFILE:
Business Name: ${businessProfile.business_name || "Not Provided"}
Industry: ${businessProfile.industry || "Not Provided"}
Website: ${businessProfile.website || "Not Provided"}
Description: ${businessProfile.description || "Not Provided"}
Target Audience: ${businessProfile.target_audience || "Not Provided"}
Goals: ${businessProfile.business_goals || "Not Provided"}
Services: ${businessProfile.products_services || "Not Provided"}
Location: ${businessProfile.location || "Not Provided"}
`;
    if (memoryResult.error) {
      throw memoryResult.error;
    }

    var memoryText = (memoryResult.data || []).map(function (task, index) {
      return "Memory " + (index + 1) + ":\nAgent: " + task.agent_type + "\nPrompt: " + task.prompt + "\nResult: " + task.result;
    }).join("\n\n");

    var agentBrains = {
      general: "You are BizForce AI, a senior business execution assistant. Produce clear, practical business outputs.",
      executive: "You are the BizForce AI Executive Coordinator Agent. Act like a chief operating officer for the user's business. Break the user's request into coordinated assignments for SEO, Sales, Content, Ads, Reputation, Analytics, Email, Community, Influencer, and Operations agents. Produce an executive plan with priorities, owners, timelines, KPIs, risks, and next actions.",
      seo: "You are the BizForce AI SEO Agent. Produce technical SEO audits, keyword strategies, local SEO plans, content clusters, and ranking action plans.",
      sales: "You are the BizForce AI Sales Agent. Build offers, sales scripts, funnels, objection handling, upsells, and conversion systems.",
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
    var finalPrompt =
  agentBrain +
  "\n\nBUSINESS PROFILE:\n" + businessContext +
  "\n\nTASK TYPE:\n" + taskType +
  "\n\nTASK INSTRUCTIONS:\n" + taskInstruction +
  "\n\nSAFETY RULES:\n" +
  "- Do not execute purchases, payments, legal filings, tax actions, account creation, or financial transactions.\n" +
  "- For high-risk actions, return requires_approval true and an approval plan.\n" +
  "- Keep outputs lawful, practical, and business-safe.\n" +
  "\n\nAPPROVAL STATUS:\n" + approvalInstruction +
  "\n\nPAST MEMORY:\n" + (memoryText || "No prior memory found.") +
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

    var response = await anthropic.messages.create({
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

app.post("/api/seo/audit", requireAuth, requireActiveSubscription, aiLimiter, async function (req, res, next) {
  req.body.agent_type = "seo";
  req.body.task_type = "seo_audit";
  req.body.prompt =
    "Run a complete SEO audit for this website: " +
    safeText(req.body.website, 1000) +
    ". Include technical SEO, keywords, local SEO, content gaps, backlink opportunities, ranking issues, and 10 priority actions.";
  return handleAiTaskRequest(req, res, next);
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

/* ── Marketplace ── */

const MARKETPLACE_CATEGORIES = ["consulting","design","development","marketing","sales","strategy","operations","other"];

app.get("/api/marketplace/listings", requireAuth, async function (req, res, next) {
  try {
    const category = safeText(req.query.category, 40);
    const q = safeText(req.query.q, 120);
    let query = supabase
      .from("marketplace_listings")
      .select("id, seller_id, title, description, price_bfc, category, tags, status, created_at")
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
    const tags        = Array.isArray(req.body.tags)
      ? req.body.tags.map(function(t) { return safeText(t, 40); }).filter(Boolean).slice(0, 10)
      : [];
    if (!title)    return res.status(400).json({ error: "Title is required" });
    if (!MARKETPLACE_CATEGORIES.includes(category)) return res.status(400).json({ error: "Invalid category" });
    const { data, error } = await supabase
      .from("marketplace_listings")
      .insert({
        seller_id: req.user.id, title, description: description || "",
        price_bfc: priceBfc, category, tags, status: "active",
        created_at: nowIso(), updated_at: nowIso()
      })
      .select("*").single();
    if (error) throw error;
    return res.status(201).json({ listing: data });
  } catch (error) { next(error); }
});

app.put("/api/marketplace/listings/:id", requireAuth, async function (req, res, next) {
  try {
    const updates = { updated_at: nowIso() };
    if (req.body.title       !== undefined) updates.title       = safeText(req.body.title, 150);
    if (req.body.description !== undefined) updates.description = safeText(req.body.description, 2000);
    if (req.body.price_bfc   !== undefined) updates.price_bfc   = Math.max(0, Math.round(Number(req.body.price_bfc) || 0));
    if (req.body.category !== undefined && MARKETPLACE_CATEGORIES.includes(req.body.category)) updates.category = req.body.category;
    if (req.body.status   !== undefined && ["active","paused","sold"].includes(req.body.status)) updates.status = req.body.status;
    if (Array.isArray(req.body.tags)) updates.tags = req.body.tags.map(function(t) { return safeText(t, 40); }).filter(Boolean).slice(0, 10);
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

app.post("/api/leads/draft-reply", requireAuth, async function (req, res, next) {
  try {
    var postText        = String(req.body.post_text        || "").trim();
    var suggestedProduct = String(req.body.suggested_product || "").trim();

    if (!postText) {
      return res.status(400).json({ error: "post_text is required" });
    }

    var prompt =
      "You are helping a small business owner engage authentically on social media.\n" +
      "Write a short, genuine reply (2-3 sentences) to the following post. The reply should sound like a real, helpful person — not a brand or a sales pitch.\n" +
      "If it feels natural, subtly mention how " + (suggestedProduct || "the product") + " might help, but only if it fits the conversation. Never be pushy or salesy.\n\n" +
      "Post: " + postText + "\n\n" +
      "Reply:";

    var response = await anthropic.messages.create({
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

app.listen(PORT, function () {
  console.log("BizForce AI server running on port " + PORT);
  startLeadRadar().catch(function (err) {
    console.error("[LeadRadar] startup error:", err.message || err);
  });
  startRedditRadar().catch(function (err) {
    console.error("[RedditRadar] startup error:", err.message || err);
  });
});
