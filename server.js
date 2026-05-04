require("dotenv").config();

const express = require("express");

const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const compression = require("compression");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const Stripe = require("stripe");
const Anthropic = require("@anthropic-ai/sdk");
const { createClient } = require("@supabase/supabase-js");

const app = express();

app.set("trust proxy", 1);

const allowedOrigins = [
  "https://bizforceai.net",
  "https://www.bizforceai.net"
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
  seo: "You are the BizForce AI SEO Agent. Produce practical SEO work that improves ranking, local visibility, technical SEO, keywords, metadata, backlinks, and search traffic. Be direct, measurable, and business-focused.",
  sales: "You are the BizForce AI Sales Agent. Produce sales scripts, offers, follow-up systems, objections handling, conversion strategy, and pipeline growth actions. Be direct, measurable, and business-focused.",
  content: "You are the BizForce AI Content Agent. Produce content plans, posts, blogs, hooks, captions, short-form video scripts, and brand messaging that can drive traffic and sales. Be direct, measurable, and business-focused.",
  ads: "You are the BizForce AI Ads Agent. Produce campaign strategy, ad copy, audience ideas, landing page improvements, budget guidance, and ROAS-focused recommendations. Be direct, measurable, and business-focused.",
  reputation: "You are the BizForce AI Reputation Agent. Produce review responses, review generation systems, credibility improvements, trust-building actions, and customer perception strategies. Be direct, measurable, and business-focused.",
  analytics: "You are the BizForce AI Analytics Agent. Analyze KPIs, traffic, revenue, leads, conversion, usage, bottlenecks, and dashboard data. Produce clear actions tied to growth. Be direct, measurable, and business-focused.",
  email: "You are the BizForce AI Email Agent. Produce subject lines, email campaigns, automations, customer follow-up, newsletters, and retention flows. Be direct, measurable, and business-focused.",
  community: "You are the BizForce AI Community Agent. Produce networking, engagement, partnership, referral, group, and customer loyalty strategies. Be direct, measurable, and business-focused.",
  influencer: "You are the BizForce AI Influencer Agent. Produce influencer outreach lists, DM scripts, partnership angles, campaign plans, creator briefs, and performance tracking ideas. Be direct, measurable, and business-focused.",
  operations: "You are the BizForce AI Operations Agent. Produce SOPs, workflow improvements, automation ideas, fulfillment systems, delegation plans, and efficiency upgrades. Be direct, measurable, and business-focused."
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

app.get("/", function (req, res) {
  res.json({
    app: "BizForce AI",
    status: "running",
    production: process.env.NODE_ENV === "production"
  });
});

app.get("/health", function (req, res) {
  res.json({
    ok: true,
    uptime: process.uptime(),
    timestamp: nowIso()
  });
});

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
    
    return res.json({
  user: Object.assign({}, publicUser(req.user), {
    subscription_status: req.user.subscription_status || "free",
    subscription_plan: "starter",
    subscription_active: req.user.subscription_status === "active"
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

app.post("/api/ai/tasks", async (req, res) => {
  try {
    var token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.status(401).json({ error: "No token" });
    }

    var decoded = jwt.verify(token, process.env.JWT_SECRET);
    var userId = decoded.id;

    var prompt = req.body.prompt;
    var agent = req.body.agent || "general";

    if (!prompt) {
      return res.status(400).json({ error: "Missing prompt" });
    }

    const anthropic = new Anthropic({
      apiKey: process.env.ANTHROPIC_API_KEY
    });

    const response = await anthropic.messages.create({
      model: "claude-3-haiku-20240307",
      max_tokens: 500,
      messages: [
        {
          role: "user",
          content: prompt
        }
      ]
    });

    var output = response.content[0].text;

   

    res.json({ result: output });

  } catch (err) {
    console.error("AI TASK ERROR:", err);
    res.status(500).json({ error: err.message || "Internal server error" });
  }
});

app.get("/api/ai/tasks", requireAuth, async function (req, res, next) {
  try {
    const limit = Math.min(Number(req.query.limit || 50), 100);

    const { data, error } = await supabase
      .from("ai_tasks")
      .select("*, agent:ai_agents(id, display_name, type)")
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: false })
      .limit(limit);

    if (error) {
      throw error;
    }

    return res.json({ tasks: data });
  } catch (error) {
    next(error);
  }
});

app.get("/api/ai/tasks/:id", requireAuth, async function (req, res, next) {
  try {
    const { data, error } = await supabase
      .from("ai_tasks")
      .select("*, agent:ai_agents(id, display_name, type)")
      .eq("id", req.params.id)
      .eq("user_id", req.user.id)
      .maybeSingle();

    if (error) {
      throw error;
    }

    if (!data) {
      return res.status(404).json({ error: "Task not found" });
    }

    return res.json({ task: data });
  } catch (error) {
    next(error);
  }
});

app.post("/api/seo/audit", requireAuth, requireActiveSubscription, aiLimiter, async function (req, res, next) {
  try {
    req.body.agent_type = "seo";
    req.body.task_type = "seo_audit";
    req.body.prompt =
      "Run a complete SEO audit for this website: " +
      safeText(req.body.website, 1000) +
      ". Include technical SEO, keywords, local SEO, content gaps, backlink opportunities, ranking issues, and 10 priority actions.";

    return app._router.handle(req, res, next);
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
    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      customer_email: req.user.email,
      line_items: [
        {
          price: "price_1TRu8o157b9npvGC2y4uYNqv",
          quantity: 1
        }
      ],
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
      success_url: "https://bizforceai.net/dashboard.html",
      cancel_url: "https://bizforceai.net/app.html",
      allow_promotion_codes: true
    });

    return res.json({ url: session.url });
  } catch (error) {
    console.error("Stripe checkout error:", error);
    return res.status(500).json({ error: "Stripe checkout failed" });
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

app.use(function (req, res) {
  return res.status(404).json({
    error: "Route not found",
    path: req.path
  });
});

app.use(function (error, req, res, next) {
  console.error("Server error:", error);

  const status = error.status || error.statusCode || 500;

  return res.status(status).json({
    error: status === 500 ? "Internal server error" : error.message,
    details: process.env.NODE_ENV === "production" ? undefined : error.message
  });
});
app.post("/api/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  const sig = req.headers["stripe-signature"];

  let event;

  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error("Webhook signature failed:", err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    // ✅ SUBSCRIPTION CREATED / UPDATED
    if (
      event.type === "customer.subscription.created" ||
      event.type === "customer.subscription.updated"
    ) {
      const subscription = event.data.object;

      const userId = subscription.metadata?.user_id;

if (!userId) {
  console.error("Missing user_id in Stripe metadata", subscription.id);
  return;
}

      if (userId) {
        await supabase
          .from("users")
          .update({
            subscription_status: "active",
            subscription_id: subscription.id,
            updated_at: new Date().toISOString()
          })
          .eq("id", userId);
      }
    }

    // ❌ SUBSCRIPTION CANCELED
    if (event.type === "customer.subscription.deleted") {
      const subscription = event.data.object;

      const userId = subscription.metadata?.user_id;

if (!userId) {
  console.error("Missing user_id in Stripe deleted metadata", subscription.id);
  return;
}

        await supabase
          .from("users")
          .update({
            subscription_status: "free",
            subscription_id: null,
            updated_at: new Date().toISOString()
          })
          .eq("id", userId);
    }

    res.json({ received: true });

  } catch (err) {
    console.error("Webhook processing error:", err);
    res.status(500).send("Webhook handler failed");
  }
});
app.listen(PORT, function () {
  console.log("BizForce AI server running on port " + PORT);
});
