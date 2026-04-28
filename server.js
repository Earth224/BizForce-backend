const express = require("express");
require("dotenv").config();


const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Stripe = require("stripe");
const Anthropic = require("@anthropic-ai/sdk");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 8080;

const requiredEnv = [
  "SUPABASE_URL",
  "SUPABASE_SERVICE_KEY",
  "JWT_SECRET",
  "STRIPE_SECRET_KEY",
  "STRIPE_WEBHOOK_SECRET",
  "ANTHROPIC_API_KEY"
];

for (const key of requiredEnv) {
  if (!process.env[key]) {
    console.warn("Missing environment variable:", key);
  }
}

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY
});

const allowedOrigins = [
  "https://bizforceai.net",
  "https://www.bizforceai.net"
];

app.use(
  helmet({
    crossOriginResourcePolicy: false
  })
);

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("CORS blocked"));
    },
    credentials: true
  })
);

app.post(
  "/api/webhook",
  express.raw({ type: "application/json" }),
  async function (req, res) {
    const sig = req.headers["stripe-signature"];

    let event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error("Stripe webhook signature error:", err.message);
      return res.status(400).send("Webhook Error: " + err.message);
    }

    try {
      if (event.type === "checkout.session.completed") {
        const session = event.data.object;

        const userId = session.metadata && session.metadata.user_id;
        const plan = session.metadata && session.metadata.plan;

        if (userId) {
          await supabase
            .from("profiles")
            .update({
              subscription_status: "active",
              subscription_plan: plan || "paid",
              stripe_customer_id: session.customer || null,
              updated_at: new Date().toISOString()
            })
            .eq("id", userId);
        }
      }

      if (event.type === "customer.subscription.deleted") {
        const subscription = event.data.object;
        const customerId = subscription.customer;

        if (customerId) {
          await supabase
            .from("profiles")
            .update({
              subscription_status: "canceled",
              updated_at: new Date().toISOString()
            })
            .eq("stripe_customer_id", customerId);
        }
      }

      return res.json({ received: true });
    } catch (err) {
      console.error("Stripe webhook handler error:", err);
      return res.status(500).json({ error: "Webhook handler failed" });
    }
  }
);

app.use(express.json({ limit: "2mb" }));

function signToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email
    },
    process.env.JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

async function authMiddleware(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Missing authorization token" });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const { data: user, error } = await supabase
      .from("users")
      .select("id, email, created_at")
      .eq("id", decoded.id)
      .single();

    if (error || !user) {
      return res.status(401).json({ error: "Invalid token" });
    }

    req.user = user;
    next();
  } catch (err) {
    console.error("Auth error:", err);
    return res.status(401).json({ error: "Unauthorized" });
  }
}

function cleanUser(user) {
  return {
    id: user.id,
    email: user.email,
    created_at: user.created_at
  };
}

const agents = {
  seo: "You are the BizForce AI SEO Agent. Improve search visibility, keywords, metadata, local SEO, backlinks, and ranking strategy.",
  sales: "You are the BizForce AI Sales Agent. Improve offers, funnels, scripts, objections, follow-up, and conversion strategy.",
  content: "You are the BizForce AI Content Agent. Create strong business content, posts, captions, blogs, hooks, and content calendars.",
  ads: "You are the BizForce AI Ads Agent. Improve ad copy, campaign structure, targeting, landing pages, and ROAS.",
  reputation: "You are the BizForce AI Reputation Agent. Improve reviews, responses, trust signals, credibility, and customer perception.",
  analytics: "You are the BizForce AI Analytics Agent. Analyze traffic, revenue, conversion, KPIs, dashboards, and business performance.",
  email: "You are the BizForce AI Email Agent. Create email campaigns, automations, subject lines, and customer follow-up sequences.",
  community: "You are the BizForce AI Community Agent. Build engagement, networking, groups, partnerships, and customer loyalty.",
  influencer: "You are the BizForce AI Influencer Agent. Find outreach angles, influencer scripts, partnership strategy, and creator campaigns.",
  operations: "You are the BizForce AI Operations Agent. Improve workflows, SOPs, fulfillment, systems, delegation, and business efficiency."
};

app.get("/", function (req, res) {
  res.json({
    app: "BizForce AI Backend",
    status: "running"
  });
});

app.get("/health", function (req, res) {
  res.json({
    ok: true,
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

app.post("/api/auth/register", async function (req, res) {
  try {
    const { email, password, business_name, website, full_name } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters" });
    }

    const normalizedEmail = email.toLowerCase().trim();

    const { data: existingUser } = await supabase
      .from("users")
      .select("id")
      .eq("email", normalizedEmail)
      .maybeSingle();

    if (existingUser) {
      return res.status(409).json({ error: "Email already registered" });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const { data: user, error: userError } = await supabase
      .from("users")
      .insert({
        email: normalizedEmail,
        password_hash: passwordHash
      })
      .select("id, email, created_at")
      .single();

    if (userError) {
      throw userError;
    }

    const { data: profile, error: profileError } = await supabase
      .from("profiles")
      .insert({
        id: user.id,
        email: normalizedEmail,
        full_name: full_name || null,
        business_name: business_name || null,
        website: website || null,
        subscription_status: "free"
      })
      .select("*")
      .single();

    if (profileError) {
      throw profileError;
    }

    const token = signToken(user);

    return res.status(201).json({
      token,
      user: cleanUser(user),
      profile
    });
  } catch (err) {
    console.error("Register error:", err);
    return res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/api/auth/login", async function (req, res) {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const normalizedEmail = email.toLowerCase().trim();

    const { data: user, error } = await supabase
      .from("users")
      .select("id, email, password_hash, created_at")
      .eq("email", normalizedEmail)
      .single();

    if (error || !user) {
      return res.status(401).json({ error: "Invalid login" });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);

    if (!validPassword) {
      return res.status(401).json({ error: "Invalid login" });
    }

    const { data: profile } = await supabase
      .from("profiles")
      .select("*")
      .eq("id", user.id)
      .maybeSingle();

    const token = signToken(user);

    return res.json({
      token,
      user: cleanUser(user),
      profile
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ error: "Login failed" });
  }
});

app.get("/api/auth/me", authMiddleware, async function (req, res) {
  try {
    const { data: profile, error } = await supabase
      .from("profiles")
      .select("*")
      .eq("id", req.user.id)
      .maybeSingle();

    if (error) {
      throw error;
    }

    return res.json({
      user: cleanUser(req.user),
      profile
    });
  } catch (err) {
    console.error("Me error:", err);
    return res.status(500).json({ error: "Could not load user" });
  }
});

app.get("/api/profile/:id", authMiddleware, async function (req, res) {
  try {
    const { id } = req.params;

    const { data: profile, error } = await supabase
      .from("profiles")
      .select("*")
      .eq("id", id)
      .single();

    if (error || !profile) {
      return res.status(404).json({ error: "Profile not found" });
    }

    return res.json({ profile });
  } catch (err) {
    console.error("Get profile error:", err);
    return res.status(500).json({ error: "Could not load profile" });
  }
});

app.put("/api/auth/profile", authMiddleware, async function (req, res) {
  try {
    const allowed = [
      "full_name",
      "business_name",
      "website",
      "bio",
      "industry",
      "location",
      "avatar_url",
      "banner_url",
      "phone",
      "social_links"
    ];

    const updates = {};

    for (const key of allowed) {
      if (Object.prototype.hasOwnProperty.call(req.body, key)) {
        updates[key] = req.body[key];
      }
    }

    updates.updated_at = new Date().toISOString();

    const { data: profile, error } = await supabase
      .from("profiles")
      .update(updates)
      .eq("id", req.user.id)
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    return res.json({ profile });
  } catch (err) {
    console.error("Update profile error:", err);
    return res.status(500).json({ error: "Profile update failed" });
  }
});

app.post("/api/posts", authMiddleware, async function (req, res) {
  try {
    const { content, media_url, post_type } = req.body;

    if (!content && !media_url) {
      return res.status(400).json({ error: "Post content or media is required" });
    }

    const { data: post, error } = await supabase
      .from("posts")
      .insert({
        user_id: req.user.id,
        content: content || null,
        media_url: media_url || null,
        post_type: post_type || "standard"
      })
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    return res.status(201).json({ post });
  } catch (err) {
    console.error("Create post error:", err);
    return res.status(500).json({ error: "Could not create post" });
  }
});

app.get("/api/feed", authMiddleware, async function (req, res) {
  try {
    const limit = Math.min(parseInt(req.query.limit || "25", 10), 100);

    const { data: posts, error } = await supabase
      .from("posts")
      .select("*, profiles:user_id(id, full_name, business_name, avatar_url)")
      .order("created_at", { ascending: false })
      .limit(limit);

    if (error) {
      throw error;
    }

    return res.json({ posts });
  } catch (err) {
    console.error("Feed error:", err);
    return res.status(500).json({ error: "Could not load feed" });
  }
});

app.delete("/api/posts/:id", authMiddleware, async function (req, res) {
  try {
    const { id } = req.params;

    const { error } = await supabase
      .from("posts")
      .delete()
      .eq("id", id)
      .eq("user_id", req.user.id);

    if (error) {
      throw error;
    }

    return res.json({ success: true });
  } catch (err) {
    console.error("Delete post error:", err);
    return res.status(500).json({ error: "Could not delete post" });
  }
});

app.post("/api/follow/:userId", authMiddleware, async function (req, res) {
  try {
    const { userId } = req.params;

    if (userId === req.user.id) {
      return res.status(400).json({ error: "You cannot follow yourself" });
    }

    const { data: follow, error } = await supabase
      .from("follows")
      .upsert(
        {
          follower_id: req.user.id,
          following_id: userId
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

    return res.status(201).json({ follow });
  } catch (err) {
    console.error("Follow error:", err);
    return res.status(500).json({ error: "Could not follow user" });
  }
});

app.delete("/api/follow/:userId", authMiddleware, async function (req, res) {
  try {
    const { userId } = req.params;

    const { error } = await supabase
      .from("follows")
      .delete()
      .eq("follower_id", req.user.id)
      .eq("following_id", userId);

    if (error) {
      throw error;
    }

    return res.json({ success: true });
  } catch (err) {
    console.error("Unfollow error:", err);
    return res.status(500).json({ error: "Could not unfollow user" });
  }
});

app.get("/api/following", authMiddleware, async function (req, res) {
  try {
    const { data, error } = await supabase
      .from("follows")
      .select("*, profiles:following_id(id, full_name, business_name, avatar_url)")
      .eq("follower_id", req.user.id);

    if (error) {
      throw error;
    }

    return res.json({ following: data });
  } catch (err) {
    console.error("Following error:", err);
    return res.status(500).json({ error: "Could not load following" });
  }
});

app.get("/api/followers", authMiddleware, async function (req, res) {
  try {
    const { data, error } = await supabase
      .from("follows")
      .select("*, profiles:follower_id(id, full_name, business_name, avatar_url)")
      .eq("following_id", req.user.id);

    if (error) {
      throw error;
    }

    return res.json({ followers: data });
  } catch (err) {
    console.error("Followers error:", err);
    return res.status(500).json({ error: "Could not load followers" });
  }
});

app.post("/api/messages", authMiddleware, async function (req, res) {
  try {
    const { receiver_id, content } = req.body;

    if (!receiver_id || !content) {
      return res.status(400).json({ error: "Receiver and content are required" });
    }

    const { data: message, error } = await supabase
      .from("messages")
      .insert({
        sender_id: req.user.id,
        receiver_id,
        content
      })
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    return res.status(201).json({ message });
  } catch (err) {
    console.error("Send message error:", err);
    return res.status(500).json({ error: "Could not send message" });
  }
});

app.get("/api/messages/:userId", authMiddleware, async function (req, res) {
  try {
    const { userId } = req.params;

    const { data: messages, error } = await supabase
      .from("messages")
      .select("*")
      .or(
        "and(sender_id.eq." +
          req.user.id +
          ",receiver_id.eq." +
          userId +
          "),and(sender_id.eq." +
          userId +
          ",receiver_id.eq." +
          req.user.id +
          ")"
      )
      .order("created_at", { ascending: true });

    if (error) {
      throw error;
    }

    return res.json({ messages });
  } catch (err) {
    console.error("Messages error:", err);
    return res.status(500).json({ error: "Could not load messages" });
  }
});

app.get("/api/conversations", authMiddleware, async function (req, res) {
  try {
    const { data: messages, error } = await supabase
      .from("messages")
      .select("*")
      .or("sender_id.eq." + req.user.id + ",receiver_id.eq." + req.user.id)
      .order("created_at", { ascending: false });

    if (error) {
      throw error;
    }

    return res.json({ conversations: messages });
  } catch (err) {
    console.error("Conversations error:", err);
    return res.status(500).json({ error: "Could not load conversations" });
  }
});

app.post("/api/deals", authMiddleware, async function (req, res) {
  try {
    const {
      title,
      description,
      amount,
      stage,
      contact_name,
      contact_email,
      expected_close_date
    } = req.body;

    if (!title) {
      return res.status(400).json({ error: "Deal title is required" });
    }

    const { data: deal, error } = await supabase
      .from("deals")
      .insert({
        user_id: req.user.id,
        title,
        description: description || null,
        amount: amount || 0,
        stage: stage || "new",
        contact_name: contact_name || null,
        contact_email: contact_email || null,
        expected_close_date: expected_close_date || null
      })
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    return res.status(201).json({ deal });
  } catch (err) {
    console.error("Create deal error:", err);
    return res.status(500).json({ error: "Could not create deal" });
  }
});

app.get("/api/deals", authMiddleware, async function (req, res) {
  try {
    const { data: deals, error } = await supabase
      .from("deals")
      .select("*")
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: false });

    if (error) {
      throw error;
    }

    return res.json({ deals });
  } catch (err) {
    console.error("Deals error:", err);
    return res.status(500).json({ error: "Could not load deals" });
  }
});

app.put("/api/deals/:id", authMiddleware, async function (req, res) {
  try {
    const { id } = req.params;

    const allowed = [
      "title",
      "description",
      "amount",
      "stage",
      "contact_name",
      "contact_email",
      "expected_close_date"
    ];

    const updates = {};

    for (const key of allowed) {
      if (Object.prototype.hasOwnProperty.call(req.body, key)) {
        updates[key] = req.body[key];
      }
    }

    updates.updated_at = new Date().toISOString();

    const { data: deal, error } = await supabase
      .from("deals")
      .update(updates)
      .eq("id", id)
      .eq("user_id", req.user.id)
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    return res.json({ deal });
  } catch (err) {
    console.error("Update deal error:", err);
    return res.status(500).json({ error: "Could not update deal" });
  }
});

app.delete("/api/deals/:id", authMiddleware, async function (req, res) {
  try {
    const { id } = req.params;

    const { error } = await supabase
      .from("deals")
      .delete()
      .eq("id", id)
      .eq("user_id", req.user.id);

    if (error) {
      throw error;
    }

    return res.json({ success: true });
  } catch (err) {
    console.error("Delete deal error:", err);
    return res.status(500).json({ error: "Could not delete deal" });
  }
});

app.post("/api/stripe/checkout", authMiddleware, async function (req, res) {
  try {
    const { price_id, plan } = req.body;

    if (!price_id) {
      return res.status(400).json({ error: "Stripe price_id is required" });
    }

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      payment_method_types: ["card"],
      line_items: [
        {
          price: price_id,
          quantity: 1
        }
      ],
      success_url: "https://bizforceai.net/dashboard?checkout=success",
      cancel_url: "https://bizforceai.net/pricing?checkout=cancel",
      metadata: {
        user_id: req.user.id,
        plan: plan || "paid"
      }
    });

    return res.json({
      url: session.url,
      session_id: session.id
    });
  } catch (err) {
    console.error("Stripe checkout error:", err);
    return res.status(500).json({ error: "Could not create checkout session" });
  }
});

app.post("/api/ai/:agent", authMiddleware, async function (req, res) {
  try {
    const agentKey = String(req.params.agent || "").toLowerCase();
    const { prompt, business_context } = req.body;

    if (!agents[agentKey]) {
      return res.status(400).json({
        error: "Invalid agent",
        available_agents: Object.keys(agents)
      });
    }

    if (!prompt) {
      return res.status(400).json({ error: "Prompt is required" });
    }

    const { data: profile } = await supabase
      .from("profiles")
      .select("*")
      .eq("id", req.user.id)
      .maybeSingle();

    const businessInfo = {
      profile: profile || null,
      business_context: business_context || null
    };

    const completion = await anthropic.messages.create({
      model: "claude-3-5-sonnet-latest",
      max_tokens: 1200,
      temperature: 0.4,
      system: agents[agentKey],
      messages: [
        {
          role: "user",
          content:
            "Business context:\n" +
            JSON.stringify(businessInfo, null, 2) +
            "\n\nTask:\n" +
            prompt
        }
      ]
    });

    const answer = completion.content
      .map(function (item) {
        return item.text || "";
      })
      .join("\n")
      .trim();

    await supabase.from("agent_logs").insert({
      user_id: req.user.id,
      agent: agentKey,
      prompt,
      response: answer
    });

    return res.json({
      agent: agentKey,
      response: answer
    });
  } catch (err) {
    console.error("AI agent error:", err);
    return res.status(500).json({ error: "AI agent request failed" });
  }
});

app.post("/api/seo/audit", authMiddleware, async function (req, res) {
  try {
    const { website } = req.body;

    if (!website) {
      return res.status(400).json({ error: "Website is required" });
    }

    const completion = await anthropic.messages.create({
      model: "claude-3-5-sonnet-latest",
      max_tokens: 1200,
      temperature: 0.3,
      system: agents.seo,
      messages: [
        {
          role: "user",
          content:
            "Run a practical SEO audit for this business website: " +
            website +
            ". Include technical SEO, local SEO, content, keywords, trust, ranking opportunities, and next actions."
        }
      ]
    });

    const audit = completion.content
      .map(function (item) {
        return item.text || "";
      })
      .join("\n")
      .trim();

    return res.json({ website, audit });
  } catch (err) {
    console.error("SEO audit error:", err);
    return res.status(500).json({ error: "SEO audit failed" });
  }
});

app.use(function (req, res) {
  return res.status(404).json({
    error: "Route not found",
    path: req.path
  });
});

app.use(function (err, req, res, next) {
  console.error("Unhandled server error:", err);

  return res.status(500).json({
    error: "Internal server error"
  });
});

app.listen(PORT, function () {
  console.log("BizForce AI backend running on port " + PORT);
});
