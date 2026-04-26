const express = require(‘express’);
const cors = require(‘cors’);
const bcrypt = require(‘bcryptjs’);
const jwt = require(‘jsonwebtoken’);
const { createClient } = require(’@supabase/supabase-js’);
const Anthropic = require(’@anthropic-ai/sdk’);
const stripe = require(‘stripe’)(process.env.STRIPE_SECRET_KEY);
const helmet = require(‘helmet’);
const rateLimit = require(‘express-rate-limit’);

const app = express();

// Security
app.use(helmet());
app.use(cors({ origin: ‘*’ }));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use(limiter);

// Stripe webhook needs raw body
app.use(’/api/webhook’, express.raw({ type: ‘application/json’ }));
app.use(express.json());

// Supabase
const supabase = createClient(
process.env.SUPABASE_URL,
process.env.SUPABASE_SERVICE_KEY
);

// Anthropic
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

// JWT middleware
const authenticateToken = (req, res, next) => {
const authHeader = req.headers[‘authorization’];
const token = authHeader && authHeader.split(’ ’)[1];
if (!token) return res.status(401).json({ error: ‘Access denied’ });
try {
const verified = jwt.verify(token, process.env.JWT_SECRET);
req.user = verified;
next();
} catch (err) {
res.status(403).json({ error: ‘Invalid token’ });
}
};

// ============================================
// AUTH ROUTES
// ============================================

// Register
app.post(’/api/auth/register’, async (req, res) => {
const { email, password, business_name, industry } = req.body;
try {
const hashedPassword = await bcrypt.hash(password, 10);
const { data, error } = await supabase
.from(‘users’)
.insert([{ email, password_hash: hashedPassword, business_name, industry }])
.select()
.single();
if (error) return res.status(400).json({ error: error.message });
const token = jwt.sign({ id: data.id, email: data.email }, process.env.JWT_SECRET, { expiresIn: ‘7d’ });
res.json({ token, user: { id: data.id, email: data.email, business_name: data.business_name, industry: data.industry, subscription_status: data.subscription_status } });
} catch (err) {
res.status(500).json({ error: err.message });
}
});

// Login
app.post(’/api/auth/login’, async (req, res) => {
const { email, password } = req.body;
try {
const { data: user, error } = await supabase
.from(‘users’)
.select(’*’)
.eq(‘email’, email)
.single();
if (error || !user) return res.status(400).json({ error: ‘Invalid credentials’ });
const validPassword = await bcrypt.compare(password, user.password_hash);
if (!validPassword) return res.status(400).json({ error: ‘Invalid credentials’ });
const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: ‘7d’ });
res.json({ token, user: { id: user.id, email: user.email, business_name: user.business_name, industry: user.industry, subscription_status: user.subscription_status, bio: user.bio, avatar_url: user.avatar_url } });
} catch (err) {
res.status(500).json({ error: err.message });
}
});

// Get current user
app.get(’/api/auth/me’, authenticateToken, async (req, res) => {
try {
const { data, error } = await supabase
.from(‘users’)
.select(‘id, email, business_name, industry, bio, avatar_url, subscription_status, created_at’)
.eq(‘id’, req.user.id)
.single();
if (error) return res.status(400).json({ error: error.message });
res.json(data);
} catch (err) {
res.status(500).json({ error: err.message });
}
});

// Update profile
app.put(’/api/auth/profile’, authenticateToken, async (req, res) => {
const { business_name, industry, bio, avatar_url } = req.body;
try {
const { data, error } = await supabase
.from(‘users’)
.update({ business_name, industry, bio, avatar_url })
.eq(‘id’, req.user.id)
.select()
.single();
if (error) return res.status(400).json({ error: error.message });
res.json(data);
} catch (err) {
res.status(500).json({ error: err.message });
}
});

// ============================================
// SOCIAL NETWORK ROUTES
// ============================================

// Get feed (posts from followed users + own posts)
app.get(’/api/feed’, authenticateToken, async (req, res) => {
try {
const { data: follows } = await supabase
.from(‘follows’)
.select(‘following_id’)
.eq(‘follower_id’, req.user.id);

```
const followingIds = follows ? follows.map(f => f.following_id) : [];
followingIds.push(req.user.id);

const { data, error } = await supabase
  .from('posts')
  .select(`
    *,
    users (id, business_name, industry, avatar_url)
  `)
  .in('user_id', followingIds)
  .order('created_at', { ascending: false })
  .limit(50);

if (error) return res.status(400).json({ error: error.message });
res.json(data);
```

} catch (err) {
res.status(500).json({ error: err.message });
}
});

// Create post
app.post(’/api/posts’, authenticateToken, async (req, res) => {
const { content } = req.body;
try {
const { data, error } = await supabase
.from(‘posts’)
.insert([{ user_id: req.user.id, content }])
.select(`*, users (id, business_name, industry, avatar_url)`)
.single();
if (error) return res.status(400).json({ error: error.message });
res.json(data);
} catch (err) {
res.status(500).json({ error: err.message });
}
});

// Delete post
app.delete(’/api/posts/:id’, authenticateToken, async (req, res) => {
try {
const { error } = await supabase
.from(‘posts’)
.delete()
.eq(‘id’, req.params.id)
.eq(‘user_id’, req.user.id);
if (error) return res.status(400).json({ error: error.message });
res.json({ success: true });
} catch (err) {
res.status(500).json({ error: err.message });
}
});

// Follow user
app.post(’/api/follow/:id’, authenticateToken, async (req, res) => {
try {
const { error } = await supabase
.from(‘follows’)
.insert([{ follower_id: req.user.id, following_id: req.params.id }]);
if (error) return res.status(400).json({ error: error.message });
res.json({ success: true });
} catch (err) {
res.status(500).json({ error: err.message });
}
});

// Unfollow user
app.delete(’/api/follow/:id’, authenticateToken, async (req, res) => {
try {
const { error } = await supabase
.from(‘follows’)
.delete()
.eq(‘follower_id’, req.user.id)
.eq(‘following_id’, req.params.id);
if (error) return res.status(400).json({ error: error.message });
res.json({ success: true });
} catch (err) {
res.status(500).json({ error: err.message });
}
});

// Get user profile + posts
app.get(’/api/users/:id’, authenticateToken, async (req, res) => {
try {
const { data: user, error } = await supabase
.from(‘users’)
.select(‘id, email, business_name, industry, bio, avatar_url, subscription_status, created_at’)
.eq(‘id’, req.params.id)
.single();
if (error) return res.status(400).json({ error: error.message });

```
const { data: posts } = await supabase
  .from('posts')
  .select('*')
  .eq('user_id', req.params.id)
  .order('created_at', { ascending: false });

const { count: followersCount } = await supabase
  .from('follows')
  .select('*', { count: 'exact', head: true })
  .eq('following_id', req.params.id);

const { count: followingCount } = await supabase
  .from('follows')
  .select('*', { count: 'exact', head: true })
  .eq('follower_id', req.params.id);

const { data: isFollowing } = await supabase
  .from('follows')
  .select('*')
  .eq('follower_id', req.user.id)
  .eq('following_id', req.params.id)
  .single();

res.json({ ...user, posts, followers: followersCount, following: followingCount, is_following: !!isFollowing });
```

} catch (err) {
res.status(500).json({ error: err.message });
}
});

// Search users/businesses
app.get(’/api/search’, authenticateToken, async (req, res) => {
const { q, industry } = req.query;
try {
let query = supabase
.from(‘users’)
.select(‘id, business_name, industry, bio, avatar_url, subscription_status’);

```
if (q) query = query.ilike('business_name', `%${q}%`);
if (industry) query = query.eq('industry', industry);

const { data, error } = await query.limit(20);
if (error) return res.status(400).json({ error: error.message });
res.json(data);
```

} catch (err) {
res.status(500).json({ error: err.message });
}
});

// ============================================
// MESSAGING ROUTES
// ============================================

// Send message
app.post(’/api/messages’, authenticateToken, async (req, res) => {
const { receiver_id, content } = req.body;
try {
const { data, error } = await supabase
.from(‘messages’)
.insert([{ sender_id: req.user.id, receiver_id, content }])
.select()
.single();
if (error) return res.status(400).json({ error: error.message });
res.json(data);
} catch (err) {
res.status(500).json({ error: err.message });
}
});

// Get conversation
app.get(’/api/messages/:userId’, authenticateToken, async (req, res) => {
try {
const { data, error } = await supabase
.from(‘messages’)
.select(`*, sender:users!sender_id(id, business_name, avatar_url)`)
.or(`and(sender_id.eq.${req.user.id},receiver_id.eq.${req.params.userId}),and(sender_id.eq.${req.params.userId},receiver_id.eq.${req.user.id})`)
.order(‘created_at’, { ascending: true });
if (error) return res.status(400).json({ error: error.message });
res.json(data);
} catch (err) {
res.status(500).json({ error: err.message });
}
});

// Get all conversations
app.get(’/api/conversations’, authenticateToken, async (req, res) => {
try {
const { data, error } = await supabase
.from(‘messages’)
.select(`*, sender:users!sender_id(id, business_name, avatar_url), receiver:users!receiver_id(id, business_name, avatar_url)`)
.or(`sender_id.eq.${req.user.id},receiver_id.eq.${req.user.id}`)
.order(‘created_at’, { ascending: false });
if (error) return res.status(400).json({ error: error.message });
res.json(data);
} catch (err) {
res.status(500).json({ error: err.message });
}
});

// ============================================
// DEAL BOARD ROUTES
// ============================================

// Get all deals
app.get(’/api/deals’, authenticateToken, async (req, res) => {
const { type } = req.query;
try {
let query = supabase
.from(‘deals’)
.select(`*, users (id, business_name, industry, avatar_url)`)
.order(‘created_at’, { ascending: false });

```
if (type) query = query.eq('deal_type', type);

const { data, error } = await query.limit(50);
if (error) return res.status(400).json({ error: error.message });
res.json(data);
```

} catch (err) {
res.status(500).json({ error: err.message });
}
});

// Create deal
app.post(’/api/deals’, authenticateToken, async (req, res) => {
const { title, description, deal_type } = req.body;
try {
const { data, error } = await supabase
.from(‘deals’)
.insert([{ user_id: req.user.id, title, description, deal_type }])
.select(`*, users (id, business_name, industry, avatar_url)`)
.single();
if (error) return res.status(400).json({ error: error.message });
res.json(data);
} catch (err) {
res.status(500).json({ error: err.message });
}
});

// Delete deal
app.delete(’/api/deals/:id’, authenticateToken, async (req, res) => {
try {
const { error } = await supabase
.from(‘deals’)
.delete()
.eq(‘id’, req.params.id)
.eq(‘user_id’, req.user.id);
if (error) return res.status(400).json({ error: error.message });
res.json({ success: true });
} catch (err) {
res.status(500).json({ error: err.message });
}
});

// ============================================
// AI STAFF ROUTES (9 Agents)
// ============================================

const AI_STAFF = {
alex: {
name: ‘Alex’,
role: ‘SEO Specialist’,
personality: ‘You are Alex, an expert SEO specialist. You help businesses rank higher in search engines, optimize content, find keywords, and build organic traffic. Be strategic, data-driven, and actionable.’,
},
jordan: {
name: ‘Jordan’,
role: ‘Community Manager’,
personality: ‘You are Jordan, a community management expert. You help businesses build and engage their online communities, manage responses, create engagement strategies, and grow loyal followings.’,
},
morgan: {
name: ‘Morgan’,
role: ‘Content Creator’,
personality: ‘You are Morgan, a creative content specialist. You write blog posts, social media content, email newsletters, product descriptions, and any written content businesses need.’,
},
casey: {
name: ‘Casey’,
role: ‘Email Marketing Expert’,
personality: ‘You are Casey, an email marketing specialist. You craft compelling email campaigns, sequences, subject lines, and help businesses build and monetize their email lists.’,
},
riley: {
name: ‘Riley’,
role: ‘Sales Strategist’,
personality: ‘You are Riley, a sales expert. You help businesses close more deals, craft sales scripts, build funnels, handle objections, and increase conversion rates.’,
},
sam: {
name: ‘Sam’,
role: ‘Reputation Manager’,
personality: ‘You are Sam, a reputation management specialist. You help businesses manage reviews, handle negative feedback, build brand trust, and protect online reputation.’,
},
dana: {
name: ‘Dana’,
role: ‘Analytics Expert’,
personality: ‘You are Dana, a business analytics specialist. You analyze data, identify trends, create reports, and help businesses make data-driven decisions.’,
},
taylor: {
name: ‘Taylor’,
role: ‘Ads Specialist’,
personality: ‘You are Taylor, a paid advertising expert. You help businesses run profitable ad campaigns on Google, Meta, and other platforms, optimize spend, and maximize ROI.’,
},
blake: {
name: ‘Blake’,
role: ‘Influencer Marketing Expert’,
personality: ‘You are Blake, an influencer marketing specialist. You help businesses find the right influencers, negotiate deals, create campaigns, and measure influencer ROI.’,
},
};

// Chat with AI staff member
app.post(’/api/ai/:agent’, authenticateToken, async (req, res) => {
const { agent } = req.params;
const { message, history = [] } = req.body;

const staffMember = AI_STAFF[agent.toLowerCase()];
if (!staffMember) return res.status(400).json({ error: ‘Agent not found’ });

try {
const { data: user } = await supabase
.from(‘users’)
.select(‘subscription_status’)
.eq(‘id’, req.user.id)
.single();

```
const messages = [
  ...history.slice(-10),
  { role: 'user', content: message }
];

const response = await anthropic.messages.create({
  model: 'claude-opus-4-5',
  max_tokens: 1024,
  system: `${staffMember.personality} You work for BizForce AI, a platform that helps businesses grow. The user's business: ${user?.business_name || 'a growing business'}. Be concise, helpful, and always provide actionable advice.`,
  messages,
});

res.json({
  agent: staffMember.name,
  role: staffMember.role,
  response: response.content[0].text,
});
```

} catch (err) {
res.status(500).json({ error: err.message });
}
});

// Get all AI staff info
app.get(’/api/ai/staff/all’, authenticateToken, (req, res) => {
const staff = Object.entries(AI_STAFF).map(([key, val]) => ({
id: key,
name: val.name,
role: val.role,
}));
res.json(staff);
});

// ============================================
// STRIPE ROUTES
// ============================================

// Create checkout session
app.post(’/api/stripe/checkout’, authenticateToken, async (req, res) => {
const { priceId } = req.body;
try {
const session = await stripe.checkout.sessions.create({
payment_method_types: [‘card’],
mode: ‘subscription’,
line_items: [{ price: priceId, quantity: 1 }],
success_url: `${process.env.FRONTEND_URL || 'https://bizforceai.net'}?success=true`,
cancel_url: `${process.env.FRONTEND_URL || 'https://bizforceai.net'}?canceled=true`,
metadata: { user_id: req.user.id },
});
res.json({ url: session.url });
} catch (err) {
res.status(500).json({ error: err.message });
}
});

// Stripe webhook
app.post(’/api/webhook’, async (req, res) => {
const sig = req.headers[‘stripe-signature’];
let event;
try {
event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
} catch (err) {
return res.status(400).send(`Webhook Error: ${err.message}`);
}
if (event.type === ‘checkout.session.completed’) {
const session = event.data.object;
await supabase
.from(‘users’)
.update({ subscription_status: ‘active’, subscription_id: session.subscription })
.eq(‘id’, session.metadata.user_id);
}
if (event.type === ‘customer.subscription.deleted’) {
const subscription = event.data.object;
await supabase
.from(‘users’)
.update({ subscription_status: ‘free’ })
.eq(‘subscription_id’, subscription.id);
}
res.json({ received: true });
});

// ============================================
// HEALTH CHECK
// ============================================

app.get(’/health’, (req, res) => {
res.json({ status: ‘BizForce AI is LIVE’, timestamp: new Date().toISOString() });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`BizForce AI running on port ${PORT}`));

