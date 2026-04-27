const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const Anthropic = require('@anthropic-ai/sdk');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const app = express();
app.set('trust proxy' , 1)
app.use(helmet());
app.use(cors({
  origin: ["https://bizforceai.net","https://www.bizforceai.net"],
  credentials: true,
  methods: ["GET","POST","PUT","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization"]
}));


app.use('/api/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const auth = (req, res, next) => {
const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];
if (!token) return res.status(401).json({ error: 'Access denied' });
try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
catch(e) { res.status(403).json({ error: 'Invalid token' }); }
};
app.post('/api/auth/register', async (req, res) => {
  const { email, password, business_name, industry } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    
    // Check if user already exists
    const { data: existing } = await supabase
      .from('users').select('*')
      .eq('email', email).single();
    
    if (existing) {
      const token = jwt.sign(
        { id: existing.id, email: existing.email },
        process.env.JWT_SECRET, { expiresIn: '7d' }
      );
      return res.json({ token, user: {
        id: existing.id,
        email: existing.email,
        business_name: existing.business_name
      }});
    }

    const { data, error } = await supabase.from('users')
      .insert([{ email, password_hash: hash, 
        business_name, industry }])
      .select().single();
    
    if (error) return res.status(400).json({ error: error.message });
    const token = jwt.sign(
      { id: data.id, email: data.email },
      process.env.JWT_SECRET, { expiresIn: '7d' }
    );
    res.json({ token, user: {
      id: data.id, email: data.email,
      business_name: data.business_name
    }});
  } catch(err) { res.status(500).json({ error: err.message }); }
});

});
app.post('/api/auth/login', async (req, res) => {
const { email, password } = req.body;
try {
const { data: user, error } = await supabase.from('users').select('*').eq('email', email).single();
if (error || !user) return res.status(400).json({ error: 'Invalid credentials' });
const valid = await bcrypt.compare(password, user.password_hash);
if (!valid) return res.status(400).json({ error: 'Invalid credentials' });
const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
res.json({ token, user: { id: user.id, email: user.email, business_name: user.business_name, industry: user.industry, subscription_status: user.subscription_status, bio: user.bio, avatar_url: user.avatar_url } });
} catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/auth/me', auth, async (req, res) => {
try {
const { data, error } = await supabase.from('users').select('id,email,business_name,industry,bio,avatar_url,subscription_status,created_at').eq('id', req.user.id).single();
if (error) return res.status(400).json({ error: error.message });
res.json(data);
} catch (err) { res.status(500).json({ error: err.message }); }
});
app.put('/api/auth/profile', auth, async (req, res) => {
const { business_name, industry, bio, avatar_url } = req.body;
try {
const { data, error } = await supabase.from('users').update({ business_name, industry, bio, avatar_url }).eq('id', req.user.id).select().single();
if (error) return res.status(400).json({ error: error.message });
res.json(data);
} catch (err) { res.status(500).json({ error: err.message }); }
});app.get('/api/feed', auth, async (req, res) => {
try {
const { data: follows } = await supabase.from('follows').select('following_id').eq('follower_id', req.user.id);
const ids = follows ? follows.map(function(f) { return f.following_id; }) : [];
ids.push(req.user.id);
const { data, error } = await supabase.from('posts').select('*, users(id,business_name,industry,avatar_url)').in('user_id', ids).order('created_at', { ascending: false }).limit(50);
if (error) return res.status(400).json({ error: error.message });
res.json(data);
} catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/posts', auth, async (req, res) => {
try {
const { data, error } = await supabase.from('posts').insert([{ user_id: req.user.id, content: req.body.content }]).select('*, users(id,business_name,industry,avatar_url)').single();
if (error) return res.status(400).json({ error: error.message });
res.json(data);
} catch (err) { res.status(500).json({ error: err.message }); }
});
app.delete('/api/posts/:id', auth, async (req, res) => {
try {
await supabase.from('posts').delete().eq('id', req.params.id).eq('user_id', req.user.id);
res.json({ success: true });
} catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/follow/:id', auth, async (req, res) => {
try {
await supabase.from('follows').insert([{ follower_id: req.user.id, following_id: req.params.id }]);
res.json({ success: true });
} catch (err) { res.status(500).json({ error: err.message }); }
});
app.delete('/api/follow/:id', auth, async (req, res) => {
try {
await supabase.from('follows').delete().eq('follower_id', req.user.id).eq('following_id', req.params.id);
res.json({ success: true });
} catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/users/:id', auth, async (req, res) => {
try {
const { data: user } = await supabase.from('users').select('id,email,business_name,industry,bio,avatar_url,subscription_status,created_at').eq('id', req.params.id).single();
const { data: posts } = await supabase.from('posts').select('*').eq('user_id', req.params.id).order('created_at', { ascending: false });
const { count: followers } = await supabase.from('follows').select('*', { count: 'exact', head: true }).eq('following_id', req.params.id);
const { count: following } = await supabase.from('follows').select('*', { count: 'exact', head: true }).eq('follower_id', req.params.id);
const { data: isFollowing } = await supabase.from('follows').select('*').eq('follower_id', req.user.id).eq('following_id', req.params.id).single();
res.json({ ...user, posts, followers, following, is_following: !!isFollowing });
} catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/search', auth, async (req, res) => {
const { q, industry } = req.query;
try {
let query = supabase.from('users').select('id,business_name,industry,bio,avatar_url,subscription_status');
if (q) query = query.ilike('business_name', '%' + q + '%');
if (industry) query = query.eq('industry', industry);
const { data, error } = await query.limit(20);
if (error) return res.status(400).json({ error: error.message });
res.json(data);
} catch (err) { res.status(500).json({ error: err.message }); }
});app.post('/api/messages', auth, async (req, res) => {
try {
const { data, error } = await supabase.from('messages').insert([{ sender_id: req.user.id, receiver_id: req.body.receiver_id, content: req.body.content }]).select().single();
if (error) return res.status(400).json({ error: error.message });
res.json(data);
} catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/messages/:userId', auth, async (req, res) => {
try {
const uid = req.user.id;
const oid = req.params.userId;
const { data, error } = await supabase.from('messages').select('*, sender:users!sender_id(id,business_name,avatar_url)').or('and(sender_id.eq.' + uid + ',receiver_id.eq.' + oid + '),and(sender_id.eq.' + oid + ',receiver_id.eq.' + uid + ')').order('created_at', { ascending: true });
if (error) return res.status(400).json({ error: error.message });
res.json(data);
} catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/deals', auth, async (req, res) => {
try {
let query = supabase.from('deals').select('*, users(id,business_name,industry,avatar_url)').order('created_at', { ascending: false });
if (req.query.type) query = query.eq('deal_type', req.query.type);
const { data, error } = await query.limit(50);
if (error) return res.status(400).json({ error: error.message });
res.json(data);
} catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/deals', auth, async (req, res) => {
try {
const { data, error } = await supabase.from('deals').insert([{ user_id: req.user.id, title: req.body.title, description: req.body.description, deal_type: req.body.deal_type }]).select('*, users(id,business_name,industry,avatar_url)').single();
if (error) return res.status(400).json({ error: error.message });
res.json(data);
} catch (err) { res.status(500).json({ error: err.message }); }
});
app.delete('/api/deals/:id', auth, async (req, res) => {
try {
await supabase.from('deals').delete().eq('id', req.params.id).eq('user_id', req.user.id);
res.json({ success: true });
} catch (err) { res.status(500).json({ error: err.message }); }
});var STAFF = {
alex: { name: 'Alex', role: 'SEO Specialist', prompt: 'You are Alex, an expert SEO specialist. Help businesses rank higher, find keywords, and build organic traffic.' },
jordan: { name: 'Jordan', role: 'Community Manager', prompt: 'You are Jordan, a community expert. Help businesses build engaged communities and grow loyal followings.' },
morgan: { name: 'Morgan', role: 'Content Creator', prompt: 'You are Morgan, a content specialist. Write blog posts, social content, emails, and product descriptions.' },
casey: { name: 'Casey', role: 'Email Marketing', prompt: 'You are Casey, an email marketing specialist. Craft compelling campaigns and subject lines.' },
riley: { name: 'Riley', role: 'Sales Strategist', prompt: 'You are Riley, a sales expert. Help close deals, craft scripts, build funnels, and increase conversions.' },
sam: { name: 'Sam', role: 'Reputation Manager', prompt: 'You are Sam, a reputation specialist. Help manage reviews and build brand trust.' },
dana: { name: 'Dana', role: 'Analytics Expert', prompt: 'You are Dana, an analytics specialist. Analyze data and drive data-based decisions.' },
taylor: { name: 'Taylor', role: 'Ads Specialist', prompt: 'You are Taylor, a paid ads expert. Help run profitable campaigns and maximize ROI.' },
blake: { name: 'Blake', role: 'Influencer Marketing', prompt: 'You are Blake, an influencer specialist. Find influencers, negotiate deals, and measure ROI.' }
};
app.post('/api/ai/:agent', auth, async (req, res) => {
var staff = STAFF[req.params.agent.toLowerCase()];
if (!staff) return res.status(400).json({ error: 'Agent not found' });
try {
const { data: user } = await supabase.from('users').select('business_name').eq('id', req.user.id).single();
var messages = (req.body.history || []).slice(-10).concat([{ role: 'user', content: req.body.message }]);
var bizname = (user && user.business_name) ? user.business_name : 'a growing business';
const response = await anthropic.messages.create({ model: 'claude-opus-4-5', max_tokens: 1024, system: staff.prompt + ' Business: ' + bizname, messages: messages });
res.json({ agent: staff.name, role: staff.role, response: response.content[0].text });
} catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/ai/staff/all', auth, function(req, res) {
res.json(Object.keys(STAFF).map(function(id) { return { id: id, name: STAFF[id].name, role: STAFF[id].role }; }));
});
app.post('/api/stripe/checkout', auth, async (req, res) => {
try {
const session = await stripe.checkout.sessions.create({ payment_method_types: ['card'], mode: 'subscription', line_items: [{ price: req.body.priceId, quantity: 1 }], success_url: 'https://bizforceai.net?success=true', cancel_url: 'https://bizforceai.net?canceled=true', metadata: { user_id: req.user.id } });
res.json({ url: session.url });
} catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/webhook', async (req, res) => {
try {
var event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
if (event.type === 'checkout.session.completed') { var s = event.data.object; await supabase.from('users').update({ subscription_status: 'active', subscription_id: s.subscription }).eq('id', s.metadata.user_id); }
if (event.type === 'customer.subscription.deleted') { await supabase.from('users').update({ subscription_status: 'free' }).eq('subscription_id', event.data.object.id); }
res.json({ received: true });
} catch (err) { res.status(400).send('Webhook Error: ' + err.message); }
});
app.get('/health', function(req, res) { res.json({ status: 'BizForce AI is LIVE', timestamp: new Date().toISOString() }); });
var PORT = process.env.PORT || 8080;
app.listen(PORT, function() { console.log('BizForce AI running on port ' + PORT); }); 



