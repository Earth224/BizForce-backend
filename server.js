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

app.use(helmet());
app.use(cors({ origin: '*' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
app.use('/api/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const auth = (req, res, next) => {
  const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(403).json({ error: 'Invalid token' });
  }
};

app.post('/api/auth/register', async (req, res) => {
  const { email, password, business_name, industry } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    const { data, error } = await supabase.from('users').insert([{ email, password_hash: hash, business_name, industry }]).select().single();
    if (error) return res.status(400).json({ error: error.message });
    const token = jwt.sign({ id: data.id, email: data.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: data });
  } catch (err) { res.status(500).json({ error: err.message }); }
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
});

app.get('/api/feed', auth, async (req, res) => {
  try {
    const { data: follows } = await supabase.from('follows').select('following_id').eq('follower_id', req.user.id);
    const ids = follows ? follows.map(f => f.following_id) : [];
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
