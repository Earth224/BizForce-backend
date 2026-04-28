require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const Anthropic = require('@anthropic-ai/sdk');
const Stripe = require('stripe');

const app = express();

/* -------------------- CONFIG -------------------- */

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_now';
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

if (!STRIPE_SECRET_KEY) console.warn('Missing STRIPE_SECRET_KEY');
if (!SUPABASE_URL) console.warn('Missing SUPABASE_URL');
if (!SUPABASE_SERVICE_ROLE_KEY) console.warn('Missing SUPABASE_SERVICE_ROLE_KEY');

const stripe = Stripe(STRIPE_SECRET_KEY);
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
const anthropic = new Anthropic({
  apiKey: ANTHROPIC_API_KEY
});

/* -------------------- SAFETY -------------------- */

process.on('unhandledRejection', (err) => {
  console.error('Unhandled Rejection:', err);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});

app.set('trust proxy', 1);

/* -------------------- MIDDLEWARE -------------------- */

app.use(helmet());

app.use(cors({
  origin: true,
  credentials: true
}));

app.use(express.json({ limit: '2mb' }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200
});

app.use(limiter);

/* -------------------- HELPERS -------------------- */

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email
    },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization;

    if (!header) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = header.replace('Bearer ', '');
    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

/* -------------------- ROUTES -------------------- */

app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    service: 'BizForce AI API'
  });
});

/* REGISTER */

app.post('/api/register', async (req, res) => {
  try {
    const { email, password, business_name } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: 'Email and password required'
      });
    }

    const hashed = await bcrypt.hash(password, 10);

    const { data, error } = await supabase
      .from('users')
      .insert([
        {
          email,
          password: hashed,
          business_name
        }
      ])
      .select()
      .single();

    if (error) throw error;

    const token = createToken(data);

    res.json({
      token,
      user: data
    });

  } catch (err) {
    res.status(500).json({
      error: err.message
    });
  }
});

/* LOGIN */

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (error || !user) {
      return res.status(401).json({
        error: 'Invalid credentials'
      });
    }

    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      return res.status(401).json({
        error: 'Invalid credentials'
      });
    }

    const token = createToken(user);

    res.json({
      token,
      user
    });

  } catch (err) {
    res.status(500).json({
      error: err.message
    });
  }
});

/* PROFILE */

app.get('/api/profile', auth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', req.user.id)
      .single();

    if (error) throw error;

    res.json(data);

  } catch (err) {
    res.status(500).json({
      error: err.message
    });
  }
});

/* STRIPE CHECKOUT */

app.post('/api/create-checkout-session', auth, async (req, res) => {
  try {
    const { price_id } = req.body;

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'subscription',
      line_items: [
        {
          price: price_id,
          quantity: 1
        }
      ],
      success_url: 'https://yourdomain.com/success',
      cancel_url: 'https://yourdomain.com/cancel'
    });

    res.json({
      url: session.url
    });

  } catch (err) {
    res.status(500).json({
      error: err.message
    });
  }
});

/* AI TASK */

app.post('/api/ai-task', auth, async (req, res) => {
  try {
    const { prompt } = req.body;

    const msg = await anthropic.messages.create({
      model: 'claude-3-5-sonnet-20241022',
      max_tokens: 1000,
      messages: [
        {
          role: 'user',
          content: prompt
        }
      ]
    });

    res.json({
      result: msg.content
    });

  } catch (err) {
    res.status(500).json({
      error: err.message
    });
  }
});

/* -------------------- START -------------------- */

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
