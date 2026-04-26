const express = require('express');
const cors = require('cors');
const cron = require('node-cron');
const { createClient } = require('@supabase/supabase-js');
const Anthropic = require('@anthropic-ai/sdk');

const app = express();
app.use(cors());
app.use(express.json());

// Initialize clients
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY
);

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY
});

// ─── HEALTH CHECK ───
app.get('/', (req, res) => {
  res.json({ status: 'BizForce AI Backend Running', time: new Date().toISOString() });
});

// ─── REGISTER NEW BUSINESS ───
app.post('/api/register', async (req, res) => {
  const { business_name, website, products, target_customer, tone, goals, email, plan } = req.body;
  try {
    const { data, error } = await supabase.from('businesses').insert([{
      business_name, website, products, target_customer, tone, goals, email, plan,
      created_at: new Date().toISOString(),
      status: 'active',
      total_revenue: 0,
      total_leads: 0,
      total_posts: 0
    }]).select();
    if (error) throw error;
    res.json({ success: true, business_id: data[0].id, message: 'AI Staff deployed successfully!' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── GET BUSINESS DASHBOARD ───
app.get('/api/dashboard/:business_id', async (req, res) => {
  try {
    const { data: business } = await supabase
      .from('businesses').select('*').eq('id', req.params.business_id).single();
    const { data: tasks } = await supabase
      .from('tasks').select('*').eq('business_id', req.params.business_id)
      .order('created_at', { ascending: false }).limit(50);
    const { data: revenue } = await supabase
      .from('revenue_events').select('*').eq('business_id', req.params.business_id);

    // Revenue per staff member
    const staffRevenue = {};
    if (revenue) {
      revenue.forEach(r => {
        if (!staffRevenue[r.staff_member]) staffRevenue[r.staff_member] = 0;
        staffRevenue[r.staff_member] += r.amount;
      });
    }

    res.json({ business, tasks, staffRevenue, totalRevenue: business?.total_revenue || 0 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── AI STAFF TASK RUNNER ───
async function runStaffTask(business, staffMember) {
  const staffRoles = {
    alex: { role: 'SEO Specialist', task: 'Generate 3 high-value SEO keyword recommendations and meta description improvements for this business. Be specific with actual keywords and search volumes.' },
    jordan: { role: 'Community Manager', task: 'Write 2 authentic Reddit/Quora responses that would help people in relevant communities while naturally referencing this business. Include the subreddit or topic.' },
    morgan: { role: 'Content Creator', task: 'Write a complete 400-word SEO blog post for this business. Include a title, meta description, and full post body with natural keyword integration.' },
    casey: { role: 'Email Marketing Manager', task: 'Write a complete email marketing sequence of 3 emails for this business. Include subject lines, preview text, and full email bodies.' },
    riley: { role: 'Sales Representative', task: 'Write 3 personalized sales follow-up templates for this business targeting their ideal customer.' },
    sam: { role: 'Reputation Manager', task: 'Write 5 professional responses to common customer reviews (mix of positive and negative) for this type of business.' },
    dana: { role: 'Analytics Officer', task: 'Create a detailed weekly performance report template with key metrics, insights, and recommendations for this business.' },
    taylor: { role: 'Ad Campaign Manager', task: 'Write 3 complete Google Ad campaigns with headlines, descriptions, and targeting recommendations for this business.' },
    blake: { role: 'Influencer Outreach Agent', task: 'Write 3 personalized influencer outreach emails for micro-influencers relevant to this business niche.' },
 };
}


​​​​​​​​​​​​​​​​
