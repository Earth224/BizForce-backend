
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const Anthropic = require('@anthropic-ai/sdk');

const app = express();
app.use(cors());
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY
);

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY,
});

app.get('/', (req, res) => {
  res.json({ status: 'BizForce AI Backend Running', time: new Date().toISOString() });
});

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

app.get('/api/dashboard/:business_id', async (req, res) => {
  try {
    const { data: business } = await supabase
      .from('businesses').select('*').eq('id', req.params.business_id).single();
    const { data: tasks } = await supabase
      .from('tasks').select('*').eq('business_id', req.params.business_id)
      .order('created_at', { ascending: false }).limit(50);
    const { data: revenue } = await supabase
      .from('revenue_events').select('*').eq('business_id', req.params.business_id);
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

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log('BizForce running on port ' + PORT));
