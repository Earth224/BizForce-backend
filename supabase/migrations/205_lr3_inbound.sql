-- ===== PART 205a: everything coming to a member (run first) =====
-- LR-3 (Nov 24 2026): Inbound and the pipeline. One row per thing that came TO a member: the first message in a
-- conversation someone else started (message), an "I can help" on the member's Need (i_can_help), a Market sale where
-- the member is the seller (sale), a lead from the member's digital card (card_lead), a donation to the member's campaign
-- (campaign), a BizCash support tip (tip), and a reply to a reply the member posted through Lead Radar (lead_reply).
-- lib/inbound.js writes every row; the member moves it New, Talking, Won or Lost on Lead Radar's Inbound tab
-- (lib/inboundRoutes.js). source_id is the row it points to (messages, marketplace_orders, card_leads, campaign_donations,
-- bfc_transfers or member_lead_replies). customer_id is the crm_customers row "Add to my customers" made, so it is made once.
-- Paste-safe: no less-or-equal or greater-or-equal operators, no DO blocks, no transaction statements; every CHECK is
-- named and dropped if it exists first. Each part runs alone, in order: 205a, 205b, 205c.
-- Row level security is on with no policies, like every table: only the server (service role) reads or writes.
CREATE TABLE IF NOT EXISTS public.inbound_items (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  kind text NOT NULL,
  source_id uuid NOT NULL,
  counterpart_user_id uuid REFERENCES public.users(id) ON DELETE SET NULL,
  counterpart_label text NOT NULL DEFAULT '',
  summary text NOT NULL DEFAULT '',
  amount_bfc integer,
  status text NOT NULL DEFAULT 'new',
  customer_id uuid REFERENCES public.crm_customers(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.inbound_items ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.inbound_items FROM anon, authenticated;

-- ===== PART 205b: what an item may hold (run second) =====
ALTER TABLE public.inbound_items DROP CONSTRAINT IF EXISTS inbound_items_kind_check;
ALTER TABLE public.inbound_items ADD CONSTRAINT inbound_items_kind_check
  CHECK (kind IN ('message', 'i_can_help', 'sale', 'card_lead', 'campaign', 'tip', 'lead_reply'));
ALTER TABLE public.inbound_items DROP CONSTRAINT IF EXISTS inbound_items_status_check;
ALTER TABLE public.inbound_items ADD CONSTRAINT inbound_items_status_check
  CHECK (status IN ('new', 'talking', 'won', 'lost'));
ALTER TABLE public.inbound_items DROP CONSTRAINT IF EXISTS inbound_items_text_check;
ALTER TABLE public.inbound_items ADD CONSTRAINT inbound_items_text_check
  CHECK (char_length(summary) < 201 AND char_length(counterpart_label) < 81);
ALTER TABLE public.inbound_items DROP CONSTRAINT IF EXISTS inbound_items_amount_check;
ALTER TABLE public.inbound_items ADD CONSTRAINT inbound_items_amount_check
  CHECK (amount_bfc IS NULL OR amount_bfc > 0);
ALTER TABLE public.inbound_items DROP CONSTRAINT IF EXISTS inbound_items_not_self_check;
ALTER TABLE public.inbound_items ADD CONSTRAINT inbound_items_not_self_check
  CHECK (counterpart_user_id IS NULL OR counterpart_user_id <> user_id);

-- ===== PART 205c: one item per source, one per conversation, and the member's list (run third) =====
-- The unique key makes every writer and the backfill safe to run again. A conversation makes one item: the partial
-- unique index holds one message or i_can_help item per member and other person.
ALTER TABLE public.inbound_items DROP CONSTRAINT IF EXISTS inbound_items_user_kind_source_key;
ALTER TABLE public.inbound_items ADD CONSTRAINT inbound_items_user_kind_source_key UNIQUE (user_id, kind, source_id);
CREATE UNIQUE INDEX IF NOT EXISTS inbound_items_one_per_conversation
  ON public.inbound_items (user_id, counterpart_user_id) WHERE kind IN ('message', 'i_can_help');
CREATE INDEX IF NOT EXISTS inbound_items_user_status_idx ON public.inbound_items (user_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS inbound_items_user_created_idx ON public.inbound_items (user_id, created_at DESC);
