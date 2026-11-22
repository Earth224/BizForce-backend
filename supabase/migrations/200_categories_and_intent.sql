-- ===== PART 200a: categories table (run first) =====
-- P3-3A (Nov 21 2026): ONE category list shared by posts and Marketplace listings
-- (garage sale and services included). Members never read it directly: the server
-- serves it, so RLS is on with no policies and anon/authenticated are revoked
-- (as in 110, 189, 191 and 193).
-- Paste-safe: no less-or-equal or greater-or-equal operators, no DO blocks, no
-- transaction statements; every CHECK is named and dropped if it exists first.
-- Each part runs alone, in order: 200a, 200b, 200c, 200d.
CREATE TABLE IF NOT EXISTS public.categories (
  slug text PRIMARY KEY,
  name text NOT NULL,
  parent_group text,
  sort_order int NOT NULL DEFAULT 0,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.categories DROP CONSTRAINT IF EXISTS categories_slug_format;
ALTER TABLE public.categories ADD CONSTRAINT categories_slug_format
  CHECK (slug ~ '^[a-z][a-z0-9_]*$' AND char_length(slug) < 41);
ALTER TABLE public.categories DROP CONSTRAINT IF EXISTS categories_name_length;
ALTER TABLE public.categories ADD CONSTRAINT categories_name_length
  CHECK (char_length(name) BETWEEN 1 AND 60);
ALTER TABLE public.categories DROP CONSTRAINT IF EXISTS categories_group_format;
ALTER TABLE public.categories ADD CONSTRAINT categories_group_format
  CHECK (parent_group IS NULL OR parent_group ~ '^[a-z][a-z0-9_]*$');
CREATE INDEX IF NOT EXISTS categories_active_sort_idx
  ON public.categories (sort_order) WHERE active;
ALTER TABLE public.categories ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.categories FROM anon, authenticated;

-- ===== PART 200b: seed the shared list (run second) =====
-- The ten Market slugs (server.js MARKETPLACE_CATEGORIES) are kept exactly, with the
-- labels marketplace.html shows. Re-running inserts nothing new (ON CONFLICT DO NOTHING).
-- No adult or prohibited category: pets is care and supplies only (live animal sales
-- stay prohibited by the content policy); food is cooking and baking, not alcohol.
INSERT INTO public.categories (slug, name, parent_group, sort_order) VALUES
  ('artists',             'Artists & Talent',       'creative',     10),
  ('art',                 'Art & Illustration',     'creative',     20),
  ('music',               'Music',                  'creative',     30),
  ('photography',         'Photography & Video',    'creative',     40),
  ('content_creation',    'Content Creation',       'creative',     50),
  ('crafts_handmade',     'Crafts & Handmade',      'creative',     60),
  ('hair_beauty',         'Hair & Beauty',          'beauty',       70),
  ('tattoo_body_art',     'Tattoo & Body Art',      'beauty',       80),
  ('health_wellness',     'Health & Wellness',      'wellness',     90),
  ('fitness',             'Fitness & Sports',       'wellness',    100),
  ('labor_trades',        'Labor & Trades',         'home',        110),
  ('home_garden',         'Home & Garden',          'home',        120),
  ('cleaning_moving',     'Cleaning & Moving',      'home',        130),
  ('real_estate',         'Real Estate',            'home',        140),
  ('garage_sale',         'Garage Sale',            'shopping',    150),
  ('clothing',            'Clothing & Apparel',     'shopping',    160),
  ('fashion_accessories', 'Jewelry & Accessories',  'shopping',    170),
  ('bookstore',           'Bookstore',              'shopping',    180),
  ('electronics',         'Electronics',            'shopping',    190),
  ('pets',                'Pet Care & Supplies',    'shopping',    200),
  ('vehicles',            'Vehicles',               'auto',        210),
  ('auto_services',       'Auto Repair & Care',     'auto',        220),
  ('food',                'Food & Cooking',         'food',        230),
  ('services',            'Services',               'professional', 240),
  ('tech',                'Tech & Software',        'professional', 250),
  ('business_marketing',  'Business & Marketing',   'professional', 260),
  ('coaching',            'Coaching & Consulting',  'professional', 270),
  ('education',           'Education & Tutoring',   'learning',    280),
  ('events',              'Events & Entertainment', 'community',   290),
  ('kids_family',         'Kids & Family',          'community',   300),
  ('community',           'Community & Causes',     'community',   310),
  ('other',               'Other',                  NULL,          999)
ON CONFLICT (slug) DO NOTHING;

-- ===== PART 200c: posts category and intent (run third) =====
-- category: nullable for old posts; the server requires it on new posts.
-- intent: share (show your work), offer (sell or book; links a listing), need (ask
-- for help). need_place is a place the member types, never device location;
-- need_when is today, week or any. Both are only set on need posts.
ALTER TABLE public.posts ADD COLUMN IF NOT EXISTS category text
  REFERENCES public.categories(slug);
ALTER TABLE public.posts ADD COLUMN IF NOT EXISTS intent text NOT NULL DEFAULT 'share';
ALTER TABLE public.posts ADD COLUMN IF NOT EXISTS need_place text;
ALTER TABLE public.posts ADD COLUMN IF NOT EXISTS need_when text;
ALTER TABLE public.posts DROP CONSTRAINT IF EXISTS posts_intent_allowed;
ALTER TABLE public.posts ADD CONSTRAINT posts_intent_allowed
  CHECK (intent IN ('share','offer','need'));
ALTER TABLE public.posts DROP CONSTRAINT IF EXISTS posts_need_place_length;
ALTER TABLE public.posts ADD CONSTRAINT posts_need_place_length
  CHECK (need_place IS NULL OR char_length(need_place) < 81);
ALTER TABLE public.posts DROP CONSTRAINT IF EXISTS posts_need_when_allowed;
ALTER TABLE public.posts ADD CONSTRAINT posts_need_when_allowed
  CHECK (need_when IS NULL OR need_when IN ('today','week','any'));
ALTER TABLE public.posts DROP CONSTRAINT IF EXISTS posts_need_fields_only_on_need;
ALTER TABLE public.posts ADD CONSTRAINT posts_need_fields_only_on_need
  CHECK (intent = 'need' OR (need_place IS NULL AND need_when IS NULL));
CREATE INDEX IF NOT EXISTS posts_intent_category_idx
  ON public.posts (intent, category, published_at DESC)
  WHERE status = 'published';

-- ===== PART 200d: marketplace_listings.category_slug (run fourth) =====
-- marketplace_listings.category is free text (006; only server.js limits it), so a
-- referenced category_slug is added and back-filled by an explicit mapping. Every
-- old value maps to the same slug; nothing is guessed. A row whose category is not
-- in the mapping keeps category_slug NULL and shows up in the verify query.
ALTER TABLE public.marketplace_listings ADD COLUMN IF NOT EXISTS category_slug text
  REFERENCES public.categories(slug);
UPDATE public.marketplace_listings AS l
   SET category_slug = m.slug
  FROM (VALUES
    ('services', 'services'),
    ('artists', 'artists'),
    ('garage_sale', 'garage_sale'),
    ('bookstore', 'bookstore'),
    ('health_wellness', 'health_wellness'),
    ('hair_beauty', 'hair_beauty'),
    ('clothing', 'clothing'),
    ('vehicles', 'vehicles'),
    ('labor_trades', 'labor_trades'),
    ('other', 'other')
  ) AS m(old_value, slug)
 WHERE l.category = m.old_value
   AND l.category_slug IS NULL;
CREATE INDEX IF NOT EXISTS marketplace_listings_category_slug_idx
  ON public.marketplace_listings (category_slug, status);

-- ===== PART 200e: agent directory view and post search fields (run fifth) =====
-- APPLIED BY HAND: all five parts (200a, 200b, 200c, 200d, 200e) were applied by the owner
-- on Nov 21 2026. The verify query answered: categories 32, unmapped_listings 0,
-- non_share_posts 0, post_columns 7, agents_view_column 1.
-- agents_card_view: the phone Agent Directory's view (ai-agents.html; FX2), NULL or
-- large, compact, grid, as hq_card_view (188). search_visible, seo_title and
-- seo_description on posts are used by later blocks.
ALTER TABLE public.user_preferences ADD COLUMN IF NOT EXISTS agents_card_view text;
ALTER TABLE public.user_preferences DROP CONSTRAINT IF EXISTS user_preferences_agents_card_view_check;
ALTER TABLE public.user_preferences ADD CONSTRAINT user_preferences_agents_card_view_check
  CHECK (agents_card_view IS NULL OR agents_card_view IN ('large', 'compact', 'grid'));
ALTER TABLE public.posts ADD COLUMN IF NOT EXISTS search_visible boolean NOT NULL DEFAULT true;
ALTER TABLE public.posts ADD COLUMN IF NOT EXISTS seo_title text;
ALTER TABLE public.posts ADD COLUMN IF NOT EXISTS seo_description text;
ALTER TABLE public.posts DROP CONSTRAINT IF EXISTS posts_seo_title_length;
ALTER TABLE public.posts ADD CONSTRAINT posts_seo_title_length
  CHECK (seo_title IS NULL OR char_length(seo_title) < 71);
ALTER TABLE public.posts DROP CONSTRAINT IF EXISTS posts_seo_description_length;
ALTER TABLE public.posts ADD CONSTRAINT posts_seo_description_length
  CHECK (seo_description IS NULL OR char_length(seo_description) < 161);
