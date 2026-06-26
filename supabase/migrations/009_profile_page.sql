-- Phase 9: Profile Page (bf_profiles, bf_products, bf_portfolio, bf_music_tracks)
-- Storage bucket 'bf-public' must be created manually in Supabase Dashboard > Storage
-- Set bucket to Public and allow file types: image/*, audio/*

-- ── Extended profile settings ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS bf_profiles (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       uuid        NOT NULL UNIQUE,
  display_name  text,
  tagline       text,
  bio           text,
  avatar_url    text,
  banner_url    text,
  accent_color  text        NOT NULL DEFAULT '#22d3ee',
  font_style    text        NOT NULL DEFAULT 'modern',
  show_products boolean     NOT NULL DEFAULT true,
  show_portfolio boolean    NOT NULL DEFAULT true,
  show_music    boolean     NOT NULL DEFAULT true,
  show_card     boolean     NOT NULL DEFAULT true,
  location      text,
  website       text,
  social_links  jsonb       NOT NULL DEFAULT '{}',
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT bf_profiles_font_check CHECK (font_style IN ('modern','classic','technical'))
);

CREATE INDEX IF NOT EXISTS bf_profiles_user_id_idx ON bf_profiles (user_id);

ALTER TABLE bf_profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY bf_profiles_select_public ON bf_profiles FOR SELECT USING (true);
CREATE POLICY bf_profiles_insert_own    ON bf_profiles FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY bf_profiles_update_own    ON bf_profiles FOR UPDATE
  USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE POLICY bf_profiles_delete_own    ON bf_profiles FOR DELETE USING (auth.uid() = user_id);

-- ── Products ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS bf_products (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid        NOT NULL,
  name        text        NOT NULL,
  description text,
  price       numeric(10,2),
  currency    text        NOT NULL DEFAULT 'USD',
  image_url   text,
  category    text,
  status      text        NOT NULL DEFAULT 'active',
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT bf_products_status_check CHECK (status IN ('active','draft'))
);

CREATE INDEX IF NOT EXISTS bf_products_user_id_idx ON bf_products (user_id, created_at DESC);

ALTER TABLE bf_products ENABLE ROW LEVEL SECURITY;
CREATE POLICY bf_products_select_public ON bf_products FOR SELECT
  USING (status = 'active' OR auth.uid() = user_id);
CREATE POLICY bf_products_insert_own ON bf_products FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY bf_products_update_own ON bf_products FOR UPDATE
  USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE POLICY bf_products_delete_own ON bf_products FOR DELETE USING (auth.uid() = user_id);

-- ── Portfolio ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS bf_portfolio (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid        NOT NULL,
  title       text        NOT NULL,
  description text,
  image_url   text,
  url         text,
  category    text,
  sort_order  int         NOT NULL DEFAULT 0,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS bf_portfolio_user_id_idx ON bf_portfolio (user_id, sort_order);

ALTER TABLE bf_portfolio ENABLE ROW LEVEL SECURITY;
CREATE POLICY bf_portfolio_select_public ON bf_portfolio FOR SELECT USING (true);
CREATE POLICY bf_portfolio_insert_own    ON bf_portfolio FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY bf_portfolio_update_own    ON bf_portfolio FOR UPDATE
  USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE POLICY bf_portfolio_delete_own    ON bf_portfolio FOR DELETE USING (auth.uid() = user_id);

-- ── Music Tracks ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS bf_music_tracks (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       uuid        NOT NULL,
  title         text        NOT NULL,
  artist        text,
  audio_url     text        NOT NULL,
  cover_url     text,
  duration_secs int,
  sort_order    int         NOT NULL DEFAULT 0,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS bf_music_tracks_user_id_idx ON bf_music_tracks (user_id, sort_order);

ALTER TABLE bf_music_tracks ENABLE ROW LEVEL SECURITY;
CREATE POLICY bf_music_select_public ON bf_music_tracks FOR SELECT USING (true);
CREATE POLICY bf_music_insert_own    ON bf_music_tracks FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY bf_music_update_own    ON bf_music_tracks FOR UPDATE
  USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE POLICY bf_music_delete_own    ON bf_music_tracks FOR DELETE USING (auth.uid() = user_id);
