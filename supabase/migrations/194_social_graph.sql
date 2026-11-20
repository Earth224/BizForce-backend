-- P2-3A (Nov 20 2026): follows, likes, saves, comments and shares, with post counters.
-- Drafted in P2-0 as 193; shifted to 194 because 192 is the purchase fix. Needs 193.
-- Safe to re-run: IF NOT EXISTS on tables and indexes, each named CHECK dropped if it
-- exists before it is added, CREATE OR REPLACE on the function, and each trigger
-- dropped if it exists before it is created.
-- Paste-safe: no less-or-equal or greater-or-equal operators.
--
-- 1. follows: a member follows another. The old follows table (migration 123) was
--    dropped; this is a new table, not a revival.
-- 2. post_likes, 3. post_saves: one per member per post.
-- 4. post_comments: author_id is SET NULL on account deletion (a tombstone, so replies
--    keep their place); parent_id gives one level of replies.
-- 5. post_share_days: shares are only counted (the share sheet is the device's), at
--    most one per member per post per day.
-- 6. posts_count_bump: adds 1 on INSERT and takes 1 on DELETE from the posts column
--    named in the trigger argument, never below 0. Four triggers use it.
--
-- Row level security is on with no policies and anon/authenticated are revoked.
BEGIN;

-- 1. follows
CREATE TABLE IF NOT EXISTS public.follows (
  follower_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  following_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (follower_id, following_id)
);
ALTER TABLE public.follows DROP CONSTRAINT IF EXISTS follows_not_self;
ALTER TABLE public.follows ADD CONSTRAINT follows_not_self
  CHECK (follower_id <> following_id);
CREATE INDEX IF NOT EXISTS follows_following_idx ON public.follows (following_id, created_at DESC);

-- 2. likes
CREATE TABLE IF NOT EXISTS public.post_likes (
  post_id uuid NOT NULL REFERENCES public.posts(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (post_id, user_id)
);
CREATE INDEX IF NOT EXISTS post_likes_user_idx ON public.post_likes (user_id, created_at DESC);

-- 3. saves
CREATE TABLE IF NOT EXISTS public.post_saves (
  post_id uuid NOT NULL REFERENCES public.posts(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (post_id, user_id)
);
CREATE INDEX IF NOT EXISTS post_saves_user_idx ON public.post_saves (user_id, created_at DESC);

-- 4. comments
CREATE TABLE IF NOT EXISTS public.post_comments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  post_id uuid NOT NULL REFERENCES public.posts(id) ON DELETE CASCADE,
  author_id uuid REFERENCES public.users(id) ON DELETE SET NULL,
  parent_id uuid REFERENCES public.post_comments(id) ON DELETE CASCADE,
  body text NOT NULL,
  status text NOT NULL DEFAULT 'published',
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.post_comments DROP CONSTRAINT IF EXISTS post_comments_body_length;
ALTER TABLE public.post_comments ADD CONSTRAINT post_comments_body_length
  CHECK (char_length(body) BETWEEN 1 AND 1000);
ALTER TABLE public.post_comments DROP CONSTRAINT IF EXISTS post_comments_status_allowed;
ALTER TABLE public.post_comments ADD CONSTRAINT post_comments_status_allowed
  CHECK (status IN ('published','hidden','removed','deleted'));
CREATE INDEX IF NOT EXISTS post_comments_post_idx ON public.post_comments (post_id, created_at);

-- 5. share days
CREATE TABLE IF NOT EXISTS public.post_share_days (
  post_id uuid NOT NULL REFERENCES public.posts(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  day date NOT NULL DEFAULT current_date,
  PRIMARY KEY (post_id, user_id, day)
);

-- 6. counters
CREATE OR REPLACE FUNCTION public.posts_count_bump() RETURNS trigger
LANGUAGE plpgsql SET search_path = public AS $$
DECLARE
  col text := TG_ARGV[0];
  d int := CASE WHEN TG_OP = 'INSERT' THEN 1 ELSE -1 END;
  pid uuid;
BEGIN
  pid := CASE WHEN TG_OP = 'INSERT' THEN NEW.post_id ELSE OLD.post_id END;
  EXECUTE format('UPDATE public.posts SET %I = GREATEST(0, %I + $1) WHERE id = $2', col, col)
    USING d, pid;
  RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS post_likes_count ON public.post_likes;
CREATE TRIGGER post_likes_count AFTER INSERT OR DELETE ON public.post_likes
  FOR EACH ROW EXECUTE FUNCTION public.posts_count_bump('like_count');
DROP TRIGGER IF EXISTS post_saves_count ON public.post_saves;
CREATE TRIGGER post_saves_count AFTER INSERT OR DELETE ON public.post_saves
  FOR EACH ROW EXECUTE FUNCTION public.posts_count_bump('save_count');
DROP TRIGGER IF EXISTS post_shares_count ON public.post_share_days;
CREATE TRIGGER post_shares_count AFTER INSERT OR DELETE ON public.post_share_days
  FOR EACH ROW EXECUTE FUNCTION public.posts_count_bump('share_count');
DROP TRIGGER IF EXISTS post_comments_count ON public.post_comments;
CREATE TRIGGER post_comments_count AFTER INSERT OR DELETE ON public.post_comments
  FOR EACH ROW EXECUTE FUNCTION public.posts_count_bump('comment_count');

-- 7. no direct member access
ALTER TABLE public.follows ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.post_likes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.post_saves ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.post_comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.post_share_days ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.follows FROM anon, authenticated;
REVOKE ALL ON public.post_likes FROM anon, authenticated;
REVOKE ALL ON public.post_saves FROM anon, authenticated;
REVOKE ALL ON public.post_comments FROM anon, authenticated;
REVOKE ALL ON public.post_share_days FROM anon, authenticated;

COMMIT;
