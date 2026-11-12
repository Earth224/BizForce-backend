-- Applied by the owner by hand in the Supabase SQL editor on Nov 11, 2026. This file is the text as run.
BEGIN;

ALTER TABLE public.user_preferences
  ADD COLUMN IF NOT EXISTS goal_metric        text,
  ADD COLUMN IF NOT EXISTS goal_weekly_target numeric(14,2),
  ADD COLUMN IF NOT EXISTS goal_currency      text,
  ADD COLUMN IF NOT EXISTS goal_time_zone     text,
  ADD COLUMN IF NOT EXISTS goal_set_at        timestamptz;

ALTER TABLE public.user_preferences DROP CONSTRAINT IF EXISTS user_preferences_goal_check;
ALTER TABLE public.user_preferences ADD CONSTRAINT user_preferences_goal_check CHECK (
  (goal_metric IS NULL AND goal_weekly_target IS NULL AND goal_currency IS NULL AND goal_time_zone IS NULL AND goal_set_at IS NULL)
  OR (
    goal_set_at IS NOT NULL
    AND goal_time_zone IS NOT NULL AND char_length(goal_time_zone) BETWEEN 1 AND 64
    AND (
         (goal_metric = 'tracked_visits'     AND goal_currency IS NULL AND goal_weekly_target = trunc(goal_weekly_target) AND goal_weekly_target BETWEEN 1 AND 100000)
      OR (goal_metric = 'store_orders'       AND goal_currency IS NULL AND goal_weekly_target = trunc(goal_weekly_target) AND goal_weekly_target BETWEEN 1 AND 100000)
      OR (goal_metric = 'card_visits'        AND goal_currency IS NULL AND goal_weekly_target = trunc(goal_weekly_target) AND goal_weekly_target BETWEEN 1 AND 100000)
      OR (goal_metric = 'marketplace_orders' AND goal_currency IS NULL AND goal_weekly_target = trunc(goal_weekly_target) AND goal_weekly_target BETWEEN 1 AND 10000)
      OR (goal_metric = 'store_sales'        AND goal_currency ~ '^[A-Z]{3}$' AND goal_weekly_target > 0 AND goal_weekly_target <= 100000000)
    )
  )
);

ALTER TABLE public.store_order_summaries
  ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'active';

ALTER TABLE public.store_order_summaries DROP CONSTRAINT IF EXISTS store_order_summaries_status_check;
ALTER TABLE public.store_order_summaries ADD CONSTRAINT store_order_summaries_status_check
  CHECK (status IN ('active', 'cancelled', 'refunded'));

REVOKE ALL ON public.user_preferences FROM anon, authenticated;

COMMIT;
