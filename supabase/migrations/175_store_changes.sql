-- Applied by the owner by hand in the Supabase SQL editor on Nov 6, 2026. This file is the text as run.

ALTER TABLE public.member_store_connections
  ADD COLUMN IF NOT EXISTS permission text NOT NULL DEFAULT 'read';

ALTER TABLE public.member_store_connections
  ADD CONSTRAINT member_store_connections_permission_check CHECK (permission IN ('read', 'read_write')),
  ADD CONSTRAINT member_store_connections_write_platform_check CHECK (permission = 'read' OR platform = 'woocommerce');

ALTER TABLE public.inventory_items
  ADD COLUMN IF NOT EXISTS external_parent_id text;

ALTER TABLE public.inventory_items
  ADD CONSTRAINT inventory_items_external_parent_id_check CHECK (external_parent_id IS NULL OR (char_length(external_parent_id) <= 100 AND external_parent_id ~ '^[0-9]+$'));

CREATE TABLE public.store_change_log (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  connection_id uuid NOT NULL REFERENCES public.member_store_connections(id) ON DELETE CASCADE,
  inventory_item_id uuid REFERENCES public.inventory_items(id) ON DELETE SET NULL,
  external_id text NOT NULL,
  item_name text NOT NULL DEFAULT '',
  field text NOT NULL,
  old_value numeric(14,2) NOT NULL,
  new_value numeric(14,2) NOT NULL,
  proposal_id uuid,
  executed_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT store_change_log_field_check CHECK (field IN ('price', 'stock')),
  CONSTRAINT store_change_log_external_id_check CHECK (char_length(external_id) BETWEEN 1 AND 100),
  CONSTRAINT store_change_log_item_name_check CHECK (char_length(item_name) <= 200),
  CONSTRAINT store_change_log_values_check CHECK (old_value >= 0 AND new_value >= 0 AND new_value <= 1000000)
);

CREATE INDEX store_change_log_user_idx ON public.store_change_log (user_id, executed_at DESC);
CREATE INDEX store_change_log_connection_idx ON public.store_change_log (connection_id, executed_at DESC);

ALTER TABLE public.store_change_log ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.store_change_log FROM anon, authenticated;
