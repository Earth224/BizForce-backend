-- APPLIED (P3-1, recorded Nov 20 2026): written in P3-1A as 196a_storage_account_tables.sql and renamed to 196
-- so every highest-migration check can read a plain number. Applied BY HAND by the owner on Nov 20 2026, as
-- written but WITHOUT the BEGIN/COMMIT below, after 195 and before 197 and 198.
-- Verified after all four (owner, Nov 20 2026): missing_canonical 0, duplicate_canonical 0, canonical_index true, totals_off 0, rls_on true, accounts_counted 1, database 83 MB.
-- The text below is unchanged from P3-1A (its "196a/196b/196c" names are now 196, 197 and 198).
--
-- 196a (P3-1A, Nov 20 2026): per-account storage totals across every bucket, part 1 of 3.
-- Run 196a, then 196b, then 196c.
--
-- 1. storage_account_objects: one row per stored file the server has counted for an
--    account (bucket, path, bytes). The server writes it through 196b's functions:
--    storage_account_reserve before an upload, storage_account_release when a file
--    is deleted or an upload fails.
-- 2. storage_account_totals: one row per account, the sum of its rows in (1), kept by
--    the trigger below on every insert, update and delete. Never edited by hand.
-- The limits are NOT stored here. They live in the server's code (free 50 MB, member
-- 500 MB) and are passed to storage_account_reserve, so the Terms can read them from
-- code like every other figure.
--
-- Safe to re-run: IF NOT EXISTS on tables and indexes, each named CHECK dropped if it
-- exists before it is added, CREATE OR REPLACE on the function, the trigger dropped
-- if it exists before it is created.
-- Paste-safe: no less-or-equal or greater-or-equal operators.
-- Row level security is on with no policies and anon/authenticated are revoked.
BEGIN;

CREATE TABLE IF NOT EXISTS public.storage_account_objects (
  bucket text NOT NULL,
  path text NOT NULL,
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  bytes bigint NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (bucket, path)
);
ALTER TABLE public.storage_account_objects DROP CONSTRAINT IF EXISTS storage_account_objects_bytes_ok;
ALTER TABLE public.storage_account_objects ADD CONSTRAINT storage_account_objects_bytes_ok
  CHECK (bytes > -1);
CREATE INDEX IF NOT EXISTS storage_account_objects_user_idx ON public.storage_account_objects (user_id);

CREATE TABLE IF NOT EXISTS public.storage_account_totals (
  user_id uuid PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE,
  bytes bigint NOT NULL DEFAULT 0,
  files integer NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.storage_account_totals DROP CONSTRAINT IF EXISTS storage_account_totals_not_negative;
ALTER TABLE public.storage_account_totals ADD CONSTRAINT storage_account_totals_not_negative
  CHECK (bytes > -1 AND files > -1);

-- The totals follow the objects.
CREATE OR REPLACE FUNCTION public.storage_account_objects_total()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP IN ('UPDATE', 'DELETE') THEN
    UPDATE public.storage_account_totals
       SET bytes = greatest(0, bytes - OLD.bytes), files = greatest(0, files - 1), updated_at = now()
     WHERE user_id = OLD.user_id;
  END IF;
  IF TG_OP IN ('INSERT', 'UPDATE') THEN
    INSERT INTO public.storage_account_totals (user_id, bytes, files) VALUES (NEW.user_id, NEW.bytes, 1)
    ON CONFLICT (user_id) DO UPDATE
      SET bytes = public.storage_account_totals.bytes + EXCLUDED.bytes,
          files = public.storage_account_totals.files + 1,
          updated_at = now();
  END IF;
  RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS storage_account_objects_total ON public.storage_account_objects;
CREATE TRIGGER storage_account_objects_total
  AFTER INSERT OR UPDATE OR DELETE ON public.storage_account_objects
  FOR EACH ROW EXECUTE FUNCTION public.storage_account_objects_total();

ALTER TABLE public.storage_account_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.storage_account_totals ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.storage_account_objects FROM anon, authenticated;
REVOKE ALL ON public.storage_account_totals FROM anon, authenticated;
REVOKE ALL ON FUNCTION public.storage_account_objects_total() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.storage_account_objects_total() TO service_role;

COMMIT;
