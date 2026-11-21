-- APPLIED (P3-1, recorded Nov 20 2026): written in P3-1A as 196b_storage_account_functions.sql and renamed to 197.
-- Applied BY HAND by the owner on Nov 20 2026, as written but WITHOUT the BEGIN/COMMIT below, after 196.
-- Verified after all four (owner, Nov 20 2026): missing_canonical 0, duplicate_canonical 0, canonical_index true, totals_off 0, rls_on true, accounts_counted 1, database 83 MB.
-- The text below is unchanged from P3-1A (its "196a/196b/196c" names are now 196, 197 and 198).
--
-- 196b (P3-1A, Nov 20 2026): per-account storage totals, part 2 of 3. Needs 196a.
--
-- storage_account_reserve(user, bucket, path, bytes, limit): called by the server
--   BEFORE an upload. It locks the account's totals row, so two uploads at once
--   cannot both slip under the limit. If the file at (bucket, path) is already
--   counted for this account, its old size is taken off first (a re-check with the
--   real size after a signed upload simply replaces the declared size).
--   Over the limit: returns {"ok": false, "used_bytes", "limit_bytes"} and counts
--   nothing. Otherwise counts the file and returns {"ok": true, ...}.
--   A path already counted for a DIFFERENT account is refused with an error.
-- storage_account_release(bucket, path): called when a file is deleted, or when an
--   upload that was reserved fails. Returns the bytes freed (0 if it was not counted).
--
-- Both are SECURITY DEFINER with a fixed search_path, and only service_role may
-- call them.
-- Safe to re-run: CREATE OR REPLACE.
-- Paste-safe: no less-or-equal or greater-or-equal operators.
BEGIN;

CREATE OR REPLACE FUNCTION public.storage_account_reserve(
  p_user uuid, p_bucket text, p_path text, p_bytes bigint, p_limit bigint)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  used bigint;
  prior bigint;
  holder uuid;
BEGIN
  IF p_user IS NULL OR p_bucket IS NULL OR p_path IS NULL
     OR p_bytes IS NULL OR p_bytes < 0 OR p_limit IS NULL OR p_limit < 0 THEN
    RAISE EXCEPTION 'storage_account_reserve: missing or negative argument';
  END IF;

  INSERT INTO storage_account_totals (user_id) VALUES (p_user) ON CONFLICT (user_id) DO NOTHING;
  SELECT bytes INTO used FROM storage_account_totals WHERE user_id = p_user FOR UPDATE;

  SELECT user_id, bytes INTO holder, prior
    FROM storage_account_objects WHERE bucket = p_bucket AND path = p_path;
  IF holder IS NOT NULL AND holder <> p_user THEN
    RAISE EXCEPTION 'storage_account_reserve: % % is counted for another account', p_bucket, p_path;
  END IF;
  prior := coalesce(prior, 0);

  IF used - prior + p_bytes > p_limit THEN
    RETURN jsonb_build_object('ok', false, 'used_bytes', used, 'limit_bytes', p_limit);
  END IF;

  INSERT INTO storage_account_objects (bucket, path, user_id, bytes)
  VALUES (p_bucket, p_path, p_user, p_bytes)
  ON CONFLICT (bucket, path) DO UPDATE SET bytes = EXCLUDED.bytes;

  RETURN jsonb_build_object('ok', true, 'used_bytes', used - prior + p_bytes, 'limit_bytes', p_limit);
END $$;

CREATE OR REPLACE FUNCTION public.storage_account_release(p_bucket text, p_path text)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE freed bigint;
BEGIN
  DELETE FROM storage_account_objects WHERE bucket = p_bucket AND path = p_path
  RETURNING bytes INTO freed;
  RETURN coalesce(freed, 0);
END $$;

REVOKE ALL ON FUNCTION public.storage_account_reserve(uuid, text, text, bigint, bigint) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.storage_account_release(text, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.storage_account_reserve(uuid, text, text, bigint, bigint) TO service_role;
GRANT EXECUTE ON FUNCTION public.storage_account_release(text, text) TO service_role;

COMMIT;
