-- APPLIED (P3-1, recorded Nov 20 2026): applied BY HAND by the owner in the Supabase SQL editor on Nov 20 2026,
-- in four parts, WITHOUT the BEGIN/COMMIT below and WITHOUT the DO-block STOP:
--   (A) the email_canonical function and the column;
--   (B) the trigger function, the trigger and the back-fill;
--   (C) a plain SELECT of canonical values held by more than one account (it returned no rows);
--   (D) the unique index and the grants.
-- Before (A), the three +tag test accounts were moved to hiram-test1@, hiram-bftest2@ and
-- hiram-bftest3@bizforceai.invalid, so no inbox folded twice.
-- Verified after all four (owner, Nov 20 2026): missing_canonical 0, duplicate_canonical 0, canonical_index true, totals_off 0, rls_on true, accounts_counted 1, database 83 MB.
-- The text below is unchanged from P3-1A.
--
-- 195 (P3-1A, Nov 20 2026): users.email_canonical, one account per inbox.
-- The canonical form of an email:
--   lowercase and trimmed;
--   the +tag is removed from the local part, for every domain;
--   dots are removed from the local part for gmail.com and googlemail.com;
--   googlemail.com becomes gmail.com.
-- The test domain @bizforceai.invalid is NOT folded (only lowercased and trimmed),
-- so the check suite's +bftest accounts there stay distinct.
-- A local part that would fold to nothing (for example "+x@site.com") is kept as it is.
--
-- Order: the function, the column, the trigger that keeps it in step on every insert
-- and update, the back-fill, then a STOP if any two accounts fold to the same value,
-- and only then the unique index. The whole file is one transaction: if it stops,
-- nothing at all is changed.
-- The STOP is the one short DO block in this file; a plain statement cannot raise an
-- error that names the clashing inboxes.
-- Safe to re-run: CREATE OR REPLACE on the functions, IF NOT EXISTS on the column and
-- the index, and the trigger dropped if it exists before it is created.
-- Paste-safe: no less-or-equal or greater-or-equal operators.
BEGIN;

CREATE OR REPLACE FUNCTION public.email_canonical(p_email text)
RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN x.e IS NULL OR x.dom IS NULL THEN x.e
    WHEN x.dom = 'bizforceai.invalid' THEN x.e
    WHEN x.loc2 IS NULL OR x.loc2 = '' THEN x.e
    ELSE x.loc2 || '@' || x.dom2
  END
  FROM (
    SELECT s.e, s.dom,
      CASE WHEN s.dom IN ('gmail.com', 'googlemail.com')
        THEN replace(split_part(s.loc, '+', 1), '.', '')
        ELSE split_part(s.loc, '+', 1) END AS loc2,
      CASE WHEN s.dom = 'googlemail.com' THEN 'gmail.com' ELSE s.dom END AS dom2
    FROM (
      SELECT lower(btrim(p_email)) AS e,
        substring(lower(btrim(p_email)) from '^(.*)@[^@]*$') AS loc,
        substring(lower(btrim(p_email)) from '@([^@]*)$') AS dom
    ) s
  ) x
$$;

ALTER TABLE public.users ADD COLUMN IF NOT EXISTS email_canonical text;

CREATE OR REPLACE FUNCTION public.users_set_email_canonical()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.email_canonical := public.email_canonical(NEW.email);
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS users_email_canonical_set ON public.users;
CREATE TRIGGER users_email_canonical_set
  BEFORE INSERT OR UPDATE ON public.users
  FOR EACH ROW EXECUTE FUNCTION public.users_set_email_canonical();

-- Back-fill (the trigger also sets it, but this states it plainly).
UPDATE public.users
   SET email_canonical = public.email_canonical(email)
 WHERE email_canonical IS DISTINCT FROM public.email_canonical(email);

-- STOP before the index if two accounts share an inbox.
DO $$
DECLARE clash text;
BEGIN
  SELECT string_agg(g.email_canonical || ' (' || g.n || ' accounts)', '; ') INTO clash
    FROM (SELECT email_canonical, count(*) AS n FROM public.users
           WHERE email_canonical IS NOT NULL
           GROUP BY email_canonical HAVING count(*) > 1) g;
  IF clash IS NOT NULL THEN
    RAISE EXCEPTION '195 STOPPED, nothing was changed. These emails fold to the same inbox: %. Change or remove the extra accounts, then run 195 again.', clash;
  END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS users_email_canonical_key ON public.users (email_canonical);

REVOKE ALL ON FUNCTION public.email_canonical(text) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.users_set_email_canonical() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.email_canonical(text) TO service_role;
GRANT EXECUTE ON FUNCTION public.users_set_email_canonical() TO service_role;

COMMIT;
