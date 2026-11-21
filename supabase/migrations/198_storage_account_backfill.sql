-- APPLIED (P3-1, recorded Nov 20 2026): written in P3-1A as 196c_storage_account_backfill.sql and renamed to 198.
-- Applied BY HAND by the owner on Nov 20 2026, as written but WITHOUT the BEGIN/COMMIT below, after 197.
-- Verified after all four (owner, Nov 20 2026): missing_canonical 0, duplicate_canonical 0, canonical_index true, totals_off 0, rls_on true, accounts_counted 1, database 83 MB.
-- It counted 1 account, because most stored paths do not carry their owner's id. P3-1's
-- scripts/storageAccountBackfill.js counts the rest from the tables that point at each file.
-- The text below is unchanged from P3-1A (its "196a/196b/196c" names are now 196, 197 and 198).
--
-- 196c (P3-1A, Nov 20 2026): per-account storage totals, part 3 of 3. Needs 196a.
-- Back-fills storage_account_objects from the files already stored, in every bucket.
-- A file belongs to the first account id that appears in its path (every member
-- upload path carries the member's id, for example media/<id>/..., avatars/<id>/...).
-- A file whose path names no account (platform files) is not counted for anyone.
-- The 196a trigger fills storage_account_totals as the rows go in.
--
-- Safe to re-run: ON CONFLICT DO NOTHING, so a file already counted is left alone and
-- is never counted twice.
-- Paste-safe: no less-or-equal or greater-or-equal operators.
BEGIN;

INSERT INTO public.storage_account_objects (bucket, path, user_id, bytes, created_at)
SELECT DISTINCT ON (o.bucket_id, o.name)
       o.bucket_id,
       o.name,
       u.id,
       greatest(0, coalesce((o.metadata ->> 'size')::bigint, 0)),
       coalesce(o.created_at, now())
  FROM storage.objects o
  CROSS JOIN LATERAL regexp_matches(lower(o.name),
       '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'g')
       WITH ORDINALITY AS m(hit, n)
  JOIN public.users u ON u.id = (m.hit[1])::uuid
 ORDER BY o.bucket_id, o.name, m.n
ON CONFLICT (bucket, path) DO NOTHING;

COMMIT;
