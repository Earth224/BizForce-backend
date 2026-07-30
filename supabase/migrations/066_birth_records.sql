-- 066_birth_records.sql
-- Adds public.birth_records: birth data for chart subjects who are not necessarily
-- account holders, with the geocoding result frozen at the moment it was resolved.
-- Purely additive. It creates one new table, its constraints and one index, and
-- touches nothing that already exists — oracle_sync in particular is left exactly
-- as migration 041 recorded it. Idempotent and safe to re-run: the table creation
-- is guarded, every constraint is dropped-if-exists before being added, the index
-- is guarded, and COMMENT ON simply overwrites.

-- ── birth_records: a chart subject's birth data, with coordinates frozen ──
CREATE TABLE IF NOT EXISTS public.birth_records (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          uuid,
  contact_email    text,
  label            text        NOT NULL DEFAULT 'self',
  birth_name       text,
  birth_date       date        NOT NULL,
  birth_time       time,
  place_query      text        NOT NULL,
  place_label      text,
  latitude         numeric(9,6),
  longitude        numeric(9,6),
  timezone         text,
  place_confidence text        NOT NULL DEFAULT 'unresolved',
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now()
);

-- ── user_id references public.users, and is deliberately nullable ──
-- public.users, NOT auth.users: this project has a documented history of keys
-- pointed at Supabase's empty auth.users, where every insert fails 23503 and
-- surfaces as an unexplained 500. Migration 041 exists solely to repoint four such
-- tables. This one is written correctly from the start.
--
-- ON DELETE SET NULL rather than CASCADE, because the row outlives the account.
-- A closed account must not delete a chart that was paid for, and for the guest
-- and second-party rows below there is no account to cascade from in the first
-- place.
ALTER TABLE public.birth_records DROP CONSTRAINT IF EXISTS birth_records_user_id_fkey;
ALTER TABLE public.birth_records ADD  CONSTRAINT birth_records_user_id_fkey
  FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;

-- ── birth_date stays inside the ephemeris band ──
-- The same 1700-01-01 to 2200-12-31 range parseBirthDate enforces in server.js.
-- That band is not caution: astronomy-engine's accuracy degrades outside it, and
-- the city-timezones dataset has nothing meaningful to say about zones there. The
-- application rejects out-of-band dates with reason 'year_out_of_range'; this is
-- the database-side mirror of that rule, so a future write path that forgets the
-- helper fails at insert rather than storing a date no chart can be built from.
--
-- Note the asymmetry with the numerology engines, which call parseBirthDate with
-- requireEphemerisRange: false on purpose — digit-summing a date needs no
-- ephemeris. This table stores chart inputs, so here the band applies.
ALTER TABLE public.birth_records DROP CONSTRAINT IF EXISTS birth_records_birth_date_range_check;
ALTER TABLE public.birth_records ADD  CONSTRAINT birth_records_birth_date_range_check
  CHECK (birth_date BETWEEN DATE '1700-01-01' AND DATE '2200-12-31');

-- ── place_confidence is a closed set ──
ALTER TABLE public.birth_records DROP CONSTRAINT IF EXISTS birth_records_place_confidence_check;
ALTER TABLE public.birth_records ADD  CONSTRAINT birth_records_place_confidence_check
  CHECK (place_confidence IN ('exact', 'chosen', 'unresolved'));

-- ── Coordinates and confidence agree, in both directions ──
-- One constraint, two exhaustive branches. 'unresolved' means the place was never
-- resolved, so all three resolved fields must be null; anything else means it WAS
-- resolved, so all three must be present. This is what stops the state that would
-- be worst to debug: a row claiming 'exact' while carrying a null latitude, which
-- would read as a resolved place and silently produce a chart with no Ascendant.
-- place_confidence is NOT NULL, so these two branches cover every row.
ALTER TABLE public.birth_records DROP CONSTRAINT IF EXISTS birth_records_place_resolution_check;
ALTER TABLE public.birth_records ADD  CONSTRAINT birth_records_place_resolution_check
  CHECK (
    (place_confidence =  'unresolved' AND latitude IS     NULL AND longitude IS     NULL AND timezone IS     NULL)
    OR
    (place_confidence <> 'unresolved' AND latitude IS NOT NULL AND longitude IS NOT NULL AND timezone IS NOT NULL)
  );

-- ── Coordinates are within the ranges the words mean ──
-- Nulls pass explicitly, which is correct: the constraint above is what decides
-- WHETHER coordinates must be present, and this one only governs their values when
-- they are. numeric(9,6) permits three integer digits, which covers longitude's
-- 180 as well as latitude's 90.
ALTER TABLE public.birth_records DROP CONSTRAINT IF EXISTS birth_records_coordinate_range_check;
ALTER TABLE public.birth_records ADD  CONSTRAINT birth_records_coordinate_range_check
  CHECK (
    (latitude  IS NULL OR latitude  BETWEEN  -90 AND  90) AND
    (longitude IS NULL OR longitude BETWEEN -180 AND 180)
  );

-- ── Index on the owner column ──
CREATE INDEX IF NOT EXISTS birth_records_user_id_idx
  ON public.birth_records (user_id);

-- ── One record per label per account, for accounts only ──
-- Partial on user_id IS NOT NULL. See the COMMENT ON INDEX below for why the
-- guest and marketplace rows are exempt by design rather than by omission.
CREATE UNIQUE INDEX IF NOT EXISTS birth_records_user_label_uniq
  ON public.birth_records (user_id, label)
  WHERE user_id IS NOT NULL;

-- ── updated_at maintenance ──
-- This is the FIRST trigger in this migrations folder. A search of every .sql file
-- here found no trigger of any kind and only one function — bfc_donate in 031,
-- which is a currency RPC and maintains nothing. So there was no existing
-- convention to follow and this establishes one.
--
-- Written generically, not as birth_records_set_updated_at_fn, so any future table
-- with an updated_at column can attach the same function instead of each one
-- growing its own copy. CREATE OR REPLACE makes it idempotent.
--
-- Clause layout follows bfc_donate in 031, including SET search_path = public,
-- which keeps the function's name resolution independent of the caller's
-- search_path. It deliberately does NOT copy that function's SECURITY DEFINER:
-- bfc_donate needs elevated rights to move currency between wallets, whereas
-- stamping a timestamp on the row already being written needs none, and running a
-- trigger with the definer's privileges for no reason is privilege for its own
-- sake. This runs as SECURITY INVOKER, the default.
--
-- Supersedes the observation recorded in 064's updated_at column comment, which
-- correctly said at the time that no such convention existed. agent_autonomy is
-- NOT retrofitted here — that is a change to an existing table and this migration
-- is additive only.
CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
NEW.updated_at = now();
RETURN NEW;
END;
$$;

-- Dropped before creating: CREATE TRIGGER has no IF NOT EXISTS form, so the
-- drop-then-create pair is what keeps this file re-runnable, exactly as the
-- constraints above use DROP CONSTRAINT IF EXISTS then ADD CONSTRAINT.
DROP TRIGGER IF EXISTS birth_records_set_updated_at ON public.birth_records;
CREATE TRIGGER birth_records_set_updated_at
  BEFORE UPDATE ON public.birth_records
  FOR EACH ROW
  EXECUTE FUNCTION public.set_updated_at();

-- ── Row level security: enabled, with no policies ──
-- Deny by default, and that is the intended end state rather than a stage on the
-- way to writing policies.
--
-- What this does NOT affect: server.js connects with the service-role key, which
-- bypasses RLS entirely, so every existing and future backend read and write
-- against this table behaves exactly as it would with RLS off. Enabling it costs
-- the application nothing.
--
-- What it does affect: with RLS on and zero policies, the anon key can read
-- nothing from this table. Not a filtered subset — nothing. That matters more here
-- than for most tables in this schema, because this one holds birth_name, the
-- exact birth_time, the birth place, and contact_email: a person's full identity
-- and precise moment of birth, which is about as sensitive as a row in this
-- database gets.
--
-- Why deny-by-default rather than a policy set: a policy needs a column to scope
-- by, and user_id is nullable here on purpose. The guest, Etsy and synastry-partner
-- rows have no user_id at all, so there is no owner to compare auth.uid() against
-- and no correct policy that could cover them — any USING clause would either
-- expose every ownerless row or hide them from the service role too. Ownership for
-- those rows is not expressible in SQL, so it is enforced in the route handlers
-- instead, the same posture 059 records for the SMS tables. If a frontend Supabase
-- client is ever introduced, this table needs a deliberate policy design, not a
-- quick USING clause.
ALTER TABLE public.birth_records ENABLE ROW LEVEL SECURITY;

-- ── Comments ──

COMMENT ON TABLE public.birth_records IS
  'Birth data for a chart subject. The resolved coordinates and timezone are stored PERMANENTLY rather than looked up at chart time, so a chart computed today produces the same Ascendant years from now even if the geocoding dataset is updated, corrected or replaced. A chart that silently moves because a city centroid shifted is indistinguishable from a bug. user_id is NULLABLE on purpose: an order arriving from Etsy or a guest checkout has no account behind it, and the second chart in a synastry pair belongs to a person who will never log in. Those rows are still real subjects with real charts, so the table must not require an account to hold one — contact_email is how a subject with no user_id is reached.';

COMMENT ON COLUMN public.birth_records.place_query IS
  'Exactly what the person typed, preserved verbatim and never overwritten by the resolver. Kept for two reasons: it is the only record of what was actually asked for when a resolution turns out to be wrong, and it is what a human re-resolves against later. "Springfield" resolving to the wrong Springfield is only diagnosable if the original string survives.';

COMMENT ON COLUMN public.birth_records.place_label IS
  'The human-readable place the resolver settled on, for display back to the subject so a wrong match is visible to them rather than only to us. Null while place_confidence is unresolved.';

COMMENT ON INDEX public.birth_records_user_label_uniq IS
  'One record per label per account. Stops a logged-in user accumulating duplicate rows for the same label — a double-clicked form submit or a retried request would otherwise create a second ''self'' record, and nothing downstream could say which of the two is the real chart. Partial on user_id IS NOT NULL, so guest, Etsy and synastry-partner rows are exempt: Postgres treats NULL values as distinct from one another in a unique index, meaning any number of rows with a null user_id can share a label. That is the INTENDED behaviour, not a loophole in the index — those rows have no account to deduplicate within, and two unrelated Etsy buyers both labelled ''self'' are two different people who must both be storable.';

COMMENT ON COLUMN public.birth_records.place_confidence IS
  'How the stored coordinates were arrived at. exact = the resolver matched place_query unambiguously. chosen = the query was ambiguous and a specific candidate was selected, so the coordinates are trustworthy but the interpretation of the query was a decision. unresolved = no coordinates; latitude, longitude and timezone are all null and no Ascendant, Midheaven or house placement can be computed from this row. Defaults to unresolved so a row inserted before geocoding runs is honest about it rather than appearing resolved.';
