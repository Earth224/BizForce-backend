-- ============================================================================
-- 091_inventory_system.sql
--
-- inventory_items and inventory_movements — a transcription, not a change.
--
-- Both tables ALREADY EXIST IN PRODUCTION and neither has ever had DDL in this
-- repo. This file records them, in the same spirit as 034 (marketplace_orders),
-- 071 (the foundation tables) and 089 (the wallet functions): the schema was
-- built live, and a migration directory that does not contain it cannot rebuild
-- it. `create table if not exists`, guarded constraint adds and
-- `create index if not exists` make this a no-op in effect against the live
-- database.
--
-- THIS FILE IS COMPLETE. Every column, type, precision, default, nullability,
-- constraint and index below, and the row level security posture, is
-- transcribed from the live database rather than inferred. The three things an
-- OpenAPI description cannot express — numeric precision, index definitions and
-- RLS state — were read from pg_attribute, pg_indexes, pg_class and pg_policies
-- and pasted verbatim. Nothing here is a guess.
--
-- ── HOW IT WAS READ ────────────────────────────────────────────────────────
--   There is no SQL path from the working environment: .env carries
--   SUPABASE_URL, SUPABASE_SERVICE_KEY and SUPABASE_ANON_KEY but no
--   DATABASE_URL, and no postgres driver is installed. Columns, types,
--   nullability, defaults, foreign key targets and comments came from
--   PostgREST's OpenAPI description, which is generated per role and served to
--   the service key alone. Everything that description cannot carry — the
--   constraint bodies with their ON DELETE actions, the numeric precisions, the
--   seven index definitions, and whether RLS is on — came from the system
--   catalogs directly.
--
--   That split is worth recording because the second half is invisible to the
--   first. PostgREST reports "numeric" identically for numeric and
--   numeric(12,2), and reports nothing at all about indexes or RLS. A
--   transcription built from the API alone would have looked complete, widened
--   three columns, dropped five indexes including a uniqueness rule, and
--   silently left RLS off.
--
-- ── THE FOUR DESIGN DECISIONS THIS SCHEMA ENCODES ──────────────────────────
--   Recorded here because the constraints state WHAT was decided and nothing
--   states why, and every one of the four was chosen against a plausible
--   alternative.
--
--   1. quantity_on_hand MAY GO NEGATIVE. There is deliberately no
--      CHECK (quantity_on_hand >= 0), which is a departure from the idiom this
--      schema otherwise follows — bfc_transfer refuses with 'insufficient
--      balance' rather than letting a wallet go under.
--
--      The wallet analogy does not carry. Money cannot leave an account that
--      lacks it, because there the ledger IS the money and the constraint is
--      the reality. Stock leaves a shelf the database believes is empty,
--      because the shelf does not consult the database. Refusing the movement
--      would not prevent the event; it would only prevent the RECORD of it, and
--      the log is the authoritative artifact here while quantity_on_hand is
--      derived from it. A negative balance is also self-announcing: it says
--      exactly one thing, that stock was shipped which was never booked in, in
--      the column an operator already watches. The refusal alternative has a
--      worse failure mode than the negative — an operator blocked from
--      recording a real sale enters a phantom `in` movement to make room, which
--      fabricates a receipt and leaves the balance looking correct.
--
--   2. adjust CARRIES counted_quantity ALONGSIDE THE DELTA. A physical count is
--      an absolute — "there are 47" — and this log is homogeneous deltas with
--      the sign in `direction`. Reinterpreting `quantity` to mean "the new
--      total" when direction is 'adjust' would have made the column mean two
--      different things and broken sum(in) - sum(out) silently for any reader
--      who assumed otherwise. Storing only the implied delta would have kept
--      the log summable but discarded 47, the one number anyone actually
--      observed. counted_quantity keeps both.
--
--   3. quantity IS >= 0, NOT > 0. wallet_transactions.amount and
--      campaign_donations.amount_bfc are both > 0, and copying that here by
--      analogy would have made a count that AGREES with the system
--      unrecordable — it is a zero delta. That is the most common outcome of
--      counting a well-run stockroom, and it is the proof the count happened.
--      The floor is relaxed to >= 0 for that case alone, and
--      inventory_movements_adjust_shape puts > 0 back for 'in' and 'out', so a
--      zero-quantity receipt or shipment is still refused. The pair does what
--      neither constraint could alone.
--
--   4. item_id IS ON DELETE RESTRICT. Not CASCADE, which is what
--      consent_events.contact_id chose in 069 — but 069's reasoning was that an
--      orphaned consent event proves nothing about anybody, and that deleting a
--      contact is an erasure where destruction is the point. Neither holds
--      here: an orphaned movement still carries quantity, unit_cost, reference
--      and occurred_at, so cascading would retroactively change historical
--      cost-of-goods for closed periods, and deleting an item is "we stopped
--      stocking this" rather than a demand that nothing remain.
--
--      SET NULL — which campaign_donations.campaign_id chose for exactly this
--      shape, a movement log pointing at the parent whose running total it
--      feeds — is not available. campaign_donations could afford it because it
--      carries donor_id and owner_id of its own, so an orphaned donation is
--      still attributable and its RLS policy still matches. inventory_movements
--      has NO user_id: item_id is its only route to an owner, so a null there
--      produces a row belonging to nobody, reachable by no policy and visible
--      to no route. That is more orphaned than the orphaned consent event 069
--      rejected.
--
--      RESTRICT leaves retirement as the intended path, which is what
--      inventory_items.status already exists for.
--
-- ── HOW A ROUTE MUST SURFACE THE RESTRICT ──────────────────────────────────
--   A DELETE against an item with movements raises SQLSTATE 23503,
--   foreign_key_violation. PostgREST returns the SQLSTATE verbatim in the error
--   body's `code` field, so the route branches on a five-character constant and
--   never reads the message — the same mechanism the prospects write routes
--   already use for 23505. It is 409, not the 404 the other delete routes
--   return on a no-op: the row exists and belongs to the caller, and the server
--   declined. The branch must sit ABOVE `if (error) throw error`, or an
--   ordinary refusal becomes a 500.
--
--   The ownership predicate closes the obvious probe for free. Scoping the
--   delete .eq("user_id", req.user.id) means another user's item matches no
--   row, so no FK check fires and the answer is the plain 404 — a 409 is only
--   ever visible to the owner, and 23503 cannot be used to discover whether
--   somebody else's item has movements.
--
--   23503 is unambiguous inside a DELETE handler only while
--   inventory_movements is the sole RESTRICT-ing child. A second one would make
--   the code alone insufficient and force either constraint-name matching or a
--   function that re-raises a token the way convert_prospect_to_customer does.
-- ============================================================================


-- ── inventory_items ────────────────────────────────────────────────────────
-- unit_cost and unit_price are numeric(12,2), matching deals.amount rather than
-- profile_products.price's numeric(10,2). The catalogue and the stock record
-- differ on purpose. profile_products holds a display price for one item on a
-- brochure page whose buy_link leaves the site; these two are multiplied by
-- quantity_on_hand to value a whole holding, and a valuation has more room
-- above it than any single price tag needs. Transcribing them as bare `numeric`
-- would have silently widened all three to unlimited precision.
create table if not exists public.inventory_items (
  id                uuid                     not null default gen_random_uuid(),
  user_id           uuid                     not null,
  name              text                     not null,
  sku               text,
  description       text,
  category          text,
  unit              text                     not null default 'unit'::text,
  quantity_on_hand  integer                  not null default 0,
  reorder_point     integer,
  reorder_quantity  integer,
  unit_cost         numeric(12,2),
  unit_price        numeric(12,2),
  location          text,
  supplier          text,
  status            text                     not null default 'active'::text,
  notes             text,
  product_id        uuid,
  last_counted_at   timestamp with time zone,
  created_at        timestamp with time zone not null default now(),
  updated_at        timestamp with time zone not null default now()
);


-- ── inventory_movements ────────────────────────────────────────────────────
-- unit_cost is numeric(12,2) on the same terms as the two above: it is the cost
-- carried by one movement, multiplied by quantity when a receipt is valued.
create table if not exists public.inventory_movements (
  id                uuid                     not null default gen_random_uuid(),
  item_id           uuid                     not null,
  direction         text                     not null,
  quantity          integer                  not null,
  reason            text,
  reference         text,
  unit_cost         numeric(12,2),
  occurred_at       timestamp with time zone not null default now(),
  created_at        timestamp with time zone not null default now(),
  counted_quantity  integer
);


-- ── Keys and checks ────────────────────────────────────────────────────────
-- Guarded with `if not exists` on conname rather than DROP-then-ADD, following
-- 071 rather than 069: this is a transcription of live objects, and a drop
-- would briefly remove a live constraint to re-add it identically.
--
-- The two PRIMARY KEY clauses below create inventory_items_pkey and
-- inventory_movements_pkey — both unique btree indexes on (id) — implicitly.
-- They are not repeated in the index section, where a separate CREATE INDEX
-- under the same name would fail.

do $$ begin if not exists (select 1 from pg_constraint where conname = 'inventory_items_pkey' and conrelid = 'public.inventory_items'::regclass) then
  alter table public.inventory_items add constraint inventory_items_pkey PRIMARY KEY (id);
end if; end $$;

do $$ begin if not exists (select 1 from pg_constraint where conname = 'inventory_items_user_id_fkey' and conrelid = 'public.inventory_items'::regclass) then
  alter table public.inventory_items add constraint inventory_items_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
end if; end $$;

do $$ begin if not exists (select 1 from pg_constraint where conname = 'inventory_items_product_id_fkey' and conrelid = 'public.inventory_items'::regclass) then
  alter table public.inventory_items add constraint inventory_items_product_id_fkey FOREIGN KEY (product_id) REFERENCES profile_products(id) ON DELETE SET NULL;
end if; end $$;

do $$ begin if not exists (select 1 from pg_constraint where conname = 'inventory_movements_pkey' and conrelid = 'public.inventory_movements'::regclass) then
  alter table public.inventory_movements add constraint inventory_movements_pkey PRIMARY KEY (id);
end if; end $$;

do $$ begin if not exists (select 1 from pg_constraint where conname = 'inventory_movements_item_id_fkey' and conrelid = 'public.inventory_movements'::regclass) then
  alter table public.inventory_movements add constraint inventory_movements_item_id_fkey FOREIGN KEY (item_id) REFERENCES inventory_items(id) ON DELETE RESTRICT;
end if; end $$;

do $$ begin if not exists (select 1 from pg_constraint where conname = 'inventory_movements_quantity_nonneg' and conrelid = 'public.inventory_movements'::regclass) then
  alter table public.inventory_movements add constraint inventory_movements_quantity_nonneg CHECK ((quantity >= 0));
end if; end $$;

do $$ begin if not exists (select 1 from pg_constraint where conname = 'inventory_movements_direction_check' and conrelid = 'public.inventory_movements'::regclass) then
  alter table public.inventory_movements add constraint inventory_movements_direction_check CHECK ((direction = ANY (ARRAY['in'::text, 'out'::text, 'adjust'::text])));
end if; end $$;

do $$ begin if not exists (select 1 from pg_constraint where conname = 'inventory_movements_adjust_shape' and conrelid = 'public.inventory_movements'::regclass) then
  alter table public.inventory_movements add constraint inventory_movements_adjust_shape CHECK ((((direction = 'adjust'::text) AND (counted_quantity IS NOT NULL)) OR ((direction = ANY (ARRAY['in'::text, 'out'::text])) AND (counted_quantity IS NULL) AND (quantity > 0))));
end if; end $$;


-- ── Indexes ────────────────────────────────────────────────────────────────
-- Seven live indexes; the two pkeys are created by the PRIMARY KEY clauses
-- above and the remaining five are below.
--
-- inventory_items_user_sku_uniq is the one carrying a rule rather than a
-- lookup: one SKU per user, case-insensitive, and PARTIAL on the sku being
-- both non-null and non-empty. Both halves of that predicate matter. Postgres
-- already treats nulls as distinct in a unique index, so the null half is
-- belt-and-braces; the `sku <> ''` half is the load-bearing one, because
-- without it every item saved with an empty SKU would compete for a single
-- slot per user and the second one would be rejected as a duplicate of the
-- first. That is the same shape as contacts_owner_email_uniq in 069, and it
-- exists here because this schema has no equivalent of the optionalText rule
-- 087 records — nothing guarantees an absent SKU arrives as null rather than
-- as "".
--
-- inventory_items_product_idx is partial on product_id IS NOT NULL, following
-- the prospects converted_customer_id index in 087: the column is nullable and
-- expected to be null on most rows, so indexing the nulls would store a large
-- entry set that no query ever reads.

create index if not exists inventory_items_product_idx
  on public.inventory_items using btree (product_id)
  where (product_id is not null);

create index if not exists inventory_items_user_created_idx
  on public.inventory_items using btree (user_id, created_at desc);

create unique index if not exists inventory_items_user_sku_uniq
  on public.inventory_items using btree (user_id, lower(sku))
  where ((sku is not null) and (sku <> ''::text));

create index if not exists inventory_items_user_status_idx
  on public.inventory_items using btree (user_id, status);

create index if not exists inventory_movements_item_idx
  on public.inventory_movements using btree (item_id, occurred_at desc);


-- ── Row level security: enabled, with no policies ──────────────────────────
-- Read from pg_class rather than assumed: relrowsecurity is true on both tables
-- and relforcerowsecurity is false on both, and pg_policies returns no rows for
-- either. There are no policies to transcribe. The absence is the design.
--
-- This is the posture 083 records for its five tables, 070 for email_sends and
-- 069 for contacts and consent_events. server.js connects with
-- SUPABASE_SERVICE_KEY and the service role bypasses RLS entirely, so every
-- backend route behaves exactly as it would with RLS off; enabling it costs the
-- application nothing. What it buys is that the anon key reads nothing here.
-- Access control stays where it already is, in the route handlers, scoped by
-- req.user.id.
--
-- THE HAZARD, in the terms 083 states it: a denied table answers the anon key
-- with HTTP 200 and an EMPTY BODY, not 42501 permission denied. The anon role
-- HOLDS the table grant and RLS alone is what stops it, so a single narrow
-- policy added to either table is the only thing standing between the anon key
-- and its contents. Whoever writes one is not loosening a restriction, they are
-- removing the only one there is.
--
-- AND THE TRAP SPECIFIC TO THIS PAIR: inventory_movements HAS NO user_id.
-- A policy on inventory_items can compare auth.uid() to a column that exists.
-- A policy on inventory_movements cannot — it has to reach the owner through
-- item_id, with an EXISTS against inventory_items. A direct auth.uid()
-- comparison written there would be against a column that is not on the table,
-- which fails loudly; the dangerous version is the one that compiles, such as a
-- USING clause that omits the join and is therefore true for every row. There
-- being no policies today is exactly when that is easiest to get wrong, because
-- there is no neighbouring policy to copy the join from.

alter table public.inventory_items     enable row level security;
alter table public.inventory_movements enable row level security;


-- ── Comments ───────────────────────────────────────────────────────────────
-- Transcribed verbatim from the live database.

comment on table public.inventory_movements is
  'Append-only movement log, following the wallet_transactions idiom: quantity is always positive and direction carries the sign, so nothing in this table is negative. quantity_on_hand on the parent is the denormalised running total, written under a row lock in the same function that inserts the movement — the same shape as user_wallets.balance and crowdfunding_campaigns.raised_bfc.';

comment on column public.inventory_items.quantity_on_hand is
  'Denormalised running total. NEVER write this directly — it is maintained by record_inventory_movement, which locks the item row and inserts the movement in the same transaction. A direct update silently desynchronises it from the log.';

comment on column public.inventory_items.product_id is
  'Optional link to a profile_products catalogue row. ON DELETE SET NULL: deleting a brochure entry must not delete the stock record. profile_products never transacts — its buy_link leaves the site — so nothing decrements from a catalogue sale.';

comment on column public.inventory_movements.direction is
  'in = received or returned, out = sold or consumed, adjust = a count correction. CHECK-constrained here rather than in the application because unlike a status vocabulary this is a three-value arithmetic sign, not a lifecycle that grows.';

comment on column public.inventory_movements.counted_quantity is
  'The figure a physical count actually observed, set only when direction is adjust and null otherwise. quantity still carries the absolute delta the count implied, so the log stays homogeneous and sum(in) - sum(out) still reconstructs the balance. A count that agrees with the system writes quantity 0 with counted_quantity set — which is why quantity is >= 0 rather than > 0, against the wallet_transactions precedent: a count confirming nothing changed is a real event and the proof the count happened.';
