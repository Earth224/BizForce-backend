-- ============================================================================
-- 092_inventory_movement_function.sql
--
-- record_inventory_movement — the one writer of inventory_items.quantity_on_hand.
--
-- The function already exists in production; this file is the repo record of
-- it. `create or replace` makes it a no-op in effect against the live database.
-- The body below is the one that was run. It is NOT a read-back from pg_proc:
-- there is no SQL path from the working environment (.env carries no
-- DATABASE_URL and no postgres driver is installed), and PostgREST exposes a
-- function's parameters but never its source. The SIGNATURE was verified
-- against the live database — nine parameters, names and types matching, with
-- p_item_id, p_user_id, p_direction and p_quantity required and the remaining
-- five defaulted — which is what the revoke and grant at the foot depend on.
--
-- ── VALIDATION ORDER ───────────────────────────────────────────────────────
--   Follows the rule bfc_transfer and bfc_donate encode between them: a check
--   goes before the lock if and only if the arguments alone can answer it.
--
--   Direction, shape and positivity are argument-only and sit first. Nothing
--   about them needs a row, so paying for a lock to learn that p_direction is
--   'inn' would be a wasted lock held while the answer was already in hand.
--   item_not_found needs the row and sits after.
--
--   The clearest evidence that this is a rule rather than a habit is that the
--   same check sits on opposite sides of the lock in the two precedents:
--   bfc_transfer compares p_from to p_to and so checks first, while bfc_donate
--   must compare p_donor against v_owner from the fetched row and so checks
--   fifth. Same rule, different information.
--
--   THE LOCK IS ON inventory_items because quantity_on_hand is the running
--   total about to move — the same reason bfc_donate locks the campaign rather
--   than a wallet, its raised_bfc being what is about to change. One lock,
--   taken once, with every later decision reading the values it returned.
--
--   The lock predicate carries user_id as well as id, so ownership and
--   existence are settled by the same statement and there is no window between
--   checking who owns the row and writing to it. item_not_found therefore
--   covers both "no such item" and "not yours", deliberately not
--   distinguishing them — the same posture the CRM and prospect routes take
--   when they answer 404 for both.
--
--   One departure from bfc_transfer, and it is an improvement rather than a
--   variation: this tests `if not found` where bfc_transfer tests
--   `if cur is null`. The latter conflates "no row came back" with "a row came
--   back holding null", which is harmless only because user_wallets.balance is
--   NOT NULL. `not found` says what is meant.
--
-- ── EXCEPTION MESSAGES ARE BARE TOKENS ─────────────────────────────────────
--   Following 088, not bfc_transfer's lowercase phrases ('insufficient
--   balance') and not bfc_donate's sentence prose ('Campaign not found').
--
--   Only tokens are usable by a route. A raised exception has no SQLSTATE of
--   its own, so the message is the only carrier, and a route can act on it
--   only by matching it exactly. 088 records why the match must be `===` on the
--   trimmed message rather than includes(): a substring test would also match
--   some future error that merely mentioned the token, and would map an
--   unrelated failure to the wrong status. Prose cannot be matched that way at
--   all without encoding a sentence into a handler.
--
--   The five, and what a route should map each to:
--
--     invalid_direction            400  p_direction absent or not one of
--                                       in / out / adjust
--     counted_quantity_required    400  direction is adjust with no observed
--                                       figure, or a negative one
--     counted_quantity_not_allowed 400  a counted figure sent on an in or out
--     quantity_must_be_positive    400  in or out with a null or non-positive
--                                       quantity
--     item_not_found               404  no item with that id belonging to the
--                                       caller
--
--   Anything else is a database fault and belongs in a 500. A route that maps
--   the five and rethrows the rest is correct; one that turns every raise into
--   a 400 is not, and that is what the wallet routes currently do.
--
-- ── THERE IS DELIBERATELY NO NEGATIVE-STOCK CHECK ──────────────────────────
--   An out movement that would take quantity_on_hand below zero is recorded,
--   not refused. There is no CHECK on the column either.
--
--   The wallet analogy does not carry, and it is the analogy this function
--   otherwise follows closely. bfc_transfer refuses with 'insufficient balance'
--   because money cannot leave an account that lacks it — there the ledger IS
--   the money, so the constraint and the reality are the same object. Stock
--   leaves a shelf that does not consult the database. Refusing the movement
--   does not prevent the event; it prevents the RECORD of the event, and here
--   the log is the authoritative artifact while quantity_on_hand is derived
--   from it. Refusing to write the log to protect a number computed from the
--   log inverts which of the two is true.
--
--   The refusal also has a worse failure mode than the negative it prevents.
--   An operator blocked from recording a real sale enters a phantom `in`
--   movement to make room. That fabricates a receipt, and the balance then
--   looks correct — so the discrepancy is gone from the one column anyone
--   watches, and nothing anywhere records that it happened. It is undetectable
--   afterwards. A visible negative is self-announcing: it says exactly one
--   thing, that stock was shipped which was never booked in, in the place an
--   operator already looks.
--
--   No CHECK (quantity_on_hand >= 0) either, so a backfill path stays open. A
--   constraint would have to be worked around by the first historical import,
--   which is the reason 069 gives for leaving consent_events append-only as a
--   discipline rather than a trigger: adding the hard version now would
--   constrain code that has not been written yet.
--
-- ── adjust IS A COUNT, NOT A DELTA ─────────────────────────────────────────
--   The caller passes the figure a physical count actually observed in
--   p_counted_quantity. The function computes the delta against the LOCKED
--   value — not against anything the caller believed — and stores its absolute
--   value in quantity, so the column stays positive on every row the way
--   wallet_transactions.amount does.
--
--   A count that agrees with the system writes quantity 0. That is a real event
--   and the proof the count happened, and it is why quantity is >= 0 rather
--   than > 0. inventory_movements_adjust_shape then puts > 0 back for in and
--   out, so a zero-quantity receipt or shipment is still refused. The pair does
--   what a bare quantity >= 0 could not: permit the one zero that means
--   something and forbid the two that do not.
--
--   RECONSTRUCTING THE BALANCE FROM THE LOG, stated precisely because it is
--   easy to state wrongly. direction 'adjust' carries no sign, and quantity
--   holds abs(delta), so a correction of three down and a correction of three
--   up are stored identically in (direction, quantity) and differ only in
--   counted_quantity. A plain sum(in) - sum(out) across the whole log therefore
--   does NOT equal quantity_on_hand once any adjust exists — it diverges by
--   exactly the adjust deltas it cannot see. The correct reconstruction
--   re-anchors: take the most recent adjust's counted_quantity, which is an
--   absolute position rather than a change, and sum the in and out rows that
--   follow it. Where there is no adjust, sum(in) - sum(out) is the whole
--   answer.
--
--   NOTE, recorded rather than silently fixed: the live column comment on
--   inventory_movements.counted_quantity, transcribed verbatim into 091, says
--   "the log stays homogeneous and sum(in) - sum(out) still reconstructs the
--   balance". The first half is true and the second is not, for the reason
--   above. Correcting a live comment is its own migration and does not belong
--   in the file that creates a function; 089 made the same call about a wrong
--   comment in server.js. It is written here so that a reader who finds the two
--   statements side by side knows which one was checked.
--
-- ── last_counted_at ────────────────────────────────────────────────────────
--   Moved only on an adjust, via a CASE that leaves it untouched otherwise.
--   That is what the column is for: it records when stock was last physically
--   counted, not when it last moved. A receipt or a shipment is not a count and
--   must not make the item look recently verified.
--
-- ── THE REVOKE SHIPS WITH THE CREATE ───────────────────────────────────────
--   This is the standing rule from 090 applied for the first time, and it is
--   why this function was never executable by anon for a single moment — unlike
--   the six that 090 had to repair after the fact.
--
--   It is SECURITY DEFINER, so RLS does not apply and p_user_id IS the
--   authorisation. That trust is unavoidable here rather than merely
--   convenient: inventory_movements has no user_id column, so the only route to
--   an owner is the inventory_items row this function locks. p_user_id must
--   come from req.user.id and from nothing a client can set.
--
--   The exposure that would follow from getting this wrong is not reading rows.
--   Anyone able to call it could write movements against anyone's items and
--   desynchronise every quantity_on_hand in the system, through the one
--   function the schema designates as the sole writer of that column.
--
-- ── ORDERING ───────────────────────────────────────────────────────────────
--   Depends on 091 for both tables. The body is stored as text and resolved at
--   execution, so creating this against a database lacking them would SUCCEED
--   and fail on first call — the failure mode 089 documents for bfc_donate,
--   where a fresh clone built cleanly and every donation failed at the point
--   money was moving. 091 precedes this file, so a full replay is correct.
-- ============================================================================

create or replace function public.record_inventory_movement(
  p_item_id uuid,
  p_user_id uuid,
  p_direction text,
  p_quantity integer,
  p_counted_quantity integer default null,
  p_reason text default null,
  p_reference text default null,
  p_unit_cost numeric default null,
  p_occurred_at timestamptz default null
)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  v_on_hand integer;
  v_delta integer;
  v_quantity integer;
  v_new_on_hand integer;
begin
  if p_direction is null or p_direction not in ('in', 'out', 'adjust') then
    raise exception 'invalid_direction';
  end if;

  if p_direction = 'adjust' then
    if p_counted_quantity is null or p_counted_quantity < 0 then
      raise exception 'counted_quantity_required';
    end if;
  else
    if p_counted_quantity is not null then
      raise exception 'counted_quantity_not_allowed';
    end if;
    if p_quantity is null or p_quantity <= 0 then
      raise exception 'quantity_must_be_positive';
    end if;
  end if;

  select quantity_on_hand into v_on_hand
  from public.inventory_items
  where id = p_item_id and user_id = p_user_id
  for update;

  if not found then
    raise exception 'item_not_found';
  end if;

  if p_direction = 'adjust' then
    v_delta := p_counted_quantity - v_on_hand;
    v_quantity := abs(v_delta);
  elsif p_direction = 'in' then
    v_delta := p_quantity;
    v_quantity := p_quantity;
  else
    v_delta := -p_quantity;
    v_quantity := p_quantity;
  end if;

  update public.inventory_items
  set quantity_on_hand = quantity_on_hand + v_delta,
      last_counted_at = case when p_direction = 'adjust' then now() else last_counted_at end,
      updated_at = now()
  where id = p_item_id and user_id = p_user_id
  returning quantity_on_hand into v_new_on_hand;

  insert into public.inventory_movements (
    item_id, direction, quantity, counted_quantity,
    reason, reference, unit_cost, occurred_at, created_at
  )
  values (
    p_item_id,
    p_direction,
    v_quantity,
    p_counted_quantity,
    p_reason,
    p_reference,
    p_unit_cost,
    coalesce(p_occurred_at, now()),
    now()
  );

  return v_new_on_hand;
end;
$$;

revoke execute on function public.record_inventory_movement(uuid, uuid, text, integer, integer, text, text, numeric, timestamptz) from public, anon, authenticated;
grant execute on function public.record_inventory_movement(uuid, uuid, text, integer, integer, text, text, numeric, timestamptz) to service_role;
