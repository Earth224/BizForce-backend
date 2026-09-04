-- ============================================================================
-- 088_prospecting_conversion_function.sql
--
-- convert_prospect_to_customer — a transcription, like 087.
--
-- This function ALREADY EXISTS IN PRODUCTION. It was created outside the
-- migration system and read back out of pg_proc to write this file, so a fresh
-- clone rebuilds it as it actually is. `create or replace` makes re-running it
-- a no-op in effect, which is also why it is here and not in 087: a function is
-- dropped and recreated freely, tables are not, and pinning the two together
-- would mean replaying table DDL to fix a function body.
--
-- THE FIRST NON-MONEY OPERATION IN THIS CODEBASE TO USE A POSTGRES FUNCTION
--   Everything else that writes two tables writes them sequentially and logs
--   what it could not finish. creditWallet is the reference: it orders its
--   writes so the survivable partial state is the one that can happen, checks
--   every .error, throws, and names the damage in the log —
--
--     "the balance was credited ... but the wallet_transactions row failed. The
--      money is in the balance with nothing explaining where it came from."
--
--   That is recoverable. Someone reading that line knows the balance is right
--   and the ledger is short one row, and can write the row. The three RPCs that
--   existed before this one — bfc_transfer, bfc_buy_listing, bfc_donate — are
--   the exception, and the line the codebase had drawn was money.
--
--   Conversion crosses that line for a different reason. Done sequentially it
--   is: insert the customer, then stamp the prospect. If the second write
--   fails, a customer exists that no prospect points at — a duplicate the next
--   conversion attempt will happily create again, because the prospect still
--   looks unconverted. Reverse the order and it is worse: a prospect marked
--   converted, carrying converted_at and a converted_customer_id, pointing at a
--   row that was never created. No log line makes that recoverable, because the
--   id in the column never existed to be found. The failure is not "one record
--   is missing", it is "the record says something that was never true".
--
--   So this is atomic, in the shape 031 already established for bfc_donate:
--   plpgsql, security definer, search_path pinned, exceptions raised by name.
--   Either both writes land or neither does.
--
-- FOR UPDATE
--   The select locks the prospect row for the length of the transaction, so two
--   concurrent converts of the same prospect cannot both pass the
--   already_converted check and both insert a customer. Without it the guard
--   below is a read that another session can invalidate a microsecond later,
--   and the result is two customer rows for one prospect with only the second
--   id recorded — the first orphaned and invisible. bfc_donate takes the same
--   lock on the campaign row for the same reason.
--
-- already_converted
--   Makes a double-click safe. A second call returns an error instead of
--   silently creating a duplicate customer and overwriting the first id, which
--   is what an unguarded version would do — and the first customer would then
--   be unreachable from the prospect that created it, with nothing anywhere
--   recording that it exists.
--
--   Both exceptions are raised as bare machine-readable names rather than
--   sentences, so the calling route can map them: prospect_not_found is a 404,
--   already_converted is a 409. supabase-js surfaces a raised exception as
--   error.message, so the route matches on the string.
--
-- OWNERSHIP UNDER SECURITY DEFINER
--   security definer means this runs as the function owner and RLS does not
--   apply to it, exactly as it does not for the service-role key the
--   application already uses. The only thing scoping this call to one user is
--   `and user_id = p_user_id`, present in BOTH the select and the update. The
--   route must pass the authenticated user's own id and never a value from a
--   request body; with a caller-supplied p_user_id this function will convert
--   anyone's prospect.
--
-- FIELDS THAT DO NOT FIT, FOLDED RATHER THAN DROPPED
--   crm_customers has no column for title, website, social_handle or
--   qualification_notes. The alternative to folding them into notes is losing
--   four fields silently at the moment a prospect becomes a customer, which is
--   the one moment a user is least likely to check. concat_ws skips nulls
--   rather than leaving blank lines, each case guards on nullif(x, '') so an
--   empty string is treated as absent, and the outer nullif(..., '') leaves
--   notes null rather than empty when a prospect carried none of them.
--
--   Labelling them ("Title: ", "Website: ") is deliberate: once folded they are
--   prose, and unlabelled prose cannot be read back apart. This is lossy on
--   purpose and recorded as such — if these fields need to survive as fields,
--   they need columns on crm_customers, not a better join here.
--
-- THE NEW CUSTOMER STARTS AT 'lead'
--   Not 'prospect'. The prospect lifecycle ends here; the customer lifecycle
--   starts at its own beginning, and crm_customers.status is the customer
--   lifecycle. Carrying 'prospect' across would put a row in the CRM that is
--   still described by the table it just left.
--
-- DEPENDENCIES
--   public.prospects and public.crm_customers must both exist — 087 and 086
--   respectively, which is why this is 088. The %rowtype declaration binds to
--   prospects' shape at call time, so a column added to prospects later needs
--   no change here unless it should be carried across.
-- ============================================================================

create or replace function public.convert_prospect_to_customer(
  p_prospect_id uuid,
  p_user_id uuid
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_prospect public.prospects%rowtype;
  v_customer_id uuid;
begin
  select * into v_prospect
  from public.prospects
  where id = p_prospect_id and user_id = p_user_id
  for update;

  if not found then
    raise exception 'prospect_not_found';
  end if;

  if v_prospect.converted_customer_id is not null then
    raise exception 'already_converted';
  end if;

  insert into public.crm_customers (
    user_id, name, company, email, phone, status, source, notes,
    last_contacted_at, created_at, updated_at
  )
  values (
    p_user_id,
    v_prospect.name,
    v_prospect.company,
    v_prospect.email,
    v_prospect.phone,
    'lead',
    v_prospect.source,
    nullif(concat_ws(
      E'\n',
      nullif(v_prospect.notes, ''),
      case when nullif(v_prospect.title, '') is not null
           then 'Title: ' || v_prospect.title end,
      case when nullif(v_prospect.website, '') is not null
           then 'Website: ' || v_prospect.website end,
      case when nullif(v_prospect.social_handle, '') is not null
           then 'Social: ' || v_prospect.social_handle end,
      case when nullif(v_prospect.qualification_notes, '') is not null
           then 'Qualification: ' || v_prospect.qualification_notes end
    ), ''),
    v_prospect.last_contacted_at,
    now(),
    now()
  )
  returning id into v_customer_id;

  update public.prospects
  set converted_customer_id = v_customer_id,
      status = 'converted',
      converted_at = now(),
      updated_at = now()
  where id = p_prospect_id and user_id = p_user_id;

  return v_customer_id;
end;
$$;
