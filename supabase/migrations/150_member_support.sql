-- 150_member_support.sql — members support each other: BizCash support, and
-- a support page with external donation links where BizForce handles no money.
--
-- WHY. Diagnostic §4 (a) and (b). A member can already send BizCash to another
-- member (bfc_send, migrations 139, 145, 148). Support is that same transfer,
-- marked as support and carrying an optional private note, so the two members'
-- trade records can say "support given" and "support received". And a member
-- can list up to five links to their own PayPal.Me, Cash App, Venmo, Ko-fi,
-- Buy Me a Coffee, Patreon or Stripe payment page, shown on a public support
-- page; those payments go straight to the provider and never through BizForce.
--
-- 1. bfc_transfers gains kind ('transfer' or 'support') and note. Every
--    existing row becomes 'transfer' through the column default. A note is
--    allowed only on support, and is stored HTML-escaped by the server
--    (lib/supportLinks.js noteForStorage: at most 140 characters before
--    escaping, so at most 840 after).
-- 2. bfc_send takes p_kind and p_note, both defaulted, so every existing call
--    (POST /api/wallet/transfer's six named arguments) means exactly what it
--    did. The old six-argument function is DROPPED first: with both present a
--    six-argument call would be ambiguous. Every limit is unchanged and is
--    checked in the same order under the same wallet row lock; support debits
--    are described 'Transfer' in the ledger exactly as a transfer is, so they
--    count in the one 24-hour total shared by transfers and donations. The
--    body is migration 148's, word for word, but for the kind check and the
--    insert naming kind and note.
-- 3. member_support: one row per member, the support page's settings. links
--    holds [{ provider, handle }] only; the URL is rebuilt from those two by
--    the server every time it is shown, never stored. page_on is null until
--    the member chooses (the page is then on exactly when they have a link),
--    true or false after. discoverable (listed in the sitemap) is off by
--    default.

-- ── 1 ───────────────────────────────────────────────────────────────────────
ALTER TABLE public.bfc_transfers ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'transfer';
ALTER TABLE public.bfc_transfers ADD COLUMN IF NOT EXISTS note text;

ALTER TABLE public.bfc_transfers DROP CONSTRAINT IF EXISTS bfc_transfers_kind_check;
ALTER TABLE public.bfc_transfers ADD CONSTRAINT bfc_transfers_kind_check CHECK (kind IN ('transfer', 'support'));
ALTER TABLE public.bfc_transfers DROP CONSTRAINT IF EXISTS bfc_transfers_note_check;
ALTER TABLE public.bfc_transfers ADD CONSTRAINT bfc_transfers_note_check
  CHECK (note IS NULL OR (kind = 'support' AND char_length(note) BETWEEN 1 AND 840));

-- ── 2 ───────────────────────────────────────────────────────────────────────
DROP FUNCTION IF EXISTS public.bfc_send(uuid, uuid, integer, integer, integer, integer);

CREATE OR REPLACE FUNCTION public.bfc_send(p_from uuid, p_to uuid, p_amount integer, p_max_per_transfer integer, p_daily_cap integer, p_hold_days integer, p_kind text DEFAULT 'transfer', p_note text DEFAULT NULL)
 RETURNS integer
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
declare
v_created timestamptz;
v_sent integer;
v_balance integer;
begin
if p_max_per_transfer is null or p_max_per_transfer < 1
   or p_daily_cap is null or p_daily_cap < 1
   or p_hold_days is null or p_hold_days < 0 then
raise exception 'limits_invalid: every transfer limit must be given (max %, daily cap %, hold days %)', p_max_per_transfer, p_daily_cap, p_hold_days;
end if;
if p_kind is null or p_kind not in ('transfer', 'support') or (p_note is not null and p_kind <> 'support') then
raise exception 'invalid_kind: a transfer is a transfer or support, and only support carries a note';
end if;
if p_from = p_to then
raise exception 'cannot transfer to self';
end if;
if p_amount is null or p_amount <= 0 then
raise exception 'amount must be positive';
end if;
if p_amount > p_max_per_transfer then
raise exception 'over_per_transfer_max: % BFC is more than the % BFC one transfer may move', p_amount, p_max_per_transfer;
end if;
if not exists (select 1 from users where id = p_to) then
raise exception 'unknown_recipient: no account has the id %', p_to;
end if;

select created_at into v_created from users where id = p_from;
if v_created is null then
raise exception 'unknown_sender: no account has the id %', p_from;
end if;
if v_created > now() - make_interval(days => p_hold_days) then
raise exception 'new_account_hold: an account can send BFC % days after it was opened; this one can from %', p_hold_days, v_created + make_interval(days => p_hold_days);
end if;

perform 1 from user_wallets where user_id = p_from for update;

select coalesce(sum(amount), 0) into v_sent
from wallet_transactions
where user_id = p_from
  and type = 'debit'
  and (description = 'Transfer' or description like 'Donation: %')
  and created_at > now() - interval '24 hours';

if v_sent + p_amount > p_daily_cap then
raise exception 'over_daily_cap: % BFC sent in the last 24 hours, transfers and donations together, and % more would pass the % BFC cap', v_sent, p_amount, p_daily_cap;
end if;

v_balance := bfc_transfer(p_from, p_to, p_amount, 'Transfer');

insert into bfc_transfers (sender_id, recipient_id, amount_bfc, kind, note)
values (p_from, p_to, p_amount, p_kind, p_note);

return v_balance;
end;
$function$;

revoke execute on function public.bfc_send(uuid, uuid, integer, integer, integer, integer, text, text) from public, anon, authenticated;
grant  execute on function public.bfc_send(uuid, uuid, integer, integer, integer, integer, text, text) to service_role;

COMMENT ON FUNCTION public.bfc_send(uuid, uuid, integer, integer, integer, integer, text, text) IS
  'Member-to-member BFC transfer behind POST /api/wallet/transfer and POST /api/wallet/support. Refuses an unknown recipient, an amount over p_max_per_transfer, a sender whose users.created_at is within p_hold_days, and a send that would take the sender''s ''Transfer'' and ''Donation: '' debits together over p_daily_cap in the last 24 hours (read under the sender''s wallet row lock), then calls bfc_transfer with description ''Transfer'' and records the transfer, with both parties, its kind (''transfer'' or ''support'') and a support note, in bfc_transfers. Migrations 139, 145, 148 and 150. EXECUTE is service_role only.';

-- ── 3 ───────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.member_support (
  user_id      uuid        PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE,
  links        jsonb       NOT NULL DEFAULT '[]'::jsonb,
  headline     text,
  page_on      boolean,
  discoverable boolean     NOT NULL DEFAULT false,
  updated_at   timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT member_support_links_check CHECK (jsonb_typeof(links) = 'array' AND jsonb_array_length(links) <= 5),
  CONSTRAINT member_support_headline_check CHECK (headline IS NULL OR char_length(headline) BETWEEN 1 AND 120)
);

alter table public.member_support enable row level security;
-- No policy: only the server's service key reads and writes it.
