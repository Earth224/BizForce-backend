-- ============================================================================
-- 096_increment_card_view.sql
--
-- increment_card_view — the only writer of digital_cards.views.
--
-- ── WHAT WAS WRONG ─────────────────────────────────────────────────────────
--   digital_cards.views and digital_cards.taps had never been incremented by
--   anything. Not one UPDATE anywhere touched either column, so all 61 cards
--   held 0 and would have held 0 for as long as the platform ran. Both columns
--   are live-only — 007 declares neither, and neither appears in 011, 012 or
--   013 — so they were added to the table directly and then never wired up.
--
-- ── WHERE THE COUNT RUNS ───────────────────────────────────────────────────
--   GET /api/cards/share/:token, at server.js:19823. That is the only
--   unauthenticated per-visitor route this table has: the owner mints a token
--   through POST /api/cards/share-token, the page builds
--   bizforceai.net/card-view.html?token=..., and every open of that link —
--   including every QR scan, which encodes the same URL — fetches this route
--   exactly once.
--
--   The route carries no auth middleware. That is deliberate and is the whole
--   point of a shareable card, and it is also what makes this the right place
--   to count: the owner's own view of their card goes through
--   GET /api/digital-cards, which is requireAuth and is a different endpoint.
--   A counter on that route would have counted the owner reading their own
--   list, which is worse than counting nothing.
--
-- ── WHY AN RPC AND NOT AN UPDATE FROM THE ROUTE ────────────────────────────
--   Because the obvious version is lossy, and silently so.
--
--   supabase-js cannot express `views = views + 1`. Through PostgREST an
--   update takes a literal, so the application-code version is necessarily
--   select-then-update:
--
--     const { data } = await supabase.from("digital_cards")
--       .select("views").eq("share_token", t).single();
--     await supabase.from("digital_cards")
--       .update({ views: data.views + 1 }).eq("share_token", t);
--
--   Two visitors opening the same card in the same moment both read 7 and both
--   write 8. One view is gone, no error is raised, and it is lost precisely
--   when a card is being shared hardest — which is the only time the number is
--   interesting.
--
--   The UPDATE below reads and writes inside one statement. Postgres holds a
--   row lock for its duration, so a second concurrent execution blocks, then
--   re-reads the committed value and adds to it. Two opens produce two
--   increments at any concurrency. That guarantee is why this file exists
--   rather than four lines in the route.
--
-- ── IT FIRES AFTER THE RESPONSE ────────────────────────────────────────────
--   The route calls res.json({ card }) first and then invokes this function
--   without awaiting it, so a visitor never waits on a counter and a failure
--   here cannot reach them. The rejection handler logs and stops: the response
--   is already sent, there is no status left to change and no caller left to
--   tell. A card that renders with an uncounted view is a working card; a card
--   that 500s to protect a counter is not.
--
-- ── THERE IS NO is_active GUARD, BECAUSE THERE IS NO is_active ─────────────
--   Recorded because it is the obvious thing to look for and its absence is
--   easy to mistake for an oversight. digital_cards has no is_active, no
--   status and no enabled column in 007, 011, 012 or 013 — the table has no
--   concept of a disabled card at all. A card is reachable exactly while its
--   share_token is set, and the route already answers 404 when no row matches,
--   in which case this function is never called. Nothing can accrue views from
--   a request that returned 404.
--
--   If a disabled state is ever added, this function is where the guard
--   belongs — a WHERE clause here, not a check in the route, so it cannot be
--   forgotten by a second caller.
--
-- ── WHAT IT COUNTS, AND WHAT IT CANNOT ─────────────────────────────────────
--   It counts FETCHES OF THE SHARE LINK, which is not the same as people.
--   The route has no identity of any kind, so the count includes:
--
--     - THE OWNER OPENING THEIR OWN LINK, indistinguishable from anyone else.
--       This is the known limitation and it is not worked around: telling the
--       owner apart would mean identifying the visitor, and a route whose
--       entire purpose is that it identifies nobody cannot be given identity
--       without defeating itself.
--     - link-preview fetches from Slack, iMessage, WhatsApp and anything else
--       that unfurls a URL — one per platform, before a human looks.
--     - crawlers and anything else that follows a link.
--
--   The number means "this link was fetched N times". Anything read into it
--   beyond that is the reader's assumption, not the column's claim, which is
--   why the column comment below says so where the data lives.
--
-- ── THE REVOKE SHIPS WITH THE CREATE ───────────────────────────────────────
--   090 had to repair six SECURITY DEFINER functions that inherited the
--   PUBLIC execute default and were callable by anon, and it set the standing
--   rule that a function's revoke ships in the same migration that creates it.
--   This is the second application of that rule after 092.
--
--   This function does not need SECURITY DEFINER and does not use it: server.js
--   connects with SUPABASE_SERVICE_KEY and the service role already bypasses
--   RLS, so invoker rights are enough. Making it definer would grant powers it
--   never exercises and recreate the exact exposure 090 closed. The grant is
--   narrowed anyway, to the one role that calls it.
--
-- ── taps REMAINS UNCOUNTED ─────────────────────────────────────────────────
--   taps sits beside views and looks like its pair. It is not, and no part of
--   this migration touches it.
--
--   A view is a request, and a request is something a route can observe. A tap
--   is a click on a link INSIDE the rendered card — the website, the phone
--   number, the email — and card-view.html renders those as ordinary anchors
--   that report nothing back. No route sees a tap, so there is nothing to
--   count.
--
--   Counting one means adding a redirect endpoint the links point through, or
--   a beacon the page fires. Either is a new public write surface accepting
--   input from an unauthenticated visitor, which is a larger decision than
--   this one and belongs in its own migration.
-- ============================================================================


create or replace function public.increment_card_view(p_share_token text)
returns void
language sql
as $$
  -- coalesce because views is live-only and 007 never declared it: a row
  -- predating the column's addition can hold null, and null + 1 is null, which
  -- would silently stop that card counting forever after one open.
  update public.digital_cards
  set views = coalesce(views, 0) + 1
  where share_token = p_share_token;
$$;


-- ── Execute grant ──────────────────────────────────────────────────────────
-- Per 090's standing rule, in this file rather than a later repair. anon has
-- no reason to call this directly — it reaches the counter by fetching the
-- card, not by invoking the function — and the only caller runs as the service
-- role, so the grant is the same size as its one consumer.
revoke execute on function public.increment_card_view(text) from public;
revoke execute on function public.increment_card_view(text) from anon;
grant  execute on function public.increment_card_view(text) to service_role;


comment on function public.increment_card_view(text) is
  'The only writer of digital_cards.views. Called by GET /api/cards/share/:token after res.json has already sent the card, and never awaited. Atomic by construction — the read and the write are one UPDATE under a row lock — because the select-then-update a PostgREST client is forced into drops a count when two visitors open the same card at once. Counts fetches of the share link, not unique people: the route is unauthenticated and cannot tell the owner from a stranger or a human from a link-preview bot.';

comment on column public.digital_cards.views is
  'Fetches of the public share link, incremented only by increment_card_view. NOT unique visitors: the route that counts them has no identity, so this includes the owner opening their own link and one fetch per platform that unfurls the URL in a chat. Read it as "this link was fetched N times".';

comment on column public.digital_cards.taps is
  'Never incremented by anything. A tap is a click on a link inside the rendered card, and no route observes one — card-view.html renders those links as ordinary anchors that report nothing back. Counting taps requires a redirect endpoint or a beacon, which is a new public write surface and a separate decision; see the header of 096.';
