/* ═════════════════════════════════════════════════════════════════════════════
   scripts/oneoff/lr3Backfill.js — LR-3 (Nov 24 2026): Inbound items for the last 90 days.
     node scripts/oneoff/lr3Backfill.js            dry run: reads only, writes nothing, prints counts only
     node scripts/oneoff/lr3Backfill.js --apply    writes the items (needs migration 205)

   WHAT IT READS (each from the last BACKFILL_DAYS days, through lib/inbound.js's own plans, so an item is exactly what
   the live action would have written):
     messages            the first message of each conversation (the earliest in the window, and only when the two had
                         not messaged before it), and every message that links the receiver's own Need (i_can_help)
     card_leads          each lead, for the card's owner
     marketplace_orders  each order, for its seller (won)
     campaign_donations  each donation, for the campaign's owner (won)
     bfc_transfers       each support tip (kind support), for the member it went to (won)
   Replies on Bluesky are not backfilled: the Mentions inbox was never stored.

   SAFE TO RUN AGAIN. inbound_items' unique key (user_id, kind, source_id) and its one-per-conversation index refuse a
   second copy, and the dry run counts what is already there. Nothing else is written: no notice, no push, no message.
   It prints counts only, never a name, an address or a message.
   ═════════════════════════════════════════════════════════════════════════════ */
"use strict";
const path = require("path");
const IB = require("../../lib/inbound");

const BACKFILL_DAYS = 90;
const PAGE = 1000;
const DAY = 86400000;

/* Every row of a table since `sinceIso`, oldest first, a page at a time. */
async function readSince(sb, table, cols, sinceIso, extra) {
  const out = [];
  for (let from = 0; ; from += PAGE) {
    let q = sb.from(table).select(cols).gt("created_at", sinceIso);
    if (typeof extra === "function") q = extra(q);
    const r = await q.order("created_at", { ascending: true }).range(from, from + PAGE - 1);
    if (r.error) throw r.error;
    out.push.apply(out, r.data || []);
    if ((r.data || []).length < PAGE) break;
  }
  return out;
}

/* The items already there, by "user|kind|source" and by "user|other" for a conversation. null when the table is missing. */
async function existing(sb, userIds) {
  const keys = new Set(), conv = new Set();
  const ids = Array.from(new Set(userIds));
  // the table itself, asked once with a GET (a HEAD request on a missing table answers no error)
  const probe = await sb.from(IB.TABLE).select("id").limit(1);
  if (probe.error) {
    if (probe.error.code === "42P01" || probe.error.code === "PGRST205" || /inbound_items/.test(String(probe.error.message || ""))) return null;
    throw probe.error;
  }
  for (let i = 0; i < ids.length; i += 200) {
    const r = await sb.from(IB.TABLE).select("user_id, kind, source_id, counterpart_user_id").in("user_id", ids.slice(i, i + 200)).limit(100000);
    if (r.error) {
      if (r.error.code === "42P01" || r.error.code === "PGRST205" || /inbound_items/.test(String(r.error.message || ""))) return null;
      throw r.error;
    }
    (r.data || []).forEach(function (x) {
      keys.add(x.user_id + "|" + x.kind + "|" + x.source_id);
      if (IB.CONVERSATION_KINDS.indexOf(x.kind) !== -1 && x.counterpart_user_id) conv.add(x.user_id + "|" + x.counterpart_user_id);
    });
  }
  return { keys: keys, conv: conv };
}

/* opts: { apply, nowMs, categoryName(slug) }. Returns { since, table_missing, kinds: { kind: { found, would_create | created, already, skipped, errors } } } */
async function run(sb, opts) {
  const o = opts || {};
  const nowMs = typeof o.nowMs === "number" ? o.nowMs : Date.now();
  const since = new Date(nowMs - BACKFILL_DAYS * DAY).toISOString();
  const kinds = {};
  IB.KINDS.filter(function (k) { return k !== "lead_reply"; }).forEach(function (k) { kinds[k] = { found: 0, planned: 0, already: 0, skipped: 0, created: 0, errors: 0 }; });
  const plans = [];   // { row }
  function plan(kind, row) {
    kinds[kind].found++;
    if (!row) { kinds[kind].skipped++; return; }
    plans.push(row);
  }

  // messages: the earliest in the window of each pair, and every message linking a Need
  const messages = await readSince(sb, "messages", "id, sender_id, receiver_id, content, created_at", since);
  const seenPair = new Set();
  for (const m of messages) {
    const pairKey = [m.sender_id, m.receiver_id].sort().join("|");
    const first = !seenPair.has(pairKey);
    seenPair.add(pairKey);
    if (!first && !IB.needLinkIn(m.content)) continue;
    const p = await IB.planMessage(sb, m, { categoryName: o.categoryName });
    if (p.row) plan(p.row.kind, p.row);
    else if (p.reason !== "not_first") { kinds.message.found++; kinds.message.skipped++; }
  }

  const leads = await readSince(sb, "card_leads", "id, user_id, name, email, phone, message, created_at", since);
  leads.forEach(function (l) { plan("card_lead", IB.planCardLead(l)); });

  const orders = await readSince(sb, "marketplace_orders", "id, buyer_id, seller_id, listing_title, amount_bfc, created_at", since);
  orders.forEach(function (x) { plan("sale", IB.planOrder(x)); });

  const donations = await readSince(sb, "campaign_donations", "id, campaign_id, donor_id, owner_id, amount_bfc, created_at", since);
  const campaignIds = Array.from(new Set(donations.map(function (d) { return d.campaign_id; }).filter(IB.isUuid)));
  const titles = {};
  for (let i = 0; i < campaignIds.length; i += 200) {
    const r = await sb.from("crowdfunding_campaigns").select("id, title").in("id", campaignIds.slice(i, i + 200));
    if (r.error) throw r.error;
    (r.data || []).forEach(function (c) { titles[c.id] = c.title; });
  }
  donations.forEach(function (d) { plan("campaign", IB.planDonation(d, titles[d.campaign_id])); });

  const tips = await readSince(sb, "bfc_transfers", "id, sender_id, recipient_id, amount_bfc, note, kind, created_at", since, function (q) { return q.eq("kind", "support"); });
  const senderIds = Array.from(new Set(tips.map(function (t) { return t.sender_id; }).filter(IB.isUuid)));
  const handles = {};
  for (let i = 0; i < senderIds.length; i += 200) {
    const r = await sb.from("bf_profiles").select("user_id, username").in("user_id", senderIds.slice(i, i + 200));
    if (r.error) throw r.error;
    (r.data || []).forEach(function (p) { if (p.username) handles[p.user_id] = "@" + p.username; });
  }
  for (const t of tips) plan("tip", IB.planTip(t, handles[t.sender_id] || IB.shortName(await IB.nameOf(sb, t.sender_id))));

  // what is already there, then each plan once (a conversation once)
  const have = await existing(sb, plans.map(function (r) { return r.user_id; }));
  const convPlanned = new Set();
  for (const row of plans) {
    const k = kinds[row.kind];
    const convKey = row.user_id + "|" + row.counterpart_user_id;
    const isConv = IB.CONVERSATION_KINDS.indexOf(row.kind) !== -1 && row.counterpart_user_id;
    if (have && (have.keys.has(row.user_id + "|" + row.kind + "|" + row.source_id) || (isConv && have.conv.has(convKey)))) { k.already++; continue; }
    if (isConv && convPlanned.has(convKey)) { k.already++; continue; }
    if (isConv) convPlanned.add(convKey);
    k.planned++;
    if (o.apply) {
      const w = await IB.record(sb, row);
      if (w.created) k.created++; else if (w.reason === "exists") { k.planned--; k.already++; } else k.errors++;
    }
  }
  return { since: since, table_missing: have === null, kinds: kinds };
}

module.exports = { run, BACKFILL_DAYS };

if (require.main === module) {
  process.chdir(path.join(__dirname, "..", ".."));
  require("dotenv").config();
  const { createClient } = require("@supabase/supabase-js");
  const APPLY = process.argv.indexOf("--apply") !== -1;
  const sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
  const CAT = require("../../lib/categories");
  run(sb, { apply: APPLY, categoryName: async function (slug) { const c = await CAT.find(sb, slug); return c ? c.name : null; } }).then(function (r) {
    console.log((APPLY ? "APPLY " : "DRY RUN ") + new Date().toISOString() + ", the last " + BACKFILL_DAYS + " days (since " + r.since + ")");
    if (r.table_missing) console.log("inbound_items does not exist yet (migration 205 not applied): nothing can be already there.");
    Object.keys(r.kinds).forEach(function (k) {
      const c = r.kinds[k];
      console.log("  " + k + ": found " + c.found + ", " + (APPLY ? "created " + c.created : "would create " + c.planned) + ", already there " + c.already +
        ", skipped (own action or bad row) " + c.skipped + (APPLY ? ", errors " + c.errors : ""));
    });
    const total = Object.keys(r.kinds).reduce(function (n, k) { return n + (APPLY ? r.kinds[k].created : r.kinds[k].planned); }, 0);
    console.log((APPLY ? "CREATED: " : "WOULD CREATE: ") + total);
    if (!APPLY) console.log("Nothing was written (dry run).");
  }).catch(function (e) { console.error("FAILED: " + ((e && (e.code || e.message)) || e)); process.exitCode = 1; });
}
