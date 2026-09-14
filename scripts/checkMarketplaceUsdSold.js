/* ══════════════════════════════════════════════════════════════════════════
   checkMarketplaceUsdSold.js — a paid USD listing must end up sold, and a
   redelivery of the same payment must change nothing.

   THE TWO DEFECTS. The webhook's marketplace_usd branch recorded the order and
   delivered the file but never touched marketplace_listings, so a USD listing
   stayed 'active' after being bought and could be bought again — while the BFC
   path, through bfc_buy_listing, flips it to 'sold' inside the same locked
   transaction that moves the money. And the branch's idempotency was a
   read-then-insert with no lock, so two deliveries of one Stripe event could
   both pass.

   HOW THIS DRIVES IT. The webhook cannot be reached over HTTP without forging
   a Stripe signature, so the check hands the real handleStripeEvent a
   real-shaped checkout.session.completed event. The handler is the thing under
   test; a re-implementation of it would proves nothing about it.

   ── WHOSE DATA THIS TOUCHES ───────────────────────────────────────────────

   Its own, and only its own. Every fixture — the listing, the order, the
   storage object — is created by this script under the subject account that
   BIZFORCE_CHECK_USER_ID names, and removed again in a finally block that
   verifies the removal. The owner's listings are read for context and never
   written.

   THE RESIDUE GUARD IS INSTALLED BUT DOES NOT OWN THE MARKETPLACE TABLES, and
   that is deliberate rather than an oversight. The guard identifies a row's
   owner by a user_id column; marketplace_listings has seller_id and
   marketplace_orders has buyer_id and seller_id, so isSubjectRow would find no
   user_id, correctly refuse to delete, and leave the fixtures behind. It is
   installed for ai_tasks and model_calls — which nothing here should write, so
   a row appearing in either is itself a finding — and the marketplace fixtures
   are tracked and deleted by explicit id below.

   MUTATE=no-sold-update strips listing_id out of the event metadata, so the
   handler records the payment and has nothing to mark sold — the behaviour
   this commit fixes, reached without editing the code under test. The "listing
   is sold" assertions must go red while the "order was still written"
   assertions stay green, which is the whole point of the ordering: a failed
   status flip must never cost a paid order.

   It deliberately does NOT point the event at a non-existent listing.
   marketplace_orders.listing_id turns out to carry a foreign key to
   marketplace_listings — undocumented, in no migration — so that shape fails
   the ORDER INSERT with 23503 instead, mutating a different thing entirely and
   losing the paid order. See the note in scenario 3.
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const { createResidueGuard, resolveSubjectAccount } = require("./checkRunResidue");
const SUBJECT_USER_ID = resolveSubjectAccount();

const path = require("path");
const REPO = path.join(__dirname, "..");

const EXPRESS_PATH = require.resolve("express", { paths: [REPO] });
const realExpress = require(EXPRESS_PATH);
let app = null;
const expressWrapper = function () {
  const made = realExpress.apply(this, arguments);
  if (!app) app = made;
  return made;
};
Object.keys(realExpress).forEach(function (k) { expressWrapper[k] = realExpress[k]; });
require.cache[EXPRESS_PATH].exports = expressWrapper;

process.env.PORT = process.env.CHECK_PORT || "0";
const server = require(path.join(REPO, "server.js"));

const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY
);

const residue = createResidueGuard({
  supabase: supabase,
  name: "marketplaceUsdSold",
  subject: SUBJECT_USER_ID,
  tables: ["ai_tasks", "model_calls"]
});
residue.install();

const MUTATING = process.env.MUTATE === "no-sold-update";

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

/* Fixtures, tracked for explicit removal. */
const made = { listings: [], orders: [], objects: [] };

const DIGITAL_BUCKET = "bf-digital-goods";
const stamp = Date.now();
const FIXTURE_OBJECT = SUBJECT_USER_ID + "/checkMarketplaceUsdSold_" + stamp + ".txt";

async function removeFixtures() {
  for (const id of made.orders) {
    await supabase.from("marketplace_orders").delete().eq("id", id);
  }
  for (const id of made.listings) {
    await supabase.from("marketplace_listings").delete().eq("id", id);
  }
  for (const obj of made.objects) {
    await supabase.storage.from(DIGITAL_BUCKET).remove([obj]);
  }

  /* THE REPORT IS THE READ-BACK, NOT THE DELETE, the same rule the residue
     guard follows for the tables it does own. */
  const ordersLeft = made.orders.length
    ? (await supabase.from("marketplace_orders").select("id", { count: "exact", head: true }).in("id", made.orders)).count
    : 0;
  const listingsLeft = made.listings.length
    ? (await supabase.from("marketplace_listings").select("id", { count: "exact", head: true }).in("id", made.listings)).count
    : 0;
  const objs = made.objects.length
    ? await supabase.storage.from(DIGITAL_BUCKET).list(SUBJECT_USER_ID, { search: "checkMarketplaceUsdSold_" + stamp })
    : { data: [] };
  const objectsLeft = (objs.data || []).length;

  console.log("    [fixture] marketplace_orders: " + made.orders.length + " written, " + ordersLeft + " still present");
  console.log("    [fixture] marketplace_listings: " + made.listings.length + " written, " + listingsLeft + " still present");
  console.log("    [fixture] storage objects: " + made.objects.length + " written, " + objectsLeft + " still present");
  if (ordersLeft || listingsLeft || objectsLeft) failures++;
}

async function makeListing(fields) {
  const row = Object.assign({
    seller_id: SUBJECT_USER_ID,
    title: "CHECK FIXTURE — marketplace usd sold " + stamp,
    description: "Created by scripts/checkMarketplaceUsdSold.js. Deleted by the same run.",
    price_bfc: 0,
    price_usd: 100,
    category: "other",
    tags: [],
    status: "active",
    media: []
  }, fields || {});
  const r = await supabase.from("marketplace_listings").insert(row).select("id, status").single();
  if (r.error) throw new Error("could not create the fixture listing: " + r.error.message);
  made.listings.push(r.data.id);
  return r.data;
}

/* listingId null builds an event whose metadata carries NO listing_id, which
   is the shape used to prove that a payment whose listing cannot be marked
   sold still records the order. */
function sessionEvent(sessionId, listingId, amountCents) {
  const metadata = {
    kind: "marketplace_usd",
    buyer_id: SUBJECT_USER_ID,
    seller_id: SUBJECT_USER_ID
  };
  if (listingId !== null) metadata.listing_id = String(listingId);

  return {
    id: "evt_check_" + sessionId,
    type: "checkout.session.completed",
    data: {
      object: {
        id: sessionId,
        amount_total: amountCents,
        payment_intent: null,
        metadata: metadata
      }
    }
  };
}

async function listingStatus(id) {
  const r = await supabase.from("marketplace_listings").select("status").eq("id", id).maybeSingle();
  return r.data ? r.data.status : "(gone)";
}

async function ordersForSession(sessionId) {
  const r = await supabase.from("marketplace_orders").select("*").eq("stripe_session_id", sessionId);
  (r.data || []).forEach(function (o) { if (made.orders.indexOf(o.id) === -1) made.orders.push(o.id); });
  return r.data || [];
}

(async function main() {
  await residue.sweepPrevious(SUBJECT_USER_ID);

  console.log("\n══ the owner's listings are read only for context ══");
  const ownerRows = await supabase.from("marketplace_listings")
    .select("id, status", { count: "exact" }).neq("seller_id", SUBJECT_USER_ID);
  const ownerBefore = (ownerRows.data || []).map(function (r) { return r.id + "=" + r.status; }).sort().join(", ");
  console.log("    " + (ownerRows.data || []).length + " listing(s) not belonging to the subject: " + ownerBefore);

  const indexProbe = await supabase.from("marketplace_orders").select("stripe_session_id").limit(1);
  console.log("    migration 112 applied: unknown from here (a unique index is not visible over PostgREST);");
  console.log("    the duplicate-delivery case below is asserted on the OUTCOME — one order — which");
  console.log("    holds whether the index or the handler's own check is what stopped it.");

  try {
    /* ── 1. a paid listing ends up sold ────────────────────────────────── */
    console.log("\n══ 1. a fresh marketplace_usd event ══");

    /* A real object in the private bucket, so delivery is proven rather than
       inferred from a soft-failure log. Removed with the rest. */
    const upload = await supabase.storage.from(DIGITAL_BUCKET)
      .upload(FIXTURE_OBJECT, Buffer.from("check fixture — not a real product\n"), { contentType: "text/plain" });
    if (upload.error) {
      console.log("    (could not upload a fixture object: " + upload.error.message + " — delivery will be asserted as soft-failed)");
    } else {
      made.objects.push(FIXTURE_OBJECT);
      console.log("    [fixture] uploaded a placeholder object to " + DIGITAL_BUCKET);
    }

    const listing = await makeListing({
      is_digital: !upload.error,
      digital_file_path: upload.error ? null : FIXTURE_OBJECT,
      digital_file_name: upload.error ? null : "fixture.txt"
    });
    console.log("    [fixture] listing " + listing.id + " created, status=" + listing.status);
    check("the fixture listing starts active", listing.status === "active", listing.status);

    const sessionId = "cs_check_" + stamp;
    /* MUTATION: the event carries no listing_id, so the handler records the
       payment and cannot mark anything sold — the pre-fix behaviour, reached
       without editing the code under test. It deliberately does NOT point at a
       non-existent listing: marketplace_orders.listing_id has a foreign key to
       marketplace_listings, so that would fail the ORDER INSERT instead and
       would be mutating the wrong thing. */
    const targetListing = MUTATING ? null : listing.id;
    if (MUTATING) {
      console.log("\n    !! MUTATION: the event carries no listing_id, so no listing can be marked");
      console.log("       sold. The 'sold' assertions must go red and the 'order still written'");
      console.log("       assertions must stay green — a failed status flip must never cost a");
      console.log("       paid order.\n");
    }

    await server.__handleStripeEvent(sessionEvent(sessionId, targetListing, 100));

    const afterOne = await listingStatus(listing.id);
    console.log("    listing status after the event: " + afterOne);
    check("the listing is marked sold", afterOne === "sold", afterOne);

    const orders1 = await ordersForSession(sessionId);
    check("exactly one order was written", orders1.length === 1, "orders: " + orders1.length);
    if (orders1.length) {
      const o = orders1[0];
      console.log("    order: " + JSON.stringify({
        status: o.status, payment_method: o.payment_method, amount_usd: o.amount_usd,
        is_digital: o.is_digital, delivered: !!o.delivered_at, download_url: o.download_url ? "set" : null
      }));
      check("the order is completed and marked usd", o.status === "completed" && o.payment_method === "usd",
        o.status + "/" + o.payment_method);
      check("the order records the amount paid", o.amount_usd === 100, String(o.amount_usd));
      if (!upload.error && !MUTATING) {
        check("the digital good was delivered", !!o.download_url && !!o.delivered_at,
          "download_url=" + (o.download_url ? "set" : "null") + " delivered_at=" + o.delivered_at);
      }
    }

    /* ── 2. a redelivery of the same session changes nothing ───────────── */
    console.log("\n══ 2. the same session delivered again ══");
    const statusBeforeReplay = await listingStatus(listing.id);
    await server.__handleStripeEvent(sessionEvent(sessionId, targetListing, 100));

    const orders2 = await ordersForSession(sessionId);
    check("still exactly one order for that session", orders2.length === 1, "orders: " + orders2.length);
    check("the listing status is unchanged by the redelivery",
      (await listingStatus(listing.id)) === statusBeforeReplay, statusBeforeReplay);

    /* ── 3. a failed status update still writes the order ──────────────── */
    console.log("\n══ 3. a payment whose listing cannot be marked sold ══");
    console.log("    The event carries no listing_id, so the handler records the payment and has");
    console.log("    nothing to mark sold. The paid order must still be written.");
    console.log("");
    console.log("    NOT tested as a missing listing id, and that is a finding rather than a");
    console.log("    convenience: marketplace_orders.listing_id has a foreign key to");
    console.log("    marketplace_listings — undocumented, in no migration — so an event naming a");
    console.log("    deleted listing fails at the ORDER INSERT with 23503 and the paid order is");
    console.log("    lost outright. That is a separate defect from the one under test here.");

    const orphanSession = "cs_check_orphan_" + stamp;
    await server.__handleStripeEvent(sessionEvent(orphanSession, null, 250));

    const orphanOrders = await ordersForSession(orphanSession);
    check("the paid order was still written", orphanOrders.length === 1, "orders: " + orphanOrders.length);
    if (orphanOrders.length) {
      check("and it is completed, not left pending", orphanOrders[0].status === "completed", orphanOrders[0].status);
      check("and it records the amount paid", orphanOrders[0].amount_usd === 250, String(orphanOrders[0].amount_usd));
    }
    console.log("    (the handler logged the listing it could not mark sold — see [marketplace-usd] above)");

    /* ── 4. nothing of the owner's moved ───────────────────────────────── */
    console.log("\n══ 4. nothing outside the subject's own rows changed ══");
    const ownerAfterRows = await supabase.from("marketplace_listings")
      .select("id, status").neq("seller_id", SUBJECT_USER_ID);
    const ownerAfter = (ownerAfterRows.data || []).map(function (r) { return r.id + "=" + r.status; }).sort().join(", ");
    check("every listing not belonging to the subject is untouched", ownerAfter === ownerBefore,
      "before: " + ownerBefore + "  after: " + ownerAfter);
  } finally {
    console.log("\n══ cleanup ══");
    await removeFixtures();
    const cleanupResult = await residue.cleanup("end of run");
    if (cleanupResult.leftovers.length) failures++;
  }

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
})().catch(async function (err) {
  console.error("\nThe check threw: " + ((err && err.stack) || err));
  try { await removeFixtures(); } catch (e) { /* the guard still runs on the way out */ }
  process.exit(1);
});
