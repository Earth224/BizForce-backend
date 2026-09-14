/* ══════════════════════════════════════════════════════════════════════════
   checkMarketplaceOrderSnapshot.js — a paid order must survive its listing.

   THE DEFECT. marketplace_orders.listing_id carries a foreign key to
   marketplace_listings. A listing deleted between checkout and payment made the
   order INSERT fail with 23503: the customer was charged, no order row was
   written, and one log line naming only the listing id was the entire trace.

   WHAT THIS PROVES, AND WHAT IT HONESTLY CANNOT

     1. A normal purchase snapshots the file path onto the order.
     2. A listing deleted AFTER the order still serves its download — from the
        order's own snapshot rather than the join. This is the case the
        snapshot actually rescues.
     3. A listing deleted BEFORE payment lands the order with listing_id NULL
        and the payment recorded. The SNAPSHOT IS EMPTY in this case and this
        script asserts that it is empty rather than pretending otherwise: the
        webhook reads the listing to build the snapshot, and by then there is
        nothing to read. The money is recorded and refundable; the purchase is
        not fulfillable. Closing that gap needs the listing captured at CHECKOUT
        time, into the Stripe session, which is a different change.
     4. An order with no snapshot at all — every order written before migration
        113 — still downloads through the join.

   MIGRATION 113 MAY NOT BE APPLIED. The script detects it and says so. Without
   it the snapshot columns do not exist, and what is proven instead is the
   fallback: the order still lands, without a snapshot, rather than the whole
   insert being refused.

   MUTATE=no-snapshot blanks the snapshot on the order after it is written, so
   the purchase has to fall back to the listing — which scenario 2 then deletes.
   Both post-deletion assertions must go red with HTTP 404, which is precisely
   the buyer this change exists to protect, put back the way they were.

   Fixtures are created under the subject account and removed with a verified
   read-back. The owner's rows are read for contrast and never written.
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
  name: "marketplaceOrderSnapshot",
  subject: SUBJECT_USER_ID,
  tables: ["ai_tasks", "model_calls"]
});
residue.install();

const MUTATING = process.env.MUTATE === "no-snapshot";

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

const DIGITAL_BUCKET = "bf-digital-goods";
const stamp = Date.now();
const made = { listings: [], orders: [], objects: [] };

async function removeFixtures() {
  for (const id of made.orders) await supabase.from("marketplace_orders").delete().eq("id", id);
  for (const id of made.listings) await supabase.from("marketplace_listings").delete().eq("id", id);
  for (const o of made.objects) await supabase.storage.from(DIGITAL_BUCKET).remove([o]);

  const ordersLeft = made.orders.length
    ? (await supabase.from("marketplace_orders").select("id", { count: "exact", head: true }).in("id", made.orders)).count : 0;
  const listingsLeft = made.listings.length
    ? (await supabase.from("marketplace_listings").select("id", { count: "exact", head: true }).in("id", made.listings)).count : 0;
  const objs = made.objects.length
    ? await supabase.storage.from(DIGITAL_BUCKET).list(SUBJECT_USER_ID, { search: "snapshotcheck_" + stamp }) : { data: [] };

  console.log("    [fixture] marketplace_orders: " + made.orders.length + " written, " + ordersLeft + " still present");
  console.log("    [fixture] marketplace_listings: " + made.listings.length + " written, " + listingsLeft + " still present");
  console.log("    [fixture] storage objects: " + made.objects.length + " written, " + (objs.data || []).length + " still present");
  if (ordersLeft || listingsLeft || (objs.data || []).length) failures++;
}

async function makeObject(tag) {
  const key = SUBJECT_USER_ID + "/snapshotcheck_" + stamp + "_" + tag + ".txt";
  const up = await supabase.storage.from(DIGITAL_BUCKET)
    .upload(key, Buffer.from("fixture " + tag + "\n"), { contentType: "text/plain" });
  if (up.error) throw new Error("could not upload the fixture object: " + up.error.message);
  made.objects.push(key);
  return key;
}

async function makeListing(objectKey, tag) {
  const r = await supabase.from("marketplace_listings").insert({
    seller_id: SUBJECT_USER_ID,
    title: "CHECK FIXTURE — snapshot " + tag + " " + stamp,
    description: "scripts/checkMarketplaceOrderSnapshot.js. Removed by the same run.",
    price_bfc: 0, price_usd: 100, category: "other", tags: [], status: "active", media: [],
    is_digital: true, digital_file_path: objectKey, digital_file_name: "fixture_" + tag + ".txt"
  }).select("id").single();
  if (r.error) throw new Error("could not create the fixture listing: " + r.error.message);
  made.listings.push(r.data.id);
  return r.data.id;
}

function sessionEvent(sessionId, listingId, cents) {
  const metadata = { kind: "marketplace_usd", buyer_id: SUBJECT_USER_ID, seller_id: SUBJECT_USER_ID };
  if (listingId !== null) metadata.listing_id = String(listingId);
  return {
    id: "evt_" + sessionId,
    type: "checkout.session.completed",
    data: { object: { id: sessionId, amount_total: cents, payment_intent: null, metadata: metadata } }
  };
}

async function orderFor(sessionId) {
  const r = await supabase.from("marketplace_orders").select("*").eq("stripe_session_id", sessionId);
  (r.data || []).forEach(function (o) { if (made.orders.indexOf(o.id) === -1) made.orders.push(o.id); });
  return (r.data || [])[0] || null;
}

/* The download route, invoked as itself with the user requireAuth would have
   attached. Nothing else in this file can answer "would the buyer get it". */
function callDownload(orderId) {
  const layer = app._router.stack.filter(function (l) {
    return l.route && l.route.path === "/api/purchases/:orderId/download" && l.route.methods.get;
  })[0];
  const stack = layer.route.stack;
  const handler = stack[stack.length - 1].handle;
  return new Promise(function (resolve) {
    let done = false;
    const fin = function (r) { if (!done) { done = true; resolve(r); } };
    const res = {
      statusCode: 200,
      status: function (c) { this.statusCode = c; return this; },
      json: function (p) { fin({ status: this.statusCode, body: p }); return this; }
    };
    Promise.resolve()
      .then(function () {
        return handler({ params: { orderId: orderId }, user: { id: SUBJECT_USER_ID }, query: {}, body: {}, headers: {} },
          res, function (e) { fin({ status: 500, body: { error: String(e) } }); });
      })
      .catch(function (e) { fin({ status: 500, body: { error: String(e) } }); });
  });
}

(async function main() {
  await residue.sweepPrevious(SUBJECT_USER_ID);

  const probe = await supabase.from("marketplace_orders").select("digital_file_path").limit(1);
  const SNAPSHOT_COLUMNS = !probe.error;
  console.log("\n══ migration 113 applied to this database: " + (SNAPSHOT_COLUMNS ? "YES" : "NO") + " ══");
  if (!SNAPSHOT_COLUMNS) {
    console.log("    The snapshot columns do not exist yet. What is proven below is the fallback:");
    console.log("    the order still lands WITHOUT a snapshot rather than the insert being refused,");
    console.log("    and the download still works through the join. Apply 113 and re-run for the rest.");
  }

  try {
    /* ── 1. a normal purchase snapshots the file ───────────────────────── */
    console.log("\n══ 1. a normal purchase ══");
    const keyA = await makeObject("a");
    const listingA = await makeListing(keyA, "a");
    const sessA = "cs_snap_a_" + stamp;
    await server.__handleStripeEvent(sessionEvent(sessA, listingA, 100));

    const orderA = await orderFor(sessA);
    check("the order was written", !!orderA, "no order");
    if (orderA) {
      console.log("    order: " + JSON.stringify({
        listing_id: orderA.listing_id ? "set" : null, listing_title: orderA.listing_title,
        is_digital: orderA.is_digital,
        digital_file_path: orderA.digital_file_path ? "set" : (orderA.digital_file_path === undefined ? "(column absent)" : null),
        digital_file_name: orderA.digital_file_name === undefined ? "(column absent)" : orderA.digital_file_name
      }));
      if (SNAPSHOT_COLUMNS) {
        check("the file path was snapshotted onto the order", orderA.digital_file_path === keyA,
          String(orderA.digital_file_path));
        check("the file name was snapshotted too", orderA.digital_file_name === "fixture_a.txt",
          String(orderA.digital_file_name));
      }
      check("the title was snapshotted, as it always was", !!orderA.listing_title, String(orderA.listing_title));
    }

    /* ── 2. the listing is deleted AFTER the order ─────────────────────── */
    console.log("\n══ 2. the seller deletes the listing after the sale ══");
    console.log("    This is the case the snapshot rescues: the order exists, carries the file,");
    console.log("    and the buyer must keep their download once the listing is gone.");

    if (MUTATING && SNAPSHOT_COLUMNS && orderA) {
      await supabase.from("marketplace_orders")
        .update({ digital_file_path: null, digital_file_name: null }).eq("id", orderA.id);
      console.log("\n    !! MUTATION: the snapshot has been blanked on the order, so only the");
      console.log("       fallback can serve it. 'served from the snapshot' must go red.\n");
    }

    const beforeDelete = await callDownload(orderA.id);
    check("the download works while the listing still exists", beforeDelete.status === 200,
      beforeDelete.status + " " + JSON.stringify(beforeDelete.body).slice(0, 70));

    await supabase.from("marketplace_listings").delete().eq("id", listingA);
    const gone = await supabase.from("marketplace_listings").select("id").eq("id", listingA).maybeSingle();
    check("the listing is deleted", !gone.data, "still present");

    const orderAfterDelete = await orderFor(sessA);
    check("the paid order survived the deletion", !!orderAfterDelete, "the order is gone too");
    if (orderAfterDelete) {
      console.log("    the order's listing_id after the deletion: " +
        (orderAfterDelete.listing_id === null ? "NULL (ON DELETE SET NULL)" : "still set (ON DELETE NO ACTION / RESTRICT did not fire)"));
    }

    const afterDelete = await callDownload(orderA.id);
    console.log("    download after the listing was deleted: HTTP " + afterDelete.status);
    /* DELIBERATELY NOT GUARDED ON !MUTATING. The first draft of this file was,
       and that made the mutation mode worthless: it blanked the snapshot, the
       download 404'd, and the suite still reported ALL CHECKS PASSED because
       the two assertions that would have noticed had stepped aside for it. A
       mutation whose assertions skip themselves proves nothing. These run
       either way — green normally, red when the snapshot is taken away. */
    if (SNAPSHOT_COLUMNS) {
      check("the buyer can still download after the listing is deleted", afterDelete.status === 200,
        afterDelete.status + " " + JSON.stringify(afterDelete.body).slice(0, 70));
      check("and the filename came from the order's snapshot",
        afterDelete.body && afterDelete.body.fileName === "fixture_a.txt", JSON.stringify(afterDelete.body && afterDelete.body.fileName));
    }

    /* ── 3. the listing is deleted BEFORE payment ──────────────────────── */
    console.log("\n══ 3. the listing is deleted before the payment arrives ══");
    console.log("    The 23503 case. The order must land with listing_id NULL and the payment");
    console.log("    recorded. The snapshot is EMPTY here and this asserts that it is: the webhook");
    console.log("    builds the snapshot by reading the listing, and by now there is none to read.");

    const keyC = await makeObject("c");
    const listingC = await makeListing(keyC, "c");
    await supabase.from("marketplace_listings").delete().eq("id", listingC);
    const sessC = "cs_snap_c_" + stamp;
    await server.__handleStripeEvent(sessionEvent(sessC, listingC, 777));

    const orderC = await orderFor(sessC);
    check("the paid order landed despite the listing being gone", !!orderC, "NO ORDER — the payment is lost");
    if (orderC) {
      check("with listing_id NULL", orderC.listing_id === null, String(orderC.listing_id));
      check("and the amount recorded", orderC.amount_usd === 777, String(orderC.amount_usd));
      check("and the session recorded, which is the key to the payment in Stripe",
        orderC.stripe_session_id === sessC, String(orderC.stripe_session_id));
      check("and marked completed", orderC.status === "completed", String(orderC.status));
      if (SNAPSHOT_COLUMNS) {
        check("the snapshot is empty, as it must be — there was nothing left to copy",
          !orderC.digital_file_path, String(orderC.digital_file_path));
      }
    }

    /* ── 4. an order with no snapshot still downloads ──────────────────── */
    console.log("\n══ 4. an order predating the snapshot ══");
    const keyD = await makeObject("d");
    const listingD = await makeListing(keyD, "d");
    const legacy = await supabase.from("marketplace_orders").insert({
      listing_id: listingD, buyer_id: SUBJECT_USER_ID, seller_id: SUBJECT_USER_ID,
      amount_bfc: 0, amount_usd: 100, payment_method: "usd", status: "completed",
      listing_title: "legacy fixture", is_digital: true,
      stripe_session_id: "cs_snap_legacy_" + stamp
    }).select("id").single();
    if (legacy.error) throw new Error("could not create the legacy order: " + legacy.error.message);
    made.orders.push(legacy.data.id);
    console.log("    an order written with no snapshot columns set at all, listing intact");

    const legacyDownload = await callDownload(legacy.data.id);
    check("it still downloads, through the foreign-key join", legacyDownload.status === 200,
      legacyDownload.status + " " + JSON.stringify(legacyDownload.body).slice(0, 70));
    check("and the filename came from the listing",
      legacyDownload.body && legacyDownload.body.fileName === "fixture_d.txt",
      JSON.stringify(legacyDownload.body && legacyDownload.body.fileName));
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
  try { await removeFixtures(); } catch (e) { /* the guard still runs */ }
  process.exit(1);
});
