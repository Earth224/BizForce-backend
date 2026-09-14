/* ══════════════════════════════════════════════════════════════════════════
   checkMarketplaceAnonRead.js — can an anonymous reader see a seller's private
   columns on marketplace_listings, and do the listing routes still work.

   RUN IT BEFORE AND AFTER MIGRATION 110. It is written to be red before and
   green after, and it says which of those two it is in plain words at the end,
   so a red run before the migration is the demonstration rather than a broken
   script:

     BEFORE   EXPOSED — anon can select digital_file_path / digital_file_name
     AFTER    CLOSED  — anon cannot select from the table at all

   WHAT IT USES. The SUPABASE_ANON_KEY, because that is the credential an
   anonymous visitor's browser would hold, and the question is what THAT can
   read. Every other check in this directory runs as the service role, which
   bypasses RLS and grants entirely and therefore cannot answer this.

   WHY THE EXPOSURE IS NOT VISIBLE IN THE DATA TODAY. The row policy
   (status = 'active' OR seller_id = auth.uid()) hides paused listings, and the
   one listing that carries a real uploaded file is paused. So anon sees three
   active listings whose digital_file_path happens to be null. That is not the
   table being safe — it is the leak being one status change away. This script
   therefore tests whether the COLUMN IS READABLE, not whether today's rows
   happen to hold anything, because a check that passed on null values would go
   green today and red the morning a seller published their product.

   READ-ONLY. It writes nothing to any table and needs no residue guard. The
   only mutation it performs is to its own client (see below).

   MUTATE=use-service-key swaps the service client in where the anon client
   belongs. The anon assertions must then go red, because the service role can
   always read. That proves this script is actually exercising the anonymous
   path rather than asserting something that is trivially true.
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const path = require("path");
const REPO = path.join(__dirname, "..");

/* server.js is booted so the two listing routes can be invoked as themselves.
   The SDK is not stubbed and no model is called: neither route touches one. */
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
require(path.join(REPO, "server.js"));

const { createClient } = require("@supabase/supabase-js");

const service = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

const MUTATING = process.env.MUTATE === "use-service-key";

/* The credential under test. Under the mutation this is deliberately the wrong
   one, and the assertions below must notice. */
const asAnon = MUTATING
  ? createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY)
  : createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

/* The columns that must never reach an anonymous reader. digital_file_path is
   the one the defect names; digital_file_name is the same lane and leaks the
   product's filename, which is arguably the more useful half to an attacker. */
const PRIVATE_COLUMNS = ["digital_file_path", "digital_file_name"];

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

function routeLayer(routePath, method) {
  const found = app._router.stack.filter(function (l) {
    return l.route && l.route.path === routePath && l.route.methods[method];
  });
  if (!found.length) throw new Error("route not mounted: " + method.toUpperCase() + " " + routePath);
  return found[0];
}

/* Invokes the route's final handler with req/res shims. requireAuth is skipped
   where present and the user it would have attached is supplied, exactly as
   scripts/checkEntitlementGate.js does. */
function callRoute(routePath, method, req) {
  const stack = routeLayer(routePath, method).route.stack;
  const handler = stack[stack.length - 1].handle;
  return new Promise(function (resolve) {
    let settled = false;
    const done = function (r) { if (!settled) { settled = true; resolve(r); } };
    const res = {
      statusCode: 200,
      status: function (c) { this.statusCode = c; return this; },
      json: function (p) { done({ status: this.statusCode, body: p }); return this; },
      send: function (p) { done({ status: this.statusCode, body: p }); return this; }
    };
    Promise.resolve()
      .then(function () { return handler(req, res, function (e) { done({ status: 500, body: { error: (e && e.message) || String(e) } }); }); })
      .catch(function (e) { done({ status: 500, body: { error: (e && e.message) || String(e) } }); });
  });
}

(async function main() {
  if (MUTATING) {
    console.log("\n!! MUTATION: the service key is standing in for the anon key.");
    console.log("   The anon assertions below must fail — the service role can always read.\n");
  }

  /* ── what the table actually holds, read as the service role ─────────── */
  console.log("══ the table, as the service role sees it ══");
  const all = await service.from("marketplace_listings")
    .select("id, status, title, is_digital, digital_file_path, digital_file_name");
  if (all.error) { console.error("could not read the table: " + all.error.message); process.exit(1); }

  const active = (all.data || []).filter(function (r) { return r.status === "active"; });
  const withFile = (all.data || []).filter(function (r) { return r.digital_file_path; });
  console.log("    " + all.data.length + " listing(s): " + active.length + " active, " +
    (all.data.length - active.length) + " not active");
  console.log("    " + withFile.length + " listing(s) carry a real digital_file_path:");
  withFile.forEach(function (r) {
    console.log("      status=" + r.status + "  name=" + JSON.stringify(r.digital_file_name) +
      "  (path withheld from this output)");
  });
  const liveRisk = withFile.filter(function (r) { return r.status === "active"; }).length;
  console.log("    of those, " + liveRisk + " are active" +
    (liveRisk === 0 && withFile.length > 0
      ? " — the leak is one status change away, not absent"
      : ""));

  /* ── the question: is the column readable as anon ────────────────────── */
  console.log("\n══ what the anon key can select ══");

  const anonAll = await asAnon.from("marketplace_listings").select("*");
  const anonBlocked = !!anonAll.error;

  if (anonBlocked) {
    console.log("    anon SELECT *              : REFUSED (" + anonAll.error.message.slice(0, 70) + ")");
  } else {
    console.log("    anon SELECT *              : " + anonAll.data.length + " row(s), " +
      (anonAll.data[0] ? Object.keys(anonAll.data[0]).length : 0) + " columns");
  }

  /* THE CLIENT UNDER TEST REALLY IS ANONYMOUS. This is the assertion the
     mutation flips, and it is the reason the mutation means anything before
     migration 110 is applied: the private-column assertions below are red
     either way until then, so on their own they could not tell a genuine anon
     client from a mis-wired one. The service role sees every row; anon sees
     only the active ones, or none at all once 110 lands. Either way it must
     see FEWER than the service role does. */
  const anonRowCount = anonBlocked ? 0 : anonAll.data.length;
  check("the client under test is genuinely anonymous, not the service role",
    anonRowCount < all.data.length,
    "it sees " + anonRowCount + " row(s); the service role sees " + all.data.length +
    (MUTATING ? " — which is the mutation working" : ""));

  /* ASKED COLUMN BY COLUMN, not inferred from SELECT *. A narrowed grant would
     still answer SELECT * — with fewer columns — so the only question that
     distinguishes the states is whether the private column itself is
     selectable. */
  const perColumn = {};
  for (const col of PRIVATE_COLUMNS) {
    const r = await asAnon.from("marketplace_listings").select("id, " + col).limit(5);
    perColumn[col] = { readable: !r.error, error: r.error ? r.error.message : null, rows: r.data ? r.data.length : 0 };
    console.log("    anon SELECT " + col.padEnd(18) + ": " +
      (r.error ? "REFUSED (" + r.error.message.slice(0, 50) + ")" : "READABLE — " + r.data.length + " row(s)"));
  }

  for (const col of PRIVATE_COLUMNS) {
    check("anon cannot select " + col, perColumn[col].readable === false,
      perColumn[col].readable ? "still readable by anon" : "");
  }

  /* ── the service key must be untouched ───────────────────────────────── */
  console.log("\n══ the service role is unaffected ══");
  const svcStill = await service.from("marketplace_listings")
    .select("id, digital_file_path").limit(5);
  check("the service role can still read the private columns", !svcStill.error,
    svcStill.error ? svcStill.error.message : "");

  /* ── both listing routes, invoked as themselves ──────────────────────── */
  console.log("\n══ the two listing routes still work ══");

  const listRes = await callRoute("/api/marketplace/listings", "get", {
    user: { id: "00000000-0000-0000-0000-000000000000" },
    query: {}, params: {}, body: {}, headers: {}
  });
  check("GET /api/marketplace/listings returns 200", listRes.status === 200,
    "status " + listRes.status + " " + JSON.stringify(listRes.body).slice(0, 80));
  const listed = (listRes.body && listRes.body.listings) || [];
  check("and returns every active listing", listed.length === active.length,
    listed.length + " returned vs " + active.length + " active");
  check("and never includes a private column in its response",
    listed.every(function (l) { return PRIVATE_COLUMNS.every(function (c) { return !(c in l); }); }),
    listed[0] ? Object.keys(listed[0]).join(", ") : "no rows");

  if (active.length) {
    const one = active[0];
    const oneRes = await callRoute("/api/marketplace/listings/:id", "get", {
      params: { id: one.id }, query: {}, body: {}, headers: {}
    });
    check("GET /api/marketplace/listings/:id returns 200", oneRes.status === 200,
      "status " + oneRes.status + " " + JSON.stringify(oneRes.body).slice(0, 80));
    const listing = oneRes.body && oneRes.body.listing;
    check("and returns the listing", !!listing, JSON.stringify(oneRes.body).slice(0, 80));
    if (listing) {
      check("and never includes a private column in its response",
        PRIVATE_COLUMNS.every(function (c) { return !(c in listing); }), Object.keys(listing).join(", "));
    }
  }

  /* ── the verdict, in words ───────────────────────────────────────────── */
  console.log("\n══ verdict ══");
  const stillExposed = PRIVATE_COLUMNS.some(function (c) { return perColumn[c].readable; });
  if (stillExposed) {
    console.log("    EXPOSED — an anonymous reader can select the private columns of every");
    console.log("    active listing. Migration 110 has NOT been applied to this database.");
    console.log("    Apply supabase/migrations/110_marketplace_listings_revoke_anon_select.sql");
    console.log("    and run this again: the failures above are the demonstration.");
  } else {
    console.log("    CLOSED — the anon key cannot read marketplace_listings.");
    console.log("    The service role and both listing routes are unaffected.");
  }

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
})().catch(function (err) {
  console.error("\nThe check threw: " + ((err && err.stack) || err));
  process.exit(1);
});
