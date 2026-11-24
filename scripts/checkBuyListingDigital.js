"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   checkBuyListingDigital.js — buying a digital listing with BizCash (P2-2 fix
   d, Nov 20 2026; migration 192).

   THE DEFECT. bfc_buy_listing (live; the body migration 089 transcribed)
   wrote every BizCash order with is_digital false and no file snapshot, and
   marked the listing sold. So a buyer of a digital listing was refused the
   download, and the listing sold out after one copy.

   WHAT THIS PROVES
     R. THE MIGRATIONS: 200 is the highest (FX2); only 191 to 200 are above 190.
     S. MIGRATION 192, as text: one transaction; the guard drops only a
        single-column unique rule on marketplace_orders.listing_id (and says
        so); and the function is 089's body with exactly the documented
        changes: putting each change back gives 089's text byte for byte, so
        nothing else moved (the arguments, the return, SECURITY DEFINER,
        search_path, the errors and their order, the transfer and its
        description). The grants are 090's.
     T. THE CHANGES, each present once: the digital fields read with the row
        lock; a blocked pair refused with "listing not available" (the words
        of a listing not on sale); sold only when not digital; the order
        copies the three fields.
     U. THE DOWNLOAD (GET /api/purchases/:orderId/download, run in a vm): an
        order from 192 on is served from its own snapshot; an older BizCash
        order of a digital listing is served from the listing when it is the
        same seller's, has a file and is digital; any other old order 403.

   MUTATE=<name> applies one mutation in memory; MUTATE=all runs each.
   ═══════════════════════════════════════════════════════════════════════════ */
const fs = require("fs");
const path = require("path");
const H = require("./_p21Harness");

const SERVER = "@server.js", M192 = "@supabase/migrations/192_buy_listing_digital.sql", M089 = "@supabase/migrations/089_record_missing_bfc_functions.sql";
const MUTATIONS = {
  "still-sold": [[M192, "  if coalesce(v_is_digital, false) = false then\n    update marketplace_listings\n      set status = 'sold', updated_at = now()\n      where id = p_listing_id;\n  end if;",
    "  update marketplace_listings\n    set status = 'sold', updated_at = now()\n    where id = p_listing_id;"]],
  "block-one-way": [[M192, "    where (blocker_id = p_buyer and blocked_id = v_seller)\n       or (blocker_id = v_seller and blocked_id = p_buyer)", "    where (blocker_id = p_buyer and blocked_id = v_seller)"]],
  "block-reveals": [[M192, "  ) then\n    raise exception 'listing not available';", "  ) then\n    raise exception 'blocked';"]],
  "no-snapshot": [[M192, "          coalesce(v_is_digital, false), v_file_path, v_file_name);", "          coalesce(v_is_digital, false), null, v_file_name);"]],
  "lock-dropped": [[M192, "    where id = p_listing_id\n    for update;", "    where id = p_listing_id;"]],
  "drops-any-unique": [[M192, "      AND i.indnatts = 1\n", ""]],
  "grant-public": [[M192, "REVOKE EXECUTE ON FUNCTION public.bfc_buy_listing(uuid, uuid) FROM PUBLIC, anon, authenticated;", "REVOKE EXECUTE ON FUNCTION public.bfc_buy_listing(uuid, uuid) FROM anon;"]],
  "download-other-seller": [[SERVER, " || bought.data.seller_id !== order.seller_id) {", ") {"]]
};
const T = H.setup(__filename, MUTATIONS, [SERVER, M192, M089]);
const { FILES, check, J, has, count } = T;

const BUYER = "11111111-1111-4111-8111-111111111111", SELLER = "22222222-2222-4222-8222-222222222222", LISTING = "44444444-4444-4444-8444-444444444444";

(async function main() {
  /* ── R ── */
  console.log("\n══ R. the migrations ══");
  const dir = path.join(H.REPO, "supabase", "migrations");
  const nums = fs.readdirSync(dir).map(f => (/^(\d{3})_.*\.sql$/.exec(f) || [])[1]).filter(Boolean).map(Number);
  const above = fs.readdirSync(dir).filter(f => /^\d{3}_.*\.sql$/.test(f) && Number(f.slice(0, 3)) > 190).sort();
  // NAMED (Nov 20 2026, P2-3, migrations 193 and 194): BEFORE "the highest migration is 192" and "only 191 and 192 are above 190".
  // AFTER 194 is the highest, and 193_posts.sql and 194_social_graph.sql are allowed above 190 too, by name.
  // NAMED (Nov 20 2026, P3-1, migrations 195 to 198): BEFORE "the highest migration is 194" and "only 191 to 194 are above 190".
  // AFTER 198 is the highest, and 195_users_email_canonical.sql, 196_storage_account_tables.sql, 197_storage_account_functions.sql and
  // 198_storage_account_backfill.sql (P3-1A's 196a/196b/196c, renamed) are allowed above 190 too, by name.
  // NAMED (Nov 21 2026, P3-2, migration 199): BEFORE "the highest migration is 198" and "only 191 to 198 are above 190". AFTER 199 is
  // the highest, and 199_verified_badge.sql (bf_profiles.verified_reason and verified_at, the Verified badge) is allowed above 190 too.
  // NAMED (Nov 21 2026, FX2, migration 200): BEFORE "the highest migration is 199" and "only 191 to 199 are above 190". AFTER 200
  // (200_categories_and_intent.sql, applied by hand Nov 21 2026) is the highest, and it is allowed above 190 too.
  // NAMED (Nov 21 2026, P3-1C, migration 201): 201_member_welcome.sql (the member welcome and the free-account clawback, once per account: two unique partial indexes on wallet_transactions) is allowed above too, by name; "the highest" (201) is checkBuyListingDigital R1's.
  // NAMED (Nov 23 2026, P3-3, migration 202): BEFORE 201. AFTER 202 (202_need_found_and_alerts.sql).
  // NAMED (Nov 23 2026, LR-1, migration 203): BEFORE 202. AFTER 203 (203_lr1_archived_and_sms_pending.sql).
  check("R1. the highest migration is 203 (LR-1)", Math.max(...nums) === 203, Math.max(...nums));
  // NAMED (Nov 21 2026, P3-1C, migration 201): 201_member_welcome.sql (the member welcome and the free-account clawback, once per account: two unique partial indexes on wallet_transactions) is allowed above too, by name; "the highest" (201) is checkBuyListingDigital R1's.
  // NAMED (Nov 23 2026, P3-3, migration 202): 202_need_found_and_alerts.sql (posts.need_found_at, a Need marked Found, and user_preferences.need_alerts) is allowed too, by name.
  // NAMED (Nov 23 2026, LR-1, migration 203): 203_lr1_archived_and_sms_pending.sql (sales_lead_pipeline may be 'archived'; sms_subscribers.consent_status defaults to 'pending') is allowed too, by name.
  check("R2. only 191 to 200 are above 190", J(above) === J(["191_safety.sql", "192_buy_listing_digital.sql", "193_posts.sql", "194_social_graph.sql", "195_users_email_canonical.sql", "196_storage_account_tables.sql", "197_storage_account_functions.sql", "198_storage_account_backfill.sql", "199_verified_badge.sql", "200_categories_and_intent.sql", "201_member_welcome.sql", "202_need_found_and_alerts.sql", "203_lr1_archived_and_sms_pending.sql"]), J(above));

  /* ── S ── */
  console.log("\n══ S. migration 192 ══");
  const sql = FILES[M192] || "";
  const code = sql.split("\n").filter(l => !/^--/.test(l)).join("\n");
  check("S1. one transaction", /^BEGIN;$/m.test(code) && /^COMMIT;$/m.test(code) && count(code, "BEGIN;") === 1 && count(code, "COMMIT;") === 1);
  const guard = (/DO \$\$[\s\S]*?END \$\$;/.exec(code) || [""])[0];
  check("S2. the guard drops only a unique, non-primary, one-column rule on marketplace_orders.listing_id, and says so",
    has(guard, "WHERE i.indrelid = 'public.marketplace_orders'::regclass") && has(guard, "AND i.indisunique AND NOT i.indisprimary") && has(guard, "AND i.indnatts = 1") &&
    has(guard, "WHERE attrelid = 'public.marketplace_orders'::regclass AND attname = 'listing_id')") && has(guard, "RAISE NOTICE '192: dropped the unique rule") &&
    count(guard, "EXECUTE format(") === 2);
  const fn = s => (/CREATE OR REPLACE FUNCTION public\.bfc_buy_listing\(p_buyer uuid, p_listing_id uuid\)[\s\S]*?\$function\$;/.exec(s) || [""])[0];
  const now192 = fn(code), was089 = fn(FILES[M089] || "");
  /* Each documented change, as [what 192 says, what 089 said]. Each must be found exactly once. */
  const CHANGES = [
    ["  v_title text;\n  v_is_digital boolean;\n  v_file_path text;\n  v_file_name text;\n", "  v_title text;\n"],
    ["  select seller_id, price_bfc, status, title, is_digital, digital_file_path, digital_file_name\n    into v_seller, v_price, v_status, v_title, v_is_digital, v_file_path, v_file_name\n",
     "  select seller_id, price_bfc, status, title\n    into v_seller, v_price, v_status, v_title\n"],
    ["  if exists (\n    select 1 from member_blocks\n    where (blocker_id = p_buyer and blocked_id = v_seller)\n       or (blocker_id = v_seller and blocked_id = p_buyer)\n  ) then\n    raise exception 'listing not available';\n  end if;\n\n", ""],
    ["  if coalesce(v_is_digital, false) = false then\n    update marketplace_listings\n      set status = 'sold', updated_at = now()\n      where id = p_listing_id;\n  end if;",
     "  update marketplace_listings\n    set status = 'sold', updated_at = now()\n    where id = p_listing_id;"],
    ["  insert into marketplace_orders (listing_id, buyer_id, seller_id, amount_bfc, listing_title, status,\n                                  is_digital, digital_file_path, digital_file_name)\n  values (p_listing_id, p_buyer, v_seller, v_price, v_title, 'completed',\n          coalesce(v_is_digital, false), v_file_path, v_file_name);",
     "  insert into marketplace_orders (listing_id, buyer_id, seller_id, amount_bfc, listing_title, status)\n  values (p_listing_id, p_buyer, v_seller, v_price, v_title, 'completed');"]
  ];
  const found = CHANGES.map(c => count(now192, c[0]));
  let back = now192;
  CHANGES.forEach(c => { back = back.split(c[0]).join(c[1]); });
  check("T1. every documented change is there, once", J(found) === J([1, 1, 1, 1, 1]), J(found));
  check("S3. putting each change back gives migration 089's function byte for byte (nothing else moved)", was089.length > 0 && back === was089,
    (() => { let i = 0; while (i < back.length && back[i] === was089[i]) i++; return "differs at " + i + ": " + J(back.slice(i, i + 80)) + " vs " + J(was089.slice(i, i + 80)); })());
  check("S4. the grants are 090's: no member calls it; the server does", has(code, "REVOKE EXECUTE ON FUNCTION public.bfc_buy_listing(uuid, uuid) FROM PUBLIC, anon, authenticated;") &&
    has(code, "GRANT EXECUTE ON FUNCTION public.bfc_buy_listing(uuid, uuid) TO service_role;"));

  /* ── T ── */
  console.log("\n══ T. the changes ══");
  check("T2. the digital fields are read under the same row lock", /digital_file_name\n\s+into [^\n]+\n\s+from marketplace_listings\n\s+where id = p_listing_id\n\s+for update;/.test(now192));
  const order = ["raise exception 'listing not found';", "raise exception 'listing not available';", "raise exception 'cannot buy your own listing';", "from member_blocks", "v_new_balance := bfc_transfer("].map(x => now192.indexOf(x));
  check("T3. a blocked pair (either way) is refused after the existing checks and before any BizCash moves, with the words of a listing not on sale",
    order.every((x, i) => x !== -1 && (i === 0 || x > order[i - 1])) && /member_blocks\n\s+where \(blocker_id = p_buyer and blocked_id = v_seller\)\n\s+or \(blocker_id = v_seller and blocked_id = p_buyer\)\n\s+\) then\n\s+raise exception 'listing not available';/.test(now192), J(order));
  check("T4. a digital listing stays on sale; any other is sold, as before", has(now192, "if coalesce(v_is_digital, false) = false then\n    update marketplace_listings\n      set status = 'sold'"));
  check("T5. the order copies is_digital (false when unset), the path and the name", has(now192, "coalesce(v_is_digital, false), v_file_path, v_file_name);"));
  const S = FILES[SERVER];
  check("T6. the server's purchase route still calls it with the buyer and the listing", /supabase\.rpc\("bfc_buy_listing", \{\s*p_buyer: req\.user\.id,\s*p_listing_id: listingId/.test(S));

  /* ── U ── */
  console.log("\n══ U. the download ══");
  async function download(orderRow, listingRow) {
    const signed = [];
    const db = H.fakeDb(t => t === "marketplace_orders" ? { data: orderRow, error: null } : t === "marketplace_listings" ? { data: listingRow, error: null } : { data: null, error: null });
    db.client.storage = { from: (b) => ({ createSignedUrl: async (p, s) => { signed.push([b, p, s]); return { data: { signedUrl: "https://signed/" + p }, error: null }; } }) };
    const route = H.route(S, "get", "/api/purchases/:orderId/download", { supabase: db.client }, T.libRequire);
    if (!route) return { status: "no route" };
    const r = await route({ user: { id: BUYER }, params: { orderId: "o1" } });
    return Object.assign(r, { signed });
  }
  const base = { id: "o1", buyer_id: BUYER, seller_id: SELLER, listing_id: LISTING };
  const u1 = await download(Object.assign({}, base, { is_digital: true, digital_file_path: SELLER + "/book.pdf", digital_file_name: "book.pdf" }), null);
  check("U1. an order from 192 on: served from its own snapshot", u1.status === 200 && u1.body.url === "https://signed/" + SELLER + "/book.pdf" && u1.body.fileName === "book.pdf" &&
    J(u1.signed[0]) === J(["bf-digital-goods", SELLER + "/book.pdf", 604800]), J(u1));
  const u2 = await download(Object.assign({}, base, { is_digital: false }), { seller_id: SELLER, is_digital: true, digital_file_path: SELLER + "/book.pdf", digital_file_name: "book.pdf" });
  check("U2. an older BizCash order of a digital listing: served from the listing", u2.status === 200 && u2.body.url === "https://signed/" + SELLER + "/book.pdf", J(u2));
  const u3 = await download(Object.assign({}, base, { is_digital: false }), { seller_id: "99999999-9999-4999-8999-999999999999", is_digital: true, digital_file_path: "x/y.pdf" });
  const u4 = await download(Object.assign({}, base, { is_digital: false }), { seller_id: SELLER, is_digital: false, digital_file_path: null });
  const u5 = await download(Object.assign({}, base, { is_digital: false, listing_id: null }), null);
  check("U3. any other old order 403: another seller's listing now, a listing that is not digital, no listing", [u3, u4, u5].every(u => u.status === 403 && u.body.error === "This purchase has no digital download" && u.signed.length === 0), J([u3.status, u4.status, u5.status]));
  const u6 = await download(null, null);
  check("U4. not this buyer's order: 404", u6.status === 404);
  check("U5. no emoji in the migration or this check", !/\p{Extended_Pictographic}/u.test(sql + fs.readFileSync(__filename, "utf8")));

  T.finish();
})().catch(e => { console.error(e); process.exit(1); });
