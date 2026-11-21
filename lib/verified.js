"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   lib/verified.js — the Verified badge (P3-2, Nov 21 2026; migration 199).

   WHO GETS IT. bf_profiles.verified_reason says why; NULL shows nothing.
     member    a PAID member while entitled: getUserPlan answers active with
               access_reason "subscription". The owner pass and the admin
               exemption are not paid memberships and never set it. Kept in
               step by the server: syncOne after every Stripe event that names
               the account, and reconcile() on a schedule (server.js), so it
               is set when the membership becomes active and cleared the same
               day it ends.
     seller    a verified seller: set and removed by the owner
               (POST /api/admin/verify/:userId, POST /api/admin/unverify/:userId;
               moderation.html "Verified sellers").
     official  the owner's official accounts, set by the owner the same way.
   A member who is also a seller or official keeps 'seller' or 'official'
   when the membership ends: syncOne only ever writes or clears 'member'.
   REMOVED on a ban (POST /api/admin/ban/:userId and the repeat-infringer ban),
   an admin un-verify, or a moderation removal of the profile. A banned
   account, or one whose profile moderation removed, is never given 'member'.

   WHERE IT SHOWS. One mark, drawn the same everywhere (badgeHtml here for the
   pages the server writes; scripts/bf-verified.js in the frontend builds the
   same markup), inline after the name. A tap opens the sheet: SHEET_TEXT.

   RANK. Suggestions sort Verified first now (lib/posts.js suggestions).
   RANK_WEIGHT is the factor For You, Market and Local will multiply a
   verified account's placement by (P2-6). It is read by the legal pages; no
   ranking uses it yet.

   It is not an endorsement, and every place that explains it says so.
   ══════════════════════════════════════════════════════════════════════════ */

const REASONS = Object.freeze(["member", "seller", "official"]);
const LABELS = Object.freeze({
  member: "BizForce member",
  seller: "Verified seller",
  official: "Official BizForce account"
});
const NOT_ENDORSEMENT = "This is not an endorsement.";
/* For You, Market and Local: a verified account's placement is multiplied by this (P2-6). Not used by any ranking yet. */
const RANK_WEIGHT = 1.5;
/* The reasons only the owner sets; a membership ending never clears them. */
const OWNER_SET = Object.freeze(["seller", "official"]);

function isReason(r) { return REASONS.indexOf(r) !== -1; }
function reasonOf(row) { return row && isReason(row.verified_reason) ? row.verified_reason : null; }
function labelFor(reason) { return isReason(reason) ? LABELS[reason] : null; }
function sheetText(reason) { return isReason(reason) ? "Verified: " + LABELS[reason] + ". " + NOT_ENDORSEMENT : null; }

/* A paid membership, while entitled. The owner pass ("owner") and the admin exemption ("admin") are not. */
function paidMember(plan) { return !!plan && plan.active === true && plan.access_reason === "subscription"; }

/* What the reason should be now. Pure.
   current: the stored reason; s: { paid, banned, removed }. */
function nextReason(current, s) {
  const st = s || {};
  if (st.banned || st.removed) return null;
  if (OWNER_SET.indexOf(current) !== -1) return current;
  return st.paid ? "member" : null;
}

/* Verified first, otherwise the order given (stable). reasonFn reads an item's reason. */
function verifiedFirst(list, reasonFn) {
  return (list || []).map(function (x, i) { return { x: x, i: i, v: reasonFn(x) ? 1 : 0 }; })
    .sort(function (a, b) { return b.v - a.v || a.i - b.i; }).map(function (o) { return o.x; });
}

/* THE MARK. scripts/bf-verified.js builds exactly this markup (checkVerifiedBadge compares them). */
const SVG = '<svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true" focusable="false">' +
  '<circle cx="8" cy="8" r="8" fill="currentColor"></circle>' +
  '<path d="M4.6 8.3l2.2 2.2 4.6-4.7" fill="none" stroke="#070b18" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"></path></svg>';
/* The mark's look, the same rules in scripts/bf-verified.js (checkVerifiedBadge compares them). 16 px drawn, inline
   INSIDE the name element after its text (names are links almost everywhere, and a control may not sit inside a link).
   It is not focusable: its kind is its accessible name, read with the name. The ::after is a 44 x 44 tap area centred on
   the mark, so it moves nothing around it; a tap opens the sheet (scripts/bf-verified.js) instead of following the link. */
const CSS =
  ".bf-vb{position:relative;display:inline-flex;align-items:center;justify-content:center;flex:none;width:16px;height:16px;margin:0 0 0 4px;padding:0;" +
  "border-radius:50%;color:var(--bf-accent-a, #22d3ee);line-height:0;vertical-align:-2px;cursor:pointer;-webkit-tap-highlight-color:transparent}" +
  ".bf-vb::after{content:\"\";position:absolute;left:50%;top:50%;width:44px;height:44px;transform:translate(-50%,-50%)}" +
  ".bf-vb svg{display:block;width:16px;height:16px}";
function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function badgeHtml(reason) {
  if (!isReason(reason)) return "";
  return '<span class="bf-vb" role="img" data-bf-verified="' + reason + '" aria-label="' + esc(LABELS[reason]) + '" title="' + esc(LABELS[reason]) + '">' + SVG + '</span>';
}

/* ── the database ──
   deps: { sb, planOf(userId) -> getUserPlan answer, now() -> ISO time } */

async function standingOf(deps, userId) {
  const u = await deps.sb.from("users").select("id, banned_at, role").eq("id", userId).maybeSingle();
  if (u.error) throw u.error;
  const m = await deps.sb.from("moderation_queue").select("object_id, state").eq("object_type", "profile").eq("object_id", userId).eq("state", "removed").limit(1);
  if (m.error) throw m.error;
  return { exists: !!u.data, banned: !!(u.data && (u.data.banned_at || u.data.role === "deleted")), removed: (m.data || []).length > 0 };
}

async function readReason(sb, userId) {
  const r = await sb.from("bf_profiles").select("user_id, verified_reason, verified_at").eq("user_id", userId).maybeSingle();
  if (r.error) throw r.error;
  return r.data || null;
}

async function writeReason(deps, userId, reason) {
  const u = await deps.sb.from("bf_profiles").update({ verified_reason: reason, verified_at: reason ? deps.now() : null })
    .eq("user_id", userId).select("user_id, verified_reason, verified_at");
  if (u.error) throw u.error;
  return (u.data || [])[0] || null;
}

/* Brings one account's 'member' reason in step with its plan. Never touches 'seller' or 'official' unless the
   account is banned or its profile was removed. An account without a bf_profiles row has nothing to show and is left. */
async function syncOne(deps, userId) {
  const row = await readReason(deps.sb, userId);
  if (!row) return { user_id: userId, changed: false, from: null, to: null, reason: "no_profile" };
  const from = reasonOf(row);
  const st = await standingOf(deps, userId);
  let paid = false;
  if (!st.banned && !st.removed && OWNER_SET.indexOf(from) === -1) paid = paidMember(await deps.planOf(userId));
  const to = nextReason(from, { paid: paid, banned: st.banned || !st.exists, removed: st.removed });
  if (to === from) return { user_id: userId, changed: false, from: from, to: to };
  await writeReason(deps, userId, to);
  return { user_id: userId, changed: true, from: from, to: to };
}

/* Clears every reason (a ban, a profile removal, an admin un-verify). Returns whether a badge was taken away. */
async function clearFor(deps, userId) {
  const row = await readReason(deps.sb, userId);
  if (!row || !reasonOf(row)) return { cleared: false, from: null };
  await writeReason(deps, userId, null);
  return { cleared: true, from: reasonOf(row) };
}

/* The owner sets 'seller' or 'official'. Refused for a banned account or a removed profile. */
async function setByOwner(deps, userId, reason) {
  if (OWNER_SET.indexOf(reason) === -1) return { status: 400, body: { error: "reason is seller or official." } };
  const row = await readReason(deps.sb, userId);
  if (!row) return { status: 404, body: { error: "That account has no profile yet. Nothing was changed." } };
  const st = await standingOf(deps, userId);
  if (st.banned || !st.exists || st.removed) return { status: 409, body: { error: "That account is banned or its profile was removed, so it cannot be verified. Nothing was changed." } };
  const saved = await writeReason(deps, userId, reason);
  return { status: 200, body: { user_id: userId, verified_reason: saved ? saved.verified_reason : reason, verified_at: saved ? saved.verified_at : null, from: reasonOf(row) } };
}

/* The owner removes 'seller' or 'official'. A paid member drops back to 'member' (syncOne), never to nothing by mistake. */
async function unsetByOwner(deps, userId) {
  const row = await readReason(deps.sb, userId);
  if (!row) return { status: 404, body: { error: "That account has no profile. Nothing was changed." } };
  const from = reasonOf(row);
  if (!from) return { status: 200, body: { user_id: userId, verified_reason: null, from: null } };
  await writeReason(deps, userId, null);
  const after = await syncOne(deps, userId);
  return { status: 200, body: { user_id: userId, verified_reason: after.to, from: from } };
}

/* THE SCHEDULED PASS: every account showing a badge (any kind: a ban or a profile removal clears seller and official
   too), and every account with a subscription row, is brought in step. Returns counts; one account's failure is
   logged and the pass goes on. */
async function reconcile(deps) {
  const a = await deps.sb.from("bf_profiles").select("user_id").not("verified_reason", "is", null).limit(10000);
  if (a.error) throw a.error;
  const { isUncountedAccount } = require("./testAccounts");
  const b = await deps.sb.from("subscriptions").select("user_id").limit(10000);
  if (b.error) throw b.error;
  // Test accounts and the owner are left out of the subscription list (lib/testAccounts.js isUncountedAccount, by id), the
  // rule for every read across accounts (checkTestAccounts 3). An account already showing a badge is still checked from the
  // first list, so a ban or removal still clears it.
  const subs = (b.data || []).filter(function (r) { return r && !isUncountedAccount({ id: r.user_id }); });
  const ids = [...new Set([].concat(a.data || [], subs).map(function (r) { return r && r.user_id; }).filter(Boolean))];
  const out = { checked: 0, set: 0, cleared: 0, failed: 0 };
  for (const id of ids) {
    try {
      const r = await syncOne(deps, id);
      out.checked++;
      if (r.changed && r.to === "member") out.set++;
      if (r.changed && r.from && r.to !== r.from && r.to !== "member") out.cleared++;
    } catch (e) {
      out.failed++;
      console.error("[verified] reconcile could not bring " + id + " in step: " + ((e && e.message) || e) + ". The pass goes on.");
    }
  }
  return out;
}

/* The account a Stripe event is about: the checkout's metadata, else the subscriptions row for its customer or subscription. */
async function stripeEventUser(sb, event) {
  const o = (event && event.data && event.data.object) || {};
  if (o.metadata && typeof o.metadata.user_id === "string" && o.metadata.user_id) return o.metadata.user_id;
  const subId = typeof o.subscription === "string" ? o.subscription : (event && /^customer\.subscription\./.test(event.type) ? o.id : null);
  if (subId) {
    const r = await sb.from("subscriptions").select("user_id").eq("stripe_subscription_id", subId).maybeSingle();
    if (!r.error && r.data && r.data.user_id) return r.data.user_id;
  }
  if (typeof o.customer === "string" && o.customer) {
    const r = await sb.from("subscriptions").select("user_id").eq("stripe_customer_id", o.customer).maybeSingle();
    if (!r.error && r.data && r.data.user_id) return r.data.user_id;
  }
  return null;
}

/* After a Stripe event was handled: the account's badge follows its membership. Never throws. */
async function afterStripeEvent(deps, event) {
  try {
    if (!event || !/^(checkout\.session\.completed|customer\.subscription\.|invoice\.payment_)/.test(String(event.type || ""))) return null;
    const userId = await stripeEventUser(deps.sb, event);
    if (!userId) return null;
    return await syncOne(deps, userId);
  } catch (e) {
    console.error("[verified] the badge could not follow Stripe event " + ((event && event.id) || "?") + ": " + ((e && e.message) || e) +
      ". The event itself stands; the scheduled pass will bring the badge in step.");
    return null;
  }
}

module.exports = {
  REASONS, LABELS, NOT_ENDORSEMENT, RANK_WEIGHT, OWNER_SET, SVG, CSS,
  isReason, reasonOf, labelFor, sheetText, paidMember, nextReason, verifiedFirst, badgeHtml,
  standingOf, syncOne, clearFor, setByOwner, unsetByOwner, reconcile, stripeEventUser, afterStripeEvent
};
