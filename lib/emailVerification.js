"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   lib/emailVerification.js — what an unverified account may not do yet
   (P3-1, Nov 20 2026).

   users.email_verified_at is the source (migration 122). A confirmed email is
   required before an account can:
     - post publicly (lib/posts.js createPost, audience "public");
     - list in the Market (POST /api/marketplace/listings, and an edit that
       makes a listing active);
     - message someone who does not follow it (POST /api/messages);
     - receive BizCash (transfer, support and tips, donations, a Market sale:
       the RECEIVING side is refused before any BizCash moves).
   Browsing, following and setting up the profile need none.

   The refusal is 403 with reason "email_unverified" and the resend route, so
   the app can show its banner with "Resend email".
   ══════════════════════════════════════════════════════════════════════════ */

const REQUIRED_FOR = Object.freeze(["post_public", "list_market", "message_non_follower", "receive_bizcash"]);

const MESSAGE =
  "Confirm your email first. We sent you a link when you signed up; nothing was saved. Use Resend email if you cannot find it.";
const RECIPIENT_MESSAGE =
  "This member has not confirmed their email yet, so they cannot receive BizCash. Nothing was sent and your balance is unchanged.";
const RESEND_URL = "/api/auth/resend-verification";

function unverifiedBody(what) {
  return { error: MESSAGE, reason: "email_unverified", blocked: what || null, resend_url: RESEND_URL, resend_method: "POST" };
}
function recipientUnverifiedBody(what) {
  return { error: RECIPIENT_MESSAGE, reason: "recipient_email_unverified", blocked: what || null };
}

/* The user row as requireAuth holds it (email_verified_at selected). */
function isVerified(user) {
  return !!(user && user.email_verified_at);
}

/* Read fresh from users, for a user id the caller does not hold a row for. A
   read error throws (the caller refuses); a missing row is not verified. */
async function verifiedById(sb, userId) {
  if (!userId) return false;
  const r = await sb.from("users").select("id, email_verified_at").eq("id", userId).maybeSingle();
  if (r.error) throw r.error;
  return !!(r.data && r.data.id === userId && r.data.email_verified_at);
}

module.exports = { REQUIRED_FOR, MESSAGE, RECIPIENT_MESSAGE, RESEND_URL, unverifiedBody, recipientUnverifiedBody, isVerified, verifiedById };
