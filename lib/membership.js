"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   lib/membership.js — free accounts and the one membership (P3-1, Nov 20 2026).

   THE OWNER'S DECISIONS, IN ONE PLACE. One membership, priced in server.js
   PLAN_CONFIG.all_access (real money only; BizCash never pays for it). A free
   account gets FREE_INCLUDES; membership adds MEMBER_ADDS. These sentences are
   read by:
     - server.js membersPanel(): the body every member-only refusal (402)
       carries, so the app can draw the "Members get this" panel without a
       second copy of the list;
     - lib/legalPages.js: the Terms' free-account paragraph;
     - scripts/checkFreeAccount.js: the route groups behind each line.
   The price is never typed here: the caller passes PLAN_CONFIG's figure.

   STORAGE PER ACCOUNT, across every bucket (lib/storageAccount.js): free
   STORAGE_FREE_BYTES, member STORAGE_MEMBER_BYTES; the owner account is exempt.
   The shared 920 MB guard (lib/storageGuard.js) stays above both.
   ══════════════════════════════════════════════════════════════════════════ */

const MB = 1024 * 1024;
const STORAGE_FREE_BYTES = 50 * MB;
const STORAGE_MEMBER_BYTES = 500 * MB;

/* NAMED (Nov 21 2026, P3-1B, the owner's final rules; they REPLACE P3-1's free list). BEFORE a free account could also
   sell and list in the Market (garage sales and services too), receive tips and donations, and message anyone. AFTER
   selling, every form of BizCash, commenting on a paid member's post and starting a conversation are members only. */
const FREE_INCLUDES = Object.freeze([
  "an account, a profile and @handle (name, photo, bio and banner, inside 50 MB)",
  "posting photos (a share post needs at least one photo) and short video",
  "posting a Need: asking for help, with text and an optional photo",
  "liking, saving, sharing and following, and watching the feed",
  "browsing the Market and viewing listings; buying by card arrives later",
  "commenting on posts by other free accounts",
  "replying in a conversation a member started with you",
  "the safety tools (report, block and mute), Settings, Your data, Billing and the Inbox"
]);

const MEMBER_ADDS = Object.freeze([
  "selling: offer posts, Market listings, garage sales and services, and linking a product or service to a post",
  "BizCash in every form: receiving tips, donations, support and sales, sending it, and the wallet",
  "text-only posts, commenting on members' posts and starting conversations",
  "showing your posts in Google, with your own search title and description",
  "the 18 AI agents and every agent page, HQ and the orbit, and the Oracle",
  "social publishing and auto-posting, store connections and analytics",
  "the business tools: CRM, prospects, ICP, inventory, calendar, BizDoc, BizBook, cover wraps, certifications, Inner IQ and the Guide",
  "music uploads, digital cards and Google Wallet passes, campaigns and media library uploads outside posts"
]);

/* NAMED (Nov 21 2026, P3-1B): the sentences of the rules the server holds inside a free account's own requests. */
const FREE_RULES = Object.freeze({
  share_photo: "A free account's share post needs at least one photo. Text-only posts are for members. Nothing was posted.",
  listing_link: "Linking a product or service to a post is for members. Nothing was posted.",
  comment_member_post: "Comments on members' posts are for members. You can comment on posts by other free accounts. Nothing was posted.",
  start_conversation: "Starting a conversation is for members. You can reply when a member messages you first. Nothing was sent."
});
/* What the payer is told when the account that would receive BizCash is a free account (nothing moves). */
const RECIPIENT_FREE = Object.freeze({
  transfer: "This account is a free account, and free accounts cannot receive BizCash. Nothing was sent.",
  support: "This account is a free account, and free accounts cannot receive support or tips in BizCash. Nothing was sent.",
  donation: "This campaign's owner is a free account, and free accounts cannot receive donations in BizCash. Nothing was sent.",
  purchase: "This listing's seller is a free account, and free accounts cannot receive BizCash for a sale. Nothing was charged."
});
function recipientFreeBody(kind) {
  return { error: RECIPIENT_FREE[kind] || RECIPIENT_FREE.transfer, reason: "recipient_free" };
}

const JOIN_URL = "/billing.html";

/* What a member-only refusal carries. price: PLAN_CONFIG.all_access.price. */
function membersPanel(price, interval) {
  const per = interval || "month";
  return {
    title: "Members get this",
    price_usd: Number(price),
    price_text: "$" + Number(price) + " a " + per,
    adds: MEMBER_ADDS.slice(),
    join_url: JOIN_URL,
    join_label: "Join"
  };
}

/* The panel at the price in code: PLAN_CONFIG.all_access in server.js, read by lib/legalPages.js codeFacts. Cached. */
let fromCode = null;
function membersPanelFromCode() {
  if (!fromCode) { const f = require("./legalPages").codeFacts(); fromCode = { price: f.price, interval: f.interval }; }
  return membersPanel(fromCode.price, fromCode.interval);
}

function storageLimitFor(tier) {
  return tier === "member" ? STORAGE_MEMBER_BYTES : STORAGE_FREE_BYTES;
}

module.exports = {
  FREE_INCLUDES, MEMBER_ADDS, FREE_RULES, RECIPIENT_FREE, recipientFreeBody, JOIN_URL, membersPanel, membersPanelFromCode,
  STORAGE_FREE_BYTES, STORAGE_MEMBER_BYTES, storageLimitFor, MB
};
