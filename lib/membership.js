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

const FREE_INCLUDES = Object.freeze([
  "a profile and @handle",
  "posting to the feed (text and photos)",
  "selling and listing in the Market, including garage sales and services",
  "receiving tips and donations",
  "messaging and following",
  "Settings, Your data and Billing",
  "the safety tools (report, block and mute) and the Inbox"
]);

const MEMBER_ADDS = Object.freeze([
  "the 18 AI agents and every agent page",
  "HQ and the orbit",
  "the Oracle",
  "social publishing and auto-posting",
  "store connections and analytics",
  "sending BizCash: transfers, support and tips, donations and buying in the Market",
  "the business tools: CRM, prospects, ICP, inventory, calendar, BizDoc, BizBook, cover wraps, certifications, Inner IQ and the Guide",
  "music uploads, digital cards and Google Wallet passes",
  "creating campaigns and media library uploads outside posts and listings"
]);

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
  FREE_INCLUDES, MEMBER_ADDS, JOIN_URL, membersPanel, membersPanelFromCode,
  STORAGE_FREE_BYTES, STORAGE_MEMBER_BYTES, storageLimitFor, MB
};
