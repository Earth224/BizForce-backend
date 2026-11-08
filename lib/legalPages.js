/* ══════════════════════════════════════════════════════════════════════════
   lib/legalPages.js — the Terms, Privacy, Refunds and Contact pages, built
   from the code they describe.

   NOTHING STATED HERE IS TYPED HERE. Who runs BizForce, the address, the
   contact address, the law, the age and the refund policy come from
   lib/legal.js. Every figure comes from the code that enforces it:
     the price and plan        server.js PLAN_CONFIG.all_access
     the billing interval      config/brain.js (the "/month" the agents state)
     the past-due grace        server.js PAST_DUE_GRACE_DEFAULT_DAYS
     the welcome bonus         server.js WELCOME_BONUS_BFC
     the certification credit  server.js, the creditWallet call on a new certification
     the number of certifications  lib/certificationCatalog.js
     the transfer limits       lib/bfcTransferLimits.js defaults
     the YouTube retention     lib/youtubeRetention.js YOUTUBE_RETENTION_DAYS
     what is collected, where it goes and how it is protected
                               lib/yourData.js, the source of the Your data page
     the music limits and link life  lib/music.js
   codeFacts() reads them; buildLegalPages(facts) writes the four pages from
   them and nothing else. scripts/buildLegalPages.js writes the pages into the
   frontend; scripts/checkLegalPages.js fails when a page there differs from
   what this builds, or when a figure stops following its source.

   THE TRANSFER LIMITS ARE THE DEFAULTS. BFC_TRANSFER_MAX,
   BFC_TRANSFER_DAILY_CAP and BFC_TRANSFER_HOLD_DAYS can be set on the server;
   if one is, set the same figure here (rebuild) or the Terms will be wrong.
   ══════════════════════════════════════════════════════════════════════════ */

/* THE SCROLLBARS: BizForce's one scrollbar rule (lib/scrollbars.js), so a legal page scrolls in BizForce's look. */
const { SCROLLBARS } = require("./scrollbars");
const fs = require("fs");
const path = require("path");
const legal = require("./legal");

const REPO = path.join(__dirname, "..");
const esc = legal.escapeHtml;

/* What Termaximus's Guide mode sends (lib/guideAsk.js says the same, and
   refuses anything else); scripts/checkGuideAsk.js holds the two to each other. */
/* Member support, in the Terms (section 8) and the Privacy Policy (section 3).
   scripts/checkMemberSupport.js holds the routes and pages to these words. */
const MEMBER_SUPPORT_TERMS = [
  "Members can support each other in two ways: with BizCash, and through support links to a member's own payment pages.",
  "BizCash support is a BizCash transfer sent as support. It follows every BizCash rule and limit above: the per-transfer maximum, the 24-hour total shared with transfers and donations, and the wait for a new account. Like all BizCash, it has no cash value.",
  "A support link goes straight to the provider (PayPal, Cash App, Venmo, Ko-fi, Buy Me a Coffee, Patreon or Stripe). BizForce is not a party to a payment made there: it does not handle, hold or refund the money and cannot reverse it. Ask the provider or the member.",
  "List only your own payment pages, and do not use support to get around the BizCash limits or these Terms.",
  "If you receive support, in BizCash or through a link, you are responsible for your own taxes on it."
];
const SUPPORT_PRIVACY_SENTENCE =
  "If you turn your support page on or add support links, your display name, photo, headline and support links are public on your support page, and the links also on your profile, storefront and card; a note you add to BizCash support is seen only by you and the member you support.";

/* Campaign sharing (Nov 4 2026), in the Privacy Policy (section 3) and the
   Terms (section 8). scripts/checkCampaignSharing.js holds the routes and
   pages to these words. */
const CAMPAIGN_PRIVACY_SENTENCE =
  "Signed-in members can see your active crowdfunding campaigns: the title, description, photos, category, goal and amount raised. If you turn sharing on for a campaign, anyone with its link can see those and your display name and photo, and if you also let search engines find it, they may list it; who donated is never shown. You can turn sharing off or make a new link at any time, and the old link then stops working.";
const CAMPAIGN_TERMS_SENTENCE =
  "If you run or share a campaign, describe it truthfully and use what you raise for the purpose you describe.";
/* The Media Library (build list item 4, migration 167, Nov 4 2026): what is
   kept, who can open it, what is removed from photos, and the in-use rule, in
   the Privacy Policy next to the campaign sentence; the right to use what is
   uploaded, in the Terms after it. scripts/checkMediaLibrary.js holds the
   pages to these words. */
const MEDIA_PRIVACY_SENTENCE =
  "Files you add to your Media Library are stored so you can reuse them, and anyone who has a file's link can open it. BizForce removes location and camera details from JPEG, PNG and WebP photos before saving them, but not from videos or GIFs. A file that is still in use cannot be deleted until you remove it from where it is used, and your files are deleted with your account.";
const MEDIA_TERMS_SENTENCE =
  "Upload only photos and videos you have the right to use and share.";
/* Card visits (C1, migration 171, Nov 6 2026): the daily counts a card keeps
   and the search switch, in the Privacy Policy (section 3) directly after
   MEDIA_PRIVACY_SENTENCE. scripts/checkCardUpgrades.js holds the routes and
   pages to these words. */
const CARD_VISITS_PRIVACY_SENTENCE =
  "When someone opens your digital card or taps its buttons, BizForce adds to a daily count for that card that only you can see; it records nothing about the visitor, no address, device or cookie, and the counts are deleted with the card. If you let search engines find a card, they may list it.";
/* Google Wallet (Nov 6 2026, lib/googleWallet.js): in the Privacy Policy
   (section 3) directly after CARD_VISITS_PRIVACY_SENTENCE. The pass is made
   from the card's public fields only, and only when a visitor chooses it.
   scripts/checkGoogleWallet.js holds the route and the page to these words. */
const CARD_WALLET_PRIVACY_SENTENCE =
  "If a visitor chooses Add to Google Wallet on your card, BizForce sends Google the details your card shows publicly (your name, title, company, the email, phone and photo you chose to show, and the card's link) to make the pass; nothing goes to Google before they choose, and a saved pass stays in their Google Wallet under Google's terms, where BizForce cannot change it.";
/* Card leads (C2, migration 172, Nov 6 2026): the lead form, in the Privacy
   Policy (section 3) directly after CARD_VISITS_PRIVACY_SENTENCE, and in the
   Terms (section 8) directly after MEDIA_TERMS_SENTENCE.
   scripts/checkCardLeads.js holds the routes and pages to these words. */
const CARD_LEADS_PRIVACY_SENTENCE =
  "If you turn on the lead form on a card, visitors can leave their name, an email or phone number and a message for you; BizForce stores what they send and the consent sentence they agreed to, records nothing about their device, and deletes each lead after 12 months, when you delete it, or with the card or your account.";
const CARD_LEADS_TERMS_SENTENCE =
  "If you collect leads with your card, contact people only about what they asked, and delete their details if they ask you to.";
/* The member's part of an approved store change (migration 175, lib/storeWrite.js), in the Terms.
   scripts/checkStoreChanges.js holds the code to these words. */
const STORE_TERMS_SENTENCE =
  "If you let BizForce change your store, you are responsible for the prices and stock levels you approve.";

/* The learning loop, in the Privacy Policy (section 2). scripts/checkLearningLoop.js
   holds the export, the delete and the agent page to these words. */
const LEARNING_PRIVACY_SENTENCE =
  "When you rate an agent's result, pin one as an example or give an agent a preference, BizForce stores it and uses it only " +
  "in that agent's prompts for you, below every rule, so the agent writes the way you asked; the AI model itself does not change. " +
  "Your ratings, examples and preferences are private to you, are in your data download, and are deleted with your account.";

/* A member's own Bluesky account, in the Privacy Policy (section 2) and the
   Terms (section 7). scripts/checkBlueskyConnect.js holds the routes, the
   export and the delete to these words. */
const BLUESKY_PRIVACY_SENTENCE =
  "If you connect your Bluesky account, BizForce stores your Bluesky handle, its account id (DID) and the app password you made for BizForce, " +
  "encrypted; it is used only to post or update your Bluesky profile when you approve a proposal, or when your own \"Post approved drafts automatically\" " +
  "setting is on, and to read the posts that mention you, reply to you or quote you when you open your Mentions inbox. It is never shown back to you " +
  "or exported (your data download says only which handle you connected and when), you can disconnect at any time, and it is deleted with your account.";
/* The Mentions inbox (migration 164), directly after it in section 2.
   scripts/checkBlueskyMentions.js holds the routes and the model message to
   these words, field by field. */
const BLUESKY_MENTIONS_PRIVACY_SENTENCE =
  "Your Mentions inbox is read from Bluesky each time you ask and is not stored. If you ask for a reply to be drafted, BizForce sends the AI model " +
  "(Anthropic) only that post's text, and the text of your own post it answers if there is one, with your business details and guidance, never the " +
  "author's name, handle or account id; BizForce keeps the draft and the address of the post it answers with your other drafts, and a reply is posted " +
  "only when you approve it.";
/* A member's own Shopify or WooCommerce store (migration 163, lib/storeSync.js),
   the approved price and stock changes (migration 175, lib/storeWrite.js),
   and Shopify connected on OAuth with its uninstall webhook (migration 176,
   lib/shopifyAuth.js, lib/shopifyApi.js), in the Privacy Policy (section 2).
   scripts/checkStoreConnections.js, scripts/checkStoreChanges.js and
   scripts/checkShopifyConnect.js hold the code to these words. */
const STORE_PRIVACY_SENTENCE =
  "If you connect a Shopify or WooCommerce store, BizForce stores the store's address and the access it is given, encrypted (for WooCommerce, " +
  "the key you made for it; for Shopify, the access you approve when you connect), and reads from the store only your products (name, SKU, price, " +
  "cost where the store has one), your stock levels, your store's currency and location names, and summaries of your orders (each order's number, " +
  "date, total, currency, and its items as SKU and quantity), never any customer's name, email, address or phone number; BizForce changes a " +
  "product's price or stock level in your store only when you approve that change, and only if you allowed changes when you connected the store, " +
  "and it keeps a record of each change (the item, the old and new value, and when). What it reads is used only for your own agents, the store's " +
  "key or access is never shown back to you or exported, and it, the products, the stock, the order summaries and the record of changes are " +
  "deleted when you disconnect the store, uninstall BizForce from Shopify, or delete your account.";
const BLUESKY_TERMS_SENTENCE =
  "If you connect your own Bluesky account, you are responsible for everything posted from it. BizForce posts to it only when you approve a " +
  "proposal, or when you have turned on \"Post approved drafts automatically\"; a profile change and a reply always wait for your approval.";
/* A member's own Mastodon account (migration 165, lib/memberMastodon.js): in
   the Privacy Policy directly after the Bluesky sentences (section 2), and in
   the Terms after the Bluesky one (section 7). scripts/checkMastodonConnect.js
   holds both to these words. */
const MASTODON_PRIVACY_SENTENCE =
  "If you connect your Mastodon account, BizForce stores your server's address, your account name and id, your server's post length limit, " +
  "and the access token you made for BizForce, encrypted; the token is used only to post to your account when you approve a proposal, or when " +
  "your own \"Post approved drafts automatically\" setting for Mastodon is on, and your posts go to the server you chose, under its rules. The " +
  "token is never shown back to you or exported (your data download says only which account and server you connected and when); you can " +
  "disconnect at any time, you can also cancel the token in your Mastodon settings, and it is deleted with your account.";
/* Images from the Media Library in a Bluesky or Mastodon post (migration 168):
   in the Privacy Policy directly after the Mastodon sentence (section 2).
   scripts/checkSocialImages.js holds it to these words. */
const SOCIAL_MEDIA_PRIVACY_SENTENCE =
  "When you attach images from your Media Library to a Bluesky or Mastodon post, copies of the images and their alt text are sent to that " +
  "service with the post, and they stay there under its rules even if you later delete them here.";
/* YouTube uploads (migration 177, lib/youtubeApi.js): in the Privacy Policy directly after the social images
   sentence (section 2), and in the Terms directly after the mailbox reply one (section 7).
   scripts/checkYoutubeUploads.js holds both to these words. */
const YOUTUBE_PRIVACY_SENTENCE =
  "If you connect your YouTube channel, BizForce stores your channel's name and id and the access Google grants BizForce, encrypted, and uses " +
  "that access only to upload or remove a video when you approve it and to check a video's status when you ask. Videos you add for YouTube " +
  "are kept privately, sent only to YouTube with the title, description and tags you approve, and deleted once every platform you sent " +
  "them to has them, or 14 days after you added them. You can disconnect at any time, which also asks Google to cancel BizForce's access, and " +
  "everything is deleted with your account.";
const YOUTUBE_TERMS_SENTENCE =
  "If you upload videos through BizForce, you confirm you have the rights to them and that they follow YouTube's rules.";
/* TikTok posting (migration 178, lib/tiktokApi.js): in the Privacy Policy directly after the YouTube sentence
   (section 2), and in the Terms directly after the YouTube one (section 7).
   scripts/checkTiktokPosting.js holds both to these words. */
const TIKTOK_PRIVACY_SENTENCE =
  "If you connect your TikTok account, BizForce stores your TikTok name and account id and the access TikTok grants BizForce, encrypted, " +
  "and uses that access only to post a video when you approve it and to check its status when you ask. Videos you send to TikTok go only " +
  "to TikTok with the caption and settings you approve; BizForce cannot delete a TikTok post, so you delete it in TikTok. You can disconnect " +
  "at any time, which also asks TikTok to cancel BizForce's access, and everything is deleted with your account.";
const TIKTOK_TERMS_SENTENCE =
  "If you post to TikTok through BizForce, you confirm you have the rights to the video and its music and that it follows TikTok's rules.";
const MASTODON_TERMS_SENTENCE =
  "If you connect your own Mastodon account, you are responsible for everything posted from it and for following your server's rules. " +
  "BizForce posts to it only when you approve a proposal, or when you have turned on \"Post approved drafts automatically\" for Mastodon.";
/* A member's own mailbox, read only (migration 169, lib/memberEmail.js): in the Privacy Policy directly after the
   social images sentence (section 2), and in the Terms after the Mastodon one (section 7).
   scripts/checkMailboxConnect.js holds both to these words.
   NAMED (Nov 6 2026, Outlook sign-in, migration 173): the privacy sentence also names the access Sign in with
   Microsoft grants, and removing BizForce from the Microsoft account; checkMailboxOutlook holds those words. */
const MAILBOX_PRIVACY_SENTENCE =
  "If you connect your mailbox, BizForce stores your email address, your mail server names and the app password you made for BizForce " +
  "or, if you sign in with Microsoft, the access Microsoft grants BizForce, encrypted; it is used only to check the connection, to read your inbox when you open it in BizForce, and to send the replies you approve. Your messages are read each " +
  "time you ask and are not stored, BizForce never marks them read or changes anything in your mailbox, and attachments are listed but " +
  "not downloaded. You can disconnect at any time, you can also cancel the app password with your email provider or remove BizForce from your Microsoft account, and it is deleted with " +
  "your account.";
/* Replies from that mailbox (migration 170, Email connection Build B): the privacy sentence directly after
   MAILBOX_PRIVACY_SENTENCE, the terms sentence directly after MAILBOX_TERMS_SENTENCE. scripts/checkMailboxReply.js
   holds both to these words. */
const MAILBOX_REPLY_PRIVACY_SENTENCE =
  "If you ask for a reply to be drafted, BizForce sends the AI model (Anthropic) only that message's subject and text, with your " +
  "business details and guidance, never the sender's name or address. When you file a reply, BizForce keeps the reply, the address " +
  "it goes to and the message it answers with your other drafts until your account is deleted, and sends it from your own address " +
  "only after you approve it.";
const MAILBOX_TERMS_SENTENCE =
  "If you connect a mailbox, you confirm it is yours or that you are allowed to connect it.";
const MAILBOX_REPLY_TERMS_SENTENCE =
  "Replies you send through BizForce are your own messages; do not use them to send marketing to people who have not agreed to receive it.";

/* A member's own music library, in the Terms (section 7) and the Privacy
   Policy (section 2). The figures are lib/music.js's; scripts/checkMusicPlayer.js
   holds the routes, the export and the delete to these words. */
function musicTerms() {
  const music = require("./music");
  return [
    "You may upload only music you have the right to use: music you made, or music whose rights holders allow you to copy and play it this way. Uploading music you do not have the rights to breaks these Terms.",
    "Your uploads are private to you: no other member and no visitor can see, list or play them. Each file is played back only to you, through a link that expires after " + Math.round(music.SIGNED_URL_SECONDS / 60) + " minutes.",
    "Each file may be at most " + music.mb(music.FILE_MAX_BYTES) + ", and your library at most " + music.mb(music.MEMBER_TOTAL_BYTES) + " in all, in MP3, M4A, AAC, Ogg, Opus, FLAC or WAV.",
    "If a file is reported to us as infringing someone's rights, BizForce may remove it. To report one, write to the address in section 16."
  ];
}
function musicPrivacySentence() {
  const music = require("./music");
  return "If you upload music, BizForce stores each file privately, with its title, artist, length, file type and size and when you added it, and your playlists; " +
    "a file is played back only to you, through a link that expires after " + Math.round(music.SIGNED_URL_SECONDS / 60) + " minutes, and no other member can see your library. " +
    "Your data download lists your tracks and playlists (not the audio files), and the files and their records are deleted with your account. " +
    "The player remembers your track, position, volume and queue in this browser, and signing out clears that.";
}

const GUIDE_PRIVACY_SENTENCE =
  "When you ask Termaximus's Guide, it sends your question with only the page you are on, which panels and tab are open, " +
  "whether an empty list or an error banner is showing, and the last 5 pages you visited; nothing typed into the page is sent, " +
  "and that list of pages stays only in this browser tab.";

/* What a typed question under "Ask about your records" sends (lib/termaximusRecords.js
   offeredSubjects and recordsUserMessage): the question, the time, and for each
   offered record only { id, kind, agent, at }. scripts/checkTermaximusRecords.js
   holds these words to that code. */
const RECORDS_PRIVACY_SENTENCE =
  "When you type a question under \"Ask about your records\", BizForce sends the AI model (Anthropic) only your question, the current time, " +
  "and for each of your own decisions and agent runs from the last 7 days, your triggers and the agent network's declared links, just its id, kind, agent and time, never its content; " +
  "that is at most one model call per question, counted within Guide mode's daily allowance, and the buttons that ask about a record send nothing to the model.";

function grab(src, re, what) {
  const m = re.exec(src);
  if (!m) throw new Error("legalPages: " + what + " was not found in the code; the pages cannot be built without it");
  return m;
}

/* Every figure the pages state, read from the code. */
function codeFacts(sources) {
  sources = sources || {};
  const server = sources.server != null ? sources.server : fs.readFileSync(path.join(REPO, "server.js"), "utf8");
  const brain = sources.brain != null ? sources.brain : fs.readFileSync(path.join(REPO, "config", "brain.js"), "utf8");
  const plan = grab(server, /const PLAN_CONFIG = \{\s*all_access: \{\s*name: "([^"]+)",\s*price: (\d+(?:\.\d+)?),/, "PLAN_CONFIG.all_access");
  const interval = grab(brain, /\n\s*"\/(month|year), single \\"" \+ plan\.name/, "the billing interval");
  const yourData = require("./yourData");
  const limits = require("./bfcTransferLimits");
  return {
    planName: plan[1],
    price: Number(plan[2]),
    interval: interval[1],
    pastDueGraceDays: Number(grab(server, /\nconst PAST_DUE_GRACE_DEFAULT_DAYS = (\d+);/, "PAST_DUE_GRACE_DEFAULT_DAYS")[1]),
    welcomeBonus: Number(grab(server, /\nconst WELCOME_BONUS_BFC = (\d+);/, "WELCOME_BONUS_BFC")[1]),
    certificationCredit: Number(grab(server, /await creditWallet\(req\.user\.id, (\d+), "Certification earned: " \+ certId\);/, "the certification credit")[1]),
    certifications: require("./certificationCatalog").CERTIFICATIONS.length,
    transferMax: limits.BFC_TRANSFER_MAX_DEFAULT,
    transferDailyCap: limits.BFC_TRANSFER_DAILY_CAP_DEFAULT,
    transferHoldDays: limits.BFC_TRANSFER_HOLD_DAYS_DEFAULT,
    youtubeRetentionDays: require("./youtubeRetention").YOUTUBE_RETENTION_DAYS,
    // BizForce Market is priced in BizCash only: the refusal every listing write gives a USD price.
    marketBfcOnly: grab(server, /\nconst LISTING_BFC_ONLY_MESSAGE = "([^"]+)";/, "LISTING_BFC_ONLY_MESSAGE")[1] === "Listings are priced in BizCash only.",
    yourData: {
      described: yourData.describe(),
      thirdParties: yourData.THIRD_PARTIES.map(function (s) { return { name: s.name, for: s.for }; }),
      pageServices: yourData.PAGE_SERVICES.map(function (s) { return { name: s.name, for: s.for, hosts: s.hosts.slice() }; }),
      protections: yourData.PROTECTIONS.map(function (p) { return { key: p.key, text: p.text }; }),
      forfeit: yourData.FORFEIT_DESCRIPTION
    }
  };
}

/* ── formatting ─────────────────────────────────────────────────────────── */
function num(n) { return Number(n).toLocaleString("en-US"); }
function money(n) { return "$" + (Number.isInteger(n) ? String(n) : Number(n).toFixed(2)); }
function bfc(n) { return num(n) + " BFC"; }
function days(n) { return n + (n === 1 ? " day" : " days"); }
// "A" or "An", by the word that follows: "An All Access subscription".
function article(word) { return /^[aeiou]/i.test(String(word)) ? "An" : "A"; }
function p(text) { return "<p>" + esc(text) + "</p>"; }
function ul(items) { return "<ul>" + items.map(function (t) { return "<li>" + esc(t) + "</li>"; }).join("") + "</ul>"; }
function h2(id, text) { return '<h2 id="' + id + '">' + esc(text) + "</h2>"; }
function link(href, text) { return '<a href="' + esc(href) + '">' + esc(text) + "</a>"; }
function mail() { return '<a href="mailto:' + esc(legal.CONTACT_EMAIL) + '">' + esc(legal.CONTACT_EMAIL) + "</a>"; }
function address() { return '<p class="address">' + legal.ADDRESS_LINES.map(esc).join("<br>") + "</p>"; }

const BFC_NOTICE_TAGS = '<p class="bfc-notice" data-bfc-notice></p>\n<script src="/scripts/bf-bfc-notice.js"></script>';
const FOOTER_TAGS = '<footer class="bf-legal-footer" data-bf-legal-footer></footer>\n<script src="/scripts/bf-legal-footer.js"></script>';

function page(o) {
  return [
    "<!DOCTYPE html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="UTF-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">',
    // SEO basics (launch item #12): a 50–60 character title, a 140–160 character description, the canonical
    // address Netlify serves the page at (the one sitemap-pages.xml lists), and Open Graph tags.
    "<title>" + esc(o.headTitle) + "</title>",
    '<meta name="description" content="' + esc(o.description) + '">',
    '<link rel="canonical" href="https://bizforceai.net' + esc(o.path) + '">',
    '<meta property="og:type" content="article">',
    '<meta property="og:site_name" content="BizForce AI">',
    '<meta property="og:title" content="' + esc(o.headTitle) + '">',
    '<meta property="og:description" content="' + esc(o.description) + '">',
    '<meta property="og:url" content="https://bizforceai.net' + esc(o.path) + '">',
    '<meta name="theme-color" content="#070b18">',
    '<link rel="icon" type="image/png" sizes="32x32" href="/icons/favicon-32.png">',
    "<!--",
    "  BUILT, NOT WRITTEN. This page is generated by the backend's",
    "  scripts/buildLegalPages.js from lib/legal.js and the code it describes",
    "  (lib/legalPages.js names each source). Do not edit it here: change the",
    "  backend and rebuild. scripts/checkLegalPages.js fails when this file",
    "  differs from what the backend builds.",
    "-->",
    "<style>",
    "  *, *::before, *::after { box-sizing: border-box; }",
    "  html, body { margin: 0; min-height: 100%; font-family: system-ui, -apple-system, \"Segoe UI\", Arial, sans-serif; color: #e8e8ff; background: #070b18; }",
    "  body { -webkit-text-size-adjust: 100%; }",
    "  .page { max-width: 860px; margin: 0 auto; padding: 28px 16px 40px; }",
    "  a { color: #22d3ee; }",
    "  .back { display: inline-block; margin-bottom: 18px; font-weight: 600; text-decoration: none; }",
    "  h1 { font-size: 2rem; margin: 0 0 8px; }",
    "  h2 { font-size: 1.3rem; margin: 36px 0 10px; color: #fff; }",
    "  p, li { line-height: 1.65; color: #c3c9e6; }",
    "  .updated { color: #8e98c2; font-size: .92rem; margin: 0 0 20px; }",
    "  .lede { font-size: 1.05rem; color: #aab3d8; }",
    "  .card { background: rgba(255,255,255,.04); border: 1px solid rgba(0,229,255,.14); border-radius: 14px; padding: 16px 20px; margin: 14px 0; }",
    "  .renewal { border: 2px solid #22d3ee; background: rgba(34,211,238,.08); }",
    "  .renewal p { color: #e8e8ff; font-size: 1.02rem; }",
    "  .address { margin: 8px 0; color: #e8e8ff; }",
    "  .toc { columns: 2; column-gap: 28px; padding-left: 18px; }",
    "  @media (max-width: 560px) { .toc { columns: 1; } }",
    "</style>",
    '<style id="bf-scrollbars">',
    SCROLLBARS,
    "</style>",
    "</head>",
    "<body>",
    '<div class="page">',
    '  <a class="back" href="/">&larr; BizForce AI</a>',
    "  <h1>" + esc(o.title) + "</h1>",
    '  <p class="updated">' + esc(legal.TERMS_UPDATED) + " &middot; Version " + esc(legal.TERMS_VERSION) + "</p>",
    o.body.filter(Boolean).map(function (line) { return "  " + line; }).join("\n"),
    "</div>",
    FOOTER_TAGS,
    "</body>",
    "</html>",
    ""
  ].join("\n");
}

/* ── the Terms of Service ───────────────────────────────────────────────── */
function terms(f) {
  const per = f.interval;
  const priceLine = money(f.price) + " per " + per;
  const body = [
    '<p class="lede">These Terms are the agreement between you and ' + esc(legal.OPERATOR) + " for using BizForce AI. Please read them; by creating an account you agree to them and to the " + link(legal.PAGES.privacy, "Privacy Policy") + ".</p>",
    '<ol class="toc"><li><a href="#who">Who we are</a></li><li><a href="#eligibility">Who can use BizForce</a></li><li><a href="#subscription">The subscription and automatic renewal</a></li><li><a href="#refunds">Refunds</a></li><li><a href="#use">Acceptable use</a></li><li><a href="#ai">AI output</a></li><li><a href="#content">Your content</a></li><li><a href="#bizcash">BizForce Market and the BizCash Member Trade Agreement</a></li><li><a href="#termination">Suspension and termination</a></li><li><a href="#data">Your data and deleting your account</a></li><li><a href="#disclaimers">Disclaimers</a></li><li><a href="#liability">Limitation of liability</a></li><li><a href="#indemnity">Indemnity</a></li><li><a href="#disputes">Disputes and governing law</a></li><li><a href="#changes">Changes to these Terms</a></li><li><a href="#contact">Contact</a></li></ol>',

    h2("who", "1. Who we are"),
    p(legal.OPERATOR + " (" + legal.OPERATOR_NOTE + "; \"BizForce\", \"we\", \"us\") runs BizForce AI at bizforceai.net. Our mailing address is:"),
    address(),
    "<p>You can reach us at " + mail() + ".</p>",

    h2("eligibility", "2. Who can use BizForce"),
    ul([
      "You must be " + legal.MINIMUM_AGE + " or older. Nobody under " + legal.MINIMUM_AGE + " may create an account.",
      "One account per person. Do not create accounts for someone else without their permission, or more than one account for yourself.",
      "Give accurate details when you sign up, and keep your password to yourself. You are responsible for what happens under your account.",
      "If you use BizForce for a business, you confirm you are allowed to accept these Terms for it."
    ]),

    h2("subscription", "3. The subscription and automatic renewal"),
    '<div class="card renewal">',
    "<p><strong>" + esc(f.planName + " costs " + priceLine + ". Your subscription renews automatically every " + per + ", and your card is charged " + money(f.price) + " at the start of each new " + per + ", until you cancel.") + "</strong></p>",
    "<p><strong>" + esc("You can cancel online at any time: sign in, open Billing, and choose \"Manage / Cancel Subscription\". Cancelling stops the next renewal. You keep access until the end of the " + per + " you have already paid for, and you are not charged again.") + "</strong></p>",
    // Worded apart from lib/legal.js REFUND_POLICY, which section 4 lists, so
    // the page does not say the same sentence twice.
    "<p><strong>" + esc("No partial or prorated refunds, as section 4 sets out.") + "</strong> " + link(legal.PAGES.refund, "Refund policy") + "</p>",
    "</div>",
    ul([
      "Prices are in US dollars. Payment is handled by Stripe; BizForce never sees or stores your card number.",
      "A promotion code entered at checkout can lower the price, as shown at checkout before you pay.",
      "If a renewal payment fails, Stripe tries your card again. You keep access for up to " + days(f.pastDueGraceDays) + " from the day the payment was due while it does. If the payment still has not gone through after " + days(f.pastDueGraceDays) + ", access pauses until you update your card on Billing. Your data stays yours and you can still download it, see Billing and cancel.",
      "If we change the price, we will tell you before the new price applies to your subscription, and you can cancel before then."
    ]),

    h2("refunds", "4. Refunds"),
    ul(legal.REFUND_POLICY),
    "<p>The full policy, with how to cancel, is on the " + link(legal.PAGES.refund, "Refunds page") + ". If the law where you live gives you a right to a refund, nothing here takes it away.</p>",

    h2("use", "5. Acceptable use"),
    p("Use BizForce only for lawful purposes. You may not use it to:"),
    ul([
      "publish, send or store anything unlawful, defamatory, harassing, hateful or sexually exploitative, or that infringes someone else's rights;",
      "say or imply that a product diagnoses, treats, cures, prevents or reverses any disease, or name a medical condition as something a product is for. BizForce's agents refuse these claims, and you may not try to get around that;",
      "make false or misleading claims about products, prices, results or endorsements;",
      "send email or text messages to people who have not agreed to receive them, or keep sending after someone asks you to stop;",
      "pretend to be someone else, or misrepresent your connection to a person or business;",
      "upload malware, probe or break BizForce's security, or get around its limits;",
      "copy, scrape or resell the service, or use it to build a competing one;",
      "use BizCash, the marketplace or trades for fraud, money laundering or anything else unlawful."
    ]),
    p("We may remove content that breaks these rules."),

    h2("ai", "6. AI output"),
    ul([
      "BizForce's agents generate text and plans with artificial intelligence. AI output can be wrong, out of date or incomplete.",
      "Review everything before you use it, publish it or send it. You are responsible for what you choose to use.",
      "Nothing BizForce produces is legal, medical, tax or financial advice. Ask a qualified professional for that.",
      "The compliance and claims tools flag risks they can recognise. A clean result is not approval by any regulator, advertising platform or marketplace, and does not mean content is lawful."
    ]),

    h2("content", "7. Your content"),
    ul([
      "You own what you put into BizForce: your business details, files, listings, messages and the work you ask the agents for.",
      "You give BizForce only the permission it needs to run the service for you: to store your content, process it (including sending it to our AI provider to produce what you asked for), and show it where you choose to publish it, such as your public profile, storefront, listings or blog.",
      "That permission ends when you delete the content or your account, except for records other members rely on, as the " + "Your data page lists.",
      "You confirm you have the rights to what you upload.",
      BLUESKY_TERMS_SENTENCE,
      MASTODON_TERMS_SENTENCE,
      MAILBOX_TERMS_SENTENCE,
      MAILBOX_REPLY_TERMS_SENTENCE,
      YOUTUBE_TERMS_SENTENCE,
      TIKTOK_TERMS_SENTENCE
    ]),
    '<h3 id="music">Your music</h3>',
    ul(musicTerms()),

    h2("bizcash", "8. BizForce Market and the BizCash Member Trade Agreement"),
    p("BizForce Market lets members trade with each other: buying and selling listings, sending BizCash, and donating to campaigns. These rules apply to every trade."),
    p(CAMPAIGN_TERMS_SENTENCE),
    p(MEDIA_TERMS_SENTENCE),
    p(CARD_LEADS_TERMS_SENTENCE),
    p(STORE_TERMS_SENTENCE),
    f.marketBfcOnly ? p("BizForce Market trades are in BizCash only. Every listing is priced and bought in BFC, and BizForce processes no member-to-member payments in US dollars.") : "",
    ul([
      "BizCash (BFC) is a closed-loop, in-app trade credit for member trades on BizForceAI.",
      "BFC has no cash value. It cannot be bought, sold, exchanged or withdrawn for money, and it is not a currency, a deposit or an investment. It earns no interest.",
      "BizForce issues BFC in two ways today: a one-time welcome bonus of " + bfc(f.welcomeBonus) + " when an account's subscription first becomes active (once per account), and " + bfc(f.certificationCredit) + " for each certification earned while the account has an active subscription (once per certification; there are " + f.certifications + "). Using the platform earns nothing else.",
      "Sending BFC to another member: one transfer can move at most " + bfc(f.transferMax) + "; an account can send at most " + bfc(f.transferDailyCap) + " in any rolling 24 hours; and a new account cannot send BFC until " + days(f.transferHoldDays) + " after it was created. You send by username, after confirming the member it finds. Marketplace purchases and campaign donations are priced by the listing or chosen by the donor and are not subject to these transfer limits.",
      "Trades are between members. BizForce records every trade (see Trades on your Wallet: a list, a CSV download and a yearly statement) but is not a party to the goods or services traded and does not guarantee them. Settle any disagreement about a trade with the other member.",
      "Bartered goods and services can count as income for tax purposes. Ask a tax professional how this applies to you.",
      "BizForce may change the BFC rules, amounts, limits or availability, or end BFC, with notice under section 15.",
      "If you delete your account, your BFC balance is forfeited and recorded in the ledger as \"" + f.yourData.forfeit + "\". It has no cash value, so nothing is paid out. A listing another member bought stays available to them."
    ]),
    BFC_NOTICE_TAGS,
    '<h3 id="support">Member support</h3>',
    ul(MEMBER_SUPPORT_TERMS),

    h2("termination", "9. Suspension and termination"),
    ul([
      "We may suspend or close an account that breaks these Terms, puts other members or BizForce at risk, or is used unlawfully. Where we can, we will tell you why.",
      "You can stop using BizForce at any time. To close your account, cancel any subscription on Billing, then delete the account on the " + "Your data page.",
      "Sections 6, 7, 8 (on trades already made), 11, 12, 13 and 14 continue after an account ends."
    ]),

    h2("data", "10. Your data and deleting your account"),
    "<p>The " + link(legal.PAGES.privacy, "Privacy Policy") + " explains what we collect and why. On the " + link(legal.PAGES.yourData, "Your data") + " page you can see what is stored, download all of it, and delete your account.</p>",

    h2("disclaimers", "11. Disclaimers"),
    p("BizForce is provided \"as is\" and \"as available\". To the fullest extent the law allows, we make no warranties, express or implied, including that the service will be uninterrupted or error-free, that AI output will be accurate, or that using BizForce will bring any particular business result."),

    h2("liability", "12. Limitation of liability"),
    p("To the fullest extent the law allows, BizForce is not liable for indirect, incidental, special, consequential or punitive damages, or for lost profits, revenue or data. Our total liability for any claim about BizForce is limited to the amount you paid us in the 12 months before the claim. Some places do not allow these limits, so they may not all apply to you."),

    h2("indemnity", "13. Indemnity"),
    p("You agree to defend and compensate BizForce for claims, losses and costs (including reasonable legal fees) that come from your content, your trades with other members, or your breaking these Terms or the law."),

    h2("disputes", "14. Disputes and governing law"),
    p("These Terms are governed by the laws of the State of " + legal.GOVERNING_STATE + ", USA, without regard to its conflict-of-laws rules. If you have a problem, write to us first and give us 30 days to try to put it right. Any dispute that remains will be decided by the state or federal courts located in " + legal.GOVERNING_STATE + ", and you and BizForce agree to their jurisdiction. Nothing here limits rights you have under the consumer laws where you live."),

    h2("changes", "15. Changes to these Terms"),
    p("We may update these Terms. The date at the top shows the version in force. When we update them, signed-in members see a notice, \"We've updated our Terms\", with a link to the new version and a button to accept it; the notice never blocks your data or Billing. If you do not agree to the new Terms, you can cancel and delete your account; changes do not apply to a " + per + " you have already paid for."),

    h2("contact", "16. Contact"),
    "<p>Write to " + mail() + ", or by post to:</p>",
    address(),
    "<p>More on the " + link(legal.PAGES.contact, "Contact page") + ".</p>"
  ];
  return page({
    title: "Terms of Service",
    headTitle: "Terms of Service — BizForce AI subscription and BizCash",
    path: legal.PAGES.terms,
    description: "BizForce AI terms: the " + money(f.price) + " per " + per + " subscription and its automatic renewal, refunds, acceptable use, AI output, and the BizCash Member Trade Agreement.",
    body: body
  });
}

/* ── the Privacy Policy ─────────────────────────────────────────────────── */
function privacy(f) {
  const yd = f.yourData;
  const protections = yd.protections.filter(function (x) { return x.key !== "no_sale"; });
  const noSale = (yd.protections.find(function (x) { return x.key === "no_sale"; }) || {}).text || "";
  const groups = yd.described.groups.filter(function (g) { return g.items.length; });
  /* What is kept after deletion. Section 1 already lists each item's full
     description, so here each is named by its first phrase, and the closing
     "You are shown as a deleted member." is said once after the list rather
     than on every line. */
  const SHOWN_DELETED = " You are shown as a deleted member.";
  const kept = [];
  let shownDeleted = false;
  groups.forEach(function (g) {
    g.items.forEach(function (it) {
      if (it.onDelete === "delete") return;
      let text = it.onDeleteText;
      if (text.slice(-SHOWN_DELETED.length) === SHOWN_DELETED) { text = text.slice(0, -SHOWN_DELETED.length); shownDeleted = true; }
      kept.push(it.what.split(/[:.]/)[0] + ": " + text);
    });
  });
  const body = [
    '<p class="lede">What BizForce AI collects about you, why, where it goes, how it is protected, and the choices you have. ' + esc(legal.OPERATOR) + " (" + esc(legal.OPERATOR_NOTE) + ") runs BizForce AI and is responsible for your data.</p>",

    h2("collect", "1. What we collect"),
    "<p>This list is drawn from the same description as the " + link(legal.PAGES.yourData, "Your data") + " page, which BizForce's own download and delete run from, so the two cannot differ.</p>",
    groups.map(function (g) {
      return '<div class="card"><p><strong>' + esc(g.title) + "</strong></p>" + ul(g.items.map(function (it) { return it.what; })) + "</div>";
    }).join("\n  "),
    BFC_NOTICE_TAGS,

    h2("use", "2. How we use it"),
    ul([
      "To run the service you ask for: your agents, storefront, listings, wallet and trades, messages, outreach and documents.",
      LEARNING_PRIVACY_SENTENCE,
      BLUESKY_PRIVACY_SENTENCE,
      BLUESKY_MENTIONS_PRIVACY_SENTENCE,
      MASTODON_PRIVACY_SENTENCE,
      SOCIAL_MEDIA_PRIVACY_SENTENCE,
      YOUTUBE_PRIVACY_SENTENCE,
      TIKTOK_PRIVACY_SENTENCE,
      MAILBOX_PRIVACY_SENTENCE,
      MAILBOX_REPLY_PRIVACY_SENTENCE,
      STORE_PRIVACY_SENTENCE,
      musicPrivacySentence(),
      "To bill your subscription, through Stripe.",
      "To email you about your account: confirming your address, resetting your password, and similar messages you need. Marketing email goes only to people who confirmed they want it, and every one has an unsubscribe link.",
      "To keep BizForce safe: rate limits, spotting abuse, and enforcing the Terms.",
      "To keep the records money and trades need, such as the wallet ledger other members' records depend on."
    ]),

    h2("share", "3. Who it goes to"),
    // noSale opens with "We do not sell your data", so the sale is stated once.
    p("We do not share your personal information for advertising."),
    p(noSale),
    p("The services BizForce sends your data to:"),
    ul(yd.thirdParties.map(function (s) { return s.name + ": " + s.for + "."; })),
    p("The services some pages have your browser fetch files from:"),
    ul(yd.pageServices.map(function (s) { return s.name + ": " + s.for + "."; })),
    ul([
      "Other members see what you choose to publish: your public profile, storefront, listings, blog posts and username.",
      SUPPORT_PRIVACY_SENTENCE,
      CAMPAIGN_PRIVACY_SENTENCE,
      MEDIA_PRIVACY_SENTENCE,
      CARD_VISITS_PRIVACY_SENTENCE,
      CARD_WALLET_PRIVACY_SENTENCE,
      CARD_LEADS_PRIVACY_SENTENCE,
      "We disclose data when the law requires it, or to protect members or BizForce from fraud or harm."
    ]),

    h2("protect", "4. How it is protected"),
    p("Exactly as the Your data page states it:"),
    ul(protections.map(function (x) { return x.text; })),

    h2("device", "5. On your device"),
    ul([
      "BizForce keeps your sign-in in your browser's own storage, and sets no cookies of its own. Signing out clears every BizForce key that belongs to you from this browser.",
      "Some preferences stay on the device after sign-out, such as the editor's colours and where panels sit; they hold nothing about your account.",
      GUIDE_PRIVACY_SENTENCE,
      RECORDS_PRIVACY_SENTENCE
    ].concat(yd.described.deviceCopy.lines)),

    h2("retention", "6. How long we keep it, and deleting it"),
    ul([
      "We keep your data while your account exists, so the service can work.",
      "You can download all of it, or delete your account, at any time on the Your data page."
    ].concat(yd.described.deleteNotes)),
    p("Some records are kept after an account is deleted, because other members' records depend on them or the law expects them:"),
    ul(kept),
    shownDeleted ? p("On the records that show who took part, you are shown as a deleted member.") : "",
    p("Encrypted nightly backups made before you delete your account still contain your data until they are deleted; they can be read only with the owner's key. YouTube data is deleted after " + days(f.youtubeRetentionDays) + " (section 9)."),

    h2("rights", "7. Your privacy rights, including in California"),
    p("Whoever you are, you can:"),
    ul([
      "Know what we hold: the Your data page lists it, and its download gives you all of it.",
      "Delete it: delete your account on the Your data page.",
      "Correct it: edit your profile and settings, or write to us.",
      "Opt out of the sale or sharing of your personal information. None occurs: we do not sell or share it.",
      "Use these rights without being treated differently for it."
    ]),
    "<p>California residents have these rights under the California Consumer Privacy Act. To make a request we cannot handle through the Your data page, email " + mail() + " from the address on your account, with \"Privacy request\" in the subject. We may ask you to confirm it is you, and we answer within 45 days. An authorised agent can make a request for you with your signed permission.</p>",

    h2("children", "8. Children"),
    p("BizForce is not for anyone under " + legal.MINIMUM_AGE + ", and nobody under " + legal.MINIMUM_AGE + " may create an account. If we learn an account belongs to someone under " + legal.MINIMUM_AGE + ", we will close it and delete its data."),

    h2("youtube", "9. YouTube"),
    '<p>BizForce uses YouTube API Services. By using the YouTube section of Lead Radar you agree to the <a href="https://www.youtube.com/t/terms">YouTube Terms of Service</a>, and YouTube data is handled under the <a href="https://policies.google.com/privacy">Google Privacy Policy</a>.</p>',
    ul([
      "What is accessed: public YouTube videos found by searching a fixed list of questions BizForce chooses, and the public comments under them: the comment text, the commenter's public display name, the video's link and the comment's time. No member's data is sent to YouTube, and BizForce does not sign in to anyone's YouTube or Google account.",
      "What is stored: those public comments, as leads in Lead Radar's YouTube section.",
      "How long: at most " + days(f.youtubeRetentionDays) + ". Older YouTube comments are deleted automatically every day.",
      "Not combined: YouTube comments are shown only in their own section. They are not scored, not replied to through outreach, not counted in demand figures, and not combined with data from any other source."
    ]),

    h2("changes", "10. Changes to this policy"),
    p("When we change this policy, the date at the top changes, and signed-in members see a notice with a link to it."),

    h2("contact", "11. Contact"),
    "<p>Questions or requests: " + mail() + ". By post:</p>",
    address()
  ];
  return page({
    title: "Privacy Policy",
    headTitle: "Privacy Policy — what BizForce AI collects, and your rights",
    path: legal.PAGES.privacy,
    description: "What BizForce AI collects, why, which services receive it, how it is protected and kept, your privacy rights including in California, and YouTube data.",
    body: body
  });
}

/* ── Refunds ────────────────────────────────────────────────────────────── */
function refund(f) {
  const per = f.interval;
  const body = [
    '<p class="lede">The short version: cancel any time, keep what you paid for, and no partial refunds.</p>',
    h2("policy", "The policy"),
    ul(legal.REFUND_POLICY),
    p(article(f.planName) + " " + f.planName + " subscription is " + money(f.price) + " per " + per + " and renews automatically until you cancel. Cancelling stops the next renewal; it does not end the " + per + " you are in, so you keep access to its end and are not charged again."),
    h2("cancel", "How to cancel"),
    "<ol><li>Sign in and open " + link("/billing.html", "Billing") + ".</li><li>Choose \"Manage / Cancel Subscription\". This opens Stripe's secure billing page for your account.</li><li>Choose to cancel, and confirm.</li></ol>",
    p("Billing then shows that your subscription will not renew, with the date your access ends."),
    h2("errors", "If something looks wrong"),
    "<p>If you think you were charged in error, write to " + mail() + " with the email address on your account and the date of the charge. If the law where you live gives you a right to a refund, this policy does not take it away.</p>",
    "<p>The full terms are in the " + link(legal.PAGES.terms, "Terms of Service") + ".</p>"
  ];
  return page({
    title: "Refunds",
    headTitle: "Refund Policy — cancel BizForce AI online, keep paid access",
    path: legal.PAGES.refund,
    description: "BizForce AI refund policy: cancel any time online on Billing, keep access to the end of the period you paid for, no partial or prorated refunds.",
    body: body
  });
}

/* ── Contact ────────────────────────────────────────────────────────────── */
function contact() {
  const body = [
    '<p class="lede">How to reach BizForce AI.</p>',
    h2("email", "Email"),
    "<p>" + mail() + "</p>",
    h2("post", "Postal address"),
    address(),
    h2("what", "What to write"),
    '<div class="card"><p><strong>Billing</strong></p>' + ul([
      "The email address on your account, the date of the charge, and what looks wrong.",
      "To cancel, you do not need to write: use Billing, as the Refunds page explains."
    ]) + "</div>",
    '<div class="card"><p><strong>Your data</strong></p>' + ul([
      "Most requests take a moment on the Your data page: see what is stored, download it, or delete your account.",
      "For anything else, write from the address on your account with \"Privacy request\" in the subject, and say what you want: to know, correct or delete."
    ]) + "</div>",
    '<div class="card"><p><strong>Reporting abuse</strong></p>' + ul([
      "The link to the page, listing or profile, or the member's username.",
      "What happened and when, with screenshots if you have them.",
      "Put \"Abuse report\" in the subject."
    ]) + "</div>",
    "<p>See also the " + link(legal.PAGES.terms, "Terms of Service") + ", the " + link(legal.PAGES.privacy, "Privacy Policy") + " and " + link(legal.PAGES.refund, "Refunds") + ".</p>"
  ];
  return page({
    title: "Contact",
    headTitle: "Contact BizForce AI — email, postal address, data requests",
    path: legal.PAGES.contact,
    description: "How to contact BizForce AI by email or post, and what to include for billing questions, data requests, account deletion help and abuse reports.",
    body: body
  });
}

/* The four pages, by their frontend file names. */
function buildLegalPages(facts) {
  facts = facts || codeFacts();
  return {
    "terms.html": terms(facts),
    "privacy.html": privacy(facts),
    "refund.html": refund(facts),
    "contact.html": contact(facts)
  };
}

module.exports = { SCROLLBARS, codeFacts, buildLegalPages, money, bfc, num, GUIDE_PRIVACY_SENTENCE, RECORDS_PRIVACY_SENTENCE, MEMBER_SUPPORT_TERMS, SUPPORT_PRIVACY_SENTENCE, LEARNING_PRIVACY_SENTENCE,
  BLUESKY_PRIVACY_SENTENCE, BLUESKY_MENTIONS_PRIVACY_SENTENCE, BLUESKY_TERMS_SENTENCE, STORE_PRIVACY_SENTENCE, musicTerms, musicPrivacySentence,
  MASTODON_PRIVACY_SENTENCE, MASTODON_TERMS_SENTENCE, CAMPAIGN_PRIVACY_SENTENCE, CAMPAIGN_TERMS_SENTENCE,
  MEDIA_PRIVACY_SENTENCE, MEDIA_TERMS_SENTENCE, SOCIAL_MEDIA_PRIVACY_SENTENCE, MAILBOX_PRIVACY_SENTENCE, MAILBOX_TERMS_SENTENCE,
  MAILBOX_REPLY_PRIVACY_SENTENCE, MAILBOX_REPLY_TERMS_SENTENCE, CARD_VISITS_PRIVACY_SENTENCE, CARD_WALLET_PRIVACY_SENTENCE, CARD_LEADS_PRIVACY_SENTENCE, CARD_LEADS_TERMS_SENTENCE,
  STORE_TERMS_SENTENCE, YOUTUBE_PRIVACY_SENTENCE, YOUTUBE_TERMS_SENTENCE, TIKTOK_PRIVACY_SENTENCE, TIKTOK_TERMS_SENTENCE };
