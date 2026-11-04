"use strict";
// ── A crowdfunding campaign's public page: bizforceai.net/campaign/<share_id> ──
//
// Built the way lib/supportPage.js builds the support page, and SERVED BY THE
// BACKEND for the same reason: the Netlify rule "/campaign/:shareId" proxies
// to GET /campaign/:shareId, which fills in the campaign AND the Open Graph
// and Twitter tags a crawler reads (crawlers do not run the page's script).
//
// THE LINK. share_id is 16 lowercase base32 characters (a-z, 2-7) made from
// 10 random bytes (crypto.randomBytes, never Math.random): 80 bits, so a link
// cannot be guessed. SHARE_ID_PATTERN is migration 166's CHECK, character for
// character (scripts/checkCampaignSharing.js holds the two equal). Sharing is
// off until the owner turns it on; "Make a new link" replaces share_id, and
// the old link then answers "No campaign found".
//
// WHAT IT SHOWS, and nothing else: the title, description, category, media,
// goal and amount raised with a progress bar; the owner's display name and
// photo, decided exactly as the support page decides them; a link to the
// owner's support page only while it is on; a donate button that goes to
// campaigns.html (signed out: "Sign in to donate", which comes back there
// after sign-in); Share, Copy link and a QR code of this page's URL. Never
// owner_id, the campaign id, a donor, a donation, a count of donors, an email
// or a phone number.
//
// FOUR STATES: "on" (active and shared), "ended" (completed and shared: the
// final totals, "This campaign has ended", no donate button), "off" (sharing
// off, or paused or cancelled: "This campaign isn't being shared right now",
// 200) and "none" (a malformed or unknown id, or an owner whose plan is not
// active: "No campaign found", 404). Only "on" or "ended" with discovery
// chosen is indexable; every other answer carries noindex.

const crypto = require("crypto");
const { SCROLLBARS } = require("./scrollbars");
var links = require("./supportLinks");

var SITE = links.SITE;
var DEFAULT_IMAGE = SITE + "/icons/icon-512.png";
var QR_SCRIPT = '<script src="https://cdn.jsdelivr.net/npm/qrcode@1.4.4/build/qrcode.min.js" integrity="sha384-0RsG1yo/crf/1Qc14sho26SXXOTngNCjgJw7fuvXBt9W/OChF/Ijx+aUuBDqQwEk" crossorigin="anonymous"></script>';

/* Migration 166: CHECK (share_id IS NULL OR share_id ~ '^[a-z2-7]{16}$'). */
var SHARE_ID_PATTERN = "^[a-z2-7]{16}$";
var SHARE_ID_RE = new RegExp(SHARE_ID_PATTERN);
var BASE32 = "abcdefghijklmnopqrstuvwxyz234567";
var DESCRIPTION_META_MAX = 200;
var MEDIA_MAX = 6;

var esc = links.escapeHtml;

function isShareId(raw) { return typeof raw === "string" && SHARE_ID_RE.test(raw); }

/* 10 random bytes, 80 bits, written as 16 base32 characters, 5 bits each. */
function newShareId(randomBytes) {
  var bytes = (randomBytes || crypto.randomBytes)(10);
  var out = "";
  var buffer = 0;
  var bits = 0;
  for (var i = 0; i < bytes.length; i++) {
    buffer = (buffer << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
    buffer &= 255;
  }
  return out;
}

function campaignUrl(shareId) { return SITE + "/campaign/" + shareId; }

function httpsUrl(url) {
  return typeof url === "string" && /^https:\/\/[^\s"'<>]+$/.test(url) && url.length <= 500 ? url : null;
}

/* The page's state from the row and whether its owner's plan is active. */
function stateFor(row, ownerActive) {
  if (!row || !isShareId(row.share_id) || ownerActive !== true) return "none";
  if (row.share_on !== true) return "off";
  if (row.status === "active") return "on";
  if (row.status === "completed") return "ended";
  return "off";
}

/* Media a stranger may be shown: https images and videos only, at most six. */
function publicMedia(media) {
  return (Array.isArray(media) ? media : []).map(function (m) {
    if (!m || typeof m !== "object") return null;
    var url = httpsUrl(m.url);
    var type = typeof m.type === "string" ? m.type : "";
    if (!url) return null;
    if (type.indexOf("image/") === 0 || type === "image") return { url: url, kind: "image" };
    if (type.indexOf("video/") === 0 || type === "video") return { url: url, kind: "video" };
    return null;
  }).filter(Boolean).slice(0, MEDIA_MAX);
}

function whole(n) { return Number.isInteger(n) && n >= 0 ? n : 0; }

/* WHAT A STRANGER IS SERVED: this allowlist and nothing else.
   row: the campaign row. owner: { displayName, photo, supportUrl } from the
   owner's bf_profiles row and member_support row (ownerFrom). */
function publicCampaignFrom(row, owner) {
  owner = owner || {};
  return {
    title: String(row.title || ""),
    description: String(row.description || ""),
    category: row.category ? String(row.category) : null,
    media: publicMedia(row.media),
    goal_bfc: whole(row.goal_bfc),
    raised_bfc: whole(row.raised_bfc),
    owner_display_name: owner.displayName || "A BizForce member",
    owner_photo: httpsUrl(owner.photo),
    support_url: owner.supportUrl || null,
    url: campaignUrl(row.share_id)
  };
}

/* The owner as the support page decides them (lib/supportPage.js viewFor):
   the display name, else the username; the profile photo, https only; the
   support page's URL only while that page is on. */
function ownerFrom(profile, support) {
  if (!profile) return { displayName: null, photo: null, supportUrl: null };
  var username = profile.username ? String(profile.username).toLowerCase() : null;
  return {
    displayName: profile.display_name || profile.username || null,
    photo: profile.avatar_url || null,
    supportUrl: username && links.pageIsOn(support) ? links.supportUrl(username) : null
  };
}

function percentOf(c) {
  return c.goal_bfc > 0 ? Math.min(100, Math.round(c.raised_bfc / c.goal_bfc * 100)) : 0;
}

function metaDescription(state, c) {
  if (state === "off") return "This campaign isn't being shared right now.";
  if (state !== "on" && state !== "ended") return "No campaign found on BizForce.";
  var text = c.description.replace(/\s+/g, " ").trim();
  if (!text) text = "A crowdfunding campaign by " + c.owner_display_name + " on BizForce, backed with BizCash.";
  var chars = Array.from(text);
  return chars.length > DESCRIPTION_META_MAX ? chars.slice(0, DESCRIPTION_META_MAX - 3).join("") + "..." : text;
}

function shareImage(c) {
  var first = c.media.filter(function (m) { return m.kind === "image"; })[0];
  return (first && first.url) || c.owner_photo || DEFAULT_IMAGE;
}

/* state: "on" | "ended" | "off" | "none". data: { campaign: publicCampaignFrom(...),
   discoverable } for "on" and "ended"; nothing for the others. */
function renderCampaignPage(state, data) {
  var shown = state === "on" || state === "ended";
  var c = shown && data && data.campaign ? data.campaign : null;
  if (!c) shown = false;
  if (!shown && state !== "off") state = "none";
  var url = shown ? c.url : SITE + "/campaigns.html";
  var title = shown ? c.title + " — a campaign on BizForce"
    : state === "off" ? "Campaign not shared — BizForce" : "No campaign found — BizForce";
  var desc = metaDescription(state, c);
  var image = shown ? shareImage(c) : DEFAULT_IMAGE;
  var index = shown && data.discoverable === true;
  var head = [
    '<!DOCTYPE html>',
    '<html lang="en" data-bf-page="campaign">',
    '<head>',
    '  <meta charset="UTF-8"/>',
    '  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>',
    '  <title>' + esc(title) + '</title>',
    '  <meta name="description" content="' + esc(desc) + '"/>',
    '  <meta name="robots" content="' + (index ? "index, follow" : "noindex") + '"/>',
    '  <link rel="canonical" href="' + esc(url) + '"/>',
    '  <meta property="og:type" content="website"/>',
    '  <meta property="og:site_name" content="BizForce AI"/>',
    '  <meta property="og:title" content="' + esc(title) + '"/>',
    '  <meta property="og:description" content="' + esc(desc) + '"/>',
    '  <meta property="og:url" content="' + esc(url) + '"/>',
    '  <meta property="og:image" content="' + esc(image) + '"/>',
    '  <meta name="twitter:card" content="' + (shown && image !== DEFAULT_IMAGE ? "summary_large_image" : "summary") + '"/>',
    '  <meta name="twitter:title" content="' + esc(title) + '"/>',
    '  <meta name="twitter:description" content="' + esc(desc) + '"/>',
    '  <meta name="twitter:image" content="' + esc(image) + '"/>',
    '  <link rel="icon" href="/icons/favicon-32.png"/>',
    shown ? '  ' + QR_SCRIPT : "",
    '  <style>',
    '    *{box-sizing:border-box}body{margin:0;background:#070b18;color:#e8e8ff;font:15px/1.55 system-ui,-apple-system,"Segoe UI",Arial,sans-serif}',
    '    main{max-width:640px;margin:0 auto;padding:32px 16px 48px}',
    '    h1{font-size:1.5rem;margin:6px 0 10px;overflow-wrap:anywhere}h2{font-size:1rem;margin:28px 0 10px;color:#c9cff0}',
    '    .cmp-cat{display:inline-block;font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;padding:3px 10px;border-radius:999px;border:1px solid #4a3a8f;color:#c9b8ff}',
    '    .cmp-owner{display:flex;gap:10px;align-items:center;margin:0 0 16px;color:#c9cff0}',
    '    .cmp-photo{width:40px;height:40px;border-radius:50%;object-fit:cover;background:#1a2040;flex-shrink:0}',
    '    .cmp-media{display:grid;gap:10px;margin:0 0 16px}',
    '    .cmp-media img,.cmp-media video{width:100%;max-height:360px;object-fit:cover;border-radius:12px;background:#10173a;display:block}',
    '    .cmp-desc{white-space:pre-wrap;overflow-wrap:anywhere;margin:0 0 18px}',
    '    .cmp-track{width:100%;height:10px;border-radius:999px;background:#1a2040;overflow:hidden}',
    '    .cmp-fill{height:100%;border-radius:999px;background:#34d399}',
    '    .cmp-totals{margin:8px 0 0;font-weight:600}',
    '    .cmp-ended{margin:14px 0 0;padding:10px 14px;border-radius:10px;background:#10173a;border:1px solid #26306a}',
    '    .cmp-box{background:#10173a;border:1px solid #26306a;border-radius:12px;padding:16px}',
    '    .cmp-btn{margin-top:12px;padding:10px 16px;border-radius:10px;border:1px solid #4a5ab8;background:#2b3a8f;color:#fff;font:inherit;font-weight:600;cursor:pointer;text-decoration:none;display:inline-block}',
    '    .cmp-btn:focus-visible,a:focus-visible,button:focus-visible{outline:2px solid #f7dd8a;outline-offset:2px}',
    '    .cmp-row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}',
    '    .cmp-status{min-height:1.4em;margin:8px 0 0;font-size:.9rem}',
    '    .cmp-plain{font-size:.85rem;color:#9aa3cc;margin-top:28px}',
    '    a{color:#9ec5ff}',
    '    #cmpQr{display:block;margin-top:12px;background:#fff;border-radius:8px;padding:6px}',
    '  </style>',
    '<style id="bf-scrollbars">',
    SCROLLBARS,
    '</style>',
    '</head>',
    '<body>'
  ];
  var body;
  if (shown) body = pageBody(state, c);
  else if (state === "off") body = ['<main id="campaignPage" data-state="off">', '  <h1>This campaign isn\'t being shared right now</h1>',
    '  <p><a href="/">BizForce AI</a></p>', '</main>'];
  else body = ['<main id="campaignPage" data-state="none">', '  <h1>No campaign found</h1>',
    '  <p>There is no shared BizForce campaign at this link. Its owner may have made a new link.</p>', '  <p><a href="/">BizForce AI</a></p>', '</main>'];
  var tail = [
    '<footer class="bf-legal-footer" data-bf-legal-footer></footer>',
    '<script src="/scripts/bf-legal-footer.js"></script>',
    '</body>',
    '</html>',
    ''
  ];
  return head.filter(function (line) { return line !== ""; }).concat(body, tail).join("\n");
}

function pageBody(state, c) {
  var percent = percentOf(c);
  var photo = httpsUrl(c.owner_photo);
  var shareId = c.url.slice(c.url.lastIndexOf("/") + 1);
  var media = c.media.map(function (m) {
    return m.kind === "image"
      ? '    <img src="' + esc(m.url) + '" alt="" loading="lazy"/>'
      : '    <video src="' + esc(m.url) + '" controls preload="metadata"></video>';
  });
  var totals = c.raised_bfc.toLocaleString("en-US") + " of " + c.goal_bfc.toLocaleString("en-US") + " BFC raised (" + percent + "%)";
  return [
    '<main id="campaignPage" data-state="' + state + '" data-share-id="' + esc(shareId) + '" data-share-url="' + esc(c.url) + '" data-title="' + esc(c.title) + '">',
    c.category ? '  <span class="cmp-cat">' + esc(c.category) + '</span>' : "",
    '  <h1 id="cmpTitle">' + esc(c.title) + '</h1>',
    '  <div class="cmp-owner">',
    '    ' + (photo ? '<img class="cmp-photo" src="' + esc(photo) + '" alt=""/>' : '<div class="cmp-photo" aria-hidden="true"></div>'),
    '    <span>By ' + esc(c.owner_display_name) + '</span>',
    '  </div>',
    media.length ? '  <div class="cmp-media">\n' + media.join("\n") + '\n  </div>' : "",
    c.description ? '  <p class="cmp-desc">' + esc(c.description) + '</p>' : "",
    '  <section aria-labelledby="cmpProgressTitle">',
    '    <h2 id="cmpProgressTitle">Progress</h2>',
    '    <div class="cmp-track" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="' + percent + '"><div class="cmp-fill" style="width:' + percent + '%"></div></div>',
    '    <p class="cmp-totals" id="cmpTotals">' + esc(totals) + '</p>',
    state === "ended" ? '    <p class="cmp-ended" id="cmpEnded">This campaign has ended</p>' : "",
    '  </section>',
    state === "on" ? [
      '  <section aria-labelledby="cmpDonateTitle">',
      '    <h2 id="cmpDonateTitle">Donate with BizCash</h2>',
      '    <div class="cmp-box">',
      '      <a class="cmp-btn" id="cmpSignIn" href="/app.html">Sign in to donate</a>',
      '      <a class="cmp-btn" id="cmpDonate" href="/campaigns.html?campaign=' + esc(shareId) + '" hidden>Donate BizCash</a>',
      '      <p class="cmp-status" id="cmpDonateStatus" role="status" aria-live="polite"></p>',
      '      <p class="cmp-plain">Donations follow the BizCash rules and limits.</p>',
      '      <p class="bfc-notice" data-bfc-notice></p>',
      '      <script src="/scripts/bf-bfc-notice.js"></script>',
      '    </div>',
      '  </section>'
    ].join("\n") : "",
    c.support_url ? '  <p><a id="cmpSupport" href="' + esc(c.support_url) + '">Support ' + esc(c.owner_display_name) + ' directly</a></p>' : "",
    '  <section aria-labelledby="cmpShareTitle">',
    '    <h2 id="cmpShareTitle">Share this campaign</h2>',
    '    <div class="cmp-row"><button type="button" class="cmp-btn" id="cmpShareBtn">Share</button><button type="button" class="cmp-btn" id="cmpCopyBtn">Copy link</button></div>',
    '    <p class="cmp-status" id="cmpShareStatus" role="status" aria-live="polite"></p>',
    '    <canvas id="cmpQr" width="148" height="148" role="img" aria-label="QR code of this campaign page"></canvas>',
    '  </section>',
    '  <p class="cmp-plain">BizCash has no cash value. BizForce records each donation but is not a party to what the campaign does with it.</p>',
    '</main>',
    '<script src="/scripts/bf-support.js"></script>',
    '<script src="/scripts/bf-campaign.js"></script>'
  ].filter(function (line) { return line !== ""; });
}

module.exports = {
  SHARE_ID_PATTERN, SHARE_ID_RE, DEFAULT_IMAGE, QR_SCRIPT, DESCRIPTION_META_MAX,
  isShareId, newShareId, campaignUrl, stateFor, publicMedia, publicCampaignFrom, ownerFrom, renderCampaignPage
};
