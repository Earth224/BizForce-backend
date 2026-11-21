"use strict";
// ── A post's public page: bizforceai.net/p/<post id> (P2-3, Nov 20 2026) ──
//
// Served by the backend, the way lib/campaignShare.js serves a campaign: the
// Netlify rule "/p/:id" proxies to GET /p/:id, which fills in the post AND the
// Open Graph and Twitter tags a crawler reads.
//
// ONLY a public, published post that moderation has not hidden, whose author's
// pages are public (ownerPagePublic), is shown; everything else (a bad id, a
// followers-only, pending, hidden or removed post, an author whose plan is not
// active) answers 404 "No post found", which never says which.
//
// WHAT IT SHOWS: the author's name and photo (linking to /@handle), the text,
// the photos (each thumbnail, opening the full photo), the counts, and Like,
// Talk, Save and Follow, which lead to sign-in and back to this page
// (scripts/bf-post-page.js sets bf_return_to; signed in, they open the post
// in the app). Share uses the device's share sheet, else copies the link; a
// signed-out share is not counted. The three-dot menu (scripts/bf-safety.js)
// offers Report and the copyright notice. Never the author's id, an email, or
// who liked or saved it.
//
// og:title is the author and the first words; og:image the first photo's
// thumbnail (else the author's photo, else the site icon). The page is
// noindex: a member posting has not asked to be in search engines.
const { SCROLLBARS } = require("./scrollbars");
var links = require("./supportLinks");
var VB = require("./verified");

var SITE = links.SITE;
var DEFAULT_IMAGE = SITE + "/icons/icon-512.png";
var TITLE_WORDS_MAX = 60;
var DESCRIPTION_META_MAX = 200;
var UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
var esc = links.escapeHtml;

function isPostId(raw) { return typeof raw === "string" && UUID_RE.test(raw); }
function postUrl(id) { return SITE + "/p/" + id; }
function httpsUrl(url) { return typeof url === "string" && /^https:\/\/[^\s"'<>]+$/.test(url) && url.length <= 500 ? url : null; }
function cut(text, n) {
  var chars = Array.from(String(text || "").replace(/\s+/g, " ").trim());
  return chars.length > n ? chars.slice(0, n - 3).join("").trim() + "..." : chars.join("");
}

/* The author and the first words: "Ana Ruiz on BizForce: Fresh bread today". */
function titleFor(post) {
  var who = (post.author && post.author.name) || "A member";
  var words = cut(post.body, TITLE_WORDS_MAX);
  return who + " on BizForce" + (words ? ": " + words : post.photos && post.photos.length ? ": a photo post" : "");
}
function descriptionFor(post) {
  var text = cut(post.body, DESCRIPTION_META_MAX);
  return text || "A post by " + ((post.author && post.author.name) || "a member") + " on BizForce.";
}
function imageFor(post) {
  var first = (post.photos || [])[0];
  return (first && httpsUrl(first.thumb_url)) || httpsUrl(post.author && post.author.avatar_url) || DEFAULT_IMAGE;
}
function count(n, one, many) { n = Number(n) || 0; return n.toLocaleString("en-US") + " " + (n === 1 ? one : many); }

/* post: lib/posts.js publicPost(...), or null for "No post found". */
function renderPostPage(post) {
  var shown = !!post;
  var url = shown ? postUrl(post.id) : SITE + "/";
  var title = shown ? titleFor(post) : "No post found — BizForce";
  var desc = shown ? descriptionFor(post) : "No post found on BizForce.";
  var image = shown ? imageFor(post) : DEFAULT_IMAGE;
  var head = [
    '<!DOCTYPE html>',
    '<html lang="en" data-bf-page="post">',
    '<head>',
    '  <meta charset="UTF-8"/>',
    '  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>',
    '  <title>' + esc(title) + '</title>',
    '  <meta name="description" content="' + esc(desc) + '"/>',
    '  <meta name="robots" content="noindex"/>',
    '  <link rel="canonical" href="' + esc(url) + '"/>',
    '  <meta property="og:type" content="article"/>',
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
    '  <style>',
    '    *{box-sizing:border-box}body{margin:0;background:#070b18;color:#e8e8ff;font:15px/1.55 system-ui,-apple-system,"Segoe UI",Arial,sans-serif}',
    '    main{max-width:600px;margin:0 auto;padding:24px 16px 48px}',
    '    .pp-head{display:flex;align-items:center;gap:12px;margin:0 0 14px}',
    '    .pp-avatar{width:44px;height:44px;border-radius:50%;object-fit:cover;background:#1a2040;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-weight:800;color:#c9d1e6}',
    '    .pp-who{flex:1;min-width:0;display:flex;flex-direction:column}',
    '    .pp-name{display:inline-flex;align-items:center;align-self:flex-start;min-height:44px;font-weight:800;color:#f4f7ff;text-decoration:none;overflow-wrap:anywhere}',
    '    .pp-handle{font-size:.85rem;color:#8892b8}',
    '    .pp-photos{display:grid;gap:8px;margin:0 0 14px}',
    '    .pp-photos.n2,.pp-photos.n3,.pp-photos.n4{grid-template-columns:repeat(2,minmax(0,1fr))}',
    '    .pp-photos a{display:block;border-radius:12px;overflow:hidden;background:#10173a}',
    '    .pp-photos img{display:block;width:100%;height:100%;max-height:520px;object-fit:cover}',
    '    .pp-body{white-space:pre-wrap;overflow-wrap:anywhere;margin:0 0 14px;font-size:1rem}',
    '    .pp-body.is-text{padding:22px 18px;border-radius:16px;background:linear-gradient(135deg,#12204a,#2a1650);font-size:1.15rem;font-weight:600}',
    '    .pp-counts{margin:0 0 12px;color:#9aa3cc;font-size:.88rem}',
    '    .pp-actions{display:flex;flex-wrap:wrap;gap:8px}',
    '    .pp-btn{display:inline-flex;align-items:center;justify-content:center;min-height:44px;min-width:44px;padding:0 16px;border-radius:12px;border:1px solid #2f3b7a;background:#141c40;color:#e8e8ff;font:600 .9rem system-ui,-apple-system,"Segoe UI",Arial,sans-serif;text-decoration:none;cursor:pointer}',
    '    .pp-btn.is-main{background:#2b3a8f;border-color:#4a5ab8}',
    '    .pp-btn:focus-visible,a:focus-visible,button:focus-visible{outline:2px solid #f7dd8a;outline-offset:2px}',
    '    .pp-status{min-height:1.4em;margin:8px 0 0;font-size:.9rem}',
    '    .pp-plain{font-size:.85rem;color:#9aa3cc;margin-top:24px}',
    '    .pp-menu{margin-left:auto}',
    '    a{color:#9ec5ff}',
    // a phone: the legal footer's links are 44 px tap targets, as css/bf-phone.css makes them on the app's pages (this page loads no theme or app CSS)
    '    @media (max-width: 760px){.bf-legal-footer a{display:inline-flex;align-items:center;justify-content:center;min-width:44px;min-height:44px}}',
    '  </style>',
    '<style id="bf-scrollbars">',
    SCROLLBARS,
    '</style>',
    '</head>',
    '<body>'
  ];
  // NAMED (Nov 21 2026, P3-2): the Verified badge's rules (lib/verified.js CSS), only on a verified author's shown post
  if (shown && verifiedReason(post)) head.splice(head.indexOf('  </style>'), 0, '    ' + VB.CSS);
  var body = shown ? pageBody(post) : ['<main id="postPage" data-state="none">', '  <h1>No post found</h1>',
    '  <p>There is no public BizForce post at this link. It may have been deleted, or shared with followers only.</p>', '  <p><a href="/">BizForce AI</a></p>', '</main>'];
  var tail = ['<footer class="bf-legal-footer" data-bf-legal-footer></footer>', '<script src="/scripts/bf-legal-footer.js"></script>', '</body>', '</html>', ''];
  return head.concat(body, tail).join("\n");
}

/* P3-2 (Nov 21 2026): the Verified badge, inside the author's name after its text (lib/verified.js badgeHtml). Only a
   verified author's post gains the badge, its rules and scripts/bf-verified.js (the tap sheet); any other post's page is
   unchanged. */
function verifiedReason(post) { return VB.reasonOf({ verified_reason: post && post.author && post.author.verified }); }
function badgeFor(post) { var r = verifiedReason(post); return r ? VB.badgeHtml(r) : ""; }

function pageBody(post) {
  var a = post.author || {};
  var avatar = httpsUrl(a.avatar_url);
  var initial = esc(String(a.name || "?").replace(/^@/, "").charAt(0).toUpperCase());
  var profile = a.username ? "/@" + a.username : "";
  var photos = (post.photos || []).map(function (p) {
    var full = httpsUrl(p.url), thumb = httpsUrl(p.thumb_url) || full;
    if (!full) return "";
    return '    <a href="' + esc(full) + '" target="_blank" rel="noopener"><img src="' + esc(thumb) + '" alt="' + esc(p.alt || "") + '" loading="lazy"/></a>';
  }).filter(Boolean);
  var textOnly = !photos.length;
  return [
    '<main id="postPage" data-state="on" data-post-id="' + esc(post.id) + '" data-post-url="' + esc(postUrl(post.id)) + '"' + (a.username ? ' data-handle="' + esc(a.username) + '"' : "") + '>',
    '  <div class="pp-head">',
    '    ' + (avatar ? '<img class="pp-avatar" src="' + esc(avatar) + '" alt=""/>' : '<span class="pp-avatar" aria-hidden="true">' + initial + '</span>'),
    '    <span class="pp-who">' + (profile ? '<a class="pp-name" href="' + esc(profile) + '">' + esc(a.name || "A member") + badgeFor(post) + '</a><span class="pp-handle">@' + esc(a.username) + '</span>'
      : '<span class="pp-name">' + esc(a.name || "A member") + badgeFor(post) + '</span>') + '</span>',
    '    <span class="pp-menu" id="ppMenu"></span>',
    '  </div>',
    photos.length ? '  <div class="pp-photos n' + photos.length + '">\n' + photos.join("\n") + '\n  </div>' : "",
    post.body ? '  <p class="pp-body' + (textOnly ? " is-text" : "") + '" id="ppBody">' + esc(post.body) + '</p>' : "",
    '  <p class="pp-counts" id="ppCounts">' + esc([count(post.like_count, "like", "likes"), count(post.comment_count, "comment", "comments"), count(post.share_count, "share", "shares")].join(" · ")) + '</p>',
    '  <div class="pp-actions">',
    '    <a class="pp-btn is-main" data-pp-act="like" href="/app.html">Like</a>',
    '    <a class="pp-btn" data-pp-act="talk" href="/app.html">Talk</a>',
    '    <a class="pp-btn" data-pp-act="save" href="/app.html">Save</a>',
    a.username ? '    <a class="pp-btn" data-pp-act="follow" href="/app.html">Follow</a>' : "",
    '    <button type="button" class="pp-btn" id="ppShare">Share</button>',
    '  </div>',
    '  <p class="pp-status" id="ppStatus" role="status" aria-live="polite"></p>',
    '  <p class="pp-plain" id="ppSignedOut">Sign in to like, talk, save or follow. You come back to this post after.</p>',
    '</main>',
    '<script src="/scripts/bf-safety.js"></script>',
    '<script src="/scripts/bf-post-page.js"></script>',
    verifiedReason(post) ? '<script src="/scripts/bf-verified.js"></script>' : ""
  ].filter(function (line) { return line !== ""; });
}

module.exports = { DEFAULT_IMAGE, TITLE_WORDS_MAX, DESCRIPTION_META_MAX, isPostId, postUrl, titleFor, descriptionFor, imageFor, renderPostPage };
