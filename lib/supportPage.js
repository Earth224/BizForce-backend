// ── A member's support page: bizforceai.net/support/<username> ──────────────
//
// SERVED BY THE BACKEND, so a link posted or texted previews properly: the
// Netlify rule "/support/:username" proxies to GET /support/:username here,
// which fills in the member's name, photo and headline AND the Open Graph and
// Twitter tags a crawler reads (crawlers do not run the page's script). The
// same template, with no member, is written to the frontend as support.html by
// scripts/buildSupportPage.js, so the page's controls, its guide entry and the
// app map all come from one source; checkMemberSupport holds the two equal.
//
// WHAT IT SHOWS, and nothing else: the display name, the photo, the headline
// the member set, their external support links (each with the provider's
// disclaimer), "Support with BizCash" for a signed-in visitor (signed out:
// "Sign in to support with BizCash", which comes back here after sign-in),
// Share and Copy link, and a QR code of this page's URL. Never an email, a
// phone number, a balance, a note or who has supported them.
//
// THREE STATES: "on" (the page), "off" (the member turned it off, or has no
// link and never turned it on: "This member's support page is off", 200) and
// "none" (no such member, an invalid username, or one whose page is not
// public: "No member found", 404). Only "on" with discovery chosen is
// indexable; every other answer carries noindex.

var links = require("./supportLinks");

var SITE = links.SITE;
var DEFAULT_IMAGE = SITE + "/icons/icon-512.png";
var QR_SCRIPT = '<script src="https://cdn.jsdelivr.net/npm/qrcode@1.4.4/build/qrcode.min.js" integrity="sha384-0RsG1yo/crf/1Qc14sho26SXXOTngNCjgJw7fuvXBt9W/OChF/Ijx+aUuBDqQwEk" crossorigin="anonymous"></script>';
var USERNAME = /^[a-z0-9_-]{1,40}$/i;

var esc = links.escapeHtml;

function imageOf(url) {
  return typeof url === "string" && /^https:\/\/[^\s"'<>]+$/.test(url) && url.length <= 500 ? url : null;
}

function descriptionOf(view) {
  if (view.state !== "on") return view.state === "off" ? "This member's support page is off." : "No member found on BizForce.";
  return view.headline || ("Support " + view.displayName + " (@" + view.username + ") directly, with BizCash or through their own payment links.");
}

/* view: { state: "on"|"off"|"none"|"shell", username, displayName, photo,
   headline, links: [publicLink], discoverable } */
function render(view) {
  var on = view.state === "on";
  var url = view.username && view.state !== "none" && view.state !== "shell" ? links.supportUrl(view.username) : SITE + "/support.html";
  var title = on ? "Support " + view.displayName + " on BizForce"
    : view.state === "off" ? "Support page off — BizForce"
    : view.state === "shell" ? "Support a member — BizForce" : "No member found — BizForce";
  var desc = descriptionOf(view);
  var image = (on && imageOf(view.photo)) || DEFAULT_IMAGE;
  var index = on && view.discoverable === true;
  var head = [
    '<!DOCTYPE html>',
    '<html lang="en" data-bf-page="support.html">',
    '<head>',
    '  <meta charset="UTF-8"/>',
    '  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>',
    '  <title>' + esc(title) + '</title>',
    '  <meta name="description" content="' + esc(desc) + '"/>',
    '  <meta name="robots" content="' + (index ? "index, follow" : "noindex") + '"/>',
    '  <link rel="canonical" href="' + esc(url) + '"/>',
    '  <meta property="og:type" content="profile"/>',
    '  <meta property="og:site_name" content="BizForce AI"/>',
    '  <meta property="og:title" content="' + esc(title) + '"/>',
    '  <meta property="og:description" content="' + esc(desc) + '"/>',
    '  <meta property="og:url" content="' + esc(url) + '"/>',
    '  <meta property="og:image" content="' + esc(image) + '"/>',
    '  <meta name="twitter:card" content="summary"/>',
    '  <meta name="twitter:title" content="' + esc(title) + '"/>',
    '  <meta name="twitter:description" content="' + esc(desc) + '"/>',
    '  <meta name="twitter:image" content="' + esc(image) + '"/>',
    '  <link rel="icon" href="/icons/favicon-32.png"/>',
    '  ' + QR_SCRIPT,
    '  <style>',
    '    *{box-sizing:border-box}body{margin:0;background:#070b18;color:#e8e8ff;font:15px/1.55 system-ui,-apple-system,"Segoe UI",Arial,sans-serif}',
    '    main{max-width:560px;margin:0 auto;padding:32px 16px 48px}',
    '    .sup-head{display:flex;gap:16px;align-items:center;margin-bottom:16px}',
    '    .sup-photo{width:84px;height:84px;border-radius:50%;object-fit:cover;background:#1a2040;flex-shrink:0}',
    '    h1{font-size:1.5rem;margin:0}.sup-user{color:#9aa3cc;margin:2px 0 0}.sup-headline{margin:12px 0 20px;font-size:1.05rem}',
    '    h2{font-size:1rem;margin:28px 0 10px;color:#c9cff0}',
    '    .sup-links{list-style:none;padding:0;margin:0;display:grid;gap:12px}',
    '    .sup-link{display:inline-block;padding:10px 16px;border-radius:10px;background:#2b3a8f;color:#fff;font-weight:600;text-decoration:none}',
    '    .sup-link:focus-visible,button:focus-visible,a:focus-visible,input:focus-visible{outline:2px solid #f7dd8a;outline-offset:2px}',
    '    .sup-disclaimer{display:block;font-size:.82rem;color:#9aa3cc;margin-top:4px}',
    '    .sup-box{background:#10173a;border:1px solid #26306a;border-radius:12px;padding:16px}',
    '    label{display:block;font-size:.85rem;margin:8px 0 4px;color:#c9cff0}',
    '    input{width:100%;padding:9px 11px;border-radius:8px;border:1px solid #34407e;background:#0b1130;color:#fff;font:inherit}',
    '    button,.sup-btn{margin-top:12px;padding:10px 16px;border-radius:10px;border:1px solid #4a5ab8;background:#2b3a8f;color:#fff;font:inherit;font-weight:600;cursor:pointer;text-decoration:none;display:inline-block}',
    '    .sup-row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}',
    '    .sup-status{min-height:1.4em;margin:8px 0 0;font-size:.9rem}',
    '    #supQr{display:block;margin-top:12px;background:#fff;border-radius:8px;padding:6px}',
    '    .sup-plain{font-size:.85rem;color:#9aa3cc;margin-top:28px}',
    '  </style>',
    '</head>',
    '<body>'
  ];
  var body;
  if (on || view.state === "shell") body = pageBody(view, url);
  else if (view.state === "off") body = ['<main id="supportPage" data-state="off">', '  <h1>This member\'s support page is off</h1>',
    '  <p><a href="/">BizForce AI</a></p>', '</main>'];
  else body = ['<main id="supportPage" data-state="none">', '  <h1>No member found</h1>',
    '  <p>There is no BizForce member with that username, or their page is not public.</p>', '  <p><a href="/">BizForce AI</a></p>', '</main>'];
  var tail = [
    '<script src="/scripts/termaximus-guide.js"></script>',
    '<footer class="bf-legal-footer" data-bf-legal-footer></footer>',
    '<script src="/scripts/bf-legal-footer.js"></script>',
    '</body>',
    '</html>',
    ''
  ];
  return head.concat(body, tail).join("\n");
}

function pageBody(view, url) {
  var shell = view.state === "shell";
  var photo = imageOf(view.photo);
  var list = (view.links || []).map(function (l) {
    return '    <li><a class="sup-link" href="' + esc(l.url) + '" target="_blank" rel="noopener noreferrer">Support on ' + esc(l.label) + '</a>' +
      '<span class="sup-disclaimer">' + esc(l.disclaimer) + '</span></li>';
  });
  return [
    '<main id="supportPage" data-state="' + (shell ? "shell" : "on") + '" data-username="' + esc(view.username || "") + '" data-display-name="' + esc(view.displayName || "") +
      '" data-support-url="' + esc(shell ? "" : url) + '">',
    shell ? '  <p id="supShellNote">Open a member\'s support link, bizforceai.net/support/&lt;username&gt;, to see their page.</p>' : "",
    '  <div class="sup-head">',
    '    ' + (photo ? '<img class="sup-photo" src="' + esc(photo) + '" alt=""/>' : '<div class="sup-photo" aria-hidden="true"></div>'),
    '    <div><h1 id="supName">' + esc(view.displayName || "") + '</h1><p class="sup-user">' + (view.username ? "@" + esc(view.username) : "") + '</p></div>',
    '  </div>',
    view.headline ? '  <p class="sup-headline">' + esc(view.headline) + '</p>' : "",
    '  <section aria-labelledby="supLinksTitle"' + (list.length ? "" : " hidden") + '>',
    '    <h2 id="supLinksTitle">Support directly</h2>',
    '    <ul class="sup-links">',
    list.join("\n"),
    '    </ul>',
    '  </section>',
    '  <section aria-labelledby="supBfcTitle">',
    '    <h2 id="supBfcTitle">Support with BizCash</h2>',
    '    <div class="sup-box">',
    '      <a class="sup-btn" id="supSignIn" href="/app.html">Sign in to support with BizCash</a>',
    '      <form id="supBfcForm" hidden>',
    '        <label for="supAmount">Amount (BFC)</label>',
    '        <input id="supAmount" type="number" min="1" step="1" inputmode="numeric" required/>',
    '        <label for="supNote">Note (optional, 140 characters, only you and this member see it)</label>',
    '        <input id="supNote" type="text" maxlength="140" autocomplete="off"/>',
    '        <button type="submit" id="supBfcBtn">Support with BizCash</button>',
    '      </form>',
    '      <div id="supConfirm" hidden>',
    '        <p id="supConfirmText"></p>',
    '        <div class="sup-row"><button type="button" id="supConfirmBtn">Send</button><button type="button" id="supCancelBtn">Cancel</button></div>',
    '      </div>',
    '      <p class="sup-status" id="supBfcStatus" role="status" aria-live="polite"></p>',
    '      <p class="sup-disclaimer">Support follows the BizCash rules and limits.</p>',
    '      <p class="bfc-notice" data-bfc-notice></p>',
    '      <script src="/scripts/bf-bfc-notice.js"></script>',
    '    </div>',
    '  </section>',
    '  <section aria-labelledby="supShareTitle">',
    '    <h2 id="supShareTitle">Share this page</h2>',
    '    <div class="sup-row"><button type="button" id="supShareBtn">Share</button><button type="button" id="supCopyBtn">Copy link</button></div>',
    '    <p class="sup-status" id="supShareStatus" role="status" aria-live="polite"></p>',
    '    <canvas id="supQr" width="148" height="148" role="img" aria-label="QR code of this support page"></canvas>',
    '  </section>',
    '  <p class="sup-plain">BizForce never sees or holds what you pay through these links, and cannot refund it.</p>',
    '</main>',
    '<script src="/scripts/bf-support.js"></script>'
  ].filter(function (line) { return line !== ""; });
}

/* The view for a member, from their bf_profiles row and member_support row. */
function viewFor(profile, support) {
  if (!profile || !profile.username) return { state: "none" };
  var displayName = profile.display_name || profile.username;
  if (!links.pageIsOn(support)) return { state: "off", username: profile.username, displayName: displayName };
  return {
    state: "on",
    username: String(profile.username).toLowerCase(),
    displayName: displayName,
    photo: profile.avatar_url || null,
    headline: support && support.headline ? support.headline : null,
    links: links.publicLinks(support && support.links),
    discoverable: !!(support && support.discoverable === true)
  };
}

module.exports = { render, viewFor, USERNAME, DEFAULT_IMAGE, QR_SCRIPT };
