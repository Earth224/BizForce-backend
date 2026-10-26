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
   codeFacts() reads them; buildLegalPages(facts) writes the four pages from
   them and nothing else. scripts/buildLegalPages.js writes the pages into the
   frontend; scripts/checkLegalPages.js fails when a page there differs from
   what this builds, or when a figure stops following its source.

   THE TRANSFER LIMITS ARE THE DEFAULTS. BFC_TRANSFER_MAX,
   BFC_TRANSFER_DAILY_CAP and BFC_TRANSFER_HOLD_DAYS can be set on the server;
   if one is, set the same figure here (rebuild) or the Terms will be wrong.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const legal = require("./legal");

const REPO = path.join(__dirname, "..");
const esc = legal.escapeHtml;

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
    "<title>" + esc(o.title) + " — BizForce AI</title>",
    '<meta name="description" content="' + esc(o.description) + '">',
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
      "You confirm you have the rights to what you upload."
    ]),

    h2("bizcash", "8. BizForce Market and the BizCash Member Trade Agreement"),
    p("BizForce Market lets members trade with each other: buying and selling listings, sending BizCash, and donating to campaigns. These rules apply to every trade."),
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
    description: "The terms for using BizForce AI: the " + money(f.price) + " per " + per + " subscription and its automatic renewal, refunds, acceptable use, AI output, and the BizCash Member Trade Agreement.",
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
      "We disclose data when the law requires it, or to protect members or BizForce from fraud or harm."
    ]),

    h2("protect", "4. How it is protected"),
    p("Exactly as the Your data page states it:"),
    ul(protections.map(function (x) { return x.text; })),

    h2("device", "5. On your device"),
    ul([
      "BizForce keeps your sign-in in your browser's own storage, and sets no cookies of its own. Signing out clears every BizForce key that belongs to you from this browser.",
      "Some preferences stay on the device after sign-out, such as the editor's colours and where panels sit; they hold nothing about your account."
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
    description: "What BizForce AI collects, why, which services it goes to, how it is protected, how long it is kept, your privacy rights including in California, and YouTube data.",
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
    description: "How to contact BizForce AI: email, postal address, and what to include for billing questions, data requests and abuse reports.",
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

module.exports = { codeFacts, buildLegalPages, money, bfc, num };
