/* ══════════════════════════════════════════════════════════════════════════
   lib/legal.js — who runs BizForce, where to write, and which Terms are in
   force. The one copy.

   Every legal page (terms, privacy, refund and contact, built from this file
   by lib/legalPages.js), every email footer (sendEmail and sendMarketingEmail
   in server.js) and the sign-up acceptance (POST /api/auth/register, GET and
   POST /api/me/terms) read these values. No other file in either repo holds
   the postal address or the contact address; scripts/checkLegalPages.js fails
   when one does.

   Operator: "BizForceAI" is a fictitious business name. No personal name is
   stated anywhere, on purpose.

   CHANGING THE TERMS. Edit the wording in lib/legalPages.js, set
   TERMS_VERSION and TERMS_UPDATED to the new date, and run
   node scripts/buildLegalPages.js to rewrite the four frontend pages. A member
   whose recorded terms_version is older than TERMS_VERSION sees the
   "We've updated our Terms" notice once, until they accept.
   ══════════════════════════════════════════════════════════════════════════ */

const OPERATOR = "BizForceAI";
const OPERATOR_NOTE = "a fictitious business name";

const ADDRESS_LINES = [
  "BizForceAI",
  "34366 Yucaipa Blvd. Ste. C #594",
  "Yucaipa, CA 92399",
  "United States"
];
const POSTAL_ADDRESS = ADDRESS_LINES.join(", ");

const CONTACT_EMAIL = "support@bizforceai.net";

const GOVERNING_LAW = "California, USA";
const GOVERNING_STATE = "California";
const MINIMUM_AGE = 18;

const REFUND_POLICY = [
  "You can cancel any time.",
  "Your access continues to the end of the period you have already paid for.",
  "There are no partial or prorated refunds."
];

const TERMS_VERSION = "2026-10-30";
const TERMS_UPDATED = "Last updated October 30, 2026";

// The paths the shared footer and every page link to.
const PAGES = {
  terms: "/terms",
  privacy: "/privacy",
  refund: "/refund",
  contact: "/contact",
  yourData: "/your-data.html"
};

// What the sign-up box says. The server refuses registration unless the box
// was ticked, and records TERMS_VERSION with the time.
const ACCEPT_LABEL = "I am " + MINIMUM_AGE + " or older and agree to the Terms and Privacy Policy";

function escapeHtml(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

/* The line every transactional email ends with (verification, password
   reset, consent confirmation): where to write, and the postal address. */
function contactFooter() {
  const line = "Questions? Write to " + CONTACT_EMAIL + ".";
  return {
    html: '<div style="margin-top:28px;padding-top:14px;border-top:1px solid #e5e5ef;font-size:12px;line-height:1.6;color:#6b6b80">' +
      '<p style="margin:0">' + escapeHtml(line) + '</p>' +
      '<p style="margin:0">' + escapeHtml(POSTAL_ADDRESS) + '</p>' +
      '</div>',
    text: "\n\n--\n" + line + "\n" + POSTAL_ADDRESS
  };
}

/* The footer every marketing email carries: why it came, a working
   unsubscribe link and the postal address, in both bodies. */
function marketingFooter(unsubscribeUrl) {
  const why = "You are receiving this because you asked to hear from us.";
  return {
    html: '<div style="margin-top:32px;padding-top:16px;border-top:1px solid #e5e5ef;font-size:12px;line-height:1.6;color:#6b6b80">' +
      '<p style="margin:0 0 8px">' + escapeHtml(why) + ' ' +
      '<a href="' + escapeHtml(unsubscribeUrl) + '" style="color:#6b6b80">Unsubscribe</a></p>' +
      '<p style="margin:0">' + ADDRESS_LINES.map(escapeHtml).join("<br>") + '</p>' +
      '<p style="margin:8px 0 0">' + escapeHtml("Questions? Write to " + CONTACT_EMAIL + ".") + '</p>' +
      '</div>',
    text: "\n\n--\n" + why + "\n" + "Unsubscribe: " + unsubscribeUrl + "\n" + ADDRESS_LINES.join("\n") +
      "\nQuestions? Write to " + CONTACT_EMAIL + "."
  };
}

/* Whether a recorded version is the one in force. A missing or older version
   needs acceptance; versions are ISO dates, so they compare as strings. */
function needsAcceptance(recordedVersion) {
  return typeof recordedVersion !== "string" || recordedVersion < TERMS_VERSION;
}

module.exports = {
  OPERATOR, OPERATOR_NOTE, ADDRESS_LINES, POSTAL_ADDRESS, CONTACT_EMAIL, GOVERNING_LAW, GOVERNING_STATE, MINIMUM_AGE,
  REFUND_POLICY, TERMS_VERSION, TERMS_UPDATED, PAGES, ACCEPT_LABEL,
  escapeHtml, contactFooter, marketingFooter, needsAcceptance
};
