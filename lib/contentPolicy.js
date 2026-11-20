"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   THE CONTENT POLICY SCREEN (P2-2, Nov 20 2026): one function for every text a
   member writes for others to read. In this order, the first refusal wins:

   (a) HEALTH CLAIMS: the existing claims screen, exactly as it is. server.js
       passes blueskyClaimsRefusal (findComplianceViolations and
       fdaRailViolations under the supplement profile, gate G7); this file never
       copies or changes its rules. Its own refusal sentence is used.
   (b) PROHIBITED ITEMS AND ADULT CONTENT: the fixed list below
       (PROHIBITED, owned by scripts/checkContentPolicy.js). A "refuse" term is
       refused; a "review" term is UNCLEAR: the text is saved and the item goes
       to the moderation queue (source policy_screen) for the owner to decide.
   (c) LINKS: at most MAX_LINKS (2), https only, no URL shorteners.
   (d) CONTACT DETAILS: no email address or phone number of anyone in PUBLIC
       text (members put their own on their business card). Not applied to a
       private message, which is between two members.
   (e) Every refusal is one clear sentence saying what to change.

   screen(text, opts) -> { ok: true, review: null }
                       | { ok: true, review: { findings: [...] } }   (unclear: save, then queue)
                       | { ok: false, status: 400, error, rule, matched, field }
   opts: { claims: function (text) -> null | { error, violations }, surface: "public" | "private", field }
   screenFields({ name: text, ... }, opts) runs screen on each and returns the first refusal, or every review finding.
   ══════════════════════════════════════════════════════════════════════════ */

const MAX_LINKS = 2;

/* What may not be sold, offered or shown on BizForce. Each term matches as whole words, any case. */
const PROHIBITED = [
  { category: "weapons", label: "Weapons and ammunition",
    refuse: ["firearm", "firearms", "handgun", "handguns", "rifle", "rifles", "shotgun", "shotguns", "ammunition", "ammo",
      "silencer", "suppressor", "ghost gun", "brass knuckles", "switchblade", "grenade", "grenades", "explosives"],
    review: ["knife", "knives", "crossbow", "pepper spray", "taser", "stun gun", "airsoft", "bb gun"] },
  { category: "drugs", label: "Drugs and drug paraphernalia",
    refuse: ["cocaine", "heroin", "methamphetamine", "meth", "fentanyl", "mdma", "ecstasy pills", "lsd", "magic mushrooms",
      "psilocybin", "ketamine", "crack pipe", "bong", "bongs", "dab rig"],
    review: ["cannabis", "marijuana", "weed", "thc", "cbd", "kratom", "delta-8", "edibles"] },
  { category: "prescription", label: "Prescription medicine",
    refuse: ["no prescription needed", "without a prescription", "prescription only", "oxycodone", "xanax", "adderall",
      "viagra", "cialis", "tramadol", "valium", "percocet", "vicodin", "ozempic", "semaglutide", "anabolic steroids"],
    review: ["prescription", "pharmaceutical", "antibiotics"] },
  { category: "tobacco", label: "Tobacco and vaping products",
    refuse: ["cigarettes", "cigars", "e-cigarette", "e-cigarettes", "vape", "vapes", "vaping", "e-liquid", "nicotine pouches",
      "chewing tobacco", "juul"],
    review: ["tobacco", "nicotine", "hookah"] },
  { category: "alcohol", label: "Alcohol sales",
    refuse: ["alcohol for sale", "liquor for sale", "beer for sale", "wine for sale"],
    review: ["wine", "beer", "liquor", "vodka", "whiskey", "whisky", "rum", "tequila", "moonshine", "alcohol"] },
  { category: "adult", label: "Adult sexual services and content",
    refuse: ["escort service", "escort services", "porn", "pornography", "sex work", "sexual services", "happy ending",
      "onlyfans", "nude photos", "nudes", "xxx", "adult content"],
    review: ["erotic", "sexy", "fetish", "lingerie photos"] },
  { category: "gambling", label: "Gambling",
    refuse: ["casino", "sports betting", "betting tips", "online gambling", "lottery tickets"],
    review: ["raffle", "lottery", "sweepstakes", "gambling"] },
  { category: "counterfeits", label: "Counterfeit and replica goods",
    refuse: ["counterfeit", "replica", "replicas", "fake id", "knockoff", "knockoffs", "first copy"],
    review: ["dupe", "dupes", "inspired by"] },
  { category: "animals", label: "Live animals",
    refuse: ["puppies for sale", "kittens for sale", "live animal", "live animals", "exotic pets"],
    review: ["puppy", "puppies", "kitten", "kittens", "for adoption", "livestock"] },
  { category: "recalled", label: "Recalled goods",
    refuse: ["recalled"],
    review: ["recall"] },
  { category: "personal_data", label: "Other people's personal data",
    refuse: ["social security number", "social security numbers", "ssn", "credit card numbers", "fullz", "personal data for sale",
      "database of emails"],
    review: ["email list", "phone list", "contact list", "leads list"] },
  { category: "guaranteed_returns", label: "Promises of risk-free or fixed investment returns",
    refuse: ["guaranteed returns", "guaranteed return", "guaranteed profit", "guaranteed profits", "risk-free investment",
      "double your money", "get rich quick"],
    review: ["forex signals", "crypto signals", "passive income"] }
];

/* Link shorteners hide where a link goes. */
const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
  "tiny.cc", "rb.gy", "s.id", "bl.ink", "t.ly", "lnkd.in", "v.gd", "shorte.st", "adf.ly", "tr.im"];

const MESSAGES = {
  prohibited: function (label, term) {
    return label + " can't be offered or shown on BizForce (it matched \"" + term + "\"). Take it out and try again. The Terms, Acceptable use, list what isn't allowed.";
  },
  tooManyLinks: "Use at most " + MAX_LINKS + " links. Take some out and try again.",
  notHttps: "Links must start with https://. Change the link and try again.",
  shortener: function (domain) { return "Link shorteners like " + domain + " aren't allowed, because they hide where a link goes. Use the full https:// address."; },
  contact: "Public text can't include an email address or phone number, yours or anyone else's. Put your own contact details on your business card instead.",
  notText: "That must be text."
};

function escapeRe(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
function termRe(term) {
  return new RegExp("(^|[^a-z0-9])" + escapeRe(term).replace(/\\-|-/g, "[-\\s]?").replace(/ /g, "\\s+") + "(?=$|[^a-z0-9])", "i");
}
const COMPILED = PROHIBITED.map(function (p) {
  return { category: p.category, label: p.label,
    refuse: p.refuse.map(function (t) { return { term: t, re: termRe(t) }; }),
    review: p.review.map(function (t) { return { term: t, re: termRe(t) }; }) };
});

const URL_RE = /\b(?:https?:\/\/|www\.)[^\s<>"')\]]+/gi;
const BARE_DOMAIN_RE = /(^|[\s(])([a-z0-9-]+(?:\.[a-z0-9-]+)+)\/[^\s<>"')\]]*/gi;
const EMAIL_RE = /[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}/i;
const PHONE_CANDIDATE_RE = /\+?\(?\d[\d\s().-]{7,}\d/g;

function hostOf(link) {
  var m = /^(?:https?:\/\/)?([^/?#:\s]+)/i.exec(link);
  return m ? m[1].toLowerCase().replace(/^www\./, "") : "";
}
function isShortener(host) {
  return SHORTENERS.some(function (s) { return host === s || host.slice(-(s.length + 1)) === "." + s; });
}

/* The links in a text, each as written. */
function findLinks(text) {
  return String(text || "").match(URL_RE) || [];
}

/* (b) */
function prohibitedFindings(text) {
  var refused = null, review = [];
  COMPILED.forEach(function (p) {
    if (refused) return;
    p.refuse.forEach(function (t) { if (!refused && t.re.test(text)) refused = { category: p.category, label: p.label, term: t.term }; });
    if (refused) return;
    p.review.forEach(function (t) { if (t.re.test(text)) review.push({ rule: "prohibited", category: p.category, term: t.term }); });
  });
  return { refused: refused, review: review };
}

/* (c) */
function linkRefusal(text) {
  var links = findLinks(text);
  for (var i = 0; i < links.length; i++) {
    if (/^http:\/\//i.test(links[i])) return { error: MESSAGES.notHttps, matched: links[i] };
  }
  var hosts = links.map(hostOf);
  var bare = [], m;
  BARE_DOMAIN_RE.lastIndex = 0;
  var withoutLinks = String(text).replace(URL_RE, " ");
  while ((m = BARE_DOMAIN_RE.exec(withoutLinks)) !== null) bare.push(m[2].toLowerCase());
  var shortener = hosts.concat(bare).filter(isShortener)[0];
  if (shortener) return { error: MESSAGES.shortener(shortener), matched: shortener };
  if (links.length > MAX_LINKS) return { error: MESSAGES.tooManyLinks, matched: links.length + " links" };
  return null;
}

/* (d) */
function contactRefusal(text) {
  var plain = String(text).replace(URL_RE, " ");
  var email = EMAIL_RE.exec(plain);
  if (email) return { error: MESSAGES.contact, matched: email[0] };
  var m;
  PHONE_CANDIDATE_RE.lastIndex = 0;
  while ((m = PHONE_CANDIDATE_RE.exec(plain)) !== null) {
    var digits = m[0].replace(/\D/g, "");
    if (digits.length >= 10 && digits.length <= 15) return { error: MESSAGES.contact, matched: m[0].trim() };
  }
  return null;
}

function screen(text, opts) {
  opts = opts || {};
  var field = opts.field || "text";
  if (text === undefined || text === null || text === "") return { ok: true, review: null };
  if (typeof text !== "string") return { ok: false, status: 400, error: MESSAGES.notText, rule: "type", matched: null, field: field };
  // (a) the existing claims screen, exactly as it is
  if (typeof opts.claims === "function") {
    var claims = opts.claims(text);
    if (claims) return { ok: false, status: 400, error: claims.error, rule: "health_claims", matched: (claims.violations || []).map(function (v) { return v.matched; }), field: field };
  }
  // (b)
  var p = prohibitedFindings(text);
  if (p.refused) return { ok: false, status: 400, error: MESSAGES.prohibited(p.refused.label, p.refused.term), rule: "prohibited", matched: p.refused.term, category: p.refused.category, field: field };
  // (c)
  var l = linkRefusal(text);
  if (l) return { ok: false, status: 400, error: l.error, rule: "links", matched: l.matched, field: field };
  // (d) public text only
  if (opts.surface !== "private") {
    var c = contactRefusal(text);
    if (c) return { ok: false, status: 400, error: c.error, rule: "contact", matched: c.matched, field: field };
  }
  return { ok: true, review: p.review.length ? { findings: p.review.map(function (f) { return Object.assign({ field: field }, f); }) } : null };
}

function screenFields(fields, opts) {
  var findings = [];
  var names = Object.keys(fields || {});
  for (var i = 0; i < names.length; i++) {
    var value = fields[names[i]];
    var texts = Array.isArray(value) ? value : [value];
    for (var j = 0; j < texts.length; j++) {
      if (texts[j] === undefined || texts[j] === null || texts[j] === "") continue;
      var r = screen(typeof texts[j] === "string" ? texts[j] : String(texts[j]), Object.assign({}, opts, { field: names[i] }));
      if (!r.ok) return r;
      if (r.review) findings = findings.concat(r.review.findings);
    }
  }
  return { ok: true, review: findings.length ? { findings: findings } : null };
}

/* The answer a route sends for a refusal. */
function refusalBody(r) {
  return { error: r.error, reason: "content_policy", rule: r.rule, field: r.field };
}

module.exports = { MAX_LINKS, PROHIBITED, SHORTENERS, MESSAGES, screen, screenFields, refusalBody, findLinks, prohibitedFindings, linkRefusal, contactRefusal };
