// ── Member support: external donation links, and the support note ──────────
//
// A member may list up to five links where people can pay them DIRECTLY:
// PayPal.Me, Cash App, Venmo, Ko-fi, Buy Me a Coffee, Patreon or a Stripe
// payment link. BizForce never handles that money: the link opens the
// provider's own page, and every place a link is shown says so (DISCLAIMER).
//
// ALLOW-LISTED, NEVER FREE-FORM. A link is accepted only as one of the
// patterns below, written out in full: https, the provider's exact host (or
// its www. form where the provider serves one), one path of the provider's
// own shape, and the handle in that provider's character set. No query
// string, no fragment, no further path segment, no port, no user:password@,
// nothing but printable ASCII (so a Unicode look-alike of a host can never
// match). The member may type the full link or just the handle.
//
// STORED NORMALIZED. What is stored is { provider, handle } and nothing else;
// the URL is REBUILT from those two every time it is shown (urlFor), so no
// text the member typed is ever an href.
//
// THE NOTE on a BizCash support payment: plain text, at most 140 characters,
// control characters refused, whitespace collapsed, then stored HTML-escaped.
// It is shown only to the two members, in their own trade records and in the
// recipient's notification.

var MAX_LINKS = 5;
var NOTE_MAX = 140;
var HEADLINE_MAX = 120;

var PROVIDERS = {
  paypal: {
    label: "PayPal",
    hosts: ["paypal.me", "www.paypal.me"],
    // PayPal.Me names: letters and digits, 1 to 20.
    handle: /^[A-Za-z0-9]{1,20}$/,
    paths: [/^\/([^/]+)\/?$/],
    url: function (h) { return "https://paypal.me/" + h; },
    example: "paypal.me/yourname"
  },
  cashapp: {
    label: "Cash App",
    hosts: ["cash.app"],
    // A $Cashtag: letters and digits, 1 to 20, at least one letter.
    handle: /^(?=[A-Za-z0-9]*[A-Za-z])[A-Za-z0-9]{1,20}$/,
    paths: [/^\/\$([^/]+)\/?$/],
    url: function (h) { return "https://cash.app/$" + h; },
    strip: /^\$/,
    example: "cash.app/$yourname"
  },
  venmo: {
    label: "Venmo",
    hosts: ["venmo.com", "www.venmo.com", "account.venmo.com"],
    // Venmo usernames: letters, digits, hyphens and underscores, 5 to 30.
    handle: /^[A-Za-z0-9_-]{5,30}$/,
    paths: [/^\/u\/([^/]+)\/?$/, /^\/([^/]+)\/?$/],
    url: function (h) { return "https://venmo.com/u/" + h; },
    strip: /^@/,
    reserved: ["u", "signup", "login", "about", "legal", "pay", "account", "business", "privacy"],
    example: "venmo.com/u/your-name"
  },
  kofi: {
    label: "Ko-fi",
    hosts: ["ko-fi.com", "www.ko-fi.com"],
    // Ko-fi page names: letters, digits and underscores, 1 to 40.
    handle: /^[A-Za-z0-9_]{1,40}$/,
    paths: [/^\/([^/]+)\/?$/],
    url: function (h) { return "https://ko-fi.com/" + h; },
    reserved: ["home", "manage", "account", "explore", "login", "signup"],
    example: "ko-fi.com/yourname"
  },
  buymeacoffee: {
    label: "Buy Me a Coffee",
    hosts: ["buymeacoffee.com", "www.buymeacoffee.com"],
    // Buy Me a Coffee pages: letters, digits and underscores, 1 to 50.
    handle: /^[A-Za-z0-9_]{1,50}$/,
    paths: [/^\/([^/]+)\/?$/],
    url: function (h) { return "https://buymeacoffee.com/" + h; },
    reserved: ["dashboard", "login", "signup", "explore", "about", "privacy-policy", "terms"],
    example: "buymeacoffee.com/yourname"
  },
  patreon: {
    label: "Patreon",
    hosts: ["patreon.com", "www.patreon.com"],
    // Patreon vanity names: letters, digits and underscores, 1 to 64.
    handle: /^[A-Za-z0-9_]{1,64}$/,
    paths: [/^\/([^/]+)\/?$/],
    url: function (h) { return "https://patreon.com/" + h; },
    reserved: ["home", "login", "signup", "explore", "search", "settings", "messages", "c", "policy", "about"],
    example: "patreon.com/yourname"
  },
  stripe: {
    label: "Stripe",
    hosts: ["buy.stripe.com"],
    // A live Stripe payment link's id: letters and digits, 8 to 40. Test links
    // (test_…) take no real payment, so they are refused.
    handle: /^[A-Za-z0-9]{8,40}$/,
    paths: [/^\/([^/]+)\/?$/],
    url: function (h) { return "https://buy.stripe.com/" + h; },
    example: "buy.stripe.com/abc123XYZ456"
  }
};
var PROVIDER_KEYS = Object.keys(PROVIDERS);

function disclaimer(providerLabel) {
  return "Payments go directly to this member through " + providerLabel + ". BizForce does not handle, hold or refund them.";
}

function refusal(reason, error) { return { error: error, reason: reason }; }

/* One link, as the member gave it: { provider, value } where value is the
   full link or the handle. -> { link: { provider, handle } } or { error, reason }. */
function normalizeLink(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return refusal("invalid_link", "Each support link must name a provider and a link or handle.");
  var key = typeof input.provider === "string" ? input.provider.trim().toLowerCase() : "";
  var p = PROVIDERS[key];
  if (!p) return refusal("unknown_provider", "Support links can be PayPal, Cash App, Venmo, Ko-fi, Buy Me a Coffee, Patreon or Stripe.");
  var raw = typeof input.value === "string" ? input.value.trim() : "";
  if (!raw) return refusal("missing_value", "Give your " + p.label + " link or handle.");
  if (raw.length > 200) return refusal("too_long", "That " + p.label + " link is too long.");
  // Printable ASCII only: a Unicode look-alike (a Cyrillic а, a full-width dot) never matches.
  if (!/^[\x21-\x7e]+$/.test(raw)) return refusal("not_ascii", "A " + p.label + " link can only use plain letters, digits and the usual URL punctuation, with no spaces.");
  var handle = null;
  if (/^[a-z][a-z0-9+.-]*:/i.test(raw) || raw.indexOf("/") !== -1 || raw.indexOf(".") !== -1) {
    handle = handleFromUrl(p, raw);
    if (handle && handle.error) return handle;
  } else {
    handle = p.strip ? raw.replace(p.strip, "") : raw;
  }
  if (!p.handle.test(handle)) return refusal("invalid_handle", "\"" + handle.slice(0, 60) + "\" is not a valid " + p.label + " name. Use the form " + p.example + ".");
  if (p.reserved && p.reserved.indexOf(handle.toLowerCase()) !== -1) return refusal("invalid_handle", "\"" + handle + "\" is a " + p.label + " page, not a member's name. Use the form " + p.example + ".");
  return { link: { provider: key, handle: handle } };
}

/* The handle from a full link, or the refusal saying what is wrong with it. */
function handleFromUrl(p, raw) {
  var withScheme = /^https?:\/\//i.test(raw) ? raw : (/^[a-z][a-z0-9+.-]*:/i.test(raw) ? raw : "https://" + raw);
  var m = /^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)([^?#]*)(.*)$/i.exec(withScheme);
  if (!m) return refusal("invalid_url", "That is not a " + p.label + " link. Use the form " + p.example + ".");
  if (m[1].toLowerCase() !== "https") return refusal("not_https", "A support link must start with https://.");
  var host = m[2].toLowerCase();
  if (host.indexOf("@") !== -1 || host.indexOf(":") !== -1) return refusal("invalid_host", "A " + p.label + " link cannot carry a login or a port.");
  if (p.hosts.indexOf(host) === -1) return refusal("wrong_host", host + " is not " + p.label + "'s site. Use the form " + p.example + ".");
  if (m[4]) return refusal("extra_parts", "Leave off anything after the name (a ? or # part) in a " + p.label + " link.");
  for (var i = 0; i < p.paths.length; i++) {
    var pm = p.paths[i].exec(m[3]);
    if (pm) return pm[1];
  }
  return refusal("invalid_path", "A " + p.label + " link has just your name after the site. Use the form " + p.example + ".");
}

/* The whole list. -> { links } or { error, reason, field }. Duplicates are refused. */
function normalizeLinks(list) {
  if (list === undefined || list === null) return { links: [] };
  if (!Array.isArray(list)) return Object.assign(refusal("invalid_links", "Support links must be a list."), { field: "links" });
  if (list.length > MAX_LINKS) return Object.assign(refusal("too_many_links", "At most " + MAX_LINKS + " support links."), { field: "links" });
  var out = [], seen = {};
  for (var i = 0; i < list.length; i++) {
    var r = normalizeLink(list[i]);
    if (r.error) return Object.assign(r, { field: "links[" + i + "]" });
    var k = r.link.provider + ":" + r.link.handle.toLowerCase();
    if (seen[k]) return Object.assign(refusal("duplicate_link", "That " + PROVIDERS[r.link.provider].label + " link is listed twice."), { field: "links[" + i + "]" });
    seen[k] = true;
    out.push(r.link);
  }
  return { links: out };
}

/* A stored link as it is shown: the URL rebuilt from provider and handle.
   A stored row that no longer passes the rules is not shown at all. */
function publicLink(stored) {
  var p = stored && PROVIDERS[stored.provider];
  if (!p || typeof stored.handle !== "string" || !p.handle.test(stored.handle)) return null;
  return { provider: stored.provider, label: p.label, handle: stored.handle, url: p.url(stored.handle), disclaimer: disclaimer(p.label) };
}
function publicLinks(stored) {
  return (Array.isArray(stored) ? stored : []).map(publicLink).filter(Boolean).slice(0, MAX_LINKS);
}

/* ── text ──────────────────────────────────────────────────────────────── */
function escapeHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function unescapeHtml(s) {
  return String(s).replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, "\"").replace(/&#39;/g, "'").replace(/&amp;/g, "&");
}
/* Plain text of at most `max` characters: control characters refused,
   whitespace runs collapsed. -> { text } (null when blank) or { error, reason }. */
function plainText(raw, max, what) {
  if (raw === undefined || raw === null) return { text: null };
  if (typeof raw !== "string") return refusal("invalid_" + what, "The " + what + " must be text.");
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f​-‏‪-‮⁦-⁩]/.test(raw)) return refusal("invalid_" + what, "The " + what + " cannot contain control characters.");
  var t = raw.replace(/\s+/g, " ").trim();
  if (!t) return { text: null };
  if (Array.from(t).length > max) return refusal(what + "_too_long", "The " + what + " can be at most " + max + " characters.");
  return { text: t };
}
/* The support note as stored: plain text, escaped. */
function noteForStorage(raw) {
  var r = plainText(raw, NOTE_MAX, "note");
  if (r.error) return r;
  return { note: r.text === null ? null : escapeHtml(r.text) };
}
function headlineFrom(raw) {
  var r = plainText(raw, HEADLINE_MAX, "headline");
  if (r.error) return r;
  return { headline: r.text };
}

/* Is a member's support page on? Off until they add a link or turn it on;
   an explicit off always wins. */
function pageIsOn(row) {
  if (!row) return false;
  if (row.page_on === false) return false;
  if (row.page_on === true) return true;
  return publicLinks(row.links).length > 0;
}

var SITE = "https://bizforceai.net";
function supportUrl(username) { return SITE + "/support/" + encodeURIComponent(String(username).toLowerCase()); }

module.exports = {
  PROVIDERS, PROVIDER_KEYS, MAX_LINKS, NOTE_MAX, HEADLINE_MAX, SITE,
  disclaimer, normalizeLink, normalizeLinks, publicLink, publicLinks,
  escapeHtml, unescapeHtml, plainText, noteForStorage, headlineFrom, pageIsOn, supportUrl
};
