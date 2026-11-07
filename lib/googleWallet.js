"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   Google Wallet pass for a digital card (build list item 6, part 2, Nov 6
   2026). A visitor on Android taps "Add to Google Wallet" on a public card;
   GET /api/cards/google-wallet answers 302 to Google's "Save to Google
   Wallet" link, https://pay.google.com/gp/v/save/<JWT>. Apple Wallet is out
   of scope.

   OFFLINE. The JWT carries one shared generic class and the card's object
   inside it, signed RS256 with the Google service account's private key, so
   BizForce makes no Google API call at any time. A saved pass cannot be
   changed afterwards; its card link shows "Card not found" once the card is
   gone or its owner has lapsed (the Privacy Policy says so).

   ONLY WHAT THE CARD SHOWS. buildObject takes publicCardFrom's output, in
   which a hidden email or phone is already "": a pass never holds more than
   the public card. The photo goes in only when the card shows it
   (show_photo === true) AND it is in this project's bf-public bucket;
   otherwise the pass shows BizForce's logo. The object id is
   "<issuer>.c" + the first 32 hex of HMAC-SHA256(k, card id), where k is
   HKDF-SHA256 of JWT_SECRET with the info "bizforce-wallet-object-v1": stable
   per card, and no BizForce id leaves the server.

   CONFIGURATION, read once and cached: GOOGLE_WALLET_ISSUER_ID (10 to 25
   digits), GOOGLE_WALLET_SA_EMAIL (a service account address, ending
   .iam.gserviceaccount.com) and GOOGLE_WALLET_SA_KEY (its private_key, PKCS#8
   PEM; a literal backslash-n as written in the JSON key file is a newline),
   plus JWT_SECRET for the object ids. Anything missing or invalid is "not
   configured": logged once with a code, never the value, and never a crash.
   The RS256 key signs only this JWT. It is never given to jwt.verify, and
   JWT_SECRET stays the only session key.

   scripts/checkGoogleWallet.js holds all of this.
   ══════════════════════════════════════════════════════════════════════════ */

const crypto = require("crypto");

const ISSUER_RE = /^[0-9]{10,25}$/;
const SA_SUFFIX = ".iam.gserviceaccount.com";
const SA_EMAIL_MAX = 254;
const KEY_BEGIN = "-----BEGIN PRIVATE KEY-----";
const CLASS_SUFFIX = "bizforce_card_v1";
const OBJECT_INFO = "bizforce-wallet-object-v1";
const SAVE_URL = "https://pay.google.com/gp/v/save/";
const ORIGINS = ["https://bizforceai.net"];
const CARD_TITLE = "BizForceAI Card";
const LOGO_URL = "https://bizforceai.net/icons/icon-512.png";
const BF_PUBLIC_PATH = "/storage/v1/object/public/bf-public/";
const LANGUAGE = "en-US";
const HEADER_MAX = 100;
const TEXT_MAX = 200;
const THEME_HEX = Object.freeze({ dark: "#0c1228", midnight: "#1a1040", forest: "#0a1f14", ember: "#220e06" });

const MESSAGES = Object.freeze({
  notConfigured: "Google Wallet isn't set up yet.",
  notFound: "Card not found",
  badRef: "A Google Wallet link names a card by its short link or share token."
});

const deps = {
  sign: function (claims, key) { return require("jsonwebtoken").sign(claims, key, { algorithm: "RS256" }); },
  log: function (line) { console.log(line); }
};

/* The configuration from env, or { error: code }. Never returns or logs a value. */
function loadConfig(env) {
  env = env || {};
  var issuer = typeof env.GOOGLE_WALLET_ISSUER_ID === "string" ? env.GOOGLE_WALLET_ISSUER_ID.trim() : "";
  var email = typeof env.GOOGLE_WALLET_SA_EMAIL === "string" ? env.GOOGLE_WALLET_SA_EMAIL.trim() : "";
  var rawKey = typeof env.GOOGLE_WALLET_SA_KEY === "string" ? env.GOOGLE_WALLET_SA_KEY : "";
  var jwtSecret = typeof env.JWT_SECRET === "string" ? env.JWT_SECRET : "";
  if (!issuer && !email && !rawKey) return { error: "missing" };
  if (!ISSUER_RE.test(issuer)) return { error: "issuer_id" };
  if (email.length > SA_EMAIL_MAX || !/^[^\s@]+@[^\s@]+$/.test(email) || email.slice(-SA_SUFFIX.length) !== SA_SUFFIX) return { error: "sa_email" };
  var pem = rawKey.split("\\n").join("\n").trim();
  if (pem.indexOf(KEY_BEGIN) !== 0) return { error: "sa_key_format" };
  var key;
  try {
    key = crypto.createPrivateKey({ key: pem, format: "pem" });
  } catch (err) {
    return { error: "sa_key_unreadable" };
  }
  if (key.asymmetricKeyType !== "rsa") return { error: "sa_key_type" };
  if (!jwtSecret) return { error: "jwt_secret" };
  var photoPrefix = null;
  try {
    var host = new URL(String(env.SUPABASE_URL || "")).host;
    if (host) photoPrefix = "https://" + host + BF_PUBLIC_PATH;
  } catch (err) {
    photoPrefix = null;
  }
  return {
    config: Object.freeze({ issuerId: issuer, saEmail: email, key: key, jwtSecret: jwtSecret, photoPrefix: photoPrefix, classId: issuer + "." + CLASS_SUFFIX })
  };
}

var cached;
/* The configuration from process.env, read once; null when not configured. */
function config() {
  if (cached === undefined) {
    var loaded = loadConfig(process.env);
    cached = loaded.config || null;
    if (!cached) deps.log("[google-wallet] not configured: " + loaded.error);
  }
  return cached;
}
/* For scripts/checkGoogleWallet.js: read process.env again on the next config(). */
function resetConfig() { cached = undefined; }

/* "<issuer>.c" + the first 32 hex of HMAC-SHA256(HKDF(JWT_SECRET), card id). */
function objectIdFor(cardId, jwtSecret, issuer) {
  var k = Buffer.from(crypto.hkdfSync("sha256", String(jwtSecret), Buffer.alloc(0), OBJECT_INFO, 32));
  return issuer + ".c" + crypto.createHmac("sha256", k).update(String(cardId)).digest("hex").slice(0, 32);
}

function themeHex(theme) {
  return Object.prototype.hasOwnProperty.call(THEME_HEX, theme) ? THEME_HEX[theme] : THEME_HEX.dark;
}

/* The owner's photo when the card shows it and it is this project's bf-public object; else null (the logo). */
function passPhoto(row, photoUrl, photoPrefix) {
  if (!row || row.show_photo !== true || !photoPrefix) return null;
  var url = typeof photoUrl === "string" ? photoUrl : "";
  if (url.indexOf(photoPrefix) !== 0 || url.length === photoPrefix.length || /[\s"'<>\\]/.test(url)) return null;
  return url;
}

/* The same rule as the frontend's scripts/bf-card.js qrUrl (scripts/checkGoogleWallet.js holds them equal). */
function qrValue(url) {
  if (!url) return null;
  var u = String(url);
  return u + (u.indexOf("?") === -1 ? "?" : "&") + "via=qr";
}

/* Server copies of bf-card.js telHref and mailtoHref, held equal by scripts/checkGoogleWallet.js. */
function telHref(phone) {
  var raw = String(phone || "").trim();
  var digits = raw.replace(/[^0-9]/g, "");
  if (digits.length < 3) return null;
  return "tel:" + (raw.charAt(0) === "+" ? "+" : "") + digits;
}
function mailtoHref(email) {
  var e = String(email || "").trim();
  if (!/^[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+$/.test(e)) return null;
  return "mailto:" + e;
}

/* At most n characters (code points), trimmed. */
function clip(value, n) {
  return Array.from(String(value == null ? "" : value).trim()).slice(0, n).join("");
}
function localized(value) { return { defaultValue: { language: LANGUAGE, value: value } }; }
function webLink(website) {
  var w = String(website || "").trim();
  if (w.length > 500 || !/^https?:\/\/[^\s"'<>\\]+$/.test(w)) return null;
  try { return new URL(w).hostname ? w : null; } catch (err) { return null; }
}

/* The genericObject for one public card (publicCardFrom's output) and its row (id, show_photo, theme). Null without a public URL. */
function buildObject(card, row, cfg) {
  if (!card || !row || !card.public_url || !cfg) return null;
  var photo = passPhoto(row, card.photo_url, cfg.photoPrefix);
  var object = {
    id: objectIdFor(row.id, cfg.jwtSecret, cfg.issuerId),
    classId: cfg.classId,
    state: "ACTIVE",
    cardTitle: localized(CARD_TITLE),
    header: localized(clip(card.full_name, HEADER_MAX) || CARD_TITLE)
  };
  var title = clip(card.job_title, HEADER_MAX);
  if (title) object.subheader = localized(title);
  object.hexBackgroundColor = themeHex(row.theme);
  object.logo = { sourceUri: { uri: photo || LOGO_URL }, contentDescription: localized(photo ? "Photo" : "BizForceAI logo") };
  object.barcode = { type: "QR_CODE", value: qrValue(card.public_url) };
  var texts = [];
  [["company", "Company", card.company], ["email", "Email", card.email], ["phone", "Phone", card.phone], ["website", "Website", card.website]].forEach(function (t) {
    var body = clip(t[2], TEXT_MAX);
    if (body) texts.push({ id: t[0], header: t[1], body: body });
  });
  if (texts.length) object.textModulesData = texts;
  var uris = [{ id: "card", uri: card.public_url, description: "Open card" }];
  var site = webLink(card.website);
  if (site) uris.push({ id: "website", uri: site, description: "Website" });
  var mail = mailtoHref(card.email);
  if (mail) uris.push({ id: "email", uri: mail, description: "Email" });
  var tel = telHref(card.phone);
  if (tel) uris.push({ id: "phone", uri: tel, description: "Call" });
  object.linksModuleData = { uris: uris };
  return object;
}

/* The "Save to Google Wallet" link for one object, signed RS256 now. */
function saveUrl(object, cfg, nowMs) {
  var claims = {
    iss: cfg.saEmail,
    aud: "google",
    typ: "savetowallet",
    iat: Math.floor(nowMs / 1000),
    origins: ORIGINS.slice(),
    payload: { genericClasses: [{ id: cfg.classId }], genericObjects: [object] }
  };
  return SAVE_URL + deps.sign(claims, cfg.key);
}

module.exports = {
  ISSUER_RE, SA_SUFFIX, KEY_BEGIN, CLASS_SUFFIX, OBJECT_INFO, SAVE_URL, ORIGINS, CARD_TITLE, LOGO_URL, BF_PUBLIC_PATH, HEADER_MAX, TEXT_MAX, THEME_HEX,
  MESSAGES, deps,
  loadConfig, config, resetConfig, objectIdFor, themeHex, passPhoto, qrValue, telHref, mailtoHref, clip, buildObject, saveUrl
};
