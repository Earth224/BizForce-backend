"use strict";

/* ══════════════════════════════════════════════════════════════════════════
   CONNECT AMAZON, the Selling Partner API with the website authorization
   workflow and Login with Amazon (LWA) tokens (migration 182).
   A member connects their own Amazon seller account, in ONE marketplace they
   choose before leaving, to the Store agent. BizForce's SP-API app is named by
   AMAZON_SPAPI_APP_ID; its LWA client is AMAZON_LWA_CLIENT_ID and
   AMAZON_LWA_CLIENT_SECRET, which stay on the server. AMAZON_SPAPI_DRAFT,
   unset or anything but "false", means the app is still a draft: the consent
   page is asked with version=beta, and only the seller account that
   registered the app can approve it.

   THE FLOW (server.js, the store section).
     1. POST /api/store/amazon/start { marketplace_id, allow_changes } (a
        signed-in member): the marketplace must be one of MARKETPLACES; its
        region follows from the table. A one-time state (newState); only its
        sha256 (stateHash) is stored, in oauth_states, purpose store_amazon,
        with flow_context { marketplace_id, region, permission }, for
        STATE_TTL_MS. There is no PKCE in this workflow, so no verifier. The
        member is sent to consentUrl: the chosen marketplace's own Seller
        Central host, /apps/authorize/consent.
     2. Amazon sends the browser back to the app's registered redirect, the
        Store Agent page (FRONTEND_URL + "/store-agent.html"), with
        spapi_oauth_code, state and selling_partner_id. The page POSTs all
        three to /api/store/amazon/finish, a requireAuth route, so the code is
        bound to the signed-in member; finishShape checks their shapes, and
        the state row is consumed by one conditional update.
     3. exchangeCode sends the code to LWA as a form; both tokens are sealed
        before lib/amazonApi.js asks the SP-API anything; the seller's
        marketplace participations are read, and the chosen marketplace must
        be one the seller sells in.

   AMAZON'S RULES THIS FOLLOWS (from Amazon's SP-API documentation as the
   build brief states them; not checked against Amazon in this build, which
   made no call to Amazon):
     - the LWA token endpoint is https://api.amazon.com/auth/o2/token and
       takes a form body: grant_type authorization_code with code, client_id
       and client_secret; grant_type refresh_token with refresh_token,
       client_id and client_secret;
     - the access token lasts expires_in seconds (about an hour); the refresh
       token does not expire unless the seller revokes it, so
       refresh_expires_at stays NULL; an answer of invalid_grant means the
       access is gone, and the member connects again;
     - the SP-API is reached at the region's own endpoint (REGION_ENDPOINTS)
       with the header x-amz-access-token, and no request signing.

   ALL I/O is the caller's guarded JSON request (lib/guardedFetch.js
   guardedJsonRequest: https on 443 only, every address checked, no redirect
   followed). Nothing here logs, and no token, code or secret is ever put into
   an error, a result a member sees, or a log line. An AmazonAuthError carries
   only a kind and a short code.
   ══════════════════════════════════════════════════════════════════════════ */

const crypto = require("crypto");

const TOKEN_URL = "https://api.amazon.com/auth/o2/token";
const CONSENT_PATH = "/apps/authorize/consent";
const PURPOSE = "store_amazon";
const STATE_TTL_MS = 10 * 60 * 1000;
const STATE_RE = /^[A-Za-z0-9_-]{43}$/;
const SELLER_ID_RE = /^[A-Z0-9]{8,20}$/;
const MARKETPLACE_ID_RE = /^[A-Z0-9]{8,20}$/;
const CODE_MAX = 2048;
const TOKEN_TIMEOUT_MS = 15 * 1000;
/* An access token is stored as expiring this much before Amazon says it does. */
const EXPIRY_SLACK_MS = 60 * 1000;
/* A token this close to its stored expiry is refreshed before use. */
const REFRESH_MARGIN_MS = 5 * 60 * 1000;

/* The SP-API endpoint of each region. */
const REGION_ENDPOINTS = Object.freeze({
  na: "https://sellingpartnerapi-na.amazon.com",
  eu: "https://sellingpartnerapi-eu.amazon.com",
  fe: "https://sellingpartnerapi-fe.amazon.com"
});
const REGION_LABEL = Object.freeze({ na: "North America", eu: "Europe", fe: "Far East" });

const EU_CENTRAL = "sellercentral-europe.amazon.com";
function market(code, region, sellerCentral, storefront) {
  return Object.freeze({ code: code, region: region, sellerCentral: sellerCentral, storefront: storefront });
}
/* Every marketplace a member can choose: its id, then its two-letter code,
   its region, its Seller Central host and its storefront host.
   scripts/checkAmazonConnect.js holds this table equal to the build brief's. */
const MARKETPLACES = Object.freeze({
  ATVPDKIKX0DER: market("US", "na", "sellercentral.amazon.com", "www.amazon.com"),
  A2EUQ1WTGCTBG2: market("CA", "na", "sellercentral.amazon.ca", "www.amazon.ca"),
  A1AM78C64UM0Y8: market("MX", "na", "sellercentral.amazon.com.mx", "www.amazon.com.mx"),
  A2Q3Y263D00KWC: market("BR", "na", "sellercentral.amazon.com.br", "www.amazon.com.br"),
  A1F83G8C2ARO7P: market("UK", "eu", EU_CENTRAL, "www.amazon.co.uk"),
  A1PA6795UKMFR9: market("DE", "eu", EU_CENTRAL, "www.amazon.de"),
  A13V1IB3VIYZZH: market("FR", "eu", EU_CENTRAL, "www.amazon.fr"),
  APJ6JRA9NG5V4: market("IT", "eu", EU_CENTRAL, "www.amazon.it"),
  A1RKKUPIHCS9HS: market("ES", "eu", EU_CENTRAL, "www.amazon.es"),
  A1805IZSGTT6HS: market("NL", "eu", EU_CENTRAL, "www.amazon.nl"),
  A2NODRKZP88ZB9: market("SE", "eu", EU_CENTRAL, "www.amazon.se"),
  A1C3SOZRARQ6R3: market("PL", "eu", EU_CENTRAL, "www.amazon.pl"),
  AMEN7PMS3EDWL: market("BE", "eu", EU_CENTRAL, "www.amazon.com.be"),
  A33AVAJ2PDY3EV: market("TR", "eu", "sellercentral.amazon.com.tr", "www.amazon.com.tr"),
  A2VIGQ35RCS4UG: market("AE", "eu", "sellercentral.amazon.ae", "www.amazon.ae"),
  A17E79C6D8DWNP: market("SA", "eu", "sellercentral.amazon.sa", "www.amazon.sa"),
  A21TJRUUN4KGV: market("IN", "eu", "sellercentral.amazon.in", "www.amazon.in"),
  A1VC38T7YXB528: market("JP", "fe", "sellercentral.amazon.co.jp", "www.amazon.co.jp"),
  A39IBJ37TRP1C6: market("AU", "fe", "sellercentral.amazon.com.au", "www.amazon.com.au"),
  A19VAU5U5O7RUS: market("SG", "fe", "sellercentral.amazon.sg", "www.amazon.sg")
});

const MESSAGES = Object.freeze({
  notConfigured: "Amazon connection isn't set up yet.",
  marketplace: "Choose the Amazon marketplace you sell in.",
  stateInvalid: "That Amazon connection link has expired or was already used. Start again.",
  notParticipating: "Your seller account doesn't sell in that marketplace. Choose another and connect again.",
  takenByOther: "This Amazon seller account and marketplace are already connected to another BizForce account.",
  unreachable: "BizForce could not finish connecting your Amazon seller account just now. Try again later. Nothing was saved.",
  noSecret: "Stores can't be connected on this server just now: its encryption key is not set. Nothing was sent to your store and nothing was saved.",
  useConnect: "Use Connect Amazon on the Store Agent page.",
  consent: "You approve BizForce on Amazon Seller Central's own page. BizForce never sees your Amazon password.",
  draft: "Until Amazon approves BizForce, only the account that registered BizForce can connect.",
  disconnected: "Disconnected. To remove BizForce from Amazon too, open Seller Central, then Apps and Services, then Manage Your Apps."
});

const deps = {
  request: function (url, options) { return require("./guardedFetch").guardedJsonRequest(url, options); },
  randomBytes: function (n) { return crypto.randomBytes(n); }
};

/* kind: rejected (LWA answered invalid_grant: the code or the refresh token
   is no good, connect again), refused (another 4xx: BizForce's own client was
   refused), no_access (the answer lacks what BizForce needs) or unreachable. */
function AmazonAuthError(kind, code) {
  this.name = "AmazonAuthError";
  this.kind = kind;
  this.code = code;
  this.message = "amazon auth " + kind + " (" + code + ")";
}
AmazonAuthError.prototype = Object.create(Error.prototype);

function envText(env, name) {
  return typeof env[name] === "string" ? env[name].trim() : "";
}
/* { appId, clientId, clientSecret, draft } when the three required env vars
   are set, else null. draft is true unless AMAZON_SPAPI_DRAFT is exactly
   "false". */
function configured(env) {
  env = env || process.env;
  var appId = envText(env, "AMAZON_SPAPI_APP_ID");
  var clientId = envText(env, "AMAZON_LWA_CLIENT_ID");
  var clientSecret = envText(env, "AMAZON_LWA_CLIENT_SECRET");
  if (!appId || !clientId || !clientSecret) return null;
  return { appId: appId, clientId: clientId, clientSecret: clientSecret, draft: isDraft(env) };
}
/* Draft unless AMAZON_SPAPI_DRAFT is exactly "false" (it is optional). */
function isDraft(env) {
  env = env || process.env;
  return envText(env, "AMAZON_SPAPI_DRAFT") !== "false";
}

/* A marketplace from the table, or null. */
function marketplaceOf(id) {
  if (typeof id !== "string" || !MARKETPLACE_ID_RE.test(id)) return null;
  return Object.prototype.hasOwnProperty.call(MARKETPLACES, id) ? MARKETPLACES[id] : null;
}
/* The SP-API endpoint of a region, or null. */
function endpointOf(region) {
  return typeof region === "string" && Object.prototype.hasOwnProperty.call(REGION_ENDPOINTS, region) ? REGION_ENDPOINTS[region] : null;
}
/* What the Store page lists: each marketplace, grouped by region, in table order. */
function marketplaceList() {
  return Object.keys(REGION_ENDPOINTS).map(function (region) {
    return { region: region, label: REGION_LABEL[region], marketplaces: Object.keys(MARKETPLACES).filter(function (id) { return MARKETPLACES[id].region === region; })
      .map(function (id) { return { id: id, code: MARKETPLACES[id].code, storefront: MARKETPLACES[id].storefront }; }) };
  });
}

function base64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
/* 32 random bytes, base64url: 43 characters. */
function newState() { return base64url(deps.randomBytes(32)); }
/* What is stored for a state: its sha256, hex. The state itself never is. */
function stateHash(state) { return crypto.createHash("sha256").update(String(state), "utf8").digest("hex"); }

/* Seller Central's own consent page, on the chosen marketplace's host, with
   version=beta while the app is a draft. */
function consentUrl(config, marketplaceId, state) {
  var m = marketplaceOf(marketplaceId);
  if (!m) throw new AmazonAuthError("no_access", "marketplace");
  return "https://" + m.sellerCentral + CONSENT_PATH +
    "?application_id=" + encodeURIComponent(config.appId) +
    "&state=" + encodeURIComponent(state) +
    (config.draft ? "&version=beta" : "");
}

/* The finish body: { ok: true, code, state, sellerId } or { ok: false }. */
function finishShape(body) {
  body = body || {};
  var code = typeof body.spapi_oauth_code === "string" ? body.spapi_oauth_code : "";
  var state = typeof body.state === "string" ? body.state : "";
  var seller = typeof body.selling_partner_id === "string" ? body.selling_partner_id : "";
  if (!code || code.length > CODE_MAX || /[\u0000- \u007f]/.test(code)) return { ok: false };
  if (!STATE_RE.test(state)) return { ok: false };
  if (!SELLER_ID_RE.test(seller)) return { ok: false };
  return { ok: true, code: code, state: state, sellerId: seller };
}

function positiveInt(v) {
  var n = typeof v === "number" ? v : (typeof v === "string" && /^\d{1,9}$/.test(v) ? Number(v) : NaN);
  return Number.isInteger(n) && n >= 1 ? n : null;
}

/* A token answer, checked. Never returns or logs the answer itself. A refresh
   answer may carry no refresh token (the old one stays good): refreshToken
   is then null. */
function grantFrom(json, needRefresh) {
  var j = json && typeof json === "object" ? json : {};
  if (typeof j.access_token !== "string" || !j.access_token) throw new AmazonAuthError("unreachable", "token_shape");
  var refresh = typeof j.refresh_token === "string" && j.refresh_token ? j.refresh_token : null;
  if (needRefresh && refresh === null) throw new AmazonAuthError("no_access", "no_refresh_token");
  var expiresIn = positiveInt(j.expires_in);
  if (expiresIn === null) throw new AmazonAuthError("no_access", "no_expiry");
  return { accessToken: j.access_token, refreshToken: refresh, expiresIn: expiresIn };
}

/* One form POST to LWA's token endpoint. invalid_grant is rejected; another
   4xx is refused; anything else that fails is unreachable. */
async function tokenRequest(form, needRefresh, request) {
  var answer;
  try {
    answer = await (typeof request === "function" ? request : deps.request)(TOKEN_URL, { method: "POST", form: form, timeoutMs: TOKEN_TIMEOUT_MS });
  } catch (err) {
    throw new AmazonAuthError("unreachable", "token_request");
  }
  var status = answer && answer.status;
  if (typeof status !== "number" || status < 200 || status >= 300) {
    var error = answer && answer.json && typeof answer.json.error === "string" ? answer.json.error : "";
    if (typeof status === "number" && status >= 400 && status < 500 && error === "invalid_grant") throw new AmazonAuthError("rejected", "invalid_grant");
    if (typeof status === "number" && status >= 400 && status < 500 && status !== 408 && status !== 429) throw new AmazonAuthError("refused", "token_status_" + status);
    throw new AmazonAuthError("unreachable", "token_status_" + (typeof status === "number" ? status : "none"));
  }
  return grantFrom(answer.json, needRefresh);
}

/* The spapi_oauth_code, exchanged for the pair. */
function exchangeCode(config, code, request) {
  return tokenRequest({ grant_type: "authorization_code", code: String(code), client_id: config.clientId, client_secret: config.clientSecret }, true, request);
}

/* A refresh: a new access token; the refresh token stays the same unless LWA
   answers a new one. */
function refreshTokens(config, refreshToken, request) {
  return tokenRequest({ grant_type: "refresh_token", refresh_token: String(refreshToken), client_id: config.clientId, client_secret: config.clientSecret }, false, request);
}

/* When the access token stops being used: EXPIRY_SLACK_MS early. The refresh
   token has no expiry. */
function expiriesFor(grant, nowMs) {
  return {
    access_expires_at: new Date(nowMs + grant.expiresIn * 1000 - EXPIRY_SLACK_MS).toISOString(),
    refresh_expires_at: null
  };
}

module.exports = {
  TOKEN_URL: TOKEN_URL,
  CONSENT_PATH: CONSENT_PATH,
  PURPOSE: PURPOSE,
  STATE_TTL_MS: STATE_TTL_MS,
  STATE_RE: STATE_RE,
  SELLER_ID_RE: SELLER_ID_RE,
  TOKEN_TIMEOUT_MS: TOKEN_TIMEOUT_MS,
  EXPIRY_SLACK_MS: EXPIRY_SLACK_MS,
  REFRESH_MARGIN_MS: REFRESH_MARGIN_MS,
  REGION_ENDPOINTS: REGION_ENDPOINTS,
  REGION_LABEL: REGION_LABEL,
  MARKETPLACES: MARKETPLACES,
  MESSAGES: MESSAGES,
  deps: deps,
  AmazonAuthError: AmazonAuthError,
  configured: configured,
  isDraft: isDraft,
  marketplaceOf: marketplaceOf,
  endpointOf: endpointOf,
  marketplaceList: marketplaceList,
  newState: newState,
  stateHash: stateHash,
  consentUrl: consentUrl,
  finishShape: finishShape,
  grantFrom: grantFrom,
  exchangeCode: exchangeCode,
  refreshTokens: refreshTokens,
  expiriesFor: expiriesFor
};
