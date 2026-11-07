"use strict";

/* ══════════════════════════════════════════════════════════════════════════
   CONNECT SHOPIFY, the app install (migration 176).
   Merchants can no longer make admin custom apps (Jan 1 2026), so a member
   connects their shop by installing BizForce's own app through Shopify's
   OAuth authorization code grant, with an EXPIRING offline token: the access
   token lasts about an hour and comes with a refresh token, and a refresh
   hands back a NEW pair (the old refresh token is spent). Shopify has no PKCE
   here: the code is exchanged with the app's client secret.

   THE FLOW (server.js, the store section).
     1. POST /api/store/shopify/start (a signed-in member): newState; only its
        sha256 (stateHash) is stored, in oauth_states, purpose store_shopify,
        with flow_context { shop, permission }, for STATE_TTL_MS. The member is
        sent to authorizeUrl on their own shop.
     2. Shopify sends the browser back to FRONTEND_URL + "/store-agent.html"
        with code, state, shop, hmac, timestamp (and host). The page POSTs the
        whole query to POST /api/store/shopify/finish, a requireAuth route.
        callbackHmacValid, timestampFresh, the shop, then the state row is
        consumed by one conditional update; a failure never says which.
     3. exchangeCode (expiring=1); the scopes are checked (grantCovers); both
        tokens are sealed before any GraphQL call; lib/shopifyApi.js reads the
        shop's currency and locations; the row is stored.

   WEBHOOKS. webhookHmacValid checks X-Shopify-Hmac-Sha256 over the RAW body.

   ALL I/O is deps.request (lib/guardedFetch.js guardedJsonRequest: https on
   443 only, every address checked, no redirect followed, a POST with a JSON
   body). Nothing here logs, and no token, code or body is ever put into an
   error, a result a member sees, or a log line. A ShopifyAuthError carries
   only a kind and a short code.
   ══════════════════════════════════════════════════════════════════════════ */

const crypto = require("crypto");

const PURPOSE = "store_shopify";
const STATE_TTL_MS = 10 * 60 * 1000;
const STATE_RE = /^[A-Za-z0-9_-]{43}$/;
/* The callback's timestamp must be within this of now, either way. */
const CALLBACK_MAX_SKEW_MS = 10 * 60 * 1000;
const TOKEN_TIMEOUT_MS = 15 * 1000;
/* An access token is stored as expiring this much before Shopify says it does. */
const EXPIRY_SLACK_MS = 60 * 1000;
/* A token this close to its stored expiry is refreshed before use. */
const REFRESH_MARGIN_MS = 5 * 60 * 1000;
const READ_SCOPES = Object.freeze(["read_products", "read_inventory", "read_orders", "read_locations"]);
const WRITE_SCOPES = Object.freeze(["write_products", "write_inventory"]);
const CODE_MAX = 512;
const PARAM_MAX = 20;
const PARAM_VALUE_MAX = 2048;
const WEBHOOK_TOPICS = Object.freeze(["app/uninstalled", "customers/data_request", "customers/redact", "shop/redact"]);
/* shopify_webhook_events rows older than this are deleted daily (04:45 UTC). */
const WEBHOOK_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const WEBHOOK_PURGE_JOB_NAME = "shopify_webhook_events_purge";

const MESSAGES = Object.freeze({
  notConfigured: "Shopify connection isn't set up yet.",
  stateInvalid: "That Shopify connection link has expired or was already used. Start again.",
  scopesMissing: "Shopify didn't grant the access needed. Connect again and approve all permissions.",
  takenByOther: "This store is already connected to another BizForce account.",
  unreachable: "BizForce could not finish connecting your Shopify store just now. Try again later. Nothing was saved.",
  noSecret: "Stores can't be connected on this server just now: its encryption key is not set. Nothing was sent to your store and nothing was saved.",
  useConnect: "Use Connect Shopify on the Store Agent page.",
  disconnected: "Disconnected. To remove BizForce from your Shopify admin too, uninstall the BizForce app under Settings, then Apps."
});

const deps = {
  request: function (url, options) { return require("./guardedFetch").guardedJsonRequest(url, options); },
  randomBytes: function (n) { return crypto.randomBytes(n); },
  now: function () { return Date.now(); }
};

/* kind: rejected (Shopify refused the code or the refresh token: connect
   again), no_access (the answer lacks what BizForce needs) or unreachable. */
function ShopifyAuthError(kind, code) {
  this.name = "ShopifyAuthError";
  this.kind = kind;
  this.code = code;
  this.message = "shopify auth " + kind + " (" + code + ")";
}
ShopifyAuthError.prototype = Object.create(Error.prototype);

/* { clientId, clientSecret } when both env vars are set, else null. */
function configured(env) {
  env = env || process.env;
  var id = typeof env.SHOPIFY_CLIENT_ID === "string" ? env.SHOPIFY_CLIENT_ID.trim() : "";
  var secret = typeof env.SHOPIFY_CLIENT_SECRET === "string" ? env.SHOPIFY_CLIENT_SECRET.trim() : "";
  if (!id || !secret) return null;
  return { clientId: id, clientSecret: secret };
}

function base64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
/* 32 random bytes, base64url: 43 characters. */
function newState() { return base64url(deps.randomBytes(32)); }
/* What is stored for a state: its sha256, hex. The state itself never is. */
function stateHash(state) { return crypto.createHash("sha256").update(String(state), "utf8").digest("hex"); }

/* The scopes asked for: read, plus write only when the member allowed changes. */
function scopesFor(permission) {
  return permission === "read_write" ? READ_SCOPES.concat(WRITE_SCOPES) : READ_SCOPES.slice();
}

/* Shopify's own authorization page on the member's shop. */
function authorizeUrl(shop, clientId, permission, redirectUri, state) {
  var q = new URLSearchParams();
  q.append("client_id", clientId);
  q.append("scope", scopesFor(permission).join(","));
  q.append("redirect_uri", redirectUri);
  q.append("state", state);
  return "https://" + shop + "/admin/oauth/authorize?" + q.toString();
}

/* The finish body: { params } holding the callback query as strings.
   { ok: true, params } or { ok: false }. */
function finishShape(body) {
  var p = body && body.params;
  if (!p || typeof p !== "object" || Array.isArray(p)) return { ok: false };
  var keys = Object.keys(p);
  if (keys.length === 0 || keys.length > PARAM_MAX) return { ok: false };
  var out = {};
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i], v = p[k];
    if (!/^[a-z_]{1,40}$/.test(k) || typeof v !== "string" || v.length > PARAM_VALUE_MAX) return { ok: false };
    out[k] = v;
  }
  if (!out.code || out.code.length > CODE_MAX || /[\u0000- \u007f]/.test(out.code)) return { ok: false };
  if (!STATE_RE.test(out.state || "")) return { ok: false };
  if (!/^[0-9a-f]{64}$/.test(out.hmac || "")) return { ok: false };
  if (!/^[0-9]{1,12}$/.test(out.timestamp || "")) return { ok: false };
  if (!out.shop) return { ok: false };
  return { ok: true, params: out };
}

/* Shopify's callback signature: hex HMAC-SHA256 under the client secret over
   every query parameter but hmac, sorted by key, joined key=value with "&".
   Compared in constant time. */
function callbackHmacValid(params, secret) {
  if (!params || typeof params !== "object" || typeof secret !== "string" || !secret) return false;
  var given = typeof params.hmac === "string" ? params.hmac : "";
  if (!/^[0-9a-f]{64}$/.test(given)) return false;
  var message = Object.keys(params).filter(function (k) { return k !== "hmac"; }).sort()
    .map(function (k) { return k + "=" + params[k]; }).join("&");
  var want = crypto.createHmac("sha256", secret).update(message, "utf8").digest();
  var got = Buffer.from(given, "hex");
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}

/* The callback's timestamp (seconds) within CALLBACK_MAX_SKEW_MS of now. */
function timestampFresh(timestamp, nowMs) {
  if (typeof timestamp !== "string" || !/^[0-9]{1,12}$/.test(timestamp)) return false;
  return Math.abs(nowMs - Number(timestamp) * 1000) <= CALLBACK_MAX_SKEW_MS;
}

/* "read_products,write_inventory" as a list of scope handles. */
function parseScopes(scope) {
  if (typeof scope !== "string") return [];
  return scope.split(",").map(function (s) { return s.trim(); }).filter(function (s) { return /^[a-z_]{1,60}$/.test(s); });
}
/* Does the granted list hold every requested scope? Shopify may answer a
   write_ scope without its read_ twin, which the write scope implies. */
function grantCovers(granted, requested) {
  return requested.every(function (s) {
    if (granted.indexOf(s) !== -1) return true;
    return /^read_/.test(s) && granted.indexOf("write_" + s.slice(5)) !== -1;
  });
}

function positiveInt(v) {
  var n = typeof v === "number" ? v : (typeof v === "string" && /^\d{1,9}$/.test(v) ? Number(v) : NaN);
  return Number.isInteger(n) && n >= 1 ? n : null;
}

/* A token answer, checked. Never returns or logs the answer itself. */
function grantFrom(json) {
  var j = json && typeof json === "object" ? json : {};
  if (typeof j.access_token !== "string" || !j.access_token) throw new ShopifyAuthError("unreachable", "token_shape");
  if (typeof j.refresh_token !== "string" || !j.refresh_token) throw new ShopifyAuthError("no_access", "no_refresh_token");
  var expiresIn = positiveInt(j.expires_in);
  if (expiresIn === null) throw new ShopifyAuthError("no_access", "no_expiry");
  return {
    accessToken: j.access_token,
    refreshToken: j.refresh_token,
    expiresIn: expiresIn,
    refreshExpiresIn: positiveInt(j.refresh_token_expires_in),
    scopes: parseScopes(j.scope)
  };
}

/* One JSON POST to the shop's token endpoint. A 4xx means Shopify refused the
   code or the refresh token (rejected); anything else that fails is unreachable. */
async function tokenRequest(shop, body, request) {
  var answer;
  try {
    answer = await (typeof request === "function" ? request : deps.request)("https://" + shop + "/admin/oauth/access_token", { method: "POST", body: body, timeoutMs: TOKEN_TIMEOUT_MS });
  } catch (err) {
    throw new ShopifyAuthError("unreachable", "token_request");
  }
  var status = answer && answer.status;
  if (typeof status !== "number" || status < 200 || status >= 300) {
    if (typeof status === "number" && status >= 400 && status < 500 && status !== 408 && status !== 429) throw new ShopifyAuthError("rejected", "token_status_" + status);
    throw new ShopifyAuthError("unreachable", "token_status_" + (typeof status === "number" ? status : "none"));
  }
  return grantFrom(answer.json);
}

/* The code, exchanged for an EXPIRING offline token (expiring: 1). request is
   the guarded JSON request to use (the caller's deps.jsonRequest), else deps.request. */
function exchangeCode(config, shop, code, request) {
  return tokenRequest(shop, { client_id: config.clientId, client_secret: config.clientSecret, code: code, expiring: 1 }, request);
}

/* A refresh: a new access token AND a new refresh token; the old one is spent. */
function refreshTokens(config, shop, refreshToken, request) {
  return tokenRequest(shop, { client_id: config.clientId, client_secret: config.clientSecret, grant_type: "refresh_token", refresh_token: refreshToken }, request);
}

/* When each token stops being used: the access token EXPIRY_SLACK_MS early. */
function expiriesFor(grant, nowMs) {
  return {
    access_expires_at: new Date(nowMs + grant.expiresIn * 1000 - EXPIRY_SLACK_MS).toISOString(),
    refresh_expires_at: grant.refreshExpiresIn === null ? null : new Date(nowMs + grant.refreshExpiresIn * 1000).toISOString()
  };
}

/* X-Shopify-Hmac-Sha256: base64 HMAC-SHA256 under the client secret over the
   RAW body bytes, exactly as delivered. Compared in constant time. */
function webhookHmacValid(rawBody, header, secret) {
  if (!Buffer.isBuffer(rawBody) || typeof header !== "string" || typeof secret !== "string" || !secret) return false;
  if (!/^[A-Za-z0-9+/]{43}=$/.test(header)) return false;
  var want = crypto.createHmac("sha256", secret).update(rawBody).digest();
  var got = Buffer.from(header, "base64");
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}

/* ── retention: Shopify's notification receipts, deleted after 30 days ─────
   Run from the 04:45 UTC cron in server.js, after the oauth_states purge, and
   claimed through its own job_runs row. Never rejects. */
async function claimWebhookPurgeDay(supabase, nowMs) {
  var today = new Date(nowMs).toISOString().slice(0, 10);
  var started = new Date(nowMs).toISOString();
  var inserted = await supabase
    .from("job_runs")
    .insert({ job_name: WEBHOOK_PURGE_JOB_NAME, last_run_on: today, started_at: started, finished_at: null, last_error: null })
    .select("job_name");
  if (!inserted.error) return true;
  // 23505 = unique_violation: the row exists. Anything else is a failure, never a claim.
  if (inserted.error.code !== "23505") {
    console.error("[ShopifyWebhookPurge] Claim insert failed: " + (inserted.error.code || "error"));
    return false;
  }
  var updated = await supabase
    .from("job_runs")
    .update({ last_run_on: today, started_at: started, finished_at: null, last_error: null })
    .eq("job_name", WEBHOOK_PURGE_JOB_NAME)
    .or("last_run_on.is.null,last_run_on.neq." + today)
    .select("job_name");
  if (updated.error) {
    console.error("[ShopifyWebhookPurge] Claim update failed: " + (updated.error.code || "error"));
    return false;
  }
  return (updated.data || []).length > 0;
}

async function webhookEventsPurgeTick(supabase, nowMs) {
  var startedMs = typeof nowMs === "number" ? nowMs : deps.now();
  var finish = async function (errorMessage) {
    var patch = { finished_at: new Date(deps.now()).toISOString() };
    if (errorMessage) patch.last_error = String(errorMessage).slice(0, 2000);
    var result = await supabase.from("job_runs").update(patch).eq("job_name", WEBHOOK_PURGE_JOB_NAME);
    if (result.error) console.error("[ShopifyWebhookPurge] Failed to record run completion: " + (result.error.code || "error"));
  };
  try {
    if (!(await claimWebhookPurgeDay(supabase, startedMs))) return { claimed: false };
    var cutoff = new Date(startedMs - WEBHOOK_RETENTION_MS).toISOString();
    var removed = await supabase.from("shopify_webhook_events").delete().lt("received_at", cutoff).select("id");
    var error = removed.error ? "shopify_webhook_events delete failed: " + (removed.error.code || "error") : null;
    var deleted = removed.error ? 0 : (removed.data || []).length;
    await finish(error);
    console.log("[ShopifyWebhookPurge] Pass finished: " + deleted + " Shopify notification receipt(s) older than " + cutoff + " deleted" + (error ? "; stopped: " + error : "") + ".");
    return { claimed: true, cutoff: cutoff, deleted: deleted, error: error };
  } catch (err) {
    console.error("[ShopifyWebhookPurge] Pass error: " + ((err && err.code) || "error"));
    try { await finish((err && err.code) || "error"); } catch (finishErr) { /* reported above */ }
    return { claimed: true, error: (err && err.code) || "error" };
  }
}

module.exports = {
  PURPOSE: PURPOSE,
  STATE_TTL_MS: STATE_TTL_MS,
  STATE_RE: STATE_RE,
  CALLBACK_MAX_SKEW_MS: CALLBACK_MAX_SKEW_MS,
  TOKEN_TIMEOUT_MS: TOKEN_TIMEOUT_MS,
  EXPIRY_SLACK_MS: EXPIRY_SLACK_MS,
  REFRESH_MARGIN_MS: REFRESH_MARGIN_MS,
  READ_SCOPES: READ_SCOPES,
  WRITE_SCOPES: WRITE_SCOPES,
  WEBHOOK_TOPICS: WEBHOOK_TOPICS,
  WEBHOOK_RETENTION_MS: WEBHOOK_RETENTION_MS,
  WEBHOOK_PURGE_JOB_NAME: WEBHOOK_PURGE_JOB_NAME,
  MESSAGES: MESSAGES,
  deps: deps,
  ShopifyAuthError: ShopifyAuthError,
  configured: configured,
  newState: newState,
  stateHash: stateHash,
  scopesFor: scopesFor,
  authorizeUrl: authorizeUrl,
  finishShape: finishShape,
  callbackHmacValid: callbackHmacValid,
  timestampFresh: timestampFresh,
  parseScopes: parseScopes,
  grantCovers: grantCovers,
  exchangeCode: exchangeCode,
  refreshTokens: refreshTokens,
  expiriesFor: expiriesFor,
  webhookHmacValid: webhookHmacValid,
  webhookEventsPurgeTick: webhookEventsPurgeTick
};
