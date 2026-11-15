"use strict";

/* ══════════════════════════════════════════════════════════════════════════
   SHOPIFY app/uninstalled, SUBSCRIBED PER SHOP (W-T4, Nov 15 2026, migration 185).

   WHY HERE. The app keeps use_legacy_install_flow = true (the connect flow is
   unchanged), and Shopify refuses app-specific webhook subscriptions in
   shopify.app.toml with that flow. The privacy (compliance) topics stay in the
   toml; APP_UNINSTALLED is subscribed on each connected shop through the
   Admin GraphQL API (2026-07, lib/storeSync.js SHOPIFY_API_VERSION), to
   STORE_API_BASE + "/api/webhooks/shopify" (server.js), the route that already
   handles app/uninstalled (lib/shopifyWebhooks.js).

   ensureUninstallWebhook(deps, connection, address[, session]):
     1. lists the shop's APP_UNINSTALLED subscriptions (a query, through
        lib/shopifyApi.js read(): paced, retried, the token refreshed once);
     2. one whose uri is exactly `address`: nothing sent, action "exists";
     3. else one whose uri is on a BizForce host (the Railway backend or
        bizforceai.net), from an earlier setup: webhookSubscriptionUpdate to
        `address`, action "updated";
     4. else webhookSubscriptionCreate(topic APP_UNINSTALLED,
        { uri: address, format: JSON }), action "created".
   A subscription on any other address is never touched. In 2026-07 the input
   field is uri (callbackUrl is deprecated), and JSON is a valid
   WebhookSubscriptionFormat (shopify.dev admin-graphql 2026-07 reference).

   It NEVER THROWS: a refused list, a userError, a GraphQL error or a transport
   failure resolves { ok: false, code } with a short code. Each mutation is
   sent ONCE, never retried here; the caller leaves uninstall_hook_at null, so
   the next Shopify sync asks again.

   recordUninstallWebhook(deps, connection, address[, session]) runs it and,
   on ok, sets member_store_connections.uninstall_hook_at. The connect calls it
   after its answer is sent; the sync calls ensureUninstallWebhook itself and
   puts the stamp in its own finishing update. A failure is logged with the
   connection id and the short code only: never a token, a secret or an
   answer body.

   The word "mutation" stays out of lib/shopifyApi.js (only writePrice and
   writeStock there); the two documents below are this file's own.
   ══════════════════════════════════════════════════════════════════════════ */

var API = require("./shopifyApi");

var TOPIC = "APP_UNINSTALLED";
var LIST_FIRST = 25;
var SEND_TIMEOUT_MS = 20000;
var SEND_MAX_BYTES = 256 * 1024;
var NOT_SENT = ["blocked", "invalid_url", "dns", "guard_refused"];

var LIST_QUERY = "query UninstallHooks { webhookSubscriptions(first: " + LIST_FIRST + ", topics: [" + TOPIC + "]) { edges { node { id topic uri } } } }";
var CREATE_DOC = "mutation UninstallHookCreate($topic: WebhookSubscriptionTopic!, $webhookSubscription: WebhookSubscriptionInput!) { " +
  "webhookSubscriptionCreate(topic: $topic, webhookSubscription: $webhookSubscription) { webhookSubscription { id uri } userErrors { field message } } }";
var UPDATE_DOC = "mutation UninstallHookUpdate($id: ID!, $webhookSubscription: WebhookSubscriptionInput!) { " +
  "webhookSubscriptionUpdate(id: $id, webhookSubscription: $webhookSubscription) { webhookSubscription { id uri } userErrors { field message } } }";

function short(code) {
  return String(code || "failed").replace(/[^a-z0-9_]/gi, "_").slice(0, 40);
}

function hostOf(uri) {
  try { return new URL(String(uri)).hostname.toLowerCase(); } catch (e) { return null; }
}

/* A BizForce backend address: the address's own host, the Railway backend, or bizforceai.net. */
function isBizforceUri(uri, address) {
  var host = hostOf(uri);
  if (!host) return false;
  return host === hostOf(address) || /^dynamic-prosperity-[a-z0-9-]+\.up\.railway\.app$/.test(host) ||
    host === "bizforceai.net" || /\.bizforceai\.net$/.test(host);
}

/* One mutation, sent once. Resolves { ok, data } or { ok: false, code }. */
async function sendOnce(deps, s, doc, variables, field) {
  var token;
  try { token = await API.accessToken(deps, s, false); } catch (err) { return { ok: false, code: short(err && err.code) }; }
  var answer;
  try {
    answer = await deps.jsonRequest(API.graphqlUrl(s.row.store_url), {
      method: "POST", headers: { "X-Shopify-Access-Token": token, "Accept": "application/json" },
      body: { query: doc, variables: variables }, maxBytes: SEND_MAX_BYTES, timeoutMs: SEND_TIMEOUT_MS });
  } catch (err) {
    var g = err && err.guardedFetch === true ? String(err.code) : "guard_refused";
    return { ok: false, code: NOT_SENT.indexOf(g) !== -1 ? "not_sent" : "unconfirmed" };
  } finally {
    token = null;
  }
  var status = answer && answer.status;
  if (typeof status !== "number" || status < 200 || status >= 300) return { ok: false, code: "http_" + short(status) };
  var json = answer.json;
  if (!json || typeof json !== "object") return { ok: false, code: "not_json" };
  if (Array.isArray(json.errors) && json.errors.length) return { ok: false, code: "graphql_error" };
  var payload = json.data && json.data[field];
  if (!payload || typeof payload !== "object") return { ok: false, code: "unconfirmed" };
  if (Array.isArray(payload.userErrors) && payload.userErrors.length) return { ok: false, code: "user_error" };
  if (!payload.webhookSubscription || payload.webhookSubscription.uri !== variables.webhookSubscription.uri) return { ok: false, code: "unconfirmed" };
  return { ok: true };
}

async function ensureUninstallWebhook(deps, connection, address, session) {
  try {
    if (!connection || connection.platform !== "shopify" || !connection.store_url) return { ok: false, code: "not_shopify" };
    if (typeof address !== "string" || !/^https:\/\//.test(address)) return { ok: false, code: "no_address" };
    var s = session || API.session(connection);
    var data;
    try {
      data = await API.read(deps, s, LIST_QUERY, {});
    } catch (err) {
      return { ok: false, code: short(err && err.code) };
    }
    var list = data && data.webhookSubscriptions && Array.isArray(data.webhookSubscriptions.edges) ? data.webhookSubscriptions.edges : null;
    if (!list) return { ok: false, code: "not_json" };
    var nodes = list.map(function (e) { return e && e.node; }).filter(function (n) { return n && n.topic === TOPIC; });
    if (nodes.some(function (n) { return n.uri === address; })) return { ok: true, action: "exists" };
    var ours = nodes.filter(function (n) { return isBizforceUri(n.uri, address); })[0];
    var input = { uri: address, format: "JSON" };
    var sent = ours
      ? await sendOnce(deps, s, UPDATE_DOC, { id: ours.id, webhookSubscription: input }, "webhookSubscriptionUpdate")
      : await sendOnce(deps, s, CREATE_DOC, { topic: TOPIC, webhookSubscription: input }, "webhookSubscriptionCreate");
    if (!sent.ok) return sent;
    return { ok: true, action: ours ? "updated" : "created" };
  } catch (err) {
    return { ok: false, code: "failed" };
  }
}

/* The connect's call: ensure, then stamp uninstall_hook_at. Never rejects. */
async function recordUninstallWebhook(deps, connection, address, session) {
  var out = await ensureUninstallWebhook(deps, connection, address, session);
  try {
    if (!out.ok) {
      console.warn("[ShopifyHook] connection " + (connection && connection.id) + " not subscribed to app/uninstalled: " + out.code + " (the next sync tries again)");
      return out;
    }
    var stamp = new Date(deps.now()).toISOString();
    var saved = await deps.supabase.from("member_store_connections").update({ uninstall_hook_at: stamp })
      .eq("id", connection.id).eq("platform", "shopify").select("id");
    if (saved.error || !(saved.data || []).length) {
      console.warn("[ShopifyHook] connection " + connection.id + " subscribed (" + out.action + ") but uninstall_hook_at was not saved (the next sync checks again)");
      return { ok: false, code: "save_failed", action: out.action };
    }
    return out;
  } catch (err) {
    return { ok: false, code: "save_failed" };
  }
}

module.exports = {
  TOPIC: TOPIC,
  LIST_QUERY: LIST_QUERY,
  isBizforceUri: isBizforceUri,
  ensureUninstallWebhook: ensureUninstallWebhook,
  recordUninstallWebhook: recordUninstallWebhook
};
