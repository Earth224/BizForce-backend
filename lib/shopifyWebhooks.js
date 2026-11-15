"use strict";

/* ══════════════════════════════════════════════════════════════════════════
   SHOPIFY WEBHOOKS: THE WORK AFTER THE ANSWER (W2, migrations 176 and 184).

   POST /api/webhooks/shopify (server.js) checks the HMAC over the raw body,
   records the receipt in shopify_webhook_events (with request_details for the
   two customer topics, built here by requestDetailsOf), answers 200, and only
   then runs processReceipt on the next turn. processed_at is set only when the
   topic's work succeeded, so a receipt whose work failed is taken again by
   sweepTick (every 5 minutes, up to 50 receipts older than 2 minutes, oldest
   first, on the partial index of migration 184).

   THE TOPICS.
     app/uninstalled   server.js removeShopifyShop: the shop's connections are
                       removed as disconnect removes them, and their ids are
                       recorded first in this receipt's request_details as
                       { connection_ids: [...] } (recordConnectionIds), so a
                       later shop/redact still finds them.
     shop/redact       the same removal, then redactShop: every agent_proposals
                       row of action_type update_store_item whose payload names
                       one of the shop's connection ids (current ones, plus those
                       recorded by earlier receipts for the shop) keeps its id,
                       user, type, status and times, and loses its payload,
                       execution result and title. The shop's pending
                       store_shopify sign-in states are deleted.
     customers/redact  the named orders' summaries, in that shop only, are
                       deleted (store_order_summaries, platform shopify). When no
                       order id could be read from the body, the owner gets ONE
                       ops alert (key shopify_redact_unreadable, one per receipt)
                       naming only the shop and the receipt id (W3).
     customers/data_request
                       the owner is emailed once. The row is CLAIMED first: one
                       conditional update sets owner_notified_at where it is still
                       null, and only the caller that got the row back sends
                       (W3), so two runs at once cannot both send. A failed send
                       puts owner_notified_at back to null (only this claim's
                       value), and the sweep sends again. The email holds what
                       BizForce holds for the named orders, a statement ready for
                       the store owner, and the link to the owner's page
                       (shopify-requests.html). The daily 04:45 UTC chain
                       reminds the owner once per request, from 23 days after
                       receipt, while it is unanswered: request_details.reminded_at
                       is set only after a reminder was sent, so a failed one is
                       sent again the next day (reminderTick, job_runs
                       shopify_data_request_reminder, W3).

   request_details NEVER holds an email, phone number or name: it is built from
   named id fields only, plus reminded_at (a timestamp) on a data request. The
   body itself is never stored or logged.
   ══════════════════════════════════════════════════════════════════════════ */

const TABLE = "shopify_webhook_events";
const DATA_REQUEST = "customers/data_request";
const CUSTOMER_REDACT = "customers/redact";
const SHOP_REDACT = "shop/redact";
const APP_UNINSTALLED = "app/uninstalled";
const DAY_MS = 24 * 60 * 60 * 1000;
/* Shopify asks for a data request to be answered within 30 days. */
const ANSWER_WITHIN_DAYS = 30;
/* The owner is reminded once, this many days after a request arrived, while it is unanswered. */
const REMINDER_AFTER_DAYS = 23;
const SWEEP_EVERY_MS = 5 * 60 * 1000;
const SWEEP_MIN_AGE_MS = 2 * 60 * 1000;
const SWEEP_BATCH = 50;
const IDS_MAX = 250;
const RECENT_ANSWERED_MS = 30 * DAY_MS;
const REMINDER_JOB_NAME = "shopify_data_request_reminder";
/* W3: the owner's page for data requests (frontend shopify-requests.html), named in every data request email. */
const REQUESTS_PAGE_URL = "https://bizforceai.net/shopify-requests.html";
/* W3: the ops alert for a customers/redact whose order ids could not be read. */
const REDACT_UNREADABLE_ALERT = "shopify_redact_unreadable";
const ROW_COLUMNS = "id, webhook_id, topic, shop_domain, received_at, processed_at, request_details, answered_at, owner_notified_at";
const REDACTED = Object.freeze({ redacted: true, reason: "shop/redact" });
const REDACTED_TITLE = "Store change (removed after the store asked for its data to be erased)";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function iso(ms) { return new Date(ms).toISOString(); }
function nowOf(deps) { return deps && typeof deps.now === "function" ? deps.now() : Date.now(); }
function logError(deps, line) { ((deps && deps.console) || console).error(line); }

/* A Shopify id as its numeric string: a number, a string of digits, or
   gid://shopify/<type>/<digits>. Anything else is null. */
function numericIdOf(v, type) {
  if (typeof v === "number") return Number.isSafeInteger(v) && v >= 1 ? String(v) : null;
  if (typeof v !== "string") return null;
  var s = v.trim();
  if (/^[0-9]{1,30}$/.test(s)) return s;
  var m = new RegExp("^gid://shopify/" + type + "/([0-9]{1,30})$").exec(s);
  return m ? m[1] : null;
}

/* A list of ids, each normalised; others dropped; no repeats; at most IDS_MAX. */
function idList(list, type) {
  if (!Array.isArray(list)) return [];
  var out = [];
  for (var i = 0; i < list.length && out.length < IDS_MAX; i++) {
    var id = numericIdOf(list[i], type);
    if (id !== null && out.indexOf(id) === -1) out.push(id);
  }
  return out;
}

/* request_details for the two customer topics, from the raw body; null for any
   other topic or a body that is not a JSON object. Only the named id fields are
   read, so no email, phone or name can reach the row. */
function requestDetailsOf(topic, raw) {
  if (topic !== DATA_REQUEST && topic !== CUSTOMER_REDACT) return null;
  var body;
  try { body = JSON.parse(Buffer.isBuffer(raw) ? raw.toString("utf8") : String(raw)); } catch (err) { return null; }
  if (!body || typeof body !== "object" || Array.isArray(body)) return null;
  var customer = body.customer && typeof body.customer === "object" ? body.customer : {};
  if (topic === DATA_REQUEST) {
    var dr = body.data_request && typeof body.data_request === "object" ? body.data_request : {};
    return { customer_id: numericIdOf(customer.id, "Customer"), orders_requested: idList(body.orders_requested, "Order"), data_request_id: numericIdOf(dr.id, "DataRequest") };
  }
  return { customer_id: numericIdOf(customer.id, "Customer"), orders_to_redact: idList(body.orders_to_redact, "Order") };
}

/* The owner's address for operational email: the one the ops alerts use
   (OPS_ALERT_EMAIL, else BACKUP_EMAIL_TO). null when neither is set. */
function ownerAddress(env) {
  return require("./opsAlert").opsAlertRecipient(env || {});
}

/* One plain-text email to the owner through the ops alerts' own Resend sender. */
function sendOwner(deps, message) {
  if (deps && typeof deps.send === "function") return deps.send(message);
  return require("./opsAlert").resendSend(message, (deps && deps.env) || {});
}

async function shopConnectionIds(supabase, shop) {
  var rows = await supabase.from("member_store_connections").select("id").eq("platform", "shopify").eq("store_url", shop);
  if (rows.error) throw rows.error;
  return (rows.data || []).map(function (r) { return r.id; });
}

/* Records the shop's connection ids in a receipt's request_details before they
   are removed, joined with any it already holds. Throws on a database error,
   so nothing is removed unless the ids were kept. */
async function recordConnectionIds(supabase, receiptId, ids) {
  var now = await supabase.from(TABLE).select("request_details").eq("id", receiptId).maybeSingle();
  if (now.error) throw now.error;
  var held = now.data && now.data.request_details && Array.isArray(now.data.request_details.connection_ids) ? now.data.request_details.connection_ids : [];
  var all = held.slice();
  (ids || []).forEach(function (id) { if (all.indexOf(id) === -1) all.push(id); });
  if (all.length === held.length) return all;
  var saved = await supabase.from(TABLE).update({ request_details: { connection_ids: all } }).eq("id", receiptId);
  if (saved.error) throw saved.error;
  return all;
}

/* What BizForce holds for the named orders in that shop: summary fields only. */
async function ordersHeld(supabase, shop, orderIds) {
  if (!orderIds || !orderIds.length) return [];
  var conns = await shopConnectionIds(supabase, shop);
  if (!conns.length) return [];
  var got = await supabase.from("store_order_summaries").select("external_id, ordered_at, total, currency, status, line_items")
    .eq("platform", "shopify").in("connection_id", conns).in("external_id", orderIds);
  if (got.error) throw got.error;
  return (got.data || []).slice().sort(function (a, b) { return String(a.external_id) < String(b.external_id) ? -1 : 1; });
}

function deadlineOf(receivedAt) {
  var ms = Date.parse(receivedAt);
  return isNaN(ms) ? null : iso(ms + ANSWER_WITHIN_DAYS * DAY_MS);
}

function dayOf(isoText) { return isoText ? String(isoText).slice(0, 10) : "unknown"; }

function orderLine(o) {
  var items = Array.isArray(o.line_items) ? o.line_items : [];
  var itemText = items.length ? items.map(function (li) {
    return "SKU " + (li && li.sku ? li.sku : "(none)") + " x " + (li && typeof li.quantity === "number" ? li.quantity : "?");
  }).join("; ") : "none";
  return "order " + o.external_id + ", placed " + (o.ordered_at || "unknown") + ", total " + (o.total == null ? "unknown" : o.total) +
    (o.currency ? " " + o.currency : "") + ", status " + (o.status || "unknown") + ", line items: " + itemText;
}

/* The owner's email for a data request (or its reminder). held is the list
   ordersHeld returned, or null when the request's orders could not be read. */
function dataRequestEmail(row, held, reminder) {
  var d = row.request_details || null;
  var deadline = deadlineOf(row.received_at);
  var subject = (reminder ? "Reminder: " : "") + "Shopify data request from " + row.shop_domain + ", answer by " + dayOf(deadline);
  var lines = [];
  if (reminder) lines.push("This Shopify data request is still marked unanswered, " + REMINDER_AFTER_DAYS + " days after it arrived.", "");
  lines.push(
    "A store that installed BizForce sent a customer data request through Shopify (customers/data_request).",
    "",
    "Shop: " + row.shop_domain,
    "Data request id: " + (d && d.data_request_id ? d.data_request_id : "not readable"),
    "Shopify customer id: " + (d && d.customer_id ? d.customer_id : "not readable"),
    "Received: " + row.received_at,
    "Deadline: " + (deadline || "unknown") + " (received + " + ANSWER_WITHIN_DAYS + " days)",
    "Orders named in the request: " + (d && d.orders_requested && d.orders_requested.length ? d.orders_requested.join(", ") : "none"),
    "",
    "What BizForce holds for those orders in this shop:"
  );
  var statement;
  if (held === null) {
    lines.push("unknown: the request could not be read. Check the request in Shopify before answering.");
    statement = null;
  } else if (!held.length) {
    lines.push("none");
    statement = "BizForce holds no customer names, emails, addresses or phone numbers. It holds nothing for the orders in this request.";
  } else {
    held.forEach(function (o) { lines.push("- " + orderLine(o)); });
    statement = "BizForce holds no customer names, emails, addresses or phone numbers. For the orders in this request it holds only: " +
      held.map(orderLine).join("; ") + ".";
  }
  if (statement) lines.push("", "Statement for the store owner, ready to send:", "", statement);
  lines.push("", "Open requests, and the button to mark this one answered: " + REQUESTS_PAGE_URL,
    "(Or POST /api/admin/shopify-data-requests/" + row.id + "/answered; GET /api/admin/shopify-data-requests lists open requests.)");
  return { subject: subject, text: lines.join("\n") };
}

/* Builds and sends one email about a data request. true when the sender accepted it. */
async function sendRequestEmail(deps, to, row, reminder) {
  var d = row.request_details;
  var held = d && Array.isArray(d.orders_requested) ? await ordersHeld(deps.supabase, row.shop_domain, d.orders_requested) : null;
  var mail = dataRequestEmail(row, held, reminder);
  var sent;
  try {
    sent = await sendOwner(deps, { from: require("./opsAlert").FROM_EMAIL, to: [to], subject: mail.subject, text: mail.text });
  } catch (err) {
    sent = { ok: false };
  }
  return !!(sent && sent.ok === true);
}

/* Emails the owner about one data request. { sent: true } or { sent: false, reason }.
   The first email: CLAIM, then send. The claim is one conditional update that
   sets owner_notified_at where it is still null and returns the row; only a
   caller that got the row back sends, so the email cannot go twice. A send
   that fails (or throws) releases the claim: owner_notified_at goes back to
   null where it still holds this claim's value, and the sweep sends again.
   A reminder: send, then set request_details.reminded_at (only after a send
   that succeeded; a failed one is tried again on the next daily run). */
async function notifyOwner(deps, row, reminder) {
  var to = ownerAddress(deps.env);
  if (!to) return { sent: false, reason: "no_owner_address" };
  if (reminder) {
    if (!(await sendRequestEmail(deps, to, row, true))) return { sent: false, reason: "send_failed" };
    var details = Object.assign({}, row.request_details || {}, { reminded_at: iso(nowOf(deps)) });
    var noted = await deps.supabase.from(TABLE).update({ request_details: details }).eq("id", row.id).is("request_details->>reminded_at", null);
    if (noted.error) logError(deps, "[ShopifyWebhooks] reminded_at not recorded: " + (noted.error.code || "error"));
    return { sent: true };
  }
  var claimedAt = iso(nowOf(deps));
  var claim = await deps.supabase.from(TABLE).update({ owner_notified_at: claimedAt }).eq("id", row.id).is("owner_notified_at", null).select("id");
  if (claim.error) return { sent: false, reason: "claim_failed" };
  if (!(claim.data || []).length) return { sent: false, reason: "already_claimed" };
  var ok = false;
  try {
    ok = await sendRequestEmail(deps, to, row, false);
  } finally {
    if (!ok) {
      var released = await deps.supabase.from(TABLE).update({ owner_notified_at: null }).eq("id", row.id).eq("owner_notified_at", claimedAt);
      if (released.error) logError(deps, "[ShopifyWebhooks] owner_notified_at claim not released: " + (released.error.code || "error"));
    }
  }
  return ok ? { sent: true } : { sent: false, reason: "send_failed" };
}

/* One ops alert (lib/opsAlert.js raise, through deps.raiseAlert) for a customers/redact
   whose order ids could not be read. Its fingerprint is the receipt id, so each such
   receipt is emailed once. It names the shop and the receipt id, nothing else. Never throws. */
async function alertRedactUnreadable(deps, row) {
  try {
    if (!deps || typeof deps.raiseAlert !== "function") {
      logError(deps, "[ShopifyWebhooks] customers/redact receipt " + row.id + " had no readable order ids, and no ops alert is wired");
      return;
    }
    await deps.raiseAlert(REDACT_UNREADABLE_ALERT, {
      what: "A Shopify customers/redact request could not be read",
      error: "Shop " + row.shop_domain + ", receipt " + row.id + ": no order ids could be read from the request, so nothing was deleted. " +
        "If the customer had orders in that shop, delete them by hand or ask Shopify to send the request again.",
      fingerprint: row.id,
      where: "Table editor > shopify_webhook_events, row " + row.id,
      log_tag: "[ShopifyWebhooks]"
    });
  } catch (err) {
    logError(deps, "[ShopifyWebhooks] the customers/redact alert failed: " + ((err && err.code) || "error"));
  }
}

async function redactCustomerOrders(deps, row) {
  var d = row.request_details;
  var ids = d && Array.isArray(d.orders_to_redact) ? idList(d.orders_to_redact, "Order") : [];
  if (!ids.length) {
    // W3: nothing could be read, so nothing was deleted: the owner hears of it once, by shop and receipt id only.
    await alertRedactUnreadable(deps, row);
    return { ok: true, deleted: 0, unreadable: true };
  }
  var conns = await shopConnectionIds(deps.supabase, row.shop_domain);
  if (!conns.length) return { ok: true, deleted: 0 };
  var gone = await deps.supabase.from("store_order_summaries").delete().eq("platform", "shopify").in("connection_id", conns).in("external_id", ids).select("id");
  if (gone.error) throw gone.error;
  return { ok: true, deleted: (gone.data || []).length };
}

/* The shop's connection ids now, plus those earlier receipts for the shop recorded. */
async function knownConnectionIds(supabase, shop) {
  var ids = await shopConnectionIds(supabase, shop);
  var earlier = await supabase.from(TABLE).select("request_details").eq("shop_domain", shop).in("topic", [APP_UNINSTALLED, SHOP_REDACT]);
  if (earlier.error) throw earlier.error;
  (earlier.data || []).forEach(function (r) {
    var list = r.request_details && Array.isArray(r.request_details.connection_ids) ? r.request_details.connection_ids : [];
    list.forEach(function (id) { if (typeof id === "string" && UUID_RE.test(id) && ids.indexOf(id) === -1) ids.push(id); });
  });
  return ids;
}

async function redactShop(deps, row) {
  var ids = await knownConnectionIds(deps.supabase, row.shop_domain);
  var anonymised = 0;
  if (ids.length) {
    var hit = await deps.supabase.from("agent_proposals").update({ payload: REDACTED, execution_result: REDACTED, title: REDACTED_TITLE })
      .eq("action_type", "update_store_item").in("payload->>connection_id", ids).select("id");
    if (hit.error) throw hit.error;
    anonymised = (hit.data || []).length;
  }
  var states = await deps.supabase.from("oauth_states").delete().eq("purpose", "store_shopify").eq("flow_context->>shop", row.shop_domain).select("id");
  if (states.error) throw states.error;
  return { ok: true, anonymised: anonymised, states_deleted: (states.data || []).length };
}

async function topicWork(deps, row) {
  if (row.topic === APP_UNINSTALLED || row.topic === SHOP_REDACT) {
    var removal = await deps.removeShopifyShop(row.shop_domain, row.id);
    if (row.topic === APP_UNINSTALLED) return { ok: true, removed: removal && removal.removed };
    var red = await redactShop(deps, row);
    red.removed = removal && removal.removed;
    return red;
  }
  if (row.topic === CUSTOMER_REDACT) return redactCustomerOrders(deps, row);
  if (row.topic === DATA_REQUEST) {
    if (row.owner_notified_at) return { ok: true, notified: false };
    var n = await notifyOwner(deps, row, false);
    // The receipt is processed either way; an unsent email is retried by the sweep (owner_notified_at null).
    return { ok: true, notified: n.sent, reason: n.reason || null };
  }
  return { ok: false, error: "unknown_topic" };
}

/* One receipt's work, at most once at a time per receipt in this process.
   processed_at is set only when the work succeeded. Never rejects. */
const running = new Set();
async function processReceipt(deps, row) {
  if (!row || !row.id) return { ok: false, error: "no_receipt" };
  if (running.has(row.id)) return { ok: false, skipped: "running" };
  running.add(row.id);
  try {
    var work = await topicWork(deps, row);
    if (!work.ok) return work;
    if (!row.processed_at) {
      var done = await deps.supabase.from(TABLE).update({ processed_at: iso(nowOf(deps)) }).eq("id", row.id);
      if (done.error) return { ok: false, error: "processed_at_not_recorded" };
    }
    return work;
  } catch (err) {
    logError(deps, "[ShopifyWebhooks] " + row.topic + " work failed: " + ((err && err.code) || "error"));
    return { ok: false, error: (err && err.code) || "error" };
  } finally {
    running.delete(row.id);
  }
}

/* The retry sweep: up to SWEEP_BATCH unprocessed receipts older than
   SWEEP_MIN_AGE_MS, oldest first; then, when an owner address is set, data
   requests whose owner email has not gone (unanswered ones only). Single
   flight: a run that finds one still going does nothing. Never rejects. */
var sweeping = false;
async function sweepTick(deps) {
  if (sweeping) return { skipped: "running" };
  sweeping = true;
  try {
    var cutoff = iso(nowOf(deps) - SWEEP_MIN_AGE_MS);
    var pending = await deps.supabase.from(TABLE).select(ROW_COLUMNS).is("processed_at", null).lt("received_at", cutoff)
      .order("received_at", { ascending: true }).limit(SWEEP_BATCH);
    if (pending.error) throw pending.error;
    var rows = (pending.data || []).slice();
    if (ownerAddress(deps.env)) {
      var unsent = await deps.supabase.from(TABLE).select(ROW_COLUMNS).eq("topic", DATA_REQUEST).is("owner_notified_at", null).is("answered_at", null)
        .lt("received_at", cutoff).order("received_at", { ascending: true }).limit(SWEEP_BATCH);
      if (unsent.error) throw unsent.error;
      (unsent.data || []).forEach(function (r) { if (!rows.some(function (x) { return x.id === r.id; })) rows.push(r); });
    }
    var summary = { seen: rows.length, ok: 0, failed: 0 };
    for (var i = 0; i < rows.length; i++) {
      var out = await processReceipt(deps, rows[i]);
      if (out.ok) summary.ok++; else summary.failed++;
    }
    return summary;
  } catch (err) {
    logError(deps, "[ShopifyWebhookSweep] Pass error: " + ((err && err.code) || "error"));
    return { error: (err && err.code) || "error" };
  } finally {
    sweeping = false;
  }
}

/* ── the 23-day reminder, a step of the 04:45 UTC chain ──────────────────── */
async function reminderClaim(supabase, nowMs) {
  var today = iso(nowMs).slice(0, 10), stamp = iso(nowMs);
  var prior = await supabase.from("job_runs").select("last_run_on, started_at").eq("job_name", REMINDER_JOB_NAME).maybeSingle();
  if (prior.error) return { claimed: false, error: prior.error.code || "error" };
  var row = { job_name: REMINDER_JOB_NAME, last_run_on: today, started_at: stamp, finished_at: null, last_error: null };
  var made = await supabase.from("job_runs").insert(row).select("job_name");
  if (!made.error) return { claimed: true, since: null };
  if (made.error.code !== "23505") return { claimed: false, error: made.error.code || "error" };
  var took = await supabase.from("job_runs").update({ last_run_on: today, started_at: stamp, finished_at: null, last_error: null })
    .eq("job_name", REMINDER_JOB_NAME).or("last_run_on.is.null,last_run_on.neq." + today).select("job_name");
  if (took.error) return { claimed: false, error: took.error.code || "error" };
  if (!(took.data || []).length) return { claimed: false };
  var since = prior.data && prior.data.started_at ? Date.parse(prior.data.started_at) : NaN;
  return { claimed: true, since: isNaN(since) ? null : since };
}

/* Emails the owner once for each data request that is REMINDER_AFTER_DAYS or
   more days old, still unanswered, and not yet reminded (no
   request_details.reminded_at; notifyOwner sets it only after a send that
   succeeded, so a failed reminder is sent again on the next daily run).
   Claimed once a day through job_runs. Never rejects. W3: BEFORE it read only
   the requests that turned 23 days old since the last run, so a failed send
   was never tried again. */
async function reminderTick(deps, nowMs) {
  var supabase = deps.supabase;
  var startMs = typeof nowMs === "number" ? nowMs : nowOf(deps);
  var finish = async function (error) {
    var patch = { finished_at: iso(nowOf(deps)) };
    if (error) patch.last_error = String(error).slice(0, 2000);
    var r = await supabase.from("job_runs").update(patch).eq("job_name", REMINDER_JOB_NAME);
    if (r.error) logError(deps, "[ShopifyDataRequestReminder] Failed to record run completion: " + (r.error.code || "error"));
  };
  try {
    var claim = await reminderClaim(supabase, startMs);
    if (!claim.claimed) return { claimed: false, error: claim.error || null };
    var to = iso(startMs - REMINDER_AFTER_DAYS * DAY_MS);
    var due = await supabase.from(TABLE).select(ROW_COLUMNS).eq("topic", DATA_REQUEST).is("answered_at", null)
      .is("request_details->>reminded_at", null).lte("received_at", to).order("received_at", { ascending: true }).limit(SWEEP_BATCH);
    if (due.error) { await finish("shopify_webhook_events read failed: " + (due.error.code || "error")); return { claimed: true, error: "read_failed" }; }
    var rows = due.data || [];
    var sent = 0, failed = 0, error = null;
    if (rows.length && !ownerAddress(deps.env)) error = "no owner address (OPS_ALERT_EMAIL or BACKUP_EMAIL_TO) for " + rows.length + " reminder(s)";
    else {
      for (var i = 0; i < rows.length; i++) {
        var n = await notifyOwner(deps, rows[i], true);
        if (n.sent) sent++; else failed++;
      }
      if (failed) error = failed + " Shopify data request reminder(s) not sent";
    }
    await finish(error);
    return { claimed: true, due: rows.length, sent: sent, failed: failed, error: error };
  } catch (err) {
    try { await finish((err && err.code) || "error"); } catch (finishErr) { /* reported above */ }
    return { claimed: true, error: (err && err.code) || "error" };
  }
}

/* ── the owner's list (GET /api/admin/shopify-data-requests) ─────────────── */
function requestView(r) {
  return { id: r.id, shop: r.shop_domain, received_at: r.received_at, deadline: deadlineOf(r.received_at), owner_notified_at: r.owner_notified_at || null,
    answered_at: r.answered_at || null, open: !r.answered_at, request_details: r.request_details || null };
}

/* Open requests, and those answered within the last 30 days, newest first. */
async function listDataRequests(supabase, nowMs) {
  var got = await supabase.from(TABLE).select(ROW_COLUMNS).eq("topic", DATA_REQUEST).order("received_at", { ascending: false }).limit(500);
  if (got.error) throw got.error;
  var recent = iso(nowMs - RECENT_ANSWERED_MS);
  var rows = (got.data || []).filter(function (r) { return !r.answered_at || r.answered_at >= recent; }).map(requestView);
  return { requests: rows, open: rows.filter(function (r) { return r.open; }).length };
}

/* POST /api/admin/shopify-data-requests/:id/answered. { status, body }. */
async function markAnswered(supabase, id, nowMs) {
  if (typeof id !== "string" || !UUID_RE.test(id)) return { status: 404, body: { error: "No such data request." } };
  var set = await supabase.from(TABLE).update({ answered_at: iso(nowMs) }).eq("id", id).eq("topic", DATA_REQUEST).is("answered_at", null).select(ROW_COLUMNS);
  if (set.error) throw set.error;
  if ((set.data || []).length) return { status: 200, body: { request: requestView(set.data[0]) } };
  var was = await supabase.from(TABLE).select(ROW_COLUMNS).eq("id", id).eq("topic", DATA_REQUEST).maybeSingle();
  if (was.error) throw was.error;
  if (!was.data) return { status: 404, body: { error: "No such data request." } };
  return { status: 200, body: { request: requestView(was.data), already_answered: true } };
}

module.exports = {
  TABLE: TABLE,
  ROW_COLUMNS: ROW_COLUMNS,
  ANSWER_WITHIN_DAYS: ANSWER_WITHIN_DAYS,
  REMINDER_AFTER_DAYS: REMINDER_AFTER_DAYS,
  SWEEP_EVERY_MS: SWEEP_EVERY_MS,
  SWEEP_MIN_AGE_MS: SWEEP_MIN_AGE_MS,
  SWEEP_BATCH: SWEEP_BATCH,
  REMINDER_JOB_NAME: REMINDER_JOB_NAME,
  REDACTED: REDACTED,
  REDACTED_TITLE: REDACTED_TITLE,
  numericIdOf: numericIdOf,
  requestDetailsOf: requestDetailsOf,
  ownerAddress: ownerAddress,
  recordConnectionIds: recordConnectionIds,
  ordersHeld: ordersHeld,
  dataRequestEmail: dataRequestEmail,
  processReceipt: processReceipt,
  sweepTick: sweepTick,
  reminderTick: reminderTick,
  listDataRequests: listDataRequests,
  markAnswered: markAnswered,
  REQUESTS_PAGE_URL: REQUESTS_PAGE_URL,
  REDACT_UNREADABLE_ALERT: REDACT_UNREADABLE_ALERT
};
