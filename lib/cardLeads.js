"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   lib/cardLeads.js — Card upgrades C2 (migration 172, Nov 6 2026): the lead
   form a member can turn on for a digital card.

   A visitor leaves a name, an email or a phone number, a message, and ticks a
   consent box. What is stored is exactly that, the consent sentence the
   SERVER built from the card's public name, a status and the time. Nothing
   about the visitor's device: no address, User-Agent, referrer or cookie.

   SPAM DEFENCES THAT NEED NO THIRD PARTY
     - A form token: HMAC-SHA256 over "card-lead|<card id>|<issued at>", keyed
       by an HKDF derivation of JWT_SECRET (info FORM_KEY_INFO). The raw secret
       never keys anything here. A submission is accepted only from 3 seconds
       to 2 hours after the token was issued, for the same card, compared in
       constant time.
     - A honeypot field, "website", hidden from people. Filled in, the request
       is answered exactly as a success and nothing is stored or sent.
     - Per-card caps: 5 leads in an hour, 20 in a day.
     - A dedupe: the same email or phone on the same card within a day stores
       nothing new and is answered as a success.
     - An IP limiter in server.js, a backstop only.

   RETENTION: a daily pass (cardLeadsPurgeTick, its own job_runs row) deletes
   leads older than 12 months, and never anything younger.

   Pure apart from what is injected: crypto, and a Supabase client for the
   purge. It never requires server.js.
   ══════════════════════════════════════════════════════════════════════════ */

var crypto = require("crypto");

var FORM_KEY_INFO = "bizforce-card-lead-form-v1";
var FORM_SECRET_ENV = "JWT_SECRET";
var FORM_MIN_AGE_MS = 3 * 1000;
var FORM_MAX_AGE_MS = 2 * 60 * 60 * 1000;

// The patterns migration 172's checks hold (card_leads_email_check, card_leads_phone_check).
var EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
var PHONE_RE = /^[0-9+() .-]{3,40}$/;

var NAME_MAX = 120, EMAIL_MAX = 254, MESSAGE_MAX = 1000, CONSENT_MAX = 300;
var HOUR_CAP = 5, DAY_CAP = 20;
var HOUR_MS = 60 * 60 * 1000, DAY_MS = 24 * HOUR_MS;
var NOTICE_TYPE = "card_lead";
var NOTICE_GAP_MS = HOUR_MS;
var LIST_PAGE = 50;
var OWNER_STATUSES = ["read", "archived"];
var RETENTION_MONTHS = 12;

var PURGE_JOB_NAME = "card_leads_purge";
var PURGE_BATCH = 500;
var PURGE_MAX_PER_TICK = 50000;

var MESSAGES = {
  notFound: "Card not found",
  tryAgain: "Please take a moment and try again.",
  name: "Leave your name, up to 120 characters.",
  email: "That email address doesn't look right.",
  phone: "That phone number doesn't look right.",
  contact: "Leave an email or a phone number so they can reach you.",
  message: "Keep the message to 1,000 characters.",
  consent: "Tick the box to send your details.",
  capped: "This card isn't taking more messages right now. Try again later.",
  failed: "Your details could not be sent just now. Try again later.",
  status: "A lead is marked read or archived.",
  noticeTitle: "New lead on your digital card",
  noticeBody: "Someone left their details on your card. Open Digital Cards to see your leads."
};

/* ── the form token ──────────────────────────────────────────────────────── */

/* The token key: HKDF-SHA256 of the server secret with FORM_KEY_INFO as the
   label, so the secret itself never keys an HMAC. Null when there is no
   secret, and then no form is offered. */
function formKey(secret) {
  if (typeof secret !== "string" || secret === "") return null;
  return Buffer.from(crypto.hkdfSync("sha256", Buffer.from(secret, "utf8"), Buffer.alloc(0), Buffer.from(FORM_KEY_INFO, "utf8"), 32));
}

function signForm(key, cardId, issuedAt) {
  return crypto.createHmac("sha256", key).update("card-lead|" + cardId + "|" + issuedAt).digest("base64url");
}

/* { form_token, form_issued_at } for a card, or null without a secret. */
function issueFormToken(cardId, issuedAtIso, secret) {
  var key = formKey(secret);
  if (!key || typeof cardId !== "string" || !cardId || typeof issuedAtIso !== "string") return null;
  return { form_token: signForm(key, cardId, issuedAtIso), form_issued_at: issuedAtIso };
}

/* True only for this card's own token, issued 3 seconds to 2 hours before
   nowMs (both edges included). The signature is compared in constant time. */
function checkFormToken(cardId, token, issuedAt, nowMs, secret) {
  var key = formKey(secret);
  if (!key || typeof cardId !== "string" || typeof token !== "string" || typeof issuedAt !== "string") return false;
  if (issuedAt.length > 40 || token.length > 100) return false;
  var issuedMs = Date.parse(issuedAt);
  if (!isFinite(issuedMs) || new Date(issuedMs).toISOString() !== issuedAt) return false;
  var age = nowMs - issuedMs;
  if (!(age >= FORM_MIN_AGE_MS && age <= FORM_MAX_AGE_MS)) return false;
  var want = Buffer.from(signForm(key, cardId, issuedAt), "utf8");
  var got = Buffer.from(token, "utf8");
  if (got.length !== want.length) return false;
  return crypto.timingSafeEqual(got, want);
}

/* ── what the visitor sends ──────────────────────────────────────────────── */

/* Control characters go, except the newline; a CR LF or lone CR becomes a newline. */
function stripControls(value) {
  return String(value).replace(/\r\n?/g, "\n").replace(/[\u0000-\u0009\u000B-\u001F\u007F]/g, "");
}

function honeypotFilled(body) {
  var v = body ? body.website : undefined;
  if (v === undefined || v === null) return false;
  if (typeof v === "string") return v.trim() !== "";
  return true;
}

function optionalText(value) {
  if (value === undefined || value === null) return { value: "" };
  if (typeof value !== "string") return { bad: true };
  return { value: stripControls(value).trim() };
}

/* { lead: { name, email, phone, message } } or { error }. */
function validateLead(body) {
  var b = body && typeof body === "object" ? body : {};
  if (typeof b.name !== "string") return { error: MESSAGES.name };
  var name = stripControls(b.name).replace(/\n/g, " ").replace(/\s+/g, " ").trim();
  if (name.length < 1 || name.length > NAME_MAX) return { error: MESSAGES.name };

  var e = optionalText(b.email);
  if (e.bad) return { error: MESSAGES.email };
  var email = e.value.replace(/\n/g, "").toLowerCase();
  if (email && (email.length > EMAIL_MAX || !EMAIL_RE.test(email))) return { error: MESSAGES.email };

  var p = optionalText(b.phone);
  if (p.bad) return { error: MESSAGES.phone };
  var phone = p.value.replace(/\n/g, "");
  if (phone && !PHONE_RE.test(phone)) return { error: MESSAGES.phone };

  if (!email && !phone) return { error: MESSAGES.contact };

  var m = optionalText(b.message);
  if (m.bad) return { error: MESSAGES.message };
  if (m.value.length > MESSAGE_MAX) return { error: MESSAGES.message };

  if (b.consent !== true) return { error: MESSAGES.consent };

  return { lead: { name: name, email: email || null, phone: phone || null, message: m.value } };
}

/* ── the words, built on the server from the card ────────────────────────── */

function publicName(fullName) {
  var n = stripControls(String(fullName == null ? "" : fullName)).replace(/\s+/g, " ").trim();
  return n || "the owner of this card";
}

var CONSENT_HEAD = "I agree that ", CONSENT_TAIL = " may contact me about this message.";

/* "I agree that <full_name> may contact me about this message.", the name cut
   (by whole characters) so the sentence is at most 300 characters. */
function consentSentence(fullName) {
  var chars = Array.from(publicName(fullName));
  var room = CONSENT_MAX - CONSENT_HEAD.length - CONSENT_TAIL.length;
  var name = "";
  for (var i = 0; i < chars.length; i++) {
    if ((name + chars[i]).length > room) break;
    name += chars[i];
  }
  return CONSENT_HEAD + name.trim() + CONSENT_TAIL;
}

function firstName(fullName) {
  var n = stripControls(String(fullName == null ? "" : fullName)).replace(/\s+/g, " ").trim();
  var first = n ? n.split(" ")[0] : "";
  return first ? Array.from(first).slice(0, 60).join("") : "They";
}

/* The answer to a new lead, a dedupe and a honeypot alike. */
function successBody(fullName) {
  return { ok: true, message: "Sent. " + firstName(fullName) + " will see your details." };
}

/* ── caps and dedupe, over the card's leads of the last 24 hours ─────────── */

function sinceIso(nowMs, ms) { return new Date(nowMs - ms).toISOString(); }

/* True when the card already has 5 leads in the last hour or 20 in the last 24 hours. */
function capReached(recent, nowMs) {
  var hour = 0, day = 0;
  (recent || []).forEach(function (r) {
    var at = Date.parse(r && r.created_at);
    if (!isFinite(at)) return;
    var age = nowMs - at;
    if (age < 0 || age > DAY_MS) return;
    day++;
    if (age <= HOUR_MS) hour++;
  });
  return hour >= HOUR_CAP || day >= DAY_CAP;
}

function digitsOf(phone) { return String(phone || "").replace(/[^0-9]/g, ""); }

/* True when a lead from the last 24 hours on this card has the same email, or the same phone. */
function isDuplicate(recent, lead, nowMs) {
  return (recent || []).some(function (r) {
    var at = Date.parse(r && r.created_at);
    if (!isFinite(at) || nowMs - at > DAY_MS) return false;
    if (lead.email && r.email && String(r.email).toLowerCase() === lead.email) return true;
    if (lead.phone && r.phone && digitsOf(r.phone) !== "" && digitsOf(r.phone) === digitsOf(lead.phone)) return true;
    return false;
  });
}

/* A notice is due when the member has none of type card_lead in the last hour. */
function noticeDue(latestAt, nowMs) {
  var at = Date.parse(latestAt);
  return !isFinite(at) || nowMs - at >= NOTICE_GAP_MS;
}

/* ── retention ───────────────────────────────────────────────────────────── */

/* 12 calendar months before nowMs. A lead is deleted when created_at is
   strictly before it; one exactly 12 months old waits a day. */
function retentionCutoff(nowMs) {
  var d = new Date(nowMs);
  d.setUTCMonth(d.getUTCMonth() - RETENTION_MONTHS);
  return d.toISOString();
}

async function claimPurgeDay(supabase, nowMs) {
  var today = new Date(nowMs).toISOString().slice(0, 10);
  var started = new Date(nowMs).toISOString();
  var inserted = await supabase
    .from("job_runs")
    .insert({ job_name: PURGE_JOB_NAME, last_run_on: today, started_at: started, finished_at: null, last_error: null })
    .select("job_name");
  if (!inserted.error) return true;
  // 23505 = unique_violation: the row exists. Anything else is a failure, never a claim.
  if (inserted.error.code !== "23505") {
    console.error("[CardLeadsPurge] Claim insert failed: " + (inserted.error.code || "error"));
    return false;
  }
  var updated = await supabase
    .from("job_runs")
    .update({ last_run_on: today, started_at: started, finished_at: null, last_error: null })
    .eq("job_name", PURGE_JOB_NAME)
    .or("last_run_on.is.null,last_run_on.neq." + today)
    .select("job_name");
  if (updated.error) {
    console.error("[CardLeadsPurge] Claim update failed: " + (updated.error.code || "error"));
    return false;
  }
  return (updated.data || []).length > 0;
}

async function finishPurge(supabase, errorMessage) {
  var patch = { finished_at: new Date().toISOString() };
  if (errorMessage) patch.last_error = String(errorMessage).slice(0, 2000);
  var result = await supabase.from("job_runs").update(patch).eq("job_name", PURGE_JOB_NAME);
  if (result.error) console.error("[CardLeadsPurge] Failed to record run completion: " + (result.error.code || "error"));
}

/* The pass body: ids older than the cutoff, a batch at a time, deleted with the cutoff repeated. */
async function runPurgePass(supabase, nowMs) {
  var cutoff = retentionCutoff(nowMs);
  var summary = { cutoff: cutoff, batches: 0, rows_read: 0, rows_deleted: 0, ceiling_reached: false, error: null };
  while (summary.rows_read < PURGE_MAX_PER_TICK) {
    var size = Math.min(PURGE_BATCH, PURGE_MAX_PER_TICK - summary.rows_read);
    var page = await supabase.from("card_leads").select("id").lt("created_at", cutoff).order("created_at", { ascending: true }).limit(size);
    if (page.error) { summary.error = "batch " + (summary.batches + 1) + ": card_leads could not be read: " + (page.error.code || "error"); break; }
    var ids = (page.data || []).map(function (row) { return row.id; });
    if (!ids.length) break;
    summary.batches++;
    summary.rows_read += ids.length;
    var removed = await supabase.from("card_leads").delete().in("id", ids).lt("created_at", cutoff).select("id");
    if (removed.error) { summary.error = "batch " + summary.batches + ": card_leads delete failed: " + (removed.error.code || "error"); break; }
    summary.rows_deleted += (removed.data || []).length;
    if (ids.length < size) break;
  }
  if (!summary.error && summary.rows_read >= PURGE_MAX_PER_TICK) summary.ceiling_reached = true;
  console.log("[CardLeadsPurge] Pass finished: " + summary.rows_deleted + " lead(s) older than " + cutoff + " deleted in " + summary.batches + " batch(es)" +
    (summary.ceiling_reached ? "; the ceiling was reached and the rest wait for tomorrow" : "") + (summary.error ? "; stopped: " + summary.error : "") + ".");
  return summary;
}

/* The cron's whole job: claim the day, run the pass, close the claim. Never rejects. */
async function cardLeadsPurgeTick(supabase, nowMs) {
  var startedMs = typeof nowMs === "number" ? nowMs : Date.now();
  try {
    if (!(await claimPurgeDay(supabase, startedMs))) return { claimed: false };
    var summary = await runPurgePass(supabase, startedMs);
    await finishPurge(supabase, summary.error);
    return { claimed: true, summary: summary };
  } catch (err) {
    console.error("[CardLeadsPurge] Pass error: " + ((err && err.code) || "error"));
    try { await finishPurge(supabase, (err && err.code) || "error"); } catch (finishErr) { /* reported above */ }
    return { claimed: true, error: (err && err.code) || "error" };
  }
}

module.exports = {
  FORM_KEY_INFO: FORM_KEY_INFO, FORM_SECRET_ENV: FORM_SECRET_ENV, FORM_MIN_AGE_MS: FORM_MIN_AGE_MS, FORM_MAX_AGE_MS: FORM_MAX_AGE_MS,
  EMAIL_RE: EMAIL_RE, PHONE_RE: PHONE_RE, NAME_MAX: NAME_MAX, EMAIL_MAX: EMAIL_MAX, MESSAGE_MAX: MESSAGE_MAX, CONSENT_MAX: CONSENT_MAX,
  HOUR_CAP: HOUR_CAP, DAY_CAP: DAY_CAP, HOUR_MS: HOUR_MS, DAY_MS: DAY_MS, NOTICE_TYPE: NOTICE_TYPE, NOTICE_GAP_MS: NOTICE_GAP_MS,
  LIST_PAGE: LIST_PAGE, OWNER_STATUSES: OWNER_STATUSES, RETENTION_MONTHS: RETENTION_MONTHS,
  PURGE_JOB_NAME: PURGE_JOB_NAME, PURGE_BATCH: PURGE_BATCH, PURGE_MAX_PER_TICK: PURGE_MAX_PER_TICK, MESSAGES: MESSAGES,
  formKey: formKey, issueFormToken: issueFormToken, checkFormToken: checkFormToken,
  stripControls: stripControls, honeypotFilled: honeypotFilled, validateLead: validateLead,
  publicName: publicName, consentSentence: consentSentence, firstName: firstName, successBody: successBody,
  sinceIso: sinceIso, capReached: capReached, isDuplicate: isDuplicate, noticeDue: noticeDue,
  retentionCutoff: retentionCutoff, claimPurgeDay: claimPurgeDay, runPurgePass: runPurgePass, cardLeadsPurgeTick: cardLeadsPurgeTick
};
