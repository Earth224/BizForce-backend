"use strict";

/* ══════════════════════════════════════════════════════════════════════════
   lib/renewalEmails.js — the account emails California's Automatic Renewal
   Law and the Terms promise (L1, Nov 14 2026).

     1. CONFIRMATION, when a checkout makes a subscription active
        (sendConfirmation, from the Stripe webhook's checkout.session.completed
        branch in server.js): the plan, the price, the interval, that it
        renews automatically until cancelled, how to cancel online, the refund
        policy, and links to the Terms and Refunds pages.
     2. YEARLY REMINDER, once every 12 months from the subscription's start
        (yearlyReminderTick, daily in the 04:45 UTC chain, claimed through
        job_runs renewal_yearly_reminder): the same facts.
     3. PRICE CHANGE, from the owner's route POST /api/admin/price-change-notice
        (priceChangeNotice): the old and new price, the date, how to cancel.
        The date must be 7 to 30 days away. IT NEVER CHANGES A STRIPE PRICE:
        the owner changes the price in Stripe separately, on that date.
     4. TERMS CHANGE, when TERMS_VERSION changes (termsChangeTick, daily in the
        same chain, claimed through job_runs terms_change_email, at most
        TERMS_PER_RUN a run): one sentence on what changed (lib/legal.js
        CHANGE_SUMMARY) and links to the Terms and Privacy pages.

   ALL ARE TRANSACTIONAL ACCOUNT EMAIL, never marketing: each goes through
   server.js sendEmail with skipConsentCheck, and a template that does not
   start with "marketing:", so sendEmail adds lib/legal.js contactFooter (the
   contact address and the postal address).

   AT MOST ONE PER MEMBER PER OCCASION. The occasion is in the template name
   (TEMPLATE_PREFIX + the occasion + the member's id), and the email_sends
   ledger row sendEmail writes BEFORE the provider call is the record: a row
   with that template in any status but "failed" means it was sent. A
   "failed" send is tried again by the next pass. Within this process, one
   send per template at a time (inFlight). No migration is needed.

   NOTHING HERE LOGS AN EMAIL ADDRESS: a log line names the member's id and
   the outcome's code only.
   ══════════════════════════════════════════════════════════════════════════ */

const legal = require("./legal");

const TEMPLATE_PREFIX = "account:";
const OCCASION = Object.freeze({
  confirmation: "renewal_confirmation",
  yearly: "renewal_yearly",
  priceChange: "price_change",
  termsChange: "terms_change"
});
const YEARLY_JOB_NAME = "renewal_yearly_reminder";
const TERMS_JOB_NAME = "terms_change_email";
const PRICE_NOTICE_MIN_DAYS = 7;
const PRICE_NOTICE_MAX_DAYS = 30;
const YEARLY_PER_RUN = 200;
const TERMS_PER_RUN = 100;
const PRICE_PER_CALL = 500;
const PAGE = 1000;
const BILLED = ["active", "trialing", "past_due"];
const DAY_MS = 24 * 60 * 60 * 1000;
const MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];

var inFlight = new Set();

function templateFor(occasion, parts) {
  return TEMPLATE_PREFIX + occasion + ":" + parts.map(String).join(":");
}

function money(n) {
  return "$" + (Number.isInteger(n) ? String(n) : Number(n).toFixed(2));
}

/* "2026-11-14" -> "November 14, 2026". */
function longDate(iso) {
  var m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(iso || ""));
  if (!m) return String(iso || "");
  return MONTHS[Number(m[2]) - 1] + " " + Number(m[3]) + ", " + m[1];
}

/* The plan facts every email states, from server.js PLAN_CONFIG.all_access, and the page links. */
function factsFrom(plan, frontendUrl) {
  var base = String(frontendUrl || "https://bizforceai.net").trim().replace(/\/+$/, "");
  return {
    planName: plan.name,
    price: Number(plan.price),
    interval: plan.interval,
    billingUrl: base + "/billing.html",
    termsUrl: base + legal.PAGES.terms,
    refundUrl: base + legal.PAGES.refund,
    privacyUrl: base + legal.PAGES.privacy
  };
}

/* The plain lines of an email, as text and as simple HTML. A line is a string, or { label, url }. */
function render(subject, lines) {
  var text = lines.map(function (l) { return typeof l === "string" ? l : l.label + ": " + l.url; }).join("\n\n");
  var html = '<div style="font-family:system-ui,-apple-system,Segoe UI,sans-serif;max-width:560px;margin:0 auto;padding:28px 22px;color:#1a1a2e">' +
    '<h1 style="font-size:20px;margin:0 0 16px">' + legal.escapeHtml(subject) + "</h1>" +
    lines.map(function (l) {
      if (typeof l === "string") return '<p style="font-size:15px;line-height:1.6;margin:0 0 14px">' + legal.escapeHtml(l) + "</p>";
      return '<p style="font-size:15px;line-height:1.6;margin:0 0 14px">' + legal.escapeHtml(l.label) + ': <a href="' + legal.escapeHtml(l.url) + '">' + legal.escapeHtml(l.url) + "</a></p>";
    }).join("") + "</div>";
  return { subject: subject, text: subject + "\n\n" + text, html: html };
}

/* What every renewal email says about the plan, cancelling and refunds. */
function planLines(f) {
  return [
    "Your plan: " + f.planName + ", " + money(f.price) + " every " + f.interval + ".",
    "It renews automatically every " + f.interval + ", and your card is charged " + money(f.price) + " at the start of each new " + f.interval + ", until you cancel.",
    "How to cancel: you can cancel online at any time. Sign in, open Billing, and choose \"Manage / Cancel Subscription\". Cancelling stops the next renewal; you keep access until the end of the " + f.interval + " you have already paid for, and you are not charged again.",
    { label: "Billing", url: f.billingUrl },
    "Refunds: " + legal.REFUND_POLICY.join(" "),
    { label: "Terms of Service", url: f.termsUrl },
    { label: "Refund policy", url: f.refundUrl }
  ];
}

function confirmationEmail(f) {
  return render("Your BizForce AI subscription: " + f.planName + ", " + money(f.price) + " every " + f.interval,
    ["Thank you for subscribing to BizForce AI. This email confirms your subscription and how to cancel it."].concat(planLines(f)));
}

function yearlyEmail(f) {
  return render("A yearly reminder about your BizForce AI subscription",
    ["This is your yearly reminder about your BizForce AI subscription."].concat(planLines(f)));
}

function priceChangeEmail(f, newPrice, effectiveDate) {
  return render("The price of your BizForce AI subscription is changing", [
    "The price of " + f.planName + " is changing from " + money(f.price) + " to " + money(newPrice) + " every " + f.interval + ", starting " + longDate(effectiveDate) + ".",
    "From that date your subscription renews automatically at " + money(newPrice) + " every " + f.interval + " until you cancel. If you do not want to pay the new price, cancel before " + longDate(effectiveDate) + ".",
    "How to cancel: sign in, open Billing, and choose \"Manage / Cancel Subscription\". Cancelling stops the next renewal; you keep access until the end of the " + f.interval + " you have already paid for, and you are not charged again.",
    { label: "Billing", url: f.billingUrl },
    "Refunds: " + legal.REFUND_POLICY.join(" "),
    { label: "Terms of Service", url: f.termsUrl },
    { label: "Refund policy", url: f.refundUrl }
  ]);
}

function termsChangeEmail(f) {
  return render("We've updated our Terms and Privacy Policy", [
    "We updated the BizForce AI Terms of Service and Privacy Policy on " + longDate(legal.TERMS_VERSION) + " (version " + legal.TERMS_VERSION + ").",
    "What changed: " + legal.CHANGE_SUMMARY,
    { label: "Terms of Service", url: f.termsUrl },
    { label: "Privacy Policy", url: f.privacyUrl },
    "The next time you sign in, BizForce shows a notice with a link to the new Terms and a button to accept them. If you do not agree to them, you can cancel on Billing and delete your account; changes do not apply to a " + f.interval + " you have already paid for."
  ]);
}

/* Whether the effective date of a price change is 7 to 30 days after today (UTC). */
function priceNoticeWindow(effectiveDate, nowMs) {
  var m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(effectiveDate || ""));
  if (!m) return { ok: false, error: "Give the date the new price applies as YYYY-MM-DD." };
  var at = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  if (new Date(at).toISOString().slice(0, 10) !== effectiveDate) return { ok: false, error: "That date does not exist." };
  var now = new Date(nowMs);
  var today = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  var days = Math.round((at - today) / DAY_MS);
  if (days < PRICE_NOTICE_MIN_DAYS || days > PRICE_NOTICE_MAX_DAYS) {
    return { ok: false, days: days, error: "The new price must apply " + PRICE_NOTICE_MIN_DAYS + " to " + PRICE_NOTICE_MAX_DAYS + " days from today; that date is " + days + " day(s) away. Nothing was sent." };
  }
  return { ok: true, days: days };
}

/* Was this template already sent? Any ledger row but a failed one counts. Throws on a read error. */
async function alreadySent(supabase, template) {
  var r = await supabase.from("email_sends").select("id, status").eq("template", template).limit(20);
  if (r.error) throw r.error;
  return (r.data || []).some(function (row) { return row.status !== "failed"; });
}

/* deps: { supabase, sendEmail(options), contactFor(userId, email) }. Returns { sent, reason }. Never throws. */
async function sendOnce(deps, userId, email, template, mail) {
  if (inFlight.has(template)) return { sent: false, reason: "in_flight" };
  inFlight.add(template);
  try {
    if (await alreadySent(deps.supabase, template)) return { sent: false, reason: "already_sent" };
    if (typeof email !== "string" || email.indexOf("@") === -1 || /@deleted\.invalid$/.test(email)) return { sent: false, reason: "no_address" };
    var contactId = await deps.contactFor(userId, email);
    if (!contactId) return { sent: false, reason: "no_contact" };
    var r = await deps.sendEmail({ contactId: contactId, to: email, subject: mail.subject, html: mail.html, text: mail.text, template: template, skipConsentCheck: true });
    return r && r.sent ? { sent: true } : { sent: false, reason: (r && r.reason) || "unknown" };
  } catch (err) {
    return { sent: false, reason: "error" };
  } finally {
    inFlight.delete(template);
  }
}

async function memberRow(supabase, userId) {
  var r = await supabase.from("users").select("id, email, role").eq("id", userId).maybeSingle();
  if (r.error) throw r.error;
  return r.data && r.data.role !== "deleted" ? r.data : null;
}

/* 1. The confirmation. One per Stripe subscription (or per account, when Stripe named none). Never throws. */
async function sendConfirmation(deps, userId, subscriptionId) {
  try {
    var member = await memberRow(deps.supabase, userId);
    if (!member) return { sent: false, reason: "no_member" };
    var template = templateFor(OCCASION.confirmation, [subscriptionId || ("account-" + userId)]);
    var out = await sendOnce(deps, userId, member.email, template, confirmationEmail(deps.facts));
    console.log("[RenewalEmail] confirmation for user " + userId + ": " + (out.sent ? "sent" : out.reason));
    return out;
  } catch (err) {
    console.error("[RenewalEmail] confirmation for user " + userId + " not sent: " + ((err && err.code) || "error"));
    return { sent: false, reason: "error" };
  }
}

/* Whole months from start to now, counting a month only once its day has come. */
function monthsSince(startIso, nowMs) {
  var s = new Date(startIso), n = new Date(nowMs);
  if (!isFinite(s.getTime())) return -1;
  var months = (n.getUTCFullYear() - s.getUTCFullYear()) * 12 + (n.getUTCMonth() - s.getUTCMonth());
  if (n.getUTCDate() < s.getUTCDate()) months--;
  return months;
}

/* 2. The yearly reminder pass. Never rejects. */
async function yearlyReminderTick(deps, nowMs) {
  var claim = require("./dailyClaim");
  var startedMs = typeof nowMs === "number" ? nowMs : deps.now();
  var result = { claimed: true, due: 0, sent: 0, already: 0, failed: 0, error: null };
  try {
    if (!(await claim.claimToday(deps.supabase, YEARLY_JOB_NAME, startedMs))) return { claimed: false };
    // Test accounts (which cannot receive mail) and the owner are not subscribers (lib/testAccounts.js isUncountedAccount).
    var uncounted = require("./testAccounts").isUncountedAccount;
    var subs = await deps.supabase.from("subscriptions").select("user_id, status, cancel_at_period_end, created_at").in("status", BILLED).limit(PAGE);
    if (subs.error) throw new Error("subscriptions could not be read");
    for (var i = 0; i < (subs.data || []).length && result.sent < YEARLY_PER_RUN; i++) {
      var s = subs.data[i];
      if (s.cancel_at_period_end === true || !s.user_id) continue;
      var year = Math.floor(monthsSince(s.created_at, startedMs) / 12);
      if (year < 1) continue;
      result.due++;
      var member = await memberRow(deps.supabase, s.user_id);
      if (!member || uncounted(member)) continue;
      var out = await sendOnce(deps, s.user_id, member.email, templateFor(OCCASION.yearly, [s.user_id, year]), yearlyEmail(deps.facts));
      if (out.sent) result.sent++; else if (out.reason === "already_sent") result.already++; else result.failed++;
    }
    await claim.recordFinish(deps.supabase, YEARLY_JOB_NAME, deps.now(), null);
    console.log("[RenewalEmail] yearly reminders: " + result.due + " due, " + result.sent + " sent, " + result.already + " already sent, " + result.failed + " not sent.");
    return result;
  } catch (err) {
    var message = (err && err.message) || "error";
    console.error("[RenewalEmail] yearly reminder pass error: " + message);
    await claim.recordFinish(deps.supabase, YEARLY_JOB_NAME, deps.now(), message);
    return { claimed: true, error: message };
  }
}

/* 3. The price-change notice. input: { new_price, effective_date }. Returns { status, body }. Never changes Stripe. */
async function priceChangeNotice(deps, input, nowMs) {
  var b = input || {};
  var newPrice = typeof b.new_price === "number" ? b.new_price : NaN;
  if (!(newPrice > 0 && newPrice <= 100000 && Math.round(newPrice * 100) === newPrice * 100)) {
    return { status: 400, body: { error: "Give the new monthly price in dollars, for example 249 or 249.50. Nothing was sent.", code: "bad_price" } };
  }
  if (newPrice === deps.facts.price) return { status: 400, body: { error: "That is today's price. Nothing was sent.", code: "same_price" } };
  var win = priceNoticeWindow(b.effective_date, nowMs);
  if (!win.ok) return { status: 400, body: { error: win.error, code: "window", days: win.days === undefined ? null : win.days } };
  // Test accounts (which cannot receive mail) and the owner are not subscribers (lib/testAccounts.js isUncountedAccount).
  var uncounted = require("./testAccounts").isUncountedAccount;
  var subs = await deps.supabase.from("subscriptions").select("user_id, status").in("status", BILLED).limit(PAGE);
  if (subs.error) throw subs.error;
  var ids = [];
  (subs.data || []).forEach(function (s) { if (s.user_id && ids.indexOf(s.user_id) === -1) ids.push(s.user_id); });
  var mail = priceChangeEmail(deps.facts, newPrice, b.effective_date);
  var tally = { subscribers: ids.length, sent: 0, already: 0, failed: 0, not_customers: 0, left: 0 };
  for (var i = 0; i < ids.length; i++) {
    if (tally.sent >= PRICE_PER_CALL) { tally.left = ids.length - i; break; }
    var member = await memberRow(deps.supabase, ids[i]);
    if (!member) { tally.failed++; continue; }
    if (uncounted(member)) { tally.not_customers++; continue; }
    var out = await sendOnce(deps, ids[i], member.email, templateFor(OCCASION.priceChange, [b.effective_date, Math.round(newPrice * 100), ids[i]]), mail);
    if (out.sent) tally.sent++; else if (out.reason === "already_sent") tally.already++; else tally.failed++;
  }
  console.log("[RenewalEmail] price-change notice for " + b.effective_date + ": " + tally.sent + " sent, " + tally.already + " already sent, " + tally.failed + " not sent, " + tally.left + " left.");
  return { status: 200, body: Object.assign({ old_price: deps.facts.price, new_price: newPrice, effective_date: b.effective_date, days_away: win.days,
    stripe_price_changed: false,
    note: "Emails only. This does not change any price in Stripe: change the price in Stripe yourself, to apply on " + b.effective_date + ". Sending again sends only to those not yet emailed." }, tally) };
}

/* 4. The terms-change pass. Never rejects. */
async function termsChangeTick(deps, nowMs) {
  var claim = require("./dailyClaim");
  var startedMs = typeof nowMs === "number" ? nowMs : deps.now();
  var result = { claimed: true, version: legal.TERMS_VERSION, sent: 0, already: 0, accepted: 0, failed: 0, error: null };
  try {
    if (!(await claim.claimToday(deps.supabase, TERMS_JOB_NAME, startedMs))) return { claimed: false };
    for (var page = 0; page < 50 && result.sent < TERMS_PER_RUN; page++) {
      var users = await deps.supabase.from("users").select("id, email, role, terms_version").order("id", { ascending: true }).range(page * PAGE, page * PAGE + PAGE - 1);
      if (users.error) throw new Error("users could not be read");
      var rows = users.data || [];
      for (var i = 0; i < rows.length && result.sent < TERMS_PER_RUN; i++) {
        var u = rows[i];
        // A test account's address cannot receive mail, so a send would fail and be tried again every day.
        if (u.role === "deleted" || require("./testAccounts").isTestAccount(u)) continue;
        // A member who has already accepted this version has seen it.
        if (!legal.needsAcceptance(u.terms_version)) { result.accepted++; continue; }
        var out = await sendOnce(deps, u.id, u.email, templateFor(OCCASION.termsChange, [legal.TERMS_VERSION, u.id]), termsChangeEmail(deps.facts));
        if (out.sent) result.sent++; else if (out.reason === "already_sent") result.already++; else result.failed++;
      }
      if (rows.length < PAGE) break;
    }
    await claim.recordFinish(deps.supabase, TERMS_JOB_NAME, deps.now(), null);
    console.log("[RenewalEmail] terms-change emails for " + legal.TERMS_VERSION + ": " + result.sent + " sent, " + result.already + " already sent, " +
      result.accepted + " already accepted, " + result.failed + " not sent.");
    return result;
  } catch (err) {
    var message = (err && err.message) || "error";
    console.error("[RenewalEmail] terms-change pass error: " + message);
    await claim.recordFinish(deps.supabase, TERMS_JOB_NAME, deps.now(), message);
    return { claimed: true, error: message };
  }
}

module.exports = {
  TEMPLATE_PREFIX: TEMPLATE_PREFIX, OCCASION: OCCASION, YEARLY_JOB_NAME: YEARLY_JOB_NAME, TERMS_JOB_NAME: TERMS_JOB_NAME,
  PRICE_NOTICE_MIN_DAYS: PRICE_NOTICE_MIN_DAYS, PRICE_NOTICE_MAX_DAYS: PRICE_NOTICE_MAX_DAYS, TERMS_PER_RUN: TERMS_PER_RUN, YEARLY_PER_RUN: YEARLY_PER_RUN,
  templateFor: templateFor, longDate: longDate, factsFrom: factsFrom, monthsSince: monthsSince,
  confirmationEmail: confirmationEmail, yearlyEmail: yearlyEmail, priceChangeEmail: priceChangeEmail, termsChangeEmail: termsChangeEmail,
  priceNoticeWindow: priceNoticeWindow, alreadySent: alreadySent, sendOnce: sendOnce,
  sendConfirmation: sendConfirmation, yearlyReminderTick: yearlyReminderTick, priceChangeNotice: priceChangeNotice, termsChangeTick: termsChangeTick
};
