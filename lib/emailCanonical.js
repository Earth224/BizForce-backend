"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   lib/emailCanonical.js — one account per inbox (P3-1, Nov 20 2026).

   THE SAME RULE AS THE DATABASE. Migration 195's public.email_canonical(text)
   folds an address so that every spelling of one inbox reads the same:
     - lowercase and trimmed;
     - the +tag is removed from the local part, for every domain;
     - dots are removed from the local part for gmail.com and googlemail.com;
     - googlemail.com becomes gmail.com.
   The test domain @bizforceai.invalid is NOT folded (only lowercased and
   trimmed), so the check suite's accounts there stay distinct. A local part
   that would fold to nothing (for example "+x@site.com") is kept as it is.
   An address without an "@" is only lowercased and trimmed.

   POST /api/auth/register asks canonicalEmail() before it inserts and answers
   409 ALREADY_USED when another account holds the same canonical value; the
   unique index users_email_canonical_key is the backstop, and its 23505 is
   answered with the same 409. scripts/checkSignupCanonical.js holds this
   function to the SQL text of migration 195, case by case.
   ══════════════════════════════════════════════════════════════════════════ */

var EXEMPT_DOMAIN = "bizforceai.invalid";
var GMAIL_DOMAINS = ["gmail.com", "googlemail.com"];
var ALREADY_USED = "An account already uses this email";

function canonicalEmail(email) {
  if (email === null || email === undefined) return null;
  var e = String(email).trim().toLowerCase();
  var at = e.lastIndexOf("@");
  if (at === -1) return e;
  var loc = e.slice(0, at), dom = e.slice(at + 1);
  if (dom === EXEMPT_DOMAIN) return e;
  var loc2 = loc.split("+")[0];
  if (GMAIL_DOMAINS.indexOf(dom) !== -1) loc2 = loc2.split(".").join("");
  if (loc2 === "") return e;
  return loc2 + "@" + (dom === "googlemail.com" ? "gmail.com" : dom);
}

module.exports = { canonicalEmail, ALREADY_USED, EXEMPT_DOMAIN, GMAIL_DOMAINS };
