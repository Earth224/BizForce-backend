// ── BizCash (BFC) transfer limits ───────────────────────────────────────────
//
// POST /api/wallet/transfer moved any amount, any number of times a day, from
// an account of any age, to any uuid at all — bfc_transfer upserted a wallet
// for an id no account had, and the BFC sent there was gone. The launch audit
// (2026-10-19, item #13) asked for three limits and a recipient check. The
// recipient check needs no setting; the three limits are read from here:
//
//   BFC_TRANSFER_MAX         the most one transfer may move.
//                            Default 1,000 BFC: the size of the welcome
//                            bonus, so a member can pass their whole bonus on
//                            in one go, and nobody can move more in one.
//   BFC_TRANSFER_DAILY_CAP   the most one account may send in any 24 hours.
//                            Default 2,000 BFC: two full transfers a day. All
//                            BFC outstanding on 2026-10-19 was 13,000 across
//                            15 wallets, and the most an account can ever earn
//                            is 2,200 (the 1,000 bonus plus 12 certifications
//                            at 100), so 2,000 a day covers every honest use
//                            and slows any drain to a crawl.
//   BFC_TRANSFER_HOLD_DAYS   how long a new account must wait before sending.
//                            Default 7 days, counted from users.created_at, so
//                            an account opened to receive and pass on credits
//                            cannot do it the same week.
//
// The 24 hours are a rolling window, not a calendar day, so there is no
// midnight at which a second full cap opens up.
//
// PARSED LIKE THE OTHER CAPS (lib/youtubeQuota.js youtubeCap): absent or blank
// gives the default; a whole number in range is honoured; anything else —
// "abc", "2.5", "-1" — makes the setting unusable, and an unusable setting
// stops every transfer with a message naming the variable. A typo must never
// lift a limit. The amounts must be at least 1; the hold may be 0, which
// turns the hold off on purpose.
//
// A CAMPAIGN DONATION IS LIMITED THE SAME WAY (launch hardening, 2026-10-27).
// bfc_donate (migration 148) takes the same three limits as bfc_send, and the
// 24 hours are ONE total: a member's 'Transfer' debits and their 'Donation: '
// debits are summed together, by both functions and by both routes
// (bfcCountsTowardDailyCap below), so 2,000 BFC a day is 2,000 across both,
// not 2,000 of each. Self-donation is refused, as self-transfer is.
//
// What these do NOT limit: a marketplace purchase (bfc_buy_listing) also
// moves BFC between members, through bfc_transfer directly. It is priced by a
// listing, not chosen by the sender, and is not capped here.

var BFC_TRANSFER_MAX_DEFAULT = 1000;
var BFC_TRANSFER_DAILY_CAP_DEFAULT = 2000;
var BFC_TRANSFER_HOLD_DAYS_DEFAULT = 7;

// The description every member-to-member transfer is written under, and the
// one the 24-hour sum counts. bfc_send (migration 139) writes the same text.
var BFC_TRANSFER_DESCRIPTION = "Transfer";

// What bfc_donate's debit is described as: "Donation: " and the campaign's
// title (migration 031, unchanged by 148).
var BFC_DONATION_DESCRIPTION_PREFIX = "Donation: ";

// Whether one of a member's debits counts toward the shared 24-hour total.
// The SQL counts the same two: description = 'Transfer' or
// description like 'Donation: %'.
function bfcCountsTowardDailyCap(description) {
  return description === BFC_TRANSFER_DESCRIPTION ||
    (typeof description === "string" && description.indexOf(BFC_DONATION_DESCRIPTION_PREFIX) === 0);
}

function bfcTransferSetting(raw, dflt, min) {
  if (raw == null || String(raw).trim() === "") {
    return dflt;
  }

  var parsed = Number(String(raw).trim());
  if (Number.isFinite(parsed) && Number.isInteger(parsed) && parsed >= min) {
    return parsed;
  }

  return null;
}

// All three limits, and the reason no transfer may be made when one is unusable.
function bfcTransferLimits(env) {
  env = env || process.env;
  var max = bfcTransferSetting(env.BFC_TRANSFER_MAX, BFC_TRANSFER_MAX_DEFAULT, 1);
  var dailyCap = bfcTransferSetting(env.BFC_TRANSFER_DAILY_CAP, BFC_TRANSFER_DAILY_CAP_DEFAULT, 1);
  var holdDays = bfcTransferSetting(env.BFC_TRANSFER_HOLD_DAYS, BFC_TRANSFER_HOLD_DAYS_DEFAULT, 0);
  var error = max === null ? "BFC_TRANSFER_MAX is set to \"" + env.BFC_TRANSFER_MAX + "\", which is not a whole number of at least 1"
    : dailyCap === null ? "BFC_TRANSFER_DAILY_CAP is set to \"" + env.BFC_TRANSFER_DAILY_CAP + "\", which is not a whole number of at least 1"
    : holdDays === null ? "BFC_TRANSFER_HOLD_DAYS is set to \"" + env.BFC_TRANSFER_HOLD_DAYS + "\", which is not a whole number of at least 0"
    : null;
  return { max: max, dailyCap: dailyCap, holdDays: holdDays, error: error };
}

module.exports = {
  bfcTransferLimits,
  bfcTransferSetting,
  BFC_TRANSFER_MAX_DEFAULT,
  BFC_TRANSFER_DAILY_CAP_DEFAULT,
  BFC_TRANSFER_HOLD_DAYS_DEFAULT,
  BFC_TRANSFER_DESCRIPTION,
  BFC_DONATION_DESCRIPTION_PREFIX,
  bfcCountsTowardDailyCap
};
