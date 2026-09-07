// ── Self-review period boundaries and metric gathering ───────────────────────
//
// UNWIRED ON PURPOSE. Nothing imports this yet: no route, no timer, no line in
// server.js. It computes what a weekly or monthly self-review would be built
// from, and stops there. Wiring it is a separate decision from being able to
// compute it, and this file makes no assumption about which caller eventually
// arrives.
//
// It takes the Supabase client by injection and never builds its own, for the
// same two reasons lib/backup.js does: there is one service-key client in the
// process, and requiring server.js from here would be a cycle, since server.js
// is what would require this.
//
// WHAT THIS FILE REFUSES TO DO. Every number it returns is either measured or
// null. A read that fails reports null and names itself in `unreadable`; it
// never reports 0. The distinction is the whole point of the module: 0 is a
// fact about the business and null is a fact about this request, and a review
// that cannot tell them apart is a review that invents a quiet week out of a
// database timeout. The revenue total is the sharpest version of that — a
// fabricated revenue figure is the worst number this system could produce — so
// it is held to the same rule as the counts and not a softer one.

// The tables a review counts, with the column that identifies the owning user
// and the column that places a row in time. Both were read out of the
// migrations rather than assumed, because three of the eight do not follow the
// house pattern:
//
//   outreach_sends dates rows by sent_at, not created_at (074).
//   marketplace_orders has no user_id at all — it has buyer_id and seller_id.
//   bsky_leads has no owner column of any kind.
//
// agent_memory is deliberately NOT in this list. It tracks ai_tasks almost row
// for row — a task runs, a memory is written — so counting both would inflate
// the review's own numbers by recording one activity twice under two names. A
// review that overstates the week it is reviewing is worse than one that omits
// a table, and the ai_tasks count already carries this signal.
const COUNT_SOURCES = [
  { key: "aiTasks",            table: "ai_tasks",             ownerColumn: "user_id", timeColumn: "created_at" },
  { key: "agentProposals",     table: "agent_proposals",      ownerColumn: "user_id", timeColumn: "created_at" },
  { key: "outreachSends",      table: "outreach_sends",       ownerColumn: "user_id", timeColumn: "sent_at"    },
  { key: "contentLibrary",     table: "content_library",      ownerColumn: "user_id", timeColumn: "created_at" },
  { key: "walletTransactions", table: "wallet_transactions",  ownerColumn: "user_id", timeColumn: "created_at" },
  { key: "revenueEvents",      table: "revenue_events",       ownerColumn: "user_id", timeColumn: "created_at" },

  // marketplace_orders is scoped by seller_id, not buyer_id and not both. A
  // self-review asks what this business produced, and a purchase the user made
  // is not that. The key says "AsSeller" so the number cannot later be read as
  // every order the user touched — server.js:17320 scopes some views with
  // `buyer_id.eq.X,seller_id.eq.X`, and that is a different figure.
  { key: "marketplaceOrdersAsSeller", table: "marketplace_orders", ownerColumn: "seller_id", timeColumn: "created_at" },

  // NOT USER-SCOPED, AND THE KEY SAYS SO. bsky_leads has no owner column —
  // migration 068's own table comment records that every row is visible to
  // every operator and that partitioning the table by tenant is a prerequisite
  // for selling Lead Radar to a second customer. So this is a platform-wide
  // count filtered only by date. It is included because the period figure is
  // still real and still useful; it is named for what it is because presenting
  // a platform total as this user's total would be the same fabrication this
  // module exists to prevent. When bsky_leads gains an owner column, give this
  // entry an ownerColumn and rename the key.
  { key: "bskyLeadsPlatformWide", table: "bsky_leads", ownerColumn: null, timeColumn: "created_at" }
];

// revenue_events.amount IS ALREADY IN DOLLARS and is not divided by anything
// here. Migration 080 puts the column comment 'Amount in major units
// (dollars), never cents.' on it, and server.js:2838 does the /100 on the way
// in from Stripe. Dividing again here would silently report a hundredth of the
// real revenue.
//
// The owner column is user_id, added by migration 080. It is NOT business_id:
// that column exists on the table but server.js:2839 writes null to it on
// every insert, because it describes staff-entered revenue, which is a
// different fact. Scoping by business_id would match nothing.
const REVENUE_TABLE         = "revenue_events";
const REVENUE_OWNER_COLUMN  = "user_id";
const REVENUE_TIME_COLUMN   = "created_at";
const REVENUE_AMOUNT_COLUMN = "amount";

// ── Period boundaries ────────────────────────────────────────────────────────
//
// ALL BOUNDARIES ARE UTC, NOT USER-LOCAL. The platform stores no verified user
// timezone anywhere, so a "local" week would be a guess dressed as a fact — and
// a guess that silently shifts which rows land in which review. UTC is not the
// friendliest boundary for any particular user; it is the only one this system
// can currently state truthfully. If a verified timezone is ever captured per
// user, this is the function that changes, and it is deliberately the only
// place that would need to.
//
// EVERY PERIOD IS CLOSED. The end is always a boundary that has already passed,
// never "now", so a review always covers a whole week or a whole month and
// never a partial one. A partial period summarised as if it were whole is a
// number that looks comparable to last week's and is not — three days of
// activity reported beside seven, with nothing in the figure to say so.
//
// Milliseconds are zeroed by construction: every boundary is built from
// Date.UTC with no time component at all, so the range is exactly midnight
// rather than approximately it.
//
// The range the reads apply is half-open, [start, end): a row written at
// exactly the end boundary belongs to the next period, not this one, so
// consecutive periods tile without counting a row twice.
function computePeriodBounds(periodType, now) {
  var reference = now instanceof Date ? now : new Date(now);
  if (isNaN(reference.getTime())) {
    throw new Error("computePeriodBounds: `now` is not a valid date.");
  }

  if (periodType === "weekly") {
    // Midnight UTC on the reference day, then walk back to Monday. getUTCDay
    // numbers Sunday 0 through Saturday 6, so (day + 6) % 7 is the number of
    // days since Monday: Monday 0, Tuesday 1, ... Sunday 6. On a Monday the
    // shift is 0, which is what makes the boundary "at or before now" rather
    // than strictly before it.
    var weekEnd = new Date(Date.UTC(
      reference.getUTCFullYear(),
      reference.getUTCMonth(),
      reference.getUTCDate()
    ));
    weekEnd.setUTCDate(weekEnd.getUTCDate() - ((weekEnd.getUTCDay() + 6) % 7));

    var weekStart = new Date(weekEnd.getTime());
    weekStart.setUTCDate(weekStart.getUTCDate() - 7);

    return { start: weekStart, end: weekEnd };
  }

  if (periodType === "monthly") {
    // Date.UTC normalises a month of -1 into December of the previous year, so
    // a January reference needs no special case.
    var monthEnd = new Date(Date.UTC(
      reference.getUTCFullYear(),
      reference.getUTCMonth(),
      1
    ));
    var monthStart = new Date(Date.UTC(
      reference.getUTCFullYear(),
      reference.getUTCMonth() - 1,
      1
    ));

    return { start: monthStart, end: monthEnd };
  }

  throw new Error("computePeriodBounds: unknown period type " + JSON.stringify(periodType) +
    '. Expected "weekly" or "monthly".');
}

// ── Metric gathering ─────────────────────────────────────────────────────────

// The failure shape, matching softCountNullable in server.js: null as the
// value, the key pushed onto `unreadable`, and one console.error saying which
// read failed for which user and why. Kept deliberately identical — a reader
// who has learned what one of these log lines means should not have to learn a
// second dialect to read the other file.
function recordUnreadable(unreadable, key, userId, error, what) {
  console.error("[selfReview] " + key + " " + what + " failed for user " + userId + ": " +
    (error && error.message ? error.message : error) +
    (error && error.code ? " (" + error.code + ")" : "") +
    ". Reporting null and marking it unreadable.");
  unreadable.push(key);
}

// ONE FAILING READ MUST NOT STOP THE OTHERS. Every read is wrapped so it
// settles rather than throws, and all of them are issued together; whatever
// succeeded comes back, with the failures named. A review built from six
// readable metrics and three named gaps is useful. A review that returned
// nothing because one table was briefly unreachable is not.
//
// `start` and `end` come from computePeriodBounds. They are sent as ISO
// strings, which is what PostgREST wants for a timestamptz comparison.
async function gatherReviewMetrics({ supabase, userId, start, end }) {
  if (!supabase) {
    throw new Error("gatherReviewMetrics: no supabase client was injected.");
  }
  if (!userId) {
    throw new Error("gatherReviewMetrics: userId is required.");
  }

  var metrics    = {};
  var unreadable = [];

  var startIso = (start instanceof Date ? start : new Date(start)).toISOString();
  var endIso   = (end   instanceof Date ? end   : new Date(end)).toISOString();

  var countReads = COUNT_SOURCES.map(function (source) {
    // head: true asks PostgREST for the count and no rows at all, so a period
    // holding thousands of rows costs the same as one holding none.
    var query = supabase
      .from(source.table)
      .select("*", { count: "exact", head: true })
      .gte(source.timeColumn, startIso)
      .lt(source.timeColumn, endIso);

    if (source.ownerColumn) {
      query = query.eq(source.ownerColumn, userId);
    }

    return Promise.resolve(query)
      .then(function (result) { return { source: source, result: result }; })
      .catch(function (thrown) { return { source: source, result: { error: thrown } }; });
  });

  // The revenue total is summed in JavaScript because PostgREST cannot sum.
  // That is the only reason this one selects rows rather than a count.
  //
  // It is not paginated. If a period ever holds more revenue_events rows than
  // PostgREST's max-rows, this figure would silently become a partial sum —
  // which is exactly the class of quiet wrong number the rest of this file
  // exists to prevent. It is left as one honest read rather than a half-measure
  // that looks complete, and it is the thing to fix before this is wired to
  // anything carrying volume.
  var revenueRead = Promise.resolve(
    supabase
      .from(REVENUE_TABLE)
      .select(REVENUE_AMOUNT_COLUMN)
      .eq(REVENUE_OWNER_COLUMN, userId)
      .gte(REVENUE_TIME_COLUMN, startIso)
      .lt(REVENUE_TIME_COLUMN, endIso)
  ).catch(function (thrown) { return { error: thrown }; });

  var settled = await Promise.all(countReads.concat([revenueRead]));

  var countResults  = settled.slice(0, settled.length - 1);
  var revenueResult = settled[settled.length - 1];

  countResults.forEach(function (entry) {
    if (entry.result && entry.result.error) {
      recordUnreadable(unreadable, entry.source.key, userId, entry.result.error, "count");
      metrics[entry.source.key] = null;
      return;
    }
    metrics[entry.source.key] = entry.result.count || 0;
  });

  if (revenueResult && revenueResult.error) {
    recordUnreadable(unreadable, "revenueTotal", userId, revenueResult.error, "revenue read");
    metrics.revenueTotal = null;
  } else {
    // Rows with a null amount are skipped rather than counted as zero. The
    // total is a raw number: not rounded, not formatted, not given a currency
    // symbol. Anything done to it here would have to be undone before it could
    // be compared or added to anything.
    var rows  = (revenueResult && revenueResult.data) || [];
    var total = 0;
    for (var i = 0; i < rows.length; i++) {
      var amount = rows[i] ? rows[i][REVENUE_AMOUNT_COLUMN] : null;
      if (amount === null || amount === undefined) continue;
      // numeric columns arrive from PostgREST as strings often enough that this
      // is not defensive padding: `+=` on a string would concatenate.
      var numeric = Number(amount);
      if (isNaN(numeric)) continue;
      total += numeric;
    }
    metrics.revenueTotal = total;
  }

  return { metrics: metrics, unreadable: unreadable };
}

module.exports = { computePeriodBounds, gatherReviewMetrics };
