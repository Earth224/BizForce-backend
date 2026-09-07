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
// migrations rather than assumed, because several of the candidate tables do
// not follow the house pattern:
//
//   outreach_sends dates rows by sent_at, not created_at (074).
//   marketplace_orders has no user_id at all — it has buyer_id and seller_id.
//   bsky_leads has no owner column of any kind, and is excluded for it (below).
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

  // bsky_leads IS DELIBERATELY ABSENT, and naming it clearly was not enough.
  //
  // The table has no owner column, so the only number available is
  // platform-wide. Storing a platform-wide figure inside a per-user review row
  // is correct only while there is exactly one account on the platform, and
  // silently wrong the moment there are two — at which point every review row
  // written before then is also wrong, retroactively, with nothing in the row
  // to say so.
  //
  // The decisive part is who reads it. A review row is durable and is read
  // later, by someone who was not present for this decision and has no reason
  // to suspect that one number in a per-user row means something different from
  // the rest. A carefully named key does not survive that: it is read as a
  // lead count in a user's review, because that is where it is stored.
  //
  // Migration 068 calls partitioning this table by tenant a prerequisite for
  // selling Lead Radar to anyone else, not a later refinement. The metric can
  // come back when the owner column does — add an entry above with that column
  // and the plain key `bskyLeads`.
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

// Paging for the revenue read, mirroring GET /api/activity/overview
// (server.js:15872-15879). PostgREST caps a response at its own max-rows
// regardless of what the range asks for, so the page size is checked against
// what actually arrived rather than assumed, and the ceiling exists to fail
// loudly rather than to be reached.
const REVENUE_PAGE_SIZE = 1000;
const REVENUE_MAX_PAGES = 50;

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

// The revenue rows for one period, walked to exhaustion.
//
// Summed in JavaScript because PostgREST cannot sum, which is the only reason
// this selects rows rather than a count. Ordered by created_at because an
// unordered range walk can repeat and drop rows between pages.
//
// Three outcomes, and the caller must distinguish all three: { rows } read to
// the end, { error } for a failed read, and { capped } for the ceiling being
// reached with rows possibly remaining. The last is NOT a success with a
// slightly small number — it is a partial sum shaped exactly like a whole one,
// which is the single failure a revenue figure has no way to reveal to whoever
// reads it. It is reported as unreadable, not returned.
async function readRevenueRows(supabase, userId, startIso, endIso) {
  var rows = [];

  for (var page = 0; page < REVENUE_MAX_PAGES; page++) {
    var offset = page * REVENUE_PAGE_SIZE;
    var result;

    try {
      result = await supabase
        .from(REVENUE_TABLE)
        .select(REVENUE_AMOUNT_COLUMN)
        .eq(REVENUE_OWNER_COLUMN, userId)
        .gte(REVENUE_TIME_COLUMN, startIso)
        .lt(REVENUE_TIME_COLUMN, endIso)
        .order(REVENUE_TIME_COLUMN, { ascending: true })
        .range(offset, offset + REVENUE_PAGE_SIZE - 1);
    } catch (thrown) {
      return { error: thrown };
    }

    if (result && result.error) {
      return { error: result.error };
    }

    var batch = (result && result.data) || [];
    for (var i = 0; i < batch.length; i++) {
      rows.push(batch[i]);
    }

    // A short page is the end of the data. Checked against what arrived rather
    // than against what was asked for, since PostgREST may return fewer rows
    // than the range requested.
    if (batch.length < REVENUE_PAGE_SIZE) {
      return { rows: rows };
    }
  }

  return { capped: true };
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

  // A BLIND SPOT THIS TOTAL CANNOT SEE, recorded here because the number looks
  // complete and is not.
  //
  // revenue_events.user_id is nullable and was only added by migration 080; the
  // table predates it. The Stripe path writes `fields.userId || null`
  // (server.js:2835), so any payment that could not be attributed to an account
  // is stored with a null user_id. Those rows match no user's review — not this
  // one, not anyone's — so unattributed revenue is invisible to every per-user
  // total this function can produce.
  //
  // Stated plainly: a per-user revenue total is a LOWER BOUND on that user's
  // revenue, and the sum of every user's total is a lower bound on the
  // platform's. Neither is the platform's revenue.
  //
  // This cannot be fixed by widening the query here. Including unattributed
  // rows in one user's review would show them revenue that is not theirs and
  // may be another tenant's, which is worse than the gap. The missing piece is
  // an operator-level view that reads revenue_events without a user filter, and
  // no such view exists yet.
  var revenueRead = readRevenueRows(supabase, userId, startIso, endIso)
    .catch(function (thrown) { return { error: thrown }; });

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
  } else if (revenueResult && revenueResult.capped) {
    // The ceiling was reached with rows possibly still unread. Everything
    // summed so far is a partial total shaped exactly like a whole one, so none
    // of it is returned — the same refusal GET /api/activity/overview makes at
    // server.js:16032-16039, which drops a fully tallied window rather than
    // answer with a partial aggregate that looks complete.
    //
    // Treated as unreadable rather than as an error because that is what it is
    // to the reader: the figure is unknown for this period, NOT zero and NOT
    // the smaller number we happened to reach.
    console.error("[selfReview] revenueTotal revenue read for user " + userId +
      " exceeded " + (REVENUE_MAX_PAGES * REVENUE_PAGE_SIZE) + " rows for the period " +
      startIso + " to " + endIso +
      ". Refusing to return a partial sum. Reporting null and marking it unreadable.");
    unreadable.push("revenueTotal");
    metrics.revenueTotal = null;
  } else {
    // Rows with a null amount are skipped rather than counted as zero. The
    // total is a raw number: not rounded, not formatted, not given a currency
    // symbol. Anything done to it here would have to be undone before it could
    // be compared or added to anything.
    var rows  = (revenueResult && revenueResult.rows) || [];
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
