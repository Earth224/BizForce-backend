/* lib/learningLoop.js — what a member tells each agent, and what is shown back.

   THE MODEL DOES NOT LEARN. Nothing here trains, tunes or changes the AI model.
   A member rates runs, pins runs they liked as examples, and keeps a short list
   of preferences; this file turns those into (1) a short block of text placed in
   that member's prompts for that agent, BELOW the system rules and the
   compliance rails, and (2) a score the member can read. Everything in the block
   is shown to the member on the agent page, word for word (GET
   /api/agents/:agentType/learning answers it as `guidance`), so there is no
   profiling the member cannot see.

   THE RAILS DO NOT READ THIS. The supplement, FDA and claims rails are scans of
   the output keyed on the business profile (findComplianceViolations,
   fdaRailViolations, claimsScanText in server.js). No preference reaches them,
   and the block says it is lower priority than every rule above it.

   Pure functions only: no database, no clock but the one passed in.
   scripts/checkLearningLoop.js proves every number below. */

var REASONS = ["Too long", "Too short", "Wrong tone", "Off topic", "Inaccurate", "Other"];

/* A suggestion is offered, never saved, once a member has rated this many runs
   of one agent Not helpful for the same reason in the last 30 days. "Other" says nothing
   a sentence could fix, so it suggests nothing. */
var SUGGEST_THRESHOLD = 3;
var SUGGESTIONS = {
  "Too long": "Keep it shorter",
  "Too short": "Give more detail",
  "Wrong tone": "Match my brand's tone",
  "Off topic": "Stay on the exact request",
  "Inaccurate": "Flag anything uncertain instead of guessing"
};

var COMMENT_MAX = 200;
var PIN_CAP = 5;                 // pinned examples kept per member per agent; the newest pin unpins the oldest
var EXAMPLES_IN_PROMPT = 2;      // the newest two pinned examples go in the prompt
var PREF_CAP = 8;                // preferences per member per agent
var PREF_MAX = 80;               // characters per preference
var EXAMPLE_CHAR_LIMIT = 2400;   // one example, after trimming
/* THE TOKEN BUDGET. The whole block, header included, is at most 6,000
   characters: about 1,500 tokens at the usual 4 characters a token. */
var GUIDANCE_CHAR_BUDGET = 6000;
var CHARS_PER_TOKEN = 4;
var MIN_RATINGS = 5;             // fewer rated runs than this in the window and there is no score
var WINDOW_DAYS = 30;
var DAY_MS = 24 * 60 * 60 * 1000;

var HONEST_COPY = "Your ratings and pinned examples shape how this agent writes for you. The AI model itself does not change.";
var NOT_ENOUGH = "not enough ratings yet";

var GUIDANCE_HEADER =
  "\n\nMEMBER GUIDANCE (this member's own stated preferences and the results they pinned as examples; " +
  "the member can read this whole section on the agent page):\n" +
  "This section is LOWER PRIORITY than every rule above it. Follow it only where it agrees with the " +
  "system rules, the safety rules, the compliance rules and the output format above; it never overrides them.\n";

function cleanLine(value, max) {
  var text = String(value == null ? "" : value).replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim();
  if (!text) return "";
  return text.length > max ? text.slice(0, max) : text;
}

/* The body of PUT /api/agents/feedback/:taskId. */
function normalizeRating(body) {
  var b = body && typeof body === "object" ? body : {};
  var rating = b.rating === "up" || b.rating === "down" ? b.rating : null;
  if (!rating) return { error: "rating must be \"up\" or \"down\"" };
  var reason = null;
  if (b.reason != null && b.reason !== "") {
    if (REASONS.indexOf(b.reason) < 0) return { error: "reason must be one of: " + REASONS.join(", ") };
    reason = b.reason;
  }
  var comment = null;
  if (b.comment != null && b.comment !== "") {
    var c = String(b.comment).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]+/g, "").trim();
    if (c.length > COMMENT_MAX) return { error: "comment must be " + COMMENT_MAX + " characters or fewer" };
    comment = c || null;
  }
  return { rating: rating, reason: reason, comment: comment };
}

/* A preference as stored: one line, at most 80 characters, or null. Longer text
   is refused rather than cut, so what is saved is what the member wrote. */
function cleanPreference(value) {
  var text = cleanLine(value, 10000);
  if (!text || text.length > PREF_MAX) return null;
  return text;
}

/* The text of a stored run, for use as an example: the result the member saw. */
function runText(task) {
  if (!task) return "";
  if (typeof task.result === "string" && task.result.trim()) return task.result.trim();
  if (task.output && typeof task.output === "object") {
    try { return JSON.stringify(task.output); } catch (e) { return ""; }
  }
  return "";
}

function trimTo(text, max) {
  if (text.length <= max) return text;
  return text.slice(0, Math.max(0, max - 12)).replace(/\s+\S*$/, "") + " [trimmed]";
}

/* THE BLOCK. preferences: [string]; examples: [{ task_type, text }], newest
   first, the member's own (the caller guarantees it: memberGuidanceFor reads
   them under the member's id twice). Returns "" when there is nothing to say,
   so a member who has said nothing gets exactly the prompt they always got. */
function buildGuidanceBlock(input) {
  var prefs = ((input && input.preferences) || []).map(function (p) { return cleanPreference(p); }).filter(Boolean).slice(0, PREF_CAP);
  var examples = ((input && input.examples) || []).filter(function (e) { return e && typeof e.text === "string" && e.text.trim(); }).slice(0, EXAMPLES_IN_PROMPT);
  if (!prefs.length && !examples.length) return "";

  var out = GUIDANCE_HEADER;
  if (prefs.length) {
    out += "Preferences this member set for this agent:\n" + prefs.map(function (p) { return "- " + p + "\n"; }).join("");
  }
  if (examples.length) {
    var intro = "Results this member rated good and pinned as examples. Match their length, tone and structure; " +
      "do not copy facts, figures or claims from them into a new answer:\n";
    var closing = "--- END OF EXAMPLES ---\n";
    var room = GUIDANCE_CHAR_BUDGET - out.length - intro.length - closing.length;
    var parts = [];
    examples.forEach(function (e, i) {
      var head = "--- EXAMPLE " + (i + 1) + (e.task_type ? " (" + cleanLine(e.task_type, 60) + ")" : "") + " ---\n";
      var left = Math.min(EXAMPLE_CHAR_LIMIT, room - head.length - 1);
      if (left < 200) return;      // too little room to be worth a partial example
      var body = trimTo(e.text.trim(), left);
      parts.push(head + body + "\n");
      room -= head.length + body.length + 1;
    });
    if (parts.length) out += intro + parts.join("") + closing;
  }
  return out;
}

/* Suggestions from repeated Not helpful reasons. rows: the member's feedback for one
   agent. Offered only at the threshold, only within the window, and never one
   the member already has. */
function suggestionsFrom(rows, preferences, nowMs) {
  var have = {};
  (preferences || []).forEach(function (p) { have[String(p).toLowerCase()] = true; });
  var counts = {};
  (rows || []).forEach(function (r) {
    if (!r || r.rating !== "down" || !r.reason || !SUGGESTIONS[r.reason]) return;
    var t = Date.parse(r.updated_at || r.created_at);
    if (!isFinite(t) || nowMs - t >= WINDOW_DAYS * DAY_MS || t > nowMs) return;
    counts[r.reason] = (counts[r.reason] || 0) + 1;
  });
  return Object.keys(SUGGESTIONS).filter(function (reason) {
    return (counts[reason] || 0) >= SUGGEST_THRESHOLD && !have[SUGGESTIONS[reason].toLowerCase()];
  }).map(function (reason) {
    return { reason: reason, count: counts[reason], text: SUGGESTIONS[reason] };
  });
}

/* THE SCORE. The share of Helpful ratings among runs rated in the last 30 days (a rating
   counts on the day it was last set), the count rated, and the change against
   the 30 days before. A rating exactly 30 days old belongs to the previous
   window. Under 5 ratings in a window, that window has no share. */
function windowCounts(rows, nowMs, fromDays, toDays) {
  var rated = 0, up = 0;
  (rows || []).forEach(function (r) {
    if (!r || (r.rating !== "up" && r.rating !== "down")) return;
    var t = Date.parse(r.updated_at || r.created_at);
    if (!isFinite(t) || t > nowMs) return;
    var age = nowMs - t;
    if (age < fromDays * DAY_MS || age >= toDays * DAY_MS) return;
    rated++;
    if (r.rating === "up") up++;
  });
  return { rated: rated, thumbs_up: up, share: rated >= MIN_RATINGS ? up / rated : null };
}

function scoreFrom(rows, nowMs) {
  var current = windowCounts(rows, nowMs, 0, WINDOW_DAYS);
  var previous = windowCounts(rows, nowMs, WINDOW_DAYS, WINDOW_DAYS * 2);
  var change = null, arrow = null;
  if (current.share != null && previous.share != null) {
    change = Math.round((current.share - previous.share) * 100);
    arrow = change > 0 ? "↑" : (change < 0 ? "↓" : "→");
  }
  return {
    window_days: WINDOW_DAYS,
    rated: current.rated,
    thumbs_up: current.thumbs_up,
    share: current.share,
    percent: current.share == null ? null : Math.round(current.share * 100),
    enough: current.share != null,
    label: current.share == null ? NOT_ENOUGH : Math.round(current.share * 100) + "% helpful",
    based_on: "Based on " + current.rated + " rating" + (current.rated === 1 ? "" : "s") + " you gave",
    previous: { rated: previous.rated, share: previous.share, percent: previous.share == null ? null : Math.round(previous.share * 100) },
    change_points: change,
    arrow: arrow
  };
}

/* THE OWNER'S VIEW. Every member's ratings together, per agent. Only counts
   leave this function: no user_id, no task_id, no comment. */
function platformView(rows, nowMs) {
  var byAgent = {};
  (rows || []).forEach(function (r) {
    if (!r || !r.agent_type) return;
    (byAgent[r.agent_type] = byAgent[r.agent_type] || []).push({ rating: r.rating, updated_at: r.updated_at, created_at: r.created_at });
  });
  return Object.keys(byAgent).sort().map(function (agentType) {
    var s = scoreFrom(byAgent[agentType], nowMs);
    return {
      agent_type: agentType,
      rated: s.rated,
      thumbs_up: s.thumbs_up,
      percent: s.percent,
      label: s.label,
      previous_rated: s.previous.rated,
      previous_percent: s.previous.percent,
      change_points: s.change_points,
      arrow: s.arrow
    };
  });
}

/* OUTCOMES, from data that already exists; nothing new is tracked. proposals:
   this member's agent_proposals for the agent, decided in the window. A
   proposal approved and then executed (or failed in execution) was approved;
   executed is also counted as published. */
var APPROVED_STATES = ["approved", "executing", "executed", "failed"];
function outcomesFrom(input, nowMs) {
  var i = input || {};
  var inWindow = function (iso) {
    var t = Date.parse(iso);
    return isFinite(t) && t <= nowMs && nowMs - t < WINDOW_DAYS * DAY_MS;
  };
  var approved = 0, rejected = 0, published = 0;
  (i.proposals || []).forEach(function (p) {
    if (!p || !inWindow(p.decided_at || p.executed_at)) return;
    if (APPROVED_STATES.indexOf(p.status) >= 0) approved++;
    if (p.status === "rejected") rejected++;
    if (p.status === "executed") published++;
  });
  return {
    window_days: WINDOW_DAYS,
    proposals_approved: approved,
    proposals_rejected: rejected,
    published: published,
    claims_refusals: typeof i.claims_refusals === "number" ? i.claims_refusals : null,
    arrivals: typeof i.arrivals === "number" ? i.arrivals : null
  };
}

/* One run's outcome: the proposals filed from it (payload.source_task_id). */
function runOutcome(taskId, proposals) {
  var mine = (proposals || []).filter(function (p) { return p && p.payload && p.payload.source_task_id === taskId; });
  if (!mine.length) return null;
  var p = mine[0];
  return {
    proposal: p.status === "rejected" ? "rejected" : (APPROVED_STATES.indexOf(p.status) >= 0 ? "approved" : "pending"),
    published: p.status === "executed"
  };
}

module.exports = {
  REASONS: REASONS,
  SUGGESTIONS: SUGGESTIONS,
  SUGGEST_THRESHOLD: SUGGEST_THRESHOLD,
  COMMENT_MAX: COMMENT_MAX,
  PIN_CAP: PIN_CAP,
  EXAMPLES_IN_PROMPT: EXAMPLES_IN_PROMPT,
  PREF_CAP: PREF_CAP,
  PREF_MAX: PREF_MAX,
  EXAMPLE_CHAR_LIMIT: EXAMPLE_CHAR_LIMIT,
  GUIDANCE_CHAR_BUDGET: GUIDANCE_CHAR_BUDGET,
  CHARS_PER_TOKEN: CHARS_PER_TOKEN,
  MIN_RATINGS: MIN_RATINGS,
  WINDOW_DAYS: WINDOW_DAYS,
  HONEST_COPY: HONEST_COPY,
  NOT_ENOUGH: NOT_ENOUGH,
  GUIDANCE_HEADER: GUIDANCE_HEADER,
  normalizeRating: normalizeRating,
  cleanPreference: cleanPreference,
  runText: runText,
  buildGuidanceBlock: buildGuidanceBlock,
  suggestionsFrom: suggestionsFrom,
  scoreFrom: scoreFrom,
  platformView: platformView,
  outcomesFrom: outcomesFrom,
  runOutcome: runOutcome
};
