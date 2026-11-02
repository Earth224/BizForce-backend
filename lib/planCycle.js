/* lib/planCycle.js — learning cycles: what a finished Executive plan measured,
   and what a review of it may say (intelligence layer B8 and B9).

   THE MODEL DOES NOT LEARN. A cycle is a plan, the results its assignments
   recorded, a review of those results, and the next plan the member approved.
   Each cycle builds on recorded results. The AI model itself does not change.

   PURE: no database, no model, no clock but the one passed in. server.js reads
   the rows (planCycleMeasure) and hands them here; it makes the one model call
   of a review and passes the reply through verifyNumbers before anything is
   stored. scripts/checkPlanCycles.js proves every rule below.

   A NUMBER THAT CANNOT BE READ IS NULL AND NAMED. Every read the server makes
   arrives here as rows or as null (the read failed). A null source makes every
   number built from it null, and `unreadable` names it with the reason; it is
   never counted as 0, because 0 is a fact about the plan and null is a fact
   about this request. */

var LEARNING = require("./learningLoop");

var CYCLE_COPY = "Each cycle builds on recorded results. The AI model itself does not change.";
var STATUSES = ["open", "review_drafted", "approved", "superseded"];
var REVIEW_MODEL = "claude-haiku-4-5-20251001";
var REVIEW_MAX_TOKENS = 900;
var REVIEW_GAP_MS = 24 * 60 * 60 * 1000;   // at most one review per cycle in any 24 hours
var REVIEW_TEXT_MAX = 4000;
var NEXT_PLAN_MAX = 2000;
var ROUTE = "POST /api/executive/cycles/:id/review";

/* The totals a cycle reports, in the order the history shows them. */
var TOTAL_KEYS = [
  "dispatches_ran", "dispatches_refused", "dispatches_failed",
  "tool_tasks_completed", "tool_tasks_failed",
  "proposals_approved", "proposals_rejected", "published",
  "arrivals"
];
var TOTAL_WORDS = {
  dispatches_ran: "Assignments run",
  dispatches_refused: "Assignments refused",
  dispatches_failed: "Assignments failed",
  tool_tasks_completed: "Runs completed",
  tool_tasks_failed: "Runs failed",
  proposals_approved: "Proposals approved",
  proposals_rejected: "Proposals rejected",
  published: "Published",
  arrivals: "Arrivals on your tracked links"
};

function agentOf(row) {
  var a = row && typeof row.agent_type === "string" && row.agent_type ? row.agent_type : null;
  return a || "unnamed";
}

/* measuredFrom(input)
   input.plan        { id, created_at }
   input.dispatches  executive_dispatches rows of this plan, or null
   input.toolTasks   ai_tasks rows of the runs the dispatches produced, or null
   input.proposals   agent_proposals filed from those runs, or null
   input.ratings     agent_feedback rows on those runs, or null
   input.arrivals    engine_visits on the member's refs since the plan, a number or null
   input.nowMs       the clock */
function measuredFrom(input) {
  var i = input || {};
  var nowMs = typeof i.nowMs === "number" ? i.nowMs : 0;
  var unreadable = [];
  var name = function (field, reason) { unreadable.push({ field: field, reason: reason }); };

  var dispatches = Array.isArray(i.dispatches) ? i.dispatches : null;
  var toolTasks = dispatches && Array.isArray(i.toolTasks) ? i.toolTasks : null;
  var proposals = dispatches && Array.isArray(i.proposals) ? i.proposals : null;
  var ratings = dispatches && Array.isArray(i.ratings) ? i.ratings : null;
  if (!dispatches) {
    name("dispatches", "the plan's dispatch records could not be read");
    name("tool_tasks", "needs the dispatch records");
    name("proposals", "needs the dispatch records");
    name("helpful", "needs the dispatch records");
  } else {
    if (!toolTasks) name("tool_tasks", "the runs could not be read");
    if (!proposals) name("proposals", "the proposals could not be read");
    if (!ratings) name("helpful", "the ratings could not be read");
  }
  var arrivals = typeof i.arrivals === "number" && isFinite(i.arrivals) ? i.arrivals : null;
  if (arrivals === null) name("arrivals", "the arrivals on your tracked links could not be read");

  var totals = {};
  TOTAL_KEYS.forEach(function (k) { totals[k] = null; });
  totals.arrivals = arrivals;
  var byAgent = null;

  if (dispatches) {
    byAgent = {};
    var runAgent = {};
    var slot = function (agent) {
      if (!byAgent[agent]) {
        byAgent[agent] = {
          dispatches: { ran: 0, refused: 0, failed: 0 },
          tool_tasks: toolTasks ? { completed: 0, failed: 0, running: 0 } : null,
          proposals: proposals ? { approved: 0, rejected: 0, published: 0 } : null,
          helpful: ratings ? { rated: 0, percent: null } : null
        };
      }
      return byAgent[agent];
    };
    totals.dispatches_ran = 0; totals.dispatches_refused = 0; totals.dispatches_failed = 0;
    dispatches.forEach(function (d) {
      if (!d || ["ran", "refused", "failed"].indexOf(d.outcome) === -1) return;
      var agent = agentOf(d);
      slot(agent).dispatches[d.outcome] += 1;
      totals["dispatches_" + d.outcome] += 1;
      if (d.outcome === "ran" && d.tool_task_id) runAgent[d.tool_task_id] = agent;
    });

    if (toolTasks) {
      totals.tool_tasks_completed = 0; totals.tool_tasks_failed = 0;
      toolTasks.forEach(function (t) {
        if (!t || !runAgent[t.id]) return;
        var s = slot(runAgent[t.id]).tool_tasks;
        if (t.status === "completed") { s.completed += 1; totals.tool_tasks_completed += 1; }
        else if (t.status === "failed") { s.failed += 1; totals.tool_tasks_failed += 1; }
        else s.running += 1;
      });
    }

    if (proposals) {
      totals.proposals_approved = 0; totals.proposals_rejected = 0; totals.published = 0;
      var perAgent = {};
      proposals.forEach(function (p) {
        var src = p && p.payload && p.payload.source_task_id;
        if (!src || !runAgent[src]) return;
        (perAgent[runAgent[src]] = perAgent[runAgent[src]] || []).push(p);
      });
      Object.keys(perAgent).forEach(function (agent) {
        var o = LEARNING.outcomesFrom({ proposals: perAgent[agent] }, nowMs);
        var s = slot(agent).proposals;
        s.approved = o.proposals_approved; s.rejected = o.proposals_rejected; s.published = o.published;
        totals.proposals_approved += o.proposals_approved;
        totals.proposals_rejected += o.proposals_rejected;
        totals.published += o.published;
      });
    }

    if (ratings) {
      var counts = {};
      ratings.forEach(function (r) {
        if (!r || !runAgent[r.task_id] || (r.rating !== "up" && r.rating !== "down")) return;
        var c = counts[runAgent[r.task_id]] = counts[runAgent[r.task_id]] || { rated: 0, up: 0 };
        c.rated += 1;
        if (r.rating === "up") c.up += 1;
      });
      Object.keys(byAgent).forEach(function (agent) {
        var c = counts[agent] || { rated: 0, up: 0 };
        byAgent[agent].helpful = {
          rated: c.rated,
          // The share only where enough data exists: the same minimum as an agent's score.
          percent: c.rated >= LEARNING.MIN_RATINGS ? Math.round((c.up / c.rated) * 100) : null
        };
      });
    }
  }

  return {
    plan_task_id: i.plan && i.plan.id ? i.plan.id : null,
    since: i.plan && i.plan.created_at ? i.plan.created_at : null,
    measured_at: new Date(nowMs).toISOString(),
    totals: totals,
    by_agent: byAgent,
    unreadable: unreadable
  };
}

/* ── THE VERIFIER ────────────────────────────────────────────────────────────
   The verifyGuideAnswer approach: the model proposes, the server keeps only
   what it can check. A review sentence is kept only when EVERY number in it
   appears in `measured`; a sentence with any other number is dropped whole.
   Digits are numbers ("3", "1,203", "40%", "2.5"), and so are the number
   words zero to twenty and the tens; "hundred", "thousand" and "million"
   can never be checked, so a sentence holding one is dropped. A sentence with
   no number at all is kept. */
var NUMBER_WORDS = {
  zero: 0, one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7, eight: 8, nine: 9, ten: 10,
  eleven: 11, twelve: 12, thirteen: 13, fourteen: 14, fifteen: 15, sixteen: 16, seventeen: 17,
  eighteen: 18, nineteen: 19, twenty: 20, thirty: 30, forty: 40, fifty: 50, sixty: 60, seventy: 70,
  eighty: 80, ninety: 90, hundred: NaN, thousand: NaN, million: NaN
};
var NUMBER_RE = /\d+(?:[.,]\d+)*|\b(?:zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|hundred|thousand|million)\b/gi;

function numbersOf(measured) {
  var seen = {};
  (function walk(v) {
    if (typeof v === "number" && isFinite(v)) { seen[String(v)] = true; return; }
    if (Array.isArray(v)) { v.forEach(walk); return; }
    if (v && typeof v === "object") Object.keys(v).forEach(function (k) { walk(v[k]); });
  })(measured);
  return seen;
}

function tokenValue(token) {
  var low = token.toLowerCase();
  if (Object.prototype.hasOwnProperty.call(NUMBER_WORDS, low)) return NUMBER_WORDS[low];
  // "1,203" is one thousand two hundred and three; "2.5" is two and a half.
  var plain = /^\d{1,3}(?:,\d{3})+$/.test(token) ? token.replace(/,/g, "") : token.replace(/,/g, ".");
  return Number(plain);
}

function sentencesOf(text) {
  var out = [];
  String(text == null ? "" : text).split(/\n+/).forEach(function (line) {
    line.split(/(?<=[.!?])\s+/).forEach(function (s) {
      var t = s.trim();
      if (t) out.push(t);
    });
  });
  return out;
}

function sentenceChecks(sentence, allowed) {
  var tokens = String(sentence).match(NUMBER_RE) || [];
  return tokens.every(function (tok) {
    var v = tokenValue(tok);
    return isFinite(v) && allowed[String(v)] === true;
  });
}

function verifyNumbers(text, measured) {
  var allowed = numbersOf(measured);
  var kept = [], dropped = [];
  sentencesOf(text).forEach(function (s) { (sentenceChecks(s, allowed) ? kept : dropped).push(s); });
  return { text: kept.join(" "), kept: kept.length, dropped: dropped };
}

/* ── THE ONE MODEL CALL: its prompt, and reading its reply ──────────────── */
function measuredLines(measured) {
  var m = measured || {};
  var lines = [];
  var t = m.totals || {};
  TOTAL_KEYS.forEach(function (k) {
    lines.push("- " + TOTAL_WORDS[k] + ": " + (t[k] === null || t[k] === undefined ? "COULD NOT BE READ (unknown, not zero)" : t[k]));
  });
  if (m.by_agent) {
    Object.keys(m.by_agent).sort().forEach(function (agent) {
      var a = m.by_agent[agent];
      var bits = ["dispatches ran " + a.dispatches.ran + ", refused " + a.dispatches.refused + ", failed " + a.dispatches.failed];
      if (a.tool_tasks) bits.push("runs completed " + a.tool_tasks.completed + ", failed " + a.tool_tasks.failed);
      if (a.proposals) bits.push("proposals approved " + a.proposals.approved + ", rejected " + a.proposals.rejected + ", published " + a.proposals.published);
      if (a.helpful) bits.push(a.helpful.percent === null ? "ratings " + a.helpful.rated + " (too few for a Helpful share)" : "Helpful " + a.helpful.percent + "% of " + a.helpful.rated + " ratings");
      lines.push("- " + agent + ": " + bits.join("; "));
    });
  }
  (m.unreadable || []).forEach(function (u) { lines.push("- " + u.field + ": COULD NOT BE READ (" + u.reason + ")"); });
  return lines.join("\n");
}

function buildReviewPrompt(plan, measured) {
  var p = plan || {};
  var assignments = Array.isArray(p.assignments) ? p.assignments : [];
  return "" +
    "You are the BizForce Executive Agent reviewing one finished plan for the member who ran it.\n\n" +
    "THE PLAN'S GOAL:\n" + String(p.goal || "(no goal recorded)").slice(0, 2000) + "\n\n" +
    "ITS ASSIGNMENTS:\n" + (assignments.length ? assignments.slice(0, 20).map(function (a) {
      return "- " + (a.agent || "unnamed") + (a.tool ? " / " + a.tool : "") + ": " + String(a.task || "").replace(/\s+/g, " ").slice(0, 200);
    }).join("\n") : "(none recorded)") + "\n\n" +
    "WHAT WAS RECORDED (these are the only numbers that exist):\n" + measuredLines(measured) + "\n\n" +
    "RULES\n" +
    "1. Use ONLY the numbers listed above. Every sentence that contains any other number, written in digits or in words, " +
    "is removed before the member sees it, so do not estimate, total, average or round.\n" +
    "2. A figure marked COULD NOT BE READ is unknown. It is not zero. Say it was unavailable, or leave it out.\n" +
    "3. Plain language. No headings, bullets or markdown inside the two parts.\n\n" +
    "REPLY IN EXACTLY THIS SHAPE:\n" +
    "REVIEW:\n<three to six sentences on what worked, what was refused or failed, and why that matters>\n" +
    "NEXT PLAN:\n<one goal for the next plan, at most 600 characters, building on what the results show>\n";
}

function parseReview(raw) {
  var text = String(raw == null ? "" : raw);
  var r = text.search(/REVIEW:\s*/i);
  var n = text.search(/NEXT PLAN:\s*/i);
  var review = "", next = "";
  if (r !== -1 && n !== -1 && n > r) {
    review = text.slice(r, n).replace(/^REVIEW:\s*/i, "");
    next = text.slice(n).replace(/^NEXT PLAN:\s*/i, "");
  } else if (n !== -1) {
    next = text.slice(n).replace(/^NEXT PLAN:\s*/i, "");
    review = text.slice(0, n);
  } else {
    review = text.replace(/^REVIEW:\s*/i, "");
  }
  return { review: review.trim(), next: next.trim() };
}

/* The review and the next plan, each through the verifier. */
function draftFrom(raw, measured) {
  var parts = parseReview(raw);
  var review = verifyNumbers(parts.review, measured);
  var next = verifyNumbers(parts.next, measured);
  return {
    review_text: review.text.slice(0, REVIEW_TEXT_MAX),
    next_plan_draft: next.text.slice(0, NEXT_PLAN_MAX),
    kept: review.kept + next.kept,
    dropped: review.dropped.concat(next.dropped)
  };
}

/* ── THE HISTORY: each cycle against the one before ─────────────────────────
   The arrows as an agent's score shows them: up, down or level, and none when
   either side is unknown. */
function arrowsAgainst(current, previous) {
  var now = current && current.totals ? current.totals : null;
  var before = previous && previous.totals ? previous.totals : null;
  return TOTAL_KEYS.map(function (k) {
    var a = now && typeof now[k] === "number" ? now[k] : null;
    var b = before && typeof before[k] === "number" ? before[k] : null;
    var change = a !== null && b !== null ? a - b : null;
    return {
      key: k,
      label: TOTAL_WORDS[k],
      now: a,
      before: b,
      change: change,
      arrow: change === null ? null : (change > 0 ? "↑" : (change < 0 ? "↓" : "→"))
    };
  });
}

/* What a route answers for one cycle. previous: the cycle it builds on, or null. */
function cycleOut(row, previous) {
  if (!row) return null;
  return {
    id: row.id,
    plan_task_id: row.plan_task_id,
    previous_cycle_id: row.previous_cycle_id || null,
    status: row.status,
    measured: row.measured || null,
    review_text: row.review_text || null,
    next_plan_draft: row.next_plan_draft || null,
    next_plan_task_id: row.next_plan_task_id || null,
    model: row.model || null,
    reviewed_at: row.reviewed_at || null,
    approved_at: row.approved_at || null,
    created_at: row.created_at,
    against_previous: previous && previous.measured && row.measured ? arrowsAgainst(row.measured, previous.measured) : null,
    copy: CYCLE_COPY
  };
}

/* The member's own edits: one bounded text each, control characters out. */
function cleanEdit(value, max) {
  if (value === undefined) return undefined;
  if (value === null) return null;
  if (typeof value !== "string") return { error: true };
  var t = value.replace(/[\u0000-\u0008\u000b-\u001f\u007f]+/g, " ").trim();
  if (t.length > max) return { error: true };
  return t;
}

/* May this cycle be reviewed now? null when it may; otherwise why not. */
function reviewRefusal(row, nowMs) {
  if (!row) return { status: 404, code: "cycle_not_found", error: "Cycle not found" };
  if (row.status !== "open" && row.status !== "review_drafted") {
    return { status: 409, code: "cycle_closed", error: "This cycle is " + row.status.replace("_", " ") + ", so it is not reviewed again." };
  }
  var last = Date.parse(row.reviewed_at);
  if (isFinite(last) && nowMs - last < REVIEW_GAP_MS && last <= nowMs) {
    return { status: 429, code: "review_once_a_day", error: "This plan was reviewed in the last 24 hours. One review per cycle per day.",
      next_at: new Date(last + REVIEW_GAP_MS).toISOString() };
  }
  return null;
}

module.exports = {
  CYCLE_COPY: CYCLE_COPY,
  STATUSES: STATUSES,
  REVIEW_MODEL: REVIEW_MODEL,
  REVIEW_MAX_TOKENS: REVIEW_MAX_TOKENS,
  REVIEW_GAP_MS: REVIEW_GAP_MS,
  REVIEW_TEXT_MAX: REVIEW_TEXT_MAX,
  NEXT_PLAN_MAX: NEXT_PLAN_MAX,
  ROUTE: ROUTE,
  TOTAL_KEYS: TOTAL_KEYS,
  TOTAL_WORDS: TOTAL_WORDS,
  measuredFrom: measuredFrom,
  numbersOf: numbersOf,
  sentencesOf: sentencesOf,
  verifyNumbers: verifyNumbers,
  buildReviewPrompt: buildReviewPrompt,
  parseReview: parseReview,
  draftFrom: draftFrom,
  arrowsAgainst: arrowsAgainst,
  cycleOut: cycleOut,
  cleanEdit: cleanEdit,
  reviewRefusal: reviewRefusal
};
