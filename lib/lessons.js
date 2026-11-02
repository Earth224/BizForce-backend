/* lib/lessons.js — candidate lessons, derived BY RULE from the weekly
   self-review's per-agent breakdown (intelligence layer B9).

   NO MODEL CALL. Every lesson is a fixed sentence with the review's own
   counts written into it; nothing here asks a model anything, and nothing is
   saved by being derived. A lesson is OFFERED on that agent's "How this agent
   learns" panel and becomes an agent_preferences row (source 'lesson') only
   when the member accepts it, within PREF_CAP, through POST
   /api/agents/:agentType/preferences, which re-derives the offer before it
   writes. From there it reaches the prompt through the existing guidance
   block, shown to the member word for word.

   THE RULES, per agent, over the review's period:
     reason    a Not helpful reason (not "Other") given 3 or more times:
               "Not helpful: Too long, 3 times. Keep it shorter."
     rejected  2 or more proposals decided and at least half rejected:
               "2 of 4 proposals rejected. Propose only what fits my brief."
     approved  3 or more proposals decided and none rejected:
               "3 of 3 proposals approved. Keep proposing the same way."
   A lesson longer than a preference may be (80 characters) is not offered.

   Pure: no database, no clock. scripts/checkPlanCycles.js proves each rule. */

var LEARNING = require("./learningLoop");

var LESSON_RULES = ["reason", "rejected", "approved"];

function lessonsForOne(entry) {
  var out = [];
  if (!entry || typeof entry !== "object") return out;
  var reasons = entry.not_helpful && typeof entry.not_helpful === "object" ? entry.not_helpful : null;
  if (reasons) {
    Object.keys(LEARNING.SUGGESTIONS).forEach(function (reason) {
      var n = reasons[reason];
      if (typeof n !== "number" || n < LEARNING.SUGGEST_THRESHOLD) return;
      out.push({ rule: "reason", evidence: "Not helpful: " + reason + ", " + n + " times",
        text: "Not helpful: " + reason + ", " + n + " times. " + LEARNING.SUGGESTIONS[reason] + "." });
    });
  }
  var p = entry.proposals && typeof entry.proposals === "object" ? entry.proposals : null;
  if (p && typeof p.approved === "number" && typeof p.rejected === "number") {
    var decided = p.approved + p.rejected;
    if (decided >= 2 && p.rejected * 2 >= decided) {
      out.push({ rule: "rejected", evidence: p.rejected + " of " + decided + " proposals rejected",
        text: p.rejected + " of " + decided + " proposals rejected. Propose only what fits my brief." });
    } else if (decided >= 3 && p.rejected === 0) {
      out.push({ rule: "approved", evidence: p.approved + " of " + decided + " proposals approved",
        text: p.approved + " of " + decided + " proposals approved. Keep proposing the same way." });
    }
  }
  return out.filter(function (l) { return LEARNING.cleanPreference(l.text) === l.text; });
}

/* byAgent: { agent_type: { tasks, proposals, not_helpful } } or null (unreadable).
   Returns { agent_type: [lesson] } with only the agents that have one, or null. */
function lessonsFrom(byAgent) {
  if (!byAgent || typeof byAgent !== "object") return null;
  var out = {};
  Object.keys(byAgent).sort().forEach(function (agent) {
    var list = lessonsForOne(byAgent[agent]);
    if (list.length) out[agent] = list;
  });
  return out;
}

/* What one agent's panel offers: the stored lessons for it, less any the
   member already has as a preference (in any words' case). */
function offeredFor(lessons, agentType, preferenceTexts) {
  if (!lessons || typeof lessons !== "object") return [];
  var have = {};
  (preferenceTexts || []).forEach(function (t) { have[String(t).toLowerCase()] = true; });
  var list = Array.isArray(lessons[agentType]) ? lessons[agentType] : [];
  return list.filter(function (l) {
    return l && typeof l.text === "string" && LESSON_RULES.indexOf(l.rule) !== -1 && !have[l.text.toLowerCase()];
  }).map(function (l) { return { rule: l.rule, evidence: String(l.evidence || ""), text: l.text }; });
}

module.exports = { LESSON_RULES: LESSON_RULES, lessonsFrom: lessonsFrom, offeredFor: offeredFor };
