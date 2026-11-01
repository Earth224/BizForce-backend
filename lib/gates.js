/* ═══════════════════════════════════════════════════════════════════════════
   lib/gates.js — one evaluator for every decision gate (intelligence layer B1)

   WHAT IT IS. The registry of every gate in the Oct 31 design report's §1.1
   inventory, by its stable id (G1 to G25), and one pure function that turns
   what the gates said into one decision:

     evaluate(action, context, gates) ->
       { action, outcome, results: [ { gate, result, code, reason } ] }

       result:  "pass" | "fail" | "bypass" | "not_reached"
       outcome: "ran" | "blocked" | "held_for_approval"

   PURE. No database, no clock, no network, no logging. The gates themselves
   still run where they always ran, in server.js, and still decide; this module
   is told what each one said (context.observed) and writes nothing. That is
   what keeps B1 from changing behaviour: the refusal a member sees is still the
   one the old code built, byte for byte, and the decision here is a record of
   it, never a second opinion on it.

   THE RULES.
     - Gates are walked in the order given (the order the code already runs
       them in; for a model call that is G9, then G11, then G10).
     - The first "fail" ends the walk. Every gate after it is "not_reached",
       whatever was observed for it.
     - A gate nothing was observed for is "not_reached": it did not run.
     - A bypass (the owner pass) is recorded as "bypass", never as "pass".
     - The outcome is "blocked" on a fail, "held_for_approval" when the gate that
       failed holds rather than refuses (G2), and "ran" otherwise.

   PRIVACY. A result carries a code and a fixed sentence for that code, never a
   prompt, an address, an amount or an id. Codes not in REASONS get the plain
   sentence for their result.

   RECORDS. toRecord(decision) is the compact form a gate_decisions row holds
   (migration 158): the results without the sentences, which REASONS gives back.
   Retention is 90 days (design §1.5); the daily sweep that enforces it comes in
   block B2.
   ═══════════════════════════════════════════════════════════════════════════ */
"use strict";

/* The §1.1 inventory. kind says where the gate stands: "platform" gates are the
   rules BizForce applies to everyone; "pass" is the owner pass, which never
   refuses and is what a bypass is recorded against. effect is what a fail does:
   "block" refuses, "require_approval" holds the action for a person. b1 marks
   the gates that have an adapter in this block. */
var GATES = Object.freeze([
  { id: "G1",  name: "Approval (proposals)",                 kind: "platform", effect: "block",            b1: true },
  { id: "G2",  name: "High-risk task approval",              kind: "platform", effect: "require_approval", b1: true },
  { id: "G3",  name: "Subscription-gated proposal actions",  kind: "platform", effect: "block",            b1: false },
  { id: "G4",  name: "Compliance profile rails",             kind: "platform", effect: "block",            b1: false },
  { id: "G5",  name: "FDA rail",                             kind: "platform", effect: "block",            b1: false },
  { id: "G6",  name: "Article claims",                       kind: "platform", effect: "block",            b1: false },
  { id: "G7",  name: "Bluesky claims",                       kind: "platform", effect: "block",            b1: false },
  { id: "G8",  name: "Grapheme limit",                       kind: "platform", effect: "block",            b1: false },
  { id: "G9",  name: "Platform daily spend ceiling",         kind: "platform", effect: "block",            b1: true },
  { id: "G10", name: "Member monthly spend cap",             kind: "platform", effect: "block",            b1: true },
  { id: "G11", name: "Daily model call cap",                 kind: "platform", effect: "block",            b1: true },
  { id: "G12", name: "Entitlement (routes)",                 kind: "platform", effect: "block",            b1: true },
  { id: "G13", name: "Entitlement (background passes)",      kind: "platform", effect: "block",            b1: false },
  { id: "G14", name: "Plan limits",                          kind: "platform", effect: "block",            b1: false },
  { id: "G15", name: "Owner pass",                           kind: "pass",     effect: "bypass",           b1: false },
  { id: "G16", name: "Autonomy (consent)",                   kind: "platform", effect: "block",            b1: false },
  { id: "G17", name: "Auto-execute",                         kind: "platform", effect: "block",            b1: false },
  { id: "G18", name: "Schedule pause",                       kind: "platform", effect: "block",            b1: false },
  { id: "G19", name: "Chaining",                             kind: "platform", effect: "block",            b1: true },
  { id: "G20", name: "Marketing email",                      kind: "platform", effect: "block",            b1: true },
  { id: "G21", name: "Unsubscribe",                          kind: "platform", effect: "block",            b1: false },
  { id: "G22", name: "Outreach caps",                        kind: "platform", effect: "block",            b1: false },
  { id: "G23", name: "outreach_safe",                        kind: "platform", effect: "block",            b1: false },
  { id: "G24", name: "BFC limits and hold",                  kind: "platform", effect: "block",            b1: false },
  { id: "G25", name: "Guide limits",                         kind: "platform", effect: "block",            b1: false }
].map(Object.freeze));

var GATE_BY_ID = {};
GATES.forEach(function (g) { GATE_BY_ID[g.id] = g; });

/* The closed action list from design §1.2, plus two the B1 adapters need and
   the design did not name: task_run (G2 holds an AI task) and route_access
   (G12 answers a route). Migration 158's check constraint holds the same list. */
var ACTIONS = Object.freeze([
  "model_call", "proposal_approve", "proposal_auto_execute", "dispatch", "schedule_run",
  "marketing_email", "outreach_send", "bfc_transfer", "social_post", "trigger_fire",
  "task_run", "route_access"
]);

/* The gates each adapted action runs, in the order server.js runs them. */
var ACTION_GATES = Object.freeze({
  model_call:       Object.freeze(["G9", "G11", "G10"]),
  proposal_approve: Object.freeze(["G3", "G1"]),
  task_run:         Object.freeze(["G2"]),
  route_access:     Object.freeze(["G12"]),
  dispatch:         Object.freeze(["G19", "G12"]),
  marketing_email:  Object.freeze(["G20"])
});

var RESULTS = Object.freeze(["pass", "fail", "bypass", "not_reached"]);
var OUTCOMES = Object.freeze(["ran", "blocked", "held_for_approval"]);

/* One fixed sentence per code. Nothing in them comes from the request. */
var REASONS = Object.freeze({
  // G9
  PLATFORM_DAILY_SPEND_LIMIT:               "The platform's daily spend ceiling was reached.",
  PLATFORM_DAILY_SPEND_LIMIT_MISCONFIGURED: "The platform's daily spend ceiling is set to a value that cannot be read.",
  PLATFORM_SPEND_UNREADABLE:                "Today's platform spend could not be read, so the call was refused.",
  // G11
  DAILY_MODEL_CALL_LIMIT:                   "The daily model call limit for this account was reached.",
  DAILY_MODEL_CALL_LIMIT_MISCONFIGURED:     "The daily model call limit is set to a value that cannot be read.",
  // G10
  MONTHLY_MODEL_SPEND_LIMIT:                "This account's monthly model spend limit was reached.",
  MONTHLY_MODEL_SPEND_LIMIT_MISCONFIGURED:  "The monthly model spend limit is set to a value that cannot be read.",
  gate_error:                               "The gate could not finish its check, so the action did not go ahead.",
  // G15, as a bypass of another gate
  owner_pass:                               "The owner's account is not held by this gate.",
  admin_exempt:                             "An admin account is not held by this gate.",
  // G12 and G3
  subscription_required:                    "An active subscription is needed for this.",
  plan_unreadable:                          "The account's plan could not be read.",
  // G1
  approved:                                 "A person approved this proposal.",
  not_pending:                              "The proposal was not found or was no longer pending.",
  no_executor:                              "No executor is registered for this kind of proposal.",
  // G2
  high_risk:                                "The task asks for a high-risk action, so it waits for a person's approval.",
  // G19
  chaining_disabled:                        "Agent chaining is switched off.",
  chain_id_missing:                         "The dispatch carried no chain id.",
  chain_depth_invalid:                      "The chain depth was not a whole number of zero or more.",
  chain_calls_invalid:                      "The chain's call count was not a whole number of zero or more.",
  chain_total_calls_reached:                "The chain reached its total call limit.",
  chain_depth_reached:                      "The chain reached its depth limit.",
  chain_fanout_reached:                     "This step reached its fan-out limit.",
  dispatch_rate_reached:                    "This account reached its dispatches-per-minute limit.",
  tool_takes_external_action:               "That tool acts on the world, and a chain may not take external action.",
  tool_not_in_router:                       "That tool is not a mounted agent tool.",
  tool_has_no_spec:                         "That tool has no input spec, so its inputs cannot be checked.",
  body_missing_required_fields:             "The dispatch was missing inputs the tool requires.",
  handler_not_found:                        "No handler is mounted for that tool.",
  // G12, inside a dispatch
  user_missing:                             "The dispatch named no account to run for.",
  entitlement_unknown:                      "The account's plan could not be read.",
  not_entitled:                             "The account has no active subscription.",
  // G20
  no_contact:                               "There was no contact with an email address to send to.",
  invalid:                                  "The email was incomplete.",
  no_postal_address:                        "No postal address is set, and marketing mail must carry one.",
  no_webhook_secret:                        "Bounce and complaint reports cannot be received yet, so marketing mail is held.",
  lookup_failed:                            "The contact's consent or history could not be read.",
  not_confirmed:                            "The contact has not confirmed their address.",
  no_consent:                               "The contact has not given confirmed consent.",
  no_owner:                                 "The contact has no owner, so no daily cap can be applied.",
  suppressed:                               "Earlier mail to this address bounced or was marked as spam.",
  cap_unreadable:                           "The daily marketing cap is set to a value that cannot be read.",
  count_failed:                             "The last day's marketing sends could not be counted.",
  cap_reached:                              "The daily marketing email cap was reached."
});

var RESULT_REASONS = Object.freeze({
  pass:        "Passed.",
  fail:        "Did not pass.",
  bypass:      "Passed over by the owner pass.",
  not_reached: "Not reached: an earlier gate decided first, or this gate did not run."
});

function reasonFor(result, code) {
  if (code && Object.prototype.hasOwnProperty.call(REASONS, code)) return REASONS[code];
  return RESULT_REASONS[result] || RESULT_REASONS.not_reached;
}

function isGate(id) {
  return typeof id === "string" && Object.prototype.hasOwnProperty.call(GATE_BY_ID, id);
}

/* A code is kept only when it is a short token: a code is never a free-text
   field, so anything else (an error message, an address) is dropped. */
function cleanCode(code) {
  if (typeof code !== "string") return null;
  return /^[A-Za-z0-9_]{1,64}$/.test(code) ? code : null;
}

function evaluate(action, context, gates) {
  if (ACTIONS.indexOf(action) === -1) {
    throw new TypeError("gates.evaluate: unknown action " + JSON.stringify(action));
  }
  var order = Array.isArray(gates) ? gates : ACTION_GATES[action];
  if (!Array.isArray(order) || !order.length) {
    throw new TypeError("gates.evaluate: no gates for action " + JSON.stringify(action));
  }
  var observed = (context && context.observed && typeof context.observed === "object") ? context.observed : {};

  var stopped = null;
  var results = order.map(function (entry) {
    var id = (entry && typeof entry === "object") ? entry.id : entry;
    if (!isGate(id)) throw new TypeError("gates.evaluate: unknown gate " + JSON.stringify(id));
    if (stopped) return { gate: id, result: "not_reached", code: null, reason: reasonFor("not_reached", null) };
    var seen = Object.prototype.hasOwnProperty.call(observed, id) ? observed[id] : null;
    var result = seen && RESULTS.indexOf(seen.result) !== -1 ? seen.result : "not_reached";
    var code = result === "not_reached" ? null : cleanCode(seen && seen.code);
    if (result === "fail") stopped = GATE_BY_ID[id];
    return { gate: id, result: result, code: code, reason: reasonFor(result, code) };
  });

  var outcome = "ran";
  if (stopped) outcome = stopped.effect === "require_approval" ? "held_for_approval" : "blocked";
  return { action: action, outcome: outcome, results: results };
}

/* What a gate_decisions row holds in `results`: gate, result and code only. */
function toRecord(decision) {
  return decision.results.map(function (r) {
    var out = { gate: r.gate, result: r.result };
    if (r.code) out.code = r.code;
    return out;
  });
}

/* Targets name what was decided on, never who or what was in it: a kind and,
   for the member's own rows, the row id. Anything that is not a short token is
   cut to its kind. */
function cleanTarget(target) {
  var s = String(target == null ? "" : target);
  if (/^[a-z_]{1,32}(:[A-Za-z0-9_./: -]{1,120})?$/.test(s)) return s;
  var kind = /^[a-z_]{1,32}/.exec(s);
  return kind ? kind[0] : "unknown";
}

var RETENTION_DAYS = 90;

module.exports = {
  GATES: GATES,
  ACTIONS: ACTIONS,
  ACTION_GATES: ACTION_GATES,
  RESULTS: RESULTS,
  OUTCOMES: OUTCOMES,
  REASONS: REASONS,
  RETENTION_DAYS: RETENTION_DAYS,
  isGate: isGate,
  reasonFor: reasonFor,
  evaluate: evaluate,
  toRecord: toRecord,
  cleanTarget: cleanTarget
};
