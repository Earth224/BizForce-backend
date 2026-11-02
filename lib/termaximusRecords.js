/* ═══════════════════════════════════════════════════════════════════════════
   lib/termaximusRecords.js — Termaximus answers from the records (intelligence
   layer B10)

   WHAT IT ANSWERS. Four questions, each built by a FIXED TEMPLATE from the
   member's own rows and nothing else:

     why_ran / why_not  one gate_decisions row (lib/gates.js explain): every
                        gate in order with pass, fail, bypass or not reached and
                        the REASONS sentence for its stored code, and the
                        member gate by name when one stopped it. The template
                        follows the record: asked "why did it run?" of a
                        blocked action, it says the record shows it did not.
     next_fire          one member_triggers row: the next hourly check (:30
                        UTC, only when ENABLE_TRIGGERS is exactly "true"; when
                        it is not, the answer says plainly that nothing fires),
                        the value read at the last check against the line, and
                        the cooldown remaining.
     flow               one declared edge of the agent network
                        (lib/agentNetwork.js): the runs that flowed along it in
                        the window, counted from the member's own rows.

   TWO WAYS IN.
     Buttons ("Why?", a trigger, a map edge) name the intent and the subject
     themselves: GET /api/guide/records/answer. ZERO model calls.
     Free text ("why didn't my SEO run yesterday?"): POST /api/guide/records.
     The model is shown ONLY a list of the member's recent subject ids, each
     labelled by kind, agent and time, never a name, a prompt, a reason or any
     other content, and it may only point at one of them: it returns
     {"intent": ..., "subject_id": ...}. The server checks the id was offered
     and the intent fits its kind, then reads the row again filtered on the
     member's user_id and answers with the same template. THE MODEL NEVER
     WRITES A FACT: its words are never shown. When nothing matches, the
     answer is exactly NO_RECORD plus the closest real page. The call is one
     Haiku call inside Guide mode's own daily allowance (30 a day with an
     active subscription, 5 without), counted from the same model_calls rows
     (route "guide"), through the same server limits and ledger
     (callGuideModel in server.js).

   SUGGESTIONS BY RULE (no model): GET /api/guide/suggestions reads the
   member's own numbers and offers a ready-made trigger when a rule holds
   (SUGGESTION_RULES). Nothing is saved here: "Add it" in the page posts the
   offered body to POST /api/triggers, which validates it like any other.

   Every read names the caller's user_id. Nothing here writes.
   ═══════════════════════════════════════════════════════════════════════════ */
"use strict";

var gates = require("./gates");
var T = require("./triggers");
var NET = require("./agentNetwork");
var guideAsk = require("./guideAsk");

var INTENTS = Object.freeze(["why_ran", "why_not", "next_fire", "flow"]);
var INTENT_KINDS = Object.freeze({
  why_ran: Object.freeze(["decision", "run"]),
  why_not: Object.freeze(["decision", "run"]),
  next_fire: Object.freeze(["trigger"]),
  flow: Object.freeze(["edge"])
});
var NO_RECORD = "There is no record of that.";
var CLOSING = "That is all the record holds; I add nothing to it.";
var RECORDS_MAX_TOKENS = 120;
var RECORDS_QUESTION_MAX = 500;
var OFFER_DAYS = 7;
var OFFER_DECISIONS = 20;
var OFFER_RUNS = 15;
var BUTTON_WINDOW = "24h";
var FREE_TEXT_WINDOW = "7d";
var HOUR_MS = 3600000;
var DAY_MS = 24 * HOUR_MS;
var HQ = "executive-agent.html";

var UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
var SUBJECT_RES = Object.freeze({
  decision: new RegExp("^decision:(" + UUID + ")$", "i"),
  run: new RegExp("^run:(" + UUID + ")$", "i"),
  trigger: new RegExp("^trigger:(" + UUID + ")$", "i"),
  edge: /^edge:([a-z_]{2,24})>([a-z_]{2,24})$/
});

var ACTION_WORDS = Object.freeze({
  model_call: "A model call", proposal_approve: "An approval", proposal_auto_execute: "An automatic run", dispatch: "A chained tool",
  schedule_run: "A scheduled run", marketing_email: "A marketing email", outreach_send: "An outreach send", bfc_transfer: "A BizCash transfer",
  social_post: "A Bluesky post", trigger_fire: "A trigger firing", task_run: "An agent run", route_access: "A request"
});
var RESULT_WORDS = Object.freeze({ pass: "Pass", fail: "Fail", bypass: "Bypass", not_reached: "Not reached" });
var UNIT_WORDS = Object.freeze({ m: "minute", h: "hour", d: "day" });

/* ── small words ──────────────────────────────────────────────────────────── */
function agentWords(a) { return Object.prototype.hasOwnProperty.call(T.AGENT_NAMES, a) ? T.AGENT_NAMES[a] : null; }
function utcWords(iso) {
  var ms = Date.parse(iso);
  if (!isFinite(ms)) return "an unrecorded time";
  var s = new Date(ms).toISOString();
  return s.slice(0, 10) + " " + s.slice(11, 16) + " UTC";
}
function plural(n, one) { return n + " " + one + (n === 1 ? "" : "s"); }
function windowWords(label) {
  var m = /^([1-9][0-9]{0,4})(m|h|d)$/.exec(String(label || ""));
  return m ? plural(Number(m[1]), UNIT_WORDS[m[2]]) : String(label);
}
function spanWords(ms) {
  var mins = Math.max(1, Math.ceil(ms / 60000));
  var h = Math.floor(mins / 60), m = mins % 60;
  if (!h) return plural(m, "minute");
  return m ? plural(h, "hour") + " " + plural(m, "minute") : plural(h, "hour");
}
function amountWords(metric, n) {
  var kind = T.METRICS[metric] ? T.METRICS[metric].kind : "count";
  if (kind === "percent") return n + "%";
  if (kind === "bfc") return n + " BFC";
  return String(n);
}
function hqLink(label, tab) { return { label: label, href: "/" + HQ + "#" + tab }; }

/* The answer every template returns. known is true for an answer from a
   record, false for NO_RECORD. */
function answer(intent, subject, title, lines, links) {
  return { intent: intent, subject: subject, known: true, title: title, lines: lines, text: lines.join(" "), links: links || [] };
}

/* NO_RECORD and the closest real page: for free text, the page whose words
   the question shares most (lib/guideAsk.js closestPage); for a button, HQ. */
function noRecord(map, question, reason) {
  var page = question && map && map.pages ? guideAsk.closestPage(map, question) : HQ;
  var p = map && map.pages && map.pages[page] ? map.pages[page] : null;
  return {
    intent: null, subject: null, known: false, title: null, lines: [NO_RECORD], text: NO_RECORD,
    links: [{ label: "The closest real page: " + (p ? (p.h || p.t || page) : page), href: p ? p.p : "/" + page }],
    reason: reason || "no_record"
  };
}

/* ── the templates (pure) ─────────────────────────────────────────────────── */

/* why_ran / why_not from one stored decision row. */
function whyTemplate(intent, row) {
  var d = gates.explain(row);
  var agent = row && row.facts && typeof row.facts.agent === "string" ? agentWords(row.facts.agent) : null;
  var stopped = d.gates.filter(function (g) { return g.result === "fail"; })[0] || null;
  var lines = [];
  var title;
  if (d.outcome === "ran") {
    title = "Why it ran";
    lines.push("It ran. No gate in the record stopped it.");
  } else if (d.outcome === "held_for_approval") {
    title = "Why it is waiting";
    lines.push("It is waiting for you. " + (stopped ? stopped.name : "A gate") + " held it for your approval.");
  } else if (d.member && !stopped) {
    title = "Why it did not run";
    lines.push("It did not run. Your own gate \"" + d.member.name + "\" stopped it after the platform's gates let it through.");
  } else {
    title = "Why it did not run";
    lines.push("It did not run. " + (stopped ? stopped.name + " stopped it." : "The record names no gate that stopped it."));
  }
  if (intent === "why_ran" && d.outcome !== "ran") lines.push("You asked why it ran; the record shows it did not.");
  if (intent === "why_not" && d.outcome === "ran") lines.push("You asked why it did not run; the record shows it ran.");
  lines.push((ACTION_WORDS[d.action] || "An action") + (agent ? " for the " + agent + " agent" : "") + ", recorded " + utcWords(d.created_at) + ".");
  d.gates.forEach(function (g, i) {
    lines.push((i + 1) + ". " + (g.name || "An unknown gate") + ": " + RESULT_WORDS[g.result] + ". " + g.reason);
  });
  if (d.member) lines.push("Your gate \"" + d.member.name + "\": Fail. " + d.member.reason);
  lines.push(CLOSING);
  var links = [{ label: "Open the Why panel", why_decision: d.id }];
  var run = /^ai_task:(.+)$/.exec(String(d.target || ""));
  if (run) links.push({ label: "Open the run", href: "/run.html?id=" + encodeURIComponent(run[1]) });
  links.push(hqLink("Every decision", "approvals"));
  return answer(intent, "decision:" + d.id, title, lines, links);
}

/* The next hourly check after nowMs: :30 UTC of this hour, or of the next. */
function nextCheckMs(nowMs) {
  var d = new Date(nowMs);
  var t = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), d.getUTCHours(), 30);
  return t > nowMs ? t : t + HOUR_MS;
}

/* next_fire from one member_triggers row. */
function nextFireTemplate(row, env, nowMs) {
  var t = T.fromRow(row);
  var serverOn = T.triggersEnabled(env);
  var lines = [T.summarize(t)];
  var next = nextCheckMs(nowMs);
  if (!serverOn) {
    lines.push("Triggers are switched off on the server right now, so \"" + t.name + "\" will not fire. Nothing is checked until they are switched on.");
  } else if (!t.enabled) {
    lines.push("\"" + t.name + "\" is switched off, so it is not checked and will not fire.");
  } else {
    lines.push("The next check is at " + utcWords(new Date(next).toISOString()) + ".");
  }
  var crossing = null;
  if (t.last_checked_at) {
    if (t.last_value === null) {
      lines.push("At the last check (" + utcWords(t.last_checked_at) + ") there was no number to judge.");
    } else {
      lines.push("At the last check (" + utcWords(t.last_checked_at) + ") the number was " + amountWords(t.metric, t.last_value) + ".");
      if (t.comparator === "drop_pct") {
        lines.push("A drop is judged at each check against the window before, so the last value alone does not say whether it crosses your line.");
      } else {
        crossing = T.crosses(t, t.last_value, null);
        lines.push(crossing ? "That crosses your line." : "That does not cross your line.");
      }
    }
  } else {
    lines.push("It has not been checked yet.");
  }
  var last = t.last_attempt_at ? Date.parse(t.last_attempt_at) : NaN;
  var coolEnds = isFinite(last) ? last + t.cooldown_hours * HOUR_MS : null;
  if (coolEnds !== null && coolEnds > nowMs) {
    lines.push("Its cooldown runs until " + utcWords(new Date(coolEnds).toISOString()) + ", " + spanWords(coolEnds - nowMs) + " from now; it cannot fire before then.");
  } else if (coolEnds !== null) {
    lines.push("No cooldown is running.");
  } else {
    lines.push("No cooldown is running: it has never reached the gates.");
  }
  if (serverOn && t.enabled) {
    if (crossing === true && (coolEnds === null || coolEnds <= next)) {
      lines.push("If the number still crosses your line at that check, it fires, within your daily cap and the gates.");
    } else if (crossing === true) {
      lines.push("It crossed your line, but the cooldown holds it until " + utcWords(new Date(coolEnds).toISOString()) + ".");
    } else {
      lines.push("It fires only if the number crosses your line at a check.");
    }
  }
  lines.push(CLOSING);
  return answer("next_fire", "trigger:" + t.id, "When \"" + t.name + "\" fires next", lines,
    [hqLink("Open your triggers", "settings")]);
}

/* flow from one declared edge and its runs (null when they could not be read). */
function flowTemplate(edge, runs, enabled, windowLabel) {
  var from = NET.name(edge.from), to = NET.name(edge.to);
  var lines = [];
  if (runs === null) {
    lines.push("This link's runs could not be read just now, so I will not give a count.");
  } else {
    lines.push("In the last " + windowWords(windowLabel) + ", " + plural(runs.length, "run") + " flowed from " + from + " to " + to + ".");
    if (runs.length) lines.push("The newest was at " + utcWords(runs[0].at) + ".");
  }
  lines.push("This link carries: " + edge.sources.map(function (s) { return s.label; }).join("; ") + ".");
  if (enabled === false) lines.push("You have switched this link off, so no new work flows along it.");
  lines.push(CLOSING);
  var links = [hqLink("Open the network map", "agents")];
  (runs || []).slice(0, 3).forEach(function (r) {
    var out = NET.runOut(r);
    if (out.href) links.push({ label: "A run at " + utcWords(r.at), href: out.href });
  });
  return answer("flow", "edge:" + edge.id, "How work flows from " + from + " to " + to, lines, links);
}

/* ── subjects ─────────────────────────────────────────────────────────────── */
function subjectKind(subject) {
  var s = String(subject == null ? "" : subject);
  var kinds = Object.keys(SUBJECT_RES);
  for (var i = 0; i < kinds.length; i++) {
    var m = SUBJECT_RES[kinds[i]].exec(s);
    if (m) return { kind: kinds[i], id: m[1].toLowerCase(), to: m[2] || null };
  }
  return null;
}

/* The button request: intent, subject and, for flow, a window. */
function validateButton(query) {
  var q = query && typeof query === "object" ? query : {};
  var extra = Object.keys(q).filter(function (k) { return ["intent", "subject", "window"].indexOf(k) === -1; });
  if (extra.length) return { error: "Unknown field " + JSON.stringify(String(extra[0]).slice(0, 40)) + ". A question about a record has intent, subject and window.", field: String(extra[0]).slice(0, 40) };
  if (INTENTS.indexOf(q.intent) === -1) return { error: "The intent is one of " + INTENTS.join(", ") + ".", field: "intent" };
  var sub = subjectKind(q.subject);
  if (!sub || INTENT_KINDS[q.intent].indexOf(sub.kind) === -1) {
    return { error: "The subject for " + q.intent + " is " + INTENT_KINDS[q.intent].map(function (k) { return k + ":<id>"; }).join(" or ") + ".", field: "subject" };
  }
  var win = q.window === undefined ? BUTTON_WINDOW : q.window;
  if (q.intent === "flow" && !NET.windowMs(win)) return { error: "The window is a whole number of minutes, hours or days, such as 90m, 24h or 7d, up to 30 days.", field: "window" };
  return { intent: q.intent, subject: String(q.subject), window: String(win) };
}

/* ── the reads, each filtered on the member's user_id ─────────────────────── */
var DECISION_ROW = "id, action, target, outcome, results, facts, member_gate_name, created_at";

async function readDecision(db, userId, id) {
  var got = await db.from("gate_decisions").select(DECISION_ROW).eq("id", id).eq("user_id", userId).maybeSingle();
  if (got.error) throw new Error("decision: " + (got.error.message || "unreadable"));
  return got.data || null;
}
async function readRunDecision(db, userId, taskId) {
  var got = await db.from("gate_decisions").select(DECISION_ROW)
    .eq("user_id", userId).eq("target", "ai_task:" + taskId).order("created_at", { ascending: false }).limit(1);
  if (got.error) throw new Error("run decision: " + (got.error.message || "unreadable"));
  return (got.data || [])[0] || null;
}
async function readTrigger(db, userId, id, columns) {
  var got = await db.from("member_triggers").select(columns).eq("id", id).eq("user_id", userId).maybeSingle();
  if (got.error) throw new Error("trigger: " + (got.error.message || "unreadable"));
  return got.data || null;
}

/* answerFor(deps, userId, intent, subject, windowLabel) -> the template's
   answer, NO_RECORD when the member has no such row, or throws when a read
   fails. deps: { supabase, env, nowMs, graph, triggerColumns, map }. */
async function answerFor(deps, userId, intent, subject, windowLabel) {
  var sub = subjectKind(subject);
  if (!userId || !sub || INTENT_KINDS[intent] === undefined || INTENT_KINDS[intent].indexOf(sub.kind) === -1) return noRecord(deps.map, null, "not_offered");
  var db = deps.supabase;
  if (sub.kind === "decision" || sub.kind === "run") {
    var row = sub.kind === "decision" ? await readDecision(db, userId, sub.id) : await readRunDecision(db, userId, sub.id);
    return row ? whyTemplate(intent, row) : noRecord(deps.map, null, "not_owned");
  }
  if (sub.kind === "trigger") {
    var trig = await readTrigger(db, userId, sub.id, deps.triggerColumns);
    return trig ? nextFireTemplate(trig, deps.env, deps.nowMs) : noRecord(deps.map, null, "not_owned");
  }
  var edge = deps.graph.edges.filter(function (e) { return e.from === sub.id && e.to === sub.to; })[0];
  if (!edge) return noRecord(deps.map, null, "not_declared");
  var since = new Date(deps.nowMs - NET.windowMs(windowLabel)).toISOString();
  var runs;
  try { runs = await NET.edgeRuns(db, userId, edge, since); } catch (readErr) { runs = null; }
  var switches = await NET.memberSwitches(db, userId);
  return flowTemplate(edge, runs, switches[edge.id] !== false, windowLabel);
}

/* The member's recent subjects, each { id, kind, agent, at }: never a name, a
   prompt, a reason, an outcome sentence or any other content. A read that
   fails throws (nothing is offered on a guess). */
async function offeredSubjects(deps, userId, nowMs) {
  var db = deps.supabase;
  var since = new Date(nowMs - OFFER_DAYS * DAY_MS).toISOString();
  var list = [];
  var decided = await db.from("gate_decisions").select("id, action, facts, created_at")
    .eq("user_id", userId).gte("created_at", since).order("created_at", { ascending: false }).limit(OFFER_DECISIONS);
  if (decided.error) throw new Error("decisions: " + (decided.error.message || "unreadable"));
  (decided.data || []).forEach(function (r) {
    var agent = r.facts && typeof r.facts.agent === "string" && agentWords(r.facts.agent) ? r.facts.agent : null;
    var action = gates.ACTIONS.indexOf(r.action) !== -1 ? r.action : "other";
    list.push({ id: "decision:" + r.id, kind: "decision_" + action, agent: agent, at: r.created_at });
  });
  var ran = await db.from("ai_tasks").select("id, agent_type, created_at")
    .eq("user_id", userId).gte("created_at", since).order("created_at", { ascending: false }).limit(OFFER_RUNS);
  if (ran.error) throw new Error("runs: " + (ran.error.message || "unreadable"));
  (ran.data || []).forEach(function (r) {
    list.push({ id: "run:" + r.id, kind: "run", agent: agentWords(r.agent_type) ? r.agent_type : null, at: r.created_at });
  });
  var trig = await db.from("member_triggers").select("id, metric_agent, action, created_at")
    .eq("user_id", userId).order("created_at", { ascending: true }).limit(T.LIMITS.MAX_TRIGGERS);
  if (trig.error) throw new Error("triggers: " + (trig.error.message || "unreadable"));
  (trig.data || []).forEach(function (r) {
    var a = r.action && typeof r.action.agent === "string" ? r.action.agent : r.metric_agent;
    list.push({ id: "trigger:" + r.id, kind: "trigger", agent: agentWords(a) ? a : null, at: r.created_at });
  });
  deps.graph.edges.forEach(function (e) {
    list.push({ id: "edge:" + e.id, kind: "edge", agent: e.from + ">" + e.to, at: null });
  });
  return list;
}

/* ── the free-text call ───────────────────────────────────────────────────── */
var RECORDS_PERSONA =
  "You match a BizForce member's question to ONE of their records, or to none. You never answer the question yourself.\n" +
  "You are given only a list of records, each with an id, a kind, an agent and a time. You know nothing else about them.\n" +
  "Intents: why_ran or why_not (for a decision_* or run record), next_fire (for a trigger record), flow (for an edge record, agent shown as from>to).\n" +
  "Reply with ONE JSON object and nothing else: {\"intent\":\"why_ran\"|\"why_not\"|\"next_fire\"|\"flow\",\"subject_id\":\"<an id copied exactly from the list>\"}, " +
  "or {\"intent\":null,\"subject_id\":null} when no record fits. Never write any other words.";

function recordsSystemBlocks() { return [{ type: "text", text: RECORDS_PERSONA }]; }
function recordsUserMessage(question, list, nowIso) {
  return JSON.stringify({ question: question, now: nowIso, records: list.map(function (s) { return { id: s.id, kind: s.kind, agent: s.agent, at: s.at }; }) });
}

/* The model's pick, checked: an intent from INTENTS, an id from the offered
   list, and an intent that fits that id's kind. Anything else is refused. */
function pickSubject(raw, list) {
  if (!raw || typeof raw !== "object") return { ok: false, reason: "no_match" };
  if (raw.intent === null || raw.subject_id === null) return { ok: false, reason: "no_match" };
  if (INTENTS.indexOf(raw.intent) === -1) return { ok: false, reason: "bad_intent" };
  var id = typeof raw.subject_id === "string" ? raw.subject_id : "";
  var offered = list.filter(function (s) { return s.id === id; })[0];
  if (!offered) return { ok: false, reason: "not_offered" };
  var sub = subjectKind(id);
  if (!sub || INTENT_KINDS[raw.intent].indexOf(sub.kind) === -1) return { ok: false, reason: "intent_does_not_fit" };
  return { ok: true, intent: raw.intent, subject: id };
}

function validateRecordsQuestion(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) return { error: "The request must be a JSON object with a question.", field: "body" };
  var extra = Object.keys(body).filter(function (k) { return k !== "question"; });
  if (extra.length) return { error: "Only a question is accepted. Nothing was sent to Termaximus.", field: String(extra[0]).slice(0, 40) };
  var q = typeof body.question === "string" ? body.question.replace(/\s+/g, " ").trim() : "";
  if (!q) return { error: "The question is missing or empty. Nothing was sent to Termaximus.", field: "question" };
  if (q.length > RECORDS_QUESTION_MAX) return { error: "The question is longer than " + RECORDS_QUESTION_MAX + " characters. Nothing was sent to Termaximus.", field: "question" };
  return { question: q };
}

/* deps: map, supabase, env, now() -> ms, graph(), triggerColumns, getPlan,
   callModel({ userId, system, user, maxTokens }) -> { text } (the server's
   limits first, then the ledger row, route "guide"), utcDay(). */
function createRecordsAskHandler(deps) {
  return async function recordsAsk(req, res, next) {
    try {
      var input = validateRecordsQuestion(req.body);
      if (input.error) return res.status(400).json({ error: input.error, field: input.field });
      var userId = req.user.id;
      var plan = await deps.getPlan(userId, req.user);
      var subscribed = !!(plan && plan.active === true);
      var limit = guideAsk.guideDailyLimit(subscribed);
      var used = await deps.supabase.from("model_calls").select("*", { count: "exact", head: true })
        .eq("user_id", userId).eq("route", guideAsk.GUIDE_ROUTE).eq("created_on", deps.utcDay());
      if (!used || used.error || typeof used.count !== "number") {
        return res.status(503).json({ error: "Termaximus could not check today's guide limit just now, so nothing was asked. Try again in a minute.", reason: "guide_count_unreadable" });
      }
      if (used.count >= limit) {
        return res.status(429).json({
          error: subscribed
            ? "That is all " + limit + " guide answers for today; they come back at midnight UTC."
            : "Without an active subscription Guide mode answers " + limit + " questions a day, and today's are used. Billing is where a subscription starts.",
          reason: "guide_daily_limit", limit: limit, used: used.count, subscribed: subscribed,
          link: { page: "billing.html", href: "/billing.html" }
        });
      }
      var nowMs = deps.now();
      var ctx = { supabase: deps.supabase, env: deps.env, nowMs: nowMs, graph: deps.graph(), triggerColumns: deps.triggerColumns, map: deps.map };
      var list;
      try { list = await offeredSubjects(ctx, userId, nowMs); } catch (readErr) {
        return res.status(503).json({ error: "Your records could not be read just now, so nothing was asked.", reason: "records_unreadable" });
      }
      var spent = 0;
      var reply = null;
      if (list.length) {
        try {
          reply = await deps.callModel({ userId: userId, system: recordsSystemBlocks(), user: recordsUserMessage(input.question, list, new Date(nowMs).toISOString()), maxTokens: RECORDS_MAX_TOKENS });
          spent = 1;
        } catch (refused) {
          if (refused && refused.status) return res.status(refused.status).json({ error: refused.message, reason: refused.code || "model_limit" });
          throw refused;
        }
      }
      var pick = list.length ? pickSubject(guideAsk.parseGuideJson(reply && reply.text), list) : { ok: false, reason: "no_records" };
      var out;
      if (!pick.ok) out = noRecord(deps.map, input.question, pick.reason);
      else {
        try { out = await answerFor(ctx, userId, pick.intent, pick.subject, FREE_TEXT_WINDOW); } catch (readErr) {
          return res.status(503).json({ error: "That record could not be read just now.", reason: "records_unreadable" });
        }
        if (out.known === false) out = noRecord(deps.map, input.question, out.reason);
      }
      out.limit = { per_day: limit, subscribed: subscribed, used: used.count + spent };
      return res.json(out);
    } catch (error) {
      next(error);
    }
  };
}

/* ── suggestions by rule ──────────────────────────────────────────────────── */
var SUGGEST_FAILED_RUNS = 3;
var SUGGEST_PENDING_OVER = 5;
var SUGGEST_SPEND_PCT = 60;
var SUGGEST_SPEND_BEFORE_DAY = 20;
var SUGGEST_STOCK_AT = 1;
var NOT_NOW_DAYS = 30;

function templateBody(key) {
  var tp = T.TEMPLATES.filter(function (x) { return x.key === key; })[0];
  return tp ? JSON.parse(JSON.stringify(tp.body)) : null;
}
function suggestion(key, title, why, numbers, body) {
  var checked = T.validateTrigger(body, null, { owner: false });
  if (!checked.ok) return null;
  return { key: key, kind: "trigger", title: title, why: why, numbers: numbers, body: body, summary: T.summarize(checked.value) };
}

/* The rules, in order. Each reads the member's own numbers and offers one
   trigger body, saved only when the member presses "Add it". */
var SUGGESTION_RULES = Object.freeze([
  Object.freeze({ key: "pause_after_failures", rule: SUGGEST_FAILED_RUNS + " or more failed runs in the last 7 days" }),
  Object.freeze({ key: "proposals_waiting", rule: "more than " + SUGGEST_PENDING_OVER + " proposals waiting for approval" }),
  Object.freeze({ key: "spend_near_cap", rule: "AI spend at " + SUGGEST_SPEND_PCT + "% or more of the monthly cap before the " + SUGGEST_SPEND_BEFORE_DAY + "th (UTC)" }),
  Object.freeze({ key: "stock_reorder", rule: SUGGEST_STOCK_AT + " or more items at their reorder point" })
]);

/* deps: supabase, nowMs, metric(t) -> { value } (lib/triggerRunner.js
   metricValue with the server's deps). Returns { suggestions, unreadable }. */
async function suggestionsFor(deps, userId) {
  var db = deps.supabase;
  var out = [];
  var unreadable = [];
  var held = {};
  var mine = await db.from("member_triggers").select("name").eq("user_id", userId);
  if (mine.error) unreadable.push({ rule: "your triggers", reason: "Your triggers could not be read, so a suggestion may repeat one you have." });
  else (mine.data || []).forEach(function (r) { held[r.name] = true; });

  // 1. failed runs in the last 7 days, by agent.
  var failed = await db.from("ai_tasks").select("id, agent_type")
    .eq("user_id", userId).eq("status", "failed").gt("created_at", new Date(deps.nowMs - 7 * DAY_MS).toISOString()).limit(1000);
  if (failed.error) unreadable.push({ rule: SUGGESTION_RULES[0].rule, reason: "Your failed runs could not be read just now." });
  else {
    var rows = failed.data || [];
    if (rows.length >= SUGGEST_FAILED_RUNS) {
      var by = {};
      rows.forEach(function (r) { if (agentWords(r.agent_type)) by[r.agent_type] = (by[r.agent_type] || 0) + 1; });
      var top = Object.keys(by).sort(function (a, b) { return by[b] - by[a] || (a < b ? -1 : 1); })[0];
      if (top) {
        var body = { name: "Pause after failures", metric: "tasks_failed", comparator: "gte", threshold: SUGGEST_FAILED_RUNS, window: "24h", cooldown_hours: 24,
          action: { kind: "pause_schedule", agent: top }, enabled: true };
        var s1 = suggestion("pause_after_failures", "Pause after failures",
          plural(rows.length, "run") + " failed in the last 7 days; the " + agentWords(top) + " agent had the most (" + by[top] + ").",
          { failed_runs_7d: rows.length, most_agent: top, most_count: by[top] }, body);
        if (s1 && !held[body.name]) out.push(s1);
      }
    }
  }

  // 2. proposals waiting.
  try {
    var pending = await deps.metric({ metric: "proposals_pending", window: "now" });
    if (typeof pending.value === "number" && pending.value > SUGGEST_PENDING_OVER) {
      var b2 = templateBody("proposals_waiting");
      var s2 = suggestion("proposals_waiting", "Proposals waiting",
        plural(pending.value, "proposal") + " are waiting for your approval now, more than " + SUGGEST_PENDING_OVER + ".", { pending_now: pending.value }, b2);
      if (s2 && !held[b2.name]) out.push(s2);
    }
  } catch (readErr) { unreadable.push({ rule: SUGGESTION_RULES[1].rule, reason: "Your pending proposals could not be read just now." }); }

  // 3. spend against the cap, before the 20th.
  var day = new Date(deps.nowMs).getUTCDate();
  if (day < SUGGEST_SPEND_BEFORE_DAY) {
    try {
      var spend = await deps.metric({ metric: "spend_vs_cap", window: "now" });
      if (typeof spend.value === "number" && spend.value >= SUGGEST_SPEND_PCT) {
        var b3 = templateBody("spend_near_cap");
        var s3 = suggestion("spend_near_cap", "Spend nearing your cap",
          "This month's AI spend is " + spend.value + "% of your monthly cap, and it is only day " + day + " of the month (UTC).", { spend_pct: spend.value, day_of_month: day }, b3);
        if (s3 && !held[b3.name]) out.push(s3);
      }
    } catch (readErr) { unreadable.push({ rule: SUGGESTION_RULES[2].rule, reason: "Your spend could not be read just now." }); }
  }

  // 4. stock at its reorder point.
  try {
    var stock = await deps.metric({ metric: "stock_at_reorder", window: "now" });
    if (typeof stock.value === "number" && stock.value >= SUGGEST_STOCK_AT) {
      var b4 = templateBody("stock_reorder");
      var s4 = suggestion("stock_reorder", "Stock at reorder point",
        plural(stock.value, "item") + " " + (stock.value === 1 ? "is" : "are") + " at or below the reorder point now.", { items_at_reorder: stock.value }, b4);
      if (s4 && !held[b4.name]) out.push(s4);
    }
  } catch (readErr) { unreadable.push({ rule: SUGGESTION_RULES[3].rule, reason: "Your stock could not be read just now." }); }

  return { suggestions: out, unreadable: unreadable, rules: SUGGESTION_RULES.map(function (r) { return r.rule; }), not_now_days: NOT_NOW_DAYS };
}

module.exports = {
  INTENTS: INTENTS,
  INTENT_KINDS: INTENT_KINDS,
  NO_RECORD: NO_RECORD,
  CLOSING: CLOSING,
  RECORDS_MAX_TOKENS: RECORDS_MAX_TOKENS,
  RECORDS_PERSONA: RECORDS_PERSONA,
  OFFER_DAYS: OFFER_DAYS,
  BUTTON_WINDOW: BUTTON_WINDOW,
  FREE_TEXT_WINDOW: FREE_TEXT_WINDOW,
  SUGGESTION_RULES: SUGGESTION_RULES,
  NOT_NOW_DAYS: NOT_NOW_DAYS,
  whyTemplate: whyTemplate,
  nextFireTemplate: nextFireTemplate,
  flowTemplate: flowTemplate,
  nextCheckMs: nextCheckMs,
  noRecord: noRecord,
  subjectKind: subjectKind,
  validateButton: validateButton,
  validateRecordsQuestion: validateRecordsQuestion,
  answerFor: answerFor,
  offeredSubjects: offeredSubjects,
  recordsSystemBlocks: recordsSystemBlocks,
  recordsUserMessage: recordsUserMessage,
  pickSubject: pickSubject,
  createRecordsAskHandler: createRecordsAskHandler,
  suggestionsFor: suggestionsFor
};
