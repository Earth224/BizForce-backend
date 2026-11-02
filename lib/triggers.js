/* ═══════════════════════════════════════════════════════════════════════════
   lib/triggers.js — member triggers (intelligence layer B4, design section 2)

   WHAT A TRIGGER IS. A member watches one number from their own account and
   names a line: "when <metric> <comparator> <threshold> over <window>, do
   <action>, at most once per <cooldown>". The hourly pass (lib/triggerRunner.js,
   at :30 UTC) reads the number, and when it crosses the line the trigger fires,
   through the gate evaluator (lib/gates.js, action trigger_fire), and the
   firing is recorded with its decision id.

   CLOSED. Every part of a trigger is a key from a fixed list here:
     - METRICS, the nine numbers of design section 2.1, each read by a count or
       a sum over rows the member already has (no new tracking of people);
     - COMPARATORS lt, lte, gt, gte, and drop_pct (a fall against the window
       before, only for numbers with a history);
     - WINDOWS now, 1h, 24h, 48h, 7d, 30d, each metric allowing its own;
     - ACTIONS raise_alert, draft_task (an agent) and pause_schedule (an agent).
   Unknown keys anywhere are refused, so nothing rides along unchecked, and no
   text a member typed is ever evaluated: the name is a label.

   NOTHING HERE PUBLISHES OR SENDS. draft_task files a saved prompt the member
   runs with one press through the normal task route, where anything that
   would publish or send waits for approval (G2's high-risk pattern holds it:
   the drafted text always asks for approval). raise_alert writes the member's
   own notification. pause_schedule pauses that agent's schedules and alerts.

   PURE. No database, no clock, no network: times are handed in, so the same
   trigger and the same numbers always give the same answer. The runner and
   the routes do the reading; this decides.
   ═══════════════════════════════════════════════════════════════════════════ */
"use strict";

var gateRules = require("./gateRules");

var AGENTS = gateRules.AGENTS;

var AGENT_NAMES = Object.freeze({
  seo: "SEO", sales: "Sales", content: "Content", ads: "Ads", reputation: "Reputation", analytics: "Analytics",
  email: "Email", community: "Community", influencer: "Influencer", operations: "Operations", executive: "Executive",
  social: "Social", etsy: "Etsy", store: "Store", broker: "Broker", publicist: "Publicist", rd: "R&D",
  vertical_marketing: "Vertical Marketing"
});

var HOUR_MS = 3600000;
var DAY_MS = 24 * HOUR_MS;

var WINDOWS = Object.freeze({
  now: Object.freeze({ ms: 0, label: "now" }),
  "1h": Object.freeze({ ms: HOUR_MS, label: "1 hour" }),
  "24h": Object.freeze({ ms: DAY_MS, label: "24 hours" }),
  "48h": Object.freeze({ ms: 2 * DAY_MS, label: "48 hours" }),
  "7d": Object.freeze({ ms: 7 * DAY_MS, label: "7 days" }),
  "30d": Object.freeze({ ms: 30 * DAY_MS, label: "30 days" })
});
var WINDOW_KEYS = Object.freeze(Object.keys(WINDOWS));

var TIMED = Object.freeze(["1h", "24h", "48h", "7d", "30d"]);

/* The nine numbers. kind is how a threshold reads (count, percent, bfc);
   replay is true when the rows carry their own time, so the preview can
   replay the last 30 days; the others are a state read now, with no history.
   drop is whether drop_pct is offered. subject is the words for the number;
   draft is what an agent drafts when it fires. */
var METRICS = Object.freeze({
  stock_at_reorder: Object.freeze({
    label: "Items at their reorder point", kind: "count", windows: Object.freeze(["now"]), replay: false, drop: false,
    max: 100000, subject: "the number of items at or below their reorder point", draft: "a reorder",
    source: "inventory_items: the member's items with a reorder point entered whose quantity_on_hand is at or below it"
  }),
  blog_arrivals: Object.freeze({
    label: "Arrivals from your blog links", kind: "count", windows: TIMED, replay: true, drop: true,
    max: 100000, subject: "the number of arrivals from your blog links in {w}", draft: "an audit",
    source: "engine_visits on the refs of the member's own tracked posts (content_library, blogRefToken), created in the window"
  }),
  tasks_failed: Object.freeze({
    label: "Agent runs that failed", kind: "count", windows: TIMED, replay: true, drop: false,
    max: 100000, subject: "the number of your agent runs that failed in {w}", draft: "a look at what failed",
    source: "ai_tasks: the member's rows with status failed, created in the window"
  }),
  proposals_pending: Object.freeze({
    label: "Proposals waiting for approval", kind: "count", windows: Object.freeze(["now", "24h", "48h", "7d"]), replay: false, drop: false,
    max: 100000, subject: "the number of proposals waiting for your approval", subjectAged: "the number of proposals waiting longer than {w} for your approval",
    draft: "a summary of what is waiting",
    source: "agent_proposals: the member's rows with status pending, created before the window began (now: all of them)"
  }),
  lead_scores: Object.freeze({
    label: "High-intent leads (owner only)", kind: "count", windows: TIMED, replay: true, drop: true, ownerOnly: true,
    max: 100000, subject: "the number of high-intent leads (score 70 or more) found in {w}", draft: "a follow-up plan",
    source: "bsky_leads (the owner's Lead Radar, which has no per-member owner): rows with intent_score 70 or more, created in the window"
  }),
  bfc_balance: Object.freeze({
    label: "BizCash balance", kind: "bfc", windows: Object.freeze(["now"]), replay: false, drop: false,
    max: 1000000000, subject: "your BizCash balance", draft: "a BizCash plan",
    source: "user_wallets.balance for the member"
  }),
  schedule_failures: Object.freeze({
    label: "Schedules whose last run failed", kind: "count", windows: Object.freeze(["now"]), replay: false, drop: false,
    max: 1000, subject: "the number of your schedules whose last run failed", draft: "a fix for the failing schedules",
    source: "agent_schedules: the member's rows with consecutive_failures of 1 or more"
  }),
  spend_vs_cap: Object.freeze({
    label: "AI spend against your monthly cap", kind: "percent", windows: Object.freeze(["now"]), replay: false, drop: false,
    max: 1000, subject: "this month's AI spend against your monthly cap", draft: "a plan to spend less",
    source: "model_calls this UTC month for the member, priced as the monthly cap prices them, as a percent of MODEL_SPEND_MONTHLY_LIMIT_USD_PER_USER"
  }),
  helpful_share: Object.freeze({
    label: "Helpful share of an agent's ratings", kind: "percent", windows: Object.freeze(["30d"]), replay: false, drop: false,
    needsAgent: true, max: 100, subject: "the Helpful share of your ratings of the {a} agent in 30 days (with 5 or more ratings)",
    draft: "changes to try",
    source: "agent_feedback: the member's ratings of that agent, scored by lib/learningLoop.js scoreFrom (5 ratings minimum, 30 days)"
  })
});
var METRIC_KEYS = Object.freeze(Object.keys(METRICS));

var COMPARATORS = Object.freeze({
  lt: Object.freeze({ label: "is below" }),
  lte: Object.freeze({ label: "is at most" }),
  gt: Object.freeze({ label: "is above" }),
  gte: Object.freeze({ label: "is at least" }),
  drop_pct: Object.freeze({ label: "drops by at least (percent)" })
});
var COMPARATOR_KEYS = Object.freeze(Object.keys(COMPARATORS));

var ACTIONS = Object.freeze({
  raise_alert: Object.freeze({ label: "Raise an alert", needsAgent: false }),
  draft_task: Object.freeze({ label: "An agent drafts a task for you to run", needsAgent: true }),
  pause_schedule: Object.freeze({ label: "Pause an agent's schedules (and alert)", needsAgent: true })
});
var ACTION_KEYS = Object.freeze(Object.keys(ACTIONS));

var COOLDOWNS = Object.freeze([6, 12, 24, 48, 72, 168]);

var LIMITS = Object.freeze({
  NAME_MAX: 60,
  MAX_TRIGGERS: 10,
  COOLDOWN_MIN: 6,
  COOLDOWN_MAX: 168,
  COOLDOWN_DEFAULT: 24,
  DAILY_FIRINGS_DEFAULT: 10,
  DAILY_FIRINGS_MIN: 1,
  DAILY_FIRINGS_MAX: 20,
  DROP_MIN_PREVIOUS: 10,
  LEAD_HIGH_INTENT: 70,
  PREVIEW_DAYS: 30
});

var KEYS = Object.freeze(["name", "metric", "metric_agent", "comparator", "threshold", "window", "cooldown_hours", "action", "enabled"]);

function own(o, k) { return Object.prototype.hasOwnProperty.call(o, k); }
function isPlain(o) { return !!o && typeof o === "object" && !Array.isArray(o); }
function refuse(error, field) { return { ok: false, error: error, field: field }; }

/* The per-member cap of firings per UTC day: TRIGGERS_DAILY_FIRINGS, a whole
   number clamped to 1..20; absent, blank or not a whole number is 10. */
function dailyFiringsCap(env) {
  var raw = env && env.TRIGGERS_DAILY_FIRINGS;
  if (raw == null || String(raw).trim() === "") return LIMITS.DAILY_FIRINGS_DEFAULT;
  var n = Number(String(raw).trim());
  if (!Number.isInteger(n)) return LIMITS.DAILY_FIRINGS_DEFAULT;
  return Math.min(LIMITS.DAILY_FIRINGS_MAX, Math.max(LIMITS.DAILY_FIRINGS_MIN, n));
}

/* ENABLE_TRIGGERS exactly "true" runs the hourly pass; anything else is off. */
function triggersEnabled(env) {
  return !!env && env.ENABLE_TRIGGERS === "true";
}

function validateAction(a) {
  if (!isPlain(a)) return refuse("The action is an object with a kind.", "action");
  var extra = Object.keys(a).filter(function (k) { return k !== "kind" && k !== "agent"; });
  if (extra.length) return refuse("Unknown action field " + JSON.stringify(String(extra[0]).slice(0, 40)) + ". An action has kind and, for some kinds, agent.", "action." + String(extra[0]).slice(0, 40));
  if (typeof a.kind !== "string" || !own(ACTIONS, a.kind)) return refuse("The action is one of " + ACTION_KEYS.join(", ") + ".", "action.kind");
  if (ACTIONS[a.kind].needsAgent) {
    if (typeof a.agent !== "string" || AGENTS.indexOf(a.agent) === -1) return refuse("This action names one of your agents.", "action.agent");
    return { ok: true, action: { kind: a.kind, agent: a.agent } };
  }
  if (own(a, "agent")) return refuse("An alert names no agent.", "action.agent");
  return { ok: true, action: { kind: a.kind } };
}

/* A trigger's fields from a request body, against the closed lists. base is
   the stored trigger for an edit (a partial body), null for a new one. ctx.owner
   is true only for the owner's account (lead scores are the owner's alone). */
function validateTrigger(body, base, ctx) {
  if (!isPlain(body)) return refuse("The request must be a JSON object.", "body");
  var extra = Object.keys(body).filter(function (k) { return KEYS.indexOf(k) === -1; });
  if (extra.length) return refuse("Unknown field " + JSON.stringify(String(extra[0]).slice(0, 40)) + ". A trigger has " + KEYS.join(", ") + ".", String(extra[0]).slice(0, 40));
  function pick(k, dflt) { return body[k] !== undefined ? body[k] : (base && base[k] !== undefined ? base[k] : dflt); }
  var t = {
    name: pick("name"),
    metric: pick("metric"),
    metric_agent: pick("metric_agent", null),
    comparator: pick("comparator"),
    threshold: pick("threshold"),
    window: pick("window"),
    cooldown_hours: pick("cooldown_hours", LIMITS.COOLDOWN_DEFAULT),
    action: pick("action"),
    enabled: pick("enabled", true)
  };
  var named = gateRules.validateName(t.name);
  if (!named.ok) return refuse(named.error, "name");
  if (typeof t.metric !== "string" || !own(METRICS, t.metric)) return refuse("The metric is one of " + METRIC_KEYS.join(", ") + ".", "metric");
  var m = METRICS[t.metric];
  if (m.ownerOnly && !(ctx && ctx.owner === true)) return refuse("Lead scores are the owner's Lead Radar only: leads have no per-member owner, so this metric is not offered.", "metric");
  if (m.needsAgent) {
    if (typeof t.metric_agent !== "string" || AGENTS.indexOf(t.metric_agent) === -1) return refuse("This metric names one of your agents.", "metric_agent");
  } else if (t.metric_agent !== null && t.metric_agent !== undefined) {
    return refuse("This metric names no agent.", "metric_agent");
  }
  if (typeof t.comparator !== "string" || !own(COMPARATORS, t.comparator)) return refuse("The comparator is one of " + COMPARATOR_KEYS.join(", ") + ".", "comparator");
  if (t.comparator === "drop_pct" && !m.drop) return refuse("A drop is measured only for arrivals and high-intent leads, which have a history.", "comparator");
  if (typeof t.window !== "string" || m.windows.indexOf(t.window) === -1) return refuse("For this metric the window is one of " + m.windows.join(", ") + ".", "window");
  if (t.comparator === "drop_pct" && t.window === "now") return refuse("A drop needs a window to compare against the one before.", "window");
  var th = t.threshold;
  if (typeof th !== "number" || !isFinite(th)) return refuse("The threshold is a number.", "threshold");
  if (t.comparator === "drop_pct") {
    if (!Number.isInteger(th) || th < 1 || th > 100) return refuse("A drop is a whole percent from 1 to 100.", "threshold");
  } else {
    if (th < 0 || th > m.max) return refuse("The threshold is from 0 to " + m.max + ".", "threshold");
    if (m.kind !== "bfc" && !Number.isInteger(th)) return refuse("The threshold is a whole number.", "threshold");
  }
  var cd = t.cooldown_hours;
  if (!Number.isInteger(cd) || cd < LIMITS.COOLDOWN_MIN || cd > LIMITS.COOLDOWN_MAX) return refuse("The cooldown is a whole number of hours from 6 to 168.", "cooldown_hours");
  var act = validateAction(t.action);
  if (!act.ok) return act;
  if (typeof t.enabled !== "boolean") return refuse("enabled is true or false.", "enabled");
  return {
    ok: true,
    value: {
      name: named.name, metric: t.metric, metric_agent: m.needsAgent ? t.metric_agent : null, comparator: t.comparator,
      threshold: th, window: t.window, cooldown_hours: cd, action: act.action, enabled: t.enabled
    }
  };
}

/* The percent fall from previous to current, or null when the window before
   held fewer than DROP_MIN_PREVIOUS (too few to call a fall). */
function dropPct(current, previous) {
  if (typeof current !== "number" || typeof previous !== "number" || !isFinite(current) || !isFinite(previous)) return null;
  if (previous < LIMITS.DROP_MIN_PREVIOUS) return null;
  return Math.max(0, Math.round((previous - current) / previous * 100));
}

/* Whether the number crosses the line: true, false, or null when it cannot be
   judged (no number, or too few before a drop). null never fires. */
function crosses(trigger, value, previous) {
  if (trigger.comparator === "drop_pct") {
    var d = dropPct(value, previous);
    return d === null ? null : d >= trigger.threshold;
  }
  if (typeof value !== "number" || !isFinite(value)) return null;
  var th = trigger.threshold;
  switch (trigger.comparator) {
    case "lt": return value < th;
    case "lte": return value <= th;
    case "gt": return value > th;
    case "gte": return value >= th;
    default: return null;
  }
}

/* The cooldown runs from the last attempt that reached the gates (fired,
   failed or blocked), so a blocked trigger is not re-tried every hour. */
function cooledDown(trigger, nowMs) {
  var last = trigger.last_attempt_at ? Date.parse(trigger.last_attempt_at) : NaN;
  if (!isFinite(last)) return true;
  return nowMs - last >= trigger.cooldown_hours * HOUR_MS;
}

/* What the hourly pass does with one trigger whose number was read:
     quiet      the line is not crossed (or cannot be judged): nothing recorded
     cooldown   crossed, inside its cooldown: nothing recorded
     daily_cap  crossed, but the member's firings today reached the cap
     gate       crossed and allowed this far: ask the gates
   firedToday is the member's firings (fired or action_failed) this UTC day. */
function plan(trigger, value, previous, nowMs, firedToday, cap) {
  if (crosses(trigger, value, previous) !== true) return "quiet";
  if (!cooledDown(trigger, nowMs)) return "cooldown";
  if (firedToday >= cap) return "daily_cap";
  return "gate";
}

/* ── words ──────────────────────────────────────────────────────────────── */
function agentName(a) { return own(AGENT_NAMES, a) ? AGENT_NAMES[a] : String(a); }
function fill(s, t) { return s.replace("{w}", WINDOWS[t.window] ? WINDOWS[t.window].label : t.window).replace("{a}", agentName(t.metric_agent)); }
function amount(kind, n) {
  if (kind === "percent") return n + "%";
  if (kind === "bfc") return n + " BFC";
  return String(n);
}
function condition(t) {
  var m = METRICS[t.metric];
  if (t.metric === "stock_at_reorder" && ((t.comparator === "gt" && t.threshold === 0) || (t.comparator === "gte" && t.threshold === 1))) {
    return "stock of any item drops to its reorder point";
  }
  var subject = fill(t.metric === "proposals_pending" && t.window !== "now" ? m.subjectAged : m.subject, t);
  if (t.comparator === "drop_pct") {
    return subject + " drops by " + t.threshold + "% or more against the " + WINDOWS[t.window].label + " before (with at least " + LIMITS.DROP_MIN_PREVIOUS + " before)";
  }
  var n = amount(m.kind, t.threshold);
  var words = { lt: "is below " + n, lte: "is at most " + n, gt: "is above " + n, gte: "is at least " + n };
  return subject + " " + words[t.comparator];
}
function consequence(t) {
  var a = t.action || {};
  if (a.kind === "draft_task") return "the " + agentName(a.agent) + " agent drafts " + METRICS[t.metric].draft;
  if (a.kind === "pause_schedule") return "the " + agentName(a.agent) + " agent's schedules are paused and you get an alert";
  return "you get an alert";
}
function cooldownWords(h) {
  if (h === 24) return "At most once a day.";
  if (h === 168) return "At most once a week.";
  if (h % 24 === 0) return "At most once every " + (h / 24) + " days.";
  return "At most once every " + h + " hours.";
}
/* The plain-English sentence for a valid trigger. */
function summarize(t) {
  if (!t || !own(METRICS, t.metric)) return "";
  return "When " + condition(t) + ", " + consequence(t) + ". " + cooldownWords(t.cooldown_hours);
}

/* The alert a firing writes: fixed words, the member's own trigger name and
   the number read. */
function alertText(t, value) {
  var m = METRICS[t.metric];
  return {
    title: "Trigger: " + t.name,
    message: summarize(t) + " Now: " + m.label.toLowerCase() + " is " + amount(m.kind, value) + "."
  };
}

/* The saved prompt a draft_task firing files. Fixed words only, plus the
   trigger's name and the number read. It always asks for approval, so when the
   member runs it, anything that would publish or send is held (G2). */
var DRAFT_PREFIX = "Trigger draft: ";
function draftName(t) { return DRAFT_PREFIX + t.name; }
function draftPrompt(t, value, atIso) {
  var m = METRICS[t.metric];
  return "My trigger \"" + t.name + "\" crossed its line at " + atIso + ": " + m.label.toLowerCase() + " was " + amount(m.kind, value) + ". " +
    "Draft " + m.draft + " for me to review. Prepare it for my approval; do not publish or send anything.";
}

/* ── the preview's replay ─────────────────────────────────────────────── */
/* The hourly pass's moments (:30 UTC each hour) in (now - days, now]. */
function passMoments(nowMs, days) {
  var out = [];
  var start = nowMs - days * DAY_MS;
  var d = new Date(nowMs);
  var t = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), d.getUTCHours(), 30);
  if (t > nowMs) t -= HOUR_MS;
  for (; t > start; t -= HOUR_MS) out.push(t);
  return out.reverse();
}
/* For a metric whose rows carry their time: at each past pass, count the rows
   in the window (and the window before, for a drop), apply the line and the
   cooldown, and list when it would have fired. The daily cap and the gates are
   not replayed (they depend on everything else that day). events are row
   times in ms. */
function replay(t, events, nowMs, days) {
  var w = WINDOWS[t.window].ms;
  var times = (events || []).filter(function (x) { return typeof x === "number" && isFinite(x); }).sort(function (a, b) { return a - b; });
  function countIn(from, to) {
    var n = 0;
    for (var i = 0; i < times.length; i++) { if (times[i] > from && times[i] <= to) n++; }
    return n;
  }
  var fired = [];
  var last = null;
  passMoments(nowMs, days || LIMITS.PREVIEW_DAYS).forEach(function (at) {
    var value = countIn(at - w, at);
    var previous = t.comparator === "drop_pct" ? countIn(at - 2 * w, at - w) : null;
    if (crosses(t, value, previous) !== true) return;
    if (last !== null && at - last < t.cooldown_hours * HOUR_MS) return;
    last = at;
    fired.push(new Date(at).toISOString());
  });
  return fired;
}

/* ── the six ready-made templates (design section 2.4) ─────────────────── */
var TEMPLATES = Object.freeze([
  Object.freeze({ key: "stock_reorder", title: "Stock at reorder point",
    body: Object.freeze({ name: "Stock at reorder point", metric: "stock_at_reorder", comparator: "gt", threshold: 0, window: "now", cooldown_hours: 24, action: Object.freeze({ kind: "draft_task", agent: "store" }), enabled: true }) }),
  Object.freeze({ key: "runs_failing", title: "Runs failing",
    body: Object.freeze({ name: "Runs failing", metric: "tasks_failed", comparator: "gte", threshold: 3, window: "24h", cooldown_hours: 24, action: Object.freeze({ kind: "raise_alert" }), enabled: true }) }),
  Object.freeze({ key: "proposals_waiting", title: "Proposals waiting",
    body: Object.freeze({ name: "Proposals waiting", metric: "proposals_pending", comparator: "gte", threshold: 5, window: "48h", cooldown_hours: 48, action: Object.freeze({ kind: "raise_alert" }), enabled: true }) }),
  Object.freeze({ key: "spend_near_cap", title: "Spend nearing your cap",
    body: Object.freeze({ name: "Spend nearing your cap", metric: "spend_vs_cap", comparator: "gte", threshold: 80, window: "now", cooldown_hours: 168, action: Object.freeze({ kind: "pause_schedule", agent: "content" }), enabled: true }) }),
  Object.freeze({ key: "arrivals_dropped", title: "Blog arrivals dropped",
    body: Object.freeze({ name: "Blog arrivals dropped", metric: "blog_arrivals", comparator: "drop_pct", threshold: 50, window: "7d", cooldown_hours: 168, action: Object.freeze({ kind: "draft_task", agent: "seo" }), enabled: true }) }),
  Object.freeze({ key: "helpful_fell", title: "Helpful share fell",
    body: Object.freeze({ name: "Helpful share fell", metric: "helpful_share", metric_agent: "content", comparator: "lt", threshold: 50, window: "30d", cooldown_hours: 168, action: Object.freeze({ kind: "raise_alert" }), enabled: true }) })
]);

/* The closed language, as the builder in HQ reads it. Lead scores are listed
   only for the owner. */
function language(ctx) {
  var owner = !!(ctx && ctx.owner === true);
  var metrics = {};
  METRIC_KEYS.forEach(function (k) {
    var m = METRICS[k];
    if (m.ownerOnly && !owner) return;
    metrics[k] = { label: m.label, kind: m.kind, windows: m.windows.slice(), replay: m.replay, drop: m.drop, needs_agent: !!m.needsAgent, max: m.max,
      subject: m.subject, subject_aged: m.subjectAged || null, draft: m.draft };
  });
  var windows = {};
  WINDOW_KEYS.forEach(function (k) { windows[k] = WINDOWS[k].label; });
  var comparators = {};
  COMPARATOR_KEYS.forEach(function (k) { comparators[k] = COMPARATORS[k].label; });
  var actions = {};
  ACTION_KEYS.forEach(function (k) { actions[k] = { label: ACTIONS[k].label, needs_agent: ACTIONS[k].needsAgent }; });
  var agents = {};
  AGENTS.forEach(function (a) { agents[a] = agentName(a); });
  return {
    metrics: metrics, comparators: comparators, windows: windows, actions: actions, agents: agents,
    cooldowns: COOLDOWNS.slice(), limits: Object.assign({}, LIMITS),
    templates: TEMPLATES.filter(function (tp) { return !METRICS[tp.body.metric].ownerOnly || owner; }).map(function (tp) {
      return { key: tp.key, title: tp.title, body: JSON.parse(JSON.stringify(tp.body)), summary: summarize(tp.body) };
    })
  };
}

/* The database row for a valid trigger (window is a reserved word in
   PostgreSQL, so the column is metric_window), and back. */
function toRow(v) {
  return { name: v.name, metric: v.metric, metric_agent: v.metric_agent, comparator: v.comparator, threshold: v.threshold,
    metric_window: v.window, cooldown_hours: v.cooldown_hours, action: v.action, enabled: v.enabled };
}
function fromRow(r) {
  return { id: r.id, name: r.name, metric: r.metric, metric_agent: r.metric_agent || null, comparator: r.comparator,
    threshold: Number(r.threshold), window: r.metric_window, cooldown_hours: r.cooldown_hours, action: r.action, enabled: r.enabled === true,
    last_value: r.last_value === null || r.last_value === undefined ? null : Number(r.last_value), last_checked_at: r.last_checked_at || null,
    last_attempt_at: r.last_attempt_at || null, last_fired_at: r.last_fired_at || null, created_at: r.created_at, updated_at: r.updated_at };
}

var FIRING_OUTCOMES = Object.freeze(["fired", "action_failed", "skipped_daily_cap", "blocked_by_gate"]);

module.exports = {
  AGENTS: AGENTS,
  AGENT_NAMES: AGENT_NAMES,
  METRICS: METRICS,
  METRIC_KEYS: METRIC_KEYS,
  COMPARATORS: COMPARATORS,
  COMPARATOR_KEYS: COMPARATOR_KEYS,
  WINDOWS: WINDOWS,
  WINDOW_KEYS: WINDOW_KEYS,
  ACTIONS: ACTIONS,
  ACTION_KEYS: ACTION_KEYS,
  COOLDOWNS: COOLDOWNS,
  LIMITS: LIMITS,
  KEYS: KEYS,
  TEMPLATES: TEMPLATES,
  FIRING_OUTCOMES: FIRING_OUTCOMES,
  DRAFT_PREFIX: DRAFT_PREFIX,
  dailyFiringsCap: dailyFiringsCap,
  triggersEnabled: triggersEnabled,
  validateTrigger: validateTrigger,
  dropPct: dropPct,
  crosses: crosses,
  cooledDown: cooledDown,
  plan: plan,
  summarize: summarize,
  alertText: alertText,
  draftName: draftName,
  draftPrompt: draftPrompt,
  passMoments: passMoments,
  replay: replay,
  language: language,
  toRow: toRow,
  fromRow: fromRow
};
