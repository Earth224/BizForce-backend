/* ═══════════════════════════════════════════════════════════════════════════
   lib/gateRules.js — the member gate rule language (intelligence layer B2,
   design section 1.3)

   WHAT A MEMBER GATE IS. A rule a member writes for their own account: "Act
   only if <condition>". It is checked AFTER the platform gates, and only when
   they have all let the action through. If its condition does not hold, the
   action is blocked, and the member's own gate name is the reason. It can
   never let through anything a platform gate refused: it is never asked then.

   CLOSED. A rule is a small tree of plain JSON, and nothing in it is ever run:
     - a condition names a KNOWN FIELD (FIELDS), a COMPARATOR from a fixed set
       (COMPARATORS) that the field's type allows, and a value of that type;
     - conditions combine with AND ({ all: [...] }), OR ({ any: [...] }) and
       NOT ({ not: ... });
     - the tree is at most LIMITS.MAX_DEPTH deep and holds at most
       LIMITS.MAX_LEAVES conditions; a list value holds at most LIMITS.MAX_LIST;
     - every string value is one of the field's fixed values. No free text is
       evaluated, no code, no regular expression, no lookup: a value that is not
       on the field's list is refused.
   Unknown keys anywhere are refused, so nothing rides along unchecked.

   THE FIELDS, per action. A scope names which actions the gate is asked about;
   a field is allowed only in a scope whose actions always know it
   (SCOPE_FIELDS), so a live check never meets a missing fact.

   PURE. No database, no clock, no network: the time is handed in (factsAt
   takes the moment and the member's time zone), so the same rule and the same
   facts always give the same answer.
   ═══════════════════════════════════════════════════════════════════════════ */
"use strict";

/* The actions a member gate is asked about, and "any" for all of them. */
var SCOPES = Object.freeze(["proposal_approve", "proposal_auto_execute", "schedule_run", "any"]);

var SCOPE_LABELS = Object.freeze({
  proposal_approve:      "Carry out an approved proposal",
  proposal_auto_execute: "Act automatically",
  schedule_run:          "Run a schedule",
  any:                   "Go ahead"
});

/* The roster (equal to server.js AGENT_SYSTEM_PROMPTS; checkGates compares). */
var AGENTS = Object.freeze(["seo", "sales", "content", "ads", "reputation", "analytics", "email", "community", "influencer",
  "operations", "executive", "social", "etsy", "store", "broker", "publicist", "rd", "vertical_marketing"]);

/* What the action is: a proposal's action type, or "agent_task" for a scheduled run. */
var ACTION_TYPES = Object.freeze(["publish_social_post", "publish_blog_post", "publish_listing", "update_listing",
  "send_email_sequence", "update_bluesky_profile", "reply_bluesky_mention", "publish_mastodon_post", "send_mailbox_reply", "create_calendar_event", "agent_task"]);

/* Where it lands. Derived from the action type (channelFor), never typed in. */
var CHANNELS = Object.freeze(["bluesky", "mastodon", "blog", "marketplace", "email", "calendar", "agent", "none"]);

var WEEKDAYS = Object.freeze(["mon", "tue", "wed", "thu", "fri", "sat", "sun"]);
var WEEKDAY_NAMES = Object.freeze({ mon: "Monday", tue: "Tuesday", wed: "Wednesday", thu: "Thursday", fri: "Friday", sat: "Saturday", sun: "Sunday" });

var FIELDS = Object.freeze({
  action_type: Object.freeze({ type: "enum",   values: ACTION_TYPES, label: "the action" }),
  agent:       Object.freeze({ type: "enum",   values: AGENTS,       label: "the agent" }),
  weekday:     Object.freeze({ type: "enum",   values: WEEKDAYS,     label: "the weekday" }),
  hour:        Object.freeze({ type: "int",    min: 0, max: 23,      label: "the hour (your time zone)" }),
  approved:    Object.freeze({ type: "bool",                         label: "approved by you" }),
  channel:     Object.freeze({ type: "enum",   values: CHANNELS,     label: "the channel" }),
  amount:      Object.freeze({ type: "number", min: 0, max: 1000000000, label: "the amount" })
});

/* Which comparators each type allows. between is inclusive: [low, high]. */
var COMPARATORS = Object.freeze({
  eq:      Object.freeze({ label: "is",                types: ["enum", "int", "number", "bool"] }),
  neq:     Object.freeze({ label: "is not",            types: ["enum", "int", "number"] }),
  in:      Object.freeze({ label: "is one of",         types: ["enum", "int"] }),
  not_in:  Object.freeze({ label: "is none of",        types: ["enum", "int"] }),
  lt:      Object.freeze({ label: "is below",          types: ["int", "number"] }),
  lte:     Object.freeze({ label: "is at most",        types: ["int", "number"] }),
  gt:      Object.freeze({ label: "is above",          types: ["int", "number"] }),
  gte:     Object.freeze({ label: "is at least",       types: ["int", "number"] }),
  between: Object.freeze({ label: "is between",        types: ["int", "number"] })
});

/* The facts each scope's actions always carry. "any" carries only what every action has. */
var SCOPE_FIELDS = Object.freeze({
  proposal_approve:      Object.freeze(["action_type", "agent", "weekday", "hour", "approved", "channel", "amount"]),
  proposal_auto_execute: Object.freeze(["action_type", "agent", "weekday", "hour", "approved", "channel", "amount"]),
  schedule_run:          Object.freeze(["action_type", "agent", "weekday", "hour", "approved", "channel"]),
  any:                   Object.freeze(["action_type", "agent", "weekday", "hour", "approved", "channel"])
});

var LIMITS = Object.freeze({ MAX_DEPTH: 4, MAX_LEAVES: 12, MAX_LIST: 10, NAME_MAX: 60, MAX_GATES: 20, MAX_BYTES: 4096 });

/* A gate's name is a label the member reads, never evaluated: letters, digits,
   spaces and a little punctuation, so it cannot carry markup or a script. */
var NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 .,'()&:-]{0,59}$/;

/* A time zone: "UTC" or an IANA name, and only one this runtime knows. */
var ZONE_RE = /^(UTC|[A-Za-z]+(\/[A-Za-z0-9_+-]+){1,2})$/;
function isTimeZone(zone) {
  if (typeof zone !== "string" || zone.length > 64 || !ZONE_RE.test(zone)) return false;
  try { new Intl.DateTimeFormat("en-US", { timeZone: zone }); return true; } catch (e) { return false; }
}

function own(o, k) { return Object.prototype.hasOwnProperty.call(o, k); }
function isPlain(o) { return !!o && typeof o === "object" && !Array.isArray(o); }
function refuse(error, path) { return { ok: false, error: error, path: path || "rule" }; }

/* One value of a field's type, or a refusal sentence. */
function valueError(spec, v) {
  if (spec.type === "enum") return typeof v === "string" && spec.values.indexOf(v) !== -1 ? null : "must be one of " + spec.values.join(", ");
  if (spec.type === "bool") return typeof v === "boolean" ? null : "must be true or false";
  if (spec.type === "int") return Number.isInteger(v) && v >= spec.min && v <= spec.max ? null : "must be a whole number from " + spec.min + " to " + spec.max;
  return typeof v === "number" && isFinite(v) && v >= spec.min && v <= spec.max ? null : "must be a number from " + spec.min + " to " + spec.max;
}

/* validateRule(rule, scope) -> { ok: true, rule } (a clean copy) or { ok: false, error, path }. */
function validateRule(rule, scope) {
  if (SCOPES.indexOf(scope) === -1) return refuse("The scope must be one of " + SCOPES.join(", ") + ".", "scope");
  var size;
  try { size = JSON.stringify(rule).length; } catch (e) { return refuse("The rule is not plain data."); }
  if (size > LIMITS.MAX_BYTES) return refuse("The rule is too large.");
  var allowed = SCOPE_FIELDS[scope];
  var leaves = 0;
  function walk(node, path, depth) {
    if (depth > LIMITS.MAX_DEPTH) return refuse("The rule is nested too deeply: at most " + LIMITS.MAX_DEPTH + " levels.", path);
    if (!isPlain(node)) return refuse("Each part of the rule must be a condition or a group.", path);
    var keys = Object.keys(node);
    if (keys.length === 1 && (keys[0] === "all" || keys[0] === "any")) {
      var list = node[keys[0]];
      if (!Array.isArray(list) || list.length < 1 || list.length > LIMITS.MAX_LEAVES) {
        return refuse("A group holds 1 to " + LIMITS.MAX_LEAVES + " parts.", path + "." + keys[0]);
      }
      var out = [];
      for (var i = 0; i < list.length; i++) {
        var c = walk(list[i], path + "." + keys[0] + "[" + i + "]", depth + 1);
        if (!c.ok) return c;
        out.push(c.rule);
      }
      var g = {}; g[keys[0]] = out;
      return { ok: true, rule: g };
    }
    if (keys.length === 1 && keys[0] === "not") {
      var inner = walk(node.not, path + ".not", depth + 1);
      return inner.ok ? { ok: true, rule: { not: inner.rule } } : inner;
    }
    // A condition: exactly field, op and value.
    if (keys.length !== 3 || !own(node, "field") || !own(node, "op") || !own(node, "value")) {
      return refuse("A condition has exactly a field, a comparator and a value.", path);
    }
    if (typeof node.field !== "string" || !own(FIELDS, node.field)) return refuse("Unknown field. The fields are " + Object.keys(FIELDS).join(", ") + ".", path + ".field");
    if (allowed.indexOf(node.field) === -1) return refuse("That field is not known for this scope.", path + ".field");
    if (typeof node.op !== "string" || !own(COMPARATORS, node.op)) return refuse("Unknown comparator. The comparators are " + Object.keys(COMPARATORS).join(", ") + ".", path + ".op");
    var spec = FIELDS[node.field];
    if (COMPARATORS[node.op].types.indexOf(spec.type) === -1) return refuse("That comparator does not fit that field.", path + ".op");
    leaves++;
    if (leaves > LIMITS.MAX_LEAVES) return refuse("The rule has too many conditions: at most " + LIMITS.MAX_LEAVES + ".", path);
    var v = node.value, err;
    if (node.op === "in" || node.op === "not_in") {
      if (!Array.isArray(v) || v.length < 1 || v.length > LIMITS.MAX_LIST) return refuse("A list holds 1 to " + LIMITS.MAX_LIST + " values.", path + ".value");
      for (var j = 0; j < v.length; j++) {
        err = valueError(spec, v[j]);
        if (err) return refuse("Each value " + err + ".", path + ".value[" + j + "]");
        if (v.indexOf(v[j]) !== j) return refuse("A list names each value once.", path + ".value[" + j + "]");
      }
      return { ok: true, rule: { field: node.field, op: node.op, value: v.slice() } };
    }
    if (node.op === "between") {
      if (!Array.isArray(v) || v.length !== 2) return refuse("Between takes two values, low then high.", path + ".value");
      err = valueError(spec, v[0]) || valueError(spec, v[1]);
      if (err) return refuse("Each value " + err + ".", path + ".value");
      if (v[0] > v[1]) return refuse("Between takes the low value first.", path + ".value");
      return { ok: true, rule: { field: node.field, op: node.op, value: [v[0], v[1]] } };
    }
    err = valueError(spec, v);
    if (err) return refuse("The value " + err + ".", path + ".value");
    return { ok: true, rule: { field: node.field, op: node.op, value: v } };
  }
  return walk(rule, "rule", 1);
}

/* A gate's name, checked: { ok, name } or { ok: false, error }. */
function validateName(name) {
  var s = typeof name === "string" ? name.trim() : "";
  if (!NAME_RE.test(s)) return { ok: false, error: "The name is 1 to " + LIMITS.NAME_MAX + " letters, digits, spaces or . , ' ( ) & : -, starting with a letter or digit." };
  return { ok: true, name: s };
}

/* ── evaluation: three-valued, so a missing fact is never read as a yes ──── */
function leafHolds(node, facts) {
  if (!isPlain(facts) || !own(facts, node.field) || facts[node.field] === null || facts[node.field] === undefined) return null;
  var f = facts[node.field], v = node.value;
  switch (node.op) {
    case "eq": return f === v;
    case "neq": return f !== v;
    case "in": return v.indexOf(f) !== -1;
    case "not_in": return v.indexOf(f) === -1;
    case "lt": return f < v;
    case "lte": return f <= v;
    case "gt": return f > v;
    case "gte": return f >= v;
    case "between": return f >= v[0] && f <= v[1];
  }
  return null;
}
/* true, false, or null when a fact the rule needs is missing. */
function evaluateRule(node, facts) {
  if (own(node, "all")) {
    var unknown = false;
    for (var i = 0; i < node.all.length; i++) { var a = evaluateRule(node.all[i], facts); if (a === false) return false; if (a === null) unknown = true; }
    return unknown ? null : true;
  }
  if (own(node, "any")) {
    var unk = false;
    for (var j = 0; j < node.any.length; j++) { var b = evaluateRule(node.any[j], facts); if (b === true) return true; if (b === null) unk = true; }
    return unk ? null : false;
  }
  if (own(node, "not")) { var n = evaluateRule(node.not, facts); return n === null ? null : !n; }
  return leafHolds(node, facts);
}

/* The weekday and hour of a moment in a time zone. */
function factsAt(ms, zone) {
  var tz = isTimeZone(zone) ? zone : "UTC";
  var parts = new Intl.DateTimeFormat("en-US", { timeZone: tz, weekday: "short", hour: "numeric", hourCycle: "h23" }).formatToParts(new Date(ms));
  var out = { weekday: null, hour: null };
  parts.forEach(function (p) {
    if (p.type === "weekday") out.weekday = String(p.value).slice(0, 3).toLowerCase();
    if (p.type === "hour") out.hour = Number(p.value) % 24;
  });
  return out;
}

/* Where an action lands, from its type alone. */
function channelFor(actionType) {
  switch (actionType) {
    case "publish_social_post": case "update_bluesky_profile": case "reply_bluesky_mention": return "bluesky";
    case "publish_mastodon_post": return "mastodon";
    case "publish_blog_post": return "blog";
    case "publish_listing": case "update_listing": return "marketplace";
    case "send_email_sequence": case "send_mailbox_reply": return "email";
    case "create_calendar_event": return "calendar";
    case "agent_task": return "agent";
  }
  return "none";
}

/* A member gate's verdict on one action. "Act only if": the action goes ahead
   only when the condition is shown to hold; false, or a fact missing, blocks.
   A stored rule that no longer validates is not applied (it could not have
   been saved through the routes), and says so in `skipped`. */
function verdict(gate, scope, facts, ms) {
  var checked = gate && validateRule(gate.rule, gate.scope);
  if (!checked || !checked.ok || (gate.scope !== scope && gate.scope !== "any")) return { applies: false, skipped: !!(checked && !checked.ok) };
  var all = Object.assign({}, facts || {}, factsAt(ms, gate.time_zone));
  var holds = evaluateRule(checked.rule, all);
  return { applies: true, block: holds !== true, holds: holds };
}

/* The first of a member's gates that blocks this action, or null. Asked only
   after every platform gate has let it through (server.js). */
function firstBlock(gates, scope, facts, ms) {
  var list = Array.isArray(gates) ? gates : [];
  for (var i = 0; i < list.length; i++) {
    var g = list[i];
    if (!g || g.enabled === false) continue;
    var v = verdict(g, scope, facts, ms);
    if (v.applies && v.block) return { id: g.id || null, name: String(g.name || ""), summary: summarize(g.rule, g.scope) };
  }
  return null;
}

/* ── the plain-English summary ───────────────────────────────────────────── */
function hh(h) { return (h < 10 ? "0" : "") + h + ":00"; }
function words(list, join) { return list.length === 1 ? list[0] : list.slice(0, -1).join(", ") + " " + join + " " + list[list.length - 1]; }
function valueWords(field, v) {
  if (field === "weekday") return WEEKDAY_NAMES[v] || String(v);
  if (field === "hour") return hh(v);
  if (field === "channel" && v === "bluesky") return "Bluesky";
  return String(v).replace(/_/g, " ");
}
function leafWords(node) {
  var f = node.field, op = node.op, v = node.value;
  if (f === "approved") return v === true ? "approved" : "not approved";
  if (f === "weekday" && (op === "in" || op === "not_in")) {
    var sorted = WEEKDAYS.filter(function (d) { return v.indexOf(d) !== -1; });
    var phrase = sorted.join() === "mon,tue,wed,thu,fri" ? "on a weekday" : sorted.join() === "sat,sun" ? "at the weekend"
      : "on " + words(sorted.map(function (d) { return WEEKDAY_NAMES[d]; }), "or");
    return op === "in" ? phrase : "NOT " + phrase;
  }
  if (f === "weekday") return (op === "neq" ? "NOT " : "") + "on " + WEEKDAY_NAMES[v];
  if (f === "hour") {
    if (op === "lt") return "before " + hh(v);
    if (op === "lte") return "before " + (v + 1 > 23 ? "midnight" : hh(v + 1));
    if (op === "gt") return "after " + (v + 1 > 23 ? "23:59" : hh(v + 1));
    if (op === "gte") return "after " + hh(v);
    if (op === "between") return "between " + hh(v[0]) + " and " + (v[1] + 1 > 23 ? "midnight" : hh(v[1] + 1));
    if (op === "eq") return "in the " + hh(v) + " hour";
    if (op === "neq") return "NOT in the " + hh(v) + " hour";
    var hours = v.map(hh);
    return (op === "not_in" ? "NOT " : "") + "in the " + words(hours, "or") + " hour";
  }
  var label = FIELDS[f].label;
  if (op === "in" || op === "not_in") return label + " " + COMPARATORS[op].label + " " + words(v.map(function (x) { return valueWords(f, x); }), "or");
  if (op === "between") return label + " is between " + v[0] + " and " + v[1];
  return label + " " + COMPARATORS[op].label + " " + valueWords(f, v);
}
function nodeWords(node, top) {
  if (own(node, "all") || own(node, "any")) {
    var list = own(node, "all") ? node.all : node.any;
    var joined = list.map(function (c) { return nodeWords(c, false); }).join(own(node, "all") ? " AND " : " OR ");
    return top || list.length === 1 ? joined : "(" + joined + ")";
  }
  if (own(node, "not")) {
    var inner = nodeWords(node.not, false);
    return "NOT " + inner;
  }
  return leafWords(node);
}
/* "Go ahead only if approved AND on a weekday AND NOT after 22:00". From the
   rule's own fixed words only: nothing a member typed is in it. */
function summarize(rule, scope) {
  var checked = validateRule(rule, scope);
  if (!checked.ok) return "";
  return (SCOPE_LABELS[scope] || SCOPE_LABELS.any) + " only if " + nodeWords(checked.rule, true);
}

/* The language, for the rule builder (GET /api/member-gates/language). */
function language() {
  var fields = {};
  Object.keys(FIELDS).forEach(function (k) {
    var f = FIELDS[k];
    fields[k] = { type: f.type, label: f.label, values: f.values ? f.values.slice() : undefined, min: f.min, max: f.max,
      comparators: Object.keys(COMPARATORS).filter(function (c) { return COMPARATORS[c].types.indexOf(f.type) !== -1; }) };
  });
  var comps = {};
  Object.keys(COMPARATORS).forEach(function (c) { comps[c] = COMPARATORS[c].label; });
  var scopes = {};
  SCOPES.forEach(function (s) { scopes[s] = { label: SCOPE_LABELS[s], fields: SCOPE_FIELDS[s].slice() }; });
  return { fields: fields, comparators: comps, scopes: scopes, limits: Object.assign({}, LIMITS) };
}

module.exports = {
  SCOPES: SCOPES,
  SCOPE_LABELS: SCOPE_LABELS,
  SCOPE_FIELDS: SCOPE_FIELDS,
  AGENTS: AGENTS,
  ACTION_TYPES: ACTION_TYPES,
  CHANNELS: CHANNELS,
  WEEKDAYS: WEEKDAYS,
  FIELDS: FIELDS,
  COMPARATORS: COMPARATORS,
  LIMITS: LIMITS,
  isTimeZone: isTimeZone,
  validateRule: validateRule,
  validateName: validateName,
  evaluateRule: evaluateRule,
  factsAt: factsAt,
  channelFor: channelFor,
  verdict: verdict,
  firstBlock: firstBlock,
  summarize: summarize,
  language: language
};
