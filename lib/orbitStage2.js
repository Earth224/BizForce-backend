"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   lib/orbitStage2.js — the dashboard orbit's stage 2 (Nov 11 2026, orbit stage 2).

   Pure helpers, no I/O and no clock but the one they are handed, shared by
   server.js (PUT/GET /api/user/preferences weekly_goal, GET /api/dashboard/top
   goal, GET /api/dashboard/pulse) and scripts/checkOrbitStage2.js. The order
   status mapping is lib/storeSync.js orderStatusOf, beside the summary it fills.

     AGENT_PORTAL      every agent in config/brain.js PLATFORM_KNOWLEDGE.agents,
                       mapped to the orbit portal its work belongs to. The page
                       never carries a copy: the pulse answers each running
                       agent's portal and every event's portal_from/portal_to,
                       and the links the events can use (linkPairs).
     validateGoal      the weekly goal's closed shape and caps (migration 183's
                       CHECK, plus the time zone through gateRules.isTimeZone).
     weekStartMs       Monday 00:00 in a time zone, as a UTC instant, by Intl
                       (correct across daylight-saving changes).
     goal values       counted from rows the routes already read.
   ══════════════════════════════════════════════════════════════════════════ */

var gateRules = require("./gateRules");

/* ── the portals ── */
var PORTAL_KEYS = ["grow", "sell", "connect", "agents", "oracle"];

// One portal per agent. A check fails if an agent in the roster is missing here.
var AGENT_PORTAL = Object.freeze({
  sales: "sell", store: "sell", etsy: "sell", broker: "sell",
  social: "connect", email: "connect", community: "connect", influencer: "connect", publicist: "connect", reputation: "connect",
  seo: "grow", content: "grow", analytics: "grow", ads: "grow", rd: "grow", vertical_marketing: "grow",
  executive: "agents", operations: "agents", general: "agents"
});
function portalOfAgent(agent) {
  return Object.prototype.hasOwnProperty.call(AGENT_PORTAL, agent) ? AGENT_PORTAL[agent] : "agents";
}

// Where an executed proposal lands, by its channel (lib/gateRules.js channelFor).
var CHANNEL_PORTAL = Object.freeze({
  bluesky: "connect", mastodon: "connect", instagram: "connect", facebook: "connect", youtube: "connect", tiktok: "connect",
  email: "connect", blog: "grow", marketplace: "sell", store: "sell", calendar: "agents", agent: "agents", none: "agents"
});
function portalOfAction(actionType) {
  var ch = gateRules.channelFor(actionType);
  return Object.prototype.hasOwnProperty.call(CHANNEL_PORTAL, ch) ? CHANNEL_PORTAL[ch] : "agents";
}

// Executed proposals whose result has its own record, read as its own event (so one action is one spark, not two).
var RECORDED_ELSEWHERE = Object.freeze(["publish_social_post", "publish_mastodon_post", "publish_blog_post", "publish_youtube_video",
  "publish_tiktok_post", "publish_instagram_post", "publish_facebook_post", "update_store_item"]);

/* Each event type: where its spark starts and ends. "core" is the orbit's centre: an event the member made with no
   agent (a card lead, their own publish) travels from the core out to its portal. */
var EVENT_TYPES = Object.freeze({
  agent_run: "an agent run completed: from the agent's portal to Agents, where its result is",
  proposal_executed: "an approved proposal ran: from the agent's portal to the portal of its channel",
  store_change: "a store change was applied: from Agents to Sell",
  card_lead: "a card lead was received: from the core to Connect",
  post_published: "a post was published (Bluesky, Mastodon, Instagram, Facebook, TikTok, YouTube): from the core to Connect",
  article_published: "a blog article was published, here or on the member's own site: from the core to Grow"
});
function eventPortals(type, agent, actionType) {
  if (type === "agent_run") return { from: portalOfAgent(agent), to: "agents" };
  if (type === "proposal_executed") return { from: portalOfAgent(agent), to: portalOfAction(actionType) };
  if (type === "store_change") return { from: "agents", to: "sell" };
  if (type === "card_lead") return { from: "core", to: "connect" };
  if (type === "post_published") return { from: "core", to: "connect" };
  if (type === "article_published") return { from: "core", to: "grow" };
  return null;
}
// Every portal-to-portal pair an event can use, each once, as "a|b" with a before b in PORTAL_KEYS order.
function linkPairs() {
  var seen = {};
  function add(a, b) {
    if (a === b || PORTAL_KEYS.indexOf(a) === -1 || PORTAL_KEYS.indexOf(b) === -1) return;
    var k = PORTAL_KEYS.indexOf(a) < PORTAL_KEYS.indexOf(b) ? a + "|" + b : b + "|" + a;
    seen[k] = true;
  }
  var agentPortals = Object.keys(AGENT_PORTAL).map(function (k) { return AGENT_PORTAL[k]; });
  var channelPortals = Object.keys(CHANNEL_PORTAL).map(function (k) { return CHANNEL_PORTAL[k]; });
  agentPortals.forEach(function (p) {
    add(p, "agents");
    channelPortals.forEach(function (q) { add(p, q); });
  });
  add("agents", "sell");
  return Object.keys(seen).sort(function (x, y) {
    var a = x.split("|"), b = y.split("|");
    return (PORTAL_KEYS.indexOf(a[0]) - PORTAL_KEYS.indexOf(b[0])) || (PORTAL_KEYS.indexOf(a[1]) - PORTAL_KEYS.indexOf(b[1]));
  });
}

/* ── the weekly goal ── */
var GOAL_METRICS = Object.freeze({
  tracked_visits: { cap: 100000, whole: true, currency: false },
  store_orders: { cap: 100000, whole: true, currency: false },
  store_sales: { cap: 100000000, whole: false, currency: true },
  card_visits: { cap: 100000, whole: true, currency: false },
  marketplace_orders: { cap: 10000, whole: true, currency: false }
});
var GOAL_METRIC_KEYS = Object.keys(GOAL_METRICS);
var GOAL_KEYS = ["metric", "weekly_target", "currency", "time_zone"];
var STORE_METRICS = ["store_orders", "store_sales"];

function refuseGoal(error, field, metric) {
  var out = { error: error, field: field, valid_goal_metrics: GOAL_METRIC_KEYS.slice() };
  if (metric && GOAL_METRICS[metric]) out.cap = GOAL_METRICS[metric].cap;
  return out;
}
/* validateGoal(body) -> { value: { metric, weekly_target, currency, time_zone } } or { error, field, valid_goal_metrics, cap? }. */
function validateGoal(g) {
  if (!g || typeof g !== "object" || Array.isArray(g)) return refuseGoal("weekly_goal must be null or an object with metric, weekly_target, currency and time_zone.", "weekly_goal");
  var extra = Object.keys(g).filter(function (k) { return GOAL_KEYS.indexOf(k) === -1; });
  if (extra.length) return refuseGoal("Unknown field " + JSON.stringify(String(extra[0]).slice(0, 40)) + ". A weekly goal has metric, weekly_target, currency and time_zone.", String(extra[0]).slice(0, 40));
  if (typeof g.metric !== "string" || GOAL_METRIC_KEYS.indexOf(g.metric) === -1) return refuseGoal("metric must be one of " + GOAL_METRIC_KEYS.join(", ") + ".", "metric");
  var spec = GOAL_METRICS[g.metric];
  var t = g.weekly_target;
  if (typeof t !== "number" || !isFinite(t)) return refuseGoal("weekly_target must be a number.", "weekly_target", g.metric);
  if (spec.whole) {
    if (!Number.isInteger(t) || t < 1 || t > spec.cap) return refuseGoal("weekly_target must be a whole number from 1 to " + spec.cap + ".", "weekly_target", g.metric);
  } else if (!(t > 0) || t > spec.cap || Math.round(t * 100) / 100 !== t) {
    return refuseGoal("weekly_target must be more than 0 and at most " + spec.cap + ", in at most two decimal places.", "weekly_target", g.metric);
  }
  var currency = null;
  if (spec.currency) {
    if (typeof g.currency !== "string" || !/^[A-Z]{3}$/.test(g.currency)) return refuseGoal("A store sales goal needs its currency, a three-letter code such as USD.", "currency", g.metric);
    currency = g.currency;
  } else if (g.currency !== undefined && g.currency !== null) {
    return refuseGoal("Only a store sales goal has a currency.", "currency", g.metric);
  }
  if (!gateRules.isTimeZone(g.time_zone)) return refuseGoal("The time zone is UTC or a name such as America/New_York.", "time_zone", g.metric);
  return { value: { metric: g.metric, weekly_target: t, currency: currency, time_zone: g.time_zone } };
}
// The goal as a preferences row stores it, or null.
function goalOfRow(row) {
  if (!row || !row.goal_metric || GOAL_METRIC_KEYS.indexOf(row.goal_metric) === -1) return null;
  var t = Number(row.goal_weekly_target);
  if (!isFinite(t)) return null;
  return { metric: row.goal_metric, weekly_target: t, currency: row.goal_currency || null,
    time_zone: gateRules.isTimeZone(row.goal_time_zone) ? row.goal_time_zone : "UTC", set_at: row.goal_set_at || null };
}

/* ── Monday 00:00 in a time zone ── */
var DAY_MS = 86400000;
var WEEKDAY = { Mon: 0, Tue: 1, Wed: 2, Thu: 3, Fri: 4, Sat: 5, Sun: 6 };
// The wall clock in zone at the instant ms.
function zoneParts(ms, zone) {
  var parts = new Intl.DateTimeFormat("en-US", { timeZone: zone, year: "numeric", month: "numeric", day: "numeric",
    hour: "numeric", minute: "numeric", second: "numeric", weekday: "short", hourCycle: "h23" }).formatToParts(new Date(ms));
  var o = {};
  parts.forEach(function (p) { o[p.type] = p.value; });
  return { y: Number(o.year), m: Number(o.month), d: Number(o.day), h: Number(o.hour) % 24, mi: Number(o.minute), s: Number(o.second), wd: WEEKDAY[o.weekday] };
}
// How far zone's wall clock is ahead of UTC at the instant ms.
function zoneOffsetMs(ms, zone) {
  var p = zoneParts(ms, zone);
  return Date.UTC(p.y, p.m - 1, p.d, p.h, p.mi, p.s) - (ms - (((ms % 1000) + 1000) % 1000));
}
// The first instant of the local day y-m-d in zone (its midnight, or the first hour after a skipped midnight).
function localDayStartMs(y, m, d, zone) {
  var wall = Date.UTC(y, m - 1, d);
  var t = wall - zoneOffsetMs(wall, zone);
  t = wall - zoneOffsetMs(t, zone);
  for (var k = 0; k < 4; k++) {
    var p = zoneParts(t, zone);
    if (Date.UTC(p.y, p.m - 1, p.d) < wall) { t += 3600000 - (p.mi * 60000 + p.s * 1000); continue; }   // still the day before: a skipped midnight
    if (Date.UTC(p.y, p.m - 1, p.d) > wall) { t -= 3600000; continue; }
    if (p.h !== 0 || p.mi !== 0) {
      var back = t - (p.h * 3600000 + p.mi * 60000 + p.s * 1000);
      var q = zoneParts(back, zone);
      if (Date.UTC(q.y, q.m - 1, q.d) === wall) { t = back; continue; }
    }
    break;
  }
  return t;
}
/* Monday 00:00 of the week holding nowMs, in zone, as a UTC instant (ms). An unknown zone is UTC. */
function weekStartMs(zone, nowMs) {
  var z = gateRules.isTimeZone(zone) ? zone : "UTC";
  var p = zoneParts(nowMs, z);
  var monday = new Date(Date.UTC(p.y, p.m - 1, p.d) - p.wd * DAY_MS);
  return localDayStartMs(monday.getUTCFullYear(), monday.getUTCMonth() + 1, monday.getUTCDate(), z);
}

/* ── goal values, from rows the routes read ── */
function countSince(times, fromMs) {
  return times.filter(function (t) { var x = Date.parse(t); return isFinite(x) && x >= fromMs; }).length;
}
// Active orders since fromMs: { orders, sales (in the currency, 2 dp), not_counted: [{ currency, orders, total }] }.
function storeWeek(orders, fromMs, currency) {
  var cents = 0, count = 0, other = {};
  orders.forEach(function (o) {
    if (!o || o.status !== "active") return;
    var at = Date.parse(o.ordered_at);
    if (!isFinite(at) || at < fromMs) return;
    count++;
    var amount = Number(o.total);
    var c = typeof o.currency === "string" ? o.currency : null;
    if (currency && c === currency) { if (isFinite(amount)) cents += Math.round(amount * 100); return; }
    var k = c === null ? "" : c;
    other[k] = other[k] || { currency: c, orders: 0, cents: 0 };
    other[k].orders++;
    if (isFinite(amount)) other[k].cents += Math.round(amount * 100);
  });
  return { orders: count, sales: cents / 100,
    not_counted: Object.keys(other).sort().map(function (k) { return { currency: other[k].currency, orders: other[k].orders, total: other[k].cents / 100 }; }) };
}
// Card visits by rule A: every UTC day from the one holding the week's start.
function cardDayFrom(fromMs) { return new Date(fromMs).toISOString().slice(0, 10); }
function cardVisitsSince(rows, fromMs) {
  var from = cardDayFrom(fromMs), n = 0;
  rows.forEach(function (r) {
    var v = Number(r && r.views);
    if (!isFinite(v) || v <= 0) return;
    if (String(r.day || "").slice(0, 10) >= from) n += Math.floor(v);
  });
  return n;
}
var CARD_VISITS_NOTE = "Card visits are counted by UTC day, so this week's count starts with the UTC day your week begins in.";

module.exports = {
  PORTAL_KEYS: PORTAL_KEYS,
  AGENT_PORTAL: AGENT_PORTAL,
  portalOfAgent: portalOfAgent,
  CHANNEL_PORTAL: CHANNEL_PORTAL,
  portalOfAction: portalOfAction,
  RECORDED_ELSEWHERE: RECORDED_ELSEWHERE,
  EVENT_TYPES: EVENT_TYPES,
  eventPortals: eventPortals,
  linkPairs: linkPairs,
  GOAL_METRICS: GOAL_METRICS,
  GOAL_METRIC_KEYS: GOAL_METRIC_KEYS,
  STORE_METRICS: STORE_METRICS,
  validateGoal: validateGoal,
  goalOfRow: goalOfRow,
  zoneParts: zoneParts,
  zoneOffsetMs: zoneOffsetMs,
  localDayStartMs: localDayStartMs,
  weekStartMs: weekStartMs,
  countSince: countSince,
  storeWeek: storeWeek,
  cardDayFrom: cardDayFrom,
  cardVisitsSince: cardVisitsSince,
  CARD_VISITS_NOTE: CARD_VISITS_NOTE
};
