"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   lib/agentSignatures.js — the signature module under every agent's live
   panel, all eighteen, from the member's own rows.
   Pure: server.js reads (agentSignatureReads) and hands each read here as
   { rows } or { unavailable: reason }, with the functions it already trusts
   (measureStockAndMargin for the Store's arithmetic).

   ONLY GET /api/agents/<type>/live CARRIES A SIGNATURE. GET /api/agents/live
   sends signature: null for every agent, so its 24 KB budget and its reads are
   unchanged; each page asks for its own agent and gets the full module.

   A READ THAT FAILED IS { unavailable: reason }, NEVER ZERO, on its own field.
   A real empty (no items, no sequences, not connected) is said as such, with
   the place to start.

   ANALYTICS counts the member's runs without 'dry_run' (GET
   /api/activity/overview counts it; this does not). ARRIVALS are bl- refs
   only — blogRefToken over the member's own posts whose stored body carries
   the ref, the Arrivals Ledger's rule — so a Lead Radar ref (lr-) or another
   member's post is never counted here.

   SOCIAL never carries a secret: the connection is rebuilt from named fields
   (handle, status and times, the last error code), never the row.

   THE OTHER TWELVE (Executive, Content, Operations, R&D and the eight thin
   agents) read run rows and their own tables: an Executive assignment's run
   status comes from that run's own ai_tasks row; Content's checklist says only
   which profile lines are set; R&D reads no output, so no lead text; a thin
   agent with no run names the tool and button its page carries.

   SALES: the radar section exists only for the credential owner (bsky_leads
   has no user_id). YouTube is its own row, "kept 30 days, not combined", and
   is never added to the Bluesky and Mastodon total.
   ══════════════════════════════════════════════════════════════════════════ */

var DAY_MS = 86400000;
var WINDOW_DAYS = 30;
var LIST_CAP = 5;
var DRAFT_CAP = 3;
var SIGNATURE_TYPES = Object.freeze(["analytics", "store", "social", "email", "seo", "sales", "executive", "content", "operations", "rd",
  "ads", "reputation", "community", "influencer", "publicist", "broker", "etsy", "vertical_marketing"]);
var NO_TRACKED_LINK = "none of your posts carries a tracked link, so arrivals cannot be counted";
var NO_SCORE = "An audit stores its flags, not a score";
var YOUTUBE_NOTE = "kept 30 days, not combined";

/* What stops the sender, keyed by GET /api/email/sequences's booleans, in the
   words emailMarketingRefusal uses where it has them. */
var SENDER_BLOCKERS = Object.freeze({
  enabled: "Sequence mail is switched off on the server (ENABLE_EMAIL_SEQUENCES is not \"true\").",
  postal_address_set: "No postal address is set in lib/legal.js, and marketing mail must carry one.",
  webhook_secret_set: "RESEND_WEBHOOK_SECRET is not set, so bounce and complaint reports cannot be received and marketing mail is held.",
  daily_cap: "EMAIL_MARKETING_DAILY_CAP is not a whole number above 0, so there is no daily cap to send under."
});

function failed(read) {
  return !read || read.unavailable !== undefined || read.rows === undefined || read.rows === null;
}
function unavailableOf(read) {
  return { unavailable: (read && read.unavailable) || "not read" };
}
function cut(text, max) {
  var s = String(text == null ? "" : text).replace(/\s+/g, " ").trim();
  return s.length > max ? s.slice(0, max - 1) + "…" : s;
}
function dayStart(ms) {
  var d = new Date(ms);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
}
/* The window: 30 UTC days ending today, oldest first. */
function windowOf(now) {
  var last = dayStart(now.getTime());
  var first = last - (WINDOW_DAYS - 1) * DAY_MS;
  return { first: first, days_from: new Date(first).toISOString().slice(0, 10), since: new Date(first).toISOString() };
}
function perDay(times, win) {
  var out = [];
  for (var i = 0; i < WINDOW_DAYS; i++) out.push(0);
  times.forEach(function (t) {
    var ms = Date.parse(t);
    if (!Number.isFinite(ms)) return;
    var i = Math.floor((dayStart(ms) - win.first) / DAY_MS);
    if (i >= 0 && i < WINDOW_DAYS) out[i] += 1;
  });
  return out;
}
function sum(list) { return list.reduce(function (n, x) { return n + x; }, 0); }
function count(read) {
  if (failed(read)) return unavailableOf(read);
  return typeof read.rows === "number" ? read.rows : { unavailable: "the count did not come back" };
}

/* ── the member's blog arrivals: bl- refs of their tracked posts only ── */
function blogArrivals(read, win) {
  if (failed(read)) return unavailableOf(read);
  var tracked = {};
  (read.rows.posts || []).forEach(function (p) { if (p && p.tracked && /^bl-/.test(p.ref)) tracked[p.ref] = true; });
  var refs = Object.keys(tracked);
  if (!refs.length) return { none: NO_TRACKED_LINK, posts: (read.rows.posts || []).length };
  var times = (read.rows.visits || []).filter(function (v) {
    return v && typeof v.ref === "string" && v.ref.indexOf("bl-") === 0 && tracked[v.ref] === true;
  }).map(function (v) { return v.created_at; });
  var days = perDay(times, win);
  return { per_day: days, total: sum(days), tracked_posts: refs.length };
}

/* ── ANALYTICS ── */
function analytics(r, opts, win) {
  var out = { days_from: win.days_from, days: WINDOW_DAYS };
  if (failed(r.runs30)) {
    out.runs = unavailableOf(r.runs30);
  } else {
    var runs = r.runs30.rows.filter(function (t) { return t && t.status !== "dry_run"; });
    var byAgent = {};
    runs.forEach(function (t) { byAgent[t.agent_type] = (byAgent[t.agent_type] || 0) + 1; });
    var names = opts.names || {};
    out.runs = {
      per_day: perDay(runs.map(function (t) { return t.created_at; }), win),
      total: 0,
      by_agent: Object.keys(byAgent).sort(function (a, b) { return byAgent[b] - byAgent[a] || (a < b ? -1 : 1); }).map(function (k) {
        return { type: k, name: cut(String(names[k] || k).replace(/ Agent$/, ""), 24), runs: byAgent[k] };
      })
    };
    out.runs.total = sum(out.runs.per_day);
  }
  out.arrivals = blogArrivals(r.arrivals, win);
  return out;
}

/* ── STORE ── */
function marginBands(measured) {
  var bands = { loss: 0, under_20: 0, from_20_to_40: 0, from_40: 0, not_priced: 0 };
  (measured.stock || []).forEach(function (row) {
    var m = row.margin_percent;
    if (typeof m !== "number") bands.not_priced += 1;
    else if (m < 0) bands.loss += 1;
    else if (m < 20) bands.under_20 += 1;
    else if (m < 40) bands.from_20_to_40 += 1;
    else bands.from_40 += 1;
  });
  return bands;
}
function store(r, opts) {
  var out = {};
  if (failed(r.items)) out.stock = unavailableOf(r.items);
  else {
    var measured = opts.measureStock(r.items.rows, [], WINDOW_DAYS);
    out.stock = {
      items: measured.items,
      with_reorder_point: measured.items_with_a_reorder_point,
      low: { count: measured.items_at_or_below_reorder_point, named: measured.items_at_or_below_reorder_point_named.slice(0, LIST_CAP).map(function (n) { return cut(n, 40); }) },
      margin_bands: marginBands(measured)
    };
  }
  out.pending = typeof opts.pendingFor === "number" ? opts.pendingFor : { unavailable: (opts.pendingFor && opts.pendingFor.unavailable) || "not read" };
  if (failed(r.trades)) out.trades_30d = unavailableOf(r.trades);
  else {
    var t = { purchases: 0, purchases_bfc: 0, sales: 0, sales_bfc: 0 };
    (r.trades.rows.trades || []).forEach(function (x) {
      if (x.type === "purchase") { t.purchases += 1; t.purchases_bfc += Math.abs(x.bfc); }
      else if (x.type === "sale") { t.sales += 1; t.sales_bfc += Math.abs(x.bfc); }
    });
    out.trades_30d = t;
  }
  return out;
}

/* ── SOCIAL ── */
var DRAFT_LABELS = { pending_approval: "Waiting for approval", published: "Published", refused: "Refused", failed: "Failed", other: "Saved" };
function draftState(d, proposalStatus) {
  if (d.status === "published") return "published";
  if (d.status === "publish_failed") return "failed";
  if (d.status === "pending_approval") return proposalStatus[d.proposal_id] === "rejected" ? "refused" : "pending_approval";
  return "other";
}
function bskyPostUrl(uri) {
  var m = /^at:\/\/(did:[a-z0-9:._-]+)\/app\.bsky\.feed\.post\/([A-Za-z0-9]+)$/.exec(String(uri || ""));
  return m ? "https://bsky.app/profile/" + m[1] + "/post/" + m[2] : null;
}
function social(r) {
  var out = {};
  if (failed(r.connection)) out.connection = unavailableOf(r.connection);
  else {
    var c = r.connection.rows;
    out.connection = c && c.handle ? {
      connected: c.status === "connected",
      handle: "@" + cut(c.handle, 60),
      status: c.status,
      since: c.created_at || null,
      last_ok_at: c.last_ok_at || null,
      last_error_at: c.last_error_at || null,
      last_error_code: c.last_error_code ? cut(c.last_error_code, 60) : null
    } : { connected: false, status: "disconnected" };
    out.automation = c && c.handle ? { on: c.auto_post === true, changed_at: c.auto_post_changed_at || null } : { on: false, changed_at: null };
  }
  if (out.automation) {
    if (failed(r.changes)) out.automation.latest = unavailableOf(r.changes);
    else {
      var ch = r.changes.rows[0];
      out.automation.latest = ch ? { to: ch.new_value === true ? "on" : "off", at: ch.changed_at } : null;
    }
  }
  if (failed(r.drafts) || failed(r.draftProposals)) out.drafts_30d = unavailableOf(failed(r.drafts) ? r.drafts : r.draftProposals);
  else {
    var ps = r.draftProposals.rows || {};
    var tally = { pending_approval: 0, published: 0, refused: 0, failed: 0, other: 0 };
    var rows = r.drafts.rows.slice().sort(function (a, b) { return a.created_at < b.created_at ? 1 : a.created_at > b.created_at ? -1 : 0; });
    rows.forEach(function (d) { tally[draftState(d, ps)] += 1; });
    tally.newest = rows.slice(0, DRAFT_CAP).map(function (d) {
      var state = draftState(d, ps);
      return { id: d.id, state: state, label: DRAFT_LABELS[state], excerpt: cut(d.content, 60), at: d.published_at || d.created_at,
        href: state === "published" ? bskyPostUrl(d.platform_post_uri) : "/proposals.html" };
    });
    out.drafts_30d = tally;
  }
  return out;
}

/* ── EMAIL ── */
function email(r, opts) {
  var out = {};
  if (failed(r.sequences) || failed(r.enrollments)) out.sequences = unavailableOf(failed(r.sequences) ? r.sequences : r.enrollments);
  else {
    var tally = {};
    r.sequences.rows.forEach(function (s) { tally[s.id] = { active: 0, stopped: 0, completed: 0 }; });
    var next = null, active = 0, stopped = 0;
    r.enrollments.rows.forEach(function (e) {
      var t = tally[e.sequence_id];
      if (!t) return;
      if (e.status === "active") { t.active += 1; active += 1; }
      else if (e.status === "stopped") { t.stopped += 1; stopped += 1; }
      else if (e.status === "completed") t.completed += 1;
      if (e.status === "active" && e.next_send_at && (next === null || Date.parse(e.next_send_at) < Date.parse(next))) next = e.next_send_at;
    });
    out.sequences = {
      count: r.sequences.rows.length,
      list: r.sequences.rows.slice(0, LIST_CAP).map(function (s) {
        return { id: s.id, name: cut(s.name || "Untitled sequence", 40), status: s.status, active: tally[s.id].active, stopped: tally[s.id].stopped, completed: tally[s.id].completed };
      }),
      enrolments_active: active,
      enrolments_stopped: stopped,
      next_send_at: next
    };
  }
  var sender = opts.sender || {};
  var blockers = Object.keys(SENDER_BLOCKERS).filter(function (k) { return sender[k] !== true; }).map(function (k) { return { key: k, text: SENDER_BLOCKERS[k] }; });
  out.sender = { ready: blockers.length === 0, blockers: blockers, daily_cap: sender.daily_cap === true ? opts.dailyCap : null };
  return out;
}

/* ── SEO ── */
function seo(r, win) {
  var out = {};
  if (failed(r.audits30)) out.audits_30d = unavailableOf(r.audits30);
  else {
    var audits = r.audits30.rows.filter(function (t) { return t && t.status !== "dry_run"; });
    out.audits_30d = { runs: audits.length, completed: audits.filter(function (t) { return t.status === "completed"; }).length };
  }
  if (failed(r.latestAudit)) out.latest_audit = unavailableOf(r.latestAudit);
  else if (!r.latestAudit.rows) out.latest_audit = null;
  else {
    var a = r.latestAudit.rows, o = a.output;
    if (typeof o === "string") { try { o = JSON.parse(o); } catch (e) { o = null; } }
    var flags = o && Array.isArray(o.flags) ? o.flags : null;
    out.latest_audit = { task_id: a.id, at: a.completed_at || a.created_at, score: null, score_reason: NO_SCORE,
      errors: flags ? flags.filter(function (f) { return f && f.basis === "error"; }).length : null,
      guidelines: flags ? flags.filter(function (f) { return f && f.basis !== "error"; }).length : null };
    if (!flags) out.latest_audit.flags_reason = "this audit's stored result has no flags list";
  }
  out.posts_published_30d = count(r.posts30);
  var arr = blogArrivals(r.arrivals, win);
  out.arrivals_30d = arr.per_day ? { total: arr.total, tracked_posts: arr.tracked_posts } : arr;
  if (failed(r.optimize)) out.latest_optimize = unavailableOf(r.optimize);
  else out.latest_optimize = r.optimize.rows ? { task_id: r.optimize.rows.id, status: r.optimize.rows.status, at: r.optimize.rows.completed_at || r.optimize.rows.created_at } : null;
  return out;
}

/* ── SALES ── */
function sales(r, opts) {
  var out = {};
  if (failed(r.pipeline)) out.pipeline = unavailableOf(r.pipeline);
  else {
    var p = {};
    (opts.stages || []).forEach(function (s) { p[s] = 0; });
    r.pipeline.rows.forEach(function (row) { p[row.status] = (p[row.status] || 0) + 1; });
    out.pipeline = { stages: p, total: r.pipeline.rows.length };
  }
  if (opts.isOwner === true && r.radar) {
    var pair = function (src) { return { d7: count(r.radar[src + "_7"]), d30: count(r.radar[src + "_30"]) }; };
    var bl = pair("bluesky"), ma = pair("mastodon");
    var both = function (k) { return typeof bl[k] === "number" && typeof ma[k] === "number" ? bl[k] + ma[k] : { unavailable: "a part of this total could not be read" }; };
    out.radar = {
      bluesky: bl,
      mastodon: ma,
      bluesky_and_mastodon: { d7: both("d7"), d30: both("d30") },
      youtube: Object.assign(pair("youtube"), { note: YOUTUBE_NOTE })
    };
  }
  return out;
}

/* ── the run lists the remaining twelve share ── */
function byNewest(a, b) { return a.created_at < b.created_at ? 1 : a.created_at > b.created_at ? -1 : (a.id < b.id ? -1 : 1); }
function runsOf(read, cap) {
  if (failed(read)) return unavailableOf(read);
  var rows = read.rows.filter(function (t) { return t && t.status !== "dry_run"; }).slice().sort(byNewest);
  var byType = {};
  rows.forEach(function (t) { byType[t.task_type || "task"] = (byType[t.task_type || "task"] || 0) + 1; });
  return {
    count: rows.length,
    by_type: byType,
    newest: rows.slice(0, cap).map(function (t) { return { task_id: t.id, task_type: t.task_type || null, status: t.status, at: t.created_at }; })
  };
}

/* ── EXECUTIVE: the latest plans and what became of each assignment ──
   An assignment's state is its latest dispatch's outcome (ran, refused,
   failed), or "ready" / "not dispatchable" when it was never dispatched. A run
   that went out is reported by the tool run's OWN ai_tasks status, never the
   plan's or the dispatch row's. */
var RUN_LABELS = { completed: "Completed", failed: "Failed", processing: "In progress", requires_approval: "Awaiting approval" };
var PLAN_CAP = 3, ASSIGNMENT_CAP = 5;
function executive(r) {
  if (failed(r.plans)) return { plans: unavailableOf(r.plans) };
  if (failed(r.dispatches)) return { plans: unavailableOf(r.dispatches) };
  if (failed(r.toolStatus)) return { plans: unavailableOf(r.toolStatus) };
  var latest = {};
  r.dispatches.rows.slice().sort(byNewest).forEach(function (d) {
    var key = d.plan_task_id + "#" + d.assignment_id;
    if (!latest[key]) latest[key] = d;
  });
  var runStatus = r.toolStatus.rows || {};
  var plans = r.plans.rows.slice().sort(byNewest).slice(0, PLAN_CAP).map(function (plan) {
    var output = plan.output && typeof plan.output === "object" ? plan.output : {};
    var list = (Array.isArray(output.assignments) ? output.assignments : []).filter(function (a) { return a && typeof a === "object"; });
    var started = false;
    var assignments = list.map(function (a) {
      var d = latest[plan.id + "#" + Number(a.id)];
      var row = { id: Number(a.id), agent: a.agent ? cut(a.agent, 24) : null, tool: a.tool ? cut(a.tool, 32) : null };
      if (!d) { row.state = a.is_dispatchable === true ? "ready" : "not_dispatchable"; return row; }
      started = true;
      row.state = d.outcome;
      if (d.outcome === "refused" && d.refused_reason) row.refused_reason = cut(d.refused_reason, 40);
      if (d.tool_task_id) {
        var st = runStatus[d.tool_task_id];
        row.run = { task_id: d.tool_task_id, status: st || null, label: st ? (RUN_LABELS[st] || st) : "Run not found" };
      }
      return row;
    });
    return {
      id: plan.id,
      goal: typeof output.goal === "string" ? cut(output.goal, 80) : null,
      created_at: plan.created_at,
      started: started,
      assignments_total: assignments.length,
      assignments: assignments.slice(0, ASSIGNMENT_CAP)
    };
  });
  return { plans: plans };
}

/* ── CONTENT: posts published, outlines and audits, the Business Profile ──
   The checklist is the eleven lines every agent's prompt carries
   (config/brain.js formatBusinessProfile); only whether each is set is sent,
   never its value. */
var PROFILE_CHECKLIST = Object.freeze([
  ["business_name", "Business name"], ["industry", "Industry"], ["website", "Website"], ["description", "Description"],
  ["products_services", "Products and services"], ["target_audience", "Target audience"], ["brand_voice", "Brand voice"],
  ["primary_goal|goals", "Goals"], ["location", "Location"], ["top_keywords", "Keywords"], ["top_competitors", "Competitors"]
]);
function profileSet(row, keys) {
  return keys.split("|").some(function (k) { return row && String(row[k] == null ? "" : row[k]).trim() !== ""; });
}
function content(r) {
  var out = { published_30d: count(r.published), runs_30d: runsOf(r.runs, DRAFT_CAP) };
  if (failed(r.profile)) out.profile = unavailableOf(r.profile);
  else {
    var row = r.profile.rows || null;
    var fields = PROFILE_CHECKLIST.map(function (f) { return { label: f[1], set: profileSet(row, f[0]) }; });
    out.profile = { exists: !!row, set: fields.filter(function (f) { return f.set; }).length, of: fields.length, fields: fields };
  }
  return out;
}

/* ── OPERATIONS: routines, and SOP and checklist runs ── */
function operations(r) {
  var out = {};
  if (failed(r.routines)) out.routines = unavailableOf(r.routines);
  else {
    var list = r.routines.rows.slice().sort(function (a, b) {
      var x = a.last_run_at || "", y = b.last_run_at || "";
      return x < y ? 1 : x > y ? -1 : (String(a.name) < String(b.name) ? -1 : 1);
    });
    out.routines = { count: list.length, list: list.slice(0, LIST_CAP).map(function (x) {
      return { id: x.id, name: cut(x.name, 40), run_count: typeof x.run_count === "number" ? x.run_count : 0, last_run_at: x.last_run_at || null };
    }) };
  }
  out.runs_30d = runsOf(r.runs, DRAFT_CAP);
  return out;
}

/* ── R&D: demand-signal runs and competitor scans. Run rows only: no output,
   so no lead text and no per-source total can reach the answer. ── */
function rd(r) {
  return { runs_30d: runsOf(r.runs, DRAFT_CAP) };
}

/* ── THE EIGHT THIN AGENTS: their own runs, or the first thing to do ──
   Each first action names a tool and its button exactly as the page labels
   them (the app map's controls; checkAgentLive holds them to it). */
var THIN_TYPES = Object.freeze(["ads", "reputation", "community", "influencer", "publicist", "broker", "etsy", "vertical_marketing"]);
var FIRST_ACTIONS = Object.freeze({
  ads:                { tool: "copy",            open: "Ad Copy",              press: "Write the copy" },
  reputation:         { tool: "review-response", open: "Review Response",      press: "Draft the reply" },
  community:          { tool: "onboarding",      open: "Member Onboarding",    press: "Build the sequence" },
  influencer:         { tool: "outreach",        open: "Creator Outreach",     press: "Write the first message" },
  publicist:          { tool: "press-release",   open: "Press Release",        press: "Write the release" },
  broker:             { tool: "term-sheet",      open: "Term Sheet Framework", press: "Draft the framework" },
  etsy:               { tool: "keyword-research", open: "Keyword Research",    press: "Find keywords" },
  vertical_marketing: { tool: "positioning",     open: "Vertical Positioning", press: "Write the positioning" }
});
var THIN_CAP = 5;
function thin(type, r) {
  var runs = runsOf(r.runs, THIN_CAP);
  var out = { runs_30d: runs };
  if (!runs.unavailable && runs.count === 0) out.first_action = FIRST_ACTIONS[type];
  return out;
}

function build(type, reads, opts) {
  opts = opts || {};
  var win = windowOf(opts.now || new Date());
  var body;
  if (type === "analytics") body = analytics(reads, opts, win);
  else if (type === "store") body = store(reads, opts);
  else if (type === "social") body = social(reads);
  else if (type === "email") body = email(reads, opts);
  else if (type === "seo") body = seo(reads, win);
  else if (type === "sales") body = sales(reads, opts);
  else if (type === "executive") body = executive(reads);
  else if (type === "content") body = content(reads);
  else if (type === "operations") body = operations(reads);
  else if (type === "rd") body = rd(reads);
  else if (THIN_TYPES.indexOf(type) !== -1) body = thin(type, reads);
  else return null;
  return Object.assign({ kind: type }, body);
}

/* The task types each agent's runs are read for; null is every run of the agent. */
var RUN_TYPES = Object.freeze({
  content: ["content/outline", "content/audit"],
  operations: ["operations/sop", "operations/checklist"],
  rd: ["rd/demand-signals", "rd/competitor-scan"]
});

/* Keep one agent's answer inside its 3 KB: the long lists go first, then the
   proposal titles, and the answer says what was left out. */
function fit(agent, budget) {
  var size = function () { return JSON.stringify(agent).length; };
  var omitted = [];
  var sig = agent.signature;
  if (size() > budget && sig) {
    if (sig.runs && Array.isArray(sig.runs.by_agent) && sig.runs.by_agent.length > LIST_CAP) { sig.runs.by_agent = sig.runs.by_agent.slice(0, LIST_CAP); omitted.push("runs by agent past the first 5"); }
    if (sig.drafts_30d && Array.isArray(sig.drafts_30d.newest)) sig.drafts_30d.newest.forEach(function (d) { d.excerpt = cut(d.excerpt, 24); });
    if (sig.sequences && Array.isArray(sig.sequences.list) && sig.sequences.list.length > 3) { sig.sequences.list = sig.sequences.list.slice(0, 3); omitted.push("sequences past the first 3"); }
    if (Array.isArray(sig.plans)) {
      sig.plans.forEach(function (p) { if (p.assignments.length > 3) p.assignments = p.assignments.slice(0, 3); });
      if (size() > budget && sig.plans.length > 1) sig.plans = sig.plans.slice(0, 1);
      omitted.push("plans and assignments past the first");
    }
    if (sig.runs_30d && Array.isArray(sig.runs_30d.newest) && sig.runs_30d.newest.length > 3) { sig.runs_30d.newest = sig.runs_30d.newest.slice(0, 3); omitted.push("runs past the newest 3"); }
  }
  if (size() > budget && agent.proposals && Array.isArray(agent.proposals.newest)) {
    agent.proposals.newest = [];
    agent.proposals.newest_omitted = "payload budget";
    omitted.push("the newest proposals");
  }
  if (omitted.length && sig) sig.omitted = omitted;
  return agent;
}

module.exports = {
  SIGNATURE_TYPES: SIGNATURE_TYPES,
  WINDOW_DAYS: WINDOW_DAYS,
  SENDER_BLOCKERS: SENDER_BLOCKERS,
  NO_TRACKED_LINK: NO_TRACKED_LINK,
  YOUTUBE_NOTE: YOUTUBE_NOTE,
  windowOf: windowOf,
  blogArrivals: blogArrivals,
  THIN_TYPES: THIN_TYPES,
  FIRST_ACTIONS: FIRST_ACTIONS,
  PROFILE_CHECKLIST: PROFILE_CHECKLIST,
  RUN_TYPES: RUN_TYPES,
  build: build,
  fit: fit
};
