/* ═══════════════════════════════════════════════════════════════════════════
   lib/agentNetwork.js — the agent network (intelligence layer B6 and B7)

   WHAT IT IS. The declared links between the 18 agents, each one a path by
   which one agent's work really reaches another and is RECORDED in a row that
   names both ends, plus the reads that count the runs that flowed along each
   link for one member, and the member's own switches (member_links,
   migration 161).

   A LINK IS DRAWN ONLY WHEN A RECORDED ROW NAMES TWO DIFFERENT AGENTS:

     dispatch   executive -> X, for every agent X that has at least one tool
                in TOOL_INPUT_SPECS that is not on CHAIN_NON_DISPATCHABLE_TOOLS.
                POST /api/assignments/dispatch runs one assignment of an
                Executive plan through dispatchToolCall as a chain (a fresh
                chain id, depth 0, the dispatched tool at depth 1, fan-out
                counted); executive_dispatches records it. Counted: rows with
                outcome 'ran'.
     handoff    executive -> sales. POST /api/assignments/:id/start runs
                orchestrateAgentWorkflow, and the only handoff in it that does
                work is the Sales Agent's conversion pass on an Executive
                assignment. Recorded as an ai_tasks row for sales whose prompt
                starts "Executive handoff: ".
     proposal   seo -> content. seo/generate-post files a publish_blog_post
                proposal (agent_type seo); approving it writes the post into
                the content library. Counted: those proposals executed. The
                tool must be in TOOL_INPUT_SPECS and on the non-dispatchable
                list: it acts, so it only ever flows through approval.
     signals    sales -> rd. rd/demand-signals reads the posts the Sales
                agent's Lead Radar captured (bsky_leads). Counted: completed
                rd/demand-signals runs. The owner's account only, as the tool is.

   NOT DRAWN, and why (NOT_DRAWN below says the same to the page):
     agent_collaborations   the mechanism was removed; its table holds 13
                            inert rows and is never read here.
     store proposals        the Store agent proposes and the Store agent's
                            executor acts once a person approves: one agent at
                            both ends, so no link between two agents.
     executive -> store, executive -> sales (dispatch)
                            every tool those agents have acts on the world
                            (CHAIN_NON_DISPATCHABLE_TOOLS), so no dispatch
                            can reach them.
     routines               a list the member typed; each step's inputs are its
                            own, so no agent hands anything to another.
     triggers               a firing drafts a saved prompt or pauses a
                            schedule; it is not a run of an agent.
     the other orchestration handoffs (seo->content, content->analytics and
                            the rest of AGENT_ORCHESTRATION_HANDOFFS) are
                            logged as "HANDOFF NOT RECORDED" and do nothing.

   MEMBER SWITCHES. A member may switch any declared link off, and on again;
   nothing else. An undeclared link is refused. A link switched off is
   refused, with the reason link_disabled_by_member, by whatever would have
   carried work along it, and the refusal goes through the gate evaluator as
   G26. A switch that cannot be read (the table missing before migration 161,
   a read error) is logged and the platform's decision stands, as a member gate
   does (server.js memberGateCheck): a member's switch only ever adds a
   restriction.

   PURE except for the reads and the one write, which take the database client
   as an argument. No model calls. No clock of its own: callers pass the time.
   ═══════════════════════════════════════════════════════════════════════════ */
"use strict";

var AGENT_NAMES = require("./agentLive").AGENT_NAMES;

/* The 18 agents on the map, the Executive first (it sits in the middle). */
var AGENTS = Object.freeze([
  "executive", "ads", "analytics", "broker", "community", "content", "email", "etsy", "influencer",
  "operations", "publicist", "rd", "reputation", "sales", "seo", "social", "store", "vertical_marketing"
]);
var CENTRE = "executive";

var HANDOFF_PROMPT_PREFIX = "Executive handoff: ";
var REASON = "link_disabled_by_member";

/* The links that are not dispatches, each with the tool that carries it (or
   none) and the rule its tool must meet. */
var OTHER_LINKS = Object.freeze([
  Object.freeze({ from: "executive", to: "sales", kind: "handoff", tool: null,
    label: "Executive assignments handed to Sales for a conversion pass" }),
  Object.freeze({ from: "seo", to: "content", kind: "proposal", tool: "seo/generate-post", toolMustAct: true,
    label: "SEO posts published into the content library, once you approve them" }),
  Object.freeze({ from: "sales", to: "rd", kind: "signals", tool: "rd/demand-signals", toolMustAct: false,
    label: "Lead Radar posts read by R&D demand signals" })
]);

var NOT_DRAWN = Object.freeze([
  { what: "agent_collaborations", why: "That mechanism was removed. Its old rows are never read." },
  { what: "store proposals", why: "The Store agent proposes and acts once you approve: one agent at both ends." },
  { what: "executive to store, executive to sales (dispatch)", why: "Every tool those agents have acts on the world, so a plan cannot dispatch to them." },
  { what: "routines", why: "A routine is a list you typed. No agent hands anything to another." },
  { what: "triggers", why: "A trigger drafts a saved prompt or pauses a schedule. It is not an agent run." }
]);

function edgeId(from, to) { return from + ">" + to; }

/* The declared graph, from the live TOOL_INPUT_SPECS keys and the
   non-dispatchable list. Returns { nodes, edges, problems }. An edge that does
   not validate is left out and named in problems; nothing is guessed. */
function buildGraph(toolSpecKeys, nonDispatchable) {
  var keys = Array.isArray(toolSpecKeys) ? toolSpecKeys.slice() : [];
  var acts = Array.isArray(nonDispatchable) ? nonDispatchable : [];
  var problems = [];
  var byId = {};
  var order = [];
  function add(from, to, source) {
    var id = edgeId(from, to);
    if (!byId[id]) {
      byId[id] = { id: id, from: from, to: to, sources: [] };
      order.push(id);
    }
    byId[id].sources.push(source);
  }
  AGENTS.forEach(function (to) {
    if (to === CENTRE) return;
    var tools = keys.filter(function (k) { return k.indexOf(to + "/") === 0 && acts.indexOf(k) === -1; }).sort();
    if (tools.length) add(CENTRE, to, { kind: "dispatch", tools: tools, label: "Executive plan assignments dispatched as a chain" });
  });
  OTHER_LINKS.forEach(function (l) {
    if (l.tool !== null) {
      if (keys.indexOf(l.tool) === -1) { problems.push(edgeId(l.from, l.to) + ": " + l.tool + " has no entry in TOOL_INPUT_SPECS"); return; }
      var isActing = acts.indexOf(l.tool) !== -1;
      if (l.toolMustAct && !isActing) { problems.push(edgeId(l.from, l.to) + ": " + l.tool + " is not on the non-dispatchable list, but this link is approval only"); return; }
    }
    add(l.from, l.to, { kind: l.kind, tools: l.tool ? [l.tool] : [], label: l.label });
  });
  var edges = order.map(function (id) { return byId[id]; });
  var bad = validateGraph({ nodes: AGENTS.slice(), edges: edges }, keys, acts);
  if (bad.length) {
    problems = problems.concat(bad);
    edges = edges.filter(function (e) { return !bad.some(function (p) { return p.indexOf(e.id + ":") === 0; }); });
  }
  return { nodes: AGENTS.slice(), edges: edges, problems: problems };
}

/* Every rule a declared graph must meet. Returns the problems, [] when it holds. */
function validateGraph(graph, toolSpecKeys, nonDispatchable) {
  var out = [];
  var keys = Array.isArray(toolSpecKeys) ? toolSpecKeys : [];
  var acts = Array.isArray(nonDispatchable) ? nonDispatchable : [];
  var seen = {};
  (graph && graph.edges || []).forEach(function (e) {
    var id = e && e.id;
    if (!e || id !== edgeId(e.from, e.to)) { out.push(String(id) + ": the id is not from>to"); return; }
    if (AGENTS.indexOf(e.from) === -1 || AGENTS.indexOf(e.to) === -1) out.push(id + ": an end is not one of the 18 agents");
    if (e.from === e.to) out.push(id + ": an agent cannot link to itself");
    if (seen[id]) out.push(id + ": declared twice");
    seen[id] = true;
    if (!Array.isArray(e.sources) || !e.sources.length) out.push(id + ": no recorded source");
    (e.sources || []).forEach(function (s) {
      if (!s || ["dispatch", "handoff", "proposal", "signals"].indexOf(s.kind) === -1) { out.push(id + ": an unknown source kind"); return; }
      if (/collaboration/i.test(JSON.stringify(s))) out.push(id + ": agent_collaborations is never drawn");
      (s.tools || []).forEach(function (t) {
        if (keys.indexOf(t) === -1) out.push(id + ": " + t + " has no entry in TOOL_INPUT_SPECS");
        if (t.indexOf(e.to + "/") !== 0 && t.indexOf(e.from + "/") !== 0) out.push(id + ": " + t + " belongs to neither end");
        if (s.kind === "dispatch" && acts.indexOf(t) !== -1) out.push(id + ": " + t + " acts on the world and cannot be dispatched");
        if (s.kind === "dispatch" && t.indexOf(e.to + "/") !== 0) out.push(id + ": a dispatch runs a tool of the receiving agent");
      });
      if (s.kind === "dispatch" && e.from !== CENTRE) out.push(id + ": only an Executive plan dispatches");
    });
  });
  return out;
}

function isDeclared(graph, from, to) {
  return (graph && graph.edges || []).some(function (e) { return e.from === from && e.to === to; });
}

/* ── windows ─────────────────────────────────────────────────────────────── */
var WINDOW_MAX_MS = 30 * 24 * 3600 * 1000;
var UNIT_MS = { m: 60000, h: 3600000, d: 86400000 };
/* "90m", "24h", "7d": a whole number of minutes, hours or days, 1 minute to
   30 days. Returns ms, or null. */
function windowMs(text) {
  var m = /^([1-9][0-9]{0,4})(m|h|d)$/.exec(String(text == null ? "" : text));
  if (!m) return null;
  var ms = Number(m[1]) * UNIT_MS[m[2]];
  return ms <= WINDOW_MAX_MS ? ms : null;
}

/* ── the reads ───────────────────────────────────────────────────────────── */
var PAGE = 1000;
async function allRows(build, what) {
  var rows = [];
  for (var from = 0; ; from += PAGE) {
    var got = await build().order("id", { ascending: true }).range(from, from + PAGE - 1);
    if (got.error) throw new Error(what + " could not be read: " + (got.error.message || got.error.code || "error"));
    var page = got.data || [];
    rows = rows.concat(page);
    if (page.length < PAGE) break;
  }
  return rows;
}

/* Each source kind's runs for one member since `sinceIso`, newest first, as
   { at, kind, agent, tool, task_id, proposal_id, chain_id }. Every read names
   the member's user_id. */
var READS = {
  dispatch: async function (db, userId, sinceIso, edge) {
    var rows = await allRows(function () {
      return db.from("executive_dispatches")
        .select("id, agent_type, tool, outcome, tool_task_id, chain_id, created_at")
        .eq("user_id", userId).eq("outcome", "ran").eq("agent_type", edge.to).gte("created_at", sinceIso);
    }, "your plan dispatches");
    return rows.map(function (r) {
      return { at: r.created_at, kind: "dispatch", tool: r.agent_type + "/" + r.tool, task_id: r.tool_task_id || null, proposal_id: null, chain_id: r.chain_id || null };
    });
  },
  handoff: async function (db, userId, sinceIso) {
    var rows = await allRows(function () {
      return db.from("ai_tasks").select("id, agent_type, prompt, created_at")
        .eq("user_id", userId).eq("agent_type", "sales").like("prompt", HANDOFF_PROMPT_PREFIX + "%").gte("created_at", sinceIso);
    }, "your handoffs");
    return rows.map(function (r) {
      return { at: r.created_at, kind: "handoff", tool: null, task_id: r.id, proposal_id: null, chain_id: null };
    });
  },
  proposal: async function (db, userId, sinceIso) {
    var rows = await allRows(function () {
      return db.from("agent_proposals").select("id, agent_type, action_type, status, executed_at")
        .eq("user_id", userId).eq("agent_type", "seo").eq("action_type", "publish_blog_post").eq("status", "executed").gte("executed_at", sinceIso);
    }, "your published posts");
    return rows.map(function (r) {
      return { at: r.executed_at, kind: "proposal", tool: "seo/generate-post", task_id: null, proposal_id: r.id, chain_id: null };
    });
  },
  signals: async function (db, userId, sinceIso) {
    var rows = await allRows(function () {
      return db.from("ai_tasks").select("id, task_type, status, created_at")
        .eq("user_id", userId).eq("task_type", "rd/demand-signals").eq("status", "completed").gte("created_at", sinceIso);
    }, "your demand-signal runs");
    return rows.map(function (r) {
      return { at: r.created_at, kind: "signals", tool: "rd/demand-signals", task_id: r.id, proposal_id: null, chain_id: null };
    });
  }
};

/* The runs that flowed along one edge, newest first. Throws when a read fails:
   a count that could not be read is never answered as 0. */
async function edgeRuns(db, userId, edge, sinceIso) {
  if (!userId) throw new Error("no member");
  var runs = [];
  for (var i = 0; i < edge.sources.length; i++) {
    runs = runs.concat(await READS[edge.sources[i].kind](db, userId, sinceIso, edge));
  }
  runs.sort(function (a, b) { return a.at < b.at ? 1 : a.at > b.at ? -1 : 0; });
  return runs;
}

/* Every edge's count. One that cannot be read is { count: null, unavailable }. */
async function edgeCounts(db, userId, graph, sinceIso) {
  var out = {};
  for (var i = 0; i < graph.edges.length; i++) {
    var e = graph.edges[i];
    try { out[e.id] = { count: (await edgeRuns(db, userId, e, sinceIso)).length }; }
    catch (readErr) { out[e.id] = { count: null, unavailable: "This link's runs could not be read just now." }; }
  }
  return out;
}

/* A run as the page shows it: the run.html link and the "Why?" target. */
function runOut(r) {
  return {
    at: r.at, kind: r.kind, tool: r.tool, chain_id: r.chain_id,
    task_id: r.task_id, proposal_id: r.proposal_id,
    href: r.task_id ? "/run.html?id=" + encodeURIComponent(r.task_id) : null,
    why: r.task_id ? "ai_task:" + r.task_id : r.proposal_id ? "proposal:" + r.proposal_id : null
  };
}

/* ── the member's switches ───────────────────────────────────────────────── */
function notRead(err) {
  try { console.error("[member-links] not read: " + ((err && err.message) || String(err)) + ". The platform's decision stands."); } catch (e) { /* nothing */ }
}

/* { "from>to": false, ... } for the member's switched-off links; {} when they
   cannot be read (logged). */
async function memberSwitches(db, userId) {
  if (!userId) return {};
  try {
    var got = await db.from("member_links").select("from_agent, to_agent, enabled").eq("user_id", userId);
    if (got.error) { notRead(got.error); return {}; }
    var out = {};
    (got.data || []).forEach(function (r) { if (r && r.enabled === false) out[edgeId(r.from_agent, r.to_agent)] = false; });
    return out;
  } catch (err) { notRead(err); return {}; }
}

/* True only when the member's row for exactly this link says enabled false. */
async function linkSwitchedOff(db, userId, from, to) {
  if (!userId) return false;
  var f = String(from || "").toLowerCase().trim(), t = String(to || "").toLowerCase().trim();
  try {
    var got = await db.from("member_links").select("enabled")
      .eq("user_id", userId).eq("from_agent", f).eq("to_agent", t).maybeSingle();
    if (got.error) { notRead(got.error); return false; }
    return !!(got.data && got.data.enabled === false);
  } catch (err) { notRead(err); return false; }
}

/* The closed body of PUT /api/agents/network/links: from, to, enabled, and
   nothing else; the link must be declared. */
function validateSwitch(body, graph) {
  if (!body || typeof body !== "object" || Array.isArray(body)) return { ok: false, error: "The body is { from, to, enabled }.", field: null };
  var extra = Object.keys(body).filter(function (k) { return ["from", "to", "enabled"].indexOf(k) === -1; });
  if (extra.length) return { ok: false, error: "Unknown field " + extra[0] + ".", field: extra[0] };
  if (typeof body.from !== "string" || AGENTS.indexOf(body.from) === -1) return { ok: false, error: "from is one of the 18 agents.", field: "from" };
  if (typeof body.to !== "string" || AGENTS.indexOf(body.to) === -1) return { ok: false, error: "to is one of the 18 agents.", field: "to" };
  if (typeof body.enabled !== "boolean") return { ok: false, error: "enabled is true or false.", field: "enabled" };
  if (!isDeclared(graph, body.from, body.to)) {
    return { ok: false, error: "There is no declared link from " + body.from + " to " + body.to + ". You can switch off a declared link, never add one.", field: "to", reason: "link_not_declared" };
  }
  return { ok: true, value: { from: body.from, to: body.to, enabled: body.enabled } };
}

/* The one write: the member's row for this link. */
async function writeSwitch(db, userId, value, nowIso) {
  return db.from("member_links")
    .upsert({ user_id: userId, from_agent: value.from, to_agent: value.to, enabled: value.enabled, updated_at: nowIso }, { onConflict: "user_id,from_agent,to_agent" })
    .select("from_agent, to_agent, enabled, updated_at")
    .single();
}

/* The link a proposal carries, if any: an SEO post going to the content library. */
function proposalLink(proposal) {
  if (proposal && proposal.agent_type === "seo" && proposal.action_type === "publish_blog_post") return { from: "seo", to: "content" };
  return null;
}

function name(key) { return AGENT_NAMES[key] || key; }

module.exports = {
  AGENTS: AGENTS,
  CENTRE: CENTRE,
  OTHER_LINKS: OTHER_LINKS,
  NOT_DRAWN: NOT_DRAWN,
  HANDOFF_PROMPT_PREFIX: HANDOFF_PROMPT_PREFIX,
  REASON: REASON,
  edgeId: edgeId,
  buildGraph: buildGraph,
  validateGraph: validateGraph,
  isDeclared: isDeclared,
  windowMs: windowMs,
  edgeRuns: edgeRuns,
  edgeCounts: edgeCounts,
  runOut: runOut,
  memberSwitches: memberSwitches,
  linkSwitchedOff: linkSwitchedOff,
  validateSwitch: validateSwitch,
  writeSwitch: writeSwitch,
  proposalLink: proposalLink,
  name: name
};
