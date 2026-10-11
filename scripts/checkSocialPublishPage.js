"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkSocialPublishPage — the social page is honest about Bluesky.

   Frontend "Bluesky posts on the page" offered Bluesky in the Social agent's
   post tool, relabelled a Bluesky result's lengths in graphemes, added
   scripts/social-publish.js (a "File for approval" button under a Bluesky
   result), publish_social_post cards on proposals.html, and stopped
   agents/content.html and scripts/agent-profile.js saying "Published." without
   proof. This runs those files in vm with a stubbed DOM and a stubbed fetch,
   and feeds them FIXTURES MADE BY THIS REPO'S REAL ROUTES: POST
   /api/agents/social/post, POST /api/agents/social/propose-post, POST
   /api/social-drafts, publicUser and the publish_social_post executor, lifted
   from server.js and run against a fake database with migration 136's CHECKs
   and a stub Bluesky gate. No browser, no network, no model, no post; nothing
   is written to either repo.

   WHAT THIS PROVES
     0. The real shapes: the post tool offers Bluesky; social.html loads
        social-publish.js after agent-profile.js; agent-profile.js hands a
        Bluesky result to bfAfterToolResult.
     A. Graphemes: a real Bluesky result renders its length, overrun and limit
        in graphemes and never in characters; an Instagram result is unchanged.
     B. Filing: the button only for an admin; the one quiet line otherwise; an
        unreadable /api/auth/me is neither. Only Bluesky results get it; the
        hook keeps any hook already installed. Filing posts the task_id alone;
        success shows the server's note verbatim with a link to the proposals
        page; an error shows the server's message unchanged.
     C. proposals.html: the text to be posted, escaped with its line breaks,
        and its grapheme count; after approval a bsky.app link built from the
        at:// uri and the published time; a replay says already published with
        the same link; a failure shows execution_error verbatim; no uri, no
        link.
     D. "Published." only with proof, in agent-profile.js and in content.html.
     And zero network.

   MUTATE=<name> edits the frontend files IN MEMORY (nothing on disk is
   touched). MUTATE=all runs each in its own process and passes only if every
   one fails. A mutation whose search text does not match exactly once is an
   ERROR, never counted as caught.

   BIZFORCE_FRONTEND_DIR overrides the frontend location (default: the
   BizForce-fronyend checkout beside this repo).
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), vm = require("vm"), path = require("path"), net = require("net"), dns = require("dns");
const s = require("./_shared");

/* ── the network tripwire ───────────────────────────────────────────────── */
const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkSocialPublishPage: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkSocialPublishPage: no network"); };

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";

const PUB_JS = "scripts/social-publish.js", PROPOSALS = "proposals.html", PROFILE = "scripts/agent-profile.js",
  SOCIAL = "agents/social.html", CONTENT = "agents/content.html";
const MUTATIONS = {
  // the filing button is shown to everyone
  "form-for-non-admins": [[PUB_JS, "slot.innerHTML = admin ? filingFormMarkup(data.task_id) : notOwnerMarkup();", "slot.innerHTML = filingFormMarkup(data.task_id);"]],
  // a link is drawn without a uri to build it from
  "link-without-uri": [[PROPOSALS, "return m ? \"https://bsky.app/profile/\" + m[1] + \"/post/\" + m[2] : null;",
    "return m ? \"https://bsky.app/profile/\" + m[1] + \"/post/\" + m[2] : \"https://bsky.app/\";"]],
  // a Bluesky result's lengths are labelled as characters
  "characters-for-bluesky": [[PROFILE, "    data = withLengthUnit(data);\n", ""]],
  // the old condition: anything but published: false is "Published."
  "old-published-condition": [[PROFILE, "    if (draft.status === \"published\" && postId) {\n", "    if (!(data && data.published === false)) {\n"],
    [CONTENT, "    if (draft.status === \"published\" && postId) return \"Published.\";\n", "    if (!(data && data.published === false)) return \"Published.\";\n"]],
  // the text to be posted is rendered as HTML
  "unescaped-text": [[PROPOSALS, "'<pre class=\"exec-block social-post-text\">' + escapeHtml(text) + '</pre>'",
    "'<pre class=\"exec-block social-post-text\">' + text + '</pre>'"]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

/* ── the frontend files, mutated in memory ──────────────────────────────── */
const FILES = {};
[PUB_JS, PROPOSALS, PROFILE, SOCIAL, CONTENT].forEach(f => { FILES[f] = fs.readFileSync(path.join(FRONTEND, f), "utf8").replace(/\r\n/g, "\n"); });
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (frontend, in memory)");
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}
const count = (h, needle) => String(h).split(needle).length - 1;
const flush = async () => { for (let i = 0; i < 30; i++) await new Promise(r => setImmediate(r)); };
const escH = (t) => String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/* ── the backend's real routes, lifted ──────────────────────────────────── */
const SRC = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
const SPANS = [];
{
  const re = /^(?:(?:async )?function [A-Za-z_$][A-Za-z0-9_$]*[(]|app[.][a-z]+[(])/gm; let m;
  while ((m = re.exec(SRC))) { const end = s.braceMatch(SRC, SRC.indexOf("{", m.index)); if (end > 0) SPANS.push([m.index, end]); }
}
function definitionOf(name) {
  let m = new RegExp("^(?:async )?function " + name + "\\(", "m").exec(SRC);
  if (m) return SRC.slice(m.index, s.braceMatch(SRC, SRC.indexOf(") {", m.index) + 2));
  const re = new RegExp("^(?:var|const|let) " + name + "[ \t]*=[ \t]*", "gm");
  while ((m = re.exec(SRC)) && SPANS.some(([x, y]) => m.index > x && m.index < y)) { /* a local */ }
  if (!m) return null;
  const brk = /;\n/g; brk.lastIndex = m.index + m[0].length;
  let b;
  while ((b = brk.exec(SRC))) {
    const next = SRC[b.index + b[0].length];
    if (next === undefined || next === "\n" || /[^\s]/.test(next)) return SRC.slice(m.index, b.index + 1);
  }
  return null;
}
const STUBS = new Set(["supabase", "nowIso", "console", "process", "require", "module", "app", "Buffer", "setTimeout", "fetch",
  "requireAuth", "requireActiveSubscription", "aiLimiter", "bskyGate", "RichText",
  "startToolRun", "toolGenerateWithOneRetry", "toolSectionShapeCorrection", "toolProvenance", "loadProfileForTool",
  "resolvePreferredLanguage", "buildAgentSystemPrompt", "buildLanguageInstruction"]);
const uncommented = (code) => code.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
function closure(root) {
  const have = new Map();
  const queue = [...new Set(uncommented(root).match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || STUBS.has(name)) continue;
    const def = definitionOf(name);
    if (!def) continue;
    try { new vm.Script(def); } catch (e) { continue; }
    have.set(name, def);
    new Set(uncommented(def).match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !STUBS.has(id)) queue.push(id); });
  }
  return [...have.values()].sort((x, y) => SRC.indexOf(x) - SRC.indexOf(y)).join("\n\n") + "\n\n" + root;
}
function routeText(method, route) {
  const sig = "app." + method + "(\"" + route + "\",";
  const start = SRC.indexOf(sig);
  if (start < 0) throw new Error(method.toUpperCase() + " " + route + " not found");
  const end = s.braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("function (req, res, next)", start)));
  if (SRC.slice(end, end + 2) !== ");") throw new Error(method.toUpperCase() + " " + route + " did not end where expected");
  return SRC.slice(start, end + 2);
}
const ROUTES = [["post", "/api/agents/social/post"], ["post", "/api/agents/social/propose-post"], ["post", "/api/social-drafts"]];
const LIFTED = closure(ROUTES.map(([m, r]) => routeText(m, r)).join("\n\n") +
  "\n\nthis.api = { execute: executePublishSocialPost, publicUser: publicUser };");

/* ── the fake database, with migration 136's CHECKs ────────────────────── */
const DRAFT_STATUSES = ["pending", "not_published", "scheduled", "pending_approval", "published", "publish_failed"];
function violates(table, row) {
  if (table !== "social_post_drafts") return null;
  if (DRAFT_STATUSES.indexOf(row.status) === -1) return "social_post_drafts_status_check";
  if (row.status === "published" && (row.platform_post_uri == null || row.published_at == null)) return "social_post_drafts_published_check";
  return null;
}
function fakeDb(seed) {
  const tables = { ai_tasks: [], users: [], social_post_drafts: [], agent_proposals: [] };
  Object.keys(seed || {}).forEach(t => { tables[t] = seed[t].map(r => JSON.parse(JSON.stringify(r))); });
  let n = 0;
  const copy = v => JSON.parse(JSON.stringify(v));
  const keep = (q, row) => q.filters.every(f => f[0] === "eq" ? row[f[1]] === f[2] : true);
  function finish(q, rows) {
    if (q.single === "single") return rows.length === 1 ? { data: copy(rows[0]), error: null } : { data: null, error: { code: "PGRST116", message: rows.length + " rows" } };
    if (q.single === "maybe") return { data: rows[0] ? copy(rows[0]) : null, error: null };
    return { data: copy(rows), error: null };
  }
  function answer(q) {
    const rows = tables[q.table];
    if (!rows) return Promise.resolve({ data: null, error: { message: "unplanned table " + q.table } });
    if (q.op === "insert") {
      const row = Object.assign({ id: "00000000-0000-4000-8000-" + String(++n).padStart(12, "0") }, copy(q.payload));
      const bad = violates(q.table, row);
      if (bad) return Promise.resolve({ data: null, error: { code: "23514", message: bad } });
      rows.push(row);
      return Promise.resolve(finish(q, [row]));
    }
    const hits = rows.filter(r => keep(q, r));
    if (q.op === "update") {
      for (const r of hits) { const bad = violates(q.table, Object.assign({}, r, q.payload)); if (bad) return Promise.resolve({ data: null, error: { code: "23514", message: bad } }); }
      hits.forEach(r => Object.assign(r, copy(q.payload)));
    }
    if (q.op === "delete") tables[q.table] = rows.filter(r => hits.indexOf(r) === -1);
    return Promise.resolve(finish(q, hits));
  }
  function from(table) {
    const q = { table, op: "select", payload: null, filters: [], single: false };
    const b = {
      select() { return b; },
      insert(p) { q.op = "insert"; q.payload = p; return b; },
      update(p) { q.op = "update"; q.payload = p; return b; },
      delete() { q.op = "delete"; return b; }
    };
    ["eq", "order", "limit"].forEach(op => { b[op] = function () { q.filters.push([op].concat([].slice.call(arguments))); return b; }; });
    b.single = () => { q.single = "single"; return answer(q); };
    b.maybeSingle = () => { q.single = "maybe"; return answer(q); };
    b.then = (res, rej) => answer(q).then(res, rej);
    return b;
  }
  return { tables, client: { from } };
}

/* ── fixtures, from the real routes ─────────────────────────────────────── */
const OWNER = "aaaaaaaa-0000-4000-8000-000000000001";
const PLAIN = "cccccccc-0000-4000-8000-000000000003";
const TASK = "11111111-0000-4000-8000-000000000001";
const FAMILY = "\u{1F468}\u200D\u{1F469}\u200D\u{1F467}";
const XSS = "<img src=x onerror=alert(1)>";
const POST_TEXT = "New colourway " + FAMILY + " & more\nSee https://example.com/launch " + XSS;
const POSTED = { uri: "at://did:plc:ownerabc123/app.bsky.feed.post/3kabc456", cid: "bafyreicid" };
const BSKY_URL = "https://bsky.app/profile/did:plc:ownerabc123/post/3kabc456";
const { RichText } = require(require.resolve("@atproto/api", { paths: [REPO] }));

function backend(opts) {
  opts = opts || {};
  const db = fakeDb({ users: [{ id: OWNER, role: "admin" }, { id: PLAIN, role: "user" }] });
  const gate = { posts: 0, call: async (fn) => { gate.posts++; return { ok: true, value: await fn({ post: async () => Object.assign({}, POSTED) }) }; } };
  const runs = [];
  const ctx = {
    supabase: db.client, bskyGate: gate, RichText, JSON, Math, Promise, Date, Intl,
    nowIso: () => "2026-10-11T12:00:00.000Z",
    process: { env: {} },
    fetch: () => { NETWORK.push("backend fetch"); return Promise.reject(new Error("no network")); },
    console: { log() {}, error() {}, warn() {} },
    requireAuth: function requireAuth(req, res, next) { next(); },
    requireActiveSubscription: function requireActiveSubscription(req, res, next) { next(); },
    aiLimiter: function aiLimiter(req, res, next) { next(); },
    startToolRun: async () => ({ taskId: TASK, complete: async (o) => { runs.push(o); return true; }, fail: async () => {} }),
    toolGenerateWithOneRetry: async (o) => { o.parse(opts.model); return { raw: opts.model, completionExtra: undefined, failureDetails: null }; },
    toolSectionShapeCorrection: () => "", toolProvenance: () => ({ measured_from: [], model_supplied: [] }), loadProfileForTool: async () => ({}),
    resolvePreferredLanguage: async () => null, buildAgentSystemPrompt: () => "SYSTEM", buildLanguageInstruction: () => ""
  };
  const routes = {};
  ctx.app = { post(p) { routes["post " + p] = [].slice.call(arguments, 1); } };
  vm.createContext(ctx);
  vm.runInContext(LIFTED, ctx);
  async function call(key, user, body) {
    const chain = routes[key];
    const res = { code: 200, body: null, status(x) { this.code = x; return this; }, json(x) { this.body = JSON.parse(JSON.stringify(x)); return this; } };
    const req = { user: { id: user, role: user === PLAIN ? "user" : "admin" }, params: {}, query: {}, body: body || {} };
    let i = 0;
    async function step() {
      const fn = chain[i++];
      if (!fn) return;
      let advanced = false;
      await fn(req, res, (e) => { if (e) { res.code = 500; res.body = { error: String(e.message || e) }; return; } advanced = true; });
      if (advanced) await step();
    }
    await step();
    return { status: res.code, body: res.body };
  }
  // A completed social/post run, stored the way run.complete stores it.
  async function draftedRun(platform, text) {
    opts.model = "POST: " + text + "\nHOOK_NOTE: leads with it";
    const r = await call("post /api/agents/social/post", OWNER, { idea: "a launch", platform });
    if (r.status === 200) {
      db.tables.ai_tasks = db.tables.ai_tasks.filter(t => t.id !== TASK);
      db.tables.ai_tasks.push({ id: TASK, user_id: OWNER, agent_type: "social", task_type: "social/post", status: "completed", output: runs[runs.length - 1] });
    }
    return r;
  }
  return { db, gate, api: ctx.api, call, draftedRun };
}

/* ── the frontend in a fake page ────────────────────────────────────────── */
function fakeEl(id) {
  return { id, innerHTML: "", textContent: "", className: "", value: "", disabled: false, children: [], style: {},
    appendChild(c) { this.children.push(c); return c; }, addEventListener() {}, setAttribute() {}, getAttribute() { return null; } };
}
function responder(handlers, posted) {
  return function fetchStub(url, init) {
    const method = (init && init.method) || "GET";
    const p = url.replace(/^https?:\/\/[^/]+/, "");
    const body = init && init.body ? JSON.parse(init.body) : undefined;
    posted.push({ method, path: p, body });
    const h = handlers(method, p, body);
    if (h === "reject") return Promise.reject(new TypeError("Failed to fetch"));
    return Promise.resolve(h).then(r => ({ ok: r.status >= 200 && r.status < 300, status: r.status,
      json: () => r.body === undefined ? Promise.reject(new SyntaxError("Unexpected end of JSON input")) : Promise.resolve(JSON.parse(JSON.stringify(r.body))) }));
  };
}
function loadPublish(handlers, priorHook) {
  const posted = [];
  const document = { readyState: "complete", head: fakeEl("head"), createElement() { return fakeEl(null); }, addEventListener() {},
    getElementById(id) { return fakeEl(id); }, querySelector() { return null; }, querySelectorAll() { return []; } };
  const window = { bfAfterToolResult: priorHook };
  const ctx = { window, document, console, localStorage: { getItem() { return "check-token"; }, setItem() {} },
    fetch: responder(handlers, posted), setTimeout() { return 0; }, clearTimeout() {} };
  vm.createContext(ctx);
  vm.runInContext(FILES[PUB_JS], ctx);
  return { sp: window.bfSocialPublish, window, posted };
}
function realHandlers(be, user, role, override) {
  return function (method, p, body) {
    const o = override && override(method, p, body);
    if (o !== undefined) return o;
    if (method === "GET" && p === "/api/auth/me") return { status: 200, body: { user: be.api.publicUser({ id: user, role, email: "o@example.com" }) } };
    if (method === "POST" && p === "/api/agents/social/propose-post") return be.call("post /api/agents/social/propose-post", user, body);
    return { status: 404, body: { error: "unplanned " + method + " " + p } };
  };
}

// agent-profile.js, run with a page config and one stubbed tool response.
function socialConfig() {
  const m = FILES[SOCIAL].match(/<script>\s*(window\.AGENT_PROFILE_CONFIG\s*=[\s\S]*?)<\/script>/);
  const w = {}; vm.runInNewContext(m[1], { window: w });
  return w.AGENT_PROFILE_CONFIG;
}
function loadProfile(cfg, response, hook) {
  const els = new Map();
  const document = { head: { appendChild() {} }, createElement() { return fakeEl(null); }, addEventListener() {},
    getElementById(id) { if (!els.has(id)) els.set(id, fakeEl(id)); return els.get(id); }, querySelector() { return fakeEl(null); }, querySelectorAll() { return []; } };
  const window = { AGENT_PROFILE_CONFIG: cfg, bfAfterToolResult: hook };
  const ctx = { window, document, console, localStorage: { getItem() { return "t"; }, setItem() {} },
    fetch: () => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(JSON.parse(JSON.stringify(response))) }),
    setTimeout() { return 0; }, clearTimeout() {}, setInterval() { return 0; }, clearInterval() {} };
  const tail = '  document.addEventListener("DOMContentLoaded", inject);\n})();';
  const src = FILES[PROFILE];
  if (src.indexOf(tail) < 0) throw new Error("agent-profile.js does not end where expected");
  vm.createContext(ctx);
  vm.runInContext(src.slice(0, src.lastIndexOf(tail)) +
    "  window.__ap = { runTool: runTool, TOOLS: TOOLS, toolDomId: toolDomId, draftSaveOutcome: draftSaveOutcome };\n" + tail, ctx);
  return { ap: window.__ap, document };
}
async function renderResult(response, platform) {
  const handed = [];
  const page = loadProfile(socialConfig(), response, (a, t, d, el) => handed.push([a, t, d, el]));
  const tool = page.ap.TOOLS.find(t => t.id === "post");
  page.document.getElementById(page.ap.toolDomId("post", "f_idea")).value = "a launch";
  page.document.getElementById(page.ap.toolDomId("post", "f_platform")).value = platform;
  page.ap.runTool(tool);
  await flush();
  return { html: page.document.getElementById(page.ap.toolDomId("post", "result")).innerHTML, handed, page };
}

(async function main() {
  /* ── 0. the real shapes ──────────────────────────────────────────────── */
  console.log("\n══ 0. the real shapes ══");
  const cfg = socialConfig();
  const postTool = cfg.tools.find(t => t.id === "post");
  const platformField = postTool && postTool.fields.find(f => f.name === "platform");
  const offered = platformField ? platformField.options.map(o => o.value) : [];
  check("the post tool offers bluesky, labelled in graphemes", offered.indexOf("bluesky") !== -1 &&
    /graphemes/.test(platformField.options.find(o => o.value === "bluesky").label), JSON.stringify(offered));
  const be0 = backend();
  const accepted = await be0.call("post /api/agents/social/post", OWNER, { idea: "x", platform: "nope" });
  check("every platform offered is one the real route accepts", accepted.status === 400 &&
    offered.every(v => accepted.body.valid_platforms.indexOf(v) !== -1), JSON.stringify(accepted.body));
  check("social.html loads social-publish.js after agent-profile.js",
    /<script src="\/scripts\/agent-profile\.js"><\/script>\n<script src="\/scripts\/social-publish\.js"><\/script>/.test(FILES[SOCIAL]));
  check("/api/auth/me reports the user through publicUser", (SRC.match(/app\.get\("\/api\/auth\/me"[\s\S]*?\n\}\);/) || [""])[0].includes("publicUser(req.user)"));

  const beB = backend();
  const blueRun = await beB.draftedRun("bluesky", FAMILY.repeat(301));
  const blueResponse = Object.assign({}, blueRun.body, { task_id: TASK, persisted: true });
  check("fixture: the real route measures a 301-emoji Bluesky post as 301 graphemes, length_unit graphemes",
    blueRun.status === 200 && blueRun.body.measured.length === 301 && blueRun.body.measured.length_unit === "graphemes" && blueRun.body.measured.chars_over_limit === 1,
    JSON.stringify(blueRun.body && blueRun.body.measured && [blueRun.body.measured.length, blueRun.body.measured.length_unit]));
  const blue = await renderResult(blueResponse, "bluesky");
  check("agent-profile.js hands the Bluesky result to bfAfterToolResult as (social, post, data, result element)",
    blue.handed.length === 1 && blue.handed[0][0] === "social" && blue.handed[0][1] === "post" && blue.handed[0][2].platform === "bluesky" &&
    blue.handed[0][3] === blue.page.document.getElementById(blue.page.ap.toolDomId("post", "result")), JSON.stringify(blue.handed.map(h => h.slice(0, 2))));

  /* ── A. graphemes ────────────────────────────────────────────────────── */
  console.log("\n══ A. a Bluesky result is measured in graphemes ══");
  const key = (h, k) => h.includes('<div class="ap-m-key">' + k + '</div>');
  check("the length cell is 'Graphemes' = 301", /<div class="ap-m-key">Graphemes<\/div><div class="ap-m-val[^"]*">301<\/div>/.test(blue.html), blue.html.slice(0, 400));
  check("the overrun is 'Graphemes over limit'", key(blue.html, "Graphemes over limit"));
  check("the limit is 'Max graphemes: 300'", blue.html.includes("<strong>Max graphemes:</strong> 300"));
  check("no length is labelled in characters: no 'Length', 'Chars …' or 'Max characters'",
    !key(blue.html, "Length") && !key(blue.html, "Length unit") && !/<div class="ap-m-key">Chars /.test(blue.html) && !blue.html.includes("Max characters"), blue.html.slice(0, 600));
  const beI = backend();
  const instaRun = await beI.draftedRun("instagram", "A caption " + FAMILY);
  const insta = await renderResult(Object.assign({}, instaRun.body, { task_id: TASK, persisted: true }), "instagram");
  check("an Instagram result is unchanged: 'Length', 'Chars over limit', 'Max characters'",
    key(insta.html, "Length") && key(insta.html, "Chars over limit") && insta.html.includes("Max characters") && !insta.html.includes("raphemes"), insta.html.slice(0, 400));

  /* ── B. filing ───────────────────────────────────────────────────────── */
  console.log("\n══ B. filing ══");
  const RESULT = { success: true, platform: "bluesky", post: POST_TEXT, task_id: TASK, persisted: true };
  async function drawn(role, override) {
    const be = backend();
    await be.draftedRun("bluesky", POST_TEXT);
    const pg = loadPublish(realHandlers(be, OWNER, role, override));
    const slot = fakeEl("slot");
    await pg.sp.drawFiling(slot, RESULT);
    return { pg, be, html: slot.innerHTML };
  }
  const admin = await drawn("admin");
  check("admin: the button, carrying this run's task_id", admin.html.includes("data-sp-file") && admin.html.includes('data-sp-task="' + TASK + '"'), admin.html);
  check("admin: no 'only the owner' line", !admin.html.includes(escH(admin.pg.sp.NOT_OWNER_LINE)) && !admin.html.includes(admin.pg.sp.NOT_OWNER_LINE));
  const user = await drawn("user");
  check("non-admin: no button", !user.html.includes("data-sp-file"), user.html);
  check("non-admin: the one quiet line", count(user.html, escH(user.pg.sp.NOT_OWNER_LINE).replace(/'/g, "&#39;")) === 1, user.html);
  const meDown = await drawn(null, (m, p) => p === "/api/auth/me" ? { status: 500, body: { error: "boom" } } : undefined);
  check("/api/auth/me unreadable: an error, neither the button nor the line",
    !meDown.html.includes("data-sp-file") && !meDown.html.includes("only the owner") && /could not be checked/.test(meDown.html) && /boom/.test(meDown.html), meDown.html);
  const meGone = await drawn(null, (m, p) => p === "/api/auth/me" ? "reject" : undefined);
  check("/api/auth/me network failure: an error too", !meGone.html.includes("data-sp-file") && !meGone.html.includes("only the owner") && /could not be checked/.test(meGone.html), meGone.html);

  {
    const prior = [];
    const pg = loadPublish(realHandlers(backend(), OWNER, "admin"), function () { prior.push([].slice.call(arguments, 0, 2)); });
    const blueEl = fakeEl("r1"), instaEl = fakeEl("r2");
    pg.window.bfAfterToolResult("social", "post", RESULT, blueEl);
    pg.window.bfAfterToolResult("social", "post", Object.assign({}, RESULT, { platform: "instagram" }), instaEl);
    pg.window.bfAfterToolResult("email", "sequence", { success: true, task_id: TASK }, fakeEl("r3"));
    check("the hook adds a filing slot under a Bluesky result", blueEl.children.length === 1 && blueEl.children[0].className === "sp-file-slot");
    check("…and nothing under an Instagram result", instaEl.children.length === 0);
    check("the hook keeps the hook that was already installed", prior.length === 3 && prior[2][0] === "email", JSON.stringify(prior));
  }

  {
    const be = backend();
    await be.draftedRun("bluesky", POST_TEXT);
    const pg = loadPublish(realHandlers(be, OWNER, "admin"));
    const msg = fakeEl("msg"), form = fakeEl("form");
    await pg.sp.filePost(TASK, msg, form, null);
    const filed = pg.posted.find(x => x.path === "/api/agents/social/propose-post");
    check("files with { task_id } and nothing else", filed && JSON.stringify(filed.body) === JSON.stringify({ task_id: TASK }), filed && JSON.stringify(filed.body));
    const proposal = be.db.tables.agent_proposals[0];
    check("fixture: the real route filed one publish_social_post with the run's text", proposal && proposal.action_type === "publish_social_post" && proposal.payload.text === POST_TEXT);
    const real = await be.call("post /api/agents/social/propose-post", OWNER, { task_id: TASK });
    check("fixture: the real route answers 201 with a note", real.status === 201 && typeof real.body.note === "string" && real.body.note.length > 20, JSON.stringify(real.body));
    check("success: the server's note verbatim", form.innerHTML.includes(escH(real.body.note).replace(/'/g, "&#39;")), form.innerHTML);
    check("success: a link to the proposals page", form.innerHTML.includes('href="/proposals.html"'));
    const msg2 = fakeEl("msg2"), form2 = fakeEl("form2");
    const other = "22222222-0000-4000-8000-000000000002";
    await pg.sp.filePost(other, msg2, form2, null);
    const refused = await be.call("post /api/agents/social/propose-post", OWNER, { task_id: other });
    check("error: the server's message, unchanged", refused.status === 404 && msg2.textContent === refused.body.error && /err/.test(msg2.className), msg2.textContent);
    check("error: no success panel", form2.innerHTML === "");
  }

  /* ── C. proposals.html ───────────────────────────────────────────────── */
  console.log("\n══ C. proposals.html ══");
  {
    const be = backend();
    await be.draftedRun("bluesky", POST_TEXT);
    const filed = await be.call("post /api/agents/social/propose-post", OWNER, { task_id: TASK });
    const pending = filed.body.proposal;
    const result = await be.api.execute(Object.assign({}, pending, { status: "executing" }));
    check("fixture: the real executor returns the uri, cid and published_at", result.uri === POSTED.uri && result.published_at === "2026-10-11T12:00:00.000Z", JSON.stringify(result));
    const replay = await be.api.execute(Object.assign({}, pending, { status: "executing" }));
    check("fixture: a replay returns already_published with the uri", replay.already_published === true && replay.uri === POSTED.uri && be.gate.posts === 1, JSON.stringify(replay));
    const executed = Object.assign({}, pending, { id: "p-2", status: "executed", execution_result: result });
    const replayed = Object.assign({}, pending, { id: "p-3", status: "executed", execution_result: replay });
    const failed = Object.assign({}, pending, { id: "p-4", status: "failed", execution_result: null,
      execution_error: "publish_social_post: Bluesky rate limit: no Bluesky call until 2026-10-11T12:15:00.000Z (900s). <b>x</b>" });
    const noUri = Object.assign({}, pending, { id: "p-5", status: "executed", execution_result: { cid: "c" } });

    function proposalsPage(list) {
      const m = FILES[PROPOSALS].match(/<script>\nvar API_URL[\s\S]*?<\/script>/);
      const script = m[0].replace(/^<script>/, "").replace(/<\/script>$/, "");
      const els = new Map();
      const document = { getElementById(id) { if (!els.has(id)) { const e = fakeEl(id); e.querySelectorAll = () => []; els.set(id, e); } return els.get(id); },
        querySelectorAll() { return []; }, querySelector() { return null; } };
      const ctx = { document, console, Intl, localStorage: { getItem() { return "t"; } }, setTimeout() { return 0; }, clearTimeout() {},
        fetch: () => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ proposals: list }) }) };
      ctx.window = ctx;
      vm.createContext(ctx);
      vm.runInContext(script, ctx);
      return els;
    }
    const cardOf = (h, id) => { const i = h.indexOf('data-id="' + id + '"'); return i < 0 ? "" : h.slice(i, (h.indexOf('<div class="proposal-card"', i) + 1 || h.length + 1) - 1); };
    let els = proposalsPage([pending, executed, replayed, failed, noUri]);
    await flush();
    const h = els.get("proposalsList").innerHTML;
    const pc = cardOf(h, pending.id);
    check("the pending card shows the text to be posted, escaped, line break kept",
      pc.includes('<pre class="exec-block social-post-text">' + escH(POST_TEXT) + '</pre>') && escH(POST_TEXT).includes("\n"), pc.slice(0, 500));
    check("the text is never raw HTML", !h.includes(XSS));
    check("its grapheme count: the real count of the text",
      pc.includes([...new Intl.Segmenter(undefined, { granularity: "grapheme" }).segment(POST_TEXT)].length + " of 300 graphemes"), pc.slice(0, 600));
    check("the pending card has no bsky.app link", !pc.includes("bsky.app/profile"));
    const ec = cardOf(h, "p-2");
    check("after approval: a link to " + BSKY_URL, ec.includes('href="' + BSKY_URL + '"'), ec.slice(0, 500));
    check("after approval: the published time", ec.includes("published</span>") && !ec.includes("time not reported") && !ec.includes("already published"), ec.slice(0, 500));
    const rc = cardOf(h, "p-3");
    check("a replay: the same link, saying already published", rc.includes('href="' + BSKY_URL + '"') && rc.includes("already published"), rc.slice(0, 500));
    const fc = cardOf(h, "p-4");
    check("a failure: execution_error verbatim (escaped), no link",
      fc.includes('<pre class="exec-block exec-error">' + escH(failed.execution_error) + '</pre>') && !fc.includes("bsky.app"), fc.slice(0, 500));
    const nc = cardOf(h, "p-5");
    check("a result with no uri: no link, saying so", !nc.includes("bsky.app") && !nc.includes("href=\"http") && /no Bluesky post address/.test(nc), nc.slice(0, 500));
  }

  /* ── D. "Published." only with proof ─────────────────────────────────── */
  console.log("\n══ D. \"Published.\" only with proof ══");
  {
    const be = backend();
    const real = await be.call("post /api/social-drafts", OWNER, { platform: "instagram", content: "x" });
    check("fixture: the real route saves it not_published and answers published: false", real.status === 201 && real.body.published === false && real.body.draft.status === "not_published", JSON.stringify(real.body));
    const outcome = loadProfile(socialConfig(), {}, null).ap.draftSaveOutcome;
    const cm = FILES[CONTENT].match(/\n  function draftSaveMessage\(data\) \{[\s\S]*?\n  \}\n/);
    const cctx = {}; vm.createContext(cctx); vm.runInContext(cm ? cm[0] : "", cctx);
    const message = cctx.draftSaveMessage;
    check("content.html defines draftSaveMessage", typeof message === "function");
    const cases = [
      ["the real gated answer (published: false)", real.body, false],
      ["a draft published with a platform_post_uri", { draft: { status: "published", platform_post_uri: POSTED.uri } }, true],
      ["a draft published with a zernio_post_id", { draft: { status: "published", zernio_post_id: "z1" } }, true],
      ["status published with no post id", { draft: { status: "published", zernio_post_id: null } }, false],
      ["a scheduled draft", { draft: { status: "scheduled", zernio_post_id: "z2" } }, false],
      ["an answer with no draft and no flag", {}, false],
      ["a pending draft with no flag", { draft: { status: "pending" } }, false]
    ];
    for (const [label, data, proven] of cases) {
      const a = outcome(data), c = typeof message === "function" ? message(data) : "";
      check("agent-profile.js, " + label + ": " + (proven ? "Published." : "not Published."),
        proven ? (a.message === "Published." && a.status === "✓ Published") : (a.message !== "Published." && !/Published$/.test(a.status) && /not published/i.test(a.message)), JSON.stringify(a));
      check("content.html, " + label + ": " + (proven ? "Published." : "not Published."),
        proven ? c === "Published." : (c !== "Published." && /not published/i.test(c)), c);
    }
    check("the gated answer keeps its own sentence", outcome(real.body).message === "Saved as a draft — not published. Publishing to social accounts is turned off for now." &&
      (typeof message === "function" && message(real.body) === outcome(real.body).message));
    check("the old ternary that said \"Published.\" for anything but published: false is gone from both files",
      ![FILES[PROFILE], FILES[CONTENT]].some(f => /notPublished \?[^:]*: "Published\."/.test(f)));
  }

  check("zero network", NETWORK.length === 0, JSON.stringify(NETWORK));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.error("\nThe check threw: " + (e && e.stack || e)); process.exit(1); });
