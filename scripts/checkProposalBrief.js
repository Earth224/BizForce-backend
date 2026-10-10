/* ═══════════════════════════════════════════════════════════════════════════
   checkProposalBrief.js — a filed SEO article keeps the brief behind it.

   THE GAP. POST /api/agents/seo/generate-post kept the brief (topic,
   site_name, site_context, money_anchor) only for a draft it REFUSED, in
   seo_refused_drafts (migration 131). A draft it FILED went into
   agent_proposals with nothing of what produced it, so no one could tell which
   inputs made a published article. Migration 132 adds agent_proposals.brief.

   WHAT THIS PROVES, with no model call and no database at all — the route is
   lifted from the working copy and from BASELINE, the commit before this
   change, and run against a recording stub database and a scripted model:
     1. A filed draft with no repair: brief has exactly the six keys,
        repair_prompt_sha256 is null (present, not absent), and prompt_sha256 is
        the lowercase hex SHA-256 of the prompt the model actually received.
     2. A filed draft after a repair: repair_prompt_sha256 is the SHA-256 of the
        repair prompt the model actually received, and differs from
        prompt_sha256.
     3. The four request fields in brief are exactly what a refused draft of the
        same request stores in seo_refused_drafts.brief — same names, same
        values — with every field given and with none given.
     4. No value in brief contains either prompt's text.
     5. A refused draft writes seo_refused_drafts exactly as BASELINE does, and
        files no proposal — refused at a gate, unreadable, and refused after a
        repair (so a repair's hash never leaks into the refusal record).
     6. Apart from brief, the filed proposal is exactly what BASELINE files.
     7. Nothing else in server.js writes brief: every agent_proposals insert,
        update and upsert is read from source, and only the generate-post
        insert names it; approve and reject set only status columns.
     8. Migration 132 is the transcription it says it is.

   MUTATE=<name> edits the lifted source before it runs (server.js on disk is
   never touched). MUTATE=all runs each in its own process and passes only if
   every one of them fails.
   ═══════════════════════════════════════════════════════════════════════════ */
"use strict";
require("dotenv").config();
const fs = require("fs");
const vm = require("vm");
const path = require("path");
const crypto = require("crypto");
const { execSync, spawnSync } = require("child_process");
const { OWNER_ACCOUNT_ID: AUTHOR } = require("../lib/ownerAccount");

const REPO = path.join(__dirname, "..");
/* The commit before brief existed. Pinned, not HEAD. */
const BASELINE = "9c93916";

const BRIEF_BLOCK =
  "        brief: {\n" +
  "          topic:                topic,\n" +
  "          site_name:            siteName,\n" +
  "          site_context:         siteContext,\n" +
  "          money_anchor:         moneyAnchor,\n" +
  "          prompt_sha256:        promptSha256,\n" +
  "          repair_prompt_sha256: claimRepair && claimRepair.prompt_sha256 ? claimRepair.prompt_sha256 : null\n" +
  "        }\n";
const MUTATIONS = {
  // the brief is not written at all
  nobrief: [["        created_at:    nowIso(),\n        // What produced this article", "        created_at:    nowIso()\n        // What produced this article"], [BRIEF_BLOCK, ""]],
  // the generation hash is taken over something other than the prompt sent
  wronghash: [["update(promptText, \"utf8\")", "update(AGENT_SYSTEM_PROMPTS.seo, \"utf8\")"]],
  // the repair hash is the generation prompt's
  wrongrepairhash: [["          repair_prompt_sha256: claimRepair && claimRepair.prompt_sha256 ? claimRepair.prompt_sha256 : null\n",
    "          repair_prompt_sha256: claimRepair && claimRepair.prompt_sha256 ? promptSha256 : null\n"]],
  // the repair hash is taken over the article, not the prompt
  repairhashdraft: [["update(prompt, \"utf8\")", "update(String(draft.body), \"utf8\")"]],
  // undefined instead of null when no repair ran
  undefinednull: [["claimRepair.prompt_sha256 : null\n        }", "claimRepair.prompt_sha256 : undefined\n        }"]],
  // the prompt text itself is stored
  storesprompt: [["          prompt_sha256:        promptSha256,\n", "          prompt_sha256:        promptSha256,\n          prompt:               promptText,\n"]],
  // a brief field read from somewhere other than the refusal record's source
  topicdrift: [["          topic:                topic,\n", "          topic:                safeText(req.body.topic, 100),\n"]],
  // a second writer: reject overwrites it
  rejectwrites: [["      .update({\n        status:     \"rejected\",", "      .update({\n        brief:      null,\n        status:     \"rejected\","]]
};
const MUTATE = process.env.MUTATE || "";

if (MUTATE === "all") {
  const names = Object.keys(MUTATIONS);
  let survived = 0;
  for (const name of names) {
    const r = spawnSync(process.execPath, [__filename], { env: Object.assign({}, process.env, { MUTATE: name }), encoding: "utf8", timeout: 300000 });
    const fails = (r.stdout.match(/^ {4}FAIL {2}.*$/gm) || []);
    const caught = r.status !== 0 && fails.length > 0;
    if (!caught) survived++;
    console.log((caught ? "    caught    " : "    SURVIVED  ") + name.padEnd(16) + " " + fails.length + " failing check(s)" +
      (fails.length ? "  e.g. " + fails[0].trim().slice(6, 110) : (r.stderr ? "  stderr: " + r.stderr.trim().split("\n")[0] : "")));
  }
  console.log(survived === 0 ? "\nALL CHECKS PASSED — every one of " + names.length + " mutations was caught" : "\nCHECKS FAILED: " + survived + " mutation(s) survived");
  process.exit(survived === 0 ? 0 : 1);
}
if (MUTATE && !MUTATIONS[MUTATE]) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }

let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

let SERVER = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
const SERVER0 = execSync("git show " + BASELINE + ":server.js", { cwd: REPO, maxBuffer: 1 << 26 }).toString("utf8").replace(/\r\n/g, "\n");
if (MUTATE) {
  for (const [from, to] of MUTATIONS[MUTATE]) {
    if (SERVER.split(from).length !== 2) { console.error("MUTATION REFUSED (" + MUTATE + "): anchor not found exactly once: " + JSON.stringify(from.slice(0, 80))); process.exit(3); }
    SERVER = SERVER.replace(from, () => to);
  }
  console.log("\n!! MUTATION: " + MUTATE);
}

/* ── lifting the route (the same way checkSeoMoneyPath does) ───────────────
   _shared caches definitions by whether the source is the working copy, so a
   mutated copy and BASELINE would share a slot; a fresh module per lift keeps
   them apart. */
const SHARED = require.resolve("./_shared");
function shared() {
  delete require.cache[SHARED];
  const s = require(SHARED);
  s.STUBS.delete("COMPLIANCE_PROFILES");
  s.STUBS.delete("COMPLIANCE_DISCLAIMER");
  return s;
}
const CLOSURES = new Map();
function closure(s, src, root) {
  const key = src.length + ":" + crypto.createHash("sha256").update(src).digest("hex");
  if (CLOSURES.has(key)) return CLOSURES.get(key);
  const have = new Map(); const queue = [...new Set(root.match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || s.STUBS.has(name)) continue;
    const def = s.definitionOf(src, name);
    if (!def) continue;
    try { new vm.Script(def); } catch (e) { continue; }
    have.set(name, def);
    new Set(def.match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !s.STUBS.has(id)) queue.push(id); });
  }
  const out = [...have.values()].sort((a, b) => src.indexOf(a) - src.indexOf(b)).join("\n\n") + "\n\n" + root;
  CLOSURES.set(key, out);
  return out;
}

const HANDLE = "check-handle";
const OWN = "/suppressed.html";
const REFUSED_TABLE = "seo_refused_drafts";
const POSTS = [
  { id: "post-bf", title: "Where customers come from without ads", slug: "customers-without-ads", keyword: "customers without ads", external_url: null,
    body: '<p>Owned channels. <a href="/suppressed.html?ref=bl-0123456789">BizForce AI</a></p>' }
];
function likeToRegExp(pattern) {
  return new RegExp("^" + pattern.split("").map(c => c === "%" ? "[\\s\\S]*" : c === "_" ? "[\\s\\S]" : c.replace(/[.*+?^${}()|[\]\\\/]/g, "\\$&")).join("") + "$", "i");
}
/* Every write is recorded; refused drafts apart from everything else. */
function fakeDb() {
  const writes = [], drafts = [];
  function q(table) {
    const st = { insert: null, likes: [] };
    const b = {};
    ["select", "eq", "neq", "gte", "lte", "gt", "in", "is", "not", "order", "limit"].forEach(k => { b[k] = () => b; });
    b.ilike = (col, pattern) => { st.likes.push([col, likeToRegExp(pattern)]); return b; };
    b.insert = (p) => {
      if (table === REFUSED_TABLE) { drafts.push(p); return Promise.resolve({ data: null, error: null }); }
      st.insert = p; writes.push({ table: table, payload: p }); return b;
    };
    ["update", "upsert", "delete"].forEach(k => { b[k] = (p) => { writes.push({ table: table, op: k, payload: p }); return b; }; });
    b.maybeSingle = () => Promise.resolve({ data: table === "bf_profiles" ? { username: HANDLE } : null, error: null });
    b.single = () => Promise.resolve(st.insert ? { data: Object.assign({ id: "row-1" }, st.insert), error: null } : { data: null, error: null });
    b.then = (res, rej) => Promise.resolve({
      data: table === "content_library" ? POSTS.filter(p => st.likes.every(([col, re]) => re.test(String(p[col] || "")))) : [], error: null
    }).then(res, rej);
    return b;
  }
  return { client: { from: q }, writes: writes, drafts: drafts };
}
/* The scripted model: the first call gets modelText, a second (the repair)
   gets opts.repair. Each prompt is kept exactly as received. */
async function generate(src, body, modelText, opts) {
  const s = shared();
  const db = fakeDb();
  const prompts = [];
  let handler = null;
  const ctx = {
    supabase: db.client, nowIso: () => "2026-10-08T12:00:00.000Z", process: { env: {} }, require: require, Buffer: Buffer, URL: URL,
    console: { log() {}, warn() {}, error() {} },
    requireAuth: 0, requireActiveSubscription: 0, aiLimiter: 0,
    resolvePreferredLanguage: async () => null,
    buildLanguageInstruction: () => "",
    AGENT_SYSTEM_PROMPTS: { seo: "SEO SYSTEM" },
    OWNER_ACCOUNT_ID: AUTHOR,
    callAnthropicText: async (prompt) => {
      prompts.push(prompt);
      if (prompts.length > 2) throw new Error("more than one repair");
      const answer = prompts.length > 1 && opts && opts.repair !== undefined ? opts.repair : modelText;
      return { text: answer, stopReason: "end_turn" };
    },
    app: { post() { handler = arguments[arguments.length - 1]; } }
  };
  vm.createContext(ctx);
  vm.runInContext(closure(s, src, s.routeCode(src, "seo/generate-post")), ctx);
  if (!handler) throw new Error("EXTRACTION FAILED: generate-post");
  const res = { statusCode: 200, body: undefined, status(c) { this.statusCode = c; return this; }, json(p) { this.body = p; return this; } };
  let nextErr = null;
  await handler({ user: { id: AUTHOR }, body: body }, res, (e) => { nextErr = e || new Error("next"); });
  return { status: res.statusCode, body: res.body, prompts: prompts, writes: db.writes, drafts: db.drafts, nextErr: nextErr && String(nextErr.message || nextErr) };
}

/* ── the model's answers ── */
function article(links, extra) {
  const pad = "<p>" + "Owned channels keep working when a platform withdraws its approval, because nothing about them depends on that approval. ".repeat(4) + "</p>";
  const body = "<h2>Where customers come from when ads are closed</h2>" + pad + "<p>" + links.map(h => '<a href="' + h + '">this page</a>').join(" and ") + "</p>" + pad +
    "<h2>Frequently asked questions</h2><h3>Can I still be found?</h3><p>Yes, through search.</p><h3>Does it take long?</h3><p>It builds over months.</p><h3>Do I need ads?</h3><p>No.</p>" + (extra || "");
  return "---TITLE---\nWhat to do when your ad account is disabled\n---SLUG---\nwhat-to-do-when-your-ad-account-is-disabled\n---META_DESCRIPTION---\nA plain answer.\n" +
    "---KEYWORD---\nwhat to do when your ad account is disabled\n---INTERNAL_LINKS---\n" + links.join(", ") + "\n---REASONING---\nA question people ask.\n---BODY---\n" + body;
}
const CLAIM_P = "<p>Most owners see results from email often within days, and no platform can disable a list.</p>";
const FIXED = "Email to people who already know you is one place to start, and how quickly it works varies.";
const one = s => "---SENTENCE 1---\n" + s + "\n---END---";
const sha = t => crypto.createHash("sha256").update(t, "utf8").digest("hex");
const REQ = {
  money_path: OWN,
  // Longer than 100 and padded, so a field read through any other limit or
  // without the route's trim is a different string.
  topic: "  getting customers after an ad account is disabled, for a small wellness practice that has been refused by every major ad network for over a year  ",
  site_name: "Earth Rose Wellness",
  site_context: "A small wellness practice that cannot advertise on the major ad networks.",
  money_anchor: "what BizForce AI does for businesses the ad networks won't serve"
};
const KEYS = ["topic", "site_name", "site_context", "money_anchor", "prompt_sha256", "repair_prompt_sha256"];
const FOUR = KEYS.slice(0, 4);
const proposalOf = r => (r.writes.find(w => w.table === "agent_proposals" && !w.op) || {}).payload || null;
const pick = (o, keys) => keys.reduce((a, k) => (a[k] = o == null ? undefined : o[k], a), {});
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const withoutBrief = p => { if (!p) return p; const c = Object.assign({}, p); delete c.brief; return c; };
/* Deep equality that keeps undefined distinct from absent and from null. */
function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const ka = Object.keys(a).sort(), kb = Object.keys(b).sort();
  return same(ka, kb) && ka.every(k => deepEqual(a[k], b[k]));
}

(async function main() {
  /* ── 1. filed, no repair ── */
  console.log("\n══ 1. a filed draft with no repair ══");
  const plain = await generate(SERVER, REQ, article([OWN]));
  const p1 = proposalOf(plain);
  const b1 = p1 && p1.brief;
  console.log("    " + plain.status + ", calls " + plain.prompts.length + ", brief " + JSON.stringify(b1));
  check("1. the draft is filed (201, one model call, one proposal)", plain.status === 201 && plain.prompts.length === 1 && !!p1, plain.status + " " + plain.nextErr);
  check("1. brief is an object with exactly the six keys", !!b1 && typeof b1 === "object" && same(Object.keys(b1).sort(), KEYS.slice().sort()), b1 && Object.keys(b1).join(","));
  check("1. repair_prompt_sha256 is present and === null", !!b1 && Object.prototype.hasOwnProperty.call(b1, "repair_prompt_sha256") && b1.repair_prompt_sha256 === null, b1 && String(b1.repair_prompt_sha256));
  check("1. … and survives a JSON round trip as null (what jsonb stores)", !!b1 && JSON.parse(JSON.stringify(b1)).repair_prompt_sha256 === null);
  check("1. prompt_sha256 === sha256 of the prompt the model received", !!b1 && b1.prompt_sha256 === sha(plain.prompts[0]), b1 && b1.prompt_sha256);
  check("1. prompt_sha256 is 64 lowercase hex characters", !!b1 && /^[0-9a-f]{64}$/.test(String(b1.prompt_sha256)));
  check("1. the topic is stored whole and trimmed, as the route read it (" + REQ.topic.trim().length + " characters)", !!b1 && b1.topic === REQ.topic.trim() && b1.topic.length > 100);

  /* ── 2. filed after a repair ── */
  console.log("\n══ 2. a filed draft after a repair ══");
  const rep = await generate(SERVER, REQ, article([OWN], CLAIM_P), { repair: one(FIXED) });
  const p2 = proposalOf(rep);
  const b2 = p2 && p2.brief;
  console.log("    " + rep.status + ", calls " + rep.prompts.length + ", brief " + JSON.stringify(b2));
  check("2. the repaired draft is filed after exactly two model calls", rep.status === 201 && rep.prompts.length === 2 && !!p2 && !!p2.payload.claim_repair, rep.status + " " + rep.nextErr);
  check("2. brief has exactly the six keys", !!b2 && same(Object.keys(b2).sort(), KEYS.slice().sort()));
  check("2. repair_prompt_sha256 === sha256 of the repair prompt the model received", !!b2 && b2.repair_prompt_sha256 === sha(rep.prompts[1] || ""), b2 && b2.repair_prompt_sha256);
  check("2. prompt_sha256 === sha256 of the generation prompt the model received", !!b2 && b2.prompt_sha256 === sha(rep.prompts[0]));
  check("2. repair_prompt_sha256 differs from prompt_sha256", !!b2 && typeof b2.repair_prompt_sha256 === "string" && b2.repair_prompt_sha256 !== b2.prompt_sha256);
  check("2. repair_prompt_sha256 is 64 lowercase hex characters", !!b2 && /^[0-9a-f]{64}$/.test(String(b2.repair_prompt_sha256)));

  /* ── 3. the same four fields as a refused draft ── */
  console.log("\n══ 3. brief describes a request the way seo_refused_drafts does ══");
  const refusedSame = await generate(SERVER, REQ, article(["/listing/not-the-money-page"]));
  const rb = (refusedSame.drafts[0] || {}).brief;
  console.log("    refused " + refusedSame.status + " stage " + JSON.stringify((refusedSame.drafts[0] || {}).stage) + ", its brief " + JSON.stringify(rb));
  check("3. the same request, refused, stores a brief", refusedSame.drafts.length === 1 && !!rb);
  check("3. the filed brief's four fields deep-equal the refused brief (names and values)", !!b1 && !!rb && deepEqual(pick(b1, FOUR), rb), JSON.stringify(pick(b1, FOUR)) + " vs " + JSON.stringify(rb));
  check("3. the refused brief names exactly those four fields", !!rb && same(Object.keys(rb).sort(), FOUR.slice().sort()));
  const bare = { money_path: OWN };
  const bareFiled = proposalOf(await generate(SERVER, bare, article([OWN])));
  const bareRefused = (await generate(SERVER, bare, article(["/listing/not-the-money-page"]))).drafts[0];
  console.log("    with no fields given: filed " + JSON.stringify(bareFiled && bareFiled.brief) + " refused " + JSON.stringify(bareRefused && bareRefused.brief));
  check("3. with none of the four given, both store them as null, alike", !!bareFiled && !!bareRefused &&
    deepEqual(pick(bareFiled.brief, FOUR), bareRefused.brief) && FOUR.every(k => bareFiled.brief[k] === null));
  const repRefused = await generate(SERVER, REQ, article([OWN], CLAIM_P), { repair: one("Most sellers usually see results within days.") });
  check("3. … and a draft refused after a repair stores the same four", repRefused.drafts.length === 1 && !!b1 && deepEqual(pick(b1, FOUR), repRefused.drafts[0].brief));

  /* ── 4. no prompt text ── */
  console.log("\n══ 4. the prompts are hashed, never kept ══");
  for (const [label, r, b] of [["no repair", plain, b1], ["after repair", rep, b2]]) {
    const values = b ? Object.keys(b).map(k => String(b[k])) : [];
    const texts = r.prompts;
    check("4. " + label + ": no value in brief contains a prompt's text, or a 200-character slice of one",
      !!b && values.every(v => texts.every(t => v.indexOf(t) === -1 && !(v.length >= 200 && t.indexOf(v) !== -1) && !slices(t).some(sl => v.indexOf(sl) !== -1))));
    // The row's payload legitimately holds the article, which the repair prompt
    // quotes; it is brief that must hold no prompt, so brief is what is read.
    check("4. " + label + ": serialized, brief carries no prompt text and stays small (" + JSON.stringify(b || {}).length + " characters)",
      !!b && texts.every(t => !slices(t).some(sl => JSON.stringify(b).indexOf(JSON.stringify(sl).slice(1, -1)) !== -1)) && JSON.stringify(b).length < 1200);
  }

  /* ── 5. refusals unchanged ── */
  console.log("\n══ 5. a refused draft is recorded exactly as at " + BASELINE + " and files nothing ══");
  const REFUSALS = [
    ["refused at the money-link gate", REQ, article(["/listing/not-the-money-page"]), undefined],
    ["unreadable", REQ, "not the delimited format at all", undefined],
    ["refused after one repair", REQ, article([OWN], CLAIM_P), one("Most sellers usually see results within days.")],
    ["refused, no fields given", bare, article(["/listing/not-the-money-page"]), undefined]
  ];
  for (const [label, body, text, repair] of REFUSALS) {
    const now = await generate(SERVER, body, text, { repair: repair });
    const was = await generate(SERVER0, body, text, { repair: repair });
    check("5. " + label + ": the same status and answer (" + now.status + ")", now.status === was.status && deepEqual(now.body, was.body));
    check("5. " + label + ": seo_refused_drafts gets exactly the row it got before", now.drafts.length === 1 && deepEqual(now.drafts, was.drafts),
      JSON.stringify(now.drafts).slice(0, 200));
    check("5. " + label + ": no proposal and no other write", now.writes.length === 0, JSON.stringify(now.writes.map(w => w.table)));
    check("5. " + label + ": no hash anywhere in the refusal record", !/[0-9a-f]{64}/.test(JSON.stringify(now.drafts)));
  }

  /* ── 6. nothing else on the filed row changed ── */
  console.log("\n══ 6. the filed proposal is otherwise what " + BASELINE + " files ══");
  for (const [label, body, text, repair] of [["no repair", REQ, article([OWN]), undefined], ["after repair", REQ, article([OWN], CLAIM_P), one(FIXED)], ["no fields", bare, article([OWN]), undefined]]) {
    const now = await generate(SERVER, body, text, { repair: repair });
    const was = await generate(SERVER0, body, text, { repair: repair });
    check("6. " + label + ": the prompts sent are identical", same(now.prompts, was.prompts));
    check("6. " + label + ": the proposal row, without brief, deep-equals BASELINE's", deepEqual(withoutBrief(proposalOf(now)), proposalOf(was)),
      JSON.stringify(withoutBrief(proposalOf(now))).slice(0, 160) + " vs " + JSON.stringify(proposalOf(was)).slice(0, 160));
    check("6. " + label + ": BASELINE wrote no brief", !!proposalOf(was) && !("brief" in proposalOf(was)));
  }

  /* ── 7. no other writer ── */
  console.log("\n══ 7. nothing else writes brief ══");
  const lines = SERVER.split("\n");
  const writers = [];
  lines.forEach((l, i) => {
    if (!/from\("agent_proposals"\)/.test(l)) return;
    const tail = lines.slice(i, i + 60).join("\n");
    const m = /\.(insert|update|upsert)\(/.exec(tail);
    if (!m || /\.select\([^)]*\)\s*\n?\s*\.(eq|order|in|limit|single|maybeSingle)/.test(tail.slice(0, m.index))) return;
    const open = tail.indexOf("(", m.index);
    let depth = 0, end = open;
    for (; end < tail.length; end++) { if (tail[end] === "(") depth++; else if (tail[end] === ")" && --depth === 0) break; }
    let arg = tail.slice(open + 1, end).trim();
    // an identifier argument: read the object it was built from, up to the call
    if (/^[A-Za-z_$][\w$]*$/.test(arg)) arg = lines.slice(Math.max(0, i - 60), i).join("\n");
    writers.push({ line: i + 1, op: m[1], brief: /\bbrief\b/.test(arg) });
  });
  console.log("    agent_proposals writes: " + writers.map(w => w.line + " " + w.op + (w.brief ? " (brief)" : "")).join(", "));
  const routeStart = SERVER.indexOf('app.post("/api/agents/seo/generate-post"');
  const routeEnd = SERVER.indexOf("\n});\n", routeStart);
  const briefWriters = writers.filter(w => w.brief);
  check("7. exactly one agent_proposals write names brief", briefWriters.length === 1, JSON.stringify(briefWriters));
  check("7. … and it is the insert inside generate-post", briefWriters.length === 1 && briefWriters[0].op === "insert" &&
    lines.slice(0, briefWriters[0].line).join("\n").length > routeStart && lines.slice(0, briefWriters[0].line).join("\n").length < routeEnd);
  check("7. no upsert of agent_proposals exists", writers.every(w => w.op !== "upsert"));
  for (const [route, label] of [['app.post("/api/proposals/:id/approve"', "approve"], ['app.post("/api/proposals/:id/reject"', "reject"]]) {
    const at = SERVER.indexOf(route);
    const s = shared();
    const code = at < 0 ? "" : SERVER.slice(at, s.braceMatch(SERVER, SERVER.indexOf("{", at)));
    const updates = (code.match(/\.update\(\{[\s\S]*?\}\)/g) || []);
    check("7. " + label + ": its updates set only status columns, never brief", at >= 0 && updates.length > 0 &&
      updates.every(u => !/\bbrief\b/.test(u)), updates.join(" | "));
  }
  const execAt = SERVER.indexOf("const PROPOSAL_EXECUTORS = {");
  const execCode = execAt < 0 ? "" : SERVER.slice(execAt, shared().braceMatch(SERVER, SERVER.indexOf("{", execAt)));
  check("7. PROPOSAL_EXECUTORS, which runs after approve, never names brief", execAt >= 0 && execCode.length > 1000 && !/\bbrief\b/.test(execCode),
    "found=" + (execAt >= 0) + " length=" + execCode.length);

  /* ── 8. migration 132 ── */
  console.log("\n══ 8. migration 132 ══");
  const dir = path.join(REPO, "supabase", "migrations");
  const files = fs.readdirSync(dir).filter(f => /^\d+_.*\.sql$/.test(f));
  // Not tied to which migration is newest: later migrations may follow 132.
  const mig = files.find(f => /^132_/.test(f));
  check("8. exactly one migration is numbered 132", files.filter(f => /^132_/.test(f)).length === 1, files.filter(f => /^132_/.test(f)).join(","));
  const sql = mig ? fs.readFileSync(path.join(dir, mig), "utf8").replace(/\r\n/g, "\n") : "";
  const statements = sql.split("\n").filter(l => l.trim() && !/^\s*--/.test(l)).join("\n");
  check("8. it holds exactly the statements applied by hand", statements ===
    "alter table public.agent_proposals add column if not exists brief jsonb;\n" +
    "comment on column public.agent_proposals.brief is 'Inputs that produced this proposal, written only by the generating route at insert: topic, site_name, site_context, money_anchor, prompt_sha256, repair_prompt_sha256. Null on rows filed before migration 132 and on routes that do not write it.';",
    JSON.stringify(statements.slice(0, 200)));
  check("8. it says it is a transcription of SQL already applied", /TRANSCRIPTION/.test(sql) && /ALREADY APPLIED BY HAND/.test(sql));

  console.log("\n" + passes + " passed, " + failures + " failed");
  console.log(failures === 0 ? "ALL CHECKS PASSED" : "CHECKS FAILED: " + failures);
  process.exit(failures === 0 ? 0 : 1);
})().catch(e => { console.log("    FAIL  the run threw: " + (e && e.stack || e)); console.log("\nCHECKS FAILED"); process.exit(1); });

/* Every 200-character window of a prompt, stepping by 100: any stored value
   that holds a stretch of the prompt that long holds one of these whole. */
function slices(text) {
  const out = [];
  for (let i = 0; i + 200 <= text.length; i += 100) out.push(text.slice(i, i + 200));
  return out;
}
