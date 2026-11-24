/* ═══════════════════════════════════════════════════════════════════════════
   checkEngineArrival.js — a reply's link says the engine sent it, and an
   arrival through that link is recorded, with nothing personal anywhere.

   THE GAP. A Lead Radar reply could link bizforceai.net, but nothing recorded
   that anyone arrived, so whether the engine drives traffic to the platform —
   the master file's north star — could not be measured at all.

   WHAT THIS PROVES, with no model call, no send and no database write — the
   functions are lifted from the working copy and, for "unchanged", from
   BASELINE, the commit before this change:
     1. The token is lr- and ten hex characters of SHA-256 over the lead's
        post_uri: the same for the same lead, different for another, and
        carrying nothing of the handle, DID or post.
     2. Rejection runs first. In convertSingleLead the rejection precedes the
        tracking, which precedes the send; and a draft in which the model wrote
        a parameter of its own is still held, never sent.
     3. The code adds ?ref= to every form of the destination the model may write
        (with or without scheme, www or slash, any case).
     4. detectOutreachLinkFacets links the whole final URL, parameter included.
     5. For every supplement product and the book, the prompt and the reply sent
        are identical to BASELINE, and no supplement reply carries a parameter.
     6. A reply that would pass 300 characters with the parameter is sent
        without it, link intact, rather than truncated through the link.
     7. POST /api/engine-visits writes exactly { ref, landing_path } — no IP,
        user agent, referrer or account, whatever the request carries; refuses
        a malformed ref or a path with a query or fragment; and answers 503,
        naming migration 128, while the table does not exist.
     8. Migration 128 creates the table with those columns and constraints,
        RLS on, anon and authenticated revoked, no policy.

   NAMED (Nov 23 2026, LR-2): BEFORE sections 2 to 6 ran the real convertSingleLead, which wrote the platform's own
   replies and added ?ref=lr-<token> to the BizForce destination. AFTER LR-2 removed the platform's own outreach
   (convertSingleLead, withOutreachTracking, the product destinations, send-approved; the original is in git, 65c0825):
   a reply is now the member's own approved text from their own account, with no parameter added. Still true and
   kept: 1 (the token, which still joins earlier lr- arrivals back to outreach_sends), 7 (the route) and 8 (the
   migration). 2 to 6 become one removal proof: none of that code remains, and the member reply path adds no
   parameter and no link. The mutations order, everydomain, lengthguard and pathless are removed with their code.

   MUTATIONS — each must turn the named section red:
     MUTATE=order        tracking runs before rejection               → 2, 3, 4
     MUTATE=everydomain  every reply gets a parameter, any host        → 5
     MUTATE=personal     the token is the lead's handle                → 1, 7
     MUTATE=lengthguard  the 300-character guard is gone               → 6
     MUTATE=visitfields  the route also stores IP and user agent       → 7
     MUTATE=visitref     the route accepts any ref                     → 7
     MUTATE=pathless     tracking matches the host only, not the destination's path → 3, 4
   ═══════════════════════════════════════════════════════════════════════════ */
"use strict";
require("dotenv").config();
const fs = require("fs");
const vm = require("vm");
const path = require("path");
const crypto = require("crypto");
const { execSync } = require("child_process");
const REPO = path.join(__dirname, "..");
const { createResidueGuard, resolveSubjectAccount } = require("./checkRunResidue");
const SUBJECT_USER_ID = resolveSubjectAccount();
const { RichText } = require(require.resolve("@atproto/api", { paths: [REPO] }));
const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY);
/* Nothing here writes; the guard is built so a future edit that adds a write
   has somewhere to record it, and its read-back runs regardless. */
const residue = createResidueGuard({ supabase: supabase, name: "engineArrival", subject: SUBJECT_USER_ID, tables: [] });
residue.install();

/* The commit before the arrival parameter existed. Pinned, not HEAD. */
const BASELINE = "ed0636f";

const MUTATIONS = ["personal", "visitfields", "visitref", "member-tracked"];   // NAMED (Nov 23 2026, LR-2): see the header
const MUTATE = process.env.MUTATE || "";
const MUT = require("./_shared");
// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") MUT.runAllMutations(__filename, MUTATIONS);
if (MUTATE && MUTATIONS.indexOf(MUTATE) === -1) { console.error("Unknown MUTATE=" + MUTATE + ". Known: " + MUTATIONS.join(", ")); process.exit(2); }

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}
function mutate(src, from, to, what) {
  return MUT.replaceOnce(src, from, to, what);
}

let SERVER = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
const SERVER0 = execSync("git show " + BASELINE + ":server.js", { cwd: REPO, maxBuffer: 1 << 26 }).toString("utf8").replace(/\r\n/g, "\n");

if (MUTATE === "personal") SERVER = mutate(SERVER, "crypto.createHash(\"sha256\").update(\"leadradar:\" + String((lead && lead.post_uri) || \"\")).digest(\"hex\").slice(0, 10)",
  "String((lead && lead.author_handle) || \"\").slice(0, 10)", "personal");
if (MUTATE === "visitfields") SERVER = mutate(SERVER, ".insert({ ref: ref, landing_path: landingPath })",
  ".insert({ ref: ref, landing_path: landingPath, ip: req.ip, user_agent: req.headers[\"user-agent\"], referrer: req.headers.referer })", "visitfields");
if (MUTATE === "visitref") SERVER = mutate(SERVER, "    if (!ENGINE_VISIT_REF.test(ref)) return", "    if (!ref) return", "visitref");
// NAMED (Nov 23 2026, LR-2): the member reply path starts adding the tracking parameter
let REPLIES = fs.readFileSync(path.join(REPO, "lib", "leadRoutes.js"), "utf8").replace(/\r\n/g, "\n");
const SEND_OPEN = "  app.post(\"/api/leads/:id/send\", M, async function (req, res, next) {\n";
if (MUTATE === "member-tracked") REPLIES = mutate(REPLIES, SEND_OPEN, SEND_OPEN + "    var withOutreachTracking = function (x) { return x + \"?ref=lr-0000000000\"; };\n", "member-tracked");
if (MUTATE) console.log("\n!! MUTATION: " + MUTATE);

const SHARED = require.resolve("./_shared");
function shared() { delete require.cache[SHARED]; return require(SHARED); }
function defs(src, names, optional) {
  const { definitionOf } = shared();
  return names.map(function (n) {
    const d = definitionOf(src, n);
    if (!d && !(optional && optional.indexOf(n) !== -1)) throw new Error("EXTRACTION FAILED: " + n);
    return d || "";
  }).join("\n\n");
}

/* ── the real convertSingleLead, stubbed at the model, database and senders ── */
// NAMED (Nov 23 2026, LR-2): only the token and the link facets are lifted; the drafter and its destinations are removed.
const LIFTED = ["outreachRefToken", "detectOutreachLinkFacets"];
const NEW_NAMES = [];
function fakeDb() {
  function q() {
    const st = { one: null, insert: false };
    const b = { then(res, rej) { return Promise.resolve({ data: st.one ? (st.insert ? { id: "fake" } : null) : [], error: null, count: 0 }).then(res, rej); } };
    ["select", "eq", "neq", "gte", "lte", "gt", "in", "is", "not", "order", "limit", "update", "upsert", "delete"].forEach(k => { b[k] = () => b; });
    b.insert = () => { st.insert = true; return b; };
    b.maybeSingle = () => { st.one = "maybe"; return b; };
    b.single = () => { st.one = "single"; return b; };
    return b;
  }
  return { from: q, rpc: async () => ({ data: null, error: null }) };
}
function liftAll(src) {
  const ctx = { supabase: fakeDb(), RichText: RichText, URL: URL, crypto: crypto, console: { log() {}, warn() {}, error() {} }, process: { env: {} } };
  vm.createContext(ctx);
  vm.runInContext(defs(src, LIFTED, NEW_NAMES) + "\nthis.api = { convertSingleLead: null, detectOutreachLinkFacets, outreachRefToken: typeof outreachRefToken === 'function' ? outreachRefToken : null };", ctx);
  return ctx;
}
const LEAD = { id: "lead-1", post_uri: "at://did:plc:abcxyz123/app.bsky.feed.post/3kfixture", source: "bluesky", author_handle: "fixture-person.bsky.social",
  author_did: "did:plc:abcxyz123", post_text: "stripe froze my account, what do other brands use?", matched_keyword: "stripe froze my account", intent_score: 80, intent_reason: "asks" };
/* ── the route, lifted with a database that records what it is asked to write ── */
function routeHandler(src, insertError) {
  const { braceMatch } = shared();
  const start = src.indexOf("app.post(\"/api/engine-visits\", async function (req, res) {");
  if (start < 0) throw new Error("EXTRACTION FAILED: the engine-visits route");
  const open = src.indexOf("{", start);
  const body = src.slice(src.indexOf("async function", start), braceMatch(src, open));
  const inserts = [];
  const db = { from(t) { return { insert(p) { inserts.push({ table: t, payload: p }); return Promise.resolve({ error: insertError || null }); } }; } };
  const ctx = { supabase: db, console: { log() {}, warn() {}, error() {} } };
  vm.runInNewContext(defs(src, ["ENGINE_VISIT_REF", "ENGINE_VISIT_PATH"]) + "\nthis.handler = " + body + ";", ctx);
  return { handler: ctx.handler, inserts: inserts };
}
async function post(h, body) {
  let status = 200, payload;
  const res = { status(c) { status = c; return res; }, json(p) { payload = p; return res; }, end() { return res; } };
  await h.handler({ body: body, ip: "203.0.113.7", headers: { "user-agent": "FixtureBrowser/1.0", referer: "https://bsky.app/profile/x" } }, res);
  return { status: status, payload: payload };
}

(async function main() {
  await residue.sweepPrevious(SUBJECT_USER_ID);
  const now = liftAll(SERVER).api;

  console.log("\n══ 1. the token ══");
  const token = now.outreachRefToken(LEAD);
  const expected = "lr-" + crypto.createHash("sha256").update("leadradar:" + LEAD.post_uri).digest("hex").slice(0, 10);
  console.log("    token for the fixture lead: " + token);
  check("1. lr- and ten hex characters of SHA-256 over the post_uri", token === expected && /^lr-[0-9a-f]{10}$/.test(token), token);
  check("1. the same lead gives the same token, another lead a different one",
    now.outreachRefToken(Object.assign({}, LEAD)) === token && now.outreachRefToken(Object.assign({}, LEAD, { post_uri: LEAD.post_uri + "x" })) !== token);
  check("1. nothing of the handle, DID or post is in it", ["fixture", "person", "abcxyz", "did", "plc", "stripe"].every(s => token.indexOf(s) === -1), token);

  console.log("\n══ 2-6. the platform's own outreach is removed; a member's reply carries no parameter ══");
  // NAMED (Nov 23 2026, LR-2): BEFORE 2 to 6 ran convertSingleLead; AFTER they prove it and its tracking are gone.
  const { definitionOf } = shared();
  const goneNames = ["convertSingleLead", "withOutreachTracking", "OUTREACH_TRACKED_HOSTS", "OUTREACH_PRODUCT_DESTINATIONS", "OUTREACH_BIZFORCE_DESTINATION", "formatLeadHandle"];
  const still = goneNames.filter(n => !!definitionOf(SERVER, n));
  check("2. convertSingleLead, withOutreachTracking and the destinations it tracked are defined nowhere in server.js", still.length === 0, JSON.stringify(still));
  check("2. the platform send (POST /api/agents/sales/send-approved) is removed", SERVER.indexOf("app.post(\"/api/agents/sales/send-approved\"") === -1);
  const sendAt = REPLIES.indexOf(SEND_OPEN);
  const sendSrc = sendAt < 0 ? "" : REPLIES.slice(sendAt, shared().braceMatch(REPLIES, REPLIES.indexOf("{", sendAt)) + 1);
  check("3. the member send (lib/leadRoutes.js POST /api/leads/:id/send) posts the approved text with no parameter, no tracking and no link added",
    sendSrc.length > 200 && !/withOutreachTracking|outreachRefToken|\?ref=|ref=lr-|https?:\/\//.test(sendSrc), sendSrc.length);
  const linkText = "We built this: https://bizforceai.net/suppressed.html?ref=" + token;
  const lf4 = now.detectOutreachLinkFacets(linkText);
  check("4. detectOutreachLinkFacets (still used by the member Bluesky sender) links a whole URL, parameter included",
    lf4.length === 1 && lf4[0].features[0].uri === "https://bizforceai.net/suppressed.html?ref=" + token, JSON.stringify(lf4));

  console.log("\n══ 7. POST /api/engine-visits ══");
  const ok = routeHandler(SERVER);
  const r1 = await post(ok, { ref: token, path: "/", email: "someone@example.com", handle: "fixture-person" });
  console.log("    wrote: " + JSON.stringify(ok.inserts));
  check("7. a valid arrival is 204 and writes exactly { ref, landing_path } to engine_visits — no IP, user agent, referrer, or anything else sent",
    r1.status === 204 && ok.inserts.length === 1 && ok.inserts[0].table === "engine_visits" &&
    JSON.stringify(Object.keys(ok.inserts[0].payload).sort()) === JSON.stringify(["landing_path", "ref"]) && ok.inserts[0].payload.ref === token, JSON.stringify(ok.inserts));
  const page = routeHandler(SERVER);
  const pagePath = "/suppressed.html";   // NAMED (Nov 23 2026, LR-2): BEFORE new URL(DEST).pathname; DEST (the BizForceAI destination at 65c0825) is removed
  const r2 = await post(page, { ref: token, path: pagePath });
  const routeRe = (function () { const c = {}; vm.runInNewContext(defs(SERVER, ["ENGINE_VISIT_PATH"]) + "\nthis.v = ENGINE_VISIT_PATH;", c); return c.v; })();
  const MIG128 = fs.readFileSync(path.join(REPO, "supabase", "migrations", "128_engine_visits.sql"), "utf8");
  const dbRe = new RegExp((/landing_path ~ '([^']+)'/.exec(MIG128) || [])[1]);
  console.log("    landing page path " + JSON.stringify(pagePath) + " against the route's " + routeRe + " and the table's " + dbRe);
  check("7. the landing page's own path " + pagePath + " is accepted by the route's regex and by the table's constraint, and written as sent",
    routeRe.test(pagePath) && dbRe.test(pagePath) && r2.status === 204 && page.inserts.length === 1 && page.inserts[0].payload.landing_path === pagePath, JSON.stringify(page.inserts));
  const bad = routeHandler(SERVER);
  const refused = [];
  for (const b of [{ ref: "LR-0123456789", path: "/" }, { ref: "lr-012345678", path: "/" }, { ref: "x", path: "/" }, { path: "/" },
    { ref: token, path: "/?ref=" + token }, { ref: token, path: "/#top" }, { ref: token, path: "start" }, { ref: token, path: "/" + "a".repeat(200) }]) {
    refused.push((await post(bad, b)).status);
  }
  check("7. a malformed ref, or a path with a query, fragment, no leading slash or over 200 characters, is 400 and writes nothing",
    refused.every(s => s === 400) && bad.inserts.length === 0, JSON.stringify(refused) + " inserts " + bad.inserts.length);
  const missing = routeHandler(SERVER, { code: "PGRST205", message: "Could not find the table 'public.engine_visits'" });
  const r3 = await post(missing, { ref: token, path: "/" });
  check("7. while the table does not exist the route answers 503 and names migration 128", r3.status === 503 && /migration 128/.test((r3.payload || {}).error || ""), JSON.stringify(r3));

  console.log("\n══ 8. migration 128: the table it defines, and whether the live database has it ══");
  const MIG = fs.readFileSync(path.join(REPO, "supabase", "migrations", "128_engine_visits.sql"), "utf8").replace(/\r\n/g, "\n");
  const cols = (/create table if not exists public\.engine_visits \(([\s\S]*?)\n\);/.exec(MIG) || [])[1] || "";
  const names = cols.split("\n").map(l => (l.trim().match(/^([a-z_]+)\s/) || [])[1]).filter(Boolean);
  check("8. the table holds id, ref, landing_path, arrived_on, created_at and nothing else", JSON.stringify(names) === JSON.stringify(["id", "ref", "landing_path", "arrived_on", "created_at"]), JSON.stringify(names));
  check("8. ref and landing_path are constrained to the shapes the route accepts",
    /ref ~ '\^lr-\[0-9a-f\]\{10\}\$'/.test(MIG) && /landing_path ~ '\^\/\[A-Za-z0-9\/\._-\]\*\$'/.test(MIG));
  check("8. RLS on, anon and authenticated revoked, no policy",
    /enable row level security/.test(MIG) && /revoke all on public\.engine_visits from anon, authenticated;/.test(MIG) && !/create policy/i.test(MIG));
  /* A row read, not a head count: a head request for a missing table comes back
     with no error body at all, which reads as "exists". */
  const live = await supabase.from("engine_visits").select("id").limit(1);
  console.log("    live database: engine_visits " + (live.error ? "does not exist (" + (live.error.code || live.error.message) + ") — 128 not applied" : "exists"));

  console.log("\n══ cleanup ══");
  const cleanupResult = await residue.cleanup("end of run");
  if (cleanupResult.leftovers.length) failures++;
  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
})().catch(function (err) {
  console.error("\nThe check threw: " + ((err && err.stack) || err));
  process.exit(1);
});
