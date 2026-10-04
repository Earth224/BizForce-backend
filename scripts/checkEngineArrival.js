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

   MUTATIONS — each must turn the named section red:
     MUTATE=order        tracking runs before rejection               → 2, 3, 4
     MUTATE=everydomain  every reply gets a parameter, any host        → 5
     MUTATE=personal     the token is the lead's handle                → 1, 7
     MUTATE=lengthguard  the 300-character guard is gone               → 6
     MUTATE=visitfields  the route also stores IP and user agent       → 7
     MUTATE=visitref     the route accepts any ref                     → 7
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

const MUTATIONS = ["order", "everydomain", "personal", "lengthguard", "visitfields", "visitref"];
const MUTATE = process.env.MUTATE || "";
if (MUTATE && MUTATIONS.indexOf(MUTATE) === -1) { console.error("Unknown MUTATE=" + MUTATE + ". Known: " + MUTATIONS.join(", ")); process.exit(2); }

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}
function mutate(src, from, to, what) {
  if (src.split(from).length !== 2) { console.error("MUTATION REFUSED (" + what + "): anchor not found exactly once."); process.exit(3); }
  return src.replace(from, () => to);
}

let SERVER = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
const SERVER0 = execSync("git show " + BASELINE + ":server.js", { cwd: REPO, maxBuffer: 1 << 26 }).toString("utf8").replace(/\r\n/g, "\n");

const TRACK_BLOCK = "  if (cleanMessage && offerKind === \"bizforce\") {\n    cleanMessage = withOutreachTracking(cleanMessage, OUTREACH_BIZFORCE_DESTINATION, lead);\n  }\n";
if (MUTATE === "order") {
  SERVER = mutate(SERVER, TRACK_BLOCK, "", "order");
  SERVER = mutate(SERVER, "  var draftRejection = cleanMessage\n", TRACK_BLOCK + "  var draftRejection = cleanMessage\n", "order");
}
if (MUTATE === "everydomain") {
  SERVER = mutate(SERVER, TRACK_BLOCK, "  if (cleanMessage) {\n    cleanMessage = withOutreachTracking(cleanMessage, offerKind === \"book\" ? OUTREACH_BOOK_DESTINATION : OUTREACH_PRODUCT_DESTINATIONS[suggestedProduct], lead);\n  }\n", "everydomain");
  SERVER = mutate(SERVER, "  if (OUTREACH_TRACKED_HOSTS.indexOf(host) === -1 || dest.search || dest.hash) return text;", "  if (dest.search || dest.hash) return text;", "everydomain");
}
if (MUTATE === "personal") SERVER = mutate(SERVER, "crypto.createHash(\"sha256\").update(\"leadradar:\" + String((lead && lead.post_uri) || \"\")).digest(\"hex\").slice(0, 10)",
  "String((lead && lead.author_handle) || \"\").slice(0, 10)", "personal");
if (MUTATE === "lengthguard") SERVER = mutate(SERVER, "  if (Array.from(out).length > 300) {", "  if (false) {", "lengthguard");
if (MUTATE === "visitfields") SERVER = mutate(SERVER, ".insert({ ref: ref, landing_path: landingPath })",
  ".insert({ ref: ref, landing_path: landingPath, ip: req.ip, user_agent: req.headers[\"user-agent\"], referrer: req.headers.referer })", "visitfields");
if (MUTATE === "visitref") SERVER = mutate(SERVER, "    if (!ENGINE_VISIT_REF.test(ref)) return", "    if (!ref) return", "visitref");
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
const LIFTED = ["formatLeadHandle", "OUTREACH_BOOK_PRODUCT", "OUTREACH_SUPPLEMENT_PRODUCTS", "OUTREACH_DAILY_CAP", "OUTREACH_PRODUCT_FACTS",
  "OUTREACH_HOME_URL", "OUTREACH_BIZFORCE_PRODUCT", "OUTREACH_PRODUCT_DESTINATIONS", "OUTREACH_BIZFORCE_DESTINATION", "OUTREACH_BOOK_DESTINATION",
  "OUTREACH_OWN_DOMAINS", "outreachDraftRejection", "OUTREACH_TRACKED_HOSTS", "outreachRefToken", "withOutreachTracking", "nowIso",
  "DRAFT_ATTEMPT_CEILING", "OUTREACH_EMOJI_PATTERN", "stripOutreachEmoji", "truncateOrchestratorPreview", "normalizeMemoryMetadata",
  "detectOutreachLinkFacets", "convertSingleLead"];
const NEW_NAMES = ["OUTREACH_TRACKED_HOSTS", "outreachRefToken", "withOutreachTracking"];
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
  vm.runInContext(defs(src, LIFTED, NEW_NAMES) + "\nthis.api = { convertSingleLead, detectOutreachLinkFacets, outreachRefToken: typeof outreachRefToken === 'function' ? outreachRefToken : null };", ctx);
  return ctx;
}
const LEAD = { id: "lead-1", post_uri: "at://did:plc:abcxyz123/app.bsky.feed.post/3kfixture", source: "bluesky", author_handle: "fixture-person.bsky.social",
  author_did: "did:plc:abcxyz123", post_text: "stripe froze my account, what do other brands use?", matched_keyword: "stripe froze my account", intent_score: 80, intent_reason: "asks" };
async function draftRun(src, product, modelMessage, lead) {
  const ctx = liftAll(src), prompts = [], sends = [];
  ctx.canSendOutreach = async () => ({ allowed: true });
  ctx.callAnthropicText = async p => { prompts.push(p); return { text: JSON.stringify({ outreach_message: modelMessage, internal_analysis: "fixture" }), stopReason: "end_turn" }; };
  ctx.sendBlueskyReply = async (l, text) => { sends.push(text); return { sent: true, uri: "at://fake/post" }; };
  ctx.sendMastodonReply = async (l, text) => { sends.push(text); return { sent: true, uri: "https://fake/post" }; };
  const r = await ctx.api.convertSingleLead(SUBJECT_USER_ID, Object.assign({}, lead || LEAD, { suggested_product: product }), "SHARED SYSTEM PROMPT", false);
  return { prompt: prompts[0] || null, sends: sends, sent: !!(r && r.sent), reason: r && r.send_reason };
}

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

  console.log("\n══ 2. rejection runs first ══");
  const csl = defs(SERVER, ["convertSingleLead"]);
  const iReject = csl.indexOf("  var draftRejection = cleanMessage\n"), iTrack = csl.indexOf("withOutreachTracking(cleanMessage"), iSend = csl.indexOf("sendBlueskyReply(lead, cleanMessage)");
  check("2. in convertSingleLead: the rejection, then the tracking, then the send", iReject > 0 && iTrack > iReject && iSend > iTrack, JSON.stringify([iReject, iTrack, iSend]));
  const own = [];
  for (const m of ["We built this for that: https://bizforceai.net/?ref=lr-0123456789", "We built this: https://bizforceai.net/?utm_source=bluesky", "bizforceai.net/#start"]) {
    const r = await draftRun(SERVER, "BizForceAI", m);
    own.push(!r.sent && r.sends.length === 0 && r.reason === "draft_rejected");
  }
  check("2. a parameter or fragment the model wrote itself is still held, never sent", own.every(Boolean), JSON.stringify(own));

  console.log("\n══ 3. the code adds the parameter ══");
  const tracked = "https://bizforceai.net/?ref=" + token;
  const forms = ["https://bizforceai.net/", "bizforceai.net", "BizForceAI.net/", "https://www.bizforceai.net"];
  const got = [];
  for (const f of forms) {
    const r = await draftRun(SERVER, "BizForceAI", "Owned channels can't be switched off by an ad network. We built BizForceAI for that: " + f);
    got.push(r.sent && r.sends.length === 1 && r.sends[0].split(tracked).length === 2 && !/bizforceai\.net(?!\/\?ref=)/i.test(r.sends[0].split(tracked).join("")) ? "ok" : (r.sends[0] || r.reason));
  }
  check("3. every form the model may write — " + forms.join(", ") + " — goes out as " + tracked, got.every(g => g === "ok"), JSON.stringify(got));
  const sample = await draftRun(SERVER, "BizForceAI", "We built BizForceAI for exactly this: https://bizforceai.net/");
  console.log("    sent: " + (sample.sends[0] || "(nothing)"));

  console.log("\n══ 4. the final URL is a link, parameter included ══");
  const text = sample.sends[0] || "";
  const facets = now.detectOutreachLinkFacets(text);
  const linked = facets.map(f => ({ uri: f.features[0].uri, span: Buffer.from(text, "utf8").slice(f.index.byteStart, f.index.byteEnd).toString("utf8") }));
  console.log("    facets: " + JSON.stringify(linked));
  check("4. one link facet, whose uri and whose linked text are both the full tracked URL", linked.length === 1 && linked[0].uri === tracked && linked[0].span === tracked, JSON.stringify(linked));

  console.log("\n══ 5. supplement and book replies are unchanged ══");
  const SUPP = (function () { const c = {}; vm.runInNewContext(defs(SERVER0, ["OUTREACH_SUPPLEMENT_PRODUCTS"]) + "\nthis.v = OUTREACH_SUPPLEMENT_PRODUCTS;", c); return c.v; })();
  let same = 0, anyRef = false;
  for (const p of SUPP.concat(["Quantum Jumping book"])) {
    const msg = p === "Quantum Jumping book" ? "That frustration is common. BlackSunCircle.com" : "Many people like it. https://mrearthrose.com/";
    const a = await draftRun(SERVER, p, msg), b = await draftRun(SERVER0, p, msg);
    if (a.prompt === b.prompt && JSON.stringify(a.sends) === JSON.stringify(b.sends) && a.sent && b.sent) same++;
    if (a.sends.some(s => /[?&]ref=/.test(s))) anyRef = true;
  }
  check("5. for all six supplement products and the book, prompt and reply sent are identical to " + BASELINE, same === SUPP.length + 1, same + " of " + (SUPP.length + 1));
  check("5. and no supplement or book reply carries a parameter", !anyRef);

  console.log("\n══ 6. the 300-character guard ══");
  const pad = "We built BizForceAI for businesses ad networks won't serve, and owned channels are the answer: search content and an email list nobody can switch off. ";
  /* The link stands as its own word, as the model writes it: a domain glued to
     the word before it is not a mention, and would make this test vacuous. */
  let long = pad;
  while (Array.from(long + "x https://bizforceai.net/").length <= 290) long += "x";
  long += " https://bizforceai.net/";
  const trackedLong = long.replace("https://bizforceai.net/", tracked);
  check("6. (the fixture is real: tracked, this draft would exceed 300 characters, and its link is a mention)",
    Array.from(trackedLong).length > 300 && Array.from(long).length <= 300 && / https:\/\/bizforceai\.net\/$/.test(long));
  const lr = await draftRun(SERVER, "BizForceAI", long);
  console.log("    a " + Array.from(long).length + "-character draft; with the parameter it would be " + Array.from(long.replace("https://bizforceai.net/", tracked)).length);
  check("6. it is sent without the parameter, its link whole, rather than truncated through the link",
    lr.sent && lr.sends.length === 1 && lr.sends[0] === long && !/\?ref=/.test(lr.sends[0]), lr.sends[0] ? Array.from(lr.sends[0]).length + " chars" : lr.reason);

  console.log("\n══ 7. POST /api/engine-visits ══");
  const ok = routeHandler(SERVER);
  const r1 = await post(ok, { ref: token, path: "/", email: "someone@example.com", handle: "fixture-person" });
  console.log("    wrote: " + JSON.stringify(ok.inserts));
  check("7. a valid arrival is 204 and writes exactly { ref, landing_path } to engine_visits — no IP, user agent, referrer, or anything else sent",
    r1.status === 204 && ok.inserts.length === 1 && ok.inserts[0].table === "engine_visits" &&
    JSON.stringify(Object.keys(ok.inserts[0].payload).sort()) === JSON.stringify(["landing_path", "ref"]) && ok.inserts[0].payload.ref === token, JSON.stringify(ok.inserts));
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

  console.log("\n══ 8. migration 128, written and not applied ══");
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
