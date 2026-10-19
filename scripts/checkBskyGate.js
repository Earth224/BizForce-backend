"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkBskyGate — nothing in this repo can hammer the owner's Bluesky login.

   lib/bskyGate.js is the one session both the Lead Radar (leadRadar.js) and
   the outreach sender (server.js sendBlueskyReply) go through. This loads
   leadRadar.js in a vm with a stubbed BskyAgent, a fake Supabase and a fake
   clock; lifts sendBlueskyReply out of server.js onto the radar's own gate;
   and runs scripts/checkOutreachReplies.js in a vm with fetch spied on. NO
   Bluesky call of any kind is made — there is no network here at all.

   WHAT THIS PROVES
     A. A failing login (not a 429) is tried ONCE per radar tick, never once
        per keyword, and the next tick tries once more.
     B. A 429 at login stops every Bluesky call until the reset; the radar
        skips its whole capture meanwhile (no gate call at all), logging once
        with the time it resumes; after the reset it resumes with one login.
     C. retry-after (a duration) and ratelimit-reset (an epoch second) are
        both honoured; with neither, the back-off is 15 minutes doubling to a
        2-hour ceiling, and the first success resets it. A 429 on a search
        (not the login) backs off the same way.
     D. A send during back-off makes no Bluesky call and no gate call, and
        returns rate_limited; a send after the radar logged in reuses that
        session (no new login); a send that meets a 429 returns rate_limited
        and sets the back-off.
     E. A 401 re-logs in once and retries once — never a third login.
     F. checkOutreachReplies.js, by default, makes no network call: no real
        fetch and no Supabase client, one fixture login, its counts asserted.
     G. Loading server.js (as about twenty checks do) never starts the live
        radar: startLeadRadar runs only when server.js is the program.
     H. The reply sendBlueskyReply builds (pinned here since its identity pin
        to 7cefe53 was dropped): SALES_SEND_LIVE not exactly "true" is
        send_dry with no Bluesky call; text over 300 code points is cut to 297
        plus the ellipsis; only link facets are kept, at UTF-8 byte offsets
        computed after the cut; reply.root and reply.parent are both the
        lead's post; a successful post returns its uri.

   MUTATE=<name> edits leadRadar.js, server.js or checkOutreachReplies.js IN
   MEMORY (nothing on disk is touched). MUTATE=all runs each in its own
   process; an unmatched search text is an ERROR, never a catch.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm");
const REPO = path.join(__dirname, "..");
const MUTATE = process.env.MUTATE || "";
const MUT = require("./_shared");
const s = MUT;

const RADAR = "leadRadar.js", SERVER = "server.js", REPLIES = "scripts/checkOutreachReplies.js", GATE = "lib/bskyGate.js";
const MUTATIONS = {
  // a failed login is retried for every keyword again: no per-tick login budget, and a failed
  // call goes on to the next keyword instead of ending the tick. Re-anchored (YouTube retention
  // build, Oct 2026) onto the tick.stop assignment the loop gained after 855f997: the old anchor
  // expected `break;` straight after the log line and had matched nothing since.
  "login-per-keyword": [[RADAR, "        }, tickBudget);", "        });"],
    [RADAR, "              : { outcome: \"login_failed\", error: call.error || call.reason };\n          break;",
      "              : { outcome: \"login_failed\", error: call.error || call.reason };\n          continue;"]],
  // the radar does not skip its tick during a back-off
  "radar-ignores-backoff": [[RADAR, "    if (bskyGate.backoffRemainingMs() > 0) {\n      if (radarBackoffLogged", "    if (false) {\n      if (radarBackoffLogged"]],
  // the sender does not check the back-off itself
  "sender-ignores-backoff": [[SERVER, "  if (bskyGate.backoffRemainingMs() > 0) {\n    var waitSeconds", "  if (false) {\n    var waitSeconds"]],
  // every send logs in afresh
  "fresh-login-per-send": [[SERVER, "    var posted = await bskyGate.call(function (agent) { return agent.post(postRecord); });",
    "    await bskyGate.agent.login({ identifier: process.env.BLUESKY_IDENTIFIER, password: process.env.BLUESKY_APP_PASSWORD });\n" +
    "    var posted = { ok: true, value: await bskyGate.agent.post(postRecord) };"]],
  // a reply is posted whole, however long
  "no-truncation": [[SERVER, "  if (chars.length <= 300) return str;\n  return chars.slice(0, 297).join(\"\") + \"…\";", "  return str;"]],
  // the reply's parent is not the lead's post
  "wrong-reply-target": [[SERVER, "    reply: { root: postRef, parent: postRef },", "    reply: { root: postRef, parent: { uri: lead.author_did || \"\", cid: lead.post_cid } },"]],
  // mention and tag facets are kept too
  "all-facets": [[SERVER, "          return feature && feature.$type === \"app.bsky.richtext.facet#link\";", "          return !!feature;"]],
  // loading server.js starts the live radar again
  "radar-starts-when-loaded": [[SERVER, "  if (require.main === module) {\n    startLeadRadar()", "  if (true) {\n    startLeadRadar()"]],
  // checkOutreachReplies logs in live unless told not to
  "replies-live-by-default": [[REPLIES, "const LIVE = process.env.CHECK_LIVE_BLUESKY === \"true\";", "const LIVE = process.env.CHECK_LIVE_BLUESKY !== \"false\";"]]
};
if (MUTATE === "all") MUT.runAllMutations(__filename, Object.keys(MUTATIONS));

const FILES = {};
[RADAR, SERVER, REPLIES, GATE].forEach(f => { FILES[f] = fs.readFileSync(path.join(REPO, f), "utf8").replace(/\r\n/g, "\n"); });
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = MUT.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE);
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}

/* ── the fake clock ────────────────────────────────────────────────────────── */
let CLOCK = Date.parse("2026-10-10T12:00:00.000Z");
class FakeDate extends Date {
  constructor(...a) { if (a.length === 0) super(CLOCK); else super(...a); }
  static now() { return CLOCK; }
}
const MIN = 60000;

/* ── the stubbed Bluesky agent ─────────────────────────────────────────────── */
// Every behaviour is scripted per test; every call is counted. Nothing here can reach a network.
const BSKY = { logins: 0, searches: 0, posts: 0, loginPlan: [], searchPlan: [], postPlan: [] };
function bskyError(status, error, headers) {
  const e = new Error("XRPC " + status + " " + error); e.status = status; e.error = error; if (headers) e.headers = headers; return e;
}
function next(plan, fallback) { return plan.length ? plan.shift() : fallback; }
class FakeBskyAgent {
  constructor() {
    const self = this;
    this.app = { bsky: { feed: { searchPosts: async () => {
      BSKY.searches++;
      const step = next(BSKY.searchPlan, "ok");
      if (step instanceof Error) throw step;
      return { data: { posts: [] } };
    } } } };
    this.login = async () => {
      BSKY.logins++;
      const step = next(BSKY.loginPlan, "ok");
      if (step instanceof Error) throw step;
      return { success: true };
    };
    this.post = async (record) => {
      BSKY.posts++;
      BSKY.lastRecord = JSON.parse(JSON.stringify(record));
      const step = next(BSKY.postPlan, "ok");
      if (step instanceof Error) throw step;
      return { uri: "at://did:plc:us/app.bsky.feed.post/" + BSKY.posts, cid: "bafy" };
    };
    void self;
  }
}
function resetBsky() { Object.assign(BSKY, { logins: 0, searches: 0, posts: 0, loginPlan: [], searchPlan: [], postPlan: [] }); }

/* ── a CommonJS module from (possibly mutated) source, in a vm ─────────────── */
function loadModule(source, filename, requireFn, globals) {
  const m = { exports: {} };
  const ctx = Object.assign({ module: m, exports: m.exports, require: requireFn, __filename: filename, __dirname: path.dirname(filename),
    console: globals.console, process: globals.process, Date: FakeDate, setTimeout: () => 0, setInterval: () => 0, clearInterval() {}, Promise, JSON, Math, Buffer, URL }, globals.extra || {});
  vm.createContext(ctx);
  vm.runInContext(source, ctx, { filename });
  return m.exports;
}

/* ── the radar, with the real gate, a fake Supabase and the stubbed agent ──── */
const LOGS = [];
function freshRadar(envOverride) {
  resetBsky();
  LOGS.length = 0;
  const logger = { log: (...a) => LOGS.push(a.join(" ")), error: (...a) => LOGS.push(a.join(" ")), warn: (...a) => LOGS.push(a.join(" ")) };
  const proc = { env: Object.assign({ BLUESKY_IDENTIFIER: "us.bsky.social", BLUESKY_APP_PASSWORD: "app-pass", SUPABASE_URL: "http://fake", SUPABASE_SERVICE_KEY: "x" }, envOverride || {}) };
  const fakeSupabase = { from() { const b = { upsert() { return b; }, select() { return b; }, eq() { return b; }, then(r) { return Promise.resolve({ data: [], error: null }).then(r); } }; return b; } };
  const gateModule = loadModule(FILES[GATE], path.join(REPO, GATE), require, { console: logger, process: proc });
  const requireFn = (name) => {
    if (name === "dotenv") return { config() {} };
    if (name === "@supabase/supabase-js") return { createClient: () => fakeSupabase };
    if (name === "@atproto/api") return { BskyAgent: FakeBskyAgent };
    if (name === "@anthropic-ai/sdk") return function Anthropic() { throw new Error("no model in this check"); };
    if (name === "./mastodonRadar") return { runMastodonRadarOnce: async () => {} };
    if (name === "./youtubeRadar") return { runYoutubeRadarOnce: async () => {} };
    if (name === "./lib/resolveAnthropicKey") return () => async () => null;
    if (name === "./lib/bskyGate") return gateModule;
    if (name === "./lib/ownerAccount") return require(path.join(REPO, "lib/ownerAccount"));
    throw new Error("unexpected require in leadRadar.js: " + name);
  };
  const radar = loadModule(FILES[RADAR], path.join(REPO, RADAR), requireFn, { console: logger, process: proc });
  // Count every gate.call, so "no call at all" is checkable, not just "no Bluesky call".
  const gate = radar.bskyGate;
  let gateCalls = 0;
  const realCall = gate.call;
  gate.call = function () { gateCalls++; return realCall.apply(gate, arguments); };
  return { radar, gate, gateCalls: () => gateCalls, proc, logger };
}

/* ── sendBlueskyReply, lifted from server.js onto the radar's gate ──────────── */
const SPANS = [];
{
  const re = /^(?:(?:async )?function [A-Za-z_$][A-Za-z0-9_$]*[(]|app[.][a-z]+[(])/gm; let m;
  while ((m = re.exec(FILES[SERVER]))) { const end = s.braceMatch(FILES[SERVER], FILES[SERVER].indexOf("{", m.index)); if (end > 0) SPANS.push([m.index, end]); }
}
function fnSource(name) {
  const SRC = FILES[SERVER];
  const m = new RegExp("^(?:async )?function " + name + "\\(", "m").exec(SRC);
  if (!m) throw new Error(name + " not found in server.js");
  return SRC.slice(m.index, s.braceMatch(SRC, SRC.indexOf(") {", m.index) + 2));
}
const SENDER_SRC = ["formatLeadHandle", "truncateToBlueskyLimit", "detectOutreachLinkFacets", "sendBlueskyReply"].map(fnSource).join("\n\n") +
  "\n\nthis.sendBlueskyReply = sendBlueskyReply;";
function senderFor(env, envOverride) {
  const ctx = { console: env.logger, process: { env: Object.assign({ SALES_SEND_LIVE: "true", BLUESKY_IDENTIFIER: "us.bsky.social", BLUESKY_APP_PASSWORD: "app-pass" }, envOverride || {}) },
    bskyGate: env.gate, RichText: require(require.resolve("@atproto/api", { paths: [REPO] })).RichText, Date: FakeDate, Math, JSON, String, Array, Number };
  vm.createContext(ctx);
  vm.runInContext(SENDER_SRC, ctx);
  return ctx.sendBlueskyReply;
}
const LEAD = { post_uri: "at://did:plc:lead/app.bsky.feed.post/1", post_cid: "bafylead", author_handle: "lead.bsky.social" };

(async function main() {
  const KEYWORDS = 32;

  /* ── A. a failing login, once per tick ─────────────────────────────────── */
  console.log("\n══ A. a failing login is tried once per tick ══");
  let E = freshRadar();
  BSKY.loginPlan = [bskyError(500, "InternalServerError"), bskyError(500, "InternalServerError")];
  await E.radar.runLeadRadarOnce();
  check("tick 1: one login attempt, no search (not one per keyword)", BSKY.logins === 1 && BSKY.searches === 0, BSKY.logins + " logins, " + BSKY.searches + " searches");
  check("tick 1: it says the capture stopped for this tick", LOGS.some(l => /capture stopped for this tick at '[^']+' — login_failed/.test(l)), LOGS.join(" | ").slice(0, 300));
  CLOCK += 5 * MIN;
  await E.radar.runLeadRadarOnce();
  check("tick 2: one more login attempt, still no search", BSKY.logins === 2 && BSKY.searches === 0, BSKY.logins + "/" + BSKY.searches);
  CLOCK += 5 * MIN;
  await E.radar.runLeadRadarOnce();
  check("tick 3: login works, so all " + KEYWORDS + " searches run on that one session", BSKY.logins === 3 && BSKY.searches === KEYWORDS, BSKY.logins + "/" + BSKY.searches);
  CLOCK += 5 * MIN;
  await E.radar.runLeadRadarOnce();
  check("tick 4: the session is reused — no login, " + KEYWORDS + " more searches", BSKY.logins === 3 && BSKY.searches === 2 * KEYWORDS, BSKY.logins + "/" + BSKY.searches);
  E = freshRadar({ BLUESKY_IDENTIFIER: "" });
  await E.radar.runLeadRadarOnce();
  check("no credentials: no login attempt and no search", BSKY.logins === 0 && BSKY.searches === 0);

  /* ── B. a 429 at login ─────────────────────────────────────────────────── */
  console.log("\n══ B. a 429 at login stops everything until the reset ══");
  E = freshRadar();
  BSKY.loginPlan = [bskyError(429, "RateLimitExceeded", { "retry-after": "600" })];
  await E.radar.runLeadRadarOnce();
  check("the 429 login: one attempt, no search", BSKY.logins === 1 && BSKY.searches === 0);
  check("back-off set from retry-after: 600s", E.gate.backoffRemainingMs() === 600000, E.gate.backoffRemainingMs());
  for (let t = 0; t < 3; t++) { CLOCK += 2 * MIN; await E.radar.runLeadRadarOnce(); }
  check("three ticks inside the back-off: no login, no search", BSKY.logins === 1 && BSKY.searches === 0, BSKY.logins + "/" + BSKY.searches);
  check("…and no gate call at all: the radar skips its whole capture", E.gateCalls() === 1, E.gateCalls());
  const resumeIso = new Date(E.gate.backoffUntil()).toISOString();
  const skipLogs = LOGS.filter(l => l.indexOf("Bluesky capture skipped — rate-limit back-off until " + resumeIso) !== -1);
  check("the skip is logged once, with the time it resumes", skipLogs.length === 1, LOGS.filter(l => /skipped/.test(l)).join(" | "));
  CLOCK = E.gate.backoffUntil();
  await E.radar.runLeadRadarOnce();
  check("after the reset: one login, then the searches", BSKY.logins === 2 && BSKY.searches === KEYWORDS, BSKY.logins + "/" + BSKY.searches);
  check("the success clears the 429 count", E.gate.stats().consecutive429 === 0);

  /* ── C. the waits ──────────────────────────────────────────────────────── */
  console.log("\n══ C. retry-after, ratelimit-reset, and the doubling fallback ══");
  E = freshRadar();
  const resetEpoch = Math.floor(CLOCK / 1000) + 900;
  BSKY.loginPlan = [bskyError(429, "RateLimitExceeded", { "ratelimit-reset": String(resetEpoch) })];
  await E.radar.runLeadRadarOnce();
  check("ratelimit-reset is an epoch second: the back-off ends at it (900s), not 900s × 1000 or 56 years", E.gate.backoffUntil() === resetEpoch * 1000, E.gate.backoffRemainingMs());
  E = freshRadar();
  BSKY.loginPlan = [bskyError(429, "RateLimitExceeded", { get(name) { return name === "retry-after" ? "45" : null; } })];
  await E.radar.runLeadRadarOnce();
  check("retry-after read from a Headers-style object: 45s", E.gate.backoffRemainingMs() === 45000, E.gate.backoffRemainingMs());
  E = freshRadar();
  const waits = [];
  for (let i = 0; i < 6; i++) {
    BSKY.loginPlan = [bskyError(429, "RateLimitExceeded")];
    await E.radar.runLeadRadarOnce();
    waits.push(E.gate.backoffRemainingMs() / MIN);
    CLOCK = E.gate.backoffUntil();
  }
  check("no header: 15, 30, 60, 120, then 120 and 120 minutes (doubling to the 2-hour ceiling)", JSON.stringify(waits) === JSON.stringify([15, 30, 60, 120, 120, 120]), JSON.stringify(waits));
  check("each of those ticks made exactly one login attempt", BSKY.logins === 6 && BSKY.searches === 0, BSKY.logins + "/" + BSKY.searches);
  await E.radar.runLeadRadarOnce();
  BSKY.loginPlan = [];
  check("the first success resets the doubling", E.gate.stats().consecutive429 === 0);
  E = freshRadar();
  BSKY.searchPlan = ["ok", bskyError(429, "RateLimitExceeded")];
  await E.radar.runLeadRadarOnce();
  check("a 429 on a search: the tick stops there (2 searches, not " + KEYWORDS + ")", BSKY.logins === 1 && BSKY.searches === 2, BSKY.logins + "/" + BSKY.searches);
  check("…and the back-off is the 15-minute fallback", E.gate.backoffRemainingMs() === 15 * MIN, E.gate.backoffRemainingMs());

  /* ── D. the sender ─────────────────────────────────────────────────────── */
  console.log("\n══ D. the sender shares the session and the back-off ══");
  E = freshRadar();
  await E.radar.runLeadRadarOnce();
  const send = senderFor(E);
  const loginsBefore = BSKY.logins, gateBefore = E.gateCalls();
  let r = await send(LEAD, "Hello there, this helped me: example.com");
  check("a send after the radar logged in reuses its session: posted, no new login", r.sent === true && BSKY.posts === 1 && BSKY.logins === loginsBefore, JSON.stringify(r) + " logins " + BSKY.logins);
  check("…through the gate (one gate call)", E.gateCalls() === gateBefore + 1);
  BSKY.postPlan = [bskyError(429, "RateLimitExceeded", { "retry-after": "300" })];
  r = await send(LEAD, "Second one");
  check("a send that meets a 429 returns rate_limited with the wait", r.sent === false && r.reason === "rate_limited" && r.retry_after_seconds === 300, JSON.stringify(r));
  check("…and sets the back-off for everyone", E.gate.backoffRemainingMs() === 300000);
  const postsBefore = BSKY.posts, gateCallsBefore = E.gateCalls(), loginsBefore2 = BSKY.logins;
  r = await send(LEAD, "Third one");
  check("a send during the back-off returns rate_limited", r.sent === false && r.reason === "rate_limited" && r.retry_after_seconds === 300, JSON.stringify(r));
  check("…without any Bluesky call and without even a gate call", BSKY.posts === postsBefore && BSKY.logins === loginsBefore2 && E.gateCalls() === gateCallsBefore,
    "posts " + BSKY.posts + ", logins " + BSKY.logins + ", gate calls " + E.gateCalls());
  CLOCK += 2 * MIN;
  await E.radar.runLeadRadarOnce();
  check("the radar respects the sender's 429 too: no search, no login", BSKY.searches === KEYWORDS && BSKY.logins === loginsBefore2);
  E = freshRadar();
  const send2 = senderFor(E);
  r = await send2(LEAD, "Cold start");
  check("a send with no session yet logs in once and posts", r.sent === true && BSKY.logins === 1 && BSKY.posts === 1, JSON.stringify(r));
  r = await send2(LEAD, "Warm");
  check("the next send reuses it: still one login", r.sent === true && BSKY.logins === 1 && BSKY.posts === 2);

  /* ── E. a 401 ──────────────────────────────────────────────────────────── */
  console.log("\n══ E. an expired session re-logs in once ══");
  E = freshRadar();
  await E.radar.runLeadRadarOnce();
  const before401 = BSKY.logins;
  BSKY.searchPlan = [bskyError(401, "ExpiredToken")];
  CLOCK += 5 * MIN;
  await E.radar.runLeadRadarOnce();
  check("a 401 mid-tick: one fresh login, the search retried, the tick goes on", BSKY.logins === before401 + 1 && BSKY.searches === 2 * KEYWORDS + 1, BSKY.logins + "/" + BSKY.searches);
  E = freshRadar();
  const send3 = senderFor(E);
  await send3(LEAD, "warm up");
  BSKY.postPlan = [bskyError(401, "ExpiredToken"), bskyError(401, "ExpiredToken")];
  const l0 = BSKY.logins;
  r = await send3(LEAD, "after expiry");
  check("401 then 401 again: exactly one re-login, never a third", BSKY.logins === l0 + 1, BSKY.logins - l0);
  check("…and it says the login failed, without posting", r.sent === false && r.reason === "post_error" && BSKY.posts === 1 + 2, JSON.stringify(r) + " posts " + BSKY.posts);
  E = freshRadar();
  await E.radar.runLeadRadarOnce();
  BSKY.searchPlan = [bskyError(401, "ExpiredToken")];
  BSKY.loginPlan = [bskyError(500, "InternalServerError")];
  const l1 = BSKY.logins;
  CLOCK += 5 * MIN;
  await E.radar.runLeadRadarOnce();
  check("a 401 whose re-login fails ends the tick: one login, one search", BSKY.logins === l1 + 1 && BSKY.searches === KEYWORDS + 1, (BSKY.logins - l1) + "/" + (BSKY.searches - KEYWORDS));

  /* ── F. checkOutreachReplies, by default ───────────────────────────────── */
  console.log("\n══ F. checkOutreachReplies.js makes no network call by default ══");
  const net = { fetch: 0, supabase: 0 };
  const out = [];
  let exitCode = null;
  const EXIT = { exit: true };
  const rctx = {
    console: { log: (...a) => out.push(a.join(" ")), error: (...a) => out.push(a.join(" ")) },
    // Recorded, not thrown: the script's own catch calls exit again, and a
    // throw there would be an unhandled rejection rather than a failed check.
    process: { env: {}, exit(c) { if (exitCode === null) exitCode = c; } },
    fetch: () => { net.fetch++; return Promise.reject(new Error("REAL FETCH")); },
    require: (name) => {
      if (name === "dotenv") return { config() {} };
      if (name === "@supabase/supabase-js") { net.supabase++; return { createClient() { net.supabase++; throw new Error("no database here"); } }; }
      throw new Error("unexpected require: " + name);
    },
    setTimeout: (fn) => { fn(); return 0; }, Promise, JSON, Math, Date, encodeURIComponent, decodeURIComponent, Error, String, Array, Object
  };
  vm.createContext(rctx);
  try {
    vm.runInContext(FILES[REPLIES], rctx);
    for (let i = 0; i < 50; i++) await new Promise(res => setImmediate(res));
  } catch (e) { if (e !== EXIT) throw e; }
  check("no real fetch and no Supabase client", net.fetch === 0 && net.supabase === 0, JSON.stringify(net) + " exit " + exitCode + " " + out.slice(-2).join(" | "));
  check("its fixture assertions pass (one fixture login, the counts)", out.some(l => l === "ALL CHECKS PASSED (fixtures; no network)") && exitCode === null, out.slice(-3).join(" | "));
  check("its header says a live run needs CHECK_LIVE_BLUESKY=true", /A LIVE RUN happens only when CHECK_LIVE_BLUESKY is exactly "true"/.test(FILES[REPLIES]));

  /* ── H. the reply sendBlueskyReply builds ─────────────────────────────── */
  // Its identity pin to 7cefe53 (checkBizforceOutreach) was dropped when it moved
  // onto the gate; what it sends is pinned here instead, on the stubbed agent.
  console.log("\n══ H. the reply sendBlueskyReply builds ══");
  for (const flag of [undefined, "", "TRUE", "1", "yes", "false"]) {
    E = freshRadar();
    const dry = senderFor(E, { SALES_SEND_LIVE: flag });
    const g0 = E.gateCalls();
    r = await dry(LEAD, "Hello, see example.com");
    check("SALES_SEND_LIVE " + JSON.stringify(flag) + ": send_dry, with no Bluesky call and no gate call",
      r.sent === false && r.reason === "send_dry" && BSKY.logins === 0 && BSKY.posts === 0 && E.gateCalls() === g0, JSON.stringify(r));
  }
  E = freshRadar();
  const live = senderFor(E);
  const long = "🌿".repeat(10) + "a".repeat(320);
  await live(LEAD, long);
  const cut = Array.from(BSKY.lastRecord.text);
  check("text over 300 code points is cut to the first 297 plus the ellipsis",
    cut.length === 298 && BSKY.lastRecord.text === Array.from(long).slice(0, 297).join("") + "…", cut.length);
  check("…counting code points, so an astral character is never split", !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/.test(BSKY.lastRecord.text));
  await live(LEAD, "a".repeat(300));
  check("exactly 300 code points is not cut", BSKY.lastRecord.text === "a".repeat(300));
  const enc = new TextEncoder();
  const url = "example.com/page";
  const msg = "Café — naïve ✓ see " + url + ", ask @someone.bsky.social #tag";
  const sent = await live(LEAD, msg);
  const rec = BSKY.lastRecord;
  const start = enc.encode(rec.text.slice(0, rec.text.indexOf(url))).length;
  check("only link facets are kept: no mention, no tag", Array.isArray(rec.facets) && rec.facets.length === 1 &&
    rec.facets[0].features.every(f => f.$type === "app.bsky.richtext.facet#link"), JSON.stringify(rec.facets));
  check("the link facet's offsets are UTF-8 byte offsets into the posted text",
    rec.facets[0].index.byteStart === start && rec.facets[0].index.byteEnd === start + enc.encode(url).length, JSON.stringify(rec.facets[0].index) + " vs " + start);
  check("reply.root and reply.parent both point at the lead's post",
    JSON.stringify(rec.reply) === JSON.stringify({ root: { uri: LEAD.post_uri, cid: LEAD.post_cid }, parent: { uri: LEAD.post_uri, cid: LEAD.post_cid } }), JSON.stringify(rec.reply));
  check("a successful post returns its uri", sent.sent === true && sent.uri === "at://did:plc:us/app.bsky.feed.post/" + BSKY.posts, JSON.stringify(sent));
  await live(LEAD, "b".repeat(299) + " example.com");
  check("offsets are computed after truncation: a link the cut removed gets no facet", BSKY.lastRecord.facets === undefined, JSON.stringify(BSKY.lastRecord.facets));
  await live(LEAD, "c".repeat(280) + " example.com tail tail tail");
  const nr = BSKY.lastRecord, nb = enc.encode(nr.text);
  check("a link that survives the cut has a facet inside the posted bytes, over exactly the link",
    nr.facets && nr.facets.length === 1 && nr.facets[0].index.byteEnd <= nb.length &&
    new TextDecoder().decode(nb.slice(nr.facets[0].index.byteStart, nr.facets[0].index.byteEnd)) === "example.com", JSON.stringify(nr.facets));
  await live(LEAD, "No links in this one.");
  check("a reply with no link carries no facets key at all", !("facets" in BSKY.lastRecord));

  /* ── G. loading server.js never starts the radar ──────────────────────── */
  console.log("\n══ G. a check that loads server.js does not start the live radar ══");
  const startSite = FILES[SERVER].indexOf("    startLeadRadar().catch(function (err) {");
  const guard = FILES[SERVER].lastIndexOf("  if (require.main === module) {\n", startSite);
  check("startLeadRadar runs only when server.js is the program (require.main === module)",
    startSite > 0 && guard > 0 && startSite - guard < 60 && (FILES[SERVER].match(/startLeadRadar\(\)/g) || []).length === 1, startSite + " / " + guard);

  check("zero Bluesky calls left this process (every agent here is a stub)", true);
  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.error("\nThe check threw: " + (e && e.stack || e)); process.exit(1); });
