"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkBskyGate — nothing in this repo can hammer the owner's Bluesky login.

   lib/bskyGate.js is the one session both the Lead Radar (leadRadar.js) and
   the outreach sender (server.js sendBlueskyReply) go through. This loads
   leadRadar.js in a vm with a stubbed BskyAgent, a fake Supabase and a fake
   clock; lifts sendBlueskyReply out of server.js onto the radar's own gate;
   and runs scripts/checkOutreachReplies.js in a vm with fetch spied on. NO
   Bluesky call of any kind is made — there is no network here at all.

   NAMED (Nov 23 2026, LR-2): BEFORE the radar searched the owner's 32 phrases in runLeadRadarOnce, and
   server.js sendBlueskyReply posted the owner's outreach through the same gate. AFTER runLeadRadarOnce and
   sendBlueskyReply (with formatLeadHandle and truncateToBlueskyLimit) are removed. The radar's Bluesky part
   is lib/memberRadar.js captureBluesky, searching members' words through leadRadar.js bskySearchFor (the
   same gate, one login per tick); here a "tick" runs the REAL captureBluesky, loaded in the vm from the
   working copy, for one member with 20 words (BSKY_SEARCHES_PER_TICK). A to C and E hold as before.
   D now proves the gate's back-off is shared: a 429 met by any call on the platform session (the
   owner's platform-account reply, blueskyActAs) stops the radar's searches too, and that path goes through
   the gate. H is a removal proof plus detectOutreachLinkFacets (still the reply's facet builder,
   lib/leadRoutes.js linkFacets): only link facets, at UTF-8 byte offsets. The reply's length rule (refused
   over 300, never cut), its reply target and SALES_SEND_LIVE are pinned by checkLeadRadarMember R1, R2, R9.

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
const MEMBER_RADAR = "lib/memberRadar.js";   // NAMED (Nov 23 2026, LR-2): the radar's Bluesky capture
const MUTATIONS = {
  // a failed login is retried for every keyword again: no per-tick login budget, and a failed
  // call goes on to the next keyword instead of ending the tick. Re-anchored (YouTube retention
  // build, Oct 2026) onto the tick.stop assignment the loop gained after 855f997: the old anchor
  // expected `break;` straight after the log line and had matched nothing since.
  // NAMED (Nov 23 2026, LR-2): BEFORE anchored on runLeadRadarOnce's call and its login_failed break. AFTER bskySearchFor
  // loses its tick budget and captureBluesky goes on to the next word after a failure.
  "login-per-keyword": [[RADAR, "    }, tickBudget);", "    });"],
    [MEMBER_RADAR, "    if (!got || !got.ok) { stopped = (got && got.reason) || \"failed\"; carried = due.length - i; break; }", "    if (!got || !got.ok) { continue; }"]],
  // the radar does not skip its search during a back-off (NAMED (Nov 23 2026, LR-2): re-anchored on bskySearchFor)
  "radar-ignores-backoff": [[RADAR, "    if (bskyGate.backoffRemainingMs() > 0) {\n      return { ok: false, reason: \"rate_limited\"", "    if (false) {\n      return { ok: false, reason: \"rate_limited\""]],
  // NAMED (Nov 23 2026, LR-2): sender-ignores-backoff, fresh-login-per-send, no-truncation and wrong-reply-target are
  // removed with sendBlueskyReply and truncateToBlueskyLimit (H proves they are gone; checkLeadRadarMember R2, R9 pin the send).
  // mention and tag facets are kept too
  "all-facets": [[SERVER, "          return feature && feature.$type === \"app.bsky.richtext.facet#link\";", "          return !!feature;"]],
  // loading server.js starts the live radar again
  // NAMED (Oct 27 2026, launch item #7): BEFORE the call was startLeadRadar(); AFTER it passes
  // shutdownControl.trackInterval, so a SIGTERM stops the radar's five-minute interval.
  // NAMED (Nov 23 2026, LR-1): BEFORE the anchor ran straight from the guard to startLeadRadar; the ledger hand-in now sits between
  // NAMED (Nov 23 2026, LR-2): BEFORE anchored on the LR-1 ledger comment; AFTER on the LR-2 member-radar comment that replaced it.
  "radar-starts-when-loaded": [[SERVER, "  if (require.main === module) {\n    /* NAMED (Nov 23 2026, LR-2): BEFORE the platform scorer",
    "  if (true) {\n    /* NAMED (Nov 23 2026, LR-2): BEFORE the platform scorer"]],
  // checkOutreachReplies logs in live unless told not to
  "replies-live-by-default": [[REPLIES, "const LIVE = process.env.CHECK_LIVE_BLUESKY === \"true\";", "const LIVE = process.env.CHECK_LIVE_BLUESKY !== \"false\";"]]
};
if (MUTATE === "all") MUT.runAllMutations(__filename, Object.keys(MUTATIONS));

const FILES = {};
[RADAR, SERVER, REPLIES, GATE, MEMBER_RADAR].forEach(f => { FILES[f] = fs.readFileSync(path.join(REPO, f), "utf8").replace(/\r\n/g, "\n"); });
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
  // NAMED (Nov 23 2026, LR-2): the real lib/memberRadar.js, from the (possibly mutated) working copy.
  const memberMod = loadModule(FILES[MEMBER_RADAR], path.join(REPO, MEMBER_RADAR), (n) => n === "./leadFingerprint" ? require(path.join(REPO, "lib", "leadFingerprint.js")) : (() => { throw new Error("unexpected require in memberRadar.js: " + n); })(),
    { console: logger, process: proc });
  const requireFn = (name) => {
    if (name === "dotenv") return { config() {} };
    if (name === "@supabase/supabase-js") return { createClient: () => fakeSupabase };
    if (name === "@atproto/api") return { BskyAgent: FakeBskyAgent };
    if (name === "@anthropic-ai/sdk") return function Anthropic() { throw new Error("no model in this check"); };
    // NAMED (Nov 23 2026, LR-1): BEFORE a "./mastodonRadar" stub; leadRadar.js no longer requires it (the file is deleted)
    if (name === "./youtubeRadar") return { memberYoutubeDeps: () => null };   // NAMED (Nov 23 2026, LR-2): BEFORE runYoutubeRadarOnce
    if (name === "./lib/memberRadar") return memberMod;
    if (name === "./lib/resolveAnthropicKey") return () => async () => null;
    if (name === "./lib/bskyGate") return gateModule;
    if (name === "./lib/ownerAccount") return require(path.join(REPO, "lib/ownerAccount"));
    throw new Error("unexpected require in leadRadar.js: " + name);
  };
  const radar = loadModule(FILES[RADAR], path.join(REPO, RADAR), requireFn, { console: logger, process: proc });
  /* NAMED (Nov 23 2026, LR-2): BEFORE radar.runLeadRadarOnce was leadRadar.js's own capture. AFTER it is this: one tick's
     Bluesky part, the real captureBluesky with the budget radarTick hands it (bskySearchFor({ logins: 1 }), pinned below),
     for one member whose 20 words are all due (an empty search cache). The name is kept so A to E read as before. */
  const memberSb = { from() { const b = { select() { return b; }, eq() { return b; }, in() { return b; }, upsert() { return b; }, then(res, rej) { return Promise.resolve({ data: [], error: null }).then(res, rej); } }; return b; } };
  const fp = require(path.join(REPO, "lib", "leadFingerprint.js")).shape({ keywords: WORDS, sources: { bluesky: true } });
  radar.runLeadRadarOnce = async () => { LAST.tick = await memberMod.captureBluesky({ sb: memberSb, bskySearch: radar.bskySearchFor({ logins: 1 }) }, [{ user_id: "m1", fp: fp }], CLOCK); return LAST.tick; };
  // Count every gate.call, so "no call at all" is checkable, not just "no Bluesky call".
  const gate = radar.bskyGate;
  let gateCalls = 0;
  const realCall = gate.call;
  gate.call = function () { gateCalls++; return realCall.apply(gate, arguments); };
  return { radar, gate, gateCalls: () => gateCalls, proc, logger };
}

/* ── functions lifted from server.js ──────────────────────────────────────── */
// NAMED (Nov 23 2026, LR-2): BEFORE sendBlueskyReply, formatLeadHandle and truncateToBlueskyLimit were lifted here and run on the
// radar's gate. AFTER they are removed; only detectOutreachLinkFacets is lifted (H).
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
function hasFn(name) { return new RegExp("^(?:async )?function " + name + "\\(", "m").test(FILES[SERVER]); }
// NAMED (Nov 23 2026, LR-2): the member's 20 words (memberRadar BSKY_SEARCHES_PER_TICK) and the last tick's result.
const WORDS = Array.from({ length: 20 }, (_, i) => "need a plumber " + i);
const LAST = { tick: null };

(async function main() {
  const KEYWORDS = 20;   // NAMED (Nov 23 2026, LR-2): BEFORE 32, the owner's phrases. AFTER a member's 20 words, one tick's budget
  console.log("\n══ 0. the tick these sections run is the radar's ══");
  {
    const tickSrc = FILES[RADAR].slice(FILES[RADAR].indexOf("async function radarTick()"), FILES[RADAR].indexOf("async function startLeadRadar("));
    const MRM = require(path.join(REPO, MEMBER_RADAR));
    check("radarTick hands the member radar bskySearchFor({ logins: 1 }) and runs memberRadar.runTick, whose Bluesky part is captureBluesky",
      tickSrc.indexOf("bskySearch: bskySearchFor({ logins: 1 }),") !== -1 && tickSrc.indexOf("result = await memberRadar.runTick(deps);") !== -1 &&
      /captureBluesky\(deps, /.test(FILES[MEMBER_RADAR].slice(FILES[MEMBER_RADAR].indexOf("async function runTick("))));
    check("one tick searches at most " + KEYWORDS + " words (BSKY_SEARCHES_PER_TICK)", MRM.BSKY_SEARCHES_PER_TICK === KEYWORDS, MRM.BSKY_SEARCHES_PER_TICK);
  }

  /* ── A. a failing login, once per tick ─────────────────────────────────── */
  console.log("\n══ A. a failing login is tried once per tick ══");
  let E = freshRadar();
  BSKY.loginPlan = [bskyError(500, "InternalServerError"), bskyError(500, "InternalServerError")];
  await E.radar.runLeadRadarOnce();
  check("tick 1: one login attempt, no search (not one per keyword)", BSKY.logins === 1 && BSKY.searches === 0, BSKY.logins + " logins, " + BSKY.searches + " searches");
  // NAMED (Nov 23 2026, LR-2): BEFORE the log line "capture stopped for this tick at ... login_failed". AFTER the tick's own result.
  check("tick 1: the capture stopped for this tick (login_failed), every word carried to the next", LAST.tick.stopped === "login_failed" && LAST.tick.carried === KEYWORDS, JSON.stringify(LAST.tick));
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
  const stops = [];
  for (let t = 0; t < 3; t++) { CLOCK += 2 * MIN; await E.radar.runLeadRadarOnce(); stops.push(LAST.tick.stopped); }
  check("three ticks inside the back-off: no login, no search", BSKY.logins === 1 && BSKY.searches === 0, BSKY.logins + "/" + BSKY.searches);
  check("…and no gate call at all: the radar skips its whole capture", E.gateCalls() === 1, E.gateCalls());
  // NAMED (Nov 23 2026, LR-2): BEFORE "the skip is logged once, with the time it resumes" (runLeadRadarOnce's log). AFTER each tick
  // reports stopped: rate_limited, and the search answer carries the time it resumes.
  check("each skipped tick stops at rate_limited", JSON.stringify(stops) === JSON.stringify(["rate_limited", "rate_limited", "rate_limited"]), JSON.stringify(stops));
  const answer = await E.radar.bskySearchFor({ logins: 1 })("x", new Date(CLOCK).toISOString());
  check("…and a search in the back-off says when it resumes", answer.ok === false && answer.reason === "rate_limited" && answer.resumes_at === new Date(E.gate.backoffUntil()).toISOString(), JSON.stringify(answer));
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

  /* ── D. the back-off is shared ─────────────────────────────────────────── */
  // NAMED (Nov 23 2026, LR-2): BEFORE sendBlueskyReply was run here on the radar's gate. AFTER it is removed; the one other
  // caller of the platform session is blueskyActAs (the owner's platform-account reply), which posts through bskyGate.call.
  // A call on the gate stands in for it: a 429 it meets stops the radar's searches too, and it reuses the radar's session.
  console.log("\n══ D. the platform session and its back-off are shared ══");
  {
    const actAs = (FILES[SERVER].match(/\n(?:async )?function blueskyActAs\([\s\S]*?\n\}\n/) || [""])[0];
    check("blueskyActAs (the platform account) posts through bskyGate.call, never a login of its own", /bskyGate\.call\(/.test(actAs) && !/\.login\(/.test(actAs), actAs.slice(0, 120));
  }
  E = freshRadar();
  await E.radar.runLeadRadarOnce();
  const loginsBefore = BSKY.logins;
  let r = await E.gate.call(a => a.post({ text: "hello" }));
  check("a post after the radar logged in reuses its session: posted, no new login", r.ok === true && BSKY.posts === 1 && BSKY.logins === loginsBefore, JSON.stringify(r) + " logins " + BSKY.logins);
  BSKY.postPlan = [bskyError(429, "RateLimitExceeded", { "retry-after": "300" })];
  r = await E.gate.call(a => a.post({ text: "second" }));
  check("a post that meets a 429 returns rate_limited and sets the back-off for everyone", r.ok === false && r.reason === "rate_limited" && E.gate.backoffRemainingMs() === 300000, JSON.stringify(r));
  const searchesBefore = BSKY.searches, loginsBefore2 = BSKY.logins;
  CLOCK += 2 * MIN;
  await E.radar.runLeadRadarOnce();
  check("the radar respects that 429 too: no search, no login", BSKY.searches === searchesBefore && BSKY.logins === loginsBefore2 && LAST.tick.stopped === "rate_limited", JSON.stringify(LAST.tick));

  /* ── E. a 401 ──────────────────────────────────────────────────────────── */
  console.log("\n══ E. an expired session re-logs in once ══");
  E = freshRadar();
  await E.radar.runLeadRadarOnce();
  const before401 = BSKY.logins;
  BSKY.searchPlan = [bskyError(401, "ExpiredToken")];
  CLOCK += 5 * MIN;
  await E.radar.runLeadRadarOnce();
  check("a 401 mid-tick: one fresh login, the search retried, the tick goes on", BSKY.logins === before401 + 1 && BSKY.searches === 2 * KEYWORDS + 1, BSKY.logins + "/" + BSKY.searches);
  // NAMED (Nov 23 2026, LR-2): BEFORE through sendBlueskyReply (reason post_error). AFTER through the gate itself.
  E = freshRadar();
  await E.gate.call(a => a.post({ text: "warm up" }));
  BSKY.postPlan = [bskyError(401, "ExpiredToken"), bskyError(401, "ExpiredToken")];
  const l0 = BSKY.logins;
  r = await E.gate.call(a => a.post({ text: "after expiry" }));
  check("401 then 401 again: exactly one re-login, never a third", BSKY.logins === l0 + 1, BSKY.logins - l0);
  check("…and it says so, without posting", r.ok === false && BSKY.posts === 1 + 2, JSON.stringify(r) + " posts " + BSKY.posts);
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

  /* ── H. the sender is gone; the facet builder stays ─────────────────────── */
  // NAMED (Nov 23 2026, LR-2): BEFORE the reply sendBlueskyReply built (send_dry, 297 plus the ellipsis, link facets, reply target).
  // AFTER sendBlueskyReply, formatLeadHandle and truncateToBlueskyLimit are removed: a reply is refused over 300, never cut, and
  // its target and SALES_SEND_LIVE are checkLeadRadarMember R1, R2, R9. detectOutreachLinkFacets still builds the facets.
  console.log("\n══ H. sendBlueskyReply is gone; detectOutreachLinkFacets keeps only links, at byte offsets ══");
  const code = FILES[SERVER].replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
  check("sendBlueskyReply, formatLeadHandle and truncateToBlueskyLimit are removed, and nothing calls them",
    !hasFn("sendBlueskyReply") && !hasFn("formatLeadHandle") && !hasFn("truncateToBlueskyLimit") && !/sendBlueskyReply\(|formatLeadHandle\(|truncateToBlueskyLimit\(/.test(code));
  check("the lead routes take their facets from detectOutreachLinkFacets", /linkFacets: detectOutreachLinkFacets,/.test(FILES[SERVER]));
  const fctx = { console: { error() {} }, RichText: require(require.resolve("@atproto/api", { paths: [REPO] })).RichText, String };
  vm.createContext(fctx);
  vm.runInContext(fnSource("detectOutreachLinkFacets") + "\nthis.f = detectOutreachLinkFacets;", fctx);
  const enc = new TextEncoder();
  const url = "example.com/page";
  const msg = "Café — naïve ✓ see " + url + ", ask @someone.bsky.social #tag";
  const facets = fctx.f(msg);
  const start = enc.encode(msg.slice(0, msg.indexOf(url))).length;
  check("only link facets are kept: no mention, no tag", Array.isArray(facets) && facets.length === 1 && facets[0].features.every(f => f.$type === "app.bsky.richtext.facet#link"), JSON.stringify(facets));
  check("the link facet's offsets are UTF-8 byte offsets into the text", facets[0].index.byteStart === start && facets[0].index.byteEnd === start + enc.encode(url).length, JSON.stringify(facets[0].index) + " vs " + start);
  check("a text with no link gets no facets", JSON.stringify(fctx.f("No links in this one.")) === "[]");

  /* ── G. loading server.js never starts the radar ──────────────────────── */
  console.log("\n══ G. a check that loads server.js does not start the live radar ══");
  // NAMED (Oct 27 2026, launch item #7): BEFORE startLeadRadar() took nothing; AFTER it takes
  // shutdownControl.trackInterval (a SIGTERM stops its interval). Still exactly one call, still guarded.
  const startSite = FILES[SERVER].indexOf("    startLeadRadar(shutdownControl.trackInterval).catch(function (err) {");
  const guard = FILES[SERVER].lastIndexOf("  if (require.main === module) {\n", startSite);
  check("startLeadRadar runs only when server.js is the program (require.main === module)",
    // NAMED (Nov 23 2026, LR-1): BEFORE under 60 characters; AFTER under 300, because the scorer's ledger hand-in
    // (setModelLedger) now sits between the guard and the start, inside the same guard (the guard's block does not close between them).
    // NAMED (Nov 23 2026, LR-2): BEFORE under 300; AFTER under 600: the member radar hand-in (setMemberRadarDeps) and its note sit there now.
    startSite > 0 && guard > 0 && startSite - guard < 600 && FILES[SERVER].slice(guard, startSite).indexOf("\n  }") === -1 &&
    (FILES[SERVER].match(/startLeadRadar\(/g) || []).length === 1, startSite + " / " + guard);

  check("zero Bluesky calls left this process (every agent here is a stub)", true);
  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.error("\nThe check threw: " + (e && e.stack || e)); process.exit(1); });
