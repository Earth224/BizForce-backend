"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkStorefrontKeywordLimits — the Storefront keyword tool measures against
   the limits the seller enters, and against nothing else.

   POST /api/agents/etsy/keyword-research used to measure every keyword against
   Etsy's limits (20-character tags, 13 tags, 140-character titles) whatever
   platform the seller used. It now takes two optional body fields, max_tags
   (1–100) and max_tag_length (1–200), measures fit only against what was
   entered, and claims no fit when nothing was.

   The route is lifted from server.js with its real helpers (scripts/_shared.js
   closureFor) and run in a vm on a fake database. The model is a stub that
   records the prompt it was sent; the system prompt is config/brain.js's real
   buildAgentSystemPrompt, so the whole prompt is checked. No network, no
   database, no model call.

   WHAT THIS PROVES
     a. No limits: every fits_tag and over_tag_limit_by is null; no tag set,
        with a reason naming both fields; constraints both null, seller-
        supplied and unverified; the prompt says none of "140", "13 tags",
        "20 characters" or "Etsy", and tells the model not to assume any
        platform's limits.
     b. Both limits: fit measured exactly at the boundary (M fits, M+1 does
        not and is over by 1); the set is the first N that fit; the prompt,
        note and provenance state N and M.
     c. Only max_tag_length: fit measured, no set, the reason names max_tags.
        Only max_tags: no fit claimed, the prompt states the count alone.
     d. Every refused value is a 400 naming the field and the value received,
        and writes no ai_tasks row and makes no model call.
     e. 0 is refused, not treated as absent; null and "" are absent.
     f. The wiring: TOOL_INPUT_SPECS declares both fields; no ETSY_MAX_*
        constant is left.

   MUTATE=<name> edits server.js in memory. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check. A mutation
   whose search text does not match exactly once is an ERROR.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), vm = require("vm"), path = require("path");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const MUTATE = process.env.MUTATE || "";
const ROUTE = "etsy/keyword-research";

const MUTATIONS = {
  // Etsy's 20 comes back as the tag length when none is entered
  "etsy-20-default": ['      var maxTagLength = readSellerTagLimit(req.body, "max_tag_length", 200);\n',
    '      var maxTagLength = readSellerTagLimit(req.body, "max_tag_length", 200);\n' +
    '      if (!maxTagLength.error && !maxTagLength.supplied) maxTagLength = { supplied: true, value: 20 };\n'],
  // a 0 is taken as "not supplied"
  "zero-as-absent": ['if (value === undefined || value === null || value === "") return { supplied: false, value: null };',
    'if (value === undefined || value === null || value === "" || value === 0) return { supplied: false, value: null };'],
  // with no limit, fits_tag says false instead of unknown
  "false-not-null": ["fits_tag: limited ? (text.length > 0 && text.length <= maxTagLength) : null,",
    "fits_tag: limited ? (text.length > 0 && text.length <= maxTagLength) : false,"],
  // the don't-assume sentence is dropped
  "drop-dont-assume": [": \"- The seller has not given their platform's limits. Do not assume any particular platform's limits on tag count or tag length.\\n\";",
    ": \"\";"],
  // a string of digits is quietly accepted as a number
  "accept-digit-string": ['  if (typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= max) {',
    '  if (typeof value === "string" && /^[0-9]+$/.test(value)) value = Number(value);\n  if (typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= max) {']
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

let SRC = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
if (MUTATE) {
  const m = MUTATIONS[MUTATE];
  if (!m) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  SRC = s.replaceOnce(SRC, m[0], m[1], MUTATE);
  console.log("\n!! MUTATION: " + MUTATE);
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}

const brain = require(path.join(REPO, "config", "brain.js"));
const CODE = s.closureFor(SRC, s.routeCode(SRC, ROUTE));

/* The model's reply: lengths chosen around a 12-character tag. */
const M = 12, N = 3;
const MODEL_TEXT = [
  "wool beanies | buyer | exactly twelve characters",      // 12: fits at M
  "warm wool hat | buyer | thirteen characters",           // 13: over by 1
  "knit cap | gift | short",                                // 8
  "winter hat | browser | short",                           // 10
  "cosy beanie | niche | short",                            // 11
  "hand knitted merino wool hat | buyer | long phrase"      // 28
].join("\n");

async function run(body) {
  const sb = s.fakeSupabase({});
  const prompts = [];
  const ctx = {
    supabase: sb.client, nowIso: () => "2026-10-13T12:00:00.000Z", process: { env: {} },
    console: { log() {}, error() {}, warn() {} },
    requireAuth: 0, requireActiveSubscription: 0, aiLimiter: 0,
    resolvePreferredLanguage: async () => null,
    buildLanguageInstruction: () => "",
    buildAgentSystemPrompt: brain.buildAgentSystemPrompt,
    callAnthropicText: async (prompt) => { prompts.push(String(prompt)); return { text: MODEL_TEXT, stopReason: "end_turn" }; }
  };
  let handler = null;
  ctx.app = { post() { handler = arguments[arguments.length - 1]; } };
  vm.createContext(ctx);
  vm.runInContext(CODE, ctx);
  const r = await s.call(handler, body);
  return { status: r.status, body: r.body || {}, nextErr: r.nextErr, prompts, inserts: sb.writes.filter(w => w.op === "insert") };
}
const kw = (b, k) => (b.keywords || []).find(x => x.keyword === k) || {};
const FORBIDDEN = ["140", "13 tags", "20 characters", "Etsy"];
const DONT_ASSUME = "Do not assume any particular platform's limits on tag count or tag length.";

(async function main() {
  /* ── a. no limits ─────────────────────────────────────────────────────── */
  console.log("\n══ a. no limits entered ══");
  const a = await run({ seed: "wool hat" });
  check("a. 200", a.status === 200, a.status + " " + JSON.stringify(a.body).slice(0, 200));
  const ak = a.body.keywords || [];
  check("a. six keywords measured", ak.length === 6, ak.length);
  check("a. every fits_tag is null", ak.length > 0 && ak.every(k => k.fits_tag === null), JSON.stringify(ak.map(k => k.fits_tag)));
  check("a. every over_tag_limit_by is null", ak.length > 0 && ak.every(k => k.over_tag_limit_by === null), JSON.stringify(ak.map(k => k.over_tag_limit_by)));
  check("a. length and word_count still measured", kw(a.body, "wool beanies").length === 12 && kw(a.body, "wool beanies").word_count === 2);
  check("a. suggested_tag_set is null", a.body.suggested_tag_set === null, JSON.stringify(a.body.suggested_tag_set));
  check("a. the reason names max_tags and max_tag_length", /max_tags/.test(a.body.suggested_tag_set_reason || "") && /max_tag_length/.test(a.body.suggested_tag_set_reason || ""), a.body.suggested_tag_set_reason);
  check("a. no tag-set note without a set", !("suggested_tag_set_note" in a.body));
  check("a. constraints: both null, seller-supplied, unverified, no title length",
    JSON.stringify(a.body.constraints) === JSON.stringify({ max_tags: null, max_tag_length: null, source: "seller_supplied", verified_against_platform: false }), JSON.stringify(a.body.constraints));
  check("a. counts claim no tag-ready total", a.body.counts && a.body.counts.tag_ready === null && a.body.counts.too_long_for_a_tag === null && a.body.counts.suggested === 6, JSON.stringify(a.body.counts));
  const ap = a.prompts[0] || "";
  check("a. one model call", a.prompts.length === 1, a.prompts.length);
  check("a. the prompt says none of " + FORBIDDEN.map(f => JSON.stringify(f)).join(", "), FORBIDDEN.every(f => ap.indexOf(f) === -1), FORBIDDEN.filter(f => ap.indexOf(f) !== -1).join(", "));
  check("a. the prompt tells the model not to assume any platform's limits", ap.indexOf(DONT_ASSUME) !== -1);
  check("a. the prompt has no length target and no phrase-matching mechanic", ap.indexOf("characters or fewer") === -1 && !/multi-word tags/i.test(ap));
  check("a. the brain is the Storefront Agent's", ap.indexOf("You are the BizForce AI Storefront Agent. You suggest search keyword candidates for a listing on the seller's online store or marketplace.") !== -1);
  const aprov = a.body.provenance || {};
  check("a. provenance claims no fit and carries the standing limits line",
    !(aprov.measured_from || []).some(x => /fits/.test(x)) && aprov.limits_note === "Limits are as you entered them; BizForce did not check them against your platform.", JSON.stringify(aprov).slice(0, 300));

  /* ── b. both limits ───────────────────────────────────────────────────── */
  console.log("\n══ b. max_tags " + N + " and max_tag_length " + M + " ══");
  const b = await run({ seed: "wool hat", max_tags: N, max_tag_length: M });
  check("b. 200", b.status === 200, b.status);
  check("b. a keyword of exactly " + M + " characters fits, over by 0", kw(b.body, "wool beanies").fits_tag === true && kw(b.body, "wool beanies").over_tag_limit_by === 0, JSON.stringify(kw(b.body, "wool beanies")));
  check("b. a keyword of " + (M + 1) + " does not fit, over by 1", kw(b.body, "warm wool hat").fits_tag === false && kw(b.body, "warm wool hat").over_tag_limit_by === 1, JSON.stringify(kw(b.body, "warm wool hat")));
  check("b. the 28-character phrase is over by 16", kw(b.body, "hand knitted merino wool hat").over_tag_limit_by === 16);
  const set = b.body.suggested_tag_set;
  check("b. the set is the first " + N + " that fit, in the model's order", JSON.stringify(set) === JSON.stringify(["wool beanies", "knit cap", "winter hat"]), JSON.stringify(set));
  check("b. the set has at most " + N, Array.isArray(set) && set.length <= N);
  check("b. no reason when the set exists", !("suggested_tag_set_reason" in b.body));
  check("b. the note uses " + N + " and " + M + ", never 13 or 20",
    /first 3 suggestions/.test(b.body.suggested_tag_set_note || "") && /12-character tag length you entered/.test(b.body.suggested_tag_set_note || "") && !/\b13\b|\b20\b/.test(b.body.suggested_tag_set_note || ""), b.body.suggested_tag_set_note);
  check("b. constraints carry the entered numbers", JSON.stringify(b.body.constraints) === JSON.stringify({ max_tags: N, max_tag_length: M, source: "seller_supplied", verified_against_platform: false }), JSON.stringify(b.body.constraints));
  check("b. counts: 4 tag-ready, 2 too long", b.body.counts && b.body.counts.tag_ready === 4 && b.body.counts.too_long_for_a_tag === 2, JSON.stringify(b.body.counts));
  const bp = b.prompts[0] || "";
  check("b. the prompt states the seller's limits", bp.indexOf("The seller says their platform allows at most 3 tags of up to 12 characters each.") !== -1);
  check("b. the length target uses " + M, bp.indexOf("Aim for at least 14 candidates that are 12 characters or fewer") !== -1);
  check("b. the prompt still says none of the Etsy figures", FORBIDDEN.every(f => bp.indexOf(f) === -1), FORBIDDEN.filter(f => bp.indexOf(f) !== -1).join(", "));
  check("b. provenance names the entered tag length", ((b.body.provenance || {}).measured_from || []).indexOf("Whether each fits the 12-character tag length you entered") !== -1, JSON.stringify((b.body.provenance || {}).measured_from));

  /* ── c. one limit ─────────────────────────────────────────────────────── */
  console.log("\n══ c. one limit ══");
  const c = await run({ seed: "wool hat", max_tag_length: M });
  check("c. only max_tag_length: 200", c.status === 200, c.status);
  check("c. fit measured", kw(c.body, "wool beanies").fits_tag === true && kw(c.body, "warm wool hat").over_tag_limit_by === 1);
  check("c. no set, and the reason names max_tags alone", c.body.suggested_tag_set === null && /max_tags/.test(c.body.suggested_tag_set_reason || "") && !/max_tag_length/.test(c.body.suggested_tag_set_reason || ""), c.body.suggested_tag_set_reason);
  check("c. the prompt states the length only", (c.prompts[0] || "").indexOf("The seller says their platform allows tags of up to 12 characters each.") !== -1 && !/at most \d+ tags/.test(c.prompts[0] || ""));
  const c2 = await run({ seed: "wool hat", max_tags: N });
  check("c. only max_tags: 200, no fit claimed", c2.status === 200 && (c2.body.keywords || []).every(k => k.fits_tag === null && k.over_tag_limit_by === null));
  check("c. only max_tags: no set, the reason names max_tag_length alone", c2.body.suggested_tag_set === null && /max_tag_length/.test(c2.body.suggested_tag_set_reason || "") && !/max_tags\b/.test(c2.body.suggested_tag_set_reason || ""), c2.body.suggested_tag_set_reason);
  const c2p = c2.prompts[0] || "";
  check("c. only max_tags: the prompt states the count alone, with no length target",
    c2p.indexOf("The seller says their platform allows at most 3 tags.") !== -1 && c2p.indexOf("characters or fewer") === -1 && c2p.indexOf("Do not assume any particular platform's tag length.") !== -1);

  /* ── d & e. refusals ──────────────────────────────────────────────────── */
  console.log("\n══ d & e. refusals ══");
  const BAD = {
    max_tags: [0, -1, 1.5, 101, true, "12", "abc", "", null, [12], { n: 12 }],
    max_tag_length: [0, -1, 1.5, 201, false, "12", "abc", "", null, [12], { n: 12 }]
  };
  for (const [field, values] of Object.entries(BAD)) {
    for (const v of values) {
      if (v === "" || v === null) continue;   // absent, checked below
      const r = await run({ seed: "wool hat", [field]: v });
      const shown = JSON.stringify(v);
      check("d. " + field + " = " + shown + ": 400 naming the field and the value, no row, no model call",
        r.status === 400 && String(r.body.error || "").indexOf(field) !== -1 && String(r.body.error || "").indexOf("Received: " + shown) !== -1 &&
        r.inserts.length === 0 && r.prompts.length === 0,
        r.status + " " + JSON.stringify(r.body) + " inserts=" + r.inserts.length + " calls=" + r.prompts.length);
    }
  }
  for (const field of ["max_tags", "max_tag_length"]) {
    const z = await run({ seed: "wool hat", [field]: 0 });
    check("e. " + field + " = 0 is refused, not taken as absent", z.status === 400 && z.prompts.length === 0, z.status);
    for (const v of [null, ""]) {
      const r = await run({ seed: "wool hat", [field]: v });
      check("e. " + field + " = " + JSON.stringify(v) + " is absent: 200, limit null", r.status === 200 && r.body.constraints && r.body.constraints[field] === null, r.status + " " + JSON.stringify(r.body.constraints));
    }
  }
  const hi = await run({ seed: "wool hat", max_tags: 100, max_tag_length: 200 });
  check("e. the upper bounds 100 and 200 are accepted", hi.status === 200 && hi.body.constraints.max_tags === 100 && hi.body.constraints.max_tag_length === 200, hi.status);
  const lo = await run({ seed: "wool hat", max_tags: 1, max_tag_length: 1 });
  check("e. the lower bound 1 is accepted", lo.status === 200 && lo.body.constraints.max_tags === 1, lo.status);

  /* ── f. wiring ────────────────────────────────────────────────────────── */
  console.log("\n══ f. wiring ══");
  check("f. TOOL_INPUT_SPECS declares max_tags as an optional number",
    SRC.indexOf('toolField("max_tags", "number", false, "How many tags your platform allows per listing, 1–100. Leave blank if you don\'t know.")') !== -1);
  check("f. TOOL_INPUT_SPECS declares max_tag_length as an optional number",
    SRC.indexOf('toolField("max_tag_length", "number", false, "Your platform\'s maximum characters per tag, 1–200. Leave blank if you don\'t know.")') !== -1);
  check("f. no ETSY_MAX_* constant is left in server.js", !/ETSY_MAX_/.test(SRC));

  console.log("\n" + (failures ? "CHECKS FAILED: " + failures + " of " + (passes + failures) : "ALL " + passes + " CHECKS PASSED") + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(failures ? 1 : 0);
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
