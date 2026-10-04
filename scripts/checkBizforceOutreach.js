/* ═══════════════════════════════════════════════════════════════════════════
   checkBizforceOutreach.js — Lead Radar finds BizForce's own buyers, on a
   pipeline of its own, and the supplement pipeline is exactly what it was.

   THE GAP. Every capture phrase, every product the scorer could name and every
   link a reply could carry served the owner's supplement business or his book.
   bizforceai.net was not a permitted destination at all, so nothing the engine
   did could send a visitor to the platform whose north star is an app that
   drives traffic to itself.

   WHAT THIS PROVES, with no model call, no database write and no send — the
   functions are lifted from the working copy and from BASELINE, the commit
   before this change, and run side by side:
     1. Capture: the 25 supplement phrases are unchanged and searched first;
        the seven BizForce phrases follow; a row records which set found it
        (matched_keyword), and only a Bluesky row found by a BizForce phrase is
        a BizForce lead.
     2. Scoring: for supplement leads the prompt is byte-identical to BASELINE;
        a BizForce lead gets its own prompt naming one product, BizForceAI; and
        each pipeline can store only its own products.
     3. Drafting, through the real convertSingleLead with the model, database
        and senders stubbed: for every supplement product and the book, the
        prompt the model receives and the reply sent are identical to
        BASELINE. A BizForce lead, which BASELINE skipped, is drafted against
        the BizForce instruction and may link https://bizforceai.net/ only.
     4. Links: a BizForce draft linking mrearthrose.com, another bizforceai.net
        path, a query string or Stripe is held; and a supplement draft linking
        bizforceai.net is now held too — the one tightening, and the
        supplement instruction already forbade any URL but its own.
     5. Sending: every server.js line naming a send flag is identical to
        BASELINE.

   MUTATIONS — each must turn the named section red:
     MUTATE=keywords     the BizForce phrases are never searched      → 1
     MUTATE=pipeline     no lead is ever a BizForce lead              → 1, 2
     MUTATE=everylead    every Bluesky lead is a BizForce lead         → 1, 2
     MUTATE=products     a BizForce lead is validated against the supplement list → 2
     MUTATE=offer        convertSingleLead has no BizForce offer       → 3
     MUTATE=instruction  a BizForce lead gets the supplement instruction → 3
     MUTATE=domain       bizforceai.net is not an own domain           → 4
   ═══════════════════════════════════════════════════════════════════════════ */
"use strict";
require("dotenv").config();
const fs = require("fs");
const vm = require("vm");
const path = require("path");
const { execSync } = require("child_process");
const REPO = path.join(__dirname, "..");
const { createResidueGuard, resolveSubjectAccount } = require("./checkRunResidue");
const SUBJECT_USER_ID = resolveSubjectAccount();
const { RichText } = require(require.resolve("@atproto/api", { paths: [REPO] }));
const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY);
/* Nothing here touches the database; the guard is built so a future edit that
   adds a write has somewhere to record it, and its read-back runs regardless. */
const residue = createResidueGuard({ supabase: supabase, name: "bizforceOutreach", subject: SUBJECT_USER_ID, tables: [] });
residue.install();

/* The commit before BizForce outreach existed: what "unchanged" is measured
   against. Pinned, not HEAD, so the comparison still means something after
   this change is committed. */
const BASELINE = "7cefe53";

const MUTATIONS = ["keywords", "pipeline", "everylead", "products", "offer", "instruction", "domain"];
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
const read = f => fs.readFileSync(path.join(REPO, f), "utf8").replace(/\r\n/g, "\n");
const atBaseline = f => execSync("git show " + BASELINE + ":" + f, { cwd: REPO, maxBuffer: 1 << 26 }).toString("utf8").replace(/\r\n/g, "\n");

let RADAR = read("leadRadar.js"), SERVER = read("server.js");
const RADAR0 = atBaseline("leadRadar.js"), SERVER0 = atBaseline("server.js");

if (MUTATE === "keywords") RADAR = mutate(RADAR, "    var capturePhrases = KEYWORDS.concat(BIZFORCE_KEYWORDS);", "    var capturePhrases = KEYWORDS;", "keywords");
if (MUTATE === "pipeline") RADAR = mutate(RADAR, "  return !!lead && (lead.source || \"bluesky\") === \"bluesky\" && BIZFORCE_KEYWORDS.indexOf(lead.matched_keyword) !== -1;",
  "  return false;", "pipeline");
if (MUTATE === "everylead") RADAR = mutate(RADAR, "  return !!lead && (lead.source || \"bluesky\") === \"bluesky\" && BIZFORCE_KEYWORDS.indexOf(lead.matched_keyword) !== -1;",
  "  return !!lead && (lead.source || \"bluesky\") === \"bluesky\";", "everylead");
if (MUTATE === "products") RADAR = mutate(RADAR, "        var allowedProducts = bizforceLead ? BIZFORCE_SCORER_PRODUCTS : SCORER_ALLOWED_PRODUCTS;",
  "        var allowedProducts = SCORER_ALLOWED_PRODUCTS;", "products");
if (MUTATE === "offer") SERVER = mutate(SERVER, "    (suggestedProduct === OUTREACH_BIZFORCE_PRODUCT ? \"bizforce\" : null));", "    null);", "offer");
if (MUTATE === "instruction") SERVER = mutate(SERVER, "(offerKind === \"bizforce\" ? bizforceInstruction : supplementInstruction)", "supplementInstruction", "instruction");
if (MUTATE === "domain") SERVER = mutate(SERVER, ", \"blacksuncircle.com\", \"bizforceai.net\"];", ", \"blacksuncircle.com\"];", "domain");
if (MUTATE) console.log("\n!! MUTATION: " + MUTATE);

/* _shared caches a definition by name for every source but the working copy, so
   it is loaded fresh for each source lifted here. */
const SHARED = require.resolve("./_shared");
function defs(src, names, optional) {
  delete require.cache[SHARED];
  const { definitionOf } = require(SHARED);
  return names.map(function (n) {
    const d = definitionOf(src, n);
    if (!d && !(optional && optional.indexOf(n) !== -1)) throw new Error("EXTRACTION FAILED: " + n);
    return d || "";
  }).join("\n\n");
}
function literal(src, name) { const c = {}; vm.runInNewContext(defs(src, [name]) + "\nthis.v = " + name + ";", c); return c.v; }

/* ── scoring: the code from the first prompt input to the call, as scoreNewLeads runs it ── */
function scoringPrompt(src, lead) {
  const a = src.indexOf("        var source  = lead.source || \"bluesky\";");
  const b = src.indexOf("        var response = await createScoringMessage({");
  if (a < 0 || b < 0) throw new Error("EXTRACTION FAILED: the scorer's prompt block");
  const ctx = { lead: lead };
  const extra = /function isBizforceLead/.test(src) ? defs(src, ["BIZFORCE_KEYWORDS", "isBizforceLead", "bizforceScoringPrompt"]) : "";
  vm.runInNewContext(extra + "\n" + src.slice(a, b) + "\nthis.out = prompt;", ctx);
  return ctx.out;
}
function storedProduct(src, lead, modelProduct) {
  const m = /        var allowedProducts[\s\S]*?: "none";\n/.exec(src);
  if (!m) throw new Error("EXTRACTION FAILED: the product validation");
  const ctx = { lead: lead, result: { product: modelProduct } };
  vm.runInNewContext(defs(src, ["SCORER_ALLOWED_PRODUCTS", "BIZFORCE_SCORER_PRODUCTS", "BIZFORCE_KEYWORDS", "isBizforceLead"]) +
    "\nvar bizforceLead = isBizforceLead(lead);\n" + m[0] + "\nthis.out = product;", ctx);
  return ctx.out;
}

/* ── drafting: the real convertSingleLead, stubbed at the model, database and senders ── */
const LIFTED = ["formatLeadHandle", "OUTREACH_BOOK_PRODUCT", "OUTREACH_SUPPLEMENT_PRODUCTS", "OUTREACH_DAILY_CAP", "OUTREACH_PRODUCT_FACTS",
  "OUTREACH_HOME_URL", "OUTREACH_BIZFORCE_PRODUCT", "OUTREACH_PRODUCT_DESTINATIONS", "OUTREACH_BIZFORCE_DESTINATION", "OUTREACH_BOOK_DESTINATION",
  "OUTREACH_OWN_DOMAINS", "outreachDraftRejection", "nowIso", "DRAFT_ATTEMPT_CEILING", "OUTREACH_EMOJI_PATTERN", "stripOutreachEmoji",
  "truncateOrchestratorPreview", "normalizeMemoryMetadata", "detectOutreachLinkFacets",
  "OUTREACH_TRACKED_HOSTS", "outreachRefToken", "withOutreachTracking", "convertSingleLead"];
const NEW_NAMES = ["OUTREACH_BIZFORCE_PRODUCT", "OUTREACH_BIZFORCE_DESTINATION", "OUTREACH_TRACKED_HOSTS", "outreachRefToken", "withOutreachTracking"];
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
async function draftRun(src, product, modelMessage) {
  const prompts = [], sends = [];
  const ctx = {
    supabase: fakeDb(), RichText: RichText, URL: URL, crypto: require("crypto"), console: { log() {}, warn() {}, error() {} }, process: { env: {} },
    canSendOutreach: async () => ({ allowed: true }),
    callAnthropicText: async p => { prompts.push(p); return { text: JSON.stringify({ outreach_message: modelMessage, internal_analysis: "fixture" }), stopReason: "end_turn" }; },
    sendBlueskyReply: async (lead, text) => { sends.push(text); return { sent: true, uri: "at://fake/post" }; },
    sendMastodonReply: async (lead, text) => { sends.push(text); return { sent: true, uri: "https://fake/post" }; }
  };
  vm.createContext(ctx);
  vm.runInContext(defs(src, LIFTED, NEW_NAMES) + "\nthis.run = convertSingleLead;", ctx);
  const lead = { id: "lead-1", post_uri: "at://did:plc:fixture/app.bsky.feed.post/1", source: "bluesky", author_handle: "fixture.bsky.social",
    post_text: "fixture post", matched_keyword: "fixture", intent_score: 80, intent_reason: "asks", suggested_product: product };
  const result = await ctx.run(SUBJECT_USER_ID, lead, "SHARED SYSTEM PROMPT", false);
  return { prompt: prompts[0] || null, sends: sends, sent: !!(result && result.sent), reason: result && result.send_reason };
}

(async function main() {
  await residue.sweepPrevious(SUBJECT_USER_ID);

  console.log("\n══ 1. capture: two phrase sets, and each row says which found it ══");
  const KW = literal(RADAR, "KEYWORDS"), KW0 = literal(RADAR0, "KEYWORDS"), BKW = literal(RADAR, "BIZFORCE_KEYWORDS");
  check("1. the 25 supplement phrases are identical to " + BASELINE, JSON.stringify(KW) === JSON.stringify(KW0) && KW.length === 25);
  check("1. the seven BizForce phrases are exactly the ones asked for", JSON.stringify(BKW) === JSON.stringify(["ad account disabled", "meta rejected my ad",
    "stripe froze my account", "shadowbanned my business", "can't advertise supplements", "payment processor dropped me", "my account got flagged selling"]), JSON.stringify(BKW));
  const loop = /    var capturePhrases = ([^;]*);\n    for \(var i = 0; i < capturePhrases\.length; i\+\+\) \{\n      var keyword = capturePhrases\[i\];/.exec(RADAR);
  const searched = loop ? vm.runInNewContext(loop[1], { KEYWORDS: KW, BIZFORCE_KEYWORDS: BKW }) : [];
  check("1. capture searches the supplement phrases first, in their order, then the BizForce phrases",
    JSON.stringify(searched) === JSON.stringify(KW.concat(BKW)), searched.length + " phrases");
  check("1. each captured row records the phrase that found it (matched_keyword: keyword)", /            matched_keyword: keyword,\n/.test(RADAR));
  const isBiz = (function () { const c = {}; vm.runInNewContext(defs(RADAR, ["BIZFORCE_KEYWORDS", "isBizforceLead"]) + "\nthis.f = isBizforceLead;", c); return c.f; })();
  check("1. a Bluesky row found by any BizForce phrase is a BizForce lead", BKW.every(k => isBiz({ source: "bluesky", matched_keyword: k })));
  check("1. a row found by any supplement phrase is not", KW.every(k => !isBiz({ source: "bluesky", matched_keyword: k })));
  check("1. nor is a Mastodon or YouTube row, whatever it matched", !isBiz({ source: "mastodon", matched_keyword: BKW[0] }) && !isBiz({ source: "youtube", matched_keyword: BKW[0] }));

  console.log("\n══ 2. scoring: the supplement prompt is untouched; BizForce has its own ══");
  const SUPP = [{ source: "bluesky", matched_keyword: "anyone tried tongkat ali", lang: "en", post_text: "anyone tried tongkat ali? asking for real" },
    { source: "mastodon", matched_keyword: "libido", lang: "en", post_text: "#libido thoughts" },
    { source: "bluesky", matched_keyword: "why is my libido low", lang: "es", post_text: "por que mi libido esta baja" }];
  check("2. for three supplement leads (Bluesky, Mastodon, Spanish) the scorer prompt is byte-identical to " + BASELINE,
    SUPP.every(l => scoringPrompt(RADAR, l) === scoringPrompt(RADAR0, l)));
  const bizLead = { source: "bluesky", matched_keyword: "stripe froze my account", lang: "en", post_text: "stripe froze my account again, what are other supplement brands using?" };
  const bp = scoringPrompt(RADAR, bizLead);
  check("2. a BizForce lead is scored against BizForceAI alone, as §1 describes it, at $199/month",
    /classifier for one product:\n- BizForceAI: the operating system for businesses the ad networks won't serve/.test(bp) && /\$199\/month/.test(bp) && !/War Horse|Tongkat|Quantum/.test(bp));
  check("2. its closing contract names BizForceAI and none, and nothing else", /"product": "<BizForceAI \| none>"/.test(bp));
  check("2. the BizForce constant is exactly BizForceAI and none; the supplement constant is identical to " + BASELINE,
    JSON.stringify(literal(RADAR, "BIZFORCE_SCORER_PRODUCTS")) === JSON.stringify(["BizForceAI", "none"]) &&
    JSON.stringify(literal(RADAR, "SCORER_ALLOWED_PRODUCTS")) === JSON.stringify(literal(RADAR0, "SCORER_ALLOWED_PRODUCTS")));
  const stored = [storedProduct(RADAR, bizLead, "BizForceAI"), storedProduct(RADAR, bizLead, "War Horse"), storedProduct(RADAR, SUPP[0], "War Horse"), storedProduct(RADAR, SUPP[0], "BizForceAI")];
  check("2. each pipeline stores only its own products: BizForceAI kept, War Horse → none on a BizForce lead; War Horse kept, BizForceAI → none on a supplement lead",
    JSON.stringify(stored) === JSON.stringify(["BizForceAI", "none", "War Horse", "none"]), JSON.stringify(stored));

  console.log("\n══ 3. drafting, through the real convertSingleLead ══");
  const SUPP_PRODUCTS = literal(SERVER0, "OUTREACH_SUPPLEMENT_PRODUCTS");
  let same = 0;
  for (const p of SUPP_PRODUCTS.concat(["Quantum Jumping book"])) {
    const msg = p === "Quantum Jumping book" ? "That frustration is common. BlackSunCircle.com" : "Many people like it. https://mrearthrose.com/";
    const now = await draftRun(SERVER, p, msg), then = await draftRun(SERVER0, p, msg);
    if (now.prompt === then.prompt && JSON.stringify(now.sends) === JSON.stringify(then.sends) && now.sent === then.sent && now.sent) same++;
    else console.log("    differs: " + p + " sent " + then.sent + " → " + now.sent);
  }
  check("3. for all six supplement products and the book, the model's prompt and the reply sent are identical to " + BASELINE, same === SUPP_PRODUCTS.length + 1, same + " of " + (SUPP_PRODUCTS.length + 1));
  const before = await draftRun(SERVER0, "BizForceAI", "x");
  check("3. at " + BASELINE + " a BizForceAI lead was skipped: no offer", !before.prompt && before.reason === "unsupported_product", before.reason);
  const biz = await draftRun(SERVER, "BizForceAI", "Owned channels can't be switched off by an ad network. We built BizForceAI for that: https://bizforceai.net/");
  check("3. now it is drafted against the BizForce instruction, with https://bizforceai.net/ as the one link",
    !!biz.prompt && /THE OFFER FOR THIS LEAD IS BIZFORCEAI/.test(biz.prompt) && /The one link you may give them: https:\/\/bizforceai\.net\//.test(biz.prompt) &&
    !/From MrEarthRose\.com|from MrEarthRose\.com/.test(biz.prompt) && !/structure-function/.test(biz.prompt));
  check("3. and a draft carrying that link is sent once (with the arrival parameter, checkEngineArrival.js)", biz.sent && biz.sends.length === 1 && /https:\/\/bizforceai\.net\//.test(biz.sends[0]), biz.reason);

  console.log("\n══ 4. links ══");
  const held = [];
  for (const m of ["We built a platform for this: https://mrearthrose.com/", "See https://bizforceai.net/pricing", "https://bizforceai.net/?utm_source=bluesky",
    "Sign up at https://buy.stripe.com/abc"]) {
    const r = await draftRun(SERVER, "BizForceAI", m);
    held.push(!r.sent && r.sends.length === 0 && r.reason === "draft_rejected");
  }
  check("4. a BizForce draft linking mrearthrose.com, another bizforceai.net path, a query string or Stripe is held", held.every(Boolean), JSON.stringify(held));
  const cross = await draftRun(SERVER, "War Horse", "Worth a look: https://bizforceai.net/");
  const cross0 = await draftRun(SERVER0, "War Horse", "Worth a look: https://bizforceai.net/");
  check("4. a supplement draft linking bizforceai.net is now held (it was sent at " + BASELINE + ") — the one tightening",
    !cross.sent && cross.reason === "draft_rejected" && cross0.sent, JSON.stringify([cross0.sent, cross.sent]));

  console.log("\n══ 5. sending is unchanged ══");
  const flagLines = src => src.split("\n").filter(l => /ENABLE_SALES_AUTOLOOP|SALES_SEND_LIVE|SALES_AUTOLOOP_DRY_RUN|OUTREACH_DAILY_CAP|OUTREACH_ACCOUNT_DAILY_CEILING|OUTREACH_MIN_INTENT|SALES_AUTOLOOP_DAILY_DRAFT_CAP/.test(l)).join("\n");
  check("5. every server.js line naming a send flag is identical to " + BASELINE, flagLines(SERVER) === flagLines(SERVER0),
    flagLines(SERVER).split("\n").length + " lines");
  check("5. sendBlueskyReply, sendMastodonReply and canSendOutreach are identical to " + BASELINE,
    ["sendBlueskyReply", "sendMastodonReply", "canSendOutreach"].every(n => defs(SERVER, [n]) === defs(SERVER0, [n])));

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
