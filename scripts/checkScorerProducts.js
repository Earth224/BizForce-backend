/* ═════════════════════════════════════════════════════════════════════════
   checkScorerProducts.js — Lead Radar's scorer and drafter name no product
   but the member's own.

   NAMED (Nov 23 2026, LR-2): BEFORE this proved that SCORER_ALLOWED_PRODUCTS
   (leadRadar.js) and OUTREACH_SUPPLEMENT_PRODUCTS (server.js) held all six
   Mr. Earth Rose products, that scoreNewLeads' prompt listed each with its
   topical or shot line, and that convertSingleLead's drafter was told what
   each product is. AFTER LR-2 removed the owner's radar, its product lists,
   its scorer and its drafter: Lead Radar is every member's, and it scores and
   drafts against that member's own Fingerprint (what they offer, who they
   serve, their place). The original is preserved in git (65c0825). What it
   guarded, a model told the wrong offer, is still guarded, the other way: no
   fixed product list can reach a member's lead.

   WHAT THIS PROVES, from the working copy, with no model call, no database
   and no network:
     1. Removed: SCORER_ALLOWED_PRODUCTS, OUTREACH_SUPPLEMENT_PRODUCTS,
        scoreNewLeads, convertSingleLead and the six product names appear
        nowhere in leadRadar.js, server.js, lib/memberRadar.js or
        lib/leadReplies.js code (comments aside).
     2. The scoring prompt (lib/memberRadar.js scoringPrompt), built for a
        member, carries that member's offer, categories, place and audience,
        and names no product of anyone else; the score it parses has no
        product field (score, reason, safety, invitation only).
     3. The drafting prompt (lib/leadReplies.js draftPrompt) carries the
        member's own offer, and its only link is the member's own listing,
        or none.

   MUTATIONS (MUTATE=<name> edits a source IN MEMORY; MUTATE=all runs each):
     product-in-scorer   the scoring prompt names "War Horse" again      → 2
     product-field       the parsed score carries a suggested_product    → 2
     product-in-drafter  the drafting prompt names "Tongkat Ali" again    → 3
   ═════════════════════════════════════════════════════════════════════════ */
"use strict";
const fs = require("fs"), path = require("path"), Module = require("module");
const REPO = path.join(__dirname, "..");
const MUT = require("./_shared");
const MUTATE = process.env.MUTATE || "";

const MR = "lib/memberRadar.js", LRP = "lib/leadReplies.js";
const MUTATIONS = {
  "product-in-scorer": [[MR, '    "What it offers: " + JSON.stringify(fp.offer_summary || "") + "\\n" +\n    "Categories: "',
    '    "What it offers: " + JSON.stringify(fp.offer_summary || "") + " (suggest War Horse where it fits)\\n" +\n    "Categories: "']],
  "product-field": [[MR, "  return { score: score, reason: reason, outreach_safe: obj.safety === \"SAFE\", reply_invited: obj.invitation === \"INVITED\" };",
    "  return { score: score, reason: reason, outreach_safe: obj.safety === \"SAFE\", reply_invited: obj.invitation === \"INVITED\", suggested_product: obj.product || \"none\" };"]],
  "product-in-drafter": [[LRP, '    "Who it serves: " + JSON.stringify(fp.who_you_serve || "") + "\\n" +\n    "Place: "',
    '    "Who it serves: " + JSON.stringify(fp.who_you_serve || "") + "\\nMention Tongkat Ali.\\n" +\n    "Place: "']]
};
if (MUTATE === "all") MUT.runAllMutations(__filename, Object.keys(MUTATIONS));

const FILES = {};
["leadRadar.js", "server.js", MR, LRP].forEach(f => { FILES[f] = fs.readFileSync(path.join(REPO, f), "utf8").replace(/\r\n/g, "\n"); });
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = MUT.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE);
}
function load(rel) {
  const m = new Module(path.join(REPO, rel), module);
  m.filename = path.join(REPO, rel);
  m.paths = Module._nodeModulePaths(path.dirname(m.filename));
  m._compile(FILES[rel], m.filename);
  return m.exports;
}

let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}
const code = src => src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
const PRODUCTS = ["War Horse", "War Horse Black", "Tongkat Ali", "Sword Vitality XXL Xtreme", "War Horse Xtreme", "War Horse Midnight"];

console.log("\n══ 1. the owner's product lists, scorer and drafter are removed ══");
{
  const all = Object.keys(FILES).map(f => code(FILES[f])).join("\n");
  const gone = ["SCORER_ALLOWED_PRODUCTS", "OUTREACH_SUPPLEMENT_PRODUCTS", "scoreNewLeads", "convertSingleLead"].filter(n => all.indexOf(n) !== -1);
  check("SCORER_ALLOWED_PRODUCTS, OUTREACH_SUPPLEMENT_PRODUCTS, scoreNewLeads and convertSingleLead appear in no code", gone.length === 0, gone.join(", "));
  const named = PRODUCTS.filter(p => [MR, LRP, "leadRadar.js"].some(f => code(FILES[f]).indexOf(p) !== -1));
  check("no product name is in the radar, its scorer or its drafter", named.length === 0, named.join(", "));
}

console.log("\n══ 2. the scorer scores against the member's own Fingerprint ══");
const M = load(MR);
const FP = { offer_summary: "Emergency plumbing and drain repair", who_you_serve: "Homeowners in Leeds", place_city: "Leeds", place_region: "West Yorkshire", reach: "local",
  keywords: ["blocked drain"], sources: { bluesky: true } };
{
  const p = M.scoringPrompt(FP, ["Plumbing"], { source: "bluesky", text: "Who can fix a blocked drain today?", lang: "en" });
  check("the prompt carries the member's offer, category, place and audience",
    p.indexOf(JSON.stringify(FP.offer_summary)) !== -1 && p.indexOf(JSON.stringify(["Plumbing"])) !== -1 && p.indexOf("Leeds, West Yorkshire") !== -1 && p.indexOf(JSON.stringify(FP.who_you_serve)) !== -1);
  const named = PRODUCTS.concat(["MrEarthRose", "mrearthrose", "BlackSunCircle", "BizForceAI"]).filter(x => p.indexOf(x) !== -1);
  check("and names no product of anyone else", named.length === 0, named.join(", "));
  const parsed = M.parseScore('{"score": 82, "reason": "asks for a plumber today", "safety": "SAFE", "invitation": "INVITED", "product": "War Horse"}');
  check("the parsed score is score, reason, safety and invitation only: a product the model names is never stored",
    JSON.stringify(Object.keys(parsed || {}).sort()) === JSON.stringify(["outreach_safe", "reason", "reply_invited", "score"]), JSON.stringify(parsed));
}

console.log("\n══ 3. the drafter writes for the member's own offer ══");
{
  const L = load(LRP);
  const lead = { source: "bluesky", text: "Who can fix a blocked drain today?" };
  const noLink = L.draftPrompt(FP, lead, null), withLink = L.draftPrompt(FP, lead, "https://bizforceai.net/listing.html?id=abc");
  check("the prompt carries the member's offer and audience", noLink.indexOf(JSON.stringify(FP.offer_summary)) !== -1 && noLink.indexOf(JSON.stringify(FP.who_you_serve)) !== -1);
  const named = PRODUCTS.concat(["MrEarthRose", "mrearthrose", "BlackSunCircle"]).filter(x => noLink.indexOf(x) !== -1 || withLink.indexOf(x) !== -1);
  check("and names no product of anyone else", named.length === 0, named.join(", "));
  check("its only link is the member's own listing, or none", /No links of any kind/.test(noLink) && /End with this link, exactly as written, and no other link: https:\/\/bizforceai\.net\/listing\.html\?id=abc/.test(withLink));
}

console.log("");
if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
console.log("ALL " + passes + " CHECKS PASSED");
