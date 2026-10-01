/* ══════════════════════════════════════════════════════════════════════════
   checkScorerProducts.js — the lead scorer and the drafter know every product
   MrEarthRose.com sells, and are told which are topicals.

   THE DEFECT. SCORER_ALLOWED_PRODUCTS (leadRadar.js) and
   OUTREACH_SUPPLEMENT_PRODUCTS (server.js) both held two of the six Mr. Earth
   Rose products, War Horse and Tongkat Ali. The scorer's prompt listed the same
   two. War Horse Black, Sword Vitality XXL Xtreme, War Horse Xtreme and War
   Horse Midnight could never be suggested, and a lead about one of them could
   never be drafted.

   WHAT THIS PROVES, from the working copy, with no model call and no database
   write:
     1. SCORER_ALLOWED_PRODUCTS holds all six, plus the book and "none".
     2. OUTREACH_SUPPLEMENT_PRODUCTS holds all six, and the drafter classifies
        a lead for each of them as a supplement-instruction offer.
     3. The scorer prompt, built exactly as scoreNewLeads builds it, lists each
        product on its own line and in the closing JSON contract.
     4. The prompt states the distinction between topicals and things taken by
        mouth: each topical's line says topical and for external use only,
        each shot's line says shot, and the selection rule forbids a topical
        for a post about something taken by mouth and the reverse.
     5. The drafter is told what each product is: the lead context it builds
        carries a facts line, and every topical's says For External Use Only.

   WHAT THIS DOES NOT PROVE. Whether the model, given a post, then chooses the
   right product. That needs a live model call, which no check here makes;
   4 proves the prompt gives it what it needs to choose, not that it chooses.

   MUTATE=drop:<product>  removes that product from both lists and from the
                          scorer prompt before anything is evaluated (default
                          "War Horse Midnight"). Its assertions in 1, 2 and 3
                          must go red.
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const { createResidueGuard, resolveSubjectAccount } = require("./checkRunResidue");
const SUBJECT_USER_ID = resolveSubjectAccount();

const fs = require("fs");
const vm = require("vm");
const path = require("path");
const REPO = path.join(__dirname, "..");

const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY
);
/* Nothing here writes; the guard is built so a future edit that adds a write
   has somewhere to record it, and its read-back runs regardless. */
const residue = createResidueGuard({ supabase: supabase, name: "scorerProducts", subject: SUBJECT_USER_ID, tables: [] });
residue.install();

const MUTATE = process.env.MUTATE || "";
if (MUTATE && !/^drop(:.+)?$/.test(MUTATE)) {
  console.error("Unknown MUTATE=" + MUTATE + ". Known: drop, drop:<product name>");
  process.exit(2);
}
const DROPPED = MUTATE ? (MUTATE.split(":")[1] || "War Horse Midnight") : null;

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

const PRODUCTS = ["War Horse", "War Horse Black", "Tongkat Ali", "Sword Vitality XXL Xtreme", "War Horse Xtreme", "War Horse Midnight"];
const TOPICALS = ["Sword Vitality XXL Xtreme", "War Horse Xtreme", "War Horse Midnight"];
const SHOTS = ["War Horse", "War Horse Black"];

let RADAR = fs.readFileSync(path.join(REPO, "leadRadar.js"), "utf8").replace(/\r\n/g, "\n");
let SERVER = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");

/* The mutation removes the product from the two list literals and its line
   from the prompt — the edit someone forgetting one product would leave. */
if (DROPPED) {
  const q = '"' + DROPPED + '"';
  const dropFromList = (src, name) => src.replace(new RegExp("(const " + name + " = \\[[^\\]]*\\])"), function (lit) {
    return lit.split(q + ", ").join("").split(", " + q).join("").split(q).join("");
  });
  RADAR = dropFromList(RADAR, "SCORER_ALLOWED_PRODUCTS");
  SERVER = dropFromList(SERVER, "OUTREACH_SUPPLEMENT_PRODUCTS");
  RADAR = RADAR.split("\n").filter(function (l) { return l.indexOf('"- ' + DROPPED + ":") === -1; }).join("\n");
  RADAR = RADAR.split(" | " + DROPPED + " |").join(" |");
  console.log("\n!! MUTATION: " + JSON.stringify(DROPPED) + " removed from both lists and the scorer prompt — its assertions must fail.");
}

function constLiteral(src, name) {
  const m = new RegExp("const " + name + " = (\\[[^\\]]*\\]);").exec(src);
  if (!m) throw new Error(name + " not found");
  return vm.runInNewContext(m[1]);
}
function objectLiteral(src, name) {
  const m = new RegExp("const " + name + " = (\\{[\\s\\S]*?\\n\\});").exec(src);
  if (!m) throw new Error(name + " not found");
  return vm.runInNewContext("(" + m[1] + ")");
}

(async function main() {
  await residue.sweepPrevious(SUBJECT_USER_ID);

  console.log("\n══ 1. SCORER_ALLOWED_PRODUCTS (leadRadar.js) ══");
  const allowed = constLiteral(RADAR, "SCORER_ALLOWED_PRODUCTS");
  console.log("    " + JSON.stringify(allowed));
  PRODUCTS.forEach(function (p) { check("1. holds " + JSON.stringify(p), allowed.indexOf(p) !== -1); });
  check("1. still holds the book and \"none\"", allowed.indexOf("Quantum Jumping book") !== -1 && allowed.indexOf("none") !== -1);

  console.log("\n══ 2. OUTREACH_SUPPLEMENT_PRODUCTS (server.js), and the offer it selects ══");
  const supplement = constLiteral(SERVER, "OUTREACH_SUPPLEMENT_PRODUCTS");
  const book = /const OUTREACH_BOOK_PRODUCT = ("[^"]*");/.exec(SERVER)[1];
  console.log("    " + JSON.stringify(supplement));
  const offerExpr = /var offerKind =\n([\s\S]*?);\n/.exec(SERVER);
  if (!offerExpr) throw new Error("the offerKind expression was not found in convertSingleLead");
  PRODUCTS.forEach(function (p) {
    const kind = vm.runInNewContext(offerExpr[1], { OUTREACH_BOOK_PRODUCT: JSON.parse(book), OUTREACH_SUPPLEMENT_PRODUCTS: supplement, suggestedProduct: p });
    check("2. holds " + JSON.stringify(p) + " and a lead for it is drafted (offer: " + kind + ")", supplement.indexOf(p) !== -1 && kind === "supplement", kind);
  });

  console.log("\n══ 3. the scorer prompt, as scoreNewLeads builds it ══");
  const promptStart = RADAR.indexOf("var prompt =\n");
  const promptEnd = RADAR.indexOf("}\";", promptStart);
  if (promptStart < 0 || promptEnd < 0) throw new Error("the scorer prompt was not found in leadRadar.js");
  const prompt = vm.runInNewContext(RADAR.slice(promptStart + "var prompt =".length, promptEnd + 2), {
    lang: "en", source: "bluesky", discovery: "keyword search", lead: { post_text: "fixture post" }
  });
  const lines = prompt.split("\n");
  const closing = lines.filter(function (l) { return l.indexOf("\"product\":") !== -1; })[0] || "";
  const contract = /"product": "<([^>]*)>"/.exec(closing);
  const contractValues = contract ? contract[1].split(" | ") : [];
  console.log("    closing contract values: " + JSON.stringify(contractValues));
  PRODUCTS.forEach(function (p) {
    check("3. " + JSON.stringify(p) + " has its own line in the product list", lines.some(function (l) { return l.indexOf("- " + p + ":") === 0; }));
    check("3. " + JSON.stringify(p) + " is in the closing JSON contract", contractValues.indexOf(p) !== -1, JSON.stringify(contractValues));
  });
  check("3. the contract's values are exactly SCORER_ALLOWED_PRODUCTS, in order",
    JSON.stringify(contractValues) === JSON.stringify(allowed), JSON.stringify(contractValues) + " vs " + JSON.stringify(allowed));
  check("3. the prompt says seven products", /classifier for seven products/.test(prompt));

  console.log("\n══ 4. the prompt states topical versus taken by mouth ══");
  function lineFor(p) { return lines.filter(function (l) { return l.indexOf("- " + p + ":") === 0; })[0] || ""; }
  TOPICALS.forEach(function (p) {
    const l = lineFor(p);
    console.log("    " + l);
    check("4. " + p + ": topical, for external use only", /topical|oil/i.test(l) && /for external use only/i.test(l), l);
  });
  SHOTS.forEach(function (p) {
    const l = lineFor(p);
    console.log("    " + l);
    check("4. " + p + ": a liquid shot", /liquid herbal shot/.test(l), l);
  });
  check("4. the selection rule forbids a topical for something taken, and a shot for something applied",
    /Never suggest a topical for a post about something to drink, swallow or take/.test(prompt) &&
    /never suggest a shot or Tongkat Ali for a post about something to apply/.test(prompt));
  check("4. Midnight is matched only on control or pacing, and no condition is named",
    /Suggest War Horse Midnight only for a post about control or pacing/.test(prompt) &&
    !/premature|ejaculat|erectile|\bED\b/i.test(lineFor("War Horse Midnight")));

  console.log("\n══ 5. what the drafter is told about each product ══");
  const facts = objectLiteral(SERVER, "OUTREACH_PRODUCT_FACTS");
  const ctxMatch = /var leadBlock =\n([\s\S]*?: ""\);)/.exec(SERVER);
  if (!ctxMatch) throw new Error("the drafter's lead context was not found in convertSingleLead");
  const ctxExpr = ctxMatch[1].replace(/;\s*$/, "");
  PRODUCTS.forEach(function (p) {
    const text = vm.runInNewContext(ctxExpr, {
      OUTREACH_PRODUCT_FACTS: facts, handle: "@fixture",
      lead: { post_text: "fixture", matched_keyword: "k", intent_score: 70, intent_reason: "r", suggested_product: p }
    });
    const line = text.split("\n").filter(function (l) { return l.indexOf("What the product is") === 0; })[0] || "";
    const topical = TOPICALS.indexOf(p) !== -1;
    check("5. " + p + ": the drafter gets a facts line" + (topical ? " saying For External Use Only" : " saying taken by mouth"),
      !!line && (topical ? /For External Use Only/.test(line) && /never describe it as taken/.test(line) : /taken by mouth/.test(line)), line || "(no facts line)");
  });

  console.log("\n══ cleanup ══");
  const done = await residue.cleanup("end of run");
  if (done.leftovers.length) failures++;

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
})().catch(function (err) {
  console.error("\nThe check threw: " + ((err && err.stack) || err));
  process.exit(1);
});
