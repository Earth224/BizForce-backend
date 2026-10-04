/* ══════════════════════════════════════════════════════════════════════════
   checkOutreachDestination.js — outreach is given the one URL it may link to,
   and a draft that links anywhere else is held, never sent.

   THE DEFECT. The drafter wrote "MrEarthRose.com" from memory: the instruction
   said "May mention MrEarthRose.com naturally at most once", and the business
   profile and past drafts repeated it. Nothing mapped a product to a page, and
   five drafts on 2026-07-08 pointed at MrEarthRose.com/libido — a path the
   model invented, which answers 404. detectOutreachLinkFacets (2026-08-19)
   now turns every URL in a reply into a working link, so an invented path
   would be posted as a clickable 404.

   WHAT THIS PROVES, by running the real convertSingleLead lifted from
   server.js — with the model, the database and both senders stubbed, so
   nothing is called, written or posted:
     1. Every product has a destination, all six https://mrearthrose.com/,
        and the destination map covers exactly the drafted products.
     2. For every product, the prompt the model receives carries that URL in
        the lead block, and the instruction names it as the only URL allowed,
        forbids checkout links, and no longer says "May mention
        MrEarthRose.com".
     3. On a LIVE run (dryRun false), a draft linking MrEarthRose.com/libido,
        a buy.stripe.com link, swordvitality.com, or mrearthrose.net/warhorse
        is rejected: no sender is called, the ai_tasks row records the reason
        in error, agent_memory is not written, the pipeline's last_draft opens
        with the rejection, and the result says send_reason "draft_rejected".
     4. A draft with the supplied URL is sent once, through the stub sender,
        unchanged — and so is a bare "MrEarthRose.com", which resolves to it.
        A book draft linking BlackSunCircle.com is sent; one linking another
        path on that site is held.
     5. The real detectOutreachLinkFacets turns the supplied URL into a link.

   MUTATE=no-rejection  runs convertSingleLead with the rejection removed.
                        Every assertion in 3 must go red.
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const { createResidueGuard, resolveSubjectAccount } = require("./checkRunResidue");
const SUBJECT_USER_ID = resolveSubjectAccount();

const fs = require("fs");
const vm = require("vm");
const path = require("path");
const { braceMatch, definitionOf } = require("./_shared");
const REPO = path.join(__dirname, "..");
const { RichText } = require(require.resolve("@atproto/api", { paths: [REPO] }));

const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY
);
/* Nothing here touches the database — the function under test gets a fake.
   The guard is built so a future edit that adds a real write has somewhere to
   record it, and its read-back runs regardless. */
const residue = createResidueGuard({ supabase: supabase, name: "outreachDestination", subject: SUBJECT_USER_ID, tables: [] });
residue.install();

const MUTATE = process.env.MUTATE || "";
if (MUTATE && MUTATE !== "no-rejection") { console.error("Unknown MUTATE=" + MUTATE + ". Known: no-rejection"); process.exit(2); }

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

const SRC = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
const HOME = "https://mrearthrose.com/";
const PRODUCTS = ["War Horse", "War Horse Black", "Tongkat Ali", "Sword Vitality XXL Xtreme", "War Horse Xtreme", "War Horse Midnight"];

function def(name) {
  const d = definitionOf(SRC, name);
  if (!d) throw new Error("EXTRACTION FAILED: " + name + " not found in server.js");
  return d;
}
let csl = def("convertSingleLead");
const REJECTION_CALL = /  var draftRejection = cleanMessage\n    \? outreachDraftRejection\([^;]*\)\n    : null;/;
if (!REJECTION_CALL.test(csl)) { console.error("EXTRACTION FAILED: the rejection call was not found in convertSingleLead."); process.exit(3); }
if (MUTATE === "no-rejection") {
  csl = csl.replace(REJECTION_CALL, "  var draftRejection = null;");
  console.log("\n!! MUTATION: convertSingleLead runs with the rejection removed — every assertion in 3 must fail.");
}
const LIFTED = ["formatLeadHandle", "OUTREACH_BOOK_PRODUCT", "OUTREACH_SUPPLEMENT_PRODUCTS", "OUTREACH_DAILY_CAP", "OUTREACH_PRODUCT_FACTS",
  "OUTREACH_HOME_URL", "OUTREACH_BIZFORCE_PRODUCT", "OUTREACH_PRODUCT_DESTINATIONS", "OUTREACH_BIZFORCE_DESTINATION", "OUTREACH_BOOK_DESTINATION", "OUTREACH_OWN_DOMAINS", "outreachDraftRejection",
  "nowIso", "DRAFT_ATTEMPT_CEILING", "OUTREACH_EMOJI_PATTERN", "stripOutreachEmoji", "truncateOrchestratorPreview", "normalizeMemoryMetadata",
  "detectOutreachLinkFacets"].map(def).join("\n\n");

/* A database that answers every query with nothing and records every write. */
function fakeDb(writes) {
  function q(table) {
    const st = { op: "select", payload: null, one: null };
    const b = {
      select() { return b; }, eq() { return b; }, neq() { return b; }, gte() { return b; }, lte() { return b; }, gt() { return b; },
      in() { return b; }, is() { return b; }, not() { return b; }, order() { return b; }, limit() { return b; },
      insert(p) { st.op = "insert"; st.payload = p; writes.push({ table: table, op: "insert", payload: p }); return b; },
      update(p) { st.op = "update"; st.payload = p; writes.push({ table: table, op: "update", payload: p }); return b; },
      upsert(p) { st.op = "upsert"; st.payload = p; writes.push({ table: table, op: "upsert", payload: p }); return b; },
      delete() { st.op = "delete"; writes.push({ table: table, op: "delete" }); return b; },
      maybeSingle() { st.one = "maybe"; return b; }, single() { st.one = "single"; return b; },
      then(res, rej) {
        let data = st.one ? null : [];
        if (st.op === "insert" && st.one) data = { id: "fake-" + table + "-" + writes.length };
        return Promise.resolve({ data: data, error: null, count: 0 }).then(res, rej);
      }
    };
    return b;
  }
  return { from: q, rpc: async () => ({ data: null, error: null }) };
}

function harness(modelText) {
  const writes = [], sends = [], prompts = [];
  const ctx = {
    supabase: fakeDb(writes), RichText: RichText, URL: URL, console: { log() {}, warn() {}, error() {} },
    process: { env: {} },
    canSendOutreach: async function () { return { allowed: true }; },
    callAnthropicText: async function (prompt) { prompts.push(prompt); return { text: modelText, stopReason: "end_turn" }; },
    sendBlueskyReply: async function (lead, text) { sends.push({ via: "bluesky", text: text }); return { sent: true, uri: "at://fake/post" }; },
    sendMastodonReply: async function (lead, text) { sends.push({ via: "mastodon", text: text }); return { sent: true, uri: "https://fake/post" }; }
  };
  vm.createContext(ctx);
  vm.runInContext(LIFTED + "\n\n" + csl + "\nthis.run = convertSingleLead;", ctx);
  return { ctx, writes, sends, prompts };
}
function lead(product) {
  return { id: "lead-1", post_uri: "at://did:plc:fixture/app.bsky.feed.post/1", source: "bluesky", author_handle: "fixture.bsky.social",
    post_text: "any recommendations for low energy?", matched_keyword: "low energy", intent_score: 80, intent_reason: "asks", suggested_product: product };
}
const draft = msg => JSON.stringify({ outreach_message: msg, internal_analysis: "fixture analysis" });

(async function main() {
  await residue.sweepPrevious(SUBJECT_USER_ID);

  console.log("\n══ 1. the destination map ══");
  const map = vm.runInNewContext(def("OUTREACH_HOME_URL") + "\n" + def("OUTREACH_PRODUCT_DESTINATIONS") + "\nOUTREACH_PRODUCT_DESTINATIONS");
  const drafted = vm.runInNewContext(def("OUTREACH_SUPPLEMENT_PRODUCTS") + "\nOUTREACH_SUPPLEMENT_PRODUCTS");
  console.log("    " + JSON.stringify(map));
  PRODUCTS.forEach(function (p) { check("1. " + p + " → " + HOME, map[p] === HOME, map[p]); });
  /* The supplement products, and BizForceAI, which the BizForce pipeline
     drafts (checkBizforceOutreach.js covers it). */
  check("1. the map's keys are exactly the drafted products", JSON.stringify(Object.keys(map).sort()) === JSON.stringify(drafted.concat(["BizForceAI"]).sort()),
    JSON.stringify(Object.keys(map)) + " vs " + JSON.stringify(drafted.concat(["BizForceAI"])));

  console.log("\n══ 2. what the model is given, per product ══");
  for (const p of PRODUCTS) {
    const h = harness(draft("Worth exploring. " + HOME));
    await h.ctx.run(SUBJECT_USER_ID, lead(p), "SYSTEM", true);
    const prompt = h.prompts[0] || "";
    check("2. " + p + ": lead block carries \"The one link you may give them: " + HOME + "\"", prompt.indexOf("The one link you may give them: " + HOME) !== -1);
    check("2. " + p + ": instruction names it as the only URL and forbids checkout",
      prompt.indexOf("You may link to " + HOME + " at most once") !== -1 &&
      prompt.indexOf("It is the only URL this reply may contain") !== -1 &&
      prompt.indexOf("Never link a checkout, cart, payment or order URL of any kind") !== -1 &&
      prompt.indexOf("May mention MrEarthRose.com") === -1);
  }
  const shown = harness(draft("x")); await shown.ctx.run(SUBJECT_USER_ID, lead("War Horse"), "SYSTEM", true);
  const instr = /You may link to [^\n]*?direct-purchase link\. /.exec(shown.prompts[0] || "");
  console.log("    instruction text: " + (instr ? JSON.stringify(instr[0]) : "(not found)"));

  console.log("\n══ 3. LIVE runs: drafts that link elsewhere are held ══");
  const bad = [
    ["MrEarthRose.com/libido (the invented 404)", "Worth exploring. MrEarthRose.com/libido"],
    ["a buy.stripe.com checkout", "Grab it here: https://buy.stripe.com/cNi00jd7y0dK4oSaezaMU02"],
    ["swordvitality.com", "Worth exploring. https://swordvitality.com/"],
    ["mrearthrose.net/warhorse", "Worth exploring. https://mrearthrose.net/warhorse"],
    ["the right host with a different path", "Worth exploring. https://mrearthrose.com/products"]
  ];
  for (const [label, msg] of bad) {
    const h = harness(draft(msg));
    const r = await h.ctx.run(SUBJECT_USER_ID, lead("War Horse"), "SYSTEM", false);
    const task = h.writes.find(w => w.table === "ai_tasks" && w.op === "insert");
    const mem = h.writes.find(w => w.table === "agent_memory");
    const pipe = h.writes.find(w => w.table === "sales_lead_pipeline" && (w.op === "upsert" || w.op === "update") && w.payload && w.payload.last_draft);
    console.log("    " + label + " → send_reason " + JSON.stringify(r && r.send_reason) + " | ai_tasks.error " + JSON.stringify(task && task.payload.error));
    check("3. " + label + ": never reaches a sender", h.sends.length === 0, h.sends.length + " send(s): " + JSON.stringify(h.sends));
    check("3. " + label + ": result says draft_rejected, not sent", !!r && r.sent === false && r.send_reason === "draft_rejected", JSON.stringify(r && { sent: r.sent, send_reason: r.send_reason }));
    check("3. " + label + ": ai_tasks.error records why", !!task && /^draft rejected, not sent: /.test(task.payload.error || ""), task && task.payload.error);
    check("3. " + label + ": not written to agent_memory", !mem, mem && "memory written");
    check("3. " + label + ": pipeline last_draft opens with the rejection", !!pipe && /^DRAFT REJECTED, NOT SENT: /.test(pipe.payload.last_draft), pipe && String(pipe.payload.last_draft).slice(0, 80));
  }

  console.log("\n══ 4. LIVE runs: drafts that link only where they were sent are sent ══");
  const good = [
    ["the supplied URL", "War Horse", "Worth exploring. " + HOME],
    ["a bare MrEarthRose.com (resolves to it)", "War Horse", "Worth exploring. MrEarthRose.com"],
    ["no link at all", "Tongkat Ali", "Worth exploring, all-natural support for energy."],
    ["a book draft on BlackSunCircle.com", "Quantum Jumping book", "It is about this exact question. BlackSunCircle.com"]
  ];
  for (const [label, product, msg] of good) {
    const h = harness(draft(msg));
    const r = await h.ctx.run(SUBJECT_USER_ID, lead(product), "SYSTEM", false);
    const task = h.writes.find(w => w.table === "ai_tasks" && w.op === "insert");
    check("4. " + label + ": sent once, unchanged, no error recorded",
      h.sends.length === 1 && h.sends[0].text === msg && !!r && r.sent === true && !!task && task.payload.error === null,
      JSON.stringify({ sends: h.sends, sent: r && r.sent, reason: r && r.send_reason, error: task && task.payload.error }));
  }
  const bookOther = harness(draft("Here it is: https://blacksuncircle.com/join"));
  const rb = await bookOther.ctx.run(SUBJECT_USER_ID, lead("Quantum Jumping book"), "SYSTEM", false);
  check("4. a book draft linking another BlackSunCircle.com path is held", bookOther.sends.length === 0 && rb.send_reason === "draft_rejected", JSON.stringify(rb && rb.send_reason));

  console.log("\n══ 5. the real link detector on the supplied URL ══");
  const det = harness("x");
  const facets = det.ctx.detectOutreachLinkFacets("Worth exploring. " + HOME);
  const uris = facets.flatMap(f => f.features.map(x => x.uri));
  console.log("    detectOutreachLinkFacets(\"Worth exploring. " + HOME + "\") → " + JSON.stringify(uris));
  check("5. the supplied URL becomes exactly one link, to itself", uris.length === 1 && uris[0] === HOME, JSON.stringify(uris));

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
