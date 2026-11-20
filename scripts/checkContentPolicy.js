"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   checkContentPolicy.js — the content policy screen (P2-2, Nov 20 2026).

   lib/contentPolicy.js screens every text a member writes for others to read:
   health claims first (the existing screen, passed in), then the prohibited
   list, then links, then contact details (public text only).

   WHAT THIS PROVES
     A. THE LIST. PROHIBITED is owned here: its twelve categories in order, and
        a fingerprint of every term. A changed term changes the fingerprint;
        update PROHIBITED_SHA below, NAMED, with the reason.
     B. THE SCREEN, run for real: a refuse term is refused with its label in
        one sentence; a review term is saved and returns findings; terms match
        as whole words, any case, a hyphen or a space alike; at most 2 links,
        https only, no shorteners (written as a link or bare); an email or a
        10 to 15 digit phone is refused in public text and allowed in a private
        message; the claims screen runs first; screenFields names the field
        and gathers every finding; refusalBody is { error, reason
        "content_policy", rule, field }.
     C. THE SERVER. policyScreen passes the server's own claims screen
        (blueskyClaimsRefusal) and the surface; policyRefused answers 400 with
        refusalBody; policyQueue (run in a vm) queues findings, and nothing
        when there are none. The routes that screen are exactly SCREENED; each
        refuses before it writes and queues after, except the support note
        (refused with "Nothing was sent.", never queued: it is not kept as an
        item). A private message is screened as "private".
     D. THE AGENTS. The proposal executors publish_listing and update_listing
        screen as their routes do and fail the proposal on a refusal.
     E. THE TERMS. terms.html's prohibited list names every label.

   MUTATE=<name> applies one mutation in memory; MUTATE=all runs each.
   ═══════════════════════════════════════════════════════════════════════════ */
const vm = require("vm");
const crypto = require("crypto");
const H = require("./_p21Harness");
const sh = require("./_shared");

const SERVER = "@server.js", CP = "@lib/contentPolicy.js", SAFETY = "@lib/safety.js";
const MUTATIONS = {
  "drop-refuse-term": [[CP, 'refuse: ["recalled"],', "refuse: [],"]],
  "contact-in-private": [[CP, 'if (opts.surface !== "private") {', "if (true) {"]],
  "three-links": [[CP, "const MAX_LINKS = 2;", "const MAX_LINKS = 3;"]],
  "claims-after-list": [[CP, "  // (a) the existing claims screen, exactly as it is\n  if (typeof opts.claims === \"function\") {", "  if (false) {"]],
  "campaign-edit-unrefused": [[SERVER, "const screened = policyScreen({ title: updates.title, description: updates.description, category: updates.category });\n    if (!screened.ok) return policyRefused(res, screened);",
    "const screened = policyScreen({ title: updates.title, description: updates.description, category: updates.category });"]],
  "messages-public": [[SERVER, 'policyScreen({ content: content }, "private")', "policyScreen({ content: content })"]],
  "queue-always-null": [[SERVER, "if (!screened || !screened.review || !objectId) return null;", "return null;"]],
  "agent-unscreened": [[SERVER, 'if (!screened.ok) throw new Error("publish_listing: " + screened.error);', ""]]
};
const T = H.setup(__filename, MUTATIONS, [SERVER, CP, SAFETY, "terms.html"]);
const { FILES, check, J, has } = T;
const C = T.libRequire("./lib/contentPolicy");

const CATEGORIES = ["weapons", "drugs", "prescription", "tobacco", "alcohol", "adult", "gambling", "counterfeits", "animals", "recalled",
  "personal_data", "guaranteed_returns"];
const PROHIBITED_SHA = "64f1d186265f8285";
const SCREENED = ["PUT /api/profile/me", "POST /api/messages", "POST /api/business-profile", "POST /api/wallet/support", "PUT /api/support/me",
  "POST /api/marketplace/listings", "PUT /api/marketplace/listings/:id", "POST /api/crowdfunding/campaigns", "PUT /api/crowdfunding/campaigns/:id",
  "PUT /api/bfp/profile/me", "PUT /api/business-profile"];

(async function main() {
  /* ── A ── */
  console.log("\n══ A. the prohibited list ══");
  const sha = crypto.createHash("sha256").update(JSON.stringify(C.PROHIBITED)).digest("hex").slice(0, 16);
  check("A1. twelve categories, in order", J(C.PROHIBITED.map(p => p.category)) === J(CATEGORIES), J(C.PROHIBITED.map(p => p.category)));
  check("A2. every category has a label, refuse terms and review terms, all lower case", C.PROHIBITED.every(p => p.label && p.refuse.length && p.review.length &&
    p.refuse.concat(p.review).every(t => t === t.toLowerCase() && t.trim() === t)));
  check("A3. the terms are exactly as owned here (fingerprint " + PROHIBITED_SHA + ")", sha === PROHIBITED_SHA, "now " + sha);
  check("A4. no term is both refused and reviewed", C.PROHIBITED.every(p => p.refuse.every(t => p.review.indexOf(t) === -1)));

  /* ── B ── */
  console.log("\n══ B. the screen ══");
  const pub = (t, o) => C.screen(t, Object.assign({ surface: "public" }, o || {}));
  const r1 = pub("Recalled strollers, cheap");
  check("B1. a refuse term is refused, with its label and the term in one sentence", r1.ok === false && r1.status === 400 && r1.rule === "prohibited" &&
    r1.category === "recalled" && r1.error === "Recalled goods can't be offered or shown on BizForce (it matched \"recalled\"). Take it out and try again. The Terms, Acceptable use, list what isn't allowed.", J(r1));
  const r2 = pub("Wine rack, solid oak");
  check("B2. a review term is saved, with its finding", r2.ok === true && J(r2.review) === J({ findings: [{ field: "text", rule: "prohibited", category: "alcohol", term: "wine" }] }), J(r2));
  check("B3. whole words only: \"swine\" and \"recalledx\" pass, \"RECALLED\" does not", pub("swine flu poster").ok && !pub("swine flu poster").review && pub("recalledx").ok && !pub("RECALLED").ok);
  const d8 = ["delta-8 gummies", "delta 8 gummies", "delta8 gummies"].map(t => pub(t).review && pub(t).review.findings[0].term);
  check("B4. a hyphen in a term matches a hyphen, a space or nothing: \"delta-8\"", J(d8) === J(["delta-8", "delta-8", "delta-8"]), J(d8));
  check("B5. plain text passes with nothing to review", J(pub("Handmade candles, lavender and cedar")) === J({ ok: true, review: null }));
  const three = pub("https://a.example/1 https://b.example/2 https://c.example/3");
  check("B6. three links are refused; two pass", three.ok === false && three.rule === "links" && three.error === C.MESSAGES.tooManyLinks && pub("https://a.example/1 https://b.example/2").ok, J(three));
  check("B7. an http:// link is refused", pub("see http://a.example/x").error === C.MESSAGES.notHttps);
  check("B8. a shortener is refused, as a link and bare", pub("https://bit.ly/abc").matched === "bit.ly" && pub("go to bit.ly/abc now").matched === "bit.ly" && /hide where a link goes/.test(pub("bit.ly/abc").error));
  check("B9. an email or a phone number is refused in public text", pub("write me at sam@example.com").rule === "contact" && pub("call 555-201-3344 today").rule === "contact" && pub("call 555-201-3344 today").error === C.MESSAGES.contact);
  check("B10. a short number is not a phone (\"order 12345\")", pub("order 12345 ships Monday").ok === true);
  check("B11. in a private message an email and a phone are allowed; the list still applies", C.screen("sam@example.com, 555-201-3344", { surface: "private" }).ok === true &&
    C.screen("recalled cribs", { surface: "private" }).ok === false);
  const order = [];
  const claimsFirst = C.screen("recalled vitamins cure cancer", { claims: t => { order.push(t); return { error: "CLAIMS", violations: [{ matched: "cure cancer" }] }; } });
  check("B12. the claims screen runs first, and its own sentence is used", claimsFirst.ok === false && claimsFirst.rule === "health_claims" && claimsFirst.error === "CLAIMS" && order.length === 1, J(claimsFirst));
  const f = C.screenFields({ title: "Oak wine rack", tags: ["beer", "home"], description: "" }, { surface: "public" });
  check("B13. screenFields gathers every finding, each with its field (arrays too)", f.ok && J(f.review.findings.map(x => x.field + ":" + x.term)) === J(["title:wine", "tags:beer"]), J(f));
  const fr = C.screenFields({ title: "Oak rack", description: "recalled" }, {});
  check("B14. screenFields returns the first refusal, naming its field", fr.ok === false && fr.field === "description", J(fr));
  check("B15. refusalBody", J(C.refusalBody(fr)) === J({ error: fr.error, reason: "content_policy", rule: "prohibited", field: "description" }));
  check("B16. text that is not text is refused", C.screen(42, {}).rule === "type" && C.screen(null, {}).ok === true);

  /* ── C ── */
  console.log("\n══ C. the server ══");
  const S = FILES[SERVER];
  const fnText = name => { const at = S.indexOf((name === "policyQueue" ? "async " : "") + "function " + name + "("); return at < 0 ? "" : S.slice(at, sh.braceMatch(S, S.indexOf("{", at)) + 1); };
  check("C1. policyScreen passes the server's claims screen and the surface (public unless named)",
    has(fnText("policyScreen"), 'require("./lib/contentPolicy").screenFields(fields, { claims: blueskyClaimsRefusal, surface: surface || "public" })'));
  check("C2. policyRefused answers 400 with refusalBody", has(fnText("policyRefused"), 'return res.status(400).json(require("./lib/contentPolicy").refusalBody(screened));'));
  const db = H.fakeDb((t, q) => t === "moderation_queue" && q.op === "select" ? { data: null, error: null } : { data: Object.assign({ id: "q1" }, q.payload), error: null });
  const ctx = { require: T.libRequire, supabase: db.client, nowIso: () => "2026-11-20T12:00:00.000Z", console: { log() {}, warn() {}, error() {} } };
  vm.createContext(ctx);
  vm.runInContext(fnText("policyQueue"), ctx);
  const none = await ctx.policyQueue({ ok: true, review: null }, "listing", "l1", "u1");
  const logBefore = db.log.length;
  const queued = await ctx.policyQueue({ ok: true, review: { findings: [{ field: "title", rule: "prohibited", category: "alcohol", term: "wine" }] } }, "listing", "l1", "u1");
  const ins = db.log.find(q => q.table === "moderation_queue" && q.op === "insert");
  check("C3. policyQueue writes nothing when there is nothing to review", none === null && logBefore === 0, db.log.length);
  check("C4. policyQueue queues the findings as source policy_screen, priority 2, waiting", !!ins && ins.payload.source === "policy_screen" && ins.payload.priority === 2 &&
    ins.payload.state === "waiting" && ins.payload.object_type === "listing" && ins.payload.object_id === "l1" && ins.payload.owner_id === "u1" &&
    J(ins.payload.screen_findings) === J([{ field: "title", rule: "prohibited", category: "alcohol", term: "wine" }]) && !!queued, J(ins && ins.payload));
  const screened = H.routesWith(S, "policyScreen(");
  check("C5. the routes that screen are exactly these " + SCREENED.length, J(screened) === J(SCREENED), J(screened));
  const refusing = H.routesWith(S, "if (!screened.ok) return policyRefused(res, screened);"), queuing = H.routesWith(S, "await policyQueue(screened, ");
  const exempt = ["POST /api/wallet/support"];
  check("C6. each refuses with policyRefused and queues with policyQueue (the support note excepted)",
    SCREENED.filter(r => exempt.indexOf(r) === -1).every(r => refusing.indexOf(r) !== -1 && queuing.indexOf(r) !== -1), J({ refusing, queuing }));
  const late = SCREENED.filter(r => {
    const [m, p] = r.split(" ");
    const st = H.routeStatement(S, m.toLowerCase(), p) || "";
    const at = st.indexOf("policyScreen("), first = Math.min(...[".insert(", ".update(", ".upsert("].map(w => { const i = st.indexOf(w); return i < 0 ? Infinity : i; }));
    return st && !(at !== -1 && at < first);
  });
  check("C7. each screens before it writes anything", late.length === 0, J(late));
  const support = H.routeStatement(S, "post", "/api/wallet/support") || "";
  check("C8. the support note is refused with \"Nothing was sent.\" and never queued", has(support, 'const screened = policyScreen({ note: note.note });') &&
    has(support, 'Object.assign(require("./lib/contentPolicy").refusalBody(screened), { error: screened.error + " Nothing was sent." })') && !has(support, "policyQueue("));
  const msg = H.routeStatement(S, "post", "/api/messages") || "";
  check("C9. a private message is screened as \"private\" (contact details allowed), and queued once saved",
    has(msg, 'policyScreen({ content: content }, "private")') && msg.indexOf('policyQueue(screened, "message", data.id') > msg.indexOf(".insert("));

  /* ── D ── */
  console.log("\n══ D. the agents ══");
  const pubFn = S.slice(S.indexOf("  publish_listing: async function (proposal) {"), S.indexOf("  update_listing: async function (proposal) {"));
  const updAt = S.indexOf("  update_listing: async function (proposal) {");
  const updFn = updAt < 0 ? "" : S.slice(updAt, sh.braceMatch(S, S.indexOf("{", updAt)) + 1);
  check("D1. publish_listing screens as the create route does, and a refusal fails the proposal",
    has(pubFn, "const screened = policyScreen({ title: title, description: description, tags: tags });\n    if (!screened.ok) throw new Error(\"publish_listing: \" + screened.error);") && has(pubFn, 'await policyQueue(screened, "listing", data.id, proposal.user_id);'));
  check("D2. update_listing screens as the edit route does, and a refusal fails the proposal",
    has(updFn, "const screened = policyScreen({ title: updates.title, description: updates.description, tags: updates.tags });\n    if (!screened.ok) throw new Error(\"update_listing: \" + screened.error);") && has(updFn, 'await policyQueue(screened, "listing", listingId, proposal.user_id);'));

  /* ── E ── */
  console.log("\n══ E. the Terms ══");
  const terms = FILES["terms.html"] || "";
  const missing = C.PROHIBITED.map(p => p.label.charAt(0).toLowerCase() + p.label.slice(1)).filter(l => terms.indexOf(l.replace(/'/g, "&#39;")) === -1 && terms.indexOf(l) === -1);
  check("E1. terms.html's prohibited list names every label", has(terms, "anything on the prohibited list:") && missing.length === 0, J(missing));
  check("E2. no emoji in the lib or this check", !/\p{Extended_Pictographic}/u.test(FILES[CP] + require("fs").readFileSync(__filename, "utf8")));

  T.finish();
})().catch(e => { console.error(e); process.exit(1); });
