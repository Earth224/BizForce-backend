/* ═══════════════════════════════════════════════════════════════════════════
   checkSeoMoneyPath.js — an internal SEO post can name a page on this platform
   as its money link, and an arrival through that link is counted.

   THE GAP. An internal post's money link could only be one of the seller's
   /listing/ pages, and the generator required exactly one whenever the seller
   had any. So no article published here could send its reader to
   /suppressed.html, the page written for the businesses BizForce serves; and
   engine_visits, which counts arrivals, accepted only a Lead Radar ref.

   WHAT THIS PROVES, with no model call, no database write and no send — the
   route, the executor and the visits route are lifted from the working copy and
   from BASELINE, the commit before this change, and run against a recording
   stub database and a scripted model:
     1. money_path that is not on the allowlist — another path, another case, an
        absolute URL, no leading slash, a number, an array — is refused with 422
        naming the allowlist. The model is never called and nothing is written.
        Absent, null and "" are no money_path at all.
     2. money_path with money_url is refused with 422, naming both. Neither wins.
     3. Generation with money_path: the prompt names the page and what it is,
        carries no listing catalog and no listing rule; a post linking the page
        is filed with money_path and no money_url or site; a post that does not
        link it — or links only a listing — is refused, nothing filed.
     4. Publish with money_path: the post is published here (internal, status
        published, site null) and its money link — body and internal_links —
        carries ?ref=bl-<token>. A body without the link, a money_path no longer
        on the allowlist, and a payload with both keys each throw and write
        nothing.
     5. The token is bl- and ten hex of SHA-256 over "blog:<user_id>:<slug>":
        the same post the same token, another slug or author another, and no
        slug or id text in it.
     6. Without money_path nothing changed: for internal posts with and without
        listings, with a topic, and external posts with and without a compliance
        profile, the prompt the model receives, the response and every row
        written are identical to BASELINE; and the executor, on internal,
        external and failing proposals, writes and returns exactly what
        BASELINE does.
     7. POST /api/engine-visits accepts bl- and still accepts lr-, writing only
        { ref, landing_path }; refuses a malformed ref; answers 503 naming
        migration 130 when the table's constraint refuses a ref, and 503 naming
        128 when the table is missing.
     8. Migration 130's constraint accepts exactly what the route accepts, over
        every lr- and bl- token above and the malformed set, and finds 128's
        check by what it checks rather than by name.

   ADDED AFTER THE FIRST REAL ARTICLE ("Three things the first article got
   wrong"). Section 6 now holds every prompt to BASELINE with the one block
   below taken out, and the route is driven as the platform's own account:
     9. An own-page post is offered only the author's posts that already link
        the same page; the first one is offered none, told so, and still filed.
        A listing-mode post is still offered every post.
    10. Every mode's prompt carries the no-invented-facts block once, ahead of
        the writing brief; it names the claims the first article invented and
        borrows nothing from NO_INVENTION_RULE.
    11. Only an own-page prompt tells the writer to name BizForce AI, write
        "we built" and not hide that it is paid.

   ADDED AFTER THE SECOND ARTICLE ("A platform cannot promise escape from
   platforms"), which called BizForce AI and an email list things no platform
   can disable, never said the platform costs anything, and linked it with the
   bare path as anchor text:
    13. The own-page prompt says BizForce AI is itself a platform, that the
        email service can suspend sending, and forbids calling BizForce AI, the
        blog, the storefront or a list beyond any platform's reach; it tells the
        writer to say the platform is paid and what it costs; and, without
        money_anchor, not to use the href as the link's text. With money_anchor
        it is the suggested text instead. No other mode's prompt says any of it.

   ADDED WHEN THE BLOCK WAS NARROWED ("Let the article name the category
   without inventing the policy"), section 10 also holds: the block asks for
   advice specific to the business, naming its category, not general advice;
   it lets the writer say ad platforms publish policies restricting some
   products in that category but never what a policy says; and the rate claim
   and "largely automated" are both still named as forbidden.

   ADDED WITH "Name the product, not the condition":
    14. With a compliance profile active — auto on a vitality host, or named
        explicitly in external, listing or own-page mode — the prompt carries a
        line telling the writer to name the category as a product type, never
        by a condition, once, after both the compliance section and the
        no-invented-facts block, ahead of the writing brief, and it is that
        commit's prompt plus exactly this line. Without a profile, the own-page,
        external and listing prompts are byte-identical to that commit's.

   ADDED WITH "Screen what the rule could not stop":
    15. findArticleClaims catches every claim the four own-page drafts made, each
        by its own class, and none of the innocent uses of the same words. An
        article stating one is 422 at generation in own-page, listing and
        external mode, listing each sentence and filing nothing; the same
        article without it is filed. At publish a body or meta description
        stating one throws and writes nothing. The positives are the drafts'
        own sentences — the screen was tuned on them, so this proves it holds
        what it was built for, not how it does on text it has not seen.

   ADDED WITH "Around the product, not around the problem":
    16. In own-page mode, when site_context names a health-adjacent product
        (supplements, CBD, hemp, wellness products and the like), the prompt
        tells the writer to advise those sellers to write around the product,
        never around a condition or problem — once, after the no-invented-facts
        block (and after the product-type line when a profile is active), ahead
        of the brief, and it is 60c9bc1's prompt plus exactly that line. With no
        site_context, or one naming only firearms or esoteric goods, the
        own-page prompt is byte-identical to 60c9bc1's; so are the listing and
        external prompts, even with a supplement site_context.
    12. money_path from any other account is 403 at generation and throws at
        publish; without money_path that account is unaffected.

   ADDED WITH "Repair the sentence, not the article":
    17. Two narrowings. typicality does not fire in a sentence ending "?", and
        named_company_policy does not fire in one carrying "not about why",
        "isn't something you can see", "no way to know", "can't know why" or
        "don't guess". Of generation 5's five hits, the declining sentence and
        the FAQ heading now pass and the other three are still caught. What each
        lets back in is asserted, so the comment in server.js stays true:
        draft 1's "...so often?" heading, and a claim wrapped in a declining
        phrase. Section 15 no longer counts that heading as a catch.
    18. ONE repair. When the claim screen is the only gate a draft fails, the
        route makes exactly one more model call, under its own ledger route,
        with the rules, the article and the numbered flagged sentences; the
        filed article is the first one with only those sentences replaced —
        title, meta description and body alike — and the proposal carries
        claim_repair. A rewrite that still states a claim, an unusable answer,
        a failed call, or a sentence that runs across markup (no call at all)
        is 422, and never a third call. The rewritten article meets every gate
        again: the money-link, compliance and claim checks run on it (counted),
        and it is refused for a compliance violation or a body under 800
        characters that only the rewrite introduced.
    19. Every draft the route refuses after the model answered — unreadable or
        failing any gate, repaired or not — is one seo_refused_drafts row with
        the draft as returned, the refusal sent, the repair and the brief; a
        filed draft writes none; a failed insert changes nothing the caller
        sees; and migration 131 has a column for every key the route writes.

   ADDED WITH "A platform is a population too":
    20. The quantity class counts the systems as well as the people: one
        sentence per noun added — networks, platforms, processors, providers,
        services, sites, websites, marketplaces, engines — is caught, generation
        7's "most ad networks publish one" verbatim among them, and none was
        caught at 44535d4. Channels, tools and apps are not counted, and a
        system noun after how, as, the or a few still passes. What it lets in —
        "there are many platforms you can post on" — is asserted, so the
        comment in server.js stays true.
    21. Every own-page prompt tells the writer to say, in the same mention,
        that the blog and storefront run on BizForce AI's platform under its
        terms and are not owned outright — once, right after the disclosure,
        ahead of the brief — and is 44535d4's prompt plus exactly that clause,
        with or without money_anchor or a compliance profile. The listing and
        external prompts are byte-identical to 44535d4's. Sections 14 and 16
        take the clause out before comparing an own-page prompt with their
        older commits.

   MUTATIONS — each must turn the named section red:
     MUTATE=allowlist    any root-relative path is accepted               → 1
     MUTATE=silent       an off-allowlist path is dropped, not refused     → 1
     MUTATE=both         money_path with money_url is not refused          → 2
     MUTATE=listingrule  an own-page post is still told to link a listing  → 3
     MUTATE=gencheck     generation does not check the money link          → 3
     MUTATE=pubcheck     publish does not check the money link             → 4
     MUTATE=noref        publish does not add the arrival parameter        → 4
     MUTATE=personal     the token is the slug itself                      → 5
     MUTATE=leak         an internal post with no listings gets the own-page rule → 6
     MUTATE=lronly       the route accepts lr- only                        → 7
     MUTATE=blonly       the route accepts bl- only                        → 7
     MUTATE=migration    migration 130 still pins lr- only                 → 8
     MUTATE=alltargets   an own-page post is offered every published post  → 9
     MUTATE=firstpost    the first own-page post is told "no posts yet"    → 9
     MUTATE=nofacts      the no-invented-facts block is not in the prompt  → 10
     MUTATE=nodisclose   an own-page post is not told to say "we built"    → 11
     MUTATE=discloseall  an external post is told to say "we built"        → 11
     MUTATE=anyauthor    any account may send money_path                   → 12
     MUTATE=escape       the page text no longer says BizForce AI is a platform → 13
     MUTATE=emailsend    it no longer says the email service can suspend sending → 13
     MUTATE=hideprice    the writer is only told "do not hide" that it is paid → 13
     MUTATE=pathanchor   the writer is not told to keep the href out of the anchor → 13
     MUTATE=generaladvice the block asks for general advice again         → 10
     MUTATE=statepolicy  the writer is not forbidden to say what a policy says → 10
     MUTATE=internals    the internals clause is gone                     → 10
     MUTATE=ratesback    the statistics clause is gone                    → 10
     MUTATE=productalways the product-type line is in every prompt        → 14
     MUTATE=productnever the product-type line is in no prompt            → 14
     MUTATE=productfirst it sits before the compliance section            → 14
     MUTATE=conditionok  it no longer forbids naming the condition        → 14
     MUTATE=noquantity   the claim screen's quantity class never matches  → 15
     MUTATE=notypicality its typicality class never matches               → 15
     MUTATE=nofigure     its figure class never matches                   → 15
     MUTATE=noreach      its beyond-reach class never matches             → 15
     MUTATE=nocompany    its named-company class never matches            → 15
     MUTATE=genscreen    generation does not screen                       → 15
     MUTATE=pubscreen    publish does not screen                          → 15
     MUTATE=innocent     "your most …", "at most", "how many" are caught  → 15
     MUTATE=faqheading   "Frequently asked questions" is caught: every
                         article has that heading, so every one is refused → 3
     MUTATE=problemnever   the around-the-product line is never emitted   → 16
     MUTATE=problemalways  it fires in own-page mode whatever site_context says → 16
     MUTATE=problemanymode it fires in every mode                          → 16
     MUTATE=problemwording it no longer says "never around a condition"    → 16
     MUTATE=noquestion     typicality fires inside a question again        → 17
     MUTATE=nodecline      declining to know no longer exempts a sentence  → 17
     MUTATE=norepair       a claim hit is refused with no repair           → 18
     MUTATE=repairloops    the repair runs until the article passes        → 18
     MUTATE=repairunscreened the repaired article is filed unchecked       → 18
     MUTATE=norecord       a refused draft is not stored                   → 19
     MUTATE=nosystems      the system nouns are gone from the population   → 20
     MUTATE=nothosted      the own-page prompt has no hosted-blog clause   → 21
     MUTATE=hostedanymode  the external prompt gets the clause too         → 21
     MUTATE=hostedwording  it no longer says "not one it owns outright"    → 21
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
/* money_path is the platform's own account's alone, so the lifted route and
   executor are driven as that account. Only their stub database ever sees the
   id — nothing here reads or writes a real row under it. The check subject
   stays the residue guard's, and is the "any other account" of section 12. */
const { OWNER_ACCOUNT_ID: AUTHOR } = require("../lib/ownerAccount");
const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY);
/* Nothing here writes; the guard is built so a future edit that adds a write
   has somewhere to record it, and its read-back runs regardless. */
const residue = createResidueGuard({ supabase: supabase, name: "seoMoneyPath", subject: SUBJECT_USER_ID, tables: [] });
residue.install();

/* The commit before money_path existed. Pinned, not HEAD. */
const BASELINE = "6f94afe";

const MUTATIONS = ["allowlist", "silent", "both", "listingrule", "gencheck", "pubcheck", "noref", "personal", "leak", "lronly", "blonly", "migration",
  "alltargets", "firstpost", "nofacts", "nodisclose", "discloseall", "anyauthor", "escape", "emailsend", "hideprice", "pathanchor",
  "generaladvice", "statepolicy", "internals", "ratesback", "productalways", "productnever", "productfirst", "conditionok",
  "noquantity", "notypicality", "nofigure", "noreach", "nocompany", "genscreen", "pubscreen", "innocent", "faqheading",
  "problemnever", "problemalways", "problemanymode", "problemwording",
  "noquestion", "nodecline", "norepair", "repairloops", "repairunscreened", "norecord",
  "nosystems", "nothosted", "hostedanymode", "hostedwording"];
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
let MIG130 = fs.readFileSync(path.join(REPO, "supabase", "migrations", "130_engine_visits_blog_ref.sql"), "utf8").replace(/\r\n/g, "\n");

if (MUTATE === "allowlist") SERVER = mutate(SERVER,
  "if (typeof rawMoneyPath !== \"string\" || !Object.prototype.hasOwnProperty.call(SEO_OWN_MONEY_PAGES, rawMoneyPath.trim())) {",
  "if (typeof rawMoneyPath !== \"string\" || rawMoneyPath.trim().charAt(0) !== \"/\") {", "allowlist");
if (MUTATE === "allowlist") SERVER = mutate(SERVER, "    if (!Object.prototype.hasOwnProperty.call(SEO_OWN_MONEY_PAGES, moneyPath)) {\n        throw",
  "    if (false) {\n        throw", "allowlist");
if (MUTATE === "silent") SERVER = mutate(SERVER,
  "      if (typeof rawMoneyPath !== \"string\" || !Object.prototype.hasOwnProperty.call(SEO_OWN_MONEY_PAGES, rawMoneyPath.trim())) {\n        return res.status(422).json({",
  "      if (typeof rawMoneyPath !== \"string\" || !Object.prototype.hasOwnProperty.call(SEO_OWN_MONEY_PAGES, rawMoneyPath.trim())) {\n        if (true) { moneyPath = null; } else return res.status(422).json({", "silent");
if (MUTATE === "silent") SERVER = mutate(SERVER, "      moneyPath = rawMoneyPath.trim();\n    }", "      else moneyPath = rawMoneyPath.trim();\n    }", "silent");
if (MUTATE === "both") SERVER = mutate(SERVER, "    if (moneyPath && externalMode) {", "    if (false) {", "both");
if (MUTATE === "listingrule") SERVER = mutate(SERVER,
  "        : (ownPageMode\n            ? \"- Link to the money page above EXACTLY ONCE, with href=",
  "        : (false\n            ? \"- Link to the money page above EXACTLY ONCE, with href=", "listingrule");
if (MUTATE === "gencheck") SERVER = mutate(SERVER, "      if (!bodyLinksToMoneyUrl(publishedBody, moneyPath)) {", "      if (false) {", "gencheck");
if (MUTATE === "pubcheck") SERVER = mutate(SERVER, "      if (!bodyLinksToMoneyUrl(body, moneyPath)) {", "      if (false) {", "pubcheck");
if (MUTATE === "noref") SERVER = mutate(SERVER, "      storedBody = withBlogArrivalTracking(body, moneyPath, arrivalToken);", "      storedBody = body;", "noref");
if (MUTATE === "personal") SERVER = mutate(SERVER,
  "return \"bl-\" + crypto.createHash(\"sha256\").update(\"blog:\" + String(userId || \"\") + \":\" + String(slug || \"\")).digest(\"hex\").slice(0, 10);",
  "return \"bl-\" + String(slug || \"\").slice(0, 10);", "personal");
if (MUTATE === "leak") SERVER = mutate(SERVER,
  "        : (ownPageMode\n            ? \"- Link to the money page above EXACTLY ONCE, with href=",
  "        : (ownPageMode || !existingListings.length\n            ? \"- Link to the money page above EXACTLY ONCE, with href=", "leak");
if (MUTATE === "lronly") SERVER = mutate(SERVER, "var ENGINE_VISIT_REF = /^(?:lr|bl)-[0-9a-f]{10}$/;", "var ENGINE_VISIT_REF = /^lr-[0-9a-f]{10}$/;", "lronly");
if (MUTATE === "blonly") SERVER = mutate(SERVER, "var ENGINE_VISIT_REF = /^(?:lr|bl)-[0-9a-f]{10}$/;", "var ENGINE_VISIT_REF = /^bl-[0-9a-f]{10}$/;", "blonly");
if (MUTATE === "migration") MIG130 = mutate(MIG130, "check (ref ~ '^(lr|bl)-[0-9a-f]{10}$')", "check (ref ~ '^lr-[0-9a-f]{10}$')", "migration");
if (MUTATE === "alltargets") SERVER = mutate(SERVER, "      if (ownPageMode) {\n        publishedQuery = publishedQuery.ilike(", "      if (false) {\n        publishedQuery = publishedQuery.ilike(", "alltargets");
if (MUTATE === "firstpost") SERVER = mutate(SERVER, "          : (ownPageMode && authorHandle\n", "          : (false\n", "firstpost");
if (MUTATE === "nofacts") SERVER = mutate(SERVER, "      complianceSection +\n      SEO_NO_INVENTED_FACTS +\n", "      complianceSection +\n", "nofacts");
if (MUTATE === "nodisclose") {
  /* Cut the disclosure sentences out of the own-page money section. */
  const from = " +\n          \"\\nThis blog and that page are BizForce AI's own";
  const to = "the article has answered the question on its own.\"";
  const a = SERVER.indexOf(from), b = SERVER.indexOf(to, a);
  if (a < 0 || b < 0 || SERVER.split(from).length !== 2) { console.error("MUTATION REFUSED (nodisclose): anchor not found exactly once."); process.exit(3); }
  SERVER = SERVER.slice(0, a) + SERVER.slice(b + to.length);
}
if (MUTATE === "discloseall") SERVER = mutate(SERVER, "        \"- url=\" + moneyUrl +\n",
  "        \"- url=\" + moneyUrl + \"\\nBe plain that you are connected to it: write \\\"we built\\\".\" +\n", "discloseall");
if (MUTATE === "anyauthor") SERVER = mutate(SERVER, "    if (ownPageMode && req.user.id !== SEO_OWN_PAGE_AUTHOR_ID) {", "    if (false) {", "anyauthor");
if (MUTATE === "anyauthor") SERVER = mutate(SERVER, "      if (proposal.user_id !== SEO_OWN_PAGE_AUTHOR_ID) {", "      if (false) {", "anyauthor");
if (MUTATE === "escape") {
  /* Cut the three sentences that are not the page's own copy. */
  const from = " \" +\n    \"BizForce AI is itself a platform";
  const to = "shut down or take away.\"";
  const a = SERVER.indexOf(from), b = SERVER.indexOf(to, a);
  if (a < 0 || b < 0 || SERVER.split(from).length !== 2) { console.error("MUTATION REFUSED (escape): anchor not found exactly once."); process.exit(3); }
  SERVER = SERVER.slice(0, a) + "\"" + SERVER.slice(b + to.length);
}
if (MUTATE === "emailsend") SERVER = mutate(SERVER,
  "under its terms, and the email \" +\n    \"goes out through the business's email service, which has its own rules and can suspend sending — a business that \" +\n" +
  "    \"keeps its own copy of its list can take it elsewhere, but cannot keep sending through a service that stopped it. \" +\n",
  "under its terms. \" +\n", "emailsend");
if (MUTATE === "hideprice") SERVER = mutate(SERVER, "\"and say in that mention that it is a paid platform and what it costs, as written above. Mention it once",
  "\"and do not hide that it is a paid platform. Mention it once", "hideprice");
if (MUTATE === "pathanchor") SERVER = mutate(SERVER,
  "            : \"\\nThe link's text is words a reader understands, naming BizForce AI or what the page is for — never the href itself.\")",
  "            : \"\")", "pathanchor");
if (MUTATE === "generaladvice") SERVER = mutate(SERVER,
  "  \"None of this asks for general advice. Write practical advice specific to the business described above, naming its category \" +\n  \"when the brief names one.\";",
  "  \"Practical, general advice needs none of these. Write that.\";", "generaladvice");
if (MUTATE === "statepolicy") SERVER = mutate(SERVER,
  " Never say what \" +\n  \"any policy says, allows, forbids or requires: tell the reader to read the current policy for their own product.\\n\" +",
  "\\n\" +", "statepolicy");
if (MUTATE === "internals") SERVER = mutate(SERVER,
  "  \"- Nothing about how a named company's review systems work inside — not \\\"largely automated\\\", not how fast or how consistently \" +\n" +
  "  \"they act — and nothing about why it acted. Describe what the reader can see (an account disabled, an appeal form) and what \" +\n" +
  "  \"they can do about it.\\n\" +\n", "", "internals");
if (MUTATE === "ratesback") SERVER = mutate(SERVER,
  "  \"- No statistics, percentages, rates or counts, and no claim about how often or how many: not \\\"at a much higher rate than average\\\", \" +\n" +
  "  \"\\\"most owners\\\", \\\"the majority\\\", \\\"often within days\\\".\\n\" +\n", "", "ratesback");
const PRODUCT_LINE = "      (complianceProfile ? SEO_CATEGORY_AS_PRODUCT_TYPE : \"\") +\n";
if (MUTATE === "productalways") SERVER = mutate(SERVER, PRODUCT_LINE, "      SEO_CATEGORY_AS_PRODUCT_TYPE +\n", "productalways");
if (MUTATE === "productnever") SERVER = mutate(SERVER, PRODUCT_LINE, "", "productnever");
if (MUTATE === "productfirst") SERVER = mutate(SERVER, "      complianceSection +\n      SEO_NO_INVENTED_FACTS +\n" + PRODUCT_LINE,
  PRODUCT_LINE + "      complianceSection +\n      SEO_NO_INVENTED_FACTS +\n", "productfirst");
if (MUTATE === "conditionok") SERVER = mutate(SERVER,
  " never by a condition it addresses, not even paraphrased, \" +\n  \"hinted at or softened.", "", "conditionok");
/* A class that never matches: its pattern moves to an unused key. */
function silenceClass(name) {
  const at = SERVER.indexOf("  { name: \"" + name + "\", says: ");
  const re = at < 0 ? -1 : SERVER.indexOf("\n    re: ", at);
  if (at < 0 || re < 0 || SERVER.split("  { name: \"" + name + "\", says: ").length !== 2) { console.error("MUTATION REFUSED (" + MUTATE + "): class not found exactly once."); process.exit(3); }
  SERVER = SERVER.slice(0, re) + " re: /(?!)/,\n    re0: " + SERVER.slice(re + "\n    re: ".length);
}
if (MUTATE === "noquantity") silenceClass("quantity");
if (MUTATE === "notypicality") silenceClass("typicality");
if (MUTATE === "nofigure") silenceClass("figure");
if (MUTATE === "noreach") silenceClass("beyond_reach");
if (MUTATE === "nocompany") silenceClass("named_company_policy");
if (MUTATE === "genscreen") SERVER = mutate(SERVER, "      if (articleClaims.length) {\n        return { stage: \"claims\"", "      if (false) {\n        return { stage: \"claims\"", "genscreen");
if (MUTATE === "pubscreen") SERVER = mutate(SERVER, "    if (articleClaims.length) {\n      throw new Error(", "    if (false) {\n      throw new Error(", "pubscreen");
if (MUTATE === "innocent") {
  SERVER = mutate(SERVER, "new RegExp(\"(?<!\\\\b(?:the|your|my|our|their|its|his|her|a|at|how|as|too|what|which|so)\\\\s)\\\\b(?:most|", "new RegExp(\"\\\\b(?:most|", "innocent");
}
if (MUTATE === "faqheading") SERVER = mutate(SERVER, "frequently(?!\\s+asked\\b)", "frequently", "faqheading");
const AROUND_LINE = "      (ownPageMode && siteContext && SEO_HEALTH_ADJACENT_CONTEXT.test(siteContext) ? SEO_AROUND_THE_PRODUCT : \"\") +\n";
if (MUTATE === "problemnever") SERVER = mutate(SERVER, AROUND_LINE, "", "problemnever");
if (MUTATE === "problemalways") SERVER = mutate(SERVER, AROUND_LINE, "      (ownPageMode ? SEO_AROUND_THE_PRODUCT : \"\") +\n", "problemalways");
if (MUTATE === "problemanymode") SERVER = mutate(SERVER, AROUND_LINE,
  "      (siteContext && SEO_HEALTH_ADJACENT_CONTEXT.test(siteContext) ? SEO_AROUND_THE_PRODUCT : \"\") +\n", "problemanymode");
if (MUTATE === "problemwording") SERVER = mutate(SERVER,
  " — \" +\n  \"never around a condition, a symptom or a problem it might be bought for.", ".", "problemwording");
if (MUTATE === "noquestion") SERVER = mutate(SERVER, "    except: ARTICLE_CLAIM_QUESTION }", "    except: null }", "noquestion");
if (MUTATE === "nodecline") SERVER = mutate(SERVER, "    except: ARTICLE_CLAIM_DECLINES }", "    except: null }", "nodecline");
const REPAIR_IF = "    if (refusal && refusal.stage === \"claims\") {\n      claimRepair = await repairSeoArticleClaims(";
if (MUTATE === "norepair") SERVER = mutate(SERVER, REPAIR_IF, "    if (false) {\n      claimRepair = await repairSeoArticleClaims(", "norepair");
if (MUTATE === "repairloops") SERVER = mutate(SERVER, REPAIR_IF, "    while (refusal && refusal.stage === \"claims\") {\n      claimRepair = await repairSeoArticleClaims(", "repairloops");
if (MUTATE === "repairunscreened") SERVER = mutate(SERVER, "        const after = seoDraftRefusal(claimRepair.draft);", "        const after = null;", "repairunscreened");
if (MUTATE === "norecord") SERVER = mutate(SERVER, "    const { error } = await supabase.from(\"seo_refused_drafts\").insert(row);", "    const error = null;", "norecord");
if (MUTATE === "nosystems") SERVER = mutate(SERVER, "|men|women|\" +\n  \"networks|platforms|processors|providers|services|sites|websites|marketplaces|engines)\";",
  "|men|women)\";", "nosystems");
if (MUTATE === "nothosted") SERVER = mutate(SERVER, "          SEO_OWN_PAGE_HOSTED +\n", "", "nothosted");
if (MUTATE === "hostedanymode") SERVER = mutate(SERVER, "        \"- url=\" + moneyUrl +\n", "        \"- url=\" + moneyUrl + SEO_OWN_PAGE_HOSTED +\n", "hostedanymode");
if (MUTATE === "hostedwording") SERVER = mutate(SERVER, "under its terms — a channel \" +\n  \"beside the business's others, not one it owns outright.", "under its terms.", "hostedwording");
if (MUTATE) console.log("\n!! MUTATION: " + MUTATE);

/* _shared caches definitions by whether the source is the working copy, so a
   mutated copy and BASELINE would share a cache slot. A fresh module per lift
   keeps them apart. The compliance profiles are lifted for real rather than
   stubbed: the external fixtures run the actual compliance rules. */
const SHARED = require.resolve("./_shared");
function shared() {
  delete require.cache[SHARED];
  const s = require(SHARED);
  s.STUBS.delete("COMPLIANCE_PROFILES");
  s.STUBS.delete("COMPLIANCE_DISCLAIMER");
  return s;
}
/* _shared.closureFor joins definitions in the order it discovered them, and a
   const read during another's initialiser must already exist. Ordering them as
   server.js does reproduces the order the module itself evaluates them in. */
/* Built once per (source, root): the walk over a 40,000-line file is the slow
   part, and every run of the same source lifts the same text. */
const CLOSURES = new Map();
function closure(s, src, root) {
  if (!CLOSURES.has(src)) CLOSURES.set(src, new Map());
  const bySrc = CLOSURES.get(src);
  if (!bySrc.has(root)) bySrc.set(root, closureUncached(s, src, root));
  return bySrc.get(root);
}
function closureUncached(s, src, root) {
  const have = new Map(); const queue = [...new Set(root.match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || s.STUBS.has(name)) continue;
    const def = s.definitionOf(src, name);
    if (!def) continue;
    try { new vm.Script(def); } catch (e) { continue; }
    have.set(name, def);
    new Set(def.match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !s.STUBS.has(id)) queue.push(id); });
  }
  return [...have.values()].sort((a, b) => src.indexOf(a) - src.indexOf(b)).join("\n\n") + "\n\n" + root;
}

/* The no-invented-facts block as server.js holds it. Every mode's prompt now
   carries it, so "nothing else changed" is: take it out, and what is left is
   byte-identical to BASELINE's prompt. */
function liftValue(src, name) {
  const c = {};
  vm.runInNewContext(shared().definitionOf(src, name) + "\nthis.v = " + name + ";", c);
  return c.v;
}
const FACTS = liftValue(SERVER, "SEO_NO_INVENTED_FACTS");
/* The product-type line rides directly after the block whenever a compliance
   profile is active, and BASELINE had neither, so both come out together.
   Section 14 holds the line to its own terms. */
const PRODUCT_TYPE = liftValue(SERVER, "SEO_CATEGORY_AS_PRODUCT_TYPE");
function unFacts(p) { return p == null ? p : p.split(PRODUCT_TYPE).join("").split(FACTS).join(""); }
/* The commit before the product-type line existed, for section 14's "nothing
   else changed". Pinned, not HEAD. */
const PREV = "d5b077c";
const SERVER_PREV = execSync("git show " + PREV + ":server.js", { cwd: REPO, maxBuffer: 1 << 26 }).toString("utf8").replace(/\r\n/g, "\n");
/* Section 16's line, and the commit before it, for its "nothing else changed". */
const AROUND = liftValue(SERVER, "SEO_AROUND_THE_PRODUCT");
const PREV16 = "60c9bc1";
const SERVER_PREV16 = execSync("git show " + PREV16 + ":server.js", { cwd: REPO, maxBuffer: 1 << 26 }).toString("utf8").replace(/\r\n/g, "\n");
/* Section 17's screen before the narrowings. Pinned, not HEAD. */
const PREV17 = "b86aa99";
const SERVER_PREV17 = execSync("git show " + PREV17 + ":server.js", { cwd: REPO, maxBuffer: 1 << 26 }).toString("utf8").replace(/\r\n/g, "\n");
/* Section 21's clause, and the commit before it, for its "nothing else changed".
   Own-page prompts carry it, so sections 14 and 16 take it out before they
   compare an own-page prompt with their older commits; no other mode's prompt
   has it to take out. */
const HOSTED = liftValue(SERVER, "SEO_OWN_PAGE_HOSTED");
function unHosted(p) { return p == null ? p : p.split(HOSTED).join(""); }
const PREV21 = "44535d4";
const SERVER_PREV21 = execSync("git show " + PREV21 + ":server.js", { cwd: REPO, maxBuffer: 1 << 26 }).toString("utf8").replace(/\r\n/g, "\n");

/* ── a database that records what it is asked to write ── */
const HANDLE = "check-handle";
const LISTINGS = [{ id: "11111111-2222-3333-4444-555555555555", title: "Wool Hat", slug: "wool-hat", category: "apparel", description: "A hand-knitted wool hat." }];
/* Two published posts: one about something else, one that already links the
   own page the way the executor stores it. */
const POSTS = [
  { id: "post-older", title: "An older post", slug: "older-post", keyword: "older question", external_url: null, body: '<p>About wool. <a href="/listing/wool-hat">a hat</a></p>' },
  { id: "post-bf", title: "Where customers come from without ads", slug: "customers-without-ads", keyword: "customers without ads", external_url: null,
    body: '<p>Owned channels. <a href="/suppressed.html?ref=bl-0123456789">BizForce AI</a></p>' }
];
/* LIKE, as Postgres reads it: % any run, _ any one character, case ignored. */
function likeToRegExp(pattern) {
  return new RegExp("^" + pattern.split("").map(c => c === "%" ? "[\\s\\S]*" : c === "_" ? "[\\s\\S]" : c.replace(/[.*+?^${}()|[\]\\\/]/g, "\\$&")).join("") + "$", "i");
}
/* Refused drafts (section 19) are recorded apart from every other write, so
   "nothing filed" everywhere above still means exactly what it meant before
   refusals were stored, and section 6 still compares filed rows with BASELINE. */
const REFUSED_TABLE = "seo_refused_drafts";
function fakeDb(opts) {
  const writes = [], drafts = [];
  const listings = opts && opts.noListings ? [] : LISTINGS;
  const posts = opts && opts.posts ? opts.posts : POSTS;
  function q(table) {
    const st = { table: table, insert: null, likes: [] };
    const b = {};
    ["select", "eq", "neq", "gte", "lte", "gt", "in", "is", "not", "order", "limit"].forEach(k => { b[k] = () => b; });
    b.ilike = (col, pattern) => { st.likes.push([col, likeToRegExp(pattern)]); return b; };
    b.insert = (p) => {
      if (table === REFUSED_TABLE) {
        drafts.push(JSON.parse(JSON.stringify(p)));
        return Promise.resolve({ data: null, error: opts && opts.draftInsertError ? opts.draftInsertError : null });
      }
      st.insert = p; writes.push({ table: table, payload: JSON.parse(JSON.stringify(p)) }); return b;
    };
    b.maybeSingle = () => Promise.resolve({ data: table === "bf_profiles" ? { username: HANDLE } : null, error: null });
    b.single = () => Promise.resolve(st.insert ? { data: Object.assign({ id: "row-1" }, st.insert), error: null } : { data: null, error: null });
    b.then = (res, rej) => Promise.resolve({
      data: table === "marketplace_listings" ? listings
        : (table === "content_library" ? posts.filter(p => st.likes.every(([col, re]) => re.test(String(p[col] || "")))) : []), error: null
    }).then(res, rej);
    return b;
  }
  return { client: { from: q }, writes: writes, drafts: drafts };
}

/* The scripted model. modelText answers the first call; a repair (the second
   call) gets opts.repair when given — a string, an Error to throw, or a
   function of the prompt — and modelText again otherwise. A fourth call for
   one article is a repair that loops: this says so as a section-18 failure
   and stops the run, because a looping route would never return. */
function baseCtx(db, modelText, opts) {
  const prompts = [], routes = [];
  const ctx = {
    supabase: db.client, nowIso: () => "2026-10-05T12:00:00.000Z", process: { env: {} }, require: require, Buffer: Buffer, URL: URL,
    console: { log() {}, warn() {}, error() {} },
    requireAuth: 0, requireActiveSubscription: 0, aiLimiter: 0,
    resolvePreferredLanguage: async () => null,
    buildLanguageInstruction: () => "",
    AGENT_SYSTEM_PROMPTS: { seo: "SEO SYSTEM" },
    /* server.js destructures it from lib/ownerAccount.js, which the lifter
       cannot follow; this is the same module's value. */
    OWNER_ACCOUNT_ID: AUTHOR,
    callAnthropicText: async (prompt, maxTokens, userId, model, ledger) => {
      prompts.push(prompt); routes.push(ledger && ledger.route);
      if (prompts.length > 3) {
        console.log("    FAIL  18. one article made " + prompts.length + " model calls — the repair loops");
        console.log("\nCHECKS FAILED: the run was stopped");
        process.exit(1);
      }
      const answer = prompts.length > 1 && opts && opts.repair !== undefined ? opts.repair : modelText;
      if (answer instanceof Error) throw answer;
      return { text: typeof answer === "function" ? answer(prompt) : answer, stopReason: "end_turn" };
    }
  };
  return { ctx: ctx, prompts: prompts, routes: routes };
}

/* The gates a draft meets, counted per call, so section 18 can show the
   repaired article met them again. Function declarations in the lifted script
   are properties of its global, and the route reaches them through it. */
const COUNTED = ["bodyLinksToMoneyUrl", "findComplianceViolations", "complianceRequiredTextPresent", "findArticleClaims"];
function liftRoute(src, db, modelText, opts) {
  const s = shared();
  const b = baseCtx(db, modelText, opts);
  let handler = null;
  b.ctx.app = { post() { handler = arguments[arguments.length - 1]; } };
  vm.createContext(b.ctx);
  vm.runInContext(closure(s, src, s.routeCode(src, "seo/generate-post")), b.ctx);
  if (!handler) throw new Error("EXTRACTION FAILED: generate-post");
  const counts = {};
  COUNTED.forEach(n => {
    const f = b.ctx[n];
    counts[n] = 0;
    if (typeof f === "function") b.ctx[n] = function () { counts[n]++; return f.apply(this, arguments); };
  });
  return { handler: handler, prompts: b.prompts, routes: b.routes, counts: counts };
}
async function generate(src, body, modelText, opts) {
  const db = fakeDb(opts);
  const r = liftRoute(src, db, modelText, opts);
  const res = { statusCode: 200, body: undefined, status(c) { this.statusCode = c; return this; }, json(p) { this.body = JSON.parse(JSON.stringify(p)); return this; } };
  let nextErr = null;
  await r.handler({ user: { id: (opts && opts.userId) || AUTHOR }, body: body }, res, (e) => { nextErr = e || new Error("next"); });
  /* A filed proposal carries brief since migration 132, and every commit this
     file compares against predates it. checkProposalBrief holds brief to its
     own terms and the rest of the row to the commit before it, so it is taken
     out here and every comparison below still sees the whole of the rest. */
  db.writes.forEach(w => { if (w.table === "agent_proposals" && w.payload) delete w.payload.brief; });
  if (res.body && res.body.proposal) delete res.body.proposal.brief;
  return { status: res.statusCode, body: res.body, prompt: r.prompts[0] || null, prompts: r.prompts, routes: r.routes, counts: r.counts,
    calls: r.prompts.length, writes: db.writes, drafts: db.drafts, nextErr: nextErr && String(nextErr.message || nextErr) };
}

function liftPublish(src, db) {
  const s = shared();
  const sig = "  publish_blog_post: async function (proposal) {";
  const at = src.indexOf(sig);
  if (at < 0) throw new Error("EXTRACTION FAILED: publish_blog_post");
  const open = src.indexOf("{", at + sig.length - 1);
  const fn = "var __publish = async function (proposal) " + src.slice(open, s.braceMatch(src, open)) + ";";
  const b = baseCtx(db, "");
  vm.createContext(b.ctx);
  vm.runInContext(closure(s, src, fn), b.ctx);
  return b.ctx.__publish;
}
async function publish(src, payload, opts) {
  const db = fakeDb(opts);
  const fn = liftPublish(src, db);
  let result = null, thrown = null;
  try { result = await fn({ id: "proposal-1", user_id: (opts && opts.userId) || AUTHOR, payload: JSON.parse(JSON.stringify(payload)) }); }
  catch (e) { thrown = String((e && e.message) || e); }
  return { result: result, thrown: thrown, writes: db.writes };
}

/* ── the model's answer, in the delimited format the route parses ── */
function article(links, extra) {
  const pad = "<p>" + "Owned channels keep working when a platform withdraws its approval, because nothing about them depends on that approval. ".repeat(4) + "</p>";
  const body = "<h2>Where customers come from when ads are closed</h2>" + pad + "<p>" + links.map(h => '<a href="' + h + '">this page</a>').join(" and ") + "</p>" + pad +
    "<h2>Frequently asked questions</h2><h3>Can I still be found?</h3><p>Yes, through search.</p><h3>Does it take long?</h3><p>It builds over months.</p><h3>Do I need ads?</h3><p>No.</p>" + (extra || "");
  return "---TITLE---\nWhat to do when your ad account is disabled\n---SLUG---\nwhat-to-do-when-your-ad-account-is-disabled\n---META_DESCRIPTION---\nA plain answer.\n" +
    "---KEYWORD---\nwhat to do when your ad account is disabled\n---INTERNAL_LINKS---\n" + links.join(", ") + "\n---REASONING---\nA question people ask.\n---BODY---\n" + body;
}
const OWN = "/suppressed.html";
const SLUG = "what-to-do-when-your-ad-account-is-disabled";
function expectedBl(userId, slug) { return "bl-" + crypto.createHash("sha256").update("blog:" + userId + ":" + slug).digest("hex").slice(0, 10); }

/* ── the visits route, lifted with a database that records its inserts ── */
function visitsRoute(src, insertError) {
  const s = shared();
  const start = src.indexOf("app.post(\"/api/engine-visits\", async function (req, res) {");
  if (start < 0) throw new Error("EXTRACTION FAILED: the engine-visits route");
  const open = src.indexOf("{", start);
  const body = src.slice(src.indexOf("async function", start), s.braceMatch(src, open));
  const inserts = [];
  const db = { from(t) { return { insert(p) { inserts.push({ table: t, payload: p }); return Promise.resolve({ error: insertError || null }); } }; } };
  const ctx = { supabase: db, console: { log() {}, warn() {}, error() {} } };
  vm.runInNewContext(["ENGINE_VISIT_REF", "ENGINE_VISIT_PATH"].map(n => s.definitionOf(src, n)).join("\n") + "\nthis.handler = " + body + ";", ctx);
  return { handler: ctx.handler, inserts: inserts };
}
async function visit(h, body) {
  let status = 200, payload;
  const res = { status(c) { status = c; return res; }, json(p) { payload = p; return res; }, end() { return res; } };
  await h.handler({ body: body, ip: "203.0.113.7", headers: { "user-agent": "FixtureBrowser/1.0" } }, res);
  return { status: status, payload: payload };
}

(async function main() {
  await residue.sweepPrevious(SUBJECT_USER_ID);

  console.log("\n══ 1. money_path off the allowlist is refused ══");
  const offList = ["/pricing", "/Suppressed.html", "/suppressed.html/", "https://bizforceai.net/suppressed.html", "suppressed.html", "/suppressed.html?ref=x", 42, ["/suppressed.html"]];
  const off = [];
  for (const p of offList) {
    const r = await generate(SERVER, { money_path: p, topic: "ad account disabled" }, article([OWN]));
    off.push(r.status === 422 && r.calls === 0 && r.writes.length === 0 && /Allowed: \/suppressed\.html/.test((r.body || {}).error || "") ? "422" : r.status + "/" + r.calls + "/" + r.writes.length);
  }
  console.log("    " + JSON.stringify(offList) + " → " + JSON.stringify(off));
  check("1. every off-allowlist money_path is 422 naming the allowlist, with no model call and nothing filed", off.every(x => x === "422"), JSON.stringify(off));
  const firstErr = (await generate(SERVER, { money_path: "/pricing" }, article([OWN]))).body;
  console.log("    e.g. " + JSON.stringify(firstErr));
  const absent = [];
  for (const v of [undefined, null, ""]) {
    const body = { topic: "wool care" }; if (v !== undefined) body.money_path = v;
    const a = await generate(SERVER, body, article(["/listing/wool-hat"])), b0 = await generate(SERVER0, { topic: "wool care" }, article(["/listing/wool-hat"]));
    absent.push(a.status === b0.status && unFacts(a.prompt) === b0.prompt && JSON.stringify(a.writes) === JSON.stringify(b0.writes));
  }
  check("1. absent, null and \"\" are no money_path: status and rows identical to " + BASELINE + " with no money_path, and the prompt too once the no-invented-facts block is taken out", absent.every(Boolean), JSON.stringify(absent));

  console.log("\n══ 2. money_path and money_url together ══");
  const both = await generate(SERVER, { money_path: OWN, money_url: "https://example.com/product" }, article([OWN, "https://example.com/product"]));
  console.log("    " + both.status + " " + JSON.stringify(both.body));
  check("2. refused with 422 naming both, no model call, nothing filed",
    both.status === 422 && both.calls === 0 && both.writes.length === 0 && /money_url or money_path, not both/.test((both.body || {}).error || ""), both.status + "/" + both.calls);

  console.log("\n══ 3. generation with money_path ══");
  const g = await generate(SERVER, { money_path: OWN, topic: "what to do when your ad account is disabled" }, article([OWN, "/blog/" + HANDLE + "/customers-without-ads"]));
  const pr = g.prompt || "";
  check("3. the prompt names " + OWN + " as the money page, with what the page is and what it will not do",
    pr.indexOf("- href=" + OWN) !== -1 && /what the page is: BizForce AI's page/.test(pr) && /does not promise traffic, rankings or sales/.test(pr));
  check("3. no listing catalog and no listing rule in it",
    pr.indexOf("marketplace listings (the money pages)") === -1 && pr.indexOf("/listing/wool-hat") === -1 && pr.indexOf("EXACTLY ONE of the seller's listings") === -1 &&
    pr.indexOf("with href=\"" + OWN + "\" copied character for character") !== -1, pr.length);
  check("3. the author's published posts that link the same page are offered as internal links (section 9 has the rest)",
    pr.indexOf("href=/blog/" + HANDLE + "/customers-without-ads") !== -1);
  const prop = (g.writes[0] || {}).payload || {};
  console.log("    " + g.status + "; filed payload keys " + JSON.stringify(Object.keys(prop.payload || {})));
  check("3. a post linking the page is filed with money_path and no money_url or site",
    g.status === 201 && g.writes.length === 1 && g.writes[0].table === "agent_proposals" && prop.payload.money_path === OWN &&
    !("money_url" in prop.payload) && !("site" in prop.payload) && prop.action_type === "publish_blog_post", g.status + " " + JSON.stringify(g.body).slice(0, 200));
  const noLink = await generate(SERVER, { money_path: OWN }, article(["/blog/" + HANDLE + "/older-post"]));
  const listingOnly = await generate(SERVER, { money_path: OWN }, article(["/listing/wool-hat"]));
  const absLink = await generate(SERVER, { money_path: OWN }, article(["https://bizforceai.net/suppressed.html"]));
  console.log("    no link " + noLink.status + ", listing only " + listingOnly.status + ", absolute URL " + absLink.status + ": " + JSON.stringify((noLink.body || {}).error));
  check("3. a post without the link, with only a listing link, or with the page as an absolute URL is 422 and nothing is filed",
    [noLink, listingOnly, absLink].every(r => r.status === 422 && r.writes.length === 0 && /money page \/suppressed\.html/.test((r.body || {}).error || "")),
    [noLink, listingOnly, absLink].map(r => r.status + "/" + r.writes.length).join(","));

  console.log("\n══ 4. publish with money_path ══");
  const token = expectedBl(AUTHOR, SLUG);
  const tracked = OWN + "?ref=" + token;
  const p = await publish(SERVER, prop.payload || {});
  const row = (p.writes[0] || {}).payload || {};
  console.log("    returned " + JSON.stringify(p.result || p.thrown));
  console.log("    stored money href(s): " + JSON.stringify((String(row.body || "").match(/href="[^"]*suppressed[^"]*"/g) || [])) + "; internal_links " + JSON.stringify(row.internal_links));
  check("4. published here: one content_library row, status published, site null, published_at set, publicly visible",
    !p.thrown && p.writes.length === 1 && p.writes[0].table === "content_library" && row.status === "published" && row.site === null && !!row.published_at &&
    p.result.publicly_visible === true && p.result.external_post === false, p.thrown || JSON.stringify(p.result));
  check("4. the body's money link is " + tracked + " and no bare " + OWN + " link is left",
    String(row.body || "").indexOf('href="' + tracked + '"') !== -1 && String(row.body || "").indexOf('href="' + OWN + '"') === -1, String(row.body || "").slice(0, 80));
  check("4. internal_links carries the tracked link and the other links unchanged",
    Array.isArray(row.internal_links) && row.internal_links.indexOf(tracked) !== -1 && row.internal_links.indexOf("/blog/" + HANDLE + "/customers-without-ads") !== -1 && row.internal_links.indexOf(OWN) === -1,
    JSON.stringify(row.internal_links));
  const variant = await publish(SERVER, Object.assign({}, prop.payload, { body: String(prop.payload.body).replace('href="' + OWN + '"', 'href="/Suppressed.html/"') }));
  check("4. a case or trailing-slash variant the check tolerates is stored as the canonical tracked path",
    !variant.thrown && String(((variant.writes[0] || {}).payload || {}).body || "").indexOf('href="' + tracked + '"') !== -1, variant.thrown);
  const pubNoLink = await publish(SERVER, Object.assign({}, prop.payload, { body: String(prop.payload.body).split('href="' + OWN + '"').join('href="/blog/' + HANDLE + '/older-post"') }));
  const pubOff = await publish(SERVER, Object.assign({}, prop.payload, { money_path: "/pricing" }));
  const pubBoth = await publish(SERVER, Object.assign({}, prop.payload, { money_url: "https://example.com/product" }));
  console.log("    no link: " + pubNoLink.thrown + "\n    off-list: " + pubOff.thrown + "\n    both: " + pubBoth.thrown);
  check("4. a body without the link, an off-allowlist money_path and both keys each throw and write nothing",
    /money page \/suppressed\.html/.test(pubNoLink.thrown || "") && /not a page a post may name/.test(pubOff.thrown || "") && /both money_url and money_path/.test(pubBoth.thrown || "") &&
    pubNoLink.writes.length + pubOff.writes.length + pubBoth.writes.length === 0,
    [pubNoLink, pubOff, pubBoth].map(r => (r.thrown ? "threw" : "wrote") + "/" + r.writes.length).join(","));

  console.log("\n══ 5. the token ══");
  const s5 = shared();
  const tctx = { crypto: crypto }; vm.createContext(tctx);
  vm.runInContext(s5.definitionOf(SERVER, "blogRefToken") + "\nthis.f = blogRefToken;", tctx);
  const t1 = tctx.f(AUTHOR, SLUG);
  console.log("    token for the fixture post: " + t1);
  check("5. bl- and ten hex of SHA-256 over \"blog:<user_id>:<slug>\", the token the published link carries", t1 === token && /^bl-[0-9a-f]{10}$/.test(t1), t1);
  check("5. the same post the same token; another slug, another author, another token",
    tctx.f(AUTHOR, SLUG) === t1 && tctx.f(AUTHOR, SLUG + "-2") !== t1 && tctx.f("00000000-0000-0000-0000-000000000000", SLUG) !== t1);
  check("5. no slug or account text in it", ["what", "ad-a", "disabled", AUTHOR.slice(0, 8)].every(x => t1.indexOf(x) === -1), t1);

  console.log("\n══ 6. without money_path, nothing changed against " + BASELINE + " but the no-invented-facts block ══");
  const CASES = [
    ["internal, with listings, no topic", { }, article(["/listing/wool-hat", "/blog/" + HANDLE + "/older-post"]), null],
    ["internal, with listings, topic", { topic: "how to wash a wool hat" }, article(["/listing/wool-hat"]), null],
    ["internal, no listings", { topic: "wool care" }, article(["/blog/" + HANDLE + "/older-post"]), { noListings: true }],
    ["internal, the model links nothing", { }, article([]), null],
    ["external, example.com", { money_url: "https://example.com/product", money_anchor: "the product", site_name: "Example", site_context: "A shop." }, article(["https://example.com/product"]), null],
    ["external, auto compliance (swordvitality.com)", { money_url: "https://swordvitality.com/store/x.html" }, article(["https://swordvitality.com/store/x.html"]), null],
    ["external, money link missing", { money_url: "https://example.com/product" }, article(["/listing/wool-hat"]), null],
    ["external, bad money_url", { money_url: "example.com" }, article([]), null]
  ];
  for (const [label, body, text, opts] of CASES) {
    const a = await generate(SERVER, body, text, opts), b0 = await generate(SERVER0, body, text, opts);
    check("6. generate · " + label + " — status, response and rows identical, and the prompt once the no-invented-facts block is out (" + a.status + ")",
      unFacts(a.prompt) === b0.prompt && a.status === b0.status && JSON.stringify(a.body) === JSON.stringify(b0.body) && JSON.stringify(a.writes) === JSON.stringify(b0.writes) && a.nextErr === b0.nextErr,
      a.status + " vs " + b0.status + (a.prompt !== b0.prompt ? " (prompt differs)" : ""));
  }
  const internalProp = (await generate(SERVER0, {}, article(["/listing/wool-hat", "/blog/" + HANDLE + "/older-post"]))).writes[0].payload.payload;
  const externalProp = (await generate(SERVER0, { money_url: "https://example.com/product" }, article(["https://example.com/product"]))).writes[0].payload.payload;
  const PUB = [
    ["internal", internalProp, null], ["internal, no listings", internalProp, { noListings: true }], ["external", externalProp, null],
    ["internal, short body", Object.assign({}, internalProp, { body: "<p>short</p>" }), null],
    ["external, money link gone", Object.assign({}, externalProp, { body: String(externalProp.body).split("https://example.com/product").join("/listing/wool-hat") }), null],
    ["internal, bad slug", Object.assign({}, internalProp, { slug: "Bad Slug" }), null]
  ];
  for (const [label, payload, opts] of PUB) {
    const a = await publish(SERVER, payload, opts), b0 = await publish(SERVER0, payload, opts);
    check("6. publish · " + label + " — row written and result identical (" + (a.thrown ? "throws" : a.result.status) + ")",
      JSON.stringify(a.writes) === JSON.stringify(b0.writes) && JSON.stringify(a.result) === JSON.stringify(b0.result) && a.thrown === b0.thrown,
      (a.thrown || "") + " | " + (b0.thrown || ""));
  }

  console.log("\n══ 7. POST /api/engine-visits ══");
  const LR = "lr-" + crypto.createHash("sha256").update("leadradar:at://did:plc:fixture/app.bsky.feed.post/3k").digest("hex").slice(0, 10);
  const lrRoute = visitsRoute(SERVER), blRoute = visitsRoute(SERVER);
  const rl = await visit(lrRoute, { ref: LR, path: "/" }), rb = await visit(blRoute, { ref: token, path: OWN, slug: SLUG, user: AUTHOR });
  console.log("    lr " + rl.status + " " + JSON.stringify(lrRoute.inserts) + "\n    bl " + rb.status + " " + JSON.stringify(blRoute.inserts));
  check("7. an lr- arrival is still 204 and writes exactly { ref, landing_path }",
    rl.status === 204 && lrRoute.inserts.length === 1 && JSON.stringify(lrRoute.inserts[0].payload) === JSON.stringify({ ref: LR, landing_path: "/" }));
  check("7. a bl- arrival at " + OWN + " is 204 and writes exactly { ref, landing_path }, whatever else the body carries",
    rb.status === 204 && blRoute.inserts.length === 1 && JSON.stringify(blRoute.inserts[0].payload) === JSON.stringify({ ref: token, landing_path: OWN }));
  const BAD = ["BL-0123456789", "bl-012345678", "bl-0123456789a", "bx-0123456789", "bl-012345678g", "lr-", "bl_0123456789", ""];
  const badRoute = visitsRoute(SERVER), refused = [];
  for (const r of BAD) refused.push((await visit(badRoute, { ref: r, path: OWN })).status);
  check("7. a malformed ref is 400 and writes nothing", refused.every(x => x === 400) && badRoute.inserts.length === 0, JSON.stringify(refused));
  const behind = await visit(visitsRoute(SERVER, { code: "23514", message: "violates check constraint \"engine_visits_ref_check\"" }), { ref: token, path: OWN });
  const missing = await visit(visitsRoute(SERVER, { code: "PGRST205", message: "no table" }), { ref: LR, path: "/" });
  console.log("    constraint behind: " + behind.status + " " + JSON.stringify(behind.payload) + "\n    table missing: " + missing.status + " " + JSON.stringify(missing.payload));
  check("7. a constraint refusal is 503 naming migration 130; a missing table is still 503 naming 128",
    behind.status === 503 && /migration 130/.test((behind.payload || {}).error || "") && missing.status === 503 && /migration 128/.test((missing.payload || {}).error || ""));

  console.log("\n══ 8. migration 130 ══");
  const conRe = new RegExp((/add constraint engine_visits_ref_check check \(ref ~ '([^']+)'\)/.exec(MIG130) || [])[1] || "^$");
  const routeRe = (function () { const c = {}; vm.runInNewContext(shared().definitionOf(SERVER, "ENGINE_VISIT_REF") + "\nthis.v = ENGINE_VISIT_REF;", c); return c.v; })();
  console.log("    route " + routeRe + "   table " + conRe);
  const SAMPLES = [LR, token, t1, tctx.f("a", "b"), "lr-0000000000", "bl-ffffffffff"].concat(BAD);
  const agree = SAMPLES.map(x => routeRe.test(x) === conRe.test(x));
  check("8. the constraint accepts exactly what the route accepts, over every token above and the malformed set",
    agree.every(Boolean) && conRe.test(LR) && conRe.test(token) && !conRe.test("BL-0123456789"), JSON.stringify(SAMPLES.filter((x, i) => !agree[i])));
  check("8. 128's check is found by what it checks and dropped; nothing else about the table changes",
    /pg_get_constraintdef\(oid\) like '%\(ref ~%'/.test(MIG130) && /drop constraint %I/.test(MIG130) &&
    !/add column|drop column|alter column|landing_path ~|disable row level security|grant /i.test(MIG130.replace(/^--.*$/gm, "")));
  const live = await supabase.from("engine_visits").select("id").limit(1);
  console.log("    live database: engine_visits " + (live.error ? "does not exist (" + (live.error.code || live.error.message) + ")" : "exists") +
    "; whether 130 is applied cannot be read without a write, and this check does not write");

  console.log("\n══ 9. an own-page post links only posts that link the same page ══");
  const BF_HREF = "/blog/" + HANDLE + "/customers-without-ads", OTHER_HREF = "/blog/" + HANDLE + "/older-post";
  const t9 = await generate(SERVER, { money_path: OWN, topic: "customers after an ad ban" }, article([OWN, BF_HREF]));
  console.log("    offered: " + JSON.stringify(((t9.prompt || "").match(/href=\/blog\/[^ ]+/g) || [])));
  check("9. the post that links " + OWN + " is offered, the unrelated one is not, under a heading that says why",
    (t9.prompt || "").indexOf("href=" + BF_HREF) !== -1 && (t9.prompt || "").indexOf(OTHER_HREF) === -1 &&
    (t9.prompt || "").indexOf("posts that also link the money page above (the only posts available as internal links)") !== -1 && t9.status === 201, t9.status);
  const first = await generate(SERVER, { money_path: OWN }, article([OWN]), { posts: [POSTS[0]] });
  const none = await generate(SERVER, { money_path: OWN }, article([OWN]), { posts: [] });
  console.log("    first own-page post, beside an unrelated one: " + first.status + "; with no posts at all: " + none.status);
  check("9. the FIRST own-page post — beside unrelated posts or none at all — is offered nothing, told so, told to link no post, and is filed",
    [first, none].every(r => r.status === 201 && r.writes.length === 1 && (r.prompt || "").indexOf(OTHER_HREF) === -1 &&
      (r.prompt || "").indexOf("(none yet — this is the first post that links this page)") !== -1 &&
      (r.prompt || "").indexOf("- Do not link to any other blog post — none are available as link targets.") !== -1),
    [first, none].map(r => r.status).join(","));
  const listing9 = await generate(SERVER, { topic: "wool care" }, article(["/listing/wool-hat"]));
  check("9. a listing-mode post is still offered every published post the author owns",
    (listing9.prompt || "").indexOf("href=" + OTHER_HREF) !== -1 && (listing9.prompt || "").indexOf("href=" + BF_HREF) !== -1);

  console.log("\n══ 10. no invented facts, in every mode ══");
  console.log("    block (" + FACTS.length + " characters):" + FACTS.replace(/\n/g, "\n      "));
  const ext10 = await generate(SERVER, { money_url: "https://example.com/product" }, article(["https://example.com/product"]));
  const modes10 = { "own page": t9, "listing": listing9, "external": ext10 };
  const placed = Object.keys(modes10).map(k => {
    const p = modes10[k].prompt || "";
    return p.split(FACTS).length === 2 && p.indexOf(FACTS) < p.indexOf("Write ONE complete blog post") ? "ok" : k;
  });
  check("10. the block is in the own-page, listing and external prompts, once, ahead of the writing brief", placed.every(x => x === "ok"), JSON.stringify(placed));
  check("10. it names the two claims the first article invented", /much higher rate than average/.test(FACTS) && /often within days/.test(FACTS) && /most owners/.test(FACTS));
  check("10. the first article's rate claim and \"largely automated\" are both still named as forbidden, and so is why a company acted",
    /No statistics, percentages, rates or counts[^\n]*not "at a much higher rate than average"/.test(FACTS) &&
    /Nothing about how a named company's review systems work inside — not "largely automated"[^\n]*nothing about why it acted/.test(FACTS));
  check("10. it lets the writer name the category and say ad platforms publish policies restricting some products in it",
    /You may name the reader's category and say that ad platforms publish policies restricting some products in it\./.test(FACTS));
  check("10. it never lets the writer say what a policy says, and sends the reader to the current policy instead",
    /Never say what any policy says, allows, forbids or requires: tell the reader to read the current policy for their own product\./.test(FACTS));
  check("10. it asks for advice specific to the business, naming its category, and not for general advice",
    /Write practical advice specific to the business described above, naming its category when the brief names one\./.test(FACTS) &&
    !/Practical, general advice/.test(FACTS));
  check("10. it is not NO_INVENTION_RULE: none of that rule's sources or its printed-refusal sentence appear in the prompt",
    Object.keys(modes10).every(k => !/LIVE PLATFORM STATS|ACCUMULATED MEMORY|I don't have that figure/.test(modes10[k].prompt || "")));

  console.log("\n══ 11. own-page posts say plainly that BizForce AI is ours ══");
  const disclosed = p => /write "we built"/.test(p || "") && /BizForce AI's own/.test(p || "") && /paid platform/.test(p || "");
  check("11. the own-page prompt tells the writer to name BizForce AI, write \"we built\", and not hide that it is paid", disclosed(t9.prompt));
  check("11. the external and listing prompts say none of it", !/we built/.test(ext10.prompt || "") && !/we built/.test(listing9.prompt || "") &&
    !/BizForce AI's own/.test(ext10.prompt || "") && !/BizForce AI's own/.test(listing9.prompt || ""));

  console.log("\n══ 12. money_path is the platform's own account's alone ══");
  const other = await generate(SERVER, { money_path: OWN }, article([OWN]), { userId: SUBJECT_USER_ID });
  console.log("    another account: " + other.status + " " + JSON.stringify(other.body));
  check("12. another account sending money_path is 403, with no model call and nothing filed",
    other.status === 403 && other.calls === 0 && other.writes.length === 0 && /only to the platform's own account/.test((other.body || {}).error || ""));
  const otherPub = await publish(SERVER, prop.payload || {}, { userId: SUBJECT_USER_ID });
  check("12. a money_path proposal belonging to another account throws at publish and writes nothing",
    /only to the platform's own account/.test(otherPub.thrown || "") && otherPub.writes.length === 0, otherPub.thrown);
  const otherPlain = await generate(SERVER, { topic: "wool care" }, article(["/listing/wool-hat"]), { userId: SUBJECT_USER_ID });
  check("12. without money_path another account is unaffected: a listing post is filed as before", otherPlain.status === 201 && otherPlain.writes.length === 1, otherPlain.status);

  console.log("\n══ 13. a platform cannot promise escape from platforms ══");
  const p13 = t9.prompt || "";
  check("13. the own-page prompt says BizForce AI is itself a platform, with the blog and storefront on bizforceai.net under its terms",
    /BizForce AI is itself a platform: the blog and the storefront live on bizforceai\.net under its terms/.test(p13));
  check("13. it forbids calling BizForce AI, the blog, the storefront or an email list beyond any platform's reach, and says what is true instead",
    /less dependence on any one platform, not freedom from platforms/.test(p13) &&
    /never call BizForce AI, the blog, the storefront or an email list something no platform can disable/.test(p13));
  check("13. it says the email service can suspend sending, and that keeping the list does not keep the sending",
    /email service, which has its own rules and can suspend sending/.test(p13) && /cannot keep sending through a service that stopped it/.test(p13));
  check("13. it tells the writer to say the platform is paid and what it costs, and the price is in the prompt",
    /say in that mention that it is a paid platform and what it costs/.test(p13) && p13.indexOf("$199/month") !== -1 && !/do not hide that it is a paid platform/.test(p13));
  const ANCHOR_RULE = "never the href itself";
  const anchored = await generate(SERVER, { money_path: OWN, money_anchor: "what BizForce AI does for suppressed businesses" }, article([OWN]));
  check("13. without money_anchor the writer is told not to use the href as the link's text; with it, the suggestion stands in its place",
    p13.indexOf(ANCHOR_RULE) !== -1 && anchored.status === 201 && (anchored.prompt || "").indexOf(ANCHOR_RULE) === -1 &&
    (anchored.prompt || "").indexOf("- suggested anchor text=\"what BizForce AI does for suppressed businesses\"") !== -1, anchored.status);
  check("13. the listing and external prompts say none of it",
    [ext10, listing9].every(r => !/itself a platform|freedom from platforms|can suspend sending|never the href itself/.test(r.prompt || "")));

  console.log("\n══ 14. under a compliance profile, the category is a product type ══");
  console.log("    line:" + PRODUCT_TYPE.replace(/\n/g, "\n      "));
  check("14. the line names the category as a product type, never by a condition even paraphrased, and says the content rules win",
    /name it as a product type/.test(PRODUCT_TYPE) && /never by a condition it addresses, not even paraphrased, hinted at or softened/.test(PRODUCT_TYPE) &&
    /MANDATORY CONTENT RULES above win over anything in NO INVENTED FACTS/.test(PRODUCT_TYPE));
  const WITH = [
    ["external, auto (swordvitality.com)", { money_url: "https://swordvitality.com/store/x.html" }, article(["https://swordvitality.com/store/x.html"]), null],
    ["external, auto (mrearthrose.com)", { money_url: "https://mrearthrose.com/x.html", site_context: "Botanical supplements for men." }, article(["https://mrearthrose.com/x.html"]), null],
    ["external, explicit", { money_url: "https://example.com/product", compliance_profile: "supplement_vitality" }, article(["https://example.com/product"]), null],
    ["listing, explicit", { topic: "wool care", compliance_profile: "supplement_vitality" }, article(["/listing/wool-hat"]), null],
    ["own page, explicit", { money_path: OWN, compliance_profile: "supplement_vitality" }, article([OWN]), null]
  ];
  for (const [label, body, text, opts] of WITH) {
    const a = await generate(SERVER, body, text, opts), b = await generate(SERVER_PREV, body, text, opts);
    const p = unHosted(a.prompt) || "", at = p.indexOf(PRODUCT_TYPE);
    const placed = p.split(PRODUCT_TYPE).length === 2 && at > p.indexOf("MANDATORY CONTENT RULES") && p.indexOf("MANDATORY CONTENT RULES") !== -1 &&
      at === p.indexOf(FACTS) + FACTS.length && at < p.indexOf("Write ONE complete blog post");
    const factsEnd = (b.prompt || "").indexOf(FACTS) + FACTS.length;
    const exact = b.prompt != null && p === b.prompt.slice(0, factsEnd) + PRODUCT_TYPE + b.prompt.slice(factsEnd);
    check("14. with a profile · " + label + " — the line is there once, after the compliance section and the facts block, ahead of the brief, and nothing else changed against " + PREV + " but section 21's clause",
      placed && exact, "placed=" + placed + " exact=" + exact);
  }
  const WITHOUT = [
    ["own page", { money_path: OWN, topic: "customers after an ad ban" }, article([OWN]), null],
    ["own page, site_context", { money_path: OWN, site_context: "Supplement and CBD sellers." }, article([OWN]), null],
    ["external, example.com", { money_url: "https://example.com/product", site_context: "A shop." }, article(["https://example.com/product"]), null],
    ["listing", { topic: "wool care" }, article(["/listing/wool-hat"]), null]
  ];
  for (const [label, body, text, opts] of WITHOUT) {
    const a = await generate(SERVER, body, text, opts), b = await generate(SERVER_PREV, body, text, opts);
    check("14. without a profile · " + label + " — no product-type line, and the prompt is byte-identical to " + PREV +
      " once section 16's line and section 21's clause are out",
      a.prompt != null && unHosted(a.prompt).split(AROUND).join("") === b.prompt && a.prompt.indexOf("NAMING THE CATEGORY") === -1, a.status + " vs " + b.status);
  }

  console.log("\n══ 15. the claim screen ══");
  const sc = shared(), sctx = {};
  vm.createContext(sctx);
  /* Its own definitions only: the closure walker would read "Stripe" in the
     company list as an identifier and lift the Stripe client. */
  vm.runInContext(["ARTICLE_CLAIM_POPULATION", "ARTICLE_CLAIM_COMPANY", "ARTICLE_CLAIM_POLICY_VERB", "ARTICLE_CLAIM_QUESTION", "ARTICLE_CLAIM_DECLINES",
    "ARTICLE_CLAIM_CLASSES", "findArticleClaims"]
    .map(n => sc.definitionOf(SERVER, n)).join("\n") + "\nthis.find = findArticleClaims;", sctx);
  const classesOf = t => sctx.find([t]).map(h => h.class);
  /* Every true hit in the four own-page drafts, one sentence per class it
     must catch, copied from the drafts so this does not depend on their rows —
     less draft 1's "...so often?" heading, which section 17 lets back in. */
  const CLAIMS = [
    ["quantity", "It varies widely by business, but most owners see the fastest recovery from email and SMS to an existing list."],
    ["quantity", "Most disabled ad accounts show a reason code or a link to an appeal form inside Ads Manager or Business Suite."],
    ["quantity", "Many businesses in restricted categories find it more useful to build channels they control instead of betting everything on one ad account again."],
    ["typicality", "It's rarely about one bad ad — it's usually the category itself triggering extra scrutiny."],
    ["typicality", "If your business sits in a category that often gets flagged, write straightforward answers."],
    ["typicality", "Businesses that already had an email list or a website tend to have a faster path forward simply because they're not starting from zero."],
    ["typicality", "The businesses that recover fastest from a disabled account are usually the ones that already had a way to reach customers."],
    ["figure", "Review systems flag categories like supplements at a much higher rate than average."],
    ["figure", "Around 40% of appeals succeed."],
    ["beyond_reach", "A practical long-term response is to build the parts of your presence that no platform can disable."],
    ["beyond_reach", "Yes — an email list is one of the few customer channels a platform can't disable."],
    ["beyond_reach", "Your email list can't be disabled by someone else's policy team."],
    ["beyond_reach", "But it's also not something a platform can turn off."],
    ["beyond_reach", "Now is the time to build it, because it's yours regardless of what any platform decides."],
    ["beyond_reach", "This takes more effort than running an ad, but nobody can disable a relationship."],
    ["named_company_policy", "Ad platforms, including Meta, publish policies that restrict advertising for certain products and categories."],
    ["named_company_policy", "Meta's review process for disabled ad accounts is largely automated."],
    ["named_company_policy", "Supplements are routinely flagged by Facebook."]
  ];
  const missed = CLAIMS.filter(([cls, t]) => classesOf(t).indexOf(cls) === -1);
  check("15. every claim from the four drafts is caught, by its own class (" + CLAIMS.length + " sentences)", missed.length === 0, JSON.stringify(missed.map(x => x[1].slice(0, 50))));
  const byClass = {};
  CLAIMS.forEach(([cls]) => { byClass[cls] = true; });
  ["quantity", "typicality", "figure", "beyond_reach", "named_company_policy"].forEach(cls => {
    const own = CLAIMS.filter(x => x[0] === cls), lost = own.filter(([c, t]) => classesOf(t).indexOf(c) === -1);
    check("15. class " + cls + " catches its " + own.length + " sentence" + (own.length === 1 ? "" : "s"), own.length > 0 && lost.length === 0, lost.length + " lost");
  });
  /* The innocent uses of the same words, and the true sentences the drafts
     scoped correctly. */
  const INNOCENT = ["These are your most reachable customers right now.", "Make the most of the list you already have.", "Send at most one email a week.",
    "Most importantly, keep a copy of your list.", "How many customers do you have on that list?", "There are many ways to reach people without ads.",
    "Ask as many past customers as you can.", "Write to a few customers this week.", "How often should I email my list?", "Post as often as you can keep it useful.",
    "Frequently asked questions", "Tend to your list every week.", "Read Meta's current policy for your product.", "The appeal form sits inside Ads Manager.",
    "Your list doesn't disappear if an ad account is disabled.", "Keep your own copy regardless of what happens to any ad account.",
    "Too many sellers wait on the appeal.", "Your most loyal buyers will read it.", "We built BizForce AI, a paid platform at $199 a month on one plan called All Access.",
    "Ad platforms publish policies restricting some products in these categories.", "It varies, and there's no fixed timeline you can count on."];
  const wrongly = INNOCENT.filter(t => sctx.find([t]).length);
  check("15. none of the " + INNOCENT.length + " innocent uses is caught", wrongly.length === 0, JSON.stringify(wrongly));
  const KNOWN_FALSE = "If your Facebook ad account was disabled, the first instinct is usually to find a way to get it back.";
  console.log("    known false catch, kept: " + JSON.stringify(sctx.find([KNOWN_FALSE]).map(h => h.class)) + " — " + KNOWN_FALSE);

  const CLAIM_P = "<p>Most owners see results from email often within days, and no platform can disable a list.</p>";
  const MODES15 = [
    ["own page", { money_path: OWN }, article([OWN], CLAIM_P)],
    ["listing", { topic: "wool care" }, article(["/listing/wool-hat"], CLAIM_P)],
    ["external", { money_url: "https://example.com/product" }, article(["https://example.com/product"], CLAIM_P)]
  ];
  for (const [label, body, text] of MODES15) {
    const r = await generate(SERVER, body, text);
    const got = ((r.body || {}).claims || []).map(c => c.class).sort().join(",");
    check("15. generate · " + label + " — an article with claims is 422, lists each with its sentence, and files nothing",
      r.status === 422 && r.writes.length === 0 && got === "beyond_reach,quantity,typicality" &&
      /states 3 things it has no source for/.test((r.body || {}).error || "") && ((r.body || {}).claims || []).every(c => /Most owners/.test(c.sentence)),
      r.status + " " + got);
  }
  const clean15 = await generate(SERVER, { money_path: OWN }, article([OWN]));
  check("15. generate · the same article without the claims is filed", clean15.status === 201 && clean15.writes.length === 1, clean15.status);
  const pubClaim = await publish(SERVER, Object.assign({}, prop.payload, { body: String(prop.payload.body) + CLAIM_P }));
  console.log("    publish: " + pubClaim.thrown);
  check("15. publish · a proposal whose body states a claim throws, naming the sentence, and writes nothing",
    /states 3 things it has no source for, and was not published/.test(pubClaim.thrown || "") && /Most owners see results/.test(pubClaim.thrown || "") && pubClaim.writes.length === 0,
    pubClaim.thrown);
  const pubMeta = await publish(SERVER, Object.assign({}, prop.payload, { meta_description: "Most sellers recover in a week." }));
  check("15. publish · the meta description is screened too", /states 1 thing/.test(pubMeta.thrown || "") && pubMeta.writes.length === 0, pubMeta.thrown);

  console.log("\n══ 16. around the product, not around the problem ══");
  console.log("    line:" + AROUND.replace(/\n/g, "\n      "));
  check("16. the line says to write around the product, its ingredients and questions about it, never around a condition, symptom or problem",
    /write around the product, its ingredients and the questions a customer asks about the product itself/.test(AROUND) &&
    /never around a condition, a symptom or a problem it might be bought for/.test(AROUND));
  const HEALTH = [
    ["supplements and CBD", "Businesses that sell natural supplements, CBD and hemp, adult wellness, esoteric and spiritual products, firearms accessories and similar."],
    ["supplements only", "Our readers sell dietary supplements."],
    ["herbal", "Small herbal and botanical brands."],
    ["kratom", "Kratom vendors."]
  ];
  for (const [label, ctx] of HEALTH) {
    const a = await generate(SERVER, { money_path: OWN, site_context: ctx }, article([OWN])), b = await generate(SERVER_PREV16, { money_path: OWN, site_context: ctx }, article([OWN]));
    const p = unHosted(a.prompt) || "", at = p.indexOf(AROUND), factsEnd = (b.prompt || "").indexOf(FACTS) + FACTS.length;
    check("16. own page, site_context names " + label + " — the line is there once, right after the facts block, ahead of the brief, and nothing else changed against " + PREV16 + " but section 21's clause",
      p.split(AROUND).length === 2 && at === p.indexOf(FACTS) + FACTS.length && at < p.indexOf("Write ONE complete blog post") &&
      b.prompt != null && p === b.prompt.slice(0, factsEnd) + AROUND + b.prompt.slice(factsEnd), a.status);
  }
  const both16 = await generate(SERVER, { money_path: OWN, compliance_profile: "supplement_vitality", site_context: "Supplement sellers." }, article([OWN]));
  const p16 = both16.prompt || "";
  check("16. with a compliance profile too, it follows the product-type line, once each",
    p16.split(AROUND).length === 2 && p16.split(PRODUCT_TYPE).length === 2 && p16.indexOf(AROUND) === p16.indexOf(PRODUCT_TYPE) + PRODUCT_TYPE.length);
  const UNCHANGED16 = [
    ["own page, no site_context", { money_path: OWN }, article([OWN])],
    ["own page, site_context names only firearms and esoteric goods", { money_path: OWN, site_context: "Sellers of firearms accessories and esoteric and spiritual products." }, article([OWN])],
    ["own page, site_context names no category", { money_path: OWN, site_context: "Small businesses cut off by an ad network." }, article([OWN])],
    ["listing, supplement site_context", { topic: "wool care", site_context: "Natural supplements, CBD and hemp." }, article(["/listing/wool-hat"])],
    ["external, supplement site_context", { money_url: "https://example.com/product", site_context: "Natural supplements, CBD and hemp." }, article(["https://example.com/product"])],
    ["external, mrearthrose.com with its profile", { money_url: "https://mrearthrose.com/x.html", site_context: "Botanical supplements for men." }, article(["https://mrearthrose.com/x.html"])]
  ];
  for (const [label, body, text] of UNCHANGED16) {
    const a = await generate(SERVER, body, text), b = await generate(SERVER_PREV16, body, text);
    check("16. " + label + " — no line, and the prompt is byte-identical to " + PREV16 + " once section 21's clause is out",
      a.prompt != null && unHosted(a.prompt) === b.prompt && a.prompt.indexOf("CONTENT ADVICE FOR HEALTH-ADJACENT SELLERS") === -1, a.status + " vs " + b.status);
  }

  console.log("\n══ 17. two narrowings ══");
  /* The screen as it stood before them, for "these are what changed". */
  const s17 = shared(), hctx = {};
  vm.createContext(hctx);
  vm.runInContext(["ARTICLE_CLAIM_POPULATION", "ARTICLE_CLAIM_COMPANY", "ARTICLE_CLAIM_POLICY_VERB", "ARTICLE_CLAIM_CLASSES", "findArticleClaims"]
    .map(n => s17.definitionOf(SERVER_PREV17, n)).join("\n") + "\nthis.find = findArticleClaims;", hctx);
  const classesBefore = t => hctx.find([t]).map(h => h.class);
  /* Generation 5's five hits, verbatim, and what each must now be. */
  const FIVE = [
    [[], "This is about what you can actually do right now — not about why Facebook's systems flagged you, which isn't something you can see or verify from the outside."],
    [["typicality"], "If you sell supplements, CBD or hemp, adult wellness items, or esoteric and spiritual products, the instinct after losing an ad account is to write content aimed at the problem a customer has — because that's often what ad copy used to do."],
    [["typicality"], "If your ad account was disabled, check whether your payment processor has flagged your account for the same category of product — the two often get scrutinized separately, but a business in a restricted category can get cut off from both around the same time."],
    [[], "How long does a Facebook ad account appeal usually take?"],
    [["typicality"], "Email to any list you already have is usually the quickest to activate, since it doesn't require building new traffic — it only requires having addresses and a service to send through."]
  ];
  FIVE.forEach(([want, t], i) => console.log("    #" + (i + 1) + " before " + JSON.stringify(classesBefore(t)) + " now " + JSON.stringify(classesOf(t))));
  check("17. before the narrowings, all five of generation 5's hits were caught", FIVE.every(([w, t]) => classesBefore(t).length === 1));
  check("17. now the declining sentence (#1) and the FAQ heading (#4) pass, and #2, #3 and #5 are still caught as typicality",
    FIVE.every(([want, t]) => JSON.stringify(classesOf(t)) === JSON.stringify(want)));
  const DECLINES = [
    ["It's not about why Google flagged the account.", "Google flagged the account."],
    ["Why Meta flagged you isn't something you can see.", "Meta flagged you."],
    ["Why Meta flagged you isn’t something you can see.", "Meta flagged you for the category."],
    ["There is no way to know why Meta flagged your account.", "Meta flagged your account."],
    ["You can't know why Facebook restricted it.", "Facebook restricted it."],
    ["Don't guess why Meta flagged it.", "Meta flagged it."]
  ];
  check("17. each of the five declining phrases — either apostrophe — exempts its sentence, and the same sentence without it is still caught",
    DECLINES.every(([with_, without]) => classesOf(with_).length === 0 && classesOf(without).indexOf("named_company_policy") !== -1),
    JSON.stringify(DECLINES.map(([a, b]) => [classesOf(a), classesOf(b)])));
  /* What each lets back in, asserted so the comment in server.js stays true. */
  const LET_IN = ["Why do Facebook ad accounts get disabled for supplement and wellness businesses so often?",
    "It's not about why Meta flags supplements; it flags them for the category."];
  check("17. LETS BACK IN: draft 1's \"...so often?\" heading, and a claim wrapped in a declining phrase — both were caught, both now pass",
    LET_IN.every(t => classesBefore(t).length > 0 && classesOf(t).length === 0), JSON.stringify(LET_IN.map(classesOf)));
  const STILL = [["named_company_policy", "That's why Meta's systems flag supplements."], ["typicality", "Appeals usually take weeks."],
    ["typicality", "They usually do."], ["quantity", "Why do most sellers lose their accounts?"], ["figure", "Do 40% of appeals succeed?"]];
  check("17. still caught: a \"why\" clause that does not decline, a statement, the answer after a question, and a question's quantity or figure",
    STILL.every(([cls, t]) => classesOf(t).indexOf(cls) !== -1) && classesOf("Do appeals usually take weeks? They usually do.").length === 1,
    JSON.stringify(STILL.map(([c, t]) => classesOf(t))));

  console.log("\n══ 18. one repair ══");
  const REPAIR_ROUTE = liftValue(SERVER, "SEO_CLAIM_REPAIR_ROUTE");
  const bodyOf = text => String(text).split("---BODY---\n")[1].trim();
  const SENT = "Most owners see results from email often within days, and no platform can disable a list.";
  const FIXED = "Email to people who already know you is one place to start, and how quickly it works varies.";
  const one = s => "---SENTENCE 1---\n" + s + "\n---END---";
  const first18 = article([OWN], CLAIM_P);
  const rep = await generate(SERVER, { money_path: OWN }, first18, { repair: one(FIXED) });
  const filed18 = ((rep.writes[0] || {}).payload || {}).payload || {};
  const plain18 = ((clean15.writes[0] || {}).payload || {}).payload || {};
  console.log("    " + rep.status + ", calls " + JSON.stringify(rep.routes) + "; claim_repair " + JSON.stringify(filed18.claim_repair));
  check("18. a claim hit gets exactly one more model call, under " + JSON.stringify(REPAIR_ROUTE) + ", and the repaired article is filed",
    rep.status === 201 && rep.calls === 2 && rep.routes[0] === "POST /api/agents/seo/generate-post" && rep.routes[1] === REPAIR_ROUTE &&
    rep.writes.length === 1 && rep.drafts.length === 0, rep.status + "/" + rep.calls);
  check("18. the filed body is the first draft's with only the flagged sentence replaced, and nothing else in the proposal differs",
    filed18.body === bodyOf(first18).replace(SENT, FIXED) &&
    ["title", "slug", "meta_description", "keyword", "internal_links", "money_path"].every(k => JSON.stringify(filed18[k]) === JSON.stringify(plain18[k])));
  check("18. the proposal records the repair: the sentence as flagged and as rewritten, where it was, and what it claimed",
    JSON.stringify(filed18.claim_repair) === JSON.stringify({ sentences: [{ part: "body", says: ["says how many of a group do something", "says what usually or often happens",
      "says something is beyond a platform's reach"], before: SENT, after: FIXED }] }) && !("claim_repair" in plain18));
  const rp = rep.prompts[1] || "";
  console.log("    the repair prompt (fixture), up to the article:\n      " + rp.slice(0, rp.indexOf("\n\nNO INVENTED FACTS")).replace(/\n/g, "\n      "));
  console.log("    ...the rules, the article, then:\n      " + rp.slice(rp.indexOf("THE SENTENCES TO REWRITE")).replace(/\n/g, "\n      "));
  check("18. the repair is given the rules, the article and the numbered sentence with what it claims, and asked for that sentence alone",
    rp.indexOf("Rewrite ONLY that sentence") !== -1 && rp.indexOf(FACTS) !== -1 && rp.indexOf(bodyOf(first18)) !== -1 &&
    rp.indexOf("1. (says how many of a group do something; says what usually or often happens; says something is beyond a platform's reach) " + SENT) !== -1 &&
    /Respond with exactly 1 section and nothing else[\s\S]*---SENTENCE 1---\nthe rewritten sentence 1\n---END---$/.test(rp) &&
    rp.indexOf("Write ONE complete blog post") === -1 && rp.indexOf("SEO SYSTEM") === -1);
  check("18. the repaired article met the money-link and claim checks again (each ran twice)",
    rep.counts.bodyLinksToMoneyUrl === 2 && rep.counts.findArticleClaims === 2, JSON.stringify(rep.counts));
  const twoParts = first18.replace("---META_DESCRIPTION---\nA plain answer.", "---META_DESCRIPTION---\nMost sellers recover in a week.");
  const rep2 = await generate(SERVER, { money_path: OWN }, twoParts, { repair: "---SENTENCE 1---\nA plain answer for sellers whose ads were stopped.\n---SENTENCE 2---\n" + FIXED });
  const filed2 = ((rep2.writes[0] || {}).payload || {}).payload || {};
  check("18. sentences in the meta description and the body are each put back where they were, and the title is untouched",
    rep2.status === 201 && rep2.calls === 2 && filed2.meta_description === "A plain answer for sellers whose ads were stopped." &&
    filed2.body === bodyOf(first18).replace(SENT, FIXED) && filed2.title === plain18.title && (filed2.claim_repair || {}).sentences.map(s => s.part).join() === "meta_description,body",
    rep2.status + " " + JSON.stringify(rep2.body || "").slice(0, 200));
  const stillClaims = await generate(SERVER, { money_path: OWN }, first18, { repair: one("Most sellers usually see results within days.") });
  const sb18 = stillClaims.body || {};
  console.log("    still claims: " + stillClaims.status + " " + JSON.stringify(sb18.error));
  check("18. a rewrite that still states a claim is 422 after exactly two calls — never a third — naming both sets of claims, and nothing is filed",
    stillClaims.status === 422 && stillClaims.calls === 2 && stillClaims.writes.length === 0 && /still states 2 things it has no source for/.test(sb18.error || "") &&
    (sb18.claims || []).map(c => c.class).sort().join() === "beyond_reach,quantity,typicality" && (sb18.repair || {}).outcome === "refused_after_repair" &&
    ((sb18.repair || {}).claims_after || []).length === 2, stillClaims.status + "/" + stillClaims.calls);
  const UNUSABLE = [
    ["unparseable", "I rewrote it: Email is one place to start."],
    ["unparseable", "---SENTENCE 1---\n" + FIXED + "\n---SENTENCE 2---\nextra\n---END---"],
    ["invalid", one("<a href=\"/pricing\">See pricing</a>, which varies.")],
    ["invalid", one(FIXED + " " + "And more. ".repeat(20))],
    ["call_failed", new Error("Daily model-call limit reached")]
  ];
  const unusable = [];
  for (const [want, answer] of UNUSABLE) {
    const r = await generate(SERVER, { money_path: OWN }, first18, { repair: answer });
    unusable.push(r.status === 422 && r.calls === 2 && r.writes.length === 0 && ((r.body || {}).repair || {}).outcome === want ? "ok" : want + ":" + r.status + "/" + r.calls + "/" + ((r.body || {}).repair || {}).outcome);
  }
  check("18. an unusable rewrite — no format, the wrong count, markup, too long — or a failed repair call is 422 after two calls, nothing filed",
    unusable.every(x => x === "ok"), JSON.stringify(unusable));
  const across = await generate(SERVER, { money_path: OWN }, article([OWN], "<p><strong>Most owners</strong> see results from email within days.</p>"), { repair: one(FIXED) });
  check("18. a flagged sentence that runs across markup is not sent for repair at all: one call, 422, nothing filed",
    across.status === 422 && across.calls === 1 && across.writes.length === 0 && ((across.body || {}).repair || {}).outcome === "unlocatable" &&
    ((across.body || {}).repair || {}).model_called === false, across.status + "/" + across.calls);
  const otherGate = await generate(SERVER, { money_path: OWN }, article(["/blog/" + HANDLE + "/older-post"], CLAIM_P), { repair: one(FIXED) });
  check("18. a draft that fails another gate as well is refused by that gate with no repair call: the claim screen runs last",
    otherGate.status === 422 && otherGate.calls === 1 && /money page \/suppressed\.html/.test((otherGate.body || {}).error || ""), otherGate.status + "/" + otherGate.calls);
  /* The rewritten article meets every gate again: a violation only the rewrite
     introduced is caught by the gate that owns it. */
  const DISCLAIMER = liftValue(SERVER, "COMPLIANCE_DISCLAIMER");
  const comp = await generate(SERVER, { topic: "wool care", compliance_profile: "supplement_vitality" },
    article(["/listing/wool-hat"], CLAIM_P + "<p>" + DISCLAIMER + "</p>"), { repair: one("Some sellers write about diabetes instead.") });
  console.log("    compliance after repair: " + comp.status + " " + JSON.stringify((comp.body || {}).error));
  check("18. a compliance violation only the rewrite introduced is refused by the compliance gate, which ran on both drafts",
    comp.status === 422 && comp.calls === 2 && comp.writes.length === 0 && (comp.body || {}).compliance_profile === "supplement_vitality" &&
    /This was the article after one rewrite of the 1 sentence the claim screen flagged\./.test((comp.body || {}).error || "") &&
    comp.counts.findComplianceViolations === 2, comp.status + " " + JSON.stringify(comp.counts));
  const LONG = "Most owners see results from email often within days, and no platform can disable a list that they have built up carefully over years of selling to the same loyal customers in their own community.";
  let pad18 = "<p>Owned channels keep working when a platform withdraws approval.</p>";
  while ((pad18 + LONG).length < 830) pad18 += "<p>Owned channels keep working when a platform withdraws approval.</p>";
  const shortBody = "<h2>Answer</h2>" + pad18 + '<p><a href="' + OWN + '">BizForce AI</a></p><p>' + LONG + "</p>";
  const shortText = article([OWN]).split("---BODY---\n")[0] + "---BODY---\n" + shortBody;
  const short = await generate(SERVER, { money_path: OWN }, shortText, { repair: one("Email is one place to start.") });
  console.log("    body " + shortBody.length + " → " + (shortBody.length - LONG.length + "Email is one place to start.".length) + " characters after the rewrite: " + short.status + " " + JSON.stringify((short.body || {}).error));
  check("18. a body the rewrite takes under 800 characters is refused by the length gate",
    short.status === 422 && short.calls === 2 && /post body of only \d+ characters/.test((short.body || {}).error || "") && short.writes.length === 0, short.status);
  const ext18 = await generate(SERVER, { money_url: "https://example.com/product" }, article(["https://example.com/product"], CLAIM_P), { repair: one(FIXED) });
  check("18. external mode: repaired and filed, its money link checked on both drafts",
    ext18.status === 201 && ext18.calls === 2 && ext18.counts.bodyLinksToMoneyUrl === 2, ext18.status + " " + JSON.stringify(ext18.counts));

  console.log("\n══ 19. refused drafts are kept ══");
  const BRIEF = { money_path: OWN, topic: "ad account disabled", site_context: "Sellers cut off by ad networks.", money_anchor: "BizForce AI" };
  const noLinkText = article(["/blog/" + HANDLE + "/older-post"]);
  const r19 = await generate(SERVER, BRIEF, noLinkText);
  const d19 = r19.drafts[0] || {};
  console.log("    row: " + JSON.stringify(Object.assign({}, d19, { body: (d19.body || "").slice(0, 40) + "…" })));
  check("19. a draft refused at a gate is one row: the gate, the refusal exactly as sent, the draft as returned, the mode and the brief",
    r19.status === 422 && r19.drafts.length === 1 && d19.stage === "money_link" && JSON.stringify(d19.refusal) === JSON.stringify(r19.body) &&
    d19.body === bodyOf(noLinkText) && d19.title === "What to do when your ad account is disabled" && d19.slug === SLUG && d19.meta_description === "A plain answer." &&
    d19.mode === "own_page" && d19.money_target === OWN && d19.user_id === AUTHOR && d19.repair === null &&
    JSON.stringify(d19.brief) === JSON.stringify({ topic: "ad account disabled", site_name: null, site_context: "Sellers cut off by ad networks.", money_anchor: "BizForce AI" }));
  const garbled = await generate(SERVER, { money_path: OWN }, "Here is your article about ad accounts.");
  check("19. an unreadable answer is kept whole, as raw_response, under stage unparseable",
    garbled.status === 502 && garbled.drafts.length === 1 && garbled.drafts[0].stage === "unparseable" && garbled.drafts[0].raw_response === "Here is your article about ad accounts.");
  const dr = stillClaims.drafts[0] || {};
  check("19. a claim refusal after a repair keeps the FIRST draft, and the rewrite beside it: each sentence before and after, the model's answer, the rewritten body",
    stillClaims.drafts.length === 1 && dr.stage === "claims" && dr.body === bodyOf(first18) && (dr.repair || {}).outcome === "refused_after_repair" &&
    ((dr.repair || {}).draft || {}).body === bodyOf(first18).replace(SENT, "Most sellers usually see results within days.") &&
    ((dr.repair || {}).sentences || [])[0].before === SENT && (dr.repair || {}).response === one("Most sellers usually see results within days."));
  check("19. a refusal by another gate after a repair is stored as after_repair:<gate>",
    (comp.drafts[0] || {}).stage === "after_repair:compliance" && (short.drafts[0] || {}).stage === "after_repair:body_length");
  check("19. a filed draft, repaired or not, writes no row", clean15.drafts.length === 0 && rep.drafts.length === 0 && ext18.drafts.length === 0);
  const noTable = await generate(SERVER, BRIEF, noLinkText, { draftInsertError: { code: "PGRST205", message: "Could not find the table" } });
  check("19. when the insert fails (131 not applied) the caller's answer is exactly the same",
    noTable.status === r19.status && JSON.stringify(noTable.body) === JSON.stringify(r19.body) && noTable.writes.length === 0);
  const MIG131 = fs.readFileSync(path.join(REPO, "supabase", "migrations", "131_seo_refused_drafts.sql"), "utf8").replace(/\r\n/g, "\n");
  const tableSql = (/create table if not exists public\.seo_refused_drafts \(([\s\S]*?)\n\);/.exec(MIG131) || [])[1] || "";
  const columns = tableSql.split("\n").map(l => (/^\s+([a-z_]+)\s/.exec(l) || [])[1]).filter(Boolean);
  const written = new Set();
  [r19, garbled, stillClaims, comp, short, across].forEach(r => r.drafts.forEach(d => Object.keys(d).forEach(k => written.add(k))));
  const modes = new Set(); [r19, garbled, stillClaims, comp].forEach(r => r.drafts.forEach(d => modes.add(d.mode)));
  console.log("    columns " + JSON.stringify(columns) + "\n    written " + JSON.stringify([...written]));
  check("19. migration 131 has a column for every key the route writes, a mode check that admits every mode written, and no access but the service role's",
    [...written].every(k => columns.indexOf(k) !== -1) && [...modes].every(m => new RegExp("mode in \\([^)]*'" + m + "'").test(MIG131)) &&
    /enable row level security/.test(MIG131) && /revoke all on public\.seo_refused_drafts from anon, authenticated/.test(MIG131),
    JSON.stringify([...written].filter(k => columns.indexOf(k) === -1)));

  console.log("\n══ 20. a platform is a population too ══");
  /* The screen at the commit before, for "none of these was caught". */
  const s20 = shared(), pctx = {};
  vm.createContext(pctx);
  vm.runInContext(["ARTICLE_CLAIM_POPULATION", "ARTICLE_CLAIM_COMPANY", "ARTICLE_CLAIM_POLICY_VERB", "ARTICLE_CLAIM_QUESTION", "ARTICLE_CLAIM_DECLINES",
    "ARTICLE_CLAIM_CLASSES", "findArticleClaims"]
    .map(n => s20.definitionOf(SERVER_PREV21, n)).join("\n") + "\nthis.find = findArticleClaims;", pctx);
  const classesAt21 = t => pctx.find([t]).map(h => h.class);
  /* The first is generation 7's sentence, verbatim. One or more per noun added. */
  const SYSTEMS = [
    "Look for an appeal form or a review request inside the ads platform's own interface — most ad networks publish one, even if it's buried a few clicks deep.",
    "Many platforms restrict supplement ads.", "Most payment processors review high-risk merchants more closely.",
    "Most email service providers let you export your list.", "Many services suspend sending without notice.",
    "Most sites that sell supplements carry a disclaimer.", "Many websites in this category were deindexed.",
    "Few marketplaces allow CBD listings.", "Most search engines index a new blog within weeks.",
    "Most of the platforms you rely on have their own rules."
  ];
  SYSTEMS.forEach(t => console.log("    " + JSON.stringify(classesAt21(t)) + " → " + JSON.stringify(classesOf(t)) + "  " + t.slice(0, 70)));
  check("20. each is caught as quantity, and none was caught at " + PREV21 + " (" + SYSTEMS.length + " sentences, generation 7's first)",
    SYSTEMS.every(t => classesOf(t).indexOf("quantity") !== -1 && classesAt21(t).length === 0),
    JSON.stringify(SYSTEMS.filter(t => classesOf(t).indexOf("quantity") === -1 || classesAt21(t).length).map(t => t.slice(0, 40))));
  const ADDED = ["networks", "platforms", "processors", "providers", "services", "sites", "websites", "marketplaces", "engines"];
  check("20. every system noun added has a sentence above that it alone makes a catch",
    ADDED.every(n => SYSTEMS.some(t => new RegExp("\\b" + n + "\\b", "i").test(t) && classesOf(t).length)));
  const NOT_ADDED = ["Spread your business across many channels.", "There are many tools for building an email list.", "Most apps let you export your contacts.",
    "Post on as many platforms as you can keep up with.", "How many platforms should I be on?", "Choose the platforms that fit your product.",
    "The most useful sites for this are your own.", "Pick the few services you actually use.", "Try a few marketplaces before committing to one."];
  check("20. channels, tools and apps are not counted, and a system noun after how/as/the/a few still passes (" + NOT_ADDED.length + " sentences)",
    NOT_ADDED.every(t => classesOf(t).length === 0), JSON.stringify(NOT_ADDED.filter(t => classesOf(t).length)));
  /* What it lets in, asserted so the comment in server.js stays true. */
  const LET_IN20 = ["There are many platforms you can post on.", "You don't need to be on many platforms at once."];
  check("20. LETS IN: \"there are many platforms you can post on\" and \"on many platforms at once\" — passed at " + PREV21 + ", caught now",
    LET_IN20.every(t => classesAt21(t).length === 0 && classesOf(t).indexOf("quantity") !== -1), JSON.stringify(LET_IN20.map(classesOf)));

  console.log("\n══ 21. the mention says where the blog lives ══");
  console.log("    clause:" + HOSTED.replace(/\n/g, "\n      "));
  check("21. the clause asks for the blog and storefront to be named as running on BizForce AI's platform under its terms, not owned outright, and not among the channels the reader controls",
    /say that the blog and the storefront run on BizForce AI's platform and under its terms/.test(HOSTED) && /not one it owns outright/.test(HOSTED) &&
    /do not let BizForce AI's blog or storefront read as one of them/.test(HOSTED) && /^\nIn that same mention/.test(HOSTED));
  const DISCLOSED = "the article has answered the question on its own.";
  const OWN21 = [
    ["own page", { money_path: OWN, topic: "customers after an ad ban" }],
    ["own page, money_anchor", { money_path: OWN, money_anchor: "what BizForce AI does for businesses the ad networks won't serve" }],
    ["own page, supplement site_context and a profile", { money_path: OWN, site_context: "Supplement and CBD sellers.", compliance_profile: "supplement_vitality" }]
  ];
  for (const [label, body] of OWN21) {
    const a = await generate(SERVER, body, article([OWN])), b = await generate(SERVER_PREV21, body, article([OWN]));
    const p = a.prompt || "", q = b.prompt || "", cut = q.indexOf(DISCLOSED) + DISCLOSED.length;
    const placed = p.split(HOSTED).length === 2 && p.indexOf(HOSTED) === p.indexOf(DISCLOSED) + DISCLOSED.length && p.indexOf(HOSTED) < p.indexOf("Write ONE complete blog post");
    const exact = q.split(DISCLOSED).length === 2 && p === q.slice(0, cut) + HOSTED + q.slice(cut);
    check("21. " + label + " — the clause is there once, right after the disclosure, ahead of the brief, and nothing else changed against " + PREV21,
      a.prompt != null && placed && exact, a.status + " placed=" + placed + " exact=" + exact);
  }
  const OTHER21 = [
    ["listing", { topic: "wool care" }, article(["/listing/wool-hat"])],
    ["external, example.com", { money_url: "https://example.com/product", site_context: "A shop." }, article(["https://example.com/product"])],
    ["external, mrearthrose.com with its profile", { money_url: "https://mrearthrose.com/x.html", site_context: "Botanical supplements for men." }, article(["https://mrearthrose.com/x.html"])]
  ];
  for (const [label, body, text] of OTHER21) {
    const a = await generate(SERVER, body, text), b = await generate(SERVER_PREV21, body, text);
    check("21. " + label + " — no clause, and the prompt is byte-identical to " + PREV21,
      a.prompt != null && a.prompt === b.prompt && a.prompt.indexOf("owns outright") === -1, a.status + " vs " + b.status);
  }

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
