"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkPageMeta — bizforceai.net's own home page and every page in its
   sitemap-pages.xml have a <title> of 50–60 characters and a meta
   description of 140–160, measured by the app's own SEO code, and say only
   what the page offers.

   The measuring is server.js's: extractSeoPageData reads the page, and
   seoAuditCharLength counts (code points, as the SEO audit's F5 and F7 do).
   Both are taken out of server.js source and run in isolation, with the
   audit's SEO_AUDIT_TITLE_MAX, SEO_AUDIT_DESCRIPTION_MIN and
   SEO_AUDIT_DESCRIPTION_MAX: the ranges here sit inside the audit's own, so
   the audit can never flag F5 or F7 on these pages.

   WHAT THIS PROVES
     P1. Every <loc> in sitemap-pages.xml resolves to a file (/ to index.html,
         a .html path to itself, any other path through _redirects).
     P2. Each page has exactly one <title> in its head and one meta
         description; the title is 50–60 characters and the description
         140–160, both inside the audit's limits.
     P3. True to the page: no cure/treat/prevent/guarantee/"#1"/"best"/
         "proven" wording; any $ price in them appears in the page's own
         visible text; a title or description that names a count of agents
         names the one AGENT_SYSTEM_PROMPTS has.
     P4. The exact text, pinned, so a change is a decision.

   MUTATE=<name> edits the frontend IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails. A search text that does not
   match exactly once is an ERROR, never counted as caught.
   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const s = require("./_shared");
const { decodeHTML, decodeHTMLAttribute } = require("entities");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const TITLE_MIN = 50, TITLE_MAX = 60, DESC_MIN = 140, DESC_MAX = 160;

/* The text as committed. A change to any of these is a decision: update the
   pin in the same commit. */
const PINNED = {
  "index.html": ["BizForce AI — AI agents for SEO, email, content and sales",
    "One subscription, eighteen AI specialists working from one business profile: SEO research, email campaigns, blog articles and analytics. All Access, $199/month."],
  "app.html": ["Sign In or Create an Account — BizForce AI All Access",
    "Sign in with a password or passkey, or create a BizForce AI account. All Access is $199/month; Lead Radar, social publishing and SMS sending aren't available."],
  "vitality.html": ["Ancient Vitality Codex — free guide to 7 traditional herbs",
    "A free guide to seven traditional herbs men have used for centuries to support energy, drive and vitality. Educational only, not medical advice. Free download."],
  "xxl-xtreme.html": ["War Horse Xtreme Oil for Men, 4 oz — Every Ingredient Named",
    "War Horse Xtreme, also sold as Sword Vitality XXL Xtreme: a 4 oz oil blend for men with no fillers, binders or additives. Its label names every ingredient."],
  "suppressed.html": ["BizForce AI — for businesses the ad networks won't serve",
    "For businesses an ad network, platform or payment processor has cut off: search content you approve, a blog and a storefront under your own handle. $199/month."]
};

const MUTATIONS = {
  // a title over 60 characters
  "title-over-60": [["index.html", "<title>BizForce AI — AI agents for SEO, email, content and sales</title>",
    "<title>BizForce AI — AI agents for SEO, email, content, ads and sales</title>"]],
  // a description over 160 characters
  "description-over-160": [["vitality.html", "Educational only, not medical advice. Free download.\"/>",
    "Educational only, not medical advice. Free PDF download.\"/>"]],
  // a title under 50 characters
  "title-under-50": [["app.html", "<title>Sign In or Create an Account — BizForce AI All Access</title>", "<title>BizForce AI</title>"]],
  // the description goes missing
  "description-missing": [["app.html", "  <meta name=\"description\" content=\"Sign in with a password or passkey, or create a BizForce AI account. All Access is $199/month; Lead Radar, social publishing and SMS sending aren't available.\">\n", ""]],
  // a claim the page cannot keep
  "health-claim": [["xxl-xtreme.html", "Its label names every ingredient.\"/>", "Proven to boost stamina.\"/>"]],
  // a price the page does not show
  "wrong-price": [["suppressed.html", "under your own handle. $199/month.\">", "under your own handle. $149/month.\">"]],
  // a page in the sitemap with no file behind it
  "sitemap-orphan": [["sitemap-pages.xml", "  <url><loc>https://bizforceai.net/vitality</loc></url>\n",
    "  <url><loc>https://bizforceai.net/vitality</loc></url>\n  <url><loc>https://bizforceai.net/no-such-page</loc></url>\n"]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}

/* ── the app's own SEO code, lifted ─────────────────────────────────────── */
const SRC = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
const VARS = ["SEO_TAG_ATTRS", "SEO_AUDIT_TITLE_MAX", "SEO_AUDIT_DESCRIPTION_MIN", "SEO_AUDIT_DESCRIPTION_MAX"];
const FNS = ["safeText", "seoTagAttributes", "seoTags", "seoCollapse", "seoText", "seoDocumentTitle", "seoMetaContent", "extractSeoPageData", "seoAuditCharLength"];
const SEO = { decodeHTML, decodeHTMLAttribute };
vm.createContext(SEO);
vm.runInContext(VARS.map(n => {
  const m = new RegExp("^var " + n + " = .*;$", "m").exec(SRC);
  if (!m) throw new Error("var " + n + " not found in server.js");
  return m[0];
}).concat(FNS.map(n => {
  const d = s.definitionOf(SRC, n);
  if (!d) throw new Error("function " + n + " not found in server.js");
  return d;
})).join("\n") + "\nthis.extract = extractSeoPageData; this.len = seoAuditCharLength;" +
  " this.LIMITS = { titleMax: SEO_AUDIT_TITLE_MAX, descMin: SEO_AUDIT_DESCRIPTION_MIN, descMax: SEO_AUDIT_DESCRIPTION_MAX };", SEO, { filename: "server.js (lifted)" });

/* ── the frontend, in memory ────────────────────────────────────────────── */
const FE = {};
function read(name) {
  if (FE[name] === undefined) {
    const p = path.join(FRONTEND, name);
    FE[name] = fs.existsSync(p) ? fs.readFileSync(p, "utf8").replace(/\r\n/g, "\n") : null;
  }
  return FE[name];
}
["index.html", "sitemap-pages.xml", "_redirects"].concat(Object.keys(PINNED)).forEach(read);
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FE[file] = s.replaceOnce(FE[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (frontend, in memory)");
}

/* A sitemap URL path to the file Netlify serves for it. */
function fileFor(urlPath) {
  if (urlPath === "/" || urlPath === "") return "index.html";
  if (/\.html$/.test(urlPath)) return urlPath.replace(/^\//, "");
  for (const line of String(FE["_redirects"] || "").split("\n")) {
    const parts = line.trim().split(/\s+/);
    if (parts.length >= 3 && parts[0] === urlPath && /^\/[^*:]+\.html$/.test(parts[1]) && parts[2] === "200") return parts[1].slice(1);
  }
  return null;
}
function visibleText(html) {
  return decodeHTML(html.replace(/<head[\s\S]*?<\/head>/i, " ").replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<!--[\s\S]*?-->/g, " ").replace(/<[^>]+>/g, " ")).replace(/\s+/g, " ");
}

(async () => {
  console.log((MUTATE ? "" : "\n") + "══ P1. the pages: index.html and sitemap-pages.xml ══");
  const sitemap = FE["sitemap-pages.xml"];
  check("P1. sitemap-pages.xml was read", typeof sitemap === "string" && /<urlset/.test(sitemap));
  const locs = (String(sitemap).match(/<loc>[^<]+<\/loc>/g) || []).map(l => l.replace(/<\/?loc>/g, "").trim());
  check("P1. it lists pages", locs.length >= 1, locs.length);
  const pages = ["index.html"];
  for (const loc of locs) {
    const u = new URL(loc);
    const file = fileFor(u.pathname);
    check("P1. " + loc + " is served from a file in the repo" + (file ? " (" + file + ")" : ""), u.host === "bizforceai.net" && !!file && read(file) !== null, file);
    if (file && read(file) !== null && pages.indexOf(file) === -1) pages.push(file);
  }
  check("P1. every page is pinned below, and every pinned page is in the set", JSON.stringify(pages.slice().sort()) === JSON.stringify(Object.keys(PINNED).sort()), pages.join(", "));
  check("P1. the audit's limits contain these ranges", SEO.LIMITS.titleMax >= TITLE_MAX && SEO.LIMITS.descMin <= DESC_MIN && SEO.LIMITS.descMax >= DESC_MAX, JSON.stringify(SEO.LIMITS));

  const AGENTS = (function () {
    const decl = /^(?:const|var|let) AGENT_SYSTEM_PROMPTS\s*=\s*\{/m.exec(SRC);
    const open = SRC.indexOf("{", decl.index);
    return Object.keys(vm.runInNewContext("(" + SRC.slice(open, s.braceMatch(SRC, open)) + ")", {})).length;
  })();
  const WORDS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve", "thirteen",
    "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen", "twenty"];
  const CLAIMS = /\b(cures?|treats?|treatment|prevents?|heals?|diagnos\w*|guarantee\w*|proven|clinically|best|#1|number one|boosts?|doubles?|explod\w*)\b/i;

  for (const page of pages) {
    console.log("\n══ P2–P4. " + page + " ══");
    const html = FE[page];
    const d = SEO.extract(html);
    const head = (/<head\b[^>]*>([\s\S]*?)<\/head>/i.exec(html) || [, ""])[1];
    const titles = (head.match(/<title\b/gi) || []).length;
    const descs = (html.match(/<meta\s[^>]*name\s*=\s*["']?description["']?[^>]*>/gi) || []).length;
    const title = d.title, desc = d.metaDescription;
    const tl = title === null ? -1 : SEO.len(title), dl = SEO.len(desc);
    console.log("    title " + tl + ": " + title + "\n    description " + dl + ": " + desc);
    check("P2. " + page + " has exactly one <title> in its head and one meta description", titles === 1 && descs === 1, titles + " title(s), " + descs + " description(s)");
    check("P2. " + page + " title is " + TITLE_MIN + "–" + TITLE_MAX + " characters", tl >= TITLE_MIN && tl <= TITLE_MAX, tl);
    check("P2. " + page + " description is " + DESC_MIN + "–" + DESC_MAX + " characters", dl >= DESC_MIN && dl <= DESC_MAX, dl);
    const both = String(title) + " " + desc;
    check("P3. " + page + " makes no cure, guarantee, proven, best or #1 claim", !CLAIMS.test(both), (both.match(CLAIMS) || [])[0]);
    const prices = both.match(/\$\d+(?:\.\d+)?/g) || [];
    const body = visibleText(html);
    check("P3. " + page + " every price it names is on the page itself", prices.every(p => body.indexOf(p) !== -1), prices.filter(p => body.indexOf(p) === -1).join(", "));
    const counts = [...both.matchAll(/\b(\d+|[A-Za-z]+)\s+(?:AI\s+)?(?:agents|specialists)\b/gi)].map(m => /^\d+$/.test(m[1]) ? Number(m[1]) : WORDS.indexOf(m[1].toLowerCase())).filter(n => n > 0);
    check("P3. " + page + " any count of agents is AGENT_SYSTEM_PROMPTS' " + AGENTS, counts.every(n => n === AGENTS), counts.join(", "));
    check("P4. " + page + " title is the pinned text", title === PINNED[page][0], title);
    check("P4. " + page + " description is the pinned text", desc === PINNED[page][1], desc);
  }

  console.log("\n" + passes + " passed, " + failures + " failed");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
/* A crash is a FAIL (exit 1), not exit 3: 3 is _shared.js's "mutation anchor did not match". */
})().catch(e => { console.log("    FAIL  the harness stopped: " + ((e && e.message) || e)); console.error((e && e.stack) || e); process.exit(1); });
