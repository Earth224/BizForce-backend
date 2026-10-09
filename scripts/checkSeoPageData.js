"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkSeoPageData — extractSeoPageData measures the page as it is written.

   It feeds POST /api/agents/seo/optimize, and the SEO audit built on it next
   reports every value it returns as a finding. Four measurement bugs were
   fixed:

     (1) alt="" and a missing alt both came out as "". They are opposite
         findings (decorative vs missing), so a missing alt is now alt null
         with has_alt false, and the optimize prompt says so in words
         (describeSeoImageAlt) instead of calling both "MISSING".
     (2) Attribute values were cut at the first quote of either kind, so
         content="Don't wait" was "Don". Now "..." may hold ', '...' may hold
         ", an unquoted value runs to whitespace or ">", and a ">" inside a
         quoted value does not end the tag.
     (3) Entities were not decoded, so "Tom &amp; Jerry" was reported as
         written. Now every value is decoded, named and numeric, with the
         entities package.
     (4) The title was the first <title> anywhere, an inline svg's included.
         Now it is the document's own, or null when there is none.

   The functions are taken out of server.js source and run in isolation, on
   local fixture HTML: no server, no database, no network. The old function is
   read from BEFORE, the commit before the fix, both to show each bug was real
   and to hold a plain page to exactly what it measured before.

   MUTATE=<name> undoes one part of a fix in the extracted source before it
   runs (nothing is written to server.js). MUTATE=all runs every mutation in
   its own process and passes only if every one of them fails.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const { execSync, spawnSync } = require("child_process");
const { decodeHTML, decodeHTMLAttribute } = require("entities");

const REPO = path.join(__dirname, "..");
const BEFORE = "7e8446d";
const MUTATE = process.env.MUTATE || "";

/* Each mutation is [exact anchor in server.js, replacement]. An anchor that is
   not found exactly once is itself a failure, so a mutation cannot silently
   stop biting. */
const MUTATIONS = {
  // (1) a missing alt reads "" again
  "alt-empty": [["alt: hasAlt ? seoCollapse(a.alt) : null,", "alt: hasAlt ? seoCollapse(a.alt) : \"\","]],
  // (1) the optimize prompt calls an empty alt and a missing one the same again
  "alt-reader": [["  if (!img.has_alt) return \"alt MISSING\";\n  if (img.alt === \"\") return \"alt=\\\"\\\" (empty: marked decorative)\";\n",
                  "  return \"alt=\\\"\" + (img.alt || \"MISSING\") + \"\\\"\";\n"]],
  // (2) a value is cut at the first quote of either kind again
  "quote-cut": [["(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))", "(?:[\"']([^\"']*)[\"']()|([^\\s>]+))"]],
  // (2) a ">" inside a quoted value ends the tag again
  "tag-cut": [["var SEO_TAG_ATTRS = \"(?:[^>=]|=\\\\s*\\\"[^\\\"]*\\\"|=\\\\s*'[^']*'|=(?!\\\\s*[\\\"']))*\";", "var SEO_TAG_ATTRS = \"[^>]*\";"]],
  // (3) text is not decoded
  "decode-text": [["return seoCollapse(decodeHTML(String(html)));", "return seoCollapse(String(html));"]],
  // (3) attribute values are not decoded
  "decode-attr": [["attrs[name] = decodeHTMLAttribute(value);", "attrs[name] = value;"]],
  // (3) attribute values are decoded a second time, as text
  "decode-twice": [["alt: hasAlt ? seoCollapse(a.alt) : null,", "alt: hasAlt ? seoText(a.alt) : null,"],
                   ["metas[i].content !== undefined ? seoCollapse(metas[i].content)", "metas[i].content !== undefined ? seoText(metas[i].content)"]],
  // (4) the first <title> anywhere is the title again
  "first-title": [["var m = (head && head[1].match(titleRe)) || doc.match(titleRe);", "var m = raw.match(titleRe);"]],
  // (4) an absent title reads "" again
  "title-empty": [["return m ? seoText(m[1]) : null;", "return m ? seoText(m[1]) : \"\";"]]
};

if (MUTATE === "all") {
  const names = Object.keys(MUTATIONS);
  let survived = 0;
  for (const name of names) {
    const r = spawnSync(process.execPath, [__filename], { env: Object.assign({}, process.env, { MUTATE: name }), encoding: "utf8", timeout: 120000 });
    const fails = (r.stdout.match(/^ {4}FAIL {2}.*$/gm) || []);
    const caught = r.status !== 0 && fails.length > 0;
    if (!caught) survived++;
    console.log((caught ? "    caught    " : "    SURVIVED  ") + name.padEnd(14) + " " + fails.length + " failing check(s)" +
      (fails.length ? "  e.g. " + fails[0].trim().slice(6, 110) : (r.stderr ? "  stderr: " + r.stderr.trim().split("\n")[0] : "")));
  }
  console.log(survived === 0 ? "\nALL CHECKS PASSED — every one of " + names.length + " mutations was caught" : "\nCHECKS FAILED: " + survived + " mutation(s) survived");
  process.exit(survived === 0 ? 0 : 1);
}

let failures = 0;
let passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}
function same(label, actual, expected) {
  const a = JSON.stringify(actual), e = JSON.stringify(expected);
  check(label, a === e, "got " + a + ", want " + e);
}

/* ── extraction ─────────────────────────────────────────────────────────── */
function braceEnd(src, open) {
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === "{") depth++;
    else if (src[i] === "}") { depth--; if (depth === 0) return i + 1; }
  }
  throw new Error("unbalanced braces");
}
function fnSource(src, name) {
  const m = new RegExp("^function " + name + "\\(", "m").exec(src);
  if (!m) throw new Error("function " + name + " not found");
  return src.slice(m.index, braceEnd(src, src.indexOf(") {", m.index) + 2));
}
function load(src, names, vars, label) {
  const parts = vars.map(function (n) {
    const m = new RegExp("^var " + n + " = .*;$", "m").exec(src);
    if (!m) throw new Error(label + ": var " + n + " not found");
    return m[0];
  }).concat(names.map(function (n) { return fnSource(src, n); }));
  const ctx = { decodeHTML: decodeHTML, decodeHTMLAttribute: decodeHTMLAttribute };
  vm.createContext(ctx);
  vm.runInContext(parts.join("\n") + "\nthis.extract = extractSeoPageData;" +
    (names.indexOf("describeSeoImageAlt") !== -1 ? " this.describe = describeSeoImageAlt;" : ""), ctx, { filename: label });
  return ctx;
}

let nowSrc = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [from, to] of edits) {
    if (nowSrc.split(from).length !== 2) { console.log("    FAIL  mutation anchor not found exactly once: " + from); process.exit(1); }
    nowSrc = nowSrc.split(from).join(to);
  }
  console.log("\n!! MUTATION: " + MUTATE);
}
const beforeSrc = execSync("git show " + BEFORE + ":server.js", { cwd: REPO, maxBuffer: 64 * 1024 * 1024 }).toString("utf8").replace(/\r\n/g, "\n");
const NOW = load(nowSrc, ["safeText", "seoTagAttributes", "seoTags", "seoCollapse", "seoText", "seoDocumentTitle", "extractSeoPageData", "describeSeoImageAlt"], ["SEO_TAG_ATTRS"], "server.js");
const OLD = load(beforeSrc, ["safeText", "extractSeoPageData"], [], "server.js@" + BEFORE);
function N(html) { return JSON.parse(JSON.stringify(NOW.extract(html))); }
function O(html) { return JSON.parse(JSON.stringify(OLD.extract(html))); }

/* ── (1) alt="" vs no alt vs alt="Logo" ─────────────────────────────────── */
console.log("\n══ 1. an empty alt and a missing alt are opposite findings ══");
{
  const html = "<html><head><title>Images</title></head><body>" +
    "<img src=\"a.png\" alt=\"\"><img src=\"b.png\"><img src=\"c.png\" alt=\"Logo\"><img src=d.png alt></body></html>";
  const imgs = N(html).imageAlts;
  same("1. alt=\"\" is present and empty", imgs[0], { src: "a.png", alt: "", has_alt: true });
  same("1. no alt attribute is absent: alt null, has_alt false", imgs[1], { src: "b.png", alt: null, has_alt: false });
  same("1. alt=\"Logo\" is Logo", imgs[2], { src: "c.png", alt: "Logo", has_alt: true });
  same("1. a bare alt with no value is present and empty", imgs[3], { src: "d.png", alt: "", has_alt: true });
  same("1. exactly four images", imgs.length, 4);
  same("1. the optimize prompt calls the empty alt decorative", NOW.describe(imgs[0]), "alt=\"\" (empty: marked decorative)");
  same("1. the optimize prompt calls the absent alt missing", NOW.describe(imgs[1]), "alt MISSING");
  same("1. the optimize prompt quotes a real alt", NOW.describe(imgs[2]), "alt=\"Logo\"");
  check("1. the optimize prompt never writes the empty and the absent alt the same way", NOW.describe(imgs[0]) !== NOW.describe(imgs[1]));
  const old = O(html).imageAlts;
  check("1. (the bug was real) BEFORE gave both the empty and the absent alt as \"\"", old[0].alt === "" && old[1].alt === "", JSON.stringify(old));
}

/* ── (2) quoting ────────────────────────────────────────────────────────── */
console.log("\n══ 2. an attribute value is read whole ══");
{
  const html = "<html><head><title>Quotes</title>" +
    "<meta name=\"description\" content=\"Don't wait\">" +
    "<meta name='keywords' content='Say \"hi\"'>" +
    "<link rel=canonical href=https://example.com/a?b=1>" +
    "</head><body><img src='q.png' alt='Say \"hi\"'><img src=\"r.png\" alt=\"Don't\"></body></html>";
  const d = N(html);
  same("2. content=\"Don't wait\" is Don't wait", d.metaDescription, "Don't wait");
  same("2. content='Say \"hi\"' is Say \"hi\"", d.metaKeywords, "Say \"hi\"");
  same("2. an unquoted href runs to \">\"", d.canonical, "https://example.com/a?b=1");
  same("2. alt='Say \"hi\"' is Say \"hi\"", d.imageAlts[0], { src: "q.png", alt: "Say \"hi\"", has_alt: true });
  same("2. alt=\"Don't\" is Don't", d.imageAlts[1], { src: "r.png", alt: "Don't", has_alt: true });
  const old = O(html);
  check("2. (the bug was real) BEFORE cut Don't wait to Don", old.metaDescription === "Don", old.metaDescription);

  const u = N("<html><head><title>U</title><meta name=description content=Unquoted-value>" +
    "<meta name=\"keywords\" content=\"a > b\"></head><body></body></html>");
  same("2. an unquoted content=Unquoted-value is Unquoted-value", u.metaDescription, "Unquoted-value");
  same("2. a \">\" inside a quoted value does not end the tag", u.metaKeywords, "a > b");
  const ws = N("<html><head><meta name=description content=first second></head><body></body></html>");
  same("2. an unquoted value stops at whitespace", ws.metaDescription, "first");

  const ld = N("<html><head><script type='application/ld+json'>{\"@type\":\"Organization\"}</script>" +
    "<script type=application/ld+json>{\"@type\":\"WebSite\"}</script><script>var x = 1;</script></head><body></body></html>");
  same("2. JSON-LD is found with a single-quoted and an unquoted type, and nothing else is", ld.structuredData, ["{\"@type\":\"Organization\"}", "{\"@type\":\"WebSite\"}"]);
  const firstWins = N("<html><head><meta name=\"description\" content=\"one\" content=\"two\"></head><body></body></html>");
  same("2. the first of a repeated attribute wins, as in a browser", firstWins.metaDescription, "one");

  // A tag that never closes, with many quoted values, still ends quickly.
  const t0 = Date.now();
  N("<html><head><meta " + "a=\"1\" ".repeat(5000) + "<img " + "b='2' ".repeat(5000));
  check("2. an unclosed tag with 10,000 quoted values is read in under 2 s", Date.now() - t0 < 2000, (Date.now() - t0) + " ms");
}

/* ── (3) entities ───────────────────────────────────────────────────────── */
console.log("\n══ 3. entities are decoded in every value ══");
{
  const ENC = "Tom &amp; Jerry &lt;3 &quot;Q&quot; it&#39;s caf&eacute;&#x2019;s&nbsp;best";
  const DEC = "Tom & Jerry <3 \"Q\" it's café’s best";
  const html = "<html><head><title>" + ENC + "</title>" +
    "<meta name=\"description\" content=\"" + ENC + "\">" +
    "<link rel=\"canonical\" href=\"https://example.com/?a=1&amp;b=2\"></head>" +
    "<body><h1>" + ENC + "</h1><h2><span>" + ENC + "</span></h2><img src=\"e.png\" alt=\"" + ENC + "\"><p>" + ENC + "</p></body></html>";
  const d = N(html);
  same("3. title", d.title, DEC);
  same("3. meta description", d.metaDescription, DEC);
  same("3. canonical", d.canonical, "https://example.com/?a=1&b=2");
  same("3. h1", d.headings.h1, [DEC]);
  same("3. h2 with markup inside", d.headings.h2, [DEC]);
  same("3. alt", d.imageAlts[0], { src: "e.png", alt: DEC, has_alt: true });
  same("3. body text", d.visibleText, DEC + " " + DEC + " " + DEC);
  same("3. an encoded tag in text stays text, not markup", N("<html><body><h3>&lt;b&gt;bold&lt;/b&gt;</h3></body></html>").headings.h3, ["<b>bold</b>"]);
  const twice = N("<html><head><title>&amp;amp;</title><meta name=\"description\" content=\"&amp;amp;\">" +
    "<link rel=\"canonical\" href=\"/?a=1&amp;amp;b\"></head><body><h4>&amp;amp;</h4><img alt=\"&amp;amp;\"><p>&amp;amp;</p></body></html>");
  same("3. decoded once, never twice: title, meta, canonical, heading, alt, body",
    [twice.title, twice.metaDescription, twice.canonical, twice.headings.h4[0], twice.imageAlts[0].alt, twice.visibleText],
    ["&amp;", "&amp;", "/?a=1&amp;b", "&amp;", "&amp;", "&amp; &amp;"]);
  const old = O(html);
  check("3. (the bug was real) BEFORE reported the title as written", old.title === ENC, old.title);
}

/* ── (4) the document's own title ───────────────────────────────────────── */
console.log("\n══ 4. the title is the document's own ══");
{
  const svgFirst = "<html><head><svg><title>Icon</title></svg><title>Real Title</title></head><body></body></html>";
  same("4. an inline svg's title before the real one is not the title", N(svgFirst).title, "Real Title");
  check("4. (the bug was real) BEFORE took the svg's title", O(svgFirst).title === "Icon", O(svgFirst).title);
  [["template", "<template><title>T</title></template>"], ["script", "<script>var s = \"<title>S</title>\";</script>"],
   ["style", "<style>/* <title>C</title> */</style>"], ["noscript", "<noscript><title>N</title></noscript>"],
   ["comment", "<!-- <title>Old</title> -->"], ["upper-case svg", "<SVG viewBox=\"0 0 1 1\"><TITLE>Icon</TITLE></SVG>"]].forEach(function (c) {
    same("4. a title inside " + c[0] + " before the real one is not the title",
      N("<html><head>" + c[1] + "<title>Real Title</title></head><body></body></html>").title, "Real Title");
  });
  same("4. an svg in the body does not displace the head's title",
    N("<html><head><title>Head</title></head><body><svg><title>Icon</title></svg></body></html>").title, "Head");
  same("4. a title only inside a comment gives null",
    N("<html><head><!-- <title>Old</title> --></head><body><p>hi</p></body></html>").title, null);
  same("4. a page with no <title> at all gives null",
    N("<html><head></head><body><p>hi</p></body></html>").title, null);
  same("4. a page whose only title is an svg's gives null",
    N("<html><head></head><body><svg><title>Icon</title></svg></body></html>").title, null);
  same("4. an empty <title></title> is present and empty, not absent",
    N("<html><head><title></title></head><body></body></html>").title, "");
  same("4. a document without <head> still has its title",
    N("<title>Bare</title><p>x</p>").title, "Bare");
}

/* ── a plain page measures exactly as before ────────────────────────────── */
console.log("\n══ 5. a page none of the four touch measures exactly as it did ══");
{
  const plain = "<!doctype html><html><head><title>Plain Page</title>" +
    "<meta name=\"description\" content=\"A plain description.\"><meta name=\"keywords\" content=\"one, two\">" +
    "<link rel=\"canonical\" href=\"https://example.com/plain\">" +
    "<script type=\"application/ld+json\">{\"@type\":\"Organization\"}</script></head>" +
    "<body><h1>Heading One</h1><h2>Two <em>A</em></h2><h2>Two B</h2><h3>Three</h3>" +
    "<img src=\"/a.png\" alt=\"First image\"><img src=\"/b.png\" alt=\"Second\">" +
    "<p>Some body   text.</p><script>var hidden = 1;</script><style>.x{}</style><!-- note --><p>More.</p></body></html>";
  const n = N(plain), o = O(plain);
  const nNoFlag = Object.assign({}, n, { imageAlts: n.imageAlts.map(function (i) { return { src: i.src, alt: i.alt }; }) });
  same("5. every field equal to BEFORE once has_alt is set aside", nNoFlag, o);
  same("5. and has_alt is true on both images", n.imageAlts.map(function (i) { return i.has_alt; }), [true, true]);
  same("5. the output keys are BEFORE's", Object.keys(n), Object.keys(o));
}

/* ── every reader of the output ─────────────────────────────────────────── */
console.log("\n══ 6. every reader of the output reads the new shape ══");
{
  const callers = nowSrc.match(/extractSeoPageData\(/g) || [];
  same("6. extractSeoPageData has one definition and one caller", callers.length, 2);
  const route = nowSrc.slice(nowSrc.indexOf("app.post(\"/api/agents/seo/optimize\""), nowSrc.indexOf("app.get(\"/api/agents/seo/optimize-count\""));
  check("6. the optimize route was found", route.length > 1000, route.length);
  check("6. the optimize route states each image through describeSeoImageAlt", /pageData\.imageAlts\.map\(function \(img, i\) \{\s*return \(i \+ 1\) \+ "\. " \+ describeSeoImageAlt\(img\);/.test(route));
  check("6. the optimize route reads img.alt nowhere else", (route.match(/img\.alt/g) || []).length === 0);
  check("6. a null title reads as MISSING in the prompt", /"Title tag: " \+ \(pageData\.title \|\| "MISSING"\)/.test(route));
}

console.log("\n" + passes + " passed, " + failures + " failed");
console.log(failures === 0 ? "ALL CHECKS PASSED" : "CHECKS FAILED");
process.exit(failures === 0 ? 0 : 1);
