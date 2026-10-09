"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkBlogSanitizer — the only defence in front of a public blog post.

   blogpost.html puts post.body into the page with innerHTML and does nothing
   else to it, so whatever sanitizeBlogHtml lets through runs in a visitor's
   browser on bizforceai.net. Two holes were found and closed:

     (a) Disallowed tags were removed in one pass and the result was never
         looked at again, so "<<b>img src=x onerror=alert(1)>" lost its <b>
         and came out as a live <img onerror>. Now every "<" and ">" the
         rebuild did not write itself is encoded.
     (b) blogSafeHref only looked at the second character of a relative href,
         so "/\evil.example" and "/<TAB>/evil.example" passed as paths on this
         site although a browser resolves both to https://evil.example/. Now a
         backslash, a control character or whitespace anywhere refuses it.

   The functions are taken out of server.js source and run in isolation (no
   server, no database, no network). Behaviour that must not change is checked
   against the same functions as they stand at b2ac83d, the commit before the
   fix, so "exactly as before" is measured, not typed in.

   MUTATE=<name> removes one guard from the extracted source before it runs
   (nothing is written to server.js). MUTATE=all runs every mutation in its own
   process and passes only if every one of them fails.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const { execSync, spawnSync } = require("child_process");

const REPO = path.join(__dirname, "..");
const BEFORE = "b2ac83d";
const MUTATE = process.env.MUTATE || "";

/* Each mutation is [exact anchor in server.js, replacement]. An anchor that is
   not found is itself a failure, so a mutation cannot silently stop biting. */
const MUTATIONS = {
  // (a) text between tags passes through unencoded again
  "encode-text": [[
    'const encodeText = function (text) { return text.replace(/</g, "&lt;").replace(/>/g, "&gt;"); };',
    'const encodeText = function (text) { return text; };'
  ]],
  // (a) only ">" stays encoded
  "encode-lt": [[
    'return text.replace(/</g, "&lt;").replace(/>/g, "&gt;"); };',
    'return text.replace(/>/g, "&gt;"); };'
  ]],
  // (a) only "<" stays encoded
  "encode-gt": [[
    'return text.replace(/</g, "&lt;").replace(/>/g, "&gt;"); };',
    'return text.replace(/</g, "&lt;"); };'
  ]],
  // (b) the whole new href guard
  "href-guard": [["if (/[\\\\\\x00-\\x20\\x7f]/.test(v)) return null;", ""]],
  // (b) backslash allowed again, controls still refused
  "href-backslash": [["if (/[\\\\\\x00-\\x20\\x7f]/.test(v)) return null;", "if (/[\\x00-\\x20\\x7f]/.test(v)) return null;"]],
  // (b) controls and whitespace allowed again, backslash still refused
  "href-controls": [["if (/[\\\\\\x00-\\x20\\x7f]/.test(v)) return null;", "if (/[\\\\]/.test(v)) return null;"]],
  // (b) DEL allowed again
  "href-del": [["if (/[\\\\\\x00-\\x20\\x7f]/.test(v)) return null;", "if (/[\\\\\\x00-\\x20]/.test(v)) return null;"]],
  // the href is judged without decoding its entities
  "decode": [["blogSafeHref(normalizeBlogHref(decodeBlogAttr(value),", "blogSafeHref(normalizeBlogHref(value,"]]
};

if (MUTATE === "all") {
  const names = Object.keys(MUTATIONS);
  let survived = 0;
  for (const name of names) {
    const r = spawnSync(process.execPath, [__filename], { env: Object.assign({}, process.env, { MUTATE: name }), encoding: "utf8", timeout: 120000 });
    const fails = (r.stdout.match(/^ {4}FAIL {2}.*$/gm) || []);
    const caught = r.status !== 0 && fails.length > 0;
    if (!caught) survived++;
    console.log((caught ? "    caught    " : "    SURVIVED  ") + name.padEnd(16) + " " + fails.length + " failing check(s)" +
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
  if (!m) return null;
  return src.slice(m.index, braceEnd(src, src.indexOf(") {", m.index) + 2));
}
function constSource(src, name) {
  const m = new RegExp("^const " + name + " = .*;$", "m").exec(src);
  if (!m) throw new Error("const " + name + " not found");
  return m[0];
}
function load(src, label) {
  const parts = ["BLOG_ALLOWED_TAGS", "BLOG_DROP_WITH_CONTENT", "BLOG_HREF_UUID", "BLOG_HREF_BARE_SLUG"].map(function (n) { return constSource(src, n); });
  ["toListingSlugSet", "normalizeBlogHref", "blogSafeHref", "decodeBlogAttr", "sanitizeBlogHtml"].forEach(function (n) {
    const s = fnSource(src, n);
    if (s) parts.push(s);
    else if (n !== "decodeBlogAttr") throw new Error(label + ": function " + n + " not found");
  });
  const ctx = {};
  vm.createContext(ctx);
  vm.runInContext(parts.join("\n") + "\nthis.sanitize = sanitizeBlogHtml; this.safeHref = blogSafeHref;", ctx, { filename: label });
  return ctx;
}

let nowSrc = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [from, to] of edits) {
    if (nowSrc.indexOf(from) === -1) { console.log("    FAIL  mutation anchor not found: " + from); process.exit(1); }
    nowSrc = nowSrc.split(from).join(to);
  }
  console.log("\n!! MUTATION: " + MUTATE);
}
const beforeSrc = execSync("git show " + BEFORE + ":server.js", { cwd: REPO, maxBuffer: 64 * 1024 * 1024 }).toString("utf8").replace(/\r\n/g, "\n");
const NOW = load(nowSrc, "server.js");
const OLD = load(beforeSrc, "server.js@" + BEFORE);

const HANDLE = "earth-rose";
const SLUGS = ["virtual-wellness-coaching"];
function S(html, external) { return NOW.sanitize(html, HANDLE, SLUGS, !!external); }
function O(html, external) { return OLD.sanitize(html, HANDLE, SLUGS, !!external); }
const TAB = "\t", NL = "\n", BS = "\\";

// The one property hole (a) broke: every "<" in the output opens a tag the
// rebuild wrote, from the allow list, in exactly the shape it writes them.
const REBUILT = /^<(?:\/?(?:h2|h3|p|ul|ol|li|strong|em|a)>|a href="[^"<>]*">)/;
function onlyRebuiltTags(out) {
  for (let i = out.indexOf("<"); i !== -1; i = out.indexOf("<", i + 1)) {
    if (!REBUILT.test(out.slice(i))) return "stray '<' at " + i + ": " + JSON.stringify(out.slice(i, i + 40));
  }
  // and every ">" closes one of those tags
  const stripped = out.replace(/<(?:\/?(?:h2|h3|p|ul|ol|li|strong|em|a)|a href="[^"<>]*")>/g, "");
  if (stripped.indexOf(">") !== -1) return "stray '>' in " + JSON.stringify(stripped.slice(Math.max(0, stripped.indexOf(">") - 30), stripped.indexOf(">") + 10));
  return null;
}
function exact(label, input, want, external) {
  const got = S(input, external);
  check(label + "  →  " + JSON.stringify(want), got === want, "got " + JSON.stringify(got));
  const stray = onlyRebuiltTags(got);
  check(label + " — only rebuilt tags in the output", stray === null, stray);
}

/* ── 1. hole (a): tags spliced together by a removal ────────────────────── */
console.log("\n══ 1. a removed tag cannot splice a new one together ══");
exact("<<b>img src=x onerror=alert(1)>", "<<b>img src=x onerror=alert(1)>", "&lt;img src=x onerror=alert(1)&gt;");
check("  … and contains no <img and no live onerror attribute", !/<img/i.test(S("<<b>img src=x onerror=alert(1)>")) && !/<[^>]*onerror/i.test(S("<<b>img src=x onerror=alert(1)>")));
exact("<</p>img src=x onerror=alert(1)>", "<</p>img src=x onerror=alert(1)>", "&lt;</p>img src=x onerror=alert(1)&gt;");
exact("<<em>svg/onload=alert(1)>", "<<em>svg/onload=alert(1)>", "&lt;<em>svg/onload=alert(1)&gt;");
exact("<im<b>g src=x onerror=alert(1)>", "<im<b>g src=x onerror=alert(1)>", "g src=x onerror=alert(1)&gt;");
exact("<<div><div>img src=x onerror=alert(1)>", "<<div><div>img src=x onerror=alert(1)>", "&lt;img src=x onerror=alert(1)&gt;");
exact("unclosed <img at the end", "<p>ok</p><img src=x onerror=alert(1)", "<p>ok</p>&lt;img src=x onerror=alert(1)");
exact("unclosed comment", "<p>a</p><!--<img src=x onerror=alert(1)>", "<p>a</p>&lt;!--");
exact("<!doctype> and <? ?> are text", "<!doctype html><?php x ?>", "&lt;!doctype html&gt;&lt;?php x ?&gt;");
exact("a literal comparison in prose", "<p>3 < 5 and 7 > 2</p>", "<p>3 &lt; 5 and 7 &gt; 2</p>");

console.log("\n══ 2. script cannot be reassembled ══");
for (const input of [
  "<scr<script>ipt>alert(1)</script>",
  "<scr<script></script>ipt>alert(1)</script>",
  "<scr<scr<script>ipt>ipt>alert(1)</script>",
  "<sc<script>ript src=//evil.example/x.js></sc<script>ript>",
  "<SCRIPT>alert(1)</SCRIPT>",
  "<script\n>alert(1)</script\n>",
  "<<script>script>alert(1)<</script>/script>"
]) {
  const got = S(input);
  check(JSON.stringify(input) + " → no <script  [" + JSON.stringify(got) + "]", !/<\s*script/i.test(got));
  const stray = onlyRebuiltTags(got);
  check(JSON.stringify(input) + " — only rebuilt tags in the output", stray === null, stray);
}
exact("<scr<script>ipt>alert(1)</script> exactly", "<scr<script>ipt>alert(1)</script>", "&lt;scr");

/* ── 3. schemes ──────────────────────────────────────────────────────────── */
console.log("\n══ 3. only / and http(s) hrefs survive ══");
exact("javascript:", '<a href="javascript:alert(1)">x</a>', "<a>x</a>");
exact("JaVaScRiPt:", '<a href="JaVaScRiPt:alert(1)">x</a>', "<a>x</a>");
exact("  javascript: with leading space", '<a href=" javascript:alert(1)">x</a>', "<a>x</a>");
exact("data:", '<a href="data:text/html,<script>alert(1)</script>">x</a>', "<a>x</a>");
exact("vbscript:", '<a href="vbscript:msgbox(1)">x</a>', "<a>x</a>");
exact("entity-encoded javascript:", '<a href="&#106;avascript:alert(1)">x</a>', "<a>x</a>");
exact("java<TAB>script:", '<a href="java' + TAB + 'script:alert(1)">x</a>', "<a>x</a>");
exact("single-quoted javascript:", "<a href='javascript:alert(1)'>x</a>", "<a>x</a>");
exact("unquoted javascript:", "<a href=javascript:alert(1)>x</a>", "<a>x</a>");

/* ── 4. hole (b): host-naming spellings of a path ───────────────────────── */
console.log("\n══ 4. nothing that resolves off-site passes as a path ══");
const OFFSITE = [
  ["/\\evil.example", "/" + BS + "evil.example"],
  ["/<TAB>/evil.example", "/" + TAB + "/evil.example"],
  ["/<NEWLINE>/evil.example", "/" + NL + "/evil.example"],
  ["/<CR>/evil.example", "/\r/evil.example"],
  ["\\\\evil.example", BS + BS + "evil.example"],
  ["//evil.example", "//evil.example"],
  ["/&#x2f;evil.example (entity slash)", "/&#x2f;evil.example"],
  ["/&#92;evil.example (entity backslash)", "/&#92;evil.example"],
  ["/&#9;/evil.example (entity tab)", "/&#9;/evil.example"],
  ["/<NUL>/evil.example", "/\u0000/evil.example"],
  ["/<DEL>/evil.example", "/\u007f/evil.example"],
  ["/blog/<SPACE>x", "/blog/ x"],
  ["https:\\\\evil.example", "https:" + BS + BS + "evil.example"]
];
for (const [label, href] of OFFSITE) {
  exact('href="' + label + '"', '<a href="' + href + '">x</a>', "<a>x</a>");
  check('blogSafeHref("' + label + '") after decoding is null', NOW.safeHref(href.replace(/&#x2f;/g, "/").replace(/&#92;/g, BS).replace(/&#9;/g, TAB)) === null);
}
// what the browser would have done with them before the fix
for (const [label, href] of OFFSITE.slice(0, 3)) {
  const was = OLD.safeHref(href);
  check('  (at ' + BEFORE + ' "' + label + '" passed and resolved off-site: ' + (was ? new URL(was, "https://bizforceai.net/blog/earth-rose/p").host : "refused") + ")",
    was !== null && new URL(was, "https://bizforceai.net/blog/earth-rose/p").host === "evil.example");
}

/* ── 5. real links are unchanged ─────────────────────────────────────────── */
console.log("\n══ 5. real links come out exactly as before ══");
const SUPPRESSED = '<a href="/suppressed.html?ref=bl-155031367a">what BizForce AI does for businesses the ad networks won\'t serve</a>';
check("the live suppressed.html anchor is byte-identical", S(SUPPRESSED) === SUPPRESSED, S(SUPPRESSED));
const SAME = [
  ["https URL", '<a href="https://example.com/x">x</a>', false],
  ["http URL", '<a href="http://example.com/x?a=1">x</a>', false],
  ["root-relative /listing", '<a href="/listing/virtual-wellness-coaching">x</a>', false],
  ["root-relative /blog", '<a href="/blog/earth-rose/how-does-virtual-wellness-coaching-work">x</a>', false],
  ["bare blog slug", '<a href="how-does-virtual-wellness-coaching-work">x</a>', false],
  ["bare listing slug", '<a href="virtual-wellness-coaching">x</a>', false],
  ["bare uuid", '<a href="0f8fad5b-d9cb-469f-a165-70867728950e">x</a>', false],
  ["bare slug on an external post", '<a href="how-does-x-work">x</a>', true],
  ["/blog on an external post", '<a href="/blog/earth-rose/x">x</a>', true],
  ["https on an external post", '<a href="https://client.example/page">x</a>', true],
  ["href with surrounding spaces", '<a href="  /listing/x  ">x</a>', false],
  ["two hrefs, last valid wins", '<a href="/a" href="/b">x</a>', false]
];
for (const [label, html, ext] of SAME) {
  const was = O(html, ext), now = S(html, ext);
  check(label + " — same as " + BEFORE + "  →  " + JSON.stringify(now), now === was, "before " + JSON.stringify(was) + " now " + JSON.stringify(now));
}
exact("bare slug is repaired to /blog/<handle>/", '<a href="how-to-x">x</a>', '<a href="/blog/earth-rose/how-to-x">x</a>');
exact("bare uuid is repaired to /listing/", '<a href="0f8fad5b-d9cb-469f-a165-70867728950e">x</a>', '<a href="/listing/0f8fad5b-d9cb-469f-a165-70867728950e">x</a>');
exact("https URL", '<a href="https://example.com/x">x</a>', '<a href="https://example.com/x">x</a>');
// The one deliberate difference from b2ac83d: an href written with &amp; (which is
// how the rebuild itself writes &) used to come out as &amp;amp; — a broken link
// and a sanitizer that changed its own output. It now stays as written.
exact("an &amp; in an href is kept, not doubled", '<a href="https://example.com/x?a=1&amp;b=2">x</a>', '<a href="https://example.com/x?a=1&amp;b=2">x</a>');
check("  (at " + BEFORE + " it was doubled to &amp;amp;)", O('<a href="https://example.com/x?a=1&amp;b=2">x</a>') === '<a href="https://example.com/x?a=1&amp;amp;b=2">x</a>');

/* ── 6. tags and attributes ─────────────────────────────────────────────── */
console.log("\n══ 6. the allow list ══");
const ALL = "<h2>a</h2><h3>b</h3><p>c <strong>d</strong> <em>e</em> <a href=\"/f\">f</a></p><ul><li>g</li></ul><ol><li>h</li></ol>";
exact("every allowed tag survives", ALL, ALL);
exact("upper-case allowed tags are lower-cased", "<P>x</P><H2>y</H2>", "<p>x</p><h2>y</h2>");
exact("on* on an anchor is dropped", '<a href="/ok" onclick="alert(1)" ONMOUSEOVER="x">x</a>', '<a href="/ok">x</a>');
exact("style on an anchor is dropped", '<a href="/ok" style="position:fixed;inset:0">x</a>', '<a href="/ok">x</a>');
exact("on* and style on a p are dropped", '<p style="x" onmouseover="alert(1)">x</p>', "<p>x</p>");
exact("disallowed tags go, their text stays", "<div><span>x</span></div><b>y</b>", "xy");
exact("script, style, iframe go with their contents", "<p>a<script>alert(1)</script>b<style>p{}</style>c<iframe src=x></iframe>d</p>", "<p>abcd</p>");
exact("a quoted '>' inside an attribute cannot open a tag", '<p title="<img src=x onerror=alert(1)>">x</p>', '<p>"&gt;x</p>');
exact("an href with a quote cannot break out", '<a href=\'/x" onmouseover="alert(1)\'>x</a>', "<a>x</a>");

/* ── 7. idempotence ─────────────────────────────────────────────────────── */
console.log("\n══ 7. sanitizing the output again changes nothing ══");
const SAMPLES = [ALL, SUPPRESSED, "<<b>img src=x onerror=alert(1)>", "<scr<script>ipt>alert(1)</script>",
  '<a href="https://example.com/x?a=1&amp;b=2&c=3">x</a>', '<a href="/x?q=a&quot;b">x</a>', "<p>3 < 5 &amp; 7 > 2 &lt;b&gt;</p>",
  '<a href="how-to-x">x</a>', '<a href="0f8fad5b-d9cb-469f-a165-70867728950e">x</a>', '<a href="/' + BS + 'evil.example">x</a>',
  "<p>a</p><!--<img src=x onerror=alert(1)>", '<a href="/x?a=&#38;b">x</a>'];
for (const s of SAMPLES) {
  const once = S(s), twice = S(once);
  check("idempotent: " + JSON.stringify(s).slice(0, 70), once === twice, JSON.stringify(once) + " → " + JSON.stringify(twice));
}

console.log("\n" + passes + " passed, " + failures + " failed");
console.log(failures === 0 ? "ALL CHECKS PASSED" : "CHECKS FAILED: " + failures);
process.exit(failures === 0 ? 0 : 1);
