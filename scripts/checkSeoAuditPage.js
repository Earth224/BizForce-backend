"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkSeoAuditPage — the SEO audit renders honestly on the SEO agent's page.

   Frontend 1d04b0c gave POST /api/agents/seo/audit its own renderer in
   scripts/agent-profile.js and a tool entry on agents/seo.html. This keeps
   that page honest. The frontend's agent-profile.js is run in vm with a
   stubbed DOM (the approach checkAgentCountCopy takes with the frontend), and
   its renderer is fed fixtures made by this repo's REAL measureSeoAudit and
   seoAuditFlags, lifted from server.js, run on fixture HTML. No browser, no
   network, no model, no database; nothing is written to either repo.

   WHAT THIS PROVES
     0. seo.html declares one tool, audit, with one required url field.
     A. Flags plus explanation, on a sitemapindex: flags first, then the
        explanation, measured, not measured, provenance; every flag's id, rule
        and evidence; chips that scroll to and highlight the flag or measured
        group they cite; "not checked" shown exactly, never as No; the seven
        measured groups; not measured open; provenance in the dashed panel.
     B. A real empty flags array: "No flags raised", once.
     C. explanation null: the amber panel with explanation_error verbatim, no
        model zone, the flags and measured block intact.
     D. points_dropped: the count, singular and plural.
     E. A client-rendered shell: the banner, above the flags, labelled a
        heuristic.
     F. A reached 404: F1 styled as an error; the HTML said to be unread.
     G. A 200 that is not a readable audit: "could not be read", never a pass.
     H. Through runTool with a stubbed fetch: the POST body; a 422's message
        unchanged with no result; a network failure with no result.
     I. Keyed seo/audit: the content agent's own "audit" keeps the generic
        renderer; an executive dispatch of seo/audit gets this one.
     R. Every other tool on every agent page renders byte-identically to
        BEFORE (the frontend commit before 1d04b0c), and BEFORE's styles are
        unchanged with only .ap-seo-* rules added. A deliberate change to the
        shared renderer will fail R: move BEFORE forward when that happens,
        or name it as [before, after] in RENDERER_CHANGES_SINCE_BEFORE, which
        is applied to BEFORE's source (the Storefront null rendering is).
     S. No recollection notice on a tool that never called a model: content/audit
        and store/stock-margin results (their flags read from their routes in
        server.js, stock-margin measured by the real measureStockAndMargin) and an
        ads/policy-check with no rewrites show none; a model tool still does, with
        the notice byte-identical to BEFORE's. A per-item boolean renders Yes / No,
        and a null still renders "—" with its reason, never No.
     And "No flags raised" appears only for the real empty arrays.

   MUTATE=<name> edits agent-profile.js IN MEMORY (the file on disk is never
   touched). MUTATE=all runs each in its own process and passes only if every
   one fails.

   BIZFORCE_FRONTEND_DIR overrides the frontend location (default: the
   BizForce-fronyend checkout beside this repo).
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), vm = require("vm"), path = require("path");
const { execSync, spawnSync } = require("child_process");
const { decodeHTML, decodeHTMLAttribute } = require("entities");
const s = require("./_shared");
const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const BEFORE = "8a47d80";
const MUTATE = process.env.MUTATE || "";
const MUT = require("./_shared");

const MUTATIONS = {
  // a response without a flags array is rendered as a clean page
  "empty-on-missing-flags": [["if (!isPlainObject(m) || !Array.isArray(data.flags)) {",
    "data.flags = data.flags || []; if (!isPlainObject(m)) {"]],
  // a sitemapindex's "not checked" is shown as No
  "sitemap-not-checked-as-no": [["renderScalarish(value) + '</div></div>';\n  }\n\n  function seoAuditGroup",
    "renderScalarish(value === \"not checked\" ? false : value) + '</div></div>';\n  }\n\n  function seoAuditGroup"]],
  // the renderer is keyed by the bare id, taking over content's audit too
  // (Demand signals on the R&D page: rd/demand-signals is registered beside it)
  "bare-audit-key": [["var TOOL_WHOLE_RENDERERS = { \"seo/audit\": renderSeoAudit, \"rd/demand-signals\": renderDemandSignals };",
    "var TOOL_WHOLE_RENDERERS = { \"audit\": renderSeoAudit, \"seo/audit\": renderSeoAudit, \"rd/demand-signals\": renderDemandSignals };"]],
  // a null explanation renders as nothing
  "blank-on-null-explanation": [["if (!Array.isArray(data.explanation)) {", "if (!Array.isArray(data.explanation)) { return \"\";"]],
  // not measured is collapsed
  // (Anchored on the audit's own label: the demand report, added in frontend
  // 3bbd299, uses the same list markup, and the bare line matched twice.)
  "collapse-not-measured": [["Not measured by this audit</div>' +\n      (items.length\n        ? '<ul class=\"ap-seo-nm-list\">'",
    "Not measured by this audit</div>' +\n      (items.length\n        ? '<details><ul class=\"ap-seo-nm-list\">'"]],
  // the client-rendered banner moves below the flags
  "banner-below-flags": [["      seoAuditShellBanner(m),\n      seoAuditUnreadPage(m),\n      seoAuditFlags(data.flags),",
    "      seoAuditUnreadPage(m),\n      seoAuditFlags(data.flags),\n      seoAuditShellBanner(m),"]],
  // an error flag looks like a guideline
  "error-as-guideline": [["var isError = f && f.basis === \"error\";", "var isError = false;"]],
  // the dropped-points count is hidden
  "hide-dropped": [["var droppedLine = dropped > 0", "var droppedLine = dropped > 5"]],
  // a chip scrolls to nothing
  "chip-goes-nowhere": [["var target = root.querySelector('[data-seo-flag=\"' + id + '\"]') ||", "var target = null &&"]],
  // one character in the shared generic renderer
  "touch-generic": [["'<div class=\"ap-zone-label\">Written by the model</div>' + parts.join(\"\") + '</div>';",
    "'<div class=\"ap-zone-label\">Written by the model.</div>' + parts.join(\"\") + '</div>';"]],
  // the recollection notice shows whether or not a model was called
  "notice-regardless-of-model": [["    if (prov.model_call_made === false || !inferred.length) return \"\";\n", ""]],
  // a null per-item value renders as No
  "null-as-no": [["      if (v === null || v === undefined) {\n        return \"<strong>\" + esc(humanise(k)) + \":</strong> \" + renderNullFor(k);\n      }\n",
    "      if (v === null || v === undefined) v = false;\n"]],
  // the named null rendering changes beyond what RENDERER_CHANGES_SINCE_BEFORE names
  "renderer-unnamed-change": [['      : "—";\n  }', '      : "-";\n  }']]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") MUT.runAllMutations(__filename, Object.keys(MUTATIONS));

let NEW_SRC = fs.readFileSync(path.join(FRONTEND, "scripts", "agent-profile.js"), "utf8").replace(/\r\n/g, "\n");
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [from, to] of edits) {
    NEW_SRC = MUT.replaceOnce(NEW_SRC, from, to, MUTATE);
  }
  console.log("\n!! MUTATION: " + MUTATE + " (agent-profile.js, in memory)");
}
const OLD_SRC_AT_BEFORE = execSync("git show " + BEFORE + ":scripts/agent-profile.js", { cwd: FRONTEND, maxBuffer: 64 << 20 }).toString("utf8").replace(/\r\n/g, "\n");

/* THE ONE DELIBERATE SHARED-RENDERER CHANGE SINCE BEFORE (frontend "The
   Storefront Agent's page says what it is and measures what you enter", Oct 13
   2026). A null inside an object used to print as the bare word "null"; it now
   prints "—", or "not measured — no limit entered" on a key that reports a
   limit check, and a null measured cell on such a key says the same. The
   keyword tool's suggested_tag_set_reason sits with the limits and standing
   statements, and .ap-not-measured is styled. Each [before, after] is applied
   to BEFORE's source and must match there exactly once; R and the style check
   then still demand byte-identity with that, so any other change to the shared
   renderer still fails. */
const RENDERER_CHANGES_SINCE_BEFORE = [
  ['    ".ap-m-val.bad{color:#fca5a5}.ap-m-val.good{color:#86efac}",\n',
   '    ".ap-m-val.bad{color:#fca5a5}.ap-m-val.good{color:#86efac}",\n    ".ap-not-measured{color:#8892b8;font-style:italic}",\n'],
  ['    "suggested_tag_set_note", "rules_checked"];', '    "suggested_tag_set_note", "suggested_tag_set_reason", "rules_checked"];'],
  ['  // A compact, depth-limited rendering of whatever a value happens to be.\n',
   '  /* A NULL ON A LIMIT CHECK IS A CHECK NOT MADE. A key that reports a limit\n' +
   '     being met or broken (fits…, within…, over…, exceeds…, ready…, …_ready,\n' +
   '     too_long…) is null when no limit was entered to check against, and it\n' +
   '     reads as exactly that — never as "No", 0 or the broken-limit colour, and\n' +
   '     never as the bare word "null". Read from the key\'s own wording, like the\n' +
   '     colouring in renderMeasured. Any other null is the ordinary "—". */\n' +
   '  var LIMIT_CHECK_KEY = /^(within|fits|over|exceeds|headline_within|ready)|_ready$|too_long/;\n' +
   '  function renderNullFor(key) {\n' +
   '    return LIMIT_CHECK_KEY.test(String(key || ""))\n' +
   '      ? \'<span class="ap-not-measured">not measured — no limit entered</span>\'\n' +
   '      : "—";\n' +
   '  }\n\n' +
   '  // A compact, depth-limited rendering of whatever a value happens to be.\n'],
  ['      var v = obj[k];\n      if (isPlainObject(v) || Array.isArray(v)) {',
   '      var v = obj[k];\n      if (v === null || v === undefined) {\n' +
   '        return "<strong>" + esc(humanise(k)) + ":</strong> " + renderNullFor(k);\n      }\n' +
   '      if (isPlainObject(v) || Array.isArray(v)) {'],
  ["        '<div class=\"ap-m-val' + cls + '\">' + renderScalarish(value) + '</div></div>');",
   "        '<div class=\"ap-m-val' + cls + '\">' + (value === null ? renderNullFor(key) : renderScalarish(value)) + '</div></div>');"],
  /* NAMED (frontend "No banner about a model on tools that never call one", Oct
     16 2026). BEFORE → AFTER: (1) the "Nothing was looked up" notice is drawn
     only when provenance.inferred_by_model is non-empty and model_call_made is
     not false; (2) a per-item boolean inside an object reads Yes / No instead
     of the literal true / false. Section S proves both against real results. */
  ['  function renderNothingRead(prov) {\n    if (!isPlainObject(prov)) return "";\n',
   '  function renderNothingRead(prov) {\n    if (!isPlainObject(prov)) return "";\n\n' +
   '    /* ONLY WHEN A MODEL WROTE PART OF THIS RESPONSE. The notice says what follows\n' +
   '       is the model\'s recollection, which is false of a tool that never called one\n' +
   '       (content/audit, store/stock-margin, a policy check with no rewrites). Read\n' +
   '       from provenance.inferred_by_model, which every tool\'s provenance carries:\n' +
   '       empty means nothing here was written by a model. model_call_made: false,\n' +
   '       where a route states it, also rules the notice out. */\n' +
   '    var inferred = Array.isArray(prov.inferred_by_model) ? prov.inferred_by_model : [];\n' +
   '    if (prov.model_call_made === false || !inferred.length) return "";\n'],
  ['        return "<strong>" + esc(humanise(k)) + ":</strong> " + renderScalarish(v);\n      }\n      return "<strong>" + esc(humanise(k)) + ":</strong> " + esc(String(v === "" ? "—" : v));',
   '        return "<strong>" + esc(humanise(k)) + ":</strong> " + renderScalarish(v);\n      }\n' +
   '      // A per-item yes/no reads as Yes or No, not true/false. A null never gets here: it is "—" above.\n' +
   '      if (typeof v === "boolean") {\n        return "<strong>" + esc(humanise(k)) + ":</strong> " + (v ? "Yes" : "No");\n      }\n' +
   '      return "<strong>" + esc(humanise(k)) + ":</strong> " + esc(String(v === "" ? "—" : v));']
];
const OLD_SRC = RENDERER_CHANGES_SINCE_BEFORE.reduce(function (src, pair, i) {
  const hits = src.split(pair[0]).length - 1;
  if (hits !== 1) {
    console.log("    FAIL  renderer change #" + (i + 1) + " since " + BEFORE + " must match BEFORE's source exactly once; found " + hits + ": " + JSON.stringify(pair[0].slice(0, 80)));
    process.exit(1);
  }
  const at = src.indexOf(pair[0]);
  return src.slice(0, at) + pair[1] + src.slice(at + pair[0].length);
}, OLD_SRC_AT_BEFORE);

let passes = 0, fails = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { fails++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}

/* ── the backend's real measurement, lifted ─────────────────────────────── */
const SRC = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
function closure(src, root) {
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
const bctx = { console, URL, decodeHTML, decodeHTMLAttribute };
vm.createContext(bctx);
vm.runInContext(closure(SRC, "this.api = { measureSeoAudit: measureSeoAudit, seoAuditFlags: seoAuditFlags, NOT_MEASURED: SEO_AUDIT_NOT_MEASURED, toolProvenance: toolProvenance, measureStockAndMargin: measureStockAndMargin };"), bctx);
const B = bctx.api;
const plain = v => JSON.parse(JSON.stringify(v));

const ORIGIN = "https://example.com";
function audit(html, opts) {
  opts = opts || {};
  const page = { ok: true, status: 200, url: ORIGIN + "/", chain: [{ url: ORIGIN + "/", status: 200 }], headers: {}, body: html };
  const robots = { url: ORIGIN + "/robots.txt", final_url: ORIGIN + "/robots.txt", status: 200, refusal: null,
    body: "User-agent: *\nDisallow:\nSitemap: " + ORIGIN + "/sitemap.xml\n" };
  const sitemap = { url: ORIGIN + "/sitemap.xml", final_url: ORIGIN + "/sitemap.xml", status: 200, refusal: null, source: "robots.txt",
    body: opts.index
      ? '<?xml version="1.0"?><sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>' + ORIGIN + '/a.xml</loc></sitemap></sitemapindex>'
      : '<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>' + ORIGIN + '/</loc></url></urlset>' };
  const measured = plain(B.measureSeoAudit(page, robots, sitemap));
  const flags = plain(B.seoAuditFlags(measured));
  return {
    success: true, url: ORIGIN + "/", measured, flags,
    explanation: opts.explanation === undefined ? null : opts.explanation,
    explanation_error: opts.explanation_error === undefined ? null : opts.explanation_error,
    points_dropped: opts.points_dropped || 0,
    not_measured: plain(B.NOT_MEASURED),
    provenance: plain(B.toolProvenance(["Measured A", "Measured B"], opts.explanation ? ["The explanation"] : [], "Only the HTML was read.",
      { model_call_made: true, page_text_sent_to_model: false })),
    task_id: "task-1", persisted: true
  };
}

const DESC = "A clear description of this example page that runs comfortably between seventy and one hundred sixty characters.";
const CLEAN = '<!doctype html><html lang="en"><head><title>Example page</title><meta name="description" content="' + DESC + '">' +
  '<meta name="viewport" content="width=device-width"><link rel="canonical" href="' + ORIGIN + '/"></head><body>' +
  '<h1>Example</h1><h2>Section</h2><p>' + "Plenty of visible text on this page. ".repeat(12) + '</p><img src="a.png" alt="A"><img src="b.png" alt=""></body></html>';
const FLAWED = '<!doctype html><html lang="en"><head><title>Flawed page</title><meta name="viewport" content="width=device-width"></head><body>' +
  '<h1>Top</h1><h3>Skipped "level"</h3><p>' + "Words enough to not be a shell. ".repeat(12) + '</p><img src="a.png"><img src="b.png" alt="B"></body></html>';
const SHELL = '<!doctype html><html lang="en"><head><title>App</title><meta name="viewport" content="width=device-width">' +
  '<meta name="description" content="' + DESC + '"></head><body><div id="root"></div><script src="/app.js"></script></body></html>';

/* ── load agent-profile.js in a fake page ───────────────────────────────── */
function fakeEl(id) {
  const el = { id, innerHTML: "", textContent: "", className: "", value: "", disabled: false, hidden: true,
    classList: { set: new Set(), add(c) { this.set.add(c); }, remove(c) { this.set.delete(c); }, contains(c) { return this.set.has(c); } } };
  return el;
}
function load(source, cfg, fetchImpl) {
  const els = new Map(), clicks = [], timers = [];
  const document = {
    head: { appendChild(n) { document._style = n; } },
    createElement() { return fakeEl(null); },
    addEventListener(type, fn) { if (type === "click") clicks.push(fn); },
    getElementById(id) { if (!els.has(id)) els.set(id, fakeEl(id)); return els.get(id); },
    querySelector() { return fakeEl(null); },
    querySelectorAll() { return []; }
  };
  const window = { AGENT_PROFILE_CONFIG: cfg };
  const ctx = { window, document, console, JSON, Object, Array, String, Number, Math, Date, RegExp, Promise, Error, TypeError,
    localStorage: { getItem() { return "check-token"; }, setItem() {} },
    fetch: fetchImpl || (() => Promise.reject(new Error("no fetch in this check"))),
    setTimeout(fn) { timers.push(fn); return timers.length; }, clearTimeout() {}, setInterval() { return 0; }, clearInterval() {} };
  const tail = '  document.addEventListener("DOMContentLoaded", inject);\n})();';
  const src = source.replace(/\r\n/g, "\n");
  if (src.lastIndexOf(tail) === -1) throw new Error("agent-profile.js tail not found");
  const exported = src.slice(0, src.lastIndexOf(tail)) +
    "  window.__ap = { renderToolResult: renderToolResult, toolsMarkup: toolsMarkup, runTool: runTool, TOOLS: TOOLS, toolDomId: toolDomId };\n" + tail;
  vm.createContext(ctx);
  vm.runInContext(exported, ctx);
  return { ap: window.__ap, document, els, clicks, timers, style: document._style ? document._style.textContent : "" };
}

function pageConfig(file) {
  const html = fs.readFileSync(file, "utf8");
  const m = html.match(/<script>\s*(window\.AGENT_PROFILE_CONFIG\s*=[\s\S]*?)<\/script>/);
  if (!m) return null;
  const w = {}; vm.runInNewContext(m[1], { window: w }); return w.AGENT_PROFILE_CONFIG;
}
const SEO_CFG = pageConfig(FRONTEND + "/agents/seo.html");
const seo = load(NEW_SRC, SEO_CFG);
const tool = seo.ap.TOOLS.find(t => t.id === "audit");
const render = data => seo.ap.renderToolResult(tool, data);
const NO_FLAGS = "No flags raised";
const count = (h, needle) => h.split(needle).length - 1;

(async function main() {
  console.log("\n══ 0. the page config ══");
  check("seo.html declares exactly one tool, id audit", seo.ap.TOOLS.length === 1 && !!tool, JSON.stringify(seo.ap.TOOLS.map(t => t.id)));
  check("its one field is url, required, type text", tool && tool.fields.length === 1 && tool.fields[0].name === "url" && tool.fields[0].required === true && tool.fields[0].type === "text");
  const markup = seo.ap.toolsMarkup();
  check("the tools section renders the url input and run button", /id="apTool_audit_f_url"/.test(markup) && /data-tool-run="audit"/.test(markup));

  /* A. flags plus explanation, on a sitemapindex */
  console.log("\n══ A. flags plus explanation (sitemapindex) ══");
  const A = audit(FLAWED, { index: true, explanation: [
    { priority: 1, point: "Add a meta description.", cites: ["F6", "meta_description"] },
    { priority: 2, point: "Do not skip from h1 to h3.", cites: ["F9"] }] });
  const ids = A.flags.map(f => f.id);
  check("fixture: the backend raised F6, F9, F16", ["F6", "F9", "F16"].every(i => ids.includes(i)), ids.join(","));
  const hA = render(A);
  check("rendered by the audit renderer", hA.startsWith('<div class="ap-seo-audit">'));
  const iFlags = hA.indexOf("ap-seo-flagzone"), iExpl = hA.indexOf("ap-generated"), iMeas = hA.indexOf("ap-measured"),
    iNM = hA.indexOf("Not measured by this audit"), iProv = hA.indexOf("ap-prov\"");
  check("order: flags, explanation, measured, not measured, provenance", iFlags > -1 && iFlags < iExpl && iExpl < iMeas && iMeas < iNM && iNM < iProv,
    [iFlags, iExpl, iMeas, iNM, iProv].join(","));
  A.flags.forEach(f => check(f.id + " shown with its id, rule and evidence (escaped)",
    hA.includes('data-seo-flag="' + f.id + '"') && hA.includes(esc(f.rule)) && hA.includes(esc(f.evidence))));
  check("F9's evidence keeps the heading text, escaped", hA.includes("&quot;Skipped &amp;quot;level&amp;quot;&quot;") || hA.includes("Skipped &amp;quot;level&amp;quot;") || hA.includes("Skipped &quot;level&quot;"));
  check("each point's text appears", hA.includes("Add a meta description.") && hA.includes("Do not skip from h1 to h3."));
  check("chips F6, meta_description, F9 are rendered", ["F6", "meta_description", "F9"].every(i => hA.includes('data-seo-cite="' + i + '"')));
  ["F6", "F9"].forEach(i => check("chip " + i + " has a flag to scroll to", hA.includes('data-seo-flag="' + i + '"')));
  check("chip meta_description has a measured group to scroll to", /data-seo-measure="[^"]*\bmeta_description\b/.test(hA));
  check("no 'No flags raised' with flags present", count(hA, NO_FLAGS) === 0);
  check("no dropped line when points_dropped is 0", !hA.includes("dropped for citing"));
  check("sitemap kind shown as sitemapindex", /Kind<\/div><div class="ap-m-val">sitemapindex/.test(hA));
  check("a sitemapindex's page_listed is 'not checked', exactly", /Page listed<\/div><div class="ap-m-val">not checked<\/div>/.test(hA));
  check("…and never as No", !/Page listed<\/div><div class="ap-m-val">No</.test(hA));
  ["Page", "Headings", "Images", "Links", "robots.txt", "Sitemap", "Structured data"].forEach(g =>
    check("measured group '" + g + "' present", hA.includes('<div class="ap-seo-group-title">' + esc(g) + '</div>')));
  check("measured figures in the monospace measured style", hA.includes('class="ap-m-val"') && hA.includes('class="ap-seo-mono"'));
  check("not_measured lists all " + A.not_measured.length + " items, not collapsed", A.not_measured.every(x => hA.includes("<li>" + esc(x) + "</li>")) && !/<details|hidden/.test(hA.slice(iNM, iProv)));
  check("provenance in the dashed panel, with the false flag as a chip", hA.includes('<div class="ap-prov">') && hA.includes("Page text sent to model: no"));
  check("guideline flags are not styled as errors", !hA.includes('class="ap-seo-flag error"'));
  check("no client-rendered banner on a page with content", !hA.includes("ap-seo-shell"));

  /* chip tap: drive the delegated handler against the rendered HTML */
  const handler = seo.clicks[seo.clicks.length - 1];
  function tapChip(html, id) {
    const target = fakeEl("t"); target.scrolled = null; target.scrollIntoView = o => { target.scrolled = o; };
    let asked = null;
    const root = { querySelector(sel) {
      asked = asked || [];
      asked.push(sel);
      const fm = sel.match(/^\[data-seo-flag="([^"]+)"\]$/), mm = sel.match(/^\[data-seo-measure~="([^"]+)"\]$/);
      if (fm && html.includes('data-seo-flag="' + fm[1] + '"')) return target;
      if (mm && new RegExp('data-seo-measure="[^"]*\\b' + mm[1] + '\\b').test(html)) return target;
      return null; } };
    const chip = { getAttribute() { return id; }, closest(sel) { return sel === ".ap-seo-audit" ? root : null; } };
    handler({ target: { closest(sel) { return sel === "[data-seo-cite]" ? chip : null; } } });
    return { target, asked };
  }
  const tap = tapChip(hA, "F9");
  check("tapping chip F9 scrolls to and highlights flag F9", tap.target.scrolled && tap.target.classList.contains("ap-seo-hit") && tap.asked[0] === '[data-seo-flag="F9"]', JSON.stringify(tap.asked));
  const tapM = tapChip(hA, "meta_description");
  check("tapping chip meta_description scrolls to its measured group", tapM.target.scrolled && tapM.target.classList.contains("ap-seo-hit"));
  seo.timers.splice(0).forEach(fn => fn());
  check("the highlight clears afterwards", !tap.target.classList.contains("ap-seo-hit"));

  /* B. an empty flags array */
  console.log("\n══ B. a real empty flags array ══");
  const Bd = audit(CLEAN, { explanation: [] });
  check("fixture: the backend raised no flags on the clean page", Bd.flags.length === 0, Bd.flags.map(f => f.id).join(","));
  const hB = render(Bd);
  check("'No flags raised' appears exactly once", count(hB, NO_FLAGS) === 1);
  check("no flag cards", !hB.includes("data-seo-flag="));
  check("an empty explanation says so, and is not blank", hB.includes("The model gave no point that cited anything measured"));
  check("urlset: page_listed is Yes", /Page listed<\/div><div class="ap-m-val">Yes/.test(hB));

  /* C. explanation null with explanation_error */
  console.log("\n══ C. explanation null ══");
  const ERR = "The explanation could not be generated (model overloaded). Everything measured and flagged above stands.";
  const Cd = audit(FLAWED, { explanation: null, explanation_error: ERR });
  const hC = render(Cd);
  check("amber panel carries explanation_error verbatim", hC.includes('<div class="ap-nothing-read"><strong>No explanation.</strong> ' + esc(ERR)));
  check("it says the measured results are complete without it", hC.includes("complete without it"));
  check("no generated (model) zone at all", !hC.includes("ap-generated"));
  check("flags and measured still render in full", hC.includes('data-seo-flag="F9"') && hC.includes("ap-measured"));
  check("no 'No flags raised'", count(hC, NO_FLAGS) === 0);
  const Cn = audit(CLEAN, { explanation: null, explanation_error: ERR });
  const hCn = render(Cn);
  check("explanation null on a clean page: amber panel AND the real 'No flags raised'", hCn.includes("No explanation.") && count(hCn, NO_FLAGS) === 1);

  /* D. points_dropped 2 */
  console.log("\n══ D. points_dropped 2 ══");
  const Dd = audit(FLAWED, { explanation: [{ priority: 1, point: "Fix the heading order.", cites: ["F9"] }], points_dropped: 2 });
  const hD = render(Dd);
  check("says 2 points were dropped for citing nothing measured", hD.includes("2 points were dropped for citing nothing that was measured."));
  const D1 = render(audit(FLAWED, { explanation: [{ priority: 1, point: "x", cites: ["F9"] }], points_dropped: 1 }));
  check("singular for 1", D1.includes("1 point was dropped"));

  /* E. client-rendered */
  console.log("\n══ E. appears_client_rendered true ══");
  const Ed = audit(SHELL, { explanation: [{ priority: 1, point: "Render server-side.", cites: ["F20"] }] });
  check("fixture: the backend judged it client-rendered and raised F20", Ed.measured.client_rendering.appears_client_rendered === true && Ed.flags.some(f => f.id === "F20"));
  const hE = render(Ed);
  const iShell = hE.indexOf("ap-seo-shell");
  check("banner present, above the flags", iShell > -1 && iShell < hE.indexOf("ap-seo-flagzone"));
  check("banner labelled a heuristic", /ap-seo-tag">Heuristic</.test(hE));
  check("banner says content checks could not be made", hE.includes("could not be made on it"));
  check("no 'No flags raised'", count(hE, NO_FLAGS) === 0);

  /* F. a page whose HTML was not read (a reached non-2xx) */
  console.log("\n══ F. a reached 404 ══");
  const Fp = { ok: false, status: 404, url: ORIGIN + "/", chain: [{ url: ORIGIN + "/", status: 404 }], headers: {}, body: "nope" };
  const Fm = plain(B.measureSeoAudit(Fp, { url: ORIGIN + "/robots.txt", status: 404, refusal: null, body: null }, { url: ORIGIN + "/sitemap.xml", status: 404, refusal: null, body: null, source: "default /sitemap.xml" }));
  const Fd = Object.assign(audit(CLEAN), { measured: Fm, flags: plain(B.seoAuditFlags(Fm)) });
  const hF = render(Fd);
  check("F1 is an error and styled as one", hF.includes('class="ap-seo-flag error" data-seo-flag="F1"'));
  check("says the HTML was not read, absent not zero", hF.includes("absent, not zero"));
  check("no 'No flags raised'", count(hF, NO_FLAGS) === 0);

  /* G. malformed 200s */
  console.log("\n══ G. a 200 that is not a readable audit ══");
  [["no flags key", { success: true, measured: A.measured }], ["flags not an array", { success: true, measured: A.measured, flags: null }],
   ["no measured", { success: true, flags: [] }], ["empty object", {}]].forEach(([n, d]) => {
    const h = render(d);
    check(n + ": shown as unreadable, no 'No flags', no measured block", h.includes("The audit could not be read") && count(h, NO_FLAGS) === 0 && !h.includes("ap-measured"));
  });

  /* H. 422 and network failure, through runTool */
  console.log("\n══ H. 422 and network failure ══");
  async function run(fetchImpl) {
    const env = load(NEW_SRC, SEO_CFG, fetchImpl);
    const t = env.ap.TOOLS[0];
    env.document.getElementById(env.ap.toolDomId("audit", "f_url")).value = "example.com";
    const result = env.document.getElementById(env.ap.toolDomId("audit", "result"));
    result.innerHTML = "STALE";
    env.ap.runTool(t);
    for (let i = 0; i < 20; i++) await new Promise(r => setImmediate(r));
    return { result, msg: env.document.getElementById(env.ap.toolDomId("audit", "msg")), sent: env.sent };
  }
  const MSG422 = "That address could not be reached, or is not one this server will fetch.";
  let sent = null;
  const r422 = await run((url, init) => { sent = { url, init }; return Promise.resolve({ ok: false, status: 422, json: () => Promise.resolve({ error: MSG422 }) }); });
  check("POSTs to /api/agents/seo/audit with {url}", sent && sent.url.endsWith("/api/agents/seo/audit") && sent.init.method === "POST" && sent.init.body === JSON.stringify({ url: "example.com" }), sent && sent.url + " " + sent.init.body);
  check("422: the server's message, unchanged", r422.msg.textContent === MSG422, r422.msg.textContent);
  check("422: shown as an error", r422.msg.className.includes("err"));
  check("422: no result rendered (no flags line, no measured)", r422.result.innerHTML === "");
  const rNet = await run(() => Promise.reject(new TypeError("Failed to fetch")));
  check("network failure: the error is shown", rNet.msg.textContent === "Failed to fetch" && rNet.msg.className.includes("err"), rNet.msg.textContent);
  check("network failure: no result rendered", rNet.result.innerHTML === "");
  const rBad = await run(() => Promise.resolve({ ok: true, status: 200, json: () => Promise.reject(new SyntaxError("bad")) }));
  check("unparseable 200: 'could not be read', no result", rBad.msg.textContent.includes("could not be read") && rBad.result.innerHTML === "");
  const rOk = await run(() => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(A) }));
  check("a 200 audit renders through runTool", rOk.result.innerHTML.startsWith('<div class="ap-seo-audit">') && rOk.msg.textContent === "");

  /* I. keying */
  console.log("\n══ I. the renderer is keyed seo/audit, not audit ══");
  const content = load(NEW_SRC, pageConfig(FRONTEND + "/agents/content.html"));
  const contentAudit = content.ap.TOOLS.find(t => t.id === "audit");
  check("content.html still has its own audit tool", !!contentAudit);
  check("content's audit does not get the SEO renderer", !content.ap.renderToolResult(contentAudit, A).includes("ap-seo-audit"));
  const exec = load(NEW_SRC, pageConfig(FRONTEND + "/executive-agent.html"));
  check("an executive dispatch of seo/audit gets the SEO renderer", exec.ap.renderToolResult({ id: "seo/audit", fields: [{ name: "url" }] }, A).startsWith('<div class="ap-seo-audit">'));

  check("across every fixture, 'No flags raised' appeared only for the real empty arrays (B and C-clean)",
    [hA, hC, hD, hE, hF].every(h => count(h, NO_FLAGS) === 0) && count(hB, NO_FLAGS) === 1 && count(hCn, NO_FLAGS) === 1);

  /* S. no recollection notice on a tool that never called a model; per-item yes/no */
  console.log("\n══ S. no model, no recollection notice; per-item Yes / No ══");
  const NOTICE = "Nothing was looked up.";
  // The flags each no-model route really sends, read from its own source in server.js.
  function routeFlags(route, anchor) {
    const at = SRC.indexOf('app.post("' + route + '"');
    const body = at === -1 ? "" : SRC.slice(at, s.braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("async function (req, res, next)", at))));
    const m = new RegExp("\\{\\s*\\n\\s*" + anchor + "[\\s\\S]*?\\}").exec(body);
    if (!m) return null;
    const fctx = { modelCallMade: false }; vm.createContext(fctx);
    return vm.runInContext("(" + m[0] + ")", fctx);
  }
  const auditFlags = routeFlags("/api/agents/content/audit", "model_call_made: false,");
  const stockFlags = routeFlags("/api/agents/store/stock-margin", "model_call_made: false,");
  const policyFlags = routeFlags("/api/agents/ads/policy-check", "model_call_made: modelCallMade,");
  check("S. the flags were read from the three routes, and each says model_call_made: false when no model ran",
    !!auditFlags && !!stockFlags && !!policyFlags && [auditFlags, stockFlags, policyFlags].every(f => f.model_call_made === false),
    JSON.stringify([auditFlags, stockFlags, policyFlags]));
  const notReadCount = f => Object.keys(f || {}).filter(k => f[k] === false && /(_read|_performed|_contacted|_checked|_reviewed)$/.test(k)).length;
  check("S. content/audit's flags hold three not-read flags, the shape that drew the notice", notReadCount(auditFlags) === 3, notReadCount(auditFlags));
  const genericTool = { id: "audit", fields: [{ name: "article" }, { name: "keyword" }] };
  const auditResult = { success: true, keyword: "k", measured: { word_count: 120, note: "n" },
    provenance: plain(B.toolProvenance(["Word count"], [], "No model call at all.", auditFlags)), task_id: "t", persisted: true };
  // Rendered on the Content agent's own page: on the SEO page "audit" is the SEO audit's whole renderer.
  const auditHtml = content.ap.renderToolResult(content.ap.TOOLS.find(t => t.id === "audit") || genericTool, auditResult);
  check("S. content/audit's result shows no recollection notice", auditHtml.indexOf(NOTICE) === -1 && auditHtml.indexOf("recollection") === -1, auditHtml.slice(0, 200));
  check("S. content/audit's result still renders its measured panel and provenance", /Measured by the server/.test(auditHtml) && /Where this came from/.test(auditHtml));

  const STORE_CFG = pageConfig(FRONTEND + "/store-agent.html");
  const store = load(NEW_SRC, STORE_CFG);
  const stockTool = store.ap.TOOLS.find(t => t.id === "stock-margin");
  const day0 = Date.now();
  const stockItems = [
    { id: "i1", name: "Widget", unit: "unit", quantity_on_hand: 10, unit_cost: 2.5, unit_price: 6, reorder_point: 12, status: "active" },
    { id: "i2", name: "Gizmo", unit: "unit", quantity_on_hand: 20, unit_cost: 1, unit_price: 3, reorder_point: 5, status: "active" },
    { id: "i3", name: "Gadget", unit: "unit", quantity_on_hand: 4, unit_cost: null, unit_price: 9.99, reorder_point: null, status: "active" }
  ];
  const stockMeasured = plain(B.measureStockAndMargin(stockItems, [], 30));
  const stockResult = { success: true, measured: stockMeasured, limitations: { not_measured: ["Sales revenue"], detail: "d" },
    provenance: plain(B.toolProvenance(["Items"], [], "Source: your own inventory entries. Model called: no.", stockFlags)), task_id: "t", persisted: true };
  const stockHtml = stockTool ? store.ap.renderToolResult(stockTool, stockResult) : "";
  check("S. store-agent.html declares Stock & Margin, rendered by the shared renderer", !!stockTool && stockHtml.length > 0);
  check("S. stock-margin's result (real measureStockAndMargin) shows no recollection notice", stockHtml.indexOf(NOTICE) === -1 && stockHtml.indexOf("recollection") === -1);
  check("S. at_or_below_reorder_point true renders Yes", /At or below reorder point:<\/strong> Yes/.test(stockHtml), (stockHtml.match(/At or below reorder point:<\/strong>[^<&]*/g) || []).join(" | "));
  check("S. at_or_below_reorder_point false renders No", /At or below reorder point:<\/strong> No/.test(stockHtml));
  check("S. no per-item value renders as the literal true or false", !/:<\/strong> (true|false)\b/.test(stockHtml), (stockHtml.match(/:<\/strong> (true|false)\b/g) || []).join(","));
  check("S. a null still renders as — with its reason beside it, never No",
    /At or below reorder point:<\/strong> — &middot; <strong>At or below reorder point reason:<\/strong> no reorder point entered/.test(stockHtml) &&
    (stockHtml.match(/At or below reorder point:<\/strong> No/g) || []).length === 1,
    (stockHtml.match(/At or below reorder point[^&]*/g) || []).join(" | "));

  const policyResult = { success: true, copy_length: 10, findings: [], suggested_rewrites: null, measured: { rules_checked: 5, rules_triggered: 0, note: "n" },
    provenance: plain(B.toolProvenance(["Every match"], [], "Deterministic.", Object.assign({}, policyFlags, { web_read: false, data_checked: false, x_reviewed: false }))) };
  check("S. a no-model response shows no notice even with three not-read flags (ads/policy-check flags plus three)",
    seo.ap.renderToolResult({ id: "policy-check", fields: [{ name: "copy" }] }, policyResult).indexOf(NOTICE) === -1);

  // A model tool keeps the notice, with exactly the text it had at BEFORE.
  const modelResult = { success: true, outline: "An outline.", measured: { sections: 4, note: "n" },
    provenance: plain(B.toolProvenance(["Section count"], ["The outline"], "The model wrote the outline.",
      { serp_read: false, competing_pages_read: false, search_volume_checked: false })), task_id: "t", persisted: true };
  const outlineTool = { id: "outline", fields: [{ name: "keyword" }] };
  const newModelHtml = seo.ap.renderToolResult(outlineTool, modelResult);
  const oldModelHtml = load(OLD_SRC_AT_BEFORE, SEO_CFG).ap.renderToolResult(outlineTool, modelResult);
  const noticeOf = h => { const i = h.indexOf('<div class="ap-nothing-read">'); return i === -1 ? "" : h.slice(i, h.indexOf("</div></div>", i) + 12); };
  check("S. a model tool's result still shows the notice", newModelHtml.indexOf(NOTICE) !== -1);
  check("S. and its notice is byte-identical to " + BEFORE + "'s", noticeOf(newModelHtml) !== "" && noticeOf(newModelHtml) === noticeOf(oldModelHtml), noticeOf(newModelHtml).slice(0, 200));
  check("S. a model tool that wrote nothing this time (inferred_by_model empty) shows no notice",
    seo.ap.renderToolResult(outlineTool, Object.assign({}, modelResult, { provenance: Object.assign({}, modelResult.provenance, { inferred_by_model: [] }) })).indexOf(NOTICE) === -1);

  /* R. regressions: every other tool on every page renders exactly as at BEFORE */
  console.log("\n══ R. every other tool, every page, against " + BEFORE + " ══");
  const pages = [];
  (function walk(dir) {
    fs.readdirSync(dir, { withFileTypes: true }).forEach(d => {
      const p = path.join(dir, d.name);
      if (d.isDirectory()) { if (!/^\.|node_modules/.test(d.name)) walk(p); }
      else if (d.name.endsWith(".html") && fs.readFileSync(p, "utf8").includes("AGENT_PROFILE_CONFIG")) pages.push(p);
    });
  })(FRONTEND);
  let toolCount = 0, compared = 0;
  pages.forEach(p => {
    let cfg;
    try { cfg = pageConfig(p); } catch (e) { check(path.relative(FRONTEND, p) + " config parses", false, e.message); return; }
    if (!cfg) return;
    const rel = path.relative(FRONTEND, p).replace(/\\/g, "/");
    /* Demand signals on the R&D page: an owner-only tool (adminOnly) is drawn
       later, after /api/auth/me, and has its own renderer — checked by
       checkDemandSignalsPage. Every other tool is compared as before. */
    const shared = Object.assign({}, cfg, { tools: (cfg.tools || []).filter(t => !t.adminOnly) });
    const o = load(OLD_SRC, shared), n = load(NEW_SRC, shared);
    const newTools = n.ap.TOOLS.filter(t => !(cfg.agentType === "seo" && t.id === "audit"));
    if (rel !== "agents/seo.html") check(rel + ": tools markup identical", o.ap.toolsMarkup() === n.ap.toolsMarkup());
    newTools.forEach(t => {
      toolCount++;
      const echo = {}; (t.fields || []).forEach(f => { echo[f.name] = "echoed"; });
      const fixtures = [
        Object.assign({ success: true, draft: "A draft.", measured: { within_limit: false, count: 3, over_limit: 2, nested: { a: 1 }, rows: [{ x: 1 }], note: "n" },
          provenance: { measured_from: ["a"], inferred_by_model: ["b"], caveat: "c", web_read: false, data_checked: false, x_reviewed: false },
          constraints: "rules", interpretation: "reading", ready_to_post: false, task_id: "t", persisted: false }, echo),
        A, Bd, Cd, {},
        { success: true, assignments: [{ id: 1, agent: "seo", tool: "seo/audit", task: "Audit", inputs: { url: "x" }, is_dispatchable: true }],
          execution_order: { can_start_now: [1] }, measured: { assignments: 1 }, task_id: "plan-1" }
      ];
      const same = fixtures.every(d => o.ap.renderToolResult(t, d) === n.ap.renderToolResult(t, d));
      compared += fixtures.length;
      check(rel + " · " + t.id + ": renders identically to " + BEFORE + " on 6 fixtures", same);
    });
  });
  const seoOld = load(OLD_SRC, SEO_CFG);
  const oldStyle = seoOld.style, newStyle = seo.style;
  // Demand signals on the R&D page added .ap-ds-* rules beside the .ap-seo-* ones.
  const removed = newStyle.replace(/\.ap-(?:seo|ds)-[^}]*\}/g, "");
  check("styles: " + BEFORE + "'s rules are all unchanged; only .ap-seo-* and .ap-ds-* rules were added", !/\.ap-(?:seo|ds)-/.test(oldStyle) && removed === oldStyle && newStyle.length > oldStyle.length);
  console.log("    (" + pages.length + " agent pages, " + toolCount + " other tools, " + compared + " renders compared)");

  console.log("\n" + (fails ? "CHECKS FAILED: " + fails + " of " + (passes + fails) : "ALL " + passes + " CHECKS PASSED"));
  process.exit(fails ? 1 : 0);
})().catch(e => { console.error("The check threw: " + (e && e.stack || e)); process.exit(1); });

function esc(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }
