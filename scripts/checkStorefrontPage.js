"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkStorefrontPage — the Storefront Agent's page says what it is and
   measures what you enter.

   Frontend "The Storefront Agent's page says what it is and measures what you
   enter" renamed the Etsy agent's page and cards to "Storefront Agent", gave
   its keyword tool the two seller-entered limits the backend accepts
   (max_tags, max_tag_length; backend 5338fe5), rewrote the page's Termaximus
   tips to what the page offers, and taught agent-profile.js's shared renderer
   that a null on a limit check means "not measured", not "No", 0 or "null".

   The pages run in jsdom from the frontend checkout. etsy-agent.html runs with
   the real scripts/agent-profile.js inlined, every fetch answered here; the
   keyword tool is filled in and run, and the stubbed answer is the backend's
   own no-limits shape. No network, no model call, no database.

   WHAT THIS PROVES
     1. No user-visible "Etsy" on etsy-agent.html (as rendered, with the tool
        forms built), agents-hub.html, index.html, or in this page's
        Termaximus tips; the tips name only what the page offers and none of
        "Shop Goals", "competitor analysis", API keys or connections.
     2. The <title>, the <h1>, agentLabel (the launcher heading) and the hub
        card read "Storefront Agent"; the hub role reads "Storefront Growth".
     3. The keyword tool has both inputs, each a number input whose label's
        for= names it, with the backend's ranges and help text; the page says
        no "20-character". A blank limit is not sent; an entered one is sent
        as a JSON number.
     4. A no-limits result (fits_tag, over_tag_limit_by, tag_ready and
        too_long_for_a_tag all null, suggested_tag_set null) renders each null
        as "not measured — no limit entered", never false, No, 0, "null" or
        the broken-limit colour, and shows suggested_tag_set_reason.

   MUTATE=<name> edits the frontend files IN MEMORY. MUTATE=all runs each in
   its own process and passes only if every one fails at least one check. A
   mutation whose search text does not match exactly once is an ERROR.

   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm");
const { JSDOM, VirtualConsole } = require("jsdom");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const PAGE = "etsy-agent.html", HUB = "agents-hub.html", INDEX = "index.html", AP = "scripts/agent-profile.js", GUIDE = "scripts/termaximus-guide.js";

const MUTATIONS = {
  // the page heading says Etsy Agent again
  "restore-etsy-h1": [[PAGE, '<h1 class="agent-title">Storefront Agent</h1>', '<h1 class="agent-title">Etsy Agent</h1>']],
  // the keyword tool claims Etsy's 20-character limit again
  "restore-20-char-description": [[PAGE,
    '"description": "Keyword candidates for your listing. Enter your platform\'s tag limits to see which ones fit; leave them blank and nothing is measured against a limit.",',
    '"description": "Etsy-shaped keyword candidates, each measured against the 20-character tag limit.",']],
  // a null fits_tag renders as "No"
  "null-fits-as-no": [[AP, '        return "<strong>" + esc(humanise(k)) + ":</strong> " + renderNullFor(k);',
    '        return "<strong>" + esc(humanise(k)) + ":</strong> " + (/^fits/.test(k) ? "No" : renderNullFor(k));']]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

const FILES = {};
[PAGE, HUB, INDEX, AP, GUIDE].forEach(f => {
  const p = path.join(FRONTEND, f);
  if (!fs.existsSync(p)) { console.error("Frontend file not found: " + p + " (set BIZFORCE_FRONTEND_DIR)."); process.exit(1); }
  FILES[f] = fs.readFileSync(p, "utf8").replace(/\r\n/g, "\n");
});
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE);
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}

/* What a person can read: the title, the text outside script/style/template,
   and the attributes that are shown or spoken. */
function visibleText(doc) {
  const body = doc.body.cloneNode(true);
  body.querySelectorAll("script, style, template, noscript").forEach(n => n.remove());
  const attrs = [];
  doc.querySelectorAll("[alt], [title], [placeholder], [aria-label]").forEach(el => {
    ["alt", "title", "placeholder", "aria-label"].forEach(a => { if (el.hasAttribute(a)) attrs.push(el.getAttribute(a)); });
  });
  return [doc.title, body.textContent, attrs.join(" ")].join("\n");
}
function staticDoc(file) { return new JSDOM(FILES[file]).window.document; }

/* The backend's no-limits answer (backend 5338fe5, checkStorefrontKeywordLimits case a). */
const NO_LIMITS = {
  success: true, seed: "wool hat",
  constraints: { max_tags: null, max_tag_length: null, source: "seller_supplied", verified_against_platform: false },
  keywords: [
    { keyword: "wool beanies", length: 12, fits_tag: null, over_tag_limit_by: null, word_count: 2, intent: "buyer", rationale: "names the product" },
    { keyword: "warm wool hat", length: 13, fits_tag: null, over_tag_limit_by: null, word_count: 3, intent: "gift", rationale: "the gift angle" }
  ],
  suggested_tag_set: null,
  counts: { suggested: 2, tag_ready: null, too_long_for_a_tag: null },
  provenance: { measured_from: ["Character length of every suggested keyword", "Word counts"], inferred_by_model: ["The keyword suggestions themselves"],
    external_data_sources_read: [], caveat: "BizForce reads no marketplace API and has no search-volume data.",
    marketplace_api_used: false, search_volume_data: false,
    limits_note: "Limits are as you entered them; BizForce did not check them against your platform." },
  suggested_tag_set_reason: "No tag set was built because you did not enter max_tags or max_tag_length. Enter both your platform's tag count and tag length to get one.",
  task_id: "task-1", persisted: true
};

async function loadPage() {
  // The page's own scripts, with agent-profile.js inlined where the page loads it; the session and guide scripts are left out.
  let html = FILES[PAGE]
    .replace(/<script src="\/scripts\/agent-profile\.js"><\/script>/, () => "<script>" + FILES[AP] + "</script>")
    .replace(/<script src="\/scripts\/[a-z-]+\.js"><\/script>/g, "");
  const seen = { posts: [], errors: [] };
  const virtualConsole = new VirtualConsole();
  virtualConsole.on("jsdomError", e => seen.errors.push(String(e && e.message || e).split("\n")[0]));
  const reply = (status, body) => ({ ok: status >= 200 && status < 300, status, json: () => Promise.resolve(body), text: () => Promise.resolve(JSON.stringify(body)) });
  const dom = new JSDOM(html, {
    url: "https://bizforce.test/etsy-agent.html", runScripts: "dangerously", pretendToBeVisual: true, virtualConsole,
    beforeParse(window) {
      window.localStorage.setItem("bf_token", "check-token");
      window.alert = () => {}; window.confirm = () => false;
      window.fetch = (url, opts) => {
        const route = String(url).replace(/^https?:\/\/[^/]+/, "").split("?")[0];
        if (route === "/api/agents/etsy/keyword-research" && opts && opts.method === "POST") {
          seen.posts.push(JSON.parse(opts.body));
          return Promise.resolve(reply(200, NO_LIMITS));
        }
        return Promise.resolve(reply(404, {}));
      };
    }
  });
  await new Promise(r => setTimeout(r, 300));
  return { dom, doc: dom.window.document, seen };
}
const settle = () => new Promise(r => setTimeout(r, 100));

(async function main() {
  const { dom, doc, seen } = await loadPage();
  const pageText = visibleText(doc);

  /* ── 1. no Etsy anywhere a person reads ───────────────────────────────── */
  console.log("\n══ 1. no user-visible Etsy ══");
  check("1. etsy-agent.html, rendered with its tool forms, shows no \"Etsy\"", !/etsy/i.test(pageText), (pageText.match(/.{0,60}etsy.{0,60}/i) || [""])[0]);
  check("1. the tool forms were built (the check read the rendered page)", !!doc.querySelector('[data-tool-run="keyword-research"]'));
  const hub = staticDoc(HUB), index = staticDoc(INDEX);
  check("1. agents-hub.html shows no \"Etsy\"", !/etsy/i.test(visibleText(hub)), (visibleText(hub).match(/.{0,60}etsy.{0,60}/i) || [""])[0]);
  check("1. index.html shows no \"Etsy\"", !/etsy/i.test(visibleText(index)), (visibleText(index).match(/.{0,60}etsy.{0,60}/i) || [""])[0]);
  const tipsSrc = /"etsy-agent\.html": (\[[\s\S]*?\n    \])/.exec(FILES[GUIDE]);
  const tips = tipsSrc ? vm.runInNewContext(tipsSrc[1]) : [];
  const tipText = tips.join("\n");
  check("1. the page's Termaximus tips were found", tips.length >= 3, tips.length);
  const banned = [/etsy/i, /shop goals/i, /competitor analysis/i, /api key/i, /\bconnect/i];
  check("1. the tips say none of Etsy, Shop Goals, competitor analysis, API keys, connections", banned.every(re => !re.test(tipText)), banned.filter(re => re.test(tipText)).join(" "));
  const cfgSrc = /window\.AGENT_PROFILE_CONFIG = (\{[\s\S]*?\n\});/.exec(FILES[PAGE]);
  const cfg = cfgSrc ? vm.runInNewContext("(" + cfgSrc[1] + ")") : { taskTypes: [], tools: [] };
  const offered = cfg.taskTypes.map(t => t.label).concat(cfg.tools.map(t => t.label));
  const named = ["Keyword Research", "Pricing Strategy", "Shop Audit Checklist", "Competitor Comparison", "Listing Optimization"];
  check("1. every feature the tips name is offered on the page", named.every(n => tipText.indexOf(n) === -1 || offered.some(o => o.indexOf(n) === 0)),
    named.filter(n => tipText.indexOf(n) !== -1 && !offered.some(o => o.indexOf(n) === 0)).join(", "));
  check("1. the tips cover Keyword Research, Pricing Strategy, Shop Audit Checklist and Competitor Comparison", ["Keyword Research", "Pricing Strategy", "Shop Audit Checklist", "Competitor Comparison"].every(n => tipText.indexOf(n) !== -1));

  /* ── 2. the name ──────────────────────────────────────────────────────── */
  console.log("\n══ 2. Storefront Agent ══");
  check("2. <title> is \"BizForce AI — Storefront Agent\"", doc.title === "BizForce AI — Storefront Agent", doc.title);
  const h1 = doc.querySelector("h1.agent-title");
  check("2. the <h1> is \"Storefront Agent\"", !!h1 && h1.textContent.trim() === "Storefront Agent", h1 && h1.textContent);
  check("2. agentLabel is \"Storefront Agent\"", cfg.agentLabel === "Storefront Agent", cfg.agentLabel);
  check("2. the launcher heading uses it", /Run Storefront Agent Task/.test(doc.body.textContent));
  const card = hub.querySelector("article.agent-card--etsy");
  check("2. the hub card reads \"Storefront Agent\" / \"Storefront Growth\"",
    !!card && card.querySelector(".agent-name").textContent.trim() === "Storefront Agent" && card.querySelector(".agent-role").textContent.trim() === "Storefront Growth",
    card && card.textContent.replace(/\s+/g, " "));
  check("2. index.html's card heading is \"Storefront Agent\"", [...index.querySelectorAll("h3")].some(h => h.textContent.trim() === "Storefront Agent"));
  check("2. internal names unchanged: agentType etsy, data-agent etsy, the hub links etsy-agent.html",
    cfg.agentType === "etsy" && !!hub.querySelector('[data-agent="etsy"]') && !!hub.querySelector('a[href="etsy-agent.html"]'));

  /* ── 3. the keyword tool's limits ─────────────────────────────────────── */
  console.log("\n══ 3. the keyword tool ══");
  const W = dom.window;
  function inputFor(labelText) {
    // A required field's label ends in its "*" marker.
    const label = [...doc.querySelectorAll("label")].find(l => l.textContent.trim().replace(/\*$/, "") === labelText);
    const id = label && label.getAttribute("for");
    return { label, id, input: id ? doc.getElementById(id) : null };
  }
  const SPEC = [["Tags allowed per listing", "1", "100", "How many tags your platform allows per listing, 1–100. Leave blank if you don't know."],
                ["Max characters per tag", "1", "200", "Your platform's maximum characters per tag, 1–200. Leave blank if you don't know."]];
  for (const [label, min, max, hint] of SPEC) {
    const f = inputFor(label);
    check("3. \"" + label + "\": a label whose for= names a number input, " + min + "–" + max,
      !!f.input && f.input.tagName === "INPUT" && f.input.type === "number" && f.input.getAttribute("min") === min && f.input.getAttribute("max") === max,
      f.id + " " + (f.input && f.input.outerHTML));
    check("3. \"" + label + "\": the backend's help text is shown", pageText.indexOf(hint) !== -1);
  }
  check("3. the page says no \"20-character\"", pageText.indexOf("20-character") === -1);
  check("3. the tool description is the new one", pageText.indexOf("Keyword candidates for your listing. Enter your platform's tag limits to see which ones fit; leave them blank and nothing is measured against a limit.") !== -1);

  const seedIn = inputFor("Seed term").input, tagsIn = inputFor("Tags allowed per listing").input, lenIn = inputFor("Max characters per tag").input;
  const runBtn = doc.querySelector('[data-tool-run="keyword-research"]');
  if (seedIn && tagsIn && lenIn && runBtn) {
    seedIn.value = "wool hat"; tagsIn.value = ""; lenIn.value = "15";
    runBtn.dispatchEvent(new W.Event("click", { bubbles: true }));
    await settle();
    const sent = seen.posts[0] || {};
    check("3. a blank limit is not sent, an entered one is sent as a JSON number",
      sent.seed === "wool hat" && !("max_tags" in sent) && sent.max_tag_length === 15, JSON.stringify(sent));
    seedIn.value = "wool hat"; tagsIn.value = ""; lenIn.value = "";
    runBtn.dispatchEvent(new W.Event("click", { bubbles: true }));
    await settle();
    const sent2 = seen.posts[1] || {};
    check("3. with both blank, neither is sent", seen.posts.length === 2 && !("max_tags" in sent2) && !("max_tag_length" in sent2), JSON.stringify(sent2));
  } else {
    check("3. the keyword tool's inputs and run button were found", false);
  }

  /* ── 4. a no-limits result ────────────────────────────────────────────── */
  console.log("\n══ 4. a no-limits result renders as not measured ══");
  const resultEl = doc.getElementById("apTool_keyword_research_result");
  const html = resultEl ? resultEl.innerHTML : "";
  const text = resultEl ? resultEl.textContent.replace(/\s+/g, " ") : "";
  check("4. the result was drawn", text.indexOf("wool beanies") !== -1, text.slice(0, 200));
  const NOT = "not measured — no limit entered";
  // [label, how many times it appears: once per keyword, or once in counts]
  for (const [key, times] of [["Fits tag", 2], ["Over tag limit by", 2], ["Tag ready", 1], ["Too long for a tag", 1]]) {
    const re = new RegExp(key + ":\\s*(.{0," + NOT.length + "})", "g");
    const vals = []; let m; while ((m = re.exec(text))) vals.push(m[1]);
    check("4. every \"" + key + "\" (" + times + ") reads \"" + NOT + "\"", vals.length === times && vals.every(v => v === NOT), JSON.stringify(vals));
  }
  check("4. no limit field renders as false, No, 0 or null",
    !/(Fits tag|Over tag limit by|Tag ready|Too long for a tag):\s*(false|No|0|null)\b/.test(text), (text.match(/(Fits tag|Over tag limit by|Tag ready|Too long for a tag):\s*(false|No|0|null)\b/) || [""])[0]);
  check("4. nothing in the result carries the broken-limit colour", resultEl && resultEl.querySelectorAll(".bad").length === 0);
  check("4. the not-measured text is styled as such", (html.match(/class="ap-not-measured"/g) || []).length >= 6, (html.match(/class="ap-not-measured"/g) || []).length);
  check("4. suggested_tag_set_reason is shown", text.indexOf(NO_LIMITS.suggested_tag_set_reason) !== -1);
  check("4. the reason is with the limits and standing statements, not under \"Written by the model\"",
    !!resultEl && !!resultEl.querySelector(".ap-ref") && resultEl.querySelector(".ap-ref").textContent.indexOf("No tag set was built") !== -1 &&
    (!resultEl.querySelector(".ap-generated") || resultEl.querySelector(".ap-generated").textContent.indexOf("No tag set was built") === -1));
  check("4. the constraints show both limits as not entered (—), never \"null\"", /Max tags:\s*—/.test(text) && /Max tag length:\s*—/.test(text) && !/:\s*null\b/.test(text));
  check("4. no script error on the page", seen.errors.length === 0, seen.errors.join(" | "));

  dom.window.close();
  console.log("\n" + (failures ? "CHECKS FAILED: " + failures + " of " + (passes + failures) : "ALL " + passes + " CHECKS PASSED") + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(failures ? 1 : 0);
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
