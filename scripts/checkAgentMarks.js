"use strict";
/* ════════════════════════════════════════════════════════════════════════════
   checkAgentMarks — FX3 (Nov 22 2026): every agent's colour and icon comes from
   ONE map, the frontend's scripts/bf-agent-marks.js, read by the dashboard
   (the AI Agent Directory box in <template id="orbitTools">) and by the Agent
   Directory (ai-agents.html's Large cards; scripts/bf-agents-views.js's
   Compact rows and Grid tiles).

     A  the map: the 18 agents the Directory names (bf-agents-views.js ROLES),
        each a colour (a theme token where it has one) and a 24 x 24 stroked
        icon; each equals the agent's own card on the Agents hub
        (agents-hub.html), so the agents not on the dashboard carry their own;
     B  the dashboard: it loads the map after the template and before
        scripts/bf-orbit.js copies the template; its five agents are filled
        from the map, and each is EXACTLY as it was at frontend e3e8ce0 (the
        same drawing, and the stroke, ring and glow its old
        css/bizforce-ui.css class gave it);
     C  the Directory, in jsdom on a phone, in each view (Large, Compact,
        Grid): every agent's card, row or tile carries the dashboard's colour
        and icon for that agent (the five on the dashboard compared with the
        dashboard's own filled icons; all 18 with the map the dashboard reads);
        an unknown type keeps the generic ring and no agent colour;
     D  the same on a desktop (Large cards);
     E  no copied values: neither page nor bf-agents-views.js holds an icon
        drawing of its own.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check.
   ════════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const MARKS = "scripts/bf-agent-marks.js", AGV = "scripts/bf-agents-views.js", AGP = "ai-agents.html", DASH = "dashboard.html";
const HUB = "agents-hub.html", UI = "css/bizforce-ui.css", ORDER = "scripts/bf-agent-order.js", DESC = "scripts/agent-descriptions.js";
const BEFORE = "e3e8ce0";   // the frontend before FX3: the dashboard's five icons drawn inline, coloured by bizforce-ui.css

const MUTATIONS = {
  // FX3B (Nov 22 2026): one of the five unused agent rules back in css/bizforce-ui.css (E3)
  "fx3b-rule-back": [[UI, ".bf-hq-icon.analytics {\n", ".bf-hq-icon.analytics,\n.bf-hq-icon.analytics-agent {\n"]],
  "map-colour-changed": [[MARKS, "content:            { colour: \"#34d399\",", "content:            { colour: \"#34d39a\","]],
  "map-icon-swapped": [[MARKS, "influencer:         { colour: \"#e879f9\", icon: '<polygon", "influencer:         { colour: \"#e879f9\", icon: '<circle cx=\"12\" cy=\"12\" r=\"3\"/><polygon"]],
  "map-token-lost": [[MARKS, "sales:              { colour: \"var(--bf-accent-b, #a855f7)\",", "sales:              { colour: \"#a855f7\","]],
  "ring-not-painted": [[MARKS, "    el.style.setProperty(\"border-color\", rgba(type, \"0.45\"));\n", ""]],
  "glow-alpha": [[MARKS, "\"0 0 24px \" + rgba(type, \"0.18\")", "\"0 0 24px \" + rgba(type, \"0.2\")"]],
  "stroke-width": [[MARKS, "stroke=\"currentColor\" stroke-width=\"1.5\"", "stroke=\"currentColor\" stroke-width=\"2\""]],
  "template-not-filled": [[MARKS, "    Array.prototype.forEach.call(r.querySelectorAll(\"template\"), function (t) { if (t.content) n += fill(t.content); });\n", ""]],
  "dash-not-loaded": [[DASH, "<script src=\"/scripts/bf-agent-marks.js\"></script>\n", ""]],
  "dash-after-views": [[DASH, "<script src=\"/scripts/bf-agent-marks.js\"></script>\n", ""], [DASH, "<script src=\"/scripts/bf-hq-views.js\"></script>\n", "<script src=\"/scripts/bf-hq-views.js\"></script>\n<script src=\"/scripts/bf-agent-marks.js\"></script>\n"]],
  "dash-before-orbit": [[DASH, "<script src=\"/scripts/bf-agent-marks.js\"></script>\n", ""], [DASH, "</template>\n<script src=\"/scripts/bf-orbit.js\"></script>", "</template>\n<script src=\"/scripts/bf-agent-marks.js\"></script>\n<script src=\"/scripts/bf-orbit.js\"></script>"]],
  "dash-wrong-agent": [[DASH, "data-bf-agent-mark=\"social\"", "data-bf-agent-mark=\"community\""]],
  "card-not-painted": [[AGP, "{ avatar.innerHTML = marks.svg(type); marks.paint(avatar, type); }", "{ avatar.innerHTML = marks.svg(type); }"]],
  "card-generic": [[AGP, "      if (marks && marks.has(type)) { avatar.innerHTML", "      if (false) { avatar.innerHTML"]],
  "card-map-not-loaded": [[AGP, "<script src=\"/scripts/bf-agent-marks.js\"></script>\n", ""]],
  "unknown-painted": [[AGP, "      if (marks && marks.has(type)) { avatar.innerHTML", "      if (marks) { avatar.innerHTML"]],
  "tile-not-painted": [[AGV, "{ tile.innerHTML = marks.svg(type); marks.paint(tile, type); }", "{ tile.innerHTML = marks.svg(type); }"]],
  "tile-card-svg": [[AGV, "      if (marks && marks.has(type)) { tile.innerHTML", "      if (false) { tile.innerHTML"]],
  "tile-copied-icon": [[AGV, "  var grid = document.querySelector(\".agents-grid\");\n", "  var SEO_ICON = '<circle cx=\"11\" cy=\"11\" r=\"8\"/><line x1=\"21\" y1=\"21\" x2=\"16.65\" y2=\"16.65\"/>';\n  var grid = document.querySelector(\".agents-grid\");\n"]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));
if (MUTATE && !MUTATIONS[MUTATE]) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }

let JSDOM;
try { ({ JSDOM } = require("jsdom")); } catch (e) { console.log("    FAIL  jsdom could not be loaded: " + e.message); process.exit(1); }

const FILES = {};
const readF = f => { try { return fs.readFileSync(path.join(FRONTEND, f), "utf8").replace(/\r\n/g, "\n"); } catch (e) { return null; } };
[MARKS, AGV, AGP, DASH, HUB, UI, ORDER, DESC].forEach(f => { FILES[f] = readF(f); });
const gitShow = (rev, f) => { try { return execFileSync("git", ["show", rev + ":" + f], { cwd: FRONTEND, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 }).replace(/\r\n/g, "\n"); } catch (e) { return null; } };
const OLD_DASH = gitShow(BEFORE, DASH);
// NAMED (Nov 22 2026, FX3B): BEFORE B3 read the five old colour rules from today's css/bizforce-ui.css. AFTER FX3B removed
// them (unused since FX3), so B3 reads them from the stylesheet as it was at BEFORE, where the five old icons used them.
const OLD_UI = gitShow(BEFORE, UI);
if (MUTATE) {
  for (const [file, from, to] of MUTATIONS[MUTATE]) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}

let passes = 0, failures = 0;
function check(name, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + name); }
  else { failures++; console.log("    FAIL  " + name + (detail !== undefined && detail !== "" ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}
process.on("unhandledRejection", e => check("no page request is left unhandled", false, (e && e.message) || e));
const J = v => JSON.stringify(v);
const has = (t, x) => typeof t === "string" && t.indexOf(x) !== -1;
const settle = ms => new Promise(r => setTimeout(r, ms || 30));
const norm = v => String(v == null ? "" : v).replace(/\s+/g, " ").trim();
const VIEWS3 = ["large", "compact", "grid"];
// jsdom writes a plain #rrggbb colour back as rgb(r, g, b) (a var() it keeps as written): read both the same way
const canon = v => { const m = /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(norm(v)); return m ? "rgb(" + parseInt(m[1], 16) + ", " + parseInt(m[2], 16) + ", " + parseInt(m[3], 16) + ")" : norm(v); };
// An element's mark: its drawing and the four values the dashboard's look is made of.
function markOf(el) {
  if (!el) return null;
  const svg = el.querySelector("svg");
  return { svg: svg ? norm(svg.outerHTML.replace(/\/>/g, ">")) : null, stroke: norm(el.style.getPropertyValue("--bf-icon-stroke")),
    color: norm(el.style.getPropertyValue("color")), ring: norm(el.style.getPropertyValue("border-color")), glow: norm(el.style.getPropertyValue("box-shadow")) };
}
function svgText(inner) { return norm(('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">' + inner + "</svg>")); }

(async () => {
  /* ══ A ══ */
  console.log("\n══ A. the map ══");
  const mw = new JSDOM("<!doctype html><html><head></head><body></body></html>", { runScripts: "outside-only" }).window;
  let mapErr = null;
  try { mw.eval(FILES[MARKS] || ""); } catch (e) { mapErr = e.message; }
  const M = mw.BFAgentMarks;
  const rolesSrc = (/var ROLES = (\{[\s\S]*?\});/.exec(FILES[AGV] || "") || [])[1];
  let ROLES = null; try { ROLES = Function("return " + rolesSrc)(); } catch (e) { ROLES = null; }
  const TYPES = ROLES ? Object.keys(ROLES).sort() : [];
  check("A1. scripts/bf-agent-marks.js loads and gives BFAgentMarks", !mapErr && !!M && typeof M.svg === "function" && typeof M.paint === "function", mapErr);
  check("A2. it holds exactly the 18 agents the Directory names (bf-agents-views.js ROLES)", !!M && TYPES.length === 18 && J(Object.keys(M.AGENTS).sort()) === J(TYPES), J([TYPES.length, M && Object.keys(M.AGENTS).length]));
  // The Agents hub's own card for each agent: its stroke and its drawing.
  const hub = {};
  const hre = /<article class="agent-card agent-card--([a-z_]+)">[\s\S]*?<svg ([^>]*)>([\s\S]*?)<\/svg>/g; let hm;
  while ((hm = hre.exec(FILES[HUB] || ""))) {
    const st = /stroke(?:="|:)(var\([^)]*\)|#[0-9a-f]{6})/.exec(hm[2]);
    hub[hm[1]] = { stroke: st ? st[1] : null, icon: hm[3].replace(/>\s+</g, "><").trim() };
  }
  const hubWrong = TYPES.filter(t => !M || !hub[t] || M.colour(t) !== hub[t].stroke || norm(M.svg(t)) !== svgText(hub[t].icon));
  check("A3. each agent's colour and drawing equal its own card on the Agents hub (agents-hub.html), so the 13 the dashboard does not show carry their own", hubWrong.length === 0 && Object.keys(hub).length === 18, hubWrong.join(", "));
  const tokenOk = !!M && M.colour("seo") === "var(--bf-accent-a, #22d3ee)" && M.colour("sales") === "var(--bf-accent-b, #a855f7)" && M.colour("rd") === "var(--bf-accent-a, #22d3ee)" &&
    M.rgba("sales", "0.45") === "rgba(var(--bf-accent-b-rgb, 168, 85, 247), 0.45)" && M.rgba("content", "0.45") === "rgba(52, 211, 153, 0.45)";
  check("A4. a colour that follows the theme is a var() with its fallback (SEO and R&D accent a, Sales accent b), in the stroke and in the ring", tokenOk);
  check("A5. an unknown type has no mark", !!M && !M.has("general") && M.svg("general") === "" && M.colour("general") === null);

  /* ══ B ══ */
  console.log("\n══ B. the dashboard ══");
  const dash = FILES[DASH] || "";
  // the template itself, on its own line (a comment above it names it too)
  const TPL_OPEN = String.fromCharCode(10) + "<template id=\"orbitTools\">";
  const tAt = dash.indexOf(TPL_OPEN) + 1, tEnd = dash.indexOf("</template>", tAt);
  const mAt = dash.indexOf("<script src=\"/scripts/bf-agent-marks.js\"></script>"), oAt = dash.indexOf("<script src=\"/scripts/bf-orbit.js\"></script>");
  const vAt = dash.indexOf("<script src=\"/scripts/bf-hq-views.js\"></script>");
  /* After bf-orbit.js (which keeps the template's boxes in the template and copies them into the page), so the map
     fills both the template and the copies already drawn; before bf-hq-views.js, which copies the boxes' icons into
     the phone's rows and tiles. (bf-orbit.js stays right after the template, as checkDashboardOrbit pins.) */
  check("B1. dashboard.html loads the map once, after the tools' template and scripts/bf-orbit.js and before scripts/bf-hq-views.js",
    tAt > 0 && oAt > tEnd && mAt > oAt && vAt > mAt && dash.indexOf("bf-agent-marks.js") === mAt + 22 && dash.indexOf("bf-agent-marks.js", mAt + 23) === -1, J([tEnd, oAt, mAt, vAt]));
  const tpl = tAt <= 0 ? "" : dash.slice(tAt, tEnd + "</template>".length);
  const dw = new JSDOM("<!doctype html><html><head></head><body>" + tpl + "</body></html>", { runScripts: "outside-only" }).window;
  if (mAt !== -1) { try { dw.eval(FILES[MARKS] || ""); } catch (e) { /* counted below */ } }
  const tc = dw.document.getElementById("orbitTools");
  const dashLis = tc ? Array.from(tc.content.querySelectorAll(".orbit-dir-agent")) : [];
  const DASH_MARK = {};
  dashLis.forEach(li => { const sp = li.querySelector(".orbit-dir-icon"); DASH_MARK[sp ? sp.getAttribute("data-bf-agent-mark") : "?"] = markOf(sp); });
  check("B2. the directory box's five agents (SEO, Sales, Content, Analytics, Social) are named for the map and drawn from it",
    J(Object.keys(DASH_MARK)) === J(["seo", "sales", "content", "analytics", "social"]) && Object.values(DASH_MARK).every(m => m && m.svg), J(DASH_MARK));
  // Before FX3: the same five, each a class on .bf-hq-icon and its own inline drawing.
  const oldAt = OLD_DASH ? OLD_DASH.indexOf(TPL_OPEN) : -1;
  const oldTpl = oldAt === -1 ? "" : OLD_DASH.slice(oldAt, OLD_DASH.indexOf("</template>", oldAt));
  const oldRe = /<li class="orbit-dir-agent"><span class="bf-neon-icon bf-hq-icon orbit-dir-icon ([a-z-]+)" aria-hidden="true">(<svg[\s\S]*?<\/svg>)<\/span>/g;
  const ui = OLD_UI || "";   // NAMED (Nov 22 2026, FX3B): BEFORE FILES[UI]
  const ruleFor = cls => { const re = new RegExp("(?:^|\\n)([^{}\\n]*(?:,\\n[^{}\\n]*)*)\\{([^}]*)\\}", "g"); let m;
    while ((m = re.exec(ui))) { if (m[1].split(",").map(x => x.trim()).indexOf(".bf-hq-icon." + cls) !== -1) return m[2]; } return null; };
  const decl = (body, prop) => { const m = new RegExp("(?:^|;|\\n)\\s*" + prop.replace(/-/g, "\\-") + ":\\s*([^;]+);").exec(body || ""); return m ? norm(m[1]) : null; };
  const was = []; let om;
  while ((om = oldRe.exec(oldTpl))) was.push({ cls: om[1], svg: norm(om[2].replace(/\/>/g, ">")) });
  const TYPE_OF = { "analytics-agent": "analytics" };
  const sameAsBefore = was.length === 5 && was.every(o => {
    const t = TYPE_OF[o.cls] || o.cls, now = DASH_MARK[t], body = ruleFor(o.cls);
    // jsdom writes an svg's children as <x ...></x>; both sides are read the same way
    const nowSvg = now && now.svg ? now.svg.replace(/><\/(circle|line|path|polyline|polygon|rect)>/g, ">") : null;
    return !!now && !!body && nowSvg === o.svg && now.stroke === decl(body, "--bf-icon-stroke") && canon(now.color) === canon(decl(body, "--bf-icon-stroke")) &&
      now.ring === decl(body, "border-color") && now.glow === decl(body, "box-shadow");
  });
  check("B3. each of the five is exactly as it was at " + BEFORE + ": the same drawing, and the stroke, ring and glow its old bizforce-ui.css class gave it",
    !!OLD_DASH && sameAsBefore, J(was.map(o => [o.cls, ruleFor(o.cls) ? "rule" : "no rule", DASH_MARK[TYPE_OF[o.cls] || o.cls]])).slice(0, 400));
  dw.close();

  /* ══ C, D ══ */
  const html = FILES[AGP] || "";
  const inline = (html.match(/<script>\n\(function renderLiveAgents\(\) \{[\s\S]*?<\/script>/) || [""])[0].replace(/^<script>/, "").replace(/<\/script>$/, "");
  const body = (/<body>([\s\S]*?)<script src="\/scripts\/bf-agent-order\.js"><\/script>/.exec(html) || ["", ""])[1];
  const loadsMap = /<script src="\/scripts\/bf-agent-marks\.js"><\/script>\n<script src="\/scripts\/bf-agent-order\.js"><\/script>/.test(html);
  const ROWS = TYPES.concat(["general"]).map(t => ({ agent_type: t, display_name: t + " Agent", page_url: "/" + t + "-agent.html", active: true }));
  async function page(phone) {
    const dom = new JSDOM("<!doctype html><html><head></head><body>" + body + "</body></html>", { url: "https://bizforce.example/ai-agents.html", runScripts: "outside-only", pretendToBeVisual: true });
    const w = dom.window, store = { bf_token: "t" };
    Object.defineProperty(w, "localStorage", { value: { getItem: k => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); }, removeItem: k => { delete store[k]; } }, configurable: true });
    w.matchMedia = q => ({ matches: phone && /max-width: 760px/.test(q), media: q, addEventListener() {}, removeEventListener() {} });
    w.fetch = u => { const url = String(u); const b = /\/api\/agents$/.test(url) ? { agents: ROWS } : /preferences$/.test(url) ? { ok: true, agents_card_view: null } : {};
      const p = Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(b) }); p.catch(() => {}); return p; };
    let err = null;
    for (const src of [loadsMap ? FILES[MARKS] : "", FILES[ORDER], FILES[DESC], inline, FILES[AGV]]) { try { w.eval(src || ""); } catch (e) { err = err || e.message; } }
    await settle(60);
    return { w, d: w.document, err };
  }
  // The mark each agent shows in a view: a Large card's avatar, or a Compact row's or Grid tile's icon.
  function marksIn(d, view) {
    const out = {};
    if (view === "large") Array.from(d.querySelectorAll("article.agent-card")).forEach(c => { const t = (/agent-card--([a-z_]+)/.exec(c.className) || [])[1]; out[t] = markOf(c.querySelector(".agent-avatar")); });
    else Array.from(d.querySelectorAll("#agList .ag-item")).forEach(it => { out[it.getAttribute("data-agent")] = markOf(it.querySelector(".ag-icon")); });
    return out;
  }
  const mapMark = t => M ? { svg: norm(M.svg(t)), stroke: M.colour(t), color: M.colour(t), ring: M.rgba(t, "0.45"), glow: "0 0 24px " + M.rgba(t, "0.18") } : null;
  const eq = (a, b) => !!a && !!b && a.svg === b.svg && a.stroke === b.stroke && canon(a.color) === canon(b.color) && a.ring === b.ring && a.glow === b.glow;
  // jsdom writes an svg's children as <x ...></x>; the map's string as <x .../>: read both the same way
  const flat = m => m ? Object.assign({}, m, { svg: m.svg ? m.svg.replace(/><\/(circle|line|path|polyline|polygon|rect)>/g, ">").replace(/\/>/g, ">") : m.svg }) : m;

  console.log("\n══ C. the Directory on a phone, in each view ══");
  check("C0. ai-agents.html loads the map before its cards' scripts", loadsMap);
  const P = await page(true);
  check("C1. the page draws every agent (and the unknown one) with no error", !P.err && P.d.querySelectorAll("article.agent-card").length === ROWS.length, P.err);
  for (const v of VIEWS3) {
    const btn = P.d.querySelector('.ag-view-btn[data-view="' + v + '"]');
    if (btn) { btn.click(); await settle(20); }
    const shown = P.d.querySelector(".page") ? P.d.querySelector(".page").getAttribute("data-ag-view") : null;
    const got = marksIn(P.d, v);
    const vsDash = ["seo", "sales", "content", "analytics", "social"].filter(t => !eq(flat(got[t]), flat(DASH_MARK[t])));
    const vsMap = TYPES.filter(t => !eq(flat(got[t]), flat(mapMark(t))));
    check("C2 " + v + ". the five the dashboard shows: each " + (v === "large" ? "card" : v === "compact" ? "row" : "tile") + " has the dashboard's own colour, ring, glow and icon for that agent",
      shown === v && vsDash.length === 0, J([shown, vsDash, vsDash.length ? [got[vsDash[0]], DASH_MARK[vsDash[0]]] : null]));
    check("C3 " + v + ". all 18 agents: each carries the colour and icon of the map the dashboard reads", vsMap.length === 0, J([vsMap, vsMap.length ? [got[vsMap[0]], mapMark(vsMap[0])] : null]));
    const g = got.general;
    const ringOnly = !!g && !g.stroke && !g.ring && !g.glow && !!g.svg && /<circle cx="12" cy="12" r="9"/.test(g.svg);
    check("C4 " + v + ". an unknown type keeps the generic ring, with no agent colour", ringOnly, J(g));
  }
  P.w.close();

  console.log("\n══ D. the Directory on a desktop ══");
  const D = await page(false);
  const dg = marksIn(D.d, "large");
  const dWrong = TYPES.filter(t => !eq(flat(dg[t]), flat(mapMark(t))));
  check("D1. above 760 px the Large cards carry the same colours and icons", !D.err && dWrong.length === 0 && ["seo", "sales", "content", "analytics", "social"].every(t => eq(flat(dg[t]), flat(DASH_MARK[t]))), J([D.err, dWrong]));
  D.w.close();

  /* ══ E ══ */
  console.log("\n══ E. one map, no copies ══");
  const bodies = M ? TYPES.map(t => M.AGENTS[t].icon) : [];
  const copies = [];
  // the dashboard's AI Agent Directory box (its other boxes draw their own tools, some with the same shapes)
  const dirAt = dash.indexOf("<div id=\"agentDirectoryLanding\""), dirBox = dirAt === -1 ? "" : dash.slice(dirAt, dash.indexOf("<div class=\"orbit-dir-actions\">", dirAt));
  [[AGP, html], [AGV, FILES[AGV] || ""], [DASH + " (the directory box)", dirBox]].forEach(([f, txt]) => {
    bodies.forEach((b, i) => { const first = /^<[^>]*\/>/.exec(b); if (first && txt.indexOf(first[0]) !== -1 && txt.indexOf(b) !== -1) copies.push(f + ": " + TYPES[i]); });
  });
  check("E1. neither page nor bf-agents-views.js holds an agent's drawing of its own (the map is the only copy)", bodies.length === 18 && copies.length === 0, copies.join(", "));
  check("E2. the dashboard's five no longer carry the agent classes that coloured them (bizforce-ui.css .bf-hq-icon.seo and the rest)",
    !/orbit-dir-icon (seo|sales|content|analytics-agent|social)"/.test(dash) && (dash.match(/data-bf-agent-mark="/g) || []).length === 5);
  // FX3B (Nov 22 2026): and the five rules that coloured them are gone from css/bizforce-ui.css (comments aside)
  const uiNow = (FILES[UI] || "").replace(/\/\*[\s\S]*?\*\//g, "");
  const left = ["seo", "sales", "content", "analytics-agent", "social"].filter(c => new RegExp("\\.bf-hq-icon\\." + c + "(?![\\w-])").test(uiNow));
  check("E3. css/bizforce-ui.css holds none of the five agent rules (.bf-hq-icon.seo, .sales, .content, .analytics-agent, .social); .bf-hq-icon.analytics stays",
    !!FILES[UI] && left.length === 0 && /\n\.bf-hq-icon\.analytics \{\n/.test(uiNow), J(left));

  if (failures) { console.log("\nCHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("\nALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the check crashed: " + (e && e.stack || e)); process.exit(1); });
