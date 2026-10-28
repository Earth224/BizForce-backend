// ── The app map: what every BizForce page offers, read from the pages ────────
//
// Termaximus's Guide mode (POST /api/guide/ask) may name only pages and
// controls that exist. This builds the list it is allowed to name, FROM THE
// FRONTEND ITSELF, so nobody writes it by hand and nobody can let it drift:
// scripts/buildAppMap.js writes the result to lib/appMap.json, and
// scripts/checkAppMap.js rebuilds it in memory and fails when the file differs
// from a fresh build, or when its inputs hash does not match the inputs.
//
// PER PAGE (keyed by file name, the key termaximus-guide.js's currentPageKey
// gives, so the client and the map agree on what a page is called):
//   p   the path a link opens ("/crm.html", "/agents/seo.html");
//   t   the <title>; h the first <h1>, tags stripped;
//   c   the controls, each [selector, label, kind, route?]:
//         selector  "#id", '[data-tool-run="copy"]' or 'a[href="/billing.html"]',
//                   exactly what document.querySelector takes, and unique on
//                   the page (a control with no stable, unique selector is
//                   left out rather than guessed at);
//         label     what the control shows (aria-label when it has one);
//         kind      "b" button, "l" link, "t" tab;
//         route     "METHOD /api/path" when the control's own handler calls it;
//   g   the page's guide tips, from PAGE_GUIDANCE in termaximus-guide.js.
// AND ONCE, routes: "METHOD /api/path" -> its gate, read from server.js, for
// every route a control in the map calls (and no other, to keep it small):
//   "auth" requireAuth, "sub" requireActiveSubscription, "admin" requireAdmin,
//   "owner" a handler that refuses everyone but the account that owns it
//   (LEAD_RADAR_UNAVAILABLE or an isOwnerAccount refusal), "public" none.
//
// NOTHING PRIVATE. Only the static markup and code of the pages is read: no
// database, no user data, no environment. Input values, placeholders and
// option lists are not read at all, and a label that looks like a key or a
// token is dropped (secretLike).
//
// No model call, no network, no database: string reading only.

var crypto = require("crypto");

var MAP_VERSION = 1;
// Pages that are not part of the app a member can be guided around.
var MAP_SKIP = /^(google[0-9a-f]+\.html|test-.*)$/i;
var LABEL_MAX = 60;

var NAMED_ENTITIES = { larr: "←", rarr: "→", uarr: "↑", darr: "↓", times: "×", check: "✓", bull: "•", ndash: "–", laquo: "«", raquo: "»", copy: "©", trade: "™" };
function decodeEntities(t) {
  return String(t)
    .replace(/&([a-z]+);/g, function (m, n) { return NAMED_ENTITIES[n] || m; })
    .replace(/&nbsp;/g, " ").replace(/&quot;/g, "\"").replace(/&#39;/g, "'").replace(/&rsquo;/g, "’")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&middot;/g, "·").replace(/&mdash;/g, "—").replace(/&hellip;/g, "…")
    .replace(/&#x([0-9a-f]+);/gi, function (m, h) { return String.fromCodePoint(parseInt(h, 16)); })
    .replace(/&#(\d+);/g, function (m, d) { return String.fromCodePoint(Number(d)); })
    .replace(/&amp;/g, "&");
}
function textOf(html) {
  return decodeEntities(String(html).replace(/<[^>]+>/g, " ")).replace(/\s+/g, " ").trim();
}
function attr(tag, name) {
  var m = new RegExp("\\s" + name + "\\s*=\\s*(\"([^\"]*)\"|'([^']*)')", "i").exec(tag);
  return m ? decodeEntities(m[2] !== undefined ? m[2] : m[3]) : null;
}
// A label that could be a credential is never put in the map.
function secretLike(label) {
  return /\b(sk-|pk_|rk_|whsec_|eyJ)[A-Za-z0-9_-]{8,}|[A-Za-z0-9_-]{32,}/.test(label);
}
function cleanLabel(label) {
  var t = String(label || "").replace(/\s+/g, " ").trim();
  if (!t || secretLike(t)) return "";
  return t.length > LABEL_MAX ? t.slice(0, LABEL_MAX - 1) + "…" : t;
}

// The page's markup with every <script> and <style> body removed, and the
// script bodies separately (inline code, then the local scripts it loads).
function splitPage(html) {
  var scripts = [];
  var markup = String(html)
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<script\b[^>]*>([\s\S]*?)<\/script>/gi, function (m, body) { scripts.push(body); return " "; });
  return { markup: markup, inline: scripts.join("\n;\n") };
}
function localScriptsOf(html) {
  var out = [];
  var re = /<script\b[^>]*\ssrc="([^"]+)"/gi, m;
  while ((m = re.exec(html))) {
    var src = m[1].replace(/^(\.\.\/|\/)/, "");
    if (/^scripts\/[\w.-]+\.js$/.test(src) && out.indexOf(src) === -1) out.push(src);
  }
  return out;
}

/* ── the server's routes and their gates ───────────────────────────────────── */
function braceMatch(src, openIdx) {
  var depth = 0;
  for (var i = openIdx; i < src.length; i++) {
    var c = src[i];
    if (c === "{") depth++;
    else if (c === "}") { depth--; if (depth === 0) return i + 1; }
  }
  return -1;
}
function serverRoutes(server) {
  var routes = [];
  var re = /^app\.(get|post|put|patch|delete)\("(\/api\/[^"]+)",([^\n]*)/gm, m;
  while ((m = re.exec(server))) {
    var open = server.indexOf("{", m.index + m[0].length - m[3].length);
    var fnAt = server.indexOf("function", m.index);
    var body = fnAt !== -1 && open !== -1 ? server.slice(open, braceMatch(server, open)) : "";
    var head = m[3].split(/async function|function \(/)[0];
    var gates = [];
    if (/\brequireAuth\b/.test(head)) gates.push("auth");
    if (/\brequireActiveSubscription\b/.test(head)) gates.push("sub");
    if (/\brequireAdmin\b/.test(head)) gates.push("admin");
    if (/LEAD_RADAR_UNAVAILABLE|!isOwnerAccount\(req\.user\.id\)/.test(body)) gates.push("owner");
    routes.push({
      method: m[1].toUpperCase(),
      path: m[2],
      norm: m[2].replace(/:[A-Za-z_]+/g, ":p"),
      gate: gates.length ? gates.join(",") : "public"
    });
  }
  return routes;
}

/* ── which routes a piece of page code calls ──────────────────────────────────
   A fetch URL is a string literal starting "/api/", possibly concatenated with
   expressions ("/api/sms/campaigns/" + id + "/enroll"); each expression becomes
   ":p", the query string is dropped, and the result must equal a server route
   with its parameters as ":p". The method is the nearest method: "X" after it
   (GET when there is none before the call closes). An unmatched URL is left
   out, never guessed at. */
var URL_RE = /["'`](?:https:\/\/[\w.-]+)?(\/api\/[^"'`?]*)(?:\?[^"'`]*)?["'`]((?:\s*\+\s*(?:[A-Za-z_$][\w$.]*(?:\([^()]*\))?)\s*(?:\+\s*["'`][^"'`?]*(?:\?[^"'`]*)?["'`])?)*)/g;
function routesIn(code, routes) {
  var out = [];
  var m;
  URL_RE.lastIndex = 0;
  while ((m = URL_RE.exec(code))) {
    var tail = m[2] || "";
    var pieces = tail.split(/\s*\+\s*/).filter(Boolean);
    var path = m[1];
    pieces.forEach(function (p) {
      var lit = /^["'`]([^"'`?]*)/.exec(p);
      path += lit ? lit[1] : ":p";
    });
    path = path.replace(/:p(:p)+/g, ":p").replace(/\/$/, "") || path;
    /* The statement the URL is in and the one after it (a save that builds
       `var path = …` then `var method = editing ? "PUT" : "POST"`), up to 400
       characters. The method is any quoted method name there — fetch's
       method: "POST", a helper's apiFetch(path, "POST", body), or both arms of
       a ternary — tried in order; "method: <variable>" is whichever write the
       server offers on that path; neither is GET. */
    var after = code.slice(m.index + m[0].length, m.index + m[0].length + 400);
    var e1 = after.search(/;\s*\n/);
    var e2 = e1 === -1 ? -1 : after.slice(e1 + 1).search(/;\s*\n/);
    var stmt = e1 === -1 ? after : e2 === -1 ? after : after.slice(0, e1 + 1 + e2);
    var lits = (stmt.match(/["'](GET|POST|PUT|PATCH|DELETE)["']/g) || []).map(function (q) { return q.slice(1, -1); });
    var methods = lits.length ? lits : /method\s*:/.test(stmt) ? ["POST", "PUT", "PATCH", "DELETE"] : ["GET"];
    var hit = null;
    methods.some(function (method) {
      hit = routes.filter(function (r) { return r.method === method && r.norm === path; })[0] || null;
      return !!hit;
    });
    if (hit) {
      var key = hit.method + " " + hit.path;
      if (out.indexOf(key) === -1) out.push(key);
    }
  }
  return out;
}
/* A button's route: the first write its handler makes. A read is kept only for
   a control that reads ("Refresh", "Show Trades", "Download CSV"): a "Save"
   whose only route found is the list it reloads afterwards has not been
   resolved, and no route is better than the wrong one. */
var READ_LABEL = /\b(refresh|reload|load|show|view|search|download|try again|find|filter|open|check|preview|export|statement)\b/i;
function controlRoute(found, label) {
  var write = found.filter(function (r) { return r.indexOf("GET ") !== 0; })[0];
  if (write) return write;
  return found[0] && READ_LABEL.test(label || "") ? found[0] : null;
}

// The body of a function declared in this code, or "".
function functionBody(code, name) {
  var m = new RegExp("function " + name.replace(/[$]/g, "\\$") + "\\s*\\(").exec(code);
  if (!m) return "";
  var open = code.indexOf("{", m.index);
  return open === -1 ? "" : code.slice(open, braceMatch(code, open));
}
/* What a control's own handler calls: its onclick attribute's function, or a
   click listener on getElementById("<id>") (directly, or through a variable it
   was assigned to), with the functions that handler calls by name followed
   one level down. */
function handlerCode(code, id, onclick) {
  var bodies = [];
  if (onclick) {
    bodies.push(onclick);
    var fn = /^\s*([A-Za-z_$][\w$]*)\s*\(/.exec(onclick);
    if (fn) bodies.push(functionBody(code, fn[1]));
  }
  if (id) {
    var esc = id.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    var handles = ['document\\.getElementById\\(["\']' + esc + '["\']\\)'];
    var v, vr = new RegExp("([A-Za-z_$][\\w$]*)\\s*=\\s*document\\.getElementById\\([\"']" + esc + "[\"']\\)", "g");
    while ((v = vr.exec(code))) handles.push(v[1].replace(/[$]/g, "\\$"));
    handles.forEach(function (h) {
      var lr = new RegExp("(?:^|[^\\w$.])" + h + "\\s*\\.\\s*(?:addEventListener\\(\\s*[\"']click[\"']\\s*,\\s*|onclick\\s*=\\s*)", "g"), l;
      while ((l = lr.exec(code))) {
        var rest = code.slice(l.index + l[0].length);
        var named = /^([A-Za-z_$][\w$]*)\s*[),;]/.exec(rest);
        if (named) { bodies.push(functionBody(code, named[1])); continue; }
        var open = rest.indexOf("{");
        if (open !== -1 && open < 80) bodies.push(rest.slice(open, braceMatch(rest, open)));
      }
    });
  }
  var direct = bodies.join("\n");
  var calls = [];
  var cr = /(?:^|[^\w$.])([A-Za-z_$][\w$]*)\s*\(/g, c;
  while ((c = cr.exec(direct))) if (calls.indexOf(c[1]) === -1 && !/^(if|for|while|function|return|switch|catch|fetch)$/.test(c[1])) calls.push(c[1]);
  return direct + "\n" + calls.map(function (n) { return functionBody(code, n); }).join("\n");
}

/* ── the controls a page shows ─────────────────────────────────────────────── */
function controlsOf(markup) {
  var found = [];
  var re = /<(button|a)\b([^>]*)>([\s\S]*?)<\/\1>/gi, m;
  while ((m = re.exec(markup))) {
    var tag = m[2];
    var label = cleanLabel(attr("<x" + tag + ">", "aria-label") || textOf(m[3]));
    if (!label) continue;
    var id = attr("<x" + tag + ">", "id");
    var role = attr("<x" + tag + ">", "role");
    var kind = role === "tab" ? "t" : m[1].toLowerCase() === "a" ? "l" : "b";
    var href = m[1].toLowerCase() === "a" ? attr("<x" + tag + ">", "href") : null;
    if (kind === "l" && (!href || /^(https?:|mailto:|tel:|javascript:|#)/i.test(href))) continue;
    found.push({ id: id, href: href, label: label, kind: kind, onclick: attr("<x" + tag + ">", "onclick") });
  }
  // Elements with role="tab" that are not buttons or links (a div or li tab).
  var tr = /<(div|li|span)\b([^>]*\srole="tab"[^>]*)>([\s\S]*?)<\/\1>/gi;
  while ((m = tr.exec(markup))) {
    var tl = cleanLabel(attr("<x" + m[2] + ">", "aria-label") || textOf(m[3]));
    if (tl) found.push({ id: attr("<x" + m[2] + ">", "id"), href: null, label: tl, kind: "t", onclick: attr("<x" + m[2] + ">", "onclick") });
  }
  return found;
}

/* The agent pages build their task launcher and tools in agent-profile.js from
   window.AGENT_PROFILE_CONFIG; those controls are as real as the markup's. */
function agentControls(html, vm) {
  var m = /window\.AGENT_PROFILE_CONFIG = (\{[\s\S]*?\n\});/.exec(html);
  if (!m) return null;
  var cfg;
  try { cfg = vm.runInNewContext("(" + m[1] + ")"); } catch (e) { return null; }
  var out = [{ sel: "#apLaunchBtn", label: "Launch Task", kind: "b", route: "POST /api/ai/tasks" }];
  (cfg.tools || []).forEach(function (t) {
    if (!t || !t.id || t.adminOnly) return;
    var route = "POST /api/agents/" + cfg.agentType + "/" + t.id;
    out.push({ sel: "[data-tool-toggle=\"" + t.id + "\"]", label: cleanLabel(t.label || t.id), kind: "t", route: null });
    out.push({ sel: "[data-tool-run=\"" + t.id + "\"]", label: cleanLabel(t.runLabel || "Run"), kind: "b", route: route });
  });
  return out;
}

/* ── the guide's tips ──────────────────────────────────────────────────────── */
function guideTips(guide, vm) {
  var i = guide.indexOf("var PAGE_GUIDANCE = {");
  var j = guide.indexOf("\n  };", i);
  if (i === -1 || j === -1) return {};
  try { return vm.runInNewContext("(" + guide.slice(guide.indexOf("{", i), j + 4) + ")"); } catch (e) { return {}; }
}

/* ── the inputs hash ───────────────────────────────────────────────────────────
   Over exactly what the map is built from: every page read, every local script
   read, and the route table read from server.js (not server.js itself, so an
   edit elsewhere in that file does not make the map stale). Sorted by name, so
   the order a directory lists in cannot change it. */
function inputsHash(inputs) {
  var h = crypto.createHash("sha256");
  Object.keys(inputs).sort().forEach(function (name) {
    h.update(name + "\u0000" + inputs[name] + "\u0000");
  });
  return h.digest("hex");
}

/* build({ pages, readFront, server }) -> the map.
     pages      the frontend's .html files, as paths relative to its root;
     readFront  rel path -> its text (LF), or null when it does not exist;
     server     server.js's text. */
function buildAppMap(opts) {
  var vm = require("vm");
  var routes = serverRoutes(opts.server);
  var inputs = {};
  var guideSrc = opts.readFront("scripts/termaximus-guide.js") || "";
  inputs["scripts/termaximus-guide.js"] = guideSrc;
  var tips = guideTips(guideSrc, vm);
  var used = {};
  var pages = {};
  opts.pages.slice().sort().forEach(function (rel) {
    var file = rel.split("/").pop();
    if (MAP_SKIP.test(file) || pages[file]) return;
    var html = opts.readFront(rel);
    if (html == null) return;
    inputs[rel] = html;
    var parts = splitPage(html);
    var code = parts.inline;
    localScriptsOf(html).forEach(function (src) {
      var s = opts.readFront(src);
      if (s == null) return;
      inputs[src] = s;
      if (src !== "scripts/termaximus-guide.js" && src !== "scripts/termaximus-presence.js") code += "\n;\n" + s;
    });
    var titleM = /<title>([\s\S]*?)<\/title>/i.exec(parts.markup);
    var h1M = /<h1\b[^>]*>([\s\S]*?)<\/h1>/i.exec(parts.markup);
    var raw = controlsOf(parts.markup);
    // A selector is kept only when it is stable and names one element.
    var idCount = {}, hrefCount = {};
    raw.forEach(function (c) {
      if (c.id) idCount[c.id] = (idCount[c.id] || 0) + 1;
      if (c.href) hrefCount[c.href] = (hrefCount[c.href] || 0) + 1;
    });
    var controls = [];
    var seen = {};
    raw.forEach(function (c) {
      var sel = null;
      if (c.id && idCount[c.id] === 1 && /^[A-Za-z][\w-]*$/.test(c.id)) sel = "#" + c.id;
      else if (!c.id && c.kind === "l" && hrefCount[c.href] === 1 && c.href.indexOf("\"") === -1) sel = "a[href=\"" + c.href + "\"]";
      if (!sel || seen[sel]) return;
      seen[sel] = true;
      var r = c.kind === "l" ? null : controlRoute(routesIn(handlerCode(code, c.id, c.onclick), routes), c.label);
      var row = [sel, c.label, c.kind];
      if (r) { row.push(r); used[r] = true; }
      controls.push(row);
    });
    (agentControls(html, vm) || []).forEach(function (c) {
      if (seen[c.sel] || !c.label) return;
      seen[c.sel] = true;
      var row = [c.sel, c.label, c.kind];
      var known = c.route && routes.some(function (r) { return r.method + " " + r.path === c.route; });
      if (known) { row.push(c.route); used[c.route] = true; }
      controls.push(row);
    });
    var entry = { p: "/" + rel, t: textOf(titleM ? titleM[1] : ""), h: textOf(h1M ? h1M[1] : ""), c: controls };
    if (tips[file]) entry.g = tips[file];
    pages[file] = entry;
  });
  var routeTable = {};
  routes.forEach(function (r) {
    var key = r.method + " " + r.path;
    if (used[key]) routeTable[key] = r.gate;
  });
  // The route table is an input too: a gate that changes makes the map stale.
  inputs["server.js#routes"] = routes.map(function (r) { return r.method + " " + r.path + " " + r.gate; }).join("\n");
  return { v: MAP_VERSION, inputs: inputsHash(inputs), routes: routeTable, pages: pages };
}

// The map as written to lib/appMap.json: one line, sorted keys as built.
function serializeAppMap(map) {
  return JSON.stringify(map) + "\n";
}

module.exports = {
  buildAppMap,
  serializeAppMap,
  inputsHash,
  serverRoutes,
  routesIn,
  controlsOf,
  secretLike,
  MAP_SKIP,
  MAP_VERSION
};
