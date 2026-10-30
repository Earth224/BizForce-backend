"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkApiBase — every request the frontend makes to an /api/ path goes to
   the API's one base, the Railway backend.

   WHY THIS EXISTS. Settings → Theme → "Save as…" answered "That did not work.
   Try again." on bizforceai.net, with a 404 for api/themes in the console.
   The studio (scripts/bf-theme-studio.js) built its URLs from
   window.API_URL, falling back to "": settings.html declares its API_URL
   inside its own function, so window.API_URL was unset and every theme
   request was a relative "/api/themes", sent to Netlify, which has no such
   route. The checks did not see it because their fake page declared a global
   API_URL that the real page does not.

   THE RULE. A base is the API's origin
   ("https://dynamic-prosperity-production-5382.up.railway.app"), a name
   declared in the same script (or as a global by another script of the same
   page) whose value is that origin, `(typeof window.API_URL === "string" &&
   window.API_URL) || <base>`, a call to a function that returns a base, or
   BFTheme.apiOrigin(). window.API_URL on its own is NOT a base: a page may
   keep its API_URL inside a function, as settings.html does. Every string
   literal in a page or script that begins with "/api" must be:
     - joined to a base:            BASE + "/api/..."   (or BASE + (c ? "/api/a" : "/api/b"));
     - given to a wrapper whose parameter is joined to a base inside it
       (function apiFetch(path) { return fetch(API_URL + path, ...) });
     - assigned to a name that is only ever joined to a base or given to such
       a wrapper, never fetched on its own;
     - or not a request at all: compared, or searched for (indexOf, startsWith…).
   Anything else is an OFFENDER, with its file and line. Pages and scripts
   are read with a small tokenizer (strings, comments, templates and regular
   expressions are told apart), so a "/api/" in a comment counts for nothing.
   Every fetch( in the frontend is also listed by the shape of its URL, and
   every one whose URL holds an "/api/" literal is covered by the rule.

   Also: no HTML attribute (href, src, action, formaction) points at /api/,
   and every literal Railway address in the frontend is that one origin.

   MUTATE=<name> edits a frontend file IN MEMORY; MUTATE=all runs each in its
   own process and passes only if every one fails at least one check. A
   mutation whose search text does not match exactly once is an ERROR.
   BIZFORCE_FRONTEND_DIR overrides the frontend location. No network.
   ══════════════════════════════════════════════════════════════════════════ */
const fs = require("fs"), path = require("path");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const ORIGIN = "https://dynamic-prosperity-production-5382.up.railway.app";
const STUDIO = "scripts/bf-theme-studio.js", THEME = "scripts/bf-theme.js";

const MUTATIONS = {
  // the live bug: the studio's base falls back to "" (a relative /api/themes)
  "relative-themes-url": [[STUDIO, "  function api() { return T.apiOrigin(); }",
    "  function api() { return (typeof window.API_URL === \"string\" && window.API_URL) || \"\"; }"]],
  // a page fetching a relative /api/ path
  "relative-fetch-literal": [["settings.html", "fetch(API_URL + \"/api/billing/portal\"", "fetch(\"/api/billing/portal\""]],
  // a wrapper that drops the base
  "wrapper-drops-base": [["crm.html", "  return fetch(API_URL + path, opts);", "  return fetch(path, opts);"]],
  // the page's own origin used as the base (Netlify, again)
  "page-origin-as-base": [[THEME, "win.fetch(origin + \"/api/themes\"", "win.fetch(win.location.origin + \"/api/themes\""]],
  // the base read from window.API_URL alone, with no fallback to the origin
  "window-api-url-alone": [["scripts/bf-support.js", "  var API = (typeof root.API_URL === \"string\" && root.API_URL) || \"" + ORIGIN + "\";",
    "  var API = root.API_URL;"]]
};
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 1200) + "]" : "")); }
}

/* ── the frontend's files ───────────────────────────────────────────────── */
if (!fs.existsSync(path.join(FRONTEND, "settings.html"))) { console.log("    FAIL  frontend not found at " + FRONTEND + " (set BIZFORCE_FRONTEND_DIR)"); process.exit(1); }
const SKIP_DIRS = new Set(["node_modules", ".git", "icons", ".netlify"]);
function walk(dir, out) {
  for (const f of fs.readdirSync(path.join(FRONTEND, dir))) {
    const rel = dir ? dir + "/" + f : f;
    const st = fs.statSync(path.join(FRONTEND, rel));
    if (st.isDirectory()) { if (!SKIP_DIRS.has(f) && f[0] !== ".") walk(rel, out); }
    else if (/\.(html|js)$/.test(f)) out.push(rel);
  }
  return out;
}
const FILES = {};
walk("", []).forEach(f => { FILES[f] = fs.readFileSync(path.join(FRONTEND, f), "utf8").replace(/\r\n/g, "\n"); });
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE);
}

/* ── a small tokenizer ──────────────────────────────────────────────────── */
const REGEX_AFTER = /^(return|typeof|case|do|else|in|of|new|delete|void|throw|instanceof|yield|await)$/;
const PUNCT = /^(>>>=|===|!==|\.\.\.|\*\*=|<<=|>>=|>>>|==|!=|<=|>=|=>|&&|\|\||\?\?|\?\.|\+\+|--|\+=|-=|\*=|\/=|%=|&=|\|=|\^=|\*\*|<<|>>|[{}()\[\];,.<>+\-*%&|^!~?:=\/@#])/;
function tokenize(src, offset, out) {
  out = out || [];
  offset = offset || 0;
  let i = 0;
  const n = src.length;
  const regexOk = () => {
    const p = out[out.length - 1];
    if (!p) return true;
    if (p.t === "punct") return !/^[)\]}]$/.test(p.v);
    if (p.t === "id") return REGEX_AFTER.test(p.v);
    return false;
  };
  while (i < n) {
    const c = src[i];
    if (c === " " || c === "\t" || c === "\n" || c === "\r") { i++; continue; }
    if (c === "/" && src[i + 1] === "/") { while (i < n && src[i] !== "\n") i++; continue; }
    if (c === "/" && src[i + 1] === "*") { const e = src.indexOf("*/", i + 2); i = e < 0 ? n : e + 2; continue; }
    if (c === "<" && src.startsWith("<!--", i)) { while (i < n && src[i] !== "\n") i++; continue; }
    if (c === "\"" || c === "'") {
      let j = i + 1, v = "";
      while (j < n && src[j] !== c && src[j] !== "\n") { if (src[j] === "\\") { v += src[j + 1]; j += 2; } else v += src[j++]; }
      out.push({ t: "str", v, at: offset + i });
      i = j + 1; continue;
    }
    if (c === "`") {
      // the text before the first ${ is the template's head; each ${...} is tokenized in place
      let j = i + 1, head = "", inHead = true;
      const start = out.length;
      out.push({ t: "tpl", v: "", at: offset + i });
      while (j < n && src[j] !== "`") {
        if (src[j] === "\\") { if (inHead) head += src[j + 1]; j += 2; continue; }
        if (src[j] === "$" && src[j + 1] === "{") {
          inHead = false;
          let d = 1, k = j + 2;
          while (k < n && d > 0) {
            const ch = src[k];
            if (ch === "\"" || ch === "'" || ch === "`") { const q = ch; k++; while (k < n && src[k] !== q) { if (src[k] === "\\") k++; k++; } }
            else if (ch === "{") d++;
            else if (ch === "}") d--;
            k++;
          }
          out.push({ t: "punct", v: "(", at: offset + j });
          tokenize(src.slice(j + 2, k - 1), offset + j + 2, out);
          out.push({ t: "punct", v: ")", at: offset + k - 1 });
          j = k; continue;
        }
        if (inHead) head += src[j];
        j++;
      }
      out[start].v = head;
      i = j + 1; continue;
    }
    if (c === "/" && regexOk()) {
      let j = i + 1, cls = false;
      while (j < n) {
        const d = src[j];
        if (d === "\\") { j += 2; continue; }
        if (d === "\n") break;
        if (d === "[") cls = true; else if (d === "]") cls = false; else if (d === "/" && !cls) break;
        j++;
      }
      j++;
      while (j < n && /[a-z]/i.test(src[j])) j++;
      out.push({ t: "regex", v: src.slice(i, j), at: offset + i });
      i = j; continue;
    }
    if (/[A-Za-z_$]/.test(c)) { let j = i; while (j < n && /[\w$]/.test(src[j])) j++; out.push({ t: "id", v: src.slice(i, j), at: offset + i }); i = j; continue; }
    if (/[0-9]/.test(c)) { let j = i; while (j < n && /[\w.]/.test(src[j])) j++; out.push({ t: "num", v: src.slice(i, j), at: offset + i }); i = j; continue; }
    const m = PUNCT.exec(src.slice(i, i + 4));
    const v = m ? m[1] : c;
    out.push({ t: "punct", v, at: offset + i });
    i += v.length;
  }
  return out;
}

/* A page's inline scripts (no src, not data), each with its offset in the file;
   a .js file is one script. */
function scriptsOf(file, text) {
  if (file.endsWith(".js")) return [{ code: text, at: 0 }];
  const out = [], re = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(text))) {
    if (/\bsrc\s*=/.test(m[1])) continue;
    const type = /\btype\s*=\s*["']?([^"'\s>]+)/i.exec(m[1]);
    if (type && !/^(text\/javascript|module|application\/javascript)$/i.test(type[1])) continue;
    out.push({ code: m[2], at: m.index + m[0].indexOf(">") + 1 });
  }
  return out;
}
const lineOf = (text, at) => text.slice(0, at).split("\n").length;

/* ── reading a script's tokens ──────────────────────────────────────────── */
const OPEN = { "(": ")", "[": "]", "{": "}" };
const CLOSE = { ")": "(", "]": "[", "}": "{" };
function matchBack(toks, k) {    // toks[k] is a closer: the index of its opener
  let d = 0;
  for (let j = k; j >= 0; j--) {
    if (toks[j].t !== "punct") continue;
    if (CLOSE[toks[j].v]) d++;
    else if (OPEN[toks[j].v]) { d--; if (d === 0) return j; }
  }
  return -1;
}
function matchFwd(toks, k) {     // toks[k] is an opener: the index of its closer
  let d = 0;
  for (let j = k; j < toks.length; j++) {
    if (toks[j].t !== "punct") continue;
    if (OPEN[toks[j].v]) d++;
    else if (CLOSE[toks[j].v]) { d--; if (d === 0) return j; }
  }
  return toks.length - 1;
}
const isP = (t, v) => t && t.t === "punct" && t.v === v;
const isId = (t, v) => t && t.t === "id" && (v === undefined || t.v === v);
const memberBefore = (toks, j) => isP(toks[j - 1], ".") || isP(toks[j - 1], "?.");

/* The member chain ending at toks[e] (an id): ["window", "BFTheme", "apiOrigin"]. */
function chainEndingAt(toks, e) {
  const names = [toks[e].v];
  let j = e;
  while (memberBefore(toks, j) && isId(toks[j - 2])) { names.unshift(toks[j - 2].v); j -= 2; }
  return { names, start: j };
}

/* Declarations: var/let/const NAME = <rhs>, with the rhs's token range and
   whether it sits at the script's top level (outside every function). */
function declarations(toks) {
  const out = [];
  let fnDepth = 0;
  const fnOpens = [];
  for (let k = 0; k < toks.length; k++) {
    const t = toks[k];
    if (isP(t, "{")) {
      // a function body opens when a "{" follows a parameter list after "function", or an "=>"
      const prev = toks[k - 1];
      let isFn = isP(prev, "=>");
      if (isP(prev, ")")) { const o = matchBack(toks, k - 1); const b = toks[o - 1], b2 = toks[o - 2]; isFn = isId(b, "function") || isId(b2, "function") || (isId(b) && isP(toks[o - 2], "}")) || (isId(b) && !REGEX_AFTER.test(b.v) && !/^(if|for|while|switch|catch|with)$/.test(b.v) && (isP(b2, "}") || isP(b2, ";") || isP(b2, ",") || isP(b2, "{") || isId(b2, "async") || isId(b2, "get") || isId(b2, "set"))); }
      fnOpens.push(isFn);
      if (isFn) fnDepth++;
      continue;
    }
    if (isP(t, "}")) { if (fnOpens.pop()) fnDepth--; continue; }
    if (!(isId(t, "var") || isId(t, "let") || isId(t, "const"))) continue;
    let j = k + 1;
    for (;;) {
      if (!isId(toks[j]) || !isP(toks[j + 1], "=")) break;
      const name = toks[j].v, from = j + 2;
      let e = from, d = 0;
      for (; e < toks.length; e++) {
        const u = toks[e];
        if (u.t === "punct") {
          if (OPEN[u.v]) d++;
          else if (CLOSE[u.v]) { if (d === 0) break; d--; }
          else if (d === 0 && (u.v === ";" || u.v === ",")) break;
        }
        if (d === 0 && e > from && (isId(u, "var") || isId(u, "let") || isId(u, "const") || isId(u, "function"))) break;
      }
      out.push({ name, from, to: e, top: fnDepth === 0 });
      if (isP(toks[e], ",")) { j = e + 1; continue; }
      break;
    }
  }
  return out;
}

/* Functions: function NAME(params) {...}, NAME = function (params) {...},
   NAME = (params) => {...} — with their parameter names and body range. */
function functions(toks) {
  const out = [];
  for (let k = 0; k < toks.length; k++) {
    let name = null, po = -1;
    if (isId(toks[k], "function") && isId(toks[k + 1]) && isP(toks[k + 2], "(")) { name = toks[k + 1].v; po = k + 2; }
    else if (isId(toks[k]) && isP(toks[k + 1], "=") && !memberBefore(toks, k)) {
      let j = k + 2;
      if (isId(toks[j], "async")) j++;
      if (isId(toks[j], "function")) { j++; if (isId(toks[j])) j++; }
      if (isP(toks[j], "(")) {
        const pc = matchFwd(toks, j);
        if (isP(toks[pc + 1], "{") && (isId(toks[j - 1], "function") || isId(toks[j - 2], "function"))) { name = toks[k].v; po = j; }
        else if (isP(toks[pc + 1], "=>")) { name = toks[k].v; po = j; }
      }
    }
    if (!name) continue;
    const pc = matchFwd(toks, po);
    const params = [];
    let d = 0, expect = true;
    for (let j = po + 1; j < pc; j++) {
      const u = toks[j];
      if (u.t === "punct" && OPEN[u.v]) d++;
      else if (u.t === "punct" && CLOSE[u.v]) d--;
      else if (d === 0 && isP(u, ",")) { expect = true; continue; }
      if (d === 0 && expect && isId(u)) { params.push(u.v); expect = false; }
      else if (d === 0 && expect) { params.push(null); expect = false; }
    }
    let bo = pc + 1;
    if (isP(toks[bo], "=>")) bo++;
    const bc = isP(toks[bo], "{") ? matchFwd(toks, bo) : (() => { let e = bo, dd = 0; for (; e < toks.length; e++) { const u = toks[e]; if (u.t === "punct") { if (OPEN[u.v]) dd++; else if (CLOSE[u.v]) { if (dd === 0) break; dd--; } else if (dd === 0 && (u.v === ";" || u.v === ",")) break; } } return e; })();
    out.push({ name, params, from: bo, to: bc });
  }
  return out;
}

/* ── one page: its scripts, its bases, its wrappers, and the judgement ───── */
const GLOBAL_STRING_TESTS = /^(indexOf|lastIndexOf|startsWith|endsWith|includes|test|match|search|replace|split|exec)$/;
function analyse(file) {
  const text = FILES[file];
  /* The page's names. A base or wrapper declared at a script's top level is
     a global every script of the page can use; one declared inside a
     function is that script's alone (settings.html's API_URL is such a name,
     and bf-theme-studio.js cannot see it). */
  const page = { bases: new Set(), baseFns: new Set(), wrappers: {} };
  const blocks = scriptsOf(file, text).map(sc => {
    const toks = tokenize(sc.code, sc.at);
    const b = { toks, decls: declarations(toks), fns: functions(toks), bases: new Set(), baseFns: new Set(), wrappers: {}, bfTheme: new Set(["BFTheme"]) };
    b.decls.forEach(d => { if (d.to - d.from === 3 && isId(toks[d.from], "window") && isP(toks[d.from + 1], ".") && isId(toks[d.from + 2], "BFTheme")) b.bfTheme.add(d.name); });
    b.topNames = new Set(b.decls.filter(d => d.top).map(d => d.name));
    return b;
  });
  const wrapperOf = (b, name) => b.wrappers[name] || page.wrappers[name];

  function tools(b) {
    const toks = b.toks;
    function baseAt(e) {
      const t = toks[e];
      if (!t) return false;
      if (t.t === "str") return t.v === ORIGIN;
      if (t.t === "id") {
        if (memberBefore(toks, e)) return false;           // window.API_URL alone is not a base
        return b.bases.has(t.v) || (!b.decls.some(d => d.name === t.v) && page.bases.has(t.v));
      }
      if (isP(t, ")")) {
        const o = matchBack(toks, e);
        if (o < 1) return false;
        if (!isId(toks[o - 1]) || /^(if|while|for|switch|return|typeof)$/.test(toks[o - 1].v)) return rhsIsBase(o + 1, e);
        const ch = chainEndingAt(toks, o - 1);
        if (ch.names.length === 1) return b.baseFns.has(ch.names[0]) || page.baseFns.has(ch.names[0]);
        return ch.names[ch.names.length - 1] === "apiOrigin" && ch.names.slice(0, -1).some(nm => b.bfTheme.has(nm));
      }
      return false;
    }
    function atomStart(e) {
      const t = toks[e];
      if (!t) return -1;
      if (t.t === "id") return chainEndingAt(toks, e).start;
      if (isP(t, ")")) { const o = matchBack(toks, e); if (o > 0 && isId(toks[o - 1]) && !/^(if|while|for|switch|return|typeof)$/.test(toks[o - 1].v)) return chainEndingAt(toks, o - 1).start; return o; }
      return e;
    }
    // a whole expression toks[from..to) is a base: a base atom, or <anything> || <base atom>
    function rhsIsBase(from, to) {
      if (to <= from || !baseAt(to - 1)) return false;
      const st = atomStart(to - 1);
      return st === from || (st > from && isP(toks[st - 1], "||"));
    }
    // the call toks[j] is an argument of: its callee and the argument index
    function enclosingCall(j) {
      let d = 0, index = 0;
      for (let x = j - 1; x >= 0; x--) {
        const u = toks[x];
        if (u.t !== "punct") continue;
        if (CLOSE[u.v]) d++;
        else if (OPEN[u.v]) {
          if (d > 0) { d--; continue; }
          if (u.v !== "(" || !isId(toks[x - 1])) return null;
          if (/^(if|for|while|switch|catch|function|return|typeof)$/.test(toks[x - 1].v)) return null;
          const ch = chainEndingAt(toks, x - 1);
          return { name: ch.names[ch.names.length - 1], chain: ch.names, index, at: x };
        } else if (d === 0 && u.v === ",") index++;
        else if (d === 0 && (u.v === ";" || u.v === "=")) return null;
      }
      return null;
    }
    // the delimiter before the expression that holds toks[k]: an opener, "=", ",", ";", "=>" or return
    function contextOf(k) {
      let d = 0;
      for (let x = k - 1; x >= 0; x--) {
        const u = toks[x];
        if (u.t === "punct") {
          if (CLOSE[u.v]) { d++; continue; }
          if (OPEN[u.v]) { if (d > 0) { d--; continue; } return { tok: u, at: x }; }
          if (d > 0) continue;
          if (/^(=|\+=|,|;|=>)$/.test(u.v)) return { tok: u, at: x };
          continue;                                            // ?, :, +, ===, &&, ||, ! … are inside the expression
        }
        if (d === 0 && isId(u, "return")) return { tok: u, at: x };
      }
      return { tok: null, at: -1 };
    }
    function usedOnlyThroughBase(name) {
      let joined = 0, bare = 0;
      for (let j = 0; j < toks.length; j++) {
        if (!isId(toks[j], name) || memberBefore(toks, j) || isP(toks[j + 1], "=")) continue;
        if (isP(toks[j - 1], "+") && baseAt(j - 2)) { joined++; continue; }
        const call = enclosingCall(j);
        if (call && wrapperOf(b, call.name) && wrapperOf(b, call.name).has(call.index)) { joined++; continue; }
        if (call && call.name === "fetch") bare++;
      }
      return joined > 0 && bare === 0;
    }
    return { baseAt, atomStart, rhsIsBase, enclosingCall, contextOf, usedOnlyThroughBase };
  }
  blocks.forEach(b => { b.t = tools(b); });

  // to a fixed point across every script of the page: bases, base functions, wrappers
  for (let round = 0, grew = true; grew && round < 20; round++) {
    grew = false;
    blocks.forEach(b => {
      const toks = b.toks, T = b.t;
      b.decls.forEach(d => {
        if (b.bases.has(d.name) || !T.rhsIsBase(d.from, d.to)) return;
        b.bases.add(d.name); grew = true;
        if (d.top) page.bases.add(d.name);
      });
      b.fns.forEach(f => {
        if (b.baseFns.has(f.name)) return;
        const rets = [];
        if (!isP(toks[f.from], "{")) rets.push([f.from, f.to]);
        else for (let j = f.from + 1; j < f.to; j++) {
          if (!isId(toks[j], "return")) continue;
          let e = j + 1, d = 0;
          for (; e < f.to; e++) { const u = toks[e]; if (u.t === "punct") { if (OPEN[u.v]) d++; else if (CLOSE[u.v]) { if (d === 0) break; d--; } else if (d === 0 && u.v === ";") break; } }
          rets.push([j + 1, e]);
        }
        // a fallback to a string that is not an address ("" above all) is never a base
        const fallsToNonAddress = toks.slice(f.from, f.to).some((u, x, arr) => isP(u, "||") && arr[x + 1] && arr[x + 1].t === "str" && !/^https?:/.test(arr[x + 1].v));
        const isNull = ([a, z]) => z - a === 1 && isId(toks[a], "null");
        const ok = rets.length > 0 && !fallsToNonAddress && rets.some(r => !isNull(r)) && rets.every(r => isNull(r) || T.rhsIsBase(r[0], r[1]) ||
          // bf-theme.js and bf-session.js: return new URL(<base>, ...).origin
          (isId(toks[r[0]], "new") && isId(toks[r[0] + 1], "URL") && isP(toks[r[0] + 2], "(") && T.baseAt(r[0] + 3) && isP(toks[r[1] - 2], ".") && isId(toks[r[1] - 1], "origin")));
        if (ok) { b.baseFns.add(f.name); page.baseFns.add(f.name); grew = true; }
      });
      b.fns.forEach(f => {
        f.params.forEach((p, pi) => {
          if (!p || (b.wrappers[f.name] && b.wrappers[f.name].has(pi))) return;
          let ok = false;
          for (let j = f.from; j < f.to && !ok; j++) {
            if (!isId(toks[j], p) || memberBefore(toks, j)) continue;
            if (isP(toks[j - 1], "+") && T.baseAt(j - 2)) ok = true;
            else {
              const call = T.enclosingCall(j);
              if (call && call.name !== f.name && wrapperOf(b, call.name) && wrapperOf(b, call.name).has(call.index)) ok = true;
            }
          }
          if (!ok) return;
          (b.wrappers[f.name] = b.wrappers[f.name] || new Set()).add(pi);
          (page.wrappers[f.name] = page.wrappers[f.name] || new Set()).add(pi);
          grew = true;
        });
      });
    });
  }

  const findings = [], literals = [], fetches = [];
  blocks.forEach(b => {
    const toks = b.toks, T = b.t;
    const wraps = (name, index) => !!(wrapperOf(b, name) && wrapperOf(b, name).has(index));
    function atomEnd(k) {
      let e = k;
      while (isId(toks[e]) && (isP(toks[e + 1], ".") || isP(toks[e + 1], "?.")) && isId(toks[e + 2])) e += 2;
      if (isP(toks[e + 1], "(")) e = matchFwd(toks, e + 1);
      return e;
    }
    // every fetch( and the shape of its URL
    for (let k = 0; k < toks.length; k++) {
      if (!isId(toks[k], "fetch") || !isP(toks[k + 1], "(") || isId(toks[k - 1], "function")) continue;
      if (memberBefore(toks, k) && !["window", "win", "self", "globalThis", "w"].includes(toks[k - 2] && toks[k - 2].v)) continue;
      const a0 = k + 2;
      let e = a0, d = 0;
      for (; e < toks.length; e++) { const u = toks[e]; if (u.t === "punct") { if (OPEN[u.v]) d++; else if (CLOSE[u.v]) { if (d === 0) break; d--; } else if (d === 0 && u.v === ",") break; } }
      const lits = [];
      for (let x = a0; x < e; x++) if ((toks[x].t === "str" || toks[x].t === "tpl") && /^\/?api(\/|$)/.test(toks[x].v)) lits.push(toks[x].at);
      const first = toks[a0];
      const shape = first && first.t === "str" && first.v.indexOf(ORIGIN) === 0 ? "the origin, written out" :
        first && first.t === "str" && e === a0 + 1 ?
        (first.v.indexOf(ORIGIN) === 0 ? "the origin, written out" : "a literal " + JSON.stringify(first.v.slice(0, 30))) :
        isP(toks[atomEnd(a0) + 1], "+") ? (T.baseAt(atomEnd(a0)) ? "a base + a path" : "something else + a path") : "a name or expression";
      fetches.push({ file, line: lineOf(text, toks[k].at), shape, lits });
    }
    // every "/api" literal
    for (let k = 0; k < toks.length; k++) {
      const t = toks[k];
      if (!((t.t === "str" || t.t === "tpl") && /^\/?api(\/|$)/.test(t.v))) continue;
      const lit = { file, line: lineOf(text, t.at), v: t.v, at: t.at };
      literals.push(lit);
      const prev = toks[k - 1];
      if (isP(prev, "+")) {
        if (T.baseAt(k - 2)) lit.how = "joined to a base";
        else { const st = toks[T.atomStart(k - 2)]; lit.why = "joined to " + JSON.stringify(text.slice(st ? st.at : t.at, t.at).replace(/\s+/g, " ").slice(0, 60)) + ", which is not the API base"; }
      } else if (prev && prev.t === "punct" && /^(===|!==|==|!=)$/.test(prev.v)) {
        lit.how = "compared, not requested";
      } else {
        let cx = T.contextOf(k), c = cx.tok;
        // a literal in a list: what is the list kept in?
        let listName = null;
        if (isP(c, ",") || isP(c, "[")) {
          const open = isP(c, "[") ? cx.at : (() => { let d = 0; for (let x = cx.at; x >= 0; x--) { const u = toks[x]; if (u.t !== "punct") continue; if (CLOSE[u.v]) d++; else if (OPEN[u.v]) { if (d === 0) return u.v === "[" ? x : -1; d--; } } return -1; })();
          const lc = open > 0 ? T.contextOf(open) : null;
          if (lc && isP(lc.tok, "=") && isId(toks[lc.at - 1]) && !isId(toks[open - 1]) && !isP(toks[open - 1], ")")) listName = toks[lc.at - 1].v;
        }
        if (listName) {
          // a list of paths a script compares a request against (bf-session.js's EXEMPT_PATHS): never fetched, never joined
          const used = [];
          for (let j = 0; j < toks.length; j++) if (isId(toks[j], listName) && !memberBefore(toks, j) && !isP(toks[j + 1], "=")) used.push(j);
          const requested = used.some(j => isP(toks[j - 1], "+") || isP(toks[j + 1], "+") || (T.enclosingCall(j) || {}).name === "fetch" ||
            (isP(toks[j + 1], "[") && (T.enclosingCall(j) || {}).name === "fetch"));
          const tested = used.length > 0 && used.every(j => (isP(toks[j + 1], ".") && isId(toks[j + 2]) && /^(length|indexOf|includes|some|every|filter|find|forEach)$/.test(toks[j + 2].v)) ||
            (isP(toks[j + 1], "[") && GLOBAL_STRING_TESTS.test((T.enclosingCall(j) || {}).name || "")));
          if (!requested && tested) lit.how = "in " + listName + ", a list of paths it compares requests against, never requested";
          else lit.why = "in the list " + listName + ", which is used as a request";
        } else if (isP(c, "(") || isP(c, ",")) {
          const call = T.enclosingCall(k);
          if (isP(c, "(") && isP(toks[cx.at - 1], "+") && T.baseAt(cx.at - 2)) lit.how = "joined to a base";
          else if (!call) lit.why = "inside a bracket or list that is not a call";
          else if (call.name === "fetch") lit.why = "fetched as a relative path: it goes to the page's own origin (Netlify), not the API";
          else if (wraps(call.name, call.index)) lit.how = "given to " + call.name + "(), which joins it to a base";
          else if (GLOBAL_STRING_TESTS.test(call.name)) lit.how = "searched for, not requested";
          else lit.why = "given to " + call.chain.join(".") + "() (argument " + (call.index + 1) + "), which does not join it to the API base";
        } else if ((isP(c, "=") || isP(c, "+=")) && isId(toks[cx.at - 1])) {
          const name = toks[cx.at - 1].v;
          if (T.usedOnlyThroughBase(name)) lit.how = "kept in " + name + ", which is only ever joined to a base";
          else lit.why = "kept in " + name + ", which is used without the API base";
        } else lit.why = "not joined to the API base (after " + JSON.stringify(c ? c.v : "the start") + ")";
      }
      if (lit.why) findings.push(file + ":" + lit.line + "  " + JSON.stringify(t.v.slice(0, 50)) + " " + lit.why);
    }
  });
  return { findings, literals, fetches };
}

/* ── run it over the frontend ───────────────────────────────────────────── */
console.log("\n══ 1. every /api/ literal in every page and script goes through the API's one base ══");
const all = { findings: [], literals: [], fetches: [] };
const order = Object.keys(FILES).sort();
for (const f of order) {
  const r = analyse(f);
  all.findings.push(...r.findings); all.literals.push(...r.literals); all.fetches.push(...r.fetches);
}
const filesWithApi = new Set(all.literals.map(l => l.file));
check("1. the tokenizer read " + order.length + " pages and scripts, and found " + all.literals.length + " \"/api\" literals in " + filesWithApi.size + " of them",
  order.length > 80 && all.literals.length > 300 && filesWithApi.size > 40, order.length + " / " + all.literals.length);
check("1. every one is joined to the API base, given to a wrapper that joins it, kept in a name only ever joined to it, or not a request: no offender",
  all.findings.length === 0, all.findings.length + " offender(s):\n      " + all.findings.join("\n      "));
const how = {};
all.literals.filter(l => l.how).forEach(l => { const k = l.how.replace(/given to \w+\(\)/, "given to a wrapper").replace(/kept in \w+/, "kept in a name"); how[k] = (how[k] || 0) + 1; });
console.log("      " + Object.keys(how).sort().map(k => how[k] + " " + k).join("\n      "));

// the studio, by name: its theme requests are among the judged literals, and each goes through a base
const studioLits = all.literals.filter(l => l.file === STUDIO);
check("1. the theme studio's " + studioLits.length + " theme paths (GET/POST/PUT/DELETE /api/themes…, the photo) each go through the base",
  studioLits.length >= 8 && studioLits.every(l => l.how), studioLits.filter(l => !l.how).map(l => l.line + " " + l.why).join("; "));
const themeLits = all.literals.filter(l => l.file === THEME);
check("1. bf-theme.js's GET /api/themes goes through the base", themeLits.length === 1 && !!themeLits[0].how, JSON.stringify(themeLits));
check("1. ... and the studio's base is bf-theme.js's apiOrigin, never window.API_URL with an empty fallback",
  /function api\(\) \{ return T\.apiOrigin\(\); \}/.test(FILES[STUDIO]) && !/API_URL[^\n]*\|\|\s*""/.test(FILES[STUDIO]) &&
  /apiOrigin: function \(\) \{ return apiOrigin\(window\); \}/.test(FILES[THEME]));

console.log("\n══ 2. every fetch( in the frontend, by the shape of its URL ══");
const shapes = {};
all.fetches.forEach(f => { shapes[f.shape] = (shapes[f.shape] || 0) + 1; });
console.log("      " + Object.keys(shapes).sort().map(k => shapes[k] + " " + k).join("\n      "));
console.log("      not a base + a path: " + all.fetches.filter(f => !/^(a base \+ a path|the origin, written out)$/.test(f.shape)).map(f => f.file + ":" + f.line).join(", "));
const apiFetches = all.fetches.filter(f => f.lits.length);
const passed = new Set(all.literals.filter(l => l.how).map(l => l.file + "@" + l.at));
const unjudged = apiFetches.filter(f => !f.lits.every(at => passed.has(f.file + "@" + at)));
check("2. every fetch( whose URL holds an \"/api\" literal (" + apiFetches.length + ") is judged above, and passes",
  apiFetches.length > 200 && unjudged.length === 0, unjudged.slice(0, 10).map(f => f.file + ":" + f.line).join(", "));
check("2. no fetch( is of a relative path or the page's own origin", !all.fetches.some(f => /^a literal "\/?api/.test(f.shape)) &&
  !Object.keys(FILES).some(f => /fetch\(\s*(window\.|win\.)?location\.origin/.test(FILES[f])));

console.log("\n══ 3. no other way to the wrong place ══");
const attrHits = [];
Object.keys(FILES).filter(f => f.endsWith(".html")).forEach(f => {
  const re = /\b(href|src|action|formaction)\s*=\s*["']\/?api\//gi;
  let m;
  while ((m = re.exec(FILES[f]))) attrHits.push(f + ":" + lineOf(FILES[f], m.index));
});
check("3. no HTML attribute (href, src, action, formaction) points at /api/", attrHits.length === 0, attrHits.join(", "));
const otherRailway = [];
Object.keys(FILES).forEach(f => {
  const re = /https:\/\/[a-z0-9.-]*railway\.app/gi;
  let m;
  while ((m = re.exec(FILES[f]))) if (m[0] !== ORIGIN) otherRailway.push(f + ":" + lineOf(FILES[f], m.index) + " " + m[0]);
});
check("3. every Railway address in the frontend is the one API origin", otherRailway.length === 0, otherRailway.join(", "));
const fallbacks = Object.keys(FILES).filter(f => /API_ORIGIN_FALLBACK\s*=\s*"/.test(FILES[f]));
check("3. each script's last-resort origin (API_ORIGIN_FALLBACK, in " + fallbacks.length + " scripts) is that origin",
  fallbacks.length >= 3 && fallbacks.every(f => new RegExp("API_ORIGIN_FALLBACK\\s*=\\s*\"" + ORIGIN.replace(/[.]/g, "\\.") + "\"").test(FILES[f])), fallbacks.join(", "));
const tokOk = (() => {
  const t = tokenize("var a = /[\"']/g; // \"/api/x\"\n/* '/api/y' */ var b = x / 2 / \"/api/z\"; var c = `${API_URL}/api/t`; var d = `/api/u`;");
  const strs = t.filter(u => u.t === "str" || u.t === "tpl").map(u => u.v);
  // a template's head is the text before its first ${: "" for `${API_URL}/api/t`, "/api/u" for `/api/u`
  return JSON.stringify(strs) === JSON.stringify(["/api/z", "", "/api/u"]) || JSON.stringify(strs);
})();
check("3. the tokenizer tells a regular expression, a division, a comment and a template apart", tokOk === true, tokOk);

console.log("\n" + (failures === 0 ? "ALL CHECKS PASSED" : "CHECKS FAILED") + " — " + passes + " passed, " + failures + " failed");
process.exit(failures === 0 ? 0 : 1);
