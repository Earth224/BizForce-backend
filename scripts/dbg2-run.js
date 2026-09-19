"use strict";
/* For every per-agent tool route: extracts the route (app.post call) plus the
   transitive closure of top-level helpers/constants it uses from server.js —
   working copy AND git HEAD — and runs both in vm contexts with a fake Supabase
   and a stubbed callAnthropicText. No network, no database.

   Usage: node tool-run-all.test.js [route ...]   (default: all 29) */
const fs = require("fs");
const vm = require("vm");
const assert = require("assert");
const { execSync } = require("child_process");

const REPO = "C:/Users/ALGORITHM/BizForce-backend";
const after = fs.readFileSync(REPO + "/server.js", "utf8");
const before = execSync("git show HEAD:server.js", { cwd: REPO, maxBuffer: 64 * 1024 * 1024 }).toString("utf8");

/* ── extraction ─────────────────────────────────────────────────────────── */
function braceMatch(src, openIdx) {
  let depth = 0, i = openIdx;
  for (; i < src.length; i++) {
    const c = src[i];
    if (c === "{" || c === "[" || c === "(") depth++;
    else if (c === "}" || c === "]" || c === ")") { depth--; if (depth === 0) return i + 1; }
    else if (c === '"' || c === "'" || c === "`") { const q = c; i++; while (i < src.length && src[i] !== q) { if (src[i] === "\\") i++; i++; } }
    else if (c === "/" && src[i + 1] === "*") { i = src.indexOf("*/", i) + 1; }
    else if (c === "/" && src[i + 1] === "/") { i = src.indexOf("\n", i); }
  }
  return -1;
}
const DEF_CACHE = new Map();
function definitionOf(src, name) {
  const key = (src === after ? "A:" : "B:") + name;
  if (DEF_CACHE.has(key)) return DEF_CACHE.get(key);
  const v = definitionOfRaw(src, name); DEF_CACHE.set(key, v); return v;
}
function definitionOfRaw(src, name) {
  let m = new RegExp("^(?:async )?function " + name + "\\(", "m").exec(src);
  if (m) return src.slice(m.index, braceMatch(src, src.indexOf("{", m.index)));
  m = new RegExp("^(?:var|const|let) " + name + " = ", "m").exec(src);
  if (m) {
    const eq = m.index + m[0].length;
    // statement ends at the first ";\n" followed by a column-0 char or blank line
    let from = eq;
    for (;;) {
      const semi = src.indexOf(";\n", from);
      if (semi === -1) return null;
      const nextCh = src[semi + 2];
      if (nextCh === undefined || nextCh === "\n" || /[^\s]/.test(nextCh)) return src.slice(m.index, semi + 1);
      from = semi + 1;
    }
  }
  return null;
}
function routeCode(src, path) {
  const sig = 'app.post("/api/agents/' + path + '"';
  const start = src.indexOf(sig);
  assert(start > 0, "route not found " + path);
  const end = braceMatch(src, src.indexOf("{", start));
  assert.strictEqual(src.slice(end, end + 3), ");\n");
  return src.slice(start, end + 2);
}
const STUBS = new Set(["supabase", "nowIso", "console", "process", "require", "module", "callAnthropicText",
  "loadProfileForTool", "resolvePreferredLanguage", "buildLanguageInstruction", "buildAgentSystemPrompt",
  "requireAuth", "requireActiveSubscription", "aiLimiter", "app", "agentToolCatalogue", "AGENT_SYSTEM_PROMPTS",
  "Anthropic", "stripe", "fetch", "setTimeout", "setImmediate", "Buffer", "URL"]);
const CLOSURE_CACHE = new Map();
function closureFor(src, rootCode) {
  const key = (src === after ? "A:" : "B:") + rootCode.length + ":" + rootCode.slice(0, 80);
  if (CLOSURE_CACHE.has(key)) return CLOSURE_CACHE.get(key);
  const v = closureForRaw(src, rootCode); CLOSURE_CACHE.set(key, v); return v;
}
function closureForRaw(src, rootCode) {
  const have = new Map(); const queue = [...new Set(rootCode.match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || STUBS.has(name)) continue;
    const def = definitionOf(src, name);
    if (!def) continue;
    have.set(name, def);
    new Set(def.match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !STUBS.has(id)) queue.push(id); });
  }
  return [...have.values()].join("\n\n") + "\n\n" + rootCode;
}


const vm2 = require("vm");
const root = routeCode(after, "etsy/keyword-research");
const have = new Map(); const queue = [...new Set(root.match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
while (queue.length) { const n = queue.shift(); if (have.has(n) || STUBS.has(n)) continue; const d = definitionOf(after, n); if (!d) continue; have.set(n, d); new Set(d.match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(i => { if (!have.has(i) && !STUBS.has(i)) queue.push(i); }); }
for (const [n, d] of have) { try { new vm2.Script(d); } catch (e) { console.log("BAD DEF:", n, "->", e.message); console.log(d.slice(0, 300)); console.log("..."); console.log(d.slice(-200)); } }
console.log("defs:", [...have.keys()].join(", "));
