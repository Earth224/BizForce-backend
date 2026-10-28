"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   _envReads — every environment variable the running backend reads, found in
   the source rather than listed by hand (launch item #13). README.md must
   name each one; scripts/checkLaunchBlockB.js fails on any it does not.

   THE FILES are the ones that run in production: server.js and every local
   module it requires, followed through their own local requires (lib/,
   config/, the radars). scripts/ and the test-*.js files are not the server.

   A READ is any of these, outside comments:
     process.env.NAME, process.env["NAME"]
     env.NAME, e.NAME, (env || {}).NAME, (env || process.env).NAME
       — the lib/ modules take the environment as a parameter named env, and
         isProductionEnv calls it e
     chainLimit("NAME", …) and envVar: "NAME" — the two places a name is
       passed in and read with process.env[name]
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");

const REPO = path.join(__dirname, "..");

function stripComments(src) {
  let out = "", i = 0, q = null;
  while (i < src.length) {
    const c = src[i], n = src[i + 1];
    if (q) {
      out += c;
      if (c === "\\") { out += n || ""; i += 2; continue; }
      if (c === q) q = null;
      i++; continue;
    }
    if (c === '"' || c === "'" || c === "`") { q = c; out += c; i++; continue; }
    if (c === "/" && n === "/") { while (i < src.length && src[i] !== "\n") i++; continue; }
    if (c === "/" && n === "*") { const end = src.indexOf("*/", i + 2); i = end === -1 ? src.length : end + 2; out += " "; continue; }
    out += c; i++;
  }
  return out;
}

function runtimeFiles() {
  const seen = new Set(), order = [];
  (function visit(rel) {
    const abs = path.join(REPO, rel);
    if (seen.has(abs) || !fs.existsSync(abs)) return;
    seen.add(abs); order.push(rel);
    const src = fs.readFileSync(abs, "utf8");
    for (const m of src.matchAll(/require\(\s*["'](\.{1,2}\/[^"']+)["']\s*\)/g)) {
      let target = path.normalize(path.join(path.dirname(rel), m[1]));
      if (!/\.js$/.test(target)) target += ".js";
      visit(target.split(path.sep).join("/"));
    }
  })("server.js");
  return order;
}

const READS = [
  /\bprocess\.env\.([A-Z][A-Z0-9_]+)\b/g,
  /\bprocess\.env\[\s*["']([A-Z][A-Z0-9_]+)["']\s*\]/g,
  /(?<![\w$.])(?:env|e)\.([A-Z][A-Z0-9_]+)\b/g,
  /\(\s*env\s*\|\|\s*(?:\{\s*\}|process\.env)\s*\)\.([A-Z][A-Z0-9_]+)\b/g,
  /\bchainLimit\(\s*"([A-Z][A-Z0-9_]+)"/g,
  /\benvVar:\s*"([A-Z][A-Z0-9_]+)"/g
];

/* { NAME: [file, …] } for every read. */
function envReads() {
  const out = {};
  for (const rel of runtimeFiles()) {
    const code = stripComments(fs.readFileSync(path.join(REPO, rel), "utf8"));
    for (const re of READS) {
      for (const m of code.matchAll(re)) {
        (out[m[1]] = out[m[1]] || []);
        if (out[m[1]].indexOf(rel) === -1) out[m[1]].push(rel);
      }
    }
  }
  return out;
}

module.exports = { envReads, runtimeFiles, stripComments };

if (require.main === module) {
  const r = envReads();
  Object.keys(r).sort().forEach(k => console.log(k + "  " + r[k].join(", ")));
  console.log(Object.keys(r).length + " variables in " + runtimeFiles().length + " files");
}
