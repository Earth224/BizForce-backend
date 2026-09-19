const fs = require("fs");
const src = fs.readFileSync("server.js", "utf8");
const lines = src.split("\n");
const starts = [];
for (let i = 18580; i < 24900; i++) {
  const m = /^app\.(get|post|put|patch|delete)\("([^"]+)"/.exec(lines[i - 1]);
  if (m) starts.push({ line: i, method: m[1].toUpperCase(), path: m[2] });
}
function topKeys(objText) {
  // objText begins after "{"; walk depth-1 keys
  const keys = []; let depth = 0, i = 0, atKeyStart = true;
  while (i < objText.length) {
    const c = objText[i];
    if (c === '"' || c === "'" || c === "`") { const q = c; i++; while (i < objText.length && objText[i] !== q) { if (objText[i] === "\\") i++; i++; } i++; continue; }
    if (c === "/" && objText[i+1] === "*") { i = objText.indexOf("*/", i) + 2; continue; }
    if (c === "/" && objText[i+1] === "/") { i = objText.indexOf("\n", i); continue; }
    if (c === "{" || c === "(" || c === "[") { depth++; i++; continue; }
    if (c === "}" || c === ")" || c === "]") { if (depth === 0) break; depth--; i++; continue; }
    if (depth === 0 && atKeyStart && /[A-Za-z_$]/.test(c)) {
      let j = i; while (/[A-Za-z0-9_$]/.test(objText[j])) j++;
      const word = objText.slice(i, j);
      const rest = objText.slice(j).replace(/^\s+/, "");
      if (rest[0] === ":" || rest[0] === "," || rest[0] === "}") keys.push(word);
      atKeyStart = false; i = j; continue;
    }
    if (c === "," && depth === 0) atKeyStart = true;
    if (!/\s/.test(c) && c !== ",") atKeyStart = atKeyStart && false;
    i++;
  }
  return keys;
}
starts.forEach((r, idx) => {
  const endLine = idx + 1 < starts.length ? starts[idx + 1].line - 1 : 24900;
  const body = lines.slice(r.line - 1, endLine).join("\n");
  const model = [...body.matchAll(/callAnthropicText\([^,]+,\s*(\d+)/g)].map(m => m[1]);
  const writes = [...body.matchAll(/\.from\("([a-z_]+)"\)\s*\.\s*(insert|update|upsert|delete)/g)].map(m => m[1] + "." + m[2]);
  const reads = [...new Set([...body.matchAll(/\.from\("([a-z_]+)"\)/g)].map(m => m[1]))];
  const measured = /\bmeasured\s*:/.test(body);
  const prov = /toolProvenance\(|etsyProvenance\(/.test(body);
  // final success res.json — last "return res.json({" not inside a 400/422 status
  const jsonIdx = [...body.matchAll(/return res\.json\(\{/g)].map(m => m.index);
  let keys = [];
  if (jsonIdx.length) { const k = jsonIdx[jsonIdx.length - 1] + "return res.json({".length; keys = topKeys(body.slice(k)); }
  const agent = r.path.split("/")[3];
  console.log(`${r.line} | ${r.method} ${r.path} | agent=${agent} | model=${model.length ? "haiku x" + model.length + " maxTokens " + model.join("/") : "NONE"} | measured=${measured} prov=${prov} | keys=${keys.join(",")} | writes=${writes.join(",") || "none"} | reads=${reads.join(",") || "none"}`);
});
