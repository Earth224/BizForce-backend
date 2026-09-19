const fs = require("fs");
const src = fs.readFileSync("server.js", "utf8");
const lines = src.split("\n");
const ROUTES = ["etsy/keyword-research","etsy/pricing-strategy","email/sequence","email/subject-lines","publicist/press-release","publicist/pitch","operations/sop","operations/checklist","ads/copy","ads/policy-check","reputation/review-response","reputation/review-request","social/post","social/calendar","broker/term-sheet","broker/due-diligence","rd/brief","community/onboarding","community/engagement-calendar","analytics/funnel","analytics/kpi-review","influencer/outreach","influencer/partnership-offer","vertical_marketing/positioning","vertical_marketing/objections","content/outline","executive/plan"];
function routeSpan(path) {
  const sig = 'app.post("/api/agents/' + path + '"';
  const startIdx = src.indexOf(sig);
  let depth = 0, i = src.indexOf("{", startIdx), end = -1;
  for (; i < src.length; i++) { const c = src[i]; if (c === "{") depth++; else if (c === "}") { depth--; if (depth === 0) { end = i + 1; break; } } }
  const startLine = src.slice(0, startIdx).split("\n").length;
  const endLine = src.slice(0, end).split("\n").length;
  return { startLine, endLine };
}
for (const p of ROUTES) {
  const { startLine, endLine } = routeSpan(p);
  let modelLine = null, catchLine = null;
  for (let l = startLine; l <= endLine; l++) {
    if (!modelLine && /callAnthropicText\(/.test(lines[l-1])) modelLine = l;
    if (/^\s*\} catch \(error\) \{/.test(lines[l-1])) catchLine = l;
  }
  const out = [];
  for (let l = startLine; l <= endLine; l++) {
    const t = lines[l-1];
    if (/res\.status\(|res\.json\(|next\(error\)/.test(t)) {
      let cls;
      if (/next\(error\)/.test(t)) cls = "catch → next(error)";
      else if (/res\.json\(\{\s*$/.test(t) && !/status\(/.test(t) && !/res\.status/.test(lines[l-2] || "")) cls = "SUCCESS";
      else if (modelLine && l > modelLine) cls = "ERROR-after-model";
      else cls = "validation-before-insert";
      out.push(`${l}: ${cls} :: ${t.trim().slice(0, 90)}`);
    }
  }
  console.log(`\n== ${p} (${startLine}-${endLine}) model@${modelLine || "NONE"}`);
  out.forEach(o => console.log("  " + o));
}
