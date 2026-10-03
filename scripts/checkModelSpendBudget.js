/* ═══════════════════════════════════════════════════════════════════════════
   checkModelSpendBudget.js — is what an account can spend bounded, in dollars?

   WHAT THIS PROVES, AGAINST THE REAL DATABASE:

     1. The price table is the one recorded, with its source and the date read.
     2. A ledger row costs input × input price + output × output price, and
        thinking_tokens is NOT added on top: thinking is already inside
        output_tokens. Proven on a fixture row and on clean-7b's real ledger,
        which must still cost $0.291114, the exported figure.
     3. A model with no price is priced at the highest rate in the table and
        logged — never skipped.
     4. Rows the account paid for itself (funded_by 'user') are not counted;
        rows from before migration 109 (funded_by NULL) are.
     5. Only this calendar month (UTC) counts.
     6. Every row is read, past PostgREST's 1,000-row page.
     7. The ceiling defaults to $60, is overridable, and a value that is not a
        positive number fails closed.
     8. Over the ceiling, enforceDailyModelCallLimit — the gate before every
        model call — refuses with 429 and a message that says what was spent,
        what the ceiling is and when it resets. Under it, the call proceeds.
     9. A ledger read that fails, fails open, as the call cap does.
    10. No account is exempt.

   HOW IT RUNS. The functions are lifted from server.js into a vm context with
   the real Supabase client, and driven with fixture model_calls rows written
   under the check subject only. Every fixture row is recorded with the residue
   guard and removed at the end, on any way out. No model is called.

   MUTATIONS — each must turn the named section red:
     MUTATE=spendwire       the gate no longer checks spend            → 8
     MUTATE=thinkingdouble  thinking_tokens added to output            → 2
     MUTATE=unpricedskip    an unpriced row is skipped                 → 3
     MUTATE=byok            user-funded rows are counted               → 4
     MUTATE=month           every month counts                         → 5
     MUTATE=paging          only the first 1,000 rows are read         → 6
     MUTATE=failclosed      a bad ceiling falls back to the default    → 7
     MUTATE=message         the refusal says only "limit exceeded"     → 8

   Usage:  BIZFORCE_CHECK_USER_ID=<subject> node scripts/checkModelSpendBudget.js
   ═══════════════════════════════════════════════════════════════════════════ */
"use strict";
require("dotenv").config();
const fs = require("fs");
const vm = require("vm");
const path = require("path");
const REPO = path.join(__dirname, "..");
const { createResidueGuard, resolveSubjectAccount } = require("./checkRunResidue");
const { definitionOf } = require("./_shared");
const SUBJECT_USER_ID = resolveSubjectAccount();

const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY);
const residue = createResidueGuard({ supabase: supabase, name: "modelSpendBudget", subject: SUBJECT_USER_ID, tables: ["model_calls"] });
residue.install();

const MUTATIONS = ["spendwire", "thinkingdouble", "unpricedskip", "byok", "month", "paging", "failclosed", "message"];
const MUTATE = process.env.MUTATE || "";
if (MUTATE && MUTATIONS.indexOf(MUTATE) === -1) { console.error("Unknown MUTATE=" + MUTATE + ". Known: " + MUTATIONS.join(", ")); process.exit(2); }

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}
function mutate(src, from, to, what) {
  if (src.split(from).length !== 2) { console.error("MUTATION REFUSED (" + what + "): anchor not found exactly once."); process.exit(3); }
  return src.replace(from, () => to);
}

let SERVER = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
if (MUTATE === "spendwire") {
  SERVER = mutate(SERVER, "  await enforceMonthlyModelSpendLimit(userId, route);\n\n  return { allowed: true, counted: true, limit: limit, used: used };",
    "  return { allowed: true, counted: true, limit: limit, used: used };", "spendwire");
}
if (MUTATE === "thinkingdouble") {
  SERVER = mutate(SERVER, "(Number(row.output_tokens) || 0) * price.output / 1e6;",
    "((Number(row.output_tokens) || 0) + (Number(row.thinking_tokens) || 0)) * price.output / 1e6;", "thinkingdouble");
  SERVER = mutate(SERVER, ".select(\"id, model, input_tokens, output_tokens, funded_by\", { count: \"exact\" })",
    ".select(\"id, model, input_tokens, output_tokens, thinking_tokens, funded_by\", { count: \"exact\" })", "thinkingdouble");
}
if (MUTATE === "unpricedskip") SERVER = mutate(SERVER, "    var cost = modelCallCostUsd(row);\n", "    var cost = modelCallCostUsd(row);\n    if (!cost.priced) return;\n", "unpricedskip");
if (MUTATE === "byok") SERVER = mutate(SERVER, "    if (row.funded_by === \"user\") return;\n", "", "byok");
if (MUTATE === "month") SERVER = mutate(SERVER, "      .gte(\"created_on\", month.since)\n", "", "month");
if (MUTATE === "paging") SERVER = mutate(SERVER, "    if (!page.data || page.data.length < 1000) break;", "    break;", "paging");
if (MUTATE === "failclosed") SERVER = mutate(SERVER, "  return Number.isFinite(parsed) && parsed > 0 ? parsed : null;\n}",
  "  return Number.isFinite(parsed) && parsed > 0 ? parsed : MODEL_SPEND_MONTHLY_LIMIT_DEFAULT_USD;\n}", "failclosed");
if (MUTATE === "message") SERVER = mutate(SERVER, "    \"Monthly model spend limit reached. This account's model calls have cost $\" + spent.toFixed(2) +\n    \" this calendar month, against a limit of $\" + limit.toFixed(2) + \" per account per month \" +\n",
  "    \"Limit exceeded. \" +\n", "message");
if (MUTATE) console.log("\n!! MUTATION: " + MUTATE);

const NAMES = ["MODEL_CALL_DAILY_LIMIT_DEFAULT", "modelCallDailyLimit", "modelCallLimitReset", "dailyModelCallLimitError", "unreadableModelCallLimitError",
  "modelCallUtcDay", "enforceDailyModelCallLimit", "MODEL_PRICES_USD_PER_MILLION", "MODEL_PRICES_SOURCE", "MODEL_SPEND_MONTHLY_LIMIT_DEFAULT_USD",
  "modelSpendMonthlyLimit", "modelCallCostUsd", "modelSpendMonth", "modelSpendThisMonth", "monthlyModelSpendLimitError", "enforceMonthlyModelSpendLimit"];
const def = name => { const d = definitionOf(SERVER, name); if (!d) throw new Error("not found in server.js: " + name); return d; };
const logs = [];
function lift(client, env) {
  const ctx = vm.createContext({ supabase: client, process: { env: Object.assign({}, env || {}) },
    console: { log() {}, warn(m) { logs.push(String(m)); }, error(m) { logs.push(String(m)); } } });
  vm.runInContext(NAMES.map(def).join("\n\n") + "\nthis.api = { enforceDailyModelCallLimit, enforceMonthlyModelSpendLimit, modelSpendThisMonth, modelCallCostUsd, modelSpendMonth, modelSpendMonthlyLimit, PRICES: MODEL_PRICES_USD_PER_MILLION, SOURCE: MODEL_PRICES_SOURCE };", ctx);
  return ctx.api;
}
const near = (a, b) => Math.abs(a - b) < 1e-9;

async function insert(rows) {
  const r = await supabase.from("model_calls").insert(rows.map(x => Object.assign({ user_id: SUBJECT_USER_ID, agent_type: "check", route: "checkModelSpendBudget fixture" }, x))).select("id");
  if (r.error) throw new Error("fixture insert failed: " + r.error.message);
  r.data.forEach(x => residue.record("model_calls", x.id));
  return r.data.map(x => x.id);
}

(async function main() {
  await residue.sweepPrevious(SUBJECT_USER_ID);
  const { data: highest } = await supabase.from("model_calls").select("id").order("id", { ascending: false }).limit(1).maybeSingle();
  residue.setLedgerMark(highest ? highest.id : 0);

  const api = lift(supabase, {});
  const month = api.modelSpendMonth(new Date());
  const today = new Date().toISOString().slice(0, 10);
  const lastMonthDay = new Date(Date.parse(month.since + "T00:00:00Z") - 86400000).toISOString().slice(0, 10);
  const base = await api.modelSpendThisMonth(SUBJECT_USER_ID);
  if (base.error) throw new Error("baseline read failed: " + base.error);
  console.log("subject " + SUBJECT_USER_ID + " · month since " + month.since + " · baseline spend $" + base.usd.toFixed(6) + " over " + base.rows + " rows");

  console.log("\n══ 1. the price table ══");
  check("1. Haiku 4.5 $1/$5, Sonnet 5 and 5.5 $2/$10, Sonnet 4.6 $3/$15 per million tokens, and nothing else",
    JSON.stringify(api.PRICES) === JSON.stringify({ "claude-haiku-4-5-20251001": { input: 1, output: 5 }, "claude-sonnet-5": { input: 2, output: 10 },
      "claude-sonnet-5-5": { input: 2, output: 10 }, "claude-sonnet-4-6": { input: 3, output: 15 } }), JSON.stringify(api.PRICES));
  check("1. the table names its source and the date it was read", /claude-api reference table/.test(api.SOURCE) && /read 2026-10-03/.test(api.SOURCE), api.SOURCE);

  console.log("\n══ 2. thinking_tokens is not added to output_tokens ══");
  await insert([{ model: "claude-sonnet-5-5", input_tokens: 0, output_tokens: 1000000, thinking_tokens: 400000, funded_by: "platform", created_on: month.since }]);
  const s2 = await api.modelSpendThisMonth(SUBJECT_USER_ID);
  check("2. a Sonnet 5.5 row of 1,000,000 output tokens, 400,000 of them thinking, costs $10.00, not $14.00", near(s2.usd - base.usd, 10), (s2.usd - base.usd).toFixed(6));
  const r7b = (await supabase.from("model_calls").select("model, input_tokens, output_tokens, thinking_tokens, funded_by").eq("user_id", "a69abc72-8ce9-4610-a71f-7ca8af0f617f")).data || [];
  const cost7b = r7b.reduce((s, r) => s + api.modelCallCostUsd(r).usd, 0);
  check("2. clean-7b's real ledger (9,376 thinking tokens inside 22,411 output) prices at $0.291114, the exported figure", r7b.length === 6 && near(Number(cost7b.toFixed(6)), 0.291114), cost7b.toFixed(6) + " over " + r7b.length + " rows");
  check("2. code: neither the cost nor the spend read names thinking_tokens",
    !/thinking/.test(def("modelCallCostUsd")) && !/thinking/.test(def("modelSpendThisMonth")));

  console.log("\n══ 3. a model with no price is priced high, not skipped ══");
  logs.length = 0;
  await insert([{ model: "claude-future-9", input_tokens: 1000000, output_tokens: 1000000, funded_by: "platform", created_on: month.since }]);
  const s3 = await api.modelSpendThisMonth(SUBJECT_USER_ID);
  check("3. an unknown model's 1M in + 1M out costs $18.00 — the highest input ($3) and output ($15) rates — and is in the total", near(s3.usd - s2.usd, 18), (s3.usd - s2.usd).toFixed(6));
  check("3. it is logged as UNPRICED, by name", logs.some(l => /UNPRICED MODEL "claude-future-9"/.test(l)) && s3.unpriced["claude-future-9"] === 1, JSON.stringify(s3.unpriced));

  console.log("\n══ 4. what the platform paid for, and nothing the account paid for itself ══");
  await insert([{ model: "claude-haiku-4-5-20251001", input_tokens: 1000000, output_tokens: 0, funded_by: "user", created_on: month.since },
    { model: "claude-haiku-4-5-20251001", input_tokens: 2000000, output_tokens: 0, funded_by: null, created_on: month.since }]);
  const s4 = await api.modelSpendThisMonth(SUBJECT_USER_ID);
  check("4. a user-funded row adds nothing; a pre-109 row (funded_by NULL) adds its $2.00", near(s4.usd - s3.usd, 2), (s4.usd - s3.usd).toFixed(6));

  console.log("\n══ 5. only this calendar month ══");
  await insert([{ model: "claude-sonnet-5-5", input_tokens: 0, output_tokens: 5000000, funded_by: "platform", created_on: lastMonthDay }]);
  const s5 = await api.modelSpendThisMonth(SUBJECT_USER_ID);
  check("5. a $50 row dated " + lastMonthDay + " (last month) adds nothing", near(s5.usd, s4.usd), (s5.usd - s4.usd).toFixed(6));
  check("5. the month resets at the first of next month, UTC", /^\d{4}-\d{2}-01T00:00:00\.000Z$/.test(month.resets_at) && Date.parse(month.resets_at) > Date.now(), month.resets_at);

  console.log("\n══ 7. the ceiling ══");
  check("7. unset or blank, the ceiling is $60", lift(supabase, {}).modelSpendMonthlyLimit() === 60 && lift(supabase, { MODEL_SPEND_MONTHLY_LIMIT_USD_PER_USER: "  " }).modelSpendMonthlyLimit() === 60);
  check("7. MODEL_SPEND_MONTHLY_LIMIT_USD_PER_USER overrides it, cents allowed", lift(supabase, { MODEL_SPEND_MONTHLY_LIMIT_USD_PER_USER: "82.50" }).modelSpendMonthlyLimit() === 82.5);
  let badErr = null;
  try { await lift(supabase, { MODEL_SPEND_MONTHLY_LIMIT_USD_PER_USER: "sixty" }).enforceMonthlyModelSpendLimit(SUBJECT_USER_ID, "check"); } catch (e) { badErr = e; }
  let zeroErr = null;
  try { await lift(supabase, { MODEL_SPEND_MONTHLY_LIMIT_USD_PER_USER: "0" }).enforceMonthlyModelSpendLimit(SUBJECT_USER_ID, "check"); } catch (e) { zeroErr = e; }
  check("7. a ceiling that is not a positive number fails closed: 503, MONTHLY_MODEL_SPEND_LIMIT_MISCONFIGURED",
    !!badErr && badErr.status === 503 && badErr.code === "MONTHLY_MODEL_SPEND_LIMIT_MISCONFIGURED" && !!zeroErr && zeroErr.status === 503,
    JSON.stringify([badErr && badErr.code, zeroErr && zeroErr.code]));

  console.log("\n══ 8. the gate before every model call refuses over the ceiling, and says why ══");
  const spent = s5.usd;   // baseline + $30 of fixtures this month
  const under = lift(supabase, { MODEL_SPEND_MONTHLY_LIMIT_USD_PER_USER: String(Math.ceil(spent) + 1) });
  const ok = await under.enforceDailyModelCallLimit(SUBJECT_USER_ID, "check under");
  check("8. under the ceiling the call proceeds", ok && ok.allowed === true, JSON.stringify(ok));
  const over = lift(supabase, { MODEL_SPEND_MONTHLY_LIMIT_USD_PER_USER: "25" });
  let refusal = null;
  try { await over.enforceDailyModelCallLimit(SUBJECT_USER_ID, "check over"); } catch (e) { refusal = e; }
  console.log("    refusal: " + (refusal ? refusal.status + " " + refusal.code + " — " + refusal.message : "none"));
  check("8. over the ceiling, enforceDailyModelCallLimit refuses with 429 MONTHLY_MODEL_SPEND_LIMIT", !!refusal && refusal.status === 429 && refusal.code === "MONTHLY_MODEL_SPEND_LIMIT",
    refusal ? refusal.code : "no refusal");
  check("8. the refusal says what was spent, what the ceiling is, that no call was made, and when it resets",
    !!refusal && refusal.message.indexOf("$" + spent.toFixed(2)) !== -1 && refusal.message.indexOf("$25.00") !== -1 &&
    /No model call was made for this request\./.test(refusal.message) && refusal.message.indexOf(month.resets_at) !== -1 && /\d+d \d+h\./.test(refusal.message),
    refusal && refusal.message);
  const gate = def("enforceDailyModelCallLimit");
  check("8. code: the gate checks spend on every path that allows a counted user's call",
    gate.split("await enforceMonthlyModelSpendLimit(userId, route);").length - 1 === 3 &&
    gate.indexOf("await enforceMonthlyModelSpendLimit(userId, route);\n\n  return { allowed: true, counted: true") !== -1);

  console.log("\n══ 9. a ledger read that fails, fails open ══");
  const broken = { from() { const q = { select() { return q; }, eq() { return q; }, gte() { return q; }, order() { return q; },
    range() { return Promise.resolve({ data: null, error: { message: "simulated outage" }, count: null }); } }; return q; } };
  logs.length = 0;
  const open = await lift(broken, { MODEL_SPEND_MONTHLY_LIMIT_USD_PER_USER: "0.01" }).enforceMonthlyModelSpendLimit(SUBJECT_USER_ID, "check outage");
  check("9. the call proceeds uncounted, and says so in the log", open.allowed === true && open.counted === false && logs.some(l => /SPEND UNAVAILABLE.*FAILING OPEN/.test(l)), JSON.stringify(open));

  console.log("\n══ 10. no account is exempt ══");
  const spendSrc = ["modelSpendMonthlyLimit", "modelCallCostUsd", "modelSpendThisMonth", "enforceMonthlyModelSpendLimit"].map(def).join("\n");
  check("10. code: the spend functions name no owner, role or harness domain", !/OWNER_ACCOUNT_ID|\.role\b|bizforceai\.invalid|exempt/i.test(spendSrc));

  console.log("\n══ 6. every row is read, past the 1,000-row page ══");
  const many = [];
  for (let i = 0; i < 1001; i++) many.push({ model: "claude-haiku-4-5-20251001", input_tokens: 1000, output_tokens: 0, funded_by: "platform", created_on: month.since });
  await insert(many);
  const s6 = await api.modelSpendThisMonth(SUBJECT_USER_ID);
  const exact = await supabase.from("model_calls").select("id", { count: "exact", head: true }).eq("user_id", SUBJECT_USER_ID).gte("created_on", month.since);
  check("6. all " + exact.count + " of this month's rows are read, and 1,001 rows of $0.001 add $1.001",
    !s6.error && s6.rows === exact.count && near(s6.usd - s5.usd, 1.001), s6.error || (s6.rows + " rows, +" + (s6.usd - s5.usd).toFixed(6)));

  console.log("\n══ cleanup ══");
  const cleanupResult = await residue.cleanup("end of run");
  if (cleanupResult.leftovers.length) failures++;
  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
})().catch(function (err) {
  console.error("\nThe check threw: " + ((err && err.stack) || err));
  process.exit(1);
});
