/* ══════════════════════════════════════════════════════════════════════════
   checkKeyFunding.js — whose Anthropic key paid, and whether the ledger says so.

   TWO DEFECTS, ONE CAUSE. processAiTask and eleven other call sites passed null
   as callAnthropicText's third argument, which is the argument that selects
   whose key pays — so every agent task ran on the platform key even for a user
   who had stored their own. And resolveAnthropicKey falls back to the platform
   key on every miss without recording it, so the first defect was invisible
   from the database: a call meant to be funded by a user and funded by the
   platform instead looked exactly like one that was never meant to be.

   WHAT THIS PROVES
     1. Every call site a person's action reaches passes a user id, and the one
        that does not is convertSingleLead and only convertSingleLead.
     2. resolveAnthropicKey.withSource reports platform/no_key_stored for a user
        with no stored key, and user/null for one with a key — proven with a
        real encrypted row, created and removed by this script.
     3. A real call through callAnthropicText writes a ledger row whose
        funded_by says which key paid.
     4. One SQL-shaped query answers "how many calls did the platform pay for,
        and for which users", with the pre-109 rows in their own bucket.

   THE BYOK ROW. user_api_keys is empty, so proving the user-funded path needs a
   key. This script encrypts a FAKE key ("sk-ant-check-..." — not a credential,
   and never sent anywhere) with the same lib/apiKeyCrypto the product uses,
   writes it for the subject account only, and deletes it again in a finally
   block. It is never written for any other account. No request is made with it:
   the Anthropic SDK is stubbed, and what is under test is which key was
   SELECTED, not whether Anthropic accepts it.

   MUTATE=unfunded puts the billing argument back to null at the callAnthropicText
   boundary — the pre-commit behaviour — and the funded_by assertions must go red.
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const { createResidueGuard, resolveSubjectAccount } = require("./checkRunResidue");
const SUBJECT_USER_ID = resolveSubjectAccount();

const path = require("path");
const REPO = path.join(__dirname, "..");

const SDK_PATH = require.resolve("@anthropic-ai/sdk", { paths: [REPO] });
const RealAnthropic = require(SDK_PATH);

/* The key each constructed client was given, in order. This is the measurement
   that matters: it is the actual string callAnthropicText chose to pay with. */
let keysUsed = [];

function FakeAnthropic(options) {
  /* RECORDED RAW, NOT COERCED. ANTHROPIC_API_KEY is unset in this environment,
     so the platform key IS undefined here — and an earlier version of this line
     wrote "|| null", which turned undefined into null and made the comparison
     against the platform key fail for a reason that had nothing to do with the
     code under test. */
  keysUsed.push(options ? options.apiKey : undefined);
  const instance = new RealAnthropic({ apiKey: "sk-ant-stub", timeout: 1000 });
  instance.messages = {
    create: async function (args) {
      return {
        id: "msg_check",
        model: (args && args.model) || "stubbed",
        content: [{ type: "text", text: "ok" }],
        stop_reason: "end_turn",
        usage: { input_tokens: 3, output_tokens: 4 }
      };
    }
  };
  return instance;
}
Object.keys(RealAnthropic).forEach(function (k) { FakeAnthropic[k] = RealAnthropic[k]; });
require.cache[SDK_PATH].exports = FakeAnthropic;

const EXPRESS_PATH = require.resolve("express", { paths: [REPO] });
const realExpress = require(EXPRESS_PATH);
let app = null;
const expressWrapper = function () {
  const made = realExpress.apply(this, arguments);
  if (!app) app = made;
  return made;
};
Object.keys(realExpress).forEach(function (k) { expressWrapper[k] = realExpress[k]; });
require.cache[EXPRESS_PATH].exports = expressWrapper;

process.env.PORT = process.env.CHECK_PORT || "0";
const server = require(path.join(REPO, "server.js"));

const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY
);

const { encrypt } = require(path.join(REPO, "lib", "apiKeyCrypto"));
const makeResolver = require(path.join(REPO, "lib", "resolveAnthropicKey"));
const resolveAnthropicKey = makeResolver(supabase);

const residue = createResidueGuard({
  supabase: supabase,
  name: "keyFunding",
  subject: SUBJECT_USER_ID,
  tables: ["ai_tasks", "model_calls"]
});
residue.install();

const MUTATING = process.env.MUTATE === "unfunded";

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

/* Not a credential. A recognisable, obviously-fake string so that if it ever
   escaped into a log it reads as what it is. */
const FAKE_BYOK_KEY = "sk-ant-check-not-a-real-key-000000000000";
const PLATFORM_KEY = process.env.ANTHROPIC_API_KEY;

/* ENCRYPTION_SECRET IS NOT SET IN THIS ENVIRONMENT. That is a real finding and
   not something to paper over: with it unset, lib/apiKeyCrypto throws, so the
   product CANNOT store a BYOK key here at all — which is why user_api_keys is
   empty. For the purposes of this check a throwaway 32-byte secret is generated
   in-process so the fixture key can be sealed and unsealed by the same run.
   That proves which BRANCH resolveAnthropicKey takes, which is what is under
   test. It proves nothing about the real deployment secret, and this value is
   never written anywhere but the fixture row, which is deleted below. */
if (!process.env.ENCRYPTION_SECRET) {
  process.env.ENCRYPTION_SECRET = require("crypto").randomBytes(32).toString("hex");
  console.log("    [fixture] ENCRYPTION_SECRET was unset — generated a throwaway one for this process only");
}

async function storeFakeKey(userId) {
  const sealed = encrypt(FAKE_BYOK_KEY);
  const ins = await supabase.from("user_api_keys").insert({
    user_id: userId,
    provider: "anthropic",
    ciphertext: sealed.ciphertext,
    iv: sealed.iv,
    auth_tag: sealed.authTag
  });
  if (ins.error) throw new Error("could not store the fixture key: " + ins.error.message);
}

async function removeFakeKey(userId) {
  const del = await supabase.from("user_api_keys").delete()
    .eq("user_id", userId).eq("provider", "anthropic");
  const back = await supabase.from("user_api_keys")
    .select("id", { count: "exact", head: true }).eq("user_id", userId);
  console.log("    [fixture] BYOK row removed — " + (back.count === 0 ? "verified gone" : "STILL PRESENT (" + back.count + ")") +
    (del.error ? "  delete reported " + del.error.message : ""));
  if (back.count !== 0) failures++;
}

/* ── the static half: which sites pass a user ───────────────────────────── */
function auditCallSites() {
  const fs = require("fs");
  const src = fs.readFileSync(path.join(REPO, "server.js"), "utf8");
  const re = /callAnthropicText\s*\(/g;
  const nullSites = [];
  let total = 0, m;
  while ((m = re.exec(src)) !== null) {
    const ls = src.lastIndexOf("\n", m.index) + 1;
    const lt = src.slice(ls, src.indexOf("\n", m.index));
    if (/async function callAnthropicText/.test(lt)) continue;
    if (/^\s*(\/\/|\*|\/\*)/.test(lt)) continue;
    let i = m.index + m[0].length - 1, d = 0, end = -1;
    for (; i < src.length; i++) { const c = src[i]; if (c === "(") d++; else if (c === ")") { d--; if (d === 0) { end = i; break; } } }
    const span = src.slice(m.index, end + 1);
    total++;
    if (span.indexOf(", null, undefined,") !== -1) {
      const r = span.match(/route:\s*"([^"]+)"/);
      nullSites.push(r ? r[1] : "line " + src.slice(0, m.index).split("\n").length);
    }
  }
  return { total: total, nullSites: nullSites };
}

(async function main() {
  await residue.sweepPrevious(SUBJECT_USER_ID);

  console.log("\n══ every callAnthropicText site ══");
  const audit = auditCallSites();
  console.log("    " + audit.total + " call sites; " + audit.nullSites.length + " still billing the platform:");
  audit.nullSites.forEach(function (n) { console.log("      " + n); });
  check("exactly one call site still bills the platform", audit.nullSites.length === 1,
    audit.nullSites.join(", "));
  check("and it is convertSingleLead — the platform's own outreach",
    audit.nullSites.length === 1 && audit.nullSites[0] === "convertSingleLead", audit.nullSites.join(", "));

  /* ── the resolver ─────────────────────────────────────────────────────── */
  console.log("\n══ resolveAnthropicKey.withSource ══");

  const noUser = await resolveAnthropicKey.withSource(null);
  check("no user named  -> platform / no_user",
    noUser.source === "platform" && noUser.reason === "no_user", JSON.stringify({ s: noUser.source, r: noUser.reason }));

  const noKey = await resolveAnthropicKey.withSource(SUBJECT_USER_ID);
  check("user with no stored key -> platform / no_key_stored",
    noKey.source === "platform" && noKey.reason === "no_key_stored",
    JSON.stringify({ s: noKey.source, r: noKey.reason }));
  check("and the key it returns really is the platform key",
    noKey.key === PLATFORM_KEY, noKey.key === PLATFORM_KEY ? "" : "returned something else");

  console.log("\n══ with a stored BYOK key (fixture) ══");
  const columnProbe = await supabase.from("model_calls").select("funded_by").limit(1);
  const MIGRATION_APPLIED = !columnProbe.error;
  console.log("    migration 109 applied to this database: " + (MIGRATION_APPLIED ? "YES" : "NO"));

  const before = await supabase.from("model_calls").select("id", { count: "exact", head: true }).eq("user_id", SUBJECT_USER_ID);
  console.log("    model_calls for the subject BEFORE: " + before.count);

  try {
    await storeFakeKey(SUBJECT_USER_ID);
    console.log("    [fixture] an encrypted, obviously-fake BYOK key stored for the subject only");

    const withKey = await resolveAnthropicKey.withSource(SUBJECT_USER_ID);
    check("user with a stored key -> user / no fallback reason",
      withKey.source === "user" && withKey.reason === null,
      JSON.stringify({ s: withKey.source, r: withKey.reason }));
    check("and the key it returns is the stored one, not the platform's",
      withKey.key === FAKE_BYOK_KEY && withKey.key !== PLATFORM_KEY,
      withKey.key === PLATFORM_KEY ? "returned the platform key" : "returned something unexpected");

    /* ── a real call, end to end ───────────────────────────────────────── */
    console.log("\n══ a real call through callAnthropicText ══");
    keysUsed = [];
    const sinceIso = new Date(Date.now() - 2000).toISOString();

    /* MUTATION: the pre-commit behaviour — the billing argument is null again. */
    const billingUser = MUTATING ? null : SUBJECT_USER_ID;
    if (MUTATING) console.log("    !! MUTATION: the billing argument is null, as it was before this commit.");

    await server.__callAnthropicText("Say ok.", 16, billingUser, undefined, {
      user_id: SUBJECT_USER_ID,
      agent_type: "check",
      route: "checkKeyFunding"
    });

    check("the client was built with the user's own key",
      keysUsed.length === 1 && keysUsed[0] === FAKE_BYOK_KEY,
      "keys used: " + keysUsed.map(function (k) { return k === PLATFORM_KEY ? "PLATFORM" : (k === FAKE_BYOK_KEY ? "USER" : String(k)); }).join(", "));

    const rows = await supabase.from("model_calls").select("*")
      .eq("user_id", SUBJECT_USER_ID).gte("created_at", sinceIso);
    (rows.data || []).forEach(function (r) { residue.record("model_calls", r.id); });
    check("a ledger row was written", (rows.data || []).length === 1, "rows: " + (rows.data || []).length);

    if (MIGRATION_APPLIED && rows.data && rows.data.length) {
      const row = rows.data[0];
      console.log("    ledger row: " + JSON.stringify({
        route: row.route, funded_by: row.funded_by, fallback_reason: row.fallback_reason,
        input: row.input_tokens, output: row.output_tokens
      }));
      check("the row records funded_by = user", row.funded_by === "user", "funded_by=" + row.funded_by);
      check("with no fallback reason", row.fallback_reason === null, "fallback_reason=" + row.fallback_reason);
    }

    /* ── the same call for a user with no key ──────────────────────────── */
    console.log("\n══ the same call, for a user with no stored key ══");
    await removeFakeKey(SUBJECT_USER_ID);
    keysUsed = [];
    const since2 = new Date(Date.now() - 1000).toISOString();

    await server.__callAnthropicText("Say ok.", 16, SUBJECT_USER_ID, undefined, {
      user_id: SUBJECT_USER_ID,
      agent_type: "check",
      route: "checkKeyFunding (no stored key)"
    });

    check("the client fell back to the platform key",
      keysUsed.length === 1 && keysUsed[0] === PLATFORM_KEY, "keys used: " + keysUsed.length);

    const rows2 = await supabase.from("model_calls").select("*")
      .eq("user_id", SUBJECT_USER_ID).gte("created_at", since2);
    (rows2.data || []).forEach(function (r) { residue.record("model_calls", r.id); });

    if (MIGRATION_APPLIED && rows2.data && rows2.data.length) {
      const row2 = rows2.data[rows2.data.length - 1];
      console.log("    ledger row: " + JSON.stringify({
        route: row2.route, funded_by: row2.funded_by, fallback_reason: row2.fallback_reason
      }));
      check("the fallback is recorded as funded_by = platform", row2.funded_by === "platform",
        "funded_by=" + row2.funded_by);
      check("with fallback_reason = no_key_stored", row2.fallback_reason === "no_key_stored",
        "fallback_reason=" + row2.fallback_reason);
    } else if (!MIGRATION_APPLIED) {
      console.log("    (funded_by assertions skipped — migration 109 is not applied here)");
      check("the ledger row survived the missing column", (rows2.data || []).length >= 1,
        "rows: " + (rows2.data || []).length);
    }

    /* ── the question the column exists to answer ──────────────────────── */
    console.log("\n══ \"how much did the platform key pay for, and for whom\" ══");
    if (MIGRATION_APPLIED) {
      const all = await supabase.from("model_calls").select("user_id, funded_by, fallback_reason, input_tokens, output_tokens");
      const groups = {};
      (all.data || []).forEach(function (r) {
        const k = (r.funded_by === null ? "(pre-109, unrecorded)" : r.funded_by) +
          " / " + (r.fallback_reason || "-") + " / " + (r.user_id || "null").slice(0, 8);
        groups[k] = groups[k] || { calls: 0, tokens: 0 };
        groups[k].calls++;
        groups[k].tokens += (r.input_tokens || 0) + (r.output_tokens || 0);
      });
      console.log("    funded_by / fallback_reason / user      calls   tokens");
      Object.keys(groups).sort().forEach(function (k) {
        console.log("    " + k.padEnd(38) + String(groups[k].calls).padStart(5) + String(groups[k].tokens).padStart(9));
      });
      const unrecorded = (all.data || []).filter(function (r) { return r.funded_by === null; }).length;
      console.log("    rows predating migration 109 (funded_by IS NULL): " + unrecorded +
        " — their own bucket, not counted as either answer");
      check("every row written by this run records who funded it",
        (rows.data || []).concat(rows2.data || []).every(function (r) { return r.funded_by !== null; }),
        "some rows have a null funded_by");
    } else {
      console.log("    (skipped — migration 109 is not applied to this database)");
      console.log("    Apply supabase/migrations/109_model_calls_funded_by.sql, then re-run.");
    }
  } finally {
    /* Whatever happened above, the fixture key does not outlive this script. */
    const still = await supabase.from("user_api_keys")
      .select("id", { count: "exact", head: true }).eq("user_id", SUBJECT_USER_ID);
    if (still.count) await removeFakeKey(SUBJECT_USER_ID);
  }

  console.log("\n══ cleanup ══");
  const cleanupResult = await residue.cleanup("end of run");
  if (cleanupResult.leftovers.length) failures++;

  const keysLeft = await supabase.from("user_api_keys").select("id", { count: "exact", head: true });
  check("user_api_keys is empty again", keysLeft.count === 0, "rows: " + keysLeft.count);

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
})().catch(async function (err) {
  console.error("\nThe check threw: " + ((err && err.stack) || err));
  try { await removeFakeKey(SUBJECT_USER_ID); } catch (e) { /* guard still runs */ }
  process.exit(1);
});
