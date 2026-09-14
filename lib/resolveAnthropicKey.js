const { decrypt } = require("./apiKeyCrypto");

/* THE FALLBACK IS NOT THE PROBLEM. THE SILENCE WAS.
   ─────────────────────────────────────────────────
   Falling back to the platform key on a miss is the right behaviour: the
   alternative is a user whose stored key went stale losing the product
   entirely. What was wrong is that it happened without a trace. A call meant to
   be funded by a user's own key and actually funded by the platform's looked
   identical to one that was never meant to be, so nobody could ask how much
   spend the platform was absorbing, for whom, or why.

   So the resolver still returns a usable key in every case, and now also says
   WHICH key it is and, when it fell back, WHY. resolveAnthropicKey keeps its
   old shape — a plain string — because several callers only need a key to make
   a request with. Callers that write the ledger use .withSource. */
module.exports = function makeResolver(supabase) {
  async function withSource(userId) {
    /* No user named. The platform was always going to pay for this one: it is
       a background pass the platform initiates, not a user's task. Distinct
       from every other reason here, which are all misses. */
    if (!userId) {
      return { key: process.env.ANTHROPIC_API_KEY, source: "platform", reason: "no_user" };
    }

    const { data: row, error } = await supabase
      .from("user_api_keys")
      .select("ciphertext, iv, auth_tag")
      .eq("user_id", userId)
      .eq("provider", "anthropic")
      .maybeSingle();

    /* A read that FAILED and a read that found NOTHING are different events and
       stopped being the same value here. "no rows" is an ordinary user without
       a key; "could not read the table" is an outage that is quietly moving
       spend onto the platform and will not show up anywhere else. */
    if (error) {
      console.warn("[key] user_api_keys could not be read for user " + userId + " (" +
        (error.message || error) + "). Falling back to the PLATFORM key — this call is " +
        "being funded by the platform and recorded as such.");
      return { key: process.env.ANTHROPIC_API_KEY, source: "platform", reason: "lookup_failed" };
    }

    if (!row) {
      return { key: process.env.ANTHROPIC_API_KEY, source: "platform", reason: "no_key_stored" };
    }

    try {
      return {
        key: decrypt({ ciphertext: row.ciphertext, iv: row.iv, authTag: row.auth_tag }),
        source: "user",
        reason: null
      };
    } catch (decryptError) {
      /* THE ONE REASON HERE THAT MEANS SOMETHING IS BROKEN. The other three are
         absences; this is a key the user believes is in use, that the settings
         page shows as saved, and that cannot be read. Loud on purpose. */
      console.error("[key] DECRYPT FAILED for the stored Anthropic key of user " + userId +
        " (" + ((decryptError && decryptError.message) || decryptError) + "). The user has a key " +
        "saved and the settings page shows it as active, but it cannot be used. Falling back to " +
        "the PLATFORM key: the platform is paying for a call the user is entitled to believe " +
        "their own key funded. Recorded as funded_by=platform, fallback_reason=decrypt_failed.");
      return { key: process.env.ANTHROPIC_API_KEY, source: "platform", reason: "decrypt_failed" };
    }
  }

  async function resolveAnthropicKey(userId) {
    const resolved = await withSource(userId);
    return resolved.key;
  }

  resolveAnthropicKey.withSource = withSource;
  return resolveAnthropicKey;
};
