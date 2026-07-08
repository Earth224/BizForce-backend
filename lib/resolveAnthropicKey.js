const { decrypt } = require("./apiKeyCrypto");

module.exports = function makeResolver(supabase) {
  return async function resolveAnthropicKey(userId) {
    if (!userId) {
      return process.env.ANTHROPIC_API_KEY;
    }

    const { data: row, error } = await supabase
      .from("user_api_keys")
      .select("ciphertext, iv, auth_tag")
      .eq("user_id", userId)
      .eq("provider", "anthropic")
      .maybeSingle();

    if (error || !row) {
      return process.env.ANTHROPIC_API_KEY;
    }

    try {
      return decrypt({ ciphertext: row.ciphertext, iv: row.iv, authTag: row.auth_tag });
    } catch (decryptError) {
      console.warn("resolveAnthropicKey: decrypt failed for user, falling back to platform key");
      return process.env.ANTHROPIC_API_KEY;
    }
  };
};
