const crypto = require("crypto");

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;
const KEY_LENGTH = 32;

function getKey() {
  const secret = process.env.ENCRYPTION_SECRET;
  if (!secret) {
    throw new Error("ENCRYPTION_SECRET is missing or malformed");
  }

  const key = Buffer.from(secret, "hex");
  if (key.length !== KEY_LENGTH) {
    throw new Error("ENCRYPTION_SECRET is missing or malformed");
  }

  return key;
}

function encrypt(plaintext) {
  const key = getKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  const encrypted = Buffer.concat([cipher.update(String(plaintext), "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    ciphertext: encrypted.toString("hex"),
    iv: iv.toString("hex"),
    authTag: authTag.toString("hex")
  };
}

function decrypt({ ciphertext, iv, authTag }) {
  const key = getKey();
  const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(iv, "hex"));
  decipher.setAuthTag(Buffer.from(authTag, "hex"));

  const decrypted = Buffer.concat([decipher.update(Buffer.from(ciphertext, "hex")), decipher.final()]);
  return decrypted.toString("utf8");
}

module.exports = { encrypt, decrypt };
