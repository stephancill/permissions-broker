import { expect, test } from "bun:test";

import { decryptCredential, encryptCredential } from "../src/crypto/ecies";
import { CLIENT_CRYPTO_JS } from "../src/passkey/clientCrypto";

type ClientCrypto = {
  deriveKek(prfOutput: ArrayBuffer, userId: string): Promise<CryptoKey>;
  generateUserKeypair(): Promise<{
    publicKeyRaw: Uint8Array;
    privateKey: CryptoKey;
  }>;
  wrapPrivateKey(
    kek: CryptoKey,
    privateKey: CryptoKey,
    userId: string
  ): Promise<Uint8Array>;
  unwrapPrivateKey(
    kek: CryptoKey,
    wrapped: Uint8Array,
    userId: string,
    extractable?: boolean
  ): Promise<CryptoKey>;
  deriveDek(
    privateKey: CryptoKey,
    epkRaw: Uint8Array,
    linkedAccountId: string
  ): Promise<Uint8Array>;
};

// Evaluate the exact source shipped to browsers.
new Function(CLIENT_CRYPTO_JS)();
const PB = (globalThis as unknown as { PB: ClientCrypto }).PB;

function randomPrf(): ArrayBuffer {
  return crypto.getRandomValues(new Uint8Array(32)).buffer;
}

test("client-derived DEK decrypts server-encrypted credential", async () => {
  const userId = "user_1";
  const prf = randomPrf();

  const kek = await PB.deriveKek(prf, userId);
  const { publicKeyRaw, privateKey } = await PB.generateUserKeypair();
  const wrapped = await PB.wrapPrivateKey(kek, privateKey, userId);

  const enc = await encryptCredential({
    userPublicKey: publicKeyRaw,
    linkedAccountId: "acct_1",
    plaintext: "refresh-token-value",
  });

  // Later approval: re-derive KEK from the same PRF output and unwrap.
  const kek2 = await PB.deriveKek(prf, userId);
  const unwrapped = await PB.unwrapPrivateKey(kek2, wrapped, userId);
  const dek = await PB.deriveDek(unwrapped, enc.epk, "acct_1");

  expect(Buffer.from(dek).equals(Buffer.from(enc.dek))).toBe(true);
  expect(
    await decryptCredential({
      dek,
      linkedAccountId: "acct_1",
      ciphertext: enc.ciphertext,
    })
  ).toBe("refresh-token-value");
});

test("wrong PRF output cannot unwrap the private key", async () => {
  const kek = await PB.deriveKek(randomPrf(), "user_1");
  const { privateKey } = await PB.generateUserKeypair();
  const wrapped = await PB.wrapPrivateKey(kek, privateKey, "user_1");

  const otherKek = await PB.deriveKek(randomPrf(), "user_1");
  await expect(
    PB.unwrapPrivateKey(otherKek, wrapped, "user_1")
  ).rejects.toThrow();
});

test("wrapped key is bound to the user id", async () => {
  const prf = randomPrf();
  const kek = await PB.deriveKek(prf, "user_1");
  const { privateKey } = await PB.generateUserKeypair();
  const wrapped = await PB.wrapPrivateKey(kek, privateKey, "user_1");

  const kekOther = await PB.deriveKek(prf, "user_2");
  await expect(
    PB.unwrapPrivateKey(kekOther, wrapped, "user_2")
  ).rejects.toThrow();
});

test("ciphertext is bound to the linked account id", async () => {
  const { publicKeyRaw, privateKey } = await PB.generateUserKeypair();
  const enc = await encryptCredential({
    userPublicKey: publicKeyRaw,
    linkedAccountId: "acct_1",
    plaintext: "secret",
  });

  // A DEK derived for a different account id does not match.
  const wrongDek = await PB.deriveDek(privateKey, enc.epk, "acct_2");
  await expect(
    decryptCredential({
      dek: wrongDek,
      linkedAccountId: "acct_1",
      ciphertext: enc.ciphertext,
    })
  ).rejects.toThrow();

  // The right DEK with a swapped account id fails the AAD check.
  await expect(
    decryptCredential({
      dek: enc.dek,
      linkedAccountId: "acct_2",
      ciphertext: enc.ciphertext,
    })
  ).rejects.toThrow();
});

test("re-encryption yields a different DEK", async () => {
  const { publicKeyRaw } = await PB.generateUserKeypair();
  const a = await encryptCredential({
    userPublicKey: publicKeyRaw,
    linkedAccountId: "acct_1",
    plaintext: "secret",
  });
  const b = await encryptCredential({
    userPublicKey: publicKeyRaw,
    linkedAccountId: "acct_1",
    plaintext: "secret",
  });
  expect(Buffer.from(a.dek).equals(Buffer.from(b.dek))).toBe(false);
  await expect(
    decryptCredential({
      dek: a.dek,
      linkedAccountId: "acct_1",
      ciphertext: b.ciphertext,
    })
  ).rejects.toThrow();
});
