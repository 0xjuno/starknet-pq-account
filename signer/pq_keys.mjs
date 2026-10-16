// "Starknet PQ key backup v0.1": one BIP39 mnemonic -> STARK-curve ECDSA key + Falcon-512 key.
// Falcon keygen is @noble/post-quantum's deterministic keygen(seed48), so the same mnemonic
// yields the same key in Node and in the browser. TESTNET / DEMO ONLY.
import { mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { HDKey } from "@scure/bip32";
import { getStarkKey, grindKey } from "@scure/starknet";
import { hkdf } from "@noble/hashes/hkdf";
import { sha512 } from "@noble/hashes/sha2";
import { falcon512 } from "@noble/post-quantum/falcon.js";

export const PROFILE = "starknet-pq-backup-v0.1";
const utf8 = (s) => new TextEncoder().encode(s);

export function deriveAccountKeys(mnemonic, index = 0) {
  if (!validateMnemonic(mnemonic, wordlist)) throw new Error("invalid mnemonic");
  const seed = mnemonicToSeedSync(mnemonic);
  const node = HDKey.fromMasterSeed(seed).derive(`m/44'/9004'/0'/0/${index}`);
  const g = grindKey(node.privateKey);
  const ecdsaPrivateKey = g.startsWith("0x") ? g : "0x" + g;
  const ecdsaPublicKey = "0x" + BigInt(getStarkKey(ecdsaPrivateKey)).toString(16);
  const falconSeed = hkdf(sha512, seed, utf8(PROFILE), utf8(`falcon-512/noble/account/${index}`), 48);
  const { publicKey: falconPublicKey, secretKey: falconSecretKey } = falcon512.keygen(falconSeed);
  return { ecdsaPrivateKey, ecdsaPublicKey, falconPublicKey, falconSecretKey };
}
