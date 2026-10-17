// "Starknet PQ key backup v0.1": one BIP39 mnemonic -> STARK-curve ECDSA key + Falcon-512 key.
// Falcon keygen is @noble/post-quantum's deterministic keygen(seed48), so the same mnemonic
// yields the same key in Node and in the browser. TESTNET / DEMO ONLY.
//
// The ECDSA key can follow an existing wallet's derivation, so the words a user already has
// restore both the account's current key and the new Falcon key:
//   "pq"      this profile: BIP32 from the BIP39 seed, m/44'/9004'/0'/0/i, grindKey
//   "argentx" Argent X / Ready: the BIP39 words give an Ethereum key (m/44'/60'/0'/0/0, as
//             ethers HDNodeWallet.fromPhrase); that key is the BIP32 master seed for
//             m/44'/9004'/0'/0/i, then grindKey (argent-x ArgentSigner.ts)
//   "braavos" same computation as "pq"; Braavos does not publish its wallet code, so this
//             matches third-party scripts only and is unconfirmed
// The Falcon key always comes from the BIP39 seed, independent of the ECDSA profile.
import { mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { HDKey } from "@scure/bip32";
import { getStarkKey, grindKey } from "@scure/starknet";
import { hkdf } from "@noble/hashes/hkdf";
import { sha512 } from "@noble/hashes/sha2";
import { hexToBytes } from "@noble/hashes/utils";
import { falcon512 } from "@noble/post-quantum/falcon.js";

export const PROFILE = "starknet-pq-backup-v0.1";
export const ECDSA_PROFILES = ["pq", "argentx", "braavos"];
const utf8 = (s) => new TextEncoder().encode(s);
const hex0x = (h) => (h.startsWith("0x") ? h : "0x" + h);

function starkKeyFromMaster(masterSeed, index) {
  const node = HDKey.fromMasterSeed(masterSeed).derive(`m/44'/9004'/0'/0/${index}`);
  const ecdsaPrivateKey = hex0x(grindKey(node.privateKey));
  const ecdsaPublicKey = "0x" + BigInt(getStarkKey(ecdsaPrivateKey)).toString(16);
  return { ecdsaPrivateKey, ecdsaPublicKey };
}

/** Argent X: an Ethereum private key (hex) is the master seed, leading zero bytes dropped. */
export function argentStarkKeyFromSecret(secretHex, index = 0) {
  let h = BigInt(secretHex).toString(16);
  if (h.length % 2) h = "0" + h;
  return starkKeyFromMaster(hexToBytes(h), index);
}

export function ethereumPrivateKey(seed) {
  const node = HDKey.fromMasterSeed(seed).derive("m/44'/60'/0'/0/0");
  return "0x" + Buffer.from(node.privateKey).toString("hex");
}

export function deriveAccountKeys(mnemonic, index = 0, ecdsaProfile = "pq") {
  if (!validateMnemonic(mnemonic, wordlist)) throw new Error("invalid mnemonic");
  if (!ECDSA_PROFILES.includes(ecdsaProfile)) throw new Error(`unknown ECDSA profile ${ecdsaProfile}`);
  const seed = mnemonicToSeedSync(mnemonic);
  const { ecdsaPrivateKey, ecdsaPublicKey } =
    ecdsaProfile === "argentx"
      ? argentStarkKeyFromSecret(ethereumPrivateKey(seed), index)
      : starkKeyFromMaster(seed, index);
  const falconSeed = hkdf(sha512, seed, utf8(PROFILE), utf8(`falcon-512/noble/account/${index}`), 48);
  const { publicKey: falconPublicKey, secretKey: falconSecretKey } = falcon512.keygen(falconSeed);
  return { ecdsaPrivateKey, ecdsaPublicKey, falconPublicKey, falconSecretKey };
}
