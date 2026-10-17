// Offline check of the wallet ECDSA profiles against published vectors.
//   Argent X: packages/extension/test/keyDerivation.test.ts (secret -> STARK keys at index 5, 7; grindKey)
//   Ethereum step: Hardhat's default mnemonic, first account private key
import { argentStarkKeyFromSecret, deriveAccountKeys, ethereumPrivateKey } from "./pq_keys.mjs";
import { grindKey } from "@scure/starknet";
import { mnemonicToSeedSync } from "@scure/bip39";

let failed = 0;
const eq = (name, got, want) => {
  const ok = BigInt(got) === BigInt(want);
  if (!ok) failed++;
  console.log(`${ok ? "ok  " : "FAIL"} ${name}: ${got}${ok ? "" : ` (want ${want})`}`);
};

const SECRET = "0xe6904d63affe7a13cd30345b000c9b1ffc087832332d7303cf237ffda8a177d0";
eq("argent index 5", argentStarkKeyFromSecret(SECRET, 5).ecdsaPublicKey, "0x05c7c65bfda7a85af0681c85c9c440f0aa6825feef6f9c96e55fb2ce08c8d4bc");
eq("argent index 7", argentStarkKeyFromSecret(SECRET, 7).ecdsaPublicKey, "0x0605d5a0ece3b316f0d72221228acb7f01dcb34db74e0c02790db156741f5a86");
eq("argent grindKey", "0x" + grindKey("0x86F3E7293141F20A8BAFF320E8EE4ACCB9D4A4BF2B4D295E8CEE784DB46E0519"), "0x5c8c8683596c732541a59e03007b2d30dbbbb873556fe65b5fb63c16688f941");

const HARDHAT = "test test test test test test test test test test test junk";
eq("ethereum m/44'/60'/0'/0/0", ethereumPrivateKey(mnemonicToSeedSync(HARDHAT)), "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

const a = deriveAccountKeys(HARDHAT, 0, "argentx");
const p = deriveAccountKeys(HARDHAT, 0, "pq");
console.log("same words, argentx ECDSA:", a.ecdsaPublicKey);
console.log("same words, pq ECDSA:     ", p.ecdsaPublicKey);
console.log("Falcon key identical across profiles:", Buffer.compare(Buffer.from(a.falconPublicKey), Buffer.from(p.falconPublicKey)) === 0);
process.exit(failed ? 1 : 0);
