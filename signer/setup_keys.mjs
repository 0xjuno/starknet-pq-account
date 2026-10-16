// Generates TESTNET-ONLY keys for the hybrid-account demo and prints the deployer address.
// Never send real funds to anything derived here.
import { ec, hash, stark } from "starknet";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { KEYS } from "./config.mjs";

const OZ_ACCOUNT_CLASS = "0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564";

mkdirSync(KEYS, { recursive: true });

function loadOrCreate(name) {
  const path = `${KEYS}/${name}.json`;
  if (existsSync(path)) return JSON.parse(readFileSync(path, "utf8"));
  const privateKey = stark.randomAddress();
  const publicKey = ec.starkCurve.getStarkKey(privateKey);
  const data = { network: "sepolia-testnet-only", privateKey, publicKey };
  writeFileSync(path, JSON.stringify(data, null, 2));
  return data;
}

const deployer = loadOrCreate("deployer-ecdsa");
const hybridEcdsa = loadOrCreate("hybrid-ecdsa");

const deployerAddress = hash.calculateContractAddressFromHash(
  deployer.publicKey, OZ_ACCOUNT_CLASS, [deployer.publicKey], 0,
);
writeFileSync(`${KEYS}/deployer-address.txt`, deployerAddress);

console.log("deployer (OZ account, Sepolia) address:", deployerAddress);
console.log("hybrid ECDSA public key:", hybridEcdsa.publicKey);
