// End-to-end passkey test of the demo page in headless Edge with a CDP virtual authenticator
// (CTAP2, resident keys, user verification, PRF). Flow: public demo words -> lock with passkey ->
// reload -> unlock with passkey -> hybrid-signed transfer. TESTNET ONLY.
import http from "node:http";
import { readFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// PQ_PAGE=<file> drives another build of the page (for example the one on main).
const PAGE = resolve(process.env.PQ_PAGE || resolve(dirname(fileURLToPath(import.meta.url)), "../docs/index.html"));
// PQ_EXPECT_VERIFIER=<label>: the account panel must show this verifier after the restore.
const EXPECT_VERIFIER = process.env.PQ_EXPECT_VERIFIER;
let failed = false;
// Any Chromium browser with CDP WebAuthn support; set CHROME_PATH to override.
const EDGE = process.env.CHROME_PATH || "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe";
const PROFILE = join(tmpdir(), "pq-passkey-e2e-profile");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const server = http.createServer((req, res) => {
  if (req.url.startsWith("/browser-wallet.html")) { res.writeHead(200, { "content-type": "text/html; charset=utf-8" }); res.end(readFileSync(PAGE)); }
  else { res.writeHead(404); res.end(); }
}).listen(8765);

const edge = spawn(EDGE, ["--headless=new", "--disable-gpu", "--no-first-run", `--user-data-dir=${PROFILE}`, "--remote-debugging-port=9333", "about:blank"], { stdio: "ignore" });
let target;
for (let i = 0; i < 40 && !target; i++) {
  await sleep(500);
  try { target = (await (await fetch("http://127.0.0.1:9333/json/list")).json()).find((t) => t.type === "page"); } catch {}
}
if (!target) throw new Error("no page target");

const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r, { once: true }));
let id = 0; const pending = new Map(); const events = [];
ws.addEventListener("message", (m) => {
  const msg = JSON.parse(m.data);
  if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); } else if (msg.method) events.push(msg.method);
});
const send = (method, params = {}) => new Promise((resolve, reject) => {
  const i = ++id; pending.set(i, (msg) => (msg.error ? reject(new Error(`${method}: ${msg.error.message}`)) : resolve(msg.result)));
  ws.send(JSON.stringify({ id: i, method, params }));
});
const evalPage = async (expr) => (await send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true })).result.value;
const waitFor = (cond, ms) => evalPage(`(async () => { for (let i = 0; i < ${ms / 250}; i++) { if (${cond}) return true; await new Promise(r => setTimeout(r, 250)); } return false; })()`);
const text = (idName) => evalPage(`document.getElementById(${JSON.stringify(idName)}).textContent`);

await send("Page.enable"); await send("Runtime.enable");
await send("WebAuthn.enable", { enableUI: false });
const { authenticatorId } = await send("WebAuthn.addVirtualAuthenticator", { options: {
  protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true,
  hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true,
} });
console.log("virtual authenticator:", authenticatorId);

const load = async (url) => { await send("Page.navigate", { url }); await waitFor(`document.readyState === "complete" && !!window.starknet`, 20000); await sleep(4000); };
await load("http://localhost:8765/browser-wallet.html");

// 1. restore from the public demo words
await evalPage(`document.getElementById("demo").click()`);
await waitFor(`!document.getElementById("send").disabled`, 60000);
console.log("1 restore:", await text("check"));
if (EXPECT_VERIFIER) {
  await waitFor(`!/checking/.test(document.getElementById("verifier").textContent)`, 20000);
  const shown = await text("verifier");
  if (shown !== EXPECT_VERIFIER) failed = true;
  console.log(`  verifier: ${shown} ${shown === EXPECT_VERIFIER ? "(as expected)" : `FAIL: expected ${EXPECT_VERIFIER}`}`);
}

// 2. lock with a passkey
await evalPage(`document.getElementById("pk-save").click()`);
await waitFor(`/Locked|Cancelled|support|blocked|need/i.test(document.getElementById("pk-log").textContent)`, 30000);
console.log("2 lock:", await text("pk-log"));
const creds = await send("WebAuthn.getCredentials", { authenticatorId });
console.log("  credentials on authenticator:", creds.credentials.length);

// 3. reload: no words in memory, unlock with the passkey
await load("http://localhost:8765/browser-wallet.html");
console.log("3 after reload, unlock enabled:", await evalPage(`!document.getElementById("pk-unlock").disabled`), "|", await text("pk-log"));
await evalPage(`document.getElementById("pk-unlock").click()`);
await waitFor(`/Unlocked|Cancelled|cannot|support/i.test(document.getElementById("pk-log").textContent) && (!document.getElementById("send").disabled || /bad/.test(document.getElementById("pk-log").className))`, 60000);
console.log("  unlock:", await text("pk-log"), "|", await text("check"));

// 4. send with keys unlocked by the passkey
if (!(await evalPage(`document.getElementById("send").disabled`))) {
  await evalPage(`document.getElementById("send").click()`);
  await waitFor(`/SUCCEEDED|REVERTED|Failed/.test(document.getElementById("log").textContent)`, 180000);
  const sent = await text("log");
  if (!/SUCCEEDED/.test(sent)) failed = true;
  console.log("4 send:", sent.replace(/\n/g, " | "));
} else failed = true;

ws.close(); edge.kill(); server.close();
process.exit(failed ? 1 : 0);
