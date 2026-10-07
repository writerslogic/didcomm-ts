#!/usr/bin/env node
/**
 * Self-contained, end-to-end demo of a real DIDComm v2 round trip using the
 * built chat CLI (dist/chat/cli.js): Bob listens on an ephemeral port, Alice
 * sends him an authcrypt'd message, and we wait for Bob's receiver to log
 * the decrypted content back out.
 *
 * Usage:
 *   npm run build
 *   node scripts/demo.mjs
 *
 * Exits 0 on a verified round trip, non-zero (with a clear message) on any
 * failure, including a timeout waiting for Bob to receive the message.
 */
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { createInterface } from "node:readline";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const RECEIVE_TIMEOUT_MS = 5000;
const STARTUP_TIMEOUT_MS = 5000;
const EXIT_TIMEOUT_MS = 3000;

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(SCRIPT_DIR, "..");
const CLI_PATH = join(REPO_ROOT, "dist", "chat", "cli.js");

const DEMO_TEXT = "Hey Bob, it's Alice — this message was end-to-end authcrypted, sent over real HTTP, and decrypted on your side. 👋";

// --- tiny color helper, degrades to plain text under NO_COLOR or a non-TTY ---
const colorsEnabled = !process.env.NO_COLOR && process.stdout.isTTY;
function paint(code, text) {
  return colorsEnabled ? `\x1b[${code}m${text}\x1b[0m` : text;
}
const bold = (s) => paint("1", s);
const green = (s) => paint("1;32", s);
const dim = (s) => paint("2", s);
const red = (s) => paint("1;31", s);
const cyan = (s) => paint("36", s);

const RULE = "=".repeat(60);

function header(text) {
  console.log("");
  console.log(bold(cyan(RULE)));
  console.log(bold(cyan(`  ${text}`)));
  console.log(bold(cyan(RULE)));
}

function step(n, total, text) {
  console.log("");
  console.log(bold(`Step ${n}/${total}: ${text}`));
}

function logLine(who, line) {
  console.log(dim(`(${who}) `) + line);
}

function cmdLine(cmd) {
  console.log(dim(`  $ ${cmd}`));
}

// --- preflight ---
if (!existsSync(CLI_PATH)) {
  console.error(
    red(
      `error: ${CLI_PATH} does not exist.\n` +
        "Run `npm run build` first to produce dist/, then re-run this demo.",
    ),
  );
  process.exit(1);
}

/** Spawns the CLI, wires up prefixed line logging, and returns the child plus its line emitter. */
function spawnCli(who, args, cwd) {
  const child = spawn(process.execPath, [CLI_PATH, ...args], {
    cwd,
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });

  const stdoutLines = createInterface({ input: child.stdout });
  const stderrLines = createInterface({ input: child.stderr });
  const listeners = new Set();

  stdoutLines.on("line", (line) => {
    logLine(who, line);
    for (const fn of listeners) fn(line);
  });
  // Startup warnings (e.g. "no passphrase set") are expected noise, not errors;
  // show them dimmed rather than hiding stderr entirely.
  stderrLines.on("line", (line) => logLine(who, dim(line)));

  return {
    child,
    onLine(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
  };
}

/** Resolves with the first line matching `predicate`, or rejects after `timeoutMs`. */
function waitForLine(handle, predicate, timeoutMs, description) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      unsubscribe();
      reject(new Error(`timed out after ${timeoutMs}ms waiting for: ${description}`));
    }, timeoutMs);
    const unsubscribe = handle.onLine((line) => {
      const match = predicate(line);
      if (match) {
        clearTimeout(timer);
        unsubscribe();
        resolve(match === true ? line : match);
      }
    });
  });
}

function killAndWait(child) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      resolve();
    }, EXIT_TIMEOUT_MS);
    child.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
    child.kill("SIGTERM");
  });
}

let aliceDir;
let bobDir;
let bob;

async function main() {
  header("DIDComm-TS Live Demo");

  step(1, 4, "Create two isolated identities (Alice, Bob)");
  aliceDir = mkdtempSync(join(tmpdir(), "didcomm-demo-alice-"));
  bobDir = mkdtempSync(join(tmpdir(), "didcomm-demo-bob-"));
  console.log(`  Alice's store: ${aliceDir}/.didcomm-ts`);
  console.log(`  Bob's store:   ${bobDir}/.didcomm-ts`);

  step(2, 4, "Bob starts listening on an ephemeral port");
  cmdLine("node dist/chat/cli.js listen 0");
  const bobHandle = spawnCli("Bob", ["listen", "0"], bobDir);
  bob = bobHandle.child;

  // Subscribe to both startup lines concurrently: they are printed back to
  // back, so waiting for them sequentially risks missing the second line
  // between the first promise resolving and the second subscription attaching.
  const bobReady = Promise.all([
    waitForLine(
      bobHandle,
      (line) => {
        const m = /^identity: (did:key:\S+)$/.exec(line);
        return m ? m[1] : null;
      },
      STARTUP_TIMEOUT_MS,
      "Bob's identity line",
    ),
    waitForLine(
      bobHandle,
      (line) => {
        const m = /^listening on port (\d+)$/.exec(line);
        return m ? m[1] : null;
      },
      STARTUP_TIMEOUT_MS,
      "Bob's listening-on-port line",
    ),
  ]).then(([bobDid, portLine]) => ({ bobDid, bobPort: Number(portLine) }));

  bob.once("exit", (code, signal) => {
    if (code !== 0 && code !== null) {
      console.error(red(`Bob's listen process exited early (code ${code}, signal ${signal})`));
    }
  });

  const { bobDid, bobPort } = await bobReady;
  const bobEndpoint = `http://127.0.0.1:${bobPort}`;
  console.log(green(`  ✔ Bob is up: ${bobDid} on ${bobEndpoint}`));

  step(3, 4, "Alice sends Bob a real, authcrypted chat message");
  cmdLine(`node dist/chat/cli.js send ${bobDid} ${bobEndpoint} "${DEMO_TEXT}"`);

  // Start waiting for Bob's decrypted receipt before sending, so there is no
  // race between the message arriving and us starting to listen for it.
  const bobReceived = waitForLine(
    bobHandle,
    (line) => (line.startsWith("[") && line.includes(DEMO_TEXT) ? true : null),
    RECEIVE_TIMEOUT_MS,
    "Bob's decrypted receipt of Alice's message",
  );

  const aliceHandle = spawnCli("Alice", ["send", bobDid, bobEndpoint, DEMO_TEXT], aliceDir);
  const aliceExitCode = await new Promise((resolve) => {
    aliceHandle.child.once("exit", (code) => resolve(code));
  });
  if (aliceExitCode !== 0) {
    throw new Error(`Alice's send process exited with code ${aliceExitCode}`);
  }

  step(4, 4, "Bob receives and decrypts it");
  const start = Date.now();
  await bobReceived;
  const elapsedMs = Date.now() - start;

  console.log("");
  console.log(green(bold(`✔ Round trip verified (decrypted on Bob's side in ${elapsedMs}ms)`)));
  console.log(bold(cyan(RULE)));
}

async function cleanup() {
  if (bob) await killAndWait(bob);
  for (const dir of [aliceDir, bobDir]) {
    if (!dir) continue;
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // best-effort cleanup; a leftover temp dir is not worth failing the demo over
    }
  }
}

main()
  .then(async () => {
    await cleanup();
    process.exit(0);
  })
  .catch(async (err) => {
    console.error("");
    console.error(red(bold(`✘ demo failed: ${err instanceof Error ? err.message : String(err)}`)));
    await cleanup();
    process.exit(1);
  });
