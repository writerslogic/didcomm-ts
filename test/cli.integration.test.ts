/**
 * Integration tests for src/chat/cli.ts, driven as a real child process
 * (node dist/chat/cli.js) against the compiled build, per the project
 * convention of exercising cross-module behavior through the actual
 * network/process boundary rather than through unit mocks (see
 * e2e.stack.test.ts, transport.http.test.ts).
 *
 * Each test gets its own fresh temp HOME/cwd so `.didcomm-ts/identity.json`
 * (see src/chat/keys.ts, which resolves relative to process.cwd()) never
 * collides across tests or with a developer's real `.didcomm-ts`.
 *
 * NOTE: cli.ts is concurrently being hardened (API auth token, persistent
 * message log, --cbor flag for `send`) by another agent in this same
 * working tree. Assertions below are deliberately loose where that work
 * could plausibly change today's exact behavior; each such spot is flagged
 * with a one-line comment.
 */
import { randomUUID } from "node:crypto";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, jest } from "@jest/globals";
import { loadOrCreateIdentity } from "../src/chat/keys.js";

const CLI_PATH = fileURLToPath(new URL("../dist/chat/cli.js", import.meta.url));

if (!existsSync(CLI_PATH)) {
  throw new Error(`${CLI_PATH} does not exist; run "npm run build" before running this test file`);
}

/** Spawns the CLI as a child process with its own isolated HOME/cwd. */
function spawnCli(
  args: string[],
  cwd: string,
): ChildProcessWithoutNullStreams {
  // Copy the env and strip DIDCOMM_TS_PASSPHRASE so a developer's real
  // passphrase never applies to these throwaway identities, and HOME is
  // pinned to the same isolated dir as cwd in case future hardening stores
  // anything (e.g. an API token) relative to HOME instead of cwd.
  const env = { ...process.env, HOME: cwd };
  delete env.DIDCOMM_TS_PASSPHRASE;
  return spawn(process.execPath, [CLI_PATH, ...args], { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
}

function makeTempDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

/** Accumulates a child's stdout/stderr into growing strings. */
function captureOutput(child: ChildProcessWithoutNullStreams): { stdout: () => string; stderr: () => string } {
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk: Buffer) => {
    stdout += chunk.toString("utf8");
  });
  child.stderr.on("data", (chunk: Buffer) => {
    stderr += chunk.toString("utf8");
  });
  return { stdout: () => stdout, stderr: () => stderr };
}

/** Waits until `predicate()` is true, polling, or rejects after `timeoutMs`. */
async function waitFor(predicate: () => boolean, timeoutMs: number, label: string): Promise<void> {
  const start = Date.now();
  while (!predicate()) {
    if (Date.now() - start > timeoutMs) {
      throw new Error(`timed out waiting for: ${label}`);
    }
    await new Promise((r) => setTimeout(r, 50));
  }
}

/** Waits for the child process to exit and resolves with its exit code. */
function waitForExit(child: ChildProcessWithoutNullStreams): Promise<number | null> {
  return new Promise((resolve) => {
    child.once("exit", (code) => resolve(code));
  });
}

const tempDirs: string[] = [];
const children: ChildProcessWithoutNullStreams[] = [];

function trackedTempDir(prefix: string): string {
  const dir = makeTempDir(prefix);
  tempDirs.push(dir);
  return dir;
}

function trackedSpawn(args: string[], cwd: string): ChildProcessWithoutNullStreams {
  const child = spawnCli(args, cwd);
  children.push(child);
  return child;
}

afterEach(async () => {
  for (const child of children.splice(0)) {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGTERM");
      await Promise.race([
        waitForExit(child),
        new Promise((r) => setTimeout(r, 2000)),
      ]);
    }
  }
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("chat CLI integration", () => {
  jest.setTimeout(30000);

  it("listen on an ephemeral port starts a real HTTP server that answers GET requests", async () => {
    const dir = trackedTempDir("didcomm-ts-listen-");
    const child = trackedSpawn(["listen", "0"], dir);
    const out = captureOutput(child);

    await waitFor(() => /listening on port \d+/.test(out.stdout()), 15000, "listen to report its bound port");
    const match = out.stdout().match(/listening on port (\d+)/);
    expect(match).not.toBeNull();
    const port = Number(match![1]);
    expect(Number.isInteger(port)).toBe(true);
    expect(port).toBeGreaterThan(0);

    // GET is not a route this receiver handles; even a 404/405 proves the
    // server is actually up and accepting connections.
    const res = await fetch(`http://127.0.0.1:${port}/`, { method: "GET" });
    expect(typeof res.status).toBe("number");
    expect(res.status).toBeGreaterThanOrEqual(400);

    child.kill("SIGTERM");
    await waitForExit(child);
  });

  it("send with missing required arguments exits non-zero and prints usage to stderr", async () => {
    const dir = trackedTempDir("didcomm-ts-send-noargs-");
    const child = trackedSpawn(["send"], dir);
    const out = captureOutput(child);
    const code = await waitForExit(child);

    expect(code).not.toBe(0);
    expect(out.stderr()).toMatch(/usage/i);
  });

  it("send with a peer-did but no endpoint/text exits non-zero and prints usage to stderr", async () => {
    const dir = trackedTempDir("didcomm-ts-send-missing-endpoint-");
    const child = trackedSpawn(["send", "did:key:z6LShs9GGBtsL5vNjbrcSjhiq4vb2cv9sVsnJ8iEHXvQEzgE"], dir);
    const out = captureOutput(child);
    const code = await waitForExit(child);

    expect(code).not.toBe(0);
    expect(out.stderr()).toMatch(/usage/i);
  });

  it("send with a peer-did and endpoint but no text exits non-zero and prints usage to stderr", async () => {
    const dir = trackedTempDir("didcomm-ts-send-missing-text-");
    const child = trackedSpawn(
      ["send", "did:key:z6LShs9GGBtsL5vNjbrcSjhiq4vb2cv9sVsnJ8iEHXvQEzgE", "http://127.0.0.1:1/"],
      dir,
    );
    const out = captureOutput(child);
    const code = await waitForExit(child);

    expect(code).not.toBe(0);
    expect(out.stderr()).toMatch(/usage/i);
  });

  it("delivers one message end-to-end from send to a listening did:key peer", async () => {
    const receiverDir = trackedTempDir("didcomm-ts-receiver-");
    const senderDir = trackedTempDir("didcomm-ts-sender-");

    // Seed the receiver's identity directly via keys.ts (reused, not
    // reimplemented) so we know its did:key up front; the override path
    // matches exactly what the receiver child will itself load (cwd +
    // ".didcomm-ts") since both point at `${receiverDir}/.didcomm-ts`.
    const receiverIdentity = loadOrCreateIdentity(join(receiverDir, ".didcomm-ts"));
    expect(receiverIdentity.did.startsWith("did:key:")).toBe(true);

    // Start the receiver first.
    const receiver = trackedSpawn(["listen", "0"], receiverDir);
    const receiverOut = captureOutput(receiver);
    await waitFor(
      () => /listening on port \d+/.test(receiverOut.stdout()),
      15000,
      "receiver to report its bound port",
    );
    // Sanity check the seeded identity is the one the child actually loaded;
    // otherwise unpack would fail downstream with an opaque timeout instead
    // of a clear assertion failure here.
    expect(receiverOut.stdout()).toContain(`identity: ${receiverIdentity.did}`);

    const portMatch = receiverOut.stdout().match(/listening on port (\d+)/);
    const port = Number(portMatch![1]);
    const endpoint = `http://127.0.0.1:${port}/`;

    const marker = `integration-test-message-${randomUUID()}`;

    // Then send, from a separate identity/dir.
    const sender = trackedSpawn(["send", receiverIdentity.did, endpoint, marker], senderDir);
    const senderOut = captureOutput(sender);
    const sendCode = await waitForExit(sender);
    expect(sendCode).toBe(0);
    expect(senderOut.stdout()).toContain("sent to");

    // Assert delivery from the receiver's own stdout, not merely from
    // send's exit code (send does not check the response status).
    await waitFor(
      () => receiverOut.stdout().includes(marker),
      15000,
      "receiver stdout to contain the sent message",
    );
    expect(receiverOut.stdout()).toContain(marker);

    receiver.kill("SIGTERM");
    await waitForExit(receiver);
  });

  it("mediate with a missing mediator-did argument exits non-zero with usage, with no network call", async () => {
    const dir = trackedTempDir("didcomm-ts-mediate-noargs-");
    const child = trackedSpawn(["mediate"], dir);
    const out = captureOutput(child);
    const code = await waitForExit(child);

    expect(code).not.toBe(0);
    expect(out.stderr()).toMatch(/usage/i);
  });

  it("pickup with a missing mediator-did argument exits non-zero with usage, with no network call", async () => {
    const dir = trackedTempDir("didcomm-ts-pickup-noargs-");
    const child = trackedSpawn(["pickup"], dir);
    const out = captureOutput(child);
    const code = await waitForExit(child);

    expect(code).not.toBe(0);
    expect(out.stderr()).toMatch(/usage/i);
  });
});
