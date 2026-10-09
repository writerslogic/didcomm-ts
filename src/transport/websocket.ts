/**
 * WebSocket transport with no dependencies: a minimal RFC 6455 server on
 * `node:http` (receive-only, one DIDComm envelope per message) and a client
 * on the global `WebSocket` (Node >= 22).
 */

import { createHash } from "node:crypto";
import { createServer, type IncomingMessage } from "node:http";
import type { Duplex } from "node:stream";

export type WsOnMessage = (envelopeBytes: Uint8Array) => void | Promise<void>;

export interface WsServerHandle {
  readonly port: number;
  close: () => Promise<void>;
}

export interface WsServerOptions {
  /** Largest accepted message in bytes (after reassembly); larger closes with 1009. Default 10 MiB. */
  maxMessageBytes?: number;
}

const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const DEFAULT_MAX_MESSAGE_BYTES = 10 * 1024 * 1024;
const OPCODE = { continuation: 0x0, text: 0x1, binary: 0x2, close: 0x8, ping: 0x9, pong: 0xa } as const;

function frame(opcode: number, payload: Uint8Array = new Uint8Array(0)): Buffer {
  const length = payload.length;
  const header =
    length < 126
      ? Buffer.from([0x80 | opcode, length])
      : length < 0x10000
        ? Buffer.from([0x80 | opcode, 126, length >> 8, length & 0xff])
        : (() => {
            const h = Buffer.alloc(10);
            h[0] = 0x80 | opcode;
            h[1] = 127;
            h.writeBigUInt64BE(BigInt(length), 2);
            return h;
          })();
  return Buffer.concat([header, payload]);
}

function closeFrame(code: number): Buffer {
  const payload = Buffer.alloc(2);
  payload.writeUInt16BE(code);
  return frame(OPCODE.close, payload);
}

/** Parses client frames from one socket and reassembles fragmented messages. */
class FrameReader {
  private buffer = Buffer.alloc(0);
  private pending: Buffer[] = [];
  private pendingBytes = 0;
  /** Total buffered bytes needed before the next parse attempt can make progress. */
  private needed = 2;
  private closed = false;
  private fragments: Buffer[] = [];
  private fragmentBytes = 0;
  private fragmentOpcode: number | null = null;

  constructor(
    private readonly socket: Duplex,
    private readonly maxMessageBytes: number,
    private readonly onMessage: WsOnMessage,
  ) {}

  private fail(code: number): void {
    this.closed = true;
    this.socket.end(closeFrame(code));
    this.buffer = Buffer.alloc(0);
    this.pending = [];
  }

  /** Buffers chunks without copying until enough bytes arrive for the next frame. */
  push(chunk: Buffer): void {
    if (this.closed) return;
    this.pending.push(chunk);
    this.pendingBytes += chunk.length;
    if (this.buffer.length + this.pendingBytes < this.needed) return;
    this.buffer = Buffer.concat([this.buffer, ...this.pending]);
    this.pending = [];
    this.pendingBytes = 0;
    this.needed = 2;
    this.parse();
  }

  private parse(): void {
    while (!this.closed && this.buffer.length >= 2) {
      const fin = (this.buffer[0] & 0x80) !== 0;
      const opcode = this.buffer[0] & 0x0f;
      const masked = (this.buffer[1] & 0x80) !== 0;
      let length = this.buffer[1] & 0x7f;
      let offset = 2;
      if (this.buffer[0] & 0x70) return this.fail(1002); // no extensions negotiated
      if (!masked) return this.fail(1002); // clients must mask (RFC 6455 §5.1)
      if (length === 126) {
        if (this.buffer.length < 4) return void (this.needed = 4);
        length = this.buffer.readUInt16BE(2);
        offset = 4;
      } else if (length === 127) {
        if (this.buffer.length < 10) return void (this.needed = 10);
        const big = this.buffer.readBigUInt64BE(2);
        if (big > BigInt(this.maxMessageBytes)) return this.fail(1009);
        length = Number(big);
        offset = 10;
      }
      const isControl = opcode >= 0x8;
      if (isControl && (!fin || length > 125)) return this.fail(1002);
      if (!isControl && this.fragmentBytes + length > this.maxMessageBytes) return this.fail(1009);
      if (this.buffer.length < offset + 4 + length) return void (this.needed = offset + 4 + length);

      const mask = this.buffer.subarray(offset, offset + 4);
      const payload = Buffer.from(this.buffer.subarray(offset + 4, offset + 4 + length));
      for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
      this.buffer = this.buffer.subarray(offset + 4 + length);

      switch (opcode) {
        case OPCODE.ping:
          this.socket.write(frame(OPCODE.pong, payload));
          break;
        case OPCODE.pong:
          break;
        case OPCODE.close:
          this.socket.end(frame(OPCODE.close, payload.subarray(0, 2)));
          return;
        case OPCODE.text:
        case OPCODE.binary:
        case OPCODE.continuation: {
          if ((opcode === OPCODE.continuation) !== (this.fragmentOpcode !== null)) return this.fail(1002);
          this.fragmentOpcode ??= opcode;
          this.fragments.push(payload);
          this.fragmentBytes += payload.length;
          if (fin) {
            const message = new Uint8Array(Buffer.concat(this.fragments));
            this.fragments = [];
            this.fragmentBytes = 0;
            this.fragmentOpcode = null;
            void Promise.resolve()
              .then(() => this.onMessage(message))
              .catch(() => this.fail(1011));
          }
          break;
        }
        default:
          return this.fail(1002);
      }
    }
  }
}

function rejectUpgrade(socket: Duplex, status: string): void {
  socket.end(`HTTP/1.1 ${status}\r\nConnection: close\r\n\r\n`);
}

/**
 * Starts a WebSocket server on `port` (0 for an ephemeral port). Each
 * incoming text or binary message is treated as one DIDComm envelope and
 * passed to `onMessage`.
 */
export function listen(port: number, onMessage: WsOnMessage, options: WsServerOptions = {}): Promise<WsServerHandle> {
  const maxMessageBytes = options.maxMessageBytes ?? DEFAULT_MAX_MESSAGE_BYTES;
  const sockets = new Set<Duplex>();
  const server = createServer((_req, res) => {
    res.writeHead(426, { upgrade: "websocket" }).end();
  });

  server.on("upgrade", (req: IncomingMessage, socket: Duplex) => {
    const key = req.headers["sec-websocket-key"];
    if (
      req.headers.upgrade?.toLowerCase() !== "websocket" ||
      req.headers["sec-websocket-version"] !== "13" ||
      typeof key !== "string" ||
      Buffer.from(key, "base64").length !== 16
    ) {
      rejectUpgrade(socket, "400 Bad Request");
      return;
    }
    const accept = createHash("sha1").update(key + WS_GUID).digest("base64");
    socket.write(
      "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
    );
    sockets.add(socket);
    const reader = new FrameReader(socket, maxMessageBytes, onMessage);
    socket.on("data", (chunk: Buffer) => reader.push(chunk));
    socket.on("error", () => socket.destroy());
    socket.on("close", () => sockets.delete(socket));
  });

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, () => {
      const address = server.address();
      const boundPort = typeof address === "object" && address !== null ? address.port : port;
      resolve({
        port: boundPort,
        close: () =>
          new Promise<void>((res, rej) => {
            for (const socket of sockets) socket.end(closeFrame(1001));
            server.close((err) => (err ? rej(err) : res()));
            for (const socket of sockets) socket.destroy();
          }),
      });
    });
  });
}

export interface WsClient {
  send: (envelopeBytes: Uint8Array) => void;
  onMessage: (cb: WsOnMessage) => void;
  close: () => Promise<void>;
}

/**
 * Connects to a WebSocket server at `url` with the global `WebSocket`,
 * resolving once the connection is open. Each envelope is sent/received as
 * a single binary WS message.
 */
export function connect(url: string): Promise<WsClient> {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url);
    socket.binaryType = "arraybuffer";
    let handler: WsOnMessage | undefined;

    socket.addEventListener("error", () => reject(new Error(`WebSocket connection to ${url} failed`)), { once: true });
    socket.addEventListener(
      "open",
      () => {
        socket.addEventListener("message", (event: MessageEvent) => {
          if (!handler) return;
          const data = event.data as ArrayBuffer | string;
          void handler(typeof data === "string" ? new TextEncoder().encode(data) : new Uint8Array(data));
        });
        resolve({
          send: (envelopeBytes: Uint8Array) => socket.send(envelopeBytes),
          onMessage: (cb: WsOnMessage) => {
            handler = cb;
          },
          close: () =>
            new Promise<void>((res) => {
              if (socket.readyState === WebSocket.CLOSED) return res();
              socket.addEventListener("close", () => res(), { once: true });
              socket.close();
            }),
        });
      },
      { once: true },
    );
  });
}
