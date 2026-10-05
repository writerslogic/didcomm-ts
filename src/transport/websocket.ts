import { WebSocket, WebSocketServer } from "ws";

export type WsOnMessage = (envelopeBytes: Uint8Array) => void | Promise<void>;

export interface WsServerHandle {
  readonly port: number;
  close: () => Promise<void>;
}

/**
 * Starts a WebSocket server on `port` (0 for an ephemeral port). Each
 * incoming binary WS message is treated as one DIDComm envelope and
 * passed to `onMessage`.
 */
export function listen(port: number, onMessage: WsOnMessage): Promise<WsServerHandle> {
  return new Promise((resolve, reject) => {
    const wss = new WebSocketServer({ port });

    wss.once("error", reject);
    wss.once("listening", () => {
      const address = wss.address();
      const boundPort = typeof address === "object" && address !== null ? address.port : port;

      wss.on("connection", (socket) => {
        socket.on("message", (data, isBinary) => {
          const bytes = isBinary
            ? new Uint8Array(data as Buffer)
            : new Uint8Array(Buffer.from(data as Buffer));
          void onMessage(bytes);
        });
      });

      resolve({
        port: boundPort,
        close: () =>
          new Promise<void>((res, rej) => {
            wss.close((err) => (err ? rej(err) : res()));
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
 * Connects to a WebSocket server at `url`, resolving once the connection
 * is open. Each envelope is sent/received as a single binary WS message.
 */
export function connect(url: string): Promise<WsClient> {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url);
    let handler: WsOnMessage | undefined;

    socket.once("error", reject);
    socket.once("open", () => {
      socket.on("message", (data, isBinary) => {
        if (!handler) return;
        const bytes = isBinary
          ? new Uint8Array(data as Buffer)
          : new Uint8Array(Buffer.from(data as Buffer));
        void handler(bytes);
      });

      resolve({
        send: (envelopeBytes: Uint8Array) => {
          socket.send(envelopeBytes, { binary: true });
        },
        onMessage: (cb: WsOnMessage) => {
          handler = cb;
        },
        close: () =>
          new Promise<void>((res) => {
            socket.once("close", () => res());
            socket.close();
          }),
      });
    });
  });
}
