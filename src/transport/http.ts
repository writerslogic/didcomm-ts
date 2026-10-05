import express, { type Express, type Request, type Response as ExpressResponse } from "express";
import type { Server } from "node:http";

/**
 * Content-types this transport recognizes for a DIDComm envelope body.
 */
export type DidCommContentType =
  | "application/didcomm-encrypted+json"
  | "application/didcomm-encrypted+cbor";

export type OnMessage = (
  envelopeBytes: Uint8Array,
  contentType: DidCommContentType,
) => void | Promise<void>;

const SUPPORTED_CONTENT_TYPES: readonly DidCommContentType[] = [
  "application/didcomm-encrypted+json",
  "application/didcomm-encrypted+cbor",
];

function isSupportedContentType(value: string): value is DidCommContentType {
  return (SUPPORTED_CONTENT_TYPES as readonly string[]).includes(value);
}

/**
 * Builds an express app that receives a DIDComm envelope on POST / and
 * invokes `onMessage` with the raw envelope bytes and the content-type
 * that produced them. The content-type on the request determines how the
 * body is parsed: JSON bodies are re-serialized to bytes (so the handler
 * always receives bytes regardless of wire format), CBOR bodies are
 * passed through as the raw bytes received.
 */
export function createHttpReceiver(onMessage: OnMessage): Express {
  const app = express();

  app.use(
    express.raw({
      type: [...SUPPORTED_CONTENT_TYPES],
      limit: "10mb",
    }),
  );

  app.post("/", (req: Request, res: ExpressResponse) => {
    const contentType = (req.headers["content-type"] ?? "").split(";")[0].trim();

    if (!isSupportedContentType(contentType)) {
      res.status(415).json({ error: "unsupported content-type" });
      return;
    }

    const body = req.body as Buffer;
    if (!body || body.length === 0) {
      res.status(400).json({ error: "empty body" });
      return;
    }

    void Promise.resolve(onMessage(new Uint8Array(body), contentType))
      .then(() => {
        res.status(202).end();
      })
      .catch((err: unknown) => {
        res.status(500).json({ error: err instanceof Error ? err.message : String(err) });
      });
  });

  return app;
}

/**
 * Starts an HTTP receiver listening on `port` (0 for an ephemeral port).
 * Resolves once the server is listening, with the server and the port
 * actually bound.
 */
export function listenHttp(
  port: number,
  onMessage: OnMessage,
): Promise<{ server: Server; port: number; close: () => Promise<void> }> {
  const app = createHttpReceiver(onMessage);
  return new Promise((resolve, reject) => {
    const server = app.listen(port);
    server.once("error", reject);
    server.once("listening", () => {
      const address = server.address();
      const boundPort = typeof address === "object" && address !== null ? address.port : port;
      resolve({
        server,
        port: boundPort,
        close: () =>
          new Promise<void>((res, rej) => {
            server.close((err) => (err ? rej(err) : res()));
          }),
      });
    });
  });
}

/**
 * Sends a DIDComm envelope to `url` via HTTP POST with the given
 * content-type header.
 */
export async function sendHttp(
  url: string,
  envelopeBytes: Uint8Array,
  contentType: DidCommContentType,
): Promise<globalThis.Response> {
  return fetch(url, {
    method: "POST",
    headers: { "content-type": contentType },
    body: Buffer.from(envelopeBytes),
  });
}
