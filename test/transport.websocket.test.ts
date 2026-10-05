import { listen, connect } from "../src/transport/websocket.js";

describe("websocket transport", () => {
  it("round-trips a binary DIDComm envelope as a single WS binary message", async () => {
    const received: Uint8Array[] = [];
    let resolveReceived: () => void;
    const receivedPromise = new Promise<void>((res) => {
      resolveReceived = res;
    });

    const server = await listen(0, (bytes) => {
      received.push(bytes);
      resolveReceived();
    });

    try {
      const client = await connect(`ws://127.0.0.1:${server.port}`);
      try {
        const envelope = new TextEncoder().encode(
          JSON.stringify({ ciphertext: "abc", iv: "xyz" }),
        );
        client.send(envelope);

        await receivedPromise;

        expect(received).toHaveLength(1);
        expect(Buffer.from(received[0]).equals(Buffer.from(envelope))).toBe(true);
      } finally {
        await client.close();
      }
    } finally {
      await server.close();
    }
  });

  it("keeps distinct envelopes framed as separate messages when sent back to back", async () => {
    const received: Uint8Array[] = [];
    let resolveSecond: () => void;
    const secondReceived = new Promise<void>((res) => {
      resolveSecond = res;
    });

    const server = await listen(0, (bytes) => {
      received.push(bytes);
      if (received.length === 2) resolveSecond();
    });

    try {
      const client = await connect(`ws://127.0.0.1:${server.port}`);
      try {
        const first = new TextEncoder().encode(JSON.stringify({ seq: 1 }));
        const second = new TextEncoder().encode(JSON.stringify({ seq: 2, pad: "x".repeat(32) }));

        client.send(first);
        client.send(second);

        await secondReceived;

        expect(received).toHaveLength(2);
        expect(Buffer.from(received[0]).equals(Buffer.from(first))).toBe(true);
        expect(Buffer.from(received[1]).equals(Buffer.from(second))).toBe(true);
      } finally {
        await client.close();
      }
    } finally {
      await server.close();
    }
  });
});
