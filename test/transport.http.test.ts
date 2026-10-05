import { listenHttp, sendHttp, type DidCommContentType } from "../src/transport/http.js";

describe("http transport", () => {
  it("round-trips a binary DIDComm envelope over POST /", async () => {
    const received: Array<{ bytes: Uint8Array; contentType: DidCommContentType }> = [];
    let resolveReceived: () => void;
    const receivedPromise = new Promise<void>((res) => {
      resolveReceived = res;
    });

    const { port, close } = await listenHttp(0, (bytes, contentType) => {
      received.push({ bytes, contentType });
      resolveReceived();
    });

    try {
      const envelope = new TextEncoder().encode(
        JSON.stringify({ ciphertext: "abc", iv: "xyz" }),
      );

      const res = await sendHttp(
        `http://127.0.0.1:${port}/`,
        envelope,
        "application/didcomm-encrypted+json",
      );
      expect(res.status).toBe(202);

      await receivedPromise;

      expect(received).toHaveLength(1);
      expect(received[0].contentType).toBe("application/didcomm-encrypted+json");
      expect(Buffer.from(received[0].bytes).equals(Buffer.from(envelope))).toBe(true);
    } finally {
      await close();
    }
  });

  it("round-trips a cbor-content-typed binary envelope and rejects unsupported content-types", async () => {
    const received: Array<{ bytes: Uint8Array; contentType: DidCommContentType }> = [];

    const { port, close } = await listenHttp(0, (bytes, contentType) => {
      received.push({ bytes, contentType });
    });

    try {
      const envelope = new Uint8Array([0xa1, 0x01, 0x02, 0x03, 0xff]);

      const okRes = await sendHttp(
        `http://127.0.0.1:${port}/`,
        envelope,
        "application/didcomm-encrypted+cbor",
      );
      expect(okRes.status).toBe(202);

      const badRes = await fetch(`http://127.0.0.1:${port}/`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ not: "didcomm" }),
      });
      expect(badRes.status).toBe(415);

      expect(received).toHaveLength(1);
      expect(received[0].contentType).toBe("application/didcomm-encrypted+cbor");
      expect(Buffer.from(received[0].bytes).equals(Buffer.from(envelope))).toBe(true);
    } finally {
      await close();
    }
  });
});
