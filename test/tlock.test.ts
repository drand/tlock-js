import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import {
  decrypt,
  encrypt,
  inspect,
  quicknet,
  roundAt,
  roundTime,
  TlockError,
} from "../src/index.js";
import { payload, quicknetBeacon as beacon, vectors } from "./fixtures.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const round = beacon.round;
const chain = quicknet.chain;
const offline = { beacon };
const sample = encrypt(payload(64), { round });

function rewriteHeader(
  bytes: Uint8Array,
  edit: (header: string) => string,
): Uint8Array {
  const start = decoder.decode(bytes.subarray(0, 300)).indexOf("\n--- ");
  const end = bytes.indexOf(10, start + 1) + 1;
  const header = encoder.encode(edit(decoder.decode(bytes.subarray(0, end))));
  const result = new Uint8Array(header.length + bytes.length - end);
  result.set(header);
  result.set(bytes.subarray(end), header.length);
  return result;
}

function changed(bytes: Uint8Array, index: number): Uint8Array {
  const copy = bytes.slice();
  copy[index] = (copy[index] ?? 0) ^ 1;
  return copy;
}

describe("compatibility", () => {
  test("decrypts a binary payload armored by legacy tlock-js", async () => {
    const input = await readFile(
      new URL("legacy-js.age", import.meta.url),
      "utf8",
    );
    expect(await decrypt(input, offline)).toEqual(
      Uint8Array.of(0, 255, 128, 1, 32, 13, 10),
    );
  });

  for (const vector of vectors) {
    test(`decrypts independently generated Go ciphertext for ${vector.name}`, async () => {
      const input = await readFile(
        new URL(`go-${vector.name}.age`, import.meta.url),
        "utf8",
      );
      expect(inspect(input)).toEqual({
        format: "armor",
        recipients: [
          { chainHash: vector.chain.hash, round: vector.beacon.round },
        ],
      });
      const result = await decrypt(input, {
        network: { chain: vector.chain },
        beacon: vector.beacon,
      });
      expect(decoder.decode(result)).toBe(vector.plaintext);
    });
  }

  test.each([0, 1, 65535, 65536, 65537, 131072, 131073, 1024 * 1024 + 97])(
    "authenticates binary and armored payloads of %i bytes",
    async (size) => {
      const input = payload(size);
      const binary = encrypt(input, { round });
      const armor = encrypt(input, { round, format: "armor" });
      expect(inspect(binary).format).toBe("binary");
      expect(inspect(armor).format).toBe("armor");
      expect(await decrypt(binary, offline)).toEqual(input);
      expect(await decrypt(armor.replaceAll("\n", "\r\n"), offline)).toEqual(
        input,
      );
    },
  );

  test("supports fully offline use of explicitly pinned metadata", async () => {
    const network = {
      chain,
      source: {
        get: async () => {
          throw new Error("Unexpected network call");
        },
      },
    };
    expect(
      await decrypt(encrypt(payload(25), { round, network }), {
        network,
        beacon,
      }),
    ).toEqual(payload(25));
  });

  test("uses fresh randomness even for an identical round and payload", () => {
    expect(encrypt(payload(12), { round })).not.toEqual(
      encrypt(payload(12), { round }),
    );
  });
});

describe("drand", () => {
  test("round timestamps always meet the requested unlock time", () => {
    const start = chain.genesisTime * 1000;
    expect(roundAt(start - 1)).toBe(1);
    expect(roundAt(start)).toBe(1);
    expect(roundAt(start + 1)).toBe(2);
    expect(roundAt(new Date(start + 3000))).toBe(2);
    expect(roundAt(start + 3001)).toBe(3);
    expect(roundTime(3)).toBe(start + 6000);
    expect(() => roundAt(Number.MAX_SAFE_INTEGER)).toThrow(
      expect.objectContaining({ code: "INVALID_TIME" }),
    );
    expect(() => roundTime(Number.MAX_SAFE_INTEGER)).toThrow(
      expect.objectContaining({ code: "INVALID_TIME" }),
    );
    const time = Date.now() + 60_001;
    const recipient = inspect(encrypt(new Uint8Array(), { unlockTime: time }))
      .recipients[0];
    expect(recipient?.round).toBe(roundAt(time));
    expect(roundTime(roundAt(time))).toBeGreaterThanOrEqual(time);
  });

  test.each([0, -1, 1.1, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1])(
    "rejects invalid round %s",
    (badRound) => {
      expect(() => encrypt(new Uint8Array(), { round: badRound })).toThrow(
        expect.objectContaining({ code: "INVALID_ROUND" }),
      );
    },
  );

  test.each([0, Infinity, NaN, new Date(NaN), Number.MAX_SAFE_INTEGER + 1])(
    "rejects invalid or past unlock time %s",
    (unlockTime) => {
      expect(() => encrypt(new Uint8Array(), { unlockTime })).toThrow(
        expect.objectContaining({ code: "INVALID_TIME" }),
      );
    },
  );

  test("does not contact the source before scheduled publication", async () => {
    let called = false;
    const network = {
      chain,
      source: {
        get: async () => {
          called = true;
          return beacon;
        },
      },
    };
    const ciphertext = encrypt(new Uint8Array(), {
      round: roundAt(Date.now() + 60_000),
      network,
    });
    await expect(decrypt(ciphertext, { network })).rejects.toMatchObject({
      code: "ROUND_NOT_READY",
    });
    expect(called).toBe(false);
  });

  test("accepts custom sources while verifying their output", async () => {
    const source = {
      get: async (requested: number) => {
        expect(requested).toBe(round);
        return beacon;
      },
    };
    expect(await decrypt(sample, { network: { chain, source } })).toEqual(
      payload(64),
    );
    const unavailable = {
      get: async () => {
        throw new Error("offline");
      },
    };
    await expect(
      decrypt(sample, { network: { chain, source: unavailable } }),
    ).rejects.toMatchObject({ code: "BEACON_UNAVAILABLE" });
    await expect(decrypt(sample, { network: { chain } })).rejects.toMatchObject(
      { code: "BEACON_UNAVAILABLE" },
    );
  });

  test("rejects incorrect rounds, signatures, randomness and network keys", async () => {
    const badBeacons = [
      { ...beacon, round: round + 1 },
      { ...beacon, signature: beacon.signature.slice(2) },
      { ...beacon, signature: "c0" + "00".repeat(47) },
      { ...beacon, signature: "80" + "00".repeat(47) },
      { ...beacon, randomness: "00".repeat(32) },
      { round, signature: vectors[1].beacon.signature },
    ];
    for (const b of badBeacons) {
      await expect(decrypt(sample, { beacon: b })).rejects.toMatchObject({
        code: "INVALID_BEACON",
      });
    }
    const alternateKey = { ...chain, publicKey: vectors[1].chain.publicKey };
    await expect(
      decrypt(sample, { beacon, network: { chain: alternateKey } }),
    ).rejects.toMatchObject({ code: "INVALID_BEACON" });
    await expect(
      decrypt(sample, { beacon, network: { chain: vectors[1].chain } }),
    ).rejects.toMatchObject({ code: "NETWORK_MISMATCH" });
  });

  test("rejects malformed chain keys, infinity and key group mismatches", () => {
    for (const key of [
      "",
      "zz".repeat(96),
      "00".repeat(96),
      "c0" + "00".repeat(95),
      "ff".repeat(96),
      vectors[2].chain.publicKey,
    ]) {
      expect(() =>
        encrypt(payload(1), {
          round,
          network: { chain: { ...chain, publicKey: key } },
        }),
      ).toThrow(expect.objectContaining({ code: "INVALID_NETWORK" }));
    }
  });

  test("rejects unsafe drand service URLs with a typed error", async () => {
    for (const url of [
      "relative",
      "file:///tmp",
      "https://username@example.com",
      "https://example.com/?x=y",
    ]) {
      await expect(
        decrypt(sample, { network: { chain, source: { url } } }),
      ).rejects.toMatchObject({ code: "INVALID_NETWORK" });
    }
  });

  test.each(["v1", "v2"] as const)(
    "uses pinned metadata on HTTP %s",
    async (api) => {
      const paths: string[] = [];
      let mismatch = false;
      const prefix =
        api === "v1" ? `/${chain.hash}` : `/v2/chains/${chain.hash}`;
      const endpoint =
        prefix + (api === "v1" ? "/public/" : "/rounds/") + round;
      const server = Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        fetch(request) {
          const path = new URL(request.url).pathname;
          paths.push(path);
          if (path === prefix + "/info") {
            const fields = {
              genesis_time: chain.genesisTime,
              period: chain.period,
              public_key: mismatch
                ? vectors[1].chain.publicKey
                : chain.publicKey,
            };
            return Response.json(
              api === "v1"
                ? { ...fields, hash: chain.hash, schemeID: chain.scheme }
                : { ...fields, chain_hash: chain.hash, scheme: chain.scheme },
            );
          }
          if (path === endpoint) {
            return Response.json(
              api === "v1" ? beacon : { round, signature: beacon.signature },
            );
          }
          return new Response(null, { status: 404 });
        },
      });
      try {
        const network = { chain, source: { url: server.url.href, api } };
        expect(await decrypt(sample, { network })).toEqual(payload(64));
        expect(paths).toEqual([prefix + "/info", endpoint]);
        mismatch = true;
        await expect(decrypt(sample, { network })).rejects.toMatchObject({
          code: "NETWORK_MISMATCH",
        });
        expect(paths).toHaveLength(3);
      } finally {
        await server.stop(true);
      }
    },
  );
});

describe("untrusted ciphertext", () => {
  test("authenticates the original header, stanza and every STREAM chunk", async () => {
    const badMac = rewriteHeader(sample, (header) =>
      header.replace(/--- [A-Za-z0-9+/]/, (m) =>
        m === "--- A" ? "--- B" : "--- A",
      ),
    );
    const badStanza = rewriteHeader(sample, (header) => {
      const lines = header.split("\n");
      const last = lines[4] ?? "";
      lines[4] = (last[0] === "A" ? "B" : "A") + last.slice(1);
      return lines.join("\n");
    });
    const chunks = encrypt(payload(65536 * 2), { round });
    for (const input of [
      badMac,
      badStanza,
      changed(sample, sample.length - 1),
      changed(chunks, chunks.length - 65600),
      chunks.subarray(0, chunks.length - 65552),
    ]) {
      expect(inspect(input).recipients[0]?.round).toBe(round);
      await expect(decrypt(input, offline)).rejects.toMatchObject({
        code: "AUTHENTICATION_FAILED",
      });
    }
  });

  test("rejects an unauthenticated empty payload and impossible chunk lengths", () => {
    const empty = encrypt(new Uint8Array(), { round });
    const twoChunks = encrypt(payload(65537), { round });
    for (const bytes of [
      empty.subarray(0, -16),
      twoChunks.subarray(0, -1),
      twoChunks.subarray(0, -2),
    ]) {
      expect(() => inspect(bytes)).toThrow(
        expect.objectContaining({ code: "INVALID_CIPHERTEXT" }),
      );
    }
  });

  test("rejects malformed arguments, point and invalid Base64 without contacting a source", async () => {
    const edits = [
      (header: string) => header.replace(`tlock ${round}`, `tlock ${round}x`),
      (header: string) =>
        header.replace(`tlock ${round}`, "tlock 9007199254740992"),
      (header: string) => header.replace(`tlock ${round}`, "tlock 00"),
      (header: string) => header.replace(`tlock ${round}`, "tlock +10"),
      (header: string) => header.replace(chain.hash, chain.hash.toUpperCase()),
      (header: string) => header.replace("-> tlock", "->  tlock"),
      (header: string) => header.replace(/\n([A-Za-z0-9+/]{64})\n/, "\n*\n"),
      (header: string) =>
        header.replace(/\n([A-Za-z0-9+/]{64})\n/, "\n" + "A".repeat(64) + "\n"),
      (header: string) => header.replace(/\n--- (.+)\n/, "\n--- AAAA=\n"),
    ];
    let calls = 0;
    const network = {
      chain,
      source: {
        get: async () => {
          calls++;
          return beacon;
        },
      },
    };
    for (const edit of edits) {
      const input = rewriteHeader(sample, edit);
      expect(() => inspect(input)).toThrow(TlockError);
      await expect(decrypt(input, { network })).rejects.toMatchObject({
        code: "INVALID_CIPHERTEXT",
      });
    }
    expect(calls).toBe(0);
  });

  test("bounds header size, stanza count and armor whitespace", () => {
    const overlong = rewriteHeader(sample, (header) =>
      header.replace("-> tlock", `-> ${"Z".repeat(65_536)}\n\n-> tlock`),
    );
    const tooMany = rewriteHeader(sample, (header) =>
      header.replace("-> tlock", "-> other\n\n".repeat(64) + "-> tlock"),
    );
    const hugeStanza = rewriteHeader(sample, (header) =>
      header.replace(/\n--- /, "\n" + "A".repeat(64) + "\n\n--- "),
    );
    for (const bytes of [overlong, tooMany, hugeStanza])
      expect(() => inspect(bytes)).toThrow(TlockError);
    const armored = encrypt(payload(4), { round, format: "armor" });
    for (const text of [
      " ".repeat(1025) + armored,
      armored + "\n".repeat(1024),
      armored + "data",
      armored.replace("FILE-----\n", "FILE-----\n" + "A".repeat(65) + "\n"),
      armored.replace("FILE-----\n", "FILE-----\n\n"),
      armored.replace("FILE-----\n", "FILE-----\nAB==\n"),
    ])
      expect(() => inspect(text)).toThrow(TlockError);
  });

  test("validates armor lines through the end of a large body", () => {
    const text = encrypt(payload(1024 * 1024), { round, format: "armor" });
    const end = text.lastIndexOf("-----END AGE ENCRYPTED FILE-----");
    const malformed = text.slice(0, end - 2) + "*\n" + text.slice(end);
    expect(inspect(text).recipients[0]?.round).toBe(round);
    expect(() => inspect(malformed)).toThrow(
      expect.objectContaining({ code: "INVALID_CIPHERTEXT" }),
    );
  });

  test("deterministically fuzzes armor and binary parsing", () => {
    let state = 0x42e678fa;
    function next(): number {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      return state;
    }
    for (let iteration = 0; iteration < 500; iteration++) {
      const data =
        iteration % 3 === 0
          ? payload(next() % 320)
          : sample.slice(0, next() % (sample.length + 1));
      for (let i = 0; i < iteration % 6; i++)
        data[next() % data.length] = next() >>> 24;
      for (const input of [data, decoder.decode(data)]) {
        try {
          const result = inspect(input);
          expect(result.recipients.length).toBeGreaterThan(0);
          for (const recipient of result.recipients) {
            expect(recipient.chainHash).toMatch(/^[0-9a-f]{64}$/);
            expect(
              Number.isSafeInteger(recipient.round) && recipient.round > 0,
            ).toBe(true);
          }
        } catch (error) {
          expect(error).toBeInstanceOf(TlockError);
        }
      }
    }
  });
});
