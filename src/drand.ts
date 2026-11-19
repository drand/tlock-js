import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import {
  parsePoint,
  publicKeyGroup,
  verifySignature,
  type GroupPoint,
} from "./ibe.js";
import { TlockError, type Beacon, type Chain, type Network } from "./types.js";

export const quicknet: Network = Object.freeze({
  chain: Object.freeze({
    hash: "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
    publicKey:
      "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a",
    scheme: "bls-unchained-g1-rfc9380",
    genesisTime: 1692803367,
    period: 3,
  }),
  source: Object.freeze({ url: "https://api.drand.sh", api: "v2" }),
});

export function assertRound(round: number): void {
  if (!Number.isSafeInteger(round) || round < 1) {
    throw new TlockError(
      "INVALID_ROUND",
      "Round must be a positive safe integer",
    );
  }
}

function schedule(chain: Chain): { genesis: bigint; period: bigint } {
  if (
    !Number.isSafeInteger(chain.genesisTime) ||
    chain.genesisTime < 0 ||
    !Number.isSafeInteger(chain.period) ||
    chain.period < 1 ||
    chain.genesisTime > Math.floor(Number.MAX_SAFE_INTEGER / 1000) ||
    chain.period > Math.floor(Number.MAX_SAFE_INTEGER / 1000)
  ) {
    throw new TlockError(
      "INVALID_NETWORK",
      "Invalid drand genesis time or period",
    );
  }
  return {
    genesis: BigInt(chain.genesisTime) * 1000n,
    period: BigInt(chain.period) * 1000n,
  };
}

function timestamp(value: number | Date): number {
  const ms = value instanceof Date ? value.getTime() : value;
  if (!Number.isSafeInteger(ms))
    throw new TlockError(
      "INVALID_TIME",
      "Expected a safe integer timestamp in milliseconds",
    );
  return ms;
}

export function roundAt(
  time: number | Date,
  chain: Chain = quicknet.chain,
): number {
  const ms = BigInt(timestamp(time));
  const { genesis, period } = schedule(chain);
  if (ms <= genesis) return 1;
  const elapsed = (ms - genesis + period - 1n) / period;
  safeTime(genesis + elapsed * period);
  return Number(elapsed + 1n);
}

export function roundTime(
  round: number,
  chain: Chain = quicknet.chain,
): number {
  assertRound(round);
  const { genesis, period } = schedule(chain);
  return safeTime(genesis + BigInt(round - 1) * period);
}

function safeTime(ms: bigint): number {
  if (ms > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new TlockError(
      "INVALID_TIME",
      "Scheduled round time exceeds the safe integer range",
    );
  }
  return Number(ms);
}

export function futureRound(time: number | Date, chain: Chain): number {
  const ms = timestamp(time);
  if (ms <= Date.now())
    throw new TlockError("INVALID_TIME", "Unlock time must be in the future");
  return roundAt(ms, chain);
}

function isHex(value: unknown, length: number): value is string {
  return (
    typeof value === "string" &&
    value.length === length &&
    !/[^0-9a-f]/i.test(value)
  );
}

export function pinChain(input: Chain): { chain: Chain; master: GroupPoint } {
  const { scheme, hash, publicKey, genesisTime, period } = input;
  if (
    scheme !== "bls-unchained-g1-rfc9380" &&
    scheme !== "bls-unchained-on-g1" &&
    scheme !== "pedersen-bls-unchained"
  ) {
    throw new TlockError("INVALID_NETWORK", "Unsupported drand scheme");
  }
  const group = publicKeyGroup(scheme);
  if (!isHex(hash, 64) || !isHex(publicKey, group === "G1" ? 96 : 192)) {
    throw new TlockError(
      "INVALID_NETWORK",
      "Expected a pinned chain hash and compressed public key",
    );
  }
  const chain: Chain = {
    scheme,
    hash: hash.toLowerCase(),
    publicKey: publicKey.toLowerCase(),
    genesisTime,
    period,
  };
  schedule(chain);
  try {
    return { chain, master: parsePoint(hexToBytes(chain.publicKey), group) };
  } catch (cause) {
    throw new TlockError("INVALID_NETWORK", "Invalid drand public key", {
      cause,
    });
  }
}

async function fetchBeacon(
  round: number,
  chain: Chain,
  source: Network["source"],
): Promise<unknown> {
  if (!source)
    throw new TlockError(
      "BEACON_UNAVAILABLE",
      "Provide a beacon or a beacon source",
    );
  if ("get" in source) return source.get(round);

  let url: URL;
  try {
    url = new URL(source.url);
  } catch (cause) {
    throw new TlockError("INVALID_NETWORK", "Invalid drand service URL", {
      cause,
    });
  }
  if (
    !["https:", "http:"].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new TlockError("INVALID_NETWORK", "Invalid drand service URL");
  }
  const root = url.href.replace(/\/+$/, "");
  const v1 = source.api === "v1";
  const endpoint = v1
    ? `${root}/${chain.hash}`
    : `${root}/v2/chains/${chain.hash}`;
  const { HttpChain, HttpChainClient } = await import("drand-client");
  const httpChain = new HttpChain(endpoint);
  const metadata: unknown = await httpChain.info();
  if (
    typeof metadata !== "object" ||
    metadata === null ||
    !("public_key" in metadata) ||
    !("genesis_time" in metadata) ||
    !("period" in metadata) ||
    metadata.public_key !== chain.publicKey ||
    metadata.genesis_time !== chain.genesisTime ||
    metadata.period !== chain.period ||
    (v1
      ? !("hash" in metadata) ||
        metadata.hash !== chain.hash ||
        !("schemeID" in metadata) ||
        metadata.schemeID !== chain.scheme
      : !("chain_hash" in metadata) ||
        metadata.chain_hash !== chain.hash ||
        !("scheme" in metadata) ||
        metadata.scheme !== chain.scheme)
  ) {
    throw new TlockError(
      "NETWORK_MISMATCH",
      "drand service metadata differs from the pinned chain",
    );
  }
  if (v1) return new HttpChainClient(httpChain, undefined, {}).get(round);

  // drand-client 1.x has no transport for the v2 rounds route.
  const response = await fetch(`${endpoint}/rounds/${round}`, {
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error(`drand returned HTTP ${response.status}`);
  return response.json();
}

export async function verifiedSignature(
  chain: Chain,
  master: GroupPoint,
  round: number,
  source: Network["source"],
  prefetched?: Beacon,
): Promise<GroupPoint> {
  let beacon: unknown = prefetched;
  if (prefetched === undefined) {
    const { genesis, period } = schedule(chain);
    if (genesis + BigInt(round - 1) * period > BigInt(Date.now())) {
      throw new TlockError(
        "ROUND_NOT_READY",
        `drand round ${round} is not scheduled yet`,
      );
    }
    try {
      beacon = await fetchBeacon(round, chain, source);
    } catch (cause) {
      if (cause instanceof TlockError) throw cause;
      throw new TlockError(
        "BEACON_UNAVAILABLE",
        `Could not retrieve drand round ${round}`,
        { cause },
      );
    }
  }

  try {
    const group = master.group === "G1" ? "G2" : "G1";
    if (
      typeof beacon !== "object" ||
      beacon === null ||
      !("round" in beacon) ||
      beacon.round !== round ||
      !("signature" in beacon) ||
      !isHex(beacon.signature, group === "G1" ? 96 : 192)
    ) {
      throw new Error("Incorrect beacon round or signature encoding");
    }
    const bytes = hexToBytes(beacon.signature);
    const point = parsePoint(bytes, group);
    if (
      "randomness" in beacon &&
      beacon.randomness !== bytesToHex(sha256(bytes))
    ) {
      throw new Error("Beacon randomness does not match its signature");
    }
    if (!verifySignature(point, master, round, chain.scheme)) {
      throw new Error("Signature does not verify on the pinned chain");
    }
    return point;
  } catch (cause) {
    throw new TlockError(
      "INVALID_BEACON",
      `Invalid beacon for drand round ${round}`,
      { cause },
    );
  }
}
