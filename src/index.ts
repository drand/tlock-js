import { armor, open, parseEnvelope, seal } from "./age.js";
import {
  assertRound,
  futureRound,
  pinChain,
  quicknet as defaultNetwork,
  roundAt as calculateRound,
  roundTime as calculateTime,
  verifiedSignature,
} from "./drand.js";
import { fileKeySize, unwrapKey, wrapKey } from "./ibe.js";
import {
  TlockError,
  type Chain,
  type CiphertextInfo,
  type DecryptOptions,
  type EncryptOptions,
  type Network,
} from "./types.js";

export const quicknet: Network = defaultNetwork;
export const roundAt: (time: number | Date, chain?: Chain) => number =
  calculateRound;
export const roundTime: (round: number, chain?: Chain) => number =
  calculateTime;
export { TlockError } from "./types.js";
export type {
  Beacon,
  BeaconSource,
  Chain,
  CiphertextInfo,
  DecryptOptions,
  EncryptOptions,
  ErrorCode,
  Network,
  Scheme,
} from "./types.js";

export function encrypt(
  plaintext: Uint8Array,
  options: EncryptOptions & { format: "armor" },
): string;
export function encrypt(
  plaintext: Uint8Array,
  options: EncryptOptions & { format?: "binary" },
): Uint8Array;
export function encrypt(
  plaintext: Uint8Array,
  options: EncryptOptions & { format?: "armor" | "binary" },
): Uint8Array | string;
export function encrypt(
  plaintext: Uint8Array,
  options: EncryptOptions & { format?: "armor" | "binary" },
): Uint8Array | string {
  const network = options.network ?? quicknet;
  const { chain, master } = pinChain(network.chain);
  const round = options.round ?? futureRound(options.unlockTime, chain);
  assertRound(round);
  const key = crypto.getRandomValues(new Uint8Array(fileKeySize));
  try {
    const stanza = wrapKey(key, round, chain.scheme, master);
    const binary = seal(plaintext, key, round, chain.hash, stanza);
    return options.format === "armor" ? armor(binary) : binary;
  } finally {
    key.fill(0);
  }
}

export function inspect(ciphertext: Uint8Array | string): CiphertextInfo {
  const { format, recipients } = parseEnvelope(ciphertext);
  return {
    format,
    recipients: recipients.map(({ round, chainHash }) => ({
      round,
      chainHash,
    })),
  };
}

export async function decrypt(
  ciphertext: Uint8Array | string,
  options: DecryptOptions = {},
): Promise<Uint8Array> {
  const envelope = parseEnvelope(ciphertext);
  const network = options.network ?? quicknet;
  const { chain, master } = pinChain(network.chain);
  const recipient = envelope.recipients.find(
    ({ chainHash }) => chain.hash === chainHash,
  );
  if (!recipient)
    throw new TlockError(
      "NETWORK_MISMATCH",
      "No tlock recipient for the pinned chain",
    );
  if (recipient.U.group !== master.group) {
    throw new TlockError(
      "INVALID_CIPHERTEXT",
      "Stanza point group does not match the pinned chain",
    );
  }
  const signature = await verifiedSignature(
    chain,
    master,
    recipient.round,
    network.source,
    options.beacon,
  );
  const key = unwrapKey(recipient.U, recipient.body, signature);
  try {
    return open(envelope, key);
  } finally {
    key.fill(0);
  }
}
