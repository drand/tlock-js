import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { equalBytes } from "@noble/ciphers/utils.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { fileKeySize, parsePoint, type GroupPoint } from "./ibe.js";
import { TlockError, type CiphertextInfo } from "./types.js";

const intro = "age-encryption.org/v1";
const beginArmor = "-----BEGIN AGE ENCRYPTED FILE-----";
const endArmor = "-----END AGE ENCRYPTED FILE-----";
const chunkSize = 64 * 1024;
const tagSize = 16;
const sealedChunkSize = chunkSize + tagSize;
const saltSize = 16;
const maxHeader = 64 * 1024;
const maxStanzas = 64;
const alphabet =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const headerLabel = encoder.encode("header");
const payloadLabel = encoder.encode("payload");

type Recipient = {
  round: number;
  chainHash: string;
  body: Uint8Array;
  U: GroupPoint;
};
type Envelope = {
  format: CiphertextInfo["format"];
  recipients: Recipient[];
  authenticatedHeader: Uint8Array;
  mac: Uint8Array;
  readPayload(): Uint8Array;
};

function invalid(message: string, cause?: unknown): never {
  throw new TlockError("INVALID_CIPHERTEXT", message, { cause });
}

function base64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function base64Size(line: string, padded: boolean): number {
  const content = padded ? line.replace(/={1,2}$/, "") : line;
  const remainder = content.length % 4;
  const last = alphabet.indexOf(content.at(-1) ?? "");
  const tailMask = remainder === 2 ? 15 : remainder === 3 ? 3 : 0;
  if (
    /[^A-Za-z0-9+/]/.test(content) ||
    remainder === 1 ||
    (last & tailMask) !== 0 ||
    (padded && line.length !== Math.ceil(content.length / 4) * 4)
  ) {
    invalid("Invalid base64 encoding");
  }
  return Math.floor((content.length * 3) / 4);
}

function decode64(line: string): Uint8Array {
  return Uint8Array.from(atob(line), (char) => char.charCodeAt(0));
}

export function armor(bytes: Uint8Array): string {
  const parts = [beginArmor, "\n"];
  const blockSize = 48 * 256;
  for (let i = 0; i < bytes.length; i += blockSize) {
    const encoded = base64(bytes.subarray(i, i + blockSize));
    parts.push(encoded.replace(/.{1,64}/g, "$&\n"));
  }
  parts.push(endArmor, "\n");
  return parts.join("");
}

function readArmor(input: string): {
  header: Uint8Array;
  size: number;
  readPayload(offset: number): Uint8Array;
} {
  const prefix =
    /^[\t\v\f\r\n ]{0,1024}(?=-----BEGIN AGE ENCRYPTED FILE-----)/.exec(input);
  if (!prefix) invalid("Invalid armor header");
  let offset = prefix[0].length + beginArmor.length;
  if (input.startsWith("\r\n", offset)) offset += 2;
  else if (input[offset++] !== "\n") invalid("Invalid armor header line");
  const footer = input.indexOf(endArmor, offset);
  const trailing = footer < 0 ? -1 : input.length - footer - endArmor.length;
  if (trailing < 0 || trailing > 1026) invalid("Invalid armor footer");
  const suffix = input.slice(footer + endArmor.length);
  if (!/^(?:\r?\n[\t\v\f\r\n ]{0,1023})?(?![\s\S])/.test(suffix))
    invalid("Invalid armor footer");
  function scan(
    visit: (line: string, position: number, length: number) => void,
  ): number {
    let position = 0;
    let short = false;
    for (let cursor = offset; cursor < footer;) {
      const end = input.indexOf("\n", cursor);
      if (short || end < 0 || end >= footer || end - cursor > 65)
        invalid("Invalid armor line");
      const line = input.slice(cursor, input[end - 1] === "\r" ? end - 1 : end);
      if (line.length > 64) invalid("Invalid armor line width");
      const length = base64Size(line, true);
      visit(line, position, length);
      position += length;
      short = length < 48;
      cursor = end + 1;
    }
    return position;
  }
  const header = new Uint8Array(
    Math.min(maxHeader, Math.floor(((footer - offset) * 3) / 4)),
  );
  const size = scan((line, position) => {
    if (position < header.length) {
      header.set(
        decode64(line).subarray(0, header.length - position),
        position,
      );
    }
  });
  return {
    header: header.subarray(0, size),
    size,
    readPayload(start) {
      const payload = new Uint8Array(size - start);
      scan((line, position, length) => {
        if (position + length > start) {
          payload.set(
            decode64(line).subarray(Math.max(0, start - position)),
            Math.max(0, position - start),
          );
        }
      });
      return payload;
    },
  };
}

function layout(length: number): { count: number; plaintextSize: number } {
  const count = Math.ceil(length / sealedChunkSize);
  const finalSize = length - (count - 1) * sealedChunkSize;
  if (
    count < 1 ||
    finalSize < tagSize ||
    (count > 1 && finalSize === tagSize)
  ) {
    invalid("Invalid AGE STREAM length");
  }
  return { count, plaintextSize: length - count * tagSize };
}

export function parseEnvelope(input: Uint8Array | string): Envelope {
  if (typeof input === "string") {
    const { header, size, readPayload } = readArmor(input);
    return parseHeader(header, size, "armor", readPayload);
  }
  const bytes =
    input.buffer instanceof ArrayBuffer ? input : new Uint8Array(input);
  return parseHeader(bytes, bytes.length, "binary", (offset) =>
    bytes.subarray(offset),
  );
}

function parseHeader(
  bytes: Uint8Array,
  size: number,
  format: Envelope["format"],
  readPayload: (offset: number) => Uint8Array,
): Envelope {
  const limit = Math.min(bytes.length, maxHeader);
  let cursor = 0;
  function line(maxLength: number): string {
    const start = cursor;
    while (cursor < limit && cursor - start <= maxLength) {
      if (bytes[cursor++] === 10) {
        try {
          return decoder.decode(bytes.subarray(start, cursor - 1));
        } catch (error) {
          invalid("Invalid AGE header encoding", error);
        }
      }
    }
    invalid("AGE header is truncated or exceeds its size limit");
  }

  if (line(intro.length) !== intro) invalid("Unsupported AGE header");
  const recipients: Recipient[] = [];
  const seen = new Set<string>();
  let stanzas = 0;
  while (true) {
    const start = cursor;
    const entry = line(1024);
    if (entry.startsWith("--- ")) {
      const encodedMac = entry.slice(4);
      if (base64Size(encodedMac, false) !== 32 || recipients.length === 0)
        invalid("Missing AGE MAC or tlock recipient");
      layout(size - cursor - saltSize);
      return {
        format,
        recipients,
        authenticatedHeader: bytes.subarray(0, start + 3),
        mac: decode64(encodedMac),
        readPayload: () => readPayload(cursor),
      };
    }
    if (++stanzas > maxStanzas || !/^-> [!-~]+(?: [!-~]+)*$/.test(entry)) {
      invalid("Invalid AGE stanza header");
    }
    const [type, roundText, chainHash, extra] = entry.slice(3).split(" ");
    const timelock = type === "tlock";
    let encoded = "";
    while (true) {
      const bodyLine = line(64);
      if (timelock) {
        encoded += bodyLine;
        if (encoded.length > 171) invalid("Oversized tlock stanza");
      } else {
        base64Size(bodyLine, false);
      }
      if (bodyLine.length < 64) break;
    }
    if (!timelock) continue;
    if (
      !roundText ||
      !/^[1-9][0-9]{0,15}$/.test(roundText) ||
      !chainHash ||
      !/^[0-9a-f]{64}$/.test(chainHash) ||
      extra !== undefined
    ) {
      invalid("Invalid tlock stanza arguments");
    }
    const round = Number(roundText);
    if (!Number.isSafeInteger(round)) invalid("Unsafe tlock round");
    const identity = roundText + chainHash;
    if (seen.has(identity)) invalid("Duplicate tlock recipient");
    seen.add(identity);
    const pointSize = base64Size(encoded, false) - 2 * fileKeySize;
    if (pointSize !== 48 && pointSize !== 96)
      invalid("Incorrect tlock stanza length");
    const body = decode64(encoded);
    try {
      const U = parsePoint(
        body.subarray(0, pointSize),
        pointSize === 48 ? "G1" : "G2",
      );
      recipients.push({ round, chainHash, body, U });
    } catch (error) {
      invalid("Invalid tlock stanza point", error);
    }
  }
}

function headerMAC(key: Uint8Array, header: Uint8Array): Uint8Array {
  const macKey = hkdf(sha256, key, undefined, headerLabel, 32);
  try {
    return hmac(sha256, macKey, header);
  } finally {
    macKey.fill(0);
  }
}

export function seal(
  plaintext: Uint8Array,
  key: Uint8Array,
  round: number,
  chainHash: string,
  stanza: Uint8Array,
): Uint8Array {
  const body = base64(stanza)
    .replace(/=+$/, "")
    .replace(/.{1,64}/g, "$&\n");
  const header = encoder.encode(
    `${intro}\n-> tlock ${round} ${chainHash}\n${body}---`,
  );
  const mac = encoder.encode(
    ` ${base64(headerMAC(key, header)).replace(/=+$/, "")}\n`,
  );
  const salt = crypto.getRandomValues(new Uint8Array(saltSize));
  const count = Math.max(1, Math.ceil(plaintext.length / chunkSize));
  const payloadOffset = header.length + mac.length + salt.length;
  const result = new Uint8Array(
    payloadOffset + plaintext.length + count * tagSize,
  );
  result.set(header);
  result.set(mac, header.length);
  result.set(salt, header.length + mac.length);
  const nonce = new Uint8Array(12);
  const counter = new DataView(nonce.buffer);
  const streamKey = hkdf(sha256, key, salt, payloadLabel, 32);
  try {
    for (let i = 0; i < count; i++) {
      counter.setBigUint64(3, BigInt(i));
      nonce[11] = Number(i === count - 1);
      const offset = payloadOffset + i * sealedChunkSize;
      chacha20poly1305(streamKey, nonce).encrypt(
        plaintext.subarray(i * chunkSize, (i + 1) * chunkSize),
        result.subarray(offset, offset + sealedChunkSize),
      );
    }
    return result;
  } finally {
    streamKey.fill(0);
  }
}

export function open(envelope: Envelope, key: Uint8Array): Uint8Array {
  const { authenticatedHeader, mac } = envelope;
  if (!equalBytes(headerMAC(key, authenticatedHeader), mac)) {
    throw new TlockError("AUTHENTICATION_FAILED", "Invalid AGE header MAC");
  }
  const payload = envelope.readPayload();
  const ciphertext = payload.subarray(saltSize);
  const { count, plaintextSize } = layout(ciphertext.length);
  const result = new Uint8Array(plaintextSize);
  const streamKey = hkdf(
    sha256,
    key,
    payload.subarray(0, saltSize),
    payloadLabel,
    32,
  );
  const nonce = new Uint8Array(12);
  const counter = new DataView(nonce.buffer);
  try {
    for (let i = 0; i < count; i++) {
      counter.setBigUint64(3, BigInt(i));
      nonce[11] = Number(i === count - 1);
      chacha20poly1305(streamKey, nonce).decrypt(
        ciphertext.subarray(i * sealedChunkSize, (i + 1) * sealedChunkSize),
        result.subarray(i * chunkSize, (i + 1) * chunkSize),
      );
    }
    return result;
  } catch (cause) {
    result.fill(0);
    throw new TlockError(
      "AUTHENTICATION_FAILED",
      "Invalid AGE STREAM authentication tag",
      { cause },
    );
  } finally {
    streamKey.fill(0);
  }
}
