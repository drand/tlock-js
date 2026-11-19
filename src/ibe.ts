import { equalBytes } from "@noble/ciphers/utils.js";
import { bls12_381 as bls } from "@noble/curves/bls12-381.js";
import { bytesToNumberBE } from "@noble/curves/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { TlockError, type Scheme } from "./types.js";

const { G1, G2, fields, pairing } = bls;
const g1Domain = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
const g2Domain = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
const h2Tag = utf8ToBytes("IBE-H2");
const h3Tag = utf8ToBytes("IBE-H3");
const h4Tag = utf8ToBytes("IBE-H4");

function signatureDomain(scheme: Scheme): string {
  // Fastnet used the G2 tag for its G1 signatures.
  return scheme === "bls-unchained-g1-rfc9380" ? g1Domain : g2Domain;
}

export const fileKeySize: number = 16;
export type GroupPoint =
  | { group: "G1"; point: typeof bls.G1.Point.BASE }
  | { group: "G2"; point: typeof bls.G2.Point.BASE };

export function publicKeyGroup(scheme: Scheme): GroupPoint["group"] {
  return scheme === "pedersen-bls-unchained" ? "G1" : "G2";
}

export function parsePoint(
  bytes: Uint8Array,
  group: GroupPoint["group"],
): GroupPoint {
  if (bytes.length !== (group === "G1" ? 48 : 96)) {
    throw new Error("Incorrect compressed point length");
  }
  const parsed: GroupPoint =
    group === "G1"
      ? { group, point: G1.Point.fromBytes(bytes) }
      : { group, point: G2.Point.fromBytes(bytes) };
  if (parsed.point.is0() || !equalBytes(parsed.point.toBytes(true), bytes)) {
    throw new Error("Invalid compressed point");
  }
  return parsed;
}

function roundDigest(round: number): Uint8Array {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(round));
  return sha256(bytes);
}

export function verifySignature(
  signature: GroupPoint,
  master: GroupPoint,
  round: number,
  scheme: Scheme,
): boolean {
  const digest = roundDigest(round);
  if (signature.group === "G2" && master.group === "G1") {
    const blsScheme = bls.longSignatures;
    return blsScheme.verify(
      signature.point,
      blsScheme.hash(digest, g2Domain),
      master.point,
    );
  }
  if (signature.group === "G1" && master.group === "G2") {
    const blsScheme = bls.shortSignatures;
    const hash = blsScheme.hash(digest, signatureDomain(scheme));
    return blsScheme.verify(signature.point, hash, master.point);
  }
  return false;
}

function scalar(sigma: Uint8Array, key: Uint8Array): bigint {
  const seed = sha256.create().update(h3Tag).update(sigma).update(key).digest();
  const counter = new Uint8Array(2);
  const view = new DataView(counter.buffer);
  try {
    for (let i = 1; i < 65535; i++) {
      view.setUint16(0, i, true);
      const candidate = sha256.create().update(counter).update(seed).digest();
      candidate[0] = (candidate[0] ?? 0) >>> 1;
      const value = bytesToNumberBE(candidate);
      candidate.fill(0);
      if (value > 0n && value < fields.Fr.ORDER) return value;
      if (value === 0n) break;
    }
    throw new TlockError("AUTHENTICATION_FAILED", "Invalid IBE scalar");
  } finally {
    seed.fill(0);
  }
}

function pairingMask(gt: ReturnType<typeof pairing>): Uint8Array {
  // Go encodes the tower coefficients in reverse order, each in big-endian form.
  const encoded = fields.Fp12.toBytes(gt);
  const width = fields.Fp.BYTES;
  const hash = sha256.create().update(h2Tag);
  for (let end = encoded.length; end > 0; end -= width) {
    hash.update(encoded.subarray(end - width, end));
  }
  encoded.fill(0);
  return hash.digest();
}

function xorMask(input: Uint8Array, mask: Uint8Array): Uint8Array {
  const output = input.map((byte, index) => byte ^ (mask[index] ?? 0));
  mask.fill(0);
  return output;
}

export function wrapKey(
  key: Uint8Array,
  round: number,
  scheme: Scheme,
  master: GroupPoint,
): Uint8Array {
  const sigma = crypto.getRandomValues(new Uint8Array(fileKeySize));
  try {
    const r = scalar(sigma, key);
    const id = roundDigest(round);
    const U = (
      master.group === "G1"
        ? G1.Point.BASE.multiply(r)
        : G2.Point.BASE.multiply(r)
    ).toBytes(true);
    const gt =
      master.group === "G1"
        ? pairing(master.point, bls.longSignatures.hash(id, g2Domain))
        : pairing(
            bls.shortSignatures.hash(id, signatureDomain(scheme)),
            master.point,
          );
    const V = xorMask(sigma, pairingMask(fields.Fp12.pow(gt, r)));
    const W = xorMask(
      key,
      sha256.create().update(h4Tag).update(sigma).digest(),
    );
    return concatBytes(U, V, W);
  } finally {
    sigma.fill(0);
  }
}

export function unwrapKey(
  U: GroupPoint,
  body: Uint8Array,
  signature: GroupPoint,
): Uint8Array {
  const gt =
    U.group === "G1" && signature.group === "G2"
      ? pairing(U.point, signature.point)
      : U.group === "G2" && signature.group === "G1"
        ? pairing(signature.point, U.point)
        : undefined;
  if (gt === undefined)
    throw new TlockError(
      "INVALID_CIPHERTEXT",
      "Stanza group does not match the network",
    );
  const sigma = xorMask(
    body.subarray(-2 * fileKeySize, -fileKeySize),
    pairingMask(gt),
  );
  const key = xorMask(
    body.subarray(-fileKeySize),
    sha256.create().update(h4Tag).update(sigma).digest(),
  );
  try {
    const r = scalar(sigma, key);
    const valid =
      U.group === "G1"
        ? G1.Point.BASE.multiply(r).equals(U.point)
        : G2.Point.BASE.multiply(r).equals(U.point);
    if (!valid)
      throw new TlockError("AUTHENTICATION_FAILED", "Invalid IBE proof");
    return key;
  } catch (error) {
    key.fill(0);
    throw error;
  } finally {
    sigma.fill(0);
  }
}
