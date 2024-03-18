import {sha256} from "@noble/hashes/sha256"
import {randomBytes} from "@noble/hashes/utils"
import {bls12_381} from "@noble/curves/bls12-381"
import {Buffer} from "buffer"
import {bytesToNumberBE, fp12ToBytes, xor} from "./utils"
import {Fp12} from "./fp"

export interface Ciphertext {
    U: Uint8Array
    V: Uint8Array
    W: Uint8Array
}

const PointG1 = bls12_381.G1
const PointG2 = bls12_381.G2

export async function encryptOnG1(master: Uint8Array, ID: Uint8Array, msg: Uint8Array): Promise<Ciphertext> {
    if (msg.length >> 8 > 1) {
        throw new Error("cannot encrypt messages larger than our hash output: 256 bits.")
    }

    // 1. Compute Gid = e(master,Q_id)
    const Qid = PointG2.hashToCurve(ID, {DST: "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"}) as never
    const m = PointG1.ProjectivePoint.fromHex(master)
    const Gid = bls12_381.pairing(m, Qid)
    // 2. Derive random sigma
    const sigma = randomBytes(msg.length)

    // 3. Derive r from sigma and msg and get a field element
    const r = h3(sigma, msg)
    const U = PointG1.ProjectivePoint.BASE.multiply(r)
    // 5. Compute V = sigma XOR H2(rGid)
    const rGid = bls12_381.fields.Fp12.pow(Gid, r)
    const hrGid = gtToHash(rGid, msg.length)
    const V = xor(sigma, hrGid)

    // 6. Compute M XOR H(sigma)
    const hsigma = h4(sigma, msg.length)

    const W = xor(msg, hsigma)

    return {
        U: U.toRawBytes(),
        V: V,
        W: W,
    }
}

// uses the DST for G2 erroneously
export async function encryptOnG2(master: Uint8Array, ID: Uint8Array, msg: Uint8Array): Promise<Ciphertext> {
    return encOnG2(master, ID, msg, "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")
}

export async function encryptOnG2RFC9380(master: Uint8Array, ID: Uint8Array, msg: Uint8Array): Promise<Ciphertext> {
    return encOnG2(master, ID, msg, "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_")

}

async function encOnG2(master: Uint8Array, ID: Uint8Array, msg: Uint8Array, dst: string): Promise<Ciphertext> {
    if (msg.length >> 8 > 1) {
        throw new Error("cannot encrypt messages larger than our hash output: 256 bits.")
    }
    // 1. Compute Gid = e(master,Q_id)
    const Qid = PointG1.hashToCurve(ID, {DST: dst}) as never
    const m = PointG2.ProjectivePoint.fromHex(master)
    const Gid = bls12_381.pairing(Qid, m)
    // 2. Derive random sigma
    const sigma = randomBytes(msg.length)

    // 3. Derive r from sigma and msg and get a field element
    const r = h3(sigma, msg)
    const U = PointG2.ProjectivePoint.BASE.multiply(r)
    // 5. Compute V = sigma XOR H2(rGid)
    const rGid = bls12_381.fields.Fp12.pow(Gid, r)
    const hrGid = gtToHash(rGid, msg.length)
    const V = xor(sigma, hrGid)

    // 6. Compute M XOR H(sigma)
    const hsigma = h4(sigma, msg.length)

    const W = xor(msg, hsigma)

    return {
        U: U.toRawBytes(),
        V: V,
        W: W,
    }
}

export async function decryptOnG1(key: Uint8Array, ciphertext: Ciphertext): Promise<Uint8Array> {
    // 1. Compute sigma = V XOR H2(e(rP,private))
    const Qid = PointG1.ProjectivePoint.fromHex(ciphertext.U)
    const m = PointG2.ProjectivePoint.fromHex(key)
    const gidt = bls12_381.pairing(Qid, m)
    const hgidt = gtToHash(gidt, ciphertext.W.length)
    if (hgidt.length != ciphertext.V.length) {
        throw new Error("XorSigma is of invalid length")
    }
    const sigma = xor(hgidt, ciphertext.V)

    // 2. Compute M = W XOR H4(sigma)
    const hsigma = h4(sigma, ciphertext.W.length)

    const msg = xor(hsigma, ciphertext.W)

    // 	3. Check U = rP
    const r = h3(sigma, msg)
    const rP = PointG1.ProjectivePoint.BASE.multiply(r)

    if (!rP.equals(Qid)) {
        throw new Error("invalid proof: rP check failed")
    }

    return msg
}

export async function decryptOnG2(key: Uint8Array, ciphertext: Ciphertext): Promise<Uint8Array> {
    // 1. Compute sigma = V XOR H2(e(rP,private))
    const Qid = PointG1.ProjectivePoint.fromHex(key)
    const m = PointG2.ProjectivePoint.fromHex(ciphertext.U)
    const gidt = bls12_381.pairing(Qid, m)
    const hgidt = gtToHash(gidt, ciphertext.W.length)
    if (hgidt.length != ciphertext.V.length) {
        throw new Error("XorSigma is of invalid length")
    }
    const sigma = xor(hgidt, ciphertext.V)

    // 2. Compute M = W XOR H4(sigma)
    const hsigma = h4(sigma, ciphertext.W.length)

    const msg = xor(hsigma, ciphertext.W)

    // 	3. Check U = rP
    const r = h3(sigma, msg)
    const rP = PointG2.ProjectivePoint.BASE.multiply(r)

    if (!rP.equals(m)) {
        throw new Error("invalid proof: rP check failed")
    }

    return msg
}

export function gtToHash(gt: Fp12, len: number): Uint8Array {
    return sha256
        .create()
        .update("IBE-H2")
        .update(fp12ToBytes(gt))
        .digest()
        .slice(0, len)
}

// Our IBE hashes
const BitsToMaskForBLS12381 = 1

function h3(sigma: Uint8Array, msg: Uint8Array) {
    const h3ret = sha256
        .create()
        .update("IBE-H3")
        .update(sigma)
        .update(msg)
        .digest()

    // We will hash iteratively: H(i || H("IBE-H3" || sigma || msg)) until we get a
    // value that is suitable as a scalar.
    for (let i = 1; i < 65535; i++) {
        let data = h3ret
        data = sha256.create()
            .update(create16BitUintBuffer(i))
            .update(data)
            .digest()
        // assuming Big Endianness
        data[0] = data[0] >> BitsToMaskForBLS12381
        const n = bytesToNumberBE(data)
        if (n < bls12_381.fields.Fr.ORDER) {
            return n
        }
    }

    throw new Error("invalid proof: rP check failed")
}

function h4(sigma: Uint8Array, len: number): Uint8Array {
    const h4sigma = sha256
        .create()
        .update("IBE-H4")
        .update(sigma)
        .digest()

    return h4sigma.slice(0, len)
}

function create16BitUintBuffer(input: number): Buffer {
    if (input < 0) {
        throw Error("cannot write a negative value as uint!")
    }
    if (input > (2 ** 16)) {
        throw Error("input value too large to fit in a uint16!")
    }

    const buf = Buffer.alloc(2)
    buf.writeUint16LE(input)
    return buf
}
