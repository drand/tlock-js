import * as bls from "@noble/bls12-381"
import {Fp12, PointG1, PointG2, utils} from "@noble/bls12-381"
import {sha256} from "@noble/hashes/sha256"
import { Buffer } from "buffer"
import {bytesToNumberBE, fp12ToBytes, xor} from "./utils"

export interface Ciphertext<T> {
    U: T
    V: Uint8Array
    W: Uint8Array
}


interface Mul<T> {
    multiply(scalar: bigint): T;
}

async function encrypt<T, U>(
    master: T,
    ID: Uint8Array,
    msg: Uint8Array,
    base: Mul<T>,
    hashToCurve: (id: Uint8Array) => Promise<U>,
    pairing: (m: T, q: U) => Fp12
): Promise<Ciphertext<T>> {

    if (msg.length >> 8 > 1) {
        throw new Error("cannot encrypt messages larger than our hash output: 256 bits.")
    }

    // 1. Compute Gid = e(master,Q_id)
    const Qid = await hashToCurve(ID)
    const Gid = pairing(master, Qid)

    // 2. Derive random sigma
    const sigma = utils.randomBytes(msg.length)

    // 3. Derive r from sigma and msg and get a field element
    const r = h3(sigma, msg)
    const U = base.multiply(r)
    // 5. Compute V = sigma XOR H2(rGid)
    const rGid = Gid.pow(r)
    const hrGid = await gtToHash(rGid, msg.length)

    const V = xor(sigma, hrGid)

    // 6. Compute M XOR H(sigma)
    const hsigma = h4(sigma, msg.length)

    const W = xor(msg, hsigma)

    return {
        U: U,
        V: V,
        W: W,
    }
}

export async function encryptOnG1(master: PointG1, ID: Uint8Array, msg: Uint8Array): Promise<Ciphertext<PointG1>> {
    return encrypt(master, ID, msg, PointG1.BASE,
        (id: Uint8Array) => bls.PointG2.hashToCurve(id, { DST: "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_" }),
        (m, Qid) => bls.pairing(m, Qid)
    )
}

// uses the DST for G2 erroneously
export async function encryptOnG2(master: PointG2, ID: Uint8Array, msg: Uint8Array): Promise<Ciphertext<PointG2>> {
    return encrypt(master, ID, msg, PointG2.BASE,
        (id: Uint8Array) => bls.PointG1.hashToCurve(id, { DST: "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_" }),
        (m, Qid) => bls.pairing(Qid, m)
    )
}

export async function encryptOnG2RFC9380(master: PointG2, ID: Uint8Array, msg: Uint8Array): Promise<Ciphertext<PointG2>> {
    return encrypt(master, ID, msg, PointG2.BASE,
        (id: Uint8Array) => bls.PointG1.hashToCurve(id, { DST: "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_" }),
        (m, Qid) => bls.pairing(Qid, m)
    )
}

interface Eq<T> {
    equals(other: T): boolean
}

async function decrypt<T extends Eq<T>, U>(
    point: U,
    ciphertext: Ciphertext<T>,
    base: Mul<T>,
    pairing: (m: T, q: U) => Fp12
): Promise<Uint8Array> {
    // 1. Compute sigma = V XOR H2(e(rP,private))
    const gidt = pairing(ciphertext.U, point)
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
    const rP = base.multiply(r)

    if (!rP.equals(ciphertext.U)) {
        throw new Error("invalid proof: rP check failed")
    }

    return msg
}

export async function decryptOnG1(point: PointG2, ciphertext: Ciphertext<PointG1>): Promise<Uint8Array> {
    return decrypt(
        point,
        ciphertext,
        PointG1.BASE,
        (m: PointG1, Qid: PointG2) => bls.pairing(m, Qid)
    )
}

export async function decryptOnG2(point: PointG1, ciphertext: Ciphertext<PointG2>) {
    return decrypt<PointG2, PointG1>(
        point,
        ciphertext,
        PointG2.BASE,
        (p: PointG2, q: PointG1) => bls.pairing(q, p)
    )
}

export async function decryptOnG2RFC9380(point: PointG1, ciphertext: Ciphertext<PointG2>) {
    return decrypt<PointG2, PointG1>(
        point,
        ciphertext,
        PointG2.BASE,
        (p: PointG2, q: PointG1) => bls.pairing(q, p)
    )
}

export function gtToHash(gt: bls.Fp12, len: number): Uint8Array {
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
        if (n < bls.CURVE.r) {
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
