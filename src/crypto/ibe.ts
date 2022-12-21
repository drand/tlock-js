import * as bls from "@noble/bls12-381"
import {PointG1, PointG2, utils} from "@noble/bls12-381"
import {sha256} from "@noble/hashes/sha256"
import {bytesToNumberBE, fp12ToBytes, xor} from "./utils"
import {hashToCurve} from "./hash-to-curve"

export interface Ciphertext {
    U: PointG1
    V: Uint8Array
    W: Uint8Array
}

export async function encrypt(master: PointG1, ID: Uint8Array, msg: Uint8Array): Promise<Ciphertext> {
    if (msg.length >> 16 > 0) {
        // we're using blake2 as XOF which only outputs at most 2^16-1 bytes
        throw new Error("cannot encrypt messages larger than 2^16-1 bytes.")
    }

    // 1. Compute Gid = e(master,Q_id)
    const Qid = await hashToCurve(ID)
    // const Qid = await bls.PointG2.hashToCurve(ID)
    const Gid = bls.pairing(master, Qid)

    // 2. Derive random sigma
    const sigma = utils.randomBytes(msg.length)

    // 3. Derive r from sigma and msg and get a field element
    const r = h3(sigma, msg)
    const U = bls.PointG1.BASE.multiply(r)

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

export async function decrypt(p: PointG2, c: Ciphertext): Promise<Uint8Array> {
    // 1. Compute sigma = V XOR H2(e(rP,private))
    const gidt = bls.pairing(c.U, p)
    const hgidt = gtToHash(gidt, c.W.length)

    if (hgidt.length != c.V.length) {
        throw new Error("XorSigma is of invalid length")
    }
    const sigma = xor(hgidt, c.V)

    // 2. Compute M = W XOR H4(sigma)
    const hsigma = h4(sigma, c.W.length)

    const msg = xor(hsigma, c.W)

    // 	3. Check U = rP
    const r = h3(sigma, msg)
    const rP = bls.PointG1.BASE.multiply(r)

    if (!rP.equals(c.U)) {
        throw new Error("invalid proof: rP check failed")
    }

    return msg
}

export function gtToHash(gt: bls.Fp12, len: number): Uint8Array {
    return sha256
        .create()
        .update("IBE-H2")
        .update(fp12ToBytes(gt))
        .digest()
        .slice(0, len)
}

function h3(sigma: Uint8Array, msg: Uint8Array) {
    const h3ret = sha256
        .create()
        .update("IBE-H3")
        .update(sigma)
        .update(msg)
        .digest()

    return toField(h3ret)
}

function h4(sigma: Uint8Array, len: number): Uint8Array {
    const h4sigma = sha256
        .create()
        .update("IBE-H4")
        .update(sigma)
        .digest()

    return h4sigma.slice(0, len)
}

// Our IBE hashes
const BitsToMaskForBLS12381 = 1

// we are hashing the data until we get a value smaller than the curve order
export function toField(h3ret: Uint8Array) {
    let data = h3ret
    // assuming Big Endianness
    let n: bigint = bytesToNumberBE(data)
    do {
        data = sha256(data)
        // assuming Big Endianness
        data[0] = data[0] >> BitsToMaskForBLS12381
        n = bytesToNumberBE(data)
    } while (n <= 0 || n > bls.CURVE.r)

    return n
}
