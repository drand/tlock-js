// this is an implementation of the ietf hash_to_field from the hash_to_curve
// suggested in draft 16
// see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#section-5.2

import {utils} from "@noble/bls12-381"

interface HashToFieldOptions {
    DST: string,
    p: bigint,
    m: number,
    k: number,
    expand: boolean
}

const CURVE = {
    P: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn,
}

const defaultsFromNoble: HashToFieldOptions = {
    DST: 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_',
    p: CURVE.P,
    m: 2,
    k: 128,
    expand: true,
}

export async function hashToField(message: Uint8Array, count: number, options: HashToFieldOptions = defaultsFromNoble): Promise<bigint[][]> {
    const log2p = options.p.toString(2).length
    const L = Math.ceil((log2p + options.k) / 8)

    const lenBytes = count * options.m * L
    const uniformBytes = await expandMessage(message, Buffer.from(options.DST), lenBytes)

    const output: bigint[][] = []
    for (let i = 0; i < count; i++) {
        const js: bigint[] = []

        for (let j = 0; j < options.m; j++) {
            const elmOffset = L * (j + i * options.m)
            const tv = uniformBytes.slice(elmOffset, L)
            const e_j = os2ip(tv) % options.p
            js.push(e_j)
        }

        output.push(js)
    }
    return output
}

const SHA256_DIGEST_SIZE = 32
const SHA256_BLOCK_SIZE = 64

// expand_message_xmd using SHA256
// dst: domain separator tag
async function expandMessage(message: Uint8Array, dst: Uint8Array, lengthBytes: number): Promise<Uint8Array> {
    const H = utils.sha256
    const bBytes = SHA256_DIGEST_SIZE
    const sBytes = SHA256_BLOCK_SIZE

    const ell = Math.ceil(lengthBytes / bBytes)
    if (ell > 255 || lengthBytes > 65535 || dst.length > 255) {
        throw new Error("separator or expansion length is too large to expand!")
    }

    const dstPrime = concat(dst, i2osp(dst.length, 1))
    const zPad = i2osp(0, sBytes)
    const lengthBytesStr = i2osp(lengthBytes, 2)
    const messagePrime = concat(zPad, message, lengthBytesStr, i2osp(0, 1), dstPrime)
    const b0 = await H(messagePrime)
    const b1 = await H(concat(b0, i2osp(1, 1), dstPrime))

    let uniformBytes = b1
    let bi = b1 // the ith iteration
    for (let i = 2; i < ell; i++) {
        bi = await H(concat(xor(b0, bi), i2osp(2, 1), dstPrime))
        uniformBytes = concat(uniformBytes, bi)
    }

    return uniformBytes.subarray(0, lengthBytes)
}

// converts a bytestring to non-negative integer
function os2ip(bytes: Uint8Array): bigint {
    let result = 0n;
    for (let i = 0; i < bytes.length; i++) {
        result <<= 8n;
        result += BigInt(bytes[i]);
    }
    return result
}

// converts a non-negative integer to a byte string
function i2osp(value: number, length: number): Uint8Array {
    if (value < 0 || value >= 1 << (8 * length)) {
        throw new Error(`bad I2OSP call: value=${value} length=${length}`)
    }
    const options = {
        length,
    }
    const res = Array.from<number>(options).fill(0)
    for (let i = length - 1; i >= 0; i--) {
        res[i] = value & 0xff
        value >>>= 8
    }
    return new Uint8Array(res)
}

// combines multiple `Uint8Array`s into a single `Uint8Array`
function concat(...a: Array<Uint8Array>): Uint8Array {
    const totalLength = a.reduce((acc, it) => acc + it.length, 0)
    const out = new Uint8Array(totalLength)

    let offset = 0
    for (let i = 0; i < a.length; i++) {
        out.set(a[i], offset)
        offset += a[i].length
    }

    return out
}

function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
    if (a.length != b.length) {
        throw new Error("xor input arrays must have the same length")
    }

    const out = new Uint8Array(a.length)
    for (let i = 0; i < a.length; i++) {
        out[i] = a[i] ^ b[i]
    }
    return out
}
