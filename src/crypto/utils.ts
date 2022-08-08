import {Fp, Fp12, Fp2} from "@noble/bls12-381"

// returns a new array with the xor of a ^ b
export function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
    if (a.length != b.length) {
        throw new Error("Error: incompatible sizes")
    }

    const ret = new Uint8Array(a.length)

    for (let i = 0; i < a.length; i++) {
        ret[i] = a[i] ^ b[i]
    }

    return ret
}

////// code from Noble:
////// https://github.com/paulmillr/noble-bls12-381/blob/6380415f1b7e5078c8883a5d8d687f2dd3bff6c2/index.ts#L132-L145
export function bytesToNumberBE(uint8a: Uint8Array): bigint {
    return BigInt('0x' + bytesToHex(Uint8Array.from(uint8a)))
}

const hexes = Array.from({length: 256}, (v, i) => i.toString(16).padStart(2, '0'))

export function bytesToHex(uint8a: Uint8Array): string {
// pre-caching chars could speed this up 6x.
    let hex = ''
    for (let i = 0; i < uint8a.length; i++) {
        hex += hexes[uint8a[i]]
    }
    return hex
}

////// end of code from Noble.

// Function to convert Noble's FPs to byte arrays compatible with Kilic library.
// weirdly all the child FPs have to be reversed when serialising to bytes
export function fpToBytes(fp: Fp): Uint8Array {
    // 48 bytes = 96 hex bytes
    const hex = BigInt(fp.value).toString(16).padStart(96, "0")
    const buf = Buffer.alloc(hex.length / 2)
    buf.write(hex, "hex")
    return buf
}

export function fp2ToBytes(fp2: Fp2): Uint8Array {
    return Buffer.concat([fp2.c1, fp2.c0].map(fpToBytes))
}

// fp6 isn't exported by noble... let's take off the guard rails
// eslint-disable-next-line  @typescript-eslint/no-explicit-any
export function fp6ToBytes(fp6: any): Uint8Array {
    return Buffer.concat([fp6.c2, fp6.c1, fp6.c0].map(fp2ToBytes))
}

export function fp12ToBytes(fp12: Fp12): Uint8Array {
    return Buffer.concat([fp12.c1, fp12.c0].map(fp6ToBytes))
}
