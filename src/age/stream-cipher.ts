// largely taken from https://github.com/paulmillr/jage,
// but hooking in a browser compatible ChaCha20 implementation
// STREAM cipher
// https://eprint.iacr.org/2015/189.pdf

// age spec:
// After the header the binary payload is nonce || STREAM[HKDF[nonce, "payload"](file key)](plaintext) where nonce is random(16) and STREAM is from Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance with ChaCha20-Poly1305 in 64KiB chunks and a nonce structure of 11 bytes of big endian counter, and 1 byte of last block flag (0x00 / 0x01). (The STREAM scheme is similar to the one Tink and Miscreant use, but without nonce prefix as we use HKDF, and with ChaCha20-Poly1305 instead of AES-GCM because the latter is unreasonably hard to do well or fast without hardware support.)
import {ChaCha20Poly1305} from "@stablelib/chacha20poly1305"

const CHUNK_SIZE = 64 * 1024 // 64 KiB
const TAG_SIZE = 16 // Poly1305 MAC size
const ENCRYPTED_CHUNK_SIZE = CHUNK_SIZE + TAG_SIZE
const NONCE_SIZE = 12 // STREAM nonce size

// due to using a 32bit uint for the counter, this is the max
// value the counter can be without risking a nonce reuse
const COUNTER_MAX = Math.pow(2, 32) - 1

type ui8a = Uint8Array

export class STREAM {
    static seal(plaintext: ui8a, privateKey: ui8a): Uint8Array {
        const stream = new STREAM(privateKey)
        const chunks = Math.ceil(plaintext.length / CHUNK_SIZE)
        const ciphertext = new Uint8Array(plaintext.length + (chunks * TAG_SIZE))

        for (let chunk64kb = 1; chunk64kb <= chunks; chunk64kb++) {
            const start = chunk64kb - 1
            const end = chunk64kb
            const isLast = chunk64kb === chunks
            const input = plaintext.slice(start * CHUNK_SIZE, end * CHUNK_SIZE)
            const output = ciphertext.subarray(start * ENCRYPTED_CHUNK_SIZE, end * ENCRYPTED_CHUNK_SIZE)
            stream.encryptChunk(input, isLast, output)
        }
        stream.clear()
        return ciphertext
    }

    static open(ciphertext: ui8a, privateKey: ui8a): Uint8Array {
        const stream = new STREAM(privateKey)
        const chunks = Math.ceil(ciphertext.length / ENCRYPTED_CHUNK_SIZE)
        const plaintext = new Uint8Array(ciphertext.length - (chunks * TAG_SIZE))

        for (let chunk64kb = 1; chunk64kb <= chunks; chunk64kb++) {
            const start = chunk64kb - 1
            const end = chunk64kb
            const isLast = chunk64kb === chunks
            const input = ciphertext.slice(start * ENCRYPTED_CHUNK_SIZE, end * ENCRYPTED_CHUNK_SIZE)
            const output = plaintext.subarray(start * CHUNK_SIZE, end * CHUNK_SIZE)
            stream.decryptChunk(input, isLast, output)
        }
        stream.clear()
        return plaintext
    }

    key: ui8a
    nonce: ui8a
    nonceView: DataView
    counter: number

    constructor(key: ui8a) {
        this.key = key.slice()
        this.nonce = new Uint8Array(NONCE_SIZE)
        this.nonceView = new DataView(this.nonce.buffer)
        this.counter = 0
    }

    encryptChunk(chunk: ui8a, isLast: boolean, output: ui8a) {
        if (chunk.length > CHUNK_SIZE) throw new Error("Chunk is too big")
        if (this.nonce[11] === 1) throw new Error("Last chunk has been processed")
        if (isLast) this.nonce[11] = 1
        const ciphertext = new ChaCha20Poly1305(this.key).seal(this.nonce, chunk)
        output.set(ciphertext)
        this.incrementCounter()
    }

    decryptChunk(chunk: ui8a, isLast: boolean, output: ui8a) {
        if (chunk.length > ENCRYPTED_CHUNK_SIZE) throw new Error("Chunk is too big")
        if (this.nonce[11] === 1) throw new Error("Last chunk has been processed")
        if (isLast) this.nonce[11] = 1
        const plaintext = new ChaCha20Poly1305(this.key).open(this.nonce, chunk)
        if (plaintext == null) {
            throw Error("Error during decryption!")
        }
        output.set(plaintext)
        this.incrementCounter()
    }

    // Increments Big Endian Uint8Array-based counter.
    // [0, 0, 0] => [0, 0, 1] ... => [0, 0, 255] => [0, 1, 0]
    incrementCounter() {
        if (this.counter == COUNTER_MAX) {
            throw new Error("Stream cipher counter has already hit max value! Aborting to avoid nonce reuse - tlock only supports payloads up to 256TB")
        }

        this.counter += 1
        this.nonceView.setUint32(7, this.counter, false)
    }

    clear() {
        function clear(arr: ui8a) {
            for (let i = 0; i < arr.length; i++) {
                arr[i] = 0
            }
        }

        clear(this.key)
        clear(this.nonce)
        this.counter = 0
    }
}
