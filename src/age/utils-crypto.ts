import {hkdf} from "@noble/hashes/hkdf"
import {sha256} from "@noble/hashes/sha256"
import {hmac} from "@noble/hashes/hmac"

export function createMacKey(fileKey: Uint8Array, macMessage: string, headerText: string): Uint8Array {
    // empty string salt as per the spec!
    const hmacKey = hkdf(sha256, fileKey, "", Buffer.from(macMessage, "utf8"), 32)
    return Buffer.from(hmac(sha256, hmacKey, Buffer.from(headerText, "utf8")))
}

// returns a string of n bytes read from a CSPRNG like /dev/urandom.
export async function random(n: number): Promise<Uint8Array> {
    if (typeof window === "object" && "crypto" in window) {
        return window.crypto.getRandomValues(new Uint8Array(n))
    }

    // parcel likes to resolve polyfills for things even if they aren't used
    // so this indirection tricks it into not doing it and not complaining :)
    const x = "crypto"
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const bytes = require(x).randomBytes(n)
    return new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength)
}
