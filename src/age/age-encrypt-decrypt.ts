import {hkdf} from "@noble/hashes/hkdf"
import {sha256} from "@noble/hashes/sha256"
import {STREAM} from "./stream-cipher"
import {NoOpEncDec} from "./no-op-encdec"
import {readAge, writeAge} from "./age-reader-writer"
import {sliceUntil, unpaddedBase64Buffer} from "./utils"
import {createMacKey, random} from "./utils-crypto"

type FileKey = Uint8Array
type EncryptionWrapper = (fileKey: FileKey) => Promise<Array<Stanza>>
type DecryptionWrapper = (recipients: Array<Stanza>) => Promise<FileKey>

// `Stanza` is a section of the age header that encapsulates the file key as
// encrypted to a specific recipient.
export type Stanza = {
    type: string,
    args: Array<string>,
    body: Uint8Array
}

const ageVersion = "age-encryption.org/v1"
const headerMacMessage = "header" // some plaintext used to generate the mac
const hkdfBodyMessage = "payload" // some plaintext used for generating the key for encrypting the body
const fileKeyLengthBytes = 16
const bodyHkdfNonceLengthBytes = 16
const hkdfKeyLengthBytes = 32

// encrypts a plaintext payload using AGE by generating a fileKey
// and passing the fileKey to another `EncryptionWrapper` for handling
export async function encryptAge(
    plaintext: Uint8Array,
    wrapFileKey: EncryptionWrapper = NoOpEncDec.wrap
): Promise<string> {
    const fileKey = await random(fileKeyLengthBytes)
    const recipients = await wrapFileKey(fileKey)
    const body = await encryptedPayload(fileKey, plaintext)

    return writeAge({
            fileKey,
            version: ageVersion,
            recipients,
            headerMacMessage,
            body
        }
    )
}

async function encryptedPayload(fileKey: Uint8Array, payload: Uint8Array): Promise<Buffer> {
    const nonce = await random(bodyHkdfNonceLengthBytes)
    const hkdfKey = hkdf(sha256, fileKey, nonce, Buffer.from(hkdfBodyMessage, "utf8"), hkdfKeyLengthBytes)
    const ciphertext = STREAM.seal(payload, hkdfKey)
    return Buffer.concat([nonce, ciphertext])
}

// decrypts a payload that has been encrypted using AGE can unwrap
// any internal encryption by passing a `DecryptionWrapper` that can
// provide the `fileKey` created during encryption
export async function decryptAge(
    payload: string,
    unwrapFileKey: DecryptionWrapper = NoOpEncDec.unwrap
): Promise<Buffer> {
    const encryptedPayload = readAge(payload)
    const version = encryptedPayload.header.version
    if (version !== ageVersion) {
        throw Error(`The payload version ${version} is not supported, only ${ageVersion}`)
    }

    const fileKey = await unwrapFileKey(encryptedPayload.header.recipients)
    const header = sliceUntil(payload, "---")
    const expectedMac = unpaddedBase64Buffer(createMacKey(fileKey, headerMacMessage, header))
    const actualMac = encryptedPayload.header.mac

    if (Buffer.compare(actualMac, expectedMac) !== 0) {
        throw Error("The MAC did not validate for the fileKey and payload!")
    }

    const nonce = Buffer.from(encryptedPayload.body.slice(0, bodyHkdfNonceLengthBytes))
    const cipherText = encryptedPayload.body.slice(bodyHkdfNonceLengthBytes)
    const hkdfKey = hkdf(sha256, fileKey, nonce, Buffer.from(hkdfBodyMessage, "utf8"), hkdfKeyLengthBytes)

    const plaintext = STREAM.open(cipherText, hkdfKey)
    return Buffer.from(plaintext)
}
