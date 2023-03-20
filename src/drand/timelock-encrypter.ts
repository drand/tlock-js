import {PointG1, PointG2} from "@noble/bls12-381"
import {sha256} from "@noble/hashes/sha256"
import * as ibe from "../crypto/ibe"
import {ChainClient} from "drand-client"
import {Stanza} from "../age/age-encrypt-decrypt"
import {Ciphertext, CiphertextOnG2} from "../crypto/ibe"

export function createTimelockEncrypter(client: ChainClient, roundNumber: number, swapped = false) {
    if (roundNumber < 1) {
        throw Error("You cannot encrypt for a roundNumber less than 1 (genesis = 0)")
    }

    return async (fileKey: Uint8Array): Promise<Array<Stanza>> => {
        const chainInfo = await client.chain().info()
        const id = hashedRoundNumber(roundNumber)
        let ciphertext: Ciphertext | CiphertextOnG2
        if (!swapped) {
            const point = PointG1.fromHex(chainInfo.public_key)
            ciphertext = await ibe.encrypt(point, id, fileKey)
        } else {
            const point = PointG2.fromHex(chainInfo.public_key)
            ciphertext = await ibe.encryptToG2(point, id, fileKey)
        }

        return [{
            type: "tlock",
            args: [`${roundNumber}`, chainInfo.hash],
            body: serialisedCiphertext(ciphertext)
        }]
    }
}


export function hashedRoundNumber(round: number): Uint8Array {
    const roundNumberBuffer = Buffer.alloc(64 / 8)
    roundNumberBuffer.writeBigUInt64BE(BigInt(round))
    return sha256(roundNumberBuffer)
}

function serialisedCiphertext(ciphertext: Ciphertext | CiphertextOnG2): Uint8Array {
    return Buffer.concat([ciphertext.U.toRawBytes(true), ciphertext.V, ciphertext.W])
}
