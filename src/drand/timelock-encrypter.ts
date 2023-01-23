import {PointG1} from "@noble/bls12-381"
import {sha256} from "@noble/hashes/sha256"
import * as ibe from "../crypto/ibe"
import {ChainClient} from "drand-client"
import {Stanza} from "../age/age-encrypt-decrypt"
import {Ciphertext} from "../crypto/ibe"

export function createTimelockEncrypter(client: ChainClient, roundNumber: number) {
    if (roundNumber < 1) {
        throw Error("You cannot encrypt for a roundNumber less than 1 (genesis = 0)")
    }

    return async (fileKey: Uint8Array): Promise<Array<Stanza>> => {
        const chainInfo = await client.chain().info()
        const point = PointG1.fromHex(chainInfo.public_key)
        const id = hashedRoundNumber(roundNumber)
        const ciphertext = await ibe.encrypt(point, id, fileKey)

        return [{
            type: "tlock",
            args: [`${roundNumber}`, chainInfo.hash],
            body: serialisedCiphertext(ciphertext)
        }]
    }
}

function hashedRoundNumber(round: number): Uint8Array {
    const roundNumberBuffer = Buffer.alloc(64 / 8)
    roundNumberBuffer.writeBigUInt64BE(BigInt(round))
    return sha256(roundNumberBuffer)
}

function serialisedCiphertext(ciphertext: Ciphertext): Uint8Array {
    return Buffer.concat([ciphertext.U.toRawBytes(true), ciphertext.V, ciphertext.W])
}
