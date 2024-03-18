import {sha256} from "@noble/hashes/sha256"
import {Buffer} from "buffer"
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
        const pk = Buffer.from(chainInfo.public_key, "hex")
        const id = hashedRoundNumber(roundNumber)
        let ciphertext: Ciphertext
        switch (chainInfo.schemeID) {
            case "pedersen-bls-unchained": {
                ciphertext = await ibe.encryptOnG1(pk, id, fileKey)
            }
                break;
            case "bls-unchained-on-g1": {
                ciphertext = await ibe.encryptOnG2(pk, id, fileKey)
            }
                break;
            case "bls-unchained-g1-rfc9380": {
                ciphertext = await ibe.encryptOnG2RFC9380(pk, id, fileKey)
            }
                break;
            default:
                throw Error(`Unsupported scheme: ${chainInfo.schemeID} - you must use a drand network with an unchained scheme for timelock encryption!`)
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

function serialisedCiphertext(ciphertext: Ciphertext): Uint8Array {
    return Buffer.concat([ciphertext.U, ciphertext.V, ciphertext.W])
}
