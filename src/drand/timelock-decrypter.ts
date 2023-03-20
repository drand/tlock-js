import {Stanza} from "../age/age-encrypt-decrypt"
import {PointG1, PointG2} from "@noble/bls12-381"
import {ChainClient, fetchBeacon} from "drand-client"
import * as ibe from "../crypto/ibe"
import {Ciphertext, CiphertextOnG2} from "../crypto/ibe"
import * as chai from "chai"

export function createTimelockDecrypter(network: ChainClient) {
    return async (recipients: Array<Stanza>): Promise<Uint8Array> => {
        if (recipients.length !== 1) {
            throw Error("Timelock only expects a single stanza!")
        }

        const {type, args, body} = recipients[0]

        if (type !== "tlock") {
            throw Error(`Timelock expects the type of the stanza to be "tlock`)
        }

        if (args.length !== 2) {
            throw Error(`Timelock stanza expected 2 args: roundNumber and chainHash. Only received ${args.length}`)
        }

        const chainInfo = await network.chain().info()
        // should probably verify chain hash here too
        const beacon = await fetchBeacon(network, parseRoundNumber(args))
        console.log(`beacon received: ${JSON.stringify(beacon)}`)

        switch (chainInfo.schemeID) {
            case "pedersen-bls-unchained": {
                const g2 = PointG2.fromHex(beacon.signature)
                const ciphertext = parseCiphertext(body)
                return await ibe.decryptOnG1(g2, ciphertext)
            }
            case "bls-unchained-on-g1": {
                const g1 = PointG1.fromHex(beacon.signature)
                const cipherText = parseCiphertextOnG2(body)
                return ibe.decryptOnG2(g1, cipherText)
            }
            default:
                throw Error(`Unsupported scheme: ${chainInfo.schemeID} - you must use a drand network with an unchained scheme for timelock decryption!`)
        }
    }

    function parseRoundNumber(args: Array<string>): number {
        const [roundNumber] = args
        const roundNumberParsed = Number.parseInt(roundNumber)

        // compare against itself, to make sure it's not NaN
        if (roundNumberParsed !== roundNumberParsed) {
            throw Error(`Expected the roundNumber arg to be a number, but it was ${roundNumber}!`)
        }

        return roundNumberParsed
    }

    function parseCiphertext(body: Uint8Array): Ciphertext {
        const g1Length = PointG1.BASE.toRawBytes(true).byteLength
        const g1Bytes = body.subarray(0, g1Length)
        const theRest = body.subarray(g1Length)
        const eachHalf = theRest.length / 2

        const U = PointG1.fromHex(Buffer.from(g1Bytes).toString("hex"))
        const V = theRest.subarray(0, eachHalf)
        const W = theRest.subarray(eachHalf)

        return {U, V, W}
    }

    function parseCiphertextOnG2(body: Uint8Array): CiphertextOnG2 {
        const g1Length = PointG2.BASE.toRawBytes(true).byteLength
        const g1Bytes = body.subarray(0, g1Length)
        const theRest = body.subarray(g1Length)
        const eachHalf = theRest.length / 2

        const U = PointG2.fromHex(Buffer.from(g1Bytes).toString("hex"))
        const V = theRest.subarray(0, eachHalf)
        const W = theRest.subarray(eachHalf)

        return {U, V, W}
    }
}