import {Buffer} from "buffer"
import {ChainClient, fetchBeacon, roundTime} from "drand-client"
import {Stanza} from "../age/age-encrypt-decrypt"
import * as ibe from "../crypto/ibe"
import {Ciphertext} from "../crypto/ibe"
import {Point} from "./index"
import {bls12_381} from "@noble/curves/bls12-381"

export function createTimelockDecrypter(network: ChainClient) {
    return async (recipients: Array<Stanza>): Promise<Uint8Array> => {
        const tlockStanza = recipients.find(it => it.type === "tlock")

        if (!tlockStanza) {
            throw Error("You must pass a timelock stanza!")
        }
        const {type, args, body} = tlockStanza

        if (type !== "tlock") {
            throw Error(`Timelock expects the type of the stanza to be "tlock`)
        }

        if (args.length !== 2) {
            throw Error(`Timelock stanza expected 2 args: roundNumber and chainHash. Only received ${args.length}`)
        }

        const chainInfo = await network.chain().info()
        // should probably verify chain hash here too
        const roundNumber = parseRoundNumber(args)
        if (roundTime(chainInfo, roundNumber) > Date.now()) {
            throw Error(`It's too early to decrypt the ciphertext - decryptable at round ${roundNumber}`)
        }

        const beacon = await fetchBeacon(network, roundNumber)
        console.log(`beacon received: ${JSON.stringify(beacon)}`)

        switch (chainInfo.schemeID) {
            case "pedersen-bls-unchained": {
                const ciphertext = parseCiphertext(body, bls12_381.G1.ProjectivePoint.BASE)
                return await ibe.decryptOnG1(Buffer.from(beacon.signature, "hex"), ciphertext)
            }
            case "bls-unchained-on-g1": {
                const ciphertext = parseCiphertext(body, bls12_381.G2.ProjectivePoint.BASE)
                return await ibe.decryptOnG2(Buffer.from(beacon.signature, "hex"), ciphertext)
            }
            case "bls-unchained-g1-rfc9380": {
                const ciphertext = parseCiphertext(body, bls12_381.G2.ProjectivePoint.BASE)
                return await ibe.decryptOnG2(Buffer.from(beacon.signature, "hex"), ciphertext)
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

    function parseCiphertext(body: Uint8Array, base: Point): Ciphertext {
        const pointLength = base.toRawBytes(true).byteLength
        const pointBytes = body.subarray(0, pointLength)
        const theRest = body.subarray(pointLength)
        const eachHalf = theRest.length / 2

        const U = pointBytes
        const V = theRest.subarray(0, eachHalf)
        const W = theRest.subarray(eachHalf)

        return {U, V, W}
    }
}