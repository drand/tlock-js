import {PointG1, PointG2} from "@noble/bls12-381"
import {Buffer} from "buffer"
import {ChainClient, fetchBeacon, roundTime} from "drand-client"
import {Stanza} from "../age/age-encrypt-decrypt"
import * as ibe from "../crypto/ibe"
import {Ciphertext} from "../crypto/ibe"
import {Point} from "./index"

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
                const g2 = PointG2.fromHex(beacon.signature)
                const ciphertext = parseCiphertext(body, PointG1.BASE, PointG1.fromHex)
                return await ibe.decryptOnG1(g2, ciphertext)
            }
            case "bls-unchained-on-g1": {
                const g1 = PointG1.fromHex(beacon.signature)
                const cipherText = parseCiphertext(body, PointG2.BASE, PointG2.fromHex)
                return ibe.decryptOnG2(g1, cipherText)
            }
            case "bls-unchained-g1-rfc9380": {
                const g1 = PointG1.fromHex(beacon.signature)
                const cipherText = parseCiphertext(body, PointG2.BASE, PointG2.fromHex)
                return ibe.decryptOnG2RFC9380(g1, cipherText)
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

    function parseCiphertext<T>(body: Uint8Array, base: Point, fromHex: (buf: Buffer) => T): Ciphertext<T> {
        const pointLength = base.toRawBytes(true).byteLength
        const pointBytes = body.subarray(0, pointLength)
        const theRest = body.subarray(pointLength)
        const eachHalf = theRest.length / 2

        const U = fromHex(Buffer.from(pointBytes))
        const V = theRest.subarray(0, eachHalf)
        const W = theRest.subarray(eachHalf)

        return {U, V, W}
    }
}