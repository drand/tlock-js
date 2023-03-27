import {expect} from "chai"
import {MockDrandClient} from "./mock-drand-client"
import {readAge} from "../../src/age/age-reader-writer"
import {decodeArmor} from "../../src/age/armor"
import {createTimelockDecrypter} from "../../src/drand/timelock-decrypter"
import {assertError} from "../utils"
import {timelockEncrypt} from "../../src"

describe("timelock decrypter", () => {
    const validBeacon = {
        round: 1,
        randomness: "8430af445106a217c174b6265093d386bd3631ccb3dae833b5e645abbb281323",
        signature: "86ecea71376e78abd19aaf0ad52f462a6483626563b1023bd04815a7b953da888c74f5bf6ee672a5688603ab310026230522898f33f23a7de363c66f90ffd49ec77ebf7f6c1478a9ecd6e714b4d532ab43d044da0a16fed13b4791d7fc999e2b"
    }

    const mockClient = new MockDrandClient(validBeacon)

    it("should decrypt for stanzas created using tlock", async () => {
        const plaintext = "hello world"
        const ciphertext = await timelockEncrypt(1, Buffer.from(plaintext), mockClient)
        const parsedAgeEncryption = readAge(decodeArmor(ciphertext))

        const decryptedFileKey = await createTimelockDecrypter(mockClient)(parsedAgeEncryption.header.recipients)
        expect(decryptedFileKey.length).to.be.greaterThan(0)
    })

    it("should throw an error if multiple recipient stanzas are provided", async () => {
        const stanza = {
            type: "tlock",
            args: ["1", "deadbeef"],
            body: Buffer.from("deadbeef")
        }

        await assertError(() => createTimelockDecrypter(mockClient)([stanza, stanza]))
    })

    it("should blow up if the stanza type isn't 'tlock'", async () => {
        const stanza = {
            type: "unsupported-type",
            args: ["1", "deadbeef"],
            body: Buffer.from("deadbeef")
        }

        await assertError(() => createTimelockDecrypter(mockClient)([stanza, stanza]))
    })

    it("should ignore additional non-tlock stanzas", async () => {
        const plaintext = "hello world"
        const ciphertext = await timelockEncrypt(1, Buffer.from(plaintext), mockClient)
        const parsedAgeEncryption = readAge(decodeArmor(ciphertext))

        const stanzas = [{
            type: "bananas",
            args: ["1", "2", "3"],
            body: Buffer.from("cafebabe")
        }, ...parsedAgeEncryption.header.recipients]

        const decryptedFileKey = await createTimelockDecrypter(mockClient)(stanzas)
        expect(decryptedFileKey.length).to.be.greaterThan(0)
    })

    it("should blow up if roundNumber or chainHash are missing from the args of the stanza", async () => {
        const missingChainHash = {
            type: "tlock",
            args: ["1"],
            body: Buffer.from("deadbeef")
        }
        const missingRoundNumber = {
            type: "tlock",
            args: ["deadbeef"],
            body: Buffer.from("deadbeef")
        }

        await assertError(() => createTimelockDecrypter(mockClient)([missingChainHash]))
        await assertError(() => createTimelockDecrypter(mockClient)([missingRoundNumber]))
    })

    it("should blow up if the roundNumber isn't a number", async () => {
        const invalidRoundNumberArg = {
            type: "tlock",
            args: ["shouldbeanum", "deadbeef"],
            body: Buffer.from("deadbeef")
        }

        await assertError(() => createTimelockDecrypter(mockClient)([invalidRoundNumberArg]))
    })

    it("should blow up if the chainHash isn't hex", async () => {
        const invalidChainHashArg = {
            type: "tlock",
            args: ["1", "not just hex chars"],
            body: Buffer.from("deadbeef")
        }

        await assertError(() => createTimelockDecrypter(mockClient)([invalidChainHashArg]))
    })

    it("should blow up if the decryption time is in the future", async () => {
        const plaintext = "hello world"
        const someHugeFutureRound = 2251799813685248 // max js number
        const ciphertext = await timelockEncrypt(someHugeFutureRound, Buffer.from(plaintext), mockClient)

        const parsedAgeEncryption = readAge(decodeArmor(ciphertext))

        await assertError(() => createTimelockDecrypter(mockClient)(parsedAgeEncryption.header.recipients))
    })
})
