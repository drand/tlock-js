import {expect} from "chai"
import {assertError} from "../utils"
import {MockDrandClient, validBeacon} from "./mock-drand-client"
import {timelockDecrypt, timelockEncrypt} from "../../src"

describe("timelock", () => {
    describe("encryption", () => {
        it("should fail for roundNumber less than 0", async () => {
            await assertError(() => timelockEncrypt(-1, Buffer.from("hello world"), new MockDrandClient(validBeacon)))
        })

        it("should pass for a valid roundNumber", async () => {
            expect(await timelockEncrypt(1, Buffer.from("hello world"), new MockDrandClient(validBeacon))).to.have.length.greaterThan(0)
        })
    })

    describe("decryption", () => {
        const validBeacon = {
            round: 1,
            randomness: "8430af445106a217c174b6265093d386bd3631ccb3dae833b5e645abbb281323",
            signature: "86ecea71376e78abd19aaf0ad52f462a6483626563b1023bd04815a7b953da888c74f5bf6ee672a5688603ab310026230522898f33f23a7de363c66f90ffd49ec77ebf7f6c1478a9ecd6e714b4d532ab43d044da0a16fed13b4791d7fc999e2b"
        }
        const mockClient = new MockDrandClient(validBeacon)
        it("should succeed for a correctly timelock encrypted payload", async () => {
            const plaintext = "hello world"
            const decryptedPayload = await timelockDecrypt(await timelockEncrypt(1, Buffer.from(plaintext), mockClient), mockClient)

            expect(decryptedPayload.toString("utf8")).to.equal(plaintext)
        })
        it("should fail if an invalid beacon is returned", async () => {
            const plaintext = "hello world"
            const invalidBeacon = {
                round: 1,
                randomness: "zzzzzzzzzzzz",
                signature: "86ecea71376e78abd19aaf0ad52f462a6483626563b1023bd04815a7b953da888c74f5bf6ee672a5688603ab310026230522898f33f23a7de363c66f90ffd49ec77ebf7f6c1478a9ecd6e714b4d532ab43d044da0a16fed13b4791d7fc999e2b"
            }
            const client = new MockDrandClient(invalidBeacon)
            const ciphertext = await timelockEncrypt(1, Buffer.from(plaintext), mockClient)
            await assertError(() => timelockDecrypt(ciphertext, client))
        })
    })
})
