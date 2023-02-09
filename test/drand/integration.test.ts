import "isomorphic-fetch"
import {testnetClient, timelockDecrypt, timelockEncrypt} from "../../src"

describe("integration", () => {
    it("should be able to encrypt and decrypt with the testnet client", async () => {
        const message = "hello world and other things"
        const ciphertext = await timelockEncrypt(1, Buffer.from(message), testnetClient())
        const plaintext = await timelockDecrypt(ciphertext, testnetClient())

        expect(plaintext).toEqual(message)
    })
})