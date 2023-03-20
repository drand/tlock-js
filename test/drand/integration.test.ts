import "isomorphic-fetch"
import {mainnetClient, testnetClient, timelockDecrypt, timelockEncrypt} from "../../src"

describe("integration", () => {
    it("should be able to encrypt and decrypt with the testnet client", async () => {
        const message = "hello world and other things"
        const ciphertext = await timelockEncrypt(1, Buffer.from(message), testnetClient())
        const plaintext = await timelockDecrypt(ciphertext, testnetClient())

        expect(plaintext).toEqual(message)
    })
    it("should be able to encrypt and decrypt with g1/g2 swapped client", async () => {
        const message = "hello world and other things"
        const ciphertext = await timelockEncrypt(1, Buffer.from(message), mainnetClient(), true)
        const plaintext = await timelockDecrypt(ciphertext, mainnetClient(), true)

        expect(plaintext).toEqual(message)
    })
})