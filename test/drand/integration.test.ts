import "isomorphic-fetch"
import {mainnetClient, testnetClient, timelockDecrypt, timelockEncrypt} from "../../src"
import {HttpCachingChain, HttpChainClient} from "drand-client"

describe("integration", () => {
    it("should be able to encrypt and decrypt with the testnet client", async () => {
        const message = "hello world and other things"
        const ciphertext = await timelockEncrypt(1, Buffer.from(message), testnetClient())
        const plaintext = await timelockDecrypt(ciphertext, testnetClient())

        expect(plaintext).toEqual(message)
    })
    it("should be able to encrypt and decrypt with g1/g2 swapped client", async () => {
        const message = "hello world and other things"
        const ciphertext = await timelockEncrypt(1, Buffer.from(message), mainnetClient())
        const plaintext = await timelockDecrypt(ciphertext, mainnetClient())

        expect(plaintext).toEqual(message)
    })
    it("should blow up using a default network client", async () => {
        const chainedChainClient = new HttpChainClient(new HttpCachingChain("https://api.drand.sh"))
        await expect(timelockEncrypt(1, Buffer.from("hello world"), chainedChainClient)).rejects.toThrow()
        await expect(timelockDecrypt("some-great-ciphertext", chainedChainClient)).rejects.toThrow()
    })
})