import "isomorphic-fetch"
import {mainnetClient, nonRFCMainnetClient, testnetClient, timelockDecrypt, timelockEncrypt} from "../../src"
import {HttpCachingChain, HttpChainClient} from "drand-client"

describe("integration", () => {
    it("should be able to encrypt and decrypt with the testnet client", async () => {
        const message = "hello world and other things"
        const ciphertext = await timelockEncrypt(1, Buffer.from(message), testnetClient())
        const plaintext = await timelockDecrypt(ciphertext, testnetClient())

        expect(plaintext.toString("utf8")).toEqual(message)
    })
    it("should be able to encrypt and decrypt with g1/g2 swapped client", async () => {
        const message = "hello world and other things"
        const ciphertext = await timelockEncrypt(1, Buffer.from(message), mainnetClient())
        const plaintext = await timelockDecrypt(ciphertext, mainnetClient())

        expect(plaintext.toString("utf8")).toEqual(message)
    })
    it("should blow up using a default network client", async () => {
        const chainedChainClient = new HttpChainClient(new HttpCachingChain("https://api.drand.sh"))
        await expect(timelockEncrypt(1, Buffer.from("hello world"), chainedChainClient)).rejects.toThrow()
        await expect(timelockDecrypt("some-great-ciphertext", chainedChainClient)).rejects.toThrow()
    })
    it("should be compatible with a non-rfc-compliant ciphertext created using the go tlock lib", async () => {
        const ciphertext = "-----BEGIN AGE ENCRYPTED FILE-----\n" +
            "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDYxNzEyNSBkYmQ1MDZkNmVm\n" +
            "NzZlNWYzODZmNDFjNjUxZGNiODA4YzViY2JkNzU0NzFjYzRlYWZhM2Y0ZGY3YWQ0\n" +
            "ZTRjNDkzCmp3d0VJRld2TkNiK21ZNDBTYlEzMHp1RkJxUDdpcU9SVHNRcWxncEFL\n" +
            "TDRNVEVPa2c4RFlDa2w3Q2w0MUJHMFkKQjMzOXhFQ1l6S0ZrdktIMnR4WUpmM21C\n" +
            "NWhtRGg1ZzNJenhscjNuVTlvSDJSNWFkUVFRckcvZjBwZGoybHdFQQpRSnBuYkRm\n" +
            "S216OEh2QVd5YmVHekJ6YktMNkRSTnduTkdyVk5uRkFwWDFBCi0tLSB6aGRxeW9U\n" +
            "NWlIeDY4M2RHaEtuNEp2cU1YZmduakZGSDlIeVNQNzVqS2RvCiC3i/d22MKp28cP\n" +
            "c2TwZmXAKEEDrcKgVp85arbO6P7vL2KWODg=\n" +
            "-----END AGE ENCRYPTED FILE-----\n"

        const plaintext = await timelockDecrypt(ciphertext, nonRFCMainnetClient())
        expect(plaintext.toString("utf8")).toEqual("blah\n")
    })
})
