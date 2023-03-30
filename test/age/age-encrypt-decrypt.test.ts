import * as chai from "chai"
import {expect} from "chai"
import {decryptAge, encryptAge} from "../../src/age/age-encrypt-decrypt"
import {assertError, assertErrorMessage} from "../utils"
import chaiString = require("chai-string")

chai.use(chaiString)

describe("age", () => {
    describe("encrypt", () => {
        const helloWorld = new Uint8Array(Buffer.from("hello world"))

        it("propagates errors from the decryptionWrapper", async () => {
            const expectedError = "boom"
            const encryptFun = async () => await encryptAge(Buffer.from(helloWorld), () => {
                throw Error(expectedError)
            })

            await assertErrorMessage(() => encryptFun(), expectedError)
        })
    })
    describe("decrypt", () => {
        const helloWorld = "helloworld"
        const helloWorldBytes = Buffer.from(helloWorld)

        it("can decrypt something that has been encrypted using ageEncrypt()", async () => {
            const encryptedPayload = await encryptAge(helloWorldBytes)

            expect((await decryptAge(encryptedPayload)).toString("utf8")).to.deep.equal(helloWorld)
        })

        it("propagates errors from the decryptionWrapper", async () => {
            const expectedError = "boom"
            const decryptFn = async () => decryptAge(await encryptAge(helloWorldBytes), async () => {
                throw Error(expectedError)
            })

            await assertErrorMessage(() => decryptFn(), expectedError)
        })

        it("should fail if the version header is unsupported", async () => {
            const invalidPayload = (await encryptAge(helloWorldBytes)).replace("age-encryption.org/v1", "some-fake-encryption.org/v1")

            await assertError(() => decryptAge(invalidPayload))
        })

        it("should fail if the mac doesn't verify", async () => {
            const invalidMacPayload = (await encryptAge(helloWorldBytes)).replace(/--- .*\n/, "--- soMeFakeMacHeader")

            await assertError(() => decryptAge(invalidMacPayload))
        })

        it("should work for payloads that are multiple chunks", async () => {
            const bigPayload = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDI2NTUxMjcgNzY3Mjc5N2Y1" +
                "NDhmM2Y0NzQ4YWM0YmYzMzUyZmM2YzZiNjQ2OGM5YWQ0MGFkNDU2YTM5NzU0NWM2" +
                "ZTJkZjViZgprbUtMbm83UVdwUnI4K3dwaWxQejkySEVJZ245U0FPcnF2UXZXejlZ" +
                "K2xoN09xSkxlaFExVlJkKzJZSjF5RDBICkhNQk5aa3pOV0JkdW1OUURwZ1RjR3Z3" +
                "VEJKdHIyNFlEUEcrTzcwcjcvWjAKLS0tIHFsU3kwTDJ3L1NyMit4YWIrMzZUd251" +
                "cnJnUHRFWWx3UW41ZkZER05MOFkKgjThUJfYAKIjliXAAoIfDBafokRDA32V37WZ" +
                "Ap6fItGwCMHYhsHGQROGTyQeQn63Wqx+afVjXgcnKADLMhJrAkNA5+uXpqlFiLZ5" +
                "sF+fSrdJ7d+FsC6RoZpZbdTYnL55RlttbdcmgWgAxWqFIThq7cnghSFmp+KYD1gO" +
                "aWDQ4mrHmw8bkhVCQN3W7lKgHPol91gqBsBdyjJC/fPi3Pbm5pMXzLtVqsTWAloj" +
                "1mgKecbhaiQZrKck6BfeCQZygrMTMcX7pcOM9xkZVWeuqsSLjfyvv7y5i10WXt3M" +
                "/fC/9ot7+dsoqXWpoQ5UZlSlEt0IAf0uaaX3T2T/6lyrD82CSpBWAWllI2+lwjXp" +
                "UqkeMWPY//Fcblo15vrivKCrC+QQQSunMZlI0Gf6aZIHo5B/Zuw+zdQMjez5ZDVw" +
                "FNTeF10Y2VwQihNnc0Rgn9v2O213pRNXSZjT80zZ6udR/PEAqilvkKqU4yW3dSzC" +
                "9HGlJWYxYPB3LILK74XLp5KVlYcT0GTmF/hSIooirkKmuQWE/Lfv9OWpikAGcTEa" +
                "S55oOWth8jDerT9/hMgi5Oq2DiHOGp1yGhwBxqvuecA5M6ce1jKj0Yq2h8qeRVQq" +
                "kaTYQUN1ElX2bFZQyxefmLq9iD3j77qijPLIdeRTVq+ueywZt57ANOcldAJtNA9B" +
                "fr6M4kzNZKx5sMHYK9XMwNJEXzKkhTnVUpewwM83knpT4ddIZBQmBklo1vUhleVW" +
                "LQiXfkczGF/uTF0RMu/nysd2v/CBVPS6jdmuZHPtqq2XSG95P/dMP4KjaizAbfxm" +
                "CO4/sybGyyEGGB/A0JTJVXW1bWhOBXrSR0U=".repeat(10000)

            const ciphertext = await encryptAge(Buffer.from(bigPayload))
            const result = await decryptAge(ciphertext)
            expect(result.toString("utf8")).to.equal(bigPayload)
        })

        it("should correctly encrypt and decrypt special characters", async () => {
            const someFrench = "ça a marché"
            const ciphertext = await encryptAge(Buffer.from(someFrench))
            const result = await decryptAge(ciphertext)

            expect(result.toString("utf8")).to.equal(someFrench)
        })
    })
})
