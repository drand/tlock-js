import * as chai from "chai"
import chaiString from "chai-string"
import {expect} from "chai"
import {unpaddedBase64, unpaddedBase64Buffer} from "../../src/age/utils"

chai.use(chaiString)

describe("util", () => {
    describe("unpaddedBase64", () => {
        it("should does not end in =", () => {
            const stringWithAnEquals = "hello world1"
            const output = unpaddedBase64(Buffer.from(stringWithAnEquals, "utf8"))
            expect(output).not.endsWith("=")
        })
        it("should decode strings to their original format", () => {
            const stringWithAnEquals = "hello world1"
            const output = unpaddedBase64(Buffer.from(stringWithAnEquals, "utf8"))
            const decoded = Buffer.from(output, "base64").toString("utf8")

            expect(decoded).to.equal(stringWithAnEquals)
        })

        it("should work with a raw string instead of a buffer", () => {
            const stringWithAnEquals = "hello world1"
            const output = unpaddedBase64(stringWithAnEquals)
            const decoded = Buffer.from(output, "base64").toString("utf8")

            expect(decoded).to.equal(stringWithAnEquals)
        })

        it("should continue to be unpadded when buffered", () => {
            const stringWithAnEquals = "hello world1"
            const buffer = unpaddedBase64Buffer(stringWithAnEquals)
            const str = unpaddedBase64(stringWithAnEquals)

            expect(buffer.toString("base64")).to.equal(str)
        })
    })
})
