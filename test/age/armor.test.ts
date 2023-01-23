import chai from "chai"
import {expect} from "chai"
import chaiString from "chai-string"
import {decodeArmor, encodeArmor} from "../../src/age/armor"

chai.use(chaiString)

describe("armor", () => {
    describe("encoding", () => {

        it("should encode input as base64", () => {
            const armor = encodeArmor("hello world")
            // created using `echo hello world | base64`
            // omitted a final character that depends
            // on whether there is a \n or not after it
            expect(armor).to.contain("aGVsbG8gd29ybGQ=")
        })
        it("should add a newline every 64 characters", () => {
            // five hello worlds encode to a string longer than the default 64 column limit
            const fiveHelloWorlds = "hello world".repeat(5)
            const armor = encodeArmor(fiveHelloWorlds)
            // newline for header, footer, and two for the longer payload = 4
            expect(Array.from(armor.matchAll(/\n/g))).to.have.length(4)
        })

        it("should add an additional newline if the input has a length that is exactly a multiple of 64", () => {
            // ... this is in the spec but I can't seem to create a base64 string that's a multiple of 64 o.O
        })

        it("should add a newline at the end of the footer", () => {
            const armor = encodeArmor("hello world")
            expect(armor).to.endWith("END AGE ENCRYPTED FILE-----\n")
        })
    })
    describe("decoding", () => {
        it("should fail if the string doesnt start with the header", () => {
            expect(() => decodeArmor("some non-armor string")).to.throw()
        })

        it("should fail if the string doesn't end with the footer", () => {
            expect(() => decodeArmor("-----BEGIN AGE ENCRYPTED FILE-----\ndeadbeefdeadbeef\n")).to.throw()
        })

        it("should fail if there are lines longer than the `chunkSize`", () => {
            const payload = "-----BEGIN AGE ENCRYPTED FILE-----\n" +
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n" +
                "-----END AGE ENCRYPTED FILE-----\n"
            expect(() => decodeArmor(payload)).to.throw()

        })

        it("should be able to decode something created with encode", () => {
            const somePlaintext = "wow that's a lot of armor"
            expect(decodeArmor(encodeArmor(somePlaintext))).to.equal(somePlaintext)
        })

        it("should ignore whitespace at the beginning and end when decoding", () => {
            const somePlaintext = "wow that's a lot of armor"
            expect(decodeArmor("   \n " + encodeArmor(somePlaintext) + "\t \n  ")).to.equal(somePlaintext)
        })

        it("should throw an error if there are more than 1024 chars of whitespace after the payload", () => {
            const payload = encodeArmor("hello world")
            const whitespace = " ".repeat(1025)

            expect(() => decodeArmor(payload + whitespace)).to.throw()
        })
        it("should throw an error if there is extra data after whitespace at the end of the armor payload", () => {
            const payload = encodeArmor("hello world")

            expect(() => decodeArmor(payload + "    " + "more data!")).to.throw()
        })

        it("should throw an error if there is extra data at the end of the armor payload", () => {
            const payload = encodeArmor("hello world")

            expect(() => decodeArmor(payload + "more data!")).to.throw()
        })
    })
})
