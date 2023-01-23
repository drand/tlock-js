import {expect} from "chai"
import {readAge, writeAge} from "../../src/age/age-reader-writer"
import {random} from "../../src/age/utils-crypto"

describe("AGE", () => {
    describe("writer", () => {
        const helloWorld = new Uint8Array(Buffer.from("hello world"))

        it("should have newlines for the version and mac", async () => {
            const params = {
                fileKey: await random(32),
                version: "my-encrypter/1",
                recipients: [],
                headerMacMessage: "banana",
                body: helloWorld
            }
            const encryptedPayload = writeAge(params)
            expect(Array.from(encryptedPayload.matchAll(/\n/g))).to.have.length(2)
        })

        it("should have an additional line for each recipient", async () => {
            const params = {
                fileKey: await random(32),
                version: "my-encrypter/1",
                recipients: [],
                headerMacMessage: "banana",
                body: helloWorld
            }
            const recipients = [{
                type: "tlock",
                args: ["0", "abc"],
                body: helloWorld
            }, {
                type: "other-stuff",
                args: ["0", "abc"],
                body: helloWorld
            }]

            // newline for version, mac = 2
            // additionally 4 more lines for recipients:
            // per recipient 1 for type and args, 1 for the payload
            const encryptedPayload = writeAge({...params, recipients})

            // sometimes the binary ciphertext actually contains a newline character... ffs
            const numberOfNewLines = Array.from(encryptedPayload.matchAll(/\n/g))
            expect(numberOfNewLines).to.have.length.greaterThanOrEqual(6)
            expect(numberOfNewLines).to.have.length.lessThanOrEqual(7)
        })
    })

    describe("reader", () => {
        it("should succeed with ciphertext", () => {
            const agePayload = "age-encryption.org/v1\n" +
                "-> tlock 2304918 7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf\n" +
                "TtaPPedtx5LHNP0Nz4jBONFzz01yPvtp8MUH5xbZS+A\n" +
                "--- FVEPwakX/J6JUIBAiyfcdxhWFsRreW6ESZXw/F28A/M\n" +
                "Uw,�ʵ��B0�!w�\\)�x5�D���ezYf�R"

            expect(() => readAge(agePayload)).not.to.throw()
        })

        it("should succeed even if there are no recipients", () => {
            const agePayload = "age-encryption.org/v1\n" +
                "TtaPPedtx5LHNP0Nz4jBONFzz01yPvtp8MUH5xbZS+A\n" +
                "--- FVEPwakX/J6JUIBAiyfcdxhWFsRreW6ESZXw/F28A/M\n" +
                "Uw,�ʵ��B0�!w�\\)�x5�D���ezYf�R"

            expect(() => readAge(agePayload)).to.throw()
        })

        it("should fail for missing version", () => {
            const agePayload = "-> tlock 2304918 7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf\n" +
                "hjpN1XsAAF1QiYTmfCyo3nPWU5coUxXN/tKvdPIJYO3yUQkF+DwtOaXsuxLZVAYg\n" +
                "TtaPPedtx5LHNP0Nz4jBONFzz01yPvtp8MUH5xbZS+A\n" +
                "--- FVEPwakX/J6JUIBAiyfcdxhWFsRreW6ESZXw/F28A/M\n" +
                "Uw,�ʵ��B0�!w�\\)�x5�D���ezYf�R"

            expect(() => readAge(agePayload)).to.throw()

        })

        it("should fail for an empty input", () => {
            expect(() => readAge("")).to.throw()
        })

        it("should fail if recipients are missing bodies", () => {
            const agePayload = "age-encryption.org/v1\n" +
                "-> tlock 2304918 7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf\n" +
                "--- FVEPwakX/J6JUIBAiyfcdxhWFsRreW6ESZXw/F28A/M\n" +
                "Uw,�ʵ��B0�!w�\\)�x5�D���ezYf�R"

            expect(() => readAge(agePayload)).to.throw()
        })

        it("should fail if the mac is missing", () => {
            const agePayload = "age-encryption.org/v1\n" +
                "-> tlock 2304918 7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf\n" +
                "hjpN1XsAAF1QiYTmfCyo3nPWU5coUxXN/tKvdPIJYO3yUQkF+DwtOaXsuxLZVAYg\n" +
                "TtaPPedtx5LHNP0Nz4jBONFzz01yPvtp8MUH5xbZS+A\n" +
                "Uw,�ʵ��B0�!w�\\)�x5�D���ezYf�R"

            expect(() => readAge(agePayload)).to.throw()
        })

        it("should succeed without ciphertext", () => {
            const agePayload = "age-encryption.org/v1\n" +
                "-> tlock 2304918 7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bfTtaPPedtx5LHNP0Nz4jBONFzz01yPvtp8MUH5xbZS+A\n" +
                "TtaPPedtx5LHNP0Nz4jBONFzz01yPvtp8MUH5xbZS+A\n" +
                "--- FVEPwakX/J6JUIBAiyfcdxhWFsRreW6ESZXw/F28A/M\n" +
                "Uw,�ʵ��B0�!w�\\)�x5�D���ezYf�R"

            expect(() => readAge(agePayload)).not.to.throw()
        })

        it("should succeed for recipients with multiple payload lines", () => {
            const agePayload = "age-encryption.org/v1\n" +
                "-> tlock 2612487 7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf\n" +
                "hcyRoEtSovbU52hrdg7cp8nNOO2i8Lvlo7mKMtyR3ZvYch9TAGKibeQ7268F6EIZ\n" +
                "6ScKaEE4Fs3GYDaZsAzzSL56m9nOkbd9XQ3FyQ7rKUq///LGX39XCQR6aTJYez39\n" +
                "6wfopPUpepadf7KDn4fEbQ\n" +
                "--- /F2kxRwJKsKNzkOTGswmMaHnWGxGMqsz49Q/5TeGmZg\n" +
                "/C�ñKË¤rJêÿ;\"c0ï���³��pÕØùl�«À�^M«�"

            expect(() => readAge(agePayload)).not.to.throw()
        })

        it("should fail for recipients with short lines amongst their payload lines", () => {
            const agePayload = "age-encryption.org/v1\n" +
                "-> tlock 2612487 7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf\n" +
                "hcyRoEtSovbU52hrdg7cp8nNOO2i8Lvlo7mKMtyR3ZvYch9TAGKibeQ7268F6EIZ\n" +
                "6wfopPUpepadf7KDn4fEbQ\n" +
                "6ScKaEE4Fs3GYDaZsAzzSL56m9nOkbd9XQ3FyQ7rKUq///LGX39XCQR6aTJYez39\n" +
                "--- /F2kxRwJKsKNzkOTGswmMaHnWGxGMqsz49Q/5TeGmZg\n" +
                "/C�ñKË¤rJêÿ;\"c0ï���³��pÕØùl�«À�^M«�"

            expect(() => readAge(agePayload)).to.throw()
        })

        it("should fail if the argument contains invalid characters", () => {
            // the euro sign has too high a character code to be accepted
            const charTooHighPayload = "age-encryption.org/v1\n" +
                "-> tlock 2304918 76727€7f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf\n" +
                "TtaPPedtx5LHNP0Nz4jBONFzz01yPvtp8MUH5xbZS+A\n" +
                "--- FVEPwakX/J6JUIBAiyfcdxhWFsRreW6ESZXw/F28A/M\n" +
                "Uw,�ʵ��B0�!w�\\)�x5�D���ezYf�R"

            expect(() => readAge(charTooHighPayload)).to.throw()

            // the null separator is too low in the character range to be valid
            const charTooLowPayload = "age-encryption.org/v1\n" +
                "-> tlock 2304918 76727�7f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf\n" +
                "TtaPPedtx5LHNP0Nz4jBONFzz01yPvtp8MUH5xbZS+A\n" +
                "--- FVEPwakX/J6JUIBAiyfcdxhWFsRreW6ESZXw/F28A/M\n" +
                "Uw,�ʵ��B0�!w�\\)�x5�D���ezYf�R"

            expect(() => readAge(charTooLowPayload)).to.throw()
        })
    })
})
