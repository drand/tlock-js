import {expect} from "chai"
import {createTimelockEncrypter} from "../../src/drand/timelock-encrypter"
import {MockDrandClient, validBeacon} from "./mock-drand-client"

describe("timelock encrypter", () => {
    it("should throw an error if created with the genesis round", () => {
        expect(() => createTimelockEncrypter(new MockDrandClient(validBeacon), 0)).to.throw()
    })

    it("should throw an error if created with a negative round", () => {
        expect(() => createTimelockEncrypter(new MockDrandClient(validBeacon), -1)).to.throw()
    })

    it("should work with 1", () => {
        expect(() => createTimelockEncrypter(new MockDrandClient(validBeacon), 1)).not.to.throw()
    })
})
