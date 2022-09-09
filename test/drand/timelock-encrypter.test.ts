import {expect} from "chai"
import {createTimelockEncrypter} from "../../src/drand/timelock-encrypter"
import {defaultClientInfo} from "../../src"
import {MockDrandClient, validBeacon} from "./mock-drand-client"

describe("timelock encrypter", () => {
    it("should throw an error if created with the genesis round", () => {
        expect(() => createTimelockEncrypter(defaultClientInfo, new MockDrandClient(validBeacon), 0)).to.throw()
    })

    it("should throw an error if created with a negative round", () => {
        expect(() => createTimelockEncrypter(defaultClientInfo, new MockDrandClient(validBeacon), -1)).to.throw()
    })
})
