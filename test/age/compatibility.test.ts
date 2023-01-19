import {expect} from "chai"
import {MockDrandClient} from "../drand/mock-drand-client"
import {timelockDecrypt} from "../../src"

test("payloads encrypted with the go impl should decrypt successfully", async () => {
    const validBeacon = {
        round: 20000,
        randomness: "49891540810f410d114b25bdd47e6c14d316da3e513a82e91cc705a9bbb43fb3",
        signature: "91130cdcb1d7cbc402bbb10caecf3eaa2aa041a8bdc5a3791f24c033431bc0c7a0275c2b76fdcc2031dd613b2641a1a715eb6e97dce0a9c0325426315d5da276bd5ebbf07d2e6a082697e31db1d3e8f7813797d3c5a7ca95e90167404426a7c3"
    }
    const mockClient = new MockDrandClient(validBeacon)
    const payloadFromGoImpl = "-----BEGIN AGE ENCRYPTED FILE-----\n" +
        "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDIwMDAwIDc2NzI3OTdmNTQ4\n" +
        "ZjNmNDc0OGFjNGJmMzM1MmZjNmM2YjY0NjhjOWFkNDBhZDQ1NmEzOTc1NDVjNmUy\n" +
        "ZGY1YmYKc3lqZWdrbGdmZlRaQ3hITEN1YUlZakhDRGdZNTBUK0owNk1Zd1dMdjZB\n" +
        "YUExN1o2YzVWWnJ5cTFBNWNLOWl4cQpUd2I5S3p0Z1NxRjRhdlNRbXRJN0pXMFk2\n" +
        "cWtMRmVDNjVjMktzOHhRdWZvCi0tLSBWNUpzL2g0SnBENFhPR1BqMHhZMHpqRGtZ\n" +
        "Y2FzUjBSUUNkSTFGMHRGbVQ0CkTlx8fbyyH+q2i65DGOJhYRgWIWsxGVE4yTJtrD\n" +
        "NdqmZSVrmhIAfkALCQi1PQw3+N88xe+5zjHy4Lpxi8uN2GMlud6x49yzcYI=\n" +
        "-----END AGE ENCRYPTED FILE-----"
    const plaintext = await timelockDecrypt(payloadFromGoImpl, mockClient)

    expect(plaintext).to.equal("why are you reading this secret message??")
})
