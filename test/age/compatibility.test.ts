import {expect} from "chai"
import {MockDrandClient} from "../drand/mock-drand-client"
import {timelockDecrypt, timelockEncrypt} from "../../src"
import {MAINNET_CHAIN_INFO, MAINNET_CHAIN_INFO_NON_RFC, TESTNET_CHAIN_INFO} from "../../src/drand/defaults";
import {assertError, assertErrorMessage} from "../utils";

test("payloads encrypted with the old go impl should not decrypt anymore", async () => {
    const validBeacon = {
        round: 20000,
        randomness: "49891540810f410d114b25bdd47e6c14d316da3e513a82e91cc705a9bbb43fb3",
        signature: "91130cdcb1d7cbc402bbb10caecf3eaa2aa041a8bdc5a3791f24c033431bc0c7a0275c2b76fdcc2031dd613b2641a1a715eb6e97dce0a9c0325426315d5da276bd5ebbf07d2e6a082697e31db1d3e8f7813797d3c5a7ca95e90167404426a7c3"
    }
    const mockClient = new MockDrandClient(validBeacon, TESTNET_CHAIN_INFO)
    const payloadFromGoImpl = "-----BEGIN AGE ENCRYPTED FILE-----\n" +
        "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDIwMDAwIDc2NzI3OTdmNTQ4\n" +
        "ZjNmNDc0OGFjNGJmMzM1MmZjNmM2YjY0NjhjOWFkNDBhZDQ1NmEzOTc1NDVjNmUy\n" +
        "ZGY1YmYKc3lqZWdrbGdmZlRaQ3hITEN1YUlZakhDRGdZNTBUK0owNk1Zd1dMdjZB\n" +
        "YUExN1o2YzVWWnJ5cTFBNWNLOWl4cQpUd2I5S3p0Z1NxRjRhdlNRbXRJN0pXMFk2\n" +
        "cWtMRmVDNjVjMktzOHhRdWZvCi0tLSBWNUpzL2g0SnBENFhPR1BqMHhZMHpqRGtZ\n" +
        "Y2FzUjBSUUNkSTFGMHRGbVQ0CkTlx8fbyyH+q2i65DGOJhYRgWIWsxGVE4yTJtrD\n" +
        "NdqmZSVrmhIAfkALCQi1PQw3+N88xe+5zjHy4Lpxi8uN2GMlud6x49yzcYI=\n" +
        "-----END AGE ENCRYPTED FILE-----"

    await assertErrorMessage(() => timelockDecrypt(payloadFromGoImpl, mockClient),"invalid proof: rP check failed")
})

test("payloads encrypted with the go impl should decrypt successfully with a non-rfc-compliant G1 beacon", async () => {
    const validBeaconOnG1 = {
        round: 2,
        randomness: "08eb40c1dff4076da53d222b2076f06c144391445cfac750815d5cacf51bf7c2",
        signature: "a050676d1a1b6ceedb5fb3281cdfe88695199971426ff003c0862460b3a72811328a07ecd53b7d57fc82bb67f35efaf1"
    }
    const mockClient = new MockDrandClient(validBeaconOnG1, MAINNET_CHAIN_INFO_NON_RFC)
    const payloadFromGoImpl = `-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDIgZGJkNTA2ZDZlZjc2ZTVm
Mzg2ZjQxYzY1MWRjYjgwOGM1YmNiZDc1NDcxY2M0ZWFmYTNmNGRmN2FkNGU0YzQ5
MwpzRXAvVVpBQXlDSjE1QUxDaUFnQ1E2cEd1elJXS0kzMkpsQnBxUFAzcHVvdWRT
a2w0OXJ0NC9rMmd0UHlVMTRxCkN3MERjVUJVUlloT2UrRjZsSE9lTFgwMkZNMjk3
UGpwNlBZL09WY3NoblhqMTVMbU9FeXV1MjlDcmJGQXU3SmgKcWxlbjFtaXBONWUz
eFpVQysxQWtjS1Z3SU9uRjJWaW8veUpkNEUyVHhQWQotLS0gN21xSHhranNqMEND
UG9qN2haU0FWdEpFK0pUZzUwWmVsVS9YRWdOaDRadwpeDBRfXZtLOC49GlI+Kozr
z6hgtLUPYvAimgekc+CeyJ8fb/0MVrpq/Ewnx1MpKig8nQ==
-----END AGE ENCRYPTED FILE-----`
    const plaintext = await timelockDecrypt(payloadFromGoImpl, mockClient)

    expect(plaintext.toString("utf8")).to.equal("Hello drand World\n")
})

test("payloads encrypted with the go impl should decrypt successfully with G2 beacon", async () => {
    const validBeaconOnG2 = {
        round: 1,
        randomness: "8430af445106a217c174b6265093d386bd3631ccb3dae833b5e645abbb281323",
        signature: "86ecea71376e78abd19aaf0ad52f462a6483626563b1023bd04815a7b953da888c74f5bf6ee672a5688603ab310026230522898f33f23a7de363c66f90ffd49ec77ebf7f6c1478a9ecd6e714b4d532ab43d044da0a16fed13b4791d7fc999e2b"
    }
    const mockClient = new MockDrandClient(validBeaconOnG2, TESTNET_CHAIN_INFO)
    const payloadFromGoImpl = `-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDEgNzY3Mjc5N2Y1NDhmM2Y0
NzQ4YWM0YmYzMzUyZmM2YzZiNjQ2OGM5YWQ0MGFkNDU2YTM5NzU0NWM2ZTJkZjVi
ZgpzditiV09ZTGh1M3ZpeWtySGdVL0U0QWd1R2c0SGFvaDJjaUJhWTlsZEgzRVZO
eER3N0hUakxxejdoSHpqdjYxClVLaHh3VlZVNnJ5VmtpQ0JuZmVhRkVOanI0OFk3
bHFRSG9NSTJQTGg5RnMKLS0tIG9OdGUrMnRtVE40NHNLVjFZVnQ3dXJ6SWh5ZWtL
aU8wTE5SVUN1QmFxdnMKSV7e0ctoMEAfh1gqfl3qEFpZxEyO/vc7Se9iNR9BfpPo
HypjufJAgOSFJtWGfxQ=
-----END AGE ENCRYPTED FILE-----`
    const plaintext = await timelockDecrypt(payloadFromGoImpl, mockClient)

    expect(plaintext.toString("utf8")).to.equal("Hello dranders\n")
})
