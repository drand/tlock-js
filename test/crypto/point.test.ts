import { bls12_381} from "@noble/curves/bls12-381"
import {hashedRoundNumber} from "../../src/drand/timelock-encrypter"

describe("beacon", () => {
    it("verifies for the new bls lib", () => {
        const pubKey = "8200fc249deb0148eb918d6e213980c5d01acd7fc251900d9260136da3b54836ce125172399ddc69c4e3e11429b62c11"
        const round = 19369534
        const sig = bls12_381.G2.ProjectivePoint.fromHex("a33833d2098f5e0c4df334fb6c5b1c2de3ab293c77825f55d816254dabf7f4f3d429b6207e1cd2a808876e06058a1f8102bb6f6927b654b391259ea99c3566a4eb55feb9665dbaf9d33af08a10b1d8d8b35d91fd3536eb4c197be0041beb5dc2")
        const msg = hashedRoundNumber(round)
        expect(bls12_381.verify(sig, msg, pubKey)).toBeTruthy()
    })
})