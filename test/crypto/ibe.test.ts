import * as bls from "@noble/bls12-381"
import {Fp, Fp2, Fp12} from "@noble/bls12-381"
import {expect} from "chai"
import {fp12ToBytes, fp2ToBytes, fpToBytes} from "../../src/crypto/utils"
import {gtToHash} from "../../src/crypto/ibe"

describe("fpToBytes", () => {
    it("should reverse the order of values in the Fps", () => {
        const combined = Buffer.concat([fpToBytes(new Fp(1n)), fpToBytes(new Fp(2n))])
        const fp2 = fp2ToBytes(Fp2.fromBigTuple([2n, 1n]))

        expect(Buffer.compare(fp2, combined)).to.equal(0)
    })

    it("Fp2s should be reversed when combined to an Fp12", () => {
        const one = fp2ToBytes(Fp2.fromBigTuple([1n, 2n]))
        const two = fp2ToBytes(Fp2.fromBigTuple([3n, 4n]))
        const three = fp2ToBytes(Fp2.fromBigTuple([5n, 6n]))
        const four = fp2ToBytes(Fp2.fromBigTuple([7n, 8n]))
        const five = fp2ToBytes(Fp2.fromBigTuple([9n, 10n]))
        const six = fp2ToBytes(Fp2.fromBigTuple([11n, 12n]))
        const combined = Buffer.concat([one, two, three, four, five, six])

        const fullFp12 = fp12ToBytes(Fp12.fromBigTwelve([11n, 12n, 9n, 10n, 7n, 8n, 5n, 6n, 3n, 4n, 1n, 2n]))

        expect(Buffer.compare(fullFp12, combined)).to.equal(0)
    })

    it("big nums should not lose precision", () => {
        // a number with more than 64bits
        const expectedHexValue = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffff"
        // the same value as a `bigint`
        const bytes = fpToBytes(new Fp(1099511627775n))

        expect(Buffer.from(bytes).toString("hex")).to.equal(expectedHexValue)
    })

    it("correctly pass the test vectors generated from the go codebase", () => {
        // note these test vectors are the reverse order of the go ones
        const test = Fp12.fromBigTwelve([
            BigInt("0x1250ebd871fc0a92a7b2d83168d0d727272d441befa15c503dd8e90ce98db3e7b6d194f60839c508a84305aaca1789b6"),
            BigInt("0x089a1c5b46e5110b86750ec6a532348868a84045483c92b7af5af689452eafabf1a8943e50439f1d59882a98eaa0170f"),
            BigInt("0x1368bb445c7c2d209703f239689ce34c0378a68e72a6b3b216da0e22a5031b54ddff57309396b38c881c4c849ec23e87"),
            BigInt("0x193502b86edb8857c273fa075a50512937e0794e1e65a7617c90d8bd66065b1fffe51d7a579973b1315021ec3c19934f"),
            BigInt("0x01b2f522473d171391125ba84dc4007cfbf2f8da752f7c74185203fcca589ac719c34dffbbaad8431dad1c1fb597aaa5"),
            BigInt("0x018107154f25a764bd3c79937a45b84546da634b8f6be14a8061e55cceba478b23f7dacaa35c8ca78beae9624045b4b6"),
            BigInt("0x19f26337d205fb469cd6bd15c3d5a04dc88784fbb3d0b2dbdea54d43b2b73f2cbb12d58386a8703e0f948226e47ee89d"),
            BigInt("0x06fba23eb7c5af0d9f80940ca771b6ffd5857baaf222eb95a7d2809d61bfe02e1bfd1b68ff02f0b8102ae1c2d5d5ab1a"),
            BigInt("0x11b8b424cd48bf38fcef68083b0b0ec5c81a93b330ee1a677d0d15ff7b984e8978ef48881e32fac91b93b47333e2ba57"),
            BigInt("0x03350f55a7aefcd3c31b4fcb6ce5771cc6a0e9786ab5973320c806ad360829107ba810c5a09ffdd9be2291a0c25a99a2"),
            BigInt("0x04c581234d086a9902249b64728ffd21a189e87935a954051c7cdba7b3872629a4fafc05066245cb9108f0242d0fe3ef"),
            BigInt("0x0f41e58663bf08cf068672cbd01a7ec73baca4d72ca93544deff686bfd6df543d48eaa24afe47e1efde449383b676631"),
        ])

        const expectedOutput = "0f41e58663bf08cf068672cbd01a7ec73baca4d72ca93544deff686bfd6df543d48eaa24afe47e1efde449383b67663104c581234d086a9902249b64728ffd21a189e87935a954051c7cdba7b3872629a4fafc05066245cb9108f0242d0fe3ef03350f55a7aefcd3c31b4fcb6ce5771cc6a0e9786ab5973320c806ad360829107ba810c5a09ffdd9be2291a0c25a99a211b8b424cd48bf38fcef68083b0b0ec5c81a93b330ee1a677d0d15ff7b984e8978ef48881e32fac91b93b47333e2ba5706fba23eb7c5af0d9f80940ca771b6ffd5857baaf222eb95a7d2809d61bfe02e1bfd1b68ff02f0b8102ae1c2d5d5ab1a19f26337d205fb469cd6bd15c3d5a04dc88784fbb3d0b2dbdea54d43b2b73f2cbb12d58386a8703e0f948226e47ee89d018107154f25a764bd3c79937a45b84546da634b8f6be14a8061e55cceba478b23f7dacaa35c8ca78beae9624045b4b601b2f522473d171391125ba84dc4007cfbf2f8da752f7c74185203fcca589ac719c34dffbbaad8431dad1c1fb597aaa5193502b86edb8857c273fa075a50512937e0794e1e65a7617c90d8bd66065b1fffe51d7a579973b1315021ec3c19934f1368bb445c7c2d209703f239689ce34c0378a68e72a6b3b216da0e22a5031b54ddff57309396b38c881c4c849ec23e87089a1c5b46e5110b86750ec6a532348868a84045483c92b7af5af689452eafabf1a8943e50439f1d59882a98eaa0170f1250ebd871fc0a92a7b2d83168d0d727272d441befa15c503dd8e90ce98db3e7b6d194f60839c508a84305aaca1789b6"
        const toBytesOutput = fp12ToBytes(test)
        expect(Buffer.from(toBytesOutput).toString("hex")).to.equal(expectedOutput)

        expect(bls.pairing(bls.PointG1.BASE, bls.PointG2.BASE)).to.deep.equal(test)
        expect(fp12ToBytes(bls.pairing(bls.PointG1.BASE, bls.PointG2.BASE))).to.deep.equal(fp12ToBytes(test))

        // the drand kyber actually multiplies when using `.add()`
        const expectedAdded = "079ab7b345eb23c944c957a36a6b74c37537163d4cbf73bad9751de1dd9c68ef72cb21447e259880f72a871c3eda1b0c017f1c95cf79b22b459599ea57e613e00cb75e35de1f837814a93b443c54241015ac9761f8fb20a44512ff5cfc04ac7f0f6b8b52b2b5d0661cbf232820a257b8c5594309c01c2a45e64c6a7142301e4fb36e6e16b5a85bd2e437599d103c3ace06d8046c6b3424c4cd2d72ce98d279f2290a28a87e8664cb0040580d0c485f34df45267f8c215dcbcd862787ab555c7e113286dee21c9c63a458898beb35914dc8daaac453441e7114b21af7b5f47d559879d477cf2a9cbd5b40c86becd071280900410bb2751d0a6af0fe175dcf9d864ecaac463c6218745b543f9e06289922434ee446030923a3e4c4473b4e3b1914081abd33a78d31eb8d4c1bb3baab0529bb7baf1103d848b4cead1a8e0aa7a7b260fbe79c67dbe41ca4d65ba8a54a72b61692a61ce5f4d7a093b2c46aa4bca6c4a66cf873d405ebc9c35d8aa639763720177b23beffaf522d5e41d3c5310ea3331409cebef9ef393aa00f2ac64673675521e8fc8fddaf90976e607e62a740ac59c3dddf95a6de4fba15beb30c43d4e3f803a3734dbeb064bf4bc4a03f945a4921e49d04ab8d45fd753a28b8fa082616b4b17bbcb685e455ff3bf8f60c3bd32a0c185ef728cf41a1b7b700b7e445f0b372bc29e370bc227d443c70ae9dbcf73fee8acedbd317a286a53266562d817269c004fb0f149dd925d2c590a960936763e519c2b62e14c7759f96672cd852194325904197b0b19c6b528ab33566946af39b"
        expect(Buffer.from(fp12ToBytes(test.multiply(test))).toString("hex")).to.equal(expectedAdded)

        const expectedGtToHash = "cb87319f24560b5231579a09ad79f12e"
        expect(Buffer.from(gtToHash(test, 16)).toString("hex")).to.equal(expectedGtToHash)

        const expectedG1Compressed = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
        const actualG1Compressed = Buffer.from(bls.PointG1.BASE.toRawBytes(true)).toString("hex")
        expect(actualG1Compressed).to.equal(expectedG1Compressed)

        // compressed g2 not yet implemented in noble
        const expectedG2Uncompressed = "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"
        const actualG2Uncompressed = Buffer.from(bls.PointG2.BASE.toRawBytes(false)).toString("hex")
        expect(actualG2Uncompressed).to.equal(expectedG2Uncompressed)
    })
})
