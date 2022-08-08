import {Beacon, DrandClient} from "../../src/drand/drand-client"

class MockDrandClient implements DrandClient {

    constructor(private beacon: Beacon) {
    }

    get(_: number): Promise<Beacon> {
        return Promise.resolve(this.beacon)
    }
}

const validBeacon = {
    round: 1,
    randomness: "8430af445106a217c174b6265093d386bd3631ccb3dae833b5e645abbb281323",
    signature: "86ecea71376e78abd19aaf0ad52f462a6483626563b1023bd04815a7b953da888c74f5bf6ee672a5688603ab310026230522898f33f23a7de363c66f90ffd49ec77ebf7f6c1478a9ecd6e714b4d532ab43d044da0a16fed13b4791d7fc999e2b"
}

export { MockDrandClient, validBeacon }
