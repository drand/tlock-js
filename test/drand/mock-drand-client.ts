import {
    Chain,
    ChainClient,
    ChainInfo,
    ChainOptions,
    RandomnessBeacon
} from "drand-client"
import {TESTNET_CHAIN_INFO} from "../../src/drand/defaults";

class MockDrandClient implements ChainClient {
    options: ChainOptions = {
        disableBeaconVerification: false,
        noCache: false,
    }

    constructor(private beacon: RandomnessBeacon, private info: ChainInfo = TESTNET_CHAIN_INFO) {
    }

    get(_: number): Promise<RandomnessBeacon> {
        return Promise.resolve(this.beacon)
    }

    latest(): Promise<RandomnessBeacon> {
        return Promise.resolve(this.beacon)
    }

    chain(): Chain {
        return new Mockchain(this.info)
    }
}

class Mockchain implements Chain {
    baseUrl = ""

    constructor(private chainInfo: ChainInfo) {
    }

    info(): Promise<ChainInfo> {
        return Promise.resolve(this.chainInfo)
    }
}

// this is a beacon from testnet-unchained-3s
const validBeacon = {
    round: 1,
    randomness: "8430af445106a217c174b6265093d386bd3631ccb3dae833b5e645abbb281323",
    signature: "86ecea71376e78abd19aaf0ad52f462a6483626563b1023bd04815a7b953da888c74f5bf6ee672a5688603ab310026230522898f33f23a7de363c66f90ffd49ec77ebf7f6c1478a9ecd6e714b4d532ab43d044da0a16fed13b4791d7fc999e2b"
}

export {MockDrandClient, validBeacon}
