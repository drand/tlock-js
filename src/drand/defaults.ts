// config for the testnet chain info
import {ChainInfo} from "drand-client"

export const defaultChainUrl = "https://pl-us.testnet.drand.sh/7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf"
export const defaultChainInfo: ChainInfo = {
    hash: "7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf",
    public_key: "8200fc249deb0148eb918d6e213980c5d01acd7fc251900d9260136da3b54836ce125172399ddc69c4e3e11429b62c11",
    genesis_time: 1651677099,
    period: 3,
    schemeID: "pedersen-bls-unchained",
    groupHash: "65083634d852ae169e21b6ce5f0410be9ed4cc679b9970236f7875cff667e13d",
    metadata: {
        beaconID: "testnet-unchained-3s"
    }
}
