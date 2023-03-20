// config for the testnet chain info
import {ChainInfo} from "drand-client"

export const MainnetChainUrl = "https://api.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493"
export const MainnetChainInfo: ChainInfo = {
    hash: "dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493",
    public_key: "a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e",
    period: 3,
    genesis_time: 1677685200,
    groupHash: "a81e9d63f614ccdb144b8ff79fbd4d5a2d22055c0bfe4ee9a8092003dab1c6c0",
    schemeID: "bls-unchained-on-g1",
    metadata: {
        beaconID: "fastnet"
    }
};

export const defaultChainUrl = MainnetChainUrl
export const defaultChainInfo = MainnetChainInfo

export const TestnetChainUrl = "https://pl-us.testnet.drand.sh/7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf"
export const TestnetChainInfo: ChainInfo = {
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
