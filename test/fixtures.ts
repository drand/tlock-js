import { quicknet, type Beacon, type Chain } from "../src/index.js";

export const vectors = [
  {
    name: "quicknet",
    chain: quicknet.chain,
    plaintext: "hello world\n",
    beacon: {
      round: 746511,
      signature:
        "a9080432fbe9dd72d25a78c092f6d507a418fd9f985f8b5e99ac380dc63d6d203198f4160e353055e9fbd8fccdfdbd37",
    },
  },
  {
    name: "fastnet",
    chain: {
      hash: "dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493",
      publicKey:
        "a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e",
      scheme: "bls-unchained-on-g1",
      genesisTime: 1677685200,
      period: 3,
    },
    plaintext: "Hello drand World\n",
    beacon: {
      round: 2,
      signature:
        "a050676d1a1b6ceedb5fb3281cdfe88695199971426ff003c0862460b3a72811328a07ecd53b7d57fc82bb67f35efaf1",
      randomness:
        "08eb40c1dff4076da53d222b2076f06c144391445cfac750815d5cacf51bf7c2",
    },
  },
  {
    name: "g2",
    chain: {
      hash: "7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf",
      publicKey:
        "8200fc249deb0148eb918d6e213980c5d01acd7fc251900d9260136da3b54836ce125172399ddc69c4e3e11429b62c11",
      scheme: "pedersen-bls-unchained",
      genesisTime: 1651677099,
      period: 3,
    },
    plaintext: "Hello dranders\n",
    beacon: {
      round: 1,
      signature:
        "86ecea71376e78abd19aaf0ad52f462a6483626563b1023bd04815a7b953da888c74f5bf6ee672a5688603ab310026230522898f33f23a7de363c66f90ffd49ec77ebf7f6c1478a9ecd6e714b4d532ab43d044da0a16fed13b4791d7fc999e2b",
      randomness:
        "8430af445106a217c174b6265093d386bd3631ccb3dae833b5e645abbb281323",
    },
  },
] as const satisfies readonly {
  name: string;
  chain: Chain;
  plaintext: string;
  beacon: Beacon;
}[];

export const quicknetBeacon: Beacon = {
  round: 746511,
  signature:
    "a9080432fbe9dd72d25a78c092f6d507a418fd9f985f8b5e99ac380dc63d6d203198f4160e353055e9fbd8fccdfdbd37",
  randomness:
    "c1ec7a314c3a5bf7741be4800bb0cf0bd009278dfa9f6bca966cf94911dc74f2",
};

export function payload(size: number): Uint8Array {
  return Uint8Array.from({ length: size }, (_, i) => i % 256);
}
