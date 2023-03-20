import {
    ChainClient,
    HttpChainClient,
    HttpCachingChain,
    roundTime,
    roundAt,
    ChainInfo,
    defaultChainOptions
} from "drand-client"
import {Buffer} from "buffer"
import {createTimelockEncrypter} from "./drand/timelock-encrypter"
import {decryptAge, encryptAge} from "./age/age-encrypt-decrypt"
import {decodeArmor, encodeArmor, isProbablyArmored} from "./age/armor"
import {createTimelockDecrypter} from "./drand/timelock-decrypter"
import {defaultChainInfo, defaultChainUrl} from "./drand/defaults"
import {version} from "../package.json"

export async function timelockEncrypt(
    roundNumber: number,
    payload: Buffer,
    chainClient: ChainClient,
    swap = false
): Promise<string> {

    const timelockEncrypter = createTimelockEncrypter(chainClient, roundNumber, swap)
    const agePayload = await encryptAge(payload, timelockEncrypter)
    return encodeArmor(agePayload)
}

export async function timelockDecrypt(
    ciphertext: string,
    chainClient: ChainClient,
    swap = false
): Promise<string> {
    const timelockDecrypter = createTimelockDecrypter(chainClient, swap)

    let cipher = ciphertext
    if (isProbablyArmored(ciphertext)) {
        cipher = decodeArmor(cipher)
    }

    return await decryptAge(cipher, timelockDecrypter)
}

export function testnetClient(): HttpChainClient {
    const chain = new HttpCachingChain(defaultChainUrl, defaultChainOptions)
    return new HttpChainClient(chain, defaultChainOptions, {
        userAgent: `tlock-js-${version}`
    })
}

export function mainnetClient(): HttpChainClient {
    const opts = {
        ...defaultChainOptions,
        chainVerificationParams: {
            chainHash: "dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493",
            publicKey: "a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e"
        }
    }
    const chain = new HttpCachingChain("https://api.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493", opts)
    return new HttpChainClient(chain, opts)
}

export {
    ChainClient,
    HttpChainClient,
    HttpCachingChain,
    ChainInfo,
    defaultChainInfo,
    defaultChainUrl,
    roundTime,
    roundAt,
    Buffer
}