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
): Promise<string> {

    const timelockEncrypter = createTimelockEncrypter(chainClient, roundNumber)
    const agePayload = await encryptAge(payload, timelockEncrypter)
    return encodeArmor(agePayload)
}

export async function timelockDecrypt(
    ciphertext: string,
    chainClient: ChainClient,
): Promise<string> {
    const timelockDecrypter = createTimelockDecrypter(chainClient)

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