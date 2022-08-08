import {defaultClientInfo, DrandClient, DrandHttpClient, DrandNetworkInfo} from "./drand/drand-client"
import {createTimelockEncrypter} from "./drand/timelock-encrypter"
import {decryptAge, encryptAge} from "./age/age-encrypt-decrypt"
import {decodeArmor, encodeArmor, isProbablyArmored} from "./age/armor"
import {createTimelockDecrypter} from "./drand/timelock-decrypter"

export async function timelockEncrypt(
    config: DrandNetworkInfo,
    roundNumber: number,
    payload: string,
    drandHttpClient: DrandClient = DrandHttpClient.createFetchClient(),
): Promise<string> {
    // probably should get `chainInfo` through /info
    const timelockEncrypter = createTimelockEncrypter(defaultClientInfo, drandHttpClient, roundNumber)
    const agePayload = await encryptAge(Buffer.from(payload), timelockEncrypter)
    return encodeArmor(agePayload)
}

export async function timelockDecrypt(
    ciphertext: string,
    drandHttpClient: DrandClient = DrandHttpClient.createFetchClient()
): Promise<string> {
    const timelockDecrypter = createTimelockDecrypter(drandHttpClient)

    let cipher = ciphertext
    if (isProbablyArmored(ciphertext)) {
        cipher = decodeArmor(cipher)
    }

    return await decryptAge(cipher, timelockDecrypter)
}

export {DrandHttpClient, defaultClientInfo}