import {defaultClientInfo, DrandClient, DrandHttpClient, roundForTime, timeForRound} from "./drand/drand-client"
import {createTimelockEncrypter} from "./drand/timelock-encrypter"
import {decryptAge, encryptAge} from "./age/age-encrypt-decrypt"
import {decodeArmor, encodeArmor, isProbablyArmored} from "./age/armor"
import {createTimelockDecrypter} from "./drand/timelock-decrypter"

export async function timelockEncrypt(
    roundNumber: number,
    payload: string,
    drandHttpClient: DrandClient = DrandHttpClient.createFetchClient(defaultClientInfo),
): Promise<string> {
    const chainInfo = await drandHttpClient.info()
    const timelockEncrypter = createTimelockEncrypter(chainInfo, drandHttpClient, roundNumber)
    const agePayload = await encryptAge(Buffer.from(payload), timelockEncrypter)
    return encodeArmor(agePayload)
}

export async function timelockDecrypt(
    ciphertext: string,
    drandHttpClient: DrandClient = DrandHttpClient.createFetchClient(defaultClientInfo)
): Promise<string> {
    const timelockDecrypter = createTimelockDecrypter(drandHttpClient)

    let cipher = ciphertext
    if (isProbablyArmored(ciphertext)) {
        cipher = decodeArmor(cipher)
    }

    return await decryptAge(cipher, timelockDecrypter)
}

export {DrandHttpClient, defaultClientInfo, roundForTime, timeForRound}