import {defaultClientInfo, DrandClient, DrandHttpClient, roundForTime, timeForRound} from "./drand/drand-client"
import {createTimelockEncrypter} from "./drand/timelock-encrypter"
import {decryptAge, encryptAge} from "./age/age-encrypt-decrypt"
import {decodeArmor, encodeArmor, isProbablyArmored} from "./age/armor"
import {createTimelockDecrypter} from "./drand/timelock-decrypter"

export async function timelockEncrypt(
    roundNumber: number,
    payload: Buffer,
    options?: {
        drandHttpClient?: DrandClient,
        doNotIncludeRoundNumber?: boolean
    }
): Promise<string> {
    let drandHttpClient = options?.drandHttpClient;
    if (!drandHttpClient) {
        drandHttpClient =  DrandHttpClient.createFetchClient(defaultClientInfo)
    }
    const chainInfo = await drandHttpClient.info()
    const timelockEncrypter = createTimelockEncrypter(chainInfo, drandHttpClient, roundNumber, {doNotIncludeRoundNumber: options?.doNotIncludeRoundNumber})
    const agePayload = await encryptAge(payload, timelockEncrypter)
    return encodeArmor(agePayload)
}

export async function timelockDecrypt(
    ciphertext: string | {ciphertext: string; roundNumber?: number},
    drandHttpClient: DrandClient = DrandHttpClient.createFetchClient(defaultClientInfo)
): Promise<string> {

    let roundNumber;
    if (typeof ciphertext !== "string") {
        roundNumber = ciphertext.roundNumber
        ciphertext = ciphertext.ciphertext
    }

    const timelockDecrypter = createTimelockDecrypter(drandHttpClient, roundNumber)

    let cipher = ciphertext
    if (isProbablyArmored(ciphertext)) {
        cipher = decodeArmor(cipher)
    }

    return await decryptAge(cipher, timelockDecrypter)
}

export {DrandHttpClient, defaultClientInfo, roundForTime, timeForRound}