import {chunked, unpaddedBase64} from "./utils"
import {createMacKey} from "./utils-crypto"

type Stanza = {
    type: string,
    args: Array<string>,
    body: Uint8Array
}

type AgeEncryptionInput = {
    fileKey: Uint8Array
    version: string
    recipients: Array<Stanza>
    body: Uint8Array
    headerMacMessage: string
}

type AgeEncryptionOutput = {
    header: {
        version: string
        recipients: Array<Stanza>
        mac: Uint8Array
    }
    body: Uint8Array
}

// takes the model to be encrypted and encodes everything to a string
// inserting newlines, other tags and the hmac as per the spec
export function writeAge(input: AgeEncryptionInput): string {
    const headerStr = header(input)
    const macKey = mac(createMacKey(input.fileKey, input.headerMacMessage, headerStr))
    const payload = Buffer.from(input.body).toString("binary")

    return `${headerStr} ${macKey}\n${payload}`
}

// ends with a `---`, as this is included in the header when
// calculating the MAC
export function header(input: AgeEncryptionInput): string {
    return `${input.version}\n${recipients(input.recipients)}---`
}

const recipients = (stanzas: Array<Stanza>) =>
    stanzas.map(it => recipient(it) + "\n")

const recipient = (stanza: Stanza) => {
    const type = stanza.type
    const aggregatedArgs = stanza.args.join(" ")
    const encodedBody = unpaddedBase64(stanza.body)
    const chunkedEncodedBody = chunked(encodedBody, 64).join("\n")

    return `-> ${type} ${aggregatedArgs}\n` + chunkedEncodedBody
}

// The `---` preceding the MAC is technically part of the MAC-able text
// so it's included in the header instead
const mac = (macStr: Uint8Array) => unpaddedBase64(macStr)

// parses an AGE encrypted string into a model object with all the
// relevant parts encoded correctly
// throws an error if things are missing, in the wrong place or cannot
// be parsed
export function readAge(input: string): AgeEncryptionOutput {
    const [version, ...lines] = input.split("\n")

    const recipients = parseRecipients(lines)

    const macStartingTag = "--- "
    const macLine = lines.shift()
    if (!macLine || !macLine.startsWith(macStartingTag)) {
        throw Error("Expected mac, but there were no more lines left!")
    }

    const mac = Buffer.from(macLine.slice(macStartingTag.length, macLine.length), "base64")

    // any remaining newlines are actually part of the payload
    const ciphertext = Buffer.from(lines.join("\n") ?? "", "binary")

    return {
        header: {version, recipients, mac},
        body: ciphertext
    }
}

// parses all the recipient stanzas from `lines`
// modifies `lines`!!
function parseRecipients(lines: Array<string>): Array<Stanza> {
    const recipients: Array<Stanza> = []

    for (let current = peek(lines); current != null && current.startsWith("->"); current = peek(lines)) {
        const [type, ...args] = current.slice(3, current.length).split(" ")
        lines.shift()

        const body = parseRecipientBody(lines)
        if (!body) {
            throw Error(`expected stanza '${type} to have a body, but it didn't`)
        }

        recipients.push({type, args, body: Buffer.from(body, "base64")})
    }

    if (recipients.length === 0) {
        throw Error("Expected at least one stanza! (beginning with -->)")
    }

    return recipients
}

function parseRecipientBody(lines: Array<string>): string {
    let body = ""
    for (let next = peek(lines); next != null; next = peek(lines)) {
        body += lines.shift()

        if (next.length < 64) {
            break
        }
    }
    return body
}

function peek<T>(arr: Array<T>): T | undefined {
    return arr[0]
}
