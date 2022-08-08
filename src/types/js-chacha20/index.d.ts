declare module "js-chacha20" {
    export default class {
        constructor(key: Uint8Array, nonce: Uint8Array)

        encrypt(message: Uint8Array): Uint8Array

        decrypt(message: Uint8Array): Uint8Array
    }
}
