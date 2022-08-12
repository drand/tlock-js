# tlock-js

A typescript library for encrypting data which can only be decrypted at a set time in the future using [drand](https://drand.love).  
tlock-js uses [AGE](https://age-encryption.org/v1) to symmetrically encrypt a payload, and encrypts the symmetric key using [pairing-based cryptography](https://drand.love/docs/cryptography/#pairing-based-cryptography) ensuring that it can only be decrypted when the drand's [threshold network](https://drand.love/docs/cryptography/#randomness-generation) has generated randomness at a future point.

## Prerequisites
- Node 16+
 
## Quickstart
- install the dependencies by running `npm install`
- run the tests with `npm test`

### `timelockEncrypt` 
This encrypts a payload that can only be decrypted when the `roundNumber` has been reached.  
The time of this `roundNumber` depends on the genesis and round frequency of the network you connect to.
By default, the drand testnet HTTP client will be used, but you can implement your own and pass it in here.
The output ciphertext should be compatible with any of the drand tlock implementations

### `timelockDecrypt`
This takes a payload that has been encrypted with any of the drand tlock implementations, reads the `roundNumber` from it and attempts to decrypt it.
If the round number has not yet been reached by the network, an error will be thrown.
It accepts both armored and unarmored payloads.

### `roundForTime`
Given a `NetworkInfo` object, it calculates what the latest-emitted round will have been at that `time`

### `timeForRound`
Given a `NetworkInfo` object, it calculates the approximate time the given `round` will be emitted at (approximate because the network must work together to create the randomness).

## Possible issues
- you may need a `fetch` polyfill on some versions of node, e.g. [isomorphic fetch](https://www.npmjs.com/package/isomorphic-fetch).  You can provide your own `DrandHttpClientOptions` to the `DrandHttpClient` if you don't want to use fetch, but it may be necessary to declare a fake `fetch` somewhere for compilation


### License

This project is licensed using the [Permissive License Stack](https://protocol.ai/blog/announcing-the-permissive-license-stack/) which means that all contributions are available under the most permissive commonly-used licenses, and dependent projects can pick the license that best suits them.

Therefore, the project is dual-licensed under Apache 2.0 and MIT terms:

- Apache License, Version 2.0, ([LICENSE-APACHE](https://github.com/drand/timevault/blob/master/LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](https://github.com/drand/timevault/blob/master/LICENSE-MIT) or http://opensource.org/licenses/MIT)