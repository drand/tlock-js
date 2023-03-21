# tlock-js

A typescript library for encrypting data which can only be decrypted at a set time in the future using [drand](https://drand.love).  
tlock-js uses [AGE](https://age-encryption.org/v1) to symmetrically encrypt a payload, and encrypts the symmetric key using [pairing-based cryptography](https://drand.love/docs/cryptography/#pairing-based-cryptography) ensuring that it can only be decrypted when the drand's [threshold network](https://drand.love/docs/cryptography/#randomness-generation) has generated randomness at a future point.

## Prerequisites
- Node 16+
- a browser that supports bigint (which is most of them - [see here](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt) )
 
## Quickstart
- install the dependencies by running `npm install`
- compile the code with `npm run compile`
- run the tests with `npm test`
- run the linter and fix the problems by running `npm run lint:fix`

## Using it as a library
- install the latest version using `npm install tlock-js`
- install the drand client using `npm install drand-client`

Note: early versions of node may need to pull in a `fetch` polyfill; versions 17+ have `fetch` already, but it may be behind the `--experimental-modules` flag.

### Test our Web demo

We have a [live web-demo](https://timevault.drand.love/) relying on this library to allow you to test Timelock encryption/decryption directly in your browser now by [visiting Timevault](https://timevault.drand.love/).
Everything is done locally in your browser and it only fetches the drand beacons it needs to decrypt your ciphertexts, nothing else, no logging, no nothing.

## API
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
- vite users may need to set their build target to "es2020" with a config such as:
 ```javascript
export default {
    build: { target: "es2020" },
    optimizeDeps: {
        esbuildOptions: { target: "es2020", supported: { bigint: true } },
    },
};
```

### npm packaging
The github actions create a `dist` folder and move the package.json and some other bits in order to do some packaging, thus running `npm pack` in the root dir will not give the expected results. Similarly, the `main`, `module` and `types` keys in the `package.json` are relative to the `dist` dir.

---

## Get in touch

- [Open an issue](https://github.com/drand/tlock-js/issues/new/choose) for feature requests or to report a bug.
- [Join the drand Slack](https://join.slack.com/t/drandworkspace/shared_invite/zt-19u4rf6if-bf7lxIvF2zYn4~TrBwfkiA) to discuss Timelock, randomness beacons and more.
- Follow the [drand blog](https://drand.love/blog/) for our articles.
- Follow the [@drand_loe](https://twitter.com/drand_loe) account on Twitter to stay tuned.

---

## License

This project is licensed using the [Permissive License Stack](https://protocol.ai/blog/announcing-the-permissive-license-stack/) which means that all contributions are available under the most permissive commonly-used licenses, and dependent projects can pick the license that best suits them.

Therefore, the project is dual-licensed under Apache 2.0 and MIT terms:

- Apache License, Version 2.0, ([LICENSE-APACHE](https://github.com/drand/timevault/blob/master/LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](https://github.com/drand/timevault/blob/master/LICENSE-MIT) or http://opensource.org/licenses/MIT)
