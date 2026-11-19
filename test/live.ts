import { deepStrictEqual } from "node:assert";
import { decrypt, encrypt, quicknet } from "../src/index.js";
import { quicknetBeacon } from "./fixtures.js";

const plaintext = new TextEncoder().encode("Quicknet live smoke test");
const ciphertext = encrypt(plaintext, {
  round: quicknetBeacon.round,
  format: "armor",
});
for (const api of ["v1", "v2"] as const) {
  const network = {
    chain: quicknet.chain,
    source: { url: "https://api.drand.sh", api },
  };
  deepStrictEqual(await decrypt(ciphertext, { network }), plaintext);
  console.log(`Verified live Quicknet via drand HTTP ${api}`);
}
