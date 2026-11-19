import { deepStrictEqual } from "node:assert";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { decrypt, encrypt } from "../src/index.js";
import { payload, vectors } from "./fixtures.js";

const temp = await mkdtemp(join(tmpdir(), "tlock-go-"));
const reference = join(
  temp,
  process.platform === "win32" ? "tlock.exe" : "tlock",
);
try {
  const build = Bun.spawn(
    ["go", "build", "-mod=readonly", "-o", reference, "."],
    {
      cwd: join(import.meta.dir, "go"),
      stderr: "inherit",
    },
  );
  if (await build.exited)
    throw new Error("Could not build the Go tlock reference");

  async function run(
    operation: string,
    vector: (typeof vectors)[number],
    input: Uint8Array | string,
  ): Promise<Uint8Array> {
    const proc = Bun.spawn([reference, operation, JSON.stringify(vector)], {
      stdin: new Response(
        input instanceof Uint8Array ? new Uint8Array(input) : input,
      ),
      stdout: "pipe",
      stderr: "inherit",
    });
    const result = await new Response(proc.stdout).bytes();
    if (await proc.exited)
      throw new Error(`Go ${operation} failed for ${vector.name}`);
    return result;
  }

  for (const vector of vectors) {
    const { chain, beacon } = vector;
    const network = { chain };
    for (const size of [0, 17, 65535, 65536, 65537, 131072, 131073]) {
      const input = payload(size);
      const format = size % 2 ? "armor" : "binary";
      const goCiphertext = await run(
        format === "armor" ? "armor" : "encrypt",
        vector,
        input,
      );
      const ciphertext =
        format === "armor"
          ? new TextDecoder().decode(goCiphertext)
          : goCiphertext;
      deepStrictEqual(await decrypt(ciphertext, { network, beacon }), input);
      deepStrictEqual(
        await run(
          "decrypt",
          vector,
          encrypt(input, { round: beacon.round, network, format }),
        ),
        input,
      );
    }
    console.log(`Verified Go tlock interoperability for ${chain.scheme}`);
  }
} finally {
  await rm(temp, { recursive: true, force: true });
}
