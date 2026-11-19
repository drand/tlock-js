import { deepStrictEqual } from "node:assert";
import { access, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { quicknet } from "../src/index.js";
import { quicknetBeacon } from "./fixtures.js";

const root = join(import.meta.dir, "..");
const temp = await mkdtemp(join(tmpdir(), "tlock-package-"));

async function run(
  command: string[],
  cwd: string,
  timeout = 60_000,
): Promise<string> {
  const subprocess = Bun.spawn(command, {
    cwd,
    stdout: "pipe",
    stderr: "pipe",
    signal: AbortSignal.timeout(timeout),
  });
  const [code, output, errors] = await Promise.all([
    subprocess.exited,
    new Response(subprocess.stdout).text(),
    new Response(subprocess.stderr).text(),
  ]);
  if (code !== 0)
    throw new Error(`${command[0]} exited with ${code}\n${output}\n${errors}`);
  return output.trim();
}

async function findBrowser(): Promise<string> {
  const candidates = [
    process.env.BROWSER_BIN,
    Bun.which("google-chrome"),
    Bun.which("chromium"),
    Bun.which("chromium-browser"),
    process.platform === "win32"
      ? "C:/Program Files/Google/Chrome/Application/chrome.exe"
      : null,
    process.platform === "darwin"
      ? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
      : null,
  ];
  for (const path of candidates) {
    if (
      path &&
      (await access(path).then(
        () => true,
        () => false,
      ))
    )
      return path;
  }
  throw new Error(
    "Chromium or Google Chrome is required for the browser package test",
  );
}

try {
  const tarball = await run(
    ["bun", "pm", "pack", "--quiet", "--destination", temp, "--ignore-scripts"],
    root,
  );
  const packed = await new Bun.Archive(
    Bun.gunzipSync(await Bun.file(tarball).bytes()),
  ).files();
  deepStrictEqual([...packed.keys()].sort(), [
    "package/LICENSE-APACHE",
    "package/LICENSE-MIT",
    "package/dist/index.d.ts",
    "package/dist/index.js",
    "package/dist/types.d.ts",
    "package/package.json",
  ]);
  await Bun.write(
    join(temp, "package.json"),
    JSON.stringify({
      name: "tlock-package-smoke",
      private: true,
      type: "module",
      dependencies: { "tlock-js": `file:./${tarball.split(/[/\\]/).at(-1)}` },
    }),
  );
  await run(["bun", "install", "--ignore-scripts"], temp);

  await Bun.write(
    join(temp, "consumer.ts"),
    `
    import { decrypt, encrypt, inspect, quicknet, roundAt, roundTime, type Beacon } from "tlock-js";
    const beacon: Beacon = ${JSON.stringify(quicknetBeacon)};
    const payload = Uint8Array.of(0, 255, 128, 10, 32);
    const binary: Uint8Array = encrypt(payload, { round: beacon.round });
    const armor: string = encrypt(payload, { round: beacon.round, format: "armor" });
    const online = typeof document === "object";
    const network = { chain: quicknet.chain, source: { url: online ? location.origin : "https://api.drand.sh" } };
    for (const ciphertext of [binary, armor]) {
      const recipient = inspect(ciphertext).recipients[0];
      if (recipient?.round !== beacon.round || recipient.chainHash !== quicknet.chain.hash ||
          roundAt(roundTime(beacon.round)) !== beacon.round) {
        throw new Error("Invalid exported metadata");
      }
      const result = await decrypt(ciphertext, online ? { network } : { beacon });
      if (result.length !== payload.length || !result.every((byte, i) => byte === payload[i])) {
        throw new Error("Unexpected plaintext");
      }
    }
    if (online) document.body.dataset.result = "pass";
  `,
  );
  await run(
    [
      "bun",
      "check",
      "--strict",
      "--module",
      "NodeNext",
      "--moduleResolution",
      "NodeNext",
      "--target",
      "ES2022",
      "--lib",
      "ES2022,DOM",
      "consumer.ts",
    ],
    temp,
  );
  await run(
    [
      "bun",
      "build",
      "./consumer.ts",
      "--target",
      "browser",
      "--packages",
      "external",
      "--outfile",
      "./consumer.mjs",
    ],
    temp,
  );
  const node = process.env.NODE_BIN ?? "node";
  await run([node, "consumer.mjs"], temp);
  await run(
    [
      node,
      "-e",
      `
      try {
        require("tlock-js");
        throw new Error("Unexpected CommonJS entry point");
      } catch (error) {
        if (error.code !== "ERR_PACKAGE_PATH_NOT_EXPORTED") throw error;
      }
    `,
    ],
    temp,
  );
  await run(["bun", "consumer.ts"], temp);
  console.log(
    "Verified installed ESM package and declarations in Node.js and Bun",
  );

  await run(
    [
      "bun",
      "build",
      "./consumer.ts",
      "--target",
      "browser",
      "--format",
      "esm",
      "--outfile",
      "./browser.js",
    ],
    temp,
  );
  const { chain } = quicknet;
  const drand = `/v2/chains/${chain.hash}`;
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    routes: {
      "/": new Response(
        '<!doctype html><title>tlock-js package test</title><script type="module" src="/browser.js"></script>',
        { headers: { "Content-Type": "text/html; charset=utf-8" } },
      ),
      "/browser.js": new Response(Bun.file(join(temp, "browser.js")), {
        headers: { "Content-Type": "text/javascript" },
      }),
      [`${drand}/info`]: Response.json({
        public_key: chain.publicKey,
        chain_hash: chain.hash,
        genesis_time: chain.genesisTime,
        period: chain.period,
        scheme: chain.scheme,
      }),
      [`${drand}/rounds/${quicknetBeacon.round}`]: Response.json({
        round: quicknetBeacon.round,
        signature: quicknetBeacon.signature,
      }),
    },
    fetch: () => new Response(null, { status: 404 }),
  });
  try {
    const result = await run(
      [
        await findBrowser(),
        "--headless",
        "--disable-gpu",
        "--no-first-run",
        "--disable-background-networking",
        `--user-data-dir=${join(temp, "chrome")}`,
        "--virtual-time-budget=8000",
        "--dump-dom",
        server.url.href,
      ],
      temp,
      30_000,
    );
    if (!result.includes('<body data-result="pass">'))
      throw new Error(`Browser did not verify the package\n${result}`);
    console.log("Verified installed ESM package in headless Chromium");
  } finally {
    await server.stop(true);
  }
  const output = process.argv[2];
  if (output) await Bun.write(output, Bun.file(tarball));
} finally {
  await rm(temp, {
    recursive: true,
    force: true,
    maxRetries: 3,
    retryDelay: 150,
  });
}
