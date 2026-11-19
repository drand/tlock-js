export type Scheme =
  "bls-unchained-g1-rfc9380" | "bls-unchained-on-g1" | "pedersen-bls-unchained";

export type Chain = Readonly<{
  hash: string;
  publicKey: string;
  scheme: Scheme;
  genesisTime: number;
  period: number;
}>;

export type Beacon = Readonly<{
  round: number;
  signature: string;
  randomness?: string;
}>;

export type BeaconSource =
  | { readonly url: string; readonly api?: "v1" | "v2" }
  | { get(round: number): Promise<Beacon> };

export type Network = Readonly<{
  chain: Chain;
  source?: BeaconSource;
}>;

export type CiphertextInfo = Readonly<{
  format: "binary" | "armor";
  recipients: readonly Readonly<{ round: number; chainHash: string }>[];
}>;

export type EncryptOptions = (
  | { round: number; unlockTime?: never }
  | { unlockTime: number | Date; round?: never }
) & { network?: Network };

export type DecryptOptions = {
  network?: Network;
  beacon?: Beacon;
};

export type ErrorCode =
  | "INVALID_ROUND"
  | "INVALID_TIME"
  | "INVALID_NETWORK"
  | "NETWORK_MISMATCH"
  | "INVALID_CIPHERTEXT"
  | "AUTHENTICATION_FAILED"
  | "ROUND_NOT_READY"
  | "BEACON_UNAVAILABLE"
  | "INVALID_BEACON";

export class TlockError extends Error {
  override readonly name = "TlockError";
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.code = code;
  }
}
