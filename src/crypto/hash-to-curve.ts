import {CURVE, Fp, Fp2, PointG2} from "@noble/bls12-381"
import {hexToBytes} from "@noble/hashes/utils"
import {hashToField} from "./hash-to-field"

// this patched `hashToCurve` uses a different implementation of `hashToField` than noble
// see: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16
export async function hashToCurve(input: Uint8Array | string): Promise<PointG2> {
    const message = ensureBytes(input)
    const u = await hashToField(message, 2)
    const Q0 = new PointG2(isogenyMapG2(u[0])[0], map_to_curve_simple_swu_9mod16(u[0])[0])
    const Q1 = new PointG2(isogenyMapG2(u[1])[0], map_to_curve_simple_swu_9mod16(u[1])[0])
    const R = Q0.add(Q1)
    return R.clearCofactor()
}

function ensureBytes(hex: Uint8Array | string) {
    return hex instanceof Uint8Array ? Uint8Array.from(hex) : hexToBytes(hex)
}

function isogenyMapG2(input: [Fp2, Fp2, Fp2] | bigint[]) {
    const xyz = input.map(it => {
        if (Array.isArray(it)) {
            return Fp2.fromBigTuple(it)
        }
        return it
    }) as [Fp2, Fp2, Fp2]
    const x = xyz[0], y = xyz[1], z = xyz[2];
    const zz = z.multiply(z);
    const zzz = zz.multiply(z);
    const zPowers = [z, zz, zzz];
    const mapped = [Fp2.ZERO, Fp2.ZERO, Fp2.ZERO, Fp2.ZERO];
    for (let i = 0; i < ISOGENY_COEFFICIENTS.length; i++) {
        const k_i = ISOGENY_COEFFICIENTS[i];
        mapped[i] = k_i.slice(-1)[0];
        const arr = k_i.slice(0, -1).reverse();
        for (let j = 0; j < arr.length; j++) {
            const k_i_j = arr[j];
            mapped[i] = mapped[i].multiply(x).add(zPowers[j].multiply(k_i_j));
        }
    }
    mapped[2] = mapped[2].multiply(y);
    mapped[3] = mapped[3].multiply(z);
    const z2 = mapped[1].multiply(mapped[3]);
    const x2 = mapped[0].multiply(mapped[3]);
    const y2 = mapped[1].multiply(mapped[2]);
    return [x2, y2, z2];
}

function map_to_curve_simple_swu_9mod16(t: bigint[] | Fp2) {
    const iso_3_a = new Fp2(new Fp(0n), new Fp(240n));
    const iso_3_b = new Fp2(new Fp(1012n), new Fp(1012n));
    const iso_3_z = new Fp2(new Fp(-2n), new Fp(-1n));
    if (Array.isArray(t))
        t = Fp2.fromBigTuple(t);
    const t2 = t.pow(2n);
    const iso_3_z_t2 = iso_3_z.multiply(t2);
    const ztzt = iso_3_z_t2.add(iso_3_z_t2.pow(2n));
    let denominator = iso_3_a.multiply(ztzt).negate();
    let numerator = iso_3_b.multiply(ztzt.add(Fp2.ONE));
    if (denominator.isZero())
        denominator = iso_3_z.multiply(iso_3_a);
    const v = denominator.pow(3n);
    let u = numerator
        .pow(3n)
        .add(iso_3_a.multiply(numerator).multiply(denominator.pow(2n)))
        .add(iso_3_b.multiply(v));
    const {success, sqrtCandidateOrGamma} = sqrt_div_fp2(u, v);
    if (!success) {
        throw new Error("failed to do some division...")
    }
    let y = sqrtCandidateOrGamma
    const sqrtCandidateX1 = sqrtCandidateOrGamma.multiply(t.pow(3n));
    u = iso_3_z_t2.pow(3n).multiply(u);
    let success2 = false;
    FP2_ETAs.forEach((eta) => {
        const etaSqrtCandidate = eta.multiply(sqrtCandidateX1);
        const temp = etaSqrtCandidate.pow(2n).multiply(v).subtract(u);
        if (temp.isZero() && !success && !success2) {
            y = etaSqrtCandidate;
            success2 = true;
        }
    });
    if (!success && !success2)
        throw new Error('Hash to Curve - Optimized SWU failure');
    if (success2)
        numerator = numerator.multiply(iso_3_z_t2);
    if (sgn0(t) !== sgn0(y))
        y = y.negate();
    y = y.multiply(denominator);
    return [numerator, y, denominator];
}

function sgn0(x: Fp2) {
    const {re: x0, im: x1} = x.reim();
    const sign_0 = x0 % 2n;
    const zero_0 = x0 === 0n;
    const sign_1 = x1 % 2n;
    return BigInt(sign_0 || (zero_0 && sign_1));
}

const ev1 = 0x699be3b8c6870965e5bf892ad5d2cc7b0e85a117402dfd83b7f4a947e02d978498255a2aaec0ac627b5afbdf1bf1c90n;
const ev2 = 0x8157cd83046453f5dd0972b6e3949e4288020b5b8a9cc99ca07e27089a2ce2436d965026adad3ef7baba37f2183e9b5n;
const ev3 = 0xab1c2ffdd6c253ca155231eb3e71ba044fd562f6f72bc5bad5ec46a0b7a3b0247cf08ce6c6317f40edbc653a72dee17n;
const ev4 = 0xaa404866706722864480885d68ad0ccac1967c7544b447873cc37e0181271e006df72162a3d3e0287bf597fbf7f8fc1n;
const FP2_ETAs = [
    [ev1, ev2],
    [-ev2, ev1],
    [ev3, ev4],
    [-ev4, ev3],
].map((pair) => Fp2.fromBigTuple(pair));

const P_MINUS_9_DIV_16 = (CURVE.P ** 2n - 9n) / 16n;
const rv1 = 0x6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09n;
const FP2_ROOTS_OF_UNITY = [
    [1n, 0n],
    [rv1, -rv1],
    [0n, 1n],
    [rv1, rv1],
    [-1n, 0n],
    [-rv1, rv1],
    [0n, -1n],
    [-rv1, -rv1],
].map((pair) => Fp2.fromBigTuple(pair));

function sqrt_div_fp2(u: Fp2, v: Fp2) {
    const v7 = v.pow(7n);
    const uv7 = u.multiply(v7);
    const uv15 = uv7.multiply(v7.multiply(v));
    const gamma = uv15.pow(P_MINUS_9_DIV_16).multiply(uv7);
    let success = false;
    let result = gamma;
    const positiveRootsOfUnity = FP2_ROOTS_OF_UNITY.slice(0, 4);
    positiveRootsOfUnity.forEach((root) => {
        const candidate = root.multiply(gamma);
        if (candidate.pow(2n).multiply(v).subtract(u).isZero() && !success) {
            success = true;
            result = candidate;
        }
    });
    return {success, sqrtCandidateOrGamma: result};
}


const xnum = [
    [
        0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6n,
        0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6n,
    ],
    [
        0x0n,
        0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71an,
    ],
    [
        0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71en,
        0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38dn,
    ],
    [
        0x171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1n,
        0x0n,
    ],
].map((pair) => Fp2.fromBigTuple(pair));
const xden = [
    [
        0x0n,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63n,
    ],
    [
        0xcn,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9fn,
    ],
    [0x1n, 0x0n],
    [0x0n, 0x0n],
].map((pair) => Fp2.fromBigTuple(pair));
const ynum = [
    [
        0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706n,
        0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706n,
    ],
    [
        0x0n,
        0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97ben,
    ],
    [
        0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71cn,
        0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38fn,
    ],
    [
        0x124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10n,
        0x0n,
    ],
].map((pair) => Fp2.fromBigTuple(pair));
const yden = [
    [
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fbn,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fbn,
    ],
    [
        0x0n,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3n,
    ],
    [
        0x12n,
        0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99n,
    ],
    [0x1n, 0x0n],
].map((pair) => Fp2.fromBigTuple(pair));
const ISOGENY_COEFFICIENTS = [xnum, xden, ynum, yden];
