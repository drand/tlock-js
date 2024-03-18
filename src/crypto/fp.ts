import * as mod from "@noble/curves/abstract/modular"

declare const Fp: Readonly<mod.IField<bigint> & Required<Pick<mod.IField<bigint>, "isOdd">>>;
type Fp = bigint;
type BigintTuple = [bigint, bigint];
type Fp2 = {
    c0: bigint;
    c1: bigint;
};

function fp2FromBigTuple(t: BigintTuple): Fp2 {
    return {
        c0: t[0],
        c1: t[1]
    }
}

declare const Fp2: mod.IField<Fp2>
type BigintSix = [bigint, bigint, bigint, bigint, bigint, bigint]
type Fp6 = {
    c0: Fp2;
    c1: Fp2;
    c2: Fp2;
};

declare const Fp6: mod.IField<Fp6>

function fp6FromBigSix(b: BigintSix): Fp6 {
    return {
        c0: {
            c0: b[0],
            c1: b[1],
        },
        c1: {
            c0: b[2],
            c1: b[3],
        },
        c2: {
            c0: b[4],
            c1: b[5],
        }
    }
}

type Fp12 = {
    c0: Fp6;
    c1: Fp6;
};
type BigintTwelve = [
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
    bigint,
    bigint
];

function fp12FromBigTwelve(b: BigintTwelve): Fp12 {
    return {
        c0: {
            c0: {
                c0: b[0],
                c1: b[1],
            },
            c1: {
                c0: b[2],
                c1: b[3],
            },
            c2: {
                c0: b[4],
                c1: b[5],
            }
        },
        c1: {
            c0: {
                c0: b[6],
                c1: b[7],
            },
            c1: {
                c0: b[8],
                c1: b[9],
            },
            c2: {
                c0: b[10],
                c1: b[11],
            }
        }
    }
}

export {Fp, Fp2, Fp6, Fp12, fp2FromBigTuple, fp6FromBigSix, fp12FromBigTwelve, BigintTwelve}