// Copyright 2026 The Libernet Team
// SPDX-License-Identifier: Apache-2.0

//! Generates the Poseidon2 test vectors for the Solidity library using the reference Rust
//! implementation in the `starkom-poseidon2` crate.
//!
//! Every field element is a 0x-prefixed hex string.
//!
//! The output isn't formatted: run `npm run vectors:poseidon2` from the root of the repository,
//! which writes it to `test/vectors/poseidon2.json` and formats it with prettier.

use serde::Serialize;
use starkom_bluesky::{Scalar, from_const};
use starkom_ff::Field;
use starkom_poseidon2::{BlueSkyConfig3, BlueSkyConfig4, Config};

/// A permutation test case.
#[derive(Serialize)]
struct PermutationCase {
    width: usize,
    alpha: usize,
    input: Vec<String>,
    output: Vec<String>,
}

/// A sponge test case.
#[derive(Serialize)]
struct HashCase {
    width: usize,
    alpha: usize,
    dst: Vec<String>,
    inputs: Vec<String>,
    output: Vec<String>,
}

#[derive(Serialize)]
struct Vectors {
    permutations: Vec<PermutationCase>,
    hashes: Vec<HashCase>,
}

fn hex(values: &[Scalar]) -> Vec<String> {
    values.iter().map(Scalar::to_string).collect()
}

/// The largest field element, p - 1.
fn max() -> Scalar {
    Scalar::ZERO - Scalar::ONE
}

/// Permutes the inputs [0, 1, ..., T - 1] like the `starkom-poseidon2` unit tests, all equal to
/// p - 1, and some larger distinct values.
fn permutation_cases<Cfg: Config<Scalar, T>, const T: usize>(cases: &mut Vec<PermutationCase>) {
    let inputs: [[Scalar; T]; 3] = [
        std::array::from_fn(|i| from_const(i as u64)),
        [max(); T],
        std::array::from_fn(|i| max() - from_const(1_000_003 * (i as u64 + 1))),
    ];
    for input in inputs {
        let output = starkom_poseidon2::permutation::<Cfg, Scalar, T>(input);
        cases.push(PermutationCase {
            width: T,
            alpha: Cfg::alpha(),
            input: hex(&input),
            output: hex(&output),
        });
    }
}

/// Hashes 1 to 2R + 1 inputs (partial, full, and multiple blocks) with capacity C, plus R + 1
/// inputs close to p with domain separator tags close to p.
fn hash_cases<Cfg: Config<Scalar, T>, const T: usize, const R: usize, const C: usize>(
    cases: &mut Vec<HashCase>,
) {
    let small_dst: [Scalar; C] = std::array::from_fn(|i| from_const(7 + i as u64));
    let large_dst: [Scalar; C] = std::array::from_fn(|i| max() - from_const(i as u64));
    let mut add_case = |dst: [Scalar; C], inputs: Vec<Scalar>| {
        let output = starkom_poseidon2::hash::<Cfg, Scalar, T, R, C>(dst, inputs.iter().copied());
        cases.push(HashCase {
            width: T,
            alpha: Cfg::alpha(),
            dst: hex(&dst),
            inputs: hex(&inputs),
            output: hex(&output),
        });
    };
    for length in 1..=(2 * R + 1) {
        add_case(
            small_dst,
            (0..length).map(|i| from_const(10 + i as u64)).collect(),
        );
    }
    add_case(
        large_dst,
        (0..(R + 1)).map(|i| max() - from_const(i as u64)).collect(),
    );
}

fn main() {
    let mut permutations = vec![];
    permutation_cases::<BlueSkyConfig3, 3>(&mut permutations);
    permutation_cases::<BlueSkyConfig4, 4>(&mut permutations);

    let mut hashes = vec![];
    hash_cases::<BlueSkyConfig3, 3, 3, 0>(&mut hashes);
    hash_cases::<BlueSkyConfig3, 3, 2, 1>(&mut hashes);
    hash_cases::<BlueSkyConfig3, 3, 1, 2>(&mut hashes);
    hash_cases::<BlueSkyConfig4, 4, 4, 0>(&mut hashes);
    hash_cases::<BlueSkyConfig4, 4, 3, 1>(&mut hashes);
    hash_cases::<BlueSkyConfig4, 4, 2, 2>(&mut hashes);
    hash_cases::<BlueSkyConfig4, 4, 1, 3>(&mut hashes);

    let vectors = Vectors {
        permutations,
        hashes,
    };
    println!("{}", serde_json::to_string(&vectors).unwrap());
}
