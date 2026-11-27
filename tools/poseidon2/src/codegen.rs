// Copyright 2026 The Libernet Team
// SPDX-License-Identifier: Apache-2.0

//! Generates `contracts/Poseidon2.sol`: the Poseidon2 permutations over BlueSky supported by the
//! Solidity library, each one in its own library together with the sponge built on it.
//!
//! The round constants, the external and internal matrices, and the number of rounds come from the
//! configurations of the `starkom-poseidon2` crate, so the generated permutations match the Rust
//! ones by construction. The matrices aren't multiplied entry by entry but with the cheaper
//! formulas that their Poseidon2 structure allows (see `LinearLayer`), and the generator panics if
//! a matrix doesn't have one of the supported structures.
//!
//! The output isn't formatted: run `npm run codegen:poseidon2` from the root of the repository,
//! which writes it to `contracts/Poseidon2.sol` and formats it with prettier.

use starkom_bluesky::{Scalar, from_const};
use starkom_ff::Field;
use starkom_poseidon2::{BlueSkyConfig3, BlueSkyConfig4, Config};

/// The BlueSky prime p.
const MODULUS: &str = "0x7ffffffffffffffffffffffffffffffe0673ddf29e9b5547c000000000000001";

/// The 4x4 matrix M4 of the Poseidon2 paper, row after row. It's the external matrix for T=4.
const M4: [u64; 16] = [5, 7, 1, 3, 4, 6, 1, 1, 1, 3, 5, 7, 1, 1, 4, 6];

/// The parameters of a Poseidon2 permutation, as defined by a `starkom-poseidon2` configuration.
struct Parameters {
    /// The name of the configuration in the `starkom-poseidon2` crate.
    config_name: &'static str,
    /// The state width T.
    width: usize,
    /// The S-box exponent.
    alpha: usize,
    /// The number of full rounds on each side.
    full_rounds_per_side: usize,
    /// The number of partial rounds.
    partial_rounds: usize,
    /// The round constants, `width` per round, round after round. The partial rounds only use the
    /// first one of theirs.
    round_constants: &'static [Scalar],
    /// The matrix of the full rounds and of the initial linear layer, row after row.
    external_matrix: &'static [Scalar],
    /// The matrix of the partial rounds, row after row.
    internal_matrix: &'static [Scalar],
}

impl Parameters {
    fn of<C: Config<Scalar, T>, const T: usize>(config_name: &'static str) -> Self {
        let parameters = Self {
            config_name,
            width: T,
            alpha: C::alpha(),
            full_rounds_per_side: C::num_full_rounds_per_side(),
            partial_rounds: C::num_partial_rounds(),
            round_constants: C::get_round_constants(),
            external_matrix: C::get_external_matrix(),
            internal_matrix: C::get_internal_matrix(),
        };
        assert_eq!(
            parameters.round_constants.len(),
            parameters.num_rounds() * T
        );
        assert_eq!(parameters.external_matrix.len(), T * T);
        assert_eq!(parameters.internal_matrix.len(), T * T);
        parameters
    }

    fn num_rounds(&self) -> usize {
        self.full_rounds_per_side * 2 + self.partial_rounds
    }

    /// The suffix that identifies the permutation in Solidity names, e.g. `T3X5`.
    fn suffix(&self) -> String {
        format!("T{}X{}", self.width, self.alpha)
    }

    fn library_name(&self) -> String {
        format!("Poseidon2{}", self.suffix())
    }

    /// The names of the state variables, e.g. `s0, s1, s2`.
    fn variables(&self, prefix: &str) -> String {
        (0..self.width)
            .map(|i| format!("{prefix}{i}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn is_full_round(&self, round: usize) -> bool {
        round < self.full_rounds_per_side
            || round >= self.full_rounds_per_side + self.partial_rounds
    }
}

/// The structure of a Poseidon2 matrix, which determines how the generated code multiplies the
/// state by it.
enum LinearLayer {
    /// The matrix is J + D, where J is the all-ones matrix and D is the diagonal matrix with these
    /// entries, so the i-th element of the product is the sum of the state plus D_i times the i-th
    /// element. That's the structure of every internal matrix and of the external matrix for T=3,
    /// circ(2, 1, 1) = J + I.
    SumPlusDiagonal(Vec<Scalar>),
    /// The matrix is `M4`.
    M4,
}

impl LinearLayer {
    /// Returns the structure of `matrix`, panicking if it's not supported.
    fn of(matrix: &[Scalar], width: usize) -> Self {
        let off_diagonal_ones =
            (0..width).all(|i| (0..width).all(|j| i == j || matrix[i * width + j] == Scalar::ONE));
        if off_diagonal_ones {
            return Self::SumPlusDiagonal(
                (0..width)
                    .map(|i| matrix[i * width + i] - Scalar::ONE)
                    .collect(),
            );
        }
        assert!(
            matrix == M4.map(from_const),
            "the matrix is neither J + D nor M4"
        );
        Self::M4
    }
}

/// Generates the Yul block that replaces `variable` with `(variable + constant)^alpha`, with the
/// left-to-right square-and-multiply method over the bits of `alpha` after the leading one.
fn sbox(variable: &str, constant: &Scalar, alpha: usize) -> String {
    assert!(alpha >= 2);
    let mut lines = vec![format!("let x := addmod({variable}, {constant}, p)")];
    // The first squaring reads `x`, every other operation reads the partial power in `variable`.
    let mut base = "x";
    let num_bits = usize::BITS - alpha.leading_zeros();
    for bit in (0..(num_bits - 1)).rev() {
        lines.push(format!("{variable} := mulmod({base}, {base}, p)"));
        base = variable;
        if (alpha >> bit) & 1 == 1 {
            lines.push(format!("{variable} := mulmod({variable}, x, p)"));
        }
    }
    format!("{{\n{}\n}}\n", lines.join("\n"))
}

/// Generates the Yul function `name` that multiplies the state by `matrix`, the `description`
/// matrix.
fn linear_function(
    parameters: &Parameters,
    name: &str,
    description: &str,
    matrix: &[Scalar],
) -> String {
    let width = parameters.width;
    let mut code = format!(
        "// Multiplies the state by the {description}.\n\
         function {name}({}) -> {} {{\n\
         let p := {MODULUS}\n",
        parameters.variables("s"),
        parameters.variables("n"),
    );
    match LinearLayer::of(matrix, width) {
        LinearLayer::SumPlusDiagonal(diagonal) => {
            code += "let sum := addmod(s0, s1, p)\n";
            for i in 2..width {
                code += &format!("sum := addmod(sum, s{i}, p)\n");
            }
            for (i, entry) in diagonal.iter().enumerate() {
                if *entry == Scalar::ONE {
                    code += &format!("n{i} := addmod(s{i}, sum, p)\n");
                } else {
                    code += &format!("n{i} := addmod(mulmod(s{i}, {entry}, p), sum, p)\n");
                }
            }
        }
        LinearLayer::M4 => {
            code += "// The addition chain of the Poseidon2 paper for M4.\n\
                     let t0 := addmod(s0, s1, p)\n\
                     let t1 := addmod(s2, s3, p)\n\
                     let t2 := addmod(mulmod(s1, 2, p), t1, p)\n\
                     let t3 := addmod(mulmod(s3, 2, p), t0, p)\n\
                     n3 := addmod(mulmod(t1, 4, p), t3, p)\n\
                     n1 := addmod(mulmod(t0, 4, p), t2, p)\n\
                     n0 := addmod(t3, n1, p)\n\
                     n2 := addmod(t2, n3, p)\n";
        }
    }
    code + "}\n"
}

fn permutation_library(parameters: &Parameters) -> String {
    let width = parameters.width;
    let full = parameters.full_rounds_per_side;
    let partial = parameters.partial_rounds;
    let state = parameters.variables("s");
    let mut body = String::new();
    body += &linear_function(
        parameters,
        "externalLinear",
        "external matrix",
        parameters.external_matrix,
    );
    body += &linear_function(
        parameters,
        "internalLinear",
        "internal matrix",
        parameters.internal_matrix,
    );
    body += &format!("let p := {MODULUS}\n");
    for i in 0..width {
        body += &format!("let s{i} := mload(add(state, {:#x}))\n", i * 32);
    }
    body += "// Initial linear layer.\n";
    body += &format!("{state} := externalLinear({state})\n");
    for round in 0..parameters.num_rounds() {
        if parameters.is_full_round(round) {
            body += &format!("// Round {round} (full).\n");
            for i in 0..width {
                let constant = &parameters.round_constants[round * width + i];
                body += &sbox(&format!("s{i}"), constant, parameters.alpha);
            }
            body += &format!("{state} := externalLinear({state})\n");
        } else {
            body += &format!("// Round {round} (partial).\n");
            let constant = &parameters.round_constants[round * width];
            body += &sbox("s0", constant, parameters.alpha);
            body += &format!("{state} := internalLinear({state})\n");
        }
    }
    for i in 0..width {
        body += &format!("mstore(add(state, {:#x}), s{i})\n", i * 32);
    }
    format!(
        r#"/// @title {library}
/// @notice The Poseidon2 permutation over BlueSky with state width {width} and S-box x^{alpha}, and
///   the sponge built on it.
/// @dev Matches `permutation::<{config}, Scalar, {width}>`, `hash`, and `hash0` of the
///   `starkom-poseidon2` crate.
/// @dev The round constants and the matrices are hard-coded rather than stored, but they take a
///   significant share of the contract size limit, so this library must be deployed on its own and
///   linked by its users, which call its functions with `DELEGATECALL`. The sponge functions are
///   in the same library so that they call the permutation internally rather than with a
///   `DELEGATECALL` per block.
library {library} {{
  /// @dev Reverted when the capacity, i.e. the number of domain separator tags, is not less than
  ///   the state width, so that there's no room for the inputs.
  error InvalidCapacity(uint256 capacity, uint256 width);

  /// @dev Reverted when there are no inputs to hash.
  error EmptyInput();

  /// @dev Reverted when an input or a domain separator tag is not a canonical field element,
  ///   i.e. it's not in [0, p).
  error NonCanonicalInput(uint256 value);

  /// @dev The BlueSky prime p.
  uint256 private constant P = {MODULUS};

  /// @notice Applies the permutation to a state.
  /// @dev The state is first multiplied by the external matrix, then there are {full} full rounds, {partial}
  ///   partial rounds, and {full} more full rounds. Every full round adds its {width} round constants, applies
  ///   the S-box to every element, and multiplies the state by the external matrix. Every partial
  ///   round adds its round constant to the first element only, applies the S-box to it, and
  ///   multiplies the state by the internal matrix.
  ///
  ///   The function is public rather than external so that the sponge functions can call it
  ///   internally.
  /// @param state The state, every element in [0, p). Elements outside the range are reduced
  ///   modulo p by the first multiplication by the external matrix, so they alias canonical ones.
  /// @return The permuted state, every element in [0, p).
  function permute(
    uint256[{width}] memory state
  ) public pure returns (uint256[{width}] memory) {{
    assembly ("memory-safe") {{
{body}    }}
    return state;
  }}

  /// @notice Hashes `inputs` with the sponge, returning the whole rate.
  /// @dev Matches `hash::<{config}, Scalar, {width}, R, C>`. The domain separator tags `dst`
  ///   initialize the capacity elements state[R..{width}], so the capacity is C = dst.length and the
  ///   rate is R = {width} - C. The inputs are absorbed R at a time by adding them to state[0..R],
  ///   and the state is permuted after every block, the last one included. The output is
  ///   state[0..R] after the last permutation.
  /// @dev WARNING: the last block is implicitly padded with zeros, so for example with rate 3 the
  ///   inputs [1, 2] and [1, 2, 0] collide. That's fine for inputs whose length is fixed by the
  ///   protocol, but otherwise the length must be prepended to the inputs. Also note that a zero
  ///   capacity leaves no security margin, so protocols should use at least one tag.
  /// @param dst The domain separator tags, which initialize the capacity elements. Their number
  ///   is the capacity C, which must be less than {width}. Every tag must be in [0, p).
  /// @param inputs The inputs, every one in [0, p). There must be at least one.
  /// @return output The R = {width} - C elements of the rate after the last permutation.
  function hash(
    uint256[] calldata dst,
    uint256[] calldata inputs
  ) external pure returns (uint256[] memory output) {{
    (uint256[{width}] memory state, uint256 rate) = _absorb(dst, inputs);
    output = new uint256[](rate);
    for (uint256 i = 0; i < rate; i++) {{
      output[i] = state[i];
    }}
  }}

  /// @notice Hashes `inputs` with the sponge, returning the first element of the rate (see `hash`).
  /// @dev Matches `hash0::<{config}, Scalar, {width}, R, C>`.
  function hash0(
    uint256[] calldata dst,
    uint256[] calldata inputs
  ) external pure returns (uint256) {{
    (uint256[{width}] memory state, ) = _absorb(dst, inputs);
    return state[0];
  }}

  /// @dev Checks the arguments of a hash, reverting if they're invalid, and absorbs `inputs` into
  ///   a state whose capacity is initialized with `dst`. Returns the final state and the rate.
  function _absorb(
    uint256[] calldata dst,
    uint256[] calldata inputs
  ) private pure returns (uint256[{width}] memory state, uint256 rate) {{
    rate = _rate(dst, inputs);
    for (uint256 i = 0; i < dst.length; i++) {{
      state[rate + i] = dst[i];
    }}
    for (uint256 offset = 0; offset < inputs.length; offset += rate) {{
      for (uint256 i = 0; i < rate && offset + i < inputs.length; i++) {{
        state[i] = addmod(state[i], inputs[offset + i], P);
      }}
      state = permute(state);
    }}
  }}

  /// @dev Checks the arguments of a hash, reverting if they're invalid, and returns its rate.
  function _rate(
    uint256[] calldata dst,
    uint256[] calldata inputs
  ) private pure returns (uint256) {{
    if (dst.length >= {width}) {{
      revert InvalidCapacity(dst.length, {width});
    }}
    if (inputs.length == 0) {{
      revert EmptyInput();
    }}
    for (uint256 i = 0; i < dst.length; i++) {{
      _checkCanonical(dst[i]);
    }}
    for (uint256 i = 0; i < inputs.length; i++) {{
      _checkCanonical(inputs[i]);
    }}
    return {width} - dst.length;
  }}

  /// @dev Reverts if `value` is not a canonical field element.
  function _checkCanonical(uint256 value) private pure {{
    if (value >= P) {{
      revert NonCanonicalInput(value);
    }}
  }}
}}
"#,
        library = parameters.library_name(),
        width = width,
        alpha = parameters.alpha,
        config = parameters.config_name,
        full = full,
        partial = partial,
        body = body,
    )
}

fn main() {
    let permutations = [
        Parameters::of::<BlueSkyConfig3, 3>("BlueSkyConfig3"),
        Parameters::of::<BlueSkyConfig4, 4>("BlueSkyConfig4"),
    ];
    print!(
        r#"// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.34;

// Generated by `tools/poseidon2` (`npm run codegen:poseidon2`) from the parameters of the
// `starkom-poseidon2` crate. Don't edit it by hand.

"#
    );
    let libraries: Vec<String> = permutations.iter().map(permutation_library).collect();
    print!("{}", libraries.join("\n"));
}
