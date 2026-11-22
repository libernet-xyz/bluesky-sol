// Copyright 2026 The Libernet Team
// SPDX-License-Identifier: Apache-2.0

//! Generates `contracts/Poseidon1.sol`: the Poseidon1 permutations over BlueSky supported by the
//! Solidity library, each one in its own library together with the sponge built on it.
//!
//! The round constants, the MDS matrices, and the number of rounds come from the configurations of
//! the `starkom-poseidon` crate, so the generated permutations match the Rust ones by construction.
//!
//! The output isn't formatted: run `npm run codegen` from the root of the repository, which writes
//! it to `contracts/Poseidon1.sol` and formats it with prettier.

use starkom_bluesky::Scalar;
use starkom_poseidon::{
    BlueSkyConfigT3X5, BlueSkyConfigT3X7, BlueSkyConfigT4X5, BlueSkyConfigT4X7, BlueSkyConfigT5X5,
    BlueSkyConfigT5X7, Config,
};

/// The BlueSky prime p.
const MODULUS: &str = "0x7ffffffffffffffffffffffffffffffe0673ddf29e9b5547c000000000000001";

/// The parameters of a Poseidon1 permutation, as defined by a `starkom-poseidon` configuration.
struct Parameters {
    /// The name of the configuration in the `starkom-poseidon` crate.
    config_name: &'static str,
    /// The state width T.
    width: usize,
    /// The S-box exponent.
    alpha: usize,
    /// The number of full rounds on each side.
    full_rounds_per_side: usize,
    /// The number of partial rounds.
    partial_rounds: usize,
    /// The round constants, `width` per round, round after round.
    round_constants: &'static [Scalar],
    /// The MDS matrix, row after row.
    mds_matrix: &'static [Scalar],
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
            mds_matrix: C::get_mds_matrix(),
        };
        assert_eq!(
            parameters.round_constants.len(),
            parameters.num_rounds() * T
        );
        assert_eq!(parameters.mds_matrix.len(), T * T);
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
        format!("Poseidon1{}", self.suffix())
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

/// Generates the Yul function that multiplies the state by the MDS matrix.
fn mds_function(parameters: &Parameters) -> String {
    let width = parameters.width;
    let mut code = format!(
        "// Multiplies the state by the MDS matrix.\n\
         function mds({}) -> {} {{\n\
         let p := {MODULUS}\n",
        parameters.variables("s"),
        parameters.variables("n"),
    );
    for i in 0..width {
        for j in 0..width {
            let entry = &parameters.mds_matrix[i * width + j];
            if j == 0 {
                code += &format!("n{i} := mulmod(s{j}, {entry}, p)\n");
            } else {
                code += &format!("n{i} := addmod(n{i}, mulmod(s{j}, {entry}, p), p)\n");
            }
        }
    }
    code + "}\n"
}

fn permutation_library(parameters: &Parameters) -> String {
    let width = parameters.width;
    let full = parameters.full_rounds_per_side;
    let partial = parameters.partial_rounds;
    let mut body = String::new();
    body += &mds_function(parameters);
    body += &format!("let p := {MODULUS}\n");
    for i in 0..width {
        body += &format!("let s{i} := mload(add(state, {:#x}))\n", i * 32);
    }
    for round in 0..parameters.num_rounds() {
        let full_round = parameters.is_full_round(round);
        let kind = if full_round { "full" } else { "partial" };
        body += &format!("// Round {round} ({kind}).\n");
        for i in 0..width {
            let constant = &parameters.round_constants[round * width + i];
            if i == 0 || full_round {
                body += &sbox(&format!("s{i}"), constant, parameters.alpha);
            } else {
                body += &format!("s{i} := addmod(s{i}, {constant}, p)\n");
            }
        }
        body += &format!(
            "{} := mds({})\n",
            parameters.variables("s"),
            parameters.variables("s")
        );
    }
    for i in 0..width {
        body += &format!("mstore(add(state, {:#x}), s{i})\n", i * 32);
    }
    format!(
        r#"/// @title {library}
/// @notice The Poseidon1 permutation over BlueSky with state width {width} and S-box x^{alpha}, and
///   the sponge built on it.
/// @dev Matches `permutation::<{config}, Scalar, {width}>`, `hash`, and `hash0` of the
///   `starkom-poseidon` crate.
/// @dev The round constants and the MDS matrix are hard-coded rather than stored, but they take a
///   large share of the contract size limit, so this library must be deployed on its own and
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
  /// @dev There are {full} full rounds, {partial} partial rounds, and {full} more full rounds. Every
  ///   round adds its {width} round constants, applies the S-box to every element (full rounds) or
  ///   only to the first one (partial rounds), and multiplies the state by the MDS matrix.
  ///
  ///   The function is public rather than external so that the sponge functions can call it
  ///   internally.
  /// @param state The state, every element in [0, p). Elements outside the range are reduced
  ///   modulo p by the first round, so they alias canonical ones.
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
  ///   capacity leaves the sponge without security margin, so protocols should use at least one tag.
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
        Parameters::of::<BlueSkyConfigT3X5, 3>("BlueSkyConfigT3X5"),
        Parameters::of::<BlueSkyConfigT4X5, 4>("BlueSkyConfigT4X5"),
        Parameters::of::<BlueSkyConfigT5X5, 5>("BlueSkyConfigT5X5"),
        Parameters::of::<BlueSkyConfigT3X7, 3>("BlueSkyConfigT3X7"),
        Parameters::of::<BlueSkyConfigT4X7, 4>("BlueSkyConfigT4X7"),
        Parameters::of::<BlueSkyConfigT5X7, 5>("BlueSkyConfigT5X7"),
    ];
    print!(
        r#"// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.34;

// Generated by `tools/poseidon1` (`npm run codegen`) from the parameters of the `starkom-poseidon`
// crate. Don't edit it by hand.

"#
    );
    let libraries: Vec<String> = permutations.iter().map(permutation_library).collect();
    print!("{}", libraries.join("\n"));
}
