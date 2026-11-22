// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.34;

import "../Poseidon1.sol";

/// @dev Merkle lookups in Sparse Merkle Trees hashed with the Poseidon1 sponge, to test the sponge
///   in a realistic use and measure its cost. It must be linked with `Poseidon1T4X7` and
///   `Poseidon1T5X7`.
///
///   The trees are those of `tools/poseidon1/src/bin/merkle.rs`: the leaves are at level 0, and
///   every inner node at level `l` is the `hash0` of its children, which it picks by the digit
///   `l - 1` of the key in base 2 or 3, with the two domain separator tags `dst`.
///
///   The children fill the rate exactly, so every `hash0` is a single permutation of the children
///   followed by the tags, and the hash is the first element of the output. The functions call
///   `permute` directly, without the checks of `hash0`: non-canonical values and siblings are
///   reduced modulo p by the permutation, so they alias canonical ones.
contract MerkleHarness {
  /// @dev Returns the root of the binary tree whose leaf at `key` is `value`, given the sibling of
  ///   every node of its path from the leaf up. Every inner node is hashed with `Poseidon1T4X7`.
  function computeBinaryRoot(
    uint256[2] calldata dst,
    uint256 key,
    uint256 value,
    uint256[] calldata siblings
  ) external pure returns (uint256 node) {
    // The permutation runs in the library's own memory, so the tags in the capacity stay put.
    uint256[4] memory state;
    state[2] = dst[0];
    state[3] = dst[1];
    node = value;
    for (uint256 level = 0; level < siblings.length; level++) {
      if ((key >> level) & 1 == 0) {
        state[0] = node;
        state[1] = siblings[level];
      } else {
        state[0] = siblings[level];
        state[1] = node;
      }
      node = Poseidon1T4X7.permute(state)[0];
    }
  }

  /// @dev Returns the root of the ternary tree whose leaf at `key` is `value`, given the two
  ///   siblings of every node of its path from the leaf up, in order. Every inner node is hashed
  ///   with `Poseidon1T5X7`.
  function computeTernaryRoot(
    uint256[2] calldata dst,
    uint256 key,
    uint256 value,
    uint256[2][] calldata siblings
  ) external pure returns (uint256 node) {
    // The permutation runs in the library's own memory, so the tags in the capacity stay put.
    uint256[5] memory state;
    state[3] = dst[0];
    state[4] = dst[1];
    node = value;
    for (uint256 level = 0; level < siblings.length; level++) {
      uint256 trit = key % 3;
      key /= 3;
      // The node goes to position `trit` and its siblings fill the other two in order.
      state[0] = trit == 0 ? node : siblings[level][0];
      state[1] = trit == 1 ? node : siblings[level][trit == 0 ? 0 : 1];
      state[2] = trit == 2 ? node : siblings[level][1];
      node = Poseidon1T5X7.permute(state)[0];
    }
  }
}
