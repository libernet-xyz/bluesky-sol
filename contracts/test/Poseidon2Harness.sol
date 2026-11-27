// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.34;

import "../Poseidon2.sol";

/// @dev Thin wrapper exposing the Poseidon2 libraries for testing. It must be linked with the two
///   permutation libraries.
contract Poseidon2Harness {
  function permuteT3X5(uint256[3] memory state) external pure returns (uint256[3] memory) {
    return Poseidon2T3X5.permute(state);
  }

  function permuteT4X5(uint256[4] memory state) external pure returns (uint256[4] memory) {
    return Poseidon2T4X5.permute(state);
  }

  function hashT3X5(
    uint256[] memory dst,
    uint256[] memory inputs
  ) external pure returns (uint256[] memory) {
    return Poseidon2T3X5.hash(dst, inputs);
  }

  function hash0T3X5(
    uint256[] memory dst,
    uint256[] memory inputs
  ) external pure returns (uint256) {
    return Poseidon2T3X5.hash0(dst, inputs);
  }

  function hashT4X5(
    uint256[] memory dst,
    uint256[] memory inputs
  ) external pure returns (uint256[] memory) {
    return Poseidon2T4X5.hash(dst, inputs);
  }

  function hash0T4X5(
    uint256[] memory dst,
    uint256[] memory inputs
  ) external pure returns (uint256) {
    return Poseidon2T4X5.hash0(dst, inputs);
  }
}
