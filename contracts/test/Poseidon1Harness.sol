// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.34;

import "../Poseidon1.sol";

/// @dev Thin wrapper exposing the Poseidon1 libraries for testing. It must be linked with the six
///   permutation libraries.
contract Poseidon1Harness {
  function permuteT3X5(uint256[3] memory state) external pure returns (uint256[3] memory) {
    return Poseidon1T3X5.permute(state);
  }

  function permuteT4X5(uint256[4] memory state) external pure returns (uint256[4] memory) {
    return Poseidon1T4X5.permute(state);
  }

  function permuteT5X5(uint256[5] memory state) external pure returns (uint256[5] memory) {
    return Poseidon1T5X5.permute(state);
  }

  function permuteT3X7(uint256[3] memory state) external pure returns (uint256[3] memory) {
    return Poseidon1T3X7.permute(state);
  }

  function permuteT4X7(uint256[4] memory state) external pure returns (uint256[4] memory) {
    return Poseidon1T4X7.permute(state);
  }

  function permuteT5X7(uint256[5] memory state) external pure returns (uint256[5] memory) {
    return Poseidon1T5X7.permute(state);
  }

  function hashT3X5(
    uint256[] memory dst,
    uint256[] memory inputs
  ) external pure returns (uint256[] memory) {
    return Poseidon1T3X5.hash(dst, inputs);
  }

  function hash0T3X5(
    uint256[] memory dst,
    uint256[] memory inputs
  ) external pure returns (uint256) {
    return Poseidon1T3X5.hash0(dst, inputs);
  }

  function hashT4X5(
    uint256[] memory dst,
    uint256[] memory inputs
  ) external pure returns (uint256[] memory) {
    return Poseidon1T4X5.hash(dst, inputs);
  }

  function hash0T4X5(
    uint256[] memory dst,
    uint256[] memory inputs
  ) external pure returns (uint256) {
    return Poseidon1T4X5.hash0(dst, inputs);
  }

  function hashT5X5(
    uint256[] memory dst,
    uint256[] memory inputs
  ) external pure returns (uint256[] memory) {
    return Poseidon1T5X5.hash(dst, inputs);
  }

  function hash0T5X5(
    uint256[] memory dst,
    uint256[] memory inputs
  ) external pure returns (uint256) {
    return Poseidon1T5X5.hash0(dst, inputs);
  }

  function hashT3X7(
    uint256[] memory dst,
    uint256[] memory inputs
  ) external pure returns (uint256[] memory) {
    return Poseidon1T3X7.hash(dst, inputs);
  }

  function hash0T3X7(
    uint256[] memory dst,
    uint256[] memory inputs
  ) external pure returns (uint256) {
    return Poseidon1T3X7.hash0(dst, inputs);
  }

  function hashT4X7(
    uint256[] memory dst,
    uint256[] memory inputs
  ) external pure returns (uint256[] memory) {
    return Poseidon1T4X7.hash(dst, inputs);
  }

  function hash0T4X7(
    uint256[] memory dst,
    uint256[] memory inputs
  ) external pure returns (uint256) {
    return Poseidon1T4X7.hash0(dst, inputs);
  }

  function hashT5X7(
    uint256[] memory dst,
    uint256[] memory inputs
  ) external pure returns (uint256[] memory) {
    return Poseidon1T5X7.hash(dst, inputs);
  }

  function hash0T5X7(
    uint256[] memory dst,
    uint256[] memory inputs
  ) external pure returns (uint256) {
    return Poseidon1T5X7.hash0(dst, inputs);
  }
}
