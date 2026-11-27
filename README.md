# BlueSky.sol

[![CI](https://img.shields.io/github/actions/workflow/status/libernet-xyz/bluesky-sol/ci.yml?label=CI)](https://github.com/libernet-xyz/bluesky-sol/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@starkom/bluesky)](https://www.npmjs.com/package/@starkom/bluesky)
[![license](https://img.shields.io/npm/l/@starkom/bluesky)](https://github.com/libernet-xyz/bluesky-sol/blob/main/LICENSE)

## Overview

The Ethereum smartcontracts in this module implement the [BlueSky prime field][bluesky] used in
Starkom and several Poseidon instances over the same field:

- Poseidon1 with state widths T=3, T=4, and T=5, each with both the x^5 and the x^7 S-box;
- Poseidon2 with state widths T=3 and T=4, both with the x^5 S-box.

Every instance is an external library that must be deployed on its own and linked by its users.

[bluesky]: https://crates.io/crates/starkom-bluesky
