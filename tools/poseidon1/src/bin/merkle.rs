// Copyright 2026 The Libernet Team
// SPDX-License-Identifier: Apache-2.0

//! Generates the Merkle lookup test vectors for the Solidity library: lookups in binary Sparse
//! Merkle Trees hashed with Poseidon1 T4X7 and in ternary ones hashed with Poseidon1 T5X7, with
//! keys of 256 bits (162 trits) and of 160 bits like Ethereum addresses (102 trits).
//!
//! The trees are built like in the tests of the `merkle` module of `starkom-gadgets`: the leaves
//! are field elements, the empty ones are zero, and every inner node is the `hash0` of its
//! children. Unlike there, the sponge has 2 capacity elements, initialized with the domain
//! separator tags `NODE_DST` and `BINARY_DST` or `TERNARY_DST`. All the trees hold the same
//! entries and the lookups look up the same key.
//!
//! Every field element is a 0x-prefixed hex string.
//!
//! The output isn't formatted: run `npm run vectors:merkle` from the root of the repository, which
//! writes it to `test/vectors/merkle.json` and formats it with prettier.

use primitive_types::{H512, U256};
use serde::Serialize;
use sha3::{Digest, Sha3_512};
use starkom_bluesky::{Scalar, from_const};
use starkom_ff::{Field, Field256};
use starkom_poseidon::{BlueSkyConfigT4X7, BlueSkyConfigT5X7};
use std::rc::Rc;

/// The entries of both trees, as (key, value) pairs.
const ENTRIES: [(u64, u64); 5] = [(12, 34), (34, 56), (56, 78), (78, 90), (90, 12)];

/// The key looked up in both trees.
const KEY: u64 = 56;

/// The heights of the binary trees, i.e. the numbers of bits of their keys.
const BINARY_HEIGHTS: [usize; 2] = [256, 160];

/// The heights of the ternary trees, i.e. the numbers of trits of their keys.
const TERNARY_HEIGHTS: [usize; 2] = [162, 102];

/// The domain separator tag of the inner nodes of all the trees, in the first capacity element.
const NODE_DST: &[u8] = b"libernet/test/merkle/node";

/// The domain separator tag of the binary trees, in the second capacity element.
const BINARY_DST: &[u8] = b"libernet/test/merkle/binary";

/// The domain separator tag of the ternary trees, in the second capacity element.
const TERNARY_DST: &[u8] = b"libernet/test/merkle/ternary";

/// Maps a domain separator tag to a field element like `hash_to_scalar` in the `crypto` and
/// `gadgets` repositories: the SHA3-512 hash, as a little-endian integer, reduced modulo p.
fn hash_to_scalar(message: &[u8]) -> Scalar {
    Scalar::from_h512(H512::from_slice(Sha3_512::digest(message).as_slice()))
}

/// The function that hashes the children of an inner node with the domain separator tags.
type HashChildren<const N: usize> = fn([Scalar; 2], [Scalar; N]) -> Scalar;

fn hash_binary_children(dst: [Scalar; 2], children: [Scalar; 2]) -> Scalar {
    starkom_poseidon::hash0::<BlueSkyConfigT4X7, Scalar, 4, 2, 2>(dst, children)
}

fn hash_ternary_children(dst: [Scalar; 2], children: [Scalar; 3]) -> Scalar {
    starkom_poseidon::hash0::<BlueSkyConfigT5X7, Scalar, 5, 3, 2>(dst, children)
}

/// A node of a Sparse Merkle Tree of arity `N`.
enum Node<const N: usize> {
    Leaf(Scalar),
    Inner {
        hash: Scalar,
        children: [Rc<Node<N>>; N],
    },
}

impl<const N: usize> Node<N> {
    fn hash(&self) -> Scalar {
        match self {
            Node::Leaf(value) => *value,
            Node::Inner { hash, .. } => *hash,
        }
    }
}

/// A persistent Sparse Merkle Tree of arity `N`.
///
/// The leaves are at level 0 and the root is at level `height`. The inner nodes at level `l` pick
/// the child of a key by its digit `l - 1` in base `N`, so the digits are consumed from the least
/// significant one, at the bottom of the tree.
struct Tree<const N: usize> {
    height: usize,
    dst: [Scalar; 2],
    hash_children: HashChildren<N>,
    root: Rc<Node<N>>,
}

impl<const N: usize> Tree<N> {
    /// Returns a tree of the given height whose leaves are all zero.
    fn new(height: usize, dst: [Scalar; 2], hash_children: HashChildren<N>) -> Self {
        let mut node = Rc::new(Node::Leaf(Scalar::ZERO));
        for _ in 0..height {
            node = Self::make_inner(dst, hash_children, std::array::from_fn(|_| node.clone()));
        }
        Self {
            height,
            dst,
            hash_children,
            root: node,
        }
    }

    fn make_inner(
        dst: [Scalar; 2],
        hash_children: HashChildren<N>,
        children: [Rc<Node<N>>; N],
    ) -> Rc<Node<N>> {
        let hash = hash_children(dst, std::array::from_fn(|i| children[i].hash()));
        Rc::new(Node::Inner { hash, children })
    }

    /// Returns the `height` digits of `key` in base `N`, from the least significant one.
    fn digits(&self, key: u64) -> Vec<usize> {
        let mut key = U256::from(key);
        let mut digits = Vec::with_capacity(self.height);
        for _ in 0..self.height {
            digits.push((key % N).as_usize());
            key /= N;
        }
        digits
    }

    fn put(&mut self, key: u64, value: Scalar) {
        let digits = self.digits(key);
        self.root = self.put_impl(&self.root, &digits, value);
    }

    /// Returns `node` with the leaf at `digits` replaced by `value`. The last digit picks the
    /// child of `node`.
    fn put_impl(&self, node: &Rc<Node<N>>, digits: &[usize], value: Scalar) -> Rc<Node<N>> {
        match node.as_ref() {
            Node::Leaf(_) => Rc::new(Node::Leaf(value)),
            Node::Inner { children, .. } => {
                let (&digit, rest) = digits.split_last().unwrap();
                let mut children = children.clone();
                children[digit] = self.put_impl(&children[digit], rest, value);
                Self::make_inner(self.dst, self.hash_children, children)
            }
        }
    }

    /// Returns the value of `key` and the siblings of its path from the leaf up: for every inner
    /// node, the hashes of its children other than the one on the path, in order.
    fn lookup(&self, key: u64) -> (Scalar, Vec<Vec<Scalar>>) {
        let digits = self.digits(key);
        let mut node = &self.root;
        let mut siblings = Vec::with_capacity(self.height);
        for &digit in digits.iter().rev() {
            let Node::Inner { children, .. } = node.as_ref() else {
                panic!("the path is longer than the tree");
            };
            siblings.push(
                (0..N)
                    .filter(|&i| i != digit)
                    .map(|i| children[i].hash())
                    .collect(),
            );
            node = &children[digit];
        }
        siblings.reverse();
        (node.hash(), siblings)
    }
}

/// A Merkle lookup test case.
#[derive(Serialize)]
struct LookupCase {
    height: usize,
    /// The domain separator tags of the inner nodes.
    dst: Vec<String>,
    key: String,
    value: String,
    /// The siblings of the path from the leaf up, `N - 1` per level (see `Tree::lookup`).
    siblings: Vec<Vec<String>>,
    root: String,
}

#[derive(Serialize)]
struct Vectors {
    binary: Vec<LookupCase>,
    ternary: Vec<LookupCase>,
}

fn hex(values: &[Scalar]) -> Vec<String> {
    values.iter().map(Scalar::to_string).collect()
}

/// Builds a tree holding `ENTRIES` and looks up `KEY` in it.
fn lookup_case<const N: usize>(
    height: usize,
    dst: [Scalar; 2],
    hash_children: HashChildren<N>,
) -> LookupCase {
    let mut tree = Tree::new(height, dst, hash_children);
    for (key, value) in ENTRIES {
        tree.put(key, from_const(value));
    }
    let (value, siblings) = tree.lookup(KEY);
    let (_, expected_value) = ENTRIES.iter().find(|(key, _)| *key == KEY).unwrap();
    assert_eq!(value, from_const(*expected_value));
    LookupCase {
        height,
        dst: hex(&dst),
        key: from_const(KEY).to_string(),
        value: value.to_string(),
        siblings: siblings.iter().map(|level| hex(level)).collect(),
        root: tree.root.hash().to_string(),
    }
}

fn main() {
    let node_dst = hash_to_scalar(NODE_DST);
    let binary_dst = [node_dst, hash_to_scalar(BINARY_DST)];
    let ternary_dst = [node_dst, hash_to_scalar(TERNARY_DST)];
    let vectors = Vectors {
        binary: BINARY_HEIGHTS
            .iter()
            .map(|&height| lookup_case(height, binary_dst, hash_binary_children))
            .collect(),
        ternary: TERNARY_HEIGHTS
            .iter()
            .map(|&height| lookup_case(height, ternary_dst, hash_ternary_children))
            .collect(),
    };
    println!("{}", serde_json::to_string(&vectors).unwrap());
}
