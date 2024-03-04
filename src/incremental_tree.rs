use alloc::{vec, vec::Vec};
use alloy_primitives::{keccak256, B256};

#[derive(Debug)]
pub enum IncrementalMerkleTreeError {
    ///  When tree is full and cannot add more leaves
    TreeFull,
    /// Not terminate at most height
    LoopDidNotTerminate,
    /// Index out of bound.
    IndexOutOfBounds,
}

/// [IncrementalMerketTree] is an append-only merkle tree of 
/// generic height, using `keccak256` as the hash function

pub struct IncrementalMerkleTree<const HEIGHT: usize>{
    /// The zero hashes
    zero_hashes: [B256; HEIGHT],
    /// The active branch of the tree, used to calculate the root hash 
    active_branch: [B256; HEIGHT], 
    /// The number of leaves that have been added to the tree
    size: usize,
    /// The intermediate cache for the tree, indexed by `generalized_index + 1`. The intermediates are
    /// only valid if `cache_valid` is true.
    intermediates: Vec<B256>,
    /// Signals whether the intermediate cache is valid. Cache Validation is global, and all levels above 
    /// the leaves will be recomputed during proof generation if it is invalid.
    cache_valid: bool,
}