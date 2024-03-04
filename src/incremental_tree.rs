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