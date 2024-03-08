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

impl<const HEIGHT: usize> Default for IncrementalMerkleTree<HEIGHT> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const HEIGHT: usize> IncrementalMerkleTree<HEIGHT> {
    /// Create a new [IncrementalMerkleTree] with a height of `height`. This function precompute the zero hashes
    /// for the tree
    pub fn new() -> Self {
        let mut zero_hashes = [B256::default(); HEIGHT];
        let mut hash_buf = [0u8; 64];
        (1..HEIGHT).for_each(|height| {
            /// copy the first32 bytes of data from `zero_hashes[height-1]` into the first 32 bytes of hash_buf
            /// it is concatinating and generating parent node
            hash_buf[..32].copy_from_slice(zero_hashes[height-1].as_slice());
            /// copy the entire content of `zero_hashes[height-1]` into the second half of 
            /// `hash_buf`, starting from the index 32
            hash_buf[32..].copy_from_slice(zero_hashes[height-1].as_slice());
            /// it  calculates a new hash using `keccak256` and assinge to zero_hashes[height]
            zero_hashes[height] = keccak256(hash_buf);
        });
        // assigned the default value for each element of vector
        // convert the HEIGHT as u32-bit integer
        // `(1 << (HEIGHT as u32 +1)` converts teh variable `HEIGHT` to an unsigned 32-bit integer
        // and subtract the 1 from this result gives the final size of the vector
        let intermediates = vec![B256::default(); (1 << (HEIGHT as u32 +1)) - 1];
        Self {
            zero_hashes, 
            active_branch: [B256::default(); HEIGHT],
            size: 0, 
            intermediates,
            cache_valid:false,
        }
    }
    /// Compute the root hash of the tree from the active branch.
    ///
    /// # Returns
    /// - The root hash of the tree.
    pub fn root(&self) -> B256 {
        let mut size = self.size;
        let mut hash_buf = [0u8; 64];
        (0..HEIGHT).fold(B256::default(), |tree_root, height| {
            if size & 1 == 1 {
                hash_buf[..32].copy_from_slice(self.active_branch[height].as_slice());
                hash_buf[32..].copy_from_slice(tree_root.as_slice());
            } else {
                hash_buf[..32].copy_from_slice(tree_root.as_slice());
                hash_buf[32..].copy_from_slice(self.zero_hashes[height].as_slice());
            }
            size >>= 1;
            keccak256(hash_buf)
        })
    }

}