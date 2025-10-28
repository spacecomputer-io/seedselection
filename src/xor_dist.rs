//! This module implements XOR distance selection.

use digest::Digest;
use num_bigint::BigUint;
use std::cmp::Ordering;
use std::collections::BinaryHeap;

// HeapEntry is an internal struct that holds an id and its xor distance from a hash value.
//
// PartialOrd and Ord are crucial for BinaryHeap to know how to order elements.
// Since BinaryHeap is a max-heap, we'll implement these to order by 'distance' in reverse.
#[derive(Debug, Clone, Eq, PartialEq)]
struct HeapEntry {
    id: Vec<u8>,
    distance: u64,
}

// Implement Ord for HeapEntry to make it compatible with BinaryHeap.
// BinaryHeap is a max-heap, so `cmp` should define what makes an element "greater".
// We want the *smallest* distances to be considered "greater" in this context
// so that BinaryHeap keeps the N smallest at the top (effectively acting as a min-heap
// for our conceptual "smallest distance" goal).
// This is done by reversing the comparison of distance.
impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.distance.cmp(&other.distance).reverse()
    }
}

/// Implement PartialOrd for HeapEntry to allow comparisons between entries based on their distance.
/// It does not need to reverse the comparison since Ord already does that.
/// Clippy warning is suppressed because this is intentional for use with BinaryHeap.
#[allow(clippy::non_canonical_partial_ord_impl)]
impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.distance.cmp(&other.distance))
    }
}

/// xor_distance_selection takes a name, (random) seed, sequence number, number of ids to select (n),
/// and a list of ids (hashes) to select from.
///
/// The hash(name, seed, seq) will be used for ordering the ids according to the XOR distance,
/// where the closest `n` ids will be selected.
/// For optimization, a max-heap (Rust's `BinaryHeap` which is a max-heap) is used to maintain
/// the `n` ids with the smallest XOR distances from the hash value.
/// If `n` is greater than or equal to the number of ids, all ids will be elected.
///
/// # Arguments
/// * `name` - A string identifier for the selection context.
/// * `seed` - A 32 byte random seed as a byte slice.
/// * `seq` - A sequence number (round/epoch).
/// * `n` - The number of ids to select.
/// * `ids` - A vector of hashed ids to select from (expected to be 32-byte SHA256 hashes encoded as hex strings).
/// * `hasher`: Closure returning a new hasher implementing [`digest::Digest`]
///
/// # Returns
/// `Some(Vec<Vec<u8>>)` of selected IDs, or `None` if `ids` is empty.
///
/// # Security
/// The selection is only as unpredictable as the seed. Use a secure, random seed for cryptographic applications.
///
/// # Example
/// ```rust
/// use sha2::{Sha256, Digest};
///
/// let ids = vec![b"peer1".to_vec(), b"peer2".to_vec()];
/// let selected = seedselection::xor_dist::xor_distance_selection("ctx", b"seed", 0, 1, &ids, Sha256::new, None).unwrap();
/// ```
pub fn xor_distance_selection<T, D>(
    name: &str,
    seed: &[u8],
    seq: u64,
    n: usize,
    ids: &[T],
    mut hasher: impl FnMut() -> D,
    weights: Option<&[u64]>,
) -> Option<Vec<Vec<u8>>>
where
    T: AsRef<[u8]>,
    D: Digest,
{
    let p = ids.len();

    if p == 0 {
        return None;
    }
    if n >= p {
        return Some(ids.iter().map(|id| id.as_ref().to_vec()).collect());
    }
    let hash_bytes = crate::hash::compute_hash(name, seed, seq, &mut hasher);
    let hash_value = BigUint::from_bytes_be(&hash_bytes);

    // We use Rust's BinaryHeap is a max-heap to keep the 'n' smallest elements,
    // if the heap size exceeds 'n' we check the largest element against the new element.
    // If the new element is smaller, we pop the largest (furthest) element and push the new one.
    // This way, we maintain a heap of the 'n' closest ids.
    let mut max_heap = BinaryHeap::with_capacity(n);

    for (i, id) in ids.iter().enumerate() {
        let id_bytes = id.as_ref();

        let id_value = BigUint::from_bytes_be(id_bytes);
        let distance_val = &hash_value ^ &id_value;

        let mut distance = distance_val.to_u64_digits().first().cloned().unwrap_or(0);
        if let Some(weights) = weights {
            // If weights are provided, we apply them to the distance.
            // This assumes that the weights are aligned with the ids.
            if let Some(&weight) = weights.get(i).filter(|&w| *w > 0) {
                // Apply weight to distance
                distance /= weight;
            }
        }
        let entry = HeapEntry {
            id: id_bytes.to_vec(),
            distance,
        };

        if max_heap.len() < n {
            max_heap.push(entry);
        } else if let Some(top_entry) = max_heap.peek()
            && entry.distance < top_entry.distance
        {
            // Check if the current entry's distance is smaller than the largest distance
            // currently in the heap (which is the root of the max-heap).
            // If it is, we pop the largest (furthest) entry and push the new one.
            max_heap.pop();
            max_heap.push(entry);
        }
    }

    let selected = max_heap
        .into_sorted_vec()
        .into_iter()
        .map(|entry| entry.id)
        .collect::<Vec<Vec<u8>>>();

    Some(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    static PEER_IDS_TEST_LITERALS: [&str; 10] = [
        "peer1", "peer2", "peer3", "peer4", "peer5", "peer6", "peer7", "peer8", "peer9", "peer10",
    ];

    static PEER_IDS_32BYTE_LITERAL_CASE: [&str; 6] = [
        "698750a09b934337746f0973448167f364cae132e2f8b327ae4913e5b5445029",
        "3b213ced003e89b35a26c22cbd011c9bfab29578415b2069f7fc8b01998b903d",
        "e42bbf8533f4f0b1d44e7fc1c9ac54a6ac368642dd1b8a10a1775255eed0c31a",
        "a7a0243e04fd71dc10068134a7dc0ab6de6e3cb76439400d17e6d531a5e596b1",
        "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4g5h6i7j8k9l0m1n2o",
        "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4g5h6i7j8k9l0m1n2o3p4",
    ];

    // Helper to construct a Vec<String> from the static string slices
    fn get_peerset_from_literals(indices: &[usize]) -> Vec<String> {
        indices
            .iter()
            .map(|&i| PEER_IDS_TEST_LITERALS[i].to_string())
            .collect()
    }

    #[test]
    fn test_seq_1_with_5_raw_string_peers() {
        let name = "test";
        let seed = b"test-seed";
        let seq = 1;
        let n = 3;
        let peerset = get_peerset_from_literals(&[0, 1, 2, 3, 4]);

        let expected = vec![
            PEER_IDS_TEST_LITERALS[4].as_bytes(), // peer5
            PEER_IDS_TEST_LITERALS[3].as_bytes(), // peer4
            PEER_IDS_TEST_LITERALS[0].as_bytes(), // peer1
        ];

        let actual =
            xor_distance_selection(name, seed, seq, n, &peerset, Sha256::new, None).unwrap();
        assert_eq!(actual, expected, "Selection mismatch");
    }

    #[test]
    fn test_seq_1_with_5_raw_string_peers_different_order() {
        let name = "test";
        let seed = b"test-seed";
        let seq = 1;
        let n = 3;
        let mut peerset = get_peerset_from_literals(&[0, 1, 2, 3, 4]);
        peerset.swap(0, 1); // swap "peer1", "peer2"
        peerset.swap(2, 3); // swap "peer3", "peer4"

        // Expected should be the same as the previous test because selection is order-agnostic
        let expected = vec![
            PEER_IDS_TEST_LITERALS[4].as_bytes(),
            PEER_IDS_TEST_LITERALS[3].as_bytes(),
            PEER_IDS_TEST_LITERALS[0].as_bytes(),
        ];

        let actual =
            xor_distance_selection(name, seed, seq, n, &peerset, Sha256::new, None).unwrap();
        assert_eq!(actual, expected, "Selection mismatch");
    }

    #[test]
    fn test_seq_2_with_5_raw_string_peers() {
        let name = "test";
        let seed = b"test-seed";
        let seq = 2;
        let n = 3;
        let peerset = get_peerset_from_literals(&[0, 1, 2, 3, 4]);

        let expected = vec![
            PEER_IDS_TEST_LITERALS[3].as_bytes(),
            PEER_IDS_TEST_LITERALS[4].as_bytes(),
            PEER_IDS_TEST_LITERALS[1].as_bytes(),
        ];

        let actual =
            xor_distance_selection(name, seed, seq, n, &peerset, Sha256::new, None).unwrap();
        assert_eq!(actual, expected, "Selection mismatch");
    }

    #[test]
    fn test_seq_1_with_specific_rng_name() {
        let name = "dummy-rng-name-x";
        let seed = b"test-seed";
        let seq = 1;
        let n = 3;
        let peerset = get_peerset_from_literals(&[0, 1, 2, 3, 4]);

        let expected = vec![
            PEER_IDS_TEST_LITERALS[3].as_bytes(),
            PEER_IDS_TEST_LITERALS[4].as_bytes(),
            PEER_IDS_TEST_LITERALS[0].as_bytes(),
        ];

        let actual =
            xor_distance_selection(name, seed, seq, n, &peerset, Sha256::new, None).unwrap();
        assert_eq!(actual, expected, "Selection mismatch for specific RNG name");
    }

    #[test]
    fn test_n_greater_than_peerset_size() {
        let name = "test";
        let seed = b"test-seed";
        let seq = 1;
        let n = 10;
        let peerset = get_peerset_from_literals(&[0, 1, 2]); // peer1 to peer3

        let expected = vec![
            PEER_IDS_TEST_LITERALS[0].as_bytes(),
            PEER_IDS_TEST_LITERALS[1].as_bytes(),
            PEER_IDS_TEST_LITERALS[2].as_bytes(),
        ];

        let actual =
            xor_distance_selection(name, seed, seq, n, &peerset, Sha256::new, None).unwrap();
        assert_eq!(actual, expected, "Selection mismatch");
    }

    #[test]
    fn test_no_nodes() {
        let name = "test";
        let seed = b"test-seed";
        let seq = 1;
        let n = 0; // Requesting 0 leaders is technically possible
        let peerset: Vec<String> = Vec::new();

        let expected: Option<Vec<Vec<u8>>> = None; // Go's nil translates to empty Vec

        let actual = xor_distance_selection(name, seed, seq, n, &peerset, Sha256::new, None);
        assert_eq!(actual, expected, "Selection mismatch for no nodes");
    }

    #[test]
    fn test_with_32byte_literal_strings_in_peerset() {
        let name = "testgroup-1";
        let seed = b"test-seed";
        let seq = 10;
        let n = 2;
        let peerset: Vec<String> = PEER_IDS_32BYTE_LITERAL_CASE
            .iter()
            .map(|&s| s.to_string())
            .collect();

        let expected = vec![
            PEER_IDS_32BYTE_LITERAL_CASE[2].as_bytes(), // e42bbf85... (Placeholder)
            PEER_IDS_32BYTE_LITERAL_CASE[3].as_bytes(), // a7a0243e... (Placeholder)
        ];

        let actual =
            xor_distance_selection(name, seed, seq, n, &peerset, Sha256::new, None).unwrap();
        assert_eq!(actual, expected, "Selection mismatch");
    }
    #[test]
    fn test_with_32byte_literal_strings_in_peerset_with_weights() {
        let name = "testgroup-1";
        let seed = b"test-seed";
        let seq = 10;
        let n = 3;
        let peerset: Vec<String> = PEER_IDS_32BYTE_LITERAL_CASE
            .iter()
            .map(|&s| s.to_string())
            .collect();

        let expected = vec![
            PEER_IDS_32BYTE_LITERAL_CASE[4].as_bytes(), // b2c3d4e5... (Placeholder)
            PEER_IDS_32BYTE_LITERAL_CASE[2].as_bytes(), // e42bbf85... (Placeholder)
            PEER_IDS_32BYTE_LITERAL_CASE[1].as_bytes(), // 3b213ced... (Placeholder)
        ];

        let actual = xor_distance_selection(
            name,
            seed,
            seq,
            n,
            &peerset,
            Sha256::new,
            Some(&[0, 10, 10, 2, 100, 1]),
        )
        .unwrap();
        assert_eq!(actual, expected, "Selection mismatch");
    }
}
