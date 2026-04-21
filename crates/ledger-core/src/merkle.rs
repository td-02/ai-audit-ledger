use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

fn hash_bytes(parts: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().to_vec()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MerkleSiblingPosition {
    Left,
    Right,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProofStep {
    pub hash: String,
    pub position: MerkleSiblingPosition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub leaf_value: String,
    pub path: Vec<MerkleProofStep>,
    pub root: String,
}

fn encode_hash(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(bytes))
}

fn decode_hash(value: &str) -> Option<Vec<u8>> {
    value
        .strip_prefix("sha256:")
        .and_then(|hex_part| hex::decode(hex_part).ok())
}

pub fn compute_merkle_root(leaves: &[String]) -> String {
    if leaves.is_empty() {
        return "sha256:empty".to_string();
    }

    let mut level: Vec<Vec<u8>> = leaves
        .iter()
        .map(|leaf| hash_bytes(&[leaf.as_bytes()]))
        .collect();

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = &pair[0];
            let right = pair.get(1).unwrap_or(left);
            next.push(hash_bytes(&[left, right]));
        }
        level = next;
    }

    format!("sha256:{}", hex::encode(&level[0]))
}

pub fn build_merkle_proof(leaves: &[String], leaf_index: usize) -> Option<MerkleProof> {
    if leaves.is_empty() || leaf_index >= leaves.len() {
        return None;
    }

    let mut index = leaf_index;
    let mut path = Vec::new();
    let mut level: Vec<Vec<u8>> = leaves
        .iter()
        .map(|leaf| hash_bytes(&[leaf.as_bytes()]))
        .collect();

    while level.len() > 1 {
        let is_right_node = index % 2 == 1;
        let sibling_index = if is_right_node { index - 1 } else { index + 1 };
        let sibling = level.get(sibling_index).unwrap_or(&level[index]);
        path.push(MerkleProofStep {
            hash: encode_hash(sibling),
            position: if is_right_node {
                MerkleSiblingPosition::Left
            } else {
                MerkleSiblingPosition::Right
            },
        });

        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = &pair[0];
            let right = pair.get(1).unwrap_or(left);
            next.push(hash_bytes(&[left, right]));
        }
        index /= 2;
        level = next;
    }

    Some(MerkleProof {
        leaf_index,
        leaf_value: leaves[leaf_index].clone(),
        path,
        root: encode_hash(&level[0]),
    })
}

pub fn verify_merkle_proof(proof: &MerkleProof) -> bool {
    if proof.root == "sha256:empty" {
        return false;
    }

    let mut current = hash_bytes(&[proof.leaf_value.as_bytes()]);
    for step in &proof.path {
        let sibling = match decode_hash(&step.hash) {
            Some(bytes) => bytes,
            None => return false,
        };
        current = match step.position {
            MerkleSiblingPosition::Left => hash_bytes(&[&sibling, &current]),
            MerkleSiblingPosition::Right => hash_bytes(&[&current, &sibling]),
        };
    }

    encode_hash(&current) == proof.root
}

#[cfg(test)]
mod tests {
    use super::{
        build_merkle_proof, compute_merkle_root, verify_merkle_proof, MerkleSiblingPosition,
    };

    #[test]
    fn empty_merkle_root_is_constant() {
        let leaves: Vec<String> = vec![];
        assert_eq!(compute_merkle_root(&leaves), "sha256:empty");
    }

    #[test]
    fn single_leaf_root_is_stable() {
        let leaves = vec!["sha256:a".to_string()];
        let first = compute_merkle_root(&leaves);
        let second = compute_merkle_root(&leaves);
        assert_eq!(first, second);
        assert!(first.starts_with("sha256:"));
    }

    #[test]
    fn odd_number_of_leaves_is_deterministic() {
        let leaves = vec![
            "sha256:1".to_string(),
            "sha256:2".to_string(),
            "sha256:3".to_string(),
        ];
        let first = compute_merkle_root(&leaves);
        let second = compute_merkle_root(&leaves);
        assert_eq!(first, second);
    }

    #[test]
    fn leaf_order_changes_root() {
        let ordered = vec![
            "sha256:1".to_string(),
            "sha256:2".to_string(),
            "sha256:3".to_string(),
            "sha256:4".to_string(),
        ];
        let swapped = vec![
            "sha256:1".to_string(),
            "sha256:3".to_string(),
            "sha256:2".to_string(),
            "sha256:4".to_string(),
        ];
        assert_ne!(compute_merkle_root(&ordered), compute_merkle_root(&swapped));
    }

    #[test]
    fn build_and_verify_merkle_proof_for_middle_leaf() {
        let leaves = vec![
            "sha256:1".to_string(),
            "sha256:2".to_string(),
            "sha256:3".to_string(),
            "sha256:4".to_string(),
            "sha256:5".to_string(),
        ];

        let proof = build_merkle_proof(&leaves, 2).expect("proof");
        assert_eq!(proof.leaf_index, 2);
        assert_eq!(proof.leaf_value, "sha256:3");
        assert_eq!(proof.root, compute_merkle_root(&leaves));
        assert!(verify_merkle_proof(&proof));
        assert!(!proof.path.is_empty());
    }

    #[test]
    fn verify_merkle_proof_rejects_tampered_leaf() {
        let leaves = vec![
            "sha256:1".to_string(),
            "sha256:2".to_string(),
            "sha256:3".to_string(),
        ];
        let mut proof = build_merkle_proof(&leaves, 1).expect("proof");
        proof.leaf_value = "sha256:tampered".to_string();
        assert!(!verify_merkle_proof(&proof));
    }

    #[test]
    fn verify_merkle_proof_rejects_tampered_path() {
        let leaves = vec![
            "sha256:1".to_string(),
            "sha256:2".to_string(),
            "sha256:3".to_string(),
        ];
        let mut proof = build_merkle_proof(&leaves, 0).expect("proof");
        proof.path[0].hash = "sha256:deadbeef".to_string();
        assert!(!verify_merkle_proof(&proof));
    }

    #[test]
    fn build_merkle_proof_returns_none_for_invalid_index() {
        let leaves = vec!["sha256:1".to_string()];
        assert!(build_merkle_proof(&leaves, 1).is_none());
    }

    #[test]
    fn odd_leaf_proof_uses_right_duplication() {
        let leaves = vec![
            "sha256:1".to_string(),
            "sha256:2".to_string(),
            "sha256:3".to_string(),
        ];
        let proof = build_merkle_proof(&leaves, 2).expect("proof");
        assert!(verify_merkle_proof(&proof));
        assert_eq!(proof.path[0].position, MerkleSiblingPosition::Right);
    }
}
