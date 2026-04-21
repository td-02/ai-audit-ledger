use sha2::{Digest, Sha256};

fn hash_bytes(parts: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().to_vec()
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

#[cfg(test)]
mod tests {
    use super::compute_merkle_root;

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
}
