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

