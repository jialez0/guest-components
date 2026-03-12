// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use canon_json::CanonicalFormatter;
use kbs_types::HashAlgorithm;
use serde::Serialize;
use serde_json::Value;

use crate::{Error, Result};

const RESOURCE_INJECTION_RUNTIME_DATA_HASH_ALGORITHM: HashAlgorithm = HashAlgorithm::Sha384;

pub(super) fn hash_runtime_data_for_evidence(runtime_data: &Value) -> Result<Vec<u8>> {
    let canonical_runtime_data = serialize_json_canonically(runtime_data).map_err(|e| {
        Error::ResourceInjection(format!(
            "canonicalize runtime_data for injection evidence failed: {e}"
        ))
    })?;

    Ok(RESOURCE_INJECTION_RUNTIME_DATA_HASH_ALGORITHM.digest(&canonical_runtime_data))
}

fn serialize_json_canonically<T: Serialize>(value: &T) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut serializer =
        serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
    value.serialize(&mut serializer)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::hash_runtime_data_for_evidence;

    #[test]
    fn runtime_data_hash_is_canonicalized() {
        let runtime_data_a = json!({
            "nonce": "nonce",
            "tee-pubkey": {
                "y": "y-value",
                "alg": "ECDH-ES+A256KW",
                "x": "x-value",
                "crv": "P-256"
            }
        });
        let runtime_data_b = json!({
            "tee-pubkey": {
                "crv": "P-256",
                "x": "x-value",
                "alg": "ECDH-ES+A256KW",
                "y": "y-value"
            },
            "nonce": "nonce"
        });

        let digest_a = hash_runtime_data_for_evidence(&runtime_data_a).unwrap();
        let digest_b = hash_runtime_data_for_evidence(&runtime_data_b).unwrap();

        assert_eq!(digest_a, digest_b);
        assert_eq!(digest_a.len(), 48);
    }
}
