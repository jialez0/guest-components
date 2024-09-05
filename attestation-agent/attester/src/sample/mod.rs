// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use super::Attester;
use anyhow::*;
use base64::Engine;
use serde::{Deserialize, Serialize};

const EVENTLOG_PATH: &str = "/sys/kernel/security/tpm0/binary_bios_measurements";

// Sample attester is always supported
pub fn detect_platform() -> bool {
    true
}

// A simple example of TEE evidence.
#[derive(Serialize, Deserialize, Debug)]
struct SampleQuote {
    svn: String,
    report_data: String,
    tcg_eventlog: Option<String>,
}

#[derive(Debug, Default)]
pub struct SampleAttester {}

#[async_trait::async_trait]
impl Attester for SampleAttester {
    async fn get_evidence(&self, report_data: Vec<u8>) -> Result<String> {
        let tcg_eventlog = match std::fs::read(EVENTLOG_PATH) {
            Result::Ok(el) => Some(base64::engine::general_purpose::STANDARD.encode(el)),
            Result::Err(e) => {
                log::warn!("Read TCG Eventlog failed: {:?}", e);
                None
            }
        };

        let evidence = SampleQuote {
            svn: "1".to_string(),
            report_data: base64::engine::general_purpose::STANDARD.encode(report_data),
            tcg_eventlog,
        };

        serde_json::to_string(&evidence).context("Serialize sample evidence failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sample_get_evidence() {
        let attester = SampleAttester::default();
        let report_data: Vec<u8> = vec![0; 48];

        let evidence = attester.get_evidence(report_data).await;
        // let _ = std::fs::write(
        //     "/root/jiale/trustee/deps/verifier/test_data/sample_evidence.txt",
        //     evidence,
        // ).unwrap();
        assert!(evidence.is_ok());
    }
}
