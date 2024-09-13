// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//
mod inner;
use super::Attester;
use anyhow::*;
use base64::Engine;
use inner::SystemAttesterdInner;
use serde::{Deserialize, Serialize};

// System attester is always supported
pub fn detect_platform() -> bool {
    true
}

#[derive(Serialize, Deserialize, Debug)]
struct SystemQuote {
    system_report: String,
    measurements: String,
    mr_register: String,
    report_data: String,
}

pub struct SystemAttester {
    inner: SystemAttesterdInner,
}

impl SystemAttester {
    pub fn new() -> Result<Self> {
        let inner = SystemAttesterdInner::default();
        inner.init()?;
        Ok(Self { inner })
    }
}

#[async_trait::async_trait]
impl Attester for SystemAttester {
    async fn get_evidence(&self, report_data: Vec<u8>) -> Result<String> {
        let system_report = self.inner.read_sys_report()?;
        let measurements = serde_json::to_string(&self.inner.get_measurements())?;
        let mr_register = self.inner.read_mr_register();
        let evidence = SystemQuote {
            system_report,
            measurements,
            mr_register,
            report_data: base64::engine::general_purpose::STANDARD.encode(report_data),
        };
        serde_json::to_string(&evidence).context("Serialize system evidence failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_system_get_evidence() {
        let attester = SystemAttester::new().unwrap(); // Update for sync
        let report_data: Vec<u8> = vec![0; 48];
        let evidence = attester.get_evidence(report_data).await;
        assert!(evidence.is_ok());
    }
}
