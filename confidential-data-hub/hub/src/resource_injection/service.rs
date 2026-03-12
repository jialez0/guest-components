// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use kbs_protocol::TeeKeyPair;
use kbs_types::Response as EncryptedResponse;
use log::info;
use rand::RngCore;
use tokio::fs;
use tokio::sync::Mutex;

use super::{
    aa_client::AaClient,
    path::{validate_resource_path, KBS_RESOURCE_STORAGE_DIR},
    runtime_data::hash_runtime_data_for_evidence,
    session::InjectionSession,
};
use crate::{Error, PrepareResourceInjectionResult, Result};

pub(crate) struct ResourceInjection {
    aa_socket: String,
    sessions: Mutex<HashMap<String, InjectionSession>>,
}

impl ResourceInjection {
    pub(crate) fn new(aa_socket: String) -> Self {
        Self {
            aa_socket,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) async fn prepare(
        &self,
        resource_path: String,
        nonce: String,
    ) -> Result<PrepareResourceInjectionResult> {
        info!("prepare resource injection called: {resource_path}");
        validate_resource_path(&resource_path)?;
        if nonce.is_empty() {
            return Err(Error::ResourceInjection(
                "nonce must not be empty".to_string(),
            ));
        }

        let tee_key = TeeKeyPair::new().map_err(|e| {
            Error::ResourceInjection(format!("create TEE key pair for injection failed: {e}"))
        })?;
        let tee_pubkey = tee_key.export_pubkey().map_err(|e| {
            Error::ResourceInjection(format!("export TEE public key for injection failed: {e}"))
        })?;
        let runtime_data = serde_json::json!({
            "nonce": nonce,
            "tee-pubkey": tee_pubkey,
        });
        let evidence_runtime_data = hash_runtime_data_for_evidence(&runtime_data)?;
        let aa_client = AaClient::new(&self.aa_socket)?;
        let evidence = aa_client.get_evidence(evidence_runtime_data).await?;

        let mut session_id_raw = [0_u8; 16];
        rand::rng().fill_bytes(&mut session_id_raw);
        let session_id = URL_SAFE_NO_PAD.encode(session_id_raw);

        self.sessions.lock().await.insert(
            session_id.clone(),
            InjectionSession {
                resource_path,
                tee_key,
            },
        );

        let tee_pubkey = serde_json::to_string(&tee_pubkey).map_err(|e| {
            Error::ResourceInjection(format!(
                "serialize TEE public key for injection failed: {e}"
            ))
        })?;

        Ok(PrepareResourceInjectionResult {
            session_id,
            nonce,
            tee_pubkey,
            evidence,
        })
    }

    pub(crate) async fn commit(
        &self,
        session_id: String,
        resource_path: String,
        encrypted_resource: Vec<u8>,
    ) -> Result<()> {
        info!("commit resource injection called: {resource_path}");
        validate_resource_path(&resource_path)?;

        let session = self
            .sessions
            .lock()
            .await
            .remove(&session_id)
            .ok_or_else(|| {
                Error::ResourceInjection(format!(
                    "resource injection session not found or already used: {session_id}"
                ))
            })?;
        if session.resource_path != resource_path {
            return Err(Error::ResourceInjection(format!(
                "resource path mismatch for session {session_id}"
            )));
        }

        let encrypted_response: EncryptedResponse = serde_json::from_slice(&encrypted_resource)
            .map_err(|e| {
                Error::ResourceInjection(format!("parse encrypted resource payload failed: {e}"))
            })?;
        let plaintext = session
            .tee_key
            .decrypt_response(encrypted_response)
            .map_err(|e| {
                Error::ResourceInjection(format!("decrypt injected resource failed: {e}"))
            })?;

        let target_path = format!("{KBS_RESOURCE_STORAGE_DIR}/{resource_path}");
        let target_path = std::path::PathBuf::from(&target_path);
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                Error::ResourceInjection(format!(
                    "create target directory for injected resource failed: {e}"
                ))
            })?;
        }
        fs::write(&target_path, plaintext).await.map_err(|e| {
            Error::ResourceInjection(format!(
                "write injected resource to {} failed: {e}",
                target_path.display()
            ))
        })?;

        Ok(())
    }
}
