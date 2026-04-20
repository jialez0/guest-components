// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

use crate::utils::read_eventlog;
use crate::{Attester, TeeEvidence};
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use kbs_types::HashAlgorithm;
use num_traits::FromPrimitive;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use tss_esapi::abstraction::{
    ak::{create_ak, load_ak},
    ek::{create_ek_object, retrieve_ek_pubcert},
    pcr,
    AsymmetricAlgorithmSelection, DefaultKey,
};
use tss_esapi::attributes::SessionAttributesBuilder;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{KeyHandle, PcrHandle};
use tss_esapi::interface_types::algorithm::{
    AsymmetricAlgorithm, HashingAlgorithm, SignatureSchemeAlgorithm,
};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::structures::digest_values::DigestValues;
use tss_esapi::structures::{
    pcr_selection_list::PcrSelectionListBuilder, pcr_slot::PcrSlot, AttestInfo, PcrSelectionList,
    Private, Public, Signature, SignatureScheme, SymmetricDefinition,
};
use tss_esapi::tcti_ldr::{DeviceConfig, TctiNameConf};
use tss_esapi::traits::Marshall;
use tss_esapi::Context as TssContext;

const TPM_EVENTLOG_FILE_PATH: &str = "/sys/kernel/security/tpm0/binary_bios_measurements";
const TPM_REPORT_DATA_SIZE: usize = 32;
const PCR_BANK_SM3: &str = "SM3";
const HYGON_CPU_VENDOR: &str = "HygonGenuine";

const TPM_QUOTE_PCR_SLOTS: [PcrSlot; 24] = [
    PcrSlot::Slot0,
    PcrSlot::Slot1,
    PcrSlot::Slot2,
    PcrSlot::Slot3,
    PcrSlot::Slot4,
    PcrSlot::Slot5,
    PcrSlot::Slot6,
    PcrSlot::Slot7,
    PcrSlot::Slot8,
    PcrSlot::Slot9,
    PcrSlot::Slot10,
    PcrSlot::Slot11,
    PcrSlot::Slot12,
    PcrSlot::Slot13,
    PcrSlot::Slot14,
    PcrSlot::Slot15,
    PcrSlot::Slot16,
    PcrSlot::Slot17,
    PcrSlot::Slot18,
    PcrSlot::Slot19,
    PcrSlot::Slot20,
    PcrSlot::Slot21,
    PcrSlot::Slot22,
    PcrSlot::Slot23,
];

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HygonSm2PublicKey {
    pub x: String,
    pub y: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HygonTpmQuote {
    pub attest_body: String,
    pub attest_sig: String,
    pub pcrs: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HygonTpmEvidence {
    pub ek_cert: Option<String>,
    pub ak_pubkey: HygonSm2PublicKey,
    pub quote: HashMap<String, HygonTpmQuote>,
    pub eventlog: Option<String>,
    pub aa_eventlog: Option<String>,
}

#[derive(Clone)]
struct AttestationKey {
    ak_private: Private,
    ak_public: Public,
}

pub fn detect_platform() -> bool {
    if !Path::new("/dev/tpm0").exists() {
        return false;
    }

    std::fs::read_to_string("/proc/cpuinfo")
        .map(|content| content.contains(HYGON_CPU_VENDOR))
        .unwrap_or(false)
}

fn create_tcti() -> Result<TctiNameConf> {
    match std::env::var("TEST_TCTI") {
        Result::Err(_) => Ok(TctiNameConf::Device(DeviceConfig::default())),
        Result::Ok(tctistr) => Ok(TctiNameConf::from_str(&tctistr)?),
    }
}

fn create_ctx_without_session() -> Result<TssContext> {
    let tcti = create_tcti()?;
    let ctx = TssContext::new(tcti)?;
    Ok(ctx)
}

fn create_ctx_with_session() -> Result<TssContext> {
    let mut ctx = create_ctx_without_session()?;

    let session = ctx.start_auth_session(
        None,
        None,
        None,
        SessionType::Hmac,
        SymmetricDefinition::Xor {
            hashing_algorithm: HashingAlgorithm::Sm3_256,
        },
        HashingAlgorithm::Sm3_256,
    )?;
    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    let valid_session = session.ok_or_else(|| anyhow!("Failed to start auth session"))?;

    ctx.tr_sess_set_attributes(valid_session, session_attributes, session_attributes_mask)?;
    ctx.set_sessions((session, None, None));

    Ok(ctx)
}

fn create_pcr_selection_list(algorithm: &str) -> Result<PcrSelectionList> {
    match algorithm {
        PCR_BANK_SM3 => PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sm3_256, &TPM_QUOTE_PCR_SLOTS)
            .build()
            .context("Build PCR selection list failed"),
        _ => bail!("Unsupported PCR algorithm of Hygon TPM attester"),
    }
}

fn dump_ek_cert_pem() -> Result<String> {
    let mut context = create_ctx_without_session()?;
    let ek_cert_bytes = retrieve_ek_pubcert(
        &mut context,
        AsymmetricAlgorithmSelection::Ecc(EccCurve::Sm2P256),
    )?;
    let ek_cert_x509 = X509::from_der(&ek_cert_bytes)?;
    let ek_cert_pem_bytes = ek_cert_x509.to_pem()?;
    let ek_cert = String::from_utf8(ek_cert_pem_bytes)?;
    Ok(ek_cert)
}

fn dump_pcrs(algorithm: &str) -> Result<Vec<String>> {
    let mut context = create_ctx_without_session()?;
    let selection_list = create_pcr_selection_list(algorithm)?;
    let pcr_data = pcr::read_all(&mut context, selection_list)?;

    let pcr_bank = match algorithm {
        PCR_BANK_SM3 => pcr_data
            .pcr_bank(HashingAlgorithm::Sm3_256)
            .ok_or_else(|| anyhow!("PCR bank not found"))?,
        _ => bail!("Unsupported PCR algorithm of Hygon TPM attester"),
    };

    let pcrs: Vec<String> = pcr_bank
        .into_iter()
        .map(|(_, digest)| hex::encode(digest.value()))
        .collect();
    Ok(pcrs)
}

fn generate_sm2_ak() -> Result<AttestationKey> {
    let mut context = create_ctx_without_session()?;
    let ek_handle = create_ek_object(&mut context, AsymmetricAlgorithm::Ecc, DefaultKey)?;

    let ak = create_ak(
        &mut context,
        ek_handle,
        HashingAlgorithm::Sm3_256,
        SignatureSchemeAlgorithm::Sm2,
        None,
        DefaultKey,
    )?;

    Ok(AttestationKey {
        ak_private: ak.out_private,
        ak_public: ak.out_public,
    })
}

fn import_ak_handle(ctx: &mut TssContext, ak: AttestationKey) -> Result<KeyHandle> {
    let ek_handle = create_ek_object(ctx, AsymmetricAlgorithm::Ecc, DefaultKey)?;
    let ak_handle = load_ak(ctx, ek_handle, None, ak.ak_private, ak.ak_public)?;
    Ok(ak_handle)
}

fn get_ak_pub(ak: AttestationKey) -> Result<HygonSm2PublicKey> {
    let mut context = create_ctx_without_session()?;
    let ek_handle = create_ek_object(&mut context, AsymmetricAlgorithm::Ecc, DefaultKey)?;
    let key_handle = load_ak(
        &mut context,
        ek_handle,
        None,
        ak.clone().ak_private,
        ak.clone().ak_public,
    )?;
    let (pk, _, _) = context.read_public(key_handle)?;

    let Public::Ecc { unique, .. } = pk else {
        bail!("unexpected key type");
    };

    Ok(HygonSm2PublicKey {
        x: hex::encode(unique.x().value()),
        y: hex::encode(unique.y().value()),
    })
}

fn get_quote(ak: AttestationKey, report_data: &[u8], pcr_algorithm: &str) -> Result<HygonTpmQuote> {
    let mut context = create_ctx_with_session()?;
    let ak_handle = import_ak_handle(&mut context, ak)?;
    let selection_list = create_pcr_selection_list(pcr_algorithm)?;

    let (attest, signature) = context
        .quote(
            ak_handle,
            report_data.to_vec().try_into()?,
            SignatureScheme::Null,
            selection_list,
        )
        .context("Call TPM Quote API failed")?;

    let AttestInfo::Quote { .. } = attest.attested() else {
        bail!("Get Quote failed");
    };

    let Signature::Sm2(_) = &signature else {
        bail!("Wrong signature type from Hygon TPM quote");
    };

    let engine = base64::engine::general_purpose::STANDARD;

    Ok(HygonTpmQuote {
        attest_body: engine.encode(attest.marshall()?),
        attest_sig: engine.encode(signature.marshall()?),
        pcrs: dump_pcrs(pcr_algorithm)?,
    })
}

fn pcr_extend(digest: Vec<u8>, index: u64) -> Result<()> {
    let mut ctx = create_ctx_with_session()?;

    if index >= TPM_QUOTE_PCR_SLOTS.len() as u64 {
        bail!("Register index out of bounds");
    }

    if digest.len() != TPM_REPORT_DATA_SIZE {
        bail!("Event digest length is not 32 bytes (SM3)");
    }

    let pcr_handle = PcrHandle::from_u64(index).ok_or_else(|| anyhow!("Invalid pcr index"))?;
    let mut digest_values = DigestValues::new();
    digest_values.set(
        HashingAlgorithm::Sm3_256,
        digest
            .try_into()
            .map_err(|_| anyhow!("Failed to convert digest"))?,
    );

    ctx.pcr_extend(pcr_handle, digest_values)?;
    Ok(())
}

#[derive(Debug, Default)]
pub struct HygonTpmAttester {}

#[async_trait::async_trait]
impl Attester for HygonTpmAttester {
    async fn get_evidence(&self, mut report_data: Vec<u8>) -> Result<TeeEvidence> {
        if report_data.len() > TPM_REPORT_DATA_SIZE {
            log::warn!(
                "Hygon TPM Attester: report data truncated from {} to {} bytes",
                report_data.len(),
                TPM_REPORT_DATA_SIZE
            );
            report_data.truncate(TPM_REPORT_DATA_SIZE);
        }
        report_data.resize(TPM_REPORT_DATA_SIZE, 0);

        let attestation_key = generate_sm2_ak()?;
        let ak_pubkey = get_ak_pub(attestation_key.clone())?;

        let mut quote = HashMap::new();
        quote.insert(
            PCR_BANK_SM3.to_string(),
            get_quote(attestation_key, &report_data, PCR_BANK_SM3)?,
        );

        let engine = base64::engine::general_purpose::STANDARD;
        let eventlog = match std::fs::read(TPM_EVENTLOG_FILE_PATH) {
            Result::Ok(el) => Some(engine.encode(el)),
            Result::Err(e) => {
                log::warn!("Read TPM eventlog failed: {:?}", e);
                None
            }
        };

        let aa_eventlog = read_eventlog().await?;
        let evidence = HygonTpmEvidence {
            ek_cert: dump_ek_cert_pem().ok(),
            ak_pubkey,
            quote,
            eventlog,
            aa_eventlog,
        };

        serde_json::to_value(evidence)
            .map_err(|e| anyhow!("Serialize Hygon TPM evidence failed: {:?}", e))
    }

    async fn extend_runtime_measurement(&self, digest: Vec<u8>, index: u64) -> Result<()> {
        pcr_extend(digest, index)
    }

    async fn get_runtime_measurement(&self, index: u64) -> Result<Vec<u8>> {
        let pcr_index = index as usize;
        let pcrs = dump_pcrs(PCR_BANK_SM3)?;
        let target_pcr = pcrs
            .get(pcr_index)
            .ok_or_else(|| anyhow!("Register index out of bounds"))?;
        let pcr_value = hex::decode(target_pcr)?;
        Ok(pcr_value)
    }

    fn pcr_to_ccmr(&self, pcr_index: u64) -> u64 {
        pcr_index
    }

    fn ccel_hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sm3
    }
}
