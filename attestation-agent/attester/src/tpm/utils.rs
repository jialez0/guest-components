// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//
use anyhow::Context;
use anyhow::*;
use base64::Engine;
use num_traits::cast::FromPrimitive;
use openssl::x509::X509;
use rsa as rust_rsa;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tss_esapi::abstraction::{
    ak::{create_ak},
    ek::{create_ek_object, retrieve_ek_pubcert},
    pcr,
    public::DecodedKey,
    AsymmetricAlgorithmSelection, DefaultKey,
};
use tss_esapi::attributes::SessionAttributesBuilder;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{PcrHandle, TpmHandle, PersistentTpmHandle};
use tss_esapi::interface_types::algorithm::{
    AsymmetricAlgorithm, HashingAlgorithm, SignatureSchemeAlgorithm,
};
use tss_esapi::{
    interface_types::{
        resource_handles::Provision,
        dynamic_handles::Persistent,
    },
};
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::structures::digest_values::DigestValues;
use tss_esapi::structures::{
    pcr_selection_list::PcrSelectionListBuilder, pcr_slot::PcrSlot, AttestInfo, PcrSelectionList,
    Private, Public, Signature, SignatureScheme, SymmetricDefinition,
};
use tss_esapi::tcti_ldr::{DeviceConfig, TctiNameConf};
use tss_esapi::traits::Marshall;
use tss_esapi::Context as TssContext;

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

// AK persistent handle constant
// 0x81: indicates persistent handle
// 0x03: indicates this is an AK (Attestation Key)
// 0x0000: instance offset
const PERSISTENT_AK_HANDLE: u32 = 0x81030000;

pub fn create_tcti() -> Result<TctiNameConf> {
    match std::env::var("TEST_TCTI") {
        std::result::Result::Err(_) => Ok(TctiNameConf::Device(DeviceConfig::default())),
        std::result::Result::Ok(tctistr) => Ok(TctiNameConf::from_str(&tctistr)?),
    }
}

pub fn create_ctx_without_session() -> Result<TssContext> {
    let tcti = create_tcti()?;
    let ctx = TssContext::new(tcti)?;
    Ok(ctx)
}

pub fn create_ctx_with_session() -> Result<TssContext> {
    let mut ctx = create_ctx_without_session()?;

    let session = ctx.start_auth_session(
        None,
        None,
        None,
        SessionType::Hmac,
        SymmetricDefinition::Xor {
            hashing_algorithm: HashingAlgorithm::Sha256,
        },
        HashingAlgorithm::Sha256,
    )?;
    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    let valid_session = session.ok_or(anyhow!("Failed to start auth session"))?;

    ctx.tr_sess_set_attributes(valid_session, session_attributes, session_attributes_mask)?;
    ctx.set_sessions((session, None, None));

    Ok(ctx)
}

pub fn create_pcr_selection_list(algorithm: &str) -> Result<PcrSelectionList> {
    match algorithm {
        "SHA1" => PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha1, &TPM_QUOTE_PCR_SLOTS)
            .build()
            .context("Build PCR selection list failed"),
        "SHA256" => PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &TPM_QUOTE_PCR_SLOTS)
            .build()
            .context("Build PCR selection list failed"),
        _ => bail!("Unsupported PCR Algorithm of AA"),
    }
}

pub fn pcr_extend(digest: Vec<u8>, index: u64) -> Result<()> {
    let mut ctx = create_ctx_with_session()?;

    if index >= TPM_QUOTE_PCR_SLOTS.len() as u64 {
        bail!("Register index out of bounds");
    }

    // Must be SHA-256 digest
    if digest.len() != 32 {
        bail!("Event digest length is not 32 bytes (SHA-256)");
    }

    let pcr_handle = PcrHandle::from_u64(index).ok_or_else(|| anyhow!("Invalid pcr index"))?;
    let mut digest_values = DigestValues::new();
    digest_values.set(
        HashingAlgorithm::Sha256,
        digest
            .try_into()
            .map_err(|_| anyhow!("Failed to convert digest"))?,
    );

    ctx.pcr_extend(pcr_handle, digest_values)?;

    Ok(())
}

pub fn dump_ek_cert_pem() -> Result<String> {
    let mut context = create_ctx_without_session()?;

    let ek_cert_bytes = retrieve_ek_pubcert(
        &mut context,
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048),
    )?;
    let ek_cert_x509 = X509::from_der(&ek_cert_bytes)?;
    let ek_cert_pem_bytes = ek_cert_x509.to_pem()?;
    let ek_cert = String::from_utf8(ek_cert_pem_bytes)?;

    Ok(ek_cert)
}

pub fn dump_pcrs(algorithm: &str) -> Result<Vec<String>> {
    let mut context = create_ctx_without_session()?;

    let selection_list = create_pcr_selection_list(algorithm)?;

    let pcr_data = pcr::read_all(&mut context, selection_list)?;
    let hashing_algorithm = match algorithm {
        "SHA1" => HashingAlgorithm::Sha1,
        "SHA256" => HashingAlgorithm::Sha256,
        _ => bail!("dump_pcrs: Unsupport PCR algorithm of AA"),
    };
    let pcr_bank = pcr_data
        .pcr_bank(hashing_algorithm)
        .ok_or(anyhow!("PCR bank not found"))?;

    let pcrs: Result<Vec<String>, _> = pcr_bank
        .into_iter()
        .map(|(_, digest)| Ok(hex::encode(digest.value())))
        .collect();
    let pcrs = pcrs?;

    Ok(pcrs)
}

#[derive(Clone)]
pub struct AttestationKey {
    pub ak_private: Private,
    pub ak_public: Public,
}

pub fn generate_rsa_ak() -> Result<()> {
    let mut context = create_ctx_without_session()?;

    // First try to load existing persistent AK
    let presistend_ak_handle = PersistentTpmHandle::new(PERSISTENT_AK_HANDLE)?;
    match context.tr_from_tpm_public(TpmHandle::try_from(PERSISTENT_AK_HANDLE)?) {
        Result::Ok(persistent_handle) => {
            // AK already exists, clear the existing AK
            context.evict_control(
                Provision::Owner,
                persistent_handle.into(),
                Persistent::Persistent(presistend_ak_handle),
            )?;
        }
        Result::Err(_) => {
            // AK doesn't exist, continue to create new AK
        }
    }

    let ek_handle = create_ek_object(&mut context, AsymmetricAlgorithm::Rsa, DefaultKey)?;

    let ak = create_ak(
        &mut context,
        ek_handle,
        HashingAlgorithm::Sha256,
        SignatureSchemeAlgorithm::RsaSsa,
        None,
        DefaultKey,
    )?;

    // Load AK first
    let loaded_ak_handle = context.load(
        ek_handle,
        ak.out_private.clone(),
        ak.out_public.clone(),
    )?;
    // Persist AK
    context.evict_control(
        Provision::Owner,
        loaded_ak_handle.into(),
        Persistent::Persistent(presistend_ak_handle),
    )?;

    Ok(())
}

pub fn get_ak_pub() -> Result<rust_rsa::RsaPublicKey> {
    let mut context = create_ctx_without_session()?;
    let presistend_ak_handle = TpmHandle::try_from(PERSISTENT_AK_HANDLE)?;
    let ak_handle = context
        .tr_from_tpm_public(presistend_ak_handle)
        .map_err(|_| anyhow!("AK handle not found, maybe not be generated yet"))?;
    let (pk, _, _) = context.read_public(ak_handle.into())?;

    let decoded_key: DecodedKey = pk.try_into()?;
    let DecodedKey::RsaPublicKey(rsa_pk) = decoded_key else {
        bail!("unexpected key type");
    };

    let bytes = rsa_pk.modulus.as_unsigned_bytes_be();
    let n = rust_rsa::BigUint::from_bytes_be(bytes);
    let bytes = rsa_pk.public_exponent.as_unsigned_bytes_be();
    let e = rust_rsa::BigUint::from_bytes_be(bytes);

    let pkey = rust_rsa::RsaPublicKey::new(n, e)?;
    Ok(pkey)
}

#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct TpmQuote {
    // Base64 encoded
    attest_body: String,
    // Base64 encoded
    attest_sig: String,
    // PCRs
    pub pcrs: Vec<String>,
}

pub fn get_quote(report_data: &[u8], pcr_algorithm: &str) -> Result<TpmQuote> {
    let mut context = create_ctx_with_session()?;
    let presistend_ak_handle = TpmHandle::try_from(PERSISTENT_AK_HANDLE)?;

    // If the AK does not exist, call generate_rsa_ak to create a new one
    let ak_handle = match context.tr_from_tpm_public(presistend_ak_handle) {
        Result::Ok(handle) => handle,
        Result::Err(_) => {
            let _ = generate_rsa_ak()?;
            context
                .tr_from_tpm_public(presistend_ak_handle)
                .map_err(|_| anyhow!("AK handle not found, maybe generate_rsa_ak failed"))?
        }
    };

    let selection_list = create_pcr_selection_list(pcr_algorithm)?;

    let (attest, signature) = context
        .quote(
            ak_handle.into(),
            report_data.to_vec().try_into()?,
            SignatureScheme::Null,
            selection_list.clone(),
        )
        .context("Call TPM Quote API failed")?;

    let AttestInfo::Quote { .. } = attest.attested() else {
        bail!("Get Quote failed");
    };
    let Signature::RsaSsa(rsa_sig) = signature.clone() else {
        bail!("Wrong Signature");
    };

    let engine = base64::engine::general_purpose::STANDARD;

    drop(context);

    Ok(TpmQuote {
        attest_body: engine.encode(attest.marshall()?),
        attest_sig: engine.encode(rsa_sig.signature().to_vec()),
        pcrs: dump_pcrs(pcr_algorithm)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::result::Result::Ok;
    use rsa::traits::PublicKeyParts;
    use tss_esapi::tcti_ldr::TctiNameConf;
    use serial_test::serial;

    // Helper function to check if TPM is available
    fn is_tpm_available() -> bool {
        match create_tcti() {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    #[test]
    #[serial]
    fn test_create_tcti() {
        if !is_tpm_available() {
            println!("Skipping test_create_tcti: TPM not available");
            return;
        }

        let tcti = create_tcti().unwrap();
        assert!(matches!(tcti, TctiNameConf::Device(_)));
    }

    #[test]
    #[serial]
    fn test_create_ctx_without_session() {
        if !is_tpm_available() {
            println!("Skipping test_create_ctx_without_session: TPM not available");
            return;
        }

        let ctx = create_ctx_without_session().unwrap();
        // Success if we can create it
        assert!(!std::ptr::eq(&ctx, std::ptr::null()));
    }

    #[test]
    #[serial]
    fn test_create_ctx_with_session() {
        if !is_tpm_available() {
            println!("Skipping test_create_ctx_with_session: TPM not available");
            return;
        }

        let ctx = create_ctx_with_session().unwrap();
        // Success if we can create it
        assert!(!std::ptr::eq(&ctx, std::ptr::null()));
    }

    #[test]
    #[serial]
    fn test_create_pcr_selection_list() {
        if !is_tpm_available() {
            println!("Skipping test_create_pcr_selection_list: TPM not available");
            return;
        }

        let selection_list = create_pcr_selection_list("SHA256").unwrap();
        // Since count method doesn't exist, we use other ways to verify
        assert_eq!(selection_list.len(), 1); // Should have only one selection (SHA256)
    }

    #[test]
    #[serial]
    fn test_dump_pcrs() {
        if !is_tpm_available() {
            println!("Skipping test_dump_pcrs: TPM not available");
            return;
        }

        let pcrs = dump_pcrs("SHA256").unwrap();
        assert_eq!(pcrs.len(), 24);
        for pcr in pcrs {
            assert_eq!(pcr.len(), 64); // SHA256 hash is 32 bytes = 64 hex chars
        }
    }

    #[test]
    #[serial]
    fn test_generate_rsa_ak() {
        if !is_tpm_available() {
            println!("Skipping test_generate_rsa_ak: TPM not available");
            return;
        }

        // Test AK generation
        generate_rsa_ak().unwrap();

        // Verify AK was successfully generated
        let ak_pub = get_ak_pub().unwrap();
        assert!(ak_pub.n().bits() >= 2048); // Verify key length is at least 2048 bits
    }

    #[test]
    #[serial]
    fn test_get_quote() {
        if !is_tpm_available() {
            println!("Skipping test_get_quote: TPM not available");
            return;
        }

        let report_data = vec![0u8; 32]; // 32 bytes of test data
        let quote = get_quote(&report_data, "SHA256").unwrap();

        // Verify each field of the quote
        assert!(!quote.attest_body.is_empty());
        assert!(!quote.attest_sig.is_empty());
        assert_eq!(quote.pcrs.len(), 24);
    }

    #[test]
    #[serial]
    fn test_dump_ek_cert_pem() {
        if !is_tpm_available() {
            println!("Skipping test_dump_ek_cert_pem: TPM not available");
            return;
        }

        let cert = dump_ek_cert_pem().unwrap();
        assert!(cert.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(cert.ends_with("-----END CERTIFICATE-----\n"));
    }
}
