use anyhow::*;
use lazy_static::lazy_static;
use log::info;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use std::sync::RwLock;
use sysinfo_rs::get_machine_info;

lazy_static! {
    static ref MR_REGISTER: RwLock<String> = RwLock::new(String::new());
    static ref MEASUREMENTS: RwLock<Vec<MeasurementEntry>> = RwLock::new(Vec::new());
}

#[derive(Clone, Serialize, Deserialize, Default, Debug, PartialEq)]
pub struct MeasurementEntry {
    pub name: String,
    pub algorithm: String,
    pub digest: String,
}

#[derive(Default)]
pub struct SystemAttesterdInner {}

impl SystemAttesterdInner {
    pub fn measure(&self, name: String, data: Vec<u8>) -> Result<()> {
        // Measure data
        let mut hasher = Sha384::new();
        hasher.update(data);
        let digest = hasher.finalize().to_vec();
        let digest_hex = hex::encode(&digest);
        // Add New Measurements Entry
        let mut measurements_log = MEASUREMENTS.read().unwrap().clone();
        let entry = MeasurementEntry {
            name,
            algorithm: "sha384".to_string(),
            digest: digest_hex,
        };
        info!("{}", format!("Measurement Entry: {:?}", &entry));
        measurements_log.push(entry);
        let mut measurements_writer = MEASUREMENTS.write().unwrap();
        *measurements_writer = measurements_log;
        // Extend MR Register Hash
        let mr_register = MR_REGISTER.read().unwrap().clone();
        let mr_register_value_bytes = hex::decode(mr_register)?;
        let mut hasher = Sha384::new();
        if !mr_register_value_bytes.is_empty() {
            hasher.update(mr_register_value_bytes.to_vec());
        }
        hasher.update(&digest);
        let new_mr_register = hex::encode(hasher.finalize().to_vec());
        info!("{}", format!("Updated MR Register: {new_mr_register}"));
        // Update MR Register
        let mut mr_register_writer = MR_REGISTER.write().unwrap();
        *mr_register_writer = new_mr_register;
        Ok(())
    }

    pub fn get_measurements(&self) -> Vec<MeasurementEntry> {
        let reader = MEASUREMENTS.read().unwrap();
        reader.clone()
    }

    pub fn read_mr_register(&self) -> String {
        let reader = MR_REGISTER.read().unwrap();
        reader.clone()
    }

    pub fn read_sys_report(&self) -> Result<String> {
        let machine_info = get_machine_info()?;
        let sys_report = serde_json::to_string(&machine_info)?;
        info!(
            "System Report: {}",
            serde_json::to_string_pretty(&machine_info)?
        );
        Ok(sys_report)
    }
}

impl SystemAttesterdInner {
    pub fn init(&self) -> Result<()> {
        info!("Initialize: measure Kernel and Initrams of this system...");
        let uname_output = std::process::Command::new("uname").arg("-r").output()?;
        let kernel_version = match uname_output.status.success() {
            true => String::from_utf8_lossy(&uname_output.stdout)
                .trim()
                .to_string(),
            false => bail!("Failed to get kernel version"),
        };
        let kernel_blob_path = format!("/boot/vmlinuz-{kernel_version}");
        let initramfs_img_path = format!("/boot/initramfs-{kernel_version}.img");
        let kernel_blob = std::fs::read(kernel_blob_path)
            .map_err(|e| anyhow!("Failed to read kernel blob: {e}"))?;
        let initramfs_blob = std::fs::read(initramfs_img_path)
            .map_err(|e| anyhow!("Failed to read initramfs blob: {e}"))?;
        self.measure("kernel".to_string(), kernel_blob)?;
        self.measure("initramfs".to_string(), initramfs_blob)?;
        Ok(())
    }
}

mod test {
    #[test]
    fn test_measure() {
        let attesterd = SystemAttesterdInner::default();
        let data = b"1234567890".to_vec();
        let result = attesterd.measure("test".to_string(), data.clone());
        assert!(result.is_ok());
        let mut hasher = Sha384::new();
        hasher.update(data);
        let digest = hasher.finalize().to_vec();
        let digest_hex = hex::encode(&digest);
        let mut hasher = Sha384::new();
        hasher.update(&digest);
        let new_mr_register = hex::encode(hasher.finalize().to_vec());
        let mr_register_read = attesterd.read_mr_register();
        assert_eq!(new_mr_register, mr_register_read);
        let entry = MeasurementEntry {
            name: "test".to_string(),
            algorithm: "sha384".to_string(),
            digest: digest_hex,
        };
        let measurement_entry = attesterd.get_measurements()[0].clone();
        assert_eq!(measurement_entry, entry);
    }

    #[test]
    fn test_init() {
        let attesterd = SystemAttesterdInner::default();
        let result = attesterd.init();
        let measurements = attesterd.get_measurements();
        let _measurements_str = serde_json::to_string(&measurements).unwrap();
        // std::fs::write(
        //     "./tests/data/init_measurements_output.txt",
        //     measurements_str,
        // )
        // .unwrap();
        assert!(result.is_ok());
    }

    #[test]
    fn test_read_sysreport() {
        let attesterd = SystemAttesterdInner::default();
        let result = attesterd.read_sys_report();
        assert!(result.is_ok());
        // std::fs::write("./tests/data/read_sysreport_output.txt", result.unwrap()).unwrap();
    }
}
