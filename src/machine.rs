//! Local deployment hints and device discovery, never attestation evidence.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, os::unix::fs::FileTypeExt, path::Path};

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineConfig {
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tee: Option<crate::tee::TeeConfig>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TeePlatform {
    #[serde(rename = "amd-sev-snp")]
    AmdSevSnp,
    #[serde(rename = "intel-tdx")]
    IntelTdx,
    #[serde(rename = "intel-sgx")]
    IntelSgx,
}

/// Interfaces visible to this process. SGX is enclave capability on the host;
/// SNP/TDX are guest interfaces. None proves that a workload is inside a TEE.
pub fn detect() -> Result<Vec<TeePlatform>> {
    detect_devices(Path::new("/dev"))
}

pub fn detect_devices(root: &Path) -> Result<Vec<TeePlatform>> {
    let mut found = Vec::new();
    for (platform, paths) in [
        (TeePlatform::AmdSevSnp, &["sev-guest"][..]),
        (TeePlatform::IntelTdx, &["tdx_guest"][..]),
        (TeePlatform::IntelSgx, &["sgx_enclave", "sgx/enclave"][..]),
    ] {
        for path in paths {
            match std::fs::symlink_metadata(root.join(path)) {
                Ok(metadata) if metadata.file_type().is_char_device() => {
                    found.push(platform);
                    break;
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(Error::Unavailable),
            }
        }
    }
    Ok(found)
}

#[derive(Serialize)]
pub struct MachineProfile {
    pub labels: BTreeMap<String, String>,
    pub tee_interfaces: Vec<TeePlatform>,
    pub attestation_verified: bool,
    pub tee_driver_configured: bool,
    pub drivers: Vec<String>,
}

impl MachineConfig {
    pub fn digest(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(crate::tee::canonical(self)?)))
    }

    /// Resolve operator intent against local discovery and configured backends.
    /// Hardware discovery never supplies verifier trust roots or substitutes for evidence.
    pub fn resolve(&self, detected: Vec<TeePlatform>, openshell: bool) -> Result<MachineProfile> {
        if self.labels.len() > 64
            || self.labels.iter().any(|(k, v)| {
                k.is_empty()
                    || k.len() > 128
                    || v.len() > 256
                    || k.contains('\0')
                    || v.contains('\0')
            })
        {
            return Err(Error::InvalidContract);
        }
        let selected = self
            .labels
            .get("runtime.driver")
            .map(String::as_str)
            .unwrap_or("auto");
        let expected = self
            .labels
            .get("tee.platform")
            .map(String::as_str)
            .unwrap_or("auto");
        let mut drivers = Vec::<String>::new();
        if let Some(tee) = &self.tee {
            tee.validate()?;
            if !matches!(selected, "auto" | "tee" | "tee-simulation")
                || (selected != "auto" && selected != tee.driver())
            {
                return Err(Error::InvalidContract);
            }
            let platform = match tee.platform.as_str() {
                "snp" => Some(TeePlatform::AmdSevSnp),
                "tdx" => Some(TeePlatform::IntelTdx),
                "sample" => None,
                _ => return Err(Error::Unsupported),
            };
            let name = match platform {
                Some(TeePlatform::AmdSevSnp) => "amd-sev-snp",
                Some(TeePlatform::IntelTdx) => "intel-tdx",
                _ => "sample",
            };
            if expected != "auto" && expected != name {
                return Err(Error::InvalidContract);
            }
            if platform.is_some_and(|p| !detected.contains(&p)) {
                return Err(Error::Untrusted);
            }
            // A native OpenShell driver has its own provisioning path; do not
            // advertise it on a node whose only configured trust gate is TEE.
            if openshell {
                return Err(Error::Unsupported);
            }
            drivers.push(tee.driver().into());
        } else {
            if !matches!(expected, "auto" | "none") {
                return Err(Error::Unsupported);
            }
            match selected {
                // Visible TEE interfaces require explicit operator configuration.
                "auto" if !detected.is_empty() && expected != "none" => {
                    return Err(Error::Unsupported)
                }
                "auto" => {
                    drivers.push("docker".into());
                    if openshell {
                        drivers.push("openshell".into());
                    }
                }
                "docker" if !openshell => drivers.push("docker".into()),
                "openshell" if openshell => drivers.push("openshell".into()),
                "docker" | "openshell" | "tee" | "tee-simulation" => {
                    return Err(Error::Unsupported)
                }
                _ => return Err(Error::InvalidContract),
            }
        }
        Ok(MachineProfile {
            labels: self.labels.clone(),
            tee_interfaces: detected,
            attestation_verified: false,
            tee_driver_configured: self.tee.is_some(),
            drivers,
        })
    }
}
