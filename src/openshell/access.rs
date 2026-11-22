//! The always-present access layer is independent of runtime infrastructure.
//! An absent user policy adds no restriction to the driver's own boundary.
//! A configured policy must be enforced by the native OpenShell boundary;
//! failures must never turn it into the unrestricted default.
use crate::{runtime::LaunchRequest, Error, Result};

pub fn validate(request: &LaunchRequest) -> Result<()> {
    if let Some(hash) = &request.access_policy_sha256 {
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::InvalidContract);
        }
    }
    Ok(())
}

pub fn requires_native(request: &LaunchRequest) -> bool {
    // Compatibility for already prepared envelopes and durable allocations.
    request.access_policy_sha256.is_some() || request.driver == "openshell"
}

pub fn driver_bounds(request: &LaunchRequest) -> Result<()> {
    validate(request)?;
    if requires_native(request) {
        return Err(Error::Unsupported);
    }
    Ok(())
}

pub fn native_policy(request: &LaunchRequest, actual_sha256: &str) -> Result<()> {
    validate(request)?;
    match request.access_policy_sha256.as_deref() {
        Some(expected) if expected == actual_sha256 => Ok(()),
        None if request.driver == "openshell" => Ok(()),
        _ => Err(Error::Untrusted),
    }
}
