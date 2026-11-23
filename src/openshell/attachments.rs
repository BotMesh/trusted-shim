//! GPU and durable-storage attachments for the unmodified native Docker driver.
//! Fleet/Ray choose the GPUs and the admitted app manifest chooses the mounts;
//! this module only translates them into upstream's exact CDI device and named
//! volume forms, and binds the gateway's native bytes to that translation.
use crate::{
    runtime::{DurableMount, LaunchRequest},
    Error, Result,
};
use openshell_core::resource_admission::DriverAdmissionConfig;
use prost_types::{value::Kind, ListValue, Struct, Value};
use std::{collections::BTreeMap, process::Stdio, time::Duration};

/// Upstream's CDI name for NVIDIA devices; Ray ids are the device indexes.
const CDI_GPU_PREFIX: &str = "nvidia.com/gpu=";
/// Upstream substitutes this whole label value with the sandbox workspace.
const WORKSPACE_PLACEHOLDER: &str = "${workspace}";
const MAX_ATTACHMENTS: usize = 16;

fn string(value: impl Into<String>) -> Value {
    Value {
        kind: Some(Kind::StringValue(value.into())),
    }
}

/// Shape checks only. Fleet separately binds GPUs to Ray's grant and mounts
/// to the admitted manifest before any launch reaches a node.
pub(crate) fn validate(request: &LaunchRequest) -> Result<()> {
    let mut gpus = std::collections::BTreeSet::new();
    let mut names = std::collections::BTreeSet::new();
    let mut targets = std::collections::BTreeSet::new();
    if request.gpus.len() > MAX_ATTACHMENTS
        || request.mounts.len() > MAX_ATTACHMENTS
        || request.gpus.iter().any(|id| {
            id.is_empty()
                || id.len() > 64
                || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                || !gpus.insert(id)
        })
        || request.mounts.iter().any(|m| {
            !valid_name(&m.name)
                || !valid_target(&m.target)
                || !names.insert(&m.name)
                || !targets.insert(&m.target)
        })
    {
        return Err(Error::InvalidContract);
    }
    Ok(())
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn valid_target(target: &str) -> bool {
    target.len() <= 1024
        && target.starts_with('/')
        && target
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'\\' && b != b',' && b != b':')
        && target[1..]
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

/// Stable across generations, so data survives replacement and resume, but
/// scoped to one workload: another workload cannot name this volume.
pub fn volume_name(request: &LaunchRequest, mount: &DurableMount) -> Result<String> {
    let digest = trusted_rail::rego::commitment(
        "trusted-shim.openshell.volume.v1",
        &(
            &request.execution.namespace,
            &request.execution.workload,
            &mount.name,
        ),
    )
    .map_err(|_| Error::InvalidContract)?;
    Ok(format!("fleet-{}", &digest[..40]))
}

/// The selected driver's inner `driver_config`, exactly as upstream forwards it.
pub(crate) fn driver_config(request: &LaunchRequest) -> Result<Option<Struct>> {
    let mut fields = BTreeMap::new();
    if !request.gpus.is_empty() {
        let devices = request
            .gpus
            .iter()
            .map(|id| string(format!("{CDI_GPU_PREFIX}{id}")))
            .collect();
        fields.insert(
            "cdi_devices".to_owned(),
            Value {
                kind: Some(Kind::ListValue(ListValue { values: devices })),
            },
        );
    }
    if !request.mounts.is_empty() {
        let mut mounts = Vec::new();
        for mount in &request.mounts {
            mounts.push(Value {
                kind: Some(Kind::StructValue(Struct {
                    fields: BTreeMap::from([
                        ("type".to_owned(), string("volume")),
                        ("source".to_owned(), string(volume_name(request, mount)?)),
                        ("target".to_owned(), string(mount.target.clone())),
                        (
                            "read_only".to_owned(),
                            Value {
                                kind: Some(Kind::BoolValue(mount.read_only)),
                            },
                        ),
                    ]),
                })),
            });
        }
        fields.insert(
            "mounts".to_owned(),
            Value {
                kind: Some(Kind::ListValue(ListValue { values: mounts })),
            },
        );
    }
    Ok((!fields.is_empty()).then_some(Struct { fields }))
}

/// The public envelope keyed by the active compute driver.
pub(crate) fn public_driver_config(request: &LaunchRequest) -> Result<Option<Struct>> {
    Ok(driver_config(request)?.map(|inner| Struct {
        fields: BTreeMap::from([(
            "docker".to_owned(),
            Value {
                kind: Some(Kind::StructValue(inner)),
            },
        )]),
    }))
}

/// Exactly one GPU per granted device; never a driver-chosen default.
pub(crate) fn gpu_count(request: &LaunchRequest) -> Option<u32> {
    (!request.gpus.is_empty()).then_some(request.gpus.len() as u32)
}

async fn docker(args: &[&str]) -> Result<Vec<u8>> {
    // Same pinned local daemon as the Docker runtime path. Workload environment
    // cannot redirect DOCKER_HOST or a context. Never log argv or Docker errors.
    let mut command = tokio::process::Command::new("/usr/bin/docker");
    command
        .arg("--host=unix:///var/run/docker.sock")
        .args(args)
        .env_remove("DOCKER_CONTEXT")
        .env_remove("DOCKER_HOST")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(60), command.output())
        .await
        .map_err(|_| Error::Unavailable)?
        .map_err(|_| Error::Unavailable)?;
    if !output.status.success() {
        return Err(Error::Unavailable);
    }
    Ok(output.stdout)
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Volume {
    driver: String,
    #[serde(default)]
    labels: Option<BTreeMap<String, String>>,
    #[serde(default)]
    options: Option<BTreeMap<String, String>>,
}

async fn inspect(name: &str) -> Result<Option<Volume>> {
    // `inspect` alone cannot distinguish absence from an unavailable daemon.
    let filter = format!("name=^{name}$");
    let listed = docker(&["volume", "ls", "-q", "--filter", &filter]).await?;
    if !String::from_utf8_lossy(&listed)
        .split_whitespace()
        .any(|v| v == name)
    {
        return Ok(None);
    }
    let raw = docker(&["volume", "inspect", "--format", "{{json .}}", name]).await?;
    serde_json::from_slice(&raw)
        .map(Some)
        .map_err(|_| Error::Unavailable)
}

/// Idempotently provision each durable volume with the labels the node's
/// upstream admission policy requires for this workspace. Existing volumes are
/// never relabeled or adopted unless upstream admission already accepts them,
/// and must be plain local volumes, not host binds. Volumes are never removed
/// here: cleanup of a runtime keeps its data for later generations.
pub(crate) async fn ensure_volumes(request: &LaunchRequest, admission_policy: &str) -> Result<()> {
    if request.mounts.is_empty() {
        return Ok(());
    }
    let admission: DriverAdmissionConfig = serde_json::from_str(
        admission_policy
            .strip_prefix("v1:")
            .ok_or(Error::Untrusted)?,
    )
    .map_err(|_| Error::Untrusted)?;
    admission.validate().map_err(|_| Error::Untrusted)?;
    if !admission.allow_driver_config {
        return Err(Error::Unsupported);
    }
    let workspace = crate::openshell_gateway::workspace_name(&request.execution.namespace);
    let mut labels: BTreeMap<String, String> = admission
        .resource_admission
        .required_labels
        .iter()
        .map(|(k, v)| {
            let value = if v == WORKSPACE_PLACEHOLDER {
                workspace.clone()
            } else {
                v.clone()
            };
            (k.clone(), value)
        })
        .collect();
    labels.insert("trusted-shim.openshell/volume".into(), "v1".into());
    for mount in &request.mounts {
        let name = volume_name(request, mount)?;
        if inspect(&name).await?.is_none() {
            let mut args = vec!["volume", "create", "--driver", "local"];
            let pairs: Vec<String> = labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
            for pair in &pairs {
                args.extend(["--label", pair.as_str()]);
            }
            args.push(&name);
            docker(&args).await?;
        }
        // Verify what the daemon holds, including after a concurrent create.
        let volume = inspect(&name).await?.ok_or(Error::Unavailable)?;
        let held = volume.labels.unwrap_or_default();
        if volume.driver != "local"
            || volume.options.is_some_and(|o| !o.is_empty())
            || held
                .get("trusted-shim.openshell/volume")
                .map(String::as_str)
                != Some("v1")
            || (admission.resource_admission.enabled
                && admission
                    .resource_admission
                    .admit(&workspace, &held)
                    .is_err())
        {
            return Err(Error::Untrusted);
        }
    }
    Ok(())
}
