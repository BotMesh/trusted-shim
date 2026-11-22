use serde_json::json;
use sha2::Digest;
use std::process::Command;
use trusted_shim::{
    docker::DockerDriver,
    runtime::{LaunchRequest, RuntimeDriver, RuntimeState},
    Error,
};

fn request(id: &str) -> LaunchRequest {
    serde_json::from_value(json!({
        "execution": {"namespace":"test", "workload":"docker", "allocation_id":id,
            "lease_id":"one", "generation":1, "node_id":"test-node"},
        "driver":"docker", "image":"alpine:3.21", "command":["sleep","300"],
        "environment":{"SYNTHETIC_SECRET":"must-not-be-in-argv"},
        "limits":{"cpu_millicores":250,"memory_bytes":33554432},
        "policy":{"issuer":"test","policy_id":"no-policy-claim","version":0,"sha256":""},
        "trust":{"attestation":{"mode":"skip_non_tee"},"policy_proof":"not_required","attestation_proof":"not_required"},
        "services":[], "driver_options":{"stop_timeout_s":1}
    })).unwrap()
}

#[tokio::test]
async fn unsupported_trust_and_driver_requirements_never_create_state() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("private-state");
    let driver = DockerDriver::new(&state, "test-node".into()).unwrap();
    let mut r = request("rejected");
    r.trust.policy_proof = trusted_shim::proof::ProofRequirement::Required;
    assert!(matches!(driver.launch(&r).await, Err(Error::Unsupported)));
    r.trust.policy_proof = trusted_shim::proof::ProofRequirement::NotRequired;
    r.driver = "openshell".into();
    assert!(matches!(driver.launch(&r).await, Err(Error::Unsupported)));
    r.driver = "docker".into();
    assert!(r.access_policy_sha256.is_none());
    assert!(serde_json::to_value(&r)
        .unwrap()
        .get("access_policy_sha256")
        .is_none());
    trusted_shim::access::driver_bounds(&r).unwrap();
    r.access_policy_sha256 = Some("ab".repeat(32));
    assert!(matches!(driver.launch(&r).await, Err(Error::Unsupported)));
    r.access_policy_sha256 = None;
    r.driver_options = json!({"privileged":true});
    assert!(matches!(
        driver.launch(&r).await,
        Err(Error::InvalidContract)
    ));
    assert_eq!(std::fs::read_dir(&state).unwrap().count(), 0);
}

fn inspect(name: &str) -> serde_json::Value {
    let out = Command::new("/usr/bin/docker")
        .args(["--host=unix:///var/run/docker.sock", "inspect", name])
        .output()
        .unwrap();
    assert!(out.status.success());
    serde_json::from_slice::<Vec<serde_json::Value>>(&out.stdout)
        .unwrap()
        .remove(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local Docker and preloaded alpine:3.21"]
async fn real_docker_limits_recovery_replay_and_generation_fences() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("private-state");
    let driver = DockerDriver::new(&state, "test-node".into()).unwrap();
    let mut r = request(&format!(
        "smoke-{}",
        dir.path().file_name().unwrap().to_str().unwrap()
    ));
    let (a, b) = tokio::join!(driver.launch(&r), driver.launch(&r));
    let status = a.unwrap();
    assert_eq!(status.runtime_id, b.unwrap().runtime_id);
    let before = inspect(&status.runtime_id);
    assert_eq!(before["HostConfig"]["NanoCpus"], 250_000_000u64);
    assert_eq!(before["HostConfig"]["Memory"], 33_554_432u64);
    assert_eq!(before["HostConfig"]["MemorySwap"], 33_554_432u64);
    assert_eq!(before["HostConfig"]["RestartPolicy"]["Name"], "no");
    let cgroup = Command::new("/usr/bin/docker").args(["exec", &status.runtime_id,"sh","-c",
        "if [ -f /sys/fs/cgroup/cpu.max ]; then cat /sys/fs/cgroup/cpu.max /sys/fs/cgroup/memory.max; else cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us /sys/fs/cgroup/cpu/cpu.cfs_period_us /sys/fs/cgroup/memory/memory.limit_in_bytes; fi"]).output().unwrap();
    assert!(cgroup.status.success());
    let values: Vec<u64> = std::str::from_utf8(&cgroup.stdout)
        .unwrap()
        .split_whitespace()
        .map(|v| v.parse().unwrap())
        .collect();
    assert_eq!(values[0] * 4, values[1]);
    assert_eq!(values[2], 33_554_432);
    let recovered = DockerDriver::new(&state, "test-node".into()).unwrap();
    assert_eq!(
        recovered.launch(&r).await.unwrap().state,
        RuntimeState::Ready
    );
    assert_eq!(
        inspect(&status.runtime_id)["State"]["StartedAt"],
        before["State"]["StartedAt"]
    );
    let mut changed = r.clone();
    changed.command = vec!["false".into()];
    assert!(matches!(
        recovered.launch(&changed).await,
        Err(Error::Ownership)
    ));
    changed.execution.lease_id = "foreign".into();
    assert!(matches!(
        recovered.delete(&changed.execution).await,
        Err(Error::Ownership)
    ));
    assert_eq!(inspect(&status.runtime_id)["Id"], before["Id"]);
    // Simulate a process dying after Docker start and before the journal commit.
    for entry in std::fs::read_dir(&state).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|s| s == "json") {
            let mut value: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            value["phase"] = json!("starting");
            std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
        }
    }
    recovered.launch(&r).await.unwrap();
    assert_eq!(
        inspect(&status.runtime_id)["State"]["StartedAt"],
        before["State"]["StartedAt"]
    );
    recovered.stop(&r.execution).await.unwrap();
    assert!(matches!(recovered.launch(&r).await, Err(Error::Ownership)));
    recovered.delete(&r.execution).await.unwrap();
    recovered.delete(&r.execution).await.unwrap();
    assert!(matches!(recovered.launch(&r).await, Err(Error::Ownership)));
    let old = r.execution.clone();
    r.execution.generation += 1;
    r.execution.lease_id = "two".into();
    recovered.launch(&r).await.unwrap();
    assert!(matches!(
        recovered.delete(&old).await,
        Err(Error::Ownership)
    ));
    // External disappearance cannot turn the same lease into a new execution.
    assert!(Command::new("/usr/bin/docker")
        .args([
            "--host=unix:///var/run/docker.sock",
            "rm",
            "-f",
            &status.runtime_id
        ])
        .status()
        .unwrap()
        .success());
    assert_eq!(
        recovered.launch(&r).await.unwrap().state,
        RuntimeState::Failed
    );
    // An ambiguous pending start must not resend Docker start, even if the
    // daemon still reports created (the original call may still be in flight).
    let record_path = std::fs::read_dir(&state)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|s| s == "json"))
        .unwrap();
    let mut record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();
    record["phase"] = json!("starting");
    std::fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();
    let execution_hash = hex::encode(sha2::Sha256::digest(
        serde_json::to_vec(&{
            let mut v = serde_json::to_value(&r.execution).unwrap();
            v.sort_all_objects();
            v
        })
        .unwrap(),
    ));
    let created = Command::new("/usr/bin/docker")
        .args([
            "create",
            "--name",
            &status.runtime_id,
            "--label",
            &format!("trusted-shim.execution={execution_hash}"),
            "--label",
            &format!(
                "trusted-shim.request={}",
                record["request_sha256"].as_str().unwrap()
            ),
            "--cpus",
            "0.25",
            "--memory",
            "33554432",
            "--memory-swap",
            "33554432",
            "alpine:3.21",
            "sleep",
            "300",
        ])
        .output()
        .unwrap();
    assert!(created.status.success());
    assert!(matches!(recovered.launch(&r).await, Err(Error::Untrusted)));
    assert_eq!(inspect(&status.runtime_id)["State"]["Status"], "created");
    recovered.delete(&r.execution).await.unwrap();
    let mut stopped_before_launch = request(&format!("{}-early", r.execution.allocation_id));
    recovered
        .delete(&stopped_before_launch.execution)
        .await
        .unwrap();
    assert!(matches!(
        recovered.launch(&stopped_before_launch).await,
        Err(Error::Ownership)
    ));
    stopped_before_launch.execution.generation += 1;
    stopped_before_launch.execution.lease_id = "later".into();
    recovered.launch(&stopped_before_launch).await.unwrap();
    recovered
        .delete(&stopped_before_launch.execution)
        .await
        .unwrap();
}
