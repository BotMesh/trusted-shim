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
    // Native OpenShell attachments are never silently dropped by this path,
    // and their omission keeps the existing launch serialization unchanged.
    assert!(serde_json::to_value(&r).unwrap().get("gpus").is_none());
    assert!(serde_json::to_value(&r).unwrap().get("mounts").is_none());
    r.gpus = vec!["0".into()];
    assert!(matches!(driver.launch(&r).await, Err(Error::Unsupported)));
    r.gpus.clear();
    r.mounts = vec![serde_json::from_value(json!({"name":"state","target":"/state"})).unwrap()];
    assert!(matches!(driver.launch(&r).await, Err(Error::Unsupported)));
    r.mounts.clear();
    r.driver_options = json!({"privileged":true});
    assert!(matches!(
        driver.launch(&r).await,
        Err(Error::InvalidContract)
    ));
    r.driver_options = json!({"stop_timeout_s":1});
    // Docker would clamp a CPU weight outside its range; it is refused instead.
    for invalid in [0, 1, 262_145] {
        r.limits.cpu_shares = Some(invalid);
        assert!(matches!(
            driver.launch(&r).await,
            Err(Error::InvalidContract)
        ));
    }
    assert_eq!(std::fs::read_dir(&state).unwrap().count(), 0);
}

/// The Docker journal and label digest, the TEE binding and the policy grant
/// digest all serialize the launch request. A request that sets none of the
/// optional fields keeps these exact bytes, so existing allocations replay.
#[test]
fn launch_request_without_optional_fields_keeps_its_serialized_form() {
    let mut r = request("pinned");
    let bytes = serde_json::to_vec(&r).unwrap();
    assert_eq!(
        serde_json::to_value(&r).unwrap()["limits"],
        json!({"cpu_millicores":250,"memory_bytes":33554432})
    );
    assert_eq!(
        hex::encode(sha2::Sha256::digest(&bytes)),
        "a22f1177d8efd59ac9e4a4493e2fa6b88317dcfb77f621d4e00227313e3f2675"
    );
    // An explicit null CPU weight is the same request as an absent one.
    let mut null = serde_json::to_value(&r).unwrap();
    null["limits"]["cpu_shares"] = serde_json::Value::Null;
    let null: LaunchRequest = serde_json::from_value(null).unwrap();
    assert_eq!(serde_json::to_vec(&null).unwrap(), bytes);
    r.limits.cpu_millicores = None;
    r.limits.memory_bytes = None;
    assert_eq!(
        serde_json::to_value(&r).unwrap()["limits"],
        json!({"cpu_millicores":null,"memory_bytes":null})
    );
    assert_eq!(
        hex::encode(sha2::Sha256::digest(serde_json::to_vec(&r).unwrap())),
        "370b3ff5d498a3fe5cb5bedf0105762231ee3a2aeeba95b01747fa00a1a01263"
    );
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

fn docker(args: &[&str]) -> std::process::Output {
    Command::new("/usr/bin/docker")
        .arg("--host=unix:///var/run/docker.sock")
        .args(args)
        .output()
        .unwrap()
}

/// The container's own CPU weight: cgroup v2 `cpu.weight`, or v1 `cpu.shares`.
fn cpu_weight(name: &str) -> u64 {
    let out = docker(&[
        "exec",
        name,
        "sh",
        "-c",
        "cat /sys/fs/cgroup/cpu.weight 2>/dev/null || cat /sys/fs/cgroup/cpu/cpu.shares",
    ]);
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout).trim().parse().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local Docker and preloaded alpine:3.21"]
async fn real_docker_cpu_shares_set_the_cgroup_weight() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("private-state");
    let driver = DockerDriver::new(&state, "test-node".into()).unwrap();
    let suffix = dir.path().file_name().unwrap().to_str().unwrap().to_owned();
    // Unset, Docker reports 0 and the container keeps the default weight.
    let unweighted = request(&format!("unweighted-{suffix}"));
    let status = driver.launch(&unweighted).await.unwrap();
    assert_eq!(status.effective_limits.cpu_shares, None);
    assert_eq!(inspect(&status.runtime_id)["HostConfig"]["CpuShares"], 0u64);
    let default = cpu_weight(&status.runtime_id);
    driver.delete(&unweighted.execution).await.unwrap();

    let mut weighted = request(&format!("weighted-{suffix}"));
    weighted.limits.cpu_shares = Some(64);
    let status = driver.launch(&weighted).await.unwrap();
    assert_eq!(status.effective_limits.cpu_shares, Some(64));
    assert_eq!(
        inspect(&status.runtime_id)["HostConfig"]["CpuShares"],
        64u64
    );
    assert!(cpu_weight(&status.runtime_id) < default);
    // A weight changed outside the shim is not the committed launch.
    assert!(
        docker(&["update", "--cpu-shares", "1024", &status.runtime_id])
            .status
            .success()
    );
    assert!(matches!(
        driver.inspect(&weighted.execution).await,
        Err(Error::Untrusted)
    ));
    driver.delete(&weighted.execution).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local Docker and preloaded alpine:3.21"]
async fn real_docker_resume_restarts_only_a_crashed_runtime_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("private-state");
    let driver = DockerDriver::new(&state, "test-node".into()).unwrap();
    let r = request(&format!(
        "resume-{}",
        dir.path().file_name().unwrap().to_str().unwrap()
    ));
    let name = driver.launch(&r).await.unwrap().runtime_id;
    let id = inspect(&name)["Id"].clone();
    assert!(docker(&[
        "exec",
        &name,
        "sh",
        "-c",
        "echo kept > /written-before-crash"
    ])
    .status
    .success());

    // A running container is left alone.
    let started = inspect(&name)["State"]["StartedAt"].clone();
    assert_eq!(
        driver.resume(&r.execution).await.unwrap().state,
        RuntimeState::Ready
    );
    assert_eq!(inspect(&name)["State"]["StartedAt"], started);

    // A crash: the same container comes back, with its writable layer.
    assert!(docker(&["kill", &name]).status.success());
    assert_eq!(
        driver.inspect(&r.execution).await.unwrap().state,
        RuntimeState::Stopped
    );
    let recovered = DockerDriver::new(&state, "test-node".into()).unwrap();
    assert_eq!(
        recovered.resume(&r.execution).await.unwrap().state,
        RuntimeState::Ready
    );
    assert_eq!(inspect(&name)["Id"], id);
    let kept = docker(&["exec", &name, "cat", "/written-before-crash"]);
    assert_eq!(String::from_utf8_lossy(&kept.stdout).trim(), "kept");

    // Another allocation cannot resume it.
    let mut foreign = r.execution.clone();
    foreign.lease_id = "foreign".into();
    assert!(recovered.resume(&foreign).await.is_err());

    // A stop is final: resume never undoes it.
    recovered.stop(&r.execution).await.unwrap();
    assert!(matches!(
        recovered.resume(&r.execution).await,
        Err(Error::Ownership)
    ));
    assert_eq!(inspect(&name)["State"]["Running"], false);

    // A missing container is never substituted.
    let gone = request(&format!("{}-gone", r.execution.allocation_id));
    let gone_name = recovered.launch(&gone).await.unwrap().runtime_id;
    assert!(docker(&["rm", "-f", &gone_name]).status.success());
    assert!(matches!(
        recovered.resume(&gone.execution).await,
        Err(Error::Ownership)
    ));
    assert!(!docker(&["inspect", &gone_name]).status.success());

    recovered.delete(&r.execution).await.unwrap();
    assert!(matches!(
        recovered.resume(&r.execution).await,
        Err(Error::Ownership)
    ));
    recovered.delete(&gone.execution).await.unwrap();
}
