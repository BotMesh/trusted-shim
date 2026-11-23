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
    // A grace period is at most an hour.
    r.driver_options = json!({"stop_timeout_s":3601});
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

fn docker(args: &[&str]) -> std::process::Output {
    Command::new("/usr/bin/docker")
        .arg("--host=unix:///var/run/docker.sock")
        .args(args)
        .output()
        .unwrap()
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires local Docker and preloaded alpine:3.21"]
async fn real_docker_stop_waits_out_a_long_grace_period_without_blocking_inspect() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("private-state");
    let driver = DockerDriver::new(&state, "test-node".into()).unwrap();
    let mut r = request(&format!(
        "grace-{}",
        dir.path().file_name().unwrap().to_str().unwrap()
    ));
    // Exits cleanly 4 s after SIGTERM, within a grace period above 90 s.
    r.command = [
        "sh",
        "-c",
        "trap 'sleep 4; exit 0' TERM; while :; do sleep 1; done",
    ]
    .map(String::from)
    .into();
    r.driver_options = json!({"stop_timeout_s":600});
    let name = driver.launch(&r).await.unwrap().runtime_id;
    let id = inspect(&name)["Id"].clone();

    let started = std::time::Instant::now();
    let stopping = {
        let (driver, execution) = (driver.clone(), r.execution.clone());
        tokio::spawn(async move { driver.stop(&execution).await })
    };
    // The allocation stays observable while its container winds down.
    loop {
        let status = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            driver.inspect(&r.execution),
        )
        .await
        .expect("inspect answers during the grace period")
        .unwrap();
        if status.state == RuntimeState::Stopping {
            break;
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    // The stop is fenced before the grace period: nothing starts it again.
    assert!(matches!(
        driver.resume(&r.execution).await,
        Err(Error::Ownership)
    ));
    assert!(matches!(driver.launch(&r).await, Err(Error::Ownership)));
    stopping.await.unwrap().unwrap();
    assert!(started.elapsed() >= std::time::Duration::from_secs(3));
    let container = inspect(&name);
    assert_eq!(container["Id"], id);
    assert_eq!(container["State"]["Running"], false);
    // It exited on its own, not by SIGKILL.
    assert_eq!(container["State"]["ExitCode"], 0);
    assert_eq!(
        driver.inspect(&r.execution).await.unwrap().state,
        RuntimeState::Stopped
    );

    // Delete gives a running container the same grace period, then removes it.
    let mut d = request(&format!("{}-delete", r.execution.allocation_id));
    d.command = r.command.clone();
    d.driver_options = r.driver_options.clone();
    let deleted = driver.launch(&d).await.unwrap().runtime_id;
    let started = std::time::Instant::now();
    driver.delete(&d.execution).await.unwrap();
    assert!(started.elapsed() >= std::time::Duration::from_secs(3));
    assert!(!docker(&["inspect", &deleted]).status.success());
    driver.delete(&r.execution).await.unwrap();
}
