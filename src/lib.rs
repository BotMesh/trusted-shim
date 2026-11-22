//! Machine-local runtime and trust interfaces below zkm-fleet.
//!
//! Preflight action admission evaluates Rego and atomically persists a remote
//! proof job alongside a single-use ledger grant; receipt generation happens in
//! the background. Strict admission still verifies a proof before granting
//! runtime creation. Both paths consume exact-request grants before dispatch. Runtime
//! lifecycle includes Docker and TEE drivers. The always-present OpenShell access layer
//! adds no restrictions when no user rules exist. Its native client
//! calls its native private compute-driver API with durable ownership and
//! proof-grant consumption through the persistent private daemon. The
//! gateway protocol bindings are stateless; Fleet owns proof jobs, private
//! delivery and the native readiness join. Application route publication joins durable service admission and app health. There is no local prover.

pub use openshell::access;
pub mod admission;
pub mod attestation;
pub mod daemon;
pub mod data_plane;
pub mod docker;
pub mod ledger;
pub mod ledger_transport;
pub mod machine;
pub mod management;
pub mod network;
pub mod openshell;
pub use openshell::daemon as openshell_daemon;
pub(crate) use openshell::data_plane as openshell_data_plane;
pub use openshell::gateway as openshell_gateway;
pub use openshell::lifecycle as openshell_lifecycle;
pub use openshell::network as openshell_network;
pub use openshell::services as openshell_services;
pub mod proof;
pub mod provisioning;
pub mod registration;
pub mod runtime;
pub mod tee;
#[cfg(feature = "ziren")]
pub mod ziren;

pub use trusted_contracts as contracts;
pub use trusted_data_router::{Connector, ServiceSpec};
pub use trusted_rail as rail;
pub use trusted_rail::{AuthorizationLedger, PolicyProofCodec, RuleEngine};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("execution is not owned by this allocation")]
    Ownership,
    #[error("invalid runtime or trust contract")]
    InvalidContract,
    #[error("unsupported runtime or trust requirement")]
    Unsupported,
    #[error("runtime or trust service unavailable")]
    Unavailable,
    #[error("attestation, policy or proof verification rejected")]
    Untrusted,
}
