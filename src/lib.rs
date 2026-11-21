//! Machine-local runtime and trust interfaces below zkm-fleet.
//!
//! Policy admission evaluates Rego, requests a remote proof, verifies its exact
//! public values and consumes a central ledger grant before dispatch. Runtime
//! lifecycle includes an opt-in Docker driver. Attestation and OpenShell adapters
//! remain interfaces. There is no local prover.

pub mod admission;
pub mod attestation;
pub mod data_plane;
pub mod docker;
pub mod network;
pub mod proof;
pub mod runtime;
#[cfg(feature = "ziren")]
pub mod ziren;

pub use trusted_contracts as contracts;
pub use trusted_data_router::{Connector, ServiceSpec};
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
