//! Machine-local runtime and trust framework below zkm-fleet.
//!
//! Traits only: there is no scheduler, Docker/OpenShell implementation, local
//! prover, permissive proof verifier or runnable node daemon in this revision.

pub mod attestation;
pub mod proof;
pub mod runtime;

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
