//! Proof-required admission and exact-request dispatch. The central ledger
//! remains the authority for current policy, lease, context and budget state.
use crate::{proof::*, runtime::ActionExecutor, Error, Result};
use async_trait::async_trait;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use trusted_contracts::ProofKind;
use trusted_rail::{
    rego::{encode_public_values, request_digest, RegorusEngine},
    *,
};

pub struct PolicyJob {
    request: ProofRequest,
    decision: DecisionRecord,
}
impl PolicyJob {
    pub fn id(&self) -> &str {
        &self.request.request_id
    }
    pub fn decision(&self) -> &DecisionRecord {
        &self.decision
    }
}

pub struct PolicyAdmission {
    network: Arc<dyn ProofNetwork>,
    verifier: Arc<dyn ReceiptVerifier>,
    ledger: Arc<dyn AuthorizationLedger>,
    program: ProgramRef,
}

fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| Error::Unavailable)
}
fn current(validity: &trusted_contracts::Validity) -> Result<()> {
    let now = now()?;
    if validity.not_before <= now && now < validity.expires_at {
        Ok(())
    } else {
        Err(Error::Untrusted)
    }
}

impl PolicyAdmission {
    pub fn new(
        network: Arc<dyn ProofNetwork>,
        verifier: Arc<dyn ReceiptVerifier>,
        ledger: Arc<dyn AuthorizationLedger>,
        program: ProgramRef,
    ) -> Result<Self> {
        if program.kind != ProofKind::PolicyEvaluation {
            return Err(Error::InvalidContract);
        }
        Ok(Self {
            network,
            verifier,
            ledger,
            program,
        })
    }

    /// Persist the caller-assigned job id and the authoritative policy/request
    /// BEFORE submit. Reconstruct with those same inputs after a process restart.
    /// No network request or local proving occurs here; only native evaluation.
    pub fn prepare(
        &self,
        job_id: &str,
        policy: &PolicyBundle,
        request: &EvaluationRequest,
    ) -> Result<PolicyJob> {
        current(&request.validity)?;
        let decision = RegorusEngine
            .evaluate(policy, request)
            .map_err(|_| Error::Untrusted)?;
        if decision.decision != Decision::Allow {
            return Err(Error::Untrusted);
        }
        let witness = RegorusEngine
            .encode_witness(policy, request)
            .map_err(|_| Error::InvalidContract)?;
        let expected_public_values =
            encode_public_values(&decision).map_err(|_| Error::InvalidContract)?;
        Ok(PolicyJob {
            request: ProofRequest {
                request_id: job_id.into(),
                program: self.program.clone(),
                witness,
                expected_public_values,
            },
            decision,
        })
    }

    /// Submit once; after ambiguous RPC failures query this job id before retrying.
    /// No automatic resubmission or implicit change of job identity occurs here.
    pub async fn submit(&self, job: &PolicyJob) -> Result<()> {
        self.check_job(job)?;
        let id = self.network.submit(&job.request).await?;
        if id != job.id() {
            return Err(Error::Untrusted);
        }
        Ok(())
    }

    /// Pending is not authorization. The ledger must independently validate this
    /// evidence and its current state before atomically issuing a single-use grant.
    pub async fn authorize(&self, job: &PolicyJob) -> Result<Option<ExecutionGrant>> {
        self.check_job(job)?;
        match self.network.status(job.id()).await? {
            ProofStatus::Pending => Ok(None),
            ProofStatus::Failed => Err(Error::Untrusted),
            ProofStatus::Complete(receipt) => {
                if receipt.job_id != job.id() {
                    return Err(Error::Untrusted);
                }
                self.verifier.verify(
                    &self.program,
                    &receipt,
                    &job.request.expected_public_values,
                )?;
                self.check_job(job)?; // proof verification may outlive validity
                let grant = self
                    .ledger
                    .reserve(&job.decision, Some(&receipt.encoded_receipt))
                    .await
                    .map_err(|_| Error::Untrusted)?;
                validate_grant(&grant, &job.decision)?;
                Ok(Some(grant))
            }
        }
    }
    fn check_job(&self, job: &PolicyJob) -> Result<()> {
        if job.request.program != self.program || job.decision.decision != Decision::Allow {
            return Err(Error::Untrusted);
        }
        current(&job.decision.validity)
    }
}

fn validate_grant(grant: &ExecutionGrant, decision: &DecisionRecord) -> Result<()> {
    if grant.id.is_empty()
        || grant.credential.is_empty()
        || grant.execution != decision.execution
        || grant.request_sha256 != decision.request_sha256
        || grant.validity.not_before < decision.validity.not_before
        || grant.validity.expires_at > decision.validity.expires_at
    {
        return Err(Error::Untrusted);
    }
    current(&grant.validity)
}

/// Implement with the trusted runtime's native enforcement interface. Hold the
/// handler exclusively behind AuthorizedExecutor: an arbitrary shell in a plain
/// Docker container is not made non-bypassable by this Rust wrapper.
#[async_trait]
pub trait ActionHandler: Send + Sync {
    async fn run(&self, request: &EvaluationRequest) -> Result<Vec<u8>>;
}
pub struct AuthorizedExecutor {
    ledger: Arc<dyn AuthorizationLedger>,
    handler: Arc<dyn ActionHandler>,
}
impl AuthorizedExecutor {
    pub fn new(ledger: Arc<dyn AuthorizationLedger>, handler: Arc<dyn ActionHandler>) -> Self {
        Self { ledger, handler }
    }
}
#[async_trait]
impl ActionExecutor for AuthorizedExecutor {
    async fn execute(
        &self,
        request: &EvaluationRequest,
        grant: &ExecutionGrant,
    ) -> Result<Vec<u8>> {
        current(&request.validity)?;
        current(&grant.validity)?;
        let digest = request_digest(request).map_err(|_| Error::InvalidContract)?;
        if grant.id.is_empty()
            || grant.credential.is_empty()
            || grant.execution != request.execution
            || grant.request_sha256 != digest
            || grant.validity.not_before < request.validity.not_before
            || grant.validity.expires_at > request.validity.expires_at
        {
            return Err(Error::Untrusted);
        }
        self.ledger
            .consume(grant, &request.execution, &digest)
            .await
            .map_err(|_| Error::Untrusted)?;
        // An execution failure never refunds or reuses the consumed grant; the
        // gateway must reconcile the outcome before authorizing another action.
        current(&grant.validity)?;
        self.handler.run(request).await
    }
}
