//! Native admission with a durable remote-proof outbox. This is an operator API,
//! never an agent-selected downgrade of proof-required runtime creation.
use super::*;
use crate::proof::{ProofNetwork, ProofRequest, ProofStatus};
use serde::Serialize;

const MAX_OUTSTANDING: i64 = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightReceiptState {
    Queued,
    Proving,
    Verified,
    Failed,
}
impl PreflightReceiptState {
    fn parse(s: &str) -> Result<Self> {
        match s {
            "queued" => Ok(Self::Queued),
            "proving" => Ok(Self::Proving),
            "verified" => Ok(Self::Verified),
            "failed" => Ok(Self::Failed),
            _ => Err(Error::Unavailable),
        }
    }
}

/// A native decision is not a completed proof. The optional grant is secret and
/// only exists for Allow; denied and approval-required decisions are also proved.
pub struct PreflightDecision {
    pub decision: DecisionRecord,
    pub grant: Option<ExecutionGrant>,
    pub receipt_state: PreflightReceiptState,
}

impl SqliteLedger {
    /// Evaluate the currently activated policy and atomically persist its exact
    /// witness, decision, budget reservation and grant before returning Allow.
    /// The embedding scheduler must retain its live allocation guard throughout.
    pub fn preflight(
        &self,
        job_id: &str,
        request: &EvaluationRequest,
        cost: u64,
    ) -> Result<PreflightDecision> {
        if !crate::network::valid_job_id(job_id)
            || cost == 0
            || request.operation.starts_with("runtime.")
        {
            return Err(Error::InvalidInput);
        }
        let mut c = self.connection.lock().map_err(|_| Error::Unavailable)?;
        let tx = db(c.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let key = execution_key(&request.execution)?;
        let (p, context, root, epoch, budget): (String, String, String, i64, String) =
            db(tx.query_row(
                "SELECT policy,context,root,epoch,budget FROM authorities WHERE execution=?1 AND active=1",
                params![key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            ))?;
        if context != text(&request.context)? || root != request.previous_state_root {
            return Err(Error::Conflict);
        }
        let policy: PolicyBundle = serde_json::from_str(&p).map_err(|_| Error::Unavailable)?;
        let decision = RegorusEngine.evaluate(&policy, request)?;
        let time = now()?;
        if time < decision.validity.not_before || time >= decision.validity.expires_at {
            return Err(Error::Rejected);
        }
        let r = text(request)?;
        let d = text(&decision)?;
        let witness = RegorusEngine.encode_witness(&policy, request)?;
        let public = encode_public_values(&decision)?;
        let existing: Option<(String, String, i64, i64, i64, String)> = db(tx
            .query_row(
                "SELECT a.request,a.decision,a.cost,a.epoch,a.state,p.status FROM actions a
             JOIN preflight_receipts p ON a.id=p.id WHERE a.id=?1",
                params![job_id],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )
            .optional())?;
        let receipt_state =
            if let Some((old_r, old_d, old_cost, old_epoch, state, status)) = existing {
                if (old_r, old_d, old_cost, old_epoch) != (r, d, amount(cost)?, epoch)
                    || state == 2
                    || status == "failed"
                {
                    return Err(Error::Conflict);
                }
                PreflightReceiptState::parse(&status)?
            } else {
                // Never convert a staged strict request into a preflight grant, or
                // reuse an action ID under a different proof job ID.
                let collision: bool = db(tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM actions WHERE id=?1 OR (execution=?2 AND action=?3))",
                params![job_id, key, request.action_id], |r| r.get(0),
            ))?;
                let failed: bool = db(tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM preflight_receipts p JOIN actions a ON a.id=p.id
                 WHERE a.execution=?1 AND p.status='failed')",
                    params![key],
                    |r| r.get(0),
                ))?;
                let outstanding: i64 = db(tx.query_row(
                    "SELECT COUNT(*) FROM preflight_receipts WHERE status<>'verified'",
                    [],
                    |r| r.get(0),
                ))?;
                if collision {
                    return Err(Error::Conflict);
                }
                if failed {
                    return Err(Error::Rejected);
                }
                if outstanding >= MAX_OUTSTANDING {
                    return Err(Error::Unavailable);
                }
                let allowed = decision.decision == Decision::Allow;
                if allowed
                    && db(tx.execute(
                        "UPDATE budgets SET spent=spent+?1 WHERE name=?2 AND ?1<=allowance-spent",
                        params![amount(cost)?, budget],
                    ))? != 1
                {
                    return Err(Error::Rejected);
                }
                db(tx.execute(
                    "INSERT INTO actions(id,execution,action,epoch,request,decision,cost,state)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                    params![
                        job_id,
                        key,
                        request.action_id,
                        epoch,
                        r,
                        d,
                        amount(cost)?,
                        if allowed { 1 } else { 3 }
                    ],
                ))?;
                db(tx.execute(
                    "INSERT INTO preflight_receipts(id,witness,public_values) VALUES(?1,?2,?3)",
                    params![job_id, witness, public],
                ))?;
                PreflightReceiptState::Queued
            };
        let grant = if decision.decision == Decision::Allow {
            current(&decision)?;
            Some(ExecutionGrant {
                id: job_id.into(),
                credential: self.credential(job_id, &decision)?,
                execution: decision.execution.clone(),
                request_sha256: decision.request_sha256.clone(),
                validity: decision.validity.clone(),
            })
        } else {
            None
        };
        db(tx.commit())?;
        Ok(PreflightDecision {
            decision,
            grant,
            receipt_state,
        })
    }

    /// Bound the worker's batch; persisted ordering survives process restarts.
    pub fn pending_preflight(&self) -> Result<Vec<String>> {
        let c = self.connection.lock().map_err(|_| Error::Unavailable)?;
        let mut q = db(c.prepare("SELECT id FROM preflight_receipts WHERE status IN ('queued','proving') ORDER BY rowid LIMIT 128"))?;
        let rows = db(q.query_map([], |r| r.get(0)))?;
        db(rows.collect())
    }

    pub fn preflight_receipt_state(&self, id: &str) -> Result<PreflightReceiptState> {
        let c = self.connection.lock().map_err(|_| Error::Unavailable)?;
        let status: String = db(c.query_row(
            "SELECT status FROM preflight_receipts WHERE id=?1",
            params![id],
            |r| r.get(0),
        ))?;
        PreflightReceiptState::parse(&status)
    }

    /// Expose receipt bytes only after cryptographic verification. A receipt is
    /// historical evidence and never renews or reissues an execution grant.
    pub fn preflight_receipt(&self, id: &str) -> Result<Option<ProofReceipt>> {
        let c = self.connection.lock().map_err(|_| Error::Unavailable)?;
        let bytes = db(c
            .query_row(
                "SELECT receipt FROM preflight_receipts WHERE id=?1 AND status='verified'",
                params![id],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional())?;
        Ok(bytes.map(|encoded_receipt| ProofReceipt {
            job_id: id.into(),
            encoded_receipt,
        }))
    }

    fn claim_preflight(&self, id: &str) -> Result<Option<ProofRequest>> {
        let mut c = self.connection.lock().map_err(|_| Error::Unavailable)?;
        let tx = db(c.transaction_with_behavior(TransactionBehavior::Immediate))?;
        if db(tx.execute(
            "UPDATE preflight_receipts SET status='proving' WHERE id=?1 AND status='queued'",
            params![id],
        ))? == 0
        {
            return Ok(None);
        }
        let (witness, expected_public_values) = db(tx.query_row(
            "SELECT witness,public_values FROM preflight_receipts WHERE id=?1",
            params![id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ))?;
        db(tx.commit())?;
        Ok(Some(ProofRequest {
            request_id: id.into(),
            program: self.program.clone(),
            witness,
            expected_public_values,
        }))
    }

    /// Operators may reconcile a failed remote job by supplying a valid receipt
    /// for the original job and witness. No execution state or budget is reset.
    pub fn complete_preflight(&self, receipt: &ProofReceipt) -> Result<()> {
        if receipt.encoded_receipt.is_empty() || receipt.encoded_receipt.len() > 1024 * 1024 {
            return Err(Error::InvalidInput);
        }
        let expected: Vec<u8> = {
            let c = self.connection.lock().map_err(|_| Error::Unavailable)?;
            db(c.query_row(
                "SELECT public_values FROM preflight_receipts WHERE id=?1",
                params![receipt.job_id],
                |r| r.get(0),
            ))?
        };
        self.verifier
            .verify(&self.program, receipt, &expected)
            .map_err(|_| Error::Rejected)?;
        let c = self.connection.lock().map_err(|_| Error::Unavailable)?;
        // Do not check today's policy/lease/expiry against historical evidence.
        db(c.execute(
            "UPDATE preflight_receipts SET status='verified',receipt=?1 WHERE id=?2",
            params![receipt.encoded_receipt, receipt.job_id],
        ))?;
        Ok(())
    }

    fn fail_preflight(&self, id: &str) -> Result<()> {
        let c = self.connection.lock().map_err(|_| Error::Unavailable)?;
        db(c.execute(
            "UPDATE preflight_receipts SET status='failed' WHERE id=?1 AND status='proving'",
            params![id],
        ))?;
        Ok(())
    }
}

/// Embedded by Fleet's gateway, using the existing remote ProofNetwork adapter.
/// No task is spawned until the embedding service calls advance; native admission
/// never awaits this worker. There is no local-prover fallback.
pub struct PreflightWorker {
    ledger: Arc<SqliteLedger>,
    network: Arc<dyn ProofNetwork>,
}
impl PreflightWorker {
    pub fn new(ledger: Arc<SqliteLedger>, network: Arc<dyn ProofNetwork>) -> Self {
        Self { ledger, network }
    }
    async fn run<T: Send + 'static>(
        &self,
        op: impl FnOnce(&SqliteLedger) -> Result<T> + Send + 'static,
    ) -> crate::Result<T> {
        let l = self.ledger.clone();
        tokio::task::spawn_blocking(move || op(&l))
            .await
            .map_err(|_| crate::Error::Unavailable)?
            .map_err(|_| crate::Error::Untrusted)
    }
    pub async fn advance(&self, id: &str) -> crate::Result<PreflightReceiptState> {
        let job_id = id.to_owned();
        if let Some(request) = self.run(move |l| l.claim_preflight(&job_id)).await? {
            // Claim is durable BEFORE the RPC. An ambiguous submission is polled
            // by its original ID, never automatically submitted a second time.
            if self.network.submit(&request).await? != id {
                return Err(crate::Error::Untrusted);
            }
        }
        let job_id = id.to_owned();
        let state = self
            .run(move |l| l.preflight_receipt_state(&job_id))
            .await?;
        if state != PreflightReceiptState::Proving {
            return Ok(state);
        }
        match self.network.status(id).await? {
            ProofStatus::Pending => (),
            ProofStatus::Failed => {
                let job_id = id.to_owned();
                self.run(move |l| l.fail_preflight(&job_id)).await?;
            }
            ProofStatus::Complete(receipt) => {
                if receipt.job_id != id {
                    return Err(crate::Error::Untrusted);
                }
                self.run(move |l| l.complete_preflight(&receipt)).await?;
            }
        }
        let job_id = id.to_owned();
        self.run(move |l| l.preflight_receipt_state(&job_id)).await
    }
}
