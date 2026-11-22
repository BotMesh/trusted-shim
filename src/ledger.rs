//! Durable central authorization state. Host this in the policy gateway, never
//! in an untrusted agent. Policy/context/budget setters are operator interfaces;
//! exposing them to execution nodes would invalidate the authorization boundary.
use crate::proof::{ProgramRef, ProofReceipt, ReceiptVerifier};
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use trusted_contracts::{ExecutionIdentity, ProofKind};
use trusted_rail::{
    rego::{canonical_bytes, commitment, encode_public_values, RegorusEngine},
    *,
};

type Result<T> = trusted_rail::Result<T>;

/// Operator-selected rights for a single exact execution, never a namespace-wide
/// credential. Admission can reserve; Execution can consume. Neither can stage
/// requests, change policy/context, activate leases or change budgets.
#[derive(Clone, Copy)]
pub enum LedgerPermission {
    Admission = 1,
    Execution = 2,
    AdmissionAndExecution = 3,
}

fn access_hash(token: &str) -> Result<String> {
    if token.len() != 64
        || !token
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(Error::Rejected);
    }
    Ok(hex::encode(Sha256::digest(token.as_bytes())))
}

fn check_access(
    c: &Connection,
    token: &str,
    execution: &ExecutionIdentity,
    permission: LedgerPermission,
) -> Result<()> {
    let time = amount(now()?)?;
    let allowed: bool = db(c.query_row(
        "SELECT EXISTS(SELECT 1 FROM ledger_access a JOIN authorities t ON a.execution=t.execution
         WHERE a.token_hash=?1 AND a.execution=?2 AND (a.permissions & ?3)=?3
         AND a.not_before<=?4 AND ?4<a.expires_at AND t.active=1)",
        params![
            access_hash(token)?,
            execution_key(execution)?,
            permission as i64,
            time
        ],
        |r| r.get(0),
    ))?;
    if allowed {
        Ok(())
    } else {
        Err(Error::Rejected)
    }
}
fn db<T>(v: rusqlite::Result<T>) -> Result<T> {
    v.map_err(|_| Error::Unavailable)
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| Error::Unavailable)
}
fn current(d: &DecisionRecord) -> Result<()> {
    let n = now()?;
    if d.decision != Decision::Allow || n < d.validity.not_before || n >= d.validity.expires_at {
        return Err(Error::Rejected);
    }
    Ok(())
}
fn execution_key(e: &ExecutionIdentity) -> Result<String> {
    commitment("trusted-ledger.execution.v1", e)
}
fn text(v: &impl serde::Serialize) -> Result<String> {
    String::from_utf8(canonical_bytes(v)?).map_err(|_| Error::InvalidInput)
}
fn amount(n: u64) -> Result<i64> {
    i64::try_from(n).map_err(|_| Error::InvalidInput)
}

pub struct SqliteLedger {
    connection: Mutex<Connection>,
    verifier: Arc<dyn ReceiptVerifier>,
    program: ProgramRef,
    key: Vec<u8>,
}
impl SqliteLedger {
    /// Central operator API. Deliver the returned secret through the node's
    /// authenticated private provisioning channel; never an ordinary App spec.
    /// Only its hash is persisted. Maximum lifetime is one hour; the operator
    /// must additionally bound it by the current Fleet lease.
    pub fn issue_access(
        &self,
        execution: &ExecutionIdentity,
        permission: LedgerPermission,
        validity: &trusted_contracts::Validity,
    ) -> Result<String> {
        let time = now()?;
        if validity.not_before > time
            || validity.expires_at <= time
            || validity.expires_at.saturating_sub(validity.not_before) > 3600
        {
            return Err(Error::InvalidInput);
        }
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).map_err(|_| Error::Unavailable)?;
        let token = hex::encode(secret);
        let c = self.connection.lock().map_err(|_| Error::Unavailable)?;
        let inserted = db(c.execute(
            "INSERT INTO ledger_access SELECT ?1,execution,?3,?4,?5 FROM authorities WHERE execution=?2 AND active=1",
            params![access_hash(&token)?, execution_key(execution)?, permission as i64,
                amount(validity.not_before)?, amount(validity.expires_at)?],
        ))?;
        if inserted != 1 {
            return Err(Error::Rejected);
        }
        Ok(token)
    }

    /// Credential revocation and grant consumption serialize on the same DB.
    pub fn revoke_access(&self, token: &str) -> Result<()> {
        self.revoke_access_id(&access_hash(token)?)
    }

    /// Operator-facing revocation identifier is SHA-256 of the bearer. It is
    /// safe to put this identifier in audit records; never log the bearer.
    pub fn revoke_access_id(&self, id: &str) -> Result<()> {
        if id.len() != 64
            || !id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(Error::InvalidInput);
        }
        let c = self.connection.lock().map_err(|_| Error::Unavailable)?;
        db(c.execute("DELETE FROM ledger_access WHERE token_hash=?1", params![id]))?;
        Ok(())
    }

    pub(crate) fn reserve_authenticated(
        &self,
        token: &str,
        d: &DecisionRecord,
        proof: &[u8],
    ) -> Result<ExecutionGrant> {
        self.reserve_inner(d, Some(proof), Some(token))
    }

    pub(crate) fn consume_authenticated(
        &self,
        token: &str,
        g: &ExecutionGrant,
        e: &ExecutionIdentity,
        digest: &str,
    ) -> Result<()> {
        self.consume_inner(g, e, digest, Some(token))
    }
    /// The caller supplies a private durable directory, approved ELF/key and real
    /// cryptographic verifier. There is no network or local prover in this layer.
    pub fn open(
        path: &Path,
        program: ProgramRef,
        verifier: Arc<dyn ReceiptVerifier>,
    ) -> Result<Self> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        if program.kind != ProofKind::PolicyEvaluation
            || [&program.program_sha256, &program.verifying_key_sha256]
                .iter()
                .any(|v| v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(Error::InvalidInput);
        }
        let parent = path.parent().ok_or(Error::InvalidInput)?;
        let meta = std::fs::symlink_metadata(parent).map_err(|_| Error::Unavailable)?;
        if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
            return Err(Error::InvalidInput);
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| Error::Unavailable)?;
        let meta = file.metadata().map_err(|_| Error::Unavailable)?;
        if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
            return Err(Error::InvalidInput);
        }
        let mut c = db(Connection::open(path))?;
        db(c.busy_timeout(std::time::Duration::from_secs(5)))?;
        db(c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
          CREATE TABLE IF NOT EXISTS secrets(id INTEGER PRIMARY KEY CHECK(id=1),key BLOB NOT NULL);
          CREATE TABLE IF NOT EXISTS program(id INTEGER PRIMARY KEY CHECK(id=1),elf TEXT NOT NULL,vk TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS budgets(name TEXT PRIMARY KEY, allowance INTEGER NOT NULL, spent INTEGER NOT NULL DEFAULT 0);
          CREATE TABLE IF NOT EXISTS revoked(execution TEXT PRIMARY KEY);
          CREATE TABLE IF NOT EXISTS authorities(execution TEXT PRIMARY KEY, policy TEXT NOT NULL, context TEXT NOT NULL, root TEXT NOT NULL, budget TEXT NOT NULL REFERENCES budgets(name), epoch INTEGER NOT NULL, active INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS ledger_access(token_hash TEXT PRIMARY KEY, execution TEXT NOT NULL REFERENCES authorities(execution), permissions INTEGER NOT NULL, not_before INTEGER NOT NULL, expires_at INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS actions(id TEXT PRIMARY KEY, execution TEXT NOT NULL REFERENCES authorities(execution), action TEXT NOT NULL, epoch INTEGER NOT NULL, request TEXT NOT NULL, decision TEXT NOT NULL, cost INTEGER NOT NULL, state INTEGER NOT NULL DEFAULT 0, proof BLOB, UNIQUE(execution,action));"))?;
        let tx = db(c.transaction_with_behavior(TransactionBehavior::Immediate))?;
        db(tx.execute(
            "INSERT OR IGNORE INTO program VALUES(1,?1,?2)",
            params![program.program_sha256, program.verifying_key_sha256],
        ))?;
        let pinned: (String, String) = db(tx.query_row(
            "SELECT elf,vk FROM program WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ))?;
        if pinned
            != (
                program.program_sha256.clone(),
                program.verifying_key_sha256.clone(),
            )
        {
            return Err(Error::Rejected);
        }
        let key: Option<Vec<u8>> = db(tx
            .query_row("SELECT key FROM secrets WHERE id=1", [], |r| r.get(0))
            .optional())?;
        let key = match key {
            Some(k) if k.len() == 32 => k,
            Some(_) => return Err(Error::Unavailable),
            None => {
                let mut k = vec![0; 32];
                getrandom::getrandom(&mut k).map_err(|_| Error::Unavailable)?;
                db(tx.execute("INSERT INTO secrets VALUES(1,?1)", params![k]))?;
                k
            }
        };
        db(tx.commit())?;
        Ok(Self {
            connection: Mutex::new(c),
            verifier,
            program,
            key,
        })
    }
    /// Set cumulative allowance without resetting expenditure, shared by every
    /// execution assigned this budget. Reducing below already spent is rejected.
    pub fn set_budget(&self, name: &str, allowance: u64) -> Result<()> {
        if name.is_empty() || name.len() > 256 {
            return Err(Error::InvalidInput);
        }
        let c = self.connection.lock().map_err(|_| Error::Unavailable)?;
        let changed=db(c.execute("INSERT INTO budgets(name,allowance) VALUES(?1,?2) ON CONFLICT(name) DO UPDATE SET allowance=excluded.allowance WHERE spent<=excluded.allowance",params![name,amount(allowance)?]))?;
        if changed != 1 {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    /// Approved policy and authoritative context for this exact live allocation.
    /// Updating these invalidates outstanding requests and grants. Revoked
    /// executions cannot be reactivated; use a new lease/generation.
    pub fn activate(
        &self,
        execution: &ExecutionIdentity,
        policy: &PolicyBundle,
        context: &serde_json::Value,
        root: &str,
        budget: &str,
    ) -> Result<()> {
        if trusted_rail::rego::policy_digest(policy)? != policy.policy.sha256
            || policy.engine != trusted_rail::rego::engine_profile()
            || root.len() != 64
            || !root.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(Error::InvalidInput);
        }
        let mut c = self.connection.lock().map_err(|_| Error::Unavailable)?;
        let tx = db(c.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let id = execution_key(execution)?;
        if db(tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM revoked WHERE execution=?1)",
            params![id],
            |r| r.get::<_, bool>(0),
        ))? {
            return Err(Error::Rejected);
        }
        let old: Option<i64> = db(tx
            .query_row(
                "SELECT active FROM authorities WHERE execution=?1",
                params![id],
                |r| r.get(0),
            )
            .optional())?;
        if old == Some(0) {
            return Err(Error::Rejected);
        }
        let p = text(policy)?;
        let ctx = text(context)?;
        db(tx.execute("INSERT INTO authorities VALUES(?1,?2,?3,?4,?5,1,1) ON CONFLICT(execution) DO UPDATE SET policy=excluded.policy,context=excluded.context,root=excluded.root,budget=excluded.budget,epoch=epoch+1 WHERE policy<>excluded.policy OR context<>excluded.context OR root<>excluded.root OR budget<>excluded.budget",params![id,p,ctx,root,budget]))?;
        db(tx.commit())
    }
    pub fn revoke(&self, execution: &ExecutionIdentity) -> Result<()> {
        let mut c = self.connection.lock().map_err(|_| Error::Unavailable)?;
        let tx = db(c.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let id = execution_key(execution)?;
        // Persist even if activation has not arrived, so reordered lifecycle
        // messages cannot resurrect a retired execution.
        db(tx.execute("INSERT OR IGNORE INTO revoked VALUES(?1)", params![id]))?;
        db(tx.execute(
            "UPDATE authorities SET active=0,epoch=epoch+1 WHERE execution=?1",
            params![id],
        ))?;
        db(tx.commit())
    }
    /// Stage before remote submission. The gateway supplies authenticated inputs
    /// and the cost; execution nodes may not choose their own budget or context.
    pub fn stage(
        &self,
        job_id: &str,
        request: &EvaluationRequest,
        cost: u64,
    ) -> Result<PolicyBundle> {
        if job_id.is_empty() || job_id.len() > 256 || cost == 0 {
            return Err(Error::InvalidInput);
        }
        let mut c = self.connection.lock().map_err(|_| Error::Unavailable)?;
        let tx = db(c.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let key = execution_key(&request.execution)?;
        let (p, context, root, epoch): (String, String, String, i64) = db(tx.query_row(
            "SELECT policy,context,root,epoch FROM authorities WHERE execution=?1 AND active=1",
            params![key],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        ))?;
        if context != text(&request.context)? || root != request.previous_state_root {
            return Err(Error::Conflict);
        }
        let policy: PolicyBundle = serde_json::from_str(&p).map_err(|_| Error::Unavailable)?;
        let decision = RegorusEngine.evaluate(&policy, request)?;
        current(&decision)?;
        let r = text(request)?;
        if r.len() > trusted_rail::rego::MAX_WITNESS_BYTES {
            return Err(Error::InvalidInput);
        }
        let d = text(&decision)?;
        db(tx.execute("INSERT OR IGNORE INTO actions(id,execution,action,epoch,request,decision,cost) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![job_id,key,request.action_id,epoch,r,d,amount(cost)?]))?;
        let existing: (String, String, i64, i64) = db(tx.query_row(
            "SELECT request,decision,cost,epoch FROM actions WHERE id=?1",
            params![job_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ))?;
        if existing != (r, d, amount(cost)?, epoch) {
            return Err(Error::Conflict);
        }
        db(tx.commit())?;
        Ok(policy)
    }
    /// Resume the persisted exact witness after a gateway restart.
    pub fn request(&self, job_id: &str) -> Result<EvaluationRequest> {
        let c = self.connection.lock().map_err(|_| Error::Unavailable)?;
        let r: String = db(c.query_row(
            "SELECT request FROM actions WHERE id=?1",
            params![job_id],
            |r| r.get(0),
        ))?;
        serde_json::from_str(&r).map_err(|_| Error::Unavailable)
    }
    fn credential(&self, id: &str, d: &DecisionRecord) -> Result<Vec<u8>> {
        Ok(self.mac(id, d)?.finalize().into_bytes().to_vec())
    }
    fn mac(&self, id: &str, d: &DecisionRecord) -> Result<Hmac<Sha256>> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).map_err(|_| Error::Unavailable)?;
        mac.update(b"trusted-ledger.grant.v1\0");
        mac.update(id.as_bytes());
        mac.update(&canonical_bytes(d)?);
        Ok(mac)
    }
}

#[async_trait]
impl AuthorizationLedger for SqliteLedger {
    async fn reserve(
        &self,
        decision: &DecisionRecord,
        evidence: Option<&[u8]>,
    ) -> Result<ExecutionGrant> {
        self.reserve_inner(decision, evidence, None)
    }
    async fn consume(
        &self,
        grant: &ExecutionGrant,
        execution: &ExecutionIdentity,
        digest: &str,
    ) -> Result<()> {
        self.consume_inner(grant, execution, digest, None)
    }
}

impl SqliteLedger {
    fn reserve_inner(
        &self,
        decision: &DecisionRecord,
        evidence: Option<&[u8]>,
        access: Option<&str>,
    ) -> Result<ExecutionGrant> {
        current(decision)?;
        let evidence = evidence
            .filter(|v| !v.is_empty() && v.len() <= 1024 * 1024)
            .ok_or(Error::Rejected)?;
        // Match the gateway's staged decision before invoking the verifier.
        let key = execution_key(&decision.execution)?;
        let d = text(decision)?;
        let id: String = {
            let c = self.connection.lock().map_err(|_| Error::Unavailable)?;
            if let Some(token) = access {
                check_access(&c, token, &decision.execution, LedgerPermission::Admission)?;
            }
            db(c.query_row(
                "SELECT id FROM actions WHERE execution=?1 AND action=?2 AND decision=?3",
                params![key, decision.action_id, d],
                |r| r.get(0),
            ))?
        };
        self.verifier
            .verify(
                &self.program,
                &ProofReceipt {
                    job_id: id.clone(),
                    encoded_receipt: evidence.to_vec(),
                },
                &encode_public_values(decision)?,
            )
            .map_err(|_| Error::Rejected)?;
        let mut c = self.connection.lock().map_err(|_| Error::Unavailable)?;
        let tx = db(c.transaction_with_behavior(TransactionBehavior::Immediate))?;
        if let Some(token) = access {
            check_access(&tx, token, &decision.execution, LedgerPermission::Admission)?;
        }
        let (state,cost,budget):(i64,i64,String)=db(tx.query_row("SELECT a.state,a.cost,t.budget FROM actions a JOIN authorities t ON a.execution=t.execution WHERE a.id=?1 AND t.active=1 AND a.epoch=t.epoch",params![id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))))?;
        current(decision)?;
        if state == 2 {
            return Err(Error::Conflict);
        }
        if state == 0 {
            if db(tx.execute(
                "UPDATE budgets SET spent=spent+?1 WHERE name=?2 AND ?1<=allowance-spent",
                params![cost, budget],
            ))? != 1
            {
                return Err(Error::Rejected);
            }
            db(tx.execute(
                "UPDATE actions SET state=1,proof=?1 WHERE id=?2",
                params![evidence, id],
            ))?;
        }
        db(tx.commit())?;
        Ok(ExecutionGrant {
            id: id.clone(),
            credential: self.credential(&id, decision)?,
            execution: decision.execution.clone(),
            request_sha256: decision.request_sha256.clone(),
            validity: decision.validity.clone(),
        })
    }
    fn consume_inner(
        &self,
        grant: &ExecutionGrant,
        execution: &ExecutionIdentity,
        digest: &str,
        access: Option<&str>,
    ) -> Result<()> {
        if grant.execution != *execution || grant.request_sha256 != digest {
            return Err(Error::Rejected);
        }
        let mut c = self.connection.lock().map_err(|_| Error::Unavailable)?;
        let tx = db(c.transaction_with_behavior(TransactionBehavior::Immediate))?;
        if let Some(token) = access {
            check_access(&tx, token, execution, LedgerPermission::Execution)?;
        }
        let d:String=db(tx.query_row("SELECT a.decision FROM actions a JOIN authorities t ON a.execution=t.execution WHERE a.id=?1 AND a.state=1 AND t.active=1 AND a.epoch=t.epoch",params![grant.id],|r|r.get(0)))?;
        let decision: DecisionRecord = serde_json::from_str(&d).map_err(|_| Error::Unavailable)?;
        current(&decision)?;
        if decision.execution != *execution
            || decision.request_sha256 != digest
            || decision.validity != grant.validity
        {
            return Err(Error::Rejected);
        }
        self.mac(&grant.id, &decision)?
            .verify_slice(&grant.credential)
            .map_err(|_| Error::Rejected)?;
        if db(tx.execute(
            "UPDATE actions SET state=2 WHERE id=?1 AND state=1",
            params![grant.id],
        ))? != 1
        {
            return Err(Error::Conflict);
        }
        db(tx.commit())
    }
}
