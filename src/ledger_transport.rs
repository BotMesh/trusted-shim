//! Authenticated central authorization transport. Embed the service in the
//! Fleet-controlled policy gateway; nodes receive only the scoped client.
//! Never expose an unencrypted listener beyond numeric loopback. The embedding
//! gateway must configure TLS (or its authenticated private TLS terminator).
use crate::ledger::SqliteLedger;
use async_trait::async_trait;
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use tonic::{
    metadata::{Ascii, MetadataValue},
    transport::{Channel, ClientTlsConfig, Endpoint},
    Request, Response, Status,
};
use trusted_contracts::{ExecutionIdentity, Validity};
use trusted_rail::{
    rego::canonical_bytes, AuthorizationLedger, DecisionRecord, Error, ExecutionGrant, Result,
};

pub mod wire {
    tonic::include_proto!("trusted.ledger.v1");
}

const MAX_MESSAGE: usize = 2 * 1024 * 1024;
const MAX_IDENTITY: usize = 16 * 1024;
const MAX_PROOF: usize = 1024 * 1024;
const MAX_GRANT_SECRET: usize = 1024;

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8], limit: usize) -> Result<T> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(Error::InvalidInput);
    }
    serde_json::from_slice(bytes).map_err(|_| Error::InvalidInput)
}
fn encode<T: serde::Serialize>(v: &T, limit: usize) -> Result<Vec<u8>> {
    let bytes = canonical_bytes(v)?;
    if bytes.len() > limit {
        return Err(Error::InvalidInput);
    }
    Ok(bytes)
}
pub(crate) fn grant_to_wire(g: ExecutionGrant) -> Result<wire::Grant> {
    if g.id.is_empty()
        || g.id.len() > 256
        || g.credential.is_empty()
        || g.credential.len() > MAX_GRANT_SECRET
        || g.request_sha256.len() != 64
        || g.validity.not_before >= g.validity.expires_at
    {
        return Err(Error::InvalidInput);
    }
    Ok(wire::Grant {
        id: g.id,
        credential: g.credential,
        execution_json: encode(&g.execution, MAX_IDENTITY)?,
        request_sha256: g.request_sha256,
        not_before: g.validity.not_before,
        expires_at: g.validity.expires_at,
    })
}
pub(crate) fn grant_from_wire(g: wire::Grant) -> Result<ExecutionGrant> {
    if g.id.is_empty()
        || g.id.len() > 256
        || g.credential.is_empty()
        || g.credential.len() > MAX_GRANT_SECRET
        || g.request_sha256.len() != 64
        || g.not_before >= g.expires_at
    {
        return Err(Error::InvalidInput);
    }
    Ok(ExecutionGrant {
        id: g.id,
        credential: g.credential,
        execution: decode(&g.execution_json, MAX_IDENTITY)?,
        request_sha256: g.request_sha256,
        validity: Validity {
            not_before: g.not_before,
            expires_at: g.expires_at,
        },
    })
}

/// No Debug implementation: this holds the allocation's bearer credential.
pub struct RemoteLedger {
    channel: Channel,
    bearer: MetadataValue<Ascii>,
    execution: ExecutionIdentity,
}
impl RemoteLedger {
    /// Validate operator configuration without requiring a live gateway. Cleanup
    /// and existing runtimes remain available during a control-plane outage.
    pub fn endpoint(endpoint: &str) -> Result<Endpoint> {
        let uri: tonic::codegen::http::Uri = endpoint.parse().map_err(|_| Error::InvalidInput)?;
        if uri.authority().is_none_or(|a| a.as_str().contains('@'))
            || uri.path_and_query().is_some_and(|p| p.as_str() != "/")
        {
            return Err(Error::InvalidInput);
        }
        let mut endpoint =
            Endpoint::from_shared(endpoint.to_owned()).map_err(|_| Error::InvalidInput)?;
        match uri.scheme_str() {
            Some("https") => {
                endpoint = endpoint
                    .tls_config(ClientTlsConfig::new().with_native_roots())
                    .map_err(|_| Error::InvalidInput)?;
            }
            Some("http") if matches!(uri.host(), Some("127.0.0.1" | "[::1]")) => (),
            _ => return Err(Error::InvalidInput),
        }
        Ok(endpoint
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30)))
    }

    pub async fn connect(
        endpoint: &str,
        token: &str,
        execution: ExecutionIdentity,
    ) -> Result<Self> {
        let channel = Self::endpoint(endpoint)?
            .connect()
            .await
            .map_err(|_| Error::Unavailable)?;
        Self::from_channel(channel, token, execution)
    }

    /// Operator-only injection for private CA/mTLS channels. Never accept a
    /// channel/endpoint from the agent. Per-call deadlines still apply.
    pub fn from_channel(
        channel: Channel,
        token: &str,
        execution: ExecutionIdentity,
    ) -> Result<Self> {
        if token.len() != 64
            || !token
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(Error::InvalidInput);
        }
        encode(&execution, MAX_IDENTITY)?;
        let mut bearer: MetadataValue<Ascii> = format!("Bearer {token}")
            .parse()
            .map_err(|_| Error::InvalidInput)?;
        bearer.set_sensitive(true);
        Ok(Self {
            channel,
            bearer,
            execution,
        })
    }
    fn request<T>(&self, value: T) -> Request<T> {
        let mut request = Request::new(value);
        request
            .metadata_mut()
            .insert("authorization", self.bearer.clone());
        request.set_timeout(Duration::from_secs(30));
        request
    }
    fn client(&self) -> wire::authorization_ledger_client::AuthorizationLedgerClient<Channel> {
        wire::authorization_ledger_client::AuthorizationLedgerClient::new(self.channel.clone())
            .max_encoding_message_size(MAX_MESSAGE)
            .max_decoding_message_size(MAX_MESSAGE)
    }
}
fn remote_error(s: Status) -> Error {
    match s.code() {
        tonic::Code::InvalidArgument => Error::InvalidInput,
        tonic::Code::Unauthenticated | tonic::Code::PermissionDenied => Error::Rejected,
        tonic::Code::FailedPrecondition | tonic::Code::Aborted => Error::Conflict,
        _ => Error::Unavailable,
    }
}
#[async_trait]
impl AuthorizationLedger for RemoteLedger {
    async fn reserve(
        &self,
        decision: &DecisionRecord,
        proof: Option<&[u8]>,
    ) -> Result<ExecutionGrant> {
        if decision.execution != self.execution {
            return Err(Error::Rejected);
        }
        let proof = proof
            .filter(|p| !p.is_empty() && p.len() <= MAX_PROOF)
            .ok_or(Error::Rejected)?;
        let request = self.request(wire::ReserveRequest {
            decision_json: encode(decision, trusted_rail::rego::MAX_PUBLIC_BYTES)?,
            proof_evidence: proof.to_vec(),
        });
        let response =
            tokio::time::timeout(Duration::from_secs(30), self.client().reserve(request))
                .await
                .map_err(|_| Error::Unavailable)?
                .map_err(remote_error)?
                .into_inner();
        let grant = grant_from_wire(response)?;
        if grant.execution != self.execution
            || grant.request_sha256 != decision.request_sha256
            || grant.validity != decision.validity
        {
            return Err(Error::Rejected);
        }
        Ok(grant)
    }
    async fn consume(
        &self,
        grant: &ExecutionGrant,
        execution: &ExecutionIdentity,
        digest: &str,
    ) -> Result<()> {
        if *execution != self.execution
            || grant.execution != *execution
            || grant.request_sha256 != digest
        {
            return Err(Error::Rejected);
        }
        let request = self.request(wire::ConsumeRequest {
            grant: Some(grant_to_wire(ExecutionGrant {
                id: grant.id.clone(),
                credential: grant.credential.clone(),
                execution: grant.execution.clone(),
                request_sha256: grant.request_sha256.clone(),
                validity: grant.validity.clone(),
            })?),
            execution_json: encode(execution, MAX_IDENTITY)?,
            request_sha256: digest.into(),
        });
        // No retries. A lost response may follow committed consumption; callers
        // must not dispatch without an unambiguous successful response.
        tokio::time::timeout(Duration::from_secs(30), self.client().consume(request))
            .await
            .map_err(|_| Error::Unavailable)?
            .map_err(remote_error)?;
        Ok(())
    }
}

pub struct LedgerService {
    ledger: Arc<SqliteLedger>,
    permits: Arc<Semaphore>,
    authority: Option<Arc<dyn ExecutionAuthority>>,
}

/// An embedding scheduler can fence its live allocation state through the
/// ledger transaction. The guard is acquired on a blocking worker and never
/// crosses an await. Policy, credential and budget checks remain in the ledger.
pub trait ExecutionGuard {}
impl<T> ExecutionGuard for T {}
pub trait ExecutionAuthority: Send + Sync {
    fn guard(&self, execution: &ExecutionIdentity) -> Result<Box<dyn ExecutionGuard + '_>>;
}
impl LedgerService {
    pub fn new(ledger: Arc<SqliteLedger>) -> Self {
        Self {
            ledger,
            permits: Arc::new(Semaphore::new(16)),
            authority: None,
        }
    }
    pub fn with_authority(mut self, authority: Arc<dyn ExecutionAuthority>) -> Self {
        self.authority = Some(authority);
        self
    }
    /// Mount beside the existing gateway's control services, behind TLS. This
    /// does not start a listener, another gateway process, or a local prover.
    pub fn into_service(
        self,
    ) -> wire::authorization_ledger_server::AuthorizationLedgerServer<Self> {
        wire::authorization_ledger_server::AuthorizationLedgerServer::new(self)
            .max_decoding_message_size(MAX_MESSAGE)
            .max_encoding_message_size(MAX_MESSAGE)
    }
    async fn run<T: Send + 'static>(
        &self,
        op: impl FnOnce(&SqliteLedger) -> Result<T> + Send + 'static,
    ) -> std::result::Result<T, Status> {
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("authorization busy"))?;
        let ledger = self.ledger.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            op(&ledger)
        })
        .await
        .map_err(|_| Status::unavailable("authorization unavailable"))?
        .map_err(status)
    }
}
fn status(e: Error) -> Status {
    match e {
        Error::InvalidInput => Status::invalid_argument("invalid authorization request"),
        Error::Rejected => Status::permission_denied("authorization rejected"),
        Error::Conflict => Status::failed_precondition("authorization state changed"),
        _ => Status::unavailable("authorization unavailable"),
    }
}
fn token<T>(r: &Request<T>) -> std::result::Result<String, Status> {
    let mut values = r.metadata().get_all("authorization").iter();
    let token = values
        .next()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|v| {
            v.len() == 64
                && v.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
        .ok_or_else(|| Status::unauthenticated("missing authorization"))?;
    if values.next().is_some() {
        return Err(Status::unauthenticated("ambiguous authorization"));
    }
    Ok(token.into())
}
#[tonic::async_trait]
impl wire::authorization_ledger_server::AuthorizationLedger for LedgerService {
    async fn reserve(
        &self,
        r: Request<wire::ReserveRequest>,
    ) -> std::result::Result<Response<wire::Grant>, Status> {
        let token = token(&r)?;
        let r = r.into_inner();
        let decision: DecisionRecord =
            decode(&r.decision_json, trusted_rail::rego::MAX_PUBLIC_BYTES).map_err(status)?;
        if r.proof_evidence.is_empty() || r.proof_evidence.len() > MAX_PROOF {
            return Err(Status::invalid_argument("invalid evidence size"));
        }
        let authority = self.authority.clone();
        let grant = self
            .run(move |l| {
                let verified = l.verify_reservation(&decision, &r.proof_evidence, Some(&token))?;
                let _guard = authority
                    .as_ref()
                    .map(|a| a.guard(&decision.execution))
                    .transpose()?;
                l.commit_reservation(verified, Some(&token))
            })
            .await?;
        Ok(Response::new(grant_to_wire(grant).map_err(status)?))
    }
    async fn consume(
        &self,
        r: Request<wire::ConsumeRequest>,
    ) -> std::result::Result<Response<wire::ConsumeResponse>, Status> {
        let token = token(&r)?;
        let r = r.into_inner();
        let grant = grant_from_wire(
            r.grant
                .ok_or_else(|| Status::invalid_argument("missing grant"))?,
        )
        .map_err(status)?;
        let execution = decode(&r.execution_json, MAX_IDENTITY).map_err(status)?;
        let authority = self.authority.clone();
        self.run(move |l| {
            let _guard = authority
                .as_ref()
                .map(|a| a.guard(&execution))
                .transpose()?;
            l.consume_authenticated(&token, &grant, &execution, &r.request_sha256)
        })
        .await?;
        Ok(Response::new(wire::ConsumeResponse {}))
    }
}
