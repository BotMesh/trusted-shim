//! Node-local administration and manifest-selected HTTP ingress. No scheduler
//! or agent-type branches. Unproved Docker administration is not a PolicyEngine
//! execution grant; proof-required runtimes remain rejected by the Docker driver.
use crate::{contracts::ExecutionIdentity, docker::DockerDriver, Error, Result};
use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::{any, get, post},
    Json, Router,
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, sync::Arc};
use tokio_util::sync::CancellationToken;
use trusted_data_router::ServiceSpec;
use trusted_router_transport::grants::{Grant, Purpose, Verifier};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ingress {
    pub paths: Vec<String>,
    pub methods: Vec<String>,
    /// Native authorization stays on the node, read from the owned container.
    pub bearer_env: Option<String>,
    /// Require body-bound, durably single-use control-plane approval.
    #[serde(default, skip_serializing_if = "is_false")]
    pub single_use: bool,
}
fn is_false(value: &bool) -> bool {
    !*value
}
impl Ingress {
    pub fn validate(&self) -> Result<()> {
        if self.paths.is_empty()
            || self.paths.len() > 32
            || self.paths.iter().any(|p| {
                !p.starts_with('/')
                    || p.len() > 256
                    || !p.is_ascii()
                    || p.contains(['%', '?', '#', '\\'])
                    || p.split('/').any(|p| p == "." || p == "..")
                    || p.chars().any(char::is_control)
            })
            || self.methods.is_empty()
            || self.methods.len() > 7
            || self.methods.iter().any(|m| {
                !matches!(
                    m.as_str(),
                    "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
                )
            })
            || self.bearer_env.as_ref().is_some_and(|e| {
                e.is_empty()
                    || e.len() > 128
                    || !e.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            })
        {
            return Err(Error::InvalidContract);
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecRequest {
    pub command: Vec<String>,
    pub user: Option<String>,
    #[serde(default)]
    pub stdin: String,
    pub timeout_seconds: u64,
}
#[derive(Serialize, Deserialize)]
pub struct ExecResponse {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

struct Service {
    driver: DockerDriver,
    execution: ExecutionIdentity,
    declaration: ServiceSpec,
    verifier: Verifier,
    ingress: Option<Ingress>,
    target: SocketAddr,
    client: reqwest::Client,
    slots: Arc<tokio::sync::Semaphore>,
}
impl Service {
    fn authorize(&self, headers: &HeaderMap) -> std::result::Result<Grant, StatusCode> {
        let token = headers
            .get("x-trusted-route")
            .and_then(|v| v.to_str().ok())
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let grant = self
            .verifier
            .verify(token, Purpose::Access)
            .map_err(|_| StatusCode::FORBIDDEN)?;
        if grant.execution != self.execution
            || grant.service != self.declaration.id
            || (self.ingress.is_none() && grant.http_request.is_some())
        {
            return Err(StatusCode::FORBIDDEN);
        }
        Ok(grant)
    }
}
fn failure(_: Error) -> StatusCode {
    StatusCode::SERVICE_UNAVAILABLE
}

/// The returned listener is reachable only from this host. Every request still
/// needs a signed exact-execution grant; a guessed port is not authorization.
#[allow(clippy::too_many_arguments)]
pub async fn bind(
    driver: DockerDriver,
    execution: ExecutionIdentity,
    declaration: ServiceSpec,
    verifier: Verifier,
    ingress: Option<Ingress>,
    target: SocketAddr,
    stop: CancellationToken,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let control = declaration.endpoint_ref == "control" && declaration.id.service == "control";
    if !control && ingress.is_none() {
        return Err(Error::InvalidContract);
    }
    let state = Arc::new(Service {
        driver,
        execution,
        declaration,
        verifier,
        ingress,
        target,
        client: reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|_| Error::Unavailable)?,
        slots: Arc::new(tokio::sync::Semaphore::new(if control { 4 } else { 64 })),
    });
    let router = if control {
        Router::new()
            .route("/metadata", get(metadata))
            .route("/exec", post(execute))
            .route("/restart", post(restart))
            .layer(DefaultBodyLimit::max(90 * 1024 * 1024))
    } else {
        Router::new()
            .fallback(any(proxy))
            .layer(DefaultBodyLimit::max(16 * 1024 * 1024))
    }
    .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| Error::Unavailable)?;
    let address = listener.local_addr().map_err(|_| Error::Unavailable)?;
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router)
            .with_graceful_shutdown(stop.cancelled_owned())
            .await;
    });
    Ok((address, task))
}
async fn metadata(
    State(service): State<Arc<Service>>,
    headers: HeaderMap,
) -> std::result::Result<Json<serde_json::Value>, StatusCode> {
    service.authorize(&headers)?;
    let _slot = service
        .slots
        .try_acquire()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    service
        .driver
        .metadata(&service.execution)
        .await
        .map(Json)
        .map_err(failure)
}
async fn execute(
    State(service): State<Arc<Service>>,
    headers: HeaderMap,
    Json(request): Json<ExecRequest>,
) -> std::result::Result<Json<ExecResponse>, StatusCode> {
    let expires_at = service.authorize(&headers)?.exp;
    let _slot = service
        .slots
        .try_acquire()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    service
        .driver
        .execute(&service.execution, request, expires_at)
        .await
        .map(Json)
        .map_err(failure)
}
async fn restart(
    State(service): State<Arc<Service>>,
    headers: HeaderMap,
) -> std::result::Result<Json<serde_json::Value>, StatusCode> {
    let expires_at = service.authorize(&headers)?.exp;
    let _slot = service
        .slots
        .try_acquire()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    service
        .driver
        .restart(&service.execution, expires_at)
        .await
        .map_err(failure)?;
    Ok(Json(serde_json::json!({"restarted":true})))
}
async fn proxy(
    State(service): State<Arc<Service>>,
    request: Request,
) -> std::result::Result<Response, StatusCode> {
    let grant = service.authorize(request.headers())?;
    let slot = service
        .slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    let ingress = service.ingress.as_ref().ok_or(StatusCode::FORBIDDEN)?;
    if !ingress.paths.iter().any(|p| p == request.uri().path())
        || !ingress
            .methods
            .iter()
            .any(|m| m == request.method().as_str())
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let (parts, body) = request.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .ok_or(StatusCode::BAD_REQUEST)?
        .as_str()
        .to_owned();
    if ingress.single_use && grant.http_request.is_none() {
        return Err(StatusCode::FORBIDDEN);
    }
    if let Some(binding) = &grant.http_request {
        if binding.method != parts.method.as_str() || binding.path != path {
            return Err(StatusCode::FORBIDDEN);
        }
    }
    let body = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        axum::body::to_bytes(body, 16 * 1024 * 1024),
    )
    .await
    .map_err(|_| StatusCode::REQUEST_TIMEOUT)?
    .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
    if let Some(binding) = &grant.http_request {
        if hex::encode(Sha256::digest(&body)) != binding.body_sha256 {
            return Err(StatusCode::FORBIDDEN);
        }
    }
    let metadata = service
        .driver
        .metadata(&service.execution)
        .await
        .map_err(failure)?;
    let bearer = if let Some(name) = &ingress.bearer_env {
        let prefix = format!("{name}=");
        Some(
            metadata["environment"]
                .as_array()
                .and_then(|env| {
                    env.iter()
                        .filter_map(|s| s.as_str())
                        .find_map(|s| s.strip_prefix(&prefix))
                })
                .filter(|s| !s.is_empty())
                .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
                .to_owned(),
        )
    } else {
        None
    };
    if trusted_router_transport::grants::now() >= grant.exp {
        return Err(StatusCode::FORBIDDEN);
    }
    if let Some(binding) = &grant.http_request {
        if !service
            .driver
            .consume_http_request(
                &service.execution,
                &service.declaration.id.service,
                &binding.id,
                grant.exp,
            )
            .await
            .map_err(failure)?
        {
            return Err(StatusCode::CONFLICT);
        }
    }
    let mut upstream = service
        .client
        .request(parts.method, format!("http://{}{path}", service.target));
    for name in ["content-type", "accept"] {
        if let Some(value) = parts.headers.get(name) {
            upstream = upstream.header(name, value);
        }
    }
    if let Some(bearer) = bearer {
        upstream = upstream.bearer_auth(bearer);
    }
    let response = upstream
        .body(body)
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let mut result = Response::builder().status(response.status());
    for name in ["content-type", "cache-control", "x-accel-buffering"] {
        if let Some(value) = response.headers().get(name) {
            result = result.header(name, value);
        }
    }
    result
        .body(Body::from_stream(response.bytes_stream().map(
            move |chunk| {
                let _hold = &slot;
                chunk
            },
        )))
        .map_err(|_| StatusCode::BAD_GATEWAY)
}
