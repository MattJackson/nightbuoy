//! Ephemeral companion: sessions, credentials and verified cache are RAM-only.
use crate::{
    crypto::*,
    model::*,
    portable_protocol as protocol,
    remote::*,
    sealed_storage::{self as opaque, MetadataKey},
};
use axum::{
    Json, Router,
    body::{Body, Bytes, to_bytes},
    extract::{
        DefaultBodyLimit, Path, RawPathParams, Request, State, rejection::RawPathParamsRejection,
    },
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
include!(concat!(env!("OUT_DIR"), "/assets.rs"));
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, Semaphore};
struct Ingress {
    normal: Arc<Semaphore>,
    posts: Arc<Semaphore>,
    recovery: Arc<Semaphore>,
}
impl Default for Ingress {
    fn default() -> Self {
        Self {
            normal: Arc::new(Semaphore::new(32)),
            posts: Arc::new(Semaphore::new(8)),
            recovery: Arc::new(Semaphore::new(2)),
        }
    }
}
#[derive(Clone)]
pub struct App {
    sessions: Arc<Mutex<HashMap<String, Arc<Mutex<Session>>>>>,
    admissions: Arc<Mutex<HashMap<String, (String, Instant)>>>,
    origin: String,
    web: String,
    testing: bool,
    allowed: Option<Connection>,
    branding: Option<crate::branding::Branding>,
    ingress: Arc<Ingress>,
}
struct Session {
    csrf: String,
    created: Instant,
    connection: Option<Connection>,
    remote: Option<Remote>,
    replicas: Vec<Remote>,
    from_replica: bool,
    copied_head: Option<String>,
    source_warning: bool,
    data: Option<Data>,
    metadata: Option<MetadataKey>,
    metadata_history: Vec<MetadataKey>,
    locked: bool,
    head_grants: std::collections::BTreeMap<String, String>,
    head_ephemeral: String,
    operator_checkpoint: Option<String>,
    device: Option<Device>,
    challenge: Option<String>,
    authenticated: bool,
    plan: Option<Plan>,
    requests: Vec<Value>,
    ingress: Arc<Semaphore>,
}
impl Session {
    fn empty(csrf: String, created: Instant, operator_checkpoint: Option<String>) -> Self {
        Self {
            csrf,
            created,
            operator_checkpoint,
            connection: None,
            remote: None,
            replicas: vec![],
            from_replica: false,
            copied_head: None,
            source_warning: false,
            data: None,
            metadata: None,
            metadata_history: vec![],
            locked: false,
            head_grants: Default::default(),
            head_ephemeral: String::new(),
            device: None,
            challenge: None,
            authenticated: false,
            plan: None,
            requests: vec![],
            ingress: Arc::new(Semaphore::new(4)),
        }
    }
}
struct Plan {
    ticket: String,
    body: String,
    data: Data,
    item: protocol::Item,
    metadata: MetadataKey,
    wrapped: std::collections::BTreeMap<String, String>,
    parent: Option<Blob>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    version: u8,
    community: String,
    branch: String,
    head: String,
    snapshot: String,
    primary: Backend,
    grants: std::collections::BTreeMap<String, String>,
    ephemeral: String,
}
type Result<T> = std::result::Result<T, Error>;
struct Error(anyhow::Error);
impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Self(e)
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let message = self.0.to_string();
        let code = if message.contains("session") || message.contains("sign in") {
            StatusCode::UNAUTHORIZED
        } else if message.contains("revoked") || message.contains("approval required") {
            StatusCode::FORBIDDEN
        } else if message.contains("conditional write")
            || message.contains("fork")
            || message.contains("rollback")
        {
            StatusCode::CONFLICT
        } else {
            StatusCode::BAD_REQUEST
        };
        (code, Json(json!({"error":message}))).into_response()
    }
}
async fn load(r: &Remote, key: &MetadataKey) -> anyhow::Result<Option<(Blob, Data, Head)>> {
    let Some(blob) = r.get(&opaque::head_path()).await? else {
        return Ok(None);
    };
    let h: Head = opaque::open_head(
        key,
        &blob.bytes,
        &opaque::context(&r.backend.namespace, "head"),
    )?;
    anyhow::ensure!(
        h.version == 2 && hex_id(&h.snapshot) && hex_id(&h.head),
        "invalid encrypted head"
    );
    let snap = r
        .get(&h.snapshot)
        .await?
        .ok_or_else(|| anyhow::anyhow!("encrypted snapshot missing"))?;
    anyhow::ensure!(
        hash(&snap.bytes) == h.snapshot,
        "ciphertext snapshot digest mismatch"
    );
    let a: Archive = key.open(
        &snap.bytes,
        &opaque::context(&r.backend.namespace, "snapshot"),
    )?;
    let d = Data::replay(&a)?;
    anyhow::ensure!(
        d.community() == h.community
            && d.branch() == h.branch
            && protocol::head(&a)? == h.head
            && d.view()
                .policy
                .portable
                .as_ref()
                .is_some_and(|p| h.primary.id().ok().as_ref() == Some(&p.primary)),
        "encrypted head binding mismatch"
    );
    validate_wrapped(&d, &h.grants)?;
    anyhow::ensure!(
        d.view()
            .discovery
            .as_ref()
            .is_some_and(|v| v.ephemeral == h.ephemeral),
        "signed discovery point mismatch"
    );
    let (ephemeral, slots, _) = opaque::split_head(&blob.bytes)?;
    anyhow::ensure!(
        ephemeral == h.ephemeral && h.grants.values().all(|v| slots.contains(v)),
        "anonymous key grant context changed"
    );
    Ok(Some((blob, d, h)))
}
fn validate_wrapped(
    data: &Data,
    wrapped: &std::collections::BTreeMap<String, String>,
) -> anyhow::Result<()> {
    let discovery = data
        .view()
        .discovery
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("opaque storage requires signed discovery grants"))?;
    anyhow::ensure!(
        &discovery.wrapped == wrapped,
        "unsigned discovery grant replacement forbidden"
    );
    let members = data
        .view()
        .members
        .iter()
        .filter(|(_, m)| m.status == "active")
        .map(|(id, _)| id)
        .collect::<std::collections::BTreeSet<_>>();
    anyhow::ensure!(
        wrapped.keys().collect::<std::collections::BTreeSet<_>>() == members,
        "metadata key grants must cover exactly active members"
    );
    anyhow::ensure!(
        data.view()
            .members
            .values()
            .filter(|m| m.status == "active")
            .all(|m| m.device.discover.is_some()),
        "active members need anonymous discovery keys"
    );
    for v in wrapped.values() {
        anyhow::ensure!(decode(v)?.len() == 60, "invalid anonymous epoch grant");
    }
    Ok(())
}
async fn publish_opaque(
    remote: &Remote,
    key: &MetadataKey,
    data: &Data,
    primary: &Backend,
    parent: Option<&Blob>,
    appended: Option<&protocol::Item>,
) -> anyhow::Result<()> {
    let discovery = data
        .view()
        .discovery
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("signed discovery grants required"))?;
    let wrapped = &discovery.wrapped;
    let ephemeral = &discovery.ephemeral;
    validate_wrapped(data, wrapped)?;
    for item in if let Some(item) = appended {
        vec![item.clone()]
    } else {
        protocol::items(&data.archive)?
    } {
        let bytes = key.seal(
            &item,
            &opaque::context(&remote.backend.namespace, "transaction"),
        )?;
        remote.immutable(&hash(&bytes), bytes).await?;
    }
    let headers = &data.archive.portable_proof.as_ref().unwrap().headers;
    for header in if appended.is_some() {
        &headers[headers.len() - 1..]
    } else {
        headers.as_slice()
    } {
        let bytes = key.seal(
            header,
            &opaque::context(&remote.backend.namespace, "certificate"),
        )?;
        remote.immutable(&hash(&bytes), bytes).await?;
    }
    let bytes = key.seal(
        &data.archive,
        &opaque::context(&remote.backend.namespace, "snapshot"),
    )?;
    let snapshot = hash(&bytes);
    remote.immutable(&snapshot, bytes).await?;
    let head = Head {
        version: 2,
        community: data.community(),
        branch: data.branch(),
        head: protocol::head(&data.archive)?,
        snapshot,
        primary: primary.clone(),
        grants: wrapped.clone(),
        ephemeral: ephemeral.clone(),
    };
    let frame = opaque::head_frame(
        key,
        &wrapped.values().cloned().collect::<Vec<_>>(),
        ephemeral,
        &head,
        &opaque::context(&remote.backend.namespace, "head"),
    )?;
    remote.put(&opaque::head_path(), frame, parent).await?;
    let (_, check, _) = load(remote, key)
        .await?
        .ok_or_else(|| anyhow::anyhow!("encrypted head readback missing"))?;
    anyhow::ensure!(
        protocol::head(&check.archive)? == head.head,
        "published checkpoint readback changed"
    );
    Ok(())
}
pub(crate) async fn client_load(
    remote: &Remote,
    key: &MetadataKey,
) -> anyhow::Result<Option<(Blob, Data, Backend)>> {
    Ok(load(remote, key)
        .await?
        .map(|(blob, data, head)| (blob, data, head.primary)))
}
pub(crate) async fn client_publish(
    remote: &Remote,
    key: &MetadataKey,
    data: &Data,
    parent: Option<&Blob>,
    item: Option<&protocol::Item>,
) -> anyhow::Result<()> {
    publish_opaque(remote, key, data, &remote.backend, parent, item).await
}
fn admission_available(
    admissions: &HashMap<String, (String, Instant)>,
    session_key: &str,
    identity: &str,
) -> bool {
    admissions
        .iter()
        .filter(|(session, (id, _))| session.as_str() != session_key && id == identity)
        .count()
        < 2
}
impl Session {
    fn remember_metadata(&mut self, old: MetadataKey) {
        if self.metadata.as_ref().is_some_and(|k| k.same(&old))
            || self.metadata_history.iter().any(|k| k.same(&old))
        {
            return;
        }
        self.metadata_history.push(old);
        if self.metadata_history.len() > 64 {
            self.metadata_history.remove(0);
        }
    }

    async fn refresh(&mut self) -> anyhow::Result<Option<Blob>> {
        self.refresh_source(true).await
    }
    async fn refresh_source(&mut self, fallback: bool) -> anyhow::Result<Option<Blob>> {
        let r = self
            .remote
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("connect to a backend first"))?;
        if self.metadata.is_none() {
            let mut sources = vec![r];
            if fallback {
                sources.extend(self.replicas.iter());
            }
            let mut error = anyhow::anyhow!("no encrypted head available");
            for (index, source) in sources.iter().enumerate() {
                match source.get(&opaque::head_path()).await {
                    Ok(Some(blob)) => {
                        if let Err(e) = opaque::split_head(&blob.bytes) {
                            error = e;
                            continue;
                        }
                        self.locked = true;
                        self.from_replica = index > 0;
                        return Ok(Some(blob));
                    }
                    Ok(None) => {
                        if index == 0 && self.connection.as_ref().unwrap().community.is_empty() {
                            anyhow::ensure!(
                                source.get("head.json").await?.is_none(),
                                "Legacy plaintext metadata exists here. Choose a new empty directory and explicitly migrate; Git history cannot be made secret retroactively."
                            );
                            self.locked = false;
                            return Ok(None);
                        }
                    }
                    Err(e) => error = e,
                }
            }
            return Err(error);
        }
        let mut sources = vec![r];
        if fallback {
            sources.extend(self.replicas.iter());
        }
        let mut selected = None;
        let mut last_error = anyhow::anyhow!("no verified compatible source available");
        let mut warnings = false;
        for (index, remote) in sources.iter().enumerate() {
            match load(remote, self.metadata.as_ref().unwrap())
                .await
                .and_then(|loaded| {
                    if let Some((_, d, _)) = &loaded {
                        self.compatible(d)?;
                    } else {
                        anyhow::ensure!(
                            index == 0
                                && self.data.is_none()
                                && self.connection.as_ref().unwrap().community.is_empty(),
                            "remote head missing or rollback"
                        );
                    }
                    Ok(loaded)
                }) {
                Ok(value) => {
                    selected = Some((index, value));
                    break;
                }
                Err(e) => {
                    warnings = true;
                    last_error = e;
                }
            }
        }
        let Some((index, loaded)) = selected else {
            return Err(last_error);
        };
        self.from_replica = index > 0;
        self.source_warning = warnings;
        let blob = loaded.as_ref().map(|(b, _, _)| b.clone());
        if let Some((_, d, head)) = loaded {
            self.locked = false;
            self.head_grants = head.grants;
            self.head_ephemeral = head.ephemeral;
            let unresolved =
                self.data.is_none() && self.connection.as_ref().unwrap().checkpoint.is_empty();
            let c = self.connection.as_mut().unwrap();
            if unresolved {
                let transport = self.remote.as_ref().unwrap();
                if let Some(rebound) = transport.rebind_same_location(&head.primary)? {
                    self.remote = Some(rebound);
                } else if transport.backend.id()? != head.primary.id()?
                    && !c.replicas.contains(&transport.backend)
                {
                    anyhow::ensure!(c.replicas.len() < 50, "replica limit");
                    c.replicas.push(transport.backend.clone());
                }
                c.primary = head.primary;
            }
            c.community = d.community();
            c.branch_pin = d.branch();
            c.checkpoint = protocol::head(&d.archive)?;
            self.data = Some(d);
        }
        Ok(blob)
    }
    fn compatible(&self, d: &Data) -> anyhow::Result<()> {
        let a = &d.archive;
        anyhow::ensure!(
            d.view().policy.portable.as_ref().is_some_and(|p| self
                .connection
                .as_ref()
                .is_some_and(|c| self.data.is_none() && c.checkpoint.is_empty())
                || Some(&p.primary)
                    == self
                        .connection
                        .as_ref()
                        .and_then(|c| c.primary.id().ok())
                        .as_ref()),
            "write backend identity mismatch"
        );
        let connection = self.connection.as_ref().unwrap();
        anyhow::ensure!(
            connection.branch_pin.is_empty() || connection.branch_pin == d.branch(),
            "branch changed; explicit selection required"
        );
        anyhow::ensure!(
            connection.checkpoint.is_empty()
                || a.portable_proof
                    .as_ref()
                    .unwrap()
                    .headers
                    .iter()
                    .any(|h| protocol::digest(h).ok().as_ref() == Some(&connection.checkpoint)),
            "checkpoint fork or rollback"
        );
        if let Some(checkpoint) = &self.operator_checkpoint {
            anyhow::ensure!(
                a.portable_proof
                    .as_ref()
                    .unwrap()
                    .headers
                    .iter()
                    .any(|h| protocol::digest(h).ok().as_ref() == Some(checkpoint)),
                "operator checkpoint rollback or fork"
            );
        }
        let expected = &connection.community;
        anyhow::ensure!(
            expected.is_empty() || expected == &d.community(),
            "community fingerprint mismatch"
        );
        if let Some(old) = &self.data {
            old.catch_up(a)?;
            let old_head = protocol::head(&old.archive)?;
            anyhow::ensure!(
                a.portable_proof
                    .as_ref()
                    .unwrap()
                    .headers
                    .iter()
                    .any(|s| protocol::digest(s).ok().as_ref() == Some(&old_head)),
                "signed head fork or rollback"
            );
        }
        Ok(())
    }
    fn active(&self) -> anyhow::Result<&Member> {
        anyhow::ensure!(self.authenticated, "sign in required");
        let m = self
            .data
            .as_ref()
            .and_then(|d| {
                self.device
                    .as_ref()
                    .and_then(|id| d.view().members.get(&id.id))
            })
            .ok_or_else(|| anyhow::anyhow!("membership approval required"))?;
        anyhow::ensure!(m.status == "active", "membership revoked");
        Ok(m)
    }
}
fn hex_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit())
}
fn ingress_error(status: StatusCode, message: &str) -> Response {
    let mut response = (status, Json(json!({"error":message}))).into_response();
    if status == StatusCode::TOO_MANY_REQUESTS {
        response
            .headers_mut()
            .insert("retry-after", "1".parse().unwrap());
    }
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
}
fn body_limit(
    app: &App,
    s: &Session,
    action: &str,
) -> std::result::Result<usize, (StatusCode, String)> {
    let protected = matches!(
        action,
        "prepare" | "commit" | "recover-prepare" | "private-read" | "private-write"
    );
    if protected && !s.authenticated {
        return Err((StatusCode::UNAUTHORIZED, "sign in required".into()));
    }
    let personal_empty =
        app.allowed.is_none() && s.remote.is_some() && s.data.is_none() && !s.locked;
    if action == "recover-prepare" {
        if !personal_empty {
            return Err((
                StatusCode::FORBIDDEN,
                "large recovery requires a personal client connected to an empty destination"
                    .into(),
            ));
        }
        return Ok(opaque::MAX_FRAME * 2);
    }
    if protected
        && !(personal_empty && matches!(action, "prepare" | "commit"))
        && let Err(error) = s.active()
    {
        return Err((StatusCode::FORBIDDEN, error.to_string()));
    }
    Ok(match action {
        "private-write" => 384 * 1024,
        "prepare" if s.active().is_ok() => 10 * 1024 * 1024,
        _ => 256 * 1024,
    })
}

type RawParams = std::result::Result<RawPathParams, RawPathParamsRejection>;
async fn security(
    State(app): State<App>,
    params: RawParams,
    mut req: Request,
    next: Next,
) -> Response {
    let expected = url::Url::parse(&app.origin).unwrap();
    let host = expected[url::Position::BeforeHost..url::Position::AfterPort].to_string();
    let valid_host = req.headers().get("host").and_then(|h| h.to_str().ok()) == Some(&host);
    let valid_origin = req.method() == "GET"
        || req.headers().get("origin").and_then(|h| h.to_str().ok()) == Some(app.origin.as_str());
    if !valid_host || !valid_origin {
        return StatusCode::FORBIDDEN.into_response();
    }
    let api = req.uri().path().starts_with("/api/");
    let mut limit = 0;
    let mut session_slots = None;
    if api && req.uri().path() != "/api/session" {
        let session = if let Some(cookie) = crate::api::cookie(req.headers(), "nb_portable") {
            app.sessions.lock().await.get(&hash(cookie)).cloned()
        } else {
            None
        };
        let Some(session) = session else {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error":"session required"})),
            )
                .into_response();
        };
        let s = session.lock().await;
        if s.created.elapsed() >= Duration::from_secs(8 * 3600) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error":"session expired"})),
            )
                .into_response();
        }
        if req.method() != axum::http::Method::GET
            && req
                .headers()
                .get("x-nightbuoy-csrf")
                .and_then(|h| h.to_str().ok())
                != Some(s.csrf.as_str())
        {
            return StatusCode::FORBIDDEN.into_response();
        }
        session_slots = Some(s.ingress.clone());
        if req.method() != axum::http::Method::GET {
            // Use the router's decoded action, including percent-encoded aliases.
            let action = params
                .as_ref()
                .ok()
                .and_then(|p| {
                    p.iter()
                        .find(|(key, _)| *key == "path")
                        .map(|(_, value)| value)
                })
                .unwrap_or("");
            limit = match body_limit(&app, &s, action) {
                Ok(limit) => limit,
                Err((status, message)) => return ingress_error(status, &message),
            };
        }
    }
    // Admission precedes body collection; a rejected stream is never polled.
    let mut _session_permit = None;
    let mut _global_permit = None;
    if api {
        if let Some(length) = req.headers().get(axum::http::header::CONTENT_LENGTH) {
            let Some(length) = length.to_str().ok().and_then(|v| v.parse::<u64>().ok()) else {
                return ingress_error(StatusCode::BAD_REQUEST, "invalid content length");
            };
            if length > limit as u64 {
                return ingress_error(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
            }
        }
        if let Some(slots) = session_slots {
            _session_permit = match slots.try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    return ingress_error(
                        StatusCode::TOO_MANY_REQUESTS,
                        "session request capacity reached; retry shortly",
                    );
                }
            };
        }
        let global = if limit > 10 * 1024 * 1024 {
            app.ingress.recovery.clone()
        } else if limit > 384 * 1024 {
            app.ingress.posts.clone()
        } else {
            app.ingress.normal.clone()
        };
        _global_permit = match global.try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                return ingress_error(
                    StatusCode::TOO_MANY_REQUESTS,
                    "request capacity reached; retry shortly",
                );
            }
        };
        let (parts, body) = req.into_parts();
        let timeout = if limit > 384 * 1024 {
            Duration::from_secs(300)
        } else {
            Duration::from_secs(120)
        };
        let bytes = match tokio::time::timeout(timeout, to_bytes(body, limit)).await {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(_)) => {
                return ingress_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body exceeds its limit or cannot be read",
                );
            }
            Err(_) => return ingress_error(StatusCode::REQUEST_TIMEOUT, "request body timed out"),
        };
        req = Request::from_parts(parts, Body::from(bytes));
    }
    let mut r = next.run(req).await;
    for (k, v) in [
        ("cache-control", "no-store"),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        (
            "content-security-policy",
            "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' blob: data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
    ] {
        r.headers_mut().insert(k, v.parse().unwrap());
    }
    r
}
async fn new_session(State(app): State<App>, headers: HeaderMap) -> Response {
    if headers
        .get("x-nightbuoy-bootstrap")
        .and_then(|h| h.to_str().ok())
        != Some("1")
    {
        return StatusCode::FORBIDDEN.into_response();
    }

    let mut map = app.sessions.lock().await; // Hard bounds; expired sessions cannot be revived.
    map.retain(|_, s| {
        s.try_lock().map_or(true, |s| {
            s.created.elapsed() < Duration::from_secs(8 * 3600)
        })
    });
    // Reuse the browser's live session; polling/reloading does not allocate more slots.
    if let Some(session) = crate::api::cookie(&headers, "nb_portable")
        .and_then(|id| map.get(&hash(id)))
        .cloned()
    {
        // An in-flight refresh is not a missing session. Release the registry
        // before waiting so unrelated browsers can still bootstrap.
        drop(map);
        let s = session.lock().await;
        if s.created.elapsed() < Duration::from_secs(8 * 3600) {
            return Json(json!({"mode":"portable","csrf":s.csrf})).into_response();
        }
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let mut admissions = app.admissions.lock().await;
    admissions
        .retain(|id, (_, t)| map.contains_key(id) && t.elapsed() < Duration::from_secs(8 * 3600));
    // Evict the oldest unauthenticated attempt instead of locking out all newcomers for eight hours.
    if map.len() >= 32 {
        let oldest = map
            .iter()
            .filter_map(|(k, v)| {
                v.try_lock()
                    .ok()
                    .filter(|s| s.active().is_err() || !admissions.contains_key(k))
                    .map(|s| (k.clone(), s.created))
            })
            .min_by_key(|(_, t)| *t)
            .map(|(k, _)| k);
        if let Some(k) = oldest {
            map.remove(&k);
        }
    }
    if map.len() >= 32 {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let id = token();
    let csrf = token();
    map.insert(
        hash(&id),
        Arc::new(Mutex::new(Session::empty(
            csrf.clone(),
            Instant::now(),
            app.allowed.as_ref().map(|c| c.checkpoint.clone()),
        ))),
    );
    let mut r = Json(json!({"mode":"portable","csrf":csrf})).into_response();
    r.headers_mut().insert(
        "set-cookie",
        format!(
            "nb_portable={id}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800{}",
            if app.origin.starts_with("https:") {
                "; Secure"
            } else {
                ""
            }
        )
        .parse()
        .unwrap(),
    );
    r
}
async fn endpoint(
    State(app): State<App>,
    Path(path): Path<String>,
    headers: HeaderMap,
    method: axum::http::Method,
    body: Bytes,
) -> Result<Json<Value>> {
    let result: anyhow::Result<Json<Value>> = async {
 let key=crate::api::cookie(&headers,"nb_portable").ok_or_else(||anyhow::anyhow!("session required"))?;
 let session=app.sessions.lock().await.get(&hash(&key)).cloned().ok_or_else(||anyhow::anyhow!("session expired"))?;let mut s=session.lock().await;
 anyhow::ensure!(s.created.elapsed()<Duration::from_secs(8*3600),"session expired");
 if !matches!(path.as_str(),"status"|"branding"|"connection"|"me"|"sync"|"requests"|"replication"|"export"){anyhow::ensure!(method==axum::http::Method::POST,"POST required");}
 if method!=axum::http::Method::GET {anyhow::ensure!(headers.get("x-nightbuoy-csrf").and_then(|h|h.to_str().ok())==Some(s.csrf.as_str()),"CSRF check failed");}
 let v:Value=if body.is_empty(){Value::Null}else{serde_json::from_slice(&body).map_err(anyhow::Error::from)?};
 let out=match path.as_str(){
  "branding"=>app.branding.as_ref().map(|b|b.public()).unwrap_or(json!({"name":"NightBuoy","home":"/","tagline":"Community-owned conversations.","logo":"/nightbuoy.svg","favicon":"/nightbuoy.svg","links":[]})),
  "resolve"=>{let request:crate::root_url::RootRequest=serde_json::from_value(v)?;let (connection,access)=crate::root_url::resolve(request,app.testing,app.allowed.as_ref()).await?;json!({"connection":connection,"backend":access.backend})},
  "bootstrap"=>{let mut sources=vec![s.remote.as_ref().ok_or_else(||anyhow::anyhow!("connect to a storage root first"))?];sources.extend(s.replicas.iter());let index=v["source"].as_u64().unwrap_or(0) as usize;let total=sources.len();let (ephemeral,grants)=if let Some(remote)=sources.get(index){match remote.get(&opaque::head_path()).await{Ok(Some(blob))=>opaque::split_head(&blob.bytes).map(|(e,g,_)|(e,g)).unwrap_or_default(),_=>Default::default()}}else{Default::default()};json!({"ephemeral":ephemeral,"grants":grants,"sources":total})},
  "metadata"=>{let candidate=MetadataKey::from_base64(v["key"].as_str().unwrap_or(""))?;let previous_connection=s.connection.clone();let previous_data=s.data.clone();let previous_grants=s.head_grants.clone();let previous_ephemeral=s.head_ephemeral.clone();let previous_locked=s.locked;let previous_warning=s.source_warning;let previous_from_replica=s.from_replica;let previous_remote=s.remote.clone();if let Some(expected)=v["community"].as_str().filter(|c|!c.is_empty())&&let Some(c)=s.connection.as_mut(){anyhow::ensure!(c.community.is_empty()||c.community==expected,"identity belongs to another forum");c.community=expected.into();}let old=s.metadata.replace(candidate);
   match s.refresh().await{Ok(_)=>{if let Some(old)=old{s.remember_metadata(old);}json!({"unlocked":true})},Err(e)=>{s.metadata=old;s.connection=previous_connection;s.data=previous_data;s.head_grants=previous_grants;s.head_ephemeral=previous_ephemeral;s.locked=previous_locked;s.source_warning=previous_warning;s.from_replica=previous_from_replica;s.remote=previous_remote;return Err(e)}}},
  "connect"=>{
   #[derive(Deserialize)]#[serde(deny_unknown_fields)]struct Input{connection:Connection,access:Access,#[serde(default)] replica_access:Vec<Access>,#[serde(default)] metadata_key:Option<String>}
   let i:Input=serde_json::from_value(v).map_err(anyhow::Error::from)?;
   anyhow::ensure!(i.connection.version==2&&i.connection.replicas.len()<=50,"invalid connection");
   if let Some(allowed)=&app.allowed{anyhow::ensure!(i.connection.primary==allowed.primary&&i.connection.community==allowed.community&&i.connection.branch_pin==allowed.branch_pin&&(i.connection.checkpoint.is_empty()||hex_id(&i.connection.checkpoint))&&i.connection.replicas.iter().all(|r|allowed.replicas.contains(r)),"operator has not approved this backend");}
   let remote=Remote::new(i.connection.primary.clone(),i.access,app.testing)?;
   s.replicas=i.connection.replicas.iter().map(|b|{let id=b.id()?;let access=i.replica_access.iter().find(|a|a.backend==id).cloned().unwrap_or(Access{backend:id,..Default::default()});Remote::new(b.clone(),access,app.testing)}).collect::<anyhow::Result<Vec<_>>>()?;
   app.admissions.lock().await.remove(&hash(&key));s.connection=Some(i.connection);s.remote=Some(remote);s.copied_head=None;s.data=None;s.metadata=i.metadata_key.as_deref().map(MetadataKey::from_base64).transpose()?;s.metadata_history=vec![];s.head_grants.clear();s.locked=false;s.authenticated=false;s.device=None;s.plan=None;s.refresh().await?;json!({"connected":true})
  },
  "status"=>{if s.remote.is_some(){s.refresh().await?;}
   if let Some(d)=&s.data{json!({"mode":"portable","connected":true,"configured":true,"locked":false,"writable":s.remote.as_ref().is_some_and(Remote::writable),"community":d.community(),"branch":d.branch(),"genesis":d.archive.genesis,"publisher":s.connection.as_ref().unwrap().primary.id()?,"providers":[],"read_only":(s.authenticated&&s.active().is_err())||s.remote.as_ref().is_none_or(|r|r.backend.id().ok()!=s.connection.as_ref().and_then(|c|c.primary.id().ok()))})}else{json!({"mode":"portable","connected":s.remote.is_some(),"configured":s.locked,"locked":s.locked,"writable":s.remote.as_ref().is_some_and(Remote::writable),"publisher":s.connection.as_ref().map(|c|c.primary.id()).transpose()?,"providers":[],"read_only":false})}},
  "connection"=>serde_json::to_value(&s.connection).map_err(anyhow::Error::from)?,
  "challenge"=>{let device:Device=serde_json::from_value(v["device"].clone()).map_err(anyhow::Error::from)?;device.validate()?;let challenge=serde_json::to_string(&json!(["nightbuoy-login",1,token(),device.id])).unwrap();s.device=Some(device);s.authenticated=false;s.plan=None;s.challenge=Some(challenge.clone());json!({"id":"session","body":challenge})},
  "login"=>{let signed:Signed=serde_json::from_value(v["signed"].clone()).map_err(anyhow::Error::from)?;let challenge=s.challenge.take().ok_or_else(||anyhow::anyhow!("challenge required"))?;anyhow::ensure!(signed.body==challenge,"challenge mismatch");verify_member(&s.device.as_ref().unwrap().sign,&signed.body,&signed.signature)?;s.authenticated=true;
   if s.active().is_ok(){let identity=format!("{}:{}",s.data.as_ref().unwrap().community(),s.device.as_ref().unwrap().id);let mut admissions=app.admissions.lock().await;admissions.retain(|_,(_,t)|t.elapsed()<Duration::from_secs(8*3600));let session_key=hash(&key);if !admission_available(&admissions,&session_key,&identity){s.authenticated=false;anyhow::bail!("this member already has two active sessions; sign out another tab first");}admissions.insert(session_key,(identity,Instant::now()));}
   json!({"ok":true})},
  "logout"=>{app.admissions.lock().await.remove(&hash(&key));s.authenticated=false;s.device=None;s.challenge=None;s.plan=None;s.metadata=None;s.metadata_history.clear();s.data=None;s.head_grants.clear();s.locked=true;json!({"ok":true})},
  "disconnect"=>{app.admissions.lock().await.remove(&hash(&key));let ingress=s.ingress.clone();*s=Session::empty(s.csrf.clone(),s.created,s.operator_checkpoint.clone());s.ingress=ingress;json!({"ok":true})},
  "private-read"|"private-write"=>{
   if path=="private-write"{s.refresh_source(false).await?;}else{s.refresh().await?;}s.active()?;
   anyhow::ensure!(v["community"].as_str()==s.data.as_ref().map(Data::community).as_deref()&&v["branch"].as_str()==s.data.as_ref().map(Data::branch).as_deref()&&v["member"].as_str()==s.device.as_ref().map(|d|d.id.as_str()),"private state belongs to another identity or forum branch");
   let remote=s.remote.as_ref().ok_or_else(||anyhow::anyhow!("connect to a backend first"))?;
   anyhow::ensure!(remote.backend.id()?==s.connection.as_ref().unwrap().primary.id()?,"private state requires its original backend");
   let locator=v["locator"].as_str().unwrap_or("");
   let object=if path=="private-read"{crate::private_objects::read(remote,locator).await?}else{
    let encoded=v["frame"].as_str().ok_or_else(||anyhow::anyhow!("private frame required"))?;
    anyhow::ensure!(encoded.len()<=crate::private_objects::MAX_PRIVATE_OBJECT*2,"private frame too large");
    let expected=match &v["version"]{Value::Null=>None,Value::String(s)=>Some(s.as_str()),_=>anyhow::bail!("invalid private state version")};
    Some(crate::private_objects::write(remote,locator,decode(encoded)?,expected).await?)
   };
   match object{Some(blob)=>json!({"frame":b64(blob.bytes),"version":blob.version}),None=>Value::Null}
  },
  "me"=>{anyhow::ensure!(s.authenticated,"sign in required");s.refresh().await?;json!({"member":s.data.as_ref().and_then(|d|d.view().members.get(&s.device.as_ref().unwrap().id)),"read_access":s.metadata.is_some()&&s.data.is_some()})},
  "sync"=>{s.refresh().await?;anyhow::ensure!(s.authenticated&&s.metadata.is_some()&&s.data.is_some(),"sign in and unlock forum access required");serde_json::to_value(&s.data.as_ref().unwrap().archive).map_err(anyhow::Error::from)?},
  "join"=>{anyhow::ensure!(s.authenticated,"sign in required");let signed:Signed=serde_json::from_value(v["signed"].clone())?;let device=s.device.as_ref().unwrap();let expected=if let Some(data)=&s.data{json!(["nightbuoy-join",1,data.community(),device])}else{json!(["nightbuoy-join",2,s.connection.as_ref().unwrap().primary.id()?,device])};anyhow::ensure!(signed.body==serde_json::to_string(&expected)?,"invalid membership request");verify_member(&device.sign,&signed.body,&signed.signature)?;json!({"request":{"device":device,"signed":signed},"export_required":true})},
  "requests"=>{s.active()?;json!(s.requests)},
  "request-import"=>{anyhow::ensure!(s.active()?.role=="administrator","administrator required");let device:Device=serde_json::from_value(v["device"].clone())?;device.validate()?;let signed:Signed=serde_json::from_value(v["signed"].clone())?;let expected=serde_json::to_string(&json!(["nightbuoy-join",1,s.data.as_ref().unwrap().community(),device]))?;let opaque_target=serde_json::to_string(&json!(["nightbuoy-join",2,s.connection.as_ref().unwrap().primary.id()?,device]))?;anyhow::ensure!(signed.body==expected||signed.body==opaque_target,"request targets another forum");verify_member(&device.sign,&signed.body,&signed.signature)?;anyhow::ensure!(s.requests.len()<100,"request limit");s.requests.push(json!({"device":device,"signed":signed,"verified":false}));json!({"ok":true})},
  "prepare"|"recover-prepare"=>{
   anyhow::ensure!(s.authenticated,"sign in required");if s.metadata.is_none(){s.metadata=v["metadata_key"].as_str().map(MetadataKey::from_base64).transpose()?;}let parent=s.refresh_source(false).await?;anyhow::ensure!(s.remote.as_ref().unwrap().writable(),"Provider write permission required. Add your scoped storage credential.");anyhow::ensure!(s.remote.as_ref().unwrap().backend.id()?==s.connection.as_ref().unwrap().primary.id()?,"This root is a read-only encrypted copy; connect to the active write backend or explicitly recover to a new branch.");
   let signed:Signed=serde_json::from_value(v["signed"].clone()).map_err(anyhow::Error::from)?;let primary=s.connection.as_ref().unwrap().primary.id()?;
   let item=match v["kind"].as_str(){Some("genesis")=>{anyhow::ensure!(app.allowed.is_none(),"create communities using a personal local client");protocol::Item::Genesis(signed)},Some("control")=>protocol::Item::Control(signed),Some("event")=>protocol::Item::Event(Record{event:signed,publisher:primary.clone(),receipt:String::new()}),_=>anyhow::bail!("invalid transaction type")};
   anyhow::ensure!(item.actor()?==s.device.as_ref().unwrap().id,"transaction author mismatch");verify_member(&s.device.as_ref().unwrap().sign,&item.signed().body,&item.signed().signature)?;
   if s.data.as_ref().is_some_and(|d|d.archive.order.contains(&item.signed().hash())||d.community()==item.signed().hash()){json!({"accepted":true})}else{
    let old_epoch=s.data.as_ref().map(|d|d.view().epoch);let mut data=if path=="recover-prepare" {
     anyhow::ensure!(s.data.is_none()&&parent.is_none(),"recovery requires a new empty backend namespace");
     let a:Archive=serde_json::from_value(v["archive"].clone())?;let old=Data::replay(&a)?;let fields:Value=serde_json::from_str(&item.signed().body)?;
     anyhow::ensure!(matches!(item,protocol::Item::Control(_))&&fields[6]=="reconstitute","explicit branch reset required");
     anyhow::ensure!(old.view().policy.portable.as_ref().is_none_or(|p|p.primary!=primary),"new branch requires a distinct backend identity");Some(old)
    }else{let fields:Value=serde_json::from_str(&item.signed().body)?;anyhow::ensure!(!matches!(item,protocol::Item::Control(_))||fields[6]!="reconstitute","branch resets require explicit recovery onto an empty distinct backend");s.data.clone()};
    let mut cert=if let Some(old)=&data {if let Some(p)=&old.archive.portable_proof{p.clone()}else{protocol::Certificate{anchor:Some(Box::new(old.archive.clone())),headers:vec![]}}}else{protocol::Certificate::default()};let sequence=data.as_ref().map(|d|d.archive.order.len()+1).unwrap_or(0);item.apply(&mut data)?;let mut data=data.unwrap();
    anyhow::ensure!(data.view().policy.portable.as_ref().is_some_and(|p|p.primary==primary),"portable backend mismatch");
    let previous=if let Some(h)=cert.headers.last(){protocol::digest(h)?}else if let Some(a)=&cert.anchor{protocol::digest(&json!({"kind":"legacy_anchor","data":a}))?}else{String::new()};let body=protocol::header_body(&data,&item,&previous,sequence)?;
    data.archive.portable_proof=Some(std::mem::take(&mut cert));
    let metadata=if old_epoch==Some(data.view().epoch){s.metadata.clone().ok_or_else(||anyhow::anyhow!("unlock metadata first"))?}else{MetadataKey::from_base64(v["metadata_key"].as_str().unwrap_or(""))?};
    let wrapped:std::collections::BTreeMap<String,String>=serde_json::from_value(v["metadata_wrapped"].clone())?;validate_wrapped(&data,&wrapped)?;
    let ephemeral=v["metadata_ephemeral"].as_str().ok_or_else(||anyhow::anyhow!("anonymous discovery envelope required"))?.to_string();
    anyhow::ensure!(data.view().discovery.as_ref().is_some_and(|d|d.ephemeral==ephemeral),"unsigned discovery point replacement forbidden");
    let ticket=token();s.plan=Some(Plan{ticket:ticket.clone(),body:body.clone(),data,item,parent,metadata,wrapped});json!({"ticket":ticket,"body":body})
   }
  },
  "commit"=>{
   anyhow::ensure!(s.authenticated,"sign in required");let plan=s.plan.as_ref().ok_or_else(||anyhow::anyhow!("prepare required"))?;anyhow::ensure!(v["ticket"]==plan.ticket,"invalid write ticket");
   let header:Signed=serde_json::from_value(v["header"].clone()).map_err(anyhow::Error::from)?;anyhow::ensure!(header.body==plan.body,"append context changed");verify_member(&s.device.as_ref().unwrap().sign,&header.body,&header.signature)?;
   let mut data=plan.data.clone();data.archive.portable_proof.as_mut().unwrap().headers.push(header.clone());protocol::verify(&data)?;
   let remote=s.remote.as_ref().unwrap();publish_opaque(remote,&plan.metadata,&data,&s.connection.as_ref().unwrap().primary,plan.parent.as_ref(),Some(&plan.item)).await?;
   let metadata=plan.metadata.clone();let wrapped=plan.wrapped.clone();if let Some(old)=s.metadata.replace(metadata){s.remember_metadata(old);}s.head_grants=wrapped;s.data=Some(data);s.plan=None;s.refresh().await?;json!({"confirmed":true})
  },
  "export"=>{s.refresh().await?;s.active()?;let data=s.data.as_ref().unwrap();let d=data.view().discovery.as_ref().ok_or_else(||anyhow::anyhow!("signed discovery grants required"))?;let bytes=opaque::head_frame(s.metadata.as_ref().unwrap(),&d.wrapped.values().cloned().collect::<Vec<_>>(),&d.ephemeral,&data.archive,&opaque::context("","private-archive"))?;json!({"frame":b64(bytes)})},
  "replication"=>{s.active()?;json!({"copied":s.data.as_ref().and_then(|d|protocol::head(&d.archive).ok()).is_some_and(|h|s.copied_head.as_ref()==Some(&h)),"remote":true,"from_replica":s.from_replica,"error":if s.source_warning{Some("A configured source is unavailable, invalid, stale or conflicting. Reading a verified compatible copy; write authority has not changed.")}else{None}})},
  "replica-copy"=>{
   s.refresh().await?;s.active()?;
   #[derive(Deserialize)]#[serde(deny_unknown_fields)]struct Input{backend:Backend,access:Access,#[serde(default)]metadata_keys:Vec<String>}
   let i:Input=serde_json::from_value(v)?;if let Some(allowed)=&app.allowed{anyhow::ensure!(allowed.replicas.contains(&i.backend),"operator has not approved this backend");}
   anyhow::ensure!(s.replicas.len()<50,"replica limit");let remote=Remote::new(i.backend.clone(),i.access,app.testing)?;let key=s.metadata.as_ref().ok_or_else(||anyhow::anyhow!("unlock metadata first"))?;let mut old_result=load(&remote,key).await;
   if old_result.is_err(){for previous in &s.metadata_history{if let Ok(old)=load(&remote,previous).await{old_result=Ok(old);break;}}}
   if old_result.is_err(){anyhow::ensure!(i.metadata_keys.len()<=4096,"too many historical metadata keys");for previous in &i.metadata_keys{let previous=MetadataKey::from_base64(previous)?;if let Ok(old)=load(&remote,&previous).await{old_result=Ok(old);break;}}}let old=old_result?;
   let data=s.data.as_ref().unwrap();if let Some((_,d,_))=&old{d.catch_up(&data.archive)?;let previous=protocol::head(&d.archive)?;anyhow::ensure!(data.archive.portable_proof.as_ref().unwrap().headers.iter().any(|h|protocol::digest(h).ok().as_ref()==Some(&previous)),"replica head fork");}
   publish_opaque(&remote,key,data,&s.connection.as_ref().unwrap().primary,old.as_ref().map(|(b,_,_)|b),None).await?;
   let copied=protocol::head(&data.archive)?;
   let c=s.connection.as_mut().unwrap();if !c.replicas.contains(&i.backend){c.replicas.push(i.backend);}s.replicas.retain(|r|r.backend!=remote.backend);s.replicas.push(remote);s.copied_head=Some(copied);json!({"copied":true})
  },
  _=>anyhow::bail!("unsupported portable operation"),
 };Ok(Json(out))
 }.await;
    result.map_err(Error)
}
async fn branding_asset(State(app): State<App>, Path(file): Path<String>) -> Response {
    if let Some((path, mime)) = app.branding.as_ref().and_then(|b| b.asset(&file))
        && let Ok(bytes) = tokio::fs::read(path).await
    {
        return (
            [
                (axum::http::header::CONTENT_TYPE, mime),
                (
                    axum::http::header::CONTENT_SECURITY_POLICY,
                    "default-src 'none'; style-src 'unsafe-inline'; sandbox",
                ),
            ],
            bytes,
        )
            .into_response();
    }
    StatusCode::NOT_FOUND.into_response()
}
async fn asset(uri: axum::http::Uri) -> Response {
    let path = uri.path();
    let entry = ASSETS.iter().find(|(p, _)| *p == path).or_else(|| {
        if !path.starts_with("/api/") && !path.rsplit('/').next().unwrap_or("").contains('.') {
            ASSETS.iter().find(|(p, _)| *p == "/index.html")
        } else {
            None
        }
    });
    if let Some((name, bytes)) = entry {
        let mime = if name.ends_with(".js") {
            "text/javascript"
        } else if name.ends_with(".css") {
            "text/css"
        } else if name.ends_with(".svg") {
            "image/svg+xml"
        } else if name.ends_with(".wasm") {
            "application/wasm"
        } else if name.ends_with(".html") {
            "text/html"
        } else {
            "application/octet-stream"
        };
        ([(axum::http::header::CONTENT_TYPE, mime)], *bytes).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}
pub fn router(app: App) -> Router {
    let router = Router::new()
        .route("/api/session", post(new_session))
        .route("/branding/{file}", get(branding_asset))
        .route("/api/{path}", get(endpoint).post(endpoint));
    let router = if ASSETS.is_empty() {
        router.fallback_service(
            tower_http::services::ServeDir::new(&app.web).not_found_service(
                tower_http::services::ServeFile::new(format!("{}/index.html", app.web)),
            ),
        )
    } else {
        router.fallback(asset)
    };
    router
        .layer(DefaultBodyLimit::max(opaque::MAX_FRAME * 2))
        .layer(middleware::from_fn_with_state(app.clone(), security))
        .with_state(app)
}
pub async fn run() -> anyhow::Result<()> {
    run_mode(false).await
}
pub async fn run_gui() -> anyhow::Result<()> {
    run_mode(true).await
}
async fn run_mode(open_gui: bool) -> anyhow::Result<()> {
    let listen: std::net::SocketAddr = std::env::var("NIGHTBUOY_LISTEN")
        .unwrap_or("127.0.0.1:8080".into())
        .parse()?;
    let origin = std::env::var("NIGHTBUOY_PUBLIC_URL")
        .unwrap_or(format!("http://localhost:{}", listen.port()))
        .trim_end_matches('/')
        .to_string();
    let u = url::Url::parse(&origin)?;
    let personal = listen.ip().is_loopback()
        && matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    let allowed = std::env::var("NIGHTBUOY_CONNECTION_FILE")
        .ok()
        .map(|p| -> anyhow::Result<Connection> { Ok(serde_json::from_slice(&std::fs::read(p)?)?) })
        .transpose()?;
    if let Some(c) = &allowed {
        anyhow::ensure!(
            c.version == 2
                && c.replicas.len() <= 50
                && hex_id(&c.community)
                && hex_id(&c.branch_pin)
                && hex_id(&c.checkpoint),
            "hosted connection must pin community, branch and checkpoint"
        );
    }
    anyhow::ensure!(
        personal || allowed.is_some(),
        "hosted mode requires an operator-approved connection file"
    );
    anyhow::ensure!(
        (personal && matches!(u.scheme(), "http" | "https"))
            || u.scheme() == "https"
            || (u.scheme() == "http" && crate::config::onion(u.host_str().unwrap_or(""))),
        "public frontends require HTTPS or Tor"
    );
    if crate::config::onion(u.host_str().unwrap_or("")) {
        anyhow::ensure!(
            std::env::var("NIGHTBUOY_SOCKS_PROXY").is_ok_and(|p| p.starts_with("socks5h://")),
            "onion hosting requires an explicit socks5h privacy path"
        );
    }
    let testing = std::env::var("NIGHTBUOY_TESTING").as_deref() == Ok("1");
    anyhow::ensure!(
        !testing || personal,
        "test transport is restricted to loopback"
    );
    anyhow::ensure!(
        u.path() == "/"
            && u.username().is_empty()
            && u.password().is_none()
            && u.query().is_none()
            && u.fragment().is_none(),
        "public URL must be an origin"
    );
    let app = App {
        sessions: Default::default(),
        admissions: Default::default(),
        ingress: Default::default(),
        origin: origin.clone(),
        web: std::env::var("NIGHTBUOY_WEB").unwrap_or("web/dist".into()),
        testing,
        allowed,
        branding: std::env::var("NIGHTBUOY_BRANDING_DIR")
            .ok()
            .map(|p| crate::branding::Branding::load(std::path::Path::new(&p)))
            .transpose()?,
    };
    let listener = tokio::net::TcpListener::bind(listen).await?;
    eprintln!(
        "NightBuoy portable client: {origin} (RAM-only companion; durable data on selected backends)"
    );
    if open_gui
        && personal
        && let Err(error) = open_browser(&origin)
    {
        eprintln!("Could not open a browser ({error}); open {origin} manually.");
    }
    axum::serve(listener, router(app))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

fn open_browser(origin: &str) -> std::io::Result<()> {
    // No shell interpolation. The validated local origin is a single process argument.
    #[cfg(target_os = "macos")]
    let mut command = std::process::Command::new("open");
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut c = std::process::Command::new("rundll32.exe");
        c.arg("url.dll,FileProtocolHandler");
        c
    };
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let mut command = std::process::Command::new("xdg-open");
    command
        .arg(origin)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use tower::ServiceExt;
    async fn ingress_fixture(active: bool) -> (App, Arc<Mutex<Session>>) {
        let app = App {
            sessions: Default::default(),
            admissions: Default::default(),
            ingress: Default::default(),
            origin: "http://localhost:8080".into(),
            web: "/nonexistent".into(),
            testing: true,
            allowed: None,
            branding: None,
        };
        let mut session = Session::empty("csrf".into(), Instant::now(), None);
        if active {
            let f: Value =
                serde_json::from_str(include_str!("../tests/fixtures/browser-identity.json"))
                    .unwrap();
            let device: Device = serde_json::from_value(f["vault"]["device"].clone()).unwrap();
            let f: Value =
                serde_json::from_str(include_str!("../tests/fixtures/member-state.json")).unwrap();
            let mut data: Data = serde_json::from_value(f["data"].clone()).unwrap();
            // The gate consumes an already authenticated membership cache, not a new archive.
            let view:View=serde_json::from_value(json!({"policy":{"name":"Ingress fixture","skin":"nightbuoy","admission":"approval","history":true,"identity":"key"},"epoch":1,"members":{(device.id.clone()):{"device":device,"role":"member","status":"active","floor":1}},"grants":{},"publishers":[]})).unwrap();
            data.views.insert(data.tip.clone(), Arc::new(view));
            session.data = Some(data);
            session.device = Some(device);
            session.authenticated = true;
        }
        let session = Arc::new(Mutex::new(session));
        app.sessions
            .lock()
            .await
            .insert(hash("ingress-session"), session.clone());
        (app, session)
    }
    fn ingress_request(path: &str, body: Body) -> Request {
        Request::builder()
            .method("POST")
            .uri(format!("/api/{path}"))
            .header("host", "localhost:8080")
            .header("origin", "http://localhost:8080")
            .header("cookie", "nb_portable=ingress-session")
            .header("x-nightbuoy-csrf", "csrf")
            .body(body)
            .unwrap()
    }
    fn counted_body(bytes: Bytes, count: Arc<AtomicUsize>) -> Body {
        Body::from_stream(futures::stream::once(async move {
            count.fetch_add(1, AtomicOrdering::SeqCst);
            Ok::<_, std::io::Error>(bytes)
        }))
    }
    #[tokio::test]
    async fn protected_ingress_rejects_unauthenticated_streams_before_polling() {
        let (app, _) = ingress_fixture(false).await;
        for path in [
            "prepare",
            "%70repare",
            "commit",
            "private-write",
            "recover-prepare",
        ] {
            let count = Arc::new(AtomicUsize::new(0));
            let request = ingress_request(
                path,
                counted_body(Bytes::from_static(b"not polled"), count.clone()),
            );
            assert_eq!(
                router(app.clone()).oneshot(request).await.unwrap().status(),
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(count.load(AtomicOrdering::SeqCst), 0);
        }
    }
    #[tokio::test]
    async fn ingress_admission_bounds_same_session_and_global_work_before_polling() {
        let (app, session) = ingress_fixture(false).await;
        let slots = session.lock().await.ingress.clone();
        let held = slots.clone().acquire_many_owned(4).await.unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let response = router(app.clone())
            .oneshot(ingress_request(
                "metadata",
                counted_body(Bytes::from_static(b"{}"), count.clone()),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(count.load(AtomicOrdering::SeqCst), 0);
        drop(held);
        let held = app
            .ingress
            .normal
            .clone()
            .acquire_many_owned(32)
            .await
            .unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        assert_eq!(
            router(app.clone())
                .oneshot(ingress_request(
                    "metadata",
                    counted_body(Bytes::from_static(b"{}"), count.clone())
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(count.load(AtomicOrdering::SeqCst), 0);
        assert_eq!(slots.available_permits(), 4);
        drop(held);
        let count = Arc::new(AtomicUsize::new(0));
        assert_eq!(
            router(app.clone())
                .oneshot(ingress_request(
                    "metadata",
                    counted_body(Bytes::from_static(b"{}"), count.clone())
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(count.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(slots.available_permits(), 4);
        assert_eq!(app.ingress.normal.available_permits(), 32);
    }
    #[tokio::test]
    async fn ingress_limits_apply_to_streams_and_admit_large_member_posts() {
        let (app, _) = ingress_fixture(false).await;
        let count = Arc::new(AtomicUsize::new(0));
        let mut declared = ingress_request(
            "metadata",
            counted_body(Bytes::from_static(b"unread"), count.clone()),
        );
        declared
            .headers_mut()
            .insert("content-length", (300 * 1024).to_string().parse().unwrap());
        assert_eq!(
            router(app.clone())
                .oneshot(declared)
                .await
                .unwrap()
                .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(count.load(AtomicOrdering::SeqCst), 0);
        let count = Arc::new(AtomicUsize::new(0));
        assert_eq!(
            router(app)
                .oneshot(ingress_request(
                    "metadata",
                    counted_body(Bytes::from(vec![b' '; 300 * 1024]), count.clone())
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(count.load(AtomicOrdering::SeqCst), 1);
        let (app, session) = ingress_fixture(true).await;
        assert_eq!(
            body_limit(&app, &*session.lock().await, "private-write").unwrap(),
            384 * 1024
        );
        let count = Arc::new(AtomicUsize::new(0));
        let response = router(app.clone())
            .oneshot(ingress_request(
                "prepare",
                counted_body(Bytes::from(vec![b' '; 6 * 1024 * 1024]), count.clone()),
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "large member input reaches endpoint validation rather than the body limit"
        );
        assert_eq!(count.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(app.ingress.posts.available_permits(), 8);
    }
    #[tokio::test]
    async fn large_recovery_is_personal_authenticated_and_empty_only() {
        let (mut app, session) = ingress_fixture(false).await;
        let backend = Backend {
            kind: "forgejo".into(),
            endpoint: "http://127.0.0.1:9".into(),
            namespace: "test".into(),
            salt: b64(random::<32>()),
            owner: "owner".into(),
            repository: "repo".into(),
            branch: "main".into(),
            bucket: String::new(),
            region: "us-east-1".into(),
        };
        let mut s = session.lock().await;
        s.remote = Some(
            Remote::new(
                backend.clone(),
                Access {
                    backend: backend.id().unwrap(),
                    ..Default::default()
                },
                true,
            )
            .unwrap(),
        );
        assert_eq!(
            body_limit(&app, &s, "recover-prepare").err().unwrap().0,
            StatusCode::UNAUTHORIZED
        );
        s.authenticated = true;
        assert_eq!(
            body_limit(&app, &s, "recover-prepare").unwrap(),
            opaque::MAX_FRAME * 2
        );
        s.locked = true;
        assert_eq!(
            body_limit(&app, &s, "recover-prepare").err().unwrap().0,
            StatusCode::FORBIDDEN
        );
        s.locked = false;
        app.allowed = Some(Connection {
            version: 2,
            primary: backend,
            replicas: vec![],
            community: String::new(),
            branch_pin: String::new(),
            checkpoint: String::new(),
        });
        assert_eq!(
            body_limit(&app, &s, "recover-prepare").err().unwrap().0,
            StatusCode::FORBIDDEN
        );
    }
    #[test]
    fn switching_identity_cannot_bypass_member_session_quota() {
        let mut registry = HashMap::new();
        for (session, identity) in [("a1", "A"), ("b1", "B"), ("b2", "B")] {
            registry.insert(session.into(), (identity.into(), Instant::now()));
        }
        assert!(!admission_available(&registry, "a1", "B"));
        assert!(admission_available(&registry, "b1", "B"));
        assert!(admission_available(&registry, "new", "A"));
    }
    #[tokio::test]
    async fn busy_session_bootstrap_reuses_existing_connection() {
        let app = App {
            sessions: Default::default(),
            admissions: Default::default(),
            ingress: Default::default(),
            origin: "http://localhost:8080".into(),
            web: "/nonexistent".into(),
            testing: true,
            allowed: None,
            branding: None,
        };
        let mut headers = HeaderMap::new();
        headers.insert("x-nightbuoy-bootstrap", "1".parse().unwrap());
        let initial = new_session(State(app.clone()), headers.clone()).await;
        let cookie = initial.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        headers.insert("cookie", cookie.parse().unwrap());
        let session = app.sessions.lock().await.values().next().unwrap().clone();
        let guard = session.lock().await;
        let csrf = guard.csrf.clone();
        let task = tokio::spawn(new_session(State(app.clone()), headers));
        tokio::task::yield_now().await;
        assert!(
            !task.is_finished(),
            "bootstrap must wait for the busy session"
        );
        assert_eq!(app.sessions.lock().await.len(), 1);
        drop(guard);
        let response = task.await.unwrap();
        assert!(!response.headers().contains_key("set-cookie"));
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["csrf"], csrf);
        assert_eq!(app.sessions.lock().await.len(), 1);
    }
    #[tokio::test]
    async fn expired_portable_sessions_return_401_before_body_parsing() {
        let app = App {
            sessions: Default::default(),
            admissions: Default::default(),
            ingress: Default::default(),
            origin: "http://localhost:8080".into(),
            web: "/nonexistent".into(),
            testing: true,
            allowed: None,
            branding: None,
        };
        let session = Session {
            csrf: "csrf".into(),
            created: Instant::now() - Duration::from_secs(9 * 3600),
            connection: None,
            remote: None,
            replicas: vec![],
            from_replica: false,
            copied_head: None,
            source_warning: false,
            data: None,
            metadata: None,
            metadata_history: vec![],
            locked: false,
            head_grants: Default::default(),
            head_ephemeral: String::new(),
            operator_checkpoint: None,
            device: None,
            challenge: None,
            authenticated: false,
            plan: None,
            requests: vec![],
            ingress: Arc::new(Semaphore::new(4)),
        };
        app.sessions
            .lock()
            .await
            .insert(hash("expired"), Arc::new(Mutex::new(session)));
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/api/prepare")
            .header("host", "localhost:8080")
            .header("origin", "http://localhost:8080")
            .header("cookie", "nb_portable=expired")
            .header("x-nightbuoy-csrf", "csrf")
            .body(axum::body::Body::from("invalid JSON"))
            .unwrap();
        assert_eq!(
            router(app).oneshot(request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }
}
