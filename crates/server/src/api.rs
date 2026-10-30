use crate::{
    config::Config,
    crypto::*,
    model::*,
    store::{Store, now},
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex, MutexGuard};
use subtle::ConstantTimeEq;
#[derive(Clone)]
pub struct App {
    pub store: Arc<Mutex<Store>>,
    pub config: Arc<Config>,
    pub client: reqwest::Client,
    pub replication: Arc<Mutex<crate::replication::Status>>,
    pub consensus: Option<Arc<crate::consensus::Consensus>>,
}
type Result<T> = std::result::Result<T, Error>;
pub struct Error(StatusCode, String);
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error":self.1}))).into_response()
    }
}
impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        let m = e.to_string();
        let code =
            if m.contains("unavailable") || m.contains("unconfirmed") || m.contains("pending") {
                StatusCode::SERVICE_UNAVAILABLE
            } else if m.contains("fork")
                || m.contains("diverged")
                || m.contains("stale")
                || m.contains("duplicate")
            {
                StatusCode::CONFLICT
            } else if m.contains("required") || m.contains("revoked") || m.contains("permission") {
                StatusCode::FORBIDDEN
            } else if m.contains("rate limit") {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::BAD_REQUEST
            };
        Self(code, m)
    }
}
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            "local persistence failed".into(),
        )
    }
}
fn bad(s: &str) -> Error {
    Error(StatusCode::BAD_REQUEST, s.into())
}
fn locked(s: &App) -> MutexGuard<'_, Store> {
    s.store.lock().unwrap()
}
pub fn cookie(h: &HeaderMap, name: &str) -> Option<String> {
    h.get("cookie")?.to_str().ok()?.split(';').find_map(|s| {
        let (k, v) = s.trim().split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}
fn set_cookie(app: &App, name: &str, value: &str, age: u64) -> String {
    format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={age}{}",
        if app.config.public_url.starts_with("https:") {
            "; Secure"
        } else {
            ""
        }
    )
}
fn member(s: &Store, h: &HeaderMap, active: bool) -> Result<String> {
    let t = cookie(h, "nb_session")
        .ok_or_else(|| Error(StatusCode::UNAUTHORIZED, "sign in required".into()))?;
    let id: Option<String> =
        s.db.query_row(
            "SELECT member FROM sessions WHERE token=?1 AND expires>=?2",
            params![hash(t), now()],
            |r| r.get(0),
        )
        .optional()?;
    let id = id.ok_or_else(|| {
        Error(
            StatusCode::UNAUTHORIZED,
            "session expired; sign in again".into(),
        )
    })?;
    if active {
        let m = s
            .data
            .as_ref()
            .and_then(|d| d.view().members.get(&id))
            .ok_or_else(|| {
                Error(
                    StatusCode::FORBIDDEN,
                    "membership awaiting administrator approval".into(),
                )
            })?;
        if m.status != "active" {
            return Err(Error(StatusCode::FORBIDDEN, "membership revoked".into()));
        }
    }
    Ok(id)
}
fn admin(s: &Store, h: &HeaderMap) -> Result<String> {
    let id = member(s, h, true)?;
    if s.data.as_ref().unwrap().view().members[&id].role != "administrator" {
        return Err(Error(
            StatusCode::FORBIDDEN,
            "administrator required".into(),
        ));
    }
    Ok(id)
}
fn bootstrap(s: &Store, h: &HeaderMap) -> Result<()> {
    let provided = h
        .get("x-bootstrap-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if s.data.is_some()
        || s.bootstrap.is_empty()
        || !bool::from(
            hash(provided)
                .as_bytes()
                .ct_eq(hash(&s.bootstrap).as_bytes()),
        )
    {
        return Err(Error(
            StatusCode::FORBIDDEN,
            "invalid or consumed setup token".into(),
        ));
    }
    Ok(())
}
async fn security(State(app): State<App>, req: Request, next: Next) -> Response {
    let mutation = !matches!(
        *req.method(),
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    );
    if mutation
        && req.headers().get("origin").and_then(|v| v.to_str().ok()) != Some(&app.config.public_url)
    {
        return Error(
            StatusCode::FORBIDDEN,
            "Origin does not match this deployment".into(),
        )
        .into_response();
    }
    if app.config.read_only
        && (req.uri().path().starts_with("/auth/")
            || (mutation
                && !matches!(
                    req.uri().path(),
                    "/api/challenge" | "/api/login" | "/api/logout" | "/api/restore"
                )))
    {
        return Error(
            StatusCode::FORBIDDEN,
            "This deployment is read-only; use a publishing frontend for changes.".into(),
        )
        .into_response();
    }
    // Authenticate before a JSON extractor allocates an archive-sized request body.
    if mutation {
        let authorized = {
            let s = locked(&app);
            match req.uri().path() {
                "/api/events" => member(&s, req.headers(), true).map(|_| ()),
                "/api/control" | "/api/import" | "/api/replicate" => {
                    admin(&s, req.headers()).map(|_| ())
                }
                "/api/setup" => bootstrap(&s, req.headers())
                    .and_then(|_| member(&s, req.headers(), false).map(|_| ())),
                "/api/restore" => bootstrap(&s, req.headers()),
                "/api/join" => member(&s, req.headers(), false).map(|_| ()),
                _ => Ok(()),
            }
        };
        if let Err(error) = authorized {
            return error.into_response();
        }
    }
    let mut response = next.run(req).await;
    let h = response.headers_mut();
    for (k, v) in [
        ("cache-control", "no-store"),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        (
            "permissions-policy",
            "camera=(), microphone=(), geolocation=(), payment=()",
        ),
        (
            "content-security-policy",
            "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        ),
    ] {
        if k != "content-security-policy" || !h.contains_key(k) {
            h.insert(k, HeaderValue::from_static(v));
        }
    }
    if app.config.public_url.starts_with("https:") {
        h.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000"),
        );
    }
    response
}
pub fn router(app: App) -> Router {
    let static_files = tower_http::services::ServeDir::new(&app.config.web).fallback(
        tower_http::services::ServeFile::new(app.config.web.join("index.html")),
    );
    Router::new()
        .route("/healthz", get(|| async { Json(json!({"ok":true})) }))
        .route("/api/status", get(status))
        .route("/api/branding", get(branding))
        .route("/branding/{file}", get(branding_asset))
        .route(
            "/api/challenge",
            post(challenge).layer(DefaultBodyLimit::max(32 * 1024)),
        )
        .route(
            "/api/login",
            post(login).layer(DefaultBodyLimit::max(32 * 1024)),
        )
        .route("/api/logout", post(logout))
        .route(
            "/api/join",
            post(join).layer(DefaultBodyLimit::max(32 * 1024)),
        )
        .route("/api/me", get(me))
        .route(
            "/api/setup",
            post(setup).layer(DefaultBodyLimit::max(8_500_000)),
        )
        .route("/api/restore", post(restore))
        .route("/api/sync", get(sync))
        .route(
            "/api/control",
            post(control).layer(DefaultBodyLimit::max(8_500_000)),
        )
        .route(
            "/api/events",
            post(event).layer(DefaultBodyLimit::max(8_500_000)),
        )
        .route("/api/requests", get(requests))
        .route("/api/replication", get(replication))
        .route("/api/replicate", post(replicate))
        .route("/api/import", post(import))
        .route("/auth/{provider}", get(oauth_start))
        .route("/auth/{provider}/callback", get(oauth_callback))
        .fallback_service(static_files)
        .layer(DefaultBodyLimit::max(64 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(app.clone(), security))
        .with_state(app)
}
async fn branding(State(app): State<App>) -> Json<Value> {
    if locked(&app).data.is_some()
        && let Some(brand) = &app.config.branding
    {
        return Json(brand.public());
    }
    Json(
        json!({"name":"NightBuoy","home":"/","tagline":"Community-owned conversations.","logo":"/nightbuoy.svg","favicon":"/nightbuoy.svg","links":[]}),
    )
}
async fn branding_asset(State(app): State<App>, Path(file): Path<String>) -> Result<Response> {
    let brand = app
        .config
        .branding
        .as_ref()
        .ok_or_else(|| Error(StatusCode::NOT_FOUND, "asset not found".into()))?;
    let (path, mime) = brand
        .asset(&file)
        .ok_or_else(|| Error(StatusCode::NOT_FOUND, "asset not found".into()))?;
    let meta = tokio::fs::symlink_metadata(&path)
        .await
        .map_err(|_| bad("branding asset unavailable"))?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 4 * 1024 * 1024 {
        return Err(bad("invalid branding asset"));
    }
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|_| bad("branding asset unavailable"))?;
    Ok((
        [
            ("content-type", mime),
            (
                "content-security-policy",
                "default-src 'none'; style-src 'unsafe-inline'; sandbox",
            ),
        ],
        bytes,
    )
        .into_response())
}
async fn status(State(app): State<App>) -> Json<Value> {
    let s = locked(&app);
    Json(
        json!({"configured":s.data.is_some(),"consensus":app.consensus.as_ref().map(|c|&c.trust),"genesis":s.data.as_ref().map(|d|&d.archive.genesis),"community":s.data.as_ref().map(Data::community),"branch":s.data.as_ref().map(Data::branch),"publisher":s.publication_key(),"origin":app.config.public_url,"providers":app.config.providers.iter().map(|p|json!({"id":p.id,"label":p.label})).collect::<Vec<_>>(),"test_mode":app.config.testing,"read_only":app.config.read_only}),
    )
}
#[derive(Deserialize)]
struct ChallengeInput {
    device: Device,
}
async fn challenge(
    State(app): State<App>,
    Json(input): Json<ChallengeInput>,
) -> Result<Json<Value>> {
    input.device.validate()?;
    let s = locked(&app);
    s.rate("challenges", 120)?;
    let community = s.data.as_ref().map(Data::community).unwrap_or_default();
    let body = serde_json::to_string(&json!([
        "nightbuoy-login",
        1,
        community,
        app.config.public_url,
        input.device.id,
        token()
    ]))
    .unwrap();
    let id = s.challenge(&body)?;
    Ok(Json(json!({"id":id,"body":body})))
}
#[derive(Deserialize)]
struct Login {
    challenge: String,
    device: Device,
    signed: Signed,
}
async fn login(State(app): State<App>, Json(i): Json<Login>) -> Result<Response> {
    i.device.validate()?;
    verify_member(&i.device.sign, &i.signed.body, &i.signed.signature)?;
    let s = locked(&app);
    s.rate("login", 120)?;
    s.consume(&i.challenge, &i.signed.body)?;
    let a: Vec<Value> =
        serde_json::from_str(&i.signed.body).map_err(|_| bad("invalid login body"))?;
    if a.len() != 6
        || a[0] != "nightbuoy-login"
        || a[2] != s.data.as_ref().map(Data::community).unwrap_or_default()
        || a[3] != app.config.public_url
        || a[4] != i.device.id
    {
        return Err(bad("invalid login context"));
    }
    if let Some(existing) = s.device(&i.device.id)?
        && existing != i.device
    {
        return Err(bad("enrolled identity key mismatch"));
    }
    let t = s.session(&i.device.id)?;
    Ok((
        [("set-cookie", set_cookie(&app, "nb_session", &t, 3600))],
        Json(json!({"ok":true})),
    )
        .into_response())
}
async fn logout(State(app): State<App>, h: HeaderMap) -> Result<Response> {
    let s = locked(&app);
    if let Some(t) = cookie(&h, "nb_session") {
        s.db.execute("DELETE FROM sessions WHERE token=?1", [hash(t)])?;
    }
    Ok((
        [("set-cookie", set_cookie(&app, "nb_session", "", 0))],
        Json(json!({"ok":true})),
    )
        .into_response())
}
async fn me(State(app): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    let s = locked(&app);
    let id = member(&s, &h, false)?;
    let data = s.data.as_ref();
    Ok(Json(
        json!({"id":id,"member":data.and_then(|d|d.view().members.get(&id)),"policy":data.map(|d|&d.view().policy),"tip":data.map(|d|&d.tip)}),
    ))
}
#[derive(Deserialize)]
struct Join {
    device: Device,
    signed: Signed,
}
async fn join(State(app): State<App>, h: HeaderMap, Json(i): Json<Join>) -> Result<Json<Value>> {
    let s = locked(&app);
    let id = member(&s, &h, false)?;
    if id != i.device.id {
        return Err(bad("wrong enrollment identity"));
    }
    i.device.validate()?;
    verify_member(&i.device.sign, &i.signed.body, &i.signed.signature)?;
    let a: Value = serde_json::from_str(&i.signed.body).map_err(|_| bad("invalid join proof"))?;
    let community = s.data.as_ref().map(Data::community).unwrap_or_default();
    if a != json!(["nightbuoy-join", 1, community, i.device]) {
        return Err(bad("invalid join context"));
    }
    s.rate("join", 20)?;
    let verified = s.request(&i.device, cookie(&h, "nb_enrollment").as_deref())?;
    Ok(Json(json!({"pending":true,"verified":verified})))
}
async fn confirmed(app: &App, tx: &crate::consensus::Transaction) -> Result<()> {
    let engine = app.consensus.as_ref().unwrap();
    engine.submit(&app.client, tx).await?;
    for _ in 0..40 {
        let _ = engine.update_proof(&app.client).await;
        {
            let s = locked(app);
            if s.data.as_ref().is_some_and(|d| d.verify_proof().is_ok()) {
                return Ok(());
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    Err(Error(StatusCode::SERVICE_UNAVAILABLE,"Transaction accepted; portable confirmation proof is still pending. Refresh before retrying.".into()))
}
async fn setup(
    State(app): State<App>,
    h: HeaderMap,
    Json(genesis): Json<Signed>,
) -> Result<Json<Value>> {
    let d = Data::create(genesis.clone())?;
    {
        let s = locked(&app);
        bootstrap(&s, &h)?;
        let id = member(&s, &h, false)?;
        if !d.view().members.contains_key(&id)
            || !d.view().publishers.contains(&s.publication_key())
        {
            return Err(bad("creator or initial publisher mismatch"));
        }
        if let Some(engine) = &app.consensus
            && d.view().policy.consensus.as_ref() != Some(&engine.trust)
        {
            return Err(bad("community must bind this validator set"));
        }
        if d.view().policy.identity == "forge" {
            let verified: bool =
                s.db.query_row(
                    "SELECT verified FROM requests WHERE member=?1",
                    [&id],
                    |r| r.get(0),
                )
                .optional()?
                .unwrap_or(false);
            if !verified {
                return Err(Error(
                    StatusCode::FORBIDDEN,
                    "forge verification required before creation".into(),
                ));
            }
        }
    }
    let community = d.community();
    if app.consensus.is_some() {
        confirmed(&app, &crate::consensus::Transaction::Genesis(genesis)).await?;
    } else {
        locked(&app).save(d)?;
    }
    locked(&app).bootstrap.clear();
    let _ = std::fs::remove_file(app.config.data.join("bootstrap-token"));
    Ok(Json(json!({"community":community})))
}

async fn restore(
    State(app): State<App>,
    h: HeaderMap,
    Json(archive): Json<Archive>,
) -> Result<Json<Value>> {
    {
        let s = locked(&app);
        bootstrap(&s, &h)?;
    }
    let expected = h
        .get("x-community-fingerprint")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let d = if let Some(engine) = &app.consensus {
        Data::recovery_seed(&archive, &engine.trust)?
    } else {
        Data::replay(&archive)?
    };
    if d.community() != expected {
        return Err(bad("trusted community fingerprint required"));
    }
    let id = d.community();
    if app.consensus.is_some() {
        confirmed(
            &app,
            &crate::consensus::Transaction::Recovery(Box::new(archive)),
        )
        .await?;
    } else {
        locked(&app).save(d)?;
    }
    locked(&app).bootstrap.clear();
    let _ = std::fs::remove_file(app.config.data.join("bootstrap-token"));
    Ok(Json(json!({"community":id})))
}

async fn sync(State(app): State<App>, h: HeaderMap) -> Result<Json<Archive>> {
    {
        let s = locked(&app);
        member(&s, &h, true)?;
    }
    if let Some(engine) = &app.consensus {
        let _ = engine.update_proof(&app.client).await;
    }
    let s = locked(&app);
    let data = s.data.as_ref().unwrap();
    data.verify_proof().map_err(|_| {
        Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Consensus proof pending; refresh shortly.".into(),
        )
    })?;
    Ok(Json(data.archive.clone()))
}

async fn control(
    State(app): State<App>,
    h: HeaderMap,
    Json(signed): Json<Signed>,
) -> Result<Json<Value>> {
    let next = {
        let s = locked(&app);
        let id = admin(&s, &h)?;
        let a: Value = serde_json::from_str(&signed.body).map_err(|_| bad("invalid control"))?;
        if a[4] != id {
            return Err(bad("wrong control author"));
        }
        let mut next = s.data.clone().unwrap();
        next.control(signed.clone())?;
        next
    };
    if app.consensus.is_some() {
        confirmed(&app, &crate::consensus::Transaction::Control(signed)).await?;
    } else {
        locked(&app).save(next)?;
    }
    app.replication.lock().unwrap().copied = false;
    let tip = locked(&app).data.as_ref().unwrap().tip.clone();
    Ok(Json(json!({"tip":tip})))
}
async fn event(
    State(app): State<App>,
    h: HeaderMap,
    Json(signed): Json<Signed>,
) -> Result<Json<Value>> {
    let hash = signed.hash();
    let (r, next) = {
        let s = locked(&app);
        let id = member(&s, &h, true)?;
        s.rate(&format!("event:{id}"), 30)?;
        let a: Value = serde_json::from_str(&signed.body).map_err(|_| bad("invalid event"))?;
        if a[2] != id {
            return Err(bad("wrong event author"));
        }
        let data = s.data.as_ref().unwrap();
        if data.archive.records.iter().any(|r| r.event.hash() == hash) {
            return Ok(Json(json!({"hash":hash,"state":"accepted"})));
        }
        let publisher = s.publication_key();
        let receipt = sign(&s.publisher, &receipt_bytes(&data.community(), &hash));
        let r = Record {
            event: signed,
            publisher,
            receipt,
        };
        data.validate_event(&r, true)?;
        let mut next = data.clone();
        next.event(r.clone())?;
        (r, next)
    };
    if app.consensus.is_some() {
        confirmed(&app, &crate::consensus::Transaction::Event(r)).await?;
    } else {
        locked(&app).save(next)?;
    }
    app.replication.lock().unwrap().copied = false;
    Ok(Json(
        json!({"hash":hash,"state":if app.consensus.is_some(){"confirmed"}else{"development_local"}}),
    ))
}

async fn requests(State(app): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    let s = locked(&app);
    admin(&s, &h)?;
    Ok(Json(json!(s.pending()?)))
}
async fn replication(State(app): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    let s = locked(&app);
    member(&s, &h, true)?;
    Ok(Json(
        serde_json::to_value(&*app.replication.lock().unwrap()).unwrap(),
    ))
}
async fn replicate(State(app): State<App>, h: HeaderMap) -> Result<Json<Value>> {
    {
        let s = locked(&app);
        admin(&s, &h)?;
    }
    crate::replication::once(&app).await?;
    Ok(Json(
        serde_json::to_value(&*app.replication.lock().unwrap()).unwrap(),
    ))
}
async fn import(
    State(app): State<App>,
    h: HeaderMap,
    Json(a): Json<Archive>,
) -> Result<Json<Value>> {
    if app.consensus.is_some() {
        return Err(bad(
            "A live consensus node catches up through its peers; archive resets require stopping the node.",
        ));
    }
    let mut s = locked(&app);
    admin(&s, &h)?;
    let next = s.data.as_ref().unwrap().catch_up(&a)?;
    s.save(next)?;
    Ok(Json(json!({"ok":true})))
}
#[derive(Deserialize)]
struct AuthQuery {
    #[serde(default)]
    return_to: String,
}
fn return_path(p: &str) -> String {
    if p.starts_with('/')
        && !p.starts_with("//")
        && !p.contains('\\')
        && !p.chars().any(char::is_control)
        && !p.starts_with("/auth")
    {
        p.into()
    } else {
        "/".into()
    }
}
async fn oauth_start(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(q): Query<AuthQuery>,
) -> Result<Response> {
    let p = app
        .config
        .providers
        .iter()
        .find(|p| p.id == id)
        .ok_or_else(|| bad("unknown identity provider"))?;
    let state = token();
    let verifier = token();
    let challenge = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        hex::decode(hash(&verifier)).unwrap(),
    );
    {
        let s = locked(&app);
        s.rate("oauth", 60)?;
        s.db.execute("DELETE FROM oauth WHERE expires<?1", [now()])?;
        s.db.execute(
            "INSERT INTO oauth VALUES(?1,?2,?3,?4,?5)",
            params![
                hash(&state),
                id,
                verifier,
                return_path(&q.return_to),
                now() + 600
            ],
        )?;
    }
    let mut u = url::Url::parse(&format!("{}/login/oauth/authorize", p.base_url))
        .map_err(|_| bad("invalid issuer"))?;
    u.query_pairs_mut().extend_pairs([
        ("client_id", p.client_id.as_str()),
        (
            "redirect_uri",
            &format!("{}/auth/{}/callback", app.config.public_url, p.id),
        ),
        ("response_type", "code"),
        ("state", &state),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
        ("scope", if p.kind == "forgejo" { "read:user" } else { "" }),
    ]);
    Ok((
        [("set-cookie", set_cookie(&app, "nb_oauth", &state, 600))],
        Redirect::to(u.as_str()),
    )
        .into_response())
}
#[derive(Deserialize)]
struct Callback {
    code: String,
    state: String,
}
async fn oauth_callback(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
    Query(q): Query<Callback>,
) -> Result<Response> {
    let p = app
        .config
        .providers
        .iter()
        .find(|p| p.id == id)
        .ok_or_else(|| bad("unknown identity provider"))?;
    if cookie(&h, "nb_oauth").as_deref() != Some(&q.state) {
        return Err(Error(StatusCode::FORBIDDEN, "OAuth state mismatch".into()));
    }
    let (verifier, return_to) = {
        let s = locked(&app);
        let row:Option<(String,String)>=s.db.query_row("SELECT verifier,return_to FROM oauth WHERE state=?1 AND provider=?2 AND expires>=?3",params![hash(&q.state),id,now()],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        s.db.execute("DELETE FROM oauth WHERE state=?1", [hash(&q.state)])?;
        row.ok_or_else(|| bad("expired or reused OAuth state"))?
    };
    let callback = format!("{}/auth/{id}/callback", app.config.public_url);
    let res = app
        .client
        .post(format!("{}/login/oauth/access_token", p.base_url))
        .header("Accept", "application/json")
        .form(&[
            ("client_id", &p.client_id),
            ("client_secret", &p.client_secret),
            ("code", &q.code),
            ("redirect_uri", &callback),
            ("code_verifier", &verifier),
            ("grant_type", &"authorization_code".to_string()),
        ])
        .send()
        .await
        .map_err(|_| bad("identity provider unavailable"))?;
    if !res.status().is_success() {
        return Err(bad("forge rejected authorization code"));
    }
    let token: Value = res
        .json()
        .await
        .map_err(|_| bad("invalid token response"))?;
    let token = token["access_token"]
        .as_str()
        .ok_or_else(|| bad("forge did not issue an access token"))?;
    let api = if p.kind == "github" && p.base_url == "https://github.com" {
        "https://api.github.com/user".to_string()
    } else {
        format!("{}/api/v1/user", p.base_url)
    };
    let res = app
        .client
        .get(api)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| bad("forge identity endpoint unavailable"))?;
    if !res.status().is_success() {
        return Err(bad("forge identity lookup failed"));
    }
    let u: Value = res
        .json()
        .await
        .map_err(|_| bad("invalid forge identity response"))?;
    let subject = u["id"]
        .as_u64()
        .filter(|v| *v > 0)
        .ok_or_else(|| bad("forge immutable account id missing"))?
        .to_string();
    let enrollment = crate::crypto::token();
    {
        let s = locked(&app);
        let issuer = format!("{}:{}", p.kind, p.base_url);
        let sealed = seal(
            &s.identity,
            &serde_json::to_vec(&(issuer, subject)).unwrap(),
            b"nightbuoy-enrollment-v1",
        )?;
        s.db.execute("DELETE FROM enrollment WHERE expires<?1", [now()])?;
        s.db.execute(
            "INSERT INTO enrollment VALUES(?1,?2,?3,?4)",
            params![hash(&enrollment), "sealed-v1", sealed, now() + 600],
        )?;
    }
    let mut response = Redirect::to(&return_to).into_response();
    response.headers_mut().append(
        "set-cookie",
        HeaderValue::from_str(&set_cookie(&app, "nb_enrollment", &enrollment, 600)).unwrap(),
    );
    response.headers_mut().append(
        "set-cookie",
        HeaderValue::from_str(&set_cookie(&app, "nb_oauth", "", 0)).unwrap(),
    );
    Ok(response)
}
