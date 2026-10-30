//! Ephemeral companion: sessions, credentials and verified cache are RAM-only.
use crate::{crypto::*, model::*, portable_protocol as protocol, remote::*};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Request, State},
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
use tokio::sync::Mutex;
#[derive(Clone)]
pub struct App {
    sessions: Arc<Mutex<HashMap<String, Arc<Mutex<Session>>>>>,
    admissions: Arc<Mutex<HashMap<String, (String, Instant)>>>,
    origin: String,
    web: String,
    testing: bool,
    allowed: Option<Connection>,
    branding: Option<crate::branding::Branding>,
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
    device: Option<Device>,
    challenge: Option<String>,
    authenticated: bool,
    plan: Option<Plan>,
    requests: Vec<Value>,
}
struct Plan {
    ticket: String,
    body: String,
    data: Data,
    item: protocol::Item,
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
async fn load(r: &Remote) -> anyhow::Result<Option<(Blob, Data, Head)>> {
    let Some(blob) = r.get("head.json").await? else {
        return Ok(None);
    };
    let h: Head = serde_json::from_slice(&blob.bytes)?;
    anyhow::ensure!(
        h.version == 1 && hex_id(&h.snapshot) && hex_id(&h.head),
        "invalid head"
    );
    let snap = r
        .get(&format!("objects/{}.json", h.snapshot))
        .await?
        .ok_or_else(|| anyhow::anyhow!("snapshot missing"))?;
    anyhow::ensure!(hash(&snap.bytes) == h.snapshot, "snapshot digest mismatch");
    let a: Archive = serde_json::from_slice(&snap.bytes)?;
    let d = Data::replay(&a)?;
    anyhow::ensure!(
        d.community() == h.community && d.branch() == h.branch && protocol::head(&a)? == h.head,
        "head binding mismatch"
    );
    Ok(Some((blob, d, h)))
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
    async fn refresh(&mut self) -> anyhow::Result<Option<Blob>> {
        self.refresh_source(true).await
    }
    async fn refresh_source(&mut self, fallback: bool) -> anyhow::Result<Option<Blob>> {
        let r = self
            .remote
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("connect to a backend first"))?;
        let mut sources = vec![r];
        if fallback {
            sources.extend(self.replicas.iter());
        }
        let mut selected = None;
        let mut last_error = anyhow::anyhow!("no verified compatible source available");
        let mut warnings = false;
        for (index, remote) in sources.iter().enumerate() {
            match load(remote).await.and_then(|loaded| {
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
        if let Some((_, d, _)) = loaded {
            let c = self.connection.as_mut().unwrap();
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
            d.view()
                .policy
                .portable
                .as_ref()
                .is_some_and(|p| Some(&p.primary)
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
async fn security(State(app): State<App>, req: Request, next: Next) -> Response {
    let expected = url::Url::parse(&app.origin).unwrap();
    let host = expected[url::Position::BeforeHost..url::Position::AfterPort].to_string();
    let valid_host = req.headers().get("host").and_then(|h| h.to_str().ok()) == Some(&host);
    let valid_origin = req.method() == "GET"
        || req.headers().get("origin").and_then(|h| h.to_str().ok()) == Some(app.origin.as_str());
    if !valid_host || !valid_origin {
        return StatusCode::FORBIDDEN.into_response();
    }
    if req.uri().path().starts_with("/api/") && req.uri().path() != "/api/session" {
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
    if let Some(key) = crate::api::cookie(&headers, "nb_portable").and_then(|id| map.get(&hash(id)))
        && let Ok(s) = key.try_lock()
    {
        return Json(json!({"mode":"portable","csrf":s.csrf})).into_response();
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
        Arc::new(Mutex::new(Session {
            csrf: csrf.clone(),
            created: Instant::now(),
            connection: None,
            remote: None,
            replicas: vec![],
            from_replica: false,
            copied_head: None,
            source_warning: false,
            data: None,
            device: None,
            challenge: None,
            authenticated: false,
            plan: None,
            requests: vec![],
        })),
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
 if !matches!(path.as_str(),"status"|"branding"|"connection"|"me"|"sync"|"requests"|"replication"){anyhow::ensure!(method==axum::http::Method::POST,"POST required");}
 if method!=axum::http::Method::GET {anyhow::ensure!(headers.get("x-nightbuoy-csrf").and_then(|h|h.to_str().ok())==Some(s.csrf.as_str()),"CSRF check failed");}
 let v:Value=if body.is_empty(){Value::Null}else{serde_json::from_slice(&body).map_err(anyhow::Error::from)?};
 let out=match path.as_str(){
  "branding"=>app.branding.as_ref().map(|b|b.public()).unwrap_or(json!({"name":"NightBuoy","home":"/","tagline":"Community-owned conversations.","logo":"/nightbuoy.svg","favicon":"/nightbuoy.svg","links":[]})),
  "connect"=>{
   #[derive(Deserialize)]#[serde(deny_unknown_fields)]struct Input{connection:Connection,access:Access,#[serde(default)] replica_access:Vec<Access>}
   let i:Input=serde_json::from_value(v).map_err(anyhow::Error::from)?;
   anyhow::ensure!(i.connection.version==1&&i.connection.replicas.len()<=50,"invalid connection");
   if let Some(allowed)=&app.allowed{anyhow::ensure!(i.connection.primary==allowed.primary&&i.connection.community==allowed.community&&i.connection.branch_pin==allowed.branch_pin&&i.connection.checkpoint==allowed.checkpoint&&i.connection.replicas.iter().all(|r|allowed.replicas.contains(r)),"operator has not approved this backend");}
   let remote=Remote::new(i.connection.primary.clone(),i.access,app.testing)?;
   s.replicas=i.connection.replicas.iter().map(|b|{let id=b.id()?;let access=i.replica_access.iter().find(|a|a.backend==id).cloned().unwrap_or(Access{backend:id,..Default::default()});Remote::new(b.clone(),access,app.testing)}).collect::<anyhow::Result<Vec<_>>>()?;
   app.admissions.lock().await.remove(&hash(&key));s.connection=Some(i.connection);s.remote=Some(remote);s.copied_head=None;s.data=None;s.authenticated=false;s.device=None;s.plan=None;s.refresh().await?;json!({"connected":true})
  },
  "status"=>{if s.remote.is_some(){s.refresh().await?;}
   if let Some(d)=&s.data{json!({"mode":"portable","connected":true,"configured":true,"community":d.community(),"branch":d.branch(),"genesis":d.archive.genesis,"publisher":s.connection.as_ref().unwrap().primary.id()?,"providers":[],"read_only":false})}else{json!({"mode":"portable","connected":s.remote.is_some(),"configured":false,"publisher":s.connection.as_ref().map(|c|c.primary.id()).transpose()?,"providers":[],"read_only":false})}},
  "connection"=>serde_json::to_value(&s.connection).map_err(anyhow::Error::from)?,
  "challenge"=>{let device:Device=serde_json::from_value(v["device"].clone()).map_err(anyhow::Error::from)?;device.validate()?;let challenge=serde_json::to_string(&json!(["nightbuoy-login",1,token(),device.id])).unwrap();s.device=Some(device);s.authenticated=false;s.plan=None;s.challenge=Some(challenge.clone());json!({"id":"session","body":challenge})},
  "login"=>{let signed:Signed=serde_json::from_value(v["signed"].clone()).map_err(anyhow::Error::from)?;let challenge=s.challenge.take().ok_or_else(||anyhow::anyhow!("challenge required"))?;anyhow::ensure!(signed.body==challenge,"challenge mismatch");verify_member(&s.device.as_ref().unwrap().sign,&signed.body,&signed.signature)?;s.authenticated=true;
   if s.active().is_ok(){let identity=format!("{}:{}",s.data.as_ref().unwrap().community(),s.device.as_ref().unwrap().id);let mut admissions=app.admissions.lock().await;admissions.retain(|_,(_,t)|t.elapsed()<Duration::from_secs(8*3600));let session_key=hash(&key);if !admission_available(&admissions,&session_key,&identity){s.authenticated=false;anyhow::bail!("this member already has two active sessions; sign out another tab first");}admissions.insert(session_key,(identity,Instant::now()));}
   json!({"ok":true})},
  "logout"=>{app.admissions.lock().await.remove(&hash(&key));s.authenticated=false;s.device=None;s.challenge=None;s.plan=None;json!({"ok":true})},
  "me"=>{anyhow::ensure!(s.authenticated,"sign in required");s.refresh().await?;json!({"member":s.data.as_ref().and_then(|d|d.view().members.get(&s.device.as_ref().unwrap().id))})},
  "sync"=>{s.refresh().await?;s.active()?;serde_json::to_value(&s.data.as_ref().unwrap().archive).map_err(anyhow::Error::from)?},
  "join"=>{anyhow::ensure!(s.authenticated,"sign in required");let signed:Signed=serde_json::from_value(v["signed"].clone()).map_err(anyhow::Error::from)?;let device=s.device.as_ref().unwrap();let community=s.data.as_ref().map(Data::community).unwrap_or_default();anyhow::ensure!(signed.body==serde_json::to_string(&json!(["nightbuoy-join",1,community,device]))?,"invalid membership request");verify_member(&device.sign,&signed.body,&signed.signature)?;json!({"request":{"device":device,"signed":signed,"community":community},"export_required":true})},
  "requests"=>{s.active()?;json!(s.requests)},
  "request-import"=>{anyhow::ensure!(s.active()?.role=="administrator","administrator required");let device:Device=serde_json::from_value(v["device"].clone()).map_err(anyhow::Error::from)?;device.validate()?;let signed:Signed=serde_json::from_value(v["signed"].clone()).map_err(anyhow::Error::from)?;let expected=serde_json::to_string(&json!(["nightbuoy-join",1,s.data.as_ref().unwrap().community(),device])).unwrap();anyhow::ensure!(signed.body==expected,"request community mismatch");verify_member(&device.sign,&signed.body,&signed.signature)?;anyhow::ensure!(s.requests.len()<100,"request limit");s.requests.push(json!({"device":device,"signed":signed,"verified":false}));json!({"ok":true})},
  "prepare"|"recover-prepare"=>{
   anyhow::ensure!(s.authenticated,"sign in required");let parent=s.refresh_source(false).await?;
   let signed:Signed=serde_json::from_value(v["signed"].clone()).map_err(anyhow::Error::from)?;let primary=s.connection.as_ref().unwrap().primary.id()?;
   let item=match v["kind"].as_str(){Some("genesis")=>{anyhow::ensure!(app.allowed.is_none(),"create communities using a personal local client");protocol::Item::Genesis(signed)},Some("control")=>protocol::Item::Control(signed),Some("event")=>protocol::Item::Event(Record{event:signed,publisher:primary.clone(),receipt:String::new()}),_=>anyhow::bail!("invalid transaction type")};
   anyhow::ensure!(item.actor()?==s.device.as_ref().unwrap().id,"transaction author mismatch");verify_member(&s.device.as_ref().unwrap().sign,&item.signed().body,&item.signed().signature)?;
   if s.data.as_ref().is_some_and(|d|d.archive.order.contains(&item.signed().hash())){json!({"accepted":true})}else{
    let mut data=if path=="recover-prepare" {
     anyhow::ensure!(s.data.is_none()&&parent.is_none(),"recovery requires a new empty backend namespace");
     let a:Archive=serde_json::from_value(v["archive"].clone())?;let old=Data::replay(&a)?;let fields:Value=serde_json::from_str(&item.signed().body)?;
     anyhow::ensure!(matches!(item,protocol::Item::Control(_))&&fields[6]=="reconstitute","explicit branch reset required");
     anyhow::ensure!(old.view().policy.portable.as_ref().is_none_or(|p|p.primary!=primary),"new branch requires a distinct backend identity");Some(old)
    }else{let fields:Value=serde_json::from_str(&item.signed().body)?;anyhow::ensure!(!matches!(item,protocol::Item::Control(_))||fields[6]!="reconstitute","branch resets require explicit recovery onto an empty distinct backend");s.data.clone()};
    let mut cert=if let Some(old)=&data {if let Some(p)=&old.archive.portable_proof{p.clone()}else{protocol::Certificate{anchor:Some(Box::new(old.archive.clone())),headers:vec![]}}}else{protocol::Certificate::default()};let sequence=data.as_ref().map(|d|d.archive.order.len()+1).unwrap_or(0);item.apply(&mut data)?;let mut data=data.unwrap();
    anyhow::ensure!(data.view().policy.portable.as_ref().is_some_and(|p|p.primary==primary),"portable backend mismatch");
    let previous=if let Some(h)=cert.headers.last(){protocol::digest(h)?}else if let Some(a)=&cert.anchor{protocol::digest(&json!({"kind":"legacy_anchor","data":a}))?}else{String::new()};let body=protocol::header_body(&data,&item,&previous,sequence)?;
    data.archive.portable_proof=Some(std::mem::take(&mut cert));let ticket=token();s.plan=Some(Plan{ticket:ticket.clone(),body:body.clone(),data,item,parent});json!({"ticket":ticket,"body":body})
   }
  },
  "commit"=>{
   anyhow::ensure!(s.authenticated,"sign in required");let plan=s.plan.as_ref().ok_or_else(||anyhow::anyhow!("prepare required"))?;anyhow::ensure!(v["ticket"]==plan.ticket,"invalid write ticket");
   let header:Signed=serde_json::from_value(v["header"].clone()).map_err(anyhow::Error::from)?;anyhow::ensure!(header.body==plan.body,"append context changed");verify_member(&s.device.as_ref().unwrap().sign,&header.body,&header.signature)?;
   let mut data=plan.data.clone();data.archive.portable_proof.as_mut().unwrap().headers.push(header.clone());protocol::verify(&data)?;
   let remote=s.remote.as_ref().unwrap();let item_bytes=protocol::canonical(&plan.item)?;remote.immutable(&format!("objects/{}.json",hash(&item_bytes)),item_bytes).await?;
   let hb=protocol::canonical(&header)?;remote.immutable(&format!("objects/{}.json",hash(&hb)),hb).await?;
   let snapshot=protocol::canonical(&data.archive)?;let snapshot_id=hash(&snapshot);remote.immutable(&format!("objects/{snapshot_id}.json"),snapshot).await?;
   let head=Head{version:1,community:data.community(),branch:data.branch(),head:protocol::head(&data.archive)?,snapshot:snapshot_id};
   remote.put("head.json",protocol::canonical(&head)?,plan.parent.as_ref()).await?;
   s.data=Some(data);s.plan=None;s.refresh().await?;json!({"confirmed":true})
  },
  "replication"=>{s.active()?;json!({"copied":s.data.as_ref().and_then(|d|protocol::head(&d.archive).ok()).is_some_and(|h|s.copied_head.as_ref()==Some(&h)),"remote":true,"from_replica":s.from_replica,"error":if s.source_warning{Some("A configured source is unavailable, invalid, stale or conflicting. Reading a verified compatible copy; write authority has not changed.")}else{None}})},
  "replica-copy"=>{
   s.refresh().await?;s.active()?;
   #[derive(Deserialize)]#[serde(deny_unknown_fields)]struct Input{backend:Backend,access:Access}
   let i:Input=serde_json::from_value(v)?;if let Some(allowed)=&app.allowed{anyhow::ensure!(allowed.replicas.contains(&i.backend),"operator has not approved this backend");}
   anyhow::ensure!(s.replicas.len()<50,"replica limit");let remote=Remote::new(i.backend.clone(),i.access,app.testing)?;let old=load(&remote).await?;
   let data=s.data.as_ref().unwrap();if let Some((_,d,_))=&old{d.catch_up(&data.archive)?;let previous=protocol::head(&d.archive)?;anyhow::ensure!(data.archive.portable_proof.as_ref().unwrap().headers.iter().any(|h|protocol::digest(h).ok().as_ref()==Some(&previous)),"replica head fork");}
   for item in protocol::items(&data.archive)?{let bytes=protocol::canonical(&item)?;remote.immutable(&format!("objects/{}.json",hash(&bytes)),bytes).await?;}
   for h in &data.archive.portable_proof.as_ref().unwrap().headers{let bytes=protocol::canonical(h)?;remote.immutable(&format!("objects/{}.json",hash(&bytes)),bytes).await?;}
   let bytes=protocol::canonical(&data.archive)?;let snapshot=hash(&bytes);remote.immutable(&format!("objects/{snapshot}.json"),bytes).await?;
   let h=Head{version:1,community:data.community(),branch:data.branch(),head:protocol::head(&data.archive)?,snapshot};remote.put("head.json",protocol::canonical(&h)?,old.as_ref().map(|(b,_,_)|b)).await?;
   let (_,read,_)=load(&remote).await?.ok_or_else(||anyhow::anyhow!("replica readback missing"))?;anyhow::ensure!(protocol::head(&read.archive)?==h.head,"replica readback changed");
   let c=s.connection.as_mut().unwrap();if !c.replicas.contains(&i.backend){c.replicas.push(i.backend);}s.replicas.retain(|r|r.backend!=remote.backend);s.replicas.push(remote);s.copied_head=Some(h.head);json!({"copied":true})
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
        .layer(DefaultBodyLimit::max(MAX_ARCHIVE_BYTES))
        .layer(middleware::from_fn_with_state(app.clone(), security))
        .with_state(app)
}
pub async fn run() -> anyhow::Result<()> {
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
            c.version == 1
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
    axum::serve(listener, router(app))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;
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
    async fn expired_portable_sessions_return_401_before_body_parsing() {
        let app = App {
            sessions: Default::default(),
            admissions: Default::default(),
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
            device: None,
            challenge: None,
            authenticated: false,
            plan: None,
            requests: vec![],
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
