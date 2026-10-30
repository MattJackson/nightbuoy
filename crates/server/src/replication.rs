//! Append-only archive replication. Mutable heads are discovery hints, never authority.
use crate::{
    api::App,
    crypto::{b64, decode, hash},
    model::Archive,
    store::now,
};
use futures::{StreamExt, stream};
use object_store::ObjectStoreExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
const LIMIT: usize = 64 * 1024 * 1024;
#[derive(Default, Serialize, Clone)]
pub struct TargetStatus {
    pub id: String,
    pub copied: bool,
    pub last_success: Option<i64>,
    pub error: Option<String>,
}
#[derive(Default, Serialize, Clone)]
pub struct Status {
    pub copied: bool,
    pub last_success: Option<i64>,
    pub error: Option<String>,
    pub fingerprint: Option<String>,
    #[serde(skip_serializing)]
    pub targets: Vec<TargetStatus>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub id: String,
    pub kind: String,
    #[serde(default = "push")]
    pub mode: String,
    #[serde(default)]
    pub directory: PathBuf,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub repository: String,
    #[serde(default = "branch")]
    pub branch: String,
    #[serde(default)]
    pub token_file: PathBuf,
    #[serde(default)]
    pub bucket: String,
    #[serde(default = "region")]
    pub region: String,
    #[serde(default)]
    pub access_key_file: PathBuf,
    #[serde(default)]
    pub secret_key_file: PathBuf,
    #[serde(default)]
    pub consent: bool,
}
fn push() -> String {
    "push".into()
}
fn branch() -> String {
    "main".into()
}
fn region() -> String {
    "us-east-1".into()
}
fn secret(p: &PathBuf) -> anyhow::Result<String> {
    Ok(std::fs::read_to_string(p)?.trim().into())
}
fn validate(t: &Target, testing: bool) -> anyhow::Result<()> {
    anyhow::ensure!(t.consent, "destination owner consent must be recorded");
    anyhow::ensure!(
        !t.id.is_empty() && t.id.len() <= 64 && matches!(t.mode.as_str(), "push" | "pull" | "both"),
        "invalid replica configuration"
    );
    if t.kind == "directory" {
        anyhow::ensure!(
            t.directory.is_absolute(),
            "replica directory must be absolute"
        );
        return Ok(());
    }
    let u = url::Url::parse(&t.endpoint)?;
    anyhow::ensure!(
        u.scheme() == "https"
            || (testing
                && u.scheme() == "http"
                && matches!(u.host_str(), Some("localhost" | "127.0.0.1")))
            || (u.scheme() == "http" && crate::config::onion(u.host_str().unwrap_or(""))),
        "replication requires HTTPS or Tor"
    );
    anyhow::ensure!(
        u.query().is_none() && u.fragment().is_none() && u.username().is_empty() && u.path() == "/",
        "replica endpoint must be an origin"
    );
    anyhow::ensure!(
        matches!(t.kind.as_str(), "github" | "forgejo" | "s3"),
        "unknown storage adapter"
    );
    if t.kind != "s3" {
        for name in [&t.owner, &t.repository, &t.branch] {
            anyhow::ensure!(
                !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)),
                "invalid repository coordinates"
            );
        }
    }
    Ok(())
}
async fn bounded(mut response: reqwest::Response) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        response
            .content_length()
            .is_none_or(|n| n <= LIMIT as u64 * 2),
        "replica response too large"
    );
    let mut bytes = Vec::new();
    while let Some(b) = response.chunk().await? {
        anyhow::ensure!(
            bytes.len() + b.len() <= LIMIT * 2,
            "replica response too large"
        );
        bytes.extend_from_slice(&b);
    }
    Ok(bytes)
}
fn repo_url(t: &Target, path: &str) -> String {
    let base = t.endpoint.trim_end_matches('/');
    let prefix = if t.kind == "github" { "" } else { "/api/v1" };
    format!(
        "{base}{prefix}/repos/{}/{}/contents/{path}",
        t.owner, t.repository
    )
}
fn s3(t: &Target, testing: bool) -> anyhow::Result<object_store::aws::AmazonS3> {
    s3_with_proxy(t, testing, std::env::var("NIGHTBUOY_SOCKS_PROXY").ok())
}
fn s3_with_proxy(
    t: &Target,
    testing: bool,
    proxy: Option<String>,
) -> anyhow::Result<object_store::aws::AmazonS3> {
    let endpoint = url::Url::parse(&t.endpoint)?;
    let onion = crate::config::onion(endpoint.host_str().unwrap_or(""));
    anyhow::ensure!(
        !onion || proxy.is_some(),
        "onion S3 endpoints require an explicit Tor SOCKS proxy"
    );
    let mut builder = object_store::aws::AmazonS3Builder::new()
        .with_bucket_name(&t.bucket)
        .with_region(&t.region)
        .with_endpoint(&t.endpoint)
        .with_access_key_id(secret(&t.access_key_file)?)
        .with_secret_access_key(secret(&t.secret_key_file)?)
        .with_allow_http(testing || onion)
        .with_virtual_hosted_style_request(false);
    if let Some(proxy) = proxy {
        anyhow::ensure!(
            proxy.starts_with("socks5h://"),
            "S3 proxy must route DNS through Tor using socks5h"
        );
        builder = builder.with_proxy_url(proxy);
    }
    Ok(builder.build()?)
}

async fn get(app: &App, t: &Target, path: &str) -> anyhow::Result<Option<Vec<u8>>> {
    if t.kind == "directory" {
        return match tokio::fs::read(t.directory.join(path)).await {
            Ok(b) => {
                anyhow::ensure!(b.len() <= LIMIT, "archive too large");
                Ok(Some(b))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        };
    }
    if t.kind == "s3" {
        let store = s3(t, app.config.testing)?;
        return match store.get(&path.into()).await {
            Ok(r) => {
                anyhow::ensure!(r.meta.size <= LIMIT as u64, "archive too large");
                Ok(Some(r.bytes().await?.to_vec()))
            }
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(e.into()),
        };
    }
    let response = app
        .client
        .get(repo_url(t, path))
        .query(&[("ref", &t.branch)])
        .bearer_auth(secret(&t.token_file)?)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await?;
    if response.status() == 404 {
        return Ok(None);
    }
    anyhow::ensure!(
        response.status().is_success(),
        "repository read failed (HTTP {})",
        response.status()
    );
    let value: Value = serde_json::from_slice(&bounded(response).await?)?;
    if let Some(content) = value["content"].as_str() {
        let bytes = decode(&content.replace(['\n', '\r'], ""))?;
        anyhow::ensure!(bytes.len() <= LIMIT, "archive too large");
        if !bytes.is_empty() {
            return Ok(Some(bytes));
        }
    }
    // GitHub's raw media type supports large Contents objects without following download URLs.
    let response = app
        .client
        .get(repo_url(t, path))
        .query(&[("ref", &t.branch)])
        .bearer_auth(secret(&t.token_file)?)
        .header("Accept", "application/vnd.github.raw+json")
        .send()
        .await?;
    anyhow::ensure!(response.status().is_success(), "repository raw read failed");
    let b = bounded(response).await?;
    anyhow::ensure!(b.len() <= LIMIT, "archive too large");
    Ok(Some(b))
}
async fn put(app: &App, t: &Target, path: &str, bytes: &[u8], mutable: bool) -> anyhow::Result<()> {
    anyhow::ensure!(bytes.len() <= LIMIT, "pilot archive exceeds 64 MiB");
    if t.kind == "directory" {
        let dest = t.directory.join(path);
        if !mutable && dest.exists() {
            anyhow::ensure!(
                tokio::fs::read(dest).await? == bytes,
                "immutable replica object differs"
            );
            return Ok(());
        }
        tokio::fs::create_dir_all(dest.parent().unwrap()).await?;
        let tmp = dest.with_extension(format!("{}.tmp", crate::crypto::token()));
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .await?;
        file.write_all(bytes).await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(tmp, &dest).await?;
        tokio::fs::File::open(dest.parent().unwrap())
            .await?
            .sync_all()
            .await?;
        return Ok(());
    }
    if t.kind == "s3" {
        let store = s3(t, app.config.testing)?;
        if !mutable && let Some(existing) = get(app, t, path).await? {
            anyhow::ensure!(existing == bytes, "immutable replica object differs");
            return Ok(());
        }
        store.put(&path.into(), bytes.to_vec().into()).await?;
        return Ok(());
    }
    let url = repo_url(t, path);
    let token = secret(&t.token_file)?;
    let response = app
        .client
        .get(&url)
        .query(&[("ref", &t.branch)])
        .bearer_auth(&token)
        .send()
        .await?;
    let mut sha = None;
    if response.status().is_success() {
        let value: Value = serde_json::from_slice(&bounded(response).await?)?;
        sha = value["sha"].as_str().map(str::to_string);
        if !mutable {
            anyhow::ensure!(
                get(app, t, path).await?.as_deref() == Some(bytes),
                "immutable replica object differs"
            );
            return Ok(());
        }
    } else {
        anyhow::ensure!(
            response.status() == 404,
            "repository write preflight failed"
        );
    }
    let mut payload = json!({"message":"Preserve encrypted NightBuoy history","content":b64(bytes),"branch":t.branch});
    if let Some(sha) = sha {
        payload["sha"] = json!(sha);
    }
    let method = if t.kind == "forgejo" && payload.get("sha").is_none() {
        reqwest::Method::POST
    } else {
        reqwest::Method::PUT
    };
    let response = app
        .client
        .request(method, url)
        .bearer_auth(token)
        .json(&payload)
        .send()
        .await?;
    anyhow::ensure!(
        response.status().is_success(),
        "repository write failed (HTTP {})",
        response.status()
    );
    Ok(())
}
async fn target(app: &App, t: &Target, archive: &Archive) -> anyhow::Result<bool> {
    validate(t, app.config.testing)?;
    let community = archive.genesis.hash();
    let prefix = format!("nightbuoy/{community}");
    if (t.mode == "pull" || t.mode == "both") && app.consensus.is_some() {
        anyhow::bail!(
            "live consensus state cannot be replaced by archive pulls; use CometBFT peer catch-up or offline recovery"
        );
    }
    if (t.mode == "pull" || t.mode == "both")
        && let Some(head) = get(app, t, &format!("{prefix}/latest.json")).await?
    {
        let h: Value = serde_json::from_slice(&head)?;
        let id = h["archive"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("invalid discovery head"))?;
        anyhow::ensure!(
            id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()),
            "invalid archive hash"
        );
        let bytes = get(app, t, &format!("{prefix}/archives/{id}.json"))
            .await?
            .ok_or_else(|| anyhow::anyhow!("archive missing"))?;
        anyhow::ensure!(hash(&bytes) == id, "archive hash mismatch");
        let incoming: Archive = serde_json::from_slice(&bytes)?;
        let mut store = app.store.lock().unwrap();
        let current = store
            .data
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("community unconfigured"))?;
        let next = current.catch_up(&incoming)?;
        store.save(next)?;
    }
    if t.mode == "pull" {
        return Ok(false);
    }
    let bytes = serde_json::to_vec(archive)?;
    let id = hash(&bytes);
    let path = format!("{prefix}/archives/{id}.json");
    put(app, t, &path, &bytes, false).await?;
    let read = get(app, t, &path)
        .await?
        .ok_or_else(|| anyhow::anyhow!("destination did not retain archive"))?;
    anyhow::ensure!(hash(&read) == id, "replica readback failed");
    let pointer = serde_json::to_vec(
        &json!({"archive":id,"tip":archive.order.last().cloned().unwrap_or(community)}),
    )?;
    put(app, t, &format!("{prefix}/latest.json"), &pointer, true).await?;
    Ok(true)
}
pub async fn once(app: &App) -> anyhow::Result<()> {
    let Some(file) = &app.config.replicas else {
        return Ok(());
    };
    let targets: Vec<Target> = serde_json::from_slice(&tokio::fs::read(file).await?)?;
    anyhow::ensure!(targets.len() <= 128, "at most 128 destinations per service");
    let mut ids = std::collections::HashSet::new();
    for t in &targets {
        anyhow::ensure!(ids.insert(&t.id), "duplicate replica id");
        validate(t, app.config.testing)?;
    }
    let archive = {
        let s = app.store.lock().unwrap();
        match &s.data {
            Some(d) => {
                d.verify_proof()?;
                d.archive.clone()
            }
            None => return Ok(()),
        }
    };
    let fingerprint = hash(serde_json::to_vec(&archive)?);
    let results=stream::iter(targets).map(|t|{let a=archive.clone();async move{let result=target(app,&t,&a).await;let ok=matches!(result,Ok(true));TargetStatus{id:t.id,copied:ok,last_success:result.as_ref().ok().map(|_|now()),error:result.err().map(|e|{let msg=e.to_string();if msg.contains("diverged"){"History diverged: choose a branch explicitly; no merge performed".into()}else{"Replication failed; check destination permissions, transport, capacity and integrity".into()}})}}}).buffer_unordered(8).collect::<Vec<_>>().await;
    let current = {
        let s = app.store.lock().unwrap();
        s.data
            .as_ref()
            .map(|d| hash(serde_json::to_vec(&d.archive).unwrap()))
    };
    let copied = current.as_deref() == Some(&fingerprint) && results.iter().any(|r| r.copied);
    *app.replication.lock().unwrap() = Status {
        copied,
        last_success: copied.then(now),
        error: results.iter().find_map(|r| r.error.clone()),
        fingerprint: Some(fingerprint),
        targets: results,
    };
    Ok(())
}
pub async fn run(app: App) {
    loop {
        if once(&app).await.is_err() {
            app.replication.lock().unwrap().error =
                Some("Replica configuration could not be loaded or validated".into());
        }
        tokio::time::sleep(std::time::Duration::from_secs(20)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    fn directory(path: PathBuf) -> Target {
        Target {
            id: "private-owner-label".into(),
            kind: "directory".into(),
            mode: "both".into(),
            directory: path,
            endpoint: String::new(),
            owner: String::new(),
            repository: String::new(),
            branch: "main".into(),
            token_file: PathBuf::new(),
            bucket: String::new(),
            region: "us-east-1".into(),
            access_key_file: PathBuf::new(),
            secret_key_file: PathBuf::new(),
            consent: true,
        }
    }
    #[test]
    fn public_replication_status_does_not_inventory_private_destinations() {
        let status = Status {
            targets: vec![TargetStatus {
                id: "private-owner-label".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("private-owner-label"));
        assert!(!json.contains("targets"));
    }
    #[tokio::test]
    async fn s3_routes_hostname_through_explicit_socks_proxy() {
        let dir = tempfile::tempdir().unwrap();
        let access = dir.path().join("access");
        let secret_file = dir.path().join("secret");
        std::fs::write(&access, "test-access").unwrap();
        std::fs::write(&secret_file, "test-secret").unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let observed = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut head = [0u8; 2];
            socket.read_exact(&mut head).await.unwrap();
            assert_eq!(head[0], 5);
            let mut methods = vec![0u8; head[1] as usize];
            socket.read_exact(&mut methods).await.unwrap();
            socket.write_all(&[5, 0]).await.unwrap();
            let mut request = [0u8; 4];
            socket.read_exact(&mut request).await.unwrap();
            assert_eq!(
                request[3], 3,
                "DNS must be handled by the proxy, not resolved to an IP locally"
            );
            let n = socket.read_u8().await.unwrap();
            let mut name = vec![0; n as usize];
            socket.read_exact(&mut name).await.unwrap();
            let _port = socket.read_u16().await.unwrap();
            socket
                .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            String::from_utf8(name).unwrap()
        });
        let mut target = directory(dir.path().into());
        target.kind = "s3".into();
        target.endpoint = "https://private-backup.invalid".into();
        target.bucket = "archive".into();
        target.access_key_file = access;
        target.secret_key_file = secret_file;
        let store =
            s3_with_proxy(&target, false, Some(format!("socks5h://127.0.0.1:{port}"))).unwrap();
        let transfer = tokio::spawn(async move {
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                store.get(&"ciphertext.json".into()),
            )
            .await;
        });
        let host = tokio::time::timeout(std::time::Duration::from_secs(3), observed)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(host, "private-backup.invalid");
        transfer.abort();
    }
    #[tokio::test]
    async fn archive_pull_cannot_replace_a_live_consensus_application() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(crate::store::Store::open(dir.path()).unwrap()));
        let genesis = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/consensus-genesis.json");
        let engine =
            crate::consensus::Consensus::new("http://127.0.0.1:1".into(), &genesis, store.clone())
                .unwrap();
        let config = crate::config::Config {
            data: dir.path().into(),
            public_url: "https://example.test".into(),
            listen: "127.0.0.1:0".into(),
            web: dir.path().into(),
            providers: vec![],
            testing: false,
            read_only: false,
            branding: None,
            replicas: None,
        };
        let app = App {
            store: store.clone(),
            config: Arc::new(config),
            client: reqwest::Client::new(),
            replication: Arc::new(Mutex::new(Status::default())),
            consensus: Some(Arc::new(engine)),
        };
        let archive = Archive {
            genesis: crate::model::Signed {
                body: "not-loaded".into(),
                signature: String::new(),
            },
            controls: vec![],
            records: vec![],
            order: vec![],
            proof: None,
        };
        let result = target(
            &app,
            &directory(dir.path().join("private-backup")),
            &archive,
        )
        .await;
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("live consensus state")
        );
        assert!(store.lock().unwrap().data.is_none());
        assert!(!dir.path().join("private-backup").exists());
    }
}
