//! Private transport profiles. No credentials are serialized into public connections.
use crate::{crypto::*, portable_protocol::canonical, sealed_storage::MAX_FRAME};
use futures::StreamExt;
use object_store::{ObjectStore, ObjectStoreExt, PutMode, PutOptions, UpdateVersion};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Backend {
    pub kind: String,
    pub endpoint: String,
    pub namespace: String,
    pub salt: String,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub repository: String,
    #[serde(default)]
    pub branch: String,
    #[serde(default)]
    pub bucket: String,
    #[serde(default)]
    pub region: String,
}
#[derive(Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Access {
    pub backend: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub access_key: String,
    #[serde(default)]
    pub secret_key: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Connection {
    pub version: u8,
    pub primary: Backend,
    #[serde(default)]
    pub replicas: Vec<Backend>,
    #[serde(default)]
    pub community: String,
    #[serde(default)]
    pub branch_pin: String,
    #[serde(default)]
    pub checkpoint: String,
}
#[derive(Clone)]
pub struct Remote {
    pub backend: Backend,
    access: Access,
    client: reqwest::Client,
    testing: bool,
}
#[derive(Clone)]
pub struct Blob {
    pub bytes: Vec<u8>,
    pub version: String,
    pub revision: Option<String>,
}
impl Backend {
    pub fn id(&self) -> anyhow::Result<String> {
        Ok(b64(sha2_digest(&canonical(self)?)))
    }
    pub fn validate(&self, testing: bool) -> anyhow::Result<()> {
        anyhow::ensure!(
            matches!(self.kind.as_str(), "github" | "forgejo" | "s3"),
            "unsupported backend"
        );
        let u = url::Url::parse(&self.endpoint)?;
        let onion = crate::config::onion(u.host_str().unwrap_or(""));
        anyhow::ensure!(
            u.scheme() == "https"
                || (u.scheme() == "http"
                    && (onion
                        || (testing && matches!(u.host_str(), Some("localhost" | "127.0.0.1"))))),
            "backend requires HTTPS or Tor"
        );
        anyhow::ensure!(
            u.username().is_empty()
                && u.password().is_none()
                && u.query().is_none()
                && u.fragment().is_none()
                && u.path() == "/",
            "backend must be an origin"
        );
        anyhow::ensure!(
            !onion || std::env::var("NIGHTBUOY_SOCKS_PROXY").is_ok(),
            "Tor proxy required"
        );
        anyhow::ensure!(
            !self.namespace.is_empty()
                && self.namespace.len() <= 512
                && self.namespace.split('/').all(safe),
            "invalid namespace"
        );
        if self.kind != "s3" {
            for v in [&self.owner, &self.repository, &self.branch] {
                anyhow::ensure!(safe(v), "invalid repository coordinates");
            }
        } else {
            anyhow::ensure!(
                safe(&self.bucket) && safe(&self.region),
                "invalid bucket or region"
            );
        }
        anyhow::ensure!(decode(&self.salt)?.len() == 32, "invalid backend salt");
        Ok(())
    }
}
fn sha2_digest(v: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha256::digest(v).to_vec()
}
fn safe(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 128
        && v != "."
        && v != ".."
        && v.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
}
impl Remote {
    pub fn new(backend: Backend, access: Access, testing: bool) -> anyhow::Result<Self> {
        backend.validate(testing)?;
        anyhow::ensure!(
            access.backend == backend.id()?,
            "credential/backend binding mismatch"
        );
        let mut b = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(45))
            .user_agent("NightBuoy/0.1");
        if let Ok(p) = std::env::var("NIGHTBUOY_SOCKS_PROXY") {
            anyhow::ensure!(p.starts_with("socks5h://"), "use socks5h for remote DNS");
            b = b.proxy(reqwest::Proxy::all(&p)?);
        }
        Ok(Self {
            backend,
            access,
            client: b.build()?,
            testing,
        })
    }
    /// Adopt a signed storage identity only when every transport coordinate is identical.
    /// A descriptor from encrypted data may never redirect credentials to another destination.
    pub fn rebind_same_location(&self, backend: &Backend) -> anyhow::Result<Option<Self>> {
        let mut old = self.backend.clone();
        old.salt = backend.salt.clone();
        if &old != backend {
            return Ok(None);
        }
        Self::new(
            backend.clone(),
            Access {
                backend: backend.id()?,
                ..self.access.clone()
            },
            self.testing,
        )
        .map(Some)
    }
    pub async fn confirm_bucket(&self) -> anyhow::Result<()> {
        let prefix = object_store::path::Path::from(self.backend.namespace.as_str());
        self.s3()?.list_with_delimiter(Some(&prefix)).await.map_err(|_|anyhow::anyhow!("Cannot confirm this bucket exists and is readable. Check the bucket and permissions; this is not a confirmed empty forum."))?;
        Ok(())
    }
    fn path(&self, key: &str) -> anyhow::Result<String> {
        anyhow::ensure!(key.split('/').all(safe), "invalid object path");
        Ok(format!("{}/{}", self.backend.namespace, key))
    }
    fn url(&self, path: &str) -> String {
        let b = &self.backend;
        format!(
            "{}{}/repos/{}/{}/contents/{}",
            b.endpoint.trim_end_matches('/'),
            if b.kind == "forgejo" { "/api/v1" } else { "" },
            b.owner,
            b.repository,
            path
        )
    }
    fn auth(&self, r: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if self.access.token.is_empty() {
            r
        } else {
            r.bearer_auth(&self.access.token)
        }
    }
    fn s3(&self) -> anyhow::Result<object_store::aws::AmazonS3> {
        let b = &self.backend;
        let onion = crate::config::onion(url::Url::parse(&b.endpoint)?.host_str().unwrap_or(""));
        let mut s = object_store::aws::AmazonS3Builder::new()
            .with_endpoint(&b.endpoint)
            .with_bucket_name(&b.bucket)
            .with_region(&b.region)
            .with_allow_http(self.testing || onion)
            .with_virtual_hosted_style_request(false)
            .with_retry(object_store::RetryConfig {
                max_retries: 2,
                retry_timeout: std::time::Duration::from_secs(15),
                ..Default::default()
            });
        if self.access.access_key.is_empty() {
            s = s.with_skip_signature(true);
        } else {
            s = s
                .with_access_key_id(&self.access.access_key)
                .with_secret_access_key(&self.access.secret_key);
        }
        if let Ok(p) = std::env::var("NIGHTBUOY_SOCKS_PROXY") {
            s = s.with_proxy_url(p);
        }
        Ok(s.with_http_connector(s3_transport(
            std::env::var("NIGHTBUOY_SOCKS_PROXY").ok().as_deref(),
        )?)
        .build()?)
    }
    pub async fn probe_repository(&self) -> anyhow::Result<String> {
        if self.backend.kind == "s3" {
            return Ok(self.backend.branch.clone());
        }
        let b = &self.backend;
        let prefix = if b.kind == "forgejo" { "/api/v1" } else { "" };
        let url = format!(
            "{}{prefix}/repos/{}/{}",
            b.endpoint.trim_end_matches('/'),
            b.owner,
            b.repository
        );
        let response = self.auth(self.client.get(url)).send().await?;
        anyhow::ensure!(
            response.status() != 404,
            "Repository not found or private. Add your repository-scoped provider token; this is not an empty forum."
        );
        anyhow::ensure!(
            response.status() != 401 && response.status() != 403,
            "Storage provider denied access. Check the token permissions or rate limit."
        );
        let metadata: Value = serde_json::from_slice(&bounded(response).await?)?;
        Ok(metadata["default_branch"]
            .as_str()
            .unwrap_or("main")
            .to_string())
    }
    pub async fn probe_branch(&self) -> anyhow::Result<()> {
        if self.backend.kind == "s3" {
            return Ok(());
        }
        let b = &self.backend;
        let prefix = if b.kind == "forgejo" { "/api/v1" } else { "" };
        let url = format!(
            "{}{prefix}/repos/{}/{}/branches/{}",
            b.endpoint.trim_end_matches('/'),
            b.owner,
            b.repository,
            b.branch
        );
        let response = self.auth(self.client.get(url)).send().await?;
        anyhow::ensure!(
            response.status().is_success(),
            "Repository branch is missing or inaccessible; this is not an empty forum."
        );
        Ok(())
    }
    pub fn writable(&self) -> bool {
        if self.backend.kind == "s3" {
            !self.access.access_key.is_empty() && !self.access.secret_key.is_empty()
        } else {
            !self.access.token.is_empty()
        }
    }
    pub async fn get(&self, key: &str) -> anyhow::Result<Option<Blob>> {
        let p = self.path(key)?;
        if self.backend.kind == "s3" {
            let r = match self.s3()?.get(&p.into()).await {
                Ok(r) => r,
                Err(object_store::Error::NotFound { .. }) => return Ok(None),
                Err(e) => return Err(e.into()),
            };
            anyhow::ensure!(r.meta.size <= MAX_FRAME as u64, "object too large");
            let version = r
                .meta
                .e_tag
                .clone()
                .ok_or_else(|| anyhow::anyhow!("backend missing conditional ETag"))?;
            let revision = r.meta.version.clone();
            let mut stream = r.into_stream();
            let mut bytes = vec![];
            while let Some(b) = stream.next().await {
                let b = b?;
                anyhow::ensure!(bytes.len() + b.len() <= MAX_FRAME, "object too large");
                bytes.extend(b);
            }
            return Ok(Some(Blob {
                bytes,
                version,
                revision,
            }));
        }
        let r = self
            .auth(self.client.get(self.url(&p)))
            .query(&[("ref", &self.backend.branch)])
            .send()
            .await?;
        if r.status() == 404 {
            return Ok(None);
        };
        let v: Value = serde_json::from_slice(&bounded(r).await?)?;
        let version = v["sha"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("backend missing version"))?
            .to_string();
        let bytes = if v["encoding"] == "base64" {
            decode(&v["content"].as_str().unwrap_or("").replace('\n', ""))?
        } else {
            // GitHub omits inline content above 1 MiB. Pin the raw fetch to
            // the immutable blob, not the mutable branch read above: otherwise
            // a concurrent update could pair new bytes with an old CAS version.
            let raw = if self.backend.kind == "github" {
                anyhow::ensure!(
                    matches!(version.len(), 40 | 64)
                        && version.bytes().all(|b| b.is_ascii_hexdigit()),
                    "invalid backend blob version"
                );
                self.client.get(format!(
                    "{}/repos/{}/{}/git/blobs/{}",
                    self.backend.endpoint.trim_end_matches('/'),
                    self.backend.owner,
                    self.backend.repository,
                    version
                ))
            } else {
                self.client
                    .get(self.url(&p))
                    .query(&[("ref", &self.backend.branch)])
            };
            // Keep the configured origin/auth path; never follow download_url.
            bounded(
                self.auth(raw)
                    .header("Accept", "application/vnd.github.raw+json")
                    .send()
                    .await?,
            )
            .await?
        };
        anyhow::ensure!(bytes.len() <= MAX_FRAME, "object too large");
        Ok(Some(Blob {
            bytes,
            version,
            revision: None,
        }))
    }
    pub async fn put(
        &self,
        key: &str,
        bytes: Vec<u8>,
        expected: Option<&Blob>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(bytes.len() <= MAX_FRAME, "object too large");
        let p = self.path(key)?;
        if self.backend.kind == "s3" {
            anyhow::ensure!(
                !self.access.access_key.is_empty(),
                "write credentials required"
            );
            let mode = match expected {
                None => PutMode::Create,
                Some(b) => PutMode::Update(UpdateVersion {
                    e_tag: Some(b.version.clone()),
                    version: b.revision.clone(),
                }),
            };
            self.s3()?
                .put_opts(
                    &p.into(),
                    bytes.into(),
                    PutOptions {
                        mode,
                        ..Default::default()
                    },
                )
                .await
                .map_err(|_| anyhow::anyhow!("conditional write failed; refresh before retry"))?;
            return Ok(());
        }
        anyhow::ensure!(!self.access.token.is_empty(), "write credentials required");
        // Do not let the provider default Git attribution to the token owner.
        // Provider authentication/activity logs remain outside this protection.
        let attribution = json!({"name":"NightBuoy", "email":"storage@nightbuoy.invalid"});
        let mut body = json!({"message":"NightBuoy encrypted append",
            "branch":self.backend.branch,"content":b64(&bytes),
            "author":attribution,"committer":attribution});
        if let Some(b) = expected {
            body["sha"] = json!(b.version);
        }
        let method = if self.backend.kind == "forgejo" && expected.is_none() {
            reqwest::Method::POST
        } else {
            reqwest::Method::PUT
        };
        let r = self
            .auth(self.client.request(method, self.url(&p)))
            .json(&body)
            .send()
            .await?;
        anyhow::ensure!(
            r.status().is_success(),
            "conditional write failed; refresh before retry"
        );
        Ok(())
    }
    pub async fn immutable(&self, key: &str, bytes: Vec<u8>) -> anyhow::Result<()> {
        if let Some(old) = self.get(key).await? {
            anyhow::ensure!(old.bytes == bytes, "immutable object conflict");
            return Ok(());
        }
        if self.put(key, bytes.clone(), None).await.is_err() {
            let old = self
                .get(key)
                .await?
                .ok_or_else(|| anyhow::anyhow!("immutable publication unavailable"))?;
            anyhow::ensure!(old.bytes == bytes, "immutable object conflict");
        }
        let check = self
            .get(key)
            .await?
            .ok_or_else(|| anyhow::anyhow!("object readback unavailable"))?;
        anyhow::ensure!(check.bytes == bytes, "object readback mismatch");
        Ok(())
    }
}
async fn bounded(mut r: reqwest::Response) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        r.status().is_success(),
        "backend request failed ({})",
        r.status()
    );
    let mut out = vec![];
    while let Some(b) = r.chunk().await? {
        anyhow::ensure!(
            out.len() + b.len() <= MAX_FRAME * 2,
            "backend response too large"
        );
        out.extend(b);
    }
    Ok(out)
}

#[derive(Debug, Clone)]
pub struct StrictS3Transport(reqwest_s3_transport::Client);
impl object_store::client::HttpConnector for StrictS3Transport {
    fn connect(
        &self,
        _: &object_store::ClientOptions,
    ) -> object_store::Result<object_store::client::HttpClient> {
        Ok(object_store::client::HttpClient::new(self.0.clone()))
    }
}
pub fn s3_transport(proxy: Option<&str>) -> anyhow::Result<StrictS3Transport> {
    let mut b = reqwest_s3_transport::Client::builder()
        .no_proxy()
        .redirect(reqwest_s3_transport::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(45));
    if let Some(p) = proxy {
        anyhow::ensure!(
            p.starts_with("socks5h://"),
            "S3 proxy requires socks5h remote DNS"
        );
        b = b.proxy(reqwest_s3_transport::Proxy::all(p)?);
    }
    Ok(StrictS3Transport(b.build()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router, extract::State, http::HeaderMap, response::IntoResponse, routing::get,
    };
    use std::sync::Arc;

    #[tokio::test]
    async fn github_large_reads_pin_raw_bytes_to_the_observed_blob() {
        let original = Arc::new(vec![17u8; 1024 * 1024 + 91]);
        async fn contents(headers: HeaderMap) -> axum::response::Response {
            // A branch moves between the metadata read and any unpinned raw read.
            if headers
                .get("accept")
                .is_some_and(|v| v == "application/vnd.github.raw+json")
            {
                return vec![99u8; 1024 * 1024 + 91].into_response();
            }
            Json(json!({"sha":"1111111111111111111111111111111111111111",
                "encoding":"none","content":"","size":1024*1024+91,
                "download_url":"https://untrusted.invalid/do-not-fetch"}))
            .into_response()
        }
        async fn blob(State(bytes): State<Arc<Vec<u8>>>, headers: HeaderMap) -> Vec<u8> {
            assert_eq!(headers["authorization"], "Bearer synthetic-only-token");
            assert_eq!(headers["accept"], "application/vnd.github.raw+json");
            (*bytes).clone()
        }
        let app = Router::new()
            .route("/repos/owner/repo/contents/forum/object", get(contents))
            .route(
                "/repos/owner/repo/contents/forum/invalid",
                get(|| async {
                    Json(json!({"sha":"../../escape","encoding":"none","content":""}))
                }),
            )
            .route(
                "/repos/owner/repo/git/blobs/1111111111111111111111111111111111111111",
                get(blob),
            )
            .with_state(original.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let backend = Backend {
            kind: "github".into(),
            endpoint,
            namespace: "forum".into(),
            salt: b64([1; 32]),
            owner: "owner".into(),
            repository: "repo".into(),
            branch: "main".into(),
            bucket: String::new(),
            region: "us-east-1".into(),
        };
        let remote = Remote::new(
            backend.clone(),
            Access {
                backend: backend.id().unwrap(),
                token: "synthetic-only-token".into(),
                ..Default::default()
            },
            true,
        )
        .unwrap();
        let result = remote.get("object").await;
        let invalid = remote.get("invalid").await;
        server.abort();
        let result = result.unwrap().unwrap();
        assert_eq!(result.version, "1111111111111111111111111111111111111111");
        assert_eq!(result.bytes, *original);
        assert!(
            invalid
                .err()
                .unwrap()
                .to_string()
                .contains("invalid backend blob version")
        );
    }
}
