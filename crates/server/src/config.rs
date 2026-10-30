use serde::{Deserialize, Serialize};
use std::{env, path::PathBuf};
#[derive(Clone, Serialize, Deserialize)]
pub struct Provider {
    pub id: String,
    pub label: String,
    pub base_url: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    #[serde(default)]
    pub client_secret_file: Option<PathBuf>,
    #[serde(default)]
    pub kind: String,
}
#[derive(Clone)]
pub struct Config {
    pub data: PathBuf,
    pub public_url: String,
    pub listen: String,
    pub web: PathBuf,
    pub providers: Vec<Provider>,
    pub testing: bool,
    pub read_only: bool,
    pub branding: Option<crate::branding::Branding>,
    pub replicas: Option<PathBuf>,
}
impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let public_url = env::var("NIGHTBUOY_PUBLIC_URL")
            .unwrap_or("https://localhost:3000".into())
            .trim_end_matches('/')
            .to_string();
        let testing = env::var("NIGHTBUOY_TEST_MODE").as_deref() == Ok("1");
        let u = url::Url::parse(&public_url)?;
        anyhow::ensure!(
            u.path() == "/"
                && u.query().is_none()
                && u.fragment().is_none()
                && u.username().is_empty()
                && u.password().is_none(),
            "PUBLIC_URL must be an origin; path mounts are not supported by this pilot"
        );
        anyhow::ensure!(
            u.scheme() == "https"
                || (u.scheme() == "http"
                    && (onion(u.host_str().unwrap_or(""))
                        || (testing && matches!(u.host_str(), Some("localhost" | "127.0.0.1"))))),
            "use HTTPS or a Tor v3 onion service; plaintext clearnet HTTP is forbidden"
        );
        anyhow::ensure!(
            !testing || matches!(u.host_str(), Some("localhost" | "127.0.0.1")),
            "test mode is restricted to localhost"
        );
        if onion(u.host_str().unwrap_or("")) {
            anyhow::ensure!(
                env::var("NIGHTBUOY_SOCKS_PROXY").is_ok_and(|p| p.starts_with("socks5h://")),
                "onion deployments require an explicit socks5h proxy for outbound application traffic"
            );
        }
        let mut providers: Vec<Provider> = if let Ok(file) = env::var("NIGHTBUOY_PROVIDERS_FILE") {
            serde_json::from_slice(&std::fs::read(file)?)?
        } else {
            Vec::new()
        };
        for p in &mut providers {
            anyhow::ensure!(
                !p.id.is_empty()
                    && p.id.len() < 40
                    && p.id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
                "invalid provider id"
            );
            let u = url::Url::parse(&p.base_url)?;
            anyhow::ensure!(
                u.scheme() == "https"
                    || (testing && matches!(u.host_str(), Some("127.0.0.1" | "localhost"))),
                "identity issuer must use HTTPS"
            );
            anyhow::ensure!(
                u.path() == "/"
                    && u.query().is_none()
                    && u.fragment().is_none()
                    && u.username().is_empty(),
                "issuer must be an origin"
            );
            p.base_url = p.base_url.trim_end_matches('/').into();
            anyhow::ensure!(
                p.kind == "github" || p.kind == "forgejo",
                "provider kind must be github or forgejo"
            );
            if let Some(f) = &p.client_secret_file {
                p.client_secret = std::fs::read_to_string(f)?.trim().into();
            }
            anyhow::ensure!(
                !p.client_id.is_empty() && !p.client_secret.is_empty(),
                "OAuth credentials are required"
            );
        }
        let mut ids = std::collections::HashSet::new();
        for p in &providers {
            anyhow::ensure!(ids.insert(&p.id), "duplicate provider id");
        }
        Ok(Self {
            data: env::var("NIGHTBUOY_DATA").unwrap_or("data".into()).into(),
            public_url,
            listen: env::var("NIGHTBUOY_LISTEN").unwrap_or("127.0.0.1:3000".into()),
            web: env::var("NIGHTBUOY_WEB")
                .unwrap_or("web/dist".into())
                .into(),
            providers,
            testing,
            read_only: env::var("NIGHTBUOY_READ_ONLY").as_deref() == Ok("1"),
            branding: env::var("NIGHTBUOY_BRANDING_DIR")
                .ok()
                .map(|d| crate::branding::Branding::load(std::path::Path::new(&d)))
                .transpose()?,
            replicas: env::var("NIGHTBUOY_REPLICAS_FILE").ok().map(Into::into),
        })
    }
}

pub fn onion(host: &str) -> bool {
    host.strip_suffix(".onion").is_some_and(|s| {
        s.len() == 56
            && s.bytes()
                .all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c))
    })
}
