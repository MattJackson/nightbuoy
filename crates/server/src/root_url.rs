//! Resolve a single root URL without guessing that provider denial means empty storage.
use crate::{crypto::*, remote::*};
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootRequest {
    pub url: String,
    #[serde(default)]
    pub provider_token: String,
    #[serde(default)]
    pub access_key: String,
    #[serde(default)]
    pub secret_key: String,
    #[serde(default)]
    pub namespace: Option<String>,
}
pub async fn resolve(
    input: RootRequest,
    testing: bool,
    allowed: Option<&Connection>,
) -> anyhow::Result<(Connection, Access)> {
    let u = url::Url::parse(input.url.trim())?;
    anyhow::ensure!(
        u.username().is_empty() && u.password().is_none() && u.fragment().is_none(),
        "use a root URL without embedded credentials or key fragments"
    );
    let parts = u
        .path_segments()
        .map(|s| s.filter(|v| !v.is_empty()).collect::<Vec<_>>())
        .unwrap_or_default();
    let scheme = u.scheme();
    let s3 = scheme == "s3" || scheme == "s3+https" || scheme == "s3+http";
    anyhow::ensure!(
        if s3 {
            u.query_pairs().all(|(k, _)| k == "region") && u.query_pairs().count() <= 1
        } else {
            u.query().is_none()
        },
        "unsupported storage URL query; keep credentials in the private credential fields"
    );
    let mut backend = Backend {
        kind: String::new(),
        endpoint: String::new(),
        namespace: String::new(),
        salt: b64([0u8; 32]),
        owner: String::new(),
        repository: String::new(),
        branch: "main".into(),
        bucket: String::new(),
        region: "us-east-1".into(),
    };
    if s3 {
        backend.kind = "s3".into();
        let region = u
            .query_pairs()
            .find(|(k, _)| k == "region")
            .map(|(_, v)| v.into_owned())
            .unwrap_or("us-east-1".into());
        backend.region = region.clone();
        if scheme == "s3" {
            backend.bucket = u.host_str().unwrap_or("").into();
            backend.endpoint = format!("https://s3.{region}.amazonaws.com");
            backend.namespace = parts.join("/");
        } else {
            anyhow::ensure!(!parts.is_empty(), "S3 URL needs a bucket");
            backend.bucket = parts[0].into();
            backend.endpoint = format!(
                "{}://{}",
                if scheme == "s3+https" {
                    "https"
                } else {
                    "http"
                },
                &u[url::Position::BeforeHost..url::Position::AfterPort]
            );
            backend.namespace = parts[1..].join("/");
        }
    } else {
        anyhow::ensure!(
            matches!(scheme, "https" | "http") && parts.len() >= 2,
            "Use a repository URL such as https://github.com/owner/repository"
        );
        let github = matches!(u.host_str(), Some("github.com" | "www.github.com"));
        backend.kind = if github { "github" } else { "forgejo" }.into();
        backend.endpoint = if github {
            "https://api.github.com".into()
        } else {
            u.origin().ascii_serialization()
        };
        backend.owner = parts[0].into();
        backend.repository = parts[1].trim_end_matches(".git").into();
        if parts.len() > 2 {
            anyhow::ensure!(
                parts.len() >= 4 && parts[2] == "tree",
                "Use the repository root or a /tree/BRANCH/directory URL"
            );
            backend.branch = parts[3].into();
            backend.namespace = parts[4..].join("/");
        }
    }
    if let Some(namespace) = input.namespace {
        anyhow::ensure!(
            backend.namespace.is_empty() || backend.namespace == namespace,
            "The URL directory and private access key name different storage roots"
        );
        backend.namespace = namespace;
    }
    if backend.namespace.is_empty() {
        backend.namespace = hash(b"nightbuoy-root-slot-v2");
    }
    if let Some(c) = allowed {
        let b = &c.primary;
        anyhow::ensure!(
            backend.kind == b.kind
                && backend.endpoint == b.endpoint
                && backend.owner == b.owner
                && backend.repository == b.repository
                && backend.bucket == b.bucket
                && backend.namespace == b.namespace
                && backend.region == b.region
                && (parts.len() <= 2 || backend.branch == b.branch),
            "operator has not approved this storage root"
        );
    }
    backend.validate(testing)?;
    let mut access = Access {
        backend: backend.id()?,
        token: input.provider_token,
        access_key: input.access_key,
        secret_key: input.secret_key,
    };
    let provisional = Remote::new(backend.clone(), access.clone(), testing)?;
    if s3
        && provisional
            .get(&crate::sealed_storage::head_path())
            .await?
            .is_none()
    {
        provisional.confirm_bucket().await?;
    }
    if !s3 {
        let default_branch = provisional.probe_repository().await?;
        if parts.len() == 2 {
            backend.branch = if let Some(c) = allowed {
                c.primary.branch.clone()
            } else {
                default_branch
            };
        }
        let check = Remote::new(
            backend.clone(),
            Access {
                backend: backend.id()?,
                ..access.clone()
            },
            testing,
        )?;
        check.probe_branch().await?;
    }
    if let Some(c) = allowed {
        anyhow::ensure!(
            backend.branch == c.primary.branch,
            "operator has not approved this branch"
        );
        access.backend = c.primary.id()?;
        return Ok((c.clone(), access));
    }
    backend.salt = b64(hex::decode(hash(serde_json::to_vec(&backend)?))?);
    backend.validate(testing)?;
    access.backend = backend.id()?;
    Ok((
        Connection {
            version: 2,
            primary: backend,
            replicas: vec![],
            community: String::new(),
            branch_pin: String::new(),
            checkpoint: String::new(),
        },
        access,
    ))
}
