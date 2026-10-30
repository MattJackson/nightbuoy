//! Optional public presentation files, mounted separately after installation.
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Link {
    pub label: String,
    pub href: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Branding {
    pub name: String,
    pub home: String,
    pub tagline: String,
    #[serde(default)]
    pub links: Vec<Link>,
    pub logo: Option<String>,
    pub favicon: Option<String>,
    pub css: Option<String>,
    #[serde(skip)]
    pub directory: PathBuf,
}
fn link(value: &str) -> bool {
    if value.starts_with('/') {
        return !value.starts_with("//")
            && !value.contains('\\')
            && !value.chars().any(char::is_control);
    }
    url::Url::parse(value)
        .is_ok_and(|u| u.scheme() == "https" && u.username().is_empty() && u.password().is_none())
}
impl Branding {
    pub fn load(directory: &Path) -> anyhow::Result<Self> {
        let manifest = directory.join("branding.json");
        anyhow::ensure!(
            std::fs::metadata(&manifest)?.len() <= 65536,
            "branding manifest too large"
        );
        let mut b: Self = serde_json::from_slice(&std::fs::read(manifest)?)?;
        anyhow::ensure!(
            !b.name.trim().is_empty()
                && b.name.len() <= 80
                && b.tagline.len() <= 320
                && b.links.len() <= 8
                && link(&b.home),
            "invalid branding metadata"
        );
        for l in &b.links {
            anyhow::ensure!(
                !l.label.trim().is_empty() && l.label.len() <= 40 && link(&l.href),
                "invalid branding navigation"
            );
        }
        b.directory = directory.to_path_buf();
        for name in [&b.logo, &b.favicon, &b.css].into_iter().flatten() {
            anyhow::ensure!(
                !name.is_empty()
                    && name.len() < 100
                    && !name.contains("..")
                    && name
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c)),
                "invalid branding asset filename"
            );
            let meta = std::fs::symlink_metadata(directory.join(name))?;
            anyhow::ensure!(
                meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= 4 * 1024 * 1024,
                "invalid branding asset"
            );
        }
        anyhow::ensure!(
            b.css.as_ref().is_none_or(|s| s.ends_with(".css")),
            "branding stylesheet must be CSS"
        );
        for name in [&b.logo, &b.favicon].into_iter().flatten() {
            anyhow::ensure!(
                [".svg", ".png", ".webp", ".ico"]
                    .iter()
                    .any(|e| name.ends_with(e)),
                "unsupported branding image"
            );
        }
        Ok(b)
    }
    pub fn public(&self) -> serde_json::Value {
        let mut value = serde_json::to_value(self).unwrap();
        for name in ["logo", "favicon", "css"] {
            if let Some(file) = value[name].as_str() {
                value[name] = serde_json::json!(format!("/branding/{file}"));
            }
        }
        value
    }
    pub fn asset(&self, file: &str) -> Option<(PathBuf, &'static str)> {
        if ![&self.logo, &self.favicon, &self.css]
            .into_iter()
            .flatten()
            .any(|n| n == file)
        {
            return None;
        }
        let mime = if file.ends_with(".css") {
            "text/css"
        } else if file.ends_with(".svg") {
            "image/svg+xml"
        } else if file.ends_with(".png") {
            "image/png"
        } else if file.ends_with(".webp") {
            "image/webp"
        } else {
            "image/x-icon"
        };
        Some((self.directory.join(file), mime))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(dir: &Path, changes: serde_json::Value) {
        std::fs::write(
            dir.join("logo.svg"),
            "<svg xmlns=\"http://www.w3.org/2000/svg\"/>",
        )
        .unwrap();
        std::fs::write(dir.join("theme.css"), ":root{--teal:#7c3aed}").unwrap();
        let mut value = serde_json::json!({"name":"Example Community","home":"/","tagline":"A separate brand.","links":[],"logo":"logo.svg","favicon":"logo.svg","css":"theme.css"});
        for (key, value2) in changes.as_object().unwrap() {
            value[key] = value2.clone();
        }
        std::fs::write(
            dir.join("branding.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
    }
    #[test]
    fn public_branding_exposes_only_declared_public_assets() {
        let dir = tempfile::tempdir().unwrap();
        fixture(dir.path(), serde_json::json!({}));
        let brand = Branding::load(dir.path()).unwrap();
        assert_eq!(brand.public()["logo"], "/branding/logo.svg");
        assert!(brand.public().get("directory").is_none());
        assert!(brand.asset("theme.css").is_some());
        assert!(brand.asset("branding.json").is_none());
        assert!(brand.asset("arbitrary.js").is_none());
        assert!(brand.asset("../secret").is_none());
    }
    #[test]
    fn branding_rejects_script_links_and_traversal() {
        for change in [
            serde_json::json!({"home":"javascript:alert(1)"}),
            serde_json::json!({"home":"//external.invalid"}),
            serde_json::json!({"logo":"../secret.svg"}),
            serde_json::json!({"css":"logo.svg"}),
        ] {
            let dir = tempfile::tempdir().unwrap();
            fixture(dir.path(), change);
            assert!(Branding::load(dir.path()).is_err());
        }
    }
    #[cfg(unix)]
    #[test]
    fn branding_rejects_symlink_assets() {
        let dir = tempfile::tempdir().unwrap();
        fixture(dir.path(), serde_json::json!({}));
        std::fs::remove_file(dir.path().join("logo.svg")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", dir.path().join("logo.svg")).unwrap();
        assert!(Branding::load(dir.path()).is_err());
    }
}
