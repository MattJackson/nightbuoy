//! Shared native client operations for CLI/TUI, using the same verified model and opaque transport.
use crate::{
    client_crypto::{self, Identity},
    crypto::*,
    model::*,
    portable, portable_protocol as protocol,
    remote::*,
    root_url::{self, RootRequest},
    sealed_storage::{self as opaque, MetadataKey},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessKey {
    pub version: u8,
    pub key: String,
    pub community: String,
    pub branch: String,
    pub checkpoint: String,
    pub namespace: String,
}
impl AccessKey {
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        use base64::Engine;
        let value = value
            .strip_prefix("nb2:")
            .ok_or_else(|| anyhow::anyhow!("forum access key must start with nb2:"))?;
        anyhow::ensure!(value.len() <= 8192, "access key too large");
        let v: Self = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value)?,
        )?;
        anyhow::ensure!(
            v.version == 2
                && decode(&v.key)?.len() == 32
                && [&v.community, &v.branch, &v.checkpoint]
                    .into_iter()
                    .all(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())),
            "invalid private access key"
        );
        Ok(v)
    }
    pub fn epoch(&self) -> anyhow::Result<[u8; 32]> {
        decode(&self.key)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid content key"))
    }
}
#[derive(Clone)]
struct Pending {
    intent: String,
    signed: Signed,
}
pub struct Client {
    pub connection: Connection,
    pub remote: Remote,
    pub identity: Option<Identity>,
    pub data: Data,
    pub contents: BTreeMap<String, Value>,
    pub rejected: usize,
    pub current: [u8; 32],
    metadata: MetadataKey,
    parent: Blob,
    pin: Option<AccessKey>,
    pending: Option<Pending>,
}
impl Drop for Client {
    fn drop(&mut self) {
        self.current.fill(0);
    }
}
impl Client {
    pub async fn open(
        url: &str,
        access: Option<AccessKey>,
        identity: Option<Identity>,
        provider_token: String,
        testing: bool,
    ) -> anyhow::Result<Self> {
        Self::open_with_credentials(
            url,
            access,
            identity,
            provider_token,
            String::new(),
            String::new(),
            testing,
        )
        .await
    }
    pub async fn open_with_credentials(
        url: &str,
        access: Option<AccessKey>,
        identity: Option<Identity>,
        provider_token: String,
        access_key: String,
        secret_key: String,
        testing: bool,
    ) -> anyhow::Result<Self> {
        let (mut connection, transport) = root_url::resolve(
            RootRequest {
                url: url.into(),
                provider_token,
                access_key,
                secret_key,
                namespace: access.as_ref().map(|a| a.namespace.clone()),
            },
            testing,
            None,
        )
        .await?;
        let mut remote = Remote::new(connection.primary.clone(), transport, testing)?;
        let head=remote.get(&opaque::head_path()).await?.ok_or_else(||anyhow::anyhow!("No encrypted forum exists at this root. Create one in the graphical setup or explicitly choose creation."))?;
        let (ephemeral, slots, _) = opaque::split_head(&head.bytes)?;
        let current = if let Some(key) = &access {
            key.epoch()?
        } else {
            identity
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("an access key or authorized identity is required"))?
                .open_discovery(&ephemeral, &slots)?
        };
        let metadata = MetadataKey::from_epoch(&current);
        let (parent, data, primary) = portable::client_load(&remote, &metadata)
            .await?
            .ok_or_else(|| anyhow::anyhow!("encrypted forum disappeared"))?;
        if let Some(key) = &access {
            anyhow::ensure!(
                data.community() == key.community && data.branch() == key.branch,
                "private key identifies a different forum or branch"
            );
            check_checkpoint(&data, &format!("p:{}", key.checkpoint))?;
        }
        if let Some(who) = &identity {
            anyhow::ensure!(
                who.community.is_empty() || who.community == data.community(),
                "identity belongs to a different forum"
            );
            check_checkpoint(&data, &who.checkpoint)?;
        }
        if let Some(rebound) = remote.rebind_same_location(&primary)? {
            remote = rebound;
        }
        if remote.backend.id()? != primary.id()? {
            connection.replicas.push(remote.backend.clone());
        }
        connection.primary = primary;
        connection.community = data.community();
        connection.branch_pin = data.branch();
        connection.checkpoint = protocol::head(&data.archive)?;
        let mut client = Self {
            connection,
            remote,
            identity,
            data,
            contents: BTreeMap::new(),
            rejected: 0,
            current,
            metadata,
            parent,
            pin: access,
            pending: None,
        };
        client.decrypt_contents()?;
        Ok(client)
    }
    pub fn can_write(&self) -> bool {
        self.remote.writable()
            && self.remote.backend.id().ok() == self.connection.primary.id().ok()
            && self.identity.as_ref().is_some_and(|i| {
                self.data
                    .view()
                    .members
                    .get(&i.device.id)
                    .is_some_and(|m| m.status == "active")
            })
    }
    pub async fn refresh(&mut self) -> anyhow::Result<()> {
        let head = self
            .remote
            .get(&opaque::head_path())
            .await?
            .ok_or_else(|| anyhow::anyhow!("encrypted head missing"))?;
        let (ephemeral, slots, _) = opaque::split_head(&head.bytes)?;
        let candidate_current = if let Some(who) = &self.identity {
            who.open_discovery(&ephemeral, &slots)
                .unwrap_or(self.current)
        } else {
            self.current
        };
        let candidate_metadata = MetadataKey::from_epoch(&candidate_current);
        let (parent, data, primary) = portable::client_load(&self.remote, &candidate_metadata)
            .await?
            .ok_or_else(|| anyhow::anyhow!("encrypted head missing"))?;
        self.data.catch_up(&data.archive)?;
        check_checkpoint(&data, &format!("p:{}", protocol::head(&self.data.archive)?))?;
        anyhow::ensure!(
            data.branch() == self.data.branch() && primary.id()? == self.connection.primary.id()?,
            "branch or write authority changed; explicit recovery selection required"
        );
        if let Some(pin) = &self.pin {
            check_checkpoint(&data, &format!("p:{}", pin.checkpoint))?;
        }
        self.current.fill(0);
        self.current = candidate_current;
        self.metadata = candidate_metadata;
        self.parent = parent;
        self.data = data;
        self.connection.checkpoint = protocol::head(&self.data.archive)?;
        self.decrypt_contents()?;
        Ok(())
    }
    fn decrypt_contents(&mut self) -> anyhow::Result<()> {
        let mut keys = BTreeMap::from([(self.data.view().epoch, self.current)]);
        if let Some(who) = &self.identity {
            for (epoch, grants) in &self.data.view().grants {
                if let Some(grant) = grants.get(&who.device.id)
                    && let Ok(key) = who.open_epoch(grant)
                {
                    keys.insert(*epoch, key);
                }
            }
        }
        self.contents.clear();
        self.rejected = 0;
        for event in &self.data.events {
            if let Some(key) = keys.get(&event.epoch) {
                match client_crypto::decrypt_event(key, &event.record.event) {
                    Ok(value) => {
                        if valid_content(&event.kind, &value) {
                            self.contents.insert(event.hash.clone(), value);
                        } else {
                            self.rejected += 1;
                        }
                    }
                    Err(_) => self.rejected += 1,
                }
            }
        }
        for key in keys.values_mut() {
            key.fill(0);
        }
        Ok(())
    }
    pub fn objects(&self) -> Vec<&Event> {
        let mut latest: BTreeMap<&str, &Event> = BTreeMap::new();
        for event in &self.data.events {
            latest.insert(&event.id, event);
        }
        latest
            .into_values()
            .filter(|e| e.kind != "delete" && self.contents.contains_key(&e.hash))
            .collect()
    }
    pub async fn post(
        &mut self,
        kind: &str,
        parent: &str,
        payload: Value,
        id: Option<String>,
        previous: &str,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(valid_content(kind, &payload), "invalid content payload");
        let intent = protocol::digest(&json!([kind, parent, payload, previous]))?;
        if let Some(pending) = &self.pending {
            let fields: Value = serde_json::from_str(&pending.signed.body)?;
            anyhow::ensure!(
                id.as_ref()
                    .is_none_or(|id| Some(id.as_str()) == fields[6].as_str()),
                "A different object is pending confirmation"
            );
            anyhow::ensure!(
                pending.intent == intent,
                "A previous submission still needs confirmation. Retry it before sending a different draft."
            );
        } else {
            self.refresh().await?;
            anyhow::ensure!(
                self.can_write(),
                "posting needs an approved member identity and your own provider write permission"
            );
            let who = self.identity.as_ref().unwrap();
            let id = id.unwrap_or_else(object_id);
            let fields = json!([
                1,
                self.data.community(),
                who.device.id,
                self.data.authority_tip(),
                self.data.view().epoch,
                kind,
                id,
                parent,
                previous,
                crate::store::now() * 1000
            ]);
            let signed = client_crypto::encrypt_event(who, &self.current, fields, &payload)?;
            self.pending = Some(Pending { intent, signed });
        }
        self.retry_pending().await
    }
    pub fn pending_id(&self) -> Option<String> {
        self.pending
            .as_ref()
            .and_then(|p| serde_json::from_str::<Value>(&p.signed.body).ok())
            .and_then(|v| v[6].as_str().map(str::to_string))
    }
    /// Explicit local discard after consulting the verified head; preserve the draft's object ID.
    pub async fn discard_pending(&mut self) -> anyhow::Result<bool> {
        self.refresh().await?;
        let accepted = self
            .pending
            .as_ref()
            .is_some_and(|p| self.data.archive.order.contains(&p.signed.hash()));
        self.pending = None;
        Ok(accepted)
    }
    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }
    pub async fn retry_pending(&mut self) -> anyhow::Result<()> {
        let signed = self
            .pending
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No pending submission"))?
            .signed
            .clone();
        self.refresh().await?;
        if self.data.archive.order.contains(&signed.hash()) {
            self.pending = None;
            return Ok(());
        }
        anyhow::ensure!(
            self.can_write(),
            "posting needs an approved member identity and your own provider write permission"
        );
        let who = self.identity.clone().unwrap();
        for attempt in 0..3 {
            let item = protocol::Item::Event(Record {
                event: signed.clone(),
                publisher: self.connection.primary.id()?,
                receipt: String::new(),
            });
            if self.data.archive.order.contains(&signed.hash()) {
                self.pending = None;
                return Ok(());
            }
            let mut candidate = Some(self.data.clone());
            item.apply(&mut candidate)?;
            let mut candidate = candidate.unwrap();
            let proof = candidate.archive.portable_proof.as_mut().unwrap();
            let sequence = candidate.archive.order.len();
            let previous = proof
                .headers
                .last()
                .map(protocol::digest)
                .transpose()?
                .unwrap_or_default();
            let body = protocol::header_body(&candidate, &item, &previous, sequence)?;
            let header = who.signed(&serde_json::from_str(&body)?)?;
            candidate
                .archive
                .portable_proof
                .as_mut()
                .unwrap()
                .headers
                .push(header);
            protocol::verify(&candidate)?;
            match portable::client_publish(
                &self.remote,
                &self.metadata,
                &candidate,
                Some(&self.parent),
                Some(&item),
            )
            .await
            {
                Ok(()) => {
                    self.data = candidate;
                    self.refresh().await?;
                    self.pending = None;
                    return Ok(());
                }
                Err(error) => {
                    if attempt == 2 {
                        return Err(error);
                    }
                    self.refresh().await?;
                }
            }
        }
        Ok(())
    }
    pub async fn sealed_export(&self) -> anyhow::Result<Vec<u8>> {
        let discovery = self
            .data
            .view()
            .discovery
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("signed discovery grants required"))?;
        opaque::head_frame(
            &self.metadata,
            &discovery.wrapped.values().cloned().collect::<Vec<_>>(),
            &discovery.ephemeral,
            &self.data.archive,
            &opaque::context("", "private-archive"),
        )
    }
}
fn valid_content(kind: &str, p: &Value) -> bool {
    fn text(value: Option<&Value>, max: usize, required: bool) -> bool {
        match value {
            None => !required,
            Some(Value::String(s)) => {
                s.encode_utf16().count() <= max && (!required || !s.trim().is_empty())
            }
            _ => false,
        }
    }
    if !p.is_object() {
        return false;
    }
    if kind == "delete" {
        return text(p.get("body"), 1000, false);
    }
    if kind == "board" {
        let order = p
            .get("order")
            .filter(|v| !v.is_null())
            .unwrap_or(&Value::Null);
        let valid_order = order.is_null()
            || order
                .as_f64()
                .is_some_and(|n| n.is_finite() && n.fract() == 0.0 && n.abs() <= 100000.0);
        return text(p.get("title"), 240, true)
            && text(p.get("description"), 2000, false)
            && valid_order;
    }
    if !matches!(kind, "topic" | "reply")
        || !text(p.get("body"), 100000, true)
        || (kind == "topic" && !text(p.get("title"), 240, true))
    {
        return false;
    }
    let Some(raw) = p.get("attachments").filter(|v| !v.is_null()) else {
        return true;
    };
    let Some(files) = raw.as_array() else {
        return false;
    };
    if files.len() > 30 {
        return false;
    }
    let mut total = 0;
    for file in files {
        if !file.is_object() || !text(file.get("name"), 255, true) {
            return false;
        }
        let Some(size) = file["size"].as_u64().filter(|s| *s <= 3145728) else {
            return false;
        };
        let Some(data) = file["data"].as_str().filter(|s| s.len() <= 4194304) else {
            return false;
        };
        let Ok(decoded) = decode(data) else {
            return false;
        };
        if decoded.len() as u64 != size {
            return false;
        }
        total += size;
        if total > 3145728 {
            return false;
        }
    }
    true
}

pub fn check_checkpoint(data: &Data, pin: &str) -> anyhow::Result<()> {
    if pin.is_empty() {
        return Ok(());
    }
    let semantic = if let Some(digest) = pin.strip_prefix("p:") {
        let h = data
            .archive
            .portable_proof
            .as_ref()
            .and_then(|p| {
                p.headers
                    .iter()
                    .find(|s| protocol::digest(s).ok().as_deref() == Some(digest))
            })
            .ok_or_else(|| anyhow::anyhow!("signed checkpoint rollback or fork"))?;
        let body: Value = serde_json::from_str(&h.body)?;
        body[9].as_str().unwrap_or("").to_string()
    } else {
        pin.to_string()
    };
    let position = if semantic == data.community() {
        None
    } else {
        Some(
            data.archive
                .order
                .iter()
                .position(|id| id == &semantic)
                .ok_or_else(|| {
                    anyhow::anyhow!("checkpoint is missing or older than your identity")
                })?,
        )
    };
    for control in &data.archive.controls {
        let fields: Value = serde_json::from_str(&control.body)?;
        if fields[6] == "reconstitute" {
            let reset = data
                .archive
                .order
                .iter()
                .position(|id| id == &control.hash())
                .unwrap();
            anyhow::ensure!(
                position.is_some_and(|p| p >= reset),
                "explicit branch choice required before opening this recovery fork"
            );
        }
    }
    Ok(())
}
pub fn object_id() -> String {
    let mut raw = random::<16>();
    raw[6] = (raw[6] & 15) | 64;
    raw[8] = (raw[8] & 63) | 128;
    let h = hex::encode(raw);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json,
        extract::{Path, State},
        routing::get,
    };
    use std::sync::Arc;
    type Objects = Arc<std::sync::Mutex<BTreeMap<String, Vec<u8>>>>;
    fn data(who: &Identity, backend: &Backend, key: &[u8; 32], label: &str) -> Data {
        let id = backend.id().unwrap();
        let discovery =
            client_crypto::discovery_grants(std::slice::from_ref(&who.device), key).unwrap();
        let genesis=who.signed(&json!(["nightbuoy-genesis",1,who.device,{"name":label,"skin":"nightbuoy","identity":"key","admission":"approval","history":true,"portable":{"version":1,"primary":id,"discovery":discovery}},id,[{"member":who.device.id,"epoch":1,"key":client_crypto::wrap_epoch(&who.device,key).unwrap()}]])).unwrap();
        let mut data = Data::create(genesis.clone()).unwrap();
        let item = protocol::Item::Genesis(genesis);
        let header = who
            .signed(
                &serde_json::from_str(&protocol::header_body(&data, &item, "", 0).unwrap())
                    .unwrap(),
            )
            .unwrap();
        data.archive.portable_proof = Some(protocol::Certificate {
            anchor: None,
            headers: vec![header],
        });
        Data::replay(&data.archive).unwrap()
    }
    fn objects_for(data: &Data, backend: &Backend, key: &MetadataKey) -> BTreeMap<String, Vec<u8>> {
        let snapshot = key
            .seal(&data.archive, &opaque::context("test", "snapshot"))
            .unwrap();
        let snapshot_id = hash(&snapshot);
        let discovery = data.view().discovery.as_ref().unwrap();
        let head=opaque::head_frame(key,&discovery.wrapped.values().cloned().collect::<Vec<_>>(),&discovery.ephemeral,&json!({"version":2,"community":data.community(),"branch":data.branch(),"head":protocol::head(&data.archive).unwrap(),"snapshot":snapshot_id,"primary":backend,"grants":discovery.wrapped,"ephemeral":discovery.ephemeral}),&opaque::context("test","head")).unwrap();
        BTreeMap::from([
            (format!("test/{snapshot_id}"), snapshot),
            (format!("test/{}", opaque::head_path()), head),
        ])
    }
    #[tokio::test]
    async fn rejected_fork_cannot_replace_retained_export_keys() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/browser-identity.json")).unwrap();
        let mut who = Identity::unlock(
            fixture["vault_json"].as_str().unwrap().as_bytes(),
            fixture["password"].as_str().unwrap(),
        )
        .unwrap();
        who.community.clear();
        who.checkpoint.clear();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = Backend {
            kind: "forgejo".into(),
            endpoint: format!("http://{}", listener.local_addr().unwrap()),
            namespace: "test".into(),
            salt: b64(random::<32>()),
            owner: "owner".into(),
            repository: "repo".into(),
            branch: "main".into(),
            bucket: String::new(),
            region: "us-east-1".into(),
        };
        let old_key = random::<32>();
        let substituted_key = random::<32>();
        let original = data(&who, &backend, &old_key, "Retained original");
        let fork = data(&who, &backend, &substituted_key, "Rejected replacement");
        let new_metadata = MetadataKey::from_epoch(&substituted_key);
        let objects = Arc::new(std::sync::Mutex::new(objects_for(
            &fork,
            &backend,
            &new_metadata,
        )));
        async fn fetch(
            State(objects): State<Objects>,
            Path(path): Path<String>,
        ) -> (axum::http::StatusCode, Json<Value>) {
            match objects.lock().unwrap().get(&path) {
                Some(bytes) => (
                    axum::http::StatusCode::OK,
                    Json(json!({"sha":"test-version","encoding":"base64","content":b64(bytes)})),
                ),
                None => (axum::http::StatusCode::NOT_FOUND, Json(json!({}))),
            }
        }
        let source = objects.clone();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                axum::Router::new()
                    .route("/api/v1/repos/owner/repo/contents/{*path}", get(fetch))
                    .with_state(source),
            )
            .await
            .unwrap()
        });
        let remote = Remote::new(
            backend.clone(),
            Access {
                backend: backend.id().unwrap(),
                token: "synthetic-test-token".into(),
                ..Default::default()
            },
            true,
        )
        .unwrap();
        let metadata = MetadataKey::from_epoch(&old_key);
        let mut client = Client {
            connection: Connection {
                version: 2,
                primary: backend,
                replicas: vec![],
                community: original.community(),
                branch_pin: original.branch(),
                checkpoint: protocol::head(&original.archive).unwrap(),
            },
            remote,
            identity: Some(who.clone()),
            data: original,
            contents: BTreeMap::new(),
            rejected: 0,
            current: old_key,
            metadata: metadata.clone(),
            parent: Blob {
                bytes: vec![],
                version: "retained".into(),
                revision: None,
            },
            pin: None,
            pending: None,
        };
        let old_community = client.data.community();
        assert!(client.refresh().await.is_err());
        assert_eq!(client.current, old_key);
        assert!(client.metadata.same(&metadata));
        assert_eq!(client.data.community(), old_community);
        assert_eq!(client.parent.version, "retained");
        let export = client.sealed_export().await.unwrap();
        let retained: Archive =
            opaque::open_head(&metadata, &export, &opaque::context("", "private-archive")).unwrap();
        assert_eq!(Data::replay(&retained).unwrap().community(), old_community);
        assert!(
            opaque::open_head::<Archive>(
                &new_metadata,
                &export,
                &opaque::context("", "private-archive")
            )
            .is_err()
        );
        // With the real head restored but all writes unavailable, distinct user retries must
        // retain the identical signed submission instead of assigning another object/nonce.
        *objects.lock().unwrap() = objects_for(&client.data, &client.connection.primary, &metadata);
        let payload = json!({"title":"Pending board","description":"Retry me"});
        assert!(
            client
                .post("board", "", payload.clone(), None, "")
                .await
                .is_err()
        );
        let pending = client.pending.as_ref().unwrap().signed.clone();
        assert!(client.post("board", "", payload, None, "").await.is_err());
        assert_eq!(
            client.pending.as_ref().unwrap().signed.hash(),
            pending.hash()
        );
        assert!(
            client
                .post("board", "", json!({"title":"Different draft"}), None, "")
                .await
                .is_err()
        );
        assert_eq!(
            client.pending.as_ref().unwrap().signed.hash(),
            pending.hash()
        );
        // A later governance checkpoint makes the old signature definitively stale.
        // Explicit review/discard unblocks posting while preserving its object identity.
        let old_id = client.pending_id().unwrap();
        let mut updated = client.data.clone();
        let mut policy = serde_json::to_value(&updated.view().policy).unwrap();
        policy["name"] = json!("Updated community");
        let control = who
            .signed(&json!([
                "nightbuoy-control",
                1,
                updated.community(),
                updated.authority_tip(),
                who.device.id,
                "c".repeat(64),
                "policy",
                policy
            ]))
            .unwrap();
        updated.control(control.clone()).unwrap();
        let parent = protocol::head(&updated.archive).unwrap();
        let body = protocol::header_body(
            &updated,
            &protocol::Item::Control(control),
            &parent,
            updated.archive.order.len(),
        )
        .unwrap();
        updated
            .archive
            .portable_proof
            .as_mut()
            .unwrap()
            .headers
            .push(who.signed(&serde_json::from_str(&body).unwrap()).unwrap());
        protocol::verify(&updated).unwrap();
        *objects.lock().unwrap() = objects_for(&updated, &client.connection.primary, &metadata);
        assert!(client.retry_pending().await.is_err());
        assert!(client.has_pending());
        assert!(!client.discard_pending().await.unwrap());
        assert!(!client.has_pending());
        assert!(
            client
                .post(
                    "board",
                    "",
                    json!({"title":"Pending board","description":"Retry me"}),
                    Some(old_id.clone()),
                    ""
                )
                .await
                .is_err()
        );
        assert_eq!(client.pending_id(), Some(old_id));
        let rebased: Value =
            serde_json::from_str(&client.pending.as_ref().unwrap().signed.body).unwrap();
        assert_eq!(rebased[3], updated.authority_tip());
        server.abort();
    }
}
