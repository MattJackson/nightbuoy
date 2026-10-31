//! Portable member-signed state. Servers possess publication keys, never community authority keys.
use crate::crypto::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
pub const MAX_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_CORE_BYTES: usize = MAX_ARCHIVE_BYTES - 256 * 1024;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub admission: String,
    pub history: bool,
    pub identity: String,
    pub name: String,
    pub skin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consensus: Option<nightbuoy_proof::Trust>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portable: Option<crate::portable_protocol::Ordering>,
}
impl Policy {
    pub fn validate(&self) -> anyhow::Result<()> {
        if let Some(ordering) = &self.portable {
            ordering.validate()?;
            anyhow::ensure!(
                self.consensus.is_none() && self.identity == "key",
                "portable ordering cannot mix legacy consensus or forge enrollment"
            );
        }
        if let Some(trust) = &self.consensus {
            trust.validate().map_err(anyhow::Error::msg)?;
        }
        anyhow::ensure!(
            matches!(self.admission.as_str(), "automatic" | "approval")
                && matches!(self.identity.as_str(), "forge" | "key"),
            "invalid admission policy"
        );
        anyhow::ensure!(
            !self.name.trim().is_empty() && self.name.len() <= 80,
            "public community label must be 1–80 bytes"
        );
        anyhow::ensure!(
            !self.skin.is_empty()
                && self.skin.len() <= 40
                && self
                    .skin
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "invalid legacy presentation identifier"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub id: String,
    pub sign: String,
    pub wrap: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discover: Option<String>,
}
impl Device {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.id == hash(decode(&self.sign)?),
            "incorrect identity fingerprint"
        );
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&decode(&self.sign)?)?;
        if let Some(key) = &self.discover {
            anyhow::ensure!(decode(key)?.len() == 65, "invalid discovery public key");
            p256::PublicKey::from_sec1_bytes(&decode(key)?)?;
        }
        anyhow::ensure!(
            self.wrap["kty"] == "RSA"
                && self.wrap["e"] == "AQAB"
                && self.wrap["n"].as_str().is_some_and(|n| n.len() == 512)
                && self.wrap.get("d").is_none(),
            "invalid RSA-3072 wrapping key"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Member {
    pub device: Device,
    pub role: String,
    pub status: String,
    pub floor: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed {
    pub body: String,
    pub signature: String,
}
impl Signed {
    pub fn hash(&self) -> String {
        hash(&self.body)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub event: Signed,
    pub publisher: String,
    pub receipt: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub record: Record,
    pub hash: String,
    pub author: String,
    pub kind: String,
    pub id: String,
    pub parent: String,
    pub previous: String,
    pub epoch: u64,
    pub created: u64,
    pub control: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct View {
    pub policy: Policy,
    pub epoch: u64,
    pub members: BTreeMap<String, Member>,
    pub grants: BTreeMap<u64, BTreeMap<String, String>>,
    pub publishers: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery: Option<crate::portable_protocol::Discovery>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Archive {
    pub genesis: Signed,
    pub controls: Vec<Signed>,
    pub records: Vec<Record>,
    pub order: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<nightbuoy_proof::Proof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portable_proof: Option<crate::portable_protocol::Certificate>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Data {
    pub archive: Archive,
    pub tip: String,
    pub views: BTreeMap<String, std::sync::Arc<View>>,
    pub events: Vec<Event>,
}
fn array(body: &str, len: usize) -> anyhow::Result<Vec<Value>> {
    let a: Vec<Value> = serde_json::from_str(body)?;
    anyhow::ensure!(
        a.len() == len && serde_json::to_string(&a)? == body,
        "invalid compact JSON encoding"
    );
    Ok(a)
}
fn text(a: &[Value], i: usize) -> anyhow::Result<&str> {
    a[i].as_str()
        .ok_or_else(|| anyhow::anyhow!("invalid string field"))
}
impl Data {
    pub fn community(&self) -> String {
        self.archive.genesis.hash()
    }
    pub fn view(&self) -> &View {
        &self.views[&self.tip]
    }
    pub fn authority_tip(&self) -> String {
        self.archive
            .controls
            .last()
            .map(Signed::hash)
            .unwrap_or_else(|| self.community())
    }
    pub fn core_bytes(&self) -> Vec<u8> {
        let mut a = self.archive.clone();
        a.proof = None;
        a.portable_proof = None;
        serde_json::to_vec(&serde_json::to_value(&a).unwrap()).unwrap()
    }
    pub fn check_append_capacity<T: serde::Serialize>(
        &self,
        record: &T,
        is_control: bool,
    ) -> anyhow::Result<()> {
        let count = if is_control {
            self.archive.controls.len()
        } else {
            self.archive.records.len()
        };
        let extra = serde_json::to_vec(record)?.len()
            + 66
            + usize::from(count > 0)
            + usize::from(!self.archive.order.is_empty());
        anyhow::ensure!(
            self.core_bytes().len() + extra <= MAX_CORE_BYTES,
            "pilot archive capacity reached; transaction was not accepted"
        );
        Ok(())
    }
    pub fn state_hash(&self) -> String {
        hash(self.core_bytes())
    }
    pub fn verify_proof(&self) -> anyhow::Result<()> {
        if self.view().policy.portable.is_some() {
            return crate::portable_protocol::verify(self);
        }
        if let Some(trust) = &self.view().policy.consensus {
            let proof = self
                .archive
                .proof
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("consensus confirmation is pending"))?;
            nightbuoy_proof::verify(trust, proof, &self.state_hash())
                .map_err(anyhow::Error::msg)?;
        }
        Ok(())
    }
    pub fn branch(&self) -> String {
        self.archive
            .controls
            .iter()
            .rev()
            .find(|c| {
                serde_json::from_str::<Value>(&c.body)
                    .ok()
                    .is_some_and(|a| a[6] == "reconstitute")
            })
            .map(Signed::hash)
            .unwrap_or_else(|| self.community())
    }
    pub fn create(genesis: Signed) -> anyhow::Result<Self> {
        let a = array(&genesis.body, 6)?;
        anyhow::ensure!(
            a[0] == "nightbuoy-genesis" && a[1] == 1,
            "unsupported genesis"
        );
        let device: Device = serde_json::from_value(a[2].clone())?;
        device.validate()?;
        verify_member(&device.sign, &genesis.body, &genesis.signature)?;
        let policy: Policy = serde_json::from_value(a[3].clone())?;
        policy.validate()?;
        let publisher = text(&a, 4)?.to_string();
        anyhow::ensure!(decode(&publisher)?.len() == 32, "invalid publisher key");
        if let Some(ordering) = &policy.portable {
            anyhow::ensure!(publisher == ordering.primary, "genesis backend mismatch");
        }
        let member = Member {
            device: device.clone(),
            role: "administrator".into(),
            status: "active".into(),
            floor: 1,
        };
        let discovery = policy.portable.as_ref().and_then(|p| p.discovery.clone());
        let mut v = View {
            policy,
            discovery,
            epoch: 1,
            members: BTreeMap::from([(device.id, member)]),
            grants: BTreeMap::new(),
            publishers: BTreeSet::from([publisher]),
        };
        grants(&mut v, &a[5])?;
        all_current_keys(&v)?;
        if let Some(d) = &v.discovery {
            d.validate(&v.members)?;
        }
        anyhow::ensure!(
            serde_json::to_vec(&genesis)?.len() < MAX_CORE_BYTES,
            "genesis capacity exceeded"
        );
        let tip = genesis.hash();
        let views = BTreeMap::from([(tip.clone(), std::sync::Arc::new(v))]);
        Ok(Self {
            archive: Archive {
                genesis,
                controls: vec![],
                records: vec![],
                order: vec![],
                proof: None,
                portable_proof: None,
            },
            tip,
            views,
            events: vec![],
        })
    }
    /// Only an explicit member-signed branch reset can seed a different live network.
    /// The reset embeds and verifies the old checkpoint certificate during replay.
    pub fn recovery_seed(a: &Archive, trust: &nightbuoy_proof::Trust) -> anyhow::Result<Self> {
        anyhow::ensure!(
            a.proof.is_none(),
            "recovery seed must await the new network's confirmation"
        );
        let last = a
            .order
            .last()
            .ok_or_else(|| anyhow::anyhow!("recovery requires a branch reset"))?;
        let control = a
            .controls
            .iter()
            .find(|c| c.hash() == *last)
            .ok_or_else(|| anyhow::anyhow!("recovery must end with a branch reset"))?;
        let body = array(&control.body, 8)?;
        anyhow::ensure!(
            body[6] == "reconstitute",
            "recovery requires a branch reset"
        );
        let mut checkpoint = a.clone();
        checkpoint.order.pop();
        checkpoint.controls.retain(|c| c.hash() != *last);
        checkpoint.proof = Some(serde_json::from_value(body[7]["checkpoint_proof"].clone())?);
        let old = Self::replay(&checkpoint)?;
        let old_trust =
            old.view().policy.consensus.as_ref().ok_or_else(|| {
                anyhow::anyhow!("recovery requires a consensus-confirmed checkpoint")
            })?;
        anyhow::ensure!(
            old_trust != trust && old_trust.chain_id != trust.chain_id,
            "recovery requires a distinct new consensus chain"
        );
        let data = Self::replay_unconfirmed(a)?;
        anyhow::ensure!(
            data.view().policy.consensus.as_ref() == Some(trust),
            "recovery must explicitly bind this new validator network"
        );
        Ok(data)
    }
    pub fn replay(a: &Archive) -> anyhow::Result<Self> {
        let d = Self::replay_unconfirmed(a)?;
        d.verify_proof()?;
        Ok(d)
    }
    pub fn replay_unconfirmed(a: &Archive) -> anyhow::Result<Self> {
        anyhow::ensure!(
            a.order.len() <= 100_000 && a.order.len() == a.controls.len() + a.records.len(),
            "invalid chain length"
        );
        anyhow::ensure!(
            a.order.iter().collect::<BTreeSet<_>>().len() == a.order.len(),
            "duplicate chain position"
        );
        let mut d = Self::create(a.genesis.clone())?;
        let controls: BTreeMap<String, &Signed> =
            a.controls.iter().map(|c| (c.hash(), c)).collect();
        let records: BTreeMap<String, &Record> =
            a.records.iter().map(|r| (r.event.hash(), r)).collect();
        anyhow::ensure!(
            controls.len() == a.controls.len() && records.len() == a.records.len(),
            "duplicate chain entry"
        );
        for id in &a.order {
            if let Some(c) = controls.get(id) {
                d.control((*c).clone())?;
            } else if let Some(r) = records.get(id) {
                d.event((*r).clone())?;
            } else {
                anyhow::bail!("missing chain block");
            }
        }
        d.archive.proof = a.proof.clone();
        d.archive.portable_proof = a.portable_proof.clone();
        Ok(d)
    }
    pub fn control(&mut self, s: Signed) -> anyhow::Result<()> {
        if self.archive.controls.iter().any(|c| c.hash() == s.hash()) {
            return Ok(());
        }
        let a = array(&s.body, 8)?;
        anyhow::ensure!(
            a[0] == "nightbuoy-control" && a[1] == 1 && a[2] == self.community(),
            "wrong control community"
        );
        anyhow::ensure!(
            a[3] == self.authority_tip(),
            "governance fork or stale control; synchronize first"
        );
        let actor = text(&a, 4)?;
        let v = self.view();
        let m = v
            .members
            .get(actor)
            .ok_or_else(|| anyhow::anyhow!("unknown administrator"))?;
        anyhow::ensure!(
            m.status == "active" && (m.role == "administrator" || a[6] == "reconstitute"),
            "administrator required"
        );
        verify_member(&m.device.sign, &s.body, &s.signature)?;
        anyhow::ensure!(text(&a, 5)?.len() == 64, "invalid command nonce");
        let op = text(&a, 6)?;
        let p = &a[7];
        let mut v = v.clone();
        match op {
            "reconstitute" => {
                if let Some(trust) = &v.policy.consensus {
                    let proof: nightbuoy_proof::Proof =
                        serde_json::from_value(p["checkpoint_proof"].clone())?;
                    nightbuoy_proof::verify(trust, &proof, &self.state_hash())
                        .map_err(anyhow::Error::msg)?;
                }
                let new_trust: Option<nightbuoy_proof::Trust> =
                    serde_json::from_value(p.get("consensus").cloned().unwrap_or(Value::Null))?;
                let portable: Option<crate::portable_protocol::Ordering> =
                    serde_json::from_value(p.get("portable").cloned().unwrap_or(Value::Null))?;
                anyhow::ensure!(
                    v.policy.portable.is_none() || portable.is_some(),
                    "portable branches cannot return to legacy ordering"
                );
                if let Some(ordering) = &portable {
                    ordering.validate()?;
                    anyhow::ensure!(
                        new_trust.is_none() && p["publisher"] == ordering.primary,
                        "invalid portable reset"
                    );
                }
                anyhow::ensure!(
                    (v.policy.consensus.is_none() && v.policy.portable.is_none())
                        || new_trust.is_some()
                        || portable.is_some(),
                    "production branch reset cannot remove consensus"
                );
                if let Some(trust) = &new_trust {
                    trust.validate().map_err(anyhow::Error::msg)?;
                }
                v.policy.consensus = new_trust;
                v.policy.portable = portable;
                if v.policy.portable.is_some() {
                    v.policy.identity = "key".into();
                }
                v.policy.validate()?;
                let excludes: Vec<String> = serde_json::from_value(p["exclude"].clone())?;
                anyhow::ensure!(
                    !excludes.iter().any(|id| id == actor),
                    "branch creator cannot exclude themselves"
                );
                for (id, m) in &mut v.members {
                    m.role = if id == actor {
                        "administrator"
                    } else {
                        "member"
                    }
                    .into();
                    if excludes.contains(id) {
                        m.status = "revoked".into();
                    }
                }
                let publisher = p["publisher"].as_str().unwrap_or("");
                anyhow::ensure!(decode(publisher)?.len() == 32, "invalid publisher key");
                v.publishers = BTreeSet::from([publisher.into()]);
                advance(&mut v, p)?;
                grants(&mut v, &p["grants"])?;
                all_current_keys(&v)?;
            }
            "policy" => {
                let policy: Policy = serde_json::from_value(p.clone())?;
                policy.validate()?;
                anyhow::ensure!(
                    policy.consensus == v.policy.consensus && policy.portable == v.policy.portable,
                    "validator trust changes require an explicit branch reset"
                );
                v.policy = policy;
            }
            "admit" => {
                let device: Device = serde_json::from_value(p["device"].clone())?;
                device.validate()?;
                anyhow::ensure!(
                    !v.members.contains_key(&device.id) && v.members.len() < 2000,
                    "duplicate member or capacity reached"
                );
                let floor = if v.policy.history { 1 } else { v.epoch + 1 };
                v.members.insert(
                    device.id.clone(),
                    Member {
                        device,
                        role: "member".into(),
                        status: "active".into(),
                        floor,
                    },
                );
                if !v.policy.history {
                    advance(&mut v, p)?;
                }
                grants(&mut v, &p["grants"])?;
                all_current_keys(&v)?;
            }
            "role" => {
                let id = p["member"].as_str().unwrap_or("");
                let role = p["role"].as_str().unwrap_or("");
                anyhow::ensure!(
                    matches!(role, "member" | "moderator" | "administrator"),
                    "unknown role"
                );
                let m = v
                    .members
                    .get_mut(id)
                    .ok_or_else(|| anyhow::anyhow!("unknown member"))?;
                anyhow::ensure!(m.status == "active", "inactive member");
                m.role = role.into();
                keep_admin(&v)?;
            }
            "revoke" => {
                let id = p["member"].as_str().unwrap_or("");
                let m = v
                    .members
                    .get_mut(id)
                    .ok_or_else(|| anyhow::anyhow!("unknown member"))?;
                anyhow::ensure!(m.status == "active", "already revoked");
                m.status = "revoked".into();
                keep_admin(&v)?;
                advance(&mut v, p)?;
                grants(&mut v, &p["grants"])?;
                all_current_keys(&v)?;
            }
            "rotate" => {
                advance(&mut v, p)?;
                grants(&mut v, &p["grants"])?;
                all_current_keys(&v)?;
            }
            "publisher" => {
                let key = p["key"].as_str().unwrap_or("");
                anyhow::ensure!(decode(key)?.len() == 32, "invalid publisher key");
                if p["approved"] == true {
                    v.publishers.insert(key.into());
                } else {
                    v.publishers.remove(key);
                }
            }
            _ => anyhow::bail!("unsupported control"),
        }
        let changes_grants = matches!(op, "admit" | "rotate" | "revoke" | "reconstitute");
        if changes_grants {
            if let Some(discovery) = p.get("discovery") {
                let discovery: crate::portable_protocol::Discovery =
                    serde_json::from_value(discovery.clone())?;
                discovery.validate(&v.members)?;
                v.discovery = Some(discovery);
            } else {
                anyhow::ensure!(
                    v.discovery.is_none(),
                    "signed discovery grants required for membership/key changes"
                );
            }
        } else {
            anyhow::ensure!(
                p.get("discovery").is_none(),
                "discovery grants may change only through signed key governance"
            );
        }
        self.check_append_capacity(&s, true)?;
        self.archive.proof = None;
        self.tip = s.hash();
        self.views.insert(self.tip.clone(), std::sync::Arc::new(v));
        self.archive.order.push(self.tip.clone());
        self.archive.controls.push(s);
        Ok(())
    }
    pub fn validate_event(&self, r: &Record, require_current: bool) -> anyhow::Result<Event> {
        let a = array(&r.event.body, 12)?;
        anyhow::ensure!(
            a[0] == 1 && a[1] == self.community(),
            "wrong event community"
        );
        let author = text(&a, 2)?.to_string();
        let control = text(&a, 3)?.to_string();
        let v = self
            .views
            .get(&control)
            .ok_or_else(|| anyhow::anyhow!("unknown governance checkpoint"))?;
        if require_current {
            anyhow::ensure!(
                control == self.authority_tip(),
                "stale permissions; synchronize and retry"
            );
        }
        let m = v
            .members
            .get(&author)
            .ok_or_else(|| anyhow::anyhow!("unknown author"))?;
        anyhow::ensure!(m.status == "active", "member revoked");
        verify_member(&m.device.sign, &r.event.body, &r.event.signature)?;
        let hash = r.event.hash();
        anyhow::ensure!(
            v.publishers.contains(&r.publisher),
            "publisher not approved"
        );
        if let Some(ordering) = &v.policy.portable {
            anyhow::ensure!(
                r.publisher == ordering.primary && r.receipt.is_empty(),
                "wrong portable write backend"
            );
        } else {
            verify_authority(
                &r.publisher,
                &receipt_bytes(&self.community(), &hash),
                &r.receipt,
            )?;
        }
        let epoch = a[4].as_u64().unwrap_or(0);
        anyhow::ensure!(
            epoch == v.epoch
                && v.grants
                    .get(&epoch)
                    .is_some_and(|g| g.contains_key(&author)),
            "wrong encryption epoch"
        );
        let kind = text(&a, 5)?.to_string();
        let id = text(&a, 6)?.to_string();
        let parent = text(&a, 7)?.to_string();
        let previous = text(&a, 8)?.to_string();
        anyhow::ensure!(
            id.len() == 36 && id.chars().all(|c| c.is_ascii_hexdigit() || c == '-'),
            "invalid object id"
        );
        anyhow::ensure!(
            decode(text(&a, 10)?)?.len() == 12
                && decode(text(&a, 11)?)?.len() >= 16
                && r.event.body.len() <= 8_000_000,
            "invalid ciphertext size"
        );
        let created = a[9].as_u64().unwrap_or(0);
        anyhow::ensure!(
            created > 0 && created <= 253_402_300_799_999,
            "invalid timestamp"
        );
        let revisions: Vec<&Event> = self.events.iter().filter(|e| e.id == id).collect();
        if revisions.is_empty() {
            anyhow::ensure!(previous.is_empty(), "missing previous revision");
            match kind.as_str() {
                "board" => anyhow::ensure!(
                    m.role == "administrator" && parent.is_empty(),
                    "administrator required for board creation"
                ),
                "topic" | "reply" => {
                    let p = self
                        .events
                        .iter()
                        .find(|e| {
                            e.id == parent
                                && ((kind == "topic" && e.kind == "board")
                                    || (kind == "reply" && e.kind == "topic"))
                        })
                        .ok_or_else(|| anyhow::anyhow!("missing or invalid parent"))?;
                    let _ = p;
                }
                _ => anyhow::bail!("invalid object type"),
            }
        } else {
            let root = revisions
                .iter()
                .find(|e| e.previous.is_empty())
                .ok_or_else(|| anyhow::anyhow!("missing object root"))?;
            anyhow::ensure!(
                revisions.last().is_some_and(|e| e.hash == previous),
                "stale object revision"
            );
            let prior = revisions
                .iter()
                .find(|e| e.hash == previous)
                .ok_or_else(|| anyhow::anyhow!("missing previous revision"))?;
            anyhow::ensure!(
                prior.kind != "delete"
                    && parent == root.parent
                    && (kind == root.kind || kind == "delete"),
                "invalid edit or deleted object"
            );
            anyhow::ensure!(
                author == root.author || matches!(m.role.as_str(), "administrator" | "moderator"),
                "cannot edit another member's content"
            );
            if root.kind == "board" {
                anyhow::ensure!(
                    m.role == "administrator",
                    "administrator required for board edits"
                );
            }
        }
        Ok(Event {
            record: r.clone(),
            hash,
            author,
            kind,
            id,
            parent,
            previous,
            epoch,
            created,
            control,
        })
    }
    pub fn event(&mut self, r: Record) -> anyhow::Result<()> {
        if self
            .archive
            .records
            .iter()
            .any(|e| e.event.hash() == r.event.hash())
        {
            return Ok(());
        }
        let e = self.validate_event(&r, true)?;
        self.check_append_capacity(&r, false)?;
        anyhow::ensure!(self.events.len() < 100_000, "event capacity reached");
        let v = self.views[&self.tip].clone();
        self.archive.proof = None;
        self.tip = e.hash.clone();
        self.views.insert(self.tip.clone(), v);
        self.archive.order.push(self.tip.clone());
        self.events.push(e);
        self.archive.records.push(r);
        Ok(())
    }
    pub fn catch_up(&self, a: &Archive) -> anyhow::Result<Self> {
        anyhow::ensure!(a.genesis.hash() == self.community(), "different community");
        let n = self.archive.order.len().min(a.order.len());
        anyhow::ensure!(
            self.archive.order[..n] == a.order[..n],
            "history diverged; choose a branch or explicitly reset; chains never merge"
        );
        let verified = Self::replay(a)?;
        if a.order.len() > self.archive.order.len() {
            anyhow::ensure!(
                verified.branch() == self.branch(),
                "explicit branch reset required; reset branches never synchronize automatically"
            );
            Ok(verified)
        } else {
            Ok(self.clone())
        }
    }
}
pub fn receipt_bytes(community: &str, event: &str) -> Vec<u8> {
    serde_json::to_vec(&json!(["nightbuoy-publication", 1, community, event])).unwrap()
}
fn keep_admin(v: &View) -> anyhow::Result<()> {
    anyhow::ensure!(
        v.members
            .values()
            .any(|m| m.role == "administrator" && m.status == "active"),
        "cannot remove last administrator"
    );
    Ok(())
}
fn advance(v: &mut View, p: &Value) -> anyhow::Result<()> {
    anyhow::ensure!(p["epoch"].as_u64() == Some(v.epoch + 1), "wrong next epoch");
    v.epoch += 1;
    Ok(())
}
fn grants(v: &mut View, p: &Value) -> anyhow::Result<()> {
    let a = p
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("missing encrypted key grants"))?;
    anyhow::ensure!(a.len() <= 4000, "too many key grants");
    for g in a {
        let epoch = g["epoch"].as_u64().unwrap_or(0);
        let id = g["member"].as_str().unwrap_or("");
        let key = g["key"].as_str().unwrap_or("");
        let m = v
            .members
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("unknown key recipient"))?;
        anyhow::ensure!(
            m.status == "active"
                && epoch >= m.floor
                && epoch <= v.epoch
                && decode(key)?.len() == 384,
            "invalid key grant"
        );
        let entry = v.grants.entry(epoch).or_default();
        if let Some(old) = entry.get(id) {
            anyhow::ensure!(old == key, "key grants are immutable");
        } else {
            entry.insert(id.into(), key.into());
        }
    }
    Ok(())
}
fn all_current_keys(v: &View) -> anyhow::Result<()> {
    for (id, m) in &v.members {
        if m.status == "active" {
            anyhow::ensure!(
                v.grants.get(&v.epoch).is_some_and(|g| g.contains_key(id)),
                "missing current key grant"
            );
        }
    }
    Ok(())
}
