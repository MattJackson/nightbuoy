//! Member-signed append certificates for a provider-CAS branch, not Byzantine consensus.
use crate::{crypto::*, model::*};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Ordering {
    pub version: u8,
    pub primary: String,
}
impl Ordering {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.version == 1 && decode(&self.primary)?.len() == 32,
            "invalid portable ordering"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<Box<Archive>>,
    pub headers: Vec<Signed>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Item {
    Genesis(Signed),
    Control(Signed),
    Event(Record),
}
pub fn canonical<T: Serialize + ?Sized>(value: &T) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(&serde_json::to_value(value)?)?)
}
pub fn digest<T: Serialize>(value: &T) -> anyhow::Result<String> {
    Ok(hash(canonical(value)?))
}
impl Item {
    pub fn signed(&self) -> &Signed {
        match self {
            Self::Genesis(s) | Self::Control(s) => s,
            Self::Event(r) => &r.event,
        }
    }
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Genesis(_) => "genesis",
            Self::Control(_) => "control",
            Self::Event(_) => "event",
        }
    }
    pub fn actor(&self) -> anyhow::Result<String> {
        let a: Value = serde_json::from_str(&self.signed().body)?;
        Ok(match self {
            Self::Genesis(_) => a[2]["id"].as_str(),
            Self::Control(_) => a[4].as_str(),
            Self::Event(_) => a[2].as_str(),
        }
        .ok_or_else(|| anyhow::anyhow!("invalid transaction author"))?
        .into())
    }
    pub fn apply(&self, data: &mut Option<Data>) -> anyhow::Result<()> {
        match self {
            Self::Genesis(g) => {
                anyhow::ensure!(data.is_none(), "community already initialized");
                *data = Some(Data::create(g.clone())?);
            }
            Self::Control(s) => data
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("community not initialized"))?
                .control(s.clone())?,
            Self::Event(r) => data
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("community not initialized"))?
                .event(r.clone())?,
        }
        Ok(())
    }
}
pub fn items(a: &Archive) -> anyhow::Result<Vec<Item>> {
    let mut out = vec![Item::Genesis(a.genesis.clone())];
    for id in &a.order {
        if let Some(s) = a.controls.iter().find(|s| s.hash() == *id) {
            out.push(Item::Control(s.clone()));
        } else if let Some(r) = a.records.iter().find(|r| r.event.hash() == *id) {
            out.push(Item::Event(r.clone()));
        } else {
            anyhow::bail!("missing transaction");
        }
    }
    Ok(out)
}
pub fn header_body(
    data: &Data,
    item: &Item,
    parent: &str,
    sequence: usize,
) -> anyhow::Result<String> {
    let p = data
        .view()
        .policy
        .portable
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("explicit portable migration required"))?;
    Ok(serde_json::to_string(&json!([
        "nightbuoy-storage-head",
        1,
        data.community(),
        data.branch(),
        p.primary,
        sequence,
        parent,
        digest(item)?,
        item.kind(),
        item.signed().hash(),
        item.actor()?
    ]))?)
}
pub fn head(a: &Archive) -> anyhow::Result<String> {
    digest(
        a.portable_proof
            .as_ref()
            .and_then(|p| p.headers.last())
            .ok_or_else(|| anyhow::anyhow!("portable confirmation pending"))?,
    )
}
pub fn verify(data: &Data) -> anyhow::Result<()> {
    let cert = data
        .archive
        .portable_proof
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("portable confirmation pending"))?;
    anyhow::ensure!(
        canonical(&data.archive)?.len() <= MAX_ARCHIVE_BYTES,
        "archive capacity exceeded"
    );
    let all = items(&data.archive)?;
    let (mut state, start, mut parent) = if let Some(anchor) = &cert.anchor {
        anyhow::ensure!(
            anchor.portable_proof.is_none(),
            "nested migration anchors forbidden"
        );
        let old = Data::replay(anchor)?;
        anyhow::ensure!(
            old.view().policy.consensus.is_some() && old.view().policy.portable.is_none(),
            "migration anchor must retain verified legacy trust"
        );
        let old_items = items(anchor)?;
        anyhow::ensure!(
            all.len() > old_items.len()
                && canonical(&all[..old_items.len()])? == canonical(&old_items)?,
            "migration ancestry changed"
        );
        let next = &all[old_items.len()];
        let fields: Value = serde_json::from_str(&next.signed().body)?;
        anyhow::ensure!(
            matches!(next, Item::Control(_)) && fields[6] == "reconstitute",
            "migration requires an explicit branch reset"
        );
        (
            Some(old),
            old_items.len(),
            digest(&json!({"kind":"legacy_anchor","data":anchor}))?,
        )
    } else {
        (None, 0, String::new())
    };
    anyhow::ensure!(
        cert.headers.len() == all.len() - start,
        "incomplete portable certificate"
    );
    for (sequence, (item, signed)) in all
        .iter()
        .enumerate()
        .skip(start)
        .zip(cert.headers.iter())
        .map(|((n, i), s)| (n, (i, s)))
    {
        let actor = item.actor()?;
        let key = if let Some(d) = &state {
            let m = d
                .view()
                .members
                .get(&actor)
                .ok_or_else(|| anyhow::anyhow!("unknown certificate author"))?;
            anyhow::ensure!(m.status == "active", "revoked certificate author");
            m.device.sign.clone()
        } else {
            let root: Value = serde_json::from_str(&item.signed().body)?;
            root[2]["sign"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("invalid genesis author"))?
                .into()
        };
        verify_member(&key, &signed.body, &signed.signature)?;
        let old_count = state
            .as_ref()
            .map(|d| d.archive.order.len() + 1)
            .unwrap_or(0);
        item.apply(&mut state)?;
        let d = state.as_ref().unwrap();
        anyhow::ensure!(
            d.archive.order.len() + 1 == old_count + 1,
            "duplicate portable transaction"
        );
        anyhow::ensure!(
            signed.body == header_body(d, item, &parent, sequence)?,
            "portable certificate context changed"
        );
        parent = digest(signed)?;
    }
    let rebuilt = state.ok_or_else(|| anyhow::anyhow!("empty portable certificate"))?;
    anyhow::ensure!(
        rebuilt.core_bytes() == data.core_bytes(),
        "portable certificate inventory changed"
    );
    Ok(())
}
