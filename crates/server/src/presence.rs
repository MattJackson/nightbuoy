//! Explicitly shared recent-activity hints. Never proof that a peer is online.
use crate::{
    client_crypto::Identity,
    crypto::*,
    model::{Data, Signed},
    sealed_storage::MetadataKey,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
pub const LIFETIME: u64 = 90_000;
pub const MAX_ENTRIES: usize = 128;
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis().try_into().unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pool {
    pub version: u8,
    pub entries: Vec<Signed>,
}
#[derive(Clone)]
pub struct Announcement {
    pub epoch: u64,
    pub member: String,
    pub session: String,
    pub public_key: String,
    pub issued: u64,
    pub expires: u64,
    pub signed: Signed,
}
pub struct Session {
    pub nonce: String,
    pub public_key: String,
    // Retained in this live session only; never serialize or export this object.
    _secret: p256::SecretKey,
}
impl Default for Session {
    fn default() -> Self {
        let secret = loop {
            if let Ok(key) = p256::SecretKey::from_slice(&random::<32>()) {
                break key;
            }
        };
        let point = p256::ecdsa::VerifyingKey::from(secret.public_key());
        Self {
            nonce: hex::encode(random::<32>()),
            public_key: b64(point.to_sec1_point(false).as_bytes()),
            _secret: secret,
        }
    }
}
pub fn storage(metadata: &MetadataKey, data: &Data) -> (MetadataKey, String, Vec<u8>) {
    let context = |domain| {
        serde_json::to_vec(&json!([
            domain,
            data.community(),
            data.branch(),
            data.view().epoch
        ]))
        .unwrap()
    };
    (
        metadata.derive(&context("nightbuoy-presence-key-v1")),
        metadata.locator(&context("nightbuoy-presence-path-v1")),
        context("nightbuoy-presence-frame-v1"),
    )
}
pub fn announce(
    who: &Identity,
    data: &Data,
    session: &Session,
    now: u64,
) -> anyhow::Result<Signed> {
    anyhow::ensure!(
        now <= 9_007_199_254_740_991 - LIFETIME
            && data
                .view()
                .members
                .get(&who.device.id)
                .is_some_and(|m| m.status == "active"),
        "active membership and valid local clock required"
    );
    who.signed(&json!([
        "nightbuoy-presence",
        1,
        data.community(),
        data.branch(),
        data.view().epoch,
        data.authority_tip(),
        who.device.id,
        session.nonce,
        session.public_key,
        now,
        now + LIFETIME
    ]))
}
pub fn check(signed: &Signed, data: &Data, now: u64) -> anyhow::Result<Announcement> {
    anyhow::ensure!(
        signed.body.len() <= 2000 && signed.signature.len() == 88,
        "invalid presence size"
    );
    let a: Vec<Value> = serde_json::from_str(&signed.body)?;
    anyhow::ensure!(
        a.len() == 11
            && serde_json::to_string(&a)? == signed.body
            && a[0] == "nightbuoy-presence"
            && a[1] == 1
            && a[2] == data.community()
            && a[3] == data.branch()
            && a[4] == data.view().epoch,
        "presence belongs to another forum, branch or epoch"
    );
    let id = a[6].as_str().unwrap_or("");
    let member = data
        .view()
        .members
        .get(id)
        .filter(|m| m.status == "active")
        .ok_or_else(|| anyhow::anyhow!("presence member is inactive"))?;
    let previous = data
        .views
        .get(a[5].as_str().unwrap_or(""))
        .and_then(|v| v.members.get(id))
        .filter(|m| m.status == "active" && m.device.sign == member.device.sign);
    let issued = a[9].as_u64();
    let expires = a[10].as_u64();
    let nonce = a[7].as_str().unwrap_or("");
    anyhow::ensure!(
        previous.is_some()
            && now <= 9_007_199_254_740_991 - 30_000
            && issued.is_some_and(|n| n <= now + 30_000 && n <= 9_007_199_254_740_991 - LIFETIME)
            && expires.is_some_and(|n| n == issued.unwrap() + LIFETIME && n > now)
            && nonce.len() == 64
            && nonce
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "presence expired or unauthorized"
    );
    let public_key = a[8].as_str().unwrap_or("");
    let point = decode(public_key)?;
    anyhow::ensure!(point.len() == 65 && point[0] == 4, "invalid presence key");
    p256::PublicKey::from_sec1_bytes(&point)?;
    verify_member(&member.device.sign, &signed.body, &signed.signature)?;
    Ok(Announcement {
        epoch: data.view().epoch,
        member: id.into(),
        session: nonce.into(),
        public_key: public_key.into(),
        issued: issued.unwrap(),
        expires: expires.unwrap(),
        signed: signed.clone(),
    })
}
pub fn read(pool: Pool, data: &Data, now: u64) -> anyhow::Result<Vec<Announcement>> {
    anyhow::ensure!(
        pool.version == 1 && pool.entries.len() <= MAX_ENTRIES,
        "invalid presence pool"
    );
    let mut entries: BTreeMap<(String, String), Announcement> = BTreeMap::new();
    for signed in pool.entries {
        if let Ok(item) = check(&signed, data, now) {
            let key = (item.member.clone(), item.session.clone());
            if entries.get(&key).is_none_or(|old| old.issued < item.issued) {
                entries.insert(key, item);
            }
        }
    }
    Ok(entries.into_values().collect())
}
pub fn open(
    metadata: &MetadataKey,
    data: &Data,
    frame: &[u8],
    now: u64,
) -> anyhow::Result<Vec<Announcement>> {
    crate::private_objects::validate(frame)?;
    let (key, _, context) = storage(metadata, data);
    let pool: Pool = key.open(&frame[1..], &context)?;
    read(pool, data, now)
}
pub fn seal(metadata: &MetadataKey, data: &Data, entries: Vec<Signed>) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(entries.len() <= MAX_ENTRIES, "recently-active list is full");
    let (key, _, context) = storage(metadata, data);
    let mut frame = vec![3];
    frame.extend(key.seal(
        &Pool {
            version: 1,
            entries,
        },
        &context,
    )?);
    crate::private_objects::validate(&frame)?;
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn browser_vector_matches_native_scope_signatures_and_frames() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/presence.json")).unwrap();
        let data =
            Data::replay(&serde_json::from_value(fixture["archive"].clone()).unwrap()).unwrap();
        let key = MetadataKey::from_base64(fixture["metadata"].as_str().unwrap()).unwrap();
        let now = fixture["now"].as_u64().unwrap();
        let frame = decode(fixture["frame"].as_str().unwrap()).unwrap();
        let (_, locator, _) = storage(&key, &data);
        assert_eq!(locator, fixture["locator"]);
        let entries = open(&key, &data, &frame, now).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            serde_json::to_value(&entries[0].signed).unwrap(),
            fixture["signed"]
        );
        assert!(
            open(&key, &data, &frame, now + LIFETIME)
                .unwrap()
                .is_empty()
        );
        assert!(open(&MetadataKey::from_epoch(&[3; 32]), &data, &frame, now).is_err());
        let native = seal(&key, &data, vec![entries[0].signed.clone()]).unwrap();
        assert_eq!(open(&key, &data, &native, now).unwrap().len(), 1);
        let mut revoked = data.clone();
        let current = revoked.tip.clone();
        std::sync::Arc::make_mut(revoked.views.get_mut(&current).unwrap())
            .members
            .get_mut(&entries[0].member)
            .unwrap()
            .status = "revoked".into();
        assert!(check(&entries[0].signed, &revoked, now).is_err());
        assert!(
            read(
                Pool {
                    version: 1,
                    entries: vec![entries[0].signed.clone(); MAX_ENTRIES + 1]
                },
                &data,
                now
            )
            .is_err()
        );
        let invisible = crate::client_presence::PresenceState::default();
        assert!(invisible.session.is_none());
        assert!(invisible.entries.is_empty());
    }
}
