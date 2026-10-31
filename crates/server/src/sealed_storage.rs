//! Opaque binary storage frames. All forum fields live inside authenticated ciphertext.
use crate::{crypto::*, model::MAX_ARCHIVE_BYTES};
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use serde::{Serialize, de::DeserializeOwned};
pub const BLOCK: usize = 4096;
pub const MAX_FRAME: usize = MAX_ARCHIVE_BYTES + 2 * 1024 * 1024;
#[derive(Clone)]
pub struct MetadataKey([u8; 32]);
impl Drop for MetadataKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}
impl MetadataKey {
    /// Separate keys/locators for bounded client state outside forum history.
    pub fn derive(&self, context: &[u8]) -> Self {
        Self(
            hex::decode(keyed(&self.0, context))
                .unwrap()
                .try_into()
                .unwrap(),
        )
    }
    pub fn locator(&self, context: &[u8]) -> String {
        keyed(&self.0, context)
    }
    pub fn same(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        bool::from(self.0.ct_eq(&other.0))
    }

    pub fn from_base64(value: &str) -> anyhow::Result<Self> {
        let key = decode(value)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("metadata key must be 32 random bytes"))?;
        Ok(Self(key))
    }
    pub fn from_epoch(key: &[u8; 32]) -> Self {
        Self(
            hex::decode(keyed(key, b"nightbuoy-metadata-v2"))
                .unwrap()
                .try_into()
                .unwrap(),
        )
    }
    pub fn seal<T: Serialize>(&self, value: &T, context: &[u8]) -> anyhow::Result<Vec<u8>> {
        let json = serde_json::to_vec(&serde_json::to_value(value)?)?;
        anyhow::ensure!(
            json.len() <= MAX_ARCHIVE_BYTES,
            "encrypted payload capacity exceeded"
        );
        let padded = (json.len() + 4).div_ceil(BLOCK) * BLOCK;
        let mut plain = vec![0; padded];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut plain);
        plain[..4].copy_from_slice(&(json.len() as u32).to_be_bytes());
        plain[4..4 + json.len()].copy_from_slice(&json);
        let nonce = random::<12>();
        let cipher = Aes256Gcm::new_from_slice(&self.0)
            .map_err(|_| anyhow::anyhow!("invalid metadata key"))?;
        let result = cipher
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: &plain,
                    aad: context,
                },
            )
            .map_err(|_| anyhow::anyhow!("metadata encryption failed"));
        plain.fill(0);
        let mut frame = nonce.to_vec();
        frame.extend(result?);
        Ok(frame)
    }
    pub fn open<T: DeserializeOwned>(&self, frame: &[u8], context: &[u8]) -> anyhow::Result<T> {
        anyhow::ensure!(
            frame.len() >= 28 + BLOCK
                && frame.len() <= MAX_FRAME
                && (frame.len() - 28).is_multiple_of(BLOCK),
            "invalid opaque frame"
        );
        let nonce: [u8; 12] = frame[..12].try_into()?;
        let cipher = Aes256Gcm::new_from_slice(&self.0)
            .map_err(|_| anyhow::anyhow!("invalid metadata key"))?;
        let mut plain = cipher
            .decrypt(
                &nonce.into(),
                Payload {
                    msg: &frame[12..],
                    aad: context,
                },
            )
            .map_err(|_| anyhow::anyhow!("access key does not unlock this encrypted forum"))?;
        let result = (|| {
            let length = u32::from_be_bytes(plain[..4].try_into()?) as usize;
            anyhow::ensure!(
                length <= MAX_ARCHIVE_BYTES && length <= plain.len() - 4,
                "invalid encrypted payload length"
            );
            Ok(serde_json::from_slice(&plain[4..4 + length])?)
        })();
        plain.fill(0);
        result
    }
}
/// Recipient ciphertexts have no identity labels; opaque framing is bounded and padded.
pub fn head_frame<T: Serialize>(
    key: &MetadataKey,
    wrapped: &[String],
    ephemeral: &str,
    value: &T,
    context: &[u8],
) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        !wrapped.is_empty() && wrapped.len() <= 4000,
        "invalid anonymous grant count"
    );
    let slots = wrapped.len().next_power_of_two().max(8);
    let mut grants = wrapped
        .iter()
        .map(|s| {
            let b = decode(s)?;
            anyhow::ensure!(b.len() == 60, "invalid anonymous grant");
            Ok(b)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    while grants.len() < slots {
        let index = grants.len();
        let seed = keyed(&key.0, b"nightbuoy-discovery-cover-v2");
        let first = hex::decode(keyed(
            seed.as_bytes(),
            format!("{ephemeral}:{index}:0").as_bytes(),
        ))?;
        let second = hex::decode(keyed(
            seed.as_bytes(),
            format!("{ephemeral}:{index}:1").as_bytes(),
        ))?;
        let mut cover = first;
        cover.extend(&second[..28]);
        grants.push(cover);
    }
    use rand::seq::SliceRandom;
    grants.shuffle(&mut rand::rngs::OsRng);
    let point = decode(ephemeral)?;
    anyhow::ensure!(point.len() == 65, "invalid ephemeral discovery key");
    p256::PublicKey::from_sec1_bytes(&point)?;
    let mut out = vec![2];
    out.extend(point);
    out.extend((slots as u32).to_be_bytes());
    for grant in grants {
        out.extend(grant);
    }
    let mut aad = context.to_vec();
    aad.extend(&out);
    out.extend(key.seal(value, &aad)?);
    anyhow::ensure!(out.len() <= MAX_FRAME, "head frame too large");
    Ok(out)
}
pub fn open_head<T: DeserializeOwned>(
    key: &MetadataKey,
    frame: &[u8],
    context: &[u8],
) -> anyhow::Result<T> {
    let (_, _, cipher) = split_head(frame)?;
    let prefix = frame.len() - cipher.len();
    let mut aad = context.to_vec();
    aad.extend(&frame[..prefix]);
    key.open(cipher, &aad)
}
pub fn split_head(frame: &[u8]) -> anyhow::Result<(String, Vec<String>, &[u8])> {
    anyhow::ensure!(
        frame.len() >= 70 && frame.len() <= MAX_FRAME && frame[0] == 2,
        "legacy plaintext storage requires explicit private migration"
    );
    let slots = u32::from_be_bytes(frame[66..70].try_into()?) as usize;
    anyhow::ensure!(
        (8..=4096).contains(&slots) && slots.is_power_of_two(),
        "invalid anonymous grant framing"
    );
    let start = 70 + slots * 60;
    anyhow::ensure!(
        start + 28 + BLOCK <= frame.len(),
        "truncated encrypted head"
    );
    Ok((
        b64(&frame[1..66]),
        frame[70..start]
            .as_chunks::<60>()
            .0
            .iter()
            .map(b64)
            .collect(),
        &frame[start..],
    ))
}
pub fn context(namespace: &str, purpose: &str) -> Vec<u8> {
    format!("nightbuoy-opaque-v2:{namespace}:{purpose}").into_bytes()
}
pub fn head_path() -> String {
    hash(b"nightbuoy-opaque-head-v2")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    fn fixture() -> (MetadataKey, String, Vec<String>) {
        let secret = p256::SecretKey::from_slice(&random::<32>()).unwrap();
        let point = p256::ecdsa::VerifyingKey::from(secret.public_key());
        (
            MetadataKey::from_epoch(&random::<32>()),
            b64(point.to_sec1_point(false).as_bytes()),
            vec![b64(random::<60>()), b64(random::<60>())],
        )
    }
    #[test]
    fn frames_authenticate_scope_and_every_header_byte() {
        let (key, point, grants) = fixture();
        let ctx = context("opaque-directory", "head");
        let value =
            json!({"name":"private forum name", "member":"private identity", "timestamp":123});
        let frame = head_frame(&key, &grants, &point, &value, &ctx).unwrap();
        assert!(!frame.windows(18).any(|w| w == b"private forum name"));
        assert_eq!(open_head::<Value>(&key, &frame, &ctx).unwrap(), value);
        assert!(open_head::<Value>(&key, &frame, &context("other", "head")).is_err());
        assert!(
            open_head::<Value>(&MetadataKey::from_epoch(&random::<32>()), &frame, &ctx).is_err()
        );
        // Prefix, recipient grants, nonce, ciphertext and tag are all authenticated.
        for offset in [1, 66, 70, 130, 549, 550, frame.len() - 1] {
            let mut tampered = frame.clone();
            tampered[offset] ^= 1;
            assert!(
                open_head::<Value>(&key, &tampered, &ctx).is_err(),
                "offset {offset}"
            );
        }
        for length in [0, 1, 69, 70, 550, frame.len() - 1] {
            assert!(open_head::<Value>(&key, &frame[..length], &ctx).is_err());
        }
    }
    #[test]
    fn stable_cover_does_not_reveal_recipients_by_intersection() {
        let (key, point, grants) = fixture();
        let a = head_frame(&key, &grants, &point, &json!({"revision":1}), b"head").unwrap();
        let b = head_frame(&key, &grants, &point, &json!({"revision":2}), b"head").unwrap();
        let (_, mut sa, _) = split_head(&a).unwrap();
        let (_, mut sb, _) = split_head(&b).unwrap();
        sa.sort();
        sb.sort();
        assert_eq!(sa, sb);
        assert_eq!(sa.len(), 8);
        assert_ne!(a, b);
        let newer = head_frame(
            &MetadataKey::from_epoch(&random::<32>()),
            &grants,
            &point,
            &json!({}),
            b"head",
        )
        .unwrap();
        let (_, new_slots, _) = split_head(&newer).unwrap();
        assert_eq!(
            sa.iter().filter(|s| new_slots.contains(s)).count(),
            grants.len()
        );
        // Changes of epoch/grant revision remain observable; cover only prevents per-post counting.
    }
}
