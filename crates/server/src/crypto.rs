use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256Key, signature::Verifier};
use rand::RngCore;
use sha2::{Digest, Sha256};

pub fn random<const N: usize>() -> [u8; N] {
    let mut b = [0; N];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}
pub fn token() -> String {
    hex::encode(random::<32>())
}
pub fn b64(b: impl AsRef<[u8]>) -> String {
    STANDARD.encode(b)
}
pub fn decode(s: &str) -> anyhow::Result<Vec<u8>> {
    Ok(STANDARD.decode(s)?)
}
pub fn hash(b: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(b))
}
pub fn keyed(key: &[u8], b: &[u8]) -> String {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    m.update(b);
    hex::encode(m.finalize().into_bytes())
}
pub fn seal(key: &[u8], bytes: &[u8], aad: &[u8]) -> anyhow::Result<String> {
    let iv = random::<12>();
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| anyhow::anyhow!("invalid key"))?;
    let mut out = iv.to_vec();
    out.extend(
        cipher
            .encrypt(&iv.into(), Payload { msg: bytes, aad })
            .map_err(|_| anyhow::anyhow!("encryption failed"))?,
    );
    Ok(b64(out))
}
pub fn verify_member(key: &str, body: &str, sig: &str) -> anyhow::Result<()> {
    let key = P256Key::from_sec1_bytes(&decode(key)?)?;
    key.verify(body.as_bytes(), &P256Signature::from_slice(&decode(sig)?)?)?;
    Ok(())
}
pub fn authority(key: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(key)
}
pub fn sign(key: &[u8; 32], bytes: &[u8]) -> String {
    b64(authority(key).sign(bytes).to_bytes())
}
pub fn verify_authority(key: &str, bytes: &[u8], sig: &str) -> anyhow::Result<()> {
    let k: [u8; 32] = decode(key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("key length"))?;
    let s = Signature::from_slice(&decode(sig)?)?;
    VerifyingKey::from_bytes(&k)?.verify_strict(bytes, &s)?;
    Ok(())
}

pub fn unseal(key: &[u8], sealed: &str, aad: &[u8]) -> anyhow::Result<Vec<u8>> {
    let b = decode(sealed)?;
    anyhow::ensure!(b.len() >= 28, "invalid sealed record");
    let iv: [u8; 12] = b[..12].try_into()?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| anyhow::anyhow!("invalid key"))?;
    cipher
        .decrypt(&iv.into(), Payload { msg: &b[12..], aad })
        .map_err(|_| anyhow::anyhow!("identity record authentication failed"))
}
