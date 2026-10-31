//! Native client crypto interoperable with browser identities. Never used by provider servers.
use crate::{
    crypto::*,
    model::{Device, Signed},
    sealed_storage::MetadataKey,
};
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der};
use aws_lc_rs::rsa::{
    KeySize, OAEP_SHA256_MGF1SHA256, OaepPrivateDecryptingKey, OaepPublicEncryptingKey,
    PrivateDecryptingKey, PublicEncryptingKey,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
#[derive(Clone)]
pub struct Identity {
    pub device: Device,
    sign: SigningKey,
    discover: Option<p256::SecretKey>,
    wrap: std::sync::Arc<OaepPrivateDecryptingKey>,
    pub private: Value,
    pub community: String,
    pub checkpoint: String,
    pub metadata: Option<MetadataKey>,
}
#[derive(Serialize, Deserialize)]
struct OrderedDevice {
    id: String,
    sign: String,
    wrap: indexmap::IndexMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    discover: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct Vault {
    version: u8,
    community: String,
    device: OrderedDevice,
    salt: String,
    iv: String,
    cipher: String,
    checkpoint: String,
}
fn url_decode(v: &str) -> anyhow::Result<Vec<u8>> {
    Ok(URL_SAFE_NO_PAD.decode(v)?)
}
fn aes(key: &[u8]) -> anyhow::Result<Aes256Gcm> {
    Aes256Gcm::new_from_slice(key).map_err(|_| anyhow::anyhow!("invalid encryption key"))
}
fn vault_key(password: &str, salt: &[u8]) -> anyhow::Result<[u8; 32]> {
    let params = argon2::Params::new(65536, 3, 4, Some(32))
        .map_err(|_| anyhow::anyhow!("invalid Argon2 parameters"))?;
    let kdf = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    kdf.hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|_| anyhow::anyhow!("identity key derivation failed"))?;
    Ok(out)
}
impl Identity {
    pub fn generate() -> anyhow::Result<Self> {
        let sign_secret = new_curve_secret();
        let sign = SigningKey::from_slice(&sign_secret.to_bytes())?;
        let discover = new_curve_secret();
        let rsa = PrivateDecryptingKey::generate(KeySize::Rsa3072)
            .map_err(|_| anyhow::anyhow!("identity key generation failed"))?;
        let public_der: PublicKeyX509Der<'static> = rsa
            .public_key()
            .as_der()
            .map_err(|_| anyhow::anyhow!("RSA public export failed"))?;
        let public_wrap = rsa_public_jwk(public_der.as_ref())?;
        let private_der: Pkcs8V1Der<'static> = rsa
            .as_der()
            .map_err(|_| anyhow::anyhow!("RSA private export failed"))?;
        let sign_public = b64(sign.verifying_key().to_sec1_point(false).as_bytes());
        let discovery_public = p256::ecdsa::VerifyingKey::from(discover.public_key());
        let device = Device {
            id: hash(decode(&sign_public)?),
            sign: sign_public,
            wrap: public_wrap,
            discover: Some(b64(discovery_public.to_sec1_point(false).as_bytes())),
        };
        device.validate()?;
        let private = json!({"sign":curve_jwk(&sign_secret,"sign"),"discover":curve_jwk(&discover,"deriveBits"),"wrap_pkcs8":b64(private_der.as_ref())});
        Ok(Self {
            device,
            sign,
            discover: Some(discover),
            wrap: std::sync::Arc::new(
                OaepPrivateDecryptingKey::new(rsa)
                    .map_err(|_| anyhow::anyhow!("RSA key initialization failed"))?,
            ),
            private,
            community: String::new(),
            checkpoint: String::new(),
            metadata: None,
        })
    }
    pub fn lock(
        &self,
        password: &str,
        community: &str,
        checkpoint: &str,
    ) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(
            (20..=1024).contains(&password.encode_utf16().count()),
            "use a unique passphrase of 20–1024 characters"
        );
        let device: OrderedDevice = serde_json::from_value(serde_json::to_value(&self.device)?)?;
        let salt = random::<16>();
        let nonce = random::<12>();
        let mut key = vault_key(password, &salt)?;
        let aad = serde_json::to_vec(&("nightbuoy-vault", 2, community, &device, checkpoint))?;
        let mut plain = serde_json::to_vec(&self.private)?;
        let result = aes(&key)?.encrypt(
            &nonce.into(),
            Payload {
                msg: &plain,
                aad: &aad,
            },
        );
        key.fill(0);
        plain.fill(0);
        let vault = Vault {
            version: 2,
            community: community.into(),
            device,
            salt: b64(salt),
            iv: b64(nonce),
            cipher: b64(result.map_err(|_| anyhow::anyhow!("identity encryption failed"))?),
            checkpoint: checkpoint.into(),
        };
        Ok(serde_json::to_vec(&vault)?)
    }
    fn private_key(
        &self,
        community: &str,
        purpose: &str,
    ) -> anyhow::Result<(MetadataKey, Vec<u8>)> {
        let context = serde_json::to_vec(&json!(["nightbuoy-private-v1", purpose, community]))?;
        let key =
            MetadataKey::from_base64(&b64(hex::decode(keyed(&self.sign.to_bytes(), &context))?))?;
        Ok((key, context))
    }
    pub fn seal_private<T: Serialize>(
        &self,
        community: &str,
        purpose: &str,
        value: &T,
    ) -> anyhow::Result<Vec<u8>> {
        let (key, context) = self.private_key(community, purpose)?;
        let mut frame = vec![3];
        frame.extend(key.seal(value, &context)?);
        Ok(frame)
    }
    pub fn private_locator(&self, community: &str, purpose: &str) -> anyhow::Result<String> {
        Ok(keyed(
            &self.sign.to_bytes(),
            &serde_json::to_vec(&json!(["nightbuoy-private-path-v1", purpose, community]))?,
        ))
    }
    pub fn open_private<T: serde::de::DeserializeOwned>(
        &self,
        community: &str,
        purpose: &str,
        frame: &[u8],
    ) -> anyhow::Result<T> {
        anyhow::ensure!(frame.first() == Some(&3), "invalid private export format");
        let (key, context) = self.private_key(community, purpose)?;
        key.open(&frame[1..], &context)
    }
    pub fn unlock(bytes: &[u8], password: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(bytes.len() <= 30000, "identity file too large");
        let vault: Vault = serde_json::from_slice(bytes)?;
        anyhow::ensure!(
            vault.version == 2
                && decode(&vault.salt)?.len() == 16
                && decode(&vault.iv)?.len() == 12
                && vault.cipher.len() <= 20000,
            "invalid identity envelope"
        );
        let mut derived = vault_key(password, &decode(&vault.salt)?)?;
        let aad = serde_json::to_vec(&(
            "nightbuoy-vault",
            2,
            &vault.community,
            &vault.device,
            &vault.checkpoint,
        ))?;
        let nonce: [u8; 12] = decode(&vault.iv)?.try_into().unwrap();
        let decrypted = aes(&derived)?.decrypt(
            &nonce.into(),
            Payload {
                msg: &decode(&vault.cipher)?,
                aad: &aad,
            },
        );
        derived.fill(0);
        let mut plain = decrypted
            .map_err(|_| anyhow::anyhow!("Incorrect passphrase or damaged recovery file"))?;
        let parsed = serde_json::from_slice(&plain);
        plain.fill(0);
        let private: Value = parsed?;
        let device: Device = serde_json::from_value(serde_json::to_value(&vault.device)?)?;
        device.validate()?;
        let sign = SigningKey::from_slice(&url_decode(
            private["sign"]["d"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("missing signing key"))?,
        )?)?;
        anyhow::ensure!(
            b64(sign.verifying_key().to_sec1_point(false).as_bytes()) == device.sign,
            "recovery signing-key mismatch"
        );
        let discover = private
            .get("discover")
            .map(|d| -> anyhow::Result<_> {
                Ok(p256::SecretKey::from_slice(&url_decode(
                    d["d"].as_str().unwrap_or(""),
                )?)?)
            })
            .transpose()?;
        anyhow::ensure!(
            discover.is_some() == device.discover.is_some(),
            "recovery discovery-key mismatch"
        );
        if let Some(secret) = &discover {
            let public = p256::ecdsa::VerifyingKey::from(secret.public_key());
            anyhow::ensure!(
                Some(b64(public.to_sec1_point(false).as_bytes())) == device.discover,
                "recovery discovery-key mismatch"
            );
        }
        let mut der = if let Some(der) = private["wrap_pkcs8"].as_str() {
            decode(der)?
        } else {
            rsa_private_der(&private["wrap"])?
        };
        let rsa = PrivateDecryptingKey::from_pkcs8(&der)
            .map_err(|_| anyhow::anyhow!("invalid RSA recovery key"));
        der.fill(0);
        let rsa = rsa?;
        anyhow::ensure!(
            rsa.key_size_bits() == 3072,
            "RSA-3072 recovery key required"
        );
        let wrap = OaepPrivateDecryptingKey::new(rsa)
            .map_err(|_| anyhow::anyhow!("invalid RSA-OAEP key"))?;
        let metadata = private["access"]["metadata"]
            .as_str()
            .map(MetadataKey::from_base64)
            .transpose()?;
        let identity = Self {
            device,
            sign,
            discover,
            wrap: std::sync::Arc::new(wrap),
            private,
            community: vault.community,
            checkpoint: vault.checkpoint,
            metadata,
        };
        let sample = random::<32>();
        let wrapped = wrap_epoch(&identity.device, &sample)?;
        anyhow::ensure!(
            identity.open_epoch(&wrapped)? == sample,
            "recovery wrapping-key mismatch"
        );
        Ok(identity)
    }
    pub fn signed(&self, value: &Value) -> anyhow::Result<Signed> {
        let body = serde_json::to_string(value)?;
        let signature: Signature = self.sign.sign(body.as_bytes());
        Ok(Signed {
            body,
            signature: b64(signature.to_bytes()),
        })
    }
    pub fn open_epoch(&self, wrapped: &str) -> anyhow::Result<[u8; 32]> {
        let ciphertext = decode(wrapped)?;
        let mut plain = vec![0u8; self.wrap.min_output_size()];
        let decoded = self
            .wrap
            .decrypt(&OAEP_SHA256_MGF1SHA256, &ciphertext, &mut plain, None)
            .map_err(|_| anyhow::anyhow!("epoch grant does not unlock"))?;
        let result = decoded
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid epoch key length"));
        plain.fill(0);
        result
    }
    pub fn open_discovery(&self, ephemeral: &str, slots: &[String]) -> anyhow::Result<[u8; 32]> {
        let secret = self
            .discover
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("identity needs a discovery-key upgrade"))?;
        let point = decode(ephemeral)?;
        let peer = p256::PublicKey::from_sec1_bytes(&point)?;
        let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
        let recipient = decode(self.device.discover.as_deref().unwrap_or(""))?;
        let mut salt = point;
        salt.extend(&recipient);
        let salt = Sha256::digest(&salt);
        let hkdf = hkdf::Hkdf::<Sha256>::new(Some(&salt), shared.raw_secret_bytes());
        let mut key = [0u8; 32];
        hkdf.expand(b"nightbuoy-anonymous-grant-v2", &mut key)
            .map_err(|_| anyhow::anyhow!("discovery key derivation failed"))?;
        let cipher = aes(&key)?;
        key.fill(0);
        for slot in slots {
            let bytes = decode(slot)?;
            if bytes.len() != 60 {
                continue;
            }
            let nonce: [u8; 12] = bytes[..12].try_into()?;
            if let Ok(mut plain) = cipher.decrypt(
                &nonce.into(),
                Payload {
                    msg: &bytes[12..],
                    aad: b"nightbuoy-anonymous-grant-v2",
                },
            ) {
                let result = plain
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid anonymous epoch grant"));
                plain.fill(0);
                return result;
            }
        }
        anyhow::bail!("No forum key grant for this identity")
    }
}
pub fn wrap_epoch(device: &Device, key: &[u8; 32]) -> anyhow::Result<String> {
    let der = rsa_public_der(&device.wrap)?;
    let public = PublicEncryptingKey::from_der(&der)
        .map_err(|_| anyhow::anyhow!("invalid RSA public key"))?;
    let public = OaepPublicEncryptingKey::new(public)
        .map_err(|_| anyhow::anyhow!("invalid RSA-OAEP public key"))?;
    let mut encrypted = vec![0; public.ciphertext_size()];
    let result = public
        .encrypt(&OAEP_SHA256_MGF1SHA256, key, &mut encrypted, None)
        .map_err(|_| anyhow::anyhow!("RSA key wrapping failed"))?;
    Ok(b64(result))
}
pub fn encrypt_event(
    identity: &Identity,
    key: &[u8; 32],
    fields: Value,
    payload: &Value,
) -> anyhow::Result<Signed> {
    let mut a = fields
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("invalid event fields"))?
        .clone();
    anyhow::ensure!(a.len() == 10, "invalid event fields");
    let nonce = random::<12>();
    let ciphertext = aes(key)?
        .encrypt(
            &nonce.into(),
            Payload {
                msg: &serde_json::to_vec(payload)?,
                aad: &serde_json::to_vec(&a)?,
            },
        )
        .map_err(|_| anyhow::anyhow!("content encryption failed"))?;
    a.push(json!(b64(nonce)));
    a.push(json!(b64(ciphertext)));
    identity.signed(&json!(a))
}
pub fn decrypt_event(key: &[u8; 32], event: &Signed) -> anyhow::Result<Value> {
    let a: Vec<Value> = serde_json::from_str(&event.body)?;
    anyhow::ensure!(a.len() == 12, "invalid event record");
    let nonce: [u8; 12] = decode(a[10].as_str().unwrap_or(""))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid event nonce"))?;
    let mut plain = aes(key)?
        .decrypt(
            &nonce.into(),
            Payload {
                msg: &decode(a[11].as_str().unwrap_or(""))?,
                aad: &serde_json::to_vec(&a[..10])?,
            },
        )
        .map_err(|_| anyhow::anyhow!("content authentication failed"))?;
    let result = serde_json::from_slice(&plain);
    plain.fill(0);
    Ok(result?)
}
fn new_curve_secret() -> p256::SecretKey {
    loop {
        if let Ok(key) = p256::SecretKey::from_slice(&random::<32>()) {
            return key;
        }
    }
}
fn curve_jwk(secret: &p256::SecretKey, operation: &str) -> Value {
    let public = p256::ecdsa::VerifyingKey::from(secret.public_key());
    let point = public.to_sec1_point(false);
    json!({"kty":"EC","crv":"P-256","x":URL_SAFE_NO_PAD.encode(&point.as_bytes()[1..33]),"y":URL_SAFE_NO_PAD.encode(&point.as_bytes()[33..65]),"d":URL_SAFE_NO_PAD.encode(secret.to_bytes()),"ext":true,"key_ops":[operation]})
}
// Only inspect public ASN.1 generated and validated by AWS-LC; arithmetic stays in the library.
fn take_der<'a>(input: &mut &'a [u8], tag: u8) -> anyhow::Result<&'a [u8]> {
    anyhow::ensure!(
        input.len() >= 2 && input[0] == tag,
        "invalid generated RSA public encoding"
    );
    let first = input[1];
    let (length, prefix) = if first < 128 {
        (usize::from(first), 2)
    } else {
        let bytes = usize::from(first & 127);
        anyhow::ensure!(
            bytes > 0 && bytes <= 4 && input.len() >= 2 + bytes,
            "invalid DER length"
        );
        let mut length = 0usize;
        for b in &input[2..2 + bytes] {
            length = (length << 8) | usize::from(*b);
        }
        (length, 2 + bytes)
    };
    anyhow::ensure!(
        length <= 4096 && input.len() >= prefix + length,
        "truncated RSA public encoding"
    );
    let value = &input[prefix..prefix + length];
    *input = &input[prefix + length..];
    Ok(value)
}
fn rsa_public_jwk(der: &[u8]) -> anyhow::Result<Value> {
    let mut outer = der;
    let mut sequence = take_der(&mut outer, 0x30)?;
    anyhow::ensure!(outer.is_empty(), "RSA public trailing data");
    let algorithm = take_der(&mut sequence, 0x30)?;
    anyhow::ensure!(
        algorithm == &rsa_algorithm()[2..],
        "unexpected RSA public algorithm"
    );
    let bits = take_der(&mut sequence, 3)?;
    anyhow::ensure!(
        sequence.is_empty() && bits.first() == Some(&0),
        "invalid RSA public bits"
    );
    let mut bits = &bits[1..];
    let mut public = take_der(&mut bits, 0x30)?;
    anyhow::ensure!(bits.is_empty(), "RSA public trailing bits");
    let modulus = take_der(&mut public, 2)?;
    let exponent = take_der(&mut public, 2)?;
    anyhow::ensure!(public.is_empty(), "RSA public trailing integers");
    let modulus = modulus.strip_prefix(&[0]).unwrap_or(modulus);
    let exponent = exponent.strip_prefix(&[0]).unwrap_or(exponent);
    Ok(
        json!({"kty":"RSA","n":URL_SAFE_NO_PAD.encode(modulus),"e":URL_SAFE_NO_PAD.encode(exponent),"alg":"RSA-OAEP-256","ext":true,"key_ops":["encrypt"]}),
    )
}
/// Explicit exports never overwrite an existing recovery file or follow an existing symlink.
pub fn write_private_file(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    anyhow::ensure!(file.metadata()?.is_file(), "exports require a regular file");
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

// DER serialization only: AWS-LC parses and validates all RSA arithmetic/key material.
fn der(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if bytes.len() < 128 {
        out.push(bytes.len() as u8);
    } else {
        let len = bytes.len().to_be_bytes();
        let first = len.iter().position(|b| *b != 0).unwrap();
        out.push(0x80 | (len.len() - first) as u8);
        out.extend(&len[first..]);
    }
    out.extend(bytes);
    out
}
fn integer(bytes: &[u8]) -> Vec<u8> {
    let first = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    let bytes = &bytes[first..];
    let mut unsigned = vec![];
    if bytes.first().is_none_or(|b| b & 0x80 != 0) {
        unsigned.push(0);
    }
    unsigned.extend(bytes);
    der(2, &unsigned)
}
fn rsa_algorithm() -> Vec<u8> {
    vec![
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ]
}
fn jwk_integer(jwk: &Value, name: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = url_decode(
        jwk[name]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing RSA key component"))?,
    )?;
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= 1024,
        "invalid RSA component size"
    );
    Ok(integer(&bytes))
}
fn rsa_public_der(jwk: &Value) -> anyhow::Result<Vec<u8>> {
    let mut content = jwk_integer(jwk, "n")?;
    content.extend(jwk_integer(jwk, "e")?);
    let mut bits = vec![0];
    bits.extend(der(0x30, &content));
    let mut spki = rsa_algorithm();
    spki.extend(der(3, &bits));
    Ok(der(0x30, &spki))
}
fn rsa_private_der(jwk: &Value) -> anyhow::Result<Vec<u8>> {
    let mut content = integer(&[0]);
    for field in ["n", "e", "d", "p", "q", "dp", "dq", "qi"] {
        content.extend(jwk_integer(jwk, field)?);
    }
    let rsa = der(0x30, &content);
    let mut pkcs8 = integer(&[0]);
    pkcs8.extend(rsa_algorithm());
    pkcs8.extend(der(4, &rsa));
    Ok(der(0x30, &pkcs8))
}

/// Fresh anonymous recipient envelopes for an authenticated grant revision.
pub fn discovery_grants(
    devices: &[Device],
    epoch: &[u8; 32],
) -> anyhow::Result<crate::portable_protocol::Discovery> {
    let secret = p256::SecretKey::from_slice(&random::<32>())?;
    let public = p256::ecdsa::VerifyingKey::from(secret.public_key());
    let point = public.to_sec1_point(false);
    let mut wrapped = std::collections::BTreeMap::new();
    for device in devices {
        let recipient = decode(
            device
                .discover
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("recipient needs a discovery-key upgrade"))?,
        )?;
        let peer = p256::PublicKey::from_sec1_bytes(&recipient)?;
        let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
        let mut salt = point.as_bytes().to_vec();
        salt.extend(&recipient);
        let hkdf =
            hkdf::Hkdf::<Sha256>::new(Some(&Sha256::digest(&salt)), shared.raw_secret_bytes());
        let mut key = [0u8; 32];
        hkdf.expand(b"nightbuoy-anonymous-grant-v2", &mut key)
            .map_err(|_| anyhow::anyhow!("discovery derivation failed"))?;
        let cipher = aes(&key)?;
        key.fill(0);
        let nonce = random::<12>();
        let ciphertext = cipher
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: epoch,
                    aad: b"nightbuoy-anonymous-grant-v2",
                },
            )
            .map_err(|_| anyhow::anyhow!("discovery encryption failed"))?;
        let mut slot = nonce.to_vec();
        slot.extend(ciphertext);
        anyhow::ensure!(
            wrapped.insert(device.id.clone(), b64(slot)).is_none(),
            "duplicate discovery recipient"
        );
    }
    anyhow::ensure!(
        !wrapped.is_empty() && wrapped.len() <= 4000,
        "invalid discovery recipient count"
    );
    Ok(crate::portable_protocol::Discovery {
        ephemeral: b64(point.as_bytes()),
        wrapped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn browser_identity_epoch_discovery_and_content_interoperate() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/browser-identity.json")).unwrap();
        let bytes = fixture["vault_json"].as_str().unwrap().as_bytes();
        let password = fixture["password"].as_str().unwrap();
        assert!(Identity::unlock(bytes, "wrong passphrase").is_err());
        let who = Identity::unlock(bytes, password).unwrap();
        let mut missing = who.private.clone();
        missing.as_object_mut().unwrap().remove("discover");
        let mut vault: Vault = serde_json::from_slice(bytes).unwrap();
        let derived = vault_key(password, &decode(&vault.salt).unwrap()).unwrap();
        let nonce: [u8; 12] = decode(&vault.iv).unwrap().try_into().unwrap();
        let aad = serde_json::to_vec(&(
            "nightbuoy-vault",
            2,
            &vault.community,
            &vault.device,
            &vault.checkpoint,
        ))
        .unwrap();
        vault.cipher = b64(aes(&derived)
            .unwrap()
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: &serde_json::to_vec(&missing).unwrap(),
                    aad: &aad,
                },
            )
            .unwrap());
        assert!(
            Identity::unlock(&serde_json::to_vec(&vault).unwrap(), password)
                .err()
                .unwrap()
                .to_string()
                .contains("discovery-key mismatch")
        );
        let private_frame = decode(fixture["private_frame"].as_str().unwrap()).unwrap();
        let locator: Value =
            serde_json::from_str(include_str!("../tests/fixtures/private-locator.json")).unwrap();
        assert_eq!(who.device.id, locator["owner"]);
        assert_eq!(
            who.private_locator(
                locator["community"].as_str().unwrap(),
                locator["purpose"].as_str().unwrap()
            )
            .unwrap(),
            locator["locator"]
        );
        assert_eq!(
            who.open_private::<Value>(&"a".repeat(64), "pending", &private_frame)
                .unwrap(),
            fixture["private_value"]
        );
        assert!(
            who.open_private::<Value>(&"b".repeat(64), "pending", &private_frame)
                .is_err()
        );
        assert!(
            who.open_private::<Value>(&"a".repeat(64), "member-state", &private_frame)
                .is_err()
        );
        let generated = Identity::generate().unwrap();
        assert!(
            generated
                .open_private::<Value>(&"a".repeat(64), "pending", &private_frame)
                .is_err()
        );
        let relocked = generated
            .lock(password, &"a".repeat(64), "retained checkpoint")
            .unwrap();
        let reopened = Identity::unlock(&relocked, password).unwrap();
        assert_eq!(reopened.device.id, generated.device.id);
        let epoch: [u8; 32] = decode(fixture["epoch"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            who.open_epoch(fixture["grant"]["key"].as_str().unwrap())
                .unwrap(),
            epoch
        );
        let grants = fixture["envelope"]["wrapped"]
            .as_object()
            .unwrap()
            .values()
            .map(|v| v.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            who.open_discovery(fixture["envelope"]["ephemeral"].as_str().unwrap(), &grants)
                .unwrap(),
            epoch
        );
        assert!(
            MetadataKey::from_epoch(&epoch)
                .same(&MetadataKey::from_base64(fixture["metadata"].as_str().unwrap()).unwrap())
        );
        let event: Signed = serde_json::from_value(fixture["event"].clone()).unwrap();
        assert_eq!(
            decrypt_event(&epoch, &event).unwrap()["body"],
            "cross-client encrypted test"
        );
        let signed = who
            .signed(&json!(["native signature", who.device.id]))
            .unwrap();
        verify_member(&who.device.sign, &signed.body, &signed.signature).unwrap();
        let another: Device = serde_json::from_value(fixture["other"].clone()).unwrap();
        let wrong = wrap_epoch(&another, &epoch).unwrap();
        assert!(who.open_epoch(&wrong).is_err());
        let mut substituted = fixture["vault"].clone();
        substituted["checkpoint"] = json!("b".repeat(64));
        assert!(Identity::unlock(&serde_json::to_vec(&substituted).unwrap(), password).is_err());
    }
}
