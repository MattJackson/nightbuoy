//! Bounded, owner-encrypted mutable state outside permanent forum history.
//! The caller authenticates membership; only the owning client can decrypt frames.
use crate::{
    crypto::*,
    remote::{Blob, Remote},
};

pub const MAX_PRIVATE_OBJECT: usize = 256 * 1024;
fn path(locator: &str) -> anyhow::Result<String> {
    anyhow::ensure!(
        locator.len() == 64 && locator.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid private locator"
    );
    // A separate opaque keyspace prevents private writes from replacing chain heads/objects.
    Ok(format!(
        "{}/{}",
        hash("nightbuoy-member-private-v1"),
        locator.to_ascii_lowercase()
    ))
}
fn validate(frame: &[u8]) -> anyhow::Result<()> {
    anyhow::ensure!(
        frame.len() >= 4125
            && frame.len() <= MAX_PRIVATE_OBJECT
            && frame[0] == 3
            && (frame.len() - 29).is_multiple_of(4096),
        "invalid private state frame"
    );
    Ok(())
}
pub async fn read(remote: &Remote, locator: &str) -> anyhow::Result<Option<Blob>> {
    let blob = remote.get(&path(locator)?).await?;
    if let Some(blob) = &blob {
        validate(&blob.bytes)?;
    }
    Ok(blob)
}
pub async fn write(
    remote: &Remote,
    locator: &str,
    frame: Vec<u8>,
    expected: Option<&str>,
) -> anyhow::Result<Blob> {
    validate(&frame)?;
    anyhow::ensure!(remote.writable(), "provider write permission required");
    let path = path(locator)?;
    anyhow::ensure!(
        expected.is_none_or(|v| v.len() <= 256),
        "invalid private state version"
    );
    let old = remote.get(&path).await?;
    if let Some(actual) = old.as_ref().filter(|b| b.bytes == frame) {
        return Ok(actual.clone());
    }
    anyhow::ensure!(
        old.as_ref().map(|b| b.version.as_str()) == expected,
        "private state changed; reload before saving"
    );
    if let Err(error) = remote.put(&path, frame.clone(), old.as_ref()).await {
        // Lost acknowledgements are safe only when readback matches the exact candidate.
        if let Ok(Some(actual)) = remote.get(&path).await
            && actual.bytes == frame
        {
            return Ok(actual);
        }
        return Err(error);
    }
    let actual = remote
        .get(&path)
        .await?
        .ok_or_else(|| anyhow::anyhow!("private state readback unavailable"))?;
    anyhow::ensure!(
        actual.bytes == frame,
        "private state changed during confirmation"
    );
    Ok(actual)
}
