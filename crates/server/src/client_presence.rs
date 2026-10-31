//! Session-only opt-in presence. No local preferences or secret-key exports.
use crate::{client::Client, presence, private_objects, sealed_storage::MetadataKey};
#[derive(Default)]
pub struct PresenceState {
    pub session: Option<presence::Session>,
    pub entries: Vec<presence::Announcement>,
    pub warning: String,
    withdraw: Option<String>,
}
impl Client {
    fn presence_scope(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.identity.as_ref().is_some_and(|who| self
                .data
                .view()
                .members
                .get(&who.device.id)
                .is_some_and(|m| m.status == "active"))
                && self.remote.backend.id()? == self.connection.primary.id()?,
            "recent activity requires active membership on the original backend"
        );
        Ok(())
    }
    pub async fn read_presence(&mut self, now: u64) -> anyhow::Result<()> {
        self.refresh().await?;
        self.presence_scope()?;
        let metadata = MetadataKey::from_epoch(&self.current);
        let (_, locator, _) = presence::storage(&metadata, &self.data);
        let object = private_objects::read(&self.remote, &locator).await?;
        self.presence.entries = if let Some(object) = object {
            presence::open(&metadata, &self.data, &object.bytes, now)?
        } else {
            vec![]
        };
        self.presence.warning.clear();
        Ok(())
    }
    pub async fn set_presence(&mut self, enabled: bool, now: u64) -> anyhow::Result<()> {
        // Forget the session secret before any potentially failing network operation.
        if !enabled && let Some(session) = self.presence.session.take() {
            self.presence.withdraw = Some(session.nonce.clone());
        }
        self.refresh().await?;
        self.presence_scope()?;
        anyhow::ensure!(
            self.can_write(),
            "provider write permission required to share activity"
        );
        if enabled && self.presence.session.is_none() {
            self.presence.session = Some(Default::default());
        }
        let metadata = MetadataKey::from_epoch(&self.current);
        let (_, locator, _) = presence::storage(&metadata, &self.data);
        // CAS races reload and merge at most once; no unconditional overwrites.
        for attempt in 0..2 {
            let old = private_objects::read(&self.remote, &locator).await?;
            let mut entries = if let Some(old) = &old {
                presence::open(&metadata, &self.data, &old.bytes, now)?
            } else {
                vec![]
            };
            let who = self.identity.as_ref().unwrap();
            let nonce = self
                .presence
                .session
                .as_ref()
                .map(|s| s.nonce.as_str())
                .or(self.presence.withdraw.as_deref());
            entries.retain(|p| p.member != who.device.id || Some(p.session.as_str()) != nonce);
            if let Some(session) = &self.presence.session {
                let signed = presence::announce(who, &self.data, session, now)?;
                entries.push(presence::check(&signed, &self.data, now)?);
            }
            let frame = presence::seal(
                &metadata,
                &self.data,
                entries.iter().map(|p| p.signed.clone()).collect(),
            )?;
            // Refuse a view change discovered while preparing this shared-key frame.
            let expected_epoch = self.data.view().epoch;
            self.refresh().await?;
            anyhow::ensure!(
                self.data.view().epoch == expected_epoch,
                "forum epoch changed; refresh before sharing activity"
            );
            self.presence_scope()?;
            match private_objects::write(
                &self.remote,
                &locator,
                frame,
                old.as_ref().map(|b| b.version.as_str()),
            )
            .await
            {
                Ok(_) => {
                    self.presence.entries = entries;
                    self.presence.withdraw = None;
                    self.presence.warning.clear();
                    return Ok(());
                }
                Err(_) if attempt == 0 => continue,
                Err(e) => return Err(e),
            }
        }
        unreachable!()
    }
}
