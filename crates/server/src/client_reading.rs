//! Native preference transport shares owner-private framing with the browser.
use crate::{
    client::Client,
    member_state::{MemberState, Missed, Summary},
    private_objects,
};
#[derive(Default)]
pub struct ReadingPreferences {
    pub state: Option<MemberState>,
    pub summary: Summary,
    pub catchup: Missed,
    pub warning: String,
    version: Option<String>,
    saved: Option<MemberState>,
    pending: Option<(Vec<u8>, Option<String>, MemberState)>,
}
impl ReadingPreferences {
    pub fn dirty(&self) -> bool {
        self.pending.is_some() || self.state != self.saved
    }
    fn restore(&mut self, value: MemberState) {
        self.state = Some(value);
        self.saved = None;
        self.pending = None;
    }
}
impl Client {
    fn reading_owner(&self) -> anyhow::Result<(crate::client_crypto::Identity, String)> {
        let who = self
            .identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("unlock the owning member identity"))?;
        Ok((who.clone(), format!("member-state:{}", self.data.branch())))
    }
    fn reading_scope(&self) -> anyhow::Result<(crate::client_crypto::Identity, String)> {
        let (who, purpose) = self.reading_owner()?;
        anyhow::ensure!(
            self.data
                .view()
                .members
                .get(&who.device.id)
                .is_some_and(|m| m.status == "active"),
            "active membership required for private reading state"
        );
        Ok((who, purpose))
    }
    pub async fn load_reading(&mut self) -> anyhow::Result<()> {
        let (who, purpose) = self.reading_scope()?;
        let community = self.data.community();
        anyhow::ensure!(
            self.remote.backend.id()? == self.connection.primary.id()?,
            "reading state requires its original backend"
        );
        let object =
            private_objects::read(&self.remote, &who.private_locator(&community, &purpose)?)
                .await?;
        let version = object.as_ref().map(|b| b.version.clone());
        let existed = object.is_some();
        let value = if let Some(blob) = object {
            let checked = (|| -> anyhow::Result<MemberState> {
                let value: MemberState = who.open_private(&community, &purpose, &blob.bytes)?;
                value.validate(&self.data)?;
                Ok(value)
            })();
            match checked {
                Ok(value) => value,
                Err(error) => {
                    // A fresh client may explicitly import a backup to replace this
                    // version. A cached valid view must not adopt an unreadable version.
                    if self.reading.state.is_none() {
                        self.reading.version = version;
                    }
                    return Err(error);
                }
            }
        } else {
            MemberState::new(&self.data)
        };
        self.reading.version = version;
        self.reading.catchup = value
            .summary(&self.data, &self.contents, &who.device.id)
            .missed
            .clone();
        self.reading.saved = existed.then(|| value.clone());
        self.reading.state = Some(MemberState {
            visit: self.data.tip.clone(),
            ..value
        });
        self.reading.pending = None;
        self.reading.warning.clear();
        self.update_reading_summary();
        Ok(())
    }
    pub(crate) fn update_reading_summary(&mut self) {
        self.reading.summary = match (&self.reading.state, &self.identity) {
            (Some(state), Some(who)) => state.summary(&self.data, &self.contents, &who.device.id),
            _ => Summary::default(),
        };
    }
    pub async fn save_reading(&mut self) -> anyhow::Result<()> {
        if !self.reading.dirty() && self.reading.pending.is_none() {
            return Ok(());
        }
        self.refresh().await?;
        anyhow::ensure!(
            self.can_write(),
            "reading state remains in memory; export a backup or supply your provider write permission"
        );
        let (who, purpose) = self.reading_scope()?;
        let community = self.data.community();
        let locator = who.private_locator(&community, &purpose)?;
        for _ in 0..2 {
            if !self.reading.dirty() && self.reading.pending.is_none() {
                break;
            }
            if self.reading.pending.is_none() {
                let value = self
                    .reading
                    .state
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("load private reading state first"))?;
                value.validate(&self.data)?;
                self.reading.pending = Some((
                    who.seal_private(&community, &purpose, &value)?,
                    self.reading.version.clone(),
                    value,
                ));
            }
            let (frame, version, value) = self.reading.pending.as_ref().unwrap();
            let result =
                private_objects::write(&self.remote, &locator, frame.clone(), version.as_deref())
                    .await;
            match result {
                Ok(blob) => {
                    self.reading.version = Some(blob.version);
                    self.reading.saved = Some(value.clone());
                    self.reading.pending = None;
                    self.reading.warning.clear();
                }
                Err(e) => {
                    self.reading.warning = e.to_string();
                    return Err(e);
                }
            }
        }
        Ok(())
    }
    pub fn toggle_watched(&mut self, topic: &str) -> anyhow::Result<()> {
        self.reading
            .state
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("load private reading state first"))?
            .toggle_watch(&self.data, topic)?;
        self.update_reading_summary();
        Ok(())
    }
    pub fn mark_read(&mut self, topic: &str) -> anyhow::Result<()> {
        self.reading
            .state
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("load private reading state first"))?
            .mark_topic_read(&self.data, &self.contents, topic)?;
        self.update_reading_summary();
        Ok(())
    }
    pub fn mark_everything_read(&mut self) -> anyhow::Result<()> {
        self.reading
            .state
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("load private reading state first"))?
            .mark_all_read(&self.data);
        self.reading.catchup = Missed::default();
        self.update_reading_summary();
        Ok(())
    }
    pub fn export_reading(&self) -> anyhow::Result<Vec<u8>> {
        let (who, purpose) = self.reading_owner()?;
        who.seal_private(
            &self.data.community(),
            &purpose,
            self.reading
                .state
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("load private reading state first"))?,
        )
    }
    pub fn import_reading(&mut self, frame: &[u8]) -> anyhow::Result<()> {
        anyhow::ensure!(
            frame.len() <= private_objects::MAX_PRIVATE_OBJECT,
            "private reading backup is too large"
        );
        let (who, purpose) = self.reading_owner()?;
        let value: MemberState = who.open_private(&self.data.community(), &purpose, frame)?;
        value.validate(&self.data)?;
        self.reading.catchup = value
            .summary(&self.data, &self.contents, &who.device.id)
            .missed;
        self.reading.restore(value);
        self.update_reading_summary();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unresolved_save_and_explicit_restore_remain_unsaved() {
        let f: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/member-state.json")).unwrap();
        let saved: MemberState = serde_json::from_value(f["state"].clone()).unwrap();
        let mut other = saved.clone();
        other.watched.clear();
        let mut reading = ReadingPreferences {
            state: Some(saved.clone()),
            saved: Some(saved.clone()),
            pending: Some((vec![3], Some("old version".into()), other)),
            ..Default::default()
        };
        assert!(
            reading.dirty(),
            "an unresolved remote save still needs reconciliation even when local changes were undone"
        );
        reading.restore(saved);
        assert!(
            reading.dirty(),
            "an imported backup must be published or explicitly retained, never assumed confirmed"
        );
    }
}
