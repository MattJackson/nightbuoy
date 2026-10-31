//! Owner-private reading preferences, positioned by verified ledger hashes.
use crate::model::{Data, Event};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
pub const MAX_TRACKED_TOPICS: usize = 1000;
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberState {
    pub version: u8,
    pub community: String,
    pub branch: String,
    pub since: String,
    pub visit: String,
    pub read: BTreeMap<String, String>,
    pub watched: Vec<String>,
}
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Missed {
    pub topics: usize,
    pub replies: usize,
    pub watched: usize,
    pub mentions: usize,
}
#[derive(Clone, Debug, Default)]
pub struct Summary {
    pub unread: BTreeMap<String, usize>,
    pub missed: Missed,
    pub total_unread: usize,
}
struct History<'a> {
    community: String,
    rank: HashMap<&'a str, usize>,
    roots: HashMap<&'a str, &'a Event>,
    latest: HashMap<&'a str, &'a Event>,
    by_hash: HashMap<&'a str, &'a Event>,
}
impl<'a> History<'a> {
    fn new(data: &'a Data) -> Self {
        let mut h = Self {
            community: data.community(),
            rank: data
                .archive
                .order
                .iter()
                .enumerate()
                .map(|(i, s)| (s.as_str(), i + 1))
                .collect(),
            roots: HashMap::new(),
            latest: HashMap::new(),
            by_hash: HashMap::new(),
        };
        for e in &data.events {
            if e.previous.is_empty() {
                h.roots.insert(&e.id, e);
            }
            h.latest.insert(&e.id, e);
            h.by_hash.insert(&e.hash, e);
        }
        h
    }
    fn position(&self, hash: &str) -> Option<usize> {
        if hash == self.community {
            Some(0)
        } else {
            self.rank.get(hash).copied()
        }
    }
    fn topic(&self, event: &Event) -> Option<&'a str> {
        let root = self.roots.get(event.id.as_str())?;
        match root.kind.as_str() {
            "topic" => Some(&root.id),
            "reply" => Some(&root.parent),
            _ => None,
        }
    }
}
impl MemberState {
    pub fn new(data: &Data) -> Self {
        Self {
            version: 1,
            community: data.community(),
            branch: data.branch(),
            since: data.tip.clone(),
            visit: data.tip.clone(),
            read: Default::default(),
            watched: Default::default(),
        }
    }
    pub fn validate(&self, data: &Data) -> anyhow::Result<()> {
        let h = History::new(data);
        let valid = self.version == 1
            && self.community == data.community()
            && self.branch == data.branch()
            && self.read.len() <= MAX_TRACKED_TOPICS
            && self.watched.len() <= MAX_TRACKED_TOPICS
            && self.watched.iter().collect::<BTreeSet<_>>().len() == self.watched.len()
            && h.position(&self.since).is_some()
            && h.position(&self.visit).is_some()
            && h.position(&self.visit) >= h.position(&self.since);
        anyhow::ensure!(
            valid,
            "private reading state does not match this verified forum history"
        );
        for (id, hash) in &self.read {
            anyhow::ensure!(
                h.roots.get(id.as_str()).is_some_and(|e| e.kind == "topic")
                    && h.by_hash
                        .get(hash.as_str())
                        .is_some_and(|e| h.topic(e) == Some(id.as_str())),
                "invalid private reading marker"
            );
        }
        for id in &self.watched {
            anyhow::ensure!(
                h.roots.get(id.as_str()).is_some_and(|e| e.kind == "topic"),
                "invalid watched topic"
            );
        }
        Ok(())
    }
    pub fn toggle_watch(&mut self, data: &Data, topic: &str) -> anyhow::Result<()> {
        let h = History::new(data);
        anyhow::ensure!(
            h.latest.get(topic).is_some_and(|e| e.kind == "topic"),
            "watch an existing live topic"
        );
        if let Some(index) = self.watched.iter().position(|id| id == topic) {
            self.watched.remove(index);
        } else {
            anyhow::ensure!(
                self.watched.len() < MAX_TRACKED_TOPICS,
                "at most 1,000 topics can be watched"
            );
            self.watched.push(topic.into());
            self.watched.sort();
        }
        Ok(())
    }
    pub fn mark_topic_read(
        &mut self,
        data: &Data,
        contents: &BTreeMap<String, Value>,
        topic: &str,
    ) -> anyhow::Result<()> {
        let h = History::new(data);
        let previous = self.read.get(topic).unwrap_or(&self.since);
        let mut marker = previous;
        for e in &data.events {
            if h.topic(e) == Some(topic)
                && contents.contains_key(&e.hash)
                && h.position(&e.hash) > h.position(marker)
            {
                marker = &e.hash;
            }
        }
        if marker != previous {
            anyhow::ensure!(
                self.read.contains_key(topic) || self.read.len() < MAX_TRACKED_TOPICS,
                "mark all read to compact reading state before tracking more topics"
            );
            self.read.insert(topic.into(), marker.clone());
        }
        Ok(())
    }
    pub fn mark_all_read(&mut self, data: &Data) {
        self.since = data.tip.clone();
        self.visit = data.tip.clone();
        self.read.clear();
    }
    pub fn summary(&self, data: &Data, contents: &BTreeMap<String, Value>, owner: &str) -> Summary {
        let h = History::new(data);
        let mut result = Summary::default();
        let watched = self
            .watched
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        for e in h.latest.values() {
            if !matches!(e.kind.as_str(), "topic" | "reply")
                || e.author == owner
                || !contents.contains_key(&e.hash)
            {
                continue;
            }
            let Some(topic) = h.topic(e) else {
                continue;
            };
            if h.latest.get(topic).is_none_or(|e| e.kind != "topic") {
                continue;
            }
            let position = h.position(&e.hash);
            let unseen = position > h.position(self.read.get(topic).unwrap_or(&self.since));
            if unseen {
                *result.unread.entry(topic.into()).or_default() += 1;
                result.total_unread += 1;
            }
            if unseen
                && h.roots
                    .get(e.id.as_str())
                    .is_some_and(|root| h.position(&root.hash) > h.position(&self.visit))
            {
                if e.kind == "topic" {
                    result.missed.topics += 1;
                } else {
                    result.missed.replies += 1;
                    if watched.contains(topic) {
                        result.missed.watched += 1;
                    }
                }
            }
            let body = contents[&e.hash]["body"].as_str().unwrap_or("");
            if unseen
                && position > h.position(&self.visit)
                && [
                    format!("@member-{}", owner.get(..10).unwrap_or(owner)),
                    format!("@{owner}"),
                ]
                .iter()
                .any(|token| mentioned(body, token))
            {
                result.missed.mentions += 1;
            }
        }
        result
    }
}
fn mentioned(text: &str, token: &str) -> bool {
    text.match_indices(token).any(|(i, _)| {
        let word = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-');
        let b = text.as_bytes();
        (i == 0 || !word(b[i - 1])) && (i + token.len() == b.len() || !word(b[i + token.len()]))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn browser_projection_vector_and_invalid_cursors_match_native() {
        let f: Value =
            serde_json::from_str(include_str!("../tests/fixtures/member-state.json")).unwrap();
        let data: Data = serde_json::from_value(f["data"].clone()).unwrap();
        let contents: BTreeMap<String, Value> =
            serde_json::from_value(f["contents"].clone()).unwrap();
        let mut state: MemberState = serde_json::from_value(f["state"].clone()).unwrap();
        state.validate(&data).unwrap();
        let summary = state.summary(&data, &contents, f["owner"].as_str().unwrap());
        assert_eq!(
            serde_json::json!({"unread":summary.unread,"missed":summary.missed,"totalUnread":summary.total_unread}),
            f["expected"]
        );
        let topic = state.watched[0].clone();
        state.mark_topic_read(&data, &contents, &topic).unwrap();
        let after = state.summary(&data, &contents, f["owner"].as_str().unwrap());
        assert_eq!(after.total_unread, 1);
        assert_eq!(after.missed.replies, 0);
        assert_eq!(after.missed.mentions, 0);
        let mut bad = state.clone();
        bad.branch = "d".repeat(64);
        assert!(bad.validate(&data).is_err());
        let mut bad = state.clone();
        bad.watched.push(topic.clone());
        assert!(bad.validate(&data).is_err());
        let mut bad = state.clone();
        bad.read
            .insert(topic.clone(), data.events.last().unwrap().hash.clone());
        assert!(bad.validate(&data).is_err());
        let mut bad = state.clone();
        bad.visit = "f".repeat(64);
        assert!(bad.validate(&data).is_err());
        state.mark_all_read(&data);
        state.validate(&data).unwrap();
        assert_eq!(
            state
                .summary(&data, &contents, f["owner"].as_str().unwrap())
                .total_unread,
            0
        );
        assert_eq!(state.watched, [topic]);
    }
}
