//! CometBFT ABCI adapter. No application-side consensus algorithm or mirror voting.
use crate::{
    crypto::*,
    model::{Archive, Data, Record, Signed},
    store::Store,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tendermint_abci::Application;
use tendermint_proto::v0_38::abci::*;
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum Transaction {
    Genesis(Signed),
    Control(Signed),
    Event(Record),
}
#[derive(Default)]
struct Stage {
    height: i64,
    app_hash: Vec<u8>,
    candidate: Option<Option<Data>>,
    next_height: i64,
}
#[derive(Clone)]
pub struct Consensus {
    pub rpc: String,
    pub trust: nightbuoy_proof::Trust,
    store: Arc<Mutex<Store>>,
    stage: Arc<Mutex<Stage>>,
}
impl Consensus {
    pub fn new(
        rpc: String,
        genesis_file: &std::path::Path,
        store: Arc<Mutex<Store>>,
    ) -> anyhow::Result<Self> {
        let mut raw: serde_json::Value = serde_json::from_slice(&std::fs::read(genesis_file)?)?;
        raw.as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("invalid consensus genesis"))?
            .entry("app_state")
            .or_insert(serde_json::Value::Null);
        let genesis: tendermint::Genesis = serde_json::from_value(raw)?;
        let trust = nightbuoy_proof::Trust {
            chain_id: genesis.chain_id.to_string(),
            validators: genesis.validators,
        };
        trust.validate().map_err(anyhow::Error::msg)?;
        let rpc_url = url::Url::parse(&rpc)?;
        anyhow::ensure!(
            rpc_url.scheme() == "http"
                && matches!(
                    rpc_url.host_str(),
                    Some("127.0.0.1" | "localhost" | "[::1]")
                ),
            "consensus RPC must remain on loopback; use a protected local tunnel for remote engines"
        );
        if let Some(data) = &store.lock().unwrap().data {
            anyhow::ensure!(
                data.view().policy.consensus.as_ref() == Some(&trust),
                "stored archive trust differs from the selected consensus network; explicit verified recovery is required"
            );
        }
        let stage = {
            let s = store.lock().unwrap();
            s.db.execute_batch("CREATE TABLE IF NOT EXISTS consensus(id INTEGER PRIMARY KEY CHECK(id=1),height INTEGER NOT NULL,app_hash TEXT NOT NULL);")?;
            use rusqlite::OptionalExtension;
            let row: Option<(i64, String)> =
                s.db.query_row(
                    "SELECT height,app_hash FROM consensus WHERE id=1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((height, hash)) = row {
                anyhow::ensure!(
                    s.data.as_ref().map(Data::state_hash).unwrap_or_default() == hash,
                    "application state does not match persisted consensus checkpoint"
                );
                Stage {
                    height,
                    app_hash: hex::decode(hash)?,
                    ..Default::default()
                }
            } else {
                Stage::default()
            }
        };
        Ok(Self {
            rpc,
            trust,
            store,
            stage: Arc::new(Mutex::new(stage)),
        })
    }
    fn apply(&self, state: &mut Option<Data>, tx: &[u8]) -> anyhow::Result<()> {
        anyhow::ensure!(tx.len() <= 8_500_000, "transaction too large");
        let tx: Transaction = serde_json::from_slice(tx)?;
        match tx {
            Transaction::Genesis(g) => {
                anyhow::ensure!(state.is_none(), "community already initialized");
                let d = Data::create(g)?;
                anyhow::ensure!(
                    d.view().policy.consensus.as_ref() == Some(&self.trust),
                    "community must bind the configured validator set"
                );
                *state = Some(d);
            }
            Transaction::Control(s) => {
                let a: serde_json::Value = serde_json::from_str(&s.body)?;
                anyhow::ensure!(
                    a[6] != "reconstitute",
                    "branch resets require a new explicitly selected network"
                );
                state
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("community unconfigured"))?
                    .control(s)?;
            }
            Transaction::Event(r) => {
                state
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("community unconfigured"))?
                    .event(r)?;
            }
        }
        Ok(())
    }
    pub async fn submit(
        &self,
        client: &reqwest::Client,
        tx: &Transaction,
    ) -> anyhow::Result<serde_json::Value> {
        let bytes = serde_json::to_vec(tx)?;
        let response=client.post(&self.rpc).json(&serde_json::json!({"jsonrpc":"2.0","id":"nightbuoy","method":"broadcast_tx_commit","params":{"tx":b64(bytes)}})).send().await.map_err(|_|anyhow::anyhow!("validators unavailable; post is unconfirmed"))?;
        let value: serde_json::Value = response
            .json()
            .await
            .map_err(|_| anyhow::anyhow!("invalid consensus response"))?;
        anyhow::ensure!(
            value.get("error").is_none(),
            "consensus confirmation unavailable; transaction may still be pending"
        );
        let result = &value["result"];
        let check = result["check_tx"]["code"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("invalid consensus admission response"))?;
        let outcome = if result.get("tx_result").is_some() {
            &result["tx_result"]
        } else {
            &result["deliver_tx"]
        };
        anyhow::ensure!(
            check == 0 && outcome["code"].as_u64() == Some(0),
            "transaction rejected by current community permissions or revision; refresh and retry"
        );
        Ok(result.clone())
    }
    pub async fn update_proof(&self, client: &reqwest::Client) -> anyhow::Result<()> {
        // Retain the first valid certificate for an unchanged state. Empty consensus
        // blocks must not create a new full archive on every client poll.
        {
            let store = self.store.lock().unwrap();
            if store
                .data
                .as_ref()
                .is_some_and(|d| d.verify_proof().is_ok())
            {
                return Ok(());
            }
        }
        let response = client
            .get(format!("{}/commit", self.rpc.trim_end_matches('/')))
            .send()
            .await?;
        let value: serde_json::Value = response.json().await?;
        let proof: nightbuoy_proof::Proof = serde_json::from_value(
            serde_json::json!({"signed_header":value["result"]["signed_header"]}),
        )?;
        let mut store = self.store.lock().unwrap();
        if let Some(d) = &store.data
            && nightbuoy_proof::verify(&self.trust, &proof, &d.state_hash()).is_ok()
        {
            let mut next = d.clone();
            next.archive.proof = Some(proof);
            store.save(next)?;
        }
        Ok(())
    }
}
impl Application for Consensus {
    fn init_chain(&self, r: RequestInitChain) -> ResponseInitChain {
        if !r.app_state_bytes.is_empty()
            && r.app_state_bytes.as_ref() != b"{}"
            && r.app_state_bytes.as_ref() != b"null"
        {
            let archive: Archive =
                serde_json::from_slice(&r.app_state_bytes).expect("invalid genesis checkpoint");
            let data =
                Data::replay_unconfirmed(&archive).expect("genesis checkpoint verification failed");
            assert_eq!(
                data.view().policy.consensus.as_ref(),
                Some(&self.trust),
                "checkpoint must explicitly select this network's validator trust"
            );
            let hash = hex::decode(data.state_hash()).unwrap();
            self.store
                .lock()
                .unwrap()
                .save(data)
                .expect("cannot initialize checkpoint");
            self.stage.lock().unwrap().app_hash = hash.clone();
            return ResponseInitChain {
                app_hash: hash.into(),
                ..Default::default()
            };
        }
        Default::default()
    }
    fn info(&self, _: RequestInfo) -> ResponseInfo {
        let s = self.stage.lock().unwrap();
        ResponseInfo {
            data: "NightBuoy".into(),
            version: "1".into(),
            app_version: 1,
            last_block_height: s.height,
            last_block_app_hash: s.app_hash.clone().into(),
        }
    }
    fn check_tx(&self, r: RequestCheckTx) -> ResponseCheckTx {
        let mut state = self.store.lock().unwrap().data.clone();
        let result = self.apply(&mut state, &r.tx);
        ResponseCheckTx {
            code: if result.is_ok() { 0 } else { 1 },
            log: if result.is_ok() {
                String::new()
            } else {
                "invalid, stale or unauthorized transaction".into()
            },
            ..Default::default()
        }
    }
    fn prepare_proposal(&self, r: RequestPrepareProposal) -> ResponsePrepareProposal {
        let mut state = self.store.lock().unwrap().data.clone();
        let mut txs = vec![];
        let mut total = 0usize;
        for tx in r.txs {
            if total + tx.len() > r.max_tx_bytes.max(0) as usize {
                continue;
            }
            let mut candidate = state.clone();
            if self.apply(&mut candidate, &tx).is_ok() {
                total += tx.len();
                txs.push(tx);
                state = candidate;
            }
        }
        ResponsePrepareProposal { txs }
    }
    fn process_proposal(&self, r: RequestProcessProposal) -> ResponseProcessProposal {
        let mut state = self.store.lock().unwrap().data.clone();
        let valid = r.txs.iter().all(|t| self.apply(&mut state, t).is_ok());
        ResponseProcessProposal {
            status: if valid {
                response_process_proposal::ProposalStatus::Accept as i32
            } else {
                response_process_proposal::ProposalStatus::Reject as i32
            },
        }
    }
    fn finalize_block(&self, r: RequestFinalizeBlock) -> ResponseFinalizeBlock {
        let mut state = self.store.lock().unwrap().data.clone();
        let mut results = vec![];
        for tx in r.txs {
            let mut candidate = state.clone();
            let ok = self.apply(&mut candidate, &tx).is_ok();
            if ok {
                state = candidate;
            }
            results.push(ExecTxResult {
                code: if ok { 0 } else { 1 },
                ..Default::default()
            });
        }
        let hash = state
            .as_ref()
            .map(|d| hex::decode(d.state_hash()).unwrap())
            .unwrap_or_default();
        let mut stage = self.stage.lock().unwrap();
        stage.candidate = Some(state);
        stage.next_height = r.height;
        ResponseFinalizeBlock {
            tx_results: results,
            app_hash: hash.into(),
            ..Default::default()
        }
    }
    fn commit(&self) -> ResponseCommit {
        let mut stage = self.stage.lock().unwrap();
        let Some(candidate) = stage.candidate.take() else {
            return Default::default();
        };
        let app_hash = candidate.as_ref().map(Data::state_hash).unwrap_or_default();
        let mut store = self.store.lock().unwrap();
        let tx = store
            .db
            .transaction()
            .expect("local durable storage unavailable");
        if let Some(d) = &candidate {
            tx.execute("INSERT INTO state(id,json) VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET json=excluded.json",[serde_json::to_string(&d.archive).unwrap()]).expect("cannot persist accepted history");
        }
        tx.execute("INSERT INTO consensus(id,height,app_hash) VALUES(1,?1,?2) ON CONFLICT(id) DO UPDATE SET height=excluded.height,app_hash=excluded.app_hash",rusqlite::params![stage.next_height,app_hash]).expect("cannot persist consensus checkpoint");
        tx.commit().expect("cannot durably commit accepted history");
        store.data = candidate;
        stage.height = stage.next_height;
        stage.app_hash = hex::decode(app_hash).unwrap();
        Default::default()
    }
}
