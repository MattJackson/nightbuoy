//! The same established CometBFT commit verification runs natively and in browsers.
use serde::{Deserialize, Serialize};
use tendermint::{
    block::signed_header::SignedHeader,
    validator::{Info, Set},
};
use tendermint_light_client_verifier::{ProdVerifier, Verdict, types::UntrustedBlockState};
use wasm_bindgen::prelude::*;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Trust {
    pub chain_id: String,
    pub validators: Vec<Info>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    pub signed_header: SignedHeader,
}
impl Trust {
    pub fn validate(&self) -> Result<(), String> {
        if self.validators.is_empty()
            || self.validators.len() > 128
            || self.chain_id.parse::<tendermint::chain::Id>().is_err()
        {
            return Err("invalid validator trust".into());
        }
        let mut addresses = std::collections::BTreeSet::new();
        let mut keys = std::collections::BTreeSet::new();
        let mut power = 0u64;
        for v in &self.validators {
            if v.power.value() == 0
                || v.pub_key.ed25519().is_none()
                || Info::new(v.pub_key, v.power).address != v.address
                || !addresses.insert(v.address.to_string())
                || !keys.insert(v.pub_key.to_bytes())
            {
                return Err("invalid or duplicate validator identity".into());
            }
            power = power
                .checked_add(v.power.value())
                .ok_or("validator power overflow")?;
        }
        if power > Set::MAX_TOTAL_VOTING_POWER {
            return Err("validator power exceeds limit".into());
        }
        Ok(())
    }
}
pub fn verify(trust: &Trust, proof: &Proof, app_hash: &str) -> Result<(), String> {
    trust.validate()?;
    let validators = Set::without_proposer(trust.validators.clone());
    let header = &proof.signed_header;
    if header.header.chain_id.as_str() != trust.chain_id
        || hex::encode(header.header.app_hash.as_bytes()) != app_hash
    {
        return Err("consensus proof does not bind this community state".into());
    }
    if header.commit.height != header.header.height {
        return Err("commit height mismatch".into());
    }
    let state = UntrustedBlockState {
        signed_header: header,
        validators: &validators,
        next_validators: Some(&validators),
    };
    let verifier = ProdVerifier::default();
    if verifier.verify_validator_sets(&state) != Verdict::Success
        || verifier.verify_commit(&state) != Verdict::Success
    {
        return Err("invalid consensus signatures, header or quorum".into());
    }
    Ok(())
}
#[wasm_bindgen]
pub fn verify_consensus(trust_json: &str, proof_json: &str, app_hash: &str) -> Result<(), JsValue> {
    let trust = serde_json::from_str(trust_json)
        .map_err(|_| JsValue::from_str("invalid consensus trust"))?;
    let proof = serde_json::from_str(proof_json)
        .map_err(|_| JsValue::from_str("invalid consensus proof"))?;
    verify(&trust, &proof, app_hash).map_err(|e| JsValue::from_str(&e))
}
