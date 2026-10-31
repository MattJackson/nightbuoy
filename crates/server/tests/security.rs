use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use nightbuoy::{
    api::{self, App},
    config::Config,
    crypto::*,
    model::*,
    store::Store,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
fn device(n: u8) -> (SigningKey, Device) {
    let key = SigningKey::from_slice(&[n; 32]).unwrap();
    let sign = b64(key.verifying_key().to_sec1_point(false).as_bytes());
    let dev = Device {
        id: hash(decode(&sign).unwrap()),
        sign,
        wrap: json!({"kty":"RSA","e":"AQAB","n":"A".repeat(512)}),
        discover: None,
    };
    (key, dev)
}
fn signed(key: &SigningKey, v: Value) -> Signed {
    let body = serde_json::to_string(&v).unwrap();
    let sig: Signature = key.sign(body.as_bytes());
    Signed {
        body,
        signature: b64(sig.to_bytes()),
    }
}
fn grants(devs: &[&Device], epoch: u64) -> Value {
    json!(
        devs.iter()
            .map(|d| json!({"member":d.id,"epoch":epoch,"key":b64([7u8;384])}))
            .collect::<Vec<_>>()
    )
}
fn setup() -> (Data, SigningKey, Device, [u8; 32]) {
    let (key, dev) = device(1);
    let pubkey = [9u8; 32];
    let g = signed(
        &key,
        json!(["nightbuoy-genesis",1,dev,{"name":"Public brand","skin":"nightbuoy","admission":"approval","history":true,"identity":"key"},b64(authority(&pubkey).verifying_key().to_bytes()),grants(&[&dev],1)]),
    );
    (Data::create(g).unwrap(), key, dev, pubkey)
}
fn ctl(data: &Data, k: &SigningKey, d: &Device, op: &str, p: Value) -> Signed {
    signed(
        k,
        json!([
            "nightbuoy-control",
            1,
            data.community(),
            data.authority_tip(),
            d.id,
            "a".repeat(64),
            op,
            p
        ]),
    )
}
#[allow(
    clippy::too_many_arguments,
    reason = "The fixture names signed event fields and signing identities explicitly"
)]
fn record(
    data: &Data,
    k: &SigningKey,
    d: &Device,
    publisher: &[u8; 32],
    kind: &str,
    id: &str,
    parent: &str,
    previous: &str,
) -> Record {
    let event = signed(
        k,
        json!([
            1,
            data.community(),
            d.id,
            data.authority_tip(),
            data.view().epoch,
            kind,
            id,
            parent,
            previous,
            1,
            b64([1u8; 12]),
            b64([2u8; 32])
        ]),
    );
    Record {
        publisher: b64(authority(publisher).verifying_key().to_bytes()),
        receipt: sign(publisher, &receipt_bytes(&data.community(), &event.hash())),
        event,
    }
}
const BOARD: &str = "11111111-1111-4111-8111-111111111111";
const TOPIC: &str = "22222222-2222-4222-8222-222222222222";
#[test]
fn tampering_missing_blocks_and_foreign_communities_fail() {
    let (mut data, key, dev, pubkey) = setup();
    data.event(record(&data, &key, &dev, &pubkey, "board", BOARD, "", ""))
        .unwrap();
    data.event(record(
        &data, &key, &dev, &pubkey, "topic", TOPIC, BOARD, "",
    ))
    .unwrap();
    let a = data.archive.clone();
    assert_eq!(Data::replay(&a).unwrap().tip, data.tip);
    let mut changed = a.clone();
    changed.records[0].event.body.push(' ');
    assert!(Data::replay(&changed).is_err());
    let mut gap = a.clone();
    gap.order.remove(0);
    assert!(Data::replay(&gap).is_err());
    let mut receipt = a.clone();
    receipt.records[0].receipt = b64([0u8; 64]);
    assert!(Data::replay(&receipt).is_err());
    let mut order = a.clone();
    order.order.reverse();
    assert!(Data::replay(&order).is_err());
}
#[test]
fn prefixes_catch_up_but_divergent_histories_never_merge() {
    let (root, key, dev, pubkey) = setup();
    let mut a = root.clone();
    let mut b = root.clone();
    a.event(record(&a, &key, &dev, &pubkey, "board", BOARD, "", ""))
        .unwrap();
    b.event(record(&b, &key, &dev, &pubkey, "board", TOPIC, "", ""))
        .unwrap();
    assert_eq!(root.catch_up(&a.archive).unwrap().tip, a.tip);
    assert!(a.catch_up(&b.archive).is_err());
    assert_eq!(a.catch_up(&root.archive).unwrap().tip, a.tip);
}
#[test]
fn membership_authority_and_rekey_exclusion() {
    let (mut data, key, admin, pubkey) = setup();
    let (user_key, user) = device(2);
    let p = json!({"device":user,"grants":grants(&[&user],1)});
    data.control(ctl(&data, &key, &admin, "admit", p)).unwrap();
    let unauthorized = ctl(
        &data,
        &user_key,
        &user,
        "policy",
        json!({"name":"hijacked","skin":"nightbuoy","admission":"automatic","history":true,"identity":"key"}),
    );
    assert!(data.clone().control(unauthorized).is_err());
    assert!(
        data.clone()
            .event(record(
                &data, &user_key, &user, &pubkey, "board", BOARD, "", ""
            ))
            .is_err()
    );
    let prior = data.clone();
    let revoke = ctl(
        &data,
        &key,
        &admin,
        "revoke",
        json!({"member":user.id,"epoch":2,"grants":grants(&[&admin],2)}),
    );
    data.control(revoke).unwrap();
    assert!(!data.view().grants[&2].contains_key(&user.id));
    assert!(
        data.clone()
            .event(record(
                &data, &user_key, &user, &pubkey, "board", BOARD, "", ""
            ))
            .is_err()
    );
    assert!(
        data.clone()
            .event(record(
                &prior, &user_key, &user, &pubkey, "board", BOARD, "", ""
            ))
            .is_err()
    );
    assert!(
        data.control(ctl(
            &data,
            &key,
            &admin,
            "role",
            json!({"member":admin.id,"role":"member"})
        ))
        .is_err()
    );
}
#[test]
fn founder_has_no_immunity_and_reset_branch_is_explicit() {
    let (mut data, key, founder, _) = setup();
    let (other_key, other) = device(2);
    data.control(ctl(
        &data,
        &key,
        &founder,
        "admit",
        json!({"device":other,"grants":grants(&[&other],1)}),
    ))
    .unwrap();
    let checkpoint = data.clone();
    data.control(ctl(
        &data,
        &key,
        &founder,
        "role",
        json!({"member":other.id,"role":"administrator"}),
    ))
    .unwrap();
    data.control(ctl(
        &data,
        &other_key,
        &other,
        "revoke",
        json!({"member":founder.id,"epoch":2,"grants":grants(&[&other],2)}),
    ))
    .unwrap();
    assert_eq!(data.view().members[&founder.id].status, "revoked");
    let mut reset = checkpoint.clone();
    let p = json!({"exclude":[founder.id],"publisher":b64(authority(&[4u8;32]).verifying_key().to_bytes()),"epoch":2,"grants":grants(&[&other],2)});
    reset
        .control(ctl(&reset, &other_key, &other, "reconstitute", p))
        .unwrap();
    assert_eq!(reset.view().members[&other.id].role, "administrator");
    assert!(checkpoint.catch_up(&reset.archive).is_err());
    assert!(data.catch_up(&reset.archive).is_err());
    assert_eq!(Data::replay(&reset.archive).unwrap().branch(), reset.tip);
}
#[test]
fn edits_preserve_ownership_and_reject_stale_revisions() {
    let (mut d, key, dev, pubkey) = setup();
    let r = record(&d, &key, &dev, &pubkey, "board", BOARD, "", "");
    let first = r.event.hash();
    d.event(r).unwrap();
    let edit = record(&d, &key, &dev, &pubkey, "board", BOARD, "", &first);
    d.event(edit).unwrap();
    let mut stale = record(&d, &key, &dev, &pubkey, "board", BOARD, "", &first);
    let mut fields: Value = serde_json::from_str(&stale.event.body).unwrap();
    fields[9] = json!(2);
    stale.event = signed(&key, fields);
    stale.receipt = sign(&pubkey, &receipt_bytes(&d.community(), &stale.event.hash()));
    assert!(
        d.event(stale)
            .unwrap_err()
            .to_string()
            .contains("stale object revision")
    );
}
#[test]
fn store_persists_verified_history_without_authority_secret() {
    let dir = tempfile::tempdir().unwrap();
    let (data, _, _, _) = setup();
    let id = data.community();
    {
        let mut s = Store::open(dir.path()).unwrap();
        s.save(data).unwrap();
    }
    let s = Store::open(dir.path()).unwrap();
    assert_eq!(s.data.as_ref().unwrap().community(), id);
    assert!(!dir.path().join("authority.key").exists());
}
#[tokio::test]
async fn anonymous_reads_csrf_and_bootstrap_takeover_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        data: dir.path().into(),
        public_url: "https://example.test".into(),
        listen: "127.0.0.1:0".into(),
        web: dir.path().into(),
        providers: vec![],
        testing: false,
        read_only: false,
        branding: None,
        replicas: None,
    };
    let state = App {
        store: Arc::new(Mutex::new(Store::open(dir.path()).unwrap())),
        config: Arc::new(config),
        client: reqwest::Client::new(),
        replication: Arc::new(Mutex::new(Default::default())),
        consensus: None,
    };
    let router = api::router(state);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/sync")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/events")
                .header("origin", "https://example.test")
                .header("content-type", "application/json")
                .body(Body::from(
                    "malformed JSON must not be parsed before authentication",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/setup")
                .header("Content-Type", "application/json")
                .header("Origin", "https://attacker.test")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test]
fn timestamp_outside_supported_display_range_is_rejected() {
    let (data, key, dev, pubkey) = setup();
    let mut r = record(&data, &key, &dev, &pubkey, "board", BOARD, "", "");
    let mut a: Value = serde_json::from_str(&r.event.body).unwrap();
    a[9] = json!(9_000_000_000_000_000u64);
    r.event = signed(&key, a);
    r.receipt = sign(&pubkey, &receipt_bytes(&data.community(), &r.event.hash()));
    assert!(
        data.validate_event(&r, true)
            .unwrap_err()
            .to_string()
            .contains("timestamp")
    );
}
#[test]
fn aggregate_capacity_is_checked_before_acceptance_and_reserves_proof_space() {
    let (mut data, key, dev, pubkey) = setup();
    let mut accepted = 0;
    loop {
        let id = format!("{:08x}-1111-4111-8111-111111111111", accepted + 1);
        let mut r = record(&data, &key, &dev, &pubkey, "board", &id, "", "");
        let mut a: Value = serde_json::from_str(&r.event.body).unwrap();
        a[11] = json!(b64(vec![2u8; 5_900_000]));
        r.event = signed(&key, a);
        r.receipt = sign(&pubkey, &receipt_bytes(&data.community(), &r.event.hash()));
        let old = data.tip.clone();
        match data.event(r) {
            Ok(()) => {
                accepted += 1;
                assert!(accepted <= 9);
            }
            Err(e) => {
                assert!(e.to_string().contains("capacity"));
                assert_eq!(data.tip, old);
                break;
            }
        }
    }
    assert!(accepted >= 7);
    assert!(data.core_bytes().len() <= nightbuoy::model::MAX_CORE_BYTES);
    assert!(nightbuoy::model::MAX_ARCHIVE_BYTES - data.core_bytes().len() >= 256 * 1024);
}

#[tokio::test]
async fn private_read_only_copy_rejects_publication_and_enrollment() {
    let dir = tempfile::tempdir().unwrap();
    let (data, _, dev, _) = setup();
    let mut store = Store::open(dir.path()).unwrap();
    store.save(data).unwrap();
    let session = store.session(&dev.id).unwrap();
    let state = App {
        store: Arc::new(Mutex::new(store)),
        config: Arc::new(Config {
            data: dir.path().into(),
            public_url: "https://copy.test".into(),
            listen: "127.0.0.1:0".into(),
            web: dir.path().into(),
            providers: vec![],
            testing: false,
            read_only: true,
            branding: None,
            replicas: None,
        }),
        client: reqwest::Client::new(),
        replication: Arc::new(Mutex::new(Default::default())),
        consensus: None,
    };
    let router = api::router(state);
    for endpoint in [
        "/api/events",
        "/api/control",
        "/api/join",
        "/api/setup",
        "/api/import",
        "/api/replicate",
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(endpoint)
                    .header("origin", "https://copy.test")
                    .header("cookie", format!("nb_session={session}"))
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{endpoint}");
    }
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/sync")
                .header("cookie", format!("nb_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/sync")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn fifty_archive_destinations_survive_loss_of_one_without_public_inventory() {
    let dir = tempfile::tempdir().unwrap();
    let (data, _, _, _) = setup();
    let community = data.community();
    let mut store = Store::open(&dir.path().join("application")).unwrap();
    store.save(data).unwrap();
    let targets: Vec<Value> = (0..50).map(|i| json!({"id":format!("private-destination-{i}"),"kind":"directory","directory":dir.path().join(format!("destination-{i}")),"mode":"push","consent":true})).collect();
    let file = dir.path().join("destinations.json");
    std::fs::write(&file, serde_json::to_vec(&targets).unwrap()).unwrap();
    let app = App {
        store: Arc::new(Mutex::new(store)),
        config: Arc::new(Config {
            data: dir.path().join("application"),
            public_url: "https://example.test".into(),
            listen: "127.0.0.1:0".into(),
            web: dir.path().into(),
            providers: vec![],
            testing: false,
            read_only: false,
            branding: None,
            replicas: Some(file),
        }),
        client: reqwest::Client::new(),
        replication: Arc::new(Mutex::new(Default::default())),
        consensus: None,
    };
    nightbuoy::replication::once(&app).await.unwrap();
    let status = serde_json::to_string(&*app.replication.lock().unwrap()).unwrap();
    assert!(!status.contains("private-destination"));
    assert!(app.replication.lock().unwrap().copied);
    std::fs::remove_dir_all(dir.path().join("destination-0")).unwrap();
    for i in 1..50 {
        let base = dir
            .path()
            .join(format!("destination-{i}/nightbuoy/{community}"));
        let pointer: Value =
            serde_json::from_slice(&std::fs::read(base.join("latest.json")).unwrap()).unwrap();
        let bytes = std::fs::read(base.join(format!(
            "archives/{}.json",
            pointer["archive"].as_str().unwrap()
        )))
        .unwrap();
        assert_eq!(hash(&bytes), pointer["archive"].as_str().unwrap());
        let archive: Archive = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(Data::replay(&archive).unwrap().community(), community);
    }
}

#[test]
fn portable_certificates_bind_inventory_and_cannot_downgrade_ordering() {
    use nightbuoy::portable_protocol as portable;
    let (key, dev) = device(11);
    let primary = b64([21u8; 32]);
    let genesis = signed(
        &key,
        json!(["nightbuoy-genesis",1,dev,{"name":"Portable","skin":"nightbuoy","admission":"approval","history":true,"identity":"key","portable":{"version":1,"primary":primary}},primary,grants(&[&dev],1)]),
    );
    let mut data = Data::create(genesis.clone()).unwrap();
    assert!(Data::replay(&data.archive).is_err());
    let body = portable::header_body(&data, &portable::Item::Genesis(genesis), "", 0).unwrap();
    let header = signed(&key, serde_json::from_str(&body).unwrap());
    data.archive.portable_proof = Some(portable::Certificate {
        anchor: None,
        headers: vec![header],
    });
    Data::replay(&data.archive).unwrap();
    for consensus in [
        Value::Null,
        json!({"chain_id":"replacement","validators":[]}),
    ] {
        let reset = ctl(
            &data,
            &key,
            &dev,
            "reconstitute",
            json!({"exclude":[],"publisher":b64([22u8;32]),"epoch":2,"grants":grants(&[&dev],2),"consensus":consensus}),
        );
        assert!(
            data.clone()
                .control(reset)
                .unwrap_err()
                .to_string()
                .contains("cannot return to legacy ordering")
        );
    }
    let mut bad = data.archive.clone();
    bad.portable_proof.as_mut().unwrap().headers[0].signature = b64([0u8; 64]);
    assert!(Data::replay(&bad).is_err());
    let mut bad = data.archive.clone();
    bad.portable_proof
        .as_mut()
        .unwrap()
        .headers
        .push(data.archive.portable_proof.as_ref().unwrap().headers[0].clone());
    assert!(Data::replay(&bad).is_err());
}
