use nightbuoy::{api, config::Config, replication, store::Store};
use std::sync::{Arc, Mutex};
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("identity") => {
            return nightbuoy::terminal::identity_command(
                &std::env::args().skip(2).collect::<Vec<_>>(),
            )
            .await;
        }
        Some("--help" | "-h") => return nightbuoy::terminal::run(&["--help".into()]).await,
        Some("--version" | "-V") => {
            println!("NightBuoy {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some("check-transports") => {
            // In particular, the S3 TLS stack needs platform root certificates.
            // This check opens no network connection and accepts no credentials.
            let _ = reqwest::Client::builder().no_proxy().build()?;
            let _ = nightbuoy::remote::s3_transport(None)?;
            println!("Provider TLS clients initialized.");
            return Ok(());
        }
        Some("gui") => return nightbuoy::portable::run_gui().await,
        Some(command)
            if !matches!(
                command,
                "cli" | "portable" | "serve" | "check-config" | "verify-archive" | "reset"
            ) =>
        {
            anyhow::bail!("Unknown command. Use nightbuoy --help.")
        }
        _ => {}
    }
    if std::env::args().nth(1).as_deref() == Some("cli") {
        return nightbuoy::terminal::run(&std::env::args().skip(2).collect::<Vec<_>>()).await;
    }
    if std::env::args().nth(1).as_deref() == Some("portable")
        || (std::env::args().nth(1).is_none()
            && std::env::var("NIGHTBUOY_DATA").is_err()
            && std::env::var("NIGHTBUOY_CONSENSUS_RPC").is_err())
    {
        return if std::env::args().nth(1).is_none() {
            nightbuoy::portable::run_gui().await
        } else {
            nightbuoy::portable::run().await
        };
    }
    let config = Config::load()?;
    if std::env::args().nth(1).as_deref() == Some("check-config") {
        println!("configuration valid");
        return Ok(());
    }
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).is_some_and(|s| s == "verify-archive") {
        let path = args
            .get(2)
            .ok_or_else(|| anyhow::anyhow!("usage: nightbuoy verify-archive FILE"))?;
        let archive: nightbuoy::model::Archive = serde_json::from_slice(&std::fs::read(path)?)?;
        let data = nightbuoy::model::Data::replay(&archive)?;
        println!(
            "{}",
            serde_json::json!({"community":data.community(),"branch":data.branch(),"tip":data.tip,"records":data.events.len()})
        );
        return Ok(());
    }
    let mut store = Store::open(&config.data)?;
    if args.get(1).is_some_and(|s| s == "reset") {
        anyhow::ensure!(
            args.len() == 5 && args[4] == "--acknowledge-history-reset",
            "usage: nightbuoy reset ARCHIVE TRUSTED_COMMUNITY_FINGERPRINT --acknowledge-history-reset (service must be stopped)"
        );
        anyhow::ensure!(
            config.testing || config.read_only,
            "direct reset is restricted to loopback tests; production recovery must be confirmed by a fresh consensus network"
        );
        let archive: nightbuoy::model::Archive = serde_json::from_slice(&std::fs::read(&args[2])?)?;
        let data = nightbuoy::model::Data::replay(&archive)?;
        anyhow::ensure!(data.community() == args[3], "trusted fingerprint mismatch");
        if let Some(old) = &store.data {
            let retained = config.data.join("retained-resets");
            std::fs::create_dir_all(&retained)?;
            std::fs::write(
                retained.join(format!("{}.json", old.tip)),
                serde_json::to_vec(&old.archive)?,
            )?;
        }
        store.save(data)?;
        store.db.execute("DELETE FROM sessions", [])?;
        let _ = std::fs::remove_file(config.data.join("bootstrap-token"));
        println!(
            "Verified checkpoint restored; former history retained. Restart the service and explicitly select the branch in each client."
        );
        return Ok(());
    }

    if config.read_only {
        anyhow::ensure!(
            std::env::var("NIGHTBUOY_CONSENSUS_RPC").is_err(),
            "a read-only service must not run a consensus application"
        );
        if let Ok(path) = std::env::var("NIGHTBUOY_ARCHIVE_FILE") {
            let bytes = std::fs::read(path)?;
            anyhow::ensure!(
                bytes.len() <= nightbuoy::model::MAX_ARCHIVE_BYTES,
                "archive capacity exceeded"
            );
            let archive: nightbuoy::model::Archive = serde_json::from_slice(&bytes)?;
            let data = if let Some(old) = &store.data {
                old.catch_up(&archive)?
            } else {
                nightbuoy::model::Data::replay(&archive)?
            };
            store.save(data)?;
        }
    }
    if store.data.is_none() {
        eprintln!(
            "NightBuoy is unconfigured. Read the one-use setup token from the protected bootstrap-token file in the data directory."
        );
    }
    let mut client_builder = reqwest::Client::builder();
    if let Ok(proxy) = std::env::var("NIGHTBUOY_SOCKS_PROXY") {
        anyhow::ensure!(
            proxy.starts_with("socks5h://"),
            "use socks5h so DNS also passes through Tor"
        );
        client_builder = client_builder.proxy(
            reqwest::Proxy::all(&proxy)?
                .no_proxy(reqwest::NoProxy::from_string("localhost,127.0.0.1,::1")),
        );
    }
    let client = client_builder
        .user_agent("NightBuoy/0.1")
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let mut state = api::App {
        store: Arc::new(Mutex::new(store)),
        config: Arc::new(config.clone()),
        client,
        replication: Arc::new(Mutex::new(Default::default())),
        consensus: None,
    };
    if let Ok(rpc) = std::env::var("NIGHTBUOY_CONSENSUS_RPC") {
        let genesis = std::env::var("NIGHTBUOY_CONSENSUS_GENESIS")
            .map_err(|_| anyhow::anyhow!("NIGHTBUOY_CONSENSUS_GENESIS is required"))?;
        let engine = nightbuoy::consensus::Consensus::new(
            rpc,
            std::path::Path::new(&genesis),
            state.store.clone(),
        )?;
        let abci: std::net::SocketAddr = std::env::var("NIGHTBUOY_ABCI_LISTEN")
            .unwrap_or("127.0.0.1:26658".into())
            .parse()?;
        anyhow::ensure!(abci.ip().is_loopback(), "ABCI must bind only to loopback");
        let server =
            tendermint_abci::ServerBuilder::new(128 * 1024 * 1024).bind(abci, engine.clone())?;
        std::thread::spawn(move || {
            if server.listen().is_err() {
                std::process::exit(1);
            }
        });
        state.consensus = Some(Arc::new(engine));
    } else {
        anyhow::ensure!(
            config.testing || config.read_only,
            "Production deployments require configured consensus; local-only mode is restricted to tests."
        );
    }
    let worker = state.clone();
    tokio::spawn(async move {
        replication::run(worker).await;
    });
    let listener = tokio::net::TcpListener::bind(&config.listen).await?;
    eprintln!(
        "NightBuoy listening on {} (public origin {})",
        config.listen, config.public_url
    );
    axum::serve(listener, api::router(state))
        .with_graceful_shutdown(async {
            #[cfg(unix)]
            {
                let mut terminate =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("install termination signal handler");
                tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
            }
        })
        .await?;
    Ok(())
}
