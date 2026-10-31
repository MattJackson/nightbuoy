//! Interactive local client. Secrets are collected before raw terminal mode.
use crate::{
    client::{AccessKey, Client},
    client_crypto::Identity,
};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};
use serde_json::json;
use std::{
    io::{self, IsTerminal},
    path::PathBuf,
    time::{Duration, Instant},
};
use zeroize::Zeroize;

#[derive(Default)]
struct Options {
    root: String,
    key: Option<String>,
    key_file: Option<PathBuf>,
    prompt_key: bool,
    identity: Option<PathBuf>,
    token_file: Option<PathBuf>,
    credentials_file: Option<PathBuf>,
    print: bool,
    pending_file: Option<PathBuf>,
    export_identity: Option<PathBuf>,
}
fn parse(args: &[String]) -> anyhow::Result<Option<Options>> {
    let mut o = Options::default();
    let mut i = 0;
    while i < args.len() {
        let name = &args[i];
        if matches!(name.as_str(), "--help" | "-h") {
            return Ok(None);
        }
        if name == "--print" {
            o.print = true;
            i += 1;
            continue;
        }
        if name == "--prompt-key" {
            o.prompt_key = true;
            i += 1;
            continue;
        }
        if matches!(name.as_str(), "-k" | "--key")
            && args.get(i + 1).is_none_or(|s| s.starts_with('-'))
        {
            o.prompt_key = true;
            i += 1;
            continue;
        }
        let value = args
            .get(i + 1)
            .ok_or_else(|| anyhow::anyhow!("missing value for option"))?
            .clone();
        match name.as_str() {
            "-f" | "--forum" => o.root = value,
            "-k" | "--key" => o.key = Some(value),
            "--key-file" => o.key_file = Some(value.into()),
            "--pending-file" => o.pending_file = Some(value.into()),
            "--export-identity" => o.export_identity = Some(value.into()),
            "-i" | "--identity" => o.identity = Some(value.into()),
            "--provider-token-file" => o.token_file = Some(value.into()),
            "--provider-credentials-file" => o.credentials_file = Some(value.into()),
            _ => anyhow::bail!("unknown CLI option; use nightbuoy cli --help"),
        }
        i += 2;
    }
    anyhow::ensure!(
        !o.root.is_empty(),
        "a storage root is required: nightbuoy cli -f URL"
    );
    anyhow::ensure!(
        usize::from(o.key.is_some())
            + usize::from(o.key_file.is_some())
            + usize::from(o.prompt_key)
            <= 1,
        "choose one access-key input"
    );
    anyhow::ensure!(
        o.token_file.is_none() || o.credentials_file.is_none(),
        "choose one provider credential file"
    );
    Ok(Some(o))
}
fn secret_file(path: &std::path::Path) -> anyhow::Result<String> {
    let f = std::fs::File::open(path)?;
    anyhow::ensure!(f.metadata()?.len() <= 30000, "secret file too large");
    use std::io::Read;
    let mut v = String::new();
    f.take(30001).read_to_string(&mut v)?;
    Ok(v.trim().to_owned())
}
pub async fn identity_command(args: &[String]) -> anyhow::Result<()> {
    if args.is_empty() || args.iter().any(|s| matches!(s.as_str(), "--help" | "-h")) {
        println!(
            "nightbuoy identity create NEW_FILE\nnightbuoy identity inspect FILE\n\nPassphrases are entered with hidden input. Creation never overwrites an existing file.\nAn identity must still receive forum membership and key access before posting."
        );
        return Ok(());
    }
    anyhow::ensure!(
        args.len() == 2,
        "usage: nightbuoy identity create|inspect FILE"
    );
    let path = std::path::Path::new(&args[1]);
    match args[0].as_str() {
        "create" => {
            anyhow::ensure!(
                !path.exists(),
                "choose a new recovery filename; existing files are preserved"
            );
            let password = zeroize::Zeroizing::new(rpassword::prompt_password(
                "Unique passphrase (20–1024 characters): ",
            )?);
            let confirmation =
                zeroize::Zeroizing::new(rpassword::prompt_password("Repeat passphrase: ")?);
            anyhow::ensure!(*password == *confirmation, "passphrases do not match");
            anyhow::ensure!(
                (20..=1024).contains(&password.encode_utf16().count()),
                "use a unique passphrase of 20–1024 characters"
            );
            eprintln!("Creating your portable identity…");
            let identity = Identity::generate()?;
            crate::client_crypto::write_private_file(path, &identity.lock(&password, "", "")?)?;
            println!(
                "{}",
                json!({"device":identity.device,"community":"","checkpoint":""})
            );
            eprintln!("Encrypted recovery file saved. Keep it and your passphrase separate.");
        }
        "inspect" => {
            let bytes = secret_file(path)?;
            let password =
                zeroize::Zeroizing::new(rpassword::prompt_password("Identity passphrase: ")?);
            let identity = Identity::unlock(bytes.as_bytes(), &password)?;
            println!(
                "{}",
                json!({"device":identity.device,"community":identity.community,"checkpoint":identity.checkpoint})
            );
        }
        _ => anyhow::bail!("usage: nightbuoy identity create|inspect FILE"),
    }
    Ok(())
}
pub async fn run(args: &[String]) -> anyhow::Result<()> {
    let Some(o) = parse(args)? else {
        println!(
            "NightBuoy\n\nnightbuoy                         Open the graphical interface\nnightbuoy portable                Run the companion without opening a browser\nnightbuoy cli -f ROOT [OPTIONS]    Open the terminal interface\nnightbuoy identity create FILE    Create an encrypted portable identity\n\n-k, --key KEY            Private nb2 access key (visible in process arguments)\n-k, --prompt-key         Read the access key with hidden input\n--key-file FILE          Read the access key from a private file\n-i, --identity FILE      Encrypted identity recovery file; passphrase prompted\n--provider-token-file FILE  Your own scoped repository token\n--provider-credentials-file FILE  Private JSON: token or access_key + secret_key\n--pending-file FILE      Import private encrypted unconfirmed submissions\n--export-identity FILE   Save an updated encrypted identity checkpoint on exit\n--print                  Print verified decrypted content instead of the TUI\n\nAn access key permits reading. Posting also needs an approved identity and provider permission.\nNo credentials or decrypted cache are saved by the terminal client."
        );
        return Ok(());
    };
    let mut key = if let Some(path) = o.key_file {
        Some(secret_file(&path)?)
    } else {
        o.key
    };
    if o.prompt_key {
        key = Some(rpassword::prompt_password("Forum access key: ")?);
    }
    let access = key.as_deref().map(AccessKey::parse).transpose();
    if let Some(k) = &mut key {
        // Clear this allocation; caller/process history may retain argument copies.
        k.zeroize();
    }
    let access = access?;
    let identity = if let Some(path) = o.identity {
        let bytes = secret_file(&path)?;
        let mut pass = rpassword::prompt_password("Identity passphrase: ")?;
        let result = Identity::unlock(bytes.as_bytes(), &pass);
        pass.zeroize();
        Some(result?)
    } else {
        None
    };
    let token = o
        .token_file
        .as_deref()
        .map(secret_file)
        .transpose()?
        .unwrap_or_default();
    #[derive(serde::Deserialize, Default)]
    #[serde(deny_unknown_fields)]
    struct Credentials {
        #[serde(default)]
        token: String,
        #[serde(default)]
        access_key: String,
        #[serde(default)]
        secret_key: String,
    }
    let credentials = if let Some(path) = o.credentials_file {
        serde_json::from_str::<Credentials>(&secret_file(&path)?)?
    } else {
        Credentials {
            token,
            ..Default::default()
        }
    };
    eprintln!("Opening encrypted forum…");
    let mut client = Client::open_with_credentials(
        &o.root,
        access,
        identity,
        credentials.token,
        credentials.access_key,
        credentials.secret_key,
        std::env::var("NIGHTBUOY_TESTING").as_deref() == Ok("1"),
    )
    .await?;
    if let Some(path) = o.pending_file {
        use std::io::Read;
        let file = std::fs::File::open(path)?;
        let mut bytes = vec![];
        file.take((crate::sealed_storage::MAX_FRAME + 2) as u64)
            .read_to_end(&mut bytes)?;
        anyhow::ensure!(
            bytes.len() <= crate::sealed_storage::MAX_FRAME + 1,
            "pending export too large"
        );
        eprintln!(
            "Imported {} private pending submission(s). Press p to retry or e to export.",
            client.import_pending(&bytes)?
        );
    }
    if o.print {
        for e in client.objects() {
            println!(
                "{}",
                json!({"id":e.id,"parent":e.parent,"kind":e.kind,"content":client.contents[&e.hash]})
            );
        }
    } else {
        anyhow::ensure!(
            io::stdin().is_terminal() && io::stdout().is_terminal(),
            "interactive CLI needs a terminal; use --print for explicit plaintext output"
        );
        interface(&mut client).await?;
    }
    if let Some(path) = o.export_identity {
        let identity = client.identity.as_ref().ok_or_else(|| {
            anyhow::anyhow!("import an identity before exporting an updated recovery checkpoint")
        })?;
        let password =
            zeroize::Zeroizing::new(rpassword::prompt_password("Recovery export passphrase: ")?);
        let confirmation =
            zeroize::Zeroizing::new(rpassword::prompt_password("Repeat passphrase: ")?);
        anyhow::ensure!(*password == *confirmation, "passphrases do not match");
        let checkpoint = format!(
            "p:{}",
            crate::portable_protocol::head(&client.data.archive)?
        );
        crate::client_crypto::write_private_file(
            &path,
            &identity.lock(&password, &client.data.community(), &checkpoint)?,
        )?;
        eprintln!("Updated encrypted recovery checkpoint saved.");
    }
    Ok(())
}
#[derive(Default)]
struct Draft {
    payload: serde_json::Value,
    id: Option<String>,
    previous: String,
    kind: String,
    parent: String,
    title: String,
    body: String,
    field: usize,
}
async fn interface(client: &mut Client) -> anyhow::Result<()> {
    // DefaultTerminal's guard restores cursor, alternate screen and raw mode on every return.
    let mut terminal = ratatui::init();
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            ratatui::restore();
        }
    }
    let _restore = Restore;
    let mut selected = 0usize;
    let mut status = String::from("↑↓ select · n new · Enter reply · r refresh · q quit");
    let mut draft: Option<Draft> = None;
    let mut export_path: Option<String> = None;
    let mut refreshed = Instant::now();
    let mut confirm_quit = false;
    let mut confirm_discard = false;
    loop {
        let objects = client.objects();
        let mut objects = objects.into_iter().collect::<Vec<_>>();
        objects.sort_by_key(|e| {
            client
                .data
                .events
                .iter()
                .position(|x| x.hash == e.hash)
                .unwrap_or(0)
        });
        selected = selected.min(objects.len().saturating_sub(1));
        let target = objects
            .get(selected)
            .map(|e| (e.kind.clone(), e.id.clone(), e.parent.clone()));
        terminal.draw(|frame| {
            let areas = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(5), Constraint::Length(3)])
                .split(frame.area());
            if let Some(path)=&export_path {
                frame.render_widget(Paragraph::new(format!("Save {} private encrypted submission(s)\n\n{}▏\n\nChoose a new filename. Existing files are preserved.",client.pending_count(),path)).wrap(Wrap{trim:false}).block(Block::default().borders(Borders::ALL).title("Export pending · Enter save · Esc return")),areas[0]);
            } else if let Some(d) = &draft {
                let text = if d.field == 0 {
                    format!("Title: {}▏\n\n{}", d.title, d.body)
                } else {
                    format!("Title: {}\n\n{}▏", d.title, d.body)
                };
                frame.render_widget(
                    Paragraph::new(text).wrap(Wrap { trim: false }).block(
                        Block::default().borders(Borders::ALL).title(format!(
                            "New {} · Tab field · Ctrl+S submit · Ctrl+E export pending · Esc cancel",
                            d.kind
                        )),
                    ),
                    areas[0],
                );
            } else {
                let columns = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
                    .split(areas[0]);
                let items = objects
                    .iter()
                    .map(|e| {
                        let p = &client.contents[&e.hash];
                        let title = p["title"]
                            .as_str()
                            .or_else(|| p["body"].as_str())
                            .unwrap_or("");
                        ListItem::new(format!(
                            "{}: {}",
                            e.kind,
                            title
                                .lines()
                                .next()
                                .unwrap_or("")
                                .chars()
                                .take(100)
                                .collect::<String>()
                        ))
                    })
                    .collect::<Vec<_>>();
                let mut state = ListState::default().with_selected(if objects.is_empty() {
                    None
                } else {
                    Some(selected)
                });
                frame.render_stateful_widget(
                    List::new(items)
                        .highlight_style(Style::default().bg(Color::DarkGray))
                        .block(Block::default().borders(Borders::ALL).title(
                            if client.can_write() {
                                "NightBuoy"
                            } else {
                                "NightBuoy · read only"
                            },
                        )),
                    columns[0],
                    &mut state,
                );
                let detail = objects
                    .get(selected)
                    .map(|e| {
                        let p = &client.contents[&e.hash];
                        format!(
                            "{}\n\n{}\n{}\n\nIdentity: {}\nObject: {}",
                            p["title"].as_str().unwrap_or(""),
                            p["body"].as_str().unwrap_or(""),
                            p["description"].as_str().unwrap_or(""),
                            e.author,
                            e.id
                        )
                    })
                    .unwrap_or_else(|| {
                        "No readable posts. Press n to create a board if you are an administrator."
                            .into()
                    });
                frame.render_widget(
                    Paragraph::new(detail).wrap(Wrap { trim: false }).block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title("Verified content"),
                    ),
                    columns[1],
                );
            }
            frame.render_widget(
                Paragraph::new(status.as_str())
                    .wrap(Wrap { trim: false })
                    .block(Block::default().borders(Borders::ALL)),
                areas[1],
            );
        })?;
        drop(objects);
        if !event::poll(Duration::from_millis(150))? {
            if draft.is_none()
                && export_path.is_none()
                && refreshed.elapsed() > Duration::from_secs(30)
            {
                status = match client.refresh().await {
                    Ok(()) => "Synced · n new · Enter reply · r refresh · q quit".into(),
                    Err(e) => format!("Refresh failed: {e}"),
                };
                refreshed = Instant::now();
            }
            continue;
        }
        let Event::Key(k) = event::read()? else {
            continue;
        };
        if k.kind != KeyEventKind::Press {
            continue;
        }
        if k.code != KeyCode::Char('d')
            || (draft.is_some() && !k.modifiers.contains(KeyModifiers::CONTROL))
        {
            confirm_discard = false;
        }
        if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
            break;
        }
        if let Some(path) = &mut export_path {
            match k.code {
                KeyCode::Esc => export_path = None,
                KeyCode::Backspace => {
                    path.pop();
                }
                KeyCode::Enter => {
                    let result = client.export_pending().and_then(|frame| {
                        crate::client_crypto::write_private_file(std::path::Path::new(path), &frame)
                    });
                    match result {
                        Ok(()) => {
                            status="Private encrypted pending copy saved. Keep your identity recovery file too.".into();
                            export_path = None;
                        }
                        Err(e) => status = format!("Export failed: {e}"),
                    }
                }
                KeyCode::Char(ch)
                    if !k
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                        && path.len() < 4096 =>
                {
                    path.push(ch)
                }
                _ => {}
            }
            continue;
        }
        if k.code == KeyCode::Char('e')
            && k.modifiers.contains(KeyModifiers::CONTROL)
            && client.has_pending()
        {
            export_path = Some("nightbuoy-pending.nbp".into());
            continue;
        }
        if let Some(d) = &mut draft {
            if k.code == KeyCode::Char('d')
                && k.modifiers.contains(KeyModifiers::CONTROL)
                && client.has_pending()
            {
                if !confirm_discard {
                    status = format!(
                        "Ctrl+D again discards saved submission {}. This draft keeps its own object ID; Ctrl+E exports saved submissions first.",
                        client.pending_id().unwrap_or_default()
                    );
                    confirm_discard = true;
                    continue;
                }
                let same_draft = d.id == client.pending_id();
                match client.discard_pending().await {Ok(true)=>{if same_draft{draft=None;}status="The previous submission was already confirmed.".into();},Ok(false)=>status="Local pending signature discarded. Review the retained draft, then Ctrl+S to submit with current permissions.".into(),Err(e)=>status=format!("Could not verify before discard: {e}")};
                confirm_discard = false;
                continue;
            }
            if k.code == KeyCode::Esc {
                draft = None;
                continue;
            }
            if k.code == KeyCode::Char('s') && k.modifiers.contains(KeyModifiers::CONTROL) {
                let mut payload = if d.payload.is_object() {
                    d.payload.clone()
                } else {
                    json!({})
                };
                match d.kind.as_str() {
                    "board" => {
                        payload["title"] = json!(d.title);
                        payload["description"] = json!(d.body);
                    }
                    "topic" => {
                        payload["title"] = json!(d.title);
                        payload["body"] = json!(d.body);
                    }
                    _ => payload["body"] = json!(d.body),
                }
                let had_pending = client.has_pending();
                match client
                    .post(&d.kind, &d.parent, payload, d.id.clone(), &d.previous)
                    .await
                {
                    Ok(()) => {
                        draft = None;
                        status = format!(
                            "Posted and verified · {} pending · p retry · e export",
                            client.pending_count()
                        );
                    }
                    Err(e) => {
                        if d.id.is_none()
                            && !had_pending
                            && let Some(id) = client.pending_id()
                        {
                            d.id = Some(id);
                        }
                        status = format!(
                            "Post failed: {e} · Ctrl+D twice to review with current permissions"
                        );
                    }
                };
                continue;
            }
            if k.code == KeyCode::Tab {
                d.field = if d.kind == "reply" { 1 } else { 1 - d.field };
                continue;
            }
            let field = if d.field == 0 {
                &mut d.title
            } else {
                &mut d.body
            };
            match k.code {
                KeyCode::Backspace => {
                    field.pop();
                }
                KeyCode::Enter if d.field == 1 => field.push('\n'),
                KeyCode::Char(ch)
                    if !k
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                        && field.len() < 60000 =>
                {
                    field.push(ch)
                }
                _ => {}
            }
            continue;
        }
        match k.code {
            KeyCode::Char('v') if client.has_pending() => match client.pending_draft() {
                Ok(p) => {
                    let field = usize::from(matches!(p.kind.as_str(), "reply" | "delete"));
                    draft = Some(Draft {
                        id: Some(p.id),
                        previous: p.previous,
                        kind: p.kind,
                        parent: p.parent,
                        title: p.payload["title"].as_str().unwrap_or("").into(),
                        body: p.payload["body"]
                            .as_str()
                            .or_else(|| p.payload["description"].as_str())
                            .unwrap_or("")
                            .into(),
                        field,
                        payload: p.payload,
                    });
                    status="Review the saved draft. Ctrl+D twice discards its old signature before resubmitting.".into();
                }
                Err(e) => status = format!("Review failed: {e}"),
            },
            KeyCode::Char('d') if client.has_pending() => {
                if !confirm_discard {
                    status="Press d again to discard this local pending copy after checking verified history. v reviews it; e exports it.".into();
                    confirm_discard = true;
                } else {
                    status = match client.discard_pending().await {
                        Ok(accepted) => format!(
                            "{} · {} pending",
                            if accepted {
                                "Submission was already confirmed"
                            } else {
                                "Local pending copy discarded"
                            },
                            client.pending_count()
                        ),
                        Err(e) => format!("Could not verify before discard: {e}"),
                    };
                    confirm_discard = false;
                }
            }
            KeyCode::Char('e') if client.has_pending() => {
                export_path = Some("nightbuoy-pending.nbp".into())
            }
            KeyCode::Char('q') => {
                if client.has_pending() && !confirm_quit {
                    status="Unconfirmed submission remains in memory. Press p to retry, e to export; q again discards it and exits.".into();
                    confirm_quit = true;
                } else {
                    break;
                }
            }
            KeyCode::Char('p') => {
                status = match client.retry_pending().await {
                    Ok(()) => format!(
                        "Submission confirmed · {} pending · p retry · v review · e export",
                        client.pending_count()
                    ),
                    Err(e) => format!("Retry failed: {e}"),
                };
                confirm_quit = false;
            }
            KeyCode::Down => selected = selected.saturating_add(1),
            KeyCode::Up => selected = selected.saturating_sub(1),
            KeyCode::Char('r') => {
                status = match client.refresh().await {
                    Ok(()) => "Synced".into(),
                    Err(e) => format!("Refresh failed: {e}"),
                };
                refreshed = Instant::now();
            }
            KeyCode::Char('n') | KeyCode::Enter if client.can_write() && client.has_pending()=>status="Saved submissions need attention first: p retries, v reviews, e exports, d discards a local copy.".into(),
            KeyCode::Char('n') | KeyCode::Enter if client.can_write() => {
                let (kind, parent) = match target {
                    Some((kind, id, parent)) if k.code == KeyCode::Enter => {
                        if kind == "board" {
                            ("topic", id)
                        } else if kind == "topic" {
                            ("reply", id)
                        } else {
                            ("reply", parent)
                        }
                    }
                    Some((kind, id, _)) if kind == "board" => ("topic", id),
                    _ => ("board", String::new()),
                };
                draft = Some(Draft {
                    kind: kind.into(),
                    parent,
                    field: usize::from(kind == "reply"),
                    ..Default::default()
                });
            }
            _ => {}
        }
    }
    Ok(())
}
