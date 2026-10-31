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
pub async fn run(args: &[String]) -> anyhow::Result<()> {
    let Some(o) = parse(args)? else {
        println!(
            "NightBuoy\n\nnightbuoy                         Open the graphical interface\nnightbuoy portable                Run the companion without opening a browser\nnightbuoy cli -f ROOT [OPTIONS]    Open the terminal interface\n\n-k, --key KEY            Private nb2 access key (visible in process arguments)\n-k, --prompt-key         Read the access key with hidden input\n--key-file FILE          Read the access key from a private file\n-i, --identity FILE      Encrypted identity recovery file; passphrase prompted\n--provider-token-file FILE  Your own scoped repository token\n--provider-credentials-file FILE  Private JSON: token or access_key + secret_key\n--print                  Print verified decrypted content instead of the TUI\n\nAn access key permits reading. Posting also needs an approved identity and provider permission.\nNo credentials or decrypted cache are saved by the terminal client."
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
    if o.print {
        for e in client.objects() {
            println!(
                "{}",
                json!({"id":e.id,"parent":e.parent,"kind":e.kind,"content":client.contents[&e.hash]})
            );
        }
        return Ok(());
    }
    anyhow::ensure!(
        io::stdin().is_terminal() && io::stdout().is_terminal(),
        "interactive CLI needs a terminal; use --print for explicit plaintext output"
    );
    interface(&mut client).await
}
#[derive(Default)]
struct Draft {
    id: Option<String>,
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
            if let Some(d) = &draft {
                let text = if d.field == 0 {
                    format!("Title: {}▏\n\n{}", d.title, d.body)
                } else {
                    format!("Title: {}\n\n{}▏", d.title, d.body)
                };
                frame.render_widget(
                    Paragraph::new(text).wrap(Wrap { trim: false }).block(
                        Block::default().borders(Borders::ALL).title(format!(
                            "New {} · Tab field · Ctrl+S submit · Esc cancel",
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
            if draft.is_none() && refreshed.elapsed() > Duration::from_secs(30) {
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
        if !(k.code == KeyCode::Char('d') && k.modifiers.contains(KeyModifiers::CONTROL)) {
            confirm_discard = false;
        }
        if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
            break;
        }
        if let Some(d) = &mut draft {
            if k.code == KeyCode::Char('d')
                && k.modifiers.contains(KeyModifiers::CONTROL)
                && client.has_pending()
            {
                if !confirm_discard {
                    status="Ctrl+D again discards the local pending signature. The draft keeps its object ID. Review before resubmitting.".into();
                    confirm_discard = true;
                    continue;
                }
                match client.discard_pending().await {Ok(true)=>{draft=None;status="The previous submission was already confirmed.".into();},Ok(false)=>status="Local pending signature discarded. Review the retained draft, then Ctrl+S to submit with current permissions.".into(),Err(e)=>status=format!("Could not verify before discard: {e}")};
                confirm_discard = false;
                continue;
            }
            if k.code == KeyCode::Esc {
                draft = None;
                continue;
            }
            if k.code == KeyCode::Char('s') && k.modifiers.contains(KeyModifiers::CONTROL) {
                let payload = match d.kind.as_str() {
                    "board" => json!({"title":d.title,"description":d.body}),
                    "topic" => json!({"title":d.title,"body":d.body}),
                    _ => json!({"body":d.body}),
                };
                match client
                    .post(&d.kind, &d.parent, payload, d.id.clone(), "")
                    .await
                {
                    Ok(()) => {
                        draft = None;
                        status = "Posted and verified".into();
                    }
                    Err(e) => {
                        if let Some(id) = client.pending_id() {
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
            KeyCode::Char('q') => {
                if client.has_pending() && !confirm_quit {
                    status="Unconfirmed submission remains in memory. Press p to retry; q again discards it and exits.".into();
                    confirm_quit = true;
                } else {
                    break;
                }
            }
            KeyCode::Char('p') => {
                status = match client.retry_pending().await {
                    Ok(()) => "Submission confirmed".into(),
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
