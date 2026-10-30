use crate::{
    crypto::*,
    model::{Data, Device},
};
use rusqlite::{Connection, OptionalExtension, params};
use std::{fs, path::Path};
pub struct Store {
    pub db: Connection,
    pub data: Option<Data>,
    pub publisher: [u8; 32],
    pub identity: [u8; 32],
    pub bootstrap: String,
    pub _lock: fs::File,
}
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
fn secret(dir: &Path, name: &str) -> anyhow::Result<[u8; 32]> {
    let p = dir.join(name);
    if !p.exists() {
        use std::io::Write;
        let mut o = fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        o.open(&p)?.write_all(&random::<32>())?;
    }
    fs::read(p)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid secret length"))
}
impl Store {
    pub fn open(dir: &Path) -> anyhow::Result<Self> {
        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(dir.join("instance.lock"))?;
        lock.try_lock().map_err(|_| {
            anyhow::anyhow!(
                "another process is using this data directory; stop it before restoring/resetting"
            )
        })?;
        let publisher = secret(dir, "publisher.key")?;
        let identity = secret(dir, "identity.key")?;
        let db = Connection::open(dir.join("nightbuoy.sqlite"))?;
        db.execute_batch("PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;CREATE TABLE IF NOT EXISTS state(id INTEGER PRIMARY KEY CHECK(id=1),json TEXT NOT NULL);CREATE TABLE IF NOT EXISTS accounts(idx TEXT PRIMARY KEY,member TEXT NOT NULL,sealed TEXT NOT NULL);CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,member TEXT NOT NULL,expires INTEGER NOT NULL);CREATE TABLE IF NOT EXISTS challenges(id TEXT PRIMARY KEY,body TEXT NOT NULL,expires INTEGER NOT NULL);CREATE TABLE IF NOT EXISTS oauth(state TEXT PRIMARY KEY,provider TEXT NOT NULL,verifier TEXT NOT NULL,return_to TEXT NOT NULL,expires INTEGER NOT NULL);CREATE TABLE IF NOT EXISTS enrollment(token TEXT PRIMARY KEY,issuer TEXT NOT NULL,subject TEXT NOT NULL,expires INTEGER NOT NULL);CREATE TABLE IF NOT EXISTS requests(member TEXT PRIMARY KEY,json TEXT NOT NULL,verified INTEGER NOT NULL);CREATE TABLE IF NOT EXISTS limits(key TEXT PRIMARY KEY,count INTEGER NOT NULL,expires INTEGER NOT NULL);")?;
        let raw: Option<String> = db
            .query_row("SELECT json FROM state WHERE id=1", [], |r| r.get(0))
            .optional()?;
        let data = raw
            .map(|r| serde_json::from_str::<crate::model::Archive>(&r))
            .transpose()?
            .map(|a| Data::replay_unconfirmed(&a))
            .transpose()?;
        let bootstrap = if data.is_none() {
            let f = dir.join("bootstrap-token");
            if !f.exists() {
                fs::write(&f, token())?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&f, fs::Permissions::from_mode(0o600))?;
                }
            }
            fs::read_to_string(f)?.trim().into()
        } else {
            String::new()
        };
        Ok(Self {
            db,
            data,
            publisher,
            identity,
            bootstrap,
            _lock: lock,
        })
    }
    pub fn save(&mut self, next: Data) -> anyhow::Result<()> {
        let json = serde_json::to_string(&next.archive)?;
        anyhow::ensure!(
            json.len() <= crate::model::MAX_ARCHIVE_BYTES,
            "pilot community capacity of 64 MiB reached; export and upgrade before adding content"
        );
        self.db.execute("INSERT INTO state(id,json) VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET json=excluded.json",[json])?;
        self.data = Some(next);
        Ok(())
    }
    pub fn publication_key(&self) -> String {
        b64(authority(&self.publisher).verifying_key().to_bytes())
    }
    pub fn session(&self, member: &str) -> anyhow::Result<String> {
        self.db
            .execute("DELETE FROM sessions WHERE expires<?1", [now()])?;
        let t = token();
        self.db.execute(
            "INSERT INTO sessions VALUES(?1,?2,?3)",
            params![hash(&t), member, now() + 3600],
        )?;
        Ok(t)
    }
    pub fn rate(&self, key: &str, max: i64) -> anyhow::Result<()> {
        let t = now();
        self.db
            .execute("DELETE FROM limits WHERE expires<?1", [t])?;
        self.db.execute(
            "INSERT INTO limits VALUES(?1,1,?2) ON CONFLICT(key) DO UPDATE SET count=count+1",
            params![key, t + 60],
        )?;
        let count: i64 =
            self.db
                .query_row("SELECT count FROM limits WHERE key=?1", [key], |r| r.get(0))?;
        anyhow::ensure!(count <= max, "rate limit exceeded");
        Ok(())
    }
    pub fn pending(&self) -> anyhow::Result<Vec<serde_json::Value>> {
        let mut st = self
            .db
            .prepare("SELECT json,verified FROM requests ORDER BY rowid LIMIT 2000")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?)))?;
        rows.map(|r| {
            let (json, verified) = r?;
            let d: Device = serde_json::from_str(&json)?;
            Ok(serde_json::json!({"device":d,"verified":verified}))
        })
        .collect()
    }
    pub fn device(&self, id: &str) -> anyhow::Result<Option<Device>> {
        if let Some(m) = self.data.as_ref().and_then(|d| d.view().members.get(id)) {
            return Ok(Some(m.device.clone()));
        }
        let raw: Option<String> = self
            .db
            .query_row("SELECT json FROM requests WHERE member=?1", [id], |r| {
                r.get(0)
            })
            .optional()?;
        Ok(raw.map(|s| serde_json::from_str(&s)).transpose()?)
    }
    pub fn challenge(&self, body: &str) -> anyhow::Result<String> {
        self.db
            .execute("DELETE FROM challenges WHERE expires<?1", [now()])?;
        let id = token();
        self.db.execute(
            "INSERT INTO challenges VALUES(?1,?2,?3)",
            params![hash(&id), body, now() + 120],
        )?;
        Ok(id)
    }
    pub fn consume(&self, id: &str, body: &str) -> anyhow::Result<()> {
        let count = self.db.execute(
            "DELETE FROM challenges WHERE id=?1 AND body=?2 AND expires>=?3",
            params![hash(id), body, now()],
        )?;
        anyhow::ensure!(count == 1, "expired or reused challenge");
        Ok(())
    }
    pub fn request(&self, device: &Device, enrollment: Option<&str>) -> anyhow::Result<bool> {
        let mut verified = false;
        if let Some(t) = enrollment {
            let account: Option<(String, String)> = self
                .db
                .query_row(
                    "SELECT issuer,subject FROM enrollment WHERE token=?1 AND expires>=?2",
                    params![hash(t), now()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((format, sealed)) = account {
                anyhow::ensure!(format == "sealed-v1", "invalid enrollment record");
                let plain = unseal(&self.identity, &sealed, b"nightbuoy-enrollment-v1")?;
                let idx = keyed(&self.identity, &plain);
                let existing: Option<String> = self
                    .db
                    .query_row("SELECT member FROM accounts WHERE idx=?1", [&idx], |r| {
                        r.get(0)
                    })
                    .optional()?;
                anyhow::ensure!(
                    existing.as_ref().is_none_or(|x| x == &device.id),
                    "this forge account already enrolled another identity; restore its recovery file"
                );
                let sealed = seal(&self.identity, &plain, idx.as_bytes())?;
                self.db.execute(
                    "INSERT OR IGNORE INTO accounts VALUES(?1,?2,?3)",
                    params![idx, device.id, sealed],
                )?;
                verified = true;
            }
        }
        let required = self
            .data
            .as_ref()
            .is_some_and(|d| d.view().policy.identity == "forge");
        anyhow::ensure!(
            !required || verified,
            "verify a configured forge before enrolling"
        );
        self.db.execute("INSERT INTO requests VALUES(?1,?2,?3) ON CONFLICT(member) DO UPDATE SET verified=MAX(verified,excluded.verified)",params![device.id,serde_json::to_string(device)?,verified])?;
        Ok(verified)
    }
}
