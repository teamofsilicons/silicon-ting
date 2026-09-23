use chrono::{DateTime, Months, Utc};
use futures_util::{SinkExt, StreamExt};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use ting_client::*;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    sync::{Notify, RwLock, mpsc, oneshot},
};
use tokio_tungstenite::{connect_async, tungstenite::Message};
#[cfg(unix)]
type LocalStream = tokio::net::UnixStream;
#[cfg(windows)]
type LocalStream = tokio::net::windows::named_pipe::NamedPipeServer;
struct LocalListener {
    #[cfg(unix)]
    inner: tokio::net::UnixListener,
    #[cfg(unix)]
    _lock: fs::File,
    #[cfg(windows)]
    inner: LocalStream,
}
impl LocalListener {
    fn bind() -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::{
                fs::{OpenOptionsExt, PermissionsExt},
                io::AsRawFd,
            };
            let path = daemon_socket();
            if !path.parent().unwrap().is_dir() {
                return Err(Error::new(
                    "service_not_installed",
                    "The system service socket directory is missing.",
                    "Run the Ting installer to register the shared service.",
                    false,
                ));
            }
            private_dir(path.parent().unwrap())?;
            let lock = fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .mode(0o600)
                .open(path.parent().unwrap().join("daemon.lock"))
                .map_err(|_| Error::io())?;
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(Error::new(
                    "daemon_running",
                    "Another Ting daemon already owns this system service.",
                    "Use the existing system service.",
                    false,
                ));
            }
            if path.exists() {
                fs::remove_file(&path).map_err(|_| Error::io())?;
            }
            let inner = tokio::net::UnixListener::bind(&path).map_err(|_| Error::io())?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .map_err(|_| Error::io())?;
            Ok(Self { inner, _lock: lock })
        }
        #[cfg(windows)]
        {
            Ok(Self {
                inner: ting_client::windows::pipe(true)?,
            })
        }
    }
    async fn accept(&mut self) -> Result<LocalStream> {
        #[cfg(unix)]
        {
            self.inner
                .accept()
                .await
                .map(|(s, _)| s)
                .map_err(|_| Error::io())
        }
        #[cfg(windows)]
        {
            self.inner.connect().await.map_err(|_| Error::io())?;
            let next = ting_client::windows::pipe(false)?;
            Ok(std::mem::replace(&mut self.inner, next))
        }
    }
}
fn service_notify(message: &str) {
    #[cfg(target_os = "linux")]
    if let Ok(path) = std::env::var("NOTIFY_SOCKET") {
        use std::os::unix::net::UnixDatagram;
        if let Ok(socket) = UnixDatagram::unbound() {
            if let Some(name) = path.strip_prefix('@') {
                use std::os::linux::net::SocketAddrExt;
                if let Ok(address) =
                    std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())
                {
                    let _ = socket.send_to_addr(message.as_bytes(), &address);
                }
            } else {
                let _ = socket.send_to(message.as_bytes(), path);
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = message;
}
fn retention_cutoff() -> DateTime<Utc> {
    Utc::now()
        .checked_sub_months(Months::new(3))
        .expect("current date supports three-month subtraction")
}
fn retained(ting: &Value, cutoff: DateTime<Utc>) -> bool {
    ting["created_at"]
        .as_str()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .is_some_and(|created| created >= cutoff)
}
async fn recovery_delay(failures: &mut u32) {
    *failures = (*failures + 1).min(6);
    let base = (1u64 << (*failures - 1)).min(30);
    let jitter = (uuid::Uuid::new_v4().as_u128() % 21) as f64 / 100.0;
    tokio::time::sleep(Duration::from_secs_f64(
        (base as f64 * (1.0 + jitter)).min(30.0),
    ))
    .await;
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
fn sql(_: rusqlite::Error) -> Error {
    Error::io()
}
fn digest(s: &str) -> String {
    format!("{:x}", Sha256::digest(s.as_bytes()))
}
fn field<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::input(format!("Missing {k}.")))
}
struct Store {
    db: Mutex<Connection>,
}
#[derive(Clone)]
struct Hook {
    id: String,
    profile: String,
    api: String,
    org: String,
    token_hash: String,
    url: String,
    secret: Option<String>,
    health: Option<String>,
    state: String,
    first_failure: Option<i64>,
    next_attempt: i64,
}
impl Store {
    fn open(path: &std::path::Path) -> Result<Self> {
        let db = Connection::open(path).map_err(sql)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; CREATE TABLE IF NOT EXISTS hooks(id TEXT PRIMARY KEY,profile TEXT NOT NULL,api TEXT NOT NULL,org TEXT NOT NULL,token_hash TEXT NOT NULL,url TEXT NOT NULL,secret TEXT,health TEXT,state TEXT NOT NULL DEFAULT 'attached',first_failure INTEGER,next_attempt INTEGER NOT NULL DEFAULT 0); CREATE TABLE IF NOT EXISTS queue(hook TEXT NOT NULL,id TEXT NOT NULL,org TEXT NOT NULL,api TEXT NOT NULL DEFAULT '',payload TEXT NOT NULL,accepted INTEGER NOT NULL DEFAULT 0,eligible INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(hook,id)); CREATE TABLE IF NOT EXISTS creations(profile TEXT NOT NULL,org TEXT NOT NULL,intent TEXT NOT NULL,request TEXT NOT NULL,key TEXT NOT NULL,created INTEGER NOT NULL,PRIMARY KEY(profile,org));").map_err(sql)?;
        let has_api = {
            let mut q = db.prepare("PRAGMA table_info(queue)").map_err(sql)?;
            let fields = q.query_map([], |r| r.get::<_, String>(1)).map_err(sql)?;
            fields
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(sql)?
                .iter()
                .any(|s| s == "api")
        };
        if !has_api {
            db.execute(
                "ALTER TABLE queue ADD COLUMN api TEXT NOT NULL DEFAULT ''",
                [],
            )
            .map_err(sql)?;
            db.execute(
                "UPDATE queue SET api=COALESCE((SELECT api FROM hooks WHERE id=queue.hook),'')",
                [],
            )
            .map_err(sql)?;
        }
        db.execute("UPDATE queue SET eligible=0 WHERE accepted=0", [])
            .map_err(sql)?;
        let store = Self { db: Mutex::new(db) };
        store.prune(None)?;
        Ok(store)
    }
    fn invalidate_offers(&self) -> Result<()> {
        self.db
            .lock()
            .unwrap()
            .execute("UPDATE queue SET eligible=0 WHERE accepted=0", [])
            .map_err(sql)?;
        Ok(())
    }
    fn prune(&self, hook: Option<&str>) -> Result<()> {
        let cutoff = retention_cutoff();
        let mut db = self.db.lock().unwrap();
        let expired = {
            let mut statement = db
                .prepare("SELECT hook,id,payload FROM queue WHERE ?1 IS NULL OR hook=?1")
                .map_err(sql)?;
            let rows = statement
                .query_map([hook], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                })
                .map_err(sql)?;
            let mut expired = vec![];
            for row in rows {
                let (hook, id, payload) = row.map_err(sql)?;
                let value: Value = serde_json::from_str(&payload).map_err(|_| Error::io())?;
                if !retained(&value, cutoff) {
                    expired.push((hook, id));
                }
            }
            expired
        };
        let tx = db.transaction().map_err(sql)?;
        for (hook, id) in expired {
            tx.execute(
                "DELETE FROM queue WHERE hook=?1 AND id=?2",
                params![hook, id],
            )
            .map_err(sql)?;
        }
        tx.commit().map_err(sql)?;
        Ok(())
    }
    fn month_old_ids(&self, hook: &str) -> Result<Vec<String>> {
        let cutoff = Utc::now().checked_sub_months(Months::new(1)).unwrap();
        let db = self.db.lock().unwrap();
        let mut statement = db
            .prepare("SELECT id,payload FROM queue WHERE hook=?1")
            .map_err(sql)?;
        let rows = statement
            .query_map([hook], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(sql)?;
        let mut ids = vec![];
        for row in rows {
            let (id, payload) = row.map_err(sql)?;
            let value: Value = serde_json::from_str(&payload).map_err(|_| Error::io())?;
            if !retained(&value, cutoff) {
                ids.push(id)
            }
        }
        Ok(ids)
    }
    fn forget_missing(&self, hook: &str, id: &str) -> Result<()> {
        self.db
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM queue WHERE hook=?1 AND id=?2",
                params![hook, id],
            )
            .map_err(sql)?;
        Ok(())
    }
    fn hooks(&self) -> Result<Vec<Hook>> {
        let db = self.db.lock().unwrap();
        let mut s=db.prepare("SELECT id,profile,api,org,token_hash,url,secret,health,state,first_failure,next_attempt FROM hooks").map_err(sql)?;
        s.query_map([], |r| {
            Ok(Hook {
                id: r.get(0)?,
                profile: r.get(1)?,
                api: r.get(2)?,
                org: r.get(3)?,
                token_hash: r.get(4)?,
                url: r.get(5)?,
                secret: r.get(6)?,
                health: r.get(7)?,
                state: r.get(8)?,
                first_failure: r.get(9)?,
                next_attempt: r.get(10)?,
            })
        })
        .map_err(sql)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(sql)
    }
    fn queue(&self, v: &Value, api: &str) -> Result<Vec<String>> {
        let hook = field(v, "webhook_id")?;
        let org = field(v, "org_id")?;
        let tings = v["tings"]
            .as_array()
            .filter(|a| !a.is_empty() && a.len() <= 100)
            .ok_or_else(|| Error::input("Invalid delivery batch."))?;
        let mut db = self.db.lock().unwrap();
        let prior_api:Option<String>=db.query_row("SELECT api FROM hooks WHERE id=?1 UNION ALL SELECT api FROM queue WHERE hook=?1 LIMIT 1",[hook],|r|r.get(0)).optional().map_err(sql)?;
        if prior_api.as_deref().is_some_and(|old| old != api) {
            return Err(Error::new(
                "local_hook_collision",
                "A hook ID conflicts with retained state from another API origin.",
                "Use the original API to recover this registration; do not reuse its local queue.",
                false,
            ));
        }
        let tx = db.transaction().map_err(sql)?;
        let mut ids = vec![];
        for t in tings {
            let id = field(t, "id")?;
            let created = field(t, "created_at")?;
            if !created.ends_with('Z') || DateTime::parse_from_rfc3339(created).is_err() {
                return Err(Error::input("Invalid delivery timestamp."));
            }
            if !retained(t, retention_cutoff()) {
                continue;
            }
            for k in ["created_at", "type", "key", "for"] {
                field(t, k)?;
            }
            if !t["data"].is_object() || !t["metadata"].is_object() {
                return Err(Error::input("Invalid delivery content."));
            }
            let local = json!({"id":t["id"],"created_at":t["created_at"],"type":t["type"],"data":t["data"],"metadata":t["metadata"],"key":t["key"]});
            tx.execute("INSERT INTO queue(hook,id,org,payload,api) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(hook,id) DO UPDATE SET eligible=1",params![hook,id,org,local.to_string(),api]).map_err(sql)?;
            ids.push(id.into());
        }
        tx.commit().map_err(sql)?;
        Ok(ids)
    }
    fn batch(&self, id: &str, accepted: bool) -> Result<Vec<Value>> {
        let cutoff = retention_cutoff();
        let db = self.db.lock().unwrap();
        let rows = {
            let mut statement=db.prepare("SELECT id,payload FROM queue WHERE hook=?1 AND accepted=?2 AND (accepted=1 OR eligible=1) LIMIT 100").map_err(sql)?;
            statement
                .query_map(params![id, accepted], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })
                .map_err(sql)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(sql)?
        };
        let mut out = vec![];
        let mut size = 20;
        for (message_id, text) in rows {
            let value: Value = serde_json::from_str(&text).map_err(|_| Error::io())?;
            if !retained(&value, cutoff) {
                db.execute(
                    "DELETE FROM queue WHERE hook=?1 AND id=?2",
                    params![id, message_id],
                )
                .map_err(sql)?;
                continue;
            }
            if size + text.len() + 1 > 1024 * 1024 {
                break;
            }
            size += text.len() + 1;
            out.push(value);
        }
        Ok(out)
    }
    fn mark(&self, hook: &str, ids: &[String], accepted: bool) -> Result<()> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(sql)?;
        for id in ids {
            tx.execute(
                if accepted {
                    "UPDATE queue SET accepted=1 WHERE hook=?1 AND id=?2"
                } else {
                    "DELETE FROM queue WHERE hook=?1 AND id=?2 AND accepted=1"
                },
                params![hook, id],
            )
            .map_err(sql)?;
        }
        if accepted {
            tx.execute(
                "UPDATE hooks SET first_failure=NULL,next_attempt=0 WHERE id=?1",
                [hook],
            )
            .map_err(sql)?;
        }
        tx.commit().map_err(sql)?;
        Ok(())
    }
    fn state(&self, id: &str, state: &str) -> Result<()> {
        self.db
            .lock()
            .unwrap()
            .execute("UPDATE hooks SET state=?2 WHERE id=?1", params![id, state])
            .map_err(sql)?;
        Ok(())
    }
    fn pause(&self, ids: &[String], reason: &str) -> Result<()> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(sql)?;
        for id in ids {
            tx.execute(
                "UPDATE queue SET eligible=0 WHERE hook=?1 AND accepted=0",
                [id],
            )
            .map_err(sql)?;
            if ["hook_detached", "binding_replaced"].contains(&reason) {
                tx.execute("UPDATE hooks SET state='detached' WHERE id=?1", [id])
                    .map_err(sql)?;
            } else if reason == "session_expired" {
                tx.execute("UPDATE hooks SET state='auth_paused' WHERE id=?1", [id])
                    .map_err(sql)?;
            }
        }
        tx.commit().map_err(sql)?;
        Ok(())
    }
    fn fail(&self, id: &str) -> Result<()> {
        let n = now();
        self.db.lock().unwrap().execute("UPDATE hooks SET first_failure=COALESCE(first_failure,?2),next_attempt=?3 WHERE id=?1",params![id,n,n+60]).map_err(sql)?;
        Ok(())
    }
}
struct SocketCommand {
    api: String,
    body: Value,
    reply: oneshot::Sender<Result<Value>>,
}
#[derive(Default)]
struct SocketStatus {
    connected: bool,
    api: Option<String>,
    receiver: Option<String>,
    authorized: HashSet<String>,
    blocked: HashSet<String>,
}
#[derive(Clone)]
struct Shared {
    store: Arc<Store>,
    tx: mpsc::Sender<SocketCommand>,
    socket: Arc<RwLock<SocketStatus>>,
    wake: Arc<Notify>,
    leases: Arc<Mutex<(Option<String>, usize)>>,
}
struct OriginLease(Arc<Mutex<(Option<String>, usize)>>);
impl Drop for OriginLease {
    fn drop(&mut self) {
        let mut l = self.0.lock().unwrap();
        l.1 -= 1;
        if l.1 == 0 {
            l.0 = None;
        }
    }
}
impl Shared {
    fn lease(&self, api: &str) -> Result<OriginLease> {
        let mut leases = self.leases.lock().unwrap();
        if leases.0.as_deref().is_some_and(|a| a != api)
            || self
                .store
                .hooks()?
                .iter()
                .any(|h| h.state == "attached" && h.api != api)
        {
            return Err(Error::new(
                "daemon_api_conflict",
                "The shared socket is active on another API origin.",
                "Use HTTP or detach active receivers before switching origins.",
                false,
            ));
        }
        leases.0 = Some(api.into());
        leases.1 += 1;
        Ok(OriginLease(self.leases.clone()))
    }
    async fn ws(&self, api: &str, mut body: Value) -> Result<Value> {
        body["request_id"] = json!(uuid::Uuid::new_v4().to_string());
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(SocketCommand {
                api: api.into(),
                body,
                reply: tx,
            })
            .await
            .map_err(|_| Error::network())?;
        tokio::time::timeout(Duration::from_secs(29), rx)
            .await
            .map_err(|_| Error::network())?
            .map_err(|_| Error::network())?
    }
    async fn ack(&self, hook: &Hook, ids: &[String], kind: &str) -> Result<Value> {
        self.ws(&hook.api,json!({"op":"ack","org_id":hook.org,"webhook_id":hook.id,"message_ids":ids,"kind":kind})).await
    }
}
fn session_for(h: &Hook) -> Result<Session> {
    let p = Profile {
        dir: PathBuf::from(&h.profile),
    };
    let s = p.session(&h.api)?;
    if digest(&s.token) != h.token_hash {
        return Err(Error::new(
            "session_expired",
            "Saved identity has changed.",
            "Explicitly reattach this profile's webhook.",
            false,
        ));
    }
    Ok(s)
}
async fn restore(shared: &Shared, api: &str) {
    let authorized = shared.socket.read().await.authorized.clone();
    if let Ok(hooks) = shared.store.hooks() {
        let mut groups: HashMap<(String, String), Vec<Hook>> = HashMap::new();
        for h in hooks {
            if h.api != api {
                continue;
            }
            if h.state == "pause_pending"
                || h.state == "attached"
                    && h.first_failure.is_some_and(|t| now() - t >= 12 * 60 * 60)
            {
                // Persist the cutoff before authenticating a replacement binding; workers cannot forward this state.
                if shared.store.state(&h.id, "pause_pending").is_err() {
                    continue;
                }
                if let Ok(session) = session_for(&h) {
                    if shared.ws(api,json!({"op":"subscribe","org_id":h.org,"session_token":session.token,"webhook_ids":[h.id]})).await.is_ok() {
                        if shared.ws(api,json!({"op":"unsubscribe","org_id":h.org,"webhook_ids":[h.id],"pause":true})).await.is_ok(){let _=shared.store.state(&h.id,"paused");}
                    }
                }
                shared.socket.write().await.authorized.remove(&h.id);
                continue;
            }
            if h.state == "attached" && !authorized.contains(&h.id) {
                groups
                    .entry((h.profile.clone(), h.org.clone()))
                    .or_default()
                    .push(h);
            }
        }
        for (_, hooks) in groups {
            for chunk in hooks.chunks(100) {
                if let Ok(session) = session_for(&chunk[0]) {
                    let ids: Vec<_> = chunk.iter().map(|h| h.id.clone()).collect();
                    let _=shared.ws(api,json!({"op":"subscribe","org_id":chunk[0].org,"session_token":session.token,"webhook_ids":ids})).await;
                }
            }
        }
    }
}
async fn socket_loop(shared: Shared, mut rx: mpsc::Receiver<SocketCommand>) {
    let mut failures = 0u32;
    loop {
        let hooks = shared.store.hooks().unwrap_or_default();
        let target = hooks
            .iter()
            .find(|h| h.state == "attached" || h.state == "pause_pending")
            .map(|h| h.api.clone());
        let first = if target.is_none() {
            rx.recv().await
        } else {
            None
        };
        if target.is_none() && first.is_none() {
            break;
        }
        let api = target.unwrap_or_else(|| first.as_ref().unwrap().api.clone());
        let url = format!(
            "{}/v1/ws?protocol=v1",
            api.replacen("https://", "wss://", 1)
                .replacen("http://", "ws://", 1)
        );
        let connection = tokio::time::timeout(Duration::from_secs(10), connect_async(&url)).await;
        let Ok(Ok((mut ws, _))) = connection else {
            if let Some(c) = first {
                let _ = c.reply.send(Err(Error::network()));
            }
            recovery_delay(&mut failures).await;
            continue;
        };
        let ready = tokio::time::timeout(Duration::from_secs(10), ws.next()).await;
        let receiver = match ready {
            Ok(Some(Ok(Message::Text(s)))) => serde_json::from_str::<Value>(&s)
                .ok()
                .filter(|v| v["op"] == "ready" && v["protocol"] == "v1")
                .and_then(|v| v["receiver_id"].as_str().map(str::to_owned)),
            _ => None,
        };
        let Some(receiver) = receiver else {
            if let Some(c) = first {
                let _ = c.reply.send(Err(Error::network()));
            }
            recovery_delay(&mut failures).await;
            continue;
        };
        {
            let mut s = shared.socket.write().await;
            s.connected = true;
            s.api = Some(api.clone());
            s.receiver = Some(receiver);
            s.authorized.clear();
        }
        let restoring = shared.clone();
        let restore_api = api.clone();
        tokio::spawn(async move {
            restore(&restoring, &restore_api).await;
        });
        let mut pending: HashMap<String, (oneshot::Sender<Result<Value>>, std::time::Instant)> =
            HashMap::new();
        if let Some(c) = first {
            let id = c.body["request_id"].as_str().unwrap().to_owned();
            if ws
                .send(Message::Text(c.body.to_string().into()))
                .await
                .is_ok()
            {
                pending.insert(id, (c.reply, std::time::Instant::now()));
            } else {
                let _ = c.reply.send(Err(Error::network()));
            }
        }
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let healthy = std::time::Instant::now();
        let mut ping_at = std::time::Instant::now();
        let mut reauth_at = std::time::Instant::now();
        let mut pong_deadline: Option<std::time::Instant> = None;
        loop {
            tokio::select! {
             command=rx.recv()=>{let Some(c)=command else{return};if c.reply.is_closed(){continue}if c.api!=api{let pinned=!pending.is_empty()||shared.leases.lock().unwrap().0.as_deref()==Some(&api)||shared.store.hooks().unwrap_or_default().iter().any(|h|h.api==api&&h.state=="attached");if pinned{let _=c.reply.send(Err(Error::new("daemon_api_conflict","The shared socket is active on another API origin.","Use HTTP or detach the existing receivers before switching origins.",false)));continue}else{let tx=shared.tx.clone();tokio::spawn(async move{let _=tx.send(c).await;});break}}let id=c.body["request_id"].as_str().unwrap().to_owned();if ws.send(Message::Text(c.body.to_string().into())).await.is_err(){let _=c.reply.send(Err(Error::network()));break}pending.insert(id,(c.reply,std::time::Instant::now()));},
             incoming=ws.next()=>{match incoming{
              Some(Ok(Message::Text(s)))=>{if s.len()>1024*1024{break}let Ok(v)=strict_json(s.as_bytes())else{break};match v["op"].as_str().unwrap_or(""){
               "tings"=>{match shared.store.queue(&v,&api){Ok(ids)=>{if ids.is_empty(){continue}shared.wake.notify_one();let ack=json!({"op":"ack","request_id":uuid::Uuid::new_v4().to_string(),"org_id":v["org_id"],"webhook_id":v["webhook_id"],"message_ids":ids,"kind":"delivery"});if ws.send(Message::Text(ack.to_string().into())).await.is_err(){break}},Err(_)=>{if let Some(id)=v["webhook_id"].as_str(){shared.socket.write().await.authorized.remove(id);}}}},
               "paused"=>{let ids:Vec<String>=v["webhook_ids"].as_array().map(|a|a.iter().filter_map(|v|v.as_str().map(str::to_owned)).collect()).unwrap_or_default();let reason=v["reason"].as_str().unwrap_or("");{let mut s=shared.socket.write().await;for id in &ids{s.authorized.remove(id);}}let _=shared.store.pause(&ids,reason);if ["preference_changed","permission_changed","authorization_unavailable"].contains(&reason){let sh=shared.clone();let a=api.clone();tokio::spawn(async move{tokio::time::sleep(Duration::from_secs(1)).await;restore(&sh,&a).await;});}},
               "subscribed"=>{if let Some(ids)=v["webhook_ids"].as_array(){let mut st=shared.socket.write().await;for id in ids.iter().filter_map(Value::as_str){if !st.blocked.contains(id){st.authorized.insert(id.into());}}shared.wake.notify_one();}},_=>{}}
               if let Some(id)=v["request_id"].as_str(){if let Some((reply,_))=pending.remove(id){let r=if v["op"]=="error"{Err(serde_json::from_value(v["error"].clone()).unwrap_or_else(|_|Error::network()))}else{Ok(v)};let _=reply.send(r);}}
              },Some(Ok(Message::Ping(p)))=>{if ws.send(Message::Pong(p)).await.is_err(){break}},Some(Ok(Message::Pong(_)))=>{pong_deadline=None},Some(Ok(Message::Close(_)))|None|Some(Err(_))=>break,_=>{}}},
             _=tick.tick()=>{let n=std::time::Instant::now();if reauth_at.elapsed()>=Duration::from_secs(30){reauth_at=n;let sh=shared.clone();let a=api.clone();tokio::spawn(async move{restore(&sh,&a).await;});}if healthy.elapsed()>=Duration::from_secs(60){failures=0}if pong_deadline.is_some_and(|d|n>=d){break}if n.duration_since(ping_at)>=Duration::from_secs(30){if ws.send(Message::Ping(vec![1].into())).await.is_err(){break}ping_at=n;pong_deadline=Some(n+Duration::from_secs(10));}let expired:Vec<_>=pending.iter().filter(|(_,(_,at))|at.elapsed()>=Duration::from_secs(29)).map(|(id,_)|id.clone()).collect();for id in expired{if let Some((r,_))=pending.remove(&id){let _=r.send(Err(Error::network()));}}}
            }
        }
        {
            let mut s = shared.socket.write().await;
            s.connected = false;
            s.authorized.clear();
            let _ = shared.store.invalidate_offers();
            s.receiver = None;
        }
        for (_, (reply, _)) in pending {
            let _ = reply.send(Err(Error::network()));
        }
        let _ = ws.close(None).await;
        recovery_delay(&mut failures).await;
    }
}
async fn cleanup_missing(shared: &Shared, hook: &Hook) -> Result<()> {
    let ids = shared.store.month_old_ids(&hook.id)?;
    if ids.is_empty() {
        return Ok(());
    }
    let session = session_for(hook)?;
    let client = Client::new(&hook.api)?;
    for id in ids {
        let path = format!("/v1/orgs/{}/inbox/{}", segment(&hook.org), segment(&id));
        match client
            .json(
                "GET",
                &path,
                None,
                Some(&session.token),
                &TestHeaders::default(),
            )
            .await
        {
            Err(e) if e.code == "not_found" => shared.store.forget_missing(&hook.id, &id)?,
            Err(e) => return Err(e),
            Ok(_) => {}
        }
    }
    Ok(())
}
async fn read_ack(shared: &Shared, hook: &Hook, ids: &[String]) -> Result<()> {
    match shared.ack(hook, ids, "read").await {
        Ok(_) => shared.store.mark(&hook.id, ids, false),
        Err(e) if e.code == "invalid_ack" => {
            cleanup_missing(shared, hook).await?;
            Err(e)
        }
        Err(e) => Err(e),
    }
}
fn delivery_telemetry(hook: &Hook, accepted: bool, duration: u64) {
    let profile = Profile {
        dir: PathBuf::from(&hook.profile),
    };
    if !profile
        .read::<Settings>("settings.json")
        .ok()
        .flatten()
        .unwrap_or_default()
        .telemetry
        .unwrap_or(true)
    {
        return;
    }
    let api = hook.api.clone();
    tokio::spawn(async move {
        telemetry(
            &api,
            "webhook_delivery",
            json!({"accepted":accepted,"duration_ms":duration}),
        )
        .await;
    });
}
async fn forward(shared: Shared, hook: Hook) -> Result<()> {
    if !shared.socket.read().await.authorized.contains(&hook.id) {
        return Ok(());
    }
    let accepted = shared.store.batch(&hook.id, true)?;
    if !accepted.is_empty() {
        let ids = accepted
            .iter()
            .map(|v| v["id"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        read_ack(&shared, &hook, &ids).await?;
        return Ok(());
    }
    if hook
        .first_failure
        .is_some_and(|t| now() - t >= 12 * 60 * 60)
    {
        shared.store.state(&hook.id, "pause_pending")?;
        shared.socket.write().await.authorized.remove(&hook.id);
        let pause = shared
            .ws(
                &hook.api,
                json!({"op":"unsubscribe","org_id":hook.org,"webhook_ids":[hook.id],"pause":true}),
            )
            .await;
        if pause.is_ok() {
            shared.store.state(&hook.id, "paused")?;
        }
        return Ok(());
    }
    let mut batch = shared.store.batch(&hook.id, false)?;
    if batch.is_empty() {
        return Ok(());
    }
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| Error::network())?;
    if hook.first_failure.is_some() {
        if let Some(health) = &hook.health {
            let mut req = http.head(health).timeout(Duration::from_secs(2));
            if let Some(s) = &hook.secret {
                req = req.bearer_auth(s)
            }
            match req.send().await {
                Ok(r) if r.status().as_u16() == 405 || r.status().as_u16() == 501 => {
                    shared
                        .store
                        .db
                        .lock()
                        .unwrap()
                        .execute("UPDATE hooks SET health=NULL WHERE id=?1", [&hook.id])
                        .map_err(sql)?;
                }
                Ok(r) if r.status().is_success() => {}
                _ => return Ok(()),
            }
        }
    }
    if now() < hook.next_attempt {
        return Ok(());
    }
    let month_cutoff = Utc::now().checked_sub_months(Months::new(1)).unwrap();
    if batch.iter().any(|ting| !retained(ting, month_cutoff)) {
        // Another destination may have read an old ting since this copy was queued.
        // Uncertain checks must not forward it; only authenticated absence permits deletion.
        cleanup_missing(&shared, &hook).await?;
        batch = shared.store.batch(&hook.id, false)?;
    }
    if !shared.socket.read().await.authorized.contains(&hook.id) {
        return Ok(());
    }
    batch.retain(|ting| retained(ting, retention_cutoff()));
    if batch.is_empty() {
        return Ok(());
    }
    let ids = batch
        .iter()
        .map(|v| v["id"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let mut req = http
        .post(&hook.url)
        .header("Ting-Webhook-Id", &hook.id)
        .json(&json!({"tings":batch}));
    if let Some(s) = &hook.secret {
        req = req.bearer_auth(s)
    }
    let started = std::time::Instant::now();
    let outcome = req.send().await;
    delivery_telemetry(
        &hook,
        outcome
            .as_ref()
            .is_ok_and(|r| r.status() == reqwest::StatusCode::NO_CONTENT),
        started.elapsed().as_millis().min(u64::MAX as u128) as u64,
    );
    match outcome {
        Ok(r) if r.status() == reqwest::StatusCode::NO_CONTENT => {
            shared.store.mark(&hook.id, &ids, true)?;
            if shared.socket.read().await.authorized.contains(&hook.id) {
                read_ack(&shared, &hook, &ids).await?;
            }
        }
        _ => shared.store.fail(&hook.id)?,
    }
    Ok(())
}
async fn workers(shared: Shared) {
    let mut jobs: HashMap<String, (tokio::task::JoinHandle<()>, std::time::Instant)> =
        HashMap::new();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut last_probe: HashMap<String, i64> = HashMap::new();
    let mut last_watchdog = 0;
    let mut last_prune = 0;
    loop {
        tokio::select! {_=tick.tick()=>{},_=shared.wake.notified()=>{}}
        let done: Vec<_> = jobs
            .iter()
            .filter(|(_, (j, at))| j.is_finished() || at.elapsed() > Duration::from_secs(45))
            .map(|(id, _)| id.clone())
            .collect();
        for id in done {
            if let Some((j, _)) = jobs.remove(&id) {
                if !j.is_finished() {
                    j.abort();
                }
            }
        }
        let hooks = shared.store.hooks().unwrap_or_default();
        if now() - last_prune >= 3600 {
            let _ = shared.store.prune(None);
            if let Ok(hooks) = shared.store.hooks() {
                for hook in hooks {
                    let state = shared.clone();
                    tokio::spawn(async move {
                        let _ = cleanup_missing(&state, &hook).await;
                    });
                }
            }
            last_prune = now();
        }
        if now() - last_watchdog >= 5 {
            service_notify("WATCHDOG=1");
            last_watchdog = now();
        }
        let authorized = shared.socket.read().await.authorized.clone();
        for hook in hooks {
            if hook.state != "attached"
                || !authorized.contains(&hook.id)
                || jobs.contains_key(&hook.id)
            {
                continue;
            }
            if hook.first_failure.is_some() && hook.health.is_some() {
                if now() - last_probe.get(&hook.id).copied().unwrap_or(0) < 5 {
                    continue;
                }
                last_probe.insert(hook.id.clone(), now());
            } else if hook.next_attempt > now()
                && hook.first_failure.is_some_and(|t| now() - t < 12 * 60 * 60)
            {
                continue;
            }
            let id = hook.id.clone();
            let s = shared.clone();
            let j = tokio::spawn(async move {
                let _ = forward(s, hook).await;
            });
            jobs.insert(id, (j, std::time::Instant::now()));
        }
    }
}
fn authenticate(v: &Value, uid: u32) -> Result<(Profile, Session)> {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    let path = PathBuf::from(field(v, "profile")?);
    let real = fs::canonicalize(&path).map_err(|_| Error::io())?;
    if path != real {
        return Err(Error::input("Profile path must be canonical."));
    }
    let sf = real.join("session.json");
    let sm = fs::symlink_metadata(&sf).map_err(|_| Error::io())?;
    if !sm.is_file() || sm.file_type().is_symlink() {
        return Err(Error::io());
    }
    #[cfg(unix)]
    {
        let meta = fs::metadata(&real).map_err(|_| Error::io())?;
        if meta.uid() != uid
            || meta.mode() & 0o077 != 0
            || sm.uid() != uid
            || sm.mode() & 0o077 != 0
        {
            return Err(Error::new(
                "permission_denied",
                "The caller cannot authenticate this private profile.",
                "Use the profile's owner account and private session credential.",
                false,
            ));
        }
    }
    #[cfg(windows)]
    {
        let _ = uid;
        if !ting_client::windows::is_private_owner(&real)?
            || !ting_client::windows::is_private_owner(&sf)?
        {
            return Err(Error::new(
                "permission_denied",
                "The profile does not have private current-user ownership and ACLs.",
                "Use this system service's owner account and private profile.",
                false,
            ));
        }
    }
    let p = Profile { dir: real };
    let session = p.session(field(v, "api_url")?)?;
    if session.token != field(v, "session_token")? {
        return Err(Error::new(
            "authentication_required",
            "The supplied profile credential is invalid.",
            "Log in using this profile.",
            false,
        ));
    }
    Ok((p, session))
}
async fn control(shared: &Shared, v: Value, uid: u32) -> Result<Value> {
    let op = field(&v, "op")?;
    let api = api_origin(field(&v, "api_url")?)?;
    let _lease = if ["send", "webhook", "reconnect"].contains(&op) {
        Some(shared.lease(&api)?)
    } else {
        None
    };
    if op == "send" {
        let p = Prepared::new(
            ProofOperation::Send,
            field(&v, "body")?.as_bytes().to_vec(),
            None,
        )?;
        let response=shared.ws(&api,json!({"op":"send","proof_token":field(&v,"proof_token")?,"body":String::from_utf8(p.body).unwrap(),"headers":v.get("headers").cloned().unwrap_or(json!({}))})).await?;
        let mut response = response;
        response.as_object_mut().unwrap().remove("op");
        response.as_object_mut().unwrap().remove("request_id");
        return Ok(response);
    }
    let (profile, session) = authenticate(&v, uid)?;
    let profile_name = profile.dir.to_string_lossy().into_owned();
    let hooks = shared.store.hooks()?;
    if op == "logout" {
        let mine: Vec<_> = hooks
            .iter()
            .filter(|h| h.profile == profile_name && h.token_hash == digest(&session.token))
            .collect();
        {
            let mut state = shared.socket.write().await;
            for hook in &mine {
                state.authorized.remove(&hook.id);
                state.blocked.insert(hook.id.clone());
            }
        }
        {
            let mut db = shared.store.db.lock().unwrap();
            let tx = db.transaction().map_err(sql)?;
            for hook in &mine {
                tx.execute(
                    "UPDATE hooks SET state='auth_paused' WHERE id=?1",
                    [&hook.id],
                )
                .map_err(sql)?;
            }
            tx.commit().map_err(sql)?;
        }
        // Local forwarding is stopped for every hook before any network wait can time out.
        for hook in mine {
            let _ = shared
                .ws(
                    &api,
                    json!({"op":"unsubscribe","org_id":hook.org,"webhook_ids":[hook.id]}),
                )
                .await;
        }
        return Ok(json!({"authenticated":false}));
    }
    let org = field(&v, "org_id")?;
    let mine = hooks
        .iter()
        .filter(|h| {
            h.profile == profile_name
                && h.api == api
                && h.org == org
                && h.token_hash == digest(&session.token)
        })
        .cloned()
        .collect::<Vec<_>>();
    let test: TestHeaders = serde_json::from_value(v.get("headers").cloned().unwrap_or(json!({})))
        .map_err(|_| Error::input("Invalid test headers."))?;
    let client = Client::new(&api)?;
    let base = format!("/v1/orgs/{}/webhooks", segment(org));
    match op {
        "status" => {
            let response = client
                .json(
                    "GET",
                    &format!("{base}?limit=100"),
                    None,
                    Some(&session.token),
                    &test,
                )
                .await;
            let pending = response.ok().and_then(|r| {
                if r.get("next_cursor").is_some() {
                    None
                } else {
                    r["items"]
                        .as_array()
                        .map(|xs| xs.iter().filter_map(|v| v["pending"].as_u64()).sum::<u64>())
                }
            });
            let s = shared.socket.read().await;
            Ok(
                json!({"running":true,"socket_connected":s.connected&&s.api.as_deref()==Some(&api),"pending":pending}),
            )
        }
        "destinations" => {
            let mut map = serde_json::Map::new();
            for hook in mine {
                map.insert(hook.id, json!(hook.url));
            }
            Ok(Value::Object(map))
        }
        "unhook" => {
            let id = field(&v, "id")?;
            let result = client
                .json(
                    "DELETE",
                    &format!("{base}/{}", segment(id)),
                    None,
                    Some(&session.token),
                    &test,
                )
                .await?;
            if mine.iter().any(|h| h.id == id) {
                shared.store.state(id, "detached")?;
                shared.socket.write().await.authorized.remove(id);
            }
            Ok(result)
        }
        "reconnect" => {
            shared.ws(&api,json!({"op":"subscribe","org_id":org,"session_token":session.token,"webhook_ids":[],"headers":test})).await?;
            let receiver = shared
                .socket
                .read()
                .await
                .receiver
                .clone()
                .ok_or_else(Error::network)?;
            for hook in mine.iter().filter(|h| h.state != "detached") {
                client
                    .json(
                        "PATCH",
                        &format!("{base}/{}", segment(&hook.id)),
                        Some(json!({"receiver_id":receiver})),
                        Some(&session.token),
                        &test,
                    )
                    .await?;
                shared.store.db.lock().unwrap().execute("UPDATE hooks SET state='attached',first_failure=NULL,next_attempt=0 WHERE id=?1",[&hook.id]).map_err(sql)?;
                shared.socket.write().await.blocked.remove(&hook.id);
                shared.ws(&api,json!({"op":"subscribe","org_id":org,"session_token":session.token,"webhook_ids":[hook.id]})).await?;
            }
            Ok(json!({"reconnected":true}))
        }
        "webhook" => {
            let url = field(&v, "url")?;
            webhook_url(url)?;
            if let Some(h) = v["health_url"].as_str() {
                webhook_url(h)?
            }
            let id = v["id"].as_str();
            let existing = id.and_then(|id| mine.iter().find(|h| h.id == id));
            let secret = if v["clear_secret"] == true {
                None
            } else {
                v["secret"]
                    .as_str()
                    .map(str::to_owned)
                    .or_else(|| existing.and_then(|h| h.secret.clone()))
            };
            let health = if v["clear_health_url"] == true {
                None
            } else {
                v["health_url"]
                    .as_str()
                    .map(str::to_owned)
                    .or_else(|| existing.and_then(|h| h.health.clone()))
            };
            shared.ws(&api,json!({"op":"subscribe","org_id":org,"session_token":session.token,"webhook_ids":[],"headers":test})).await?;
            let receiver = shared
                .socket
                .read()
                .await
                .receiver
                .clone()
                .ok_or_else(Error::network)?;
            let mut response = if let Some(id) = id {
                client.json("PATCH",&format!("{base}/{}",segment(id)),Some(json!({"receiver_id":receiver,"takeover":v["takeover"].as_bool().unwrap_or(false)})),Some(&session.token),&test).await?
            } else {
                let intent=json!({"api_url":api,"url":url,"secret":secret,"health_url":health,"token_hash":digest(&session.token)}).to_string();
                let mut attempt = {
                    let db = shared.store.db.lock().unwrap();
                    db.query_row("SELECT intent,request,key,created FROM creations WHERE profile=?1 AND org=?2",params![profile_name,org],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,i64>(3)?))).optional().map_err(sql)?
                };
                if let Some((saved, _, _, created)) = &attempt {
                    if saved != &intent {
                        return Err(Error::new(
                            "creation_pending",
                            "A previous webhook creation is unresolved for this profile/org.",
                            "Retry with the same local destination settings to recover its stable hook ID.",
                            false,
                        ));
                    }
                    if now() - created >= 14 * 86400 {
                        return Err(Error::new(
                            "creation_expired",
                            "An unresolved webhook creation exceeded its idempotency window.",
                            "List existing hooks and reattach the matching stable ID; do not create a replacement blindly.",
                            false,
                        ));
                    }
                }
                if attempt.is_none() {
                    let body = json!({"receiver_id":receiver}).to_string();
                    let key = uuid::Uuid::new_v4().to_string();
                    let created = now();
                    shared.store.db.lock().unwrap().execute("INSERT INTO creations(profile,org,intent,request,key,created) VALUES(?1,?2,?3,?4,?5,?6)",params![profile_name,org,intent,body,key,created]).map_err(sql)?;
                    attempt = Some((intent, body, key, created));
                }
                let (_, body, key, _) = attempt.unwrap();
                let reply = client
                    .request(
                        "POST",
                        &base,
                        Some(body.as_bytes().to_vec()),
                        Some(&session.token),
                        &test,
                        Some(&key),
                    )
                    .await;
                let mut reply = match reply {
                    Ok(v) => v,
                    Err(e) if e.code == "receiver_gone" => {
                        shared
                            .store
                            .db
                            .lock()
                            .unwrap()
                            .execute(
                                "DELETE FROM creations WHERE profile=?1 AND org=?2",
                                params![profile_name, org],
                            )
                            .map_err(sql)?;
                        return Err(Error::new(
                            "receiver_gone",
                            "The previous creation did not create a hook; its receiver is gone.",
                            "Repeat this command to begin a fresh, durably saved creation attempt.",
                            true,
                        ));
                    }
                    Err(e) => return Err(e),
                };
                if reply["receiver_id"] != receiver {
                    let id = field(&reply, "id")?;
                    reply = client
                        .json(
                            "PATCH",
                            &format!("{base}/{}", segment(id)),
                            Some(json!({"receiver_id":receiver})),
                            Some(&session.token),
                            &test,
                        )
                        .await?;
                }
                reply
            };
            let hook_id = field(&response, "id")?.to_owned();
            if hooks
                .iter()
                .any(|h| h.id == hook_id && (h.api != api || h.profile != profile_name))
            {
                let mut e = Error::new(
                    "local_hook_collision",
                    "This hook ID is already associated with another API or private profile.",
                    "Recover or detach the original registration before assigning this destination.",
                    false,
                );
                e.details = Some(json!({"webhook_id":hook_id}));
                return Err(e);
            }
            let queued_api: Option<String> = shared
                .store
                .db
                .lock()
                .unwrap()
                .query_row(
                    "SELECT api FROM queue WHERE hook=?1 LIMIT 1",
                    [&hook_id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(sql)?;
            if queued_api.as_deref().is_some_and(|old| old != api) {
                let mut e = Error::new(
                    "local_hook_collision",
                    "Early queued copies belong to another API origin.",
                    "Recover the original registration without replacing its local destination.",
                    false,
                );
                e.details = Some(json!({"webhook_id":hook_id}));
                return Err(e);
            }
            let saved = (|| -> Result<()> {
                let mut db = shared.store.db.lock().unwrap();
                let tx = db.transaction().map_err(sql)?;
                tx.execute("INSERT INTO hooks(id,profile,api,org,token_hash,url,secret,health,state) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'attached') ON CONFLICT(id) DO UPDATE SET profile=excluded.profile,api=excluded.api,org=excluded.org,token_hash=excluded.token_hash,url=excluded.url,secret=excluded.secret,health=excluded.health,state='attached',first_failure=NULL,next_attempt=0",params![hook_id,profile_name,api,org,digest(&session.token),url,secret,health]).map_err(sql)?;
                if id.is_none() {
                    tx.execute(
                        "DELETE FROM creations WHERE profile=?1 AND org=?2",
                        params![profile_name, org],
                    )
                    .map_err(sql)?;
                }
                tx.commit().map_err(sql)?;
                Ok(())
            })();
            if let Err(mut e) = saved {
                e.details = Some(json!({"webhook_id":hook_id}));
                return Err(e);
            }
            shared.socket.write().await.blocked.remove(&hook_id);
            if let Err(mut e)=shared.ws(&api,json!({"op":"subscribe","org_id":org,"session_token":session.token,"webhook_ids":[hook_id]})).await{e.details=Some(json!({"webhook_id":hook_id}));return Err(e)}
            response["url"] = json!(url);
            response.as_object_mut().unwrap().remove("receiver_id");
            Ok(response)
        }
        _ => Err(Error::input("Unknown daemon operation.")),
    }
}
async fn serve(shared: Shared, socket: LocalStream) {
    #[cfg(unix)]
    let uid = match socket.peer_cred() {
        Ok(c) => c.uid(),
        Err(_) => return,
    };
    #[cfg(windows)]
    let uid = 0;
    let (reader, mut writer) = tokio::io::split(socket);
    let task = async {
        let mut line = Vec::new();
        let mut reader = BufReader::new(reader);
        let mut total = 0;
        loop {
            let buf = reader.fill_buf().await.map_err(|_| Error::network())?;
            if buf.is_empty() {
                return Err(Error::input("Incomplete IPC frame."));
            }
            let n = buf
                .iter()
                .position(|&b| b == b'\n')
                .map_or(buf.len(), |n| n + 1);
            total += n;
            if total > 2 * 1024 * 1024 {
                return Err(Error::input("IPC request exceeds limit."));
            }
            let done = buf[n - 1] == b'\n';
            line.extend_from_slice(&buf[..n]);
            reader.consume(n);
            if done {
                break;
            }
        }
        let v = strict_json(&line)?;
        control(&shared, v, uid).await
    };
    let result = tokio::time::timeout(Duration::from_secs(30), task)
        .await
        .unwrap_or_else(|_| Err(Error::network()));
    let value = result.unwrap_or_else(|e| e.envelope());
    let _ = writer.write_all(format!("{value}\n").as_bytes()).await;
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("{e}");
        std::process::exit(1)
    }
}
async fn run() -> Result<()> {
    #[cfg(unix)]
    unsafe {
        libc::umask(0o077);
    }
    let mut listener = LocalListener::bind()?;
    let dir = real_home()?.join(".ting-daemon");
    private_dir(&dir)?;
    let store = Arc::new(Store::open(&dir.join("queue.sqlite3"))?);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.join("queue.sqlite3"), fs::Permissions::from_mode(0o600))
            .map_err(|_| Error::io())?;
    }
    #[cfg(windows)]
    ting_client::windows::private_path(&dir.join("queue.sqlite3"), false)?;
    let (tx, rx) = mpsc::channel(128);
    let shared = Shared {
        store,
        tx,
        socket: Arc::new(RwLock::new(SocketStatus::default())),
        wake: Arc::new(Notify::new()),
        leases: Arc::new(Mutex::new((None, 0))),
    };
    let sockets = tokio::spawn(socket_loop(shared.clone(), rx));
    let jobs = tokio::spawn(workers(shared.clone()));
    service_notify("READY=1");
    loop {
        tokio::select! {result=listener.accept()=>{let socket=result?;tokio::spawn(serve(shared.clone(),socket));},_=tokio::signal::ctrl_c()=>break,_=async{while !sockets.is_finished()&&!jobs.is_finished(){tokio::time::sleep(Duration::from_secs(5)).await;}}=>return Err(Error::new("worker_stopped","A daemon supervisor stopped.","The platform service manager will restart Ting.",true))}
    }
    #[cfg(unix)]
    let _ = fs::remove_file(daemon_socket());
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn local_identity_requires_credential_and_private_ownership() {
        let dir = std::env::temp_dir().join(format!("ting-profile-{}", uuid::Uuid::new_v4()));
        private_dir(&dir).unwrap();
        let p = Profile {
            dir: fs::canonicalize(&dir).unwrap(),
        };
        p.save(
            "session.json",
            &Session {
                api_url: "https://test.invalid".into(),
                id: "si:alice".into(),
                token: "secret-a".into(),
                context: None,
            },
        )
        .unwrap();
        let uid = unsafe { libc::getuid() };
        let mut v =
            json!({"profile":p.dir,"api_url":"https://test.invalid","session_token":"secret-a"});
        assert!(authenticate(&v, uid).is_ok());
        v["session_token"] = json!("secret-b");
        assert!(authenticate(&v, uid).is_err());
        v["session_token"] = json!("secret-a");
        assert!(authenticate(&v, uid.wrapping_add(1)).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn proof_sends_share_one_socket_and_preserve_body() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            ws.send(Message::Text(
                json!({"op":"ready","receiver_id":"receiver-test","protocol":"v1"})
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
            for _ in 0..2 {
                let msg = ws.next().await.unwrap().unwrap();
                let value: Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
                assert_eq!(value["body"], r#"{ "exact": true }"#);
                ws.send(Message::Text(
                    json!({"op":"accepted","request_id":value["request_id"],"id":"m"})
                        .to_string()
                        .into(),
                ))
                .await
                .unwrap();
            }
        });
        let p = std::env::temp_dir().join(format!("ting-socket-{}.sqlite", uuid::Uuid::new_v4()));
        let (tx, rx) = mpsc::channel(16);
        let sh = Shared {
            store: Arc::new(Store::open(&p).unwrap()),
            tx,
            socket: Arc::new(RwLock::new(SocketStatus::default())),
            wake: Arc::new(Notify::new()),
            leases: Arc::new(Mutex::new((None, 0))),
        };
        let driver = tokio::spawn(socket_loop(sh.clone(), rx));
        for _ in 0..2 {
            let v = sh
                .ws(
                    &api,
                    json!({"op":"send","proof_token":"proof","body":r#"{ "exact": true }"#}),
                )
                .await
                .unwrap();
            assert_eq!(v["id"], "m");
        }
        server.await.unwrap();
        driver.abort();
        let _ = fs::remove_file(p);
    }
    #[tokio::test]
    async fn expired_receipts_require_authenticated_missing_confirmation() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut buf = [0u8; 1024];
                    let n = socket.read(&mut buf).await.unwrap();
                    request.extend_from_slice(&buf[..n]);
                    if request.windows(4).any(|s| s == b"\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8(request).unwrap();
                assert!(
                    request
                        .to_ascii_lowercase()
                        .contains("authorization: bearer private-test")
                );
                let expired = request.starts_with("GET /v1/orgs/tos/inbox/expired ");
                let (status, body) = if expired {
                    ("404 Not Found",json!({"error":{"code":"not_found","message":"No retained record","hint":"","retryable":false}}).to_string())
                } else {
                    ("200 OK", json!({"id":"unread"}).to_string())
                };
                socket.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
            }
        });
        let dir = std::env::temp_dir().join(format!("ting-expired-{}", uuid::Uuid::new_v4()));
        private_dir(&dir).unwrap();
        let profile = Profile {
            dir: fs::canonicalize(&dir).unwrap(),
        };
        profile
            .save(
                "session.json",
                &Session {
                    api_url: api.clone(),
                    id: "si:test".into(),
                    token: "private-test".into(),
                    context: None,
                },
            )
            .unwrap();
        let store = Arc::new(Store::open(&dir.join("queue.sqlite")).unwrap());
        let created = Utc::now()
            .checked_sub_months(Months::new(2))
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        for id in ["expired", "unread"] {
            store.queue(&json!({"org_id":"tos","webhook_id":"hook","tings":[{"id":id,"created_at":created,"type":"dm.msg.received","for":"si:test","key":id,"data":{},"metadata":{}}]}),&api).unwrap();
            store.mark("hook", &[id.into()], true).unwrap();
        }
        let (tx, _rx) = mpsc::channel(1);
        let shared = Shared {
            store,
            tx,
            socket: Arc::new(RwLock::new(SocketStatus::default())),
            wake: Arc::new(Notify::new()),
            leases: Arc::new(Mutex::new((None, 0))),
        };
        let hook = Hook {
            id: "hook".into(),
            profile: profile.dir.to_string_lossy().into(),
            api,
            org: "tos".into(),
            token_hash: digest("private-test"),
            url: "http://127.0.0.1/unused".into(),
            secret: None,
            health: None,
            state: "attached".into(),
            first_failure: None,
            next_attempt: 0,
        };
        cleanup_missing(&shared, &hook).await.unwrap();
        let remaining = shared.store.batch("hook", true).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0]["id"], "unread");
        server.await.unwrap();
        drop(shared);
        fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn aged_pending_rechecks_retention_before_forwarding() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            for attempt in 0..6 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let header_end = loop {
                    let mut buf = [0u8; 1024];
                    let n = socket.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&buf[..n]);
                    if let Some(end) = bytes.windows(4).position(|s| s == b"\r\n\r\n") {
                        break end + 4;
                    }
                };
                let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                while bytes.len() < header_end + length {
                    let mut buf = [0u8; 1024];
                    let n = socket.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&buf[..n]);
                }
                let (status, body) = if headers.starts_with("GET ") {
                    assert!(
                        headers
                            .to_ascii_lowercase()
                            .contains("authorization: bearer private-test")
                    );
                    assert!(
                        attempt < 3 || attempt == 5,
                        "Fresh notifications must not need retention GETs"
                    );
                    if attempt == 0 {
                        ("503 Service Unavailable", json!({"error":{"code":"unavailable","message":"uncertain","hint":"","retryable":true}}).to_string())
                    } else if headers.starts_with("GET /v1/orgs/tos/inbox/expired ")
                        || headers.starts_with("GET /v1/orgs/tos/inbox/onlyexpired ")
                    {
                        ("404 Not Found", json!({"error":{"code":"not_found","message":"Read elsewhere and expired","hint":"","retryable":false}}).to_string())
                    } else {
                        assert!(headers.starts_with("GET /v1/orgs/tos/inbox/unread "));
                        ("200 OK", json!({"id":"unread","read":false}).to_string())
                    }
                } else {
                    assert!(headers.starts_with("POST /hook "));
                    assert!(attempt >= 3, "Uncertain retention must not forward a batch");
                    let payload: Value =
                        serde_json::from_slice(&bytes[header_end..header_end + length]).unwrap();
                    assert_eq!(payload["tings"].as_array().unwrap().len(), 1);
                    assert_eq!(
                        payload["tings"][0]["id"],
                        if attempt == 3 { "unread" } else { "fresh" }
                    );
                    ("204 No Content", String::new())
                };
                socket.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(100), listener.accept())
                    .await
                    .is_err(),
                "An emptied batch must not make a webhook POST"
            );
        });
        let dir =
            std::env::temp_dir().join(format!("ting-pending-retention-{}", uuid::Uuid::new_v4()));
        private_dir(&dir).unwrap();
        let profile = Profile {
            dir: fs::canonicalize(&dir).unwrap(),
        };
        profile
            .save(
                "session.json",
                &Session {
                    api_url: api.clone(),
                    id: "si:test".into(),
                    token: "private-test".into(),
                    context: None,
                },
            )
            .unwrap();
        profile
            .save(
                "settings.json",
                &Settings {
                    telemetry: Some(false),
                    ..Settings::default()
                },
            )
            .unwrap();
        let store = Arc::new(Store::open(&dir.join("queue.sqlite")).unwrap());
        let queue = |id: &str, created: String| {
            store.queue(&json!({"org_id":"tos","webhook_id":"hook","tings":[{"id":id,"created_at":created,"type":"dm.msg.received","for":"si:test","key":id,"data":{},"metadata":{}}]}), &api).unwrap();
        };
        let old = Utc::now()
            .checked_sub_months(Months::new(2))
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        queue("expired", old.clone());
        queue("unread", old.clone());
        let (tx, mut rx) = mpsc::channel::<SocketCommand>(2);
        let acknowledgements = tokio::spawn(async move {
            for id in ["unread", "fresh"] {
                let command = rx.recv().await.unwrap();
                assert_eq!(command.body["kind"], "read");
                assert_eq!(command.body["message_ids"], json!([id]));
                command.reply.send(Ok(json!({"op":"acked"}))).unwrap();
            }
        });
        let shared = Shared {
            store: store.clone(),
            tx,
            socket: Arc::new(RwLock::new(SocketStatus {
                authorized: HashSet::from(["hook".into()]),
                ..SocketStatus::default()
            })),
            wake: Arc::new(Notify::new()),
            leases: Arc::new(Mutex::new((None, 0))),
        };
        let hook = Hook {
            id: "hook".into(),
            profile: profile.dir.to_string_lossy().into(),
            api: api.clone(),
            org: "tos".into(),
            token_hash: digest("private-test"),
            url: format!("{api}/hook"),
            secret: None,
            health: None,
            state: "attached".into(),
            first_failure: None,
            next_attempt: 0,
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            assert!(forward(shared.clone(), hook.clone()).await.is_err());
            assert_eq!(store.batch("hook", false).unwrap().len(), 2);
            forward(shared.clone(), hook.clone()).await.unwrap();
            assert!(store.batch("hook", false).unwrap().is_empty());
            queue(
                "fresh",
                Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            );
            forward(shared.clone(), hook.clone()).await.unwrap();
            queue("onlyexpired", old);
            forward(shared.clone(), hook).await.unwrap();
            assert!(store.batch("hook", false).unwrap().is_empty());
            server.await.unwrap();
            acknowledgements.await.unwrap();
        })
        .await
        .unwrap();
        drop(shared);
        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn stale_authority_and_three_month_expiry_block_forwarding() {
        let path =
            std::env::temp_dir().join(format!("ting-expiry-{}.sqlite", uuid::Uuid::new_v4()));
        let store = Store::open(&path).unwrap();
        let mut batch = json!({"webhook_id":"hook","org_id":"tos","tings":[{"id":"fresh","created_at":Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis,true),"type":"dm.msg.received","for":"si:test","key":"k","data":{},"metadata":{}}]});
        store.queue(&batch, "https://test.invalid").unwrap();
        assert_eq!(store.batch("hook", false).unwrap().len(), 1);
        assert!(store.queue(&batch, "https://different.invalid").is_err());
        store.invalidate_offers().unwrap();
        assert!(store.batch("hook", false).unwrap().is_empty());
        store.queue(&batch, "https://test.invalid").unwrap();
        assert_eq!(store.batch("hook", false).unwrap().len(), 1);
        let old = Utc::now()
            .checked_sub_months(Months::new(4))
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        batch["tings"][0]["id"] = json!("expired");
        batch["tings"][0]["created_at"] = json!(old);
        assert!(
            store
                .queue(&batch, "https://test.invalid")
                .unwrap()
                .is_empty()
        );
        store.db.lock().unwrap().execute("INSERT INTO queue(hook,id,org,payload,accepted) VALUES('hook','old-accepted','tos',?1,1)",[batch["tings"][0].to_string()]).unwrap();
        assert!(store.batch("hook", true).unwrap().is_empty());
        drop(store);
        let store = Store::open(&path).unwrap();
        assert!(store.batch("hook", false).unwrap().is_empty());
        drop(store);
        let _ = fs::remove_file(path);
    }
    #[test]
    fn acceptance_survives_reopen_and_replay() {
        let p = std::env::temp_dir().join(format!("ting-{}.sqlite", uuid::Uuid::new_v4()));
        let v = json!({"webhook_id":"h","org_id":"tos","tings":[{"id":"m","created_at":Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis,true),"type":"dm.msg.received","data":{},"metadata":{},"for":"si:one","key":"k"}]});
        {
            let store = Store::open(&p).unwrap();
            assert_eq!(store.queue(&v, "https://test.invalid").unwrap(), vec!["m"]);
            store.mark("h", &["m".into()], true).unwrap();
        }
        let store = Store::open(&p).unwrap();
        store.queue(&v, "https://test.invalid").unwrap();
        assert_eq!(store.batch("h", true).unwrap().len(), 1);
        assert!(store.batch("h", false).unwrap().is_empty());
        store.mark("h", &["m".into()], false).unwrap();
        assert!(store.batch("h", true).unwrap().is_empty());
        drop(store);
        let _ = fs::remove_file(p);
    }
}
