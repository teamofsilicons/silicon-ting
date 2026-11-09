use crate::{
    auth::{AppAuthority, Principal, Proof},
    error::{Error, Result},
    validation as v,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::{Mutex, MutexGuard};
use uuid::Uuid;

/// Stored hook ID, account namespace, recipient UUID, and session.
pub type ActiveHookRow = (String, String, String, String);

pub fn id(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::new_v4().simple())
}
pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}
pub fn retention_cutoff(months: u32) -> String {
    (chrono::Utc::now() - chrono::Months::new(months))
        .to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}
fn stamp() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}
fn decode(s: String) -> Result<Value> {
    serde_json::from_str(&s).map_err(Into::into)
}
// Historical body bytes stay immutable; only typed public fields project current IDs.
fn current_body(body: String, typ: String, recipient: String) -> Result<Value> {
    let mut body = decode(body)?;
    body["type"] = typ.into();
    body["for"] = if recipient.starts_with("session:") {
        Value::Null
    } else {
        recipient.into()
    };
    Ok(body)
}
fn conflict(code: &str, msg: &str) -> Error {
    Error::new(
        409,
        code,
        msg,
        "Use the original request or a new idempotency key for a new operation.",
    )
}

pub struct Store {
    db: Mutex<Connection>,
}
impl Store {
    pub fn open(path: &str) -> anyhow::Result<Self> {
        let c = Connection::open(path)?;
        c.busy_timeout(std::time::Duration::from_secs(5))?;
        crate::migration::ensure_current(&c)?;
        c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
 CREATE TABLE IF NOT EXISTS types(ctx TEXT,app TEXT,name TEXT,description TEXT,PRIMARY KEY(ctx,name));
 CREATE INDEX IF NOT EXISTS accounts_types_app ON types(ctx,app,name);
 CREATE TABLE IF NOT EXISTS grants(id TEXT PRIMARY KEY,ctx TEXT,app TEXT,recipient TEXT,active INTEGER,UNIQUE(ctx,app,recipient));
 CREATE TABLE IF NOT EXISTS preferences(ctx TEXT,recipient TEXT,app TEXT,scope TEXT,enabled INTEGER,PRIMARY KEY(ctx,recipient,app,scope));
 CREATE TABLE IF NOT EXISTS tings(id TEXT PRIMARY KEY,ctx TEXT,app TEXT,recipient TEXT,type TEXT,created TEXT,body TEXT,silent INTEGER,read INTEGER DEFAULT 0);
 CREATE INDEX IF NOT EXISTS accounts_inbox ON tings(ctx,recipient,created,id);
 CREATE INDEX IF NOT EXISTS accounts_ting_age ON tings(created);
 CREATE INDEX IF NOT EXISTS accounts_sent ON tings(ctx,app,created,id);
 CREATE TABLE IF NOT EXISTS keys(ctx TEXT,owner TEXT,kind TEXT,key TEXT,fingerprint TEXT,response TEXT,expires INTEGER,PRIMARY KEY(ctx,owner,kind,key));
 CREATE TABLE IF NOT EXISTS hooks(id TEXT PRIMARY KEY,ctx TEXT,recipient TEXT,state TEXT,receiver TEXT,session TEXT);
 CREATE INDEX IF NOT EXISTS accounts_hooks_owner ON hooks(ctx,recipient);
 CREATE TABLE IF NOT EXISTS deliveries(hook TEXT,message TEXT,offered INTEGER DEFAULT 0,offer_receiver TEXT,delivery INTEGER DEFAULT 0,read INTEGER DEFAULT 0,last_offer INTEGER DEFAULT 0,PRIMARY KEY(hook,message),FOREIGN KEY(hook) REFERENCES hooks(id),FOREIGN KEY(message) REFERENCES tings(id));
 CREATE TABLE IF NOT EXISTS cursors(id TEXT PRIMARY KEY,binding TEXT,position INTEGER,boundary TEXT,expires INTEGER);
 CREATE TABLE IF NOT EXISTS login_attempts(id TEXT PRIMARY KEY,next TEXT,expires INTEGER);
 UPDATE hooks SET receiver=NULL,session=NULL,state=CASE WHEN state='connected' THEN 'disconnected' ELSE state END;
 UPDATE deliveries SET delivery=0,offer_receiver=NULL,last_offer=0 WHERE read=0;")?;
        crate::migration::copy_types(&c)?;
        c.execute_batch("CREATE TABLE IF NOT EXISTS type_schemas(ctx TEXT,name TEXT,schema TEXT NOT NULL,PRIMARY KEY(ctx,name));
 CREATE TABLE IF NOT EXISTS ting_preferences(ctx TEXT,recipient TEXT,app TEXT,scope TEXT,mode TEXT NOT NULL,PRIMARY KEY(ctx,recipient,app,scope));
 INSERT OR IGNORE INTO ting_preferences SELECT ctx,recipient,app,scope,CASE enabled WHEN 1 THEN 'allowed' ELSE 'silent' END FROM preferences WHERE scope<>'delivery:required' AND scope NOT LIKE 'service:%';
 INSERT OR IGNORE INTO ting_preferences SELECT p.ctx,p.recipient,p.app,'type:'||t.name,CASE p.enabled WHEN 1 THEN 'allowed' ELSE 'silent' END FROM preferences p JOIN types t ON t.ctx=p.ctx AND t.app=p.app AND t.name LIKE p.app||'.'||substr(p.scope,9)||'.%' WHERE p.scope LIKE 'service:%';
 DELETE FROM preferences WHERE scope LIKE 'service:%';
 CREATE TABLE IF NOT EXISTS receiver_sessions(id TEXT PRIMARY KEY,created TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS receiver_accounts(receiver TEXT,ctx TEXT,recipient TEXT,auth_session TEXT,PRIMARY KEY(receiver,ctx,recipient),FOREIGN KEY(receiver) REFERENCES receiver_sessions(id) ON DELETE CASCADE);
 CREATE INDEX IF NOT EXISTS receiver_accounts_owner ON receiver_accounts(ctx,recipient);
 CREATE TABLE IF NOT EXISTS session_deliveries(receiver TEXT,message TEXT,batch TEXT,PRIMARY KEY(receiver,message),FOREIGN KEY(receiver) REFERENCES receiver_sessions(id) ON DELETE CASCADE,FOREIGN KEY(message) REFERENCES tings(id) ON DELETE CASCADE);
 CREATE TABLE IF NOT EXISTS silent_state(message TEXT PRIMARY KEY,sent INTEGER NOT NULL DEFAULT 0,FOREIGN KEY(message) REFERENCES tings(id) ON DELETE CASCADE);
 INSERT OR IGNORE INTO silent_state(message) SELECT id FROM tings WHERE silent=1;
 CREATE TABLE IF NOT EXISTS silent_schedules(ctx TEXT,recipient TEXT,enabled INTEGER NOT NULL DEFAULT 1,time TEXT NOT NULL DEFAULT '09:00',timezone TEXT NOT NULL DEFAULT 'UTC',next_at INTEGER NOT NULL,default_pending INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(ctx,recipient));
 CREATE INDEX IF NOT EXISTS silent_schedules_due ON silent_schedules(enabled,next_at);
 DELETE FROM receiver_sessions;
 DELETE FROM grants WHERE recipient LIKE 'session:%';
 DELETE FROM silent_schedules WHERE recipient LIKE 'session:%';
 DELETE FROM ting_preferences WHERE recipient LIKE 'session:%';")?;
        let has_digest: bool = c
            .prepare("PRAGMA table_info(deliveries)")?
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<std::result::Result<Vec<_>, _>>()?
            .iter()
            .any(|name| name == "digest");
        if !has_digest {
            c.execute_batch(
                "ALTER TABLE deliveries ADD COLUMN digest INTEGER NOT NULL DEFAULT 0;",
            )?;
        }
        let has_default_pending = c
            .prepare("PRAGMA table_info(silent_schedules)")?
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<std::result::Result<Vec<_>, _>>()?
            .iter()
            .any(|name| name == "default_pending");
        if !has_default_pending {
            // Existing schedules may be intentional, including 09:00 UTC.
            c.execute_batch("ALTER TABLE silent_schedules ADD COLUMN default_pending INTEGER NOT NULL DEFAULT 0;")?;
        }
        let store = Self { db: Mutex::new(c) };
        store.prune()?;
        Ok(store)
    }
    // ponytail: one serialized SQLite writer on one durable AWS volume; use Postgres before adding server replicas.
    fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.db
            .lock()
            .map_err(|_| Error::unavailable("Database writer lock is unavailable."))
    }
    fn mode(
        db: &Connection,
        ctx: &str,
        recipient: &str,
        typ: &str,
        sender: Option<&str>,
    ) -> Result<&'static str> {
        let (app, tail) = typ
            .split_once('.')
            .ok_or_else(|| v_err("Invalid stored notification type."))?;
        let service = tail
            .split_once('.')
            .map(|(service, _)| format!("service:{service}"));
        let mut scopes = vec![
            (app.to_owned(), "app".to_owned()),
            (app.to_owned(), format!("type:{typ}")),
        ];
        if let Some(service) = service {
            scopes.push((app.to_owned(), service));
        }
        if let Some(sender) = sender {
            scopes.push((String::new(), format!("from:{sender}")));
        }
        let mut result = "allowed";
        for (app, scope) in scopes {
            let mode: Option<String> = db.query_row("SELECT mode FROM ting_preferences WHERE ctx=? AND recipient=? AND app=? AND scope=?",params![ctx,recipient,app,scope],|r|r.get(0)).optional()?;
            match mode.as_deref() {
                Some("blocked") => return Ok("blocked"),
                Some("silent") => result = "silent",
                _ => {}
            }
        }
        Ok(result)
    }
    fn grant(db: &Connection, ctx: &str, app: &str, recipient: &str) -> Result<bool> {
        Ok(db
            .query_row(
                "SELECT active FROM grants WHERE ctx=? AND app=? AND recipient=?",
                params![ctx, app, recipient],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(false))
    }
    fn required_delivery_enabled(
        db: &Connection,
        ctx: &str,
        app: &str,
        recipient: &str,
    ) -> Result<bool> {
        Ok(db.query_row(
            "SELECT EXISTS(SELECT 1 FROM preferences WHERE ctx=? AND app=? AND recipient=? AND scope='delivery:required' AND enabled=1)",
            params![ctx, app, recipient],
            |r| r.get(0),
        )?)
    }
    pub fn register_type(
        &self,
        p: &Principal,
        app: &str,
        b: &Value,
        update: bool,
    ) -> Result<(u16, Value)> {
        v::fields(
            b,
            if update {
                &["description", "schema"]
            } else {
                &["type", "description", "schema"]
            },
            if update {
                &[]
            } else {
                &["type", "description", "schema"]
            },
        )?;
        if update && b.as_object().is_none_or(|m| m.is_empty()) {
            return Err(v_err("Supply description or schema."));
        }
        let typ = if update {
            app
        } else {
            v::string(b, "type", 255)?
        };
        let (owner, _) = v::type_parts(typ)?;
        if !update && owner != app {
            return Err(v_err("The type must belong to the app in the URL."));
        }
        if b.get("description").is_some() {
            v::text(b, "description", 1000)?;
        }
        if let Some(schema) = b.get("schema") {
            v::schema(schema)?;
        }
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        let old: Option<(String, String)> = tx.query_row("SELECT t.description,COALESCE(s.schema,'{}') FROM types t LEFT JOIN type_schemas s ON s.ctx=t.ctx AND s.name=t.name WHERE t.ctx=? AND t.name=?",params![p.context,typ],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        if update && old.is_none() {
            return Err(Error::not_found());
        }
        let description = b
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| old.as_ref().map(|r| r.0.clone()))
            .unwrap();
        let schema = b.get("schema").cloned().unwrap_or(decode(
            old.as_ref()
                .map(|r| r.1.clone())
                .unwrap_or_else(|| "{}".into()),
        )?);
        let status = if update {
            200
        } else if let Some((old_description, old_schema)) = &old {
            if old_description != &description || decode(old_schema.clone())? != schema {
                return Err(conflict(
                    "type_exists",
                    "This type already has a different definition. Use PATCH to update it.",
                ));
            }
            200
        } else {
            201
        };
        tx.execute(
            "INSERT OR REPLACE INTO types VALUES(?,?,?,?)",
            params![p.context, owner, typ, description],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO type_schemas VALUES(?,?,?)",
            params![p.context, typ, schema.to_string()],
        )?;
        tx.commit()?;
        Ok((
            status,
            json!({"type":typ,"description":description,"schema":schema,"defaults":{"carbon":"allowed","silicon":"allowed"}}),
        ))
    }
    pub fn types_for_app(&self, app: &str) -> Result<Vec<Value>> {
        let db = self.lock()?;
        let mut q = db.prepare("SELECT t.name,t.description,COALESCE(s.schema,'{}') FROM types t LEFT JOIN type_schemas s ON s.ctx=t.ctx AND s.name=t.name WHERE t.ctx='accounts' AND t.app=? ORDER BY t.name")?;
        let rows = q
            .query_map([app], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        rows.into_iter().map(|(typ,description,schema)|Ok(json!({"type":typ,"description":description,"schema":decode(schema)?,"defaults":{"carbon":"allowed","silicon":"allowed"}}))).collect()
    }
    pub fn subscribe_app(&self, p: &Proof, b: &Value) -> Result<(u16, Value)> {
        v::fields(b, &["app_id", "for"], &["app_id"])?;
        if v::string(b, "app_id", 255)? != p.app_id
            || b.get("for")
                .is_some_and(|f| f.as_str() != Some(&p.actor_id))
        {
            return Err(Error::new(
                403,
                "permission_denied",
                "The registration must match the verified issuing app and actor.",
                "Obtain the recipient's consent through Silicon Accounts User verification.",
            ));
        }
        let db = self.lock()?;
        let old: Option<(String, bool)> = db
            .query_row(
                "SELECT id,active FROM grants WHERE ctx=? AND app=? AND recipient=?",
                params![p.context, p.app_id, p.actor_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (sid, status) = if let Some((sid, active)) = old {
            db.execute("UPDATE grants SET active=1 WHERE id=?", [&sid])?;
            (sid, if active { 200 } else { 201 })
        } else {
            let sid = id("sub");
            db.execute(
                "INSERT INTO grants VALUES(?,?,?,?,1)",
                params![sid, p.context, p.app_id, p.actor_id],
            )?;
            (sid, 201)
        };
        Ok((
            status,
            json!({"id":sid,"app_id":p.app_id,"for":p.actor_id,"active":true,"required_delivery":Self::required_delivery_enabled(&db,&p.context,&p.app_id,&p.actor_id)?}),
        ))
    }
    pub fn grants(
        &self,
        ctx: &str,
        recipient: Option<&str>,
        app: Option<&str>,
    ) -> Result<Vec<Value>> {
        let db = self.lock()?;
        let mut q=db.prepare("SELECT g.id,g.app,g.recipient,g.active,g.active AND COALESCE(p.enabled,0) FROM grants g LEFT JOIN preferences p ON p.ctx=g.ctx AND p.app=g.app AND p.recipient=g.recipient AND p.scope='delivery:required' WHERE g.ctx=? AND (? IS NULL OR g.recipient=?) AND (? IS NULL OR g.app=?) ORDER BY g.id")?;
        Ok(q.query_map(params![ctx,recipient,recipient,app,app],|r|Ok(json!({"id":r.get::<_,String>(0)?,"app_id":r.get::<_,String>(1)?,"for":r.get::<_,String>(2)?,"active":r.get::<_,bool>(3)?,"required_delivery":r.get::<_,bool>(4)?})))?.collect::<std::result::Result<_,_>>()?)
    }
    pub fn required_delivery(
        &self,
        p: &Principal,
        sid: &str,
        enabled: Option<bool>,
    ) -> Result<Value> {
        let db = self.lock()?;
        let grant: Option<(String, bool)> = db
            .query_row(
                "SELECT app,active FROM grants WHERE ctx=? AND id=? AND recipient=?",
                params![p.context, sid, p.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (app, active) = grant.ok_or_else(Error::not_found)?;
        if enabled == Some(true) && !active {
            return Err(Error::new(
                403,
                "recipient_not_registered",
                "Required delivery needs an active recipient registration.",
                "Register through Silicon Accounts User verification, then explicitly enable required delivery.",
            ));
        }
        if let Some(enabled) = enabled {
            if enabled {
                db.execute(
                    "INSERT OR REPLACE INTO preferences VALUES(?,?,?,'delivery:required',1)",
                    params![p.context, p.id, app],
                )?;
            } else {
                db.execute(
                    "DELETE FROM preferences WHERE ctx=? AND recipient=? AND app=? AND scope='delivery:required'",
                    params![p.context, p.id, app],
                )?;
            }
        }
        Ok(
            json!({"id":sid,"app_id":app,"for":p.id,"enabled":active && Self::required_delivery_enabled(&db,&p.context,&app,&p.id)?}),
        )
    }
    pub fn revoke(
        &self,
        ctx: &str,
        sid: &str,
        recipient: Option<&str>,
        app: Option<&str>,
    ) -> Result<(Value, String)> {
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        let grant:Option<(String,String)>=tx.query_row("SELECT recipient,app FROM grants WHERE ctx=? AND id=? AND (? IS NULL OR recipient=?) AND (? IS NULL OR app=?)",params![ctx,sid,recipient,recipient,app,app],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let (owner, app) = grant.ok_or_else(Error::not_found)?;
        tx.execute("UPDATE grants SET active=0 WHERE id=?", [sid])?;
        tx.execute("DELETE FROM preferences WHERE ctx=? AND recipient=? AND app=? AND scope='delivery:required'",params![ctx,owner,app])?;
        tx.commit()?;
        Ok((
            json!({"id":sid,"active":false,"required_delivery":false}),
            owner,
        ))
    }
    pub fn send(&self, p: &AppAuthority, b: &Value) -> Result<(u16, Value)> {
        v::fields(
            b,
            &[
                "type",
                "data",
                "metadata",
                "for",
                "from",
                "session_id",
                "key",
                "delivery",
            ],
            &["type", "data", "key"],
        )?;
        let typ = v::string(b, "type", 255)?;
        let (app, _) = v::type_parts(typ)?;
        if app != p.app_id {
            return Err(Error::new(
                403,
                "permission_denied",
                "The type does not belong to the verified app.",
                "Use a type registered to the issuing app.",
            ));
        }
        let key = v::string(b, "key", 200)?;
        let target = if b.get("session_id").is_some() {
            Some(v::string(b, "session_id", 255)?)
        } else {
            None
        };
        let sender = if b.get("from").is_some_and(|x| !x.is_null()) {
            Some(v::string(b, "from", 255)?)
        } else {
            None
        };
        let explicit_recipient = if b.get("for").is_some() {
            Some(v::string(b, "for", 255)?)
        } else {
            None
        };
        if explicit_recipient.is_none() && target.is_none() {
            return Err(v_err("Supply for, session_id, or both."));
        }
        let required = match b.get("delivery") {
            None => false,
            Some(Value::String(mode)) if mode == "required" => true,
            _ => return Err(v_err("delivery must be 'required' when specified.")),
        };
        if !b["data"].is_object() || b.get("metadata").is_some_and(|x| !x.is_object()) {
            return Err(v_err("data and metadata must be JSON objects."));
        }
        let mut normalized = b.clone();
        if normalized.get("metadata").is_none() {
            normalized["metadata"] = json!({});
        }
        let fingerprint = hex::encode(Sha256::digest(serde_json::to_vec(&normalized)?));
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if let Some((fp,response))=tx.query_row("SELECT fingerprint,response FROM keys WHERE ctx=? AND owner=? AND kind='send' AND key=? AND expires>?",params![p.context,p.app_id,key,now()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?))).optional()?{if fp!=fingerprint{return Err(conflict("idempotency_conflict","This key was accepted with different content."))}return Ok((200,decode(response)?))}
        let schema:Option<String>=tx.query_row("SELECT COALESCE(s.schema,'{}') FROM types t LEFT JOIN type_schemas s ON s.ctx=t.ctx AND s.name=t.name WHERE t.ctx=? AND t.app=? AND t.name=?",params![p.context,app,typ],|r|r.get(0)).optional()?;
        let schema = decode(schema.ok_or_else(Error::not_found)?)?;
        if !v::schema(&schema)?.is_valid(&b["data"]) {
            return Err(v_err(
                "data does not match this notification type's schema.",
            ));
        }
        let recipient = match (explicit_recipient, target) {
            (Some(recipient), _) => recipient.to_owned(),
            (None, Some(target)) => {
                let mut q = tx.prepare(
                    "SELECT recipient FROM receiver_accounts WHERE receiver=? AND ctx=?",
                )?;
                let owners = q
                    .query_map(params![target, p.context], |r| r.get::<_, String>(0))?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                match owners.as_slice() {
                    [] => format!("session:{target}"),
                    [owner] => owner.clone(),
                    _ => {
                        return Err(v_err(
                            "for is required when a session has more than one identity.",
                        ));
                    }
                }
            }
            _ => unreachable!(),
        };
        let receivers = Self::target_receivers(&tx, &p.context, &recipient, target)?;
        if target.is_some() && receivers.is_empty() {
            return Err(Error::new(
                409,
                "session_gone",
                "The target session is inactive or does not belong to the recipient.",
                "Use an active session for this recipient.",
            ));
        }
        if !Self::grant(&tx, &p.context, app, &recipient)? {
            return Err(Error::new(
                403,
                "recipient_not_registered",
                "The app does not have permission to notify this recipient.",
                "The recipient must subscribe; anonymous sessions register app_ids over WebSocket.",
            ));
        }
        if required && !Self::required_delivery_enabled(&tx, &p.context, app, &recipient)? {
            return Err(Error::new(
                403,
                "required_delivery_not_enabled",
                "The recipient has not enabled required delivery for this app.",
                "The recipient must explicitly enable required delivery on their subscription.",
            ));
        }
        let mode = Self::mode(&tx, &p.context, &recipient, typ, sender)?;
        let silent = mode == "silent";
        let mid = id("msg");
        let created = stamp();
        let mut full = json!({"id":mid,"created_at":created,"type":typ,"data":b["data"],"metadata":normalized["metadata"],"for":if recipient.starts_with("session:"){None}else{Some(&recipient)},"from":sender,"session_id":target,"key":key,"silent":silent,"read":false});
        if required {
            full["delivery"] = "required".into();
        }
        if mode != "blocked" {
            tx.execute("INSERT INTO tings(id,ctx,app,recipient,type,created,body,silent) VALUES(?,?,?,?,?,?,?,?)",params![mid,p.context,app,recipient,typ,created,full.to_string(),silent])?;
            if silent {
                tx.execute("INSERT INTO silent_state(message) VALUES(?)", [&mid])?;
                Self::ensure_schedule(&tx, &p.context, &recipient, now())?;
            } else {
                tx.execute("INSERT INTO deliveries(hook,message) SELECT id,? FROM hooks WHERE ctx=? AND recipient=? AND (? IS NULL OR receiver=?)",params![mid,p.context,recipient,target,target])?;
                for receiver in receivers {
                    tx.execute(
                        "INSERT INTO session_deliveries(receiver,message) VALUES(?,?)",
                        params![receiver, mid],
                    )?;
                }
            }
        }
        let mut response = json!({"id":mid,"created_at":created,"status":if mode=="blocked"{"blocked"}else{"accepted"},"key":key,"mode":mode,"silent":silent,"for":full["for"],"session_id":target});
        if required {
            response["delivery"] = "required".into();
        }
        tx.execute(
            "INSERT OR REPLACE INTO keys VALUES(?,?,'send',?,?,?,?)",
            params![
                p.context,
                p.app_id,
                key,
                fingerprint,
                response.to_string(),
                now() + 14 * 86400
            ],
        )?;
        tx.commit()?;
        Ok((202, response))
    }
    pub fn tings(
        &self,
        ctx: &str,
        recipient: Option<&str>,
        app: Option<&str>,
        f: &Value,
    ) -> Result<Vec<Value>> {
        v::filters(f)?;
        let db = self.lock()?;
        let limit = f["limit"].as_u64().unwrap_or(50) as i64;
        let (last, boundary) = if let Some(cursor) = f["cursor"].as_str() {
            let row: Option<(String, String)> = db
                .query_row(
                    "SELECT position,boundary FROM cursors WHERE id=? AND expires>?",
                    params![cursor, now()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let (position, boundary) = row.ok_or_else(cursor_err)?;
            (
                Some(serde_json::from_str::<Vec<String>>(&position).map_err(|_| cursor_err())?),
                boundary,
            )
        } else {
            (None, stamp())
        };
        let last_created = last.as_ref().and_then(|p| p.first()).map(String::as_str);
        let last_id = last.as_ref().and_then(|p| p.get(1)).map(String::as_str);
        let mut q = db.prepare(
            "SELECT body,read,type,recipient,silent FROM tings WHERE ctx=?1
          AND (?2 IS NULL OR recipient=?2) AND (?3 IS NULL OR app=?3)
          AND (?4 IS NULL OR type=?4) AND (?5 IS NULL OR read=?5) AND (?6 IS NULL OR silent=?6)
          AND created<=?7 AND (?8 IS NULL OR (created,id)<(?8,?9))
          AND (((read=0 AND (EXISTS(SELECT 1 FROM silent_state s WHERE s.message=tings.id AND s.sent=0) OR EXISTS(SELECT 1 FROM session_deliveries d WHERE d.message=tings.id))) OR EXISTS(SELECT 1 FROM deliveries d WHERE d.message=tings.id AND d.digest=1 AND d.read=0)) OR (created>=?11 AND ((read=0 AND silent=0) OR created>=?12))) ORDER BY created DESC,id DESC LIMIT ?10",
        )?;
        let rows = q.query_map(
            params![
                ctx,
                recipient,
                app,
                f["type"].as_str(),
                f["read"].as_bool(),
                f["silent"].as_bool(),
                boundary,
                last_created,
                last_id,
                limit + 1,
                retention_cutoff(3),
                retention_cutoff(1)
            ],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, bool>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, bool>(4)?,
                ))
            },
        )?;
        let mut out = vec![];
        for row in rows {
            let (body, read, typ, recipient, silent) = row?;
            let mut t = current_body(body, typ, recipient)?;
            t["read"] = read.into();
            t["silent"] = silent.into();
            out.push(t);
        }
        Ok(out)
    }
    pub fn ting(
        &self,
        ctx: &str,
        mid: &str,
        recipient: Option<&str>,
        app: Option<&str>,
    ) -> Result<Value> {
        let db = self.lock()?;
        let row:Option<(String,bool,String,String,bool)>=db.query_row("SELECT body,read,type,recipient,silent FROM tings WHERE ctx=? AND id=? AND (? IS NULL OR recipient=?) AND (? IS NULL OR app=?) AND (((read=0 AND (EXISTS(SELECT 1 FROM silent_state s WHERE s.message=tings.id AND s.sent=0) OR EXISTS(SELECT 1 FROM session_deliveries d WHERE d.message=tings.id))) OR EXISTS(SELECT 1 FROM deliveries d WHERE d.message=tings.id AND d.digest=1 AND d.read=0)) OR (created>=? AND ((read=0 AND silent=0) OR created>=?)))",params![ctx,mid,recipient,recipient,app,app,retention_cutoff(3),retention_cutoff(1)],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
        let (b, read, typ, recipient, silent) = row.ok_or_else(Error::not_found)?;
        let mut b = current_body(b, typ, recipient)?;
        b["read"] = read.into();
        b["silent"] = silent.into();
        Ok(b)
    }
    pub fn deliveries(&self, mid: &str) -> Result<Vec<Value>> {
        let db = self.lock()?;
        let mut q =
            db.prepare("SELECT hook,delivery,read FROM deliveries WHERE message=? ORDER BY hook")?;
        Ok(q.query_map([mid],|r|Ok(json!({"webhook_id":r.get::<_,String>(0)?,"delivery_acked":r.get::<_,bool>(1)?,"read_acked":r.get::<_,bool>(2)?})))?.collect::<std::result::Result<_,_>>()?)
    }
    pub fn sent_read(&self, p: &AppAuthority, b: &Value) -> Result<(Value, Vec<(String, bool)>)> {
        let fields = &["app_id", "message_ids", "read", "key"];
        v::fields(b, fields, fields)?;
        if v::string(b, "app_id", 255)? != p.app_id {
            return Err(Error::new(
                403,
                "permission_denied",
                "The app must match the verified proof issuer.",
                "Prepare a request for the issuing app.",
            ));
        }
        let ids = v::ids(b, "message_ids", false)?;
        let read = v::optional_bool(b, "read")?.unwrap();
        let key = v::string(b, "key", 200)?;
        let mut normalized = b.clone();
        normalized["message_ids"] = json!(ids);
        let fingerprint = hex::encode(Sha256::digest(serde_json::to_vec(&normalized)?));
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let prior: Option<(String, String)> = tx.query_row(
            "SELECT fingerprint,response FROM keys WHERE ctx=? AND owner=? AND kind='sent-read' AND key=? AND expires>?",
            params![p.context,p.app_id,key,now()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ).optional()?;
        if let Some((original, response)) = prior {
            if original != fingerprint {
                return Err(conflict(
                    "idempotency_conflict",
                    "This read-state key was accepted with different content.",
                ));
            }
            // A delayed retry must not overwrite a newer read/unread decision.
            return Ok((decode(response)?, vec![]));
        }
        let cutoff = retention_cutoff(3);
        let read_cutoff = retention_cutoff(1);
        let mut owners = std::collections::BTreeMap::<String, bool>::new();
        for mid in &ids {
            let row: Option<(String, String, bool)> = tx
                .query_row(
                    "SELECT recipient,created,read FROM tings WHERE ctx=? AND app=? AND id=?
                 AND (((read=0 AND (EXISTS(SELECT 1 FROM silent_state s WHERE s.message=tings.id AND s.sent=0) OR EXISTS(SELECT 1 FROM session_deliveries d WHERE d.message=tings.id))) OR EXISTS(SELECT 1 FROM deliveries d WHERE d.message=tings.id AND d.digest=1 AND d.read=0)) OR (created>=? AND ((read=0 AND silent=0) OR created>=?)))",
                    params![p.context, p.app_id, mid, cutoff, read_cutoff],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let (recipient, created, previous) = row.ok_or_else(Error::not_found)?;
            if previous != read {
                let expired = read && created < read_cutoff;
                *owners.entry(recipient).or_default() |= expired;
            }
        }
        // Validate the entire batch before changing any recipient's state.
        for mid in &ids {
            tx.execute("UPDATE tings SET read=? WHERE id=?", params![read, mid])?;
        }
        let response = json!({"message_ids":ids,"read":read});
        tx.execute(
            "INSERT OR REPLACE INTO keys VALUES(?,?,'sent-read',?,?,?,?)",
            params![
                p.context,
                p.app_id,
                key,
                fingerprint,
                response.to_string(),
                now() + 14 * 86400
            ],
        )?;
        tx.commit()?;
        Ok((response, owners.into_iter().collect()))
    }
    pub fn read(&self, p: &Principal, ids: &[String]) -> Result<(Value, bool)> {
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        let cutoff = retention_cutoff(1);
        let mut expired = false;
        for mid in ids {
            let row: Option<(String, bool)> = tx
                .query_row(
                    "SELECT created,read FROM tings WHERE id=? AND ctx=? AND recipient=?",
                    params![mid, p.context, p.id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let (created, read) = row.ok_or_else(Error::not_found)?;
            expired |= !read && created < cutoff;
        }
        for mid in ids {
            tx.execute("UPDATE tings SET read=1 WHERE id=?", [mid])?;
        }
        tx.commit()?;
        Ok((json!({"message_ids":ids,"read":true}), expired))
    }
    pub fn preferences(&self, p: &Principal, f: &Value) -> Result<Vec<Value>> {
        let db = self.lock()?;
        let mut q=db.prepare("SELECT app,scope,mode FROM ting_preferences WHERE ctx=? AND recipient=? ORDER BY app,scope")?;
        let rows = q.query_map(params![p.context, p.id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        let mut out = vec![];
        for row in rows {
            let (app, scope, mode) = row?;
            let value = json!({"app_id":if app.is_empty(){None}else{Some(app)},"type":scope.strip_prefix("type:"),"service":scope.strip_prefix("service:"),"from":scope.strip_prefix("from:"),"mode":mode,"enabled":mode=="allowed"});
            if ["app_id", "type", "service", "from", "mode"]
                .iter()
                .any(|k| f.get(*k).is_some_and(|x| *x != value[*k]))
            {
                continue;
            }
            out.push(value);
        }
        Ok(out)
    }
    pub fn preference(&self, p: &Principal, b: &Value, reset: bool) -> Result<Value> {
        v::preference(b, !reset)?;
        let app = b["app_id"].as_str().unwrap_or("");
        let scope = if let Some(sender) = b["from"].as_str() {
            format!("from:{sender}")
        } else if let Some(typ) = b["type"].as_str() {
            format!("type:{typ}")
        } else {
            "app".into()
        };
        let mode = b["mode"]
            .as_str()
            .unwrap_or(if b["enabled"].as_bool().unwrap_or(true) {
                "allowed"
            } else {
                "silent"
            });
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        if reset {
            tx.execute(
                "DELETE FROM ting_preferences WHERE ctx=? AND recipient=? AND app=? AND scope=?",
                params![p.context, p.id, app, scope],
            )?;
            // Remove the migrated source so restarting cannot restore a reset preference.
            tx.execute(
                "DELETE FROM preferences WHERE ctx=? AND recipient=? AND app=? AND scope=?",
                params![p.context, p.id, app, scope],
            )?;
        } else {
            tx.execute(
                "INSERT OR REPLACE INTO ting_preferences VALUES(?,?,?,?,?)",
                params![p.context, p.id, app, scope, mode],
            )?;
        }
        let pending = {
            let mut q=tx.prepare("SELECT id,type,body FROM tings WHERE ctx=? AND recipient=? AND read=0 AND silent=0")?;
            q.query_map(params![p.context, p.id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
        };
        for (mid, typ, body) in pending {
            let body = decode(body)?;
            match Self::mode(&tx, &p.context, &p.id, &typ, body["from"].as_str())? {
                "silent" => {
                    tx.execute("UPDATE tings SET silent=1 WHERE id=?", [&mid])?;
                    tx.execute(
                        "INSERT OR IGNORE INTO silent_state(message) VALUES(?)",
                        [&mid],
                    )?;
                    tx.execute("DELETE FROM deliveries WHERE message=?", [&mid])?;
                    tx.execute("DELETE FROM session_deliveries WHERE message=?", [&mid])?;
                    Self::ensure_schedule(&tx, &p.context, &p.id, now())?;
                }
                "blocked" => {
                    tx.execute("DELETE FROM deliveries WHERE message=?", [&mid])?;
                    tx.execute("DELETE FROM session_deliveries WHERE message=?", [&mid])?;
                }
                _ => {}
            }
        }
        tx.commit()?;
        Ok(
            json!({"app_id":b["app_id"],"type":b["type"],"from":b["from"],"mode":mode,"reset":reset,"enabled":mode=="allowed"}),
        )
    }
    pub fn page(
        &self,
        mut rows: Vec<Value>,
        binding: &str,
        f: &Value,
        ting: bool,
    ) -> Result<Value> {
        let limit = match f.get("limit") {
            None => 50,
            Some(v) => v
                .as_u64()
                .filter(|x| *x >= 1 && *x <= 100)
                .ok_or_else(|| v_err("limit must be an integer from 1 to 100."))?
                as usize,
        };
        let mut filters = f.clone();
        filters.as_object_mut().unwrap().remove("cursor");
        filters.as_object_mut().unwrap().remove("limit");
        let binding = format!("{binding}:{}", filters);
        let db = self.lock()?;
        let (position, mut boundary) = if let Some(c) = f.get("cursor") {
            let c = c.as_str().ok_or_else(cursor_err)?;
            let state: Option<(String, String, String, i64)> = db
                .query_row(
                    "SELECT binding,position,boundary,expires FROM cursors WHERE id=?",
                    [c],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?;
            let (b, pos, upper, expires) = state.ok_or_else(cursor_err)?;
            if b != binding || expires <= now() {
                return Err(cursor_err());
            }
            (
                Some(serde_json::from_str::<Vec<String>>(&pos).map_err(|_| cursor_err())?),
                upper,
            )
        } else {
            (None, stamp())
        };
        let key = |r: &Value| -> Vec<String> {
            if ting {
                vec![
                    r["created_at"].as_str().unwrap_or_default().into(),
                    r["id"].as_str().unwrap_or_default().into(),
                ]
            } else if let Some(id) = r["id"].as_str().or(r["webhook_id"].as_str()) {
                vec![id.into()]
            } else if r.get("enabled").is_some() {
                vec![
                    r["app_id"].as_str().unwrap_or_default().into(),
                    r["service"].as_str().unwrap_or_default().into(),
                    r["type"].as_str().unwrap_or_default().into(),
                    r["from"].as_str().unwrap_or_default().into(),
                ]
            } else {
                vec![
                    r["type"]
                        .as_str()
                        .or(r["app_id"].as_str())
                        .unwrap_or_default()
                        .into(),
                ]
            }
        };
        if !ting {
            if position.is_none() {
                boundary = serde_json::to_string(&rows.iter().map(&key).collect::<Vec<_>>())?;
            }
            let allowed: std::collections::HashSet<Vec<String>> =
                serde_json::from_str::<Vec<Vec<String>>>(&boundary)
                    .map_err(|_| cursor_err())?
                    .into_iter()
                    .collect();
            rows.retain(|r| allowed.contains(&key(r)));
        }
        rows.sort_by_key(&key);
        if ting {
            rows.reverse();
            rows.retain(|r| {
                r["created_at"]
                    .as_str()
                    .is_some_and(|s| s <= boundary.as_str())
            })
        }
        if let Some(last) = position {
            rows.retain(|r| if ting { key(r) < last } else { key(r) > last });
        }
        let more = rows.len() > limit;
        let items: Vec<_> = rows.into_iter().take(limit).collect();
        let position = items.last().map(key);
        let mut out = json!({"items":items});
        if more {
            let c = id("cur");
            db.execute(
                "INSERT INTO cursors VALUES(?,?,?,?,?)",
                params![
                    c,
                    binding,
                    serde_json::to_string(&position.unwrap())?,
                    boundary,
                    now() + 86400
                ],
            )?;
            out["next_cursor"] = c.into();
        }
        Ok(out)
    }
    pub fn create_receiver_session(&self, receiver: &str) -> Result<()> {
        self.lock()?.execute(
            "INSERT INTO receiver_sessions VALUES(?,?)",
            params![receiver, stamp()],
        )?;
        Ok(())
    }
    pub fn attach_receiver_session(&self, receiver: &str, p: &Principal) -> Result<()> {
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        let anonymous = format!("session:{receiver}");
        tx.execute("DELETE FROM session_deliveries WHERE receiver=? AND message IN(SELECT id FROM tings WHERE recipient=?)",params![receiver,anonymous])?;
        tx.execute("DELETE FROM grants WHERE recipient=?", [&anonymous])?;
        tx.execute(
            "DELETE FROM silent_schedules WHERE recipient=?",
            [&anonymous],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO receiver_accounts VALUES(?,?,?,?)",
            params![receiver, p.context, p.id, p.session],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn remove_receiver_identity(&self, receiver: &str, auth_session: &str) -> Result<()> {
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        tx.execute("DELETE FROM session_deliveries WHERE receiver=?1 AND message IN(SELECT t.id FROM tings t JOIN receiver_accounts a ON a.ctx=t.ctx AND a.recipient=t.recipient WHERE a.receiver=?1 AND a.auth_session=?2)",params![receiver,auth_session])?;
        tx.execute(
            "DELETE FROM receiver_accounts WHERE receiver=? AND auth_session=?",
            params![receiver, auth_session],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn remove_receiver_session(&self, receiver: &str) -> Result<()> {
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        tx.execute("DELETE FROM receiver_sessions WHERE id=?", [receiver])?;
        let owner = format!("session:{receiver}");
        tx.execute("DELETE FROM grants WHERE recipient=?", [&owner])?;
        tx.execute("DELETE FROM ting_preferences WHERE recipient=?", [&owner])?;
        tx.execute("DELETE FROM silent_schedules WHERE recipient=?", [&owner])?;
        tx.commit()?;
        Ok(())
    }
    pub fn receiver_sessions(&self, p: &Principal) -> Result<Vec<Value>> {
        let db = self.lock()?;
        let mut q=db.prepare("SELECT s.id,s.created FROM receiver_sessions s JOIN receiver_accounts a ON a.receiver=s.id WHERE a.ctx=? AND a.recipient=? ORDER BY s.created,s.id")?;
        Ok(q.query_map(params![p.context,p.id],|r|{let id:String=r.get(0)?;Ok(json!({"id":id,"session_id":id,"created_at":r.get::<_,String>(1)?,"for":p.id,"active":true}))})?.collect::<std::result::Result<_,_>>()?)
    }
    pub fn register_receiver_apps(&self, receiver: &str, apps: &[String]) -> Result<()> {
        if apps.len() > 100 || apps.iter().any(|app| !v::app_id(app)) {
            return Err(v_err("app_ids must contain at most 100 Silicon Apps IDs."));
        }
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM receiver_sessions WHERE id=?)",
            [receiver],
            |r| r.get(0),
        )?;
        if !exists {
            return Err(Error::not_found());
        }
        let identified: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM receiver_accounts WHERE receiver=?)",
            [receiver],
            |r| r.get(0),
        )?;
        if identified {
            return Err(v_err(
                "Identified sessions must subscribe through a User verification proof.",
            ));
        }
        let owner = format!("session:{receiver}");
        for app in apps {
            tx.execute("INSERT INTO grants(id,ctx,app,recipient,active) VALUES(?,'accounts',?,?,1) ON CONFLICT(ctx,app,recipient) DO UPDATE SET active=1",params![id("sub"),app,owner])?;
        }
        tx.commit()?;
        Ok(())
    }
    fn target_receivers(
        db: &Connection,
        ctx: &str,
        recipient: &str,
        target: Option<&str>,
    ) -> Result<Vec<String>> {
        if let Some(anonymous) = recipient.strip_prefix("session:") {
            let exists:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM receiver_sessions s WHERE s.id=?1 AND NOT EXISTS(SELECT 1 FROM receiver_accounts a WHERE a.receiver=s.id))",[anonymous],|r|r.get(0))?;
            return Ok(if exists && target.is_none_or(|id| id == anonymous) {
                vec![anonymous.to_owned()]
            } else {
                vec![]
            });
        }
        let mut q=db.prepare("SELECT receiver FROM receiver_accounts WHERE ctx=? AND recipient=? AND (? IS NULL OR receiver=?) ORDER BY receiver")?;
        Ok(
            q.query_map(params![ctx, recipient, target, target], |r| r.get(0))?
                .collect::<std::result::Result<_, _>>()?,
        )
    }
    fn ensure_schedule(db: &Connection, ctx: &str, recipient: &str, at: i64) -> Result<()> {
        db.execute(
            "INSERT OR IGNORE INTO silent_schedules(ctx,recipient,next_at,default_pending) VALUES(?,?,?,1)",
            params![ctx, recipient, next_schedule("09:00", "UTC", at)?],
        )?;
        Ok(())
    }
    pub fn initialize_timezone(&self, ctx: &str, recipient: &str, timezone: &str) -> Result<()> {
        let next = next_schedule("00:00", timezone, now())?;
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        let changed = tx.execute("INSERT INTO silent_schedules(ctx,recipient,time,timezone,next_at,default_pending) VALUES(?,?,'00:00',?,?,0) ON CONFLICT(ctx,recipient) DO UPDATE SET time='00:00',timezone=excluded.timezone,next_at=excluded.next_at,default_pending=0 WHERE silent_schedules.default_pending=1",params![ctx,recipient,timezone,next])?;
        if changed > 0 {
            tx.execute("DELETE FROM session_deliveries WHERE batch IS NOT NULL AND message IN(SELECT t.id FROM tings t JOIN silent_state s ON s.message=t.id WHERE t.ctx=? AND t.recipient=? AND s.sent=0)",params![ctx,recipient])?;
            tx.execute("DELETE FROM deliveries WHERE digest=1 AND offered=0 AND message IN(SELECT t.id FROM tings t JOIN silent_state s ON s.message=t.id WHERE t.ctx=? AND t.recipient=? AND s.sent=0)",params![ctx,recipient])?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn silent_schedule(&self, p: &Principal) -> Result<Value> {
        let db = self.lock()?;
        Self::ensure_schedule(&db, &p.context, &p.id, now())?;
        Ok(db.query_row("SELECT enabled,time,timezone,next_at FROM silent_schedules WHERE ctx=? AND recipient=?",params![p.context,p.id],|r|Ok(json!({"enabled":r.get::<_,bool>(0)?,"time":r.get::<_,String>(1)?,"timezone":r.get::<_,String>(2)?,"next_at":r.get::<_,i64>(3)?})))?)
    }
    pub fn set_silent_schedule(&self, p: &Principal, b: &Value) -> Result<Value> {
        v::fields(b, &["enabled", "time", "timezone"], &[])?;
        if b.as_object().is_none_or(|m| m.is_empty()) {
            return Err(v_err("Supply enabled, time, or timezone."));
        }
        let old = self.silent_schedule(p)?;
        let enabled = v::optional_bool(b, "enabled")?.unwrap_or(old["enabled"].as_bool().unwrap());
        let time = if b.get("time").is_some() {
            v::string(b, "time", 5)?
        } else {
            old["time"].as_str().unwrap()
        };
        let timezone = if b.get("timezone").is_some() {
            v::string(b, "timezone", 100)?
        } else {
            old["timezone"].as_str().unwrap()
        };
        let next = next_schedule(time, timezone, now())?;
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        tx.execute("UPDATE silent_schedules SET enabled=?,time=?,timezone=?,next_at=?,default_pending=0 WHERE ctx=? AND recipient=?",params![enabled,time,timezone,next,p.context,p.id])?;
        tx.execute("DELETE FROM session_deliveries WHERE batch IS NOT NULL AND message IN(SELECT id FROM tings WHERE ctx=? AND recipient=?)",params![p.context,p.id])?;
        tx.execute("DELETE FROM deliveries WHERE digest=1 AND offered=0 AND message IN(SELECT id FROM tings WHERE ctx=? AND recipient=?)",params![p.context,p.id])?;
        tx.commit()?;
        Ok(json!({"enabled":enabled,"time":time,"timezone":timezone,"next_at":next}))
    }
    pub fn queue_due_digests(&self) -> Result<()> {
        self.queue_due_digests_at(now())
    }
    fn queue_due_digests_at(&self, at: i64) -> Result<()> {
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        let owners = {
            let mut q=tx.prepare("SELECT DISTINCT t.ctx,t.recipient FROM tings t JOIN silent_state s ON s.message=t.id JOIN grants g ON g.ctx=t.ctx AND g.app=t.app AND g.recipient=t.recipient AND g.active=1 WHERE s.sent=0 AND t.read=0 AND NOT EXISTS(SELECT 1 FROM silent_schedules schedule WHERE schedule.ctx=t.ctx AND schedule.recipient=t.recipient)")?;
            q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        for (ctx, owner) in owners {
            Self::ensure_schedule(&tx, &ctx, &owner, at)?;
        }
        let schedules = {
            let mut q=tx.prepare("SELECT ctx,recipient,time,timezone FROM silent_schedules WHERE enabled=1 AND next_at<=?")?;
            q.query_map([at], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
        };
        for (ctx, owner, time, timezone) in schedules {
            tx.execute(
                "UPDATE silent_schedules SET next_at=? WHERE ctx=? AND recipient=?",
                params![next_schedule(&time, &timezone, at)?, ctx, owner],
            )?;
            let pending = {
                let mut q=tx.prepare("SELECT t.id,t.app,t.type,t.body FROM tings t JOIN silent_state s ON s.message=t.id WHERE t.ctx=? AND t.recipient=? AND t.read=0 AND s.sent=0 ORDER BY t.created,t.id")?;
                q.query_map(params![ctx, owner], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?
            };
            let batch = id("digest");
            for (mid, app, typ, body) in pending {
                let body = decode(body)?;
                if !Self::grant(&tx, &ctx, &app, &owner)?
                    || Self::mode(&tx, &ctx, &owner, &typ, body["from"].as_str())? == "blocked"
                {
                    continue;
                }
                let receivers =
                    Self::target_receivers(&tx, &ctx, &owner, body["session_id"].as_str())?;
                if receivers.is_empty() {
                    continue;
                }
                for receiver in receivers {
                    tx.execute(
                        "INSERT OR IGNORE INTO session_deliveries VALUES(?,?,?)",
                        params![receiver, mid, batch],
                    )?;
                    tx.execute("INSERT OR IGNORE INTO deliveries(hook,message,digest) SELECT id,?,1 FROM hooks WHERE ctx=? AND recipient=? AND receiver=? AND state='connected'",params![mid,ctx,owner,receiver])?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }
    pub fn offer_session(&self, receiver: &str) -> Result<Option<Value>> {
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        let rows = {
            let mut q=tx.prepare("SELECT t.id,t.ctx,t.app,t.recipient,t.type,t.body,d.batch FROM session_deliveries d JOIN tings t ON t.id=d.message WHERE d.receiver=? AND t.read=0 ORDER BY t.created,t.id LIMIT 100")?;
            q.query_map([receiver], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, Option<String>>(6)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
        };
        let mut tings = vec![];
        let mut batch: Option<String> = None;
        let mut digest = false;
        let mut bytes = 256;
        for (mid, ctx, app, owner, typ, body, row_batch) in rows {
            let mut body = current_body(body, typ.clone(), owner.clone())?;
            let mode = Self::mode(&tx, &ctx, &owner, &typ, body["from"].as_str())?;
            let digest_enabled:bool=tx.query_row("SELECT COALESCE((SELECT enabled FROM silent_schedules WHERE ctx=? AND recipient=?),1)",params![ctx,owner],|r|r.get(0))?;
            let eligible = Self::grant(&tx, &ctx, &app, &owner)?
                && Self::target_receivers(&tx, &ctx, &owner, Some(receiver))?
                    .contains(&receiver.to_owned())
                && mode != "blocked"
                && (body["delivery"] != "required"
                    || Self::required_delivery_enabled(&tx, &ctx, &app, &owner)?);
            if !eligible
                || (row_batch.is_some() && !digest_enabled)
                || (row_batch.is_none() && mode == "silent")
            {
                tx.execute(
                    "DELETE FROM session_deliveries WHERE receiver=? AND message=?",
                    params![receiver, mid],
                )?;
                if eligible && mode == "silent" {
                    tx.execute("UPDATE tings SET silent=1 WHERE id=?", [&mid])?;
                    tx.execute(
                        "INSERT OR IGNORE INTO silent_state(message) VALUES(?)",
                        [&mid],
                    )?;
                    Self::ensure_schedule(&tx, &ctx, &owner, now())?;
                }
                continue;
            }
            if !tings.is_empty() && batch != row_batch {
                break;
            }
            let size = body.to_string().len() + 1;
            if bytes + size > 1024 * 1024 {
                break;
            }
            bytes += size;
            batch = row_batch;
            digest = batch.is_some();
            body["silent"] = digest.into();
            if digest {
                tx.execute("UPDATE silent_state SET sent=1 WHERE message=?", [&mid])?;
            }
            tings.push(body);
            tx.execute(
                "DELETE FROM session_deliveries WHERE receiver=? AND message=?",
                params![receiver, mid],
            )?;
        }
        tx.commit()?;
        Ok((!tings.is_empty()).then(||json!({"op":if digest{"silent_digest"}else{"tings"},"session_id":receiver,"digest_id":batch,"tings":tings})))
    }
    pub fn hooks(&self, p: &Principal) -> Result<Vec<Value>> {
        let db = self.lock()?;
        let mut q=db.prepare("SELECT h.id,h.receiver,h.state,(SELECT COUNT(*) FROM deliveries d JOIN tings t ON t.id=d.message WHERE d.hook=h.id AND d.read=0 AND (d.digest=1 OR (t.created>=? AND ((t.read=0 AND t.silent=0) OR t.created>=?)))) FROM hooks h WHERE ctx=? AND recipient=? ORDER BY id")?;
        Ok(q.query_map(params![retention_cutoff(3),retention_cutoff(1),p.context,p.id],|r|Ok(json!({"id":r.get::<_,String>(0)?,"receiver_id":r.get::<_,Option<String>>(1)?,"for":p.id,"state":r.get::<_,String>(2)?,"pending":r.get::<_,i64>(3)?})))?.collect::<std::result::Result<_,_>>()?)
    }
    pub fn hook_retry(&self, p: &Principal, key: &str, b: &Value) -> Result<Option<Value>> {
        let db = self.lock()?;
        let row:Option<(String,String)>=db.query_row("SELECT fingerprint,response FROM keys WHERE ctx=? AND owner=? AND kind='hook' AND key=? AND expires>?",params![p.context,p.id,key,now()],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        if let Some((fp, res)) = row {
            // Compare the stored serialized fingerprint, not a JSON string value.
            let request_fingerprint = b.to_string();
            if fp != request_fingerprint {
                return Err(conflict(
                    "idempotency_conflict",
                    "The webhook key belongs to a different creation request.",
                ));
            }
            return Ok(Some(decode(res)?));
        }
        Ok(None)
    }
    pub fn create_hook(
        &self,
        p: &Principal,
        receiver: &str,
        key: &str,
        b: &Value,
    ) -> Result<Value> {
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let hid = id("hook");
        tx.execute(
            "INSERT INTO hooks VALUES(?,?,?,'connected',?,?)",
            params![hid, p.context, p.id, receiver, p.session],
        )?;
        let backlog = {
            let mut q=tx.prepare("SELECT id,type,body FROM tings WHERE ctx=? AND recipient=? AND read=0 AND silent=0 AND created>=? AND (json_extract(body,'$.session_id') IS NULL OR json_extract(body,'$.session_id')=?)")?;
            q.query_map(
                params![p.context, p.id, retention_cutoff(3), receiver],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                },
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?
        };
        for (mid, typ, body) in backlog {
            let body = decode(body)?;
            let app = typ.split_once('.').map(|p| p.0).unwrap_or("");
            if Self::grant(&tx, &p.context, app, &p.id)?
                && Self::mode(&tx, &p.context, &p.id, &typ, body["from"].as_str())? == "allowed"
                && (body["delivery"] != "required"
                    || Self::required_delivery_enabled(&tx, &p.context, app, &p.id)?)
            {
                tx.execute(
                    "INSERT INTO deliveries(hook,message) VALUES(?,?)",
                    params![hid, mid],
                )?;
            }
        }
        let pending: i64 = tx.query_row(
            "SELECT COUNT(*) FROM deliveries WHERE hook=?",
            [&hid],
            |r| r.get(0),
        )?;
        let result = json!({"id":hid,"receiver_id":receiver,"for":p.id,"state":"connected","pending":pending});
        tx.execute(
            "INSERT OR REPLACE INTO keys VALUES(?,?,'hook',?,?,?,?)",
            params![
                p.context,
                p.id,
                key,
                b.to_string(),
                result.to_string(),
                now() + 86400 * 14
            ],
        )?;
        tx.commit()?;
        Ok(result)
    }
    pub fn bind(
        &self,
        p: &Principal,
        receiver: &str,
        ids: &[String],
        explicit: bool,
        takeover: bool,
    ) -> Result<Vec<(String, String)>> {
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        let mut replaced = vec![];
        for hid in ids {
            let row: Option<(String, Option<String>)> = tx
                .query_row(
                    "SELECT state,receiver FROM hooks WHERE id=? AND ctx=? AND recipient=?",
                    params![hid, p.context, p.id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let (state, old) = row.ok_or_else(Error::not_found)?;
            if !explicit && (state == "paused" || state == "detached") {
                return Err(Error::new(
                    409,
                    "hook_in_use",
                    "This hook requires explicit reattachment.",
                    "Run ting webhook URL --id ID or daemon reconnect for a paused hook.",
                ));
            }
            if let Some(old) = old.filter(|r| r != receiver) {
                if !takeover {
                    return Err(Error::new(
                        409,
                        "hook_in_use",
                        "The hook has another active receiver.",
                        "Use explicit takeover to move this destination.",
                    ));
                }
                replaced.push((old, hid.clone()));
            }
        }
        for hid in ids {
            tx.execute(
                "UPDATE hooks SET state='connected',receiver=?,session=? WHERE id=?",
                params![receiver, p.session, hid],
            )?;
            tx.execute("UPDATE deliveries SET delivery=0,offer_receiver=NULL,last_offer=0 WHERE hook=? AND read=0",[hid])?;
        }
        tx.commit()?;
        Ok(replaced)
    }
    pub fn detach(&self, p: &Principal, hid: &str) -> Result<Option<String>> {
        let db = self.lock()?;
        let row: Option<Option<String>> = db
            .query_row(
                "SELECT receiver FROM hooks WHERE id=? AND ctx=? AND recipient=?",
                params![hid, p.context, p.id],
                |r| r.get(0),
            )
            .optional()?;
        let old = row.ok_or_else(Error::not_found)?;
        db.execute(
            "UPDATE hooks SET state='detached',receiver=NULL,session=NULL WHERE id=?",
            [hid],
        )?;
        db.execute("UPDATE deliveries SET delivery=0,offer_receiver=NULL,last_offer=0 WHERE hook=? AND read=0",[hid])?;
        Ok(old)
    }
    pub fn release_receiver(&self, receiver: &str) -> Result<()> {
        let db = self.lock()?;
        db.execute("UPDATE deliveries SET delivery=0,offer_receiver=NULL,last_offer=0 WHERE hook IN(SELECT id FROM hooks WHERE receiver=?) AND read=0",[receiver])?;
        db.execute("UPDATE hooks SET receiver=NULL,session=NULL,state=CASE WHEN state='connected' THEN 'disconnected' ELSE state END WHERE receiver=?",[receiver])?;
        Ok(())
    }
    pub fn invalidate(&self, ctx: &str, recipient: &str) -> Result<Vec<(String, String)>> {
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        let rows = {
            let mut q=tx.prepare("SELECT receiver,id FROM hooks WHERE ctx=? AND recipient=? AND receiver IS NOT NULL")?;
            q.query_map(params![ctx, recipient], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<std::result::Result<Vec<(String, String)>, _>>()?
        };
        for (_, hid) in &rows {
            tx.execute("UPDATE deliveries SET delivery=0,offer_receiver=NULL,last_offer=0 WHERE hook=? AND read=0",[hid])?;
            tx.execute(
                "UPDATE hooks SET receiver=NULL,session=NULL,state='disconnected' WHERE id=?",
                [hid],
            )?;
        }
        tx.commit()?;
        Ok(rows)
    }
    pub fn unsubscribe(&self, receiver: &str, ids: &[String], pause: bool) -> Result<()> {
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        for hid in ids {
            if !tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM hooks WHERE id=? AND receiver=?)",
                params![hid, receiver],
                |r| r.get::<_, bool>(0),
            )? {
                return Err(Error::not_found());
            }
        }
        for hid in ids {
            tx.execute(
                "UPDATE hooks SET receiver=NULL,session=NULL,state=? WHERE id=?",
                params![if pause { "paused" } else { "disconnected" }, hid],
            )?;
            tx.execute("UPDATE deliveries SET delivery=0,offer_receiver=NULL,last_offer=0 WHERE hook=? AND read=0",[hid])?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn active_hooks(&self, receiver: &str) -> Result<Vec<ActiveHookRow>> {
        let db = self.lock()?;
        let mut q = db.prepare(
            "SELECT id,ctx,recipient,session FROM hooks WHERE receiver=? AND state='connected'",
        )?;
        Ok(q.query_map([receiver], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?
        .collect::<std::result::Result<_, _>>()?)
    }
    pub fn offer(&self, receiver: &str, hid: &str) -> Result<Option<Value>> {
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        let owner: Option<(String, String)> = tx
            .query_row(
                "SELECT ctx,recipient FROM hooks WHERE id=? AND receiver=? AND state='connected'",
                params![hid, receiver],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((ctx, owner)) = owner else {
            return Ok(None);
        };
        let active: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM deliveries WHERE hook=? AND read=0 AND offer_receiver=?)",
            params![hid, receiver],
            |r| r.get(0),
        )?;
        let rows = {
            let mut q=tx.prepare("SELECT t.id,t.app,t.type,t.body,d.digest FROM deliveries d JOIN tings t ON t.id=d.message WHERE d.hook=?1 AND d.read=0 AND (d.digest=1 OR (t.created>=?5 AND t.silent=0)) AND (?2=0 OR (d.offer_receiver=?3 AND d.delivery=0 AND d.last_offer<=?4)) AND (json_extract(t.body,'$.session_id') IS NULL OR json_extract(t.body,'$.session_id')=?3) ORDER BY t.created,t.id LIMIT 100")?;
            q.query_map(
                params![hid, active, receiver, now() - 10, retention_cutoff(3)],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, bool>(4)?,
                    ))
                },
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?
        };
        let mut tings = vec![];
        let mut bytes = 256;
        let mut digest = false;
        for (mid, app, typ, body, row_digest) in rows {
            let mut body = current_body(body, typ.clone(), owner.clone())?;
            let mode = Self::mode(&tx, &ctx, &owner, &typ, body["from"].as_str())?;
            let digest_enabled:bool=tx.query_row("SELECT COALESCE((SELECT enabled FROM silent_schedules WHERE ctx=? AND recipient=?),1)",params![ctx,owner],|r|r.get(0))?;
            if (row_digest && !digest_enabled)
                || !Self::grant(&tx, &ctx, &app, &owner)?
                || mode == "blocked"
                || (!row_digest && mode == "silent")
                || (body["delivery"] == "required"
                    && !Self::required_delivery_enabled(&tx, &ctx, &app, &owner)?)
            {
                tx.execute(
                    "DELETE FROM deliveries WHERE hook=? AND message=?",
                    params![hid, mid],
                )?;
                continue;
            }
            if !tings.is_empty() && digest != row_digest {
                break;
            }
            let size = body.to_string().len() + 1;
            if bytes + size > 1024 * 1024 {
                break;
            }
            bytes += size;
            digest = row_digest;
            body["silent"] = digest.into();
            body.as_object_mut().unwrap().remove("read");
            if digest {
                tx.execute("UPDATE silent_state SET sent=1 WHERE message=?", [&mid])?;
            }
            tings.push(body);
        }
        if tings.is_empty() {
            tx.commit()?;
            return Ok(None);
        }
        for ting in &tings {
            tx.execute("UPDATE deliveries SET offered=1,offer_receiver=?,last_offer=? WHERE hook=? AND message=?",params![receiver,now(),hid,ting["id"].as_str()])?;
        }
        tx.commit()?;
        Ok(Some(
            json!({"op":if digest{"silent_digest"}else{"tings"},"webhook_id":hid,"session_id":receiver,"tings":tings}),
        ))
    }
    pub fn ack(
        &self,
        receiver: &str,
        hid: &str,
        ids: &[String],
        kind: &str,
    ) -> Result<(String, String, bool)> {
        if kind != "read" && kind != "delivery" {
            return Err(v_err("ACK kind must be delivery or read."));
        }
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        let owner: Option<(String, String)> = tx
            .query_row(
                "SELECT ctx,recipient FROM hooks WHERE id=? AND receiver=? AND state='connected'",
                params![hid, receiver],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let owner = owner.ok_or_else(Error::not_found)?;
        let cutoff = retention_cutoff(1);
        let mut expired = false;
        for mid in ids {
            let row: Option<(bool, Option<String>, bool)> = tx
                .query_row(
                    "SELECT offered,offer_receiver,read FROM deliveries WHERE hook=? AND message=?",
                    params![hid, mid],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let valid = row.is_some_and(|(offered, offer, read)| {
                read || (offered && (kind == "read" || offer.as_deref() == Some(receiver)))
            });
            if !valid {
                return Err(Error::new(
                    400,
                    "invalid_ack",
                    "An ID was not offered to this hook on an authorized binding.",
                    "ACK only IDs received for this hook; no IDs were changed.",
                ));
            }
        }
        for mid in ids {
            if kind == "read" {
                let completed = tx.execute(
                    "UPDATE deliveries SET read=1,delivery=1 WHERE hook=? AND message=? AND read=0",
                    params![hid, mid],
                )?;
                // Replayed completion must not undo an app's later mark-unread.
                if completed > 0 {
                    expired |= tx.execute(
                        "UPDATE tings SET read=1 WHERE id=? AND read=0 AND created<? AND NOT EXISTS(SELECT 1 FROM deliveries d WHERE d.message=tings.id AND d.digest=1 AND d.read=0)",
                        params![mid, cutoff],
                    )? > 0;
                    tx.execute("UPDATE tings SET read=1 WHERE id=?", [mid])?;
                }
            } else {
                tx.execute(
                    "UPDATE deliveries SET delivery=1 WHERE hook=? AND message=?",
                    params![hid, mid],
                )?;
            }
        }
        tx.commit()?;
        Ok((owner.0, owner.1, expired))
    }
    pub fn expired_owners(&self) -> Result<Vec<(String, String)>> {
        let db = self.lock()?;
        let mut q=db.prepare("SELECT DISTINCT h.ctx,h.recipient FROM hooks h JOIN deliveries d ON d.hook=h.id JOIN tings t ON t.id=d.message WHERE h.receiver IS NOT NULL AND d.read=0 AND d.digest=0 AND (t.created<?1 OR ((t.read=1 OR t.silent=1) AND t.created<?2))")?;
        Ok(
            q.query_map(params![retention_cutoff(3), retention_cutoff(1)], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?
            .collect::<std::result::Result<_, _>>()?,
        )
    }
    pub fn prune(&self) -> Result<usize> {
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        let cutoff = retention_cutoff(3);
        let read_cutoff = retention_cutoff(1);
        tx.execute(
            "DELETE FROM deliveries WHERE message IN(SELECT id FROM tings WHERE NOT ((read=0 AND (EXISTS(SELECT 1 FROM silent_state s WHERE s.message=tings.id AND s.sent=0) OR EXISTS(SELECT 1 FROM session_deliveries d WHERE d.message=tings.id))) OR EXISTS(SELECT 1 FROM deliveries d WHERE d.message=tings.id AND d.digest=1 AND d.read=0)) AND (created<?1 OR ((read=1 OR silent=1) AND created<?2)))",
            params![cutoff,read_cutoff],
        )?;
        let removed = tx.execute(
            "DELETE FROM tings WHERE NOT ((read=0 AND (EXISTS(SELECT 1 FROM silent_state s WHERE s.message=tings.id AND s.sent=0) OR EXISTS(SELECT 1 FROM session_deliveries d WHERE d.message=tings.id))) OR EXISTS(SELECT 1 FROM deliveries d WHERE d.message=tings.id AND d.digest=1 AND d.read=0)) AND (created<?1 OR ((read=1 OR silent=1) AND created<?2))",
            params![cutoff, read_cutoff],
        )?;
        tx.execute("DELETE FROM keys WHERE expires<=?", [now()])?;
        tx.execute("DELETE FROM cursors WHERE expires<=?", [now()])?;
        tx.execute("DELETE FROM login_attempts WHERE expires<=?", [now()])?;
        tx.commit()?;
        Ok(removed)
    }
    pub fn login_attempt(&self, next: &str) -> Result<String> {
        let db = self.lock()?;
        let state = id("login");
        db.execute(
            "INSERT INTO login_attempts VALUES(?,?,?)",
            params![state, next, now() + 600],
        )?;
        Ok(state)
    }
    pub fn read_login_attempt(&self, state: &str) -> Result<String> {
        let mut db = self.lock()?;
        let tx = db.transaction()?;
        let next: Option<String> = tx
            .query_row(
                "SELECT next FROM login_attempts WHERE id=? AND expires>?",
                params![state, now()],
                |r| r.get(0),
            )
            .optional()?;
        // Keep the bounded attempt so a lost callback response can recover the
        // original encrypted login receipt. Auth binds the state to one SLT hash.
        tx.commit()?;
        next.ok_or_else(|| v_err("This browser login attempt has expired."))
    }
}
fn v_err(s: &str) -> Error {
    Error::invalid(s)
}
fn cursor_err() -> Error {
    Error::new(
        400,
        "invalid_cursor",
        "The cursor is invalid, expired or belongs to another query.",
        "Start a new list request without a cursor.",
    )
}

fn next_schedule(time: &str, timezone: &str, after: i64) -> Result<i64> {
    use chrono::{NaiveTime, TimeZone, Utc};
    if time.len() != 5
        || time.as_bytes()[2] != b':'
        || !time
            .bytes()
            .enumerate()
            .all(|(i, c)| i == 2 || c.is_ascii_digit())
    {
        return Err(v_err("time must use HH:MM in 24-hour format."));
    }
    let time = NaiveTime::parse_from_str(time, "%H:%M")
        .map_err(|_| v_err("time must use HH:MM in 24-hour format."))?;
    let zone: chrono_tz::Tz = timezone
        .parse()
        .map_err(|_| v_err("timezone must be an IANA time zone, such as Asia/Kolkata."))?;
    let local = chrono::DateTime::<Utc>::from_timestamp(after, 0)
        .ok_or_else(|| v_err("Invalid schedule timestamp."))?
        .with_timezone(&zone);
    for day in 0..3 {
        let date = local.date_naive() + chrono::Days::new(day);
        let scheduled = date.and_time(time);
        // A skipped DST time runs at the first valid minute after the gap; a repeated time runs once.
        for minute in 0..=180 {
            if let Some(candidate) = zone
                .from_local_datetime(&(scheduled + chrono::Duration::minutes(minute)))
                .earliest()
            {
                if candidate.timestamp() > after {
                    return Ok(candidate.timestamp());
                }
                break;
            }
        }
    }
    Err(v_err("Could not calculate the next scheduled time."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(owner: &str) -> Principal {
        Principal {
            context: "accounts".into(),
            id: owner.into(),
            kind: "carbon".into(),
            session: format!("auth-{owner}"),
        }
    }
    fn app() -> AppAuthority {
        AppAuthority {
            context: "accounts".into(),
            app_id: "demo".into(),
            expires_at: now() + 3600,
        }
    }
    fn fixture() -> (Store, Principal, String) {
        let store = Store::open(":memory:").unwrap();
        let p = principal("alice");
        store.register_type(&p,"demo",&json!({"type":"demo.buildDone","description":"Build completed","schema":{"type":"object","properties":{"n":{"type":"integer"}},"required":["n"],"additionalProperties":false}}),false).unwrap();
        let proof = Proof {
            context: p.context.clone(),
            app_id: "demo".into(),
            actor_id: p.id.clone(),
            expires_at: now() + 3600,
        };
        let (_, grant) = store
            .subscribe_app(&proof, &json!({"app_id":"demo"}))
            .unwrap();
        (store, p, grant["id"].as_str().unwrap().into())
    }
    fn body(key: &str) -> Value {
        json!({"type":"demo.buildDone","for":"alice","key":key,"data":{"n":1}})
    }
    fn attach(store: &Store, p: &Principal, id: &str) {
        store.create_receiver_session(id).unwrap();
        store.attach_receiver_session(id, p).unwrap();
    }
    fn due(store: &Store, p: &Principal, at: i64) {
        store.silent_schedule(p).unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE silent_schedules SET next_at=? WHERE ctx=? AND recipient=?",
                params![at, p.context, p.id],
            )
            .unwrap();
        store.queue_due_digests_at(at).unwrap();
    }

    #[test]
    fn schemas_are_public_editable_and_enforced_without_breaking_retries() {
        let (store, p, _) = fixture();
        assert_eq!(
            store.types_for_app("demo").unwrap()[0]["schema"]["required"],
            json!(["n"])
        );
        let accepted = store.send(&app(), &body("first")).unwrap();
        let mut invalid = body("bad");
        invalid["data"]["n"] = "wrong".into();
        assert!(store.send(&app(), &invalid).is_err());
        store
            .register_type(
                &p,
                "demo.buildDone",
                &json!({"schema":{"type":"object","required":["changed"]}}),
                true,
            )
            .unwrap();
        assert_eq!(
            store.send(&app(), &body("first")).unwrap(),
            (200, accepted.1)
        );
        assert!(store.send(&app(), &body("new")).is_err());
        assert!(
            store
                .register_type(
                    &p,
                    "demo",
                    &json!({"type":"demo.nested.event","description":"Old","schema":{}}),
                    false
                )
                .is_err()
        );
        assert!(store.register_type(&p,"demo",&json!({"type":"demo.remote","description":"Bad","schema":{"$ref":"https://example.com/schema"}}),false).is_err());
        assert!(store.register_type(&p,"demo",&json!({"type":"demo.invalid","description":"Bad","schema":{"type":"nonsense"}}),false).is_err());
    }

    #[test]
    fn sessions_fan_out_and_target_only_the_correct_owner() {
        let (store, p, _) = fixture();
        attach(&store, &p, "s1");
        attach(&store, &p, "s2");
        store.send(&app(), &body("all")).unwrap();
        assert_eq!(
            store.offer_session("s1").unwrap().unwrap()["tings"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            store.offer_session("s2").unwrap().unwrap()["tings"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let mut targeted = body("specific");
        targeted["session_id"] = "s1".into();
        store.send(&app(), &targeted).unwrap();
        assert_eq!(
            store.offer_session("s1").unwrap().unwrap()["tings"][0]["session_id"],
            "s1"
        );
        assert!(store.offer_session("s2").unwrap().is_none());
        attach(&store, &principal("bob"), "other");
        targeted["key"] = "wrong-owner".into();
        targeted["session_id"] = "other".into();
        assert!(store.send(&app(), &targeted).is_err());
        assert!(store.offer_session("other").unwrap().is_none());
        targeted["key"] = "gone".into();
        targeted["session_id"] = "missing".into();
        assert!(store.send(&app(), &targeted).is_err());
        store
            .attach_receiver_session("s1", &principal("bob"))
            .unwrap();
        targeted["key"] = "ambiguous".into();
        targeted["session_id"] = "s1".into();
        targeted.as_object_mut().unwrap().remove("for");
        assert!(store.send(&app(), &targeted).is_err());
        store.remove_receiver_session("s2").unwrap();
        assert_eq!(store.receiver_sessions(&p).unwrap().len(), 1);
    }

    #[test]
    fn anonymous_consent_cannot_bypass_attached_identity() {
        let (store, p, _) = fixture();
        store.create_receiver_session("anon").unwrap();
        let mut message = body("anon");
        message.as_object_mut().unwrap().remove("for");
        message["session_id"] = "anon".into();
        assert!(store.send(&app(), &message).is_err());
        store
            .register_receiver_apps("anon", &["demo".into()])
            .unwrap();
        store.send(&app(), &message).unwrap();
        store.attach_receiver_session("anon", &p).unwrap();
        assert!(store.offer_session("anon").unwrap().is_none());
        assert!(
            store
                .register_receiver_apps("anon", &["demo".into()])
                .is_err()
        );
        store
            .preference(&p, &json!({"app_id":"demo","mode":"blocked"}), false)
            .unwrap();
        message["key"] = "identified".into();
        assert_eq!(store.send(&app(), &message).unwrap().1["status"], "blocked");
        store.remove_receiver_identity("anon", &p.session).unwrap();
        message["key"] = "after-logout".into();
        assert!(store.send(&app(), &message).is_err());
    }

    #[test]
    fn restrictive_rules_win_and_required_delivery_cannot_bypass_them() {
        let (store, p, grant) = fixture();
        attach(&store, &p, "s1");
        store.required_delivery(&p, &grant, Some(true)).unwrap();
        store
            .preference(&p, &json!({"app_id":"demo","mode":"silent"}), false)
            .unwrap();
        store
            .preference(
                &p,
                &json!({"app_id":"demo","type":"demo.buildDone","mode":"allowed"}),
                false,
            )
            .unwrap();
        let mut message = body("quiet");
        message["delivery"] = "required".into();
        message["from"] = "bob".into();
        assert_eq!(store.send(&app(), &message).unwrap().1["mode"], "silent");
        assert!(store.offer_session("s1").unwrap().is_none());
        store
            .preference(&p, &json!({"from":"bob","mode":"blocked"}), false)
            .unwrap();
        message["key"] = "blocked".into();
        let blocked = store.send(&app(), &message).unwrap().1;
        assert_eq!(blocked["status"], "blocked");
        assert!(
            store
                .ting("accounts", blocked["id"].as_str().unwrap(), None, None)
                .is_err()
        );
        assert_eq!(store.send(&app(), &message).unwrap().0, 200);
        due(&store, &p, now());
        assert!(store.offer_session("s1").unwrap().is_none());
    }

    #[test]
    fn required_delivery_revocation_suppresses_queued_session_and_hook() {
        let (store, p, grant) = fixture();
        attach(&store, &p, "s1");
        let hook = store
            .create_hook(&p, "s1", "hook", &json!({"receiver_id":"s1"}))
            .unwrap();
        store.required_delivery(&p, &grant, Some(true)).unwrap();
        let mut message = body("required");
        message["delivery"] = "required".into();
        store.send(&app(), &message).unwrap();
        store.required_delivery(&p, &grant, Some(false)).unwrap();
        assert!(store.offer_session("s1").unwrap().is_none());
        assert!(
            store
                .offer("s1", hook["id"].as_str().unwrap())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn digest_waits_until_next_schedule_after_an_offline_run() {
        let (store, p, _) = fixture();
        store
            .preference(&p, &json!({"app_id":"demo","mode":"silent"}), false)
            .unwrap();
        store.send(&app(), &body("pending")).unwrap();
        let at = now();
        due(&store, &p, at);
        let next = store.silent_schedule(&p).unwrap()["next_at"]
            .as_i64()
            .unwrap();
        assert!(next > at);
        attach(&store, &p, "s1");
        attach(&store, &p, "s2");
        store.queue_due_digests_at(at + 1).unwrap();
        assert!(store.offer_session("s1").unwrap().is_none());
        store.queue_due_digests_at(next).unwrap();
        assert_eq!(
            store.offer_session("s1").unwrap().unwrap()["op"],
            "silent_digest"
        );
        assert_eq!(
            store.offer_session("s2").unwrap().unwrap()["op"],
            "silent_digest"
        );
        store.queue_due_digests_at(next + 1).unwrap();
        assert!(store.offer_session("s1").unwrap().is_none());
    }

    #[test]
    fn digest_targeting_disable_and_disconnect_preserve_pending() {
        let (store, p, _) = fixture();
        attach(&store, &p, "s1");
        attach(&store, &p, "s2");
        store
            .preference(&p, &json!({"app_id":"demo","mode":"silent"}), false)
            .unwrap();
        let mut message = body("target");
        message["session_id"] = "s1".into();
        store.send(&app(), &message).unwrap();
        due(&store, &p, now());
        assert!(store.offer_session("s2").unwrap().is_none());
        store
            .set_silent_schedule(&p, &json!({"enabled":false}))
            .unwrap();
        assert!(store.offer_session("s1").unwrap().is_none());
        store
            .set_silent_schedule(&p, &json!({"enabled":true}))
            .unwrap();
        due(&store, &p, now());
        assert_eq!(
            store.offer_session("s1").unwrap().unwrap()["op"],
            "silent_digest"
        );
        store.send(&app(), &body("untargeted")).unwrap();
        due(&store, &p, now());
        store.remove_receiver_session("s1").unwrap();
        store.remove_receiver_session("s2").unwrap();
        attach(&store, &p, "s3");
        assert!(store.offer_session("s3").unwrap().is_none());
        due(&store, &p, now() + 86400);
        assert_eq!(
            store.offer_session("s3").unwrap().unwrap()["tings"][0]["key"],
            "untargeted"
        );
    }

    #[test]
    fn quieting_a_queued_hook_holds_it_for_digest_and_retains_old_pending_data() {
        let (store, p, _) = fixture();
        attach(&store, &p, "s1");
        let hook = store
            .create_hook(&p, "s1", "hook", &json!({"receiver_id":"s1"}))
            .unwrap();
        let hid = hook["id"].as_str().unwrap();
        let response = store.send(&app(), &body("old")).unwrap().1;
        let mid = response["id"].as_str().unwrap();
        store
            .preference(&p, &json!({"app_id":"demo","mode":"silent"}), false)
            .unwrap();
        assert!(store.offer_session("s1").unwrap().is_none());
        assert!(store.offer("s1", hid).unwrap().is_none());
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE tings SET created='2020-01-01T00:00:00.000000Z' WHERE id=?",
                [mid],
            )
            .unwrap();
        assert_eq!(store.prune().unwrap(), 0);
        assert!(store.ting("accounts", mid, Some("alice"), None).is_ok());
        due(&store, &p, now());
        assert_eq!(
            store.offer_session("s1").unwrap().unwrap()["op"],
            "silent_digest"
        );
        assert_eq!(store.prune().unwrap(), 0);
        assert!(store.expired_owners().unwrap().is_empty());
        assert_eq!(
            store.offer("s1", hid).unwrap().unwrap()["op"],
            "silent_digest"
        );
        assert_eq!(store.prune().unwrap(), 0);
        assert!(store.ting("accounts", mid, Some("alice"), None).is_ok());
        store.ack("s1", hid, &[mid.into()], "read").unwrap();
        assert_eq!(store.prune().unwrap(), 1);
    }

    #[test]
    fn changed_silence_is_visible_and_read_digests_skip_direct_delivery() {
        let (store, p, _) = fixture();
        attach(&store, &p, "s1");
        let hook = store
            .create_hook(&p, "s1", "hook", &json!({"receiver_id":"s1"}))
            .unwrap();
        let sent = store.send(&app(), &body("pending-read")).unwrap().1;
        let mid = sent["id"].as_str().unwrap();
        store
            .preference(&p, &json!({"app_id":"demo","mode":"silent"}), false)
            .unwrap();
        assert_eq!(
            store.ting("accounts", mid, Some("alice"), None).unwrap()["silent"],
            true
        );
        assert_eq!(
            store
                .tings("accounts", Some("alice"), None, &json!({}))
                .unwrap()[0]["silent"],
            true
        );
        due(&store, &p, now());
        store.read(&p, &[mid.into()]).unwrap();
        assert!(store.offer_session("s1").unwrap().is_none());
        assert!(
            store
                .offer("s1", hook["id"].as_str().unwrap())
                .unwrap()
                .is_some()
        );
        assert!(v::filters(&json!({"mode":"muted"})).is_err());
    }

    #[test]
    fn digest_hooks_acknowledge_independently_even_after_global_read() {
        let (store, p, _) = fixture();
        attach(&store, &p, "s1");
        let first = store
            .create_hook(&p, "s1", "first", &json!({"receiver_id":"s1"}))
            .unwrap();
        let second = store
            .create_hook(&p, "s1", "second", &json!({"receiver_id":"s1"}))
            .unwrap();
        let first = first["id"].as_str().unwrap();
        let second = second["id"].as_str().unwrap();
        store
            .preference(&p, &json!({"app_id":"demo","mode":"silent"}), false)
            .unwrap();
        let sent = store.send(&app(), &body("siblings")).unwrap().1;
        let mid = sent["id"].as_str().unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE tings SET created='2020-01-01T00:00:00.000000Z' WHERE id=?",
                [mid],
            )
            .unwrap();
        due(&store, &p, now());
        assert_eq!(
            store.offer("s1", first).unwrap().unwrap()["op"],
            "silent_digest"
        );
        let (_, _, expired) = store.ack("s1", first, &[mid.into()], "read").unwrap();
        assert!(!expired);
        assert_eq!(store.prune().unwrap(), 0);
        assert_eq!(
            store.ting("accounts", mid, Some("alice"), None).unwrap()["read"],
            true
        );
        assert_eq!(
            store.offer("s1", second).unwrap().unwrap()["tings"][0]["id"],
            mid
        );
        store.ack("s1", second, &[mid.into()], "read").unwrap();
        assert_eq!(store.prune().unwrap(), 1);
    }

    #[test]
    fn sender_preferences_paginate_and_filter_without_collisions() {
        let (store, p, _) = fixture();
        for sender in ["bob", "carol"] {
            store
                .preference(&p, &json!({"from":sender,"mode":"blocked"}), false)
                .unwrap();
        }
        let filter = json!({"limit":1,"mode":"blocked"});
        let first = store
            .page(
                store.preferences(&p, &filter).unwrap(),
                "prefs",
                &filter,
                false,
            )
            .unwrap();
        let filter = json!({"limit":1,"mode":"blocked","cursor":first["next_cursor"]});
        let second = store
            .page(
                store.preferences(&p, &filter).unwrap(),
                "prefs",
                &filter,
                false,
            )
            .unwrap();
        assert_ne!(first["items"][0]["from"], second["items"][0]["from"]);
        assert_eq!(second["items"].as_array().unwrap().len(), 1);
        assert!(
            store
                .preferences(&p, &json!({"mode":"allowed"}))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn migration_preserves_legacy_history_and_reset_survives_reopen() {
        let path = std::env::temp_dir().join(format!("ting-store-{}.sqlite", id("test")));
        let filename = path.to_str().unwrap();
        let p = principal("alice");
        {
            let store = Store::open(filename).unwrap();
            let db = store.lock().unwrap();
            db.execute(
                "INSERT INTO types VALUES('accounts','demo','demo.build.finished','Legacy')",
                [],
            )
            .unwrap();
            db.execute(
                "INSERT INTO preferences VALUES('accounts','alice','demo','service:build',0)",
                [],
            )
            .unwrap();
            db.execute(
                "INSERT INTO preferences VALUES('accounts','alice','demo','app',0)",
                [],
            )
            .unwrap();
        }
        {
            let store = Store::open(filename).unwrap();
            let prefs = store.preferences(&p, &json!({})).unwrap();
            assert_eq!(prefs.len(), 2);
            assert!(prefs.iter().all(|x| x["service"].is_null()));
            store
                .preference(&p, &json!({"app_id":"demo"}), true)
                .unwrap();
            store
                .preference(
                    &p,
                    &json!({"app_id":"demo","type":"demo.build.finished"}),
                    true,
                )
                .unwrap();
        }
        {
            let store = Store::open(filename).unwrap();
            assert!(store.preferences(&p, &json!({})).unwrap().is_empty());
            assert_eq!(
                store.types_for_app("demo").unwrap()[0]["type"],
                "demo.build.finished"
            );
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn detected_timezone_defaults_to_midnight_once_and_preserves_manual_settings() {
        let (store, p, _) = fixture();
        store
            .initialize_timezone(&p.context, &p.id, "Asia/Kolkata")
            .unwrap();
        let first = store.silent_schedule(&p).unwrap();
        assert_eq!(first["time"], "00:00");
        assert_eq!(first["timezone"], "Asia/Kolkata");
        store
            .initialize_timezone(&p.context, &p.id, "America/New_York")
            .unwrap();
        assert_eq!(store.silent_schedule(&p).unwrap(), first);
        store
            .set_silent_schedule(
                &p,
                &json!({"time":"18:45","timezone":"Europe/London","enabled":false}),
            )
            .unwrap();
        let custom = store.silent_schedule(&p).unwrap();
        store
            .initialize_timezone(&p.context, &p.id, "Asia/Kolkata")
            .unwrap();
        assert_eq!(store.silent_schedule(&p).unwrap(), custom);
        let manual = principal("manual");
        store
            .set_silent_schedule(&manual, &json!({"time":"09:00","timezone":"UTC"}))
            .unwrap();
        store
            .initialize_timezone(&manual.context, &manual.id, "Asia/Kolkata")
            .unwrap();
        assert_eq!(store.silent_schedule(&manual).unwrap()["time"], "09:00");
        assert_eq!(store.silent_schedule(&manual).unwrap()["timezone"], "UTC");
        assert!(
            store
                .initialize_timezone("accounts", "invalid", "not/a-zone")
                .is_err()
        );
        assert!(
            !store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM silent_schedules WHERE recipient='invalid')",
                    [],
                    |r| r.get::<_, bool>(0)
                )
                .unwrap()
        );
    }

    #[test]
    fn fallback_timezone_upgrades_once_across_restart() {
        let path = std::env::temp_dir().join(format!("ting-timezone-{}.sqlite", id("test")));
        let filename = path.to_str().unwrap();
        let p = principal("alice");
        {
            let store = Store::open(filename).unwrap();
            let fallback = store.silent_schedule(&p).unwrap();
            assert_eq!(fallback["time"], "09:00");
            assert_eq!(fallback["timezone"], "UTC");
        }
        {
            let store = Store::open(filename).unwrap();
            store
                .initialize_timezone(&p.context, &p.id, "Asia/Kolkata")
                .unwrap();
            assert_eq!(store.silent_schedule(&p).unwrap()["time"], "00:00");
        }
        {
            let store = Store::open(filename).unwrap();
            store
                .initialize_timezone(&p.context, &p.id, "Europe/London")
                .unwrap();
            assert_eq!(
                store.silent_schedule(&p).unwrap()["timezone"],
                "Asia/Kolkata"
            );
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn timezone_migration_preserves_all_existing_schedules() {
        let path = std::env::temp_dir().join(format!("ting-old-timezone-{}.sqlite", id("test")));
        let filename = path.to_str().unwrap();
        {
            let db = Connection::open(filename).unwrap();
            db.execute_batch("CREATE TABLE silent_schedules(ctx TEXT,recipient TEXT,enabled INTEGER NOT NULL DEFAULT 1,time TEXT NOT NULL DEFAULT '09:00',timezone TEXT NOT NULL DEFAULT 'UTC',next_at INTEGER NOT NULL,PRIMARY KEY(ctx,recipient)); INSERT INTO silent_schedules VALUES('accounts','alice',0,'18:45','Europe/London',1234); INSERT INTO silent_schedules VALUES('accounts','bob',1,'09:00','UTC',5678);").unwrap();
        }
        {
            let store = Store::open(filename).unwrap();
            for user in ["alice", "bob"] {
                let p = principal(user);
                let before = store.silent_schedule(&p).unwrap();
                store
                    .initialize_timezone(&p.context, &p.id, "Asia/Kolkata")
                    .unwrap();
                assert_eq!(store.silent_schedule(&p).unwrap(), before);
            }
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn schedule_validation_and_dst_use_local_wall_clock() {
        let after = chrono::DateTime::parse_from_rfc3339("2026-03-08T06:00:00Z")
            .unwrap()
            .timestamp();
        let next = next_schedule("02:30", "America/New_York", after).unwrap();
        assert_eq!(
            chrono::DateTime::from_timestamp(next, 0)
                .unwrap()
                .to_rfc3339(),
            "2026-03-08T07:00:00+00:00"
        );
        let next = next_schedule("09:00", "Asia/Kolkata", after).unwrap();
        assert_eq!(
            chrono::DateTime::from_timestamp(next, 0)
                .unwrap()
                .to_rfc3339(),
            "2026-03-09T03:30:00+00:00"
        );
        assert!(next_schedule("25:00", "UTC", after).is_err());
        assert!(next_schedule("9:00", "UTC", after).is_err());
        assert!(next_schedule("09:00", "not/a-zone", after).is_err());
    }
}
