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
    body["for"] = recipient.into();
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
    fn enabled(db: &Connection, ctx: &str, recipient: &str, typ: &str) -> Result<bool> {
        let (app, service, _) = v::type_parts(typ)?;
        for scope in [
            format!("type:{typ}"),
            format!("service:{service}"),
            "app".into(),
        ] {
            let b=db.query_row("SELECT enabled FROM preferences WHERE ctx=? AND recipient=? AND app=? AND scope=?",params![ctx,recipient,app,scope],|r|r.get(0)).optional()?;
            if let Some(b) = b {
                return Ok(b);
            }
        }
        Ok(true)
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
                &["description"]
            } else {
                &["type", "description"]
            },
            if update {
                &["description"]
            } else {
                &["type", "description"]
            },
        )?;
        let description = v::text(b, "description", 1000)?;
        let typ = if update {
            app
        } else {
            v::string(b, "type", 255)?
        };
        let (owner, _, _) = v::type_parts(typ)?;
        if !update && owner != app {
            return Err(v_err("The type must belong to the app in the URL."));
        }
        let db = self.lock()?;
        let old: Option<String> = db
            .query_row(
                "SELECT description FROM types WHERE ctx=? AND name=?",
                params![p.context, typ],
                |r| r.get(0),
            )
            .optional()?;
        let status = if update {
            if old.is_none() {
                return Err(Error::not_found());
            }
            db.execute(
                "UPDATE types SET description=? WHERE ctx=? AND name=?",
                params![description, p.context, typ],
            )?;
            200
        } else if let Some(old) = old {
            if old != description {
                return Err(conflict(
                    "type_exists",
                    "This type already has a different description.",
                ));
            }
            200
        } else {
            db.execute(
                "INSERT INTO types VALUES(?,?,?,?)",
                params![p.context, app, typ, description],
            )?;
            201
        };
        Ok((
            status,
            json!({"type":typ,"description":description,"defaults":{"carbon":true,"silicon":true}}),
        ))
    }
    pub fn types(&self, p: &Principal, app: &str) -> Result<Vec<Value>> {
        let db = self.lock()?;
        let mut q =
            db.prepare("SELECT name,description FROM types WHERE ctx=? AND app=? ORDER BY name")?;
        Ok(q.query_map(params![p.context,app],|r|Ok(json!({"type":r.get::<_,String>(0)?,"description":r.get::<_,String>(1)?,"defaults":{"carbon":true,"silicon":true}})))?.collect::<std::result::Result<_,_>>()?)
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
            &["type", "data", "metadata", "for", "key", "delivery"],
            &["type", "data", "for", "key"],
        )?;
        let typ = v::string(b, "type", 255)?;
        let (app, _, _) = v::type_parts(typ)?;
        if app != p.app_id {
            return Err(Error::new(
                403,
                "permission_denied",
                "The type does not belong to the verified app.",
                "Use a type registered to the issuing app.",
            ));
        }
        let recipient = v::string(b, "for", 255)?;
        let key = v::string(b, "key", 200)?;
        let required = match b.get("delivery") {
            None => false,
            Some(Value::String(mode)) if mode == "required" => true,
            Some(_) => return Err(v_err("delivery must be 'required' when specified.")),
        };
        if !b["data"].is_object() || b.get("metadata").is_some_and(|x| !x.is_object()) {
            return Err(v_err("data and metadata must be JSON objects."));
        }
        let mut normalized = b.clone();
        if normalized.get("metadata").is_none() {
            normalized["metadata"] = json!({})
        }
        let fingerprint = hex::encode(Sha256::digest(serde_json::to_vec(&normalized)?));
        let mut db = self.lock()?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if let Some((fp,response))=tx.query_row("SELECT fingerprint,response FROM keys WHERE ctx=? AND owner=? AND kind='send' AND key=? AND expires>?",params![p.context,p.app_id,key,now()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?))).optional()?{if fp!=fingerprint{return Err(conflict("idempotency_conflict","This key was accepted with different content."))}return Ok((200,decode(response)?))}
        // Notification types belong to the verified sending app.
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM types WHERE ctx=? AND app=? AND name=?)",
            params![p.context, app, typ],
            |r| r.get(0),
        )?;
        if !exists {
            return Err(Error::not_found());
        }
        if !Self::grant(&tx, &p.context, app, recipient)? {
            return Err(Error::new(
                403,
                "recipient_not_registered",
                "The app does not have permission to notify this recipient.",
                "Register the recipient through a fresh Silicon Accounts User verification proof.",
            ));
        }
        if required && !Self::required_delivery_enabled(&tx, &p.context, app, recipient)? {
            return Err(Error::new(
                403,
                "required_delivery_not_enabled",
                "The recipient has not enabled required delivery for this app.",
                "The recipient must explicitly enable required delivery on their subscription.",
            ));
        }
        let silent = !Self::enabled(&tx, &p.context, recipient, typ)?;
        let mid = id("msg");
        let created = stamp();
        let mut full = json!({"id":mid,"created_at":created,"type":typ,"data":b["data"],"metadata":normalized["metadata"],"for":recipient,"key":key,"silent":silent,"read":false});
        if required {
            full["delivery"] = "required".into();
        }
        tx.execute("INSERT INTO tings(id,ctx,app,recipient,type,created,body,silent) VALUES(?,?,?,?,?,?,?,?)",params![mid,p.context,app,recipient,typ,created,full.to_string(),silent])?;
        if !silent || required {
            tx.execute("INSERT INTO deliveries(hook,message) SELECT id,? FROM hooks WHERE ctx=? AND recipient=?",params![mid,p.context,recipient])?;
        }
        let mut response =
            json!({"id":mid,"created_at":created,"status":"accepted","key":key,"silent":silent});
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
            "SELECT body,read,type,recipient FROM tings WHERE ctx=?1
          AND (?2 IS NULL OR recipient=?2) AND (?3 IS NULL OR app=?3)
          AND (?4 IS NULL OR type=?4) AND (?5 IS NULL OR read=?5) AND (?6 IS NULL OR silent=?6)
          AND created<=?7 AND (?8 IS NULL OR (created,id)<(?8,?9))
          AND created>=?11 AND ((read=0 AND silent=0) OR created>=?12) ORDER BY created DESC,id DESC LIMIT ?10",
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
                ))
            },
        )?;
        let mut out = vec![];
        for row in rows {
            let (body, read, typ, recipient) = row?;
            let mut t = current_body(body, typ, recipient)?;
            t["read"] = read.into();
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
        let row:Option<(String,bool,String,String)>=db.query_row("SELECT body,read,type,recipient FROM tings WHERE ctx=? AND id=? AND (? IS NULL OR recipient=?) AND (? IS NULL OR app=?) AND created>=? AND ((read=0 AND silent=0) OR created>=?)",params![ctx,mid,recipient,recipient,app,app,retention_cutoff(3),retention_cutoff(1)],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        let (b, read, typ, recipient) = row.ok_or_else(Error::not_found)?;
        let mut b = current_body(b, typ, recipient)?;
        b["read"] = read.into();
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
                 AND created>=? AND ((read=0 AND silent=0) OR created>=?)",
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
        let mut q=db.prepare("SELECT app,scope,enabled FROM preferences WHERE ctx=? AND recipient=? AND scope<>'delivery:required' ORDER BY app,scope")?;
        let rows = q.query_map(params![p.context, p.id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, bool>(2)?,
            ))
        })?;
        let mut out = vec![];
        for r in rows {
            let (app, scope, enabled) = r?;
            let v = json!({"app_id":app,"service":scope.strip_prefix("service:"),"type":scope.strip_prefix("type:"),"enabled":enabled});
            if ["app_id", "service", "type"]
                .iter()
                .any(|k| f.get(*k).is_some_and(|x| *x != v[*k]))
            {
                continue;
            }
            out.push(v)
        }
        Ok(out)
    }
    pub fn preference(&self, p: &Principal, b: &Value, reset: bool) -> Result<Value> {
        v::preference(b, !reset)?;
        let scope = if let Some(s) = b["type"].as_str() {
            format!("type:{s}")
        } else if let Some(s) = b["service"].as_str() {
            format!("service:{s}")
        } else {
            "app".into()
        };
        let db = self.lock()?;
        if reset {
            db.execute(
                "DELETE FROM preferences WHERE ctx=? AND recipient=? AND app=? AND scope=?",
                params![p.context, p.id, b["app_id"].as_str(), scope],
            )?;
        } else {
            db.execute(
                "INSERT OR REPLACE INTO preferences VALUES(?,?,?,?,?)",
                params![
                    p.context,
                    p.id,
                    b["app_id"].as_str(),
                    scope,
                    b["enabled"].as_bool()
                ],
            )?;
        }
        let mut out = json!({"app_id":b["app_id"],"service":b.get("service").unwrap_or(&Value::Null),"type":b.get("type").unwrap_or(&Value::Null)});
        out[if reset { "reset" } else { "enabled" }] = if reset {
            true.into()
        } else {
            b["enabled"].clone()
        };
        Ok(out)
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
    pub fn hooks(&self, p: &Principal) -> Result<Vec<Value>> {
        let db = self.lock()?;
        let mut q=db.prepare("SELECT h.id,h.receiver,h.state,(SELECT COUNT(*) FROM deliveries d JOIN tings t ON t.id=d.message WHERE d.hook=h.id AND d.read=0 AND t.created>=? AND ((t.read=0 AND t.silent=0) OR t.created>=?)) FROM hooks h WHERE ctx=? AND recipient=? ORDER BY id")?;
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
        tx.execute("INSERT INTO deliveries(hook,message) SELECT ?1,t.id FROM tings t WHERE t.ctx=?2 AND t.recipient=?3 AND t.read=0 AND t.created>=?4 AND (t.silent=0 OR t.created>=?5)
        AND EXISTS(SELECT 1 FROM grants g WHERE g.ctx=t.ctx AND g.app=t.app AND g.recipient=t.recipient AND g.active=1)
        AND ((json_extract(t.body,'$.delivery')='required' AND EXISTS(SELECT 1 FROM preferences p WHERE p.ctx=t.ctx AND p.recipient=t.recipient AND p.app=t.app AND p.scope='delivery:required' AND p.enabled=1))
        OR (COALESCE(json_extract(t.body,'$.delivery'),'')<>'required' AND t.silent=0 AND COALESCE((SELECT p.enabled FROM preferences p WHERE p.ctx=t.ctx AND p.recipient=t.recipient AND p.app=t.app
          AND p.scope IN ('type:'||t.type,'service:'||substr(t.type,length(t.app)+2,instr(substr(t.type,length(t.app)+2),'.')-1),'app')
          ORDER BY CASE WHEN p.scope LIKE 'type:%' THEN 0 WHEN p.scope LIKE 'service:%' THEN 1 ELSE 2 END LIMIT 1),1)=1))",params![hid,p.context,p.id,retention_cutoff(3),retention_cutoff(1)])?;
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
        let row: Option<(String, String)> = tx
            .query_row(
                "SELECT ctx,recipient FROM hooks WHERE id=? AND receiver=? AND state='connected'",
                params![hid, receiver],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((_ctx, _recipient)) = row else {
            return Ok(None);
        };
        let active: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM deliveries WHERE hook=? AND read=0 AND offer_receiver=?)",
            params![hid, receiver],
            |r| r.get(0),
        )?;
        let rows = {
            let mut q=tx.prepare("SELECT t.body,t.type,t.recipient FROM deliveries d JOIN tings t ON t.id=d.message
              WHERE d.hook=?1 AND d.read=0 AND t.created>=?5 AND ((t.read=0 AND t.silent=0) OR t.created>=?6)
              AND (?2=0 OR (d.offer_receiver=?3 AND d.delivery=0 AND d.last_offer<=?4))
              AND EXISTS(SELECT 1 FROM grants g WHERE g.ctx=t.ctx AND g.app=t.app AND g.recipient=t.recipient AND g.active=1)
              AND ((json_extract(t.body,'$.delivery')='required' AND EXISTS(SELECT 1 FROM preferences p WHERE p.ctx=t.ctx AND p.recipient=t.recipient AND p.app=t.app AND p.scope='delivery:required' AND p.enabled=1))
              OR (COALESCE(json_extract(t.body,'$.delivery'),'')<>'required' AND t.silent=0 AND COALESCE((SELECT p.enabled FROM preferences p WHERE p.ctx=t.ctx AND p.recipient=t.recipient AND p.app=t.app
                AND p.scope IN ('type:'||t.type, 'service:'||substr(t.type,length(t.app)+2,instr(substr(t.type,length(t.app)+2),'.')-1),'app')
                ORDER BY CASE WHEN p.scope LIKE 'type:%' THEN 0 WHEN p.scope LIKE 'service:%' THEN 1 ELSE 2 END LIMIT 1),1)=1))
              ORDER BY t.created,t.id LIMIT 100")?;
            q.query_map(
                params![
                    hid,
                    active,
                    receiver,
                    now() - 10,
                    retention_cutoff(3),
                    retention_cutoff(1)
                ],
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
        let mut tings = vec![];
        let mut bytes = 256usize;
        for (body, typ, recipient) in rows {
            let mut b = current_body(body, typ, recipient)?;
            b.as_object_mut().unwrap().remove("read");
            b.as_object_mut().unwrap().remove("silent");
            let size = b.to_string().len() + 1;
            if bytes + size > 1024 * 1024 || tings.len() == 100 {
                break;
            }
            bytes += size;
            tings.push(b);
        }
        if tings.is_empty() {
            return Ok(None);
        }
        for ting in &tings {
            tx.execute("UPDATE deliveries SET offered=1,offer_receiver=?,last_offer=? WHERE hook=? AND message=?",params![receiver,now(),hid,ting["id"].as_str()])?;
        }
        let envelope = json!({"op":"tings","webhook_id":hid,"tings":tings});
        if envelope.to_string().len() > 1024 * 1024 {
            return Err(Error::unavailable("Delivery envelope exceeded its limit."));
        }
        tx.commit()?;
        Ok(Some(envelope))
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
                        "UPDATE tings SET read=1 WHERE id=? AND read=0 AND created<?",
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
        let mut q=db.prepare("SELECT DISTINCT h.ctx,h.recipient FROM hooks h JOIN deliveries d ON d.hook=h.id JOIN tings t ON t.id=d.message WHERE h.receiver IS NOT NULL AND d.read=0 AND (t.created<?1 OR ((t.read=1 OR t.silent=1) AND t.created<?2))")?;
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
            "DELETE FROM deliveries WHERE message IN(SELECT id FROM tings WHERE created<?1 OR ((read=1 OR silent=1) AND created<?2))",
            params![cutoff,read_cutoff],
        )?;
        let removed = tx.execute(
            "DELETE FROM tings WHERE created<?1 OR ((read=1 OR silent=1) AND created<?2)",
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
