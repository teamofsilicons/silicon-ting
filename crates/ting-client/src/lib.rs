pub mod websocket;
#[cfg(windows)]
pub mod windows;
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fmt, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use url::Url;

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Error {
    pub code: String,
    pub message: String,
    pub hint: String,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}
impl Error {
    pub fn input(message: impl Into<String>) -> Self {
        Self::new(
            "invalid_input",
            message,
            "Run the command with --help to check its inputs.",
            false,
        )
    }
    pub fn new(code: &str, message: impl Into<String>, hint: &str, retryable: bool) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            hint: hint.into(),
            retryable,
            details: None,
        }
    }
    pub fn io() -> Self {
        Self::new(
            "local_storage_unavailable",
            "Could not access private local state.",
            "Check file ownership, permissions and available disk space.",
            true,
        )
    }
    pub fn network() -> Self {
        Self::new(
            "connection_failed",
            "The request failed or timed out; its outcome may be uncertain.",
            "Check connectivity. Use a valid token authorized for this operation before retrying an app request; preserve its key and exact bytes.",
            true,
        )
    }
    pub fn envelope(&self) -> Value {
        json!({"error":self})
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} {}", self.code, self.message, self.hint)
    }
}
impl std::error::Error for Error {}

// Recursively reject duplicate keys before serde_json can silently overwrite them.
struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("valid JSON with unique object keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Strict, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| Strict(Value::Number(n)))
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_none<E: de::Error>(self) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut out = Vec::new();
                while let Some(Strict(v)) = a.next_element()? {
                    out.push(v)
                }
                Ok(Strict(Value::Array(out)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut out = serde_json::Map::new();
                while let Some(k) = a.next_key::<String>()? {
                    if out.contains_key(&k) {
                        return Err(de::Error::custom("duplicate object key"));
                    }
                    let Strict(v) = a.next_value()?;
                    out.insert(k, v);
                }
                Ok(Strict(Value::Object(out)))
            }
        }
        d.deserialize_any(V)
    }
}
pub fn strict_json(bytes: &[u8]) -> Result<Value> {
    let mut d = serde_json::Deserializer::from_slice(bytes);
    let Strict(v) = Strict::deserialize(&mut d).map_err(|_| {
        Error::input("Invalid UTF-8 JSON, duplicate object keys, or unsupported number.")
    })?;
    d.end()
        .map_err(|_| Error::input("Trailing content after JSON."))?;
    Ok(v)
}
pub fn object_argument(s: &str) -> Result<Value> {
    let bytes = if let Some(p) = s.strip_prefix('@') {
        fs::read(p).map_err(|_| Error::input("Could not read JSON input file."))?
    } else {
        s.as_bytes().to_vec()
    };
    let v = strict_json(&bytes)?;
    if !v.is_object() {
        return Err(Error::input("JSON input must be an object."));
    }
    Ok(v)
}
pub fn nonempty(s: &str, name: &str) -> Result<()> {
    if s.is_empty() || s.chars().any(char::is_control) {
        Err(Error::input(format!(
            "{name} must be nonempty and contain no control characters."
        )))
    } else {
        Ok(())
    }
}
pub fn type_app(s: &str) -> Result<&str> {
    if s.len() > 255 {
        return Err(Error::input("Type exceeds 255 bytes."));
    }
    let mut p = s.rsplitn(3, '.');
    let event = p.next().unwrap_or("");
    let service = p.next().unwrap_or("");
    let app = p.next().unwrap_or("");
    for x in [service, event] {
        if !x.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
            || !x
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        {
            return Err(Error::input(
                "Type must use app.service.event with lowercase service and event names.",
            ));
        }
    }
    if app.len() > 80
        || !app.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        || !app
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        return Err(Error::input(
            "App ID must be a Silicon Apps ID: 1–80 lowercase letters, digits, underscores or hyphens, starting with a letter. Use the ID published in Silicon Apps.",
        ));
    }
    Ok(app)
}
pub fn api_origin(s: &str) -> Result<String> {
    let u = Url::parse(s).map_err(|_| Error::input("API URL must be an absolute HTTPS origin."))?;
    let loopback = u.host_str().is_some_and(|h| {
        h == "localhost"
            || h == "[::1]"
            || h == "::1"
            || h.parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if !(u.scheme() == "https" || u.scheme() == "http" && loopback)
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.path() != "/"
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return Err(Error::input(
            "API URL requires HTTPS (HTTP only on loopback), with no credentials, path, query or fragment.",
        ));
    }
    Ok(u.origin().ascii_serialization())
}
pub fn webhook_url(s: &str) -> Result<()> {
    let u =
        Url::parse(s).map_err(|_| Error::input("Webhook URL must be absolute HTTP or HTTPS."))?;
    if !["http", "https"].contains(&u.scheme())
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.fragment().is_some()
    {
        return Err(Error::input(
            "Webhook URL must use HTTP(S) without credentials or fragment.",
        ));
    }
    Ok(())
}
pub fn segment(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}
pub fn query(path: &str, pairs: &[(String, String)]) -> String {
    if pairs.is_empty() {
        return path.into();
    }
    format!(
        "{}?{}",
        path,
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish()
    )
}
pub fn secret(source: Option<&str>) -> Result<String> {
    let mut s = String::new();
    if let Some(p) = source {
        s = fs::read_to_string(p)
            .map_err(|_| Error::input("Could not read secret file as UTF-8."))?
    } else {
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|_| Error::input("Could not read secret from stdin."))?;
    }
    if s.ends_with("\r\n") {
        s.truncate(s.len() - 2)
    } else if s.ends_with('\n') {
        s.pop();
    }
    if s.is_empty() || s.contains(['\r', '\n']) {
        return Err(Error::input("Secret must be one nonempty line."));
    }
    Ok(s)
}
#[derive(Clone)]
pub struct Client {
    pub origin: String,
    http: reqwest::Client,
}
impl Client {
    pub fn new(origin: &str) -> Result<Self> {
        Ok(Self {
            origin: api_origin(origin)?,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|_| Error::network())?,
        })
    }
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
        credential: Option<&str>,
        key: Option<&str>,
    ) -> Result<Value> {
        let method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|_| Error::input("Invalid HTTP method."))?;
        let mut req = self
            .http
            .request(method, format!("{}{}", self.origin, path))
            .header("Ting-Client-Version", env!("CARGO_PKG_VERSION"));
        if let Some(c) = credential {
            req = req.bearer_auth(c)
        }
        if let Some(b) = body {
            req = req.header("Content-Type", "application/json").body(b)
        }
        if let Some(k) = key {
            req = req.header("Idempotency-Key", k)
        }
        let r = req.send().await.map_err(|_| Error::network())?;
        let status = r.status();
        let b = r.bytes().await.map_err(|_| Error::network())?;
        let v: Value = serde_json::from_slice(&b).map_err(|_| {
            Error::new(
                "invalid_server_response",
                "Server returned an invalid response.",
                "Check the API origin and client/server compatibility.",
                true,
            )
        })?;
        if !status.is_success() {
            return Err(
                serde_json::from_value(v.get("error").cloned().unwrap_or(Value::Null))
                    .unwrap_or_else(|_| {
                        Error::new(
                            "api_error",
                            format!("API returned HTTP {}.", status.as_u16()),
                            "Check the request and server status.",
                            status.is_server_error(),
                        )
                    }),
            );
        }
        Ok(v)
    }
    pub async fn json(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        credential: Option<&str>,
    ) -> Result<Value> {
        self.request(
            method,
            path,
            body.map(|v| serde_json::to_vec(&v).unwrap()),
            credential,
            None,
        )
        .await
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProofOperation {
    Send,
    Register,
    Subscriptions,
    Revoke,
    SentList,
    SentGet,
    SentRead,
}
impl ProofOperation {
    pub fn path(self) -> &'static str {
        match self {
            Self::Send => "/v1/tings",
            Self::Register => "/v1/subscriptions",
            Self::Subscriptions => "/v1/subscriptions/query",
            Self::Revoke => "/v1/subscriptions/revoke",
            Self::SentList | Self::SentGet => "/v1/sent/query",
            Self::SentRead => "/v1/sent/read",
        }
    }
}
pub struct Prepared {
    pub body: Vec<u8>,
    pub value: Value,
    pub operation: ProofOperation,
}
impl Prepared {
    pub fn new(operation: ProofOperation, bytes: Vec<u8>) -> Result<Self> {
        if bytes.len()
            > if operation == ProofOperation::Send {
                256 * 1024
            } else {
                1024 * 1024
            }
        {
            return Err(Error::input("Request exceeds its byte limit."));
        }
        let v = strict_json(&bytes)?;
        let obj = v
            .as_object()
            .ok_or_else(|| Error::input("Request must be a JSON object."))?;
        let (required, optional): (&[&str], &[&str]) = match operation {
            ProofOperation::Send => (&["type", "for", "key", "data"], &["metadata", "delivery"]),
            ProofOperation::Register => (&["app_id"], &["for"]),
            ProofOperation::Subscriptions => (&["app_id"], &["for", "limit", "cursor"]),
            ProofOperation::Revoke => (&["id"], &["app_id"]),
            ProofOperation::SentList => (&["app_id"], &["for", "type", "read", "limit", "cursor"]),
            ProofOperation::SentGet => (&["app_id", "id"], &["deliveries_cursor"]),
            ProofOperation::SentRead => (&["app_id", "message_ids", "read", "key"], &[]),
        };
        for k in required {
            if !obj.contains_key(*k) {
                return Err(Error::input(format!("Missing request field {k}.")));
            }
        }
        for (k, value) in obj {
            if !required.contains(&k.as_str()) && !optional.contains(&k.as_str()) {
                return Err(Error::input(format!("Unknown request field {k}.")));
            }
            match k.as_str() {
                "data" | "metadata" => {
                    if !value.is_object() {
                        return Err(Error::input(format!("{k} must be an object.")));
                    }
                }
                "read" => {
                    if !value.is_boolean() {
                        return Err(Error::input("read must be a boolean."));
                    }
                }
                "message_ids" => {
                    let ids = value
                        .as_array()
                        .ok_or_else(|| Error::input("message_ids must be an array."))?
                        .iter()
                        .map(|id| {
                            id.as_str()
                                .map(str::to_owned)
                                .ok_or_else(|| Error::input("Each message ID must be a string."))
                        })
                        .collect::<Result<Vec<_>>>()?;
                    unique_ids(ids)?;
                }
                "limit" => {
                    if !value.as_u64().is_some_and(|n| (1..=100).contains(&n)) {
                        return Err(Error::input("limit must be an integer from 1 to 100."));
                    }
                }
                "delivery" => {
                    if value.as_str() != Some("required") {
                        return Err(Error::input(
                            "delivery must be required, or omitted for ordinary notifications.",
                        ));
                    }
                }
                _ => nonempty(
                    value
                        .as_str()
                        .ok_or_else(|| Error::input(format!("{k} must be a string.")))?,
                    k,
                )?,
            }
        }
        if let Some(t) = v.get("type").and_then(Value::as_str) {
            let app = type_app(t)?;
            if let Some(a) = v.get("app_id").and_then(Value::as_str)
                && a != app
            {
                return Err(Error::input("Type does not belong to the selected app."));
            }
        }
        if v.get("key")
            .and_then(Value::as_str)
            .is_some_and(|s| s.len() > 200)
        {
            return Err(Error::input("key exceeds 200 bytes."));
        }
        Ok(Self {
            body: bytes,
            value: v,
            operation,
        })
    }
    pub fn sha256(&self) -> String {
        format!("{:x}", Sha256::digest(&self.body))
    }
    /// Submit the original bytes using the operation's credential. App sends and
    /// sent history use scoped Accounts tokens; registration requires recipient delegation.
    /// No Ting user session is needed, and retries retain the original body/key.
    pub async fn execute(&self, client: &Client, proof: &str) -> Result<Value> {
        client
            .request(
                "POST",
                self.operation.path(),
                Some(self.body.clone()),
                Some(proof),
                None,
            )
            .await
    }
    pub fn write(&self, path: &Path) -> Result<Value> {
        if path.exists() {
            return Err(Error::input(
                "Request output file already exists; choose a new path.",
            ));
        }
        write_private(path, &self.body, true)?;
        Ok(
            json!({"method":"POST","path":self.operation.path(),"request_file":fs::canonicalize(path).map_err(|_|Error::io())?,"body_sha256":self.sha256()}),
        )
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Session {
    pub api_url: String,
    pub id: String,
    pub token: String,
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub context: Option<Value>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Settings {
    pub telemetry: Option<bool>,
}
#[derive(Clone)]
pub struct Profile {
    pub dir: PathBuf,
}
pub fn real_home() -> Result<PathBuf> {
    #[cfg(unix)]
    {
        let uid = unsafe { libc::getuid() };
        let p = unsafe { libc::getpwuid(uid) };
        if p.is_null() {
            return Err(Error::io());
        }
        let s = unsafe { std::ffi::CStr::from_ptr((*p).pw_dir) }
            .to_str()
            .map_err(|_| Error::io())?;
        if s.is_empty() {
            return Err(Error::io());
        }
        Ok(PathBuf::from(s))
    }
    #[cfg(windows)]
    {
        windows::home()
    }
}
pub fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|_| Error::io())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        let directory = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| Error::io())?;
        if directory.metadata().map_err(|_| Error::io())?.uid() != unsafe { libc::geteuid() } {
            return Err(Error::io());
        }
        directory
            .set_permissions(fs::Permissions::from_mode(0o700))
            .map_err(|_| Error::io())?;
    }
    #[cfg(windows)]
    windows::private_path(path, true)?;
    Ok(())
}
pub fn write_private(path: &Path, bytes: &[u8], exclusive: bool) -> Result<()> {
    if let Some(p) = path.parent().filter(|p| !p.as_os_str().is_empty())
        && !p.exists()
    {
        return Err(Error::io());
    }
    let target = if exclusive {
        path.to_owned()
    } else {
        path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()))
    };
    let mut o = fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(&target).map_err(|_| Error::io())?;
    #[cfg(windows)]
    windows::private_path(&target, false)?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|_| Error::io())?;
    if !exclusive {
        fs::rename(&target, path).map_err(|_| Error::io())?;
    }
    #[cfg(unix)]
    if let Some(p) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::File::open(p)
            .and_then(|f| f.sync_all())
            .map_err(|_| Error::io())?;
    }
    Ok(())
}
impl Profile {
    pub fn current() -> Result<Self> {
        let base = match std::env::var_os("SILICON_HOME") {
            Some(p) if p.is_empty() => return Err(Error::input("SILICON_HOME cannot be empty.")),
            Some(p) => PathBuf::from(p),
            None => real_home()?,
        };
        let dir = base.join(".ting");
        private_dir(&dir)?;
        Ok(Self {
            dir: fs::canonicalize(dir).map_err(|_| Error::io())?,
        })
    }
    pub fn lock(&self) -> Result<fs::File> {
        let mut options = fs::OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(0);
        }
        let file = options
            .open(self.dir.join("profile.lock"))
            .map_err(|_| Error::io())?;
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(Error::new(
                    "profile_busy",
                    "Another command is updating this profile.",
                    "Retry when the active command completes.",
                    true,
                ));
            }
        }
        Ok(file)
    }
    pub fn read<T: serde::de::DeserializeOwned>(&self, name: &str) -> Result<Option<T>> {
        let p = self.dir.join(name);
        if !p.exists() {
            return Ok(None);
        }
        let b = fs::read(p).map_err(|_| Error::io())?;
        serde_json::from_slice(&b)
            .map(Some)
            .map_err(|_| Error::io())
    }
    pub fn save<T: Serialize>(&self, name: &str, v: &T) -> Result<()> {
        write_private(
            &self.dir.join(name),
            &serde_json::to_vec(v).map_err(|_| Error::io())?,
            false,
        )
    }
    pub fn remove(&self, name: &str) -> Result<()> {
        match fs::remove_file(self.dir.join(name)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(Error::io()),
        }
    }
    pub fn session(&self, origin: &str) -> Result<Session> {
        let s: Session = self.read("session.json")?.ok_or_else(|| {
            Error::new(
                "authentication_required",
                "This profile is not logged in.",
                "Run ting login with a Silicon Accounts short-lived token.",
                false,
            )
        })?;
        if s.api_url != origin {
            return Err(Error::new(
                "session_api_mismatch",
                "Saved session belongs to a different API origin.",
                "Use its API URL or a separate SILICON_HOME profile.",
                false,
            ));
        }
        Ok(s)
    }
}
pub fn daemon_socket() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/var/tmp/silicon-ting/daemon.sock")
    }
    #[cfg(windows)]
    {
        PathBuf::from(r"\\.\pipe\silicon-ting")
    }
}
#[cfg(unix)]
fn verify_unix_server(socket: &tokio::net::UnixStream, owner: u32) -> Result<()> {
    if socket.peer_cred().map_err(|_| Error::io())?.uid() != owner {
        return Err(Error::new(
            "daemon_identity_mismatch",
            "The local Ting service belongs to another operating-system user.",
            "Run the installer as the owner of this Ting profile.",
            false,
        ));
    }
    Ok(())
}
/// Maps a failed daemon connect: only a missing or refused endpoint may start a daemon.
/// Access denied means another account owns the endpoint, where a second daemon cannot bind.
pub fn daemon_connect_error(error: &std::io::Error) -> Error {
    #[cfg(unix)]
    let denied = error.kind() == std::io::ErrorKind::PermissionDenied;
    #[cfg(windows)]
    let denied = error.raw_os_error() == Some(5);
    if denied {
        return Error::new(
            "daemon_identity_mismatch",
            "The Ting socket belongs to another account.",
            if cfg!(windows) {
                "Stop that account's Ting daemon, or run as that account."
            } else {
                "Remove /var/tmp/silicon-ting as its owner, or run as that account."
            },
            false,
        );
    }
    Error::new(
        "daemon_unavailable",
        "The Ting daemon is not running.",
        "Run ting daemon start; log: ~/.ting-daemon/daemon.log",
        true,
    )
}
#[cfg(unix)]
type DaemonStream = tokio::net::UnixStream;
#[cfg(windows)]
type DaemonStream = tokio::net::windows::named_pipe::NamedPipeClient;
/// Connects to a daemon endpoint and verifies that it runs as this account.
async fn connect_daemon(endpoint: &Path) -> Result<DaemonStream> {
    #[cfg(unix)]
    {
        let socket = tokio::net::UnixStream::connect(endpoint)
            .await
            .map_err(|e| daemon_connect_error(&e))?;
        verify_unix_server(&socket, unsafe { libc::geteuid() })?;
        Ok(socket)
    }
    #[cfg(windows)]
    {
        let mut attempts = 0;
        let pipe = loop {
            match tokio::net::windows::named_pipe::ClientOptions::new().open(endpoint) {
                Ok(s) => break s,
                Err(e) if e.raw_os_error() == Some(231) && attempts < 20 => {
                    attempts += 1;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) => return Err(daemon_connect_error(&e)),
            }
        };
        windows::verify_pipe_server(&pipe)?;
        Ok(pipe)
    }
}
/// Whether this account's daemon answers at `endpoint`. Sends no request.
pub async fn daemon_answers(endpoint: &Path) -> Result<bool> {
    match connect_daemon(endpoint).await {
        Ok(_) => Ok(true),
        Err(e) if e.code == "daemon_unavailable" => Ok(false),
        Err(e) => Err(e),
    }
}
pub async fn ipc(request: Value) -> Result<Value> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let task = async {
        let mut socket = connect_daemon(&daemon_socket()).await?;
        let mut bytes =
            serde_json::to_vec(&request).map_err(|_| Error::input("Invalid daemon request."))?;
        bytes.push(b'\n');
        socket
            .write_all(&bytes)
            .await
            .map_err(|_| Error::network())?;
        let mut line = String::new();
        BufReader::new(socket)
            .read_line(&mut line)
            .await
            .map_err(|_| Error::network())?;
        let v = strict_json(line.as_bytes())?;
        if let Some(e) = v.get("error") {
            return Err(serde_json::from_value(e.clone()).map_err(|_| Error::network())?);
        }
        Ok(v)
    };
    tokio::time::timeout(Duration::from_secs(30), task)
        .await
        .map_err(|_| Error::network())?
}
pub fn unique_ids(ids: Vec<String>) -> Result<Vec<String>> {
    if ids.is_empty() || ids.len() > 100 {
        return Err(Error::input("Supply 1 to 100 IDs."));
    }
    let mut seen = HashSet::new();
    ids.into_iter()
        .filter_map(|s| {
            if seen.insert(s.clone()) {
                Some(if s.len() > 255 {
                    Err(Error::input("ID exceeds 255 bytes."))
                } else {
                    nonempty(&s, "ID").map(|_| s)
                })
            } else {
                None
            }
        })
        .collect()
}
/// Best-effort, bounded diagnostic events. Callers must pass categories and timings only.
/// Credentials, user request bodies, attachment contents and local paths are never included.
pub async fn telemetry(origin: &str, event: &str, data: Value) {
    let Ok(origin) = api_origin(origin) else {
        return;
    };
    let Ok(http) = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_millis(1500))
        .build()
    else {
        return;
    };
    let _ = http.post(format!("{origin}/v1/telemetry")).json(&json!({"table":"tingclidaemon","events":[{"id":uuid::Uuid::new_v4().to_string(),"type":event,"data":data,"metadata":{"version":env!("CARGO_PKG_VERSION"),"platform":std::env::consts::OS}}]})).send().await;
}
