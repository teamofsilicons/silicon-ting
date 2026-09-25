//! Starts the local receiver on demand as the calling account: no sudo, no prompt and no
//! service manager required. An installed platform service is preferred, but is never
//! asked for credentials; without one, the sibling `ting-daemon` is spawned detached.
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use ting_client::*;

/// Sends one IPC request, starting the daemon and retrying once if nothing answers.
pub async fn ipc_starting(request: Value) -> Result<Value> {
    match ipc(request.clone()).await {
        Err(e) if e.code == "daemon_unavailable" => {
            ensure_daemon().await?;
            ipc(request).await
        }
        result => result,
    }
}
pub async fn ensure_daemon() -> Result<()> {
    ensure(&Layout::current()?).await
}
struct Layout {
    home: PathBuf,
    state: PathBuf,
    socket: PathBuf,
    daemon: PathBuf,
    platform_service: bool,
}
impl Layout {
    fn current() -> Result<Self> {
        let home = real_home()?;
        Ok(Self {
            state: home.join(".ting-daemon"),
            socket: daemon_socket(),
            daemon: daemon_binary(),
            platform_service: true,
            home,
        })
    }
}
/// Honeycomb and the installers place `ting-daemon` beside `ting`; Honeycomb's Unix
/// launchers are symlinks, so resolve them first. Windows launchers are `.cmd` files that
/// `Command` cannot find by bare name, so Windows never falls back to PATH.
fn daemon_binary() -> PathBuf {
    #[cfg(unix)]
    {
        std::env::current_exe()
            .and_then(fs::canonicalize)
            .map(|p| p.with_file_name("ting-daemon"))
            .ok()
            .filter(|p| p.is_file())
            .unwrap_or_else(|| PathBuf::from("ting-daemon"))
    }
    #[cfg(windows)]
    {
        std::env::current_exe()
            .map(|p| p.with_file_name("ting-daemon.exe"))
            .unwrap_or_default()
    }
}
fn unavailable(message: impl Into<String>, log: &Path) -> Error {
    let mut e = Error::new("daemon_unavailable", message, "", true);
    e.hint = format!("Run ting daemon start; log: {}", log.display());
    e
}
async fn ensure(l: &Layout) -> Result<()> {
    if daemon_answers(&l.socket).await? {
        return Ok(());
    }
    private_dir(&l.state)?;
    let log = l.state.join("daemon.log");
    let _lock = lock(&l.state.join("startup.lock"), &log).await?;
    // Another starter may have finished while this one waited.
    if daemon_answers(&l.socket).await? {
        return Ok(());
    }
    #[cfg(unix)]
    socket_directory(&l.socket)?;
    if l.platform_service && platform_service().await && wait(&l.socket, 8).await? {
        return Ok(());
    }
    let mut child = Some(spawn(l, &log)?);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if daemon_answers(&l.socket).await? {
            return Ok(());
        }
        if let Some(Ok(Some(_))) = child.as_mut().map(|c| c.try_wait()) {
            child = None;
            let line = last_line(&log);
            // A daemon started elsewhere holds the single-instance lock; wait for its socket.
            if !line.starts_with("daemon_running") {
                return Err(unavailable(
                    format!("The Ting daemon exited during startup: {line}"),
                    &log,
                ));
            }
        }
        if Instant::now() >= deadline {
            return Err(unavailable(
                "The Ting daemon did not become ready within 10 seconds.",
                &log,
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
async fn wait(socket: &Path, seconds: u64) -> Result<bool> {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < deadline {
        if daemon_answers(socket).await? {
            return Ok(true);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(false)
}
/// Serializes starters across processes for at most 30 seconds.
async fn lock(path: &Path, log: &Path) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(|_| Error::io())?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await
            }
            Err(fs::TryLockError::WouldBlock) => {
                return Err(unavailable(
                    "Another ting command is still starting the daemon.",
                    log,
                ));
            }
            Err(fs::TryLockError::Error(_)) => return Err(Error::io()),
        }
    }
}
/// The daemon creates the directory itself; an existing one must be this account's own.
#[cfg(unix)]
fn socket_directory(socket: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let dir = socket.parent().ok_or_else(Error::io)?;
    match fs::symlink_metadata(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(Error::io()),
        Ok(m)
            if !m.file_type().is_symlink()
                && m.is_dir()
                && m.uid() == unsafe { libc::geteuid() } =>
        {
            Ok(())
        }
        Ok(_) => {
            let mut e = Error::new(
                "daemon_identity_mismatch",
                "The Ting socket directory belongs to another account or is not a directory.",
                "",
                false,
            );
            e.hint = format!(
                "Remove {} as its owner, or run as that account.",
                dir.display()
            );
            Err(e)
        }
    }
}
/// Asks an installed platform service to start, never interactively. Returns whether one
/// is installed, so its supervisor may still bring the daemon up.
async fn platform_service() -> bool {
    #[cfg(target_os = "linux")]
    {
        if !Path::new("/etc/systemd/system/silicon-ting.service").exists() {
            return false;
        }
        // systemd 258+ opens a polkit prompt on any caller with a controlling terminal
        // unless told not to; nobody can answer it from a captured command.
        let mut c = tokio::process::Command::new("systemctl");
        c.args(["--no-ask-password", "start", "silicon-ting.service"]);
        quiet(&mut c).await;
        true
    }
    #[cfg(target_os = "macos")]
    {
        // KeepAlive restarts the LaunchDaemon; kickstart would require root.
        Path::new("/Library/LaunchDaemons/com.silicon.ting.plist").exists()
    }
    #[cfg(windows)]
    {
        let mut c = tokio::process::Command::new("schtasks.exe");
        c.args(["/Run", "/TN", "SiliconTingDaemon"]);
        quiet(&mut c).await
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    false
}
#[cfg(any(target_os = "linux", windows))]
async fn quiet(c: &mut tokio::process::Command) -> bool {
    c.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    matches!(
        tokio::time::timeout(Duration::from_secs(5), c.status()).await,
        Ok(Ok(s)) if s.success()
    )
}
fn spawn(l: &Layout, log: &Path) -> Result<std::process::Child> {
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let out = options.open(log).map_err(|_| Error::io())?;
    #[cfg(windows)]
    ting_client::windows::private_path(log, false)?;
    #[cfg(windows)]
    private_stdio();
    let mut c = Command::new(&l.daemon);
    // Callers such as Silicon read ting's pipes to EOF: the daemon must never hold them.
    c.stdin(Stdio::null())
        .stdout(out.try_clone().map_err(|_| Error::io())?)
        .stderr(out)
        .current_dir(&l.home)
        .env_remove("NOTIFY_SOCKET")
        .env_remove("WATCHDOG_USEC")
        .env_remove("WATCHDOG_PID");
    #[cfg(unix)]
    unsafe {
        use std::os::unix::process::CommandExt;
        // A new session drops the caller's controlling terminal, not only its process group.
        c.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    #[cfg(windows)]
    let spawned = {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
        c.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB);
        match c.spawn() {
            // A job that forbids breakaway denies the flag; stay in the job instead.
            Err(e) if e.raw_os_error() == Some(5) => {
                c.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
                c.spawn()
            }
            result => result,
        }
    };
    #[cfg(unix)]
    let spawned = c.spawn();
    spawned.map_err(|e| {
        unavailable(
            if e.kind() == std::io::ErrorKind::NotFound {
                format!(
                    "ting-daemon was not found at {}; reinstall Ting.",
                    l.daemon.display()
                )
            } else {
                format!("Could not start {}.", l.daemon.display())
            },
            log,
        )
    })
}
/// Windows children inherit every inheritable handle, not only their stdio slots, and
/// ting's own stdio handles came inheritable from its caller. Keep them out of the daemon.
#[cfg(windows)]
fn private_stdio() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
    for handle in [
        std::io::stdin().as_raw_handle(),
        std::io::stdout().as_raw_handle(),
        std::io::stderr().as_raw_handle(),
    ] {
        if !handle.is_null() {
            unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) };
        }
    }
}
fn last_line(log: &Path) -> String {
    let text = fs::read(log).unwrap_or_default();
    let text = String::from_utf8_lossy(&text);
    let line = text
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("");
    line.trim().chars().take(500).collect()
}
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{os::unix::fs::PermissionsExt, sync::Arc};
    struct Fixture {
        root: PathBuf,
        layout: Arc<Layout>,
        record: PathBuf,
    }
    /// A stand-in daemon with the real one's single-instance lock, bind and exit contract.
    fn fixture(delay: f64, fail: bool) -> Fixture {
        let root = std::env::temp_dir().join(format!(
            "ting-svc-{}",
            &uuid::Uuid::new_v4().to_string()[..8]
        ));
        fs::create_dir(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let socket = root.join("run").join("daemon.sock");
        let record = root.join("record");
        let daemon = root.join("fake-daemon");
        let script = format!(
            r#"#!/usr/bin/env python3
import fcntl, json, os, socket, stat, sys, threading, time
if {fail}:
    print("boom: broken configuration", file=sys.stderr); sys.exit(3)
os.makedirs("{run}", mode=0o700, exist_ok=True)
lock = open("{run}/daemon.lock", "a")
try:
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
except OSError:
    print("daemon_running: Another Ting daemon is already running for this account.", file=sys.stderr); sys.exit(1)
open("{run}/locked", "w").close()
time.sleep({delay})
if os.path.exists("{socket}"): os.unlink("{socket}")
s = socket.socket(socket.AF_UNIX); s.bind("{socket}"); s.listen(64)
null, log = os.stat("/dev/null"), os.stat("{log}")
with open("{record}", "a") as r:
    r.write(json.dumps({{"pid": os.getpid(), "sid": os.getsid(0), "cwd": os.getcwd(),
        "stdin_null": stat.S_ISCHR(os.fstat(0).st_mode) and os.fstat(0).st_rdev == null.st_rdev,
        "stdout_log": os.fstat(1).st_ino == log.st_ino, "stderr_log": os.fstat(2).st_ino == log.st_ino,
        "notify": os.environ.get("NOTIFY_SOCKET")}}) + "\n")
def hold(c):
    while c.recv(1024): pass
    c.close()
while True:
    threading.Thread(target=hold, args=(s.accept()[0],), daemon=True).start()
"#,
            fail = if fail { "True" } else { "False" },
            run = socket.parent().unwrap().display(),
            socket = socket.display(),
            log = root.join("state").join("daemon.log").display(),
            record = record.display(),
        );
        fs::write(&daemon, script).unwrap();
        fs::set_permissions(&daemon, fs::Permissions::from_mode(0o755)).unwrap();
        let layout = Arc::new(Layout {
            home: root.clone(),
            state: root.join("state"),
            socket,
            daemon,
            platform_service: false,
        });
        Fixture {
            root,
            layout,
            record,
        }
    }
    impl Fixture {
        fn records(&self) -> Vec<Value> {
            fs::read_to_string(&self.record)
                .unwrap_or_default()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            for r in self.records() {
                unsafe { libc::kill(r["pid"].as_i64().unwrap() as i32, libc::SIGKILL) };
            }
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    #[tokio::test]
    async fn starts_one_detached_daemon_without_the_callers_pipes() {
        let f = fixture(0.0, false);
        ensure(&f.layout).await.unwrap();
        let r = &f.records()[0];
        assert_eq!(r["sid"], r["pid"], "daemon must lead its own session");
        assert_eq!(r["cwd"], json!(f.root));
        for k in ["stdin_null", "stdout_log", "stderr_log"] {
            assert_eq!(r[k], true, "{k}");
        }
        assert_eq!(r["notify"], Value::Null);
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&f.layout.state), 0o700);
        assert_eq!(mode(&f.layout.state.join("daemon.log")), 0o600);
        // A running daemon is only probed.
        ensure(&f.layout).await.unwrap();
        assert_eq!(f.records().len(), 1);
    }
    #[tokio::test]
    async fn concurrent_starters_leave_exactly_one_daemon() {
        let f = fixture(0.3, false);
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..10 {
            let l = f.layout.clone();
            set.spawn(async move { ensure(&l).await });
        }
        while let Some(result) = set.join_next().await {
            result.unwrap().unwrap();
        }
        assert_eq!(f.records().len(), 1);
    }
    #[tokio::test]
    async fn a_lost_instance_race_waits_for_the_winner() {
        let f = fixture(1.0, false);
        // A daemon started elsewhere, e.g. by a service manager, holds the lock but has not bound yet.
        fs::create_dir(&f.layout.state).unwrap();
        let mut winner = Command::new(&f.layout.daemon)
            .stdout(fs::File::create(f.root.join("winner.log")).unwrap())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let locked = f.layout.socket.with_file_name("locked");
        for _ in 0..200 {
            if locked.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        ensure(&f.layout).await.unwrap();
        // The spawned instance lost the lock and exited; only the winner bound the socket.
        assert_eq!(f.records().len(), 1);
        let log = f.layout.state.join("daemon.log");
        let mut reported = false;
        for _ in 0..100 {
            reported = last_line(&log).starts_with("daemon_running");
            if reported {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let running = winner.try_wait().unwrap().is_none();
        winner.kill().unwrap();
        winner.wait().unwrap();
        assert!(running, "the winner keeps running");
        assert!(
            reported,
            "the losing instance did not report daemon_running"
        );
    }
    #[tokio::test]
    async fn startup_failure_reports_the_log() {
        let f = fixture(0.0, true);
        let e = ensure(&f.layout).await.unwrap_err();
        assert_eq!(e.code, "daemon_unavailable");
        assert!(
            e.message.contains("boom: broken configuration"),
            "{}",
            e.message
        );
        assert!(e.hint.contains("daemon.log"), "{}", e.hint);
    }
    #[tokio::test]
    async fn foreign_or_linked_socket_directories_spawn_nothing() {
        for kind in ["symlink", "file"] {
            let f = fixture(0.0, false);
            let dir = f.layout.socket.parent().unwrap();
            if kind == "symlink" {
                fs::create_dir(f.root.join("elsewhere")).unwrap();
                std::os::unix::fs::symlink(f.root.join("elsewhere"), dir).unwrap();
            } else {
                fs::write(dir, b"").unwrap();
            }
            let e = ensure(&f.layout).await.unwrap_err();
            assert_eq!(e.code, "daemon_identity_mismatch", "{kind}");
            assert!(f.records().is_empty(), "{kind}");
        }
    }
    #[tokio::test]
    async fn missing_binary_is_reported() {
        let f = fixture(0.0, false);
        fs::remove_file(&f.layout.daemon).unwrap();
        let e = ensure(&f.layout).await.unwrap_err();
        assert_eq!(e.code, "daemon_unavailable");
        assert!(e.message.contains("was not found"), "{}", e.message);
    }
}
