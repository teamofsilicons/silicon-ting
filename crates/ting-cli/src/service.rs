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
/// Silicon Apps and the installers place `ting-daemon` beside `ting`; Silicon Apps's Unix
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
