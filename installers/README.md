# Ting shared service

Ting runs one daemon per account, started on demand; the installer adds start-at-boot supervision. The first `ting webhook`, WebSocket send, `daemon reconnect` or `daemon start` starts the `ting-daemon` installed beside `ting`, detached and as the calling account, with no sudo or prompt. All that account's `SILICON_HOME` profiles connect through `/var/tmp/silicon-ting/daemon.sock`. The socket is independent of profile and API settings. The installer is optional; run it once per system to start the daemon at boot and restart it after crashes. It does not authenticate any identity.

```sh
curl -fsSL https://raw.githubusercontent.com/teamofsilicons/silicon-ting/main/scripts/install.sh | sh
```

The installer checks the release's SHA-256 manifest, installs `ting` and `ting-daemon`, and registers launchd or systemd. It requests sudo for the system installation. For a source checkout with Rust installed:

```sh
TING_INSTALL_FROM_SOURCE=1 sh scripts/install.sh
```

Honeycomb installs the `ting` and `ting-daemon` executables side by side with `honeycomb install 'ting'`. Honeycomb installs need no further step; the installer is optional, for start at boot. On Windows, the optional PowerShell installer below runs from an elevated prompt. `cargo install silicon-ting-cli` installs the CLI only; webhooks also need `ting-daemon` from a release archive, beside `ting` or on `PATH`. HTTP commands work independently of the daemon.

```powershell
Invoke-WebRequest https://ting.teamofsilicons.com/install.ps1 -OutFile install-ting.ps1
.\install-ting.ps1
```

Daemon state lives in the service owner's real `~/.ting-daemon` with private permissions. Session credentials remain in each profile's private `.ting/session.json`. The IPC server verifies the Unix peer's UID, private profile ownership, and the matching session token; profile paths alone confer no authority. Different operating-system users cannot share this service; all profiles belong to its owner account. Releases contain native x86_64 and ARM64 builds for macOS, Linux and Windows.

The Linux release binaries require glibc 2.39 or newer, as provided by Ubuntu 24.04. For older distributions, build from source using the installation command above. Linux service registration requires systemd; on-demand start does not.

On Windows, download and run `scripts/install.ps1` from an elevated PowerShell prompt. It verifies the published ZIP checksum, installs the binaries, and registers one `SiliconTingDaemon` task with Windows Task Scheduler. The task starts at owner sign-in, is invoked on demand by the CLI, and restarts process failures. Without the task, the CLI starts `ting-daemon.exe` from beside `ting.exe`. It uses the fixed local named pipe `\\.\pipe\silicon-ting`, with a current-user-only native DACL and remote pipe clients disabled. Native owner-only ACLs protect profiles, queue and prepared files; the daemon also verifies the profile owner/ACL and its private session token. State remains in the service owner's real Windows profile directory, independently of `SILICON_HOME`.

The local SQLite WAL stores incoming batches before delivery ACK and stores acceptance before read ACK. With the installed service, the service manager restarts process failures. Without it, a stopped daemon restarts on the next `webhook`, `daemon reconnect`, `daemon start` or WebSocket send; tings wait on the server meanwhile. The daemon writes its startup errors to `~/.ting-daemon/daemon.log`. Per-hook forwarding tasks recover independently. Do not delete daemon state during ordinary upgrades. After actual disk loss, list the server's hooks and explicitly reattach the existing IDs.

Read or silent tings expire after one calendar month; unread non-silent tings expire after three calendar months, measured from original creation in UTC. The daemon enforces the three-month hard limit locally. For older-than-one-month local copies it confirms server expiration with the authenticated inbox before deleting them, because another destination may have changed overall read state. A recorded webhook acceptance is never re-forwarded while waiting for a read ACK. Expired history cannot be recovered by reattaching a hook.
