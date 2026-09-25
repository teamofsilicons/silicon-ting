#!/bin/sh
# Install the published CLI and one system service. No IAM login is performed.
set -eu
VERSION=${TING_VERSION:-v0.1.9}
REPOSITORY=https://github.com/teamofsilicons/silicon-ting
PREFIX=${TING_INSTALL_PREFIX:-/usr/local}
case "$(uname -s)" in Darwin) OS=apple-darwin;; Linux) OS=unknown-linux-gnu;; *) echo 'Use the PowerShell installer on Windows; this shell installer supports macOS and Linux.' >&2; exit 1;; esac
case "$(uname -m)" in arm64|aarch64) ARCH=aarch64;; x86_64|amd64) ARCH=x86_64;; *) echo 'Unsupported CPU architecture.' >&2; exit 1;; esac
OWNER=${SUDO_USER:-$(id -un)}
if [ "$OWNER" = root ]; then echo 'Run as the account that owns your Ting profiles (sudo is requested for installation).' >&2; exit 1; fi
if [ "$OS" = apple-darwin ]; then OWNER_HOME=$(dscl . -read "/Users/$OWNER" NFSHomeDirectory | sed 's/^NFSHomeDirectory: //'); else OWNER_HOME=$(getent passwd "$OWNER" | cut -d: -f6); fi
case "$PREFIX" in /*) ;; *) echo 'TING_INSTALL_PREFIX must be absolute.' >&2; exit 1;; esac
# Validate the fixed IPC directory before any privileged mutation. /var/tmp is sticky.
IPC_DIR=/var/tmp/silicon-ting
CREATE_IPC_DIR=0
if [ -L "$IPC_DIR" ]; then
  echo 'The Ting socket directory must not be a symbolic link.' >&2; exit 1
elif [ -e "$IPC_DIR" ]; then
  [ -d "$IPC_DIR" ] || { echo 'The Ting socket path must be a directory.' >&2; exit 1; }
  if [ "$OS" = apple-darwin ]; then IPC_OWNER=$(stat -f %u "$IPC_DIR"); else IPC_OWNER=$(stat -c %u "$IPC_DIR"); fi
  [ "$IPC_OWNER" = "$(id -u "$OWNER")" ] || { echo 'The Ting socket directory belongs to another account.' >&2; exit 1; }
else
  CREATE_IPC_DIR=1
fi
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
if [ "${TING_INSTALL_FROM_SOURCE:-0}" = 1 ]; then
  command -v cargo >/dev/null 2>&1 || { echo 'Rust is required for a source installation.' >&2; exit 1; }
  ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
  (cd "$ROOT" && cargo build --release -p silicon-ting-cli -p silicon-ting-daemon)
  cp "$ROOT/target/release/ting" "$ROOT/target/release/ting-daemon" "$TMP/"
else
  ARCHIVE="ting-$VERSION-$ARCH-$OS.tar.gz"
  BASE="$REPOSITORY/releases/download/$VERSION"
  curl --fail --silent --show-error --location "$BASE/$ARCHIVE" --output "$TMP/$ARCHIVE"
  curl --fail --silent --show-error --location "$BASE/SHA256SUMS" --output "$TMP/SHA256SUMS"
  EXPECTED=$(awk -v f="$ARCHIVE" '$2==f { print $1 }' "$TMP/SHA256SUMS")
  [ ${#EXPECTED} -eq 64 ] || { echo 'The release checksum is missing.' >&2; exit 1; }
  if command -v sha256sum >/dev/null 2>&1; then ACTUAL=$(sha256sum "$TMP/$ARCHIVE" | awk '{print $1}'); else ACTUAL=$(shasum -a 256 "$TMP/$ARCHIVE" | awk '{print $1}'); fi
  [ "$EXPECTED" = "$ACTUAL" ] || { echo 'Release checksum verification failed.' >&2; exit 1; }
  tar -xzf "$TMP/$ARCHIVE" -C "$TMP" ting ting-daemon
fi
# A competing creation fails closed. Never follow this path with privileged chown/chmod.
if [ "$CREATE_IPC_DIR" = 1 ]; then sudo -u "$OWNER" mkdir -m 700 "$IPC_DIR"; fi
sudo install -d -m 755 "$PREFIX/bin"
sudo install -m 755 "$TMP/ting" "$TMP/ting-daemon" "$PREFIX/bin/"
if [ "$OS" = apple-darwin ]; then
  cat > "$TMP/com.silicon.ting.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.silicon.ting</string>
<key>ProgramArguments</key><array><string>$PREFIX/bin/ting-daemon</string></array>
<key>UserName</key><string>$OWNER</string>
<key>EnvironmentVariables</key><dict><key>HOME</key><string>$OWNER_HOME</string></dict>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>5</integer>
<key>Umask</key><integer>63</integer>
</dict></plist>
PLIST
  sudo launchctl bootout system/com.silicon.ting 2>/dev/null || true
  sudo install -m 644 "$TMP/com.silicon.ting.plist" /Library/LaunchDaemons/com.silicon.ting.plist
  sudo launchctl bootstrap system /Library/LaunchDaemons/com.silicon.ting.plist
else
  cat > "$TMP/silicon-ting.service" <<UNIT
[Unit]
Description=Ting shared notification receiver
After=network-online.target
Wants=network-online.target
[Service]
Type=notify
NotifyAccess=main
WatchdogSec=30
User=$OWNER
ExecStart=$PREFIX/bin/ting-daemon
Restart=always
RestartSec=5
UMask=0077
Environment=HOME=$OWNER_HOME
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
UNIT
  sudo install -m 644 "$TMP/silicon-ting.service" /etc/systemd/system/silicon-ting.service
  sudo systemctl daemon-reload
  sudo systemctl enable --now silicon-ting.service
  # enable --now leaves an already-running daemon on its old binary.
  sudo systemctl restart silicon-ting.service
fi
printf 'Installed Ting %s and the shared system service. Run: ting --help\n' "$VERSION"
