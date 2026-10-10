#!/bin/bash
set -euo pipefail
release="${1:?release directory}"
region="${2:-us-east-1}"
umask 077
exec 9>/var/lock/ting-deploy.lock
flock -n 9
previous=$(readlink -e /opt/ting/current || true)
backup=$(mktemp -d)
database_backup=
database_snapshot_ready=0
targets=(/etc/ting/runtime.env /etc/systemd/system/ting-server.service /etc/caddy/Caddyfile /usr/local/bin/caddy /etc/systemd/system/caddy.service /etc/systemd/system/ting-backup.service /etc/systemd/system/ting-backup.timer)
for target in "${targets[@]}"; do
  [[ ! -f "$target" ]] || cp -p "$target" "$backup/$(basename "$target")"
done
rollback() {
  result=$?
  trap - EXIT
  if [[ "$result" != 0 && -n "$previous" ]]; then
    systemctl stop ting-server ting-backup.timer ting-backup.service || true
    if [[ "$database_snapshot_ready" == 1 ]]; then
      python3 - "$database_backup" <<'RESTORE'
import json, os, pathlib, shutil, sys
backup = pathlib.Path(sys.argv[1])
failed = backup / 'failed'
failed.mkdir(mode=0o700)
manifest = json.loads((backup / 'manifest.json').read_text())
for name in ('ting.sqlite', 'ting.sqlite.auth', 'ting.sqlite.lifecycle'):
    for suffix in ('', '-wal', '-shm', '-journal'):
        source = pathlib.Path('/var/lib/ting') / (name + suffix)
        if source.exists():
            source.replace(failed / source.name)
    record = manifest.get(name)
    if record:
        destination = pathlib.Path('/var/lib/ting') / name
        shutil.copy2(backup / name, destination)
        os.chown(destination, record['uid'], record['gid'])
        destination.chmod(0o600)
print('Restored pre-deployment databases; failed state retained at ' + str(failed))
RESTORE
    fi
    for target in "${targets[@]}"; do
      [[ ! -f "$backup/$(basename "$target")" ]] || cp -p "$backup/$(basename "$target")" "$target"
    done
    ln -sfn "$previous" /opt/ting/current.next
    mv -Tf /opt/ting/current.next /opt/ting/current
    systemctl daemon-reload
    systemctl restart ting-server || true
    systemctl restart caddy || true
    systemctl start ting-backup.timer || true
  fi
  rm -rf "$backup"
  exit "$result"
}
trap rollback EXIT
python3 - "$region" <<'PY'
import json,pathlib,subprocess,sys
value=json.loads(subprocess.check_output(['aws','secretsmanager','get-secret-value','--region',sys.argv[1],'--secret-id','silicon-ting/production/runtime']))['SecretString']
env=json.loads(value)
def quote(v):
    if any(c in v for c in '\n\r\0'):raise ValueError('Multiline runtime value')
    return '"'+v.replace('\\','\\\\').replace('"','\\"')+'"'
p=pathlib.Path('/etc/ting/runtime.env');p.write_text(''.join(k+'='+quote(v)+'\n' for k,v in env.items() if isinstance(v,str)));p.chmod(0o600)
PY
install -m 0755 "$release/caddy" /usr/local/bin/caddy
install -m 0644 "$release/Caddyfile" /etc/caddy/Caddyfile
install -m 0644 "$release/ting-server.service" /etc/systemd/system/ting-server.service
install -m 0644 "$release/caddy.service" /etc/systemd/system/caddy.service
install -m 0644 "$release/ting-backup.service" /etc/systemd/system/ting-backup.service
install -m 0644 "$release/ting-backup.timer" /etc/systemd/system/ting-backup.timer
/usr/local/bin/caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
# The account UUID migration is one way; rollback needs the database snapshot too.
systemctl stop ting-server ting-backup.timer ting-backup.service
database_backup=$(mktemp -d "/var/lib/ting/pre-accounts-$(basename "$release")-XXXXXXXX")
python3 - "$database_backup" <<'SNAPSHOT'
import json, pathlib, sqlite3, sys
backup = pathlib.Path(sys.argv[1])
manifest = {}
for name in ('ting.sqlite', 'ting.sqlite.auth', 'ting.sqlite.lifecycle'):
    source = pathlib.Path('/var/lib/ting') / name
    if not source.exists():
        continue
    metadata = source.stat()
    snapshot = backup / name
    with sqlite3.connect(f'file:{source}?mode=ro', uri=True) as db, sqlite3.connect(snapshot) as destination:
        db.backup(destination)
        if destination.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise RuntimeError('Snapshot failed integrity check: ' + name)
    snapshot.chmod(0o600)
    manifest[name] = {'uid': metadata.st_uid, 'gid': metadata.st_gid}
(backup / 'manifest.json').write_text(json.dumps(manifest))
(backup / 'manifest.json').chmod(0o600)
print('Pre-deployment database snapshot: ' + str(backup))
SNAPSHOT
database_snapshot_ready=1
ln -sfn "$release" /opt/ting/current.next
mv -Tf /opt/ting/current.next /opt/ting/current
systemctl daemon-reload
systemctl enable ting-server caddy ting-backup.timer
systemctl restart ting-server
for attempt in {1..30}; do
 if curl -fsS http://127.0.0.1:8080/healthz; then
   systemctl restart caddy
   for gateway_attempt in {1..15}; do
     if curl -fsS --connect-timeout 2 --max-time 5 --resolve backend.ting.teamofsilicons.com:443:127.0.0.1 https://backend.ting.teamofsilicons.com/healthz; then
       systemctl start ting-backup.timer
       printf '\nInstalled %s\n' "$release"
       exit 0
     fi
     sleep 2
   done
   break
 fi
 sleep 2
done
printf 'Health check failed; restoring previous release.\n' >&2
exit 1
