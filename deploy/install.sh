#!/bin/bash
set -euo pipefail
release="${1:?release directory}"
region="${2:-us-east-1}"
umask 077
exec 9>/var/lock/ting-deploy.lock
flock -n 9
previous=$(readlink -e /opt/ting/current || true)
backup=$(mktemp -d)
targets=(/etc/ting/runtime.env /etc/systemd/system/ting-server.service /etc/caddy/Caddyfile /usr/local/bin/caddy /etc/systemd/system/caddy.service /etc/systemd/system/ting-backup.service /etc/systemd/system/ting-backup.timer)
for target in "${targets[@]}"; do
  [[ ! -f "$target" ]] || cp -p "$target" "$backup/$(basename "$target")"
done
rollback() {
  result=$?
  trap - EXIT
  if [[ "$result" != 0 && -n "$previous" ]]; then
    for target in "${targets[@]}"; do
      [[ ! -f "$backup/$(basename "$target")" ]] || cp -p "$backup/$(basename "$target")" "$target"
    done
    ln -sfn "$previous" /opt/ting/current.next
    mv -Tf /opt/ting/current.next /opt/ting/current
    systemctl daemon-reload
    systemctl restart ting-server || true
    systemctl restart caddy || true
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
if [[ -f /etc/ting/probe.env ]]; then
  set -a
  source /etc/ting/probe.env
  set +a
fi
/usr/local/bin/caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
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
