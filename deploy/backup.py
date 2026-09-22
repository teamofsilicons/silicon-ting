#!/usr/bin/env python3
"""Encrypted SQLite online snapshots; restoring applies current Ting retention."""
import datetime, os, pathlib, sqlite3, subprocess, tempfile
bucket = os.environ['TING_BACKUP_BUCKET']
with tempfile.TemporaryDirectory() as tmp:
    prefix = datetime.datetime.now(datetime.timezone.utc).strftime('%Y/%m/%d/%H%M%S')
    for name in ('ting.sqlite', 'ting.sqlite.auth', 'ting.sqlite.lifecycle'):
        source = pathlib.Path('/var/lib/ting') / name
        if not source.exists():
            continue
        snapshot = pathlib.Path(tmp) / name
        with sqlite3.connect(f'file:{source}?mode=ro', uri=True) as db, sqlite3.connect(snapshot) as target:
            db.backup(target)
        snapshot.chmod(0o600)
        subprocess.run(['aws', 's3', 'cp', str(snapshot), f's3://{bucket}/backups/{prefix}/{name}', '--region', 'us-east-1', '--sse', 'AES256', '--only-show-errors'], check=True)
