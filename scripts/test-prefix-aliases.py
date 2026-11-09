#!/usr/bin/env python3
"""Real loopback Ting/SQLite/Accounts fixture plus actual CLI; no real credentials."""
import os
import pathlib
import subprocess

root = pathlib.Path(__file__).resolve().parents[1]
subprocess.run(["cargo", "build", "--locked", "-p", "silicon-ting-cli", "--bin", "ting"], cwd=root, check=True)
env = os.environ.copy()
env["TING_TEST_CLI"] = str(root / "target/debug/ting")
subprocess.run([
    "cargo", "test", "--locked", "-p", "silicon-ting-server", "--bin", "ting-server",
    "real_cli_alias_registration_preferences_and_history", "--", "--ignored", "--nocapture"
], cwd=root, env=env, check=True)
