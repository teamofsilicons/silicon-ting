#!/usr/bin/env python3
"""Exercise the real installer with fixture paths and a sudo stub; never elevate."""
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import tempfile
import unittest


class InstallerDirectoryBoundary(unittest.TestCase):
    def test_shared_directory_is_not_followed_or_privileged(self):
        source = (Path(__file__).resolve().parent / "install.sh").read_text()
        self.assertEqual(source.count("IPC_DIR=/var/tmp/silicon-ting\n"), 1)
        for kind in ("symlink", "owned", "missing", "creation-race"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix="ting-installer-") as name:
                root = Path(name)
                target = root / "target"
                target.mkdir(mode=0o755)
                target.chmod(0o755)
                (target / "sentinel").write_text("unchanged")
                ipc = root / "ipc"
                if kind == "symlink":
                    ipc.symlink_to(target, target_is_directory=True)
                elif kind == "owned":
                    ipc.mkdir(mode=0o700)
                project = root / "project"
                (project / "scripts").mkdir(parents=True)
                release = project / "target" / "release"
                release.mkdir(parents=True)
                for binary in ("ting", "ting-daemon"):
                    (release / binary).write_text("fixture")
                installer = project / "scripts" / "install.sh"
                installer.write_text(source.replace("IPC_DIR=/var/tmp/silicon-ting\n", f"IPC_DIR='{ipc}'\n"))
                commands = root / "commands"
                commands.mkdir()
                cargo = commands / "cargo"
                cargo.write_text('#!/bin/sh\nif [ -n "${IPC_RACE_TARGET:-}" ]; then ln -s "$IPC_RACE_TARGET" "$IPC_FIXTURE_PATH"; fi\n')
                cargo.chmod(0o755)
                sudo = commands / "sudo"
                sudo.write_text('''#!/usr/bin/env python3
import json, os, sys
with open(os.environ["SUDO_CALLS"], "a") as out:
    out.write(json.dumps(sys.argv[1:]) + "\\n")
if sys.argv[1] == "-u":
    assert sys.argv[3:6] == ["mkdir", "-m", "700"]
    assert sys.argv[6] == os.environ["IPC_FIXTURE_PATH"]
    os.execvp("mkdir", sys.argv[3:])
sys.exit(73)  # Stop before any installation or service mutation.
''')
                sudo.chmod(0o755)
                calls = root / "sudo-calls"
                env = dict(os.environ, PATH=f"{commands}:{os.environ['PATH']}",
                           SUDO_USER=pwd.getpwuid(os.geteuid()).pw_name,
                           TING_INSTALL_FROM_SOURCE="1", TING_INSTALL_PREFIX=str(root / "prefix"),
                           SUDO_CALLS=str(calls), IPC_FIXTURE_PATH=str(ipc),
                           IPC_RACE_TARGET=str(target) if kind == "creation-race" else "")
                result = subprocess.run(["sh", str(installer)], env=env, capture_output=True, text=True)
                recorded = [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
                if kind == "symlink":
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertEqual(recorded, [])
                elif kind == "creation-race":
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(len(recorded), 1)
                    self.assertEqual(recorded[0][2:5], ["mkdir", "-m", "700"])
                else:
                    self.assertEqual(result.returncode, 73, result.stderr)
                    self.assertEqual(recorded[-1][:2], ["install", "-d"])
                    self.assertEqual(stat.S_IMODE(ipc.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)
                self.assertEqual((target / "sentinel").read_text(), "unchanged")


if __name__ == "__main__":
    unittest.main()
