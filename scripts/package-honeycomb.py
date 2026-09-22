#!/usr/bin/env python3
"""Assemble a Honeycomb release from all six checksum-verified native CI assets."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    "linux-x86_64": "x86_64-unknown-linux-gnu",
    "linux-aarch64": "aarch64-unknown-linux-gnu",
    "macos-x86_64": "x86_64-apple-darwin",
    "macos-aarch64": "aarch64-apple-darwin",
    "windows-x86_64": "x86_64-pc-windows-msvc",
    "windows-aarch64": "aarch64-pc-windows-msvc",
}


def checksums(path):
    result = {}
    for line in path.read_text().splitlines():
        match = re.fullmatch(r"([a-fA-F0-9]{64}) [ *]([^/\\]+)", line)
        if not match or match[2] in result:
            raise ValueError("Invalid or duplicate SHA256SUMS entry")
        result[match[2]] = match[1].lower()
    return result


def unpack(archive, expected, destination):
    """Copy only two named regular files; never extract archive paths or links."""
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as source:
            entries = source.infolist()
            if sorted(item.filename for item in entries) != sorted(expected):
                raise ValueError(f"Unexpected files in {archive.name}")
            for item in entries:
                mode = item.external_attr >> 16
                if item.is_dir() or stat.S_IFMT(mode) not in (0, stat.S_IFREG) or not item.file_size:
                    raise ValueError(f"Nonregular or empty executable in {archive.name}")
                with source.open(item) as content, (destination / item.filename).open("wb") as output:
                    shutil.copyfileobj(content, output)
    else:
        with tarfile.open(archive, "r:gz") as source:
            entries = source.getmembers()
            if sorted(item.name for item in entries) != sorted(expected):
                raise ValueError(f"Unexpected files in {archive.name}")
            for item in entries:
                if not item.isfile() or not item.size:
                    raise ValueError(f"Nonregular or empty executable in {archive.name}")
                with source.extractfile(item) as content, (destination / item.name).open("wb") as output:
                    shutil.copyfileobj(content, output)
    for name in expected:
        (destination / name).chmod(0o755)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, required=True, help="Directory containing six release archives and SHA256SUMS")
    parser.add_argument("--output", type=Path, required=True, help="New Honeycomb .tar.gz archive")
    parser.add_argument("--honeycomb", default="honeycomb", help="Installed Honeycomb CLI")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; immutable releases must use a new path")
    manifest = json.loads((ROOT / "honeycomb.yaml").read_text())  # JSON is valid YAML.
    version = manifest["version"]
    for crate in ("ting-client", "ting-cli", "ting-daemon"):
        if tomllib.loads((ROOT / "crates" / crate / "Cargo.toml").read_text())["package"]["version"] != version:
            parser.error("Honeycomb and Cargo package versions differ")
    sums = checksums(args.assets / "SHA256SUMS")
    with tempfile.TemporaryDirectory(prefix="ting-honeycomb-") as directory:
        stage = Path(directory)
        shutil.copyfile(ROOT / "honeycomb.yaml", stage / "honeycomb.yaml")
        for platform, target in TARGETS.items():
            extension = "zip" if platform.startswith("windows-") else "tar.gz"
            archive = args.assets / f"ting-v{version}-{target}.{extension}"
            with archive.open("rb") as content:
                actual = hashlib.file_digest(content, "sha256").hexdigest()
            if sums.get(archive.name) != actual:
                parser.error(f"missing or invalid checksum for {archive.name}")
            entry = manifest["targets"][platform]
            destination = stage / entry["root"]
            destination.mkdir(parents=True)
            unpack(archive, list(entry["executables"].values()), destination)
            # Honeycomb packs only its manifest and target trees, not root docs.
            shutil.copyfile(ROOT / "LICENSE", destination / "LICENSE")
            shutil.copyfile(ROOT / "installers" / "README.md", destination / "SERVICE.md")
        env = dict(os.environ, HONEYCOMB_AUTO_UPDATE="0", HONEYCOMB_NO_SERVICE="1", HONEYCOMB_TELEMETRY="0")
        subprocess.run([args.honeycomb, "pack", str(stage), "--output", str(args.output.resolve()), "--json"], check=True, env=env)
    with tarfile.open(args.output, "r:gz") as packed:
        for platform in TARGETS:
            for name in ("LICENSE", "SERVICE.md"):
                if not packed.getmember(f"targets/{platform}/{name}").isfile():
                    raise ValueError("Packed target is missing its license or service instructions")


if __name__ == "__main__":
    main()
