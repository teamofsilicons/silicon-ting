#!/usr/bin/env python3
"""Unit fixtures exercise archive handling; these are not publishable binaries."""
import importlib.util
import io
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location("package", Path(__file__).with_name("package-honeycomb.py"))
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.output = self.root / "output"
        self.output.mkdir()

    def test_tar_regular_files_and_executable_mode(self):
        archive = self.root / "release.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            for name in ("ting", "ting-daemon"):
                entry = tarfile.TarInfo(name)
                data = name.encode()
                entry.size = len(data)
                output.addfile(entry, io.BytesIO(data))
        package.unpack(archive, ["ting", "ting-daemon"], self.output)
        self.assertEqual((self.output / "ting").read_bytes(), b"ting")
        self.assertEqual((self.output / "ting").stat().st_mode & 0o777, 0o755)

    def test_zip_regular_files(self):
        archive = self.root / "release.zip"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("ting.exe", b"cli fixture")
            output.writestr("ting-daemon.exe", b"daemon fixture")
        package.unpack(archive, ["ting.exe", "ting-daemon.exe"], self.output)
        self.assertEqual((self.output / "ting-daemon.exe").read_bytes(), b"daemon fixture")

    def test_tar_link_and_zip_traversal_rejected(self):
        archive = self.root / "release.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            entry = tarfile.TarInfo("ting")
            entry.type = tarfile.SYMTYPE
            entry.linkname = "/elsewhere"
            output.addfile(entry)
        with self.assertRaises(ValueError):
            package.unpack(archive, ["ting"], self.output)
        archive = self.root / "release.zip"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("../ting.exe", b"fixture")
        with self.assertRaises(ValueError):
            package.unpack(archive, ["ting.exe"], self.output)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_zip_symlink_rejected(self):
        archive = self.root / "release.zip"
        with zipfile.ZipFile(archive, "w") as output:
            entry = zipfile.ZipInfo("ting.exe")
            entry.create_system = 3
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            output.writestr(entry, "/elsewhere")
        with self.assertRaises(ValueError):
            package.unpack(archive, ["ting.exe"], self.output)

    def test_checksums_reject_duplicate_and_path_entries(self):
        manifest = self.root / "SHA256SUMS"
        line = "a" * 64 + "  ting.zip\n"
        manifest.write_text(line)
        self.assertEqual(package.checksums(manifest), {"ting.zip": "a" * 64})
        for data in (line * 2, "a" * 64 + "  ../ting.zip\n"):
            manifest.write_text(data)
            with self.assertRaises(ValueError):
                package.checksums(manifest)


if __name__ == "__main__":
    unittest.main()
